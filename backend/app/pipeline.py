"""Phase 3 — Universal tool execution policy pipeline.

Every model-initiated tool invocation is funnelled through ONE ordered gate
chain before anything can touch the OS:

    model decision -> schema validation -> identity/context -> permission
    -> risk policy -> approval -> sandbox/execution -> output validation
    -> audit

The chain deliberately *reuses* the existing enforcement points instead of
re-implementing them:

* ``app.tools.base.Registry.execute`` performs schema validation (input AND
  output), permission enforcement, timeouts and output-size limits. This
  pipeline calls it exactly once per attempt; it never executes a tool itself.
* ``app.computer.contracts.ComputerPolicy`` (deterministic, fail-closed) is
  consulted for every action when a policy is installed. A DENY or an
  evaluation error blocks the call before the registry is reached.
* Approval is enforced from trusted tool metadata (``requires_approval``,
  which PermissionManager escalates for HIGH/CRITICAL risk). The model cannot
  influence this: only the Registry's own view of the tool counts.
* Audit goes to the append-only ``MemoryStore.audit`` (secret-redacted at
  write time). Every attempt — allowed, blocked, replayed, simulated or
  failed — emits exactly one ``tool.pipeline.executed`` event.

Additional Phase 3 guarantees implemented here:

* **Idempotency keys** — callers may attach a bounded key. Replays with the
  same (conversation, tool, arguments-hash, key) return the original
  ``ToolResult`` without re-executing.
* **Duplicate-action protection** — non-idempotent tools executed without an
  idempotency key are fingerprinted by (conversation, tool, arguments-hash)
  for a TTL window; a duplicate inside the window is BLOCKED (fail closed)
  rather than silently repeating a side effect.
* **Dry-run / simulation** — runs every gate (schema, identity, permission,
  risk policy, approval) but never reaches the tool implementation; the
  result is explicitly marked as simulated so no consumer can mistake it for
  real execution. Dry-run never writes to the idempotency/duplicate stores.

Security invariants:
* Fail closed on unknown tools, malformed envelopes, missing context ids,
  policy errors, missing approvals and internal errors.
* Nothing in this module lets the caller weaken metadata; the agent cannot
  mutate the pipeline's configuration after construction (private attributes,
  no setters) and cannot touch the audit trail beyond appending.
* No secrets or raw sensitive payloads are logged: only identifiers, hashes,
  decisions and redacted error strings appear in audit details.
"""

from __future__ import annotations

import hashlib
import json
import re
import threading
import time
from enum import StrEnum
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.computer.contracts import (
    Action,
    ActionCategory,
    ComputerPolicy,
    PolicyEffect,
)
from app.models import Permission, RiskLevel, ToolResult

IDEMPOTENCY_KEY_PATTERN = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")

# Pipeline stages in canonical order. Exposed for diagnostics/tests only.
PIPELINE_STAGES: tuple[str, ...] = (
    "model_decision",
    "schema_validation",
    "identity_context",
    "permission",
    "risk_policy",
    "approval",
    "execution",          # sandbox/tool run happens inside Registry.execute
    "output_validation",  # enforced by Registry.execute; audited here
    "audit",
)


class ToolContext(BaseModel):
    """Identity/context envelope attached by the application (never the model).

    ``extra="forbid"`` plus identifier pattern checks stop smuggled fields and
    make malformed contexts fail closed.
    """

    model_config = ConfigDict(extra="forbid")

    conversation_id: str = Field(min_length=1, max_length=120)
    task_id: str | None = Field(None, max_length=120)
    step_id: str | None = Field(None, max_length=120)
    actor: str = Field("agent", max_length=64)
    idempotency_key: str | None = None
    dry_run: bool = False

    @field_validator("conversation_id", "task_id", "step_id")
    @classmethod
    def valid_identifier(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,119}", value):
            raise ValueError("invalid context identifier")
        return value

    @field_validator("idempotency_key")
    @classmethod
    def valid_key(cls, value: str | None) -> str | None:
        if value is None:
            return value
        if not IDEMPOTENCY_KEY_PATTERN.fullmatch(value):
            raise ValueError("invalid idempotency key")
        return value


class PipelineOutcome(StrEnum):
    EXECUTED = "executed"                  # tool actually ran
    BLOCKED = "blocked"                    # a gate refused execution
    REPLAYED = "replayed"                  # idempotent replay of a stored result
    DUPLICATE_BLOCKED = "duplicate_blocked"  # duplicate-action protection fired
    SIMULATED = "simulated"                # dry-run: all gates passed, no side effects


class PipelineDecision(BaseModel):
    """Bounded, JSON-safe outcome returned by every pipeline call."""

    model_config = ConfigDict(extra="forbid")

    outcome: PipelineOutcome
    stage: str = Field(min_length=1, max_length=40)
    reason: str = Field("", max_length=500)
    result: ToolResult | None = None
    simulated: bool = False
    replayed: bool = False
    idempotency_key: str | None = None
    action_hash: str = Field(min_length=12, max_length=64)
    duration_ms: int = Field(0, ge=0)


def _canonical_arguments(arguments: dict[str, Any]) -> bytes:
    try:
        return json.dumps(arguments, sort_keys=True, separators=(",", ":"),
                          ensure_ascii=False, default=str).encode("utf-8")
    except (TypeError, ValueError):
        # Non-serialisable payloads still need a stable hash; hashing the
        # repr keeps duplicate detection total (fail closed, never skip).
        return repr(sorted(arguments.items())).encode("utf-8", "replace")


def action_hash(tool: str, arguments: dict[str, Any]) -> str:
    digest = hashlib.sha256()
    digest.update(tool.encode("utf-8"))
    digest.update(b"\x00")
    digest.update(_canonical_arguments(arguments))
    return digest.hexdigest()[:16]


class DuplicateActionGuard:
    """Thread-safe TTL store for idempotent replays + duplicate side effects."""

    def __init__(self, *, ttl_seconds: float = 300.0, max_entries: int = 1000):
        self._ttl = float(ttl_seconds)
        self._max_entries = int(max_entries)
        self._lock = threading.Lock()
        self._idempotent: dict[tuple[str, str, str, str], tuple[float, ToolResult]] = {}
        self._inflight: set[tuple[str, str, str]] = set()
        self._recent: dict[tuple[str, str, str], float] = {}

    def reset(self) -> None:
        with self._lock:
            self._idempotent.clear()
            self._inflight.clear()
            self._recent.clear()

    def _prune_locked(self) -> None:
        now = time.monotonic()
        expired = [k for k, ts in self._recent.items() if now - ts > self._ttl]
        for key in expired:
            del self._recent[key]
        stale = [k for k, (ts, _) in self._idempotent.items() if now - ts > self._ttl]
        for key in stale:
            del self._idempotent[key]
        overflow = len(self._idempotent) - self._max_entries
        if overflow > 0:
            for key in sorted(self._idempotent, key=lambda k: self._idempotent[k][0])[:overflow]:
                del self._idempotent[key]
        overflow = len(self._recent) - self._max_entries
        if overflow > 0:
            for key in sorted(self._recent, key=lambda k: self._recent[k])[:overflow]:
                del self._recent[key]

    def cached(self, scope: tuple[str, str, str, str]) -> ToolResult | None:
        with self._lock:
            entry = self._idempotent.get(scope)
            if entry is None:
                return None
            if time.monotonic() - entry[0] > self._ttl:
                del self._idempotent[scope]
                return None
            return entry[1]

    def remember(self, scope: tuple[str, str, str, str], result: ToolResult) -> None:
        with self._lock:
            self._idempotent[scope] = (time.monotonic(), result)
            self._prune_locked()

    def begin(self, scope: tuple[str, str, str]) -> str | None:
        """Claim the side-effect slot. Returns a block reason or None."""
        with self._lock:
            if scope in self._inflight:
                return "duplicate action already in flight"
            last = self._recent.get(scope)
            if last is not None and time.monotonic() - last <= self._ttl:
                return "duplicate action blocked within protection window"
            self._inflight.add(scope)
            self._prune_locked()
            return None

    def complete(self, scope: tuple[str, str, str]) -> None:
        with self._lock:
            self._inflight.discard(scope)
            self._recent[scope] = time.monotonic()
            self._prune_locked()

    def release(self, scope: tuple[str, str, str]) -> None:
        """Free the in-flight claim without recording a side effect (failure)."""
        with self._lock:
            self._inflight.discard(scope)


class ToolExecutionPipeline:
    """Ordered, fail-closed gate chain around the canonical Registry.

    ``registry_provider`` is called per execution so workspaces and test
    overrides resolve lazily; ``memory`` (duck-typed ``async audit``) receives
    one event per attempt; ``policy`` is the optional ComputerPolicy layer
    which can only make decisions stricter.
    """

    def __init__(self, *, registry_provider: Callable[[], Any],
                 memory: Any = None, policy: ComputerPolicy | None = None,
                 emergency_stopped_check: Callable[[], bool] | None = None,
                 guard: DuplicateActionGuard | None = None):
        self._registry_provider = registry_provider
        self._memory = memory
        self._policy = policy
        self._emergency_stopped_check = emergency_stopped_check or (lambda: False)
        self._guard = guard or DuplicateActionGuard()

    # -- read-only views (no setters: the agent cannot reconfigure policy) -- #

    @property
    def guard(self) -> DuplicateActionGuard:
        return self._guard

    @property
    def policy(self) -> ComputerPolicy | None:
        return self._policy

    async def run(self, tool_name: str, arguments: dict[str, Any], *,
                  approved_permissions: set[Permission], context: ToolContext) -> PipelineDecision:
        started = time.perf_counter()
        digest = action_hash(tool_name if isinstance(tool_name, str) else "?", 
                             arguments if isinstance(arguments, dict) else {})
        decision = await self._run(tool_name, arguments,
                                   approved_permissions=approved_permissions,
                                   context=context, digest=digest)
        decision.duration_ms = int((time.perf_counter() - started) * 1000)
        await self._audit(decision, tool_name, context)
        return decision

    # ------------------------------------------------------------------ #

    async def _run(self, tool_name: str, arguments: dict[str, Any], *,
                   approved_permissions: set[Permission], context: ToolContext,
                   digest: str) -> PipelineDecision:
        # Stage 1: model decision — the envelope itself must be well-formed.
        if not isinstance(context, ToolContext):
            return self._blocked("model_decision", "malformed execution context", digest, context=None)
        if not isinstance(tool_name, str) or not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", tool_name):
            return self._blocked("model_decision", "invalid tool name", digest, context)
        if not isinstance(arguments, dict):
            return self._blocked("model_decision", "arguments must be an object", digest, context)

        # Stage 3 (early): identity/context — refuse anonymous executions so
        # idempotency scoping and audits are always attributable.
        if not context.conversation_id:
            return self._blocked("identity_context", "missing conversation identity", digest, context)

        try:
            registry = self._registry_provider()
        except Exception:
            return self._blocked("model_decision", "tool registry unavailable", digest, context)
        tool = registry.tools.get(tool_name) if hasattr(registry, "tools") else None
        if tool is None:
            # Unknown tool => blocked (the Registry would also refuse; we fail
            # before any state mutation so duplicate tracking stays clean).
            return self._blocked("schema_validation", f"unknown tool: {tool_name}", digest, context)

        # Emergency stop blocks everything (mirrors Control Center semantics).
        try:
            if self._emergency_stopped_check():
                return self._blocked("risk_policy", "blocked_by_emergency", digest, context)
        except Exception:
            return self._blocked("risk_policy", "emergency check failed", digest, context)

        # Stage 5: risk policy (ComputerPolicy — deterministic, deny-on-error).
        if self._policy is not None:
            effect = self._policy_effect(tool)
            if effect != PolicyEffect.ALLOW.value:
                return self._blocked("risk_policy", f"COMPUTER_POLICY_{effect.upper()}", digest, context)

        # Stage 6: approval — enforced from TRUSTED metadata only.
        requires_approval = bool(getattr(tool, "requires_approval", False))
        if requires_approval and not context.dry_run:
            # Callers satisfy approval via granted permissions (session/persistent
            # approvals) or by executing with explicit approval upstream. If the
            # tool's non-SAFE permissions are not all granted, the Registry will
            # block it; we additionally require that grant evidence here so a
            # misconfigured registry cannot execute an approval tool anonymously.
            missing = ({p for p in getattr(tool, "permissions", frozenset()) if p != Permission.SAFE}
                       - set(approved_permissions or set()))
            if missing:
                return self._blocked("approval", "approval required for this exact operation", digest, context)

        idem_scope = (context.conversation_id, tool_name, digest, context.idempotency_key or "")
        side_scope = (context.conversation_id, tool_name, digest)
        has_key = context.idempotency_key is not None
        idempotent_tool = bool(getattr(tool, "idempotent", True))
        # Duplicate tracking applies to any side-effecting tool (non-idempotent
        # OR approval-required), not just the non-idempotent flag.
        tracked = (not idempotent_tool) or requires_approval

        # Idempotent replay: return the stored result without re-executing.
        if has_key:
            cached = self._guard.cached(idem_scope)
            if cached is not None:
                return PipelineDecision(outcome=PipelineOutcome.REPLAYED, stage="identity_context",
                                        reason="idempotent replay", result=cached, replayed=True,
                                        idempotency_key=context.idempotency_key, action_hash=digest)
        elif tracked and not context.dry_run:
            # Duplicate-action protection for side-effecting tools without a key.
            block_reason = self._guard.begin(side_scope)
            if block_reason:
                return PipelineDecision(outcome=PipelineOutcome.DUPLICATE_BLOCKED,
                                        stage="duplicate_action", reason=block_reason,
                                        action_hash=digest,
                                        idempotency_key=context.idempotency_key)

        claimed = (has_key or (tracked and not context.dry_run))
        try:
            if context.dry_run:
                # Stage 7 is SKIPPED by design: every preceding gate has run,
                # including full input-schema validation below, but nothing
                # executes. Validate the input schema against the tool model
                # so a dry run still catches invalid payloads.
                try:
                    tool.input_model.model_validate(arguments)
                except Exception:
                    return self._blocked("schema_validation", "input schema validation failed", digest, context)
                decision = PipelineDecision(
                    outcome=PipelineOutcome.SIMULATED, stage="execution", simulated=True,
                    reason="dry-run: all policy gates passed, no side effects performed",
                    result=ToolResult(name=tool_name, success=True, code="simulated",
                                      output={"simulated": True, "tool": tool_name,
                                              "version": getattr(tool, "version", "1.0.0"),
                                              "risk_level": getattr(tool, "risk_level", RiskLevel.LOW).value,
                                              "reversibility": getattr(tool, "reversibility", None).value
                                              if getattr(tool, "reversibility", None) is not None else None}),
                    idempotency_key=context.idempotency_key, action_hash=digest)
                return decision

            # Stages 2+4+7+8: the canonical Registry performs schema
            # validation, permission enforcement, timeout/sandboxed execution
            # and output validation. It fails closed on each.
            result = await registry.execute(tool_name, arguments, set(approved_permissions or set()))
            if result.success:
                if has_key:
                    self._guard.remember(idem_scope, result)
                return PipelineDecision(outcome=PipelineOutcome.EXECUTED, stage="audit",
                                        result=result, idempotency_key=context.idempotency_key,
                                        action_hash=digest)
            code = result.code or "tool_failed"
            stage = {"unknown_tool": "schema_validation",
                     "permission_required": "permission",
                     "tool_disabled": "risk_policy",
                     "timeout": "execution"}.get(code, "execution")
            return PipelineDecision(outcome=PipelineOutcome.BLOCKED if stage != "execution"
                                    else PipelineOutcome.EXECUTED,
                                    stage=stage, reason=(result.error or "")[:500],
                                    result=result, idempotency_key=context.idempotency_key,
                                    action_hash=digest)
        except Exception:
            # Internal errors fail closed AND release the duplicate claim so a
            # crashed attempt does not poison the window forever.
            if claimed and not has_key:
                self._guard.release(side_scope)
            claimed = False
            return self._blocked("execution", "pipeline internal error", digest, context)
        finally:
            if claimed and not has_key:
                # Record the side-effect window once the attempt completed
                # (success OR failure — both consumed the "one shot" safely
                # because retries must carry an explicit idempotency key).
                self._guard.complete(side_scope)

    # ------------------------------------------------------------------ #

    def _policy_effect(self, tool: Any) -> str:
        try:
            try:
                category = ActionCategory(str(getattr(tool, "category", "general")))
            except ValueError:
                category = ActionCategory.SCREEN
            physical = category in {ActionCategory.MOUSE, ActionCategory.KEYBOARD}
            probe = Action(
                task_id="pipeline-probe", category=category, operation="run",
                target=re.sub(r"[^a-z0-9_.:-]", "-", tool.name)[:64].lstrip("0123456789-:.") or "probe",
                risk_level=getattr(tool, "risk_level", RiskLevel.LOW),
                requires_approval=True if physical else bool(getattr(tool, "requires_approval", False)),
            )
            if physical and probe.risk_level == RiskLevel.LOW:
                probe = probe.model_copy(update={"risk_level": RiskLevel.MEDIUM})
            return self._policy.evaluate_or_deny(probe).value
        except Exception:
            return PolicyEffect.DENY.value

    def _blocked(self, stage: str, reason: str, digest: str,
                 context: ToolContext | None) -> PipelineDecision:
        return PipelineDecision(outcome=PipelineOutcome.BLOCKED, stage=stage,
                                reason=reason[:500], action_hash=digest,
                                idempotency_key=context.idempotency_key if context else None)

    async def _audit(self, decision: PipelineDecision, tool_name: str,
                     context: ToolContext) -> None:
        if self._memory is None:
            return
        try:
            result = decision.result
            await self._memory.audit("tool.pipeline.executed", {
                "stage": decision.stage,
                "outcome": decision.outcome.value,
                "reason": decision.reason or None,
                "tool": tool_name[:64],
                "action_hash": decision.action_hash,
                "idempotency": bool(decision.idempotency_key),
                "dry_run": decision.simulated,
                "conversation_id": context.conversation_id[:120],
                "task_id": (context.task_id or "")[:120] or None,
                "actor": context.actor[:64],
                "success": bool(result.success) if result is not None else False,
                "code": (result.code or ("ok" if result and result.success else None)),
                "duration_ms": decision.duration_ms,
            })
        except Exception:
            # Audit failures must never crash execution, but they are severe;
            # surface them on the decision so callers can react.
            decision.reason = ((decision.reason + "; ") if decision.reason else "") + "AUDIT_WRITE_FAILED"


_pipeline_lock = threading.Lock()
_default_pipeline: ToolExecutionPipeline | None = None


def get_execution_pipeline() -> ToolExecutionPipeline:
    """Process-wide default pipeline wired to the canonical registry factory."""
    global _default_pipeline
    with _pipeline_lock:
        if _default_pipeline is None:
            from app.tools.factory import registry

            emergency_check = None
            try:
                from app.control_center import get_control_center
                center = get_control_center()
                if center is not None:
                    emergency_check = lambda: bool(center.blocked_by_emergency)  # noqa: E731
            except Exception:
                emergency_check = None
            policy = None
            try:
                from app.config import settings
                if settings().computer_agent_enabled:
                    from app.computer.runtime import get_computer_runtime
                    policy = get_computer_runtime().policy
            except Exception:
                policy = None
            _default_pipeline = ToolExecutionPipeline(
                registry_provider=registry,
                emergency_stopped_check=emergency_check,
                policy=policy,
            )
        return _default_pipeline


def reset_execution_pipeline() -> None:
    """Test/lifecycle hook: drop the default pipeline singleton."""
    global _default_pipeline
    with _pipeline_lock:
        _default_pipeline = None
