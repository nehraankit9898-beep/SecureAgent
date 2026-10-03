"""Stable Computer Agent contracts (Phase 1 — interfaces only, no execution).

These models and abstract interfaces form the integration boundary between
the existing SecureAgent core (tool Registry, PermissionManager, Control
Center, audit store) and the future Computer Agent layer (screen capture,
input synthesis, window management, browser automation, voice, verification).

Design rules encoded here (and enforced by tests):

* Every structured model uses ``extra="forbid"`` so malformed or smuggled
  payloads fail validation closed.
* All free-text fields are length-bounded; all lists are size-bounded.
* ``Action.target`` is a validated identifier pattern — never arbitrary text,
  never shell content. Coordinates are bounded to sane screen sizes.
* Observation/VerificationResult/AuditEvent mark their payload as UNTRUSTED
  data: it must never be interpreted as instructions by the LLM.
* The interfaces define NO OS access. Concrete providers arrive in later
  phases behind platform adapters; until then every provider method raises
  ``ComputerAgentDisabledError`` via the disabled stubs in this module.
* ``ComputerTool.to_core_tool_def()`` reuses the canonical
  ``app.tools.base.Registry`` metadata contract verbatim — computer tools can
  only enter the system through the existing central registry, which applies
  PermissionManager, Control Center gates, timeouts and output limits.
"""

from __future__ import annotations

import json
import re
from abc import ABC, abstractmethod
from datetime import UTC, datetime
from enum import StrEnum
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.models import Permission, RiskLevel, ToolDef
from app.security import redact

# --------------------------------------------------------------------------- #
# shared bounded primitives
# --------------------------------------------------------------------------- #

TARGET_ID = re.compile(r"[a-z][a-z0-9_.:-]{0,63}")
PROVIDER_ID = re.compile(r"[a-z][a-z0-9_-]{0,63}")
EVENT_NAME = re.compile(r"[a-z][a-z0-9_.:-]{0,79}")


MAX_PAYLOAD_BYTES = 100_000


class _Contract(BaseModel):
    """Base for every computer-agent contract: strict, bounded, fail-closed.

    ``extra="forbid"`` rejects smuggled fields; the shared validator enforces a
    global serialized-size ceiling so no contract can carry an unbounded blob.
    """

    model_config = ConfigDict(extra="forbid")

    @model_validator(mode="after")
    def _global_size_limit(self) -> "_Contract":
        try:
            size = len(self.model_dump_json().encode("utf-8"))
        except (TypeError, ValueError):
            raise ValueError("contract must be JSON-serialisable") from None
        if size > MAX_PAYLOAD_BYTES:
            raise ValueError(f"contract exceeds {MAX_PAYLOAD_BYTES} byte limit")
        return self


class ProviderKind(StrEnum):
    PERCEPTION = "perception"   # screen capture / OCR / vision
    INPUT = "input"             # mouse / keyboard synthesis
    WINDOW = "window"           # window enumeration / focus control
    BROWSER = "browser"         # Playwright-style browser automation
    VOICE = "voice"             # STT / TTS


class ActionCategory(StrEnum):
    SCREEN = "screen"           # read-only observation of the display
    MOUSE = "mouse"             # physical pointer synthesis (gated, Phase 2+)
    KEYBOARD = "keyboard"       # physical text input (gated, Phase 2+)
    WINDOW = "window"
    FILESYSTEM = "filesystem"
    TERMINAL = "terminal"
    BROWSER = "browser"
    VOICE = "voice"


class ActionStatus(StrEnum):
    PLANNED = "planned"
    APPROVAL_REQUIRED = "approval_required"
    APPROVED = "approved"
    DENIED = "denied"
    EXECUTING = "executing"
    SUCCEEDED = "succeeded"
    FAILED = "failed"
    CANCELLED = "cancelled"


class PolicyEffect(StrEnum):
    ALLOW = "allow"
    REQUIRE_APPROVAL = "require_approval"
    DENY = "deny"


class ApprovalDecision(StrEnum):
    PENDING = "pending"
    APPROVED_ONCE = "approved_once"
    APPROVED_SESSION = "approved_session"
    DENIED = "denied"
    EXPIRED = "expired"


def _bounded_json_bytes(payload: dict[str, Any], limit: int, label: str) -> dict[str, Any]:
    """Fail closed on oversized/unserializable structured payloads."""
    try:
        size = len(json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8"))
    except (TypeError, ValueError) as error:
        raise ValueError(f"{label} must be JSON-serialisable") from error
    if size > limit:
        raise ValueError(f"{label} exceeds {limit} byte limit")
    return payload


# --------------------------------------------------------------------------- #
# structured data models
# --------------------------------------------------------------------------- #


class ComputerTask(_Contract):
    """Planner-level task record for the Computer Agent layer.

    Deliberately separate from the chat-level ``app.models.Task``: a computer
    task owns perception/action steps, not just tool steps. It references the
    core task/conversation ids instead of duplicating them.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    goal: str = Field(min_length=1, max_length=4000)
    conversation_id: str | None = Field(None, max_length=120)
    core_task_id: str | None = Field(None, max_length=120)
    status: Literal["planning", "awaiting_approval", "running", "verifying",
                    "completed", "failed", "cancelled"] = "planning"
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    updated_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    max_actions: int = Field(10, ge=1, le=50)
    max_runtime_seconds: float = Field(120, gt=0, le=900)

    @field_validator("goal")
    @classmethod
    def non_blank_goal(cls, value: str) -> str:
        if not value.strip():
            raise ValueError("blank goal")
        return value


class Observation(_Contract):
    """One structured snapshot produced by a perception provider.

    ``content`` is UNTRUSTED DATA (OCR text, page text, accessibility trees).
    Downstream code must wrap it with ``app.security.untrusted_context`` before
    showing it to any model; the flag makes accidental trust reviewable.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    task_id: str = Field(min_length=1, max_length=120)
    provider: str = Field(min_length=1, max_length=64)
    kind: Literal["screen", "ocr", "vision", "window", "browser", "voice", "system"]
    captured_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    untrusted: bool = True
    summary: str = Field("", max_length=2000)
    content: dict[str, Any] = Field(default_factory=dict)
    truncated: bool = False

    @field_validator("provider")
    @classmethod
    def valid_provider(cls, value: str) -> str:
        if not PROVIDER_ID.fullmatch(value):
            raise ValueError("invalid provider identifier")
        return value

    @field_validator("content")
    @classmethod
    def bounded_content(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _bounded_json_bytes(value, 60_000, "observation content")

    @model_validator(mode="after")
    def must_be_untrusted(self) -> "Observation":
        # Perception output is never trusted; refusing to construct a
        # "trusted" observation keeps callers honest.
        if self.untrusted is not True:
            raise ValueError("observations are always untrusted data")
        return self


class Action(_Contract):
    """A single planned/executed computer action.

    Only *declarative* data lives here. There is no callable payload, no
    command string and no raw key text persisted in coordinates/keys/buttons.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    task_id: str = Field(min_length=1, max_length=120)
    category: ActionCategory
    operation: str = Field(min_length=1, max_length=64)
    target: str = Field(min_length=1, max_length=64)
    arguments: dict[str, Any] = Field(default_factory=dict)
    status: ActionStatus = ActionStatus.PLANNED
    risk_level: RiskLevel = RiskLevel.LOW
    required_permissions: list[Permission] = Field(default_factory=list)
    requires_approval: bool = False
    reason: str = Field("", max_length=1000)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("operation")
    @classmethod
    def valid_operation(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", normalized):
            raise ValueError("invalid action operation identifier")
        return normalized

    @field_validator("target")
    @classmethod
    def valid_target(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not TARGET_ID.fullmatch(normalized):
            raise ValueError("invalid action target identifier")
        return normalized

    @field_validator("arguments")
    @classmethod
    def bounded_arguments(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _bounded_json_bytes(value, 20_000, "action arguments")

    @field_validator("required_permissions")
    @classmethod
    def unique_permissions(cls, value: list[Permission]) -> list[Permission]:
        if len(value) != len(set(value)):
            raise ValueError("duplicate permissions")
        return value

    @model_validator(mode="after")
    def coherent_risk(self) -> "Action":
        # Physical input and destructive categories can never be LOW risk and
        # must always carry an explicit approval requirement at plan time.
        risky = {ActionCategory.MOUSE, ActionCategory.KEYBOARD,
                 ActionCategory.WINDOW, ActionCategory.TERMINAL, ActionCategory.BROWSER}
        if self.category in risky and self.risk_level == RiskLevel.LOW:
            raise ValueError(f"{self.category.value} actions cannot be low risk")
        if self.category in {ActionCategory.MOUSE, ActionCategory.KEYBOARD} and not self.requires_approval:
            raise ValueError("physical input actions require approval")
        return self


class ToolCall(_Contract):
    """The exact envelope handed to the central tool Registry.

    The planner/model may only produce this structure; the application (never
    the model) fills ``approved_permissions`` from the permission pipeline.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    task_id: str = Field(min_length=1, max_length=120)
    tool: str = Field(min_length=1, max_length=64)
    arguments: dict[str, Any] = Field(default_factory=dict)
    approved_permissions: list[Permission] = Field(default_factory=list)
    timeout_seconds: float = Field(20, gt=0, le=600)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("tool")
    @classmethod
    def valid_tool_name(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", normalized):
            raise ValueError("invalid tool name")
        return normalized

    @field_validator("arguments")
    @classmethod
    def bounded_arguments(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _bounded_json_bytes(value, 100_000, "tool call arguments")

    @field_validator("approved_permissions")
    @classmethod
    def unique_permissions(cls, value: list[Permission]) -> list[Permission]:
        if len(value) != len(set(value)):
            raise ValueError("duplicate permissions")
        return value


class ApprovalRequest(_Contract):
    """Human-in-the-loop approval ticket for one action or tool call.

    Requests expire; expiry is fail-closed. Secrets and typed text are
    redacted before the request is ever shown or stored.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    task_id: str = Field(min_length=1, max_length=120)
    action_id: str | None = Field(None, max_length=120)
    tool_call_id: str | None = Field(None, max_length=120)
    tool: str = Field(min_length=1, max_length=64)
    risk_level: RiskLevel
    summary: str = Field(min_length=1, max_length=1000)
    arguments_preview: dict[str, Any] = Field(default_factory=dict)
    decision: ApprovalDecision = ApprovalDecision.PENDING
    actor: str = Field("user", max_length=64)
    note: str = Field("", max_length=500)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    expires_at: datetime

    @field_validator("tool")
    @classmethod
    def valid_tool_name(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", normalized):
            raise ValueError("invalid tool name")
        return normalized

    @field_validator("arguments_preview")
    @classmethod
    def redacted_preview(cls, value: dict[str, Any]) -> dict[str, Any]:
        safe = redact(value)
        if not isinstance(safe, dict):
            raise ValueError("preview must be an object")
        return _bounded_json_bytes(safe, 4_000, "approval preview")

    @model_validator(mode="after")
    def valid_window(self) -> "ApprovalRequest":
        if self.expires_at <= self.created_at:
            raise ValueError("approval expiry must be after creation")
        return self

    def is_expired(self, now: datetime | None = None) -> bool:
        current = now or datetime.now(UTC)
        if current.tzinfo is None:
            current = current.replace(tzinfo=UTC)
        return current >= self.expires_at


class VerificationResult(_Contract):
    """Post-action verification evidence. No verification => no completion."""

    id: str = Field(default_factory=lambda: str(uuid4()))
    task_id: str = Field(min_length=1, max_length=120)
    action_id: str | None = Field(None, max_length=120)
    verified: bool
    confidence: float = Field(0.0, ge=0, le=1)
    method: str = Field(min_length=1, max_length=64)
    evidence: dict[str, Any] = Field(default_factory=dict)
    failures: list[str] = Field(default_factory=list, max_length=20)
    checked_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("method")
    @classmethod
    def valid_method(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not re.fullmatch(r"[a-z][a-z0-9_]{0,63}", normalized):
            raise ValueError("invalid verification method identifier")
        return normalized

    @field_validator("evidence")
    @classmethod
    def bounded_evidence(cls, value: dict[str, Any]) -> dict[str, Any]:
        return _bounded_json_bytes(redact(value) if isinstance(value, dict) else {}, 20_000,
                                   "verification evidence")

    @model_validator(mode="after")
    def verified_needs_confidence(self) -> "VerificationResult":
        if self.verified and self.confidence < 0.5:
            raise ValueError("verified results require confidence >= 0.5")
        if self.verified and not self.evidence:
            raise ValueError("verified results require evidence")
        return self


class AuditEvent(_Contract):
    """Immutable audit record shape for computer-agent activity.

    Persisted exclusively through the existing ``MemoryStore.audit`` path
    (append-only SQL table); nothing in this package can modify or delete the
    audit trail. Events are secret-redacted at construction time.
    """

    id: str = Field(default_factory=lambda: str(uuid4()))
    event: str = Field(min_length=1, max_length=80)
    category: Literal["agent", "computer", "approval", "policy", "security", "errors"] = "computer"
    actor: str = Field("computer-agent", max_length=64)
    task_id: str | None = Field(None, max_length=120)
    details: dict[str, Any] = Field(default_factory=dict)
    created_at: datetime = Field(default_factory=lambda: datetime.now(UTC))

    @field_validator("event")
    @classmethod
    def valid_event(cls, value: str) -> str:
        normalized = value.strip().lower()
        if not EVENT_NAME.fullmatch(normalized):
            raise ValueError("invalid audit event name")
        return normalized

    @field_validator("details")
    @classmethod
    def redacted_details(cls, value: dict[str, Any]) -> dict[str, Any]:
        safe = redact(value)
        if not isinstance(safe, dict):
            raise ValueError("audit details must be an object")
        return _bounded_json_bytes(safe, 10_000, "audit details")


# --------------------------------------------------------------------------- #
# stable provider/tool interfaces (no execution capability in Phase 1)
# --------------------------------------------------------------------------- #


class ComputerAgentDisabledError(RuntimeError):
    """Raised by every disabled stub. Fail closed: never silently no-op."""


class ComputerTool(ABC):
    """Contract for computer-agent capabilities exposed to the agent loop.

    A ComputerTool is *not* registered anywhere by implementing this class;
    registration happens only through ``app.computer.registry.register_computer_tools``,
    which routes the instance through the existing PermissionManager and the
    canonical ``app.tools.base.Registry``. The metadata below mirrors the
    core ``Tool`` contract so both pipelines enforce identical policy.
    """

    name: str
    description: str
    category: ActionCategory = ActionCategory.SCREEN
    risk_level: RiskLevel = RiskLevel.LOW
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    permissions: frozenset[Permission] = frozenset({Permission.SAFE})
    timeout_seconds: float = 20.0
    network_required: bool = False
    sandbox_required: bool = False
    audit_required: bool = True
    idempotent: bool = True
    enabled: bool = True
    requires_approval: bool = False
    disabled_reason: str | None = None
    platforms: list[str] | None = None  # None = all platforms
    provider_kind: ProviderKind | None = None

    def to_core_tool_def(self) -> ToolDef:
        """Canonical metadata bridge into the existing ToolDef schema.

        Single source of truth: this produces exactly the same structure the
        core ``Tool.definition()`` emits, so no policy field can diverge.
        """
        required = sorted(self.permissions, key=str)
        return ToolDef(
            name=self.name,
            description=self.description,
            category=self.category.value,
            risk_level=self.risk_level,
            required_permissions=required,
            permissions=required,
            input_schema=self.input_model.model_json_schema(),
            output_schema=self.output_model.model_json_schema(),
            timeout_seconds=self.timeout_seconds,
            network_required=self.network_required,
            sandbox_required=self.sandbox_required,
            audit_required=self.audit_required,
            idempotent=self.idempotent,
            enabled=self.enabled,
            requires_approval=self.requires_approval,
            disabled_reason=self.disabled_reason,
            platforms=self.platforms or ["linux", "windows", "macos"],
        )

    @abstractmethod
    async def run(self, args: dict[str, Any]) -> dict[str, Any]:
        """Execute the capability. Implementations must not raise raw OS errors."""


class PerceptionProvider(ABC):
    """Screen capture / OCR / vision. Read-only by contract."""

    kind: ProviderKind = ProviderKind.PERCEPTION
    provider_id: str

    @abstractmethod
    async def available(self) -> bool: ...

    @abstractmethod
    async def observe(self, task_id: str, params: dict[str, Any]) -> Observation: ...


class InputProvider(ABC):
    """Mouse/keyboard/window-input synthesis.

    Phase 1 ships NO implementation. Even future implementations must accept
    only pre-approved ``Action`` objects and must honour the emergency stop.
    """

    kind: ProviderKind = ProviderKind.INPUT
    provider_id: str

    @abstractmethod
    async def available(self) -> bool: ...

    @abstractmethod
    async def perform(self, action: Action) -> VerificationResult:
        """Perform one already-approved action. Never plans; never escalates."""


class WindowProvider(ABC):
    """Window enumeration/focus/state. Listing is read-only; activation is an
    input-class capability and inherits the same approval requirements."""

    kind: ProviderKind = ProviderKind.WINDOW
    provider_id: str

    @abstractmethod
    async def available(self) -> bool: ...

    @abstractmethod
    async def list_windows(self) -> list[dict[str, Any]]: ...


class BrowserProvider(ABC):
    """Playwright-style browser automation adapter (later phase).

    Web content returned through this interface is untrusted data and must be
    wrapped by callers before reaching any model.
    """

    kind: ProviderKind = ProviderKind.BROWSER
    provider_id: str

    @abstractmethod
    async def available(self) -> bool: ...

    @abstractmethod
    async def navigate(self, url: str) -> Observation: ...


class TaskPlanner(ABC):
    """Turns a ComputerTask into a bounded list of Actions + ToolCalls.

    Planners receive only sanitized context and registered tool definitions;
    they never receive OS privileges and their output is schema-validated and
    policy-checked before anything executes.
    """

    @abstractmethod
    async def plan(self, task: ComputerTask, context: dict[str, Any]) -> list[Action]: ...


class Verifier(ABC):
    """Independent post-condition checking. Unverified work is not complete."""

    @abstractmethod
    async def verify(self, action: Action, observation_before: Observation | None,
                     observation_after: Observation | None) -> VerificationResult: ...


class ApprovalService(ABC):
    """Human approval workflow. Implementations must persist decisions to the
    append-only audit trail and default to DENIED on timeout/expiry."""

    @abstractmethod
    async def request(self, item: ApprovalRequest) -> ApprovalRequest: ...

    @abstractmethod
    async def resolve(self, approval_id: str, decision: ApprovalDecision,
                      *, actor: str = "user", note: str = "") -> ApprovalRequest: ...

    @abstractmethod
    async def status(self, approval_id: str) -> ApprovalRequest: ...


class ComputerPolicy(ABC):
    """Risk/policy decision point for computer actions.

    Must be deterministic and must fail closed: any internal error resolves to
    ``DENY``. Implementations may consult Settings, PermissionManager and the
    Control Center, but may never be modified by the agent itself.
    """

    @abstractmethod
    def evaluate(self, action: Action) -> PolicyEffect: ...

    def evaluate_or_deny(self, action: Action) -> PolicyEffect:
        """Fail-closed wrapper used by every caller."""
        try:
            return self.evaluate(action)
        except Exception:
            return PolicyEffect.DENY


# --------------------------------------------------------------------------- #
# Phase-1 disabled stubs (prove the boundary exists without any capability)
# --------------------------------------------------------------------------- #


class DisabledPerceptionProvider(PerceptionProvider):
    provider_id = "disabled-perception"

    async def available(self) -> bool:
        return False

    async def observe(self, task_id: str, params: dict[str, Any]) -> Observation:
        raise ComputerAgentDisabledError("COMPUTER_AGENT_DISABLED: perception is not available")


class DisabledInputProvider(InputProvider):
    provider_id = "disabled-input"

    async def available(self) -> bool:
        return False

    async def perform(self, action: Action) -> VerificationResult:
        raise ComputerAgentDisabledError("COMPUTER_AGENT_DISABLED: input synthesis is not available")


class DisabledWindowProvider(WindowProvider):
    provider_id = "disabled-window"

    async def available(self) -> bool:
        return False

    async def list_windows(self) -> list[dict[str, Any]]:
        raise ComputerAgentDisabledError("COMPUTER_AGENT_DISABLED: window listing is not available")


class DisabledBrowserProvider(BrowserProvider):
    provider_id = "disabled-browser"

    async def available(self) -> bool:
        return False

    async def navigate(self, url: str) -> Observation:
        raise ComputerAgentDisabledError("COMPUTER_AGENT_DISABLED: browser automation is not available")
