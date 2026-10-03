"""SecureAgent Control Center — the backend runtime authority.

The Desktop Control Center (Electron) is only a CONTROL PANEL. This module is
the SECURITY AUTHORITY: every switch displayed in the UI maps to a validated,
typed, versioned, persisted, audited field in the runtime control state, and
every runtime component (terminal executor, agent, automation engine, network
client, LLM provider) consults the gates in this module at execution time.

Properties mandated by the Desktop Control Center spec (section 19):

* validated  — every patch is validated against the typed ControlState model;
               unknown fields, bad types, and security violations are rejected
* typed      — pydantic models with strict field types and bounds
* versioned  — every applied change increments ``revision``; ``schema_version``
               migrates the on-disk document
* atomic     — the state file is written to a temp file and ``os.replace``d;
               a crash can never leave a half-written document
* recoverable— the last known valid configuration is kept as ``.bak``; a
               corrupted file is replaced by the backup or safe defaults and
               the recovery is audited
* audited    — every applied change, rejection cause, recovery, emergency
               stop and resume is written to the audit log

The frontend is NEVER the authority: it can only request changes through the
authenticated PATCH /api/v1/config transaction, and mandatory security
protections cannot be disabled through any path (see MANDATORY_PROTECTIONS).
"""
from __future__ import annotations

import asyncio
import json
import logging
import os
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, ClassVar, Literal

from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

logger = logging.getLogger("secureagent.control")

SCHEMA_VERSION = 1

# Protections that can never be turned off through the API. The UI must render
# them as locked. (Spec sections 3, 14: "mandatory protections cannot be
# disabled through normal UI" and "The AI is NEVER the security authority".)
MANDATORY_PROTECTIONS = (
    "command_policy",
    "filesystem_protection",
    "network_policy",
    "approval_system",
    "audit_logging",
    "secret_redaction",
)

SudoMode = Literal["disabled", "approval_required", "host_control_only"]
NetworkMode = Literal["disabled", "localhost", "private", "external", "full"]


class ControlModelError(ValueError):
    """Raised when a configuration patch violates the control policy."""


class AgentControls(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    # Auto Planning / Auto Tool Calling / Auto Execution / Auto Retry each
    # control real backend behavior inside app.agent.Agent.
    auto_planning: bool = True
    auto_tool_calling: bool = True
    auto_execution: bool = True
    auto_retry: bool = True


class TerminalControls(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    # Restricted Mode is MANDATORY while Secure Mode is active (the
    # cross-field validator in ControlState enforces this).
    restricted_mode: bool = True
    command_approval: bool = True
    allow_sudo: bool = False
    allow_network: bool = False
    max_command_time_seconds: int = Field(30, ge=1, le=600)
    max_commands_per_task: int = Field(12, ge=1, le=50)
    max_output_bytes: int = Field(200_000, ge=1_000, le=5_000_000)


class HostControlControls(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Host Control is NEVER enabled automatically and never by the AI. The
    # update path requires explicit user confirmation (confirm=True) and the
    # desktop shows a warning dialog before sending it.
    enabled: bool = False
    auto_off_on_exit: bool = True


class NetworkControls(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # The five-tier network model. ``disabled`` is the safe default.
    mode: NetworkMode = "disabled"
    allowed_destinations: list[str] = Field(default_factory=list, max_length=64)
    blocked_destinations: list[str] = Field(default_factory=list, max_length=64)

    @field_validator("mode", mode="before")
    @classmethod
    def normalize_mode(cls, value: Any) -> Any:
        # ``local`` is a legacy alias for ``localhost``.
        return "localhost" if value == "local" else value

    @field_validator("allowed_destinations", "blocked_destinations")
    @classmethod
    def clean_destinations(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for item in value:
            text = str(item).strip().lower()
            if not text or len(text) > 253:
                raise ControlModelError("network destinations must be 1-253 character hostnames")
            allowed = set("abcdefghijklmnopqrstuvwxyz0123456789.-:*[]")
            if not set(text) <= allowed:
                raise ControlModelError("network destinations accept hostnames, wildcards, and CIDR-style '*' only")
            if text not in cleaned:
                cleaned.append(text)
        return cleaned


class SudoControls(BaseModel):
    model_config = ConfigDict(extra="forbid")
    mode: SudoMode = "disabled"


class FilesystemControls(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Extra jail roots the user explicitly approved. The backend canonical
    # path enforcer validates every entry (API layer) and the terminal
    # executor unions them into its jail at runtime.
    allowed_paths: list[str] = Field(default_factory=list, max_length=32)
    # Protected locations are fixed by policy; the list is informational and
    # enforcement lives in linux_sandbox.classify_path_sensitivity.
    protected_paths: list[str] = Field(default_factory=lambda: [
        "/etc/shadow", "/etc/sudoers", "/etc/passwd-",
        "~/.ssh", "credential files", "private keys (*.pem, *.key)", ".env files",
    ])


ROUTING_MODES = ("auto", "local_first", "cloud_first", "cost_aware", "speed_first",
                 "privacy_first", "manual")
ROUTING_ROUTES = ("chat", "planner", "coding", "vision", "security", "reviewer",
                  "embedding", "fast")


class AIControls(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    ollama_enabled: bool = True
    model: str | None = Field(None, max_length=200)
    temperature: float | None = Field(None, ge=0, le=2)
    context_size: int | None = Field(None, ge=512, le=262_144)
    max_tokens: int | None = Field(None, ge=128, le=131_072)
    tool_calling: bool = True
    planning: bool = True
    # --- multi-model routing (Phase 13) ------------------------------------ #
    # Remote/cloud providers stay OFF until the operator turns this on AND
    # enables the same switch in Settings. Local providers (Ollama, or any
    # provider whose base_url is loopback) are unaffected by this gate.
    remote_providers_enabled: bool = False
    routing_mode: Literal["auto", "local_first", "cloud_first", "cost_aware",
                          "speed_first", "privacy_first", "manual"] = "local_first"
    # Explicit per-route assignment as "<provider-id>:<model>". An assignment
    # is honoured only when that provider is enabled+configured; otherwise the
    # router falls back to the selected mode (never to an unconfigured vendor).
    route_models: dict[str, str] = Field(default_factory=dict, max_length=32)
    # Ordered provider preference for fallback. Providers not listed keep their
    # mode-derived order and remain eligible after the listed ones.
    fallback_chain: list[str] = Field(default_factory=list, max_length=16)

    @field_validator("route_models")
    @classmethod
    def valid_route_models(cls, value: dict[str, str]) -> dict[str, str]:
        for route, target in value.items():
            if route not in ROUTING_ROUTES:
                raise ValueError(f"unknown routing route: {route}")
            if not isinstance(target, str) or not target.strip():
                raise ValueError("route assignment must be '<provider>:<model>'")
            if ":" not in target:
                raise ValueError("route assignment must be '<provider>:<model>'")
            provider_id = target.split(":", 1)[0]
            if not provider_id or not all(character.islower() or character.isdigit()
                                          or character in "._-"
                                          for character in provider_id):
                raise ValueError("route assignment provider id is invalid")
        return value

    @field_validator("fallback_chain")
    @classmethod
    def valid_fallback_chain(cls, value: list[str]) -> list[str]:
        cleaned: list[str] = []
        for item in value:
            identifier = str(item).strip().lower()
            if not identifier:
                continue
            if not all(character.islower() or character.isdigit() or character in "._-"
                       for character in identifier):
                raise ValueError("fallback chain entries must be provider ids")
            if identifier not in cleaned:
                cleaned.append(identifier)
        return cleaned


class MemoryControls(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    ingestion: bool = True
    retrieval: bool = True
    max_context_items: int = Field(50, ge=1, le=500)
    max_documents: int = Field(5_000, ge=1, le=100_000)
    sensitive_filtering: bool = True


class RAGControls(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True
    ingestion_enabled: bool = True
    retrieval_enabled: bool = True


class AutomationControls(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    scheduled_tasks: bool = False
    automatic_workflows: bool = False
    auto_retry: bool = False
    background_tasks: bool = True
    paused: bool = False  # runtime pause-all (persisted so it survives restarts)


class WorkflowsControls(BaseModel):
    model_config = ConfigDict(extra="forbid")
    enabled: bool = True


class BrowserControls(BaseModel):
    """Phase 09 browser automation. OFF by default (spec: secure defaults).

    ``sensitive_action_approval`` is MANDATORY and cannot be turned off: a
    patch that sets it False is rejected by the ControlState validator, so a
    purchase/send/delete/credential action can never lose its approval gate.
    """
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    headless: bool = True
    sensitive_action_approval: bool = True
    downloads: bool = False
    uploads: bool = False
    max_sessions: int = Field(2, ge=1, le=8)


class VoiceControls(BaseModel):
    """Phase 11 voice I/O. OFF by default; push-to-talk is the default mode."""
    model_config = ConfigDict(extra="forbid")
    enabled: bool = False
    push_to_talk: bool = True
    wake_word_enabled: bool = False
    microphone_permission: bool = False
    stt_provider: str = Field("auto", max_length=64)
    tts_provider: str = Field("auto", max_length=64)
    speak_replies: bool = False


class SecurityControls(BaseModel):
    model_config = ConfigDict(extra="forbid")
    # Every field below is MANDATORY. A patch that attempts to set any of
    # them False is rejected with MANDATORY_PROTECTION (ControlState
    # validator) — regardless of secure_mode or the requesting actor.
    command_policy: bool = True
    filesystem_protection: bool = True
    network_policy: bool = True
    approval_system: bool = True
    audit_logging: bool = True
    secret_redaction: bool = True


class ControlState(BaseModel):
    """Typed runtime control state (the configuration source of truth)."""

    model_config = ConfigDict(extra="forbid")
    secure_mode: bool = True
    agent: AgentControls = Field(default_factory=AgentControls)
    terminal: TerminalControls = Field(default_factory=TerminalControls)
    host_control: HostControlControls = Field(default_factory=HostControlControls)
    network: NetworkControls = Field(default_factory=NetworkControls)
    sudo: SudoControls = Field(default_factory=SudoControls)
    filesystem: FilesystemControls = Field(default_factory=FilesystemControls)
    ai: AIControls = Field(default_factory=AIControls)
    browser: BrowserControls = Field(default_factory=BrowserControls)
    voice: VoiceControls = Field(default_factory=VoiceControls)
    memory: MemoryControls = Field(default_factory=MemoryControls)
    rag: RAGControls = Field(default_factory=RAGControls)
    automation: AutomationControls = Field(default_factory=AutomationControls)
    workflows: WorkflowsControls = Field(default_factory=WorkflowsControls)
    security: SecurityControls = Field(default_factory=SecurityControls)

    # -- validation --------------------------------------------------------- #

    @model_validator(mode="after")
    def enforce_security_invariants(self) -> "ControlState":
        if self.security.command_policy is False or self.security.audit_logging is False:
            raise ControlModelError("mandatory security protections cannot be disabled")
        if any(getattr(self.security, name) is False for name in MANDATORY_PROTECTIONS):
            raise ControlModelError("mandatory security protections cannot be disabled")
        if self.secure_mode and not self.terminal.restricted_mode:
            # Secure Mode mandates the restricted sandbox; disabling it
            # requires turning Secure Mode off first (explicit user action).
            raise ControlModelError("restricted terminal mode is mandatory while Secure Mode is active")
        if self.browser.sensitive_action_approval is False:
            # Mirrors MANDATORY_PROTECTIONS for the browser: the approval gate
            # in front of purchase/send/delete/credential actions is permanent.
            raise ControlModelError("browser sensitive-action approval cannot be disabled")
        if self.terminal.allow_sudo and self.sudo.mode == "disabled":
            # Terminal-level sudo toggle requires the master sudo switch to
            # permit at least approval-gated usage.
            raise ControlModelError("terminal sudo requires the SUDO master switch (set it to approval_required or host_control_only)")
        return self

    # -- merge-patch -------------------------------------------------------- #

    SECTIONS: ClassVar[tuple[str, ...]] = ("agent", "terminal", "host_control", "network", "sudo",
                                           "filesystem", "ai", "browser", "voice", "memory", "rag",
                                           "automation", "workflows", "security")

    @classmethod
    def apply_patch(cls, base: "ControlState", patch: dict[str, Any]) -> "ControlState":
        """Validate a merge-patch and return a NEW state.

        The patch is a nested dict of {section: {field: value}} (top-level
        scalars: secure_mode). Unknown fields, unknown sections and invalid
        values raise ControlModelError with the offending field. The base
        state is never mutated: callers persist only after validation
        succeeds, giving single-transaction semantics.
        """
        if not isinstance(patch, dict) or not patch:
            raise ControlModelError("configuration patch must be a non-empty object")
        payload = base.model_dump()
        for key, value in patch.items():
            if key == "secure_mode":
                if not isinstance(value, bool):
                    raise ControlModelError("secure_mode must be a boolean")
                payload[key] = value
                continue
            if key not in cls.SECTIONS:
                raise ControlModelError(f"unknown configuration section: {key}")
            if not isinstance(value, dict):
                raise ControlModelError(f"section {key} must be an object of field values")
            section = payload[key]
            for field_name, field_value in value.items():
                if field_name not in section:
                    raise ControlModelError(f"unknown configuration field: {key}.{field_name}")
                section[field_name] = field_value
        try:
            return cls.model_validate(payload)
        except ValidationError as error:
            raise ControlModelError(_describe_validation_error(error)) from None


# --------------------------------------------------------------------------- #
# Runtime telemetry (never persisted — this is live observability state)
# --------------------------------------------------------------------------- #

class NetworkTelemetry(BaseModel):
    request_count: int = 0
    blocked_count: int = 0
    last_request: str | None = None
    last_destination: str | None = None
    last_result: str | None = None  # allowed | blocked


# --------------------------------------------------------------------------- #
# ControlCenter
# --------------------------------------------------------------------------- #

class ControlCenter:
    """Owns the runtime control state, its persistence and its gates."""

    def __init__(self, state_file: Path, store=None):
        self.state_file = Path(state_file)
        self.backup_file = self.state_file.with_suffix(self.state_file.suffix + ".bak")
        self.store = store
        self.revision = 1
        self.updated_at: str = datetime.now(UTC).isoformat()
        self.updated_by: str = "system"
        self.emergency_stopped: bool = False
        self._pre_emergency: dict[str, Any] | None = None
        self._listeners: set[asyncio.Queue] = set()
        self._lock = asyncio.Lock()
        self.telemetry = NetworkTelemetry()
        self.recovery: dict[str, Any] | None = None
        self._task_command_counts: dict[str, int] = {}
        # Kill-switch callbacks registered by main.py at startup:
        # emergency stop must cancel real running work, not just flip flags.
        self._kill_switches: dict[str, Any] = {}
        self.state: ControlState = ControlState()
        self._load()

    # -- persistence -------------------------------------------------------- #

    def _document(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "revision": self.revision,
            "updated_at": self.updated_at,
            "updated_by": self.updated_by,
            "emergency_stopped": self.emergency_stopped,
            "state": self.state.model_dump(),
        }

    def _load(self) -> None:
        """Load the persisted state with backup recovery (spec 19)."""
        loaded, recovery = self._read_document(self.state_file)
        if loaded is None:
            loaded, recovery2 = self._read_document(self.backup_file)
            recovery = recovery or recovery2
        if loaded is None:
            # No valid file anywhere: start from safe defaults and record why.
            self.recovery = recovery or {
                "reason": "no_configuration_file", "file": str(self.state_file),
            }
            self.state = ControlState()
            self.revision = 1
            self._persist()
            return
        self._adopt(loaded)
        if recovery:
            self.recovery = recovery
            logger.warning("control center recovered configuration: %s", recovery.get("reason"))
            # Rewrite the last known valid document over the corrupted file so
            # every subsequent start loads a healthy state file.
            try:
                self._persist()
            except OSError:
                logger.exception("could not rewrite recovered control center state")

    def _read_document(self, file: Path) -> tuple[dict[str, Any] | None, dict[str, Any] | None]:
        try:
            raw = file.read_text(encoding="utf-8")
        except FileNotFoundError:
            return None, None
        except OSError as error:
            return None, {"reason": "configuration_file_unreadable", "file": str(file), "error": str(error)[:200]}
        try:
            document = json.loads(raw)
            if not isinstance(document, dict):
                raise ValueError("document is not an object")
            schema_version = int(document.get("schema_version", -1))
            if schema_version != SCHEMA_VERSION:
                # Forward/reverse version mismatches are not migratable yet;
                # fall back to the backup or defaults rather than guessing.
                return None, {"reason": "unsupported_schema_version", "file": str(file), "found": schema_version}
            state = ControlState.model_validate(document.get("state") or {})
        except Exception as error:  # corrupted or invalid: recover
            return None, {"reason": "configuration_corrupted", "file": str(file), "error": str(error)[:200]}
        return {"document": document, "state": state}, None

    def _adopt(self, loaded: dict[str, Any]) -> None:
        document = loaded["document"]
        state: ControlState = loaded["state"]
        self.state = state
        self.revision = max(int(document.get("revision", 1) or 1), 1)
        self.updated_at = str(document.get("updated_at") or self.updated_at)
        self.updated_by = str(document.get("updated_by") or "system")
        self.emergency_stopped = bool(document.get("emergency_stopped", False))
        # Emergency Stop is fail-closed and survives restart. Only an
        # explicit Resume action may clear it.
        if state.host_control.enabled and state.host_control.auto_off_on_exit:
            object.__setattr__(state, "host_control", state.host_control.model_copy(update={"enabled": False}))
            self._persist()

    def _persist(self) -> None:
        """Atomically persist the current document (tmp + fsync + replace)."""
        self.state_file.parent.mkdir(parents=True, exist_ok=True)
        payload = json.dumps(self._document(), indent=2, ensure_ascii=False)
        # Keep the last known valid configuration as the recovery source.
        if self.state_file.exists():
            try:
                os.replace(self.state_file, self.backup_file)
            except OSError:
                pass
        handle = tempfile.NamedTemporaryFile(
            "w", encoding="utf-8", dir=self.state_file.parent,
            prefix=".control-center-", suffix=".tmp", delete=False,
        )
        try:
            handle.write(payload)
            handle.flush()
            os.fsync(handle.fileno())
            handle.close()
            os.chmod(handle.name, 0o600)
            os.replace(handle.name, self.state_file)
        except Exception:
            try:
                handle.close()
            except Exception:
                pass
            try:
                os.unlink(handle.name)
            except OSError:
                pass
            raise

    # -- change transaction -------------------------------------------------- #

    async def update(self, patch: dict[str, Any], *, actor: str = "user", confirm: bool = False) -> dict[str, Any]:
        """Validated configuration transaction (spec 23).

        Either every field in the patch is applied and persisted, or nothing
        changes and a ControlModelError is raised. The caller receives the
        new public snapshot.
        """
        if self.emergency_stopped:
            raise ControlModelError("SECUREAGENT_STOPPED: resume before changing configuration")
        async with self._lock:
            # Host Control requires explicit human confirmation; the AI never
            # gets to enable it (spec 6).
            requested_host_control = patch.get("host_control", {}).get("enabled") if isinstance(patch.get("host_control"), dict) else None
            if requested_host_control is True:
                if actor != "user":
                    raise ControlModelError("HOST_CONTROL_FORBIDDEN: only the user may enable Host Control")
                if not confirm:
                    raise ControlModelError(
                        "HOST_CONTROL_REQUIRES_CONFIRMATION: Host Control allows approved operations "
                        "to affect the Linux host — repeat the request with confirm=true"
                    )
            candidate = ControlState.apply_patch(self.state, patch)
            # Security invariants that depend on the requesting actor.
            if actor != "user":
                _assert_user_only_fields(patch)
            previous_state, previous_revision = self.state, self.revision
            self.state = candidate
            self.revision += 1
            self.updated_at = datetime.now(UTC).isoformat()
            self.updated_by = actor
            try:
                self._persist()
            except Exception as error:
                # Roll back in-memory state; disk still holds the previous
                # valid configuration, so UI and backend can never diverge.
                self.state, self.revision = previous_state, previous_revision
                await self._audit("config.persist_failed", {"error": str(error)[:200]})
                raise ControlModelError("configuration could not be persisted") from error
            await self._audit("config.updated", {
                "revision": self.revision, "actor": actor,
                "fields": _changed_fields(previous_state.model_dump(), candidate.model_dump()),
            })
            self._notify()
            return self.snapshot()

    # -- emergency stop / resume --------------------------------------------- #

    def register_kill_switch(self, name: str, callback) -> None:
        """Register an async callback invoked on EMERGENCY STOP.

        main.py registers: terminal process-group killer, agent task
        canceller, automation job canceller. Emergency stop must terminate
        real running work (spec 7 / test 6).
        """
        self._kill_switches[name] = callback

    async def emergency_stop(self, actor: str = "user") -> dict[str, Any]:
        if self.emergency_stopped:
            return self.snapshot()
        async with self._lock:
            self._pre_emergency = self.state.model_dump()
            self.emergency_stopped = True
            results: dict[str, Any] = {}
            for name, callback in list(self._kill_switches.items()):
                try:
                    result = callback()
                    if asyncio.iscoroutine(result) or isinstance(result, asyncio.Future):
                        results[name] = await result
                    else:
                        results[name] = result
                except Exception as error:  # a failed kill switch must not block the others
                    results[name] = {"error": str(error)[:200]}
            # Host Control must turn OFF on emergency stop (spec 6/7).
            if self.state.host_control.enabled:
                self.state = ControlState.model_validate({
                    **self.state.model_dump(),
                    "host_control": {**self.state.host_control.model_dump(), "enabled": False},
                })
                results["host_control"] = "disabled"
            self.revision += 1
            self.updated_at = datetime.now(UTC).isoformat()
            self.updated_by = actor
            self._persist()
            await self._audit("control.emergency_stop", {
                "revision": self.revision, "kill_switches": results,
                "pre_emergency_revision": self.revision - 1,
            })
            self._notify()
            return self.snapshot()

    async def resume(self, actor: str = "user") -> dict[str, Any]:
        if not self.emergency_stopped:
            return self.snapshot()
        async with self._lock:
            previous = self._pre_emergency or {}
            self.emergency_stopped = False
            self._pre_emergency = None
            if previous:
                try:
                    self.state = ControlState.model_validate(previous)
                except Exception:
                    # A snapshot that no longer validates (policy change) falls
                    # back to safe defaults rather than staying stopped.
                    self.state = ControlState()
            self.revision += 1
            self.updated_at = datetime.now(UTC).isoformat()
            self.updated_by = actor
            self._persist()
            await self._audit("control.resumed", {"revision": self.revision, "restored": bool(previous)})
            self._notify()
            return self.snapshot()

    # -- shutdown hook -------------------------------------------------------- #

    async def on_backend_exit(self) -> None:
        """Host Control auto-off on application exit (spec 6, config-gated).

        This is an INTERNAL safety action performed by the system itself: it
        only ever DISABLES Host Control, never enables it. It must not go
        through ``update()`` because the user-only-fields guard correctly
        rejects non-user actors touching ``host_control`` — routing the
        shutdown hook through that path made auto-off silently fail forever
        (observed on a live run), leaving HOST_CONTROL active across
        restarts. The guard for API-driven/AI-driven requests is unchanged.
        """
        if self.state.host_control.enabled and self.state.host_control.auto_off_on_exit:
            try:
                async with self._lock:
                    self.state.host_control.enabled = False
                    self.revision += 1
                    self.updated_at = datetime.now(UTC).isoformat()
                    self.updated_by = "system"
                    self._persist()
                    await self._audit("host_control.auto_disabled", {"reason": "application_exit"})
                self._notify()
            except Exception:
                logger.exception("host_control auto-disable failed")

    # -- runtime gates (consumed by terminal/agent/automation/network/llm) ---- #

    @property
    def blocked_by_emergency(self) -> bool:
        return self.emergency_stopped

    def check_terminal(self) -> None:
        """Raise PermissionError unless terminal execution is allowed."""
        if self.emergency_stopped:
            raise PermissionError("SECUREAGENT_STOPPED: emergency stop is active — terminal execution is disabled")
        if not self.state.terminal.enabled:
            raise PermissionError("TERMINAL_DISABLED_BY_CONTROL_CENTER: the Terminal master switch is OFF")

    def terminal_limits(self) -> dict[str, int]:
        state = self.state.terminal
        return {
            "max_command_time_seconds": state.max_command_time_seconds,
            "max_commands_per_task": state.max_commands_per_task,
            "max_output_bytes": state.max_output_bytes,
            "command_approval": 1 if state.command_approval else 0,
            "restricted_mode": 1 if state.restricted_mode else 0,
            "allow_network": 1 if state.allow_network else 0,
        }

    def task_command_count(self, task_id: str | None) -> int:
        if not task_id:
            return 0
        return self._task_command_counts.get(task_id, 0)

    def record_task_command(self, task_id: str | None) -> None:
        if task_id:
            self._task_command_counts[task_id] = self._task_command_counts.get(task_id, 0) + 1
            if len(self._task_command_counts) > 1_000:
                # Bound the tracker; agent tasks are short-lived.
                for key in list(self._task_command_counts)[:500]:
                    self._task_command_counts.pop(key, None)

    def check_sudo(self) -> None:
        """Raise PermissionError unless sudo usage is currently permitted."""
        if self.emergency_stopped:
            raise PermissionError("SECUREAGENT_STOPPED: sudo is disabled during emergency stop")
        mode = self.state.sudo.mode
        if mode == "disabled" or not self.state.terminal.allow_sudo:
            raise PermissionError("TERMINAL_SUDO_DISABLED: sudo is disabled by the Control Center policy")

    def check_host_control_operation(self) -> None:
        if self.emergency_stopped:
            raise PermissionError("SECUREAGENT_STOPPED: host-control operations are disabled")
        if not self.state.host_control.enabled:
            raise PermissionError("HOST_CONTROL_DISABLED: enable Host Control in the Control Center first")

    def check_network(self, destination: str | None = None) -> None:
        """Runtime network policy gate. Records telemetry, raises when blocked."""
        if self.emergency_stopped:
            self.telemetry.blocked_count += 1
            self._record_network(destination, "blocked")
            raise PermissionError("SECUREAGENT_STOPPED: network access is disabled during emergency stop")
        mode = self.state.network.mode
        # NOTE: terminal.allow_network governs whether terminal COMMANDS may
        # touch the network (enforced by the command policy layer); the gate
        # here is the master network policy for all tool HTTP traffic.
        if mode == "disabled":
            self.telemetry.blocked_count += 1
            self._record_network(destination, "blocked")
            raise PermissionError("NETWORK_BLOCKED_BY_CONTROL_CENTER: the Network master switch is OFF")
        if destination:
            host = destination.strip().lower()
            for pattern in self.state.network.blocked_destinations:
                if _destination_matches(host, pattern):
                    self.telemetry.blocked_count += 1
                    self._record_network(destination, "blocked")
                    raise PermissionError(f"NETWORK_DESTINATION_BLOCKED: {pattern} is on the blocked list")
            if self.state.network.allowed_destinations and not any(
                _destination_matches(host, pattern) for pattern in self.state.network.allowed_destinations
            ):
                self.telemetry.blocked_count += 1
                self._record_network(destination, "blocked")
                raise PermissionError("NETWORK_DESTINATION_NOT_ALLOWED: destination is not on the allow list")
        self.telemetry.request_count += 1
        self._record_network(destination, "allowed")

    def _record_network(self, destination: str | None, result: str) -> None:
        self.telemetry.last_request = datetime.now(UTC).isoformat()
        self.telemetry.last_destination = (destination or "")[:253] or None
        self.telemetry.last_result = result

    def agent_active(self) -> bool:
        return not self.emergency_stopped and self.state.agent.enabled

    def agent_flags(self) -> dict[str, bool]:
        state = self.state.agent
        return {
            "auto_planning": state.auto_planning and self.state.ai.planning,
            "auto_tool_calling": state.auto_tool_calling and self.state.ai.tool_calling,
            "auto_execution": state.auto_execution,
            "auto_retry": state.auto_retry,
        }

    def ai_active(self) -> bool:
        return not self.emergency_stopped and self.state.ai.enabled

    def ollama_active(self) -> bool:
        return self.ai_active() and self.state.ai.ollama_enabled

    def ai_limits(self) -> dict[str, Any]:
        state = self.state.ai
        return {
            "model": state.model,
            "temperature": state.temperature,
            "context_size": state.context_size,
            "max_tokens": state.max_tokens,
        }

    def provider_routing(self) -> dict[str, Any]:
        """Secret-free routing policy consumed by app.providers.ModelRouter.

        Remote providers require BOTH the Settings switch and this Control
        Center switch, so flipping either one OFF immediately stops egress.
        """
        state = self.state.ai
        settings_allows = True
        try:
            from app.config import settings as _settings
            settings_allows = bool(getattr(_settings(), "remote_providers_enabled", False))
        except Exception:
            settings_allows = False
        return {
            "remote_providers_enabled": bool(state.remote_providers_enabled and settings_allows),
            "control_center_remote_switch": bool(state.remote_providers_enabled),
            "settings_remote_switch": settings_allows,
            "routing_mode": state.routing_mode,
            "route_models": dict(state.route_models),
            "fallback_chain": list(state.fallback_chain),
            "ai_active": self.ai_active(),
            "ollama_enabled": bool(state.ollama_enabled),
        }

    def browser_active(self) -> bool:
        return (not self.emergency_stopped and self.state.browser.enabled
                and self.state.agent.enabled)

    def browser_limits(self) -> dict[str, Any]:
        state = self.state.browser
        return {"headless": state.headless, "max_sessions": state.max_sessions,
                "downloads": state.downloads, "uploads": state.uploads,
                "sensitive_action_approval": state.sensitive_action_approval}

    def voice_active(self) -> bool:
        return (not self.emergency_stopped and self.state.voice.enabled
                and self.state.voice.microphone_permission)

    def voice_limits(self) -> dict[str, Any]:
        state = self.state.voice
        return {"push_to_talk": state.push_to_talk, "wake_word_enabled": state.wake_word_enabled,
                "stt_provider": state.stt_provider, "tts_provider": state.tts_provider,
                "speak_replies": state.speak_replies,
                "microphone_permission": state.microphone_permission}

    def memory_active(self) -> bool:
        return not self.emergency_stopped and self.state.memory.enabled

    def rag_active(self) -> bool:
        return not self.emergency_stopped and self.state.rag.enabled

    def automation_active(self) -> bool:
        state = self.state.automation
        return (not self.emergency_stopped and state.enabled
                and state.scheduled_tasks and state.background_tasks and not state.paused)

    def workflows_active(self) -> bool:
        return not self.emergency_stopped and self.state.workflows.enabled

    def extra_allowed_roots(self) -> list[str]:
        return list(self.state.filesystem.allowed_paths)

    # -- listeners (live configuration sync, spec 24) ------------------------- #

    def subscribe(self) -> asyncio.Queue:
        queue: asyncio.Queue = asyncio.Queue(maxsize=16)
        self._listeners.add(queue)
        return queue

    def unsubscribe(self, queue: asyncio.Queue) -> None:
        self._listeners.discard(queue)

    def _notify(self) -> None:
        for queue in list(self._listeners):
            try:
                queue.put_nowait(self.revision)
            except asyncio.QueueFull:
                pass

    # -- audit ---------------------------------------------------------------- #

    async def _audit(self, event: str, details: dict[str, Any]) -> None:
        if self.store is None:
            return
        try:
            await self.store.audit(event, details, actor="control-center")
        except Exception:  # auditing must never break control operations
            logger.exception("control center audit write failed")

    # -- snapshot -------------------------------------------------------------- #

    def snapshot(self) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "revision": self.revision,
            "updated_at": self.updated_at,
            "updated_by": self.updated_by,
            "emergency_stopped": self.emergency_stopped,
            "secure_mode": self.state.secure_mode,
            "state": self.state.model_dump(),
            "network_telemetry": self.telemetry.model_dump(),
            "recovery": self.recovery,
        }


# --------------------------------------------------------------------------- #
# helpers
# --------------------------------------------------------------------------- #

def _assert_user_only_fields(patch: dict[str, Any]) -> None:
    """Non-user actors (defence in depth against an AI-driven request) may not
    touch security-relevant sections. The agent has no tool that reaches this
    module, but the backend must still enforce authority boundaries."""
    forbidden = {"secure_mode", "sudo", "host_control", "security", "network", "agent"}
    touched = [key for key in patch if key in forbidden]
    if touched:
        raise ControlModelError(f"only the user may modify sections: {', '.join(sorted(touched))}")


def _changed_fields(before: dict[str, Any], after: dict[str, Any]) -> list[str]:
    changed: list[str] = []
    for section, value in after.items():
        old = before.get(section)
        if isinstance(value, dict) and isinstance(old, dict):
            for field_name, field_value in value.items():
                if old.get(field_name) != field_value:
                    changed.append(f"{section}.{field_name}")
        elif old != value:
            changed.append(str(section))
    return changed


def _destination_matches(host: str, pattern: str) -> bool:
    """Simple hostname/wildcard matcher for the allow/block lists."""
    if pattern in {"*", host}:
        return True
    if pattern.startswith("*."):
        suffix = pattern[1:]
        return host.endswith(suffix)
    return host == pattern


def _describe_validation_error(error: ValidationError) -> str:
    """Render a pydantic ValidationError as a single-line policy message."""
    parts = []
    for item in error.errors(include_url=False):
        location = ".".join(str(part) for part in item.get("loc", ()) if part not in ("__root__",))
        message = str(item.get("msg", "invalid value"))
        parts.append(f"{location}: {message}" if location else message)
    return "configuration rejected — " + "; ".join(parts[:5])


# --------------------------------------------------------------------------- #
# Process-wide singleton (lazy — imported by runtime gates)
# --------------------------------------------------------------------------- #

_instance: ControlCenter | None = None


def set_control_center(instance: ControlCenter | None) -> None:
    global _instance
    _instance = instance


def get_control_center() -> ControlCenter | None:
    return _instance
