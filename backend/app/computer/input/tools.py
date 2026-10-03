"""Phase 5 computer tools — registered ONLY via the existing bridge.

Each tool is a ``ComputerTool`` whose ``run`` builds a declarative ``Action``,
asks the installed ``ComputerPolicy`` (fail closed on anything but ALLOW),
honours dry-run, then dispatches to the concrete adapter. Typed text never
appears in returned output; only character counts and static codes do.

Registration path (identical for every capability):
    tools list -> register_computer_tools() -> PermissionManager.apply()
              -> canonical Registry -> ToolExecutionPipeline gates.
"""

from __future__ import annotations

from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field

from app.computer.contracts import (
    Action,
    ActionCategory,
    ComputerAgentDisabledError,
    ComputerPolicy,
    ComputerTool,
    PolicyEffect,
)
from app.computer.input.adapters import LinuxInputAdapter, LinuxWindowAdapter
from app.computer.input.geometry import InputValidationError, scrub_typed_text
from app.models import Permission, Reversibility, RiskLevel


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class MouseArgs(_Strict):
    operation: str = Field(min_length=1, max_length=32)
    x: int = Field(ge=-32768, le=32767)
    y: int = Field(ge=-32768, le=32767)
    button: str = Field("single", max_length=16)
    direction: str = Field("down", max_length=8)
    amount: int = Field(3, ge=-20, le=20)
    to_x: int | None = Field(None, ge=-32768, le=32767)
    to_y: int | None = Field(None, ge=-32768, le=32767)
    dry_run: bool = False


class KeyboardArgs(_Strict):
    operation: str = Field("type", max_length=32)
    text: str | None = Field(None, min_length=1, max_length=10_000)
    key: str | None = Field(None, min_length=1, max_length=32)
    keys: str | None = Field(None, min_length=1, max_length=128)
    window_id: str | None = Field(None, max_length=32)
    dry_run: bool = False


class WindowArgs(_Strict):
    window_id: str = Field(min_length=1, max_length=32)
    dry_run: bool = False


class EmptyArgs(_Strict):
    pass


class InputOutput(BaseModel):
    """Static-shaped result: identifiers, booleans and counts only."""
    model_config = ConfigDict(extra="forbid")
    verified: bool
    simulated: bool = False
    operation: str = Field(max_length=64)
    failures: list[str] = Field(default_factory=list, max_length=20)
    evidence: dict[str, Any] = Field(default_factory=dict)


_MOUSE_OPS = {"move", "click", "double_click", "right_click", "scroll", "drag"}
_KEYBOARD_OPS = {"type", "keypress", "hotkey", "focus"}
_WINDOW_OPS = {"focus", "raise", "minimize", "close"}


def _policy_effect(policy: ComputerPolicy | None, action: Action) -> str:
    if policy is None:
        # No policy installed => fail closed (never execute without one).
        return PolicyEffect.DENY.value
    try:
        return policy.evaluate_or_deny(action).value
    except Exception:
        return PolicyEffect.DENY.value


class _BaseInputTool(ComputerTool):
    platforms = ["linux"]
    provider_kind = None
    network_required = False
    sandbox_required = False
    audit_required = True
    idempotent = False          # physical actions are side effects
    reversibility = Reversibility.PARTIAL
    permissions = frozenset({Permission.EXECUTE})
    requires_approval = True    # permission manager escalates HIGH anyway
    risk_level = RiskLevel.HIGH
    timeout_seconds = 15.0

    def __init__(self, adapter_provider: Callable[[], LinuxInputAdapter | None],
                 policy_provider: Callable[[], ComputerPolicy | None]):
        self._adapter_provider = adapter_provider
        self._policy_provider = policy_provider

    def _adapter(self) -> LinuxInputAdapter:
        adapter = self._adapter_provider()
        if adapter is None:
            raise ComputerAgentDisabledError(
                "COMPUTER_AGENT_DISABLED: input synthesis unavailable")
        return adapter

    async def _perform(self, action: Action, dry_run: bool) -> dict[str, Any]:
        effect = _policy_effect(self._policy_provider(), action)
        if effect != PolicyEffect.ALLOW.value:
            # The pipeline also blocks non-ALLOW before reaching here; this is
            # defense-in-depth so direct adapter misuse still fails closed.
            raise PermissionError(f"COMPUTER_POLICY_DENIED: {effect} for {action.operation}")
        if dry_run:
            return {"verified": True, "simulated": True,
                    "operation": action.operation, "failures": [],
                    "evidence": {"dry_run": True}}
        verification = await self._adapter().perform(action)
        evidence = dict(verification.evidence or {})
        # Belt-and-braces: scrub any accidental credential-looking text from
        # echoed metadata (typed payloads are never present by construction).
        safe_evidence = {k: scrub_typed_text(str(v))[:200] if isinstance(v, str) else v
                         for k, v in evidence.items()}
        return {"verified": bool(verification.verified), "simulated": False,
                "operation": action.operation,
                "failures": [str(f)[:80] for f in verification.failures],
                "evidence": safe_evidence}


class MouseTool(_BaseInputTool):
    name = "mouse_action"
    description = ("Synthesize one mouse gesture (move/click/double_click/"
                   "right_click/scroll/drag) at validated screen coordinates. "
                   "Requires approval; blocked by emergency stop; supports dry_run.")
    category = ActionCategory.MOUSE
    version = "1.0.0"
    input_model = MouseArgs
    output_model = InputOutput

    async def run(self, args: dict[str, Any]) -> dict[str, Any]:
        parsed = MouseArgs.model_validate(args)
        op = parsed.operation.lower()
        if op not in _MOUSE_OPS:
            raise InputValidationError("INPUT_OPERATION_UNSUPPORTED")
        arguments: dict[str, Any] = {"x": parsed.x, "y": parsed.y}
        if op == "click":
            arguments["button"] = parsed.button
        if op == "scroll":
            arguments.update(direction=parsed.direction, amount=parsed.amount)
        if op == "drag":
            if parsed.to_x is None or parsed.to_y is None:
                raise InputValidationError("INPUT_DRAG_TARGET_REQUIRED")
            arguments.update(to_x=parsed.to_x, to_y=parsed.to_y)
        action = Action(task_id="mouse-action", category=ActionCategory.MOUSE,
                        operation=op, target=self.name, arguments=arguments,
                        risk_level=RiskLevel.HIGH,
                        required_permissions=[Permission.EXECUTE],
                        requires_approval=True)
        return await self._perform(action, parsed.dry_run)


class KeyboardTool(_BaseInputTool):
    name = "keyboard_action"
    description = ("Type text (via stdin, never logged), press a single allowed "
                   "key, or a hotkey combination. Requires approval; supports "
                   "dry_run. Typed text content is never persisted or audited.")
    category = ActionCategory.KEYBOARD
    version = "1.0.0"
    input_model = KeyboardArgs
    output_model = InputOutput

    async def run(self, args: dict[str, Any]) -> dict[str, Any]:
        parsed = KeyboardArgs.model_validate(args)
        op = parsed.operation.lower()
        if op not in _KEYBOARD_OPS:
            raise InputValidationError("INPUT_OPERATION_UNSUPPORTED")
        arguments: dict[str, Any] = {}
        if op == "type":
            if not parsed.text:
                raise InputValidationError("INPUT_TEXT_INVALID")
            arguments["text"] = parsed.text
        elif op == "keypress":
            if not parsed.key:
                raise InputValidationError("INPUT_KEY_INVALID")
            arguments["key"] = parsed.key
        elif op == "hotkey":
            if not parsed.keys:
                raise InputValidationError("INPUT_HOTKEY_INVALID")
            arguments["keys"] = parsed.keys
        elif op == "focus":
            if not parsed.window_id:
                raise InputValidationError("INPUT_WINDOW_ID_INVALID")
            arguments["window_id"] = parsed.window_id
        action = Action(task_id="keyboard-action", category=ActionCategory.KEYBOARD,
                        operation=op, target=self.name, arguments=arguments,
                        risk_level=RiskLevel.HIGH,
                        required_permissions=[Permission.EXECUTE],
                        requires_approval=True)
        result = await self._perform(action, parsed.dry_run)
        # Never echo typed text even inside evidence dicts.
        if isinstance(result.get("evidence"), dict):
            result["evidence"].pop("text", None)
        return result


class WindowActionTool(_BaseInputTool):
    name = "window_action"
    description = ("Focus, raise, minimize or close a window by validated id. "
                   "Closing is irreversible and always requires approval.")
    category = ActionCategory.WINDOW
    version = "1.0.0"
    input_model = WindowArgs
    output_model = InputOutput
    reversibility = Reversibility.PARTIAL

    async def run(self, args: dict[str, Any]) -> dict[str, Any]:
        parsed = WindowArgs.model_validate(args)
        # 'close' is destructive/irreversible -> escalate risk metadata.
        op = str(args.get("operation", "focus")).lower()
        if op not in _WINDOW_OPS:
            raise InputValidationError("INPUT_OPERATION_UNSUPPORTED")
        risk = RiskLevel.CRITICAL if op == "close" else RiskLevel.MEDIUM
        self.risk_level = risk
        action = Action(task_id="window-action", category=ActionCategory.WINDOW,
                        operation=op, target=self.name,
                        arguments={"window_id": parsed.window_id},
                        risk_level=risk,
                        required_permissions=[Permission.EXECUTE],
                        requires_approval=True)
        return await self._perform(action, parsed.dry_run)


class WindowListTool(ComputerTool):
    name = "window_list"
    description = ("List open windows (id, desktop, scrubbed title). Read-only; "
                   "no OS mutation; titles are privacy-scrubbed.")
    category = ActionCategory.WINDOW
    version = "1.0.0"
    input_model = EmptyArgs
    output_model = InputOutput
    platforms = ["linux"]
    permissions = frozenset({Permission.READ})
    risk_level = RiskLevel.LOW
    reversibility = Reversibility.READ_ONLY
    idempotent = True
    requires_approval = False
    audit_required = True
    timeout_seconds = 10.0

    def __init__(self, adapter_provider: Callable[[], LinuxWindowAdapter | None],
                 policy_provider: Callable[[], ComputerPolicy | None]):
        self._adapter_provider = adapter_provider
        self._policy_provider = policy_provider

    async def run(self, args: dict[str, Any]) -> dict[str, Any]:
        effect = _policy_effect(self._policy_provider(), Action(
            task_id="window-list", category=ActionCategory.WINDOW,
            operation="list", target=self.name, risk_level=RiskLevel.LOW))
        if effect != PolicyEffect.ALLOW.value:
            raise PermissionError(f"COMPUTER_POLICY_DENIED: {effect} for window_list")
        adapter = self._adapter_provider()
        if adapter is None:
            raise ComputerAgentDisabledError(
                "COMPUTER_AGENT_DISABLED: window listing unavailable")
        windows = await adapter.list_windows()
        return {"verified": True, "operation": "list", "failures": [],
                "evidence": {"windows": windows[:100], "count": len(windows)}}


def build_input_tools(adapter_provider: Callable[[], LinuxInputAdapter | None],
                      policy_provider: Callable[[], ComputerPolicy | None],
                      window_provider: Callable[[], LinuxWindowAdapter | None]
                      ) -> list[ComputerTool]:
    """Factory consumed by runtime wiring; pure construction, no registration."""
    return [
        MouseTool(adapter_provider, policy_provider),
        KeyboardTool(adapter_provider, policy_provider),
        WindowActionTool(adapter_provider, policy_provider),
        WindowListTool(window_provider, policy_provider),
    ]
