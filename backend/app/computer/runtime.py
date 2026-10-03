"""Feature-gated Computer Agent runtime facade.

``get_computer_runtime()`` is the ONLY object later phases should use to wire
computer capabilities into the application. In Phase 1 it always reports
disabled unless the explicit feature flag is set, and even then it installs no
input/perception providers (they do not exist yet).

The facade owns:
  * the capability snapshot (detected once, read-only),
  * the deterministic ComputerPolicy instance,
  * disabled provider stubs implementing every Phase-1 interface,
  * a status view for diagnostics/Control Center surfaces.

It performs no OS actions and registers nothing by itself; registration of any
future computer tool must go through ``app.computer.bridge.register_computer_tools``.
"""

from __future__ import annotations

import threading
from typing import Any, Callable

from app.computer.capabilities import Capabilities, detect_capabilities
from app.computer.contracts import (
    ApprovalService,
    BrowserProvider,
    ComputerAgentDisabledError,
    ComputerPolicy,
    DisabledBrowserProvider,
    DisabledInputProvider,
    DisabledPerceptionProvider,
    DisabledWindowProvider,
    InputProvider,
    PerceptionProvider,
    TaskPlanner,
    Verifier,
    WindowProvider,
)
from app.computer.policy import DefaultComputerPolicy


class ComputerRuntime:
    """Process-wide, thread-safe, fail-closed Computer Agent boundary state."""

    def __init__(self, *, enabled: bool, capabilities: Capabilities,
                 emergency_stopped_check: Callable[[], bool] | None = None):
        self._enabled = bool(enabled)
        self._capabilities = capabilities
        self._policy = DefaultComputerPolicy(
            enabled=self._enabled,
            capabilities=capabilities,
            emergency_stopped_check=emergency_stopped_check or (lambda: False),
            physical_input_allowed=False,  # Phase 1: never
        )
        # Phase 1 ships only disabled stubs. Later phases swap concrete
        # adapters in here behind these same interfaces.
        self._perception: PerceptionProvider = DisabledPerceptionProvider()
        self._input: InputProvider = DisabledInputProvider()
        self._window: WindowProvider = DisabledWindowProvider()
        self._browser: BrowserProvider = DisabledBrowserProvider()
        self._planner: TaskPlanner | None = None
        self._verifier: Verifier | None = None
        self._approvals: ApprovalService | None = None

    # -- flags -------------------------------------------------------------- #

    @property
    def enabled(self) -> bool:
        return self._enabled

    @property
    def capabilities(self) -> Capabilities:
        return self._capabilities

    @property
    def policy(self) -> ComputerPolicy:
        return self._policy

    def provider(self, kind: str) -> Any:
        mapping = {"perception": self._perception, "input": self._input,
                   "window": self._window, "browser": self._browser}
        if kind not in mapping:
            raise ComputerAgentDisabledError(f"COMPUTER_AGENT_DISABLED: unknown provider {kind!r}")
        return mapping[kind]

    def status(self) -> dict[str, Any]:
        return {
            "enabled": self._enabled,
            "physical_input_enabled": False,
            "providers": {
                "perception": "disabled", "input": "disabled",
                "window": "disabled", "browser": "disabled",
            },
            "planner": "not_installed",
            "verifier": "not_installed",
            "approvals": "core_agent_approval_pipeline",
            "capabilities": self._capabilities.public_dict(),
            "disable_reason": None if self._enabled else "COMPUTER_AGENT_DISABLED: feature flag off",
        }


_lock = threading.Lock()
_instance: ComputerRuntime | None = None


def configure_computer_runtime(*, enabled: bool,
                               emergency_stopped_check: Callable[[], bool] | None = None,
                               capabilities: Capabilities | None = None) -> ComputerRuntime:
    """Build the singleton from Settings + Control Center checks (startup only)."""
    global _instance
    with _lock:
        _instance = ComputerRuntime(
            enabled=enabled,
            capabilities=capabilities or detect_capabilities(),
            emergency_stopped_check=emergency_stopped_check,
        )
        return _instance


def get_computer_runtime() -> ComputerRuntime:
    """Return the configured runtime; default-deny when nothing configured it."""
    current = _instance
    if current is None:
        with _lock:
            if _instance is None:
                _instance = ComputerRuntime(enabled=False, capabilities=detect_capabilities())
            current = _instance
    return current


def reset_computer_runtime() -> None:
    """Test/lifecycle hook: drop the singleton so the next call re-defaults."""
    global _instance
    with _lock:
        _instance = None
