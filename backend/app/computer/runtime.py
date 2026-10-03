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
                 emergency_stopped_check: Callable[[], bool] | None = None,
                 settings: Any | None = None):
        self._enabled = bool(enabled)
        self._capabilities = capabilities
        self._settings = settings
        physical_input_allowed = False
        if settings is not None and getattr(settings, "computer_agent_physical_input", False):
            # Explicit operator opt-in AND detected synthesis capability are
            # both required; otherwise the policy keeps denying (fail closed).
            physical_input_allowed = bool(capabilities.supports("input_synthesis"))
        self._policy = DefaultComputerPolicy(
            enabled=self._enabled,
            capabilities=capabilities,
            emergency_stopped_check=emergency_stopped_check or (lambda: False),
            physical_input_allowed=physical_input_allowed,
        )
        self._emergency_check = emergency_stopped_check or (lambda: False)
        # Phase 4/5 install concrete adapters behind the SAME Phase-1
        # interfaces when the feature flag is on and tooling exists. When
        # anything is missing the disabled stubs remain — they fail closed.
        self._perception: PerceptionProvider = DisabledPerceptionProvider()
        self._input: InputProvider = DisabledInputProvider()
        self._window: WindowProvider = DisabledWindowProvider()
        self._browser: BrowserProvider = DisabledBrowserProvider()
        if self._enabled:
            self._install_perception()
            self._install_input()

    # -- Phase 4: perception -------------------------------------------------- #

    def _install_perception(self) -> None:
        try:
            from pathlib import Path as _P

            from app.computer.perception.capture import make_capture_backend
            from app.computer.perception.ocr import OcrAdapter
            from app.computer.perception.privacy import RedactionPlan, ScreenshotStore
            from app.computer.perception.providers import (
                OcrPerceptionProvider, ScreenPerceptionProvider)
            from app.computer.perception.vision import VisionAdapter

            settings = self._settings
            max_bytes = int(getattr(settings, "screen_capture_max_bytes", 12_000_000)) \
                if settings is not None else 12_000_000
            persist = bool(getattr(settings, "screen_capture_persist", False)) \
                if settings is not None else False
            retention = int(getattr(settings, "screen_capture_retention_seconds", 300)) \
                if settings is not None else 300
            regions = list(getattr(settings, "screen_sensitive_regions", []) or []) \
                if settings is not None else []
            backend = make_capture_backend()
            # Redaction plan construction can fail closed (malformed config):
            # in that case we refuse to install ANY persistence and keep the
            # disabled provider rather than capturing unredacted screens.
            plan = RedactionPlan.from_settings(regions)
            store = None
            if persist:
                db_dir = getattr(settings, "database_path", None)
                root = _P(db_dir).parent / "screens" if db_dir else _P(".secureagent") / "screens"
                store = ScreenshotStore(root, retention_seconds=retention, enabled=True)
            screen = ScreenPerceptionProvider(backend, redaction=plan,
                                              store=store, max_bytes=max_bytes)
            vision = None
            if settings is not None:
                vision = VisionAdapter(
                    enabled=bool(getattr(settings, "vision_cloud_enabled", False)),
                    endpoint=str(getattr(settings, "vision_cloud_endpoint", "") or "") or None,
                    api_key=getattr(settings, "vision_cloud_api_key", None),
                    timeout_seconds=float(getattr(settings, "ocr_timeout_seconds", 20.0)))
            self._perception = screen
            self._screen_provider = screen
            self._ocr_provider = OcrPerceptionProvider(screen, OcrAdapter(),
                                                       vision_adapter=vision)
        except Exception:
            # Provider installation failure must NEVER enable a capability.
            self._perception = DisabledPerceptionProvider()
            self._ocr_provider = None
            self._screen_provider = None

    # -- Phase 5: physical input ---------------------------------------------- #

    def _install_input(self) -> None:
        try:
            from app.computer.input.adapters import make_input_adapter, make_window_adapter

            settings = self._settings
            window = make_window_adapter(self._emergency_check)
            adapter = make_input_adapter(
                self._emergency_check,
                rate_per_minute=int(getattr(settings, "input_action_rate_per_minute", 60)),
                max_text_chars=int(getattr(settings, "input_max_text_chars", 2000)),
                drag_max_distance_px=int(getattr(settings, "input_drag_max_distance_px", 4000)))
            if adapter is not None and window is not None:
                self._input = adapter
                self._window = window
        except Exception:
            self._input = DisabledInputProvider()
            self._window = DisabledWindowProvider()

    def input_adapter(self):
        """Concrete adapter for tool wiring; None when disabled/unavailable."""
        from app.computer.input.adapters import LinuxInputAdapter
        return self._input if isinstance(self._input, LinuxInputAdapter) else None

    def window_adapter(self):
        from app.computer.input.adapters import LinuxWindowAdapter
        return self._window if isinstance(self._window, LinuxWindowAdapter) else None

    def perception_provider(self):
        provider = getattr(self, "_screen_provider", None)
        if provider is None:
            from app.computer.perception.providers import ScreenPerceptionProvider
            return None if not isinstance(self._perception, ScreenPerceptionProvider) \
                else self._perception
        return provider

    def ocr_provider(self):
        return getattr(self, "_ocr_provider", None)

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
        from app.computer.input.adapters import LinuxInputAdapter
        from app.computer.perception.providers import ScreenPerceptionProvider
        perception_state = ("ready" if isinstance(self._perception, ScreenPerceptionProvider)
                            else "disabled")
        input_state = ("ready" if isinstance(self._input, LinuxInputAdapter)
                       else "disabled")
        window_state = ("ready" if input_state == "ready" else "disabled")
        return {
            "enabled": self._enabled,
            "physical_input_enabled": self._policy._physical_input_allowed,
            "providers": {
                "perception": perception_state, "input": input_state,
                "window": window_state, "browser": "disabled",
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
                               capabilities: Capabilities | None = None,
                               settings: Any | None = None) -> ComputerRuntime:
    """Build the singleton from Settings + Control Center checks (startup only)."""
    global _instance
    with _lock:
        _instance = ComputerRuntime(
            enabled=enabled,
            capabilities=capabilities or detect_capabilities(),
            emergency_stopped_check=emergency_stopped_check,
            settings=settings,
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
