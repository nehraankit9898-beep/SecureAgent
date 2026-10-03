"""Default ComputerPolicy implementation (deterministic, fail-closed).

This policy is the *additional* gate that computer actions must clear on top
of the existing pipeline (PermissionManager availability + Registry permission
enforcement + Control Center gates + agent approval flow). It never replaces
them; it can only make decisions stricter.

Rules (evaluated in order):

1. Computer Agent feature flag off                     -> DENY
2. EMERGENCY STOP active                               -> DENY
3. Action targets physical input (mouse/keyboard)      -> DENY until Phase 2
   adapters exist (this phase must not execute input at all)
4. Capability required by the action category missing  -> DENY
5. HIGH / CRITICAL risk                                -> REQUIRE_APPROVAL
6. Anything else                                       -> ALLOW (registry still
   enforces permissions/timeouts/output limits)

Any internal error resolves to DENY via ``ComputerPolicy.evaluate_or_deny``.
The policy object is read-only with respect to configuration: agents cannot
mutate it (attributes are private and there are no setters).
"""

from __future__ import annotations

from app.computer.capabilities import Capabilities
from app.computer.contracts import (
    Action,
    ActionCategory,
    ComputerPolicy,
    PolicyEffect,
)
from app.models import RiskLevel

# Action categories mapped to the capability a future adapter would need.
CATEGORY_CAPABILITY: dict[ActionCategory, str] = {
    ActionCategory.SCREEN: "screen_capture",
    ActionCategory.WINDOW: "window_control",
    ActionCategory.BROWSER: "browser_automation",
    ActionCategory.VOICE: "voice_stt",
    ActionCategory.FILESYSTEM: "",   # served by core tools, no extra capability
    ActionCategory.TERMINAL: "",     # served by core terminal tools
}


class DefaultComputerPolicy(ComputerPolicy):
    """Deterministic risk policy for the Computer Agent boundary."""

    def __init__(self, *, enabled: bool, capabilities: Capabilities,
                 emergency_stopped_check=None, physical_input_allowed: bool = False):
        self._enabled = bool(enabled)
        self._capabilities = capabilities
        self._emergency_stopped_check = emergency_stopped_check or (lambda: False)
        # Phase 1: always False. Later phases flip this only when an actual
        # InputProvider adapter has been installed and gated.
        self._physical_input_allowed = bool(physical_input_allowed)

    @property
    def enabled(self) -> bool:
        return self._enabled

    def evaluate(self, action: Action) -> PolicyEffect:
        if not isinstance(action, Action):
            # Malformed tool/action payloads fail closed.
            return PolicyEffect.DENY
        if not self._enabled:
            return PolicyEffect.DENY
        if self._emergency_stopped_check():
            return PolicyEffect.DENY
        if action.category in {ActionCategory.MOUSE, ActionCategory.KEYBOARD}:
            if not self._physical_input_allowed:
                return PolicyEffect.DENY
            return PolicyEffect.REQUIRE_APPROVAL
        capability = CATEGORY_CAPABILITY.get(action.category, "")
        if capability and not self._capabilities.supports(capability):
            return PolicyEffect.DENY
        if action.risk_level in {RiskLevel.HIGH, RiskLevel.CRITICAL}:
            return PolicyEffect.REQUIRE_APPROVAL
        return PolicyEffect.ALLOW
