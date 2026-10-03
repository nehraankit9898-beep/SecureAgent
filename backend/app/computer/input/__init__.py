"""Phase 5 — Controlled physical interaction (mouse, keyboard, windows).

Layering (all fail-closed):

* ``geometry.py``   — screen-geometry validation + rate limiting + typed-text
                      scrubbing. Pure logic; no OS calls. Every adapter shares it.
* ``adapters.py``   — Linux X11 adapters (xdotool / wmctrl) built ONLY from
                      fixed argv vectors with validated integers. No shell
                      strings, nothing model-authored ever reaches a process.
* ``tools.py``      — ComputerTool definitions registered ONLY through the
                      existing bridge -> PermissionManager -> Registry path and
                      executed ONLY through the Phase-3 ToolExecutionPipeline.

Hard guarantees enforced here:
- Physical input stays DENIED by the ComputerPolicy until the explicit
  ``computer_agent_physical_input`` flag is on AND the runtime was configured.
- Emergency stop (Control Center) is re-checked before EVERY queued action.
- Coordinates are validated against current screen geometry; out-of-bounds
  actions are rejected before any OS call.
- Typed text is never placed in audit payloads or returned output; only its
  length is reported.
- Dry-run performs every check and returns a simulated result with zero side
  effects.
"""

from app.computer.input.geometry import (
    ActionRateLimiter,
    InputValidationError,
    ScreenGeometry,
    SCRUBBED,
    scrub_typed_text,
    validate_point,
)
from app.computer.input.adapters import (
    LinuxInputAdapter,
    LinuxWindowAdapter,
    UnsupportedPlatformInput,
    make_input_adapter,
    make_window_adapter,
)

__all__ = [
    "ActionRateLimiter", "InputValidationError", "ScreenGeometry",
    "SCRUBBED", "scrub_typed_text", "validate_point",
    "LinuxInputAdapter", "LinuxWindowAdapter", "UnsupportedPlatformInput",
    "make_input_adapter", "make_window_adapter",
]
