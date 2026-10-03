"""Pure validation helpers for Phase 5 physical input (no OS calls).

Everything in this module is deterministic and unit-testable:
* ``ScreenGeometry`` / ``validate_point`` — coordinate bounds checking.
* ``ActionRateLimiter`` — sliding-window budget per minute.
* ``scrub_typed_text`` — replaces typed text with a static marker so secrets
  never enter audit payloads or tool output (only length survives).
"""

from __future__ import annotations

import math
import re
import threading
import time
from collections import deque

from pydantic import BaseModel, ConfigDict, Field


class InputValidationError(ValueError):
    """Static-coded rejection raised BEFORE any OS side effect."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class ScreenGeometry(BaseModel):
    """Current display extents used to validate every pointer coordinate."""

    model_config = ConfigDict(extra="forbid", frozen=True)
    width: int = Field(gt=0, le=16384)
    height: int = Field(gt=0, le=16384)


def validate_point(geometry: ScreenGeometry | None, x: int, y: int,
                   *, label: str = "coordinate") -> tuple[int, int]:
    """Reject out-of-bounds/non-finite coordinates fail-closed."""
    for value in (x, y):
        if isinstance(value, float) and not math.isfinite(value):
            raise InputValidationError(f"INPUT_{label.upper()}_INVALID")
        if not isinstance(value, int):
            raise InputValidationError(f"INPUT_{label.upper()}_INVALID")
    if geometry is None:
        # Without verified geometry we cannot prove the point is on-screen.
        raise InputValidationError("INPUT_GEOMETRY_UNAVAILABLE")
    if not (0 <= x < geometry.width and 0 <= y < geometry.height):
        raise InputValidationError("INPUT_COORDINATE_OUT_OF_BOUNDS")
    return x, y


class ActionRateLimiter:
    """Sliding-window action budget (per minute). Thread-safe, fail-closed."""

    def __init__(self, *, per_minute: int = 60, clock=time.monotonic):
        self._limit = max(1, int(per_minute))
        self._clock = clock
        self._events: deque[float] = deque()
        self._lock = threading.Lock()

    @property
    def limit_per_minute(self) -> int:
        return self._limit

    def acquire(self) -> None:
        """Consume one slot; raise INPUT_RATE_LIMITED when over budget."""
        now = self._clock()
        with self._lock:
            while self._events and now - self._events[0] >= 60.0:
                self._events.popleft()
            if len(self._events) >= self._limit:
                raise InputValidationError("INPUT_RATE_LIMITED")
            self._events.append(now)

    def pending(self) -> int:
        with self._lock:
            return len(self._events)


# --------------------------------------------------------------------------- #
# Typed-text privacy scrubbing                                                #
# --------------------------------------------------------------------------- #

SCRUBBED = "[REDACTED]"

_SECRET_KEY_RE = re.compile(
    r"(?i)(password|passwd|pwd|secret|token|api[_-]?key|passphrase|otp|pin)\b"
)
_PASSWORD_FIELD_RE = re.compile(
    r"(?i)\b(password|passwd|pwd|secret|token|api[_-]?key|passphrase)\b(\s*[=:]\s*)(\S+)"
)


def contains_sensitive_field(text: str) -> bool:
    """True when the text looks like it carries credential material."""
    return bool(_SECRET_KEY_RE.search(text or ""))


def scrub_typed_text(text: str) -> str:
    """Replace any password/token-looking assignment values in free text.

    Used for *non-typed* metadata paths (window titles, verification echo).
    The actual keyboard payload is never echoed anywhere at all — see
    ``LinuxInputAdapter.perform`` which only records its length.
    """
    if not text:
        return text
    return _PASSWORD_FIELD_RE.sub(
        lambda m: f"{m.group(1)}{m.group(2)}{SCRUBBED}", text
    )
