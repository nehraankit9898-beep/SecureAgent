"""Linux X11 mouse/keyboard/window adapters built from FIXED argv vectors.

Security rules enforced structurally here:
* Every OS call is an argv list assembled inside this module from validated
  integers and a strict key-name allowlist. No shell, no model-authored
  strings, no interpolation of arbitrary text into commands (typing goes to
  xdotool via *stdin*, never argv).
* The emergency stop is re-checked before EVERY queued action; a trip between
  queueing and execution still prevents the action.
* Coordinates are validated against live screen geometry before dispatch.
* Typed text is never echoed into results or verification evidence — only its
  character count is reported.
* When the platform/tooling is unavailable every method fails closed with a
  static code; nothing partially executes.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import sys
from typing import Any, Callable

from app.computer.contracts import (
    Action,
    ActionCategory,
    InputProvider,
    Observation,
    VerificationResult,
    WindowProvider,
)
from app.computer.input.geometry import (
    ActionRateLimiter,
    InputValidationError,
    ScreenGeometry,
    scrub_typed_text,
    validate_point,
)

# Strict keysym allowlist for keypress/hotkey synthesis. Anything not matching
# is rejected before it can reach xdotool (no injection surface at all).
_KEY_RE = re.compile(r"^[a-zA-Z0-9]$|^F(?:[1-9]|1[0-2])$|"
                     r"^(?:alt|alt_l|alt_r|ctrl|control|control_l|control_r|shift|shift_l|shift_r|"
                     r"super|super_l|super_r|meta|meta_l|meta_r|win_l|win_r|"
                     r"return|enter|tab|backspace|delete|insert|escape|esc|space|"
                     r"home|end|page_up|page_down|prior|next|"
                     r"up|down|left|right|print|caps_lock|num_lock|scroll_lock)$")
_BUTTONS = {1, 2, 3, 4, 5, 6, 7, 8, 9}
_CLICK_KINDS = {"single", "double", "right", "middle"}


class UnsupportedPlatformInput(RuntimeError):
    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


def _require_int(value: Any, code: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int):
        raise InputValidationError(code)
    return value


class LinuxInputAdapter(InputProvider):
    """xdotool-backed mouse/keyboard synthesis (X11 only)."""

    provider_id = "xdotool-input"

    def __init__(self, window: "LinuxWindowAdapter", *,
                 emergency_stopped_check: Callable[[], bool] | None = None,
                 rate_limiter: ActionRateLimiter | None = None,
                 max_text_chars: int = 2000,
                 drag_max_distance_px: int = 4000):
        self._window = window
        self._emergency = emergency_stopped_check or (lambda: False)
        self._rate = rate_limiter or ActionRateLimiter()
        self._max_text_chars = int(max_text_chars)
        self._drag_max = int(drag_max_distance_px)
        self._cancelled = False

    # -- lifecycle guards ---------------------------------------------------- #

    def cancel(self) -> None:
        """Queue-level cancellation: aborts remaining actions in a batch."""
        self._cancelled = True

    def reset_cancel(self) -> None:
        self._cancelled = False

    async def available(self) -> bool:
        return (sys.platform.startswith("linux")
                and os.environ.get("DISPLAY") is not None
                and shutil.which("xdotool") is not None)

    def _guard(self) -> None:
        # Fail-closed checks run BEFORE any side effect and BEFORE the rate
        # budget is consumed by an action that will not happen anyway.
        if self._emergency():
            raise InputValidationError("INPUT_BLOCKED_BY_EMERGENCY_STOP")
        if self._cancelled:
            raise InputValidationError("INPUT_CANCELLED")

    async def _run_argv(self, argv: list[str], *, stdin: bytes | None = None,
                        timeout: float = 10.0) -> str:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL,
        )
        try:
            out, _ = await asyncio.wait_for(proc.communicate(stdin), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise InputValidationError("INPUT_TOOL_TIMEOUT")
        if proc.returncode != 0:
            raise InputValidationError("INPUT_TOOL_FAILED")
        return (out or b"").decode("utf-8", "replace").strip()

    # -- action dispatch ------------------------------------------------------ #

    async def perform(self, action: Action) -> VerificationResult:
        """Perform ONE already-approved action. Never plans; never escalates."""
        task_id = action.task_id
        try:
            self._guard()
            self._rate.acquire()
            geometry = await self._window.geometry()
            evidence = await self._dispatch(action, geometry)
        except (InputValidationError, UnsupportedPlatformInput) as error:
            code = getattr(error, "code", "INPUT_FAILED")
            return VerificationResult(task_id=task_id, action_id=action.id,
                                      verified=False, confidence=0.0,
                                      method="xdotool", failures=[str(code)[:80]])
        except Exception:
            # Raw OS errors never leak; failure is simply "not verified".
            return VerificationResult(task_id=task_id, action_id=action.id,
                                      verified=False, confidence=0.0,
                                      method="xdotool",
                                      failures=["INPUT_EXECUTION_FAILED"])
        return VerificationResult(task_id=task_id, action_id=action.id,
                                  verified=True, confidence=1.0,
                                  method="xdotool", evidence=evidence)

    async def _dispatch(self, action: Action, geometry: ScreenGeometry) -> dict[str, Any]:
        category = action.category
        op = action.operation
        args = action.arguments

        if category == ActionCategory.MOUSE:
            if op in {"move", "click", "double_click", "right_click", "scroll", "drag"}:
                x = validate_point(geometry,
                                   _require_int(args.get("x"), "INPUT_X_INVALID"),
                                   _require_int(args.get("y"), "INPUT_Y_INVALID"))
            if op == "move":
                await self._run_argv(["xdotool", "mousemove", str(x[0]), str(x[1])])
                return {"operation": op, "x": x[0], "y": x[1]}
            if op == "click":
                kind = str(args.get("button", "single"))[:16]
                if kind == "double":
                    await self._run_argv(["xdotool", "mousemove", str(x[0]), str(x[1]),
                                          "click", "--repeat", "2", "--delay", "50", "1"])
                    return {"operation": op, "kind": "double", "x": x[0], "y": x[1]}
                if kind == "right":
                    button = 3
                elif kind == "middle":
                    button = 2
                else:
                    button = 1
                await self._run_argv(["xdotool", "mousemove", str(x[0]), str(x[1]),
                                      "click", str(button)])
                return {"operation": op, "button": button, "x": x[0], "y": x[1]}
            if op == "double_click":
                await self._run_argv(["xdotool", "mousemove", str(x[0]), str(x[1]),
                                      "click", "--repeat", "2", "--delay", "50", "1"])
                return {"operation": op, "x": x[0], "y": x[1]}
            if op == "right_click":
                await self._run_argv(["xdotool", "mousemove", str(x[0]), str(x[1]),
                                      "click", "3"])
                return {"operation": op, "button": 3, "x": x[0], "y": x[1]}
            if op == "scroll":
                amount = _require_int(args.get("amount", 3), "INPUT_AMOUNT_INVALID")
                if not (-20 <= amount <= 20):
                    raise InputValidationError("INPUT_SCROLL_AMOUNT_INVALID")
                direction = str(args.get("direction", "down"))[:8]
                # xdotool wheel buttons: 4=up, 5=down (clamped iterations only).
                button = 4 if direction == "up" else 5
                clicks = min(abs(amount) or 1, 20)
                await self._run_argv(["xdotool", "mousemove", str(x[0]), str(x[1]),
                                      "click", "--repeat", str(clicks), "--delay", "20",
                                      str(button)])
                return {"operation": op, "direction": direction, "clicks": clicks}
            if op == "drag":
                tx = validate_point(geometry,
                                    _require_int(args.get("to_x"), "INPUT_TOX_INVALID"),
                                    _require_int(args.get("to_y"), "INPUT_TOY_INVALID"))
                distance = max(abs(tx[0] - x[0]), abs(tx[1] - x[1]))
                if distance > self._drag_max:
                    raise InputValidationError("INPUT_DRAG_DISTANCE_EXCEEDED")
                button = _require_int(args.get("button", 1), "INPUT_BUTTON_INVALID")
                if button not in _BUTTONS:
                    raise InputValidationError("INPUT_BUTTON_INVALID")
                # mousedown/mouseup use the SAME numeric button id (1-based).
                await self._run_argv(["xdotool", "mousemove", str(x[0]), str(x[1]),
                                      "mousedown", str(button)])
                try:
                    await self._run_argv(["xdotool", "mousemove", str(tx[0]), str(tx[1])])
                finally:
                    await self._run_argv(["xdotool", "mouseup", str(button)])
                return {"operation": op, "from": [x[0], x[1]], "to": [tx[0], tx[1]]}
            raise InputValidationError("INPUT_OPERATION_UNSUPPORTED")

        if category == ActionCategory.KEYBOARD:
            if op == "type":
                text = args.get("text")
                if not isinstance(text, str) or not text:
                    raise InputValidationError("INPUT_TEXT_INVALID")
                if len(text) > self._max_text_chars:
                    raise InputValidationError("INPUT_TEXT_TOO_LONG")
                # Text goes through STDIN only (never argv); it is NEVER echoed
                # back into evidence, audit payloads or results.
                await self._run_argv(["xdotool", "type", "--clearmodifiers", "--file", "-"],
                                     stdin=text.encode("utf-8"))
                return {"operation": op, "chars": len(text)}
            if op == "keypress":
                key = str(args.get("key", ""))[:32]
                if not _KEY_RE.fullmatch(key):
                    raise InputValidationError("INPUT_KEY_NOT_ALLOWED")
                await self._run_argv(["xdotool", "key", key])
                return {"operation": op, "key": key}
            if op == "hotkey":
                combo_raw = str(args.get("keys", ""))[:128]
                parts = [p.strip().lower() for p in re.split(r"[+]", combo_raw) if p.strip()]
                if not 2 <= len(parts) <= 4:
                    raise InputValidationError("INPUT_HOTKEY_INVALID")
                for part in parts:
                    if not _KEY_RE.fullmatch(part):
                        raise InputValidationError("INPUT_KEY_NOT_ALLOWED")
                await self._run_argv(["xdotool", "key", "+".join(parts)])
                return {"operation": op, "keys": "+".join(parts)}
            if op == "focus":
                wid = self._validated_window_id(args.get("window_id"))
                await self._run_argv(["xdotool", "windowactivate", "--sync", wid])
                return {"operation": op, "window_id": wid}
            raise InputValidationError("INPUT_OPERATION_UNSUPPORTED")

        if category == ActionCategory.WINDOW:
            wid = self._validated_window_id(args.get("window_id"))
            if op == "focus":
                await self._run_argv(["xdotool", "windowactivate", "--sync", wid])
                return {"operation": op, "window_id": wid}
            if op == "raise":
                await self._run_argv(["xdotool", "windowraise", wid])
                return {"operation": op, "window_id": wid}
            if op == "minimize":
                await self._run_argv(["xdotool", "windowminimize", wid])
                return {"operation": op, "window_id": wid}
            if op == "close":
                # Destructive dialog path: policy/approval already gated this
                # (HIGH risk => REQUIRE_APPROVAL in tools.py). Still guarded.
                self._guard()
                await self._run_argv(["xdotool", "windowclose", wid])
                return {"operation": op, "window_id": wid}
            raise InputValidationError("INPUT_OPERATION_UNSUPPORTED")

        raise InputValidationError("INPUT_CATEGORY_UNSUPPORTED")

    @staticmethod
    def _validated_window_id(value: Any) -> str:
        text = str(value or "")[:32]
        if not re.fullmatch(r"(?:0x)?[0-9a-fA-F]{1,16}", text):
            raise InputValidationError("INPUT_WINDOW_ID_INVALID")
        return text


class LinuxWindowAdapter(WindowProvider):
    """wmctrl/xdotool window enumeration + geometry discovery."""

    provider_id = "wmctrl-window"

    def __init__(self, *, emergency_stopped_check: Callable[[], bool] | None = None):
        self._emergency = emergency_stopped_check or (lambda: False)
        self._geometry_cache: ScreenGeometry | None = None

    async def available(self) -> bool:
        return (sys.platform.startswith("linux")
                and os.environ.get("DISPLAY") is not None
                and shutil.which("xdotool") is not None)

    async def _argv(self, argv: list[str], timeout: float = 5.0) -> str:
        if self._emergency():
            raise InputValidationError("INPUT_BLOCKED_BY_EMERGENCY_STOP")
        proc = await asyncio.create_subprocess_exec(
            *argv, stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL)
        try:
            out, _ = await asyncio.wait_for(proc.communicate(), timeout=timeout)
        except asyncio.TimeoutError:
            proc.kill()
            await proc.wait()
            raise InputValidationError("WINDOW_TOOL_TIMEOUT")
        if proc.returncode != 0:
            raise InputValidationError("WINDOW_TOOL_FAILED")
        return (out or b"").decode("utf-8", "replace")

    async def geometry(self) -> ScreenGeometry:
        """Live screen extents; cached once per process unless invalid."""
        if self._geometry_cache is None:
            info = await self._argv(["xdotool", "getdisplaygeometry"])
            match = re.fullmatch(r"\s*(\d{1,5})\s+(\d{1,5})\s*", info)
            if not match:
                raise InputValidationError("WINDOW_GEOMETRY_UNREADABLE")
            width, height = int(match.group(1)), int(match.group(2))
            if not (0 < width <= 16384 and 0 < height <= 16384):
                raise InputValidationError("WINDOW_GEOMETRY_UNREADABLE")
            self._geometry_cache = ScreenGeometry(width=width, height=height)
        return self._geometry_cache

    async def active_window(self) -> Observation | None:
        try:
            wid_raw = await self._argv(["xdotool", "getactivewindow"])
        except Exception:
            return None
        wid = wid_raw.strip()[:20]
        if not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", wid):
            return None
        title = ""
        try:
            title = (await self._argv(["xdotool", "getwindowname", wid])).strip()[:500]
        except Exception:
            pass
        return Observation(task_id="window-metadata", provider=self.provider_id,
                           kind="window", summary=scrub_typed_text(title),
                           content={"window_id": wid, "title_scrubbed": True})

    async def list_windows(self) -> list[dict[str, Any]]:
        wmctrl = shutil.which("wmctrl")
        if wmctrl:
            raw = await self._argv([wmctrl, "-l"])
            windows: list[dict[str, Any]] = []
            for line in raw.splitlines():
                parts = line.split(None, 3)
                if len(parts) < 4:
                    continue
                wid = parts[0][:20]
                if not re.fullmatch(r"0x[0-9a-fA-F]{1,16}", wid):
                    continue
                desktop = _safe_int(parts[1], default=-1)
                windows.append({
                    "id": wid,
                    "desktop": desktop,
                    "title": scrub_typed_text(parts[3].strip())[:500],
                })
            return windows[:200]
        # Fallback: xdotool search with bounded output.
        raw = await self._argv(["xdotool", "search", "--onlyvisible", "--name", "."])
        ids = [line.strip()[:20] for line in raw.splitlines()
               if re.fullmatch(r"0x[0-9a-fA-F]{1,16}", line.strip())]
        return [{"id": wid, "desktop": -1, "title": ""} for wid in ids[:200]]


def _safe_int(value: str, *, default: int = 0) -> int:
    try:
        return int(value)
    except (TypeError, ValueError):
        return default


def make_input_adapter(emergency_stopped_check: Callable[[], bool] | None = None,
                       *, rate_per_minute: int = 60,
                       max_text_chars: int = 2000,
                       drag_max_distance_px: int = 4000) -> LinuxInputAdapter | None:
    """Factory used by the runtime; returns None when unsupported (fail closed)."""
    if not sys.platform.startswith("linux"):
        return None
    if os.environ.get("DISPLAY") is None or shutil.which("xdotool") is None:
        return None
    window = LinuxWindowAdapter(emergency_stopped_check=emergency_stopped_check)
    return LinuxInputAdapter(
        window,
        emergency_stopped_check=emergency_stopped_check,
        rate_limiter=ActionRateLimiter(per_minute=rate_per_minute),
        max_text_chars=max_text_chars,
        drag_max_distance_px=drag_max_distance_px,
    )


def make_window_adapter(emergency_stopped_check: Callable[[], bool] | None = None
                        ) -> LinuxWindowAdapter | None:
    if not sys.platform.startswith("linux"):
        return None
    if os.environ.get("DISPLAY") is None or shutil.which("xdotool") is None:
        return None
    return LinuxWindowAdapter(emergency_stopped_check=emergency_stopped_check)
