"""Platform capability detection for the Computer Agent (read-only, bounded).

Detection never installs anything, never executes shell commands and never
opens network connections. It answers one question for the runtime gate:
"which computer capabilities could a future adapter *possibly* serve on this
host right now?" — so that the feature flag can fail closed per capability.

Import cost is intentionally tiny: ``shutil.which`` plus ``sys.platform``.
Heavy probes (Wayland/X11 sockets, Playwright browsers, audio devices) belong
to later-phase adapters, not to this boundary module.
"""

from __future__ import annotations

import os
import shutil
import sys
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Capabilities(BaseModel):
    """Immutable snapshot of host computer-agent capability support."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    platform: str                       # normalized: linux | windows | darwin | unknown
    platform_release: str = Field("", max_length=200)
    display_server: str | None = None   # wayland | x11 | none | unsupported-platform
    has_display: bool = False
    screen_capture: bool = False        # a capture backend is plausibly available
    ocr: bool = False                   # an OCR engine binary is present
    input_synthesis: bool = False       # uinput / Win32 / CGEvent path exists
    window_control: bool = False        # a window manager interface exists
    browser_automation: bool = False    # playwright package importable
    voice_stt: bool = False
    voice_tts: bool = False
    emergency_stop_available: bool = True  # Control Center kill switches exist
    notes: tuple[str, ...] = ()

    def supports(self, name: str) -> bool:
        value = getattr(self, name, None)
        return bool(value) if isinstance(value, bool) else False

    def public_dict(self) -> dict[str, Any]:
        """JSON-safe view used by diagnostics/Control Center surfaces."""
        return self.model_dump(mode="json")


def _normalize_platform() -> str:
    current = sys.platform
    if current.startswith("linux"):
        return "linux"
    if current == "darwin":
        return "darwin"
    if current == "win32":
        return "windows"
    return "unknown"


def _display_server() -> tuple[str | None, list[str]]:
    """Best-effort Wayland/X11 detection from environment variables only."""
    notes: list[str] = []
    wayland = os.environ.get("WAYLAND_DISPLAY", "").strip()
    x11 = os.environ.get("DISPLAY", "").strip()
    if wayland and x11:
        notes.append("both WAYLAND_DISPLAY and DISPLAY are set; Wayland preferred")
    if wayland:
        return "wayland", notes
    if x11:
        return "x11", notes
    return None, notes


SCREEN_CAPTURE_BINARIES = ("grim", "wl-copy", "scrot", "import", "gnome-screenshot", "spectacle")
OCR_BINARIES = ("tesseract",)
WINDOW_HINTS = ("wmctrl", "xdotool", "qdbus")


def detect_capabilities() -> Capabilities:
    """Detect computer-agent capabilities without executing anything."""
    notes: list[str] = []
    platform_name = _normalize_platform()
    release = ""
    try:
        release = str(sys.platform) + "/" + (os.uname().release if hasattr(os, "uname") else "")
        release = release[:200]
    except Exception:  # pragma: no cover - defensive, detection must not crash startup
        release = platform_name

    binaries = {name: shutil.which(name) for name in set(SCREEN_CAPTURE_BINARIES + OCR_BINARIES + WINDOW_HINTS)}

    if platform_name == "linux":
        server, env_notes = _display_server()
        notes.extend(env_notes)
        has_display = server is not None
        screen_capture = has_display and any(binaries[name] for name in SCREEN_CAPTURE_BINARIES)
        window_control = has_display and any(binaries[name] for name in WINDOW_HINTS)
        # uinput is the kernel interface for synthesized input on Linux.
        input_synthesis = has_display and os.path.exists("/dev/uinput")
    elif platform_name in {"windows", "darwin"}:
        # Platform adapters arrive in later phases; Phase 1 reports nothing as
        # ready so the feature gate stays fail-closed on non-Linux hosts too.
        server = None
        has_display = False
        screen_capture = window_control = input_synthesis = False
        notes.append(f"{platform_name} adapter not implemented yet (planned phase)")
    else:
        server = None
        has_display = False
        screen_capture = window_control = input_synthesis = False
        notes.append("unrecognized platform; all computer capabilities disabled")

    ocr = bool(binaries["tesseract"])

    browser = False
    try:  # cheap module-existence probe; no browser is launched
        from importlib.util import find_spec
        browser = find_spec("playwright") is not None
    except Exception:
        browser = False

    if not has_display:
        notes.append("no display session detected; perception/input/window stay disabled")

    return Capabilities(
        platform=platform_name,
        platform_release=release,
        display_server=server if platform_name == "linux" else None,
        has_display=has_display,
        screen_capture=screen_capture,
        ocr=ocr,
        input_synthesis=input_synthesis,
        window_control=window_control,
        browser_automation=browser,
        voice_stt=False,
        voice_tts=False,
        emergency_stop_available=True,
        notes=tuple(notes),
    )
