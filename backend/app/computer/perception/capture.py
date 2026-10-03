"""Platform screen-capture adapters (Linux first; others stay disabled).

Design rules:
* Adapters receive only validated integers/identifiers — never shell strings,
  never model-authored commands. Commands are fixed argv vectors built here.
* Output size is bounded BEFORE any image is returned or stored.
* Every failure raises ``CaptureError`` with a static code so callers can
  handle capture failure safely (no partial state, no raw OS error leakage).
* Active-window metadata is best-effort: missing window info degrades to
  ``None`` rather than failing the whole observation.
"""

from __future__ import annotations

import asyncio
import os
import re
import shutil
import sys
from abc import ABC, abstractmethod

from pydantic import BaseModel, ConfigDict, Field

MAX_CAPTURE_BYTES_DEFAULT = 12_000_000


class CaptureError(RuntimeError):
    """Static-coded capture failure. Never carries raw stderr content."""

    def __init__(self, code: str):
        super().__init__(code)
        self.code = code


class MonitorInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: int = Field(ge=0, le=32)
    name: str = Field("monitor", max_length=64)
    width: int = Field(gt=0, le=16384)
    height: int = Field(gt=0, le=16384)


class WindowInfo(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    id: str = Field(max_length=64)
    title: str = Field("", max_length=500)
    pid: int | None = Field(None, ge=0)
    x: int = Field(0, ge=-32768, le=32767)
    y: int = Field(0, ge=-32768, le=32767)
    width: int = Field(0, ge=0, le=16384)
    height: int = Field(0, ge=0, le=16384)


class CaptureResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    image_png: bytes
    monitors: tuple[MonitorInfo, ...] = ()
    selected_monitor: int = 0
    active_window: WindowInfo | None = None
    backend: str = Field(min_length=1, max_length=64)
    display_server: str = Field("none", max_length=16)
    truncated: bool = False


class ScreenCaptureBackend(ABC):
    """Interface every platform adapter implements."""

    provider_id = "screen-capture"

    @abstractmethod
    async def available(self) -> bool: ...

    @abstractmethod
    def list_monitors(self) -> list[MonitorInfo]: ...

    @abstractmethod
    async def active_window(self) -> WindowInfo | None: ...

    @abstractmethod
    async def capture(self, monitor: int = 0,
                      max_bytes: int = MAX_CAPTURE_BYTES_DEFAULT) -> CaptureResult: ...


def _clamp(value: int) -> int:
    return max(-32768, min(32767, value))


_XRANDR_MODE = re.compile(r"^\s*(\d+)x(\d+)\+(\d+)\+(\d+).*\*\s*$")
_XRANDR_CONNECTED = re.compile(r"^(\S+) connected(?: primary)?(?:\s+(\d+)x(\d+)\+(\d+)\+(\d+))?")
_WLR_OUTPUT = re.compile(r"^(\S+) mode:\s*(\d+)x(\d+)@")


def _parse_xrandr(text: str) -> list[MonitorInfo]:
    monitors: list[MonitorInfo] = []
    for line in (text or "").splitlines():
        m = _XRANDR_CONNECTED.match(line)
        if m and m.group(2):
            monitors.append(MonitorInfo(id=len(monitors), name=m.group(1)[:64],
                                        width=int(m.group(2)), height=int(m.group(3))))
    if not monitors:
        raise CaptureError("SCREEN_GEOMETRY_UNKNOWN")
    return monitors


def _parse_wlr_randr(text: str) -> list[MonitorInfo]:
    monitors: list[MonitorInfo] = []
    for line in (text or "").splitlines():
        m = _WLR_OUTPUT.match(line.strip())
        if m:
            monitors.append(MonitorInfo(id=len(monitors), name=m.group(1)[:64],
                                        width=int(m.group(2)), height=int(m.group(3))))
    if not monitors:
        raise CaptureError("SCREEN_GEOMETRY_UNKNOWN")
    return monitors


class LinuxScreenCapture(ScreenCaptureBackend):
    """grim (Wayland) / scrot|import (X11) capture with geometry validation."""

    provider_id = "linux-screen-capture"

    def __init__(self, env: dict[str, str] | None = None,
                 which=shutil.which, runner=None):
        self._env = env if env is not None else dict(os.environ)
        self._which = which
        # runner(argv) -> bytes|str ; injectable for tests, defaults to subprocess
        self._runner = runner

    # -- environment -------------------------------------------------------- #

    def display_server(self) -> str | None:
        if self._env.get("WAYLAND_DISPLAY", "").strip():
            return "wayland"
        if self._env.get("DISPLAY", "").strip():
            return "x11"
        return None

    async def available(self) -> bool:
        server = self.display_server()
        if server is None:
            return False
        if server == "wayland":
            return bool(self._which("grim"))
        return bool(self._which("scrot") or self._which("import"))

    # -- geometry ----------------------------------------------------------- #

    def _run(self, argv: list[str]) -> bytes:
        if self._runner is not None:
            out = self._runner(argv)
            return out if isinstance(out, bytes) else (out or "").encode("utf-8", "ignore")
        import subprocess
        try:
            done = subprocess.run(argv, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL,
                                  timeout=5, env={**self._env}, check=False)
        except (OSError, subprocess.SubprocessError):
            return b""
        return done.stdout or b""

    def list_monitors(self) -> list[MonitorInfo]:
        server = self.display_server()
        if server is None:
            raise CaptureError("SCREEN_NO_DISPLAY")
        if server == "x11":
            return _parse_xrandr(self._run(["xrandr", "--query"]).decode("utf-8", "ignore"))
        return _parse_wlr_randr(self._run(["wlr-randr"]).decode("utf-8", "ignore"))

    async def active_window(self) -> WindowInfo | None:
        if self.display_server() != "x11" or not self._which("xdotool"):
            return None
        name = await asyncio.to_thread(self._run, ["xdotool", "getactivewindow", "getwindowname"])
        text = name.decode("utf-8", "ignore").strip()
        if not text:
            return None
        geom = (await asyncio.to_thread(self._run,
                ["xdotool", "getactivewindow", "getwindowgeometry"])).decode("utf-8", "ignore")
        x = y = w = h = 0
        m = re.search(r"Position:\s*(\d+),(\d+)", geom or "")
        if m:
            x, y = int(m.group(1)), int(m.group(2))
        m = re.search(r"Size:\s*(\d+)x(\d+)", geom or "")
        if m:
            w, h = int(m.group(1)), int(m.group(2))
        try:
            return WindowInfo(id="active", title=text[:500], x=_clamp(x), y=_clamp(y),
                              width=min(w, 16384), height=min(h, 16384))
        except Exception:
            return None

    # -- capture ------------------------------------------------------------ #

    def _capture_argv(self, server: str) -> list[str]:
        if server == "wayland":
            if not self._which("grim"):
                raise CaptureError("SCREEN_BACKEND_UNAVAILABLE")
            return ["grim", "-"]
        if self._which("scrot"):
            return ["scrot", "--overwrite", "-z", "-"]
        if self._which("import"):  # ImageMagick (X11)
            return ["import", "-window", "root", "png:-"]
        raise CaptureError("SCREEN_BACKEND_UNAVAILABLE")

    async def capture(self, monitor: int = 0,
                      max_bytes: int = MAX_CAPTURE_BYTES_DEFAULT) -> CaptureResult:
        if not isinstance(monitor, int) or isinstance(monitor, bool) or monitor < 0 or monitor > 32:
            raise CaptureError("SCREEN_MONITOR_INVALID")
        server = self.display_server()
        if server is None:
            raise CaptureError("SCREEN_NO_DISPLAY")
        monitors = self.list_monitors()
        if monitor >= len(monitors):
            raise CaptureError("SCREEN_MONITOR_OUT_OF_RANGE")
        argv = self._capture_argv(server)
        data = await asyncio.to_thread(self._run, argv)
        if not data:
            raise CaptureError("SCREEN_CAPTURE_FAILED")
        if len(data) > max_bytes:
            # Fail SAFE: oversized captures are refused, never silently stored.
            raise CaptureError("SCREEN_CAPTURE_TOO_LARGE")
        window = await self.active_window()
        return CaptureResult(image_png=data, monitors=tuple(monitors),
                             selected_monitor=monitor, active_window=window,
                             backend=self.provider_id, display_server=server,
                             truncated=False)


class UnsupportedPlatformCapture(ScreenCaptureBackend):
    """Fail-closed stub for windows/macos until native adapters land."""

    provider_id = "unsupported-capture"

    async def available(self) -> bool:
        return False

    def list_monitors(self) -> list[MonitorInfo]:
        raise CaptureError("SCREEN_PLATFORM_UNSUPPORTED")

    async def active_window(self) -> WindowInfo | None:
        return None

    async def capture(self, monitor: int = 0,
                      max_bytes: int = MAX_CAPTURE_BYTES_DEFAULT) -> CaptureResult:
        raise CaptureError("SCREEN_PLATFORM_UNSUPPORTED")


def make_capture_backend(env: dict[str, str] | None = None) -> ScreenCaptureBackend:
    if sys.platform.startswith("linux"):
        return LinuxScreenCapture(env=env)
    return UnsupportedPlatformCapture()
