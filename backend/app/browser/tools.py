"""Phase 09 — browser tools exposed to the agent catalog.

These are the ONLY way a model can touch a browser. Every tool:
* is schema-validated by the Registry (``extra='forbid'`` input models),
* declares its permissions (NETWORK for navigation/interaction, READ for
  observation of the already-loaded page),
* is disabled unless the Browser master switches are ON — the registry then
  returns ``tool_disabled`` with the reason, never a silent execution,
* delegates all policy decisions to ``BrowserPolicy``/``BrowserSession``.
"""
from __future__ import annotations

from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field

from app.browser.policy import BrowserPolicyError
from app.browser.runtime import get_browser_runtime
from app.config import settings
from app.models import Permission, Reversibility, RiskLevel
from app.tools.base import Tool


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class _BrowserTool(Tool):
    category = "browser"
    timeout_seconds = 60.0
    network_required = True
    platforms = ["linux", "windows", "macos"]

    def __init__(self, runtime_getter=None, config=None):
        self._runtime_getter = runtime_getter or get_browser_runtime
        self.config = config or settings()

    async def _session(self, session_id: str | None):
        runtime = self._runtime_getter()
        if runtime is None:
            raise RuntimeError("BROWSER_UNAVAILABLE: the browser runtime has not been initialized")
        return await runtime.session(session_id or "default")

    async def _close_runtime(self) -> None:
        runtime = self._runtime_getter()
        if runtime is not None:
            await runtime.stop()


# --------------------------------------------------------------------------- #
# Navigation + observation                                                    #
# --------------------------------------------------------------------------- #


class NavigateIn(_Strict):
    url: str = Field(min_length=1, max_length=2000)
    session_id: str | None = Field(None, max_length=64)


class NavigateOut(_Strict):
    session_id: str
    url: str
    title: str
    status: int | None = None
    text: str
    text_chars: int
    links: list[dict[str, str]]
    forms: list[dict[str, Any]]
    has_password_field: bool
    injection_suspected: bool
    untrusted: bool


class BrowserNavigate(_BrowserTool):
    name = "browser_navigate"
    description = ("Open an http(s) URL in an isolated browser session. The destination is checked "
                   "against the network/SSRF policy and the Control Center allow/block lists. Page "
                   "content is returned as untrusted data.")
    risk_level = RiskLevel.MEDIUM
    reversibility = Reversibility.REVERSIBLE
    input_model = NavigateIn
    output_model = NavigateOut
    permissions = frozenset({Permission.NETWORK})

    async def invoke(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._session(args.get("session_id"))
        return await session.navigate(args["url"])


class SnapshotIn(_Strict):
    session_id: str | None = Field(None, max_length=64)
    include_accessibility: bool = False


class SnapshotOut(NavigateOut):
    """Same untrusted observation shape as navigation, plus the optional
    accessibility tree."""
    accessibility: str | None = None
    accessibility_injection_suspected: bool = False


class BrowserSnapshot(_BrowserTool):
    name = "browser_snapshot"
    description = ("Read the current page's visible text, links and forms (bounded, wrapped as "
                   "untrusted data) for the already-open session.")
    risk_level = RiskLevel.LOW
    reversibility = Reversibility.READ_ONLY
    network_required = False
    input_model = SnapshotIn
    output_model = SnapshotOut
    permissions = frozenset({Permission.READ})

    async def invoke(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._session(args.get("session_id"))
        view = await session.view()
        if args.get("include_accessibility"):
            tree = await session.accessibility()
            view["accessibility"] = tree["tree"]
            view["accessibility_injection_suspected"] = tree["injection_suspected"]
        else:
            view["accessibility"] = None
        return view


class ScreenshotIn(_Strict):
    session_id: str | None = Field(None, max_length=64)
    full_page: bool = False
    persist: bool = False
    analyze: bool = False


class ScreenshotOut(_Strict):
    session_id: str
    url: str
    bytes: int
    sha256: str
    redacted: bool
    saved_path: str | None = None
    description: str | None = None
    untrusted: bool


class BrowserScreenshot(_BrowserTool):
    name = "browser_screenshot"
    description = ("Capture the page as a PNG (sensitive regions are redacted when configured). "
                   "The image itself is never returned to the model: only metadata, an optional "
                   "workspace path and an optional vision description.")
    risk_level = RiskLevel.MEDIUM
    reversibility = Reversibility.READ_ONLY
    network_required = False
    input_model = ScreenshotIn
    output_model = ScreenshotOut
    permissions = frozenset({Permission.READ})

    async def invoke(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._session(args.get("session_id"))
        return await session.screenshot(full_page=bool(args.get("full_page")),
                                        persist=bool(args.get("persist")),
                                        analyze=bool(args.get("analyze")))


# --------------------------------------------------------------------------- #
# Interaction                                                                 #
# --------------------------------------------------------------------------- #


class ClickIn(_Strict):
    selector: str = Field(min_length=1, max_length=500)
    action: Literal["purchase", "send_message", "submit_form", "delete", "account_change",
                    "security_change", "credential_operation"] | None = None
    approval: Literal["APPROVE"] | None = None
    session_id: str | None = Field(None, max_length=64)


class BrowserClick(_BrowserTool):
    name = "browser_click"
    description = ("Click one element by CSS selector. Buttons that perform a sensitive action "
                   "(purchase/send/delete/account/security/credential) are detected from their page "
                   "label and refused unless the action class plus approval are supplied.")
    risk_level = RiskLevel.MEDIUM
    reversibility = Reversibility.PARTIAL
    idempotent = False
    input_model = ClickIn
    output_model = NavigateOut
    permissions = frozenset({Permission.NETWORK})

    async def invoke(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._session(args.get("session_id"))
        return await session.click(args["selector"], action=args.get("action"),
                                   approval=args.get("approval"))


class TypeIn(_Strict):
    selector: str = Field(min_length=1, max_length=500)
    text: str = Field(default="", max_length=10_000)
    submit: bool = False
    action: Literal["purchase", "send_message", "submit_form", "delete", "account_change",
                    "security_change", "credential_operation"] | None = None
    approval: Literal["APPROVE"] | None = None
    session_id: str | None = Field(None, max_length=64)


class BrowserType(_BrowserTool):
    name = "browser_type"
    description = ("Type text into one field. Password fields and form submissions are refused "
                   "without the matching approval class. Typed values are never logged.")
    risk_level = RiskLevel.MEDIUM
    reversibility = Reversibility.PARTIAL
    idempotent = False
    input_model = TypeIn
    output_model = NavigateOut
    permissions = frozenset({Permission.NETWORK})

    async def invoke(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._session(args.get("session_id"))
        return await session.type_text(args["selector"], args.get("text", ""),
                                       submit=bool(args.get("submit")),
                                       action=args.get("action"), approval=args.get("approval"))


class SelectIn(_Strict):
    selector: str = Field(min_length=1, max_length=500)
    value: str = Field(min_length=1, max_length=200)
    action: Literal["purchase", "send_message", "submit_form", "delete", "account_change",
                    "security_change", "credential_operation"] | None = None
    approval: Literal["APPROVE"] | None = None
    session_id: str | None = Field(None, max_length=64)


class BrowserSelect(_BrowserTool):
    name = "browser_select"
    description = "Choose an option in a select element (sensitive labels require approval)."
    risk_level = RiskLevel.MEDIUM
    reversibility = Reversibility.PARTIAL
    idempotent = False
    input_model = SelectIn
    output_model = NavigateOut
    permissions = frozenset({Permission.NETWORK})

    async def invoke(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._session(args.get("session_id"))
        return await session.select_option(args["selector"], args["value"],
                                           action=args.get("action"),
                                           approval=args.get("approval"))


class PressIn(_Strict):
    key: str = Field(min_length=1, max_length=40)
    session_id: str | None = Field(None, max_length=64)


class BrowserPress(_BrowserTool):
    name = "browser_press"
    description = "Press one keyboard key (e.g. Enter, Escape, ArrowDown) in the current page."
    risk_level = RiskLevel.LOW
    reversibility = Reversibility.PARTIAL
    idempotent = False
    input_model = PressIn
    output_model = NavigateOut
    permissions = frozenset({Permission.NETWORK})

    async def invoke(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._session(args.get("session_id"))
        return await session.press(args["key"])


class ScrollIn(_Strict):
    dx: int = Field(0, ge=-10_000, le=10_000)
    dy: int = Field(600, ge=-10_000, le=10_000)
    session_id: str | None = Field(None, max_length=64)


class BrowserScroll(_BrowserTool):
    name = "browser_scroll"
    description = "Scroll the current page by a bounded pixel delta."
    risk_level = RiskLevel.LOW
    reversibility = Reversibility.READ_ONLY
    network_required = False
    input_model = ScrollIn
    output_model = NavigateOut
    permissions = frozenset({Permission.READ})

    async def invoke(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._session(args.get("session_id"))
        return await session.scroll(args.get("dx", 0), args.get("dy", 600))


class HistoryIn(_Strict):
    action: Literal["back", "forward", "refresh"]
    session_id: str | None = Field(None, max_length=64)


class BrowserHistory(_BrowserTool):
    name = "browser_history"
    description = "Navigate the current tab backwards, forwards, or reload the page."
    risk_level = RiskLevel.LOW
    reversibility = Reversibility.PARTIAL
    idempotent = False
    input_model = HistoryIn
    output_model = NavigateOut
    permissions = frozenset({Permission.NETWORK})

    async def invoke(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._session(args.get("session_id"))
        return await session.history(args["action"])


# --------------------------------------------------------------------------- #
# Tabs, downloads, uploads, session lifecycle                                 #
# --------------------------------------------------------------------------- #


class TabsIn(_Strict):
    action: Literal["list", "new", "close", "switch"]
    index: int | None = Field(None, ge=0, le=32)
    session_id: str | None = Field(None, max_length=64)


class TabsOut(_Strict):
    session_id: str
    index: int
    tabs: list[dict[str, Any]]


class BrowserTabs(_BrowserTool):
    name = "browser_tabs"
    description = "List, open, close or switch browser tabs inside one isolated session."
    risk_level = RiskLevel.LOW
    reversibility = Reversibility.PARTIAL
    idempotent = False
    network_required = False
    input_model = TabsIn
    output_model = TabsOut
    permissions = frozenset({Permission.READ})

    async def invoke(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._session(args.get("session_id"))
        return await session.tabs(args["action"], args.get("index"))


class DownloadIn(_Strict):
    selector: str = Field(min_length=1, max_length=500)
    action: Literal["purchase", "send_message", "submit_form", "delete", "account_change",
                    "security_change", "credential_operation"] | None = None
    approval: Literal["APPROVE"] | None = None
    session_id: str | None = Field(None, max_length=64)


class DownloadOut(_Strict):
    session_id: str
    filename: str
    bytes: int
    sha256: str
    saved_path: str
    untrusted: bool


class BrowserDownload(_BrowserTool):
    name = "browser_download"
    description = ("Download a file by clicking one element (disabled unless downloads are enabled). "
                   "The file is written into the workspace and only its metadata is returned.")
    risk_level = RiskLevel.HIGH
    reversibility = Reversibility.REVERSIBLE
    idempotent = False
    input_model = DownloadIn
    output_model = DownloadOut
    permissions = frozenset({Permission.NETWORK})

    async def invoke(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._session(args.get("session_id"))
        return await session.download(args["selector"], action=args.get("action"),
                                      approval=args.get("approval"))


class UploadIn(_Strict):
    selector: str = Field(min_length=1, max_length=500)
    path: str = Field(min_length=1, max_length=500)
    session_id: str | None = Field(None, max_length=64)


class BrowserUpload(_BrowserTool):
    name = "browser_upload"
    description = ("Attach ONE workspace file to a file input (disabled unless uploads are enabled; "
                   "host paths are rejected).")
    risk_level = RiskLevel.HIGH
    reversibility = Reversibility.PARTIAL
    idempotent = False
    input_model = UploadIn
    output_model = NavigateOut
    permissions = frozenset({Permission.READ, Permission.NETWORK})

    async def invoke(self, args: dict[str, Any]) -> dict[str, Any]:
        session = await self._session(args.get("session_id"))
        return await session.upload(args["selector"], args["path"])


class CloseIn(_Strict):
    session_id: str | None = Field(None, max_length=64)


class CloseOut(_Strict):
    session_id: str
    closed: bool


class BrowserClose(_BrowserTool):
    name = "browser_close"
    description = "Close one browser session and destroy its isolated context and cookies."
    risk_level = RiskLevel.LOW
    reversibility = Reversibility.PARTIAL
    network_required = False
    input_model = CloseIn
    output_model = CloseOut
    permissions = frozenset({Permission.SAFE})

    async def invoke(self, args: dict[str, Any]) -> dict[str, Any]:
        runtime = self._runtime_getter()
        if runtime is None:
            raise RuntimeError("BROWSER_UNAVAILABLE: the browser runtime has not been initialized")
        session_id = args.get("session_id") or "default"
        closed = await runtime.close(session_id, reason="tool")
        return {"session_id": session_id, "closed": bool(closed)}


BROWSER_TOOL_CLASSES = (
    BrowserNavigate, BrowserSnapshot, BrowserScreenshot, BrowserClick, BrowserType,
    BrowserSelect, BrowserPress, BrowserScroll, BrowserHistory, BrowserTabs,
    BrowserDownload, BrowserUpload, BrowserClose,
)


def build_browser_tools(config, runtime=None) -> list[Tool]:
    """Construct the catalog entries (registry registration happens in factory)."""
    getter = (lambda: runtime) if runtime is not None else get_browser_runtime
    return [klass(runtime_getter=getter, config=config) for klass in BROWSER_TOOL_CLASSES]


__all__ = ["BROWSER_TOOL_CLASSES", "build_browser_tools", "BrowserPolicyError"]
