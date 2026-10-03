"""Browser engines.

``BrowserEngine`` is the provider boundary: SecureAgent policy lives in
``app.browser.session``/``app.browser.policy`` and never depends on Playwright
internals. The default engine drives Playwright's async API; if Playwright or
a browser binary is missing the engine reports itself unavailable and every
browser tool fails closed with ``BROWSER_ENGINE_UNAVAILABLE`` (no silent
substitution of another engine, and no fallback to raw HTTP that would bypass
page-level isolation).
"""
from __future__ import annotations

import asyncio
import importlib.util
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger("secureagent.browser")

MAX_ACCESSIBILITY_CHARS = 20_000


class BrowserEngineUnavailable(RuntimeError):
    def __init__(self, code: str = "BROWSER_ENGINE_UNAVAILABLE", detail: str = ""):
        super().__init__(code if not detail else f"{code}: {detail}")
        self.code = code


@dataclass
class PageView:
    """Engine-level page observation. Still untrusted; the session layer wraps it."""
    url: str = ""
    title: str = ""
    text: str = ""
    links: list[dict[str, str]] = field(default_factory=list)
    forms: list[dict[str, Any]] = field(default_factory=list)
    has_password_field: bool = False
    status: int | None = None


@dataclass(frozen=True)
class EngineProbe:
    available: bool
    provider_id: str
    reason: str | None = None


def probe_browser_engine() -> EngineProbe:
    """Cheap import probe (never launches a browser)."""
    try:
        spec = importlib.util.find_spec("playwright")
    except Exception:
        spec = None
    if spec is None:
        return EngineProbe(False, "playwright",
                           "BROWSER_ENGINE_UNAVAILABLE: the 'playwright' package is not installed "
                           "(pip install playwright && playwright install chromium)")
    return EngineProbe(True, "playwright")


class BrowserPage(ABC):
    """One isolated page inside an isolated browser context."""

    @property
    @abstractmethod
    def url(self) -> str: ...

    @property
    @abstractmethod
    def title(self) -> str: ...

    @abstractmethod
    async def goto(self, url: str, *, timeout_seconds: float) -> PageView: ...

    @abstractmethod
    async def click(self, selector: str, *, timeout_seconds: float) -> PageView: ...

    @abstractmethod
    async def fill(self, selector: str, text: str, *, submit: bool,
                   timeout_seconds: float) -> PageView: ...

    @abstractmethod
    async def select_option(self, selector: str, value: str, *,
                            timeout_seconds: float) -> PageView: ...

    @abstractmethod
    async def press(self, key: str, *, timeout_seconds: float) -> PageView: ...

    @abstractmethod
    async def scroll(self, dx: int, dy: int) -> PageView: ...

    @abstractmethod
    async def history(self, action: str, *, timeout_seconds: float) -> PageView: ...

    @abstractmethod
    async def view(self) -> PageView: ...

    @abstractmethod
    async def accessibility(self, limit: int = MAX_ACCESSIBILITY_CHARS) -> str: ...

    @abstractmethod
    async def screenshot(self, *, full_page: bool = False) -> bytes: ...

    @abstractmethod
    async def download(self, selector: str, *, timeout_seconds: float) -> tuple[str, bytes]: ...

    @abstractmethod
    async def upload(self, selector: str, path: str, *, timeout_seconds: float) -> PageView: ...

    async def element_label(self, selector: str) -> str:
        """Best-effort accessible label of an element (policy signal)."""
        return ""

    async def field_type(self, selector: str) -> str:
        """Best-effort input type of a form element (policy signal)."""
        return ""

    @abstractmethod
    async def close(self) -> None: ...


class BrowserEngine(ABC):
    provider_id = "abstract"

    @property
    @abstractmethod
    def available(self) -> bool: ...

    @property
    @abstractmethod
    def reason(self) -> str | None: ...

    @abstractmethod
    async def start(self) -> None: ...

    @abstractmethod
    async def stop(self) -> None: ...

    @abstractmethod
    async def new_page(self, session_id: str) -> BrowserPage: ...

    @abstractmethod
    async def close_session(self, session_id: str) -> None: ...


class DisabledBrowserEngine(BrowserEngine):
    """Fail-closed placeholder used until an engine is started successfully."""
    provider_id = "disabled"

    def __init__(self, reason: str):
        self._reason = reason

    @property
    def available(self) -> bool:
        return False

    @property
    def reason(self) -> str | None:
        return self._reason

    async def start(self) -> None:
        raise BrowserEngineUnavailable(self._reason)

    async def stop(self) -> None:
        return None

    async def new_page(self, session_id: str) -> BrowserPage:
        raise BrowserEngineUnavailable(self._reason)

    async def close_session(self, session_id: str) -> None:
        return None


class PlaywrightBrowserEngine(BrowserEngine):
    """Playwright/Chromium engine with one isolated context per session.

    Isolation rules:
    * every session gets its own ``BrowserContext`` (cookies, localStorage and
      sessionStorage are never shared between sessions/tasks);
    * downloads are only accepted when the policy allows them and the file is
      size-checked before it is handed anywhere;
    * ``ignore_https_errors`` stays False — certificate validation is never
      disabled for convenience;
    * closing a context always clears its storage state, and ``stop()`` closes
      the browser plus the Playwright driver.
    """
    provider_id = "playwright"

    def __init__(self, config):
        self.config = config
        self._playwright = None
        self._browser = None
        self._contexts: dict[str, Any] = {}
        self._reason: str | None = None
        self._lock = asyncio.Lock()

    @property
    def available(self) -> bool:
        return self._browser is not None and self._reason is None

    @property
    def reason(self) -> str | None:
        return self._reason

    async def start(self) -> None:
        async with self._lock:
            if self._browser is not None:
                return
            probe = probe_browser_engine()
            if not probe.available:
                self._reason = probe.reason
                raise BrowserEngineUnavailable(self._reason or "BROWSER_ENGINE_UNAVAILABLE")
            try:
                from playwright.async_api import async_playwright
                self._playwright = await async_playwright().start()
                self._browser = await self._playwright.chromium.launch(
                    headless=bool(getattr(self.config, "browser_headless", True)),
                    args=["--disable-dev-shm-usage", "--no-first-run",
                          "--no-default-browser-check", "--disable-extensions",
                          "--disable-background-networking", "--disable-sync"],
                )
                self._reason = None
                logger.info("browser engine started (playwright/chromium)")
            except Exception as error:  # never leak paths/keys through the message
                self._reason = ("BROWSER_ENGINE_UNAVAILABLE: Chromium could not be launched "
                                f"({type(error).__name__}). Run: playwright install chromium")
                self._browser = None
                if self._playwright is not None:
                    try:
                        await self._playwright.stop()
                    except Exception:
                        pass
                    self._playwright = None
                raise BrowserEngineUnavailable(self._reason) from None

    async def stop(self) -> None:
        for session_id in list(self._contexts):
            await self.close_session(session_id)
        if self._browser is not None:
            try:
                await self._browser.close()
            except Exception:
                logger.debug("browser close failed", exc_info=True)
            self._browser = None
        if self._playwright is not None:
            try:
                await self._playwright.stop()
            except Exception:
                logger.debug("playwright stop failed", exc_info=True)
            self._playwright = None

    async def new_page(self, session_id: str) -> BrowserPage:
        if not self.available:
            raise BrowserEngineUnavailable(self._reason or "BROWSER_ENGINE_UNAVAILABLE")
        context = self._contexts.get(session_id)
        if context is None:
            context = await self._browser.new_context(
                accept_downloads=False,       # downloads are handled explicitly
                ignore_https_errors=False,    # TLS verification is never relaxed
                java_script_enabled=True,
            )
            self._contexts[session_id] = context
        page = await context.new_page()
        page.set_default_navigation_timeout(
            float(getattr(self.config, "browser_navigation_timeout_seconds", 30)) * 1000)
        page.set_default_timeout(
            float(getattr(self.config, "browser_action_timeout_seconds", 20)) * 1000)
        return PlaywrightPage(page, self)

    async def close_session(self, session_id: str) -> None:
        context = self._contexts.pop(session_id, None)
        if context is None:
            return
        try:
            await context.clear_cookies()
        except Exception:
            pass
        try:
            await context.close()
        except Exception:
            logger.debug("context close failed", exc_info=True)


class PlaywrightPage(BrowserPage):
    def __init__(self, page, engine: PlaywrightBrowserEngine):
        self._page = page
        self._engine = engine
        self.config = engine.config

    @property
    def url(self) -> str:
        try:
            return str(self._page.url)
        except Exception:
            return ""

    @property
    def title(self) -> str:
        return ""

    async def _view(self) -> PageView:
        """Read the page DOM with hard bounds; never raises into the model."""
        limit = int(getattr(self.config, "browser_max_snapshot_chars", 20_000))
        links_limit = int(getattr(self.config, "browser_max_links", 60))
        view = PageView(url=self.url)
        try:
            view.title = str(await self._page.title())[:300]
        except Exception:
            view.title = ""
        try:
            view.text = str(await self._page.inner_text("body"))[:limit]
        except Exception:
            view.text = ""
        try:
            links = await self._page.eval_on_selector_all(
                "a[href]",
                "els => els.slice(0, %d).map(e => ({text: (e.innerText || '').slice(0, 200),"
                " href: String(e.href).slice(0, 500)}))" % links_limit)
            view.links = [{"text": str(item.get("text", ""))[:200],
                           "href": str(item.get("href", ""))[:500]}
                          for item in (links or []) if isinstance(item, dict)]
        except Exception:
            view.links = []
        try:
            forms = await self._page.eval_on_selector_all(
                "form",
                "els => els.slice(0, 10).map(f => ({action: String(f.action || '').slice(0, 500),"
                " method: String(f.method || 'get').slice(0, 10),"
                " fields: Array.from(f.querySelectorAll('input,select,textarea')).slice(0, 20)"
                ".map(i => ({name: String(i.name || '').slice(0, 100), type: String(i.type || '').slice(0, 30)}))}))")
            view.forms = [item for item in (forms or []) if isinstance(item, dict)]
            view.has_password_field = any(
                field.get("type") == "password"
                for form in view.forms for field in form.get("fields", [])
                if isinstance(field, dict))
        except Exception:
            view.forms = []
        return view

    async def goto(self, url: str, *, timeout_seconds: float) -> PageView:
        response = await self._page.goto(url, wait_until="domcontentloaded",
                                         timeout=timeout_seconds * 1000)
        view = await self._view()
        try:
            view.status = response.status if response is not None else None
        except Exception:
            view.status = None
        return view

    async def click(self, selector: str, *, timeout_seconds: float) -> PageView:
        await self._page.click(selector, timeout=timeout_seconds * 1000)
        return await self._view()

    async def fill(self, selector: str, text: str, *, submit: bool,
                   timeout_seconds: float) -> PageView:
        await self._page.fill(selector, text, timeout=timeout_seconds * 1000)
        if submit:
            await self._page.press(selector, "Enter", timeout=timeout_seconds * 1000)
        return await self._view()

    async def select_option(self, selector: str, value: str, *,
                            timeout_seconds: float) -> PageView:
        await self._page.select_option(selector, value, timeout=timeout_seconds * 1000)
        return await self._view()

    async def press(self, key: str, *, timeout_seconds: float) -> PageView:
        await self._page.keyboard.press(key, timeout=timeout_seconds * 1000)
        return await self._view()

    async def scroll(self, dx: int, dy: int) -> PageView:
        await self._page.mouse.wheel(dx, dy)
        return await self._view()

    async def history(self, action: str, *, timeout_seconds: float) -> PageView:
        if action == "back":
            await self._page.go_back(timeout=timeout_seconds * 1000)
        elif action == "forward":
            await self._page.go_forward(timeout=timeout_seconds * 1000)
        elif action == "refresh":
            await self._page.reload(timeout=timeout_seconds * 1000)
        else:
            raise ValueError("invalid history action")
        return await self._view()

    async def view(self) -> PageView:
        return await self._view()

    async def accessibility(self, limit: int = MAX_ACCESSIBILITY_CHARS) -> str:
        try:
            snapshot = await self._page.accessibility.snapshot()
        except Exception:
            snapshot = None
        if not snapshot:
            return ""
        import json as _json
        return _json.dumps(snapshot, ensure_ascii=False, default=str)[:limit]

    async def screenshot(self, *, full_page: bool = False) -> bytes:
        return await self._page.screenshot(type="png", full_page=full_page)

    async def download(self, selector: str, *, timeout_seconds: float) -> tuple[str, bytes]:
        async with self._page.expect_download(timeout=timeout_seconds * 1000) as info:
            await self._page.click(selector, timeout=timeout_seconds * 1000)
        download = await info.value
        name = str(download.suggested_filename or "download.bin")[:200]
        path = await download.path()
        if path is None:
            raise RuntimeError("BROWSER_DOWNLOAD_FAILED")
        with open(path, "rb") as handle:
            data = handle.read(int(getattr(self.config, "browser_max_download_bytes", 5_000_000)) + 1)
        return name, data

    async def upload(self, selector: str, path: str, *, timeout_seconds: float) -> PageView:
        await self._page.set_input_files(selector, path, timeout=timeout_seconds * 1000)
        return await self._view()

    async def element_label(self, selector: str) -> str:
        try:
            label = await self._page.eval_on_selector(
                selector,
                "e => [e.innerText, e.value, e.getAttribute('aria-label'), e.getAttribute('title'),"
                " e.getAttribute('name'), e.getAttribute('id')].filter(Boolean).join(' ').slice(0, 300)")
            return str(label or "")
        except Exception:
            return ""

    async def field_type(self, selector: str) -> str:
        try:
            kind = await self._page.eval_on_selector(
                selector, "e => String(e.getAttribute('type') || e.tagName || '').slice(0, 30)")
            return str(kind or "").lower()
        except Exception:
            return ""

    async def close(self) -> None:
        try:
            await self._page.close()
        except Exception:
            logger.debug("page close failed", exc_info=True)
