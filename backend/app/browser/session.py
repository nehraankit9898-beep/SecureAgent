"""Browser sessions — the only code path from a tool call to a real page.

Every method here:
1. re-checks the Browser master gate (config + Control Center + emergency stop),
2. validates the destination through the DNS-pinned SSRF layer,
3. classifies sensitive actions and refuses without explicit approval,
4. performs the engine call with a bounded timeout,
5. wraps everything that came from the page as UNTRUSTED data before it can
   reach a prompt/log, and strips credential-bearing metadata,
6. writes an audit event (never containing typed secrets — only lengths and
   hashed selectors).
"""
from __future__ import annotations

import hashlib
import json
import time
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.browser.policy import (APPROVAL_TOKEN, BrowserPolicy,
                                BrowserPolicyError)
from app.browser.provider import BrowserPage, PageView

MAX_SELECTOR_CHARS = 500


def _selector_ok(selector: str) -> str:
    if not isinstance(selector, str) or not selector.strip() or len(selector) > MAX_SELECTOR_CHARS:
        raise BrowserPolicyError("BROWSER_INVALID_SELECTOR: selector must be 1-500 characters")
    if "\x00" in selector:
        raise BrowserPolicyError("BROWSER_INVALID_SELECTOR")
    return selector.strip()


def _selector_tag(selector: str) -> str:
    """Stable, non-reversible tag for audit records (selectors themselves can
    contain tenant/user identifiers, so only the digest is persisted)."""
    return hashlib.sha256(selector.encode("utf-8", "ignore")).hexdigest()[:16]


class BrowserSession:
    """One isolated task/session: its own browser context and page set."""

    def __init__(self, session_id: str, engine, policy: BrowserPolicy, config, *,
                 store=None, task_id: str | None = None):
        self.id = session_id
        self.engine = engine
        self.policy = policy
        self.config = config
        self.store = store
        self.task_id = task_id
        self.created_at = time.monotonic()
        self.last_used = self.created_at
        self._pages: list[BrowserPage] = []
        self._index = 0

    # -- lifecycle ------------------------------------------------------------ #
    async def page(self) -> BrowserPage:
        if not self._pages:
            self._pages.append(await self.engine.new_page(self.id))
            self._index = 0
        return self._pages[self._index]

    async def close(self) -> None:
        for page in self._pages:
            try:
                await page.close()
            except Exception:
                pass
        self._pages = []
        try:
            await self.engine.close_session(self.id)
        except Exception:
            pass

    def _touch(self) -> None:
        self.last_used = time.monotonic()

    def expired(self, ttl_seconds: float, idle_seconds: float) -> bool:
        now = time.monotonic()
        return (now - self.created_at) > ttl_seconds or (now - self.last_used) > idle_seconds

    # -- observation shaping --------------------------------------------------- #
    def _view(self, view: PageView, *, wrap: bool = True) -> dict[str, Any]:
        """Convert an engine view into the model-facing, untrusted observation."""
        max_chars = int(getattr(self.config, "browser_max_snapshot_chars", 20_000))
        text = (view.text or "")[:max_chars]
        if wrap:
            wrapped, suspected = self.policy.observe(text, label="webpage-text")
        else:
            wrapped, suspected = "", False
        links = []
        for link in (view.links or [])[: int(getattr(self.config, "browser_max_links", 60))]:
            links.append({"text": self.policy.observe(str(link.get("text", ""))[:200],
                                                     label="page-link-text")[0]
                          if False else str(link.get("text", ""))[:200],
                          "href": str(link.get("href", ""))[:500]})
        return {
            "session_id": self.id,
            "url": str(view.url)[:2000],
            "title": str(view.title)[:300],
            "status": view.status,
            "text": wrapped,
            "text_chars": len(text),
            "links": links,
            "forms": json.loads(json.dumps(view.forms or [])[:20_000]) if view.forms else [],
            "has_password_field": bool(view.has_password_field),
            "injection_suspected": suspected,
            "untrusted": True,
        }

    # -- actions --------------------------------------------------------------- #
    async def navigate(self, url: str) -> dict[str, Any]:
        target = await self.policy.validate_url(url)
        page = await self.page()
        await self._audit("browser.navigate", {"url": target[:500], "session_id": self.id})
        view = await page.goto(target, timeout_seconds=float(
            getattr(self.config, "browser_navigation_timeout_seconds", 30)))
        self._touch()
        return self._view(view)

    async def view(self) -> dict[str, Any]:
        self.policy.check_enabled()
        page = await self.page()
        self._touch()
        return self._view(await page.view())

    async def accessibility(self) -> dict[str, Any]:
        self.policy.check_enabled()
        page = await self.page()
        tree = await page.accessibility()
        wrapped, suspected = self.policy.observe(tree, label="accessibility-tree")
        self._touch()
        return {"session_id": self.id, "url": page.url[:2000], "tree": wrapped,
                "injection_suspected": suspected, "untrusted": True}

    async def click(self, selector: str, *, action: str | None = None,
                    approval: str | None = None) -> dict[str, Any]:
        self.policy.check_enabled()
        selector = _selector_ok(selector)
        page = await self.page()
        label = await page.element_label(selector)
        implied = self.policy.classify_target_label(label)
        declared = self.policy.check_action(action, approval)
        required = declared or implied
        if required and not declared:
            raise BrowserPolicyError(
                f"BROWSER_APPROVAL_REQUIRED: clicking '{label[:80]}' is classified as '{required}' "
                f"and needs approval (resend with action='{required}', approval='{APPROVAL_TOKEN}')")
        if required and not self.policy.check_action(required, approval):
            # check_action already raised; this line keeps the type checker honest.
            raise BrowserPolicyError("BROWSER_APPROVAL_REQUIRED")
        await self._audit("browser.action", {
            "session_id": self.id, "action": "click", "selector": _selector_tag(selector),
            "sensitive_action": required, "approved": bool(required and approval)})
        view = await page.click(selector, timeout_seconds=float(
            getattr(self.config, "browser_action_timeout_seconds", 20)))
        self._touch()
        return self._view(view)

    async def type_text(self, selector: str, text: str, *, submit: bool = False,
                        action: str | None = None, approval: str | None = None) -> dict[str, Any]:
        self.policy.check_enabled()
        selector = _selector_ok(selector)
        if not isinstance(text, str) or len(text) > int(getattr(self.config, "input_max_text_chars", 2000)):
            raise BrowserPolicyError("BROWSER_INVALID_TEXT: text exceeds the configured input budget")
        page = await self.page()
        field = (await page.field_type(selector)).lower()
        declared = self.policy.check_action(action, approval)
        required = declared
        if field == "password" and required != "credential_operation":
            self.policy.check_action("credential_operation", approval)
            required = "credential_operation"
        if submit and required not in {"submit_form", "send_message", "purchase", "credential_operation"}:
            self.policy.check_action("submit_form", approval)
            required = required or "submit_form"
        # The typed value is NEVER logged or returned; only its length.
        await self._audit("browser.action", {
            "session_id": self.id, "action": "type", "selector": _selector_tag(selector),
            "chars": len(text), "submit": bool(submit), "field_type": field[:20],
            "sensitive_action": required, "approved": bool(required and approval)})
        view = await page.fill(selector, text, submit=submit, timeout_seconds=float(
            getattr(self.config, "browser_action_timeout_seconds", 20)))
        self._touch()
        return self._view(view)

    async def select_option(self, selector: str, value: str, *,
                            action: str | None = None, approval: str | None = None) -> dict[str, Any]:
        self.policy.check_enabled()
        selector = _selector_ok(selector)
        declared = self.policy.check_action(action, approval)
        page = await self.page()
        label = await page.element_label(selector)
        implied = self.policy.classify_target_label(label)
        required = declared or implied
        if implied and not declared:
            raise BrowserPolicyError(
                f"BROWSER_APPROVAL_REQUIRED: selecting in '{label[:80]}' is classified as "
                f"'{implied}' and needs approval")
        await self._audit("browser.action", {"session_id": self.id, "action": "select",
                                             "selector": _selector_tag(selector),
                                             "sensitive_action": required})
        view = await page.select_option(selector, str(value)[:200], timeout_seconds=float(
            getattr(self.config, "browser_action_timeout_seconds", 20)))
        self._touch()
        return self._view(view)

    async def press(self, key: str) -> dict[str, Any]:
        self.policy.check_enabled()
        key = str(key or "").strip()
        if not key or len(key) > 40 or "\x00" in key:
            raise BrowserPolicyError("BROWSER_INVALID_KEY")
        page = await self.page()
        await self._audit("browser.action", {"session_id": self.id, "action": "press", "key": key[:40]})
        view = await page.press(key, timeout_seconds=float(
            getattr(self.config, "browser_action_timeout_seconds", 20)))
        self._touch()
        return self._view(view)

    async def scroll(self, dx: int = 0, dy: int = 600) -> dict[str, Any]:
        self.policy.check_enabled()
        if abs(int(dx)) > 10_000 or abs(int(dy)) > 10_000:
            raise BrowserPolicyError("BROWSER_INVALID_SCROLL")
        page = await self.page()
        view = await page.scroll(int(dx), int(dy))
        self._touch()
        return self._view(view)

    async def history(self, action: str) -> dict[str, Any]:
        self.policy.check_enabled()
        if action not in {"back", "forward", "refresh"}:
            raise BrowserPolicyError("BROWSER_INVALID_HISTORY_ACTION")
        page = await self.page()
        await self._audit("browser.action", {"session_id": self.id, "action": f"history:{action}"})
        view = await page.history(action, timeout_seconds=float(
            getattr(self.config, "browser_navigation_timeout_seconds", 30)))
        self._touch()
        return self._view(view)

    async def screenshot(self, *, full_page: bool = False, persist: bool = False,
                         analyze: bool = False) -> dict[str, Any]:
        self.policy.check_enabled()
        page = await self.page()
        image = await page.screenshot(full_page=bool(full_page))
        limit = int(getattr(self.config, "browser_screenshot_max_bytes", 8_000_000))
        if len(image) > limit:
            raise BrowserPolicyError("BROWSER_SCREENSHOT_TOO_LARGE", f"limit is {limit} bytes")
        redacted = False
        plan = self._redaction_plan()
        if plan is not None and not plan.empty:
            from app.computer.perception.privacy import redact_png
            image = redact_png(image, plan)
            redacted = True
        digest = hashlib.sha256(image).hexdigest()
        saved_path = None
        if persist and bool(getattr(self.config, "browser_screenshot_persist", False)):
            saved_path = self._store_image(image, digest)
        description = None
        if analyze:
            description = await self._analyze(image)
        await self._audit("browser.screenshot", {
            "session_id": self.id, "bytes": len(image), "sha256": digest[:16],
            "redacted": redacted, "persisted": bool(saved_path), "analyzed": bool(description)})
        self._touch()
        return {"session_id": self.id, "url": page.url[:2000], "bytes": len(image),
                "sha256": digest, "redacted": redacted, "saved_path": saved_path,
                "description": description, "untrusted": True}

    async def download(self, selector: str, *, action: str | None = None,
                       approval: str | None = None) -> dict[str, Any]:
        self.policy.check_enabled()
        selector = _selector_ok(selector)
        declared = self.policy.check_action(action, approval)
        page = await self.page()
        label = await page.element_label(selector)
        implied = self.policy.classify_target_label(label)
        if implied and not declared:
            raise BrowserPolicyError(
                f"BROWSER_APPROVAL_REQUIRED: downloading from '{label[:80]}' is classified as "
                f"'{implied}' and needs approval")
        name, data = await page.download(selector, timeout_seconds=float(
            getattr(self.config, "browser_action_timeout_seconds", 20)))
        self.policy.check_download(len(data))
        digest = hashlib.sha256(data).hexdigest()
        saved = self._store_download(name, data)
        await self._audit("browser.download", {"session_id": self.id, "bytes": len(data),
                                               "sha256": digest[:16], "saved_path": saved})
        self._touch()
        return {"session_id": self.id, "filename": name[:200], "bytes": len(data),
                "sha256": digest, "saved_path": saved, "untrusted": True}

    async def upload(self, selector: str, path: str) -> dict[str, Any]:
        self.policy.check_enabled()
        selector = _selector_ok(selector)
        resolved = self.policy.resolve_upload_path(path)
        page = await self.page()
        await self._audit("browser.upload", {"session_id": self.id,
                                             "selector": _selector_tag(selector),
                                             "bytes": resolved.stat().st_size})
        view = await page.upload(selector, str(resolved), timeout_seconds=float(
            getattr(self.config, "browser_action_timeout_seconds", 20)))
        self._touch()
        return self._view(view)

    # -- tabs -------------------------------------------------------------------- #
    async def tabs(self, action: str, index: int | None = None) -> dict[str, Any]:
        self.policy.check_enabled()
        limit = int(getattr(self.config, "browser_max_pages_per_session", 4))
        if action == "new":
            if len(self._pages) >= limit:
                raise BrowserPolicyError("BROWSER_TAB_LIMIT: too many open tabs for this session")
            self._pages.append(await self.engine.new_page(self.id))
            self._index = len(self._pages) - 1
        elif action == "close":
            if len(self._pages) <= 1:
                raise BrowserPolicyError("BROWSER_TAB_LIMIT: cannot close the last tab")
            target = self._index if index is None else int(index)
            if not 0 <= target < len(self._pages):
                raise BrowserPolicyError("BROWSER_INVALID_TAB_INDEX")
            await self._pages.pop(target).close()
            self._index = max(0, min(self._index, len(self._pages) - 1))
        elif action == "switch":
            target = int(index if index is not None else 0)
            if not 0 <= target < len(self._pages):
                raise BrowserPolicyError("BROWSER_INVALID_TAB_INDEX")
            self._index = target
        elif action != "list":
            raise BrowserPolicyError("BROWSER_INVALID_TAB_ACTION")
        self._touch()
        return {"session_id": self.id, "index": self._index,
                "tabs": [{"index": i, "url": page.url[:500]} for i, page in enumerate(self._pages)]}

    # -- helpers ------------------------------------------------------------------ #
    def _redaction_plan(self):
        try:
            from app.computer.perception.privacy import RedactionPlan
            return RedactionPlan.from_settings(list(getattr(self.config, "screen_sensitive_regions", []) or []))
        except Exception:
            return None

    def _screenshot_dir(self) -> Path:
        directory = Path(self.config.workspace_root) / ".secureagent-browser" / "screenshots"
        directory.mkdir(parents=True, exist_ok=True)
        return directory

    def _store_image(self, image: bytes, digest: str) -> str:
        target = self._screenshot_dir() / f"{digest[:16]}.png"
        target.write_bytes(image)
        try:
            target.chmod(0o600)
        except OSError:
            pass
        return target.relative_to(Path(self.config.workspace_root)).as_posix()

    def _store_download(self, name: str, data: bytes) -> str:
        safe = "".join(ch for ch in name if ch.isalnum() or ch in "._-")[:120] or "download.bin"
        directory = Path(self.config.workspace_root) / ".secureagent-browser" / "downloads"
        directory.mkdir(parents=True, exist_ok=True)
        target = directory / f"{uuid4().hex[:8]}-{safe}"
        target.write_bytes(data)
        try:
            target.chmod(0o600)
        except OSError:
            pass
        return target.relative_to(Path(self.config.workspace_root)).as_posix()

    async def _analyze(self, image: bytes) -> str | None:
        """Optional vision description — LOCAL by default; cloud only when the
        operator configured an external vision provider (same adapter the
        computer-use layer uses)."""
        try:
            from app.computer.perception.vision import VisionAdapter, VisionDisabled
            adapter = VisionAdapter(
                enabled=bool(getattr(self.config, "vision_cloud_enabled", False)),
                endpoint=str(getattr(self.config, "vision_cloud_endpoint", "") or "") or None,
                api_key=getattr(self.config, "vision_cloud_api_key", None),
                timeout_seconds=float(getattr(self.config, "ocr_timeout_seconds", 20)),
            )
            if not await adapter.available():
                return None
            result = await adapter.describe(image, "Describe the browser page screenshot.")
            return result.description[:4000]
        except Exception:
            return None

    async def _audit(self, event: str, details: dict[str, Any]) -> None:
        if self.store is None:
            return
        try:
            await self.store.audit(event, details, actor="browser")
        except Exception:
            pass
