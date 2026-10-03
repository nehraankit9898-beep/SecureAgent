"""REST surface for the browser subsystem (Control Center + diagnostics).

The API never returns raw page bytes, cookies, headers or typed secrets — only
the same untrusted, bounded observations the tools receive.
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.browser.policy import BrowserPolicyError
from app.browser.runtime import get_browser_runtime


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SessionIn(_Strict):
    session_id: str = Field("default", min_length=1, max_length=64)
    task_id: str | None = Field(None, max_length=64)


class NavigateIn(_Strict):
    url: str = Field(min_length=1, max_length=2000)


class BrowserActionIn(_Strict):
    action: Literal["click", "type", "select", "press", "scroll", "history", "tabs"]
    selector: str | None = Field(None, max_length=500)
    text: str | None = Field(None, max_length=10_000)
    value: str | None = Field(None, max_length=200)
    key: str | None = Field(None, max_length=40)
    dx: int = Field(0, ge=-10_000, le=10_000)
    dy: int = Field(600, ge=-10_000, le=10_000)
    submit: bool = False
    tab_action: Literal["list", "new", "close", "switch"] = "list"
    index: int | None = Field(None, ge=0, le=32)
    sensitive_action: Literal["purchase", "send_message", "submit_form", "delete",
                              "account_change", "security_change",
                              "credential_operation"] | None = None
    approval: Literal["APPROVE"] | None = None


class ScreenshotIn(_Strict):
    full_page: bool = False
    persist: bool = False
    analyze: bool = False


def _runtime():
    runtime = get_browser_runtime()
    if runtime is None:
        raise HTTPException(status_code=503, detail={
            "error_code": "BROWSER_UNAVAILABLE",
            "message": "The browser runtime has not been initialized."})
    return runtime


async def _session_or_404(session_id: str):
    runtime = _runtime()
    try:
        return await runtime.session(session_id)
    except BrowserPolicyError as error:
        raise HTTPException(status_code=404 if "NOT_FOUND" in error.code else 403,
                            detail={"error_code": error.code, "message": str(error)}) from None


def build_browser_router(prefix: str = "/api/v1/browser") -> APIRouter:
    router = APIRouter(prefix=prefix, tags=["browser"])

    @router.get("")
    async def browser_status() -> dict[str, Any]:
        return await _runtime().status()

    @router.post("/engine/start")
    async def engine_start() -> dict[str, Any]:
        runtime = _runtime()
        started = await runtime.start()
        return {"started": started, "status": await runtime.status()}

    @router.get("/sessions")
    async def list_sessions() -> dict[str, Any]:
        status = await _runtime().status()
        return {"sessions": status["sessions"], "limits": status["limits"]}

    @router.post("/sessions", status_code=201)
    async def create_session(payload: SessionIn) -> dict[str, Any]:
        runtime = _runtime()
        try:
            session = await runtime.session(payload.session_id, task_id=payload.task_id)
        except BrowserPolicyError as error:
            status = 409 if "LIMIT" in error.code else 403
            raise HTTPException(status_code=status, detail={
                "error_code": error.code, "message": str(error)}) from None
        return {"session_id": session.id, "task_id": session.task_id,
                "created": True, "status": await runtime.status()}

    @router.delete("/sessions/{session_id}")
    async def close_session(session_id: str) -> dict[str, Any]:
        closed = await _runtime().close(session_id, reason="api")
        return {"session_id": session_id, "closed": closed}

    @router.post("/sessions/{session_id}/navigate")
    async def navigate(session_id: str, payload: NavigateIn) -> dict[str, Any]:
        session = await _session_or_404(session_id)
        return await session.navigate(payload.url)

    @router.post("/sessions/{session_id}/snapshot")
    async def snapshot(session_id: str, include_accessibility: bool = False) -> dict[str, Any]:
        session = await _session_or_404(session_id)
        view = await session.view()
        if include_accessibility:
            tree = await session.accessibility()
            view["accessibility"] = tree["tree"]
            view["accessibility_injection_suspected"] = tree["injection_suspected"]
        return view

    @router.post("/sessions/{session_id}/action")
    async def action(session_id: str, payload: BrowserActionIn) -> dict[str, Any]:
        session = await _session_or_404(session_id)
        kind = payload.action
        if kind == "click":
            if not payload.selector:
                raise HTTPException(status_code=422, detail={"error_code": "BROWSER_INVALID_SELECTOR",
                                                             "message": "selector is required"})
            return await session.click(payload.selector, action=payload.sensitive_action,
                                       approval=payload.approval)
        if kind == "type":
            if not payload.selector:
                raise HTTPException(status_code=422, detail={"error_code": "BROWSER_INVALID_SELECTOR",
                                                             "message": "selector is required"})
            return await session.type_text(payload.selector, payload.text or "", submit=payload.submit,
                                           action=payload.sensitive_action, approval=payload.approval)
        if kind == "select":
            if not payload.selector or payload.value is None:
                raise HTTPException(status_code=422, detail={"error_code": "BROWSER_INVALID_SELECTOR",
                                                             "message": "selector and value are required"})
            return await session.select_option(payload.selector, payload.value,
                                               action=payload.sensitive_action,
                                               approval=payload.approval)
        if kind == "press":
            if not payload.key:
                raise HTTPException(status_code=422, detail={"error_code": "BROWSER_INVALID_KEY",
                                                             "message": "key is required"})
            return await session.press(payload.key)
        if kind == "scroll":
            return await session.scroll(payload.dx, payload.dy)
        if kind == "history":
            if payload.value not in {"back", "forward", "refresh"}:
                raise HTTPException(status_code=422, detail={
                    "error_code": "BROWSER_INVALID_HISTORY_ACTION",
                    "message": "value must be back, forward or refresh"})
            return await session.history(payload.value)
        return await session.tabs(payload.tab_action, payload.index)

    @router.post("/sessions/{session_id}/screenshot")
    async def screenshot(session_id: str, payload: ScreenshotIn) -> dict[str, Any]:
        session = await _session_or_404(session_id)
        return await session.screenshot(full_page=payload.full_page, persist=payload.persist,
                                        analyze=payload.analyze)

    @router.post("/close-all")
    async def close_all() -> dict[str, Any]:
        runtime = _runtime()
        closed = await runtime.close_all()
        return {"closed": closed, "status": await runtime.status()}

    return router


__all__ = ["build_browser_router", "BrowserActionIn", "NavigateIn", "ScreenshotIn", "SessionIn"]
