"""Browser runtime — process-wide session manager.

Owns the single engine instance, the bounded session table (isolation per
task/session, TTL + idle expiry), the availability probe and the audit of
session lifecycle events. Tools and the REST layer both talk to this object;
nothing else constructs an engine.
"""
from __future__ import annotations

import asyncio
import logging
import time
from typing import Any

from app.browser.policy import BrowserPolicy, BrowserPolicyError
from app.browser.provider import (BrowserEngine, BrowserEngineUnavailable,
                                  DisabledBrowserEngine, PlaywrightBrowserEngine,
                                  probe_browser_engine)
from app.browser.session import BrowserSession

logger = logging.getLogger("secureagent.browser")

DEFAULT_SESSION = "default"


class BrowserRuntime:
    def __init__(self, config, *, engine: BrowserEngine | None = None, store=None,
                 control_center=None):
        self.config = config
        self.store = store
        self.policy = BrowserPolicy(config, control_center=control_center)
        probe = probe_browser_engine()
        self.engine: BrowserEngine = engine or (
            PlaywrightBrowserEngine(config) if probe.available
            else DisabledBrowserEngine(probe.reason or "BROWSER_ENGINE_UNAVAILABLE"))
        self.sessions: dict[str, BrowserSession] = {}
        self.started = False
        self.last_error: str | None = None
        self._lock = asyncio.Lock()

    # -- availability ---------------------------------------------------------- #
    @property
    def available(self) -> bool:
        return self.started and self.engine.available

    @property
    def engine_available(self) -> bool:
        """Engine-level availability, independent of the master switches."""
        return bool(getattr(self.engine, "available", False))

    def reason(self) -> str | None:
        """Honest, ordered availability explanation (never a fake success)."""
        if not bool(getattr(self.config, "browser_enabled", False)):
            return "BROWSER_DISABLED: Browser automation is disabled in Settings"
        if not self.policy.enabled:
            return self.policy.disabled_reason()
        if self.last_error:
            return self.last_error
        if not self.engine_available:
            return getattr(self.engine, "reason", None) or "BROWSER_ENGINE_UNAVAILABLE"
        return None

    async def start(self) -> bool:
        """Idempotent engine start. Never raises: availability is reported."""
        if not bool(getattr(self.config, "browser_enabled", False)):
            self.last_error = "BROWSER_DISABLED: Browser automation is disabled in Settings"
            return False
        if self.started and self.engine.available:
            return True
        try:
            await self.engine.start()
            self.started = True
            self.last_error = None
            await self._audit("browser.engine_started", {"provider": self.engine.provider_id})
            return True
        except BrowserEngineUnavailable as error:
            self.started = False
            self.last_error = str(error)[:300]
            await self._audit("browser.engine_unavailable", {"provider": self.engine.provider_id,
                                                             "reason": str(error)[:200]})
            return False
        except Exception as error:  # defensive: availability is data, never an exception
            self.started = False
            self.last_error = f"BROWSER_ENGINE_UNAVAILABLE: {type(error).__name__}"
            await self._audit("browser.engine_unavailable", {"provider": self.engine.provider_id,
                                                             "reason": type(error).__name__})
            return False

    async def stop(self) -> None:
        for session_id in list(self.sessions):
            await self.close(session_id, reason="shutdown")
        try:
            await self.engine.stop()
        except Exception:
            logger.debug("engine stop failed", exc_info=True)
        self.started = False

    # -- sessions --------------------------------------------------------------- #
    async def session(self, session_id: str = DEFAULT_SESSION, *,
                      task_id: str | None = None, create: bool = True) -> BrowserSession:
        self.policy.check_enabled()
        if not isinstance(session_id, str) or not session_id.strip() or len(session_id) > 64:
            raise BrowserPolicyError("BROWSER_INVALID_SESSION_ID")
        session_id = session_id.strip()
        await self.sweep()
        existing = self.sessions.get(session_id)
        if existing is not None:
            existing.task_id = task_id or existing.task_id
            return existing
        if not create:
            raise BrowserPolicyError("BROWSER_SESSION_NOT_FOUND")
        limit = self.session_limit()
        if len(self.sessions) >= limit:
            raise BrowserPolicyError(
                "BROWSER_SESSION_LIMIT: too many browser sessions "
                "(close one or raise browser_max_sessions)")
        if not await self.start():
            raise BrowserPolicyError(self.reason() or "BROWSER_ENGINE_UNAVAILABLE")
        session = BrowserSession(session_id, self.engine, self.policy, self.config,
                                 store=self.store, task_id=task_id)
        self.sessions[session_id] = session
        await self._audit("browser.session_started", {"session_id": session_id, "task_id": task_id})
        return session

    async def close(self, session_id: str, *, reason: str = "user") -> bool:
        session = self.sessions.pop(session_id, None)
        if session is None:
            return False
        await session.close()
        await self._audit("browser.session_closed", {"session_id": session_id, "reason": reason})
        return True

    async def close_all(self) -> int:
        closed = 0
        for session_id in list(self.sessions):
            closed += 1 if await self.close(session_id, reason="close_all") else 0
        return closed

    async def sweep(self) -> int:
        """Close sessions past their TTL/idle deadline (bounded resource use)."""
        ttl = float(getattr(self.config, "browser_session_ttl_seconds", 600))
        idle = float(getattr(self.config, "browser_session_idle_seconds", 300))
        expired = [sid for sid, session in self.sessions.items() if session.expired(ttl, idle)]
        for session_id in expired:
            await self.close(session_id, reason="expired")
        return len(expired)

    def session_limit(self) -> int:
        """Effective session ceiling = min(Settings, Control Center)."""
        limit = int(getattr(self.config, "browser_max_sessions", 2))
        try:
            from app.control_center import get_control_center
            gate = get_control_center()
            if gate is not None:
                limit = min(limit, int(gate.state.browser.max_sessions))
        except Exception:
            pass
        return max(1, limit)

    def downloads_allowed(self) -> bool:
        if not bool(getattr(self.config, "browser_allow_downloads", False)):
            return False
        try:
            from app.control_center import get_control_center
            gate = get_control_center()
            if gate is not None:
                return bool(gate.state.browser.downloads)
        except Exception:
            pass
        return True

    def uploads_allowed(self) -> bool:
        if not bool(getattr(self.config, "browser_allow_uploads", False)):
            return False
        try:
            from app.control_center import get_control_center
            gate = get_control_center()
            if gate is not None:
                return bool(gate.state.browser.uploads)
        except Exception:
            pass
        return True

    # -- status ------------------------------------------------------------------ #
    async def status(self) -> dict[str, Any]:
        await self.sweep()
        probe = probe_browser_engine()
        gate_active = None
        try:
            from app.control_center import get_control_center
            gate = get_control_center()
            gate_active = None if gate is None else bool(gate.browser_active())
        except Exception:
            gate_active = None
        return {
            "enabled": bool(getattr(self.config, "browser_enabled", False)),
            "control_center_active": gate_active,
            "policy_active": self.policy.enabled,
            "engine": getattr(self.engine, "provider_id", "unknown"),
            "engine_installed": bool(probe.available),
            "engine_started": bool(self.started and self.engine.available),
            "available": self.available,
            "reason": self.reason(),
            "headless": bool(getattr(self.config, "browser_headless", True)),
            "sessions": [{"session_id": sid, "task_id": session.task_id,
                          "open_tabs": len(session._pages),
                          "age_seconds": round(time.monotonic() - session.created_at, 1),
                          "idle_seconds": round(time.monotonic() - session.last_used, 1)}
                         for sid, session in self.sessions.items()],
            "limits": {
                "max_sessions": int(getattr(self.config, "browser_max_sessions", 2)),
                "max_pages_per_session": int(getattr(self.config, "browser_max_pages_per_session", 4)),
                "session_ttl_seconds": int(getattr(self.config, "browser_session_ttl_seconds", 600)),
                "navigation_timeout_seconds": float(getattr(self.config, "browser_navigation_timeout_seconds", 30)),
                "action_timeout_seconds": float(getattr(self.config, "browser_action_timeout_seconds", 20)),
                "max_snapshot_chars": int(getattr(self.config, "browser_max_snapshot_chars", 20_000)),
            },
            "capabilities": {
                "navigation": True, "snapshot": True, "click": True, "type": True,
                "select": True, "scroll": True, "history": True, "tabs": True,
                "screenshot": True, "downloads": bool(getattr(self.config, "browser_allow_downloads", False)),
                "uploads": bool(getattr(self.config, "browser_allow_uploads", False)),
                "sensitive_action_approval": bool(
                    getattr(self.config, "browser_sensitive_actions_require_approval", True)),
            },
        }

    async def _audit(self, event: str, details: dict[str, Any]) -> None:
        if self.store is None:
            return
        try:
            await self.store.audit(event, details, actor="browser")
        except Exception:
            logger.debug("browser audit failed", exc_info=True)


_runtime: BrowserRuntime | None = None


def get_browser_runtime() -> BrowserRuntime | None:
    return _runtime


def set_browser_runtime(runtime: BrowserRuntime | None) -> BrowserRuntime | None:
    global _runtime
    _runtime = runtime
    return _runtime
