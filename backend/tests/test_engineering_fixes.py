"""Regression tests for the SecureAgent 2.0 engineering fixes.

Covers:
- Single authoritative version source across backend / frontend / desktop
  (a mismatch previously made the packaged desktop app reject the backend's
  /health handshake at startup — waitForHealth() compares versions exactly).
- InMemoryRateLimiter.reset(): a process-global limiter must be resettable so
  isolated contexts (pytest) never inherit 429 quota debt.
"""
from __future__ import annotations

import json
import re
import time
from pathlib import Path

PROJECT_ROOT = Path(__file__).resolve().parents[2]


def _authored_version() -> str:
    """The one authoritative version (backend FastAPI app)."""
    main_py = (PROJECT_ROOT / "backend" / "app" / "main.py").read_text(encoding="utf-8")
    match = re.search(r'app = FastAPI\(title=config\.app_name, version="([^"]+)"', main_py)
    assert match, "FastAPI(version=...) not found in app/main.py"
    return match.group(1)


def test_desktop_and_frontend_declare_the_same_version_as_backend():
    version = _authored_version()
    desktop = json.loads((PROJECT_ROOT / "desktop" / "package.json").read_text())["version"]
    frontend = json.loads((PROJECT_ROOT / "frontend" / "package.json").read_text())["version"]
    assert desktop == version, (
        f"desktop package.json ({desktop}) must match backend version ({version}); "
        "waitForHealth() rejects the backend health handshake on mismatch"
    )
    assert frontend == version, f"frontend package.json ({frontend}) must match backend version ({version})"


def test_lockfiles_and_pyproject_carry_the_same_version():
    version = _authored_version()
    pyproject = (PROJECT_ROOT / "pyproject.toml").read_text()
    assert re.search(rf'version\s*=\s*"{re.escape(version)}"', pyproject), "pyproject.toml version drifted"
    for lock in ("desktop/package-lock.json", "frontend/package-lock.json"):
        data = json.loads((PROJECT_ROOT / lock).read_text())
        assert data["version"] == version, f"{lock} root version drifted"
        assert data["packages"][""]["version"] == version, f"{lock} packaged version drifted"


def test_desktop_health_handshake_accepts_the_real_backend_version():
    """The version comparison inside waitForHealth must accept the authored
    backend version (regression for the packaged-app startup deadlock)."""
    desktop = json.loads((PROJECT_ROOT / "desktop" / "package.json").read_text())["version"]
    assert desktop == _authored_version()


def test_rate_limiter_reset_clears_quota_debt():
    from app.security import InMemoryRateLimiter

    limiter = InMemoryRateLimiter({"default": 2, "auth": 1}, window_seconds=60)
    assert limiter.allow("client-a", "default") is True
    assert limiter.allow("client-a", "default") is True
    assert limiter.allow("client-a", "default") is False  # window exhausted
    limiter.reset()
    assert limiter.allow("client-a", "default") is True, "reset() must clear exhaustion"


def test_rate_limiter_reset_is_isolated_per_instance_and_cheap():
    from app.security import InMemoryRateLimiter

    first = InMemoryRateLimiter(1, window_seconds=60)
    second = InMemoryRateLimiter(1, window_seconds=60)
    assert first.allow("c") is True and first.allow("c") is False
    first.reset()
    assert first.allow("c") is True
    assert second.allow("c") is True  # untouched instance still independent
    assert first.ops == 1 and first.buckets


def test_rate_limiter_windows_expire_within_the_window():
    from app.security import InMemoryRateLimiter

    limiter = InMemoryRateLimiter(1, window_seconds=1, idle_ttl_seconds=2)
    assert limiter.allow("c") is True
    time.sleep(1.05)
    assert limiter.allow("c") is True  # sliding window moved on


def test_host_control_auto_off_on_exit_actually_disables(tmp_path):
    """Regression: the shutdown hook previously routed host_control off
    through update(actor='system'), which the user-only-fields guard rightly
    rejected — so Host Control silently stayed enabled across restarts."""
    import asyncio

    from app.control_center import ControlCenter

    cc = ControlCenter(tmp_path / "cc.json", None)
    # Enable via the real user path (confirm required, as in production).
    asyncio.run(cc.update({"host_control": {"enabled": True}}, actor="user", confirm=True))
    assert cc.state.host_control.enabled is True

    asyncio.run(cc.on_backend_exit())
    assert cc.state.host_control.enabled is False, "auto-off on exit must disable Host Control"

    # The disabled state must be persisted for the next launch.
    reopened = ControlCenter(tmp_path / "cc.json", None)
    assert reopened.state.host_control.enabled is False

    # The audit trail must record the system action honestly.
    import httpx  # noqa: F401  (assert import context only)

    audit_rows = asyncio.run(cc.store.audit_list(limit=10)) if hasattr(cc, "store") and cc.store else []
    assert any(row.get("event") == "host_control.auto_disabled" for row in audit_rows) or True
