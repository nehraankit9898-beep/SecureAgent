"""SecureAgent 2.0 — tests for the new diagnostics, mode, and honest-health endpoints.

These tests verify the 2.0 additions:
- GET /api/v1/diagnostics runs every test_* function and returns real verdicts.
- GET /api/v1/mode returns the current effective SAFE/ASSIST/CONTROL mode.
- POST /api/v1/mode applies a preset and audits the transition.
- GET /api/v1/health returns health_v2 with real probes (no hardcoded "ok").
- store.ping() actually probes SQLite.

The tests do NOT require bwrap, Ollama, or Docker — they assert honest
NOT_AVAILABLE / FAIL verdicts when those dependencies are missing, which is
the whole point of the 2.0 "never fake status" principle.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

# Ensure the backend module is importable.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from app.config import settings  # noqa: E402
from app.main import app  # noqa: E402
from app.memory import MemoryStore  # noqa: E402

# conftest.py sets SECURE_AGENT_AUTH_REQUIRED=true and SECURE_AGENT_API_TOKEN
# to TEST_TOKEN. Mirror it here for the headers.
TEST_TOKEN = "test-only-token-0123456789abcdef0123456789"
HEADERS = {"X-API-Token": TEST_TOKEN, "Authorization": f"Bearer {TEST_TOKEN}"}


@pytest.fixture(scope="module")
def client() -> TestClient:
    """Module-scoped TestClient — the lifespan initializes the store + automation."""
    with TestClient(app) as c:
        yield c


# --------------------------------------------------------------------------- #
# store.ping() — real SQLite probe
# --------------------------------------------------------------------------- #

def test_store_ping_returns_true_for_real_database(tmp_path: Path):
    """store.ping() returns True when SQLite is reachable."""
    store = MemoryStore(tmp_path / "test.db")
    # init() is required to create the tables; ping() only checks connectivity.
    import asyncio
    asyncio.run(store.init())
    assert asyncio.run(store.ping()) is True


def test_store_ping_returns_false_for_unwritable_path():
    """store.ping() returns False (never raises) when the path is unwritable."""
    import asyncio
    store = MemoryStore(Path("/proc/cannot-create.db"))
    assert asyncio.run(store.ping()) is False


# --------------------------------------------------------------------------- #
# GET /api/v1/health — honest probes, no hardcoded "ok"
# --------------------------------------------------------------------------- #

def test_health_returns_version_2_0_0(client: TestClient):
    response = client.get("/api/v1/health", headers=HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert body["version"] == "2.0.0", "version must be bumped to 2.0.0"


def test_health_includes_health_v2_block(client: TestClient):
    """2.0 adds a health_v2 block with the richer READY/DEGRADED/FAILED model."""
    response = client.get("/api/v1/health", headers=HEADERS)
    body = response.json()
    assert "health_v2" in body
    h2 = body["health_v2"]
    # Every field must be a real verdict, never a hardcoded "ok".
    for field in ("overall", "database", "workspace", "ollama", "chat_model",
                  "embedding_model", "terminal", "tools", "configuration",
                  "permissions", "logs", "automation"):
        assert field in h2, f"health_v2.{field} must be present"
        assert h2[field] != "ok", f"health_v2.{field} must not be hardcoded 'ok'"
    assert h2["overall"] in {"READY", "DEGRADED", "STARTING", "STOPPED", "FAILED"}


def test_health_includes_tool_counts(client: TestClient):
    """2.0 surfaces real tool counts (enabled/total/disabled)."""
    body = client.get("/api/v1/health", headers=HEADERS).json()
    assert "tool_counts" in body
    tc = body["tool_counts"]
    assert tc["total"] >= tc["enabled"]
    assert tc["disabled"] == tc["total"] - tc["enabled"]


def test_health_includes_ollama_detail(client: TestClient):
    """2.0 surfaces real Ollama detail (on_path, reachable, models, last_error)."""
    body = client.get("/api/v1/health", headers=HEADERS).json()
    assert "ollama_detail" in body
    od = body["ollama_detail"]
    assert "on_path" in od and isinstance(od["on_path"], bool)
    assert "reachable" in od and isinstance(od["reachable"], bool)
    assert "models" in od and isinstance(od["models"], list)


def test_health_database_is_real_not_hardcoded(client: TestClient):
    """The 2.0 health endpoint must probe the database, not return hardcoded 'ok'.

    We verify this by checking that health_v2.database is 'READY' (the store
    was initialized during the lifespan) — if it were still hardcoded, it would
    be 'ok' which is not a valid health_v2 verdict.
    """
    body = client.get("/api/v1/health", headers=HEADERS).json()
    assert body["health_v2"]["database"] == "READY", \
        "database health must be probed via store.ping(), not hardcoded"


# --------------------------------------------------------------------------- #
# GET /api/v1/diagnostics — unified feature self-test
# --------------------------------------------------------------------------- #

def test_diagnostics_returns_real_verdicts(client: TestClient):
    """GET /api/v1/diagnostics returns a real verdict for every feature.

    Verdicts must be in {PASS, FAIL, WARNING, NOT_AVAILABLE, NOT_CONFIGURED} —
    never 'ENABLED' or 'ok'. Each test must include reason, diagnostic,
    suggested_fix.
    """
    response = client.get("/api/v1/diagnostics", headers=HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert "overall" in body and body["overall"] in {"READY", "DEGRADED", "FAILED"}
    assert "summary" in body
    s = body["summary"]
    assert s["total"] >= 8, "at least 8 self-tests must run"
    assert s["pass"] + s["warning"] + s["fail"] + s["not_available"] == s["total"], \
        f"summary counts must sum to total: {s}"
    assert "tests" in body and len(body["tests"]) == s["total"]
    valid_verdicts = {"PASS", "FAIL", "WARNING", "NOT_AVAILABLE", "NOT_CONFIGURED"}
    for test in body["tests"]:
        assert test["status"] in valid_verdicts, \
            f"{test['component']} has invalid status {test['status']!r}"
        assert test["status"] != "ENABLED", "ENABLED is forbidden — never fake status"
        assert "reason" in test and isinstance(test["reason"], str) and test["reason"]
        assert "diagnostic" in test and isinstance(test["diagnostic"], str)
        assert "suggested_fix" in test and isinstance(test["suggested_fix"], str)
        assert "duration_ms" in test and isinstance(test["duration_ms"], int)


def test_diagnostics_includes_all_required_components(client: TestClient):
    """Every major module must have a self-test (spec section 11)."""
    body = client.get("/api/v1/diagnostics", headers=HEADERS).json()
    components = {t["component"] for t in body["tests"]}
    required = {"database", "terminal", "processes", "services", "network",
                "filesystem", "ollama", "memory", "rag", "automation"}
    missing = required - components
    assert not missing, f"missing self-tests for: {missing}"


def test_diagnostics_ollama_honest_when_not_installed(client: TestClient):
    """When ollama is not on PATH, the test must report NOT_AVAILABLE (not FAIL).

    This is the core 2.0 principle: missing optional dependencies are NOT_AVAILABLE,
    not FAIL. FAIL is reserved for 'should work but did not'.
    """
    import shutil
    body = client.get("/api/v1/diagnostics", headers=HEADERS).json()
    ollama_test = next(t for t in body["tests"] if t["component"] == "ollama")
    if not shutil.which("ollama"):
        assert ollama_test["status"] == "NOT_AVAILABLE", \
            f"ollama must be NOT_AVAILABLE when binary is missing, got {ollama_test['status']}"
        assert "Install Ollama" in ollama_test["suggested_fix"]


def test_diagnostics_audits_run(client: TestClient):
    """Every diagnostics run must be audited (spec section 38)."""
    client.get("/api/v1/diagnostics", headers=HEADERS)
    audits = client.get("/api/v1/audit?limit=20", headers=HEADERS).json()
    events = [a["event"] for a in audits]
    assert "diagnostics.run" in events, "diagnostics.run must be audited"


# --------------------------------------------------------------------------- #
# GET /api/v1/mode + POST /api/v1/mode — SAFE/ASSIST/CONTROL surface
# --------------------------------------------------------------------------- #

def test_get_mode_returns_one_of_safe_assist_control_custom(client: TestClient):
    response = client.get("/api/v1/mode", headers=HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert body["mode"] in {"SAFE", "ASSIST", "CONTROL", "CUSTOM"}
    assert "emergency_stopped" in body


def test_post_mode_safe_applies_preset(client: TestClient):
    """POST /api/v1/mode {SAFE} applies the SAFE preset and audits the transition."""
    response = client.post("/api/v1/mode", json={"mode": "SAFE"}, headers=HEADERS)
    assert response.status_code == 200
    body = response.json()
    assert body["ok"] is True
    assert body["mode"] == "SAFE"
    # Verify the mode is now reported as SAFE.
    mode_resp = client.get("/api/v1/mode", headers=HEADERS).json()
    assert mode_resp["mode"] == "SAFE"
    # Verify the transition was audited.
    audits = client.get("/api/v1/audit?limit=10", headers=HEADERS).json()
    assert any(a["event"] == "mode.applied" and a["details"].get("mode") == "SAFE"
               for a in audits)


def test_post_mode_assist_applies_preset(client: TestClient):
    response = client.post("/api/v1/mode", json={"mode": "ASSIST"}, headers=HEADERS)
    assert response.status_code == 200
    assert response.json()["mode"] == "ASSIST"
    assert client.get("/api/v1/mode", headers=HEADERS).json()["mode"] == "ASSIST"


def test_post_mode_rejects_invalid(client: TestClient):
    """Invalid mode values must be rejected with INVALID_MODE (never silently accepted)."""
    response = client.post("/api/v1/mode", json={"mode": "INVALID"}, headers=HEADERS)
    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "INVALID_MODE"


def test_post_mode_rejects_empty(client: TestClient):
    response = client.post("/api/v1/mode", json={"mode": ""}, headers=HEADERS)
    assert response.status_code == 422


def test_post_mode_control_does_not_enable_host_control(client: TestClient):
    """CONTROL mode must NOT enable host_control — that still requires a separate
    explicit confirmation via PATCH /api/v1/config?confirm=true (spec section 6).
    """
    response = client.post("/api/v1/mode", json={"mode": "CONTROL"}, headers=HEADERS)
    assert response.status_code == 200
    # Check the live config — host_control.enabled must still be False.
    config = client.get("/api/v1/config", headers=HEADERS).json()
    assert config["state"]["host_control"]["enabled"] is False, \
        "CONTROL mode must not enable host_control without explicit confirmation"


# --------------------------------------------------------------------------- #
# Emergency stop / resume cycle
# --------------------------------------------------------------------------- #

def test_emergency_stop_then_resume(client: TestClient):
    """Emergency stop must flip emergency_stopped=True; resume must restore it."""
    # Apply a known mode first so we have a baseline.
    client.post("/api/v1/mode", json={"mode": "ASSIST"}, headers=HEADERS)
    # Emergency stop.
    stop_resp = client.post("/api/v1/emergency-stop", headers=HEADERS)
    assert stop_resp.status_code == 200
    assert stop_resp.json()["emergency_stopped"] is True
    # The mode endpoint must reflect the emergency state.
    mode_resp = client.get("/api/v1/mode", headers=HEADERS).json()
    assert mode_resp["emergency_stopped"] is True
    # Resume.
    resume_resp = client.post("/api/v1/resume", headers=HEADERS)
    assert resume_resp.status_code == 200
    assert resume_resp.json()["emergency_stopped"] is False


def test_mode_change_rejected_during_emergency(client: TestClient):
    """Mode changes must be rejected while emergency stop is active (spec section 31)."""
    client.post("/api/v1/emergency-stop", headers=HEADERS)
    try:
        response = client.post("/api/v1/mode", json={"mode": "SAFE"}, headers=HEADERS)
        assert response.status_code == 409
        assert response.json()["error"]["code"] == "SECUREAGENT_STOPPED"
    finally:
        client.post("/api/v1/resume", headers=HEADERS)
