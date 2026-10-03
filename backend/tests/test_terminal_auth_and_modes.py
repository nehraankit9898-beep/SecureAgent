"""Authentication and rate-limit regression tests for the new terminal
security model.

Covers:
* API token required on /terminal/mode, /terminal/execute, /terminal/executions/.../cancel
* Constant-time token comparison (already in app.security.token_matches)
* HOST_CONTROL mode switch requires explicit confirm=true
* Rate limiting on terminal execution and approval endpoints
* The AI cannot switch to HOST_CONTROL — only the authenticated HTTP layer can
"""
from __future__ import annotations

import asyncio
import os
import time

import pytest

from app.config import settings
from app.linux_terminal import LinuxTerminalExecutor, TerminalMode
from tests.environment import requires_sandbox


TEST_TOKEN = "test-only-token-0123456789abcdef0123456789"
HEADERS = {"Authorization": f"Bearer {TEST_TOKEN}"}


def _client():
    from fastapi.testclient import TestClient
    from app.main import app
    return TestClient(app)


# --------------------------------------------------------------------------- #
# Authentication on new terminal endpoints
# --------------------------------------------------------------------------- #

def test_terminal_mode_endpoint_requires_auth():
    with _client() as client:
        response = client.post("/api/v1/terminal/mode", json={"mode": "host_control", "confirm": True})
        assert response.status_code == 401


def test_terminal_mode_endpoint_rejects_invalid_token():
    with _client() as client:
        response = client.post("/api/v1/terminal/mode",
                               json={"mode": "host_control", "confirm": True},
                               headers={"Authorization": "Bearer wrong-token"})
        assert response.status_code == 401


def test_terminal_mode_requires_confirm_for_host_control():
    """Switching to HOST_CONTROL requires confirm=true — a stale click
    must NOT flip the switch."""
    with _client() as client:
        response = client.post("/api/v1/terminal/mode",
                               json={"mode": "host_control", "confirm": False},
                               headers=HEADERS)
        assert response.status_code == 403
        body = response.json()
        assert body["error"]["code"] == "HOST_CONTROL_REQUIRES_CONFIRMATION"


def test_terminal_mode_switch_round_trip():
    """User can switch to HOST_CONTROL and back, with audit logging."""
    from app.control_center import get_control_center
    cc = get_control_center()
    cc.state.host_control.enabled = True  # user enabled Host Control in the Control Center
    try:
      with _client() as client:
        # Switch to HOST_CONTROL with confirm=true.
        response = client.post("/api/v1/terminal/mode",
                               json={"mode": "host_control", "confirm": True},
                               headers=HEADERS)
        assert response.status_code == 200
        assert response.json()["mode"] == "host_control"
        # Verify /status reports the mode.
        status = client.get("/api/v1/terminal/status", headers=HEADERS)
        assert status.json()["mode"] == "host_control"
        assert status.json()["host_control_warning"] is not None
        # Switch back to RESTRICTED_AGENT.
        response = client.post("/api/v1/terminal/mode",
                               json={"mode": "restricted_agent", "confirm": False},
                               headers=HEADERS)
        assert response.status_code == 200
        assert response.json()["mode"] == "restricted_agent"
    finally:
        cc.state.host_control.enabled = False


def test_terminal_status_reports_sandbox_info():
    """/terminal/status must report the sandbox mechanism and availability."""
    with _client() as client:
        status = client.get("/api/v1/terminal/status", headers=HEADERS)
        assert status.status_code == 200
        body = status.json()
        assert "sandbox" in body
        assert "available" in body["sandbox"]
        assert "mechanism" in body["sandbox"]
        assert body["mode"] == "restricted_agent"


@requires_sandbox
def test_terminal_execute_in_restricted_mode_includes_sandbox_metadata():
    """Completed executions in RESTRICTED_AGENT mode must include the
    sandbox mechanism in their snapshot."""
    with _client() as client:
        response = client.post("/api/v1/terminal/execute",
                               json={"command": "echo sandbox-test"},
                               headers=HEADERS)
        assert response.status_code == 200
        body = response.json()
        assert body["mode"] == "restricted_agent"
        assert body["sandbox"] is not None
        assert body["sandbox"]["mechanism"] in {"bubblewrap", "linux-user-namespace"}


def test_terminal_execute_in_host_control_no_sandbox():
    """In HOST_CONTROL mode, executions report mechanism='host-control'."""
    from app.control_center import get_control_center
    cc = get_control_center()
    cc.state.host_control.enabled = True
    try:
      with _client() as client:
        # Switch to HOST_CONTROL.
        client.post("/api/v1/terminal/mode",
                    json={"mode": "host_control", "confirm": True}, headers=HEADERS)
        try:
            response = client.post("/api/v1/terminal/execute",
                                   json={"command": "echo host-control-test"},
                                   headers=HEADERS)
            assert response.status_code == 200
            body = response.json()
            assert body["mode"] == "host_control"
            assert body["sandbox"]["mechanism"] == "host-control"
        finally:
            # Always return to safe mode.
            client.post("/api/v1/terminal/mode",
                        json={"mode": "restricted_agent", "confirm": False}, headers=HEADERS)
    finally:
        cc.state.host_control.enabled = False


# --------------------------------------------------------------------------- #
# Rate limiting
# --------------------------------------------------------------------------- #

def test_terminal_execute_rate_limited():
    """Spamming /terminal/execute must hit the rate limiter."""
    with _client() as client:
        # The default 'tools' rate limit is 60 req/min. We'll send 65
        # requests and expect at least one 429.
        statuses = []
        for i in range(65):
            response = client.post("/api/v1/terminal/execute",
                                   json={"command": "echo spam"},
                                   headers=HEADERS)
            statuses.append(response.status_code)
            if response.status_code == 429:
                break
        assert 429 in statuses, f"expected rate limiting, got statuses: {set(statuses)}"


def test_terminal_mode_endpoint_rate_limited():
    """The mode-switch endpoint is in the 'tools' rate-limit group."""
    with _client() as client:
        statuses = []
        for i in range(70):
            response = client.post("/api/v1/terminal/mode",
                                   json={"mode": "restricted_agent", "confirm": False},
                                   headers=HEADERS)
            statuses.append(response.status_code)
            if response.status_code == 429:
                break
        assert 429 in statuses, f"expected rate limiting, got statuses: {set(statuses)}"


# --------------------------------------------------------------------------- #
# AI cannot switch to HOST_CONTROL
# --------------------------------------------------------------------------- #

@pytest.mark.asyncio
async def test_ai_tools_never_activate_host_control():
    """The agent's terminal tools must not expose any way to flip the mode.
    We verify by inspecting the tool registry — no tool name contains
    'mode' or 'host_control' or 'activate'."""
    from app.tools.factory import registry
    tools = registry().tools
    for name in tools:
        name_lower = name.lower()
        assert "mode" not in name_lower, f"tool {name} mentions mode"
        assert "host_control" not in name_lower, f"tool {name} mentions host_control"
        assert "activate" not in name_lower, f"tool {name} mentions activate"


@pytest.mark.asyncio
@requires_sandbox
async def test_executor_mode_not_flipped_by_execute():
    """Calling executor.execute() must not change the mode, even if the
    command somehow references mode-switching."""
    executor = LinuxTerminalExecutor(settings())
    assert executor.mode is TerminalMode.RESTRICTED_AGENT
    await executor.execute("echo test")
    assert executor.mode is TerminalMode.RESTRICTED_AGENT


@pytest.mark.asyncio
async def test_host_control_revocation_is_enforced_at_spawn(tmp_path):
    """The master switch is rechecked immediately before execution."""
    from app.control_center import ControlCenter, get_control_center, set_control_center

    previous = get_control_center()
    cc = ControlCenter(tmp_path / "control-center.json")
    set_control_center(cc)
    cc.state.host_control.enabled = True
    executor = LinuxTerminalExecutor(settings())
    executor.set_mode(TerminalMode.HOST_CONTROL)
    cc.state.host_control.enabled = False
    try:
        try:
            result = await executor.execute("echo must-not-run-on-host")
            assert result.mode == "restricted_agent"
            assert result.sandbox["mechanism"] != "host-control"
        except RuntimeError as error:
            assert "LINUX_SANDBOX_UNAVAILABLE" in str(error)
        assert executor.mode is TerminalMode.RESTRICTED_AGENT
    finally:
        cc.state.host_control.enabled = False
        set_control_center(previous)
