"""SecureAgent Control Center — runtime enforcement tests.

These tests prove that the Desktop Control Center switches have REAL backend
effects (spec section 25). Every scenario follows the pattern:

    toggle OFF  ->  execute feature  ->  confirm rejection
    toggle ON   ->  execute feature  ->  confirm success

The Control Center state file lives under .pytest-data (see conftest) and the
app lifespan initializes it, so every test exercises the real runtime gates.
"""
from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

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


def _run(coro):
    """Run a coroutine on a fresh loop (executor calls are loop-independent)."""
    return asyncio.run(coro)


def _cc():
    from app.control_center import get_control_center
    return get_control_center()


def _set(section: str, field: str, value):
    """Flip a runtime control directly (simulating a Control Center toggle)."""
    getattr(_cc().state, section).__setattr__(field, value)


def _restore_defaults():
    from app.control_center import ControlState
    _cc().state = ControlState()
    _cc().emergency_stopped = False


# --------------------------------------------------------------------------- #
# 1. Terminal OFF -> terminal execution rejected
# --------------------------------------------------------------------------- #

@requires_sandbox
def test_1_terminal_off_rejects_execution_then_on_allows():
    with _client() as client:
        _set("terminal", "enabled", False)
        try:
            response = client.post("/api/v1/terminal/execute",
                                   json={"command": "echo should-be-rejected"}, headers=HEADERS)
            assert response.status_code == 409
            assert response.json()["error"]["code"] == "TERMINAL_DISABLED_BY_CONTROL_CENTER"
            # The gate must also refuse direct executor calls (the AI tool path).
            executor = LinuxTerminalExecutor(settings())
            with pytest.raises(PermissionError, match="TERMINAL_DISABLED_BY_CONTROL_CENTER"):
                _run(executor.execute("echo direct"))
        finally:
            _set("terminal", "enabled", True)
        response = client.post("/api/v1/terminal/execute",
                               json={"command": "echo terminal-on-works"}, headers=HEADERS)
        assert response.status_code == 200
        assert response.json()["status"] == "completed"
        assert "terminal-on-works" in response.json()["stdout"]


# --------------------------------------------------------------------------- #
# 2. Network OFF -> network tool rejected
# --------------------------------------------------------------------------- #

def test_2_network_disabled_blocks_http_client_and_records_telemetry():
    from app.network_security import SafeHttpClient
    cc = _cc()
    assert cc.state.network.mode == "disabled"
    with pytest.raises(PermissionError, match="NETWORK_BLOCKED_BY_CONTROL_CENTER"):
        _run(SafeHttpClient(1, 1000).request("GET", "https://example.com/"))
    assert cc.telemetry.blocked_count >= 1
    assert cc.telemetry.last_result == "blocked"


# --------------------------------------------------------------------------- #
# 3. Sudo OFF -> sudo command rejected
# --------------------------------------------------------------------------- #

def test_3_sudo_disabled_rejects_sudo_command():
    with _client() as client:
        assert _cc().state.sudo.mode == "disabled"
        response = client.post("/api/v1/terminal/execute",
                               json={"command": "sudo -n id", "confirm": True}, headers=HEADERS)
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "TERMINAL_SUDO_DISABLED"


# --------------------------------------------------------------------------- #
# 4. Automation OFF -> scheduled execution rejected
# --------------------------------------------------------------------------- #

def test_4_automation_off_rejects_schedule_creation():
    with _client() as client:
        _set("automation", "enabled", False)
        _set("automation", "scheduled_tasks", False)
        try:
            from datetime import UTC, datetime, timedelta
            response = client.post("/api/v1/schedules", headers=HEADERS, json={
                "name": "should-be-rejected", "prompt": "echo hi", "kind": "once",
                "run_at": (datetime.now(UTC) + timedelta(hours=1)).isoformat(),
            })
            assert response.status_code == 409
            assert "AUTOMATION_DISABLED" in response.text
        finally:
            _set("automation", "enabled", False)  # stay off (safe default)


# --------------------------------------------------------------------------- #
# 5. Tool OFF -> tool execution rejected
# --------------------------------------------------------------------------- #

def test_5_tool_disabled_is_refused_by_registry_then_reenabled():
    from app.tools.factory import registry
    tool = registry().tools["calculator"]
    with _client() as client:
        response = client.patch("/api/v1/tools/calculator",
                                json={"enabled": False}, headers=HEADERS)
        assert response.status_code == 200
        assert tool.enabled is False
        result = _run(registry().execute("calculator", {"expression": "1+1"}, set()))
        assert result.success is False
        assert result.code == "tool_disabled"
        # Re-enable via the API and confirm the tool runs again.
        response = client.patch("/api/v1/tools/calculator",
                                json={"enabled": True}, headers=HEADERS)
        assert response.status_code == 200
        result = _run(registry().execute("calculator", {"expression": "1+1"}, set()))
        assert result.success is True


# --------------------------------------------------------------------------- #
# 6. Emergency Stop -> running process actually terminated
# --------------------------------------------------------------------------- #

@requires_sandbox
def test_6_emergency_stop_kills_running_process_and_resume_restores():
    import threading
    import time as time_module
    with _client() as client:
        from app.main import terminal_executor
        assert terminal_executor is not None
        # Start a REAL long-running command on a background loop (the way a
        # live agent task would run it).
        loop = asyncio.new_event_loop()
        thread = threading.Thread(target=loop.run_forever, daemon=True)
        thread.start()
        marker = Path(settings().workspace_root) / "emergency-marker.txt"
        try:
            future = asyncio.run_coroutine_threadsafe(
                terminal_executor.execute("sleep 5 && touch emergency-marker.txt", approval="user"),
                loop)
            execution_id = None
            for _ in range(100):
                running = terminal_executor.tracker.running()
                if running:
                    execution_id = running[0].id
                    break
                time_module.sleep(0.1)
            assert execution_id, "long-running execution did not start"
            live = terminal_executor.snapshot(execution_id)
            assert live["status"] == "running"
            # EMERGENCY STOP.
            response = client.post("/api/v1/emergency-stop", headers=HEADERS)
            assert response.status_code == 200
            assert response.json()["emergency_stopped"] is True
            # The process must actually be gone (process group SIGKILL).
            for _ in range(50):
                snap = terminal_executor.snapshot(execution_id)
                if snap and snap["status"] != "running":
                    break
                time_module.sleep(0.1)
            snap = terminal_executor.snapshot(execution_id)
            assert snap["status"] in {"cancelled", "failed"}, snap
            assert not marker.exists(), "the long-running command must never complete"
            # Terminal execution is refused while stopped.
            response = client.post("/api/v1/terminal/execute",
                                   json={"command": "echo after-stop"}, headers=HEADERS)
            assert response.status_code == 409
            assert response.json()["error"]["code"] == "SECUREAGENT_STOPPED"
            # Audit logs are preserved.
            audit_rows = client.get("/api/v1/audit?category=security", headers=HEADERS).json()
            assert any(row["event"] == "control.emergency_stop" for row in audit_rows)
            # RESUME restores the configured state and terminal works again.
            response = client.post("/api/v1/resume", headers=HEADERS)
            assert response.status_code == 200
            assert response.json()["emergency_stopped"] is False
            response = client.post("/api/v1/terminal/execute",
                                   json={"command": "echo resumed-ok"}, headers=HEADERS)
            assert response.status_code == 200
        finally:
            loop.call_soon_threadsafe(loop.stop)
            thread.join(timeout=2)
            loop.close()
            _restore_defaults()


# --------------------------------------------------------------------------- #
# 7. Secure Mode ON -> mandatory protections remain active
# --------------------------------------------------------------------------- #

def test_7_secure_mode_mandatory_protections_cannot_be_disabled():
    with _client() as client:
        assert _cc().state.secure_mode is True
        for field in ("audit_logging", "command_policy", "approval_system", "filesystem_protection"):
            response = client.patch("/api/v1/config",
                                    json={"security": {field: False}}, headers=HEADERS)
            assert response.status_code == 422, field
            assert response.json()["error"]["code"] == "CONFIG_REJECTED"
        # Restricted mode is mandatory while secure mode is on.
        response = client.patch("/api/v1/config",
                                json={"terminal": {"restricted_mode": False}}, headers=HEADERS)
        assert response.status_code == 422
        # The state still shows everything enabled.
        state = client.get("/api/v1/config", headers=HEADERS).json()["state"]
        assert state["security"]["audit_logging"] is True
        assert state["security"]["command_policy"] is True
        assert state["terminal"]["restricted_mode"] is True


# --------------------------------------------------------------------------- #
# 8. Host Control OFF -> host-control operation rejected
# --------------------------------------------------------------------------- #

def test_8_host_control_off_rejects_host_control_mode():
    with _client() as client:
        assert _cc().state.host_control.enabled is False
        # With confirm=true the endpoint still refuses: the master is OFF.
        response = client.post("/api/v1/terminal/mode",
                               json={"mode": "host_control", "confirm": True}, headers=HEADERS)
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "HOST_CONTROL_DISABLED"
        # Enabling Host Control via config REQUIRES confirm (the UI shows the
        # warning dialog and only sends confirm=true after explicit consent).
        response = client.patch("/api/v1/config",
                                json={"host_control": {"enabled": True}}, headers=HEADERS)
        assert response.status_code == 422
        assert response.json()["error"]["code"] == "HOST_CONTROL_REQUIRES_CONFIRMATION"
    try:
        with _client() as client:
            response = client.patch("/api/v1/config?confirm=true",
                                    json={"host_control": {"enabled": True}}, headers=HEADERS)
            assert response.status_code == 200, response.text
            assert response.json()["state"]["host_control"]["enabled"] is True
            response = client.post("/api/v1/terminal/mode",
                                   json={"mode": "host_control", "confirm": True}, headers=HEADERS)
            assert response.status_code == 200
            assert response.json()["mode"] == "host_control"
            # Back to safety.
            client.post("/api/v1/terminal/mode",
                        json={"mode": "restricted_agent", "confirm": False}, headers=HEADERS)
    finally:
        _set("host_control", "enabled", False)


# --------------------------------------------------------------------------- #
# 9. Ollama OFF -> AI calls handled correctly
# --------------------------------------------------------------------------- #

def test_9_ollama_off_reports_disabled_not_fake_ready():
    with _client() as client:
        _set("ai", "ollama_enabled", False)
        try:
            provider = _client_status(client)
            # The status must NOT claim generative availability.
            assert provider["generative_available"] is False or provider["ollama_available"] is False
            assert provider.get("active_provider") == "LOCAL CORE"
            status = client.get("/api/v1/status", headers=HEADERS).json()
            assert status["cards"]["ollama"]["status"] == "OFFLINE"
        finally:
            _set("ai", "ollama_enabled", True)


def _client_status(client):
    response = client.get("/api/v1/ollama/status", headers=HEADERS)
    return response.json()


# --------------------------------------------------------------------------- #
# 10. Configuration restart -> saved settings restored
# --------------------------------------------------------------------------- #

def test_10_configuration_persists_across_restart(tmp_path):
    from app.control_center import ControlCenter
    state_file = tmp_path / "cc.json"
    cc = ControlCenter(state_file, None)
    _run(cc.update({"terminal": {"enabled": True, "max_command_time_seconds": 42},
                    "network": {"mode": "private"}}, actor="user"))
    assert cc.revision >= 2
    # "Restart": a fresh instance loads the same file.
    cc2 = ControlCenter(state_file, None)
    assert cc2.state.terminal.max_command_time_seconds == 42
    assert cc2.state.network.mode == "private"
    assert cc2.revision == cc.revision
    assert cc2.state.security.audit_logging is True  # mandatory protections intact


def test_10a_emergency_stop_persists_across_restart(tmp_path):
    """A backend restart must not silently clear the kill switch."""
    from app.control_center import ControlCenter
    state_file = tmp_path / "cc.json"
    cc = ControlCenter(state_file, None)
    _run(cc.emergency_stop())
    restarted = ControlCenter(state_file, None)
    assert restarted.emergency_stopped is True
    with pytest.raises(PermissionError, match="SECUREAGENT_STOPPED"):
        restarted.check_terminal()
    _run(restarted.resume())
    assert ControlCenter(state_file, None).emergency_stopped is False


def test_10b_corrupted_configuration_recovers_previous_valid_state(tmp_path):
    from app.control_center import ControlCenter
    state_file = tmp_path / "cc.json"
    cc = ControlCenter(state_file, None)
    _run(cc.update({"terminal": {"max_output_bytes": 111111}}, actor="user"))
    _run(cc.update({"terminal": {"max_command_time_seconds": 42}}, actor="user"))
    assert cc.state.terminal.max_output_bytes == 111111
    # Corrupt the live file; the backup from the last atomic write must
    # restore the last known VALID configuration (previous revision).
    state_file.write_text("{ this is not json !!!")
    cc2 = ControlCenter(state_file, None)
    assert cc2.recovery and cc2.recovery["reason"] == "configuration_corrupted"
    assert cc2.state.terminal.max_output_bytes == 111111  # from the backup
    assert cc2.state.terminal.max_command_time_seconds == 30  # default (pre-revision-2)
    assert cc2.state.security.audit_logging is True  # mandatory protections intact
    assert json.loads(state_file.read_text())["state"]["terminal"]["max_output_bytes"] == 111111


# --------------------------------------------------------------------------- #
# 11. Invalid configuration -> rejected, previous retained
# --------------------------------------------------------------------------- #

def test_11_invalid_config_rejected_and_previous_retained():
    with _client() as client:
        before = client.get("/api/v1/config", headers=HEADERS).json()
        for bad_patch in (
            {"terminal": {"max_command_time_seconds": 99999}},   # out of bounds
            {"network": {"mode": "teleport"}},                    # invalid enum
            {"agent": {"enabled": "banana"}},                     # invalid type
            {"totally_unknown": {"x": 1}},                        # unknown section
            {"terminal": {"no_such_field": True}},                # unknown field
        ):
            response = client.request("PATCH", "/api/v1/config", json=bad_patch, headers=HEADERS)
            assert response.status_code == 422, bad_patch
        after = client.get("/api/v1/config", headers=HEADERS).json()
        assert after["state"] == before["state"]
        assert after["revision"] == before["revision"]


# --------------------------------------------------------------------------- #
# 12. Frontend manipulation -> backend still enforces security
# --------------------------------------------------------------------------- #

def test_12_frontend_manipulation_cannot_bypass_backend_security():
    with _client() as client:
        # a) Tampered field types / injection attempts are rejected.
        response = client.request("PATCH", "/api/v1/config",
                                  json={"sudo": {"mode": "unrestricted"}}, headers=HEADERS)
        assert response.status_code == 422
        # b) The tool toggle cannot make a BLOCKED command runnable.
        client.patch("/api/v1/tools/terminal_execute_approved",
                     json={"enabled": True}, headers=HEADERS)
        response = client.post("/api/v1/terminal/execute",
                               json={"command": "rm -rf /", "confirm": True}, headers=HEADERS)
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "TERMINAL_COMMAND_BLOCKED"
        # c) Admin grants stay impossible.
        response = client.request("PATCH", "/api/v1/config",
                                  json={"security": {"audit_logging": False}}, headers=HEADERS)
        assert response.status_code == 422
        response = client.patch("/api/v1/permissions",
                                json={"action": "grant", "permission": "admin"}, headers=HEADERS)
        assert response.status_code == 422
        # d) Emergency stop cannot be undone by a config patch while active.
        client.post("/api/v1/emergency-stop", headers=HEADERS)
        response = client.request("PATCH", "/api/v1/config",
                                  json={"terminal": {"enabled": True}}, headers=HEADERS)
        assert response.status_code == 422
        assert "SECUREAGENT_STOPPED" in response.json()["error"]["message"]
        client.post("/api/v1/resume", headers=HEADERS)


# --------------------------------------------------------------------------- #
# Presets, apply-transaction, status cards, filesystem, audit surface
# --------------------------------------------------------------------------- #

def test_presets_apply_and_full_control_requires_confirmation():
    with _client() as client:
        response = client.post("/api/v1/config/preset", json={"name": "safe"}, headers=HEADERS)
        assert response.status_code == 200
        state = response.json()["state"]
        assert state["network"]["mode"] == "disabled"
        assert state["sudo"]["mode"] == "disabled"
        assert state["automation"]["enabled"] is False
        # full_control without confirm -> 403
        response = client.post("/api/v1/config/preset",
                               json={"name": "full_control", "confirm": False}, headers=HEADERS)
        assert response.status_code == 403
        response = client.post("/api/v1/config/preset",
                               json={"name": "full_control", "confirm": True}, headers=HEADERS)
        assert response.status_code == 200
        state = response.json()["state"]
        # NOT unrestricted: mandatory protections still on, sandbox stays.
        assert state["security"]["command_policy"] is True
        assert state["terminal"]["restricted_mode"] is True
        assert state["terminal"]["allow_sudo"] is True
        assert state["sudo"]["mode"] == "approval_required"
        client.post("/api/v1/config/preset", json={"name": "safe"}, headers=HEADERS)


def test_status_cards_come_from_backend_not_frontend():
    with _client() as client:
        status = client.get("/api/v1/status", headers=HEADERS).json()
        expected = {"backend", "agent", "terminal", "sandbox", "security",
                    "ollama", "network", "memory", "rag", "automation"}
        assert expected <= set(status["cards"].keys())
        for name, card in status["cards"].items():
            assert card["status"] in {"ONLINE", "OFFLINE", "DEGRADED", "BLOCKED", "ERROR"}, name


def test_filesystem_path_validation_is_backend_side():
    with _client() as client:
        response = client.post("/api/v1/filesystem/paths",
                               json={"path": "relative/path"}, headers=HEADERS)
        assert response.status_code == 422
        # Pseudo/system roots can never be added — even with confirm.
        response = client.post("/api/v1/filesystem/paths",
                               json={"path": "/proc", "confirm": True}, headers=HEADERS)
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "PATH_FORBIDDEN"
        # A sensitive system tree requires explicit confirmation first.
        response = client.post("/api/v1/filesystem/paths",
                               json={"path": "/etc"}, headers=HEADERS)
        assert response.status_code == 403
        assert response.json()["error"]["code"] == "SENSITIVE_PATH_REQUIRES_CONFIRMATION"
        # A real directory outside the workspace can be added and extends the
        # terminal jail at runtime.
        target = Path(settings().workspace_root).parent / "cc-extra-root"
        target.mkdir(exist_ok=True)
        try:
            response = client.post("/api/v1/filesystem/paths",
                                   json={"path": str(target)}, headers=HEADERS)
            assert response.status_code == 200, response.text
            from app.main import terminal_executor
            if terminal_executor:
                roots = [str(p) for p in terminal_executor.allowed_roots()]
                assert str(target) in roots
            # Duplicate add is idempotent.
            response = client.post("/api/v1/filesystem/paths",
                                   json={"path": str(target)}, headers=HEADERS)
            assert response.json().get("already_allowed") is True
            # Remove again.
            response = client.post("/api/v1/filesystem/paths/remove",
                                   json={"path": str(target)}, headers=HEADERS)
            assert response.status_code == 200
        finally:
            import shutil
            shutil.rmtree(target, ignore_errors=True)


def test_audit_filters_export_and_clear_requires_confirmation():
    with _client() as client:
        # generate some traffic
        client.get("/api/v1/config", headers=HEADERS)
        rows = client.get("/api/v1/audit?category=security&limit=50", headers=HEADERS).json()
        security_prefixes = ("config.", "control.", "control_center.", "security.", "schedule.",
                             "host_control.", "tool.toggled", "filesystem.", "audit.",
                             "permission.granted", "permission.revoked")
        assert all(row["event"].startswith(security_prefixes) for row in rows)
        exported = client.post("/api/v1/audit/export", headers=HEADERS).json()
        assert exported["ok"] is True and Path(exported["path"]).exists()
        # clear without confirm is refused
        response = client.post("/api/v1/audit/clear", json={"confirm": False}, headers=HEADERS)
        assert response.status_code == 403
        response = client.post("/api/v1/audit/clear", json={"confirm": True}, headers=HEADERS)
        assert response.status_code == 200
        rows = client.get("/api/v1/audit", headers=HEADERS).json()
        assert all(row["event"] in {"audit.cleared"} or row["event"] == "audit.cleared" for row in rows)


def test_control_center_state_file_is_versioned_and_typed():
    cc = _cc()
    document = json.loads(cc.state_file.read_text())
    assert document["schema_version"] == 1
    assert document["revision"] >= 1
    assert set(document["state"].keys()) >= {"secure_mode", "agent", "terminal", "network",
                                             "sudo", "host_control", "ai", "memory", "rag",
                                             "automation", "workflows", "security", "filesystem"}
    # Permissions on the state file must be owner-only (0600).
    mode = cc.state_file.stat().st_mode & 0o777
    assert mode == 0o600, f"state file must be 0600, got {oct(mode)}"
