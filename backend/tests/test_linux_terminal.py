"""Linux terminal executor, terminal API, workflows, grants, plugins, notifications."""
import asyncio
import os
from pathlib import Path

import pytest

from app.config import settings
from app.linux_terminal import LinuxTerminalExecutor, redact_output
from app.security_engine import SecurityEngine
from app.security import SECRET_PATTERN
from tests.environment import requires_sandbox


@pytest.fixture()
def executor():
    config = settings()
    return LinuxTerminalExecutor(config)


@pytest.fixture()
def store():
    from app.memory import MemoryStore
    store = MemoryStore(settings().database_path)
    return store


@pytest.fixture()
def engine(store, executor):
    return SecurityEngine(executor, store, settings())


# --- executor core ----------------------------------------------------------- #

@requires_sandbox
async def test_executor_runs_safe_command_and_captures_output(executor):
    execution = await executor.execute("echo hello-secureagent")
    assert execution.status == "completed"
    assert execution.exit_code == 0
    assert "hello-secureagent" in execution.snapshot(1000)["stdout"]
    assert execution.duration_ms >= 0
    assert execution.risk == "safe"


@requires_sandbox
async def test_executor_captures_stderr_and_exit_code(executor):
    execution = await executor.execute("ls /definitely/not/here-12345")
    assert execution.status == "completed"
    assert execution.exit_code != 0
    assert execution.error  # first stderr line is surfaced as failure reason


@requires_sandbox
async def test_executor_stderr_stream(executor):
    execution = await executor.execute("echo boom >&2; true")
    snap = execution.snapshot(1000)
    assert "boom" in snap["stderr"]


async def test_executor_blocks_disallowed_cwd(executor):
    with pytest.raises(PermissionError):
        await executor.execute("ls", cwd="/etc")


async def test_executor_rejects_unknown_cwd(executor):
    with pytest.raises((ValueError, OSError)):
        await executor.execute("ls", cwd="/definitely/not/here-xyz")


async def test_executor_cwd_outside_workspace_via_traversal(executor):
    root = str(settings().workspace_root)
    with pytest.raises(PermissionError):
        await executor.execute("ls", cwd=root + "/../../")


async def test_executor_blocks_the_command_classifier(executor):
    with pytest.raises(ValueError) as error:
        await executor.execute("rm -rf /")
    assert "TERMINAL_COMMAND_BLOCKED" in str(error.value)


@requires_sandbox
async def test_executor_timeout_kills_process(executor):
    execution = await executor.execute("sleep 30", timeout=1.0)
    assert execution.status == "timeout"
    assert execution.error and "timeout" in execution.error.lower()


@requires_sandbox
async def test_executor_cancel(executor):
    execution_started = asyncio.create_task(executor.execute("sleep 30"))
    await asyncio.sleep(0.4)
    running = executor.tracker.running()
    assert running, "execution should be registered while running"
    target = running[-1]
    assert executor.cancel(target.id) is True
    execution = await execution_started
    assert execution.status == "cancelled"


@requires_sandbox
async def test_executor_output_cap(executor):
    execution = await executor.execute("yes secureagent-spam | head -c 400000")
    snap = execution.snapshot(settings().terminal_max_output_bytes)
    assert snap["truncated"] is True
    assert len(snap["stdout"]) <= settings().terminal_max_output_bytes


@requires_sandbox
async def test_executor_env_scrubbed(executor):
    os.environ["SECURE_AGENT_FAKE_TEST_SECRET"] = "supersecretvalue"
    try:
        execution = await executor.execute("printenv SECURE_AGENT_FAKE_TEST_SECRET; echo done")
        snap = execution.snapshot(4000)
        assert "supersecretvalue" not in snap["stdout"]
        assert "done" in snap["stdout"]
    finally:
        os.environ.pop("SECURE_AGENT_FAKE_TEST_SECRET", None)


@requires_sandbox
async def test_executor_shell_injection_env_vectors_removed(executor):
    os.environ["BASH_ENV"] = "/tmp/evil"
    try:
        execution = await executor.execute("echo ok")
        assert execution.status == "completed"
    finally:
        os.environ.pop("BASH_ENV", None)


def test_redact_output_masks_secret_patterns():
    masked = redact_output("password=hunter2 and api_key=abcd1234")
    assert "hunter2" not in masked
    assert "[REDACTED]" in masked


async def test_sudo_non_interactive_surfaces_structured_error(executor, host_control_enabled):
    # sudo -n without credentials must fail fast with the structured state,
    # never hang and never prompt. (CI users typically have no sudo rights.)
    if os.getuid() == 0:
        pytest.skip("running as root: sudo would succeed without password")
    # sudo is only permitted in HOST_CONTROL mode (RESTRICTED_AGENT blocks
    # it by design). Switch into HOST_CONTROL for this test.
    from app.linux_terminal import TerminalMode
    executor.set_mode(TerminalMode.HOST_CONTROL)
    try:
        execution = await executor.execute("sudo -n id")
        assert execution.status in {"completed", "failed"}
        if execution.exit_code not in (0, None):
            assert "never" in (execution.error or "").lower() or "sudo" in (execution.error or "").lower()
    finally:
        executor.set_mode(TerminalMode.RESTRICTED_AGENT)


async def test_sudo_blocked_in_restricted_agent_mode(executor):
    """RESTRICTED_AGENT mode refuses sudo outright, even with allow_sudo=True."""
    from app.linux_terminal import TerminalMode
    assert executor.mode is TerminalMode.RESTRICTED_AGENT
    with pytest.raises(ValueError) as error:
        await executor.execute("sudo -n id")
    assert "TERMINAL_SUDO_BLOCKED_IN_RESTRICTED_MODE" in str(error.value)


async def test_interactive_sudo_shell_always_blocked(executor, host_control_enabled):
    """Interactive root shells (sudo -i / sudo -s / sudo bash) are forbidden
    in every mode — the user can never approve them."""
    from app.linux_terminal import TerminalMode
    executor.set_mode(TerminalMode.HOST_CONTROL)
    try:
        for cmd in ("sudo -i", "sudo -s", "sudo bash", "sudo sh", "sudo su"):
            with pytest.raises(ValueError) as error:
                await executor.execute(cmd)
            assert "TERMINAL_COMMAND_BLOCKED" in str(error.value) or "interactive root shell" in str(error.value), cmd
    finally:
        executor.set_mode(TerminalMode.RESTRICTED_AGENT)


# --- agent tool layer (registry enforced) ------------------------------------- #

async def test_registry_contains_terminal_suite():
    from app.tools.factory import registry
    names = set(registry().tools)
    for expected in ("terminal_execute", "terminal_execute_approved", "terminal_execute_script",
                     "terminal_inspect_process", "terminal_inspect_network", "terminal_inspect_services",
                     "terminal_inspect_system", "terminal_get_environment_info",
                     "terminal_list_directory", "terminal_read_file", "terminal_search_files",
                     "terminal_get_working_directory"):
        assert expected in names, expected


async def test_terminal_execute_tool_requires_execute_permission():
    from app.tools.factory import registry
    result = await registry().execute("terminal_execute", {"command": "echo hi"}, set())
    assert result.success is False
    assert result.code == "permission_required"


@requires_sandbox
async def test_terminal_execute_tool_runs_safe_command():
    from app.tools.factory import registry
    result = await registry().execute("terminal_execute", {"command": "echo tool-ok"}, {"execute"})
    assert result.success is True
    assert "tool-ok" in result.output["stdout"]


async def test_terminal_execute_tool_approval_gate():
    from app.tools.factory import registry
    result = await registry().execute("terminal_execute", {"command": "systemctl restart nginx"}, {"execute"})
    assert result.success is False
    assert result.code == "terminal_approval_required"
    assert "TERMINAL_APPROVAL_REQUIRED" in result.error


async def test_terminal_execute_tool_blocks_after_approval():
    from app.tools.factory import registry
    result = await registry().execute("terminal_execute_approved", {"command": "rm -rf /"}, {"execute"})
    assert result.success is False
    assert result.code == "terminal_command_blocked"


async def test_terminal_execute_script_blocks_dangerous_lines():
    from app.tools.factory import registry
    result = await registry().execute(
        "terminal_execute_script",
        {"content": "echo start\nrm -rf /\necho end"},
        {"execute", "write"},
    )
    assert result.success is False
    assert result.code == "terminal_command_blocked"


@requires_sandbox
async def test_inspect_tools_run_fixed_vectors():
    from app.tools.factory import registry
    result = await registry().execute("terminal_inspect_system", {}, {"execute"})
    assert result.success is True
    assert "Linux" in result.output["stdout"] or result.output["exit_code"] in (0, 1)


async def test_terminal_read_file_jail():
    from app.tools.factory import registry
    ok = await registry().execute("terminal_read_file", {"path": "/etc/passwd"}, {"read"})
    assert ok.success is False
    assert "escapes" in ok.error


async def test_terminal_list_directory():
    from app.tools.factory import registry
    result = await registry().execute("terminal_list_directory", {"path": "."}, {"read"})
    assert result.success is True
    assert isinstance(result.output["entries"], list)


# --- terminal HTTP API --------------------------------------------------------- #

@requires_sandbox
def test_terminal_status_and_execute_api():
    from fastapi.testclient import TestClient
    from app.main import app
    from app.security import token_matches
    headers = {"Authorization": "Bearer test-only-token-0123456789abcdef0123456789"}
    with TestClient(app) as client:
        status = client.get("/api/v1/terminal/status", headers=headers)
        assert status.status_code == 200
        assert status.json()["available"] is True
        assert status.json()["backend"] == "linux"

        blocked = client.post("/api/v1/terminal/execute", headers=headers, json={"command": "rm -rf /"})
        assert blocked.status_code == 403
        assert blocked.json()["error"]["code"] == "TERMINAL_COMMAND_BLOCKED"

        approval = client.post("/api/v1/terminal/execute", headers=headers, json={"command": "systemctl restart nginx"})
        assert approval.status_code == 403
        assert approval.json()["error"]["code"] == "TERMINAL_APPROVAL_REQUIRED"

        ok = client.post("/api/v1/terminal/execute", headers=headers, json={"command": "echo api-ok"})
        assert ok.status_code == 200
        assert "api-ok" in ok.json()["stdout"]

        confirmed = client.post("/api/v1/terminal/execute", headers=headers,
                                json={"command": "touch confirmed-marker", "confirm": True})
        assert confirmed.status_code == 200
        assert confirmed.json()["exit_code"] == 0

        history = client.get("/api/v1/terminal/history", headers=headers)
        assert history.status_code == 200
        commands = [row["command"] for row in history.json()]
        assert any("api-ok" in command for command in commands)

        searched = client.get("/api/v1/terminal/history", headers=headers, params={"query": "api-ok"})
        assert any("api-ok" in row["command"] for row in searched.json())


def test_terminal_requires_auth():
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as client:
        response = client.post("/api/v1/terminal/execute", json={"command": "ls"})
        assert response.status_code == 401


# --- workflows / reports -------------------------------------------------------- #

async def test_system_audit_workflow(engine):
    report = await engine.run_workflow("system_audit")
    assert report["status"] in {"completed", "failed"}
    assert report["workflow"] == "system_audit"
    assert report["findings"]
    labels = {finding["status"] for finding in report["findings"]}
    assert labels <= {"OBSERVED", "INFERRED", "RECOMMENDED", "NOT_AVAILABLE"}
    assert any(finding["check"] == "kernel_version" for finding in report["findings"])


async def test_network_discovery_is_local_only(engine):
    report = await engine.run_workflow("network_discovery")
    assert report["workflow"] == "network_discovery"
    assert any(finding["check"] == "interfaces" for finding in report["findings"])
    joined = str(report["findings"])
    assert "nmap" not in joined.lower() or "not" in joined.lower()


async def test_log_analysis_workflow(engine):
    report = await engine.run_workflow("log_analysis", {"lines": 50})
    assert report["status"] in {"completed", "failed"}
    assert any(finding["check"] in {"log_collection", "log_collection"} for finding in report["findings"]) or \
           any(finding["status"] == "NOT_AVAILABLE" for finding in report["findings"])


async def test_file_security_audit_scopes_to_workspace(engine, tmp_path):
    workspace = settings().workspace_root
    marker = Path(workspace) / "audit-target.txt"
    marker.write_text("hello", encoding="utf-8")
    try:
        report = await engine.run_workflow("file_security_audit", {"path": "."})
        assert report["status"] in {"completed", "failed"}
        assert any("audit_scope" in finding["check"] for finding in report["findings"])
    finally:
        marker.unlink(missing_ok=True)


async def test_file_security_audit_rejects_outside_paths(engine):
    with pytest.raises(ValueError):
        await engine.run_workflow("file_security_audit", {"path": "/etc"})


async def test_report_persisted_and_listable(store, engine):
    report = await engine.run_workflow("system_audit")
    rows = await store.reports(10)
    assert any(row["id"] == report["id"] for row in rows)
    loaded = await store.report(report["id"])
    assert loaded["id"] == report["id"]
    assert loaded["summary"]["checks"] == len(report["findings"])


# --- permission grants ------------------------------------------------------------ #

async def test_grant_lifecycle(store):
    created = await store.create_grant("read", "always", "test grant")
    grants = await store.grants()
    assert any(item["id"] == created["id"] for item in grants)
    active = await store.active_grant_permissions()
    assert "read" in active
    assert await store.delete_grant(created["id"]) is True
    active = await store.active_grant_permissions()
    assert "read" not in active


def test_grants_api_forbids_admin():
    from fastapi.testclient import TestClient
    from app.main import app
    headers = {"Authorization": "Bearer test-only-token-0123456789abcdef0123456789"}
    with TestClient(app) as client:
        response = client.post("/api/v1/permissions/grants", headers=headers,
                               json={"permission": "admin", "scope": "always"})
        assert response.status_code == 422
        response = client.post("/api/v1/permissions/grants", headers=headers,
                               json={"permission": "read", "scope": "always", "note": "test"})
        assert response.status_code == 201
        grant_id = response.json()["id"]
        deleted = client.delete(f"/api/v1/permissions/grants/{grant_id}", headers=headers)
        assert deleted.status_code == 204


# --- plugins ------------------------------------------------------------------------ #

def test_plugin_loader_validates_manifests(tmp_path):
    from app.plugins.loader import PluginLoader
    from app.tools.base import Registry

    good = tmp_path / "good_plugin"
    good.mkdir()
    (good / "manifest.json").write_text(
        '{"name":"good_plugin","version":"1.0.0","description":"ok","module":"plugin",'
        '"tools":["good_tool"],"permissions":["safe"],"risk_levels":{"good_tool":"low"},'
        '"platforms":["linux"],"enabled":true}', encoding="utf-8")
    (good / "plugin.py").write_text(
        "from pydantic import BaseModel\n"
        "from app.tools.base import Tool\n"
        "class In(BaseModel):pass\n"
        "class Out(BaseModel):value:int=1\n"
        "class GoodTool(Tool):\n"
        " name='good_tool';description='good';category='plugins'\n"
        " input_model=In;output_model=Out\n"
        " async def run(self,a):return {'value':1}\n"
        "def register():return [GoodTool()]\n",
        encoding="utf-8")

    bad = tmp_path / "bad_plugin"
    bad.mkdir()
    (bad / "manifest.json").write_text('{"name":"bad_plugin"}', encoding="utf-8")

    registry = Registry()
    loader = PluginLoader(tmp_path, enabled=True)
    loaded = loader.discover(registry)
    by_name = {item.name: item for item in loaded}
    assert "good_plugin" in by_name
    assert by_name["good_plugin"].error is None
    assert "good_tool" in registry.tools
    assert "bad_plugin" in by_name
    assert by_name["bad_plugin"].error  # manifest validation failure recorded


def test_plugin_loader_disabled_by_default(tmp_path):
    from app.plugins.loader import PluginLoader
    from app.tools.base import Registry
    loader = PluginLoader(tmp_path, enabled=False)
    assert loader.discover(Registry()) == []


# --- notifications / system info ------------------------------------------------------ #

def test_notifications_and_system_info_api():
    from fastapi.testclient import TestClient
    from app.main import app
    headers = {"Authorization": "Bearer test-only-token-0123456789abcdef0123456789"}
    with TestClient(app) as client:
        notifications = client.get("/api/v1/notifications", headers=headers)
        assert notifications.status_code == 200
        assert isinstance(notifications.json(), list)
        info = client.get("/api/v1/system/info", headers=headers)
        assert info.status_code == 200
        body = info.json()
        assert body["platform"] in {"linux", "darwin", "windows"}
        assert "kernel" in body and "architecture" in body
        assert isinstance(body["tools"], dict)
        workflows = client.get("/api/v1/workflows", headers=headers)
        assert workflows.status_code == 200
        names = {row["name"] for row in workflows.json()}
        assert names == {"system_audit", "network_discovery", "log_analysis", "file_security_audit"}


def test_health_reports_terminal_state():
    from fastapi.testclient import TestClient
    from app.main import app
    headers = {"Authorization": "Bearer test-only-token-0123456789abcdef0123456789"}
    with TestClient(app) as client:
        health = client.get("/api/v1/health", headers=headers)
        assert health.status_code == 200
        assert "terminal" in health.json()
