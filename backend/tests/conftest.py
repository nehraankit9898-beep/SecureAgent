import os
import pytest
from pathlib import Path

TEST_TOKEN="test-only-token-0123456789abcdef0123456789"
os.environ.update({
    "SECURE_AGENT_ENVIRONMENT":"test",
    "SECURE_AGENT_AUTH_REQUIRED":"true",
    "SECURE_AGENT_API_TOKEN":TEST_TOKEN,
    "SECURE_AGENT_TEST_SANDBOX_ENABLED":"false",
    "SECURE_AGENT_PYTHON_EXECUTION_BACKEND":"disabled",
    "SECURE_AGENT_ENABLE_AUTOMATION":"false",
    "SECURE_AGENT_ENABLE_NETWORK_TOOLS":"false",
    # Linux-native terminal backend under test; commands run inside the
    # workspace jail with the command policy engine in front of every shell.
    # The new RESTRICTED_AGENT mode wraps commands in a user+pid+net
    # namespace sandbox (uid remapped to 65534) so /etc/shadow and friends
    # are unreadable at the kernel level. Tests that need sudo flip into
    # HOST_CONTROL mode explicitly via the executor's set_mode() helper.
    "SECURE_AGENT_TERMINAL_BACKEND":"linux",
    "SECURE_AGENT_TERMINAL_TOOLS_ENABLED":"true",
    "SECURE_AGENT_TERMINAL_ALLOW_SUDO":"true",
    "SECURE_AGENT_SECURITY_WORKFLOWS_ENABLED":"true",
    "SECURE_AGENT_DATABASE_PATH":str(Path(".pytest-data")/"state.db"),
    "SECURE_AGENT_WORKSPACE_ROOT":str(Path(".pytest-data")/"workspace"),
})

# A previous session may have persisted a modified Control Center document
# (e.g. an ASSIST preset that leaves network.mode='localhost'). The Control
# Center is loaded from disk at app import, so stale files make the suite
# order- and history-dependent. Reset to factory defaults before any import.
# NOTE: config.py resolves relative paths against the PROJECT ROOT, so the
# runtime .pytest-data directory lives there — not under backend/.
_PROJECT_ROOT = Path(__file__).resolve().parents[2]
_PYTEST_DATA = _PROJECT_ROOT / ".pytest-data"
for _stale in (
    _PYTEST_DATA / "control_center.json",
    _PYTEST_DATA / "control_center.json.bak",
):
    try:
        _stale.unlink()
    except OSError:
        pass


# --- Honest environment gating (spec section 33) --------------------------- #
# Tests that execute commands through the RESTRICTED_AGENT sandbox need the
# complete bubblewrap user+mount+pid+network namespace profile. On hosts
# without it (or with AppArmor-restricted unprivileged userns) those tests
# are BLOCKED — ENVIRONMENT REQUIRED, and must be reported as skipped, not
# as failures (the sandbox itself correctly fails closed).
def _sandbox_available() -> bool:
    try:
        from app.linux_sandbox import probe_sandbox_capabilities
        return bool(probe_sandbox_capabilities().available)
    except Exception:
        return False


SANDBOX_AVAILABLE = _sandbox_available()
requires_sandbox = pytest.mark.skipif(
    not SANDBOX_AVAILABLE,
    reason=(
        "BLOCKED — environment requires bubblewrap with the full "
        "user+mount+pid+network namespace profile; install bubblewrap "
        "(and enable unprivileged user namespaces) on a real Linux host"
    ),
)


@pytest.fixture(autouse=True)
def _isolate_control_center_state():
    """Snapshot the global Control Center state before each test and restore
    it afterwards, so a test that flips a master switch (or applies a mode
    preset) cannot leak policy changes into other tests. Also clears the
    process-global rate limiter and session approval grants, which would
    otherwise carry quota exhaustion (429 debt) and approvals across tests."""
    from app.control_center import ControlState, get_control_center
    cc = get_control_center()
    if cc is not None:
        snapshot = cc.state.model_dump()
        stopped = cc.emergency_stopped
    else:
        snapshot = None
        stopped = False
    yield
    if snapshot is not None:
        cc.state = ControlState(**snapshot)
        cc.emergency_stopped = stopped
    try:
        import app.main as main_module
        main_module.limiter.reset()
        main_module.session_approvals.clear()
        main_module.session_approval_activity.clear()
    except (ImportError, AttributeError):
        pass


# --- Control Center fixtures ------------------------------------------------ #
# The Control Center is the backend runtime authority: HOST_CONTROL mode now
# requires the Host Control master switch to be enabled. Tests that exercise
# HOST_CONTROL paths explicitly use this fixture (production flow: the user
# enables it via the Control Center with explicit confirmation).

@pytest.fixture()
def host_control_enabled():
    from app.control_center import get_control_center
    cc = get_control_center()
    if cc is not None:
        cc.state.host_control.enabled = True
        cc.state.sudo.mode = "approval_required"
        cc.state.terminal.allow_sudo = True
    yield cc
    if cc is not None:
        cc.state.host_control.enabled = False
        cc.state.sudo.mode = "disabled"
        cc.state.terminal.allow_sudo = False


@pytest.fixture()
def runtime_network_allowed(tmp_path):
    """Allow runtime network traffic for SafeHttpClient unit tests (the
    Control Center NETWORK master gate is active in production)."""
    from app.control_center import ControlCenter, get_control_center, set_control_center
    cc = get_control_center()
    previous = cc
    if cc is None:
        cc = ControlCenter(tmp_path / "network-control-center.json")
        set_control_center(cc)
    cc.state.network.mode = "full"
    yield cc
    cc.state.network.mode = "disabled"
    if previous is None:
        set_control_center(None)
