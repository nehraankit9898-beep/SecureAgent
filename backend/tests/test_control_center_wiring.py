"""Control Center wiring proof: every section switch is consumed by real code.

Two complementary checks:

1. a source-level link check — for every ``ControlState`` section the gate
   method (or section state) is referenced by at least one runtime module
   outside ``control_center.py``. A section with no consumer would be a
   UI-only switch and fails here;
2. behaviour checks for the wiring that the other suites do not cover directly
   (AI engine limits reaching the Ollama payload, agent auto-* flags, the
   memory/RAG/automation/workflow API gates).
"""
from pathlib import Path

import pytest

from app.config import Settings
from app.control_center import ControlCenter, ControlState, set_control_center
from app.models import ChatRequest

APP_ROOT = Path(__file__).resolve().parents[1] / "app"

# section → the gate/state expression a runtime module must reference.
SECTION_CONSUMERS = {
    "agent": "agent_active",
    "terminal": "check_terminal",
    "host_control": "check_host_control_operation",
    "network": "check_network",
    "sudo": "check_sudo",
    "filesystem": "extra_allowed_roots",
    "ai": "ai_active",
    "browser": "browser_active",
    "voice": "voice_active",
    "memory": "memory_active",
    "rag": "rag_active",
    "automation": "automation_active",
    "workflows": "workflows_active",
    "security": "MANDATORY_PROTECTIONS",
}


def _runtime_sources() -> dict[str, str]:
    sources = {}
    for path in APP_ROOT.rglob("*.py"):
        if path.name == "control_center.py":
            continue
        sources[str(path.relative_to(APP_ROOT))] = path.read_text(encoding="utf-8")
    return sources


def test_every_control_state_section_has_a_runtime_consumer():
    sources = _runtime_sources()
    missing = []
    for section, expression in SECTION_CONSUMERS.items():
        assert section in ControlState.SECTIONS, f"{section} is not a ControlState section"
        if not any(expression in text for text in sources.values()):
            missing.append(f"{section} → {expression}")
    assert not missing, f"UI-only switch(es) with no runtime consumer: {missing}"


def test_every_section_is_exposed_by_the_config_and_status_surfaces():
    from fastapi.testclient import TestClient
    from app.main import app
    headers = {"Authorization": "Bearer test-only-token-0123456789abcdef0123456789"}
    with TestClient(app) as client:
        snapshot = client.get("/api/v1/config", headers=headers).json()
        state = snapshot["state"]
        for section in ControlState.SECTIONS:
            assert section in state, f"{section} missing from the config snapshot"
        cards = client.get("/api/v1/status", headers=headers)
        assert cards.status_code == 200
        assert "cards" in cards.json()


def _gate(tmp_path) -> ControlCenter:
    center = ControlCenter(tmp_path / "control_center.json")
    set_control_center(center)
    return center


@pytest.mark.asyncio()
async def test_ai_limits_reach_the_ollama_request(tmp_path):
    """Control Center AI ENGINE limits are applied to the real provider payload."""
    from app.llm import OllamaProvider
    gate = _gate(tmp_path)
    gate.state.ai.model = "cc-model"
    gate.state.ai.temperature = 0.9
    gate.state.ai.context_size = 4096
    gate.state.ai.max_tokens = 512
    provider = OllamaProvider()
    captured: dict = {}

    async def fake_json(method, path, payload=None):
        captured["method"] = method
        captured["path"] = path
        captured["payload"] = payload
        return {"message": {"content": "ok"}, "model": "cc-model"}

    provider._json = fake_json
    response = await provider.chat(ChatRequest(messages=[{"role": "user", "content": "hi"}]))
    assert captured["payload"]["model"] == "cc-model"
    assert captured["payload"]["options"]["temperature"] == 0.9
    assert captured["payload"]["options"]["num_ctx"] == 4096
    assert captured["payload"]["options"]["num_predict"] == 512
    assert response.content == "ok"
    await provider.close()


@pytest.mark.asyncio()
async def test_ai_master_switch_blocks_generative_provider(tmp_path):
    from app.llm import LLMError, OllamaProvider
    gate = _gate(tmp_path)
    gate.state.ai.enabled = False
    provider = OllamaProvider()
    captured = {}

    async def fake_json(method, path, payload=None):  # pragma: no cover - must not run
        captured["called"] = True
        return {}

    provider._json = fake_json
    # The FallbackProvider consults the gate before calling Ollama; the direct
    # call still works (it is the composition that gates), so assert the gate.
    assert gate.ai_active() is False
    from app.llm import FallbackProvider
    fallback = FallbackProvider()
    assert await fallback.refresh() is False
    assert fallback.active == "LOCAL CORE"
    assert fallback._last_error.code == "AI_DISABLED"
    assert "called" not in captured
    await provider.close()
    await fallback.close()


@pytest.mark.asyncio()
async def test_agent_auto_flags_are_enforced(tmp_path):
    """Each Auto-* switch changes real agent behaviour (spec section 4)."""
    import json

    from app.agent import Agent
    from app.memory import MemoryStore
    from app.models import AgentRequest, ChatResponse, Permission, StepStatus, TaskStatus
    from app.tools.factory import _build_registry

    gate = _gate(tmp_path)
    config = Settings(environment="test", auth_required=True, api_token="x" * 40,
                      database_path=tmp_path / "state.db",
                      workspace_root=tmp_path / "workspace")
    store = MemoryStore(config.database_path)
    await store.init()

    class Planner:
        async def chat(self, request):
            if request.json_mode:
                return ChatResponse(model="test", content=json.dumps({
                    "mode": "plan", "intent": "file",
                    "steps": [{"title": "read", "tool": "read_file",
                               "arguments": {"path": "missing.txt"}}]}))
            return ChatResponse(model="test", content="done")

    registry = _build_registry(config, config.workspace_root)
    agent = Agent(Planner(), registry, store)
    request = lambda: AgentRequest(message="read a file",  # noqa: E731
                                  approved_permissions={Permission.READ})

    # auto_execution OFF ⇒ the run is refused before any planning.
    gate.state.agent.auto_execution = False
    task = await agent.run(request())
    assert task.status == TaskStatus.FAILED
    assert any("AUTO_EXECUTION_DISABLED" in error for error in task.errors)
    assert task.steps == []
    gate.state.agent.auto_execution = True

    # auto_planning OFF ⇒ a plan-producing request is refused, not executed.
    gate.state.agent.auto_planning = False
    task = await agent.run(request())
    assert task.status == TaskStatus.FAILED
    assert any("AUTO_PLANNING_DISABLED" in error for error in task.errors)
    gate.state.agent.auto_planning = True

    # auto_tool_calling OFF ⇒ the plan exists but every tool step is cancelled.
    gate.state.agent.auto_tool_calling = False
    task = await agent.run(request())
    assert task.status == TaskStatus.FAILED
    assert any("AUTO_TOOL_CALLING_DISABLED" in error for error in task.errors)
    assert task.steps and all(step.status != StepStatus.DONE for step in task.steps)
    gate.state.agent.auto_tool_calling = True

    # With every switch ON the same request really executes (control case).
    task = await agent.run(request())
    assert task.steps
    assert task.steps[0].status in {StepStatus.DONE, StepStatus.FAILED}


def test_memory_rag_automation_workflow_gates_are_served(tmp_path):
    from fastapi.testclient import TestClient
    from app.control_center import get_control_center
    from app.main import app
    headers = {"Authorization": "Bearer test-only-token-0123456789abcdef0123456789"}
    with TestClient(app) as client:
        gate = get_control_center()
        gate.state.memory.enabled = False
        memory_post = client.post("/api/v1/memories", json={"content": "x"}, headers=headers)
        assert memory_post.status_code == 409
        assert "MEMORY_DISABLED" in memory_post.text
        gate.state.memory.enabled = True

        gate.state.rag.enabled = False
        documents = client.post("/api/v1/documents/search", json={"query": "test"}, headers=headers)
        assert documents.status_code == 409
        assert "KNOWLEDGE_DISABLED" in documents.text
        gate.state.rag.enabled = True

        gate.state.automation.enabled = False
        created = client.post("/api/v1/schedules", headers=headers, json={
            "name": "blocked", "prompt": "calculate 2+2", "kind": "once",
            "run_at": "2030-01-01T00:00:00Z"})
        assert created.status_code == 409
        assert "AUTOMATION_DISABLED" in created.text
        # Listing stays readable (observability is never blocked by a switch).
        assert client.get("/api/v1/schedules", headers=headers).status_code == 200
        gate.state.automation.enabled = True

        gate.state.workflows.enabled = False
        workflows = client.post("/api/v1/workflows/host_security_audit/run",
                                json={}, headers=headers)
        assert workflows.status_code == 409
        assert "WORKFLOWS_DISABLED" in workflows.text
        gate.state.workflows.enabled = True
