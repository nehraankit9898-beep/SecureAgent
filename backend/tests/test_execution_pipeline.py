import re

import pytest

from app.agent import Agent
from app.config import Settings
from app.llm import LocalCoreProvider
from app.memory import MemoryStore
from app.models import AgentRequest, ChatRequest, Message, Permission, TaskStatus
from app.tools.factory import _build_registry


@pytest.mark.asyncio
async def test_structured_user_request_is_preserved_exactly():
    provider = LocalCoreProvider()
    request = ChatRequest(
        messages=[
            Message(role="system", content="ROLE=Planner"),
            Message(role="user", content="wrapped prompt text that must not be parsed"),
        ],
        user_request="calculate 2+2",
        json_mode=True,
    )
    response = await provider.chat(request)
    assert '"expression": "2+2"' in response.content


async def _agent(tmp_path, monkeypatch):
    config = Settings(
        environment="test",
        auth_required=True,
        api_token="x" * 40,
        database_path=tmp_path / "state.db",
        workspace_root=tmp_path / "workspace",
        ollama_enabled=False,
    )
    config.workspace_root.mkdir()
    (config.workspace_root / "example.txt").write_text("safe")
    monkeypatch.setattr("app.agent.settings", lambda: config)
    monkeypatch.setattr("app.tools.builtins.settings", lambda: config)
    store = MemoryStore(config.database_path)
    await store.init()
    return Agent(LocalCoreProvider(), _build_registry(config, config.workspace_root), store)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("message", "permission", "expected"),
    [
        ("calculate 2+2", set(), "4"),
        ("what time is it", set(), r"\d{4}-\d{2}-\d{2}T"),
        ("list files in the workspace", {Permission.READ}, "example.txt"),
    ],
)
async def test_deterministic_requests_work_without_ollama(tmp_path, monkeypatch, message, permission, expected):
    task = await (await _agent(tmp_path, monkeypatch)).run(AgentRequest(message=message, approved_permissions=permission))
    assert task.status == TaskStatus.DONE
    assert task.answer
    assert re.search(expected, task.answer)


@pytest.mark.asyncio
async def test_generative_request_without_ollama_is_controlled(tmp_path, monkeypatch):
    task = await (await _agent(tmp_path, monkeypatch)).run(AgentRequest(message="Explain what HTTP is"))
    assert task.status == TaskStatus.FAILED
    assert task.answer and task.answer.startswith("AI_REASONING_UNAVAILABLE")
    assert task.errors


@pytest.mark.asyncio
async def test_permission_denial_is_persisted_as_an_approval_request(tmp_path, monkeypatch):
    item = await _agent(tmp_path, monkeypatch)
    task = await item.run(AgentRequest(message="list files in the workspace"))
    assert task.status == TaskStatus.WAITING
    events = [row["event"] for row in await item.memory.audits(20)]
    assert "tool.executed" in events
    assert "approval.required" in events
