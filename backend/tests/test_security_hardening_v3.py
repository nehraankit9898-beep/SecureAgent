import asyncio
import json
from pathlib import Path
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.llm import LLMError, OllamaProvider
from app.memory import MemoryStore
from app.models import DocumentIn, Permission, RiskLevel
from app.security import request_id_var
from app.tools.base import Registry, Tool
from app.tools.builtins import Calculator, DeleteFile, ReadFile, WriteFile
from app.workspace import WorkspacePolicy


@pytest.mark.parametrize("hostile", [
    "../escape", "../../escape", "../../../escape", "/etc/passwd",
    r"C:\\Windows\\system.ini", r"\\server\\share\\secret.txt",
    "%2e%2e/escape", "%252e%252e/escape", "%2Fetc%2Fpasswd",
    "%00.txt", "safe/../escape", "a" * 256, "a/" * 20 + "x",
])
def test_workspace_rejects_hostile_cross_platform_paths(tmp_path: Path, hostile: str):
    policy = WorkspacePolicy(tmp_path, max_depth=8)
    with pytest.raises((PermissionError, ValueError, OSError)):
        policy.resolve(hostile)


def test_workspace_atomic_write_and_delete_are_no_follow(tmp_path: Path):
    policy = WorkspacePolicy(tmp_path)
    target = policy.atomic_write("nested/value.txt", "one")
    assert target.read_text() == "one"
    with pytest.raises((ValueError, FileExistsError)):
        policy.atomic_write("nested/value.txt", "two")
    policy.atomic_write("nested/value.txt", "two", overwrite=True)
    assert target.read_text() == "two"
    policy.delete("nested/value.txt", "DELETE")
    assert not target.exists()


def test_workspace_rejects_nested_symlink_parent(tmp_path: Path):
    outside = tmp_path.parent / "secureagent-outside"
    outside.mkdir(exist_ok=True)
    link = tmp_path / "linked"
    try:
        link.symlink_to(outside, target_is_directory=True)
    except OSError:
        pytest.skip("symlink creation unavailable")
    policy = WorkspacePolicy(tmp_path)
    with pytest.raises((PermissionError, OSError)):
        policy.atomic_write("linked/escape.txt", "blocked")
    assert not (outside / "escape.txt").exists()


def test_tool_definitions_include_complete_policy_metadata(tmp_path: Path):
    tools = [Calculator(), ReadFile(tmp_path), WriteFile(tmp_path), DeleteFile(tmp_path)]
    for tool in tools:
        definition = tool.definition()
        assert definition.name and definition.description and definition.category
        assert definition.risk_level in set(RiskLevel)
        assert definition.input_schema and definition.output_schema
        assert definition.timeout_seconds > 0
        assert isinstance(definition.audit_required, bool)
        assert isinstance(definition.sandbox_required, bool)
        assert isinstance(definition.network_required, bool)
    assert WriteFile(tmp_path).idempotent is False
    assert DeleteFile(tmp_path).risk_level == RiskLevel.HIGH


@pytest.mark.asyncio
async def test_timeout_is_retryable_only_for_low_risk_idempotent_tool():
    from pydantic import BaseModel

    class Input(BaseModel):
        value: int = 1

    class Output(BaseModel):
        value: int

    class SlowRead(Tool):
        name = "slow_read"
        description = "test"
        category = "test"
        input_model = Input
        output_model = Output
        timeout_seconds = 0.001

        async def run(self, args):
            await asyncio.sleep(0.1)
            return args

    class SlowWrite(SlowRead):
        name = "slow_write"
        risk_level = RiskLevel.HIGH
        idempotent = False
        permissions = frozenset({Permission.WRITE})

    registry = Registry(timeout=1)
    registry.add(SlowRead())
    registry.add(SlowWrite())
    read = await registry.execute("slow_read", {}, set())
    write = await registry.execute("slow_write", {}, {Permission.WRITE})
    assert read.code == "timeout" and read.retryable is True
    assert write.code == "timeout" and write.retryable is False


def test_cors_wildcards_fail_closed():
    common = dict(_env_file=None, environment="test", auth_required=True, api_token="x" * 32)
    with pytest.raises(ValidationError):
        Settings(**common, cors_origins=["*"])
    settings = Settings(**common, cors_origins=["http://localhost:5173/", "http://localhost:5173"])
    assert settings.cors_origins == ["http://localhost:5173"]


def test_document_metadata_is_bounded():
    with pytest.raises(ValidationError):
        DocumentIn(path="a.md", metadata={str(index): "x" for index in range(51)})
    with pytest.raises(ValidationError):
        DocumentIn(path="a.md", metadata={"key": "x" * 1001})
    with pytest.raises(ValidationError):
        DocumentIn(path="a.md", metadata={"bad\nkey": "value"})


@pytest.mark.asyncio
async def test_audit_adds_request_id_and_redacts(tmp_path: Path):
    store = MemoryStore(tmp_path / "state.db")
    await store.init()
    token = request_id_var.set("request-12345678")
    try:
        await store.audit("blocked", {"token": "secret-value", "result": "blocked"})
    finally:
        request_id_var.reset(token)
    record = (await store.audits(1))[0]
    assert record["details"]["request_id"] == "request-12345678"
    assert record["details"]["token"] == "[REDACTED]"


@pytest.mark.asyncio
async def test_llm_rejects_empty_chat_and_malformed_embeddings(monkeypatch):
    monkeypatch.setattr("app.llm.settings", lambda: SimpleNamespace(
        ollama_model="model", embedding_model="embed", ollama_base_url="http://127.0.0.1:11434", llm_timeout_seconds=1,
        max_llm_response_bytes=1_000_000, max_llm_output_chars=100_000,
        max_llm_completion_tokens=16_384, max_embedding_batch=128,
        max_embedding_input_chars=100_000, max_embedding_dimension=8_192
    ))
    provider = OllamaProvider()

    class Response:
        def __init__(self, body): self.body = body
        headers = {}
        async def __aenter__(self): return self
        async def __aexit__(self, *args): return None
        def raise_for_status(self): return None
        async def aiter_bytes(self):
            import json
            yield json.dumps(self.body).encode()

    class Client:
        def stream(self, method, path, json=None):
            return Response({"message": {"content": ""}} if path == "/api/chat" else {"embeddings": [[1.0], [1.0, 2.0]]})
        async def aclose(self): return None

    await provider.client.aclose()
    provider.client = Client()
    from app.models import ChatRequest, Message
    with pytest.raises(LLMError):
        await provider.chat(ChatRequest(messages=[Message(role="user", content="hello")]))
    with pytest.raises(LLMError):
        await provider.embed(["a", "b"])
