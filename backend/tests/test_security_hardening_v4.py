import asyncio
import json
import os
from datetime import UTC, datetime, timedelta
from pathlib import Path
from types import SimpleNamespace
from zoneinfo import ZoneInfo

import pytest
from pydantic import ValidationError

from app.coding import SearchCode
from app.llm import LLMError, OllamaProvider
from app.models import PlanStep, ScheduleCreate
from app.memory import MemoryStore
from app.security import redact, request_id_var
from app.workspace import WorkspacePolicy


@pytest.mark.parametrize('name', ['api-key','apikey','api_key','API-Key','authorization','Authorization','token','access_token','refresh_token','password','secret','private_key','client_secret'])
def test_all_secret_aliases_are_redacted(name):
    assert redact({name: 'value-123'})[name] == '[REDACTED]'
    assert 'value-123' not in redact(f'{name}=value-123')


def test_nested_and_object_redaction():
    class Payload:
        def __init__(self):
            self.client_secret = 'hidden'
            self.items = [{'Authorization': 'Bearer hidden'}]
    rendered = json.dumps(redact(Payload()))
    assert 'hidden' not in rendered


def test_audit_details_cannot_override_trusted_request_id(tmp_path):
    async def scenario():
        store = MemoryStore(tmp_path / 'audit.db')
        await store.init()
        token = request_id_var.set('trusted-request-123')
        try:
            await store.audit('security.test', {'request_id': 'forged-request-999'})
        finally:
            request_id_var.reset(token)
        record = (await store.audits(1))[0]
        assert record['details']['request_id'] == 'trusted-request-123'
    asyncio.run(scenario())


@pytest.mark.parametrize('pattern', ['(a+)+$', '(a|aa)+$', '(.*a){20}'])
def test_catastrophic_regex_is_rejected(tmp_path, pattern):
    (tmp_path / 'a.txt').write_text('a' * 100_000 + '!')
    tool = SearchCode(tmp_path)
    with pytest.raises(ValueError, match='unsafe regular expression'):
        asyncio.run(tool.run({'query': pattern, 'path': '.', 'regex': True, 'limit': 1}))


def test_tool_argument_json_depth_and_size_are_bounded():
    value = {'x': 1}
    for _ in range(12):
        value = {'x': value}
    with pytest.raises(ValidationError):
        PlanStep(title='x', tool='calculator', arguments=value)
    with pytest.raises(ValidationError):
        PlanStep(title='x', tool='calculator', arguments={'x': 'a' * 60_000})


def test_schedule_requires_explicit_future_timezone_and_normalizes_utc():
    for value in [datetime.now(), datetime.now(UTC) - timedelta(seconds=1), datetime.now(UTC) + timedelta(days=4000)]:
        with pytest.raises(ValidationError):
            ScheduleCreate(name='x', prompt='x', run_at=value)
    local = datetime.now(ZoneInfo('Asia/Kolkata')) + timedelta(hours=1)
    item = ScheduleCreate(name='x', prompt='x', run_at=local)
    assert item.run_at.tzinfo is UTC


def test_workspace_blocks_sensitive_names_and_hardlinks(tmp_path):
    policy = WorkspacePolicy(tmp_path)
    for name in ['.env', '.SSH/id_rsa', 'docker.sock', 'Secrets/x']:
        with pytest.raises(PermissionError):
            policy.resolve(name)
    policy.atomic_write('a.txt', 'x')
    os.link(tmp_path / 'a.txt', tmp_path / 'b.txt')
    with pytest.raises(PermissionError, match='hard-linked'):
        policy.read_text('a.txt')
    with pytest.raises(PermissionError, match='hard-linked'):
        policy.delete('a.txt', 'DELETE')


class FakeStream:
    def __init__(self, body): self.body = body; self.headers = {}
    async def __aenter__(self): return self
    async def __aexit__(self, *args): return None
    def raise_for_status(self): return None
    async def aiter_bytes(self): yield self.body

class FakeClient:
    def __init__(self, body): self.body = body
    def stream(self, *args, **kwargs): return FakeStream(self.body)


def provider(body, **overrides):
    item = OllamaProvider.__new__(OllamaProvider)
    defaults = dict(max_llm_response_bytes=1000, max_llm_output_chars=100, max_llm_completion_tokens=100, max_embedding_batch=4, max_embedding_input_chars=1000, max_embedding_dimension=8, max_embedding_values=16)
    defaults.update(overrides); item.config = SimpleNamespace(**defaults); item.default_model='m'; item.embedding_model='e'; item.client=FakeClient(body)
    return item


def test_llm_response_bytes_and_characters_are_bounded():
    with pytest.raises(LLMError):
        asyncio.run(provider(b'x' * 1001).chat(SimpleNamespace(model=None, messages=[], temperature=0, json_mode=False)))
    body=json.dumps({'message':{'content':'x'*101},'model':'m'}).encode()
    with pytest.raises(LLMError):
        asyncio.run(provider(body).chat(SimpleNamespace(model=None,messages=[],temperature=0,json_mode=False)))


@pytest.mark.parametrize('vector', [[], [float('nan')], [float('inf')], list(range(9))])
def test_invalid_or_oversized_embeddings_are_rejected(vector):
    body=json.dumps({'embeddings':[vector]}).encode()
    with pytest.raises(LLMError): asyncio.run(provider(body).embed(['x']))
