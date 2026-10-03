import asyncio
from datetime import UTC, datetime, timedelta

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.memory import MemoryStore
from app.models import ScheduleCreate, SchedulePatch
from fastapi.responses import JSONResponse


def secure_settings(tmp_path, **overrides):
    values = dict(environment='test', auth_required=True, api_token='x' * 40,
                  database_path=tmp_path/'state.db', workspace_root=tmp_path/'workspace')
    values.update(overrides)
    return Settings(**values)


def test_ollama_model_names_and_completion_limit_are_validated(tmp_path):
    assert secure_settings(tmp_path).max_llm_completion_tokens == 16384
    with pytest.raises(ValidationError):
        secure_settings(tmp_path, max_llm_completion_tokens=1)
    with pytest.raises(ValidationError):
        secure_settings(tmp_path, ollama_model='../escape')
    with pytest.raises(ValidationError):
        secure_settings(tmp_path, ollama_base_url='http://user:pass@127.0.0.1:11434')


@pytest.mark.asyncio
async def test_schedule_update_is_persisted_and_cancelled_schedule_fails_closed(tmp_path):
    store = MemoryStore(tmp_path/'state.db')
    await store.init()
    created = await store.create_schedule(ScheduleCreate(
        name='original', prompt='calculate 1+1',
        run_at=datetime.now(UTC)+timedelta(hours=1)))
    updated = await store.update_schedule(created['id'], SchedulePatch(
        name='updated', run_at=datetime.now(UTC)+timedelta(hours=2)))
    assert updated['name'] == 'updated'
    assert await store.cancel_schedule(created['id'])
    with pytest.raises(ValueError, match='cancelled'):
        await store.update_schedule(created['id'], SchedulePatch(name='forbidden'))


@pytest.mark.asyncio
async def test_readiness_fails_closed_when_required_models_are_missing(monkeypatch):
    import app.main as main

    class Provider:
        async def status(self):
            return {
                "generative_available": False,
                "embedding_available": False,
                "last_error": {
                    "code": "OLLAMA_SERVICE_STOPPED",
                    "message": "The Ollama service is not reachable.",
                    "recovery_action": "Start Ollama.",
                },
            }

    monkeypatch.setattr(main, "get_llm", lambda: Provider())
    response = await main.ready()
    assert isinstance(response, JSONResponse)
    assert response.status_code == 503
    assert b"OLLAMA_SERVICE_STOPPED" in response.body


def test_structured_error_contract_is_wired_in_source():
    from pathlib import Path
    source = (Path(__file__).parents[1]/'app'/'main.py').read_text()
    assert '"success":False,"error":{"code"' in source
    assert 'X-API-Contract-Version' in source
    assert 'AUTHENTICATION_REQUIRED' in source
    assert 'RequestValidationError' in source


def test_python_sandbox_uses_bounded_stream_readers():
    from pathlib import Path
    source = (Path(__file__).parents[1]/'app'/'sandbox.py').read_text()
    section = source.split('class DockerPythonSandbox', 1)[1]
    assert 'read_stream_limited' in section
    assert 'process.communicate' not in section
    assert 'except asyncio.CancelledError' in section
