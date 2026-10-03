"""Phase 13 — multi-model / API provider routing acceptance tests.

Everything here runs against ``httpx.MockTransport`` (a real HTTP client stack
with a scripted transport), so the assertions are about SecureAgent's own code:
request shaping, credential handling, gating, fallback order, error mapping and
secret non-disclosure. No network access and no live vendor is used.
"""
import json
from pathlib import Path

import httpx
import pytest
from pydantic import ValidationError

from app.config import Settings
from app.control_center import ControlCenter, set_control_center
from app.crypto import chacha20_block, decrypt, derive_key, encrypt
from app.models import ChatRequest
from app.providers import (ProviderConfig, ProviderError, ProviderRuntime,
                           ModelRouter, ROUTES, RouterConfig, RoutingProvider,
                           SecretStore)

TEST_KEY = "sk-test-DO-NOT-LEAK-0123456789abcdef"


# --------------------------------------------------------------------------- #
# Crypto / secret store                                                       #
# --------------------------------------------------------------------------- #


def test_rfc8439_chacha20_vector_and_tamper_detection():
    key = bytes(range(32))
    nonce = bytes.fromhex("000000090000004a00000000")
    expected = bytes.fromhex(
        "10f1e7e4d13b5915500fdd1fa32071c4c7d1f4c733c068030422aa9ac3d46c4e"
        "d2826446079faa0914c2d705d98b02a2b5129cd1de164eb9cbd083e8a2503c4e")
    assert chacha20_block(key, 1, nonce) == expected
    master = derive_key(b"passphrase", b"salt", n=2 ** 10)
    payload = encrypt(master, b"secret-value", associated_data=b"provider:x")
    assert decrypt(master, payload, associated_data=b"provider:x") == b"secret-value"
    with pytest.raises(ValueError):
        decrypt(master, payload[:-1] + bytes([payload[-1] ^ 1]), associated_data=b"provider:x")
    with pytest.raises(ValueError):
        decrypt(master, payload, associated_data=b"provider:y")


def test_secret_store_encrypts_and_never_returns_plaintext(tmp_path):
    store = SecretStore(tmp_path / "providers.secrets", key_path=tmp_path / "providers.key",
                        backend="encrypted-file")
    assert store.set("openai", TEST_KEY) is True
    assert store.get("openai") == TEST_KEY
    raw = (tmp_path / "providers.secrets").read_bytes()
    assert TEST_KEY.encode() not in raw
    assert b"openai" in raw  # provider ids are metadata, not secrets
    mode = (tmp_path / "providers.secrets").stat().st_mode & 0o777
    assert mode == 0o600
    status = store.status()
    assert status["backend"] == "encrypted-file"
    assert TEST_KEY not in json.dumps(status)
    assert store.delete("openai") is True
    assert store.get("openai") is None


def test_secret_store_survives_restart(tmp_path):
    first = SecretStore(tmp_path / "s.secrets", key_path=tmp_path / "s.key",
                        backend="encrypted-file")
    first.set("groq", TEST_KEY)
    second = SecretStore(tmp_path / "s.secrets", key_path=tmp_path / "s.key",
                         backend="encrypted-file")
    assert second.get("groq") == TEST_KEY


def test_secret_store_rejects_invalid_keys(tmp_path):
    store = SecretStore(tmp_path / "s.secrets", key_path=tmp_path / "s.key")
    with pytest.raises(ProviderError):
        store.set("openai", "")
    with pytest.raises(ProviderError):
        store.set("openai", "x" * 5000)


# --------------------------------------------------------------------------- #
# Provider configuration                                                      #
# --------------------------------------------------------------------------- #


def test_provider_config_requires_https_for_remote_endpoints():
    with pytest.raises(ValidationError):
        ProviderConfig(id="p", kind="custom", base_url="http://api.example.com/v1")
    item = ProviderConfig(id="p", kind="custom", base_url="https://api.example.com/v1")
    assert item.local is False
    local = ProviderConfig(id="l", kind="ollama", base_url="http://127.0.0.1:11434")
    assert local.local is True


def test_provider_config_rejects_credentials_in_url_and_bad_ids():
    with pytest.raises(ValidationError):
        ProviderConfig(id="p", kind="custom", base_url="https://user:pass@api.example.com/v1")
    with pytest.raises(ValidationError):
        ProviderConfig(id="BAD ID", kind="custom", base_url="https://api.example.com")
    with pytest.raises(ValidationError):
        ProviderConfig(id="p", kind="unknown-kind", base_url="https://api.example.com")


def test_known_provider_kinds_get_default_endpoints():
    assert ProviderConfig(id="g", kind="groq").base_url == "https://api.groq.com/openai/v1"
    assert ProviderConfig(id="d", kind="deepseek").base_url == "https://api.deepseek.com/v1"
    with pytest.raises(ValidationError):
        ProviderConfig(id="c", kind="custom")  # custom requires an explicit base_url


def _config(tmp_path, **overrides) -> Settings:
    values = dict(database_path=Path(".pytest-data/state.db"),
                  workspace_root=Path(".pytest-data/workspace"),
                  providers_config_path=tmp_path / "providers.json")
    values.update(overrides)
    return Settings(**values)


def _gate(tmp_path, *, remote: bool = True, ai: bool = True, ollama: bool = False) -> ControlCenter:
    center = ControlCenter(tmp_path / "control_center.json")
    center.state.ai.enabled = ai
    center.state.ai.remote_providers_enabled = remote
    center.state.ai.ollama_enabled = ollama
    set_control_center(center)
    return center


def _runtime(tmp_path, handler, **overrides) -> ProviderRuntime:
    config = _config(tmp_path, remote_providers_enabled=True, **overrides)
    runtime = ProviderRuntime(config, transport=httpx.MockTransport(handler))
    runtime.upsert({"id": "openai", "kind": "openai_compatible",
                    "base_url": "https://api.openai.com/v1", "enabled": True,
                    "default_model": "gpt-4o-mini", "models": ["gpt-4o-mini"],
                    "embedding_model": "text-embedding-3-small"})
    runtime.upsert({"id": "local", "kind": "ollama", "base_url": "http://127.0.0.1:11434",
                    "enabled": True, "default_model": "llama3.2"})
    runtime.secrets.set("openai", TEST_KEY)
    return runtime


def _openai_success(request: httpx.Request) -> httpx.Response:
    return httpx.Response(200, json={"model": "gpt-4o-mini",
                                     "choices": [{"message": {"content": "routed answer"}}],
                                     "usage": {"prompt_tokens": 7, "completion_tokens": 3}})


# --------------------------------------------------------------------------- #
# Routing gate: OFF by default                                                #
# --------------------------------------------------------------------------- #


def test_providers_off_by_default(tmp_path):
    config = _config(tmp_path, remote_providers_enabled=True)
    runtime = ProviderRuntime(config, transport=httpx.MockTransport(_openai_success))
    runtime.upsert({"id": "openai", "kind": "openai_compatible", "enabled": True,
                    "base_url": "https://api.openai.com/v1", "default_model": "gpt-4o-mini"})
    runtime.secrets.set("openai", TEST_KEY)
    _gate(tmp_path, remote=True)  # Control Center allows, Settings allows ...
    assert runtime.configured(runtime.providers["openai"]) is True
    # ... but flipping the Control Center master switch OFF stops egress.
    set_control_center(None)
    assert runtime.configured(runtime.providers["openai"]) is False
    assert runtime.denial_reason(runtime.providers["openai"]) == "PROVIDER_REMOTE_DISABLED_BY_CONTROL_CENTER"


def test_settings_switch_also_blocks_remote(tmp_path):
    config = _config(tmp_path, remote_providers_enabled=False)
    runtime = ProviderRuntime(config, transport=httpx.MockTransport(_openai_success))
    runtime.upsert({"id": "openai", "kind": "openai_compatible", "enabled": True,
                    "base_url": "https://api.openai.com/v1", "default_model": "gpt-4o-mini"})
    runtime.secrets.set("openai", TEST_KEY)
    _gate(tmp_path, remote=True)
    assert runtime.configured(runtime.providers["openai"]) is False
    assert runtime.denial_reason(runtime.providers["openai"]) == "PROVIDER_REMOTE_DISABLED_IN_SETTINGS"


def test_missing_key_blocks_provider(tmp_path):
    runtime = ProviderRuntime(_config(tmp_path, remote_providers_enabled=True),
                              transport=httpx.MockTransport(_openai_success))
    runtime.upsert({"id": "openai", "kind": "openai_compatible", "enabled": True,
                    "base_url": "https://api.openai.com/v1", "default_model": "gpt-4o-mini"})
    _gate(tmp_path)
    assert runtime.configured(runtime.providers["openai"]) is False
    assert runtime.denial_reason(runtime.providers["openai"]) == "PROVIDER_KEY_MISSING"


def test_ai_master_switch_off_disables_every_provider(tmp_path):
    runtime = _runtime(tmp_path, _openai_success)
    _gate(tmp_path, remote=True, ai=False)
    assert runtime.configured(runtime.providers["openai"]) is False


# --------------------------------------------------------------------------- #
# Real request shaping per provider family                                    #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio()
async def test_openai_compatible_request_shape_and_parsing(tmp_path):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["url"] = str(request.url)
        seen["auth"] = request.headers.get("authorization")
        seen["body"] = json.loads(request.content)
        return _openai_success(request)

    runtime = _runtime(tmp_path, handler)
    _gate(tmp_path)
    response = await runtime.chat(runtime.providers["openai"],
                                  ChatRequest(messages=[{"role": "user", "content": "hi"}],
                                              json_mode=True))
    assert seen["url"].endswith("/chat/completions")
    assert seen["auth"] == f"Bearer {TEST_KEY}"
    assert seen["body"]["model"] == "gpt-4o-mini"
    assert seen["body"]["response_format"] == {"type": "json_object"}
    assert response.content == "routed answer"
    assert response.prompt_tokens == 7 and response.completion_tokens == 3


@pytest.mark.asyncio()
async def test_anthropic_request_shape(tmp_path):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["key_header"] = request.headers.get("x-api-key")
        seen["version"] = request.headers.get("anthropic-version")
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"model": "claude-3-5-sonnet",
                                         "content": [{"type": "text", "text": "claude says hi"}],
                                         "usage": {"input_tokens": 5, "output_tokens": 2}})

    runtime = ProviderRuntime(_config(tmp_path, remote_providers_enabled=True),
                              transport=httpx.MockTransport(handler))
    runtime.upsert({"id": "anthropic", "kind": "anthropic", "enabled": True,
                    "default_model": "claude-3-5-sonnet"})
    runtime.secrets.set("anthropic", TEST_KEY)
    _gate(tmp_path)
    response = await runtime.chat(runtime.providers["anthropic"],
                                  ChatRequest(messages=[{"role": "system", "content": "be nice"},
                                                        {"role": "user", "content": "hi"}]))
    assert seen["path"].endswith("/v1/messages")
    assert seen["key_header"] == TEST_KEY
    assert seen["version"] == "2023-06-01"
    assert seen["body"]["system"] == "be nice"
    assert [message["role"] for message in seen["body"]["messages"]] == ["user"]
    assert response.content == "claude says hi"


@pytest.mark.asyncio()
async def test_google_request_shape(tmp_path):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["key"] = request.url.params.get("key")
        return httpx.Response(200, json={"candidates": [{"content": {"parts": [{"text": "gemini"}]}}]})

    runtime = ProviderRuntime(_config(tmp_path, remote_providers_enabled=True),
                              transport=httpx.MockTransport(handler))
    runtime.upsert({"id": "google", "kind": "google", "enabled": True,
                    "default_model": "gemini-2.0-flash"})
    runtime.secrets.set("google", TEST_KEY)
    _gate(tmp_path)
    response = await runtime.chat(runtime.providers["google"],
                                  ChatRequest(messages=[{"role": "user", "content": "hi"}]))
    assert "generateContent" in seen["path"]
    assert seen["key"] == TEST_KEY
    assert response.content == "gemini"


@pytest.mark.asyncio()
async def test_ollama_request_shape(tmp_path):
    seen = {}

    def handler(request: httpx.Request) -> httpx.Response:
        seen["path"] = request.url.path
        seen["body"] = json.loads(request.content)
        return httpx.Response(200, json={"model": "llama3.2",
                                         "message": {"content": "local model"},
                                         "prompt_eval_count": 4, "eval_count": 1})

    runtime = ProviderRuntime(_config(tmp_path), transport=httpx.MockTransport(handler))
    runtime.upsert({"id": "local", "kind": "ollama", "enabled": True,
                    "default_model": "llama3.2", "api_key_required": False})
    _gate(tmp_path, remote=False, ollama=True)
    response = await runtime.chat(runtime.providers["local"],
                                  ChatRequest(messages=[{"role": "user", "content": "hi"}]))
    assert seen["path"].endswith("/api/chat")
    assert seen["body"]["options"]["num_ctx"] == 8_192
    assert response.content == "local model"


@pytest.mark.asyncio()
async def test_embeddings_and_model_listing(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.path.endswith("/embeddings"):
            return httpx.Response(200, json={"data": [{"embedding": [0.1, 0.2]},
                                                      {"embedding": [0.3, 0.4]}]})
        return httpx.Response(200, json={"data": [{"id": "gpt-4o-mini"}, {"id": "gpt-4o"}]})

    runtime = _runtime(tmp_path, handler)
    _gate(tmp_path)
    vectors = await runtime.embed(runtime.providers["openai"], ["a", "b"])
    assert vectors == [[0.1, 0.2], [0.3, 0.4]]
    assert await runtime.models(runtime.providers["openai"]) == ["gpt-4o-mini", "gpt-4o"]


@pytest.mark.asyncio()
async def test_malformed_embedding_is_refused(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, json={"data": [{"embedding": ["not", "numbers"]}]})

    runtime = _runtime(tmp_path, handler)
    _gate(tmp_path)
    with pytest.raises(ProviderError) as error:
        await runtime.embed(runtime.providers["openai"], ["a"])
    assert "PROVIDER_INVALID_RESPONSE" in str(error.value)


# --------------------------------------------------------------------------- #
# Structured failures (never a fake answer)                                    #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio()
@pytest.mark.parametrize("status,code", [(401, "PROVIDER_AUTH_FAILED"),
                                         (403, "PROVIDER_AUTH_FAILED"),
                                         (429, "PROVIDER_RATE_LIMITED"),
                                         (500, "PROVIDER_REQUEST_FAILED")])
async def test_http_failures_map_to_structured_codes(tmp_path, status, code):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(status, json={"error": {"message": "nope"}})

    runtime = _runtime(tmp_path, handler)
    _gate(tmp_path)
    with pytest.raises(ProviderError) as error:
        await runtime.chat(runtime.providers["openai"],
                           ChatRequest(messages=[{"role": "user", "content": "hi"}]))
    assert error.value.code == code
    assert TEST_KEY not in json.dumps(error.value.payload())


@pytest.mark.asyncio()
async def test_unreachable_and_timeout_are_reported_honestly(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        raise httpx.ConnectError("no route", request=request)

    runtime = _runtime(tmp_path, handler)
    _gate(tmp_path)
    with pytest.raises(ProviderError) as error:
        await runtime.chat(runtime.providers["openai"],
                           ChatRequest(messages=[{"role": "user", "content": "hi"}]))
    assert error.value.code == "PROVIDER_UNREACHABLE"

    def slow(request: httpx.Request) -> httpx.Response:
        raise httpx.ReadTimeout("too slow", request=request)

    runtime = _runtime(tmp_path, slow)
    with pytest.raises(ProviderError) as error:
        await runtime.chat(runtime.providers["openai"],
                           ChatRequest(messages=[{"role": "user", "content": "hi"}]))
    assert error.value.code == "PROVIDER_TIMEOUT"


@pytest.mark.asyncio()
async def test_oversized_response_is_bounded(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(200, content=b'{"choices":[{"message":{"content":"' + b"x" * 100_000 + b'"}}]}')

    runtime = _runtime(tmp_path, handler, provider_max_response_bytes=10_000)
    _gate(tmp_path)
    with pytest.raises(ProviderError) as error:
        await runtime.chat(runtime.providers["openai"],
                           ChatRequest(messages=[{"role": "user", "content": "hi"}]))
    assert error.value.code == "PROVIDER_INVALID_RESPONSE"


@pytest.mark.asyncio()
async def test_test_endpoint_never_returns_the_key(tmp_path):
    runtime = _runtime(tmp_path, lambda request: httpx.Response(
        200, json={"data": [{"id": "gpt-4o-mini"}]}))
    _gate(tmp_path)
    result = await runtime.test("openai")
    assert result["reachable"] is True
    assert result["api_key_configured"] is True
    assert TEST_KEY not in json.dumps(result)


# --------------------------------------------------------------------------- #
# Router: modes, ordering, fallback chain                                      #
# --------------------------------------------------------------------------- #


def _second_provider(runtime, handler):
    runtime.upsert({"id": "backup", "kind": "openai_compatible",
                    "base_url": "https://backup.example.com/v1", "enabled": True,
                    "default_model": "backup-model"})
    runtime.secrets.set("backup", "sk-backup-0000")


@pytest.mark.asyncio()
async def test_local_first_prefers_local_provider(tmp_path):
    calls = []

    def handler(request: httpx.Request) -> httpx.Response:
        calls.append(request.url.host)
        if request.url.host == "127.0.0.1":
            return httpx.Response(200, json={"model": "llama3.2",
                                             "message": {"content": "local"}})
        return _openai_success(request)

    runtime = _runtime(tmp_path, handler)
    _gate(tmp_path, ollama=True)
    router = ModelRouter(runtime, runtime.config)
    decision = router.resolve("chat")
    assert decision.provider_id == "local"
    response, provider_id, _ = await router.chat("chat", ChatRequest(
        messages=[{"role": "user", "content": "hi"}]))
    assert provider_id == "local" and response.content == "local"
    assert calls == ["127.0.0.1"]


@pytest.mark.asyncio()
async def test_cloud_first_and_cost_aware_ordering(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return _openai_success(request)

    runtime = _runtime(tmp_path, handler)
    runtime.providers["local"].cost_per_1k_input = 0.0
    runtime.providers["local"].cost_per_1k_output = 0.0
    runtime.providers["openai"].cost_per_1k_input = 5.0
    runtime.providers["openai"].cost_per_1k_output = 15.0
    runtime.providers["local"].enabled = False  # only the cloud provider remains
    _gate(tmp_path, ollama=False)
    router = ModelRouter(runtime, runtime.config)
    assert router.resolve("chat").provider_id == "openai"
    runtime.router.mode = "cost_aware"
    assert router.resolve("chat").provider_id == "openai"


@pytest.mark.asyncio()
async def test_fallback_chain_uses_next_provider(tmp_path):
    seen = []

    def handler(request: httpx.Request) -> httpx.Response:
        seen.append(request.url.host)
        if request.url.host == "api.openai.com":
            return httpx.Response(500, json={"error": "boom"})
        return httpx.Response(200, json={"model": "backup-model",
                                         "choices": [{"message": {"content": "backup answer"}}]})

    runtime = _runtime(tmp_path, handler)
    _second_provider(runtime, handler)
    _gate(tmp_path)
    runtime.router.mode = "manual"
    runtime.router.fallback_chain = ["openai", "backup"]
    runtime.router.assignments = {"chat": "openai:gpt-4o-mini"}
    runtime.save()
    router = ModelRouter(runtime, runtime.config)
    response, provider_id, attempts = await router.chat("chat", ChatRequest(
        messages=[{"role": "user", "content": "hi"}]), allow_local_fallback=False)
    assert provider_id == "backup"
    assert response.content == "backup answer"
    assert [attempt["provider"] for attempt in attempts] == ["openai", "backup"]
    assert attempts[0]["code"] == "PROVIDER_REQUEST_FAILED"


@pytest.mark.asyncio()
async def test_exhausted_chain_raises_and_never_fabricates(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    runtime = _runtime(tmp_path, handler)
    _gate(tmp_path)
    router = ModelRouter(runtime, runtime.config)
    with pytest.raises(ProviderError) as error:
        await router.chat("chat", ChatRequest(messages=[{"role": "user", "content": "hi"}]),
                          allow_local_fallback=False)
    assert error.value.code == "ROUTER_CHAIN_EXHAUSTED"


@pytest.mark.asyncio()
async def test_privacy_first_refuses_when_only_remote_providers_exist(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        raise AssertionError("remote provider must not be called in privacy_first mode")

    runtime = _runtime(tmp_path, handler)
    runtime.providers["local"].enabled = False
    _gate(tmp_path)
    runtime.router.mode = "privacy_first"
    router = ModelRouter(runtime, runtime.config)
    decision = router.resolve("chat")
    assert decision.provider_id is None
    assert "privacy-first" in decision.reason


def test_router_rejects_unknown_route_and_bad_assignments():
    with pytest.raises(ProviderError):
        ModelRouter.__new__(ModelRouter).resolve("nonsense")
    with pytest.raises(ValidationError):
        RouterConfig(assignments={"nonsense": "openai:gpt-4o"})
    with pytest.raises(ValidationError):
        RouterConfig(assignments={"chat": "gpt-4o"})
    assert RouterConfig(fallback_chain=["B", "a", "b", ""]).fallback_chain == ["b", "a"]


def test_control_center_route_validation(tmp_path):
    from app.control_center import ControlModelError, ControlState
    state = ControlState()
    assert state.ai.remote_providers_enabled is False
    assert state.ai.routing_mode == "local_first"
    with pytest.raises(ValidationError):
        ControlState(ai={"routing_mode": "sneaky"})
    with pytest.raises(ValidationError):
        ControlState(ai={"route_models": {"nonsense": "openai:gpt-4o"}})


# --------------------------------------------------------------------------- #
# RoutingProvider composition (agent-facing)                                  #
# --------------------------------------------------------------------------- #


class FakeLegacy:
    name = "LOCAL CORE"
    active = "LOCAL CORE"

    def __init__(self):
        self.calls = 0

    async def chat(self, request):
        self.calls += 1
        from app.models import ChatResponse
        return ChatResponse(content="legacy answer", model="LOCAL CORE")

    async def embed(self, texts):
        raise ProviderError("EMBEDDING_UNAVAILABLE", "no embedding provider")

    async def models(self):
        return []

    async def status(self):
        return {"active_provider": "LOCAL CORE", "local_core": True,
                "generative_available": False, "models": []}

    async def diagnostics(self):
        return await self.status()

    async def close(self):
        return None


@pytest.mark.asyncio()
async def test_routing_provider_uses_configured_provider(tmp_path):
    runtime = _runtime(tmp_path, _openai_success)
    _gate(tmp_path)
    legacy = FakeLegacy()
    provider = RoutingProvider(_config(tmp_path, remote_providers_enabled=True),
                               runtime=runtime, legacy=legacy)
    response = await provider.chat(ChatRequest(messages=[{"role": "user", "content": "hi"}]))
    assert response.content == "routed answer"
    assert provider.active == "openai"
    assert legacy.calls == 0
    status = await provider.status()
    assert status["active_provider"] == "openai"
    assert status["multi_model"]["configured_providers"] == ["openai"]
    assert TEST_KEY not in json.dumps(status)


@pytest.mark.asyncio()
async def test_routing_provider_falls_back_to_legacy_when_chain_fails(tmp_path):
    def handler(request: httpx.Request) -> httpx.Response:
        return httpx.Response(500, json={"error": "boom"})

    runtime = _runtime(tmp_path, handler)
    runtime.providers["local"].enabled = False
    _gate(tmp_path)
    legacy = FakeLegacy()
    provider = RoutingProvider(_config(tmp_path, remote_providers_enabled=True),
                               runtime=runtime, legacy=legacy)
    response = await provider.chat(ChatRequest(messages=[{"role": "user", "content": "hi"}]))
    assert response.content == "legacy answer"
    assert legacy.calls == 1
    assert provider.active == "LOCAL CORE"
    assert provider.last_attempts[0]["status"] == "failed"
    assert provider.last_attempts[-1]["status"] == "fallback"


@pytest.mark.asyncio()
async def test_routing_provider_with_no_providers_is_legacy(tmp_path):
    runtime = ProviderRuntime(_config(tmp_path), transport=httpx.MockTransport(_openai_success))
    _gate(tmp_path)
    legacy = FakeLegacy()
    provider = RoutingProvider(_config(tmp_path), runtime=runtime, legacy=legacy)
    response = await provider.chat(ChatRequest(messages=[{"role": "user", "content": "hi"}]))
    assert response.content == "legacy answer"
    assert legacy.calls == 1
    assert TEST_KEY not in json.dumps(await provider.diagnostics())


# --------------------------------------------------------------------------- #
# REST surface                                                                #
# --------------------------------------------------------------------------- #


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    from app.main import provider_runtime
    headers = {"Authorization": "Bearer test-only-token-0123456789abcdef0123456789"}
    with TestClient(app) as test_client:
        test_client.headers.update(headers)
        yield test_client
    # Never leave a stored key or provider behind for the next test.
    for provider_id in list(provider_runtime.providers):
        provider_runtime.remove(provider_id)
    provider_runtime.router = RouterConfig()
    provider_runtime.save()


def test_model_api_lists_providers_and_policy(client):
    body = client.get("/api/v1/models").json()
    assert body["policy"]["remote_providers_allowed"] is False
    assert body["policy"]["control_center_remote_switch"] is False
    assert body["secret_store"]["encrypted"] is True
    assert set(body["routes"]) == set(ROUTES)


def test_model_api_store_never_echoes_the_key(client):
    response = client.post("/api/v1/models/providers", json={
        "id": "openai", "kind": "openai_compatible", "label": "OpenAI",
        "enabled": True, "default_model": "gpt-4o-mini",
        "models": ["gpt-4o-mini"], "api_key": TEST_KEY})
    assert response.status_code == 201
    assert response.json()["api_key_configured"] is True
    assert TEST_KEY not in response.text
    listed = client.get("/api/v1/models/providers")
    assert TEST_KEY not in listed.text
    assert listed.json()["providers"][0]["api_key_configured"] is True
    # The status endpoint must not leak it either.
    assert TEST_KEY not in client.get("/api/v1/models").text
    # Test endpoint: remote providers are refused while the switches are OFF,
    # with a structured code and no key in the body.
    tested = client.post("/api/v1/models/providers/openai/test")
    assert tested.status_code == 200
    body = tested.json()
    assert body["reachable"] is False
    assert TEST_KEY not in tested.text
    # Key rotation + deletion.
    assert client.post("/api/v1/models/providers/openai/key",
                       json={"api_key": "sk-rotated"}).status_code == 200
    assert client.delete("/api/v1/models/providers/openai/key").json()["api_key_configured"] is False
    assert client.delete("/api/v1/models/providers/openai").json()["removed"] is True
    assert client.delete("/api/v1/models/providers/openai").status_code == 404


def test_model_api_rejects_insecure_and_unknown_providers(client):
    insecure = client.post("/api/v1/models/providers", json={
        "id": "evil", "kind": "custom", "base_url": "http://api.example.com", "enabled": True})
    assert insecure.status_code == 422
    unknown_key = client.post("/api/v1/models/providers/ghost/key", json={"api_key": "k"})
    assert unknown_key.status_code == 404
    assert unknown_key.json()["error"]["code"] == "PROVIDER_UNKNOWN"


def test_model_api_router_patch_validates(client):
    ok = client.patch("/api/v1/models/router", json={
        "mode": "cost_aware", "fallback_chain": ["openai", "local"],
        "assignments": {"chat": "openai:gpt-4o-mini"}})
    assert ok.status_code == 200
    assert ok.json()["mode"] == "cost_aware"
    assert ok.json()["router"]["fallback_chain"] == ["openai", "local"]
    bad = client.patch("/api/v1/models/router", json={"mode": "sneaky"})
    assert bad.status_code == 422
    bad_route = client.patch("/api/v1/models/router", json={"assignments": {"nope": "a:b"}})
    assert bad_route.status_code == 422


def test_model_api_route_chat_refuses_without_provider(client):
    response = client.post("/api/v1/models/route-chat", json={"message": "hello"})
    assert response.status_code in {403, 409}
    assert response.json()["error"]["code"] in {
        "ROUTER_CHAIN_EXHAUSTED", "PROVIDER_REMOTE_DISABLED_BY_CONTROL_CENTER",
        "PROVIDER_REMOTE_DISABLED_IN_SETTINGS"}


def test_model_api_requires_auth():
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as anonymous:
        assert anonymous.get("/api/v1/models").status_code in {401, 403}
