import asyncio
import ipaddress
from types import SimpleNamespace

import pytest

from app.config import Settings
from app.network_security import NetworkPolicyError, SafeHttpClient, ValidatedTarget, validate_url
from app.tools.factory import _build_registry


@pytest.mark.asyncio
@pytest.mark.parametrize("url", [
    "file:///etc/passwd",
    "http://127.0.0.1:8080",
    "http://169.254.169.254/latest/meta-data",
    "http://[::1]/",
])
async def test_ssrf_targets_are_blocked(url):
    with pytest.raises(NetworkPolicyError):
        await validate_url(url)


def test_network_disabled_by_default(tmp_path):
    config = Settings(environment="test", database_path=tmp_path/"db.sqlite", workspace_root=tmp_path/"workspace")
    config.workspace_root.mkdir()
    search = next(item for item in _build_registry(config, config.workspace_root).definitions() if item.name == "web_search")
    assert search.enabled is False
    assert search.disabled_reason.startswith("NETWORK_DISABLED")


def test_enabled_network_requires_provider(tmp_path):
    with pytest.raises(ValueError, match="SearXNG"):
        Settings(environment="test", database_path=tmp_path/"db.sqlite", workspace_root=tmp_path/"workspace", enable_network_tools=True, network_mode="full", allow_external_network=True, web_search_enabled=True)


@pytest.mark.asyncio
async def test_http_client_connects_to_validated_numeric_address(monkeypatch, runtime_network_allowed):
    observed = {}

    class Response:
        is_redirect = False
        status_code = 200
        headers = {"content-type": "text/plain", "content-length": "2"}
        def raise_for_status(self): return None
        async def aiter_bytes(self): yield b"ok"

    class Stream:
        async def __aenter__(self): return Response()
        async def __aexit__(self, *_): return False

    class Client:
        async def __aenter__(self): return self
        async def __aexit__(self, *_): return False
        def stream(self, method, url, **kwargs):
            observed.update(method=method, url=url, kwargs=kwargs)
            return Stream()

    async def target(*_args, **_kwargs):
        return ValidatedTarget(
            "https://example.test/path", "https://203.0.113.10/path",
            "example.test", "example.test", ("203.0.113.10",),
        )

    monkeypatch.setattr("app.network_security.validate_url", target)
    monkeypatch.setattr("app.network_security.httpx.AsyncClient", lambda **_: Client())
    status, _, text = await SafeHttpClient(1, 100).request("GET", "https://example.test/path")
    assert (status, text) == (200, "ok")
    assert observed["url"] == "https://203.0.113.10/path"
    assert observed["kwargs"]["headers"]["Host"] == "example.test"
    assert observed["kwargs"]["extensions"]["sni_hostname"] == b"example.test"


@pytest.mark.asyncio
async def test_http_client_fails_closed_when_runtime_policy_is_unavailable(monkeypatch):
    monkeypatch.setattr("app.network_security.get_control_center", lambda: None)
    with pytest.raises(NetworkPolicyError, match="NETWORK_RUNTIME_POLICY_UNAVAILABLE"):
        await SafeHttpClient(1, 100).request("GET", "https://example.test/path")


@pytest.mark.asyncio
async def test_http_client_fails_closed_when_runtime_policy_loader_errors(monkeypatch):
    def broken_gate():
        raise RuntimeError("corrupted runtime configuration")

    monkeypatch.setattr("app.network_security.get_control_center", broken_gate)
    with pytest.raises(NetworkPolicyError, match="NETWORK_RUNTIME_POLICY_UNAVAILABLE"):
        await SafeHttpClient(1, 100).request("GET", "https://example.test/path")
