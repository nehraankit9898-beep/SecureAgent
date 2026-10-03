import pytest

from app.network_security import NetworkPolicyError, SafeHttpClient


class _Headers(dict):
    pass


class _Response:
    is_redirect = False
    status_code = 200
    url = "https://example.test/data"

    def __init__(self, content_length):
        self.headers = _Headers({"content-length": content_length, "content-type": "application/json"})

    def raise_for_status(self):
        return None

    async def aiter_bytes(self):
        yield b"{}"


class _Stream:
    def __init__(self, response):
        self.response = response

    async def __aenter__(self):
        return self.response

    async def __aexit__(self, *_):
        return False


@pytest.mark.asyncio
@pytest.mark.parametrize("value", ["not-a-number", "-1"])
async def test_invalid_content_length_is_rejected(monkeypatch, value, runtime_network_allowed):
    class Client:
        async def __aenter__(self): return self
        async def __aexit__(self, *_): return False
        def stream(self, *_args, **_kwargs): return _Stream(_Response(value))

    async def allow(*_args, **_kwargs): return "https://example.test/data"
    monkeypatch.setattr("app.network_security.httpx.AsyncClient", lambda **_: Client())
    monkeypatch.setattr("app.network_security.validate_url", allow)
    with pytest.raises(NetworkPolicyError, match="invalid content length"):
        await SafeHttpClient(timeout=1, max_bytes=100).request("GET", "https://example.test/data")
