"""REST surface for multi-model provider management (Phase 13).

Security contract of this API:

* an API key can be SET and DELETED, but it is never returned — responses only
  ever contain ``api_key_configured: true/false``;
* provider test/list endpoints perform real network calls (or fail honestly);
  nothing is faked;
* remote providers stay refused until the operator enables them in Settings
  AND in the Control Center, so flipping either switch OFF stops egress;
* the router configuration (mode / per-route model / fallback order) is typed,
  bounded and validated here and persisted by ``ProviderRuntime``.
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.models import ChatRequest
from app.providers import (ROUTING_MODES, ROUTES, ProviderError, ProviderRuntime,
                           RoutingProvider, RouterConfig)


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class ProviderIn(_Strict):
    id: str = Field(min_length=1, max_length=48)
    kind: Literal["ollama", "openai_compatible", "anthropic", "google", "groq",
                  "together", "openrouter", "deepseek", "qwen", "zai", "custom"]
    label: str = Field("", max_length=120)
    base_url: str = Field("", max_length=500)
    enabled: bool = False
    models: list[str] = Field(default_factory=list, max_length=200)
    default_model: str | None = Field(None, max_length=200)
    embedding_model: str | None = Field(None, max_length=200)
    vision_model: str | None = Field(None, max_length=200)
    temperature: float = Field(0.2, ge=0, le=2)
    max_tokens: int = Field(4_096, ge=1, le=131_072)
    timeout_seconds: float = Field(120, gt=0, le=600)
    context_window: int = Field(8_192, ge=512, le=2_000_000)
    streaming: bool = False
    reasoning: bool = False
    cost_per_1k_input: float = Field(0.0, ge=0, le=10_000)
    cost_per_1k_output: float = Field(0.0, ge=0, le=10_000)
    api_key_env: str | None = Field(None, max_length=64)
    api_key_required: bool = True
    # Write-only: stored in the OS vault / encrypted file, never echoed back.
    api_key: str | None = Field(None, min_length=1, max_length=4096)


class KeyIn(_Strict):
    api_key: str = Field(min_length=1, max_length=4096)


class RouterIn(_Strict):
    mode: Literal["auto", "local_first", "cloud_first", "cost_aware", "speed_first",
                  "privacy_first", "manual"] | None = None
    assignments: dict[str, str] | None = None
    fallback_chain: list[str] | None = None


class RouteChatIn(_Strict):
    message: str = Field(min_length=1, max_length=20_000)
    route: Literal["chat", "planner", "coding", "vision", "security", "reviewer",
                   "embedding", "fast"] = "chat"
    model: str | None = Field(None, max_length=200)
    temperature: float = Field(0.2, ge=0, le=2)


def provider_error_status(code: str) -> int:
    if code.endswith("UNKNOWN"):
        return 404
    if code in {"ROUTER_CHAIN_EXHAUSTED", "EMBEDDING_UNAVAILABLE"}:
        return 409
    if "AUTH_FAILED" in code or "DISABLED" in code or "KEY_MISSING" in code \
            or "NOT_CONFIGURED" in code:
        return 403
    if "UNREACHABLE" in code or "TIMEOUT" in code or "RATE_LIMITED" in code \
            or "INVALID_RESPONSE" in code or "REQUEST_FAILED" in code:
        return 502
    return 400


def _provider_error(error: ProviderError) -> HTTPException:
    return HTTPException(provider_error_status(error.code),
                         detail={"error_code": error.code,
                                 "message": error.message or error.code,
                                 "details": {"recovery_action": error.recovery}})


def build_model_router_api(runtime: ProviderRuntime, provider: RoutingProvider,
                           prefix: str = "/api/v1/models") -> APIRouter:
    router = APIRouter(prefix=prefix, tags=["models"])

    @router.get("")
    async def model_status() -> dict[str, Any]:
        return {
            "success": True,
            "multi_model": True,
            "policy": runtime.policy(),
            "router": runtime.router.model_dump(),
            "secret_store": runtime.secrets.status(),
            "configured_providers": sorted(item.id for item in runtime.providers.values()
                                           if runtime.configured(item)),
            "providers": runtime.public_providers(),
            "routes": {route: runtime_router_decision(provider, route) for route in ROUTES},
            "available_providers": sorted(item.id for item in runtime.providers.values()
                                          if runtime.configured(item)),
        }

    @router.get("/providers")
    async def list_providers() -> dict[str, Any]:
        return {"providers": runtime.public_providers(), "policy": runtime.policy()}

    @router.post("/providers", status_code=201)
    async def upsert_provider(payload: ProviderIn) -> dict[str, Any]:
        document = payload.model_dump(exclude={"api_key"})
        try:
            item = runtime.upsert(document)
        except ProviderError as error:
            raise _provider_error(error) from None
        except ValueError as error:
            raise HTTPException(422, detail={"error_code": "PROVIDER_INVALID",
                                            "message": str(error)[:300]}) from None
        if payload.api_key:
            runtime.set_api_key(item.id, payload.api_key)
        return {"provider": item.public(configured=runtime.secrets.get_for(item) is not None,
                                        backend=runtime.secrets.backend),
                "api_key_configured": runtime.secrets.get_for(item) is not None}

    @router.delete("/providers/{provider_id}")
    async def delete_provider(provider_id: str) -> dict[str, Any]:
        removed = runtime.remove(provider_id)
        if not removed:
            raise HTTPException(404, detail={"error_code": "PROVIDER_UNKNOWN",
                                            "message": f"unknown provider: {provider_id}"})
        return {"provider": provider_id, "removed": True}

    @router.post("/providers/{provider_id}/key")
    async def set_key(provider_id: str, payload: KeyIn) -> dict[str, Any]:
        try:
            runtime.set_api_key(provider_id, payload.api_key)
        except ProviderError as error:
            raise _provider_error(error) from None
        return {"provider": provider_id, "api_key_configured": True,
                "backend": runtime.secrets.backend}

    @router.delete("/providers/{provider_id}/key")
    async def delete_key(provider_id: str) -> dict[str, Any]:
        return {"provider": provider_id, "removed": runtime.delete_api_key(provider_id),
                "api_key_configured": False}

    @router.post("/providers/{provider_id}/test")
    async def test_provider(provider_id: str) -> dict[str, Any]:
        try:
            return await runtime.test(provider_id)
        except ProviderError as error:
            raise _provider_error(error) from None

    @router.get("/providers/{provider_id}/models")
    async def provider_models(provider_id: str) -> dict[str, Any]:
        item = runtime.providers.get(provider_id)
        if item is None:
            raise HTTPException(404, detail={"error_code": "PROVIDER_UNKNOWN",
                                            "message": f"unknown provider: {provider_id}"})
        try:
            models = await runtime.models(item)
        except ProviderError as error:
            raise _provider_error(error) from None
        return {"provider": provider_id, "models": models}

    @router.patch("/router")
    async def patch_router(payload: RouterIn) -> dict[str, Any]:
        document = runtime.router.model_dump()
        if payload.mode is not None:
            document["mode"] = payload.mode
        if payload.assignments is not None:
            document["assignments"] = payload.assignments
        if payload.fallback_chain is not None:
            document["fallback_chain"] = payload.fallback_chain
        try:
            runtime.router = RouterConfig.model_validate(document)
        except ValueError as error:
            raise HTTPException(422, detail={"error_code": "ROUTER_INVALID",
                                            "message": str(error)[:300]}) from None
        runtime.save()
        return {"router": runtime.router.model_dump(), "mode": runtime.router.mode}

    @router.get("/routes")
    async def routes() -> dict[str, Any]:
        return {"routes": {route: runtime_router_decision(provider, route) for route in ROUTES},
                "modes": list(ROUTING_MODES)}

    @router.post("/route-chat")
    async def route_chat(payload: RouteChatIn) -> dict[str, Any]:
        """Run one message through a route. Real providers only; no fabrication."""
        request = ChatRequest(messages=[{"role": "user", "content": payload.message}],
                              model=payload.model, temperature=payload.temperature)
        response, provider_id, attempts = await provider.router.chat(
            payload.route, request, allow_local_fallback=False)
        return {"provider": provider_id, "model": response.model, "content": response.content,
                "prompt_tokens": response.prompt_tokens,
                "completion_tokens": response.completion_tokens,
                "attempts": attempts}

    return router


def runtime_router_decision(provider: RoutingProvider, route: str) -> dict[str, Any]:
    try:
        return provider.router.resolve(route).public()
    except ProviderError as error:
        return {"route": route, "provider": None, "model": None,
                "reason": error.code, "fallback_chain": []}


__all__ = ["build_model_router_api", "ProviderIn", "KeyIn", "RouterIn", "RouteChatIn"]
