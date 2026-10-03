"""REST surface for the Network Center (runtime policy, capabilities, telemetry).

The API can change exactly three things — mode, allow list, block list — and
every change goes through the Control Center's validated, audited, atomic
update path. Everything else is read-only observability.
"""
from __future__ import annotations

from typing import Any, Literal

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.network_center import NetworkCenter, NetworkCenterError


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class NetworkPolicyIn(_Strict):
    mode: Literal["disabled", "localhost", "private", "external", "full"] | None = None
    allowed_destinations: list[str] | None = Field(None, max_length=64)
    blocked_destinations: list[str] | None = Field(None, max_length=64)
    confirm: bool = False


def network_error_status(code: str) -> int:
    if "UNAVAILABLE" in code:
        return 503
    if "BLOCKED" in code or "DISABLED" in code:
        return 403
    if "REJECTED" in code:
        return 422
    return 400


def _http_error(error: NetworkCenterError) -> HTTPException:
    return HTTPException(network_error_status(error.code),
                         detail={"error_code": error.code,
                                 "message": error.message or error.code,
                                 "details": {"recovery_action": error.recovery}})


def build_network_center_router(center: NetworkCenter,
                                prefix: str = "/api/v1/network") -> APIRouter:
    router = APIRouter(prefix=prefix, tags=["network"])

    @router.get("")
    async def network_status() -> dict[str, Any]:
        return await center.status()

    @router.get("/capabilities")
    async def network_capabilities() -> dict[str, Any]:
        return {"effective": center.effective(), "capabilities": center.capabilities()}

    @router.get("/telemetry")
    async def network_telemetry() -> dict[str, Any]:
        return {"telemetry": center.telemetry()}

    @router.patch("/policy")
    async def patch_network_policy(payload: NetworkPolicyIn) -> dict[str, Any]:
        patch = payload.model_dump(exclude={"confirm"}, exclude_none=True)
        try:
            return await center.patch(patch, actor="user", confirm=payload.confirm)
        except NetworkCenterError as error:
            raise _http_error(error) from None

    # NOTE: GET/POST /api/v1/network/test are handled by main.py's frozen v1
    # route, which delegates to NetworkCenter.test_search (real request).

    return router


__all__ = ["build_network_center_router", "NetworkPolicyIn", "network_error_status"]
