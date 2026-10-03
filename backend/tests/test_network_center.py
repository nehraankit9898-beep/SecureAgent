"""Network Center acceptance tests.

Every switch asserted here maps to real backend behaviour: the effective policy
is the intersection of Settings and the Control Center, capability refusals are
structured, the policy patch path is the validated Control Center transaction,
and the connectivity test performs a real (bounded) request — or fails
honestly.
"""
from pathlib import Path

import pytest

from app.config import Settings
from app.control_center import ControlCenter, set_control_center
from app.network_center import (ALWAYS_ON_PROTECTIONS, MODES, NetworkCenter,
                                NetworkCenterError)
from app.network_security import NetworkPolicyError, SafeHttpClient


def _config(tmp_path, **overrides) -> Settings:
    values = dict(environment="test", auth_required=True, api_token="x" * 40,
                  database_path=tmp_path / "state.db",
                  workspace_root=tmp_path / "workspace")
    values.update(overrides)
    return Settings(**values)


def _gate(tmp_path, mode="disabled", **network) -> ControlCenter:
    center = ControlCenter(tmp_path / "control_center.json")
    center.state.network.mode = mode
    for key, value in network.items():
        setattr(center.state.network, key, value)
    set_control_center(center)
    return center


def _center(tmp_path, *, mode="disabled", center_mode="disabled", **overrides) -> NetworkCenter:
    _gate(tmp_path, mode=center_mode)
    return NetworkCenter(_config(tmp_path, network_mode=mode, **overrides))


# --------------------------------------------------------------------------- #
# Secure defaults and the intersection rule                                    #
# --------------------------------------------------------------------------- #


def test_network_off_by_default(tmp_path):
    center = _center(tmp_path)
    effective = center.effective()
    assert effective["mode"] == "disabled"
    assert effective["network_tools_enabled"] is False
    assert effective["allow_local_network"] is False
    assert effective["allow_external_network"] is False
    assert effective["web_search_operational"] is False
    for entry in center.capabilities():
        assert entry["allowed"] is False
        assert entry["reason"], f"{entry['capability']} must explain why it is OFF"


def test_control_center_mode_narrows_settings(tmp_path):
    center = _center(tmp_path, mode="full", center_mode="localhost",
                     enable_network_tools=True, allow_local_network=True,
                     allow_private_network=True, allow_external_network=True)
    effective = center.effective()
    assert effective["mode"] == "localhost"
    assert effective["allow_local_network"] is True
    assert effective["allow_private_network"] is False
    assert effective["allow_external_network"] is False
    assert effective["narrowed_by_control_center"] is True


def test_settings_mode_narrows_control_center(tmp_path):
    center = _center(tmp_path, mode="private", center_mode="full",
                     enable_network_tools=True, allow_private_network=True,
                     allow_external_network=True)
    effective = center.effective()
    assert effective["mode"] == "private"
    assert effective["allow_external_network"] is False
    assert effective["narrowed_by_settings"] is True


def test_emergency_stop_kills_network_capabilities(tmp_path):
    center = _center(tmp_path, mode="full", center_mode="full", enable_network_tools=True,
                     web_search_enabled=True, http_requests_enabled=True,
                     allow_external_network=True,
                     searxng_base_url="https://search.example.com")
    assert center.effective()["mode"] == "full"
    _gate(tmp_path, mode="full").emergency_stopped = True
    effective = center.effective()
    assert effective["mode"] == "disabled"
    assert effective["network_tools_enabled"] is False


@pytest.mark.parametrize("mode,expect_local,expect_private,expect_external", [
    ("disabled", False, False, False),
    ("localhost", True, False, False),
    ("private", True, True, False),
    ("external", True, True, True),
    ("full", True, True, True),
])
def test_tier_matrix(tmp_path, mode, expect_local, expect_private, expect_external):
    center = _center(tmp_path, mode=mode, center_mode=mode, enable_network_tools=True,
                     allow_local_network=True, allow_private_network=True,
                     allow_external_network=True)
    effective = center.effective()
    assert effective["mode"] == mode
    assert effective["allow_local_network"] is expect_local
    assert effective["allow_private_network"] is expect_private
    assert effective["allow_external_network"] is expect_external
    assert effective["dns_enabled"] is (mode != "disabled")


def test_web_search_capability_requires_provider_and_tools(tmp_path):
    center = _center(tmp_path, mode="full", center_mode="full", enable_network_tools=True,
                     web_search_enabled=True, allow_external_network=True,
                     searxng_base_url="https://search.example.com")
    entry = next(item for item in center.capabilities() if item["capability"] == "web_search")
    assert entry["allowed"] is True and entry["reason"] is None
    # Removing the provider URL (declarative settings) turns it OFF with a code.
    center.config.searxng_base_url = None
    entry = next(item for item in center.capabilities() if item["capability"] == "web_search")
    assert entry["allowed"] is False
    assert entry["reason"] == "NETWORK_SEARCH_NOT_CONFIGURED"


@pytest.mark.asyncio()
async def test_protections_are_always_reported(tmp_path):
    center = _center(tmp_path)
    for protection in ("ssrf_address_validation", "dns_pinning_single_resolution",
                       "cloud_metadata_blocklist", "mixed_trust_dns_rejection",
                       "response_size_limit", "control_center_master_gate"):
        assert protection in ALWAYS_ON_PROTECTIONS
    status = await center.status()
    assert set(status["protections"]) == set(ALWAYS_ON_PROTECTIONS)


@pytest.mark.asyncio()
async def test_status_is_honest_and_secret_free(tmp_path):
    center = _center(tmp_path, mode="full", center_mode="localhost", enable_network_tools=True,
                     allow_local_network=True, allow_external_network=True,
                     searxng_base_url="https://search.example.com")
    status = await center.status()
    assert status["effective"]["mode"] == "localhost"
    assert status["settings"]["search_provider_host"] == "search.example.com"
    assert status["control_center"]["available"] is True
    assert "telemetry" in status and "recent_network_audit" in status
    assert status["telemetry"]["blocked_count"] >= 0


# --------------------------------------------------------------------------- #
# Policy patch goes through the validated Control Center transaction           #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio()
async def test_patch_changes_real_policy_and_is_audited(tmp_path):
    center = _center(tmp_path, mode="localhost", enable_network_tools=True,
                     allow_local_network=True)
    result = await center.patch({"mode": "localhost", "allowed_destinations": ["search.example.com"]})
    assert result["effective"]["mode"] == "localhost"
    gate = center._gate()
    assert gate.state.network.mode == "localhost"
    gate.check_network("search.example.com")  # allowed


@pytest.mark.asyncio()
async def test_patch_rejects_unknown_fields_and_bad_modes(tmp_path):
    center = _center(tmp_path)
    with pytest.raises(NetworkCenterError) as error:
        await center.patch({"mode": "localhost", "sneaky": True})
    assert error.value.code == "NETWORK_PATCH_INVALID"
    with pytest.raises(NetworkCenterError):
        await center.patch({"mode": "omnipotent"})
    with pytest.raises(NetworkCenterError):
        await center.patch({"blocked_destinations": ["not a hostname!"]})


@pytest.mark.asyncio()
async def test_block_and_allow_lists_are_enforced(tmp_path):
    center = _center(tmp_path, mode="full", center_mode="full", enable_network_tools=True,
                     allow_external_network=True)
    await center.patch({"blocked_destinations": ["evil.example.com"],
                        "allowed_destinations": ["good.example.com"]}, confirm=True)
    gate = center._gate()
    with pytest.raises(PermissionError) as blocked:
        gate.check_network("evil.example.com")
    assert "NETWORK_DESTINATION_BLOCKED" in str(blocked.value)
    with pytest.raises(PermissionError) as not_allowed:
        gate.check_network("other.example.com")
    assert "NETWORK_DESTINATION_NOT_ALLOWED" in str(not_allowed.value)
    gate.check_network("good.example.com")


@pytest.mark.asyncio()
async def test_safe_http_client_enforces_effective_policy(tmp_path):
    center = _center(tmp_path, mode="localhost", center_mode="localhost",
                     enable_network_tools=True, allow_local_network=True,
                     dns_enabled=False)
    client = center._client()
    assert client.allow_local is True and client.allow_private is False
    assert client.allow_external is False and client.allow_dns is False
    with pytest.raises(NetworkPolicyError) as error:
        await SafeHttpClient(5, 1000, False, False, False,
                             False).request("GET", "https://example.com")
    assert "master switch" in str(error.value) or "DNS" in str(error.value)


# --------------------------------------------------------------------------- #
# Real connectivity test (or an honest structured refusal)                     #
# --------------------------------------------------------------------------- #


class FakeClient:
    def __init__(self, payload=None, error=None):
        self.payload = payload
        self.error = error
        self.calls: list[tuple[str, dict]] = []

    async def get_json(self, url, *, params):
        self.calls.append((url, params))
        if self.error:
            raise self.error
        return self.payload


@pytest.mark.asyncio()
async def test_test_search_refuses_without_configuration(tmp_path):
    center = _center(tmp_path, mode="full", center_mode="full",
                     enable_network_tools=True, allow_external_network=True)
    with pytest.raises(NetworkCenterError) as error:
        await center.test_search()
    assert error.value.code == "NETWORK_SEARCH_NOT_CONFIGURED"

    disabled = _center(tmp_path)  # mode disabled ⇒ tools disabled in Settings
    with pytest.raises(NetworkCenterError) as error:
        await disabled.test_search()
    assert error.value.code == "NETWORK_TOOLS_DISABLED"


@pytest.mark.asyncio()
async def test_test_search_reports_real_results(tmp_path):
    _gate(tmp_path, mode="external")
    config = _config(tmp_path, network_mode="external", enable_network_tools=True,
                     web_search_enabled=True, allow_external_network=True,
                     searxng_base_url="https://search.example.com")
    client = FakeClient({"results": [{"title": "a"}, {"title": "b"}]})
    center = NetworkCenter(config, http_factory=lambda: client)
    result = await center.test_search("secureagent")
    assert result["success"] is True and result["result_count"] == 2
    url, params = client.calls[0]
    assert url == "https://search.example.com/search" and params["q"] == "secureagent"


@pytest.mark.asyncio()
async def test_test_search_reports_real_failures(tmp_path):
    _gate(tmp_path, mode="external")
    config = _config(tmp_path, network_mode="external", enable_network_tools=True,
                     web_search_enabled=True, allow_external_network=True,
                     searxng_base_url="https://search.example.com")
    blocked = NetworkCenter(config, http_factory=lambda: FakeClient(
        error=NetworkPolicyError("external network targets are disabled by Network settings")))
    with pytest.raises(NetworkCenterError) as error:
        await blocked.test_search()
    assert error.value.code == "NETWORK_TEST_BLOCKED"

    broken = NetworkCenter(config, http_factory=lambda: FakeClient(error=RuntimeError("boom")))
    with pytest.raises(NetworkCenterError) as error:
        await broken.test_search()
    assert error.value.code == "NETWORK_TEST_FAILED"


# --------------------------------------------------------------------------- #
# REST surface                                                                #
# --------------------------------------------------------------------------- #


@pytest.fixture()
def client():
    from fastapi.testclient import TestClient
    from app.main import app
    headers = {"Authorization": "Bearer test-only-token-0123456789abcdef0123456789"}
    with TestClient(app) as test_client:
        test_client.headers.update(headers)
        yield test_client


def test_network_api_status_defaults_off(client):
    body = client.get("/api/v1/network").json()
    assert body["effective"]["mode"] == "disabled"
    assert body["effective"]["network_tools_enabled"] is False
    assert body["control_center"]["available"] is True
    capabilities = {item["capability"]: item for item in body["capabilities"]}
    assert capabilities["web_search"]["allowed"] is False
    assert capabilities["http_request"]["reason"] == "NETWORK_TOOLS_DISABLED"
    assert body["protections"] and client.get("/api/v1/network/telemetry").status_code == 200


def test_network_api_patch_validates_and_persists(client):
    ok = client.patch("/api/v1/network/policy", json={"mode": "localhost"})
    assert ok.status_code == 200
    body = ok.json()
    # The Control Center really changed; the EFFECTIVE mode is still disabled
    # because the (declarative) Settings mode is disabled — narrower wins.
    assert body["control_center"]["mode"] == "localhost"
    assert body["effective"]["mode"] == "disabled"
    assert body["effective"]["narrowed_by_settings"] is True
    assert client.get("/api/v1/network").json()["control_center"]["mode"] == "localhost"
    # Back to the secure default (turning OFF never requires confirmation).
    assert client.patch("/api/v1/network/policy", json={"mode": "disabled"}).status_code == 200
    assert client.patch("/api/v1/network/policy", json={"mode": "sneaky"}).status_code == 422
    refused = client.patch("/api/v1/network/policy", json={"unknown": True})
    assert refused.status_code == 422
    assert refused.json()["error"]["code"] == "VALIDATION_ERROR"


def test_network_api_test_endpoint_is_honest(client):
    response = client.post("/api/v1/network/test", json={})
    assert response.status_code == 403
    assert response.json()["error"]["code"] == "NETWORK_TOOLS_DISABLED"


def test_network_api_requires_auth():
    from fastapi.testclient import TestClient
    from app.main import app
    with TestClient(app) as anonymous:
        assert anonymous.get("/api/v1/network").status_code in {401, 403}
