"""Network Center — the single truthful runtime surface for network policy.

Design rule (spec section 9): the effective network policy is the INTERSECTION
of the declarative Settings and the Control Center runtime authority, and every
switch shown in the Network Center maps to a real, enforced behaviour:

* tier (disabled / localhost / private / external / full) → SafeHttpClient's
  ``allow_local``/``allow_private``/``allow_external`` and the Control Center
  network gate consulted on every request;
* allowed/blocked destination lists → the Control Center gate check;
* web search / HTTP requests / DNS toggles → tool enablement and resolution;
* remote model providers, MCP/HTTP integrations and terminal network → their
  own gates, reported here with the exact reason when they are OFF;
* SSRF, DNS pinning, cloud-metadata blocking, redirect/rate/size limits and
  audit logging are always-on protections and are reported as such.

Nothing in this module invents connectivity: ``test_search`` performs a real
bounded request through ``SafeHttpClient`` and reports the real result or the
real structured refusal.
"""
from __future__ import annotations

from typing import Any
from urllib.parse import urlsplit

from app.control_center import ControlModelError, get_control_center
from app.network_security import NetworkPolicyError, SafeHttpClient

MODES = ("disabled", "localhost", "private", "external", "full")
MODE_RANK = {"disabled": 0, "localhost": 1, "local": 1, "private": 2,
             "external": 3, "full": 4}
ALWAYS_ON_PROTECTIONS = (
    "ssrf_address_validation",
    "dns_pinning_single_resolution",
    "cloud_metadata_blocklist",
    "mixed_trust_dns_rejection",
    "redirect_limit",
    "response_size_limit",
    "request_timeout",
    "per_minute_rate_limit",
    "control_center_master_gate",
    "audit_logging",
    "secret_redaction",
)


class NetworkCenterError(RuntimeError):
    def __init__(self, code: str, message: str = "", recovery: str = ""):
        super().__init__(code if not message else f"{code}: {message}")
        self.code = code
        self.message = message
        self.recovery = recovery

    def payload(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message or self.code,
                "recovery_action": self.recovery}


class NetworkCenter:
    def __init__(self, config, *, control_center=None, store=None, http_factory=None):
        self.config = config
        self.control_center = control_center
        self.store = store
        self.http_factory = http_factory

    # -- gates ---------------------------------------------------------------- #
    def _gate(self):
        if self.control_center is not None:
            return self.control_center
        try:
            return get_control_center()
        except Exception:
            return None

    # -- policy views ---------------------------------------------------------- #
    def settings_policy(self) -> dict[str, Any]:
        config = self.config
        return {
            "mode": "localhost" if config.network_mode == "local" else config.network_mode,
            "network_tools_enabled": bool(config.enable_network_tools),
            "web_search_enabled": bool(config.web_search_enabled),
            "http_requests_enabled": bool(config.http_requests_enabled),
            "dns_enabled": bool(config.dns_enabled),
            "allow_local_network": bool(config.allow_local_network),
            "allow_private_network": bool(config.allow_private_network),
            "allow_external_network": bool(config.allow_external_network),
            "require_approval_for_external_network": bool(config.require_approval_for_external_network),
            "search_provider_configured": bool(config.searxng_base_url),
            "search_provider_host": urlsplit(str(config.searxng_base_url)).hostname
            if config.searxng_base_url else None,
            "rate_limit_per_minute": int(config.network_rate_limit_per_minute),
            "timeout_seconds": float(config.network_timeout_seconds),
            "max_response_bytes": int(config.network_max_response_bytes),
            "block_cloud_metadata": bool(config.block_cloud_metadata),
            "remote_model_providers_enabled": bool(getattr(config, "remote_providers_enabled", False)),
        }

    def control_center_policy(self) -> dict[str, Any]:
        gate = self._gate()
        if gate is None:
            return {"available": False, "mode": None, "allowed_destinations": [],
                    "blocked_destinations": []}
        state = gate.state.network
        return {"available": True, "mode": state.mode,
                "allowed_destinations": list(state.allowed_destinations),
                "blocked_destinations": list(state.blocked_destinations),
                "emergency_stopped": bool(gate.emergency_stopped)}

    def effective(self) -> dict[str, Any]:
        """Intersection of Settings and the Control Center (narrower wins)."""
        settings_policy = self.settings_policy()
        center = self.control_center_policy()
        settings_rank = MODE_RANK.get(settings_policy["mode"], 0)
        center_rank = MODE_RANK.get(center["mode"], 0) if center["available"] else 0
        rank = min(settings_rank, center_rank)
        mode = next((name for name in MODES if MODE_RANK[name] == rank), "disabled")
        if center["available"] and center.get("emergency_stopped"):
            mode, rank = "disabled", 0
        return {
            "mode": mode,
            "rank": rank,
            "network_tools_enabled": bool(settings_policy["network_tools_enabled"] and rank > 0),
            "allow_local_network": bool(settings_policy["allow_local_network"] and rank >= 1),
            "allow_private_network": bool(settings_policy["allow_private_network"] and rank >= 2),
            "allow_external_network": bool(settings_policy["allow_external_network"] and rank >= 3),
            "dns_enabled": bool(settings_policy["dns_enabled"] and rank > 0),
            "allowed_destinations": center["allowed_destinations"],
            "blocked_destinations": center["blocked_destinations"],
            "web_search_operational": bool(settings_policy["network_tools_enabled"]
                                           and settings_policy["web_search_enabled"]
                                           and settings_policy["search_provider_configured"]
                                           and rank > 0),
            "narrowed_by_control_center": settings_rank > center_rank,
            "narrowed_by_settings": center_rank > settings_rank,
            "settings_mode": settings_policy["mode"],
            "control_center_mode": center["mode"],
        }

    # -- capabilities ---------------------------------------------------------- #
    def _client(self) -> SafeHttpClient:
        effective = self.effective()
        return SafeHttpClient(self.config.network_timeout_seconds,
                              self.config.network_max_response_bytes,
                              effective["allow_local_network"],
                              effective["allow_private_network"],
                              effective["allow_external_network"],
                              effective["dns_enabled"])

    def _search_url(self) -> str | None:
        if not self.config.searxng_base_url:
            return None
        return str(self.config.searxng_base_url).rstrip("/") + "/search"

    def capabilities(self) -> list[dict[str, Any]]:
        effective = self.effective()
        settings_policy = self.settings_policy()
        gate = self._gate()
        remote = gate.provider_routing() if gate is not None else {}
        entries: list[dict[str, Any]] = []

        def entry(name, allowed, reason=None, **extra):
            entries.append({"capability": name, "allowed": bool(allowed),
                            "reason": None if allowed else reason, **extra})

        mode_off = effective["mode"] == "disabled"
        search_code, search_message, _ = _search_refusal(effective, settings_policy)
        entry("web_search", effective["web_search_operational"], search_code,
              detail={"provider_configured": bool(self.config.searxng_base_url),
                      "reason_detail": search_message})
        entry("http_request", (settings_policy["network_tools_enabled"]
                               and settings_policy["http_requests_enabled"] and not mode_off),
              "NETWORK_TOOLS_DISABLED" if not settings_policy["network_tools_enabled"]
              else "HTTP_REQUESTS_DISABLED" if not settings_policy["http_requests_enabled"]
              else "NETWORK_BLOCKED_BY_CONTROL_CENTER")
        entry("dns", effective["dns_enabled"],
              "DNS_DISABLED" if not settings_policy["dns_enabled"]
              else "NETWORK_RUNTIME_POLICY_UNAVAILABLE" if gate is None
              else "NETWORK_BLOCKED_BY_CONTROL_CENTER")
        entry("remote_model_providers", bool(remote.get("remote_providers_enabled", False)),
              "PROVIDER_REMOTE_DISABLED_IN_SETTINGS"
              if not settings_policy["remote_model_providers_enabled"]
              else "PROVIDER_REMOTE_DISABLED_BY_CONTROL_CENTER")
        entry("mcp_integrations", bool(getattr(self.config, "integrations_enabled", False)
                                       and getattr(self.config, "mcp_enabled", False)
                                       and effective["rank"] > 0),
              "INTEGRATIONS_DISABLED" if not getattr(self.config, "integrations_enabled", False)
              else "MCP_DISABLED")
        terminal_network = bool(gate is not None and gate.state.terminal.allow_network
                                and effective["rank"] > 0)
        entry("terminal_network", terminal_network,
              "TERMINAL_NETWORK_DISABLED" if not (gate is not None
                                                  and gate.state.terminal.allow_network)
              else "NETWORK_BLOCKED_BY_CONTROL_CENTER")
        entry("browser_network", bool(getattr(self.config, "browser_enabled", False)
                                      and effective["rank"] > 0),
              "BROWSER_DISABLED" if not getattr(self.config, "browser_enabled", False)
              else "NETWORK_BLOCKED_BY_CONTROL_CENTER")
        return entries

    # -- status ---------------------------------------------------------------- #
    async def status(self) -> dict[str, Any]:
        gate = self._gate()
        telemetry = gate.telemetry.model_dump() if gate is not None else {}
        audit: list[dict[str, Any]] = []
        if self.store is not None:
            try:
                rows = await self.store.audits(limit=200)
                audit = [row for row in rows
                         if str(row.get("event", "")).startswith("network.")][:20]
            except Exception:
                audit = []
        return {
            "effective": self.effective(),
            "settings": self.settings_policy(),
            "control_center": self.control_center_policy(),
            "capabilities": self.capabilities(),
            "protections": list(ALWAYS_ON_PROTECTIONS),
            "telemetry": telemetry,
            "recent_network_audit": audit,
        }

    # -- control (real, validated, audited) ------------------------------------- #
    async def patch(self, payload: dict[str, Any], *, actor: str = "user",
                    confirm: bool = False) -> dict[str, Any]:
        gate = self._gate()
        if gate is None:
            raise NetworkCenterError("NETWORK_RUNTIME_POLICY_UNAVAILABLE",
                                     "the Control Center is not available",
                                     "Start the backend before changing network policy.")
        allowed_fields = {"mode", "allowed_destinations", "blocked_destinations"}
        unknown = set(payload) - allowed_fields
        if unknown:
            raise NetworkCenterError("NETWORK_PATCH_INVALID",
                                     f"unknown network field(s): {', '.join(sorted(unknown))}",
                                     "Use mode, allowed_destinations or blocked_destinations.")
        if "mode" in payload and payload["mode"] == "disabled":
            # Turning the network OFF is always safe and never needs confirmation.
            confirm = True
        try:
            snapshot = await gate.update({"network": payload}, actor=actor, confirm=confirm)
        except ControlModelError as error:
            raise NetworkCenterError("NETWORK_PATCH_REJECTED", str(error)[:300],
                                     "Adjust the network policy and retry.") from None
        return {"revision": snapshot.get("revision"), "effective": self.effective(),
                "control_center": self.control_center_policy()}

    async def test_search(self, query: str = "SecureAgent connectivity test") -> dict[str, Any]:
        """Real bounded request to the configured search provider. No faking."""
        effective = self.effective()
        if not effective["web_search_operational"]:
            raise NetworkCenterError(*_search_refusal(effective, self.settings_policy()))
        url = self._search_url()
        try:
            client = self.http_factory() if self.http_factory else self._client()
            body = await client.get_json(url, params={"q": query[:200], "format": "json"})
        except NetworkPolicyError as error:
            raise NetworkCenterError("NETWORK_TEST_BLOCKED", str(error)[:300],
                                     str(error)[:300]) from None
        except Exception as error:
            raise NetworkCenterError("NETWORK_TEST_FAILED", type(error).__name__,
                                     "Verify the search provider is running and reachable.") from None
        results = body.get("results")
        return {"success": True, "provider": "SearXNG", "query": query[:200],
                "result_count": len(results) if isinstance(results, list) else 0,
                "mode": effective["mode"]}

    def telemetry(self) -> dict[str, Any]:
        gate = self._gate()
        return gate.telemetry.model_dump() if gate is not None else {}


def _search_refusal(effective: dict[str, Any], settings_policy: dict[str, Any]) -> tuple[str, str, str]:
    if not settings_policy["network_tools_enabled"]:
        return ("NETWORK_TOOLS_DISABLED", "network tools are disabled in Settings",
                "Enable network tools in Settings and apply.")
    if not settings_policy["search_provider_configured"]:
        return ("NETWORK_SEARCH_NOT_CONFIGURED", "no search provider URL is configured",
                "Configure the SearXNG base URL in the Network Center.")
    if effective["mode"] == "disabled":
        return ("NETWORK_BLOCKED_BY_CONTROL_CENTER", "the network is disabled",
                "Turn the Network master switch ON (choose at least localhost mode).")
    if not settings_policy["web_search_enabled"]:
        return ("WEB_SEARCH_DISABLED", "web search is disabled",
                "Enable Web search in the Network Center.")
    return ("NETWORK_TEST_BLOCKED", "the network policy blocked the request",
            "Review the network mode and allow/block lists.")


__all__ = ["NetworkCenter", "NetworkCenterError", "MODES", "MODE_RANK",
           "ALWAYS_ON_PROTECTIONS"]
