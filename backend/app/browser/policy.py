"""Browser policy — the security boundary in front of every browser action.

Everything here is deterministic, config-driven and fail-closed. A browser
tool may only reach the engine after this module has approved the URL, the
action class, the download/upload size and the content that will be shown to
the model.
"""
from __future__ import annotations

import ipaddress
from pathlib import Path
from typing import Any, Iterable
from urllib.parse import urlsplit

from app.network_security import NetworkPolicyError
from app.security import contains_prompt_injection, redact, untrusted_context

# Action classes that need an explicit human approval in addition to the
# ordinary tool approval. A page can never perform these by itself: the model
# must name the class and the caller must present an approval token that the
# API/approval layer issued.
SENSITIVE_ACTIONS = {
    "purchase": "complete a purchase or payment",
    "send_message": "send a message, email or form reply on the user's behalf",
    "submit_form": "submit a form",
    "delete": "delete data or an account resource",
    "account_change": "change account settings",
    "security_change": "change security settings",
    "credential_operation": "create, read or enter credentials",
}
APPROVAL_TOKEN = "APPROVE"

# Named risk classes accepted from callers; anything unknown is refused (a
# typo must never silently downgrade to "not sensitive").
_ACTION_ALIASES = {
    "purchase": "purchase", "buy": "purchase", "payment": "purchase", "checkout": "purchase",
    "send_message": "send_message", "send": "send_message", "message": "send_message",
    "submit": "submit_form", "submit_form": "submit_form", "form_submit": "submit_form",
    "delete": "delete", "remove": "delete",
    "account_change": "account_change", "account": "account_change",
    "security_change": "security_change", "security": "security_change",
    "credential": "credential_operation", "credential_operation": "credential_operation",
    "login": "credential_operation", "sign_in": "credential_operation",
}

# Response headers that must never be surfaced to the model.
_SECRET_HEADERS = {"set-cookie", "cookie", "authorization", "proxy-authorization",
                   "www-authenticate", "x-api-key", "x-auth-token"}


class BrowserPolicyError(ValueError):
    """Structured, secret-safe refusal (the message IS the error code)."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code if not detail else f"{code}: {detail}")
        self.code = code
        self.detail = detail


def _localhost(host: str) -> bool:
    name = host.strip("[]").lower()
    if name in {"localhost", "127.0.0.1", "::1"}:
        return True
    try:
        return ipaddress.ip_address(name).is_loopback
    except ValueError:
        return False


class BrowserPolicy:
    """Config + Control Center driven browser policy."""

    def __init__(self, config, *, control_center=None):
        self.config = config
        self._control_center = control_center

    # -- master gate ---------------------------------------------------------- #
    @property
    def enabled(self) -> bool:
        if not bool(getattr(self.config, "browser_enabled", False)):
            return False
        gate = self._gate()
        if gate is not None:
            if gate.blocked_by_emergency:
                return False
            if not gate.browser_active():
                return False
        return True

    def disabled_reason(self) -> str:
        if not bool(getattr(self.config, "browser_enabled", False)):
            return "BROWSER_DISABLED: Browser automation is disabled in Settings"
        gate = self._gate()
        if gate is not None and gate.blocked_by_emergency:
            return "SECUREAGENT_STOPPED: emergency stop is active — browser actions are disabled"
        if gate is not None and not gate.browser_active():
            return "BROWSER_DISABLED_BY_CONTROL_CENTER: the Browser master switch is OFF"
        return "BROWSER_DISABLED"

    def _gate(self):
        if self._control_center is not None:
            return self._control_center
        try:
            from app.control_center import get_control_center
            return get_control_center()
        except Exception:
            return None

    def check_enabled(self) -> None:
        if not self.enabled:
            raise BrowserPolicyError(self.disabled_reason())

    # -- URL / network policy -------------------------------------------------- #
    async def validate_url(self, url: str, *, allow_schemes: Iterable[str] = ("http", "https")) -> str:
        """Validate a navigation target through the SAME SSRF/network layer as
        the other network tools (DNS pinning, metadata blocklist, Control
        Center allow/block lists, mode). Raises ``BrowserPolicyError``."""
        self.check_enabled()
        if not isinstance(url, str) or not url.strip() or len(url) > 2000:
            raise BrowserPolicyError("BROWSER_INVALID_URL: url must be 1-2000 characters")
        candidate = url.strip()
        parts = urlsplit(candidate)
        if parts.scheme.lower() not in set(allow_schemes):
            raise BrowserPolicyError("BROWSER_SCHEME_BLOCKED: only http(s) navigation is allowed")
        if parts.username or parts.password:
            raise BrowserPolicyError("BROWSER_CREDENTIALS_IN_URL: URLs with embedded credentials are refused")
        host = parts.hostname or ""
        if not host:
            raise BrowserPolicyError("BROWSER_INVALID_URL: url has no host")
        allowed = [str(item).strip().lower() for item in getattr(self.config, "browser_allowed_domains", []) or []]
        if allowed and not any(host.lower() == item or host.lower().endswith("." + item)
                               for item in allowed if item):
            raise BrowserPolicyError("BROWSER_DOMAIN_NOT_ALLOWED: destination is not in browser_allowed_domains")
        gate = self._gate()
        if gate is not None:
            try:
                # Same allow/block lists, telemetry and emergency-stop gate the
                # HTTP tools use; a blocked destination fails here.
                gate.check_network(host)
            except PermissionError as error:
                raise BrowserPolicyError(str(error)) from None
        from app.network_security import validate_url as ssrf_validate
        try:
            await ssrf_validate(
                candidate,
                allow_local=bool(getattr(self.config, "allow_local_network", False)),
                allow_private=bool(getattr(self.config, "allow_private_network", False)),
                allow_external=bool(getattr(self.config, "allow_external_network", False)),
                allow_dns=bool(getattr(self.config, "dns_enabled", True)),
            )
        except NetworkPolicyError as error:
            raise BrowserPolicyError("BROWSER_URL_BLOCKED", str(error)) from None
        return candidate

    # -- action policy --------------------------------------------------------- #
    def classify_action(self, action: str | None) -> str | None:
        if action is None:
            return None
        key = str(action).strip().lower()
        if not key:
            return None
        if key not in _ACTION_ALIASES:
            raise BrowserPolicyError(
                "BROWSER_INVALID_ACTION: unknown action class "
                f"(allowed: {', '.join(sorted(SENSITIVE_ACTIONS))})")
        return _ACTION_ALIASES[key]

    def check_action(self, action: str | None, approval: str | None) -> str | None:
        """Validate a sensitive-action declaration.

        Returns the normalized class (or ``None``). Fail-closed rules:
        * an unknown class is refused outright;
        * a sensitive class requires ``approval == 'APPROVE'`` AND the Control
          Center must not have switched approvals off (they are mandatory);
        * when sensitive-action approval is disabled by configuration, sensitive
          actions are BLOCKED rather than silently allowed.
        """
        normalized = self.classify_action(action)
        if normalized is None:
            return None
        if not bool(getattr(self.config, "browser_sensitive_actions_require_approval", True)):
            raise BrowserPolicyError(
                "BROWSER_SENSITIVE_ACTION_BLOCKED: sensitive actions are disabled by configuration")
        if str(approval or "").strip().upper() != APPROVAL_TOKEN:
            raise BrowserPolicyError(
                f"BROWSER_APPROVAL_REQUIRED: '{normalized}' requires explicit user approval "
                f"(resend with approval='{APPROVAL_TOKEN}' after the user approves)")
        gate = self._gate()
        if gate is not None:
            if gate.blocked_by_emergency:
                raise BrowserPolicyError("SECUREAGENT_STOPPED: emergency stop is active")
            if not gate.state.security.approval_system:
                raise BrowserPolicyError("BROWSER_APPROVAL_REQUIRED: the approval system is mandatory")
        return normalized

    # -- downloads / uploads ---------------------------------------------------- #
    def downloads_allowed(self) -> bool:
        """Downloads need BOTH the Settings switch and the Control Center switch."""
        if not bool(getattr(self.config, "browser_allow_downloads", False)):
            return False
        gate = self._gate()
        if gate is not None and not bool(gate.state.browser.downloads):
            return False
        return True

    def uploads_allowed(self) -> bool:
        if not bool(getattr(self.config, "browser_allow_uploads", False)):
            return False
        gate = self._gate()
        if gate is not None and not bool(gate.state.browser.uploads):
            return False
        return True

    def check_download(self, size_bytes: int) -> None:
        if not self.downloads_allowed():
            raise BrowserPolicyError("BROWSER_DOWNLOADS_DISABLED: downloads are disabled")
        limit = int(getattr(self.config, "browser_max_download_bytes", 5_000_000))
        if int(size_bytes) > limit:
            raise BrowserPolicyError("BROWSER_DOWNLOAD_TOO_LARGE", f"limit is {limit} bytes")

    def resolve_upload_path(self, relative: str) -> Path:
        """Uploads may only read inside the workspace root (never host paths)."""
        if not self.uploads_allowed():
            raise BrowserPolicyError("BROWSER_UPLOADS_DISABLED: uploads are disabled")
        root = Path(self.config.workspace_root).resolve()
        if not isinstance(relative, str) or not relative.strip():
            raise BrowserPolicyError("BROWSER_INVALID_UPLOAD_PATH")
        candidate = (root / relative.strip()).resolve()
        if candidate != root and root not in candidate.parents:
            raise BrowserPolicyError("BROWSER_UPLOAD_OUTSIDE_WORKSPACE: uploads stay inside the workspace")
        if not candidate.is_file():
            raise BrowserPolicyError("BROWSER_UPLOAD_NOT_FOUND")
        limit = int(getattr(self.config, "browser_max_upload_bytes", 2_000_000))
        if candidate.stat().st_size > limit:
            raise BrowserPolicyError("BROWSER_UPLOAD_TOO_LARGE", f"limit is {limit} bytes")
        return candidate

    # -- observation handling ---------------------------------------------------- #
    def observe(self, text: str, *, label: str = "webpage") -> tuple[str, bool]:
        """Wrap page-derived text as untrusted data and flag injection attempts."""
        content = redact(text if isinstance(text, str) else str(text))
        suspected = contains_prompt_injection(content)
        return untrusted_context(label, content), suspected

    def safe_metadata(self, headers: dict[str, Any] | None) -> dict[str, str]:
        """Strip credential-bearing response headers before anything is stored."""
        safe: dict[str, str] = {}
        for key, value in (headers or {}).items():
            name = str(key).strip().lower()
            if name in _SECRET_HEADERS:
                continue
            safe[name[:64]] = redact(str(value))[:500]
        return safe


# Button/link labels that imply a sensitive action. This is DEFENSE IN DEPTH:
# even when the caller declares no action class, clicking an element whose
# accessible label matches one of these patterns requires the corresponding
# approval. The model cannot talk its way past this — the label comes from the
# page, not from the model.
_SENSITIVE_LABEL_PATTERNS: tuple[tuple[str, str], ...] = (
    (r"\b(buy|purchase|checkout|pay( now)?|place order|subscribe|upgrade|donate|transfer|withdraw)\b", "purchase"),
    (r"\b(send|send message|send email|reply|post comment|publish|share)\b", "send_message"),
    (r"\b(submit|confirm order|place bid|apply now|save changes)\b", "submit_form"),
    (r"\b(delete|remove|unsubscribe|terminate|cancel account|close account|deactivate|wipe)\b", "delete"),
    (r"\b(account settings|profile settings|change plan|billing|payment method)\b", "account_change"),
    (r"\b(security settings|two-factor|2fa|change password|reset password|revoke|api keys?|permissions)\b", "security_change"),
    (r"\b(log ?in|sign ?in|log ?out|sign ?out|password|passcode|otp|verification code)\b", "credential_operation"),
)


def _classify_label(label: str) -> str | None:
    import re as _re
    text = (label or "").strip().lower()
    if not text:
        return None
    for pattern, action in _SENSITIVE_LABEL_PATTERNS:
        if _re.search(pattern, text):
            return action
    return None


# Attach to BrowserPolicy (kept as a free function so it is unit-testable
# without constructing a policy object).
def classify_target_label(self, label: str) -> str | None:
    return _classify_label(label)


BrowserPolicy.classify_target_label = classify_target_label  # type: ignore[attr-defined]
