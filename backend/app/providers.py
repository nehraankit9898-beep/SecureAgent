"""Multi-model provider system + model router (provider-neutral).

Architecture::

    LLMProvider (app.llm)            transport contract used by the agent
    ProviderRuntime (this module)    provider registry, credentials, HTTP calls
        ├── OllamaProvider          local, http://127.0.0.1:11434
        ├── OpenAICompatibleProvider OpenAI / Groq / Together / OpenRouter /
        │                           DeepSeek / Qwen / ZAI-GLM / custom endpoint
        ├── AnthropicProvider       /v1/messages
        └── GoogleProvider          Gemini generateContent
    ModelRouter (this module)        route → provider/model + fallback chain

Non-negotiable rules implemented here:

* providers are configuration, not code: the agent core never names a vendor;
* an API key is stored through ``SecretStore`` (OS vault first, encrypted local
  file second) and is NEVER returned to the UI, written to the audit log, put
  in a prompt or included in an error message;
* the router only ever uses providers the user configured AND enabled. If the
  chain is empty it falls back to the deterministic LocalCore path (never a
  silent switch to some other vendor), and an unavailable provider is reported
  as ``NOT_CONFIGURED`` / ``UNREACHABLE`` instead of being faked.
"""
from __future__ import annotations

import base64
import json
import logging
import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Literal
from urllib.parse import urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from app.crypto import decrypt, derive_key, encrypt, load_or_create_key
from app.models import ChatRequest, ChatResponse

logger = logging.getLogger("secureagent.providers")

ProviderKind = Literal["ollama", "openai_compatible", "anthropic", "google",
                       "groq", "together", "openrouter", "deepseek", "qwen", "zai",
                       "custom"]

REMOTE_KINDS = {"openai_compatible", "anthropic", "google", "groq", "together",
                "openrouter", "deepseek", "qwen", "zai", "custom"}
KNOWN_HOSTS = {
    "openai_compatible": "https://api.openai.com/v1",
    "openai": "https://api.openai.com/v1",
    "anthropic": "https://api.anthropic.com",
    "google": "https://generativelanguage.googleapis.com",
    "groq": "https://api.groq.com/openai/v1",
    "together": "https://api.together.xyz/v1",
    "openrouter": "https://openrouter.ai/api/v1",
    "deepseek": "https://api.deepseek.com/v1",
    "qwen": "https://dashscope.aliyuncs.com/compatible-mode/v1",
    "zai": "https://api.z.ai/api/paas/v4",
    "custom": "",
}
ROUTES = ("chat", "planner", "coding", "vision", "security", "reviewer", "embedding", "fast")
ROUTING_MODES = ("auto", "local_first", "cloud_first", "cost_aware", "speed_first",
                 "privacy_first", "manual")
DEFAULT_ROUTING_MODE = "local_first"


class ProviderError(RuntimeError):
    """Structured provider failure. The message never contains a credential."""

    def __init__(self, code: str, message: str = "", recovery: str = ""):
        super().__init__(code if not message else f"{code}: {message}")
        self.code = code
        self.message = message
        self.recovery = recovery

    def payload(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message or self.code,
                "recovery_action": self.recovery}


# --------------------------------------------------------------------------- #
# Configuration (never contains secrets)                                      #
# --------------------------------------------------------------------------- #


class ProviderConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(min_length=1, max_length=48)
    kind: ProviderKind
    label: str = Field("", max_length=120)
    base_url: str = Field("", max_length=500)
    enabled: bool = False
    local: bool = False
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

    @field_validator("id")
    @classmethod
    def valid_id(cls, value: str) -> str:
        import re
        if not re.fullmatch(r"[a-z][a-z0-9_.-]{0,47}", value):
            raise ValueError("provider id must be lowercase letters, digits, '.', '_' or '-'")
        return value

    @field_validator("api_key_env")
    @classmethod
    def valid_env_name(cls, value):
        import re
        if value is None:
            return None
        if not re.fullmatch(r"[A-Z][A-Z0-9_]{0,63}", value):
            raise ValueError("api_key_env must be an upper-case environment variable name")
        return value

    @model_validator(mode="before")
    @classmethod
    def default_ollama_keyless(cls, data):
        """Ollama is a local, keyless daemon unless the user says otherwise."""
        if isinstance(data, dict) and data.get("kind") == "ollama" \
                and "api_key_required" not in data:
            data = {**data, "api_key_required": False}
        return data

    @model_validator(mode="after")
    def resolve_endpoint(self) -> "ProviderConfig":
        if not self.base_url and self.kind in KNOWN_HOSTS:
            self.base_url = KNOWN_HOSTS[self.kind]
        if self.kind == "ollama":
            self.local = True
            if not self.base_url:
                self.base_url = "http://127.0.0.1:11434"
        if not self.base_url:
            raise ValueError("base_url is required for this provider kind")
        parts = urlsplit(self.base_url)
        if parts.scheme not in {"http", "https"} or not parts.hostname:
            raise ValueError("provider base_url must be an http(s) origin")
        if parts.username or parts.password:
            raise ValueError("provider base_url must not embed credentials")
        host = (parts.hostname or "").lower()
        loopback = host in {"localhost", "127.0.0.1", "::1"}
        if not loopback:
            if parts.scheme != "https":
                raise ValueError("remote providers require an https base_url")
            if not self.local:
                self.local = False
        else:
            self.local = True
        return self

    def public(self, *, configured: bool, backend: str | None = None) -> dict[str, Any]:
        """Secret-free view for the API/UI: ``api_key_configured`` is a boolean."""
        payload = self.model_dump()
        payload["api_key_configured"] = bool(configured)
        payload["api_key_backend"] = backend
        payload.pop("api_key_env", None)
        payload["configured"] = bool(configured and self.enabled)
        return payload


class RouterConfig(BaseModel):
    model_config = ConfigDict(extra="forbid")

    mode: Literal["auto", "local_first", "cloud_first", "cost_aware", "speed_first",
                  "privacy_first", "manual"] = "local_first"
    assignments: dict[str, str] = Field(default_factory=dict, max_length=32)
    fallback_chain: list[str] = Field(default_factory=list, max_length=16)

    @field_validator("assignments")
    @classmethod
    def valid_assignments(cls, value: dict[str, str]) -> dict[str, str]:
        for route, target in value.items():
            if route not in ROUTES:
                raise ValueError(f"unknown route: {route}")
            if target and ":" not in target:
                raise ValueError("route assignments use '<provider>:<model>'")
        return value

    @field_validator("fallback_chain")
    @classmethod
    def valid_chain(cls, value: list[str]) -> list[str]:
        cleaned = []
        for item in value:
            identifier = str(item).strip().lower()
            if not identifier:
                continue
            if identifier not in cleaned:
                cleaned.append(identifier)
        return cleaned


# --------------------------------------------------------------------------- #
# Credential storage (OS vault first, encrypted file second)                  #
# --------------------------------------------------------------------------- #


class SecretStore:
    """Per-provider API keys. Raw keys never leave this object."""

    def __init__(self, path: Path, *, key_path: Path | None = None, backend: str | None = None):
        self.path = Path(path)
        self.key_path = Path(key_path) if key_path else self.path.with_suffix(".key")
        self._cache: dict[str, str] = {}
        self._loaded = False
        self.backend = backend or self._detect_backend()
        self._keyring = None
        if self.backend == "keyring":
            try:
                import keyring  # type: ignore
                self._keyring = keyring
            except Exception:
                self.backend = "encrypted-file"

    def _detect_backend(self) -> str:
        try:
            import keyring  # type: ignore
            backend = keyring.get_keyring()
            name = type(backend).__name__.lower()
            if "fail" in name or "null" in name:
                return "encrypted-file"
            return "keyring"
        except Exception:
            return "encrypted-file"

    # -- helpers ----------------------------------------------------------- #
    def _master_key(self) -> bytes:
        key = load_or_create_key(self.key_path)
        salt_file = self.path.with_suffix(".salt")
        if salt_file.exists():
            salt = salt_file.read_bytes()
        else:
            import secrets as _secrets
            salt = _secrets.token_bytes(16)
            salt_file.parent.mkdir(parents=True, exist_ok=True)
            salt_file.write_bytes(salt)
            try:
                salt_file.chmod(0o600)
            except OSError:
                pass
        return derive_key(key, salt, n=2 ** 14)

    def _load(self) -> None:
        if self._loaded:
            return
        self._loaded = True
        if self.backend == "keyring":
            try:
                raw = self._keyring.get_password("secureagent", "providers")
                self._cache = json.loads(raw) if raw else {}
            except Exception:
                self._cache = {}
            return
        try:
            document = json.loads(self.path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self._cache = {}
            return
        key = self._master_key()
        decoded: dict[str, str] = {}
        for provider_id, blob in (document.get("secrets") or {}).items():
            try:
                decoded[str(provider_id)] = decrypt(key, base64.b64decode(blob),
                                                    associated_data=str(provider_id).encode()).decode()
            except Exception:
                logger.warning("stored secret for provider %s could not be decrypted", provider_id)
        self._cache = decoded

    def _persist(self) -> None:
        if self.backend == "keyring":
            try:
                self._keyring.set_password("secureagent", "providers", json.dumps(self._cache))
                return
            except Exception:
                self.backend = "encrypted-file"
        key = self._master_key()
        payload = {"version": 1, "backend": "encrypted-file",
                   "secrets": {provider_id: base64.b64encode(
                       encrypt(key, value.encode(), associated_data=provider_id.encode())).decode()
                       for provider_id, value in self._cache.items()}}
        self.path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.path.with_suffix(".tmp")
        temporary.write_text(json.dumps(payload, indent=2), encoding="utf-8")
        try:
            temporary.chmod(0o600)
        except OSError:
            pass
        os.replace(temporary, self.path)

    # -- public API --------------------------------------------------------- #
    def set(self, provider_id: str, secret: str) -> bool:
        if not isinstance(secret, str) or not secret.strip():
            raise ProviderError("PROVIDER_KEY_INVALID", "an API key must be a non-empty string")
        if len(secret) > 4096:
            raise ProviderError("PROVIDER_KEY_INVALID", "API key is unreasonably long")
        self._load()
        self._cache[provider_id] = secret.strip()
        self._persist()
        return True

    def get(self, provider_id: str) -> str | None:
        self._load()
        value = self._cache.get(provider_id)
        if value:
            return value
        # Environment fallback: an operator may point at an env var name; the
        # value itself is never written to disk by SecureAgent.
        return None

    def get_for(self, config: ProviderConfig) -> str | None:
        stored = self.get(config.id)
        if stored:
            return stored
        if config.api_key_env:
            value = os.environ.get(config.api_key_env)
            return value.strip() if value else None
        return None

    def delete(self, provider_id: str) -> bool:
        self._load()
        existed = self._cache.pop(provider_id, None) is not None
        if existed:
            self._persist()
        return existed

    def contains(self, provider_id: str) -> bool:
        return self.get(provider_id) is not None

    def status(self) -> dict[str, Any]:
        self._load()
        return {"backend": self.backend,
                "stores_os_vault": self.backend == "keyring",
                "file": None if self.backend == "keyring" else str(self.path),
                "providers_with_keys": sorted(self._cache),
                "encrypted": True}

    def public_keys_status(self) -> dict[str, bool]:
        return {provider_id: True for provider_id in self._cache}


# --------------------------------------------------------------------------- #
# Runtime: real provider calls                                                 #
# --------------------------------------------------------------------------- #


class ProviderRuntime:
    def __init__(self, config, *, config_path: Path | None = None, secrets: SecretStore | None = None,
                 transport: httpx.AsyncBaseTransport | None = None, store=None,
                 control_center=None):
        self.config = config
        self.control_center = control_center
        self.config_path = Path(config_path or getattr(config, "providers_config_path",
                                                       Path("data/providers.json")))
        backend = getattr(config, "provider_secret_backend", "auto")
        self.secrets = secrets or SecretStore(
            self.config_path.with_suffix(".secrets"),
            key_path=self.config_path.with_suffix(".key"),
            backend=None if backend in (None, "auto") else backend)
        self.transport = transport
        self.store = store
        self.providers: dict[str, ProviderConfig] = {}
        self.router = RouterConfig()
        self.load()

    # -- gates --------------------------------------------------------------- #
    def _gate(self):
        if self.control_center is not None:
            return self.control_center
        try:
            from app.control_center import get_control_center
            return get_control_center()
        except Exception:
            return None

    def remote_allowed(self) -> bool:
        """Remote providers need Settings AND the Control Center switch.

        The Effective gate is evaluated against THIS runtime's configuration
        (not the process-global Settings), so an application that constructs a
        runtime from an explicit config gets the behaviour it configured while
        the Control Center remains the runtime authority.
        """
        if not bool(getattr(self.config, "remote_providers_enabled", False)):
            return False
        gate = self._gate()
        if gate is None:
            return False
        try:
            return bool(gate.state.ai.remote_providers_enabled) and bool(gate.ai_active())
        except Exception:
            return False

    def policy(self) -> dict[str, Any]:
        gate = self._gate()
        policy = gate.provider_routing() if gate is not None else {}
        return {"remote_providers_allowed": self.remote_allowed(),
                "settings_remote_switch": bool(getattr(self.config,
                                                       "remote_providers_enabled", False)),
                "control_center_remote_switch": bool(policy.get("control_center_remote_switch",
                                                                False)),
                "ai_active": bool(policy.get("ai_active", True)),
                "routing_mode": policy.get("routing_mode", self.router.mode)}


    # -- configuration ------------------------------------------------------ #
    def load(self) -> None:
        try:
            document = json.loads(self.config_path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            self.providers, self.router = {}, RouterConfig()
            return
        providers: dict[str, ProviderConfig] = {}
        for entry in (document.get("providers") or [])[:64]:
            try:
                item = ProviderConfig.model_validate(entry)
            except Exception:
                logger.warning("ignoring invalid provider entry")
                continue
            providers[item.id] = item
        self.providers = providers
        try:
            self.router = RouterConfig.model_validate(document.get("router") or {})
        except Exception:
            self.router = RouterConfig()

    def save(self) -> None:
        document = {"version": 1, "providers": [item.model_dump() for item in self.providers.values()],
                    "router": self.router.model_dump()}
        self.config_path.parent.mkdir(parents=True, exist_ok=True)
        temporary = self.config_path.with_suffix(".tmp")
        temporary.write_text(json.dumps(document, indent=2), encoding="utf-8")
        os.replace(temporary, self.config_path)

    def upsert(self, payload: dict[str, Any]) -> ProviderConfig:
        item = ProviderConfig.model_validate(payload)
        self.providers[item.id] = item
        self.save()
        return item

    def remove(self, provider_id: str) -> bool:
        removed = self.providers.pop(provider_id, None) is not None
        if removed:
            self.secrets.delete(provider_id)
            self.save()
        return removed

    def set_api_key(self, provider_id: str, secret: str) -> bool:
        if provider_id not in self.providers:
            raise ProviderError("PROVIDER_UNKNOWN", f"unknown provider: {provider_id}")
        return self.secrets.set(provider_id, secret)

    def delete_api_key(self, provider_id: str) -> bool:
        return self.secrets.delete(provider_id)

    def configured(self, item: ProviderConfig) -> bool:
        """Enabled + credentialed + permitted by the runtime switches.

        A remote provider is usable only while BOTH the Settings switch and the
        Control Center switch allow egress; a local provider additionally
        respects the Control Center OLLAMA master switch. Fail closed: an
        exception while reading the gates denies the provider.
        """
        if not item.enabled:
            return False
        if item.api_key_required and self.secrets.get_for(item) is None:
            return False
        try:
            gate = self._gate()
            if gate is not None:
                policy = gate.provider_routing()
                if not policy.get("ai_active", True):
                    return False
                if item.local and item.kind == "ollama" and not policy.get("ollama_enabled", True):
                    return False
            if not item.local and not self.remote_allowed():
                return False
        except Exception:
            return False
        return True

    def denial_reason(self, item: ProviderConfig) -> str | None:
        """Honest, secret-free explanation for why a provider cannot be used."""
        if not item.enabled:
            return "PROVIDER_DISABLED"
        if item.api_key_required and self.secrets.get_for(item) is None:
            return "PROVIDER_KEY_MISSING"
        if not item.local:
            if not bool(getattr(self.config, "remote_providers_enabled", False)):
                return "PROVIDER_REMOTE_DISABLED_IN_SETTINGS"
            if not self.remote_allowed():
                return "PROVIDER_REMOTE_DISABLED_BY_CONTROL_CENTER"
        return None

    def public_providers(self) -> list[dict[str, Any]]:
        return [item.public(configured=self.secrets.get_for(item) is not None,
                            backend=self.secrets.backend)
                for item in sorted(self.providers.values(), key=lambda entry: entry.id)]

    def status(self) -> dict[str, Any]:
        return {"providers": self.public_providers(),
                "router": self.router.model_dump(),
                "policy": self.policy(),
                "secret_store": self.secrets.status(),
                "configured_providers": sorted(item.id for item in self.providers.values()
                                               if self.configured(item)),
                "denied": {item.id: self.denial_reason(item) for item in self.providers.values()
                           if not self.configured(item)}}

    def _client(self, item: ProviderConfig) -> httpx.AsyncClient:
        ceiling = float(getattr(self.config, "provider_request_timeout_seconds",
                                item.timeout_seconds))
        return httpx.AsyncClient(base_url=item.base_url.rstrip("/"),
                                 timeout=httpx.Timeout(min(item.timeout_seconds, ceiling)),
                                 follow_redirects=False, trust_env=False,
                                 transport=self.transport,
                                 limits=httpx.Limits(max_connections=8, max_keepalive_connections=4))

    def _headers(self, item: ProviderConfig) -> dict[str, str]:
        secret = self.secrets.get_for(item)
        if item.kind == "anthropic":
            return {"x-api-key": secret or "", "anthropic-version": "2023-06-01"}
        if item.kind == "google":
            return {}
        if secret:
            return {"Authorization": f"Bearer {secret}"}
        return {}

    async def _post(self, item: ProviderConfig, path: str, payload: dict[str, Any],
                    *, params: dict[str, Any] | None = None) -> dict[str, Any]:
        try:
            async with self._client(item) as client:
                response = await client.post(path, json=payload, headers=self._headers(item),
                                             params=params)
        except httpx.TimeoutException:
            raise ProviderError("PROVIDER_TIMEOUT", f"{item.id} did not answer in time",
                                "Check the endpoint and increase the timeout.") from None
        except httpx.HTTPError:
            raise ProviderError("PROVIDER_UNREACHABLE", f"{item.id} is not reachable",
                                "Verify the base URL, network policy and provider status.") from None
        if response.status_code in {401, 403}:
            raise ProviderError("PROVIDER_AUTH_FAILED", f"{item.id} rejected the credential",
                                "Re-enter the API key.")
        if response.status_code == 429:
            raise ProviderError("PROVIDER_RATE_LIMITED", f"{item.id} rate-limited the request",
                                "Retry later or configure a fallback provider.")
        if response.status_code >= 400:
            raise ProviderError("PROVIDER_REQUEST_FAILED",
                                f"{item.id} returned HTTP {response.status_code}",
                                "Check the model name and provider configuration.")
        try:
            body = json.loads(response.content[:_bounded_limit(self.config)])
        except ValueError:
            raise ProviderError("PROVIDER_INVALID_RESPONSE", f"{item.id} returned invalid JSON") from None
        if not isinstance(body, dict):
            raise ProviderError("PROVIDER_INVALID_RESPONSE", f"{item.id} returned an invalid object")
        return body

    async def _get(self, item: ProviderConfig, path: str) -> dict[str, Any]:
        try:
            async with self._client(item) as client:
                response = await client.get(path, headers=self._headers(item))
        except httpx.HTTPError:
            raise ProviderError("PROVIDER_UNREACHABLE", f"{item.id} is not reachable") from None
        if response.status_code >= 400:
            raise ProviderError("PROVIDER_REQUEST_FAILED", f"{item.id} returned HTTP {response.status_code}")
        try:
            body = json.loads(response.content[:_bounded_limit(self.config)])
        except ValueError:
            raise ProviderError("PROVIDER_INVALID_RESPONSE", f"{item.id} returned invalid JSON") from None
        return body if isinstance(body, dict) else {}

    # -- chat ---------------------------------------------------------------- #
    async def chat(self, item: ProviderConfig, request: ChatRequest, *, model: str | None = None) -> ChatResponse:
        if not self.configured(item):
            raise ProviderError("PROVIDER_NOT_CONFIGURED", f"{item.id} is not configured",
                                "Enable the provider and store an API key.")
        chosen = model or item.default_model or (item.models[0] if item.models else None)
        if not chosen:
            raise ProviderError("PROVIDER_MODEL_MISSING", f"{item.id} has no model selected",
                                "Select a model in the Control Center.")
        messages = [message.model_dump(exclude={"user_request"}) for message in request.messages]
        temperature = request.temperature if request.temperature is not None else item.temperature
        if item.kind in {"ollama"}:
            body = await self._post(item, "/api/chat", {
                "model": chosen, "messages": messages, "stream": False,
                "options": {"temperature": temperature, "num_predict": item.max_tokens,
                            "num_ctx": item.context_window}})
            content = (body.get("message") or {}).get("content")
            if not isinstance(content, str) or not content.strip():
                raise ProviderError("PROVIDER_INVALID_RESPONSE", f"{item.id} returned no content")
            return ChatResponse(content=content[: _output_limit(self.config)], model=str(body.get("model") or chosen),
                                prompt_tokens=body.get("prompt_eval_count"),
                                completion_tokens=body.get("eval_count"))
        if item.kind in {"anthropic"}:
            body = await self._post(item, "/v1/messages", {
                "model": chosen, "max_tokens": item.max_tokens, "temperature": temperature,
                "system": next((message["content"] for message in messages
                                if message["role"] == "system"), None),
                "messages": [message for message in messages if message["role"] != "system"]})
            blocks = body.get("content") or []
            text = "".join(str(block.get("text", "")) for block in blocks if isinstance(block, dict))
            if not text.strip():
                raise ProviderError("PROVIDER_INVALID_RESPONSE", f"{item.id} returned no content")
            usage = body.get("usage") or {}
            return ChatResponse(content=text[: _output_limit(self.config)], model=str(body.get("model") or chosen),
                                prompt_tokens=usage.get("input_tokens"),
                                completion_tokens=usage.get("output_tokens"))
        if item.kind == "google":
            body = await self._post(item, f"/v1beta/models/{chosen}:generateContent",
                                    {"contents": [{"role": "user" if message["role"] != "system" else "user",
                                                   "parts": [{"text": message["content"]}]}
                                                  for message in messages],
                                     "generationConfig": {"temperature": temperature,
                                                          "maxOutputTokens": item.max_tokens}},
                                    params={"key": self.secrets.get_for(item) or ""})
            candidates = body.get("candidates") or []
            text = ""
            if candidates and isinstance(candidates[0], dict):
                text = "".join(str(part.get("text", ""))
                               for part in (candidates[0].get("content") or {}).get("parts") or [])
            if not text.strip():
                raise ProviderError("PROVIDER_INVALID_RESPONSE", f"{item.id} returned no content")
            return ChatResponse(content=text[: _output_limit(self.config)], model=chosen)
        # OpenAI-compatible family (OpenAI, Groq, Together, OpenRouter, DeepSeek,
        # Qwen, ZAI/GLM, custom endpoints).
        payload: dict[str, Any] = {"model": chosen, "messages": messages, "stream": False,
                                   "temperature": temperature, "max_tokens": item.max_tokens}
        if request.json_mode:
            payload["response_format"] = {"type": "json_object"}
        body = await self._post(item, "/chat/completions", payload)
        choices = body.get("choices") or []
        content = None
        if choices and isinstance(choices[0], dict):
            content = (choices[0].get("message") or {}).get("content")
        if not isinstance(content, str) or not content.strip():
            raise ProviderError("PROVIDER_INVALID_RESPONSE", f"{item.id} returned no content")
        usage = body.get("usage") or {}
        return ChatResponse(content=content[: _output_limit(self.config)],
                            model=str(body.get("model") or chosen),
                            prompt_tokens=usage.get("prompt_tokens"),
                            completion_tokens=usage.get("completion_tokens"))

    # -- embeddings + models -------------------------------------------------- #
    async def embed(self, item: ProviderConfig, texts: list[str]) -> list[list[float]]:
        if not self.configured(item):
            raise ProviderError("PROVIDER_NOT_CONFIGURED", f"{item.id} is not configured")
        model = item.embedding_model or item.default_model
        if not model:
            raise ProviderError("PROVIDER_MODEL_MISSING", f"{item.id} has no embedding model")
        if item.kind == "ollama":
            body = await self._post(item, "/api/embed", {"model": model, "input": texts})
            vectors = body.get("embeddings")
        elif item.kind == "google":
            body = await self._post(item, f"/v1beta/models/{model}:batchEmbedContents",
                                    {"requests": [{"model": f"models/{model}",
                                                   "content": {"parts": [{"text": text}]}}
                                                  for text in texts]},
                                    params={"key": self.secrets.get_for(item) or ""})
            vectors = [entry.get("values") for entry in body.get("embeddings") or []]
        elif item.kind == "anthropic":
            raise ProviderError("PROVIDER_EMBEDDING_UNSUPPORTED", f"{item.id} has no embeddings API",
                                "Configure an Ollama or OpenAI-compatible embedding provider.")
        else:
            body = await self._post(item, "/embeddings", {"model": model, "input": texts})
            vectors = [entry.get("embedding") for entry in body.get("data") or []]
        if not isinstance(vectors, list) or len(vectors) != len(texts):
            raise ProviderError("PROVIDER_INVALID_RESPONSE", f"{item.id} returned malformed embeddings")
        validated: list[list[float]] = []
        for vector in vectors:
            try:
                numeric = [float(value) for value in vector]
            except (TypeError, ValueError):
                raise ProviderError("PROVIDER_INVALID_RESPONSE", f"{item.id} returned non-numeric embeddings")
            if not numeric:
                raise ProviderError("PROVIDER_INVALID_RESPONSE", f"{item.id} returned an empty embedding")
            validated.append(numeric)
        return validated

    async def models(self, item: ProviderConfig) -> list[str]:
        if item.kind == "ollama":
            body = await self._get(item, "/api/tags")
            return [str(entry.get("name")) for entry in body.get("models") or []
                    if isinstance(entry, dict) and entry.get("name")][:200]
        body = await self._get(item, "/models")
        entries = body.get("data") or body.get("models") or []
        names = [str(entry.get("id") or entry.get("name")) for entry in entries if isinstance(entry, dict)]
        return [name for name in names if name][:200]

    async def test(self, provider_id: str) -> dict[str, Any]:
        """Real connectivity + credential check. NEVER returns the key."""
        item = self.providers.get(provider_id)
        if item is None:
            raise ProviderError("PROVIDER_UNKNOWN", f"unknown provider: {provider_id}")
        result: dict[str, Any] = {"provider": provider_id, "kind": item.kind,
                                  "enabled": item.enabled, "local": item.local,
                                  "api_key_configured": self.secrets.get_for(item) is not None,
                                  "reachable": False, "models": [], "error": None}
        if not item.enabled:
            result["error"] = ProviderError("PROVIDER_DISABLED", f"{item.id} is disabled").payload()
            return result
        if item.api_key_required and self.secrets.get_for(item) is None:
            result["error"] = ProviderError("PROVIDER_KEY_MISSING",
                                            "No API key stored for this provider",
                                            "Store a key in the Control Center.").payload()
            return result
        try:
            result["models"] = await self.models(item)
            result["reachable"] = True
            if item.models and not set(item.models) & set(result["models"]) and result["models"]:
                result["warning"] = "configured model names were not listed by the provider"
        except ProviderError as error:
            result["error"] = error.payload()
        return result

    def snapshot(self) -> dict[str, Any]:
        """Secret-safe runtime view for audit/diagnostics."""
        return {"providers": [{"id": item.id, "kind": item.kind, "enabled": item.enabled,
                               "local": item.local,
                               "configured": self.configured(item)} for item in self.providers.values()],
                "router": self.router.model_dump(),
                "secret_backend": self.secrets.backend}


def _bounded_limit(config) -> int:
    return int(getattr(config, "provider_max_response_bytes",
                       getattr(config, "max_llm_response_bytes", 2_000_000)))


def _output_limit(config) -> int:
    return int(getattr(config, "max_llm_output_chars", 100_000))


# --------------------------------------------------------------------------- #
# Model router                                                                 #
# --------------------------------------------------------------------------- #


@dataclass(frozen=True)
class RouteDecision:
    route: str
    mode: str
    provider_id: str | None
    model: str | None
    reason: str
    chain: tuple[str, ...] = field(default_factory=tuple)

    def public(self) -> dict[str, Any]:
        return {"route": self.route, "mode": self.mode, "provider": self.provider_id,
                "model": self.model, "reason": self.reason, "fallback_chain": list(self.chain)}


class ModelRouter:
    """Route-aware provider selection with an explicit, auditable fallback chain."""

    LOCAL_KINDS = {"ollama"}

    def __init__(self, runtime: ProviderRuntime, config, *, control_center=None):
        self.runtime = runtime
        self.config = config
        self.control_center = control_center
        # Last secret-free attempt record (what was tried and why it failed).
        self.last_attempts: list[dict[str, Any]] = []

    # -- routing state --------------------------------------------------------- #
    def _gate(self):
        if self.control_center is not None:
            return self.control_center
        try:
            from app.control_center import get_control_center
            return get_control_center()
        except Exception:
            return None

    def mode(self) -> str:
        """Routing mode precedence.

        An explicit (non-default) Control Center choice wins — the Control
        Center is the runtime authority. Otherwise the persisted router
        configuration applies; ``local_first`` is the secure shared default.
        """
        gate = self._gate()
        if gate is not None:
            value = getattr(gate.state.ai, "routing_mode", None)
            if value in ROUTING_MODES and value != DEFAULT_ROUTING_MODE:
                return value
        return self.runtime.router.mode

    def fallback_order(self) -> list[str]:
        """User-declared provider order (Control Center wins when non-empty)."""
        gate = self._gate()
        if gate is not None:
            chain = list(getattr(gate.state.ai, "fallback_chain", []) or [])
            if chain:
                return chain
        return list(self.runtime.router.fallback_chain)

    def assignment(self, route: str) -> tuple[str, str] | None:
        gate = self._gate()
        target = None
        if gate is not None:
            target = (getattr(gate.state.ai, "route_models", {}) or {}).get(route)
        target = target or self.runtime.router.assignments.get(route)
        if not target or ":" not in target:
            return None
        provider_id, _, model = target.partition(":")
        return provider_id.strip(), model.strip()

    def _configured(self, item: ProviderConfig) -> bool:
        return self.runtime.configured(item)

    def available(self) -> list[ProviderConfig]:
        return [item for item in self.runtime.providers.values() if self._configured(item)]

    def _ordered(self, mode: str, route: str = "chat") -> list[ProviderConfig]:
        items = self.available()
        explicit = self.fallback_order()
        if explicit:
            rank = {provider_id: index for index, provider_id in enumerate(explicit)}
            declared = sorted((item for item in items if item.id in rank),
                              key=lambda entry: rank[entry.id])
            rest = [item for item in items if item.id not in rank]
        else:
            declared, rest = [], list(items)
        if mode == "privacy_first":
            declared = [item for item in declared if item.kind in self.LOCAL_KINDS]
            rest = [item for item in rest if item.kind in self.LOCAL_KINDS]
            return declared + rest
        if mode == "local_first" or mode == "auto":
            return declared + sorted(rest, key=lambda item: (item.kind not in self.LOCAL_KINDS,))
        if mode in {"cloud_first", "speed_first"}:
            return declared + sorted(rest, key=lambda item: (item.kind in self.LOCAL_KINDS,))
        if mode == "cost_aware":
            return declared + sorted(rest,
                                     key=lambda item: (item.cost_per_1k_input + item.cost_per_1k_output,
                                                       item.kind not in self.LOCAL_KINDS))
        if mode == "manual":
            target = self.assignment(route)
            if target:
                item = self.runtime.providers.get(target[0])
                first = [item] if item is not None and self._configured(item) else []
                return first + [entry for entry in declared + rest if entry.id not in {e.id for e in first}]
            return declared + rest if declared else []
        return declared + rest

    def resolve(self, route: str) -> RouteDecision:
        if route not in ROUTES:
            raise ProviderError("ROUTER_UNKNOWN_ROUTE", f"unknown route: {route}")
        mode = self.mode()
        if mode == "privacy_first" and not any(item.kind in self.LOCAL_KINDS for item in self.available()):
            return RouteDecision(route, mode, None, None,
                                 "no local provider configured for privacy-first routing")
        target = self.assignment(route)
        if target:
            item = self.runtime.providers.get(target[0])
            if item is None or not self._configured(item):
                return RouteDecision(route, mode, None, None,
                                     f"assigned provider '{target[0]}' is not configured",
                                     ())
            chain = [item.id] + [entry.id for entry in self._ordered(mode, route)
                                 if entry.id != item.id]
            return RouteDecision(route, mode, item.id, target[1] or item.default_model,
                                 "explicit route assignment", tuple(chain))
        ordered = self._ordered(mode, route)
        if not ordered:
            return RouteDecision(route, mode, None, None, "no configured provider available", ())
        chain: list[str] = []
        for item in ordered:
            if item.id not in chain:
                chain.append(item.id)
        first = ordered[0]
        model = self._model_for(first, route)
        return RouteDecision(route, mode, first.id, model,
                             f"{mode} routing over {len(chain)} configured provider(s)",
                             tuple(chain))

    @staticmethod
    def _model_for(item: ProviderConfig, route: str) -> str | None:
        if route == "embedding":
            return item.embedding_model or item.default_model or (item.models[0] if item.models else None)
        if route == "vision":
            return item.vision_model or item.default_model or (item.models[0] if item.models else None)
        return item.default_model or (item.models[0] if item.models else None)

    # -- execution -------------------------------------------------------------- #
    async def chat(self, route: str, request: ChatRequest, *,
                   allow_local_fallback: bool = True
                   ) -> tuple[ChatResponse, str, list[dict[str, Any]]]:
        """Run the route's fallback chain. Empty chain → deterministic LocalCore.

        Returns ``(response, provider_id, attempts)``; ``attempts`` lists what was
        tried and why it failed — auditable, secret-free. With
        ``allow_local_fallback=False`` an exhausted chain raises instead, which
        lets a caller run its own final fallback (e.g. the Ollama→LocalCore
        provider) exactly once.
        """
        decision = self.resolve(route)
        attempts: list[dict[str, Any]] = []
        for provider_id in decision.chain:
            item = self.runtime.providers.get(provider_id)
            if item is None or not self._configured(item):
                continue
            try:
                response = await self.runtime.chat(item, request, model=decision.model
                                                   if provider_id == decision.provider_id else None)
                attempts.append({"provider": provider_id, "status": "ok"})
                return response, provider_id, attempts
            except ProviderError as error:
                attempts.append({"provider": provider_id, "status": "failed", **error.payload()})
                logger.warning("provider %s failed: %s", provider_id, error.code)
        self.last_attempts = list(attempts)
        if not allow_local_fallback:
            raise ProviderError("ROUTER_CHAIN_EXHAUSTED",
                                "no configured provider could serve the request",
                                "Fix the provider configuration or the fallback chain.")
        if decision.provider_id is None and not decision.chain:
            from app.llm import LocalCoreProvider
            response = await LocalCoreProvider().chat(request)
            attempts.append({"provider": "local_core", "status": "ok",
                             "reason": decision.reason})
            return response, "LOCAL CORE", attempts
        # Every configured provider failed: fall back to the deterministic core
        # rather than silently switching to an unconfigured vendor.
        from app.llm import LocalCoreProvider
        response = await LocalCoreProvider().chat(request)
        attempts.append({"provider": "local_core", "status": "ok",
                         "reason": "all configured providers failed"})
        return response, "LOCAL CORE", attempts

    async def embed(self, texts: list[str], route: str = "embedding") -> tuple[list[list[float]], str]:
        decision = self.resolve(route)
        for provider_id in decision.chain:
            item = self.runtime.providers.get(provider_id)
            if item is None or not self._configured(item):
                continue
            try:
                return await self.runtime.embed(item, texts), provider_id
            except ProviderError as error:
                logger.warning("embedding provider %s failed: %s", provider_id, error.code)
        raise ProviderError("EMBEDDING_UNAVAILABLE",
                            "no configured embedding provider could serve the request",
                            "Configure an Ollama or OpenAI-compatible embedding provider.")

    def status(self) -> dict[str, Any]:
        routes = {route: self.resolve(route).public() for route in ROUTES}
        return {"mode": self.mode(), "routes": routes,
                "providers": [{"id": item.id, "kind": item.kind, "local": item.local,
                               "configured": self.runtime.configured(item),
                               "models": item.models[:20]} for item in self.runtime.providers.values()],
                "available_providers": [item.id for item in self.available()]}


# --------------------------------------------------------------------------- #
# The provider the agent core sees                                            #
# --------------------------------------------------------------------------- #


class RoutingProvider:
    """Composition of the multi-model router with the legacy provider chain.

    ``app.llm.get_llm()`` returns this object, so every existing caller
    (``Agent``, knowledge/RAG, diagnostics) keeps working unchanged:

    * when the user has configured NO provider, behaviour is byte-for-byte the
      previous one (Ollama when enabled and reachable, otherwise the
      deterministic ``LOCAL CORE``);
    * when providers ARE configured, the route's fallback chain (mode +
      assignments + user order) is tried first, then the legacy chain runs as
      the final fallback — a provider failure never silently switches to an
      unconfigured vendor and never fakes a generative answer;
    * ``status()`` keeps every legacy key and adds a secret-free routing
      section, so the Control Center shows the truth.
    """

    name = "ROUTED"

    def __init__(self, config=None, *, runtime: ProviderRuntime | None = None, legacy=None):
        from app.config import settings as _settings
        from app.llm import FallbackProvider

        self.config = config or _settings()
        self.runtime = runtime or ProviderRuntime(self.config)
        self.router = ModelRouter(self.runtime, self.config)
        self.legacy = legacy if legacy is not None else FallbackProvider()
        self.active = getattr(self.legacy, "active", "LOCAL CORE")
        self.last_attempts: list[dict[str, Any]] = []

    # -- routing -------------------------------------------------------------- #
    @staticmethod
    def _route(request) -> str:
        route = getattr(request, "route", None)
        return route if isinstance(route, str) and route in ROUTES else "chat"

    def _configured(self) -> list[ProviderConfig]:
        return [item for item in self.runtime.providers.values() if self.runtime.configured(item)]

    # -- LLMProvider contract -------------------------------------------------- #
    async def chat(self, request: ChatRequest) -> ChatResponse:
        route = self._route(request)
        decision = self.router.resolve(route)
        if decision.chain:
            try:
                response, provider_id, attempts = await self.router.chat(
                    route, request, allow_local_fallback=False)
            except ProviderError as error:
                attempts = list(self.router.last_attempts) or [
                    {"provider": decision.provider_id, "status": "failed", **error.payload()}]
                attempts.append({"provider": "legacy", "status": "fallback",
                                 "code": error.code})
                provider_id = None
            if provider_id is not None:
                self.last_attempts = attempts
                self.active = provider_id
                return response
            self.last_attempts = attempts
        response = await self.legacy.chat(request)
        self.active = getattr(self.legacy, "active", "LOCAL CORE")
        return response

    async def embed(self, texts: list[str]) -> list[list[float]]:
        decision = self.router.resolve("embedding")
        if decision.chain:
            try:
                vectors, provider_id = await self.router.embed(texts)
            except ProviderError:
                vectors = []
            if vectors:
                self.active = provider_id
                return vectors
        return await self.legacy.embed(texts)

    async def models(self) -> list[str]:
        names: list[str] = []
        for name in await self.legacy.models():
            if name not in names:
                names.append(name)
        for item in self._configured():
            for name in list(item.models) + [item.default_model, item.embedding_model,
                                             item.vision_model]:
                if name and name not in names:
                    names.append(name)
        return names

    async def status(self) -> dict[str, Any]:
        legacy = await self.legacy.status()
        routed = self.router.status()
        return {**legacy,
                "active_provider": self.active,
                "multi_model": {
                    "enabled": True,
                    "mode": routed["mode"],
                    "available_providers": routed["available_providers"],
                    "configured_providers": [item.id for item in self._configured()],
                    "provider_count": len(self.runtime.providers),
                    "remote_allowed": self.runtime.remote_allowed(),
                    "last_attempts": list(self.last_attempts)[-5:],
                },
                "routing": routed["routes"]}

    async def diagnostics(self) -> dict[str, Any]:
        legacy = await self.legacy.diagnostics()
        return {**legacy,
                "providers": self.runtime.public_providers(),
                "routing": {route: self.router.resolve(route).public() for route in ROUTES},
                "provider_policy": self.runtime.policy(),
                "secret_store": self.runtime.secrets.status()}

    async def close(self) -> None:
        try:
            await self.legacy.close()
        except Exception:
            logger.warning("closing legacy provider failed", exc_info=False)
