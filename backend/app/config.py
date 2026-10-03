from functools import lru_cache
from pathlib import Path
from typing import Literal

from pydantic import AnyHttpUrl, Field, field_validator, model_validator
from pydantic import ValidationError
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parents[2]
ENV_FILE = PROJECT_ROOT / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ENV_FILE, env_prefix="SECURE_AGENT_", extra="ignore"
    )

    app_name: str = "SecureAgent"
    api_prefix: str = "/api/v1"
    environment: Literal["development", "test", "production"] = "development"
    # Local development is usable without an unrelated external provider key.
    # Production validation below still requires a strong internal API token.
    auth_required: bool = False
    api_token: str | None = Field(default=None, repr=False)
    allow_unauthenticated_localhost: bool = True
    deployment_mode: Literal["single_user"] = "single_user"

    ollama_base_url: AnyHttpUrl = AnyHttpUrl("http://127.0.0.1:11434")
    ollama_enabled: bool = True
    allow_remote_ollama: bool = False
    ollama_model: str = "llama3.2"
    embedding_model: str = "nomic-embed-text"
    llm_timeout_seconds: float = Field(120, gt=0, le=600)
    max_llm_response_bytes: int = Field(2_000_000, ge=10_000, le=20_000_000)
    max_llm_output_chars: int = Field(100_000, ge=1_000, le=1_000_000)
    max_llm_completion_tokens: int = Field(16_384, ge=128, le=131_072)
    max_embedding_batch: int = Field(128, ge=1, le=512)
    max_embedding_dimension: int = Field(8_192, ge=1, le=65_536)
    max_embedding_values: int = Field(2_000_000, ge=1_000, le=20_000_000)
    max_embedding_input_chars: int = Field(100_000, ge=1_000, le=1_000_000)

    database_path: Path = Path("data/secure_agent.db")
    workspace_root: Path = Path("workspace")
    max_agent_steps: int = Field(8, ge=1, le=20)
    max_agent_depth: int = Field(2, ge=1, le=4)
    max_agent_retries: int = Field(1, ge=0, le=3)
    agent_timeout_seconds: float = Field(180, gt=1, le=900)
    max_tool_calls: int = Field(12, ge=1, le=50)
    tool_timeout_seconds: float = Field(20, gt=0, le=600)
    max_tool_output_chars: int = Field(20_000, ge=1_000, le=100_000)
    agent_enabled: bool = True
    # --- Phase 15: multi-agent architecture --------------------------------- #
    # OFF by default: /orchestrate keeps the stable single-agent ManagerAgent
    # path. When ON, requests that route to specialist workers run through
    # app.multi_agent.MultiAgentManager (bounded depth/runtime/tokens/tool
    # calls/concurrency; reviewer validation before completion). Every action
    # still passes the central Registry/Control Center/approval pipeline.
    multi_agent_enabled: bool = False
    multi_agent_max_tokens: int = Field(500_000, ge=10_000, le=10_000_000)
    multi_agent_max_tool_calls: int = Field(20, ge=1, le=50)
    multi_agent_max_concurrent_workers: int = Field(2, ge=1, le=4)
    # Phase 6 — Observe→Plan→Act→Verify→Recover loop. When enabled, bounded
    # task execution runs through app.computer.loop.ComputerLoop (which reuses
    # the same Registry/permission/Control-Center gates). Disabled by default;
    # flipping it on is an explicit operator decision.
    computer_loop_enabled: bool = False
    # Token budget charged against every completed loop run (estimate-based;
    # real prompt/completion counts are used when the provider reports them).
    max_loop_tokens: int = Field(2_000_000, ge=1_000, le=100_000_000)
    autonomous_mode: bool = False
    tools_enabled: bool = True
    filesystem_tools_enabled: bool = True
    coding_tools_enabled: bool = True
    terminal_tools_enabled: bool = False
    # terminal backend selects the terminal subsystem: 'docker' keeps the
    # original locked-down Docker sandbox terminal; 'linux' enables the
    # Linux-native terminal agent (command policy engine + /bin/bash jail);
    # the master switch terminal_tools_enabled gates both.
    terminal_backend: Literal["docker", "linux"] = "docker"
    terminal_shell: str = "/bin/bash"
    terminal_allowed_paths: list[str] = Field(default_factory=list)
    terminal_command_timeout_seconds: float = Field(30, gt=0, le=600)
    terminal_max_output_bytes: int = Field(200_000, ge=1_000, le=5_000_000)
    terminal_history_limit: int = Field(1_000, ge=10, le=100_000)
    terminal_allow_sudo: bool = False
    security_workflows_enabled: bool = True
    plugins_enabled: bool = False
    memory_enabled: bool = True
    knowledge_enabled: bool = True

    max_read_bytes: int = Field(1_000_000, ge=1_024, le=20_000_000)
    max_write_bytes: int = Field(1_000_000, ge=1_024, le=20_000_000)
    max_edit_file_bytes: int = Field(1_000_000, ge=1_024, le=20_000_000)
    max_replacement_bytes: int = Field(500_000, ge=1, le=10_000_000)
    max_backup_bytes: int = Field(1_000_000, ge=1_024, le=20_000_000)
    max_search_file_bytes: int = Field(512_000, ge=1_024, le=10_000_000)
    max_search_files: int = Field(2_000, ge=10, le=100_000)
    max_search_results: int = Field(500, ge=1, le=5_000)
    max_search_output_bytes: int = Field(200_000, ge=1_000, le=5_000_000)
    max_directory_depth: int = Field(8, ge=1, le=32)
    # Phase 7: workspace-relative paths that policy protects from every
    # mutating filesystem tool unless the explicit PROTECTED-OVERRIDE token
    # is supplied by an approved caller. Reads remain allowed.
    workspace_protected_paths: list[str] = Field(default_factory=lambda: ["memory", "knowledge", ".secureagent-config"])

    max_document_bytes: int = Field(15_000_000, ge=1_000, le=100_000_000)
    max_chunks_per_document: int = Field(2_000, ge=1, le=20_000)
    max_total_documents: int = Field(5_000, ge=1, le=100_000)
    max_chunk_size: int = Field(1_500, ge=200, le=10_000)
    max_retrieval_chunks: int = Field(12, ge=1, le=50)
    max_retrieval_candidates: int = Field(10_000, ge=100, le=100_000)

    python_execution_backend: Literal["disabled", "docker"] = "disabled"
    python_sandbox_image: str | None = None
    python_timeout_seconds: float = Field(5, gt=0, le=30)
    python_memory_mb: int = Field(128, ge=32, le=512)
    python_cpu_limit: float = Field(0.5, gt=0, le=2)
    python_pids_limit: int = Field(32, ge=8, le=128)

    test_sandbox_enabled: bool = False
    test_sandbox_image: str | None = None
    test_timeout_seconds: float = Field(120, gt=1, le=600)
    test_memory_mb: int = Field(512, ge=64, le=4096)
    test_cpu_limit: float = Field(1.0, gt=0, le=4)
    test_pids_limit: int = Field(128, ge=16, le=512)
    test_output_limit: int = Field(100_000, ge=1_000, le=1_000_000)
    test_network: bool = False
    test_max_copy_bytes: int = Field(100_000_000, ge=1_000_000, le=1_000_000_000)
    test_max_copy_files: int = Field(20_000, ge=100, le=200_000)

    enable_network_tools: bool = False
    # Five-tier network model (spec section 9). ``local`` is kept as a
    # backward-compatible alias for ``localhost``.
    network_mode: Literal["disabled", "localhost", "local", "private", "external", "full"] = "disabled"
    searxng_base_url: AnyHttpUrl | None = None
    web_search_enabled: bool = False
    http_requests_enabled: bool = False
    dns_enabled: bool = True
    allow_local_network: bool = False
    allow_private_network: bool = False
    allow_external_network: bool = False
    require_approval_for_external_network: bool = True
    # SSRF defence: block cloud metadata endpoints and link-local addresses
    # even when local/private network is allowed. These are always blocked
    # unless explicitly allowed via the dedicated toggles below.
    block_cloud_metadata: bool = True
    allow_cloud_metadata: bool = False
    # Rate-limit expensive network operations per minute.
    network_rate_limit_per_minute: int = Field(20, ge=1, le=300)
    network_timeout_seconds: float = Field(12, gt=0, le=60)
    network_max_response_bytes: int = Field(1_000_000, ge=10_000, le=5_000_000)
    # --- Computer Agent integration boundary (Phase 1 contracts) ----------- #
    # Master feature flag for the future Computer Agent layer (screen/input/
    # window/browser/voice). It is OFF by default and turning it on performs no
    # OS action by itself: concrete providers do not exist until later phases,
    # and every capability must still pass the existing permission/policy/
    # approval pipeline. computer_agent_physical_input additionally gates
    # mouse/keyboard synthesis and stays fail-closed in this release.
    computer_agent_enabled: bool = False
    computer_agent_physical_input: bool = False
    # --- Phase 4: screen perception (capture / OCR / vision) --------------- #
    # Screenshots are NEVER persisted by default; enabling persistence applies
    # the retention window below and mandatory sensitive-region redaction.
    screen_capture_persist: bool = False
    screen_capture_retention_seconds: int = Field(300, ge=30, le=86_400)
    screen_capture_max_bytes: int = Field(12_000_000, ge=10_000, le=50_000_000)
    # Rectangles in monitor-relative pixels that are masked out BEFORE any
    # storage or logging: {"name": "label", "x": .., "y": .., "width": .., "height": ..}
    screen_sensitive_regions: list[dict[str, int | str]] = Field(default_factory=list)
    # Cloud vision stays off unless explicitly configured AND enabled. Local
    # OCR (tesseract binary) is the local-first default when present.
    vision_cloud_enabled: bool = False
    vision_cloud_endpoint: AnyHttpUrl | None = None
    vision_cloud_api_key: str | None = Field(default=None, repr=False)
    ocr_timeout_seconds: float = Field(20, gt=0, le=120)
    # --- Phase 5: physical input synthesis budgets -------------------------- #
    input_action_rate_per_minute: int = Field(60, ge=1, le=600)
    input_drag_max_distance_px: int = Field(4000, ge=1, le=20_000)
    input_max_text_chars: int = Field(2000, ge=1, le=10_000)
    enable_automation: bool = False
    automation_require_approval: bool = True
    automation_max_concurrent_jobs: int = Field(2, ge=1, le=16)
    automation_max_runtime_seconds: int = Field(300, ge=10, le=3600)
    scheduler_poll_seconds: float = Field(10, ge=1, le=300)
    approval_mode: Literal["all", "high-risk"] = "high-risk"
    require_approval_for_high_risk: bool = True

    # --- Phase 14: MCP & external integrations ------------------------------ #
    # Master kill switch for ALL external integrations (MCP servers and
    # provider connectors). OFF by default: with no configuration nothing in
    # this subsystem loads, registers tools, or touches credentials.
    integrations_enabled: bool = False
    # Optional JSON file describing configured providers/MCP servers. Relative
    # paths resolve against the project root at use time. The file may carry
    # environment-variable NAMES for secrets — never secret values.
    integrations_config_path: Path = Path("data/integrations.json")
    mcp_enabled: bool = False
    # Explicit server allowlist. A server not listed here can never connect,
    # regardless of what the integration config file says. Empty = no server.
    mcp_allowed_servers: list[str] = Field(default_factory=list)
    mcp_connect_timeout_seconds: float = Field(10, gt=0, le=120)
    mcp_call_timeout_seconds: float = Field(30, gt=0, le=300)
    mcp_max_request_bytes: int = Field(65_536, ge=1_024, le=1_000_000)
    mcp_max_response_bytes: int = Field(200_000, ge=1_000, le=2_000_000)
    # Per-server tool-name allowlists; a server without an entry exposes zero
    # tools (fail closed). Applies to stdio and HTTP transports alike.
    mcp_server_tool_allowlists: dict[str, list[str]] = Field(default_factory=dict)
    # Stdio command allowlist: resolved executable path -> allowed arguments
    # (exact match). An empty mapping disables the stdio transport entirely.
    mcp_stdio_allowed_commands: dict[str, list[str]] = Field(default_factory=dict)
    # Remote MCP endpoints must be HTTPS unless allow_local_mcp opens
    # loopback http:// URLs for local development only.
    allow_local_mcp: bool = False
    # When true (default) every connector starts in read-only mode and any
    # mutating call is refused until the operator flips it per provider.
    integrations_default_read_only: bool = True

    max_request_bytes: int = Field(1_000_000, ge=1_024, le=20_000_000)
    rate_limit_window_seconds: int = Field(60, ge=1, le=3_600)
    rate_limit_max_clients: int = Field(10_000, ge=10, le=100_000)
    rate_limit_default: int = Field(120, ge=1, le=5_000)
    rate_limit_auth: int = Field(20, ge=1, le=5_000)
    rate_limit_chat: int = Field(30, ge=1, le=5_000)
    rate_limit_agent: int = Field(30, ge=1, le=5_000)
    rate_limit_tools: int = Field(60, ge=1, le=5_000)
    rate_limit_automation: int = Field(20, ge=1, le=5_000)
    cors_origins: list[str] = ["http://localhost:5173", "http://127.0.0.1:5173"]

    @field_validator('ollama_model','embedding_model')
    @classmethod
    def valid_model_name(cls,value):
        import re
        normalized=value.strip()
        if not re.fullmatch(r'[A-Za-z0-9][A-Za-z0-9._:/-]{0,199}',normalized) or '..' in normalized:
            raise ValueError('invalid Ollama model name')
        return normalized

    @staticmethod
    def _immutable_image(value: str | None) -> bool:
        if not value or "@sha256:" not in value:
            return False
        digest = value.rsplit("@sha256:", 1)[1]
        return len(digest) == 64 and all(char in "0123456789abcdef" for char in digest)

    @model_validator(mode="after")
    def validate_security(self):
        ollama=str(self.ollama_base_url)
        if self.ollama_base_url.username or self.ollama_base_url.password or self.ollama_base_url.query or self.ollama_base_url.fragment:
            raise ValueError('Ollama URL must be an HTTP(S) origin without credentials, query, or fragment')
        host=(self.ollama_base_url.host or '').strip('[]').lower()
        local=host in {'localhost','127.0.0.1','::1'}
        if not local and not self.allow_remote_ollama:
            raise ValueError('remote Ollama requires explicit SECURE_AGENT_ALLOW_REMOTE_OLLAMA=true data-egress approval')
        if not local and self.ollama_base_url.scheme != 'https':
            raise ValueError('remote Ollama requires HTTPS')
        origins=[]
        for origin in self.cors_origins:
            normalized=origin.strip().rstrip('/')
            if normalized in {'*','null'}:
                raise ValueError('wildcard or null CORS origins are forbidden')
            if normalized and normalized not in origins:origins.append(normalized)
        if not origins:raise ValueError('at least one explicit CORS origin is required')
        self.cors_origins=origins
        if self.environment == "production" and not self.auth_required:
            raise ValueError("authentication is mandatory in production")
        if not self.auth_required and not (
            self.environment == "development" and self.allow_unauthenticated_localhost
        ):
            raise ValueError(
                "authentication may be disabled only for explicitly allowed localhost development"
            )
        if not self.auth_required:
            self.api_token = None
        elif (
            not self.api_token
            or len(self.api_token) < 32
            or self.api_token.startswith("replace-")
        ):
            raise ValueError("a non-placeholder API token of at least 32 characters is required")
        if self.python_execution_backend == "docker" and not self._immutable_image(
            self.python_sandbox_image
        ):
            raise ValueError("Python sandbox image must be pinned by sha256 digest")
        if self.test_sandbox_enabled:
            if not self._immutable_image(self.test_sandbox_image):
                raise ValueError("test sandbox image must be pinned by sha256 digest")
            if self.test_network:
                raise ValueError("test sandbox networking cannot be enabled")
        if self.network_mode == "disabled":
            self.enable_network_tools = False
        elif not self.enable_network_tools:
            raise ValueError("network mode requires SECURE_AGENT_ENABLE_NETWORK_TOOLS=true")
        elif self.web_search_enabled and not self.searxng_base_url:
            raise ValueError("enabled web search requires a SearXNG base URL")
        # Five-tier network model (spec section 9). ``local`` is a backward-
        # compatible alias for ``localhost``.
        if self.network_mode in {"localhost", "local"}:
            self.allow_external_network = False
            self.allow_private_network = False
            self.allow_local_network = True
        elif self.network_mode == "private":
            self.allow_external_network = False
            if not (self.allow_local_network or self.allow_private_network):
                self.allow_local_network = True
                self.allow_private_network = True
        elif self.network_mode == "external":
            self.allow_external_network = True
            if not (self.allow_local_network or self.allow_private_network):
                self.allow_local_network = True
                self.allow_private_network = True
        if self.network_mode == "full" and not self.allow_external_network:
            raise ValueError("full network mode requires external network access")
        if not self.enable_network_tools:
            self.web_search_enabled = False
            self.http_requests_enabled = False
        # Cloud metadata endpoints are blocked unless explicitly allowed.
        if self.allow_cloud_metadata:
            self.block_cloud_metadata = False
        if self.require_approval_for_high_risk is False:
            raise ValueError("high-risk approval cannot be disabled")
        # terminal allowed paths must be absolute, existing, non-root directories
        normalized_paths: list[str] = []
        for raw in self.terminal_allowed_paths:
            if not isinstance(raw, str) or not raw.strip():
                raise ValueError("terminal allowed paths must be non-empty strings")
            candidate = Path(raw).expanduser()
            if not candidate.is_absolute():
                raise ValueError(f"terminal allowed path must be absolute: {raw}")
            resolved = str(candidate)
            if resolved == "/" or resolved in normalized_paths:
                continue
            normalized_paths.append(resolved)
        self.terminal_allowed_paths = normalized_paths
        if not self.database_path.is_absolute():
            self.database_path = (PROJECT_ROOT / self.database_path).resolve()
        if not self.workspace_root.is_absolute():
            self.workspace_root = (PROJECT_ROOT / self.workspace_root).resolve()
        return self


@lru_cache
def settings() -> Settings:
    try:
        return Settings()
    except ValidationError as error:
        problems = "; ".join(
            f"{'.'.join(str(part) for part in item['loc'])}: {item['msg']}"
            for item in error.errors(include_url=False)
        )
        raise RuntimeError(
            "CONFIGURATION ERROR: " + problems
            + f". Copy {PROJECT_ROOT / '.env.example'} to {ENV_FILE} and configure the required values."
        ) from None
