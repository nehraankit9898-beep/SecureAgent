import asyncio
import json
import re
from abc import ABC
from time import perf_counter
from typing import Any

from pydantic import BaseModel

from app.models import Permission, Reversibility, RiskLevel, ToolDef, ToolResult


class Tool(ABC):
    """Typed tool contract. Metadata is immutable trusted application policy."""

    name: str
    description: str
    category = "general"
    version = "1.0.0"  # Phase 3 metadata: semver of the tool implementation
    risk_level = RiskLevel.LOW
    reversibility = Reversibility.PARTIAL  # Phase 3 metadata: undo characteristics
    input_model: type[BaseModel]
    output_model: type[BaseModel]
    permissions = frozenset({Permission.SAFE})
    timeout_seconds = 20.0
    network_required = False
    sandbox_required = False
    audit_required = True
    idempotent = True
    enabled = True
    requires_approval = False
    disabled_reason = None
    platforms: list[str] | None = None  # None = all platforms

    def definition(self) -> ToolDef:
        required = sorted(self.permissions, key=str)
        return ToolDef(
            name=self.name,
            description=self.description,
            category=self.category,
            version=self.version,
            reversibility=self.reversibility,
            risk_level=self.risk_level,
            required_permissions=required,
            permissions=required,
            input_schema=self.input_model.model_json_schema(),
            output_schema=self.output_model.model_json_schema(),
            timeout_seconds=self.timeout_seconds,
            network_required=self.network_required,
            sandbox_required=self.sandbox_required,
            audit_required=self.audit_required,
            idempotent=self.idempotent,
            enabled=self.enabled,
            requires_approval=self.requires_approval,
            disabled_reason=self.disabled_reason,
            platforms=self.platforms or ["linux", "windows", "macos"],
            platform=self.platforms or ["linux", "windows", "macos"],
        )

    async def invoke(self, args: dict[str, Any]) -> dict[str, Any]:
        """Validated execution hook. Subclasses implement either ``invoke``
        (preferred; receives fully schema-validated arguments with defaults
        applied) or the legacy ``run`` entry point below. The registry always
        calls :meth:`run`, which dispatches to exactly one implementation and
        never recurses."""
        if type(self).run is not Tool.run:
            return await _call_legacy_run(self, args)
        raise NotImplementedError(
            f"{type(self).__name__} must implement 'invoke' or 'run'"
        )

    async def run(self, args: dict[str, Any]) -> dict[str, Any]:
        """Public entry point: apply schema defaults before invoking.

        ``invoke`` implementations may assume every declared input field is
        present (defaults applied). Direct callers of ``run`` therefore get
        the same validated shape as the registry pipeline enforces.

        Backwards compatibility: subclasses (e.g. third-party plugins) that
        still override ``run`` directly are honored as-is instead of recursing.
        """
        if type(self).invoke is not Tool.invoke:
            return await self.invoke(self.input_model.model_validate(args).model_dump())
        return await _call_legacy_run(self, args)


async def _call_legacy_run(tool: "Tool", args: dict[str, Any]) -> dict[str, Any]:
    """Invoke a subclass's legacy ``run`` override without recursion."""
    for klass in type(tool).__mro__:
        if klass is Tool:
            continue
        override = klass.__dict__.get("run")
        if override is not None:
            return await override(tool, args)
    raise NotImplementedError(f"{type(tool).__name__} implements neither run nor invoke")


class Registry:
    """Single fail-closed policy enforcement point for every tool execution."""

    def __init__(self, timeout: float = 120, max_output_bytes: int = 20_000):
        self.tools: dict[str, Tool] = {}
        self.timeout = timeout
        self.max_output_bytes = max_output_bytes

    def add(self, tool: Tool) -> None:
        required=("name","description","input_model","output_model","permissions","risk_level","timeout_seconds","idempotent","audit_required")
        if any(not hasattr(tool,item) for item in required) or not isinstance(tool.name,str) or not tool.name or not isinstance(tool.description,str) or not isinstance(tool.permissions,frozenset) or not isinstance(tool.idempotent,bool) or not isinstance(tool.timeout_seconds,(int,float)) or tool.timeout_seconds<=0:
            raise ValueError("tool security metadata is incomplete")
        # Phase 3: version + reversibility are mandatory first-class metadata.
        if not isinstance(getattr(tool, "version", None), str) or not re.fullmatch(r"\d+\.\d+\.\d+", tool.version):
            raise ValueError("tool security metadata is incomplete")
        if not isinstance(getattr(tool, "reversibility", None), Reversibility):
            raise ValueError("tool security metadata is incomplete")
        if tool.name in self.tools:
            raise ValueError(f"duplicate tool: {tool.name}")
        self.tools[tool.name] = tool

    def definitions(self) -> list[ToolDef]:
        return [tool.definition() for tool in self.tools.values()]

    async def execute(self, name: str, args: dict[str, Any], approved: set[Permission]) -> ToolResult:
        started = perf_counter()
        tool = self.tools.get(name)
        if not tool:
            return ToolResult(name=name, success=False, error="Unknown tool", code="unknown_tool")
        if not tool.enabled:
            return ToolResult(name=name, success=False, error=tool.disabled_reason or "Tool disabled", code="tool_disabled")
        missing = (tool.permissions - {Permission.SAFE}) - approved
        if missing:
            required = ",".join(sorted(permission.value for permission in missing))
            return ToolResult(name=name, success=False, error=f"Permission required: {required}", code="permission_required")
        try:
            validated = tool.input_model.model_validate(args).model_dump()
            timeout = min(self.timeout, tool.timeout_seconds)
            raw = await asyncio.wait_for(tool.run(validated), timeout)
            output = tool.output_model.model_validate(raw).model_dump(mode="json")
            if len(json.dumps(output,separators=(",",":"),ensure_ascii=False).encode("utf-8")) > self.max_output_bytes:
                raise ValueError("tool output exceeds configured byte limit")
            return ToolResult(name=name, success=True, output=output, duration_ms=int((perf_counter() - started) * 1000))
        except asyncio.TimeoutError:
            retryable = tool.idempotent and tool.risk_level == RiskLevel.LOW
            return ToolResult(name=name, success=False, error="Tool timeout", code="timeout", retryable=retryable, duration_ms=int((perf_counter() - started) * 1000))
        except Exception as error:
            # RuntimeError carries structured, static, non-sensitive status codes
            # from tools (NETWORK_RATE_LIMITED, PYTHON_SANDBOX_UNAVAILABLE,
            # TERMINAL_SANDBOX_UNAVAILABLE) and must reach the agent verbatim.
            safe = str(error)[:500] if isinstance(error, (ValueError, PermissionError, FileNotFoundError, TimeoutError, ConnectionError, RuntimeError)) else f"{type(error).__name__}: tool failed"
            code = safe.split(':',1)[0].lower() if safe.startswith(('NETWORK_','PYTHON_','TERMINAL_')) else "tool_failed"
            return ToolResult(name=name, success=False, error=safe, code=code, retryable=isinstance(error, ConnectionError) and tool.idempotent, duration_ms=int((perf_counter() - started) * 1000))
