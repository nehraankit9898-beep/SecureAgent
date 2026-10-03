import asyncio
import json
import logging
from datetime import UTC, datetime
from time import perf_counter
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException, Query, Request
from fastapi.exceptions import RequestValidationError
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse
from fastapi.staticfiles import StaticFiles
from app.models import Permission

from app.agent import Agent
from app.automation import AutomationEngine
from app.config import settings
from app.control_center import ControlCenter, ControlModelError, MANDATORY_PROTECTIONS, set_control_center, get_control_center
from app.execution_registry import ExecutionRegistry
from app.knowledge import KnowledgeStore
from app.llm import LLMError, close_llm, get_llm
from app.network_security import NetworkPolicyError, SafeHttpClient
from app.browser.api import build_browser_router
from app.browser.policy import BrowserPolicyError
from app.browser.runtime import BrowserRuntime, set_browser_runtime
from app.voice.api import build_voice_router
from app.voice.pipeline import VoiceError, VoicePipeline
from app.memory import MemoryStore
from app.memory_service import MemoryService
from app.models import AgentRequest, AuditClearIn, AutomationActionIn, ChatRequest, DocumentIn, DocumentSearch, ExecutionResponse, FilesystemPathIn, GrantIn, MemoryIn, MemoryItem, MemoryPatch, PermissionActionIn, PresetIn, ResumeRequest, ScheduleCreate, SchedulePatch, StepStatus, Task, TaskStatus, TerminalExecuteIn, ToolDef, ToolPatchIn
from app.orchestration import Orchestrator, execution_response
from app.security import InMemoryRateLimiter, RequestSizeLimitMiddleware, configure_logging, token_matches, new_request_id, request_id_var
from app.tools.factory import registry

config = settings()
API_CONTRACT_VERSION = "1.0.0"
logger = logging.getLogger("secureagent.http")
store = MemoryStore(config.database_path)
memory_service = MemoryService(store)
# --- Control Center: the backend runtime authority (spec sections 2-27) ---- #
# The desktop UI is only a control panel; this object owns the real switches.
control_center = ControlCenter(config.database_path.parent / "control_center.json", store)
set_control_center(control_center)
# --- Phase 09 browser runtime (engine starts lazily on first session) ------ #
browser_runtime = BrowserRuntime(config, store=store, control_center=control_center)
set_browser_runtime(browser_runtime)


async def _emergency_close_browser_sessions():
    """EMERGENCY STOP: close every browser context (cookies/storage dropped)."""
    return {"closed_sessions": await browser_runtime.close_all()}


# --- Phase 11 voice pipeline (push-to-talk; OFF by default) ---------------- #
async def _voice_agent_runner(request: AgentRequest):
    """Execute a transcript through the SAME Orchestrator used for typed chat."""
    gate = get_control_center()
    if gate is not None and not gate.agent_active():
        task = Task(goal=request.message)
        task.status = TaskStatus.FAILED
        task.errors.append("AGENT_DISABLED_BY_CONTROL_CENTER: the AI Agent master switch is OFF")
        return execution_response(task, "LOCAL CORE", roles=["manager", "voice"], review_approved=False)
    try:
        return await asyncio.wait_for(Orchestrator(await agent()).run(request),
                                      config.agent_timeout_seconds)
    except asyncio.TimeoutError:
        task = Task(goal=request.message)
        task.status = TaskStatus.FAILED
        task.errors.append("VOICE_TASK_TIMEOUT: the agent did not finish in time")
        return execution_response(task, "LOCAL CORE", roles=["manager", "voice"], review_approved=False)


voice_pipeline = VoicePipeline(config, runner=_voice_agent_runner, store=store,
                              control_center=control_center)


limiter = InMemoryRateLimiter({'default':config.rate_limit_default,'auth':config.rate_limit_auth,'chat':config.rate_limit_chat,'agent':config.rate_limit_agent,'tools':config.rate_limit_tools,'automation':config.rate_limit_automation},config.rate_limit_window_seconds,config.rate_limit_max_clients)
automation: AutomationEngine | None = None
session_approvals: dict[str, set] = {}
# Session-scope approvals must not silently become lifetime grants. Each
# conversation's grant carries a sliding expiry: it is refreshed whenever the
# user grants more permissions for that conversation and is dropped after
# SESSION_APPROVAL_TTL_SECONDS without new activity.
SESSION_APPROVAL_TTL_SECONDS = 30 * 60
session_approval_activity: dict[str, float] = {}
executions = ExecutionRegistry()

# --- Linux terminal agent + deterministic security engine (singletons) ------ #
from app.linux_terminal import LinuxTerminalExecutor
from app.security_engine import SecurityEngine, WORKFLOWS
from app.linux_detect import detect_environment

terminal_executor: LinuxTerminalExecutor | None = None
if config.terminal_backend == "linux":
    terminal_executor = LinuxTerminalExecutor(config)
security_engine = SecurityEngine(terminal_executor, store, config)


def _terminal_enabled() -> bool:
    gate = get_control_center()
    runtime_allowed = gate is None or (not gate.blocked_by_emergency and gate.state.terminal.enabled)
    return bool(config.terminal_tools_enabled and runtime_allowed and terminal_executor and terminal_executor.available)


# --- EMERGENCY STOP kill switches (registered in the lifespan) ------------- #

async def _emergency_kill_terminal():
    """Kill every running terminal process group and force the safe mode."""
    if not terminal_executor:
        return {"killed_executions": [], "mode": "unavailable"}
    return terminal_executor.kill_all_running()


async def _emergency_cancel_agent_tasks():
    """Cancel every live agent task (asyncio cancellation propagates)."""
    active = executions.active_ids()
    cancelled = []
    for task_id in active:
        if await executions.request_cancel(task_id):
            cancelled.append(task_id)
    return {"cancelled_tasks": cancelled}


async def _emergency_cancel_automation():
    """Cancel all running automation jobs (pause is persisted separately)."""
    if automation:
        return await automation.cancel_all()
    return {"cancelled_jobs": []}


async def _persist_terminal_event(execution) -> None:
    """Persist a redacted terminal execution summary (audit trail)."""
    if execution.status == "running":
        return  # persist once, on completion
    try:
        snap = execution.snapshot(config.terminal_max_output_bytes)
        await store.save_terminal_execution({
            "id": execution.id,
            "task_id": None,
            "session_id": None,
            "command": execution.command,
            "cwd": execution.cwd,
            "risk": execution.risk,
            "approval": execution.approval,
            "exit_code": execution.exit_code,
            "status": execution.status,
            "duration_ms": execution.duration_ms,
            "stdout": snap["stdout"],
            "stderr": snap["stderr"],
            "truncated": snap["truncated"],
            "history_limit": config.terminal_history_limit,
        })
    except Exception:  # persistence must never break execution
        logger.exception("terminal history persistence failed")


def prune_session_approvals() -> None:
    """Drop expired session-scope approval grants (sliding 30 minute window)."""
    now = perf_counter()
    stale = [conversation for conversation, seen in session_approval_activity.items() if now - seen > SESSION_APPROVAL_TTL_SECONDS]
    for conversation in stale:
        session_approval_activity.pop(conversation, None)
        session_approvals.pop(conversation, None)


async def agent() -> Agent:
    prune_session_approvals()
    persistent = set()
    try:
        persistent = {Permission(value) for value in await store.active_grant_permissions()}
    except Exception:
        logger.exception("persistent grant load failed")
    return Agent(get_llm(), registry(), store, session_approvals=session_approvals, execution_registry=executions, persistent_permissions=persistent)


@asynccontextmanager
async def life(app):
    global automation
    configure_logging()
    config.workspace_root.mkdir(parents=True, exist_ok=True)
    await store.init()
    if terminal_executor:
        def _terminal_event_sink(execution):
            # Resolve the running loop lazily: the lifespan loop may differ
            # from the loop serving later requests (TestClient, restarts).
            try:
                asyncio.get_running_loop().create_task(_persist_terminal_event(execution))
            except RuntimeError:
                pass
        terminal_executor.on_event = _terminal_event_sink
    automation = AutomationEngine(store, agent, config.scheduler_poll_seconds, config.automation_max_concurrent_jobs, config.automation_max_runtime_seconds)
    # The automation worker always runs; the Control Center AUTOMATION gate
    # inside the loop decides whether schedules may actually execute, so
    # flipping the master switch takes effect immediately without a restart.
    automation.start()
    # EMERGENCY STOP kill switches: real running work must terminate.
    control_center.register_kill_switch("terminal", _emergency_kill_terminal)
    control_center.register_kill_switch("agent_tasks", _emergency_cancel_agent_tasks)
    control_center.register_kill_switch("automation", _emergency_cancel_automation)
    control_center.register_kill_switch("browser", _emergency_close_browser_sessions)
    if control_center.recovery:
        await store.audit("control.recovered", control_center.recovery, actor="control-center")
    await store.audit("control.loaded", {
        "revision": control_center.revision,
        "secure_mode": control_center.state.secure_mode,
        "file": str(control_center.state_file),
    }, actor="control-center")
    yield
    await control_center.on_backend_exit()
    if automation:
        await automation.close()
    await browser_runtime.stop()
    await voice_pipeline.stop()
    await close_llm()


app = FastAPI(title=config.app_name, version="2.0.0", lifespan=life)
app.add_middleware(CORSMiddleware, allow_origins=config.cors_origins, allow_credentials=True, allow_methods=["GET","POST","PATCH","DELETE","OPTIONS"], allow_headers=["Authorization","Content-Type","X-Request-ID","X-API-Token"])
app.add_middleware(RequestSizeLimitMiddleware, max_bytes=config.max_request_bytes)


@app.exception_handler(LLMError)
async def llm_error_handler(request: Request, error: LLMError):
    status = 504 if error.code == "OLLAMA_TIMEOUT" else 502 if error.code == "OLLAMA_INVALID_RESPONSE" else 503
    return JSONResponse({"success":False,"error":{"code":error.code,"message":error.message,"details":{"component":error.component,"recovery_action":error.recovery_action}},"request_id":request_id_var.get()}, status_code=status)


@app.exception_handler(NetworkPolicyError)
async def network_error_handler(request: Request, error: NetworkPolicyError):
    return JSONResponse({"success":False,"error":{"code":error.code,"message":str(error),"details":{"component":"network","recovery_action":"Review Network settings and trusted endpoint policy."}},"request_id":request_id_var.get()}, status_code=403)

@app.exception_handler(BrowserPolicyError)
async def browser_policy_handler(request: Request, error: BrowserPolicyError):
    """Structured, secret-safe browser refusal (approval, policy, engine)."""
    approval = "APPROVAL_REQUIRED" in error.code or "APPROVAL_REQUIRED" in str(error)
    status = 403 if not approval else 409
    return JSONResponse({"success": False, "error": {
        "code": error.code,
        "message": str(error)[:500],
        "details": {"component": "browser",
                    "recovery_action": ("Approve the action in the Control Center and resend with "
                                        "approval='APPROVE'." if approval else
                                        "Review browser/network policy settings.")}},
        "request_id": request_id_var.get()}, status_code=status)


@app.exception_handler(VoiceError)
async def voice_error_handler(request: Request, error: VoiceError):
    approval = "APPROVAL" in error.code
    return JSONResponse({"success": False, "error": {
        "code": error.code,
        "message": str(error)[:500],
        "details": {"component": "voice",
                    "recovery_action": ("Approve the pending task in the Control Center." if approval
                                        else "Enable voice / configure a local STT/TTS provider.")}},
        "request_id": request_id_var.get()}, status_code=409 if approval else 403)


@app.exception_handler(RequestValidationError)
async def validation_error_handler(request: Request, error: RequestValidationError):
    return JSONResponse({"success":False,"error":{"code":"VALIDATION_ERROR","message":"Request validation failed.","details":{"fields":[{"location":".".join(str(part) for part in item['loc']),"message":item['msg']} for item in error.errors()]}},"request_id":request_id_var.get()},status_code=422)

@app.exception_handler(HTTPException)
async def http_error_handler(request: Request, error: HTTPException):
    detail=error.detail
    if isinstance(detail,dict):code=str(detail.get('error_code') or detail.get('code') or 'REQUEST_FAILED');message=str(detail.get('message') or 'Request failed.');details=detail.get('details') or {}
    else:
        text=str(detail);prefix,separator,message=text.partition(':');code=prefix if separator and prefix.replace('_','').isalnum() else f'HTTP_{error.status_code}';message=message.strip() if separator else text;details={}
    return JSONResponse({"success":False,"error":{"code":code,"message":message,"details":details},"request_id":request_id_var.get()},status_code=error.status_code,headers=error.headers)


@app.exception_handler(Exception)
async def unexpected_error_handler(request: Request, error: Exception):
    logger.exception("unhandled request error path=%s", request.url.path)
    return JSONResponse({"success":False,"error":{"code":"INTERNAL_ERROR","message":"The request could not be completed.","details":{}},"request_id":request_id_var.get()}, status_code=500)


@app.middleware("http")
async def security_middleware(request: Request, call_next):
    request_id=new_request_id(request.headers.get("x-request-id"));context=request_id_var.set(request_id)
    started = perf_counter()
    response = None
    try:
        path=request.url.path;public={"/health",config.api_prefix+"/health",config.api_prefix+"/auth/status"}
        client=request.client.host if request.client else "unknown"
        group="auth" if path.endswith("/auth/status") else "chat" if "/chat" in path else "agent" if "/agent/" in path or "/orchestrate" in path else "tools" if "/tools" in path or "/terminal/" in path or "/workflows" in path else "automation" if "/schedule" in path else "default"
        if not limiter.allow(client,group):response=JSONResponse({"success":False,"error":{"code":"RATE_LIMITED","message":"Too many requests.","details":{}},"request_id":request_id},status_code=429,headers={"Retry-After":str(config.rate_limit_window_seconds)})
        else:
            local=request.client and request.client.host in {"127.0.0.1","::1"};bypass=config.environment=="development" and not config.auth_required and config.allow_unauthenticated_localhost and local
            supplied=request.headers.get("authorization","")
            if supplied:
                scheme,separator,value=supplied.partition(" ");token=value.strip() if separator and scheme.lower()=="bearer" and value.strip() else None
            else:token=request.headers.get("x-api-token")
            protected=path.startswith(config.api_prefix) or path in {"/docs","/redoc","/openapi.json"}
            if protected and path not in public and not bypass and not token_matches(config.api_token,token):
                logger.warning("authentication_failed path=%s client=%s",path,client)
                response=JSONResponse({"success":False,"error":{"code":"AUTHENTICATION_REQUIRED","message":"Authentication required.","details":{}},"request_id":request_id},status_code=401,headers={"WWW-Authenticate":"Bearer"})
            else:response=await call_next(request)
        response.headers.update({"X-Request-ID":request_id,"X-API-Contract-Version":API_CONTRACT_VERSION,"X-Content-Type-Options":"nosniff","X-Frame-Options":"DENY","Referrer-Policy":"no-referrer","Permissions-Policy":"camera=(), microphone=(), geolocation=()","Content-Security-Policy":"default-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'","Cache-Control":"no-store"});return response
    finally:
        logger.info(
            "http_request method=%s path=%s status=%s duration_ms=%s",
            request.method,
            request.url.path,
            response.status_code if response is not None else 500,
            int((perf_counter() - started) * 1000),
        )
        request_id_var.reset(context)


app.include_router(build_browser_router(config.api_prefix + "/browser"))
app.include_router(build_voice_router(voice_pipeline, config.api_prefix + "/voice"))


@app.get(config.api_prefix + "/auth/status")
async def auth_status(request: Request):
    local=bool(request.client and request.client.host in {"127.0.0.1","::1"})
    return {"required":config.auth_required,"environment":config.environment,"local_bypass":config.environment=="development" and not config.auth_required and config.allow_unauthenticated_localhost and local}


@app.get("/health", include_in_schema=False)
@app.get(config.api_prefix + "/health")
async def health():
    """Real backend health — every field is probed, never hardcoded (spec 11/12).

    The legacy `ok`/`unavailable` strings are preserved for backward
    compatibility; the new `health_v2` block adds the richer
    READY/DEGRADED/STARTING/STOPPED/FAILED/NOT_INSTALLED/NOT_CONFIGURED
    model from spec section 12.
    """
    provider = await get_llm().status()
    tool_rows = registry().definitions()
    python_tool = next((item for item in tool_rows if item.name == "python_executor"), None)
    # Real probes (2.0) — replace every hardcoded "ok" with an actual check.
    db_ok = await store.ping()
    workspace_ok = config.workspace_root.is_dir() and config.workspace_root.exists()
    enabled_tools = sum(1 for item in tool_rows if item.enabled)
    total_tools = len(tool_rows)
    tools_ok = enabled_tools > 0
    # Configuration health: ControlState validates and is loaded.
    config_ok = control_center.state is not None and not control_center.emergency_stopped
    # Permissions health: mandatory protections are enforced.
    perms_ok = all(getattr(control_center.state.security, name) for name in MANDATORY_PROTECTIONS)
    # Logs health: a handler is attached to the root logger.
    logs_ok = bool(logging.getLogger().handlers)
    # Terminal: real availability probe (sandbox + shell + control gate).
    terminal_real = _terminal_enabled()
    # Ollama: real probe (already in provider; derive a NOT_INSTALLED verdict
    # when the binary is missing).
    import shutil as _shutil
    ollama_on_path = bool(_shutil.which("ollama"))
    if provider["ollama_available"]:
        ollama_state = "ready"
    elif not ollama_on_path:
        ollama_state = "not_installed"
    else:
        ollama_state = "unreachable"
    # Overall status: degraded if any real probe failed.
    degraded = not (db_ok and workspace_ok and tools_ok and config_ok and perms_ok and logs_ok)
    if control_center.emergency_stopped:
        overall = "stopped"
    elif degraded:
        overall = "degraded"
    else:
        overall = "ok"
    return {
        # Legacy fields (kept for backward compat with 1.3.4 clients).
        "status": overall,
        "version": "2.0.0",
        "backend": "ok",
        "database": "ok" if db_ok else "error",
        "workspace": "ok" if workspace_ok else "error",
        "ollama": "ok" if provider["ollama_available"] else "unavailable",
        "chat_model": "ok" if provider["generative_available"] else "missing",
        "embedding_model": "ok" if provider["embedding_available"] else "missing",
        "network": "enabled" if config.enable_network_tools and config.network_mode != "disabled" else "disabled",
        "tools": "ok" if tools_ok else "error",
        "terminal": "available" if terminal_real else "restricted",
        "agent": "ready" if provider["generative_available"] else "local_tools_ready",
        "automation": "enabled" if config.enable_automation else "disabled",
        "python_sandbox": "ready" if (python_tool and python_tool.enabled) else "disabled",
        "provider": provider["active_provider"],
        # New 2.0 health block: richer model, real probes.
        "health_v2": {
            "overall": "READY" if overall == "ok" else ("STOPPED" if overall == "stopped" else "DEGRADED"),
            "database": "READY" if db_ok else "FAILED",
            "workspace": "READY" if workspace_ok else "FAILED",
            "ollama": ("READY" if provider["ollama_available"]
                       else ("NOT_INSTALLED" if not ollama_on_path
                             else ("DEGRADED" if provider.get("generative_available") or provider.get("embedding_available")
                                   else "FAILED"))),
            "chat_model": "READY" if provider["generative_available"] else "NOT_CONFIGURED",
            "embedding_model": "READY" if provider["embedding_available"] else "NOT_CONFIGURED",
            "terminal": "READY" if terminal_real else "DEGRADED",
            "tools": "READY" if tools_ok else "FAILED",
            "configuration": "READY" if config_ok else "DEGRADED",
            "permissions": "READY" if perms_ok else "DEGRADED",
            "logs": "READY" if logs_ok else "DEGRADED",
            "automation": "READY" if (config.enable_automation and automation and not automation.worker.done()) else ("STOPPED" if not config.enable_automation else "FAILED"),
            "python_sandbox": "READY" if (python_tool and python_tool.enabled) else "NOT_AVAILABLE",
            "provider": provider["active_provider"],
            "emergency_stopped": control_center.emergency_stopped,
        },
        "tool_counts": {"enabled": enabled_tools, "total": total_tools, "disabled": total_tools - enabled_tools},
        "ollama_detail": {
            "on_path": ollama_on_path,
            "reachable": provider["ollama_available"],
            "models": provider.get("models", []),
            "last_error": provider.get("last_error"),
        },
    }


@app.get(config.api_prefix + "/system/health")
async def system_health():
    base = await health()
    tools = registry().definitions()
    # 2.0: real probes instead of hardcoded "ok".
    configuration_ok = base["health_v2"]["configuration"] == "READY"
    permissions_ok = base["health_v2"]["permissions"] == "READY"
    logs_ok = base["health_v2"]["logs"] == "READY"
    return {**base,
            "configuration": "ok" if configuration_ok else "degraded",
            "permissions": "ok" if permissions_ok else "degraded",
            "filesystem": "ok" if base["workspace"] == "ok" else "error",
            "logs": "ok" if logs_ok else "degraded",
            "search": "available" if any(t.name=='web_search' and t.enabled for t in tools) else "disabled",
            "components": {key:{"status":value,"error":None if value in {'ok','ready','enabled','available'} else value,"fix":None if value in {'ok','ready','enabled','available'} else "Run GET /api/v1/diagnostics for a real self-test and suggested fix."} for key,value in base.items() if key not in {'status','version','health_v2','tool_counts','ollama_detail'}}}


@app.get(config.api_prefix + "/diagnostics/{component}")
async def component_diagnostic(component: str):
    if component == "backend": return await system_health()
    if component == "tools":
        rows=registry().definitions();return {"component":"tools","status":"PASS","enabled":sum(1 for item in rows if item.enabled),"disabled":[{"name":item.name,"reason":item.disabled_reason} for item in rows if not item.enabled]}
    if component == "permissions":
        rows=registry().definitions();unsafe=[item.name for item in rows if item.risk_level.value in {'high','critical'} and not item.requires_approval]
        return {"component":"permissions","status":"PASS" if not unsafe else "FAIL","unsafe_tools":unsafe}
    if component == "agent":
        if not config.agent_enabled:return {"component":"agent","status":"NOT_CONFIGURED","error":"Agent disabled in Settings","fix":"Enable Agent and apply settings"}
        task=await (await agent()).run(AgentRequest(message="calculate 2+2"));return {"component":"agent","status":"PASS" if task.status==TaskStatus.DONE else "FAIL","task_id":task.id,"answer":task.answer,"errors":task.errors}
    if component == "search": return await test_network()
    raise HTTPException(404,"unknown diagnostic component")


@app.get(config.api_prefix + "/diagnostics")
async def full_diagnostics():
    """Unified feature self-test system (spec section 11).

    Runs every ``test_*`` function in ``app.diagnostics`` and returns a real
    verdict for each. Never reports PASS without exercising the feature.
    Each test returns ``status`` in {PASS, FAIL, WARNING, NOT_AVAILABLE}
    with ``reason``, ``diagnostic``, ``suggested_fix``, ``duration_ms`` and
    ``evidence``.

    The endpoint is read-only and side-effect-free (the memory test writes
    a probe entry but deletes it immediately; the terminal test runs
    ``echo diagnostic_ok`` which is harmless).
    """
    from app.diagnostics import run_all_diagnostics
    # Build a throwaway KnowledgeStore bound to the same memory + llm so the
    # RAG test can exercise the real search path without affecting the
    # registry-cached singleton.
    knowledge_store = KnowledgeStore(store, get_llm(), config.workspace_root, config.max_document_bytes)
    report = await run_all_diagnostics(
        store=store,
        terminal_executor=terminal_executor,
        config=config,
        get_llm=get_llm,
        knowledge_store=knowledge_store,
        automation_engine=automation,
    )
    await store.audit("diagnostics.run", {
        "overall": report["overall"],
        "summary": report["summary"],
        "duration_ms": report["duration_ms"],
    })
    return report


# --------------------------------------------------------------------------- #
# SECUREAGENT 2.0 — SAFE / ASSIST / CONTROL mode surface (spec section 4)     #
# A single tri-state UX on top of the existing 13 policy surfaces. The        #
# underlying ControlState stays the source of truth; this endpoint just       #
# applies a curated preset patch and audits the transition.                   #
# --------------------------------------------------------------------------- #

MODE_PRESETS: dict[str, dict] = {
    # SAFE: read-only operations. No system-changing actions.
    "SAFE": {
        "agent": {"enabled": True, "auto_planning": True, "auto_tool_calling": True, "auto_execution": True, "auto_retry": True},
        "terminal": {"enabled": True, "restricted_mode": True, "allow_sudo": False, "allow_network": False, "command_approval": True},
        "network": {"mode": "disabled"},
        "sudo": {"mode": "disabled"},
        "automation": {"enabled": False, "scheduled_tasks": False, "automatic_workflows": False, "paused": False},
        "workflows": {"enabled": True},
        "ai": {"enabled": True, "ollama_enabled": True},
        "memory": {"enabled": True},
        "rag": {"enabled": True},
        "host_control": {"enabled": False},
    },
    # ASSIST: normal agent operation. Safe commands automatic; medium-risk
    # execute with visible notification; high-risk require one confirmation.
    "ASSIST": {
        "agent": {"enabled": True, "auto_planning": True, "auto_tool_calling": True, "auto_execution": True, "auto_retry": True},
        "terminal": {"enabled": True, "restricted_mode": True, "allow_sudo": False, "allow_network": True, "command_approval": True},
        "network": {"mode": "localhost"},
        "sudo": {"mode": "disabled"},
        "automation": {"enabled": True, "scheduled_tasks": True, "automatic_workflows": False, "paused": False},
        "workflows": {"enabled": True},
        "ai": {"enabled": True, "ollama_enabled": True},
        "memory": {"enabled": True},
        "rag": {"enabled": True},
        "host_control": {"enabled": False},
    },
    # CONTROL: explicitly enabled advanced local control. Still protects
    # destructive/irreversible actions — host_control requires a separate
    # explicit confirmation (see PATCH /config?confirm=true).
    "CONTROL": {
        "agent": {"enabled": True, "auto_planning": True, "auto_tool_calling": True, "auto_execution": True, "auto_retry": True},
        "terminal": {"enabled": True, "restricted_mode": True, "allow_sudo": True, "allow_network": True, "command_approval": True},
        "network": {"mode": "full"},
        "sudo": {"mode": "approval_required"},
        "automation": {"enabled": True, "scheduled_tasks": True, "automatic_workflows": True, "paused": False},
        "workflows": {"enabled": True},
        "ai": {"enabled": True, "ollama_enabled": True},
        "memory": {"enabled": True},
        "rag": {"enabled": True},
        "host_control": {"enabled": False},  # still requires explicit confirm
    },
}


@app.get(config.api_prefix + "/mode")
async def get_mode():
    """Return the current effective user-facing mode (SAFE/ASSIST/CONTROL).

    Derived from the live ControlState by matching against the curated
    MODE_PRESETS. If the state does not exactly match any preset, returns
    ``CUSTOM`` with a description of the divergence.
    """
    state = control_center.state
    current = {
        "agent": state.agent.model_dump(),
        "terminal": state.terminal.model_dump(),
        "network": state.network.model_dump(),
        "sudo": state.sudo.model_dump(),
        "automation": state.automation.model_dump(),
        "workflows": state.workflows.model_dump(),
        "ai": state.ai.model_dump(),
        "memory": state.memory.model_dump(),
        "rag": state.rag.model_dump(),
        "host_control": state.host_control.model_dump(),
    }
    for mode_name, preset in MODE_PRESETS.items():
        # Compare only the keys present in the preset (the preset is a
        # partial patch; the state has every field). Match if every preset
        # value equals the corresponding state value.
        if all(current[section].get(key) == value
               for section, patch in preset.items()
               for key, value in patch.items()):
            return {"mode": mode_name, "source": "preset_match", "emergency_stopped": control_center.emergency_stopped}
    return {"mode": "CUSTOM", "source": "diverged_from_presets",
            "emergency_stopped": control_center.emergency_stopped,
            "note": "The current ControlState does not exactly match any of SAFE/ASSIST/CONTROL. Use PATCH /api/v1/config to inspect or restore a preset."}


@app.post(config.api_prefix + "/mode")
async def set_mode(item: dict):
    """Apply a SAFE/ASSIST/CONTROL preset (spec section 4).

    Body: ``{"mode": "SAFE" | "ASSIST" | "CONTROL", "confirm": bool}``.

    CONTROL does NOT enable host_control — that still requires a separate
    explicit confirmation via ``PATCH /api/v1/config?confirm=true`` (spec 6).
    """
    mode = str(item.get("mode", "")).upper()
    if mode not in MODE_PRESETS:
        raise HTTPException(422, detail={"error_code": "INVALID_MODE",
                                         "message": f"mode must be one of: {', '.join(sorted(MODE_PRESETS))}",
                                         "details": {"received": mode}})
    if control_center.emergency_stopped:
        raise HTTPException(409, detail={"error_code": "SECUREAGENT_STOPPED",
                                         "message": "Resume from EMERGENCY STOP before changing mode.",
                                         "details": {}})
    patch = MODE_PRESETS[mode]
    try:
        snapshot = await control_center.update(patch, actor="user")
    except ControlModelError as error:
        await store.audit("mode.rejected", {"mode": mode, "reason": str(error)[:300]})
        raise HTTPException(422, detail={"error_code": "MODE_REJECTED",
                                         "message": str(error),
                                         "details": {"mode": mode}}) from None
    await store.audit("mode.applied", {"mode": mode, "revision": snapshot["revision"]})
    return {"ok": True, "mode": mode, "snapshot": snapshot}


@app.get(config.api_prefix + "/ready")
async def ready():
    provider = await get_llm().status()
    missing = []
    if config.agent_enabled and not provider["generative_available"]:
        missing.append("chat_model")
    if config.knowledge_enabled and not provider["embedding_available"]:
        missing.append("embedding_model")
    if missing:
        error = provider.get("last_error") or {}
        return JSONResponse(
            {
                "status": "not_ready",
                "database": "ok",
                "workspace": "configured",
                "missing": missing,
                "error": {
                    "code": error.get("code", "OLLAMA_NOT_READY"),
                    "message": error.get("message", "Required Ollama models are unavailable."),
                    "recovery_action": error.get("recovery_action", "Start Ollama and install the configured models."),
                },
            },
            status_code=503,
        )
    return {"status": "ready", "database": "ok", "workspace": "configured"}


@app.get(config.api_prefix + "/models")
async def models():
    return {"models": await get_llm().models(), "default": config.ollama_model, "embedding": config.embedding_model}


@app.get(config.api_prefix + "/ollama/status")
async def ollama_status():
    return await get_llm().diagnostics()


@app.post(config.api_prefix + "/ollama/test-chat")
async def test_ollama_chat():
    response = await get_llm().ollama.chat(ChatRequest(messages=[{"role":"user","content":"Reply with exactly: CONNECTED"}], model=config.ollama_model, temperature=0))
    return {"status":"CONNECTED","model":response.model,"response":response.content[:500]}


@app.post(config.api_prefix + "/ollama/test-embedding")
async def test_ollama_embedding():
    vectors = await get_llm().ollama.embed(["SecureAgent embedding test"])
    return {"status":"CONNECTED","model":config.embedding_model,"dimension":len(vectors[0])}


@app.post(config.api_prefix + "/network/test")
@app.get(config.api_prefix + "/network/test")
async def test_network():
    gate = get_control_center()
    if gate is not None and not gate.workflows_active() and gate.state.network.mode == "disabled":
        # The Control Center NETWORK master switch is the runtime authority.
        raise HTTPException(409, "NETWORK_DISABLED: The Network master switch is OFF in the Control Center")
    if not config.enable_network_tools or config.network_mode == "disabled":
        raise HTTPException(409, "NETWORK_DISABLED: Network tools are disabled by policy")
    if not config.searxng_base_url:
        raise HTTPException(409, "NETWORK_NOT_CONFIGURED: SearXNG URL is required")
    started = perf_counter()
    try:
        body = await SafeHttpClient(config.network_timeout_seconds, config.network_max_response_bytes, config.allow_local_network, config.allow_private_network, config.allow_external_network, config.dns_enabled).get_json(str(config.searxng_base_url).rstrip('/') + '/search', params={'q':'SecureAgent connectivity test','format':'json'})
        count = len(body.get('results', [])) if isinstance(body.get('results'), list) else 0
        result = {"status":"CONNECTED","provider":"SearXNG","result_count":count,"duration_ms":int((perf_counter()-started)*1000)}
        await store.audit("network.test", result)
        return result
    except Exception as error:
        await store.audit("network.test", {"status":"FAILED","error":str(error)[:300]})
        if isinstance(error, NetworkPolicyError): raise
        raise HTTPException(503, "NETWORK_UNAVAILABLE: SearXNG did not respond") from error


def _agent_request(request: AgentRequest | ChatRequest) -> AgentRequest:
    if isinstance(request, AgentRequest):
        return request
    text = request.user_request
    if text is None:
        text = next((item.content for item in reversed(request.messages) if item.role == 'user' and not item.content.startswith('<untrusted-data')), None)
    if not text:
        raise HTTPException(422, detail={"error_code":"INVALID_CHAT_REQUEST","message":"A non-empty user message is required.","details":{}})
    return AgentRequest(message=text, model=request.model)

@app.post(config.api_prefix + "/chat", response_model=ExecutionResponse)
async def chat(request: AgentRequest | ChatRequest):
    if not config.agent_enabled:
        raise HTTPException(409, detail={"error_code":"AGENT_DISABLED","message":"Enable Agent in Settings.","details":{}})
    gate = get_control_center()
    if gate is not None:
        # AI ENGINE master switch: chat may remain available when only the
        # AI AGENT switch is OFF (spec section 4), but a disabled AI engine
        # blocks every generative call (spec section 11).
        if not gate.ai_active():
            raise HTTPException(409, detail={"error_code":"AI_DISABLED","message":"The AI engine is OFF in the Control Center.","details":{}})
    try:
        task = await asyncio.wait_for((await agent()).run(_agent_request(request)), config.agent_timeout_seconds)
        return execution_response(task, get_llm().active)
    except asyncio.TimeoutError as error:
        logger.exception("chat execution timed out")
        raise HTTPException(504, detail={"error_code":"AGENT_TIMEOUT","message":"Chat execution timed out.","details":{}}) from error


@app.get(config.api_prefix + "/tools", response_model=list[ToolDef])
async def tools():
    return registry().definitions()


@app.post(config.api_prefix + "/agent/tasks", response_model=Task)
async def create_task(request: AgentRequest):
    if not config.agent_enabled: raise HTTPException(409, "AGENT_DISABLED: Enable Agent in Settings")
    gate = get_control_center()
    if gate is not None and not gate.agent_active():
        raise HTTPException(409, detail={"error_code":"AGENT_DISABLED_BY_CONTROL_CENTER","message":"The AI Agent master switch is OFF.","details":{}})
    try:return await asyncio.wait_for((await agent()).run(request),config.agent_timeout_seconds)
    except asyncio.TimeoutError:raise HTTPException(504,"agent execution timed out")


@app.get(config.api_prefix + "/agent/tasks", response_model=list[Task])
async def list_tasks(limit: int = Query(50, ge=1, le=200)):
    return await store.tasks(limit)


@app.get(config.api_prefix + "/agent/tasks/{item_id}", response_model=Task)
async def get_task(item_id: str):
    item = await store.task(item_id)
    if not item:
        raise HTTPException(404, "task not found")
    return item


@app.post(config.api_prefix + "/agent/tasks/{item_id}/resume", response_model=Task)
async def resume(item_id: str, request: ResumeRequest):
    try:
        item = await store.task(item_id)
        if not item: raise KeyError("task not found")
        step = item.steps[item.current_step] if item.current_step < len(item.steps) else None
        if request.scope == 'session':
            session_approvals.setdefault(item.conversation_id, set()).update(request.approved_permissions)
            session_approval_activity[item.conversation_id] = perf_counter()
            prune_session_approvals()
        await store.audit("approval.granted", {"task_id":item_id,"step_id":step.id if step else None,"scope":request.scope,"permissions":sorted(p.value for p in request.approved_permissions)})
        return await asyncio.wait_for(
            (await agent()).resume(item_id, request.approved_permissions, step.id if step else None),
            config.agent_timeout_seconds,
        )
    except KeyError:
        raise HTTPException(404, "task not found")
    except asyncio.TimeoutError:
        raise HTTPException(504, "agent execution timed out")


@app.post(config.api_prefix + "/agent/tasks/{item_id}/reject", response_model=Task)
async def reject_task(item_id: str):
    item = await store.task(item_id)
    if not item: raise HTTPException(404, "task not found")
    if item.status.value != "waiting_confirmation": raise HTTPException(409, "task is not waiting for approval")
    item.status = TaskStatus.CANCELLED; item.errors.append("User rejected the requested operation")
    for step in item.steps:
        if step.status.value == "waiting_confirmation": step.status = StepStatus.CANCELLED
    await store.save_task(item); await store.audit("task.rejected", {"task_id": item_id})
    return item


@app.post(config.api_prefix + "/agent/tasks/{item_id}/cancel", response_model=Task)
async def cancel_task(item_id: str):
    item = await store.task(item_id)
    if not item: raise HTTPException(404, "task not found")
    if item.status.value in {"completed","cancelled"}: raise HTTPException(409, "task is already final")
    item.status = TaskStatus.CANCELLED; item.errors.append("Task cancelled by user")
    await store.save_task(item); await store.audit("task.cancelled", {"task_id": item_id})
    await executions.request_cancel(item_id)
    return item


@app.post(config.api_prefix + "/orchestrate", response_model=ExecutionResponse)
async def orchestrate(request: AgentRequest):
    gate = get_control_center()
    if gate is not None and not gate.agent_active():
        raise HTTPException(409, detail={"error_code":"AGENT_DISABLED_BY_CONTROL_CENTER","message":"The AI Agent master switch is OFF.","details":{}})
    try:return await asyncio.wait_for(Orchestrator(await agent()).run(request),config.agent_timeout_seconds)
    except asyncio.TimeoutError:raise HTTPException(504,"orchestration timed out")


@app.get(config.api_prefix + "/agents/roles")
async def agent_roles():
    """Phase 15 — read-only view of the multi-agent role specifications.
    Diagnostic only: this endpoint cannot modify roles, permissions or policy
    (the agent may never alter its own security configuration)."""
    from app.multi_agent import build_roles
    roles = build_roles(registry())
    return {
        "multi_agent_enabled": config.multi_agent_enabled,
        "budgets": {
            "max_depth": config.max_agent_depth,
            "runtime_seconds": config.agent_timeout_seconds,
            "total_tokens": config.multi_agent_max_tokens,
            "total_tool_calls": config.multi_agent_max_tool_calls,
            "concurrent_workers": config.multi_agent_max_concurrent_workers,
        },
        "roles": [role.model_dump(mode="json") for role in roles.values()],
    }


@app.get(config.api_prefix + "/memories", response_model=list[MemoryItem])
async def memories(query: str | None = Query(None, max_length=500), limit: int = Query(50, ge=1, le=200)):
    gate = get_control_center()
    if gate is not None and not gate.memory_active(): raise HTTPException(409, "MEMORY_DISABLED: Enable Memory in the Control Center")
    if gate is not None and not gate.state.memory.retrieval: raise HTTPException(409, "MEMORY_RETRIEVAL_DISABLED: Memory retrieval is OFF in the Control Center")
    limit = min(limit, gate.state.memory.max_context_items) if gate is not None else limit
    return await store.list(query, limit)


@app.post(config.api_prefix + "/memories", response_model=MemoryItem, status_code=201)
async def create_memory(item: MemoryIn):
    gate = get_control_center()
    if gate is not None and not gate.memory_active(): raise HTTPException(409, "MEMORY_DISABLED: Enable Memory in the Control Center")
    if gate is not None and not gate.state.memory.ingestion: raise HTTPException(409, "MEMORY_INGESTION_DISABLED: Memory ingestion is OFF in the Control Center")
    try:
        result = await memory_service.create(item)
    except ValueError as error:
        raise HTTPException(422, str(error))
    await store.audit("memory.created", {"memory_id": result.id, "category": result.category})
    return result


@app.patch(config.api_prefix + "/memories/{item_id}", response_model=MemoryItem)
async def patch_memory(item_id: str, patch: MemoryPatch):
    try:
        item = await memory_service.update(item_id, patch)
    except ValueError as error:
        raise HTTPException(422, str(error))
    if not item:
        raise HTTPException(404, "memory not found")
    await store.audit("memory.updated", {"memory_id": item_id})
    return item


@app.delete(config.api_prefix + "/memories/{item_id}", status_code=204)
async def delete_memory(item_id: str):
    if not await store.delete(item_id):
        raise HTTPException(404, "memory not found")
    await store.audit("memory.deleted", {"memory_id": item_id})


@app.get(config.api_prefix + "/schedules")
async def schedules():
    return await store.schedules()


@app.post(config.api_prefix + "/schedules", status_code=201)
async def create_schedule(item: ScheduleCreate):
    gate = get_control_center()
    if gate is not None and not gate.automation_active():
        raise HTTPException(409, "AUTOMATION_DISABLED: Enable Automation (and Scheduled Tasks) in the Control Center")
    if not config.enable_automation: raise HTTPException(409, "AUTOMATION_DISABLED: Enable Automation in Settings")
    # Creating autonomous work is itself a high-impact action even when the
    # scheduled prompt currently requests only SAFE tools.  Do not let an
    # empty permission set bypass the configured approval gate.
    approval_required = bool(config.automation_require_approval)
    try:
        result = await store.create_schedule_pending(item, approval_required)
    except ValueError as error:
        raise HTTPException(422, str(error))
    await store.audit("schedule.created", {"schedule_id": result["id"], "kind": result["kind"], "permissions": result["permissions"], "approval_required": approval_required})
    return result

@app.patch(config.api_prefix + "/schedules/{item_id}")
async def update_schedule(item_id: str, patch: SchedulePatch):
    gate = get_control_center()
    if gate is not None and not gate.automation_active():raise HTTPException(409,"AUTOMATION_DISABLED: Enable Automation in the Control Center")
    if not config.enable_automation:raise HTTPException(409,"AUTOMATION_DISABLED: Enable Automation in Settings")
    try:item=await store.update_schedule(item_id,patch)
    except ValueError as error:raise HTTPException(409,str(error)) from error
    if not item:raise HTTPException(404,"schedule not found")
    await store.audit('schedule.updated',{'schedule_id':item_id,'fields':sorted(patch.model_dump(exclude_none=True))})
    return item


@app.post(config.api_prefix + "/schedules/{item_id}/approve")
async def approve_schedule(item_id: str):
    rows=await store.schedules();item=next((row for row in rows if row['id']==item_id),None)
    if not item:raise HTTPException(404,"schedule not found")
    if item['cancelled']:raise HTTPException(409,"schedule is cancelled")
    if not item['policy'].get('approval_required'):raise HTTPException(409,"schedule does not require approval")
    if not await store.approve_schedule(item_id):raise HTTPException(409,"schedule could not be approved")
    await store.audit("schedule.approved",{"schedule_id":item_id,"permissions":item['permissions'],"scope":"schedule"})
    return {"ok":True,"schedule_id":item_id,"status":"approved"}


@app.post(config.api_prefix + "/schedules/{item_id}/cancel", status_code=204)
async def cancel_schedule(item_id: str):
    if not await store.cancel_schedule(item_id):
        raise HTTPException(404, "schedule not found")
    await store.audit("schedule.cancelled", {"schedule_id": item_id})


@app.delete(config.api_prefix + "/schedules/{item_id}", status_code=204)
async def delete_schedule(item_id: str):
    if not await store.delete_schedule(item_id):
        raise HTTPException(404, "schedule not found")
    await store.audit("schedule.deleted", {"schedule_id": item_id})


@app.get(config.api_prefix + "/schedule-runs")
async def schedule_runs(limit: int = Query(100, ge=1, le=500)):
    return await store.schedule_runs(limit)


@app.post(config.api_prefix + "/documents", status_code=201)
async def ingest_document(item: DocumentIn):
    gate = get_control_center()
    if gate is not None:
        if not gate.rag_active(): raise HTTPException(409, "KNOWLEDGE_DISABLED: Enable RAG in the Control Center")
        if not gate.state.rag.ingestion_enabled: raise HTTPException(409, "DOCUMENT_INGESTION_DISABLED: Document ingestion is OFF in the Control Center")
        documents = await store.documents()
        if len(documents) >= gate.state.memory.max_documents:
            raise HTTPException(409, "MAX_DOCUMENTS_REACHED: the Maximum Documents limit is reached")
    if not config.knowledge_enabled: raise HTTPException(409, "KNOWLEDGE_DISABLED: Enable Knowledge in Settings")
    try:
        result = await KnowledgeStore(store, get_llm(), config.workspace_root, config.max_document_bytes).ingest(item.path, item.title, item.reindex, item.metadata)
    except (ValueError, PermissionError, FileNotFoundError) as error:
        raise HTTPException(422, str(error))
    await store.audit("document.ingested", result)
    return result


@app.get(config.api_prefix + "/documents")
async def documents():
    return await store.documents()


@app.post(config.api_prefix + "/documents/search")
async def search_documents(item: DocumentSearch):
    gate = get_control_center()
    if gate is not None:
        if not gate.rag_active(): raise HTTPException(409, "KNOWLEDGE_DISABLED: Enable RAG in the Control Center")
        if not gate.state.rag.retrieval_enabled: raise HTTPException(409, "RETRIEVAL_DISABLED: Retrieval is OFF in the Control Center")
    if not config.knowledge_enabled: raise HTTPException(409, "KNOWLEDGE_DISABLED: Enable Knowledge in Settings")
    return await KnowledgeStore(store, get_llm(), config.workspace_root, config.max_document_bytes).search(item.query, min(item.limit, config.max_retrieval_chunks), item.document_id, item.min_score)


@app.delete(config.api_prefix + "/documents/{item_id}", status_code=204)
async def delete_document(item_id: str):
    if not await store.delete_document(item_id):
        raise HTTPException(404, "document not found")
    await store.audit("document.deleted", {"document_id": item_id})


# (the /audit endpoint lives in the Control Center section below — it supports
#  category filtering there)


@app.get(config.api_prefix + "/settings")
async def safe_settings():
    provider = await get_llm().status()
    return {"app_name": config.app_name, **provider, "model": config.ollama_model, "embedding_model": config.embedding_model, "max_completion_tokens":config.max_llm_completion_tokens, "workspace": "configured", "agent_enabled":config.agent_enabled, "autonomous_mode":config.autonomous_mode, "max_agent_steps":config.max_agent_steps, "tools_enabled":config.tools_enabled, "filesystem_tools":config.filesystem_tools_enabled, "coding_tools":config.coding_tools_enabled, "terminal_tools":config.terminal_tools_enabled, "terminal_backend":config.terminal_backend, "security_workflows":config.security_workflows_enabled, "plugins_enabled":config.plugins_enabled, "memory_enabled":config.memory_enabled, "knowledge_enabled":config.knowledge_enabled, "network_tools": config.enable_network_tools, "web_search":config.web_search_enabled, "http_requests":config.http_requests_enabled, "network_mode": config.network_mode, "network_provider": "SearXNG" if config.searxng_base_url else None, "network_url_configured": bool(config.searxng_base_url), "allow_local_network":config.allow_local_network, "allow_private_network":config.allow_private_network, "allow_external_network":config.allow_external_network, "approval_mode":config.approval_mode, "automation": config.enable_automation, "automation_require_approval":config.automation_require_approval, "automation_max_concurrent_jobs":config.automation_max_concurrent_jobs, "authentication": config.auth_required, "environment": config.environment, "python_execution": config.python_execution_backend}


# --------------------------------------------------------------------------- #
# Linux terminal agent API
# --------------------------------------------------------------------------- #

@app.get(config.api_prefix + "/system/info")
async def system_info():
    """Linux auto-detection: distro, kernel, arch, shell, toolchain."""
    return detect_environment()


@app.get(config.api_prefix + "/terminal/status")
async def terminal_status():
    backend = config.terminal_backend
    available = _terminal_enabled()
    sandbox = terminal_executor.sandbox_status() if terminal_executor else {"available": False, "mechanism": "none"}
    mode = terminal_executor.mode.value if terminal_executor else "restricted_agent"
    return {
        "backend": backend,
        "enabled": bool(config.terminal_tools_enabled and control_center.state.terminal.enabled),
        "available": available,
        "shell": config.terminal_shell,
        "workspace_root": str(config.workspace_root),
        "allowed_paths": [str(path) for path in (terminal_executor.allowed_roots() if terminal_executor else [])],
        "sudo_enabled": config.terminal_allow_sudo,
        "timeout_seconds": config.terminal_command_timeout_seconds,
        "max_output_bytes": config.terminal_max_output_bytes,
        "mode": mode,
        "sandbox": sandbox,
        "host_control_warning": (
            "HOST_CONTROL is active — commands run on the host outside the namespace sandbox."
            if mode == "host_control" else None
        ),
        "unavailable_reason": None if available else (
            "TERMINAL_TOOLS_DISABLED: enable Terminal tools in Settings" if not config.terminal_tools_enabled
            else (terminal_executor.unavailable_reason() if terminal_executor else "terminal backend not initialized")),
    }


@app.post(config.api_prefix + "/terminal/mode")
async def terminal_set_mode(item: dict, request: Request):
    """User-initiated switch between RESTRICTED_AGENT and HOST_CONTROL.

    The body must contain ``{"mode": "host_control"|"restricted_agent",
    "confirm": true}`` — the explicit ``confirm`` flag exists so the
    frontend can never accidentally flip the switch with a stale click.
    The AI cannot call this endpoint on its own behalf; agent-initiated
    mode elevation is refused at the orchestrator layer.
    """
    if not terminal_executor:
        raise HTTPException(409, "terminal backend unavailable")
    requested = str(item.get("mode", "")).strip().lower()
    confirm = bool(item.get("confirm"))
    if requested not in {"restricted_agent", "host_control"}:
        raise HTTPException(422, detail={"error_code": "INVALID_MODE",
                                         "message": "mode must be 'restricted_agent' or 'host_control'",
                                         "details": {}})
    if requested == "host_control" and not confirm:
        raise HTTPException(403, detail={"error_code": "HOST_CONTROL_REQUIRES_CONFIRMATION",
                                         "message": "Switching to HOST_CONTROL requires explicit confirm=true.",
                                         "details": {"warning": "HOST_CONTROL runs commands on the host "
                                                                  "outside the namespace sandbox. The command "
                                                                  "policy engine still classifies everything "
                                                                  "and BLOCKED commands remain blocked."}})
    gate = get_control_center()
    if requested == "host_control" and gate is not None:
        # The Control Center HOST CONTROL master switch must be ON; the AI
        # can never enable it (spec sections 5/6).
        try:
            gate.check_host_control_operation()
        except PermissionError as error:
            raise HTTPException(403, detail={"error_code": "HOST_CONTROL_DISABLED",
                                             "message": str(error),
                                             "details": {"hint": "Enable Host Control in the Control Center first (explicit user confirmation required)."}}) from None
        if gate.emergency_stopped:
            raise HTTPException(409, detail={"error_code": "SECUREAGENT_STOPPED",
                                             "message": "Emergency stop is active — resume before changing terminal mode.",
                                             "details": {}})
    from app.linux_terminal import TerminalMode
    target = TerminalMode.HOST_CONTROL if requested == "host_control" else TerminalMode.RESTRICTED_AGENT
    result = terminal_executor.set_mode(target)
    await store.audit("terminal.mode_change", {
        "mode": target.value, "user_initiated": True, "client": request.client.host if request.client else "unknown",
    })
    return result


@app.post(config.api_prefix + "/terminal/execute")
async def terminal_execute(item: TerminalExecuteIn, request: Request):
    """User-initiated terminal execution (same policy engine as the agent).

    SAFE/LOW_RISK commands run immediately. REQUIRES_APPROVAL/HIGH_RISK
    commands require confirm=true (the UI shows an explicit approval dialog
    with the exact command, risk, why, affected paths, network/privilege
    scope, and expected effect). BLOCKED commands are always rejected. The
    user is the approver here; agent-initiated commands go through the task
    approval flow instead.
    """
    if not _terminal_enabled():
        gate = get_control_center()
        if gate is not None and gate.emergency_stopped:
            raise HTTPException(409, detail={"error_code": "SECUREAGENT_STOPPED",
                                             "message": "Emergency stop is active — terminal execution is disabled. Press RESUME to restore.",
                                             "details": {}})
        if gate is not None and not gate.state.terminal.enabled:
            raise HTTPException(409, detail={"error_code": "TERMINAL_DISABLED_BY_CONTROL_CENTER",
                                             "message": "The Terminal master switch is OFF in the Control Center.",
                                             "details": {"backend": config.terminal_backend}})
        raise HTTPException(409, detail={"error_code": "TERMINAL_UNAVAILABLE",
                                         "message": "The Linux terminal backend is disabled or unavailable.",
                                         "details": {"backend": config.terminal_backend}})
    classification = terminal_executor.policy.classify(item.command)
    from app.terminal_policy import CommandRisk
    if classification.risk is CommandRisk.BLOCKED:
        await store.audit("terminal.blocked", {"command": item.command, "reasons": list(classification.reasons)})
        raise HTTPException(403, detail={"error_code": "TERMINAL_COMMAND_BLOCKED",
                                         "message": classification.summary(),
                                         "details": {"reasons": list(classification.reasons)}})
    if classification.risk in {CommandRisk.REQUIRES_APPROVAL, CommandRisk.HIGH_RISK} and not item.confirm:
        # Build the structured approval dialog the UI must show.
        approval_dialog = _build_approval_dialog(item.command, classification)
        raise HTTPException(403, detail={"error_code": "TERMINAL_APPROVAL_REQUIRED",
                                         "message": classification.summary() + " — confirm the exact command to approve it.",
                                         "details": approval_dialog})
    if classification.requires_elevation and not config.terminal_allow_sudo:
        raise HTTPException(403, detail={"error_code": "TERMINAL_SUDO_DISABLED",
                                         "message": "sudo usage is disabled by policy",
                                         "details": {}})
    gate = get_control_center()
    if classification.requires_elevation and gate is not None:
        # The SUDO master switch (disabled / approval_required / host_control_only)
        # is the runtime authority; passwords are never requested or stored.
        try:
            gate.check_sudo()
        except PermissionError as error:
            raise HTTPException(403, detail={"error_code": "TERMINAL_SUDO_DISABLED",
                                             "message": str(error),
                                             "details": {"sudo_mode": gate.state.sudo.mode}}) from None
    try:
        execution = await terminal_executor.execute(
            item.command, cwd=item.cwd, timeout=item.timeout_seconds,
            approval="user-confirmed" if item.confirm else "user",
            task_id=item.task_id, session_id=item.session_id)
    except (ValueError, PermissionError, RuntimeError) as error:
        msg = str(error)
        if msg.startswith("LINUX_SANDBOX_UNAVAILABLE"):
            code = "LINUX_SANDBOX_UNAVAILABLE"
            status_code = 409
        elif msg.startswith("SENSITIVE_RESOURCE_BLOCKED"):
            code = "SENSITIVE_RESOURCE_BLOCKED"
            status_code = 403
        elif msg.startswith("TERMINAL_SUDO_BLOCKED_IN_RESTRICTED_MODE"):
            code = "TERMINAL_SUDO_BLOCKED_IN_RESTRICTED_MODE"
            status_code = 403
        elif msg.startswith("TERMINAL_COMMAND_BLOCKED"):
            code = "TERMINAL_COMMAND_BLOCKED"
            status_code = 403
        elif msg.startswith("TERMINAL_SUDO_DISABLED"):
            code = "TERMINAL_SUDO_DISABLED"
            status_code = 403
        elif msg.startswith("TERMINAL_") or msg.startswith("SUDO_"):
            code = msg.split(':', 1)[0]
            status_code = 422
        else:
            code = "TERMINAL_EXECUTE_FAILED"
            status_code = 422
        await store.audit("terminal.error", {"command": item.command, "error": msg[:300], "code": code})
        raise HTTPException(status_code, detail={"error_code": code, "message": msg, "details": {}}) from error
    await store.audit("terminal.executed", {
        "execution_id": execution.id, "command": item.command, "cwd": execution.cwd,
        "risk": execution.risk, "approval": execution.approval, "exit_code": execution.exit_code,
        "status": execution.status, "duration_ms": execution.duration_ms,
        "mode": execution.mode, "sandbox_mechanism": (execution.sandbox or {}).get("mechanism"),
    })
    return terminal_executor.snapshot(execution.id)


def _build_approval_dialog(command: str, classification) -> dict:
    """Construct the structured approval payload the UI must display.

    The dialog always contains the EXACT COMMAND, RISK, WHY (human-readable
    reasons), AFFECTED PATH (write targets detected by the policy engine),
    NETWORK ACCESS, PRIVILEGE (whether sudo is required), and EXPECTED
    EFFECT (a deterministic one-liner derived from the policy rules).
    """
    import re
    from app.terminal_policy import CommandRisk
    reasons = list(classification.reasons) if classification.reasons else ["classified by command policy"]
    # Extract affected paths from the reasons and the raw command.
    affected: list[str] = []
    for match in re.finditer(r"(/(?:etc|usr|bin|sbin|lib|boot|root|opt|srv|var|home|dev|proc|sys|run|tmp|mnt|media)[^\s|&;<>']*)", command):
        affected.append(match.group(1))
    for reason in reasons:
        m = re.search(r"under protected system path (\S+)", reason)
        if m and m.group(1) not in affected:
            affected.append(m.group(1))
    return {
        "exact_command": command,
        "risk": classification.risk.value,
        "why": reasons,
        "affected_paths": affected or ["(workspace or relative path)"],
        "network_access": "blocked" if classification.risk is CommandRisk.BLOCKED else (
            "external" if any(r.startswith("approval:network") for r in classification.matched_rules)
            else "restricted_agent_default"
        ),
        "privilege": "sudo_required" if classification.requires_elevation else "user",
        "expected_effect": (
            "destructive system operation — verify the target before approving"
            if classification.risk is CommandRisk.HIGH_RISK
            else "modifies system state outside the workspace"
        ),
        "matched_rules": list(classification.matched_rules),
    }


@app.get(config.api_prefix + "/terminal/executions/{item_id}/stream")
async def terminal_stream(item_id: str):
    """Server-Sent Events stream for a running terminal execution.

    Emits one ``event: snapshot`` line per status change with a JSON
    payload matching the polling endpoint. The stream closes when the
    execution reaches a terminal status (completed / failed / timeout /
    cancelled). Maintains v1 polling compatibility — clients that prefer
    polling can ignore this endpoint.
    """
    from fastapi.responses import StreamingResponse
    if not terminal_executor:
        raise HTTPException(409, "terminal backend unavailable")
    cap = config.terminal_max_output_bytes

    async def event_stream():
        last_status = None
        # Cap total stream duration to timeout + 5s so a hung executor
        # cannot keep the SSE connection alive forever.
        deadline = 60.0 + config.terminal_command_timeout_seconds
        started = asyncio.get_event_loop().time()
        while True:
            snap = terminal_executor.snapshot(item_id, cap)
            if not snap:
                # Fall back to the persisted record if execution already left
                # the live tracker.
                stored = await store.terminal_execution(item_id)
                if stored:
                    yield f"event: snapshot\ndata: {__import__('json').dumps(stored)}\n\n"
                yield "event: end\ndata: {}\n\n"
                return
            if snap["status"] != last_status:
                yield f"event: snapshot\ndata: {__import__('json').dumps(snap)}\n\n"
                last_status = snap["status"]
            if snap["status"] in {"completed", "failed", "timeout", "cancelled"}:
                yield "event: end\ndata: {}\n\n"
                return
            if asyncio.get_event_loop().time() - started > deadline:
                yield "event: end\ndata: {}\n\n"
                return
            await asyncio.sleep(0.25)

    return StreamingResponse(event_stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


@app.get(config.api_prefix + "/terminal/history")
async def terminal_history(limit: int = Query(100, ge=1, le=1000), query: str | None = Query(None, max_length=200)):
    return await store.terminal_history(limit, query)


@app.get(config.api_prefix + "/terminal/executions")
async def terminal_live_executions():
    """Live tracker view: every currently running terminal execution.

    The Control Center uses this to show what EMERGENCY STOP would kill."""
    if not terminal_executor:
        raise HTTPException(409, "terminal backend unavailable")
    cap = config.terminal_max_output_bytes
    return [execution.snapshot(cap) for execution in terminal_executor.tracker.running()]


@app.get(config.api_prefix + "/terminal/executions/{item_id}")
async def terminal_execution(item_id: str):
    """Live snapshot of a running or completed execution (poll for live output)."""
    live = terminal_executor.snapshot(item_id) if terminal_executor else None
    if live:
        return live
    stored = await store.terminal_execution(item_id)
    if not stored:
        raise HTTPException(404, "terminal execution not found")
    return stored


@app.post(config.api_prefix + "/terminal/executions/{item_id}/cancel")
async def terminal_cancel(item_id: str):
    if not terminal_executor:
        raise HTTPException(409, "terminal backend unavailable")
    cancelled = terminal_executor.cancel(item_id)
    await store.audit("terminal.cancel_requested", {"execution_id": item_id, "process_killed": cancelled})
    return {"ok": True, "execution_id": item_id, "process_killed": cancelled}


# --------------------------------------------------------------------------- #
# One-click deterministic security workflows + reports
# --------------------------------------------------------------------------- #

@app.get(config.api_prefix + "/workflows")
async def workflows():
    return [{"name": name, **meta} for name, meta in WORKFLOWS.items()]


@app.post(config.api_prefix + "/workflows/{name}/run")
async def run_workflow(name: str, scope: dict | None = None):
    gate = get_control_center()
    if gate is not None and not gate.workflows_active():
        raise HTTPException(409, "WORKFLOWS_DISABLED: the Workflows master switch is OFF in the Control Center")
    if not config.security_workflows_enabled:
        raise HTTPException(409, "WORKFLOWS_DISABLED: security workflows are disabled in Settings")
    if name not in WORKFLOWS:
        raise HTTPException(404, "unknown workflow")
    if name == "file_security_audit" and not terminal_executor:
        raise HTTPException(409, "TERMINAL_UNAVAILABLE: file security audit requires the Linux terminal backend")
    try:
        report = await security_engine.run_workflow(name, scope or {})
    except ValueError as error:
        raise HTTPException(422, str(error)) from error
    return report


@app.get(config.api_prefix + "/reports")
async def reports(limit: int = Query(50, ge=1, le=200)):
    return await store.reports(limit)


@app.get(config.api_prefix + "/reports/{item_id}")
async def report_detail(item_id: str):
    item = await store.report(item_id)
    if not item:
        raise HTTPException(404, "report not found")
    return item


# --------------------------------------------------------------------------- #
# Permission Center — persistent grants + derived notification center
# --------------------------------------------------------------------------- #

@app.get(config.api_prefix + "/permissions/grants")
async def list_grants():
    return await store.grants()


@app.post(config.api_prefix + "/permissions/grants", status_code=201)
async def create_grant(item: GrantIn):
    # 'admin' grants would let scheduled/agent work disable security controls.
    if item.permission is Permission.ADMIN:
        raise HTTPException(422, detail={"error_code": "GRANT_FORBIDDEN", "message": "admin permission cannot be granted persistently", "details": {}})
    created = await store.create_grant(item.permission.value, item.scope, item.note)
    await store.audit("permission.granted", {"grant_id": created["id"], "permission": item.permission.value, "scope": item.scope})
    return created


@app.delete(config.api_prefix + "/permissions/grants/{item_id}", status_code=204)
async def delete_grant(item_id: str):
    if not await store.delete_grant(item_id):
        raise HTTPException(404, "grant not found")
    await store.audit("permission.revoked", {"grant_id": item_id})


@app.get(config.api_prefix + "/notifications")
async def notifications():
    """Derived notification center: approvals, failures, provider health, findings."""
    items: list[dict] = []
    try:
        tasks = await store.tasks(50)
        waiting = [task for task in tasks if task.status is TaskStatus.WAITING]
        for task in waiting[:10]:
            step = task.steps[task.current_step] if task.current_step < len(task.steps) else None
            items.append({"id": f"approval-{task.id}", "kind": "approval_required", "severity": "high",
                          "message": f"Task '{task.goal[:60]}' is waiting for your approval"
                                     + (f" (step: {step.title[:60]})" if step else ""),
                          "target": {"task_id": task.id}, "created_at": task.updated_at.isoformat()})
        for task in [task for task in tasks if task.status is TaskStatus.FAILED][:5]:
            items.append({"id": f"failed-{task.id}", "kind": "task_failed", "severity": "medium",
                          "message": f"Task '{task.goal[:60]}' failed: " + (task.errors[-1][:120] if task.errors else "unknown error"),
                          "target": {"task_id": task.id}, "created_at": task.updated_at.isoformat()})
        provider = await get_llm().status()
        if not provider["ollama_available"]:
            error = provider.get("last_error") or {}
            items.append({"id": "ollama-unavailable", "kind": "provider_down", "severity": "medium",
                          "message": f"Ollama is unavailable: {error.get('message', 'service unreachable')} — the deterministic local core keeps core features working.",
                          "target": {}, "created_at": None})
        schedules = await store.schedules()
        for schedule in [row for row in schedules if row.get("failure_count", 0) > 0][:5]:
            items.append({"id": f"schedule-{schedule['id']}", "kind": "automation_failing", "severity": "medium",
                          "message": f"Automation '{schedule['name'][:60]}' has {schedule['failure_count']} failed run(s)",
                          "target": {"schedule_id": schedule["id"]}, "created_at": schedule.get("updated_at")})
        rows = await store.reports(5)
        for row in rows:
            if row.get("overall_severity") in {"high", "critical"}:
                items.append({"id": f"report-{row['id']}", "kind": "security_finding", "severity": row["overall_severity"],
                              "message": f"{row.get('title') or row['workflow']} found {row['overall_severity']} severity issues",
                              "target": {"report_id": row["id"]}, "created_at": row.get("created_at")})
    except Exception:
        logger.exception("notification aggregation failed")
    return items[:30]


# --------------------------------------------------------------------------- #
# SECUREAGENT CONTROL CENTER — live configuration API (spec sections 2-24)   #
# The desktop Control Center UI drives the backend exclusively through these  #
# endpoints; the backend remains the security authority.                      #
# --------------------------------------------------------------------------- #

# One-click presets (spec section 18). Mandatory protections are never part
# of a preset patch, so no preset can weaken security enforcement.
PRESETS: dict[str, tuple[dict, bool]] = {
    "safe": ({
        "agent": {"enabled": True, "auto_planning": True, "auto_tool_calling": True, "auto_execution": True, "auto_retry": True},
        "terminal": {"enabled": True, "restricted_mode": True, "allow_sudo": False, "allow_network": False, "command_approval": True},
        "network": {"mode": "disabled"},
        "sudo": {"mode": "disabled"},
        "automation": {"enabled": False, "scheduled_tasks": False, "automatic_workflows": False, "paused": False},
        "workflows": {"enabled": True},
        "ai": {"enabled": True, "ollama_enabled": True},
        "memory": {"enabled": True},
        "rag": {"enabled": True},
    }, False),
    "development": ({
        "agent": {"enabled": True},
        "terminal": {"enabled": True, "restricted_mode": True, "allow_sudo": False, "allow_network": True, "command_approval": True},
        "network": {"mode": "localhost"},
        "sudo": {"mode": "disabled"},
        "automation": {"enabled": True, "scheduled_tasks": False, "automatic_workflows": False},
        "workflows": {"enabled": True},
        "ai": {"enabled": True, "ollama_enabled": True},
    }, False),
    "security_lab": ({
        "agent": {"enabled": True},
        "terminal": {"enabled": True, "restricted_mode": True, "command_approval": True},
        "sudo": {"mode": "approval_required"},
        "automation": {"enabled": True, "scheduled_tasks": True, "automatic_workflows": True},
        "workflows": {"enabled": True},
        "ai": {"enabled": True, "ollama_enabled": True},
    }, False),
    "full_control": ({
        # Deliberately NOT unrestricted: mandatory security controls stay
        # active, the sandbox stays mandatory, and Host Control is a separate
        # explicit confirmation (spec section 18: "DO NOT make this
        # unrestricted").
        "agent": {"enabled": True, "auto_planning": True, "auto_tool_calling": True, "auto_execution": True, "auto_retry": True},
        "terminal": {"enabled": True, "restricted_mode": True, "allow_network": True, "command_approval": True, "allow_sudo": True},
        "sudo": {"mode": "approval_required"},
        "network": {"mode": "full"},
        "automation": {"enabled": True, "scheduled_tasks": True, "automatic_workflows": True, "paused": False},
        "workflows": {"enabled": True},
        "ai": {"enabled": True, "ollama_enabled": True},
        "memory": {"enabled": True},
        "rag": {"enabled": True},
    }, True),
}


@app.get(config.api_prefix + "/config")
async def get_config():
    """Full runtime control state (single source of truth, spec 19/20)."""
    return control_center.snapshot()


@app.patch(config.api_prefix + "/config")
async def patch_config(patch: dict, request: Request, confirm: bool = Query(False)):
    """Validated configuration transaction (spec 20/23).

    Either every field applies (validated → persisted → audited) or nothing
    changes. Partial application is impossible by construction; the UI shows
    Applied or Failed and can never diverge from the backend. Enabling Host
    Control through this endpoint requires ``?confirm=true`` (spec section 6).
    """
    if not isinstance(patch, dict) or not patch:
        raise HTTPException(422, detail={"error_code": "INVALID_CONFIG_PATCH", "message": "a non-empty JSON object is required", "details": {}})
    try:
        snapshot = await control_center.update(patch, actor="user", confirm=confirm)
    except ControlModelError as error:
        await store.audit("config.rejected", {"patch_keys": sorted(str(key) for key in patch.keys()), "reason": str(error)[:300]})
        code = "HOST_CONTROL_REQUIRES_CONFIRMATION" if "HOST_CONTROL" in str(error) else "CONFIG_REJECTED"
        raise HTTPException(422, detail={"error_code": code, "message": str(error), "details": {}}) from None
    return snapshot


@app.post(config.api_prefix + "/config/preset")
async def apply_preset(item: PresetIn):
    patch, requires_confirm = PRESETS.get(item.name, ({}, True))
    if requires_confirm and not item.confirm:
        raise HTTPException(403, detail={"error_code": "PRESET_REQUIRES_CONFIRMATION",
                                         "message": f"The {item.name} preset changes multiple security-relevant settings — confirm to apply.",
                                         "details": {"preset": item.name}})
    if control_center.emergency_stopped:
        raise HTTPException(409, detail={"error_code": "SECUREAGENT_STOPPED", "message": "Resume before applying presets.", "details": {}})
    try:
        snapshot = await control_center.update(patch, actor="user")
    except ControlModelError as error:
        raise HTTPException(422, detail={"error_code": "CONFIG_REJECTED", "message": str(error), "details": {}}) from None
    await store.audit("config.preset", {"preset": item.name, "revision": snapshot["revision"]})
    return snapshot


@app.get(config.api_prefix + "/config/events")
async def config_events():
    """SSE stream of configuration revisions for real-time sync (spec 24)."""
    from fastapi.responses import StreamingResponse
    queue = control_center.subscribe()

    async def stream():
        try:
            yield f"event: config\ndata: {json.dumps({'revision': control_center.revision})}\n\n"
            while True:
                try:
                    revision = await asyncio.wait_for(queue.get(), 15)
                except asyncio.TimeoutError:
                    yield ": keepalive\n\n"
                    continue
                yield f"event: config\ndata: {json.dumps({'revision': revision})}\n\n"
        finally:
            control_center.unsubscribe(queue)

    return StreamingResponse(stream(), media_type="text/event-stream",
                             headers={"Cache-Control": "no-store", "X-Accel-Buffering": "no"})


@app.post(config.api_prefix + "/emergency-stop")
async def emergency_stop():
    """EMERGENCY STOP (spec section 7): stop running agent tasks, cancel
    terminal processes, kill process groups, disable autonomous execution,
    disable terminal + network tool access, preserve audit logs."""
    snapshot = await control_center.emergency_stop(actor="user")
    await store.audit("control.emergency_stop.applied", {
        "revision": snapshot["revision"],
        "note": "running processes killed; audit preserved; RESUME restores configured state",
    })
    return snapshot


@app.post(config.api_prefix + "/resume")
async def resume_from_emergency():
    """RESUME (spec section 7): restore the pre-emergency configured state."""
    return await control_center.resume(actor="user")


@app.get(config.api_prefix + "/status")
async def control_status():
    """Live status cards (spec section 17). Every value is measured from the
    real backend — the frontend never infers status from its own state."""
    provider = await get_llm().status()
    gate = control_center
    state = gate.state
    sandbox = terminal_executor.sandbox_status() if terminal_executor else {"available": False, "mechanism": "none"}
    schedules = await store.schedules()
    runs = await store.schedule_runs(200)
    active_jobs = sum(1 for row in schedules if row.get("enabled") and not row.get("cancelled"))
    failed_jobs = sum(1 for row in runs if row.get("status") == "failed")
    completed_jobs = sum(1 for row in runs if row.get("status") == "completed")
    queued_jobs = len(schedules) - active_jobs

    def _terminal_card():
        if gate.emergency_stopped:
            return "BLOCKED"
        if not state.terminal.enabled:
            return "BLOCKED"
        if not terminal_executor or not terminal_executor.available:
            return "OFFLINE"
        if not _terminal_enabled():
            return "OFFLINE"
        if terminal_executor.mode.value == "restricted_agent" and not sandbox.get("available"):
            return "BLOCKED"
        return "ONLINE"

    def _sandbox_card():
        if not state.terminal.enabled or not terminal_executor:
            return "OFFLINE"
        if gate.emergency_stopped:
            return "BLOCKED"
        return "ONLINE" if sandbox.get("available") else "DEGRADED"

    def _security_card():
        if gate.emergency_stopped:
            return "BLOCKED"
        degraded = state.terminal.enabled and terminal_executor and not sandbox.get("available")
        return "DEGRADED" if degraded else "ONLINE"

    cards = {
        "backend": {"status": "ONLINE", "detail": f"database={'ok' if config.database_path.exists() else 'initializing'}"},
        "agent": {"status": "ONLINE" if (state.agent.enabled and not gate.emergency_stopped) else "BLOCKED",
                  "detail": "master switch OFF" if not state.agent.enabled else ("emergency stop" if gate.emergency_stopped else "ready")},
        "terminal": {"status": _terminal_card(), "detail": str(terminal_executor.mode.value) if terminal_executor else "backend unavailable"},
        "sandbox": {"status": _sandbox_card(), "detail": sandbox.get("mechanism", "none")},
        "security": {"status": _security_card(), "detail": "secure mode" if state.secure_mode else "secure mode OFF"},
        "ollama": {"status": "ONLINE" if provider.get("ollama_available") else "OFFLINE",
                   "detail": provider.get("active_provider", "unknown")},
        "network": {"status": "BLOCKED" if (state.network.mode == "disabled" or gate.emergency_stopped) else "ONLINE",
                    "detail": state.network.mode},
        "memory": {"status": "ONLINE" if gate.memory_active() else "BLOCKED", "detail": "master switch OFF" if not state.memory.enabled else "ready"},
        "rag": {"status": "ONLINE" if gate.rag_active() else "BLOCKED", "detail": "master switch OFF" if not state.rag.enabled else "ready"},
        "automation": {"status": "ONLINE" if gate.automation_active() else "BLOCKED",
                       "detail": "paused" if state.automation.paused else ("master switch OFF" if not state.automation.enabled else "ready")},
    }
    return {
        "emergency_stopped": gate.emergency_stopped,
        "revision": gate.revision,
        "cards": cards,
        "automation_jobs": {"active": active_jobs, "queued": max(queued_jobs, 0), "failed": failed_jobs, "completed": completed_jobs},
        "network_telemetry": gate.telemetry.model_dump(),
        "ollama": provider,
    }


@app.get(config.api_prefix + "/security")
async def security_status():
    """Security policy display (spec section 14). Mandatory protections are
    reported with their enforcement source; when a protection cannot be fully
    enforced the status is SECURITY DEGRADED — never silently continue."""
    state = control_center.state
    sandbox = terminal_executor.sandbox_status() if terminal_executor else {"available": False, "mechanism": "none"}
    protections = []
    for name in MANDATORY_PROTECTIONS:
        enforced = bool(getattr(state.security, name))
        protections.append({"name": name, "enabled": enforced, "mandatory": True,
                            "source": "backend policy (not user-modifiable)"})
    degraded = []
    if state.terminal.enabled and terminal_executor and not sandbox.get("available"):
        degraded.append({"component": "terminal_sandbox",
                         "reason": "namespace sandbox unavailable — RESTRICTED_AGENT refuses host execution (fail closed)"})
    if not config.auth_required and config.environment != "development":
        degraded.append({"component": "authentication", "reason": "authentication is disabled outside development"})
    return {
        "secure_mode": state.secure_mode,
        "status": "DEGRADED" if degraded else "ONLINE",
        "protections": protections,
        "degraded": degraded,
        "approval_mode": config.approval_mode,
        "emergency_stopped": control_center.emergency_stopped,
    }


@app.get(config.api_prefix + "/permissions")
async def permissions_overview():
    """Capability matrix + persistent grants (spec section 20)."""
    state = control_center.state
    capabilities = [
        {"capability": "terminal_execute", "allowed": state.terminal.enabled and not control_center.emergency_stopped, "reason": "terminal master switch" if not state.terminal.enabled else None},
        {"capability": "sudo", "allowed": state.sudo.mode != "disabled" and state.terminal.allow_sudo, "reason": f"sudo mode: {state.sudo.mode}"},
        {"capability": "host_control", "allowed": state.host_control.enabled, "reason": "explicit user confirmation required" if not state.host_control.enabled else "active"},
        {"capability": "network_tools", "allowed": state.network.mode != "disabled", "reason": f"network mode: {state.network.mode}"},
        {"capability": "autonomous_execution", "allowed": state.agent.enabled and state.agent.auto_execution, "reason": "agent master switch" if not state.agent.enabled else None},
        {"capability": "scheduled_tasks", "allowed": control_center.automation_active(), "reason": "automation disabled" if not control_center.automation_active() else None},
        {"capability": "document_ingestion", "allowed": state.rag.enabled and state.rag.ingestion_enabled, "reason": None},
        {"capability": "memory_write", "allowed": state.memory.enabled and state.memory.ingestion, "reason": None},
    ]
    return {"capabilities": capabilities, "grants": await store.grants(), "emergency_stopped": control_center.emergency_stopped}


@app.patch(config.api_prefix + "/permissions")
async def permissions_patch(item: PermissionActionIn):
    """Grant/revoke persistent permissions (delegates to the Permission
    Center store; admin grants stay forbidden)."""
    if item.action == "grant":
        if item.permission is None:
            raise HTTPException(422, "permission is required for grant")
        if item.permission is Permission.ADMIN:
            raise HTTPException(422, detail={"error_code": "GRANT_FORBIDDEN", "message": "admin permission cannot be granted persistently", "details": {}})
        created = await store.create_grant(item.permission.value, item.scope, item.note)
        await store.audit("permission.granted", {"grant_id": created["id"], "permission": item.permission.value, "scope": item.scope, "source": "control-center"})
        return {"ok": True, "grant": created}
    if not item.grant_id:
        raise HTTPException(422, "grant_id is required for revoke")
    if not await store.delete_grant(item.grant_id):
        raise HTTPException(404, "grant not found")
    await store.audit("permission.revoked", {"grant_id": item.grant_id, "source": "control-center"})
    return {"ok": True}


@app.patch(config.api_prefix + "/tools/{name}")
async def patch_tool(name: str, item: ToolPatchIn):
    """Enable/disable a registered tool — affects REAL execution (spec 15).

    The Registry refuses to run a disabled tool, so this toggle has an
    immediate runtime effect on both user- and agent-initiated tool calls.
    """
    rows = registry().definitions()
    target = next((row for row in rows if row.name == name), None)
    if target is None:
        raise HTTPException(404, "tool not found")
    tools_map = registry().tools
    tool = tools_map.get(name)
    if tool is None:
        raise HTTPException(404, "tool not found")
    tool.enabled = item.enabled
    tool.disabled_reason = None if item.enabled else "Disabled via Control Center"
    await store.audit("tool.toggled", {"tool": name, "enabled": item.enabled})
    control_center._notify()
    return {"ok": True, "tool": name, "enabled": item.enabled, "definition": tool.definition().model_dump(mode="json")}


@app.get(config.api_prefix + "/audit")
async def audit(limit: int = Query(100, ge=1, le=500), category: str = Query("all", pattern="^(all|agent|terminal|network|security|permission|errors)$")):
    return await store.audits_filtered(limit, category)


@app.post(config.api_prefix + "/audit/export")
async def audit_export():
    """Export the full audit trail to a JSONL file (spec section 16)."""
    rows = await store.audits(500)
    export_dir = config.database_path.parent / "exports"
    export_dir.mkdir(parents=True, exist_ok=True)
    target = export_dir / f"audit-export-{datetime.now(UTC).strftime('%Y%m%d-%H%M%S')}.jsonl"
    payload = "".join(json.dumps(row, default=str, ensure_ascii=False) + "\n" for row in rows)
    target.write_text(payload, encoding="utf-8")
    try:
        target.chmod(0o600)
    except OSError:
        pass
    await store.audit("audit.exported", {"path": str(target), "entries": len(rows)})
    return {"ok": True, "path": str(target), "entries": len(rows)}


@app.post(config.api_prefix + "/audit/clear")
async def audit_clear(item: AuditClearIn):
    """Clear the audit trail — requires explicit confirmation (spec 16)."""
    if not item.confirm:
        raise HTTPException(403, detail={"error_code": "AUDIT_CLEAR_REQUIRES_CONFIRMATION",
                                         "message": "Clearing the audit trail is destructive — repeat with confirm=true.",
                                         "details": {}})
    count = await store.clear_audits()
    # The clear itself is recorded so the trail is never silently empty.
    await store.audit("audit.cleared", {"cleared_entries": count, "actor": "user"})
    return {"ok": True, "cleared_entries": count}


@app.get(config.api_prefix + "/filesystem")
async def filesystem_overview():
    """FILESYSTEM display (spec section 10): workspace, approved paths,
    read/write permissions, protected paths."""
    state = control_center.state
    roots = terminal_executor.allowed_roots() if terminal_executor else [config.workspace_root.resolve()]
    return {
        "workspace": str(config.workspace_root),
        "allowed_paths": [str(path) for path in roots],
        "control_center_paths": state.filesystem.allowed_paths,
        "read_permissions": {"workspace": True, "approved_paths": True, "system_paths": False},
        "write_permissions": {"workspace": True, "approved_paths": state.terminal.enabled, "system_paths": False},
        "protected_paths": state.filesystem.protected_paths,
        "terminal_tools_enabled": config.filesystem_tools_enabled,
    }


_SENSITIVE_PATH_MARKERS = ("/etc/shadow", "/etc/sudoers", "/etc/passwd", "/root/.ssh", "/.ssh",
                           ".pem", ".key", "id_rsa", "id_ed25519", "id_ecdsa", ".env")
# System locations that are never acceptable as terminal workspaces (pseudo
# filesystems, boot assets, and the root home) — rejected even with confirm.
_FORBIDDEN_ROOTS = {"/", "/proc", "/sys", "/dev", "/boot", "/root"}
# Sensitive system locations: adding one requires explicit user confirmation
# in the UI (spec section 10) — the sandbox still jails execution.
_CONFIRM_ROOTS = {"/etc", "/usr", "/var", "/opt", "/srv", "/run", "/lib", "/lib64", "/bin", "/sbin", "/mnt", "/media"}


@app.post(config.api_prefix + "/filesystem/paths")
async def add_filesystem_path(item: FilesystemPathIn):
    """Add an allowed path — validated by the BACKEND canonical path enforcer
    (frontend validation is never trusted, spec section 10)."""
    from app.linux_sandbox import classify_path_sensitivity
    raw = item.path.strip()
    if not raw:
        raise HTTPException(422, "path is required")
    if "\x00" in raw or len(raw) > 4096:
        raise HTTPException(422, "invalid path")
    candidate = Path(raw).expanduser()
    if not candidate.is_absolute():
        raise HTTPException(422, detail={"error_code": "PATH_NOT_ABSOLUTE", "message": "allowed paths must be absolute", "details": {"path": raw}})
    try:
        resolved = candidate.resolve(strict=False)
    except OSError as error:
        raise HTTPException(422, f"path could not be resolved: {error}") from error
    if str(resolved) in _FORBIDDEN_ROOTS or resolved == Path("/"):
        raise HTTPException(403, detail={"error_code": "PATH_FORBIDDEN", "message": f"{resolved} can never be an allowed path", "details": {"path": str(resolved)}})
    workspace = config.workspace_root.resolve()
    if resolved == workspace or workspace in resolved.parents:
        raise HTTPException(422, "the workspace root is already allowed")
    decision = classify_path_sensitivity(str(resolved)) if classify_path_sensitivity else None
    hard_protected = bool(decision and decision.blocked) or "/etc/shadow" in str(resolved) or "/etc/sudoers" in str(resolved)
    # Sensitive locations (system trees and credential-shaped paths) require
    # explicit confirmation; hard-protected locations are refused outright.
    needs_confirmation = (
        any(str(resolved) == root or str(resolved).startswith(root + "/") for root in _CONFIRM_ROOTS)
        or any(marker in str(resolved).lower() for marker in _SENSITIVE_PATH_MARKERS)
    )
    if hard_protected:
        raise HTTPException(403, detail={"error_code": "SENSITIVE_PATH_FORBIDDEN",
                                         "message": f"{resolved} is a protected location and can never be added as an allowed path.",
                                         "details": {"path": str(resolved), "reason": (decision.reason if decision and decision.blocked else "protected location")}})
    if needs_confirmation and not item.confirm:
        raise HTTPException(403, detail={"error_code": "SENSITIVE_PATH_REQUIRES_CONFIRMATION",
                                         "message": f"{resolved} looks like a sensitive location — confirm to allow it.",
                                         "details": {"path": str(resolved)}})
    if not resolved.is_dir():
        raise HTTPException(422, detail={"error_code": "PATH_NOT_DIRECTORY", "message": "allowed paths must be existing directories", "details": {"path": str(resolved)}})
    state = control_center.state
    resolved_str = str(resolved)
    if resolved_str in state.filesystem.allowed_paths:
        return {"ok": True, "path": resolved_str, "already_allowed": True}
    new_paths = [*state.filesystem.allowed_paths, resolved_str]
    try:
        await control_center.update({"filesystem": {"allowed_paths": new_paths}}, actor="user")
    except ControlModelError as error:
        raise HTTPException(422, detail={"error_code": "CONFIG_REJECTED", "message": str(error), "details": {}}) from None
    await store.audit("filesystem.path_added", {"path": resolved_str})
    return {"ok": True, "path": resolved_str}


@app.post(config.api_prefix + "/filesystem/paths/remove")
@app.delete(config.api_prefix + "/filesystem/paths")
async def remove_filesystem_path(item: FilesystemPathIn):
    candidate = Path(item.path.strip()).expanduser()
    try:
        resolved = str(candidate.resolve(strict=False))
    except OSError:
        resolved = str(candidate)
    state = control_center.state
    if resolved not in state.filesystem.allowed_paths:
        raise HTTPException(404, "path is not in the allowed list")
    new_paths = [path for path in state.filesystem.allowed_paths if path != resolved]
    try:
        await control_center.update({"filesystem": {"allowed_paths": new_paths}}, actor="user")
    except ControlModelError as error:
        raise HTTPException(422, detail={"error_code": "CONFIG_REJECTED", "message": str(error), "details": {}}) from None
    await store.audit("filesystem.path_removed", {"path": resolved})
    return {"ok": True, "path": resolved}


@app.post(config.api_prefix + "/automation/{action}")
async def automation_action(action: str):
    """Pause All / Resume All / Cancel All (spec section 13)."""
    if action not in {"pause_all", "resume_all", "cancel_all"}:
        raise HTTPException(404, "unknown automation action")
    state = control_center.state
    if action == "pause_all":
        await control_center.update({"automation": {"paused": True}}, actor="user")
        await store.audit("automation.paused_all", {})
        return {"ok": True, "action": "pause_all", "paused": True, "cancelled": []}
    if action == "resume_all":
        await control_center.update({"automation": {"paused": False}}, actor="user")
        await store.audit("automation.resumed_all", {})
        return {"ok": True, "action": "resume_all", "paused": False}
    # cancel_all: cancel running jobs now and disable pending schedules.
    cancelled = []
    if automation:
        result = await automation.cancel_all()
        cancelled = result.get("cancelled_jobs", [])
    schedules = await store.schedules()
    for row in schedules:
        if row.get("enabled") and not row.get("cancelled"):
            await store.cancel_schedule(row["id"])
    await store.audit("automation.cancelled_all", {"cancelled_jobs": cancelled})
    return {"ok": True, "action": "cancel_all", "cancelled": cancelled}


static_dir = Path(__file__).resolve().parent.parent / "static"
if static_dir.is_dir():
    app.mount("/", StaticFiles(directory=static_dir, html=True), name="dashboard")


# --------------------------------------------------------------------------- #
# Production host-binding guard
# --------------------------------------------------------------------------- #
# When the server is launched with --host 0.0.0.0 or any non-loopback
# address in production mode without authentication, refuse to start.
# This is the last line of defence against accidentally exposing the
# terminal API on a LAN.
def _validate_host_binding_for_production() -> None:
    if config.environment != "production":
        return
    if not config.auth_required:
        raise RuntimeError(
            "REFUSING_TO_START: production mode requires SECURE_AGENT_AUTH_REQUIRED=true "
            "and a strong SECURE_AGENT_API_TOKEN (>= 32 chars). The terminal API "
            "must never be exposed on a network without authentication."
        )


_validate_host_binding_for_production()
