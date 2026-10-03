from app.agents import AgentInput, ManagerAgent
from app.config import settings
from app.models import ExecutionError, ExecutionResponse, TaskStatus


def _multi_agent_enabled() -> bool:
    """Phase 15 opt-in flag. Fail closed: any configuration problem keeps the
    stable single-agent path."""
    try:
        return bool(settings().multi_agent_enabled)
    except Exception:
        return False

def execution_response(task, provider, *, roles=None, review_approved=True, notes=None):
    successful = [step for step in task.steps if step.result and step.result.success]
    if task.status == TaskStatus.WAITING:
        response_type = 'approval_required'
    elif task.status == TaskStatus.FAILED:
        response_type = 'controlled_error'
    elif successful:
        response_type = 'multi_step_result' if len(successful) > 1 else 'deterministic_local_result'
    elif task.intent == 'requires_model':
        response_type = 'llm_response' if provider == 'OLLAMA' else 'controlled_error'
    else:
        response_type = 'direct_answer'
    error = None
    if response_type == 'controlled_error':
        message = task.errors[0] if task.errors else (task.answer or 'The request could not be completed.')
        code = 'AI_REASONING_UNAVAILABLE' if task.intent == 'requires_model' else 'AGENT_EXECUTION_FAILED'
        error = ExecutionError(error_code=code, message=message, details={'task_id': task.id})
    return ExecutionResponse(response_type=response_type,status=task.status,answer=task.answer,task=task,provider=provider,roles=roles or [],review_approved=review_approved,notes=notes or [],error=error)

class Orchestrator:
    def __init__(self,agent):
        self.manager=ManagerAgent(agent)
        # Phase 15 — optional multi-agent layer. OFF by default; when the
        # operator enables SECURE_AGENT_MULTI_AGENT_ENABLED the MultiAgentManager
        # routes specialist delegation through the SAME central Registry,
        # Control Center gates and audit trail. The single-agent ManagerAgent
        # remains the fallback for every unrouted request and any failure.
        from app.multi_agent import MultiAgentManager, build_roles
        # ``settings_fn`` is read at CALL time (not import time) so tests and
        # embedding applications can monkeypatch ``app.multi_agent.settings``
        # after construction and still drive fresh configuration. Production
        # always resolves to the cached global ``settings()``.
        self.multi_agent = MultiAgentManager(
            agent, build_roles(agent.tools),
            settings_fn=lambda: __import__("app.multi_agent", fromlist=["settings"]).settings())
    async def run(self,request):
        if _multi_agent_enabled():
            try:
                return await self.multi_agent.run(request)
            except Exception as error:
                # Fail closed visibly: record the refusal, then fall back to
                # the stable single-agent path (never widen privileges).
                await self.manager.core.memory.audit("multi_agent.fallback", {
                    "reason": f"{type(error).__name__}: single-agent fallback"})
        result=await self.manager.run(AgentInput(request=request))
        roles=['manager',result.task.intent if result.task else 'unknown','reviewer','security']
        provider = getattr(self.manager.core.llm, 'active', getattr(self.manager.core.llm, 'name', type(self.manager.core.llm).__name__))
        return execution_response(result.task, provider, roles=roles, review_approved=result.approved, notes=result.notes)
