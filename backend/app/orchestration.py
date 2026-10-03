from app.agents import AgentInput, ManagerAgent
from app.models import ExecutionError, ExecutionResponse, TaskStatus

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
    def __init__(self,agent):self.manager=ManagerAgent(agent)
    async def run(self,request):
        result=await self.manager.run(AgentInput(request=request))
        roles=['manager',result.task.intent if result.task else 'unknown','reviewer','security']
        provider = getattr(self.manager.core.llm, 'active', getattr(self.manager.core.llm, 'name', type(self.manager.core.llm).__name__))
        return execution_response(result.task, provider, roles=roles, review_approved=result.approved, notes=result.notes)
