import asyncio
from uuid import uuid4
from contextlib import suppress
from datetime import UTC,datetime,timedelta

from app.agent import Agent
from app.agents import ScopedRegistry
from app.models import AgentRequest,Permission
from app.tools.factory import registry_for_workspace


def _control_gate():
    try:
        from app.control_center import get_control_center
        return get_control_center()
    except Exception:
        return None


SAFE_AUTOMATION_TOOLS={'calculator','date_time','text_processing','list_files','read_file'}
class AutomationEngine:
    def __init__(self,store,agent_factory,poll_seconds=10,max_concurrent=2,max_runtime=300):self.store=store;self.agent_factory=agent_factory;self.poll_seconds=poll_seconds;self.max_concurrent=max_concurrent;self.max_runtime=max_runtime;self.stop_event=asyncio.Event();self.worker=None;self.running={};self.owner_id=str(uuid4())
    def start(self):
        if not self.worker:self.worker=asyncio.create_task(self.loop(),name='SecureAgent-automation')
    async def close(self):
        self.stop_event.set()
        for task in self.running.values():task.cancel()
        if self.worker:
            self.worker.cancel()
            with suppress(asyncio.CancelledError):await self.worker
    async def loop(self):
        while not self.stop_event.is_set():
            # Control Center AUTOMATION master gate: when the switch is OFF,
            # paused, or emergency stop is active, the engine claims no new
            # schedule work (spec sections 2/13). The loop keeps polling so
            # flipping the switch back ON takes effect without a restart.
            gate=_control_gate()
            if gate is not None and not gate.automation_active():
                try:await asyncio.wait_for(self.stop_event.wait(),self.poll_seconds)
                except asyncio.TimeoutError:pass
                continue
            # Lease only as many due schedules as can start right now: leasing
            # more would park them invisibly until the lease expires and delay
            # their execution behind an idle capacity slot.
            capacity=self.max_concurrent-len(self.running)
            if capacity>0:
                for item in await self.store.claim_due_schedules(datetime.now(UTC),self.owner_id,self.max_runtime+30,limit=capacity):
                    if item['id'] not in self.running and len(self.running) < self.max_concurrent:
                        task=asyncio.create_task(self.run_item(item),name='schedule-'+item['id']);self.running[item['id']]=task;task.add_done_callback(lambda _,i=item['id']:self.running.pop(i,None))
            try:await asyncio.wait_for(self.stop_event.wait(),self.poll_seconds)
            except asyncio.TimeoutError:pass
    async def cancel_all(self):
        """EMERGENCY STOP / Cancel All: cancel every running schedule task."""
        cancelled=list(self.running.keys())
        for task in self.running.values():task.cancel()
        return {'cancelled_jobs':cancelled}

    async def run_item(self,item):
        policy=item.get('policy',{});permissions={Permission(value) for value in item['permissions'] if value!='admin'}
        if policy.get('network_policy','deny')=='deny':permissions.discard(Permission.NETWORK)
        # Execute is never autonomous unless both permission and an explicit allowlisted tool are stored.
        allowed=set(policy.get('allowed_tools',[]))
        if policy.get('network_policy','deny')=='deny':allowed.discard('web_search')
        if Permission.EXECUTE not in permissions:allowed.discard('run_tests')
        timeout=min(max(int(policy.get('max_runtime',300)),10),self.max_runtime);retries=min(max(int(policy.get('retry_limit',0)),0),3);max_steps=min(max(int(policy.get('max_steps',1)),1),20);workspace=policy.get('workspace','.');errors=[];task=None;scoped=None
        try:
            factory_result=self.agent_factory()
            base=await factory_result if hasattr(factory_result,'__await__') else factory_result
            workspace_registry=registry_for_workspace(workspace)
            selected=[workspace_registry.tools[name] for name in allowed if name in workspace_registry.tools]
            # registry_for_workspace() is the single source of truth for tool
            # metadata; Registry.add() rejects incomplete tool policy before a
            # tool can enter the registry.  Keep a fail-closed fallback for
            # custom/test registries that do not expose the optional metadata.
            if any(not getattr(tool,'idempotent',False) or getattr(getattr(tool,'risk_level',None),'value','high') != 'low' for tool in selected):
                retries=0
            scoped=Agent(base.llm,ScopedRegistry(workspace_registry,allowed),base.memory,max_steps=max_steps,max_tool_calls=max_steps,max_retries=0)
        except Exception as error:errors.append(f'{type(error).__name__}: {str(error)[:300]}')
        for attempt in range(retries+1 if scoped else 0):
            try:
                task=await asyncio.wait_for(scoped.run(AgentRequest(message=item['prompt'],approved_permissions=permissions)),timeout)
                if task.status.value=='completed':break
                errors.extend(task.errors)
            except asyncio.CancelledError:errors.append('cancelled');break
            except Exception as error:errors.append(f'{type(error).__name__}: {str(error)[:300]}')
        status=task.status.value if task else ('cancelled' if 'cancelled' in errors else 'failed')
        await self.store.record_schedule_run(item['id'],status,task.id if task else None,task.answer if task else None,errors)
        await self.store.audit('schedule.executed',{'schedule_id':item['id'],'task_id':task.id if task else None,'status':status,'workspace':workspace,'allowed_tools':sorted(allowed),'permissions':sorted(value.value for value in permissions),'max_steps':max_steps,'max_runtime':timeout,'retry_limit':retries,'network_policy':policy.get('network_policy','deny')})
        if item['kind']=='once' or status=='cancelled':await self.store.disable_schedule(item['id'])
        elif item.get('interval_seconds'):await self.store.advance_schedule(item['id'],datetime.now(UTC)+timedelta(seconds=item['interval_seconds']))
