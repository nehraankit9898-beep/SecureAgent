from __future__ import annotations
import asyncio,json,sys,tempfile,types
from datetime import UTC,datetime,timedelta
from pathlib import Path
sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
import pydantic
if 'pydantic_settings' not in sys.modules:
 m=types.ModuleType('pydantic_settings');m.BaseSettings=pydantic.BaseModel;m.SettingsConfigDict=dict;sys.modules['pydantic_settings']=m
from app import agent as agent_module
from app.agent import Agent
from app.config import Settings
from app.memory import MemoryStore
from app.models import AgentRequest,ChatResponse,Permission,ScheduleCreate,TaskStatus
from app.tools.factory import _build_registry
class FakePlanner:
 async def chat(self,r):
  if r.json_mode:return ChatResponse(content=json.dumps({'mode':'plan','intent':'file','steps':[{'title':'Write approved file','tool':'write_file','arguments':{'path':'approved.txt','content':'verified','overwrite':True}}]}),model='acceptance')
  return ChatResponse(content='Verified write completed.',model='acceptance')
async def main():
 with tempfile.TemporaryDirectory(prefix='secureagent-acceptance-') as d:
  root=Path(d)/'workspace';root.mkdir();db=Path(d)/'agent.db'
  c=Settings(environment='test',auth_required=True,api_token='x'*40,database_path=db,workspace_root=root,tools_enabled=True,filesystem_tools_enabled=True,require_approval_for_high_risk=True)
  agent_module.settings=lambda:c
  registry=_build_registry(c,root);defs={x.name:x for x in registry.definitions()}
  assert defs['write_file'].requires_approval and not defs['python_executor'].enabled and not defs['web_search'].enabled
  store=MemoryStore(db);await store.init();core=Agent(FakePlanner(),registry,store)
  task=await core.run(AgentRequest(message='write approved.txt',approved_permissions={Permission.WRITE}))
  assert task.status==TaskStatus.WAITING and not (root/'approved.txt').exists()
  step=task.steps[task.current_step];task=await core.resume(task.id,{Permission.WRITE},step.id)
  assert task.status==TaskStatus.DONE and (root/'approved.txt').read_text()=='verified'
  schedule=ScheduleCreate(name='approval test',prompt='calculate 2+2',run_at=datetime.now(UTC)+timedelta(minutes=5),approved_permissions={Permission.READ},allowed_tools=['calculator'])
  created=await store.create_schedule_pending(schedule,True);assert not created['enabled'];assert await store.approve_schedule(created['id'])
  saved=next(x for x in await store.schedules() if x['id']==created['id']);assert saved['enabled'] and saved['policy']['approval_granted']
 print('OFFLINE_ACCEPTANCE_PASS')
if __name__=='__main__':asyncio.run(main())
