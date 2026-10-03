import asyncio
from types import SimpleNamespace

import pytest
from pydantic import ValidationError

import app.automation as automation_module
from app.agent import Agent
from app.automation import AutomationEngine
from app.knowledge import KnowledgeStore
from app.memory_service import MemoryService
from app.models import ChatResponse,MemoryIn,MemoryPatch,Permission,ScheduleCreate
from app.sandbox import SandboxPolicy,read_stream_limited
from app.tools.base import Registry
from app.tools.builtins import Calculator

@pytest.mark.asyncio
async def test_memory_rejects_secret_in_category():
 class Store:
  async def create(self,item):raise AssertionError('store reached')
  async def patch(self,item_id,patch):raise AssertionError('store reached')
 service=MemoryService(Store())
 with pytest.raises(ValueError):await service.create(MemoryIn(content='safe',category='token=secret'))
 with pytest.raises(ValueError):await service.update('id',MemoryPatch(category='password: secret'))

def test_schedule_rejects_admin_duplicate_and_malformed_tools():
 base=dict(name='x',prompt='x',kind='interval',interval_seconds=60)
 with pytest.raises(ValidationError):ScheduleCreate(**base,approved_permissions={Permission.ADMIN})
 with pytest.raises(ValidationError):ScheduleCreate(**base,allowed_tools=['read_file','read_file'])
 with pytest.raises(ValidationError):ScheduleCreate(**base,allowed_tools=['../tool'])

@pytest.mark.asyncio
async def test_automation_enforces_stored_policy(monkeypatch):
 captured={}
 class Store:
  async def record_schedule_run(self,*args):captured['run']=args
  async def audit(self,event,details):captured['audit']=details
  async def disable_schedule(self,item_id):captured['disabled']=item_id
 class Tools:tools={name:object() for name in ('read_file','web_search','run_tests')}
 class Core:llm=object();tools=Tools();memory=object()
 class ScheduledAgent:
  def __init__(self,llm,tools,memory,**limits):captured['allowed']=tools.allowed;captured['limits']=limits
  async def run(self,request):captured['permissions']=request.approved_permissions;return SimpleNamespace(status=SimpleNamespace(value='completed'),id='task',answer='ok',errors=[])
 def workspace_registry(workspace):captured['workspace']=workspace;return Tools()
 monkeypatch.setattr(automation_module,'registry_for_workspace',workspace_registry)
 monkeypatch.setattr(automation_module,'Agent',ScheduledAgent)
 item={'id':'s','prompt':'read','kind':'once','interval_seconds':None,'permissions':['read','network','admin'],'policy':{'workspace':'project','allowed_tools':['read_file','web_search','run_tests'],'max_steps':2,'max_runtime':17,'retry_limit':0,'network_policy':'deny'}}
 await AutomationEngine(Store(),lambda:Core()).run_item(item)
 assert captured['workspace']=='project' and captured['allowed']=={'read_file'}
 assert captured['permissions']=={Permission.READ}
 assert captured['limits']=={'max_steps':2,'max_tool_calls':2,'max_retries':0}
 assert captured['audit']['workspace']=='project' and captured['audit']['max_runtime']==17

@pytest.mark.asyncio
async def test_agent_rejects_over_policy_plan():
 class LLM:
  async def chat(self,request):return ChatResponse(content='{"mode":"plan","steps":[{"title":"1","tool":"calculator","arguments":{"expression":"1"}},{"title":"2","tool":"calculator","arguments":{"expression":"2"}}]}',model='fake')
 tools=Registry();tools.add(Calculator())
 with pytest.raises(ValueError):await Agent(LLM(),tools,object(),max_steps=1).plan('x',[],[],None)

def test_sandbox_digest_validation_is_exact():
 for image in ('python:3.14','image@sha256:x','image@sha256:'+'g'*64):
  with pytest.raises(ValueError):SandboxPolicy(image,10,128,.5,32,1000)

@pytest.mark.asyncio
async def test_sandbox_output_is_memory_bounded():
 stream=asyncio.StreamReader();stream.feed_data(b'x'*5000);stream.feed_eof()
 output,truncated=await read_stream_limited(stream,100)
 assert output==b'x'*100 and truncated

@pytest.mark.asyncio
async def test_rag_candidate_scan_is_bounded(tmp_path):
 captured=[]
 class Memory:
  async def document_chunks(self,document_id,limit):captured.append(limit);return []
 class LLM:
  async def embed(self,texts):return [[1.0]]
 store=KnowledgeStore(Memory(),LLM(),tmp_path,1000);store.max_candidates=123
 assert await store.search('query')==[] and captured==[123]
