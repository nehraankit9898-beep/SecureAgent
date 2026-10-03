from datetime import UTC, datetime, timedelta
from enum import StrEnum
import re
from typing import Any, Literal
from uuid import uuid4

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

class Message(BaseModel):
    role:Literal['system','user','assistant'];content:str=Field(min_length=1,max_length=100000)
    @field_validator('content')
    @classmethod
    def nonblank(cls,value):
        if not value.strip():raise ValueError('blank message')
        return value
class ChatRequest(BaseModel):
    messages:list[Message]=Field(min_length=1,max_length=200)
    model:str|None=None
    temperature:float=Field(.2,ge=0,le=2)
    json_mode:bool=False
    # Trusted structured copy of the original request. Internal planners set
    # this explicitly instead of asking providers to scrape prompt text.
    user_request:str|None=Field(None,min_length=1,max_length=50000)
class ChatResponse(BaseModel):content:str=Field(min_length=1,max_length=100000);model:str=Field(min_length=1,max_length=300);prompt_tokens:int|None=Field(None,ge=0,le=10000000);completion_tokens:int|None=Field(None,ge=0,le=10000000)
class Permission(StrEnum):SAFE='safe';READ='read';WRITE='write';EXECUTE='execute';NETWORK='network';SCHEDULE='schedule';AUTOMATION='automation';ADMIN='admin'
class RiskLevel(StrEnum):LOW='low';MEDIUM='medium';HIGH='high';CRITICAL='critical'
class ToolDef(BaseModel):
    name:str
    description:str
    category:str
    risk_level:RiskLevel
    required_permissions:list[Permission]
    permissions:list[Permission]
    input_schema:dict[str,Any]
    output_schema:dict[str,Any]
    timeout_seconds:float
    network_required:bool
    sandbox_required:bool
    audit_required:bool
    idempotent:bool
    enabled:bool
    requires_approval:bool
    disabled_reason:str|None=None
    platforms:list[str]=Field(default_factory=lambda:['linux','windows','macos'])

class ToolResult(BaseModel):name:str;success:bool;output:dict[str,Any]|None=None;error:str|None=None;code:str|None=None;retryable:bool=False;duration_ms:int=0
class StepStatus(StrEnum):PENDING='pending';RUNNING='running';WAITING='waiting_confirmation';DONE='completed';FAILED='failed';CANCELLED='cancelled'
class TaskStatus(StrEnum):PLANNING='planning';RUNNING='running';WAITING='waiting_confirmation';DONE='completed';FAILED='failed';CANCELLED='cancelled'
class Step(BaseModel):id:str=Field(default_factory=lambda:str(uuid4()));title:str;tool:str;arguments:dict[str,Any]=Field(default_factory=dict);status:StepStatus=StepStatus.PENDING;result:ToolResult|None=None
class Task(BaseModel):id:str=Field(default_factory=lambda:str(uuid4()));conversation_id:str=Field(default_factory=lambda:str(uuid4()));goal:str;intent:str='general';status:TaskStatus=TaskStatus.PLANNING;steps:list[Step]=Field(default_factory=list);current_step:int=0;errors:list[str]=Field(default_factory=list);answer:str|None=None;created_at:datetime=Field(default_factory=lambda:datetime.now(UTC));updated_at:datetime=Field(default_factory=lambda:datetime.now(UTC))
class AgentRequest(BaseModel):
    model_config=ConfigDict(extra='forbid');message:str=Field(min_length=1,max_length=50000);conversation_id:str|None=None;model:str|None=None;approved_permissions:set[Permission]=Field(default_factory=set)
class ExecutionError(BaseModel):
    error_code:str
    message:str
    details:dict[str,Any]=Field(default_factory=dict)
class ExecutionResponse(BaseModel):
    response_type:Literal['direct_answer','tool_result','multi_step_result','approval_required','llm_response','deterministic_local_result','controlled_error']
    status:TaskStatus
    answer:str|None=None
    task:Task
    provider:str
    roles:list[str]=Field(default_factory=list)
    review_approved:bool=True
    notes:list[str]=Field(default_factory=list)
    error:ExecutionError|None=None
class ResumeRequest(BaseModel):
    approved_permissions:set[Permission]
    scope:Literal['once','session']='once'
def _json_limits(value,depth=0):
    if depth>10:raise ValueError('JSON nesting exceeds limit')
    if isinstance(value,dict):
        if len(value)>100:raise ValueError('too many object fields')
        for key,item in value.items():
            if not isinstance(key,str) or len(key)>200:raise ValueError('invalid object key')
            _json_limits(item,depth+1)
    elif isinstance(value,list):
        if len(value)>500:raise ValueError('array exceeds limit')
        for item in value:_json_limits(item,depth+1)
    elif isinstance(value,str) and len(value)>50000:raise ValueError('string exceeds limit')

class PlanStep(BaseModel):
    title:str=Field(min_length=1,max_length=500);tool:str=Field(min_length=1,max_length=64);arguments:dict[str,Any]=Field(default_factory=dict)
    @field_validator('arguments')
    @classmethod
    def bounded_arguments(cls,value):
        import json
        _json_limits(value)
        if len(json.dumps(value,separators=(',',':')).encode())>100000:raise ValueError('tool arguments exceed byte limit')
        return value
class Plan(BaseModel):mode:Literal['direct','plan'];intent:str=Field('general',max_length=200);direct_answer:str|None=Field(None,max_length=100000);steps:list[PlanStep]=Field(default_factory=list,max_length=20)
class MemoryIn(BaseModel):content:str=Field(min_length=1,max_length=10000);category:str=Field('preference',max_length=100)
class MemoryPatch(BaseModel):content:str|None=Field(None,min_length=1,max_length=10000);category:str|None=Field(None,min_length=1,max_length=100)
class MemoryItem(BaseModel):id:str;content:str;category:str;created_at:datetime;updated_at:datetime
class ScheduleCreate(BaseModel):
    name:str=Field(min_length=1,max_length=120);prompt:str=Field(min_length=1,max_length=20000);kind:Literal['once','interval']='once';run_at:datetime|None=None;interval_seconds:int|None=Field(None,ge=60,le=31536000)
    approved_permissions:set[Permission]=Field(default_factory=set);allowed_tools:list[str]=Field(default_factory=list,max_length=50);workspace:str=Field('.',min_length=1,max_length=500);max_steps:int=Field(8,ge=1,le=20);max_runtime:int=Field(300,ge=10,le=3600);network_policy:Literal['deny','allow']='deny';retry_limit:int=Field(0,ge=0,le=3);enabled:bool=True
    @field_validator('approved_permissions')
    @classmethod
    def restricted_permissions(cls,value):
        if Permission.ADMIN in value:raise ValueError('scheduled tasks cannot receive admin permission')
        return value
    @field_validator('allowed_tools')
    @classmethod
    def valid_allowed_tools(cls,value):
        if len(value)!=len(set(value)) or any(not re.fullmatch(r'[a-z][a-z0-9_]{0,63}',name) for name in value):raise ValueError('invalid allowed_tools')
        return value
    @model_validator(mode='after')
    def validate_schedule(self):
        if self.kind=='once' and not self.run_at:raise ValueError('run_at is required for one-time schedules')
        if self.run_at:
            if self.run_at.tzinfo is None or self.run_at.utcoffset() is None:raise ValueError('run_at must include an explicit timezone')
            normalized=self.run_at.astimezone(UTC);now=datetime.now(UTC)
            if normalized<=now:raise ValueError('run_at must be in the future')
            if normalized>now+timedelta(days=3660):raise ValueError('run_at exceeds scheduling horizon')
            self.run_at=normalized
        if self.kind=='interval' and not self.interval_seconds:raise ValueError('interval_seconds is required for interval schedules')
        if self.network_policy=='deny' and Permission.NETWORK in self.approved_permissions:raise ValueError('network permission conflicts with deny policy')
        return self
class SchedulePatch(BaseModel):
    name:str|None=Field(None,min_length=1,max_length=120)
    prompt:str|None=Field(None,min_length=1,max_length=20000)
    run_at:datetime|None=None
    interval_seconds:int|None=Field(None,ge=60,le=31536000)
    enabled:bool|None=None
    @field_validator('run_at')
    @classmethod
    def valid_run_at(cls,value):
        if value is None:return value
        if value.tzinfo is None or value.utcoffset() is None:raise ValueError('run_at must include an explicit timezone')
        value=value.astimezone(UTC)
        if value<=datetime.now(UTC):raise ValueError('run_at must be in the future')
        return value
class DocumentIn(BaseModel):
    path:str=Field(min_length=1,max_length=1000)
    title:str|None=Field(None,max_length=300)
    reindex:bool=False
    metadata:dict[str,str]=Field(default_factory=dict)

    @field_validator('metadata')
    @classmethod
    def bounded_metadata(cls,value):
        if len(value)>50:raise ValueError('too many metadata entries')
        total=0
        for key,item in value.items():
            if not key or len(key)>100 or len(item)>1000 or any(ord(char)<32 for char in key+item):raise ValueError('invalid metadata')
            total+=len(key.encode())+len(item.encode())
        if total>20000:raise ValueError('metadata exceeds byte limit')
        return value
class DocumentSearch(BaseModel):query:str=Field(min_length=2,max_length=2000);limit:int=Field(6,ge=1,le=20);document_id:str|None=None;min_score:float=Field(0,ge=-1,le=1)
class TerminalExecuteIn(BaseModel):
    command:str=Field(min_length=1,max_length=8000)
    cwd:str=Field('.',max_length=4096)
    timeout_seconds:float=Field(30,gt=0,le=600)
    # user-initiated executes confirm high-risk commands in the UI; the flag
    # is an explicit acknowledgement, never a policy bypass
    confirm:bool=False
    task_id:str|None=None
    session_id:str|None=None
class GrantIn(BaseModel):
    permission:Permission
    scope:Literal['always']='always'
    note:str=Field('',max_length=200)
class GrantItem(BaseModel):
    id:str;permission:Permission;scope:str;note:str;created_at:str;expires_at:str|None=None

# --- Control Center request bodies ---------------------------------------- #
class AuditClearIn(BaseModel):
    # Clearing the audit trail is destructive and must be explicitly confirmed.
    confirm:bool
class PresetIn(BaseModel):
    name:Literal['safe','development','security_lab','full_control']
    confirm:bool=False
class ToolPatchIn(BaseModel):
    enabled:bool
class FilesystemPathIn(BaseModel):
    path:str=Field(min_length=1,max_length=4096)
    # Adding a sensitive location requires explicit confirmation in the UI.
    confirm:bool=False
class PermissionActionIn(BaseModel):
    action:Literal['grant','revoke']
    permission:Permission|None=None
    scope:Literal['always']='always'
    note:str=Field('',max_length=200)
    grant_id:str|None=None
class AutomationActionIn(BaseModel):
    action:Literal['pause_all','resume_all','cancel_all']
