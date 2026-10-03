import ast,asyncio,math,operator,re,sys
from datetime import UTC,datetime
from pathlib import Path
from typing import Any,Literal
from zoneinfo import ZoneInfo,ZoneInfoNotFoundError
from pydantic import BaseModel,ConfigDict,Field
from app.config import settings
from app.models import Permission, Reversibility, RiskLevel
from app.tools.base import Tool
from app.workspace import WorkspacePolicy
class CalcIn(BaseModel):expression:str=Field(min_length=1,max_length=500)
class CalcOut(BaseModel):result:int|float
class Calculator(Tool):
 name='calculator';description='Safely evaluate arithmetic';category='utility';risk_level=RiskLevel.LOW;input_model=CalcIn;output_model=CalcOut
 async def invoke(self,a):
  ops={ast.Add:operator.add,ast.Sub:operator.sub,ast.Mult:operator.mul,ast.Div:operator.truediv,ast.FloorDiv:operator.floordiv,ast.Mod:operator.mod,ast.Pow:operator.pow}
  def ev(n,d=0):
   if d>20:raise ValueError('expression too complex')
   if isinstance(n,ast.Constant) and type(n.value) in (int,float):return n.value
   if isinstance(n,ast.Name) and n.id in {'pi','e'}:return {'pi':math.pi,'e':math.e}[n.id]
   if isinstance(n,ast.UnaryOp) and isinstance(n.op,(ast.UAdd,ast.USub)):return ev(n.operand,d+1)*(1 if isinstance(n.op,ast.UAdd) else -1)
   if isinstance(n,ast.BinOp) and type(n.op) in ops:
    x,y=ev(n.left,d+1),ev(n.right,d+1)
    if isinstance(n.op,ast.Pow) and abs(y)>100:raise ValueError('exponent too large')
    return ops[type(n.op)](x,y)
   raise ValueError('only arithmetic is allowed')
  z=ev(ast.parse(a['expression'],mode='eval').body)
  if not math.isfinite(float(z)):raise ValueError('non-finite result')
  return {'result':z}
class TimeIn(BaseModel):timezone:str='UTC'
class TimeOut(BaseModel):iso_datetime:str;timezone:str
class DateTimeTool(Tool):
 name='date_time';description='Current time in an IANA timezone';category='utility';risk_level=RiskLevel.LOW;input_model=TimeIn;output_model=TimeOut
 async def invoke(self,a):
  try:z=ZoneInfo(a['timezone'])
  except ZoneInfoNotFoundError as e:raise ValueError('unknown timezone') from e
  return {'iso_datetime':datetime.now(UTC).astimezone(z).isoformat(),'timezone':a['timezone']}
class TextIn(BaseModel):text:str=Field(max_length=100000);operation:Literal['word_count','character_count','normalize_whitespace']
class TextOut(BaseModel):result:str|int
class TextTool(Tool):
 name='text_processing';description='Count or normalize text';category='utility';risk_level=RiskLevel.LOW;input_model=TextIn;output_model=TextOut
 async def invoke(self,a):return {'result':len(re.findall(r'\b\w+\b',a['text'])) if a['operation']=='word_count' else len(a['text']) if a['operation']=='character_count' else ' '.join(a['text'].split())}
class FileBase(Tool):
 # Phase 7: workspace-relative names that policy protects from mutation
 # unless the caller supplies the explicit PROTECTED-OVERRIDE token.
 WORKSPACE_PROTECTED_RELPATHS = ("memory", "knowledge", ".secureagent-config")
 def __init__(self,root:Path,limit=20000):
  from app.config import settings
  c=settings()
  protected=list(getattr(c,"workspace_protected_paths",()) or ())
  self.policy=WorkspacePolicy(root,c.max_read_bytes,c.max_write_bytes,c.max_search_file_bytes,c.max_search_files,c.max_directory_depth,protected);self.root=self.policy.root;self.limit=limit
 def path(self,p):return self.policy.resolve(p)
 def override(self,a):return a.get('policy_override')==WorkspacePolicy.PROTECTED_TOKEN
class ListIn(BaseModel):path:str='.';recursive:bool=False;limit:int=Field(200,ge=1,le=1000)
class ListOut(BaseModel):entries:list[dict[str,Any]];truncated:bool
class ListFiles(FileBase):
 name='list_files';description='List bounded workspace files';category='filesystem';risk_level=RiskLevel.LOW;input_model=ListIn;output_model=ListOut;permissions=frozenset({Permission.READ})
 async def invoke(self,a):
  p=self.policy.resolve(a['path'],True);out=[];seen=0
  if not p.is_dir():raise ValueError('not a directory')
  for x in (self.policy.walk_bounded(a['path'], self.policy.max_search_files, stop_at_limit=True) if a['recursive'] else p.iterdir()):
   seen+=1
   if x.is_symlink():continue
   if seen>self.policy.max_search_files or len(out)>=a['limit']:return {'entries':out,'truncated':True}
   r=x.relative_to(self.root)
   if len(r.parts)>self.policy.max_depth:continue
   out.append({'path':r.as_posix(),'type':'directory' if x.is_dir() else 'file','size':None if x.is_dir() else x.stat().st_size})
  return {'entries':out,'truncated':False}
class ReadIn(BaseModel):path:str
class ReadOut(BaseModel):content:str;truncated:bool;sha256:str;binary:bool=Field(default=False);encoding:str='utf-8';size:int=0;protected:bool=False
class ReadFile(FileBase):
 name='read_file';description='Stream bounded UTF-8 workspace text';category='filesystem';risk_level=RiskLevel.LOW;input_model=ReadIn;output_model=ReadOut;permissions=frozenset({Permission.READ})
 async def invoke(self,a):
  import hashlib
  content,truncated,data=self.policy.read_text(a['path'])
  binary=b'\x00' in data[:8192]
  return {'content':'' if binary else content[:self.limit],'truncated':(not binary and (truncated or len(content)>self.limit)),'sha256':hashlib.sha256(data).hexdigest(),'binary':binary,'encoding':'binary' if binary else 'utf-8','size':len(data),'protected':self.policy.is_protected(a['path'])}
class WriteIn(BaseModel):path:str;content:str;overwrite:bool=False;create_parents:bool=True;policy_override:Literal['PROTECTED-OVERRIDE']|None=None
class WriteOut(BaseModel):path:str;bytes_written:int;backup_path:str|None=None
class WriteFile(FileBase):
 name='write_file';description='Atomically write bounded workspace text with optional pre-overwrite backup';category='filesystem';risk_level=RiskLevel.HIGH;idempotent=False;reversibility=Reversibility.REVERSIBLE;input_model=WriteIn;output_model=WriteOut;permissions=frozenset({Permission.WRITE})
 async def invoke(self,a):
  backup=None
  if a['overwrite']:
   try:backup=self.policy.backup_file(a['path'])
   except FileNotFoundError:backup=None
   except PermissionError:raise
  p=self.policy.atomic_write(a['path'],a['content'],a['overwrite'],allow_protected=self.override(a),backup=False);return {'path':p.relative_to(self.root).as_posix(),'bytes_written':len(a['content'].encode()),'backup_path':backup}
class DeleteIn(BaseModel):path:str;confirmation:Literal['DELETE'];permanent:bool=False;policy_override:Literal['PROTECTED-OVERRIDE']|None=None
class DeleteOut(BaseModel):path:str;deleted:bool;recycle_entry:str|None=None;reversible:bool
class DeleteFile(FileBase):
 name='delete_file';description='Safely delete one regular file (recycles to the internal trash unless permanent=true) with explicit confirmation';category='filesystem';risk_level=RiskLevel.HIGH;idempotent=False;reversibility=Reversibility.REVERSIBLE;input_model=DeleteIn;output_model=DeleteOut;permissions=frozenset({Permission.WRITE})
 async def invoke(self,a):
  if a['permanent']:
   self.policy.delete(a['path'],a['confirmation'],allow_protected=self.override(a));return {'path':a['path'],'deleted':True,'recycle_entry':None,'reversible':False}
  entry=self.policy.recycle_file(a['path'],a['confirmation'],allow_protected=self.override(a));return {'path':a['path'],'deleted':True,'recycle_entry':entry,'reversible':True}
class PyIn(BaseModel):code:str=Field(min_length=1,max_length=10000)
class PyOut(BaseModel):stdout:str;stderr:str;exit_code:int;truncated:bool
class PythonTool(FileBase):
 name='python_executor';description='Arbitrary Python is disabled unless a separately reviewed container runner is configured';category='execution';risk_level=RiskLevel.HIGH;idempotent=False;input_model=PyIn;output_model=PyOut;permissions=frozenset({Permission.EXECUTE});sandbox_required=True;timeout_seconds=30;enabled=False
 disabled_reason='PYTHON_SANDBOX_UNAVAILABLE: Docker execution is not configured'
 def __init__(self,root,runner=None,timeout=5,limit=20000):
  super().__init__(root,limit);self.runner=runner;self.timeout_seconds=min(float(timeout),30);self.enabled=bool(runner and runner.available);self.disabled_reason=None if self.enabled else 'PYTHON_SANDBOX_UNAVAILABLE: Docker sandbox is disabled or unavailable'
 async def invoke(self,a):
  if not self.runner or not self.runner.available:raise RuntimeError('PYTHON_SANDBOX_UNAVAILABLE')
  return await self.runner.execute(a['code'])
class SearchIn(BaseModel):query:str=Field(min_length=2,max_length=500)
class SearchOut(BaseModel):results:list[dict[str,str]]
class SearchTool(Tool):
 name='web_search';description='Search through configured self-hosted SearXNG';category='network';risk_level=RiskLevel.MEDIUM;input_model=SearchIn;output_model=SearchOut;permissions=frozenset({Permission.NETWORK});network_required=True;timeout_seconds=15
 def __init__(self,url,enabled,mode='disabled',allow_local=False,allow_private=False,allow_external=False,allow_dns=True,timeout=12,max_bytes=1000000,rate_limit=20):
  from collections import deque
  self.url=str(url).rstrip('/') if url else None;self.mode=mode;self.enabled=enabled and mode!='disabled' and bool(url);self.disabled_reason=None if self.enabled else ('NETWORK_DISABLED: Network tools are disabled by policy' if mode=='disabled' or not enabled else 'NETWORK_NOT_CONFIGURED: SearXNG URL is required');self.allow_local=bool(allow_local);self.allow_private=bool(allow_private);self.allow_external=bool(allow_external);self.allow_dns=bool(allow_dns);self.timeout_seconds=min(float(timeout),60);self.max_bytes=max_bytes;self._requests=deque();self._rate_limit=int(rate_limit)
 async def invoke(self,a):
  import httpx,time
  from app.network_security import NetworkPolicyError,SafeHttpClient
  now=time.monotonic()
  while self._requests and self._requests[0] <= now-60:self._requests.popleft()
  if len(self._requests)>=self._rate_limit:raise RuntimeError('NETWORK_RATE_LIMITED: Retry after one minute')
  self._requests.append(now)
  try:d=await SafeHttpClient(self.timeout_seconds,self.max_bytes,self.allow_local,self.allow_private,self.allow_external,self.allow_dns).get_json(self.url+'/search',params={'q':a['query'],'format':'json'})
  except NetworkPolicyError:raise
  except (httpx.HTTPError,TimeoutError) as error:raise ConnectionError('NETWORK_UNAVAILABLE: SearXNG did not respond') from error
  return {'results':[{'title':str(x.get('title') or x.get('url',''))[:500],'url':str(x.get('url',''))[:2000],'snippet':str(x.get('content',''))[:2000]} for x in d.get('results',[])[:8] if x.get('url')]}
class HttpIn(BaseModel):
 url:str=Field(min_length=8,max_length=2000);method:Literal['GET','POST']='GET';json_body:dict[str,Any]|None=None
class HttpOut(BaseModel):status_code:int;content_type:str;body:str;truncated:bool
class HttpRequestTool(Tool):
 name='http_request';description='Perform an approved bounded HTTP request';category='network';risk_level=RiskLevel.HIGH;idempotent=False;input_model=HttpIn;output_model=HttpOut;permissions=frozenset({Permission.NETWORK});network_required=True;timeout_seconds=30
 def __init__(self,enabled,mode,allow_local,allow_private,allow_external,allow_dns,timeout,max_bytes,rate_limit=20):
  from collections import deque
  self.enabled=bool(enabled and mode!='disabled');self.disabled_reason=None if self.enabled else 'HTTP_REQUESTS_DISABLED: Disabled in Settings';self.client_config=(float(timeout),int(max_bytes),bool(allow_local),bool(allow_private),bool(allow_external),bool(allow_dns));self._requests=deque();self._rate_limit=int(rate_limit)
 async def invoke(self,a):
  import time
  from app.network_security import SafeHttpClient
  now=time.monotonic()
  while self._requests and self._requests[0]<=now-60:self._requests.popleft()
  if len(self._requests)>=self._rate_limit:raise RuntimeError('NETWORK_RATE_LIMITED: Retry after one minute')
  self._requests.append(now)
  client=SafeHttpClient(*self.client_config);status,content_type,text=await client.request(a['method'],a['url'],json_body=a.get('json_body'))
  return {'status_code':status,'content_type':content_type[:200],'body':text[:20000],'truncated':len(text)>20000}
class TerminalIn(BaseModel):
 command:list[str]=Field(min_length=1,max_length=20);path:str='.'
class TerminalOut(BaseModel):
 command:list[str];stdout:str;stderr:str;exit_code:int;truncated:bool;isolation:str;files_copied:int;bytes_copied:int
class TerminalTool(FileBase):
 name='terminal';description='Run an argument-vector command only inside the configured locked-down Docker sandbox';category='execution';risk_level=RiskLevel.CRITICAL;idempotent=False;input_model=TerminalIn;output_model=TerminalOut;permissions=frozenset({Permission.EXECUTE});sandbox_required=True;timeout_seconds=300
 def __init__(self,root,sandbox=None,limit=20000):
  super().__init__(root,limit);self.sandbox=sandbox;self.enabled=bool(sandbox and sandbox.available);self.disabled_reason=None if self.enabled else 'TERMINAL_SANDBOX_UNAVAILABLE: Configure a pinned Docker image and start Docker'
 async def invoke(self,a):
  if not self.sandbox or not self.sandbox.available:raise RuntimeError('TERMINAL_SANDBOX_UNAVAILABLE')
  if any(not isinstance(part,str) or not part or len(part)>500 or '\x00' in part for part in a['command']):raise ValueError('invalid terminal argument vector')
  from app.config import settings
  copy_config=settings()
  # Honor the configured sandbox copy budget instead of hardcoded limits so
  # the terminal and the test runner share one authoritative configuration.
  result=await self.sandbox.execute_copy(self.policy,a['path'],a['command'],copy_config.test_max_copy_files,copy_config.test_max_copy_bytes)
  return {'command':a['command'],**result}

# --------------------------------------------------------------------------- #
# Phase 7 — extended filesystem agent tools. Every operation goes through     #
# WorkspacePolicy (normalized paths, allowed root, symlink/hardlink guards,   #
# protected paths, size budgets) and uses filesystem APIs only — never shell. #
# --------------------------------------------------------------------------- #
class _FsBase(FileBase):
 category='filesystem';timeout_seconds=20
 def override(self,a):return a.get('policy_override')==WorkspacePolicy.PROTECTED_TOKEN

class InspectIn(BaseModel):path:str
class InspectOut(BaseModel):info:dict[str,Any]
class InspectFile(_FsBase):
 name='inspect_file';description='Inspect one workspace file or directory (type, size, hash, binary flag, protected flag)';risk_level=RiskLevel.LOW;reversibility=Reversibility.READ_ONLY;input_model=InspectIn;output_model=InspectOut;permissions=frozenset({Permission.READ})
 async def invoke(self,a):return {'info':self.policy.inspect(a['path'])}

class CreateDirIn(BaseModel):path:str;policy_override:Literal['PROTECTED-OVERRIDE']|None=None
class CreateDirOut(BaseModel):path:str;created:bool
class CreateDirectory(_FsBase):
 name='create_directory';description='Create a workspace directory inside the policy root';risk_level=RiskLevel.MEDIUM;reversibility=Reversibility.PARTIAL;input_model=CreateDirIn;output_model=CreateDirOut;permissions=frozenset({Permission.WRITE})
 async def invoke(self,a):p=self.policy.create_directory(a['path'],allow_protected=self.override(a));return {'path':p.relative_to(self.root).as_posix(),'created':True}

class CopyIn(BaseModel):source:str;destination:str;overwrite:bool=False;policy_override:Literal['PROTECTED-OVERRIDE']|None=None
class CopyOut(BaseModel):source:str;destination:str;copied:bool
class CopyFile(_FsBase):
 name='copy_file';description='Copy one regular workspace file atomically within the policy root';risk_level=RiskLevel.MEDIUM;reversibility=Reversibility.REVERSIBLE;idempotent=False;input_model=CopyIn;output_model=CopyOut;permissions=frozenset({Permission.READ,Permission.WRITE})
 async def invoke(self,a):d=self.policy.copy_file(a['source'],a['destination'],a['overwrite'],allow_protected=self.override(a));return {'source':a['source'],'destination':d,'copied':True}

class MoveIn(BaseModel):source:str;destination:str;policy_override:Literal['PROTECTED-OVERRIDE']|None=None
class MoveOut(BaseModel):source:str;destination:str;moved:bool
class MovePath(_FsBase):
 name='move_path';description='Move a workspace file or directory inside the policy root';risk_level=RiskLevel.HIGH;reversibility=Reversibility.PARTIAL;idempotent=False;input_model=MoveIn;output_model=MoveOut;permissions=frozenset({Permission.WRITE})
 async def invoke(self,a):d=self.policy.move_path(a['source'],a['destination'],allow_protected=self.override(a));return {'source':a['source'],'destination':d,'moved':True}

class RenameIn(BaseModel):path:str;new_name:str;policy_override:Literal['PROTECTED-OVERRIDE']|None=None
class RenameOut(BaseModel):old_path:str;new_path:str;renamed:bool
class RenamePath(_FsBase):
 name='rename_path';description='Rename a workspace path within its directory';risk_level=RiskLevel.HIGH;reversibility=Reversibility.REVERSIBLE;idempotent=False;input_model=RenameIn;output_model=RenameOut;permissions=frozenset({Permission.WRITE})
 async def invoke(self,a):n=self.policy.rename_path(a['path'],a['new_name'],allow_protected=self.override(a));return {'old_path':a['path'],'new_path':n,'renamed':True}

class RecycleIn(BaseModel):path:str;confirmation:Literal['DELETE'];policy_override:Literal['PROTECTED-OVERRIDE']|None=None
class RecycleOut(BaseModel):path:str;recycle_entry:str;reversible:bool=True
class RecycleFile(_FsBase):
 name='recycle_file';description='Move one regular file to the internal recoverable trash with explicit confirmation';risk_level=RiskLevel.HIGH;reversibility=Reversibility.REVERSIBLE;idempotent=False;input_model=RecycleIn;output_model=RecycleOut;permissions=frozenset({Permission.WRITE})
 async def invoke(self,a):entry=self.policy.recycle_file(a['path'],a['confirmation'],allow_protected=self.override(a));return {'path':a['path'],'recycle_entry':entry,'reversible':True}

class RestoreIn(BaseModel):entry:str
class RestoreOut(BaseModel):path:str;restored:bool
class RestoreRecycled(_FsBase):
 name='restore_recycled_file';description='Restore a recycled file from the internal trash';risk_level=RiskLevel.MEDIUM;reversibility=Reversibility.PARTIAL;idempotent=False;input_model=RestoreIn;output_model=RestoreOut;permissions=frozenset({Permission.WRITE})
 async def invoke(self,a):p=self.policy.restore_recycled(a['entry']);return {'path':p,'restored':True}

class TrashListIn(BaseModel):model_config=ConfigDict(extra='forbid')
class TrashListOut(BaseModel):entries:list[dict[str,Any]];truncated:bool=False
class ListTrash(_FsBase):
 name='list_recycle_entries';description='List recoverable trash entries';risk_level=RiskLevel.LOW;reversibility=Reversibility.READ_ONLY;input_model=TrashListIn;output_model=TrashListOut;permissions=frozenset({Permission.READ})
 async def invoke(self,a):return {'entries':self.policy.list_recycle_entries(),'truncated':False}

class PurgeIn(BaseModel):entry:str;confirmation:Literal['PURGE']
class PurgeOut(BaseModel):entry:str;purged:bool
class PurgeTrash(_FsBase):
 name='purge_recycle_entry';description='Permanently remove one trash entry with explicit PURGE confirmation';risk_level=RiskLevel.CRITICAL;reversibility=Reversibility.IRREVERSIBLE;idempotent=False;input_model=PurgeIn;output_model=PurgeOut;permissions=frozenset({Permission.WRITE})
 async def invoke(self,a):self.policy.purge_recycle_entry(a['entry'],a['confirmation']);return {'entry':a['entry'],'purged':True}

class BackupIn(BaseModel):path:str
class BackupOut(BaseModel):backup_path:str
class BackupFileTool(_FsBase):
 name='backup_file';description='Snapshot one workspace file into the internal backup store';risk_level=RiskLevel.LOW;reversibility=Reversibility.READ_ONLY;idempotent=False;input_model=BackupIn;output_model=BackupOut;permissions=frozenset({Permission.READ})
 async def invoke(self,a):return {'backup_path':self.policy.backup_file(a['path'])}
