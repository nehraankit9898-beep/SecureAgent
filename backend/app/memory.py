import asyncio,json,re,sqlite3
from datetime import UTC,datetime
from pathlib import Path
from uuid import uuid4
from app.models import MemoryIn,MemoryItem,MemoryPatch,ScheduleCreate,SchedulePatch,Task
from app.security import redact,request_id_var
from app.migrations import run_migrations
def now():return datetime.now(UTC).isoformat()
class MemoryStore:
 def __init__(self,path:Path):self.path=path
 def conn(self):
  self.path.parent.mkdir(parents=True,exist_ok=True);c=sqlite3.connect(self.path,timeout=10);c.row_factory=sqlite3.Row;c.execute('PRAGMA journal_mode=WAL');c.execute('PRAGMA foreign_keys=ON');return c
 async def init(self):await asyncio.to_thread(self._init)
 async def ping(self) -> bool:
  """Real database health probe (used by /health and /diagnostics).

  Returns True iff a SQLite connection can be opened and ``SELECT 1`` succeeds.
  Never raises — callers use the boolean to set health status honestly.
  """
  try:
   return bool(await asyncio.to_thread(self._ping))
  except Exception:
   return False
 def _ping(self) -> bool:
  with self.conn() as c:
   row = c.execute('SELECT 1').fetchone()
   return row is not None and row[0] == 1
 def _init(self):
  sql='CREATE TABLE IF NOT EXISTS messages(id TEXT PRIMARY KEY,conversation_id TEXT,role TEXT,content TEXT,created_at TEXT);CREATE INDEX IF NOT EXISTS msg_idx ON messages(conversation_id,created_at);CREATE TABLE IF NOT EXISTS memories(id TEXT PRIMARY KEY,content TEXT,category TEXT,created_at TEXT,updated_at TEXT);CREATE TABLE IF NOT EXISTS tasks(id TEXT PRIMARY KEY,payload TEXT,updated_at TEXT);CREATE TABLE IF NOT EXISTS audit_logs(id TEXT PRIMARY KEY,event TEXT,actor TEXT,details TEXT,created_at TEXT);CREATE TABLE IF NOT EXISTS schedules(id TEXT PRIMARY KEY,name TEXT,prompt TEXT,kind TEXT,next_run TEXT,interval_seconds INTEGER,permissions TEXT,enabled INTEGER,created_at TEXT,updated_at TEXT);CREATE TABLE IF NOT EXISTS schedule_runs(id TEXT PRIMARY KEY,schedule_id TEXT,status TEXT,task_id TEXT,answer TEXT,errors TEXT,created_at TEXT);CREATE TABLE IF NOT EXISTS documents(id TEXT PRIMARY KEY,title TEXT,path TEXT,created_at TEXT);CREATE TABLE IF NOT EXISTS document_chunks(id TEXT PRIMARY KEY,document_id TEXT,chunk_index INTEGER,content TEXT,embedding TEXT,FOREIGN KEY(document_id) REFERENCES documents(id) ON DELETE CASCADE);'
  with self.conn() as c:c.executescript(sql);run_migrations(c)
 async def audit(self,event,details,actor='user'):await asyncio.to_thread(self._audit,event,details,actor)
 def _audit(self,event,details,actor):
  payload={**dict(details),'request_id':request_id_var.get()}
  with self.conn() as c:c.execute('INSERT INTO audit_logs VALUES(?,?,?,?,?)',(str(uuid4()),event,actor,json.dumps(redact(payload),default=str),now()))
 async def audits(self,limit=100):return await asyncio.to_thread(self._audits,limit)
 def _audits(self,limit):
  with self.conn() as c:r=c.execute('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?',(limit,)).fetchall()
  return [{**dict(x),'details':json.loads(x['details'])} for x in r]
 # Control Center audit surface: category filtering, clear-with-confirm and
 # export. Categories map onto event-prefix families (see main.py AUDIT_FILTERS).
 async def audits_filtered(self,limit=100,category='all'):return await asyncio.to_thread(self._audits_filtered,limit,category)
 def _audits_filtered(self,limit,category):
  rows=self._audits(limit) if category=='all' else None
  if rows is not None:return rows
  with self.conn() as c:r=c.execute('SELECT * FROM audit_logs ORDER BY created_at DESC LIMIT ?',(limit*8,)).fetchall()
  items=[{**dict(x),'details':json.loads(x['details'])} for x in r]
  matched=[]
  for item in items:
   event=item['event']
   if category=='agent' and event.startswith(('task.','tool.','agent.','approval.')):matched.append(item)
   elif category=='terminal' and event.startswith('terminal.'):matched.append(item)
   elif category=='network' and event.startswith('network.'):matched.append(item)
   elif category=='security' and event.startswith(('config.','control.','control_center.','security.','schedule.','host_control.','tool.toggled','filesystem.','audit.','permission.granted','permission.revoked')):matched.append(item)
   elif category=='permission' and event.startswith('permission.'):matched.append(item)
   elif category=='errors' and (event.endswith(('.error','.failed','.blocked','.persist_failed')) or isinstance(item['details'].get('error'),str)):matched.append(item)
   if len(matched)>=limit:break
  return matched
 async def audit_count(self):return await asyncio.to_thread(self._audit_count)
 def _audit_count(self):
  with self.conn() as c:return int(c.execute('SELECT COUNT(*) FROM audit_logs').fetchone()[0])
 async def clear_audits(self):return await asyncio.to_thread(self._clear_audits)
 def _clear_audits(self):
  with self.conn() as c:
   count=int(c.execute('SELECT COUNT(*) FROM audit_logs').fetchone()[0])
   c.execute('DELETE FROM audit_logs')
   return count
 async def message(self,cid,role,content):await asyncio.to_thread(self._message,cid,role,content)
 def _message(self,cid,role,content):
  with self.conn() as c:c.execute('INSERT INTO messages VALUES(?,?,?,?,?)',(str(uuid4()),cid,role,content[:100000],now()))
 async def recent(self,cid,limit=20):return await asyncio.to_thread(self._recent,cid,limit)
 def _recent(self,cid,limit):
  with self.conn() as c:r=c.execute('SELECT role,content FROM messages WHERE conversation_id=? ORDER BY created_at DESC LIMIT ?',(cid,limit)).fetchall()
  return [dict(x) for x in reversed(r)]
 async def create(self,x):return await asyncio.to_thread(self._create,x)
 def _create(self,x):
  t=now();m=MemoryItem(id=str(uuid4()),content=x.content,category=x.category,created_at=t,updated_at=t)
  with self.conn() as c:c.execute('INSERT INTO memories VALUES(?,?,?,?,?)',(m.id,m.content,m.category,t,t))
  return m
 async def list(self,q=None,limit=50):return await asyncio.to_thread(self._list,q,limit)
 def _list(self,q,limit):
  # Escape LIKE metacharacters so a query of '%' or '_' filters literally
  # instead of matching every row; ESCAPE declares the escape character.
  escaped=q.replace('\\','\\\\').replace('%','\\%').replace('_','\\_') if q else q
  with self.conn() as c:r=c.execute("SELECT * FROM memories WHERE content LIKE ? ESCAPE '\\' ORDER BY updated_at DESC LIMIT ?",(f'%{escaped}%',limit)).fetchall() if q else c.execute('SELECT * FROM memories ORDER BY updated_at DESC LIMIT ?',(limit,)).fetchall()
  return [MemoryItem(**dict(x)) for x in r]
 async def relevant(self,text,limit=5):
  out={}
  for w in re.findall(r'[\w-]{3,}',text.lower())[:8]:
   for x in await self.list(w,limit):out[x.id]=x
   if len(out)>=limit:break
  return list(out.values())[:limit]
 async def patch(self,i,p):return await asyncio.to_thread(self._patch,i,p)
 def _patch(self,i,p):
  with self.conn() as c:
   x=c.execute('SELECT * FROM memories WHERE id=?',(i,)).fetchone()
   if not x:return None
   content=p.content or x['content'];cat=p.category or x['category'];t=now();c.execute('UPDATE memories SET content=?,category=?,updated_at=? WHERE id=?',(content,cat,t,i))
  return MemoryItem(id=i,content=content,category=cat,created_at=x['created_at'],updated_at=t)
 async def delete(self,i):return await asyncio.to_thread(self._delete,i)
 def _delete(self,i):
  with self.conn() as c:return c.execute('DELETE FROM memories WHERE id=?',(i,)).rowcount>0
 async def save_task(self,t):await asyncio.to_thread(self._save_task,t)
 def _save_task(self,t):
  with self.conn() as c:c.execute('INSERT INTO tasks VALUES(?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload,updated_at=excluded.updated_at',(t.id,t.model_dump_json(),now()))
 async def task(self,i):return await asyncio.to_thread(self._task,i)
 def _task(self,i):
  with self.conn() as c:x=c.execute('SELECT payload FROM tasks WHERE id=?',(i,)).fetchone()
  return Task.model_validate_json(x['payload']) if x else None
 async def tasks(self,limit=50):return await asyncio.to_thread(self._tasks,limit)
 def _tasks(self,limit):
  with self.conn() as c:r=c.execute('SELECT payload FROM tasks ORDER BY updated_at DESC LIMIT ?',(limit,)).fetchall()
  return [Task.model_validate_json(x['payload']) for x in r]
 async def create_schedule(self,x):return await asyncio.to_thread(self._create_schedule,x)
 def _create_schedule(self,x,approval_required=False):
  t=now();nr=(x.run_at or datetime.now(UTC)).astimezone(UTC).isoformat();policy={'allowed_tools':x.allowed_tools,'workspace':x.workspace,'max_steps':x.max_steps,'max_runtime':x.max_runtime,'network_policy':x.network_policy,'retry_limit':x.retry_limit,'approval_required':approval_required,'approval_granted':not approval_required};row={'id':str(uuid4()),'name':x.name,'prompt':x.prompt,'kind':x.kind,'next_run':nr,'interval_seconds':x.interval_seconds,'permissions':sorted(p.value for p in x.approved_permissions),'policy':policy,'enabled':x.enabled and not approval_required,'cancelled':False,'failure_count':0,'created_at':t,'updated_at':t,'approval_required':approval_required}
  with self.conn() as c:c.execute('INSERT INTO schedules(id,name,prompt,kind,next_run,interval_seconds,permissions,enabled,created_at,updated_at,policy,cancelled,failure_count) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)',(row['id'],row['name'],row['prompt'],row['kind'],nr,row['interval_seconds'],json.dumps(row['permissions']),int(row['enabled']),t,t,json.dumps(policy),0,0))
  return row
 async def create_schedule_pending(self,x,approval_required=False):return await asyncio.to_thread(self._create_schedule,x,approval_required)
 async def schedules(self):return await asyncio.to_thread(self._schedules)
 def _schedules(self):
  with self.conn() as c:r=c.execute('SELECT * FROM schedules ORDER BY created_at DESC').fetchall()
  return [{**dict(x),'permissions':json.loads(x['permissions']),'policy':json.loads(x['policy'] or '{}'),'enabled':bool(x['enabled']),'cancelled':bool(x['cancelled'])} for x in r]
 async def update_schedule(self,i,p):return await asyncio.to_thread(self._update_schedule,i,p)
 def _update_schedule(self,i,p):
  values=p.model_dump(exclude_none=True)
  if not values:return None
  with self.conn() as c:
   row=c.execute('SELECT * FROM schedules WHERE id=?',(i,)).fetchone()
   if not row:return None
   if row['cancelled']:raise ValueError('cancelled schedule cannot be updated')
   allowed={'name','prompt','interval_seconds','enabled'};updates={key:value for key,value in values.items() if key in allowed}
   if 'run_at' in values:updates['next_run']=values['run_at'].astimezone(UTC).isoformat()
   if row['kind']=='once' and 'next_run' not in updates and row['next_run']<=now():raise ValueError('one-time schedule run_at must be moved into the future')
   if row['kind']=='interval' and updates.get('interval_seconds',row['interval_seconds']) is None:raise ValueError('interval_seconds is required')
   if 'enabled' in updates:updates['enabled']=int(updates['enabled'])
   updates['updated_at']=now();columns=', '.join(f'{key}=?' for key in updates)
   c.execute(f'UPDATE schedules SET {columns} WHERE id=?',(*updates.values(),i))
  return next((item for item in self._schedules() if item['id']==i),None)
 async def claim_due_schedules(self,m,owner,lease_seconds=300,limit=10):return await asyncio.to_thread(self._claim_due,m,owner,lease_seconds,limit)
 def _claim_due(self,m,owner,lease_seconds,limit=10):
  from datetime import timedelta
  expires=(m+timedelta(seconds=lease_seconds)).isoformat()
  with self.conn() as c:
   c.execute('BEGIN IMMEDIATE')
   rows=c.execute('SELECT id FROM schedules WHERE enabled=1 AND cancelled=0 AND next_run<=? AND (lease_expires IS NULL OR lease_expires<=?) ORDER BY next_run LIMIT ?',(m.isoformat(),m.isoformat(),max(1,int(limit)))).fetchall()
   ids=[]
   for row in rows:
    if c.execute('UPDATE schedules SET lease_owner=?,lease_expires=? WHERE id=? AND (lease_expires IS NULL OR lease_expires<=?)',(owner,expires,row['id'],m.isoformat())).rowcount: ids.append(row['id'])
   if not ids:return []
   marks=','.join('?' for _ in ids); claimed=c.execute(f'SELECT * FROM schedules WHERE id IN ({marks})',ids).fetchall()
  return [{**dict(x),'permissions':json.loads(x['permissions']),'policy':json.loads(x['policy'] or '{}')} for x in claimed]
 async def due_schedules(self,m):return await asyncio.to_thread(self._due,m)
 def _due(self,m):
  with self.conn() as c:r=c.execute('SELECT * FROM schedules WHERE enabled=1 AND cancelled=0 AND next_run<=? ORDER BY next_run LIMIT 10',(m.isoformat(),)).fetchall()
  return [{**dict(x),'permissions':json.loads(x['permissions']),'policy':json.loads(x['policy'] or '{}')} for x in r]
 async def disable_schedule(self,i):await asyncio.to_thread(self._sup,i,None,False)
 async def approve_schedule(self,i):return await asyncio.to_thread(self._approve_schedule,i)
 def _approve_schedule(self,i):
  with self.conn() as c:
   row=c.execute('SELECT policy,cancelled FROM schedules WHERE id=?',(i,)).fetchone()
   if not row or row['cancelled']:return False
   policy=json.loads(row['policy'] or '{}');policy['approval_granted']=True
   return c.execute('UPDATE schedules SET policy=?,enabled=1,updated_at=? WHERE id=?',(json.dumps(policy),now(),i)).rowcount>0
 async def advance_schedule(self,i,n):await asyncio.to_thread(self._sup,i,n.isoformat(),True)
 def _sup(self,i,n,e):
  with self.conn() as c:c.execute('UPDATE schedules SET next_run=COALESCE(?,next_run),enabled=?,updated_at=? WHERE id=?',(n,int(e),now(),i))
 async def cancel_schedule(self,i):return await asyncio.to_thread(self._cancel_schedule,i)
 def _cancel_schedule(self,i):
  with self.conn() as c:return c.execute('UPDATE schedules SET cancelled=1,enabled=0,updated_at=? WHERE id=?',(now(),i)).rowcount>0
 async def delete_schedule(self,i):return await asyncio.to_thread(self._ds,i)
 def _ds(self,i):
  with self.conn() as c:return c.execute('DELETE FROM schedules WHERE id=?',(i,)).rowcount>0
 async def record_schedule_run(self,s,status,task,answer,errors):await asyncio.to_thread(self._rs,s,status,task,answer,errors)
 def _rs(self,s,status,task,answer,errors):
  with self.conn() as c:
   c.execute('INSERT INTO schedule_runs VALUES(?,?,?,?,?,?,?)',(str(uuid4()),s,status,task,answer,json.dumps(errors),now()))
   # Keep the failure counter meaningful: it was written at creation time and
   # never updated, leaving operators without a signal of repeated failures.
   if status!='completed':
    c.execute("UPDATE schedules SET failure_count=failure_count+1,updated_at=? WHERE id=?",(now(),s))
 async def schedule_runs(self,limit=100):return await asyncio.to_thread(self._runs,limit)
 def _runs(self,limit):
  with self.conn() as c:r=c.execute('SELECT * FROM schedule_runs ORDER BY created_at DESC LIMIT ?',(limit,)).fetchall()
  return [{**dict(x),'errors':json.loads(x['errors'])} for x in r]
 async def find_document_hash(self,h):return await asyncio.to_thread(self._find_document_hash,h)
 def _find_document_hash(self,h):
  with self.conn() as c:x=c.execute('SELECT * FROM documents WHERE content_hash=?',(h,)).fetchone()
  return dict(x) if x else None
 async def save_document(self,i,title,path,t,parts,vectors,content_hash,version,metadata,replace_document_id=None):await asyncio.to_thread(self._sd,i,title,path,t,parts,vectors,content_hash,version,metadata,replace_document_id)
 def _sd(self,i,title,path,t,parts,vectors,content_hash,version,metadata,replace_document_id):
  with self.conn() as c:
   if replace_document_id:c.execute('DELETE FROM documents WHERE id=?',(replace_document_id,))
   c.execute('INSERT INTO documents(id,title,path,created_at,content_hash,version,metadata,updated_at) VALUES(?,?,?,?,?,?,?,?)',(i,title,path,t,content_hash,version,json.dumps(metadata),t))
   c.executemany('INSERT INTO document_chunks(id,document_id,chunk_index,content,embedding,metadata) VALUES(?,?,?,?,?,?)',[(str(uuid4()),i,n,part,json.dumps(vectors[n]),json.dumps({'source':path,'chunk_index':n,'version':version})) for n,part in enumerate(parts)])
 async def documents(self):return await asyncio.to_thread(self._docs)
 def _docs(self):
  with self.conn() as c:rows=c.execute('SELECT d.*,COUNT(c.id) chunk_count FROM documents d LEFT JOIN document_chunks c ON c.document_id=d.id GROUP BY d.id ORDER BY COALESCE(d.updated_at,d.created_at) DESC').fetchall()
  return [{**dict(x),'metadata':json.loads(x['metadata'] or '{}')} for x in rows]
 async def document_chunks(self,i=None,limit=10000):return await asyncio.to_thread(self._chunks,i,limit)
 def _chunks(self,i,limit):
  q='SELECT c.*,d.title,d.path,d.version,d.content_hash FROM document_chunks c JOIN documents d ON d.id=c.document_id'
  with self.conn() as c:rows=c.execute(q+' WHERE c.document_id=? ORDER BY c.chunk_index LIMIT ?',(i,limit)).fetchall() if i else c.execute(q+' ORDER BY d.updated_at DESC,c.chunk_index LIMIT ?',(limit,)).fetchall()
  return [{**dict(x),'metadata':json.loads(x['metadata'] or '{}')} for x in rows]
 async def delete_document(self,i):return await asyncio.to_thread(self._dd,i)
 def _dd(self,i):
  with self.conn() as c:return c.execute('DELETE FROM documents WHERE id=?',(i,)).rowcount>0
 async def save_terminal_execution(self,record:dict):await asyncio.to_thread(self._save_terminal_execution,record)
 def _save_terminal_execution(self,r):
  with self.conn() as c:
   c.execute('INSERT INTO terminal_history(id,task_id,session_id,command,cwd,risk,approval,exit_code,status,duration_ms,stdout,stderr,truncated,created_at) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?)',
    (r['id'],r.get('task_id'),r.get('session_id'),r['command'][:8000],r.get('cwd'),r.get('risk'),r.get('approval'),r.get('exit_code'),r.get('status'),r.get('duration_ms',0),(r.get('stdout') or '')[:200000],(r.get('stderr') or '')[:100000],int(bool(r.get('truncated'))),now()))
   c.execute('DELETE FROM terminal_history WHERE id NOT IN (SELECT id FROM terminal_history ORDER BY created_at DESC LIMIT ?)',(r.get('history_limit',1000),))
 async def terminal_history(self,limit=100,query=None):return await asyncio.to_thread(self._terminal_history,limit,query)
 def _terminal_history(self,limit,query):
  with self.conn() as c:
   if query:
    # literal-match history (LIKE metacharacters escaped); audit-log style search
    escaped=query.replace('\\','\\\\').replace('%','\\%').replace('_','\\_')
    rows=c.execute("SELECT * FROM terminal_history WHERE command LIKE ? ESCAPE '\\' ORDER BY created_at DESC LIMIT ?",(f'%{escaped}%',min(limit,1000))).fetchall()
   else:
    rows=c.execute('SELECT * FROM terminal_history ORDER BY created_at DESC LIMIT ?',(min(limit,1000),)).fetchall()
  return [{**dict(row),'truncated':bool(row['truncated'])} for row in rows]
 async def terminal_execution(self,i):return await asyncio.to_thread(self._terminal_execution,i)
 def _terminal_execution(self,i):
  with self.conn() as c:row=c.execute('SELECT * FROM terminal_history WHERE id=?',(i,)).fetchone()
  return {**dict(row),'truncated':bool(row['truncated'])} if row else None
 async def save_report(self,report:dict):await asyncio.to_thread(self._save_report,report)
 def _save_report(self,report):
  with self.conn() as c:
   c.execute('INSERT INTO security_reports(id,workflow,title,status,overall_severity,payload,created_at) VALUES(?,?,?,?,?,?,?) ON CONFLICT(id) DO UPDATE SET payload=excluded.payload',
    (report['id'],report['workflow'],report.get('title'),report.get('status'),report.get('summary',{}).get('overall_severity','info'),json.dumps(report,default=str),now()))
 async def reports(self,limit=50):return await asyncio.to_thread(self._reports,limit)
 def _reports(self,limit):
  with self.conn() as c:rows=c.execute('SELECT id,workflow,title,status,overall_severity,created_at FROM security_reports ORDER BY created_at DESC LIMIT ?',(min(limit,200),)).fetchall()
  return [dict(row) for row in rows]
 async def report(self,i):return await asyncio.to_thread(self._report,i)
 def _report(self,i):
  with self.conn() as c:row=c.execute('SELECT payload FROM security_reports WHERE id=?',(i,)).fetchone()
  return json.loads(row['payload']) if row else None
 async def create_grant(self,permission,scope,note):return await asyncio.to_thread(self._create_grant,permission,scope,note)
 def _create_grant(self,permission,scope,note):
  item={'id':str(uuid4()),'permission':permission,'scope':scope,'note':note or '','created_at':now(),'expires_at':None}
  with self.conn() as c:c.execute('INSERT INTO permission_grants VALUES(?,?,?,?,?,?)',(item['id'],permission,scope,item['note'],item['created_at'],None))
  return item
 async def grants(self):return await asyncio.to_thread(self._grants)
 def _grants(self):
  with self.conn() as c:rows=c.execute('SELECT * FROM permission_grants ORDER BY created_at DESC').fetchall()
  return [dict(row) for row in rows]
 async def active_grant_permissions(self):return await asyncio.to_thread(self._active_grants)
 def _active_grants(self):
  with self.conn() as c:rows=c.execute('SELECT permission FROM permission_grants WHERE scope=? AND (expires_at IS NULL OR expires_at>?)',('always',now())).fetchall()
  return {row['permission'] for row in rows}
 async def delete_grant(self,i):return await asyncio.to_thread(self._delete_grant,i)
 def _delete_grant(self,i):
  with self.conn() as c:return c.execute('DELETE FROM permission_grants WHERE id=?',(i,)).rowcount>0
