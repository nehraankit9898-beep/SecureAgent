from app.security import SECRET_PATTERN, redact


def _control_gate():
    try:
        from app.control_center import get_control_center
        return get_control_center()
    except Exception:
        return None


class MemoryService:
 def __init__(self,store):self.store=store
 def _validate(self,*values):
  gate=_control_gate()
  sensitive=[value for value in values if value is not None and SECRET_PATTERN.search(value)]
  if not sensitive:return values
  # Control Center "Sensitive Data Filtering" (spec section 12):
  #   ON  (default) -> refuse to store sensitive-looking memories
  #   OFF           -> store a REDACTED copy; raw secrets are never persisted
  if gate is not None and not gate.state.memory.sensitive_filtering:
   return tuple(redact(value) if isinstance(value,str) else value for value in values)
  raise ValueError("sensitive-looking memory is not stored automatically")
 async def create(self,item):
  (content,category),=(self._validate(item.content,item.category),)
  return await self.store.create(type(item).model_validate({**item.model_dump(),'content':content,'category':category}))
 async def retrieve(self,i):return next((x for x in await self.store.list(None,500) if x.id==i),None)
 async def search(self,q,limit=50):return await self.store.list(q,limit)
 async def update(self,i,p):
  content=p.content;category=p.category
  if content is not None or category is not None:
   validated=self._validate(*[v for v in (content,category) if v is not None])
   idx=0
   if content is not None:content=validated[idx];idx+=1
   if category is not None:category=validated[idx]
   p=type(p).model_validate({**{k:v for k,v in p.model_dump().items() if v is not None},'content':content,'category':category})
  return await self.store.patch(i,p)
 async def delete(self,i):return await self.store.delete(i)
 async def relevance(self,text,limit=5):return await self.store.relevant(text,limit)
