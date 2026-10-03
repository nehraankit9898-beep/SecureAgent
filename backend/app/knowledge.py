import asyncio
import hashlib
import json
import math
import re
import zipfile
from datetime import UTC, datetime
from pathlib import Path
from uuid import uuid4

from app.config import settings
from app.security import SECRET_PATTERN, contains_prompt_injection
from app.workspace import WorkspacePolicy

SUPPORTED={'.txt','.md','.py','.js','.ts','.tsx','.json','.csv','.html','.css','.pdf','.docx'}


def _strip_secrets(text: str) -> tuple[str, int]:
    """Replace secret-shaped patterns with ``[REDACTED]`` so secrets never
    enter the embedding model's context window. Returns the cleaned text
    and a count of redactions performed."""
    if not text:
        return text, 0
    count = 0
    def _sub(match):
        nonlocal count
        count += 1
        return f"{match.group(1)}=[REDACTED]"
    cleaned = SECRET_PATTERN.sub(_sub, text)
    return cleaned, count

def split_chunks(text,size,overlap=180,max_chunks=2000):
    clean=re.sub(r'\r\n?','\n',text).strip();output=[];start=0
    while start<len(clean) and len(output)<max_chunks:
        end=min(len(clean),start+size);chunk=clean[start:end].strip()
        if chunk:output.append(chunk)
        if end>=len(clean):break
        start=max(start+1,end-overlap)
    if start<len(clean) and len(output)>=max_chunks:raise ValueError('document exceeds maximum chunk count')
    return output

def cosine(left,right):
    if not left or len(left)!=len(right):return 0.0
    dot=sum(x*y for x,y in zip(left,right));a=math.sqrt(sum(x*x for x in left));b=math.sqrt(sum(y*y for y in right))
    return dot/(a*b) if a and b else 0.0

def extract(path:Path,data:bytes,max_pages=500,max_chars=2_000_000,max_members=2000,max_expanded=50_000_000):
    suffix=path.suffix.lower()
    if suffix not in SUPPORTED:raise ValueError('unsupported document type')
    try:
        if suffix=='.pdf':
            from io import BytesIO
            from pypdf import PdfReader
            reader=PdfReader(BytesIO(data));
            if reader.is_encrypted: raise ValueError('encrypted PDF is not supported')
            if len(reader.pages)>max_pages: raise ValueError('PDF page limit exceeded')
            text='\n\n'.join(page.extract_text() or '' for page in reader.pages)
            if len(text)>max_chars: raise ValueError('document text limit exceeded')
            return text
        if suffix=='.docx':
            from io import BytesIO
            from docx import Document
            with zipfile.ZipFile(BytesIO(data)) as archive:
                infos=archive.infolist()
                if len(infos)>max_members or sum(i.file_size for i in infos)>max_expanded: raise ValueError('DOCX expansion limit exceeded')
                if any(i.file_size>max_expanded or '..' in Path(i.filename).parts for i in infos): raise ValueError('unsafe DOCX archive')
            text='\n'.join(paragraph.text for paragraph in Document(BytesIO(data)).paragraphs)
            if len(text)>max_chars: raise ValueError('document text limit exceeded')
            return text
    except Exception as error:raise ValueError(f'invalid {suffix[1:]} document') from error
    return data.decode('utf-8',errors='replace')

class KnowledgeStore:
    def __init__(self,memory,llm,workspace,max_bytes):
        config=settings();self.memory=memory;self.llm=llm;self.max_bytes=min(max_bytes,config.max_document_bytes)
        self.policy=WorkspacePolicy(workspace,config.max_read_bytes,config.max_write_bytes,config.max_search_file_bytes,config.max_search_files,config.max_directory_depth)
        self.max_chunks=config.max_chunks_per_document;self.max_documents=config.max_total_documents;self.chunk_size=config.max_chunk_size;self.max_candidates=config.max_retrieval_candidates
    async def ingest(self,relative,title=None,reindex=False,metadata=None):
        path=self.policy.resolve(relative,must_exist=True)
        if path.suffix.lower() not in SUPPORTED:raise ValueError('unsupported document type')
        data,truncated=self.policy.read_bytes(relative,self.max_bytes)
        if truncated:raise ValueError('document too large')
        digest=hashlib.sha256(data).hexdigest();existing=await self.memory.find_document_hash(digest)
        if existing and not reindex:raise ValueError(f'duplicate document: {existing["id"]}')
        documents=await self.memory.documents()
        if not existing and len(documents)>=self.max_documents:raise ValueError('document limit reached')
        try: text=await asyncio.wait_for(asyncio.to_thread(extract,path,data),20)
        except asyncio.TimeoutError as error: raise ValueError('document parser timeout') from error
        # Strip secret-shaped patterns from the text BEFORE chunking and
        # embedding so secrets never enter the LLM context window. This is
        # defence-in-depth on top of the WorkspacePolicy's sensitive-path
        # blocklist (which refuses to ingest .env, *.pem, ~/.ssh/*, etc.).
        text, secret_count = _strip_secrets(text)
        parts=await asyncio.to_thread(split_chunks,text,self.chunk_size,min(180,self.chunk_size//4),self.max_chunks)
        if not parts:raise ValueError('no extractable text')
        config=settings();vectors=[];total_values=0
        for start in range(0,len(parts),config.max_embedding_batch):
            batch=await self.llm.embed(parts[start:start+config.max_embedding_batch])
            total_values+=sum(len(vector) for vector in batch)
            if total_values>config.max_embedding_values:raise ValueError('document embeddings exceed value limit')
            vectors.extend(batch)
        if len(vectors)!=len(parts):raise ValueError('embedding count mismatch')
        version=int(existing['version'])+1 if existing else 1
        document_id=str(uuid4());stamp=datetime.now(UTC).isoformat();meta=dict(metadata or {})
        meta['contains_prompt_injection_pattern']=contains_prompt_injection(text)
        meta['secrets_stripped']=secret_count
        meta['untrusted']=True  # documents are DATA, never authorization
        await self.memory.save_document(document_id,title or path.name,relative,stamp,parts,vectors,digest,version,meta,existing['id'] if existing and reindex else None)
        # Audit ingestion so we have a record of what entered the knowledge base.
        await self.memory.audit('knowledge.ingested', {
            'document_id': document_id, 'title': title or path.name,
            'path': relative, 'chunk_count': len(parts),
            'secrets_stripped': secret_count,
            'contains_prompt_injection_pattern': meta['contains_prompt_injection_pattern'],
        })
        return {'id':document_id,'title':title or path.name,'path':relative,'content_hash':digest,'version':version,'chunk_count':len(parts),'created_at':stamp,'metadata':meta}
    async def search(self,query,limit=6,document_id=None,min_score=0.0):
        vector=(await self.llm.embed([query]))[0];rows=await self.memory.document_chunks(document_id,self.max_candidates)
        # Audit retrieval so we have a record of what left the knowledge base
        # and entered the LLM context window. Best-effort: mock stores in
        # tests may not implement audit().
        try:
            await self.memory.audit('knowledge.retrieved', {
                'query': query[:200], 'limit': limit,
                'document_id': document_id, 'candidate_count': len(rows),
            })
        except (AttributeError, Exception):
            pass
        return await asyncio.to_thread(self._rank,vector,rows,limit,min_score)
    @staticmethod
    def _rank(vector,rows,limit,min_score):
        ranked=[]
        for row in rows:
            try:stored=json.loads(row['embedding'])
            except (TypeError,json.JSONDecodeError):continue
            if not isinstance(stored,list) or len(stored)!=len(vector):continue
            try:score=cosine(vector,[float(value) for value in stored])
            except (TypeError,ValueError,OverflowError):continue
            if not math.isfinite(score) or score<min_score:continue
            ranked.append({'document_id':row['document_id'],'title':row['title'],'path':row['path'],'document_version':row['version'],'chunk_index':row['chunk_index'],'content':row['content'],'score':round(score,6),'source':{'document_id':row['document_id'],'path':row['path'],'chunk_index':row['chunk_index']},'untrusted':True})
        return sorted(ranked,key=lambda item:item['score'],reverse=True)[:limit]
