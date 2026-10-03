from __future__ import annotations

from abc import ABC, abstractmethod
import asyncio
import json
import logging
import math
import re
import time
from typing import Any

import httpx

from app.config import settings
from app.models import ChatRequest, ChatResponse


class LLMError(Exception):
    """Structured, secret-safe provider failure."""
    def __init__(self, code: str, message: str, recovery_action: str, *, component: str = "ollama"):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
        self.component = component
        self.recovery_action = recovery_action

    def payload(self) -> dict[str, str]:
        return {"code": self.code, "message": self.message, "component": self.component, "recovery_action": self.recovery_action}


class LLMProvider(ABC):
    @abstractmethod
    async def chat(self, request): ...
    @abstractmethod
    async def embed(self, texts): ...
    @abstractmethod
    async def models(self): ...
    @abstractmethod
    async def close(self): ...


class LocalCoreProvider(LLMProvider):
    """Deterministic utilities only. It never impersonates a generative model."""
    name = "LOCAL CORE"

    @staticmethod
    def _user_text(request: ChatRequest) -> str:
        if request.user_request is not None:
            return request.user_request
        for message in reversed(request.messages):
            if message.role == "user" and not message.content.startswith("<untrusted-data"):
                return message.content.strip()
        return ""

    @staticmethod
    def _evidence_answer(request: ChatRequest) -> str | None:
        for message in reversed(request.messages):
            if message.role != "user" or not message.content.startswith("<untrusted-data"):
                continue
            match = re.search(r"(\[\{.*\}\])\s*</untrusted-data>\s*$", message.content, re.S)
            if not match:
                continue
            try:
                evidence = json.loads(match.group(1))
            except json.JSONDecodeError:
                continue
            verified = []
            for item in evidence:
                result = item.get("result", {}) if isinstance(item, dict) else {}
                if result.get("success"):
                    verified.append({"step": item.get("step"), "tool": item.get("tool"), "output": result.get("output")})
            if verified:
                if len(verified) == 1 and isinstance(verified[0].get("output"), dict) and set(verified[0]["output"]) == {"result"}:
                    return str(verified[0]["output"]["result"])
                return "Verified local tool results: " + json.dumps(verified, ensure_ascii=False)
        return None

    @staticmethod
    def _plan(text: str) -> dict[str, Any]:
        # The arithmetic fallback must not fire on ordinary prose that happens
        # to contain digits ("hello world 123", "room 101-102"). It only plans
        # a calculator step when either the whole message is one arithmetic
        # expression, or an explicit intent keyword ("calculate", "compute",
        # "what is") introduces an arithmetic expression with an operator.
        stripped = text.strip().rstrip("?!.,;:").strip()
        arithmetic_shape = re.compile(r"[0-9eEpiPI+\-*/%(). ^]+", re.I)
        has_operator = re.compile(r"[+\-*/%^]")
        bare = arithmetic_shape.fullmatch(stripped)
        if bare and re.search(r"\d", stripped) and has_operator.search(stripped):
            return {"mode": "plan", "intent": "calculation", "steps": [{"title": "Calculate expression", "tool": "calculator", "arguments": {"expression": stripped.replace("^", "**")}}]}
        intent = re.match(r"(?:calculate|compute|what\s+is)\s*[:\-]?\s*(.+)", stripped, re.I)
        if intent:
            expression = intent.group(1).strip()
            if expression and arithmetic_shape.fullmatch(expression) and re.search(r"\d", expression) and has_operator.search(expression):
                return {"mode": "plan", "intent": "calculation", "steps": [{"title": "Calculate expression", "tool": "calculator", "arguments": {"expression": expression.replace("^", "**")}}]}
        if re.search(r"\b(list|show)\b.*\b(files|workspace)\b", text, re.I):
            return {"mode": "plan", "intent": "files", "steps": [{"title": "List workspace files", "tool": "list_files", "arguments": {"path": ".", "recursive": False, "limit": 200}}]}
        words = re.search(r"(?:word count|count words)(?:\s+(?:in|for))?\s*[:\-]?\s*(.+)", text, re.I | re.S)
        if words:
            return {"mode": "plan", "intent": "text", "steps": [{"title": "Count words", "tool": "text_processing", "arguments": {"text": words.group(1), "operation": "word_count"}}]}
        if re.search(r"\b(current time|what time|date and time)\b", text, re.I):
            zone = (re.search(r"\b(?:in|timezone)\s+([A-Za-z_]+/[A-Za-z_]+|UTC)\b", text, re.I) or [None, "UTC"])[1]
            return {"mode": "plan", "intent": "date_time", "steps": [{"title": "Get local time", "tool": "date_time", "arguments": {"timezone": zone}}]}
        return {"mode": "direct", "intent": "requires_model", "direct_answer": "AI_REASONING_UNAVAILABLE: Ollama is required for generative agent reasoning.", "steps": []}

    async def chat(self, request: ChatRequest) -> ChatResponse:
        if not request.json_mode:
            evidence = self._evidence_answer(request)
            if evidence:
                return ChatResponse(content=evidence, model=self.name)
        plan = self._plan(self._user_text(request))
        if request.json_mode:
            content = json.dumps(plan, ensure_ascii=False)
        else:
            content = plan.get("direct_answer") or "A deterministic tool execution is required for this request."
        return ChatResponse(content=content, model=self.name)

    async def embed(self, texts: list[str]) -> list[list[float]]:
        raise LLMError("AI_EMBEDDING_UNAVAILABLE", "Ollama and the configured embedding model are required for knowledge indexing.", "Start Ollama and install the configured embedding model.")

    async def models(self): return [self.name]
    async def close(self): return None


class OllamaProvider(LLMProvider):
    # (class body continues below; runtime Control Center gates are applied in chat())
    name = "OLLAMA"
    def __init__(self):
        self.config = settings()
        self.default_model = self.config.ollama_model
        self.embedding_model = self.config.embedding_model
        self.client = httpx.AsyncClient(base_url=str(self.config.ollama_base_url).rstrip('/'), timeout=httpx.Timeout(self.config.llm_timeout_seconds), limits=httpx.Limits(max_connections=20, max_keepalive_connections=10), trust_env=False, follow_redirects=False)

    async def _json(self, method: str, path: str, payload=None) -> dict:
        chunks=[]; total=0
        try:
            async with self.client.stream(method, path, json=payload) as response:
                response.raise_for_status()
                declared=response.headers.get('content-length')
                if declared and int(declared)>self.config.max_llm_response_bytes: raise ValueError('response too large')
                async for chunk in response.aiter_bytes():
                    total += len(chunk)
                    if total>self.config.max_llm_response_bytes: raise ValueError('response too large')
                    chunks.append(chunk)
        except httpx.TimeoutException as error:
            raise LLMError("OLLAMA_TIMEOUT", "Ollama did not respond before the timeout.", "Verify the Ollama service and model, then retry.") from error
        except httpx.ConnectError as error:
            raise LLMError("OLLAMA_SERVICE_STOPPED", "The Ollama service is not reachable.", "Start Ollama and test the connection.") from error
        except httpx.HTTPStatusError as error:
            code = "MODEL_NOT_FOUND" if error.response.status_code == 404 else "OLLAMA_INVALID_RESPONSE"
            raise LLMError(code, "Ollama rejected the request.", "Refresh models and verify the configured model.") from error
        except httpx.HTTPError as error:
            raise LLMError("OLLAMA_UNAVAILABLE", "Ollama is unavailable.", "Check the configured URL and service status.") from error
        except (ValueError, TypeError) as error:
            raise LLMError("OLLAMA_INVALID_RESPONSE", "Ollama returned an invalid or oversized response.", "Upgrade or restart Ollama and retry.") from error
        try:
            value=json.loads(b''.join(chunks))
        except (ValueError, UnicodeError) as error:
            raise LLMError("OLLAMA_INVALID_RESPONSE", "Ollama returned invalid JSON.", "Upgrade or restart Ollama and retry.") from error
        if not isinstance(value,dict):
            raise LLMError("OLLAMA_INVALID_RESPONSE", "Ollama returned an invalid response object.", "Upgrade or restart Ollama and retry.")
        return value

    async def version(self) -> str:
        body = await self._json('GET','/api/version')
        version = body.get('version')
        if not isinstance(version, str) or not version:
            raise LLMError("OLLAMA_INVALID_RESPONSE", "Ollama did not return a version.", "Upgrade or restart Ollama.")
        return version

    async def chat(self, request):
        if not request.messages or not any(getattr(message, 'content', '').strip() for message in request.messages):
            raise LLMError("INVALID_CHAT_REQUEST", "Chat input must not be empty.", "Enter a non-empty message and retry.")
        # Control Center AI ENGINE runtime limits (spec section 11): model,
        # temperature, context size and max tokens are applied per request
        # when configured in the Control Center.
        try:
            from app.control_center import get_control_center
            gate = get_control_center()
        except Exception:
            gate = None
        limits = gate.ai_limits() if gate is not None else {}
        model = request.model or limits.get('model') or self.default_model
        completion_tokens = self.config.max_llm_completion_tokens
        if limits.get('max_tokens'):
            completion_tokens = min(int(limits['max_tokens']), completion_tokens)
        if not isinstance(completion_tokens, int) or isinstance(completion_tokens, bool) or not 128 <= completion_tokens <= 131_072:
            raise LLMError("INVALID_CONFIGURATION", "Maximum completion tokens must be an integer between 128 and 131072.", "Correct max_llm_completion_tokens in Settings and restart SecureAgent.", component="configuration")
        temperature = request.temperature
        if limits.get('temperature') is not None and request.temperature == 0.2:
            # The Control Center temperature is the default for ordinary chat
            # requests; the planner's explicit temperature=0 is preserved so
            # autonomous planning stays deterministic.
            temperature = float(limits['temperature'])
        options = {'temperature': temperature, 'num_predict': completion_tokens}
        if limits.get('context_size'):
            options['num_ctx'] = int(limits['context_size'])
        payload={'model':model,'messages':[m.model_dump(exclude={'user_request'}) for m in request.messages],'stream':False,'options':options}
        if request.json_mode: payload['format']='json'
        body=await self._json('POST','/api/chat',payload)
        try: content=body['message']['content']
        except (KeyError, TypeError) as error: raise LLMError("OLLAMA_INVALID_RESPONSE", "Ollama chat response is malformed.", "Test the chat model and inspect diagnostics.") from error
        if not isinstance(content,str) or not content.strip() or len(content)>self.config.max_llm_output_chars:
            raise LLMError("OLLAMA_INVALID_RESPONSE", "Ollama chat content is invalid.", "Test the chat model and inspect diagnostics.")
        return ChatResponse(content=content,model=body.get('model',model),prompt_tokens=body.get('prompt_eval_count'),completion_tokens=body.get('eval_count'))

    async def embed(self,texts):
        if not texts or len(texts)>self.config.max_embedding_batch or any(not isinstance(text,str) or not text or len(text)>self.config.max_embedding_input_chars for text in texts):
            raise LLMError("INVALID_EMBEDDING_REQUEST", "Embedding input is invalid.", "Reduce the batch or text size.")
        body=await self._json('POST','/api/embed',{'model':self.embedding_model,'input':texts}); vectors=body.get('embeddings')
        if not isinstance(vectors,list) or len(vectors)!=len(texts): raise LLMError("OLLAMA_INVALID_RESPONSE", "Ollama embeddings are malformed.", "Test the embedding model.")
        validated=[]
        expected_dimension: int | None = None
        for vector in vectors:
            try: numeric=[float(v) for v in vector]
            except (TypeError, ValueError) as error: raise LLMError("OLLAMA_INVALID_RESPONSE", "Ollama returned a non-numeric embedding.", "Test the embedding model.") from error
            if not numeric or len(numeric)>self.config.max_embedding_dimension or any(not math.isfinite(v) for v in numeric): raise LLMError("OLLAMA_INVALID_RESPONSE", "Ollama returned an invalid embedding.", "Test the embedding model.")
            if expected_dimension is None: expected_dimension = len(numeric)
            elif len(numeric) != expected_dimension: raise LLMError("OLLAMA_INVALID_RESPONSE", "Ollama returned embeddings with inconsistent dimensions.", "Test the embedding model and ensure the configured model is stable.")
            validated.append(numeric)
        return validated

    async def models(self):
        body=await self._json('GET','/api/tags'); models=body.get('models',[])
        if not isinstance(models,list): raise LLMError("OLLAMA_INVALID_RESPONSE", "Ollama model list is invalid.", "Upgrade or restart Ollama.")
        return [item['name'] for item in models if isinstance(item,dict) and isinstance(item.get('name'),str)]
    async def close(self): await self.client.aclose()


class FallbackProvider(LLMProvider):
    def __init__(self):
        self.local=LocalCoreProvider(); self.ollama=OllamaProvider(); self.enabled=settings().ollama_enabled; self.active=self.local.name; self._service=False; self._version=None; self._chat=False; self._embedding=False; self._models=[]; self._last_error: LLMError|None=None; self._checked=0.0; self._lock=asyncio.Lock()

    @staticmethod
    def _has(models: list[str], wanted: str) -> bool:
        return any(name==wanted or name.split(':')[0]==wanted.split(':')[0] for name in models)

    async def refresh(self, force=False):
        # Control Center OLLAMA master switch (spec section 11): when OFF the
        # provider reports OLLAMA_DISABLED and the deterministic local core
        # keeps deterministic features working. Never fake an AI-ready state.
        try:
            from app.control_center import get_control_center
            gate = get_control_center()
        except Exception:
            gate = None
        if gate is not None and not gate.state.ai.ollama_enabled:
            self._models=[];self._service=False;self._version=None;self._chat=False;self._embedding=False;self.active=self.local.name;self._last_error=LLMError("OLLAMA_DISABLED","Ollama is disabled in the Control Center.","Turn the OLLAMA switch ON to use generative models.");return False
        if gate is not None and not gate.ai_active():
            self._models=[];self._service=False;self._version=None;self._chat=False;self._embedding=False;self.active=self.local.name;self._last_error=LLMError("AI_DISABLED","The AI engine is disabled in the Control Center.","Turn the AI ENGINE switch ON to use generative models.");return False
        if not self.enabled:
            self._models=[];self._service=False;self._version=None;self._chat=False;self._embedding=False;self.active=self.local.name;self._last_error=LLMError("OLLAMA_DISABLED","Ollama is disabled in Settings.","Enable Ollama and apply settings.");return False
        if not force and time.monotonic()-self._checked<10: return self._chat
        async with self._lock:
            try:
                self._version=await self.ollama.version();self._service=True;self._models=await self.ollama.models();self._last_error=None
                self._chat=self._has(self._models,self.ollama.default_model); self._embedding=self._has(self._models,self.ollama.embedding_model)
                if not self._chat: self._last_error=LLMError("MODEL_NOT_FOUND", f"Chat model '{self.ollama.default_model}' is not installed.", f"Run: ollama pull {self.ollama.default_model}")
            except LLMError as error:
                self._models=[];self._service=False;self._version=None;self._chat=False;self._embedding=False;self._last_error=error
            self._checked=time.monotonic();self.active=self.ollama.name if self._chat else self.local.name
            return self._chat

    async def chat(self,request):
        if await self.refresh():
            try: self.active=self.ollama.name; return await self.ollama.chat(request)
            except LLMError as error: self._last_error=error;self._chat=False;self.active=self.local.name
        return await self.local.chat(request)

    async def embed(self,texts):
        await self.refresh()
        if not self._embedding:
            if self._last_error and self._last_error.code not in {"MODEL_NOT_FOUND"}: raise self._last_error
            raise LLMError("EMBEDDING_MODEL_NOT_FOUND", f"Embedding model '{self.ollama.embedding_model}' is not installed.", f"Run: ollama pull {self.ollama.embedding_model}")
        return await self.ollama.embed(texts)

    async def models(self):
        await self.refresh(force=True)
        return list(self._models)

    async def status(self):
        await self.refresh()
        return {'active_provider':self.active,'local_core':True,'service_available':self._service,'ollama_version':self._version,'ollama_available':self._service,'generative_available':self._chat,'embedding_available':self._embedding,'model':self.ollama.default_model,'embedding_model':self.ollama.embedding_model,'models':self._models,'last_error':self._last_error.payload() if self._last_error else None}

    async def diagnostics(self):
        await self.refresh(force=True)
        result=await self.status();result['base_url']=str(self.ollama.config.ollama_base_url).rstrip('/');return result
    async def close(self): await self.ollama.close()


_provider=None
def get_llm():
    """The provider the agent core uses.

    Multi-model routing (Phase 13) is composed in ``app.providers``: the router
    tries the configured provider chain first and falls back to this module's
    legacy chain (Ollama when enabled and reachable, otherwise the
    deterministic ``LOCAL CORE``). With no provider configured the behaviour is
    exactly the legacy behaviour.
    """
    global _provider
    if _provider is None:
        try:
            from app.providers import RoutingProvider
            _provider = RoutingProvider(config=settings())
        except Exception:
            logging.getLogger("secureagent.llm").exception(
                "multi-model router unavailable; using the legacy provider chain")
            _provider = FallbackProvider()
    return _provider
async def close_llm():
    global _provider
    if _provider: await _provider.close(); _provider=None
