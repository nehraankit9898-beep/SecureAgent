"""Voice pipeline: microphone → STT → the SAME agent/policy pipeline → TTS.

Security parity is the whole point of this module:

* the transcript becomes an ordinary ``AgentRequest`` and is executed by the
  injected runner (production: ``Orchestrator.run``), so it passes schema
  validation, permissions, approval, sandboxing, verification and audit exactly
  like typed text;
* voice NEVER auto-approves anything: if the agent pauses for approval, the
  pipeline returns ``WAITING_APPROVAL`` and the approval must still arrive from
  the Control Center/API;
* sessions are push-to-talk by default: nothing is captured or processed
  unless the caller explicitly pushes a recording, and the microphone gate
  (Settings + Control Center) must be open;
* mute/interrupt/cancel are first-class operations;
* one audio buffer at a time per session, bounded size, bounded rate.
"""
from __future__ import annotations

import asyncio
import base64
import time
from dataclasses import dataclass, field
from typing import Any, Callable
from uuid import uuid4

from app.config import settings
from app.models import AgentRequest, TaskStatus
from app.voice.providers import (STTProvider, TTSProvider, Transcript,
                                 VoiceProviderError, build_stt, build_tts, capabilities,
                                 decode_audio)

MAX_SESSIONS = 4


class VoiceError(RuntimeError):
    def __init__(self, code: str, detail: str = ""):
        super().__init__(code if not detail else f"{code}: {detail}")
        self.code = code


@dataclass
class VoiceSession:
    session_id: str
    conversation_id: str
    created_at: float = field(default_factory=time.monotonic)
    last_used: float = field(default_factory=time.monotonic)
    muted: bool = False
    speaking: bool = False
    listening: bool = False
    turns: int = 0
    task: asyncio.Task | None = None
    last_transcript_chars: int = 0


class VoicePipeline:
    def __init__(self, config, *, runner: Callable[[AgentRequest], Any], store=None,
                 stt: STTProvider | None = None, tts: TTSProvider | None = None,
                 control_center=None):
        self.config = config
        self.runner = runner
        self.store = store
        self.control_center = control_center
        self.stt = stt or build_stt(config)
        self.tts = tts or build_tts(config)
        self.sessions: dict[str, VoiceSession] = {}
        self._lock = asyncio.Lock()

    # -- gates ---------------------------------------------------------------- #
    def _gate(self):
        if self.control_center is not None:
            return self.control_center
        try:
            from app.control_center import get_control_center
            return get_control_center()
        except Exception:
            return None

    @property
    def enabled(self) -> bool:
        if not bool(getattr(self.config, "voice_enabled", False)):
            return False
        gate = self._gate()
        if gate is not None:
            if gate.blocked_by_emergency or not gate.voice_active():
                return False
        return True

    def disabled_reason(self) -> str:
        if not bool(getattr(self.config, "voice_enabled", False)):
            return "VOICE_DISABLED: Voice is disabled in Settings"
        gate = self._gate()
        if gate is not None and gate.blocked_by_emergency:
            return "SECUREAGENT_STOPPED: emergency stop is active"
        if gate is not None and not gate.state.voice.enabled:
            return "VOICE_DISABLED_BY_CONTROL_CENTER: the Voice master switch is OFF"
        if gate is not None and not gate.state.voice.microphone_permission:
            return "VOICE_MICROPHONE_NOT_PERMITTED: grant microphone permission in the Control Center"
        return "VOICE_DISABLED"

    def check_enabled(self) -> None:
        if not self.enabled:
            raise VoiceError(self.disabled_reason())

    # -- sessions -------------------------------------------------------------- #
    async def session(self, conversation_id: str, *, session_id: str | None = None) -> VoiceSession:
        self.check_enabled()
        await self.sweep()
        if session_id:
            existing = self.sessions.get(session_id)
            if existing is not None:
                existing.last_used = time.monotonic()
                return existing
        if len(self.sessions) >= MAX_SESSIONS:
            raise VoiceError("VOICE_SESSION_LIMIT: too many voice sessions")
        identifier = session_id or uuid4().hex[:12]
        session = VoiceSession(session_id=identifier, conversation_id=conversation_id)
        self.sessions[identifier] = session
        await self._audit("voice.session_started", {"session_id": identifier,
                                                    "conversation_id": conversation_id})
        return session

    async def close(self, session_id: str) -> bool:
        session = self.sessions.pop(session_id, None)
        if session is None:
            return False
        if session.task is not None and not session.task.done():
            session.task.cancel()
        await self._audit("voice.session_closed", {"session_id": session_id})
        return True

    async def sweep(self, ttl_seconds: float = 1800.0) -> int:
        now = time.monotonic()
        expired = [sid for sid, session in self.sessions.items()
                   if (now - session.last_used) > ttl_seconds and session.task is None]
        for session_id in expired:
            await self.close(session_id)
        return len(expired)

    def mute(self, session_id: str, muted: bool = True) -> dict[str, Any]:
        session = self.sessions.get(session_id)
        if session is None:
            raise VoiceError("VOICE_SESSION_NOT_FOUND")
        session.muted = bool(muted)
        return {"session_id": session_id, "muted": session.muted}

    async def cancel(self, session_id: str) -> dict[str, Any]:
        session = self.sessions.get(session_id)
        if session is None:
            raise VoiceError("VOICE_SESSION_NOT_FOUND")
        cancelled = False
        if session.task is not None and not session.task.done():
            session.task.cancel()
            cancelled = True
        session.listening = False
        session.speaking = False
        await self._audit("voice.cancelled", {"session_id": session_id, "cancelled": cancelled})
        return {"session_id": session_id, "cancelled": cancelled}

    # -- transcribe / speak ------------------------------------------------------ #
    async def transcribe(self, audio: bytes, *, language: str | None = None) -> dict[str, Any]:
        self.check_enabled()
        max_bytes = int(getattr(self.config, "voice_max_audio_bytes", 8_000_000))
        if len(audio) > max_bytes:
            raise VoiceError("VOICE_AUDIO_TOO_LARGE")
        if not self.stt.available:
            raise VoiceError(self.stt.reason or "VOICE_STT_UNAVAILABLE")
        started = time.monotonic()
        transcript = await self.stt.transcribe(audio, language=language)
        # Defence in depth: the pipeline re-applies its own text bound even if a
        # provider (or an injected fake) returns more.
        max_chars = int(getattr(self.config, "voice_max_text_chars", 4_000))
        if len(transcript.text) > max_chars:
            transcript = Transcript(text=transcript.text[:max_chars], provider=transcript.provider,
                                    confidence=transcript.confidence, language=transcript.language)
        await self._audit("voice.transcribed", {"provider": transcript.provider,
                                                "chars": len(transcript.text),
                                                "duration_ms": int((time.monotonic() - started) * 1000)})
        return {"text": transcript.text, "provider": transcript.provider,
                "confidence": transcript.confidence, "language": transcript.language,
                "duration_ms": int((time.monotonic() - started) * 1000)}

    async def speak(self, text: str) -> dict[str, Any]:
        self.check_enabled()
        if not self.tts.available:
            raise VoiceError(self.tts.reason or "VOICE_TTS_UNAVAILABLE")
        max_chars = int(getattr(self.config, "voice_max_text_chars", 4_000))
        if not str(text or "").strip():
            raise VoiceError("VOICE_EMPTY_TEXT")
        speech = await self.tts.synthesize(str(text)[:max_chars])
        await self._audit("voice.spoken", {"provider": speech.provider, "bytes": len(speech.audio)})
        return {"audio_base64": base64.b64encode(speech.audio).decode("ascii"),
                "mime": speech.mime, "provider": speech.provider, "bytes": len(speech.audio)}

    # -- push-to-talk ------------------------------------------------------------ #
    async def push_to_talk(self, audio: bytes, *, conversation_id: str, session_id: str | None = None,
                           model: str | None = None, language: str | None = None,
                           speak_reply: bool | None = None) -> dict[str, Any]:
        """The full voice flow. The transcript runs through the injected runner
        (the same Orchestrator/Agent used for typed chat)."""
        self.check_enabled()
        session = await self.session(conversation_id, session_id=session_id)
        if session.muted:
            raise VoiceError("VOICE_MUTED: unmute before talking")
        if session.listening or session.task is not None:
            raise VoiceError("VOICE_BUSY: finish or cancel the current voice turn first")
        transcript = await self.transcribe(audio, language=language)
        text = transcript["text"].strip()
        if not text:
            raise VoiceError("VOICE_NO_SPEECH_DETECTED")
        session.listening = True
        session.turns += 1
        session.last_transcript_chars = len(text)
        await self._audit("voice.turn", {"session_id": session.session_id, "chars": len(text),
                                         "conversation_id": conversation_id})
        request = AgentRequest(message=text, conversation_id=conversation_id, model=model)
        try:
            response = await self.runner(request)
        finally:
            session.listening = False
            session.last_used = time.monotonic()
        status = getattr(response, "status", None)
        result: dict[str, Any] = {
            "session_id": session.session_id,
            "conversation_id": conversation_id,
            "transcript": transcript,
            "response": response.model_dump(mode="json") if hasattr(response, "model_dump") else response,
            "status": getattr(status, "value", status),
            "approval_required": bool(status == TaskStatus.WAITING
                                      or str(getattr(status, "value", status)) == "waiting"),
            "audio": None,
        }
        # Voice output never includes approval decisions: a WAITING task must be
        # approved through the Control Center/API, exactly like typed chat.
        if result["approval_required"]:
            result["note"] = "The task is waiting for user approval (voice cannot approve)."
            return result
        reply = getattr(response, "answer", None)
        wanted = bool(getattr(self.config, "voice_speak_replies", False)) if speak_reply is None else speak_reply
        if wanted and reply and self.tts.available:
            try:
                session.speaking = True
                result["audio"] = await self.speak(str(reply))
            except VoiceProviderError as error:
                result["audio_error"] = error.code
            finally:
                session.speaking = False
        elif wanted and reply and not self.tts.available:
            result["audio_error"] = self.tts.reason or "VOICE_TTS_UNAVAILABLE"
        return result

    # -- status ------------------------------------------------------------------ #
    async def status(self) -> dict[str, Any]:
        caps = capabilities(self.config, stt_engine=self.stt, tts_engine=self.tts)
        gate = self._gate()
        limits = gate.voice_limits() if gate is not None else {}
        return {
            "enabled": bool(getattr(self.config, "voice_enabled", False)),
            "active": self.enabled,
            "reason": None if self.enabled else self.disabled_reason(),
            "push_to_talk": bool(getattr(self.config, "voice_push_to_talk", True)) and bool(
                limits.get("push_to_talk", True)),
            "wake_word_enabled": bool(limits.get("wake_word_enabled", False)),
            "microphone_permission": bool(limits.get("microphone_permission", False)),
            "speak_replies": bool(limits.get("speak_replies",
                                            getattr(self.config, "voice_speak_replies", False))),
            "stt": {"provider": caps.stt_provider, "available": caps.stt_available,
                    "reason": caps.stt_reason, "remote": bool(self.stt.remote)},
            "tts": {"provider": caps.tts_provider, "available": caps.tts_available,
                    "reason": caps.tts_reason, "remote": bool(self.tts.remote)},
            "limits": {"max_audio_bytes": int(getattr(self.config, "voice_max_audio_bytes", 8_000_000)),
                       "max_text_chars": int(getattr(self.config, "voice_max_text_chars", 4_000)),
                       "timeout_seconds": float(getattr(self.config, "voice_timeout_seconds", 60)),
                       "max_sessions": MAX_SESSIONS},
            "sessions": [{"session_id": session.session_id,
                          "conversation_id": session.conversation_id,
                          "muted": session.muted, "turns": session.turns,
                          "busy": session.listening or session.task is not None,
                          "speaking": session.speaking} for session in self.sessions.values()],
        }

    async def stop(self) -> None:
        for session_id in list(self.sessions):
            await self.close(session_id)

    async def _audit(self, event: str, details: dict[str, Any]) -> None:
        if self.store is None:
            return
        try:
            await self.store.audit(event, details, actor="voice")
        except Exception:
            pass


def decode_audio_payload(payload_b64: str, config=None) -> bytes:
    config = config or settings()
    return decode_audio(payload_b64, max_bytes=int(getattr(config, "voice_max_audio_bytes", 8_000_000)))
