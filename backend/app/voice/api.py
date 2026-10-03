"""REST surface for voice I/O (Phase 11).

Audio in/out stays in the API layer: transcripts become normal AgentRequests and
audio payloads are bounded base64 blobs. No secret, model path or provider key
is ever returned.
"""
from __future__ import annotations

from typing import Any

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel, ConfigDict, Field

from app.voice.pipeline import VoiceError, VoicePipeline


class _Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class SessionIn(_Strict):
    conversation_id: str = Field(min_length=1, max_length=128)
    session_id: str | None = Field(None, max_length=64)


class AudioIn(_Strict):
    audio_base64: str = Field(min_length=4, max_length=80_000_000)
    language: str | None = Field(None, max_length=16)


class TalkIn(AudioIn):
    conversation_id: str | None = Field(None, max_length=128)
    session_id: str | None = Field(None, max_length=64)
    model: str | None = Field(None, max_length=200)
    speak_reply: bool | None = None


class SpeakIn(_Strict):
    text: str = Field(min_length=1, max_length=50_000)


class MuteIn(_Strict):
    muted: bool = True


def build_voice_router(pipeline: VoicePipeline, prefix: str = "/api/v1/voice") -> APIRouter:
    router = APIRouter(prefix=prefix, tags=["voice"])

    @router.get("")
    async def voice_status() -> dict[str, Any]:
        return await pipeline.status()

    @router.post("/sessions", status_code=201)
    async def create_session(payload: SessionIn) -> dict[str, Any]:
        session = await pipeline.session(payload.conversation_id, session_id=payload.session_id)
        return {"session_id": session.session_id, "conversation_id": session.conversation_id,
                "muted": session.muted, "push_to_talk": True}

    @router.delete("/sessions/{session_id}")
    async def close_session(session_id: str) -> dict[str, Any]:
        return {"session_id": session_id, "closed": await pipeline.close(session_id)}

    @router.post("/sessions/{session_id}/transcribe")
    async def transcribe(session_id: str, payload: AudioIn) -> dict[str, Any]:
        if session_id not in pipeline.sessions:
            raise HTTPException(404, detail={"error_code": "VOICE_SESSION_NOT_FOUND",
                                             "message": "Unknown voice session."})
        from app.voice.pipeline import decode_audio_payload
        audio = decode_audio_payload(payload.audio_base64, pipeline.config)
        return await pipeline.transcribe(audio, language=payload.language)

    @router.post("/sessions/{session_id}/mute")
    async def mute(session_id: str, payload: MuteIn) -> dict[str, Any]:
        return pipeline.mute(session_id, payload.muted)

    @router.post("/sessions/{session_id}/cancel")
    async def cancel(session_id: str) -> dict[str, Any]:
        return await pipeline.cancel(session_id)

    @router.post("/push-to-talk")
    async def push_to_talk(payload: TalkIn) -> dict[str, Any]:
        from app.voice.pipeline import decode_audio_payload
        audio = decode_audio_payload(payload.audio_base64, pipeline.config)
        session = pipeline.sessions.get(payload.session_id) if payload.session_id else None
        conversation_id = payload.conversation_id or (session.conversation_id if session else None)
        if not conversation_id:
            raise HTTPException(422, detail={"error_code": "VOICE_CONVERSATION_REQUIRED",
                                             "message": "conversation_id is required for a new voice session."})
        return await pipeline.push_to_talk(audio, conversation_id=conversation_id,
                                           session_id=payload.session_id, model=payload.model,
                                           language=payload.language, speak_reply=payload.speak_reply)

    @router.post("/speak")
    async def speak(payload: SpeakIn) -> dict[str, Any]:
        return await pipeline.speak(payload.text)

    return router


__all__ = ["build_voice_router", "VoiceError", "SessionIn", "TalkIn", "AudioIn", "SpeakIn", "MuteIn"]
