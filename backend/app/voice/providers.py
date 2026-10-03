"""Phase 11 — Voice (provider-neutral STT/TTS).

Design rules:
* Providers are pluggable: local CLI providers (whisper.cpp for STT, Piper for
  TTS) are the default; remote providers exist but are refused unless the
  operator explicitly enables remote voice processing.
* Nothing is downloaded automatically and no model is assumed: an unconfigured
  or missing binary/model reports ``VOICE_*_UNAVAILABLE`` honestly.
* Default mode is PUSH TO TALK. There is no always-on listening path, and the
  microphone gate (Settings + Control Center) must be open before any audio is
  accepted.
* A transcript is USER INPUT: it enters exactly the same AgentRequest pipeline
  (schema → permissions → approval → tools → verification → audit) as typed
  text. Voice can never grant a permission or approve a high-risk action — the
  approval must still come from the Control Center.

Local-first provider layout::

    STTProvider  ├── WhisperCppSTT      (local binary + model)
                 ├── OpenAICompatibleSTT (remote; opt-in only)
                 └── NullSTT            (unavailable, honest reason)
    TTSProvider  ├── PiperTTS           (local binary + voice model)
                 ├── OpenAICompatibleTTS (remote; opt-in only)
                 └── NullTTS            (unavailable, honest reason)
"""
from __future__ import annotations

import asyncio
import base64
import os
import shutil
import tempfile
from abc import ABC, abstractmethod
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from app.config import settings
from app.security import redact


class VoiceProviderError(RuntimeError):
    """Structured, secret-safe provider failure (message == code)."""

    def __init__(self, code: str, detail: str = ""):
        super().__init__(code if not detail else f"{code}: {detail}")
        self.code = code


@dataclass(frozen=True)
class Transcript:
    text: str
    provider: str
    confidence: float = 0.0
    language: str | None = None


@dataclass(frozen=True)
class Speech:
    audio: bytes
    mime: str
    provider: str


def _safe_text(value: str, limit: int) -> str:
    text = redact(str(value or "")).strip()
    return text[:limit]


class STTProvider(ABC):
    provider_id = "abstract"
    remote = False

    @property
    @abstractmethod
    def available(self) -> bool: ...

    @property
    @abstractmethod
    def reason(self) -> str | None: ...

    @abstractmethod
    async def transcribe(self, audio: bytes, *, mime: str = "audio/wav",
                         language: str | None = None) -> Transcript: ...


class TTSProvider(ABC):
    provider_id = "abstract"
    remote = False

    @property
    @abstractmethod
    def available(self) -> bool: ...

    @property
    @abstractmethod
    def reason(self) -> str | None: ...

    @abstractmethod
    async def synthesize(self, text: str, *, voice: str | None = None) -> Speech: ...


class NullSTT(STTProvider):
    provider_id = "disabled"

    def __init__(self, reason: str = "VOICE_STT_UNAVAILABLE: no local speech-to-text provider configured"):
        self._reason = reason

    @property
    def available(self) -> bool:
        return False

    @property
    def reason(self) -> str | None:
        return self._reason

    async def transcribe(self, audio: bytes, *, mime: str = "audio/wav",
                         language: str | None = None) -> Transcript:
        raise VoiceProviderError(self._reason)


class NullTTS(TTSProvider):
    provider_id = "disabled"

    def __init__(self, reason: str = "VOICE_TTS_UNAVAILABLE: no local text-to-speech provider configured"):
        self._reason = reason

    @property
    def available(self) -> bool:
        return False

    @property
    def reason(self) -> str | None:
        return self._reason

    async def synthesize(self, text: str, *, voice: str | None = None) -> Speech:
        raise VoiceProviderError(self._reason)


class _CliProvider:
    """Shared, shell-free CLI invocation with a hard timeout and bounded output."""

    def __init__(self, binary: str | None, timeout_seconds: float):
        self.binary = str(binary).strip() if binary else None
        self.timeout = float(timeout_seconds)
        self._resolved: str | None = None
        self._reason: str | None = None
        self._probe()

    def _probe(self) -> None:
        if not self.binary:
            self._reason = "not configured"
            return
        candidate = Path(self.binary).expanduser()
        resolved = None
        if candidate.is_absolute() and candidate.is_file() and os.access(candidate, os.X_OK):
            resolved = str(candidate)
        elif "/" not in self.binary:
            found = shutil.which(self.binary)
            if found:
                resolved = found
        self._resolved = resolved
        if resolved is None:
            self._reason = f"binary not found or not executable: {self.binary}"

    @property
    def available(self) -> bool:
        return self._resolved is not None

    @property
    def reason(self) -> str | None:
        return None if self.available else (self._reason or "unavailable")

    async def _run(self, argv: list[str], *, stdin: bytes | None = None) -> tuple[int, bytes, bytes]:
        try:
            process = await asyncio.create_subprocess_exec(
                *argv, stdin=asyncio.subprocess.PIPE if stdin is not None else asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        except (OSError, ValueError) as error:
            raise VoiceProviderError("VOICE_PROVIDER_START_FAILED",
                                     type(error).__name__) from None
        try:
            stdout, stderr = await asyncio.wait_for(process.communicate(stdin), self.timeout)
        except asyncio.TimeoutError:
            process.kill()
            await process.wait()
            raise VoiceProviderError("VOICE_PROVIDER_TIMEOUT") from None
        return process.returncode or 0, stdout[: self.max_output], stderr[: 4000]

    max_output = 2_000_000


class WhisperCppSTT(_CliProvider, STTProvider):
    """Local whisper.cpp CLI. Never runs a shell; arguments are a fixed vector."""
    provider_id = "whisper.cpp"
    remote = False

    def __init__(self, config):
        _CliProvider.__init__(self, getattr(config, "voice_stt_binary", None),
                              float(getattr(config, "voice_timeout_seconds", 60)))
        self.model = str(getattr(config, "voice_stt_model_path", "") or "").strip() or None
        self.max_chars = int(getattr(config, "voice_max_text_chars", 4_000))
        if self.available and not (self.model and Path(self.model).expanduser().is_file()):
            self._reason = "VOICE_STT_MODEL_MISSING: configure voice_stt_model_path"

    @property
    def available(self) -> bool:
        return self._resolved is not None and bool(self.model and Path(self.model).expanduser().is_file())

    async def transcribe(self, audio: bytes, *, mime: str = "audio/wav",
                         language: str | None = None) -> Transcript:
        if not self.available:
            raise VoiceProviderError("VOICE_STT_UNAVAILABLE", self.reason or "unavailable")
        suffix = ".wav" if "wav" in (mime or "") else ".audio"
        with tempfile.TemporaryDirectory(prefix="secureagent-voice-") as directory:
            source = Path(directory) / f"input{suffix}"
            source.write_bytes(audio)
            out_prefix = Path(directory) / "transcript"
            argv = [str(self._resolved), "-m", str(Path(self.model).expanduser()),
                    "-f", str(source), "-nt", "-otxt", "-of", str(out_prefix), "-np"]
            if language:
                argv += ["-l", str(language)[:8]]
            code, stdout, _stderr = await self._run(argv)
            text = ""
            produced = Path(str(out_prefix) + ".txt")
            if produced.is_file():
                text = produced.read_text(encoding="utf-8", errors="replace")
            elif stdout:
                text = stdout.decode("utf-8", "replace")
            if code != 0 and not text.strip():
                raise VoiceProviderError("VOICE_STT_FAILED")
            return Transcript(text=_safe_text(text, self.max_chars), provider=self.provider_id,
                              language=language)


class PiperTTS(_CliProvider, TTSProvider):
    """Local Piper CLI; text is piped on stdin (no shell interpolation)."""
    provider_id = "piper"
    remote = False

    def __init__(self, config):
        _CliProvider.__init__(self, getattr(config, "voice_tts_binary", None),
                              float(getattr(config, "voice_timeout_seconds", 60)))
        self.model = str(getattr(config, "voice_tts_model_path", "") or "").strip() or None
        self.max_chars = int(getattr(config, "voice_max_text_chars", 4_000))
        self.max_bytes = int(getattr(config, "voice_max_audio_bytes", 8_000_000))

    @property
    def available(self) -> bool:
        return self._resolved is not None and bool(self.model and Path(self.model).expanduser().is_file())

    async def synthesize(self, text: str, *, voice: str | None = None) -> Speech:
        if not self.available:
            raise VoiceProviderError("VOICE_TTS_UNAVAILABLE", self.reason or "unavailable")
        payload = _safe_text(text, self.max_chars).encode("utf-8")
        if not payload:
            raise VoiceProviderError("VOICE_EMPTY_TEXT")
        with tempfile.TemporaryDirectory(prefix="secureagent-voice-") as directory:
            target = Path(directory) / "speech.wav"
            argv = [str(self._resolved), "--model", str(Path(self.model).expanduser()),
                    "--output_file", str(target)]
            if voice:
                argv += ["--speaker", str(voice)[:64]]
            code, _stdout, _stderr = await self._run(argv, stdin=payload)
            if code != 0 or not target.is_file():
                raise VoiceProviderError("VOICE_TTS_FAILED")
            audio = target.read_bytes()
        if len(audio) > self.max_bytes:
            raise VoiceProviderError("VOICE_TTS_OUTPUT_TOO_LARGE")
        return Speech(audio=audio, mime="audio/wav", provider=self.provider_id)


class OpenAICompatibleSTT(STTProvider):
    """Remote STT (OpenAI-compatible /audio/transcriptions). Opt-in only."""
    provider_id = "openai-compatible-stt"
    remote = True

    def __init__(self, config):
        self.enabled = bool(getattr(config, "voice_allow_remote_providers", False))
        self.endpoint = str(getattr(config, "voice_remote_stt_endpoint", "") or "").strip() or None
        self.api_key = getattr(config, "voice_remote_api_key", None)
        self.model = str(getattr(config, "voice_remote_model", "") or "whisper-1")
        self.timeout = float(getattr(config, "voice_timeout_seconds", 60))
        self.max_chars = int(getattr(config, "voice_max_text_chars", 4_000))
        self._reason = None
        if not self.enabled:
            self._reason = "VOICE_REMOTE_DISABLED: remote voice processing is disabled in Settings"
        elif not self.endpoint or not self.api_key:
            self._reason = "VOICE_REMOTE_NOT_CONFIGURED: endpoint and key are required"

    @property
    def available(self) -> bool:
        return self.enabled and bool(self.endpoint and self.api_key)

    @property
    def reason(self) -> str | None:
        return None if self.available else self._reason

    async def transcribe(self, audio: bytes, *, mime: str = "audio/wav",
                         language: str | None = None) -> Transcript:
        if not self.available:
            raise VoiceProviderError("VOICE_STT_UNAVAILABLE", self.reason or "unavailable")
        import httpx
        from urllib.parse import urlsplit
        parts = urlsplit(self.endpoint)
        if parts.scheme != "https" or not parts.hostname:
            raise VoiceProviderError("VOICE_REMOTE_ENDPOINT_DENIED: https is required")
        files = {"file": ("audio.wav", audio, mime or "audio/wav")}
        data: dict[str, Any] = {"model": self.model}
        if language:
            data["language"] = str(language)[:8]
        try:
            async with httpx.AsyncClient(timeout=self.timeout, trust_env=False,
                                         follow_redirects=False) as client:
                response = await client.post(self.endpoint, files=files, data=data,
                                             headers={"Authorization": f"Bearer {self.api_key}"})
                response.raise_for_status()
                payload = response.json()
        except Exception:
            raise VoiceProviderError("VOICE_STT_REQUEST_FAILED") from None
        text = payload.get("text") if isinstance(payload, dict) else None
        if not isinstance(text, str):
            raise VoiceProviderError("VOICE_STT_INVALID_RESPONSE")
        return Transcript(text=_safe_text(text, self.max_chars), provider=self.provider_id,
                          language=language)


class OpenAICompatibleTTS(TTSProvider):
    """Remote TTS (OpenAI-compatible /audio/speech). Opt-in only."""
    provider_id = "openai-compatible-tts"
    remote = True

    def __init__(self, config):
        self.enabled = bool(getattr(config, "voice_allow_remote_providers", False))
        self.endpoint = str(getattr(config, "voice_remote_tts_endpoint", "") or "").strip() or None
        self.api_key = getattr(config, "voice_remote_api_key", None)
        self.model = str(getattr(config, "voice_remote_tts_model", "") or "tts-1")
        self.timeout = float(getattr(config, "voice_timeout_seconds", 60))
        self.max_chars = int(getattr(config, "voice_max_text_chars", 4_000))
        self.max_bytes = int(getattr(config, "voice_max_audio_bytes", 8_000_000))
        self._reason = None
        if not self.enabled:
            self._reason = "VOICE_REMOTE_DISABLED: remote voice processing is disabled in Settings"
        elif not self.endpoint or not self.api_key:
            self._reason = "VOICE_REMOTE_NOT_CONFIGURED: endpoint and key are required"

    @property
    def available(self) -> bool:
        return self.enabled and bool(self.endpoint and self.api_key)

    @property
    def reason(self) -> str | None:
        return None if self.available else self._reason

    async def synthesize(self, text: str, *, voice: str | None = None) -> Speech:
        if not self.available:
            raise VoiceProviderError("VOICE_TTS_UNAVAILABLE", self.reason or "unavailable")
        import httpx
        from urllib.parse import urlsplit
        parts = urlsplit(self.endpoint)
        if parts.scheme != "https" or not parts.hostname:
            raise VoiceProviderError("VOICE_REMOTE_ENDPOINT_DENIED: https is required")
        payload = {"model": self.model, "input": _safe_text(text, self.max_chars),
                   "voice": str(voice or "alloy")[:64], "format": "wav"}
        try:
            async with httpx.AsyncClient(timeout=self.timeout, trust_env=False,
                                         follow_redirects=False) as client:
                response = await client.post(self.endpoint, json=payload,
                                             headers={"Authorization": f"Bearer {self.api_key}"})
                response.raise_for_status()
                audio = response.content
        except Exception:
            raise VoiceProviderError("VOICE_TTS_REQUEST_FAILED") from None
        if not audio or len(audio) > self.max_bytes:
            raise VoiceProviderError("VOICE_TTS_OUTPUT_TOO_LARGE")
        return Speech(audio=audio, mime="audio/wav", provider=self.provider_id)


@dataclass(frozen=True)
class VoiceCapabilities:
    stt_provider: str
    stt_available: bool
    stt_reason: str | None
    tts_provider: str
    tts_available: bool
    tts_reason: str | None


def build_stt(config, *, engine=None) -> STTProvider:
    """Select an STT provider. Local first; remote only when explicitly enabled."""
    if engine is not None:
        return engine
    preference = str(getattr(config, "voice_stt_provider", "auto") or "auto").lower()
    local = WhisperCppSTT(config)
    remote = OpenAICompatibleSTT(config)
    if preference in {"whisper", "whisper.cpp", "local", "auto"}:
        if local.available or preference != "auto":
            return local
        return remote if remote.available else local
    if preference in {"openai", "remote", "openai-compatible"}:
        return remote
    raise VoiceProviderError("VOICE_UNKNOWN_STT_PROVIDER", preference[:40])


def build_tts(config, *, engine=None) -> TTSProvider:
    if engine is not None:
        return engine
    preference = str(getattr(config, "voice_tts_provider", "auto") or "auto").lower()
    local = PiperTTS(config)
    remote = OpenAICompatibleTTS(config)
    if preference in {"piper", "local", "auto"}:
        if local.available or preference != "auto":
            return local
        return remote if remote.available else local
    if preference in {"openai", "remote", "openai-compatible"}:
        return remote
    raise VoiceProviderError("VOICE_UNKNOWN_TTS_PROVIDER", preference[:40])


def capabilities(config, *, stt_engine=None, tts_engine=None) -> VoiceCapabilities:
    stt = build_stt(config, engine=stt_engine)
    tts = build_tts(config, engine=tts_engine)
    return VoiceCapabilities(stt_provider=stt.provider_id, stt_available=stt.available,
                             stt_reason=None if stt.available else stt.reason,
                             tts_provider=tts.provider_id, tts_available=tts.available,
                             tts_reason=None if tts.available else tts.reason)


def decode_audio(payload_b64: str, *, max_bytes: int) -> bytes:
    """Decode bounded base64 audio from an API payload (never a file path)."""
    if not isinstance(payload_b64, str) or not payload_b64.strip():
        raise VoiceProviderError("VOICE_EMPTY_AUDIO")
    if len(payload_b64) > (max_bytes * 4 // 3) + 1024:
        raise VoiceProviderError("VOICE_AUDIO_TOO_LARGE")
    try:
        audio = base64.b64decode(payload_b64, validate=True)
    except Exception:
        raise VoiceProviderError("VOICE_INVALID_AUDIO_ENCODING") from None
    if len(audio) > max_bytes:
        raise VoiceProviderError("VOICE_AUDIO_TOO_LARGE")
    return audio


def default_config():
    return settings()
