"""Phase 11 — Voice acceptance tests (provider-neutral STT/TTS, push-to-talk).

Voice must be OFF by default, must require the microphone gate, must run the
transcript through exactly the same agent pipeline as typed text, and must never
approve anything by itself. The local CLIs are not installed in CI, so these
tests inject providers and assert the REAL pipeline/policy code paths.
"""
import base64
from pathlib import Path

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.control_center import ControlCenter, set_control_center
from app.models import AgentRequest, ExecutionError, ExecutionResponse, Task, TaskStatus
from app.voice.pipeline import VoiceError, VoicePipeline, decode_audio_payload
from app.voice.providers import (NullSTT, NullTTS, OpenAICompatibleSTT,
                                 OpenAICompatibleTTS, PiperTTS, Speech, Transcript,
                                 VoiceProviderError, WhisperCppSTT, build_stt, build_tts)


# --------------------------------------------------------------------------- #
# Fakes                                                                       #
# --------------------------------------------------------------------------- #


class FakeSTT:
    provider_id = "fake-stt"
    remote = False

    def __init__(self, text="open the browser and search", available=True, reason=None):
        self.text = text
        self._available = available
        self._reason = reason
        self.calls: list[bytes] = []

    @property
    def available(self):
        return self._available

    @property
    def reason(self):
        return self._reason

    async def transcribe(self, audio, *, mime="audio/wav", language=None):
        self.calls.append(audio)
        return Transcript(text=self.text, provider=self.provider_id, language=language)


class FakeTTS:
    provider_id = "fake-tts"
    remote = False

    def __init__(self, available=True, reason=None):
        self._available = available
        self._reason = reason
        self.spoken: list[str] = []

    @property
    def available(self):
        return self._available

    @property
    def reason(self):
        return self._reason

    async def synthesize(self, text, *, voice=None):
        self.spoken.append(text)
        return Speech(audio=b"RIFF" + b"0" * 32, mime="audio/wav", provider=self.provider_id)


def _config(**overrides) -> Settings:
    values = dict(database_path=Path(".pytest-data/state.db"),
                  workspace_root=Path(".pytest-data/workspace"),
                  voice_enabled=True, voice_speak_replies=True)
    values.update(overrides)
    return Settings(**values)


def _gate(tmp_path, *, voice=True, microphone=True, emergency=False) -> ControlCenter:
    center = ControlCenter(tmp_path / "control_center.json")
    center.state.voice.enabled = voice
    center.state.voice.microphone_permission = microphone
    if emergency:
        center.emergency_stopped = True
    set_control_center(center)
    return center


class Runner:
    def __init__(self, status=TaskStatus.DONE, answer="done", waiting=False):
        self.requests: list[AgentRequest] = []
        self.waiting = waiting
        self.status = status
        self.answer = answer

    async def __call__(self, request: AgentRequest):
        self.requests.append(request)
        task = Task(goal=request.message)
        task.status = TaskStatus.WAITING if self.waiting else self.status
        task.answer = self.answer
        error = None
        if task.status == TaskStatus.FAILED:
            error = ExecutionError(error_code="AGENT_EXECUTION_FAILED", message="failed")
        return ExecutionResponse(response_type="approval_required" if self.waiting else "direct_answer",
                                 status=task.status, answer=task.answer, task=task,
                                 provider="FAKE", roles=["manager"], error=error)


def _pipeline(tmp_path, *, config=None, stt=None, tts=None, runner=None, **gate):
    _gate(tmp_path, **gate)
    return VoicePipeline(config or _config(), runner=runner or Runner(),
                         store=None, stt=stt or FakeSTT(), tts=tts or FakeTTS())


# --------------------------------------------------------------------------- #
# Secure defaults                                                             #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio()
async def test_voice_disabled_by_default(tmp_path):
    set_control_center(_gate(tmp_path))
    pipeline = VoicePipeline(Settings(voice_enabled=False), runner=Runner(),
                             stt=FakeSTT(), tts=FakeTTS())
    assert pipeline.enabled is False
    assert "VOICE_DISABLED" in pipeline.disabled_reason()
    with pytest.raises(VoiceError):
        await pipeline.session("c1")


@pytest.mark.asyncio()
async def test_control_center_switch_and_microphone_gate(tmp_path):
    center = _gate(tmp_path, voice=False)
    pipeline = VoicePipeline(_config(), runner=Runner(), stt=FakeSTT(), tts=FakeTTS())
    with pytest.raises(VoiceError) as error:
        await pipeline.session("c1")
    assert "VOICE_DISABLED_BY_CONTROL_CENTER" in str(error.value)

    center.state.voice.enabled = True
    center.state.voice.microphone_permission = False
    with pytest.raises(VoiceError) as error:
        await pipeline.session("c1")
    assert "VOICE_MICROPHONE_NOT_PERMITTED" in str(error.value)


@pytest.mark.asyncio()
async def test_emergency_stop_blocks_voice(tmp_path):
    _gate(tmp_path, emergency=True)
    pipeline = VoicePipeline(_config(), runner=Runner(), stt=FakeSTT(), tts=FakeTTS())
    with pytest.raises(VoiceError) as error:
        await pipeline.session("c1")
    assert "SECUREAGENT_STOPPED" in str(error.value)


@pytest.mark.asyncio()
async def test_push_to_talk_is_the_default_mode(tmp_path):
    pipeline = _pipeline(tmp_path)
    status = await pipeline.status()
    assert status["push_to_talk"] is True
    assert status["wake_word_enabled"] is False
    assert status["limits"]["max_audio_bytes"] > 0


# --------------------------------------------------------------------------- #
# Security parity with typed input                                             #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio()
async def test_transcript_runs_through_the_same_agent_pipeline(tmp_path):
    runner = Runner(answer="searching")
    pipeline = _pipeline(tmp_path, runner=runner, stt=FakeSTT("search for the news"))
    result = await pipeline.push_to_talk(b"\x00" * 64, conversation_id="c-1")
    assert runner.requests, "the runner (Orchestrator) must receive the transcript"
    request = runner.requests[0]
    assert isinstance(request, AgentRequest)
    assert request.message == "search for the news"
    assert request.conversation_id == "c-1"
    assert result["status"] == TaskStatus.DONE.value
    assert result["transcript"]["provider"] == "fake-stt"


@pytest.mark.asyncio()
async def test_voice_cannot_approve_permissions(tmp_path):
    runner = Runner(waiting=True)
    pipeline = _pipeline(tmp_path, runner=runner, tts=FakeTTS())
    result = await pipeline.push_to_talk(b"\x00" * 16, conversation_id="c-2")
    assert result["approval_required"] is True
    assert result["audio"] is None
    assert "voice cannot approve" in result["note"]
    assert runner.requests[0].approved_permissions == set()  # never widened by voice


@pytest.mark.asyncio()
async def test_transcript_is_bounded(tmp_path):
    pipeline = _pipeline(tmp_path, config=_config(voice_max_text_chars=20),
                         stt=FakeSTT("x" * 500))
    result = await pipeline.transcribe(b"\x00" * 8)
    assert len(result["text"]) == 20


# --------------------------------------------------------------------------- #
# Fail-closed provider behaviour                                               #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio()
async def test_stt_unavailable_is_honest(tmp_path):
    pipeline = _pipeline(tmp_path, stt=FakeSTT(available=False, reason="VOICE_STT_UNAVAILABLE: no model"))
    with pytest.raises(VoiceError) as error:
        await pipeline.transcribe(b"\x00" * 8)
    assert "VOICE_STT_UNAVAILABLE" in str(error.value)


@pytest.mark.asyncio()
async def test_tts_unavailable_still_returns_text_answer(tmp_path):
    pipeline = _pipeline(tmp_path, tts=FakeTTS(available=False, reason="VOICE_TTS_UNAVAILABLE: no binary"))
    result = await pipeline.push_to_talk(b"\x00" * 8, conversation_id="c-3")
    assert result["response"]["answer"] == "done"
    assert "VOICE_TTS_UNAVAILABLE" in result["audio_error"]


@pytest.mark.asyncio()
async def test_audio_bounds_and_encoding(tmp_path):
    pipeline = _pipeline(tmp_path, config=_config(voice_max_audio_bytes=1_024))
    with pytest.raises(VoiceError) as error:
        await pipeline.transcribe(b"\x00" * 2_048)
    assert "VOICE_AUDIO_TOO_LARGE" in str(error.value)
    with pytest.raises(VoiceProviderError) as error:
        decode_audio_payload("not-base64!!", _config(voice_max_audio_bytes=1_024))
    assert "VOICE_INVALID_AUDIO_ENCODING" in str(error.value)
    good = base64.b64encode(b"\x00" * 32).decode()
    assert decode_audio_payload(good, _config(voice_max_audio_bytes=1_024)) == b"\x00" * 32
    with pytest.raises(VoiceProviderError):
        decode_audio_payload(base64.b64encode(b"\x00" * 4_000).decode(),
                             _config(voice_max_audio_bytes=1_024))


@pytest.mark.asyncio()
async def test_remote_providers_require_explicit_opt_in(tmp_path):
    config = _config(voice_stt_provider="remote", voice_allow_remote_providers=False,
                     voice_remote_stt_endpoint="https://api.example.com/v1/audio/transcriptions",
                     voice_remote_api_key="k")
    provider = build_stt(config)
    assert isinstance(provider, OpenAICompatibleSTT)
    assert provider.available is False
    assert "VOICE_REMOTE_DISABLED" in (provider.reason or "")
    with pytest.raises(VoiceProviderError):
        await provider.transcribe(b"\x00" * 8)

    tts = OpenAICompatibleTTS(config)
    assert tts.available is False


def test_settings_reject_plain_http_remote_voice():
    with pytest.raises(ValidationError):
        Settings(voice_allow_remote_providers=True,
                 voice_remote_stt_endpoint="http://api.example.com")


@pytest.mark.asyncio()
async def test_remote_provider_refuses_non_https_endpoint(tmp_path):
    # Defence in depth: even if a non-https endpoint reached the provider, the
    # provider refuses it (the Settings validator is the first line).
    config = _config(voice_allow_remote_providers=True,
                     voice_remote_stt_endpoint="https://api.example.com/v1",
                     voice_remote_api_key="test-key")
    provider = OpenAICompatibleSTT(config)
    provider.endpoint = "http://api.example.com/v1"
    assert provider.available is True
    with pytest.raises(VoiceProviderError) as error:
        await provider.transcribe(b"\x00" * 8)
    assert "VOICE_REMOTE_ENDPOINT_DENIED" in str(error.value)


def test_local_cli_providers_report_missing_binaries(tmp_path):
    config = _config(voice_stt_binary="/nonexistent/whisper-cli",
                     voice_tts_binary="/nonexistent/piper")
    stt = WhisperCppSTT(config)
    tts = PiperTTS(config)
    assert stt.available is False and "not found" in (stt.reason or "")
    assert tts.available is False and "not found" in (tts.reason or "")


def test_unknown_provider_preference_is_refused(tmp_path):
    # The typed Settings field refuses unknown provider names outright ...
    with pytest.raises(ValidationError):
        _config(voice_stt_provider="magic")
    # ... and the provider factory still refuses them if one slips through.
    raw = _config()
    raw.voice_stt_provider = "magic"
    with pytest.raises(VoiceProviderError):
        build_stt(raw)
    raw_tts = _config()
    raw_tts.voice_tts_provider = "magic"
    with pytest.raises(VoiceProviderError):
        build_tts(raw_tts)


@pytest.mark.asyncio()
async def test_null_providers_raise_structured_errors():
    with pytest.raises(VoiceProviderError):
        await NullSTT().transcribe(b"x")
    with pytest.raises(VoiceProviderError):
        await NullTTS().synthesize("hi")


# --------------------------------------------------------------------------- #
# Session controls                                                             #
# --------------------------------------------------------------------------- #


@pytest.mark.asyncio()
async def test_mute_blocks_push_to_talk(tmp_path):
    pipeline = _pipeline(tmp_path)
    session = await pipeline.session("c-4")
    pipeline.mute(session.session_id, True)
    with pytest.raises(VoiceError) as error:
        await pipeline.push_to_talk(b"\x00" * 8, conversation_id="c-4", session_id=session.session_id)
    assert "VOICE_MUTED" in str(error.value)
    pipeline.mute(session.session_id, False)
    result = await pipeline.push_to_talk(b"\x00" * 8, conversation_id="c-4",
                                         session_id=session.session_id)
    assert result["status"] == TaskStatus.DONE.value


@pytest.mark.asyncio()
async def test_cancel_and_session_limit(tmp_path):
    pipeline = _pipeline(tmp_path)
    session = await pipeline.session("c-5")
    assert (await pipeline.cancel(session.session_id))["cancelled"] is False
    assert await pipeline.close(session.session_id) is True
    for index in range(4):
        await pipeline.session(f"c-{index}")
    with pytest.raises(VoiceError) as error:
        await pipeline.session("c-overflow")
    assert "VOICE_SESSION_LIMIT" in str(error.value)


@pytest.mark.asyncio()
async def test_unknown_session_conversation_is_refused(tmp_path):
    pipeline = _pipeline(tmp_path)
    with pytest.raises(VoiceError):
        pipeline.mute("missing", True)
    with pytest.raises(VoiceError):
        await pipeline.cancel("missing")


@pytest.mark.asyncio()
async def test_speak_returns_bounded_audio(tmp_path):
    tts = FakeTTS()
    pipeline = _pipeline(tmp_path, tts=tts)
    result = await pipeline.speak("hello there")
    assert result["mime"] == "audio/wav"
    assert base64.b64decode(result["audio_base64"]).startswith(b"RIFF")
    assert tts.spoken == ["hello there"]
    with pytest.raises(VoiceError):
        await pipeline.speak("   ")


@pytest.mark.asyncio()
async def test_voice_audit_trail(tmp_path):
    class Store:
        def __init__(self):
            self.events = []

        async def audit(self, event, details, actor="user"):
            self.events.append((event, details))

    store = Store()
    _gate(tmp_path)
    pipeline = VoicePipeline(_config(), runner=Runner(), store=store, stt=FakeSTT(), tts=FakeTTS())
    await pipeline.push_to_talk(b"\x00" * 8, conversation_id="c-audit")
    names = [event for event, _ in store.events]
    assert "voice.session_started" in names
    assert "voice.transcribed" in names
    assert "voice.turn" in names
    assert "voice.spoken" in names
    # Audit records never carry audio or full transcripts.
    joined = repr(store.events)
    assert "open the browser and search" not in joined


def test_voice_settings_validation(tmp_path):
    with pytest.raises(ValidationError):
        Settings(voice_allow_remote_providers=True, voice_remote_stt_endpoint="http://plain")
    with pytest.raises(ValidationError):
        Settings(voice_max_audio_bytes=10)
