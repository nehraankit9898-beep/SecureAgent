"""PerceptionProvider implementations behind the Phase-1 contract.

Both providers compose the adapters (capture -> redaction -> optional OCR /
optional vision) and return structured ``Observation`` objects carrying
source, timestamp, confidence and screen/window identifiers. Capture failure
is handled safely: it always produces an Observation with kind="system" and
an error summary rather than raising raw OS errors into the agent loop.
"""

from __future__ import annotations

from typing import Any

from app.computer.contracts import Observation, PerceptionProvider
from app.computer.perception.capture import (
    CaptureError,
    ScreenCaptureBackend,
    UnsupportedPlatformCapture,
)
from app.computer.perception.privacy import RedactionPlan, ScreenshotStore, redact_png


class ScreenPerceptionProvider(PerceptionProvider):
    """Screen capture observation: geometry + window metadata, no pixels by default."""

    provider_id = "screen-capture"

    def __init__(self, backend: ScreenCaptureBackend, *,
                 redaction: RedactionPlan | None = None,
                 store: ScreenshotStore | None = None,
                 max_bytes: int = 12_000_000):
        self._backend = backend
        self._redaction = redaction or RedactionPlan()
        self._store = store
        self._max_bytes = int(max_bytes)

    async def available(self) -> bool:
        try:
            return await self._backend.available()
        except Exception:
            return False

    async def observe(self, task_id: str, params: dict[str, Any]) -> Observation:
        monitor = int(params.get("monitor", 0) or 0)
        include_pixels = bool(params.get("include_pixels", False))
        try:
            capture = await self._backend.capture(monitor=monitor, max_bytes=self._max_bytes)
        except CaptureError as error:
            return Observation(task_id=task_id, provider=self.provider_id, kind="system",
                               summary=f"capture failed: {error.code}",
                               content={"error": error.code, "monitor": monitor})
        except Exception:
            return Observation(task_id=task_id, provider=self.provider_id, kind="system",
                               summary="capture failed: SCREEN_CAPTURE_FAILED",
                               content={"error": "SCREEN_CAPTURE_FAILED", "monitor": monitor})

        image = capture.image_png
        redacted = False
        if not self._redaction.empty:
            image = redact_png(image, self._redaction)
            redacted = True

        selected = capture.monitors[capture.selected_monitor]
        content: dict[str, Any] = {
            "monitor": {"id": selected.id, "name": selected.name,
                        "width": selected.width, "height": selected.height},
            "display_server": capture.display_server,
            "monitors_total": len(capture.monitors),
            "window": capture.active_window.model_dump() if capture.active_window else None,
            "bytes": len(image),
            "persisted_path": None,
        }
        stored_path = None
        if self._store is not None and self._store.enabled:
            probe = Observation(task_id=task_id, provider=self.provider_id, kind="screen",
                                summary="persist-probe")
            stored_path = self._store.store(image, probe.id, redacted=redacted or self._redaction.empty)
            content["persisted_path"] = stored_path
        if include_pixels:
            # Only ever present when explicitly requested AND after redaction.
            content["image_b64_len"] = len(image)

        window_title = capture.active_window.title if capture.active_window else ""
        return Observation(
            task_id=task_id, provider=self.provider_id, kind="screen",
            summary=(f"{selected.width}x{selected.height} on {selected.name}"
                     + (f"; active window: {window_title[:200]}" if window_title else ""))[:2000],
            content=content,
        )


class OcrPerceptionProvider(PerceptionProvider):
    """Local-first OCR observation over the same capture pipeline."""

    provider_id = "local-ocr"

    def __init__(self, capture_provider: ScreenPerceptionProvider, ocr_adapter, *,
                 vision_adapter=None):
        self._capture = capture_provider
        self._ocr = ocr_adapter
        self._vision = vision_adapter

    async def available(self) -> bool:
        try:
            return await self._capture.available() and await self._ocr.available()
        except Exception:
            return False

    async def observe(self, task_id: str, params: dict[str, Any]) -> Observation:
        screen = await self._capture.observe(task_id, params)
        if screen.kind == "system":
            return screen  # capture failure propagates safely as system observation
        # Re-capture the (already-redacted) image bytes for the engine: the
        # screen observation intentionally does not carry pixels by default.
        try:
            monitor = int(params.get("monitor", 0) or 0)
            capture = await self._capture._backend.capture(monitor=monitor, max_bytes=self._capture._max_bytes)
            image = capture.image_png
            plan = self._capture._redaction
            if not plan.empty:
                image = redact_png(image, plan)
            result = await self._ocr.recognize(image)
        except CaptureError as error:
            return Observation(task_id=task_id, provider=self.provider_id, kind="system",
                               summary=f"capture failed: {error.code}",
                               content={"error": error.code})
        except Exception as error:
            code = getattr(error, "code", "OCR_ENGINE_FAILED")
            return Observation(task_id=task_id, provider=self.provider_id, kind="system",
                               summary=f"ocr failed: {str(code)[:80]}",
                               content={"error": str(code)[:80]})
        content: dict[str, Any] = {
            "text": result.text[:20_000],
            "confidence": result.confidence,
            "engine": result.engine,
            "screen": screen.content.get("monitor"),
            "window": screen.content.get("window"),
        }
        if self._vision is not None and params.get("use_vision"):
            try:
                vision = await self._vision.describe(image)
                content["vision_description"] = vision.description
                content["vision_confidence"] = vision.confidence
                content["vision_model"] = vision.model
            except Exception as error:
                content["vision_error"] = str(getattr(error, "code", error))[:80]
        return Observation(task_id=task_id, provider=self.provider_id, kind="ocr",
                           summary=result.text[:2000], content=content)
