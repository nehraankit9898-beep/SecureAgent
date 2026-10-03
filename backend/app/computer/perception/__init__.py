"""Phase 4 — Safe computer perception (screen capture, OCR, vision).

Layering (all fail-closed):

* ``capture.py``   — platform screen-capture adapters (grim / scrot / import)
                     with monitor selection and active-window metadata.
* ``privacy.py``   — sensitive-region redaction + screenshot persistence with
                     mandatory retention purge. Persistence is OFF by default.
* ``ocr.py``       — local-first tesseract adapter (no network).
* ``vision.py``    — optional cloud vision adapter; refuses to run unless the
                     endpoint AND key are explicitly configured.
* ``providers.py`` — PerceptionProvider implementations behind the existing
                     Phase-1 contract, returning structured Observations.
* ``tools.py``     — ComputerTool definitions registered ONLY through the
                     existing bridge -> PermissionManager -> Registry path.

Nothing in this package persists a screenshot unless the operator flips
``screen_capture_persist``; even then images are redacted first and deleted
after ``screen_capture_retention_seconds``. OCR/vision text is always marked
untrusted (the Observation contract enforces it).
"""

from app.computer.perception.capture import (
    CaptureError,
    CaptureResult,
    LinuxScreenCapture,
    MonitorInfo,
    ScreenCaptureBackend,
    WindowInfo,
    make_capture_backend,
)
from app.computer.perception.ocr import OcrAdapter, OcrResult
from app.computer.perception.privacy import RedactionPlan, ScreenshotStore
from app.computer.perception.providers import OcrPerceptionProvider, ScreenPerceptionProvider
from app.computer.perception.vision import VisionAdapter, VisionResult

__all__ = [
    "CaptureError", "CaptureResult", "LinuxScreenCapture", "MonitorInfo",
    "ScreenCaptureBackend", "WindowInfo", "make_capture_backend",
    "OcrAdapter", "OcrResult", "RedactionPlan", "ScreenshotStore",
    "ScreenPerceptionProvider", "OcrPerceptionProvider",
    "VisionAdapter", "VisionResult",
]
