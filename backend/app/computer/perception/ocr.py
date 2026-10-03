"""Local-first OCR adapter (tesseract). No network access, ever.

The adapter runs a FIXED argv vector against a temp file containing the
already-redacted image, with a hard timeout and output bound. Text produced
here is UNTRUSTED observation data; callers must wrap it with
``app.security.untrusted_context`` before presenting it to any model.
"""

from __future__ import annotations

import asyncio
import os
import shutil
import tempfile

from pydantic import BaseModel, ConfigDict, Field

MAX_OCR_TEXT_CHARS = 20_000


class OcrResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    text: str = Field(max_length=MAX_OCR_TEXT_CHARS)
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    engine: str = "tesseract"


class OcrUnavailable(RuntimeError):
    def __init__(self, code: str = "OCR_UNAVAILABLE"):
        super().__init__(code)
        self.code = code


class OcrAdapter:
    provider_id = "local-ocr"

    def __init__(self, *, which=shutil.which, runner=None,
                 timeout_seconds: float = 20.0):
        self._which = which
        self._timeout = float(timeout_seconds)
        # runner(argv, image) -> (text, mean_confidence|None); injectable for tests
        self._runner = runner

    async def available(self) -> bool:
        return self._runner is not None or bool(self._which("tesseract"))

    async def recognize(self, image: bytes) -> OcrResult:
        if self._runner is not None:
            outcome = await asyncio.to_thread(self._runner, ["tesseract"], image)
            text, confidence = outcome if isinstance(outcome, tuple) else (outcome, None)
        else:
            if not self._which("tesseract"):
                raise OcrUnavailable()
            text, confidence = await self._run_tesseract(image)
        cleaned = (text or "").strip()[:MAX_OCR_TEXT_CHARS]
        conf = float(confidence) if confidence is not None else 0.0
        conf = max(0.0, min(1.0, conf / 100.0 if conf > 1.0 else conf))
        return OcrResult(text=cleaned, confidence=conf)

    async def _run_tesseract(self, image: bytes) -> tuple[str, float | None]:
        fd, path = tempfile.mkstemp(suffix=".png")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(image[:50_000_000])

            def run() -> tuple[str, float | None]:
                out_base = path + ".out"
                try:
                    done = subprocess_run(["tesseract", path, out_base, "--psm", "6"],
                                          timeout=self._timeout)
                    if done != 0:
                        raise OcrUnavailable("OCR_ENGINE_FAILED")
                    with open(out_base + ".txt", encoding="utf-8", errors="ignore") as fh:
                        text = fh.read(MAX_OCR_TEXT_CHARS)
                    return text, None
                finally:
                    for extra in (out_base + ".txt",):
                        try:
                            if os.path.exists(extra):
                                os.unlink(extra)
                        except OSError:
                            pass

            return await asyncio.wait_for(asyncio.to_thread(run), self._timeout + 5)
        except asyncio.TimeoutError:
            raise OcrUnavailable("OCR_TIMEOUT") from None
        finally:
            try:
                if os.path.exists(path):
                    os.unlink(path)
            except OSError:
                pass


def subprocess_run(argv: list[str], timeout: float) -> int:
    import subprocess
    try:
        done = subprocess.run(argv, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
                              timeout=timeout, check=False)
    except (OSError, subprocess.SubprocessError):
        return -1
    return done.returncode
