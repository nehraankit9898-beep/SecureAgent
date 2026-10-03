"""Optional cloud vision adapter — refuses to run unless explicitly configured.

Local-first is the default: this adapter raises ``VisionDisabled`` unless BOTH
``vision_cloud_enabled`` AND a concrete HTTPS endpoint are configured. The API
key is never logged and never leaves the request headers. Response text is
untrusted observation data (bounded, redacted of secrets before storage).
"""

from __future__ import annotations

import asyncio
import json
from urllib.parse import urlparse
from urllib.request import Request, urlopen

from pydantic import BaseModel, ConfigDict, Field

MAX_VISION_TEXT_CHARS = 20_000


class VisionResult(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    description: str = Field(max_length=MAX_VISION_TEXT_CHARS)
    confidence: float = Field(0.0, ge=0.0, le=1.0)
    model: str = Field("cloud-vision", max_length=120)


class VisionDisabled(RuntimeError):
    def __init__(self, code: str = "VISION_NOT_CONFIGURED"):
        super().__init__(code)
        self.code = code


class VisionAdapter:
    provider_id = "cloud-vision"

    def __init__(self, *, enabled: bool, endpoint: str | None, api_key: str | None,
                 timeout_seconds: float = 20.0, opener=None):
        self._enabled = bool(enabled)
        self._endpoint = endpoint
        self._api_key = api_key
        self._timeout = float(timeout_seconds)
        self._opener = opener  # injectable for tests; never used in production paths

    def configured(self) -> bool:
        if not self._enabled or not self._endpoint or not self._api_key:
            return False
        try:
            parsed = urlparse(str(self._endpoint))
        except Exception:
            return False
        return parsed.scheme == "https" and bool(parsed.netloc)

    async def available(self) -> bool:
        return self.configured()

    async def describe(self, image: bytes, prompt: str = "Describe what is on this screen.") -> VisionResult:
        if not self.configured():
            raise VisionDisabled()
        payload = json.dumps({
            "prompt": prompt[:2000],
            "image_base64_bytes": len(image),  # metadata only in logs; body sent once
            "images": [_b64(image)],
        }).encode("utf-8")

        def send() -> dict:
            request = Request(str(self._endpoint), data=payload, method="POST", headers={
                "Content-Type": "application/json",
                "Authorization": f"Bearer {self._api_key}",
            })
            if self._opener is not None:
                return self._opener(request)
            with urlopen(request, timeout=self._timeout) as response:  # noqa: S310 - https-only validated above
                body = response.read(2_000_000)
            return json.loads(body.decode("utf-8", "ignore"))

        try:
            data = await asyncio.wait_for(asyncio.to_thread(send), self._timeout + 5)
        except asyncio.TimeoutError:
            raise VisionDisabled("VISION_TIMEOUT") from None
        except Exception:
            # Never leak endpoint/key details through exception strings.
            raise VisionDisabled("VISION_REQUEST_FAILED") from None
        text = ""
        confidence = 0.0
        if isinstance(data, dict):
            text = str(data.get("description") or data.get("text") or data.get("result") or "")
            try:
                confidence = float(data.get("confidence") or 0.0)
            except (TypeError, ValueError):
                confidence = 0.0
        return VisionResult(description=text.strip()[:MAX_VISION_TEXT_CHARS],
                            confidence=max(0.0, min(1.0, confidence)))


def _b64(image: bytes) -> str:
    import base64
    return base64.b64encode(image[:20_000_000]).decode("ascii")
