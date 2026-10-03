"""Privacy controls for perception: region redaction + retention-bounded store.

* ``RedactionPlan`` validates configured sensitive rectangles (bounded ints,
  clamped to the frame) — malformed regions fail closed at validation time.
* ``redact_png`` masks those rectangles with solid black before any image is
  returned, persisted or handed to an OCR/vision adapter. Without Pillow it
  fails CLOSED (raises) rather than leaking unredacted pixels when redaction
  was requested.
* ``ScreenshotStore`` only exists when persistence is explicitly enabled;
  every stored file carries a deadline and ``purge_expired`` deletes anything
  past it. The store refuses images that were not redacted when a redaction
  plan was present.
"""

from __future__ import annotations

import os
import re
import tempfile
import time
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, field_validator

REGION_NAME = re.compile(r"[a-z][a-z0-9_.-]{0,31}")


class RedactionRegion(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    name: str = Field(min_length=1, max_length=32)
    x: int = Field(ge=0, le=32767)
    y: int = Field(ge=0, le=32767)
    width: int = Field(gt=0, le=16384)
    height: int = Field(gt=0, le=16384)

    @field_validator("name")
    @classmethod
    def valid_name(cls, value: str) -> str:
        if not REGION_NAME.fullmatch(value.lower()):
            raise ValueError("invalid region name")
        return value.lower()


class RedactionPlan(BaseModel):
    model_config = ConfigDict(extra="forbid", frozen=True)
    regions: tuple[RedactionRegion, ...] = Field(default=(), max_length=32)

    @classmethod
    def from_settings(cls, raw: list[dict]) -> "RedactionPlan":
        regions = []
        for item in raw[:32]:
            try:
                regions.append(RedactionRegion(
                    name=str(item.get("name") or f"region{len(regions)}"),
                    x=int(item["x"]), y=int(item["y"]),
                    width=int(item["width"]), height=int(item["height"])))
            except (KeyError, TypeError, ValueError):
                # A malformed configured region must not silently disable
                # redaction for the others; fail closed on the whole plan.
                raise ValueError("SCREEN_REDACTION_PLAN_INVALID") from None
        return cls(regions=tuple(regions))

    @property
    def empty(self) -> bool:
        return not self.regions


def redact_png(image: bytes, plan: RedactionPlan,
               frame_width: int | None = None, frame_height: int | None = None) -> bytes:
    """Mask configured regions. Raises RuntimeError if masking cannot be done."""
    if plan.empty:
        return image
    try:
        from io import BytesIO

        from PIL import Image, ImageDraw
    except ImportError:
        raise RuntimeError("SCREEN_REDACTION_UNAVAILABLE: Pillow is not installed") from None
    try:
        img = Image.open(BytesIO(image)).convert("RGB")
    except Exception:
        raise RuntimeError("SCREEN_REDACTION_FAILED: undecodable image") from None
    draw = ImageDraw.Draw(img)
    for region in plan.regions:
        x2 = min(region.x + region.width, img.width)
        y2 = min(region.y + region.height, img.height)
        if region.x < img.width and region.y < img.height and x2 > region.x and y2 > region.y:
            draw.rectangle([region.x, region.y, x2 - 1, y2 - 1], fill=(0, 0, 0))
    out = BytesIO()
    img.save(out, format="PNG")
    return out.getvalue()


class ScreenshotStore:
    """Retention-bounded screenshot directory. Created ONLY when enabled."""

    FILENAME = re.compile(r"obs-[0-9a-f-]{36}\.png")

    def __init__(self, root: Path, *, retention_seconds: float, enabled: bool):
        self._root = Path(root)
        self._retention = float(retention_seconds)
        self._enabled = bool(enabled)

    @property
    def enabled(self) -> bool:
        return self._enabled

    def store(self, image: bytes, observation_id: str, *, redacted: bool) -> str | None:
        """Persist one redacted screenshot; returns relative path or None."""
        if not self._enabled:
            return None  # default behaviour: never write screenshots to disk
        if not redacted:
            raise RuntimeError("SCREEN_PERSISTENCE_DENIED: image was not redacted")
        safe_id = observation_id if self.FILENAME.fullmatch(f"obs-{observation_id}.png") else None
        if safe_id is None:
            raise RuntimeError("SCREEN_PERSISTENCE_DENIED: invalid observation id")
        self._root.mkdir(parents=True, exist_ok=True)
        target = self._root / f"obs-{observation_id}.png"
        payload = image[:50_000_000]
        fd, tmp = tempfile.mkstemp(dir=str(self._root), suffix=".part")
        try:
            with os.fdopen(fd, "wb") as handle:
                handle.write(payload)
            os.replace(tmp, target)
        finally:
            if os.path.exists(tmp):
                os.unlink(tmp)
        return target.name

    def purge_expired(self, now: float | None = None) -> int:
        """Delete files older than the retention window. Returns count."""
        if not self._root.exists():
            return 0
        current = now if now is not None else time.time()
        removed = 0
        for candidate in self._root.glob("obs-*.png"):
            try:
                if current - candidate.stat().st_mtime > self._retention:
                    candidate.unlink()
                    removed += 1
            except OSError:
                continue
        return removed
