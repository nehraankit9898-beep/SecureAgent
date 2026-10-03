"""Frozen desktop entry point for SecureAgent's loopback-only API."""

import os
import sys
from pathlib import Path

import uvicorn
from app.main import app as fastapi_app


def _frozen_root() -> Path:
    return Path(getattr(sys, "_MEIPASS", Path(__file__).resolve().parent))


def main() -> None:
    host = os.environ.get("SECURE_AGENT_HOST", "127.0.0.1")
    if host not in {"127.0.0.1", "::1"}:
        raise SystemExit("Desktop backend may bind only to loopback")
    try:
        port = int(os.environ["SECURE_AGENT_PORT"])
    except (KeyError, ValueError):
        raise SystemExit("SECURE_AGENT_PORT must be a valid local port") from None
    if not 1024 <= port <= 65535:
        raise SystemExit("SECURE_AGENT_PORT is outside the allowed range")
    os.chdir(_frozen_root())
    uvicorn.run(
        fastapi_app,
        host=host,
        port=port,
        log_level="info",
        access_log=False,
        server_header=False,
        workers=1,
    )


if __name__ == "__main__":
    main()
