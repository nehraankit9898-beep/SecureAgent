"""Example plugin: read-only Docker inspection.

Ships disabled; enable by setting "enabled": true in manifest.json AND
SECURE_AGENT_PLUGINS_ENABLED=true. The tool runs only fixed read-only
docker command vectors through the Linux terminal executor.
"""
from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from app.linux_terminal import LinuxTerminalExecutor, quote_argv
from app.models import Permission, RiskLevel
from app.tools.base import Tool


class _In(BaseModel):
    pass


class _Out(BaseModel):
    stdout: str
    exit_code: int
    available: bool


_executor: LinuxTerminalExecutor | None = None


def bind(executor: LinuxTerminalExecutor) -> None:
    global _executor
    _executor = executor


class DockerInspect(Tool):
    name = "docker_inspect"
    description = "Read-only Docker inventory: version, images, and running containers."
    category = "plugins"
    risk_level = RiskLevel.LOW
    input_model = _In
    output_model = _Out
    permissions = frozenset({Permission.EXECUTE})

    def __init__(self):
        available = bool(_executor and _executor.available)
        self.enabled = available
        self.disabled_reason = None if available else "TERMINAL_UNAVAILABLE: Linux terminal backend is required"

    async def run(self, args: dict[str, Any]) -> dict[str, Any]:
        if not _executor or not _executor.available:
            raise RuntimeError("TERMINAL_UNAVAILABLE")
        sections = []
        last_exit = 0
        for argv in (["docker", "--version"], ["docker", "images", "--format",
                                              "{{.Repository}}:{{.Tag}} {{.Size}}"],
                     ["docker", "ps", "--format", "{{.Names}} {{.Image}} {{.Status}}"]):
            execution = await _executor.execute(quote_argv(argv), approval="plugin-fixed")
            snap = execution.snapshot(20000)
            sections.append(f"$ {quote_argv(argv)}\n{(snap['stdout'] or snap['stderr']).strip()}")
            last_exit = execution.exit_code or 0
        return {"stdout": "\n\n".join(sections), "exit_code": last_exit,
                "available": True}


def register() -> list[Tool]:
    return [DockerInspect()]
