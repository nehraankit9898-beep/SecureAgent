"""Linux terminal executor — controlled host-shell execution.

Pipeline position:  Permission Engine → Command Policy Engine → THIS MODULE.

Two operating modes govern what this module will actually do:

* ``RESTRICTED_AGENT`` (default)
  - Commands run inside a Linux namespace sandbox (user+pid+net) when the
    kernel supports unprivileged user namespaces, with the child mapped
    to uid 65534 (nobody). When bubblewrap is installed it is preferred
    because it gives a proper mount-namespace view of the filesystem.
  - If no isolation mechanism is available, autonomous execution is
    refused with ``LINUX_SANDBOX_UNAVAILABLE``. We NEVER silently fall
    through to unrestricted host execution.
  - The Sensitive Resource Guard rejects reads/writes of ``/etc/shadow``,
    ``~/.ssh/*``, ``*.pem``, ``.env``, etc. before any subprocess is
    spawned.
  - ``sudo`` is forbidden in this mode.

* ``HOST_CONTROL`` (explicit user activation only)
  - The user has manually switched into Host Control Mode after seeing
    a visible warning. Every command still flows through the policy
    engine; BLOCKED commands stay BLOCKED. ``sudo -n`` is allowed when
    ``terminal_allow_sudo`` is configured. Interactive root shells
    (``sudo -i``, ``sudo -s``, ``sudo bash``) are always refused.
  - The AI never gets to flip this switch itself.

Other security properties preserved from the original implementation:

* The only entry point is an argument array: ``[/bin/bash, -c, command]``.
  No shell is ever spawned from string concatenation.
* ``cwd`` must resolve inside the configured SAFE_WORKSPACE or an
  explicitly configured allowed path. The canonical path enforcer
  rejects ``..``, URL-encoded traversal, symlinks, hardlinks,
  ``/proc/self/fd`` escapes and protected host prefixes.
* The child environment is scrubbed of secret-shaped variables and runs
  with ``TERM=dumb`` and stdin closed; nothing can prompt the user.
* ``sudo`` is forced non-interactive (``sudo -n``). When sudo reports a
  password requirement the executor returns the structured
  ``SUDO_PASSWORD_REQUIRED`` state — passwords are never requested,
  stored, or logged.
* Output is captured incrementally with a hard byte cap and redacted.
* Wall-clock timeout kills the whole process group; cancellation is
  honored between and during executions.
"""
from __future__ import annotations

import asyncio
import os
import re
import shlex
import signal
import time
from collections import deque
from dataclasses import dataclass, field
from enum import StrEnum
from pathlib import Path
from typing import Callable
from uuid import uuid4

from app.security import redact
from app.terminal_policy import CommandClassification, CommandPolicyEngine, CommandRisk


def _control_gate():
    """Return the Control Center runtime gate, or None when unavailable.

    Lazily imported to avoid a circular dependency: the control center is the
    runtime authority and the terminal executor is one of its enforcement
    points. When the control center has not been initialized (unit tests of
    the executor in isolation) the gate is a no-op.
    """
    try:
        from app.control_center import get_control_center
        return get_control_center()
    except Exception:
        return None

# Import the new sandbox module — fail-closed if it is unavailable.
try:
    from app.linux_sandbox import (
        SandboxCapabilities,
        SandboxInvocation,
        build_sandbox_argv,
        classify_path_sensitivity,
        enforce_canonical_workspace_path,
        probe_sandbox_capabilities,
        PathEscapeError,
    )
except ImportError:  # pragma: no cover — only happens if sandbox module is missing
    SandboxCapabilities = None  # type: ignore[assignment]
    SandboxInvocation = None  # type: ignore[assignment]
    build_sandbox_argv = None  # type: ignore[assignment]
    classify_path_sensitivity = None  # type: ignore[assignment]
    enforce_canonical_workspace_path = None  # type: ignore[assignment]
    probe_sandbox_capabilities = None  # type: ignore[assignment]
    PathEscapeError = PermissionError  # type: ignore[misc, assignment]


SENSITIVE_ENV = re.compile(r"(?i)(secret|token|api[-_]?key|password|passwd|credential|private[-_]?key|auth)")
DEFAULT_PATH = "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin"
SUDO_HINTS = ("a password is required", "no tty present", "not allowed to execute",
              "a terminal is required")

# Commands that imply an interactive root shell. These are BLOCKED in every
# mode — the user can never approve them through SecureAgent.
INTERACTIVE_SUDO_SHELLS = re.compile(
    r"(?<![\w/-])sudo\s+(-[^\s]+\s+)*(-i|-s|--shell|--login|--user\s+root\b)\b"
)


class TerminalMode(StrEnum):
    """Two operating modes for the Linux terminal backend.

    ``RESTRICTED_AGENT`` is the default and runs commands inside the
    namespace sandbox. ``HOST_CONTROL`` is opt-in, requires a visible
    warning, and lifts only the sandbox layer — the policy engine still
    classifies everything and BLOCKED commands stay BLOCKED.
    """
    RESTRICTED_AGENT = "restricted_agent"
    HOST_CONTROL = "host_control"


def redact_output(data: bytes | str) -> str:
    text = data.decode("utf-8", errors="replace") if isinstance(data, bytes) else data
    return redact(text)


@dataclass
class TerminalExecution:
    id: str
    command: str
    cwd: str
    risk: str
    approval: str
    classification: CommandClassification | None
    mode: str = TerminalMode.RESTRICTED_AGENT.value
    sandbox: dict | None = None
    status: str = "running"          # running | completed | timeout | cancelled | failed
    exit_code: int | None = None
    started_at: float = field(default_factory=time.time)
    finished_at: float | None = None
    stdout: bytearray = field(default_factory=bytearray)
    stderr: bytearray = field(default_factory=bytearray)
    output_bytes: int = 0
    output_truncated: bool = False
    duration_ms: int = 0
    error: str | None = None

    def snapshot(self, cap: int) -> dict:
        return {
            "id": self.id,
            "command": self.command,
            "cwd": self.cwd,
            "risk": self.risk,
            "approval": self.approval,
            "mode": self.mode,
            "sandbox": self.sandbox,
            "status": self.status,
            "exit_code": self.exit_code,
            "duration_ms": self.duration_ms,
            "started_at": self.started_at,
            "finished_at": self.finished_at,
            "stdout": redact_output(bytes(self.stdout[:cap])),
            "stderr": redact_output(bytes(self.stderr[:cap])),
            "output_bytes": self.output_bytes,
            "truncated": self.output_truncated,
            "error": self.error,
            "reasons": list(self.classification.reasons) if self.classification else [],
            "requires_elevation": self.classification.requires_elevation if self.classification else False,
        }


class TerminalExecutionTracker:
    """In-memory live registry of terminal executions (bounded)."""

    def __init__(self, keep: int = 200):
        self.keep = keep
        self._items: dict[str, TerminalExecution] = {}
        self._order: deque[str] = deque()

    def register(self, execution: TerminalExecution) -> None:
        self._items[execution.id] = execution
        self._order.append(execution.id)
        while len(self._order) > self.keep:
            self._items.pop(self._order.popleft(), None)

    def get(self, execution_id: str) -> TerminalExecution | None:
        return self._items.get(execution_id)

    def running(self) -> list[TerminalExecution]:
        return [item for item in self._items.values() if item.status == "running"]


class TerminalCancellation:
    """Maps agent-task cancellation onto live terminal executions."""

    def __init__(self) -> None:
        self._processes: dict[str, asyncio.subprocess.Process] = {}
        self._cancelled: set[str] = set()

    def attach(self, execution_id: str, process: asyncio.subprocess.Process) -> None:
        self._processes[execution_id] = process

    def detach(self, execution_id: str) -> None:
        self._processes.pop(execution_id, None)

    def cancel(self, execution_id: str) -> bool:
        process = self._processes.get(execution_id)
        if process is None or process.returncode is not None:
            self._cancelled.add(execution_id)
            return False
        self._cancelled.add(execution_id)
        _kill_process_group(process)
        return True

    def was_cancelled(self, execution_id: str) -> bool:
        return execution_id in self._cancelled


def _kill_process_group(process: asyncio.subprocess.Process) -> None:
    """Kill the entire process group of ``process`` so children cannot
    survive the parent. Uses SIGKILL after the policy engine has already
    classified the command — we are past the "ask nicely" stage."""
    try:
        os.killpg(os.getpgid(process.pid), signal.SIGKILL)
    except (ProcessLookupError, PermissionError, OSError):
        try:
            process.kill()
        except ProcessLookupError:
            pass


class LinuxTerminalExecutor:
    """Controlled /bin/bash execution with two-tier security model.

    Construction parameters (read from the global ``Settings``):

    * ``config.workspace_root``             — primary jail root
    * ``config.terminal_allowed_paths``     — additional jail roots
    * ``config.terminal_shell``             — shell binary
    * ``config.terminal_command_timeout_seconds``
    * ``config.terminal_max_output_bytes``
    * ``config.terminal_history_limit``
    * ``config.terminal_allow_sudo``        — only honored in HOST_CONTROL
    """

    def __init__(self, config):
        self.config = config
        self.policy = CommandPolicyEngine()
        self.tracker = TerminalExecutionTracker(keep=max(config.terminal_history_limit, 200))
        self.cancellation = TerminalCancellation()
        self.on_event: Callable[[TerminalExecution], None] | None = None
        # The mode starts in RESTRICTED_AGENT. The user must explicitly
        # activate HOST_CONTROL via the API; the AI cannot.
        self._mode: TerminalMode = TerminalMode.RESTRICTED_AGENT
        # Cache the sandbox capabilities so the /status endpoint can report
        # them without re-probing on every request.
        self._sandbox_caps: SandboxCapabilities | None = (
            probe_sandbox_capabilities() if probe_sandbox_capabilities else None
        )

    # -- mode management ---------------------------------------------------- #

    @property
    def mode(self) -> TerminalMode:
        return self._mode

    def activate_host_control(self) -> dict:
        """User-initiated switch to HOST_CONTROL mode. Returns the audit
        record. The AI cannot call this — it is only exposed on the
        authenticated ``/api/v1/terminal/mode`` endpoint and requires
        ``confirm=True`` from a real human."""
        self._mode = TerminalMode.HOST_CONTROL
        return {
            "mode": self._mode.value,
            "warning": "HOST_CONTROL active: subsequent commands run on the host "
                       "outside the namespace sandbox. BLOCKED commands remain "
                       "blocked. sudo -n is allowed when terminal_allow_sudo is set.",
            "activated_at": time.time(),
        }

    def deactivate_host_control(self) -> dict:
        """Return to RESTRICTED_AGENT mode (the safe default)."""
        self._mode = TerminalMode.RESTRICTED_AGENT
        return {
            "mode": self._mode.value,
            "warning": "Returned to RESTRICTED_AGENT mode. Commands will run "
                       "inside the namespace sandbox again.",
            "activated_at": time.time(),
        }

    def set_mode(self, mode: TerminalMode) -> dict:
        # The Control Center HOST CONTROL master must be ON before the
        # executor may enter HOST_CONTROL mode (spec sections 5/6). The AI
        # cannot flip either switch.
        if mode is TerminalMode.HOST_CONTROL:
            gate = _control_gate()
            if gate is not None:
                gate.check_host_control_operation()
            return self.activate_host_control()
        return self.deactivate_host_control()

    def kill_all_running(self) -> dict:
        """EMERGENCY STOP support: kill every running execution's process group."""
        killed: list[str] = []
        for execution in self.tracker.running():
            if self.cancellation.cancel(execution.id):
                killed.append(execution.id)
        # Emergency stop also forces the safe terminal mode.
        self._mode = TerminalMode.RESTRICTED_AGENT
        return {"killed_executions": killed, "mode": self._mode.value}

    # -- availability ------------------------------------------------------ #

    @property
    def available(self) -> bool:
        import sys
        if sys.platform != "linux":
            return False
        return Path(self.config.terminal_shell).exists()

    def unavailable_reason(self) -> str:
        import sys
        if sys.platform != "linux":
            return "TERMINAL_UNAVAILABLE: Linux is required for the native terminal backend"
        return f"TERMINAL_UNAVAILABLE: shell {self.config.terminal_shell} was not found"

    def sandbox_status(self) -> dict:
        """Report the current sandbox capability snapshot for /status."""
        if not self._sandbox_caps:
            return {"available": False, "mechanism": "none",
                    "reason": "sandbox module not loaded"}
        return self._sandbox_caps.describe()

    # -- path jail ---------------------------------------------------------- #

    def allowed_roots(self) -> list[Path]:
        roots = [self.config.workspace_root.resolve()]
        for raw in self.config.terminal_allowed_paths:
            try:
                roots.append(Path(raw).expanduser().resolve())
            except (OSError, RuntimeError):
                continue
        # Control Center FILESYSTEM approved paths extend the jail at runtime
        # (Add Allowed Path has a real effect, spec section 10).
        gate = _control_gate()
        if gate is not None:
            for raw in gate.extra_allowed_roots():
                try:
                    resolved = Path(raw).expanduser().resolve()
                except (OSError, RuntimeError):
                    continue
                if resolved != Path("/") and resolved not in roots:
                    roots.append(resolved)
        return roots

    def resolve_cwd(self, cwd: str | None) -> Path:
        """Resolve ``cwd`` and verify it stays inside an approved root.

        Uses the canonical path enforcer so symlink/hardlink/proc-self-fd
        escapes are caught at the kernel level (O_NOFOLLOW walk).
        """
        roots = self.allowed_roots()
        if cwd in (None, "", "."):
            return roots[0]
        if "\x00" in cwd or len(cwd) > 4096:
            raise ValueError("invalid working directory")
        candidate = Path(cwd).expanduser()
        if not candidate.is_absolute():
            candidate = roots[0] / candidate
        try:
            resolved = enforce_canonical_workspace_path(
                candidate,
                workspace_root=roots[0],
                allowed_roots=roots[1:],
                allow_create=False,
            )
        except PathEscapeError as error:
            raise PermissionError(f"working directory escapes the approved workspace: {error.kind}") from error
        if not resolved.is_dir():
            raise ValueError("working directory is not a directory")
        return resolved

    # -- environment -------------------------------------------------------- #

    def _child_env(self) -> dict[str, str]:
        env: dict[str, str] = {}
        for key, value in os.environ.items():
            if SENSITIVE_ENV.search(key):
                continue
            if key in {"LS_COLORS", "BASH_ENV", "ENV", "PROMPT_COMMAND", "SHELLOPTS",
                       "GLOBIGNORE", "IFS", "CDPATH", "GDBINIT", "PYTHONSTARTUP",
                       "PYTHONPATH", "PERL5OPT", "RUBYOPT", "NODE_OPTIONS"}:
                continue  # shell/interpreter injection vectors
            if len(key) <= 64 and len(value) <= 2048:
                env[key] = value
        env["PATH"] = env.get("PATH") or DEFAULT_PATH
        env["TERM"] = "dumb"
        env["SECURE_AGENT_TERMINAL"] = "1"
        return env

    # -- sudo --------------------------------------------------------------- #

    @staticmethod
    def _force_non_interactive_sudo(command: str) -> str:
        """Replace bare ``sudo`` with ``sudo -n`` so the child never prompts."""
        return re.sub(r"(?<![\w/-])sudo(?![\w-])", "sudo -n", command, count=0)

    def _check_sudo_policy(self, command: str, classification: CommandClassification) -> None:
        """Enforce sudo rules. Raises ``ValueError`` on violation."""
        if INTERACTIVE_SUDO_SHELLS.search(command):
            raise ValueError(
                "TERMINAL_COMMAND_BLOCKED: interactive root shell via sudo "
                "(sudo -i / sudo -s / sudo bash) is forbidden in every mode"
            )
        if classification.requires_elevation:
            # Architectural rule first: sudo is never allowed in
            # RESTRICTED_AGENT mode regardless of any runtime switch.
            if self._mode is TerminalMode.RESTRICTED_AGENT:
                raise ValueError(
                    "TERMINAL_SUDO_BLOCKED_IN_RESTRICTED_MODE: sudo requires "
                    "HOST_CONTROL mode (activate via /api/v1/terminal/mode with "
                    "explicit confirmation)"
                )
            # The Control Center SUDO master switch is the runtime authority:
            # disabled / approval_required / host_control_only (spec section 9).
            gate = _control_gate()
            if gate is not None:
                gate.check_sudo()
            if not self.config.terminal_allow_sudo:
                raise ValueError("TERMINAL_SUDO_DISABLED: sudo usage is disabled by policy")

    # -- sensitive resource guard ------------------------------------------ #

    def _check_sensitive_resources(self, command: str) -> None:
        """Pre-scan the command for sensitive file references. The sandbox
        layer would block /etc/shadow at the kernel level (uid remap), but
        we also block at the lexical layer so the agent gets a structured
        error instead of an opaque 'Permission denied' from cat(1)."""
        if not classify_path_sensitivity:
            return
        # Find candidate path tokens in the command. We look for absolute
        # paths and ~-prefixed paths. We deliberately over-approximate —
        # blocking a benign command that mentions /etc/shadow in a comment
        # is preferable to letting the agent read /etc/shadow.
        tokens = re.findall(r"(?:[A-Za-z0-9_@.-]*~[^\s|&;<>]*|/[^\s|&;<>]*)", command)
        for token in tokens:
            # Strip surrounding quotes if present.
            cleaned = token.strip("'\"")
            decision = classify_path_sensitivity(cleaned)
            if decision.blocked:
                raise ValueError(decision.reason)

    # -- execution ---------------------------------------------------------- #

    async def execute(
        self,
        command: str,
        *,
        cwd: str | None = None,
        timeout: float | None = None,
        approval: str = "approved",
        task_id: str | None = None,
        session_id: str | None = None,
    ) -> TerminalExecution:
        # --- Control Center runtime gates (the UI switch has real effect) --- #
        gate = _control_gate()
        if gate is not None:
            gate.check_terminal()
            if self._mode is TerminalMode.HOST_CONTROL:
                try:
                    gate.check_host_control_operation()
                except PermissionError:
                    # Revocation is effective at the execution boundary even
                    # if the UI and executor changed state concurrently.
                    self._mode = TerminalMode.RESTRICTED_AGENT
            limits = gate.terminal_limits()
            if task_id:
                if gate.task_command_count(task_id) >= limits["max_commands_per_task"]:
                    raise ValueError(
                        f"TERMINAL_COMMAND_LIMIT_REACHED: task reached the maximum of "
                        f"{limits['max_commands_per_task']} commands per task"
                    )
                gate.record_task_command(task_id)
        if not self.available:
            raise RuntimeError(self.unavailable_reason())
        if not isinstance(command, str) or not command.strip():
            raise ValueError("a non-empty command is required")
        if len(command) > 8000:
            raise ValueError("command exceeds the 8000 character limit")

        classification = self.policy.classify(command)
        if classification.risk is CommandRisk.BLOCKED:
            raise ValueError("TERMINAL_COMMAND_BLOCKED: " + classification.summary())

        # Sudo policy (mode + interactive shells).
        self._check_sudo_policy(command, classification)

        # Sensitive resource pre-scan — refuses /etc/shadow, ~/.ssh, *.pem, etc.
        self._check_sensitive_resources(command)

        resolved_cwd = self.resolve_cwd(cwd)
        static_timeout = self.config.terminal_command_timeout_seconds
        static_output_cap = self.config.terminal_max_output_bytes
        gate = _control_gate()
        if gate is not None:
            # Runtime limits from the Control Center tighten (never loosen)
            # the static configuration.
            limits = gate.terminal_limits()
            static_timeout = min(static_timeout, limits["max_command_time_seconds"])
            static_output_cap = min(static_output_cap, limits["max_output_bytes"])
        effective_timeout = min(
            float(timeout or static_timeout),
            static_timeout,
        )

        # Build the sandbox prefix argv. In RESTRICTED_AGENT mode the sandbox
        # is mandatory; if it is unavailable we fail closed. In HOST_CONTROL
        # mode we skip the sandbox (the user has explicitly accepted the risk).
        sandbox_info: dict | None = None
        argv_prefix: list[str] = []
        if self._mode is TerminalMode.RESTRICTED_AGENT:
            if not build_sandbox_argv:
                raise RuntimeError(
                    "LINUX_SANDBOX_UNAVAILABLE: sandbox module not loaded; "
                    "autonomous terminal execution is disabled"
                )
            try:
                invocation: SandboxInvocation = build_sandbox_argv(
                    allow_loopback=False,
                    workspace_mount=str(resolved_cwd),
                )
            except RuntimeError as error:
                # Propagate as a structured error so the API layer can surface
                # LINUX_SANDBOX_UNAVAILABLE to the user/UI.
                raise RuntimeError(str(error)) from None
            argv_prefix = list(invocation.prefix_argv)
            sandbox_info = invocation.describe()
            sandbox_info["mode"] = self._mode.value
        else:
            sandbox_info = {
                "mode": self._mode.value,
                "mechanism": "host-control",
                "available": True,
                "notes": ["HOST_CONTROL: command runs on the host without namespace isolation"],
            }

        execution = TerminalExecution(
            id=str(uuid4()),
            command=command,
            cwd=str(resolved_cwd),
            risk=classification.risk.value,
            approval=approval,
            classification=classification,
            mode=self._mode.value,
            sandbox=sandbox_info,
        )
        self.tracker.register(execution)
        if self.on_event:
            self.on_event(execution)

        # Construct the full argv. The bash -c "<command>" tail is appended
        # after the sandbox prefix. We use the same non-interactive-sudo
        # rewriting so a stray `sudo` never blocks on a TTY.
        bash_argv = [self.config.terminal_shell, "-c",
                     self._force_non_interactive_sudo(command)]
        full_argv = argv_prefix + bash_argv

        process = await asyncio.create_subprocess_exec(
            *full_argv,
            cwd=str(resolved_cwd),
            env=self._child_env(),
            stdin=asyncio.subprocess.DEVNULL,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            start_new_session=True,
        )
        self.cancellation.attach(execution.id, process)
        cap = static_output_cap
        started = time.perf_counter()
        stdout_task = asyncio.create_task(self._drain(process.stdout, execution.stdout, execution, cap))
        stderr_task = asyncio.create_task(self._drain(process.stderr, execution.stderr, execution, cap))
        try:
            await asyncio.wait_for(process.wait(), effective_timeout)
            status = "completed"
        except asyncio.TimeoutError:
            _kill_process_group(process)
            await process.wait()
            status = "timeout"
            execution.error = f"command exceeded the {effective_timeout:.0f}s timeout and was killed"
        except asyncio.CancelledError:
            _kill_process_group(process)
            await process.wait()
            self.cancellation.detach(execution.id)
            execution.status = "cancelled"
            execution.error = "cancelled by user"
            execution.finished_at = time.time()
            execution.duration_ms = int((time.perf_counter() - started) * 1000)
            if self.on_event:
                self.on_event(execution)
            raise
        finally:
            self.cancellation.detach(execution.id)
            for pending in (stdout_task, stderr_task):
                pending.cancel()
            await asyncio.gather(stdout_task, stderr_task, return_exceptions=True)

        execution.status = status
        execution.exit_code = process.returncode
        execution.finished_at = time.time()
        execution.duration_ms = int((time.perf_counter() - started) * 1000)

        stderr_text = redact_output(bytes(execution.stderr))
        if status == "completed" and process.returncode != 0 and "sudo" in command.lower():
            if any(hint in stderr_text.lower() for hint in SUDO_HINTS):
                execution.error = ("SUDO_PASSWORD_REQUIRED: sudo needs authentication. "
                                   "Authenticate sudo in your own terminal (sudo -v) or configure "
                                   "passwordless sudo for this exact command. SecureAgent never "
                                   "collects or stores passwords.")
        if status == "completed" and process.returncode != 0 and not execution.error:
            first_line = next((line for line in stderr_text.splitlines() if line.strip()), "")
            execution.error = (first_line[:300] or f"command exited with code {process.returncode}")
        if self.cancellation.was_cancelled(execution.id) and status == "completed":
            execution.status = "cancelled"
        if self.on_event:
            self.on_event(execution)
        return execution

    async def _drain(self, stream: asyncio.StreamReader | None,
                     buffer: bytearray, execution: TerminalExecution, cap: int) -> None:
        if stream is None:
            return
        total = 0
        while chunk := await stream.read(8192):
            total += len(chunk)
            execution.output_bytes += len(chunk)
            if len(buffer) < cap:
                buffer.extend(chunk[: cap - len(buffer)])
            elif not execution.output_truncated:
                execution.output_truncated = True
            if self.on_event:
                self.on_event(execution)

    def cancel(self, execution_id: str) -> bool:
        return self.cancellation.cancel(execution_id)

    def snapshot(self, execution_id: str, cap: int | None = None) -> dict | None:
        execution = self.tracker.get(execution_id)
        if not execution:
            return None
        return execution.snapshot(cap or self.config.terminal_max_output_bytes)


def quote_argv(argv: list[str]) -> str:
    """Display helper that renders a fixed argv as a shell-quoted string."""
    return " ".join(shlex.quote(part) for part in argv)


__all__ = [
    "LinuxTerminalExecutor",
    "TerminalExecution",
    "TerminalExecutionTracker",
    "TerminalCancellation",
    "TerminalMode",
    "quote_argv",
    "redact_output",
]
