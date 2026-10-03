"""Agent-facing terminal tools.

Every tool in this module is a typed Tool registered in the fail-closed
Registry, so each call passes Permission Engine → Command Policy Engine →
LinuxTerminalExecutor. The AI never obtains unrestricted OS execution.

Two execution tools exist:

* ``terminal_execute``          — runs SAFE / LOW_RISK commands only. Anything
  riskier fails with a structured ``TERMINAL_APPROVAL_REQUIRED`` result so the
  agent can either propose a safe alternative or plan the same command through
  ``terminal_execute_approved``.
* ``terminal_execute_approved`` — requires the standard user-approval flow
  (tool.requires_approval). The classifier still rejects BLOCKED commands
  even after approval; approval can never promote a blocked command.

The inspection tools run *fixed* command vectors (never AI-supplied strings)
through the same executor — defense in depth.
"""

from __future__ import annotations

import os
import re
import stat
from pathlib import Path
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.linux_terminal import LinuxTerminalExecutor, quote_argv
from app.models import Permission, RiskLevel
from app.tools.base import Tool
from app.terminal_policy import CommandRisk

MAX_OUTPUT_CHARS = 20000


def _truncate(text: str, limit: int = MAX_OUTPUT_CHARS) -> tuple[str, bool]:
    if len(text) > limit:
        return text[:limit], True
    return text, False


def _run_error(result) -> dict[str, Any]:
    """Convert a failed executor classification/execution into a structured error."""
    if result.error and result.error.startswith("SUDO_PASSWORD_REQUIRED"):
        raise PermissionError(result.error)
    raise RuntimeError(result.error or "terminal execution failed")


class TerminalCommandIn(BaseModel):
    command: str = Field(min_length=1, max_length=8000)
    cwd: str = Field(".", max_length=4096)
    timeout_seconds: float = Field(30, gt=0, le=600)
    reason: str = Field("", max_length=500)


class TerminalCommandOut(BaseModel):
    command: str
    stdout: str
    stderr: str
    exit_code: int
    duration_ms: int
    truncated: bool
    cwd: str
    risk: str
    classification: str
    requires_elevation: bool
    status: str
    error: str | None = None
    execution_id: str


class _TerminalExecuteBase(Tool):
    category = "terminal"
    platforms = ["linux"]
    risk_level = RiskLevel.MEDIUM
    idempotent = False
    input_model = TerminalCommandIn
    output_model = TerminalCommandOut
    permissions = frozenset({Permission.EXECUTE})

    def __init__(self, executor: LinuxTerminalExecutor, limit: int = MAX_OUTPUT_CHARS):
        self.executor = executor
        self.limit = limit
        self.enabled = executor.available
        self.disabled_reason = None if executor.available else executor.unavailable_reason()

    def _guard(self, args: dict[str, Any]) -> Any:
        """Classify and either execute or raise a structured error."""
        classification = self.executor.policy.classify(args["command"])
        if classification.risk is CommandRisk.BLOCKED:
            raise ValueError("TERMINAL_COMMAND_BLOCKED: " + classification.summary())
        if not self._approved_tier() and classification.risk in {
            CommandRisk.REQUIRES_APPROVAL, CommandRisk.HIGH_RISK,
        }:
            raise PermissionError(
                "TERMINAL_APPROVAL_REQUIRED: " + classification.summary()
                + " — plan this command through terminal_execute_approved so the user can approve it"
            )
        if classification.requires_elevation and not self.executor.config.terminal_allow_sudo:
            raise ValueError("TERMINAL_SUDO_DISABLED: sudo usage is disabled by policy")
        return classification

    def _approved_tier(self) -> bool:
        raise NotImplementedError

    async def run(self, args: dict[str, Any]) -> dict[str, Any]:
        classification = self._guard(args)
        try:
            execution = await self.executor.execute(
                args["command"],
                cwd=args.get("cwd") or ".",
                timeout=args.get("timeout_seconds"),
                approval="approved" if self._approved_tier() else "policy",
            )
        except (PermissionError, ValueError):
            raise
        except RuntimeError as error:
            raise RuntimeError(str(error)) from error
        snap = execution.snapshot(self.executor.config.terminal_max_output_bytes)
        stdout, stdout_truncated = _truncate(snap["stdout"], self.limit)
        stderr, _ = _truncate(snap["stderr"], self.limit)
        if execution.error and execution.error.startswith("SUDO_PASSWORD_REQUIRED"):
            raise PermissionError(execution.error)
        return {
            "command": execution.command,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": execution.exit_code if execution.exit_code is not None else -1,
            "duration_ms": execution.duration_ms,
            "truncated": stdout_truncated or execution.output_truncated,
            "cwd": execution.cwd,
            "risk": execution.risk,
            "classification": classification.summary(),
            "requires_elevation": classification.requires_elevation,
            "status": execution.status,
            "error": execution.error,
            "execution_id": execution.id,
        }


class TerminalExecute(_TerminalExecuteBase):
    name = "terminal_execute"
    description = (
        "Run a shell command on this Linux host inside the approved workspace. "
        "Only read-only (safe) and bounded low-risk commands execute here; state-changing "
        "commands fail with TERMINAL_APPROVAL_REQUIRED. Use this for inspection first."
    )

    def _approved_tier(self) -> bool:
        return False


class TerminalExecuteApproved(_TerminalExecuteBase):
    name = "terminal_execute_approved"
    description = (
        "Run a shell command that requires explicit user approval (modifies services, "
        "packages, users, files, or firewall). Requires the user to approve the exact "
        "command. Blocked commands are rejected even after approval."
    )
    risk_level = RiskLevel.HIGH
    requires_approval = True

    def _approved_tier(self) -> bool:
        return True


class TerminalScriptIn(BaseModel):
    content: str = Field(min_length=1, max_length=50000)
    cwd: str = Field(".", max_length=4096)
    timeout_seconds: float = Field(60, gt=0, le=600)
    reason: str = Field("", max_length=500)


class TerminalScriptOut(TerminalCommandOut):
    script_path: str


class TerminalExecuteScript(Tool):
    name = "terminal_execute_script"
    description = (
        "Write a bash script into the workspace and execute it with explicit user "
        "approval. The whole script body is parsed and validated — not line-by-line, "
        "because line-by-line classification misses cross-line dangers (heredocs, "
        "pipe-to-shell, command substitution, process substitution). Blocked "
        "constructs anywhere in the script (eval, source, dynamic command "
        "construction, base64 payloads, fork bombs, disk wipes, remote pipes) "
        "reject the entire script."
    )
    category = "terminal"
    platforms = ["linux"]
    risk_level = RiskLevel.HIGH
    requires_approval = True
    idempotent = False
    input_model = TerminalScriptIn
    output_model = TerminalScriptOut
    permissions = frozenset({Permission.EXECUTE, Permission.WRITE})

    # Patterns that are forbidden anywhere in the script body. These are
    # whole-script defence layers — they catch cross-line evasion that
    # line-by-line classification would miss (e.g. a heredoc spanning
    # multiple lines containing an eval, or a base64 blob piped to bash).
    FORBIDDEN_SCRIPT_PATTERNS: tuple[tuple[Any, str], ...] = (
        (re.compile(r"\beval\b"), "eval hides its payload from classification"),
        (re.compile(r"(^|\s)(source|\.)\s+\S"), "source/. executes file content in the current shell"),
        (re.compile(r"\bexec\b\s+[A-Za-z/]"), "exec replaces the shell with an arbitrary process"),
        (re.compile(r"\bbase64\b.*\|\s*(ba|z|da)?sh"), "base64 payload piped into a shell"),
        (re.compile(r"\b(?:ba|z|da|fi)?sh\b\s+-c\s"), "nested shell -c invocation hides its payload"),
        (re.compile(r"\$\(\s*\("), "arithmetic command substitution can construct commands"),
        (re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:\s*-"), "parameter expansion can construct commands"),
        (re.compile(r"\$\{?IFS\}?"), "${IFS} variable is a known shell evasion trick"),
        (re.compile(r"\bnohup\b"), "nohup spawns detached children"),
        (re.compile(r"\b(setsid|disown)\b"), "process detachment evades process-group cleanup"),
        (re.compile(r"/proc/self/(fd|root|ns|cwd)"), "/proc/self/* is a sandbox-escape vector"),
        (re.compile(r"/dev/(fd|tcp|udp)"), "/dev/fd|tcp|udp is a sandbox-escape or exfil vector"),
        (re.compile(r":\(\)\s*\{.*\};\s*:"), "fork bomb pattern"),
        (re.compile(r"\bmkfs(\.\w+)?\b"), "filesystem creation (mkfs)"),
        (re.compile(r"\b(shred|wipefs|dd)\b"), "secure-wipe or raw disk utility"),
        (re.compile(r"\b(shutdown|poweroff|halt|reboot)\b"), "system power control"),
        (re.compile(r"\b(chmod|chown)\s+(-[a-zA-Z]*[Rr][a-zA-Z]*\s+)+/(etc|usr|bin|sbin|lib|boot|root)\b"),
         "recursive permission rewrite of a system tree"),
    )

    def __init__(self, executor: LinuxTerminalExecutor, limit: int = MAX_OUTPUT_CHARS):
        self.executor = executor
        self.limit = limit
        self.enabled = executor.available
        self.disabled_reason = None if executor.available else executor.unavailable_reason()

    def _validate_script(self, content: str) -> tuple[list[str], list[str]]:
        """Whole-script validation. Returns (reasons, rules).

        We do TWO passes:
        1. A whole-body regex scan for forbidden constructs that span
           multiple lines or hide inside heredocs/substitutions.
        2. A line-by-line classification pass with the policy engine —
           this catches per-line risks (HIGH_RISK / BLOCKED) but is no
           longer the only defence (it was the original design and was
           insufficient).

        The script is rejected if any forbidden pattern matches or any
        line classifies as BLOCKED. HIGH_RISK lines are allowed only
        because the tool itself requires_approval — the user has
        explicitly approved the script.
        """
        reasons: list[str] = []
        rules: list[str] = []
        # Whole-body scan.
        for pattern, description in self.FORBIDDEN_SCRIPT_PATTERNS:
            if pattern.search(content):
                reasons.append(f"blocked script construct: {description}")
                rules.append("blocked:script-pattern")
                return reasons, rules
        # Line-by-line pass (defence in depth, not the only layer).
        from app.terminal_policy import CommandPolicyEngine
        policy = CommandPolicyEngine()
        # Strip heredoc bodies from the line-by-line pass — heredoc
        # contents are data, not commands, but they were already scanned
        # by the whole-body patterns above.
        cleaned_lines = self._strip_heredocs(content)
        for line in cleaned_lines[:400]:
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            verdict = policy.classify(stripped)
            if verdict.risk is CommandRisk.BLOCKED:
                reasons.append(f"blocked line: {verdict.summary()}")
                rules.append("blocked:script-line")
                return reasons, rules
        return reasons, rules

    @staticmethod
    def _strip_heredocs(content: str) -> list[str]:
        """Remove heredoc bodies so the line-by-line classifier doesn't
        trip on heredoc data lines (which are not commands). The whole-
        body scanner already inspected the heredoc contents for forbidden
        constructs."""
        out: list[str] = []
        in_heredoc = False
        heredoc_terminator = ""
        for line in content.splitlines():
            if in_heredoc:
                if line.strip() == heredoc_terminator:
                    in_heredoc = False
                    heredoc_terminator = ""
                continue
            m = re.search(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1", line)
            if m:
                in_heredoc = True
                heredoc_terminator = m.group(2)
            out.append(line)
        return out

    async def run(self, args: dict[str, Any]) -> dict[str, Any]:
        content = args["content"]
        # Whole-script validation — fails closed.
        reasons, rules = self._validate_script(content)
        if reasons:
            raise ValueError(
                "TERMINAL_COMMAND_BLOCKED: script rejected — "
                + "; ".join(reasons[:3])
            )
        workspace = self.executor.resolve_cwd(args.get("cwd") or ".")
        script_path = workspace / f".secureagent-script-{os.getpid()}-{os.urandom(4).hex()}.sh"
        script_path.write_text("#!/usr/bin/env bash\nset -u -o pipefail\n" + content, encoding="utf-8")
        os.chmod(script_path, 0o700)
        try:
            execution = await self.executor.execute(
                f"bash {quote_argv([str(script_path)])}",
                cwd=str(workspace),
                timeout=args.get("timeout_seconds"),
                approval="approved",
            )
        finally:
            try:
                script_path.unlink()
            except OSError:
                pass
        snap = execution.snapshot(self.executor.config.terminal_max_output_bytes)
        stdout, stdout_truncated = _truncate(snap["stdout"], self.limit)
        stderr, _ = _truncate(snap["stderr"], self.limit)
        if execution.error and execution.error.startswith("SUDO_PASSWORD_REQUIRED"):
            raise PermissionError(execution.error)
        return {
            "command": execution.command,
            "stdout": stdout,
            "stderr": stderr,
            "exit_code": execution.exit_code if execution.exit_code is not None else -1,
            "duration_ms": execution.duration_ms,
            "truncated": stdout_truncated or execution.output_truncated,
            "cwd": execution.cwd,
            "risk": execution.risk,
            "classification": "whole-script validated (forbidden patterns + per-line policy)",
            "requires_elevation": False,
            "status": execution.status,
            "error": execution.error,
            "execution_id": execution.id,
            "script_path": "(temporary script removed after execution)",
        }


class _FixedInspection(Tool):
    """Base for tools that run a fixed argv through the executor."""
    category = "terminal"
    platforms = ["linux"]
    risk_level = RiskLevel.LOW
    permissions = frozenset({Permission.EXECUTE})
    output_model = TerminalCommandOut

    def __init__(self, executor: LinuxTerminalExecutor, limit: int = MAX_OUTPUT_CHARS):
        self.executor = executor
        self.limit = limit
        self.enabled = executor.available
        self.disabled_reason = None if executor.available else executor.unavailable_reason()

    def argv(self) -> list[list[str]]:
        raise NotImplementedError

    async def run(self, args: dict[str, Any]) -> dict[str, Any]:
        sections: list[str] = []
        last_exit = 0
        last_execution = None
        errors: list[str] = []
        for vector in self.argv():
            execution = await self.executor.execute(quote_argv(vector), approval="fixed-vector")
            snap = execution.snapshot(self.executor.config.terminal_max_output_bytes)
            header = f"$ {quote_argv(vector)}"
            body = (snap["stdout"] or snap["stderr"]).strip()
            if body:
                sections.append(f"{header}\n{body}")
            if execution.exit_code:
                last_exit = execution.exit_code
                if snap["stderr"]:
                    errors.append(f"{header}: {snap['stderr'].strip()[:200]}")
            last_execution = execution
            if self.executor.cancellation.was_cancelled(execution.id):
                break
        combined = "\n\n".join(sections) or "(no output)"
        text, truncated = _truncate(combined, self.limit)
        return {
            "command": " ; ".join(quote_argv(vector) for vector in self.argv()),
            "stdout": text,
            "stderr": "\n".join(errors)[:2000],
            "exit_code": last_exit,
            "duration_ms": last_execution.duration_ms if last_execution else 0,
            "truncated": truncated,
            "cwd": str(self.executor.resolve_cwd(".")),
            "risk": "safe",
            "classification": "fixed read-only command vector",
            "requires_elevation": False,
            "status": last_execution.status if last_execution else "completed",
            "error": "\n".join(errors)[:500] or None,
            "execution_id": last_execution.id if last_execution else "",
        }


class TerminalWorkingDirectory(_FixedInspection):
    name = "terminal_get_working_directory"
    description = "Show the approved terminal workspace root and all allowed roots."
    input_model = type("EmptyIn", (BaseModel,), {})

    def argv(self) -> list[list[str]]:
        roots = self.executor.allowed_roots()
        return [["pwd"]]

    async def run(self, args):  # override to include roots without shell
        roots = [str(root) for root in self.executor.allowed_roots()]
        return {
            "command": ["(builtin) workspace report"],
            "stdout": f"workspace_root={roots[0]}\nallowed_roots=" + "\n".join(roots),
            "stderr": "",
            "exit_code": 0,
            "duration_ms": 0,
            "truncated": False,
            "cwd": roots[0],
            "risk": "safe",
            "classification": "deterministic workspace report",
            "requires_elevation": False,
            "status": "completed",
            "error": None,
            "execution_id": "",
        }


class TerminalInspectProcess(_FixedInspection):
    name = "terminal_inspect_process"
    description = "List running processes ordered by CPU (read-only ps)."

    class _In(BaseModel):
        limit: int = Field(40, ge=1, le=200)

    input_model = _In

    def argv(self) -> list[list[str]]:
        return [
            ["ps", "-eo", "pid,ppid,user,stat,etimes,%cpu,%mem,comm", "--sort=-%cpu"],
        ]


class TerminalInspectNetwork(_FixedInspection):
    name = "terminal_inspect_network"
    description = "Show local interfaces, routes, DNS servers, and listening sockets (read-only)."

    class _In(BaseModel):
        pass

    input_model = _In

    def argv(self) -> list[list[str]]:
        return [
            ["ip", "-brief", "address"],
            ["ip", "route"],
            ["cat", "/etc/resolv.conf"],
            ["ss", "-tulwn"],
        ]


class TerminalInspectServices(_FixedInspection):
    name = "terminal_inspect_services"
    description = "List running and enabled systemd services (read-only)."

    class _In(BaseModel):
        pass

    input_model = _In

    def argv(self) -> list[list[str]]:
        import shutil
        if shutil.which("systemctl"):
            return [
                ["systemctl", "list-units", "--type=service", "--state=running",
                 "--no-pager", "--no-legend"],
                ["systemctl", "list-unit-files", "--type=service", "--state=enabled",
                 "--no-pager", "--no-legend"],
            ]
        return [["ps", "-eo", "pid,user,comm,args"]]


class TerminalInspectSystem(_FixedInspection):
    name = "terminal_inspect_system"
    description = "Report kernel, distribution, uptime, disk, and memory (read-only)."

    class _In(BaseModel):
        pass

    input_model = _In

    def argv(self) -> list[list[str]]:
        return [
            ["uname", "-a"],
            ["cat", "/etc/os-release"],
            ["uptime"],
            ["df", "-h", "-x", "tmpfs", "-x", "devtmpfs"],
            ["free", "-m"],
        ]


class TerminalEnvironmentInfo(_FixedInspection):
    name = "terminal_get_environment_info"
    description = "Detect installed toolchain versions (python, node, git, docker, ollama, shell)."

    class _In(BaseModel):
        pass

    input_model = _In

    def argv(self) -> list[list[str]]:
        import shutil
        vectors: list[list[str]] = [["bash", "--version"]]
        for binary, flag in (("python3", "--version"), ("node", "--version"),
                             ("npm", "--version"), ("git", "--version"),
                             ("docker", "--version"), ("ollama", "--version")):
            if shutil.which(binary):
                vectors.append([binary, flag])
            else:
                vectors.append(["true", f"{binary}=not-installed"])
        return vectors


class TerminalListDirectory(Tool):
    name = "terminal_list_directory"
    description = "List a directory inside the approved workspace (no shell involved)."
    category = "terminal"
    platforms = ["linux"]
    risk_level = RiskLevel.LOW
    permissions = frozenset({Permission.READ})

    class _In(BaseModel):
        path: str = Field(".", max_length=4096)

    class _Out(BaseModel):
        path: str
        entries: list[dict[str, Any]]
        truncated: bool

    input_model = _In
    output_model = _Out

    def __init__(self, executor: LinuxTerminalExecutor):
        self.executor = executor
        self.enabled = True
        self.disabled_reason = None

    async def run(self, args: dict[str, Any]) -> dict[str, Any]:
        directory = self.executor.resolve_cwd(args.get("path") or ".")
        entries: list[dict[str, Any]] = []
        truncated = False
        try:
            children = sorted(os.scandir(directory), key=lambda item: item.name)
        except OSError as error:
            raise ValueError(f"cannot list directory: {error.strerror or error}") from error
        for index, child in enumerate(children):
            if index >= 500:
                truncated = True
                break
            try:
                info = child.stat(follow_symlinks=False)
                mode = stat.filemode(info.st_mode)
                entries.append({
                    "name": child.name,
                    "type": "directory" if child.is_dir(follow_symlinks=False) else "file",
                    "size": None if child.is_dir(follow_symlinks=False) else info.st_size,
                    "mode": mode,
                    "owner": f"{info.st_uid}:{info.st_gid}",
                })
            except OSError:
                continue
        return {"path": str(directory), "entries": entries, "truncated": truncated}


class TerminalReadFile(Tool):
    name = "terminal_read_file"
    description = "Read a bounded text file inside the approved workspace or allowed paths (redacted, no shell)."
    category = "terminal"
    platforms = ["linux"]
    risk_level = RiskLevel.LOW
    permissions = frozenset({Permission.READ})

    class _In(BaseModel):
        path: str = Field(min_length=1, max_length=4096)

    class _Out(BaseModel):
        path: str
        content: str
        truncated: bool
        size_bytes: int

    input_model = _In
    output_model = _Out

    def __init__(self, executor: LinuxTerminalExecutor, limit: int = MAX_OUTPUT_CHARS):
        self.executor = executor
        self.limit = limit
        self.enabled = True
        self.disabled_reason = None

    async def run(self, args: dict[str, Any]) -> dict[str, Any]:
        raw = args["path"]
        if "\x00" in raw or len(raw) > 4096:
            raise ValueError("invalid path")
        candidate = Path(raw).expanduser()
        if not candidate.is_absolute():
            candidate = self.executor.allowed_roots()[0] / candidate
        resolved = candidate.resolve(strict=True)
        roots = self.executor.allowed_roots()
        if not any(resolved == root or root in resolved.parents for root in roots):
            raise PermissionError("path escapes the approved workspace and allowed paths")
        if not resolved.is_file():
            raise ValueError("not a regular file")
        size = resolved.stat().st_size
        cap = min(self.limit, 200000)
        with open(resolved, "rb") as handle:
            data = handle.read(cap + 1)
        truncated = len(data) > cap or size > cap
        from app.linux_terminal import redact_output
        content = redact_output(data[:cap].decode("utf-8", errors="replace"))
        return {"path": str(resolved), "content": content, "truncated": truncated, "size_bytes": size}


class TerminalSearchFiles(Tool):
    name = "terminal_search_files"
    description = "Search file names and contents inside the approved workspace (bounded, no shell)."
    category = "terminal"
    platforms = ["linux"]
    risk_level = RiskLevel.LOW
    permissions = frozenset({Permission.READ})

    class _In(BaseModel):
        query: str = Field(min_length=1, max_length=200)
        path: str = Field(".", max_length=4096)
        search_content: bool = False
        limit: int = Field(100, ge=1, le=500)

    class _Out(BaseModel):
        matches: list[dict[str, Any]]
        truncated: bool

    input_model = _In
    output_model = _Out

    def __init__(self, executor: LinuxTerminalExecutor):
        self.executor = executor
        self.enabled = True
        self.disabled_reason = None

    async def run(self, args: dict[str, Any]) -> dict[str, Any]:
        import fnmatch
        base = self.executor.resolve_cwd(args.get("path") or ".")
        pattern = args["query"].lower()
        content_mode = bool(args.get("search_content"))
        matches: list[dict[str, Any]] = []
        truncated = False
        files_seen = 0
        for root, directories, files in os.walk(base):
            directories[:] = [d for d in directories if d not in {".git", "node_modules", "__pycache__", ".venv"}]
            for name in files:
                files_seen += 1
                if files_seen > 20000 or len(matches) >= args["limit"]:
                    truncated = True
                    return {"matches": matches, "truncated": truncated}
                path = Path(root) / name
                if fnmatch.fnmatch(name.lower(), f"*{pattern}*") if "*" in pattern else pattern in name.lower():
                    matches.append({"path": str(path), "match": "filename"})
                    continue
                if content_mode and path.stat().st_size < 512000:
                    try:
                        with open(path, "rb") as handle:
                            data = handle.read(512000)
                        if pattern.encode("utf-8", "ignore") in data.lower():
                            from app.linux_terminal import redact_output
                            matches.append({"path": str(path), "match": "content",
                                            "preview": redact_output(data.decode("utf-8", "replace"))[:200]})
                    except OSError:
                        continue
        return {"matches": matches, "truncated": truncated}
