import asyncio
import difflib
import hashlib
import re
from typing import Any, Literal

from pydantic import BaseModel, Field

from app.config import settings
from app.models import Permission, RiskLevel
from app.sandbox import DockerSandbox
from app.tools.builtins import FileBase

IGNORED = {".git", ".venv", "node_modules", "dist", "build", "__pycache__"}
TEXT = {".py", ".ts", ".tsx", ".js", ".jsx", ".json", ".md", ".toml", ".yml", ".yaml", ".css", ".html", ".txt"}


class InspectIn(BaseModel):
    path: str = "."
    max_depth: int = Field(4, ge=1, le=16)
    limit: int = Field(500, ge=1, le=2_000)


class InspectOut(BaseModel):
    files: list[dict[str, Any]]
    files_scanned: int
    files_skipped: int
    truncated: bool


class InspectProject(FileBase):
    name = "inspect_project"
    description = "Inspect a bounded authorized project tree"
    category = "coding"
    risk_level = RiskLevel.LOW
    input_model = InspectIn
    output_model = InspectOut
    permissions = frozenset({Permission.READ})

    async def run(self, args):
        base = self.policy.resolve(args["path"], must_exist=True)
        if not base.is_dir():
            raise ValueError("not a directory")
        output: list[dict[str, Any]] = []
        scanned = skipped = 0
        maximum_depth = min(args["max_depth"], self.policy.max_depth)
        for path in self.policy.walk_bounded(args["path"], self.policy.max_search_files, stop_at_limit=True):
            relative = path.relative_to(base)
            if path.is_symlink() or any(part in IGNORED for part in relative.parts) or len(relative.parts) > maximum_depth:
                skipped += 1
                continue
            scanned += 1
            if len(output) >= args["limit"] or scanned > self.policy.max_search_files:
                return {"files": output, "files_scanned": scanned, "files_skipped": skipped, "truncated": True}
            output.append({
                "path": relative.as_posix(),
                "type": "directory" if path.is_dir() else "file",
                "size": None if path.is_dir() else path.stat().st_size,
            })
        return {"files": output, "files_scanned": scanned, "files_skipped": skipped, "truncated": False}


class CodeSearchIn(BaseModel):
    query: str = Field(min_length=1, max_length=300)
    path: str = "."
    regex: bool = False
    limit: int = Field(100, ge=1, le=500)


class CodeSearchOut(BaseModel):
    matches: list[dict[str, Any]]
    files_scanned: int
    files_skipped: int
    matches_found: int
    output_bytes: int
    truncated: bool


class SearchCode(FileBase):
    name = "search_code"
    description = "Search bounded workspace code without loading oversized files"
    category = "coding"
    risk_level = RiskLevel.LOW
    input_model = CodeSearchIn
    output_model = CodeSearchOut
    permissions = frozenset({Permission.READ})

    async def run(self, args):
        return await asyncio.to_thread(self._run_sync, args)

    def _run_sync(self, args):
        config = settings()
        base = self.policy.resolve(args["path"], must_exist=True)
        if not base.is_dir():
            raise ValueError("not a directory")
        query=args["query"]
        if args["regex"] and (re.search(r"[(){}|*+?]",query) or re.search(r"\\[1-9]|\(\?",query)):
            raise ValueError("unsafe regular expression; only the bounded linear subset is supported")
        try:pattern = re.compile(query if args["regex"] else re.escape(query), re.I)
        except re.error as error:raise ValueError("invalid regular expression") from error
        result_limit = min(args["limit"], config.max_search_results)
        # The tool's WorkspacePolicy is initialized from the configured search
        # limits and is the authoritative per-tool boundary; reading the global
        # config here instead would bypass callers that scope the policy
        # (for example scheduled runs confined to a sub-workspace).
        search_file_limit = self.policy.max_search_file_bytes
        output: list[dict[str, Any]] = []
        scanned = skipped = output_bytes = 0
        truncated = False
        for path in self.policy.iter_files(args["path"], self.policy.max_search_files):
            relative_from_base = path.relative_to(base)
            if path.suffix.lower() not in TEXT or any(part in IGNORED for part in relative_from_base.parts):
                skipped += 1
                continue
            if path.stat().st_size > search_file_limit:
                skipped += 1
                continue
            relative = self.policy.relative(path)
            text, was_truncated, _ = self.policy.read_text(relative, search_file_limit)
            if was_truncated or "\x00" in text[:4_096]:
                skipped += 1
                continue
            scanned += 1
            if truncated:
                # Output is already at its configured bound; keep walking the
                # (walk_bounded-limited) tree only so scan/skip accounting
                # stays accurate instead of silently dropping the remainder.
                continue
            for number, line in enumerate(text.splitlines(), 1):
                if not pattern.search(line[:10_000]):
                    continue
                record = {"path": relative, "line": number, "text": line[:500]}
                size = len(str(record).encode("utf-8"))
                if len(output) >= result_limit or output_bytes + size > config.max_search_output_bytes:
                    truncated = True
                    break
                output.append(record)
                output_bytes += size
        return {
            "matches": output,
            "files_scanned": scanned,
            "files_skipped": skipped,
            "matches_found": len(output),
            "output_bytes": output_bytes,
            "truncated": truncated,
        }


class ReplaceIn(BaseModel):
    path: str
    old_text: str = Field(min_length=1)
    new_text: str
    expected_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class ReplaceOut(BaseModel):
    path: str
    backup_path: str
    before_sha256: str
    after_sha256: str
    diff: str


class ReplaceInFile(FileBase):
    name = "replace_in_file"
    description = "Atomically replace one exact match through WorkspacePolicy"
    category = "coding"
    risk_level = RiskLevel.HIGH
    idempotent = False
    input_model = ReplaceIn
    output_model = ReplaceOut
    permissions = frozenset({Permission.WRITE})

    async def run(self, args):
        config = settings()
        if len(args["old_text"].encode("utf-8")) > config.max_replacement_bytes or len(args["new_text"].encode("utf-8")) > config.max_replacement_bytes:
            raise ValueError("replacement exceeds configured byte limit")
        before, truncated, data = self.policy.read_text(args["path"], config.max_edit_file_bytes)
        if truncated:
            raise ValueError("file exceeds configured edit limit")
        digest = hashlib.sha256(data).hexdigest()
        if digest != args["expected_sha256"]:
            raise ValueError("file changed; inspect it again")
        if before.count(args["old_text"]) != 1:
            raise ValueError("old_text must match exactly once")
        after = before.replace(args["old_text"], args["new_text"], 1)
        if len(after.encode("utf-8")) > config.max_edit_file_bytes:
            raise ValueError("edited file exceeds configured byte limit")
        # Phase 7: protected paths cannot be edited without the explicit override token.
        if self.policy.is_protected(args["path"]) and args.get("policy_override") != "PROTECTED-OVERRIDE":
            raise PermissionError("protected path requires explicit policy override")
        backup = self.policy.backup_file(args["path"])
        try:
            self.policy.atomic_write(
                args["path"], after, overwrite=True,
                max_bytes=config.max_edit_file_bytes,
                expected_sha256=digest,
            )
        except Exception:
            # Backup remains available for explicit recovery.
            raise
        after_digest = hashlib.sha256(after.encode("utf-8")).hexdigest()
        diff = "\n".join(difflib.unified_diff(
            before.splitlines(), after.splitlines(),
            fromfile=args["path"], tofile=args["path"], lineterm=""
        ))
        return {
            "path": args["path"],
            "backup_path": backup,
            "before_sha256": digest,
            "after_sha256": after_digest,
            "diff": diff[: self.limit],
        }


class TestIn(BaseModel):
    path: str = "."
    suite: Literal["pytest", "python_pytest", "npm_test"] = "pytest"


class TestOut(BaseModel):
    command: list[str]
    stdout: str
    stderr: str
    exit_code: int
    truncated: bool
    isolation: str
    files_copied: int
    bytes_copied: int


class RunTests(FileBase):
    name = "run_tests"
    description = "Run repository tests only inside the configured Docker sandbox"
    category = "execution"
    risk_level = RiskLevel.HIGH
    sandbox_required = True
    idempotent = False
    timeout_seconds = 600.0
    input_model = TestIn
    output_model = TestOut
    permissions = frozenset({Permission.EXECUTE})

    def __init__(self, root, sandbox: DockerSandbox | None, limit=20_000):
        super().__init__(root, limit)
        self.sandbox = sandbox
        self.enabled = bool(sandbox and sandbox.available)
        self.disabled_reason = None if self.enabled else "TEST_SANDBOX_UNAVAILABLE: Configure a pinned Docker image and start Docker"

    async def run(self, args):
        if self.sandbox is None:
            raise RuntimeError(
                "Sandbox unavailable. Untrusted test execution has been blocked."
            )
        commands = {
            "pytest": ["python", "-m", "pytest", "-q"],
            "python_pytest": ["python", "-m", "pytest", "-q"],
            "npm_test": ["npm", "test", "--", "--run"],
        }
        config = settings()
        result = await self.sandbox.execute_copy(
            self.policy,
            args["path"],
            commands[args["suite"]],
            config.test_max_copy_files,
            config.test_max_copy_bytes,
        )
        return {"command": commands[args["suite"]], **result}
