import asyncio
import re
import shutil
import tempfile
from dataclasses import dataclass
from pathlib import Path
from uuid import uuid4

from app.workspace import WorkspacePolicy

FORBIDDEN_DOCKER_OPTIONS = {
    "--privileged", "--pid=host", "--network=host", "/var/run/docker.sock"
}
async def read_stream_limited(stream,limit):
    kept=bytearray();total=0
    while chunk:=await stream.read(65_536):
        total+=len(chunk)
        if len(kept)<limit:kept.extend(chunk[:limit-len(kept)])
    return bytes(kept),total>limit


@dataclass(frozen=True)
class SandboxPolicy:
    image: str
    timeout_seconds: float
    memory_mb: int
    cpu_limit: float
    pids_limit: int
    output_limit: int
    network: bool = False

    def __post_init__(self):
        if not re.fullmatch(r"[^\s]+@sha256:[0-9a-f]{64}",self.image):
            raise ValueError("sandbox image must be pinned by immutable sha256 digest")
        if self.network:
            raise ValueError("sandbox network must remain disabled")


class DockerSandbox:
    """Executes fixed commands in a locked-down container.

    The LLM controls neither Docker options nor the executable. A bounded,
    symlink-free project copy is mounted read-only; execution occurs in a tmpfs.
    """

    def __init__(self, policy: SandboxPolicy):
        self.policy = policy

    @property
    def available(self) -> bool:
        return shutil.which("docker") is not None

    def command(self, name: str, source: Path, fixed_command: list[str]) -> list[str]:
        mount = f"type=bind,src={source},dst=/input,readonly"
        command = [
            "docker", "run", "--rm", "--name", name,
            "--network", "none",
            "--read-only",
            "--memory", f"{self.policy.memory_mb}m",
            "--cpus", str(self.policy.cpu_limit),
            "--pids-limit", str(self.policy.pids_limit),
            "--user", "65534:65534",
            "--cap-drop", "ALL",
            "--security-opt", "no-new-privileges",
            "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m",
            "--tmpfs", "/work:rw,nosuid,size=256m",
            "--mount", mount,
            "--workdir", "/work",
            self.policy.image,
            "sh", "-c",
            "cp -R /input/. /work/ && exec \"$@\"",
            "sandbox-runner",
            *fixed_command,
        ]
        joined = " ".join(command)
        if any(option in joined for option in FORBIDDEN_DOCKER_OPTIONS):
            raise RuntimeError("unsafe Docker option detected")
        return command

    async def execute_copy(
        self,
        workspace: WorkspacePolicy,
        project_path: str,
        fixed_command: list[str],
        max_files: int,
        max_total_bytes: int,
    ) -> dict:
        if not self.available:
            raise RuntimeError(
                "Sandbox unavailable. Untrusted test execution has been blocked."
            )
        name = "SecureAgent-sandbox-" + uuid4().hex[:12]
        with tempfile.TemporaryDirectory(prefix="agent-sandbox-") as temporary:
            copy_root = Path(temporary) / "project"
            copy_root.mkdir()
            files, copied_bytes = workspace.safe_copy_tree(
                project_path, copy_root, max_files, max_total_bytes
            )
            process = await asyncio.create_subprocess_exec(
                *self.command(name, copy_root, fixed_command),
                stdin=asyncio.subprocess.DEVNULL,
                stdout=asyncio.subprocess.PIPE,
                stderr=asyncio.subprocess.PIPE,
            )
            try:
                stdout_task=asyncio.create_task(read_stream_limited(process.stdout,self.policy.output_limit));stderr_task=asyncio.create_task(read_stream_limited(process.stderr,self.policy.output_limit))
                stdout_result,stderr_result,_=await asyncio.wait_for(asyncio.gather(stdout_task,stderr_task,process.wait()),self.policy.timeout_seconds)
            except asyncio.TimeoutError:
                process.kill()
                await process.wait()
                await asyncio.gather(stdout_task,stderr_task,return_exceptions=True)
                await self._cleanup(name)
                raise TimeoutError("sandbox execution timeout")
            except asyncio.CancelledError:
                process.kill()
                await process.wait()
                await asyncio.gather(stdout_task,stderr_task,return_exceptions=True)
                await self._cleanup(name)
                raise
            finally:
                if process.returncode is None:
                    await self._cleanup(name)
            stdout,stdout_truncated=stdout_result;stderr,stderr_truncated=stderr_result
            output = stdout.decode("utf-8", errors="replace");error = stderr.decode("utf-8", errors="replace")
            return {
                "stdout": output[: self.policy.output_limit],
                "stderr": error[: self.policy.output_limit],
                "exit_code": process.returncode,
                "truncated": stdout_truncated or stderr_truncated,
                "isolation": "docker-copy-network-none-read-only-nonroot",
                "files_copied": files,
                "bytes_copied": copied_bytes,
            }

    async def _cleanup(self, name: str) -> None:
        if not self.available:
            return
        cleanup = await asyncio.create_subprocess_exec(
            "docker", "rm", "-f", name,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=asyncio.subprocess.DEVNULL,
        )
        await cleanup.wait()


class DockerPythonSandbox(DockerSandbox):
    async def execute(self, code: str) -> dict:
        if not self.available:
            raise RuntimeError("PYTHON_SANDBOX_UNAVAILABLE")
        if not isinstance(code, str) or not code or len(code.encode("utf-8")) > 10_000:
            raise ValueError("invalid Python input")
        name = "SecureAgent-python-" + uuid4().hex[:12]
        command = ["docker", "run", "--rm", "--name", name, "--network", "none", "--read-only", "--memory", f"{self.policy.memory_mb}m", "--cpus", str(self.policy.cpu_limit), "--pids-limit", str(self.policy.pids_limit), "--user", "65534:65534", "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--tmpfs", "/tmp:rw,noexec,nosuid,size=32m", "--workdir", "/tmp", "-i", self.policy.image, "python", "-I", "-B", "-"]
        process = await asyncio.create_subprocess_exec(*command, stdin=asyncio.subprocess.PIPE, stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.PIPE)
        stdout_task=asyncio.create_task(read_stream_limited(process.stdout,self.policy.output_limit));stderr_task=asyncio.create_task(read_stream_limited(process.stderr,self.policy.output_limit))
        try:
            process.stdin.write(code.encode('utf-8'));await process.stdin.drain();process.stdin.close()
            stdout_result,stderr_result,_=await asyncio.wait_for(asyncio.gather(stdout_task,stderr_task,process.wait()),self.policy.timeout_seconds)
        except asyncio.TimeoutError:
            process.kill();await process.wait();await asyncio.gather(stdout_task,stderr_task,return_exceptions=True);await self._cleanup(name)
            raise TimeoutError("Python sandbox timeout")
        except asyncio.CancelledError:
            process.kill();await process.wait();await asyncio.gather(stdout_task,stderr_task,return_exceptions=True);await self._cleanup(name);raise
        limit = self.policy.output_limit
        stdout,stdout_truncated=stdout_result;stderr,stderr_truncated=stderr_result
        return {"stdout": stdout.decode("utf-8", "replace"), "stderr": stderr.decode("utf-8", "replace"), "exit_code": process.returncode, "truncated": stdout_truncated or stderr_truncated}
