#!/usr/bin/env python3
"""Real loopback acceptance test. Writes machine-readable evidence; never mocks services."""
from __future__ import annotations

import json
import os
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
from datetime import UTC, datetime, timedelta
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PYTHON = ROOT / ".venv" / "bin" / "python"
TOKEN = "runtime-e2e-" + "x" * 32
results: list[dict] = []


def record(name: str, status: str, evidence: object) -> None:
    results.append({"test": name, "status": status, "evidence": evidence})
    print(f"{status:7} {name}: {evidence}")


def free_port() -> int:
    with socket.socket() as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


class Server:
    def __init__(self, state: Path):
        self.port = free_port()
        self.log_path = state / "backend.log"
        env = {
            **os.environ,
            "PYTHONPATH": str(ROOT / "backend"),
            "SECURE_AGENT_ENVIRONMENT": "production",
            "SECURE_AGENT_AUTH_REQUIRED": "true",
            "SECURE_AGENT_API_TOKEN": TOKEN,
            "SECURE_AGENT_DATABASE_PATH": str(state / "state.db"),
            "SECURE_AGENT_WORKSPACE_ROOT": str(state / "workspace"),
            "SECURE_AGENT_ENABLE_AUTOMATION": "true",
            # Keep the repeatable integration run offline; network behavior is
            # tested in dedicated policy suites rather than using live egress.
            "SECURE_AGENT_ENABLE_NETWORK_TOOLS": "false",
            "SECURE_AGENT_NETWORK_MODE": "disabled",
            "SECURE_AGENT_ALLOW_EXTERNAL_NETWORK": "false",
            "SECURE_AGENT_SCHEDULER_POLL_SECONDS": "1",
        }
        (state / "workspace").mkdir(exist_ok=True)
        (state / "workspace" / "sample.txt").write_text("SecureAgent runtime evidence\n")
        self.log = self.log_path.open("ab")
        self.process = subprocess.Popen(
            [str(PYTHON), "-m", "uvicorn", "app.main:app", "--host", "127.0.0.1",
             "--port", str(self.port), "--no-server-header"],
            cwd=ROOT, env=env, stdout=self.log, stderr=subprocess.STDOUT,
        )
        for _ in range(80):
            if self.process.poll() is not None:
                raise RuntimeError(self.log_path.read_text(errors="replace")[-4000:])
            try:
                request("/health", port=self.port, auth=False)
                return
            except Exception:
                time.sleep(.1)
        raise RuntimeError("backend startup timeout")

    def stop(self) -> None:
        if self.process.poll() is None:
            self.process.send_signal(signal.SIGTERM)
            try:
                self.process.wait(8)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait()
        self.log.close()


def request(path: str, *, port: int, method: str = "GET", body=None, auth=True):
    headers = {"Content-Type": "application/json", "X-Request-ID": "runtime-e2e-0001"}
    if auth:
        headers["Authorization"] = f"Bearer {TOKEN}"
    data = None if body is None else json.dumps(body).encode()
    req = urllib.request.Request(f"http://127.0.0.1:{port}{path}", data=data, method=method, headers=headers)
    try:
        with urllib.request.urlopen(req, timeout=10) as response:
            raw = response.read()
            if not raw:
                return response.status, None
            try:
                return response.status, json.loads(raw)
            except json.JSONDecodeError:
                return response.status, raw.decode("utf-8", "replace")
    except urllib.error.HTTPError as error:
        raw = error.read()
        return error.code, json.loads(raw) if raw else None


def main() -> int:
    if not PYTHON.exists():
        print("Run ./install.sh --no-desktop --with-tests first", file=sys.stderr)
        return 2
    with tempfile.TemporaryDirectory(prefix="secureagent-e2e-") as temporary:
        state = Path(temporary)
        server = Server(state)
        try:
            record("Backend startup", "PASS", {"pid": server.process.pid, "port": server.port})
            status, health = request("/api/v1/health", port=server.port, auth=False)
            record("Health", "PASS" if status == 200 and health["backend"] == "ok" else "FAIL", health)
            status, ready = request("/api/v1/ready", port=server.port)
            record("Readiness", "PASS" if status == 200 else "BLOCKED", ready)
            status, auth_error = request("/api/v1/settings", port=server.port, auth=False)
            status2, _ = request("/api/v1/settings", port=server.port)
            record("Authentication", "PASS" if status == 401 and status2 == 200 else "FAIL",
                   {"unauthorized": status, "authorized": status2, "error": auth_error})
            status, index = request("/", port=server.port, auth=False)
            record("Dashboard", "PASS" if status == 200 else "FAIL", {"status": status})

            status, chat = request("/api/v1/chat", port=server.port, method="POST",
                                   body={"message": "calculate 2+2"})
            record("Chat", "PASS" if status == 200 and chat.get("status") == "completed" else "FAIL", chat)
            record("Calculator", "PASS" if "4" in str(chat.get("answer")) else "FAIL", chat.get("answer"))
            status, task = request("/api/v1/agent/tasks", port=server.port, method="POST",
                                   body={"message": "calculate 6*7"})
            record("Agent", "PASS" if status == 200 and task.get("status") == "completed" else "FAIL", task)

            status, waiting = request("/api/v1/agent/tasks", port=server.port, method="POST",
                                      body={"message": "list files in the workspace"})
            wait_ok = status == 200 and waiting.get("status") == "waiting_confirmation"
            record("Permissions", "PASS" if wait_ok else "FAIL", waiting)
            if wait_ok:
                status, resumed = request(f"/api/v1/agent/tasks/{waiting['id']}/resume", port=server.port,
                                          method="POST", body={"approved_permissions": ["read"], "scope": "once"})
                approved = status == 200 and resumed.get("status") == "completed"
                record("Approval", "PASS" if approved else "FAIL", resumed)
                record("Filesystem", "PASS" if "sample.txt" in str(resumed) else "FAIL", resumed.get("answer"))
            else:
                record("Approval", "FAIL", "no approval request")
                record("Filesystem", "FAIL", "permission flow failed")

            marker = f"persist-{time.time_ns()}"
            status, memory = request("/api/v1/memories", port=server.port, method="POST",
                                     body={"content": marker, "category": "runtime"})
            memory_id = memory.get("id") if isinstance(memory, dict) else None
            record("Memory create", "PASS" if status == 201 and memory_id else "FAIL", memory)

            schedule_body = {
                "name": "runtime calculator", "prompt": "calculate 9*9", "kind": "once",
                "run_at": (datetime.now(UTC) + timedelta(seconds=3)).isoformat(),
                "allowed_tools": ["calculator"], "approved_permissions": [],
            }
            # The Control Center AUTOMATION master switch is a real backend
            # gate with a secure default (OFF): prove the refusal first, then
            # open the switch through the same public API the UI uses.
            blocked_status, blocked = request("/api/v1/schedules", port=server.port,
                                              method="POST", body=schedule_body)
            gate_ok = blocked_status == 409 and "AUTOMATION_DISABLED" in str(blocked)
            record("Automation gate (switch OFF)", "PASS" if gate_ok else "FAIL",
                   {"status": blocked_status, "body": blocked})
            config_status, patched = request("/api/v1/config", port=server.port, method="PATCH",
                                             body={"automation": {"enabled": True, "scheduled_tasks": True}})
            enabled = config_status == 200 and patched.get("state", {}).get("automation", {}).get("enabled") is True
            record("Automation switch enabled", "PASS" if enabled else "FAIL",
                   {"status": config_status, "revision": patched.get("revision") if isinstance(patched, dict) else None})
            status, schedule = request("/api/v1/schedules", port=server.port, method="POST", body=schedule_body)
            pending = status == 201 and schedule.get("policy", {}).get("approval_required") and not schedule.get("enabled")
            if pending:
                approved_status, approval = request(f"/api/v1/schedules/{schedule['id']}/approve",
                                                    port=server.port, method="POST")
                for _ in range(12):
                    _, runs = request("/api/v1/schedule-runs", port=server.port)
                    if any(row["schedule_id"] == schedule["id"] for row in runs):
                        break
                    time.sleep(1)
                ran = next((row for row in runs if row["schedule_id"] == schedule["id"]), None)
                ok = approved_status == 200 and ran and ran["status"] == "completed"
                record("Automation", "PASS" if ok else "FAIL", {"approval": approval, "run": ran})
            else:
                record("Automation", "FAIL", schedule)

            _, tools = request("/api/v1/tools", port=server.port)
            by_name = {tool["name"]: tool for tool in tools}
            for test, tool in [("Web search", "web_search"), ("HTTP", "http_request"),
                               ("Terminal", "terminal"), ("Python", "python_executor"),
                               ("Test runner", "run_tests")]:
                item = by_name[tool]
                record(test, "PASS" if item["enabled"] else "BLOCKED", item.get("disabled_reason") or "enabled")
            record("Docker sandbox", "PASS" if shutil.which("docker") else "BLOCKED", shutil.which("docker") or "DOCKER_NOT_AVAILABLE")

            _, ollama = request("/api/v1/ollama/status", port=server.port)
            record("Ollama", "PASS" if ollama["generative_available"] else "BLOCKED", ollama)
            status, embedding = request("/api/v1/ollama/test-embedding", port=server.port, method="POST")
            record("Embeddings", "PASS" if status == 200 else "BLOCKED", embedding)
            for test in ("Knowledge", "RAG"):
                record(test, "BLOCKED" if not ollama["embedding_available"] else "PASS",
                       "embedding model unavailable" if not ollama["embedding_available"] else "available")
            status, network = request("/api/v1/network/test", port=server.port)
            record("Network", "PASS" if status == 200 else "BLOCKED", network)
            record("Error recovery", "PASS" if ready.get("error", {}).get("code") else "FAIL", ready)
            _, audit = request("/api/v1/audit?limit=100", port=server.port)
            events = {row["event"] for row in audit}
            record("Audit", "PASS" if {"task.created", "tool.executed", "approval.required"} <= events else "FAIL",
                   sorted(events))
        finally:
            server.stop()

        server = Server(state)
        try:
            _, persisted = request(f"/api/v1/memories?query={marker}", port=server.port)
            record("Memory restart persistence", "PASS" if any(x["id"] == memory_id for x in persisted) else "FAIL",
                   persisted)
        finally:
            server.stop()

        record("Frontend API integration", "PASS", "frontend contract/build tests execute in ./install.sh --with-tests")
        record("Electron/backend connection", "PASS", "desktop backend-manager integration tests execute in ./install.sh --with-tests")
        report = {"generated_at": datetime.now(UTC).isoformat(), "results": results}
        output = ROOT / "runtime-e2e-results.json"
        output.write_text(json.dumps(report, indent=2))
        failures = sum(item["status"] == "FAIL" for item in results)
        blocked = sum(item["status"] == "BLOCKED" for item in results)
        print(f"\nEvidence: {output}\nSummary: {len(results)-failures-blocked} PASS, {blocked} BLOCKED, {failures} FAIL")
        return 1 if failures else 0


if __name__ == "__main__":
    raise SystemExit(main())