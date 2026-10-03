#!/usr/bin/env python3
"""Smoke-test the PyInstaller-built SecureAgentBackend binary.

Mirrors the desktop launch contract: loopback host, dynamic port, production
environment, mandatory bearer auth, isolated data/workspace paths.
"""
import json
import os
import secrets
import socket
import subprocess
import sys
import tempfile
import time
import urllib.error
import urllib.request
import re
from pathlib import Path

BINARY = sys.argv[1] if len(sys.argv) > 1 else "build/backend-build/SecureAgentBackend"

# The expected version is read from the single authoritative source — the
# FastAPI app declaration in backend/app/main.py, the same source
# backend/tests/test_engineering_fixes.py pins the frontend/desktop
# package.json files to. Hardcoding a copy here is what made this smoke test
# fail against a correctly built binary after the 2.0.0 version bump.
_MAIN = Path(__file__).resolve().parents[1] / "app" / "main.py"
_match = re.search(r'app = FastAPI\(title=config\.app_name, version="([^"]+)"',
                   _MAIN.read_text(encoding="utf-8"))
if not _match:
    raise SystemExit("could not determine the application version from backend/app/main.py")
VERSION = _match.group(1)


def free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
        sock.bind(("127.0.0.1", 0))
        return sock.getsockname()[1]


def request(url: str, token: str | None = None, timeout: float = 5.0):
    headers = {"Authorization": f"Bearer {token}"} if token else {}
    req = urllib.request.Request(url, headers=headers)
    with urllib.request.urlopen(req, timeout=timeout) as response:
        return response.status, json.loads(response.read().decode())


def expect_status(url: str, token: str | None = None):
    try:
        status, _ = request(url, token)
        return status
    except urllib.error.HTTPError as error:
        return error.code


def main() -> int:
    port = free_port()
    token = secrets.token_urlsafe(32)
    root = tempfile.mkdtemp(prefix="secureagent-smoke-")
    env = dict(os.environ)
    env.update(
        {
            "SECURE_AGENT_HOST": "127.0.0.1",
            "SECURE_AGENT_PORT": str(port),
            "SECURE_AGENT_ENVIRONMENT": "production",
            "SECURE_AGENT_AUTH_REQUIRED": "true",
            "SECURE_AGENT_ALLOW_UNAUTHENTICATED_LOCALHOST": "false",
            "SECURE_AGENT_API_TOKEN": token,
            "SECURE_AGENT_DATABASE_PATH": os.path.join(root, "data", "smoke.db"),
            "SECURE_AGENT_WORKSPACE_ROOT": os.path.join(root, "workspace"),
        }
    )
    os.makedirs(env["SECURE_AGENT_DATABASE_PATH"].rsplit("/", 1)[0], exist_ok=True)
    os.makedirs(env["SECURE_AGENT_WORKSPACE_ROOT"], exist_ok=True)

    base = f"http://127.0.0.1:{port}"
    process = subprocess.Popen([BINARY], env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    checks = []
    try:
        deadline = time.time() + 60
        health = None
        while time.time() < deadline:
            if process.poll() is not None:
                print(f"SMOKE_FAIL backend exited early code={process.returncode}")
                return 1
            try:
                status, health = request(f"{base}/health", timeout=2)
                if health.get("status") == "ok":
                    break
                health = None
            except (urllib.error.URLError, ConnectionError, TimeoutError, OSError):
                pass
            time.sleep(0.5)

        checks.append(("health ok", bool(health and health.get("status") == "ok")))
        checks.append(("health version", bool(health and health.get("version") == VERSION)))
        checks.append(("database ok", bool(health and health.get("database") == "ok")))
        checks.append(("workspace ok", bool(health and health.get("workspace") == "ok")))

        try:
            status, settings = request(f"{base}/api/v1/settings", token)
            checks.append(("auth accepted", status == 200 and settings.get("app_name") == "SecureAgent"))
        except Exception:
            checks.append(("auth accepted", False))
        checks.append(("unauth rejected 401", expect_status(f"{base}/api/v1/settings") == 401))
        checks.append(("bad token rejected 401", expect_status(f"{base}/api/v1/settings", "x" * 40) == 401))

        for name, ok in checks:
            print(f"  [{'PASS' if ok else 'FAIL'}] {name}")
        if all(ok for _, ok in checks):
            print("BINARY_SMOKE_PASS")
            return 0
        print("SMOKE_FAIL")
        return 1
    finally:
        if process.poll() is None:
            process.terminate()
            try:
                process.wait(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()


if __name__ == "__main__":
    sys.exit(main())
