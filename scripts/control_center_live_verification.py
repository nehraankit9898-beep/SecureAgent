#!/usr/bin/env python3
"""SecureAgent Control Center — LIVE verification (spec section 26).

Starts the REAL SecureAgent backend (uvicorn, Linux terminal backend enabled)
and performs real UI/API operations against it:

    toggle OFF  ->  execute feature  ->  confirm rejection
    toggle ON   ->  execute feature  ->  confirm success
    emergency stop against a real long-running process
    configuration persistence across a backend restart
    invalid configuration rejected with previous state retained

Writes a machine-readable report to .live-verify/live-verification-report.json
and exits non-zero when any check fails. This script is idempotent: every run
uses a fresh .live-verify data directory.
"""
from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import time
from pathlib import Path

import httpx

PROJECT_ROOT = Path(__file__).resolve().parents[1]
LIVE_DIR = PROJECT_ROOT / ".live-verify"
PORT = int(os.environ.get("LIVE_VERIFY_PORT", "8791"))
ORIGIN = f"http://127.0.0.1:{PORT}"
TOKEN = "live-verify-token-0123456789abcdef0123456789"
HEADERS = {"Authorization": f"Bearer {TOKEN}", "Content-Type": "application/json"}

RESULTS: list[dict] = []
BACKEND_ENV = {
    "SECURE_AGENT_ENVIRONMENT": "development",
    "SECURE_AGENT_AUTH_REQUIRED": "true",
    "SECURE_AGENT_API_TOKEN": TOKEN,
    "SECURE_AGENT_DATABASE_PATH": str(LIVE_DIR / "state.db"),
    "SECURE_AGENT_WORKSPACE_ROOT": str(LIVE_DIR / "workspace"),
    "SECURE_AGENT_TERMINAL_BACKEND": "linux",
    "SECURE_AGENT_TERMINAL_TOOLS_ENABLED": "true",
    "SECURE_AGENT_TERMINAL_ALLOW_SUDO": "true",
    "SECURE_AGENT_TERMINAL_COMMAND_TIMEOUT_SECONDS": "120",
    "SECURE_AGENT_SECURITY_WORKFLOWS_ENABLED": "true",
    "SECURE_AGENT_ENABLE_AUTOMATION": "false",
    "SECURE_AGENT_ENABLE_NETWORK_TOOLS": "false",
}


def check(name: str, ok: bool, evidence: str) -> bool:
    RESULTS.append({"check": name, "ok": bool(ok), "evidence": evidence})
    print(f"  [{'PASS' if ok else 'FAIL'}] {name} — {evidence}")
    return bool(ok)


def start_backend() -> subprocess.Popen:
    env = {**os.environ, **BACKEND_ENV}
    process = subprocess.Popen(
        [sys.executable, "-m", "uvicorn", "app.main:app", "--app-dir", str(PROJECT_ROOT / "backend"),
         "--host", "127.0.0.1", "--port", str(PORT), "--log-level", "warning"],
        cwd=str(PROJECT_ROOT), env=env,
        stdout=subprocess.DEVNULL, stderr=subprocess.PIPE,
    )
    deadline = time.time() + 60
    while time.time() < deadline:
        try:
            response = httpx.get(f"{ORIGIN}/health", headers=HEADERS, timeout=2)
            if response.status_code == 200:
                return process
        except Exception:
            pass
        if process.poll() is not None:
            stderr = process.stderr.read().decode()[-1500:]
            raise RuntimeError(f"backend exited during startup: {stderr}")
        time.sleep(0.4)
    process.kill()
    raise RuntimeError("backend did not become healthy within 60s")


def stop_backend(process: subprocess.Popen) -> None:
    process.terminate()
    try:
        process.wait(timeout=10)
    except subprocess.TimeoutExpired:
        process.kill()
        process.wait(timeout=5)


def get(client: httpx.Client, route: str):
    return client.get(f"{ORIGIN}{route}", headers=HEADERS, timeout=30)


def post(client: httpx.Client, route: str, body: dict | None = None):
    return client.post(f"{ORIGIN}{route}", headers=HEADERS, json=body, timeout=60)


def patch(client: httpx.Client, route: str, body: dict):
    return client.patch(f"{ORIGIN}{route}", headers=HEADERS, json=body, timeout=30)


def main() -> int:
    import shutil
    shutil.rmtree(LIVE_DIR, ignore_errors=True)
    LIVE_DIR.mkdir(parents=True, exist_ok=True)

    print("== SecureAgent Control Center — LIVE verification ==")
    print(f"backend origin: {ORIGIN}")
    process = start_backend()
    failures = 0
    try:
        with httpx.Client() as client:
            # ---------------------------------------------------- baseline
            response = get(client, "/api/v1/config")
            check("backend reachable, config API live", response.status_code == 200,
                  f"GET /config -> {response.status_code}")
            config = response.json()
            check("control state file created by backend",
                  (LIVE_DIR / "control_center.json").exists(),
                  str(LIVE_DIR / "control_center.json"))
            check("secure mode defaults ON", config["state"]["secure_mode"] is True,
                  f"secure_mode={config['state']['secure_mode']}")
            check("network defaults DISABLED", config["state"]["network"]["mode"] == "disabled",
                  f"mode={config['state']['network']['mode']}")
            check("sudo defaults OFF", config["state"]["sudo"]["mode"] == "disabled",
                  f"sudo={config['state']['sudo']['mode']}")

            # --------------------------------------- 1. terminal toggle round trip
            response = post(client, "/api/v1/terminal/execute", {"command": "echo live-terminal-on"})
            ok = response.status_code == 200 and "live-terminal-on" in response.json().get("stdout", "")
            check("terminal ON: echo executes", ok, f"POST /terminal/execute -> {response.status_code}")

            response = patch(client, "/api/v1/config", {"terminal": {"enabled": False}})
            check("terminal toggle OFF applied", response.status_code == 200 and response.json()["state"]["terminal"]["enabled"] is False,
                  f"PATCH /config -> {response.status_code}")

            response = post(client, "/api/v1/terminal/execute", {"command": "echo must-be-rejected"})
            check("terminal OFF: execution rejected", response.status_code == 409
                  and response.json()["error"]["code"] == "TERMINAL_DISABLED_BY_CONTROL_CENTER",
                  f"POST /terminal/execute -> {response.status_code} {response.json()['error']['code'] if response.status_code == 409 else response.text[:120]}")

            patch(client, "/api/v1/config", {"terminal": {"enabled": True}})
            response = post(client, "/api/v1/terminal/execute", {"command": "echo live-terminal-back"})
            check("terminal ON again: execution succeeds",
                  response.status_code == 200 and "live-terminal-back" in response.json().get("stdout", ""),
                  f"POST /terminal/execute -> {response.status_code}")

            # ------------------------------------------------- 3. sudo rejected
            response = post(client, "/api/v1/terminal/execute", {"command": "sudo -n id", "confirm": True})
            check("sudo OFF: sudo command rejected", response.status_code == 403
                  and response.json()["error"]["code"] == "TERMINAL_SUDO_DISABLED",
                  f"-> {response.status_code} {response.json().get('error', {}).get('code')}")

            # ------------------------------------------------- 2. network blocked
            response = get(client, "/api/v1/network/test")
            check("network OFF: network test blocked", response.status_code == 409,
                  f"GET /network/test -> {response.status_code}")
            status = get(client, "/api/v1/status").json()
            check("status card: network BLOCKED", status["cards"]["network"]["status"] == "BLOCKED",
                  f"network card={status['cards']['network']}")

            # ------------------------------------------- 4. automation rejected
            from datetime import UTC, datetime, timedelta
            future = (datetime.now(UTC) + timedelta(hours=1)).isoformat()
            response = post(client, "/api/v1/schedules",
                            {"name": "live-verify", "prompt": "echo hi", "kind": "once", "run_at": future})
            check("automation OFF: schedule creation rejected",
                  response.status_code == 409 and "AUTOMATION_DISABLED" in response.text,
                  f"POST /schedules -> {response.status_code}")

            # --------------------------------------------------- 5. tool toggle
            response = patch(client, "/api/v1/tools/calculator", {"enabled": False})
            check("tool toggle OFF applied", response.status_code == 200,
                  f"PATCH /tools/calculator -> {response.status_code}")
            tools = get(client, "/api/v1/tools").json()
            calculator = next(row for row in tools if row["name"] == "calculator")
            check("tool registry reports calculator disabled", calculator["enabled"] is False,
                  f"enabled={calculator['enabled']} reason={calculator['disabled_reason']}")
            patch(client, "/api/v1/tools/calculator", {"enabled": True})
            tools = get(client, "/api/v1/tools").json()
            calculator = next(row for row in tools if row["name"] == "calculator")
            check("tool toggle ON restores calculator", calculator["enabled"] is True,
                  f"enabled={calculator['enabled']}")

            # --------------------------- 6. emergency stop kills real process
            # The terminal execute endpoint is synchronous, so the long-running
            # command is fired from a background thread (exactly what a live
            # agent task does) while the main thread verifies and stops it.
            import threading
            long_result: dict = {}

            def _fire_long_command():
                try:
                    long_result["response"] = post(client, "/api/v1/terminal/execute",
                                                   {"command": "sleep 30 && touch live-emergency-marker.txt",
                                                    "timeout_seconds": 100, "confirm": True})
                except Exception as error:  # noqa: BLE001
                    long_result["error"] = str(error)

            thread = threading.Thread(target=_fire_long_command, daemon=True)
            thread.start()
            running_seen = False
            execution_id = None
            for _ in range(100):
                running = subprocess.run(["pgrep", "-f", "sleep 30"], capture_output=True)
                if running.returncode == 0:
                    running_seen = True
                    break
                time.sleep(0.2)
            check("long-running process started and really alive (pgrep sees sleep 30)",
                  running_seen, "pgrep -f 'sleep 30' found the live child")
            live_executions = get(client, "/api/v1/terminal/executions").json()
            execution_id = live_executions[0]["id"] if live_executions else None
            check("backend tracks the execution as running", execution_id is not None,
                  f"tracked execution id={execution_id}")

            response = post(client, "/api/v1/emergency-stop")
            check("EMERGENCY STOP accepted", response.status_code == 200
                  and response.json()["emergency_stopped"] is True,
                  f"-> {response.status_code}")
            time.sleep(0.6)
            alive = subprocess.run(["pgrep", "-f", "sleep 30"], capture_output=True).returncode == 0
            check("no orphan sleep process remains (killpg worked)", not alive,
                  "pgrep -f 'sleep 30' -> " + ("STILL ALIVE" if alive else "none"))
            if execution_id:
                snap = get(client, f"/api/v1/terminal/executions/{execution_id}").json()
                check("running process terminated by emergency stop",
                      snap.get("status") in {"cancelled", "failed", "timeout"},
                      f"execution status={snap.get('status')}")
            else:
                check("running process terminated by emergency stop", False, "no tracked execution")
            check("marker file never created",
                  not (LIVE_DIR / "workspace" / "live-emergency-marker.txt").exists(),
                  "workspace marker absent")
            response = post(client, "/api/v1/terminal/execute", {"command": "echo blocked-while-stopped"})
            check("terminal refused while stopped", response.status_code == 409
                  and response.json()["error"]["code"] == "SECUREAGENT_STOPPED",
                  f"-> {response.status_code} {response.json().get('error', {}).get('code')}")
            audits = get(client, "/api/v1/audit?category=security").json()
            check("audit preserved (emergency stop recorded)",
                  any(row["event"] == "control.emergency_stop" for row in audits),
                  f"{sum(1 for row in audits if row['event'] == 'control.emergency_stop')} entries")

            response = post(client, "/api/v1/resume")
            check("RESUME restores configured state", response.status_code == 200
                  and response.json()["emergency_stopped"] is False, f"-> {response.status_code}")
            response = post(client, "/api/v1/terminal/execute", {"command": "echo live-after-resume"})
            check("terminal works again after resume",
                  response.status_code == 200 and "live-after-resume" in response.json().get("stdout", ""),
                  f"-> {response.status_code}")

            # ------------------------------------- 7/8. secure mode + host control
            response = patch(client, "/api/v1/config", {"host_control": {"enabled": True}})
            check("host control enable WITHOUT confirm refused",
                  response.status_code == 422
                  and response.json()["error"]["code"] == "HOST_CONTROL_REQUIRES_CONFIRMATION",
                  f"-> {response.status_code}")
            response = patch(client, "/api/v1/config?confirm=true", {"host_control": {"enabled": True}})
            check("host control enable WITH confirm applied", response.status_code == 200
                  and response.json()["state"]["host_control"]["enabled"] is True,
                  f"-> {response.status_code}")
            response = post(client, "/api/v1/terminal/mode", {"mode": "host_control", "confirm": True})
            check("terminal enters HOST_CONTROL after host control enabled",
                  response.status_code == 200 and response.json()["mode"] == "host_control",
                  f"-> {response.status_code}")
            response = patch(client, "/api/v1/config", {"terminal": {"restricted_mode": False}})
            check("restricted mode cannot be disabled while Secure Mode is ON",
                  response.status_code == 422, f"-> {response.status_code}")
            response = post(client, "/api/v1/emergency-stop")
            check("emergency stop turns host control OFF",
                  response.status_code == 200
                  and response.json()["state"]["host_control"]["enabled"] is False,
                  f"host_control={response.json()['state']['host_control']['enabled']}")
            post(client, "/api/v1/resume")
            response = get(client, "/api/v1/terminal/status").json()
            check("terminal mode forced back to restricted_agent",
                  response["mode"] == "restricted_agent", f"mode={response['mode']}")

            # ------------------------------------------- 9. Ollama off behavior
            response = patch(client, "/api/v1/config", {"ai": {"ollama_enabled": False}})
            check("OLLAMA switch OFF applied", response.status_code == 200
                  and response.json()["state"]["ai"]["ollama_enabled"] is False,
                  f"-> {response.status_code}")
            ollama_status = get(client, "/api/v1/ollama/status").json()
            check("ollama OFF reports unavailable (never fake-ready)",
                  ollama_status.get("ollama_available") is not True,
                  f"service_available={ollama_status.get('service_available')}")
            patch(client, "/api/v1/config", {"ai": {"ollama_enabled": True}})

            # ------------------------------ 10. persistence across a restart
            response = patch(client, "/api/v1/config",
                             {"terminal": {"max_command_time_seconds": 77},
                              "memory": {"max_context_items": 25}})
            check("pre-restart config change applied", response.status_code == 200,
                  f"revision={response.json().get('revision')}")
            revision_before = response.json()["revision"]
            stop_backend(process)
            process = start_backend()
            config = get(client, "/api/v1/config").json()
            check("settings restored after full backend restart",
                  config["state"]["terminal"]["max_command_time_seconds"] == 77
                  and config["state"]["memory"]["max_context_items"] == 25,
                  f"max_command_time={config['state']['terminal']['max_command_time_seconds']} max_context={config['state']['memory']['max_context_items']}")
            check("revision preserved across restart", config["revision"] == revision_before,
                  f"revision={config['revision']}")
            check("mandatory protections intact after restart",
                  config["state"]["security"]["audit_logging"] is True
                  and config["state"]["security"]["command_policy"] is True,
                  "audit_logging + command_policy enforced")

            # ------------------------- 11. invalid config rejected + retained
            before = get(client, "/api/v1/config").json()
            for bad_patch, label in (
                ({"terminal": {"max_command_time_seconds": 99999}}, "out-of-bounds timeout"),
                ({"network": {"mode": "teleport"}}, "invalid network mode"),
                ({"security": {"audit_logging": False}}, "mandatory protection disabled"),
                ({"sudo": {"mode": "unrestricted"}}, "invalid sudo mode"),
                ({"agent": {"enabled": "banana"}}, "invalid type"),
            ):
                response = patch(client, "/api/v1/config", bad_patch)
                check(f"invalid config rejected: {label}", response.status_code == 422,
                      f"-> {response.status_code}")
            after = get(client, "/api/v1/config").json()
            check("previous configuration retained after rejections",
                  after["state"] == before["state"] and after["revision"] == before["revision"],
                  f"revision={after['revision']} (unchanged)")

            # --------------------------------- 12. frontend manipulation denied
            response = patch(client, "/api/v1/permissions",
                             {"action": "grant", "permission": "admin", "scope": "always", "note": "live-verify"})
            check("admin grant refused", response.status_code == 422,
                  f"-> {response.status_code}")
            response = post(client, "/api/v1/terminal/execute",
                            {"command": "cat /etc/shadow", "confirm": True})
            check("sensitive file access refused even with confirm", response.status_code == 403,
                  f"-> {response.status_code}")
            response = patch(client, "/api/v1/config", {"host_control": {"enabled": True}})
            check("config PATCH without confirm still refused after all tests",
                  response.status_code == 422, f"-> {response.status_code}")

            # ------------------------------------------- 17. live status cards
            status = get(client, "/api/v1/status").json()
            expected_cards = {"backend", "agent", "terminal", "sandbox", "security",
                              "ollama", "network", "memory", "rag", "automation"}
            valid_states = {"ONLINE", "OFFLINE", "DEGRADED", "BLOCKED", "ERROR"}
            ok = expected_cards <= set(status["cards"].keys()) and all(
                card["status"] in valid_states for card in status["cards"].values())
            check("live status cards for all 10 components", ok,
                  ", ".join(f"{name}={card['status']}" for name, card in status["cards"].items()))

            # --------------------------------------- 24. real-time sync (SSE)
            sse_ok = False
            sse_evidence = "no event received"
            try:
                with httpx.stream("GET", f"{ORIGIN}/api/v1/config/events",
                                  headers=HEADERS, timeout=8) as stream:
                    buffer = ""
                    started = time.time()
                    for chunk in stream.iter_text():
                        buffer += chunk
                        if "event: config" in buffer and "revision" in buffer:
                            sse_ok = True
                            sse_evidence = buffer.strip().splitlines()[-1][:80]
                            break
                        if time.time() - started > 6:
                            break
            except Exception as error:
                sse_evidence = f"stream error: {error}"
            check("config events SSE stream delivers revisions", sse_ok, sse_evidence)

            # -------------------------------------------- 16. audit export/clear
            response = post(client, "/api/v1/audit/clear", {"confirm": False})
            check("audit clear refused without confirmation", response.status_code == 403,
                  f"-> {response.status_code}")
            response = post(client, "/api/v1/audit/export")
            exported = response.json()
            check("audit export writes a JSONL file", response.status_code == 200
                  and Path(exported["path"]).exists() and exported["entries"] > 0,
                  f"{exported.get('entries')} entries -> {exported.get('path')}")

            # -------------------------------------------- 23. one-click transaction
            response = patch(client, "/api/v1/config", {
                "terminal": {"max_output_bytes": 150000},
                "agent": {"auto_retry": False},
                "network": {"mode": "localhost"},
            })
            transaction_ok = (response.status_code == 200
                              and response.json()["state"]["terminal"]["max_output_bytes"] == 150000
                              and response.json()["state"]["agent"]["auto_retry"] is False
                              and response.json()["state"]["network"]["mode"] == "localhost")
            check("multi-field transaction applied atomically", transaction_ok,
                  f"revision={response.json().get('revision') if response.status_code == 200 else response.text[:120]}")
            patch(client, "/api/v1/config", {"network": {"mode": "disabled"}})
    finally:
        stop_backend(process)

    failures = sum(1 for item in RESULTS if not item["ok"])
    report = {
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "origin": ORIGIN,
        "total": len(RESULTS),
        "failures": failures,
        "results": RESULTS,
    }
    report_path = LIVE_DIR / "live-verification-report.json"
    report_path.write_text(json.dumps(report, indent=2), encoding="utf-8")
    print(f"\n== {len(RESULTS) - failures}/{len(RESULTS)} checks passed — report: {report_path} ==")
    return 1 if failures else 0


if __name__ == "__main__":
    code = 1
    backend = None
    try:
        backend = None  # started inside main()
        code = main()
    except Exception as error:  # noqa: BLE001
        print(f"LIVE VERIFICATION ERROR: {error}")
        code = 2
    sys.exit(code)
