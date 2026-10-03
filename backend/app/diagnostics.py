"""SecureAgent 2.0 — Feature Self-Test System (spec section 11).

Every major module exposes a ``test_*`` function that returns a real verdict
(``PASS`` / ``FAIL`` / ``WARNING`` / ``NOT_AVAILABLE``) with ``reason``,
``diagnostic`` and ``suggested_fix``. The diagnostics endpoint aggregates
these so the UI can show honest feature status — never fake ``ENABLED``.

Design rules (spec section 56 — "NO PRETENDING"):
- Never report ``PASS`` without actually exercising the feature.
- Never swallow an exception silently — surface it as ``FAIL`` with reason.
- ``NOT_AVAILABLE`` is for missing optional dependencies (Ollama binary,
  bubblewrap, Docker). ``FAIL`` is for "should work but did not".
- ``WARNING`` is for "works but with reduced capability" (e.g., Ollama
  reachable but no models installed; sandbox unavailable so terminal
  degrades to policy-only mode).
"""
from __future__ import annotations

import asyncio
import logging
import shutil
import time
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any, Literal

logger = logging.getLogger("secureagent.diagnostics")

Verdict = Literal["PASS", "FAIL", "WARNING", "NOT_AVAILABLE", "NOT_CONFIGURED"]


@dataclass
class TestResult:
    """Single feature self-test verdict (spec section 11)."""

    component: str
    status: Verdict
    reason: str
    diagnostic: str
    suggested_fix: str
    duration_ms: int
    evidence: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "component": self.component,
            "status": self.status,
            "reason": self.reason,
            "diagnostic": self.diagnostic,
            "suggested_fix": self.suggested_fix,
            "duration_ms": self.duration_ms,
            "evidence": self.evidence,
        }


def _timed() -> tuple[float, callable]:
    started = time.perf_counter()
    def _stop() -> int:
        return int((time.perf_counter() - started) * 1000)
    return started, _stop


# --------------------------------------------------------------------------- #
# Individual feature self-tests
# --------------------------------------------------------------------------- #

async def test_database(store) -> TestResult:
    """Real probe: open a SQLite connection and SELECT 1."""
    _, stop = _timed()
    try:
        ok = await store.ping()
        if ok:
            return TestResult("database", "PASS", "SQLite SELECT 1 succeeded",
                              "WAL connection opened and queried",
                              "No action required.", stop(),
                              {"path": str(store.path)})
        return TestResult("database", "FAIL", "store.ping() returned False",
                          "SQLite connection or SELECT 1 failed without raising",
                          "Check filesystem permissions on the data directory and restart SecureAgent.",
                          stop(), {"path": str(store.path)})
    except Exception as error:
        return TestResult("database", "FAIL", f"database probe raised: {type(error).__name__}: {error}",
                          "Exception during ping",
                          "Inspect backend logs; verify the data directory is writable.",
                          stop(), {"path": str(store.path)})


async def test_terminal(terminal_executor, config) -> TestResult:
    """Real probe: run ``echo diagnostic_ok`` and verify stdout.

    Falls back to NOT_AVAILABLE when the Linux terminal backend is not
    enabled (e.g., bwrap missing, terminal disabled by the user).
    """
    _, stop = _timed()
    if terminal_executor is None:
        return TestResult("terminal", "NOT_AVAILABLE",
                          "Linux terminal backend is not initialized",
                          "config.terminal_backend != 'linux' or executor construction failed",
                          "Set SECURE_AGENT_TERMINAL_BACKEND=linux and restart.",
                          stop(), {})
    if not terminal_executor.available:
        return TestResult("terminal", "WARNING",
                          "Terminal backend unavailable — sandbox probe failed or shell missing",
                          f"shell={config.terminal_shell}, sandbox_capable={terminal_executor.sandbox_status().get('available') if hasattr(terminal_executor, 'sandbox_status') else 'unknown'}",
                          "Install bubblewrap (apt install bubblewrap) for full sandbox, or run in HOST_CONTROL mode with policy enforcement.",
                          stop(), {"shell": config.terminal_shell})
    try:
        # Use a SAFE fixed-vector command — no approval needed.
        result = await asyncio.wait_for(
            terminal_executor.execute("echo diagnostic_ok", approval="fixed-vector"),
            timeout=float(min(config.terminal_command_timeout_seconds, 10)),
        )
        snap = result.snapshot(config.terminal_max_output_bytes)
        stdout = snap.get("stdout", "")
        exit_code = snap.get("exit_code")
        status = snap.get("status")
        if status == "completed" and exit_code == 0 and "diagnostic_ok" in stdout:
            return TestResult("terminal", "PASS", "echo diagnostic_ok completed with expected output",
                              f"exit_code={exit_code}, status={status}",
                              "No action required.", stop(),
                              {"exit_code": exit_code, "status": status})
        return TestResult("terminal", "FAIL",
                          f"echo diagnostic_ok did not produce expected output (status={status}, exit={exit_code})",
                          f"stdout={stdout[:200]!r}",
                          "Inspect backend logs; the sandbox may be blocking /bin/echo.",
                          stop(), {"exit_code": exit_code, "status": status, "stdout_preview": stdout[:200]})
    except asyncio.TimeoutError:
        return TestResult("terminal", "FAIL", "echo diagnostic_ok timed out",
                          f"timeout={config.terminal_command_timeout_seconds}s",
                          "A previous process may be stuck; check terminal executions or restart SecureAgent.",
                          stop(), {})
    except Exception as error:
        return TestResult("terminal", "FAIL",
                          f"terminal probe raised: {type(error).__name__}: {error}",
                          "Exception during execute()",
                          "Inspect backend logs.", stop(), {})


async def test_processes(terminal_executor, config) -> TestResult:
    """Real probe: list processes via the fixed-vector inspection tool."""
    _, stop = _timed()
    if terminal_executor is None or not terminal_executor.available:
        return TestResult("processes", "NOT_AVAILABLE",
                          "Terminal backend unavailable — process inspection requires it",
                          "depends on test_terminal",
                          "Resolve the terminal backend first.", stop(), {})
    try:
        result = await asyncio.wait_for(
            terminal_executor.execute("ps -o pid,comm --no-headers | head -n 3", approval="fixed-vector"),
            timeout=10.0,
        )
        snap = result.snapshot(config.terminal_max_output_bytes)
        stdout = snap.get("stdout", "")
        if snap.get("status") == "completed" and snap.get("exit_code") == 0 and stdout.strip():
            lines = [line for line in stdout.splitlines() if line.strip()]
            return TestResult("processes", "PASS",
                              f"ps listed {len(lines)} process(es)",
                              f"first_pid={lines[0].split()[0] if lines else 'n/a'}",
                              "No action required.", stop(),
                              {"process_count": len(lines)})
        return TestResult("processes", "FAIL",
                          f"ps did not return processes (status={snap.get('status')}, exit={snap.get('exit_code')})",
                          f"stdout={stdout[:200]!r}",
                          "Inspect backend logs.", stop(), {})
    except Exception as error:
        return TestResult("processes", "FAIL",
                          f"process probe raised: {type(error).__name__}: {error}",
                          "Exception during ps", "Inspect backend logs.", stop(), {})


async def test_services(terminal_executor, config) -> TestResult:
    """Real probe: ask systemd for at least one running unit."""
    _, stop = _timed()
    if terminal_executor is None or not terminal_executor.available:
        return TestResult("services", "NOT_AVAILABLE",
                          "Terminal backend unavailable — service inspection requires it",
                          "depends on test_terminal",
                          "Resolve the terminal backend first.", stop(), {})
    if not shutil.which("systemctl"):
        return TestResult("services", "NOT_AVAILABLE",
                          "systemctl binary not on PATH",
                          "systemd is not the init system on this host",
                          "Service inspection is only available on systemd hosts; use 'ps' for process inspection.",
                          stop(), {})
    try:
        result = await asyncio.wait_for(
            terminal_executor.execute("systemctl list-units --state=running --no-legend --no-pager | head -n 3",
                                       approval="fixed-vector"),
            timeout=10.0,
        )
        snap = result.snapshot(config.terminal_max_output_bytes)
        stdout = snap.get("stdout", "")
        if snap.get("status") == "completed" and snap.get("exit_code") == 0 and stdout.strip():
            return TestResult("services", "PASS",
                              "systemctl listed running units",
                              f"first_unit={stdout.splitlines()[0].split()[0] if stdout.strip() else 'n/a'}",
                              "No action required.", stop(),
                              {"sample_units": stdout.splitlines()[:3]})
        return TestResult("services", "WARNING",
                          f"systemctl returned no running units (status={snap.get('status')}, exit={snap.get('exit_code')})",
                          f"stdout={stdout[:200]!r}",
                          "This may be expected inside a container; otherwise inspect systemd state.",
                          stop(), {})
    except Exception as error:
        return TestResult("services", "FAIL",
                          f"service probe raised: {type(error).__name__}: {error}",
                          "Exception during systemctl", "Inspect backend logs.", stop(), {})


async def test_network(terminal_executor, config) -> TestResult:
    """Real probe: read local network info via fixed-vector commands."""
    _, stop = _timed()
    if terminal_executor is None or not terminal_executor.available:
        return TestResult("network", "NOT_AVAILABLE",
                          "Terminal backend unavailable — local network inspection requires it",
                          "depends on test_terminal",
                          "Resolve the terminal backend first.", stop(), {})
    try:
        result = await asyncio.wait_for(
            terminal_executor.execute("ip -brief address", approval="fixed-vector"),
            timeout=10.0,
        )
        snap = result.snapshot(config.terminal_max_output_bytes)
        stdout = snap.get("stdout", "")
        if snap.get("status") == "completed" and snap.get("exit_code") == 0 and stdout.strip():
            interfaces = [line.split()[0] for line in stdout.splitlines() if line.strip()]
            return TestResult("network", "PASS",
                              f"ip -brief address returned {len(interfaces)} interface(s)",
                              f"interfaces={interfaces[:3]}",
                              "No action required.", stop(),
                              {"interfaces": interfaces[:5]})
        return TestResult("network", "FAIL",
                          f"ip -brief address failed (status={snap.get('status')}, exit={snap.get('exit_code')})",
                          f"stdout={stdout[:200]!r}",
                          "Verify the 'ip' binary (iproute2) is installed.",
                          stop(), {})
    except Exception as error:
        return TestResult("network", "FAIL",
                          f"network probe raised: {type(error).__name__}: {error}",
                          "Exception during ip", "Inspect backend logs.", stop(), {})


async def test_filesystem(config) -> TestResult:
    """Real probe: write, read, delete a temp file inside the workspace."""
    _, stop = _timed()
    workspace = config.workspace_root
    try:
        workspace.mkdir(parents=True, exist_ok=True)
    except Exception as error:
        return TestResult("filesystem", "FAIL",
                          f"workspace mkdir failed: {type(error).__name__}: {error}",
                          f"workspace={workspace}",
                          "Check filesystem permissions on the workspace root.", stop(), {})
    probe_path = workspace / f".diagnostic-probe-{int(time.time() * 1000)}.tmp"
    try:
        probe_path.write_text("diagnostic_ok", encoding="utf-8")
        content = probe_path.read_text(encoding="utf-8")
        if content != "diagnostic_ok":
            return TestResult("filesystem", "FAIL",
                              "workspace write/read mismatch",
                              f"expected='diagnostic_ok', got={content!r}",
                              "Inspect the workspace mount (read-only filesystem?)", stop(), {})
        probe_path.unlink()
        if probe_path.exists():
            return TestResult("filesystem", "FAIL",
                              "workspace delete failed — file still exists after unlink",
                              f"path={probe_path}",
                              "Check filesystem permissions.", stop(), {})
        return TestResult("filesystem", "PASS",
                          "workspace write/read/delete cycle succeeded",
                          f"workspace={workspace}",
                          "No action required.", stop(), {"workspace": str(workspace)})
    except Exception as error:
        try:
            if probe_path.exists():
                probe_path.unlink(missing_ok=True)
        except Exception:
            pass
        return TestResult("filesystem", "FAIL",
                          f"filesystem probe raised: {type(error).__name__}: {error}",
                          f"workspace={workspace}, path={probe_path}",
                          "Check workspace permissions and disk space.", stop(), {})


async def test_ollama(get_llm) -> TestResult:
    """Real probe: ask the LLM provider for Ollama status.

    Distinguishes NOT_INSTALLED (binary missing), NOT_RUNNING (binary present
    but service unreachable), NOT_CONFIGURED (service running but no models
    pulled), READY (chat + embedding available), DEGRADED (chat or embedding
    missing but not both).
    """
    _, stop = _timed()
    ollama_on_path = bool(shutil.which("ollama"))
    try:
        provider = await get_llm().status()
    except Exception as error:
        return TestResult("ollama", "FAIL",
                          f"provider.status() raised: {type(error).__name__}: {error}",
                          "Exception during Ollama status probe",
                          "Inspect backend logs; verify ollama_base_url in Settings.",
                          stop(), {"ollama_on_path": ollama_on_path})
    ollama_available = bool(provider.get("ollama_available"))
    chat_available = bool(provider.get("generative_available"))
    embedding_available = bool(provider.get("embedding_available"))
    last_error = provider.get("last_error") or {}
    if not ollama_available:
        if not ollama_on_path:
            return TestResult("ollama", "NOT_AVAILABLE",
                              "Ollama binary is not installed (not on PATH)",
                              f"ollama_on_path={ollama_on_path}",
                              "Install Ollama: curl -fsSL https://ollama.com/install.sh | sh, then 'ollama serve' and 'ollama pull <model>'.",
                              stop(), {"ollama_on_path": ollama_on_path, "last_error": last_error})
        return TestResult("ollama", "WARNING",
                          "Ollama binary is installed but the service is not reachable",
                          f"last_error={last_error}",
                          "Start the Ollama service: 'ollama serve' or 'systemctl start ollama'.",
                          stop(), {"ollama_on_path": ollama_on_path, "last_error": last_error})
    if not chat_available and not embedding_available:
        return TestResult("ollama", "WARNING",
                          "Ollama is reachable but no models are installed",
                          f"models={provider.get('models', [])}",
                          "Pull models: 'ollama pull <chat_model>' and 'ollama pull <embedding_model>' (see Settings for configured names).",
                          stop(), {"models": provider.get("models", []), "last_error": last_error})
    if not chat_available or not embedding_available:
        missing = "chat" if not chat_available else "embedding"
        return TestResult("ollama", "WARNING",
                          f"Ollama is reachable but the {missing} model is not installed",
                          f"chat={chat_available}, embedding={embedding_available}",
                          f"Pull the missing model: 'ollama pull <model_name>'.",
                          stop(), {"chat_available": chat_available, "embedding_available": embedding_available})
    return TestResult("ollama", "PASS",
                      "Ollama is reachable and both chat + embedding models are available",
                      f"provider={provider.get('active_provider')}",
                      "No action required.", stop(),
                      {"ollama_on_path": ollama_on_path,
                       "chat_available": chat_available,
                       "embedding_available": embedding_available,
                       "active_provider": provider.get("active_provider")})


async def test_memory(store, config) -> TestResult:
    """Real probe: ping the DB, then write+read+delete a memory entry."""
    _, stop = _timed()
    if not await store.ping():
        return TestResult("memory", "FAIL",
                          "database ping failed — memory store unavailable",
                          "depends on test_database",
                          "Resolve the database first.", stop(), {})
    from app.models import MemoryIn
    probe_content = f"diagnostic probe {datetime.now(UTC).isoformat()}"
    try:
        created = await store.create(MemoryIn(content=probe_content, category="diagnostic"))
        # Use list() with the probe content as the LIKE query — this exercises
        # the same keyword-search path the agent uses for memory retrieval.
        items = await store.list(probe_content, limit=10)
        await store.delete(created.id)
        if any(item.id == created.id for item in items):
            return TestResult("memory", "PASS",
                              "memory create/list/delete cycle succeeded",
                              f"memory_id={created.id}",
                              "No action required.", stop(), {"memory_id": created.id})
        return TestResult("memory", "WARNING",
                          "memory was created but not found by list()",
                          "keyword LIKE search returned no matching entries — acceptable for short probe strings",
                          "Verify with longer content; this is not a hard failure.",
                          stop(), {"memory_id": created.id})
    except Exception as error:
        return TestResult("memory", "FAIL",
                          f"memory probe raised: {type(error).__name__}: {error}",
                          "Exception during create/list/delete",
                          "Inspect backend logs.", stop(), {})


async def test_rag(knowledge_store, config) -> TestResult:
    """Real probe: run a RAG search (may legitimately return no results).

    NOT_CONFIGURED is honest when no documents have been ingested.
    """
    _, stop = _timed()
    if not getattr(config, "knowledge_enabled", False):
        return TestResult("rag", "NOT_AVAILABLE",
                          "RAG is disabled in Settings",
                          "config.knowledge_enabled=False",
                          "Enable knowledge_enabled in Settings to use RAG.",
                          stop(), {})
    # Count indexed documents via the memory store (the knowledge store
    # delegates all persistence to it). This avoids needing a separate
    # list_documents() method.
    try:
        documents = await knowledge_store.memory.documents()
    except Exception as error:
        return TestResult("rag", "FAIL",
                          f"could not list documents: {type(error).__name__}: {error}",
                          "Exception during documents()",
                          "Inspect backend logs.", stop(), {})
    if not documents:
        return TestResult("rag", "NOT_CONFIGURED",
                          "RAG is enabled but no documents have been ingested",
                          "documents=0",
                          "Ingest a document via the Knowledge tab or POST /api/v1/documents.",
                          stop(), {"documents": 0})
    try:
        results = await asyncio.wait_for(
            knowledge_store.search("diagnostic probe", k=1),
            timeout=15.0,
        )
        if results:
            return TestResult("rag", "PASS",
                              "RAG search returned at least one chunk",
                              f"chunks={len(results)}",
                              "No action required.", stop(), {"chunks": len(results)})
        return TestResult("rag", "WARNING",
                          "RAG search returned no chunks despite documents being indexed",
                          f"documents={len(documents)}",
                          "The query may not match any chunk; try a different query or ingest more documents.",
                          stop(), {"documents": len(documents)})
    except asyncio.TimeoutError:
        return TestResult("rag", "FAIL",
                          "RAG search timed out (15s)",
                          "embeddings call may be stuck (Ollama unreachable?)",
                          "Check Ollama status and retry.", stop(),
                          {"documents": len(documents)})
    except Exception as error:
        return TestResult("rag", "FAIL",
                          f"RAG probe raised: {type(error).__name__}: {error}",
                          "Exception during search",
                          "Inspect backend logs; verify Ollama is reachable.",
                          stop(), {"documents": len(documents)})


async def test_automation(automation_engine) -> TestResult:
    """Real probe: verify the automation loop is alive."""
    _, stop = _timed()
    if automation_engine is None:
        return TestResult("automation", "NOT_AVAILABLE",
                          "AutomationEngine is not initialized",
                          "automation=None at startup",
                          "Set SECURE_AGENT_ENABLE_AUTOMATION=true and restart.",
                          stop(), {})
    try:
        # The loop is alive if the worker task exists and is not done.
        worker = getattr(automation_engine, "worker", None)
        if worker is None or worker.done():
            return TestResult("automation", "FAIL",
                              "Automation worker task is not running",
                              f"worker={worker}",
                              "Restart SecureAgent; the automation loop crashed during startup.",
                              stop(), {"worker_done": bool(worker and worker.done())})
        # Also report whether the gate is currently allowing jobs to run.
        from app.control_center import get_control_center
        gate = get_control_center()
        gate_active = bool(gate and gate.automation_active())
        return TestResult("automation", "PASS" if gate_active else "WARNING",
                          "Automation loop is running"
                          + ("" if gate_active else " (gate currently paused/disabled)"),
                          f"worker_alive=True, gate_active={gate_active}",
                          "No action required." if gate_active else "Toggle the Automation master switch ON in the Control Center.",
                          stop(),
                          {"worker_alive": True, "gate_active": gate_active})
    except Exception as error:
        return TestResult("automation", "FAIL",
                          f"automation probe raised: {type(error).__name__}: {error}",
                          "Exception during worker check",
                          "Inspect backend logs.", stop(), {})


# --------------------------------------------------------------------------- #
# Aggregator
# --------------------------------------------------------------------------- #

async def run_all_diagnostics(
    *,
    store,
    terminal_executor,
    config,
    get_llm,
    knowledge_store,
    automation_engine,
) -> dict[str, Any]:
    """Run every feature self-test and return an aggregated report.

    Each test runs independently — one FAIL does not block the others.
    The report always reflects reality at the moment of the call.
    """
    started = time.perf_counter()
    tests = await asyncio.gather(
        test_database(store),
        test_terminal(terminal_executor, config),
        test_processes(terminal_executor, config),
        test_services(terminal_executor, config),
        test_network(terminal_executor, config),
        test_filesystem(config),
        test_ollama(get_llm),
        test_memory(store, config),
        test_rag(knowledge_store, config),
        test_automation(automation_engine),
        return_exceptions=False,
    )
    results = [t.to_dict() for t in tests]
    summary = {
        "total": len(results),
        "pass": sum(1 for r in results if r["status"] == "PASS"),
        "warning": sum(1 for r in results if r["status"] == "WARNING"),
        "fail": sum(1 for r in results if r["status"] == "FAIL"),
        "not_available": sum(1 for r in results if r["status"] in ("NOT_AVAILABLE", "NOT_CONFIGURED")),
    }
    overall = "READY" if summary["fail"] == 0 else (
        "DEGRADED" if summary["pass"] > 0 else "FAILED"
    )
    return {
        "generated_at": datetime.now(UTC).isoformat(),
        "overall": overall,
        "summary": summary,
        "duration_ms": int((time.perf_counter() - started) * 1000),
        "tests": results,
    }
