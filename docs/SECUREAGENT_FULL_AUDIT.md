# SecureAgent 1.3.4 — Full Codebase Audit

Audit date: 2026-10-02 · Auditor: automated pre-upgrade review (task 2 of the
SecureAgent hardening program). Every claim below was verified by reading the
source and by executing the existing validation suites on a clean checkout.

**Baseline verification (this checkout, Python 3.12.14 / Node 24 / npm 11):**

| Suite | Result |
|---|---|
| `python -m pytest -q backend/tests` | **113 / 113 passed** |
| `backend/scripts/security_smoke.py` | **PASS (14 checks)** |
| `backend/scripts/offline_acceptance.py` | **PASS** |
| `backend/scripts/security_hardening_source.py` | **PASS (5 checks)** |

---

## 1. Repository map

```
backend/            FastAPI backend (Python 3.11–3.14, no paid API dependency)
  app/main.py           HTTP API v1 (/api/v1), auth, rate limits, security headers
  app/agent.py          Planner → execute → observe → answer task loop
  app/agents.py         Manager/specialist/reviewer/security agent roles
  app/orchestration.py  /orchestrate entry + response typing
  app/llm.py            OllamaProvider + LocalCoreProvider fallback (FailoverProvider)
  app/tools/            Tool contract, fail-closed Registry, builtins, factory
  app/permissions.py    PermissionManager (runtime enable/approval policy)
  app/workspace.py      WorkspacePolicy — lexical + fs-level path boundary
  app/sandbox.py        Docker sandboxes (terminal + Python), sha256-pinned
  app/network_security.py  DNS-pinned fail-closed HTTP client
  app/security.py       redaction, rate limiter, request limits, logging
  app/memory.py         SQLite store: messages, memories, tasks, audit, schedules, documents
  app/automation.py     Scheduled-task engine (leases, approval gate)
  app/knowledge.py      RAG: parse → chunk → embed → cosine retrieval
  app/execution_registry.py  Live task cancellation registry
  app/migrations.py     Schema migrations 001–003
  tests/                113 pytest cases (API contract, security, pipeline)
  static/               Prebuilt dashboard bundle served at /
frontend/           React 19 + Vite + TypeScript dashboard source
desktop/            Electron shell (main, preload, IPC allowlist, services, tests)
scripts/            runtime_e2e.py
install.sh, serve.sh, run.sh, build-linux.sh, start-dev.sh, diagnose.sh, uninstall.sh
Dockerfile, docker-compose.yml, .github/workflows/source-validation.yml
```

## 2. Feature inventory and status

| Feature | Status | Files | Linux notes |
|---|---|---|---|
| FastAPI backend + auth + rate limits + security headers | Working | `backend/app/main.py`, `security.py` | Localhost bypass dev mode; token auth otherwise |
| Health/system/diagnostics endpoints | Working | `main.py` | No Linux-native detail (distro/kernel/tools) — gap |
| Ollama integration (status, models, test-chat/embed) | Working | `llm.py`, `main.py` | Loopback default; remote requires HTTPS+flag |
| Local deterministic fallback (no AI key) | Working | `llm.py` LocalCoreProvider | Arithmetic/files/time/text only |
| Planner→execute agent with bounded steps | Working | `agent.py`, `models.py` | Static plan; no mid-task re-plan — gap (see §4) |
| Approval flow (once/session scope) | Working | `agent.py`, `main.py` | Session grants TTL 30 min; no persistent grants — gap |
| Tool registry (fail-closed) + 15 tools | Working | `tools/base.py`, `factory.py`, `builtins.py`, `coding.py` | No platform field; no plugin loading — gap |
| Terminal tool (Docker-sandbox only) | Working, disabled by default | `tools/builtins.py` TerminalTool | **No Linux-native executor, no command classification, no sudo handling — primary gap** |
| Filesystem tools (workspace-confined) | Working | `builtins.py`, `workspace.py` | Strong boundary (no symlink/hardlink, O_NOFOLLOW) |
| Network policy (DNS-pinned client) | Working | `network_security.py` | Local vs external separation exists |
| Automation/schedules | Working | `automation.py`, `memory.py` | Approval gate enforced; leases |
| Memory (SQLite) | Working | `memory.py`, `memory_service.py` | Secret-shaped content rejected |
| Knowledge/RAG | Working | `knowledge.py` | PDF/DOCX/MD/TXT; embedding via Ollama |
| Audit log with redaction | Working | `memory.py`, `security.py` | Redaction covers key names + value patterns |
| Task manager + cancel | Working | `agent.py`, `execution_registry.py`, `main.py` | Real cancellation of live asyncio tasks |
| React dashboard (14 tabs) | Working | `frontend/src/App.tsx` | No terminal panel, no workflows, no simple/advanced mode — gap |
| Electron desktop shell | Working | `desktop/` | IPC allowlist; /health + /orchestrate fixed in 1.3.4 |
| Windows compatibility | Retained in source | platform-agnostic Python; `desktop/windows/` is Electron window UI (not OS-specific) | Not a Linux problem |
| Docs (README/INSTALL/API/SECURITY) | Present | root | Release report missing — gap |

## 3. Identified problems / gaps (drives the upgrade plan)

1. **No Linux-native terminal subsystem.** The only terminal tool executes
   argument vectors inside a pinned Docker image (`TERMINAL_SANDBOX_UNAVAILABLE`
   without Docker). On a plain Linux host the agent cannot run `uname`, `ss`,
   `systemctl`, etc. No command string classification exists, no risk tiers
   beyond tool-level risk, no sudo detection.
2. **No Command Safety Engine.** Tool risk is static metadata; a command's
   actual content (`rm -rf /` vs `ls -la`) is not classified.
3. **No deterministic security engine / one-click workflows.** The AI is the
   only interpreter of tool output; there is no System Audit, Network
   Discovery, Log Analysis, or File Security Audit workflow, and no report
   artifact with OBSERVED/INFERRED/RECOMMENDED labeling.
4. **No Linux auto-detection** (distro, kernel, arch, shell, tool availability).
5. **No persistent "Always allow" grants** (only once/session), no OFF/ASK/ALLOWED
   permission-center surface, no notifications endpoint.
6. **Frontend gaps:** no Terminal panel, no workflow launcher, no report viewer,
   no Simple/Advanced mode, no terminal history view.
7. **No plugin architecture**; tools are hard-wired in `factory.py`.
8. **ToolDef lacks platform metadata** so Linux-only tools can't be filtered.

Non-problems verified during audit: TODO/FIXME scan found **zero** markers in
`backend/app`, `frontend/src`, `desktop`; no mocked/stubbed success paths found
(disabled features return structured `*_DISABLED`/`*_UNAVAILABLE` codes, which
is the intended fail-closed behavior); dead code scan found none beyond the
documented `desktop/windows/` naming note; no Windows-only assumptions break
Linux (`PureWindowsPath` checks in `workspace.py` are defense-in-depth).

## 4. Architecture decisions for the upgrade (smallest correct change)

- Keep Registry/PermissionManager as the single enforcement points; add a
  **CommandPolicyEngine** *inside* the terminal executor so classification is
  defense-in-depth, not a bypass path.
- Add a **LinuxTerminalExecutor** (`subprocess` argument-array discipline,
  `/bin/bash -c` only for the user/AI-supplied command string, scrubbed env,
  cwd jail, wall-clock timeout, incremental output capture, cooperative
  cancel). Docker path remains available and default-off unchanged.
- Expose inspection tools (`inspect_process/network/services/system`,
  `get_environment_info`, `get_working_directory`, `list_directory`,
  `read_file`, `search_files`) that run **fixed** command arrays — they never
  interpolate AI input into shell.
- Two agent-facing tools: `terminal_execute` (SAFE/LOW only; structured
  `TERMINAL_APPROVAL_REQUIRED` otherwise) and `terminal_execute_approved`
  (requires the existing approval flow; classifier still blocks BLOCKED).
- Workflows are **deterministic Python** (SecurityEngine) invoked via API and
  optionally summarized by the LLM; findings labeled OBSERVED/INFERRED/RECOMMENDED.
- New SQLite tables via migration 004: `terminal_history`, `security_reports`,
  `permission_grants`.
- API additions are additive; existing contract v1.0.0 is preserved (additive
  optional fields only). Desktop IPC allowlist gains the new read-only routes.

## 5. Test requirements carried into implementation

Command classification (incl. injection/evasion negatives), path jail, timeout,
cancellation, output caps, sudo non-interactive behavior, secret redaction in
terminal history, workflow determinism, report schema, Linux detection on
non-Linux platforms (graceful NOT_AVAILABLE), permission grant lifecycle,
plugin manifest validation, and full existing-suite regression.
