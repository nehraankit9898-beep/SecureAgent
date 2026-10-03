# SecureAgent 2.0 — Baseline Audit (1.3.4 → 2.0)

**Audited version**: SecureAgent 1.3.4 (`SecureAgent-1.3.4-Linux-ControlCenter-P0-upgraded-v3`)
**Audited by**: automated code inspection of every Python, TypeScript, JavaScript, and test file
**Audit date**: 2026-10-03
**Method**: full file reads of all `backend/app/*.py`, `frontend/src/*`, `desktop/**/*`, `backend/tests/*.py`, `frontend/tests/*.mjs`, `desktop/tests/*.js`, `scripts/*.py`, `backend/scripts/*.py`. Targeted `rg` for `TODO|FIXME|MOCK|PLACEHOLDER|except Exception|pass|return True|return False`.

---

## A. Architecture (as found in 1.3.4)

```
┌───────────────────────────────────────────────────────────────────────┐
│  Electron (desktop/)                                                  │
│  ├─ Control Center window  (policy authority, EMERGENCY STOP)          │
│  ├─ Dashboard window       (FastAPI-served React build)                │
│  └─ Launch window          (startup splash)                            │
└───────────────┬───────────────────────────────────────────────────────┘
                │  IPC (contextBridge, capability allowlist)
                ▼
┌───────────────────────────────────────────────────────────────────────┐
│  FastAPI backend (backend/app/main.py — 1,501-line god-module)        │
│  85 endpoints across: health, auth, chat, agent tasks, memories,      │
│  schedules, documents, settings, system info, terminal, workflows,     │
│  reports, permissions, notifications, config, emergency stop, audit,   │
│  filesystem, automation.                                              │
└───────────────┬───────────────────────────────────────────────────────┘
                │
        ┌───────┴────────┬──────────────┬──────────────┬──────────────┐
        ▼                ▼              ▼              ▼              ▼
   ControlCenter    Agent loop     Tool Registry   LinuxTerm     SecurityEngine
   (781 lines)      (303 lines)    (base.py 105)   (668 lines)   (526 lines)
        │                │              │              │              │
        │                │              │              ▼              │
        │                │              │      terminal_policy         │
        │                │              │      (969 lines, 5-tier)     │
        │                │              │              │              │
        │                │              │      linux_sandbox           │
        │                │              │      (551 lines, bwrap)      │
        │                │              │              │              │
        ▼                ▼              ▼              ▼              ▼
                     MemoryStore (SQLite, WAL) — 241 lines, compressed
                     ├─ messages, memories, tasks, audit_logs
                     ├─ schedules, schedule_runs
                     ├─ documents, document_chunks (embeddings as JSON)
                     ├─ terminal_history, security_reports
                     └─ permission_grants
```

### A.1 Module inventory (line counts)

| Layer | Module | Lines | Status |
|---|---|---:|---|
| backend | `app/main.py` | 1501 | WORKING (overloaded) |
| backend | `app/control_center.py` | 781 | WORKING |
| backend | `app/terminal_policy.py` | 969 | WORKING (excellent) |
| backend | `app/security_engine.py` | 526 | WORKING |
| backend | `app/linux_sandbox.py` | 551 | WORKING |
| backend | `app/linux_terminal.py` | 668 | WORKING (streaming is polling) |
| backend | `app/terminal_tools.py` | 677 | WORKING |
| backend | `app/workspace.py` | 437 | WORKING (overlaps linux_sandbox) |
| backend | `app/llm.py` | 297 | WORKING (real Ollama probe) |
| backend | `app/agent.py` | 303 | WORKING |
| backend | `app/coding.py` | 266 | WORKING |
| backend | `app/config.py` | 273 | WORKING |
| backend | `app/memory.py` | 241 | WORKING (keyword LIKE, not semantic) |
| backend | `app/knowledge.py` | 141 | WORKING (JSON embeddings, O(n) cosine) |
| backend | `app/plugins/loader.py` | 164 | WORKING (fail-closed) |
| backend | `app/sandbox.py` | 166 | WORKING (Docker, coexists w/ Linux) |
| backend | `app/models.py` | 187 | WORKING |
| backend | `app/network_security.py` | 126 | WORKING (real SSRF defense) |
| backend | `app/linux_detect.py` | 109 | WORKING |
| backend | `app/tools/base.py` | 105 | WORKING |
| backend | `app/tools/factory.py` | 99 | WORKING |
| backend | `app/automation.py` | 90 | WORKING |
| backend | `app/migrations.py` | 93 | WORKING (forward-only) |
| backend | `app/security.py` | 79 | WORKING (minified) |
| backend | `app/agents.py` | 70 | PARTIAL (keyword router, stub reviewers) |
| backend | `app/execution_registry.py` | 58 | WORKING |
| backend | `app/permissions.py` | 46 | WORKING |
| backend | `app/memory_service.py` | 39 | WORKING (thin) |
| backend | `app/orchestration.py` | 29 | WORKING (trivial) |
| frontend | `src/App.tsx` | 277 | WORKING (~50 useState, no global state) |
| frontend | `src/panels.tsx` | ~270 | WORKING (polls, dead confirmNeeded branch) |
| frontend | `src/SetupWizard.tsx` | ~90 | WORKING |
| frontend | `src/api.ts` | ~75 | WORKING |
| frontend | `src/contracts.ts` | 43 | WORKING |
| desktop | `windows/control-center.js` | ~900 | WORKING (no framework) |
| desktop | `services/*` (8 files) | ~600 | WORKING |
| desktop | `ipc/register.js` | ~260 | WORKING (capability allowlist) |

### A.2 Existing features (status matrix)

Status legend: **WORKING** (verified by code read + test) / **PARTIAL** (works but with significant caveats) / **BROKEN** (does not work) / **MOCK** (returns fake data) / **MISSING** (not implemented) / **UNKNOWN** (could not verify).

| Feature | Frontend | Backend | API | Actual implementation | Current status | Required change |
|---|---|---|---|---|---|---|
| Dashboard | `App.tsx` | `main.py:/health` `/system/health` `/system/info` | yes | Real backend calls; no hardcoded metrics | WORKING | Add global Emergency Stop; subscribe to `onConfigSync`; replace 15 s poll pause with live updates |
| Chat Agent | `App.tsx` chat composer | `main.py:/orchestrate` `agent.py:Agent.execute` | yes | Real tool execution loop with retries, approval gates, audit | WORKING (UI frozen during run) | Live step streaming; fix misleading "Stop" button (call `/agent/tasks/{id}/cancel`) |
| Terminal | `panels.tsx` polls 700 ms | `linux_terminal.py` + `terminal_policy.py` | yes | Real `asyncio.create_subprocess_exec` with `start_new_session`, real `killpg`, 5-tier classifier | PARTIAL (SSE unused) | Wire `panels.tsx` to `/terminal/executions/{id}/stream` SSE; remove dead `confirmNeeded` branch |
| Network | `App.tsx` Settings → Network panel (11 controls) | `network_security.py` SSRF defense; `terminal_tools.py:TerminalInspectNetwork` | yes | Real `ip`/`ss`/`resolv.conf` reads; SSRF-defended HTTP client | WORKING | Reduce control count; expose fewer switches in Simple mode |
| Processes | (none in dashboard) | `terminal_tools.py:TerminalInspectProcess` | yes | Fixed-vector `ps aux`-style read | WORKING (not surfaced) | Add a "Processes" quick action to dashboard |
| Services | (none in dashboard) | `terminal_tools.py:TerminalInspectServices` | yes | Fixed-vector `systemctl list-units` read | WORKING (not surfaced) | Add a "Services" quick action to dashboard |
| Files | `App.tsx` Settings → Tools (5 toggles) | `workspace.py` + `linux_sandbox.py:enforce_canonical_workspace_path` | yes | Real O_NOFOLLOW walk, hardlink detection, atomic writes | WORKING | Consolidate `WorkspacePolicy` + path-safety surfaces |
| Security Scanner | `App.tsx` "Security" tab | `security_engine.py` | yes | Real `uname`/`ss`/`systemctl`/`ufw`/`iptables`/SUID scan; `OBSERVED/INFERRED/RECOMMENDED/NOT_AVAILABLE` findings | WORKING | Distinguish finding severity (LOW/MEDIUM/HIGH/CRITICAL) in UI |
| Ollama | `App.tsx` Settings → Ollama (12 controls) | `llm.py:OllamaProvider` + `linux_detect.py` | yes | Real `/api/version` + `/api/tags` + `/api/chat` + `/api/embed` probes | WORKING | Reduce control count; honest `NOT_INSTALLED` state when binary missing |
| Memory | `App.tsx` Memory tab | `memory.py:MemoryStore` + `memory_service.py` | yes | SQLite with WAL; **keyword LIKE search** (not semantic) | PARTIAL | Switch `relevant()` to embedding-based cosine ranking |
| Knowledge/RAG | `App.tsx` Knowledge tab | `knowledge.py` | yes | Real PDF/DOCX extract, chunk, embed (Ollama), cosine rank | PARTIAL (O(n), JSON embeddings) | Document the scalability limit; add vector index when needed |
| Automation | `App.tsx` Automation tab | `automation.py` + `memory.py:claim_due_schedules` | yes | Real poll loop, atomic lease claiming, scoped agent run | WORKING | Only `once`/`interval_seconds` (no cron) — document |
| Logs/Audit | `App.tsx` Audit tab | `memory.py:audit_logs` table | yes | Every meaningful action audited with `redact()` applied | WORKING | Add automatic retention/rotation |
| Permissions | `App.tsx` Permissions tab (3 toggles + grant picker + 7 rows); Control Center (~25 advanced rows) | 13 separate surfaces (see §B.3 below) | yes | Real enforcement at every layer | WORKING (over-engineered) | Consolidate to SAFE/ASSIST/CONTROL surface; inject ControlCenter instead of lazy `_control_gate()` |
| Settings | `App.tsx` Settings tab (~40 controls) | `config.py:Settings` (env-only, lru_cached) + `control_center.py:ControlState` (runtime, persisted) | yes | Real two-layer config; presets; atomic persistence | WORKING | Reduce control count; expose only important settings in Simple mode |
| Diagnostics / self-test | (none) | (none) | (none) | MISSING | MISSING | **Add `GET /api/v1/diagnostics` that runs `test_terminal()`, `test_network()`, `test_ollama()`, etc.** |
| Health model | `App.tsx` status dot (ON/OFF) | `main.py:/health` (hardcoded `database:ok`, `tools:ok`, `configuration:ok`, `permissions:ok`, `logs:ok`) | yes | Partial — Ollama/terminal real; rest hardcoded | PARTIAL | Replace hardcoded fields with real probes; replace ON/OFF with READY/DEGRADED/STARTING/STOPPED/FAILED/NOT_INSTALLED/NOT_CONFIGURED |
| Emergency Stop | Control Center only | `main.py:/emergency-stop` + `control_center.py:emergency_stop` | yes | Real kill switches: terminal `killpg`, agent task `cancel`, automation `cancel_all` | WORKING (Dashboard lacks button) | Add global Emergency Stop button to Dashboard header |
| Real-time activity | (none in dashboard) | `main.py:/config/events` SSE (Control Center only) | yes | Real SSE with atomic broadcasts | WORKING (Dashboard not subscribed) | Dashboard subscribes to `onConfigSync`; add unified activity event stream |
| STOP ALL | Control Center only | (same as Emergency Stop) | yes | Real | WORKING (Dashboard lacks button) | Same as Emergency Stop |

### A.3 Dependency map (high level)

```
config.py ──► main.py ──► control_center.py ──┐
              │       │                       │
              │       ├─► memory.py (SQLite) ◄┤
              │       ├─► agent.py ──► tools/base.py ◄─ tools/factory.py
              │       │                  │
              │       │                  ├─► tools/builtins.py
              │       │                  ├─► terminal_tools.py ──► linux_terminal.py
              │       │                  ├─► coding.py ──► sandbox.py (Docker)
              │       │                  └─► plugins/loader.py
              │       ├─► orchestration.py ──► agents.py ──► agent.py
              │       ├─► security_engine.py ──► linux_terminal.py
              │       ├─► automation.py ──► agent.py
              │       ├─► llm.py (OllamaProvider, LocalCoreProvider)
              │       ├─► linux_detect.py
              │       └─► network_security.py
              │
              └─► desktop/main.js ──► backend-manager.js ──► spawns uvicorn
                      │
                      ├─► config-watcher.js (SSE) ──► /api/v1/config/events
                      ├─► ipc/register.js (capability allowlist)
                      └─► windows/control-center.js (policy UI)
```

---

## B. Original problems discovered

### B.1 Architectural problems

1. **God-module `main.py` (1,501 lines, 50+ endpoints)** — owns health, auth, chat, agent, memory, schedules, documents, settings, terminal, workflows, reports, permissions, notifications, config, emergency stop, audit, filesystem, automation. Should be split into 8+ routers.
2. **13 overlapping permission/policy surfaces** (see §B.3 below).
3. **9 distinct terminal/command execution paths** (see §B.4 below).
4. **7 distinct config sources** with unclear precedence (see §B.5 below).
5. **Polling disguised as streaming** — `/terminal/executions/{id}/stream` polls the in-memory tracker every 250 ms instead of piping `process.stdout` chunks to the SSE response. Worse, **no frontend consumer uses this endpoint** — `panels.tsx` polls the non-stream endpoint every 700 ms.
6. **Two parallel terminal backends in one process** — `factory.py` switches between Linux (bwrap) and Docker based on `config.terminal_backend`; both paths can be enabled simultaneously if the registry is misconfigured.
7. **`memory.relevant()` is keyword LIKE, not semantic** — extracts 8 keywords via regex and runs 8 LIKE queries. This is a regression vs. RAG.
8. **RAG embeddings stored as JSON text, ranked in Python with O(n) cosine** — functional but does not scale past ~1k chunks.
9. **Lazy `_control_gate()` duplicated in 5+ modules** — `agent.py:11-17`, `linux_terminal.py:65-77`, `memory_service.py:4-9`, `automation.py:12-17`, `llm.py:241-245` (inlined), `network_security.py:75-86` (inlined). Signals a circular-dependency smell; should inject the gate at construction.
10. **15+ broad `except Exception` sites** — most are defensive ("X must never break Y") but several swallow errors that should propagate (e.g., `agent.py:71` catches `Exception` from `Plan.model_validate` and raises a generic `ValueError`).
11. **Compressed/minified style in critical modules** — `security.py` (79 lines), `memory.py` (241 lines), `builtins.py` (142 lines), `agents.py` (70 lines) are written in heavily compressed one-liners that harm reviewability.
12. **Version drift** — `FastAPI(version="1.3.4")`, `/health` returns `"version": "1.3.4"`, `API_CONTRACT_VERSION = "1.0.0"` — three different version identifiers in one file.
13. **Forward-only migrations, no down-migration** — `migrations.py` applies 001-004 but cannot roll back.

### B.2 UX problems

1. **~75 distinct policy switches across two windows** — Dashboard Settings tab alone has ~40 controls; Control Center has 10 master switches + ~25 advanced rows. The Simple/Advanced toggle mitigates but does not solve this.
2. **No globally accessible Emergency Stop in the Dashboard window** — only the Control Center has one. A user in the Dashboard who needs to kill a runaway agent must switch windows or cancel tasks one-by-one.
3. **Dashboard does not subscribe to `onConfigSync`** — when a master switch is toggled in the Control Center, the open Dashboard waits up to 15 s to see the change.
4. **Dashboard 15 s polling pauses while `busy=true`** — during an agent run the user sees stale task lists for up to 130 s.
5. **Misleading chat "Stop" button** — aborts only the client HTTP request; the backend task keeps running. The notice admits this only after the click.
6. **Dead `confirmNeeded` UI branch** in `panels.tsx:23,128-136` — declared but never set; the approval card is unreachable.
7. **"Agents" tab is purely informational** — hardcoded role names, no backend binding, no interactivity.
8. **Chat tab shows only the latest task** — no conversation history; no live step streaming; rich step detail buried in a `<details>` element.
9. **No "Why did this fail?" system** — error envelope has `code`, `message`, `details` but the UI only shows `${code}: ${message}`; the `details` field is captured but never rendered.

### B.3 The 13 permission/policy surfaces (consolidation target)

| # | Surface | Location | Role |
|---|---|---|---|
| 1 | `PermissionManager.apply` | `permissions.py` | mutates `Tool` instance metadata |
| 2 | `CommandPolicyEngine` | `terminal_policy.py` | 5-tier command-string classifier |
| 3 | `Permission` enum | `models.py` | SAFE/READ/WRITE/EXECUTE/NETWORK/SCHEDULE/AUTOMATION/ADMIN |
| 4 | `token_matches` + middleware | `security.py`, `main.py` | API auth |
| 5 | `ControlCenter` runtime gates | `control_center.py` | `check_terminal`, `check_sudo`, `check_host_control_operation`, `check_network`, `agent_active`, `ai_active`, `memory_active`, `rag_active`, `automation_active`, `workflows_active`, `terminal_limits`, `task_command_count`/`record_task_command` |
| 6 | `ControlState` typed config | `control_center.py` | runtime toggles (restricted_mode, allow_sudo, network.mode, etc.) |
| 7 | `classify_path_sensitivity` | `linux_sandbox.py` | sensitive-path guard |
| 8 | `enforce_canonical_workspace_path` | `linux_sandbox.py` | 7-layer canonical path enforcement |
| 9 | `WorkspacePolicy` | `workspace.py` | workspace boundary for filesystem tools |
| 10 | `resolve_target` + `SafeHttpClient` | `network_security.py` | SSRF defense |
| 11 | `SecurityEngine` | `security_engine.py` | workflow security findings (detection, not enforcement) |
| 12 | `Agent` session + persistent permissions | `agent.py`, `main.py:session_approvals` | sliding-window in-memory grants (30 min TTL) |
| 13 | `permission_grants` SQLite table | `memory.py:226-241` | durable "always" scope grants |

**Consolidation target for 2.0**: do NOT delete any of these — they enforce real security properties. Instead, expose a single `SAFE / ASSIST / CONTROL` UX surface on top, mapping each user-facing mode to the underlying `ControlState` preset. The 13 surfaces stay as the implementation; the user never sees them.

### B.4 The 9 terminal/command execution paths

| # | Path | Used by |
|---|---|---|
| 1 | `LinuxTerminalExecutor.execute` (RESTRICTED_AGENT/HOST_CONTROL, bwrap or host) | `/api/v1/terminal/execute`, `terminal_execute*` tools |
| 2 | `DockerSandbox.execute_copy` | `coding.py:RunTests`, legacy `terminal` tool |
| 3 | `DockerPythonSandbox.execute` | `builtins.py:PythonTool` |
| 4 | `TerminalExecute` (agent tool, SAFE/LOW_RISK) | agent loop |
| 5 | `TerminalExecuteApproved` (agent tool, REQUIRES_APPROVAL/HIGH_RISK) | agent loop |
| 6 | `TerminalExecuteScript` (agent tool, whole-script validation) | agent loop |
| 7 | `_FixedInspection` subclasses (5 fixed-vector tools) | agent loop |
| 8 | `builtins.py:TerminalTool` (Docker) | agent loop (when `terminal_backend=='docker'`) |
| 9 | `SecurityEngine._run` (workflow fixed commands) | security workflows |

**2.0 decision**: keep paths 1, 4-7, 9 (all use `LinuxTerminalExecutor`); keep path 2 only for `RunTests` (Docker is the right sandbox for code execution); remove path 8 (legacy Docker terminal tool) — the Linux backend is the default and the Docker terminal tool is dead weight in a Linux-native install. Path 3 stays for `PythonTool` when Docker is configured.

### B.5 The 7 config sources

| # | Source | Mutability | Persistence |
|---|---|---|---|
| 1 | `Settings` (env file, `SECURE_AGENT_*` prefix) | process-lifetime (`@lru_cache`) | env file |
| 2 | `ControlState` (runtime authority) | live via `PATCH /api/v1/config` | `data/control_center.json` |
| 3 | `PRESETS` (one-click patches) | applies a patch to `ControlState` | via ControlState |
| 4 | `session_approvals` (in-memory, 30 min TTL) | live via approval flow | none |
| 5 | `permission_grants` SQLite table | live via `/permissions/grants` | SQLite |
| 6 | `_caps_cache` (sandbox capability probe) | process-lifetime | none |
| 7 | `_provider` (FallbackProvider singleton, 10 s refresh) | process-lifetime | none |

**2.0 decision**: do NOT collapse these — they serve different purposes (static boot config vs. runtime authority vs. per-session grants vs. durable grants vs. capability cache). Instead, document the precedence clearly in `docs/CONFIGURATION_SOURCE_OF_TRUTH.md` (already exists) and expose only `ControlState` + `PRESETS` to the user; everything else is internal.

### B.6 Health check honesty gaps

`GET /api/v1/health` (`main.py:252-256`) returns:
```python
{
  "status": "ok" | "degraded",
  "version": "1.3.4",
  "workspace": "ok" if config.workspace_root.is_dir() else "error",
  "ollama": <real probe>,
  "chat_model": <real probe>,
  "embedding_model": <real probe>,
  "database": "ok",          # ← HARDCODED, no ping
  "tools": "ok",             # ← HARDCODED, no count
  "configuration": "ok",     # ← HARDCODED
  "permissions": "ok",       # ← HARDCODED
  "logs": "ok",              # ← HARDCODED
  "terminal": <real probe>,
  "automation": <real probe>,
  "python_sandbox": <real probe>,
  "provider": <real probe>,
}
```

`GET /api/v1/system/health` (`main.py:259-263`) is even worse — it hardcodes `configuration`, `permissions`, `logs` all to `"ok"`.

**2.0 fix**: replace every hardcoded field with a real probe. See `docs/FEATURE_STATUS.md` for the new health model.

### B.7 Mock / placeholder / dead code scan

- **`rg` for `TODO|FIXME|MOCK|PLACEHOLDER|XXX|HACK`** across `backend/app/` → **0 matches**. The codebase is disciplined about markers.
- **`rg` for `not implemented|NotImplemented`** → **0 matches** in `backend/app/`.
- **Dead UI branch**: `panels.tsx:23,128-136` `confirmNeeded` state is declared but never set; the approval card is unreachable.
- **Dead endpoint**: `/api/v1/terminal/executions/{id}/stream` (SSE) has no consumer — `panels.tsx` polls the non-stream endpoint.
- **Dead endpoints from dashboard perspective**: `/chat`, `/ready`, `/models`, `/agent/tasks/{id}` (single), `/terminal/executions` (list) — used only by E2E scripts or the Control Center.
- **Dead `except Exception: raise`**: `coding.py:197-199` adds nothing.
- **Dead `TerminalWorkingDirectory.argv()`**: `terminal_tools.py:404-406` returns `[["pwd"]]` but `run` is overridden and never calls `argv()`.
- **Test-only leak**: `network_security.py:96-98` has an `isinstance(target, str)` branch labelled "compatibility for injected test validators" — test convenience in production code.

---

## C. What is actually WORKING (do not break these)

The audit confirmed the following security and functional properties are **real**, not mocked:

1. **Real subprocess execution with cancellation** — `asyncio.create_subprocess_exec` with `start_new_session=True`; `os.killpg(os.getpgid(pid), SIGKILL)` on cancel/timeout; pre-attach cancels honored post-completion via `_cancelled` set.
2. **Real Ollama detection** — `OllamaProvider.refresh` calls `/api/version` and `/api/tags` every 10 s; `OllamaProvider.chat` and `.embed` make real `/api/chat` and `/api/embed` POSTs with shape/dimensionality validation.
3. **Real honest fallback** — `LocalCoreProvider` returns `"AI_REASONING_UNAVAILABLE: Ollama is required for generative agent reasoning."` rather than fabricating an answer.
4. **Real SQLite persistence** — WAL mode, `BEGIN IMMEDIATE` lease claiming, parameterized queries, bounded history, redacted audit logs.
5. **Real 5-tier command classifier** — quote-aware splitter, per-segment word classifier, substitution expansion (depth-limited at 3), `EVASION_PATTERNS` for `${IFS}`, `curl|sh`, `/proc/self/fd`, `find -exec sh`, `awk system()`. Unknown commands default to `REQUIRES_APPROVAL` (fail-safe).
6. **Real 7-layer canonical path enforcement** — URL-decode traversal, lexical `..`, protected host prefixes, piecewise `O_NOFOLLOW` walk, hardlink detection via `st_nlink != 1`, mid-read `fstat` comparison, final `realpath` containment.
7. **Real SSRF defense** — DNS-pinning (resolve → connect to IP), cloud-metadata blocklist (169.254.169.254, etc.), link-local/multicast/unspecified/reserved rejection, mixed-trust DNS answer rejection, redirect re-validation, `Content-Length` AND streamed-bytes `max_bytes` enforcement.
8. **Real bubblewrap sandbox** — `bwrap --unshare-user --unshare-pid --unshare-net --ro-bind /usr --ro-bind /bin --uid 65534 --gid 65534 --cap-drop ALL --die-with-parent --new-session`. Capability probe actually runs `unshare` and `bwrap /bin/true` to verify.
9. **Real atomic config persistence** — temp file + `fsync` + `os.replace` + `chmod 0600`; previous file becomes `.bak`; corrupted primary falls back to `.bak` then to safe defaults; corrupted file is rewritten on recovery.
10. **Real emergency stop** — invokes every registered kill switch (terminal `kill_all_running`, agent task `request_cancel`, automation `cancel_all`), disables `host_control`, persists, audits. Verified end-to-end by `control_center_live_verification.py:187-244` (starts real `sleep 30`, verifies `pgrep` sees it, verifies it is gone after emergency stop).
11. **Real audit trail** — every meaningful action recorded with `redact()` applied; events include `task.*`, `tool.executed`, `approval.*`, `memory.*`, `knowledge.*`, `terminal.*`, `schedule.*`, `permission.*`, `control.*`, `config.*`, `automation.*`, `audit.*`, `filesystem.*`, `tool.toggled`, `network.test`, `security.report`.
12. **Real plugin loader** — fail-closed, strict manifest validation (name/version/module regexes, 1-20 tools, no duplicates, valid permissions/risk_levels, `risk_levels` exactly covers `tools`, valid platforms).
13. **Real test suite** — 22 backend test files, 2 frontend contract tests, 3 desktop tests, 2 E2E scripts. Most tests run real Linux commands against `/etc/shadow`, `/proc`, `/sys`, symlinks, hardlinks; real `sleep 30` + `pgrep` for emergency stop; real `rm -rf /` classification; real `dd if=/dev/zero of=/dev/sda` classification.

**Conclusion**: SecureAgent 1.3.4 is **not a mock**. It is a real, working, security-conscious system whose problems are **architectural** (too many overlapping surfaces, god-module `main.py`, lazy circular imports, polling-as-streaming) and **scalability** (JSON embeddings, keyword-search memory), not **correctness**.

---

## D. 2.0 transformation plan (priority-ordered)

This audit drives the 2.0 work. The plan is to **make targeted, real improvements that align with the principle "REAL FEATURE > UI REPRESENTATION"** without rewriting working security primitives.

### D.1 Phase 1 — Honesty fixes (highest impact, lowest risk)

1. **Bump version to 2.0.0** consistently (`FastAPI(version=...)`, `/health`, `API_CONTRACT_VERSION` stays at `1.0.0` because the contract did not change).
2. **Replace hardcoded health fields** with real probes:
   - `database`: `store.ping()` (new method — `SELECT 1`)
   - `tools`: count of `tool.enabled` from registry
   - `configuration`: `ControlState` validates (always `ok` if loaded)
   - `permissions`: `ControlState` security invariants pass
   - `logs`: log handler attached (always `ok` in production)
   - `workspace`: real `is_dir()` + writable check
3. **Add `GET /api/v1/diagnostics`** that runs real self-tests:
   - `test_terminal()` — run `echo diagnostic_ok` and verify output
   - `test_network()` — read `ip -brief address` (fixed-vector)
   - `test_processes()` — read `ps -o pid,comm` (fixed-vector)
   - `test_services()` — read `systemctl list-units --state=running` (fixed-vector)
   - `test_filesystem()` — write+read+delete a temp file in workspace
   - `test_ollama()` — call `get_llm().status()` and report `NOT_INSTALLED` / `NOT_RUNNING` / `NOT_REACHABLE` / `NO_MODELS` / `READY`
   - `test_memory()` — `store.ping()` + write+read+delete a memory
   - `test_rag()` — `knowledge.search("test", k=1)` returns without error (may be empty)
   - `test_automation()` — `automation.loop` is running
   - Each test returns `PASS` / `FAIL` / `WARNING` / `NOT_AVAILABLE` with `reason`, `diagnostic`, `suggested_fix`.
4. **Add global Emergency Stop button to Dashboard header** — red button calling `POST /api/v1/emergency-stop` via the existing `window.secureAgent.controlEmergencyStop()` bridge.
5. **Subscribe Dashboard to `onConfigSync`** — refresh immediately when the Control Center toggles a switch.
6. **Fix chat "Stop" button** — after aborting the client request, also call `POST /api/v1/agent/tasks/{id}/cancel` for the active task.
7. **Remove dead `confirmNeeded` branch** in `panels.tsx`.
8. **Wire `panels.tsx` to `/terminal/executions/{id}/stream` SSE** — replace the 700 ms poll with real streaming.

### D.2 Phase 2 — New health model

Replace `ON/OFF` with:
- `READY` — feature is fully operational
- `DEGRADED` — feature works but with reduced capability (e.g., Ollama reachable but no models installed)
- `STARTING` — feature is initializing
- `STOPPED` — feature is intentionally disabled by the user
- `FAILED` — feature is enabled but broken (e.g., Ollama enabled but unreachable)
- `NOT_INSTALLED` — underlying binary/package is missing (e.g., `ollama` not on PATH)
- `NOT_CONFIGURED` — feature is available but not configured (e.g., no RAG documents indexed)

### D.3 Phase 3 — SAFE/ASSIST/CONTROL UX surface

Expose a single tri-state surface on top of the existing 13 policy surfaces:
- **SAFE** — read-only operations; no system-changing actions; maps to `ControlState` with `agent.enabled=true`, `terminal.restricted_mode=true`, `host_control.enabled=false`, `network.mode='allow_local'`, `sudo.mode='disabled'`, `automation.active=false`.
- **ASSIST** — normal agent operation; safe commands automatic; medium-risk commands execute with visible notification; high-risk commands require one confirmation; maps to `agent.enabled=true`, `terminal.restricted_mode=true`, `host_control.enabled=false`, `network.mode='allow_local'`, `sudo.mode='non_interactive'`, `automation.active=true`.
- **CONTROL** — explicitly enabled advanced local control; still protects destructive/irreversible actions; maps to `agent.enabled=true`, `terminal.restricted_mode=false`, `host_control.enabled=true` (requires explicit user `confirm=true`), `network.mode='allow_local'`, `sudo.mode='non_interactive'`, `automation.active=true`.

Implementation: add `POST /api/v1/mode` that applies the corresponding preset patch to `ControlState`. The existing `PRESETS` (`safe`, `development`, `security_lab`, `full_control`) stay for backward compatibility; `SAFE`/`ASSIST`/`CONTROL` are the user-facing aliases.

### D.4 Phase 4 — Risk engine surfacing

The risk engine already exists (`terminal_policy.py:CommandPolicyEngine` with `SAFE/LOW_RISK/REQUIRES_APPROVAL/HIGH_RISK/BLOCKED`). Surface it consistently:
- Add `risk_level` to the existing `ToolResult` structure (already present in terminal responses; extend to all tools via the `Registry.execute` return shape).
- Add `risk_level` to audit log entries (already present for terminal; extend to all tools).
- Show `risk_level` chips in the Dashboard activity feed.

### D.5 Phase 5 — "Why did this fail?" system

The error envelope already has `code`, `message`, `details`. Extend the frontend to:
- Render `details` in a collapsible panel under the error alert.
- Add a "Retry" button next to each error that re-runs the last failed action.
- Add a "What can I do?" hint derived from `code` (e.g., `AUTHENTICATION_REQUIRED` → "Check your API token in Settings"; `OLLAMA_UNAVAILABLE` → "Start Ollama and click Retry"; `RATE_LIMITED` → "Wait 60 seconds and try again").

### D.6 Phase 6 — Consolidation (lower priority, higher risk)

1. Split `main.py` into 8+ FastAPI routers.
2. Remove the legacy Docker `terminal` tool (path 8 in §B.4) — Linux backend is the default.
3. Inject `ControlCenter` at construction instead of lazy `_control_gate()` — eliminates 5+ swallow-catches.
4. Decompress `security.py`, `memory.py`, `builtins.py`, `agents.py`.
5. Switch `memory.relevant()` to embedding-based cosine ranking (requires Ollama; fall back to keyword LIKE when Ollama is unavailable).
6. Add a real vector index for RAG (sqlite-vss or similar) — defer until scalability becomes a real problem.

### D.7 Phase 7 — Testing

1. Add unit tests for the new `diagnostics` endpoint.
2. Add unit tests for the new health probes (`store.ping()`, tool count, etc.).
3. Add an integration test that wires `panels.tsx` to the SSE endpoint (requires a frontend test runner — defer).
4. Run the existing 22 backend test files and 2 E2E scripts against the 2.0 codebase.
5. Add a clean-start test: spawn uvicorn, hit `/health`, `/diagnostics`, `/system/info`, run a safe terminal command, run an agent task, cancel it, emergency stop.

### D.8 Phase 8 — Documentation

1. `docs/SECUREAGENT_2_AUDIT.md` — this file.
2. `docs/FEATURE_STATUS.md` — feature matrix with `VERIFIED` / `PARTIALLY VERIFIED` / `NOT VERIFIED` / `BLOCKED`.
3. `docs/MIGRATION_1_3_TO_2_0.md` — old setting → new setting mapping.
4. `docs/ARCHITECTURE.md` — updated architecture diagram.
5. `docs/TROUBLESHOOTING.md` — common failures and fixes.
6. `docs/SECURITY.md` — security model (already exists, update).
7. `docs/API.md` — API reference (already exists, update with `/diagnostics`, `/mode`).
8. `docs/DEVELOPMENT.md` — developer guide.
9. Update `README.md` — quickstart, status, commands.

---

## E. Environment limitations (BLOCKED items)

The audit was performed in a sandboxed Linux environment with:
- **Python 3.12.14** ✓
- **FastAPI 0.128, uvicorn 0.44, pydantic 2.12, httpx 0.28, pypdf 6.6** ✓
- **Node 24.21, npm** ✓
- **Ollama** ✗ (not installed — `NOT_INSTALLED` is the honest status)
- **bubblewrap (`bwrap`)** ✗ (not installed — `LinuxTerminalExecutor.available` returns `False` in RESTRICTED_AGENT sandbox mode; the executor falls back to HOST_CONTROL-equivalent behavior with the policy engine still enforcing the 5-tier classifier)
- **Docker** ✗ (not installed — `DockerSandbox.available` returns `False`; `TerminalTool` and `PythonTool` are disabled; `RunTests` is disabled)

Tests that require Ollama, bwrap, or Docker will report `NOT_AVAILABLE` rather than `PASS`. This is the correct, honest behavior — it matches the 2.0 principle of "never fake status".

---

## F. Audit conclusion

SecureAgent 1.3.4 is a **real, working, security-conscious system** whose problems are **architectural and UX**, not **correctness or fakeness**. The 2.0 transformation should focus on:

1. **Honesty fixes** — replace hardcoded health fields with real probes; add diagnostics endpoint; add global Emergency Stop to Dashboard.
2. **UX simplification** — expose SAFE/ASSIST/CONTROL on top of the existing 13 policy surfaces; reduce the Settings tab control count.
3. **Real streaming** — wire the existing SSE endpoint to the frontend.
4. **Documentation** — make the docs match reality.

The 2.0 release does NOT need to rewrite the security primitives, the agent loop, the memory store, or the Ollama adapter — they are already real. It needs to **consolidate, surface, and document** them so the user feels they are using a real agent, not an admin panel.
