# SecureAgent 2.0 — Real Local AI Security Agent

A real, reliable, usable local AI security agent for authorized Linux machines. SecureAgent 2.0 is a targeted improvement of 1.3.4 focused on **real execution, real backend integration, real Linux integration, and honest status reporting** — not an admin panel full of rules.

> **Principle**: REAL FEATURE > UI REPRESENTATION. If a UI says a feature is enabled, the backend must prove that the feature actually works. Never fake status.

---

## Quick start

```bash
# 1. Install Python deps
cd backend && pip install -r requirements.txt

# 2. (Optional) Install Ollama for generative AI
curl -fsSL https://ollama.com/install.sh | sh
ollama serve &
ollama pull llama3.2           # chat model
ollama pull nomic-embed-text   # embedding model

# 3. (Optional) Install bubblewrap for full terminal sandbox
sudo apt install bubblewrap    # Debian/Ubuntu/Kali

# 4. Start the backend
python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 5. Open the dashboard
#    Either visit http://127.0.0.1:8000 in a browser,
#    or launch the Electron desktop app (see desktop/).
```

---

## What's new in 2.0

| Area | Change |
|---|---|
| **Honesty** | Every `/health` field is now a real probe; new `/diagnostics` endpoint runs 10 real self-tests (database, terminal, processes, services, network, filesystem, ollama, memory, rag, automation) |
| **UX** | Single SAFE/ASSIST/CONTROL mode surface in the header — no need to understand the 13 underlying policy surfaces |
| **Emergency Stop** | Globally accessible STOP ALL button in the Dashboard header (was only in the Control Center) |
| **Live sync** | Dashboard refreshes immediately on Control Center changes via `onConfigSync` IPC |
| **Chat Stop** | Now cancels the backend task too (was misleading client-only abort) |
| **Terminal** | Wired to the real SSE stream endpoint (was 700ms polling); dead `confirmNeeded` branch removed |
| **Diagnostics tab** | New tab showing real verdicts (PASS/FAIL/WARNING/NOT_AVAILABLE) with reason + suggested fix for every feature |
| **Version** | Bumped to 2.0.0 |

See `docs/MIGRATION_1_3_TO_2_0.md` for the full migration guide.

---

## Architecture

```
┌───────────────────────────────────────────────────────────────────────┐
│  Electron desktop                                                     │
│  ├─ Control Center window  (policy authority, EMERGENCY STOP)          │
│  ├─ Dashboard window       (FastAPI-served React build)                │
│  └─ Launch window          (startup splash)                            │
└───────────────┬───────────────────────────────────────────────────────┘
                │  IPC (contextBridge, capability allowlist, onConfigSync)
                ▼
┌───────────────────────────────────────────────────────────────────────┐
│  FastAPI backend (2.0.0)                                              │
│  76 endpoints across: health, diagnostics, mode, auth, chat, agent,   │
│  memory, schedules, documents, settings, terminal, workflows, reports, │
│  permissions, notifications, config, emergency stop, audit,           │
│  filesystem, automation.                                              │
└───────────────┬───────────────────────────────────────────────────────┘
                │
        ┌───────┴────────┬──────────────┬──────────────┬──────────────┐
        ▼                ▼              ▼              ▼              ▼
   ControlCenter    Agent loop     Tool Registry   LinuxTerm     SecurityEngine
   (runtime policy) (real exec)    (fail-closed)   (bwrap jail)  (deterministic)
        │                │              │              │              │
        ▼                ▼              ▼              ▼              ▼
                     MemoryStore (SQLite, WAL) — real persistence
                     ├─ messages, memories, tasks, audit_logs
                     ├─ schedules, schedule_runs
                     ├─ documents, document_chunks (embeddings as JSON)
                     ├─ terminal_history, security_reports
                     └─ permission_grants
```

### SecureAgent 2.0 flow

```
USER REQUEST (chat / mode / quick action)
     ↓
INTENT PARSER (LLM via OllamaProvider, or LocalCore fallback)
     ↓
PLAN (pydantic-validated)
     ↓
TOOL SELECTION (Registry — fail-closed)
     ↓
RISK CHECK (terminal_policy 5-tier classifier + path enforcer + SSRF defense)
     ↓
AUTHORIZATION (Control Center gates + session/persistent grants)
     ↓
EXECUTION (real subprocess with timeout + cancellation)
     ↓
LIVE OUTPUT (SSE stream for terminal; polling for agent tasks)
     ↓
RESULT VALIDATION (pydantic output model + byte size check)
     ↓
RECOVERY / RETRY (bounded exponential backoff)
     ↓
FINAL RESPONSE (with evidence)
     ↓
AUDIT LOG (redacted, persisted, exportable)
```

---

## Key commands

```bash
# Start the backend
cd backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# Check health (real probes, version 2.0.0)
curl http://127.0.0.1:8000/api/v1/health | python -m json.tool

# Run full diagnostics (10 real self-tests)
curl http://127.0.0.1:8000/api/v1/diagnostics | python -m json.tool

# Check current mode (SAFE / ASSIST / CONTROL / CUSTOM)
curl http://127.0.0.1:8000/api/v1/mode

# Apply a mode preset
curl -X POST -H "Content-Type: application/json" -d '{"mode":"ASSIST"}' http://127.0.0.1:8000/api/v1/mode

# Emergency stop (cancels all tasks, kills terminal, pauses automation)
curl -X POST http://127.0.0.1:8000/api/v1/emergency-stop

# Resume from emergency
curl -X POST http://127.0.0.1:8000/api/v1/resume

# View audit trail
curl http://127.0.0.1:8000/api/v1/audit?limit=50 | python -m json.tool
```

---

## Testing

```bash
# Backend tests (402 pass, 0 fail, 31 skip with explicit
# "BLOCKED — environment requires bubblewrap" reasons where the full
# sandbox profile is unavailable)
cd backend && python -m pytest tests/ -q

# Frontend tests (12 pass, 0 fail) + typecheck/build
cd frontend && npm test && npm run build

# Desktop shell tests, including behavioral IPC trust-gate and
# orphaned-backend recovery tests (35 pass, 0 fail)
cd desktop && node --test tests/*.test.js

# Clean-start validation (9 YES, 0 NO)
python scripts/clean_start_validation.py

# E2E (backend) — 17 PASS / 12 BLOCKED / 0 FAIL; BLOCKED entries are the
# environment-limited features (bwrap, Ollama, Docker) reported honestly
python scripts/runtime_e2e.py
```

> The counts above are the numbers measured on the last verification run. If
> your run reports fewer passes, treat it as a regression, not as rounding.

On this engineering pass every visible feature was re-verified against the real backend, six real defects were found and fixed (two of which made the desktop Control Center / packaged app dead on arrival — see `docs/AUDIT_REPORT.md`), and live integration runs exercised the full pipeline (31/31 endpoint checks, 13/13 real-execution checks).

---

## Documentation

| Doc | Purpose |
|---|---|
| `docs/SECUREAGENT_2_AUDIT.md` | Full audit of the 1.3.4 codebase — what was real, what was broken, what changed |
| `docs/FEATURE_STATUS.md` | Feature matrix with verification evidence (VERIFIED / PARTIALLY VERIFIED / BLOCKED) |
| `docs/MIGRATION_1_3_TO_2_0.md` | Old setting → new setting mapping |
| `docs/TROUBLESHOOTING.md` | Common failures and real fixes |
| `docs/SECURITY.md` | Security model |
| `docs/SANDBOX_SECURITY_MODEL.md` | Bubblewrap sandbox details |
| `docs/CONFIGURATION_SOURCE_OF_TRUTH.md` | The 7 config sources and their precedence |
| `docs/LINUX_E2E_TEST_PLAN.md` | End-to-end test plan |
| `API.md` | API reference |
| `INSTALL_LINUX.md` | Linux installation guide |

---

## Status

**READY WITH EXPLICIT LIMITATIONS** — see `docs/RELEASE_READINESS.md` and `docs/AUDIT_REPORT.md`.

Verified for:
- All backend honesty fixes (real probes, no hardcoded "ok")
- Diagnostics endpoint (10 real self-tests) with honest FAIL/NOT_AVAILABLE verdicts
- SAFE/ASSIST/CONTROL mode surface, Emergency Stop / Resume cycle
- Frontend + desktop builds, behavioral IPC trust-gate tests, orphaned-backend recovery
- Live integration: task lifecycle, cancellation, permissions, audit, emergency stop, real terminal execution via HOST_CONTROL

Limitations (BLOCKED on environment, not on code — the app reports each of these honestly at runtime):
- Sandbox execution requires `bubblewrap` + unprivileged user namespaces (on Debian 13+ hosts where AppArmor restricts userns, see `docs/TROUBLESHOOTING.md`); RESTRICTED_AGENT fails closed with `LINUX_SANDBOX_UNAVAILABLE` and the policy engine offers HOST_CONTROL with explicit confirmation
- Ollama is not installed here (the system honestly reports `NOT_INSTALLED`/`NOT_AVAILABLE` and falls back to `LocalCore`, which never fabricates AI answers)
- Multi-agent delegation is wired, audited and fails closed, but a SUCCESSFUL
  end-to-end delegation needs Ollama: without it workers cannot reason, so runs
  end as `MULTI_AGENT_REVIEW_REJECTED` (the honest verdict, not a silent
  single-agent fallback)
- `memory.relevant()` is keyword-LIKE, not semantic (deferred)
- RAG embeddings are JSON-stored with O(n) cosine (deferred)
- `main.py` remains a large module (splitting deferred)

---

## Safety boundary

SecureAgent is intended for use on **your own authorized local Linux machines**. It implements defensive and administrative security functionality. It does NOT add malware, persistence intended to evade detection, credential theft, stealth mechanisms, destructive autonomous behavior, or unauthorized access. For security testing, an authorized target/context is required.

---

## License

See the project repository for license details.
