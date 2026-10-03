# SecureAgent — Linux Release Report

Build: SecureAgent 1.3.4 + Linux terminal agent upgrade · Date: 2026-10-02
Verification host: Linux x86_64 (kernel 5.10.134), Python 3.12.14, Node 24.21,
Debian 13 (trixie) container · Ollama: not installed in CI (handled gracefully
by the deterministic Local Core — verified).

## 1. Verification matrix

| Suite | Command | Result |
|---|---|---|
| Backend tests (incl. 160 new security/terminal/workflow tests) | `python -m pytest -q backend/tests` | **273 / 273 PASS** |
| Security smoke | `python backend/scripts/security_smoke.py` | **PASS (14 checks)** |
| Source hardening scan | (run by security_smoke) | **PASS (5 checks)** |
| Offline acceptance | `python backend/scripts/offline_acceptance.py` | **PASS** |
| Cancellation smoke | `python backend/scripts/cancellation_smoke.py` | **PASS (2 checks)** |
| Runtime E2E (real loopback, machine-readable evidence) | `python scripts/runtime_e2e.py` | **17 PASS / 0 FAIL / 12 BLOCKED*** |
| Frontend contract tests | `npm --prefix frontend test` | **9 / 9 PASS** |
| Frontend typecheck / lint / build | `tsc -b`, lint.mjs, `vite build` | **PASS (7 source files)** |
| Desktop lifecycle/security tests | `node --test desktop/tests/*.test.js` | **17 / 17 PASS** |

\* "BLOCKED" items (Docker sandbox, Ollama, network search) are environment
dependencies that the build deliberately reports as structured
`*_UNAVAILABLE` / `*_DISABLED` states instead of faking success — see §4.

Live E2E performed against a running uvicorn instance (HTTP, not mocks):

- `/api/v1/health` → `terminal: available`
- `POST /terminal/execute` — safe command executed (real `uname -r` output),
  `rm -rf /` → 403 `TERMINAL_COMMAND_BLOCKED`, `systemctl restart nginx` → 403
  `TERMINAL_APPROVAL_REQUIRED`, confirmed write executed with `requires_approval`
  risk label, history + audit rows recorded.
- `POST /workflows/system_audit/run` on the live host → 23 deterministic
  checks, real findings (UID-0 accounts, listening sockets incl. exact
  wildcard listeners `0.0.0.0:19005`, `0.0.0.0:19006`, `*:81`), 1 honest
  `NOT_AVAILABLE`.
- Grants: created/revoked; `admin` grant refused with `GRANT_FORBIDDEN`.
- Dashboard bundle served from `backend/static` (synced build).

## 2. Feature status (FEATURE / STATUS / TEST / RESULT / LIMITATION)

| Feature | Status | Test | Result | Limitation |
|---|---|---|---|---|
| Full codebase audit doc | Implemented | manual + suites | PASS | — |
| Command Safety Engine (5-tier classification) | Implemented | `test_command_policy.py` (123 cases incl. injection/evasion negatives) | PASS | Static analysis; conservative false positives possible (documented in module docstring) |
| Linux terminal executor (`/bin/bash` jail, scrubbed env, output cap, timeout, cancel, process-group kill) | Implemented | `test_linux_terminal.py` (36 cases) | PASS | Output is polled snapshots, not byte-stream SSE |
| Sudo handling (non-interactive `sudo -n`, structured `SUDO_PASSWORD_REQUIRED`, passwords never collected) | Implemented | executor tests + live E2E | PASS | User must pre-authenticate sudo in their own terminal for passworded hosts |
| Agent terminal tools (`terminal_execute`, `terminal_execute_approved`, `terminal_execute_script`, 9 inspection tools, fixed argv) | Implemented | registry + approval-flow tests | PASS | Agent-driven planning needs Ollama (Local Core covers arithmetic/files/time/text only) |
| Terminal HTTP API + redacted history (SQLite) | Implemented | API tests + live E2E | PASS | History capped at `terminal_history_limit` rows |
| One-click workflows (system_audit, network_discovery, log_analysis, file_security_audit) | Implemented | engine tests + live host run | PASS | Root-only checks return `NOT_AVAILABLE`; no root bypass by design |
| Deterministic Security Engine (AI never sole authority) | Implemented | engine tests | PASS | — |
| Reports with OBSERVED/INFERRED/RECOMMENDED/NOT_AVAILABLE + download | Implemented | store/API tests, UI viewer | PASS | — |
| Linux auto-detection (distro/kernel/arch/shell/toolchain) | Implemented | API test + live E2E | PASS | Optional security tools (nmap/clamav/…) reported missing with install hints |
| Permission Center: OFF/ASK/ALLOWED surface, Allow once / task / always / Deny, admin refused | Implemented | grants API tests | PASS | "Allow for task" maps to existing task-scoped resume approval |
| Notifications (approvals, failures, Ollama down, failing automations, findings) | Implemented | API test | PASS | Derived on request; no push channel |
| Tool registry platform metadata (`platforms`) | Implemented | `/tools` live check | PASS | — |
| Plugin architecture with validated manifests | Implemented | loader tests (valid/invalid/disabled) | PASS | Ships with one disabled example plugin (`docker_info`) |
| Simple / Advanced UI mode | Implemented | typecheck/lint/build, manual | PASS | Mode stored in localStorage |
| Terminal UI (risk chip, live output, cancel/retry/copy/clear, searchable history) | Implemented | build + live | PASS | — |
| Workflows UI + report viewer | Implemented | build + live | PASS | — |
| Dashboard system status (backend/terminal/ollama/permissions/db/network/agent) | Implemented | health API test | PASS | — |
| Desktop IPC allowlist for new routes | Implemented | desktop tests | PASS | — |
| Existing features preserved (chat, tasks, memory, RAG, automation, Docker terminal, network policy) | Preserved | full regression (273/9/17) | PASS | Docker/Ollama paths need those services (reported BLOCKED when absent) |
| Secret redaction (audit logs, terminal output/history, agent-visible output) | Preserved + extended | redaction tests | PASS | Pattern-based; cannot catch novel formats |
| Task statuses | Existing set kept (`planning/running/waiting_confirmation/completed/failed/cancelled`) | regression | PASS | Spec's QUEUED/PAUSED map to `planning`/task-waiting; renaming would break the frozen v1 contract — documented instead |

## 3. Exact setup instructions

### 1) Install

```bash
cd SecureAgent
chmod +x *.sh
./install.sh --with-tests          # browser mode + tests
# or: ./install.sh --desktop       # + Electron app
```

Manual equivalent:

```bash
python3 -m venv .venv
.venv/bin/pip install -r backend/requirements.txt
cp .env.example .env
```

### 2) Start

```bash
./serve.sh                         # http://127.0.0.1:8000
# development alternative: ./start-dev.sh
```

### 3) Ollama setup (primary local AI; no paid API anywhere)

```bash
curl -fsSL https://ollama.com/install.sh | sh
ollama pull llama3.2               # chat model (configurable)
ollama pull nomic-embed-text       # embedding model for Knowledge/RAG
```

SecureAgent detects Ollama automatically at `http://127.0.0.1:11434`
(verify in Settings → Test connection). Without Ollama the deterministic
Local Core keeps utility, workflow, and terminal features fully working and
honestly reports `AI_REASONING_UNAVAILABLE` for generative requests.

### 4) Default permissions

- The restricted Linux terminal is enabled by default and fails closed unless
  the complete bubblewrap sandbox is usable. Host Control and sudo remain off.
- Bounded HTTP tools permit approved public external egress; localhost/private
  targets stay blocked. Web search remains opt-in and requires SearXNG.
- Automation, browser, voice, physical input, MCP, and remote AI providers stay
  opt-in. Approval mode `high-risk` remains active; BLOCKED actions cannot be
  approved.
- No persistent grants exist by default; every agent permission grant expires
  with its session (30-minute sliding TTL).

### 5) Configure the Linux terminal agent + workflows

The restricted Linux terminal is already enabled by default. Keep the following
values explicit when provisioning a new environment; execution still fails
closed if bubblewrap isolation is unavailable.

```bash
cat >> .env <<'EOF'
SECURE_AGENT_TERMINAL_TOOLS_ENABLED=true
SECURE_AGENT_TERMINAL_BACKEND=linux
SECURE_AGENT_SECURITY_WORKFLOWS_ENABLED=true
EOF
# optional extra working directories (JSON list of absolute paths):
# SECURE_AGENT_TERMINAL_ALLOWED_PATHS=["/home/user/projects"]
```

Restart and open the Terminal or Workflows tab.

### 6) Enable Advanced mode

Header → **Advanced** toggle (Simple/Advanced switch). Simple shows
Dashboard, Chat, Workflows, Terminal, Tasks, Reports, Health. Advanced adds
Agents, Tools, Memory, Knowledge, Automation, Security, Permissions,
Approvals, Audit Logs, Settings.

### 7) Approving terminal commands

- **Direct (you typed it):** REQUIRES_APPROVAL/HIGH commands return an
  approval dialog with the exact command, risk, and reasons → *Approve and
  run* (server re-checks policy; BLOCKED always rejected).
- **Agent-initiated:** the task enters `waiting_confirmation`; approve the
  exact step in the Approvals tab (Allow once / Allow for session) or reject.
  Grant "Always allow" in the Permission Center to pre-approve a permission
  domain (never for BLOCKED content, never `admin`).

### 8) Stop / cancel an agent task or execution

- Task: Tasks tab → Cancel (kills live asyncio work via the ExecutionRegistry).
- Terminal execution: Cancel button or `POST /api/v1/terminal/executions/{id}/cancel`
  (kills the whole process group). Timeout kills automatically.

### 9) View audit logs

Audit Logs tab (filterable) or `GET /api/v1/audit` — every task, approval,
tool call, terminal execution (command, cwd, risk, approval, exit code,
duration), workflow report, and grant change is recorded with automatic
secret redaction. Terminal output history is additionally searchable at
`GET /api/v1/terminal/history?query=…`.

## 4. Security limitations (honest disclosure)

1. **The Linux terminal executes on your host** under your user account. The
   Command Safety Engine is deterministic and conservative, but static
   classification cannot be perfect. Dangerous raw patterns (disk wipes,
   `rm -rf /`, fork bombs, `curl | sh`, poweroff, interactive shells) are
   BLOCKED outright; everything unusual requires explicit approval.
2. **Root is never bypassed.** sudo runs non-interactively; passworded sudo
   surfaces `SUDO_PASSWORD_REQUIRED`. Root-only checks report NOT_AVAILABLE.
3. **Terminal output is redacted but pattern-based.** If a command prints a
   secret in an unrecognized format, redaction may miss it. Prefer not
   reading credential files through the agent.
4. **File Security Audit is local-only** and scans within approved roots
   (max 20k files per run). Nothing is ever uploaded.
5. **Network Discovery inspects the local machine only.** Active external
   scanning (nmap etc.) classifies HIGH_RISK and requires explicit approval;
   the workflows never automate it against arbitrary targets.
6. **Agent re-planning is bounded**: the planner creates a fixed, validated
   step list per task (retry/backoff and structured error recovery are
   built in; true mid-task LLM re-planning is intentionally not enabled).
7. **Live output** uses sub-second polling of execution snapshots, not an
   SSE stream; a future `/terminal/stream` endpoint can add byte streaming
   without contract changes.

## 5. Remaining TODOs

- Optional: SSE endpoint for byte-level live stdout streaming.
- Optional: per-schedule workflow runner for automated weekly audits.
- Optional: AppImage/.deb packaging validation on Kali bare metal (build
  script unchanged; `./build-linux.sh` after `./install.sh --desktop`).
- Optional: additional plugins (log triage, CIS benchmark mapping) — see
  `backend/app/plugins/loader.py` manifest contract.

## 6. Files added/changed in this upgrade

```
docs/SECUREAGENT_FULL_AUDIT.md               new
docs/SECUREAGENT_LINUX_RELEASE_REPORT.md     new
backend/app/terminal_policy.py               new  (Command Safety Engine)
backend/app/linux_terminal.py                new  (executor, tracker, cancel)
backend/app/terminal_tools.py                new  (12 agent tools)
backend/app/security_engine.py               new  (deterministic checks/workflows)
backend/app/linux_detect.py                  new  (auto-detection)
backend/app/plugins/loader.py                new  (plugin architecture)
backend/app/plugins/available/docker_info/   new  (example plugin, disabled)
backend/app/config.py                        extended (terminal_* settings)
backend/app/models.py                        extended (platforms, terminal, grants)
backend/app/permissions.py                   extended (platform gate, terminal/workflow categories)
backend/app/tools/base.py                    extended (platforms metadata)
backend/app/tools/factory.py                 extended (terminal suite, plugin loading)
backend/app/agent.py                         extended (persistent permissions)
backend/app/automation.py                    extended (async agent factory)
backend/app/main.py                          extended (14 new endpoints, terminal wiring)
backend/app/memory.py                        extended (history/reports/grants stores)
backend/app/migrations.py                    migration 004
backend/tests/test_command_policy.py         new  (123 cases)
backend/tests/test_linux_terminal.py         new  (37 cases)
backend/tests/conftest.py                    test env for linux backend
backend/tests/test_fresh_database_initialization.py  schema evolution
frontend/src/panels.tsx                      new  (Terminal/Workflows/Reports UI)
frontend/src/App.tsx                         extended (mode switch, notifications, grants, tabs)
frontend/src/contracts.ts                    extended (new types)
frontend/src/styles.css                      extended
frontend/tests/api-contract-v1.test.mjs      endpoint inventory 38 → 52
desktop/ipc/register.js                      allowlist + new routes
desktop/services/config.js                   terminal backend settings
desktop/services/backend-manager.js          env mapping
desktop/tests/desktop.test.js                extended
backend/static/                              rebuilt dashboard bundle (synced)
.env.example, README.md, API.md              updated
```
