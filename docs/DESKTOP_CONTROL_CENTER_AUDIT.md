# SecureAgent Desktop Control Center — Audit

**Upgrade:** Control Center on top of SecureAgent 1.3.4 (Linux Agent Master Upgrade)
**Scope:** Electron desktop control panel driving the real FastAPI backend, with a
backend-owned runtime configuration authority.
**Verification:** unit/regression suites + a live verification run against a real
backend process (`scripts/control_center_live_verification.py`, 52/52 checks,
report: `.live-verify/live-verification-report.json`).

---

## 1. Architecture

```
Electron Desktop (Control Center window)
   │  window.secureAgent.* (contextBridge, frozen, contextIsolation: true,
   │  nodeIntegration: false, sandbox: true)
   ▼
Secure IPC (main process; injects Bearer token; capability-regex-checked routes)
   ▼
SecureAgent Backend (FastAPI)  ← the SECURITY AUTHORITY
   │  ControlCenter (app/control_center.py) — typed / versioned / atomic /
   │  recoverable / audited runtime state  (data/control_center.json)
   ▼
Real Runtime Enforcement
   Linux terminal executor · agent · automation engine · tool registry ·
   network HTTP client · LLM provider · memory/RAG stores
```

Key rule enforced everywhere: **the Desktop is a control panel, the backend is
the security authority, the AI is never the security authority.** The renderer
holds no token, no Node access, and no authoritative state; every switch maps
to a backend field; every rejection reverts the UI to the backend snapshot.

### Configuration source of truth (spec §19)

* `data/control_center.json` — pydantic-validated `ControlState`, 13 sections
  (`secure_mode`, `agent`, `terminal`, `host_control`, `network`, `sudo`,
  `filesystem`, `ai`, `memory`, `rag`, `automation`, `workflows`, `security`).
* **validated** — merge-patch transactions validate the whole candidate state
  (unknown field/section, bad type, out-of-bounds, security violation ⇒ 422,
  nothing applied).
* **typed** — strict pydantic models with bounds.
* **versioned** — every applied change bumps `revision`; document carries
  `schema_version` (currently 1; mismatch ⇒ recovery path, never guessed).
* **atomic** — temp file + `fsync` + `os.replace`; previous document kept as
  `.bak` (0600 permissions).
* **recoverable** — corrupted main file ⇒ restore `.bak`; no file at all ⇒
  safe defaults; every recovery audited (`control.recovered`).
* **audited** — every apply, rejection, recovery, emergency stop and resume
  written to the SQLite audit trail.
* `localStorage` is **not** used anywhere as configuration authority
  (asserted by `desktop/tests/control-center.test.js`).

---

## 2. Control → backend mapping (every switch has a real effect)

| Control Center switch | Backend field / enforcement point | Runtime effect when turned OFF |
|---|---|---|
| AI AGENT | `agent.enabled` — gates `/agent/tasks`, `/orchestrate`, agent run | Autonomous task execution refused (`AGENT_DISABLED_BY_CONTROL_CENTER`) |
| Auto Planning | `agent.auto_planning` × `ai.planning` — `Agent.plan` | Tool plans refused (`AUTO_PLANNING_DISABLED`), direct answers allowed |
| Auto Tool Calling | `agent.auto_tool_calling` × `ai.tool_calling` — `Agent.execute` | Every autonomous tool invocation refused |
| Auto Execution | `agent.auto_execution` — `Agent.run` | Task refused before planning (`AUTO_EXECUTION_DISABLED`) |
| Auto Retry | `agent.auto_retry` — `Agent.execute` | Retry limit forced to 0 |
| TERMINAL | `terminal.enabled` — `LinuxTerminalExecutor.execute` + `/terminal/execute` | ALL terminal execution refused, user- and AI-initiated (`TERMINAL_DISABLED_BY_CONTROL_CENTER`) |
| Restricted Mode | `terminal.restricted_mode` — executor sandbox selection | Locked ON while Secure Mode is ON (422 otherwise) |
| Command Approval | `terminal.command_approval` — policy engine confirm flow | High-risk commands require explicit confirm |
| Host Control | `host_control.enabled` — `/terminal/mode` + `executor.set_mode` | HOST_CONTROL refused (`HOST_CONTROL_DISABLED`); enable requires `?confirm=true`; AI can never enable it |
| NETWORK | `network.mode` (disabled/localhost/private/external/full) — `SafeHttpClient.request` gate | All tool HTTP traffic refused (`NETWORK_BLOCKED_BY_CONTROL_CENTER`), telemetry counters recorded |
| Allowed/Blocked destinations | `network.allowed_destinations` / `blocked_destinations` — `check_network` | Per-host allow-list/deny-list with wildcard support |
| SUDO | `sudo.mode` (disabled / approval_required / host_control_only) × `terminal.allow_sudo` — `_check_sudo_policy` + endpoint | sudo refused (`TERMINAL_SUDO_DISABLED`); interactive sudo shells always blocked; passwords never requested/stored |
| AUTOMATION | `automation.enabled` × `scheduled_tasks` × `background_tasks` × `paused` — engine loop + `/schedules` | Engine claims no work; schedule creation refused (`AUTOMATION_DISABLED`) |
| Pause/Resume/Cancel All | `/automation/pause-all|resume-all|cancel-all` | Cancels running jobs (asyncio cancel), pauses claiming |
| AI ENGINE | `ai.enabled` — `/chat` gate + provider refresh | Generative calls refused (`AI_DISABLED`); deterministic local core continues |
| OLLAMA | `ai.ollama_enabled` — `FallbackProvider.refresh` | Reports `OLLAMA_DISABLED`; never fakes AI-ready; local core serves deterministic answers |
| Model / Temperature / Context / Max Tokens | `ai.model` / `temperature` / `context_size` / `max_tokens` — `OllamaProvider.chat` | Applied per request (`model`, `temperature`, `num_ctx`, `num_predict`); planner's deterministic temperature=0 preserved |
| MEMORY | `memory.enabled` × `ingestion` × `retrieval` — `/memories` gates | Read/write refused (`MEMORY_*_DISABLED`); `max_context_items` clamps listing |
| Sensitive Data Filtering | `memory.sensitive_filtering` — `MemoryService` | ON: sensitive-looking memories refused; OFF: stored **redacted** (raw secrets never persisted) |
| RAG | `rag.enabled` × `ingestion_enabled` × `retrieval_enabled` — `/documents` gates + `memory.max_documents` | Ingestion/search refused; document ceiling enforced |
| WORKFLOWS | `workflows.enabled` — `/workflows/{name}/run` | Workflow runs refused (`WORKFLOWS_DISABLED`) |
| TOOLS | `PATCH /tools/{name}` → `Registry` per-tool `enabled` | Registry refuses execution of a disabled tool (`tool_disabled`) |
| AUDIT | `/audit?category=`, `/audit/export`, `/audit/clear?confirm` | Filters (all/agent/terminal/network/security/permission/errors); JSONL export; clear refused without confirmation |
| FILESYSTEM | `/filesystem`, `/filesystem/paths` — backend canonical validation | Approved paths extend the terminal jail at runtime; `/`, pseudo-fs and protected locations refused; sensitive trees need confirm |

### Mandatory security protections (spec §3, §14)

`command_policy`, `filesystem_protection`, `network_policy`, `approval_system`,
`audit_logging`, `secret_redaction` are **always mandatory** — any patch
attempting to disable them is rejected (`CONFIG_REJECTED`, 422), regardless of
Secure Mode or the requesting actor. While Secure Mode is ON, restricted
terminal mode is also locked. Enforcement sources are reported by
`GET /api/v1/security`; if the namespace sandbox is unavailable the response
is `SECURITY DEGRADED` (fail-closed: RESTRICTED_AGENT refuses execution rather
than falling back to host execution).

### EMERGENCY STOP (spec §7)

`POST /api/v1/emergency-stop` (runtime-only flag; a fresh backend start always
comes up in its configured state):

1. kills every running terminal execution's process group (SIGKILL),
   verified live with `pgrep`;
2. cancels live agent tasks through the execution registry;
3. cancels running automation jobs;
4. forces Host Control OFF;
5. disables agent / terminal / network / automation gates (all checks
   return `SECUREAGENT_STOPPED`);
6. preserves the audit trail and records the stop;
7. the desktop shows the `SECUREAGENT STOPPED` overlay; `RESUME`
   (`POST /api/v1/resume`) restores the exact pre-emergency configuration.

### One-click presets (spec §18)

`POST /api/v1/config/preset` — `safe` (default posture), `development`
(localhost network), `security_lab` (approval-gated sudo + automation),
`full_control` (**requires `confirm: true`**; enables autonomous execution,
external-network runtime mode, approval-gated sudo, automation — but is NOT
unrestricted: sandbox, command policy, approvals, audit and redaction stay
mandatory, and Host Control remains a separate explicit confirmation).
Note: the runtime network mode can only narrow the statically configured
ceiling — it can never grant tools that were disabled at startup.

### One-click apply & real-time sync (spec §23–24)

* Multiple advanced changes are staged client-side and sent as **one**
  `PATCH /config` transaction (`Applying… → Applied / Failed`); the backend
  applies all-or-nothing, so UI and backend can never diverge; on failure the
  UI reverts to the backend snapshot.
* `GET /api/v1/config/events` (SSE) streams revision changes; the Electron
  main process holds the single authenticated connection
  (`desktop/services/config-watcher.js`) and broadcasts
  `control:config-sync` to every renderer; the Control Center refetches and
  flashes `CONFIGURATION SYNCHRONIZED`. A 5 s status poll backs this up.
  No restart is required for any runtime switch.

### Electron security (spec §21)

* `contextIsolation: true`, `nodeIntegration: false`, `sandbox: true`,
  strict CSP on the control panel (`connect-src 'none'` — the page cannot
  open its own network connections).
* Preload exposes only the frozen `secureAgent` bridge (asserted by tests to
  contain no `child_process`, `shell`, `fs`, `process`, …).
* The main process injects the backend token; the renderer never sees it.
* The renderer backend broker allows only capability-regex-matched routes
  (`BACKEND_CAPABILITY_PATTERN`, exported and unit-tested).

---

## 3. API surface added (spec §20)

| Method & route | Purpose |
|---|---|
| `GET /api/v1/config` | Full runtime control state + telemetry + recovery info |
| `PATCH /api/v1/config` | Validated configuration transaction (`?confirm=true` for Host Control) |
| `POST /api/v1/config/preset` | Apply `safe` / `development` / `security_lab` / `full_control` |
| `GET /api/v1/config/events` | SSE revision stream (real-time sync) |
| `POST /api/v1/emergency-stop` | Kill switches + global execution block |
| `POST /api/v1/resume` | Restore pre-emergency configuration |
| `GET /api/v1/status` | Live status cards + automation job counters + network telemetry |
| `GET /api/v1/security` | Mandatory-protection matrix, `SECURITY DEGRADED` detection |
| `GET /api/v1/permissions` | Capability matrix + persistent grants |
| `PATCH /api/v1/permissions` | Grant/revoke (admin forbidden) |
| `PATCH /api/v1/tools/{name}` | Real per-tool enable/disable |
| `GET /api/v1/audit?category=` | Filtered audit (all/agent/terminal/network/security/permission/errors) |
| `POST /api/v1/audit/export` | JSONL export (0600) |
| `POST /api/v1/audit/clear` | Clear — requires `confirm: true` |
| `GET /api/v1/filesystem` | Workspace / approved paths / protected paths / permissions |
| `POST /api/v1/filesystem/paths` | Add allowed path (backend canonical validation) |
| `POST /api/v1/filesystem/paths/remove` | Remove allowed path |
| `POST /api/v1/automation/{action}` | `pause-all` / `resume-all` / `cancel-all` |
| `GET /api/v1/terminal/executions` | Live tracker view (what emergency stop would kill) |

Pre-existing endpoints were reused wherever they existed (`/tools`,
`/audit`, `/permissions/grants`, `/terminal/*`, `/workflows`, …); the desktop
capability pattern was extended rather than duplicated.

### Configuration schema (abridged defaults)

```
secure_mode: true
agent:        {enabled: true,  auto_planning: true,  auto_tool_calling: true, auto_execution: true, auto_retry: true}
terminal:     {enabled: true,  restricted_mode: true, command_approval: true, allow_sudo: false,
               allow_network: false, max_command_time_seconds: 30, max_commands_per_task: 12,
               max_output_bytes: 200000}
host_control: {enabled: false, auto_off_on_exit: true}
network:      {mode: "disabled", allowed_destinations: [], blocked_destinations: []}
sudo:         {mode: "disabled"}
filesystem:   {allowed_paths: [], protected_paths: [/etc/shadow, /etc/sudoers, ~/.ssh, …]}
ai:           {enabled: true, ollama_enabled: true, model: null, temperature: null,
               context_size: null, max_tokens: null, tool_calling: true, planning: true}
memory:       {enabled: true, ingestion: true, retrieval: true, max_context_items: 50,
               max_documents: 5000, sensitive_filtering: true}
rag:          {enabled: true, ingestion_enabled: true, retrieval_enabled: true}
automation:   {enabled: false, scheduled_tasks: false, automatic_workflows: false,
               auto_retry: false, background_tasks: true, paused: false}
workflows:    {enabled: true}
security:     {command_policy: true, filesystem_protection: true, network_policy: true,
               approval_system: true, audit_logging: true, secret_redaction: true}   # all mandatory
```

---

## 4. Tests

### Backend (`backend/tests/test_control_center.py` + regression suites)

All 347 backend tests pass (329 pre-existing regressions + 18 new). The 12
spec-§25 scenarios are covered as named tests:

1. `test_1_terminal_off_rejects_execution_then_on_allows` — Terminal OFF ⇒ API
   409 **and** direct executor call raises (AI tool path covered)
2. `test_2_network_disabled_blocks_http_client_and_records_telemetry`
3. `test_3_sudo_disabled_rejects_sudo_command`
4. `test_4_automation_off_rejects_schedule_creation`
5. `test_5_tool_disabled_is_refused_by_registry_then_reenabled`
6. `test_6_emergency_stop_kills_running_process_and_resume_restores` — real
   background execution, process-group kill, marker never created, audit preserved
7. `test_7_secure_mode_mandatory_protections_cannot_be_disabled`
8. `test_8_host_control_off_rejects_host_control_mode` (incl. confirm semantics)
9. `test_9_ollama_off_reports_disabled_not_fake_ready`
10. `test_10_configuration_persists_across_restart` +
    `test_10b_corrupted_configuration_recovers_previous_valid_state`
11. `test_11_invalid_config_rejected_and_previous_retained`
12. `test_12_frontend_manipulation_cannot_bypass_backend_security`

### Desktop (`desktop/tests/`)

26 tests pass, including the new `control-center.test.js`: preload bridge
surface (no Node primitives exposed), capability-pattern allow/deny matrix,
SSE parser, no-localStorage-as-authority, emergency-stop wiring.

---

## 5. Live verification (spec §26) — real backend, real operations

`python3 scripts/control_center_live_verification.py` boots the real backend
(Linux terminal backend, token auth) and executed **52 checks — all passing**
(`.live-verify/live-verification-report.json`). Highlights:

* toggle OFF → execute → **rejected**; toggle ON → execute → **succeeded**
  (terminal, sudo, network, automation, tools)
* **EMERGENCY STOP against a real `sleep 30 && touch …` process**: `pgrep`
  confirmed the process alive; after the stop the process group was gone,
  the marker file was never created, and `RESUME` restored operation
* configuration change survived a **full backend restart** (values + revision)
* five invalid-configuration classes rejected with state + revision retained
* secure-mode mandatory protections, admin-grant refusal, `/etc/shadow`
  refusal, host-control confirm semantics, SSE revision stream, audit
  export/clear-with-confirmation, multi-field atomic transaction

---

## 6. Feature classification (spec §28)

### REAL FEATURES (backend implementation + config state + API/IPC path + runtime effect + test)

Control Center config API and transactions · all master switches (AI AGENT,
TERMINAL, NETWORK, SUDO, AUTOMATION, AI ENGINE, OLLAMA, MEMORY, RAG,
WORKFLOWS, TOOLS, AUDIT, SECURITY) · Auto Planning / Auto Tool Calling /
Auto Execution / Auto Retry · Secure Mode with locked mandatory protections ·
Host Control (confirm-gated, auto-off on exit / emergency / unsafe state) ·
Restricted terminal mode, command approval, sudo policy, terminal network
policy, max command time / commands-per-task / output size · Emergency Stop
with real process-group kills and Resume · Network modes + allow/block
destination lists + request telemetry · Filesystem allowed-path management
with backend canonical validation · AI model/temperature/context/max-token
limits · Ollama on/off with honest OFFLINE reporting · Memory/RAG
ingestion/retrieval gates and limits · Sensitive-data filtering · Automation
pause/resume/cancel-all and job counters · Per-tool enable/disable · Audit
filters/export/clear · Live status cards · Presets (safe/development/
security-lab/full-control with confirmation) · Settings persistence
(versioned, atomic, recoverable, audited) · Real-time sync (SSE → desktop).
All verified live.

### PARTIAL FEATURES

* **Runtime network mode cannot exceed the static startup configuration.**
  `network.mode` is a live narrowing gate on top of the statically
  constructed tools; if Network tools were disabled at startup, selecting
  FULL at runtime cannot enable them (by design — but the UI explains it).
* **AI parameter application nuance** — the Control Center temperature is
  applied to ordinary chat requests; the planner's explicit temperature=0 is
  preserved for deterministic planning.
* **Sudo "approval_required / host_control_only" modes** both currently
  resolve to non-interactive `sudo -n` gated by the command policy; a
  per-command approval queue distinct from the existing approval engine is
  future work.
* **Status card "backend"** is trivially ONLINE while the request is being
  served (the honest failure mode is the pill flipping to BACKEND OFFLINE in
  the desktop when polling fails).

### BLOCKED FEATURES

* **AI modifying any control** — blocked by design: the agent tool set
  contains no configuration capability, non-user actors are rejected for
  security-relevant sections (`_assert_user_only_fields`), admin grants are
  forbidden, and mandatory protections are un-disable-able. This is
  intentional and permanent.

### NOT AVAILABLE FEATURES

Displayed as `NOT AVAILABLE` / `OFFLINE` rather than a fake switch, per spec §27:

* Terminal switch shows OFFLINE/NOT AVAILABLE when the Linux terminal backend
  is unavailable (non-Linux platform or missing shell) — the backend then
  refuses execution fail-closed.
* Ollama card shows OFFLINE (never a fake AI-ready state) when the service or
  models are unavailable; the deterministic local core keeps core features
  working.
* Sandbox card shows DEGRADED when user-namespace/bubblewrap isolation is
  unavailable, with the security endpoint reporting SECURITY DEGRADED.

---

## 7. Known limitations

1. Emergency stop is runtime state — a backend restart returns to the
   configured (non-stopped) state deliberately, so a crash can never leave
   the agent permanently bricked.
2. `revision` is per data directory; wiping `data/control_center.json`
   resets to safe defaults (recovery audited).
3. Host Control auto-off-on-exit depends on a clean shutdown path
   (`before-quit` → backend lifespan); a hard kill of the whole desktop
   process naturally ends all host operations anyway because the backend
   process (and its children) die with it.
4. The Control Center window is Electron-only; browser mode keeps the
   existing React dashboard (all new APIs are also reachable there via the
   same authenticated routes).
5. The audit `errors` category matches event-name suffixes and an `error`
   key in details; exotic failure shapes may need the `all` filter.

## 8. Files changed / added

**Added:** `backend/app/control_center.py`, `backend/tests/test_control_center.py`,
`desktop/windows/control-center.{html,css,js}`, `desktop/services/config-watcher.js`,
`desktop/tests/control-center.test.js`, `scripts/control_center_live_verification.py`,
`docs/DESKTOP_CONTROL_CENTER_AUDIT.md`.

**Modified:** `backend/app/main.py` (control center API + endpoint gates +
kill switches), `backend/app/linux_terminal.py` (runtime gates, sudo
precedence, allowed-root union, kill-all), `backend/app/agent.py`
(auto-flag enforcement), `backend/app/automation.py` (loop gate, cancel-all),
`backend/app/llm.py` (AI limits + honest disabled reporting),
`backend/app/network_security.py` (network gate + telemetry),
`backend/app/memory_service.py` (sensitive filtering),
`backend/app/memory.py` (audit filters/clear/export store support),
`backend/app/models.py` (Control Center request bodies),
`backend/app/execution_registry.py` (active_ids),
`desktop/preload.js`, `desktop/ipc/register.js`, `desktop/main.js`,
`desktop/tests/conftest.py` (fixture), three terminal regression tests
(host-control fixture), `.gitignore`.
