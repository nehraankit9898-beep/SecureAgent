# Control Center Architecture Audit

## Scope

Audited SecureAgent 1.3.4 in place. The existing FastAPI, React, Electron,
SQLite and tool architecture was retained.

## Existing architecture

| Layer | Primary files | Responsibility |
|---|---|---|
| Electron | `desktop/main.js`, `desktop/preload.js`, `desktop/ipc/register.js` | Starts the packaged backend, exposes narrow IPC and hosts the Control Center |
| Control Center UI | `desktop/windows/control-center.*` | Reads backend state, submits patches and follows configuration SSE events |
| Web UI | `frontend/src/*` | Browser dashboard and API client |
| API | `backend/app/main.py` | Authentication, validation, approvals and API orchestration |
| Runtime authority | `backend/app/control_center.py` | Typed runtime state, atomic persistence, runtime gates, emergency stop and SSE revisions |
| Policy | `backend/app/security_engine.py`, `permissions.py`, `terminal_policy.py` | Deterministic permission and command decisions |
| Execution | `backend/app/linux_terminal.py`, `terminal_tools.py` | Command lifecycle, timeout, cancellation, output bounds and audit integration |
| OS sandbox | `backend/app/linux_sandbox.py` | Capability probe, bubblewrap profile and canonical path checks |
| Data/audit | `backend/app/models.py`, `migrations.py` | SQLite state and audit records |
| AI/data services | `llm.py`, `memory*.py`, `knowledge.py`, `automation.py` | Ollama, memory, RAG and automation |

## Dependency map

`Control Center UI -> preload/IPC -> FastAPI /api/v1/config -> ControlCenter
-> runtime gate -> feature -> audit store`.

Terminal execution adds:

`ControlCenter -> permission check -> command policy -> LinuxTerminalExecutor
-> bubblewrap -> child process`.

Backend changes are broadcast through `/api/v1/config/events`; Electron's
watcher causes the renderer to reload authoritative state.

## Configuration sources

1. Project-root `.env`: installation/startup settings and secrets.
2. `control_center.json`: typed mutable runtime policy.
3. SQLite: tools, permissions, tasks, schedules and audit events.
4. Electron launcher configuration translated into a backend environment
   allowlist.

The launcher/environment layer remains a compatibility ceiling. Feature
decisions must be made by `ControlCenter` at execution time; static settings
may further restrict a feature but must not bypass a runtime denial.

## Runtime gates

Runtime gates exist for agent flags, terminal, host control, sudo, network,
Ollama, memory, RAG, automation and workflows. Tool enablement also has a
registry-level gate. Emergency Stop is checked by security-sensitive gates and
has callbacks for terminal, task and automation cancellation.

## Security boundaries

- API authentication and loopback binding.
- Typed configuration validation and atomic persistence.
- Deterministic permission and command policy.
- Explicit approval for high-impact operations.
- Restricted/host-control separation.
- Bubblewrap user, mount, PID and network namespaces with an empty root,
  capability drop and uid/gid 65534.
- Canonical workspace checks and secret redaction.
- SQLite audit trail.

The former `unshare`-only fallback exposed the host root mount. It is no longer
accepted as a restricted sandbox. If the complete bubblewrap profile cannot be
executed, restricted execution fails closed.

## Known gaps

- The current test host has `unshare` but no bubblewrap, so Linux restricted
  runtime tests are blocked here.
- Environment settings still include legacy feature flags.
- The local SQLite audit database is not cryptographically tamper-evident.
- Package install/launch/uninstall needs a clean graphical Linux host.
- Distribution support outside Debian/Ubuntu has not been verified.

## Files modified

Sandbox, terminal, Control Center, status reporting, regression tests,
frontend contract test, packaging script and documentation.

## Files intentionally left structurally unchanged

Database migrations, authentication middleware, permission engine, agent
orchestration, LLM protocol, memory/RAG storage and Electron's IPC security
model were retained. No endpoint was removed.