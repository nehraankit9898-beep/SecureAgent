# SecureAgent 1.3.4 — Bug Fix Report

Source: `SecureAgent-1.3.4-Linux-Source-Audited.zip`
Fixed package: `SecureAgent-1.3.4-Linux-Source-Fixed.zip`
Method: every finding re-verified with render-proof byte checks and dynamic probes before and after the fix; full regression suites re-run.

> Important note on the original audit: two P0 findings (SetupWizard.tsx "syntax error",
> installModels "signature mismatch") and one P3 finding (install.sh "broken color
> escapes") turned out to be **false positives** caused by a display-transport
> artifact that swallowed `[m`-sequences in text output (e.g. `[models` rendered as
> `odels`). Byte-level verification against the pristine zip proves the shipped
> code for those three items was already correct. They are documented here for
> traceability, not as defects.

---

## Confirmed and fixed

### BUG 1 (P0) — Desktop IPC allowlist blocked `/health` and `/orchestrate`
- **Where:** `desktop/ipc/register.js` (`desktop:backend-request` allowlist regex)
- **Symptom:** in the Electron app the dashboard never loaded data (`publicHealth()` → `/api/v1/health` denied every boot and on the 15 s polling interval) and Chat always failed (`POST /api/v1/orchestrate` denied).
- **Fix:** added `health` and `orchestrate` to the capability regex. Verified in Node: all 15 frontend-used routes pass, 8 malicious/unknown paths still denied; desktop test suite (16/16) passes, including its allowlist assertions.

### BUG 4 (P1) — `docker-compose.yml` crashed the backend at startup
- **Where:** `SECURE_AGENT_OLLAMA_BASE_URL: http://host.docker.internal:11434` vs `backend/app/config.py` remote-Ollama validation (remote requires `ALLOW_REMOTE_OLLAMA=true` **and** HTTPS).
- **Symptom:** `Settings()` raised `CONFIGURATION ERROR` → uvicorn exited → container restart loop.
- **Fix:** removed the invalid default (backend now boots with the loopback default; the dashboard works via the built-in deterministic local core) and documented in the compose file exactly how to enable a host-side Ollama (explicit egress approval + HTTPS endpoint — plain-HTTP remote remains rejected by design).

### BUG 5 (P2) — `Registry.execute` masked `RuntimeError` diagnostics
- **Where:** `backend/app/tools/base.py` safe-error whitelist.
- **Symptom:** agent saw `"RuntimeError: tool failed"` instead of structured codes such as `NETWORK_RATE_LIMITED: Retry after one minute`, `PYTHON_SANDBOX_UNAVAILABLE`, `TERMINAL_SANDBOX_UNAVAILABLE`.
- **Fix:** added `RuntimeError` to the whitelist (messages are static, non-sensitive) and mapped `TERMINAL_` prefixes to structured result codes alongside `NETWORK_`/`PYTHON_`.

### BUG 6 (P2) — `walk_bounded` failed listings on large workspaces
- **Where:** `backend/app/workspace.py`; consumers `ListFiles` (recursive), `InspectProject`, `SearchCode`/`iter_files`.
- **Symptom:** any workspace subtree with more than `max_search_files` (default 2000) files made `list_files`/`inspect_project`/`search_code` raise `workspace traversal limits exceeded` instead of returning `truncated: true`.
- **Fix:** new `stop_at_limit=False` parameter. Read-only listings now pass `stop_at_limit=True` and truncate cleanly; `safe_copy_tree` keeps the default raise semantics so sandbox copying stays fail-closed. Timeout and directory-limit guards still raise in both modes.

### BUG 7 (P2) — invalid ports leaked raw `ValueError`
- **Where:** `backend/app/network_security.py::resolve_target` — `urlsplit(...).port` raises `ValueError("Port out of range 0-65535")` before any policy wrapping.
- **Symptom:** `http://example.com:99999/` produced an uncontrolled exception (misleading `503 NETWORK_UNAVAILABLE`) instead of a 4xx policy error.
- **Fix:** port is parsed once inside `try/except ValueError → NetworkPolicyError('invalid network port')`; all downstream uses (`getaddrinfo`, connect URL, Host header) use the validated variable.

### BUG 8 (P2) — memory search treated `%`/`_` as LIKE wildcards
- **Where:** `backend/app/memory.py::MemoryStore._list`.
- **Symptom:** query `%` returned every memory; `_` matched unintended characters (parameterized, so no injection — a correctness bug).
- **Fix:** `\`, `%`, `_` are escaped and the SQL uses `LIKE ? ESCAPE '\'`; literal searches still match, `relevant()` keyword recall benefits too.

### P3-9 — dead environment export removed
`desktop/services/backend-manager.js` exported `SECURE_AGENT_NETWORK_TRUSTED_PRIVATE_ENDPOINT`, which does not exist in backend `Settings` (silently ignored — config drift). Removed; the desktop-only derived display field remains in the local config/UI contract.

### P3-10 — broker requests now honour timeouts and cancellation
- `frontend/src/api.ts`: in broker mode `timeoutMs` and `AbortController` had no effect (an `ipcRenderer.invoke` cannot be aborted). The broker call is now raced against `controller.signal`, so the existing timeout/cancel handling maps rejections to `REQUEST_TIMEOUT` / `REQUEST_CANCELLED`.
- `desktop/ipc/register.js`: the main-process upstream `fetch` for `desktop:backend-request` now carries a 130 s `AbortController`, matching the existing `backendPost` guard, so a wedged backend can no longer hang the UI indefinitely.
- The fixed bundle is synced into `backend/static/` (desktop loads the dashboard from the backend origin, so this is the code path that ships the fix).

### P3-11 — corrupt desktop config no longer bricks startup
`desktop/services/config.js::loadConfig` tolerated only `ENOENT`; malformed JSON or a value rejected by `normalizeConfig` threw inside `app.whenReady()` (unhandled rejection, no window). It now parks the unusable file as `desktop.json.corrupt-<timestamp>` and continues with defaults; `desktop/main.js` logs `config.recovered` with the backup path.

### P3-12 — session approvals expire
`backend/app/main.py::session_approvals` accumulated per-conversation grants forever (until process restart). Grants now carry a sliding 30-minute TTL (`SESSION_APPROVAL_TTL_SECONDS`), refreshed on each new session-scope grant and pruned when the agent is constructed and when grants are renewed.

### P3-13 — terminal honours configured copy limits
`TerminalTool.run` hardcoded `execute_copy(..., 20000, 100000000)`. It now uses `config.test_max_copy_files` / `config.test_max_copy_bytes`, the same authoritative budget as the test runner.

### P3-14 — fallback planner false positives eliminated
`LocalCoreProvider._plan` matched almost any prose containing digits (e.g. "hello world 123" planned a calculator step on `123`). Calculation is now planned only when the whole message is one arithmetic expression or an explicit keyword (`calculate`, `compute`, `what is`) introduces an arithmetic expression containing an operator. "calculate 2+3*4" → `2+3*4` (existing test), bare "2+3*4" → calculator, "hello world 123" and "room 101-102" → `AI_REASONING_UNAVAILABLE` as intended.

### P3-15 — scheduler leases only what it can run
`AutomationEngine.loop` leased up to 10 due schedules per tick but started only `max_concurrent`, parking the rest until lease expiry. It now computes free capacity and claims exactly that (`claim_due_schedules(..., limit=capacity)`), skipping the claim entirely when at capacity.

### P3-16 — `schedules.failure_count` is now maintained
The column was written as 0 at creation and never updated. `record_schedule_run` increments it for every non-completed run, giving operators a real repeated-failure signal.

### P3-17 (documentation-only) — install.sh colors were never broken
`$'\033[1m'` ANSI-C quoting is valid bash; the audit's "missing `[`" observation was the same `[m`-swallowing display artifact. No change required.

---

## Verification matrix

| Check | Result |
|---|---|
| Backend pytest suite | **113 / 113 passed** |
| `backend/scripts/security_smoke.py` | **PASS (14 checks)** |
| `backend/scripts/security_hardening_source.py` | **PASS (5 checks)** |
| `backend/scripts/offline_acceptance.py` | **PASS** |
| Frontend `tsc -b` typecheck | **PASS** |
| Frontend production build (`vite build`) | **PASS** |
| Frontend source lint | **PASS (6 files)** |
| Frontend unit tests (`node --test`) | **9 / 9 passed** |
| Desktop test suite (`node --test`) | **16 / 16 passed** |
| Node syntax check (`node --check`) on all modified JS | **PASS** |
| Dynamic fix probes (Registry, ports, LIKE, walk, compose, planner, scheduler, approvals, config recovery, allowlist, timeouts) | **23 / 23 passed** |
| Shipped dashboard bundle re-synced with fixed frontend source | **DONE** (`backend/static/assets/index-Bhv8lO6j.js`) |

## Files changed (relative to the audited zip)

```
docker-compose.yml
desktop/ipc/register.js
desktop/main.js
desktop/services/backend-manager.js
desktop/services/config.js
frontend/src/api.ts
backend/static/index.html                 (re-bundled dashboard)
backend/static/assets/index-Bhv8lO6j.js   (re-bundled dashboard)
backend/app/tools/base.py
backend/app/tools/builtins.py
backend/app/workspace.py
backend/app/coding.py
backend/app/network_security.py
backend/app/memory.py
backend/app/automation.py
backend/app/main.py
backend/app/llm.py
```

All backend security boundaries (fail-closed tool registry, allowlisted IPC surface, remote-Ollama HTTPS/egress policy, sandbox copy limits, DNS-pinned HTTP client) remain intact; every change strictly narrows failure modes or restores intended behaviour.
