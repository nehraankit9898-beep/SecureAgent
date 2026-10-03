# SecureAgent 2.0 — Engineering Audit Report

**Scope:** full repository (`backend/`, `frontend/`, `desktop/`, `scripts/`, `docs/`, build system)
**Method:** static audit (2 parallel deep-reading passes, ~13.4k LOC backend + ~2.4k LOC desktop + ~1.1k LOC frontend), full test-suite execution, and real-machine live verification against a running backend.
**Date:** 2026-10-02 · **Version audited:** 2.0.0

---

## 1. Feature matrix (verified state)

| Feature | UI | API | Backend | Real execution | Tests | Status |
|---|---|---|---|---|---|---|
| Health probes (db/workspace/tools/terminal/ollama) | ✅ | ✅ `/health`, `/system/health` | ✅ computed from live probes | ✅ `SELECT 1`, sandbox probe, provider HTTP | ✅ | **VERIFIED** |
| System Doctor (10 self-tests) | ✅ Diagnostics tab | ✅ `/diagnostics` | ✅ real probes each run | ✅ echo via executor, probe memory, RAG search | ✅ | **VERIFIED** (terminal/ollama honestly FAIL/NOT_AVAILABLE here) |
| SAFE/ASSIST/CONTROL mode surface | ✅ header selector | ✅ `/mode` GET/POST | ✅ curated presets on ControlState | ✅ audit `mode.applied` | ✅ | **VERIFIED** |
| Agent task lifecycle | ✅ Chat/Tasks | ✅ `/agent/tasks…` | ✅ plan→approve→execute→verify→audit | ✅ LocalCore plan + calculator → `161` verified live | ✅ | **VERIFIED** |
| Task cancel / resume / reject | ✅ | ✅ | ✅ asyncio.Task.cancel + DB state | ✅ live cancel → `cancelled` | ✅ | **VERIFIED** |
| Permission & approval system | ✅ Approvals tab | ✅ grants, resume, permissions | ✅ request/session/persistent grants, high-risk forced | ✅ | ✅ | **VERIFIED** |
| Terminal engine (classify→sandbox→execute) | ✅ Terminal tab | ✅ `/terminal/*` | ✅ 5-tier policy, argv-only, fail-closed | ✅ real exec/timeout/kill/cancel via HOST_CONTROL live run; sandbox path BLOCKED (env) | ✅ | **VERIFIED** (sandbox execution BLOCKED — env) |
| Bubblewrap sandbox | ✅ status cards | ✅ | ✅ probes + full profile (nobody uid, no /etc, unshare-net) | ⚠️ fails closed here (AppArmor userns restriction) | ✅ skip=BLOCKED | **BLOCKED — ENVIRONMENT REQUIRED** |
| Ollama detection & chat/embedding | ✅ Settings | ✅ `/ollama/*` | ✅ real HTTP `/api/version`+`/api/tags` | ✅ honest NOT_AVAILABLE; LocalCore refuses to fake AI | ✅ | **VERIFIED (detection)** / **BLOCKED (inference — not installable here)** |
| Memory (short/long term) | ✅ | ✅ CRUD+search | ✅ SQLite WAL, secret filtering | ✅ live CRUD | ✅ | **VERIFIED** |
| RAG / knowledge | ✅ | ✅ documents+search | ✅ real embeddings, chunk dedupe, source refs | ⚠️ needs Ollama for embedding | ✅ | **VERIFIED (code)** / **BLOCKED (runtime needs model)** |
| Automation scheduler | ✅ | ✅ schedules+runs | ✅ lease-claiming, approval, budgets | ✅ code-verified; disabled in tests | ✅ | **VERIFIED** |
| Audit log | ✅ | ✅ list/export/clear | ✅ append-only, redacted | ✅ 18 live events, no secrets | ✅ | **VERIFIED** |
| Emergency stop / resume | ✅ global button | ✅ | ✅ 3 kill switches + persisted flag | ✅ live: blocks terminal, resume restores | ✅ | **VERIFIED** |
| Desktop Control Center | ✅ primary window | ✅ IPC proxies | ✅ every control → real endpoint | ✅ trust-gate behavioral tests | ✅ | **VERIFIED (after B-1 fix)** |
| Desktop backend lifecycle | ✅ | ✅ | ✅ spawn/health/restart/stop | ✅ integration tests + orphan reap tests | ✅ | **VERIFIED (after B-4/B-5 fixes)** |
| Network egress control | ✅ | ✅ | ✅ DNS-pinned, metadata blocked, gate-checked | ✅ tests | ✅ | **VERIFIED** |
| Filesystem boundaries | ✅ | ✅ | ✅ O_NOFOLLOW walk, hardlink checks, protected paths | ✅ live: `/etc/shadow` denied | ✅ | **VERIFIED** |

## 2. Fake/placeholder scan result

**No fake features found.** Zero TODO/FIXME in backend; every `pass` is an except-guard or empty pydantic model; the only hardcoded status literal is `"backend": "ok"` in `/health` (trivially true — it is the responding server). LocalCore explicitly returns `AI_REASONING_UNAVAILABLE` instead of impersonating an LLM; `embed()` raises rather than fabricating vectors; cancellation kills real process groups.

## 3. Defects found and fixed

| ID | Severity | Defect | Fix |
|---|---|---|---|
| B-1 | **High** | IPC trust gate rejected the Control Center window (`file://` URL not in allowlist) → every `control:*` call threw `Untrusted IPC sender`; primary desktop UI dead while backend healthy | `register.js` admits exact file URLs of the two shipped local windows only |
| B-5 | **High** | Version drift: desktop `1.3.4` vs backend `2.0.0`; `waitForHealth()` compares exactly → packaged desktop app could **never** reach READY | Single source of truth enforced; all manifests/lockfiles bumped to 2.0.0; cross-component consistency regression test added |
| B-6 | **High** | Host Control auto-off-on-exit **never worked**: shutdown hook called `update(actor='system')` which the user-only-fields guard rejects; HOST_CONTROL silently persisted across restarts (found in live-run logs) | Internal system-only disable path (lock → persist → honest `host_control.auto_disabled` audit); guard for API/AI actors unchanged |
| B-2 | Medium | `/mode` and `/diagnostics` missing from IPC capability pattern → mode selector + diagnostics tab broken inside desktop dashboard | Pattern extended; negative tests added |
| A-1 | Medium | Terminal SSE URL missing `/api/v1` prefix → EventSource 404s, silently degraded to polling forever | URL built from `API_URL` |
| B-3 | Low/Med | Desktop dashboard always showed false "enter your local API token" (token is broker-injected; user cannot know it) | Browser-standalone-only prompt |
| A-2 | Low | Successful Test Chat/Embedding/Network results rendered in the red error banner | Surfaced as success notices |
| B-4 | Low | No orphaned-backend cleanup: hard-killed Electron left uvicorn serving its port with the previous token | pidfile + cmdline-verified reap (SIGTERM→SIGKILL); unrelated processes strictly untouched (behavioral tests) |
| F7 | Med (test hygiene) | 21 sandbox-dependent tests FAILed instead of reporting BLOCKED when bwrap unavailable | `requires_sandbox` marker with explicit environment reason; suite now 0-fail deterministic |
| TP-1 | Med (test hygiene) | ControlCenter state leakage across tests/runs (ASSIST preset persisted `network.mode=localhost`; stale `.pytest-data` at project root) | conftest resets persisted CC state (correct resolved path); autouse fixture restores CC state, clears rate limiter (new `reset()`) and session approvals |

## 4. Security review (fixes + verified properties)

- **Command policy**: 5-tier classifier, quote-aware split, recursive substitution analysis, evasion pattern layers (verified live: `$((6*7))` command substitution BLOCKED; `rm -rf /` BLOCKED).
- **Sandbox fail-closed**: RESTRICTED_AGENT refuses execution when the bwrap profile is absent (`LINUX_SANDBOX_UNAVAILABLE` with fix guidance) — never falls through to unrestricted host execution (verified live).
- **Host Control boundary**: user-only confirmation for enable; system may only disable (B-6 fix preserves the AI/API authority boundary).
- **Path security**: `O_NOFOLLOW` fd-walk, hardlink detection, protected prefixes, sensitive-file lexical guard (live: `/etc/shadow` cat → 403).
- **Secrets**: constant-time token compare, redaction on logs/audit/terminal output, desktop token never persisted and never exposed to the renderer (tests enforce).
- **IPC/Electron**: frozen capability regex + trust gate (now with behavioral tests incl. query-string and sibling-file spoofing denials), contextIsolation/sandbox/webSecurity on, navigation + popup guards, 2 MB response caps.
- **Release hygiene**: dev `.env` no longer shipped (scripts generate from `.env.example`); shipped runtime state and caches removed; production refuses dev auth configuration (import-time validation, tested).

## 5. Remaining (honest status)

1. **Sandbox execution tests** — BLOCKED: this environment's AppArmor restricts unprivileged userns for unprofiled binaries and there is no root to install setuid bubblewrap. On a real Linux host with `bubblewrap` installed the 31 skipped tests exercise the full jail.
2. **Ollama inference end-to-end** — BLOCKED: release assets unreachable in this sandbox (detection, status reporting, and honest fallback verified; generation/embedding need a host with `ollama` + models).
3. `memory.relevant()` remains keyword-LIKE (embedding retrieval lives in the RAG store) — documented design fact, deferred.
4. `main.py` remains a large module (~1.7k lines) — splitting deferred; no behavioral defect associated.
