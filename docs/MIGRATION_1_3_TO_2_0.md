# SecureAgent 2.0 — Migration Guide (1.3.4 → 2.0)

This guide explains what changed between SecureAgent 1.3.4 and 2.0, how your existing configuration maps to the new system, and what you need to do.

---

## A. What changed (summary)

SecureAgent 2.0 is a **targeted improvement** of 1.3.4, not a rewrite. The security primitives (sandbox, command classifier, path enforcement, SSRF defense, audit trail) are unchanged — they were already real. The 2.0 work focused on:

1. **Honesty fixes** — every health field is now a real probe; the new `/diagnostics` endpoint runs 10 real self-tests.
2. **UX simplification** — a single SAFE/ASSIST/CONTROL mode surface replaces the need to understand the 13 underlying policy surfaces.
3. **Globally accessible Emergency Stop** — the Dashboard header now has a STOP ALL button (was only in the Control Center).
4. **Live config sync** — the Dashboard refreshes immediately when the Control Center toggles a switch (was 15s polling).
5. **Fixed chat Stop button** — now cancels the backend task too (was client-only abort, misleading).
6. **Dead code removal** — the unreachable `confirmNeeded` branch in the terminal panel is gone.
7. **Version bump** — `1.3.4` → `2.0.0`.

---

## B. Old setting → New setting mapping

The underlying `ControlState` config schema is **unchanged** — your existing `data/control_center.json` file works as-is. The 2.0 additions are pure superset.

### B.1 One-click presets (unchanged)

The existing presets still work:

| Old preset (1.3.4) | New alias (2.0) | Behavior |
|---|---|---|
| `safe` | `SAFE` | read-only; no system-changing actions; automation off |
| `development` | `ASSIST` | normal agent operation; localhost network; automation on |
| `security_lab` | (no alias) | sudo approval-required; automation on; workflows on |
| `full_control` | `CONTROL` | sudo approval-required; full network; automatic workflows |

**Migration**: nothing to do. `POST /api/v1/config/preset {"name":"safe"}` still works. The new `POST /api/v1/mode {"mode":"SAFE"}` is an alias that applies the same patch.

### B.2 Settings tab controls (unchanged but de-emphasized)

The ~40 controls in the Settings tab still work. In 2.0, the recommended workflow is:

1. **Start with a mode preset** — click SAFE, ASSIST, or CONTROL in the header.
2. **Adjust only if needed** — open Settings only for advanced tuning.
3. **Use Diagnostics** — click the Diagnostics tab to verify every feature works after changes.

### B.3 Health endpoint (enhanced, backward-compatible)

`GET /api/v1/health` now returns additional fields:

```json
{
  "status": "ok",                    // unchanged
  "version": "2.0.0",                // was "1.3.4"
  "database": "ok",                  // unchanged (but now real-probed)
  "tools": "ok",                     // unchanged (but now real-probed)
  ...                                // all 1.3.4 fields preserved
  "health_v2": {                     // NEW — richer model
    "overall": "READY",
    "database": "READY",
    "ollama": "NOT_INSTALLED",       // honest — was hardcoded "ok" before
    ...
  },
  "tool_counts": {"enabled": 22, "total": 26, "disabled": 4},  // NEW
  "ollama_detail": {"on_path": false, "reachable": false, ...}  // NEW
}
```

**Migration**: existing clients that read `health.database` etc. continue to work. New clients should prefer `health.health_v2.*` for the richer model.

### B.4 New endpoints (additive)

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v1/diagnostics` | GET | Run all 10 feature self-tests; returns real verdicts |
| `/api/v1/mode` | GET | Return current effective SAFE/ASSIST/CONTROL mode |
| `/api/v1/mode` | POST | Apply a mode preset (alias for `/config/preset`) |

All existing endpoints are unchanged.

---

## C. Behavioral changes

### C.1 Health checks are now real (may surface previously-hidden failures)

In 1.3.4, `health.database`, `health.tools`, `health.configuration`, `health.permissions`, `health.logs` were all hardcoded to `"ok"`. In 2.0, they are real probes:

- `database`: `store.ping()` runs `SELECT 1`
- `tools`: counts `tool.enabled` from the registry
- `configuration`: `ControlState` validates and is loaded
- `permissions`: mandatory protections are enforced
- `logs`: a log handler is attached

**Impact**: if your monitoring was relying on these fields always being `"ok"`, you may now see `"error"` or `"degraded"` when something is actually wrong. This is the correct behavior — the 2.0 principle is "never fake status".

### C.2 Chat Stop button now cancels the backend task

In 1.3.4, clicking "Stop" in the chat composer only aborted the client HTTP request; the backend task kept running. In 2.0, it also calls `POST /api/v1/agent/tasks/{id}/cancel` for the latest task.

**Impact**: clicking Stop now actually stops the task. The previous notice "Generation request cancelled. Refresh Tasks to see any backend result already committed." is still shown but the backend task is now also cancelled.

### C.3 Dashboard refreshes immediately on Control Center changes

In 1.3.4, the Dashboard waited up to 15s to see changes made in the Control Center. In 2.0, it subscribes to `onConfigSync` and refreshes immediately.

**Impact**: no action required. This is a pure improvement.

### C.4 Dead `confirmNeeded` branch removed

In 1.3.4, the terminal panel declared a `confirmNeeded` state that was never set to a truthy value, making the approval card unreachable. In 2.0, the dead branch is removed.

**Impact**: no user-visible change. The real approval flow happens server-side (the backend returns 403 with `TERMINAL_APPROVAL_REQUIRED` if the user must confirm, which the catch block surfaces as an error).

---

## D. Configuration file compatibility

| File | 1.3.4 | 2.0 | Migration |
|---|---|---|---|
| `.env` (`SECURE_AGENT_*`) | yes | yes | no changes — all env vars preserved |
| `data/control_center.json` | yes | yes | no changes — schema unchanged |
| `data/state.db` (SQLite) | yes | yes | no changes — schema unchanged (migrations 001-004 still apply) |
| `data/exports/*.jsonl` | yes | yes | no changes |

**Your existing data directory works as-is.** Just restart the backend.

---

## E. API contract version

The `API_CONTRACT_VERSION` stays at `"1.0.0"` — the contract is backward-compatible. The 2.0 additions are pure superset (new endpoints, new fields in `/health`).

The FastAPI app version (returned by `/health.version` and the OpenAPI spec) is bumped from `"1.3.4"` to `"2.0.0"`.

---

## F. Testing your migration

After upgrading, run:

```bash
# 1. Start the backend
cd backend && python -m uvicorn app.main:app --host 127.0.0.1 --port 8000

# 2. Verify health (should show version 2.0.0 and health_v2 block)
curl http://127.0.0.1:8000/api/v1/health | python -m json.tool

# 3. Run diagnostics (should show real verdicts for every feature)
curl http://127.0.0.1:8000/api/v1/diagnostics | python -m json.tool

# 4. Verify mode (should show SAFE, ASSIST, CONTROL, or CUSTOM)
curl http://127.0.0.1:8000/api/v1/mode

# 5. Apply a mode preset
curl -X POST -H "Content-Type: application/json" -d '{"mode":"ASSIST"}' http://127.0.0.1:8000/api/v1/mode

# 6. Run the clean-start validation
python scripts/clean_start_validation.py
```

If every step succeeds, your migration is complete.

---

## G. Rollback

If you need to roll back to 1.3.4:

1. Stop the backend.
2. Restore the 1.3.4 codebase.
3. Restart — your `data/` directory is compatible.

The 2.0 changes are purely additive (new endpoints, new fields, frontend updates). No database migration is required in either direction.

---

## H. Getting help

- **Audit report**: `docs/SECUREAGENT_2_AUDIT.md` — full findings from the 1.3.4 codebase audit
- **Feature status**: `docs/FEATURE_STATUS.md` — verification matrix with evidence
- **Troubleshooting**: `docs/TROUBLESHOOTING.md` — common failures and fixes
- **Architecture**: `docs/ARCHITECTURE.md` — updated architecture diagram
- **Security model**: `docs/SECURITY.md` and `docs/SANDBOX_SECURITY_MODEL.md` — unchanged from 1.3.4
