# SecureAgent 2.0 — Troubleshooting

Common failures, their causes, and how to fix them. Every fix is real — no "restart and pray".

---

## A. "Ollama is unavailable" / `NOT_INSTALLED`

**Symptom**: The Diagnostics tab shows `ollama: NOT_AVAILABLE` with reason "Ollama binary is not installed (not on PATH)". The Chat tab shows "Generative AI unavailable. Local Core never fabricates AI answers."

**Cause**: The `ollama` binary is not installed on this host, or is not on the `$PATH` that the backend sees.

**Fix**:
```bash
# Install Ollama
curl -fsSL https://ollama.com/install.sh | sh

# Start the service
ollama serve &

# Pull the configured models (check Settings for the names)
ollama pull <chat_model>      # e.g. llama3.2
ollama pull <embedding_model> # e.g. nomic-embed-text

# Verify
ollama --version
curl http://127.0.0.1:11434/api/version
```

After installing, click "Test Connection" in Settings → Ollama, or run `GET /api/v1/diagnostics` and verify `ollama: PASS`.

**What does NOT work**: the system will not fabricate AI answers when Ollama is missing. The `LocalCoreProvider` handles arithmetic, file listing, word count, and current time deterministically; everything else returns `AI_REASONING_UNAVAILABLE`. This is intentional — see spec section 56 ("NO PRETENDING").

---

## B. "LINUX_SANDBOX_UNAVAILABLE" / terminal FAIL

**Symptom**: The Diagnostics tab shows `terminal: FAIL` with reason containing "LINUX_SANDBOX_UNAVAILABLE". The Terminal tab returns 409 for every command.

**Cause**: The bubblewrap (`bwrap`) binary is not installed, or unprivileged user namespaces are disabled.

**Fix**:
```bash
# Install bubblewrap
sudo apt install bubblewrap    # Debian/Ubuntu
sudo dnf install bubblewrap    # Fedora
sudo pacman -S bubblewrap      # Arch

# Verify unprivileged user namespaces are enabled
cat /proc/sys/kernel/unprivileged_userns_clone
# Should print 1. If 0:
echo 1 | sudo tee /proc/sys/kernel/unprivileged_userns_clone

# Verify bwrap works
bwrap --unshare-user --unshare-pid --unshare-net /bin/true && echo OK
```

After installing, restart the backend and run `GET /api/v1/diagnostics` — `terminal` should now be `PASS`.

**Workaround**: if you cannot install bwrap, you can switch to `HOST_CONTROL` mode (requires explicit confirmation) which runs commands directly on the host with the 5-tier command classifier still enforcing safety. This is less secure than the sandbox but functional.

---

## C. "AUTHENTICATION_REQUIRED" (401)

**Symptom**: Every API call returns 401 with `error.code: AUTHENTICATION_REQUIRED`.

**Cause**: `SECURE_AGENT_AUTH_REQUIRED=true` is set but no token is being sent, or the token is wrong.

**Fix**:
1. In the Dashboard, open Settings → API ACCESS, enter the token, click Connect.
2. Or set the `Authorization: Bearer <token>` header (or `X-API-Token: <token>`) on every request.
3. The token is configured via `SECURE_AGENT_API_TOKEN` in `.env`.

**Development bypass**: if `SECURE_AGENT_ENVIRONMENT=development` and `SECURE_AGENT_ALLOW_UNAUTHENTICATED_LOCALHOST=true`, requests from `127.0.0.1` / `::1` bypass auth. This is disabled in production.

---

## D. "SECUREAGENT_STOPPED" (409)

**Symptom**: Mode changes, terminal execution, and automation return 409 with `error.code: SECUREAGENT_STOPPED`.

**Cause**: Emergency Stop is active. The backend is in a locked-down state.

**Fix**: Click the RESUME button in the header (it replaces STOP ALL when emergency is active), or call `POST /api/v1/resume`.

**What Emergency Stop does**:
- Cancels every running agent task (`ExecutionRegistry.request_cancel`)
- Kills every running terminal process group (`os.killpg(SIGKILL)`)
- Cancels every running automation job (`automation.cancel_all`)
- Disables `host_control`
- Persists the locked-down state
- Preserves all audit logs

**What it does NOT do**: it does not lose data, corrupt the database, or require a restart. Resume restores the pre-emergency ControlState exactly.

---

## E. "RATE_LIMITED" (429)

**Symptom**: API calls return 429 with `error.code: RATE_LIMITED` and a `Retry-After` header.

**Cause**: You exceeded the rate limit for a group (default 60/min for most groups, 5/min for auth).

**Fix**: wait `Retry-After` seconds and retry. The limits are configurable via `SECURE_AGENT_RATE_LIMIT_*` env vars.

**Debug**: the limit is per-(client, group). The group is derived from the path: `/auth/*` → auth, `/chat` → chat, `/agent/*` or `/orchestrate` → agent, `/tools/*` or `/terminal/*` → tools, `/schedule*` → automation, everything else → default.

---

## F. "AI_REASONING_UNAVAILABLE" (502/503)

**Symptom**: `POST /orchestrate` returns `status: failed` with `answer: AI_REASONING_UNAVAILABLE: Ollama is required for generative agent reasoning.`

**Cause**: Ollama is not reachable, or the configured chat model is not installed.

**Fix**:
1. Verify Ollama is running: `curl http://127.0.0.1:11434/api/version`
2. Verify the configured chat model is installed: `ollama list`
3. If the model is missing: `ollama pull <model_name>`
4. Click "Test Chat" in Settings → Ollama to verify inference works.

**What still works without Ollama**: the `LocalCoreProvider` handles arithmetic (`What is 17 * 23?` → `391`), file listing, word count, and current time. Everything else returns the honest `AI_REASONING_UNAVAILABLE` error.

---

## G. "TERMINAL_COMMAND_BLOCKED"

**Symptom**: `POST /api/v1/terminal/execute` returns 400 with `error.code: TERMINAL_COMMAND_BLOCKED`.

**Cause**: The command was classified as `BLOCKED` by the 5-tier command policy engine. This is the highest-risk tier — the command is refused outright, not just approval-gated.

**Examples of BLOCKED commands**:
- `rm -rf /` — destructive system operation
- `dd if=/dev/zero of=/dev/sda` — destructive disk operation
- `:(){ :|:& };:` — fork bomb
- `mkfs.ext4 /dev/sda1` — format disk
- Interactive shells (`bash`, `sh`, `python` without `-c`) in RESTRICTED_AGENT mode

**Fix**: don't run these commands. If you genuinely need to perform a destructive operation, use `HOST_CONTROL` mode (requires explicit confirmation) and run the command outside SecureAgent.

**Debug**: the response includes the classification `reasons` and `matched_rules`. The full classifier is in `backend/app/terminal_policy.py` (969 lines).

---

## H. "PATH_FORBIDDEN" or "SENSITIVE_PATH_FORBIDDEN" (403)

**Symptom**: `POST /api/v1/filesystem/paths` returns 403 with `error.code: PATH_FORBIDDEN` or `SENSITIVE_PATH_FORBIDDEN`.

**Cause**: You tried to add a protected path (`/`, `/proc`, `/sys`, `/dev`, `/boot`, `/root`, `/etc/shadow`, `/etc/sudoers`) as an allowed terminal workspace.

**Fix**: these paths can never be allowed. Use a subdirectory of your home directory or `/tmp` instead.

**For sensitive paths** (`/etc`, `/usr`, `/var`, etc.): the endpoint returns `SENSITIVE_PATH_REQUIRES_CONFIRMATION` — repeat the request with `confirm: true` in the body to allow it. The sandbox still jails execution; this just adds the path to the allowed list.

---

## I. "HOST_CONTROL_REQUIRES_CONFIRMATION" (422)

**Symptom**: `PATCH /api/v1/config` returns 422 with `error.code: HOST_CONTROL_REQUIRES_CONFIRMATION`.

**Cause**: You tried to enable `host_control.enabled` without explicit confirmation. This is a spec section 6 requirement — the AI cannot enable Host Control on its own.

**Fix**: repeat the request with `?confirm=true` query parameter:
```bash
curl -X PATCH -H "Content-Type: application/json" \
  -d '{"host_control":{"enabled":true}}' \
  "http://127.0.0.1:8000/api/v1/config?confirm=true"
```

**What Host Control does**: allows the terminal executor to run commands directly on the host (no bubblewrap sandbox). The 5-tier command classifier still enforces safety, but the kernel-level isolation is gone. Use only when you trust the commands you're running.

---

## J. Frontend shows stale data after Control Center change

**Symptom**: You toggled a switch in the Control Center, but the Dashboard still shows the old state.

**Cause in 1.3.4**: the Dashboard polled every 15s and paused while busy. You could wait up to 15s for the change to appear.

**Fix in 2.0**: the Dashboard now subscribes to `onConfigSync` (an IPC event broadcast by the desktop main process to all windows). Changes appear immediately. If you still see stale data:
1. Click the Refresh button in the header.
2. Check the desktop logs (`~/.config/secureagent/logs/*.log`) for `config-watcher` errors.
3. Verify the SSE endpoint works: `curl http://127.0.0.1:8000/api/v1/config/events` (should stream `event: config` lines).

---

## K. Backend won't start in production

**Symptom**: `python -m uvicorn app.main:app --host 0.0.0.0 --port 8000` fails with `REFUSING_TO_START: production mode requires SECURE_AGENT_AUTH_REQUIRED=true`.

**Cause**: the production host-binding guard refuses to start if auth is disabled and the host is non-loopback. This is the last line of defense against accidentally exposing the terminal API on a LAN.

**Fix**: set `SECURE_AGENT_ENVIRONMENT=production`, `SECURE_AGENT_AUTH_REQUIRED=true`, and `SECURE_AGENT_API_TOKEN=<strong 32+ char token>` in `.env`. Or use `--host 127.0.0.1` to bind only to loopback.

---

## L. Diagnostic shows "automation: WARNING (gate currently paused/disabled)"

**Symptom**: The Diagnostics tab shows `automation: WARNING` with reason "Automation loop is running (gate currently paused/disabled)".

**Cause**: The automation worker is alive, but the Control Center `automation_active()` gate is OFF. This happens when:
- The `automation.enabled` master switch is OFF in the Control Center.
- The `automation.paused` flag is True (set by Emergency Stop or Pause All).
- Emergency Stop is active.

**Fix**:
1. Click RESUME in the header if emergency is active.
2. Open the Control Center and toggle the Automation master switch ON.
3. If paused, click "Resume All" in the Automation tab.
4. Re-run diagnostics to verify `automation: PASS`.

---

## L2. LINUX_SANDBOX_UNAVAILABLE on Debian 13+ (or other AppArmor userns-restricted hosts)

**Symptom**: terminal commands are rejected with
`LINUX_SANDBOX_UNAVAILABLE: the complete bubblewrap user+mount+pid+network namespace profile is unavailable`
even though `bubblewrap` is installed and `unshare --user echo ok` works.

**Cause**: Debian 13 (trixie) ships `kernel.apparmor_restrict_unprivileged_userns=1`.
Unprofiled binaries (including a manually-extracted `bwrap`) are then barred from
creating user namespaces, so the sandbox probe fails. Check with:

```bash
sysctl kernel.unprivileged_userns_clone kernel.apparmor_restrict_unprivileged_userns
```

**Impact**: RESTRICTED_AGENT sandboxed execution is unavailable. The backend fails
CLOSED — it will never silently run the command unsandboxed.

**Fix** (pick one):

```bash
# 1. Preferred: install bubblewrap from the distro (ships a permitted profile / setuid config)
sudo apt install bubblewrap

# 2. Host-level: relax the AppArmor userns restriction if your threat model allows
sudo sysctl -w kernel.apparmor_restrict_unprivileged_userns=0
```

**Alternative**: switch the terminal to HOST_CONTROL (Control Center → Terminal Mode,
explicit confirmation required) so commands run on the host under the full policy
engine without the namespace jail. Every execution stays classified, audited, and
approval-gated; the mode auto-disables on backend exit when `auto_off_on_exit` is set.

## M. Audit log is empty

**Symptom**: The Audit Logs tab shows "No audit records."

**Cause**: either no auditable actions have happened yet, or the audit trail was cleared.

**Fix**: perform any action (run a terminal command, create a memory, apply a mode preset) and refresh. Every meaningful action is audited. If the trail was cleared, the clear itself is audited as `audit.cleared` — check for that event.

**To export the audit trail**: `POST /api/v1/audit/export` writes a JSONL file to `data/exports/audit-export-<timestamp>.jsonl`.

**To clear the audit trail**: `POST /api/v1/audit/clear {"confirm": true}` — requires explicit confirmation. The clear itself is recorded as `audit.cleared` so the trail is never silently empty.

---

## N. Reporting a bug

When reporting a bug, include:

1. The output of `GET /api/v1/diagnostics` (the real feature status).
2. The output of `GET /api/v1/health` (the health_v2 block).
3. The relevant audit entries: `GET /api/v1/audit?limit=50`.
4. The backend logs (JSONL in `~/.config/secureagent/logs/` or wherever `SECURE_AGENT_LOG_DIR` points).
5. The exact steps to reproduce.
6. The expected vs actual behavior.

**Never** report "it doesn't work" without the diagnostics output — the diagnostics are designed to tell us exactly what is broken and why.
