# SecureAgent API Reference

SecureAgent exposes a versioned REST API under the `/api/v1` prefix. All
routes are served by the FastAPI backend, which in desktop mode is bound to
the loopback interface on a dynamic port selected by the Electron shell. The
HTTP surface is identical in the Docker container, except that authentication
is always required and the host is determined by the deployment.

## Conventions

- **API prefix**: `/api/v1`
- **API contract version header**: every response carries
  `X-API-Contract-Version: 1`.
- **Request correlation**: every response carries `X-Request-ID`. If the
  caller supplies `X-Request-ID`, the value is reused when it matches
  `^[A-Za-z0-9._-]{1,128}$`; otherwise a fresh ULID is generated.
- **Authentication**: protected routes require
  `Authorization: Bearer <token>`. The token is either configured via
  `SECURE_AGENT_API_TOKEN` (production) or generated per Electron launch and
  never persisted.
- **Error envelope**: errors return a consistent JSON body:

  ```json
  {
    "error": {
      "code": "NETWORK_POLICY_BLOCKED",
      "message": "external network targets are disabled by Network settings",
      "details": { "url": "https://example.test" },
      "request_id": "01J9KBK3..."
    }
  }
  ```

- **Rate limiting**: per-route sliding window counters are enforced. Limits
  are configurable through `SECURE_AGENT_RATE_LIMIT_*` settings.
- **CORS**: explicit origins only. Wildcard and `null` are rejected during
  configuration validation.

## Public routes

These routes do not require authentication and exist for liveness and
configuration discovery only.

| Method | Path | Purpose |
|---|---|---|
| `GET` | `/health` | Minimal liveness probe |
| `GET` | `/api/v1/health` | Liveness with component summary |
| `GET` | `/api/v1/auth/status` | Reports whether authentication is required and which model the backend is configured to use |

## Protected routes

All other routes require a valid bearer token.

### Chat and orchestration

| Method | Path | Body | Returns |
|---|---|---|---|
| `POST` | `/api/v1/chat` | `ChatRequest` | `ChatResponse` with model, content, and token counts |
| `POST` | `/api/v1/orchestrate` | `AgentRequest` | Delegated agent plan |
| `POST` | `/api/v1/agent/tasks` | `AgentRequest` | `Task` with status, plan, and step list |
| `GET` | `/api/v1/agent/tasks` | `?status=...&limit=...` | Recent tasks |
| `GET` | `/api/v1/agent/tasks/{item_id}` | – | Single task with steps |
| `POST` | `/api/v1/agent/tasks/{item_id}/cancel` | – | Task cancellation request |
| `POST` | `/api/v1/agent/tasks/{item_id}/reject` | – | Reject an approval step |
| `POST` | `/api/v1/agent/tasks/{item_id}/resume` | `{approved_permissions: [...]}` | Resume a waiting task |

Chat is non-streaming. Generative content requires Ollama; otherwise the
`Local Core` provider returns deterministic tool plans and explicit
`AI_REASONING_UNAVAILABLE` errors for unsupported generative requests.

### Memory and audit

| Method | Path | Body | Returns |
|---|---|---|---|
| `GET` | `/api/v1/memories` | `?q=...&limit=...` | Recent or relevant memories |
| `POST` | `/api/v1/memories` | `MemoryIn` | Stored memory record |
| `PATCH` | `/api/v1/memories/{item_id}` | partial memory | Updated memory |
| `DELETE` | `/api/v1/memories/{item_id}` | – | 204 |
| `GET` | `/api/v1/audit` | `?limit=...&event=...` | Audit records with redacted secret-shaped fields |

### Knowledge base and documents

| Method | Path | Body | Returns |
|---|---|---|---|
| `GET` | `/api/v1/documents` | – | Indexed documents |
| `POST` | `/api/v1/documents` | multipart upload | Document metadata |
| `DELETE` | `/api/v1/documents/{item_id}` | – | 204 |
| `POST` | `/api/v1/documents/search` | `SearchRequest` | Ranked retrieval chunks |

Documents are bounded by `max_document_bytes`, `max_chunks_per_document`, and
`max_total_documents`. Search returns at most `max_retrieval_chunks` ranked
chunks; embedding generation requires the configured Ollama embedding model.

### Tools and permissions

| Method | Path | Returns |
|---|---|---|
| `GET` | `/api/v1/tools` | Tool definitions with input/output schemas, risk level, permissions, sandbox/network requirements, and supported platforms |

Tools are policy-bearing: the registry refuses to execute a tool unless the
caller supplies the matching `Permission` set. High-risk tools additionally
require an explicit per-step approval.

### Linux terminal agent

The Linux terminal backend (`SECURE_AGENT_TERMINAL_BACKEND=linux`) exposes a
controlled host shell. Every command passes the fail-closed Registry, the
Permission Engine, and the Command Safety Engine
(`safe / low_risk / requires_approval / high_risk / blocked`) before
`/bin/bash` runs it inside the approved workspace jail with a scrubbed
environment, hard output caps, wall-clock timeout, and cancellation.

| Method | Path | Body / query | Returns |
|---|---|---|---|
| `GET` | `/api/v1/terminal/status` | – | Backend, availability, shell, allowed roots, sudo policy |
| `POST` | `/api/v1/terminal/execute` | `TerminalExecuteIn` | Execution snapshot (stdout/stderr/exit/duration/risk/classification) |
| `GET` | `/api/v1/terminal/history` | `?limit=&query=` | Redacted execution history (SQLite) |
| `GET` | `/api/v1/terminal/executions/{item_id}` | – | Live snapshot while running; stored summary afterwards |
| `POST` | `/api/v1/terminal/executions/{item_id}/cancel` | – | Kill the process group of a running execution |

Behavioral contract:

- `safe` / `low_risk` commands execute immediately.
- `requires_approval` / `high_risk` return HTTP 403
  `TERMINAL_APPROVAL_REQUIRED` unless the request carries `confirm: true`
  (the UI shows an explicit approval dialog with the exact command).
- `blocked` commands are always rejected (`TERMINAL_COMMAND_BLOCKED`), even
  with confirmation. Approval never promotes a blocked command.
- `sudo` runs non-interactively (`sudo -n`). When sudo needs a password the
  API surfaces `SUDO_PASSWORD_REQUIRED`; SecureAgent never collects, stores,
  or logs passwords.

### One-click security workflows and reports

Deterministic Security Engine workflows run fixed read-only commands and
pure-Python checks; findings are labeled `OBSERVED`, `INFERRED`,
`RECOMMENDED`, or `NOT_AVAILABLE`. Nothing is invented and nothing is
uploaded.

| Method | Path | Body | Returns |
|---|---|---|---|
| `GET` | `/api/v1/workflows` | – | Workflow catalog |
| `POST` | `/api/v1/workflows/{name}/run` | `{"path": "...", "lines": n}` scope | Full `SecurityReport` |
| `GET` | `/api/v1/reports` | `?limit=` | Report index |
| `GET` | `/api/v1/reports/{item_id}` | – | Stored report payload |

Workflow names: `system_audit`, `network_discovery` (local only),
`log_analysis`, `file_security_audit`.

### Permission Center and notifications

| Method | Path | Body | Returns |
|---|---|---|---|
| `GET` | `/api/v1/permissions/grants` | – | Persistent ("always allow") grants |
| `POST` | `/api/v1/permissions/grants` | `GrantIn` | Created grant (`admin` is refused) |
| `DELETE` | `/api/v1/permissions/grants/{item_id}` | – | Revoke grant |
| `GET` | `/api/v1/notifications` | – | Derived alerts: waiting approvals, failed tasks, Ollama health, failing automations, high-severity findings |
| `GET` | `/api/v1/system/info` | – | Linux auto-detection: distro, kernel, arch, shell, toolchain inventory |

Persistent grants are loaded by the agent on every task and unioned with the
existing per-conversation session approvals. They never bypass BLOCKED
command enforcement.

### Schedules and automation

| Method | Path | Body | Returns |
|---|---|---|---|
| `GET` | `/api/v1/schedules` | – | Enabled and disabled schedules |
| `POST` | `/api/v1/schedules` | `ScheduleIn` | Stored schedule |
| `PATCH` | `/api/v1/schedules/{item_id}` | partial schedule | Updated schedule |
| `POST` | `/api/v1/schedules/{item_id}/approve` | – | Approve pending schedule |
| `POST` | `/api/v1/schedules/{item_id}/cancel` | – | Cancel schedule |
| `GET` | `/api/v1/schedule-runs` | `?schedule_id=...&limit=...` | Execution history |

Automation is opt-in. When `SECURE_AGENT_ENABLE_AUTOMATION=false`, the
scheduler is dormant and these endpoints are read-only.

### Settings, diagnostics, and models

| Method | Path | Returns |
|---|---|---|
| `GET` | `/api/v1/settings` | Non-secret runtime configuration |
| `GET` | `/api/v1/models` | Installed Ollama models |
| `GET` | `/api/v1/ollama/status` | Provider availability, configured models, and last error |
| `POST` | `/api/v1/ollama/test-chat` | Chat model probe |
| `POST` | `/api/v1/ollama/test-embedding` | Embedding model probe |
| `GET` | `/api/v1/network/test` | Network policy summary |
| `POST` | `/api/v1/network/test` | Probe a specific URL under the current policy |
| `GET` | `/api/v1/diagnostics/{component}` | Component diagnostics (`llm`, `network`, `database`, `sandbox`, `system`) |
| `GET` | `/api/v1/system/health` | Aggregated system health |
| `GET` | `/api/v1/ready` | Readiness probe used by the Electron startup gate |

### Interactive documentation

`/docs` and `/redoc` are protected by the same authentication middleware as
the rest of the API. They are disabled in production builds unless
`SECURE_AGENT_ENVIRONMENT=development`.

## Standard error codes

| Code | Meaning |
|---|---|
| `UNAUTHORIZED` | Missing or invalid bearer token |
| `FORBIDDEN` | Authenticated but not permitted for this operation |
| `VALIDATION_ERROR` | Request body failed Pydantic validation |
| `NOT_FOUND` | Resource does not exist |
| `RATE_LIMITED` | Caller exceeded the configured rate |
| `PERMISSION_REQUIRED` | Tool requires request-scoped approval |
| `AI_REASONING_UNAVAILABLE` | Local Core cannot satisfy a generative request without Ollama |
| `OLLAMA_TIMEOUT` / `OLLAMA_SERVICE_STOPPED` / `MODEL_NOT_FOUND` | Ollama provider errors with recovery hints |
| `NETWORK_POLICY_BLOCKED` | URL, address class, redirect, or response size was rejected |
| `PYTHON_SANDBOX_UNAVAILABLE` | Docker sandbox not configured |
| `INTERNAL_ERROR` | Unhandled server error; details are logged with the request ID |

## Versioning

The contract version is `1`. A future incompatible change will introduce
`/api/v2` and keep `v1` available for one minor release cycle. The
`X-API-Contract-Version` response header lets clients detect drift without
parsing the URL.
