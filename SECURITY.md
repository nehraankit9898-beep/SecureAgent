# Security Model

## Intended use

Authorized systems, defensive research, lab/CTF environments, and explicitly scoped organizational assets. SecureAgent does not implement unrestricted autonomous offensive behavior.

## Controls

- Fail-closed production bearer authentication with constant-time comparison.
- Request IDs, security headers, bounded request bodies, and per-group process-local rate limits.
- Central `READ`, `WRITE`, `EXECUTE`, `NETWORK`, and `ADMIN` permissions; model output cannot grant them.
- Human approval via waiting tasks and the authenticated resume endpoint.
- Typed tools with risk, timeout, network, sandbox, and audit metadata.
- Central workspace boundary: traversal/absolute/null-byte/reserved-name/symlink defenses, size/count/depth limits, atomic writes, stale hashes, bounded backups.
- Host Python execution disabled. Container policies require immutable image digests, non-root UID, no network, read-only input, dropped capabilities, PID/CPU/memory/output/time bounds.
- Secret-pattern rejection for memory and recursive audit redaction.
- Prompt-injection framing for memories, history, repositories, documents, web results, and tool results.
- Automation stays disabled by default. Bounded HTTP tools are enabled for public
  external destinations with explicit approval; localhost/private-LAN access
  and cloud metadata remain blocked by the layered network policy. Web search
  remains opt-in and requires a configured SearXNG endpoint.

## Deployment requirements

Use a unique random token, TLS at a trusted reverse proxy, restricted CORS, patched dependencies, protected Ollama/SearXNG, log retention, tested backup/restore, and loopback/private-network exposure. Never commit `.env`, mount `/var/run/docker.sock`, use privileged containers, or enable a mutable sandbox image.

## Known limitations

Single-user identity model; process-local rate limiter; mutable application base-image tags; no completed dependency CVE database scan in the supplied offline environment; live sandbox, Ollama, embedding, and Docker runtime require target-environment validation. Security is a risk-reduction property, not a guarantee.

## Reporting

Do not include credentials or sensitive customer data in reports. Provide the affected component, reproducible steps in an authorized environment, impact, and a proposed mitigation.
