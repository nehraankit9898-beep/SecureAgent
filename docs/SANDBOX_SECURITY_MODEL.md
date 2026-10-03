# Linux Sandbox Security Model

## Modes

- `RESTRICTED_AGENT` is the default and requires the complete sandbox.
- `HOST_CONTROL` is unsandboxed host execution and requires enabling Host
  Control plus a separate confirmed mode change. Policy, permission, approval
  and audit still apply.

There is no automatic elevation.

## Restricted boundary

Restricted execution uses a successfully probed bubblewrap profile:

- new user, mount, PID and network namespaces;
- empty tmpfs root;
- executable/runtime trees exposed read-only;
- host `/etc`, `/home`, `/root`, `/var` and `/run` absent;
- private `/proc`, `/dev` and writable `/tmp`;
- only the approved workspace bind-mounted writable;
- uid/gid 65534 and all capabilities dropped;
- closed stdin, bounded output, timeout and process-group cleanup.

An `unshare` user/PID/network namespace without mount isolation is refused.
Missing or unusable bubblewrap returns `LINUX_SANDBOX_UNAVAILABLE`; there is
no host fallback.

## Defense in depth

Canonical checks reject traversal, protected prefixes, symlinks, hardlinks and
pseudo-filesystem paths for API filesystem operations. A lexical
sensitive-resource guard gives early structured denials but is not the
security boundary. The mount namespace remains authoritative against shell
expansion, substitution, globbing and symlinks.

Restricted mode denies sudo and does not mount host privilege brokers. Child
environments omit application secrets.

## Network

Restricted mode creates a fresh network namespace. Application network policy
independently governs HTTP tools and destination lists.

## Capability report

Status distinguishes installed binaries from a usable profile and reports
user/mount/PID/network namespaces, bubblewrap, firejail, AppArmor, SELinux,
systemd, sudo, pkexec, Ollama, bash and Python.

## Limitations

Writable workspace content is intentionally exposed. Kernel, bubblewrap and
filesystem vulnerabilities are out of scope. Host Control is intentionally
outside the sandbox. Audit storage is not cryptographically tamper-evident.