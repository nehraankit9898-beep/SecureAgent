# Final Security and Control Center Audit

## Executive Summary

The P0 regression was traced to an `unshare` fallback that retained the host
root mount. It is no longer accepted. Restricted execution now requires a
successfully probed bubblewrap user+mount+PID+network profile and otherwise
fails closed. Recommendation: **NOT READY** pending clean-host verification.

## Architecture

The Electron -> FastAPI -> typed ControlCenter -> deterministic policy ->
runtime architecture is retained. No API was removed.

## Sandbox Security

Implemented empty-root bubblewrap, read-only runtime mounts, private
pseudo-filesystems and `/tmp`, writable approved workspace only, uid/gid
65534 and capability drop. Added reported-indirection and unshare-only
regressions. Current host lacks bubblewrap, so OS attack execution is
`BLOCKED`.

## Control Center

Configuration remains typed, atomic, versioned and broadcast over SSE. Host
Control revocation is checked at spawn. Emergency Stop survives restart and
requires explicit Resume.

## Configuration

`control_center.json` is mutable runtime authority. Environment values are
startup ceilings and cannot override a denial. Legacy feature variables remain
a documented migration risk.

## Terminal

Timeout, cancellation, process groups, stdout/stderr, exit code, working
directory, environment scrubbing and audit paths remain. Restricted mode has
no host fallback.

## Network

Restricted commands use a new network namespace. HTTP tools also use the
application destination policy. A fail-open bug was found in
`SafeHttpClient`: Control Center import/loader errors were converted to
`gate=None`, allowing the request to continue without the runtime master gate.
This now fails closed with `NETWORK_RUNTIME_POLICY_UNAVAILABLE`; both missing
and throwing policy-loader regressions pass. OS namespace verification remains
blocked on this host.

## Permissions

Feature enablement is distinct from operation authorization. Host Control,
sudo, high-risk commands and tools retain separate gates and approvals.

## Ollama

Connectivity/model diagnostics exist. No live Ollama service was verified.

## Audit System

Configuration, terminal, network, host-control and emergency actions have
audit paths with secret redaction. SQLite is not tamper-evident.

## Test Results

- Desktop: `PASS` — 26/26.
- Frontend: `PASS` — 9/9; TypeScript and production build also passed.
- Backend: `FAIL` — 326 passed, 21 failed, 10 skipped. The failures are
  restricted lifecycle tests that expect execution while this host returns
  `LINUX_SANDBOX_UNAVAILABLE`.
- Focused P0 regressions: 3 passed, 7 skipped, 42 deselected. The skips are
  OS-execution cases blocked by missing bubblewrap.
- OS sandbox attacks: `BLOCKED` — bubblewrap unavailable.
- Frozen backend: `PASS` — loopback health, version, database, workspace and
  authentication smoke checks passed.
- AppImage: `PASS` for build/format only; install/launch/uninstall `NOT_RUN`.
- `.tar.gz`: `PASS` for build/archive integrity only; launch/uninstall `NOT_RUN`.
- `.deb`: `FAIL` — electron-builder requires project homepage metadata that is
  not present in the supplied source. No URL was fabricated.
- Package lifecycle as a whole: `NOT_RUN` for install/launch/uninstall.

## Failed Tests

Restricted execution lifecycle tests fail in this environment because the
complete sandbox is unavailable. They must not be redirected to host mode.

## Blocked Tests

OS filesystem, symlink, `/proc`, network, timeout, cancellation and cleanup
execution are blocked by missing bubblewrap.

## Remaining Risks

Clean-host sandbox and packages are unverified; legacy environment ceilings
duplicate policy; audit storage lacks tamper evidence; broad distribution
compatibility is unverified.

## Linux Compatibility

First intended target: Ubuntu 24.04 with usable unprivileged user namespaces
and bubblewrap. Other distributions are not certified.

## Packaging

The build script now calls the declared `npm run dist` command and runs the
real frozen-backend smoke test. AppImage and tar artifacts were produced and
format-checked. The `.deb` build failed because required homepage metadata is
absent; a project URL was not invented. No artifact is marked fully working
until install, launch, backend connection, runtime test and uninstall complete.

## Release Recommendation

**NOT READY**