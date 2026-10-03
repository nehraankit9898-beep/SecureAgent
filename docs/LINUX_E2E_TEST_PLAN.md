# Linux End-to-End Test Plan

Run on a clean supported Linux VM as an unprivileged desktop user.

## Matrix

Test Ubuntu 24.04 first. Record kernel, bubblewrap version, user-namespace
sysctl, desktop environment, package format and Ollama version. Add Debian 12
only after Ubuntu passes.

## Procedure

1. Install prerequisites and verify package checksums.
2. Install AppImage, `.deb` and `.tar.gz` independently.
3. Launch and verify backend loopback binding, authentication and readiness.
4. Require the complete bubblewrap capability profile.
5. Run a normal restricted command and verify stdout, stderr and exit code.
6. Run shadow, `/proc`, symlink, shell-indirection, network and privilege
   regressions; inspect child uid, namespaces and mounts externally.
7. Toggle every Control Center feature. Verify API response, persisted
   document, restart state, runtime behavior and audit event.
8. Verify external changes propagate over SSE to Electron.
9. Verify Ollama disconnected, connected and missing-model states.
10. Start terminal, agent and automation work; activate Emergency Stop and
    verify cleanup and denial of new work.
11. Restart while stopped; require explicit Resume.
12. Export audit data and check secret redaction.
13. Quit, relaunch, then uninstall and inspect remaining processes/files.

## Required attacks

Include variables, quoted variables, command substitution, subshells,
redirection, globbing, relative/absolute traversal, symlinks to `/etc/shadow`,
`/root` and `~/.ssh`, `/proc/1/root`, `sudo`, `su`, `pkexec`, `curl`, `wget`,
Python sockets/urllib, `nc` and bash `/dev/tcp`.

## Result policy

Record `PASS`, `FAIL`, `SKIPPED`, `BLOCKED` or `NOT_RUN`. A missing sandbox
primitive is `BLOCKED`, not `PASS`. Preserve output, hashes and host details.