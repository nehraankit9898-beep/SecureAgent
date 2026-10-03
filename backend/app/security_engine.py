"""Deterministic Security Engine — security checks that never depend on the LLM.

The AI interprets results; this engine produces them. Every check is
deterministic Python (plus fixed read-only commands through the terminal
executor) so that findings exist independently of model availability or
model behavior.

Workflows:

* ``system_audit``         — OS, kernel, users, services, ports, firewall, SSH, permissions
* ``network_discovery``    — local interfaces, routes, DNS, listeners (no external probing)
* ``log_analysis``         — journal/error collection with deterministic suspicious-event detection
* ``file_security_audit``  — authorized-path scan: permissions, SUID, executables, secret patterns

Every finding is labeled:

* OBSERVED     — directly measured evidence (command output / file stat)
* INFERRED     — a deterministic rule judged severity from observed evidence
* RECOMMENDED  — remediation advice (never counted as a finding of fact)
* NOT_AVAILABLE — the check could not run (missing tool, permissions); never faked

The report is persisted (security_reports table) and returned as JSON.
"""

from __future__ import annotations

import os
import re
import stat
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any
from uuid import uuid4

from app.linux_terminal import LinuxTerminalExecutor, redact_output
from app.security import SECRET_PATTERN

WORKFLOWS: dict[str, dict[str, str]] = {
    "system_audit": {
        "title": "System Security Audit",
        "description": "Deterministic posture check: OS, kernel, accounts, services, "
                       "listening ports, firewall, SSH configuration, and key file permissions.",
    },
    "network_discovery": {
        "title": "Network Discovery (local only)",
        "description": "Local interfaces, routing, DNS configuration, listening services, "
                       "and neighbor table. No external or intrusive scanning is performed.",
    },
    "log_analysis": {
        "title": "Log Analysis",
        "description": "Collect recent journal/error logs and detect failed logins, "
                       "crashes, and denials with deterministic patterns.",
    },
    "file_security_audit": {
        "title": "File Security Audit",
        "description": "Scan an authorized directory for world-writable files, SUID/SGID "
                       "binaries, executables in unexpected places, and secret-looking content. "
                       "Nothing is uploaded anywhere.",
    },
}

MAX_FINDINGS_PER_CHECK = 50


@dataclass
class Finding:
    check: str
    status: str            # OBSERVED | INFERRED | RECOMMENDED | NOT_AVAILABLE
    severity: str          # info | low | medium | high | critical
    component: str
    summary: str
    evidence: list[str] = field(default_factory=list)
    recommendation: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "check": self.check,
            "status": self.status,
            "severity": self.severity,
            "component": self.component,
            "summary": self.summary,
            "evidence": self.evidence[:10],
            "recommendation": self.recommendation,
        }


def _sev_order(sev: str) -> int:
    return {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}.get(sev, 0)


class SecurityEngine:
    def __init__(self, executor: LinuxTerminalExecutor | None, store, config):
        self.executor = executor
        self.store = store
        self.config = config

    # -- helpers ------------------------------------------------------------ #

    async def _run(self, argv: list[str]) -> tuple[int, str, str]:
        """Run a fixed read-only vector; failures are reported, never faked."""
        if not self.executor or not self.executor.available:
            raise RuntimeError("TERMINAL_UNAVAILABLE: the Linux terminal backend is disabled")
        from app.linux_terminal import quote_argv
        execution = await self.executor.execute(quote_argv(argv), approval="workflow-fixed")
        snap = execution.snapshot(self.config.terminal_max_output_bytes)
        return execution.exit_code or 0, snap["stdout"], snap["stderr"]

    async def _try(self, argv: list[str]) -> tuple[bool, int, str, str]:
        try:
            code, out, err = await self._run(argv)
            return True, code, out, err
        except (RuntimeError, ValueError, PermissionError) as error:
            return False, -1, "", str(error)[:300]

    @staticmethod
    def _lines(text: str) -> list[str]:
        return [line for line in text.splitlines() if line.strip()]

    # -- workflow: system audit --------------------------------------------- #

    async def system_audit(self, scope: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []

        # 1. OS / kernel / architecture
        ok, code, out, _ = await self._try(["uname", "-r"])
        if ok:
            findings.append(Finding("kernel_version", "OBSERVED", "info", "system",
                                    f"Kernel release: {out.strip()}"))
        else:
            findings.append(Finding("kernel_version", "NOT_AVAILABLE", "info", "system", out or "uname unavailable"))
        ok, code, out, _ = await self._try(["cat", "/etc/os-release"])
        if ok:
            name = next((line for line in self._lines(out) if line.startswith("PRETTY_NAME=")), "")
            findings.append(Finding("distribution", "OBSERVED", "info", "system",
                                    name or "os-release present"))
        else:
            findings.append(Finding("distribution", "NOT_AVAILABLE", "info", "system", "os-release unreadable"))

        # 2. Root-equivalent accounts (deterministic parse)
        ok, code, out, err = await self._try(["cat", "/etc/passwd"])
        if ok:
            root_users = [line.split(":")[0] for line in self._lines(out)
                          if len(line.split(":")) > 2 and line.split(":")[2] == "0"]
            sev = "info" if root_users == ["root"] else "high"
            findings.append(Finding(
                "uid_zero_accounts", "OBSERVED", sev, "accounts",
                f"Accounts with UID 0: {', '.join(root_users)}",
                evidence=root_users,
                recommendation=None if sev == "info" else "Investigate additional UID-0 accounts; only root should have UID 0.",
            ))
            shells = [line.split(":")[-1] for line in self._lines(out)]
            nologin = sum(1 for shell in shells if shell in {"/usr/sbin/nologin", "/bin/false"})
            findings.append(Finding("account_shell_inventory", "OBSERVED", "info", "accounts",
                                    f"{len(self._lines(out))} accounts, {nologin} without login shell"))
        else:
            findings.append(Finding("uid_zero_accounts", "NOT_AVAILABLE", "medium", "accounts",
                                    f"/etc/passwd unreadable: {err}"))

        # 3. Listening ports
        ok, code, out, err = await self._try(["ss", "-tulwn"])
        if ok:
            listeners = self._lines(out)[1:] if ok else []
            findings.append(Finding("listening_ports", "OBSERVED", "info", "network",
                                    f"{len(listeners)} listening sockets"))
            for line in listeners:
                parts = line.split()
                # ss -tulwn: Netid State Recv-Q Send-Q Local:Port Peer:Port
                local = parts[4] if len(parts) >= 6 else ""
                if re.search(r"^(0\.0\.0\.0|\[::\]|\*):", local):
                    findings.append(Finding("listening_ports_wildcard", "INFERRED", "medium", "network",
                                            f"Socket bound to all interfaces: {local}",
                                            evidence=[line.strip()],
                                            recommendation="Confirm this service must accept remote connections; bind it to loopback if local-only."))
        else:
            findings.append(Finding("listening_ports", "NOT_AVAILABLE", "medium", "network", err))

        # 4. Running services
        ok, code, out, err = await self._try(["systemctl", "list-units", "--type=service",
                                              "--state=running", "--no-pager", "--no-legend"])
        if ok:
            services = [line.split()[0] for line in self._lines(out) if line.split()]
            findings.append(Finding("running_services", "OBSERVED", "info", "services",
                                    f"{len(services)} running services", evidence=services[:20]))
            risky = [name for name in services if any(tag in name for tag in
                     ("telnet", "ftp", "rsh", "tftp", "snmp"))]
            for name in risky[:10]:
                findings.append(Finding("legacy_service_running", "INFERRED", "high", "services",
                                        f"Legacy/insecure service is running: {name}",
                                        recommendation="Disable the service if it is not explicitly required."))
        else:
            findings.append(Finding("running_services", "NOT_AVAILABLE", "low", "services",
                                    f"systemctl unavailable: {err}"))

        # 5. Firewall
        for argv, label in ((["ufw", "status"], "ufw"),
                            (["iptables", "-L", "-n"], "iptables"),
                            (["nft", "list", "ruleset"], "nft")):
            ok, code, out, err = await self._try(argv)
            if ok:
                if label == "ufw":
                    active = "Status: active" in out
                    findings.append(Finding("firewall_ufw", "OBSERVED",
                                            "info" if active else "medium", "firewall",
                                            f"ufw status: {'active' if active else 'inactive'}",
                                            recommendation=None if active else "Enable the host firewall (ufw enable) after reviewing rules."))
                else:
                    rules = len(self._lines(out))
                    findings.append(Finding(f"firewall_{label}", "OBSERVED", "info", "firewall",
                                            f"{rules} rules/policies reported by {label}"))
                break
        else:
            findings.append(Finding("firewall", "NOT_AVAILABLE", "medium", "firewall",
                                    "No firewall tooling reachable (ufw/iptables/nft); root may be required"))

        # 6. SSH configuration (deterministic parse; no root needed for 0644 configs)
        ssh_findings = await self._check_ssh()
        findings.extend(ssh_findings)

        # 7. Key file permissions (deterministic stat)
        for path, max_mode, label in (
            ("/etc/passwd", 0o666, "world-writable /etc/passwd"),
            ("/etc/shadow", 0o000, None),   # handled below (root-only expected)
            ("/etc/sudoers", 0o000, None),
        ):
            try:
                info = os.stat(path)
                if info.st_mode & 0o002:
                    findings.append(Finding("file_permissions", "OBSERVED", "high", "permissions",
                                            f"{path} is world-writable (mode {stat.filemode(info.st_mode)})",
                                            recommendation="Restore safe permissions (chmod o-w " + path + ")."))
                else:
                    findings.append(Finding("file_permissions", "OBSERVED", "info", "permissions",
                                            f"{path} mode {stat.filemode(info.st_mode)}"))
            except OSError as error:
                findings.append(Finding("file_permissions", "NOT_AVAILABLE", "low", "permissions",
                                        f"{path}: {error.strerror or 'unavailable'}"))

        # 8. SUID binaries in standard paths (bounded)
        suid = await self._scan_suid(["/usr/bin", "/bin", "/usr/sbin", "/sbin"])
        if suid is None:
            findings.append(Finding("suid_binaries", "NOT_AVAILABLE", "low", "permissions",
                                    "SUID scan could not run"))
        else:
            unexpected = [path for path in suid if not re.search(
                r"/(sudo|su|passwd|chsh|chfn|newgrp|mount|umount|ping|gpasswd|fusermount3?|crontab|pkexec|chage|expiry|sg|staprun|at|mtr-packet|unix_chkpwd)$", path)]
            findings.append(Finding("suid_binaries", "OBSERVED", "info", "permissions",
                                    f"{len(suid)} SUID binaries found in standard paths"))
            for path in unexpected[:10]:
                findings.append(Finding("suid_unexpected", "INFERRED", "medium", "permissions",
                                        f"Unexpected SUID binary: {path}",
                                        recommendation="Verify the binary is packaged and expected; remove or restrict if unknown."))

        # 9. Pending remediation summary
        findings.append(Finding("audit_scope", "RECOMMENDED", "info", "policy",
                                "Run this audit periodically and review NOT_AVAILABLE entries: "
                                "they usually require elevated privileges (sudo) that SecureAgent never bypasses."))
        return findings

    async def _check_ssh(self) -> list[Finding]:
        findings: list[Finding] = []
        config_path = Path("/etc/ssh/sshd_config")
        try:
            text = config_path.read_text(encoding="utf-8", errors="replace")[:200000]
        except OSError as error:
            return [Finding("ssh_configuration", "NOT_AVAILABLE", "medium", "ssh",
                            f"{config_path} unreadable: {error.strerror or 'permission denied'} (root-readable on hardened systems)")]
        values: dict[str, str] = {}
        for line in text.splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            key, _, value = line.partition(" ")
            values.setdefault(key, value.strip())
        checks = (
            ("PermitRootLogin", "yes", "high", "Direct root SSH login is permitted",
             "Set PermitRootLogin no or prohibit-password."),
            ("PasswordAuthentication", "yes", "medium", "SSH password authentication is enabled",
             "Prefer key-based authentication (PasswordAuthentication no)."),
            ("PermitEmptyPasswords", "yes", "critical", "SSH permits empty passwords",
             "Set PermitEmptyPasswords no."),
            ("X11Forwarding", "yes", "low", "X11 forwarding is enabled",
             "Disable X11Forwarding if not required."),
            ("Protocol", "1", "critical", "Legacy SSH protocol 1 enabled", "Use protocol 2 (default on modern OpenSSH)."),
        )
        reported = False
        for key, bad, severity, message, fix in checks:
            if key in values and values[key].lower() == bad:
                findings.append(Finding("ssh_configuration", "OBSERVED", severity, "ssh",
                                        f"{key} {values[key]} — {message}",
                                        recommendation=fix))
                reported = True
        if "PermitRootLogin" in values or "PasswordAuthentication" in values:
            reported = True
        if not reported:
            findings.append(Finding("ssh_configuration", "OBSERVED", "info", "ssh",
                                    "sshd_config parsed; no insecure defaults detected"))
        return findings

    async def _scan_suid(self, roots: list[str]) -> list[str] | None:
        suid: list[str] = []
        try:
            for root in roots:
                base = Path(root)
                if not base.is_dir():
                    continue
                count = 0
                for entry in base.iterdir():
                    count += 1
                    if count > 5000:
                        break
                    try:
                        info = entry.stat()
                    except OSError:
                        continue
                    if stat.S_ISREG(info.st_mode) and info.st_mode & 0o4000:
                        suid.append(str(entry))
        except OSError:
            return None
        return suid

    # -- workflow: network discovery ---------------------------------------- #

    async def network_discovery(self, scope: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        steps = (
            (["ip", "-brief", "address"], "interfaces"),
            (["ip", "route"], "routing_table"),
            (["cat", "/etc/resolv.conf"], "dns_configuration"),
            (["ss", "-tulwn"], "listening_services"),
            (["ip", "neigh"], "neighbor_table"),
        )
        for argv, label in steps:
            ok, code, out, err = await self._try(argv)
            if ok:
                findings.append(Finding(label, "OBSERVED", "info", "network",
                                        f"{label.replace('_', ' ').title()}: {len(self._lines(out))} lines collected",
                                        evidence=self._lines(out)[:15]))
            else:
                findings.append(Finding(label, "NOT_AVAILABLE", "low", "network",
                                        f"{argv[0]} failed: {err}"))
        findings.append(Finding("external_scanning", "RECOMMENDED", "info", "policy",
                                "This workflow inspects the local machine only. Active scanning of any "
                                "external target requires explicit authorization and is not automated here."))
        return findings

    # -- workflow: log analysis ---------------------------------------------- #

    SUSPICIOUS = (
        (re.compile(r"failed password|authentication failure|auth failure", re.I), "failed_authentication", "medium"),
        (re.compile(r"invalid user", re.I), "unknown_user_login_attempt", "medium"),
        (re.compile(r"segfault|general protection", re.I), "process_crash", "low"),
        (re.compile(r"denied|blocked|refused", re.I), "access_denial", "low"),
        (re.compile(r"out of memory|oom-killer|killed process", re.I), "memory_exhaustion", "medium"),
        (re.compile(r"raid.*error|disk.*error|i/o error", re.I), "storage_error", "high"),
    )

    async def log_analysis(self, scope: dict[str, Any]) -> list[Finding]:
        findings: list[Finding] = []
        limit = int(scope.get("lines", 200))
        limit = max(50, min(limit, 1000))
        ok, code, out, err = await self._try(["journalctl", "-n", str(limit), "--no-pager"])
        source = "journalctl"
        if not ok or (code == 0 and not out.strip()):
            ok, code, out, err = await self._try(["dmesg", "--level=err,warn", "--color=never"])
            source = "dmesg"
        if not ok:
            findings.append(Finding("log_collection", "NOT_AVAILABLE", "medium", "logs",
                                    f"journalctl and dmesg unavailable: {err} (root may be required)"))
            return findings
        lines = self._lines(out)
        findings.append(Finding("log_collection", "OBSERVED", "info", "logs",
                                f"Collected {len(lines)} lines from {source}"))
        for pattern, label, severity in self.SUSPICIOUS:
            hits = [line for line in lines if pattern.search(line)]
            if hits:
                findings.append(Finding(label, "INFERRED", severity, "logs",
                                        f"{len(hits)} suspicious event(s) matched '{label}'",
                                        evidence=[redact_output(h.strip()[:300]) for h in hits[:5]],
                                        recommendation="Review the quoted log lines in context with: journalctl -g " + label))
        if not any(item.status == "INFERRED" for item in findings):
            findings.append(Finding("suspicious_events", "OBSERVED", "info", "logs",
                                    "No suspicious patterns matched in the collected window"))
        findings.append(Finding("log_retention", "RECOMMENDED", "info", "logs",
                                "For deeper history, run: journalctl --since=-7d -p warning --no-pager"))
        return findings

    # -- workflow: file security audit ---------------------------------------- #

    async def file_security_audit(self, scope: dict[str, Any]) -> list[Finding]:
        target_raw = scope.get("path") or "."
        findings: list[Finding] = []
        if not self.executor:
            return [Finding("file_security_audit", "NOT_AVAILABLE", "medium", "filesystem",
                            "terminal backend disabled")]
        try:
            base = self.executor.resolve_cwd(target_raw)
        except (ValueError, PermissionError) as error:
            raise ValueError(f"audit scope rejected: {error}") from error
        findings.append(Finding("audit_scope", "OBSERVED", "info", "filesystem",
                                f"Scanning {base} (local analysis only; nothing is uploaded)"))
        world_writable = 0
        suid = 0
        executables = 0
        secret_hits: list[tuple[str, str]] = []
        scanned = 0
        max_files = 20000
        skip_names = {".git", "node_modules", "__pycache__", ".venv", "venv"}
        for root, directories, files in os.walk(base):
            directories[:] = [d for d in directories if d not in skip_names and not d.startswith(".secureagent-")][:200]
            for name in files:
                scanned += 1
                if scanned > max_files:
                    findings.append(Finding("scan_bounds", "OBSERVED", "low", "filesystem",
                                            f"Scan stopped at {max_files} files (truncated)"))
                    break
                path = Path(root) / name
                try:
                    info = path.lstat()
                except OSError:
                    continue
                if info.st_mode & 0o002 and info.st_uid != 0:
                    world_writable += 1
                    if world_writable <= 10:
                        findings.append(Finding("world_writable_file", "OBSERVED", "medium", "filesystem",
                                                f"World-writable file: {path} ({stat.filemode(info.st_mode)})",
                                                recommendation="Restrict write access unless the file intentionally is shared."))
                if info.st_mode & 0o4000:
                    suid += 1
                    if suid <= 10:
                        findings.append(Finding("suid_in_scope", "OBSERVED", "high", "filesystem",
                                                f"SUID binary inside audited scope: {path}",
                                                recommendation="Confirm this binary should carry SUID in this directory."))
                if info.st_mode & 0o111 and Path(root).name in {".tmp", "tmp", ".cache", "uploads"}:
                    executables += 1
                    if executables <= 10:
                        findings.append(Finding("executable_in_temp", "INFERRED", "high", "filesystem",
                                                f"Executable file inside a temporary/upload directory: {path}",
                                                recommendation="Executables in temp directories are a common malware pattern; remove if unexpected."))
                if path.suffix.lower() in {".env", ".pem", ".key", ".p12", ".pfx"} or name in {"id_rsa", "id_ed25519", "credentials", ".npmrc", ".netrc"}:
                    try:
                        sample = path.read_bytes()[:4000].decode("utf-8", "replace")
                        if SECRET_PATTERN.search(sample) or path.suffix.lower() in {".pem", ".key", ".p12", ".pfx"} or name in {"id_rsa", "id_ed25519"}:
                            secret_hits.append((str(path), "credential-shaped file"))
                            if len(secret_hits) <= 10:
                                findings.append(Finding("potential_secret", "INFERRED", "high", "filesystem",
                                                        f"Credential-shaped file detected: {path} (content redacted, never uploaded)",
                                                        recommendation="Move secrets into a secrets manager or protect with strict permissions (0600)."))
                    except OSError:
                        pass
            else:
                continue
            break
        findings.append(Finding("scan_summary", "OBSERVED", "info", "filesystem",
                                f"Scanned {scanned} files: {world_writable} world-writable, {suid} SUID, "
                                f"{executables} executables in temp dirs, {len(secret_hits)} credential-shaped files"))
        return findings

    # -- report assembly ------------------------------------------------------ #

    async def run_workflow(self, workflow: str, scope: dict[str, Any] | None = None) -> dict[str, Any]:
        if workflow not in WORKFLOWS:
            raise ValueError(f"unknown workflow '{workflow}'")
        scope = scope or {}
        started = time.perf_counter()
        stamp = time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())
        report_id = str(uuid4())
        try:
            if workflow == "system_audit":
                findings = await self.system_audit(scope)
            elif workflow == "network_discovery":
                findings = await self.network_discovery(scope)
            elif workflow == "log_analysis":
                findings = await self.log_analysis(scope)
            else:
                findings = await self.file_security_audit(scope)
            status = "completed"
        except ValueError:
            raise
        except Exception as error:  # deterministic engines must fail honestly
            findings = [Finding(workflow, "NOT_AVAILABLE", "medium", "engine",
                                f"workflow aborted: {type(error).__name__}: {str(error)[:200]}")]
            status = "failed"

        counts: dict[str, int] = {}
        for finding in findings:
            if finding.status == "INFERRED":
                counts[finding.severity] = counts.get(finding.severity, 0) + 1
        worst = max((item for item in findings if item.status == "INFERRED"),
                    key=lambda item: _sev_order(item.severity), default=None)
        summary = {
            "checks": len(findings),
            "inferred_counts_by_severity": counts,
            "overall_severity": worst.severity if worst else "info",
            "not_available": sum(1 for item in findings if item.status == "NOT_AVAILABLE"),
        }
        commands: list[dict[str, Any]] = []
        if self.executor:
            for execution in list(self.executor.tracker._items.values())[-24:]:
                if execution.approval == "workflow-fixed":
                    commands.append({"command": execution.command, "exit_code": execution.exit_code,
                                     "duration_ms": execution.duration_ms})
        report = {
            "id": report_id,
            "workflow": workflow,
            "title": WORKFLOWS[workflow]["title"],
            "generated_at": stamp,
            "status": status,
            "duration_ms": int((time.perf_counter() - started) * 1000),
            "scope": {key: value for key, value in scope.items() if key in {"path", "lines"}},
            "summary": summary,
            "findings": [finding.to_dict() for finding in findings],
            "performed_commands": commands[-50:],
            "limitations": [
                "Checks that require root are reported as NOT_AVAILABLE; SecureAgent never bypasses sudo.",
                "Severity values are deterministic INFERRED judgments from fixed rules.",
                "OBSERVED evidence is redacted and truncated.",
            ],
        }
        await self.store.save_report(report)
        await self.store.audit("security.report", {
            "report_id": report_id, "workflow": workflow, "status": status,
            "checks": len(findings), "overall_severity": summary["overall_severity"],
        })
        return report
