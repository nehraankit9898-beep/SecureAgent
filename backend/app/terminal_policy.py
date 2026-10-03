"""Command Safety Engine — deterministic, conservative command classification.

Every command that reaches the Linux terminal executor is classified into one
of five tiers before execution:

    SAFE               read-only inspection; no system state change
    LOW_RISK           bounded state change inside the working directory
    REQUIRES_APPROVAL  modifies system state (packages, services, users, files)
    HIGH_RISK          destructive, security-control-altering, or unbounded
    BLOCKED            never executable through SecureAgent policy

Design rules (fail-closed):

* Unknown commands classify as REQUIRES_APPROVAL, never SAFE.
* The command is split on shell separators with quote awareness; every
  segment (including ``$()``/backtick substitutions, recursively) must be
  classified and the worst tier wins.
* Redirection and ``tee``/``cp``/``mv`` write targets are analyzed: absolute
  targets under system roots escalate the tier.
* ``sudo`` marks the command as requiring elevation; the inner command is
  still fully classified. ``su``/``doas``/``pkexec`` and interactive
  full-screen programs are BLOCKED.
* A blocklist scan runs over the entire raw string as defense in depth
  (fork bombs, disk wipe utilities, ``curl | sh``, ``rm -rf /`` ...).
* The classifier never executes anything and never sees secrets.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import StrEnum


class CommandRisk(StrEnum):
    SAFE = "safe"
    LOW_RISK = "low_risk"
    REQUIRES_APPROVAL = "requires_approval"
    HIGH_RISK = "high_risk"
    BLOCKED = "blocked"


_RISK_ORDER = {
    CommandRisk.SAFE: 0,
    CommandRisk.LOW_RISK: 1,
    CommandRisk.REQUIRES_APPROVAL: 2,
    CommandRisk.HIGH_RISK: 3,
    CommandRisk.BLOCKED: 4,
}

MAX_SUBSTITUTION_DEPTH = 3
MAX_COMMAND_CHARS = 8000


@dataclass(frozen=True)
class CommandClassification:
    risk: CommandRisk
    reasons: tuple[str, ...] = ()
    matched_rules: tuple[str, ...] = ()
    requires_elevation: bool = False
    segments: tuple[str, ...] = ()

    @property
    def executable_without_approval(self) -> bool:
        return self.risk in {CommandRisk.SAFE, CommandRisk.LOW_RISK}

    def summary(self) -> str:
        label = self.risk.value.replace("_", " ").upper()
        reason = self.reasons[0] if self.reasons else "classified by command policy"
        return f"{label}: {reason}"


# --------------------------------------------------------------------------- #
# Lexical helpers
# --------------------------------------------------------------------------- #

def _split_top_level(command: str) -> list[str]:
    """Quote-aware split on shell separators (| || && ; & newline)."""
    segments: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    index = 0
    length = len(command)
    while index < length:
        char = command[index]
        if escaped:
            current.append(char)
            escaped = False
            index += 1
            continue
        if char == "\\" and quote in {None, '"'}:
            current.append(char)
            escaped = True
            index += 1
            continue
        if quote:
            if char == quote:
                quote = None
            current.append(char)
            index += 1
            continue
        if char in {"'", '"'}:
            quote = char
            current.append(char)
            index += 1
            continue
        if char in {"|", "&", ";", "\n"}:
            # '||' '&&' ';;' consume both
            if index + 1 < length and command[index + 1] == char:
                index += 1
            segments.append("".join(current))
            current = []
            index += 1
            continue
        current.append(char)
        index += 1
    segments.append("".join(current))
    return [segment for segment in (s.strip() for s in segments) if segment]


def _words(segment: str) -> list[str]:
    """Rough quote-aware word split used for argv analysis."""
    words: list[str] = []
    current: list[str] = []
    quote: str | None = None
    escaped = False
    for char in segment:
        if escaped:
            current.append(char)
            escaped = False
            continue
        if char == "\\" and quote != "'":
            current.append(char)
            escaped = True
            continue
        if quote:
            if char == quote:
                quote = None
            else:
                current.append(char)
            continue
        if char in {"'", '"'}:
            quote = char
            continue
        if char.isspace():
            if current:
                words.append("".join(current))
                current = []
            continue
        current.append(char)
    if current:
        words.append("".join(current))
    return words


_SUBSTITUTION = re.compile(r"\$\(([^()]*)\)|`([^`]*)`")


def _expand_substitutions(command: str, depth: int) -> list[str]:
    """Collect command-substitution bodies as additional segments to classify."""
    if depth > MAX_SUBSTITUTION_DEPTH:
        return [command]
    found = [match.group(1) or match.group(2) for match in _SUBSTITUTION.finditer(command)]
    extra: list[str] = []
    for item in found:
        extra.extend(_expand_substitutions(item, depth + 1))
    return extra


# --------------------------------------------------------------------------- #
# Command knowledge base
# --------------------------------------------------------------------------- #

SAFE_READ_COMMANDS = {
    "pwd", "whoami", "id", "groups", "hostname", "uname", "uptime", "w", "who",
    "last", "lastlog", "ls", "dir", "vdir", "stat", "file", "wc", "sort", "uniq",
    "cut", "head", "tail", "tac", "nl", "od", "xxd", "hexdump", "strings",
    "cksum", "md5sum", "sha1sum", "sha256sum", "sha512sum", "diff", "cmp",
    "comm", "paste", "column", "fold", "fmt", "grep", "egrep", "fgrep",
    "zgrep", "bzgrep", "du", "df", "free", "lscpu", "lsblk", "lspci", "lsusb",
    "lsscsi", "sensors", "vmstat", "iostat", "mpstat", "ps", "pgrep", "pidof",
    "pstree", "lsof", "ss", "netstat", "nstat", "journalctl", "dmesg",
    "printenv", "locale", "date", "cal", "which", "whereis", "type", "getent",
    "cat", "zcat", "bzcat", "xzcat", "basename", "dirname", "realpath",
    "readlink", "tty", "seq", "numfmt", "echo", "printf", "true", "false",
    "lsattr", "getfacl", "getenforce", "sestatus", "apparmor_status",
    "aa-status", "getsebool", "findmnt", "lsns", "lsmod", "blkid", "hostnamectl",
    "timedatectl", "localectl", "apt-cache", "dpkg-query", "systemctl",
    "service", "ufw", "iptables", "iptables-save", "nft", "firewall-cmd",
    "docker", "git", "gzip", "gunzip", "bzip2", "xz", "tar", "zipinfo",
    "env", "sysctl", "route", "arp", "ifconfig", "ip", "ping", "awk", "sed",
    "find", "openssl", "getfacl", "test", "[", "history", "alias", "umask",
    "cd", "dpkg", "sleep", "zless",
}

INTERACTIVE_COMMANDS = {
    "vim", "vi", "nano", "emacs", "joe", "less", "more", "most", "watch",
    "top", "htop", "iotop", "atop", "iftop", "nmon", "btop", "glances",
    "lesspipe", "pager", "visudo", "crontab-e", "passwd", "chpass", "chsh",
    "adduser", "gdb", "strace", "ltrace", "screen", "tmux", "fish", "zsh",
    "ksh", "dash", "csh", "tcsh",
}

ELEVATION_COMMANDS = {"su", "doas", "pkexec"}  # interactive elevation shells

BLOCKED_DISASTER_COMMANDS = {
    "mkfs", "mkfs.ext2", "mkfs.ext3", "mkfs.ext4", "mkfs.xfs", "mkfs.btrfs",
    "mkfs.vfat", "mkfs.ntfs", "mkswap", "wipefs", "shred", "dd", "shutdown",
    "reboot", "poweroff", "halt", "init", "telinit",
}

SESSION_COMMANDS = {"ssh", "telnet", "nc", "ncat", "netcat", "socat", "ftp",
                    "sftp", "mosh"}

PACKAGE_MANAGERS = {
    "apt": ({"install", "remove", "purge", "upgrade", "update", "autoremove",
             "dist-upgrade", "full-upgrade", "download", "add-apt-repository"},
            {"search", "show", "list", "policy", "info"}),
    "apt-get": ({"install", "remove", "purge", "upgrade", "update", "autoremove",
                 "dist-upgrade", "full-upgrade"},
                {"search", "show", "list", "policy", "changelog"}),
    "aptitude": ({"install", "remove", "purge", "upgrade"}, {"search", "show"}),
    "dpkg": ({"-i", "--install", "-r", "--remove", "-P", "--purge",
              "--configure", "--unpack"}, {"-l", "-s", "-L", "-S", "--list", "--status"}),
    "apk": ({"add", "del", "upgrade", "fix"}, {"info", "search", "list"}),
    "dnf": ({"install", "remove", "erase", "upgrade", "update", "downgrade",
             "distro-sync", "autoremove"},
            {"info", "list", "search", "provides", "check-update"}),
    "yum": ({"install", "remove", "erase", "upgrade", "update", "downgrade"},
            {"info", "list", "search", "provides", "check-update"}),
    "zypper": ({"install", "remove", "update", "patch"},
               {"info", "list-updates", "search"}),
    "pacman": ({"-S", "-R", "-Rs", "-U", "-Sy", "-Su"},
               {"-Q", "-Qi", "-Ql", "-Ss", "-Si"}),
    "snap": ({"install", "remove", "refresh", "revert"}, {"list", "info", "find"}),
    "flatpak": ({"install", "uninstall", "update"}, {"list", "info", "search"}),
    "pip": ({"install", "uninstall", "download"}, {"list", "show", "search", "freeze", "check"}),
    "pip3": ({"install", "uninstall", "download"}, {"list", "show", "search", "freeze", "check"}),
    "npm": ({"install", "uninstall", "remove", "update", "ci", "run", "test",
             "exec", "start", "link", "publish"},
            {"list", "ls", "show", "view", "search", "outdated", "--version"}),
    "gem": ({"install", "uninstall", "update"}, {"list", "search", "info"}),
    "cargo": ({"install", "uninstall", "update"}, {"search", "tree"}),
}

PACKAGE_MANAGERS["apt-add-repository"] = PACKAGE_MANAGERS["apt"][0], PACKAGE_MANAGERS["apt"][1]

READ_GIT = {
    "status", "log", "diff", "show", "blame", "describe", "rev-parse", "ls-files",
    "grep", "cat-file", "cat-file -p", "reflog", "shortlog", "archive", "help",
    "branch", "tag", "remote", "config", "stash list", "worktree list", "version",
}

READ_SYSTEMCTL = {
    "status", "show", "is-active", "is-enabled", "is-failed", "list-units",
    "list-unit-files", "list-timers", "list-dependencies", "list-sockets",
    "cat", "help", "daemon-reload-ok", "--version", "isolate?",
}

WRITE_SYSTEMCTL = {
    "start", "stop", "restart", "reload", "try-restart", "reload-or-restart",
    "kill", "freeze", "thaw", "daemon-reload", "reset-failed",
}

BOOT_SYSTEMCTL = {"enable", "disable", "mask", "unmask", "link", "revert", "set-default"}

READ_DOCKER = {"ps", "images", "image ls", "version", "info", "inspect", "stats",
               "system df", "network ls", "volume ls", "container ls", "--version",
               "compose ps", "compose config", "compose version"}

HIGH_DOCKER = {"run", "exec", "commit", "push", "rmi", "rm", "prune", "kill",
               "stop", "start", "restart", "pause", "unpause", "build", "pull",
               "system prune", "network rm", "volume rm", "compose up",
               "compose down", "compose rm", "compose kill"}

FIREWALL_READ = {
    "ufw": {"status", "version"},
    "iptables": {"-L", "--list", "-S", "--list-rules"},
    "nft": {"list"},
    "firewall-cmd": {"--state", "--list-all", "--list-services", "--list-ports",
                     "--get-zones", "--get-default-zone", "--info-zone"},
}

# Absolute path prefixes whose modification is treated as HIGH_RISK when they
# appear as write targets (redirection, tee, cp/mv destination).
SYSTEM_WRITE_ROOTS = ("/etc", "/boot", "/usr", "/bin", "/sbin", "/lib", "/lib64",
                      "/root", "/opt", "/srv", "/home", "/dev")

APPROVAL_WRITE_ROOTS = ("/var", "/etc/alternatives")

ENV_ASSIGNMENT = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")

DISASTER_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r":\(\)\s*\{.*\};\s*:"), "fork bomb pattern"),
    (re.compile(r"(?<![\w/.-])rm\s+(-[a-zA-Z]*[rf][a-zA-Z]*\s+)+(/|~|\$HOME|\*|\.\.)"),
     "recursive deletion of a system or home path"),
    (re.compile(r">\s*/dev/(sd[a-z]|nvme|hd[a-z]|vd[a-z])"), "raw block-device write"),
    (re.compile(r"\bof=\s*/dev/(sd|nvme|hd|vd|mmcblk)"), "raw block-device write via dd"),
    (re.compile(r"\bmkfs(\.\w+)?\b"), "filesystem creation (mkfs)"),
    (re.compile(r"\bwipefs\b"), "filesystem signature wipe"),
    (re.compile(r"\bshred\b"), "secure-wipe utility (shred)"),
    (re.compile(r"\bdd\s+"), "raw disk/data copy utility (dd)"),
    (re.compile(r"\b(shutdown|poweroff|halt)\b"), "system power control"),
    (re.compile(r"\binit\s+[06]\b|\btelinit\s+[06]\b"), "runlevel change to halt/reboot"),
    (re.compile(r"\bcurl\b[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b"),
     "remote script piped into a shell (curl | sh)"),
    (re.compile(r"\bwget\b[^|;]*\|\s*(sudo\s+)?(ba|z|da)?sh\b"),
     "remote script piped into a shell (wget | sh)"),
    (re.compile(r"\bchmod\s+(-[a-zA-Z]+\s+)*777\s+/(\s|$)"), "world-writable root filesystem"),
    (re.compile(r"\b(chmod|chown)\s+(-[a-zA-Z]*[Rr][a-zA-Z]*\s+)+/(etc|usr|bin|sbin|lib|boot|root)\b"),
     "recursive permission rewrite of a system tree"),
    (re.compile(r"\b(history\s+-c)\b"), "shell history wipe"),
    (re.compile(r"\b(journalctl\s+--vacuum)"), "journal vacuum"),
    (re.compile(r"\b(echo|printf|tee)\b.*>\s*/dev/(sd[a-z]|nvme)"), "raw block-device write"),
)


def _base_name(word: str) -> str:
    return word.rstrip("/").rsplit("/", 1)[-1].lower() if word else word


_WRAPPER_FLAGS_WITH_VALUE = {"-u", "--user", "-g", "--group", "-C", "--directory",
                             "--preserve-status", "-k", "--kill-after"}


def _unwrap(words: list[str]) -> tuple[list[str], bool, bool]:
    """Strip env assignments and benign wrappers.

    Returns (remaining words, requires_elevation, used_timeout).
    """
    elevation = False
    while words:
        head = words[0]
        if ENV_ASSIGNMENT.match(head):
            words = words[1:]
            continue
        lowered = head.lower()
        if lowered == "sudo":
            elevation = True
            words = words[1:]
            # strip sudo option arguments (-n, -u user, -g group, -i? -> blocked later)
            while words and (words[0].startswith("-")) and words[0] not in {"--"}:
                flag = words.pop(0)
                if flag in _WRAPPER_FLAGS_WITH_VALUE and words:
                    words.pop(0)
            continue
        if lowered in {"nohup", "setsid", "stdbuf", "command", "builtin", "time", "env", "nice"}:
            words = words[1:]
            # nice -n N / env -i / stdbuf -o0 flags
            while words and words[0].startswith("-") and words[0] not in {"--"}:
                flag = words.pop(0)
                if flag in {"-n", "-i", "-o", "-e"} and words and not words[0].startswith("-"):
                    words.pop(0)
            continue
        if lowered in {"timeout"} and len(words) >= 2:
            words = words[1:]
            while words and words[0].startswith("-"):
                words.pop(0)
            if words and re.fullmatch(r"[0-9.]+[a-z]?", words[0]):
                words.pop(0)
            continue
        if lowered == "exec" and len(words) > 1:
            words = words[1:]
            continue
        break
    return words, elevation, True


def _classify_redirects(segment: str, words: list[str], current: CommandRisk,
                        reasons: list[str], rules: list[str]) -> CommandRisk:
    """Analyze redirection targets and update the running classification."""
    # Find > >> &> <> targets, ignoring < (input redirection is read-only).
    for match in re.finditer(r"(&?>{1,2}|>{1,2})\s*([^\s|&;]+)?", segment):
        target = match.group(2)
        if not target:
            continue
        target = target.strip("'\"")
        if target == "/dev/null":
            continue
        escalated = _write_target_risk(target, reasons, rules)
        if _RISK_ORDER[escalated] > _RISK_ORDER[current]:
            current = escalated
    # tee / cp / mv / install write destinations
    if words:
        base = _base_name(words[0])
        if base in {"tee", "cp", "mv", "install", "rsync", "truncate", "touch", "dd"}:
            for arg in words[1:]:
                if arg.startswith("-"):
                    continue
                escalated = _write_target_risk(arg.strip("'\""), reasons, rules, is_tee=base == "tee")
                if _RISK_ORDER[escalated] > _RISK_ORDER[current]:
                    current = escalated
    return current


def _write_target_risk(target: str, reasons: list[str], rules: list[str], *, is_tee: bool = False) -> CommandRisk:
    if not target or target == "/dev/null":
        return CommandRisk.SAFE
    if target.startswith("/dev/") and not target.startswith("/dev/shm"):
        reasons.append(f"device write target {target}")
        rules.append("write:device")
        return CommandRisk.HIGH_RISK
    if target.startswith("/"):
        for root in SYSTEM_WRITE_ROOTS:
            if target == root or target.startswith(root + "/"):
                reasons.append(f"write target under protected system path {root}")
                rules.append(f"write:system:{root}")
                return CommandRisk.HIGH_RISK
        reasons.append(f"write target outside the workspace ({target})")
        rules.append("write:absolute")
        return CommandRisk.REQUIRES_APPROVAL
    if target.startswith(".."):
        reasons.append("write target escapes the working directory")
        rules.append("write:traversal")
        return CommandRisk.REQUIRES_APPROVAL
    if is_tee:
        rules.append("write:tee-relative")
        return CommandRisk.LOW_RISK
    return CommandRisk.LOW_RISK


def _classify_words(words: list[str], segment: str, reasons: list[str],
                    rules: list[str], depth: int) -> CommandRisk:
    if not words:
        return CommandRisk.SAFE
    base = _base_name(words[0])
    args = words[1:]

    if base in ELEVATION_COMMANDS:
        reasons.append(f"interactive elevation program '{base}' is not allowed; use sudo")
        rules.append(f"blocked:elevation:{base}")
        return CommandRisk.BLOCKED

    if base in INTERACTIVE_COMMANDS:
        # passwd/su style full-screen or prompting programs hang a non-tty run.
        reasons.append(f"interactive program '{base}' cannot run without a terminal")
        rules.append(f"blocked:interactive:{base}")
        return CommandRisk.BLOCKED

    if base in BLOCKED_DISASTER_COMMANDS:
        reasons.append(f"'{base}' can destroy data or host state and is blocked by policy")
        rules.append(f"blocked:disaster:{base}")
        return CommandRisk.BLOCKED

    if base in SESSION_COMMANDS:
        reasons.append(f"interactive network session '{base}' is blocked; use approved network tools instead")
        rules.append(f"blocked:session:{base}")
        return CommandRisk.BLOCKED

    if base in {"bash", "sh", "dash", "zsh", "ksh"}:
        # bash -c "<string>" is classified recursively.
        if args and args[0] in {"-c", "--command"} and len(args) >= 2:
            if depth >= MAX_SUBSTITUTION_DEPTH:
                reasons.append("nested shell invocation exceeds classification depth")
                rules.append("blocked:shell-depth")
                return CommandRisk.BLOCKED
            return _classify_segment(args[1], reasons, rules, depth + 1)
        if args and args[0].startswith("-"):
            # -x/-v traces, login shells etc. still execute unknown stdin/scripts
            reasons.append(f"'{base}' invoked with options cannot be statically verified")
            rules.append(f"blocked:shell-options:{base}")
            return CommandRisk.BLOCKED
        if not args:
            reasons.append(f"bare '{base}' executes unverifiable stdin content")
            rules.append(f"blocked:shell-stdin:{base}")
            return CommandRisk.BLOCKED
        reasons.append(f"script execution requires explicit approval")
        rules.append(f"approval:script:{base}")
        return CommandRisk.REQUIRES_APPROVAL

    if base == "eval":
        reasons.append("'eval' hides its payload from classification")
        rules.append("blocked:eval")
        return CommandRisk.BLOCKED

    if base in {"source", "."}:
        reasons.append("'source' executes file content in the current shell")
        rules.append("approval:source")
        return CommandRisk.REQUIRES_APPROVAL

    if base in {"python", "python3", "python2", "perl", "ruby", "php", "node",
                "nodejs", "lua", "tclsh", "deno", "bun"}:
        reasons.append(f"interpreter '{base}' executes arbitrary code and requires approval")
        rules.append(f"approval:interpreter:{base}")
        return CommandRisk.REQUIRES_APPROVAL

    if base in {"chmod", "chown", "chgrp", "setfacl", "chattr", "chsmack"}:
        recursive = any(re.fullmatch(r"-[a-zA-Z]*[Rr][a-zA-Z]*", arg) for arg in args)
        targets = [arg for arg in args if not arg.startswith("-")]
        if recursive and any(_is_system_root(target) for target in targets):
            reasons.append(f"recursive '{base}' across a system tree is blocked")
            rules.append(f"blocked:{base}:recursive-system")
            return CommandRisk.BLOCKED
        if base == "chattr":
            reasons.append("'chattr' alters file immutability/security attributes")
            rules.append("high:chattr")
            return CommandRisk.HIGH_RISK
        reasons.append(f"'{base}' changes permissions or ownership")
        rules.append(f"approval:{base}")
        return CommandRisk.REQUIRES_APPROVAL

    if base in {"useradd", "adduser", "usermod", "groupadd", "addgroup", "groupmod",
                "gpasswd", "deluser"}:
        reasons.append(f"'{base}' modifies system users or groups")
        rules.append(f"approval:{base}")
        return CommandRisk.REQUIRES_APPROVAL
    if base in {"userdel", "groupdel", "delgroup"}:
        reasons.append(f"'{base}' deletes system users or groups")
        rules.append(f"high:{base}")
        return CommandRisk.HIGH_RISK

    if base == "systemctl" or base == "systemctl2":
        for arg in args:
            if arg in BOOT_SYSTEMCTL:
                reasons.append(f"systemctl {arg} changes boot/service configuration")
                rules.append(f"high:systemctl:{arg}")
                return CommandRisk.HIGH_RISK
            if arg in WRITE_SYSTEMCTL:
                reasons.append(f"systemctl {arg} changes running services")
                rules.append(f"approval:systemctl:{arg}")
                return CommandRisk.REQUIRES_APPROVAL
            if arg.startswith("set-") or arg in {"link"}:
                reasons.append(f"systemctl {arg} changes system configuration")
                rules.append(f"high:systemctl:{arg}")
                return CommandRisk.HIGH_RISK
        for arg in args:
            if arg in READ_SYSTEMCTL or arg.startswith("-") or arg == "--no-pager":
                break
        else:
            if args and not any(arg in READ_SYSTEMCTL for arg in args):
                reasons.append("unrecognized systemctl verb requires approval")
                rules.append("approval:systemctl:unknown")
                return CommandRisk.REQUIRES_APPROVAL
        rules.append("safe:systemctl-read")
        return CommandRisk.SAFE

    if base == "service":
        if args and args[0] in {"status"}:
            rules.append("safe:service-status")
            return CommandRisk.SAFE
        reasons.append("'service' changes running services")
        rules.append("approval:service")
        return CommandRisk.REQUIRES_APPROVAL

    if base in FIREWALL_READ:
        read_verbs = FIREWALL_READ[base]
        if any(arg in read_verbs for arg in args):
            rules.append(f"safe:firewall-read:{base}")
            return CommandRisk.SAFE
        reasons.append(f"'{base}' modifies firewall configuration")
        rules.append(f"high:firewall:{base}")
        return CommandRisk.HIGH_RISK

    if base in {"update-rc.d", "chkconfig", "rcconf", "sysv-rc-conf"}:
        reasons.append(f"'{base}' modifies boot service configuration")
        rules.append(f"high:{base}")
        return CommandRisk.HIGH_RISK

    if base == "setenforce" or base in {"aa-disable", "aa-complain", "aa-enforce",
                                         "auditctl", "semodule", "semanage", "setsebool"}:
        reasons.append(f"'{base}' alters mandatory access control / audit policy")
        rules.append(f"high:mac:{base}")
        return CommandRisk.HIGH_RISK

    if base in PACKAGE_MANAGERS:
        write_verbs, read_verbs = PACKAGE_MANAGERS[base]
        stripped = [arg for arg in args if not arg.startswith("-") or arg in write_verbs]
        for arg in args:
            if arg in write_verbs:
                reasons.append(f"'{base} {arg}' installs, removes, or updates packages")
                rules.append(f"approval:package:{base}:{arg}")
                return CommandRisk.REQUIRES_APPROVAL
            if arg in read_verbs or arg.startswith("-"):
                continue
        if any(arg in read_verbs for arg in args) or not args:
            rules.append(f"safe:package-read:{base}")
            return CommandRisk.SAFE
        reasons.append(f"unrecognized '{base}' operation requires approval")
        rules.append(f"approval:package:{base}:unknown")
        return CommandRisk.REQUIRES_APPROVAL

    if base == "nmap" or base in {"masscan", "zmap", "unicornscan"}:
        reasons.append(f"active network scanner '{base}' requires an authorized target/scope")
        rules.append(f"high:scanner:{base}")
        return CommandRisk.HIGH_RISK

    if base in {"curl", "wget", "http", "httpie", "aria2c", "axel"}:
        reasons.append(f"'{base}' contacts the network; use approved network tools or grant approval")
        rules.append(f"approval:network-fetch:{base}")
        return CommandRisk.REQUIRES_APPROVAL

    if base in {"scp", "rsync"}:
        reasons.append(f"'{base}' transfers data to another host")
        rules.append(f"approval:transfer:{base}")
        return CommandRisk.REQUIRES_APPROVAL

    if base == "ping":
        targets = [arg for arg in args if not arg.startswith("-")]
        if not targets or any(target in {"127.0.0.1", "::1", "localhost"} for target in targets):
            rules.append("safe:ping-local")
            return CommandRisk.SAFE
        reasons.append("ping to a non-local target requires approval")
        rules.append("approval:ping-external")
        return CommandRisk.REQUIRES_APPROVAL

    if base in {"dig", "nslookup", "host", "resolvectl", "systemd-resolve"}:
        rules.append("safe:dns-lookup")
        return CommandRisk.SAFE

    if base == "ip":
        write_verbs = {"add", "del", "delete", "set", "change", "replace", "flush",
                       "netns", "restore", "monitor"}
        for arg in args:
            if arg in write_verbs:
                reasons.append(f"'ip {arg}' modifies network configuration")
                rules.append(f"approval:ip:{arg}")
                return CommandRisk.REQUIRES_APPROVAL
        rules.append("safe:ip-read")
        return CommandRisk.SAFE

    if base in {"ifconfig", "route", "arp"}:
        write_args = {"add", "del", "delete", "set", "change", "replace", "flush",
                      "-s", "-d", "down", "up"}
        if any(arg in write_args for arg in args):
            reasons.append(f"'{base}' with modification arguments")
            rules.append(f"approval:{base}")
            return CommandRisk.REQUIRES_APPROVAL
        rules.append(f"safe:{base}-read")
        return CommandRisk.SAFE

    if base == "sysctl":
        if any(arg in {"-w", "--write"} or "=" in arg for arg in args):
            reasons.append("'sysctl -w' modifies kernel parameters")
            rules.append("high:sysctl-write")
            return CommandRisk.HIGH_RISK
        rules.append("safe:sysctl-read")
        return CommandRisk.SAFE

    if base == "mount" or base == "umount" or base in {"swapon", "swapoff", "losetup"}:
        if base == "mount" and not args:
            rules.append("safe:mount-list")
            return CommandRisk.SAFE
        reasons.append(f"'{base}' changes mount state")
        rules.append(f"approval:{base}")
        return CommandRisk.REQUIRES_APPROVAL

    if base in {"kill", "pkill", "killall", "skill", "snice", "renice"}:
        reasons.append(f"'{base}' signals processes")
        rules.append(f"approval:{base}")
        return CommandRisk.REQUIRES_APPROVAL

    if base == "crontab":
        if args and args[0] in {"-l"}:
            rules.append("safe:crontab-list")
            return CommandRisk.SAFE
        reasons.append("'crontab' modifies scheduled jobs (persistence-capable)")
        rules.append("high:crontab")
        return CommandRisk.HIGH_RISK

    if base in {"at", "batch", "anacron"}:
        reasons.append(f"'{base}' schedules deferred execution")
        rules.append(f"high:{base}")
        return CommandRisk.HIGH_RISK

    if base in {"mkdir", "touch", "ln", "rmdir"}:
        reasons.append(f"'{base}' changes files or directories")
        rules.append(f"approval:{base}")
        return CommandRisk.REQUIRES_APPROVAL

    if base in {"cp", "mv", "install", "tee", "truncate"}:
        reasons.append(f"'{base}' writes file content")
        rules.append(f"approval-or-low:{base}")
        return None  # resolved by redirect/write-target analysis below

    if base in {"rm", "shred_local", "unlink"}:
        targets = [arg for arg in args if not arg.startswith("-")]
        flags = "".join(arg for arg in args if arg.startswith("-"))
        if "r" in flags or "R" in flags:
            for target in targets:
                if _is_dangerous_deletion_target(target):
                    reasons.append(f"recursive deletion of '{target}' is blocked")
                    rules.append("blocked:rm-recursive")
                    return CommandRisk.BLOCKED
        reasons.append("'rm' deletes files and requires approval")
        rules.append("approval:rm")
        return CommandRisk.REQUIRES_APPROVAL

    if base == "find":
        for arg in args:
            if arg in {"-exec", "-execdir", "-ok", "-okdir", "-delete", "-fprintf",
                       "-fprint", "-fprint0"}:
                reasons.append(f"find {arg} executes or deletes")
                rules.append(f"approval:find:{arg}")
                return CommandRisk.REQUIRES_APPROVAL
        rules.append("safe:find-read")
        return CommandRisk.SAFE

    if base == "grep" or base in {"egrep", "fgrep", "zgrep", "bzgrep"}:
        rules.append("safe:grep")
        return CommandRisk.SAFE

    if base == "awk" or base == "gawk" or base == "mawk":
        program = next((arg for arg in args if not arg.startswith("-") and not arg.startswith("-F")), "")
        for arg in args:
            if arg.startswith("-f") or arg == "--exec" or arg == "--source":
                reasons.append("awk program file or exec requires approval")
                rules.append("approval:awk-file")
                return CommandRisk.REQUIRES_APPROVAL
        if re.search(r"system\s*\(|getline|\|{1,2}|>\s*[^>]|close\(", program):
            reasons.append("awk program can execute commands or write files")
            rules.append("approval:awk-side-effects")
            return CommandRisk.REQUIRES_APPROVAL
        rules.append("safe:awk-pure")
        return CommandRisk.SAFE

    if base == "sed" or base == "gsed":
        if any(arg.startswith("-i") for arg in args):
            reasons.append("'sed -i' rewrites files in place")
            rules.append("approval:sed-inplace")
            return CommandRisk.REQUIRES_APPROVAL
        script = next((arg for arg in args if not arg.startswith("-")), "")
        if re.search(r"(^|[^\\])[weWrR]\s", script):
            reasons.append("sed script writes files or executes commands")
            rules.append("approval:sed-side-effects")
            return CommandRisk.REQUIRES_APPROVAL
        rules.append("safe:sed-pure")
        return CommandRisk.SAFE

    if base == "git":
        if args and args[0] == "branch" and any(arg.startswith("-") and ("d" in arg or "D" in arg or "m" in arg) for arg in args[1:]):
            reasons.append("git branch deletion/rename modifies the repository")
            rules.append("approval:git:branch-delete")
            return CommandRisk.REQUIRES_APPROVAL
        for arg in args:
            if arg in {"push", "pull", "fetch", "clone", "remote add", "ls-remote"}:
                reasons.append(f"git {arg} contacts the network")
                rules.append(f"approval:git:{arg}")
                return CommandRisk.REQUIRES_APPROVAL
            if arg in {"clean", "reset"}:
                reasons.append(f"git {arg} can discard work")
                rules.append(f"high:git:{arg}")
                return CommandRisk.HIGH_RISK
            if arg in {"commit", "merge", "rebase", "revert", "checkout", "cherry-pick",
                       "apply", "stash", "am", "mv", "rm", "add", "config", "init"}:
                reasons.append(f"git {arg} modifies the repository")
                rules.append(f"approval:git:{arg}")
                return CommandRisk.REQUIRES_APPROVAL
        rules.append("safe:git-read")
        return CommandRisk.SAFE

    if base == "docker":
        joined_args = " ".join(args)
        for high in HIGH_DOCKER:
            if joined_args == high or joined_args.startswith(high + " ") or high in {"run", "exec"} and joined_args.startswith(high):
                reasons.append(f"docker {high} changes container state")
                rules.append(f"high:docker:{high}")
                return CommandRisk.HIGH_RISK
        for read in READ_DOCKER:
            if joined_args == read or joined_args.startswith(read + " "):
                rules.append(f"safe:docker-read:{read}")
                return CommandRisk.SAFE
        reasons.append("unrecognized docker operation requires approval")
        rules.append("approval:docker:unknown")
        return CommandRisk.REQUIRES_APPROVAL

    if base == "tar":
        if any(arg.startswith("-C") or arg == "--directory" for arg in args):
            reasons.append("tar with -C writes outside the working directory")
            rules.append("approval:tar-directory")
            return CommandRisk.REQUIRES_APPROVAL
        extract = any(arg.startswith(("-x", "--extract", "--unpack")) for arg in args)
        create = any(arg.startswith(("-c", "--create")) for arg in args)
        if extract:
            reasons.append("tar extraction may write anywhere in the archive paths")
            rules.append("approval:tar-extract")
            return CommandRisk.REQUIRES_APPROVAL
        list_only = any(arg.startswith(("-t", "--list")) for arg in args)
        if list_only:
            rules.append("safe:tar-list")
            return CommandRisk.SAFE
        if create:
            rules.append("low:tar-create")
            return CommandRisk.LOW_RISK
        reasons.append("unrecognized tar operation requires approval")
        rules.append("approval:tar:unknown")
        return CommandRisk.REQUIRES_APPROVAL

    if base in {"unzip", "gunzip", "bunzip2", "unxz", "7z", "p7zip"}:
        if base == "unzip" and any(arg == "-l" for arg in args):
            rules.append("safe:unzip-list")
            return CommandRisk.SAFE
        reasons.append(f"'{base}' extracts archives (zip-slip risk)")
        rules.append(f"approval:{base}")
        return CommandRisk.REQUIRES_APPROVAL

    if base == "openssl":
        if any(arg in {"-out", "-keyout", "-set_serial"} for arg in args):
            reasons.append("openssl writes output files")
            rules.append("approval:openssl-write")
            return CommandRisk.REQUIRES_APPROVAL
        rules.append("safe:openssl-read")
        return CommandRisk.SAFE

    if base == "xargs":
        if len(words) >= 2:
            return _classify_words(words[1:], segment, reasons, rules, depth)
        reasons.append("xargs executes stdin-derived commands")
        rules.append("approval:xargs")
        return CommandRisk.REQUIRES_APPROVAL

    if base == "cd":
        target = next((arg for arg in args if not arg.startswith("-")), None)
        if target and target.startswith("/") and not _is_allowed_absolute(target):
            reasons.append(f"cd outside the approved workspace or scratch space ({target})")
            rules.append("approval:cd-external")
            return CommandRisk.REQUIRES_APPROVAL
        if target and target.startswith("/") and _is_allowed_absolute(target):
            rules.append("safe:cd-scratch")
            return CommandRisk.SAFE
        if target and target.count("..") >= 2:
            reasons.append("cd traverses multiple parent directories")
            rules.append("approval:cd-traversal")
            return CommandRisk.REQUIRES_APPROVAL
        rules.append("safe:cd")
        return CommandRisk.SAFE

    if base == "ls" or base in SAFE_READ_COMMANDS:
        rules.append(f"safe:known-read:{base}")
        return CommandRisk.SAFE

    reasons.append(f"unknown command '{base}' requires approval by default policy")
    rules.append("approval:unknown-command")
    return CommandRisk.REQUIRES_APPROVAL


def _is_system_root(target: str) -> bool:
    return target in {"/", "/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64",
                      "/boot", "/var", "/root", "/opt", "/srv", "/home", "/dev",
                      "/proc", "/sys"}


def _is_dangerous_deletion_target(target: str) -> bool:
    normalized = target.strip("'\"")
    if normalized in {"/", "/*", "/*/*", "..", "../..", "~", "$HOME", "./.."}:
        return True
    if normalized.startswith("$HOME") or normalized.startswith("~/"):
        return normalized in {"~", "$HOME", "~/", "$HOME/"} or normalized.rstrip("/") in {"~", "$HOME"}
    for root in _is_system_root_candidates():
        if normalized == root or normalized.startswith(root + "/"):
            return True
    return normalized.startswith("/") and normalized.count("/") <= 2


def _is_system_root_candidates() -> tuple[str, ...]:
    return ("/etc", "/usr", "/bin", "/sbin", "/lib", "/lib64", "/boot", "/var",
            "/root", "/opt", "/srv", "/proc", "/sys", "/dev")


def _is_allowed_absolute(target: str) -> bool:
    """Scratch-space allowlist for cd targets. Any other absolute cd target
    requires approval because it moves relative writes outside the workspace."""
    return target.startswith(("/tmp", "/var/tmp", "/dev/shm"))


def _classify_segment(segment: str, reasons: list[str], rules: list[str],
                      depth: int = 0) -> CommandRisk:
    words = _words(segment)
    words, elevation, _ = _unwrap(words)
    risk = _classify_words(words, segment, reasons, rules, depth)
    if risk is None:
        # write commands whose tier depends on the destination targets
        risk = _classify_redirects(segment, words, CommandRisk.LOW_RISK, reasons, rules)
        if risk is CommandRisk.LOW_RISK:
            base = _base_name(words[0]) if words else ""
            reasons.append(f"'{base}' writes files (bounded to workspace by default)")
    else:
        risk = _classify_redirects(segment, words, risk, reasons, rules)
    return risk if risk is not None else CommandRisk.REQUIRES_APPROVAL


class CommandPolicyEngine:
    """Stateless classifier instance; configuration knobs live on the executor."""

    # Extra raw-string defence patterns covering shell evasion vectors that
    # the per-segment classifier cannot catch because they hide inside
    # command substitution, variable expansion, or process substitution.
    # These are deliberately targeted — `nohup systemctl disable ssh` is
    # still classified by the per-segment engine after _unwrap strips the
    # nohup wrapper, so we only block nohup/exec/setsid when they wrap a
    # shell. Interpreter invocations (python -c, node -e, etc.) are handled
    # by the per-segment classifier as REQUIRES_APPROVAL — the user can
    # still approve them — so they are NOT in this blocklist.
    EVASION_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
        (re.compile(r"\$\{?IFS\}?"), "${IFS} variable is a known shell evasion trick"),
        (re.compile(r"\bbase64\b\s+-d\b.*\|\s*(ba|z|da|fi)?sh"), "base64 payload piped into a shell"),
        (re.compile(r"/proc/self/(fd|root|ns|cwd)"), "/proc/self/* is a sandbox-escape vector"),
        (re.compile(r"/dev/(fd|tcp|udp)/"), "/dev/fd|tcp|udp is a sandbox-escape or exfil vector"),
        (re.compile(r"\bexec\s+(ba|z|da|fi)?sh\b"), "exec replaces the shell with a shell process"),
        (re.compile(r"\bnohup\s+(ba|z|da|fi)?sh\b"), "nohup wrapping a shell spawns detached children"),
        (re.compile(r"\b(setsid|disown)\s+(ba|z|da|fi)?sh\b"), "process detachment evades process-group cleanup"),
        (re.compile(r"\benv\s+-[A-Za-z]+\s+(ba|z|da|fi)?sh\b"), "env -i shell invocation hides payload"),
        (re.compile(r"\bcommand\s+(ba|z|da|fi)?sh\b"), "command builtin used to wrap a shell"),
        (re.compile(r"\bbuiltin\s+(ba|z|da|fi)?sh\b"), "builtin used to wrap a shell"),
        (re.compile(r"\bxargs\s+(-[^\s]+\s+)*-(I|i)\s*\S+\s+(ba|z|da|fi)?sh\b"), "xargs wrapping a shell"),
        (re.compile(r"\bfind\s+.*-exec\s+(ba|z|da|fi)?sh\b"), "find -exec wrapping a shell"),
        (re.compile(r"\bawk\s+.*system\s*\("), "awk system() executes commands"),
        (re.compile(r"\bsed\s+.*\be\b.*;"), "sed e command executes shell"),
        (re.compile(r"\bperl\s+.*\bsystem\s*\("), "perl system() executes code"),
        (re.compile(r"\$\(\s*\("), "arithmetic command substitution can construct commands"),
        (re.compile(r"\$\{[A-Za-z_][A-Za-z0-9_]*:\s*-"), "parameter expansion can construct commands"),
        (re.compile(r"<\s*\(\s*(ba|z|da|fi)?sh\b"), "process substitution hides a subshell"),
        (re.compile(r"\bcurl\b[^|;]*\|\s*(sudo\s+)?(ba|z|da|fi)?sh\b"),
         "remote script piped into a shell (curl | sh)"),
        (re.compile(r"\bwget\b[^|;]*\|\s*(sudo\s+)?(ba|z|da|fi)?sh\b"),
         "remote script piped into a shell (wget | sh)"),
    )

    def classify(self, command: str) -> CommandClassification:
        reasons: list[str] = []
        rules: list[str] = []
        if not command or not command.strip():
            return CommandClassification(CommandRisk.BLOCKED, ("empty command",), ("blocked:empty",))
        command = command.strip()
        if len(command) > MAX_COMMAND_CHARS:
            return CommandClassification(CommandRisk.BLOCKED,
                                         (f"command exceeds {MAX_COMMAND_CHARS} characters",),
                                         ("blocked:length",))
        elevation = bool(re.search(r"(?<![\w/-])sudo(?![\w-])", command))
        if re.search(r"(?<![\w/-])sudo\s+(-[^\s]+\s+)*(-i|-s|--shell|--login|--user\s+root\b)\b", command):
            reasons.append("interactive root shell via sudo is not allowed")
            return CommandClassification(CommandRisk.BLOCKED, tuple(reasons), ("blocked:sudo-shell",),
                                         requires_elevation=True)

        # raw-string defense in depth — original DISASTER_PATTERNS
        for pattern, description in DISASTER_PATTERNS:
            if pattern.search(command):
                reasons.append(description)
                rules.append("blocked:raw-pattern")
                return CommandClassification(CommandRisk.BLOCKED, tuple(reasons), tuple(set(rules)),
                                             requires_elevation=elevation)

        # raw-string defense in depth — added EVASION_PATTERNS (shell evasion
        # vectors: ${IFS}, base64 payloads, /proc/self/fd escapes, process
        # substitution, curl|sh, find -exec sh, awk system(), etc.)
        for pattern, description in self.EVASION_PATTERNS:
            if pattern.search(command):
                reasons.append(description)
                rules.append("blocked:evasion-pattern")
                return CommandClassification(CommandRisk.BLOCKED, tuple(reasons), tuple(set(rules)),
                                             requires_elevation=elevation)

        segments = _split_top_level(command)
        for extra in _expand_substitutions(command, 0):
            segments.extend(_split_top_level(extra))
        worst = CommandRisk.SAFE
        seen: set[str] = set()
        for segment in segments:
            if segment in seen:
                continue
            seen.add(segment)
            risk = _classify_segment(segment, reasons, rules)
            if _RISK_ORDER[risk] > _RISK_ORDER[worst]:
                worst = risk
            if worst is CommandRisk.BLOCKED:
                break
        return CommandClassification(worst, tuple(dict.fromkeys(reasons)), tuple(dict.fromkeys(rules)),
                                     requires_elevation=elevation, segments=tuple(segments))
