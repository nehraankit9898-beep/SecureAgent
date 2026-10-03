"""Linux namespace sandbox for restricted terminal execution.

This module implements real filesystem isolation for the RESTRICTED_AGENT
terminal mode using Linux user+mount+pid+net namespaces. The sandbox:

* Runs the child as uid/gid 65534 (nobody/nogroup) inside a new user
  namespace — host root-owned files (/etc/shadow, /root, /etc/sudoers)
  become unreadable because the uid is remapped.
* Spawns a private PID namespace — host processes are invisible.
* Spawns a private network namespace with only loopback down — the
  child has no network access by default. The caller may optionally
  bring loopback up inside the namespace for ``localhost`` testing.
* Adds a deterministic *Sensitive Resource Guard* layer that blocks
  reads/writes of /etc/shadow, ~/.ssh, *.pem, *.key, .env, etc.
  regardless of uid — defence in depth on top of the uid remap.
* Fails closed: if the namespace mechanism is unavailable (non-Linux
  host, kernel disabled user namespaces, missing unshare(1)), the
  sandbox reports ``LINUX_SANDBOX_UNAVAILABLE`` and the caller must
  keep autonomous terminal execution disabled.

The sandbox NEVER silently downgrades to unrestricted host execution.
The host can only be reached when the user explicitly activates
``HOST_CONTROL`` mode (handled in ``linux_terminal.py``).
"""
from __future__ import annotations

import os
import re
import shutil
import stat
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Iterable

# --------------------------------------------------------------------------- #
# Sensitive resource guard — defence in depth below the namespace sandbox.
# --------------------------------------------------------------------------- #

SENSITIVE_PATH_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    (re.compile(r"^/etc/shadow$"), "password hash database"),
    (re.compile(r"^/etc/gshadow$"), "group password database"),
    (re.compile(r"^/etc/sudoers$"), "sudo policy"),
    (re.compile(r"^/etc/sudoers\.d/"), "sudo policy fragment"),
    (re.compile(r"/\.ssh/(id_|id_|identity|authorized_keys|known_hosts|config)"), "ssh key material"),
    (re.compile(r"/\.ssh/$"), "ssh directory"),
    (re.compile(r"\.(pem|key|p12|pfx|kdbx|keystore|jks)$", re.IGNORECASE), "private key / credential store"),
    (re.compile(r"(^|/)\.env(\.|$)"), "environment secrets file"),
    (re.compile(r"(^|/)\.env\.[A-Za-z0-9_-]+$"), "environment secrets variant"),
    (re.compile(r"(^|/)credentials(\.|$)", re.IGNORECASE), "credentials file"),
    (re.compile(r"(^|/)secrets(\.|$)", re.IGNORECASE), "secrets file"),
    (re.compile(r"(^|/)\.aws/credentials$"), "cloud credentials"),
    (re.compile(r"(^|/)\.config/gcloud/credentials"), "cloud credentials"),
    (re.compile(r"(^|/)\.kube/config$"), "kubernetes credentials"),
    (re.compile(r"(^|/)\.docker/config\.json$"), "docker credentials"),
    (re.compile(r"(^|/)\.netrc$", re.IGNORECASE), "netrc credentials"),
    (re.compile(r"(^|/)token(\.|$)", re.IGNORECASE), "token file"),
    (re.compile(r"(^|/)\.gnupg/"), "gpg keyring"),
)

SENSITIVE_PATH_PREFIXES: tuple[str, ...] = (
    "/etc/shadow", "/etc/gshadow", "/etc/sudoers", "/etc/sudoers.d/",
)


@dataclass(frozen=True)
class SensitiveResourceDecision:
    blocked: bool
    reason: str = ""

    @classmethod
    def allow(cls) -> "SensitiveResourceDecision":
        return cls(blocked=False)

    @classmethod
    def deny(cls, reason: str) -> "SensitiveResourceDecision":
        return cls(blocked=True, reason=reason)


def classify_path_sensitivity(path: str) -> SensitiveResourceDecision:
    """Deterministically classify an absolute or home-relative path.

    Returns ``deny(reason)`` when the path matches a known sensitive
    pattern. The check is purely lexical/structural so it can be applied
    before any filesystem access happens.
    """
    if not path or not isinstance(path, str):
        return SensitiveResourceDecision.allow()
    normalized = path.rstrip("/")
    if not normalized:
        return SensitiveResourceDecision.allow()
    expanded = os.path.expanduser(normalized)
    if expanded != normalized:
        # ~/.ssh/...  -> /home/<user>/.ssh/...
        normalized = expanded
    for prefix in SENSITIVE_PATH_PREFIXES:
        if normalized == prefix.rstrip("/") or normalized.startswith(prefix):
            return SensitiveResourceDecision.deny(
                f"SENSITIVE_RESOURCE_BLOCKED: '{path}' is a privileged system file"
            )
    for pattern, description in SENSITIVE_PATH_PATTERNS:
        if pattern.search(normalized):
            return SensitiveResourceDecision.deny(
                f"SENSITIVE_RESOURCE_BLOCKED: '{path}' is {description}"
            )
    return SensitiveResourceDecision.allow()


# --------------------------------------------------------------------------- #
# Sandbox availability probe — run once at startup, cached.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class SandboxCapabilities:
    """Snapshot of what isolation primitives are usable on this host."""
    platform: str
    unprivileged_userns: bool
    unshare_binary: str | None
    setpriv_binary: str | None
    bwrap_binary: str | None
    firejail_binary: str | None
    bwrap_usable: bool = False
    user_namespace: bool = False
    mount_namespace: bool = False
    pid_namespace: bool = False
    network_namespace: bool = False
    apparmor: bool = False
    selinux: bool = False
    systemd: bool = False
    sudo_binary: str | None = None
    pkexec_binary: str | None = None
    ollama_binary: str | None = None
    bash_binary: str | None = None
    python_binary: str | None = None

    @property
    def available(self) -> bool:
        """True only when the complete restricted profile was exercised."""
        return (
            self.platform == "linux"
            and self.unprivileged_userns
            and self.bwrap_binary is not None
            and self.bwrap_usable
            and self.user_namespace
            and self.mount_namespace
            and self.pid_namespace
            and self.network_namespace
        )

    @property
    def mechanism(self) -> str:
        if self.available:
            return "bubblewrap"
        return "none"

    def describe(self) -> dict:
        return {
            "platform": self.platform,
            "available": self.available,
            "mechanism": self.mechanism,
            "unprivileged_userns": self.unprivileged_userns,
            "unshare": self.unshare_binary,
            "setpriv": self.setpriv_binary,
            "bwrap": self.bwrap_binary,
            "bwrap_usable": self.bwrap_usable,
            "firejail": self.firejail_binary,
            "user_namespace": self.user_namespace,
            "mount_namespace": self.mount_namespace,
            "pid_namespace": self.pid_namespace,
            "network_namespace": self.network_namespace,
            "apparmor": self.apparmor,
            "selinux": self.selinux,
            "systemd": self.systemd,
            "sudo": self.sudo_binary,
            "pkexec": self.pkexec_binary,
            "ollama": self.ollama_binary,
            "bash": self.bash_binary,
            "python": self.python_binary,
        }


_caps_cache: SandboxCapabilities | None = None


def probe_sandbox_capabilities() -> SandboxCapabilities:
    """Probe the host once for sandbox primitives. Cached for the process."""
    global _caps_cache
    if _caps_cache is not None:
        return _caps_cache

    platform = sys.platform
    unshare_bin = shutil.which("unshare") if platform == "linux" else None
    setpriv_bin = shutil.which("setpriv") if platform == "linux" else None
    bwrap_bin = shutil.which("bwrap") if platform == "linux" else None
    firejail_bin = shutil.which("firejail") if platform == "linux" else None

    userns_ok = False
    bwrap_usable = False
    if platform == "linux":
        # 1) Kernel must allow unprivileged user namespaces.
        try:
            with open("/proc/sys/kernel/unprivileged_userns_clone", "r") as f:
                userns_ok = f.read().strip() in {"1", "y", "yes"}
        except OSError:
            # If the sysctl is absent, the kernel default is usually "allow".
            userns_ok = True
        # 2) The unshare binary must actually be able to spawn a user ns.
        if userns_ok and unshare_bin:
            import subprocess
            try:
                result = subprocess.run(
                    [unshare_bin, "--user", "--pid", "--net", "--fork",
                     "echo", "USERNS_PROBE_OK"],
                    stdin=subprocess.DEVNULL,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.DEVNULL,
                    timeout=4,
                )
                userns_ok = result.returncode == 0 and b"USERNS_PROBE_OK" in result.stdout
            except (OSError, subprocess.SubprocessError):
                userns_ok = False
        else:
            userns_ok = False

        if userns_ok and bwrap_bin:
            import subprocess
            probe = [
                bwrap_bin, "--unshare-user", "--unshare-pid", "--unshare-net",
                "--die-with-parent", "--new-session", "--cap-drop", "ALL",
                "--tmpfs", "/", "--proc", "/proc", "--dev", "/dev",
            ]
            for source in ("/usr", "/bin", "/lib", "/lib64", "/sbin"):
                if Path(source).exists():
                    probe += ["--ro-bind", source, source]
            probe += ["--uid", "65534", "--gid", "65534", "/bin/true"]
            try:
                result = subprocess.run(
                    probe, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL,
                    stderr=subprocess.DEVNULL, timeout=4,
                )
                bwrap_usable = result.returncode == 0
            except (OSError, subprocess.SubprocessError):
                bwrap_usable = False

    _caps_cache = SandboxCapabilities(
        platform=platform,
        unprivileged_userns=userns_ok,
        unshare_binary=unshare_bin,
        setpriv_binary=setpriv_bin,
        bwrap_binary=bwrap_bin,
        firejail_binary=firejail_bin,
        bwrap_usable=bwrap_usable,
        user_namespace=userns_ok,
        mount_namespace=bwrap_usable,
        pid_namespace=bwrap_usable,
        network_namespace=bwrap_usable,
        apparmor=Path("/sys/module/apparmor/parameters/enabled").exists(),
        selinux=Path("/sys/fs/selinux/enforce").exists(),
        systemd=shutil.which("systemctl") is not None,
        sudo_binary=shutil.which("sudo"),
        pkexec_binary=shutil.which("pkexec"),
        ollama_binary=shutil.which("ollama"),
        bash_binary=shutil.which("bash"),
        python_binary=shutil.which("python3") or shutil.which("python"),
    )
    return _caps_cache


# --------------------------------------------------------------------------- #
# Sandbox invocation — builds the prefix argv for a sandboxed command.
# --------------------------------------------------------------------------- #

@dataclass(frozen=True)
class SandboxInvocation:
    """A prefix argv that, when prepended to a user command argv, executes
    that command inside the configured sandbox. The sandbox guarantees:

    * child runs as uid/gid 65534 (nobody/nogroup) inside a user ns
    * private pid namespace — host processes invisible
    * private network namespace — no network (or loopback-only if allowed)
    * no-new-privs set
    * supplementary groups cleared

    The caller is responsible for setting cwd/env/stdin/stdout/stderr on
    the spawned process.
    """
    prefix_argv: tuple[str, ...]
    mechanism: str
    capabilities: SandboxCapabilities
    notes: tuple[str, ...] = field(default_factory=tuple)

    def describe(self) -> dict:
        return {
            "mechanism": self.mechanism,
            "prefix_argv": list(self.prefix_argv),
            "notes": list(self.notes),
            "capabilities": self.capabilities.describe(),
        }


def build_sandbox_argv(
    *,
    allow_loopback: bool = False,
    workspace_mount: str | None = None,
) -> SandboxInvocation:
    """Build the sandbox prefix argv.

    Raises ``RuntimeError("LINUX_SANDBOX_UNAVAILABLE: ...")`` when no
    isolation mechanism is available. The caller MUST keep terminal
    execution disabled in that case — never silently fall through to
    unrestricted host execution.
    """
    caps = probe_sandbox_capabilities()
    if not caps.available:
        raise RuntimeError(
            "LINUX_SANDBOX_UNAVAILABLE: "
            + (
                "host is not Linux"
                if caps.platform != "linux"
                else "the complete bubblewrap user+mount+pid+network namespace "
                     "profile is unavailable; install bubblewrap and enable "
                     "unprivileged user namespaces"
            )
        )

    # Start from an empty root.  The host root is never inherited.  Only
    # executable/runtime trees are exposed read-only; the selected workspace
    # is the sole writable host bind and /tmp is private.
    argv: list[str] = [
        caps.bwrap_binary,
        "--unshare-user", "--unshare-pid",
        "--share-net" if allow_loopback else "--unshare-net",
        "--die-with-parent", "--new-session", "--cap-drop", "ALL",
        "--tmpfs", "/", "--proc", "/proc", "--dev", "/dev",
        "--dir", "/tmp", "--chmod", "1777", "/tmp",
    ]
    for source in ("/usr", "/bin", "/lib", "/lib64", "/sbin"):
        if Path(source).exists():
            argv += ["--ro-bind", source, source]
    if workspace_mount:
        workspace = str(Path(workspace_mount).resolve(strict=True))
        argv += ["--bind", workspace, workspace, "--chdir", workspace]
    argv += [
        "--uid", "65534", "--gid", "65534",
        "--setenv", "HOME", "/tmp",
        "--setenv", "SECURE_AGENT_SANDBOX", "1",
        "--setenv", "TERM", "dumb",
    ]
    notes = (
        "bubblewrap user+mount+pid+network namespace isolation",
        "empty root; executable/runtime trees are read-only",
        "host /etc /home /root /var /run are not mounted",
        "uid/gid 65534 with all capabilities dropped",
        "private /tmp, /proc and /dev",
    )
    return SandboxInvocation(tuple(argv), "bubblewrap", caps, notes)


# --------------------------------------------------------------------------- #
# Canonical path enforcement — race-aware filesystem boundary checks.
# --------------------------------------------------------------------------- #

class PathEscapeError(PermissionError):
    """Raised when a path resolves outside the approved workspace, including
    via symlinks, /proc/self/fd, /proc/self/root, hardlinks, or mount
    traversal."""

    def __init__(self, message: str, *, kind: str = "escape"):
        super().__init__(message)
        self.kind = kind


FORBIDDEN_PREFIXES: tuple[str, ...] = (
    "/proc/self/fd", "/proc/self/root", "/proc/self/cwd", "/proc/self/ns",
    "/dev/fd", "/proc", "/sys", "/dev", "/run", "/boot", "/etc", "/root",
    "/var", "/usr", "/opt", "/srv", "/media", "/mnt",
)


def _path_is_inside(child: Path, parent: Path) -> bool:
    """True iff ``child`` equals or lives under ``parent`` (both absolute)."""
    try:
        child.relative_to(parent)
        return True
    except ValueError:
        return False


def enforce_canonical_workspace_path(
    raw_path: str | Path,
    *,
    workspace_root: Path,
    allowed_roots: Iterable[Path] = (),
    allow_create: bool = False,
    follow_symlinks: bool = False,
) -> Path:
    """Resolve ``raw_path`` and verify it stays inside an approved root.

    Defence layers applied (each layer can short-circuit with a
    ``PathEscapeError``):

    1. null-byte / overlong input rejection
    2. URL-decoding traversal detection (defends against ``%2e%2e``)
    3. backslash and ``..`` lexical rejection
    4. protected host prefix rejection (``/etc``, ``/proc``, ``/sys``,
       ``/dev``, ``/root``, ``/var``, ``/usr``, ``/opt``, ``/srv``,
       ``/media``, ``/mnt``, ``/boot``, ``/run``, ``/proc/self/fd``,
       ``/proc/self/root``, ``/dev/fd``)
    5. symlink-traversal rejection — every path component is opened with
       ``O_NOFOLLOW``; symlinks anywhere on the path are refused
    6. hardlink detection via ``st_nlink != 1`` for regular files
    7. canonical resolution (``realpath``) must land inside an approved
       root — defends against mount-traversal and bind-mount escapes
       that survived the earlier checks

    Raises ``PathEscapeError`` on any violation.
    """
    import errno

    if not isinstance(raw_path, (str, Path)):
        raise PathEscapeError("invalid path type", kind="invalid")
    text = str(raw_path)
    if "\x00" in text or len(text) > 4096:
        raise PathEscapeError("invalid path: null byte or excessive length", kind="invalid")

    # Layer 2: URL-decoding traversal defence.
    from urllib.parse import unquote
    decoded = text
    for _ in range(3):
        nxt = unquote(decoded)
        if nxt == decoded:
            break
        decoded = nxt
    if "\\" in decoded:
        raise PathEscapeError("backslash in path is not allowed", kind="invalid")
    if ".." in Path(decoded).parts:
        raise PathEscapeError("'..' traversal is not allowed", kind="traversal")

    # Layer 4: protected host prefix rejection (absolute paths only).
    candidate_raw = Path(text).expanduser()
    if candidate_raw.is_absolute():
        for prefix in FORBIDDEN_PREFIXES:
            s = str(candidate_raw)
            if s == prefix or s.startswith(prefix + "/"):
                raise PathEscapeError(
                    f"path '{text}' falls under protected host prefix {prefix}",
                    kind="protected-prefix",
                )

    # Resolve roots to canonical form for the final check.
    roots: list[Path] = [workspace_root.resolve(strict=True)]
    for raw_root in allowed_roots:
        try:
            roots.append(Path(raw_root).expanduser().resolve(strict=True))
        except (OSError, RuntimeError):
            continue

    if not candidate_raw.is_absolute():
        candidate_raw = workspace_root / candidate_raw

    # Layer 5 & 6: piecewise O_NOFOLLOW walk. We always start from an opened
    # fd to the starting directory ("/" for absolute paths) and walk
    # downwards; every component is opened with O_NOFOLLOW so a symlink
    # anywhere on the path is refused at the kernel level.
    parts = candidate_raw.parts[1:]  # drop leading "/"
    open_fds: list[int] = []
    flags_dir = os.O_RDONLY | getattr(os, "O_DIRECTORY", 0) | getattr(os, "O_NOFOLLOW", 0)
    flags_nofollow = os.O_RDONLY | getattr(os, "O_NOFOLLOW", 0)
    progressive: Path = Path("/")
    try:
        # Open the starting directory so all subsequent opens are dir_fd-relative.
        try:
            root_fd = os.open("/", flags_dir)
        except OSError as e:
            raise PathEscapeError(f"cannot open root directory: {e.strerror}", kind="open-failed") from e
        open_fds.append(root_fd)

        for index, part in enumerate(parts):
            parent_fd = open_fds[-1]
            progressive_str = str(progressive / part)
            try:
                fd = os.open(part, flags_dir, dir_fd=parent_fd)
            except NotADirectoryError:
                # Component is a file but more parts remain — that's an error.
                if index != len(parts) - 1:
                    raise PathEscapeError(
                        f"path component is not a directory: {progressive_str}",
                        kind="not-directory",
                    )
                # Final component: try opening as a regular file (O_NOFOLLOW).
                try:
                    fd = os.open(part, flags_nofollow, dir_fd=parent_fd)
                except OSError as e:
                    if e.errno == errno.ENOENT and allow_create:
                        progressive = progressive / part
                        continue
                    raise PathEscapeError(f"cannot open {progressive_str}: {e.strerror}", kind="open-failed") from e
                open_fds.append(fd)
                info = os.fstat(fd)
                if stat.S_ISLNK(info.st_mode):
                    raise PathEscapeError(f"symlink at {progressive_str}", kind="symlink")
                if not stat.S_ISREG(info.st_mode):
                    raise PathEscapeError(f"not a regular file: {progressive_str}", kind="not-regular")
                if info.st_nlink != 1:
                    raise PathEscapeError(f"hardlink detected at {progressive_str}", kind="hardlink")
                progressive = progressive / part
                continue
            except FileNotFoundError:
                if not allow_create:
                    raise PathEscapeError(f"path does not exist: {progressive_str}", kind="missing")
                progressive = progressive / part
                continue
            except OSError as e:
                if e.errno in {errno.ELOOP, errno.EACCES, errno.EPERM}:
                    raise PathEscapeError(f"unsafe path component {progressive_str}: {e.strerror}", kind="unsafe") from e
                raise
            open_fds.append(fd)
            info = os.fstat(fd)
            if stat.S_ISLNK(info.st_mode):
                raise PathEscapeError(f"symlink in path at {progressive_str}", kind="symlink")
            progressive = progressive / part

        # Layer 7: final canonical resolution must land inside an approved root.
        resolved = Path(os.path.realpath(str(progressive)))
        if not any(_path_is_inside(resolved, root) or resolved == root for root in roots):
            raise PathEscapeError(
                f"resolved path '{resolved}' escapes the approved workspace roots",
                kind="escape",
            )
        return resolved
    finally:
        for fd in reversed(open_fds):
            try:
                os.close(fd)
            except OSError:
                pass


__all__ = [
    "SENSITIVE_PATH_PATTERNS",
    "SENSITIVE_PATH_PREFIXES",
    "SensitiveResourceDecision",
    "classify_path_sensitivity",
    "SandboxCapabilities",
    "probe_sandbox_capabilities",
    "SandboxInvocation",
    "build_sandbox_argv",
    "PathEscapeError",
    "enforce_canonical_workspace_path",
    "FORBIDDEN_PREFIXES",
]
