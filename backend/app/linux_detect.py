"""Linux auto-detection — startup inventory of host and toolchain.

Detection is read-only and bounded. Missing optional tools are reported with
an install hint; the application must keep working when they are absent.
"""

from __future__ import annotations

import os
import platform
import re
import shutil
import subprocess
from pathlib import Path
from typing import Any


def _read_os_release() -> dict[str, str]:
    data: dict[str, str] = {}
    for path in ("/etc/os-release", "/usr/lib/os-release"):
        try:
            text = Path(path).read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        for line in text.splitlines():
            key, sep, value = line.partition("=")
            if sep and key:
                data[key.strip()] = value.strip().strip('"')
        if data:
            break
    return data


def _binary_version(argv: list[str]) -> str | None:
    try:
        result = subprocess.run(argv, capture_output=True, text=True, timeout=5,
                                stdin=subprocess.DEVNULL)
    except (OSError, subprocess.TimeoutExpired):
        return None
    text = (result.stdout or result.stderr).strip().splitlines()
    return text[0][:200] if text else None


def detect_environment() -> dict[str, Any]:
    """Detect distro, kernel, architecture, shell, and common security tools.

    Never raises: on non-Linux platforms the same structure is returned with
    platform set accordingly and linux-specific entries marked unavailable.
    """
    system = platform.system().lower()  # 'linux' | 'darwin' | 'windows'
    os_release = _read_os_release() if system == "linux" else {}
    kernel = platform.release()
    machine = platform.machine()

    shell = os.environ.get("SHELL") or (shutil.which("bash") and f"{shutil.which('bash')}") or ""
    shell_version = _binary_version([shell, "--version"]) if shell and Path(shell).exists() else None

    tools: dict[str, dict[str, Any]] = {}
    for name, argv in (
        ("python", ["python3", "--version"]),
        ("node", ["node", "--version"]),
        ("npm", ["npm", "--version"]),
        ("git", ["git", "--version"]),
        ("docker", ["docker", "--version"]),
        ("ollama", ["ollama", "--version"]),
        ("systemctl", ["systemctl", "--version"]),
        ("ufw", ["ufw", "version"]),
        ("nmap", ["nmap", "--version"]),
        ("suricata", ["suricata", "--build-info"]),
        ("clamav", ["clamscan", "--version"]),
        ("rkhunter", ["rkhunter", "--version"]),
        ("chkrootkit", ["chkrootkit", "-V"]),
        ("john", ["john", "--version"]),
        ("hashcat", ["hashcat", "--version"]),
    ):
        binary = shutil.which(argv[0])
        if binary:
            tools[name] = {"installed": True, "path": binary, "version": _binary_version(argv)}
        else:
            tools[name] = {"installed": False, "path": None, "version": None}

    optional_security = {name for name in ("nmap", "suricata", "clamav", "rkhunter", "chkrootkit", "john", "hashcat")}
    missing_optional = [name for name in optional_security if not tools[name]["installed"]]

    distro = {
        "id": os_release.get("ID"),
        "name": os_release.get("PRETTY_NAME") or os_release.get("NAME"),
        "version": os_release.get("VERSION_ID"),
        "like": os_release.get("ID_LIKE"),
    }

    return {
        "platform": system,
        "linux": system == "linux",
        "distro": distro,
        "kernel": kernel,
        "architecture": machine,
        "hostname": platform.node(),
        "python_version": platform.python_version(),
        "shell": {"path": shell or None, "version": shell_version},
        "tools": tools,
        "missing_optional_tools": missing_optional,
        "install_hints": {
            "ollama": "curl -fsSL https://ollama.com/install.sh | sh  (or https://ollama.com/download/linux)",
            "docker": "sudo apt-get install docker.io  (or docs.docker.com/engine/install)",
            "nmap": "sudo apt-get install nmap",
            "clamav": "sudo apt-get install clamav",
        },
    }
