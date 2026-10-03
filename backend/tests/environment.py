"""Shared, honest environment gating for execution tests (spec section 33).

Tests that run commands through the RESTRICTED_AGENT sandbox require the
complete bubblewrap user+mount+pid+network namespace profile. On hosts
without that profile the sandbox correctly fails closed — the runtime is
behaving as designed. Such tests must surface as BLOCKED (skipped with an
explicit environment reason), never as failures and never as fake passes.
"""
import pytest


def _sandbox_available() -> bool:
    try:
        from app.linux_sandbox import probe_sandbox_capabilities
        return bool(probe_sandbox_capabilities().available)
    except Exception:
        return False


SANDBOX_AVAILABLE = _sandbox_available()

requires_sandbox = pytest.mark.skipif(
    not SANDBOX_AVAILABLE,
    reason=(
        "BLOCKED — environment requires bubblewrap with the full "
        "user+mount+pid+network namespace profile; install bubblewrap "
        "and enable unprivileged user namespaces on a real Linux host"
    ),
)
