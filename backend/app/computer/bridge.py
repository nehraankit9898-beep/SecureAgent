"""Single, audited registration path for Computer Tools into the core Registry.

There is deliberately no other way for a computer capability to become
executable: ``register_computer_tools`` adapts each ``ComputerTool`` to the
core ``app.tools.base.Tool`` ABC and then runs it through the SAME
``PermissionManager.apply()`` + ``Registry.add()`` pipeline every built-in
tool passes through. Consequences (enforced by tests):

* Unknown/malformed tools raise at registration time (fail closed).
* Disabled feature flag => zero registrations; callers get an explicit result.
* The adapter's ``run`` re-checks the ComputerPolicy immediately before doing
  anything, so policy denials cannot be bypassed even if stale metadata was
  handed to the registry.
* No duplicate competing registry exists: this module only feeds the canonical
  one from ``app.tools.base``.
"""

from __future__ import annotations

from typing import Any

from pydantic import BaseModel

from app.computer.contracts import (
    Action,
    ActionCategory,
    ComputerAgentDisabledError,
    ComputerPolicy,
    ComputerTool,
    PolicyEffect,
)
from app.permissions import PermissionManager
from app.tools.base import Registry, Tool


class _EmptyInput(BaseModel):
    model_config = {"extra": "forbid"}


class _DisabledStatusOutput(BaseModel):
    enabled: bool
    reason: str


class ComputerToolAdapter(Tool):
    """Wraps a ComputerTool so the central Registry treats it like any tool."""

    def __init__(self, inner: ComputerTool, policy: ComputerPolicy | None = None):
        self.inner = inner
        self.policy = policy
        # Copy the security-relevant metadata verbatim — never invent values.
        self.name = inner.name
        self.description = inner.description
        self.category = inner.category.value
        self.risk_level = inner.risk_level
        self.input_model = inner.input_model
        self.output_model = inner.output_model
        self.permissions = frozenset(inner.permissions)
        self.timeout_seconds = inner.timeout_seconds
        self.network_required = inner.network_required
        self.sandbox_required = inner.sandbox_required
        self.audit_required = inner.audit_required
        self.idempotent = inner.idempotent
        self.enabled = inner.enabled
        self.requires_approval = inner.requires_approval
        self.disabled_reason = inner.disabled_reason
        self.platforms = list(inner.platforms) if inner.platforms else None

    async def run(self, args: dict[str, Any]) -> dict[str, Any]:
        if self.policy is not None:
            # Defense in depth: re-evaluate at execution time. The probe action
            # carries only static identifiers — never user or screen data.
            try:
                category = ActionCategory(self.category)
            except ValueError:
                category = ActionCategory.SCREEN
            physical = category in {ActionCategory.MOUSE, ActionCategory.KEYBOARD}
            risk = self.risk_level
            if physical and risk.value == "low":
                # Action refuses to construct low-risk physical input; probe at
                # medium so fail-closed policy evaluation still applies.
                from app.models import RiskLevel
                risk = RiskLevel.MEDIUM
            probe = Action(
                task_id="execution-probe",
                category=category,
                operation="run",
                target=self.name,
                risk_level=risk,
                requires_approval=True if physical else self.requires_approval,
            )
            effect = self.policy.evaluate_or_deny(probe)
            if effect is not PolicyEffect.ALLOW:
                raise PermissionError(
                    f"COMPUTER_POLICY_DENIED: {effect.value} for tool {self.name}"
                )
        return await self.inner.run(args)


def register_computer_tools(registry: Registry, tools: list[ComputerTool],
                            policy: ComputerPolicy | None,
                            permission_manager: PermissionManager) -> list[str]:
    """Register computer tools through the existing security pipeline.

    Returns the names actually registered. Raises ValueError on duplicates or
    incomplete security metadata (the Registry itself enforces both).
    """
    registered: list[str] = []
    for tool in tools:
        if not isinstance(tool, ComputerTool):
            raise ValueError("computer tools must implement the ComputerTool contract")
        adapter = ComputerToolAdapter(tool, policy)
        registry.add(permission_manager.apply(adapter))
        registered.append(adapter.name)
    return registered


class DisabledComputerTool(ComputerTool):
    """Contract-shaped placeholder with NO capability.

    It exists so later phases can prove the registration path end-to-end. In
    Phase 1 it is intentionally never registered: the runtime registers zero
    computer tools regardless of the feature flag, because no concrete
    provider exists yet. Calling ``run`` fails closed.
    """

    name = "computer_status"
    description = (
        "Reports whether the Computer Agent layer is active. "
        "Read-only metadata, performs no computer actions."
    )
    category = ActionCategory.SCREEN
    input_model = _EmptyInput
    output_model = _DisabledStatusOutput
    permissions = frozenset()
    idempotent = True
    requires_approval = False
    provider_kind = None

    async def run(self, args: dict[str, Any]) -> dict[str, Any]:
        raise ComputerAgentDisabledError(
            "COMPUTER_AGENT_DISABLED: the Computer Agent feature flag is off"
        )
