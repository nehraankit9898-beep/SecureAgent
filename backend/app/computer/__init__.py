"""SecureAgent Computer Agent integration boundary (Phase 1).

This package contains ONLY contracts, capability detection and fail-closed
disabled stubs. It deliberately ships no mouse/keyboard/screen/browser
execution — those arrive in later phases behind these same interfaces.

Importing this package must never import OS-control libraries. Every concrete
provider lives in a platform adapter that is imported lazily and only when
``Settings.computer_agent_enabled`` is True (which it is not by default).

Modules:
  * ``contracts``   — structured Task/Observation/Action/ToolCall/
                      ApprovalRequest/VerificationResult/AuditEvent models
                      plus the stable provider interfaces.
  * ``capabilities``— read-only platform capability detection.
  * ``registry``    — the single registration path for computer tools into the
                      existing central tool Registry (never bypassing
                      PermissionManager or any other security gate).
  * ``runtime``     — feature-gated runtime facade; disabled by default.
"""

from app.computer.contracts import (
    Action,
    ActionCategory,
    ActionStatus,
    ApprovalDecision,
    ApprovalRequest,
    ApprovalService,
    AuditEvent,
    BrowserProvider,
    ComputerPolicy,
    ComputerTask,
    ComputerTool,
    InputProvider,
    Observation,
    PerceptionProvider,
    PolicyEffect,
    ProviderKind,
    TaskPlanner,
    VerificationResult,
    Verifier,
    WindowProvider,
)

__all__ = [
    "Action",
    "ActionCategory",
    "ActionStatus",
    "ApprovalDecision",
    "ApprovalRequest",
    "ApprovalService",
    "AuditEvent",
    "BrowserProvider",
    "ComputerPolicy",
    "ComputerTask",
    "ComputerTool",
    "InputProvider",
    "Observation",
    "PerceptionProvider",
    "PolicyEffect",
    "ProviderKind",
    "TaskPlanner",
    "VerificationResult",
    "Verifier",
    "WindowProvider",
]
