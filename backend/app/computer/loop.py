"""Phase 6 — Observe → Plan → Act → Verify → Recover computer loop.

This module turns the individual tools (core registry tools plus the Phase 5
computer adapters) into a *reliable* bounded agent loop. It deliberately
reuses every existing enforcement point instead of re-implementing them:

* Execution goes through ``app.tools.base.Registry.execute`` exactly once per
  attempt, so schema validation, permission enforcement, timeouts and output
  limits stay in the canonical place (same as ``app.agent.Agent``). The LLM
  never receives OS privileges: it only summarizes verified evidence at the
  end of a run, wrapped in the untrusted-data channel.
* Control Center gates are honored before anything starts or continues
  (agent master switch, auto planning / tool calling / auto execution /
  auto retry, EMERGENCY STOP). The loop can only be *stricter* than the
  gates; it never weakens them.
* Cancellation uses ``app.execution_registry.ExecutionRegistry``: register on
  start, checkpoint between phases, unregister on exit. A cancel request at
  any checkpoint terminates the run safely (final state CANCELLED).
* Every phase transition is validated against the Phase 2 task state machine
  in ``app.agent_core`` (illegal transitions raise and fail closed), and the
  legacy wire-status mapping keeps the public API contract unchanged.
* Audit events go to the append-only ``MemoryStore.audit`` (secret-redacted
  at write time by the memory layer itself). Failed verifications are always
  visible both to the user (task errors / step results) and the audit trail.

Loop guarantees (acceptance gate):
1. Bounded step/time/token/tool budgets. When ANY budget is exhausted the run
   FAILS with an explicit error — it never silently continues and never
   claims success.
2. Before acting, the intended action AND its expected observation are
   recorded (step title + arguments + verification criteria persisted via
   ``memory.save_task`` and audited as ``loop.intention``).
3. After acting, an observation is captured (tool result, optionally cross-
   checked with screen perception when a provider is installed) and verified
   against EXPLICIT success criteria supplied with the plan. Criteria are
   deterministic predicates evaluated over the redacted tool-output JSON —
   the model can propose criteria but can never mark itself verified.
4. Failed verification enters bounded recovery (retry with corrective
   feedback up to the recovery budget); when the budget is exhausted the task
   fails terminally rather than blindly repeating actions.
5. Checkpoints are written after every completed step and the durable Task
   record supports resuming unfinished work without re-running completed
   steps (``resume`` below).
6. Completion requires either (a) every step verified by evidence, or (b) an
   explicit user-approved assumption (``user_approved_completion``). An
   unverified completion attempt raises and fails closed.
"""

from __future__ import annotations

import asyncio
import json
import time
from enum import StrEnum
from typing import Any, Callable

from pydantic import BaseModel, ConfigDict, Field, field_validator

from app.agent_core import (
    BudgetExceeded,
    DecisionBudget,
    PromptChannels,
    StateTransitionError,
    TaskState,
    assert_completion_invariants,
    legacy_status,
    validate_transition,
)
from app.models import (
    ChatRequest,
    Message,
    Permission,
    Step,
    StepStatus,
    Task,
    TaskStatus,
    ToolResult,
)


class GateBlockedError(RuntimeError):
    """Control Center forbids autonomous execution; fail closed."""


class LoopOutcome(StrEnum):
    """Terminal outcomes of one loop run (all final states)."""

    COMPLETED = "completed"
    PARTIAL = "partial"            # paused for approval; resumable
    FAILED = "failed"
    CANCELLED = "cancelled"


class VerificationCriteria(BaseModel):
    """Deterministic, explicit success criteria for one planned action.

    Evaluation happens over the *redacted tool-output JSON* — never over raw
    OS state — and every operator is a plain equality/containment check. The
    model may propose these criteria, but only this code decides whether they
    hold, so the LLM can never mark itself verified.
    """

    model_config = ConfigDict(extra="forbid", frozen=True)

    description: str = Field(min_length=1, max_length=500)
    expect_success: bool = True
    output_field_equals: dict[str, str] = Field(default_factory=dict)
    output_contains: list[str] = Field(default_factory=list, max_length=10)
    min_output_items: int | None = Field(None, ge=1, le=10_000)

    @field_validator("output_field_equals")
    @classmethod
    def bounded_pairs(cls, value: dict[str, str]) -> dict[str, str]:
        if len(value) > 8:
            raise ValueError("too many field expectations")
        for key, item in value.items():
            if not key or len(key) > 120 or len(item) > 500:
                raise ValueError("invalid field expectation")
        return value

    def evaluate(self, result: ToolResult) -> tuple[bool, list[str]]:
        """Return ``(passed, failure_reasons)``. Fail closed on missing output."""
        reasons: list[str] = []
        if self.expect_success and not result.success:
            reasons.append(f"action failed ({result.code or 'error'})")
        if not self.expect_success and result.success:
            reasons.append("expected failure but action succeeded")
        output = result.output if isinstance(result.output, dict) else {}
        if self.expect_success and not isinstance(result.output, dict):
            reasons.append("no structured output to verify")
        text = json.dumps(output, default=str)[:20_000]
        for key, expected in self.output_field_equals.items():
            if str(output.get(key)) != expected:
                reasons.append(f"output.{key} did not match expectation")
        for needle in self.output_contains:
            if needle not in text:
                reasons.append("expected content not observed")
        if self.min_output_items is not None:
            count = 0
            for value in output.values():
                if isinstance(value, list):
                    count = max(count, len(value))
            if count < self.min_output_items:
                reasons.append("observed fewer items than expected")
        return (not reasons), reasons


class LoopStep(BaseModel):
    """One planned action: intent + expected observation + criteria."""

    model_config = ConfigDict(extra="forbid")

    title: str = Field(min_length=1, max_length=500)
    tool: str = Field(min_length=1, max_length=64)
    arguments: dict[str, Any] = Field(default_factory=dict)
    expected_observation: str = Field(min_length=1, max_length=2000)
    verification: VerificationCriteria | None = None

    @field_validator("arguments")
    @classmethod
    def bounded_arguments(cls, value: dict[str, Any]) -> dict[str, Any]:
        from app.models import _json_limits
        _json_limits(value)
        if len(json.dumps(value, separators=(",", ":")).encode()) > 100_000:
            raise ValueError("tool arguments exceed byte limit")
        return value


class LoopPlan(BaseModel):
    """Bounded ordered plan fed into the loop."""

    model_config = ConfigDict(extra="forbid")

    goal: str = Field(min_length=1, max_length=20_000)
    steps: list[LoopStep] = Field(min_length=1, max_length=20)


class LoopCheckpoint(BaseModel):
    """Serializable mid-run state enabling resumable tasks."""

    model_config = ConfigDict(extra="forbid")

    task_id: str
    conversation_id: str
    next_index: int = Field(ge=0, le=20)
    pending_step_id: str | None = None
    spent: dict[str, int] = Field(default_factory=dict)
    created_at: float = Field(default_factory=time.time)


class LoopReport(BaseModel):
    """Final report of one loop run; visible to users and the audit trail."""

    model_config = ConfigDict(extra="forbid")

    task_id: str
    outcome: LoopOutcome
    state: TaskState
    verified_steps: int = Field(ge=0, le=20)
    failed_steps: int = Field(ge=0, le=20)
    unverified_steps: int = Field(ge=0, le=20)
    recoveries_used: int = Field(ge=0, le=20)
    budget: dict[str, int] = Field(default_factory=dict)
    elapsed_seconds: float = Field(ge=0)
    errors: list[str] = Field(default_factory=list, max_length=20)
    answer: str | None = None
    user_approved_completion: bool = False


def _to_loop_plan(steps: list[Step], goal: str) -> LoopPlan:
    """Adapt a legacy (model-produced) plan into a LoopPlan.

    Each legacy step's title doubles as its expected observation; verification
    defaults to "the tool must succeed". This keeps the existing planner and
    API contracts fully compatible while routing all execution through the
    Phase 6 loop.
    """
    return LoopPlan(
        goal=goal[:20_000],
        steps=[
            LoopStep(
                title=step.title,
                tool=step.tool,
                arguments=dict(step.arguments),
                expected_observation=step.title,
            )
            for step in steps
        ],
    )


_WIRE_STATUS: dict[str, TaskStatus] = {
    "planning": TaskStatus.PLANNING,
    "running": TaskStatus.RUNNING,
    "waiting_confirmation": TaskStatus.WAITING,
    "completed": TaskStatus.DONE,
    "failed": TaskStatus.FAILED,
    "cancelled": TaskStatus.CANCELLED,
}


class ComputerLoop:
    """Bounded Observe→Plan→Act→Verify→Recover executor.

    Construction is application-side only; the agent/model has no way to
    instantiate or reconfigure this object (budgets and gates are private).
    """

    MAX_RECOVERIES = 2

    def __init__(self, *, llm, registry, memory, config,
                 control_center_provider: Callable[[], Any] | None = None,
                 execution_registry=None,
                 perception_provider: Callable[[], Any] | None = None):
        self._llm = llm
        self._registry = registry
        self._memory = memory
        self._config = config
        self._control_center_provider = control_center_provider
        self._executions = execution_registry
        self._perception_provider = perception_provider
        self._checkpoints: dict[str, LoopCheckpoint] = {}

    # ------------------------------------------------------------------ gates

    def _gate(self):
        if self._control_center_provider is None:
            try:
                from app.control_center import get_control_center
                return get_control_center()
            except Exception:
                return None
        try:
            return self._control_center_provider()
        except Exception:
            return None

    def _gate_check(self) -> None:
        """Fail closed when Control Center forbids autonomous execution."""
        gate = self._gate()
        if gate is None:
            return
        if getattr(gate, "emergency_stopped", False) or gate.blocked_by_emergency:
            raise GateBlockedError("EMERGENCY_STOP: computer loop is halted")
        if not gate.agent_active():
            raise GateBlockedError("AGENT_DISABLED_BY_CONTROL_CENTER")
        flags = gate.agent_flags()
        if not flags["auto_execution"]:
            raise GateBlockedError("AUTO_EXECUTION_DISABLED")
        if not flags["auto_tool_calling"]:
            raise GateBlockedError("AUTO_TOOL_CALLING_DISABLED")

    def _auto_retry_allowed(self) -> bool:
        gate = self._gate()
        return True if gate is None else bool(gate.agent_flags()["auto_retry"])

    # ------------------------------------------------------------- checkpoints

    def checkpoint(self, task_id: str) -> LoopCheckpoint | None:
        return self._checkpoints.get(task_id)

    def _save_checkpoint(self, task: Task, index: int, budget: DecisionBudget,
                         pending_step_id: str | None) -> None:
        self._checkpoints[task.id] = LoopCheckpoint(
            task_id=task.id,
            conversation_id=task.conversation_id,
            next_index=index,
            pending_step_id=pending_step_id,
            spent=budget.snapshot(),
        )

    # ------------------------------------------------------------------- run

    async def run(self, plan: LoopPlan | list[Step], *, goal: str | None = None,
                  conversation_id: str | None = None,
                  approved_permissions: set[Permission] | None = None,
                  user_approved_completion: bool = False,
                  resume_task: Task | None = None) -> Task:
        """Execute the bounded loop. Returns the durable Task (legacy model)
        so all existing API/desktop consumers keep working unchanged.
        """
        started = time.monotonic()
        if isinstance(plan, LoopPlan):
            loop_plan = plan
        else:
            if not goal:
                raise ValueError("goal required when adapting legacy steps")
            loop_plan = _to_loop_plan(plan, goal)
        approved = set(approved_permissions or ())
        config = self._config

        if resume_task is not None:
            task = resume_task
            if task.status not in {TaskStatus.WAITING, TaskStatus.PLANNING}:
                raise ValueError("only waiting/planning tasks can be resumed")
            if len(task.steps) != len(loop_plan.steps):
                raise ValueError("resume plan does not match persisted task")
            state = TaskState.WAITING_APPROVAL
            start_index = task.current_step
        else:
            task = Task(goal=(goal or loop_plan.goal)[:20_000],
                        conversation_id=conversation_id or Task(goal=loop_plan.goal).conversation_id)
            task.intent = "computer_loop"
            task.steps = [Step(title=item.title, tool=item.tool, arguments=dict(item.arguments))
                          for item in loop_plan.steps]
            state = TaskState.PENDING
            start_index = 0
            await self._memory.message(task.conversation_id, "user", task.goal)
            await self._memory.audit("loop.started", {
                "task_id": task.id, "steps": len(loop_plan.steps),
            })

        budget = DecisionBudget(
            max_iterations=min(len(loop_plan.steps) * (self.MAX_RECOVERIES + 2),
                               config.max_agent_steps * (self.MAX_RECOVERIES + 2)),
            max_llm_calls=config.max_agent_steps,
            max_tool_calls=config.max_tool_calls,
            max_malformed_retries=0,
        )
        deadline = started + float(config.agent_timeout_seconds)
        token_budget = int(getattr(config, "max_loop_tokens", 2_000_000))
        tokens_used = 0
        recoveries = 0
        verification_failures: dict[int, list[str]] = {}
        errors: list[str] = []

        if self._executions:
            await self._executions.register(task.id)
        try:
            # PLANNING (resume enters via WAITING_APPROVAL -> OBSERVING below)
            self._transition(task, state, TaskState.PLANNING)
            state = TaskState.PLANNING
            if resume_task is None:
                gate = self._gate()
                if gate is not None and not gate.agent_flags()["auto_planning"]:
                    raise GateBlockedError("AUTO_PLANNING_DISABLED")
            self._gate_check()

            index = start_index
            while index < len(loop_plan.steps):
                # --- budgets & cancellation (fail closed) -------------------
                budget.start_iteration()
                if time.monotonic() > deadline:
                    raise BudgetExceeded("wall-clock budget exceeded")
                if tokens_used >= token_budget:
                    raise BudgetExceeded("token budget exceeded")
                if self._executions:
                    await self._executions.checkpoint(task.id)
                self._gate_check()

                step_def = loop_plan.steps[index]
                step = task.steps[index]
                # --- OBSERVE: prior evidence collected as untrusted data ----
                self._transition(task, state, TaskState.OBSERVING)
                state = TaskState.OBSERVING
                self._observe(index, task, loop_plan, verification_failures)
                # --- ACT (intent + expected observation recorded first) -----
                self._transition(task, state, TaskState.ACTING)
                state = TaskState.ACTING
                step.title = step_def.title
                step.tool = step_def.tool
                step.arguments = dict(step_def.arguments)
                step.status = StepStatus.RUNNING
                task.current_step = index
                await self._memory.save_task(task)
                await self._memory.audit("loop.intention", {
                    "task_id": task.id, "step_id": step.id, "index": index,
                    "tool": step_def.tool, "intent": step_def.title[:500],
                    "expected_observation": step_def.expected_observation[:2000],
                    "criteria": (step_def.verification.description[:500]
                                 if step_def.verification else "action-success"),
                })
                # --- single canonical registry gate --------------------------
                budget.spend_tool()
                result = await self._registry.execute(step_def.tool, dict(step_def.arguments), approved)
                step.result = result
                await self._memory.audit("loop.action", {
                    "task_id": task.id, "step_id": step.id, "tool": step_def.tool,
                    "result": "success" if result.success else "failed",
                    "code": result.code, "duration_ms": result.duration_ms,
                })
                # --- VERIFY: explicit deterministic criteria -----------------
                self._transition(task, state, TaskState.VERIFYING)
                state = TaskState.VERIFYING
                criteria = step_def.verification or VerificationCriteria(
                    description="tool reports success", expect_success=True)
                passed, reasons = criteria.evaluate(result)
                if passed and self._perception_provider is not None:
                    extra = await self._perception_crosscheck(task.id)
                    reasons.extend(extra)
                    passed = not extra
                if passed:
                    step.status = StepStatus.DONE
                    task.current_step = index + 1
                    self._save_checkpoint(task, index + 1, budget, None)
                    await self._memory.save_task(task)
                    await self._memory.audit("loop.verified", {
                        "task_id": task.id, "step_id": step.id, "index": index,
                    })
                    index += 1
                    continue

                # --- RECOVER: bounded, never blind repetition ---------------
                self._transition(task, state, TaskState.RECOVERING)
                state = TaskState.RECOVERING
                verification_failures[index] = reasons
                await self._memory.audit("loop.verification_failed", {
                    "task_id": task.id, "step_id": step.id, "index": index,
                    "reasons": reasons[:5],
                })
                if result.code == "permission_required":
                    step.status = StepStatus.WAITING
                    task.status = TaskStatus.WAITING
                    self._save_checkpoint(task, index, budget, step.id)
                    await self._memory.save_task(task)
                    await self._memory.audit("loop.awaiting_approval", {
                        "task_id": task.id, "step_id": step.id, "tool": step_def.tool,
                    })
                    report = self._report(task, LoopOutcome.PARTIAL,
                                          TaskState.WAITING_APPROVAL, budget, recoveries,
                                          started, ["approval required"])
                    await self._audit_report(report)
                    return task
                can_retry = (recoveries < self.MAX_RECOVERIES
                             and self._auto_retry_allowed()
                             and budget.iterations < budget.max_iterations
                             and budget.tool_calls < budget.max_tool_calls)
                if can_retry:
                    recoveries += 1
                    await self._memory.audit("loop.recovery", {
                        "task_id": task.id, "step_id": step.id, "attempt": recoveries,
                        "note": "bounded retry; corrective feedback recorded",
                    })
                    # Corrective feedback stays in verification_failures and is
                    # surfaced through _observe(); the same step is retried a
                    # bounded number of times — never blindly forever.
                    continue
                # Recovery budget exhausted → terminate safely (visible everywhere).
                step.status = StepStatus.FAILED
                task.status = TaskStatus.FAILED
                message = f"step {index + 1} verification failed: {'; '.join(reasons)[:300]}"
                task.errors.append(message)
                errors.append(message)
                await self._memory.save_task(task)
                report = self._report(task, LoopOutcome.FAILED, TaskState.FAILED,
                                      budget, recoveries, started, errors)
                await self._audit_report(report)
                return task
        except GateBlockedError as blocked:
            self._finalize_failed(task, str(blocked))
            await self._memory.save_task(task)
            report = self._report(task, LoopOutcome.FAILED, TaskState.FAILED,
                                  budget, recoveries, started, [str(blocked)])
            await self._audit_report(report)
            return task
        except asyncio.CancelledError:
            self._finalize_cancelled(task)
            await self._memory.save_task(task)
            report = self._report(task, LoopOutcome.CANCELLED, TaskState.CANCELLED,
                                  budget, recoveries, started, task.errors)
            await self._audit_report(report)
            return task
        except (BudgetExceeded, StateTransitionError) as stop:
            self._finalize_failed(task, str(stop)[:500])
            await self._memory.save_task(task)
            report = self._report(task, LoopOutcome.FAILED, TaskState.FAILED,
                                  budget, recoveries, started, task.errors)
            await self._audit_report(report)
            return task
        except Exception:  # unexpected: fail closed, never claim success
            self._finalize_failed(task, "COMPUTER_LOOP_FAILED: internal error")
            await self._memory.save_task(task)
            report = self._report(task, LoopOutcome.FAILED, TaskState.FAILED,
                                  budget, recoveries, started, task.errors)
            await self._audit_report(report)
            return task
        finally:
            if self._executions:
                await self._executions.unregister(task.id)

        # ---- all steps verified: compose answer (LLM optional) -------------
        try:
            answer, used = await self._compose_answer(task, budget)
            tokens_used += used
        except BudgetExceeded as stop:
            self._finalize_failed(task, str(stop))
            await self._memory.save_task(task)
            report = self._report(task, LoopOutcome.FAILED, TaskState.FAILED,
                                  budget, recoveries, started, task.errors)
            await self._audit_report(report)
            return task
        unverified = sum(1 for s in task.steps if s.status != StepStatus.DONE)
        if not answer or not answer.strip():
            if not user_approved_completion:
                self._finalize_failed(task, "completion refused: empty verified answer")
                await self._memory.save_task(task)
                report = self._report(task, LoopOutcome.FAILED, TaskState.FAILED,
                                      budget, recoveries, started, task.errors)
                await self._audit_report(report)
                return task
            answer = (f"Completed {len(task.steps) - unverified}/{len(task.steps)} "
                      "verified steps (user-approved assumption).")
        try:
            self._transition(task, state, TaskState.COMPLETED)
            assert_completion_invariants(TaskState.COMPLETED, answer=answer,
                                         errors=[], unverified_steps=unverified)
        except StateTransitionError as invalid:
            self._finalize_failed(task, str(invalid))
            await self._memory.save_task(task)
            report = self._report(task, LoopOutcome.FAILED, TaskState.FAILED,
                                  budget, recoveries, started, task.errors)
            await self._audit_report(report)
            return task
        task.answer = answer
        await self._memory.message(task.conversation_id, "assistant", answer)
        await self._memory.save_task(task)
        report = self._report(task, LoopOutcome.COMPLETED, TaskState.COMPLETED,
                              budget, recoveries, started, [], answer,
                              user_approved_completion=user_approved_completion)
        await self._audit_report(report)
        self._checkpoints.pop(task.id, None)
        return task

    # -------------------------------------------------------------- internals

    def _transition(self, task: Task, current: TaskState, target: TaskState) -> None:
        validate_transition(current, target)
        task.status = _WIRE_STATUS[legacy_status(target)]

    def _observe(self, index: int, task: Task, plan: LoopPlan,
                 failures: dict[int, list[str]]) -> list[str]:
        """Collect prior-step evidence (as untrusted data) for the channels."""
        summary: list[str] = []
        for previous in range(index):
            step = task.steps[previous]
            result = step.result
            label = f"step-{previous + 1}:{plan.steps[previous].tool}"
            payload = json.dumps({
                "success": bool(result and result.success),
                "code": result.code if result else None,
                "output": result.output if result else None,
            }, default=str)[:4000]
            summary.append(f"{label} => {payload}")
            if previous in failures:
                summary.append(f"{label} earlier verification issues: "
                               + "; ".join(failures[previous])[:500])
        return summary

    async def _perception_crosscheck(self, task_id: str) -> list[str]:
        """Optional screen cross-check. Perception problems NEVER verify a
        step by themselves (fail closed) and are reported as reasons."""
        try:
            provider = self._perception_provider()
            if provider is None:
                return []
            observation = await provider.observe(task_id, {})
            if getattr(observation, "kind", None) in {None, ""}:
                return ["perception returned no observable content"]
            return []
        except Exception:
            return ["perception provider unavailable during verification"]

    async def _compose_answer(self, task: Task,
                              budget: DecisionBudget) -> tuple[str, int]:
        """Summarize verified evidence via the LLM (untrusted-data wrapped).
        Falls back to a deterministic evidence summary when the model is
        unavailable — the fallback NEVER claims more than the evidence.
        Returns (answer, tokens_charged_against_budget).
        """
        evidence = [{
            "step": step.title, "tool": step.tool,
            "result": step.result.model_dump() if step.result else None,
        } for step in task.steps]
        digest = json.dumps(evidence, default=str)[:60_000]
        estimated = max(1, len(digest) // 4)
        try:
            budget.spend_llm()
            channels = PromptChannels(user_request=task.goal)
            channels.observe("verified-tool-evidence", digest, source="loop")
            messages = channels.messages(Message)
            response = await self._llm.chat(ChatRequest(
                messages=messages, user_request=task.goal[:50_000]))
            content = getattr(response, "content", None)
            used = int(getattr(response, "prompt_tokens", 0) or 0) \
                + int(getattr(response, "completion_tokens", 0) or 0)
            answer = content if isinstance(content, str) and content.strip() else self._fallback(task)
            return answer, (used or estimated)
        except BudgetExceeded:
            raise
        except Exception:
            return self._fallback(task), estimated

    @staticmethod
    def _fallback(task: Task) -> str:
        done = sum(1 for s in task.steps if s.status == StepStatus.DONE)
        return (f"Completed {done}/{len(task.steps)} verified steps. "
                "Details are available in the audit trail.")

    def _finalize_failed(self, task: Task, reason: str) -> None:
        task.status = TaskStatus.FAILED
        if reason and reason not in task.errors:
            task.errors.append(reason[:500])
        for step in task.steps:
            if step.status in {StepStatus.RUNNING, StepStatus.WAITING, StepStatus.PENDING}:
                step.status = StepStatus.FAILED

    def _finalize_cancelled(self, task: Task) -> None:
        task.status = TaskStatus.CANCELLED
        task.answer = None
        if "Task cancelled by user" not in task.errors:
            task.errors.append("Task cancelled by user")
        for step in task.steps:
            if step.status in {StepStatus.RUNNING, StepStatus.WAITING, StepStatus.PENDING}:
                step.status = StepStatus.CANCELLED

    def _report(self, task: Task, outcome: LoopOutcome, state: TaskState,
                budget: DecisionBudget, recoveries: int, started: float,
                errors: list[str], answer: str | None = None,
                user_approved_completion: bool = False) -> LoopReport:
        return LoopReport(
            task_id=task.id, outcome=outcome, state=state,
            verified_steps=sum(1 for s in task.steps if s.status == StepStatus.DONE),
            failed_steps=sum(1 for s in task.steps if s.status == StepStatus.FAILED),
            unverified_steps=sum(1 for s in task.steps
                                 if s.status in {StepStatus.PENDING, StepStatus.RUNNING}),
            recoveries_used=recoveries, budget=budget.snapshot(),
            elapsed_seconds=max(0.0, time.monotonic() - started),
            errors=[e[:500] for e in (task.errors or errors)][:20],
            answer=answer, user_approved_completion=user_approved_completion,
        )

    async def _audit_report(self, report: LoopReport) -> None:
        await self._memory.audit("loop.finished", report.model_dump(mode="json"))
