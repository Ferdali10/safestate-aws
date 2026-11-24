"""Fail-closed execution gateway and local simulated AWS executor.

The gateway is the only supported orchestration path: it obtains a fresh
DecisionService result, requires one-time human approval where needed, and
calls an injected executor only after authorization succeeds.

The simulated executor never makes network or AWS API calls.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from threading import RLock
from typing import Any, Mapping, Protocol

from .approvals import ApprovalCredential, ApprovalError, ApprovalService
from .models import ActionRequest, ActionType, Decision, DecisionStatus
from .recovery import ExecutionJournal, ExecutionRecord, ExecutionState


class ExecutionNotAppliedError(RuntimeError):
    """Executor guarantee: the requested side effect was not applied."""


class Executor(Protocol):
    """Narrow execution interface; implementations must not make policy decisions."""

    def execute(self, request: ActionRequest) -> Mapping[str, Any]: ...


class DecisionRevalidator(Protocol):
    """Fresh, trusted policy/context check before an approved mutation executes.

    Implementations must be side-effect-free: in particular, they must not
    reserve or charge R8 budget a second time. Production wiring must provide
    an implementation with fresh trusted mission/resource context.
    """

    def revalidate(self, request: ActionRequest) -> Decision: ...


@dataclass(frozen=True, slots=True)
class GatewayResult:
    outcome: str
    decision: Decision
    execution: Mapping[str, Any] | None = None
    approval: ApprovalCredential | None = None
    error_code: str | None = None


class ExecutionGateway:
    """Route requests through policy and approval before invoking an executor."""

    def __init__(
        self,
        decision_service,
        approval_service: ApprovalService,
        executor: Executor,
        revalidator: DecisionRevalidator | None = None,
        risk_budget_store=None,
        execution_journal: ExecutionJournal | None = None,
        clock=None,
    ) -> None:
        self._decisions = decision_service
        self._approvals = approval_service
        self._executor = executor
        self._revalidator = revalidator
        self._risk_budget = risk_budget_store
        self._execution_journal = execution_journal
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def submit(self, request: ActionRequest) -> GatewayResult:
        """Evaluate a request; execute ALLOW, or issue a pending approval."""
        try:
            decision = self._decisions.decide(request)
        except Exception:  # noqa: BLE001 - decision service faults fail closed
            return self._blocked_result(
                self._fallback_decision(request), "DECISION_SERVICE_FAILED"
            )
        if not self._valid_decision(decision, request):
            return self._blocked_result(
                self._fallback_decision(request), "INVALID_DECISION"
            )
        if decision.status is DecisionStatus.BLOCK:
            return self._blocked_result(decision, "POLICY_BLOCKED")
        if decision.status is DecisionStatus.REQUIRE_APPROVAL:
            try:
                credential = self._approvals.issue(request, decision)
            except Exception:  # noqa: BLE001 - no approval, no execution
                return self._blocked_result(decision, "APPROVAL_ISSUE_FAILED")
            return GatewayResult(
                outcome="APPROVAL_REQUIRED", decision=decision, approval=credential
            )
        return self._execute_after_allow(request, decision)

    def execute_approved(
        self, request: ActionRequest, credential: ApprovalCredential
    ) -> GatewayResult:
        """Revalidate trusted context, consume one-time approval, then execute."""
        if self._revalidator is None:
            return self._blocked_result(
                self._fallback_decision(request), "REVALIDATOR_UNAVAILABLE"
            )
        try:
            fresh = self._revalidator.revalidate(request)
        except Exception:  # noqa: BLE001 - fresh context/policy failure blocks
            return self._blocked_result(
                self._fallback_decision(request), "REVALIDATION_FAILED"
            )
        if not self._valid_decision(fresh, request):
            return self._blocked_result(
                self._fallback_decision(request), "INVALID_REVALIDATION_RESULT"
            )
        if fresh.status is DecisionStatus.BLOCK:
            return self._blocked_result(fresh, "POLICY_BLOCKED_ON_REVALIDATION")
        try:
            reservation_id = self._approvals.reservation_id_for(credential)
        except ApprovalError:
            return self._blocked_result(fresh, "APPROVAL_INVALID_OR_CONSUMED")
        except Exception:  # noqa: BLE001 - store failures fail closed
            return self._blocked_result(fresh, "APPROVAL_STORE_FAILED")
        if reservation_id is not None and self._risk_budget is None:
            return self._blocked_result(fresh, "RISK_LEDGER_UNAVAILABLE")
        try:
            approval_record = self._approvals.consume(credential, request)
        except ApprovalError:
            return self._blocked_result(fresh, "APPROVAL_INVALID_OR_CONSUMED")
        except Exception:  # noqa: BLE001 - store failures fail closed
            return self._blocked_result(fresh, "APPROVAL_STORE_FAILED")
        return self._execute_after_allow(
            request, fresh, reservation_id=approval_record.risk_reservation_id
        )

    def _execute_after_allow(
        self, request: ActionRequest, decision: Decision,
        reservation_id: str | None = None,
    ) -> GatewayResult:
        if decision.status not in {
            DecisionStatus.ALLOW, DecisionStatus.REQUIRE_APPROVAL
        }:
            return self._blocked_result(decision, "DECISION_NOT_EXECUTABLE")
        effective_reservation = reservation_id or decision.risk_reservation_id
        if effective_reservation is not None and self._risk_budget is None:
            return self._blocked_result(decision, "RISK_LEDGER_UNAVAILABLE")
        if self._execution_journal is not None:
            return self._execute_with_journal(request, decision, effective_reservation)
        return self._execute_legacy(request, decision, effective_reservation)

    def _execute_legacy(
        self, request: ActionRequest, decision: Decision,
        reservation_id: str | None,
    ) -> GatewayResult:
        """Compatibility path for callers that have not wired a journal yet."""
        try:
            result = self._executor.execute(request)
            if not isinstance(result, Mapping):
                raise TypeError("executor result must be a mapping")
        except Exception:  # noqa: BLE001 - legacy behavior retained
            if reservation_id is not None:
                try:
                    if self._risk_budget.release(reservation_id) is not True:
                        raise RuntimeError("reservation release returned false")
                except Exception:  # noqa: BLE001
                    return self._blocked_result(decision, "EXECUTOR_FAILED_RISK_RELEASE_FAILED")
            return self._blocked_result(decision, "EXECUTOR_FAILED")
        if reservation_id is not None:
            try:
                settled = self._risk_budget.settle(reservation_id)
            except Exception:  # noqa: BLE001
                settled = False
            if settled is not True:
                return GatewayResult(
                    outcome="EXECUTED_ACCOUNTING_FAILED", decision=decision,
                    execution=dict(result), error_code="RISK_SETTLEMENT_FAILED",
                )
        return GatewayResult(outcome="EXECUTED", decision=decision, execution=dict(result))

    def _execute_with_journal(
        self, request: ActionRequest, decision: Decision,
        reservation_id: str | None,
    ) -> GatewayResult:
        """Execute only after the journal claims PREPARED -> EXECUTING."""
        journal = self._execution_journal
        now = self._now()
        mission_key = decision.risk_mission_key or (
            f"{request.agent_id}:{request.mission_id}:{request.mission_version}"
        )
        execution_id = f"{mission_key}:{request.request_id}"
        record = ExecutionRecord(
            execution_id=execution_id, request_id=request.request_id,
            mission_key=mission_key, reservation_id=reservation_id,
            action=request.action.value, resource_id=request.resource_id,
            state=ExecutionState.PREPARED, created_at=now, updated_at=now,
        )
        try:
            existing = journal.prepare(record)
        except Exception:  # noqa: BLE001 - journal failure blocks before executor
            return self._blocked_result(decision, "EXECUTION_JOURNAL_PREPARE_FAILED")
        if existing.state is not ExecutionState.PREPARED:
            return self._blocked_result(decision, "EXECUTION_ALREADY_CLAIMED_OR_TERMINAL")
        try:
            claimed = journal.transition(
                execution_id, ExecutionState.PREPARED,
                ExecutionState.EXECUTING, self._now(),
            )
        except Exception:  # noqa: BLE001
            claimed = False
        if claimed is not True:
            return self._blocked_result(decision, "EXECUTION_JOURNAL_CLAIM_FAILED")

        try:
            result = self._executor.execute(request)
            if not isinstance(result, Mapping):
                raise RuntimeError("executor returned a non-mapping result")
        except ExecutionNotAppliedError:
            # Only this explicit signal guarantees that no side effect occurred.
            try:
                marked = journal.transition(
                    execution_id, ExecutionState.EXECUTING,
                    ExecutionState.FAILED, self._now(),
                )
            except Exception:  # noqa: BLE001
                marked = False
            if marked is not True:
                return self._blocked_result(decision, "EXECUTION_FAILURE_JOURNAL_FAILED")
            # Claim RELEASING in the journal before touching R8, exactly as the
            # recovery service does, so the two paths cannot release concurrently.
            try:
                claimed_release = journal.transition(
                    execution_id, ExecutionState.FAILED,
                    ExecutionState.RELEASING, self._now(),
                )
            except Exception:  # noqa: BLE001
                claimed_release = False
            if claimed_release is not True:
                return self._blocked_result(decision, "EXECUTION_FAILURE_JOURNAL_FAILED")
            if reservation_id is not None:
                try:
                    released = self._risk_budget.release(reservation_id)
                except Exception:  # noqa: BLE001
                    released = False
                if released is not True:
                    # RELEASING is retained; recovery retries the release safely.
                    return self._blocked_result(decision, "EXECUTOR_FAILED_RISK_RELEASE_FAILED")
            try:
                finalized = journal.transition(
                    execution_id, ExecutionState.RELEASING,
                    ExecutionState.RELEASED, self._now(),
                )
            except Exception:  # noqa: BLE001
                finalized = False
            if finalized is not True:
                return self._blocked_result(decision, "EXECUTION_FAILURE_FINALIZE_FAILED")
            return self._blocked_result(decision, "EXECUTOR_FAILED")
        except Exception:  # noqa: BLE001 - generic failure may follow a side effect
            try:
                journal.transition(
                    execution_id, ExecutionState.EXECUTING,
                    ExecutionState.UNKNOWN, self._now(),
                )
            except Exception:  # noqa: BLE001
                pass
            return self._blocked_result(decision, "EXECUTION_OUTCOME_UNKNOWN")

        try:
            marked = journal.transition(
                execution_id, ExecutionState.EXECUTING,
                ExecutionState.EXECUTED, self._now(),
            )
        except Exception:  # noqa: BLE001
            marked = False
        if marked is not True:
            # The side effect may have happened. Never release its reservation.
            return GatewayResult(
                outcome="EXECUTED_RECOVERY_REQUIRED", decision=decision,
                execution=dict(result), error_code="EXECUTION_SUCCESS_JOURNAL_FAILED",
            )
        if reservation_id is not None:
            try:
                settled = self._risk_budget.settle(reservation_id)
            except Exception:  # noqa: BLE001
                settled = False
            if settled is not True:
                return GatewayResult(
                    outcome="EXECUTED_ACCOUNTING_FAILED", decision=decision,
                    execution=dict(result), error_code="RISK_SETTLEMENT_FAILED",
                )
        try:
            finalized = journal.transition(
                execution_id, ExecutionState.EXECUTED,
                ExecutionState.SETTLED, self._now(),
            )
        except Exception:  # noqa: BLE001
            finalized = False
        if finalized is not True:
            return GatewayResult(
                outcome="EXECUTED_RECOVERY_REQUIRED", decision=decision,
                execution=dict(result), error_code="EXECUTION_FINALIZE_FAILED",
            )
        return GatewayResult(outcome="EXECUTED", decision=decision, execution=dict(result))

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("execution clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)

    @staticmethod
    def _valid_decision(decision: object, request: ActionRequest) -> bool:
        return (
            isinstance(decision, Decision)
            and decision.request_id == request.request_id
            and isinstance(decision.status, DecisionStatus)
            and decision.approval_required
            is (decision.status is DecisionStatus.REQUIRE_APPROVAL)
        )

    @staticmethod
    def _fallback_decision(request: ActionRequest) -> Decision:
        from datetime import datetime, timezone

        return Decision(
            decision_id="gateway-fallback",
            request_id=getattr(request, "request_id", "unavailable"),
            status=DecisionStatus.BLOCK,
            rule_id="R7",
            reason_code="GATEWAY_FAIL_CLOSED",
            reason="The gateway could not establish a safe authorization result.",
            policy_version="gateway",
            evaluated_at=datetime.now(timezone.utc),
            approval_required=False,
        )

    @staticmethod
    def _blocked_result(decision: Decision, error_code: str) -> GatewayResult:
        return GatewayResult(
            outcome="BLOCKED", decision=decision, error_code=error_code
        )


class SimulatedAWSExecutor:
    """In-memory AWS-shaped simulator; no SDK, credentials, network or cloud use."""

    SUPPORTED_ACTIONS = frozenset(ActionType)

    def __init__(self) -> None:
        self._lock = RLock()
        self._instance_states = {
            "i-dev-001": "running",
            "i-test-001": "running",
            "i-prod-001": "running",
        }

    def execute(self, request: ActionRequest) -> Mapping[str, Any]:
        if not isinstance(request, ActionRequest):
            raise TypeError("executor accepts only validated ActionRequest objects")
        if request.action not in self.SUPPORTED_ACTIONS:
            raise ValueError("action is not exposed by the simulated executor")
        with self._lock:
            if request.action is ActionType.REQUEST_STOP_INSTANCE:
                if request.resource_id not in self._instance_states:
                    return {
                        "simulated": True,
                        "action": request.action.value,
                        "resource_id": request.resource_id,
                        "status": "NOT_FOUND",
                    }
                self._instance_states[request.resource_id] = "stopped"
                return {
                    "simulated": True,
                    "action": request.action.value,
                    "resource_id": request.resource_id,
                    "previous_state": "running",
                    "state": "stopped",
                }
            if request.action in {
                ActionType.LIST_INSTANCES, ActionType.DESCRIBE_INSTANCE
            }:
                if request.action is ActionType.LIST_INSTANCES:
                    return {
                        "simulated": True,
                        "action": request.action.value,
                        "instances": [
                            {"instance_id": key, "state": value}
                            for key, value in sorted(self._instance_states.items())
                        ],
                    }
                return {
                    "simulated": True,
                    "action": request.action.value,
                    "resource_id": request.resource_id,
                    "state": self._instance_states.get(request.resource_id, "NOT_FOUND"),
                }
            return {
                "simulated": True,
                "action": request.action.value,
                "resource_id": request.resource_id,
                "status": "READ_SIMULATED",
            }
