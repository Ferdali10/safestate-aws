"""Fail-closed execution gateway and local simulated AWS executor.

The gateway is the only supported orchestration path: it obtains a fresh
DecisionService result, requires one-time human approval where needed, and
calls an injected executor only after authorization succeeds.

The simulated executor never makes network or AWS API calls.
"""
from __future__ import annotations

from dataclasses import dataclass
from threading import RLock
from typing import Any, Mapping, Protocol

from .approvals import ApprovalCredential, ApprovalError, ApprovalService
from .models import ActionRequest, ActionType, Decision, DecisionStatus


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
    ) -> None:
        self._decisions = decision_service
        self._approvals = approval_service
        self._executor = executor
        self._revalidator = revalidator
        self._risk_budget = risk_budget_store

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
            self._approvals.consume(credential, request)
        except ApprovalError:
            return self._blocked_result(fresh, "APPROVAL_INVALID_OR_CONSUMED")
        except Exception:  # noqa: BLE001 - store failures fail closed
            return self._blocked_result(fresh, "APPROVAL_STORE_FAILED")
        return self._execute_after_allow(request, fresh)

    def _execute_after_allow(
        self, request: ActionRequest, decision: Decision,
        reservation_id: str | None = None,
    ) -> GatewayResult:
        if decision.status is not DecisionStatus.ALLOW and (
            decision.status is not DecisionStatus.REQUIRE_APPROVAL
        ):
            return self._blocked_result(decision, "DECISION_NOT_EXECUTABLE")
        effective_reservation = reservation_id or decision.risk_reservation_id
        if effective_reservation is not None and self._risk_budget is None:
            return self._blocked_result(decision, "RISK_LEDGER_UNAVAILABLE")
        try:
            result = self._executor.execute(request)
            if not isinstance(result, Mapping):
                raise TypeError("executor result must be a mapping")
        except Exception:  # noqa: BLE001 - execution errors are never reported as success
            if effective_reservation is not None:
                try:
                    released = self._risk_budget.release(effective_reservation)
                    if released is not True:
                        raise RuntimeError("reservation release returned false")
                except Exception:  # noqa: BLE001
                    return self._blocked_result(decision, "EXECUTOR_FAILED_RISK_RELEASE_FAILED")
            return self._blocked_result(decision, "EXECUTOR_FAILED")
        if effective_reservation is not None:
            try:
                settled = self._risk_budget.settle(effective_reservation)
            except Exception:  # noqa: BLE001
                settled = False
            if settled is not True:
                return GatewayResult(
                    outcome="EXECUTED_ACCOUNTING_FAILED",
                    decision=decision,
                    execution=dict(result),
                    error_code="RISK_SETTLEMENT_FAILED",
                )
        return GatewayResult(
            outcome="EXECUTED", decision=decision, execution=dict(result)
        )

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
