from dataclasses import replace
from datetime import datetime, timedelta, timezone
import itertools

import pytest

from safestate_core.approvals import ApprovalService, InMemoryApprovalStore
from safestate_core.execution import ExecutionGateway, SimulatedAWSExecutor
from safestate_core.models import (
    ActionRequest, ActionType, Decision, DecisionStatus, ResourceType,
)

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)


def request(**changes):
    values = dict(
        request_id="req-gw-1", agent_id="agent-1", mission_id="mission-1",
        mission_version="v1", action=ActionType.DESCRIBE_INSTANCE,
        resource_id="i-dev-001", resource_type=ResourceType.EC2_INSTANCE,
        parameters={}, requested_at=NOW,
    )
    values.update(changes)
    return ActionRequest(**values)


def decision(req, status=DecisionStatus.ALLOW, **changes):
    values = dict(
        decision_id="decision-1", request_id=req.request_id, status=status,
        rule_id="R1" if status is DecisionStatus.ALLOW else "R3",
        reason_code="READ_WITHIN_MISSION", reason="test decision",
        policy_version="test-v1", evaluated_at=NOW,
        approval_required=status is DecisionStatus.REQUIRE_APPROVAL,
    )
    values.update(changes)
    return Decision(**values)


class FakeDecisionService:
    def __init__(self, result):
        self.result = result
        self.calls = 0

    def decide(self, req):
        self.calls += 1
        return self.result


class FakeRevalidator:
    def __init__(self, result=None, error=None):
        self.result = result
        self.error = error
        self.calls = 0

    def revalidate(self, req):
        self.calls += 1
        if self.error:
            raise self.error
        return self.result


class FakeExecutor:
    def __init__(self, result=None, error=None):
        self.result = result or {"simulated": True, "status": "ok"}
        self.error = error
        self.calls = 0

    def execute(self, req):
        self.calls += 1
        if self.error:
            raise self.error
        return self.result


class Harness:
    def __init__(self, initial_status=DecisionStatus.ALLOW, fresh_status=None):
        self.req = request(
            action=ActionType.REQUEST_STOP_INSTANCE
            if initial_status is DecisionStatus.REQUIRE_APPROVAL
            else ActionType.DESCRIBE_INSTANCE
        )
        self.now = NOW
        ids = itertools.count(1)
        self.approvals = ApprovalService(
            InMemoryApprovalStore(), lambda: self.now,
            lambda: f"approval-{next(ids)}", timedelta(minutes=5),
        )
        self.initial = decision(self.req, initial_status)
        self.fresh = decision(self.req, fresh_status or initial_status)
        self.decisions = FakeDecisionService(self.initial)
        self.revalidator = FakeRevalidator(self.fresh)
        self.executor = FakeExecutor()
        self.gateway = ExecutionGateway(
            self.decisions, self.approvals, self.executor, self.revalidator
        )


def test_allow_executes_once():
    h = Harness()
    result = h.gateway.submit(h.req)
    assert result.outcome == "EXECUTED"
    assert result.execution["simulated"] is True
    assert h.executor.calls == 1


def test_block_never_calls_executor():
    h = Harness(DecisionStatus.BLOCK)
    result = h.gateway.submit(h.req)
    assert result.outcome == "BLOCKED"
    assert result.error_code == "POLICY_BLOCKED"
    assert h.executor.calls == 0


def test_require_approval_issues_credential_without_execution():
    h = Harness(DecisionStatus.REQUIRE_APPROVAL)
    result = h.gateway.submit(h.req)
    assert result.outcome == "APPROVAL_REQUIRED"
    assert result.approval is not None
    assert h.executor.calls == 0


def test_approved_request_revalidates_consumes_and_executes():
    h = Harness(DecisionStatus.REQUIRE_APPROVAL)
    pending = h.gateway.submit(h.req)
    h.approvals.approve(pending.approval, "verified-human")
    result = h.gateway.execute_approved(h.req, pending.approval)
    assert result.outcome == "EXECUTED"
    assert h.revalidator.calls == 1
    assert h.executor.calls == 1


def test_approved_request_is_blocked_if_fresh_policy_blocks():
    h = Harness(DecisionStatus.REQUIRE_APPROVAL, DecisionStatus.BLOCK)
    pending = h.gateway.submit(h.req)
    h.approvals.approve(pending.approval, "verified-human")
    result = h.gateway.execute_approved(h.req, pending.approval)
    assert result.outcome == "BLOCKED"
    assert result.error_code == "POLICY_BLOCKED_ON_REVALIDATION"
    assert h.executor.calls == 0


def test_approved_request_fails_closed_without_revalidator():
    h = Harness(DecisionStatus.REQUIRE_APPROVAL)
    pending = h.gateway.submit(h.req)
    h.approvals.approve(pending.approval, "verified-human")
    gateway = ExecutionGateway(h.decisions, h.approvals, h.executor)
    result = gateway.execute_approved(h.req, pending.approval)
    assert result.outcome == "BLOCKED"
    assert result.error_code == "REVALIDATOR_UNAVAILABLE"
    assert h.executor.calls == 0


def test_approval_cannot_be_replayed():
    h = Harness(DecisionStatus.REQUIRE_APPROVAL)
    pending = h.gateway.submit(h.req)
    h.approvals.approve(pending.approval, "verified-human")
    assert h.gateway.execute_approved(h.req, pending.approval).outcome == "EXECUTED"
    replay = h.gateway.execute_approved(h.req, pending.approval)
    assert replay.outcome == "BLOCKED"
    assert replay.error_code == "APPROVAL_INVALID_OR_CONSUMED"
    assert h.executor.calls == 1


def test_executor_failure_is_not_reported_as_success():
    h = Harness()
    h.executor.error = RuntimeError("simulated executor failure")
    result = h.gateway.submit(h.req)
    assert result.outcome == "BLOCKED"
    assert result.error_code == "EXECUTOR_FAILED"


def test_decision_for_another_request_is_rejected():
    h = Harness()
    h.decisions.result = replace(h.initial, request_id="foreign-request")
    result = h.gateway.submit(h.req)
    assert result.outcome == "BLOCKED"
    assert result.error_code == "INVALID_DECISION"
    assert h.executor.calls == 0


def test_invalid_executor_result_is_rejected():
    h = Harness()
    h.executor.result = ["not", "a", "mapping"]
    result = h.gateway.submit(h.req)
    assert result.outcome == "BLOCKED"
    assert result.error_code == "EXECUTOR_FAILED"


def test_simulated_stop_changes_only_in_memory_state():
    executor = SimulatedAWSExecutor()
    req = request(action=ActionType.REQUEST_STOP_INSTANCE)
    result = executor.execute(req)
    assert result["simulated"] is True
    assert result["state"] == "stopped"
    described = executor.execute(request())
    assert described["state"] == "stopped"


def test_simulator_rejects_unknown_action_even_if_constructed_unsafely():
    executor = SimulatedAWSExecutor()
    req = request()
    forged = replace(req, action="DELETE_ALL")
    with pytest.raises(ValueError):
        executor.execute(forged)


def test_allow_settles_risk_reservation_after_success():
    from safestate_core.controls import InMemoryRiskBudgetStore
    ledger = InMemoryRiskBudgetStore()
    assert ledger.reserve("agent:mission:v1", "req-gw-1", 2, 5)
    h = Harness()
    h.initial = replace(
        h.initial, risk_reservation_id="req-gw-1",
        risk_mission_key="agent:mission:v1", risk_points=2,
    )
    h.decisions.result = h.initial
    h.gateway = ExecutionGateway(
        h.decisions, h.approvals, h.executor, h.revalidator,
        risk_budget_store=ledger,
    )
    result = h.gateway.submit(h.req)
    assert result.outcome == "EXECUTED"
    assert ledger.reserved("agent:mission:v1") == 0
    assert ledger.spent("agent:mission:v1") == 2


def test_executor_failure_releases_risk_reservation():
    from safestate_core.controls import InMemoryRiskBudgetStore
    ledger = InMemoryRiskBudgetStore()
    assert ledger.reserve("agent:mission:v1", "req-gw-1", 2, 5)
    h = Harness()
    h.initial = replace(
        h.initial, risk_reservation_id="req-gw-1",
        risk_mission_key="agent:mission:v1", risk_points=2,
    )
    h.decisions.result = h.initial
    h.executor.error = RuntimeError("simulated failure")
    h.gateway = ExecutionGateway(
        h.decisions, h.approvals, h.executor, h.revalidator,
        risk_budget_store=ledger,
    )
    result = h.gateway.submit(h.req)
    assert result.outcome == "BLOCKED"
    assert result.error_code == "EXECUTOR_FAILED"
    assert ledger.reserved("agent:mission:v1") == 0
    assert ledger.spent("agent:mission:v1") == 0


def test_approved_execution_settles_the_original_reservation():
    from safestate_core.controls import InMemoryRiskBudgetStore
    ledger = InMemoryRiskBudgetStore()
    assert ledger.reserve("agent:mission:v1", "req-gw-1", 2, 5)
    h = Harness(DecisionStatus.REQUIRE_APPROVAL)
    h.initial = replace(
        h.initial, risk_reservation_id="req-gw-1",
        risk_mission_key="agent:mission:v1", risk_points=2,
    )
    h.decisions.result = h.initial
    h.approvals = ApprovalService(
        InMemoryApprovalStore(), lambda: h.now, lambda: "approval-with-risk",
        risk_budget_store=ledger,
    )
    h.gateway = ExecutionGateway(
        h.decisions, h.approvals, h.executor, h.revalidator,
        risk_budget_store=ledger,
    )
    pending = h.gateway.submit(h.req)
    assert pending.outcome == "APPROVAL_REQUIRED"
    h.approvals.approve(pending.approval, "verified-human")
    result = h.gateway.execute_approved(h.req, pending.approval)
    assert result.outcome == "EXECUTED"
    assert ledger.reserved("agent:mission:v1") == 0
    assert ledger.spent("agent:mission:v1") == 2
