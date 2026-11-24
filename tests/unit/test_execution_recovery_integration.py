from datetime import datetime, timedelta, timezone

from safestate_core.approvals import ApprovalService, InMemoryApprovalStore
from safestate_core.controls import InMemoryRiskBudgetStore
from safestate_core.execution import (
    ExecutionGateway, ExecutionNotAppliedError,
)
from safestate_core.models import (
    ActionRequest, ActionType, Decision, DecisionStatus, ResourceType,
)
from safestate_core.recovery import (
    ExecutionState, InMemoryExecutionJournal,
)

NOW = datetime(2026, 11, 24, 0, 0, tzinfo=timezone.utc)
MISSION = "agent-1:mission-1:v1"
RESERVATION = f"{MISSION}:req-1"


def make_request():
    return ActionRequest(
        request_id="req-1", agent_id="agent-1", mission_id="mission-1",
        mission_version="v1", action=ActionType.DESCRIBE_INSTANCE,
        resource_id="i-dev-001", resource_type=ResourceType.EC2_INSTANCE,
        parameters={}, requested_at=NOW,
    )


def make_decision(request, reservation=True):
    return Decision(
        decision_id="decision-1", request_id=request.request_id,
        status=DecisionStatus.ALLOW, rule_id="R1",
        reason_code="READ_ALLOWED", reason="test",
        policy_version="test-v1", evaluated_at=NOW,
        approval_required=False,
        risk_reservation_id=RESERVATION if reservation else None,
        risk_mission_key=MISSION if reservation else None,
        risk_points=2 if reservation else 0,
    )


class Decisions:
    def __init__(self, decision):
        self.decision = decision

    def decide(self, request):
        return self.decision


class Executor:
    def __init__(self, error=None):
        self.error = error
        self.calls = 0

    def execute(self, request):
        self.calls += 1
        if self.error:
            raise self.error
        return {"simulated": True, "status": "ok"}


def build(error=None, journal=None):
    request = make_request()
    decision = make_decision(request)
    ledger = InMemoryRiskBudgetStore()
    assert ledger.reserve(MISSION, RESERVATION, 2, 5)
    executor = Executor(error)
    journal = journal or InMemoryExecutionJournal()
    approvals = ApprovalService(
        InMemoryApprovalStore(), lambda: NOW, lambda: "approval-1",
        timedelta(minutes=5), risk_budget_store=ledger,
    )
    gateway = ExecutionGateway(
        Decisions(decision), approvals, executor,
        risk_budget_store=ledger, execution_journal=journal,
        clock=lambda: NOW,
    )
    return request, ledger, executor, journal, gateway


def test_gateway_journals_execution_and_settlement():
    request, ledger, executor, journal, gateway = build()
    result = gateway.submit(request)
    record = journal.get(f"{MISSION}:{request.request_id}")
    assert result.outcome == "EXECUTED"
    assert executor.calls == 1
    assert record.state is ExecutionState.SETTLED
    assert ledger.reserved(MISSION) == 0
    assert ledger.spent(MISSION) == 2


def test_ambiguous_executor_error_moves_to_unknown_and_keeps_reservation():
    request, ledger, executor, journal, gateway = build(RuntimeError("connection lost"))
    result = gateway.submit(request)
    record = journal.get(f"{MISSION}:{request.request_id}")
    assert result.error_code == "EXECUTION_OUTCOME_UNKNOWN"
    assert executor.calls == 1
    assert record.state is ExecutionState.UNKNOWN
    assert ledger.reserved(MISSION) == 2
    assert ledger.spent(MISSION) == 0


def test_explicit_not_applied_error_releases_reservation():
    request, ledger, executor, journal, gateway = build(
        ExecutionNotAppliedError("rejected before applying")
    )
    result = gateway.submit(request)
    record = journal.get(f"{MISSION}:{request.request_id}")
    assert result.error_code == "EXECUTOR_FAILED"
    assert record.state is ExecutionState.RELEASED
    assert ledger.reserved(MISSION) == 0
    assert ledger.spent(MISSION) == 0


def test_same_request_cannot_be_executed_twice():
    request, ledger, executor, journal, gateway = build()
    assert gateway.submit(request).outcome == "EXECUTED"
    replay = gateway.submit(request)
    assert replay.outcome == "BLOCKED"
    assert replay.error_code == "EXECUTION_ALREADY_CLAIMED_OR_TERMINAL"
    assert executor.calls == 1


class BrokenPrepareJournal(InMemoryExecutionJournal):
    def prepare(self, record):
        raise OSError("journal unavailable")


def test_journal_prepare_failure_blocks_before_executor():
    request, ledger, executor, journal, gateway = build(journal=BrokenPrepareJournal())
    result = gateway.submit(request)
    assert result.error_code == "EXECUTION_JOURNAL_PREPARE_FAILED"
    assert executor.calls == 0
    assert ledger.reserved(MISSION) == 2
