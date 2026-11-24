from dataclasses import replace
from datetime import datetime, timedelta, timezone

import pytest

from safestate_core.approvals import ApprovalError, ApprovalService, InMemoryApprovalStore
from safestate_core.controls import InMemoryRiskBudgetStore
from safestate_core.execution import ExecutionGateway
from safestate_core.models import DecisionStatus
from test_execution import Harness, decision, request

MK = "agent-1:mission-1:v1"


class Clock:
    def __init__(self):
        self.now = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)

    def __call__(self):
        return self.now


def reserved_decision(req, points=2):
    return decision(
        req, DecisionStatus.REQUIRE_APPROVAL,
        risk_reservation_id=f"{MK}:{req.request_id}", risk_mission_key=MK,
        risk_points=points,
    )


def make_service(clock, ledger, **kw):
    counter = iter(range(1, 1000))
    return ApprovalService(
        InMemoryApprovalStore(), clock, lambda: f"approval-{next(counter)}",
        risk_budget_store=ledger, **kw,
    )


def issue(service, ledger, req):
    assert ledger.reserve(MK, f"{MK}:{req.request_id}", 2, 100)
    return service.issue(req, reserved_decision(req))


def test_requesting_agent_cannot_approve_its_own_request():
    clock, ledger = Clock(), InMemoryRiskBudgetStore()
    service = make_service(clock, ledger)
    credential = issue(service, ledger, request(request_id="r1"))
    with pytest.raises(ApprovalError):
        service.approve(credential, "agent-1")
    assert service.approve(credential, "human-1").approved_by == "human-1"


def test_open_approvals_are_capped_and_the_blocked_reservation_is_released():
    clock, ledger = Clock(), InMemoryRiskBudgetStore()
    service = make_service(clock, ledger, max_open_per_mission=2)
    issue(service, ledger, request(request_id="r1"))
    issue(service, ledger, request(request_id="r2"))
    with pytest.raises(ApprovalError):
        issue(service, ledger, request(request_id="r3"))
    assert ledger.reserved(MK) == 4  # only the two open approvals hold points


def test_expire_stale_frees_budget_of_abandoned_approvals():
    clock, ledger = Clock(), InMemoryRiskBudgetStore()
    service = make_service(clock, ledger, ttl=timedelta(minutes=5))
    issue(service, ledger, request(request_id="r1"))
    assert service.expire_stale() == 0 and ledger.reserved(MK) == 2
    clock.now += timedelta(minutes=6)
    assert service.expire_stale() == 1
    assert ledger.reserved(MK) == 0
    assert service.expire_stale() == 0  # idempotent


def test_expired_slot_can_be_reused_after_a_sweep():
    clock, ledger = Clock(), InMemoryRiskBudgetStore()
    service = make_service(clock, ledger, ttl=timedelta(minutes=5), max_open_per_mission=1)
    issue(service, ledger, request(request_id="r1"))
    clock.now += timedelta(minutes=6)
    issue(service, ledger, request(request_id="r2"))  # expired r1 no longer counts


def gateway_for(h, ledger, **kw):
    return ExecutionGateway(
        h.decisions, h.approvals, h.executor, h.revalidator,
        risk_budget_store=ledger, **kw,
    )


def prepared(clock, ledger):
    h = Harness(DecisionStatus.REQUIRE_APPROVAL)
    h.decisions.result = reserved_decision(h.req)
    h.approvals = make_service(clock, ledger)
    assert ledger.reserve(MK, f"{MK}:{h.req.request_id}", 2, 100)
    return h


def test_secret_goes_to_the_notifier_and_not_back_to_the_caller():
    clock, ledger = Clock(), InMemoryRiskBudgetStore()
    h = prepared(clock, ledger)
    sent = []

    class Notifier:
        def deliver(self, credential, request, decision):
            sent.append(credential)

    result = gateway_for(h, ledger, approval_notifier=Notifier()).submit(h.req)
    assert result.outcome == "APPROVAL_REQUIRED"
    assert result.approval is None
    assert result.approval_id == sent[0].approval_id
    assert h.executor.calls == 0


def test_no_approval_channel_fails_closed_and_releases_the_reservation():
    clock, ledger = Clock(), InMemoryRiskBudgetStore()
    h = prepared(clock, ledger)
    result = gateway_for(h, ledger).submit(h.req)
    assert result.outcome == "BLOCKED"
    assert result.error_code == "APPROVAL_CHANNEL_UNAVAILABLE"
    assert ledger.reserved(MK) == 0


def test_failed_delivery_cancels_the_approval_and_releases_the_reservation():
    clock, ledger = Clock(), InMemoryRiskBudgetStore()
    h = prepared(clock, ledger)

    class Broken:
        def deliver(self, credential, request, decision):
            raise OSError("channel down")

    result = gateway_for(h, ledger, approval_notifier=Broken()).submit(h.req)
    assert result.error_code == "APPROVAL_DELIVERY_FAILED"
    assert ledger.reserved(MK) == 0
    assert h.approvals._store.list_open() == []


def test_submit_sweeps_expired_approvals_before_deciding():
    clock, ledger = Clock(), InMemoryRiskBudgetStore()
    service = make_service(clock, ledger, ttl=timedelta(minutes=5))
    issue(service, ledger, request(request_id="old"))
    clock.now += timedelta(minutes=6)
    h = Harness()
    h.approvals = service
    gateway_for(h, ledger).submit(request(request_id="new"))
    assert ledger.reserved(MK) == 0
