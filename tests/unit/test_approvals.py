from dataclasses import replace
from datetime import datetime, timedelta, timezone
import itertools
import threading

import pytest

from safestate_core.approvals import (
    ApprovalError, ApprovalExpiredError, ApprovalService,
    InMemoryApprovalStore,
)
from safestate_core.models import (
    ActionRequest, ActionType, ApprovalStatus, Decision, DecisionStatus,
    ResourceType,
)

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)


def request(**changes):
    values = dict(
        request_id="req-1", agent_id="agent-1", mission_id="mission-1",
        mission_version="v1", action=ActionType.REQUEST_STOP_INSTANCE,
        resource_id="i-dev-1", resource_type=ResourceType.EC2_INSTANCE,
        parameters={"region": "eu-central-1", "dry_run": False},
        requested_at=NOW,
    )
    values.update(changes)
    return ActionRequest(**values)


def decision(**changes):
    values = dict(
        decision_id="dec-1", request_id="req-1",
        status=DecisionStatus.REQUIRE_APPROVAL, rule_id="R3",
        reason_code="STOP_REQUIRES_HUMAN_APPROVAL", reason="Human approval required.",
        policy_version="test-v1", evaluated_at=NOW, approval_required=True,
    )
    values.update(changes)
    return Decision(**values)


class Harness:
    def __init__(self, ttl=timedelta(minutes=5)):
        self.now = NOW
        self.ids = itertools.count(1)
        self.store = InMemoryApprovalStore()
        self.service = ApprovalService(
            self.store, lambda: self.now, lambda: f"approval-{next(self.ids)}", ttl
        )

    def issue(self, req=None):
        return self.service.issue(req or request(), decision())


def test_issue_only_for_require_approval_decision():
    h = Harness()
    with pytest.raises(ApprovalError):
        h.service.issue(request(), decision(status=DecisionStatus.ALLOW, approval_required=False))


def test_issue_requires_matching_request_id():
    h = Harness()
    with pytest.raises(ApprovalError):
        h.service.issue(request(), decision(request_id="other"))


def test_credential_is_opaque_and_record_stores_only_digest():
    h = Harness()
    credential = h.issue()
    record = h.store.get(credential.approval_id)
    assert credential.token
    assert credential.token not in record.token_digest
    assert record.status is ApprovalStatus.PENDING


def test_approve_then_consume_exact_request_once():
    h = Harness()
    req = request()
    credential = h.issue(req)
    approved = h.service.approve(credential, "human:alice")
    assert approved.status is ApprovalStatus.APPROVED
    consumed = h.service.consume(credential.approval_id, req)
    assert consumed.status is ApprovalStatus.CONSUMED
    assert consumed.approved_by == "human:alice"
    with pytest.raises(ApprovalError):
        h.service.consume(credential.approval_id, req)


def test_rejection_cannot_be_consumed():
    h = Harness()
    credential = h.issue()
    h.service.reject(credential, "human:bob")
    with pytest.raises(ApprovalError):
        h.service.consume(credential.approval_id, request())


def test_wrong_token_is_rejected():
    h = Harness()
    credential = h.issue()
    forged = replace(credential, token="attacker-token")
    with pytest.raises(ApprovalError):
        h.service.approve(forged, "human:mallory")


def test_blank_approver_identity_is_rejected():
    h = Harness()
    credential = h.issue()
    with pytest.raises(ApprovalError):
        h.service.approve(credential, "  ")


@pytest.mark.parametrize("changes", [
    {"action": ActionType.DESCRIBE_INSTANCE},
    {"resource_id": "i-other"},
    {"mission_id": "other-mission"},
    {"mission_version": "v2"},
    {"parameters": {"region": "us-east-1", "dry_run": False}},
    {"agent_id": "other-agent"},
])
def test_approval_cannot_be_reused_for_changed_request(changes):
    h = Harness()
    req = request()
    credential = h.issue(req)
    h.service.approve(credential, "human:alice")
    with pytest.raises(ApprovalError):
        h.service.consume(credential.approval_id, request(**changes))


def test_expiry_blocks_human_decision_and_marks_record_expired():
    h = Harness(ttl=timedelta(minutes=1))
    credential = h.issue()
    h.now += timedelta(minutes=1)
    with pytest.raises(ApprovalExpiredError):
        h.service.approve(credential, "human:alice")
    assert h.store.get(credential.approval_id).status is ApprovalStatus.EXPIRED


def test_expiry_after_approval_blocks_consumption():
    h = Harness(ttl=timedelta(minutes=1))
    req = request()
    credential = h.issue(req)
    h.service.approve(credential, "human:alice")
    h.now += timedelta(minutes=1)
    with pytest.raises(ApprovalExpiredError):
        h.service.consume(credential.approval_id, req)


def test_approval_cannot_be_approved_twice():
    h = Harness()
    credential = h.issue()
    h.service.approve(credential, "human:alice")
    with pytest.raises(ApprovalError):
        h.service.approve(credential, "human:bob")


def test_concurrent_consumption_has_exactly_one_winner():
    h = Harness()
    req = request()
    credential = h.issue(req)
    h.service.approve(credential, "human:alice")
    outcomes = []
    barrier = threading.Barrier(8)

    def consume():
        barrier.wait()
        try:
            h.service.consume(credential.approval_id, req)
            outcomes.append("consumed")
        except ApprovalError:
            outcomes.append("rejected")

    threads = [threading.Thread(target=consume) for _ in range(8)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    assert outcomes.count("consumed") == 1
    assert outcomes.count("rejected") == 7


def test_ttl_must_be_positive_and_bounded():
    with pytest.raises(ValueError):
        ApprovalService(InMemoryApprovalStore(), lambda: NOW, lambda: "id", timedelta(0))
    with pytest.raises(ValueError):
        ApprovalService(InMemoryApprovalStore(), lambda: NOW, lambda: "id", timedelta(days=2))
