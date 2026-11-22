from dataclasses import FrozenInstanceError
from datetime import datetime, timezone

import pytest

from safestate_core.models import (
    ActionRequest,
    ActionType,
    Decision,
    DecisionStatus,
    EnvironmentClass,
    MissionContract,
    ResourceContext,
    ResourceType,
)


NOW = datetime(2026, 11, 22, 12, 0, tzinfo=timezone.utc)


def make_request(**overrides):
    values = {
        "request_id": "req-001",
        "agent_id": "cost-analysis-agent",
        "mission_id": "aws-cost-analysis",
        "mission_version": "1.0",
        "action": ActionType.REQUEST_STOP_INSTANCE,
        "resource_id": "i-dev-001",
        "resource_type": ResourceType.EC2_INSTANCE,
        "parameters": {},
        "requested_at": NOW,
    }
    values.update(overrides)
    return ActionRequest(**values)


def test_action_request_accepts_utc_timestamp():
    request = make_request()
    assert request.requested_at == NOW
    assert request.action is ActionType.REQUEST_STOP_INSTANCE


def test_action_request_rejects_naive_timestamp():
    with pytest.raises(ValueError, match="timezone-aware"):
        make_request(requested_at=datetime(2026, 11, 22, 12, 0))


def test_action_request_rejects_non_utc_offset():
    from datetime import timedelta, timezone as tz

    non_utc = datetime(2026, 11, 22, 13, 0, tzinfo=tz(timedelta(hours=1)))
    with pytest.raises(ValueError, match="must use UTC"):
        make_request(requested_at=non_utc)


def test_mission_contract_accepts_frozen_action_and_resource_scopes():
    mission = MissionContract(
        mission_id="aws-cost-analysis",
        version="1.0",
        agent_id="cost-analysis-agent",
        purpose="Analyze cloud costs without direct resource mutation.",
        allowed_actions=frozenset({ActionType.REQUEST_STOP_INSTANCE}),
        resource_scope=frozenset({ResourceType.EC2_INSTANCE}),
        policy_ids=frozenset({"R1", "R2", "R3"}),
        created_at=NOW,
    )
    assert ActionType.REQUEST_STOP_INSTANCE in mission.allowed_actions
    with pytest.raises(FrozenInstanceError):
        mission.version = "2.0"


def test_resource_context_preserves_unknown_classification():
    context = ResourceContext(
        resource_id="i-unknown-001",
        resource_type=ResourceType.EC2_INSTANCE,
        environment=EnvironmentClass.UNKNOWN,
        classification_source="unverified",
        classification_verified=False,
        metadata={"Name": "test-instance"},
    )
    assert context.environment is EnvironmentClass.UNKNOWN
    assert context.classification_verified is False


def test_decision_requires_approval_flag_for_approval_status():
    decision = Decision(
        decision_id="dec-001",
        request_id="req-001",
        status=DecisionStatus.REQUIRE_APPROVAL,
        rule_id="R3",
        reason_code="DEV_STOP_REQUIRES_APPROVAL",
        reason="A human must approve this development instance stop request.",
        policy_version="1.0",
        evaluated_at=NOW,
        approval_required=True,
    )
    assert decision.approval_required is True


def test_decision_rejects_inconsistent_approval_flag():
    with pytest.raises(ValueError, match="approval_required"):
        Decision(
            decision_id="dec-002",
            request_id="req-002",
            status=DecisionStatus.BLOCK,
            rule_id="R2",
            reason_code="PRODUCTION_RESOURCE_PROTECTED",
            reason="Production resources cannot be modified.",
            policy_version="1.0",
            evaluated_at=NOW,
            approval_required=True,
        )


def test_decision_rejects_naive_evaluation_timestamp():
    with pytest.raises(ValueError, match="timezone-aware"):
        Decision(
            decision_id="dec-003",
            request_id="req-003",
            status=DecisionStatus.BLOCK,
            rule_id="R7",
            reason_code="FAIL_CLOSED",
            reason="Required policy context is unavailable.",
            policy_version="1.0",
            evaluated_at=datetime(2026, 11, 22, 12, 0),
            approval_required=False,
        )
