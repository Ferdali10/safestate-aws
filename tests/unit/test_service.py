from datetime import datetime, timezone
import itertools

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
from safestate_core.service import DefaultDecisionService

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)
ALL_RULES = frozenset({"R1", "R2", "R3", "R4", "R5", "R6", "R7"})


def make_request(**overrides):
    values = {
        "request_id": "req-001",
        "agent_id": "cost-agent",
        "mission_id": "cost-analysis",
        "mission_version": "1.0",
        "action": ActionType.DESCRIBE_INSTANCE,
        "resource_id": "i-dev-001",
        "resource_type": ResourceType.EC2_INSTANCE,
        "parameters": {},
        "requested_at": NOW,
    }
    values.update(overrides)
    return ActionRequest(**values)


def make_mission(**overrides):
    values = {
        "mission_id": "cost-analysis",
        "version": "1.0",
        "agent_id": "cost-agent",
        "purpose": "Analyze AWS costs and request approved DEV instance stops.",
        "allowed_actions": frozenset(ActionType),
        "resource_scope": frozenset(ResourceType),
        "policy_ids": ALL_RULES,
        "created_at": NOW,
    }
    values.update(overrides)
    return MissionContract(**values)


def make_resource(**overrides):
    values = {
        "resource_id": "i-dev-001",
        "resource_type": ResourceType.EC2_INSTANCE,
        "environment": EnvironmentClass.DEV,
        "classification_source": "trusted-inventory",
        "classification_verified": True,
        "metadata": {},
    }
    values.update(overrides)
    return ResourceContext(**values)


class FakeMissionProvider:
    def __init__(self, mission=None, error=None):
        self.mission = mission or make_mission()
        self.error = error
        self.calls = 0

    def get_active_mission(self, agent_id, mission_id):
        self.calls += 1
        if self.error:
            raise self.error
        return self.mission


class FakeResourceProvider:
    def __init__(self, resource=None, error=None):
        self.resource = resource or make_resource()
        self.error = error
        self.calls = 0

    def get_context(self, resource_id, resource_type):
        self.calls += 1
        if self.error:
            raise self.error
        return self.resource


class FakePolicyEngine:
    def __init__(self, status=DecisionStatus.ALLOW, error=None, result=None):
        self.status = status
        self.error = error
        self.result = result
        self.calls = 0

    def evaluate(self, request, mission, resource):
        self.calls += 1
        if self.error:
            raise self.error
        if self.result is not None:
            return self.result
        return Decision(
            decision_id="decision-001",
            request_id=request.request_id,
            status=self.status,
            rule_id="R1" if self.status is DecisionStatus.ALLOW else "R3",
            reason_code="READ_WITHIN_MISSION",
            reason="Test policy result.",
            policy_version="test",
            evaluated_at=NOW,
            approval_required=self.status is DecisionStatus.REQUIRE_APPROVAL,
        )


def make_service(missions=None, resources=None, policy=None):
    ids = itertools.count(1)
    return DefaultDecisionService(
        mission_provider=missions or FakeMissionProvider(),
        resource_provider=resources or FakeResourceProvider(),
        policy_engine=policy or FakePolicyEngine(),
        clock=lambda: NOW,
        id_generator=lambda: f"decision-{next(ids):03d}",
    )


def make_raw_payload(action="DESCRIBE_INSTANCE"):
    return {
        "request_id": "raw-001",
        "agent_id": "cost-agent",
        "mission_id": "cost-analysis",
        "mission_version": "1.0",
        "action": action,
        "resource_id": "i-dev-001",
        "resource_type": "EC2_INSTANCE",
        "parameters": {},
        "requested_at": NOW.isoformat(),
    }


def test_read_request_is_delegated_to_policy_engine():
    policy = FakePolicyEngine(DecisionStatus.ALLOW)
    decision = make_service(policy=policy).decide(make_request())
    assert decision.status is DecisionStatus.ALLOW
    assert policy.calls == 1


def test_verified_dev_stop_can_require_human_approval():
    policy = FakePolicyEngine(DecisionStatus.REQUIRE_APPROVAL)
    request = make_request(action=ActionType.REQUEST_STOP_INSTANCE)
    decision = make_service(policy=policy).decide(request)
    assert decision.status is DecisionStatus.REQUIRE_APPROVAL
    assert decision.approval_required is True


def test_mission_provider_failure_fails_closed():
    decision = make_service(
        missions=FakeMissionProvider(error=RuntimeError("unavailable"))
    ).decide(make_request())
    assert decision.status is DecisionStatus.BLOCK
    assert decision.reason_code == "DECISION_PIPELINE_ERROR"


def test_resource_provider_failure_fails_closed():
    decision = make_service(
        resources=FakeResourceProvider(error=RuntimeError("unavailable"))
    ).decide(make_request())
    assert decision.status is DecisionStatus.BLOCK


def test_policy_engine_failure_fails_closed():
    decision = make_service(
        policy=FakePolicyEngine(error=RuntimeError("failure"))
    ).decide(make_request())
    assert decision.status is DecisionStatus.BLOCK


def test_invalid_typed_request_never_calls_providers():
    missions = FakeMissionProvider()
    resources = FakeResourceProvider()
    decision = make_service(missions, resources).decide(
        make_request(request_id="")
    )
    assert decision.status is DecisionStatus.BLOCK
    assert missions.calls == 0
    assert resources.calls == 0


@pytest.mark.parametrize(
    ("action", "expected_rule"),
    [
        ("DELETE_VOLUME", "R4"),
        ("EXPORT_SECRETS", "R5"),
        ("MAGIC_ACTION", "R6"),
    ],
)
def test_unknown_actions_are_classified_and_blocked(action, expected_rule):
    decision = make_service().decide_raw(make_raw_payload(action))
    assert decision.status is DecisionStatus.BLOCK
    assert decision.rule_id == expected_rule


def test_invalid_raw_payload_never_calls_providers():
    missions = FakeMissionProvider()
    payload = make_raw_payload()
    payload["claimed_environment"] = "DEV"
    decision = make_service(missions=missions).decide_raw(payload)
    assert decision.status is DecisionStatus.BLOCK
    assert decision.reason_code == "REQUEST_VALIDATION_FAILED"
    assert missions.calls == 0


def test_non_mapping_payload_fails_closed():
    decision = make_service().decide_raw(None)
    assert decision.status is DecisionStatus.BLOCK
    assert decision.request_id == "unavailable"


def test_invalid_mission_object_fails_closed():
    decision = make_service(
        missions=FakeMissionProvider(mission=object())
    ).decide(make_request())
    assert decision.status is DecisionStatus.BLOCK
    assert decision.reason_code == "MISSION_CONTEXT_INVALID"


def test_mission_version_mismatch_blocks_before_resource_lookup():
    resources = FakeResourceProvider()
    decision = make_service(
        missions=FakeMissionProvider(mission=make_mission(version="2.0")),
        resources=resources,
    ).decide(make_request())
    assert decision.status is DecisionStatus.BLOCK
    assert decision.reason_code == "MISSION_MISMATCH"
    assert resources.calls == 0


def test_malformed_mission_action_set_fails_closed():
    decision = make_service(
        missions=FakeMissionProvider(
            mission=make_mission(allowed_actions=frozenset({"REQUEST_STOP_INSTANCE"}))
        )
    ).decide(make_request())
    assert decision.status is DecisionStatus.BLOCK
    assert decision.reason_code == "MISSION_CONTEXT_INVALID"


def test_invalid_resource_context_fails_closed():
    decision = make_service(
        resources=FakeResourceProvider(resource=object())
    ).decide(make_request())
    assert decision.status is DecisionStatus.BLOCK
    assert decision.reason_code == "RESOURCE_CONTEXT_INVALID"


def test_resource_mismatch_blocks_before_policy_evaluation():
    policy = FakePolicyEngine()
    decision = make_service(
        resources=FakeResourceProvider(resource=make_resource(resource_id="i-other")),
        policy=policy,
    ).decide(make_request())
    assert decision.status is DecisionStatus.BLOCK
    assert decision.reason_code == "RESOURCE_CONTEXT_MISMATCH"
    assert policy.calls == 0


def test_untyped_resource_environment_fails_closed():
    decision = make_service(
        resources=FakeResourceProvider(resource=make_resource(environment="DEV"))
    ).decide(make_request())
    assert decision.status is DecisionStatus.BLOCK


def test_invalid_policy_result_fails_closed():
    policy = FakePolicyEngine(result=object())
    decision = make_service(policy=policy).decide(make_request())
    assert decision.status is DecisionStatus.BLOCK
    assert decision.reason_code == "POLICY_ENGINE_INVALID_RESULT"


def test_policy_result_for_another_request_fails_closed():
    wrong_request = Decision(
        decision_id="decision-foreign",
        request_id="other-request",
        status=DecisionStatus.ALLOW,
        rule_id="R1",
        reason_code="READ_WITHIN_MISSION",
        reason="Wrong request.",
        policy_version="test",
        evaluated_at=NOW,
        approval_required=False,
    )
    decision = make_service(
        policy=FakePolicyEngine(result=wrong_request)
    ).decide(make_request())
    assert decision.status is DecisionStatus.BLOCK
