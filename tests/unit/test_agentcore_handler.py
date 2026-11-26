from datetime import datetime, timezone
from types import SimpleNamespace

import pytest

from adapters.aws.handler import LambdaHandler, TrustedRequestContext
from safestate_core.execution import GatewayResult
from safestate_core.models import Decision, DecisionStatus


NOW = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)


def make_context():
    # These are documented AgentCore Lambda routing fields. They are not an
    # authenticated agent identity.
    return SimpleNamespace(client_context=SimpleNamespace(custom={
        "bedrockAgentCoreMessageVersion": "1.0",
        "bedrockAgentCoreAwsRequestId": "aws-request",
        "bedrockAgentCoreMcpMessageId": "mcp-message",
        "bedrockAgentCoreGatewayId": "gateway-id",
        "bedrockAgentCoreTargetId": "target-id",
        "bedrockAgentCoreToolName": "target___tool",
    }))


class Identity:
    def __init__(self, value=TrustedRequestContext("authenticated-agent", "trusted-mission", "v1")):
        self.value = value
        self.calls = []

    def resolve(self, context):
        self.calls.append(context)
        return self.value


def decision(request_id, status=DecisionStatus.ALLOW):
    return Decision(
        decision_id="d-1", request_id=request_id, status=status,
        rule_id="R1" if status is DecisionStatus.ALLOW else "R3",
        reason_code="READ_ALLOWED" if status is DecisionStatus.ALLOW else "STOP_REQUIRES_HUMAN_APPROVAL",
        reason="decision reason", policy_version="test", evaluated_at=NOW,
        approval_required=status is DecisionStatus.REQUIRE_APPROVAL,
    )


class DecisionService:
    def __init__(self, raw_result=None, raw_error=None):
        self.payloads = []
        self.raw_result = raw_result
        self.raw_error = raw_error

    def decide_raw(self, payload):
        self.payloads.append(dict(payload))
        if self.raw_error:
            raise self.raw_error
        return self.raw_result or Decision(
            decision_id="d-raw", request_id=payload["request_id"],
            status=DecisionStatus.BLOCK, rule_id="R9",
            reason_code="TRIPWIRE_TRIGGERED", reason="decoy",
            policy_version="test", evaluated_at=NOW, approval_required=False,
        )


class Gateway:
    def __init__(self, status=DecisionStatus.ALLOW, error=None):
        self.requests = []
        self.status = status
        self.error = error

    def submit(self, request):
        self.requests.append(request)
        if self.error:
            raise self.error
        return GatewayResult(
            outcome=("APPROVAL_REQUIRED" if self.status is DecisionStatus.REQUIRE_APPROVAL else
                     "BLOCKED" if self.status is DecisionStatus.BLOCK else "EXECUTED"),
            decision=decision(request.request_id, self.status),
            approval_id="approval-123" if self.status is DecisionStatus.REQUIRE_APPROVAL else None,
            execution={"simulated": True} if self.status is DecisionStatus.ALLOW else None,
            error_code=None,
            approval=SimpleNamespace(token="MUST_NOT_ESCAPE"),
        )


def flat_event(**overrides):
    event = {
        "agent_id": "attacker-controlled",
        "request_id": "attacker-request",
        "requested_at": "2000-01-01T00:00:00Z",
        "mission_id": "attacker-mission",
        "mission_version": "attacker-version",
        "action": "LIST_INSTANCES",
        "resource_id": "*",
        "resource_type": "EC2_INSTANCE",
        "parameters": {},
    }
    event.update(overrides)
    return event


_DEFAULT_IDENTITY = object()


def make_handler(*, identity=_DEFAULT_IDENTITY, gateway=None, decisions=None, clock=lambda: NOW):
    gateway = gateway or Gateway()
    decisions = decisions or DecisionService()
    identity = Identity() if identity is _DEFAULT_IDENTITY else identity
    handler = LambdaHandler(
        gateway, decisions, identity, clock=clock,
        id_generator=lambda: "server-request-1",
    )
    return handler, gateway, decisions, identity


def test_flat_gateway_event_uses_only_trusted_context_and_calls_submit_once():
    handler, gateway, decisions, identity = make_handler()
    event = flat_event()
    context = make_context()
    result = handler(event, context)

    assert result["outcome"] == "EXECUTED"
    assert len(gateway.requests) == 1
    request = gateway.requests[0]
    assert request.agent_id == "authenticated-agent"
    assert request.mission_id == "trusted-mission"
    assert request.mission_version == "v1"
    assert request.request_id == "server-request-1"
    assert request.requested_at == NOW
    assert request.requested_at.utcoffset().total_seconds() == 0
    assert identity.calls == [context]
    assert decisions.payloads == []


@pytest.mark.parametrize("identity", [None, Identity(""), Identity("  "), Identity(7)])
def test_absent_or_invalid_trusted_context_fails_closed(identity):
    handler, gateway, decisions, _ = make_handler(identity=identity)
    result = handler(flat_event(), make_context())
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "TRUSTED_IDENTITY_UNAVAILABLE"
    assert gateway.requests == []
    assert decisions.payloads == []


def test_agent_supplied_identity_and_mission_cannot_override_trusted_binding():
    handler, gateway, _, identity = make_handler()
    event = flat_event(agent_id="forged-agent", mission_id="forged-mission",
                       mission_version="forged-version")
    context = make_context()
    handler(event, context)
    assert gateway.requests[0].agent_id == "authenticated-agent"
    assert gateway.requests[0].mission_id == "trusted-mission"
    assert gateway.requests[0].mission_version == "v1"
    assert identity.calls == [context]


def test_resolver_exception_fails_closed():
    class BrokenIdentity:
        def resolve(self, context):
            raise RuntimeError("identity source unavailable")

    handler, gateway, decisions, _ = make_handler(identity=BrokenIdentity())
    result = handler(flat_event(), make_context())
    assert result["reason_code"] == "TRUSTED_IDENTITY_UNAVAILABLE"
    assert gateway.requests == []
    assert decisions.payloads == []


def test_unknown_action_uses_core_raw_path_for_tripwire():
    handler, gateway, decisions, _ = make_handler()
    result = handler(flat_event(action="DECOY_ACTION"), make_context())
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "TRIPWIRE_TRIGGERED"
    assert len(decisions.payloads) == 1
    assert decisions.payloads[0]["agent_id"] == "authenticated-agent"
    assert decisions.payloads[0]["mission_id"] == "trusted-mission"
    assert decisions.payloads[0]["mission_version"] == "v1"
    assert gateway.requests == []


def test_decide_raw_exception_fails_closed():
    handler, gateway, decisions, _ = make_handler(
        decisions=DecisionService(raw_error=RuntimeError("service error"))
    )
    result = handler(flat_event(action="NOT_A_REAL_ACTION"), make_context())
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "DECISION_SERVICE_FAILURE"
    assert len(decisions.payloads) == 1
    assert gateway.requests == []


@pytest.mark.parametrize("status", [DecisionStatus.ALLOW, DecisionStatus.BLOCK,
                                    DecisionStatus.REQUIRE_APPROVAL])
def test_gateway_decisions_are_rendered_without_approval_credentials(status):
    handler, _, _, _ = make_handler(gateway=Gateway(status=status))
    result = handler(flat_event(), make_context())
    assert result["decision"] == status.value
    assert "approval" not in result
    assert "token" not in result
    assert "MUST_NOT_ESCAPE" not in repr(result)
    if status is DecisionStatus.REQUIRE_APPROVAL:
        assert result["approval_id"] == "approval-123"


def test_submit_exception_fails_closed():
    handler, gateway, _, _ = make_handler(gateway=Gateway(error=RuntimeError("failed")))
    result = handler(flat_event(), make_context())
    assert result["reason_code"] == "GATEWAY_FAILURE"
    assert result["decision"] == "BLOCK"
    assert len(gateway.requests) == 1


def test_old_nested_input_shape_is_not_treated_as_gateway_contract():
    handler, gateway, decisions, _ = make_handler()
    result = handler({"input": flat_event()}, make_context())
    assert result["decision"] == "BLOCK"
    assert gateway.requests == []
    assert len(decisions.payloads) == 1
