from datetime import datetime, timezone
from types import SimpleNamespace

from adapters.aws.handler import LambdaHandler
from safestate_core.models import Decision, DecisionStatus


NOW = datetime(2026, 11, 25, 12, 0, tzinfo=timezone.utc)


class Identity:
    def resolve(self, event):
        return "authenticated-agent"


class DecisionService:
    def __init__(self):
        self.payloads = []

    def decide_raw(self, payload):
        self.payloads.append(dict(payload))
        return Decision(
            decision_id="d-1", request_id=payload["request_id"],
            status=DecisionStatus.BLOCK, rule_id="R9",
            reason_code="TRIPWIRE_TRIGGERED", reason="decoy",
            policy_version="test", evaluated_at=NOW, approval_required=False,
        )


class Gateway:
    def __init__(self):
        self.requests = []

    def submit(self, request):
        self.requests.append(request)
        decision = Decision(
            decision_id="d-2", request_id=request.request_id,
            status=DecisionStatus.ALLOW, rule_id="R1",
            reason_code="READ_ALLOWED", reason="read allowed",
            policy_version="test", evaluated_at=NOW, approval_required=False,
        )
        return SimpleNamespace(
            outcome="EXECUTED", decision=decision, approval_id=None,
            execution={"simulated": True}, error_code=None, approval=None,
        )


def make_handler():
    gateway = Gateway()
    decisions = DecisionService()
    handler = LambdaHandler(
        gateway, decisions, Identity(), clock=lambda: NOW,
        id_generator=lambda: "server-request-1",
    )
    return handler, gateway, decisions


def test_valid_input_uses_trusted_identity_and_server_fields():
    handler, gateway, decisions = make_handler()
    result = handler({
        "input": {
            "agent_id": "attacker-controlled",
            "request_id": "attacker-request",
            "requested_at": "2000-01-01T00:00:00Z",
            "mission_id": "mission-1",
            "mission_version": "v1",
            "action": "LIST_INSTANCES",
            "resource_id": "account",
            "resource_type": "EC2_INSTANCE",
            "parameters": {},
        }
    })
    assert result["outcome"] == "EXECUTED"
    assert len(gateway.requests) == 1
    request = gateway.requests[0]
    assert request.agent_id == "authenticated-agent"
    assert request.request_id == "server-request-1"
    assert request.requested_at == NOW
    assert decisions.payloads == []


def test_identity_failure_blocks_without_calling_core_or_gateway():
    class BrokenIdentity:
        def resolve(self, event):
            raise ValueError("not authenticated")

    gateway = Gateway()
    decisions = DecisionService()
    handler = LambdaHandler(gateway, decisions, BrokenIdentity(), clock=lambda: NOW)
    result = handler({"input": {"action": "LIST_INSTANCES"}})
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "TRUSTED_IDENTITY_UNAVAILABLE"
    assert gateway.requests == []
    assert decisions.payloads == []


def test_unknown_action_uses_core_raw_path_for_tripwire():
    handler, gateway, decisions = make_handler()
    result = handler({"input": {
        "mission_id": "mission-1",
        "mission_version": "v1",
        "action": "DECOY_ACTION",
        "resource_id": "i-dev-001",
        "resource_type": "EC2_INSTANCE",
        "parameters": {},
    }})
    assert result["decision"] == "BLOCK"
    assert result["reason_code"] == "TRIPWIRE_TRIGGERED"
    assert len(decisions.payloads) == 1
    assert decisions.payloads[0]["agent_id"] == "authenticated-agent"
    assert gateway.requests == []


def test_approval_secret_is_never_returned():
    handler, gateway, _ = make_handler()
    result = handler({"input": {
        "mission_id": "mission-1",
        "mission_version": "v1",
        "action": "LIST_INSTANCES",
        "resource_id": "account",
        "resource_type": "EC2_INSTANCE",
        "parameters": {},
    }})
    assert "approval" not in result
    assert "token" not in result
