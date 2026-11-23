from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import itertools

from safestate_core.audit import AuditedDecisionService, JsonlAuditSink
from safestate_core.controls import InMemoryRiskBudgetStore, InMemoryTripwireHandler
from safestate_core.models import (
    ActionRequest, ActionType, Decision, DecisionStatus, EnvironmentClass,
    MissionContract, ResourceContext, ResourceType,
)
from safestate_core.service import DefaultDecisionService

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)
POLICIES = frozenset({f"R{i}" for i in range(1, 10)})


def mission(**overrides):
    values = {
        "mission_id": "cost-analysis", "version": "1.0", "agent_id": "cost-agent",
        "purpose": "Analyze cloud costs and recommend safe savings.",
        "allowed_actions": frozenset(ActionType), "resource_scope": frozenset(ResourceType),
        "policy_ids": POLICIES, "created_at": NOW, "risk_budget": None,
        "decoy_actions": frozenset(), "decoy_resource_ids": frozenset(),
    }
    values.update(overrides)
    return MissionContract(**values)


def request(**overrides):
    values = {
        "request_id": "req-001", "agent_id": "cost-agent",
        "mission_id": "cost-analysis", "mission_version": "1.0",
        "action": ActionType.DESCRIBE_INSTANCE, "resource_id": "i-dev-001",
        "resource_type": ResourceType.EC2_INSTANCE, "parameters": {}, "requested_at": NOW,
    }
    values.update(overrides)
    return ActionRequest(**values)


class Missions:
    def __init__(self, value):
        self.value = value
        self.calls = 0
    def get_active_mission(self, agent_id, mission_id):
        self.calls += 1
        return self.value


class Resources:
    def __init__(self):
        self.calls = 0
    def get_context(self, resource_id, resource_type):
        self.calls += 1
        return ResourceContext(
            resource_id=resource_id, resource_type=resource_type,
            environment=EnvironmentClass.DEV, classification_source="trusted-test-inventory",
            classification_verified=True, metadata={},
        )


class AllowPolicy:
    def evaluate(self, request, mission, resource):
        return Decision(
            decision_id="dec-001", request_id=request.request_id,
            status=DecisionStatus.ALLOW, rule_id="R1",
            reason_code="READ_WITHIN_MISSION", reason="Read allowed.",
            policy_version="test-1", evaluated_at=NOW, approval_required=False,
        )


class BrokenBudget:
    def try_reserve(self, mission_key, points, limit):
        raise OSError("budget store unavailable")
    def spent(self, mission_key):
        raise OSError("budget store unavailable")


class BrokenTripwire:
    def trigger(self, *args):
        raise OSError("tripwire unavailable")


def make_service(active_mission=None, risk_store=None, tripwires=None, resources=None):
    ids = itertools.count(1)
    return DefaultDecisionService(
        mission_provider=Missions(active_mission or mission()),
        resource_provider=resources or Resources(), policy_engine=AllowPolicy(),
        clock=lambda: NOW, id_generator=lambda: f"generated-{next(ids)}",
        risk_budget_store=risk_store, tripwire_handler=tripwires,
    )


def raw_payload(action="DESCRIBE_INSTANCE", resource_id="i-dev-001"):
    return {
        "request_id": "req-raw-001", "agent_id": "cost-agent",
        "mission_id": "cost-analysis", "mission_version": "1.0",
        "action": action, "resource_id": resource_id, "resource_type": "EC2_INSTANCE",
        "parameters": {}, "requested_at": NOW.isoformat(),
    }


def test_r8_reserves_points_for_permitted_action():
    store = InMemoryRiskBudgetStore()
    result = make_service(mission(risk_budget=2), risk_store=store).decide(request())
    assert result.status is DecisionStatus.ALLOW
    assert store.spent("cost-agent:cost-analysis:1.0") == 1


def test_r8_exhausted_budget_requires_human_approval():
    store = InMemoryRiskBudgetStore()
    service = make_service(mission(risk_budget=1), risk_store=store)
    assert service.decide(request(request_id="req-1")).status is DecisionStatus.ALLOW
    result = service.decide(request(request_id="req-2"))
    assert result.status is DecisionStatus.REQUIRE_APPROVAL
    assert result.rule_id == "R8"
    assert result.reason_code == "RISK_BUDGET_EXCEEDED"
    assert result.approval_required is True


def test_r8_missing_store_fails_closed_when_budget_is_configured():
    result = make_service(mission(risk_budget=10)).decide(request())
    assert result.status is DecisionStatus.BLOCK
    assert result.reason_code == "RISK_BUDGET_STORE_UNAVAILABLE"


def test_r8_store_error_fails_closed():
    result = make_service(mission(risk_budget=10), risk_store=BrokenBudget()).decide(request())
    assert result.status is DecisionStatus.BLOCK
    assert result.reason_code == "RISK_BUDGET_STORE_ERROR"


def test_r8_is_disabled_when_mission_has_no_budget():
    assert make_service().decide(request()).status is DecisionStatus.ALLOW


def test_r8_does_not_charge_a_decision_already_blocked_by_policy():
    class DenyPolicy:
        def evaluate(self, request, mission, resource):
            return Decision(
                decision_id="dec-deny", request_id=request.request_id,
                status=DecisionStatus.BLOCK, rule_id="R6",
                reason_code="ACTION_NOT_IN_MISSION", reason="Out of scope.",
                policy_version="test-1", evaluated_at=NOW, approval_required=False,
            )
    store = InMemoryRiskBudgetStore()
    service = DefaultDecisionService(
        Missions(mission(risk_budget=10)), Resources(), DenyPolicy(),
        lambda: NOW, lambda: "deny-1", risk_budget_store=store,
    )
    result = service.decide(request())
    assert result.status is DecisionStatus.BLOCK
    assert store.spent("cost-agent:cost-analysis:1.0") == 0


def test_r8_budget_store_is_atomic_under_concurrent_requests():
    store = InMemoryRiskBudgetStore()
    with ThreadPoolExecutor(max_workers=20) as pool:
        outcomes = list(pool.map(lambda _: store.try_reserve("mission-v1", 1, 5), range(20)))
    assert sum(outcomes) == 5
    assert store.spent("mission-v1") == 5


def test_r9_decoy_action_records_incident_and_revokes_agent():
    handler = InMemoryTripwireHandler(lambda: "incident-001", lambda: NOW)
    service = make_service(mission(decoy_actions=frozenset({"EXPORT_ALL_CREDENTIALS"})), tripwires=handler)
    result = service.decide_raw(raw_payload(action="export_all_credentials"))
    assert result.status is DecisionStatus.BLOCK
    assert result.rule_id == "R9"
    assert result.reason_code == "TRIPWIRE_TRIGGERED"
    assert handler.is_revoked("cost-agent")
    assert handler.incidents[0].trigger_type == "DECOY_ACTION"
    assert handler.incidents[0].target == "export_all_credentials"


def test_r9_decoy_resource_is_detected_before_inventory_lookup():
    handler = InMemoryTripwireHandler(lambda: "incident-002", lambda: NOW)
    resources = Resources()
    service = make_service(
        mission(decoy_resource_ids=frozenset({"i-decoy-001"})),
        tripwires=handler, resources=resources,
    )
    result = service.decide(request(resource_id="i-decoy-001"))
    assert result.status is DecisionStatus.BLOCK
    assert result.rule_id == "R9"
    assert result.reason_code == "TRIPWIRE_TRIGGERED"
    assert resources.calls == 0
    assert handler.is_revoked("cost-agent")


def test_r9_missing_tripwire_handler_fails_closed():
    result = make_service(mission(decoy_resource_ids=frozenset({"i-decoy-001"}))).decide(
        request(resource_id="i-decoy-001")
    )
    assert result.status is DecisionStatus.BLOCK
    assert result.reason_code == "TRIPWIRE_HANDLER_UNAVAILABLE"


def test_r9_tripwire_handler_failure_fails_closed():
    result = make_service(
        mission(decoy_resource_ids=frozenset({"i-decoy-001"})), tripwires=BrokenTripwire()
    ).decide(request(resource_id="i-decoy-001"))
    assert result.status is DecisionStatus.BLOCK
    assert result.reason_code == "TRIPWIRE_HANDLER_FAILED"


def test_r9_incident_is_written_to_audit_journal(tmp_path):
    handler = InMemoryTripwireHandler(lambda: "incident-003", lambda: NOW)
    service = make_service(mission(decoy_actions=frozenset({"DECOY_EXPORT"})), tripwires=handler)
    audited = AuditedDecisionService(service, JsonlAuditSink(tmp_path / "audit.jsonl"), lambda: "event-001")
    result = audited.decide_raw(raw_payload(action="DECOY_EXPORT"))
    assert result.rule_id == "R9"
    journal = JsonlAuditSink(tmp_path / "audit.jsonl")
    assert journal.verify().valid
    assert '"reason_code":"TRIPWIRE_TRIGGERED"' in journal.path.read_text(encoding="utf-8")


def test_r9_handler_failure_is_not_mistaken_for_successful_revocation():
    result = make_service(
        mission(decoy_actions=frozenset({"DECOY_EXPORT"})), tripwires=BrokenTripwire()
    ).decide_raw(raw_payload(action="DECOY_EXPORT"))
    assert result.status is DecisionStatus.BLOCK
    assert result.reason_code == "TRIPWIRE_HANDLER_FAILED"
