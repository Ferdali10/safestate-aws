from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
import threading

import pytest

from safestate_core.controls import InMemoryRiskBudgetStore
from safestate_core.models import (
    ActionRequest, ActionType, Decision, DecisionStatus, EnvironmentClass,
    MissionContract, ResourceContext, ResourceType,
)
from safestate_core.service import DefaultDecisionService

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)
MISSION_KEY = "agent:mission:v1"


def test_reservation_counts_against_available_budget_but_not_spent():
    store = InMemoryRiskBudgetStore()
    assert store.reserve(MISSION_KEY, "agent:mission:v1:req-1", 3, 5)
    assert store.reserved(MISSION_KEY) == 3
    assert store.spent(MISSION_KEY) == 0
    assert not store.reserve(MISSION_KEY, "agent:mission:v1:req-2", 3, 5)


def test_settlement_moves_reserved_points_to_spent_idempotently():
    store = InMemoryRiskBudgetStore()
    assert store.reserve(MISSION_KEY, "agent:mission:v1:req-1", 3, 5)
    assert store.settle("agent:mission:v1:req-1")
    assert store.settle("agent:mission:v1:req-1")
    assert store.reserved(MISSION_KEY) == 0
    assert store.spent(MISSION_KEY) == 3
    assert store.reservation("agent:mission:v1:req-1").status == "SETTLED"


def test_release_returns_points_and_is_idempotent():
    store = InMemoryRiskBudgetStore()
    assert store.reserve(MISSION_KEY, "agent:mission:v1:req-1", 3, 5)
    assert store.release("agent:mission:v1:req-1")
    assert store.release("agent:mission:v1:req-1")
    assert store.reserved(MISSION_KEY) == 0
    assert store.spent(MISSION_KEY) == 0
    assert store.reserve(MISSION_KEY, "agent:mission:v1:req-2", 5, 5)


def test_reservation_id_cannot_be_reused_for_different_payload():
    store = InMemoryRiskBudgetStore()
    assert store.reserve(MISSION_KEY, "agent:mission:v1:req-1", 2, 5)
    with pytest.raises(ValueError):
        store.reserve(MISSION_KEY, "agent:mission:v1:req-1", 3, 5)


def test_concurrent_reservations_never_overspend():
    store = InMemoryRiskBudgetStore()
    barrier = threading.Barrier(12)

    def reserve(i):
        barrier.wait()
        return store.reserve(MISSION_KEY, f"agent:mission:v1:req-{i}", 2, 10)

    with ThreadPoolExecutor(max_workers=12) as pool:
        outcomes = list(pool.map(reserve, range(12)))
    assert sum(outcomes) == 5
    assert store.reserved(MISSION_KEY) == 10


def test_settled_reservation_cannot_be_released_and_released_cannot_be_settled():
    store = InMemoryRiskBudgetStore()
    assert store.reserve(MISSION_KEY, "agent:mission:v1:settle", 1, 5)
    assert store.settle("agent:mission:v1:settle")
    assert not store.release("agent:mission:v1:settle")
    assert store.reserve(MISSION_KEY, "agent:mission:v1:release", 1, 5)
    assert store.release("agent:mission:v1:release")
    assert not store.settle("agent:mission:v1:release")


class Missions:
    def __init__(self, mission):
        self.mission = mission

    def get_active_mission(self, agent_id, mission_id):
        return self.mission


class Resources:
    def get_context(self, resource_id, resource_type):
        return ResourceContext(
            resource_id, resource_type, EnvironmentClass.DEV,
            "trusted-inventory", True, {},
        )


class Policy:
    def evaluate(self, request, mission, resource):
        return Decision(
            "dec-1", request.request_id, DecisionStatus.ALLOW, "R1",
            "TEST_ALLOW", "test", "test-v1", NOW, False,
        )


def request(request_id="req-1"):
    return ActionRequest(
        request_id, "agent", "mission", "v1", ActionType.DESCRIBE_INSTANCE,
        "i-dev-1", ResourceType.EC2_INSTANCE, {}, NOW,
    )


def service_for(store, budget=5):
    mission = MissionContract(
        "mission", "v1", "agent", "test", frozenset(ActionType),
        frozenset(ResourceType), frozenset({"R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8"}),
        NOW, risk_budget=budget,
    )
    return DefaultDecisionService(
        Missions(mission), Resources(), Policy(), lambda: NOW,
        lambda: "decision-id", risk_budget_store=store,
        risk_costs={ActionType.DESCRIBE_INSTANCE: 3},
    )


def test_decision_service_creates_reservation_not_spend():
    store = InMemoryRiskBudgetStore()
    decision = service_for(store).decide(request())
    assert decision.status is DecisionStatus.ALLOW
    assert decision.risk_reservation_id == "agent:mission:v1:req-1"
    assert decision.risk_points == 3
    assert store.reserved(MISSION_KEY) == 3
    assert store.spent(MISSION_KEY) == 0


def test_decision_service_blocks_when_budget_is_insufficient():
    store = InMemoryRiskBudgetStore()
    assert store.reserve(MISSION_KEY, "agent:mission:v1:other-request", 3, 5)
    decision = service_for(store).decide(request())
    assert decision.status is DecisionStatus.BLOCK
    assert decision.rule_id == "R8"
    assert decision.reason_code == "RISK_BUDGET_EXCEEDED"
    assert store.reserved(MISSION_KEY) == 3


def test_decision_service_retry_uses_same_idempotency_key():
    store = InMemoryRiskBudgetStore()
    svc = service_for(store)
    first = svc.decide(request())
    second = svc.decide(request())
    assert first.risk_reservation_id == second.risk_reservation_id
    assert store.reserved(MISSION_KEY) == 3


def test_audit_sink_records_each_reservation_transition():
    class RecordingSink:
        def __init__(self):
            self.events = []
        def append(self, record):
            self.events.append(dict(record))
    sink = RecordingSink()
    store = InMemoryRiskBudgetStore(audit_sink=sink, clock=lambda: NOW)
    assert store.reserve(MISSION_KEY, "agent:mission:v1:audit-1", 2, 5)
    assert store.settle("agent:mission:v1:audit-1")
    assert [event["reason_code"] for event in sink.events] == [
        "RISK_RESERVATION_CREATED", "RISK_RESERVATION_SETTLED"
    ]
    assert all(event["rule_id"] == "R8" for event in sink.events)


def test_audit_failure_prevents_reservation_state_change():
    class BrokenSink:
        def append(self, record):
            raise OSError("journal unavailable")
    store = InMemoryRiskBudgetStore(audit_sink=BrokenSink(), clock=lambda: NOW)
    with pytest.raises(OSError):
        store.reserve(MISSION_KEY, "agent:mission:v1:audit-fail", 2, 5)
    assert store.reserved(MISSION_KEY) == 0
