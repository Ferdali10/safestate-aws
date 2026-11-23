"""Public, framework-independent interfaces of the SafeState core.

Concrete AWS adapters (Lambda handlers, Gateway targets, DynamoDB stores) must
implement these protocols; they must not duplicate policy logic.
"""
from __future__ import annotations

from datetime import datetime
from typing import Any, Callable, Mapping, Protocol

from .models import (
    ActionRequest,
    Decision,
    MissionContract,
    ResourceContext,
    ResourceType,
)

# Injected so that tests are deterministic and production can use real time.
Clock = Callable[[], datetime]
IdGenerator = Callable[[], str]


class MissionProvider(Protocol):
    """Trusted source of the active mission. The agent cannot influence it."""

    def get_active_mission(self, agent_id: str, mission_id: str) -> MissionContract: ...


class ResourceContextProvider(Protocol):
    """Trusted inventory that classifies resources.

    Implementations must never derive classification from tags or other values
    supplied by the agent.
    """

    def get_context(self, resource_id: str, resource_type: ResourceType) -> ResourceContext: ...


class PolicyEngine(Protocol):
    """Pure, deterministic evaluation of one validated request."""

    def evaluate(
        self,
        request: ActionRequest,
        mission: MissionContract,
        resource: ResourceContext,
    ) -> Decision: ...


class DecisionService(Protocol):
    """Entry point shared by local tools and future AWS Lambda handlers."""

    def decide(self, request: ActionRequest) -> Decision: ...

    def decide_raw(self, payload: Mapping[str, Any]) -> Decision: ...


class RiskBudgetStore(Protocol):
    """Atomic point accounting per mission (R8).

    A DynamoDB implementation must use a conditional update so that concurrent
    requests cannot overspend the budget.
    """

    def reserve(self, mission_key: str, reservation_id: str, points: int, limit: int) -> bool: ...

    def settle(self, reservation_id: str) -> bool: ...

    def release(self, reservation_id: str) -> bool: ...

    def spent(self, mission_key: str) -> int: ...

    def reserved(self, mission_key: str) -> int: ...


class TripwireHandler(Protocol):
    """Record a decoy incident and revoke the affected agent session.

    Implementations must make incident recording and session revocation durable
    before returning. If either operation fails, the caller blocks the request.
    """

    def trigger(
        self,
        agent_id: str,
        mission_id: str,
        request_id: str,
        trigger_type: str,
        target: str,
    ) -> None: ...


class AuditSink(Protocol):
    """Append-only audit destination. Raising means persistence failed."""

    def append(self, record: Mapping[str, Any]) -> None: ...
