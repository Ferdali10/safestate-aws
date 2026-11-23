"""Local, dependency-free control adapters for SafeState R8 and R9."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import threading
from typing import Callable

from .interfaces import RiskBudgetStore, TripwireHandler


class InMemoryRiskBudgetStore(RiskBudgetStore):
    """Thread-safe local budget counter for tests and simulations.

    Reservations are consumed when a non-BLOCK decision is issued, including
    decisions that still require human approval. The MVP has no release/refund
    lifecycle; a future approval subsystem should introduce explicit reservation
    IDs and settlement/release semantics before production use.
    """

    def __init__(self) -> None:
        self._spent: dict[str, int] = {}
        self._lock = threading.Lock()

    def try_reserve(self, mission_key: str, points: int, limit: int) -> bool:
        if not isinstance(mission_key, str) or not mission_key:
            raise ValueError("mission_key must be a non-empty string")
        if isinstance(points, bool) or not isinstance(points, int) or points <= 0:
            raise ValueError("points must be a positive integer")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            raise ValueError("limit must be a non-negative integer")
        with self._lock:
            current = self._spent.get(mission_key, 0)
            if current + points > limit:
                return False
            self._spent[mission_key] = current + points
            return True

    def spent(self, mission_key: str) -> int:
        with self._lock:
            return self._spent.get(mission_key, 0)


@dataclass(frozen=True, slots=True)
class TripwireIncident:
    incident_id: str
    occurred_at: datetime
    agent_id: str
    mission_id: str
    request_id: str
    trigger_type: str
    target: str


class InMemoryTripwireHandler(TripwireHandler):
    """Local tripwire adapter that records incidents and revokes agent sessions."""

    def __init__(
        self,
        id_generator: Callable[[], str],
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._new_id = id_generator
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._incidents: list[TripwireIncident] = []
        self._revoked_agents: set[str] = set()
        self._lock = threading.Lock()

    def trigger(
        self,
        agent_id: str,
        mission_id: str,
        request_id: str,
        trigger_type: str,
        target: str,
    ) -> None:
        timestamp = self._clock()
        if timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("tripwire clock must return an aware timestamp")
        incident = TripwireIncident(
            incident_id=self._new_id(),
            occurred_at=timestamp.astimezone(timezone.utc),
            agent_id=agent_id,
            mission_id=mission_id,
            request_id=request_id,
            trigger_type=trigger_type,
            target=target,
        )
        with self._lock:
            self._incidents.append(incident)
            self._revoked_agents.add(agent_id)

    @property
    def incidents(self) -> tuple[TripwireIncident, ...]:
        with self._lock:
            return tuple(self._incidents)

    def is_revoked(self, agent_id: str) -> bool:
        with self._lock:
            return agent_id in self._revoked_agents
