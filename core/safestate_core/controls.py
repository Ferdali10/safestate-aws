"""Local, dependency-free control adapters for SafeState R8 and R9."""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
import threading
from typing import Callable

from .interfaces import RiskBudgetStore, TripwireHandler


@dataclass(frozen=True, slots=True)
class RiskReservation:
    reservation_id: str
    mission_key: str
    points: int
    status: str


class InMemoryRiskBudgetStore(RiskBudgetStore):
    """Thread-safe local R8 ledger; use a transactional durable adapter in production."""

    def __init__(self, audit_sink=None, clock=None) -> None:
        self._spent: dict[str, int] = {}
        self._reservations: dict[str, RiskReservation] = {}
        self._audit = audit_sink
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._lock = threading.RLock()

    def reserve(self, mission_key: str, reservation_id: str, points: int, limit: int) -> bool:
        self._validate(mission_key, points, limit)
        if not isinstance(reservation_id, str) or not reservation_id:
            raise ValueError("reservation_id must be a non-empty string")
        with self._lock:
            existing = self._reservations.get(reservation_id)
            if existing is not None:
                if existing.mission_key != mission_key or existing.points != points:
                    raise ValueError("reservation idempotency key conflicts with existing reservation")
                return existing.status == "RESERVED"
            reserved = sum(
                item.points for item in self._reservations.values()
                if item.mission_key == mission_key and item.status == "RESERVED"
            )
            spent = self._spent.get(mission_key, 0)
            if spent + reserved + points > limit:
                return False
            self._emit(reservation_id, "RISK_RESERVATION_CREATED")
            self._reservations[reservation_id] = RiskReservation(
                reservation_id, mission_key, points, "RESERVED"
            )
            return True

    def settle(self, reservation_id: str) -> bool:
        with self._lock:
            item = self._reservations.get(reservation_id)
            if item is None:
                return False
            if item.status == "SETTLED":
                return True
            if item.status != "RESERVED":
                return False
            self._emit(reservation_id, "RISK_RESERVATION_SETTLED")
            self._spent[item.mission_key] = self._spent.get(item.mission_key, 0) + item.points
            self._reservations[reservation_id] = RiskReservation(
                item.reservation_id, item.mission_key, item.points, "SETTLED"
            )
            return True

    def release(self, reservation_id: str) -> bool:
        with self._lock:
            item = self._reservations.get(reservation_id)
            if item is None:
                return False
            if item.status == "RELEASED":
                return True
            if item.status != "RESERVED":
                return False
            self._emit(reservation_id, "RISK_RESERVATION_RELEASED")
            self._reservations[reservation_id] = RiskReservation(
                item.reservation_id, item.mission_key, item.points, "RELEASED"
            )
            return True

    def reservation(self, reservation_id: str) -> RiskReservation | None:
        with self._lock:
            return self._reservations.get(reservation_id)

    def reserved(self, mission_key: str) -> int:
        with self._lock:
            return sum(
                item.points for item in self._reservations.values()
                if item.mission_key == mission_key and item.status == "RESERVED"
            )

    def spent(self, mission_key: str) -> int:
        with self._lock:
            return self._spent.get(mission_key, 0)

    def try_reserve(self, mission_key: str, points: int, limit: int) -> bool:
        """Backward-compatible immediate spend; new code must use reserve()."""
        self._validate(mission_key, points, limit)
        with self._lock:
            reserved = sum(
                item.points for item in self._reservations.values()
                if item.mission_key == mission_key and item.status == "RESERVED"
            )
            current = self._spent.get(mission_key, 0)
            if current + reserved + points > limit:
                return False
            self._spent[mission_key] = current + points
            return True

    def _emit(self, reservation_id: str, reason_code: str) -> None:
        if self._audit is None:
            return
        timestamp = self._clock()
        if not isinstance(timestamp, datetime) or timestamp.tzinfo is None or timestamp.utcoffset() is None:
            raise ValueError("risk audit clock must return an aware datetime")
        self._audit.append({
            "event_id": f"{reservation_id}:{reason_code}",
            "timestamp": timestamp.astimezone(timezone.utc).isoformat(),
            "request_id": reservation_id,
            "decision_id": reservation_id,
            "status": "ALLOW",
            "rule_id": "R8",
            "reason_code": reason_code,
            "policy_version": "R8-v1",
        })

    @staticmethod
    def _validate(mission_key: str, points: int, limit: int) -> None:
        if not isinstance(mission_key, str) or not mission_key:
            raise ValueError("mission_key must be a non-empty string")
        if isinstance(points, bool) or not isinstance(points, int) or points <= 0:
            raise ValueError("points must be a positive integer")
        if isinstance(limit, bool) or not isinstance(limit, int) or limit < 0:
            raise ValueError("limit must be a non-negative integer")


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
        self, agent_id: str, mission_id: str, request_id: str,
        trigger_type: str, target: str,
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
