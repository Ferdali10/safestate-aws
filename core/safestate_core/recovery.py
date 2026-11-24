"""Conservative recovery primitives for execution/R8 crash windows.

The in-memory journal is a test adapter only. A production adapter must persist
records durably before execution and provide atomic conditional transitions.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from threading import RLock
from typing import Callable, Protocol

from .controls import InMemoryRiskBudgetStore


class ExecutionState(str, Enum):
    PREPARED = "PREPARED"
    EXECUTING = "EXECUTING"
    EXECUTED = "EXECUTED"
    FAILED = "FAILED"
    SETTLING = "SETTLING"
    RELEASING = "RELEASING"
    SETTLED = "SETTLED"
    RELEASED = "RELEASED"
    UNKNOWN = "UNKNOWN"


@dataclass(frozen=True, slots=True)
class ExecutionRecord:
    execution_id: str
    request_id: str
    mission_key: str
    reservation_id: str | None
    action: str
    resource_id: str
    state: ExecutionState
    created_at: datetime
    updated_at: datetime

    def __post_init__(self) -> None:
        for field_name in ("created_at", "updated_at"):
            value = getattr(self, field_name)
            if value.tzinfo is None or value.utcoffset() is None:
                raise ValueError(f"{field_name} must be timezone-aware")


class ExecutionJournal(Protocol):
    def prepare(self, record: ExecutionRecord) -> ExecutionRecord: ...
    def transition(
        self, execution_id: str, expected: ExecutionState,
        target: ExecutionState, updated_at: datetime,
    ) -> bool: ...
    def get(self, execution_id: str) -> ExecutionRecord | None: ...
    def list_records(self) -> tuple[ExecutionRecord, ...]: ...


class InMemoryExecutionJournal:
    """Thread-safe journal for local tests; state is lost when the process exits."""

    def __init__(self) -> None:
        self._records: dict[str, ExecutionRecord] = {}
        self._lock = RLock()

    def prepare(self, record: ExecutionRecord) -> ExecutionRecord:
        if record.state is not ExecutionState.PREPARED:
            raise ValueError("new execution records must start in PREPARED")
        with self._lock:
            existing = self._records.get(record.execution_id)
            if existing is not None:
                identity = (
                    existing.request_id, existing.mission_key,
                    existing.reservation_id, existing.action, existing.resource_id,
                )
                proposed = (
                    record.request_id, record.mission_key, record.reservation_id,
                    record.action, record.resource_id,
                )
                if identity != proposed:
                    raise ValueError("execution id conflicts with existing record")
                return existing
            self._records[record.execution_id] = record
            return record

    def transition(
        self, execution_id: str, expected: ExecutionState,
        target: ExecutionState, updated_at: datetime,
    ) -> bool:
        if updated_at.tzinfo is None or updated_at.utcoffset() is None:
            raise ValueError("updated_at must be timezone-aware")
        allowed = {
            (ExecutionState.PREPARED, ExecutionState.EXECUTING),
            (ExecutionState.PREPARED, ExecutionState.RELEASING),
            (ExecutionState.FAILED, ExecutionState.RELEASING),
            (ExecutionState.RELEASING, ExecutionState.RELEASED),
            (ExecutionState.EXECUTING, ExecutionState.EXECUTED),
            (ExecutionState.EXECUTING, ExecutionState.FAILED),
            (ExecutionState.EXECUTING, ExecutionState.UNKNOWN),
            (ExecutionState.EXECUTED, ExecutionState.SETTLING),
            (ExecutionState.SETTLING, ExecutionState.SETTLED),
            (ExecutionState.EXECUTED, ExecutionState.SETTLED),
        }
        if (expected, target) not in allowed:
            raise ValueError(f"unsupported execution transition: {expected} -> {target}")
        with self._lock:
            current = self._records.get(execution_id)
            if current is None:
                return False
            if current.state is target:
                return True
            if current.state is not expected:
                return False
            self._records[execution_id] = ExecutionRecord(
                execution_id=current.execution_id,
                request_id=current.request_id,
                mission_key=current.mission_key,
                reservation_id=current.reservation_id,
                action=current.action,
                resource_id=current.resource_id,
                state=target,
                created_at=current.created_at,
                updated_at=updated_at.astimezone(timezone.utc),
            )
            return True

    def get(self, execution_id: str) -> ExecutionRecord | None:
        with self._lock:
            return self._records.get(execution_id)

    def list_records(self) -> tuple[ExecutionRecord, ...]:
        with self._lock:
            return tuple(self._records[key] for key in sorted(self._records))


@dataclass(frozen=True, slots=True)
class RecoveryItem:
    execution_id: str
    previous_state: ExecutionState
    outcome: str
    detail: str


class ExecutionRecoveryService:
    """Reconcile known execution states without ever replaying an uncertain action.

    PREPARED means the executor was not entered and its reservation can be
    released. EXECUTED means the side effect was confirmed and its reservation
    can be settled. FAILED means the executor confirmed failure and the
    reservation can be released. EXECUTING is ambiguous after a crash: it is
    moved to UNKNOWN and left for operator reconciliation.
    """

    def __init__(
        self,
        journal: ExecutionJournal,
        risk_budget_store,
        clock: Callable[[], datetime] | None = None,
    ) -> None:
        self._journal = journal
        self._risk_budget = risk_budget_store
        self._clock = clock or (lambda: datetime.now(timezone.utc))

    def recover(self) -> tuple[RecoveryItem, ...]:
        outcomes: list[RecoveryItem] = []
        for record in self._journal.list_records():
            if record.state in {
                ExecutionState.SETTLED, ExecutionState.RELEASED,
                ExecutionState.UNKNOWN,
            }:
                continue
            if record.state is ExecutionState.PREPARED:
                outcomes.append(self._claim_and_release(record, ExecutionState.PREPARED))
            elif record.state is ExecutionState.FAILED:
                outcomes.append(self._claim_and_release(record, ExecutionState.FAILED))
            elif record.state is ExecutionState.EXECUTED:
                outcomes.append(self._claim_and_settle(record))
            elif record.state is ExecutionState.RELEASING:
                outcomes.append(self._finish_release(record))
            elif record.state is ExecutionState.SETTLING:
                outcomes.append(self._finish_settlement(record))
            elif record.state is ExecutionState.EXECUTING:
                now = self._now()
                changed = self._journal.transition(
                    record.execution_id, ExecutionState.EXECUTING,
                    ExecutionState.UNKNOWN, now,
                )
                outcomes.append(RecoveryItem(
                    record.execution_id, record.state,
                    "NEEDS_RECONCILIATION" if changed else "CONCURRENT_CHANGE",
                    "Execution outcome is uncertain; no retry, settlement or release was attempted.",
                ))
        return tuple(outcomes)

    def _claim_and_release(
        self, record: ExecutionRecord, expected: ExecutionState
    ) -> RecoveryItem:
        # Claim the journal state before touching R8. This prevents a concurrent
        # gateway from moving PREPARED to EXECUTING while recovery releases budget.
        claimed = self._journal.transition(
            record.execution_id, expected, ExecutionState.RELEASING, self._now()
        )
        if not claimed:
            current = self._journal.get(record.execution_id)
            if current is not None and current.state is ExecutionState.RELEASING:
                return self._finish_release(current)
            return RecoveryItem(
                record.execution_id, record.state, "CONCURRENT_CHANGE",
                "Execution state changed before recovery could claim the release.",
            )
        current = self._journal.get(record.execution_id) or record
        return self._finish_release(current)

    def _finish_release(self, record: ExecutionRecord) -> RecoveryItem:
        if record.reservation_id is not None:
            try:
                released = (
                    self._risk_budget is not None
                    and self._risk_budget.release(record.reservation_id) is True
                )
            except Exception:  # noqa: BLE001 - leave RELEASING for retry
                released = False
            if not released:
                return RecoveryItem(
                    record.execution_id, record.state, "ACCOUNTING_FAILED",
                    "Reservation release failed; RELEASING is retained for safe retry.",
                )
        changed = self._journal.transition(
            record.execution_id, ExecutionState.RELEASING,
            ExecutionState.RELEASED, self._now()
        )
        return RecoveryItem(
            record.execution_id, record.state,
            "RELEASED" if changed else "CONCURRENT_CHANGE",
            "Reservation released after the journal claimed RELEASING.",
        )

    def _claim_and_settle(self, record: ExecutionRecord) -> RecoveryItem:
        claimed = self._journal.transition(
            record.execution_id, ExecutionState.EXECUTED,
            ExecutionState.SETTLING, self._now()
        )
        if not claimed:
            current = self._journal.get(record.execution_id)
            if current is not None and current.state is ExecutionState.SETTLING:
                return self._finish_settlement(current)
            return RecoveryItem(
                record.execution_id, record.state, "CONCURRENT_CHANGE",
                "Execution state changed before recovery could claim settlement.",
            )
        current = self._journal.get(record.execution_id) or record
        return self._finish_settlement(current)

    def _finish_settlement(self, record: ExecutionRecord) -> RecoveryItem:
        if record.reservation_id is not None:
            try:
                settled = (
                    self._risk_budget is not None
                    and self._risk_budget.settle(record.reservation_id) is True
                )
            except Exception:  # noqa: BLE001 - leave SETTLING for retry
                settled = False
            if not settled:
                return RecoveryItem(
                    record.execution_id, record.state, "ACCOUNTING_FAILED",
                    "Reservation settlement failed; SETTLING is retained for safe retry.",
                )
        changed = self._journal.transition(
            record.execution_id, ExecutionState.SETTLING,
            ExecutionState.SETTLED, self._now()
        )
        return RecoveryItem(
            record.execution_id, record.state,
            "SETTLED" if changed else "CONCURRENT_CHANGE",
            "Confirmed execution settled after the journal claimed SETTLING.",
        )

    def _now(self) -> datetime:
        value = self._clock()
        if value.tzinfo is None or value.utcoffset() is None:
            raise ValueError("recovery clock must return a timezone-aware datetime")
        return value.astimezone(timezone.utc)
