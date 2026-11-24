from datetime import datetime, timezone

import pytest

from safestate_core.controls import InMemoryRiskBudgetStore
from safestate_core.recovery import (
    ExecutionRecord, ExecutionRecoveryService, ExecutionState,
    InMemoryExecutionJournal,
)

NOW = datetime(2026, 11, 24, 12, 0, tzinfo=timezone.utc)
MISSION = "agent:mission:v1"


def record(state=ExecutionState.PREPARED, reservation_id="agent:mission:v1:req-1"):
    return ExecutionRecord(
        execution_id="exec-1",
        request_id="req-1",
        mission_key=MISSION,
        reservation_id=reservation_id,
        action="DESCRIBE_INSTANCE",
        resource_id="i-dev-001",
        state=state,
        created_at=NOW,
        updated_at=NOW,
    )


def reserved_ledger(reservation_id="agent:mission:v1:req-1"):
    ledger = InMemoryRiskBudgetStore()
    assert ledger.reserve(MISSION, reservation_id, 2, 5)
    return ledger


def test_recovery_releases_prepared_execution_without_calling_executor():
    journal = InMemoryExecutionJournal()
    journal.prepare(record())
    ledger = reserved_ledger()

    result = ExecutionRecoveryService(journal, ledger, lambda: NOW).recover()

    assert result[0].outcome == "RELEASED"
    assert journal.get("exec-1").state is ExecutionState.RELEASED
    assert ledger.reserved(MISSION) == 0
    assert ledger.spent(MISSION) == 0


def test_recovery_settles_confirmed_execution_without_replaying_it():
    journal = InMemoryExecutionJournal()
    journal.prepare(record())
    assert journal.transition(
        "exec-1", ExecutionState.PREPARED, ExecutionState.EXECUTING, NOW
    )
    assert journal.transition(
        "exec-1", ExecutionState.EXECUTING, ExecutionState.EXECUTED, NOW
    )
    ledger = reserved_ledger()

    result = ExecutionRecoveryService(journal, ledger, lambda: NOW).recover()

    assert result[0].outcome == "SETTLED"
    assert journal.get("exec-1").state is ExecutionState.SETTLED
    assert ledger.reserved(MISSION) == 0
    assert ledger.spent(MISSION) == 2


def test_recovery_marks_inflight_execution_unknown_and_keeps_reservation():
    journal = InMemoryExecutionJournal()
    journal.prepare(record())
    assert journal.transition(
        "exec-1", ExecutionState.PREPARED, ExecutionState.EXECUTING, NOW
    )
    ledger = reserved_ledger()

    result = ExecutionRecoveryService(journal, ledger, lambda: NOW).recover()

    assert result[0].outcome == "NEEDS_RECONCILIATION"
    assert journal.get("exec-1").state is ExecutionState.UNKNOWN
    assert ledger.reserved(MISSION) == 2
    assert ledger.spent(MISSION) == 0


def test_recovery_releases_confirmed_executor_failure():
    journal = InMemoryExecutionJournal()
    journal.prepare(record())
    assert journal.transition(
        "exec-1", ExecutionState.PREPARED, ExecutionState.EXECUTING, NOW
    )
    assert journal.transition(
        "exec-1", ExecutionState.EXECUTING, ExecutionState.FAILED, NOW
    )
    ledger = reserved_ledger()

    result = ExecutionRecoveryService(journal, ledger, lambda: NOW).recover()

    assert result[0].outcome == "RELEASED"
    assert journal.get("exec-1").state is ExecutionState.RELEASED
    assert ledger.reserved(MISSION) == 0


def test_recovery_is_idempotent_after_terminal_transition():
    journal = InMemoryExecutionJournal()
    journal.prepare(record())
    assert journal.transition(
        "exec-1", ExecutionState.PREPARED, ExecutionState.EXECUTING, NOW
    )
    assert journal.transition(
        "exec-1", ExecutionState.EXECUTING, ExecutionState.EXECUTED, NOW
    )
    ledger = reserved_ledger()
    service = ExecutionRecoveryService(journal, ledger, lambda: NOW)

    assert service.recover()[0].outcome == "SETTLED"
    assert service.recover() == ()
    assert ledger.spent(MISSION) == 2


def test_execution_journal_rejects_conflicting_idempotency_key():
    journal = InMemoryExecutionJournal()
    journal.prepare(record())
    with pytest.raises(ValueError):
        journal.prepare(record(reservation_id="different-reservation"))


def test_execution_journal_rejects_unsupported_state_transition():
    journal = InMemoryExecutionJournal()
    journal.prepare(record())
    with pytest.raises(ValueError):
        journal.transition(
            "exec-1", ExecutionState.PREPARED, ExecutionState.SETTLED, NOW
        )
