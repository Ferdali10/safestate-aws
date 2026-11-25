from datetime import datetime, timezone
import json

import pytest

from safestate_core.audit import (
    GENESIS_HASH,
    AuditEvent,
    AuditedDecisionService,
    JsonlAuditSink,
)
from safestate_core.models import Decision, DecisionStatus

NOW = datetime(2026, 11, 23, 12, 0, tzinfo=timezone.utc)


def make_decision(status=DecisionStatus.ALLOW):
    return Decision(
        decision_id="dec-001",
        request_id="req-001",
        status=status,
        rule_id="R1" if status is DecisionStatus.ALLOW else "R3",
        reason_code="READ_WITHIN_MISSION",
        reason="Test decision.",
        policy_version="test-1",
        evaluated_at=NOW,
        approval_required=status is DecisionStatus.REQUIRE_APPROVAL,
    )


def make_record(event_id="evt-001"):
    return AuditEvent.from_decision(make_decision(), event_id).to_record()


def test_append_creates_jsonl_record_with_genesis_hash(tmp_path):
    path = tmp_path / "audit" / "journal.jsonl"
    sink = JsonlAuditSink(path)
    sink.append(make_record())
    record = json.loads(path.read_text(encoding="utf-8").splitlines()[0])
    assert record["previous_hash"] == GENESIS_HASH
    assert len(record["event_hash"]) == 64
    assert sink.verify().valid
    assert sink.verify().records_checked == 1


def test_second_record_links_to_previous_record(tmp_path):
    sink = JsonlAuditSink(tmp_path / "journal.jsonl")
    sink.append(make_record("evt-1"))
    first = json.loads(sink.path.read_text().splitlines()[0])
    sink.append(make_record("evt-2"))
    second = json.loads(sink.path.read_text().splitlines()[1])
    assert second["previous_hash"] == first["event_hash"]
    assert sink.verify().records_checked == 2


def test_tampered_field_is_detected(tmp_path):
    sink = JsonlAuditSink(tmp_path / "journal.jsonl")
    sink.append(make_record())
    record = json.loads(sink.path.read_text())
    record["status"] = "ALLOW_WITHOUT_REVIEW"
    sink.path.write_text(json.dumps(record) + "\n")
    result = sink.verify()
    assert not result.valid
    assert "hash mismatch" in result.error


def test_deleted_record_is_detected_by_chain_link(tmp_path):
    sink = JsonlAuditSink(tmp_path / "journal.jsonl")
    sink.append(make_record("evt-1"))
    sink.append(make_record("evt-2"))
    records = sink.path.read_text().splitlines()
    sink.path.write_text(records[1] + "\n")
    result = sink.verify()
    assert not result.valid
    assert "link mismatch" in result.error


def test_reordered_records_are_detected(tmp_path):
    sink = JsonlAuditSink(tmp_path / "journal.jsonl")
    sink.append(make_record("evt-1"))
    sink.append(make_record("evt-2"))
    records = sink.path.read_text().splitlines()
    sink.path.write_text("\n".join(reversed(records)) + "\n")
    assert not sink.verify().valid


def test_incomplete_final_line_is_detected(tmp_path):
    sink = JsonlAuditSink(tmp_path / "journal.jsonl")
    sink.append(make_record())
    sink.path.write_text(sink.path.read_text().rstrip("\n"))
    result = sink.verify()
    assert not result.valid
    assert result.error == "incomplete final record"


def test_invalid_existing_journal_rejects_future_append(tmp_path):
    sink = JsonlAuditSink(tmp_path / "journal.jsonl")
    sink.path.write_text("{broken json}\n")
    with pytest.raises(ValueError, match="existing audit journal is invalid"):
        sink.append(make_record())


def test_append_rejects_naive_timestamp(tmp_path):
    record = make_record()
    record["timestamp"] = "2026-11-23T12:00:00"
    with pytest.raises(ValueError, match="timezone-aware"):
        JsonlAuditSink(tmp_path / "journal.jsonl").append(record)


class FakeDecisionService:
    def __init__(self, decision):
        self.decision = decision

    def decide(self, request):
        return self.decision

    def decide_raw(self, payload):
        return self.decision


class FakeAuditSink:
    def __init__(self, error=None):
        self.error = error
        self.records = []

    def append(self, record):
        if self.error:
            raise self.error
        self.records.append(dict(record))


def test_audited_service_records_allow_before_returning_it():
    sink = FakeAuditSink()
    service = AuditedDecisionService(
        FakeDecisionService(make_decision()), sink, lambda: "evt-001"
    )
    result = service.decide(object())
    assert result.status is DecisionStatus.ALLOW
    assert len(sink.records) == 1
    assert sink.records[0]["decision_id"] == "dec-001"


def test_audit_failure_converts_allow_to_block():
    service = AuditedDecisionService(
        FakeDecisionService(make_decision()),
        FakeAuditSink(error=OSError("disk full")),
        lambda: "evt-002",
    )
    result = service.decide(object())
    assert result.status is DecisionStatus.BLOCK
    assert result.rule_id == "R7"
    assert result.reason_code == "AUDIT_PERSISTENCE_FAILED"
    assert result.approval_required is False


def test_approval_decision_is_audited_without_changing_status():
    sink = FakeAuditSink()
    decision = make_decision(DecisionStatus.REQUIRE_APPROVAL)
    service = AuditedDecisionService(
        FakeDecisionService(decision), sink, lambda: "evt-003"
    )
    result = service.decide_raw({})
    assert result.status is DecisionStatus.REQUIRE_APPROVAL
    assert sink.records[0]["status"] == "REQUIRE_APPROVAL"


def test_many_writers_on_one_file_keep_a_single_valid_chain(tmp_path):
    import threading

    path = tmp_path / "shared.jsonl"
    sinks = [JsonlAuditSink(path) for _ in range(4)]  # like four Lambda instances
    errors = []
    start = threading.Barrier(len(sinks))

    def work(sink, offset):
        start.wait()
        for i in range(40):
            n = offset * 1000 + i
            try:
                sink.append({
                    "event_id": f"e{n}", "timestamp": "2026-11-25T12:00:00+00:00",
                    "request_id": f"r{n}", "decision_id": f"d{n}", "status": "ALLOW",
                    "rule_id": "R1", "reason_code": "X", "policy_version": "v",
                })
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    threads = [threading.Thread(target=work, args=(sink, k)) for k, sink in enumerate(sinks)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()
    result = sinks[0].verify()
    records = [json.loads(line) for line in path.read_text(encoding="utf-8").splitlines()]
    assert errors == []
    assert result.valid and result.records_checked == 160
    assert len(records) == 160
    assert {record["event_id"] for record in records} == {
        f"e{offset * 1000 + i}" for offset in range(4) for i in range(40)
    }


def test_concurrent_writers_on_different_files_keep_independent_chains(tmp_path):
    import threading

    sinks = [JsonlAuditSink(tmp_path / f"journal-{index}.jsonl") for index in range(4)]
    errors = []
    start = threading.Barrier(len(sinks))

    def work(sink, offset):
        start.wait()
        for i in range(40):
            n = offset * 1000 + i
            try:
                sink.append({
                    "event_id": f"e{n}", "timestamp": "2026-11-25T12:00:00+00:00",
                    "request_id": f"r{n}", "decision_id": f"d{n}", "status": "ALLOW",
                    "rule_id": "R1", "reason_code": "X", "policy_version": "v",
                })
            except Exception as exc:  # noqa: BLE001
                errors.append(exc)

    threads = [threading.Thread(target=work, args=(sink, index))
               for index, sink in enumerate(sinks)]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join()

    assert errors == []
    for index, sink in enumerate(sinks):
        result = sink.verify()
        records = [json.loads(line) for line in sink.path.read_text(encoding="utf-8").splitlines()]
        assert result.valid and result.records_checked == 40
        assert len(records) == 40
        assert {record["event_id"] for record in records} == {
            f"e{index * 1000 + i}" for i in range(40)
        }


def test_append_detects_tampering_of_the_last_record(tmp_path):
    path = tmp_path / "a.jsonl"
    sink = JsonlAuditSink(path)
    record = {
        "event_id": "e1", "timestamp": "2026-11-25T12:00:00+00:00", "request_id": "r1",
        "decision_id": "d1", "status": "ALLOW", "rule_id": "R1", "reason_code": "X",
        "policy_version": "v",
    }
    sink.append(record)
    path.write_text(path.read_text().replace("ALLOW", "BLOCK"))
    fresh = JsonlAuditSink(path)
    with pytest.raises(ValueError):
        fresh.append({**record, "event_id": "e2"})
