"""Tamper-evident JSONL audit journal for SafeState decisions.

The journal is local-first and dependency-free. SHA-256 chaining detects edits,
deletions and reordering; it is not a digital signature or protection against an
attacker who can rewrite the entire journal and its trusted checkpoint.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import threading
from typing import Any, Callable, Mapping, Protocol

from .models import Decision, DecisionStatus

GENESIS_HASH = "0" * 64
SCHEMA_VERSION = 1
_HASH_FIELDS = (
    "schema_version",
    "event_id",
    "timestamp",
    "request_id",
    "decision_id",
    "status",
    "rule_id",
    "reason_code",
    "policy_version",
    "previous_hash",
)


@dataclass(frozen=True, slots=True)
class AuditEvent:
    """Immutable decision facts to be persisted by an AuditSink."""

    event_id: str
    timestamp: datetime
    request_id: str
    decision_id: str
    status: str
    rule_id: str
    reason_code: str
    policy_version: str

    @classmethod
    def from_decision(
        cls, decision: Decision, event_id: str, timestamp: datetime | None = None
    ) -> "AuditEvent":
        return cls(
            event_id=event_id,
            timestamp=timestamp or decision.evaluated_at,
            request_id=decision.request_id,
            decision_id=decision.decision_id,
            status=decision.status.value,
            rule_id=decision.rule_id,
            reason_code=decision.reason_code,
            policy_version=decision.policy_version,
        )

    def to_record(self) -> dict[str, Any]:
        if self.timestamp.tzinfo is None or self.timestamp.utcoffset() is None:
            raise ValueError("audit timestamp must be timezone-aware")
        timestamp = self.timestamp.astimezone(timezone.utc).isoformat()
        record = asdict(self)
        record["timestamp"] = timestamp
        record["schema_version"] = SCHEMA_VERSION
        return record


class AuditSink(Protocol):
    def append(self, record: Mapping[str, Any]) -> None: ...


@dataclass(frozen=True, slots=True)
class VerificationResult:
    valid: bool
    records_checked: int
    error: str | None = None
    line_number: int | None = None


def _canonical_json(record: Mapping[str, Any]) -> bytes:
    payload = {key: record[key] for key in _HASH_FIELDS}
    return json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
    ).encode("utf-8")


def _event_hash(record: Mapping[str, Any]) -> str:
    return hashlib.sha256(_canonical_json(record)).hexdigest()


class JsonlAuditSink:
    """Append-only JSONL writer with a SHA-256 hash chain and process lock."""

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()

    def append(self, record: Mapping[str, Any]) -> None:
        required = (
            "event_id", "timestamp", "request_id", "decision_id",
            "status", "rule_id", "reason_code", "policy_version",
        )
        if not isinstance(record, Mapping):
            raise TypeError("audit record must be a mapping")
        payload = {key: record[key] for key in required}
        if any(not isinstance(value, str) or not value for value in payload.values()):
            raise ValueError("audit record fields must be non-empty strings")
        # Validate timestamp and normalize to canonical UTC representation.
        parsed = datetime.fromisoformat(payload["timestamp"])
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("audit timestamp must be timezone-aware")
        payload["timestamp"] = parsed.astimezone(timezone.utc).isoformat()
        payload["schema_version"] = SCHEMA_VERSION

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock:
            previous_hash = GENESIS_HASH
            if self.path.exists() and self.path.stat().st_size:
                result = self.verify()
                if not result.valid:
                    raise ValueError(
                        f"existing audit journal is invalid: {result.error}"
                    )
                with self.path.open("rb") as source:
                    for line in source:
                        if line.strip():
                            previous_hash = json.loads(line)["event_hash"]
            payload["previous_hash"] = previous_hash
            payload["event_hash"] = _event_hash(payload)
            encoded = json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
            with self.path.open("a", encoding="utf-8", newline="\n") as target:
                target.write(encoded + "\n")
                target.flush()
                os.fsync(target.fileno())

    def verify(self) -> VerificationResult:
        """Verify every record, hash, schema and chain link in the journal."""
        if not self.path.exists():
            return VerificationResult(True, 0)
        previous_hash = GENESIS_HASH
        checked = 0
        try:
            with self.path.open("r", encoding="utf-8") as source:
                for line_number, line in enumerate(source, start=1):
                    if not line.endswith("\n"):
                        return VerificationResult(
                            False, checked, "incomplete final record", line_number
                        )
                    if not line.strip():
                        return VerificationResult(
                            False, checked, "blank journal line", line_number
                        )
                    record = json.loads(line)
                    if not isinstance(record, dict):
                        raise ValueError("record must be a JSON object")
                    if record.get("schema_version") != SCHEMA_VERSION:
                        raise ValueError("unsupported schema version")
                    if record.get("previous_hash") != previous_hash:
                        raise ValueError("hash-chain link mismatch")
                    expected = _event_hash(record)
                    if record.get("event_hash") != expected:
                        raise ValueError("event hash mismatch")
                    previous_hash = expected
                    checked += 1
        except (OSError, UnicodeError, json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            return VerificationResult(False, checked, str(exc), checked + 1)
        return VerificationResult(True, checked)


class DecisionServiceLike(Protocol):
    def decide(self, request: Any) -> Decision: ...
    def decide_raw(self, payload: Mapping[str, Any]) -> Decision: ...


class AuditedDecisionService:
    """Decorator that requires durable audit append before returning a decision.

    If persistence fails, an otherwise permissive decision is converted to BLOCK.
    The failure itself cannot be written to the unavailable sink; the caller must
    surface operational alerts through an independent channel.
    """

    def __init__(
        self,
        decision_service: DecisionServiceLike,
        audit_sink: AuditSink,
        id_generator: Callable[[], str],
    ) -> None:
        self._service = decision_service
        self._audit = audit_sink
        self._new_id = id_generator

    def decide(self, request: Any) -> Decision:
        return self._record(self._service.decide(request))

    def decide_raw(self, payload: Mapping[str, Any]) -> Decision:
        return self._record(self._service.decide_raw(payload))

    def _record(self, decision: Decision) -> Decision:
        event = AuditEvent.from_decision(decision, self._new_id())
        try:
            self._audit.append(event.to_record())
        except Exception:  # noqa: BLE001 - audit persistence is authorization-critical
            return replace(
                decision,
                status=DecisionStatus.BLOCK,
                rule_id="R7",
                reason_code="AUDIT_PERSISTENCE_FAILED",
                reason="The decision could not be durably audited; the request is blocked.",
                approval_required=False,
            )
        return decision
