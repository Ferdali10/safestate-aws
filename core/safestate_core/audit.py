"""Tamper-evident JSONL audit journal for SafeState decisions.

The journal is local-first and dependency-free. SHA-256 chaining detects edits,
deletions and reordering; it is not a digital signature or protection against an
attacker who can rewrite the entire journal and its trusted checkpoint.
"""
from __future__ import annotations

from dataclasses import asdict, dataclass, replace
from datetime import datetime, timezone
import errno
import hashlib
import json
import os
from pathlib import Path
import threading
import time
from typing import Any, Callable, Mapping, Protocol

from .models import Decision, DecisionStatus

try:  # POSIX advisory lock for cross-process coordination.
    import fcntl
except ImportError:  # pragma: no cover - non-POSIX platforms
    fcntl = None  # type: ignore[assignment]

try:  # Windows byte-range lock for cross-process coordination.
    import msvcrt
except ImportError:  # pragma: no cover - POSIX platforms
    msvcrt = None  # type: ignore[assignment]


_PATH_LOCKS: dict[str, threading.RLock] = {}
_PATH_LOCKS_GUARD = threading.Lock()


def _thread_lock_for(path: Path) -> threading.RLock:
    """Return one process-wide lock for a canonical journal path."""
    key = os.path.normcase(str(path.resolve()))
    with _PATH_LOCKS_GUARD:
        lock = _PATH_LOCKS.get(key)
        if lock is None:
            lock = threading.RLock()
            _PATH_LOCKS[key] = lock
        return lock

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


class _ExclusiveFileLock:
    """Per-path thread and process lock held across a journal transaction."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._thread_lock = _thread_lock_for(path)
        self._handle = None

    def __enter__(self) -> "_ExclusiveFileLock":
        self._thread_lock.acquire()
        try:
            self._handle = open(self._path, "a+b")
            if fcntl is not None:
                fcntl.flock(self._handle.fileno(), fcntl.LOCK_EX)
            elif msvcrt is not None:  # pragma: no branch - selected by platform
                # Lock one stable byte in the sidecar. LK_NBLCK lets us wait
                # indefinitely instead of failing after LK_LOCK's retry cap.
                self._handle.seek(0, os.SEEK_END)
                if self._handle.tell() == 0:
                    self._handle.write(b"\0")
                    self._handle.flush()
                while True:
                    self._handle.seek(0)
                    try:
                        msvcrt.locking(self._handle.fileno(), msvcrt.LK_NBLCK, 1)
                        break
                    except OSError as exc:
                        if exc.errno not in {errno.EACCES, errno.EDEADLK}:
                            raise
                        time.sleep(0.01)
            else:  # pragma: no cover - unsupported platform
                raise RuntimeError("no supported inter-process file locking API")
        except Exception:
            if self._handle is not None:
                self._handle.close()
                self._handle = None
            self._thread_lock.release()
            raise
        return self

    def __exit__(self, *exc_info: object) -> None:
        try:
            if self._handle is not None:
                if fcntl is not None:
                    fcntl.flock(self._handle.fileno(), fcntl.LOCK_UN)
                elif msvcrt is not None:  # pragma: no branch - selected by platform
                    self._handle.seek(0)
                    msvcrt.locking(self._handle.fileno(), msvcrt.LK_UNLCK, 1)
        finally:
            if self._handle is not None:
                self._handle.close()
                self._handle = None
            self._thread_lock.release()


class JsonlAuditSink:
    """Append-only JSONL writer with a SHA-256 hash chain.

    Appends are serialized across sink instances in one process and across
    processes using a per-path thread lock plus the platform's sidecar lock
    (flock on POSIX, a byte-range lock on Windows), so concurrent writers extend
    one chain instead of forking it. The full journal
    is verified on the first append of each sink instance; later appends read
    and check only the last record, so cost does not grow with journal size.
    Call verify() periodically to re-check the whole chain.
    """

    def __init__(self, path: str | os.PathLike[str]) -> None:
        self.path = Path(path)
        self._lock = threading.Lock()
        self._verified = False

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
        if payload["status"] not in {status.value for status in DecisionStatus}:
            raise ValueError("audit status is not a recognized decision status")
        # Validate timestamp and normalize to canonical UTC representation.
        parsed = datetime.fromisoformat(payload["timestamp"])
        if parsed.tzinfo is None or parsed.utcoffset() is None:
            raise ValueError("audit timestamp must be timezone-aware")
        payload["timestamp"] = parsed.astimezone(timezone.utc).isoformat()
        payload["schema_version"] = SCHEMA_VERSION

        self.path.parent.mkdir(parents=True, exist_ok=True)
        with self._lock, self._file_lock():
            previous_hash = GENESIS_HASH
            if self.path.exists() and self.path.stat().st_size:
                if not self._verified:
                    result = self._verify_unlocked()
                    if not result.valid:
                        raise ValueError(
                            f"existing audit journal is invalid: {result.error}"
                        )
                    self._verified = True
                previous_hash = self._last_valid_hash()
            payload["previous_hash"] = previous_hash
            payload["event_hash"] = _event_hash(payload)
            encoded = json.dumps(
                payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False
            )
            with self.path.open("a", encoding="utf-8", newline="\n") as target:
                target.write(encoded + "\n")
                target.flush()
                os.fsync(target.fileno())

    def _file_lock(self):
        return _ExclusiveFileLock(self.path.with_name(self.path.name + ".lock"))

    def _last_valid_hash(self) -> str:
        """Read the final record and check that it is complete and self-consistent."""
        with self.path.open("rb") as source:
            source.seek(0, os.SEEK_END)
            size = source.tell()
            window = min(size, 65536)
            source.seek(size - window)
            tail = source.read()
        if not tail.endswith(b"\n"):
            raise ValueError("existing audit journal is invalid: incomplete final record")
        lines = tail.splitlines()
        if len(lines) == 1 and window < size:
            raise ValueError("existing audit journal is invalid: oversized record")
        try:
            record = json.loads(lines[-1])
            if record.get("event_hash") != _event_hash(record):
                raise ValueError("event hash mismatch")
        except (json.JSONDecodeError, KeyError, TypeError, ValueError) as exc:
            raise ValueError(f"existing audit journal is invalid: {exc}") from exc
        return record["event_hash"]

    def verify(self) -> VerificationResult:
        """Verify every record, hash, schema and chain link in the journal."""
        # Preserve the no-side-effect result for a missing journal. This check
        # can be linearized before a concurrent first append.
        if not self.path.exists():
            return VerificationResult(True, 0)
        with self._file_lock():
            return self._verify_unlocked()

    def _verify_unlocked(self) -> VerificationResult:
        """Verify the journal while the caller holds its per-path lock."""
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
                    if any(
                        not isinstance(record.get(key), str) or not record[key]
                        for key in _HASH_FIELDS
                        if key not in {"schema_version", "previous_hash"}
                    ):
                        raise ValueError("record contains missing or invalid fields")
                    timestamp = datetime.fromisoformat(record["timestamp"])
                    if timestamp.tzinfo is None or timestamp.utcoffset() is None:
                        raise ValueError("record timestamp is not timezone-aware")
                    if record.get("previous_hash") != previous_hash:
                        raise ValueError("hash-chain link mismatch")
                    expected = _event_hash(record)
                    if record.get("event_hash") != expected:
                        raise ValueError("event hash mismatch")
                    if record.get("status") not in {status.value for status in DecisionStatus}:
                        raise ValueError("record contains an invalid decision status")
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
        try:
            event = AuditEvent.from_decision(decision, self._new_id())
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
