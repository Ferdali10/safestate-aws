"""One-time, request-bound human approval workflow.

This module is a local-first reference implementation. Production deployments
must replace the in-memory store with a durable store whose compare-and-set
transitions are atomic across processes, and authenticate approver identities
outside this module.
"""
from __future__ import annotations

from dataclasses import dataclass, replace
from datetime import datetime, timedelta, timezone
import hashlib
import hmac
import json
import secrets
import threading
from typing import Protocol

from .models import ActionRequest, ApprovalStatus, Decision, DecisionStatus


@dataclass(frozen=True, slots=True)
class ApprovalRecord:
    approval_id: str
    request_id: str
    decision_id: str
    request_fingerprint: str
    token_digest: str
    created_at: datetime
    expires_at: datetime
    status: ApprovalStatus
    approved_by: str | None = None
    decided_at: datetime | None = None
    consumed_at: datetime | None = None
    risk_reservation_id: str | None = None
    risk_mission_key: str | None = None
    risk_points: int = 0


class ApprovalStore(Protocol):
    """Store contract. transition() must be an atomic compare-and-set."""

    def create(self, record: ApprovalRecord) -> None: ...
    def get(self, approval_id: str) -> ApprovalRecord | None: ...
    def transition(
        self, approval_id: str, expected: ApprovalStatus,
        updated: ApprovalRecord,
    ) -> bool: ...


class InMemoryApprovalStore:
    """Thread-safe process-local store for tests and local demonstrations only."""

    def __init__(self) -> None:
        self._records: dict[str, ApprovalRecord] = {}
        self._lock = threading.RLock()

    def create(self, record: ApprovalRecord) -> None:
        with self._lock:
            if record.approval_id in self._records:
                raise ValueError("approval id already exists")
            self._records[record.approval_id] = record

    def get(self, approval_id: str) -> ApprovalRecord | None:
        with self._lock:
            return self._records.get(approval_id)

    def transition(
        self, approval_id: str, expected: ApprovalStatus,
        updated: ApprovalRecord,
    ) -> bool:
        with self._lock:
            current = self._records.get(approval_id)
            if current is None or current.status is not expected:
                return False
            if updated.approval_id != approval_id:
                raise ValueError("approval id cannot change")
            self._records[approval_id] = updated
            return True


@dataclass(frozen=True, slots=True)
class ApprovalCredential:
    """Secret delivered to the authenticated human approval interface once."""

    approval_id: str
    token: str
    expires_at: datetime


class ApprovalError(ValueError):
    """Base class for rejected approval operations."""


class ApprovalExpiredError(ApprovalError):
    pass


class ApprovalService:
    """Issue, decide and consume approvals bound to an exact action request."""

    def __init__(
        self,
        store: ApprovalStore,
        clock,
        id_generator,
        ttl: timedelta = timedelta(minutes=10),
        risk_budget_store=None,
    ) -> None:
        if ttl <= timedelta(0):
            raise ValueError("approval TTL must be positive")
        if ttl > timedelta(hours=24):
            raise ValueError("approval TTL must not exceed 24 hours")
        self._store = store
        self._clock = clock
        self._new_id = id_generator
        self._ttl = ttl
        self._risk_budget = risk_budget_store

    def issue(self, request: ActionRequest, decision: Decision) -> ApprovalCredential:
        """Issue an opaque credential only for a genuine REQUIRE_APPROVAL decision."""
        if not isinstance(request, ActionRequest) or not isinstance(decision, Decision):
            raise TypeError("request and decision must be validated domain models")
        if (
            decision.status is not DecisionStatus.REQUIRE_APPROVAL
            or decision.approval_required is not True
            or decision.request_id != request.request_id
        ):
            raise ApprovalError("decision does not authorize an approval workflow")
        if decision.risk_reservation_id is not None and self._risk_budget is None:
            raise ApprovalError("risk budget ledger is required for reserved approvals")
        now = self._now()
        approval_id = self._new_id()
        token = secrets.token_urlsafe(32)
        record = ApprovalRecord(
            approval_id=approval_id,
            request_id=request.request_id,
            decision_id=decision.decision_id,
            request_fingerprint=request_fingerprint(request),
            token_digest=hashlib.sha256(token.encode("utf-8")).hexdigest(),
            created_at=now,
            expires_at=now + self._ttl,
            status=ApprovalStatus.PENDING,
            risk_reservation_id=decision.risk_reservation_id,
            risk_mission_key=decision.risk_mission_key,
            risk_points=decision.risk_points,
        )
        try:
            self._store.create(record)
        except Exception:
            self._release_reservation(record)
            raise
        return ApprovalCredential(approval_id, token, record.expires_at)

    def approve(self, credential: ApprovalCredential, approver_id: str) -> ApprovalRecord:
        return self._decide(credential, approver_id, ApprovalStatus.APPROVED)

    def reject(self, credential: ApprovalCredential, approver_id: str) -> ApprovalRecord:
        return self._decide(credential, approver_id, ApprovalStatus.REJECTED)

    def _decide(
        self, credential: ApprovalCredential, approver_id: str,
        target: ApprovalStatus,
    ) -> ApprovalRecord:
        if not isinstance(approver_id, str) or not approver_id.strip():
            raise ApprovalError("authenticated approver identity is required")
        record = self._load_and_authenticate(credential)
        now = self._now()
        if now >= record.expires_at:
            expired = replace(record, status=ApprovalStatus.EXPIRED)
            if self._store.transition(record.approval_id, ApprovalStatus.PENDING, expired):
                self._release_reservation(record)
            raise ApprovalExpiredError("approval request has expired")
        updated = replace(
            record, status=target, approved_by=approver_id.strip(), decided_at=now
        )
        if not self._store.transition(record.approval_id, ApprovalStatus.PENDING, updated):
            raise ApprovalError("approval request is no longer pending")
        if target is ApprovalStatus.REJECTED:
            self._release_reservation(record)
        return updated

    def expire(self, credential: ApprovalCredential) -> ApprovalRecord:
        """Explicitly expire a pending/approved request and release its reservation."""
        record = self._load_and_authenticate(credential)
        now = self._now()
        if now < record.expires_at:
            raise ApprovalError("approval request has not expired")
        if record.status not in {ApprovalStatus.PENDING, ApprovalStatus.APPROVED}:
            raise ApprovalError("approval request cannot be expired from its current state")
        expired = replace(record, status=ApprovalStatus.EXPIRED)
        if not self._store.transition(record.approval_id, record.status, expired):
            raise ApprovalError("approval state changed concurrently")
        self._release_reservation(record)
        return expired

    def consume(self, credential: ApprovalCredential, request: ActionRequest) -> ApprovalRecord:
        """Atomically consume an approved grant using its secret and exact request."""
        record = self._load_and_authenticate(credential)
        approval_id = record.approval_id
        if record.status is not ApprovalStatus.APPROVED:
            raise ApprovalError("approval is not in APPROVED state")
        if self._now() >= record.expires_at:
            expired = replace(record, status=ApprovalStatus.EXPIRED)
            if self._store.transition(approval_id, ApprovalStatus.APPROVED, expired):
                self._release_reservation(record)
            raise ApprovalExpiredError("approval request has expired")
        if request_fingerprint(request) != record.request_fingerprint:
            raise ApprovalError("approval is bound to a different action request")
        consumed = replace(
            record, status=ApprovalStatus.CONSUMED, consumed_at=self._now()
        )
        if not self._store.transition(approval_id, ApprovalStatus.APPROVED, consumed):
            raise ApprovalError("approval was already consumed or changed")
        return consumed

    def reservation_id_for(self, credential: ApprovalCredential) -> str | None:
        """Return reservation metadata only after authenticating the secret."""
        return self._load_and_authenticate(credential).risk_reservation_id

    def _release_reservation(self, record: ApprovalRecord) -> None:
        if record.risk_reservation_id is None:
            return
        if self._risk_budget is None:
            raise ApprovalError("risk budget ledger unavailable; reservation cannot be released")
        try:
            released = self._risk_budget.release(record.risk_reservation_id)
        except Exception as exc:
            raise ApprovalError("risk reservation release failed") from exc
        if released is not True:
            raise ApprovalError("risk reservation could not be released")

    def _load_and_authenticate(self, credential: ApprovalCredential) -> ApprovalRecord:
        if not isinstance(credential, ApprovalCredential):
            raise ApprovalError("valid approval credential is required")
        record = self._store.get(credential.approval_id)
        if record is None:
            raise ApprovalError("approval does not exist")
        supplied = hashlib.sha256(credential.token.encode("utf-8")).hexdigest()
        if not hmac.compare_digest(supplied, record.token_digest):
            raise ApprovalError("invalid approval credential")
        return record

    def _now(self) -> datetime:
        value = self._clock()
        if not isinstance(value, datetime) or value.tzinfo is None or value.utcoffset() is None:
            raise ApprovalError("approval clock must return an aware datetime")
        return value.astimezone(timezone.utc)


def request_fingerprint(request: ActionRequest) -> str:
    """Canonical digest binding identity, action, target, parameters and timestamp."""
    if not isinstance(request, ActionRequest):
        raise TypeError("request must be an ActionRequest")
    payload = {
        "request_id": request.request_id,
        "agent_id": request.agent_id,
        "mission_id": request.mission_id,
        "mission_version": request.mission_version,
        "action": request.action.value,
        "resource_id": request.resource_id,
        "resource_type": request.resource_type.value,
        "parameters": request.parameters,
        "requested_at": request.requested_at.astimezone(timezone.utc).isoformat(),
    }
    encoded = json.dumps(
        payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")
    return hashlib.sha256(encoded).hexdigest()
