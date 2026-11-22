"""Typed domain models for the SafeState AWS governance core.

These models are deliberately independent of AWS, Bedrock, and agent frameworks.
Validation of cross-field and untrusted input constraints lives in validation.py.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import StrEnum
from typing import TypeAlias


class DecisionStatus(StrEnum):
    """Outcome returned by the deterministic policy engine."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ActionType(StrEnum):
    """Allow-listed actions understood by the initial cost-analysis MVP."""

    LIST_INSTANCES = "LIST_INSTANCES"
    DESCRIBE_INSTANCE = "DESCRIBE_INSTANCE"
    LIST_VOLUMES = "LIST_VOLUMES"
    DESCRIBE_VOLUME = "DESCRIBE_VOLUME"
    LIST_BUCKETS = "LIST_BUCKETS"
    GET_BUCKET_METADATA = "GET_BUCKET_METADATA"
    GET_COST_AND_UTILIZATION = "GET_COST_AND_UTILIZATION"
    REQUEST_STOP_INSTANCE = "REQUEST_STOP_INSTANCE"


class EnvironmentClass(StrEnum):
    """Trusted environment classification; UNKNOWN is never write-eligible."""

    PROD = "PROD"
    DEV = "DEV"
    TEST = "TEST"
    UNKNOWN = "UNKNOWN"


class ResourceType(StrEnum):
    EC2_INSTANCE = "EC2_INSTANCE"
    EBS_VOLUME = "EBS_VOLUME"
    S3_BUCKET = "S3_BUCKET"
    COST_REPORT = "COST_REPORT"


class ApprovalStatus(StrEnum):
    """Lifecycle states reserved for the approval subsystem."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"


class PolicyEffect(StrEnum):
    """Internal policy effects used when rules are evaluated."""

    PERMIT_READ = "PERMIT_READ"
    DENY = "DENY"
    REQUIRE_HUMAN_APPROVAL = "REQUIRE_HUMAN_APPROVAL"


JSONValue: TypeAlias = (
    str | int | float | bool | None | list["JSONValue"] | dict[str, "JSONValue"]
)


def _require_aware_utc(value: datetime, field_name: str) -> None:
    """Reject naive timestamps and timestamps not normalized to UTC."""
    if not isinstance(value, datetime):
        raise TypeError(f"{field_name} must be a datetime")
    offset = value.utcoffset()
    if value.tzinfo is None or offset is None:
        raise ValueError(f"{field_name} must be timezone-aware")
    if offset != timedelta(0):
        raise ValueError(f"{field_name} must use UTC (offset +00:00)")


@dataclass(frozen=True, slots=True)
class MissionContract:
    mission_id: str
    version: str
    agent_id: str
    purpose: str
    allowed_actions: frozenset[ActionType]
    resource_scope: frozenset[ResourceType]
    policy_ids: frozenset[str]
    created_at: datetime

    def __post_init__(self) -> None:
        _require_aware_utc(self.created_at, "created_at")


@dataclass(frozen=True, slots=True)
class ResourceContext:
    resource_id: str
    resource_type: ResourceType
    environment: EnvironmentClass
    classification_source: str
    classification_verified: bool
    metadata: dict[str, str]


@dataclass(frozen=True, slots=True)
class ActionRequest:
    request_id: str
    agent_id: str
    mission_id: str
    mission_version: str
    action: ActionType
    resource_id: str
    resource_type: ResourceType
    parameters: dict[str, JSONValue]
    requested_at: datetime

    def __post_init__(self) -> None:
        _require_aware_utc(self.requested_at, "requested_at")


@dataclass(frozen=True, slots=True)
class Decision:
    decision_id: str
    request_id: str
    status: DecisionStatus
    rule_id: str
    reason_code: str
    reason: str
    policy_version: str
    evaluated_at: datetime
    approval_required: bool

    def __post_init__(self) -> None:
        _require_aware_utc(self.evaluated_at, "evaluated_at")
        expected = self.status is DecisionStatus.REQUIRE_APPROVAL
        if self.approval_required is not expected:
            raise ValueError(
                "approval_required must be true exactly when status is REQUIRE_APPROVAL"
            )
