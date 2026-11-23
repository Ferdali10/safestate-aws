"""Typed domain models for the SafeState AWS governance core.

These models are deliberately independent of AWS, Bedrock, and agent frameworks.
Validation of cross-field and untrusted input constraints lives in validation.py.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timedelta
from enum import Enum
from typing import TypeAlias


class DecisionStatus(str, Enum):
    """Outcome returned by the deterministic policy engine."""

    ALLOW = "ALLOW"
    BLOCK = "BLOCK"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


class ActionType(str, Enum):
    """Allow-listed actions understood by the initial cost-analysis MVP."""

    LIST_INSTANCES = "LIST_INSTANCES"
    DESCRIBE_INSTANCE = "DESCRIBE_INSTANCE"
    LIST_VOLUMES = "LIST_VOLUMES"
    DESCRIBE_VOLUME = "DESCRIBE_VOLUME"
    LIST_BUCKETS = "LIST_BUCKETS"
    GET_BUCKET_METADATA = "GET_BUCKET_METADATA"
    GET_COST_AND_UTILIZATION = "GET_COST_AND_UTILIZATION"
    REQUEST_STOP_INSTANCE = "REQUEST_STOP_INSTANCE"


class EnvironmentClass(str, Enum):
    """Trusted environment classification; UNKNOWN is never write-eligible."""

    PROD = "PROD"
    DEV = "DEV"
    TEST = "TEST"
    UNKNOWN = "UNKNOWN"


class ResourceType(str, Enum):
    EC2_INSTANCE = "EC2_INSTANCE"
    EBS_VOLUME = "EBS_VOLUME"
    S3_BUCKET = "S3_BUCKET"
    COST_REPORT = "COST_REPORT"


class ApprovalStatus(str, Enum):
    """Lifecycle states reserved for the approval subsystem."""

    PENDING = "PENDING"
    APPROVED = "APPROVED"
    REJECTED = "REJECTED"
    EXPIRED = "EXPIRED"
    CONSUMED = "CONSUMED"


class PolicyEffect(str, Enum):
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
    # R8: total point budget for the mission; None means R8 is not enforced.
    risk_budget: int | None = None
    # R9: decoy tool names and decoy resource ids that no honest task touches.
    decoy_actions: frozenset[str] = frozenset()
    decoy_resource_ids: frozenset[str] = frozenset()

    def __post_init__(self) -> None:
        _require_aware_utc(self.created_at, "created_at")
        if self.risk_budget is not None:
            if isinstance(self.risk_budget, bool) or not isinstance(self.risk_budget, int):
                raise TypeError("risk_budget must be an int or None")
            if self.risk_budget < 0:
                raise ValueError("risk_budget must not be negative")
        real_names = {action.value for action in ActionType}
        for name in self.decoy_actions:
            if not isinstance(name, str) or not name.strip():
                raise ValueError("decoy_actions must contain non-empty strings")
            if name.strip().upper() in real_names:
                raise ValueError(f"decoy action {name!r} collides with a real action")
        for resource_id in self.decoy_resource_ids:
            if not isinstance(resource_id, str) or not resource_id.strip():
                raise ValueError("decoy_resource_ids must contain non-empty strings")


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
    # R8 reservation metadata; absent when the mission has no risk budget.
    risk_reservation_id: str | None = None
    risk_mission_key: str | None = None
    risk_points: int = 0

    def __post_init__(self) -> None:
        _require_aware_utc(self.evaluated_at, "evaluated_at")
        expected = self.status is DecisionStatus.REQUIRE_APPROVAL
        if self.approval_required is not expected:
            raise ValueError(
                "approval_required must be true exactly when status is REQUIRE_APPROVAL"
            )
        if self.risk_reservation_id is None:
            if self.risk_mission_key is not None or self.risk_points != 0:
                raise ValueError("risk reservation metadata must be complete")
        else:
            if not isinstance(self.risk_reservation_id, str) or not self.risk_reservation_id:
                raise ValueError("risk_reservation_id must be a non-empty string")
            if not isinstance(self.risk_mission_key, str) or not self.risk_mission_key:
                raise ValueError("risk_mission_key must be a non-empty string")
            if isinstance(self.risk_points, bool) or not isinstance(self.risk_points, int) or self.risk_points <= 0:
                raise ValueError("risk_points must be a positive integer")
