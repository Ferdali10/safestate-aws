"""Strict parsing and validation of untrusted action requests.

Anything arriving from an agent is untrusted. Parsing is deliberately strict:
unknown fields, unknown actions and unexpected parameters are rejected rather
than ignored or mapped onto something similar.
"""
from __future__ import annotations

import math
import re
import unicodedata
from datetime import date, datetime
from typing import Any, Mapping

from .actions import (
    ACTION_RESOURCE_TYPE,
    ALLOWED_PARAMETER_KEYS,
    COLLECTION_ACTIONS,
    WILDCARD_RESOURCE_ID,
)
from .models import ActionRequest, ActionType, ResourceType

MAX_ID_LENGTH = 200
MAX_STRING_LENGTH = 1000
MAX_NESTING_DEPTH = 4

_ALLOWED_PAYLOAD_KEYS = frozenset(
    {
        "request_id",
        "agent_id",
        "mission_id",
        "mission_version",
        "action",
        "resource_id",
        "resource_type",
        "parameters",
        "requested_at",
    }
)
_REQUIRED_ID_FIELDS = (
    "request_id",
    "agent_id",
    "mission_id",
    "mission_version",
    "resource_id",
)


class ValidationError(ValueError):
    """A request was rejected before policy evaluation; nothing may execute."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code


class UnknownActionError(ValidationError):
    """The action string is not one of the allow-listed actions."""

    def __init__(self, raw_action: object) -> None:
        super().__init__("UNKNOWN_ACTION", "action is not an allow-listed action")
        self.raw_action = raw_action


def parse_action(raw: object) -> ActionType:
    """Exact-match parsing; unknown strings are never mapped to a known action."""
    if isinstance(raw, ActionType):
        return raw
    if isinstance(raw, str):
        try:
            return ActionType(raw)
        except ValueError:
            pass
    raise UnknownActionError(raw)


def parse_resource_type(raw: object) -> ResourceType:
    if isinstance(raw, ResourceType):
        return raw
    if isinstance(raw, str):
        try:
            return ResourceType(raw)
        except ValueError:
            pass
    raise ValidationError("UNKNOWN_RESOURCE_TYPE", "resource_type is not supported")


def _check_identifier(name: str, value: object) -> str:
    if not isinstance(value, str) or not value.strip():
        raise ValidationError("MISSING_FIELD", f"{name} must be a non-empty string")
    if len(value) > MAX_ID_LENGTH:
        raise ValidationError("INVALID_FIELD", f"{name} is too long")
    if not value.isprintable():
        raise ValidationError("INVALID_FIELD", f"{name} contains control characters")
    return value


def _check_json(value: object, path: str, depth: int = 0) -> None:
    if depth > MAX_NESTING_DEPTH:
        raise ValidationError("INVALID_PARAMETER_VALUE", f"{path} is nested too deeply")
    if value is None or isinstance(value, (bool, int)):
        return
    if isinstance(value, float):
        if not math.isfinite(value):
            raise ValidationError("INVALID_PARAMETER_VALUE", f"{path} is not finite")
        return
    if isinstance(value, str):
        if len(value) > MAX_STRING_LENGTH:
            raise ValidationError("INVALID_PARAMETER_VALUE", f"{path} is too long")
        return
    if isinstance(value, list):
        for index, item in enumerate(value):
            _check_json(item, f"{path}[{index}]", depth + 1)
        return
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                raise ValidationError("INVALID_PARAMETER_VALUE", f"{path} has a non-string key")
            _check_json(item, f"{path}.{key}", depth + 1)
        return
    raise ValidationError(
        "INVALID_PARAMETER_VALUE", f"{path} is not a JSON value ({type(value).__name__})"
    )


def validate_request(request: ActionRequest) -> None:
    """Validate cross-field constraints of an already typed request."""
    for field_name in _REQUIRED_ID_FIELDS:
        _check_identifier(field_name, getattr(request, field_name))

    action = parse_action(request.action)
    expected_type = ACTION_RESOURCE_TYPE[action]
    if request.resource_type is not expected_type:
        raise ValidationError(
            "RESOURCE_TYPE_MISMATCH",
            f"{action.value} requires resource type {expected_type.value}",
        )

    is_wildcard = request.resource_id == WILDCARD_RESOURCE_ID
    if action in COLLECTION_ACTIONS and not is_wildcard:
        raise ValidationError(
            "INVALID_RESOURCE_ID", f"{action.value} must target the wildcard resource"
        )
    if action not in COLLECTION_ACTIONS and is_wildcard:
        raise ValidationError(
            "INVALID_RESOURCE_ID", f"{action.value} must target one specific resource"
        )

    if not is_wildcard:
        pattern = _RESOURCE_ID_PATTERNS.get(request.resource_type)
        if pattern is None or not pattern.match(request.resource_id) or (
            ".." in request.resource_id
        ):
            raise ValidationError(
                "INVALID_RESOURCE_ID",
                f"resource id is not a valid {request.resource_type.value} identifier",
            )

    if not isinstance(request.parameters, dict):
        raise ValidationError("INVALID_PARAMETER_VALUE", "parameters must be an object")
    unsupported = set(request.parameters) - ALLOWED_PARAMETER_KEYS[action]
    if unsupported:
        raise ValidationError(
            "UNSUPPORTED_PARAMETER",
            f"unsupported parameters for {action.value}: {sorted(map(str, unsupported))}",
        )
    _check_json(request.parameters, "parameters")
    _check_parameter_values(action, request.parameters)


MAX_RESULTS_LIMIT = 1000
_RESOURCE_ID_PATTERNS = {
    ResourceType.EC2_INSTANCE: re.compile(r"^i-[a-z0-9][a-z0-9-]{0,60}$"),
    ResourceType.EBS_VOLUME: re.compile(r"^vol-[a-z0-9][a-z0-9-]{0,60}$"),
    ResourceType.S3_BUCKET: re.compile(r"^[a-z0-9][a-z0-9.-]{1,61}[a-z0-9]$"),
}
MAX_REASON_LENGTH = 200
MAX_DATE_RANGE_DAYS = 366
_DATE_PATTERN = re.compile(r"^\d{4}-\d{2}-\d{2}$")
_GRANULARITIES = frozenset({"DAILY", "MONTHLY"})


def _bad_value(name: str, why: str) -> ValidationError:
    return ValidationError("INVALID_PARAMETER_VALUE", f"parameter {name} {why}")


def _parse_date_parameter(name: str, value: object) -> date:
    if not isinstance(value, str) or not _DATE_PATTERN.match(value):
        raise _bad_value(name, "must be a YYYY-MM-DD date")
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise _bad_value(name, "is not a real calendar date") from None


def _check_parameter_values(action: ActionType, parameters: Mapping[str, Any]) -> None:
    """Bound every allowed parameter so an executor never receives free-form input."""
    if "max_results" in parameters:
        value = parameters["max_results"]
        if isinstance(value, bool) or not isinstance(value, int) or not (
            1 <= value <= MAX_RESULTS_LIMIT
        ):
            raise _bad_value("max_results", f"must be an integer from 1 to {MAX_RESULTS_LIMIT}")
    if "granularity" in parameters and parameters["granularity"] not in _GRANULARITIES:
        raise _bad_value("granularity", "must be DAILY or MONTHLY")
    if "start_date" in parameters or "end_date" in parameters:
        if "start_date" not in parameters or "end_date" not in parameters:
            raise _bad_value("start_date/end_date", "must be provided together")
        start = _parse_date_parameter("start_date", parameters["start_date"])
        end = _parse_date_parameter("end_date", parameters["end_date"])
        if end < start:
            raise _bad_value("end_date", "must not be before start_date")
        if (end - start).days > MAX_DATE_RANGE_DAYS:
            raise _bad_value("end_date", f"range must not exceed {MAX_DATE_RANGE_DAYS} days")
    if "reason" in parameters:
        value = parameters["reason"]
        if (
            not isinstance(value, str)
            or not value.strip()
            or len(value) > MAX_REASON_LENGTH
            or any(unicodedata.category(char).startswith("C") for char in value)
        ):
            raise _bad_value(
                "reason", f"must be 1-{MAX_REASON_LENGTH} printable characters"
            )


def _parse_timestamp(value: object) -> datetime:
    if isinstance(value, datetime):
        return value
    if isinstance(value, str):
        text = value[:-1] + "+00:00" if value.endswith("Z") else value
        try:
            return datetime.fromisoformat(text)
        except ValueError:
            pass
    raise ValidationError("INVALID_TIMESTAMP", "requested_at must be an ISO 8601 timestamp")


def parse_request(payload: Mapping[str, Any], *, now: datetime | None = None) -> ActionRequest:
    """Build a validated ActionRequest from an untrusted payload.

    ``now`` supplies requested_at when the payload omits it (the gateway adapter
    stamps requests server-side). Unknown fields, such as claimed tags, an
    environment, or credentials, are rejected.
    """
    if not isinstance(payload, Mapping):
        raise ValidationError("INVALID_PAYLOAD", "payload must be an object")
    unexpected = set(payload) - _ALLOWED_PAYLOAD_KEYS
    if unexpected:
        raise ValidationError(
            "UNSUPPORTED_FIELD", f"unsupported fields: {sorted(map(str, unexpected))}"
        )

    for field_name in _REQUIRED_ID_FIELDS:
        _check_identifier(field_name, payload.get(field_name))
    if "action" not in payload:
        raise ValidationError("MISSING_FIELD", "action is required")
    if "resource_type" not in payload:
        raise ValidationError("MISSING_FIELD", "resource_type is required")

    action = parse_action(payload["action"])
    resource_type = parse_resource_type(payload["resource_type"])

    raw_parameters = payload.get("parameters", {})
    if not isinstance(raw_parameters, Mapping):
        raise ValidationError("INVALID_PARAMETER_VALUE", "parameters must be an object")
    parameters = dict(raw_parameters)

    if "requested_at" in payload:
        requested_at = _parse_timestamp(payload["requested_at"])
    elif now is not None:
        requested_at = now
    else:
        raise ValidationError("MISSING_FIELD", "requested_at is required")

    try:
        request = ActionRequest(
            request_id=payload["request_id"],
            agent_id=payload["agent_id"],
            mission_id=payload["mission_id"],
            mission_version=payload["mission_version"],
            action=action,
            resource_id=payload["resource_id"],
            resource_type=resource_type,
            parameters=parameters,
            requested_at=requested_at,
        )
    except (TypeError, ValueError) as exc:
        raise ValidationError("INVALID_TIMESTAMP", str(exc)) from exc

    validate_request(request)
    return request
