"""Strict parsing and validation of untrusted action requests.

Anything arriving from an agent is untrusted. Parsing is deliberately strict:
unknown fields, unknown actions and unexpected parameters are rejected rather
than ignored or mapped onto something similar.
"""
from __future__ import annotations

import math
from datetime import datetime
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

    if not isinstance(request.parameters, dict):
        raise ValidationError("INVALID_PARAMETER_VALUE", "parameters must be an object")
    unsupported = set(request.parameters) - ALLOWED_PARAMETER_KEYS[action]
    if unsupported:
        raise ValidationError(
            "UNSUPPORTED_PARAMETER",
            f"unsupported parameters for {action.value}: {sorted(map(str, unsupported))}",
        )
    _check_json(request.parameters, "parameters")


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
