"""Static metadata about the actions the MVP understands.

This module holds facts, not decisions. Policy decisions live in policy.py.
"""
from __future__ import annotations

import re
import unicodedata
from typing import Mapping

from .models import ActionType, ResourceType

WILDCARD_RESOURCE_ID = "*"

ACTION_RESOURCE_TYPE: Mapping[ActionType, ResourceType] = {
    ActionType.LIST_INSTANCES: ResourceType.EC2_INSTANCE,
    ActionType.DESCRIBE_INSTANCE: ResourceType.EC2_INSTANCE,
    ActionType.LIST_VOLUMES: ResourceType.EBS_VOLUME,
    ActionType.DESCRIBE_VOLUME: ResourceType.EBS_VOLUME,
    ActionType.LIST_BUCKETS: ResourceType.S3_BUCKET,
    ActionType.GET_BUCKET_METADATA: ResourceType.S3_BUCKET,
    ActionType.GET_COST_AND_UTILIZATION: ResourceType.COST_REPORT,
    ActionType.REQUEST_STOP_INSTANCE: ResourceType.EC2_INSTANCE,
}

# Actions that target a whole collection and therefore use the "*" resource id.
COLLECTION_ACTIONS = frozenset(
    {
        ActionType.LIST_INSTANCES,
        ActionType.LIST_VOLUMES,
        ActionType.LIST_BUCKETS,
        ActionType.GET_COST_AND_UTILIZATION,
    }
)

READ_ACTIONS = frozenset(
    action for action in ActionType if action is not ActionType.REQUEST_STOP_INSTANCE
)
MUTATING_ACTIONS = frozenset({ActionType.REQUEST_STOP_INSTANCE})

# Parameters are allow-listed per action; anything else is rejected.
ALLOWED_PARAMETER_KEYS: Mapping[ActionType, frozenset[str]] = {
    ActionType.LIST_INSTANCES: frozenset({"max_results"}),
    ActionType.DESCRIBE_INSTANCE: frozenset(),
    ActionType.LIST_VOLUMES: frozenset({"max_results"}),
    ActionType.DESCRIBE_VOLUME: frozenset(),
    ActionType.LIST_BUCKETS: frozenset({"max_results"}),
    ActionType.GET_BUCKET_METADATA: frozenset(),
    ActionType.GET_COST_AND_UTILIZATION: frozenset({"start_date", "end_date", "granularity"}),
    ActionType.REQUEST_STOP_INSTANCE: frozenset({"reason"}),
}

# Default point costs for R8. They are operator configuration, not a measure of
# real-world impact.
DEFAULT_RISK_COSTS: Mapping[ActionType, int] = {
    **{action: 1 for action in READ_ACTIONS},
    ActionType.REQUEST_STOP_INSTANCE: 20,
}

_DESTRUCTIVE_SUBSTRINGS = ("DELETE", "TERMINATE", "DESTROY", "PURGE", "WIPE")
_EXFIL_OR_PRIVILEGE_SUBSTRINGS = (
    "POLICY",
    "ASSUME",
    "CREDENTIAL",
    "SECRET",
    "TOKEN",
    "SNAPSHOT",
    "SHARE",
    "EXPORT",
    "EXFIL",
    "UPLOAD",
    "PRESIGN",
    "OBJECT",
)
_EXFIL_OR_PRIVILEGE_TOKENS = frozenset({"IAM", "ROLE", "KEY", "SEND", "COPY", "PUBLIC"})


def normalize_action_name(value: object) -> str:
    """Normalize an untrusted action name for matching (decoys, classification).

    This is never used to map a string onto a real action: parsing a real
    action requires an exact match (see validation.parse_action).
    """
    if not isinstance(value, str):
        raise TypeError("action name must be a string")
    text = unicodedata.normalize("NFKC", value).strip().upper()
    return re.sub(r"[\s\-]+", "_", text)


def classify_unknown_action(raw_action: object) -> tuple[str, str]:
    """Return (rule_id, reason_code) for an action string SafeState does not know.

    The result only labels the BLOCK; every unknown action is blocked.
    """
    try:
        name = normalize_action_name(raw_action)
    except TypeError:
        return "R6", "UNKNOWN_ACTION_OUT_OF_MISSION"
    if any(part in name for part in _DESTRUCTIVE_SUBSTRINGS):
        return "R4", "DESTRUCTIVE_ACTION_NOT_EXPOSED"
    tokens = set(name.split("_"))
    if any(part in name for part in _EXFIL_OR_PRIVILEGE_SUBSTRINGS) or (
        tokens & _EXFIL_OR_PRIVILEGE_TOKENS
    ):
        return "R5", "EXFILTRATION_OR_PRIVILEGE_ACTION"
    return "R6", "UNKNOWN_ACTION_OUT_OF_MISSION"
