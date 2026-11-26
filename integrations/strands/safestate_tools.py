"""Strands tool definitions that route every action through SafeState.

Each tool validates its arguments, builds a request using server-controlled
identity, and passes it to the SafeState ExecutionGateway. No tool executes
AWS operations directly.
"""
from __future__ import annotations

import json
from typing import Any

from strands import tool

from safestate_adapter import SafeStateRuntime


_runtime: SafeStateRuntime | None = None


def set_runtime(runtime: SafeStateRuntime) -> None:
    global _runtime
    _runtime = runtime


def _get_runtime() -> SafeStateRuntime:
    if _runtime is None:
        raise RuntimeError("SafeState runtime not initialized")
    return _runtime


def _result_json(result: dict[str, Any]) -> str:
    return json.dumps(result, indent=2, default=str)


@tool
def list_ec2_instances(max_results: int = 100) -> str:
    """List EC2 instances visible to this mission.

    Args:
        max_results: Maximum number of instances to return (1-1000, default 100).

    Returns:
        JSON with instance list or governance decision.
    """
    params: dict[str, Any] = {}
    if max_results != 100:
        params["max_results"] = max_results
    result = _get_runtime().submit_action("LIST_INSTANCES", parameters=params)
    return _result_json(result)


@tool
def describe_ec2_instance(instance_id: str) -> str:
    """Describe a specific EC2 instance.

    Args:
        instance_id: The EC2 instance ID (e.g., i-dev-001).

    Returns:
        JSON with instance details or governance decision.
    """
    if not instance_id or not isinstance(instance_id, str):
        return _result_json({"outcome": "BLOCKED", "error": "instance_id is required"})
    result = _get_runtime().submit_action("DESCRIBE_INSTANCE", resource_id=instance_id)
    return _result_json(result)


@tool
def list_ebs_volumes(max_results: int = 100) -> str:
    """List EBS volumes visible to this mission.

    Args:
        max_results: Maximum number of volumes to return (1-1000, default 100).

    Returns:
        JSON with volume list or governance decision.
    """
    params: dict[str, Any] = {}
    if max_results != 100:
        params["max_results"] = max_results
    result = _get_runtime().submit_action("LIST_VOLUMES", parameters=params)
    return _result_json(result)


@tool
def describe_ebs_volume(volume_id: str) -> str:
    """Describe a specific EBS volume.

    Args:
        volume_id: The EBS volume ID (e.g., vol-dev-001).

    Returns:
        JSON with volume details or governance decision.
    """
    if not volume_id or not isinstance(volume_id, str):
        return _result_json({"outcome": "BLOCKED", "error": "volume_id is required"})
    result = _get_runtime().submit_action("DESCRIBE_VOLUME", resource_id=volume_id)
    return _result_json(result)


@tool
def list_s3_buckets(max_results: int = 100) -> str:
    """List S3 buckets visible to this mission.

    Args:
        max_results: Maximum number of buckets to return (1-1000, default 100).

    Returns:
        JSON with bucket list or governance decision.
    """
    params: dict[str, Any] = {}
    if max_results != 100:
        params["max_results"] = max_results
    result = _get_runtime().submit_action("LIST_BUCKETS", parameters=params)
    return _result_json(result)


@tool
def get_bucket_metadata(bucket_name: str) -> str:
    """Get metadata for a specific S3 bucket.

    Args:
        bucket_name: The S3 bucket name (e.g., my-dev-bucket).

    Returns:
        JSON with bucket metadata or governance decision.
    """
    if not bucket_name or not isinstance(bucket_name, str):
        return _result_json({"outcome": "BLOCKED", "error": "bucket_name is required"})
    result = _get_runtime().submit_action("GET_BUCKET_METADATA", resource_id=bucket_name)
    return _result_json(result)


@tool
def get_cost_and_utilization(
    start_date: str = "",
    end_date: str = "",
    granularity: str = "MONTHLY",
) -> str:
    """Get cost and utilization information.

    Args:
        start_date: Start date in YYYY-MM-DD format (optional).
        end_date: End date in YYYY-MM-DD format (optional).
        granularity: DAILY or MONTHLY (default MONTHLY).

    Returns:
        JSON with cost data or governance decision.
    """
    params: dict[str, Any] = {}
    if start_date and end_date:
        params["start_date"] = start_date
        params["end_date"] = end_date
    if granularity != "MONTHLY":
        params["granularity"] = granularity
    result = _get_runtime().submit_action("GET_COST_AND_UTILIZATION", parameters=params)
    return _result_json(result)


@tool
def request_stop_instance(instance_id: str, reason: str = "") -> str:
    """Request to stop an EC2 instance. Requires human approval for dev/test instances.
    Production instances are always blocked.

    Args:
        instance_id: The EC2 instance ID to stop (e.g., i-dev-001).
        reason: Reason for stopping the instance (required, 1-200 chars).

    Returns:
        JSON with execution result, approval requirement, or block decision.
    """
    if not instance_id or not isinstance(instance_id, str):
        return _result_json({"outcome": "BLOCKED", "error": "instance_id is required"})
    if not reason or not isinstance(reason, str):
        return _result_json({"outcome": "BLOCKED", "error": "reason is required for stop requests"})
    params: dict[str, Any] = {"reason": reason}
    result = _get_runtime().submit_action(
        "REQUEST_STOP_INSTANCE", resource_id=instance_id, parameters=params,
    )
    return _result_json(result)


SAFESTATE_TOOLS = [
    list_ec2_instances,
    describe_ec2_instance,
    list_ebs_volumes,
    describe_ebs_volume,
    list_s3_buckets,
    get_bucket_metadata,
    get_cost_and_utilization,
    request_stop_instance,
]
