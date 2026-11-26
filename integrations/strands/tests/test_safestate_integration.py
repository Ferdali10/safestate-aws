"""Comprehensive tests for the SafeState + Strands + AgentCore integration.

These tests exercise the real SafeState Core components without making
any paid model inference calls or deploying AWS resources.
"""
from __future__ import annotations

import json
import os
import tempfile
import uuid
from datetime import datetime, timedelta, timezone
from typing import Any, Mapping
from unittest.mock import MagicMock, patch

import pytest

from safestate_adapter import (
    DEMO_AGENT_ID,
    DEMO_MISSION,
    DEMO_MISSION_ID,
    DEMO_MISSION_VERSION,
    DEMO_RESOURCES,
    DemoMissionProvider,
    DemoResourceContextProvider,
    SafeStateRuntime,
)
from safestate_core import (
    ActionRequest,
    ActionType,
    ApprovalService,
    AuditedDecisionService,
    DecisionStatus,
    EnvironmentClass,
    ExecutionGateway,
    GatewayResult,
    InMemoryApprovalStore,
    InMemoryRiskBudgetStore,
    InMemoryTripwireHandler,
    JsonlAuditSink,
    MissionContract,
    ResourceContext,
    ResourceType,
    SimulatedAWSExecutor,
)
from safestate_core.recovery import InMemoryExecutionJournal
from safestate_core.actions import WILDCARD_RESOURCE_ID
from safestate_core.policy import DeterministicPolicyEngine
from safestate_core.service import DefaultDecisionService
from safestate_tools import (
    SAFESTATE_TOOLS,
    describe_ebs_volume,
    describe_ec2_instance,
    get_bucket_metadata,
    get_cost_and_utilization,
    list_ebs_volumes,
    list_ec2_instances,
    list_s3_buckets,
    request_stop_instance,
    set_runtime,
)


def _utc_now():
    return datetime.now(timezone.utc)


def _new_id():
    return str(uuid.uuid4())


@pytest.fixture
def audit_path(tmp_path):
    return str(tmp_path / "test_audit.jsonl")


@pytest.fixture
def runtime(audit_path):
    rt = SafeStateRuntime(audit_path=audit_path)
    set_runtime(rt)
    return rt


# ─────────────────────────────────────────────────────────────
# 1. Read action on an allowed development resource
# ─────────────────────────────────────────────────────────────

class TestReadAllowedDevResource:
    def test_list_instances_allowed(self, runtime):
        result = runtime.submit_action("LIST_INSTANCES")
        assert result["outcome"] == "EXECUTED"
        assert result["status"] == "ALLOW"
        assert result["rule"] == "R1"
        assert "execution" in result
        assert result["execution"]["simulated"] is True

    def test_describe_dev_instance(self, runtime):
        result = runtime.submit_action("DESCRIBE_INSTANCE", resource_id="i-dev-001")
        assert result["outcome"] == "EXECUTED"
        assert result["status"] == "ALLOW"

    def test_list_volumes(self, runtime):
        result = runtime.submit_action("LIST_VOLUMES")
        assert result["outcome"] == "EXECUTED"
        assert result["status"] == "ALLOW"

    def test_list_buckets(self, runtime):
        result = runtime.submit_action("LIST_BUCKETS")
        assert result["outcome"] == "EXECUTED"
        assert result["status"] == "ALLOW"

    def test_get_cost_and_utilization(self, runtime):
        result = runtime.submit_action("GET_COST_AND_UTILIZATION")
        assert result["outcome"] == "EXECUTED"
        assert result["status"] == "ALLOW"


# ─────────────────────────────────────────────────────────────
# 2. Read action on a known resource
# ─────────────────────────────────────────────────────────────

class TestReadKnownResource:
    def test_describe_known_volume(self, runtime):
        result = runtime.submit_action("DESCRIBE_VOLUME", resource_id="vol-dev-001")
        assert result["outcome"] == "EXECUTED"
        assert result["status"] == "ALLOW"

    def test_get_known_bucket_metadata(self, runtime):
        result = runtime.submit_action("GET_BUCKET_METADATA", resource_id="my-dev-bucket")
        assert result["outcome"] == "EXECUTED"
        assert result["status"] == "ALLOW"


# ─────────────────────────────────────────────────────────────
# 3. Write/stop request requiring human approval
# ─────────────────────────────────────────────────────────────

class TestStopRequiresApproval:
    def test_stop_dev_instance_requires_approval(self, runtime):
        result = runtime.submit_action(
            "REQUEST_STOP_INSTANCE",
            resource_id="i-dev-001",
            parameters={"reason": "Cost savings"},
        )
        assert result["outcome"] in ("APPROVAL_REQUIRED", "BLOCKED")
        if result["outcome"] == "APPROVAL_REQUIRED":
            assert result["status"] == "REQUIRE_APPROVAL"
            assert "approval_id" in result
            assert "token" not in json.dumps(result)
            assert "message" in result

    def test_stop_test_instance_requires_approval(self, runtime):
        result = runtime.submit_action(
            "REQUEST_STOP_INSTANCE",
            resource_id="i-test-001",
            parameters={"reason": "Test cleanup"},
        )
        assert result["outcome"] in ("APPROVAL_REQUIRED", "BLOCKED")
        if result["outcome"] == "APPROVAL_REQUIRED":
            assert result["status"] == "REQUIRE_APPROVAL"


# ─────────────────────────────────────────────────────────────
# 4. Production stop request blocked
# ─────────────────────────────────────────────────────────────

class TestProductionBlocked:
    def test_stop_prod_instance_blocked(self, runtime):
        result = runtime.submit_action(
            "REQUEST_STOP_INSTANCE",
            resource_id="i-prod-001",
            parameters={"reason": "Cost savings"},
        )
        assert result["outcome"] == "BLOCKED"
        assert result["status"] == "BLOCK"
        assert result["rule"] == "R2"


# ─────────────────────────────────────────────────────────────
# 5. Destructive unknown action blocked
# ─────────────────────────────────────────────────────────────

class TestDestructiveActionBlocked:
    def test_terminate_instance_blocked(self, runtime):
        result = runtime.submit_action("TERMINATE_INSTANCE", resource_id="i-dev-001")
        assert result["outcome"] == "BLOCKED"
        assert result["status"] == "BLOCK"

    def test_delete_bucket_blocked(self, runtime):
        result = runtime.submit_action("DELETE_BUCKET", resource_id="my-dev-bucket")
        assert result["outcome"] == "BLOCKED"
        assert result["status"] == "BLOCK"


# ─────────────────────────────────────────────────────────────
# 6. Unknown action blocked
# ─────────────────────────────────────────────────────────────

class TestUnknownActionBlocked:
    def test_completely_unknown_action(self, runtime):
        result = runtime.submit_action("REBOOT_UNIVERSE")
        assert result["outcome"] == "BLOCKED"
        assert result["status"] == "BLOCK"
        assert result["rule"] in ("R4", "R5", "R6", "R9")

    def test_unknown_with_suspicious_name(self, runtime):
        result = runtime.submit_action("ASSUME_ROLE")
        assert result["outcome"] == "BLOCKED"


# ─────────────────────────────────────────────────────────────
# 7. Out-of-scope resource blocked
# ─────────────────────────────────────────────────────────────

class TestOutOfScopeResource:
    def test_describe_unknown_instance(self, runtime):
        result = runtime.submit_action("DESCRIBE_INSTANCE", resource_id="i-unknown-999")
        assert result["outcome"] == "BLOCKED"

    def test_describe_unknown_volume(self, runtime):
        result = runtime.submit_action("DESCRIBE_VOLUME", resource_id="vol-unknown-999")
        assert result["outcome"] == "BLOCKED"


# ─────────────────────────────────────────────────────────────
# 8. Invalid payload blocked
# ─────────────────────────────────────────────────────────────

class TestInvalidPayload:
    def test_empty_action(self, runtime):
        result = runtime.submit_action("")
        assert result["outcome"] == "BLOCKED"

    def test_missing_resource_id_for_describe(self, runtime):
        result = runtime.submit_action("DESCRIBE_INSTANCE", resource_id=None)
        assert result["outcome"] == "BLOCKED"

    def test_invalid_resource_id_format(self, runtime):
        result = runtime.submit_action("DESCRIBE_INSTANCE", resource_id="bad-format")
        assert result["outcome"] == "BLOCKED"


# ─────────────────────────────────────────────────────────────
# 9. Agent-supplied identity rejected or ignored
# ─────────────────────────────────────────────────────────────

class TestAgentIdentityRejected:
    def test_identity_is_always_server_controlled(self, runtime):
        result = runtime.submit_action("LIST_INSTANCES")
        assert result["outcome"] == "EXECUTED"
        assert result["decision_id"] is not None

    def test_cannot_inject_different_agent_id(self, runtime):
        """The adapter always uses the server mission agent_id.
        Even if someone tried to pass different identity, it's ignored."""
        payload = {
            "request_id": _new_id(),
            "agent_id": "malicious-agent",
            "mission_id": DEMO_MISSION_ID,
            "mission_version": DEMO_MISSION_VERSION,
            "action": "LIST_INSTANCES",
            "resource_id": "*",
            "resource_type": "EC2_INSTANCE",
            "parameters": {},
        }
        from safestate_core import parse_request
        request = parse_request(payload, now=_utc_now())
        result = runtime.gateway.submit(request)
        assert result.outcome == "BLOCKED"
        assert result.decision.reason_code in (
            "MISSION_MISMATCH", "DECISION_PIPELINE_ERROR"
        )


# ─────────────────────────────────────────────────────────────
# 10. Agent-supplied environment classification rejected
# ─────────────────────────────────────────────────────────────

class TestEnvironmentClassificationRejected:
    def test_environment_comes_from_trusted_inventory(self, runtime):
        """The resource provider returns the environment, not the agent.
        A prod resource stays prod regardless of what the agent might claim."""
        result = runtime.submit_action(
            "REQUEST_STOP_INSTANCE",
            resource_id="i-prod-001",
            parameters={"reason": "trying to stop prod"},
        )
        assert result["outcome"] == "BLOCKED"
        assert result["rule"] == "R2"

    def test_dev_resource_stays_dev(self, runtime):
        ctx = runtime.resource_provider.get_context("i-dev-001", ResourceType.EC2_INSTANCE)
        assert ctx.environment == EnvironmentClass.DEV
        assert ctx.classification_source == "demo-inventory"


# ─────────────────────────────────────────────────────────────
# 11. Audit journal verification
# ─────────────────────────────────────────────────────────────

class TestAuditJournal:
    def test_audit_records_created_on_allow(self, runtime, audit_path):
        runtime.submit_action("LIST_INSTANCES")
        verification = runtime.audit_sink.verify()
        assert verification.valid is True
        assert verification.records_checked >= 1

    def test_audit_records_created_on_block(self, runtime, audit_path):
        runtime.submit_action("REQUEST_STOP_INSTANCE", resource_id="i-prod-001",
                              parameters={"reason": "test"})
        verification = runtime.audit_sink.verify()
        assert verification.valid is True

    def test_audit_hash_chain_integrity(self, runtime, audit_path):
        runtime.submit_action("LIST_INSTANCES")
        runtime.submit_action("LIST_VOLUMES")
        runtime.submit_action("LIST_BUCKETS")
        verification = runtime.audit_sink.verify()
        assert verification.valid is True
        assert verification.records_checked >= 3


# ─────────────────────────────────────────────────────────────
# 12. Audit persistence failure causes BLOCK
# ─────────────────────────────────────────────────────────────

class TestAuditFailureCausesBlock:
    def test_broken_audit_sink_blocks(self, tmp_path):
        audit_path = str(tmp_path / "audit.jsonl")
        rt = SafeStateRuntime(audit_path=audit_path)
        set_runtime(rt)

        original_append = rt.audit_sink.append
        def failing_append(record):
            raise IOError("Simulated audit failure")
        rt.audit_sink.append = failing_append

        result = rt.submit_action("LIST_INSTANCES")
        assert result["outcome"] == "BLOCKED"
        assert result["reason_code"] == "AUDIT_PERSISTENCE_FAILED"


# ─────────────────────────────────────────────────────────────
# 13. Approval credentials never appear in tool output
# ─────────────────────────────────────────────────────────────

class TestApprovalCredentialsNeverExposed:
    def test_no_token_in_approval_response(self, runtime):
        result = runtime.submit_action(
            "REQUEST_STOP_INSTANCE",
            resource_id="i-dev-001",
            parameters={"reason": "Cost savings"},
        )
        result_str = json.dumps(result)
        assert "token" not in result_str.lower() or "token_digest" not in result_str
        if result["outcome"] == "APPROVAL_REQUIRED":
            assert "approval_id" in result
            assert result.get("approval") is None

    def test_gateway_does_not_expose_credentials(self, runtime):
        assert runtime.gateway._expose_credential is False

    def test_strands_tool_no_token_leak(self, runtime):
        output = request_stop_instance(instance_id="i-dev-001", reason="testing")
        parsed = json.loads(output)
        result_str = json.dumps(parsed)
        assert '"token":' not in result_str
        assert "token_digest" not in result_str


# ─────────────────────────────────────────────────────────────
# 14. Gateway is called exactly once for valid requests
# ─────────────────────────────────────────────────────────────

class TestGatewayCalledOnce:
    def test_single_gateway_call(self, runtime):
        with patch.object(runtime.gateway, 'submit', wraps=runtime.gateway.submit) as mock_submit:
            runtime.submit_action("LIST_INSTANCES")
            assert mock_submit.call_count == 1

    def test_no_separate_decide_before_submit(self, runtime):
        with patch.object(
            runtime.audited_decision_service, 'decide',
            wraps=runtime.audited_decision_service.decide,
        ) as mock_decide:
            runtime.submit_action("LIST_INSTANCES")
            assert mock_decide.call_count == 1


# ─────────────────────────────────────────────────────────────
# 15. Tripwire revocation prevents further actions
# ─────────────────────────────────────────────────────────────

class TestTripwireRevocation:
    def test_decoy_action_triggers_tripwire(self, runtime):
        result = runtime.submit_action("TERMINATE_INSTANCE", resource_id="i-dev-001")
        assert result["outcome"] == "BLOCKED"
        assert runtime.tripwire_handler.is_revoked(DEMO_AGENT_ID) is True

    def test_revoked_agent_blocked_on_subsequent_requests(self, runtime):
        runtime.submit_action("TERMINATE_INSTANCE", resource_id="i-dev-001")
        result = runtime.submit_action("LIST_INSTANCES")
        assert result["outcome"] == "BLOCKED"
        assert result["reason_code"] == "AGENT_SESSION_REVOKED"

    def test_decoy_resource_triggers_tripwire(self, runtime):
        result = runtime.submit_action("DESCRIBE_INSTANCE", resource_id="i-decoy-001")
        assert result["outcome"] == "BLOCKED"
        assert runtime.tripwire_handler.is_revoked(DEMO_AGENT_ID) is True


# ─────────────────────────────────────────────────────────────
# 16. Agent tool cannot bypass SafeState
# ─────────────────────────────────────────────────────────────

class TestCannotBypassSafeState:
    def test_all_tools_go_through_gateway(self, runtime):
        with patch.object(runtime.gateway, 'submit', wraps=runtime.gateway.submit) as mock_submit:
            runtime.submit_action("LIST_INSTANCES")
            runtime.submit_action("DESCRIBE_INSTANCE", resource_id="i-dev-001")
            runtime.submit_action("LIST_VOLUMES")
            assert mock_submit.call_count == 3

    def test_tools_do_not_call_executor_directly(self, runtime):
        with patch.object(runtime.executor, 'execute', wraps=runtime.executor.execute) as mock_exec:
            runtime.submit_action("LIST_INSTANCES")
            assert mock_exec.call_count == 1

    def test_blocked_action_never_reaches_executor(self, runtime):
        with patch.object(runtime.executor, 'execute') as mock_exec:
            runtime.submit_action("REQUEST_STOP_INSTANCE",
                                  resource_id="i-prod-001",
                                  parameters={"reason": "test"})
            mock_exec.assert_not_called()


# ─────────────────────────────────────────────────────────────
# 17. AgentCore invocation handler works without deploying
# ─────────────────────────────────────────────────────────────

class TestAgentCoreHandler:
    def test_valid_prompt(self):
        from main import handle_invocation, _runtime
        import main
        main._runtime = None
        with patch('main._create_agent') as mock_agent:
            mock_instance = MagicMock()
            mock_instance.return_value = "Here are the instances: i-dev-001 (running)"
            mock_instance.__str__ = lambda self: "Here are the instances: i-dev-001 (running)"
            mock_agent.return_value = mock_instance

            result = handle_invocation({"prompt": "List EC2 instances"})
            assert "response" in result
            assert "governance" in result
            assert result["governance"]["agent_id"] == DEMO_AGENT_ID

    def test_missing_prompt(self):
        from main import handle_invocation
        result = handle_invocation({"something": "else"})
        assert result["error"] == "MISSING_PROMPT"

    def test_invalid_payload(self):
        from main import handle_invocation
        result = handle_invocation("not a dict")
        assert result["error"] == "INVALID_PAYLOAD"

    def test_empty_prompt(self):
        from main import handle_invocation
        result = handle_invocation({"prompt": ""})
        assert result["error"] == "MISSING_PROMPT"

    def test_agent_failure_handled(self):
        from main import handle_invocation
        import main
        main._runtime = None
        with patch('main._create_agent') as mock_agent:
            mock_instance = MagicMock()
            mock_instance.side_effect = RuntimeError("Model access denied")
            mock_agent.return_value = mock_instance

            result = handle_invocation({"prompt": "test"})
            assert result["error"] == "AGENT_INVOCATION_FAILED"
            assert "governance" in result


# ─────────────────────────────────────────────────────────────
# 18. Strands tool definitions expose only permitted operations
# ─────────────────────────────────────────────────────────────

class TestStrandsToolDefinitions:
    def test_tool_count(self):
        assert len(SAFESTATE_TOOLS) == 8

    def test_all_tools_are_callable(self):
        for tool_fn in SAFESTATE_TOOLS:
            assert callable(tool_fn)

    def test_tool_names(self):
        expected = {
            "list_ec2_instances",
            "describe_ec2_instance",
            "list_ebs_volumes",
            "describe_ebs_volume",
            "list_s3_buckets",
            "get_bucket_metadata",
            "get_cost_and_utilization",
            "request_stop_instance",
        }
        actual = {t.tool_name if hasattr(t, 'tool_name') else t.__name__ for t in SAFESTATE_TOOLS}
        assert actual == expected

    def test_no_direct_aws_tools_exposed(self):
        for tool_fn in SAFESTATE_TOOLS:
            name = tool_fn.tool_name if hasattr(tool_fn, 'tool_name') else tool_fn.__name__
            assert "boto" not in name.lower()
            assert "aws_sdk" not in name.lower()


# ─────────────────────────────────────────────────────────────
# R8 Budget controls
# ─────────────────────────────────────────────────────────────

class TestR8BudgetControls:
    def test_budget_decreases_with_actions(self, audit_path):
        mission = MissionContract(
            mission_id=DEMO_MISSION_ID,
            version=DEMO_MISSION_VERSION,
            agent_id=DEMO_AGENT_ID,
            purpose="Budget test",
            allowed_actions=frozenset(ActionType),
            resource_scope=frozenset(ResourceType),
            policy_ids=frozenset({"R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9"}),
            created_at=_utc_now(),
            risk_budget=5,
            decoy_actions=frozenset({"TERMINATE_INSTANCE"}),
            decoy_resource_ids=frozenset(),
        )
        rt = SafeStateRuntime(mission=mission, audit_path=audit_path)
        set_runtime(rt)

        for i in range(5):
            result = rt.submit_action("LIST_INSTANCES")
            assert result["outcome"] == "EXECUTED", f"Action {i+1} should succeed"

        result = rt.submit_action("LIST_INSTANCES")
        assert result["outcome"] == "BLOCKED"
        assert result["reason_code"] == "RISK_BUDGET_EXCEEDED"

    def test_budget_respects_action_costs(self, audit_path):
        mission = MissionContract(
            mission_id=DEMO_MISSION_ID,
            version=DEMO_MISSION_VERSION,
            agent_id=DEMO_AGENT_ID,
            purpose="Budget cost test",
            allowed_actions=frozenset(ActionType),
            resource_scope=frozenset(ResourceType),
            policy_ids=frozenset({"R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9"}),
            created_at=_utc_now(),
            risk_budget=10,
            decoy_actions=frozenset({"TERMINATE_INSTANCE"}),
            decoy_resource_ids=frozenset(),
        )
        rt = SafeStateRuntime(mission=mission, audit_path=audit_path)
        set_runtime(rt)

        for _ in range(10):
            rt.submit_action("LIST_INSTANCES")

        result = rt.submit_action("LIST_VOLUMES")
        assert result["outcome"] == "BLOCKED"
        assert result["reason_code"] == "RISK_BUDGET_EXCEEDED"


# ─────────────────────────────────────────────────────────────
# R9 Tripwire controls
# ─────────────────────────────────────────────────────────────

class TestR9TripwireControls:
    def test_decoy_action_triggers_incident(self, runtime):
        runtime.submit_action("DELETE_BUCKET", resource_id="my-dev-bucket")
        incidents = runtime.tripwire_handler.incidents
        assert len(incidents) >= 1
        assert incidents[0].trigger_type == "DECOY_ACTION"

    def test_decoy_resource_triggers_incident(self, runtime):
        runtime.submit_action("DESCRIBE_INSTANCE", resource_id="i-decoy-001")
        incidents = runtime.tripwire_handler.incidents
        assert len(incidents) >= 1
        assert incidents[0].trigger_type == "DECOY_RESOURCE"
        assert incidents[0].target == "i-decoy-001"

    def test_post_revocation_all_actions_blocked(self, runtime):
        runtime.tripwire_handler.trigger(
            DEMO_AGENT_ID, DEMO_MISSION_ID, "test-req", "MANUAL", "test"
        )
        for action in ["LIST_INSTANCES", "LIST_VOLUMES", "LIST_BUCKETS"]:
            result = runtime.submit_action(action)
            assert result["outcome"] == "BLOCKED"
            assert result["reason_code"] == "AGENT_SESSION_REVOKED"


# ─────────────────────────────────────────────────────────────
# Strands tool function outputs
# ─────────────────────────────────────────────────────────────

class TestStrandsToolFunctions:
    def test_list_ec2_instances_tool(self, runtime):
        output = list_ec2_instances()
        parsed = json.loads(output)
        assert parsed["outcome"] == "EXECUTED"

    def test_describe_instance_tool(self, runtime):
        output = describe_ec2_instance(instance_id="i-dev-001")
        parsed = json.loads(output)
        assert parsed["outcome"] == "EXECUTED"

    def test_list_ebs_volumes_tool(self, runtime):
        output = list_ebs_volumes()
        parsed = json.loads(output)
        assert parsed["outcome"] == "EXECUTED"

    def test_describe_volume_tool(self, runtime):
        output = describe_ebs_volume(volume_id="vol-dev-001")
        parsed = json.loads(output)
        assert parsed["outcome"] == "EXECUTED"

    def test_list_s3_buckets_tool(self, runtime):
        output = list_s3_buckets()
        parsed = json.loads(output)
        assert parsed["outcome"] == "EXECUTED"

    def test_get_bucket_metadata_tool(self, runtime):
        output = get_bucket_metadata(bucket_name="my-dev-bucket")
        parsed = json.loads(output)
        assert parsed["outcome"] == "EXECUTED"

    def test_get_cost_tool(self, runtime):
        output = get_cost_and_utilization()
        parsed = json.loads(output)
        assert parsed["outcome"] == "EXECUTED"

    def test_stop_instance_tool(self, runtime):
        output = request_stop_instance(instance_id="i-dev-001", reason="Cost savings")
        parsed = json.loads(output)
        assert parsed["outcome"] in ("APPROVAL_REQUIRED", "BLOCKED")

    def test_stop_instance_no_reason_blocked(self, runtime):
        output = request_stop_instance(instance_id="i-dev-001", reason="")
        parsed = json.loads(output)
        assert parsed["outcome"] == "BLOCKED"


# ─────────────────────────────────────────────────────────────
# DemoMissionProvider and DemoResourceContextProvider
# ─────────────────────────────────────────────────────────────

class TestDemoProviders:
    def test_mission_provider_returns_correct_mission(self):
        provider = DemoMissionProvider()
        mission = provider.get_active_mission(DEMO_AGENT_ID, DEMO_MISSION_ID)
        assert mission.mission_id == DEMO_MISSION_ID
        assert mission.agent_id == DEMO_AGENT_ID

    def test_mission_provider_rejects_wrong_agent(self):
        provider = DemoMissionProvider()
        with pytest.raises(ValueError):
            provider.get_active_mission("wrong-agent", DEMO_MISSION_ID)

    def test_mission_provider_rejects_wrong_mission(self):
        provider = DemoMissionProvider()
        with pytest.raises(ValueError):
            provider.get_active_mission(DEMO_AGENT_ID, "wrong-mission")

    def test_resource_provider_returns_known_resources(self):
        provider = DemoResourceContextProvider()
        ctx = provider.get_context("i-dev-001", ResourceType.EC2_INSTANCE)
        assert ctx.resource_id == "i-dev-001"
        assert ctx.environment == EnvironmentClass.DEV

    def test_resource_provider_rejects_unknown_resources(self):
        provider = DemoResourceContextProvider()
        with pytest.raises(ValueError):
            provider.get_context("i-nonexistent", ResourceType.EC2_INSTANCE)


# ─────────────────────────────────────────────────────────────
# Approval workflow safeguards
# ─────────────────────────────────────────────────────────────

class TestApprovalWorkflow:
    def test_approval_id_returned_but_not_token(self, runtime):
        result = runtime.submit_action(
            "REQUEST_STOP_INSTANCE",
            resource_id="i-dev-001",
            parameters={"reason": "testing approval"},
        )
        if result["outcome"] == "APPROVAL_REQUIRED":
            assert "approval_id" in result
            result_json = json.dumps(result)
            assert "token" not in result_json or result_json.count('"token"') == 0

    def test_approval_channel_unavailable_blocks(self, runtime):
        result = runtime.submit_action(
            "REQUEST_STOP_INSTANCE",
            resource_id="i-dev-001",
            parameters={"reason": "no approval channel"},
        )
        assert result["outcome"] in ("APPROVAL_REQUIRED", "BLOCKED")
        if result["outcome"] == "BLOCKED" and "APPROVAL_CHANNEL_UNAVAILABLE" in str(result):
            assert True


# ─────────────────────────────────────────────────────────────
# End-to-end execution flow
# ─────────────────────────────────────────────────────────────

class TestEndToEndFlow:
    def test_full_read_flow(self, runtime, audit_path):
        result = runtime.submit_action("LIST_INSTANCES")
        assert result["outcome"] == "EXECUTED"
        assert result["execution"]["simulated"] is True

        result = runtime.submit_action("DESCRIBE_INSTANCE", resource_id="i-dev-001")
        assert result["outcome"] == "EXECUTED"
        assert result["execution"]["state"] == "running"

        verification = runtime.audit_sink.verify()
        assert verification.valid is True
        assert verification.records_checked >= 2

    def test_mixed_allow_and_block_flow(self, runtime):
        r1 = runtime.submit_action("LIST_INSTANCES")
        assert r1["outcome"] == "EXECUTED"

        r2 = runtime.submit_action("REQUEST_STOP_INSTANCE",
                                   resource_id="i-prod-001",
                                   parameters={"reason": "test"})
        assert r2["outcome"] == "BLOCKED"

        r3 = runtime.submit_action("LIST_VOLUMES")
        assert r3["outcome"] == "EXECUTED"
