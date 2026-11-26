"""SafeState adapter: trusted bridge between Strands tools and the SafeState Core.

This module owns all server-controlled identity, timestamps, and request IDs.
Nothing from the LLM is trusted for identity, environment, or authorization.
"""
from __future__ import annotations

import os
import tempfile
import uuid
from datetime import datetime, timezone
from typing import Any, Mapping

from safestate_core import (
    ActionType,
    ApprovalService,
    AuditedDecisionService,
    DefaultDecisionService,
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
    UnknownActionError,
    ValidationError,
    parse_request,
)
from safestate_core.actions import ACTION_RESOURCE_TYPE, COLLECTION_ACTIONS, WILDCARD_RESOURCE_ID
from safestate_core.policy import DeterministicPolicyEngine
from safestate_core.recovery import InMemoryExecutionJournal


def _utc_now() -> datetime:
    return datetime.now(timezone.utc)


def _new_id() -> str:
    return str(uuid.uuid4())


DEMO_AGENT_ID = "safestate-strands-agent"
DEMO_MISSION_ID = "cost-analysis-demo"
DEMO_MISSION_VERSION = "1"
DEMO_POLICY_VERSION = "2026-11-22.1"

DEMO_MISSION = MissionContract(
    mission_id=DEMO_MISSION_ID,
    version=DEMO_MISSION_VERSION,
    agent_id=DEMO_AGENT_ID,
    purpose="Cost analysis and infrastructure read access with governed stop requests",
    allowed_actions=frozenset(ActionType),
    resource_scope=frozenset(ResourceType),
    policy_ids=frozenset({"R1", "R2", "R3", "R4", "R5", "R6", "R7", "R8", "R9"}),
    created_at=_utc_now(),
    risk_budget=100,
    decoy_actions=frozenset({"TERMINATE_INSTANCE", "DELETE_BUCKET"}),
    decoy_resource_ids=frozenset({"i-decoy-001"}),
)

DEMO_RESOURCES: dict[tuple[str, ResourceType], ResourceContext] = {
    ("*", ResourceType.EC2_INSTANCE): ResourceContext(
        resource_id="*",
        resource_type=ResourceType.EC2_INSTANCE,
        environment=EnvironmentClass.DEV,
        classification_source="demo-inventory",
        classification_verified=True,
        metadata={},
    ),
    ("*", ResourceType.EBS_VOLUME): ResourceContext(
        resource_id="*",
        resource_type=ResourceType.EBS_VOLUME,
        environment=EnvironmentClass.DEV,
        classification_source="demo-inventory",
        classification_verified=True,
        metadata={},
    ),
    ("*", ResourceType.S3_BUCKET): ResourceContext(
        resource_id="*",
        resource_type=ResourceType.S3_BUCKET,
        environment=EnvironmentClass.DEV,
        classification_source="demo-inventory",
        classification_verified=True,
        metadata={},
    ),
    ("*", ResourceType.COST_REPORT): ResourceContext(
        resource_id="*",
        resource_type=ResourceType.COST_REPORT,
        environment=EnvironmentClass.DEV,
        classification_source="demo-inventory",
        classification_verified=True,
        metadata={},
    ),
    ("i-dev-001", ResourceType.EC2_INSTANCE): ResourceContext(
        resource_id="i-dev-001",
        resource_type=ResourceType.EC2_INSTANCE,
        environment=EnvironmentClass.DEV,
        classification_source="demo-inventory",
        classification_verified=True,
        metadata={"name": "dev-web-server"},
    ),
    ("i-test-001", ResourceType.EC2_INSTANCE): ResourceContext(
        resource_id="i-test-001",
        resource_type=ResourceType.EC2_INSTANCE,
        environment=EnvironmentClass.TEST,
        classification_source="demo-inventory",
        classification_verified=True,
        metadata={"name": "test-api-server"},
    ),
    ("i-prod-001", ResourceType.EC2_INSTANCE): ResourceContext(
        resource_id="i-prod-001",
        resource_type=ResourceType.EC2_INSTANCE,
        environment=EnvironmentClass.PROD,
        classification_source="demo-inventory",
        classification_verified=True,
        metadata={"name": "prod-database"},
    ),
    ("vol-dev-001", ResourceType.EBS_VOLUME): ResourceContext(
        resource_id="vol-dev-001",
        resource_type=ResourceType.EBS_VOLUME,
        environment=EnvironmentClass.DEV,
        classification_source="demo-inventory",
        classification_verified=True,
        metadata={"size_gb": "100"},
    ),
    ("vol-prod-001", ResourceType.EBS_VOLUME): ResourceContext(
        resource_id="vol-prod-001",
        resource_type=ResourceType.EBS_VOLUME,
        environment=EnvironmentClass.PROD,
        classification_source="demo-inventory",
        classification_verified=True,
        metadata={"size_gb": "500"},
    ),
    ("my-dev-bucket", ResourceType.S3_BUCKET): ResourceContext(
        resource_id="my-dev-bucket",
        resource_type=ResourceType.S3_BUCKET,
        environment=EnvironmentClass.DEV,
        classification_source="demo-inventory",
        classification_verified=True,
        metadata={"region": "us-east-1"},
    ),
    ("my-prod-bucket", ResourceType.S3_BUCKET): ResourceContext(
        resource_id="my-prod-bucket",
        resource_type=ResourceType.S3_BUCKET,
        environment=EnvironmentClass.PROD,
        classification_source="demo-inventory",
        classification_verified=True,
        metadata={"region": "us-east-1"},
    ),
}


class DemoMissionProvider:
    """Returns a fixed, server-controlled mission. Never trusts agent-supplied identity."""

    def __init__(self, mission: MissionContract | None = None) -> None:
        self._mission = mission or DEMO_MISSION

    def get_active_mission(self, agent_id: str, mission_id: str) -> MissionContract:
        if agent_id != self._mission.agent_id or mission_id != self._mission.mission_id:
            raise ValueError("no active mission for this agent/mission pair")
        return self._mission


class DemoResourceContextProvider:
    """Returns resource contexts from a trusted server-side inventory."""

    def __init__(self, resources: dict[tuple[str, ResourceType], ResourceContext] | None = None) -> None:
        self._resources = resources if resources is not None else DEMO_RESOURCES

    def get_context(self, resource_id: str, resource_type: ResourceType) -> ResourceContext:
        key = (resource_id, resource_type)
        ctx = self._resources.get(key)
        if ctx is not None:
            return ctx
        raise ValueError(f"resource {resource_id} ({resource_type.value}) not in trusted inventory")


class SafeStateRuntime:
    """Wires up the full SafeState Core stack for the demo agent."""

    def __init__(
        self,
        mission: MissionContract | None = None,
        resources: dict[tuple[str, ResourceType], ResourceContext] | None = None,
        audit_path: str | None = None,
    ) -> None:
        self.mission_provider = DemoMissionProvider(mission)
        self.resource_provider = DemoResourceContextProvider(resources)
        self.risk_budget_store = InMemoryRiskBudgetStore()
        self.tripwire_handler = InMemoryTripwireHandler(id_generator=_new_id)
        self.policy_engine = DeterministicPolicyEngine(
            clock=_utc_now, id_generator=_new_id, policy_version=DEMO_POLICY_VERSION,
        )
        self.decision_service = DefaultDecisionService(
            mission_provider=self.mission_provider,
            resource_provider=self.resource_provider,
            policy_engine=self.policy_engine,
            clock=_utc_now,
            id_generator=_new_id,
            policy_version=DEMO_POLICY_VERSION,
            risk_budget_store=self.risk_budget_store,
            tripwire_handler=self.tripwire_handler,
        )
        if audit_path is None:
            audit_path = os.path.join(tempfile.gettempdir(), "safestate_audit.jsonl")
        self.audit_sink = JsonlAuditSink(audit_path)
        self.audited_decision_service = AuditedDecisionService(
            decision_service=self.decision_service,
            audit_sink=self.audit_sink,
            id_generator=_new_id,
        )
        self.approval_store = InMemoryApprovalStore()
        self.approval_service = ApprovalService(
            store=self.approval_store,
            clock=_utc_now,
            id_generator=_new_id,
            risk_budget_store=self.risk_budget_store,
        )
        self.executor = SimulatedAWSExecutor()
        self.execution_journal = InMemoryExecutionJournal()
        self.gateway = ExecutionGateway(
            decision_service=self.audited_decision_service,
            approval_service=self.approval_service,
            executor=self.executor,
            risk_budget_store=self.risk_budget_store,
            execution_journal=self.execution_journal,
            clock=_utc_now,
            expose_approval_credential=False,
        )
        self._mission = mission or DEMO_MISSION

    def submit_action(
        self,
        action: str,
        resource_id: str | None = None,
        parameters: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        """Build a trusted request from tool arguments and submit to the gateway.

        Identity, mission, timestamps, and request IDs are all server-controlled.
        Only action, resource_id, and parameters come from the tool (LLM).
        """
        try:
            action_type = ActionType(action)
        except ValueError:
            return self._handle_unknown_action(action, resource_id, parameters)

        resource_type = ACTION_RESOURCE_TYPE[action_type]
        if action_type in COLLECTION_ACTIONS:
            effective_resource_id = WILDCARD_RESOURCE_ID
        else:
            if not resource_id:
                return {"outcome": "BLOCKED", "error": "resource_id is required for this action"}
            effective_resource_id = resource_id

        payload: dict[str, Any] = {
            "request_id": _new_id(),
            "agent_id": self._mission.agent_id,
            "mission_id": self._mission.mission_id,
            "mission_version": self._mission.version,
            "action": action_type.value,
            "resource_id": effective_resource_id,
            "resource_type": resource_type.value,
            "parameters": parameters or {},
        }

        try:
            request = parse_request(payload, now=_utc_now())
        except (ValidationError, UnknownActionError) as exc:
            return {"outcome": "BLOCKED", "error": str(exc), "rule": getattr(exc, "code", "VALIDATION")}

        result = self.gateway.submit(request)
        return self._sanitize_result(result)

    def _handle_unknown_action(
        self,
        action: str,
        resource_id: str | None,
        parameters: dict[str, Any] | None,
    ) -> dict[str, Any]:
        """Route unknown actions through decide_raw for proper R4/R5/R6/R9 classification."""
        payload: dict[str, Any] = {
            "request_id": _new_id(),
            "agent_id": self._mission.agent_id,
            "mission_id": self._mission.mission_id,
            "mission_version": self._mission.version,
            "action": action,
            "resource_id": resource_id or "*",
            "resource_type": "EC2_INSTANCE",
            "parameters": parameters or {},
        }
        decision = self.audited_decision_service.decide_raw(payload)
        return {
            "outcome": "BLOCKED",
            "decision_id": decision.decision_id,
            "status": decision.status.value,
            "rule": decision.rule_id,
            "reason_code": decision.reason_code,
            "reason": decision.reason,
        }

    @staticmethod
    def _sanitize_result(result: GatewayResult) -> dict[str, Any]:
        """Return only safe fields. Never expose approval credentials."""
        sanitized: dict[str, Any] = {
            "outcome": result.outcome,
            "decision_id": result.decision.decision_id,
            "status": result.decision.status.value,
            "rule": result.decision.rule_id,
            "reason_code": result.decision.reason_code,
            "reason": result.decision.reason,
        }
        if result.execution is not None:
            sanitized["execution"] = dict(result.execution)
        if result.error_code is not None:
            sanitized["error_code"] = result.error_code
        if result.approval_id is not None:
            sanitized["approval_id"] = result.approval_id
            sanitized["message"] = (
                "This action requires human approval. "
                "An approval request has been created. "
                "A human operator must approve it through a secure channel."
            )
        return sanitized
