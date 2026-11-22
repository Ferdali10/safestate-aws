"""Deterministic policy engine for rules R1-R7.

Evaluation order is fixed and deny-first. The first matching rule decides, and a
later rule can never turn a BLOCK into an ALLOW or REQUIRE_APPROVAL:

1. R7  mission binding, policy set and resource-context integrity
2. R6  action and resource type must be inside the mission
3. R2  production resources are never modified
4. R3  stop requests need a verified dev/test environment and human approval
5. R1  approved reads inside the mission are allowed

R4 (destructive actions) and R5 (exfiltration, IAM changes) are enforced before
this engine: no corresponding ActionType exists, so such requests are blocked
when they are parsed (see actions.classify_unknown_action and service.py).

No LLM is involved. Identical inputs, clock and id generator give identical
decisions.
"""
from __future__ import annotations

from .actions import MUTATING_ACTIONS
from .interfaces import Clock, IdGenerator
from .models import (
    ActionRequest,
    Decision,
    DecisionStatus,
    EnvironmentClass,
    MissionContract,
    ResourceContext,
)

POLICY_VERSION = "2026-11-22.1"
REQUIRED_POLICY_IDS = frozenset({"R1", "R2", "R3", "R4", "R5", "R6", "R7"})


class DeterministicPolicyEngine:
    """Implements the PolicyEngine protocol for rules R1-R7."""

    def __init__(
        self,
        clock: Clock,
        id_generator: IdGenerator,
        policy_version: str = POLICY_VERSION,
    ) -> None:
        self._clock = clock
        self._new_id = id_generator
        self._policy_version = policy_version

    def evaluate(
        self,
        request: ActionRequest,
        mission: MissionContract,
        resource: ResourceContext,
    ) -> Decision:
        try:
            return self._evaluate(request, mission, resource)
        except Exception:  # noqa: BLE001 - any engine fault must fail closed (R7)
            return self.decision(
                request,
                DecisionStatus.BLOCK,
                "R7",
                "POLICY_ENGINE_ERROR",
                "The policy engine could not evaluate the request safely.",
            )

    def decision(
        self,
        request: ActionRequest,
        status: DecisionStatus,
        rule_id: str,
        reason_code: str,
        reason: str,
    ) -> Decision:
        """Build a Decision stamped with this engine's clock, ids and version."""
        return Decision(
            decision_id=self._new_id(),
            request_id=request.request_id,
            status=status,
            rule_id=rule_id,
            reason_code=reason_code,
            reason=reason,
            policy_version=self._policy_version,
            evaluated_at=self._clock(),
            approval_required=status is DecisionStatus.REQUIRE_APPROVAL,
        )

    def _evaluate(
        self,
        request: ActionRequest,
        mission: MissionContract,
        resource: ResourceContext,
    ) -> Decision:
        block = DecisionStatus.BLOCK

        # 1. R7: integrity of the mission binding and of the resource context.
        if (
            request.agent_id != mission.agent_id
            or request.mission_id != mission.mission_id
            or request.mission_version != mission.version
        ):
            return self.decision(
                request, block, "R7", "MISSION_MISMATCH",
                "The request does not match the active mission, agent or version.",
            )
        if not REQUIRED_POLICY_IDS <= mission.policy_ids:
            return self.decision(
                request, block, "R7", "POLICY_SET_INCOMPLETE",
                "The mission does not enable every required policy rule.",
            )
        if (
            resource.resource_id != request.resource_id
            or resource.resource_type is not request.resource_type
        ):
            return self.decision(
                request, block, "R7", "RESOURCE_CONTEXT_MISMATCH",
                "The trusted resource context does not match the requested resource.",
            )

        # 2. R6: stay inside the mission.
        if request.action not in mission.allowed_actions:
            return self.decision(
                request, block, "R6", "ACTION_NOT_IN_MISSION",
                "The action is outside the mission's allowed actions.",
            )
        if request.resource_type not in mission.resource_scope:
            return self.decision(
                request, block, "R6", "RESOURCE_OUT_OF_SCOPE",
                "The resource type is outside the mission's scope.",
            )

        # Reads: R1.
        if request.action not in MUTATING_ACTIONS:
            return self.decision(
                request, DecisionStatus.ALLOW, "R1", "READ_WITHIN_MISSION",
                "Read-only action inside the mission.",
            )

        # Mutating requests: R2 then R3.
        environment = resource.environment
        if environment is EnvironmentClass.PROD:
            return self.decision(
                request, block, "R2", "PRODUCTION_RESOURCE_PROTECTED",
                "Production resources are never modified, even with approval.",
            )
        if (
            environment is EnvironmentClass.UNKNOWN
            or not resource.classification_verified
        ):
            return self.decision(
                request, block, "R3", "ENVIRONMENT_UNVERIFIED",
                "The environment is unknown or unverified, so writes are blocked.",
            )
        if environment in (EnvironmentClass.DEV, EnvironmentClass.TEST):
            return self.decision(
                request, DecisionStatus.REQUIRE_APPROVAL, "R3",
                "STOP_REQUIRES_HUMAN_APPROVAL",
                "Stopping a dev or test instance needs explicit human approval.",
            )

        return self.decision(
            request, block, "R7", "UNHANDLED_ENVIRONMENT",
            "The environment classification is not handled; failing closed.",
        )
