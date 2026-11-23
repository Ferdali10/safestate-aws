"""Fail-closed orchestration for the framework-independent SafeState core."""
from __future__ import annotations

from dataclasses import replace
from typing import Any, Mapping

from .actions import DEFAULT_RISK_COSTS, classify_unknown_action, normalize_action_name
from .interfaces import (
    Clock,
    IdGenerator,
    MissionProvider,
    PolicyEngine,
    ResourceContextProvider,
    RiskBudgetStore,
    TripwireHandler,
)
from .models import (
    ActionRequest,
    ActionType,
    Decision,
    DecisionStatus,
    EnvironmentClass,
    MissionContract,
    ResourceContext,
    ResourceType,
)
from .validation import (
    UnknownActionError,
    ValidationError,
    parse_request,
    validate_request,
)

SERVICE_POLICY_VERSION = "2026-11-22.1"
DEFAULT_ACTION_RISK_COSTS = DEFAULT_RISK_COSTS


class DefaultDecisionService:
    """Validate requests, load trusted context, then delegate to policy."""

    def __init__(
        self,
        mission_provider: MissionProvider,
        resource_provider: ResourceContextProvider,
        policy_engine: PolicyEngine,
        clock: Clock,
        id_generator: IdGenerator,
        policy_version: str = SERVICE_POLICY_VERSION,
        risk_budget_store: RiskBudgetStore | None = None,
        tripwire_handler: TripwireHandler | None = None,
        risk_costs: Mapping[ActionType, int] | None = None,
    ) -> None:
        self._missions = mission_provider
        self._resources = resource_provider
        self._policy = policy_engine
        self._clock = clock
        self._new_id = id_generator
        self._policy_version = policy_version
        self._risk_budget = risk_budget_store
        self._tripwires = tripwire_handler
        self._risk_costs = dict(
            DEFAULT_ACTION_RISK_COSTS if risk_costs is None else risk_costs
        )
        if any(
            not isinstance(action, ActionType)
            or isinstance(cost, bool)
            or not isinstance(cost, int)
            or cost <= 0
            for action, cost in self._risk_costs.items()
        ):
            raise ValueError("risk costs must map ActionType values to positive integers")

    def decide_raw(self, payload: Mapping[str, Any]) -> Decision:
        """Parse untrusted input; invalid requests return a BLOCK decision."""
        request_id = self._safe_request_id(payload)
        try:
            request = parse_request(payload, now=self._clock())
        except UnknownActionError as exc:
            tripwire_decision = self._check_decoy_action(
                payload, exc.raw_action, request_id
            )
            if tripwire_decision is not None:
                return tripwire_decision
            rule_id, reason_code = classify_unknown_action(exc.raw_action)
            return self._blocked(
                request_id, rule_id, reason_code,
                "The requested action is not exposed by this mission-aware service.",
            )
        except (ValidationError, TypeError, ValueError):
            return self._blocked(
                request_id, "R7", "REQUEST_VALIDATION_FAILED",
                "The request is invalid and was rejected before trusted context was loaded.",
            )
        return self.decide(request)

    def decide(self, request: ActionRequest) -> Decision:
        """Validate typed input and run the trusted decision pipeline."""
        request_id = getattr(request, "request_id", "unavailable")
        try:
            validate_request(request)
        except UnknownActionError as exc:
            rule_id, reason_code = classify_unknown_action(exc.raw_action)
            return self._blocked(
                request_id, rule_id, reason_code,
                "The requested action is not exposed by this mission-aware service.",
            )
        except (ValidationError, TypeError, ValueError):
            return self._blocked(
                request_id, "R7", "REQUEST_VALIDATION_FAILED",
                "The request is invalid and was rejected before trusted context was loaded.",
            )

        try:
            mission = self._missions.get_active_mission(
                request.agent_id, request.mission_id
            )
            if not isinstance(mission, MissionContract):
                return self._blocked(
                    request_id, "R7", "MISSION_CONTEXT_INVALID",
                    "The trusted mission provider returned an invalid contract.",
                )
            if (
                not isinstance(mission.version, str)
                or not mission.version
                or not isinstance(mission.agent_id, str)
                or not mission.agent_id
                or not isinstance(mission.mission_id, str)
                or not mission.mission_id
                or not isinstance(mission.allowed_actions, frozenset)
                or any(not isinstance(action, ActionType) for action in mission.allowed_actions)
                or not isinstance(mission.resource_scope, frozenset)
                or any(not isinstance(item, ResourceType) for item in mission.resource_scope)
                or not isinstance(mission.policy_ids, frozenset)
                or any(not isinstance(item, str) for item in mission.policy_ids)
                or not isinstance(mission.decoy_actions, frozenset)
                or any(not isinstance(item, str) for item in mission.decoy_actions)
                or not isinstance(mission.decoy_resource_ids, frozenset)
                or any(not isinstance(item, str) for item in mission.decoy_resource_ids)
                or (
                    mission.risk_budget is not None
                    and (
                        isinstance(mission.risk_budget, bool)
                        or not isinstance(mission.risk_budget, int)
                        or mission.risk_budget < 0
                    )
                )
            ):
                return self._blocked(
                    request_id, "R7", "MISSION_CONTEXT_INVALID",
                    "The trusted mission contract contains invalid fields.",
                )
            if (
                mission.agent_id != request.agent_id
                or mission.mission_id != request.mission_id
                or mission.version != request.mission_version
            ):
                return self._blocked(
                    request_id, "R7", "MISSION_MISMATCH",
                    "The request does not match the active trusted mission.",
                )

            if mission.risk_budget is not None and "R8" not in mission.policy_ids:
                return self._blocked(
                    request_id, "R7", "POLICY_SET_INCOMPLETE",
                    "A risk budget is configured but R8 is not enabled in the trusted mission.",
                )
            if (
                (mission.decoy_actions or mission.decoy_resource_ids)
                and "R9" not in mission.policy_ids
            ):
                return self._blocked(
                    request_id, "R7", "POLICY_SET_INCOMPLETE",
                    "Tripwires are configured but R9 is not enabled in the trusted mission.",
                )

            if request.resource_id in mission.decoy_resource_ids:
                return self._tripwire_block(
                    request.agent_id, request.mission_id, request_id,
                    "DECOY_RESOURCE", request.resource_id,
                )

            resource = self._resources.get_context(
                request.resource_id, request.resource_type
            )
            if not isinstance(resource, ResourceContext):
                return self._blocked(
                    request_id, "R7", "RESOURCE_CONTEXT_INVALID",
                    "The trusted inventory returned an invalid resource context.",
                )
            if (
                resource.resource_id != request.resource_id
                or resource.resource_type is not request.resource_type
                or not isinstance(resource.environment, EnvironmentClass)
                or not isinstance(resource.classification_verified, bool)
                or not isinstance(resource.classification_source, str)
                or not resource.classification_source.strip()
                or not isinstance(resource.metadata, dict)
                or any(
                    not isinstance(key, str) or not isinstance(value, str)
                    for key, value in resource.metadata.items()
                )
            ):
                return self._blocked(
                    request_id, "R7", "RESOURCE_CONTEXT_MISMATCH",
                    "The trusted resource context does not match the request.",
                )

            decision = self._policy.evaluate(request, mission, resource)
            if (
                not isinstance(decision, Decision)
                or decision.request_id != request.request_id
                or not isinstance(decision.status, DecisionStatus)
                or decision.approval_required
                is not (decision.status is DecisionStatus.REQUIRE_APPROVAL)
                or not decision.reason_code
                or not decision.rule_id
            ):
                return self._blocked(
                    request_id, "R7", "POLICY_ENGINE_INVALID_RESULT",
                    "The policy engine returned an invalid decision.",
                )

            if (
                decision.status is not DecisionStatus.BLOCK
                and mission.risk_budget is not None
            ):
                if self._risk_budget is None:
                    return self._blocked(
                        request_id, "R7", "RISK_BUDGET_STORE_UNAVAILABLE",
                        "A mission risk budget is configured but no trusted budget store is available.",
                    )
                points = self._risk_costs.get(request.action)
                if points is None:
                    return self._blocked(
                        request_id, "R7", "RISK_COST_UNCONFIGURED",
                        "No risk cost is configured for this action.",
                    )
                mission_key = (
                    f"{mission.agent_id}:{mission.mission_id}:{mission.version}"
                )
                try:
                    reserved = self._risk_budget.try_reserve(
                        mission_key, points, mission.risk_budget
                    )
                    if not isinstance(reserved, bool):
                        raise TypeError("risk budget store must return bool")
                except Exception:  # noqa: BLE001 - budget store errors fail closed
                    return self._blocked(
                        request_id, "R7", "RISK_BUDGET_STORE_ERROR",
                        "The risk budget could not be checked safely; the request is blocked.",
                    )
                if not reserved:
                    return replace(
                        decision,
                        status=DecisionStatus.REQUIRE_APPROVAL,
                        rule_id="R8",
                        reason_code="RISK_BUDGET_EXCEEDED",
                        reason=(
                            "The remaining mission risk budget cannot cover this "
                            "action; human approval is required."
                        ),
                        approval_required=True,
                    )
            return decision
        except Exception:  # noqa: BLE001 - provider or policy faults fail closed
            return self._blocked(
                request_id, "R7", "DECISION_PIPELINE_ERROR",
                "The decision pipeline failed; the request is blocked.",
            )

    def _check_decoy_action(
        self, payload: object, raw_action: object, request_id: str
    ) -> Decision | None:
        if not isinstance(payload, Mapping):
            return None
        agent_id = payload.get("agent_id")
        mission_id = payload.get("mission_id")
        if (
            not isinstance(agent_id, str) or not agent_id
            or not isinstance(mission_id, str) or not mission_id
        ):
            return None
        try:
            mission = self._missions.get_active_mission(agent_id, mission_id)
        except Exception:  # noqa: BLE001 - normal validation path fails closed
            return None
        if (
            not isinstance(raw_action, str)
            or not isinstance(mission, MissionContract)
            or mission.agent_id != agent_id
            or mission.mission_id != mission_id
            or mission.version != payload.get("mission_version")
            or not isinstance(mission.decoy_actions, frozenset)
        ):
            return None
        try:
            normalized_action = normalize_action_name(raw_action)
            decoys = {
                normalize_action_name(item)
                for item in mission.decoy_actions
                if isinstance(item, str)
            }
        except TypeError:
            return None
        if normalized_action not in decoys:
            return None
        if "R9" not in mission.policy_ids:
            return self._blocked(
                request_id, "R7", "POLICY_SET_INCOMPLETE",
                "A decoy action is configured but R9 is not enabled in the trusted mission.",
            )
        return self._tripwire_block(
            agent_id, mission_id, request_id, "DECOY_ACTION", raw_action
        )

    def _tripwire_block(
        self,
        agent_id: str,
        mission_id: str,
        request_id: str,
        trigger_type: str,
        target: str,
    ) -> Decision:
        if self._tripwires is None:
            return self._blocked(
                request_id, "R7", "TRIPWIRE_HANDLER_UNAVAILABLE",
                "A decoy was targeted but no trusted tripwire handler is configured; the request is blocked.",
            )
        try:
            self._tripwires.trigger(
                agent_id, mission_id, request_id, trigger_type, target
            )
        except Exception:  # noqa: BLE001 - revocation/incident failure fails closed
            return self._blocked(
                request_id, "R7", "TRIPWIRE_HANDLER_FAILED",
                "The tripwire could not confirm incident recording and session revocation; the request is blocked.",
            )
        return self._blocked(
            request_id, "R9", "TRIPWIRE_TRIGGERED",
            "A mission decoy was targeted. The request is blocked and the agent session was revoked.",
        )

    def _blocked(
        self, request_id: str, rule_id: str, reason_code: str, reason: str
    ) -> Decision:
        return Decision(
            decision_id=self._new_id(),
            request_id=(
                request_id
                if isinstance(request_id, str) and request_id
                else "unavailable"
            ),
            status=DecisionStatus.BLOCK,
            rule_id=rule_id,
            reason_code=reason_code,
            reason=reason,
            policy_version=self._policy_version,
            evaluated_at=self._clock(),
            approval_required=False,
        )

    @staticmethod
    def _safe_request_id(payload: object) -> str:
        if isinstance(payload, Mapping):
            value = payload.get("request_id", "unavailable")
            if isinstance(value, str) and value.strip():
                return value
        return "unavailable"
