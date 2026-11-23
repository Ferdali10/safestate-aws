"""Fail-closed orchestration for the framework-independent SafeState core."""
from __future__ import annotations

from typing import Any, Mapping

from .actions import classify_unknown_action
from .interfaces import (
    Clock,
    IdGenerator,
    MissionProvider,
    PolicyEngine,
    ResourceContextProvider,
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


class DefaultDecisionService:
    """Validate requests, load trusted context, then delegate to the policy engine."""

    def __init__(
        self,
        mission_provider: MissionProvider,
        resource_provider: ResourceContextProvider,
        policy_engine: PolicyEngine,
        clock: Clock,
        id_generator: IdGenerator,
        policy_version: str = SERVICE_POLICY_VERSION,
    ) -> None:
        self._missions = mission_provider
        self._resources = resource_provider
        self._policy = policy_engine
        self._clock = clock
        self._new_id = id_generator
        self._policy_version = policy_version

    def decide_raw(self, payload: Mapping[str, Any]) -> Decision:
        """Parse an untrusted payload and return a decision without raising validation errors."""
        request_id = self._safe_request_id(payload)
        try:
            request = parse_request(payload, now=self._clock())
        except UnknownActionError as exc:
            rule_id, reason_code = classify_unknown_action(exc.raw_action)
            return self._blocked(
                request_id,
                rule_id,
                reason_code,
                "The requested action is not exposed by this mission-aware service.",
            )
        except (ValidationError, TypeError, ValueError):
            return self._blocked(
                request_id,
                "R7",
                "REQUEST_VALIDATION_FAILED",
                "The request is invalid and was rejected before trusted context was loaded.",
            )
        return self.decide(request)

    def decide(self, request: ActionRequest) -> Decision:
        """Validate a typed request and run the trusted decision pipeline."""
        request_id = getattr(request, "request_id", "unavailable")
        try:
            validate_request(request)
        except UnknownActionError as exc:
            rule_id, reason_code = classify_unknown_action(exc.raw_action)
            return self._blocked(
                request_id,
                rule_id,
                reason_code,
                "The requested action is not exposed by this mission-aware service.",
            )
        except (ValidationError, TypeError, ValueError):
            return self._blocked(
                request_id,
                "R7",
                "REQUEST_VALIDATION_FAILED",
                "The request is invalid and was rejected before trusted context was loaded.",
            )

        try:
            mission = self._missions.get_active_mission(
                request.agent_id, request.mission_id
            )
            if not isinstance(mission, MissionContract):
                return self._blocked(
                    request_id,
                    "R7",
                    "MISSION_CONTEXT_INVALID",
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
                or any(
                    not isinstance(action, ActionType)
                    for action in mission.allowed_actions
                )
                or not isinstance(mission.resource_scope, frozenset)
                or any(
                    not isinstance(item, ResourceType)
                    for item in mission.resource_scope
                )
                or not isinstance(mission.policy_ids, frozenset)
                or any(not isinstance(item, str) for item in mission.policy_ids)
            ):
                return self._blocked(
                    request_id,
                    "R7",
                    "MISSION_CONTEXT_INVALID",
                    "The trusted mission contract contains invalid fields.",
                )
            if (
                mission.agent_id != request.agent_id
                or mission.mission_id != request.mission_id
                or mission.version != request.mission_version
            ):
                return self._blocked(
                    request_id,
                    "R7",
                    "MISSION_MISMATCH",
                    "The request does not match the active trusted mission.",
                )

            resource = self._resources.get_context(
                request.resource_id, request.resource_type
            )
            if not isinstance(resource, ResourceContext):
                return self._blocked(
                    request_id,
                    "R7",
                    "RESOURCE_CONTEXT_INVALID",
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
                    request_id,
                    "R7",
                    "RESOURCE_CONTEXT_MISMATCH",
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
                    request_id,
                    "R7",
                    "POLICY_ENGINE_INVALID_RESULT",
                    "The policy engine returned an invalid decision.",
                )
            return decision
        except Exception:  # noqa: BLE001 - provider or policy faults must fail closed
            return self._blocked(
                request_id,
                "R7",
                "DECISION_PIPELINE_ERROR",
                "The decision pipeline failed; the request is blocked.",
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
