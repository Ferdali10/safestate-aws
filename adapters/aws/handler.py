"""Fail-closed AWS Lambda adapter for an AgentCore Gateway target.

The adapter contains no policy logic. Trusted identity must be supplied by an
injected resolver that validates an authenticated Gateway context; tool input
fields are never an identity source.
"""
from __future__ import annotations

from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Callable, Mapping, Protocol
from uuid import uuid4

from safestate_core.execution import ExecutionGateway, GatewayResult
from safestate_core.models import Decision, DecisionStatus
from safestate_core.service import DefaultDecisionService
from safestate_core.validation import UnknownActionError, ValidationError, parse_request


@dataclass(frozen=True, slots=True)
class TrustedRequestContext:
    """Authenticated agent and assigned mission binding for one invocation."""

    agent_id: str
    mission_id: str
    mission_version: str


class TrustedIdentityResolver(Protocol):
    """Resolve trusted identity and mission binding from Lambda context.

    The event is deliberately not passed to the resolver: tool arguments must
    not select the authenticated agent or its assigned mission. Lambda context
    routing metadata is not inherently an authenticated identity either, so the
    injected implementation must validate a deployment-specific trusted source.
    """

    def resolve(self, context: Any) -> TrustedRequestContext: ...


class LambdaHandler:
    """Translate Gateway events into validated Core requests."""

    def __init__(
        self,
        gateway: ExecutionGateway,
        decision_service: DefaultDecisionService,
        identity_resolver: TrustedIdentityResolver,
        clock: Callable[[], datetime] | None = None,
        id_generator: Callable[[], str] | None = None,
    ) -> None:
        self._gateway = gateway
        self._decisions = decision_service
        self._identity = identity_resolver
        self._clock = clock or (lambda: datetime.now(timezone.utc))
        self._new_id = id_generator or (lambda: str(uuid4()))

    def __call__(self, event: Mapping[str, Any], context: Any = None) -> dict[str, Any]:
        if not isinstance(event, Mapping):
            return self._invalid("INVALID_EVENT", "Gateway event must be an object.")

        try:
            if self._identity is None:
                raise ValueError("trusted context resolver is unavailable")
            trusted = self._identity.resolve(context)
            if (
                not isinstance(trusted, TrustedRequestContext)
                or not isinstance(trusted.agent_id, str)
                or not trusted.agent_id.strip()
                or not isinstance(trusted.mission_id, str)
                or not trusted.mission_id.strip()
                or not isinstance(trusted.mission_version, str)
                or not trusted.mission_version.strip()
            ):
                raise ValueError("trusted identity or mission binding is unavailable")
        except Exception:  # noqa: BLE001 - identity failure must fail closed
            return self._invalid("TRUSTED_IDENTITY_UNAVAILABLE",
                                 "Authenticated request context could not be established.")

        # AgentCore Gateway Lambda targets pass the tool inputSchema properties
        # directly as the event map. Routing metadata is in Lambda context.
        # Identity and mission assignment come from the resolver only. Ignore
        # all caller-supplied identity, mission, request ID, and timestamp data.
        payload = dict(event)
        payload.pop("agent_id", None)
        payload.pop("mission_id", None)
        payload.pop("mission_version", None)
        payload.pop("request_id", None)
        payload.pop("requested_at", None)
        payload["agent_id"] = trusted.agent_id.strip()
        payload["mission_id"] = trusted.mission_id.strip()
        payload["mission_version"] = trusted.mission_version.strip()
        try:
            payload["request_id"] = self._new_id()
            now = self._clock()
        except Exception:  # noqa: BLE001 - server context faults fail closed
            return self._invalid("SERVER_REQUEST_CONTEXT_FAILED", "Server request context is unavailable.")
        if not isinstance(payload["request_id"], str) or not payload["request_id"].strip():
            return self._invalid("SERVER_REQUEST_CONTEXT_FAILED", "Server request context is unavailable.")
        if not isinstance(now, datetime) or now.tzinfo is None or now.utcoffset() is None:
            return self._invalid("SERVER_CLOCK_INVALID", "Server clock is not timezone-aware.")
        payload["requested_at"] = now.astimezone(timezone.utc)

        try:
            request = parse_request(payload, now=payload["requested_at"])
        except (UnknownActionError, ValidationError, TypeError, ValueError):
            # Keep the Core's raw-input path for malformed/unknown actions so
            # configured R9 decoy actions still trigger the existing tripwire.
            try:
                decision = self._decisions.decide_raw(payload)
            except Exception:  # noqa: BLE001 - raw decision faults fail closed
                return self._invalid("DECISION_SERVICE_FAILURE", "SafeState decision service failed closed.")
            try:
                return self._decision_response(decision)
            except Exception:  # noqa: BLE001 - malformed Core results fail closed
                return self._invalid("DECISION_SERVICE_FAILURE", "SafeState decision service failed closed.")

        try:
            result = self._gateway.submit(request)
        except Exception:  # noqa: BLE001 - adapter boundary fails closed
            return self._invalid("GATEWAY_FAILURE", "SafeState gateway failed closed.")
        try:
            return self._gateway_response(result)
        except Exception:  # noqa: BLE001 - malformed Gateway results fail closed
            return self._invalid("GATEWAY_RESPONSE_INVALID", "SafeState gateway failed closed.")

    @staticmethod
    def _decision_response(decision: Decision) -> dict[str, Any]:
        return {
            "outcome": "BLOCKED" if decision.status is DecisionStatus.BLOCK else decision.status.value,
            "decision_id": decision.decision_id,
            "request_id": decision.request_id,
            "decision": decision.status.value,
            "rule_id": decision.rule_id,
            "reason_code": decision.reason_code,
            "reason": decision.reason,
            "approval_required": decision.approval_required,
            "approval_id": None,
            "execution": None,
        }

    @classmethod
    def _gateway_response(cls, result: GatewayResult) -> dict[str, Any]:
        if not isinstance(result, GatewayResult) or not isinstance(result.decision, Decision):
            raise TypeError("gateway returned an invalid result")
        if result.execution is not None and not isinstance(result.execution, Mapping):
            raise TypeError("gateway returned an invalid execution result")
        decision = result.decision
        return {
            "outcome": result.outcome,
            "decision_id": decision.decision_id,
            "request_id": decision.request_id,
            "decision": decision.status.value,
            "rule_id": decision.rule_id,
            "reason_code": decision.reason_code,
            "reason": decision.reason,
            "approval_required": decision.approval_required,
            # The credential/token is intentionally never serialized.
            "approval_id": result.approval_id,
            "execution": dict(result.execution) if result.execution is not None else None,
            "error_code": result.error_code,
        }

    @staticmethod
    def _invalid(code: str, reason: str) -> dict[str, Any]:
        return {
            "outcome": "BLOCKED",
            "decision": DecisionStatus.BLOCK.value,
            "rule_id": "R7",
            "reason_code": code,
            "reason": reason,
            "approval_required": False,
            "approval_id": None,
            "execution": None,
        }


def build_handler(
    gateway: ExecutionGateway,
    decision_service: DefaultDecisionService,
    identity_resolver: TrustedIdentityResolver,
) -> LambdaHandler:
    """Explicit dependency-injection entry point for deployment wiring."""
    return LambdaHandler(gateway, decision_service, identity_resolver)


def lambda_handler(event: Mapping[str, Any], context: Any = None) -> dict[str, Any]:
    """Deployment entry point; intentionally unavailable until wired.

    Do not construct in-memory production dependencies implicitly. Deployment
    code must build the Core and inject an authenticated identity resolver.
    """
    return LambdaHandler._invalid(
        "HANDLER_NOT_CONFIGURED",
        "Deployment must configure SafeState dependencies before invocation.",
    )
