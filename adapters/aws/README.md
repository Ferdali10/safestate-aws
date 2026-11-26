# AWS Lambda adapter

This is a local adapter around the existing SafeState Core. It contains no
policy rules and makes no AWS API calls. No deployed Gateway, Lambda function,
or live identity propagation has been configured or verified.

For the complete request flow, trust boundaries, response behavior, and audit
concurrency model, see the [Mission A1 adapter guide](../../docs/AGENTCORE_LAMBDA_ADAPTER.md).

## AgentCore Gateway Lambda event

AWS documents a Lambda target event as a map of the properties declared in the
tool `inputSchema`, passed directly as the event argument. The Lambda `context`
is a separate second argument. Its `client_context.custom` metadata can contain
routing values such as `bedrockAgentCoreGatewayId`,
`bedrockAgentCoreTargetId`, `bedrockAgentCoreToolName`, and request/message
identifiers. Those fields identify the route and invocation; they are not an
authenticated agent identity.

This handler therefore reads tool arguments from the flat event mapping. It
does not accept the former `{ "input": {...} }` wrapper as an alternate
contract. The tool schema should expose only `action`, `resource_id`,
`resource_type`, and optional `parameters`. Any `agent_id`, `mission_id`,
`mission_version`, `request_id`, or `requested_at` supplied in the event is
discarded. The adapter obtains agent and mission assignment from its trusted
resolver, generates the request ID, and sets the timestamp in UTC.

## Identity resolver contract

`TrustedIdentityResolver.resolve(context)` must return a `TrustedRequestContext`
containing `agent_id`, `mission_id`, and `mission_version` only after validating
the authenticated principal and its assigned mission against independently
trusted sources. The handler does not pass the raw event to the resolver and
does not infer identity or mission assignment from tool arguments, tool names,
Gateway routing metadata, or arbitrary propagated headers. A missing resolver,
invalid trusted context, or resolver error blocks before Core decision or
execution.

No concrete authenticated identity resolver is included. Production wiring
must explicitly choose and validate both an identity mechanism and the
principal-to-mission assignment. Gateway header
propagation is opt-in through target `metadataConfiguration` allowlists and
arrives in Lambda client context. Propagation alone does not establish trust:
the deployment must ensure the value was produced by a trusted authenticator or
interceptor, cannot be spoofed by the caller, and is cryptographically or
otherwise authoritatively validated by the resolver. The standard Gateway
routing metadata does not supply an agent ID. Do not treat this adapter as
authenticated until that wiring and its evidence are reviewed.

## Core flow and response

For a valid request, the handler builds a typed request and calls
`ExecutionGateway.submit()` once. It does not call `decide_raw()` first. Inputs
that cannot be parsed, including unknown actions, go through the existing
`DefaultDecisionService.decide_raw()` path so Core validation and configured
R9 tripwires remain authoritative. Unexpected raw-decision and gateway errors
are converted to controlled `BLOCK` responses.

Responses are built from an explicit set of fields. They may contain the
non-secret `approval_id`, but never serialize the `GatewayResult` or its
approval credential/token. The module-level `lambda_handler` remains
fail-closed until a deployment composition module injects the Core, Gateway,
and a verified identity resolver.

## Local tests and remaining work

Run from the repository root:

```bash
python -m pytest -q tests/unit/test_agentcore_handler.py
python -m pytest -q
python examples/local_stress_demo.py
git diff --check
```

Tests use local fakes and do not require AWS credentials or incur cloud costs.
Remaining work for a real integration includes a documented tool schema,
deployment composition, a verified identity source and resolver, explicit
Gateway authentication/propagation configuration, and validation in an AWS
account. None of those deployment steps is claimed complete here.
