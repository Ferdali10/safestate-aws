# AWS Lambda adapter

This adapter is a thin boundary around the SafeState Core. It does not contain
policy rules and does not execute AWS APIs itself.

## Event contract

The handler expects a mapping with an `input` object containing the Core
request fields: `mission_id`, `mission_version`, `action`, `resource_id`,
`resource_type`, and optional `parameters`.

The handler generates `request_id` and `requested_at` on the server. Any
agent-supplied `agent_id`, `request_id`, or `requested_at` is discarded.

## Trusted identity is deployment-specific

Production wiring MUST inject a `TrustedIdentityResolver` that validates an
authenticated identity from a trusted AgentCore Gateway context. The resolver
must not read identity from `event["input"]` or any other agent-controlled
tool argument. If identity cannot be verified, the handler blocks.

AgentCore context/header propagation must be explicitly configured and protected
against caller spoofing. This repository does not yet implement a concrete
AgentCore identity resolver. Do not treat this adapter as production-ready
until that resolver and its Gateway authentication configuration are reviewed.

## Dependency injection

Use `build_handler(gateway, decision_service, identity_resolver)` from a
deployment composition module. The module-level `lambda_handler` deliberately
fails closed until deployment wiring exists; it does not silently create
in-memory stores or an executor.

Valid requests go through `ExecutionGateway.submit()` exactly once. Malformed
or unknown actions go through `DefaultDecisionService.decide_raw()` so the
Core's existing validation and R9 decoy behavior remain authoritative.

Only the non-secret `approval_id` may be returned. Approval credentials and
tokens are never serialized to the agent.

## Current status

Local unit tests are authored but must be executed before this adapter is
considered validated. No AWS deployment or real AgentCore identity propagation
has been performed.
