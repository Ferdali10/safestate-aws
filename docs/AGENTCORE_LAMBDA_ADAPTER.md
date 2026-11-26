# Mission A1: AgentCore Gateway Lambda Adapter

## Status and scope

The repository contains a local, dependency-injected Lambda adapter for an
Amazon Bedrock AgentCore Gateway Lambda target. The adapter connects the
Gateway request contract to the existing SafeState Core and
`ExecutionGateway`; it does not implement a second policy engine.

This is an implementation milestone, not a deployed AWS integration. The
repository does not contain a configured Gateway, a deployed Lambda, a concrete
authenticated identity resolver, or evidence of live identity propagation.
No AWS resources or credentials are required for the local tests.

For the adapter's event details and local invocation commands, see
[`adapters/aws/README.md`](../adapters/aws/README.md). This page documents the
system boundary, trust assumptions, request lifecycle, and remaining deployment
work.

## Request path

```mermaid
sequenceDiagram
    participant A as Agent
    participant G as AgentCore Gateway
    participant L as LambdaHandler
    participant I as TrustedIdentityResolver
    participant C as SafeState Core
    participant X as ExecutionGateway

    A->>G: Invoke tool with tool arguments
    G->>L: Flat event and separate Lambda context
    L->>I: resolve(context)
    I-->>L: Verified agent and mission binding or failure
    alt Identity cannot be verified
        L-->>G: Controlled BLOCK response
    else Identity verified
        L->>L: Replace agent identity and generate request ID/time
        L->>C: Parse and validate request
        alt Valid ActionRequest
            L->>X: submit(request), exactly once
            X->>C: Decide through existing DecisionService
            X-->>L: GatewayResult
        else Unknown or malformed action
            L->>C: decide_raw(payload)
            C-->>L: Core BLOCK (including configured R9 handling)
        end
        L-->>G: Explicit response fields; no approval credential
    end
```

The adapter performs request normalization and response shaping. Mission rules,
resource checks, risk-budget decisions, approvals, tripwires, and execution
authorization remain in their existing Core services.

## Gateway event and Lambda context

For a Lambda target, AgentCore Gateway sends the tool's `inputSchema` properties
as the Lambda event map. Lambda context is a separate second argument. Gateway
routing metadata, when available, is exposed through the Lambda client context;
it identifies the invocation or route, not an authenticated SafeState agent.

The adapter reads the flat event. The expected tool arguments are:

| Field | Source | Use |
|---|---|---|
| `mission_id` | Trusted identity resolver | Assigned mission; never selected by tool arguments. |
| `mission_version` | Trusted identity resolver | Trusted mission version binding; never selected by tool arguments. |
| `action` | Tool event | Parsed against the Core's exact action allow-list. |
| `resource_id` | Tool event | Target identifier validated by the Core. |
| `resource_type` | Tool event | Parsed and checked against the action and mission. |
| `parameters` | Tool event, optional | Validated by the Core against per-action schemas. |
| `agent_id` | Trusted identity resolver | Never accepted from tool arguments. |
| `request_id` | Adapter | Generated server-side for each invocation. |
| `requested_at` | Adapter clock | Generated server-side and normalized to UTC. |

The older `{ "input": {...} }` wrapper is not the Gateway Lambda contract and
is not accepted as an alternate input format.

## Trusted identity boundary

`TrustedIdentityResolver.resolve(context)` is an injected protocol returning a
`TrustedRequestContext` with `agent_id`, `mission_id`, and `mission_version`.
The resolver must validate both the authenticated principal and its assigned
mission using independently trusted state. The handler does not pass the raw
event to this resolver, ignores caller-provided identity and mission fields,
and rejects a missing, invalid, or failing resolver before it calls the Core or
Gateway.

The standard Lambda routing metadata does not establish agent identity or
mission assignment. Gateway
header propagation is optional and must be configured in the target's metadata
configuration. Propagation alone does not prove that a header is authentic or
that an agent could not supply it. A deployment must establish a trusted
provenance for the identity value, prevent caller spoofing, and have the
resolver validate that provenance. No such concrete mechanism is implemented
in this repository.

## Decision and response behavior

1. Resolve trusted identity. Failure returns a controlled `BLOCK` response.
2. Copy the flat tool arguments, discard agent-supplied identity, mission
   binding, request ID, and timestamp, then add trusted and server-generated
   fields.
3. Parse a typed `ActionRequest` using the Core's validator.
4. For a valid request, call `ExecutionGateway.submit()` exactly once. The
   Gateway delegates decision-making to the existing DecisionService.
5. For an unknown action or malformed request, use
   `DefaultDecisionService.decide_raw()` so the Core remains authoritative,
   including for configured R9 decoys.
6. Convert decision and gateway failures to a fail-closed response.

Responses are built field by field; the `GatewayResult` object is never
serialized directly. A response may include the non-secret `approval_id`, but
not the approval credential or token. An approval-required response does not
execute the action; human approval and approved execution follow the existing
Gateway workflow.

## Dependency wiring

Local callers can use `build_handler(gateway, decision_service,
identity_resolver)` from `adapters/aws/handler.py`. The module-level
`lambda_handler` deliberately returns a fail-closed response until a deployment
composition module supplies configured dependencies. It does not silently
create in-memory stores or an executor.

Production wiring still needs to provide and review:

- A real, validated identity source and `TrustedIdentityResolver`.
- Gateway inbound authentication and any trusted context/header propagation.
- Durable stores and an expiry/recovery strategy where required.
- A controlled executor with least-privilege AWS permissions and independent
  server-side authorization checks.
- A tool schema that exposes only the intended SafeState request fields.

## Audit journal concurrency

The local `JsonlAuditSink` serializes operations on the journal file itself.
Thread locks use the file's `(st_dev, st_ino)` identity; process locks use
`flock` on POSIX and a byte-range lock through `msvcrt` on Windows. Thus,
different path names for the same physical file, including hard links, share
the lock. The lock covers reading the previous hash, calculating the next
record hash, and appending through the locked file handle. `verify()` uses the
same file lock. Different journal files use independent locks.

The SHA-256 chain format is unchanged. OS file locks are advisory and rely on
the underlying filesystem honoring their semantics. The journal is local and
tamper-evident, not a substitute for durable append-only cloud storage or a
protected checkpoint; see [`AUDIT_JOURNAL.md`](AUDIT_JOURNAL.md).

## Local validation

The adapter and Core can be exercised without AWS credentials:

```bash
python -m pytest -q tests/unit/test_agentcore_handler.py
python -m pytest -q tests/unit/test_audit.py
python -m pytest -q
python examples/local_stress_demo.py
git diff --check
```

Unit tests use fakes for the Gateway, identity resolver, and decision service.
They validate local contracts; they do not demonstrate a deployed Gateway,
live authentication, or AWS-side enforcement.
