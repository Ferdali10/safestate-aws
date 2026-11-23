# R8 Risk Budget and R9 Tripwires

## Scope

This document describes the local, framework-independent implementation of R8
and R9. It does not claim that DynamoDB, AgentCore Gateway, or a production
session-revocation service has been deployed.

## R8 — cumulative mission risk budget

```text
validated request
    -> trusted mission (risk_budget)
    -> R1-R7 deterministic policy
    -> atomic RiskBudgetStore.try_reserve(mission_key, action_cost, limit)
       -> reserved: preserve R1-R7 decision
       -> insufficient: REQUIRE_APPROVAL / R8
       -> store missing or failing: BLOCK / R7
```

The mission key is `agent_id:mission_id:mission_version`, so a new mission
version receives a separate counter. The default point costs are:

| Action | Points |
|---|---:|
| LIST_INSTANCES | 1 |
| DESCRIBE_INSTANCE | 1 |
| LIST_VOLUMES | 1 |
| DESCRIBE_VOLUME | 1 |
| LIST_BUCKETS | 1 |
| GET_BUCKET_METADATA | 1 |
| GET_COST_AND_UTILIZATION | 2 |
| REQUEST_STOP_INSTANCE | 5 |

Costs can be overridden through the service constructor. Every configured cost
must be a positive integer. A mission with `risk_budget=None` does not enable
R8. If a mission configures a budget but no trusted store is supplied, the
service blocks rather than silently skipping enforcement.

The store operation must be atomic. The included `InMemoryRiskBudgetStore`
uses a lock and is suitable only for one-process tests and local simulations.
A future DynamoDB adapter must use a conditional atomic update.

**MVP accounting semantics:** points are consumed when a non-BLOCK decision is
issued, including `REQUIRE_APPROVAL` decisions. The current interface has no
reservation ID, release, or refund lifecycle. This is intentionally
conservative, but rejected/expired approvals still consume points. A production
approval workflow must add explicit reservation and settlement semantics before
this behavior is used in a real environment.

## R9 — decoy tripwires

A trusted mission may contain:
- `decoy_actions`: unknown action names that no legitimate workflow uses.
- `decoy_resource_ids`: resource identifiers reserved as decoys.

A decoy action is checked when raw request parsing rejects an unknown action.
A decoy resource is checked after loading and validating the trusted mission,
but before querying the resource inventory. On a match, the service calls the
injected `TripwireHandler`. The handler contract requires incident recording
and agent-session revocation to complete before it returns.

A successful trigger returns `BLOCK / R9 / TRIPWIRE_TRIGGERED`. Missing or
failing handlers return a fail-closed `BLOCK / R7`; the service never claims
that a session was revoked unless the handler returned successfully.

The included `InMemoryTripwireHandler` stores incident details and marks the
agent as revoked in process memory. It demonstrates the contract for tests and
local simulation only. It does not revoke a real Bedrock/AgentCore session.
A production adapter must connect to the actual session lifecycle and durable
incident store.

## Audit integration

When wrapped by `AuditedDecisionService`, tripwire decisions are written to
the JSONL audit journal like other decisions. The in-memory tripwire incident
also records the trigger type and decoy target. Audit persistence failure
converts the returned decision to BLOCK.

## Security boundaries and non-goals

- R8/R9 remain deterministic; no LLM decides whether a request is allowed.
- R8/R9 cannot override an R1-R7 BLOCK.
- A budget-exceeded request is not automatically executed; it only asks for
  human approval. The approval workflow is not implemented yet.
- No AWS SDK, cloud credentials, network calls, DynamoDB, or AgentCore runtime
  dependency is included in this local implementation.
