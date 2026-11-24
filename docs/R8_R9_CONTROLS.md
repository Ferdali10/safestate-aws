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
    -> reserve(mission_key, mission-scoped request_id, action_cost, limit)
       -> reserved: preserve R1-R7 decision and attach reservation metadata
       -> insufficient: BLOCK / R8 / RISK_BUDGET_EXCEEDED
       -> store missing or failing: BLOCK / R7
    -> execution success: SETTLED (reserved points become spent)
    -> rejection / expiry / execution failure: RELEASED (points become available)
```

The mission key is `agent_id:mission_id:mission_version`, so a new mission
version receives a separate budget. Reservation IDs include the mission key
and validated request ID, preventing cross-mission collisions and making
retries idempotent.

Default point costs:

| Action | Points |
|---|---:|
| LIST_INSTANCES | 1 |
| DESCRIBE_INSTANCE | 1 |
| LIST_VOLUMES | 1 |
| DESCRIBE_VOLUME | 1 |
| LIST_BUCKETS | 1 |
| GET_BUCKET_METADATA | 1 |
| GET_COST_AND_UTILIZATION | 2 |
| REQUEST_STOP_INSTANCE | 20 |

Costs can be overridden through the service constructor. Every configured cost
must be a positive integer. A mission with `risk_budget=None` does not enable
R8. If a mission configures a budget but no trusted reservation store is
supplied, the service blocks rather than silently skipping enforcement.

The local ledger enforces `RESERVED -> SETTLED` or `RESERVED -> RELEASED`.
Settlement and release are idempotent; cross-terminal transitions are rejected.
Concurrent reservations are protected by a process-local lock. The store can
emit R8 transition events through the existing AuditSink; if audit append fails,
the corresponding local state transition is not committed.

A hard budget shortage returns `BLOCK / R8 / RISK_BUDGET_EXCEEDED`. Human
approval cannot override the mission's point cap. A request with a reservation
that requires human approval holds those points while pending; rejection or
expiry releases them. Successful execution settles the reservation; executor
failure releases it.

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
also records the trigger type and decoy target. R8 reservation transitions can
be written to the same journal through the injected AuditSink. Audit
persistence failure prevents the corresponding state transition or converts a
decision to BLOCK, depending on the integration point.

## Security boundaries and non-goals

- R8/R9 remain deterministic; no LLM decides whether a request is allowed.
- R8/R9 cannot override an R1-R7 BLOCK.
- Human approval is request-bound, expiring and single-use; it does not bypass
  a hard R8 budget cap.
- In-memory risk and tripwire adapters are local-only and not cross-process
  durable. Production requires transactional conditional writes, an expiry
  sweeper and operational reconciliation.
- No AWS SDK, cloud credentials, network calls, DynamoDB, or AgentCore runtime
  dependency is included in this local implementation.
