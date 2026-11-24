# R8 Risk Budget Reservation and Settlement

## Lifecycle

R8 distinguishes available, reserved and spent points.

- **Reserve**: after deterministic policy evaluation, DecisionService creates an
  idempotent reservation keyed by the validated request ID. Reserved points
  reduce availability immediately but do not count as spent.
- **Pending approval**: ApprovalService stores the reservation ID with the
  request-bound approval record. The reservation remains held while pending.
- **Reject / expire**: ApprovalService releases the reservation. Expiry can be
  processed when the credential is used or explicitly through `expire()`.
  Production needs a scheduled sweeper for abandoned records.
- **Successful execution**: ExecutionGateway settles the reservation after the
  executor reports success. Points move from reserved to spent.
- **Execution failure**: ExecutionGateway releases the reservation. If release
  fails, a distinct error code is returned for operator reconciliation.
- **Hard budget limit**: if no reservation can be made, DecisionService returns
  BLOCK with R8 / RISK_BUDGET_EXCEEDED. Human approval cannot override the cap.

## State transitions

```text
RESERVED -> SETTLED
RESERVED -> RELEASED
```

Both terminal operations are idempotent when repeated with the same ID.
Cross-terminal transitions are rejected. Concurrent reservations are guarded
by one lock in the local adapter.

## Audit

The in-memory adapter can emit structured R8 transition events through an
injected AuditSink. When the sink fails, the state transition is not committed.
The audit sink must be provisioned and monitored independently.

## Production limitations

- In-memory storage is for local tests only. Production requires durable
  transactional conditional writes across reservation and mission-budget state.
- The local lock does not coordinate multiple processes or hosts.
- Execution and accounting cannot be made atomic across an arbitrary external
  AWS side effect and a local ledger. A production executor needs an operation
  idempotency key, durable execution state, and reconciliation for the
  EXECUTED_ACCOUNTING_FAILED outcome.
- Approval expiry needs a scheduled sweeper to release abandoned reservations.
- R8 reservation metadata is internal trusted service output; callers must not
  be allowed to construct or alter it.
