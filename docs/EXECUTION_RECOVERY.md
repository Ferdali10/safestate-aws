# Execution Recovery and Crash Reconciliation

## Purpose

R8 reservation settlement and an external executor cannot be committed atomically
without a shared transactional system. A process can stop after an external
side effect but before the local reservation is settled. Retrying blindly can
duplicate an operation; releasing blindly can undercount a completed action.

This change introduces a local execution-state journal and a conservative
recovery service. It is a foundation for the gateway integration, not a claim
of durable production recovery.

## Execution state machine

```text
PREPARED -> EXECUTING -> EXECUTED -> SETTLED
                    \-> FAILED -> RELEASED
PREPARED -----------------------> RELEASED
EXECUTING ----------------------> UNKNOWN
```

- `PREPARED`: journal entry exists, executor has not been entered. Recovery first
  atomically claims `RELEASING`, then releases its R8 reservation.
- `EXECUTING`: executor may or may not have produced an external side effect.
  Recovery changes it to `UNKNOWN`; it does not retry, settle or release.
- `EXECUTED`: executor success was durably recorded. Recovery settles R8
  without calling the executor again.
- `FAILED`: executor failure was durably recorded. Recovery first claims
  `RELEASING`, then releases R8.
- `RELEASING` / `SETTLING`: recovery has claimed the accounting operation before
  touching R8. These intermediate states make retries safe after accounting
  errors, provided the R8 adapter preserves idempotent reservation operations.
- `UNKNOWN`: operator reconciliation is required. The reservation remains
  held until evidence establishes the external outcome.
- `SETTLED` / `RELEASED`: terminal accounting states.

## Safety invariants

1. Recovery never invokes an executor.
2. An uncertain `EXECUTING` record is never automatically retried.
3. An uncertain record is never automatically settled or released.
4. Recovery claims `RELEASING` or `SETTLING` in the journal before calling R8;
   settlement/release uses the original reservation ID and idempotent R8 operations.
5. A journal transition is conditional on its expected prior state.
6. The local in-memory journal is not durable and cannot recover after a real
   process restart. It exists for deterministic tests and simulation only.

## Production requirements

A production journal must persist `PREPARED` before any side effect, persist
`EXECUTING` before entering the executor, and use atomic conditional writes
for state transitions. It must also support listing non-terminal records after
restart. A durable store (for example, DynamoDB with conditional updates) and
an operator reconciliation workflow are still required.

The external executor must accept an idempotency key where the AWS API or
operation supports it. Where it does not, `UNKNOWN` requires checking the
resource's authoritative state before an operator chooses `SETTLED` or
`RELEASED`. This local implementation does not claim exactly-once execution.
