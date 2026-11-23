# Audit Journal & Traceability

## Purpose

The audit layer records each decision produced by the SafeState decision service.
It is local-first, dependency-free, and independent of AWS or agent frameworks.

## Data flow

```text
Untrusted request
      |
      v
DefaultDecisionService ----> deterministic policy engine
      |                               |
      +-------------------------------+
                      |
                      v
            AuditedDecisionService
                      |
              AuditEvent (JSON)
                      |
                      v
             JsonlAuditSink
                      |
              append-only JSONL
                      |
              SHA-256 hash chain
                      |
                      v
                verify()
```

## Record format

Each JSONL line contains a schema version, event and decision identifiers,
UTC timestamp, request identifier, decision status, rule, reason code, policy
version, previous-record hash and current event hash. Hashes use canonical JSON
with sorted keys and compact separators.

## Failure behavior

The audited service writes the record before returning the decision. If the
audit sink raises an exception, the wrapper changes the decision to BLOCK with
`R7 / AUDIT_PERSISTENCE_FAILED`. This is fail-closed. The failure itself cannot
be persisted to the failed sink, so production deployments must also alert through
an independent operational channel.

## Integrity verification

`JsonlAuditSink.verify()` checks schema version, each record hash, previous-hash
link, JSON validity, and an incomplete final line. It detects ordinary edits,
record deletion, and reordering.

## Security limitations

A local SHA-256 chain is tamper-evident, not tamper-proof. An attacker who can
rewrite the entire journal can recompute the chain. Stronger guarantees require
an independently protected checkpoint, digital signatures, remote append-only
storage, or WORM retention. Those are deliberately outside this local MVP.

The current implementation uses a process-local lock. Multiple independent
processes writing the same journal need an OS-level file lock or a single-writer
service before production use.
