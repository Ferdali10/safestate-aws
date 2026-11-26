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

## Concurrent writers

`JsonlAuditSink` serializes each append transaction per canonical journal path.
The transaction includes reading the previous record hash, computing the new
hash, and appending the JSONL record. A process-wide per-path thread lock
coordinates independent sink instances in one process. A sidecar lock provides
cross-process coordination: POSIX uses `flock`, and Windows uses an `msvcrt`
byte-range lock. `verify()` takes the same per-path lock so it does not inspect a
file while a writer is appending. Different journal paths use independent locks.

This preserves the existing record schema and SHA-256 calculation. The lock
files are coordination artifacts; they are not journal records and do not
change the chain format. The locks are advisory and depend on the underlying
filesystem honoring the operating system's locking semantics. Symlink aliases
are resolved to a common sidecar path. Appends verify the full existing chain
before extending it, including records written earlier by the same sink. This
detects prior tampering but makes each append O(n) in journal length; use a
durable indexed audit store for larger journals.

## Security limitations

A local SHA-256 chain is tamper-evident, not tamper-proof. An attacker who can
rewrite the entire journal can recompute the chain. Stronger guarantees require
an independently protected checkpoint, digital signatures, remote append-only
storage, or WORM retention. Those are deliberately outside this local MVP.

This local implementation is not a durable multi-host audit service. Production
still requires an appropriately durable append-only store, operational
monitoring, protected checkpoints, and testing against the target filesystem.
