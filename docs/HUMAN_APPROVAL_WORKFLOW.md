# Human Approval Workflow (local reference implementation)

## Purpose

The approval workflow turns a policy result of `REQUIRE_APPROVAL` into a
short-lived, one-time grant for **one exact request**. It does not change the
policy engine and does not execute cloud actions.

## Lifecycle

1. `ApprovalService.issue(request, decision)` accepts only a
   `REQUIRE_APPROVAL` decision whose `request_id` matches the validated request.
2. The service creates a cryptographically random opaque token. Only its
   SHA-256 digest is stored. The plaintext token is returned once to the
   caller and must be delivered only through an authenticated approval UI.
3. An authenticated human identity calls `approve` or `reject`. The token
   is compared in constant time and the pending-state transition is atomic.
4. An executor must call `consume(approval_id, original_request)` immediately
   before execution. Consumption atomically changes APPROVED to CONSUMED.
5. Expiry is checked both when the human decides and immediately before
   consumption. The default TTL is 10 minutes; values above 24 hours are rejected.

The fingerprint binds request ID, agent, mission and version, action, resource
ID and type, complete canonical parameters, and request timestamp. Changing
any of these fields invalidates the approval.

## Local example

```python
from datetime import datetime, timezone
from safestate_core.approvals import ApprovalService, InMemoryApprovalStore

approvals = ApprovalService(
    store=InMemoryApprovalStore(),
    clock=lambda: datetime.now(timezone.utc),
    id_generator=lambda: "approval-unique-id",
)
# request and decision must come from the trusted validation/decision pipeline.
credential = approvals.issue(request, decision)
# The authenticated human interface presents credential.token once.
approvals.approve(credential, approver_id="authenticated-user-id")
# Trusted executor checks and consumes immediately before performing the action.
approvals.consume(credential.approval_id, request)
```

## Security boundaries and production requirements

- This module does not authenticate the human. `approver_id` must come from a
  verified identity provider/session, never from an agent-supplied field.
- The in-memory store is process-local and is not suitable for production.
  A production adapter must persist records durably and implement atomic
  compare-and-set transitions (for example, conditional writes in DynamoDB).
- The approval token must be transported over an authenticated, encrypted
  channel, excluded from logs, and protected against browser/session theft.
- The executor must re-evaluate current policy and trusted resource context
  before acting; approval is not an override for R2, R4, R5, R6, R7, R8 or R9.
- A changed request requires a new approval. Approval is not a general-purpose
  permission and cannot be replayed after consumption.
- No AWS SDK, Bedrock, external dependency, network call, or paid cloud service
  is used by this local implementation.

This is a core workflow primitive, not yet an end-to-end AWS approval product.
