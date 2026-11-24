# Execution Gateway and Simulated AWS Executor

## Scope

This milestone adds a local execution boundary. It does not connect to AWS,
Bedrock, AgentCore, IAM, or a network. The simulator changes only in-memory
state and is intended for deterministic tests and demonstrations.

## Request lifecycle

- `ExecutionGateway.submit(request)` calls the trusted DecisionService.
- `BLOCK`: return BLOCKED; the executor is never called.
- `ALLOW`: invoke the executor, then settle any R8 reservation on success.
- `REQUIRE_APPROVAL`: issue a request-bound, expiring, one-time credential and
  return APPROVAL_REQUIRED; do not execute anything. Any R8 reservation stays
  held during the human decision.
- Rejection/expiry releases a linked reservation. Approved execution requires
  fresh trusted policy/context revalidation, consumes the exact one-time
  approval, executes, and settles the original reservation.
- Executor failure releases the reservation. Settlement failure after a
  successful external side effect is surfaced as EXECUTED_ACCOUNTING_FAILED;
  it cannot honestly be represented as a rollback.
- Any decision, approval, revalidation, or accounting error fails closed.

## R8 contract

The DecisionService reserves points under the validated request ID. Repeated
evaluation of the same request is idempotent. A hard budget shortage is BLOCK,
not a human-approval override. The revalidator must be side-effect-free with
respect to R8 and must not create a second reservation.

## Security boundaries

The revalidator must fetch fresh trusted mission and resource context.
Human identity authentication is external. The `approver_id` supplied to
ApprovalService must come from a verified identity provider, not agent input.
The in-memory approval and risk stores are not multi-process or production
durable.

## Simulated executor

`SimulatedAWSExecutor` supports the current ActionType allow-list. It returns
AWS-shaped sample data and tracks EC2 instance state in process memory. It
performs no AWS API calls, and state disappears when the process exits.

## Production work still required

- Durable cross-process approval and risk reservation storage with atomic
  conditional transitions.
- Authenticated human approval UI and identity provider.
- Side-effect-free policy revalidation plus a durable execution state machine.
- AWS executor adapter with narrowly scoped IAM permissions and independent
  server-side authorization.
- Execution audit events, reservation-expiry sweeper, and reconciliation for
  EXECUTED_ACCOUNTING_FAILED.
- Integration tests against a controlled AWS sandbox, only when credentials
  and an approved budget are available.
