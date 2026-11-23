# Execution Gateway and Simulated AWS Executor

## Scope

This milestone adds a local execution boundary. It does not connect to AWS,
Bedrock, AgentCore, IAM, or a network. The simulator changes only in-memory
state and is intended for deterministic tests and demonstrations.

## Request lifecycle

- `ExecutionGateway.submit(request)` calls the trusted DecisionService.
- `BLOCK`: return BLOCKED; the executor is never called.
- `ALLOW`: invoke the executor and return its simulated result.
- `REQUIRE_APPROVAL`: issue a request-bound, expiring, one-time credential and
  return APPROVAL_REQUIRED; do not execute anything.
- `execute_approved(request, credential)`: require an injected fresh
  `DecisionRevalidator`, re-check trusted mission/resource/policy state, reject
  BLOCK, consume the exact one-time approval, and only then call the executor.
- Any decision, approval, revalidation, or executor error fails closed.

## Critical integration contract

The revalidator must fetch fresh trusted mission and resource context and
re-evaluate policy. It must be side-effect-free: it must not reserve/charge R8
again. The current R8 implementation charges during DecisionService evaluation;
therefore wiring the existing DefaultDecisionService directly as the revalidator
would double-charge. Until R8 gains reservation/settlement semantics, production
wiring must use a dedicated no-accounting revalidation path. This repository
milestone makes that dependency explicit rather than silently introducing
double accounting.

Human identity authentication is external. The `approver_id` supplied to
ApprovalService must come from a verified identity provider, not agent input.
The in-memory approval store is not multi-process or production durable.

## Simulated executor

`SimulatedAWSExecutor` supports the current ActionType allow-list. It returns
AWS-shaped sample data and tracks EC2 instance state in process memory. It
performs no AWS API calls, and state disappears when the process exits.

## Production work still required

- Durable cross-process approval storage with atomic conditional transitions.
- Authenticated human approval UI and identity provider.
- Side-effect-free policy revalidation plus R8 reservation/settlement.
- AWS executor adapter with narrowly scoped IAM permissions and independent
  server-side authorization.
- Execution audit events and operational alerting.
- Integration tests against a controlled AWS sandbox, only when credentials
  and an approved budget are available.
