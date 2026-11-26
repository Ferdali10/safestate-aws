# Strands Agent Integration

A **Strands AI agent** backed by **Amazon Bedrock** (Claude Haiku 4.5),
running inside an **AgentCore** runtime, governed by the shared
**SafeState Core** from `core/safestate_core/`.

This integration does not contain its own copy of the Core. All policy
decisions (R1-R9), audit, approvals, risk budget, and tripwires are
provided by the single authoritative Core at the repository root.

## Architecture

```
User → AgentCore Runtime (main.py)
     → Strands Agent (Claude Haiku 4.5)
     → SafeState Tools (safestate_tools.py)
     → SafeState Adapter (safestate_adapter.py)
     → ExecutionGateway (core/safestate_core/execution.py)
     → DeterministicPolicyEngine (core/safestate_core/policy.py)
     → SimulatedAWSExecutor (no real AWS calls)
     → JsonlAuditSink (SHA-256 hash chain)
```

## Security boundaries

| Boundary | Enforcement |
|---|---|
| LLM cannot authorize | SafeState Core decides; agent selects tools |
| Identity is server-controlled | Adapter stamps agent_id, mission_id, timestamps |
| R2 blocks production | Production resources can never be modified |
| Executor is simulated | No real AWS API calls |
| Audit is tamper-evident | SHA-256 hash-chained JSONL; audit failure blocks |
| Approval tokens never exposed | Only `approval_id` returned to agent |

## Demo scenarios

```bash
# R1 — Authorized read (ALLOW)
uv run --project . python demo_agent.py --scenario read-ec2

# R2 — Production resource protection (BLOCK)
uv run --project . python demo_agent.py --scenario stop-production

# Both scenarios
uv run --project . python demo_agent.py --scenario all
```

## Local testing (no Bedrock inference)

```bash
# From integrations/strands/
uv run pytest tests/ -v

# Or from repository root
uv run --project integrations/strands pytest integrations/strands/tests/ -v
```

## Model configuration

| Variable | Default | Description |
|---|---|---|
| `BEDROCK_MODEL_ID` | `us.anthropic.claude-haiku-4-5-20251001-v1:0` | Foundation model |
| `AWS_REGION` | `us-west-2` | AWS region for Bedrock |
| `SAFESTATE_AUDIT_PATH` | `/tmp/safestate_audit.jsonl` | Audit journal location |

## Core dependency

The `safestate_core` symlink in this directory points to `../../core/safestate_core/`.
This makes the shared Core importable both by pytest and by the AgentCore runtime
(which runs `main.py` from this directory). The Core is never copied or vendored.
Any Core change is immediately visible to these tests.

For AgentCore deployment (`agentcore deploy`), the CodeZip build resolves the
symlink and bundles the Core files into the deployment artifact. No manual copy
is needed.
