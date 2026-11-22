# SafeState AWS Core Contract

**Status:** Proposed contract — implementation not yet started  
**Scope:** Sprint 1, Task 01 (domain model and public interfaces)  
**Decision authority:** Deterministic SafeState Core; never the LLM

This document defines the first stable contract shared by the local agent, simulator, and future AWS adapters. It is a design specification, not evidence of an implemented or deployed system.

## 1. Design principles

1. **Mission-scoped:** every request is evaluated against an explicit, versioned mission.
2. **Deterministic:** identical normalized inputs and policy versions produce identical decisions.
3. **Fail closed:** missing, malformed, ambiguous, or unavailable security context cannot authorize a write.
4. **Least authority:** the agent can request actions; it cannot grant itself permissions or directly execute protected writes.
5. **Untrusted resource data:** tags, names, descriptions, logs, and object metadata are data, never policy instructions.
6. **Adapter-independent:** core policy logic has no dependency on AWS SDK, Bedrock, Ollama, HTTP, or a database.
7. **Auditable:** decisions carry stable reason codes and correlation identifiers without logging secrets.

## 2. Core domain types

### 2.1 Enumerations

- `DecisionStatus`: `ALLOW`, `BLOCK`, `REQUIRE_APPROVAL`.
- `ActionType`: initially `LIST_INSTANCES`, `DESCRIBE_INSTANCE`, `LIST_VOLUMES`, `DESCRIBE_VOLUME`, `LIST_BUCKETS`, `GET_BUCKET_METADATA`, `GET_COST_AND_UTILIZATION`, `REQUEST_STOP_INSTANCE`.
- `EnvironmentClass`: `PROD`, `DEV`, `TEST`, `UNKNOWN`.
- `ResourceType`: `EC2_INSTANCE`, `EBS_VOLUME`, `S3_BUCKET`, `COST_REPORT`.
- `ApprovalStatus`: `PENDING`, `APPROVED`, `REJECTED`, `EXPIRED`, `CONSUMED`.
- `PolicyEffect`: `PERMIT_READ`, `DENY`, `REQUIRE_HUMAN_APPROVAL`.

Unknown action strings must be rejected during request parsing; they must not be silently mapped to a known action.

### 2.2 MissionContract

Required fields:

- `mission_id: str` — stable identifier.
- `version: str` — immutable version for an evaluation.
- `agent_id: str` — agent identity to which this mission applies.
- `purpose: str` — human-readable task description.
- `allowed_actions: set[ActionType]`.
- `resource_scope: set[ResourceType]`.
- `policy_ids: set[str]` — enabled rules, initially R1–R7.
- `created_at: datetime` — timezone-aware UTC timestamp.

The active mission is supplied by a trusted configuration/operator boundary. The agent must not be able to edit the mission contract or select a weaker policy version.

### 2.3 ResourceContext

Required fields:

- `resource_id: str`.
- `resource_type: ResourceType`.
- `environment: EnvironmentClass`.
- `classification_source: str` — trusted inventory/configuration source identifier.
- `classification_verified: bool`.
- `metadata: Mapping[str, str]` — untrusted descriptive data; never interpreted as instructions.

**Trust rule:** raw agent-supplied tags do not establish a trusted environment classification. The simulator and future AWS adapter must obtain classification from a trusted inventory/configuration boundary. If provenance cannot be verified, use `UNKNOWN` and `classification_verified=false`. A `PROD` classification is always protected; an approval cannot override R2.

### 2.4 ActionRequest

Required fields:

- `request_id: str` — unique request identifier (UUID recommended).
- `agent_id: str`.
- `mission_id: str`.
- `mission_version: str`.
- `action: ActionType`.
- `resource_id: str`.
- `resource_type: ResourceType`.
- `parameters: Mapping[str, JSONValue]` — validated, allow-listed parameters only.
- `requested_at: datetime` — timezone-aware UTC timestamp.

The request must not contain credentials, access tokens, secret values, arbitrary shell commands, or executable code. The server-side adapter resolves the authoritative resource context; it must not trust the request's claimed tags or environment.

### 2.5 Decision

Required fields:

- `decision_id: str`.
- `request_id: str`.
- `status: DecisionStatus`.
- `rule_id: str` — primary rule responsible, e.g. R1–R7.
- `reason_code: str` — stable machine-readable reason.
- `reason: str` — concise human-readable explanation.
- `policy_version: str`.
- `evaluated_at: datetime` — timezone-aware UTC timestamp.
- `approval_required: bool` — true only for `REQUIRE_APPROVAL`.

A decision is not an AWS permission grant. An `ALLOW` only permits the request to proceed to the separately controlled executor, which must still enforce IAM and re-check applicable invariants.

## 3. Public interfaces

The first implementation should expose framework-independent Python interfaces equivalent to:

```python
class MissionProvider(Protocol):
    def get_active_mission(self, agent_id: str, mission_id: str) -> MissionContract: ...

class ResourceContextProvider(Protocol):
    def get_context(self, resource_id: str, resource_type: ResourceType) -> ResourceContext: ...

class PolicyEngine(Protocol):
    def evaluate(
        self,
        request: ActionRequest,
        mission: MissionContract,
        resource: ResourceContext,
    ) -> Decision: ...

class DecisionService(Protocol):
    def decide(self, request: ActionRequest) -> Decision: ...
```

The concrete local implementation will compose trusted mission and resource providers with a deterministic policy engine. Future AWS Lambda handlers and local agent tools call the same service boundary; they do not duplicate policy logic.

## 4. Initial rule semantics

Rules are evaluated in deny-first order. A deny condition takes precedence over any approval or allow condition.

| Rule | Condition | Result |
|---|---|---|
| R1 | Action is an approved read and inside mission scope | `ALLOW` |
| R1 | Any direct mutation not explicitly represented as a request workflow | `BLOCK` |
| R2 | Target is verified `PROD` and action is mutating | `BLOCK` |
| R3 | `REQUEST_STOP_INSTANCE`, verified environment is `DEV` or `TEST`, mission allows the request | `REQUIRE_APPROVAL` |
| R3 | Stop request with unknown/unverified environment | `BLOCK` |
| R4 | Delete, terminate, or any unknown destructive action | `BLOCK`; no corresponding agent tool is exposed |
| R5 | S3 object-content read, snapshot sharing, IAM mutation, or unapproved export | `BLOCK` |
| R6 | Action/resource outside mission scope, malformed input, or attempt to treat metadata as instructions | `BLOCK` |
| R7 | Mission, context, decision, or approval dependency unavailable or invalid | `BLOCK` |

The exact ordering and precedence must be captured in unit tests. A request cannot become eligible merely because it passes a later rule.

## 5. Approval boundary (contract only; implementation in Sprint 2)

An approval record must eventually bind to all of:

- `approval_id`.
- `request_id`.
- `agent_id`.
- `mission_id` and `mission_version`.
- Exact `action`, `resource_id`, and canonical parameters digest.
- `approved_by` trusted human identity.
- `issued_at` and `expires_at`.
- `status` and one-time consumption state.

Any mismatch, expiry, replay, altered parameters, or production target must be rejected. The approval subsystem must not turn an otherwise blocked request into an allowed one. Approval is not implemented by this task.

## 6. Error and trust semantics

- Invalid request schema: reject before policy evaluation; no execution.
- Unknown action: reject; no fallback.
- Missing mission or mission-version mismatch: block.
- Missing or unverified resource classification: block mutation requests.
- Provider timeout or exception: fail closed.
- Policy engine exception: fail closed.
- Logging failure must not cause an unsafe action to execute. The execution boundary must define whether audit persistence is a prerequisite; for the MVP, protected writes must not proceed if required audit persistence fails.
- Do not log secrets or full sensitive payloads.

## 7. Task 01 acceptance criteria

Task 01 is complete only when all of the following are true:

1. The domain types and public interfaces above are implemented in Python with type annotations.
2. Datetimes are timezone-aware; naive timestamps are rejected.
3. Enum parsing rejects unknown values.
4. Request validation rejects missing identifiers, invalid resource/action combinations, unsupported parameter keys, and non-JSON parameter values.
5. Resource classification provenance is explicit; caller-supplied tags alone cannot authorize a stop request.
6. Decision objects always contain a status, rule ID, stable reason code, policy version, request ID, and evaluation timestamp.
7. The core package imports without AWS SDK, Bedrock SDK, Ollama, Docker, or network access.
8. Unit tests cover valid construction, invalid input, unknown actions, unknown environment, untrusted classification, mission mismatch, and timezone validation.
9. `pytest` passes; formatting/type checks (if configured) pass; `git diff --check` is clean.
10. No AWS resource is provisioned and no cloud credentials are required.

## 8. Explicit non-goals for Task 01

- No Bedrock or AgentCore integration.
- No AWS API calls or Terraform deployment.
- No approval token generation/consumption implementation.
- No EC2/EBS/S3 simulator implementation.
- No LLM-based policy decisions.
- No claim of production readiness or AWS validation.

## 9. Proposed package layout for Task 01

```text
core/
  safestate_core/
    __init__.py
    models.py
    interfaces.py
    validation.py
tests/
  unit/
    test_models.py
    test_validation.py
```

This layout is proposed for Task 01. Existing repository content must be preserved; new files are added only after this contract is accepted.
