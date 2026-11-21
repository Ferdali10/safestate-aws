# SafeState AWS

**Mission-Aware Governance for Autonomous AI Agents**
*Let AI Agents Act. Keep Your Cloud Under Control.*

![Status](https://img.shields.io/badge/status-in%20development-orange)
![Hackathon](https://img.shields.io/badge/AWS%20Builder%20Center-Bedrock%20Managed%20Agents%20hackathon-232f3e)

A security and governance layer that evaluates agent-requested cloud actions against a written mission before they reach protected AWS resources.

**In one paragraph.** An AI agent can hold a valid IAM permission and still propose an action that is wrong for its current job. SafeState AWS puts a deterministic decision point between the agent and AWS. Each requested action is checked against a written mission contract and returns `ALLOW`, `BLOCK` or `REQUIRE_APPROVAL`. Allowed actions run through a separate, narrowly scoped executor, and everything is audited.

> **Hackathon note.** This project was developed for the AWS Builder Center hackathon *"Agents, your rules: Bedrock Managed Agents build"* (Nov 18 – Dec 2, 2026). Components are listed as implemented only once they have been demonstrated. See [Project status](#10-project-status).

---

## 1. The problem

AI agents can reason, call tools, and operate against real cloud environments. AWS IAM determines whether an identity is authorized to call an API on a resource. That authorization is essential, but it does not by itself express every task-level boundary an organization wants an agent to respect.

An agent may have a technically valid permission and still propose an action that is inappropriate for its current assignment.

For example, an agent is asked to analyze cloud costs without changing infrastructure. It discovers an idle development EC2 instance and proposes stopping it. The IAM role may permit that API call, but the active mission is analysis-only.

- IAM asks: *"May this identity perform this API operation?"*
- SafeState asks: *"Is this operation appropriate for this agent's assigned mission, the resource context, and the organization's rules?"*

SafeState complements AWS security controls. It does not replace IAM.

### How it relates to existing controls

| Control | What it answers | Where SafeState differs |
|---------|-----------------|-------------------------|
| AWS IAM / SCP | May this identity call this API? | Adds the agent's mission as a decision input |
| Amazon Bedrock Guardrails | Is this input or output unsafe content? | Authorizes operations, not content |
| Policy in Amazon Bedrock AgentCore (Cedar) | May this principal call this tool with these inputs? | Binds decisions to a per-agent mission contract, adds action-bound human approval and a separated executor |

## 2. Product vision and hackathon MVP

### Product vision

SafeState AWS is a mission-aware governance layer for autonomous AI agents operating on AWS. It evaluates requested actions against an explicit task contract, resource context, organizational rules, and risk requirements before execution.

| Decision | Meaning |
|----------|---------|
| `ALLOW` | The request is within the active mission and satisfies the applicable rules. |
| `BLOCK` | The request violates a rule, exceeds the mission, or cannot be safely evaluated. |
| `REQUIRE_APPROVAL` | The request is potentially permitted but requires an authorized human decision. |

### Hackathon MVP: AWS cost-analysis agent

To make the product demonstrable, the MVP focuses on one clearly defined job:

> Analyze AWS infrastructure and cost/utilization metadata, identify potentially unused resources, and recommend cost-saving actions. The agent must not modify resources directly. It may request that a non-production EC2 instance be stopped, but execution requires a SafeState `REQUIRE_APPROVAL` decision followed by an explicit human approval.

Resource scope: EC2, EBS and S3 metadata, plus cost and utilization metrics. The MVP does not read S3 object contents.

This narrow agent demonstrates the broader governance model; it is not the full product scope.

