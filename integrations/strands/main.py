"""SafeState-governed Strands agent inside the AgentCore runtime.

The agent interprets natural-language requests using a Bedrock foundation model,
selects narrowly scoped tools, and routes every action through the SafeState
ExecutionGateway. The LLM never makes security decisions or executes AWS
operations directly.
"""
from __future__ import annotations

import json
import logging
import os
from typing import Any

from bedrock_agentcore.runtime import BedrockAgentCoreApp

from safestate_adapter import SafeStateRuntime
from safestate_tools import SAFESTATE_TOOLS, set_runtime

logger = logging.getLogger(__name__)

SYSTEM_PROMPT = """You are a cost-analysis assistant governed by SafeState security controls.

You can inspect AWS infrastructure (EC2 instances, EBS volumes, S3 buckets) and
retrieve cost information. All actions are routed through a governance layer that
enforces strict security policies.

Rules you must follow:
- Use the provided tools to inspect resources. Never claim to execute AWS operations directly.
- If a tool returns a BLOCKED outcome, explain the governance reason to the user.
- If a tool returns APPROVAL_REQUIRED, tell the user that human approval is needed.
- Never try to work around blocked actions.
- You cannot approve your own requests.
- For stop requests, always provide a clear reason.

Available actions:
- List EC2 instances, describe a specific instance
- List EBS volumes, describe a specific volume
- List S3 buckets, get bucket metadata
- Get cost and utilization reports
- Request stopping a development EC2 instance (requires human approval)
"""

_runtime: SafeStateRuntime | None = None


def _get_runtime() -> SafeStateRuntime:
    global _runtime
    if _runtime is None:
        audit_path = os.environ.get(
            "SAFESTATE_AUDIT_PATH",
            os.path.join("/tmp", "safestate_audit.jsonl"),
        )
        _runtime = SafeStateRuntime(audit_path=audit_path)
        set_runtime(_runtime)
    return _runtime


def _create_agent():
    """Create the Strands agent with SafeState tools.

    Falls back gracefully if model access is unavailable.
    """
    from strands import Agent
    from strands.models.bedrock import BedrockModel

    model_id = os.environ.get("BEDROCK_MODEL_ID", "us.anthropic.claude-haiku-4-5-20251001-v1:0")
    region = os.environ.get("AWS_REGION", "us-west-2")

    model = BedrockModel(
        model_id=model_id,
        region_name=region,
    )
    agent = Agent(
        model=model,
        tools=SAFESTATE_TOOLS,
        system_prompt=SYSTEM_PROMPT,
    )
    return agent


def handle_invocation(payload: dict[str, Any]) -> dict[str, Any]:
    """Process an invocation request through the Strands agent.

    Input format: {"prompt": "List development EC2 instances"}

    Returns a structured response with the agent's answer and governance metadata.
    """
    runtime = _get_runtime()

    if not isinstance(payload, dict):
        return {
            "error": "INVALID_PAYLOAD",
            "message": "Payload must be a JSON object with a 'prompt' field.",
        }

    prompt = payload.get("prompt", "")
    if not isinstance(prompt, str) or not prompt.strip():
        return {
            "error": "MISSING_PROMPT",
            "message": "A non-empty 'prompt' field is required.",
        }

    try:
        agent = _create_agent()
        result = agent(prompt.strip())
        response_text = str(result)
    except Exception as exc:
        logger.warning("Agent invocation failed: %s", exc)
        safe_message = type(exc).__name__
        return {
            "error": "AGENT_INVOCATION_FAILED",
            "message": f"The agent could not process this request ({safe_message}).",
            "governance": {
                "agent_id": runtime._mission.agent_id,
                "mission_id": runtime._mission.mission_id,
                "audit_path": str(runtime.audit_sink.path),
            },
        }

    return {
        "response": response_text,
        "governance": {
            "agent_id": runtime._mission.agent_id,
            "mission_id": runtime._mission.mission_id,
            "policy_version": "2026-11-22.1",
            "audit_path": str(runtime.audit_sink.path),
        },
    }


app = BedrockAgentCoreApp()


@app.entrypoint
def invoke(payload, context):
    return handle_invocation(payload)


if __name__ == "__main__":
    app.run()
