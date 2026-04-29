from app.models.schemas import InterceptRequest, PolicyDecision

# Per-agent tool allowlists
AGENT_POLICIES = {
    "agent-001": {
        "allowed_tools": ["search_web", "read_file", "calculate"]
    },
    "agent-002": {
        "allowed_tools": ["search_web", "send_email", "read_file"]
    }
}

# Fail safe — if agent has no policy, DENY by default
DEFAULT_DECISION = PolicyDecision(
    decision="DENY",
    risk_score=100,
    reason="No policy found for this agent. Failing safe."
)

def evaluate(request: InterceptRequest) -> PolicyDecision:
    
    # Get this agent's policy
    policy = AGENT_POLICIES.get(request.agent_id)
    
    # No policy = fail safe DENY
    if not policy:
        return DEFAULT_DECISION
    
    # Check tool allowlist
    if request.tool_name not in policy["allowed_tools"]:
        return PolicyDecision(
            decision="DENY",
            risk_score=80,
            reason=f"Tool '{request.tool_name}' is not in the allowed list for agent '{request.agent_id}'",
            policy_id="tool_allowlist"
        )
    
    # Tool is allowed
    return PolicyDecision(
        decision="ALLOW",
        risk_score=0,
        reason=f"Tool '{request.tool_name}' is permitted for agent '{request.agent_id}'",
        policy_id="tool_allowlist"
    )

