from app.models.schemas import InterceptRequest, PolicyDecision
import re

# Per-agent policies
AGENT_POLICIES = {
    "agent-001": {
        "allowed_tools": ["search_web", "read_file", "calculate"],
        "budget": {
            "max_single_action_usd": 500,
            "max_daily_usd": 1000
        }
    },
    "agent-002": {
        "allowed_tools": ["search_web", "send_email", "read_file"],
        "budget": {
            "max_single_action_usd": 100,
            "max_daily_usd": 500
        }
    }
}

# PII patterns
PII_PATTERNS = {
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b",
    "phone": r"\b(\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b",
}

def detect_pii(data: dict) -> list:
    found = []
    text = str(data)
    for pii_type, pattern in PII_PATTERNS.items():
        if re.search(pattern, text):
            found.append(pii_type)
    return found

# Fail safe
DEFAULT_DECISION = PolicyDecision(
    decision="DENY",
    risk_score=100,
    reason="No policy found for this agent. Failing safe."
)

def evaluate(request: InterceptRequest) -> PolicyDecision:

    policy = AGENT_POLICIES.get(request.agent_id)

    if not policy:
        return DEFAULT_DECISION

    # Policy 1: Tool allowlist
    if request.tool_name not in policy["allowed_tools"]:
        return PolicyDecision(
            decision="DENY",
            risk_score=80,
            reason=f"Tool '{request.tool_name}' is not in the allowed list for agent '{request.agent_id}'",
            policy_id="tool_allowlist"
        )

    # Policy 2: Budget Guard
    budget = policy.get("budget")
    if budget:
        amount = request.tool_input.get("amount_usd", 0)
        if amount > budget["max_single_action_usd"]:
            return PolicyDecision(
                decision="DENY",
                risk_score=90,
                reason=f"Action exceeds single action limit of ${budget['max_single_action_usd']}. Requested: ${amount}",
                policy_id="budget_guard"
            )

    # Policy 3: PII Detection
    pii_found = detect_pii(request.tool_input)
    if pii_found:
        return PolicyDecision(
            decision="DENY",
            risk_score=95,
            reason=f"PII detected in tool input: {', '.join(pii_found)}. Transmission blocked.",
            policy_id="pii_detector"
        )

    # All policies passed
    return PolicyDecision(
        decision="ALLOW",
        risk_score=0,
        reason=f"Tool '{request.tool_name}' is permitted for agent '{request.agent_id}'",
        policy_id="tool_allowlist"
    )