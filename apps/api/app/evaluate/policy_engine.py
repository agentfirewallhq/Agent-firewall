import os
import re
import yaml
from typing import Dict, Any, List

from app.models.schemas import InterceptRequest, PolicyDecision
from app.audit import store as _audit

_POLICY_PATH = os.environ.get(
    "AGENT_FIREWALL_POLICIES",
    os.path.join(os.path.dirname(os.path.dirname(__file__)), "policies.yaml"),
)

# PII patterns
PII_PATTERNS = {
    "SSN": r"\b\d{3}-\d{2}-\d{4}\b",
    "credit_card": r"\b(?:\d{4}[-\s]?){3}\d{4}\b",
    "email": r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b",
    "phone": r"\b(?:\+\d{1,2}\s?)?\(?\d{3}\)?[\s.-]?\d{3}[\s.-]?\d{4}\b",
}

# Common prompt-injection / instruction-override signatures.
# Conservative heuristics: they favour flagging over missing an attack.
INJECTION_PATTERNS = [
    r"ignore (all )?(your |the )?(previous|above|prior) (instructions|rules)",
    r"disregard (the |your )?(previous|above|system)",
    r"you are now ",
    r"new instructions\s*:",
    r"system\s*:",
    r"reveal (your )?(system )?(prompt|instructions)",
    r"override (the |your )?(policy|limit|rules)",
    r"act as (an? )?(unrestricted|admin|developer)",
]


def _load_policies() -> Dict[str, Any]:
    with open(_POLICY_PATH, "r") as f:
        return yaml.safe_load(f)


def detect_pii(data: Any, types: List[str]) -> List[str]:
    text = str(data)
    found = []
    for pii_type in types:
        pattern = PII_PATTERNS.get(pii_type)
        if pattern and re.search(pattern, text):
            found.append(pii_type)
    return found


def redact_pii(data: Any) -> tuple:
    """Recursively replace PII values with [REDACTED:<type>] markers.

    Returns (redacted_copy, found_types). Call this before persisting
    tool_input anywhere (audit log, approval records) so raw sensitive
    values never land in storage, even for PII types the policy allows
    in normal operation (e.g. customer emails).
    """
    found: List[str] = []

    def redact_text(text: str) -> str:
        for pii_type, pattern in PII_PATTERNS.items():
            new_text, n = re.subn(pattern, f"[REDACTED:{pii_type}]", text)
            if n and pii_type not in found:
                found.append(pii_type)
            text = new_text
        return text

    def walk(value: Any) -> Any:
        if isinstance(value, str):
            return redact_text(value)
        if isinstance(value, dict):
            return {k: walk(v) for k, v in value.items()}
        if isinstance(value, list):
            return [walk(v) for v in value]
        return value

    return walk(data), found


def detect_injection(text: str) -> bool:
    low = text.lower()
    return any(re.search(pat, low) for pat in INJECTION_PATTERNS)


def _amount_from(tool_input: Dict[str, Any]) -> float:
    if not isinstance(tool_input, dict):
        return 0.0
    for key in ("amount_usd", "amount", "total_usd"):
        if key in tool_input:
            try:
                return float(tool_input[key])
            except (TypeError, ValueError):
                pass
    return 0.0


def evaluate(request: InterceptRequest) -> PolicyDecision:
    policies = _load_policies()
    defaults = policies.get("defaults", {})
    agents = policies.get("agents", {})
    policy = agents.get(request.agent_id)

    # Fail safe: unknown agent.
    if not policy:
        return PolicyDecision(
            decision="DENY",
            risk_score=100,
            reason=f"No policy found for agent '{request.agent_id}'. Failing safe.",
            policy_id="default_deny",
        )

    # Policy 1: Tool allowlist.
    if request.tool_name not in policy.get("allowed_tools", []):
        return PolicyDecision(
            decision="DENY",
            risk_score=80,
            reason=f"Tool '{request.tool_name}' is not in the allowed list for agent '{request.agent_id}'.",
            policy_id="tool_allowlist",
        )

    # Policy 2: Untrusted-content / prompt-injection check.
    # If untrusted context (or the input itself) carries an instruction
    # override, the action may be hijacked. Block or route per config.
    untrusted = [c.content for c in request.context if c.source == "untrusted"]
    injection = any(detect_injection(b) for b in untrusted) or detect_injection(str(request.tool_input))
    if injection:
        if defaults.get("on_untrusted_instruction", "deny") == "require_approval":
            return PolicyDecision(
                decision="REQUIRE_APPROVAL",
                risk_score=85,
                reason="Possible prompt-injection detected in untrusted content. Routed to human approval.",
                policy_id="untrusted_content",
            )
        return PolicyDecision(
            decision="DENY",
            risk_score=95,
            reason="Possible prompt-injection detected in untrusted content. Action blocked.",
            policy_id="untrusted_content",
        )

    # Policy 3: Hard PII block (SSN, credit card). Email/phone allowed by default,
    # so a support agent can still email a customer.
    pii_found = detect_pii(request.tool_input, defaults.get("block_pii", ["SSN", "credit_card"]))
    if pii_found:
        return PolicyDecision(
            decision="DENY",
            risk_score=95,
            reason=f"Sensitive PII detected in tool input: {', '.join(pii_found)}. Transmission blocked.",
            policy_id="pii_detector",
        )

    # Policy 4: Hard budget limit (deny outright).
    amount = _amount_from(request.tool_input)
    budget = policy.get("budget") or {}
    hard = budget.get("max_single_action_usd")
    if hard is not None and amount > hard:
        return PolicyDecision(
            decision="DENY",
            risk_score=90,
            reason=f"Action ${amount:.0f} exceeds the single-action limit of ${hard}.",
            policy_id="budget_guard",
        )

    # Policy 4b: Daily spend cap (hard). Sums today's ALLOW'd spend for this agent.
    max_daily = budget.get("max_daily_usd")
    if max_daily is not None and amount > 0:
        spent = _audit.daily_spend(request.agent_id)
        if spent + amount > max_daily:
            return PolicyDecision(
                decision="DENY",
                risk_score=90,
                reason=f"Daily spend cap reached: ${spent:.0f} already spent today + ${amount:.0f} would exceed the ${max_daily}/day limit.",
                policy_id="budget_guard_daily",
            )

    # Policy 5: Sensitive tools always require a human.
    if request.tool_name in defaults.get("require_approval_tools", []):
        return PolicyDecision(
            decision="REQUIRE_APPROVAL",
            risk_score=70,
            reason=f"Tool '{request.tool_name}' is a sensitive action and requires human approval.",
            policy_id="approval_router",
        )

    # Policy 6: Spend above the auto-approve threshold needs a human.
    approval_at = budget.get("approval_threshold_usd")
    if approval_at is not None and amount > approval_at:
        return PolicyDecision(
            decision="REQUIRE_APPROVAL",
            risk_score=60,
            reason=f"Action ${amount:.0f} exceeds the auto-approve threshold of ${approval_at}. Human approval required.",
            policy_id="budget_guard",
        )

    # All policies passed.
    return PolicyDecision(
        decision="ALLOW",
        risk_score=0,
        reason=f"Tool '{request.tool_name}' is permitted for agent '{request.agent_id}'.",
        policy_id="allow",
    )
