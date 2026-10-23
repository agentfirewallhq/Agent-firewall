# 🛡️ Agent Firewall

> Runtime governance proxy for AI agents. Intercept, evaluate, and log every tool call before it executes.

[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](https://opensource.org/licenses/MIT)

## What is Agent Firewall?

Agent Firewall is a thin security layer that sits between your AI agent and the real world. Every time an agent tries to take an action — send an email, issue a refund, spend money — it passes through Agent Firewall first.

The firewall inspects the action, evaluates it against your policies, scores its risk, and returns one of three decisions:

- **ALLOW** — action goes through
- **DENY** — action is blocked, with a reason
- **REQUIRE_APPROVAL** — a human must approve before it executes

## Quick start

All endpoints require an API key in the `X-API-Key` header.

```bash
curl -X POST https://your-host/intercept \
  -H "Content-Type: application/json" \
  -H "X-API-Key: your-key" \
  -d '{
    "agent_id": "agent-002",
    "tool_name": "issue_refund",
    "tool_input": {"amount_usd": 40},
    "session_id": "session-001"
  }'
```

Response:

```json
{
  "decision": "REQUIRE_APPROVAL",
  "risk_score": 70,
  "reason": "Tool 'issue_refund' is a sensitive action and requires human approval.",
  "policy_id": "approval_router",
  "approval_id": "a1b2c3d4-..."
}
```

A human then approves or denies it:

```bash
curl -X POST https://your-host/approvals/a1b2c3d4-.../approve -H "X-API-Key: your-key"
```

## Policies

Policies live in `app/policies.yaml` — onboarding a new agent is a config change, not a code change.

| Policy | What it does | Decision |
|---|---|---|
| Tool allowlist | Each agent can only call permitted tools | DENY |
| Untrusted-content check | Flags prompt-injection hidden in pasted/external content | DENY |
| PII block | Blocks SSN and card numbers in tool inputs (email/phone allowed) | DENY |
| Budget guard (single) | Blocks a single action above the per-agent limit | DENY |
| Budget guard (daily) | Blocks once the agent's daily spend cap is reached | DENY |
| Approval router | Routes sensitive tools and over-threshold spend to a human | REQUIRE_APPROVAL |

Unknown agents fail safe: no policy found → DENY at risk 100.

## How it works

```
Agent calls tool → Firewall intercepts → Policies evaluated → Decision returned → Logged
```

Every decision is written to a **persistent, tamper-evident audit log**. Each entry is hash-chained to the one before it, so any later edit to a past record is detectable via `/audit/verify`.

## Endpoints

| Method | Path | Purpose |
|---|---|---|
| GET | `/` | Health check |
| POST | `/intercept` | Evaluate a tool call |
| GET | `/audit` | View the audit log |
| GET | `/audit/verify` | Verify the audit chain is intact |
| GET | `/approvals` | List pending approvals |
| POST | `/approvals/{id}/approve` | Approve a pending action |
| POST | `/approvals/{id}/deny` | Deny a pending action |

## Run it

```bash
cd apps/api
pip install -r requirements.txt
export AGENT_FIREWALL_API_KEY="your-key"
uvicorn main:app --port 8080
python demo_check.py   # runs every policy and verifies the audit chain
```

## Tech stack

- Python 3.11 + FastAPI
- Pydantic for schema validation
- SQLite for the audit log and approval queue
- YAML policy files
- Fly.io for deployment · MIT License — open core

## Roadmap

- Slack notifications for pending approvals
- Python SDK (`pip install agent-firewall`)
- Dashboard UI
- Purpose binding (flag actions that drift from an agent's declared purpose)
- LangChain / CrewAI integration examples
- Tuning the injection heuristics against real traffic

## License

MIT — free to use, self-host, and modify.
