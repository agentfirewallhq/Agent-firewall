# 🛡️ Agent Firewall

> Runtime governance proxy for AI agents. Intercept, evaluate, and log every tool call before it executes.

[![License: MIT](https://img.shields.io/badge/License-MIT-red.svg)](https://opensource.org/licenses/MIT)
[![API Status](https://img.shields.io/badge/API-Live-green)](https://agent-firewall-api.fly.dev/docs)

## What is Agent Firewall?

Agent Firewall is a thin security layer that sits between your AI agent and the real world. Every time an agent tries to take an action — send an email, delete a record, spend money — it passes through Agent Firewall first.

The firewall inspects the action, evaluates it against your policies, scores its risk, and returns a decision in under 10ms:

- **ALLOW** — action goes through
- **DENY** — action is blocked with a reason
- **REQUIRE_APPROVAL** — human must approve before execution

## Live API



https://agent-firewall-api.fly.dev


Interactive docs: [https://agent-firewall-api.fly.dev/docs](https://agent-firewall-api.fly.dev/docs)

## Quick Start

Send a tool call to the firewall:

```bash
curl -X POST https://agent-firewall-api.fly.dev/intercept \
  -H "Content-Type: application/json" \
  -d '{
    "agent_id": "agent-001",
    "tool_name": "send_email",
    "tool_input": {"to": "user@example.com", "body": "Hello"},
    "session_id": "session-001"
  }'


Response:

{
  "decision": "DENY",
  "risk_score": 80,
  "reason": "Tool 'send_email' is not in the allowed list for agent 'agent-001'",
  "policy_id": "tool_allowlist"
}


Core Policies



|Policy         |What it does                                                |Action|
|---------------|------------------------------------------------------------|------|
|Tool Allowlist |Each agent can only call permitted tools                    |DENY  |
|Budget Guard   |Blocks actions exceeding spend limits                       |DENY  |
|PII Detector   |Detects SSN, credit cards, email, phone in inputs           |DENY  |
|Approval Router|Routes high-risk actions to human via Slack                 |REVIEW|
|Purpose Binding|Prevents agents from drifting outside their declared purpose|DENY  |

How It Works

Agent calls tool → Firewall intercepts → Policy evaluated → Decision returned → Everything logged


Every decision is written to an immutable audit log with full context, risk score, and reason.

Endpoints

	•	GET / — Health check
	•	POST /intercept — Evaluate a tool call
	•	GET /audit — View audit log

Tech Stack

	•	Python 3.11 + FastAPI
	•	Pydantic for schema validation
	•	Fly.io for deployment
	•	MIT License — open core

Roadmap

	•	Slack approval notifications
	•	YAML policy files
	•	Python SDK (pip install agent-firewall)
	•	Dashboard UI
	•	LangChain / CrewAI integration examples

Early Access

We are onboarding our first 10 design partners for free 3-month access.

👉 Join the waitlist

License

MIT — free to use, self-host, and modify.

