from fastapi import FastAPI
from app.models.schemas import InterceptRequest, PolicyDecision, AuditEvent
from app.evaluate.policy_engine import evaluate
import uuid
from datetime import datetime

app = FastAPI(title="Agent Firewall")

audit_log = []

@app.get("/")
def root():
    return {"status": "Agent Firewall is running"}

@app.post("/intercept")
def intercept(request: InterceptRequest):
    
    # Step 1: evaluate against policies
    decision = evaluate(request)

    # Step 2: log it
    event = AuditEvent(
        id=str(uuid.uuid4()),
        created_at=datetime.utcnow(),
        agent_id=request.agent_id,
        tool_name=request.tool_name,
        tool_input=request.tool_input,
        decision=decision.decision,
        risk_score=decision.risk_score,
        reason=decision.reason,
    )
    audit_log.append(event)

    return decision

@app.get("/audit")
def get_audit_log():
    return audit_log

