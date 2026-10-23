import os
from fastapi import FastAPI, Header, HTTPException, Depends
from app.models.schemas import InterceptRequest, PolicyDecision, AuditEvent, ApprovalRecord
from app.evaluate.policy_engine import evaluate, redact_pii
from app.audit import store as audit_store
from app.approvals import store as approval_store

API_KEY = os.environ.get("AGENT_FIREWALL_API_KEY")
if not API_KEY:
    raise RuntimeError(
        "AGENT_FIREWALL_API_KEY is not set. Refusing to start: "
        "a firewall must never run with a default public key."
    )

app = FastAPI(title="Agent Firewall", version="0.2.0")


# Create tables at import so they exist however the app is started.
audit_store.init_db()
approval_store.init_db()


def require_key(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return True


@app.get("/")
def root():
    return {"status": "Agent Firewall is running", "version": "0.2.0"}


@app.post("/intercept", response_model=PolicyDecision)
def intercept(request: InterceptRequest, _=Depends(require_key)):
    decision = evaluate(request)

    # Redact PII before anything is persisted: the audit log and the
    # approval queue must never hold raw sensitive values.
    redacted_input, pii_types = redact_pii(request.tool_input)

    # A REQUIRE_APPROVAL decision opens a pending item a human can act on.
    if decision.decision == "REQUIRE_APPROVAL":
        approval = approval_store.create(
            ApprovalRecord(
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                tool_input=redacted_input,
                reason=decision.reason,
                risk_score=decision.risk_score,
            )
        )
        decision.approval_id = approval.id

    audit_store.record(
        AuditEvent(
            agent_id=request.agent_id,
            tool_name=request.tool_name,
            tool_input=redacted_input,
            decision=decision.decision,
            risk_score=decision.risk_score,
            reason=decision.reason,
            policy_id=decision.policy_id,
            session_id=request.session_id,
            pii_types=pii_types,
        )
    )
    return decision


@app.get("/audit")
def get_audit_log(limit: int = 100, _=Depends(require_key)):
    return audit_store.list_events(limit)


@app.get("/audit/verify")
def verify_audit(_=Depends(require_key)):
    return audit_store.verify_chain()


@app.get("/approvals")
def pending_approvals(_=Depends(require_key)):
    return approval_store.list_pending()


@app.post("/approvals/{approval_id}/approve")
def approve(approval_id: str, _=Depends(require_key)):
    result = approval_store.decide(approval_id, True)
    if not result:
        raise HTTPException(status_code=404, detail="Approval not found.")
    return result


@app.post("/approvals/{approval_id}/deny")
def deny(approval_id: str, _=Depends(require_key)):
    result = approval_store.decide(approval_id, False)
    if not result:
        raise HTTPException(status_code=404, detail="Approval not found.")
    return result
