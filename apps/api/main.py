import os
from fastapi import FastAPI, Header, HTTPException, Depends, Request
from fastapi.responses import FileResponse
from app.models.schemas import InterceptRequest, PolicyDecision, AuditEvent, ApprovalRecord
from app.evaluate.policy_engine import evaluate, redact_pii, mask_pii
from app.audit import store as audit_store
from app.approvals import store as approval_store

API_KEY = os.environ.get("AGENT_FIREWALL_API_KEY")
if not API_KEY:
    raise RuntimeError(
        "AGENT_FIREWALL_API_KEY is not set. Refusing to start: "
        "a firewall must never run with a default public key."
    )

app = FastAPI(title="Agent Firewall", version="0.2.1")


# Create tables at import so they exist however the app is started.
audit_store.init_db()
approval_store.init_db()


def require_key(x_api_key: str = Header(None)):
    if x_api_key != API_KEY:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return True


LANDING_PATH = os.path.join(os.path.dirname(__file__), "landing.html")


@app.get("/")
def root(request: Request):
    # Browsers get the landing page; API clients keep the JSON version reply.
    # httpx/curl default Accept (*/*) does not contain "text/html", so automated
    # checks are unaffected.
    accept = request.headers.get("accept", "")
    if "text/html" in accept and os.path.exists(LANDING_PATH):
        return FileResponse(LANDING_PATH, media_type="text/html")
    return {"status": "Agent Firewall is running", "version": "0.2.1"}


@app.post("/intercept", response_model=PolicyDecision)
def intercept(request: InterceptRequest, _=Depends(require_key)):
    decision = evaluate(request)

    # Redact PII before anything is persisted: the audit log and the
    # approval queue must never hold raw sensitive values.
    redacted_input, pii_types = redact_pii(request.tool_input)

    # A REQUIRE_APPROVAL decision opens a pending item a human can act on.
    # The queue stores partially masked input (c***@example.com) so the
    # approver can tell who the action is for without seeing raw PII.
    if decision.decision == "REQUIRE_APPROVAL":
        masked_input, _ = mask_pii(request.tool_input)
        approval = approval_store.create(
            ApprovalRecord(
                agent_id=request.agent_id,
                tool_name=request.tool_name,
                tool_input=masked_input,
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
