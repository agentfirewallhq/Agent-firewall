import os
import hmac
import threading
from fastapi import FastAPI, Header, HTTPException, Depends
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

app = FastAPI(title="Agent Firewall", version="0.2.2")

# Serializes the evaluate-then-record sequence for /intercept.
# Without this, two requests arriving at the same moment can both
# pass the daily-cap check before either is recorded. This guards a
# single process; a multi-worker deployment needs DB-level
# serialization instead.
_intercept_lock = threading.Lock()


# Create tables at import so they exist however the app is started.
audit_store.init_db()
approval_store.init_db()


def require_key(x_api_key: str = Header(None)):
    try:
        ok = x_api_key is not None and hmac.compare_digest(x_api_key, API_KEY)
    except (TypeError, ValueError):
        ok = False
    if not ok:
        raise HTTPException(status_code=401, detail="Invalid or missing API key.")
    return True


@app.get("/")
def root():
    return {"status": "Agent Firewall is running", "version": "0.2.2"}


@app.post("/intercept", response_model=PolicyDecision)
def intercept(request: InterceptRequest, _=Depends(require_key)):
    with _intercept_lock:
        decision = _intercept_locked(request)
    return decision


def _intercept_locked(request: InterceptRequest) -> PolicyDecision:
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
    try:
        result = approval_store.decide(approval_id, True)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    if not result:
        raise HTTPException(status_code=404, detail="Approval not found.")
    # Approval decisions are audit events too: without this, an
    # approved action leaves no trace of who said yes, and approved
    # spend never counts toward the daily cap. The event carries the
    # approval id and the amount only, not the action's input: the
    # original REQUIRE_APPROVAL event already holds the redacted
    # input, and the amount is what daily-spend accounting needs.
    approved_amount, _ = audit_store.extract_amount(result["tool_input"])
    audit_store.record(
        AuditEvent(
            agent_id=result["agent_id"],
            tool_name=result["tool_name"],
            tool_input={"approval_id": approval_id, "amount_usd": approved_amount},
            decision="APPROVED",
            risk_score=result["risk_score"],
            reason=f"Human approved approval {approval_id}.",
            policy_id="approval_decision",
        )
    )
    return result


@app.post("/approvals/{approval_id}/deny")
def deny(approval_id: str, _=Depends(require_key)):
    try:
        result = approval_store.decide(approval_id, False)
    except ValueError as e:
        raise HTTPException(status_code=409, detail=str(e))
    if not result:
        raise HTTPException(status_code=404, detail="Approval not found.")
    audit_store.record(
        AuditEvent(
            agent_id=result["agent_id"],
            tool_name=result["tool_name"],
            tool_input={"approval_id": approval_id},
            decision="DENIED",
            risk_score=result["risk_score"],
            reason=f"Human denied approval {approval_id}.",
            policy_id="approval_decision",
        )
    )
    return result
