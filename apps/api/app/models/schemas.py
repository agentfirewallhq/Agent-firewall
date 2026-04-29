from pydantic import BaseModel
from typing import Optional
from datetime import datetime
import uuid

class InterceptRequest(BaseModel):
    agent_id: str
    tool_name: str
    tool_input: dict
    session_id: Optional[str] = None

class PolicyDecision(BaseModel):
    decision: str  # ALLOW, DENY, REQUIRE_APPROVAL
    risk_score: int  # 0-100
    reason: str
    policy_id: Optional[str] = None

class AuditEvent(BaseModel):
    id: str = str(uuid.uuid4())
    created_at: datetime = datetime.utcnow()
    agent_id: str
    tool_name: str
    tool_input: dict
    decision: str
    risk_score: int
    reason: str

