from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any
from datetime import datetime, timezone
import uuid


def _uuid() -> str:
    return str(uuid.uuid4())


def _now() -> datetime:
    return datetime.now(timezone.utc)


class ContextItem(BaseModel):
    """A piece of content the agent saw, tagged by where it came from.

    source:
      user      - typed by the human the agent is serving
      system    - the business's own trusted configuration
      trusted   - a vetted internal source
      untrusted - external text (web page, email, pasted content)
    """
    source: str
    content: str


class InterceptRequest(BaseModel):
    agent_id: str
    tool_name: str
    tool_input: Dict[str, Any]
    session_id: Optional[str] = None
    # Optional provenance: the content that led to this action.
    context: List[ContextItem] = Field(default_factory=list)


class PolicyDecision(BaseModel):
    decision: str  # ALLOW, DENY, REQUIRE_APPROVAL
    risk_score: int  # 0-100
    reason: str
    policy_id: Optional[str] = None
    approval_id: Optional[str] = None  # set when decision == REQUIRE_APPROVAL


class AuditEvent(BaseModel):
    # default_factory so each event gets its OWN id/timestamp
    # (the previous version computed these once at import time).
    id: str = Field(default_factory=_uuid)
    created_at: datetime = Field(default_factory=_now)
    agent_id: str
    tool_name: str
    tool_input: Dict[str, Any]
    decision: str
    risk_score: int
    reason: str
    policy_id: Optional[str] = None
    session_id: Optional[str] = None
    pii_types: List[str] = Field(default_factory=list)


class ApprovalRecord(BaseModel):
    id: str = Field(default_factory=_uuid)
    created_at: datetime = Field(default_factory=_now)
    agent_id: str
    tool_name: str
    tool_input: Dict[str, Any]
    reason: str
    risk_score: int
    status: str = "PENDING"  # PENDING, APPROVED, DENIED
    decided_at: Optional[datetime] = None
    decided_by: Optional[str] = None
