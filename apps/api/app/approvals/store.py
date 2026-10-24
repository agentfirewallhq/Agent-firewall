"""Human-approval queue for REQUIRE_APPROVAL decisions."""
import sqlite3
import json
import os
import threading
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional

from app.models.schemas import ApprovalRecord

_DB_PATH = os.environ.get("AGENT_FIREWALL_DB", "agent_firewall.db")
_lock = threading.Lock()


def _connect():
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS approvals (
                id TEXT PRIMARY KEY,
                created_at TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                tool_input TEXT NOT NULL,
                reason TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                status TEXT NOT NULL,
                decided_at TEXT,
                decided_by TEXT
            )
            """
        )
        conn.commit()


def create(record: ApprovalRecord) -> ApprovalRecord:
    with _lock, _connect() as conn:
        conn.execute(
            """INSERT INTO approvals
               (id, created_at, agent_id, tool_name, tool_input, reason, risk_score, status, decided_at, decided_by)
               VALUES (?,?,?,?,?,?,?,?,?,?)""",
            (
                record.id, record.created_at.isoformat(), record.agent_id, record.tool_name,
                json.dumps(record.tool_input, default=str), record.reason, record.risk_score,
                record.status, None, None,
            ),
        )
        conn.commit()
    return record


def list_pending() -> List[Dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM approvals WHERE status='PENDING' ORDER BY created_at ASC").fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["tool_input"] = json.loads(d["tool_input"])
        out.append(d)
    return out


def decide(approval_id: str, approve: bool, decided_by: str = "human") -> Optional[Dict[str, Any]]:
    """Decide a pending approval. Raises ValueError if the approval
    was already decided: a denied action must never become approved
    later by deciding it again, and vice versa."""
    with _lock, _connect() as conn:
        row = conn.execute("SELECT id, status FROM approvals WHERE id=?", (approval_id,)).fetchone()
        if not row:
            return None
        if row["status"] != "PENDING":
            raise ValueError(f"Approval {approval_id} already decided: {row['status']}")
        conn.execute(
            "UPDATE approvals SET status=?, decided_at=?, decided_by=? WHERE id=?",
            ("APPROVED" if approve else "DENIED", datetime.now(timezone.utc).isoformat(), decided_by, approval_id),
        )
        conn.commit()
        row = conn.execute("SELECT * FROM approvals WHERE id=?", (approval_id,)).fetchone()
    d = dict(row)
    d["tool_input"] = json.loads(d["tool_input"])
    return d
