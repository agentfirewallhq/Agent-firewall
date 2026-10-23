"""Persistent, tamper-evident audit log.

Each entry is hash-chained to the one before it:
    entry_hash = sha256(prev_hash + canonical_json(entry))
Change any stored row and every hash after it stops matching, so
`verify_chain()` can prove the log has not been altered.
"""
import sqlite3
import json
import hashlib
import os
import threading
from typing import List, Dict, Any

import datetime as _dt
from app.models.schemas import AuditEvent

_DB_PATH = os.environ.get("AGENT_FIREWALL_DB", "agent_firewall.db")
_GENESIS = "0" * 64
_AMOUNT_KEYS = ("amount_usd", "amount", "total_usd")
_lock = threading.Lock()


def _connect():
    conn = sqlite3.connect(_DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    with _connect() as conn:
        conn.execute(
            """
            CREATE TABLE IF NOT EXISTS audit_log (
                seq INTEGER PRIMARY KEY AUTOINCREMENT,
                id TEXT NOT NULL,
                created_at TEXT NOT NULL,
                agent_id TEXT NOT NULL,
                tool_name TEXT NOT NULL,
                tool_input TEXT NOT NULL,
                decision TEXT NOT NULL,
                risk_score INTEGER NOT NULL,
                reason TEXT NOT NULL,
                policy_id TEXT,
                session_id TEXT,
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            )
            """
        )
        conn.commit()


def _payload(row_or_event, created_at: str) -> Dict[str, Any]:
    return {
        "id": row_or_event["id"] if isinstance(row_or_event, dict) else row_or_event.id,
        "created_at": created_at,
        "agent_id": row_or_event["agent_id"] if isinstance(row_or_event, dict) else row_or_event.agent_id,
        "tool_name": row_or_event["tool_name"] if isinstance(row_or_event, dict) else row_or_event.tool_name,
        "tool_input": row_or_event["tool_input"] if isinstance(row_or_event, dict) else row_or_event.tool_input,
        "decision": row_or_event["decision"] if isinstance(row_or_event, dict) else row_or_event.decision,
        "risk_score": row_or_event["risk_score"] if isinstance(row_or_event, dict) else row_or_event.risk_score,
        "reason": row_or_event["reason"] if isinstance(row_or_event, dict) else row_or_event.reason,
        "policy_id": row_or_event["policy_id"] if isinstance(row_or_event, dict) else row_or_event.policy_id,
        "session_id": row_or_event["session_id"] if isinstance(row_or_event, dict) else row_or_event.session_id,
    }


def _hash(prev_hash: str, payload: Dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


def record(event: AuditEvent) -> Dict[str, Any]:
    with _lock, _connect() as conn:
        row = conn.execute("SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = row["entry_hash"] if row else _GENESIS
        payload = _payload(event, event.created_at.isoformat())
        entry_hash = _hash(prev_hash, payload)
        conn.execute(
            """INSERT INTO audit_log
               (id, created_at, agent_id, tool_name, tool_input, decision,
                risk_score, reason, policy_id, session_id, prev_hash, entry_hash)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                event.id, payload["created_at"], event.agent_id, event.tool_name,
                json.dumps(event.tool_input, default=str), event.decision,
                event.risk_score, event.reason, event.policy_id, event.session_id,
                prev_hash, entry_hash,
            ),
        )
        conn.commit()
    return {**payload, "entry_hash": entry_hash}


def list_events(limit: int = 100) -> List[Dict[str, Any]]:
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["tool_input"] = json.loads(d["tool_input"])
        out.append(d)
    return out


def daily_spend(agent_id: str, on_date: str = None) -> float:
    """Sum the USD amount of ALLOW'd actions for an agent on a given day (UTC)."""
    day = on_date or _dt.datetime.now(_dt.timezone.utc).date().isoformat()
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT tool_input FROM audit_log "
                "WHERE agent_id=? AND decision='ALLOW' AND substr(created_at,1,10)=?",
                (agent_id, day),
            ).fetchall()
    except sqlite3.OperationalError:
        return 0.0
    total = 0.0
    for r in rows:
        try:
            ti = json.loads(r["tool_input"])
        except Exception:
            continue
        if not isinstance(ti, dict):
            continue
        for k in _AMOUNT_KEYS:
            if k in ti:
                try:
                    total += float(ti[k])
                    break
                except (TypeError, ValueError):
                    pass
    return total


def verify_chain() -> Dict[str, Any]:
    """Recompute the whole chain. Any edit to a stored row breaks it."""
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY seq ASC").fetchall()
    prev = _GENESIS
    for r in rows:
        payload = _payload({**dict(r), "tool_input": json.loads(r["tool_input"])}, r["created_at"])
        if r["prev_hash"] != prev or r["entry_hash"] != _hash(prev, payload):
            return {"valid": False, "broken_at_seq": r["seq"], "entries": len(rows)}
        prev = r["entry_hash"]
    return {"valid": True, "entries": len(rows)}
