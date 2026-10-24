"""Persistent, tamper-evident audit log.

Each entry is hash-chained to the one before it:
    entry_hash = sha256(prev_hash + canonical_json(entry))
Change any stored row and every hash after it stops matching, so
`verify_chain()` can prove the log has not been altered.

The chain head (last seq, last hash, row count) is also kept in the
audit_meta table, updated in the same transaction as each new row, so
deleting rows off the tail is caught too: the remaining chain is
internally consistent, but it no longer reaches the recorded head.
A writer with full database access could rewrite the head as well;
full protection against that needs an external anchor, which is
out of scope for this local log.
"""
import sqlite3
import json
import hashlib
import math
import os
import threading
from typing import List, Dict, Any

import datetime as _dt
from app.models.schemas import AuditEvent

_DB_PATH = os.environ.get("AGENT_FIREWALL_DB", "agent_firewall.db")
_GENESIS = "0" * 64
# Amount-like keys scanned at any depth. value_usd is only scanned at
# the top level: nested "value" fields are often non-money metadata.
_AMOUNT_KEYS_ANY = ("amount_usd", "amount", "total_usd")
_AMOUNT_KEYS_TOP = ("value_usd",)
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
                pii_types TEXT NOT NULL DEFAULT '[]',
                prev_hash TEXT NOT NULL,
                entry_hash TEXT NOT NULL
            )
            """
        )
        conn.commit()
        # Migration for databases created before v0.2.1.
        try:
            conn.execute("ALTER TABLE audit_log ADD COLUMN pii_types TEXT NOT NULL DEFAULT '[]'")
            conn.commit()
        except sqlite3.OperationalError:
            pass  # column already exists
        # v0.2.2: hash version per row, so pii_types can join the
        # hashed payload for new rows without breaking old chains.
        try:
            conn.execute("ALTER TABLE audit_log ADD COLUMN hash_version INTEGER NOT NULL DEFAULT 1")
            conn.commit()
        except sqlite3.OperationalError:
            pass  # column already exists
        # Chain-head anchor (see module docstring). Seeded from the
        # current head for pre-upgrade databases; that means a tail
        # deletion performed BEFORE this upgrade is not detectable,
        # only deletions after the anchor exists.
        conn.execute(
            "CREATE TABLE IF NOT EXISTS audit_meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)"
        )
        head_row = conn.execute("SELECT value FROM audit_meta WHERE key='head'").fetchone()
        if not head_row:
            last = conn.execute(
                "SELECT seq, entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1"
            ).fetchone()
            count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
            if last:
                head = {"last_seq": last["seq"], "last_hash": last["entry_hash"], "entries": count}
            else:
                head = {"last_seq": 0, "last_hash": _GENESIS, "entries": 0}
            conn.execute(
                "INSERT INTO audit_meta (key, value) VALUES ('head', ?)", (json.dumps(head),)
            )
        conn.commit()


def _payload(row_or_event, created_at: str, include_pii_types: bool = False) -> Dict[str, Any]:
    d = {
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
    if include_pii_types:
        if isinstance(row_or_event, dict):
            try:
                d["pii_types"] = json.loads(row_or_event.get("pii_types") or "[]")
            except Exception:
                d["pii_types"] = []
        else:
            d["pii_types"] = list(row_or_event.pii_types)
    return d


def extract_amount(tool_input: Any) -> tuple:
    """Find the action's USD amount, wherever it hides.

    Scans amount_usd/amount/total_usd at any depth (dicts and lists)
    plus top-level value_usd, and returns (amount, invalid):
    - amount is the largest finite, non-negative value found, else 0.0.
      Taking the max is fail-safe for caps: a hidden large amount
      cannot masquerade as $0.
    - invalid is True when any scanned scalar is negative, non-finite
      (NaN/inf), or an unparseable string. None, dicts and lists in
      amount positions are skipped, not treated as money.
    Callers enforcing limits must DENY on invalid; callers totalling
    spend use amount (which already excludes the bad values).
    """
    valid: List[float] = []
    invalid = False

    def scan_value(value: Any) -> None:
        nonlocal invalid
        if isinstance(value, bool) or value is None or isinstance(value, (dict, list)):
            return
        try:
            num = float(value)
        except (TypeError, ValueError):
            invalid = True
            return
        if not math.isfinite(num) or num < 0:
            invalid = True
            return
        valid.append(num)

    def walk(node: Any, top: bool) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k in _AMOUNT_KEYS_ANY or (top and k in _AMOUNT_KEYS_TOP):
                    scan_value(v)
                else:
                    walk(v, False)
        elif isinstance(node, list):
            for item in node:
                walk(item, False)

    if isinstance(tool_input, dict):
        walk(tool_input, True)
    return (max(valid) if valid else 0.0, invalid)


def _spendable(tool_input: Any) -> float:
    """Amount a stored row contributes to daily spend: the largest
    finite, non-negative amount found, else 0.0. Legacy rows recorded
    before amount validation (negative or NaN ALLOWs) contribute 0,
    which closes the old hole instead of carrying it forward."""
    return extract_amount(tool_input)[0]


def _hash(prev_hash: str, payload: Dict[str, Any]) -> str:
    canonical = json.dumps(payload, sort_keys=True, default=str)
    return hashlib.sha256((prev_hash + canonical).encode()).hexdigest()


def record(event: AuditEvent) -> Dict[str, Any]:
    with _lock, _connect() as conn:
        row = conn.execute("SELECT entry_hash FROM audit_log ORDER BY seq DESC LIMIT 1").fetchone()
        prev_hash = row["entry_hash"] if row else _GENESIS
        # v2 payload: pii_types joins the hash, so tampering with the
        # redaction metadata breaks the chain like any other edit.
        payload = _payload(event, event.created_at.isoformat(), include_pii_types=True)
        entry_hash = _hash(prev_hash, payload)
        cur = conn.execute(
            """INSERT INTO audit_log
               (id, created_at, agent_id, tool_name, tool_input, decision,
                risk_score, reason, policy_id, session_id, pii_types, prev_hash, entry_hash,
                hash_version)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,2)""",
            (
                event.id, payload["created_at"], event.agent_id, event.tool_name,
                json.dumps(event.tool_input, default=str), event.decision,
                event.risk_score, event.reason, event.policy_id, event.session_id,
                json.dumps(event.pii_types), prev_hash, entry_hash,
            ),
        )
        count = conn.execute("SELECT COUNT(*) FROM audit_log").fetchone()[0]
        conn.execute(
            "INSERT INTO audit_meta (key, value) VALUES ('head', ?) "
            "ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            (json.dumps(
                {"last_seq": cur.lastrowid, "last_hash": entry_hash, "entries": count}
            ),),
        )
        conn.commit()
    return {**payload, "entry_hash": entry_hash}


def list_events(limit: int = 100) -> List[Dict[str, Any]]:
    # Bounded: SQLite treats LIMIT -1 as "no limit", so invalid
    # values fall back to the default instead of dumping the log.
    try:
        limit = int(limit)
    except (TypeError, ValueError):
        limit = 100
    if limit < 1:
        limit = 100
    limit = min(limit, 1000)
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY seq DESC LIMIT ?", (limit,)).fetchall()
    out = []
    for r in rows:
        d = dict(r)
        d["tool_input"] = json.loads(d["tool_input"])
        try:
            d["pii_types"] = json.loads(d.get("pii_types") or "[]")
        except Exception:
            d["pii_types"] = []
        out.append(d)
    return out


def daily_spend(agent_id: str, on_date: str = None) -> float:
    """Sum the USD amount of money that actually moved for an agent
    on a given day (UTC): ALLOW decisions plus human-APPROVED ones.
    REQUIRE_APPROVAL rows are not counted (nothing moved yet), so
    approving an action cannot double-count it, and approved spend
    can no longer slip past the cap."""
    day = on_date or _dt.datetime.now(_dt.timezone.utc).date().isoformat()
    try:
        with _connect() as conn:
            rows = conn.execute(
                "SELECT tool_input FROM audit_log "
                "WHERE agent_id=? AND decision IN ('ALLOW','APPROVED') AND substr(created_at,1,10)=?",
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
        total += _spendable(ti)
    return total


def verify_chain() -> Dict[str, Any]:
    """Recompute the whole chain and check it against the head anchor.

    Any edit to a stored row breaks it, and deleting rows off the tail
    leaves a chain that no longer reaches the recorded head. Pre-upgrade
    databases report head "unanchored" until their first post-upgrade
    record anchors them."""
    with _connect() as conn:
        rows = conn.execute("SELECT * FROM audit_log ORDER BY seq ASC").fetchall()
        head_row = conn.execute("SELECT value FROM audit_meta WHERE key='head'").fetchone()
    prev = _GENESIS
    for r in rows:
        keys = r.keys()
        version = r["hash_version"] if "hash_version" in keys else 1
        payload = _payload(
            {**dict(r), "tool_input": json.loads(r["tool_input"])},
            r["created_at"],
            include_pii_types=(version == 2),
        )
        if r["prev_hash"] != prev or r["entry_hash"] != _hash(prev, payload):
            return {"valid": False, "broken_at_seq": r["seq"], "entries": len(rows)}
        prev = r["entry_hash"]
    if not head_row:
        return {"valid": True, "entries": len(rows), "head": "unanchored"}
    try:
        head = json.loads(head_row["value"])
    except Exception:
        return {"valid": False, "entries": len(rows), "reason": "unreadable chain head"}
    last_seq = rows[-1]["seq"] if rows else 0
    last_hash = rows[-1]["entry_hash"] if rows else _GENESIS
    if head.get("entries") != len(rows) or head.get("last_seq") != last_seq or head.get("last_hash") != last_hash:
        return {
            "valid": False,
            "entries": len(rows),
            "reason": "chain head mismatch: log ends at seq "
            f"{last_seq} with {len(rows)} entries, but the recorded head is "
            f"seq {head.get('last_seq')} with {head.get('entries')} entries "
            "(rows may have been deleted)",
        }
    return {"valid": True, "entries": len(rows), "head": "ok"}
