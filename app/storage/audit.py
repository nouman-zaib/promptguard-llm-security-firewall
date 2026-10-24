import sqlite3
import json
import hashlib
from datetime import datetime, timezone
from typing import List, Dict, Any, Optional
from app.config import settings
from app.schemas import AuditLogRecord


def get_db_connection() -> sqlite3.Connection:
    conn = sqlite3.connect(settings.audit_db_path)
    conn.row_factory = sqlite3.Row
    return conn


def init_db() -> None:
    """Initializes the audit storage SQLite database and tables."""
    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS audit_events (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    request_id TEXT NOT NULL,
                    created_at TEXT NOT NULL,
                    action TEXT NOT NULL,
                    risk_score INTEGER NOT NULL,
                    category TEXT NOT NULL,
                    reasons TEXT NOT NULL,
                    model_id TEXT NOT NULL,
                    latency_ms REAL NOT NULL,
                    content_hash TEXT NOT NULL
                )
                """
            )
    finally:
        conn.close()


def compute_content_hash(prompt: str, context: str = "") -> str:
    """Computes a SHA-256 hash of the input to correlate events without storing sensitive raw text."""
    combined = f"{prompt}\n---\n{context}".encode("utf-8")
    return hashlib.sha256(combined).hexdigest()[:16]


def record_audit_event(
    request_id: str,
    action: str,
    risk_score: int,
    category: str,
    reasons: List[str],
    model_id: str,
    latency_ms: float,
    content_hash: str,
) -> AuditLogRecord:
    """Records a security evaluation event into SQLite audit log."""
    init_db()
    created_at = datetime.now(timezone.utc).isoformat()
    reasons_json = json.dumps(reasons)

    conn = get_db_connection()
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(
                """
                INSERT INTO audit_events (
                    request_id, created_at, action, risk_score,
                    category, reasons, model_id, latency_ms, content_hash
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    request_id,
                    created_at,
                    action,
                    risk_score,
                    category,
                    reasons_json,
                    model_id,
                    round(latency_ms, 2),
                    content_hash,
                ),
            )
            row_id = cursor.lastrowid
    finally:
        conn.close()

    return AuditLogRecord(
        id=row_id,
        request_id=request_id,
        created_at=created_at,
        action=action,
        risk_score=risk_score,
        category=category,
        reasons=reasons,
        model_id=model_id,
        latency_ms=round(latency_ms, 2),
        content_hash=content_hash,
    )


def get_recent_audit_events(limit: int = 50) -> List[Dict[str, Any]]:
    """Retrieves the latest audit events."""
    init_db()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute(
            """
            SELECT id, request_id, created_at, action, risk_score,
                   category, reasons, model_id, latency_ms, content_hash
            FROM audit_events
            ORDER BY id DESC
            LIMIT ?
            """,
            (limit,),
        )
        rows = cursor.fetchall()
        results = []
        for r in rows:
            results.append({
                "id": r["id"],
                "request_id": r["request_id"],
                "created_at": r["created_at"],
                "action": r["action"],
                "risk_score": r["risk_score"],
                "category": r["category"],
                "reasons": json.loads(r["reasons"]) if r["reasons"] else [],
                "model_id": r["model_id"],
                "latency_ms": r["latency_ms"],
                "content_hash": r["content_hash"],
            })
        return results
    finally:
        conn.close()


def get_audit_summary() -> Dict[str, Any]:
    """Retrieves aggregated statistics for the audit log."""
    init_db()
    conn = get_db_connection()
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT COUNT(*) FROM audit_events")
        total = cursor.fetchone()[0]

        cursor.execute("SELECT action, COUNT(*) FROM audit_events GROUP BY action")
        actions = dict(cursor.fetchall())

        cursor.execute("SELECT AVG(latency_ms), AVG(risk_score) FROM audit_events")
        avg_row = cursor.fetchone()
        avg_latency = round(avg_row[0], 2) if avg_row and avg_row[0] is not None else 0.0
        avg_score = round(avg_row[1], 1) if avg_row and avg_row[1] is not None else 0.0

        return {
            "total_requests": total,
            "actions": {
                "allow": actions.get("allow", 0),
                "review": actions.get("review", 0),
                "block": actions.get("block", 0),
            },
            "avg_latency_ms": avg_latency,
            "avg_risk_score": avg_score,
        }
    finally:
        conn.close()
