"""
SQLite Persistence Layer
Handles users, risk history, scan history, compliance history, and alerts.
"""
import sqlite3
import os
from datetime import datetime, timezone

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))), "security.db")


def get_conn():
    conn = sqlite3.connect(DB_PATH)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = get_conn()
    conn.executescript("""
        CREATE TABLE IF NOT EXISTS users (
            user_id TEXT PRIMARY KEY,
            username TEXT UNIQUE NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password_hash TEXT NOT NULL,
            role TEXT NOT NULL,
            full_name TEXT,
            created_at TEXT,
            last_login TEXT,
            is_active INTEGER DEFAULT 1
        );

        CREATE TABLE IF NOT EXISTS risk_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            unified_score REAL,
            ml_score REAL,
            cspm_score REAL,
            ciem_score REAL,
            level TEXT
        );

        CREATE TABLE IF NOT EXISTS cspm_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            timestamp TEXT,
            vulnerability_id TEXT,
            title TEXT,
            severity TEXT,
            resource TEXT,
            status TEXT
        );

        CREATE TABLE IF NOT EXISTS ciem_history (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            scan_id TEXT,
            timestamp TEXT,
            risk_id TEXT,
            title TEXT,
            entity_name TEXT,
            entity_type TEXT,
            risk_level TEXT
        );

        CREATE TABLE IF NOT EXISTS alert_log (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT,
            alert_type TEXT,
            severity TEXT,
            message TEXT,
            email_sent INTEGER DEFAULT 0,
            recipient TEXT
        );
    """)
    conn.commit()
    conn.close()


# ── Risk History ──────────────────────────────────────────────────────────────

def save_risk_score(unified: float, ml: float, cspm: float, ciem: float, level: str):
    conn = get_conn()
    conn.execute(
        "INSERT INTO risk_history (timestamp, unified_score, ml_score, cspm_score, ciem_score, level) VALUES (?,?,?,?,?,?)",
        (datetime.now(timezone.utc).isoformat(), unified, ml, cspm, ciem, level)
    )
    conn.commit()
    conn.close()


def get_risk_trend_db(periods: int = 7):
    conn = get_conn()
    rows = conn.execute(
        "SELECT timestamp, unified_score, level FROM risk_history ORDER BY timestamp DESC LIMIT ?", (periods,)
    ).fetchall()
    conn.close()
    trend = [{"period": r["timestamp"][:10], "score": r["unified_score"], "level": r["level"]} for r in reversed(rows)]
    return trend


# ── CSPM / CIEM History ───────────────────────────────────────────────────────

def save_cspm_scan(findings: list):
    if not findings:
        return
    ts = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    for f in findings:
        conn.execute(
            "INSERT INTO cspm_history (scan_id, timestamp, vulnerability_id, title, severity, resource, status) VALUES (?,?,?,?,?,?,?)",
            (f.get("scan_id"), ts, f.get("vulnerability_id"), f.get("title"), f.get("severity"), f.get("resource"), f.get("status"))
        )
    conn.commit()
    conn.close()


def save_ciem_scan(findings: list):
    if not findings:
        return
    ts = datetime.now(timezone.utc).isoformat()
    conn = get_conn()
    for f in findings:
        conn.execute(
            "INSERT INTO ciem_history (scan_id, timestamp, risk_id, title, entity_name, entity_type, risk_level) VALUES (?,?,?,?,?,?,?)",
            (f.get("scan_id"), ts, f.get("risk_id"), f.get("title"), f.get("entity_name"), f.get("entity_type"), f.get("risk_level"))
        )
    conn.commit()
    conn.close()


def get_cspm_history(limit: int = 50):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM cspm_history ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_ciem_history(limit: int = 50):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM ciem_history ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Alert Log ─────────────────────────────────────────────────────────────────

def log_alert(alert_type: str, severity: str, message: str, email_sent: bool = False, recipient: str = ""):
    conn = get_conn()
    conn.execute(
        "INSERT INTO alert_log (timestamp, alert_type, severity, message, email_sent, recipient) VALUES (?,?,?,?,?,?)",
        (datetime.now(timezone.utc).isoformat(), alert_type, severity, message, int(email_sent), recipient)
    )
    conn.commit()
    conn.close()


def get_alert_log(limit: int = 100):
    conn = get_conn()
    rows = conn.execute(
        "SELECT * FROM alert_log ORDER BY timestamp DESC LIMIT ?", (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


# ── Compliance Trend ──────────────────────────────────────────────────────────

def save_compliance_score(score: float):
    conn = get_conn()
    # Reuse risk_history table's timestamp for compliance — store in alert_log as type
    conn.execute(
        "INSERT INTO alert_log (timestamp, alert_type, severity, message) VALUES (?,?,?,?)",
        (datetime.now(timezone.utc).isoformat(), "compliance_score", "info", str(score))
    )
    conn.commit()
    conn.close()


def get_compliance_trend_db(current_score: float):
    conn = get_conn()
    row = conn.execute(
        "SELECT message FROM alert_log WHERE alert_type='compliance_score' ORDER BY timestamp DESC LIMIT 1 OFFSET 6"
    ).fetchone()
    conn.close()
    week_ago = float(row["message"]) if row else current_score
    return {
        "direction": "improving" if current_score >= week_ago else "declining",
        "change_7d": round(current_score - week_ago, 1)
    }


# Initialize on import
init_db()
