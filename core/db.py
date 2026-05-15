"""
core/db.py - SQLite persistence for scan history
"""

import sqlite3
import json
import time
import os

DB_PATH = os.path.join(os.path.dirname(os.path.dirname(__file__)), "data", "scans.db")


def _get_conn():
    os.makedirs(os.path.dirname(DB_PATH), exist_ok=True)
    conn = sqlite3.connect(DB_PATH, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_db():
    conn = _get_conn()
    conn.execute("""
        CREATE TABLE IF NOT EXISTS scan_history (
            id        INTEGER PRIMARY KEY AUTOINCREMENT,
            job_id    TEXT NOT NULL,
            scan_type TEXT NOT NULL,
            target    TEXT NOT NULL,
            status    TEXT DEFAULT 'running',
            result    TEXT,
            error     TEXT,
            started_at  REAL,
            finished_at REAL
        )
    """)
    conn.commit()
    conn.close()


def save_scan(job_id: str, scan_type: str, target: str):
    conn = _get_conn()
    conn.execute(
        "INSERT OR IGNORE INTO scan_history (job_id, scan_type, target, started_at) VALUES (?,?,?,?)",
        (job_id, scan_type, target, time.time())
    )
    conn.commit()
    conn.close()


def update_scan(job_id: str, status: str, result=None, error=None):
    conn = _get_conn()
    conn.execute(
        "UPDATE scan_history SET status=?, result=?, error=?, finished_at=? WHERE job_id=?",
        (status, json.dumps(result) if result else None, error, time.time(), job_id)
    )
    conn.commit()
    conn.close()


def get_history(limit: int = 50) -> list:
    conn = _get_conn()
    rows = conn.execute(
        "SELECT id, job_id, scan_type, target, status, started_at, finished_at FROM scan_history ORDER BY id DESC LIMIT ?",
        (limit,)
    ).fetchall()
    conn.close()
    return [dict(r) for r in rows]


def get_scan_result(job_id: str) -> dict | None:
    conn = _get_conn()
    row = conn.execute("SELECT * FROM scan_history WHERE job_id=?", (job_id,)).fetchone()
    conn.close()
    if not row:
        return None
    d = dict(row)
    if d.get("result"):
        d["result"] = json.loads(d["result"])
    return d
