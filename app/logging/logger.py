from __future__ import annotations

import sqlite3
import time
from pathlib import Path

from app.config import DB_PATH


CREATE_TABLE = """
CREATE TABLE IF NOT EXISTS requests (
    id              INTEGER PRIMARY KEY AUTOINCREMENT,
    timestamp       REAL    NOT NULL,
    user_id         TEXT    NOT NULL,
    query           TEXT    NOT NULL,
    injection_score REAL    NOT NULL DEFAULT 0,
    abuse_score     REAL    NOT NULL DEFAULT 0,
    attack_detected INTEGER NOT NULL DEFAULT 0,
    blocked         INTEGER NOT NULL DEFAULT 0,
    response_time   REAL    NOT NULL DEFAULT 0
)
"""


class RequestLogger:
    """
    Appends one row per request to a SQLite database.
    Thread-safe because each call opens its own connection.
    """

    def __init__(self, db_path: str = DB_PATH):
        self.db_path = db_path
        Path(db_path).parent.mkdir(parents=True, exist_ok=True)
        self._init()

    def _init(self) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(CREATE_TABLE)
            conn.commit()

    def log(
        self,
        user_id: str,
        query: str,
        injection_score: float = 0.0,
        abuse_score: float = 0.0,
        attack_detected: bool = False,
        blocked: bool = False,
        response_time: float = 0.0,
    ) -> None:
        with sqlite3.connect(self.db_path) as conn:
            conn.execute(
                """INSERT INTO requests
                   (timestamp, user_id, query, injection_score, abuse_score,
                    attack_detected, blocked, response_time)
                   VALUES (?, ?, ?, ?, ?, ?, ?, ?)""",
                (
                    time.time(),
                    user_id,
                    query[:2000],  # cap stored query length
                    round(injection_score, 4),
                    round(abuse_score, 4),
                    int(attack_detected),
                    int(blocked),
                    round(response_time, 4),
                ),
            )
            conn.commit()

    def recent(self, limit: int = 20) -> list[dict]:
        """Return the most recent N log rows as dicts."""
        with sqlite3.connect(self.db_path) as conn:
            conn.row_factory = sqlite3.Row
            rows = conn.execute(
                "SELECT * FROM requests ORDER BY id DESC LIMIT ?", (limit,)
            ).fetchall()
        return [dict(r) for r in rows]

    def attack_summary(self) -> dict:
        """High-level counts for a quick status check."""
        with sqlite3.connect(self.db_path) as conn:
            total = conn.execute("SELECT COUNT(*) FROM requests").fetchone()[0]
            attacks = conn.execute(
                "SELECT COUNT(*) FROM requests WHERE attack_detected = 1"
            ).fetchone()[0]
            blocked = conn.execute(
                "SELECT COUNT(*) FROM requests WHERE blocked = 1"
            ).fetchone()[0]
        return {"total_requests": total, "attacks_detected": attacks, "requests_blocked": blocked}
