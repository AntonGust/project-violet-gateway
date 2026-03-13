"""
Ban Manager — Escalating IP bans stored in SQLite.
Shared with the filter gateway sidecar (reads bans.db).
"""

import logging
import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

log = logging.getLogger("ban_manager")

ESCALATION_DURATIONS = [
    timedelta(hours=1),    # Level 0: first offense
    timedelta(hours=6),    # Level 1
    timedelta(hours=24),   # Level 2
    timedelta(days=7),     # Level 3
    timedelta(days=30),    # Level 4: repeat offender
]


class BanManager:
    def __init__(self, db_path: Path):
        self.db_path = db_path
        self._init_db()

    def _init_db(self):
        conn = sqlite3.connect(str(self.db_path), timeout=5)
        conn.execute("""
            CREATE TABLE IF NOT EXISTS bans (
                ip           TEXT PRIMARY KEY,
                reason       TEXT NOT NULL,
                level        INTEGER DEFAULT 0,
                ban_until    TIMESTAMP NOT NULL,
                created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                hit_count    INTEGER DEFAULT 1
            )
        """)
        conn.execute(
            "CREATE INDEX IF NOT EXISTS idx_bans_until ON bans(ban_until)"
        )
        conn.commit()
        conn.close()

    def _get_conn(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.db_path), timeout=5)

    def ban_ip(self, ip: str, reason: str):
        """Ban an IP with escalating duration."""
        now = datetime.now(timezone.utc)
        conn = self._get_conn()
        try:
            row = conn.execute(
                "SELECT level, hit_count FROM bans WHERE ip = ?", (ip,)
            ).fetchone()

            if row:
                current_level = row[0]
                hit_count = row[1]
                # Escalate if not at max
                new_level = min(current_level + 1, len(ESCALATION_DURATIONS) - 1)
                duration = ESCALATION_DURATIONS[new_level]
                ban_until = now + duration

                conn.execute(
                    """UPDATE bans
                       SET reason = ?, level = ?, ban_until = ?,
                           updated_at = ?, hit_count = ?
                       WHERE ip = ?""",
                    (reason, new_level, ban_until.isoformat(), now.isoformat(),
                     hit_count + 1, ip),
                )
                log.info(
                    "Escalated ban: %s level %d→%d, until %s (reason: %s)",
                    ip, current_level, new_level, ban_until.isoformat(), reason,
                )
            else:
                level = 0
                duration = ESCALATION_DURATIONS[level]
                ban_until = now + duration

                conn.execute(
                    """INSERT INTO bans (ip, reason, level, ban_until, created_at, updated_at, hit_count)
                       VALUES (?, ?, ?, ?, ?, ?, 1)""",
                    (ip, reason, level, ban_until.isoformat(), now.isoformat(),
                     now.isoformat()),
                )
                log.info(
                    "New ban: %s level 0, until %s (reason: %s)",
                    ip, ban_until.isoformat(), reason,
                )

            conn.commit()
        except Exception:
            log.exception("Error banning IP %s", ip)
        finally:
            conn.close()

    def is_banned(self, ip: str) -> bool:
        conn = self._get_conn()
        try:
            now = datetime.now(timezone.utc).isoformat()
            row = conn.execute(
                "SELECT 1 FROM bans WHERE ip = ? AND ban_until > ?",
                (ip, now),
            ).fetchone()
            return row is not None
        finally:
            conn.close()
