"""Session catalog backed by SQLite. All mutations return new records (immutable pattern)."""
import asyncio
import dataclasses
import json
import random
from dataclasses import dataclass, field
from datetime import date, datetime, timezone
from pathlib import Path
from typing import Optional

import aiosqlite

from .geo import lookup

DB_DEFAULT_PATH = Path("/data/theater.db")

_SCHEMA = """
CREATE TABLE IF NOT EXISTS sessions (
    session_id    TEXT PRIMARY KEY,
    hop           INTEGER,
    src_ip        TEXT,
    country       TEXT,
    country_code  TEXT,
    asn_org       TEXT,
    lat           REAL,
    lon           REAL,
    start_time    REAL,
    end_time      REAL,
    command_count INTEGER DEFAULT 0,
    duration      REAL,
    tty_file_path TEXT,
    is_interesting INTEGER DEFAULT 0,
    commands_json TEXT DEFAULT '[]'
);
CREATE INDEX IF NOT EXISTS idx_interesting ON sessions (is_interesting);
CREATE INDEX IF NOT EXISTS idx_start_time  ON sessions (start_time);
"""

_MIN_COMMANDS = 3
_MIN_DURATION_SEC = 20.0


@dataclass(frozen=True)
class SessionRecord:
    session_id: str
    hop: int
    src_ip: str
    country: str = "Unknown"
    country_code: str = ""
    asn_org: str = "Unknown"
    lat: Optional[float] = None
    lon: Optional[float] = None
    start_time: float = 0.0
    end_time: Optional[float] = None
    command_count: int = 0
    duration: Optional[float] = None
    tty_file_path: Optional[str] = None
    is_interesting: bool = False
    commands: tuple[str, ...] = ()


class Catalog:
    def __init__(self, db_path: Path = DB_DEFAULT_PATH):
        self._db_path = db_path
        self._sessions: dict[str, SessionRecord] = {}
        self._login_successes: set[str] = set()
        self._db: Optional[aiosqlite.Connection] = None
        self._lock = asyncio.Lock()

    async def init(self) -> None:
        self._db = await aiosqlite.connect(str(self._db_path))
        await self._db.execute("PRAGMA journal_mode=WAL")
        await self._db.executescript(_SCHEMA)
        # Migrate existing DBs that predate commands_json column
        try:
            await self._db.execute("ALTER TABLE sessions ADD COLUMN commands_json TEXT DEFAULT '[]'")
        except Exception:
            pass  # column already exists
        await self._db.commit()
        await self._load_from_db()

    async def close(self) -> None:
        if self._db:
            await self._db.close()

    async def record_start(self, event: dict) -> None:
        async with self._lock:
            session_id = event["session_id"]
            geo = lookup(event["src_ip"])
            rec = SessionRecord(
                session_id=session_id,
                hop=event["hop"],
                src_ip=event["src_ip"],
                country=geo.country,
                country_code=geo.country_code,
                asn_org=geo.asn_org,
                lat=geo.lat,
                lon=geo.lon,
                start_time=event["start_time"],
                tty_file_path=event.get("tty_file_path"),
            )
            self._sessions[session_id] = rec
            await self._persist(rec)

    async def append_command(self, session_id: str, command: str) -> None:
        async with self._lock:
            rec = self._sessions.get(session_id)
            if rec is None:
                return
            new_commands = (*rec.commands, command)
            updated = dataclasses.replace(
                rec,
                command_count=rec.command_count + 1,
                commands=new_commands,
            )
            self._sessions[session_id] = updated
            await self._db.execute(
                "UPDATE sessions SET command_count=?, commands_json=? WHERE session_id=?",
                (updated.command_count, json.dumps(list(new_commands)), session_id),
            )
            await self._db.commit()

    async def mark_login_success(self, session_id: str) -> None:
        self._login_successes.add(session_id)

    async def update_tty_path(self, session_id: str, tty_path: str) -> None:
        async with self._lock:
            rec = self._sessions.get(session_id)
            if rec is None:
                return
            updated = dataclasses.replace(rec, tty_file_path=tty_path)
            self._sessions[session_id] = updated
            await self._db.execute(
                "UPDATE sessions SET tty_file_path=? WHERE session_id=?",
                (tty_path, session_id),
            )
            await self._db.commit()

    async def finalize(self, event: dict) -> None:
        async with self._lock:
            session_id = event["session_id"]
            rec = self._sessions.get(session_id)
            if rec is None:
                return
            end_time = event["end_time"]
            duration = end_time - rec.start_time if rec.start_time else None
            # Use max of tracked count vs cowrie's reported count (handles missed events)
            cmd_count = max(event.get("command_count", 0), rec.command_count)
            interesting = (
                session_id in self._login_successes
                and cmd_count >= _MIN_COMMANDS
                and (duration or 0.0) >= _MIN_DURATION_SEC
            )
            updated = dataclasses.replace(
                rec,
                end_time=end_time,
                command_count=cmd_count,
                duration=duration,
                is_interesting=interesting,
            )
            self._sessions[session_id] = updated
            await self._db.execute(
                "UPDATE sessions SET end_time=?, command_count=?, duration=?, is_interesting=?"
                " WHERE session_id=?",
                (end_time, cmd_count, duration, int(interesting), session_id),
            )
            await self._db.commit()

    def pick_next_archive(self, exclude_ids: list[str]) -> Optional[SessionRecord]:
        candidates = [
            r for r in self._sessions.values()
            if r.is_interesting and r.session_id not in exclude_ids and r.tty_file_path
        ]
        return random.choice(candidates) if candidates else None

    def get(self, session_id: str) -> Optional[SessionRecord]:
        return self._sessions.get(session_id)

    def recent_pins(self, n: int = 50) -> list[dict]:
        with_geo = [r for r in self._sessions.values() if r.lat is not None and r.lon is not None]
        top = sorted(with_geo, key=lambda r: r.start_time, reverse=True)[:n]
        return [{"lat": r.lat, "lon": r.lon, "country_code": r.country_code} for r in top]

    def top_countries_today(self) -> list[dict]:
        from collections import Counter
        today_start = _today_epoch()
        counts: Counter[str] = Counter(
            r.country
            for r in self._sessions.values()
            if r.start_time >= today_start and r.country != "Unknown"
        )
        code_map = {r.country: r.country_code for r in self._sessions.values()}
        return [
            {"country": country, "count": count, "country_code": code_map.get(country, "")}
            for country, count in counts.most_common(5)
        ]

    def attacks_today_count(self) -> int:
        today_start = _today_epoch()
        return sum(1 for r in self._sessions.values() if r.start_time >= today_start)

    async def _load_from_db(self) -> None:
        cols = (
            "session_id, hop, src_ip, country, country_code, asn_org,"
            " lat, lon, start_time, end_time, command_count, duration,"
            " tty_file_path, is_interesting, commands_json"
        )
        async with self._db.execute(f"SELECT {cols} FROM sessions") as cur:
            async for row in cur:
                try:
                    cmds = tuple(json.loads(row[14] or "[]"))
                except (json.JSONDecodeError, TypeError):
                    cmds = ()
                rec = SessionRecord(
                    session_id=row[0],
                    hop=row[1] or 0,
                    src_ip=row[2] or "",
                    country=row[3] or "Unknown",
                    country_code=row[4] or "",
                    asn_org=row[5] or "Unknown",
                    lat=row[6],
                    lon=row[7],
                    start_time=row[8] or 0.0,
                    end_time=row[9],
                    command_count=row[10] or 0,
                    duration=row[11],
                    tty_file_path=row[12],
                    is_interesting=bool(row[13]),
                    commands=cmds,
                )
                self._sessions[rec.session_id] = rec

    async def _persist(self, rec: SessionRecord) -> None:
        await self._db.execute(
            """INSERT OR REPLACE INTO sessions
               (session_id, hop, src_ip, country, country_code, asn_org,
                lat, lon, start_time, end_time, command_count, duration,
                tty_file_path, is_interesting, commands_json)
               VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)""",
            (
                rec.session_id, rec.hop, rec.src_ip,
                rec.country, rec.country_code, rec.asn_org,
                rec.lat, rec.lon, rec.start_time, rec.end_time,
                rec.command_count, rec.duration,
                rec.tty_file_path, int(rec.is_interesting),
                json.dumps(list(rec.commands)),
            ),
        )
        await self._db.commit()


def _today_epoch() -> float:
    today = datetime.now(timezone.utc).date()
    return datetime(today.year, today.month, today.day, tzinfo=timezone.utc).timestamp()
