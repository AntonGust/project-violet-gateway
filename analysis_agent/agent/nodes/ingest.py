"""Ingest node: fetch the next unanalyzed interesting session from theater.db."""
import logging
import os
from pathlib import Path

import aiosqlite

from ..state import SessionAnalysisState

log = logging.getLogger("nodes.ingest")

THEATER_DB = Path(os.environ.get("THEATER_DB_PATH", "/data/theater.db"))
ANALYSIS_DB = Path(os.environ.get("ANALYSIS_DB_PATH", "/data/analysis.db"))

_ANALYSIS_SCHEMA = """
CREATE TABLE IF NOT EXISTS analyzed_sessions (
    session_id TEXT PRIMARY KEY,
    analyzed_at REAL
);
"""


async def ingest_node(state: SessionAnalysisState) -> SessionAnalysisState:
    """Load the next unanalyzed interesting session. Sets done=True if none found."""
    import time

    async with aiosqlite.connect(str(ANALYSIS_DB)) as adb:
        await adb.execute("PRAGMA journal_mode=WAL")
        await adb.executescript(_ANALYSIS_SCHEMA)
        await adb.commit()

        if not THEATER_DB.exists():
            log.warning("theater.db not found at %s", THEATER_DB)
            return _done(state)

        async with aiosqlite.connect(str(THEATER_DB)) as tdb:
            # analyzed_sessions lives in analysis.db; ATTACH so the NOT IN
            # subquery can reference it without a second round-trip.
            await tdb.execute(f"ATTACH DATABASE '{ANALYSIS_DB}' AS adb")
            async with tdb.execute(
                """SELECT t.session_id, t.src_ip, t.country, t.asn_org,
                          t.hop, t.duration, t.command_count, t.tty_file_path,
                          t.commands_json
                   FROM sessions t
                   WHERE t.is_interesting = 1
                     AND t.session_id NOT IN (
                         SELECT session_id FROM adb.analyzed_sessions
                     )
                   ORDER BY t.start_time ASC
                   LIMIT 1"""
            ) as cursor:
                row = await cursor.fetchone()

        if row is None:
            log.info("No new sessions to analyze")
            return _done(state)

        session_id, src_ip, country, asn_org, hop, duration, command_count, tty_path, commands_json = row
        log.info("Ingesting session %s from %s (%s)", session_id, src_ip, country)

    import json
    try:
        commands = list(json.loads(commands_json or "[]"))
    except (json.JSONDecodeError, TypeError):
        commands = []

    return SessionAnalysisState(
        session_id=session_id,
        src_ip=src_ip or "",
        country=country or "Unknown",
        asn_org=asn_org or "Unknown",
        hop=hop or 0,
        duration=duration or 0.0,
        command_count=command_count or 0,
        tty_file_path=tty_path,
        commands=commands,
    )


def _done(state: SessionAnalysisState) -> SessionAnalysisState:
    from dataclasses import replace
    return replace(state, done=True)
