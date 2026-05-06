"""Output node: persist the analysis report and mark session as analyzed."""
import dataclasses
import logging
import time
from pathlib import Path

import aiosqlite

from .ingest import ANALYSIS_DB

log = logging.getLogger("nodes.output")

REPORTS_DIR = Path("/data/reports")


async def output_node(state):
    if state.done:
        return state

    session_id = state.session_id
    if not session_id:
        return state

    if state.error:
        log.warning("Skipping output for %s due to earlier error: %s", session_id, state.error)
        return dataclasses.replace(state, done=True)

    report_path = _report_path(state)
    report_written = False
    try:
        REPORTS_DIR.mkdir(parents=True, exist_ok=True)
        report_path.write_text(_render_report(state), encoding="utf-8")
        log.info("Report written: %s", report_path)
        report_written = True
    except OSError as exc:
        log.error("Failed to write report for %s: %s", session_id, exc)

    if report_written:
        await _mark_analyzed(session_id)
    return dataclasses.replace(state, done=True)


def _render_report(state) -> str:
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    ttps_str = "\n".join(f"- {t}" for t in state.ttps) if state.ttps else "- None identified"
    commands_str = (
        "\n".join(f"- `{c}`" for c in state.commands[:20]) if state.commands else "- (none recorded)"
    )
    return f"""# Threat Intelligence Report — {state.session_id}

**Generated**: {now}
**Severity**: {state.severity.upper()}
**Attack Type**: {state.attack_type}

## Session Metadata

| Field | Value |
|---|---|
| Source IP | `{state.src_ip}` |
| Country | {state.country} |
| ASN / ISP | {state.asn_org} |
| Hop | {state.hop} |
| Duration | {state.duration:.1f}s |
| Commands | {state.command_count} |

## Observed TTPs

{ttps_str}

## Commands Recorded

{commands_str}

## Threat Context

{state.threat_context or "_No enrichment available._"}

## Analyst Summary

{state.summary or "_No summary generated._"}
"""


def _report_path(state) -> Path:
    """Build a sortable, scannable filename: <ISO-UTC>_<severity>_<session_id>.md.

    Uses the attack's start_time so the filename reflects when the event
    actually happened, not when analysis ran. Falls back to "now" only if
    start_time is missing (shouldn't happen in normal flow).
    """
    import datetime
    ts = state.start_time or datetime.datetime.now(datetime.timezone.utc).timestamp()
    when = datetime.datetime.fromtimestamp(ts, datetime.timezone.utc).strftime("%Y-%m-%dT%H%MZ")
    severity = (state.severity or "unknown").lower()
    safe_id = "".join(c if c.isalnum() or c in "-_" else "_" for c in state.session_id)
    return REPORTS_DIR / f"{when}_{severity}_{safe_id}.md"


async def _mark_analyzed(session_id: str) -> None:
    async with aiosqlite.connect(str(ANALYSIS_DB)) as db:
        await db.execute(
            "CREATE TABLE IF NOT EXISTS analyzed_sessions "
            "(session_id TEXT PRIMARY KEY, analyzed_at REAL)"
        )
        await db.execute(
            "INSERT OR REPLACE INTO analyzed_sessions (session_id, analyzed_at) VALUES (?, ?)",
            (session_id, time.time()),
        )
        await db.commit()
