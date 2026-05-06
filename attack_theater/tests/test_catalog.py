"""Unit tests for Catalog — focus on mark_if_interesting threshold edges."""
import asyncio
from pathlib import Path

import pytest

from app.catalog import Catalog, SessionRecord


@pytest.fixture
async def catalog(tmp_path: Path) -> Catalog:
    c = Catalog(tmp_path / "test.db")
    await c.init()
    yield c
    await c.close()


def _start_event(session_id: str = "abc123", src_ip: str = "10.0.0.1") -> dict:
    return {
        "type": "session_started",
        "session_id": session_id,
        "hop": 1,
        "src_ip": src_ip,
        "start_time": 1_000_000.0,
        "tty_file_path": "/tmp/tty/abc123",
    }


def _end_event(session_id: str = "abc123", end_time: float = 1_000_025.0, cmd_count: int = 5) -> dict:
    return {
        "type": "session_ended",
        "session_id": session_id,
        "end_time": end_time,
        "command_count": cmd_count,
        "duration": end_time - 1_000_000.0,
    }


# ── record_start ───────────────────────────────────────────────────────────────

class TestRecordStart:
    async def test_inserts_session(self, catalog):
        await catalog.record_start(_start_event())
        rec = catalog.get("abc123")
        assert rec is not None
        assert rec.src_ip == "10.0.0.1"
        assert rec.hop == 1

    async def test_private_ip_gets_unknown_country(self, catalog):
        await catalog.record_start(_start_event(src_ip="192.168.1.1"))
        rec = catalog.get("abc123")
        assert rec.country == "Unknown"


# ── mark_if_interesting parametrized ─────────────────────────────────────────

@pytest.mark.parametrize("login_success, cmd_count, duration, expected", [
    # All conditions met
    (True,  3,  20.0, True),
    # Not enough commands
    (True,  2,  20.0, False),
    # Duration too short
    (True,  3,  19.0, False),
    # No login success
    (False, 5,  30.0, False),
    # Edge: exactly on threshold
    (True,  3,  20.0, True),
    # Edge: one command short
    (True,  2,  25.0, False),
    # Edge: 0.1s short
    (True,  3,  19.9, False),
    # All conditions exceeded
    (True,  10, 120.0, True),
])
async def test_mark_if_interesting(catalog, login_success, cmd_count, duration, expected):
    session_id = "sess_x"
    start = 1_000_000.0
    await catalog.record_start({
        "session_id": session_id,
        "hop": 1,
        "src_ip": "10.0.0.1",
        "start_time": start,
        "tty_file_path": "/tmp/t",
    })
    if login_success:
        await catalog.mark_login_success(session_id)
    await catalog.finalize({
        "session_id": session_id,
        "end_time": start + duration,
        "command_count": cmd_count,
    })
    rec = catalog.get(session_id)
    assert rec.is_interesting == expected


# ── append_command ────────────────────────────────────────────────────────────

class TestAppendCommand:
    async def test_increments_count(self, catalog):
        await catalog.record_start(_start_event())
        await catalog.append_command("abc123", "ls -la")
        await catalog.append_command("abc123", "whoami")
        rec = catalog.get("abc123")
        assert rec.command_count == 2

    async def test_no_op_for_unknown_session(self, catalog):
        await catalog.append_command("no_such_session", "ls")  # should not raise


# ── pick_next_archive ────────────────────────────────────────────────────────

class TestPickNextArchive:
    async def test_returns_none_when_empty(self, catalog):
        assert catalog.pick_next_archive([]) is None

    async def test_excludes_recent_played(self, catalog):
        sid = "interesting_one"
        await catalog.record_start(_start_event(session_id=sid))
        await catalog.mark_login_success(sid)
        await catalog.finalize({"session_id": sid, "end_time": 1_000_025.0, "command_count": 5})
        # Should be excluded
        result = catalog.pick_next_archive([sid])
        assert result is None

    async def test_returns_interesting_session(self, catalog):
        sid = "interesting_two"
        await catalog.record_start(_start_event(session_id=sid))
        await catalog.mark_login_success(sid)
        await catalog.finalize({"session_id": sid, "end_time": 1_000_025.0, "command_count": 5})
        result = catalog.pick_next_archive([])
        assert result is not None
        assert result.session_id == sid


# ── attacks_today_count ───────────────────────────────────────────────────────

async def test_attacks_today_count(catalog):
    import time
    now = time.time()
    for i in range(3):
        await catalog.record_start({
            "session_id": f"today_{i}",
            "hop": 1,
            "src_ip": "1.2.3.4",
            "start_time": now,
            "tty_file_path": None,
        })
    assert catalog.attacks_today_count() == 3


# ── persistence across restart ───────────────────────────────────────────────

async def test_reloads_from_db(tmp_path):
    db = tmp_path / "persist.db"
    c1 = Catalog(db)
    await c1.init()
    await c1.record_start(_start_event(session_id="persist1"))
    await c1.close()

    c2 = Catalog(db)
    await c2.init()
    rec = c2.get("persist1")
    assert rec is not None
    assert rec.src_ip == "10.0.0.1"
    await c2.close()
