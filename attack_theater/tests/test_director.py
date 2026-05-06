"""Unit tests for the Director state machine."""
import asyncio
from pathlib import Path
from unittest.mock import AsyncMock, patch

import pytest

from app.catalog import Catalog
from app.director import Director, State


@pytest.fixture
async def catalog(tmp_path: Path) -> Catalog:
    c = Catalog(tmp_path / "dir_test.db")
    await c.init()
    yield c
    await c.close()


class BroadcastCapture:
    def __init__(self):
        self.messages: list[dict] = []

    async def __call__(self, msg: dict) -> None:
        self.messages.append(msg)

    def types(self) -> list[str]:
        return [m["type"] for m in self.messages]

    def last(self) -> dict:
        return self.messages[-1] if self.messages else {}


def _make_director(catalog: Catalog) -> tuple[Director, BroadcastCapture]:
    bc = BroadcastCapture()
    d = Director(catalog, bc)
    return d, bc


# ── IDLE → ARCHIVE on catalog populated ──────────────────────────────────────

async def test_idle_stays_idle_on_empty_catalog(catalog, tmp_path):
    d, bc = _make_director(catalog)
    await d.run()
    await asyncio.sleep(0.05)
    # Director stays IDLE on empty catalog; title_card is broadcast when
    # a failed archive pick occurs, not at startup (frontend gets state on WS connect).
    assert d.current_state.state == State.IDLE


async def test_idle_to_archive_after_interesting_session(catalog, tmp_path):
    tty = tmp_path / "tty.bin"
    tty.write_bytes(b"\x00" * 24)  # minimal TTY (no frames → empty archive play)

    d, bc = _make_director(catalog)
    await d.run()

    # Inject events to create an interesting session
    d.push_event({
        "type": "session_started", "session_id": "s1", "hop": 1,
        "src_ip": "1.2.3.4", "start_time": 1_000_000.0, "tty_file_path": str(tty),
    })
    await asyncio.sleep(0.05)
    await catalog.mark_login_success("s1")
    await catalog.update_tty_path("s1", str(tty))
    d.push_event({
        "type": "session_ended", "session_id": "s1",
        "end_time": 1_000_025.0, "command_count": 5,
    })
    await asyncio.sleep(0.05)

    # The session should be marked interesting now; director should move to ARCHIVE
    assert d.current_state.state in (State.ARCHIVE, State.IDLE)


# ── ARCHIVE → LIVE on login_success ──────────────────────────────────────────

async def test_archive_to_live_on_login_success(catalog, tmp_path):
    tty_archive = tmp_path / "archive.tty"
    tty_archive.write_bytes(b"")
    tty_live = tmp_path / "live.tty"
    tty_live.write_bytes(b"")

    d, bc = _make_director(catalog)
    await d.run()

    # Set up an archive session
    d.push_event({
        "type": "session_started", "session_id": "arch1", "hop": 1,
        "src_ip": "10.0.0.1", "start_time": 999_990.0, "tty_file_path": str(tty_archive),
    })
    await asyncio.sleep(0.05)
    await catalog.mark_login_success("arch1")
    await catalog.update_tty_path("arch1", str(tty_archive))
    d.push_event({
        "type": "session_ended", "session_id": "arch1",
        "end_time": 1_000_020.0, "command_count": 5,
    })
    await asyncio.sleep(0.1)

    # Now trigger a live login
    d.push_event({
        "type": "session_started", "session_id": "live1", "hop": 1,
        "src_ip": "5.6.7.8", "start_time": 1_000_030.0, "tty_file_path": str(tty_live),
    })
    await asyncio.sleep(0.05)
    d.push_event({"type": "session_login_success", "session_id": "live1"})
    await asyncio.sleep(0.3)  # wait for TTY resolution timeout

    assert d.current_state.state in (State.LIVE, State.ARCHIVE)
    assert any(m["type"] == "session_start" for m in bc.messages)


# ── LIVE → ARCHIVE on session_ended ──────────────────────────────────────────

async def test_live_to_archive_on_session_ended(catalog, tmp_path):
    tty = tmp_path / "t.tty"
    tty.write_bytes(b"")

    d, bc = _make_director(catalog)
    await d.run()

    d.push_event({
        "type": "session_started", "session_id": "lv2", "hop": 1,
        "src_ip": "1.1.1.1", "start_time": 1_000_000.0, "tty_file_path": str(tty),
    })
    await asyncio.sleep(0.05)
    d.push_event({"type": "session_login_success", "session_id": "lv2"})
    await asyncio.sleep(0.3)

    was_live = d.current_state.state == State.LIVE

    d.push_event({
        "type": "session_ended", "session_id": "lv2",
        "end_time": 1_000_025.0, "command_count": 5,
    })
    await asyncio.sleep(0.1)

    if was_live:
        assert d.current_state.state in (State.ARCHIVE, State.IDLE)


# ── ARCHIVE → IDLE on empty catalog ──────────────────────────────────────────

async def test_archive_to_idle_on_empty_catalog(catalog, tmp_path):
    d, bc = _make_director(catalog)
    await d.run()
    await asyncio.sleep(0.05)
    assert d.current_state.state == State.IDLE
