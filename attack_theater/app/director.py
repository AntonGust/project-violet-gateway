"""Asyncio state machine: IDLE | LIVE(session_id) | ARCHIVE(session_id)."""
import asyncio
import base64
import logging
import time
from dataclasses import dataclass
from enum import Enum, auto
from pathlib import Path
from typing import Awaitable, Callable, Optional

from .catalog import Catalog, SessionRecord
from .log_watcher import _TTY_DIRS as _WATCHER_TTY_DIRS
from . import tty_reader

log = logging.getLogger("director")

_LIVE_TIMEOUT_SEC = 600
_RECENT_PLAYED_MAX = 5
_LIVE_TTY_WAIT_SEC = 10.0
_STATS_INTERVAL_SEC = 5.0

BroadcastFn = Callable[[dict], Awaitable[None]]


class State(Enum):
    IDLE = auto()
    LIVE = auto()
    ARCHIVE = auto()


@dataclass
class _PlayState:
    state: State = State.IDLE
    session_id: Optional[str] = None


class Director:
    def __init__(self, catalog: Catalog, broadcast: BroadcastFn):
        self._catalog = catalog
        self._broadcast = broadcast
        self._event_queue: asyncio.Queue = asyncio.Queue()
        self._play = _PlayState()
        self._recent_played: list[str] = []
        self._playback_task: Optional[asyncio.Task] = None
        self._playback_stop: Optional[asyncio.Event] = None

    @property
    def current_state(self) -> _PlayState:
        return self._play

    def push_event(self, event: dict) -> None:
        self._event_queue.put_nowait(event)

    async def run(self) -> None:
        asyncio.ensure_future(self._event_loop())
        asyncio.ensure_future(self._stats_loop())
        asyncio.ensure_future(self._startup_kickoff())

    # ------------------------------------------------------------------
    # Event loop
    # ------------------------------------------------------------------

    async def _event_loop(self) -> None:
        while True:
            event = await self._event_queue.get()
            etype = event.get("type")
            try:
                if etype == "session_started":
                    await self._catalog.record_start(event)
                    await self._maybe_start_archive()
                elif etype == "session_login_success":
                    await self._handle_login_success(event["session_id"])
                elif etype == "session_command":
                    await self._handle_command(event)
                elif etype == "session_ended":
                    await self._handle_session_ended(event)
                elif etype == "tty_closed":
                    await self._catalog.update_tty_path(
                        event["session_id"], event["tty_file_path"]
                    )
            except Exception:
                log.exception("Error handling event %s", etype)

    async def _handle_login_success(self, session_id: str) -> None:
        await self._catalog.mark_login_success(session_id)
        if self._play.state != State.LIVE:
            await self._switch_to_live(session_id)

    async def _handle_command(self, event: dict) -> None:
        await self._catalog.append_command(event["session_id"], event.get("command", ""))
        if self._play.state == State.LIVE and self._play.session_id == event["session_id"]:
            await self._broadcast({"type": "command", "command": event["command"]})

    async def _handle_session_ended(self, event: dict) -> None:
        await self._catalog.finalize(event)
        if self._play.state == State.LIVE and self._play.session_id == event["session_id"]:
            await self._broadcast({"type": "session_end"})
            await self._switch_to_archive()

    # ------------------------------------------------------------------
    # State transitions
    # ------------------------------------------------------------------

    async def _switch_to_live(self, session_id: str) -> None:
        self._cancel_playback()
        tty_path = await self._resolve_tty(session_id)
        if tty_path is None:
            log.warning("No TTY for live session %s — falling back to archive", session_id)
            await self._switch_to_archive()
            return

        self._play = _PlayState(state=State.LIVE, session_id=session_id)
        rec = self._catalog.get(session_id)
        await self._broadcast(
            {"type": "session_start", "mode": "live", "session": _meta(rec)}
        )
        stop = asyncio.Event()
        self._playback_stop = stop
        self._playback_task = asyncio.ensure_future(
            self._stream_live(tty_path, session_id, stop)
        )

    async def _switch_to_archive(self) -> None:
        self._cancel_playback()
        pick = self._catalog.pick_next_archive(self._recent_played)
        if pick is None:
            if self._recent_played:
                # All sessions played — reset rotation and loop
                self._recent_played.clear()
                pick = self._catalog.pick_next_archive(self._recent_played)
            if pick is None:
                self._play = _PlayState(state=State.IDLE)
                await self._broadcast({"type": "title_card"})
                return

        self._record_played(pick.session_id)
        self._play = _PlayState(state=State.ARCHIVE, session_id=pick.session_id)
        await self._broadcast(
            {"type": "session_start", "mode": "replay", "session": _meta(pick)}
        )
        stop = asyncio.Event()
        self._playback_stop = stop
        self._playback_task = asyncio.ensure_future(
            self._stream_archive(Path(pick.tty_file_path), stop)
        )

    async def _maybe_start_archive(self) -> None:
        if self._play.state == State.IDLE:
            await self._switch_to_archive()

    async def _startup_kickoff(self) -> None:
        await asyncio.sleep(0.5)  # let catalog finish loading
        if self._play.state == State.IDLE:
            await self._switch_to_archive()

    # ------------------------------------------------------------------
    # Playback coroutines
    # ------------------------------------------------------------------

    async def _stream_archive(self, path: Path, stop: asyncio.Event) -> None:
        frames = tty_reader.read_finite(path)
        for delay_ms, data in frames:
            if stop.is_set():
                return
            if delay_ms > 0:
                await asyncio.sleep(delay_ms / 1000.0)
            await self._broadcast(
                {"type": "frame", "delay_ms": delay_ms, "data": base64.b64encode(data).decode()}
            )
        if not stop.is_set():
            await self._broadcast({"type": "session_end"})
            await self._switch_to_archive()

    async def _stream_live(self, path: Path, session_id: str, stop: asyncio.Event) -> None:
        timeout_at = time.monotonic() + _LIVE_TIMEOUT_SEC
        async for delay_ms, data in tty_reader.tail(path, stop):
            if time.monotonic() > timeout_at:
                log.info("Live session %s hit %ds cap, switching to archive", session_id, _LIVE_TIMEOUT_SEC)
                break
            await self._broadcast(
                {"type": "frame", "delay_ms": delay_ms, "data": base64.b64encode(data).decode()}
            )
        if not stop.is_set():
            await self._switch_to_archive()

    # ------------------------------------------------------------------
    # Stats
    # ------------------------------------------------------------------

    async def _stats_loop(self) -> None:
        while True:
            await asyncio.sleep(_STATS_INTERVAL_SEC)
            await self._broadcast({
                "type": "stats",
                "attacks_today": self._catalog.attacks_today_count(),
                "top_countries": self._catalog.top_countries_today(),
                "recent_pins": self._catalog.recent_pins(50),
            })

    # ------------------------------------------------------------------
    # Helpers
    # ------------------------------------------------------------------

    async def _resolve_tty(self, session_id: str) -> Optional[Path]:
        deadline = asyncio.get_event_loop().time() + _LIVE_TTY_WAIT_SEC
        while asyncio.get_event_loop().time() < deadline:
            rec = self._catalog.get(session_id)
            if rec and rec.tty_file_path:
                p = Path(rec.tty_file_path)
                if p.exists():
                    return p
            # Scan TTY dirs directly — file exists from session start, not just at close
            found = _scan_for_tty(session_id)
            if found:
                return found
            await asyncio.sleep(0.25)
        return None

    def _cancel_playback(self) -> None:
        if self._playback_stop:
            self._playback_stop.set()
        if self._playback_task and not self._playback_task.done():
            self._playback_task.cancel()
        self._playback_task = None
        self._playback_stop = None

    def _record_played(self, session_id: str) -> None:
        self._recent_played.append(session_id)
        if len(self._recent_played) > _RECENT_PLAYED_MAX:
            self._recent_played.pop(0)


def _scan_for_tty(session_id: str) -> Optional[Path]:
    for tty_dir in _WATCHER_TTY_DIRS.values():
        if not tty_dir.is_dir():
            continue
        matches = list(tty_dir.glob(f"*{session_id}*"))
        if matches:
            return matches[0]
    return None


def _meta(rec: Optional[SessionRecord]) -> dict:
    if rec is None:
        return {}
    return {
        "session_id": rec.session_id,
        "src_ip": rec.src_ip,
        "country": rec.country,
        "country_code": rec.country_code,
        "asn_org": rec.asn_org,
        "lat": rec.lat,
        "lon": rec.lon,
        "hop": rec.hop,
        "start_time": rec.start_time,
    }
