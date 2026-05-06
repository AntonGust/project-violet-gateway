"""Watch Cowrie JSON log files and emit parsed events onto an asyncio queue."""
import asyncio
import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent, FileCreatedEvent

log = logging.getLogger("log_watcher")

_LOG_DIRS: list[tuple[int, Path]] = [
    (1, Path("/cowrie_logs/hop1/log/cowrie")),
    (2, Path("/cowrie_logs/hop2/log/cowrie")),
    (3, Path("/cowrie_logs/hop3/log/cowrie")),
]
_TTY_DIRS: dict[int, Path] = {
    1: Path("/cowrie_logs/hop1/lib/cowrie/tty"),
    2: Path("/cowrie_logs/hop2/lib/cowrie/tty"),
    3: Path("/cowrie_logs/hop3/lib/cowrie/tty"),
}


class LogWatcher:
    def __init__(
        self,
        queue: asyncio.Queue,
        loop: asyncio.AbstractEventLoop,
        log_dirs: list[tuple[int, Path]] = _LOG_DIRS,
        tty_dirs: dict[int, Path] = _TTY_DIRS,
    ):
        self._queue = queue
        self._loop = loop
        self._log_dirs = log_dirs
        self._tty_dirs = tty_dirs
        self._observer = Observer()

    def start(self) -> None:
        for hop, log_dir in self._log_dirs:
            if not log_dir.exists():
                log.warning("Log dir missing, skipping: %s", log_dir)
                continue
            tty_dir = self._tty_dirs.get(hop, Path("/dev/null"))
            handler = _JsonFileHandler(hop, tty_dir, self._queue, self._loop)
            self._observer.schedule(handler, str(log_dir), recursive=False)
            for f in sorted(log_dir.glob("cowrie.json*")):
                if f.name.endswith(".bz2") or f.name.endswith(".gz"):
                    continue
                handler.tail_file(f)
        self._observer.start()
        log.info("Log watcher started (%d directories)", len(self._log_dirs))

    def stop(self) -> None:
        self._observer.stop()
        self._observer.join()


class _JsonFileHandler(FileSystemEventHandler):
    def __init__(
        self,
        hop: int,
        tty_dir: Path,
        queue: asyncio.Queue,
        loop: asyncio.AbstractEventLoop,
    ):
        super().__init__()
        self._hop = hop
        self._tty_dir = tty_dir
        self._queue = queue
        self._loop = loop
        self._offsets: dict[Path, int] = {}

    def tail_file(self, path: Path) -> None:
        if path not in self._offsets:
            self._offsets[path] = 0
            self._drain(path)

    def on_modified(self, event) -> None:
        if isinstance(event, FileModifiedEvent):
            path = Path(event.src_path)
            if _is_cowrie_json(path):
                self._drain(path)

    def on_created(self, event) -> None:
        if isinstance(event, FileCreatedEvent):
            path = Path(event.src_path)
            if _is_cowrie_json(path):
                self._offsets[path] = 0
                self._drain(path)

    def _drain(self, path: Path) -> None:
        offset = self._offsets.get(path, 0)
        try:
            with path.open("rb") as fh:
                fh.seek(offset)
                chunk = fh.read()
                self._offsets[path] = fh.tell()
        except OSError:
            return

        for raw_line in chunk.splitlines():
            line = raw_line.strip()
            if not line:
                continue
            try:
                data = json.loads(line)
            except json.JSONDecodeError:
                continue
            evt = self._parse(data)
            if evt:
                asyncio.run_coroutine_threadsafe(self._queue.put(evt), self._loop)

    def _parse(self, data: dict) -> dict | None:
        etype = data.get("eventid", "")
        session_id = data.get("session", "")
        ts = _parse_ts(data.get("timestamp", ""))

        if etype == "cowrie.session.connect":
            return {
                "type": "session_started",
                "session_id": session_id,
                "hop": self._hop,
                "src_ip": data.get("src_ip", ""),
                "tty_file_path": None,
                "start_time": ts,
            }

        if etype == "cowrie.login.success":
            return {"type": "session_login_success", "session_id": session_id}

        if etype == "cowrie.command.input":
            return {
                "type": "session_command",
                "session_id": session_id,
                "command": data.get("input", ""),
            }

        if etype == "cowrie.session.closed":
            return {
                "type": "session_ended",
                "session_id": session_id,
                "end_time": ts,
                "duration": data.get("duration", 0.0),
                "command_count": data.get("commands", 0),
            }

        if etype == "cowrie.log.closed":
            ttylog = data.get("ttylog", "")
            if ttylog:
                tty_path = self._tty_dir / Path(ttylog).name
                return {
                    "type": "tty_closed",
                    "session_id": session_id,
                    "tty_file_path": str(tty_path),
                }

        return None


def _is_cowrie_json(path: Path) -> bool:
    return path.name.startswith("cowrie.json") and not path.name.endswith((".bz2", ".gz"))


def _parse_ts(ts: str) -> float:
    import time
    if not ts:
        return time.time()
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
        if dt.tzinfo is None:
            dt = dt.replace(tzinfo=timezone.utc)
        return dt.timestamp()
    except (ValueError, AttributeError):
        return time.time()
