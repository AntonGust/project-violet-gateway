"""
Session Analyzer — Main entry point.
Watches Cowrie JSON logs, aggregates sessions, feeds to pattern matcher.
"""

import json
import logging
import os
import signal
import sys
import threading
import time
from collections import defaultdict
from datetime import datetime, timezone
from pathlib import Path

from watchdog.observers import Observer
from watchdog.events import FileSystemEventHandler, FileModifiedEvent

from pattern_matcher import PatternMatcher
from ban_manager import BanManager
from alert_manager import AlertManager

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(name)s: %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("analyzer")

DATA_DIR = Path("/data")
LOG_DIRS = [
    Path("/cowrie_logs/hop1/log/cowrie"),
    Path("/cowrie_logs/hop2/log/cowrie"),
    Path("/cowrie_logs/hop3/log/cowrie"),
]


class Session:
    """Accumulates events for a single Cowrie session."""

    def __init__(self, session_id: str, src_ip: str, hop: int):
        self.session_id = session_id
        self.src_ip = src_ip
        self.hop = hop
        self.start_time: float | None = None
        self.end_time: float | None = None
        self.auth_failed: int = 0
        self.auth_success: int = 0
        self.commands: list[str] = []
        self.downloads: list[str] = []

    @property
    def duration_sec(self) -> float | None:
        if self.start_time and self.end_time:
            return self.end_time - self.start_time
        return None

    def to_dict(self) -> dict:
        return {
            "session_id": self.session_id,
            "src_ip": self.src_ip,
            "hop": self.hop,
            "auth_failed": self.auth_failed,
            "auth_success": self.auth_success,
            "commands": self.commands,
            "downloads": self.downloads,
            "duration_sec": self.duration_sec,
        }


class SessionAggregator:
    """Groups Cowrie log events by session ID."""

    def __init__(self):
        self._sessions: dict[str, Session] = {}
        self._lock = threading.Lock()

    def process_event(self, event: dict, hop: int) -> Session | None:
        """Process a single Cowrie JSON event. Returns Session if it just closed."""
        event_id = event.get("eventid", "")
        session_id = event.get("session", "")
        if not session_id:
            return None

        with self._lock:
            if event_id == "cowrie.session.connect":
                src_ip = event.get("src_ip", "unknown")
                session = Session(session_id, src_ip, hop)
                session.start_time = _parse_timestamp(event.get("timestamp"))
                self._sessions[session_id] = session
                return None

            session = self._sessions.get(session_id)
            if session is None:
                return None

            if event_id == "cowrie.login.failed":
                session.auth_failed += 1

            elif event_id == "cowrie.login.success":
                session.auth_success += 1

            elif event_id == "cowrie.command.input":
                cmd = event.get("input", "")
                if cmd:
                    session.commands.append(cmd)

            elif event_id == "cowrie.session.file_download":
                url = event.get("url", "")
                if url:
                    session.downloads.append(url)

            elif event_id == "cowrie.session.closed":
                session.end_time = _parse_timestamp(event.get("timestamp"))
                del self._sessions[session_id]
                return session

        return None


def _parse_timestamp(ts_str: str | None) -> float | None:
    if not ts_str:
        return None
    try:
        dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
        return dt.timestamp()
    except (ValueError, TypeError):
        return time.time()


class CowrieLogHandler(FileSystemEventHandler):
    """Watches a Cowrie log directory for modifications."""

    def __init__(self, hop: int, aggregator: SessionAggregator, on_session_closed):
        self.hop = hop
        self.aggregator = aggregator
        self.on_session_closed = on_session_closed
        self._file_positions: dict[str, int] = {}

    def on_modified(self, event):
        if not isinstance(event, FileModifiedEvent):
            return
        if not event.src_path.endswith(".json") and not event.src_path.endswith(
            ".json"
        ):
            # Also handle rotated files like cowrie.json.2026-03-13
            if ".json" not in event.src_path:
                return
        self._read_new_lines(event.src_path)

    def on_created(self, event):
        if ".json" in event.src_path:
            self._file_positions[event.src_path] = 0
            self._read_new_lines(event.src_path)

    def _read_new_lines(self, filepath: str):
        pos = self._file_positions.get(filepath, 0)
        try:
            with open(filepath, "r") as f:
                f.seek(pos)
                for line in f:
                    line = line.strip()
                    if not line:
                        continue
                    try:
                        event = json.loads(line)
                    except json.JSONDecodeError:
                        continue
                    closed_session = self.aggregator.process_event(event, self.hop)
                    if closed_session:
                        self.on_session_closed(closed_session)
                self._file_positions[filepath] = f.tell()
        except FileNotFoundError:
            pass
        except Exception:
            log.exception("Error reading %s", filepath)

    def initial_scan(self, directory: Path):
        """Read any existing log files on startup."""
        for log_file in sorted(directory.glob("cowrie.json*")):
            self._file_positions[str(log_file)] = 0
            self._read_new_lines(str(log_file))


class Analyzer:
    def __init__(self):
        self.aggregator = SessionAggregator()
        self.ban_manager = BanManager(DATA_DIR / "bans.db")
        self.alert_manager = AlertManager(
            slack_webhook_url=os.environ.get("SLACK_WEBHOOK_URL", ""),
            spike_window_min=int(os.environ.get("SPIKE_WINDOW_MIN", "10")),
            spike_multiplier=float(os.environ.get("SPIKE_MULTIPLIER", "5")),
        )
        self.pattern_matcher = PatternMatcher(
            signatures_dir=Path("/app/signatures"),
            db_path=DATA_DIR / "signatures.db",
            learn_threshold=int(os.environ.get("LEARN_THRESHOLD", "5")),
            brute_force_threshold=int(os.environ.get("BRUTE_FORCE_THRESHOLD", "20")),
            rapid_disconnect_sec=float(os.environ.get("RAPID_DISCONNECT_SEC", "5")),
            alert_manager=self.alert_manager,
        )
        self._running = True
        self._observer = Observer()
        self._stats_lock = threading.Lock()
        self._daily_stats = defaultdict(int)

    def on_session_closed(self, session: Session):
        """Called when a Cowrie session completes."""
        log.info(
            "Session closed: %s from %s (hop%d, %d cmds, %d auth_fail, %.1fs)",
            session.session_id,
            session.src_ip,
            session.hop,
            len(session.commands),
            session.auth_failed,
            session.duration_sec or 0,
        )

        # Track connection for spike detection
        self.alert_manager.record_connection(session.src_ip)

        # Run pattern matching
        matches = self.pattern_matcher.analyze_session(session.to_dict())

        # Ban if any patterns matched
        if matches:
            reasons = ", ".join(matches)
            log.info("Banning %s: %s", session.src_ip, reasons)
            self.ban_manager.ban_ip(session.src_ip, reasons)

        # Update daily stats
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        with self._stats_lock:
            self._daily_stats[f"{today}:total"] += 1
            if matches:
                self._daily_stats[f"{today}:dropped"] += 1
                for m in matches:
                    self._daily_stats[f"{today}:dropped_{m}"] += 1
            else:
                self._daily_stats[f"{today}:accepted"] += 1

    def _spike_check_loop(self):
        """Periodically check for connection spikes."""
        while self._running:
            try:
                self.alert_manager.check_spike()
            except Exception:
                log.exception("Spike check error")
            time.sleep(60)

    def _daily_summary_loop(self):
        """Send daily summary at midnight UTC."""
        while self._running:
            now = datetime.now(timezone.utc)
            # Sleep until next midnight
            tomorrow = now.replace(hour=0, minute=0, second=0, microsecond=0)
            if now.hour != 0 or now.minute > 1:
                from datetime import timedelta
                tomorrow += timedelta(days=1)
            sleep_sec = (tomorrow - now).total_seconds()
            # Sleep in chunks so we can stop
            while sleep_sec > 0 and self._running:
                time.sleep(min(sleep_sec, 30))
                sleep_sec -= 30

            if not self._running:
                break

            try:
                with self._stats_lock:
                    stats = dict(self._daily_stats)
                self.alert_manager.send_daily_summary(stats)
            except Exception:
                log.exception("Daily summary error")

    def run(self):
        DATA_DIR.mkdir(parents=True, exist_ok=True)

        # Set up file watchers for each hop
        handlers = []
        for i, log_dir in enumerate(LOG_DIRS, start=1):
            if not log_dir.exists():
                log.warning("Log dir not found (will watch parent): %s", log_dir)
                log_dir.mkdir(parents=True, exist_ok=True)

            handler = CowrieLogHandler(i, self.aggregator, self.on_session_closed)
            handler.initial_scan(log_dir)
            self._observer.schedule(handler, str(log_dir), recursive=False)
            handlers.append(handler)
            log.info("Watching hop%d logs at %s", i, log_dir)

        self._observer.start()

        # Start background threads
        spike_thread = threading.Thread(target=self._spike_check_loop, daemon=True)
        spike_thread.start()

        summary_thread = threading.Thread(target=self._daily_summary_loop, daemon=True)
        summary_thread.start()

        log.info("Session analyzer running.")

        # Block until signaled
        while self._running:
            time.sleep(1)

        self._observer.stop()
        self._observer.join()
        log.info("Session analyzer stopped.")

    def stop(self):
        self._running = False


def main():
    analyzer = Analyzer()

    def signal_handler(sig, frame):
        log.info("Received signal %d, shutting down", sig)
        analyzer.stop()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    analyzer.run()


if __name__ == "__main__":
    main()
