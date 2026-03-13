"""
Filter Sidecar Server
Listens on a Unix socket for IP check requests from HAProxy Lua.
Checks: blocklist file → ban database → returns ACCEPT/DROP.
"""

import json
import logging
import os
import signal
import socket
import sqlite3
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("filter_sidecar")

SOCKET_PATH = "/tmp/filter.sock"
DATA_DIR = Path("/data")
BLOCKLIST_PATH = DATA_DIR / "blocklist.txt"
BANS_DB_PATH = DATA_DIR / "bans.db"
FILTER_LOG_PATH = DATA_DIR / "filter.log"

BLOCKLIST_RELOAD_INTERVAL = 300  # 5 minutes


class BlocklistStore:
    """Thread-safe blocklist backed by a plain text file."""

    def __init__(self):
        self._ips: set[str] = set()
        self._lock = threading.Lock()
        self._last_loaded = 0.0

    def _should_reload(self) -> bool:
        return time.time() - self._last_loaded > BLOCKLIST_RELOAD_INTERVAL

    def reload(self):
        try:
            if BLOCKLIST_PATH.exists():
                with open(BLOCKLIST_PATH) as f:
                    ips = {line.strip() for line in f if line.strip()}
                with self._lock:
                    self._ips = ips
                    self._last_loaded = time.time()
                log.info("Blocklist reloaded: %d IPs", len(ips))
            else:
                log.warning("Blocklist file not found: %s", BLOCKLIST_PATH)
        except Exception:
            log.exception("Failed to reload blocklist")

    def contains(self, ip: str) -> bool:
        if self._should_reload():
            self.reload()
        with self._lock:
            return ip in self._ips


class BanChecker:
    """Thread-safe ban checker backed by SQLite."""

    def __init__(self):
        self._local = threading.local()
        self._init_db()

    def _get_conn(self) -> sqlite3.Connection:
        if not hasattr(self._local, "conn"):
            self._local.conn = sqlite3.connect(
                str(BANS_DB_PATH),
                check_same_thread=False,
                timeout=5,
            )
        return self._local.conn

    def _init_db(self):
        conn = sqlite3.connect(str(BANS_DB_PATH), timeout=5)
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
        log.info("Bans database initialized at %s", BANS_DB_PATH)

    def is_banned(self, ip: str) -> bool:
        try:
            conn = self._get_conn()
            now = datetime.now(timezone.utc).isoformat()
            row = conn.execute(
                "SELECT 1 FROM bans WHERE ip = ? AND ban_until > ?",
                (ip, now),
            ).fetchone()
            return row is not None
        except Exception:
            log.exception("Error checking ban for %s", ip)
            return False


class FilterLogger:
    """Append-only log of filter decisions."""

    def __init__(self):
        self._lock = threading.Lock()
        self._file = open(FILTER_LOG_PATH, "a", buffering=1)  # line-buffered

    def log_decision(self, ip: str, decision: str, reason: str):
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.%fZ")
        entry = json.dumps(
            {"ts": ts, "ip": ip, "decision": decision, "reason": reason}
        )
        with self._lock:
            self._file.write(entry + "\n")

    def close(self):
        self._file.close()


class FilterServer:
    def __init__(self):
        self.blocklist = BlocklistStore()
        self.bans = BanChecker()
        self.filter_log = FilterLogger()
        self._running = True

    def check_ip(self, ip: str) -> tuple[str, str]:
        """Returns (decision, reason)."""
        # 1. Blocklist
        if self.blocklist.contains(ip):
            return "DROP", "blocklist"

        # 2. Ban DB
        if self.bans.is_banned(ip):
            return "DROP", "ban"

        return "ACCEPT", "passed"

    def handle_client(self, conn: socket.socket):
        try:
            data = conn.recv(256)
            if not data:
                return
            ip = data.decode("utf-8").strip()
            if not ip:
                return

            decision, reason = self.check_ip(ip)
            conn.sendall((decision + "\n").encode("utf-8"))
            self.filter_log.log_decision(ip, decision, reason)
        except Exception:
            log.exception("Error handling client")
        finally:
            conn.close()

    def serve(self):
        # Load blocklist on startup
        self.blocklist.reload()

        # Clean up stale socket
        if os.path.exists(SOCKET_PATH):
            os.unlink(SOCKET_PATH)

        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.bind(SOCKET_PATH)
        os.chmod(SOCKET_PATH, 0o777)
        sock.listen(64)
        sock.settimeout(1.0)  # Allow periodic check of _running

        log.info("Filter sidecar listening on %s", SOCKET_PATH)

        while self._running:
            try:
                conn, _ = sock.accept()
                t = threading.Thread(target=self.handle_client, args=(conn,), daemon=True)
                t.start()
            except socket.timeout:
                continue
            except Exception:
                if self._running:
                    log.exception("Accept error")

        sock.close()
        self.filter_log.close()
        log.info("Filter sidecar stopped")

    def stop(self):
        self._running = False


def main():
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    server = FilterServer()

    def signal_handler(sig, frame):
        log.info("Received signal %d, shutting down", sig)
        server.stop()

    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)

    server.serve()


if __name__ == "__main__":
    main()
