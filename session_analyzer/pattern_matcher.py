"""
Pattern Matcher — Static rules + learned signature matching.
Fingerprints sessions and auto-learns repeated patterns.
"""

import hashlib
import json
import logging
import re
import sqlite3
from pathlib import Path

log = logging.getLogger("pattern_matcher")

# Regex for normalizing commands
IP_RE = re.compile(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b")
URL_RE = re.compile(r"https?://\S+")
PATH_RE = re.compile(r"/[\w./-]+")


class PatternMatcher:
    def __init__(
        self,
        signatures_dir: Path,
        db_path: Path,
        learn_threshold: int = 5,
        brute_force_threshold: int = 20,
        rapid_disconnect_sec: float = 5.0,
        alert_manager=None,
    ):
        self.signatures_dir = signatures_dir
        self.db_path = db_path
        self.learn_threshold = learn_threshold
        self.brute_force_threshold = brute_force_threshold
        self.rapid_disconnect_sec = rapid_disconnect_sec
        self.alert_manager = alert_manager

        # Load seed signatures
        self._seed_patterns: dict[str, list[list[str]]] = {}
        self._load_seed_signatures()

        # Initialize SQLite
        self._init_db()

    def _load_seed_signatures(self):
        if not self.signatures_dir.exists():
            log.warning("Signatures directory not found: %s", self.signatures_dir)
            return
        for sig_file in self.signatures_dir.glob("*.json"):
            try:
                with open(sig_file) as f:
                    data = json.load(f)
                label = data.get("label", sig_file.stem)
                patterns = data.get("patterns", [])
                self._seed_patterns[label] = patterns
                log.info("Loaded seed signature '%s': %d patterns", label, len(patterns))
            except Exception:
                log.exception("Failed to load signature file: %s", sig_file)

    def _init_db(self):
        conn = sqlite3.connect(str(self.db_path), timeout=5)
        conn.executescript("""
            CREATE TABLE IF NOT EXISTS sessions (
                id           INTEGER PRIMARY KEY AUTOINCREMENT,
                session_id   TEXT UNIQUE NOT NULL,
                src_ip       TEXT NOT NULL,
                fingerprint  TEXT NOT NULL,
                commands     TEXT NOT NULL,
                auth_attempts INTEGER DEFAULT 0,
                duration_sec REAL,
                hop          INTEGER DEFAULT 1,
                timestamp    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
            );

            CREATE TABLE IF NOT EXISTS signatures (
                fingerprint  TEXT PRIMARY KEY,
                label        TEXT NOT NULL,
                commands     TEXT NOT NULL,
                first_seen   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
                hit_count    INTEGER DEFAULT 1,
                unique_ips   INTEGER DEFAULT 1,
                auto_ban     BOOLEAN DEFAULT 1
            );

            CREATE TABLE IF NOT EXISTS stats (
                date              TEXT PRIMARY KEY,
                total_connections  INTEGER DEFAULT 0,
                accepted           INTEGER DEFAULT 0,
                dropped_blocklist  INTEGER DEFAULT 0,
                dropped_ban        INTEGER DEFAULT 0,
                dropped_rate       INTEGER DEFAULT 0,
                dropped_pattern    INTEGER DEFAULT 0,
                unique_ips         INTEGER DEFAULT 0
            );

            CREATE INDEX IF NOT EXISTS idx_sessions_fingerprint ON sessions(fingerprint);
            CREATE INDEX IF NOT EXISTS idx_sessions_src_ip ON sessions(src_ip);
        """)
        conn.commit()
        conn.close()
        log.info("Signatures database initialized at %s", self.db_path)

    def _get_conn(self) -> sqlite3.Connection:
        return sqlite3.connect(str(self.db_path), timeout=5)

    @staticmethod
    def normalize_command(cmd: str) -> str:
        """Normalize a command for fingerprinting."""
        cmd = cmd.lower().strip()
        cmd = URL_RE.sub("URLARG", cmd)
        cmd = IP_RE.sub("IPARG", cmd)
        # Replace full paths with basename
        def _basename(m):
            parts = m.group(0).rsplit("/", 1)
            return parts[-1] if len(parts) > 1 else parts[0]
        cmd = PATH_RE.sub(_basename, cmd)
        return cmd

    @staticmethod
    def fingerprint(commands: list[str]) -> str:
        """SHA256 of sorted normalized commands."""
        normalized = sorted(PatternMatcher.normalize_command(c) for c in commands)
        combined = "\n".join(normalized)
        return hashlib.sha256(combined.encode()).hexdigest()

    def analyze_session(self, session: dict) -> list[str]:
        """
        Analyze a completed session.
        Returns list of matched rule labels (empty = clean).
        """
        matches = []

        commands = session.get("commands", [])
        auth_failed = session.get("auth_failed", 0)
        duration = session.get("duration_sec")
        auth_success = session.get("auth_success", 0)

        # --- Static Rule: AUTH_BRUTE ---
        if auth_failed >= self.brute_force_threshold:
            matches.append("auth_brute")

        # --- Static Rule: RAPID_DISCONNECT ---
        if (
            auth_success > 0
            and duration is not None
            and duration < self.rapid_disconnect_sec
            and len(commands) == 0
        ):
            matches.append("rapid_disconnect")

        # --- Static Rule: MIRAI_SIG (seed patterns) ---
        if commands:
            cmd_lower_set = {c.lower() for c in commands}
            for label, patterns in self._seed_patterns.items():
                for pattern_cmds in patterns:
                    if all(
                        any(p.lower() in cmd for cmd in cmd_lower_set)
                        for p in pattern_cmds
                    ):
                        matches.append(f"seed_{label}")
                        break

        # --- Fingerprint-based matching + learning ---
        if commands:
            fp = self.fingerprint(commands)
            self._store_and_learn(session, fp, commands)

            # Check known signatures
            conn = self._get_conn()
            try:
                row = conn.execute(
                    "SELECT label, auto_ban FROM signatures WHERE fingerprint = ?",
                    (fp,),
                ).fetchone()
                if row and row[1]:  # auto_ban is True
                    matches.append(f"known_sig:{row[0]}")
                    conn.execute(
                        "UPDATE signatures SET hit_count = hit_count + 1 WHERE fingerprint = ?",
                        (fp,),
                    )
                    conn.commit()
            finally:
                conn.close()

        return matches

    def _store_and_learn(self, session: dict, fp: str, commands: list[str]):
        """Store session and check if fingerprint should be auto-learned."""
        conn = self._get_conn()
        try:
            # Insert session (ignore if duplicate session_id)
            conn.execute(
                """INSERT OR IGNORE INTO sessions
                   (session_id, src_ip, fingerprint, commands, auth_attempts, duration_sec, hop)
                   VALUES (?, ?, ?, ?, ?, ?, ?)""",
                (
                    session["session_id"],
                    session["src_ip"],
                    fp,
                    json.dumps(commands),
                    session.get("auth_failed", 0),
                    session.get("duration_sec"),
                    session.get("hop", 1),
                ),
            )
            conn.commit()

            # Check if this fingerprint should be learned
            row = conn.execute(
                "SELECT COUNT(DISTINCT src_ip) FROM sessions WHERE fingerprint = ?",
                (fp,),
            ).fetchone()
            unique_ips = row[0] if row else 0

            # Check if already in signatures
            existing = conn.execute(
                "SELECT 1 FROM signatures WHERE fingerprint = ?", (fp,)
            ).fetchone()

            if unique_ips >= self.learn_threshold and not existing:
                conn.execute(
                    """INSERT INTO signatures (fingerprint, label, commands, unique_ips)
                       VALUES (?, ?, ?, ?)""",
                    (fp, "auto_learned", json.dumps(commands[:20]), unique_ips),
                )
                conn.commit()
                log.info(
                    "Auto-learned signature: fp=%s, unique_ips=%d, commands=%s",
                    fp[:16],
                    unique_ips,
                    commands[:5],
                )
                # Alert
                if self.alert_manager:
                    self.alert_manager.send_new_pattern_alert(fp, commands, unique_ips)
        except Exception:
            log.exception("Error in store_and_learn")
        finally:
            conn.close()
