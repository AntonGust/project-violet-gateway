"""
Blocklist Updater — Pulls IP blocklist from AbuseIPDB API.
Writes to /data/blocklist.txt (atomic write).
"""

import ipaddress
import logging
import os
import sys
import tempfile
import time
from datetime import datetime, timedelta, timezone
from pathlib import Path

import requests

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("blocklist_updater")

API_URL = "https://api.abuseipdb.com/api/v2/blacklist"
DATA_DIR = Path("/data")
BLOCKLIST_PATH = DATA_DIR / "blocklist.txt"


def fetch_blocklist() -> list[str] | None:
    api_key = os.environ.get("ABUSEIPDB_API_KEY", "")
    if not api_key:
        log.error("ABUSEIPDB_API_KEY not set, skipping update")
        return None

    confidence = int(os.environ.get("CONFIDENCE_MINIMUM", "90"))

    headers = {
        "Key": api_key,
        "Accept": "application/json",
    }
    params = {
        "confidenceMinimum": confidence,
    }

    try:
        log.info("Fetching blocklist from AbuseIPDB (confidence >= %d)...", confidence)
        resp = requests.get(API_URL, headers=headers, params=params, timeout=30)

        if resp.status_code == 429:
            log.warning("Rate limited by AbuseIPDB, keeping existing blocklist")
            return None

        resp.raise_for_status()
        data = resp.json()

        raw_ips = [entry["ipAddress"] for entry in data.get("data", [])]
        ips = []
        for raw in raw_ips:
            try:
                ipaddress.ip_address(raw)
                ips.append(raw)
            except ValueError:
                log.warning("Blocklist: skipping invalid IP from AbuseIPDB: %r", raw)
        log.info("Fetched %d IPs from AbuseIPDB (%d invalid skipped)", len(ips), len(raw_ips) - len(ips))
        return ips

    except requests.exceptions.RequestException:
        log.exception("Failed to fetch blocklist from AbuseIPDB")
        return None
    except (KeyError, ValueError):
        log.exception("Failed to parse AbuseIPDB response")
        return None


def write_blocklist(ips: list[str]):
    """Atomic write: write to temp file, then rename."""
    DATA_DIR.mkdir(parents=True, exist_ok=True)

    # Write to temp file in same directory (for atomic rename)
    fd, tmp_path = tempfile.mkstemp(dir=str(DATA_DIR), suffix=".tmp")
    try:
        with os.fdopen(fd, "w") as f:
            for ip in ips:
                f.write(ip + "\n")
        os.rename(tmp_path, str(BLOCKLIST_PATH))
        log.info("Blocklist written: %d IPs → %s", len(ips), BLOCKLIST_PATH)
    except Exception:
        log.exception("Failed to write blocklist")
        # Clean up temp file on failure
        try:
            os.unlink(tmp_path)
        except OSError:
            pass


UPDATE_HOUR = int(os.environ.get("UPDATE_HOUR", "3"))  # UTC hour for daily refresh


def run_once():
    ts = datetime.now(timezone.utc).isoformat()
    log.info("Blocklist update started at %s", ts)

    ips = fetch_blocklist()
    if ips is not None and len(ips) > 0:
        write_blocklist(ips)
    elif ips is not None and len(ips) == 0:
        log.warning("AbuseIPDB returned 0 IPs, keeping existing blocklist")
    else:
        log.warning("Fetch failed, keeping existing blocklist")

    log.info("Blocklist update complete")


def seconds_until_next_run() -> float:
    """Seconds until the next UPDATE_HOUR:00 UTC."""
    now = datetime.now(timezone.utc)
    next_run = now.replace(hour=UPDATE_HOUR, minute=0, second=0, microsecond=0)
    if next_run <= now:
        next_run += timedelta(days=1)
    return (next_run - now).total_seconds()


def loop():
    """Run immediately on startup, then once daily at UPDATE_HOUR UTC."""
    log.info("Starting in loop mode (daily update at %02d:00 UTC)", UPDATE_HOUR)
    run_once()
    while True:
        delay = seconds_until_next_run()
        log.info("Next update in %.0f seconds (at %02d:00 UTC)", delay, UPDATE_HOUR)
        time.sleep(delay)
        run_once()


def main():
    if len(sys.argv) > 1 and sys.argv[1] == "--loop":
        loop()
    else:
        run_once()


if __name__ == "__main__":
    main()
