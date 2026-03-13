"""
Blocklist Updater — Pulls IP blocklist from AbuseIPDB API.
Writes to /data/blocklist.txt (atomic write).
"""

import logging
import os
import sys
import tempfile
from datetime import datetime, timezone
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

        ips = [entry["ipAddress"] for entry in data.get("data", [])]
        log.info("Fetched %d IPs from AbuseIPDB", len(ips))
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


def main():
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


if __name__ == "__main__":
    main()
