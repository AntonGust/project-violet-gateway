"""
Alert Manager — Slack webhook alerts for spikes, new patterns, and daily summaries.
"""

import json
import logging
import time
from collections import deque
from datetime import datetime, timezone

import requests

log = logging.getLogger("alert_manager")

_SLACK_ESCAPE = str.maketrans({"&": "&amp;", "<": "&lt;", ">": "&gt;"})


def _sanitize(s: str) -> str:
    """Escape attacker-controlled strings before embedding in Slack mrkdwn."""
    return s.translate(_SLACK_ESCAPE)


class AlertManager:
    def __init__(
        self,
        slack_webhook_url: str,
        spike_window_min: int = 10,
        spike_multiplier: float = 5.0,
    ):
        self.slack_webhook_url = slack_webhook_url
        self.spike_window_sec = spike_window_min * 60
        self.spike_multiplier = spike_multiplier

        # Connection tracking for spike detection
        self._connections: deque[tuple[float, str]] = deque()  # (timestamp, ip)
        self._baseline_window_sec = 3600  # 1 hour for baseline
        self._last_spike_alert = 0.0
        self._spike_cooldown_sec = 1800  # 30 min cooldown

    def record_connection(self, src_ip: str):
        """Record a connection for spike detection."""
        now = time.time()
        self._connections.append((now, src_ip))
        # Prune old entries beyond baseline window
        cutoff = now - self._baseline_window_sec
        while self._connections and self._connections[0][0] < cutoff:
            self._connections.popleft()

    def check_spike(self):
        """Check if current connection rate is a spike."""
        now = time.time()

        if now - self._last_spike_alert < self._spike_cooldown_sec:
            return

        if len(self._connections) < 10:
            return  # Not enough data

        # Current window count
        window_cutoff = now - self.spike_window_sec
        current_count = sum(
            1 for ts, _ in self._connections if ts >= window_cutoff
        )

        # Baseline: average rate over the full hour, normalized to window size
        total = len(self._connections)
        time_span = now - self._connections[0][0] if self._connections else 1
        if time_span < self.spike_window_sec:
            return  # Not enough history
        baseline = (total / time_span) * self.spike_window_sec

        if baseline <= 0:
            return

        ratio = current_count / baseline

        if ratio >= self.spike_multiplier:
            # Get top IPs in current window
            ip_counts: dict[str, int] = {}
            for ts, ip in self._connections:
                if ts >= window_cutoff:
                    ip_counts[ip] = ip_counts.get(ip, 0) + 1
            top_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)[:5]

            self._send_spike_alert(current_count, baseline, ratio, top_ips)
            self._last_spike_alert = now

    def _send_spike_alert(
        self,
        current: int,
        baseline: float,
        ratio: float,
        top_ips: list[tuple[str, int]],
    ):
        top_str = ", ".join(f"`{_sanitize(ip)}` ({c})" for ip, c in top_ips)
        text = (
            f"*Connection spike detected*\n"
            f"Current: {current} conns/{self.spike_window_sec // 60}min\n"
            f"Baseline: {baseline:.0f} conns/{self.spike_window_sec // 60}min\n"
            f"Ratio: {ratio:.1f}x\n"
            f"Top IPs: {top_str}"
        )
        self._post_slack(":rotating_light: *Honeypot Alert: Connection Spike*", text)

    def send_new_pattern_alert(
        self, fingerprint: str, commands: list[str], unique_ips: int
    ):
        cmds_str = ", ".join(f"`{_sanitize(c)}`" for c in commands[:10])
        text = (
            f"*New attack pattern auto-learned*\n"
            f"Fingerprint: `{fingerprint[:16]}...`\n"
            f"Seen from: {unique_ips} unique IPs\n"
            f"Commands: {cmds_str}\n"
            f"Action: Auto-ban enabled"
        )
        self._post_slack(":mag: *Honeypot Alert: New Attack Pattern*", text)

    def send_daily_summary(self, stats: dict):
        today = datetime.now(timezone.utc).strftime("%Y-%m-%d")
        total = stats.get(f"{today}:total", 0)
        accepted = stats.get(f"{today}:accepted", 0)
        dropped = stats.get(f"{today}:dropped", 0)

        if total == 0:
            return

        drop_pct = (dropped / total * 100) if total else 0
        text = (
            f"*{today} Summary*\n"
            f"Total connections: {total:,}\n"
            f"Accepted: {accepted:,} ({100 - drop_pct:.1f}%)\n"
            f"Dropped: {dropped:,} ({drop_pct:.1f}%)\n"
        )

        # Add per-reason breakdown
        for key, val in sorted(stats.items()):
            if key.startswith(f"{today}:dropped_") and val > 0:
                reason = key.split("dropped_", 1)[1]
                text += f"  - {reason}: {val:,}\n"

        self._post_slack(":bar_chart: *Honeypot Daily Summary*", text)

    def _post_slack(self, title: str, body: str):
        if not self.slack_webhook_url:
            log.warning("No Slack webhook configured, skipping alert")
            log.info("Alert: %s\n%s", title, body)
            return

        payload = {
            "text": title,
            "blocks": [
                {
                    "type": "section",
                    "text": {"type": "mrkdwn", "text": f"{title}\n\n{body}"},
                }
            ],
        }

        try:
            resp = requests.post(
                self.slack_webhook_url,
                json=payload,
                timeout=10,
            )
            if resp.status_code != 200:
                log.error("Slack webhook failed: %d %s", resp.status_code, resp.text)
            else:
                log.info("Slack alert sent: %s", title)
        except Exception:
            log.exception("Failed to send Slack alert")
