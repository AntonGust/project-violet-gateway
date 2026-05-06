# Enforcement Pipeline

Documents how `blocklist_updater`, `filter_gateway`, and `session_analyzer` work together to detect and block attackers.

---

## Architecture Overview

```
AbuseIPDB API (external threat intel)
       │
       ▼ HTTPS (once daily at 03:00 UTC)
blocklist_updater
       │
       ▼ atomic write
/data/blocklist.txt  ──────────────────────────────────────┐
                                                            │
Internet attacker                                           │
       │                                                    │
       ▼ port 2222                                          ▼
┌─────────────────────────────────────────────┐    filter_gateway container
│  HAProxy (Layer 1: rate limiting, in-memory)│
│       │                                     │
│  HAProxy Lua (Layer 2: IP check)            │
│       │  ──── Unix socket ────▶             │
│       │       filter_server.py              │
│       │         ├── blocklist.txt (5m cache)│
│       │         └── bans.db  ◀─────────────────── session_analyzer writes here
│       │                                     │
│  ACCEPT ──▶ Cowrie honeypot                 │
│  DROP   ──▶ blackhole (30s silent hang)     │
└─────────────────────────────────────────────┘
                     │
              Cowrie JSON logs
                     │
                     ▼
            session_analyzer
              ├── PatternMatcher
              ├── BanManager ──▶ bans.db
              └── AlertManager ──▶ Slack
```

---

## Component 1: `blocklist_updater`

**Role**: Pre-emptive blocking based on global threat intelligence.

### What It Does

Pulls known-bad IPs from the AbuseIPDB `/api/v2/blacklist` endpoint once per day and writes them to `/data/blocklist.txt`. The filter gateway reads this file to block IPs before they ever reach the honeypot.

### Schedule

Runs immediately on container start, then sleeps until the next `UPDATE_HOUR:00 UTC` (default: 03:00). Sleep is computed precisely to the target wall-clock time rather than a fixed interval.

### Fetch Logic

- `CONFIDENCE_MINIMUM` env var (default: 90) filters to high-confidence malicious IPs only
- Each IP from the API response is validated with `ipaddress.ip_address()` — invalid entries are skipped
- Three failure modes, all conservative (existing file is never deleted on failure):
  - Rate limited (429) → keep existing file
  - Network error → keep existing file
  - AbuseIPDB returns 0 IPs → keep existing file (treats empty list as suspicious)

### Atomic Write

```python
fd, tmp_path = tempfile.mkstemp(dir=str(DATA_DIR), suffix=".tmp")
# ... write all IPs to tmp_path ...
os.rename(tmp_path, str(BLOCKLIST_PATH))
```

`os.rename()` is atomic on Linux when source and destination are on the same filesystem. The filter sidecar can never read a half-written file — it sees either the complete old list or the complete new list.

---

## Component 2: `filter_gateway`

**Role**: Internet-facing TCP gate that enforces two blocklists at connection time.

The container runs two processes together: HAProxy and a Python sidecar. The entrypoint has a safety interlock — if the sidecar socket doesn't appear within 5 seconds, the container aborts and HAProxy never starts. This guarantees HAProxy cannot run without the filter in place.

### Layer 1 — HAProxy Rate Limiting (in-memory, no I/O)

```
stick-table type ip size 100k expire 5m store conn_rate(1m),conn_cur
tcp-request connection reject if { sc0_conn_rate gt env(MAX_CONN_RATE) }
tcp-request connection reject if { sc0_conn_cur gt env(MAX_CONCURRENT) }
```

HAProxy maintains an in-memory stick table keyed by source IP tracking connections per minute and current open connections. Connections exceeding either threshold are dropped at the TCP level — no Lua, no Python, no database lookup. Cheapest possible filter.

### Layer 2 — Lua Bridge to Python Sidecar

```
tcp-request content lua.check_filter
use_backend blackhole if { var(txn.filter_decision) -m str DROP }
```

The Lua function sends the client IP over a Unix socket (`/tmp/filter.sock`) to `filter_server.py`, reads back `ACCEPT` or `DROP`, and sets a HAProxy transaction variable. HAProxy routes based on that variable.

`DROP` goes to the `blackhole` backend which has no server — the connection hangs for 30 seconds before timing out. Silent drop: the attacker gets no RST, no error, wasting their scanner's time.

### Filter Sidecar Decision Logic

Two-step waterfall, checked in order:

```python
def check_ip(self, ip: str) -> tuple[str, str]:
    if self.blocklist.contains(ip):   # Step 1: set lookup
        return "DROP", "blocklist"
    if self.bans.is_banned(ip):       # Step 2: SQL query
        return "DROP", "ban"
    return "ACCEPT", "passed"
```

**Step 1 — BlocklistStore**: The `blocklist.txt` file is loaded into a Python `set` in memory. `contains()` checks `time.time() - last_loaded > 300` on every call — if 5 minutes have elapsed, it re-reads the file before answering. Reload is lazy (no polling thread), triggered by incoming connections.

**Step 2 — BanChecker**: Queries `bans.db` with a single indexed SQL lookup:
```sql
SELECT 1 FROM bans WHERE ip = ? AND ban_until > ?
```
The `ban_until` timestamp makes bans auto-expire with no cleanup job. This is the same database `session_analyzer` writes to.

Input is validated with `ipaddress.ip_address()` before any lookup. Invalid input gets `ACCEPT` — fail-open on malformed data since Lua controls the input.

Every decision (ACCEPT and DROP) is appended as a JSON line to `/data/filter.log` for auditing.

---

## Component 3: `session_analyzer`

**Role**: Real-time behavioral analysis of completed Cowrie sessions; writes IP bans.

### Data Flow

```
Cowrie log line (JSON)
   → parse
   → SessionAggregator: accumulate events until session.closed
   → Session object (ip, commands, auth counts, duration)
   → PatternMatcher.analyze_session()
       ├─ auth_brute?        (counter threshold)
       ├─ rapid_disconnect?  (timing heuristic)
       ├─ seed signature?    (JSON pattern substring match)
       └─ known fingerprint? (SHA256 lookup in signatures.db)
   → if any match: BanManager.ban_ip() → bans.db
   → AlertManager.record_connection() (always, for spike tracking)
```

### Log Watching

`watchdog` monitors three Cowrie log directories (one per hop) simultaneously. Each `CowrieLogHandler` tracks byte offsets per file — on each `FileModifiedEvent` it seeks to the last known position and reads only new lines. `initial_scan()` on startup reads pre-existing logs from position 0.

### Session Aggregation

Cowrie emits individual JSON events per line, each with a `session` ID and `eventid`. The aggregator stitches them into a `Session` object:

| Cowrie event | Effect |
|---|---|
| `cowrie.session.connect` | Creates Session, records src_ip and start time |
| `cowrie.login.failed` | Increments `auth_failed` |
| `cowrie.login.success` | Increments `auth_success` |
| `cowrie.command.input` | Appends to `commands` list |
| `cowrie.session.file_download` | Appends URL to `downloads` list |
| `cowrie.session.closed` | Records end time, removes from memory, returns Session |

A threading lock guards the sessions dict since all three hop handlers write to it concurrently.

### Pattern Matching

**Rule 1 — Auth brute force**
```python
if auth_failed >= brute_force_threshold:  # default: 20
    matches.append("auth_brute")
```

**Rule 2 — Rapid disconnect**
```python
if auth_success > 0 and duration < rapid_disconnect_sec and len(commands) == 0:
    matches.append("rapid_disconnect")
```
Catches credential sprayers: they log in but disconnect immediately without running commands.

**Rule 3 — Seed signatures**
JSON files in `signatures/` define known attack patterns. Each signature has multiple pattern groups, each group a list of command substrings that must all appear anywhere in the session's command set:

```json
// mirai.json
{"label": "mirai", "patterns": [
  ["wget", "chmod 777", "/tmp/"],
  ["/bin/busybox", "cat /proc/mounts"]
]}
```

Match is substring-based and order-independent. A match produces a label like `seed_mirai`.

**Rule 4 — Fingerprint auto-learning**

Every session with commands gets fingerprinted:
1. Each command is normalized: lowercased, IPs → `IPARG`, URLs → `URLARG`, full paths → basename
2. Normalized commands are sorted (order-independent) and concatenated
3. SHA256 is computed over the result

The fingerprint is stored in `signatures.db`. When the count of distinct source IPs producing the same fingerprint reaches `learn_threshold` (default: 5), the fingerprint is promoted to a known signature — future sessions with the same command pattern get auto-banned. Normalization is key: two Mirai bots from different IPs produce the same fingerprint because `IPARG` replaces the specific address.

### IP Banning with Escalation

```python
ESCALATION_DURATIONS = [
    timedelta(hours=1),   # Level 0: first offense
    timedelta(hours=6),   # Level 1
    timedelta(hours=24),  # Level 2
    timedelta(days=7),    # Level 3
    timedelta(days=30),   # Level 4: repeat offender
]
```

Each repeat offense against the same IP escalates one level. The filter sidecar's `ban_until > now` query makes expiry automatic.

### Alerting (Slack Webhook)

Three alert types:

**Connection spike** — background thread runs every 60 seconds. Compares connection rate in the last N minutes against the 1-hour rolling baseline. Fires if ratio exceeds `SPIKE_MULTIPLIER` (default: 5×), with a 30-minute cooldown to prevent floods. Reports top 5 IPs by count.

**New pattern learned** — fires immediately when a fingerprint crosses the auto-learn threshold. Reports the first 10 commands and number of unique source IPs.

**Daily summary** — fires at midnight UTC. Reports total, accepted, dropped counts with per-reason breakdown.

All attacker-controlled strings are HTML-escaped before embedding in Slack mrkdwn to prevent injection.

---

## Enforcement List Comparison

| | `blocklist.txt` | `bans.db` |
|---|---|---|
| Written by | `blocklist_updater` | `session_analyzer` |
| Source | AbuseIPDB global community intel | Local honeypot observations |
| Updated | Daily at 03:00 UTC | Real-time, within seconds of session close |
| Scope | Known-bad IPs globally | IPs that attacked this honeypot |
| Expiry | Replaced entirely each update | Per-ban `ban_until` timestamp |
| Lookup cost | `set` membership test | Single indexed SQL query |

The filter sidecar checks blocklist first (cheaper) then bans second. An IP only needs to appear in one list to be dropped.

---

## End-to-End Example

```
1. blocklist_updater fetches AbuseIPDB at 03:00 UTC
   └─▶ writes 50,000 IPs to /data/blocklist.txt (atomic rename)

2. Attacker 1.2.3.4 connects (already in AbuseIPDB)
   └─▶ HAProxy rate check: passes
       └─▶ Lua sends "1.2.3.4" to filter_server.py
           └─▶ BlocklistStore.contains() → True
               └─▶ returns "DROP" → blackhole → 30s silent hang

3. Attacker 5.6.7.8 connects (not in AbuseIPDB, not yet banned)
   └─▶ ACCEPT → Cowrie honeypot (hop1)
       └─▶ runs wget, chmod 777, downloads from /tmp/
           └─▶ session closes
               └─▶ session_analyzer: PatternMatcher matches "seed_mirai"
                   └─▶ BanManager.ban_ip("5.6.7.8") → bans.db (1hr)
                       └─▶ AlertManager: Slack alert

4. Attacker 5.6.7.8 reconnects
   └─▶ HAProxy rate check: passes
       └─▶ Lua sends "5.6.7.8" to filter_server.py
           └─▶ BlocklistStore: not in blocklist
               └─▶ BanChecker.is_banned() → True (ban_until in future)
                   └─▶ returns "DROP" → blackhole
```
