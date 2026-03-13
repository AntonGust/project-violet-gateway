# Internet-Exposed Honeypot Module — Architecture Design

**Based on**: `docs/internet_honeypot_requirements.md`

---

## 1. System Architecture

```
                        ┌─────────────────────────────────────────────────────────┐
                        │                    VLAN / DMZ (Layer 1)                  │
                        │                                                         │
  Internet              │  ┌─────────────────────────────────────────────────┐    │
     │                  │  │         Docker: honeypot_isolated network        │    │
     │                  │  │                                                  │    │
     ▼                  │  │  ┌──────────────┐    ┌───────────────────────┐  │    │
  Router                │  │  │   Blocklist   │    │    Session Store      │  │    │
  NAT:22→2222           │  │  │   Updater     │    │    (SQLite volume)    │  │    │
     │                  │  │  │  (cron daily)  │    │  - session metadata   │  │    │
     ▼                  │  │  └──────┬─────────┘    │  - learned signatures │  │    │
  Host:2222             │  │         │ writes       │  - ban state          │  │    │
     │                  │  │         ▼              └───────────┬───────────┘  │    │
     │  iptables        │  │  ┌──────────────┐                 │              │    │
     │  (Layer 2)       │  │  │              │◄────────────────┘              │    │
     ▼                  │  │  │   Filter     │         reads                  │    │
  ┌─────────────────┐   │  │  │   Gateway    │                               │    │
  │ host:2222       │───┼──┼─►│   :2222      │    ┌──────────────────────┐   │    │
  │ (mapped)        │   │  │  │              │───►│   Alert Manager      │   │    │
  └─────────────────┘   │  │  │  (haproxy +  │    │   (Slack webhook)    │   │    │
                        │  │  │   Python     │    └──────────────────────┘   │    │
                        │  │  │   sidecar)   │                               │    │
                        │  │  └──────┬───────┘                               │    │
                        │  │         │ proxy (accepted connections only)      │    │
                        │  │         ▼                                        │    │
                        │  │  ┌──────────────────────────────────────────┐   │    │
                        │  │  │            net_entry: 172.20.0.0/24      │   │    │
                        │  │  │                                          │   │    │
                        │  │  │  ┌──────────────┐                        │   │    │
                        │  │  │  │ Cowrie Hop1  │  172.20.0.10           │   │    │
                        │  │  │  │ :2222        │                        │   │    │
                        │  │  │  └──────┬───────┘                        │   │    │
                        │  │  │         │                                 │   │    │
                        │  │  ├─────────┼────────────────────────────────┤   │    │
                        │  │  │         │  net_hop1: 172.20.1.0/24       │   │    │
                        │  │  │         ▼                                 │   │    │
                        │  │  │  ┌──────────────┐  ┌──────────────────┐  │   │    │
                        │  │  │  │ Cowrie Hop2  │  │ honeypot_db_hop2 │  │   │    │
                        │  │  │  │ 172.20.1.11  │  │ (postgres)       │  │   │    │
                        │  │  │  └──────┬───────┘  │ 172.20.1.22      │  │   │    │
                        │  │  │         │          └──────────────────┘  │   │    │
                        │  │  ├─────────┼────────────────────────────────┤   │    │
                        │  │  │         │  net_hop2: 172.20.2.0/24       │   │    │
                        │  │  │         ▼                                 │   │    │
                        │  │  │  ┌──────────────┐                        │   │    │
                        │  │  │  │ Cowrie Hop3  │                        │   │    │
                        │  │  │  │ 172.20.2.12  │                        │   │    │
                        │  │  │  └──────────────┘                        │   │    │
                        │  │  └──────────────────────────────────────────┘   │    │
                        │  └─────────────────────────────────────────────────┘    │
                        └─────────────────────────────────────────────────────────┘
```

---

## 2. Container Topology

### 2.1 Containers (7 total)

| Container | Image | Role | Networks |
|-----------|-------|------|----------|
| `filter_gateway` | Custom (HAProxy + Python sidecar) | TCP proxy with filtering logic | `honeypot_external`, `net_entry` |
| `cowrie_hop1` | `Cowrie/cowrie-src` (existing) | SSH honeypot, entry point | `net_entry`, `net_hop1` |
| `cowrie_hop2` | `Cowrie/cowrie-src` (existing) | SSH honeypot, lateral move target | `net_hop1`, `net_hop2` |
| `cowrie_hop3` | `Cowrie/cowrie-src` (existing) | SSH honeypot, deep target | `net_hop2` |
| `honeypot_db_hop2` | `postgres:16` | Decoy database for hop2 | `net_hop1` |
| `session_analyzer` | Custom Python | Reads Cowrie logs, builds signatures, manages bans | `net_entry` (for log volume access) |
| `blocklist_updater` | Custom Python (cron) | Daily AbuseIPDB pull → shared blocklist file | None (volume-only) |

### 2.2 Docker Networks (4 internal + 1 external-facing)

| Network | Subnet | Purpose | Connected Containers |
|---------|--------|---------|---------------------|
| `honeypot_external` | `172.20.99.0/24` | Receives host-mapped port, isolated from all else | `filter_gateway` only |
| `net_entry` | `172.20.0.0/24` | Gateway → Hop1, session analyzer | `filter_gateway`, `cowrie_hop1`, `session_analyzer` |
| `net_hop1` | `172.20.1.0/24` | Hop1 → Hop2, decoy DB | `cowrie_hop1`, `cowrie_hop2`, `honeypot_db_hop2` |
| `net_hop2` | `172.20.2.0/24` | Hop2 → Hop3 | `cowrie_hop2`, `cowrie_hop3` |

Key: `honeypot_external` is the only network with a port published to the host. No Cowrie container is directly reachable from outside.

---

## 3. Filter Gateway — Detailed Design

The filter gateway is the core security component. It's a **TCP-level proxy** — it does not terminate SSH, it proxies raw TCP to Cowrie.

### 3.1 Architecture

```
┌─────────────────────────────────────────────────────┐
│                  filter_gateway container             │
│                                                       │
│  ┌─────────────┐     ┌────────────────────────────┐  │
│  │  HAProxy    │     │  Filter Sidecar (Python)    │  │
│  │  :2222      │     │                             │  │
│  │             │────►│  1. Check blocklist (file)   │  │
│  │  TCP mode   │     │  2. Check ban DB (SQLite)    │  │
│  │  lua hook   │     │  3. Check rate limiter        │  │
│  │             │◄────│  4. Return: ACCEPT / DROP     │  │
│  │             │     │                             │  │
│  │  if ACCEPT: │     └────────────────────────────┘  │
│  │   proxy to  │                                      │
│  │   hop1:2222 │     ┌────────────────────────────┐  │
│  │             │     │  Shared Volumes:             │  │
│  │  if DROP:   │     │  - /data/blocklist.txt       │  │
│  │   silent    │     │  - /data/bans.db (SQLite)    │  │
│  │   timeout   │     │  - /data/signatures.db       │  │
│  └─────────────┘     └────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

### 3.2 Decision Flow (per connection)

```
New TCP connection from IP X
        │
        ▼
┌─ 1. Blocklist check ─┐
│ IP in blocklist.txt?  │──YES──► Silent drop (close after 30s timeout)
└───────┬───────────────┘
        │ NO
        ▼
┌─ 2. Ban check ────────┐
│ IP in bans.db with    │──YES──► Silent drop
│ active ban?           │
└───────┬───────────────┘
        │ NO
        ▼
┌─ 3. Rate limit ───────┐
│ >10 conns/min from IP?│──YES──► Silent drop + add ban (1h initial)
└───────┬───────────────┘
        │ NO
        ▼
┌─ 4. Concurrent limit ─┐
│ >3 active sessions    │──YES──► Silent drop
│ from this IP?         │
└───────┬───────────────┘
        │ NO
        ▼
    ACCEPT → Proxy TCP to cowrie_hop1:2222
    Log: timestamp, src_ip, decision=ACCEPT
```

### 3.3 Silent Drop Implementation

Not a TCP RST. HAProxy `tcp-request connection reject` with a `timeout client 30s` on a dummy backend that never responds. The attacker sees a connection that hangs and eventually times out — indistinguishable from a filtered port or network issue.

### 3.4 HAProxy Configuration (Conceptual)

```haproxy
global
    log stdout format raw local0

defaults
    mode tcp
    timeout connect 5s
    timeout client  300s    # Real sessions can be long
    timeout server  300s

frontend ssh_in
    bind *:2222
    # Lua script calls filter sidecar via unix socket
    tcp-request connection lua.check_filter
    tcp-request connection reject if { var(txn.filter_decision) -m str DROP }

    # Rate limiting at HAProxy level (first line of defense)
    stick-table type ip size 100k expire 1m store conn_rate(1m),conn_cur
    tcp-request connection track-sc0 src
    tcp-request connection reject if { sc0_conn_rate gt 10 }
    tcp-request connection reject if { sc0_conn_cur gt 3 }

    default_backend cowrie_hop1

backend cowrie_hop1
    server hop1 cowrie_hop1:2222

backend blackhole
    # Silent drop — no server, connection hangs until timeout
    timeout server 30s
```

---

## 4. Session Analyzer — Detailed Design

Runs as a separate container. Watches Cowrie log files, extracts patterns, and updates the ban/signature databases.

### 4.1 Architecture

```
┌─────────────────────────────────────────────────────┐
│              session_analyzer container               │
│                                                       │
│  ┌─────────────────────────────────────────────────┐ │
│  │              Log Watcher (inotify)               │ │
│  │  Watches: /cowrie_logs/cowrie.json               │ │
│  └──────────────────────┬──────────────────────────┘ │
│                         │ new log lines               │
│                         ▼                             │
│  ┌─────────────────────────────────────────────────┐ │
│  │              Session Aggregator                   │ │
│  │  Groups log events by session ID                  │ │
│  │  Builds: auth_attempts, commands[], duration,     │ │
│  │          downloads[], src_ip                       │ │
│  └──────────────────────┬──────────────────────────┘ │
│                         │ completed sessions          │
│                         ▼                             │
│  ┌─────────────────────────────────────────────────┐ │
│  │              Pattern Matcher                      │ │
│  │                                                   │ │
│  │  Static rules:                                    │ │
│  │  - AUTH_BRUTE: >20 failed auths in session       │ │
│  │  - MIRAI_SIG:  commands match known Mirai set    │ │
│  │  - RAPID_DISC: session <5s after auth             │ │
│  │  - KNOWN_BOT:  command hash matches signature DB  │ │
│  │                                                   │ │
│  │  Learned signatures:                              │ │
│  │  - Command sequence fingerprints (n-gram hash)    │ │
│  │  - If same fingerprint seen >N times from         │ │
│  │    different IPs → auto-add to signature DB       │ │
│  └──────────────────────┬──────────────────────────┘ │
│                         │ match results               │
│                         ▼                             │
│  ┌────────────────┐  ┌────────────────────────────┐  │
│  │  Ban Manager   │  │  Alert Manager             │  │
│  │                │  │                            │  │
│  │  Writes to     │  │  Spike detection:          │  │
│  │  bans.db:      │  │  - 10min sliding window    │  │
│  │                │  │  - alert if >5x baseline   │  │
│  │  - IP          │  │                            │  │
│  │  - reason      │  │  New pattern alert:        │  │
│  │  - ban_until   │  │  - unknown signature seen  │  │
│  │  - escalation  │  │    from >3 IPs             │  │
│  │    level       │  │                            │  │
│  │                │  │  → Slack webhook POST      │  │
│  └────────────────┘  └────────────────────────────┘  │
└─────────────────────────────────────────────────────┘
```

### 4.2 Signature Learning Algorithm

```
For each completed session:
  1. Extract command sequence → ["uname -a", "cat /etc/passwd", "wget http://..."]
  2. Normalize: lowercase, strip args with IPs/URLs → ["uname -a", "cat /etc/passwd", "wget URLARG"]
  3. Compute fingerprint: SHA256 of normalized sorted command set
  4. Store in sessions table: (session_id, src_ip, fingerprint, timestamp, commands_json)
  5. Count: SELECT COUNT(DISTINCT src_ip) WHERE fingerprint = X
  6. If count >= LEARN_THRESHOLD (default: 5 unique IPs):
     → INSERT INTO signatures (fingerprint, label="auto_learned", commands, first_seen, hit_count)
     → Future sessions matching this fingerprint → auto-ban
```

This ensures we only learn patterns that are genuinely repeated across multiple attackers, not one-off sessions.

### 4.3 Ban Escalation Logic

```python
ESCALATION_DURATIONS = [
    timedelta(hours=1),     # Level 0: first offense
    timedelta(hours=6),     # Level 1
    timedelta(hours=24),    # Level 2
    timedelta(days=7),      # Level 3
    timedelta(days=30),     # Level 4: repeat offender
]

def ban_ip(ip: str, reason: str):
    existing = db.get_ban(ip)
    if existing and existing.level < len(ESCALATION_DURATIONS) - 1:
        level = existing.level + 1
    elif existing:
        level = existing.level  # Max level, extend duration
    else:
        level = 0

    duration = ESCALATION_DURATIONS[level]
    db.upsert_ban(ip, reason, level, ban_until=now() + duration)
```

---

## 5. Blocklist Updater — Design

Minimal container that runs once daily via cron.

```
┌────────────────────────────────────────┐
│        blocklist_updater container       │
│                                          │
│  Entrypoint: crond (runs daily at 03:00) │
│                                          │
│  Script: update_blocklist.py             │
│  1. GET abuseipdb.com/api/v2/blacklist  │
│     Header: Key=$ABUSEIPDB_API_KEY      │
│     Params: confidenceMinimum=90         │
│  2. Parse response → IP list             │
│  3. Write to /data/blocklist.txt         │
│     (one IP per line, atomic write)      │
│  4. Log: "Updated blocklist: N IPs"      │
│                                          │
│  Volume: /data (shared with gateway)     │
└────────────────────────────────────────┘
```

Atomic write: write to `.tmp`, then `os.rename()` to avoid HAProxy reading a partial file.

---

## 6. Network Isolation — iptables Rules

### 6.1 Host iptables Script (`setup_iptables.sh`)

This script locks down the host so honeypot containers cannot reach the LAN.

```bash
#!/bin/bash
# Internet Honeypot — Host Firewall Setup
# Run once after boot (or add to systemd)

set -euo pipefail

# === CONFIGURATION ===
HONEYPOT_PORT=2222                          # Host port for incoming SSH
DOCKER_HONEYPOT_SUBNETS=(                   # All honeypot Docker subnets
    "172.20.0.0/24"   # net_entry
    "172.20.1.0/24"   # net_hop1
    "172.20.2.0/24"   # net_hop2
    "172.20.99.0/24"  # honeypot_external
)
LAN_SUBNETS=(                               # Lab network ranges to PROTECT
    "10.0.0.0/8"
    "192.168.0.0/16"
    "172.16.0.0/12"   # Except our 172.20.x.x honeypot ranges
)

# === Create custom chain ===
iptables -N HONEYPOT_ISOLATION 2>/dev/null || iptables -F HONEYPOT_ISOLATION

# === Rule 1: Allow honeypot containers to talk to each other ===
for subnet in "${DOCKER_HONEYPOT_SUBNETS[@]}"; do
    for dest in "${DOCKER_HONEYPOT_SUBNETS[@]}"; do
        iptables -A HONEYPOT_ISOLATION -s "$subnet" -d "$dest" -j ACCEPT
    done
done

# === Rule 2: Allow outbound HTTPS (for Slack webhooks + AbuseIPDB API) ===
for subnet in "${DOCKER_HONEYPOT_SUBNETS[@]}"; do
    iptables -A HONEYPOT_ISOLATION -s "$subnet" -p tcp --dport 443 -d 0.0.0.0/0 -j ACCEPT
    iptables -A HONEYPOT_ISOLATION -s "$subnet" -p tcp --dport 53 -j ACCEPT
    iptables -A HONEYPOT_ISOLATION -s "$subnet" -p udp --dport 53 -j ACCEPT
done

# === Rule 3: BLOCK all honeypot → LAN traffic ===
for subnet in "${DOCKER_HONEYPOT_SUBNETS[@]}"; do
    for lan in "${LAN_SUBNETS[@]}"; do
        iptables -A HONEYPOT_ISOLATION -s "$subnet" -d "$lan" -j DROP
    done
done

# === Rule 4: BLOCK honeypot → host services (except Docker gateway) ===
for subnet in "${DOCKER_HONEYPOT_SUBNETS[@]}"; do
    iptables -A HONEYPOT_ISOLATION -s "$subnet" -d "$(hostname -I | awk '{print $1}')" -j DROP
done

# === Insert into FORWARD chain ===
iptables -I FORWARD 1 -j HONEYPOT_ISOLATION

# === Allow inbound to honeypot port ===
iptables -A INPUT -p tcp --dport "$HONEYPOT_PORT" -j ACCEPT

echo "[+] Honeypot isolation rules applied."
echo "[+] Honeypot subnets blocked from LAN: ${LAN_SUBNETS[*]}"
```

### 6.2 What This Prevents

| Attack Vector | Mitigation |
|---------------|------------|
| Container escape → LAN access | iptables DROP on all honeypot→LAN |
| Container escape → host services | DROP honeypot→host IP |
| Cowrie reaching internet directly | Only port 443 (HTTPS) outbound allowed |
| Cross-network Docker escape | Subnets are bridged, iptables blocks forwarding |
| Docker socket mount | Not mounted (compose config) |

### 6.3 VLAN Documentation (for Lab Network Admin)

```
VLAN Requirements for Honeypot DMZ
===================================

Request: Dedicated VLAN for honeypot host.

1. Create VLAN (e.g., VLAN 100) on the lab switch
2. Assign one switch port to VLAN 100 (honeypot host NIC)
3. Router/firewall rules:
   - ALLOW: Internet → VLAN 100, TCP port 22 (NAT to host:2222)
   - ALLOW: VLAN 100 → Internet, TCP port 443 (HTTPS for alerts/blocklists)
   - ALLOW: VLAN 100 → Internet, UDP/TCP port 53 (DNS)
   - DENY:  VLAN 100 → Lab LAN (all other VLANs)
   - DENY:  Lab LAN → VLAN 100 (optional, for management use SSH on separate port)
4. NAT rule: External port 22 → VLAN 100 host:2222
```

---

## 7. Shared Volumes & Data Model

### 7.1 Volume Layout

```
volumes:
  filter_data:        # Shared between gateway, analyzer, updater
    # /data/blocklist.txt     — IP blocklist (updated daily)
    # /data/bans.db           — SQLite: active bans + escalation state
    # /data/signatures.db     — SQLite: learned attack signatures
    # /data/filter.log        — Connection decisions log

  cowrie_logs:        # Cowrie JSON logs (read by session_analyzer)
    # /cowrie_logs/hop1/cowrie.json
    # /cowrie_logs/hop2/cowrie.json
    # /cowrie_logs/hop3/cowrie.json

  cowrie_hop1_config: # Existing hop1 config (etc, honeyfs, share, var)
  cowrie_hop2_config: # Existing hop2 config
  cowrie_hop3_config: # Existing hop3 config
```

### 7.2 SQLite Schemas

**bans.db**
```sql
CREATE TABLE bans (
    ip           TEXT PRIMARY KEY,
    reason       TEXT NOT NULL,       -- 'rate_limit', 'brute_force', 'spam_pattern', 'blocklist'
    level        INTEGER DEFAULT 0,   -- Escalation level (0-4)
    ban_until    TIMESTAMP NOT NULL,
    created_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    updated_at   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    hit_count    INTEGER DEFAULT 1    -- Times this IP was re-banned
);

CREATE INDEX idx_bans_until ON bans(ban_until);
```

**signatures.db**
```sql
CREATE TABLE sessions (
    id           INTEGER PRIMARY KEY AUTOINCREMENT,
    session_id   TEXT UNIQUE NOT NULL,
    src_ip       TEXT NOT NULL,
    fingerprint  TEXT NOT NULL,       -- SHA256 of normalized command set
    commands     TEXT NOT NULL,        -- JSON array of commands
    auth_attempts INTEGER DEFAULT 0,
    duration_sec REAL,
    hop          INTEGER DEFAULT 1,   -- Which hop (1/2/3)
    timestamp    TIMESTAMP DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE signatures (
    fingerprint  TEXT PRIMARY KEY,
    label        TEXT NOT NULL,       -- 'mirai', 'auto_learned', 'brute_force', etc.
    commands     TEXT NOT NULL,        -- JSON: representative command set
    first_seen   TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    hit_count    INTEGER DEFAULT 1,
    unique_ips   INTEGER DEFAULT 1,
    auto_ban     BOOLEAN DEFAULT TRUE
);

CREATE TABLE stats (
    date              TEXT PRIMARY KEY,  -- YYYY-MM-DD
    total_connections  INTEGER DEFAULT 0,
    accepted           INTEGER DEFAULT 0,
    dropped_blocklist  INTEGER DEFAULT 0,
    dropped_ban        INTEGER DEFAULT 0,
    dropped_rate       INTEGER DEFAULT 0,
    dropped_pattern    INTEGER DEFAULT 0,
    unique_ips         INTEGER DEFAULT 0
);

CREATE INDEX idx_sessions_fingerprint ON sessions(fingerprint);
CREATE INDEX idx_sessions_src_ip ON sessions(src_ip);
```

---

## 8. Alert Manager — Slack Integration

### 8.1 Alert Types & Payloads

**Connection Spike Alert**
```json
{
  "text": "🚨 *Honeypot Alert: Connection Spike*",
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*Connection spike detected*\nCurrent: 150 conns/10min\nBaseline: 25 conns/10min\nRatio: 6.0x\nTop IPs: `203.0.113.5` (42), `198.51.100.12` (31)"
      }
    }
  ]
}
```

**New Pattern Alert**
```json
{
  "text": "🔍 *Honeypot Alert: New Attack Pattern*",
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*New attack pattern auto-learned*\nFingerprint: `a3f8...b2c1`\nSeen from: 5 unique IPs\nCommands: `uname -a`, `cat /proc/cpuinfo`, `curl http://...`, `chmod +x /tmp/x`\nAction: Auto-ban enabled"
      }
    }
  ]
}
```

**Daily Summary (posted at 00:00 UTC)**
```json
{
  "text": "📊 *Honeypot Daily Summary*",
  "blocks": [
    {
      "type": "section",
      "text": {
        "type": "mrkdwn",
        "text": "*2026-03-13 Summary*\nTotal connections: 1,247\nAccepted: 89 (7.1%)\nDropped: 1,158 (92.9%)\n  - Blocklist: 430\n  - Rate limit: 512\n  - Ban: 198\n  - Pattern match: 18\nUnique IPs: 342\nNew signatures learned: 2\nActive bans: 156"
      }
    }
  ]
}
```

---

## 9. Docker Compose — Full Specification

```yaml
# docker-compose.internet-honeypot.yml

services:

  # === FILTER GATEWAY ===
  filter_gateway:
    build: ./internet_honeypot/filter_gateway
    restart: always
    ports:
      - "2222:2222"
    networks:
      honeypot_external:
        ipv4_address: 172.20.99.2
      net_entry:
        ipv4_address: 172.20.0.2
    volumes:
      - filter_data:/data
    environment:
      - COWRIE_HOP1_HOST=172.20.0.10
      - COWRIE_HOP1_PORT=2222
      - MAX_CONN_RATE=10        # per IP per minute
      - MAX_CONCURRENT=3        # per IP
      - SILENT_DROP_TIMEOUT=30  # seconds
    mem_limit: 256m
    cpus: 0.5
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true

  # === SESSION ANALYZER ===
  session_analyzer:
    build: ./internet_honeypot/session_analyzer
    restart: always
    networks:
      net_entry:
        ipv4_address: 172.20.0.5
    volumes:
      - filter_data:/data
      - cowrie_hop1_var:/cowrie_logs/hop1:ro
      - cowrie_hop2_var:/cowrie_logs/hop2:ro
      - cowrie_hop3_var:/cowrie_logs/hop3:ro
    environment:
      - LEARN_THRESHOLD=5           # Unique IPs before auto-learn
      - BRUTE_FORCE_THRESHOLD=20    # Failed auths before ban
      - RAPID_DISCONNECT_SEC=5      # Session shorter than this = suspicious
      - SPIKE_WINDOW_MIN=10         # Sliding window for spike detection
      - SPIKE_MULTIPLIER=5          # Alert if >5x baseline
      - SLACK_WEBHOOK_URL=${SLACK_WEBHOOK_URL}
    mem_limit: 256m
    cpus: 0.5
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true

  # === BLOCKLIST UPDATER ===
  blocklist_updater:
    build: ./internet_honeypot/blocklist_updater
    restart: always
    volumes:
      - filter_data:/data
    environment:
      - ABUSEIPDB_API_KEY=${ABUSEIPDB_API_KEY}
      - CONFIDENCE_MINIMUM=90
      - UPDATE_HOUR=3   # Run at 03:00
    mem_limit: 128m
    cpus: 0.25
    read_only: true
    tmpfs:
      - /tmp
    security_opt:
      - no-new-privileges:true

  # === COWRIE HOP 1 (Entry Point) ===
  cowrie_hop1:
    build: Cowrie/cowrie-src
    restart: always
    environment:
      - COWRIE_HYBRID_LLM_API_KEY=${OPENAI_API_KEY}
      - COWRIE_HYBRID_LLM_ENABLED=true
      - HONEYNET_MODE=true
      - COWRIE_DB_HOST=172.20.0.4
      - COWRIE_DB_ENGINE=mysql
      - COWRIE_DB_PORT=3306
      - COWRIE_DB_ROOT_PASSWORD=H0n3yp0t_R00t!
      - COWRIE_DB_NAME=wordpress_prod
      - COWRIE_DB_USER=wp_admin
      - COWRIE_DB_PASSWORD=Str0ng_But_Le4ked!
    volumes:
      - ./cowrie_config_hop1/etc:/cowrie/cowrie-git/etc
      - ./cowrie_config_hop1/honeyfs:/cowrie/cowrie-git/honeyfs
      - ./cowrie_config_hop1/share:/cowrie/cowrie-git/share/cowrie
      - cowrie_hop1_var:/cowrie/cowrie-git/var
    networks:
      net_entry:
        ipv4_address: 172.20.0.10
      net_hop1:
        ipv4_address: 172.20.1.10
    mem_limit: 512m
    cpus: 1.0
    security_opt:
      - no-new-privileges:true

  # === COWRIE HOP 2 ===
  cowrie_hop2:
    build: Cowrie/cowrie-src
    restart: always
    environment:
      - COWRIE_HYBRID_LLM_API_KEY=${OPENAI_API_KEY}
      - COWRIE_HYBRID_LLM_ENABLED=true
      - HONEYNET_MODE=true
      - COWRIE_DB_HOST=172.20.1.22
      - COWRIE_DB_ENGINE=postgresql
      - COWRIE_DB_PORT=5432
      - COWRIE_DB_ROOT_PASSWORD=H0n3yp0t_R00t!
      - COWRIE_DB_NAME=postgres
      - COWRIE_DB_USER=postgres
      - COWRIE_DB_PASSWORD=P0stgr3s_Sup3r_S3cret!
    volumes:
      - ./cowrie_config_hop2/etc:/cowrie/cowrie-git/etc
      - ./cowrie_config_hop2/honeyfs:/cowrie/cowrie-git/honeyfs
      - ./cowrie_config_hop2/share:/cowrie/cowrie-git/share/cowrie
      - cowrie_hop2_var:/cowrie/cowrie-git/var
    networks:
      net_hop1:
        ipv4_address: 172.20.1.11
      net_hop2:
        ipv4_address: 172.20.2.11
    mem_limit: 512m
    cpus: 1.0
    security_opt:
      - no-new-privileges:true

  # === COWRIE HOP 3 ===
  cowrie_hop3:
    build: Cowrie/cowrie-src
    restart: always
    environment:
      - COWRIE_HYBRID_LLM_API_KEY=${OPENAI_API_KEY}
      - COWRIE_HYBRID_LLM_ENABLED=true
      - HONEYNET_MODE=true
      - COWRIE_DB_HOST=
      - COWRIE_DB_ENGINE=
      - COWRIE_DB_PORT=
      - COWRIE_DB_NAME=
      - COWRIE_DB_USER=
      - COWRIE_DB_PASSWORD=
      - COWRIE_DB_ROOT_PASSWORD=
    volumes:
      - ./cowrie_config_hop3/etc:/cowrie/cowrie-git/etc
      - ./cowrie_config_hop3/honeyfs:/cowrie/cowrie-git/honeyfs
      - ./cowrie_config_hop3/share:/cowrie/cowrie-git/share/cowrie
      - cowrie_hop3_var:/cowrie/cowrie-git/var
    networks:
      net_hop2:
        ipv4_address: 172.20.2.12
    mem_limit: 512m
    cpus: 1.0
    security_opt:
      - no-new-privileges:true

  # === DECOY DATABASE ===
  honeypot_db_hop2:
    image: postgres:16
    restart: "no"
    volumes:
      - ./cowrie_config_hop2/db_init:/docker-entrypoint-initdb.d:ro
    networks:
      net_hop1:
        ipv4_address: 172.20.1.22
    environment:
      POSTGRES_PASSWORD: H0n3yp0t_R00t!
      POSTGRES_DB: app_production
    healthcheck:
      test: ["CMD-SHELL", "pg_isready -U postgres"]
      interval: 5s
      timeout: 3s
      retries: 15
    mem_limit: 256m
    cpus: 0.5

# === NETWORKS ===
networks:
  honeypot_external:
    driver: bridge
    internal: false    # Can reach internet (for inbound connections)
    ipam:
      config:
        - subnet: 172.20.99.0/24
  net_entry:
    driver: bridge
    internal: true     # No direct internet access
    ipam:
      config:
        - subnet: 172.20.0.0/24
  net_hop1:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.20.1.0/24
  net_hop2:
    driver: bridge
    internal: true
    ipam:
      config:
        - subnet: 172.20.2.0/24

# === VOLUMES ===
volumes:
  filter_data:
  cowrie_hop1_var:
  cowrie_hop2_var:
  cowrie_hop3_var:
```

---

## 10. Directory Structure (New Module)

```
internet_honeypot/
├── docker-compose.internet-honeypot.yml
├── setup_iptables.sh                    # Host firewall script
├── .env.example                         # Template: API keys, webhook URL
├── vlan_requirements.txt                # Handoff doc for network admin
│
├── filter_gateway/
│   ├── Dockerfile
│   ├── haproxy.cfg                      # HAProxy TCP proxy config
│   ├── filter_check.lua                 # Lua script for HAProxy
│   └── sidecar/
│       ├── filter_server.py             # Unix socket server, checks blocklist/bans/rate
│       └── requirements.txt
│
├── session_analyzer/
│   ├── Dockerfile
│   ├── analyzer.py                      # Main: log watcher + session aggregator
│   ├── pattern_matcher.py               # Static rules + learned signature matching
│   ├── ban_manager.py                   # Escalating ban logic
│   ├── alert_manager.py                 # Slack webhook + spike detection
│   ├── signatures/
│   │   └── mirai.json                   # Known Mirai command patterns (seed)
│   │   └── generic_brute.json           # Known brute-force patterns (seed)
│   └── requirements.txt
│
└── blocklist_updater/
    ├── Dockerfile
    ├── update_blocklist.py              # AbuseIPDB pull + atomic write
    ├── crontab                          # Schedule: daily at 03:00
    └── requirements.txt
```

---

## 11. Security Hardening Summary

| Layer | Control | Implementation |
|-------|---------|----------------|
| **Network L1** | VLAN isolation | Physical switch config (network admin) |
| **Network L2** | iptables | `setup_iptables.sh` — blocks honeypot→LAN |
| **Docker** | Internal networks | `internal: true` on all except `honeypot_external` |
| **Docker** | Resource limits | `mem_limit`, `cpus` on every container |
| **Docker** | Read-only FS | `read_only: true` + `tmpfs` for temp |
| **Docker** | No privilege escalation | `no-new-privileges:true` |
| **Docker** | No Docker socket | Not mounted anywhere |
| **Application** | Pre-filter | Daily AbuseIPDB blocklist |
| **Application** | Rate limiting | HAProxy stick-table + sidecar |
| **Application** | Ban escalation | 1h → 6h → 24h → 7d → 30d |
| **Application** | Pattern learning | Auto-signature after 5 unique IP matches |
| **Application** | Silent drop | No RST, 30s timeout — looks like filtered port |
| **Monitoring** | Slack alerts | Spikes, new patterns, daily summary |

---

## 12. Next Steps

1. **`/sc:workflow`** — Break this into implementation tasks with ordering and dependencies
2. **`/sc:implement`** — Build the filter_gateway, session_analyzer, and blocklist_updater containers
3. **Network admin handoff** — Share `vlan_requirements.txt` to get VLAN provisioned
