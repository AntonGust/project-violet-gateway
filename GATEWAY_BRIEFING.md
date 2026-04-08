# Project Violet Gateway — Technical Briefing

## The Big Picture

This is a **multi-hop SSH honeypot** with an intelligent filtering gateway in front. When an attacker connects, they hit a filtering layer first, and if allowed through, they land in a chain of **3 Cowrie honeypot instances** that simulate real servers. Each hop looks like a different machine the attacker can "pivot" to, making it feel like a real compromised network. The Cowrie instances are **LLM-enhanced** (using OpenAI API) to generate more convincing responses.

---

## Architecture (7 containers total)

```
Internet
   │
   │ TCP port 2222
   ▼
┌──────────────────────┐
│  filter_gateway       │  HAProxy + Python sidecar
│  172.20.99.2 / 0.2   │  Checks blocklist + bans → ACCEPT or silent DROP
└──────────┬───────────┘
           │ (net_entry: 172.20.0.0/24, internal)
           ▼
┌──────────────────────┐       ┌──────────────────┐
│  cowrie_hop1          │       │ session_analyzer  │
│  172.20.0.10          │──────▶│ 172.20.0.5        │  (reads cowrie logs)
│  "WordPress server"  │       └──────────────────┘
│  MySQL db creds       │
└──────────┬───────────┘
           │ (net_hop1: 172.20.1.0/24, internal)
           ▼
┌──────────────────────┐       ┌───────────────────┐
│  cowrie_hop2          │       │ honeypot_db_hop2   │
│  172.20.1.11          │◀─────▶│ PostgreSQL 16      │
│  "App server"         │       │ 172.20.1.22        │
│  Postgres creds       │       │ Real, with bait    │
└──────────┬───────────┘       └───────────────────┘
           │ (net_hop2: 172.20.2.0/24, internal)
           ▼
┌──────────────────────┐       ┌───────────────────┐
│  cowrie_hop3          │       │ blocklist_updater  │
│  172.20.2.12          │       │ (cron, no network  │
│  "Isolated server"    │       │  except AbuseIPDB) │
└──────────────────────┘       └───────────────────┘
```

---

## Is the Docker container running in privileged mode?

**No. None of them are privileged.** Every single container has:
- `security_opt: no-new-privileges:true` — prevents privilege escalation inside the container
- `read_only: true` — the root filesystem is read-only (only `/tmp` is writable via `tmpfs`)
- Strict **memory and CPU limits** (e.g., filter gateway: 256MB / 0.5 CPU; Cowrie instances: 512MB / 1 CPU)
- The session analyzer even runs as a **non-root user** (`USER analyzer` in its Dockerfile)

The only container without `read_only` is the Postgres decoy database (it needs to write data files), and it's set to `restart: "no"` so if it crashes, it stays down.

---

## What ports are exposed?

**Only one port is exposed to the host: TCP 2222.**

That's it. The filter gateway binds `0.0.0.0:2222` and everything else is internal Docker networking. The AI lab would point their external firewall/NAT to forward port 22 (or whatever they want attackers to hit) to port 2222 on the host machine.

---

## How are the networks isolated?

There are **4 Docker networks**, and only one has external access:

| Network | Subnet | External? | Purpose |
|---|---|---|---|
| `honeypot_external` | 172.20.99.0/24 | Yes | Only the filter gateway connects here |
| `net_entry` | 172.20.0.0/24 | **Internal** | Gateway → Hop1, Session Analyzer |
| `net_hop1` | 172.20.1.0/24 | **Internal** | Hop1 → Hop2, Decoy DB |
| `net_hop2` | 172.20.2.0/24 | **Internal** | Hop2 → Hop3 |

The `internal: true` flag means Docker won't create a gateway for those networks — containers on them literally cannot reach the internet or the host LAN.

On top of this, the **`setup_iptables.sh`** script adds host-level firewall rules that:
1. Allow honeypot containers to talk to each other
2. Allow outbound HTTPS + DNS (for Slack alerts and AbuseIPDB API calls)
3. **Block all honeypot → LAN traffic** (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)
4. **Block honeypot → host machine** specifically

This is the script they'll need to run as root on the host before starting the stack.

---

## How does filtering work? (3 layers)

**Layer 1 — HAProxy rate limiting (in-memory, sub-millisecond):**
- Stick-table tracks per-IP connection rate and concurrent connections
- Rejects if: >10 connections/minute OR >3 concurrent connections
- These thresholds are configurable via `MAX_CONN_RATE` and `MAX_CONCURRENT` env vars

**Layer 2 — Lua → Python sidecar (blocklist + ban check):**
- HAProxy calls a Lua script (`filter_check.lua`) on every connection
- The Lua script sends the source IP over a **Unix socket** (`/tmp/filter.sock`) to a Python sidecar process running inside the same container
- The sidecar checks two things:
  1. **Blocklist** — a flat text file of known-bad IPs from AbuseIPDB (refreshed daily at 3 AM UTC)
  2. **Ban database** — a SQLite DB (`/data/bans.db`) written by the session analyzer
- Returns `ACCEPT` or `DROP`. If the sidecar is unreachable, it **defaults to ACCEPT** (fail-open, so the honeypot keeps collecting data)

**Layer 3 — Silent drop (blackhole backend):**
- If the decision is `DROP`, HAProxy routes to a "blackhole" backend with no actual server
- The connection just hangs for 30 seconds and then times out — no TCP RST, no banner, nothing
- This mimics a dead host, so the attacker doesn't know they've been detected

---

## How are logs saved?

**Multiple layers of logging:**

1. **Cowrie logs** — Each hop writes JSON logs to its Docker volume (`cowrie_hop1_var`, etc.) at `/cowrie/cowrie-git/var/log/cowrie/cowrie.json`. These contain every event: connections, login attempts, commands typed, files downloaded.

2. **Session analyzer logs** — Watches all 3 Cowrie log directories in real-time using `watchdog` (inotify-based file watcher). Aggregates events into sessions and stores analyzed data in **SQLite** at `/data/signatures.db`.

3. **Ban database** — `/data/bans.db` (SQLite) — shared between the session analyzer (writes) and the filter sidecar (reads).

4. **Filter decision log** — `/data/filter.log` — JSON-lines file recording every IP check with timestamp, decision, and reason. Line-buffered for near-real-time visibility.

5. **Blocklist updater log** — `/data/blocklist_updater.log` — output from the daily AbuseIPDB fetch.

All persistent data lives in Docker volumes (`filter_data`, `cowrie_hop*_var`), so it survives container restarts.

---

## How does the session analyzer work?

The session analyzer is the intelligence layer. It:

1. **Watches Cowrie JSON logs** in real-time via inotify across all 3 hops
2. **Aggregates events into sessions** — tracks auth attempts, commands, downloads, duration
3. **Runs pattern matching** against each completed session:
   - **Static rules**: brute-force detection (>20 failed auths), rapid disconnect detection (<5s session with no commands)
   - **Seed signatures**: known Mirai botnet command sequences (loaded from JSON files)
   - **Auto-learned signatures**: sessions are fingerprinted (SHA256 of normalized commands). When the same fingerprint appears from **5+ unique IPs**, it's auto-learned as a new attack pattern and future matches are auto-banned

4. **Escalating bans**: First offense = 1 hour, then 6h → 24h → 7 days → 30 days for repeat offenders

5. **Slack alerts** for:
   - Connection spikes (5x baseline rate in a 10-minute window, with 30-min cooldown)
   - Newly auto-learned attack patterns
   - Daily summary at midnight UTC (total/accepted/dropped counts)

---

## How does the blocklist work?

The `blocklist_updater` container runs a **cron job at 3:00 AM UTC daily**. It:
1. Calls the AbuseIPDB API with a confidence threshold of 90% (configurable)
2. Downloads known malicious IPs
3. Writes them atomically to `/data/blocklist.txt` (write to temp file, then rename — no partial reads)
4. The filter sidecar reloads this file every 5 minutes automatically

If AbuseIPDB is rate-limited or returns 0 results, it keeps the existing blocklist rather than wiping it.

---

## What do they need to provide / configure?

Environment variables (via a `.env` file):

| Variable | Required? | Purpose |
|---|---|---|
| `OPENAI_API_KEY` | Yes | For Cowrie's LLM-enhanced responses |
| `ABUSEIPDB_API_KEY` | Optional | For blocklist updates (works without, just no blocklist) |
| `SLACK_WEBHOOK_URL` | Optional | For alerts (works without, alerts go to stdout) |
| `MAX_CONN_RATE` | No (default: 10) | Connections/minute before rate-limiting |
| `MAX_CONCURRENT` | No (default: 3) | Max simultaneous connections per IP |
| `BRUTE_FORCE_THRESHOLD` | No (default: 20) | Failed auths before ban |
| `LEARN_THRESHOLD` | No (default: 5) | Unique IPs before auto-learning a pattern |

---

## Deployment Steps

1. Clone the repo (and the `project-violet` repo alongside it — Cowrie configs live there)
2. Create a `.env` file with the API keys
3. Run `sudo bash setup_iptables.sh` to isolate the honeypot from their LAN
4. Run `docker compose -f docker-compose.internet-honeypot.yml up -d`
5. Point their external firewall to forward inbound SSH to port 2222 on the host

---

## Key points to emphasize

- **Zero privileged containers** — everything runs with minimal privileges, read-only filesystems, and memory limits
- **Defense in depth** — even if an attacker somehow escapes Cowrie, Docker network isolation + iptables rules prevent LAN access
- **Fail-open design** — if the filter sidecar crashes, traffic still reaches the honeypot (you don't lose data)
- **Self-learning** — the system automatically identifies new attack patterns and starts blocking them without human intervention
- **The bait is realistic** — fake MySQL/Postgres credentials in env vars, a real Postgres decoy database with seeded data, LLM-powered shell responses across 3 "servers"
