# How the Gateway Works

Project Violet Gateway is an internet-exposed honeypot that autonomously collects and analyzes real-world SSH attack traffic. It filters out known-bad actors, proxies the rest into a multi-hop network of Project Violet's custom Cowrie honeypots — the same patched Cowrie with hybrid LLM fallback, database proxy, and profile-driven context that powers the main Project Violet environment. The gateway learns attack patterns over time and alerts operators via Slack, all without manual intervention.

---

## High-Level Request Flow

```
Internet :22
    │
    ▼  (NAT → host:2222 → container:2222)
┌──────────────────────────────┐
│  HAProxy  (TCP, Layer 4)     │
│  • 10 conn/min/IP rate limit │
│  • 3 concurrent conn/IP      │
│  • Calls Lua filter hook      │
└──────────────┬───────────────┘
               │
     ┌─────────▼──────────┐
     │  Python Sidecar     │
     │  (Unix socket)      │
     │  • Blocklist check  │
     │  • Ban DB check     │
     │  → ACCEPT or DROP   │
     └────┬──────────┬─────┘
          │          │
       ACCEPT       DROP
          │          │
          ▼          ▼
    Cowrie Hop 1   Blackhole backend
    (SSH shell +   (30s silent timeout,
     hybrid LLM)    no RST — looks like
          │         a filtered port)
          ▼
    Cowrie Hop 2
    (+ real PostgreSQL via db_proxy)
          │
          ▼
    Cowrie Hop 3
    (deep target, LLM-only)
```

Every accepted session is logged by Cowrie in JSON. The **Session Analyzer** watches those logs in real time, extracts commands and auth attempts, matches against known signatures, and bans offenders with escalating durations.

---

## Container Topology

The stack runs 7 containers across 4 Docker networks:

| Container | Role | Network(s) |
|---|---|---|
| `filter_gateway` | HAProxy + Python sidecar | `honeypot_external`, `net_entry` |
| `session_analyzer` | Log watcher, pattern learner, alerter | `net_entry` |
| `blocklist_updater` | Daily AbuseIPDB IP pull | volume-only |
| `cowrie_hop1` | SSH honeypot (entry), hybrid LLM + MySQL db_proxy | `net_entry`, `net_hop1` |
| `cowrie_hop2` | SSH honeypot (lateral move), hybrid LLM + PostgreSQL db_proxy | `net_hop1`, `net_hop2` |
| `cowrie_hop3` | SSH honeypot (deep target), hybrid LLM only | `net_hop2` |
| `honeypot_db_hop2` | Real PostgreSQL 16 (decoy data) | `net_hop1` |

Only `honeypot_external` (172.20.99.0/24) exposes port 2222 to the host. All other networks are marked `internal: true` — no direct internet access.

All three Cowrie containers are built from the same source: `../project-violet/Cowrie/cowrie-src`. They mount per-hop configs from `../project-violet/cowrie_config_hop{1,2,3}/` — the identical profiles, filesystems, and LLM prompts used in the main Project Violet environment.

---

## The Cowrie Honeypot — Project Violet's Patched Build

This is not stock Cowrie. The gateway uses Project Violet's custom fork with patched `honeypot.py` and `protocol.py`, plus three new modules: `llm_fallback.py`, `prequery.py`, and `db_proxy.py`. Together these turn Cowrie from a honeypot with pre-scripted responses into an intelligent system that can convincingly simulate any Linux server.

### Command Resolution Priority

When an attacker runs a command, Cowrie resolves it in this order:

1. **Built-in Python handlers** (`commands/*.py`) — 60+ handlers for common commands (ls, cat, wget, curl, ssh, sudo, docker, apt, mysql, etc.)
2. **Txtcmd static files** (`txtcmds/`) — Pre-baked outputs generated from the hop's profile (uname, ps, ifconfig, netstat, df, whoami, etc.)
3. **Hybrid LLM fallback** (`llm_fallback.py`) — For anything the first two layers don't cover: queries the LLM with full session context and server profile to generate a realistic response.
4. **"Command not found"** — Only reached if hybrid LLM is disabled.

The critical insight: layers 1 and 2 handle the fast, common cases. The LLM catches everything else — obscure admin tools, chained pipelines, custom scripts — so the attacker never hits a dead end that reveals the honeypot.

### Hybrid LLM Fallback (`llm_fallback.py`)

The `LLMFallbackHandler` is the core of the deception. When a command falls through to layer 3:

1. **Cache check** — A SHA-256 hash of the profile is used to invalidate stale cache entries. If a cached response exists for this command + profile combination, it's returned immediately without an API call.

2. **Context assembly** — The prequery system (see below) analyzes the command and injects relevant server context into the LLM prompt: filesystem listings, config file contents, service states, database schemas, network interfaces.

3. **Session state injection** — The `SessionStateRegister` tracks every command/response pair in the current session (up to 50 entries). Each entry gets an impact score (0-4):
   - 0 = read-only (info gathering)
   - 1 = minor state change (cd, export, alias)
   - 2 = file creation/modification
   - 3 = privilege/permission changes
   - 4 = critical system modification

   Low-impact entries are pruned first when the buffer fills. This history is injected into the LLM prompt so responses stay consistent across the session — if the attacker `cd /var/www` and then runs `ls`, the LLM knows the current directory.

4. **LLM call** — Sent to an OpenAI-compatible API (default model: `gpt-4.1-mini`). The system prompt describes the fake server's identity, OS, role, and installed software. The response is stripped of any markdown formatting before being returned to the attacker's terminal.

5. **Cache write** — The response is cached for future sessions with the same profile.

Additional features:
- **SIGUSR1 hot-reload** — Send SIGUSR1 to the Cowrie process to reload profiles without restarting the container.
- **Credential path detection** — Identifies credential files by name pattern and content keywords, returns realistic fake credentials.
- **Package overlay tracking** — If the attacker "installs" a package during the session, subsequent commands reflect that package as available.

### Prequery Context System (`prequery.py`)

This is the intelligence behind what context the LLM receives. It analyzes the command being run and extracts only the relevant context from the hop's profile, staying within a 3000-character budget.

**Command-to-context mapping** covers 27 command families:

| Category | Commands | Context Injected |
|---|---|---|
| Packages | apt, yum, pip, snap, rpm, dpkg | Installed packages with versions |
| Services | systemctl, service, journalctl | Running services, ports, PIDs |
| Network | netstat, ss, ip, ifconfig, ping, curl, wget | Interface details, routing |
| Database | mysql, psql, redis-cli, mongo | DB services, credentials, schemas |
| Containers | docker, podman, kubectl | Container/pod listings, images |
| User mgmt | useradd, passwd, sudo | Sudo rules, SUID binaries |
| Cloud | aws, gcloud, az | AWS keys, GCP tokens, Azure creds |
| CI/CD | gitlab-runner, gh, jenkins-cli | CI configs, tokens |
| Supply chain | npm, yarn, mvn, gradle | Registry configs, lock files |

It also extracts filesystem paths from command arguments and includes directory trees and file contents for those paths. Context is prioritized: path-specific context first, then command-family context, all within budget.

### Database Proxy (`db_proxy.py`)

When the attacker runs database commands (`mysql -e "SELECT ..."`, `psql -c "..."`, piped SQL), the db_proxy intercepts them and executes real queries against the decoy database containers. This means:

- `mysql -e "SHOW DATABASES"` on hop1 returns real MySQL output from the WordPress decoy
- `psql -c "SELECT * FROM users"` on hop2 queries the real PostgreSQL instance (`honeypot_db_hop2`)
- Schema discovery (`SHOW TABLES`, `\dt`) returns actual table structures with row counts
- Results are formatted as ASCII tables matching the real client output

The proxy supports MySQL and PostgreSQL, uses lazy connection initialization, and has a 5-second query timeout to prevent attacker-crafted slow queries from hanging the honeypot.

Connection details come from environment variables per hop:
- **Hop 1**: MySQL (`wordpress_prod`, user `wp_admin`, password `Str0ng_But_Le4ked!`)
- **Hop 2**: PostgreSQL (host `172.20.1.22`, user `postgres`, password `P0stgr3s_Sup3r_S3cret!`)
- **Hop 3**: No database (empty env vars — deep target, LLM responses only)

### Per-Hop Profiles

Each hop has its own identity, configured via Project Violet's profile system:

| File | Purpose |
|---|---|
| `cowrie.cfg` | Hostname, LLM settings, log paths, SSH config |
| `llm_prompt.txt` | System prompt describing the fake server (OS, role, software) |
| `profile.json` | Full JSON profile: filesystem tree, services, users, credentials, packages |
| `fs.pickle` | Serialized virtual filesystem (what `ls`, `cat`, `find` see) |
| `honeyfs/` | Real file contents on disk (config files, scripts, etc.) |
| `txtcmds/` | Pre-baked static outputs (uname, ps, ifconfig, etc.) |
| `userdb.txt` | SSH credentials (`username:uid:password`) |

These are the same profiles used in Project Violet's internal lab — generated by the Reconfigurator and deployed via `deploy_test_profile.py`.

---

## Filtering — Two Layers

### Layer 1: HAProxy (in-memory, fast)

HAProxy runs in pure TCP mode with a stick-table that tracks connections per source IP. Any IP exceeding 10 connections/minute or 3 concurrent connections is rejected before reaching the filter sidecar.

### Layer 2: Python Sidecar (persistent, learned)

HAProxy's Lua hook (`filter_check.lua`) sends each source IP over a Unix socket to `filter_server.py`. The sidecar checks two things:

1. **Blocklist** — a plain-text file of IPs pulled daily from AbuseIPDB (confidence >= 90%). Reloaded into memory every 5 minutes.
2. **Ban database** — a SQLite table of IPs banned by the session analyzer, with expiry timestamps.

If either check matches, the sidecar responds `DROP`. HAProxy routes the connection to a blackhole backend that holds it open for 30 seconds with no response — indistinguishable from a filtered port to the attacker.

---

## Session Analysis

The session analyzer (`analyzer.py`) uses inotify to watch Cowrie's JSON log files in real time. It aggregates events by session ID:

- `cowrie.session.connect` — new session
- `cowrie.login.failed` / `cowrie.login.success` — auth tracking
- `cowrie.command.input` — command capture
- `cowrie.session.file_download` — malware download URLs
- `cowrie.session.closed` — session complete, trigger analysis

When a session closes, it runs through the pattern matcher.

### Pattern Matching

Four types of rules are evaluated:

| Rule | Trigger | Action |
|---|---|---|
| **Brute force** | >= 20 failed auth attempts | Ban IP |
| **Rapid disconnect** | Successful auth but < 5s session, no commands | Ban IP |
| **Seed signatures** | Commands match known patterns (e.g., Mirai botnet) | Ban IP |
| **Learned signatures** | Commands match auto-learned fingerprint | Ban IP |

#### Fingerprinting and Auto-Learning

Every session's commands are normalized (lowercased, whitespace-collapsed) and sorted. The sorted list is SHA256-hashed to produce a fingerprint. This fingerprint is stored alongside the source IP.

When 5 or more unique IPs produce the same fingerprint, the system automatically promotes it to a **learned signature** with `auto_ban: true`. All future sessions matching that fingerprint are immediately banned. This means the system teaches itself new attack patterns without human rule-writing.

### Ban Escalation

Bans escalate on repeat offenses:

| Level | Duration |
|---|---|
| 0 | 1 hour |
| 1 | 6 hours |
| 2 | 24 hours |
| 3 | 7 days |
| 4 | 30 days |

Each time an IP is re-banned, its level increments (max 4). The `bans.db` SQLite table tracks IP, reason, level, expiry, and hit count.

---

## Blocklist Updates

The `blocklist_updater` container runs a cron job daily at 03:00 UTC. It queries the AbuseIPDB API for IPs with abuse confidence >= 90%, writes them to a temp file, then atomically renames the temp file to `blocklist.txt`. The atomic rename prevents the sidecar from reading a partially-written file.

On first startup, the updater runs an immediate fetch before entering the cron loop.

---

## Alerting

The alert manager sends three types of Slack notifications:

1. **Connection spike** — When the current 10-minute window has > 5x the baseline connection rate. Includes the top 5 source IPs. 30-minute cooldown to avoid spam.

2. **New pattern learned** — When the system auto-learns a new signature (5+ unique IPs). Includes the fingerprint, unique IP count, and representative commands.

3. **Daily summary** (00:00 UTC) — Total connections, accepted/dropped percentages, per-reason breakdown, and number of new signatures learned.

---

## Network Isolation

The system uses three layers of isolation to prevent a compromised honeypot container from reaching the real network:

### VLAN / DMZ (physical)

The honeypot host sits on a dedicated VLAN. Switch-level rules prevent any traffic between the honeypot VLAN and the lab LAN. This is configured by the network admin using the `vlan_requirements.txt` handoff document.

### Docker Networks (software)

All inter-container networks are `internal: true`. Containers can only reach each other through their assigned networks — hop3 cannot talk to hop1, and no honeypot container has a route to the host's LAN interface.

### iptables (host firewall)

`setup_iptables.sh` creates a `HONEYPOT_ISOLATION` chain in the FORWARD table:

- **Allow** inter-honeypot subnet traffic (172.20.x.0/24 <-> 172.20.y.0/24)
- **Allow** outbound HTTPS (443) and DNS (53) for blocklist updates and Slack alerts
- **Drop** all traffic from honeypot subnets to RFC 1918 ranges (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)
- **Drop** all traffic from honeypot subnets to the host IP

---

## Decoy Infrastructure

The honeypot is designed to look realistic to attackers who gain shell access:

- **Hop 1** presents as `wp-prod-01` — a WordPress production server. Environment variables reference a MySQL database (`wordpress_prod`, user `wp_admin`, password `Str0ng_But_Le4ked!`). The db_proxy executes real SQL against the decoy MySQL, so `mysql -e "SHOW TABLES"` returns actual WordPress tables with data.

- **Hop 2** has a real PostgreSQL 16 instance (`honeypot_db_hop2`) on 172.20.1.22:5432 with deliberately weak credentials. The db_proxy connects to it, so attackers running `psql` get real query results. This is the lateral-move reward — finding a "real" database makes the honeypot convincing.

- **Hop 3** is a dead-end: an isolated shell with no database, no lateral paths. The hybrid LLM still responds to all commands, keeping the illusion alive even at the deepest level.

Each hop runs its own LLM prompt and profile, so the server personality, filesystem, and installed software differ per hop — just as they would in a real multi-tier environment.

---

## Deployment

```bash
# Configure
cp .env.example .env
# Edit .env: set ABUSEIPDB_API_KEY, SLACK_WEBHOOK_URL, OPENAI_API_KEY

# Apply host firewall rules
sudo ./setup_iptables.sh

# Start the stack
docker compose -f docker-compose.internet-honeypot.yml up -d
```

The Cowrie containers build from `../project-violet/Cowrie/cowrie-src` and mount configs from `../project-violet/cowrie_config_hop{1,2,3}/`. The project-violet repo must be checked out alongside this one.

The system is fully autonomous after startup. Blocklists update daily, bans escalate automatically, signatures are learned without intervention, LLM responses are cached to reduce API costs, and daily summaries arrive in Slack.

---

## Data Storage

All persistent state lives in Docker volumes mounted to `/data`:

| File | Purpose |
|---|---|
| `blocklist.txt` | AbuseIPDB IPs, updated daily |
| `bans.db` | SQLite — active bans with escalation levels |
| `signatures.db` | SQLite — sessions, learned signatures, daily stats |
| `filter.log` | JSON lines — every connection decision (IP, action, reason) |

Cowrie logs are stored in per-hop volumes under `/cowrie_logs/hop{1,2,3}/`.

LLM response cache (`llm_cache.json`) lives inside each Cowrie container's data directory, keyed by profile hash + command. Cache invalidates automatically when the profile changes.
