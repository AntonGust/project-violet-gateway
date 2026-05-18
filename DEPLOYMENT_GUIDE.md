# Project Violet Gateway — Deployment Guide

## Prerequisites

- **Docker Engine** + **Docker Compose v2** (`docker compose` subcommand)
- **Git** to clone the repos
- **Root access** for the iptables firewall script
- An LLM inference server (cloud API, or local model via vLLM/Ollama/LM Studio)

---

## Step 0: Directory Layout

The compose file expects two sibling repos:

```
/opt/honeypot/                              # or wherever you want
├── Project-Violet-2.0/                     # Cowrie source + per-hop configs
│   ├── Cowrie/cowrie-src/                   # Cowrie Dockerfile + source code
│   ├── cowrie_config_hop1/etc/             # cowrie.cfg, llm_prompt.txt, profile.json, userdb.txt
│   ├── cowrie_config_hop1/honeyfs/         # fake filesystem contents
│   ├── cowrie_config_hop1/share/           # txtcmds, fs.pickle
│   ├── cowrie_config_hop2/...              # same structure
│   ├── cowrie_config_hop2/db_init/         # SQL init scripts for decoy Postgres
│   └── cowrie_config_hop3/...              # same structure
└── project-violet-gateway/                 # this repo
    ├── filter_gateway/
    ├── session_analyzer/
    ├── blocklist_updater/
    ├── llm_proxy/
    ├── docker-compose.yml
    ├── setup_iptables.sh
    └── .env
```

Clone both repos side by side:

```bash
cd /opt/honeypot
git clone <project-violet-repo-url> Project-Violet-2.0
git clone <gateway-repo-url> project-violet-gateway
```

The names matter — the compose file references `../Project-Violet-2.0/` for Cowrie's build context and config mounts.

**After cloning, purge any runtime data that may have been left in the repo:**

```bash
rm -rf /opt/honeypot/project-violet-gateway/logs/
```

The `logs/` directory is in `.gitignore` and is never committed, but a developer copy of the repo may contain Cowrie-generated SSH host keys and attacker log data from prior test runs. These must not be present on a partner deployment — Cowrie generates fresh host keys on first startup.

---

## Step 1: Create the `.env` File

```bash
cd /opt/honeypot/project-violet-gateway
cp .env.example .env
nano .env
```

### LLM Provider Configuration

The `llm_proxy` container acts as a reverse proxy between Cowrie and your LLM backend. It holds the API key so that Cowrie containers never see it. You configure four variables:

| Variable | Purpose |
|---|---|
| `LLM_BACKEND` | URL of the actual LLM server the proxy forwards to |
| `HP_MODEL` | Model used by the Cowrie honeypot instances |
| `AGENT_MODEL` | Model used by the analysis agent (monitoring profile only) |
| `LLM_API_KEY` | API key injected by the proxy (leave empty for local models) |

#### Cloud API Examples

**aiqu.ai (default):**
```env
LLM_BACKEND=https://llm.aiqu.ai
HP_MODEL=gpt-oss-120b
AGENT_MODEL=nemotron-3-super
LLM_API_KEY=your_aiqu_api_key
```

**OpenAI:**
```env
LLM_BACKEND=https://api.openai.com
HP_MODEL=gpt-4.1-mini
AGENT_MODEL=gpt-4.1-mini
LLM_API_KEY=sk-proj-...
```

**Together AI:**
```env
LLM_BACKEND=https://api.together.xyz
HP_MODEL=meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8
AGENT_MODEL=meta-llama/Llama-4-Maverick-17B-128E-Instruct-FP8
LLM_API_KEY=your_together_api_key
```

#### Local Model Examples

For models running on the **same machine** as Docker (reached via `host.docker.internal`):

**Ollama:**
```env
LLM_BACKEND=http://host.docker.internal:11434
HP_MODEL=qwen2.5:32b
LLM_API_KEY=
```

**vLLM:**
```env
LLM_BACKEND=http://host.docker.internal:8000
HP_MODEL=Qwen/Qwen2.5-32B-Instruct
LLM_API_KEY=
```

For models running on a **different machine** on the network (e.g., a GPU server at `10.0.1.100`):

```env
LLM_BACKEND=http://10.0.1.100:8000
HP_MODEL=nvidia/Nemotron-Ultra-120B-HF
LLM_API_KEY=
```

This works because the `llm_proxy` container sits on `honeypot_external` (the only network with outbound access). The Cowrie containers cannot reach the LLM server directly — they only talk to the proxy on the internal `net_llm` network.

#### Tested Large Models

| Model | Backend | `HP_MODEL` value |
|---|---|---|
| GPT-OSS-120B | vLLM / Ollama | `openai/GPT-OSS-120B` or `gpt-oss:120b` |
| Nemotron 120B | vLLM / Ollama | `nvidia/Nemotron-Ultra-120B-HF` or `nemotron:120b` |
| Kimi K2 | vLLM (0.8.x+) | `moonshotai/Kimi-K2-Instruct` |

All three work out of the box. The gateway sends standard OpenAI-format requests (`messages`, `model`, `max_tokens`, `temperature`) and reads `choices[0].message.content` from the response. Any model served behind an OpenAI-compatible `/v1/chat/completions` endpoint will work.

#### Other `.env` Variables (Optional)

| Variable | Default | Purpose |
|---|---|---|
| `ABUSEIPDB_API_KEY` | — | For daily blocklist updates (works without, just no blocklist) |
| `SLACK_WEBHOOK_URL` | — | For alerts (works without, alerts go to stdout) |
| `MAX_CONN_RATE` | 10 | Max new connections per IP per minute |
| `MAX_CONCURRENT` | 3 | Max concurrent sessions per IP |
| `BRUTE_FORCE_THRESHOLD` | 20 | Failed auth attempts before banning |
| `LEARN_THRESHOLD` | 5 | Unique IPs before auto-learning a pattern |
| `CONFIDENCE_MINIMUM` | 90 | AbuseIPDB confidence threshold |
| `ANALYSIS_POLL_INTERVAL_SEC` | 300 | How often the analysis agent checks for new sessions |
| `MMDB_PATH` | — | Host path to `GeoLite2-City.mmdb` for IP geolocation (monitoring profile) |

---

## Step 2: Run the Firewall Isolation Script

This **must** run before the containers start. It prevents honeypot containers from reaching the lab's internal network.

```bash
sudo bash setup_iptables.sh
```

Expected output:
```
[*] Setting up honeypot isolation firewall rules...
[+] Allowing inter-honeypot communication...
[+] Allowing outbound HTTPS and DNS...
[+] Blocking honeypot → LAN traffic...
[+] Blocking honeypot → host (10.0.1.50)...
[+] Honeypot isolation rules applied.
[+] Protected LAN subnets: 10.0.0.0/8 192.168.0.0/16 172.16.0.0/12
[+] Honeypot subnets:      172.20.0.0/24 172.20.1.0/24 172.20.2.0/24 172.20.10.0/24 172.20.99.0/24
[+] Inbound port:          2222
```

The script is **idempotent** — safe to re-run. It flushes and recreates its own chain each time.

### Persisting Rules Across Reboots (MANDATORY)

**These iptables rules do not survive a reboot.** Docker containers with `restart: always` start automatically on boot. Without persistence, there is a window after every reboot where honeypot containers are running with no network isolation.

**Required:** install the provided systemd unit before going live:

```bash
sudo cp /opt/honeypot/project-violet-gateway/honeypot-iptables.service \
        /etc/systemd/system/honeypot-iptables.service
sudo systemctl daemon-reload
sudo systemctl enable --now honeypot-iptables
```

This guarantees the isolation chain is in place before Docker starts any container on boot.

---

## Step 3: Create Data Directories

All logs and databases are written to the host filesystem as bind mounts. Create the directories before first run:

```bash
bash setup_data_dirs.sh
```

Or specify a custom location:

```bash
bash setup_data_dirs.sh /opt/honeypot/data
```

If using a custom location, set `LOG_DIR` in `.env`:

```env
LOG_DIR=/opt/honeypot/data
```

The default is `./data` (relative to the compose file).

---

## Deployment Modes

The gateway supports two deployment modes controlled by Docker Compose profiles.

### Honeypot Only (default — recommended for remote/partner sites)

Runs the core honeypot stack: filter gateway, Cowrie hops, LLM proxy, session analyzer, and blocklist updater. The attack theater dashboard and analysis agent are **not** started.

```bash
docker compose up -d --build
```

This is the right choice for remote deployments where you only want to collect data. Logs are written to `data/` and can be synced or shipped to a central collector.

### Full Stack with Monitoring (local / central site)

Also starts the **attack theater** (live session dashboard) and **analysis agent** (LLM-powered session classifier and report generator).

```bash
docker compose --profile monitoring up -d --build
```

The attack theater has no published host port — it sits on the internal `net_entry` network at `172.20.0.6:8080`. From the Docker host, open it directly:

```bash
xdg-open http://172.20.0.6:8080/
```

Login with any username and the `THEATER_PASSWORD` value from `.env`. From a remote machine, reach it via SSH local-forward instead (never expose port 8080 to the internet):

```bash
ssh -L 8080:172.20.0.6:8080 <user>@<gateway-host>   # then open http://localhost:8080/
```

> **GeoIP (optional):** Download `GeoLite2-City.mmdb` from [MaxMind](https://dev.maxmind.com/geoip/geolite2-free-geolocation-data) (free account required) and place it in `./data/theater/` (or `$LOG_DIR/theater/`). No extra config needed — the theater picks it up automatically on startup. Without it the theater works fine but IP locations will show as unknown.

---

## Step 4: Build and Start Everything

```bash
cd /opt/honeypot/project-violet-gateway
docker compose up -d --build
```

`docker compose` picks up `docker-compose.yml` automatically, so no `-f` flag is needed. For the full stack with the live dashboard, add the monitoring profile (see [Deployment Modes](#deployment-modes)):

```bash
docker compose --profile monitoring up -d --build
```

`--build` forces a fresh image build. On first run it will:

1. Build the `filter_gateway` image (HAProxy + Python sidecar)
2. Build the `session_analyzer` image
3. Build the `blocklist_updater` image
4. Build the `llm_proxy` image (nginx reverse proxy)
5. Build the `cowrie` image (same image for all 3 hops)
6. Pull `postgres:16` for the decoy database
7. Create 5 Docker networks
8. Start all 8 containers

This takes a few minutes the first time (Cowrie's build is the heaviest).

---

## Step 5: Verify It's Running

```bash
# Check all containers are up
docker compose ps
```

Expected output — 8 containers, all "Up":
```
NAME               STATUS
filter_gateway     Up
llm_proxy          Up
session_analyzer   Up
blocklist_updater  Up
cowrie_hop1        Up
cowrie_hop2        Up
cowrie_hop3        Up
honeypot_db_hop2   Up
```

### Test SSH Access

```bash
ssh -p 2222 localhost
```

You should see a fake SSH banner and login prompt. Try `root` with any password — Cowrie will let you in (on purpose). Type some commands and watch them get logged.

### Watch Logs

All logs are on the host filesystem under `LOG_DIR` (default `./data`):

```bash
# Cowrie hop 1 — live attacker sessions
tail -f ./data/cowrie_hop1/log/cowrie/cowrie.json

# Filter decisions — every connection accept/drop
tail -f ./data/filter/filter.log

# Session analyzer container logs
docker compose logs -f session_analyzer

# LLM proxy logs (check if requests are forwarding)
docker compose logs llm_proxy
```

---

## Step 6: Expose to the Internet

The honeypot listens on **port 2222** on the host. Only this one port is exposed — everything else is internal Docker networking.

To make it look like a real SSH server to attackers, configure the lab's external firewall/router with a NAT rule:

```
External port 22  →  <host-IP>:2222
```

Attackers scanning port 22 will hit the honeypot.

---

## Common Operations

```bash
# Stop everything (data is preserved on disk)
docker compose down

# Stop full stack including monitoring profile
docker compose --profile monitoring down

# Stop and DELETE all data (fresh start)
docker compose down
rm -rf ./data   # or your LOG_DIR path

# Rebuild just one container after a code change
docker compose up -d --build session_analyzer

# Remove iptables rules (full teardown)
sudo iptables -D FORWARD -j HONEYPOT_ISOLATION
sudo iptables -F HONEYPOT_ISOLATION
sudo iptables -X HONEYPOT_ISOLATION
```

---

## Logs and Data Reference

All data is written to the host filesystem under `LOG_DIR` (default: `./data`).

### Directory Structure

```
./data/
├── filter/                              # shared by filter_gateway, session_analyzer, blocklist_updater
│   ├── filter.log                       # JSON-lines: every IP check (timestamp, decision, reason)
│   ├── bans.db                          # SQLite: banned IPs, escalation level, expiry
│   ├── signatures.db                    # SQLite: session fingerprints, auto-learned patterns, stats
│   ├── blocklist.txt                    # AbuseIPDB IPs, one per line
│   └── blocklist_updater.log            # cron job output
├── cowrie_hop1/
│   ├── log/cowrie/cowrie.json            # Cowrie events: connections, logins, commands, downloads
│   ├── llm_tokens.jsonl                 # per-request prompt/completion token counts
│   └── llm_cache.json                   # cached LLM responses
├── cowrie_hop2/
│   └── ...                              # same structure
└── cowrie_hop3/
    └── ...                              # same structure
```

### What's in Each File

| File | Format | Contents |
|---|---|---|
| `filter/filter.log` | JSON-lines | Every connection: `{ts, ip, decision, reason}`. Line-buffered, near-real-time. |
| `filter/bans.db` | SQLite | Banned IPs with escalation level (0-4), expiry time, hit count. Shared between session analyzer (writes) and filter sidecar (reads). |
| `filter/signatures.db` | SQLite | Session fingerprints, auto-learned attack patterns, daily stats. |
| `filter/blocklist.txt` | Plain text | One IP per line, refreshed daily at 3 AM UTC from AbuseIPDB. |
| `cowrie_hop*/log/cowrie/cowrie.json` | JSON-lines | Every Cowrie event: `cowrie.session.connect`, `cowrie.login.failed`, `cowrie.command.input`, `cowrie.session.file_download`, etc. |
| `cowrie_hop*/llm_tokens.jsonl` | JSON-lines | Per-request token usage: `{prompt_tokens, completion_tokens, timestamp}`. Use for cost tracking. |
| `cowrie_hop*/llm_cache.json` | JSON | Cached LLM responses keyed by normalized command. Auto-invalidates when the hop profile changes. |

### Reading Logs from the Host

```bash
# Live tail Cowrie events (all hops)
tail -f ./data/cowrie_hop{1,2,3}/log/cowrie/cowrie.json

# Live tail filter decisions
tail -f ./data/filter/filter.log

# Pretty-print the last 5 filter decisions
tail -5 ./data/filter/filter.log | python -m json.tool

# Count banned IPs
sqlite3 ./data/filter/bans.db "SELECT COUNT(*) FROM bans"

# List top 10 banned IPs by hit count
sqlite3 -column -header ./data/filter/bans.db \
  "SELECT ip, reason, level, hit_count, ban_until FROM bans ORDER BY hit_count DESC LIMIT 10"

# List auto-learned attack signatures
sqlite3 -column -header ./data/filter/signatures.db \
  "SELECT label, hit_count, unique_ips, commands FROM signatures ORDER BY hit_count DESC LIMIT 10"

# Check blocklist size
wc -l ./data/filter/blocklist.txt

# Sum LLM tokens used today (hop 1)
python -c "
import json
total = 0
for line in open('./data/cowrie_hop1/llm_tokens.jsonl'):
    total += json.loads(line).get('completion_tokens', 0)
print(f'Total completion tokens: {total:,}')
"
```

### SIEM / Log Collector Integration

Since everything is regular files on disk, you can point any log collector at the data directory:

- **Filebeat**: Watch `./data/filter/filter.log` and `./data/cowrie_hop*/log/cowrie/cowrie.json`
- **Fluentd/Fluent Bit**: Tail the JSON-lines files
- **rsync**: Periodically sync `./data/` to a remote archive
- **Splunk Universal Forwarder**: Monitor the data directory

All log files are JSON-lines (one JSON object per line), so they parse without custom regex.

---

## Ollama-Specific Notes

If using Ollama on the host, make sure the model is pulled before starting the honeypot:

```bash
ollama pull qwen2.5:32b
```

Ollama binds to `localhost` by default. The `llm_proxy` container reaches it via `host.docker.internal`, which Docker maps to the host's IP. If Ollama is configured to only listen on `127.0.0.1`, it won't accept connections from Docker. Fix:

```bash
# Set Ollama to listen on all interfaces
OLLAMA_HOST=0.0.0.0 ollama serve

# Or in the systemd unit file:
# Environment="OLLAMA_HOST=0.0.0.0"
```

---

## Security Architecture

### Network Isolation

| Network | Subnet | External? | Connected Services |
|---|---|---|---|
| `honeypot_external` | 172.20.99.0/24 | Yes | filter_gateway, llm_proxy |
| `net_entry` | 172.20.0.0/24 | Internal | filter_gateway, cowrie_hop1, session_analyzer |
| `net_hop1` | 172.20.1.0/24 | Internal | cowrie_hop1, cowrie_hop2, honeypot_db |
| `net_hop2` | 172.20.2.0/24 | Internal | cowrie_hop2, cowrie_hop3 |
| `net_llm` | 172.20.10.0/24 | Internal | llm_proxy, cowrie_hop1/2/3 |

### Host SSH Hardening (MANDATORY for partner sites)

Before the deployment goes live, disable password authentication on the host:

```bash
# /etc/ssh/sshd_config
PasswordAuthentication no
PermitRootLogin no
AllowUsers honeypot-admin   # replace with your actual admin username
```

```bash
sudo systemctl reload sshd
```

Verify you can still log in with your key before closing the session.

### Filter Gateway: Fail-Open Behavior

If the Python filter sidecar crashes or takes longer than 200 ms to respond, HAProxy defaults to **ACCEPT**. This is intentional — it keeps the honeypot reachable even during sidecar restarts. Consequence: during a sidecar outage, blocklisted and banned IPs are admitted to Cowrie unfiltered.

If you see the filter container restart in `docker compose ps`, check `docker compose logs filter_gateway` to determine how long it was down and whether any blocked IPs connected during that window.

### Container Hardening

Every container has:
- `no-new-privileges:true` — prevents privilege escalation
- Memory and CPU limits
- `filter_gateway` runs as the dedicated `filter` non-root user
- The session analyzer runs as a non-root user

Only `filter_gateway` runs with `read_only: true` (read-only root filesystem, with `/tmp` writable via `tmpfs`). The remaining services (`session_analyzer`, `blocklist_updater`, `llm_proxy`, `attack_theater`, `analysis_agent`) run with a writable root filesystem and `tmpfs` scratch mounts; the Cowrie hops and the two decoy databases use the default writable root.

### API Key Isolation

The `llm_proxy` (nginx) is the only container that holds the LLM API key. It:
- Sits on `honeypot_external` (outbound access) + `net_llm` (internal)
- Only proxies `POST /v1/chat/completions` — returns 404 for everything else
- Limits request body to 64KB
- Injects the `Authorization: Bearer` header on behalf of Cowrie

Cowrie containers have `COWRIE_HYBRID_LLM_API_KEY=proxy-no-key-needed` (a dummy value). If an attacker escapes Cowrie's sandbox into the container, they cannot:
- Read the real API key (it's in a different container)
- Reach the LLM backend directly (no route from internal networks)
- Reach the host machine (no `extra_hosts`, iptables blocks it)
- Use the proxy for anything other than chat completions (nginx returns 404)

### Host Firewall (iptables)

The `setup_iptables.sh` script creates a `HONEYPOT_ISOLATION` chain that:
1. Allows honeypot containers to talk to each other
2. Allows outbound HTTPS (443) + DNS (53) for Slack alerts and AbuseIPDB
3. Blocks all honeypot → LAN traffic (10.0.0.0/8, 192.168.0.0/16, 172.16.0.0/12)
4. Blocks all honeypot → host machine traffic
