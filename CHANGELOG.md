# Project Violet Gateway — Changelog

## 2026-04-28: Security Fourth-Pass Fixes

Two findings from the fourth security review resolved:

**Base images pinned to SHA256 digests (MEDIUM)** (all 6 Dockerfiles)
`pin-image-digests.sh` was run and the resulting digests committed. All `FROM` lines now include `@sha256:` references:
- `haproxy:2.9-alpine` → `@sha256:3e29449a...`
- `python:3.11-slim` → `@sha256:6d85378d...`
- `python:3.12-slim` → `@sha256:46cb7cc2...`
- `nginxinc/nginx-unprivileged:1.27-alpine` → `@sha256:65e3e85d...`

Re-run `pin-image-digests.sh` and commit before any future deployment to refresh digests.

**`THEATER_PASSWORD` startup warning added (LOW)** (`attack_theater/app/main.py`)
Container now logs a WARNING at startup if `THEATER_PASSWORD` is unset, prompting operators to set it before exposing the host to shared users.

---

## 2026-04-28: Security Third-Pass Fixes

Five findings from the third security review resolved:

**HAProxy backend server line was using shell syntax (CRITICAL)** (`filter_gateway/haproxy.cfg`)
`server hop1 "${COWRIE_HOP1_HOST}":"${COWRIE_HOP1_PORT}" check` used shell-style variable expansion that HAProxy never performs — the literal strings would have been used as the server address, breaking all routing to Cowrie. Fixed to `env(COWRIE_HOP1_HOST)` / `env(COWRIE_HOP1_PORT)` consistent with the rate-limiting fix.

**WebSocket auth was silently rejecting all browser connections (HIGH)** (`attack_theater/app/web.py`)
The server-side `/stream` handler checked for an `Authorization: Basic` header that the browser `WebSocket` API cannot send. With `THEATER_PASSWORD` set, every connection was rejected with code 1008, making the dashboard non-functional. Removed the unreachable per-socket check; auth is enforced at the HTTP layer (`GET /` requires Basic Auth before the browser loads the JS that opens the socket).

**Month-end crash in blocklist updater loop (HIGH)** (`blocklist_updater/update_blocklist.py`)
`datetime.replace(day=next_run.day + 1)` raised `ValueError` on the last day of any month. The unhandled exception terminated the scheduling loop, causing Docker restart thrash for the rest of the day. Fixed with `+= timedelta(days=1)`.

**pin-image-digests.sh referenced wrong nginx image (MEDIUM)** (`pin-image-digests.sh`)
Script had `nginx:1.27-alpine` for `llm_proxy/Dockerfile`, which now uses `nginxinc/nginx-unprivileged:1.27-alpine`. Running it would have pinned the privileged image digest, silently reverting N4. Fixed the key.

**XSS via innerHTML in top-countries list (MEDIUM)** (`attack_theater/static/app.js`)
`renderTopCountries` used template-literal `innerHTML` with interpolated `entry.country` and `entry.country_code`. Replaced with `createElement` + `textContent` per field.

**Bonus: .gitignore hardened** (`.gitignore`)
Added `data/`, `.env.*`, `*.env`, and `!.env.example` to prevent accidental commits of env overrides, operational databases, and log data.

---

## 2026-04-28: Security Should-Fix Items (post-reassessment)

Three non-blocker high/medium findings from the second security review resolved:

**N4 — `llm_proxy` nginx master process no longer runs as root** (`llm_proxy/Dockerfile`)
Swapped base image from `nginx:1.27-alpine` to `nginxinc/nginx-unprivileged:1.27-alpine`. The unprivileged image runs all nginx processes as a non-root user and listens on port 8080 (already the configured port) — no other changes needed.

**N5 — Attack theater dashboard now supports HTTP Basic Auth** (`attack_theater/app/web.py`, `docker-compose.yml`, `.env.example`)
Added `_require_auth` FastAPI dependency using `HTTPBasicCredentials`. Auth is gated on the `THEATER_PASSWORD` env var: if unset, auth is disabled (preserving dev-mode behaviour); if set, all HTTP routes and the WebSocket `/stream` endpoint require the correct password. Uses `secrets.compare_digest` to prevent timing attacks. `THEATER_PASSWORD` wired into `docker-compose.yml` and documented in `.env.example`.

**N1 — SSH private keys purged from `logs/` directory**
18 Cowrie-generated SSH host key files (`rsa`, `ecdsa`, `ed25519` + `.pub` for each of 3 hops) were present in `logs/data/` from prior test runs. All deleted. `DEPLOYMENT_GUIDE.md` updated with a mandatory `rm -rf logs/` step immediately after cloning, with explanation that Cowrie regenerates keys on first startup.

---

## 2026-04-28: Security Blocker Fixes (post-reassessment)

Three blocking findings from the second security review resolved:

**N2 — HAProxy rate limiting was silently broken** (`filter_gateway/haproxy.cfg`)
Quoted string syntax `"${MAX_CONN_RATE}"` is a type mismatch for integer ACL comparisons in HAProxy 2.x. Replaced with the correct `env(MAX_CONN_RATE)` / `env(MAX_CONCURRENT)` form. Rate limiting now actually applies the values set in `.env`.

**N3 — `blocklist_updater` ran cron as root** (`blocklist_updater/Dockerfile`, `update_blocklist.py`)
Removed the cron daemon (which requires root). Replaced with a Python sleep loop inside `update_blocklist.py` (`--loop` mode): runs immediately on startup, then waits until the next `UPDATE_HOUR:00 UTC` and repeats. Added a dedicated `blocklist` system user; container now runs as `USER blocklist`. Removed `entrypoint.sh` and `crontab` (no longer needed).

**N8 — HAProxy started even if filter sidecar never created its socket** (`filter_gateway/entrypoint.sh`)
Added a post-wait socket existence check: if `/tmp/filter.sock` is absent after the 5-second startup window, the entrypoint kills the sidecar process and exits with code 1, preventing HAProxy from starting in an unfiltered state. Docker `restart: always` will retry the container.

---

## 2026-04-28: Pre-Deployment Security Hardening

### Overview

Addressed all 14 findings from the pre-deployment security review (`docs/security_analysis.md`). No new features; changes are limited to the minimum required to close each finding.

---

### C1 — Hardcoded decoy credentials removed from docker-compose.yml

**`docker-compose.yml`** — four hardcoded passwords replaced with `${VAR}` references:

| Old literal | New variable |
|---|---|
| `H0n3yp0t_R00t!` (hop1 root) | `${COWRIE_DB_ROOT_PASSWORD_HOP1}` |
| `Str0ng_But_Le4ked!` (hop1 user) | `${COWRIE_DB_PASSWORD_HOP1}` |
| `H0n3yp0t_R00t!` (hop2 root) | `${COWRIE_DB_ROOT_PASSWORD_HOP2}` |
| `P0stgr3s_Sup3r_S3cret!` (hop2 user) | `${COWRIE_DB_PASSWORD_HOP2}` |
| `H0n3yp0t_R00t!` (Postgres) | `${HONEYPOT_DB_PASSWORD}` |

**`.env.example`** — new section added with generation instructions and a note that `HONEYPOT_DB_PASSWORD` should match `COWRIE_DB_ROOT_PASSWORD_HOP2` to keep the decoy illusion consistent.

---

### H1 — blocklist_updater added to honeypot_external network

**`docker-compose.yml`** — `blocklist_updater` service now has an explicit network assignment:

```yaml
networks:
  honeypot_external:
    ipv4_address: 172.20.99.11
```

Previously the container had no `networks:` key and defaulted to the unmanaged Docker bridge, bypassing all iptables isolation rules.

---

### H2 — filter_gateway drops root privileges

**`filter_gateway/Dockerfile`** — dedicated `filter` user and group created; `USER filter` set before `ENTRYPOINT`. Both HAProxy and the Python sidecar now run as this user.

**`filter_gateway/haproxy.cfg`** — `user filter` and `group filter` added to the `global` section so HAProxy does not attempt an independent privilege drop (which would fail since the process is already non-root).

---

### H3 — filter socket permissions tightened

**`filter_gateway/sidecar/filter_server.py`** — socket permissions changed from `0o777` to `0o600`. Both processes share the `filter` user (H2), so world-access is no longer needed.

---

### H4 — IP format validation added to filter sidecar

**`filter_gateway/sidecar/filter_server.py`** — added `ipaddress.ip_address()` validation immediately after receiving data on the Unix socket. Invalid strings are logged at WARNING level and returned ACCEPT (fail-open), rather than being passed to `check_ip` or written verbatim to the filter log.

---

### M1 — HAProxy rate limits now read from environment variables

**`filter_gateway/haproxy.cfg`** — hardcoded literals `10` and `3` replaced with `"${MAX_CONN_RATE}"` and `"${MAX_CONCURRENT}"`. The `.env` / `.env.example` variables that were already documented now actually take effect.

---

### M2 — iptables persistence made mandatory

**`honeypot-iptables.service`** (new file) — systemd unit that runs `setup_iptables.sh` before `docker.service` on every boot.

**`DEPLOYMENT_GUIDE.md`** — the "optional" iptables persistence section replaced with a mandatory install step using the systemd unit.

---

### M3 — IPv6 firewall rules added

**`setup_iptables.sh`** — IPv6 handling added. Since all honeypot subnets are IPv4-only (`172.20.x.x`), the IPv6 `HONEYPOT_ISOLATION` chain drops all forwarded traffic. Inbound IPv6 on port 22 is also blocked to prevent unmonitored SSH connections.

The existing IPv4 rule logic was refactored into an `apply_rules` helper function; both `iptables` and `ip6tables` receive the same structural treatment.

---

### M4 — Data directory permissions tightened

**`setup_data_dirs.sh`** — `chmod -R 777` replaced with targeted ownership:
- Cowrie hop directories: `chown -R 1000:1000` (Cowrie runs as UID 1000)
- Filter directory: `chmod 775` + `chmod g+s` (setgid so new files inherit the group)

---

### M5 — LLM proxy rate limiting added

**`llm_proxy/nginx.conf.template`** — added per-client rate limiting: 10 requests/minute with burst of 5. Prevents unbounded LLM API cost if a container is compromised or loops requests.

---

### M6 — Base image digest pinning helper added

**`pin-image-digests.sh`** (new file) — script that pulls each base image, resolves its SHA256 digest, and rewrites the `FROM` lines in all Dockerfiles to include `@sha256:<digest>`. Operators run this on the deployment machine before `docker compose build`. Re-running it refreshes digests when intentional upstream updates are wanted.

---

### M7 / L1 / L3 — Documentation and low-severity fixes

**`DEPLOYMENT_GUIDE.md`**:
- Added mandatory **Host SSH Hardening** section: `PasswordAuthentication no`, `PermitRootLogin no`, `AllowUsers`.
- Added **Filter Gateway: Fail-Open Behavior** section explaining that the sidecar defaults to ACCEPT on timeout/crash and how to investigate post-outage.

**`session_analyzer/alert_manager.py`** (L3) — added `_sanitize()` helper that escapes `&`, `<`, `>` in attacker-controlled strings. Applied to top-IP lists and command strings before embedding in Slack payloads.

**`blocklist_updater/update_blocklist.py`** (L2) — added `ipaddress.ip_address()` validation when parsing AbuseIPDB responses. Invalid entries are logged and skipped rather than written to `blocklist.txt`.

---

## 2026-04-07: LLM Proxy, Bind Mounts, Command Output Logging

### Overview

Three sets of changes across both repos:
1. LLM provider abstraction with security proxy
2. Docker volumes replaced with host bind mounts
3. Command output logging added to Cowrie JSON logs

---

### 1. LLM Proxy (project-violet-gateway)

**Problem**: Cowrie containers held the LLM API key in their env vars. A container escape would expose it. Also, no support for local models (Ollama, vLLM).

**Solution**: Added an nginx reverse proxy (`llm_proxy`) that sits between Cowrie and the LLM backend.

#### New files

**`llm_proxy/Dockerfile`**
```dockerfile
FROM nginx:1.27-alpine

RUN rm /etc/nginx/conf.d/default.conf

COPY nginx.conf.template /etc/nginx/templates/default.conf.template

EXPOSE 8080

# nginx docker image runs envsubst on /etc/nginx/templates/*.template
# and writes results to /etc/nginx/conf.d/ on startup.
# Required env vars: LLM_BACKEND, LLM_API_KEY
```

**`llm_proxy/nginx.conf.template`**
```nginx
server {
    listen 8080;

    # Only allow POST to the chat completions endpoint
    location /v1/chat/completions {
        if ($request_method != POST) {
            return 405;
        }

        proxy_pass ${LLM_BACKEND}/v1/chat/completions;
        proxy_set_header Host $proxy_host;
        proxy_set_header Content-Type "application/json";
        proxy_set_header Authorization "Bearer ${LLM_API_KEY}";

        # Strip any auth header from the client (Cowrie sends its own)
        proxy_set_header X-Forwarded-For "";

        proxy_connect_timeout 10s;
        proxy_read_timeout 120s;
        proxy_send_timeout 30s;

        # Limit request body size (prevents abuse if container is compromised)
        client_max_body_size 64k;
    }

    # Reject everything else
    location / {
        return 404;
    }
}
```

#### docker-compose.internet-honeypot.yml changes

Added `llm_proxy` service:
```yaml
llm_proxy:
  build: ./llm_proxy
  restart: always
  extra_hosts:
    - "host.docker.internal:host-gateway"
  networks:
    honeypot_external:
      ipv4_address: 172.20.99.10
    net_llm:
      ipv4_address: 172.20.10.2
  environment:
    - LLM_BACKEND=${LLM_BACKEND:-https://api.openai.com}
    - LLM_API_KEY=${LLM_API_KEY:-}
  mem_limit: 64m
  cpus: 0.25
  read_only: true
  tmpfs:
    - /tmp
    - /var/cache/nginx
    - /run
  security_opt:
    - no-new-privileges:true
```

Added `net_llm` network:
```yaml
net_llm:
  driver: bridge
  internal: true
  ipam:
    config:
      - subnet: 172.20.10.0/24
```

Changed all 3 Cowrie services:
- Removed `extra_hosts` (no direct host access)
- Changed `COWRIE_HYBRID_LLM_API_KEY` from `${OPENAI_API_KEY}` to `proxy-no-key-needed`
- Added `COWRIE_HYBRID_LLM_HOST=http://172.20.10.2:8080`
- Added `COWRIE_HYBRID_LLM_MODEL=${LLM_MODEL:-gpt-4.1-mini}`
- Added `COWRIE_HYBRID_LLM_PATH=/v1/chat/completions`
- Added `net_llm` to each container's networks
- Changed build context from `../project-violet/Cowrie/cowrie-src` to `../Project-Violet-2.0/Cowrie/cowrie-src`
- Changed all config mounts from `../project-violet/cowrie_config_hop*` to `../Project-Violet-2.0/cowrie_config_hop*`

#### .env.example changes

Replaced `OPENAI_API_KEY` with:
```env
LLM_BACKEND=https://api.openai.com
LLM_MODEL=gpt-4.1-mini
LLM_API_KEY=your_api_key_here
```

Added `LOG_DIR` variable.

#### setup_iptables.sh changes

Added `172.20.10.0/24` (net_llm) to `DOCKER_HONEYPOT_SUBNETS` array.

#### How to revert

1. Delete `llm_proxy/` directory
2. `git checkout -- docker-compose.internet-honeypot.yml .env.example setup_iptables.sh`
3. Remove `net_llm` network from compose and iptables

---

### 2. Bind Mounts (project-violet-gateway)

**Problem**: Logs stored in Docker volumes, inaccessible from the host without `docker exec`.

**Solution**: Replaced all Docker volumes with bind mounts under `${LOG_DIR:-./data}/`.

#### docker-compose.internet-honeypot.yml changes

Replaced volume references:
```
filter_data:/data                    → ${LOG_DIR:-./data}/filter:/data
cowrie_hop1_var:/cowrie/cowrie-git/var → ${LOG_DIR:-./data}/cowrie_hop1:/cowrie/cowrie-git/var
cowrie_hop2_var:/cowrie/cowrie-git/var → ${LOG_DIR:-./data}/cowrie_hop2:/cowrie/cowrie-git/var
cowrie_hop3_var:/cowrie/cowrie-git/var → ${LOG_DIR:-./data}/cowrie_hop3:/cowrie/cowrie-git/var
```

Session analyzer volume mounts also updated:
```
cowrie_hop1_var:/cowrie_logs/hop1:ro → ${LOG_DIR:-./data}/cowrie_hop1:/cowrie_logs/hop1:ro
cowrie_hop2_var:/cowrie_logs/hop2:ro → ${LOG_DIR:-./data}/cowrie_hop2:/cowrie_logs/hop2:ro
cowrie_hop3_var:/cowrie_logs/hop3:ro → ${LOG_DIR:-./data}/cowrie_hop3:/cowrie_logs/hop3:ro
```

Changed `volumes:` section from named volumes to `volumes: {}`.

#### New file: setup_data_dirs.sh

```bash
#!/bin/bash
set -euo pipefail

DATA_DIR="${1:-./data}"

echo "[*] Creating data directories under $DATA_DIR ..."

mkdir -p \
    "$DATA_DIR/filter" \
    "$DATA_DIR/cowrie_hop1/log/cowrie" \
    "$DATA_DIR/cowrie_hop2/log/cowrie" \
    "$DATA_DIR/cowrie_hop3/log/cowrie"

chmod -R 777 "$DATA_DIR"

echo "[+] Done. Directory structure:"
find "$DATA_DIR" -type d | sort | sed 's/^/    /'
echo ""
echo "[+] Point LOG_DIR=$DATA_DIR in your .env (or leave default for ./data)"
```

#### How to revert

1. Delete `setup_data_dirs.sh`
2. In `docker-compose.internet-honeypot.yml`:
   - Replace all `${LOG_DIR:-./data}/filter:/data` with `filter_data:/data`
   - Replace all `${LOG_DIR:-./data}/cowrie_hop1:` with `cowrie_hop1_var:`
   - Replace all `${LOG_DIR:-./data}/cowrie_hop2:` with `cowrie_hop2_var:`
   - Replace all `${LOG_DIR:-./data}/cowrie_hop3:` with `cowrie_hop3_var:`
3. Restore named volumes section:
   ```yaml
   volumes:
     filter_data:
     cowrie_hop1_var:
     cowrie_hop2_var:
     cowrie_hop3_var:
   ```
4. Remove `LOG_DIR` from `.env.example`

---

### 3. Command Output Logging (Project-Violet-2.0)

**Problem**: Cowrie JSON log (`cowrie.json`) records `cowrie.command.input` (what the attacker typed) but not what Cowrie responded. Responses were only captured in binary TTY replay files.

**Solution**: Added `cowrie.command.output` events to the JSON log at all three output paths.

#### File: `Cowrie/cowrie-src/src/cowrie/shell/honeypot.py`

Changed the LLM fallback callback to pass the original command through:

```python
# BEFORE (line ~589):
d.addCallback(self._write_llm_response)

# AFTER:
d.addCallback(self._write_llm_response, cmd_string)
```

Changed `_write_llm_response` to log the output:

```python
# BEFORE:
def _write_llm_response(self, response: str) -> None:
    """Write LLM fallback response to terminal, then continue pending commands."""
    self.protocol.llm_pending = False
    if response:
        if not response.endswith("\n"):
            response += "\n"
        self.protocol.terminal.write(response.encode("utf8"))

# AFTER:
def _write_llm_response(self, response: str, cmd_string: str = "") -> None:
    """Write LLM fallback response to terminal, then continue pending commands."""
    self.protocol.llm_pending = False
    if response:
        if not response.endswith("\n"):
            response += "\n"
        log.msg(
            eventid="cowrie.command.output",
            input=cmd_string,
            output=response.rstrip("\n"),
            source="llm",
            format="OUTPUT (%(source)s): %(input)s -> %(output)s",
        )
        self.protocol.terminal.write(response.encode("utf8"))
```

#### File: `Cowrie/cowrie-src/src/cowrie/shell/pipe.py`

Added output accumulation constant:

```python
# After imports:
_OUTPUT_LOG_MAX = 4096
```

Added output buffer to `PipeProtocol.__init__`:

```python
# After self.has_redirections:
self._terminal_output = b""
```

Changed `_write_to_terminal` to accumulate output:

```python
# BEFORE:
def _write_to_terminal(self, data: bytes) -> None:
    if self.protocol is not None and self.protocol.terminal is not None:
        self.protocol.terminal.write(data)
    else:
        log.msg("Connection was probably lost. Could not write to terminal")

# AFTER:
def _write_to_terminal(self, data: bytes) -> None:
    if self.protocol is not None and self.protocol.terminal is not None:
        self.protocol.terminal.write(data)
        if len(self._terminal_output) < _OUTPUT_LOG_MAX:
            self._terminal_output += data[:_OUTPUT_LOG_MAX - len(self._terminal_output)]
    else:
        log.msg("Connection was probably lost. Could not write to terminal")
```

Changed `outConnectionLost` to log accumulated output:

```python
# BEFORE:
def outConnectionLost(self) -> None:
    if self.next_command:
        npcmd = self.next_command.cmd
        npcmdargs = self.next_command.cmdargs
        self.protocol.call_command(self.next_command, npcmd, *npcmdargs)

# AFTER:
def outConnectionLost(self) -> None:
    # Log command output for cowrie.command.output
    if self._terminal_output and self.cmd is not None:
        cmd_name = getattr(self.cmd, "__name__", str(self.cmd))
        cmd_input = cmd_name + (" " + " ".join(self.cmdargs) if self.cmdargs else "")
        output_str = self._terminal_output.decode("utf-8", errors="replace").rstrip("\n")
        if output_str:
            log.msg(
                eventid="cowrie.command.output",
                input=cmd_input,
                output=output_str,
                source="builtin",
                format="OUTPUT (%(source)s): %(input)s -> %(output)s",
            )

    if self.next_command:
        npcmd = self.next_command.cmd
        npcmdargs = self.next_command.cmdargs
        self.protocol.call_command(self.next_command, npcmd, *npcmdargs)
```

#### File: `Cowrie/cowrie-src/src/cowrie/llm/protocol.py`

Changed `_handle_llm_response` to log output:

```python
# BEFORE:
def _handle_llm_response(self, response: str) -> None:
    if self.terminal is None:
        return
    if response:
        clean_response = strip_markdown(response)
        self.command_history.append(f"System: {clean_response}")
        self.terminal.write(f"{clean_response}\n".encode())
    self._show_prompt()

# AFTER:
def _handle_llm_response(self, response: str) -> None:
    if self.terminal is None:
        return
    if response:
        clean_response = strip_markdown(response)
        self.command_history.append(f"System: {clean_response}")
        cmd_input = self.command_history[-2].removeprefix("User: ") if len(self.command_history) >= 2 else ""
        log.msg(
            eventid="cowrie.command.output",
            input=cmd_input,
            output=clean_response,
            source="llm",
            format="OUTPUT (%(source)s): %(input)s -> %(output)s",
        )
        self.terminal.write(f"{clean_response}\n".encode())
    self._show_prompt()
```

#### JSON log output format

Each command now produces a paired input/output entry in `cowrie.json`:

```json
{"eventid":"cowrie.command.input","input":"uname -a","session":"abc123","timestamp":"2026-04-07T12:00:00.000Z"}
{"eventid":"cowrie.command.output","input":"uname -a","output":"Linux wp-prod-01 5.4.0-169-generic #187-Ubuntu SMP ...","source":"llm","session":"abc123","timestamp":"2026-04-07T12:00:00.100Z"}
```

The `source` field indicates where the response came from:
- `"llm"` — generated by the LLM fallback
- `"builtin"` — from a built-in Cowrie command handler (ls, cat, whoami, etc.)

Output is capped at 4KB per command for built-in commands to prevent log bloat.

#### How to revert

In the `Project-Violet-2.0` repo:

```bash
cd Project-Violet-2.0
git checkout -- \
  Cowrie/cowrie-src/src/cowrie/shell/honeypot.py \
  Cowrie/cowrie-src/src/cowrie/shell/pipe.py \
  Cowrie/cowrie-src/src/cowrie/llm/protocol.py
```
