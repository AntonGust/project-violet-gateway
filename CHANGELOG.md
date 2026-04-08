# Project Violet Gateway — Changelog

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
