# Project Violet Gateway — Security Analysis

**Scope:** Pre-deployment review for internet exposure at partner sites
**Depth:** Deep — all source files, configuration, networking, and runtime behavior
**Date:** 2026-04-23

---

## CRITICAL

### C1 — Hardcoded credentials committed to git (`docker-compose.yml:117-120, 152-154, 213`)

Three sets of credentials are hardcoded in the compose file rather than pulled from `.env`:

```yaml
# hop1 cowrie
- COWRIE_DB_ROOT_PASSWORD=H0n3yp0t_R00t!
- COWRIE_DB_PASSWORD=Str0ng_But_Le4ked!

# hop2 cowrie
- COWRIE_DB_PASSWORD=P0stgr3s_Sup3r_S3cret!

# honeypot_db_hop2 (actual Postgres container)
  POSTGRES_PASSWORD: H0n3yp0t_R00t!
```

These are in git history. Anyone who clones the repo sees them. Even though they're "decoy" credentials, they create two real risks:

1. Partners deploy clones of this repo and ship the same decoy passwords across all sites — making inter-partner pivoting trivial if an attacker ever correlates deployments.
2. The decoy password `H0n3yp0t_R00t!` in the actual Postgres container **does not match** the `Str0ng_But_Le4ked!` / `P0stgr3s_Sup3r_S3cret!` shown to attackers in the Cowrie env. An attacker who exfiltrates the Cowrie environment and tries the credentials against `172.20.1.22:5432` will get a failed auth, breaking the illusion.

**Fix:** Move all DB passwords to `.env` variables (`COWRIE_DB_PASSWORD_HOP1`, `HONEYPOT_DB_PASSWORD`, etc.). Use `${VAR}` references in the compose. Generate unique decoy passwords per deployment in the partner setup script.

---

## HIGH

### H1 — `blocklist_updater` has no network assignment — bypasses all iptables isolation (`docker-compose.yml:57-73`)

The `blocklist_updater` service has no `networks:` key. Docker Compose assigns it to the auto-created default bridge network (`<project>_default`, typically `172.17.0.0/16`). This network is **not one of the five explicitly managed subnets** in `setup_iptables.sh`.

Consequence: the `HONEYPOT_ISOLATION` iptables chain only acts on traffic from `172.20.x.x` subnets. The blocklist_updater can reach the host machine, the LAN, and any internet destination — entirely unfiltered. If AbuseIPDB serves a malicious response that tricks the container into an SSRF, or if the container is compromised via a dependency vulnerability, there is no network-layer barrier.

**Fix:** Add the container to `honeypot_external` explicitly:

```yaml
blocklist_updater:
  networks:
    honeypot_external:
      ipv4_address: 172.20.99.11
```

### H2 — `filter_gateway` runs as root with no user switch (`filter_gateway/Dockerfile:3`)

```dockerfile
USER root
# ... no subsequent USER directive
```

Both HAProxy and the Python sidecar run as root inside the container. Despite `no-new-privileges:true` and the read-only filesystem, root in a container has significantly more attack surface than a non-root user — particularly if a container escape vulnerability exists in the kernel or Docker runtime.

**Fix:** Add a dedicated user in the Dockerfile and drop privileges before starting both processes. HAProxy supports running as a non-root user via `user haproxy` in the global config section.

### H3 — Unix socket has `0o777` permissions (`filter_gateway/sidecar/filter_server.py:182`)

```python
os.chmod(SOCKET_PATH, 0o777)
```

The filter socket at `/tmp/filter.sock` is world-readable and world-writable. Since `/tmp` is a `tmpfs` shared within the container, any process running in the container can connect to it and inject arbitrary IP strings, or read all filter decisions. This is the single interface through which HAProxy bans or admits connections to the internet.

**Fix:** Run both HAProxy and the sidecar as the same dedicated user and tighten the permissions:

```python
os.chmod(SOCKET_PATH, 0o600)
```

### H4 — No IP format validation before SQLite and log operations (`filter_gateway/sidecar/filter_server.py:156-164`)

```python
ip = data.decode("utf-8").strip()
if not ip:
    return
decision, reason = self.check_ip(ip)
```

The string received on the Unix socket is used as-is with no validation that it is a valid IPv4 or IPv6 address. The SQLite queries are parameterized (so no SQL injection), but the raw string is written verbatim to `filter.log`. A malicious process connecting to the `0o777` socket could inject a crafted string to corrupt the JSON log structure or, in future code changes, introduce an injection surface.

**Fix:**

```python
import ipaddress
try:
    ipaddress.ip_address(ip)
except ValueError:
    log.warning("filter_check: invalid IP format: %r", ip)
    conn.sendall(b"ACCEPT\n")
    return
```

---

## MEDIUM

### M1 — HAProxy rate limits are hardcoded, env vars are silently ignored (`filter_gateway/haproxy.cfg:21-22`)

```haproxy
tcp-request connection reject if { sc0_conn_rate gt 10 }
tcp-request connection reject if { sc0_conn_cur gt 3 }
```

The docker-compose sets `MAX_CONN_RATE` and `MAX_CONCURRENT` environment variables, and the `.env.example` documents them — but HAProxy's config file uses literal `10` and `3`. Changing those variables in `.env` has no effect. Partners who tune these values will be confused when their changes don't work.

**Fix:** Use HAProxy's native env var support in the config:

```haproxy
tcp-request connection reject if { sc0_conn_rate gt ${MAX_CONN_RATE} }
tcp-request connection reject if { sc0_conn_cur gt ${MAX_CONCURRENT} }
```

### M2 — iptables rules don't survive reboot; containers do (`setup_iptables.sh`, `DEPLOYMENT_GUIDE.md:159-169`)

Docker containers with `restart: always` start automatically on boot. The iptables rules do not — they require a manual re-run of `setup_iptables.sh`. There is a window after every reboot where honeypot containers are running with no network isolation: they can reach the LAN, and attackers who manage to pivot during that window have an unblocked path.

The guide documents this and offers `iptables-persistent` as a fix, but it's presented as optional. For internet-deployed partner hardware it is mandatory.

**Fix:** Make persistence mandatory in the deployment checklist. Provide a concrete systemd unit file as the preferred approach:

```ini
# /etc/systemd/system/honeypot-iptables.service
[Unit]
Description=Honeypot iptables isolation
Before=docker.service
After=network.target

[Service]
Type=oneshot
ExecStart=/opt/honeypot/project-violet-gateway/setup_iptables.sh
RemainAfterExit=yes

[Install]
WantedBy=multi-user.target
```

This guarantees the chain is in place before Docker starts any container.

### M3 — No IPv6 firewall rules

`setup_iptables.sh` only configures `iptables` (IPv4). If the host has a public IPv6 address or the Docker daemon has IPv6 enabled, containers may be reachable over IPv6 entirely outside the isolation rules. IPv6 scanner traffic also won't hit the honeypot at all (invisible to port 22).

**Fix:** Mirror the iptables logic in `ip6tables`. Decide intentionally whether to accept IPv6 honeypot traffic; if not, add a blanket `ip6tables -P INPUT DROP` on the host-level for the honeypot interface.

### M4 — Data directories are `chmod 777` on the host (`setup_data_dirs.sh:22`)

```bash
chmod -R 777 "$DATA_DIR"
```

This makes `bans.db`, `signatures.db`, `filter.log`, and all Cowrie session logs readable and writable by any user on the host. At partner sites the host may be shared or only partially administered.

**Fix:** Use targeted ownership instead:

```bash
# Cowrie runs as UID 1000, session analyzer as the 'analyzer' user
chown -R 1000:1000 "$DATA_DIR/cowrie_hop1"
chown -R 1000:1000 "$DATA_DIR/cowrie_hop2"
chown -R 1000:1000 "$DATA_DIR/cowrie_hop3"
# Filter data shared between filter_gateway and session_analyzer
chmod 750 "$DATA_DIR/filter"
```

### M5 — No rate limiting on the LLM proxy (`llm_proxy/nginx.conf.template`)

The nginx LLM proxy limits request body size (`client_max_body_size 64k`) but has no per-client request rate limiting. If the `net_llm` network is ever accessed by more than the three Cowrie containers (or a container is compromised and loops requests), the LLM API key could incur unbounded costs.

**Fix:** Add nginx rate limiting:

```nginx
limit_req_zone $binary_remote_addr zone=llm:1m rate=10r/m;

location /v1/chat/completions {
    limit_req zone=llm burst=5 nodelay;
    ...
}
```

### M6 — Container images not pinned to digests

All Dockerfiles use floating tags:
- `haproxy:2.9-alpine`
- `python:3.11-slim`
- `nginx:1.27-alpine`
- `postgres:16` (in compose)

A tag can be silently updated upstream. For internet-deployed security infrastructure, a supply chain change in a base image is a real risk.

**Fix:** Pin to SHA256 digests in production builds:

```dockerfile
FROM haproxy:2.9-alpine@sha256:<digest>
```

Run `docker pull haproxy:2.9-alpine && docker inspect --format='{{index .RepoDigests 0}}' haproxy:2.9-alpine` to get the current digest, then commit it.

### M7 — No management SSH hardening guidance for partner hosts (`vlan_requirements.txt`)

The VLAN requirements document correctly separates management SSH to a different port, but does not require disabling password authentication on the host. Partners at unfamiliar sites may leave the host SSH daemon with password auth enabled, creating an unrelated but adjacent risk.

**Fix:** Add to the deployment checklist:

```bash
# /etc/ssh/sshd_config on each partner host
PasswordAuthentication no
PermitRootLogin no
AllowUsers honeypot-admin  # or specific user
```

---

## LOW

### L1 — Fail-open behavior undocumented for partners (`filter_gateway/filter_check.lua:6-7`)

```lua
local TIMEOUT_MS = 200
local decision = "ACCEPT"  -- default if sidecar unreachable
```

If the Python sidecar crashes or is slow (>200ms), all connections are admitted to Cowrie with no blocklist or ban check applied. This is a reasonable design choice for a honeypot, but partner operators who see the filter container crash and restart may believe no traffic was admitted during that period when it actually was. It should be documented explicitly.

### L2 — Blocklist file content not validated before use (`blocklist_updater/update_blocklist.py:54`)

```python
ips = [entry["ipAddress"] for entry in data.get("data", [])]
```

AbuseIPDB responses are trusted without validating that `ipAddress` values are valid IP strings. In `filter_server.py`, the blocklist is loaded into a set and checked with `ip in self._ips`. No SQL injection risk (it's a set lookup), but a compromised AbuseIPDB response could inject strings like `"127.0.0.1\n172.20.0.2"` that may affect log parsing downstream.

**Fix:** Add `ipaddress.ip_address()` validation when loading the blocklist.

### L3 — Attacker-controlled data flows into Slack messages (`session_analyzer/alert_manager.py:88`)

```python
top_str = ", ".join(f"`{ip}` ({c})" for ip, c in top_ips)
```

Alert messages include top IPs by connection count. IP addresses are attacker-controlled. Slack's mrkdwn is not HTML, so XSS is not applicable, but a creative attacker could craft a source IP (rare but possible via certain proxy setups) that produces misleading or confusing alert text. Attacker-typed commands also flow into `send_new_pattern_alert` messages, which could include Slack formatting characters.

**Fix:** Sanitize or quote any attacker-sourced strings before embedding them in Slack payloads.

### L4 — `session_analyzer` has read access to all three hop log directories simultaneously

The session analyzer mounts cowrie logs from all three hops with `:ro`. If a sophisticated attacker causes a malformed JSON entry to exploit a hypothetical vulnerability in the log parser, they affect analysis of all hops from one entry point. This is architectural — keep it in mind if the log parsing code is ever extended.

---

## Summary Table

| ID | Area | Severity | Effort to Fix |
|---|---|---|---|
| C1 | Hardcoded decoy credentials in git | Critical | Low |
| H1 | `blocklist_updater` bypasses iptables isolation | High | Low |
| H2 | `filter_gateway` runs as root | High | Medium |
| H3 | Unix socket `0o777` permissions | High | Low |
| H4 | No IP format validation in filter sidecar | High | Low |
| M1 | HAProxy rate limits ignore env vars | Medium | Low |
| M2 | iptables rules lost on reboot | Medium | Low |
| M3 | No IPv6 firewall rules | Medium | Medium |
| M4 | Data dirs `chmod 777` on host | Medium | Low |
| M5 | No LLM proxy rate limiting | Medium | Low |
| M6 | Container images not digest-pinned | Medium | Low |
| M7 | Host SSH not hardened in partner docs | Medium | Low |
| L1 | Fail-open behavior undocumented | Low | Low |
| L2 | Blocklist IPs not validated on load | Low | Low |
| L3 | Attacker data in Slack messages | Low | Low |
| L4 | All hops share one analyzer process | Low | Architectural |

---

## Recommended Fix Order for Pre-Deploy

1. **C1** — rotate hardcoded credentials out of git, parameterize per-partner
2. **M2** — make iptables persistence mandatory (systemd unit) before shipping to partners
3. **H1** — add `blocklist_updater` to `honeypot_external` network
4. **M1** — wire HAProxy config to `MAX_CONN_RATE` / `MAX_CONCURRENT` env vars
5. **H3 + H4** — fix socket permissions and add IP validation (same file, same PR)
6. **M4** — replace `chmod 777` with targeted ownership in `setup_data_dirs.sh`
7. **M3** — add `ip6tables` rules to `setup_iptables.sh`
8. **H2** — drop root in `filter_gateway` Dockerfile
9. **M5** — add nginx rate limiting to LLM proxy
10. **M6** — pin base images to digests before any partner deployment
