# Internet-Exposed Honeypot Module — Requirements Specification

## 1. Project Goal

A standalone, zero-touch Docker module that exposes the multi-hop Cowrie honeynet to the open internet with two-layer network isolation and intelligent traffic filtering. Fully independent from the Project Violet loop (Sangria, Reconfigurator, Purple).

---

## 2. Functional Requirements

### FR-1: Standalone Deployment
- Self-contained Docker Compose stack (Cowrie hop1/hop2/hop3 + filter gateway + logging + alerting)
- No dependencies on any Project Violet component
- Single `docker compose up` to deploy

### FR-2: Network Isolation (Two-Layer)
- **Layer 1 — VLAN/DMZ**: Honeypot containers on a dedicated VLAN, physically separated from lab LAN at switch level. Coordinated with lab network admin. (Timeline: upcoming weeks)
- **Layer 2 — Software (deploy immediately)**: Docker network + host iptables rules. Honeypot containers can ONLY:
  - Accept inbound SSH from the internet (via filter gateway)
  - Communicate with each other (multi-hop)
  - Send logs/alerts outbound (Slack webhook)
  - **Zero access** to any LAN subnet, host services, or Docker socket

### FR-3: Traffic Filter Gateway
A filter gateway sits in front of Cowrie. Per-connection decision: proxy to honeypot or silent drop (no RST, no banner).

| Signal | Source | Action |
|--------|--------|--------|
| Known bad IP | Daily pull from AbuseIPDB (free tier, 1000 checks/day) | Silent drop |
| Rate limit exceeded | Connection metadata (N conns/min/IP) | Silent drop |
| Repeated ban | Escalating duration (1h → 6h → 24h → 7d) | Silent drop |
| Spam pattern match | Session content analysis (known bot signatures, e.g., Mirai command sequences) | Silent drop + ban |
| Auth brute-force | Failed auth count per IP | Silent drop + ban |

- Filter learns over time by analyzing session content + metadata to build local signature database
- Static rule engine (rules don't auto-update, but blocklists refresh daily)

### FR-4: Logging & Alerting
- **Logs**: Every connection decision (accepted / dropped + reason), daily statistics (total connections, dropped %, top blocked IPs, top ban reasons)
- **Alerts via Slack webhook**:
  - Sudden connection spike (>5x baseline in 10min window)
  - New attack pattern not matching existing signatures
- Log rotation handled internally

### FR-5: Session Storage
- Analyzed sessions stored persistently (Docker volume) for signature building
- Survives container restarts

### FR-6: Exposed Service
- SSH only
- Port mapping: host high port (2222) with router NAT (external 22 → host 2222)
- Router NAT configured by lab network admin alongside VLAN setup

---

## 3. Non-Functional Requirements

### NFR-1: Zero-Touch Operation
- Starts, runs, self-maintains without human intervention
- Daily blocklist updates (cron inside container)
- Automatic ban escalation and signature learning
- Internal log rotation

### NFR-2: Security
- Host iptables setup script included in deployment
- No exposed management ports — logs via Docker volumes / local file access only
- Containers run non-root where possible
- Docker socket never mounted into honeypot containers

### NFR-3: Resource Protection
- Per-container connection limits to prevent Cowrie exhaustion
- Max concurrent sessions cap
- Docker resource constraints (memory/CPU limits)

### NFR-4: Portability
- Any Linux host with Docker and iptables
- VLAN setup documented as manual prerequisite

---

## 4. User Stories

- **As a researcher**, I deploy with one command and the honeypot collects real attacker sessions within minutes.
- **As a network admin**, I receive clear VLAN requirements documentation to isolate the honeypot segment.
- **As an operator**, I never touch the system — spam is filtered, bans escalate, and I check logs/Slack when I want.
- **As a researcher**, I see only "interesting" sessions because brute-force bots and known scanners are silently dropped.

---

## 5. Architecture Overview

```
Internet → Router (NAT: port 22 → host:2222) → [VLAN/DMZ]
    → Filter Gateway container (silent drop / proxy)
        → Cowrie Hop1 → Hop2 → Hop3
    → Session Store (Docker volume, signature DB)
    → Slack Alerts (webhook, outbound only)
    → Blocklist Updater (daily AbuseIPDB pull)
```

All in one `docker-compose.yml` + host iptables setup script.

---

## 6. Phased Deployment

1. **Phase 1 (immediate)**: Software isolation (Layer 2) + filter gateway + multi-hop Cowrie
2. **Phase 2 (when VLAN ready)**: Add Layer 1 hardware isolation, router NAT config

---

## 7. Next Steps

- `/sc:design` — detailed architecture (filter gateway internals, container topology, iptables rules)
- `/sc:workflow` — implementation plan broken into tasks
