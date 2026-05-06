# Latest Gateway Review

Date: 2026-04-27

Scope: `/home/anton/Documents/Programming/robertbridges/project-violet-gateway` only.

## Findings

### High: Live playback likely never starts for real Cowrie sessions

`Director` switches to live mode on `session_login_success` and waits 2 seconds for `tty_file_path`, but `LogWatcher` only records the TTY path on `cowrie.log.closed`, which happens at or near session end. Real live sessions will usually fall back to archive instead of being shown live.

References:

- `attack_theater/app/director.py:82`
- `attack_theater/app/director.py:192`
- `attack_theater/app/log_watcher.py:148`

### Medium: WebSocket stream disconnects every 30 seconds

`/stream` waits on `websocket.receive_text()` with a 30 second timeout, but the browser client only receives server pushes and never sends frames back. This causes periodic reconnects and can drop or replay UI state.

References:

- `attack_theater/app/web.py:65`
- `attack_theater/static/app.js:237`

### Medium: Runtime log artifacts are still visible to Git

Runtime logs under `logs/` are untracked but not fully ignored. `*.db` and `*.log` are ignored, but files such as `logs/data/cowrie_hop1/llm_cache.json` and `logs/data/cowrie_hop1/llm_tokens.jsonl` remain visible to Git and may contain prompts, outputs, token metadata, or operational data.

Recommendation: add `logs/` or `data/` to `.gitignore`.

Reference:

- `.gitignore:1`

### Low: TTY reader tests reference missing fixtures

`attack_theater/tests/test_tty_reader.py` references `sample.tty`, `truncated.tty`, and `dead_air.tty`, but the fixture directory only contains `cowrie.json`. Once dependencies are installed, these tests will fail.

Reference:

- `attack_theater/tests/test_tty_reader.py:23`

## Verification

- `docker compose config` succeeds, with warnings for unset `SLACK_WEBHOOK_URL` and `ABUSEIPDB_API_KEY`.
- `git diff --check` fails due trailing whitespace in the edited compose/firewall lines.
- `pytest attack_theater/tests` could not collect because the current environment lacks `aiosqlite` and `fastapi`.

## Latest Pass: Analysis Agent and Compose Wiring

Date: 2026-04-27

Scope: latest local changes in `project-violet-gateway`, including the new `attack_theater` and `analysis_agent` compose services.

### High: Analysis failures are marked as completed

`analysis_agent` permanently marks a session as analyzed even when earlier nodes fail or report writing fails. If classify/enrich/summarize errors, or if the report cannot be written, `output_node` still records the session in `analyzed_sessions`. A transient LLM, proxy, or filesystem problem can therefore skip a session forever without a successful report.

References:

- `analysis_agent/agent/nodes/output.py:24`
- `analysis_agent/agent/nodes/output.py:34`

### High: Analysis pipeline does not receive command text

The analysis prompts and report renderer expect `state.commands`, but `attack_theater` only stores `command_count`. `Catalog.append_command()` increments a counter and discards the command string, while `analysis_agent` only selects session metadata from `sessions`. This leaves command lists empty for classification, enrichment, summaries, and reports.

References:

- `attack_theater/app/catalog.py:97`
- `analysis_agent/agent/nodes/ingest.py:38`
- `analysis_agent/agent/templates/classify.jinja2:1`

### Medium: Default GeoLite mount can crash `attack_theater`

Compose bind-mounts `${MMDB_PATH:-./data/GeoLite2-City.mmdb}` to `/data/GeoLite2-City.mmdb:ro`. If the host file does not exist, Docker may create a directory at that path. `attack_theater/app/main.py` only checks `MMDB_PATH.exists()` before calling `geo.init()`, so a directory or invalid file can raise during startup.

References:

- `docker-compose.yml:239`
- `attack_theater/app/main.py:30`

### Medium: Runtime artifacts remain visible to Git

`.venv` and pytest caches are ignored, but runtime files such as `logs/data/cowrie_hop1/llm_cache.json` and `logs/data/cowrie_hop1/llm_tokens.jsonl` are still visible as untracked files. These may contain prompts, outputs, token metadata, or operational data.

Recommendation: add `logs/` or the runtime data root to `.gitignore`.

Reference:

- `.gitignore:1`

### Verification

- `docker compose config` succeeds, with warnings for unset `ABUSEIPDB_API_KEY` and `SLACK_WEBHOOK_URL`.
- `git diff --check` fails due trailing whitespace in `docker-compose.yml` and `setup_iptables.sh`.
- Focused `attack_theater` and `analysis_agent` pytest runs did not complete in this sandbox; both hung around async SQLite tests, so they were not usable as pass/fail evidence.
