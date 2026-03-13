#!/bin/bash
set -e

echo "[entrypoint] Running initial blocklist fetch..."
python /app/update_blocklist.py || echo "[entrypoint] Initial fetch failed, continuing..."

echo "[entrypoint] Starting cron daemon..."
exec cron -f
