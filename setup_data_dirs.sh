#!/bin/bash
# ============================================================================
# Create data directories for honeypot bind mounts.
# Run before first `docker compose up`.
# Sets permissions so non-root container users can write.
# ============================================================================

set -euo pipefail

DATA_DIR="${1:-./data}"

echo "[*] Creating data directories under $DATA_DIR ..."

mkdir -p \
    "$DATA_DIR/filter" \
    "$DATA_DIR/cowrie_hop1/log/cowrie" \
    "$DATA_DIR/cowrie_hop2/log/cowrie" \
    "$DATA_DIR/cowrie_hop3/log/cowrie"

# Cowrie runs as UID 1000 inside the container, session analyzer as 'analyzer'.
# Make everything world-writable so containers can write regardless of UID mapping.
chmod -R 777 "$DATA_DIR"

echo "[+] Done. Directory structure:"
find "$DATA_DIR" -type d | sort | sed 's/^/    /'
echo ""
echo "[+] Point LOG_DIR=$DATA_DIR in your .env (or leave default for ./data)"
