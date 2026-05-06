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
    "$DATA_DIR/cowrie_hop3/log/cowrie" \
    "$DATA_DIR/theater" \
    "$DATA_DIR/analysis/reports"

# Cowrie runs as UID 1000 inside the container.
# The filter sidecar runs as the 'filter' user (UID assigned at image build time).
# Use targeted ownership rather than world-writable permissions.
chown -R 1000:1000 "$DATA_DIR/cowrie_hop1"
chown -R 1000:1000 "$DATA_DIR/cowrie_hop2"
chown -R 1000:1000 "$DATA_DIR/cowrie_hop3"
# attack_theater runs as UID 1000, analysis_agent as UID 1001
chown -R 1000:1000 "$DATA_DIR/theater"
chown -R 1001:1001 "$DATA_DIR/analysis"
# filter_gateway and blocklist_updater share the filter directory.
# 777 is intentionally avoided; both containers write here, so group-write suffices
# if they share GID 1000. If UIDs differ across images, adjust accordingly.
chmod 775 "$DATA_DIR/filter"
chmod g+s "$DATA_DIR/filter"  # new files inherit group

echo "[+] Done. Directory structure:"
find "$DATA_DIR" -type d | sort | sed 's/^/    /'
echo ""
echo "[+] Point LOG_DIR=$DATA_DIR in your .env (or leave default for ./data)"
