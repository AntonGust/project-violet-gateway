#!/bin/bash
# ============================================================================
# Internet Honeypot — Host Firewall Setup
# Isolates honeypot Docker containers from the lab LAN.
# Run as root. Idempotent (safe to re-run).
# ============================================================================

set -euo pipefail

# === CONFIGURATION ===
HONEYPOT_PORT=2222

DOCKER_HONEYPOT_SUBNETS=(
    "172.20.0.0/24"   # net_entry
    "172.20.1.0/24"   # net_hop1
    "172.20.2.0/24"   # net_hop2
    "172.20.99.0/24"  # honeypot_external
)

# Lab network ranges to PROTECT from honeypot traffic
LAN_SUBNETS=(
    "10.0.0.0/8"
    "192.168.0.0/16"
    "172.16.0.0/12"   # Covers all private 172.x except our honeypot 172.20.x
)

CHAIN_NAME="HONEYPOT_ISOLATION"

# === Check root ===
if [[ $EUID -ne 0 ]]; then
    echo "[-] This script must be run as root"
    exit 1
fi

echo "[*] Setting up honeypot isolation firewall rules..."

# === Create or flush the custom chain ===
if iptables -L "$CHAIN_NAME" -n &>/dev/null; then
    echo "[*] Flushing existing $CHAIN_NAME chain..."
    iptables -F "$CHAIN_NAME"
else
    echo "[*] Creating $CHAIN_NAME chain..."
    iptables -N "$CHAIN_NAME"
fi

# Remove old references from FORWARD chain (idempotent)
while iptables -D FORWARD -j "$CHAIN_NAME" 2>/dev/null; do :; done

# === Rule 1: Allow honeypot containers to talk to each other ===
echo "[+] Allowing inter-honeypot communication..."
for subnet in "${DOCKER_HONEYPOT_SUBNETS[@]}"; do
    for dest in "${DOCKER_HONEYPOT_SUBNETS[@]}"; do
        iptables -A "$CHAIN_NAME" -s "$subnet" -d "$dest" -j ACCEPT
    done
done

# === Rule 2: Allow outbound HTTPS + DNS (for Slack webhooks, AbuseIPDB) ===
echo "[+] Allowing outbound HTTPS and DNS..."
for subnet in "${DOCKER_HONEYPOT_SUBNETS[@]}"; do
    iptables -A "$CHAIN_NAME" -s "$subnet" -p tcp --dport 443 -j ACCEPT
    iptables -A "$CHAIN_NAME" -s "$subnet" -p tcp --dport 53 -j ACCEPT
    iptables -A "$CHAIN_NAME" -s "$subnet" -p udp --dport 53 -j ACCEPT
done

# === Rule 3: BLOCK all honeypot → LAN traffic ===
echo "[+] Blocking honeypot → LAN traffic..."
for subnet in "${DOCKER_HONEYPOT_SUBNETS[@]}"; do
    for lan in "${LAN_SUBNETS[@]}"; do
        iptables -A "$CHAIN_NAME" -s "$subnet" -d "$lan" -j DROP
    done
done

# === Rule 4: BLOCK honeypot → host machine ===
HOST_IP=$(hostname -I | awk '{print $1}')
if [[ -n "$HOST_IP" ]]; then
    echo "[+] Blocking honeypot → host ($HOST_IP)..."
    for subnet in "${DOCKER_HONEYPOT_SUBNETS[@]}"; do
        iptables -A "$CHAIN_NAME" -s "$subnet" -d "$HOST_IP" -j DROP
    done
fi

# === Insert chain into FORWARD ===
iptables -I FORWARD 1 -j "$CHAIN_NAME"

# === Allow inbound to honeypot port ===
# Check if rule already exists
if ! iptables -C INPUT -p tcp --dport "$HONEYPOT_PORT" -j ACCEPT 2>/dev/null; then
    iptables -A INPUT -p tcp --dport "$HONEYPOT_PORT" -j ACCEPT
fi

echo ""
echo "[+] Honeypot isolation rules applied."
echo "[+] Protected LAN subnets: ${LAN_SUBNETS[*]}"
echo "[+] Honeypot subnets:      ${DOCKER_HONEYPOT_SUBNETS[*]}"
echo "[+] Inbound port:          $HONEYPOT_PORT"
echo ""
echo "[!] To remove: iptables -D FORWARD -j $CHAIN_NAME && iptables -F $CHAIN_NAME && iptables -X $CHAIN_NAME"
