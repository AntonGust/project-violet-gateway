#!/bin/bash
# ============================================================================
# Internet Honeypot — Host Firewall Setup
# Isolates honeypot Docker containers from the lab LAN.
# Run as root. Idempotent (safe to re-run).
# ============================================================================

set -euo pipefail

# === CONFIGURATION ===
HONEYPOT_PORT=22

DOCKER_HONEYPOT_SUBNETS=(
    "172.20.0.0/24"   # net_entry
    "172.20.1.0/24"   # net_hop1
    "172.20.2.0/24"   # net_hop2
    "172.20.10.0/24"  # net_llm
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

echo "[*] Setting up honeypot isolation firewall rules (IPv4 + IPv6)..."

# Helper: apply identical rules to both iptables and ip6tables
apply_rules() {
    local ipt="$1"
    shift

    # === Create or flush the custom chain ===
    if $ipt -L "$CHAIN_NAME" -n &>/dev/null; then
        echo "[*] Flushing existing $CHAIN_NAME chain ($ipt)..."
        $ipt -F "$CHAIN_NAME"
    else
        echo "[*] Creating $CHAIN_NAME chain ($ipt)..."
        $ipt -N "$CHAIN_NAME"
    fi

    # Remove old references from FORWARD chain (idempotent)
    while $ipt -D FORWARD -j "$CHAIN_NAME" 2>/dev/null; do :; done

    # === Rule 1: Allow honeypot containers to talk to each other ===
    for subnet in "${DOCKER_HONEYPOT_SUBNETS[@]}"; do
        for dest in "${DOCKER_HONEYPOT_SUBNETS[@]}"; do
            $ipt -A "$CHAIN_NAME" -s "$subnet" -d "$dest" -j ACCEPT
        done
    done

    # === Rule 2: Allow outbound HTTPS + DNS ===
    for subnet in "${DOCKER_HONEYPOT_SUBNETS[@]}"; do
        $ipt -A "$CHAIN_NAME" -s "$subnet" -p tcp --dport 443 -j ACCEPT
        $ipt -A "$CHAIN_NAME" -s "$subnet" -p tcp --dport 53 -j ACCEPT
        $ipt -A "$CHAIN_NAME" -s "$subnet" -p udp --dport 53 -j ACCEPT
    done

    # === Rule 3: BLOCK all honeypot → LAN traffic ===
    for subnet in "${DOCKER_HONEYPOT_SUBNETS[@]}"; do
        for lan in "${LAN_SUBNETS[@]}"; do
            $ipt -A "$CHAIN_NAME" -s "$subnet" -d "$lan" -j DROP
        done
    done

    # === Rule 4: BLOCK honeypot → host machine (IPv4 only) ===
    if [[ "$ipt" == "iptables" ]]; then
        HOST_IP=$(hostname -I | awk '{print $1}')
        if [[ -n "$HOST_IP" ]]; then
            echo "[+] Blocking honeypot → host ($HOST_IP)..."
            for subnet in "${DOCKER_HONEYPOT_SUBNETS[@]}"; do
                $ipt -A "$CHAIN_NAME" -s "$subnet" -d "$HOST_IP" -j DROP
            done
        fi
    fi

    # === Insert chain into FORWARD ===
    $ipt -I FORWARD 1 -j "$CHAIN_NAME"
}

# === IPv4 rules ===
echo "[+] Applying IPv4 rules..."
apply_rules iptables

# === Allow inbound to honeypot port (IPv4) ===
if ! iptables -C INPUT -p tcp --dport "$HONEYPOT_PORT" -j ACCEPT 2>/dev/null; then
    iptables -A INPUT -p tcp --dport "$HONEYPOT_PORT" -j ACCEPT
fi

# === IPv6 rules ===
# Honeypot subnets are IPv4-only (172.20.x.x), so the IPv6 chain will have no
# subnet-specific rules. We block all IPv6 forwarding from/to the honeypot
# interface to prevent any unfiltered path.
echo "[+] Applying IPv6 rules (blanket DROP for honeypot interface traffic)..."
if ip6tables -L "$CHAIN_NAME" -n &>/dev/null; then
    ip6tables -F "$CHAIN_NAME"
else
    ip6tables -N "$CHAIN_NAME"
fi
while ip6tables -D FORWARD -j "$CHAIN_NAME" 2>/dev/null; do :; done
# Drop all IPv6 forwarded traffic — honeypot containers are IPv4-only
ip6tables -A "$CHAIN_NAME" -j DROP
ip6tables -I FORWARD 1 -j "$CHAIN_NAME"

# Block inbound IPv6 on honeypot port to prevent unmonitored SSH
if ! ip6tables -C INPUT -p tcp --dport "$HONEYPOT_PORT" -j DROP 2>/dev/null; then
    ip6tables -A INPUT -p tcp --dport "$HONEYPOT_PORT" -j DROP
fi

echo ""
echo "[+] Honeypot isolation rules applied (IPv4 + IPv6)."
echo "[+] Protected LAN subnets: ${LAN_SUBNETS[*]}"
echo "[+] Honeypot subnets:      ${DOCKER_HONEYPOT_SUBNETS[*]}"
echo "[+] Inbound port:          $HONEYPOT_PORT"
echo ""
echo "[!] To remove IPv4: iptables -D FORWARD -j $CHAIN_NAME && iptables -F $CHAIN_NAME && iptables -X $CHAIN_NAME"
echo "[!] To remove IPv6: ip6tables -D FORWARD -j $CHAIN_NAME && ip6tables -F $CHAIN_NAME && ip6tables -X $CHAIN_NAME"
