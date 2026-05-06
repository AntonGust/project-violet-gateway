#!/bin/bash
# ============================================================================
# Pin base image tags to their current SHA256 digests in all Dockerfiles.
# Run this script on the deployment machine before `docker compose build`.
# Re-run it to refresh digests when you intentionally want upstream updates.
# ============================================================================

set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

declare -A IMAGES=(
    ["haproxy:2.9-alpine"]="filter_gateway/Dockerfile"
    ["python:3.11-slim"]="session_analyzer/Dockerfile blocklist_updater/Dockerfile"
    ["python:3.12-slim"]="attack_theater/Dockerfile analysis_agent/Dockerfile"
    ["nginxinc/nginx-unprivileged:1.27-alpine"]="llm_proxy/Dockerfile"
)

echo "[*] Pulling images and resolving digests..."

for image in "${!IMAGES[@]}"; do
    echo "[+] Pulling $image ..."
    docker pull "$image" --quiet

    digest=$(docker inspect --format='{{index .RepoDigests 0}}' "$image" 2>/dev/null || true)
    if [[ -z "$digest" ]]; then
        echo "[-] Could not resolve digest for $image — skipping"
        continue
    fi

    # digest is in the form "repo@sha256:..."
    sha="${digest#*@}"
    tag="${image%%:*}:${image##*:}"
    pinned_ref="${image%:*}:${image##*:}@${sha}"

    echo "    Digest: $sha"

    for dockerfile_rel in ${IMAGES[$image]}; do
        dockerfile="$SCRIPT_DIR/$dockerfile_rel"
        if [[ ! -f "$dockerfile" ]]; then
            echo "    [-] $dockerfile not found, skipping"
            continue
        fi
        # Replace "FROM <image>" (with or without existing digest) with pinned ref
        sed -i "s|FROM ${image}[^ ]*|FROM ${pinned_ref}|g" "$dockerfile"
        echo "    [+] Pinned in $dockerfile_rel"
    done
done

echo ""
echo "[+] Done. Commit the Dockerfile changes before deploying."
echo "    Re-run this script whenever you intentionally want to update base images."
