#!/bin/bash
set -e

echo "[entrypoint] Starting filter sidecar..."
python3 /app/sidecar/filter_server.py &
SIDECAR_PID=$!

# Wait for socket to be ready
for i in $(seq 1 10); do
    if [ -S /tmp/filter.sock ]; then
        echo "[entrypoint] Sidecar ready."
        break
    fi
    sleep 0.5
done

echo "[entrypoint] Starting HAProxy..."
haproxy -f /usr/local/etc/haproxy/haproxy.cfg &
HAPROXY_PID=$!

# Trap signals and forward to both processes
cleanup() {
    echo "[entrypoint] Shutting down..."
    kill -TERM "$HAPROXY_PID" 2>/dev/null || true
    kill -TERM "$SIDECAR_PID" 2>/dev/null || true
    wait "$HAPROXY_PID" 2>/dev/null || true
    wait "$SIDECAR_PID" 2>/dev/null || true
    echo "[entrypoint] Done."
    exit 0
}

trap cleanup SIGTERM SIGINT

# Wait for either process to exit
wait -n "$HAPROXY_PID" "$SIDECAR_PID"
EXIT_CODE=$?
echo "[entrypoint] Process exited with code $EXIT_CODE, shutting down..."
cleanup
