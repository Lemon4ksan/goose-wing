#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

set -e

# If arguments were provided and first arg is not "test", execute user command
if [ "$#" -gt 0 ] && [ "$1" != "test" ]; then
    exec "$@"
fi

echo "[*] Starting Shopify Toxiproxy daemon on 0.0.0.0:8474..."
/usr/local/bin/toxiproxy-server -host 0.0.0.0 -port 8474 &
TOXI_PID=$!

# shellcheck disable=SC2329 # Invoked indirectly via trap handler
cleanup() {
    echo "[*] Shutting down Toxiproxy daemon (PID $TOXI_PID)..."
    kill -TERM "$TOXI_PID" 2>/dev/null || true
    wait "$TOXI_PID" 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Wait for Toxiproxy to become ready
echo "[*] Waiting for Toxiproxy daemon to respond..."
READY=0
for _ in $(seq 1 30); do
    if curl -s http://127.0.0.1:8474/version >/dev/null 2>&1; then
        READY=1
        break
    fi
    sleep 0.2
done

if [ "$READY" -ne 1 ]; then
    echo "[!] Toxiproxy daemon failed to start within 6 seconds!" >&2
    exit 1
fi

echo "[+] Toxiproxy daemon is live and healthy."
echo "[*] Executing 43-stage live chaos stress runner..."

# Run the unified chaos stress runner
export PYTHONUNBUFFERED=1
export PYTHONUTF8=1
export TOXIPROXY_HOST=127.0.0.1
export TOXIPROXY_PORT=8474
export PROXY_CONNECT_HOST=127.0.0.1
export CHAOS_SERVER_BIN=/app/tools/bin/goose_chaos_server

python3 /app/tools/toxiproxy/stress_all_goose.py
EXIT_CODE=$?

if [ "$EXIT_CODE" -eq 0 ]; then
    echo "[+] All chaos scenarios passed successfully in Docker!"
else
    echo "[!] Chaos test suite exited with error code $EXIT_CODE"
fi

exit $EXIT_CODE
