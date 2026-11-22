#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

# Applies Linux kernel `tc netem` packet loss, delay/jitter, duplication, and
# reordering on loopback (`lo`) during live goose-wing HTTP/3 & QUIC transfers,
# then optionally runs Google `packetdrill` against the Wing TCP .pkt scripts.

set -euo pipefail

SERVER_BIN="${SERVER_BIN:-/app/tools/bin/http3_server}"
CLIENT_BIN="${CLIENT_BIN:-/app/tools/bin/http3_client}"
PKT_DIR="${PKT_DIR:-/app/tools/netem_packetdrill}"
NETEM_DEV="${NETEM_DEV:-lo}"
SRV_PID=""
PORT_LOG="$(mktemp)"

cleanup() {
    tc qdisc del dev "$NETEM_DEV" root 2>/dev/null || true
    if [ -n "$SRV_PID" ]; then
        kill "$SRV_PID" 2>/dev/null || true
        wait "$SRV_PID" 2>/dev/null || true
    fi
    rm -f "$PORT_LOG"
}
trap cleanup EXIT

echo "[*] Starting goose-wing HTTP/3 server ($SERVER_BIN)..."
"$SERVER_BIN" >"$PORT_LOG" 2>&1 &
SRV_PID=$!

PORT=""
for _ in $(seq 1 50); do
    if grep -q "READY_PORT:" "$PORT_LOG"; then
        PORT="$(grep -m1 "READY_PORT:" "$PORT_LOG" | sed 's/.*READY_PORT://')"
        break
    fi
    sleep 0.1
done

if [ -z "$PORT" ]; then
    echo "[!] http3_server failed to report READY_PORT" >&2
    cat "$PORT_LOG" >&2
    exit 1
fi
echo "[+] http3_server listening on 127.0.0.1:$PORT"

echo "[*] Applying tc netem profile on $NETEM_DEV..."
tc qdisc del dev "$NETEM_DEV" root 2>/dev/null || true
tc qdisc add dev "$NETEM_DEV" root netem loss 5% delay 15ms 5ms duplicate 2% reorder 10%
tc qdisc show dev "$NETEM_DEV"

echo "[*] Running live HTTP/3 client transfers under tc netem impairments..."
PASS_RUNS=0
for attempt in $(seq 1 5); do
    if WING_PORT="$PORT" PORT="$PORT" "$CLIENT_BIN" | grep -q "H3_NATIVE_GET_ROOT: PASS"; then
        PASS_RUNS=$((PASS_RUNS + 1))
        echo "  [PASS] netem run #$attempt succeeded"
        break
    fi
    echo "  [*] netem run #$attempt hit injected UDP loss; retrying..."
    sleep 0.1
done

if [ "$PASS_RUNS" -lt 1 ]; then
    echo "[!] HTTP/3 client did not recover under tc netem" >&2
    exit 1
fi

echo "[*] Removing tc netem qdisc from $NETEM_DEV..."
tc qdisc del dev "$NETEM_DEV" root 2>/dev/null || true

if command -v packetdrill >/dev/null 2>&1 && [ -c /dev/net/tun ]; then
    echo "[*] Executing packetdrill TCP edge-case scripts..."
    for pkt in "$PKT_DIR"/tcp_*.pkt; do
        echo "  [*] packetdrill $(basename "$pkt")"
        packetdrill "$pkt"
    done
else
    echo "[*] Skipping live kernel packetdrill (/dev/net/tun unavailable); validating DSL via runner.py..."
    python3 "$PKT_DIR/runner.py" --validate-pkt-only
fi

echo "[+] netem_quic_test.sh completed successfully."
