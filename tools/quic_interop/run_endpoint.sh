#!/usr/bin/env bash
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

# Official marten-seemann/quic-interop-runner endpoint entrypoint for goose-wing.
# Honors ROLE=client|server, TESTCASE, SSLKEYLOGFILE, REQUESTS, /www, /downloads.
# Exits 127 for unsupported testcases per quic-interop-runner specification.

set -euo pipefail

if [ -x /setup.sh ]; then
    /setup.sh
fi

ROLE="${ROLE:-server}"
TESTCASE="${TESTCASE:-transfer}"
SSLKEYLOGFILE="${SSLKEYLOGFILE:-}"
WWW_DIR="${WWW_DIR:-/www}"
DOWNLOADS_DIR="${DOWNLOADS_DIR:-/downloads}"
PORT="${PORT:-443}"
ENDPOINT_BIN="${ENDPOINT_BIN:-/app/tools/bin/quic_interop_endpoint}"

case "$TESTCASE" in
    handshake|transfer|retry|resumption|keyupdate|chacha20|multiconnect|zerortt|http3)
        ;;
    *)
        echo "[goose-wing] Unsupported testcase: $TESTCASE" >&2
        exit 127
        ;;
esac

if [ -n "$SSLKEYLOGFILE" ]; then
    mkdir -p "$(dirname "$SSLKEYLOGFILE")"
fi

if [ "$ROLE" = "server" ]; then
    mkdir -p "$WWW_DIR"
    exec "$ENDPOINT_BIN" server "$PORT" "$WWW_DIR" "$TESTCASE" "$SSLKEYLOGFILE"
elif [ "$ROLE" = "client" ]; then
    mkdir -p "$DOWNLOADS_DIR"
    if [ -x /wait-for-it.sh ]; then
        /wait-for-it.sh sim:57832 -s -t 30 || true
    fi
    REQ_LIST="${REQUESTS:-https://server:${PORT}/index.html}"
    for req_url in $REQ_LIST; do
        no_scheme="${req_url#*://}"
        hostport="${no_scheme%%/*}"
        path_part="/${no_scheme#*/}"
        host="${hostport%%:*}"
        req_port="$PORT"
        if [[ "$hostport" == *:* ]]; then
            req_port="${hostport##*:}"
        fi
        fname="${path_part#/}"
        [ -z "$fname" ] && fname="index.html"
        "$ENDPOINT_BIN" client "$host" "$req_port" "$DOWNLOADS_DIR" "$TESTCASE" "$fname" "$SSLKEYLOGFILE"
    done
    exit 0
else
    echo "[goose-wing] Unknown ROLE: $ROLE" >&2
    exit 1
fi
