#!/usr/bin/env bash
set -e

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

export WING_PORT="${WING_PORT:-9001}"
echo "[*] Starting goose-wing RFC 6455 WebSocket Server on 0.0.0.0:${WING_PORT}..."

exec /app/tools/bin/autobahn_server
