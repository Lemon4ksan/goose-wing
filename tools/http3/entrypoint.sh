#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

set -e

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

export WING_PORT="${WING_PORT:-4433}"
echo "[*] Starting goose-wing HTTP/3 & QUIC Server on 0.0.0.0:${WING_PORT} (UDP)..."

exec /app/tools/bin/http3_server --enable-test-hooks
