#!/usr/bin/env bash

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

set -e

if [ "$#" -gt 0 ]; then
    exec "$@"
fi

export WING_PORT="${WING_PORT:-8088}"
echo "[*] Starting goose-wing Chaos Reactor Server on 0.0.0.0:${WING_PORT}..."

exec /app/tools/bin/chaos_server
