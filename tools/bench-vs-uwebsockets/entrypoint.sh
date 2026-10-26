#!/usr/bin/env bash
set -e

GW_PORT=${GW_PORT:-3001}
UWS_PORT=${UWS_PORT:-3002}
BENCH_PORT=${BENCH_PORT:-8080}

echo "[entrypoint] Starting goose-wing server on port $GW_PORT..."
/app/bin/server_goose_wing &
export GW_PID=$!

echo "[entrypoint] Starting uWebSockets server on port $UWS_PORT..."
/app/bin/server_uwebsockets &
export UWS_PID=$!

# Cleanup on exit
cleanup() {
    echo "[entrypoint] Stopping child processes..."
    kill $GW_PID 2>/dev/null || true
    kill $UWS_PID 2>/dev/null || true
    wait $GW_PID 2>/dev/null || true
    wait $UWS_PID 2>/dev/null || true
}
trap cleanup EXIT INT TERM

# Wait for both servers to bind
echo "[entrypoint] Waiting for servers to become ready..."
for _ in {1..30}; do
    if nc -z 127.0.0.1 $GW_PORT && nc -z 127.0.0.1 $UWS_PORT; then
        echo "[entrypoint] Both engines listening and healthy (goose-wing:$GW_PORT, uWebSockets:$UWS_PORT)."
        break
    fi
    sleep 0.2
done

if [ "$1" = "--cli" ]; then
    echo "[entrypoint] Running automated CLI benchmark..."
    shift
    python3 /app/run_cli.py "$@"
    exit 0
elif [ "$#" -gt 0 ]; then
    exec "$@"
else
    echo "[entrypoint] Starting orchestrator web console on port $BENCH_PORT..."
    echo "[entrypoint] Open your browser at http://localhost:$BENCH_PORT"
    exec python3 /app/orchestrator.py
fi
