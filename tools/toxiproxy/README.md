# Toxiproxy integration

This package integrates the [Shopify Toxiproxy](https://github.com/Shopify/toxiproxy) daemon (v2.13.0+) for network anomaly injection and chaos testing in goose-wing.

## Architecture

- `tools/bin/toxiproxy-server.exe`: Toxiproxy daemon binary.
- `tools/bin/toxiproxy-cli.exe`: Toxiproxy CLI utility.
- `tools/bin/goose_chaos_server.exe`: Standalone Goose server supporting HTTP/1.1, WebSocket, and HTTP/2.
- `tools/toxiproxy/server.py`: Lifecycle manager and health checker.
- `tools/toxiproxy/client.py`: Python REST client for the Toxiproxy HTTP API (`localhost:8474`).
- `tools/toxiproxy/toxics.py`: Toxic definitions (`LatencyToxic`, `BandwidthToxic`, `SlicerToxic`, `ResetPeerToxic`, `TimeoutToxic`, `SlowCloseToxic`, `LimitDataToxic`).
- `tools/toxiproxy/proxy.py`: `ChaosProxy` session manager with context managers for toxic injection.
- `tools/toxiproxy/stress_all_goose.py`: 43-stage chaos and attack stress runner testing HTTP/1.1 smuggling, HTTP/2 flow control, WebSocket invariants, and L4 network anomalies.

## Usage

### 1. Starting the server manually

Run from the repository root:

```powershell
.\tools\start_toxiproxy.bat
```

Or check status via Python:

```powershell
python tools/toxiproxy/server.py --status
```

`ChaosProxy` starts the daemon automatically if it is not already running.

### 2. Using the CLI

```powershell
.\tools\toxiproxy_cli.bat list
```

### 3. Running chaos stress tests

#### Locally

```powershell
python tools/toxiproxy/stress_all_goose.py
```

#### In Docker (Docker Compose)

```powershell
# Run the 43-stage suite in a Linux container
docker compose -f tools/toxiproxy/docker-compose.yml up --build chaos-suite --abort-on-container-exit

# Or via the Python helper:
python tools/toxiproxy.py --docker

# Or run standalone Toxiproxy daemon in Docker:
python tools/toxiproxy.py --daemon
```

### 4. Python API

#### Synchronous usage with scoped toxics

```python
from tools.toxiproxy import ChaosProxy, LatencyToxic, SlicerToxic

# Automatically starts Toxiproxy server if needed, binds ephemeral port:
with ChaosProxy(upstream_host="127.0.0.1", upstream_port=8080) as proxy:
    print(f"Chaos proxy listening on 127.0.0.1:{proxy.bound_port}")

    # Inject real network slicing (1..4 byte chunks with 2ms delay):
    with proxy.toxic(SlicerToxic("stream_slicer", min_bytes=1, max_bytes=4, delay_ms=2)):
        # ... send requests through proxy.bound_port ...
        pass

    # Inject 50ms latency with 10ms jitter:
    with proxy.toxic(LatencyToxic("latency", latency_ms=50, jitter_ms=10)):
        # ... send requests through proxy.bound_port ...
        pass
```

#### Asynchronous usage

```python
import asyncio
from tools.toxiproxy import ChaosProxy, BandwidthToxic

async def test():
    async with ChaosProxy(upstream_host="127.0.0.1", upstream_port=8080) as proxy:
        async with proxy.atoxic(BandwidthToxic("throttle", rate_kib=32)):
            # ... run async requests through proxy.bound_port ...
            pass

asyncio.run(test())
```
