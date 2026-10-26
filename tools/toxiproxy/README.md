# Real Shopify Toxiproxy Integration

This package provides native integration with the official **[Shopify Toxiproxy](https://github.com/Shopify/toxiproxy)** daemon (v2.13.0+) for network anomaly injection and chaos testing in `goose-wing`.

## Architecture

- **`tools/bin/toxiproxy-server.exe`**: Official Shopify Toxiproxy daemon binary (compiled in Go).
- **`tools/bin/toxiproxy-cli.exe`**: Official Toxiproxy CLI utility.
- **`tools/bin/goose_chaos_server.exe`**: Standalone native Goose server supporting live HTTP/1.1, WebSocket, and HTTP/2.
- **`tools/toxiproxy/server.py`**: Automatic lifecycle manager and health checker (downloads or spawns daemon on demand).
- **`tools/toxiproxy/client.py`**: Zero-dependency Python REST client for Toxiproxy HTTP API (`localhost:8474`).
- **`tools/toxiproxy/toxics.py`**: Native Toxic definitions (`LatencyToxic`, `BandwidthToxic`, `SlicerToxic`, `ResetPeerToxic`, `TimeoutToxic`, `SlowCloseToxic`, `LimitDataToxic`).
- **`tools/toxiproxy/proxy.py`**: High-level `ChaosProxy` session manager supporting sync/async context managers and scoped toxic blocks.
- **`tools/toxiproxy/stress_all_goose.py`**: 43-stage live chaos & security attack stress runner testing HTTP/1.1 Smuggling & CRLF injection, HTTP/2 CVEs & Flow Control, WebSocket RFC 6455 invariants, L4 network anomalies, and 50 rapid chaos cycles.

## Quick Usage

### 1. Starting the Server Manually

Run from repo root:
```powershell
.\tools\start_toxiproxy.bat
```
Or check status via Python:
```powershell
python tools/toxiproxy/server.py --status
```

*(Note: `ChaosProxy` will also automatically start the daemon if it is not already running!)*

### 2. Using the CLI

```powershell
.\tools\toxiproxy_cli.bat list
```

### 3. Running Chaos Stress Test Suite

```powershell
# Unified 43-stage chaos & attack suite covering HTTP/1.1 smuggling, HTTP/2 CVEs, WebSocket invariants, L4 anomalies and 50 rapid cycles
python tools/toxiproxy/stress_all_goose.py
```

### 4. Programmatic Python API

#### Synchronous Usage with Scoped Toxics
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

#### Asynchronous Usage
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
