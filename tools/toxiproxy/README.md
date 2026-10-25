# Real Shopify Toxiproxy Integration

This package provides native integration with the official **[Shopify Toxiproxy](https://github.com/Shopify/toxiproxy)** daemon (v2.13.0+) for network anomaly injection and chaos testing in `goose-wing`.

## Architecture

- **`tools/bin/toxiproxy-server.exe`**: Official Shopify Toxiproxy daemon binary (compiled in Go).
- **`tools/bin/toxiproxy-cli.exe`**: Official Toxiproxy CLI utility.
- **`tools/toxiproxy/server.py`**: Automatic lifecycle manager and health checker (downloads or spawns daemon on demand).
- **`tools/toxiproxy/client.py`**: Zero-dependency Python REST client for Toxiproxy HTTP API (`localhost:8474`).
- **`tools/toxiproxy/toxics.py`**: Native Toxic definitions (`LatencyToxic`, `BandwidthToxic`, `SlicerToxic`, `ResetPeerToxic`, `TimeoutToxic`, `SlowCloseToxic`, `LimitDataToxic`).
- **`tools/toxiproxy/proxy.py`**: High-level `ChaosProxy` session manager supporting `async/await` and context managers.
- **`tools/toxiproxy/run_e2e_stress.py`**: 5-stage live chaos stress runner.
- **`tools/toxiproxy/stress_wing_e2e.py`**: 150-iteration high-frequency chaos stress runner.

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

### 3. Running Stress Test Suites

```powershell
# 5-stage chaos suite
python tools/toxiproxy/run_e2e_stress.py

# 150-iteration heavy chaos suite
python tools/toxiproxy/stress_wing_e2e.py
```

### 4. Programmatic Python API

```python
import asyncio
from tools.toxiproxy import ChaosProxy, LatencyToxic, SlicerToxic

async def test():
    # Automatically starts Toxiproxy server if needed, binds ephemeral port:
    proxy = ChaosProxy(upstream_host="127.0.0.1", upstream_port=8080)
    proxy_port = await proxy.start()

    # Inject real network slicing:
    proxy.add_toxic(SlicerToxic("stream_slicer", min_bytes=1, max_bytes=4, delay_ms=2))

    # Add 50ms latency with 10ms jitter:
    proxy.add_toxic(LatencyToxic("latency", latency_ms=50, jitter_ms=10))

    # ... send requests to 127.0.0.1:proxy_port ...

    proxy.clear_toxics()
    await proxy.stop()

asyncio.run(test())
```
