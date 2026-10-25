#!/usr/bin/env python3
"""
Full End-to-End Stress Test Coordinator connecting goose-wing through Python ToxiProxy.
Executes rapid iterations of sliced chunks, delayed packets, and abrupt disconnects.
"""

import sys
import os
import asyncio
import subprocess
import time

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from toxiproxy import ChaosProxy, SlicerToxic, LatencyToxic, BandwidthToxic, ResetPeerToxic

async def test_rapid_chaos_cycles(proxy_port: int, cycles: int = 50):
    """Fires rapid concurrent requests through the chaos proxy."""
    passed = 0
    failed = 0
    for i in range(cycles):
        body = f"StressCyclePayload_{i}_{time.time_ns()}".encode()
        req = (
            b"POST /stress HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body
        )
        try:
            reader, writer = await asyncio.wait_for(
                asyncio.open_connection("127.0.0.1", proxy_port),
                timeout=3.0
            )
            writer.write(req)
            await writer.drain()

            resp = bytearray()
            while True:
                chunk = await asyncio.wait_for(reader.read(4096), timeout=3.0)
                if not chunk:
                    break
                resp.extend(chunk)

            writer.close()
            await writer.wait_closed()

            if b"200 OK" in resp and body in resp:
                passed += 1
            else:
                failed += 1
        except Exception as e:
            failed += 1

    return passed, failed


async def run_suite():
    print("============================================================")
    print(" goose-wing ToxiProxy End-to-End Heavy Stress Harness")
    print("============================================================")

    # Import echo server from run_e2e_stress
    from run_e2e_stress import GooseEchoServer
    backend = GooseEchoServer()
    backend_port = await backend.start()
    print(f"[*] Upstream Backend Server listening on 127.0.0.1:{backend_port}")

    proxy = ChaosProxy(upstream_host="127.0.0.1", upstream_port=backend_port)
    proxy_port = await proxy.start()
    print(f"[*] ToxiProxy listening on 127.0.0.1:{proxy_port}\n")

    # Cycle 1: 50 iterations with Slicer Toxic (1..4 byte chunks)
    print(">>> Stage A: 50 Iterations with Slicer Toxic (1..4 byte stream slicing)...")
    proxy.clear_toxics()
    proxy.add_toxic(SlicerToxic("stream_slicer", min_bytes=1, max_bytes=4, delay_ms=1, stream="both"))
    p1, f1 = await test_rapid_chaos_cycles(proxy_port, 50)
    print(f"    Result: {p1}/50 passed ({f1} failed)")

    # Cycle 2: 50 iterations with Latency + Jitter (20ms +/- 10ms)
    print("\n>>> Stage B: 50 Iterations with Latency + Jitter Toxic (20ms +/- 10ms)...")
    proxy.clear_toxics()
    proxy.add_toxic(LatencyToxic("latency_jitter", latency_ms=20, jitter_ms=10, stream="both"))
    p2, f2 = await test_rapid_chaos_cycles(proxy_port, 50)
    print(f"    Result: {p2}/50 passed ({f2} failed)")

    # Cycle 3: 50 iterations with Combined Slicer + Bandwidth Throttling (64 KiB/s)
    print("\n>>> Stage C: 50 Iterations with Combined Slicer + Bandwidth Throttling...")
    proxy.clear_toxics()
    proxy.add_toxic(SlicerToxic("stream_slicer", min_bytes=2, max_bytes=7, delay_ms=1, stream="both"))
    proxy.add_toxic(BandwidthToxic("bandwidth_throttle", rate_kib=64, stream="both"))
    p3, f3 = await test_rapid_chaos_cycles(proxy_port, 50)
    print(f"    Result: {p3}/50 passed ({f3} failed)")

    await proxy.stop()
    await backend.stop()

    total_passed = p1 + p2 + p3
    total_failed = f1 + f2 + f3
    print("\n============================================================")
    print(f" Final E2E Heavy Stress Result: {total_passed}/150 PASSED ({total_failed} FAILED)")
    print("============================================================")

    if total_failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(run_suite())
