#!/usr/bin/env python3
"""
End-to-end chaos stress test runner for goose-wing using Python ToxiProxy.
Executes live TCP tests through the chaos proxy with various network anomalies:
  1. Baseline clean proxy roundtrip
  2. Slicer toxic (1..3 byte chunks with delays)
  3. Latency & Jitter toxic
  4. Bandwidth throttling toxic
  5. Peer connection reset (RST) injection
"""

import sys
import os
import asyncio
import socket
import time

# Ensure UTF-8 output on Windows
sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from toxiproxy import ChaosProxy, SlicerToxic, LatencyToxic, BandwidthToxic, ResetPeerToxic

class GooseEchoServer:
    """Simple asynchronous HTTP/1.1 echo backend simulating Goose server."""
    def __init__(self, host: str = "127.0.0.1", port: int = 0):
        self.host = host
        self.port = port
        self.server = None
        self.bound_port = 0

    async def start(self) -> int:
        self.server = await asyncio.start_server(self._handle_client, self.host, self.port)
        self.bound_port = self.server.sockets[0].getsockname()[1]
        return self.bound_port

    async def stop(self):
        if self.server:
            self.server.close()
            await self.server.wait_closed()

    async def _handle_client(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            buf = bytearray()
            while True:
                chunk = await reader.read(1024)
                if not chunk:
                    break
                buf.extend(chunk)
                if b"\r\n\r\n" in buf:
                    # Request header complete
                    body_start = buf.find(b"\r\n\r\n") + 4
                    # Read content-length if present
                    cl = 0
                    for line in bytes(buf[:body_start]).split(b"\r\n"):
                        if line.lower().startswith(b"content-length:"):
                            try:
                                cl = int(line.split(b":")[1].strip())
                            except Exception:
                                pass
                    while len(buf) - body_start < cl:
                        c = await reader.read(1024)
                        if not c:
                            break
                        buf.extend(c)

                    # Send response
                    body = bytes(buf[body_start:])
                    resp_body = b"ECHO:" + body if body else b"OK"
                    resp = (
                        b"HTTP/1.1 200 OK\r\n"
                        b"Content-Type: text/plain\r\n"
                        b"Content-Length: " + str(len(resp_body)).encode() + b"\r\n"
                        b"Connection: close\r\n\r\n" + resp_body
                    )
                    writer.write(resp)
                    await writer.drain()
                    break
        except Exception:
            pass
        finally:
            writer.close()


async def run_client_request(proxy_port: int, request_bytes: bytes, timeout: float = 5.0) -> bytes:
    """Connects to proxy, sends request, and returns response."""
    reader, writer = await asyncio.wait_for(
        asyncio.open_connection("127.0.0.1", proxy_port),
        timeout=timeout
    )
    writer.write(request_bytes)
    await writer.drain()

    resp = bytearray()
    while True:
        try:
            chunk = await asyncio.wait_for(reader.read(4096), timeout=timeout)
            if not chunk:
                break
            resp.extend(chunk)
        except asyncio.TimeoutError:
            break
        except Exception:
            break

    writer.close()
    try:
        await writer.wait_closed()
    except Exception:
        pass
    return bytes(resp)


async def main():
    print("============================================================")
    print(" goose-wing ToxiProxy Live Chaos E2E Test Runner")
    print("============================================================")

    # 1. Start Echo Server
    server = GooseEchoServer()
    server_port = await server.start()
    print(f"[*] Started Echo Backend Server on 127.0.0.1:{server_port}")

    # 2. Start Chaos Proxy
    proxy = ChaosProxy(upstream_host="127.0.0.1", upstream_port=server_port)
    proxy_port = await proxy.start()
    print(f"[*] Started Chaos Proxy on 127.0.0.1:{proxy_port} -> 127.0.0.1:{server_port}\n")

    passed = 0
    failed = 0

    # Test 1: Clean Baseline
    print("--- [Test 1] Baseline Clean Roundtrip ---")
    proxy.clear_toxics()
    req = b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    res = await run_client_request(proxy_port, req)
    if b"200 OK" in res and b"OK" in res:
        print("  [PASS] Clean HTTP/1.1 request/response roundtrip succeeded.")
        passed += 1
    else:
        print(f"  [FAIL] Expected 200 OK, got: {res}")
        failed += 1

    # Test 2: Slicer Toxic (1..3 byte slices with micro-delays)
    print("\n--- [Test 2] Slicer Toxic (1..3 byte chunks, 2ms delay) ---")
    proxy.clear_toxics()
    proxy.add_toxic(SlicerToxic("stream_slicer", min_bytes=1, max_bytes=3, delay_ms=2, stream="both"))
    post_body = b"ChaosSlicerPayload1234567890"
    post_req = (
        b"POST /echo HTTP/1.1\r\n"
        b"Host: localhost\r\n"
        b"Content-Length: " + str(len(post_body)).encode() + b"\r\n"
        b"Connection: close\r\n\r\n" + post_body
    )
    t0 = time.time()
    res = await run_client_request(proxy_port, post_req, timeout=10.0)
    dur = time.time() - t0
    if b"200 OK" in res and b"ECHO:" + post_body in res:
        print(f"  [PASS] Sliced stream correctly reassembled and processed in {dur*1000:.1f}ms.")
        passed += 1
    else:
        print(f"  [FAIL] Slicer reassembly failed, got: {res}")
        failed += 1

    # Test 3: Latency & Jitter Toxic (50ms latency, 15ms jitter)
    print("\n--- [Test 3] Latency & Jitter Toxic (50ms +/- 15ms) ---")
    proxy.clear_toxics()
    proxy.add_toxic(LatencyToxic("latency_jitter", latency_ms=50, jitter_ms=15, stream="both"))
    t0 = time.time()
    res = await run_client_request(proxy_port, req, timeout=5.0)
    elapsed_ms = (time.time() - t0) * 1000
    if b"200 OK" in res and elapsed_ms >= 40:
        print(f"  [PASS] Delayed request successfully delivered in {elapsed_ms:.1f}ms.")
        passed += 1
    else:
        print(f"  [FAIL] Latency test failed ({elapsed_ms:.1f}ms), got: {res}")
        failed += 1

    # Test 4: Bandwidth Throttling (32 KiB/s rate limit)
    print("\n--- [Test 4] Bandwidth Throttling (32 KiB/s) ---")
    proxy.clear_toxics()
    proxy.add_toxic(BandwidthToxic("rate_limit", rate_kib=32, stream="both"))
    res = await run_client_request(proxy_port, req, timeout=5.0)
    if b"200 OK" in res:
        print("  [PASS] Bandwidth throttled connection completed successfully.")
        passed += 1
    else:
        print(f"  [FAIL] Rate limit test failed, got: {res}")
        failed += 1

    # Test 5: Peer Reset Toxic (TCP RST mid-request)
    print("\n--- [Test 5] Peer Reset Toxic (RST after 15 bytes) ---")
    proxy.clear_toxics()
    proxy.add_toxic(ResetPeerToxic("tcp_rst", reset_after_bytes=15, stream="upstream"))
    res = await run_client_request(proxy_port, post_req, timeout=3.0)
    if len(res) == 0:
        print("  [PASS] TCP RST successfully handled and aborted without hangs.")
        passed += 1
    else:
        print(f"  [FAIL] Expected immediate disconnect/RST, got response: {res}")
        failed += 1

    # Cleanup
    await proxy.stop()
    await server.stop()

    print("\n============================================================")
    print(f" ToxiProxy Chaos Suite Complete: {passed} PASSED, {failed} FAILED")
    print("============================================================")
    if failed > 0:
        sys.exit(1)

if __name__ == "__main__":
    asyncio.run(main())
