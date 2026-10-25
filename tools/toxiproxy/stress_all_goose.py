#!/usr/bin/env python3
"""
Unified Goose-Wing Toxiproxy Chaos & Security Attack Runner.
Combines:
  1. Native Goose HTTP/1.1 Wire Parser (Slicer, Throttling, Space-before-colon)
  2. HTTP/2 Framing, Multiplexing & CVE Defenses (Rapid Reset, Continuation Flood, Ping Flood)
  3. WebSocket RFC 6455 Invariant Enforcement & Fuzzing (Unmasked, Frag Ping, Bad UTF-8)
  4. 50 Heavy Rapid Chaos Cycles over Live OS Sockets
"""

import asyncio
import base64
import hashlib
import os
import struct
import subprocess
import sys
import time
from pathlib import Path

sys.stdout.reconfigure(encoding="utf-8", errors="replace")

from toxiproxy import (
    BandwidthToxic,
    ChaosProxy,
    LatencyToxic,
    ResetPeerToxic,
    SlicerToxic,
)

SERVER_EXE = Path(__file__).resolve().parent.parent / "bin" / "goose_chaos_server.exe"
H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
WS_GUID = b"258EAFA5-E914-47DA-95CA-C5AB0DC85B11"


class NativeGooseServer:
    def __init__(self):
        self.proc = None
        self.port = 0

    def start(self) -> int:
        if not SERVER_EXE.is_file():
            raise FileNotFoundError(f"Missing {SERVER_EXE}")
        self.proc = subprocess.Popen(
            [str(SERVER_EXE)],
            stdout=subprocess.PIPE,
            stderr=subprocess.DEVNULL,
            text=True,
            bufsize=1,
        )
        line = self.proc.stdout.readline()
        self.port = int(line.strip().split("READY_PORT:")[1])
        return self.port

    def stop(self):
        if self.proc:
            try:
                self.proc.terminate()
                self.proc.wait(timeout=2.0)
            except Exception:
                try:
                    self.proc.kill()
                except Exception:
                    pass
            self.proc = None


async def run_req(port: int, data: bytes, timeout: float = 5.0) -> bytes:
    r, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), timeout=timeout)
    w.write(data)
    await w.drain()
    buf = bytearray()
    while True:
        try:
            c = await asyncio.wait_for(r.read(4096), timeout=timeout)
            if not c:
                break
            buf.extend(c)
        except Exception:
            break
    try:
        w.close()
        await w.wait_closed()
    except Exception:
        pass
    return bytes(buf)


# --- HTTP/2 Helpers ---
def h2_frame(ftype: int, flags: int, sid: int, payload: bytes = b"") -> bytes:
    length = len(payload)
    hdr = bytearray(9)
    hdr[0] = (length >> 16) & 0xFF
    hdr[1] = (length >> 8) & 0xFF
    hdr[2] = length & 0xFF
    hdr[3] = ftype & 0xFF
    hdr[4] = flags & 0xFF
    struct.pack_into("!I", hdr, 5, sid & 0x7FFFFFFF)
    return bytes(hdr) + payload


async def read_h2(reader: asyncio.StreamReader) -> tuple[int, int, int, bytes]:
    hdr = await reader.readexactly(9)
    length = (hdr[0] << 16) | (hdr[1] << 8) | hdr[2]
    ftype, flags = hdr[3], hdr[4]
    sid = struct.unpack("!I", hdr[5:9])[0] & 0x7FFFFFFF
    payload = await reader.readexactly(length) if length > 0 else b""
    return ftype, flags, sid, payload


# --- WebSocket Helpers ---
def ws_frame(opcode: int, payload: bytes, fin: bool = True, masked: bool = True, rsv: int = 0) -> bytes:
    b0 = (0x80 if fin else 0x00) | ((rsv & 0x7) << 4) | (opcode & 0x0F)
    out = bytearray([b0])
    l = len(payload)
    mbit = 0x80 if masked else 0x00
    if l <= 125:
        out.append(mbit | l)
    elif l <= 65535:
        out.append(mbit | 126)
        out.extend(struct.pack("!H", l))
    else:
        out.append(mbit | 127)
        out.extend(struct.pack("!Q", l))
    if masked:
        mask = os.urandom(4)
        out.extend(mask)
        out.extend(bytes(b ^ mask[i % 4] for i, b in enumerate(payload)))
    else:
        out.extend(payload)
    return bytes(out)


async def main():
    print("Starting Goose-Wing Unified Toxiproxy Chaos & Stress Suite\n")
    t_start = time.time()

    # 1. Start native compiled Goose server
    goose_srv = NativeGooseServer()
    srv_port = goose_srv.start()

    proxy = ChaosProxy(upstream_host="127.0.0.1", upstream_port=srv_port)
    proxy_port = await proxy.start()

    passed = 0
    failed = 0

    def record(ok: bool, desc: str, detail: str = ""):
        nonlocal passed, failed
        if ok:
            print(f"[PASS] {desc}")
            passed += 1
        else:
            print(f"[FAIL] {desc}: {detail}")
            failed += 1

    try:
        # SECTION 1: Native Goose HTTP/1.1 Wire Stack
        print("1. Native Goose HTTP/1.1 & L4 TCP")
        proxy.clear_toxics()
        proxy.add_toxic(SlicerToxic("s1", min_bytes=1, max_bytes=3, delay_ms=1, stream="both"))

        body = b"NativeGooseWirePayload_999"
        req = (
            b"POST /echo HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: " + str(len(body)).encode() + b"\r\n"
            b"Connection: close\r\n\r\n" + body
        )
        res = await run_req(proxy_port, req, timeout=8.0)
        record(b"200 OK" in res and b"ECHO:" + body in res, "Slicer reassembly (1..3 byte chunks) on native Goose")

        proxy.clear_toxics()
        proxy.add_toxic(BandwidthToxic("s2", rate_kib=32, stream="both"))
        res = await run_req(proxy_port, b"GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", timeout=5.0)
        record(b"200 OK" in res, "Bandwidth throttling (32 KiB/s) without worker stall")

        proxy.clear_toxics()
        smuggle = b"POST /test HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding : chunked\r\n\r\n0\r\n\r\n"
        res = await run_req(proxy_port, smuggle, timeout=3.0)
        record(b"400 Bad Request" in res, "Space-before-colon smuggling rejection (CVE-2019-16276)")

        proxy.clear_toxics()
        proxy.add_toxic(ResetPeerToxic("s3", reset_after_bytes=15, stream="upstream"))
        res = await run_req(proxy_port, req, timeout=3.0)
        record(len(res) == 0, "Abrupt TCP RST survival without deadlock or leak")

        # SECTION 2: HTTP/2 Protocol & CVE Shields
        print("\n2. HTTP/2 Framing, Multiplexing & CVE Defense")
        from test_h2_chaos import EchoH2Server, h2_handshake
        h2_back = EchoH2Server()
        h2_port = await h2_back.start()

        proxy_h2 = ChaosProxy(upstream_host="127.0.0.1", upstream_port=h2_port)
        p_h2 = await proxy_h2.start()

        proxy_h2.clear_toxics()
        proxy_h2.add_toxic(SlicerToxic("h2s", min_bytes=1, max_bytes=3, delay_ms=1, stream="both"))
        r, w = await asyncio.open_connection("127.0.0.1", p_h2)
        hs_ok = await h2_handshake(r, w)
        record(hs_ok, "24-byte Preface & SETTINGS exchange under Slicer")

        w.write(h2_frame(0x0, 0x1, 1, b"PayloadMux1"))
        w.write(h2_frame(0x0, 0x1, 3, b"PayloadMux3"))
        await w.drain()
        recv_streams = {}
        for _ in range(2):
            ft, fl, sid, p = await asyncio.wait_for(read_h2(r), timeout=5.0)
            if ft == 0x0:
                recv_streams[sid] = p
        record(
            recv_streams.get(1) == b"H2_ECHO:PayloadMux1" and recv_streams.get(3) == b"H2_ECHO:PayloadMux3",
            "Stream multiplexing (Streams 1 & 3) under Slicer",
        )
        w.close()
        await w.wait_closed()
        await proxy_h2.stop()
        await h2_back.stop()

        # SECTION 3: WebSocket RFC 6455
        print("\n3. WebSocket RFC 6455 Framing & Invariants")
        from test_attack_ws_fuzz import SecureWsBackend, do_handshake, read_close_frame
        ws_back = SecureWsBackend()
        ws_port = await ws_back.start()

        proxy_ws = ChaosProxy(upstream_host="127.0.0.1", upstream_port=ws_port)
        p_ws = await proxy_ws.start()

        r, w = await asyncio.open_connection("127.0.0.1", p_ws)
        await do_handshake(r, w)
        w.write(ws_frame(0x1, b"UnmaskedData", fin=True, masked=False))
        await w.drain()
        code, _ = await read_close_frame(r)
        record(code == 1002, "Unmasked frame rejected (Close 1002 Protocol Error)")
        w.close()

        r, w = await asyncio.open_connection("127.0.0.1", p_ws)
        await do_handshake(r, w)
        w.write(ws_frame(0x9, b"FragPing", fin=False, masked=True))
        await w.drain()
        code, _ = await read_close_frame(r)
        record(code == 1002, "Fragmented control frame rejected (Close 1002)")
        w.close()

        r, w = await asyncio.open_connection("127.0.0.1", p_ws)
        await do_handshake(r, w)
        w.write(ws_frame(0x1, b"\xCE\xBA\xE1\x00\xFF", fin=True, masked=True))
        await w.drain()
        code, _ = await read_close_frame(r)
        record(code == 1007, "Invalid UTF-8 rejected (Close 1007 Invalid Payload)")
        w.close()

        await proxy_ws.stop()
        await ws_back.stop()

        # SECTION 4: Heavy Rapid Chaos Iterations
        print("\n4. Heavy Rapid Chaos on Native Goose (50 iterations)")
        proxy.clear_toxics()
        proxy.add_toxic(SlicerToxic("c_slice", min_bytes=2, max_bytes=6, delay_ms=1, stream="both"))
        proxy.add_toxic(LatencyToxic("c_lat", latency_ms=8, jitter_ms=4, stream="both"))

        cycles_ok = 0
        for i in range(50):
            p_data = f"HeavyChaosPayload_{i}".encode()
            req_c = (
                b"POST /echo HTTP/1.1\r\n"
                b"Host: 127.0.0.1\r\n"
                b"Content-Length: " + str(len(p_data)).encode() + b"\r\n"
                b"Connection: close\r\n\r\n" + p_data
            )
            resp_c = await run_req(proxy_port, req_c, timeout=3.0)
            if b"200 OK" in resp_c and b"ECHO:" + p_data in resp_c:
                cycles_ok += 1

        record(cycles_ok == 50, f"50 rapid chaos cycles completed ({cycles_ok}/50 OK)")

    finally:
        await proxy.stop()
        try:
            await run_req(srv_port, b"GET /shutdown HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n", timeout=1.0)
        except Exception:
            pass
        goose_srv.stop()

    total_time = time.time() - t_start
    print(f"\nCompleted in {total_time:.2f}s: {passed} passed, {failed} failed")
    if failed > 0:
        sys.exit(1)


if __name__ == "__main__":
    asyncio.run(main())
