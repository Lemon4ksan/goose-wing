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


def hpack_lit(name_idx: int, value: bytes) -> bytes:
    # Literal Header Field without Indexing, indexed name (RFC 7541 6.2.2)
    return bytes([name_idx & 0x0F, len(value)]) + value


def h2_req_block(method: str, path: bytes) -> bytes:
    m = b"\x82" if method == "GET" else b"\x83"  # :method GET / POST
    return m + b"\x86" + hpack_lit(4, path) + hpack_lit(1, b"127.0.0.1")  # :scheme http, :path, :authority


async def h2_open(port: int, timeout: float = 5.0):
    r, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), timeout=timeout)
    w.write(H2_PREFACE + h2_frame(0x4, 0x0, 0))
    await w.drain()
    got_settings = got_ack = False
    while not (got_settings and got_ack):
        ft, fl, sid, _ = await asyncio.wait_for(read_h2(r), timeout=timeout)
        if ft == 0x4 and not (fl & 0x1):
            got_settings = True
            w.write(h2_frame(0x4, 0x1, 0))
            await w.drain()
        elif ft == 0x4 and (fl & 0x1):
            got_ack = True
    return r, w


async def h2_wait_goaway(r: asyncio.StreamReader, timeout: float = 5.0) -> int:
    # Returns GOAWAY error code, -1 on clean EOF without GOAWAY, -2 on timeout
    try:
        while True:
            ft, _, _, p = await asyncio.wait_for(read_h2(r), timeout=timeout)
            if ft == 0x7 and len(p) >= 8:
                return struct.unpack("!I", p[4:8])[0]
    except asyncio.IncompleteReadError:
        return -1
    except (asyncio.TimeoutError, ConnectionError):
        return -2


async def close_w(w: asyncio.StreamWriter):
    try:
        w.close()
        await w.wait_closed()
    except Exception:
        pass


async def ws_open(port: int, timeout: float = 5.0):
    r, w = await asyncio.wait_for(asyncio.open_connection("127.0.0.1", port), timeout=timeout)
    key = base64.b64encode(os.urandom(16))
    w.write(
        b"GET /ws HTTP/1.1\r\nHost: 127.0.0.1\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n"
        b"Sec-WebSocket-Key: " + key + b"\r\nSec-WebSocket-Version: 13\r\n\r\n"
    )
    await w.drain()
    head = await asyncio.wait_for(r.readuntil(b"\r\n\r\n"), timeout=timeout)
    expect = base64.b64encode(hashlib.sha1(key + WS_GUID).digest())
    ok = b"101" in head.split(b"\r\n")[0] and expect in head
    return r, w, ok


async def ws_read(r: asyncio.StreamReader, timeout: float = 5.0) -> tuple[int, bytes]:
    h = await asyncio.wait_for(r.readexactly(2), timeout=timeout)
    op, ln = h[0] & 0x0F, h[1] & 0x7F
    if ln == 126:
        ln = struct.unpack("!H", await r.readexactly(2))[0]
    elif ln == 127:
        ln = struct.unpack("!Q", await r.readexactly(8))[0]
    return op, (await r.readexactly(ln) if ln else b"")


async def ws_close_code(r: asyncio.StreamReader, timeout: float = 5.0) -> int:
    try:
        while True:
            op, p = await ws_read(r, timeout)
            if op == 0x8:
                return struct.unpack("!H", p[:2])[0] if len(p) >= 2 else 1005
    except Exception:
        return -1


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

        proxy.clear_toxics()
        proxy.add_toxic(SlicerToxic("s4", min_bytes=1, max_bytes=4, delay_ms=1, stream="upstream"))
        chunked = (
            b"POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nTransfer-Encoding: chunked\r\nConnection: close\r\n\r\n"
            b"5\r\nGoose\r\n6\r\n-Wing!\r\n0\r\n\r\n"
        )
        res = await run_req(proxy_port, chunked, timeout=8.0)
        record(b"200 OK" in res and b"ECHO:Goose-Wing!" in res, "Chunked transfer decoding under Slicer", res[:60])

        proxy.clear_toxics()
        dup_cl = b"POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\nContent-Length: 9\r\n\r\nABCDEFGHI"
        res = await run_req(proxy_port, dup_cl, timeout=3.0)
        record(b"400" in res.split(b"\r\n")[0], "Conflicting duplicate Content-Length rejected (request smuggling)", res[:60])

        huge = b"GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Big: " + b"A" * 70000 + b"\r\n\r\n"
        res = await run_req(proxy_port, huge, timeout=5.0)
        record(b"200 OK" not in res, "70 KB header block refused (64 KB header limit)", res[:60])

        t0 = time.time()
        r, w = await asyncio.open_connection("127.0.0.1", proxy_port)
        w.write(b"GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Slow: a")
        await w.drain()
        try:
            got = await asyncio.wait_for(r.read(1024), timeout=10.0)
            closed = got == b"" or b"200 OK" not in got
        except asyncio.TimeoutError:
            closed = False
        await close_w(w)
        record(closed, f"Slowloris stalled headers dropped by server ({time.time() - t0:.1f}s)")

        # SECTION 2: HTTP/2 Protocol & CVE Shields (native Goose h2_multiplexer)
        print("\n2. HTTP/2 Framing, Multiplexing & CVE Defense")
        proxy.clear_toxics()
        proxy.add_toxic(SlicerToxic("h2s", min_bytes=1, max_bytes=3, delay_ms=1, stream="both"))
        try:
            r, w = await h2_open(proxy_port, timeout=8.0)
            record(True, "24-byte Preface & SETTINGS exchange under Slicer")
            w.write(h2_frame(0x1, 0x5, 1, h2_req_block("GET", b"/ping")))
            w.write(h2_frame(0x1, 0x5, 3, h2_req_block("GET", b"/ping")))
            await w.drain()
            seen = set()
            while seen != {1, 3}:
                ft, _, sid, _ = await asyncio.wait_for(read_h2(r), timeout=8.0)
                if ft == 0x1:
                    seen.add(sid)
            record(True, "Stream multiplexing (Streams 1 & 3) under Slicer")
            await close_w(w)
        except Exception as e:
            record(False, "HTTP/2 handshake + multiplexing under Slicer", repr(e))

        proxy.clear_toxics()
        try:
            r, w = await h2_open(proxy_port)
            w.write(h2_frame(0x6, 0x0, 0, b"GOOSEPNG"))
            await w.drain()
            ack = None
            while ack is None:
                ft, fl, _, p = await asyncio.wait_for(read_h2(r), timeout=5.0)
                if ft == 0x6 and (fl & 0x1):
                    ack = p
            record(ack == b"GOOSEPNG", "PING -> PING ACK with identical opaque data")
            await close_w(w)
        except Exception as e:
            record(False, "PING -> PING ACK with identical opaque data", repr(e))

        try:
            r, w = await h2_open(proxy_port)
            burst = bytearray()
            for i in range(1100):
                sid = 1 + 2 * i
                burst += h2_frame(0x1, 0x4, sid, h2_req_block("GET", b"/ping"))
                burst += h2_frame(0x3, 0x0, sid, struct.pack("!I", 0x8))
            w.write(bytes(burst))
            await w.drain()
            code = await h2_wait_goaway(r, timeout=8.0)
            record(code == 0xB, "Rapid Reset flood -> GOAWAY ENHANCE_YOUR_CALM (CVE-2023-44487)", f"code={code}")
            await close_w(w)
        except Exception as e:
            record(False, "Rapid Reset flood (CVE-2023-44487)", repr(e))

        try:
            r, w = await h2_open(proxy_port)
            flood = h2_frame(0x1, 0x0, 1, h2_req_block("GET", b"/ping"))
            flood += b"".join(h2_frame(0x9, 0x0, 1) for _ in range(64))
            w.write(flood)
            await w.drain()
            code = await h2_wait_goaway(r)
            record(code == 0x1, "Zero-length CONTINUATION -> instant GOAWAY PROTOCOL_ERROR (CVE-2024-2758)", f"code={code}")
            await close_w(w)
        except Exception as e:
            record(False, "Zero-length CONTINUATION (CVE-2024-2758)", repr(e))

        try:
            r, w = await h2_open(proxy_port)
            flood = h2_frame(0x1, 0x0, 1, h2_req_block("GET", b"/ping"))
            flood += b"".join(h2_frame(0x9, 0x0, 1, b"\x00") for _ in range(64))
            w.write(flood)
            await w.drain()
            code = await h2_wait_goaway(r)
            record(code == 0xB, "CONTINUATION flood > 16 frames -> GOAWAY ENHANCE_YOUR_CALM (CVE-2024-27983)", f"code={code}")
            await close_w(w)
        except Exception as e:
            record(False, "CONTINUATION flood (CVE-2024-27983)", repr(e))

        try:
            r, w = await h2_open(proxy_port)
            w.write(b"".join(h2_frame(0x6, 0x0, 0, struct.pack("!Q", i)) for i in range(200)))
            await w.drain()
            code = await h2_wait_goaway(r)
            record(code == 0xB, "PING control-frame flood -> GOAWAY (CVE-2019-9512)", f"code={code}")
            await close_w(w)
        except Exception as e:
            record(False, "PING control-frame flood (CVE-2019-9512)", repr(e))

        # SECTION 3: WebSocket RFC 6455 (native Goose realtime/websocket)
        print("\n3. WebSocket RFC 6455 Framing & Invariants")
        proxy.clear_toxics()
        proxy.add_toxic(SlicerToxic("wss", min_bytes=1, max_bytes=3, delay_ms=1, stream="both"))
        try:
            r, w, hs_ok = await ws_open(proxy_port, timeout=8.0)
            record(hs_ok, "101 Switching Protocols + valid Sec-WebSocket-Accept under Slicer")
            w.write(ws_frame(0x1, "Привет, Goose!".encode()))
            await w.drain()
            op, p = await ws_read(r, timeout=8.0)
            record(op == 0x1 and p == "Привет, Goose!".encode(), "Masked UTF-8 text echo under Slicer")
            blob = os.urandom(3000)
            w.write(ws_frame(0x2, blob))
            await w.drain()
            op, p = await ws_read(r, timeout=8.0)
            record(op == 0x2 and p == blob, "3000-byte binary echo (16-bit length) under Slicer")
            w.write(ws_frame(0x9, b"hb"))
            await w.drain()
            op, p = await ws_read(r, timeout=8.0)
            record(op == 0xA and p == b"hb", "Ping -> Pong with identical payload")
            await close_w(w)
        except Exception as e:
            record(False, "WebSocket echo/ping under Slicer", repr(e))
        proxy.clear_toxics()

        ws_attacks = [
            (ws_frame(0x1, b"UnmaskedData", masked=False), 1002, "Unmasked client frame rejected (Close 1002)"),
            (ws_frame(0x9, b"FragPing", fin=False), 1002, "Fragmented control frame rejected (Close 1002)"),
            (ws_frame(0x9, b"P" * 126), 1002, "Control frame payload > 125 rejected (Close 1002)"),
            (ws_frame(0x1, b"rsv", rsv=0x4), 1002, "RSV1 bit without extension rejected (Close 1002)"),
            (ws_frame(0x1, b"\xCE\xBA\xE1\x00\xFF"), 1007, "Invalid UTF-8 text rejected (Close 1007)"),
        ]
        for frame, want, desc in ws_attacks:
            try:
                r, w, _ = await ws_open(proxy_port)
                w.write(frame)
                await w.drain()
                code = await ws_close_code(r)
                record(code == want, desc, f"code={code}")
                await close_w(w)
            except Exception as e:
                record(False, desc, repr(e))

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
