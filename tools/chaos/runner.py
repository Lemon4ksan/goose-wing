#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
goose-wing Network Chaos & TCP Micro-Slicing E2E Verification Runner.
Exercises serve_reactor under TCP packet fragmentation, micro-slicing,
slowloris drips, boundary splits, and pipelining across MTU boundaries.
"""

import argparse
import io
import socket
import subprocess
import sys
import threading
import time
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if (
    isinstance(sys.stdout, io.TextIOWrapper)
    and sys.stdout.encoding
    and sys.stdout.encoding.lower() != "utf-8"
):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if (
    isinstance(sys.stderr, io.TextIOWrapper)
    and sys.stderr.encoding
    and sys.stderr.encoding.lower() != "utf-8"
):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = ROOT_DIR / "tools"
BIN_DIR = TOOLS_DIR / "bin"
SERVER_SRC = TOOLS_DIR / "chaos" / "server.goose"
SERVER_EXE = BIN_DIR / ("chaos_server.exe" if sys.platform == "win32" else "chaos_server")


def ensure_server_binary(force_rebuild: bool = False) -> Path:
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    if not force_rebuild and SERVER_EXE.is_file():
        return SERVER_EXE

    print(f"[*] Building native Chaos Reactor server: {SERVER_SRC} -> {SERVER_EXE}...")
    cmd = ["goose", "build", str(SERVER_SRC), "-o", str(SERVER_EXE), "-O2"]
    res = subprocess.run(cmd, check=False, cwd=str(ROOT_DIR), capture_output=True, text=True)
    if res.returncode != 0:
        print("[!] Failed to build Chaos server:", file=sys.stderr)
        if res.stdout:
            print(res.stdout, file=sys.stderr)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        sys.exit(1)

    print(f"[+] Successfully built {SERVER_EXE.name}")
    return SERVER_EXE


class NativeChaosServer:
    def __init__(self, binary_path: Path):
        self.binary_path = binary_path
        self.proc: subprocess.Popen | None = None
        self.port: int = 0

    def start(self, timeout: float = 5.0) -> int:
        self.proc = subprocess.Popen(
            [str(self.binary_path)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
            cwd=str(ROOT_DIR),
        )
        assert self.proc and self.proc.stdout and self.proc.stderr

        t_start = time.time()
        while time.time() - t_start < timeout:
            line = self.proc.stdout.readline()
            if "READY_PORT:" in line:
                self.port = int(line.strip().split("READY_PORT:")[1])
                return self.port
            if self.proc.poll() is not None:
                err = self.proc.stderr.read()
                raise RuntimeError(
                    f"Server exited immediately with code {self.proc.returncode}: {err}"
                )
            time.sleep(0.02)

        self.stop()
        raise TimeoutError(f"Server did not print READY_PORT within {timeout}s")

    def stop(self):
        if not self.proc:
            return

        if self.port > 0:
            try:
                s = socket.socket()
                s.settimeout(0.5)
                s.connect(("127.0.0.1", self.port))
                s.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
                s.close()
            except Exception:
                pass

        try:
            self.proc.terminate()
            self.proc.wait(timeout=1.0)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        self.proc = None


def recv_all(s: socket.socket, timeout: float = 3.0) -> bytes:
    s.settimeout(timeout)
    buf = bytearray()
    try:
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            buf.extend(chunk)
            if b"\r\n\r\n" in buf and b"Content-Length:" not in buf:
                break
            if b"Content-Length:" in buf:
                # check if body reached
                hdr_end = buf.find(b"\r\n\r\n")
                if hdr_end >= 0:
                    headers = buf[:hdr_end].decode("latin1", errors="replace")
                    for h in headers.split("\r\n"):
                        if h.lower().startswith("content-length:"):
                            try:
                                cl = int(h.split(":")[1].strip())
                                if len(buf) >= hdr_end + 4 + cl:
                                    return bytes(buf)
                            except ValueError:
                                pass
    except TimeoutError:
        pass
    return bytes(buf)


# -----------------------------------------------------------------------------
# Test Cases
# -----------------------------------------------------------------------------


def test_1byte_micro_slicing(host: str, port: int):
    """Slices a GET request into 1-byte TCP packets with inter-byte delays."""
    req = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    s = socket.socket()
    s.settimeout(4.0)
    s.connect((host, port))
    try:
        for b in req:
            s.sendall(bytes([b]))
            time.sleep(0.002)

        resp = recv_all(s, timeout=3.0)
        assert b"200 OK" in resp, f"Expected 200 OK, got: {resp[:128]!r}"
    finally:
        s.close()


def test_boundary_split_headers(host: str, port: int):
    """Splits request across method, path, and CRLF delimiter boundaries."""
    chunks = [
        b"GET /",
        b" HTTP/1.1\r\n",
        b"Host: 127.0.0.1\r\n",
        b"X-Custom-Chunk: alpha-beta\r\n",
        b"Connection: close\r\n",
        b"\r\n",
    ]
    s = socket.socket()
    s.settimeout(4.0)
    s.connect((host, port))
    try:
        for chunk in chunks:
            s.sendall(chunk)
            time.sleep(0.01)

        resp = recv_all(s, timeout=3.0)
        assert b"200 OK" in resp, f"Expected 200 OK, got: {resp[:128]!r}"
    finally:
        s.close()


def test_pipelined_split_across_boundary(host: str, port: int):
    """Sends 3 pipelined HTTP requests sliced into irregular chunks across MTU boundaries."""
    req1 = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    req2 = b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n"
    req3 = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
    payload = req1 + req2 + req3

    # Slice into irregular chunk sizes: 17, 29, 31, 13, etc.
    chunk_sizes = [17, 29, 31, 13, 23, 19, 41]
    s = socket.socket()
    s.settimeout(4.0)
    s.connect((host, port))
    try:
        idx = 0
        c_i = 0
        while idx < len(payload):
            sz = chunk_sizes[c_i % len(chunk_sizes)]
            c_i += 1
            chunk = payload[idx : idx + sz]
            s.sendall(chunk)
            idx += sz
            time.sleep(0.005)

        resp = recv_all(s, timeout=3.0)
        count_200 = resp.count(b"200 OK")
        assert count_200 == 3, (
            f"Expected 3 pipelined 200 OK responses, got {count_200} in: {resp!r}"
        )
    finally:
        s.close()


def test_post_body_slicing(host: str, port: int):
    """Sends POST request with headers in chunk 1, and body fragmented across subsequent chunks."""
    body = b"ChaosPayload_1234567890_ABCDEFGHIJ_!@#$%^&*()_BodySliceVerification"
    headers = f"POST /echo HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode(
        "latin1"
    )

    s = socket.socket()
    s.settimeout(4.0)
    s.connect((host, port))
    try:
        # Send headers
        s.sendall(headers)
        time.sleep(0.02)

        # Send body in 3 fragments
        part1 = body[:20]
        part2 = body[20:45]
        part3 = body[45:]

        s.sendall(part1)
        time.sleep(0.01)
        s.sendall(part2)
        time.sleep(0.01)
        s.sendall(part3)

        resp = recv_all(s, timeout=3.0)
        assert b"200 OK" in resp, f"Expected 200 OK for POST body slicing, got: {resp[:128]!r}"
    finally:
        s.close()


def test_trailing_poison_extra_bytes(host: str, port: int):
    """Sends trailing poison bytes after Content-Length to verify smuggling rejection."""
    poison_stream = (
        b"POST /echo HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Content-Length: 5\r\n"
        b"\r\n"
        b"HELLOPOISON_EXTRA_BYTES_LINGERING"
    )
    s = socket.socket()
    s.settimeout(3.0)
    s.connect((host, port))
    try:
        s.sendall(poison_stream)
        resp = recv_all(s, timeout=2.0)
        # Server must either emit 400 Bad Request or immediately close connection
        is_rejected = (
            (b"400 Bad Request" in resp) or (len(resp) == 0) or (b"Connection: close" in resp)
        )
        assert is_rejected, f"Trailing poison bytes must be rejected, got: {resp!r}"
    finally:
        s.close()


def test_header_overflow_protection(host: str, port: int):
    """Sends header block exceeding 8192 bytes; verifies 400 Bad Request rejection."""
    oversized = b"GET / HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Junk: " + (b"A" * 9000) + b"\r\n\r\n"
    s = socket.socket()
    s.settimeout(3.0)
    s.connect((host, port))
    try:
        s.sendall(oversized)
        resp = recv_all(s, timeout=2.0)
        is_rejected = (b"400 Bad Request" in resp) or (len(resp) == 0)
        assert is_rejected, f"Oversized header block > 8KB must be rejected, got: {resp[:128]!r}"
    finally:
        s.close()


def test_slowloris_drip(host: str, port: int):
    """Sends headers slowly one line at a time to test drip resilience without timing out."""
    s = socket.socket()
    s.settimeout(4.0)
    s.connect((host, port))
    try:
        lines = [
            b"GET /health HTTP/1.1\r\n",
            b"Host: 127.0.0.1\r\n",
            b"X-Drip-1: alpha\r\n",
            b"X-Drip-2: beta\r\n",
            b"Connection: close\r\n",
            b"\r\n",
        ]
        for line in lines:
            s.sendall(line)
            time.sleep(0.03)

        resp = recv_all(s, timeout=3.0)
        assert b"200 OK" in resp, f"Expected 200 OK after slowloris drip, got: {resp[:128]!r}"
    finally:
        s.close()


def test_concurrent_chaos_blast(host: str, port: int):
    """Launches 10 parallel threads each sending 1-byte sliced requests simultaneously."""
    errors = []

    def worker(worker_id: int):
        try:
            req = f"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Worker: {worker_id}\r\nConnection: close\r\n\r\n".encode(
                "latin1"
            )
            s = socket.socket()
            s.settimeout(4.0)
            s.connect((host, port))
            try:
                for b in req:
                    s.sendall(bytes([b]))
                    time.sleep(0.001)
                resp = recv_all(s, timeout=3.0)
                if b"200 OK" not in resp:
                    errors.append(f"Worker {worker_id} expected 200 OK, got: {resp[:64]!r}")
            finally:
                s.close()
        except Exception as e:
            errors.append(f"Worker {worker_id} raised: {e}")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(10)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()

    assert not errors, f"Concurrent chaos blast encountered errors: {errors}"


def test_payload_too_large_413(host: str, port: int):
    """Sends Content-Length exceeding 10MB limit; verifies 413 Payload Too Large response."""
    oversized_req = (
        b"POST /echo HTTP/1.1\r\n"
        b"Host: 127.0.0.1\r\n"
        b"Content-Length: 20971520\r\n"
        b"Connection: close\r\n\r\n"
    )
    s = socket.socket()
    s.settimeout(3.0)
    s.connect((host, port))
    try:
        s.sendall(oversized_req)
        resp = recv_all(s, timeout=2.0)
        assert b"413 Payload Too Large" in resp, (
            f"Expected 413 Payload Too Large, got: {resp[:128]!r}"
        )
    finally:
        s.close()


def test_slowloris_slot_starvation_eviction(host: str, port: int):
    """Tests that active clients are never locked out when slowloris clients idle."""
    slow_sockets = []
    try:
        for _ in range(10):
            sock = socket.socket()
            sock.settimeout(4.0)
            sock.connect((host, port))
            sock.sendall(b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Stale: 1")
            slow_sockets.append(sock)

        active_s = socket.socket()
        active_s.settimeout(4.0)
        active_s.connect((host, port))
        try:
            active_s.sendall(
                b"GET /health HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n"
            )
            resp = recv_all(active_s, timeout=3.0)
            assert b"200 OK" in resp, (
                f"Active client must receive 200 OK despite idle slowloris sockets, got: {resp[:128]!r}"
            )
        finally:
            active_s.close()
    finally:
        for sock in slow_sockets:
            try:
                sock.close()
            except Exception:
                pass


TEST_CASES = [
    ("1-Byte Micro-Slicing Ingress", test_1byte_micro_slicing),
    ("Header Boundary & CRLF Slicing", test_boundary_split_headers),
    ("Pipelining Split Across MTU Boundaries", test_pipelined_split_across_boundary),
    ("POST Request Body Slicing", test_post_body_slicing),
    ("Trailing Poison Extra Bytes Defense", test_trailing_poison_extra_bytes),
    ("Header Overflow > 8KB Protection", test_header_overflow_protection),
    ("Slowloris Progressive Header Drip", test_slowloris_drip),
    ("Slowloris Slot Starvation Eviction", test_slowloris_slot_starvation_eviction),
    ("Payload Too Large 413 Defense (> 10MB)", test_payload_too_large_413),
    ("Concurrent Chaos Blast (10 Threads)", test_concurrent_chaos_blast),
]


def run_all_tests(host: str, port: int) -> bool:
    print(f"[*] Targeting Chaos Reactor at {host}:{port}")
    passed = 0
    failed = 0
    total = len(TEST_CASES)
    t0 = time.time()

    for i, (name, func) in enumerate(TEST_CASES, start=1):
        case_t0 = time.time()
        try:
            func(host, port)
            dt_ms = (time.time() - case_t0) * 1000
            print(f"  [PASS] {i}. {name} ({dt_ms:.1f} ms)")
            passed += 1
        except Exception as exc:
            dt_ms = (time.time() - case_t0) * 1000
            print(f"  [FAIL] {i}. {name} ({dt_ms:.1f} ms): {exc}")
            failed += 1

    total_time_ms = (time.time() - t0) * 1000
    print("-" * 76)
    print(
        f"SUITE: Network Chaos & TCP Slicing | PASS: {passed}/{total} | FAIL: {failed} | TIME: {total_time_ms:.1f} ms"
    )
    print("-" * 76)
    return failed == 0


def main():
    parser = argparse.ArgumentParser(description="goose-wing Network Chaos Test Runner")
    parser.add_argument("--host", default=None, help="Server host (if targeting existing server)")
    parser.add_argument(
        "--port", type=int, default=0, help="Server port (if targeting existing server)"
    )
    parser.add_argument(
        "--build", action="store_true", help="Force rebuild of native server binary"
    )
    args = parser.parse_args()

    if args.host and args.port:
        ok = run_all_tests(args.host, args.port)
        sys.exit(0 if ok else 1)

    bin_path = ensure_server_binary(force_rebuild=args.build)
    server = NativeChaosServer(bin_path)

    try:
        port = server.start()
        print(f"[+] Chaos server listening on port {port}")
        ok = run_all_tests("127.0.0.1", port)
        sys.exit(0 if ok else 1)
    finally:
        server.stop()


if __name__ == "__main__":
    main()
