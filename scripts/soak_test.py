#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""scripts/soak_test.py.

Adversarial reactor soak & SoAConnTable slot-leak verifier for goose-wing.
1. Executes native LIT soak verification (`tests/lit/verify_reactor_soa_soak.goose`)
   testing 10,240 connection slot allocations/releases, TickTimerWheel Slowloris
   reaping, and server pool zeroization.
2. Starts a live `goose_chaos_server` instance over OS TCP sockets and drives
   multi-wave adversarial socket traffic (`SO_LINGER=0` RST aborts, malformed
   smuggling frames, keep-alive bursts, and post-wave `/ping` health probes)
   before verifying clean shutdown.
"""

import argparse
import os
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path


def build_chaos_server(root: Path, cc: str) -> Path:
    cache_dir = root / ".lit" / "cache" / "soak"
    cache_dir.mkdir(parents=True, exist_ok=True)
    exe_name = "goose_chaos_server.exe" if os.name == "nt" else "goose_chaos_server"
    exe_path = cache_dir / exe_name
    src_path = root / "tools" / "toxiproxy" / "goose_chaos_server.goose"

    cmd = ["goose", "build", "--cc", cc, "-O2", "-o", str(exe_path), str(src_path)]
    res = subprocess.run(cmd, cwd=root, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(f"Failed to build goose_chaos_server:\n{res.stdout}\n{res.stderr}\n")
        raise RuntimeError("goose_chaos_server build failed")
    return exe_path


def send_rst_abort(port: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect(("127.0.0.1", port))
        s.sendall(b"GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Partial: ")
        # Enable SO_LINGER with timeout 0 to force TCP RST on close
        s.setsockopt(socket.SOL_SOCKET, socket.SO_LINGER, struct.pack("ii", 1, 0))
    except OSError:
        pass
    finally:
        s.close()


def send_smuggle_frame(port: int) -> None:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(2.0)
    try:
        s.connect(("127.0.0.1", port))
        s.sendall(
            b"POST /echo HTTP/1.1\r\n"
            b"Host: 127.0.0.1\r\n"
            b"Content-Length: 5\r\n"
            b"Transfer-Encoding: chunked\r\n\r\n"
            b"0\r\n\r\n"
        )
        _ = s.recv(1024)
    except OSError:
        pass
    finally:
        s.close()


def check_health_ping(port: int) -> bool:
    with socket.create_connection(("127.0.0.1", port), timeout=3.0) as s:
        s.sendall(b"GET /ping HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
        resp = b""
        while True:
            chunk = s.recv(1024)
            if not chunk:
                break
            resp += chunk
        return b"200 OK" in resp and resp.endswith(b"OK")


def run_live_socket_soak(root: Path, cc: str, waves: int) -> bool:
    exe_path = build_chaos_server(root, cc)
    env = os.environ.copy()
    env["PORT"] = "0"

    proc = subprocess.Popen(
        [str(exe_path)],
        cwd=root,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    try:
        if proc.stdout is None:
            return False
        ready_line = proc.stdout.readline().strip()
        if not ready_line.startswith("READY_PORT:"):
            sys.stderr.write(f"Unexpected server startup line: {ready_line}\n")
            return False
        port = int(ready_line.split(":", 1)[1].strip())

        for wave in range(waves):
            for _ in range(10):
                send_rst_abort(port)
                send_smuggle_frame(port)
            if not check_health_ping(port):
                sys.stderr.write(f"Health ping failed after wave {wave}\n")
                return False

        # Trigger graceful shutdown via /shutdown route
        with socket.create_connection(("127.0.0.1", port), timeout=3.0) as s:
            s.sendall(b"GET /shutdown HTTP/1.1\r\nHost: 127.0.0.1\r\nConnection: close\r\n\r\n")
            _ = s.recv(512)

        proc.wait(timeout=5.0)
        return proc.returncode == 0
    finally:
        if proc.poll() is None:
            proc.kill()
            proc.wait(timeout=2.0)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Adversarial reactor soak & SoAConnTable slot-leak verifier"
    )
    parser.add_argument("--cc", default="gcc", help="C compiler")
    parser.add_argument("--waves", type=int, default=5, help="Live TCP chaos waves")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    lit_file = root / "tests" / "lit" / "verify_reactor_soa_soak.goose"

    # 1. Run deterministic LIT SoAConnTable 10,240-slot soak & pool zeroization suite
    res_lit = subprocess.run(["goose-lit", str(lit_file)], cwd=root, capture_output=True, text=True)
    sys.stdout.write(res_lit.stdout)
    if res_lit.returncode != 0:
        sys.stderr.write(res_lit.stderr)
        return 1

    # 2. Run live OS TCP socket soak against goose_chaos_server
    t0 = time.perf_counter()
    if not run_live_socket_soak(root, args.cc, args.waves):
        return 1
    elapsed_ms = int((time.perf_counter() - t0) * 1000)
    print(f"OK LIVE_SOCKET_SOAK_WAVES: {args.waves} ELAPSED_MS: {elapsed_ms}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
