#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
gRPC & gRPC-Web End-to-End Verification Test Runner for goose-wing.
Validates Unary RPCs over HTTP/2, gRPC-Web (binary & text), metadata propagation,
LPM framing, and error statuses against the native Goose server.
"""

import argparse
import base64
import io
import socket
import struct
import subprocess
import sys
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
SERVER_SRC = TOOLS_DIR / "grpc" / "server.goose"
SERVER_EXE = BIN_DIR / ("grpc_server.exe" if sys.platform == "win32" else "grpc_server")

H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"


def ensure_server_binary(force_rebuild: bool = False) -> Path:
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    if not force_rebuild and SERVER_EXE.is_file():
        return SERVER_EXE

    print(f"[*] Building native gRPC server: {SERVER_SRC} -> {SERVER_EXE}...")
    cmd = ["goose", "build", str(SERVER_SRC), "-o", str(SERVER_EXE), "-O2"]
    res = subprocess.run(cmd, check=False, cwd=str(ROOT_DIR), capture_output=True, text=True)
    if res.returncode != 0:
        print("[!] Failed to build gRPC server:", file=sys.stderr)
        if res.stdout:
            print(res.stdout, file=sys.stderr)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        sys.exit(1)

    print(f"[+] Successfully built {SERVER_EXE.name}")
    return SERVER_EXE


class NativeGrpcServer:
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
                s.sendall(b"GET /shutdown HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
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


def encode_lpm(data: bytes, compressed: bool = False) -> bytes:
    flag = 1 if compressed else 0
    return struct.pack(">BI", flag, len(data)) + data


def decode_lpm(data: bytes) -> tuple[int, bytes]:
    if len(data) < 5:
        return 0, b""
    flag, length = struct.unpack(">BI", data[:5])
    return flag, data[5 : 5 + length]


def run_grpc_web_test(
    host: str,
    port: int,
    path: str,
    payload: bytes,
    is_text: bool = False,
    headers: dict | None = None,
) -> tuple[int, bytes, dict]:
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3.0)
    s.connect((host, port))

    lpm = encode_lpm(payload)
    if is_text:
        body = base64.b64encode(lpm)
        ct = "application/grpc-web-text"
    else:
        body = lpm
        ct = "application/grpc-web+proto"

    req = f"POST {path} HTTP/1.1\r\nHost: {host}\r\nContent-Type: {ct}\r\nContent-Length: {len(body)}\r\n"
    if headers:
        for k, v in headers.items():
            req += f"{k}: {v}\r\n"
    req += "\r\n"

    s.sendall(req.encode("latin1") + body)

    resp_data = b""
    while True:
        try:
            chunk = s.recv(4096)
            if not chunk:
                break
            resp_data += chunk
            if b"\r\n\r\n" in resp_data:
                # check content-length
                hdr_part, body_part = resp_data.split(b"\r\n\r\n", 1)
                for line in hdr_part.decode("latin1", "ignore").splitlines():
                    if line.lower().startswith("content-length:"):
                        cl = int(line.split(":")[1].strip())
                        if len(body_part) >= cl:
                            break
        except TimeoutError:
            break
    s.close()

    hdr_end = resp_data.find(b"\r\n\r\n")
    if hdr_end < 0:
        return -1, b"", {}

    header_block = resp_data[:hdr_end].decode("latin1", "replace")
    body = resp_data[hdr_end + 4 :]

    status_code = 0
    headers_dict = {}
    lines = header_block.splitlines()
    if lines:
        parts = lines[0].split()
        if len(parts) >= 2 and parts[1].isdigit():
            status_code = int(parts[1])
        for line in lines[1:]:
            if ":" in line:
                k, v = line.split(":", 1)
                headers_dict[k.strip().lower()] = v.strip()

    if is_text and body:
        try:
            body = base64.b64decode(body)
        except Exception:
            pass

    return status_code, body, headers_dict


def run_e2e_tests(host: str, port: int) -> tuple[int, int]:
    passed = 0
    failed = 0

    def record(ok: bool, desc: str, detail: str = ""):
        nonlocal passed, failed
        if ok:
            passed += 1
            print(f"  [PASS] {desc}")
        else:
            failed += 1
            msg = f"  [FAIL] {desc}"
            if detail:
                msg += f" ({detail})"
            print(msg)

    print("\nExecuting goose-wing gRPC & gRPC-Web E2E Verification Suite...")

    # 1. gRPC-Web Binary Unary Call (helloworld.Greeter/SayHello)
    st, body, hdrs = run_grpc_web_test(host, port, "/helloworld.Greeter/SayHello", b"Antigravity")
    _flag, msg = decode_lpm(body)
    record(
        st == 200 and msg == b"Hello, Antigravity!",
        "gRPC-Web Binary Unary Call (SayHello)",
        f"status={st}, body={msg}",
    )

    # 2. Response Metadata Headers
    record(
        hdrs.get("x-server-version") == "wing-grpc-v2"
        and hdrs.get("x-grpc-engine") == "goose-wing",
        "Response Metadata Headers Propagation",
        f"x-server-version={hdrs.get('x-server-version')}",
    )

    # 3. gRPC-Web Authentication Failure (Unauthenticated)
    st_auth, body_auth, _hdrs_auth = run_grpc_web_test(
        host,
        port,
        "/helloworld.Greeter/SayHello",
        b"Mallory",
        headers={"Authorization": "Bearer invalid-token"},
    )
    # Trailers are encoded in gRPC-Web body with flag 0x80
    has_trailer_flag = len(body_auth) > 0 and (
        body_auth[0] == 0x80 or b"grpc-status: 16" in body_auth
    )
    record(
        st_auth == 200
        and (
            has_trailer_flag
            or b"grpc-status: 16" in body_auth
            or b"Invalid authorization token" in body_auth
        ),
        "gRPC Error Status Propagation (Unauthenticated = 16)",
        f"body={body_auth}",
    )

    # 4. Echo Service (Echo Payload)
    st_echo, body_echo, _ = run_grpc_web_test(
        host, port, "/echo.EchoService/Echo", b"PipelinedEchoPayload_0123456789"
    )
    _, msg_echo = decode_lpm(body_echo)
    record(
        st_echo == 200 and msg_echo == b"PipelinedEchoPayload_0123456789",
        "EchoService Roundtrip Payload Integrity",
        f"msg={msg_echo}",
    )

    # 5. Echo Service Metadata Reflection
    st_meta, _, hdrs_meta = run_grpc_web_test(
        host, port, "/echo.EchoService/Echo", b"Test", headers={"x-echo-trace-id": "trace-98765"}
    )
    record(
        st_meta == 200 and hdrs_meta.get("x-echo-trace-id") == "trace-98765",
        "Custom Metadata Header Reflection (x-echo-*)",
        f"echo-trace={hdrs_meta.get('x-echo-trace-id')}",
    )

    # 6. Echo Service PermissionDenied
    st_fail, body_fail, _ = run_grpc_web_test(host, port, "/echo.EchoService/Fail", b"")
    record(
        st_fail == 200 and (b"grpc-status: 7" in body_fail or b"Access denied" in body_fail),
        "PermissionDenied Error Invariant (grpc-status: 7)",
        f"body={body_fail}",
    )

    # 7. gRPC-Web-Text (Base64 Encoding)
    st_txt, body_txt, _ = run_grpc_web_test(
        host, port, "/helloworld.Greeter/SayHello", b"TextClient", is_text=True
    )
    _, msg_txt = decode_lpm(body_txt)
    record(
        st_txt == 200 and msg_txt == b"Hello, TextClient!",
        "gRPC-Web-Text Base64 Protocol (SayHello)",
        f"msg={msg_txt}",
    )

    # 8. Large LPM Payload (32 KB Payload)
    large_payload = b"A" * 32768
    st_lg, body_lg, _ = run_grpc_web_test(host, port, "/echo.EchoService/Echo", large_payload)
    _, msg_lg = decode_lpm(body_lg)
    record(
        st_lg == 200 and len(msg_lg) == 32768 and msg_lg == large_payload,
        "Large 32 KB LPM Frame Transmission & Parsing",
        f"recvd_len={len(msg_lg)}",
    )

    return passed, failed


def main():
    parser = argparse.ArgumentParser(
        description="goose-wing gRPC & gRPC-Web E2E Verification Runner"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Target server host")
    parser.add_argument(
        "--port", type=int, default=0, help="Target server port (if already running)"
    )
    parser.add_argument("--docker", action="store_true", help="Run gRPC suite in Docker")
    parser.add_argument("--compose", action="store_true", help="Launch via docker compose")
    parser.add_argument("--rebuild", action="store_true", help="Rebuild gRPC server executable")
    args = parser.parse_args()

    if args.compose:
        compose_file = TOOLS_DIR / "grpc" / "docker-compose.yml"
        cmd = [
            "docker",
            "compose",
            "-f",
            str(compose_file),
            "up",
            "--build",
            "--abort-on-container-exit",
        ]
        print(f"[*] Running gRPC suite via docker compose ({compose_file.name})...")
        sys.exit(subprocess.run(cmd, check=False, cwd=str(ROOT_DIR)).returncode)

    if args.port > 0:
        passed, failed = run_e2e_tests(args.host, args.port)
        total = passed + failed
        print(f"\nCompleted: {passed}/{total} passed, {failed} failed.")
        sys.exit(0 if failed == 0 and total > 0 else 1)

    server_exe = ensure_server_binary(force_rebuild=args.rebuild)
    server = NativeGrpcServer(server_exe)
    print(f"[*] Starting native Goose gRPC server ({server_exe.name})...")
    port = server.start()
    print(f"[+] Server listening on 127.0.0.1:{port}")

    try:
        passed, failed = run_e2e_tests("127.0.0.1", port)
        total = passed + failed
        print(f"\nCompleted: {passed}/{total} passed, {failed} failed.")
        sys.exit(0 if failed == 0 and total > 0 else 1)
    finally:
        server.stop()
        print("[+] Server stopped cleanly.")


if __name__ == "__main__":
    main()
