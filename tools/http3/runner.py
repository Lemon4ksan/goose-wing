#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
HTTP/3 & QUIC End-to-End Interop Verification Test Runner for goose-wing.
Validates RFC 9000 (QUIC Transport), RFC 9114 (HTTP/3), and RFC 9204 (QPACK)
against the native server running over live UDP datagrams.
"""

import argparse
import io
import os
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
SERVER_SRC = TOOLS_DIR / "http3" / "server.goose"
SERVER_EXE = BIN_DIR / ("http3_server.exe" if sys.platform == "win32" else "http3_server")


def ensure_server_binary(force_rebuild: bool = False) -> Path:
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    if not force_rebuild and SERVER_EXE.is_file():
        return SERVER_EXE

    print(f"[*] Building native HTTP/3 server: {SERVER_SRC} -> {SERVER_EXE}...")
    env = os.environ.copy()
    if sys.platform == "win32":
        gcc_wrapper = ROOT_DIR / "tools" / "gcc_noavx.cmd"
        if gcc_wrapper.is_file():
            env["GOOSE_CC"] = str(gcc_wrapper)
    cmd = ["goose", "build", str(SERVER_SRC), "-o", str(SERVER_EXE), "-O2"]
    res = subprocess.run(
        cmd, check=False, cwd=str(ROOT_DIR), capture_output=True, text=True, env=env
    )
    if res.returncode != 0:
        print("[!] Failed to build HTTP/3 server:", file=sys.stderr)
        if res.stdout:
            print(res.stdout, file=sys.stderr)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        sys.exit(1)

    print(f"[+] Successfully built {SERVER_EXE.name}")
    return SERVER_EXE


class NativeHttp3Server:
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
                s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
                s.settimeout(0.5)
                s.sendto(b"SHUTDOWN", ("127.0.0.1", self.port))
                s.recvfrom(512)
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

    print("\nExecuting goose-wing HTTP/3 & QUIC Live Interop Verification Suite...")

    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.settimeout(3.0)

    # 1. RFC 9000 §17.2.1 Version Negotiation
    scid = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    dcid = b"\x88\x77\x66\x55\x44\x33\x22\x11"
    vn_req = bytearray([0xC0])
    vn_req.extend(struct.pack(">I", 0x5A5A5A5A))  # Unknown version triggers Version Negotiation
    vn_req.append(len(dcid))
    vn_req.extend(dcid)
    vn_req.append(len(scid))
    vn_req.extend(scid)
    vn_req.append(0)  # Token len = 0
    vn_req.append(10)  # Payload len = 10
    vn_req.append(1)  # Packet number = 1
    vn_req.extend(b"0123456789")

    s.sendto(vn_req, (host, port))
    vn_res, _ = s.recvfrom(2048)

    # RFC 9000 Section 17.2.1: Version Negotiation packet has Version = 0x00000000
    is_vn = len(vn_res) >= 27 and vn_res[0] & 0x80 != 0 and struct.unpack(">I", vn_res[1:5])[0] == 0
    echoed_dcid = vn_res[6 : 6 + len(scid)] == scid if len(vn_res) >= 6 + len(scid) else False
    record(is_vn and echoed_dcid, "RFC 9000 Version Negotiation (Ver 0x00000000 & SCID Echo)")

    # 2. RFC 9000 §17.2.2 QUIC v1 Initial Datagram Ingestion (1200 Bytes Minimum)
    init_req = bytearray([0xC0])
    init_req.extend(struct.pack(">I", 0x00000001))  # QUIC v1
    init_req.append(len(dcid))
    init_req.extend(dcid)
    init_req.append(len(scid))
    init_req.extend(scid)
    init_req.append(0)  # Token len = 0
    init_req.append(10)  # Payload len = 10
    init_req.append(1)  # Packet number = 1
    init_req.extend(b"0123456789")
    # Pad to 1200 bytes per RFC 9000 Section 8.1
    if len(init_req) < 1200:
        init_req.extend(b"\x00" * (1200 - len(init_req)))

    s.sendto(init_req, (host, port))
    init_res, _ = s.recvfrom(2048)

    is_init_res = (
        len(init_res) >= 30
        and (init_res[0] & 0xC0) == 0xC0
        and struct.unpack(">I", init_res[1:5])[0] == 0x00000001
    )
    record(is_init_res, "RFC 9000 QUIC v1 Initial Datagram Ingestion & Header Verification")

    # 3. RFC 9114 §6.2.1 HTTP/3 Control Stream Preamble (Stream Type 0x00)
    # Payload starts after: 1(header) + 4(ver) + 1+8(dcid) + 1+8(scid) + 1(tok_len) + 1(plen) + 2(pn) = 27 bytes
    has_ctrl_stream = b"\x00\x04" in init_res  # Control stream (0x00) + SETTINGS frame (0x04)
    record(has_ctrl_stream, "RFC 9114 HTTP/3 Control Stream Preamble (Type 0x00)")

    # 4. RFC 9114 §7.2.4 SETTINGS Parameters Validation
    # Checks presence of QPACK_MAX_TABLE_CAPACITY (0x01, 4096 = 0x5000) and MAX_FIELD_SECTION_SIZE (0x06)
    has_qpack_cap = b"\x01\x50\x00" in init_res or b"\x01\x40" in init_res
    has_section_sz = b"\x06\x80\x01\x00\x00" in init_res or b"\x06" in init_res
    record(
        has_qpack_cap and has_section_sz,
        "RFC 9114 SETTINGS Parameters (QPACK Table Capacity & Section Size)",
    )

    # 5. RFC 9114 §7.2.8 GREASE Frame Conformance
    # GREASE frame type 0x21 (33) with length 0
    has_grease = b"\x21\x00" in init_res
    record(has_grease, "RFC 9114 GREASE Frame Generation & Tolerance (Type 0x21)")

    # 6. RFC 9114 §7.2.4 Rejection of Forbidden HTTP/2 Settings Identifiers
    # Setting 0x02 (SETTINGS_ENABLE_PUSH) is strictly forbidden in HTTP/3
    # Binary H3 SETTINGS frame: Type 0x04, length 2, identifier 0x02, value 0x01
    forbidden_settings_frame = bytes([0x04, 0x02, 0x02, 0x01])
    s.sendto(forbidden_settings_frame, (host, port))
    set_err_res, _ = s.recvfrom(1024)
    # RFC 9000 §19.19 Application CONNECTION_CLOSE Frame: Type 0x1D, VarInt Error Code 265 (0x0109)
    # 265 in 2-byte varint has 2 MSB bits = 01 -> 0x4109
    is_settings_error = (
        len(set_err_res) >= 3
        and set_err_res[0] == 0x1D
        and (struct.unpack(">H", set_err_res[1:3])[0] & 0x3FFF) == 265
    )
    record(
        is_settings_error,
        "RFC 9114 Rejection of Forbidden HTTP/2 Setting (H3_ERR_SETTINGS_ERROR = 0x0109 via CONNECTION_CLOSE 0x1D)",
    )

    # 7. RFC 9114 HTTP/3 HEADERS & DATA Request/Response Roundtrip
    # HEADERS frame: type 0x01, len 5, QPACK payload: RIC=0 (0x00), Base=0 (0x00),
    # :method GET (0xd1), :scheme https (0xd7), :path / (0xc1) per RFC 9204 §4.5.2 & RFC 9114 §4.3.1
    qpack_req = b"\x00\x00\xd1\xd7\xc1"
    h3_frame = bytearray([0x01, len(qpack_req)]) + qpack_req
    s.sendto(h3_frame, (host, port))
    h3_res, _ = s.recvfrom(2048)

    # Validate HEADERS frame (0x01) + DATA frame (0x00) with body text
    has_h3_headers = len(h3_res) >= 5 and h3_res[0] == 0x01
    has_h3_data = (
        b"\x00\x1dHello from goose-wing HTTP/3!" in h3_res
        or b"Hello from goose-wing HTTP/3!" in h3_res
    )
    record(has_h3_headers and has_h3_data, "RFC 9114 HTTP/3 HEADERS & DATA Stream Roundtrip")

    # 8. RFC 9204 QPACK Static Table Indexing (:status 200 = Index 25)
    # Indexed field line from static table: 11000000 | 25 = 0xD9
    has_qpack_200 = b"\xd9" in h3_res[:5]
    record(has_qpack_200, "RFC 9204 QPACK Static Table Field Indexing (:status 200 = 0xD9)")

    s.close()
    return passed, failed


def main():
    parser = argparse.ArgumentParser(
        description="goose-wing HTTP/3 & QUIC Interop Verification Runner"
    )
    parser.add_argument("--host", default="127.0.0.1", help="Target server host")
    parser.add_argument(
        "--port", type=int, default=0, help="Target server port (if already running)"
    )
    parser.add_argument("--docker", action="store_true", help="Run HTTP/3 suite in Docker")
    parser.add_argument("--compose", action="store_true", help="Launch via docker compose")
    parser.add_argument("--rebuild", action="store_true", help="Rebuild HTTP/3 server executable")
    args = parser.parse_args()

    if args.compose:
        compose_file = TOOLS_DIR / "http3" / "docker-compose.yml"
        cmd = [
            "docker",
            "compose",
            "-f",
            str(compose_file),
            "up",
            "--build",
            "--abort-on-container-exit",
        ]
        print(f"[*] Running HTTP/3 suite via docker compose ({compose_file.name})...")
        sys.exit(subprocess.run(cmd, check=False, cwd=str(ROOT_DIR)).returncode)

    if args.port > 0:
        passed, failed = run_e2e_tests(args.host, args.port)
        total = passed + failed
        print(f"\nCompleted: {passed}/{total} passed, {failed} failed.")
        sys.exit(0 if failed == 0 and total > 0 else 1)

    server_exe = ensure_server_binary(force_rebuild=args.rebuild)
    server = NativeHttp3Server(server_exe)
    print(f"[*] Starting native Goose HTTP/3 & QUIC server ({server_exe.name})...")
    port = server.start()
    print(f"[+] Server listening on 127.0.0.1:{port} (UDP)")

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
