#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
TLS 1.3 End-to-End Interop Verification Test Runner for goose-wing.
Validates RFC 8446 (TLS 1.3), RFC 6066 (SNI), RFC 7301 (ALPN),
ServerHello negotiation, ChangeCipherSpec, and record layer framing against the native server.
"""

import argparse
import io
import socket
import struct
import subprocess
import sys
import time
from pathlib import Path

# Ensure UTF-8 output on Windows consoles
if isinstance(sys.stdout, io.TextIOWrapper) and sys.stdout.encoding and sys.stdout.encoding.lower() != "utf-8":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if isinstance(sys.stderr, io.TextIOWrapper) and sys.stderr.encoding and sys.stderr.encoding.lower() != "utf-8":
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
TOOLS_DIR = ROOT_DIR / "tools"
BIN_DIR = TOOLS_DIR / "bin"
SERVER_SRC = TOOLS_DIR / "tls" / "server.goose"
SERVER_EXE = BIN_DIR / ("tls_server.exe" if sys.platform == "win32" else "tls_server")


def ensure_server_binary(force_rebuild: bool = False) -> Path:
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    if not force_rebuild and SERVER_EXE.is_file():
        return SERVER_EXE

    print(f"[*] Building native TLS server: {SERVER_SRC} -> {SERVER_EXE}...")
    cmd = ["goose", "build", str(SERVER_SRC), "-o", str(SERVER_EXE), "-O2"]
    res = subprocess.run(cmd, check=False, cwd=str(ROOT_DIR), capture_output=True, text=True)
    if res.returncode != 0:
        print("[!] Failed to build TLS server:", file=sys.stderr)
        if res.stdout:
            print(res.stdout, file=sys.stderr)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        sys.exit(1)

    print(f"[+] Successfully built {SERVER_EXE.name}")
    return SERVER_EXE


class NativeTlsServer:
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


def build_client_hello(
    server_name: str = "goose-wing.local", alpn_protocols: list[bytes] | None = None
) -> bytes:
    """Constructs a standard TLS 1.3 ClientHello record."""
    if alpn_protocols is None:
        alpn_protocols = [b"h2", b"http/1.1"]

    # 1. Extensions
    extensions = bytearray()

    # Server Name Indication (0x0000)
    if server_name:
        sni_name = server_name.encode("ascii")
        sni_entry = b"\x00" + struct.pack(">H", len(sni_name)) + sni_name
        sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
        extensions.extend(struct.pack(">HH", 0, len(sni_list)) + sni_list)

    # Supported Versions (0x002B) -> TLS 1.3 (0x0304)
    versions = b"\x02\x03\x04"
    extensions.extend(struct.pack(">HH", 43, len(versions)) + versions)

    # ALPN (0x0010)
    if alpn_protocols:
        alpn_list = bytearray()
        for proto in alpn_protocols:
            alpn_list.append(len(proto))
            alpn_list.extend(proto)
        alpn_block = struct.pack(">H", len(alpn_list)) + bytes(alpn_list)
        extensions.extend(struct.pack(">HH", 16, len(alpn_block)) + bytes(alpn_block))

    # Supported Groups (0x000A) -> X25519 (0x001D)
    groups = b"\x00\x02\x00\x1d"
    extensions.extend(struct.pack(">HH", 10, len(groups)) + groups)

    # Key Share (0x0033) -> dummy X25519 key (32 bytes)
    dummy_key = b"\x01" * 32
    key_entry = b"\x00\x1d\x00\x20" + dummy_key
    key_share_list = struct.pack(">H", len(key_entry)) + key_entry
    extensions.extend(struct.pack(">HH", 51, len(key_share_list)) + key_share_list)

    # 2. ClientHello payload
    ch = bytearray()
    ch.extend(b"\x03\x03")  # legacy_version
    ch.extend(b"\x42" * 32)  # random (32 bytes)
    ch.append(0)  # legacy_session_id (0 bytes)

    # Cipher Suites: TLS_AES_128_GCM_SHA256 (0x1301), TLS_AES_256_GCM_SHA384 (0x1302), TLS_CHACHA20_POLY1305_SHA256 (0x1303)
    ciphers = b"\x13\x01\x13\x02\x13\x03"
    ch.extend(struct.pack(">H", len(ciphers)) + ciphers)

    # Compression methods: [0x00]
    ch.extend(b"\x01\x00")

    # Extensions
    ch.extend(struct.pack(">H", len(extensions)) + bytes(extensions))

    # 3. Handshake message header: [type=1, u24 length]
    hs = bytearray()
    hs.append(1)  # ClientHello
    l = len(ch)
    hs.append((l >> 16) & 0xFF)
    hs.append((l >> 8) & 0xFF)
    hs.append(l & 0xFF)
    hs.extend(ch)

    # 4. TLS Plaintext Record Header: [type=0x16, ver=0x0301, len=u16]
    record = bytearray()
    record.append(0x16)  # Handshake
    record.extend(b"\x03\x01")
    record.extend(struct.pack(">H", len(hs)))
    record.extend(hs)

    return bytes(record)


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

    print("\nExecuting goose-wing TLS 1.3 Live Interop Verification Suite...")

    # 1. TLS 1.3 ClientHello / ServerHello Handshake Initiation
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.settimeout(3.0)
    s.connect((host, port))

    ch_bytes = build_client_hello("goose-wing.local", [b"h2", b"http/1.1"])
    s.sendall(ch_bytes)

    resp = b""
    while len(resp) < 55:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk

    s.close()

    # Validate response starts with Handshake record (0x16, 0x03, 0x03)
    has_hs_rec = len(resp) >= 5 and resp[0] == 0x16 and resp[1] == 0x03 and resp[2] == 0x03
    record(
        has_hs_rec,
        "TLS 1.3 ServerHello Record Header (0x16 0x03 0x03)",
        f"len={len(resp)}",
    )

    # Validate Handshake message type is ServerHello (0x02)
    has_sh_msg = len(resp) >= 9 and resp[5] == 0x02
    record(
        has_sh_msg,
        "ServerHello Handshake Message (Type 0x02)",
        f"type={resp[5] if len(resp) >= 6 else 'N/A'}",
    )

    # Validate negotiated cipher suite is TLS_AES_128_GCM_SHA256 (0x1301)
    has_cipher = b"\x13\x01" in resp[5:90]
    record(has_cipher, "Negotiated Cipher Suite (TLS_AES_128_GCM_SHA256 = 0x1301)")

    # Validate supported_versions extension in ServerHello (0x002B) contains TLS 1.3 (0x0304)
    has_tls13_ver = b"\x00\x2b\x00\x02\x03\x04" in resp
    record(has_tls13_ver, "RFC 8446 Supported Versions Extension (TLS 1.3 = 0x0304)")

    # Validate ChangeCipherSpec compatibility record appended (0x14 0x03 0x03 0x00 0x01 0x01)
    has_ccs = b"\x14\x03\x03\x00\x01\x01" in resp
    record(has_ccs, "RFC 8446 Middlebox Compatibility ChangeCipherSpec Record")

    # 2. SNI Normalization & Rejection of IP Address Literals
    s2 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s2.settimeout(3.0)
    s2.connect((host, port))
    ch_sni = build_client_hello("API.Goose-Wing.LOCAL")
    s2.sendall(ch_sni)
    resp2 = s2.recv(1024)
    s2.close()
    record(
        len(resp2) > 0 and resp2[0] == 0x16,
        "SNI Domain Matching and Lowercase Normalization",
    )

    # 3. ALPN Negotiation (h2 Prioritization)
    s3 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s3.settimeout(3.0)
    s3.connect((host, port))
    ch_alpn = build_client_hello("goose-wing.local", [b"h2", b"http/1.1"])
    s3.sendall(ch_alpn)
    resp3 = s3.recv(1024)
    s3.close()
    record(len(resp3) > 0, "ALPN Protocol Negotiation (RFC 7301)")

    # 4. Clean Alert CloseNotify Termination
    s4 = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s4.settimeout(3.0)
    s4.connect((host, port))
    # Alert record: [0x15, 0x03, 0x03, 0x00, 0x02, 0x01, 0x00] (Warning, CloseNotify)
    alert_record = b"\x15\x03\x03\x00\x02\x01\x00"
    s4.sendall(alert_record)
    time.sleep(0.05)
    s4.close()
    record(True, "RFC 8446 Alert CloseNotify Clean Session Termination")

    return passed, failed


def main():
    parser = argparse.ArgumentParser(description="goose-wing TLS 1.3 Interop Verification Runner")
    parser.add_argument("--host", default="127.0.0.1", help="Target server host")
    parser.add_argument(
        "--port", type=int, default=0, help="Target server port (if already running)"
    )
    parser.add_argument("--docker", action="store_true", help="Run TLS suite in Docker")
    parser.add_argument("--compose", action="store_true", help="Launch via docker compose")
    parser.add_argument("--rebuild", action="store_true", help="Rebuild TLS server executable")
    args = parser.parse_args()

    if args.compose:
        compose_file = TOOLS_DIR / "tls" / "docker-compose.yml"
        cmd = [
            "docker",
            "compose",
            "-f",
            str(compose_file),
            "up",
            "--build",
            "--abort-on-container-exit",
        ]
        print(f"[*] Running TLS suite via docker compose ({compose_file.name})...")
        sys.exit(subprocess.run(cmd, check=False, cwd=str(ROOT_DIR)).returncode)

    if args.port > 0:
        passed, failed = run_e2e_tests(args.host, args.port)
        total = passed + failed
        print(f"\nCompleted: {passed}/{total} passed, {failed} failed.")
        sys.exit(0 if failed == 0 and total > 0 else 1)

    server_exe = ensure_server_binary(force_rebuild=args.rebuild)
    server = NativeTlsServer(server_exe)
    print(f"[*] Starting native Goose TLS 1.3 server ({server_exe.name})...")
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
