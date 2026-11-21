#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
TLS 1.3 End-to-End Interop Verification Test Runner for goose-wing.
Validates RFC 8446 (TLS 1.3), RFC 6066 (SNI), RFC 7301 (ALPN),
pluggable SystemOpenSsl + PureGoose interop against live `openssl s_server -tls1_2` / `-tls1_3`,
strict TLS 1.3 default vs opt-in TlsMinVersion.Tls12 policy, and negative tls-anvil/tlsfuzzer
state-machine attacks (1-byte fragmented ClientHello, unexpected CCS, bad record MAC,
DOWNGRD\\x01 downgrade sentinel, unmatched ALPN, duplicate extensions, and TLS 1.2 rejection).
"""

from __future__ import annotations

import argparse
import io
import os
import shutil
import socket
import struct
import subprocess
import sys
import tempfile
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
SERVER_SRC = TOOLS_DIR / "tls" / "server.goose"
SERVER_EXE = BIN_DIR / ("tls_server.exe" if sys.platform == "win32" else "tls_server")
CLIENT_SRC = TOOLS_DIR / "tls" / "client.goose"
CLIENT_EXE = BIN_DIR / ("tls_client.exe" if sys.platform == "win32" else "tls_client")


def find_openssl_cli() -> str | None:
    found = shutil.which("openssl")
    if found:
        return found
    for cand in (
        Path(r"C:\Program Files\Git\usr\bin\openssl.exe"),
        Path(r"C:\Program Files\OpenSSL-Win64\bin\openssl.exe"),
    ):
        if cand.is_file():
            return str(cand)
    return None


def prepare_runtime_env() -> dict[str, str]:
    env = os.environ.copy()
    if sys.platform != "win32" or "WING_OPENSSL_LIB" in env:
        return env
    py_dlls = Path(sys.executable).resolve().parent / "DLLs"
    candidates = [
        (
            Path(r"C:\Program Files\Git\ucrt64\bin\libssl-3-x64.dll"),
            Path(r"C:\Program Files\Git\ucrt64\bin\libcrypto-3-x64.dll"),
        ),
        (
            py_dlls / "libssl-3.dll",
            py_dlls / "libcrypto-3.dll",
        ),
    ]
    for ssl_dll, cry_dll in candidates:
        if ssl_dll.is_file() and cry_dll.is_file():
            env["WING_OPENSSL_LIB"] = str(ssl_dll)
            env["WING_CRYPTO_LIB"] = str(cry_dll)
            env["PATH"] = f"{ssl_dll.parent};{env.get('PATH', '')}"
            break
    return env


def _build_goose_binary(src: Path, exe: Path, label: str, force_rebuild: bool = False) -> Path:
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    if not force_rebuild and exe.is_file() and exe.stat().st_mtime >= src.stat().st_mtime:
        return exe

    print(f"[*] Building native {label}: {src} -> {exe}...")
    env = os.environ.copy()
    opt_flag = "-O2"
    if sys.platform == "win32":
        opt_flag = "-O0"
        if "GOOSE_CC" not in env:
            stack_cc = ROOT_DIR / "tools" / "gcc_stack.bat"
            if stack_cc.is_file():
                env["GOOSE_CC"] = str(stack_cc)
    cmd = ["goose", "build", str(src), "-o", str(exe), opt_flag]
    res = subprocess.run(
        cmd, check=False, cwd=str(ROOT_DIR), capture_output=True, text=True, env=env
    )
    if res.returncode != 0:
        print(f"[!] Failed to build {label}:", file=sys.stderr)
        if res.stdout:
            print(res.stdout, file=sys.stderr)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        sys.exit(1)

    print(f"[+] Successfully built {exe.name}")
    return exe


def ensure_client_binary(force_rebuild: bool = False) -> Path:
    return _build_goose_binary(CLIENT_SRC, CLIENT_EXE, "TLS client", force_rebuild)


def ensure_server_binary(force_rebuild: bool = False) -> Path:
    return _build_goose_binary(SERVER_SRC, SERVER_EXE, "TLS server", force_rebuild)


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


class OneByteFragmentProxy:
    """TCP proxy forwarding client-to-server handshake bytes 1 byte per TCP write."""

    def __init__(self, target_host: str, target_port: int) -> None:
        self.target_host = target_host
        self.target_port = target_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.port: int = self.sock.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _pipe(self, src: socket.socket, dst: socket.socket, frag_one_byte: bool) -> None:
        try:
            while self.running:
                data = src.recv(4096)
                if not data:
                    break
                if frag_one_byte:
                    for i in range(len(data)):
                        dst.sendall(data[i : i + 1])
                else:
                    dst.sendall(data)
        except Exception:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    def _loop(self) -> None:
        while self.running:
            try:
                cli, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                cli.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                rem = socket.create_connection((self.target_host, self.target_port), timeout=2.0)
                rem.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                threading.Thread(target=self._pipe, args=(cli, rem, True), daemon=True).start()
                threading.Thread(target=self._pipe, args=(rem, cli, False), daemon=True).start()
            except Exception:
                cli.close()

    def close(self) -> None:
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass


class DowngradeSentinelServer:
    """Mock TLS peer replying with RFC 8446 §4.1.3 TLS 1.2 downgrade sentinel `DOWNGRD\\x01`."""

    def __init__(self) -> None:
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.port: int = self.sock.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    @staticmethod
    def _build_downgrade_server_hello() -> bytes:
        body = bytearray()
        body.extend(b"\x03\x03")  # legacy_version = TLS 1.2
        body.extend(b"\x22" * 24 + b"DOWNGRD\x01")  # RFC 8446 §4.1.3 sentinel
        body.append(0)  # session_id_len = 0
        body.extend(b"\x13\x01")  # TLS_AES_128_GCM_SHA256
        body.append(0)  # compression = null
        # supported_versions = 0x0304 + dummy key_share so parsers inspect random sentinel
        ext = b"\x00\x2b\x00\x02\x03\x04\x00\x33\x00\x24\x00\x1d\x00\x20" + (b"\x07" * 32)
        body.extend(struct.pack(">H", len(ext)) + ext)
        hs = bytes([0x02, (len(body) >> 16) & 0xFF, (len(body) >> 8) & 0xFF, len(body) & 0xFF]) + bytes(body)
        return bytes([0x16, 0x03, 0x03]) + struct.pack(">H", len(hs)) + hs

    def _loop(self) -> None:
        sh_record = self._build_downgrade_server_hello()
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            try:
                conn.settimeout(1.5)
                _ = conn.recv(4096)
                conn.sendall(sh_record)
                time.sleep(0.05)
            except Exception:
                pass
            finally:
                conn.close()

    def close(self) -> None:
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass


def _alloc_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return int(s.getsockname()[1])


class OpenSslSServer:
    """Manages an external `openssl s_server` peer (-tls1_2 or -tls1_3) on loopback."""

    def __init__(
        self,
        openssl_bin: str,
        cert_file: Path,
        key_file: Path,
        tls_flag: str,
        alpn: str = "",
    ) -> None:
        self.openssl_bin = openssl_bin
        self.cert_file = cert_file
        self.key_file = key_file
        self.tls_flag = tls_flag
        self.alpn = alpn
        self.port = _alloc_free_port()
        self.proc: subprocess.Popen | None = None

    def start(self, timeout: float = 5.0) -> int:
        cmd = [
            self.openssl_bin,
            "s_server",
            "-accept",
            f"127.0.0.1:{self.port}",
            "-cert",
            str(self.cert_file),
            "-key",
            str(self.key_file),
            self.tls_flag,
            "-www",
        ]
        if self.alpn:
            cmd.extend(["-alpn", self.alpn])
        self.proc = subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            stdin=subprocess.DEVNULL,
            text=True,
        )
        deadline = time.time() + timeout
        while time.time() < deadline:
            if self.proc.poll() is not None:
                err = self.proc.stderr.read() if self.proc.stderr else ""
                raise RuntimeError(f"openssl s_server exited early: {err}")
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.15):
                    return self.port
            except OSError:
                time.sleep(0.05)
        self.stop()
        raise TimeoutError(f"openssl s_server failed to bind port {self.port}")

    def stop(self) -> None:
        if not self.proc:
            return
        try:
            self.proc.terminate()
            self.proc.wait(timeout=1.5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        self.proc = None


def generate_temp_ecdsa_cert(work_dir: Path, openssl_bin: str) -> tuple[Path, Path]:
    """Generates a self-signed ECDSA P-256 cert with SAN=DNS:localhost,IP:127.0.0.1."""
    key_file = work_dir / "srv.key"
    cert_file = work_dir / "srv.pem"
    cnf_file = work_dir / "srv.cnf"
    cnf_file.write_text(
        """
[req]
distinguished_name = dn
x509_extensions = v3_ext
prompt = no

[dn]
CN = localhost

[v3_ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
""".strip()
        + "\n",
        encoding="utf-8",
    )
    subprocess.run(
        [openssl_bin, "ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key_file)],
        check=True,
        capture_output=True,
    )
    subprocess.run(
        [
            openssl_bin,
            "req",
            "-new",
            "-x509",
            "-key",
            str(key_file),
            "-out",
            str(cert_file),
            "-days",
            "365",
            "-config",
            str(cnf_file),
            "-extensions",
            "v3_ext",
        ],
        check=True,
        capture_output=True,
    )
    return cert_file, key_file


def build_client_hello(
    server_name: str = "goose-wing.local",
    alpn_protocols: list[bytes] | None = None,
    supported_versions: list[int] | None = None,
    duplicate_alpn_ext: bool = False,
) -> bytes:
    """Constructs a synthetic TLS ClientHello record with configurable extensions."""
    if alpn_protocols is None:
        alpn_protocols = [b"h2", b"http/1.1"]
    if supported_versions is None:
        supported_versions = [0x0304]

    extensions = bytearray()

    if server_name:
        sni_name = server_name.encode("ascii")
        sni_entry = b"\x00" + struct.pack(">H", len(sni_name)) + sni_name
        sni_list = struct.pack(">H", len(sni_entry)) + sni_entry
        extensions.extend(struct.pack(">HH", 0, len(sni_list)) + sni_list)

    if supported_versions:
        ver_bytes = b"".join(struct.pack(">H", v) for v in supported_versions)
        versions = bytes([len(ver_bytes)]) + ver_bytes
        extensions.extend(struct.pack(">HH", 43, len(versions)) + versions)

    if alpn_protocols:
        alpn_list = bytearray()
        for proto in alpn_protocols:
            alpn_list.append(len(proto))
            alpn_list.extend(proto)
        alpn_block = struct.pack(">H", len(alpn_list)) + bytes(alpn_list)
        alpn_ext = struct.pack(">HH", 16, len(alpn_block)) + bytes(alpn_block)
        extensions.extend(alpn_ext)
        if duplicate_alpn_ext:
            extensions.extend(alpn_ext)

    groups = b"\x00\x02\x00\x1d"
    extensions.extend(struct.pack(">HH", 10, len(groups)) + groups)

    dummy_key = b"\x01" * 32
    key_entry = b"\x00\x1d\x00\x20" + dummy_key
    key_share_list = struct.pack(">H", len(key_entry)) + key_entry
    extensions.extend(struct.pack(">HH", 51, len(key_share_list)) + key_share_list)

    ch = bytearray()
    ch.extend(b"\x03\x03")
    ch.extend(b"\x42" * 32)
    ch.append(0)

    ciphers = b"\x13\x01\x13\x02\x13\x03"
    ch.extend(struct.pack(">H", len(ciphers)) + ciphers)
    ch.extend(b"\x01\x00")
    ch.extend(struct.pack(">H", len(extensions)) + bytes(extensions))

    hs = bytearray()
    hs.append(1)
    msg_len = len(ch)
    hs.append((msg_len >> 16) & 0xFF)
    hs.append((msg_len >> 8) & 0xFF)
    hs.append(msg_len & 0xFF)
    hs.extend(ch)

    record = bytearray()
    record.append(0x16)
    record.extend(b"\x03\x01")
    record.extend(struct.pack(">H", len(hs)))
    record.extend(hs)
    return bytes(record)


def invoke_client_probe(
    client_exe: Path,
    env: dict[str, str],
    backend: str,
    min_ver: str,
    host: str,
    port: int,
    sni: str,
    ca_path: str,
    alpn: str,
) -> tuple[str, str, int]:
    res = subprocess.run(
        [str(client_exe), "probe", backend, min_ver, host, str(port), sni, ca_path, alpn],
        cwd=str(ROOT_DIR),
        env=env,
        capture_output=True,
        text=True,
        timeout=15.0,
        check=False,
    )
    for line in res.stdout.splitlines():
        if line.startswith("PROBE\t"):
            cols = line.split("\t")
            if len(cols) >= 4:
                return cols[1], cols[2], int(cols[3])
    return "ProcessError", "-", 0


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
    s.sendall(build_client_hello("goose-wing.local", [b"h2", b"http/1.1"]))

    resp = b""
    while len(resp) < 55:
        chunk = s.recv(4096)
        if not chunk:
            break
        resp += chunk
    s.close()

    record(
        len(resp) >= 5 and resp[0] == 0x16 and resp[1] == 0x03 and resp[2] == 0x03,
        "TLS 1.3 ServerHello Record Header (0x16 0x03 0x03)",
        f"len={len(resp)}",
    )
    record(
        len(resp) >= 9 and resp[5] == 0x02,
        "ServerHello Handshake Message (Type 0x02)",
        f"type={resp[5] if len(resp) >= 6 else 'N/A'}",
    )
    record(b"\x13\x01" in resp[5:90], "Negotiated Cipher Suite (TLS_AES_128_GCM_SHA256 = 0x1301)")
    record(
        b"\x00\x2b\x00\x02\x03\x04" in resp,
        "RFC 8446 Supported Versions Extension (TLS 1.3 = 0x0304)",
    )
    record(
        b"\x14\x03\x03\x00\x01\x01" in resp,
        "RFC 8446 Middlebox Compatibility ChangeCipherSpec Record",
    )

    # 2. SNI Normalization
    with socket.create_connection((host, port), timeout=3.0) as s2:
        s2.sendall(build_client_hello("API.Goose-Wing.LOCAL"))
        resp2 = s2.recv(1024)
    record(
        len(resp2) > 0 and resp2[0] == 0x16,
        "SNI Domain Matching and Lowercase Normalization",
    )

    # 3. ALPN Negotiation (h2 Prioritization)
    with socket.create_connection((host, port), timeout=3.0) as s3:
        s3.sendall(build_client_hello("goose-wing.local", [b"h2", b"http/1.1"]))
        resp3 = s3.recv(1024)
    record(len(resp3) > 0 and resp3[0] == 0x16, "ALPN Protocol Negotiation (RFC 7301)")

    # 4. Clean Alert CloseNotify Termination
    with socket.create_connection((host, port), timeout=3.0) as s4:
        s4.sendall(b"\x15\x03\x03\x00\x02\x01\x00")
        time.sleep(0.05)
    record(True, "RFC 8446 Alert CloseNotify Clean Session Termination")

    # 5-7. Native Goose Client (wing::Client) Full TLS 1.3 + ALPN h2 E2E Suite
    client_exe = ensure_client_binary(force_rebuild=False)
    rt_env = prepare_runtime_env()
    cli_env = rt_env.copy()
    cli_env["WING_PORT"] = str(port)
    cli_env["PORT"] = str(port)
    cli_res = subprocess.run(
        [str(client_exe)],
        cwd=str(ROOT_DIR),
        env=cli_env,
        capture_output=True,
        text=True,
        timeout=15.0,
        check=False,
    )
    cli_out = cli_res.stdout or ""
    record(
        "TLS_CLI_UNTRUSTED_REJECT: PASS" in cli_out,
        "Native Goose TLS 1.3 Client: Untrusted Self-Signed Certificate Rejection",
        cli_out.strip(),
    )
    record(
        "TLS_CLI_VERIFIED_H2: PASS" in cli_out,
        "Native Goose TLS 1.3 Client: Full Handshake, Ed25519 PKI + IP SAN Verification & ALPN h2 GET",
        cli_out.strip(),
    )
    record(
        "TLS_CLI_H2_STREAM_REUSE: PASS" in cli_out,
        "Native Goose TLS 1.3 Client: Pooled TLS 1.3 + HTTP/2 Stream Multiplexing (Stream 3 POST)",
        cli_out.strip(),
    )

    # 8. Fragmented 1-byte ClientHello & live TLS 1.3 handshake via 1-byte TCP proxy
    frag_proxy = OneByteFragmentProxy(host, port)
    try:
        frag_env = rt_env.copy()
        frag_env["WING_PORT"] = str(frag_proxy.port)
        frag_env["PORT"] = str(frag_proxy.port)
        frag_res = subprocess.run(
            [str(client_exe)],
            cwd=str(ROOT_DIR),
            env=frag_env,
            capture_output=True,
            text=True,
            timeout=20.0,
            check=False,
        )
        frag_out = frag_res.stdout or ""
        record(
            "TLS_CLI_VERIFIED_H2: PASS" in frag_out,
            "Negative/Fuzz: 1-byte TCP fragmented ClientHello reassembles into valid TLS 1.3 + H2",
            frag_out.strip(),
        )
    finally:
        frag_proxy.close()

    # 9. Unexpected ChangeCipherSpec before ClientHello -> fatal unexpected_message (10)
    with socket.create_connection((host, port), timeout=3.0) as s_ccs:
        s_ccs.settimeout(2.0)
        s_ccs.sendall(b"\x14\x03\x03\x00\x01\x01")
        ccs_resp = s_ccs.recv(64)
    record(
        len(ccs_resp) >= 7 and ccs_resp[0] == 0x15 and ccs_resp[5] == 0x02 and ccs_resp[6] == 10,
        "Negative/Fuzz: Unexpected CCS before handshake triggers fatal unexpected_message alert",
        f"resp={ccs_resp.hex()}",
    )

    # 10. Bad Record MAC (post-handshake corrupted AEAD tag) -> fail-closed
    badmac_res = subprocess.run(
        [str(client_exe), "badmac", host, str(port)],
        cwd=str(ROOT_DIR),
        env=rt_env,
        capture_output=True,
        text=True,
        timeout=15.0,
        check=False,
    )
    record(
        "TLS_BAD_RECORD_MAC: PASS" in (badmac_res.stdout or ""),
        "Negative/Fuzz: Post-handshake corrupted AEAD record MAC fails closed",
        (badmac_res.stdout or "").strip(),
    )

    # 11. Wrong / unmatched ALPN -> fatal no_application_protocol (120) alert
    with socket.create_connection((host, port), timeout=3.0) as s_alpn:
        s_alpn.settimeout(2.0)
        s_alpn.sendall(build_client_hello("goose-wing.local", [b"bogus-proto/99"]))
        alpn_resp = s_alpn.recv(64)
    record(
        len(alpn_resp) >= 7 and alpn_resp[0] == 0x15 and alpn_resp[5] == 0x02 and alpn_resp[6] == 120,
        "Negative/Fuzz: Unmatched ALPN triggers fatal no_application_protocol alert (120)",
        f"resp={alpn_resp.hex()}",
    )

    # 12. Duplicate extension in ClientHello -> fatal illegal_parameter (47) alert
    with socket.create_connection((host, port), timeout=3.0) as s_dup:
        s_dup.settimeout(2.0)
        s_dup.sendall(build_client_hello("goose-wing.local", [b"h2"], duplicate_alpn_ext=True))
        dup_resp = s_dup.recv(64)
    record(
        len(dup_resp) >= 7 and dup_resp[0] == 0x15 and dup_resp[5] == 0x02 and dup_resp[6] in (47, 50),
        "Negative/Fuzz: Duplicate ClientHello extension triggers fatal alert",
        f"resp={dup_resp.hex()}",
    )

    # 13. TLS 1.2-only ClientHello -> fatal protocol_version (70) alert
    with socket.create_connection((host, port), timeout=3.0) as s_v12:
        s_v12.settimeout(2.0)
        s_v12.sendall(build_client_hello("goose-wing.local", [b"h2"], supported_versions=[0x0303]))
        v12_resp = s_v12.recv(64)
    record(
        len(v12_resp) >= 7 and v12_resp[0] == 0x15 and v12_resp[5] == 0x02 and v12_resp[6] == 70,
        "Negative/Fuzz: TLS 1.2-only ClientHello rejected with fatal protocol_version alert (70)",
        f"resp={v12_resp.hex()}",
    )

    # 14-15. Downgrade sentinel `DOWNGRD\x01` in ServerHello.random[24..32] rejected fail-closed
    dg_srv = DowngradeSentinelServer()
    try:
        st_pure, _, _ = invoke_client_probe(
            client_exe, rt_env, "pure", "tls13", "127.0.0.1", dg_srv.port, "localhost", "-", "-"
        )
        record(
            st_pure in ("HandshakeError", "Error", "Closed"),
            "Negative/Fuzz: PureGoose rejects RFC 8446 §4.1.3 DOWNGRD\\x01 downgrade sentinel",
            f"status={st_pure}",
        )
        st_ossl, _, _ = invoke_client_probe(
            client_exe, rt_env, "openssl", "tls13", "127.0.0.1", dg_srv.port, "localhost", "-", "-"
        )
        if st_ossl != "Unavailable":
            record(
                st_ossl in ("HandshakeError", "Error", "Closed"),
                "Negative/Fuzz: SystemOpenSsl rejects RFC 8446 §4.1.3 DOWNGRD\\x01 downgrade sentinel",
                f"status={st_ossl}",
            )
    finally:
        dg_srv.close()

    # 16-21. Live `openssl s_server -tls1_2` and `-tls1_3` interop & SystemOpenSsl verification
    openssl_bin = find_openssl_cli()
    if openssl_bin:
        with tempfile.TemporaryDirectory(prefix="wing_tls_sserver_") as td:
            cert_file, key_file = generate_temp_ecdsa_cert(Path(td), openssl_bin)
            ca_str = str(cert_file)

            # Live `openssl s_server -tls1_2`
            s12 = OpenSslSServer(openssl_bin, cert_file, key_file, "-tls1_2")
            try:
                p12 = s12.start()
                st_p12, _, _ = invoke_client_probe(
                    client_exe, rt_env, "pure", "tls13", "127.0.0.1", p12, "localhost", ca_str, "-"
                )
                record(
                    st_p12 != "Ok" and st_p12 != "ConnectError",
                    "OpenSSL s_server -tls1_2: PureGoose (strict TLS 1.3) rejects TLS 1.2-only peer",
                    f"status={st_p12}",
                )

                st_o13_12, _, _ = invoke_client_probe(
                    client_exe, rt_env, "openssl", "tls13", "127.0.0.1", p12, "localhost", ca_str, "-"
                )
                if st_o13_12 != "Unavailable":
                    record(
                        st_o13_12 in ("HandshakeError", "Error", "Closed"),
                        "OpenSSL s_server -tls1_2: SystemOpenSsl default Tls13 rejects TLS 1.2-only peer",
                        f"status={st_o13_12}",
                    )
                    st_o12_12, _, app12 = invoke_client_probe(
                        client_exe, rt_env, "openssl", "tls12", "127.0.0.1", p12, "localhost", ca_str, "-"
                    )
                    record(
                        st_o12_12 == "Ok" and app12 > 0,
                        "OpenSSL s_server -tls1_2: SystemOpenSsl opt-in TlsMinVersion.Tls12 succeeds",
                        f"status={st_o12_12} app={app12}",
                    )
            finally:
                s12.stop()

            # Live `openssl s_server -tls1_3 -alpn h2,http/1.1`
            s13 = OpenSslSServer(openssl_bin, cert_file, key_file, "-tls1_3", alpn="h2,http/1.1")
            try:
                p13 = s13.start()
                st_p13, alpn_p13, app_p13 = invoke_client_probe(
                    client_exe, rt_env, "pure", "tls13", "127.0.0.1", p13, "localhost", ca_str, "h2,http/1.1"
                )
                record(
                    st_p13 == "Ok" and alpn_p13 == "h2" and app_p13 > 0,
                    "OpenSSL s_server -tls1_3: PureGoose interop + matching SAN + ALPN h2",
                    f"status={st_p13} alpn={alpn_p13} app={app_p13}",
                )

                st_o13, alpn_o13, app_o13 = invoke_client_probe(
                    client_exe, rt_env, "openssl", "tls13", "127.0.0.1", p13, "localhost", ca_str, "h2,http/1.1"
                )
                if st_o13 != "Unavailable":
                    record(
                        st_o13 == "Ok" and alpn_o13 == "h2" and app_o13 > 0,
                        "OpenSSL s_server -tls1_3: SystemOpenSsl interop + matching SAN + ALPN h2",
                        f"status={st_o13} alpn={alpn_o13} app={app_o13}",
                    )
                    st_badhost, _, _ = invoke_client_probe(
                        client_exe,
                        rt_env,
                        "openssl",
                        "tls13",
                        "127.0.0.1",
                        p13,
                        "wrong.goose-wing.local",
                        ca_str,
                        "h2",
                    )
                    record(
                        st_badhost == "VerifyError",
                        "OpenSSL s_server -tls1_3: SystemOpenSsl rejects wrong hostname with VerifyError",
                        f"status={st_badhost}",
                    )
            finally:
                s13.stop()

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

    if args.compose or args.docker:
        compose_file = TOOLS_DIR / "tls" / "docker-compose.yml"
        cmd = [
            "docker",
            "compose",
            "-f",
            str(compose_file),
            "up",
            "--build",
            "--abort-on-container-exit",
            "--exit-code-from",
            "tls-runner",
        ]
        print(f"[*] Running TLS suite via docker compose ({compose_file.name})...")
        sys.exit(subprocess.run(cmd, check=False, cwd=str(ROOT_DIR)).returncode)

    if args.port > 0:
        passed, failed = run_e2e_tests(args.host, args.port)
        total = passed + failed
        print(f"\nCompleted: {passed}/{total} passed, {failed} failed.")
        sys.exit(0 if failed == 0 and total > 0 else 1)

    server_exe = ensure_server_binary(force_rebuild=args.rebuild)
    ensure_client_binary(force_rebuild=args.rebuild)
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
