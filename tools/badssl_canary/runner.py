#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
TLS Interop Canary Runner (`badssl.com` live matrix + deterministic offline local CA matrix).
Exercises `PureGoose`, `SystemOpenSsl`, and `SystemSchannel` (when available) via
`tools/badssl_canary/canary.goose`.
"""

from __future__ import annotations

import argparse
import io
import os
import shutil
import socket
import ssl
import subprocess
import sys
import tempfile
import threading
from dataclasses import dataclass
from pathlib import Path

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
CANARY_SRC = TOOLS_DIR / "badssl_canary" / "canary.goose"
CANARY_EXE = BIN_DIR / ("badssl_canary.exe" if sys.platform == "win32" else "badssl_canary")


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
    """Configures environment so dynamic OpenSSL loading works out of the box on Windows."""
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


def ensure_canary_binary(force_rebuild: bool = False) -> Path:
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    if not force_rebuild and CANARY_EXE.is_file() and CANARY_EXE.stat().st_mtime >= CANARY_SRC.stat().st_mtime:
        return CANARY_EXE

    print(f"[*] Building TLS canary probe: {CANARY_SRC.name} -> {CANARY_EXE.name}...")
    env = os.environ.copy()
    build_flags = ["-O2"]
    if sys.platform == "win32":
        build_flags = ["-O0"]
        if "GOOSE_CC" not in env:
            stack_cc = ROOT_DIR / "tools" / "gcc_stack.bat"
            if stack_cc.is_file():
                env["GOOSE_CC"] = str(stack_cc)
    cmd = ["goose", "build", *build_flags, "-o", str(CANARY_EXE), str(CANARY_SRC)]
    res = subprocess.run(
        cmd, check=False, cwd=str(ROOT_DIR), capture_output=True, text=True, env=env
    )
    if res.returncode != 0:
        print("[!] Failed to build badssl_canary:", file=sys.stderr)
        if res.stdout:
            print(res.stdout, file=sys.stderr)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        sys.exit(1)
    print(f"[+] Built {CANARY_EXE.name}")
    return CANARY_EXE


def _run_openssl(openssl_bin: str, args: list[str], cwd: Path) -> None:
    res = subprocess.run(
        [openssl_bin, *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        check=False,
    )
    if res.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args)} failed:\n{res.stderr}\n{res.stdout}")


@dataclass
class LocalPkiBundle:
    ca_cert: Path
    valid_cert: Path
    valid_key: Path
    expired_cert: Path
    expired_key: Path
    wrong_host_cert: Path
    wrong_host_key: Path
    self_signed_cert: Path
    self_signed_key: Path
    untrusted_cert: Path
    untrusted_key: Path
    weak_rsa_cert: Path
    weak_rsa_key: Path
    client_eku_cert: Path
    client_eku_key: Path
    not_yet_valid_cert: Path
    not_yet_valid_key: Path
    ip_san_cert: Path
    ip_san_key: Path
    wildcard_cert: Path
    wildcard_key: Path
    two_tier_cert: Path
    two_tier_key: Path
    non_ca_inter_cert: Path
    non_ca_inter_key: Path
    ed25519_cert: Path
    ed25519_key: Path


def _init_ca(openssl_bin: str, ca_dir: Path, cn: str) -> tuple[Path, Path, Path]:
    ca_dir.mkdir(parents=True, exist_ok=True)
    (ca_dir / "newcerts").mkdir(exist_ok=True)
    (ca_dir / "index.txt").write_text("", encoding="utf-8")
    (ca_dir / "serial").write_text("1000\n", encoding="utf-8")

    ca_key = ca_dir / "ca.key"
    ca_cert = ca_dir / "ca.pem"
    cnf = ca_dir / "ca.cnf"
    cnf.write_text(
        f"""
[ca]
default_ca = CA_default

[CA_default]
dir = {ca_dir.as_posix()}
database = $dir/index.txt
new_certs_dir = $dir/newcerts
certificate = $dir/ca.pem
serial = $dir/serial
private_key = $dir/ca.key
default_md = sha256
policy = policy_loose
unique_subject = no
copy_extensions = none

[policy_loose]
commonName = supplied

[req]
distinguished_name = req_dn
x509_extensions = v3_ca
prompt = no

[req_dn]
CN = {cn}

[v3_ca]
basicConstraints = critical, CA:TRUE
keyUsage = critical, keyCertSign, cRLSign
subjectKeyIdentifier = hash
""".strip()
        + "\n",
        encoding="utf-8",
    )
    _run_openssl(openssl_bin, ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ca_key)], ca_dir)
    _run_openssl(
        openssl_bin,
        [
            "req",
            "-new",
            "-x509",
            "-key",
            str(ca_key),
            "-out",
            str(ca_cert),
            "-days",
            "3650",
            "-config",
            str(cnf),
            "-extensions",
            "v3_ca",
        ],
        ca_dir,
    )
    return ca_cert, ca_key, cnf


def _sign_leaf(
    openssl_bin: str,
    ca_dir: Path,
    ca_cnf: Path,
    name: str,
    cn: str,
    san: str,
    start_date: str,
    end_date: str,
    key_type: str = "ec",
    eku: str = "serverAuth",
) -> tuple[Path, Path]:
    key_path = ca_dir / f"{name}.key"
    csr_path = ca_dir / f"{name}.csr"
    cert_path = ca_dir / f"{name}.pem"
    ext_path = ca_dir / f"{name}.ext"

    ext_path.write_text(
        f"""
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = {eku}
subjectAltName = {san}
""".strip()
        + "\n",
        encoding="utf-8",
    )
    if key_type == "rsa1024":
        _run_openssl(openssl_bin, ["genrsa", "-out", str(key_path), "1024"], ca_dir)
    elif key_type == "ed25519":
        _run_openssl(openssl_bin, ["genpkey", "-algorithm", "Ed25519", "-out", str(key_path)], ca_dir)
    else:
        _run_openssl(
            openssl_bin,
            ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key_path)],
            ca_dir,
        )
    _run_openssl(
        openssl_bin,
        ["req", "-new", "-key", str(key_path), "-subj", f"/CN={cn}", "-out", str(csr_path)],
        ca_dir,
    )
    _run_openssl(
        openssl_bin,
        [
            "ca",
            "-batch",
            "-config",
            str(ca_cnf),
            "-startdate",
            start_date,
            "-enddate",
            end_date,
            "-extfile",
            str(ext_path),
            "-in",
            str(csr_path),
            "-out",
            str(cert_path),
        ],
        ca_dir,
    )
    return cert_path, key_path


def generate_local_pki(work_dir: Path, openssl_bin: str) -> LocalPkiBundle:
    """Builds a deterministic ECDSA P-256 local CA + leaf matrix for offline canary tests."""
    trusted_dir = work_dir / "trusted_ca"
    ca_cert, _, ca_cnf = _init_ca(openssl_bin, trusted_dir, "Wing Canary Trusted Root CA")

    valid_cert, valid_key = _sign_leaf(
        openssl_bin,
        trusted_dir,
        ca_cnf,
        "valid",
        "localhost",
        "DNS:localhost,IP:127.0.0.1",
        "20250101000000Z",
        "20350101000000Z",
    )
    expired_cert, expired_key = _sign_leaf(
        openssl_bin,
        trusted_dir,
        ca_cnf,
        "expired",
        "localhost",
        "DNS:localhost,IP:127.0.0.1",
        "20200101000000Z",
        "20200102000000Z",
    )
    wrong_cert, wrong_key = _sign_leaf(
        openssl_bin,
        trusted_dir,
        ca_cnf,
        "wronghost",
        "wrong.host.local",
        "DNS:wrong.host.local",
        "20250101000000Z",
        "20350101000000Z",
    )
    weak_rsa_cert, weak_rsa_key = _sign_leaf(
        openssl_bin,
        trusted_dir,
        ca_cnf,
        "weakrsa1024",
        "localhost",
        "DNS:localhost,IP:127.0.0.1",
        "20250101000000Z",
        "20350101000000Z",
        key_type="rsa1024",
    )
    client_eku_cert, client_eku_key = _sign_leaf(
        openssl_bin,
        trusted_dir,
        ca_cnf,
        "clienteku",
        "localhost",
        "DNS:localhost,IP:127.0.0.1",
        "20250101000000Z",
        "20350101000000Z",
        eku="clientAuth",
    )
    not_yet_valid_cert, not_yet_valid_key = _sign_leaf(
        openssl_bin,
        trusted_dir,
        ca_cnf,
        "notyetvalid",
        "localhost",
        "DNS:localhost,IP:127.0.0.1",
        "20340101000000Z",
        "20350101000000Z",
    )
    ip_san_cert, ip_san_key = _sign_leaf(
        openssl_bin,
        trusted_dir,
        ca_cnf,
        "ipsan",
        "127.0.0.1",
        "IP:127.0.0.1",
        "20250101000000Z",
        "20350101000000Z",
    )
    wildcard_cert, wildcard_key = _sign_leaf(
        openssl_bin,
        trusted_dir,
        ca_cnf,
        "wildcard",
        "*.wing.local",
        "DNS:*.wing.local",
        "20250101000000Z",
        "20350101000000Z",
    )
    ed25519_cert, ed25519_key = _sign_leaf(
        openssl_bin,
        trusted_dir,
        ca_cnf,
        "ed25519leaf",
        "localhost",
        "DNS:localhost,IP:127.0.0.1",
        "20250101000000Z",
        "20350101000000Z",
        key_type="ed25519",
    )

    # Two-tier chain: Root CA -> Intermediate CA (CA:TRUE, pathlen:0) -> Leaf
    inter_dir = work_dir / "two_tier_inter"
    inter_dir.mkdir(parents=True, exist_ok=True)
    (inter_dir / "newcerts").mkdir(exist_ok=True)
    (inter_dir / "index.txt").write_text("", encoding="utf-8")
    (inter_dir / "serial").write_text("2000\n", encoding="utf-8")
    inter_key = inter_dir / "ca.key"
    inter_csr = inter_dir / "ca.csr"
    inter_cert = inter_dir / "ca.pem"
    inter_ext = inter_dir / "inter.ext"
    inter_ext.write_text(
        "basicConstraints = critical, CA:TRUE, pathlen:0\nkeyUsage = critical, keyCertSign, cRLSign\n",
        encoding="utf-8",
    )
    _run_openssl(openssl_bin, ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(inter_key)], inter_dir)
    _run_openssl(
        openssl_bin,
        ["req", "-new", "-key", str(inter_key), "-subj", "/CN=Wing Canary Intermediate CA", "-out", str(inter_csr)],
        inter_dir,
    )
    _run_openssl(
        openssl_bin,
        [
            "ca",
            "-batch",
            "-config",
            str(ca_cnf),
            "-startdate",
            "20250101000000Z",
            "-enddate",
            "20350101000000Z",
            "-extfile",
            str(inter_ext),
            "-in",
            str(inter_csr),
            "-out",
            str(inter_cert),
        ],
        trusted_dir,
    )
    inter_cnf = inter_dir / "ca.cnf"
    inter_cnf.write_text(
        ca_cnf.read_text(encoding="utf-8").replace(trusted_dir.as_posix(), inter_dir.as_posix()),
        encoding="utf-8",
    )
    two_tier_leaf_cert, two_tier_key = _sign_leaf(
        openssl_bin,
        inter_dir,
        inter_cnf,
        "twotierleaf",
        "localhost",
        "DNS:localhost,IP:127.0.0.1",
        "20250101000000Z",
        "20350101000000Z",
    )
    two_tier_cert = work_dir / "two_tier_fullchain.pem"
    two_tier_cert.write_text(
        two_tier_leaf_cert.read_text(encoding="utf-8") + "\n" + inter_cert.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    # Invalid chain: Trusted Root -> non-CA intermediate (CA:FALSE) -> Leaf
    non_ca_dir = work_dir / "non_ca_inter"
    non_ca_dir.mkdir(parents=True, exist_ok=True)
    non_ca_key = non_ca_dir / "non_ca.key"
    non_ca_csr = non_ca_dir / "non_ca.csr"
    non_ca_cert = non_ca_dir / "non_ca.pem"
    non_ca_ext = non_ca_dir / "non_ca.ext"
    non_ca_ext.write_text(
        "basicConstraints = critical, CA:FALSE\nkeyUsage = critical, digitalSignature, keyCertSign\n",
        encoding="utf-8",
    )
    _run_openssl(openssl_bin, ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(non_ca_key)], non_ca_dir)
    _run_openssl(
        openssl_bin,
        ["req", "-new", "-key", str(non_ca_key), "-subj", "/CN=Wing Non-CA Sub", "-out", str(non_ca_csr)],
        non_ca_dir,
    )
    _run_openssl(
        openssl_bin,
        [
            "ca",
            "-batch",
            "-config",
            str(ca_cnf),
            "-startdate",
            "20250101000000Z",
            "-enddate",
            "20350101000000Z",
            "-extfile",
            str(non_ca_ext),
            "-in",
            str(non_ca_csr),
            "-out",
            str(non_ca_cert),
        ],
        trusted_dir,
    )
    non_ca_leaf_key = non_ca_dir / "leaf.key"
    non_ca_leaf_csr = non_ca_dir / "leaf.csr"
    non_ca_leaf_cert = non_ca_dir / "leaf.pem"
    non_ca_leaf_ext = non_ca_dir / "leaf.ext"
    non_ca_leaf_ext.write_text(
        "basicConstraints = critical, CA:FALSE\n"
        "keyUsage = critical, digitalSignature\n"
        "extendedKeyUsage = serverAuth\n"
        "subjectAltName = DNS:localhost,IP:127.0.0.1\n",
        encoding="utf-8",
    )
    _run_openssl(openssl_bin, ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(non_ca_leaf_key)], non_ca_dir)
    _run_openssl(
        openssl_bin,
        ["req", "-new", "-key", str(non_ca_leaf_key), "-subj", "/CN=localhost", "-out", str(non_ca_leaf_csr)],
        non_ca_dir,
    )
    _run_openssl(
        openssl_bin,
        [
            "x509",
            "-req",
            "-in",
            str(non_ca_leaf_csr),
            "-CA",
            str(non_ca_cert),
            "-CAkey",
            str(non_ca_key),
            "-CAcreateserial",
            "-out",
            str(non_ca_leaf_cert),
            "-days",
            "365",
            "-sha256",
            "-extfile",
            str(non_ca_leaf_ext),
        ],
        non_ca_dir,
    )
    non_ca_inter_cert = work_dir / "non_ca_fullchain.pem"
    non_ca_inter_cert.write_text(
        non_ca_leaf_cert.read_text(encoding="utf-8") + "\n" + non_ca_cert.read_text(encoding="utf-8"),
        encoding="utf-8",
    )

    # Self-signed leaf (not signed by trusted CA)
    ss_key = work_dir / "selfsigned.key"
    ss_cert = work_dir / "selfsigned.pem"
    ss_cnf = work_dir / "selfsigned.cnf"
    ss_cnf.write_text(
        """
[req]
distinguished_name = dn
x509_extensions = ext
prompt = no

[dn]
CN = localhost

[ext]
basicConstraints = critical, CA:FALSE
keyUsage = critical, digitalSignature
extendedKeyUsage = serverAuth
subjectAltName = DNS:localhost,IP:127.0.0.1
""".strip()
        + "\n",
        encoding="utf-8",
    )
    _run_openssl(openssl_bin, ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ss_key)], work_dir)
    _run_openssl(
        openssl_bin,
        [
            "req",
            "-new",
            "-x509",
            "-key",
            str(ss_key),
            "-out",
            str(ss_cert),
            "-days",
            "365",
            "-config",
            str(ss_cnf),
            "-extensions",
            "ext",
        ],
        work_dir,
    )

    # Leaf signed by a separate untrusted root CA
    evil_dir = work_dir / "untrusted_ca"
    _, _, evil_cnf = _init_ca(openssl_bin, evil_dir, "Wing Canary Untrusted Root CA")
    untrusted_cert, untrusted_key = _sign_leaf(
        openssl_bin,
        evil_dir,
        evil_cnf,
        "untrusted",
        "localhost",
        "DNS:localhost,IP:127.0.0.1",
        "20250101000000Z",
        "20350101000000Z",
    )

    return LocalPkiBundle(
        ca_cert=ca_cert,
        valid_cert=valid_cert,
        valid_key=valid_key,
        expired_cert=expired_cert,
        expired_key=expired_key,
        wrong_host_cert=wrong_cert,
        wrong_host_key=wrong_key,
        self_signed_cert=ss_cert,
        self_signed_key=ss_key,
        untrusted_cert=untrusted_cert,
        untrusted_key=untrusted_key,
        weak_rsa_cert=weak_rsa_cert,
        weak_rsa_key=weak_rsa_key,
        client_eku_cert=client_eku_cert,
        client_eku_key=client_eku_key,
        not_yet_valid_cert=not_yet_valid_cert,
        not_yet_valid_key=not_yet_valid_key,
        ip_san_cert=ip_san_cert,
        ip_san_key=ip_san_key,
        wildcard_cert=wildcard_cert,
        wildcard_key=wildcard_key,
        two_tier_cert=two_tier_cert,
        two_tier_key=two_tier_key,
        non_ca_inter_cert=non_ca_inter_cert,
        non_ca_inter_key=non_ca_leaf_key,
        ed25519_cert=ed25519_cert,
        ed25519_key=ed25519_key,
    )


class LoopbackTlsEndpoint:
    """Minimal threaded OpenSSL-backed TLS loopback server for offline canary scenarios."""

    def __init__(
        self,
        cert_file: Path,
        key_file: Path,
        min_ver: ssl.TLSVersion,
        max_ver: ssl.TLSVersion,
        alpn: list[str] | None = None,
        seclevel_zero: bool = False,
    ) -> None:
        self.ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        if seclevel_zero:
            self.ctx.set_ciphers("DEFAULT:@SECLEVEL=0")
        self.ctx.minimum_version = min_ver
        self.ctx.maximum_version = max_ver
        self.ctx.load_cert_chain(certfile=str(cert_file), keyfile=str(key_file))
        if alpn:
            self.ctx.set_alpn_protocols(alpn)
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(16)
        self.sock.settimeout(0.2)
        self.port: int = self.sock.getsockname()[1]
        self.running = True
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _handle_client(self, raw_conn: socket.socket) -> None:
        try:
            raw_conn.settimeout(2.0)
            with self.ctx.wrap_socket(raw_conn, server_side=True) as tls_conn:
                _ = tls_conn.recv(1024)
                tls_conn.sendall(
                    b"HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n"
                    b"Content-Length: 9\r\nConnection: close\r\n\r\nCANARY_OK"
                )
        except Exception:
            pass
        finally:
            try:
                raw_conn.close()
            except Exception:
                pass

    def _serve(self) -> None:
        while self.running:
            try:
                conn, _ = self.sock.accept()
            except TimeoutError:
                continue
            except OSError:
                break
            threading.Thread(target=self._handle_client, args=(conn,), daemon=True).start()

    def close(self) -> None:
        self.running = False
        try:
            self.sock.close()
        except Exception:
            pass


def query_backends(exe: Path, env: dict[str, str]) -> dict[str, bool]:
    res = subprocess.run(
        [str(exe), "backends"],
        cwd=str(ROOT_DIR),
        env=env,
        capture_output=True,
        text=True,
        timeout=10.0,
        check=False,
    )
    out = {"pure": False, "openssl": False, "schannel": False, "secure_transport": False}
    for line in res.stdout.splitlines():
        if line.startswith("BACKENDS\t"):
            for tok in line.split("\t")[1:]:
                if "=" in tok:
                    k, v = tok.split("=", 1)
                    out[k] = v == "1"
    return out


def invoke_probe(
    exe: Path,
    env: dict[str, str],
    backend: str,
    min_ver: str,
    host: str,
    port: int,
    sni: str,
    ca_path: str,
    alpn: str,
) -> tuple[str, str, str, int]:
    res = subprocess.run(
        [str(exe), "probe", backend, min_ver, host, str(port), sni, ca_path, alpn],
        cwd=str(ROOT_DIR),
        env=env,
        capture_output=True,
        text=True,
        timeout=15.0,
        check=False,
    )
    for line in res.stdout.splitlines():
        if line.startswith("CANARY\t"):
            cols = line.split("\t")
            if len(cols) >= 5:
                return cols[1], cols[2], cols[3], int(cols[4])
    return "ProcessError", backend, "-", 0


def run_offline_matrix(rebuild: bool = False) -> int:
    openssl_bin = find_openssl_cli()
    if not openssl_bin:
        print("[!] openssl CLI not found; required to generate offline local CA matrix.", file=sys.stderr)
        return 1

    exe = ensure_canary_binary(force_rebuild=rebuild)
    env = prepare_runtime_env()
    avail = query_backends(exe, env)
    print(
        f"[*] TLS Backend availability: pure={avail['pure']} "
        f"openssl={avail['openssl']} schannel={avail['schannel']}"
    )

    passed = 0
    failed = 0

    def check(ok: bool, name: str, detail: str = "") -> None:
        nonlocal passed, failed
        if ok:
            passed += 1
            print(f"  [PASS] {name}")
        else:
            failed += 1
            print(f"  [FAIL] {name} ({detail})")

    with tempfile.TemporaryDirectory(prefix="wing_badssl_offline_") as td:
        pki = generate_local_pki(Path(td), openssl_bin)
        servers: dict[str, LoopbackTlsEndpoint] = {
            "valid_tls13": LoopbackTlsEndpoint(
                pki.valid_cert, pki.valid_key, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3, ["h2", "http/1.1"]
            ),
            "tls12_only": LoopbackTlsEndpoint(
                pki.valid_cert, pki.valid_key, ssl.TLSVersion.TLSv1_2, ssl.TLSVersion.TLSv1_2, ["http/1.1"]
            ),
            "expired": LoopbackTlsEndpoint(
                pki.expired_cert, pki.expired_key, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3
            ),
            "wrong_host": LoopbackTlsEndpoint(
                pki.wrong_host_cert, pki.wrong_host_key, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3
            ),
            "self_signed": LoopbackTlsEndpoint(
                pki.self_signed_cert, pki.self_signed_key, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3
            ),
            "untrusted_root": LoopbackTlsEndpoint(
                pki.untrusted_cert, pki.untrusted_key, ssl.TLSVersion.TLSv1_3, ssl.TLSVersion.TLSv1_3
            ),
            "weak_rsa1024": LoopbackTlsEndpoint(
                pki.weak_rsa_cert,
                pki.weak_rsa_key,
                ssl.TLSVersion.TLSv1_3,
                ssl.TLSVersion.TLSv1_3,
                seclevel_zero=True,
            ),
            "client_eku": LoopbackTlsEndpoint(
                pki.client_eku_cert,
                pki.client_eku_key,
                ssl.TLSVersion.TLSv1_3,
                ssl.TLSVersion.TLSv1_3,
            ),
            "not_yet_valid": LoopbackTlsEndpoint(
                pki.not_yet_valid_cert,
                pki.not_yet_valid_key,
                ssl.TLSVersion.TLSv1_3,
                ssl.TLSVersion.TLSv1_3,
            ),
            "ip_san": LoopbackTlsEndpoint(
                pki.ip_san_cert,
                pki.ip_san_key,
                ssl.TLSVersion.TLSv1_3,
                ssl.TLSVersion.TLSv1_3,
            ),
            "wildcard": LoopbackTlsEndpoint(
                pki.wildcard_cert,
                pki.wildcard_key,
                ssl.TLSVersion.TLSv1_3,
                ssl.TLSVersion.TLSv1_3,
            ),
            "two_tier": LoopbackTlsEndpoint(
                pki.two_tier_cert,
                pki.two_tier_key,
                ssl.TLSVersion.TLSv1_3,
                ssl.TLSVersion.TLSv1_3,
            ),
            "non_ca_inter": LoopbackTlsEndpoint(
                pki.non_ca_inter_cert,
                pki.non_ca_inter_key,
                ssl.TLSVersion.TLSv1_3,
                ssl.TLSVersion.TLSv1_3,
            ),
            "ed25519": LoopbackTlsEndpoint(
                pki.ed25519_cert,
                pki.ed25519_key,
                ssl.TLSVersion.TLSv1_3,
                ssl.TLSVersion.TLSv1_3,
            ),
        }

        try:
            print("\nExecuting Offline Local CA TLS Canary Matrix...")
            ca_str = str(pki.ca_cert)

            # 1. PureGoose TLS 1.3 Matrix (16 checks)
            st, act, alpn, app_n = invoke_probe(
                exe, env, "pure", "tls13", "127.0.0.1", servers["valid_tls13"].port, "localhost", ca_str, "h2,http/1.1"
            )
            check(
                st == "Ok" and act == "pure" and alpn == "h2" and app_n > 0,
                "PureGoose: valid local CA cert + matching SAN + ALPN h2 (TLS 1.3)",
                f"st={st} act={act} alpn={alpn} app={app_n}",
            )
            for label, srv_key in (
                ("expired cert -> VerifyError", "expired"),
                ("not-yet-valid cert -> VerifyError", "not_yet_valid"),
                ("wrong hostname -> VerifyError", "wrong_host"),
                ("self-signed cert -> VerifyError", "self_signed"),
                ("untrusted root CA -> VerifyError", "untrusted_root"),
                ("weak 1024-bit RSA cert -> VerifyError", "weak_rsa1024"),
                ("clientAuth-only EKU cert -> VerifyError", "client_eku"),
                ("non-CA intermediate cert -> VerifyError", "non_ca_inter"),
            ):
                st, act, _, _ = invoke_probe(
                    exe, env, "pure", "tls13", "127.0.0.1", servers[srv_key].port, "localhost", ca_str, "-"
                )
                check(st == "VerifyError", f"PureGoose: {label}", f"st={st} act={act}")

            st, act, _, app_n = invoke_probe(
                exe, env, "pure", "tls13", "127.0.0.1", servers["ip_san"].port, "127.0.0.1", ca_str, "-"
            )
            check(
                st == "Ok" and act == "pure" and app_n > 0,
                "PureGoose: IP SAN 127.0.0.1 matches peer certificate",
                f"st={st} act={act} app={app_n}",
            )
            st, act, _, app_n = invoke_probe(
                exe, env, "pure", "tls13", "127.0.0.1", servers["wildcard"].port, "sub.wing.local", ca_str, "-"
            )
            check(
                st == "Ok" and act == "pure" and app_n > 0,
                "PureGoose: wildcard SAN *.wing.local matches single label",
                f"st={st} act={act} app={app_n}",
            )
            st, act, _, _ = invoke_probe(
                exe, env, "pure", "tls13", "127.0.0.1", servers["wildcard"].port, "a.b.wing.local", ca_str, "-"
            )
            check(
                st == "VerifyError",
                "PureGoose: wildcard SAN *.wing.local rejects multi-label subdomain",
                f"st={st} act={act}",
            )
            st, act, _, app_n = invoke_probe(
                exe, env, "pure", "tls13", "127.0.0.1", servers["two_tier"].port, "localhost", ca_str, "-"
            )
            check(
                st == "Ok" and act == "pure" and app_n > 0,
                "PureGoose: two-tier Root -> Intermediate CA chain accepted",
                f"st={st} act={act} app={app_n}",
            )
            st, act, _, app_n = invoke_probe(
                exe, env, "pure", "tls13", "127.0.0.1", servers["ed25519"].port, "localhost", ca_str, "-"
            )
            check(
                st == "Ok" and act == "pure" and app_n > 0,
                "PureGoose: Ed25519 leaf certificate chain verified",
                f"st={st} act={act} app={app_n}",
            )
            st, act, alpn, app_n = invoke_probe(
                exe, env, "pure", "tls13", "127.0.0.1", servers["valid_tls13"].port, "localhost", ca_str, "http/1.1"
            )
            check(
                st == "Ok" and act == "pure" and alpn == "http/1.1" and app_n > 0,
                "PureGoose: ALPN http/1.1 preference honored (TLS 1.3)",
                f"st={st} act={act} alpn={alpn} app={app_n}",
            )

            st, act, _, _ = invoke_probe(
                exe, env, "pure", "tls13", "127.0.0.1", servers["tls12_only"].port, "localhost", ca_str, "-"
            )
            check(
                st != "Ok" and st in ("HandshakeError", "Error", "Closed"),
                "PureGoose: strict TLS 1.3 rejects TLS 1.2-only peer",
                f"st={st} act={act}",
            )

            # 2. SystemOpenSsl Matrix (7 checks when OpenSSL library is available)
            if avail["openssl"]:
                st, act, alpn, app_n = invoke_probe(
                    exe, env, "openssl", "tls13", "127.0.0.1", servers["valid_tls13"].port, "localhost", ca_str, "h2,http/1.1"
                )
                check(
                    st == "Ok" and act == "openssl" and alpn == "h2" and app_n > 0,
                    "SystemOpenSsl: valid local CA cert + matching SAN + ALPN h2 (TLS 1.3)",
                    f"st={st} act={act} alpn={alpn} app={app_n}",
                )
                for label, srv_key in (
                    ("expired cert -> VerifyError", "expired"),
                    ("wrong hostname -> VerifyError", "wrong_host"),
                    ("self-signed cert -> VerifyError", "self_signed"),
                    ("untrusted root CA -> VerifyError", "untrusted_root"),
                ):
                    st, act, _, _ = invoke_probe(
                        exe, env, "openssl", "tls13", "127.0.0.1", servers[srv_key].port, "localhost", ca_str, "-"
                    )
                    check(st == "VerifyError", f"SystemOpenSsl: {label}", f"st={st} act={act}")

                st, act, _, _ = invoke_probe(
                    exe, env, "openssl", "tls13", "127.0.0.1", servers["tls12_only"].port, "localhost", ca_str, "-"
                )
                check(
                    st in ("HandshakeError", "Error", "Closed"),
                    "SystemOpenSsl: default TlsMinVersion.Tls13 rejects TLS 1.2-only peer",
                    f"st={st} act={act}",
                )

                st, act, alpn, app_n = invoke_probe(
                    exe, env, "openssl", "tls12", "127.0.0.1", servers["tls12_only"].port, "localhost", ca_str, "http/1.1"
                )
                check(
                    st == "Ok" and act == "openssl" and app_n > 0,
                    "SystemOpenSsl: opt-in TlsMinVersion.Tls12 succeeds against TLS 1.2-only peer",
                    f"st={st} act={act} alpn={alpn} app={app_n}",
                )

            # 3. SystemSchannel Matrix (2 checks on Windows)
            if avail["schannel"]:
                st, act, _, _ = invoke_probe(
                    exe, env, "schannel", "tls13", "127.0.0.1", servers["self_signed"].port, "localhost", "-", "-"
                )
                check(
                    st in ("VerifyError", "HandshakeError"),
                    "SystemSchannel: untrusted self-signed cert rejected fail-closed",
                    f"st={st} act={act}",
                )
                st, act, _, _ = invoke_probe(
                    exe, env, "schannel", "tls13", "127.0.0.1", servers["tls12_only"].port, "localhost", "-", "-"
                )
                check(
                    st != "Ok",
                    "SystemSchannel: default TlsMinVersion.Tls13 rejects TLS 1.2-only peer",
                    f"st={st} act={act}",
                )
        finally:
            for srv in servers.values():
                srv.close()

    total = passed + failed
    print(f"\nCompleted: {passed}/{total} passed, {failed} failed.")
    return 0 if failed == 0 and total > 0 else 1


def find_system_ca_bundle() -> str:
    paths = ssl.get_default_verify_paths()
    if paths.cafile and Path(paths.cafile).is_file():
        return paths.cafile
    for cand in (
        "/etc/ssl/certs/ca-certificates.crt",
        "/etc/pki/tls/certs/ca-bundle.crt",
        r"C:\Program Files\Git\mingw64\etc\ssl\certs\ca-bundle.crt",
        r"C:\Program Files\Git\usr\ssl\certs\ca-bundle.crt",
    ):
        if Path(cand).is_file():
            return cand
    return "-"


def run_live_badssl(rebuild: bool = False) -> int:
    exe = ensure_canary_binary(force_rebuild=rebuild)
    env = prepare_runtime_env()
    avail = query_backends(exe, env)
    ca_bundle = find_system_ca_bundle()
    print(
        f"[*] Live badssl.com Canary (backends: pure={avail['pure']} "
        f"openssl={avail['openssl']} schannel={avail['schannel']}, ca={ca_bundle})"
    )

    targets = [
        ("tls-v1-3.badssl.com", 1013, "tls13", "Ok", "TLS 1.3 valid host"),
        ("tls-v1-2.badssl.com", 1012, "tls13", "HandshakeError", "TLS 1.2 rejected under default Tls13"),
        ("tls-v1-2.badssl.com", 1012, "tls12", "Ok", "TLS 1.2 accepted with opt-in Tls12"),
        ("expired.badssl.com", 443, "tls13", "VerifyError", "Expired certificate rejected"),
        ("wrong.host.badssl.com", 443, "tls13", "VerifyError", "Wrong hostname rejected"),
        ("self-signed.badssl.com", 443, "tls13", "VerifyError", "Self-signed certificate rejected"),
        ("untrusted-root.badssl.com", 443, "tls13", "VerifyError", "Untrusted root CA rejected"),
    ]

    backends = [b for b in ("pure", "openssl", "schannel") if avail.get(b, False)]
    passed = 0
    failed = 0
    for backend in backends:
        for host, port, min_ver, expect_st, desc in targets:
            if backend == "pure" and min_ver == "tls12":
                continue
            ca_arg = ca_bundle if backend == "pure" else "-"
            if backend == "pure" and ca_arg == "-":
                continue
            st, act, alpn, app_n = invoke_probe(
                exe, env, backend, min_ver, host, port, host, ca_arg, "http/1.1"
            )
            ok = st == expect_st if expect_st == "Ok" else (st != "Ok" and st != "ConnectError")
            if ok:
                passed += 1
                print(f"  [PASS] [{backend:8s}] {host}:{port} ({min_ver}) -> {st} ({desc})")
            else:
                failed += 1
                print(
                    f"  [FAIL] [{backend:8s}] {host}:{port} ({min_ver}) -> {st} "
                    f"(want {expect_st}, act={act}, alpn={alpn}, app={app_n})"
                )

    total = passed + failed
    print(f"\nCompleted live badssl.com canary: {passed}/{total} passed, {failed} failed.")
    return 0 if failed == 0 and total > 0 else 1


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TLS Interop Canary (badssl.com live + offline local CA matrix) for goose-wing"
    )
    parser.add_argument(
        "--offline",
        action="store_true",
        help="Run deterministic offline local CA matrix (no internet required)",
    )
    parser.add_argument(
        "--live",
        action="store_true",
        help="Run live public badssl.com interop matrix (requires internet)",
    )
    parser.add_argument(
        "--docker",
        action="store_true",
        help="Run offline TLS canary suite inside Docker",
    )
    parser.add_argument("--rebuild", action="store_true", help="Force rebuild canary probe binary")
    args = parser.parse_args()

    if args.docker:
        compose_file = TOOLS_DIR / "badssl_canary" / "docker-compose.yml"
        cmd = [
            "docker",
            "compose",
            "-f",
            str(compose_file),
            "up",
            "--build",
            "--abort-on-container-exit",
            "--exit-code-from",
            "badssl-canary",
        ]
        print(f"[*] Running TLS canary via docker compose ({compose_file.name})...")
        sys.exit(subprocess.run(cmd, check=False, cwd=str(ROOT_DIR)).returncode)

    if args.live:
        sys.exit(run_live_badssl(rebuild=args.rebuild))

    sys.exit(run_offline_matrix(rebuild=args.rebuild))


if __name__ == "__main__":
    main()
