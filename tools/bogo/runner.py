#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
BoGo TLS 1.3 Protocol Test Suite Runner for goose-wing.
Supports `--local` (builds `tools/bogo/shim.goose` and executes 20+ BoGo-style TLS 1.3
conformance, downgrade, alert, ALPN, KeyUpdate, and mTLS tests against OpenSSL and
self-peer shims) and `--docker` (runs BoringSSL's Go BoGo runner against `bogo_shim`).
"""

from __future__ import annotations

import argparse
import io
import os
import shutil
import socket
import ssl
import struct
import subprocess
import sys
import tempfile
import threading
import time
from collections.abc import Callable
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
SHIM_SRC = TOOLS_DIR / "bogo" / "shim.goose"
SHIM_EXE = BIN_DIR / ("bogo_shim.exe" if sys.platform == "win32" else "bogo_shim")
BOGO_EXIT_UNIMPLEMENTED = 89


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


def ensure_shim_binary(force_rebuild: bool = False) -> Path:
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    if (
        not force_rebuild
        and SHIM_EXE.is_file()
        and SHIM_EXE.stat().st_mtime >= SHIM_SRC.stat().st_mtime
    ):
        return SHIM_EXE

    print(f"[*] Building BoGo shim: {SHIM_SRC.name} -> {SHIM_EXE.name}...")
    env = os.environ.copy()
    opt_flag = "-O2"
    if sys.platform == "win32":
        opt_flag = "-O0"
        if "GOOSE_CC" not in env:
            stack_cc = ROOT_DIR / "tools" / "gcc_stack.bat"
            if stack_cc.is_file():
                env["GOOSE_CC"] = str(stack_cc)
    cmd = ["goose", "build", opt_flag, "-o", str(SHIM_EXE), str(SHIM_SRC)]
    res = subprocess.run(
        cmd, check=False, cwd=str(ROOT_DIR), capture_output=True, text=True, env=env
    )
    if res.returncode != 0:
        print("[!] Failed to build bogo_shim:", file=sys.stderr)
        if res.stdout:
            print(res.stdout, file=sys.stderr)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        sys.exit(1)
    print(f"[+] Built {SHIM_EXE.name}")
    return SHIM_EXE


@dataclass
class BogoPki:
    ca_cert: Path
    srv_cert: Path
    srv_key: Path
    cli_cert: Path
    cli_key: Path
    self_signed_cert: Path
    self_signed_key: Path


def _run_openssl(openssl_bin: str, args: list[str], cwd: Path) -> None:
    res = subprocess.run(
        [openssl_bin, *args], cwd=str(cwd), capture_output=True, text=True, check=False
    )
    if res.returncode != 0:
        raise RuntimeError(f"openssl {' '.join(args)} failed:\n{res.stderr}\n{res.stdout}")


def _sign_ecdsa_leaf(
    openssl_bin: str,
    ca_dir: Path,
    ca_cnf: Path,
    name: str,
    cn: str,
    san: str,
    eku: str,
) -> tuple[Path, Path]:
    key_p = ca_dir / f"{name}.key"
    csr_p = ca_dir / f"{name}.csr"
    cert_p = ca_dir / f"{name}.pem"
    ext_p = ca_dir / f"{name}.ext"
    ext_p.write_text(
        f"basicConstraints = critical, CA:FALSE\n"
        f"keyUsage = critical, digitalSignature\n"
        f"extendedKeyUsage = {eku}\n"
        f"subjectAltName = {san}\n",
        encoding="utf-8",
    )
    _run_openssl(
        openssl_bin,
        ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(key_p)],
        ca_dir,
    )
    _run_openssl(
        openssl_bin,
        ["req", "-new", "-key", str(key_p), "-subj", f"/CN={cn}", "-out", str(csr_p)],
        ca_dir,
    )
    _run_openssl(
        openssl_bin,
        [
            "ca", "-batch", "-config", str(ca_cnf),
            "-startdate", "20250101000000Z", "-enddate", "20350101000000Z",
            "-extfile", str(ext_p), "-in", str(csr_p), "-out", str(cert_p),
        ],
        ca_dir,
    )
    return cert_p, key_p


def generate_bogo_pki(work_dir: Path, openssl_bin: str) -> BogoPki:
    ca_dir = work_dir / "ca"
    ca_dir.mkdir(parents=True, exist_ok=True)
    (ca_dir / "newcerts").mkdir(exist_ok=True)
    (ca_dir / "index.txt").write_text("", encoding="utf-8")
    (ca_dir / "serial").write_text("1000\n", encoding="utf-8")
    ca_key, ca_cert, ca_cnf = ca_dir / "ca.key", ca_dir / "ca.pem", ca_dir / "ca.cnf"
    ca_cnf.write_text(
        f"[ca]\ndefault_ca = CA_default\n[CA_default]\ndir = {ca_dir.as_posix()}\n"
        "database = $dir/index.txt\nnew_certs_dir = $dir/newcerts\n"
        "certificate = $dir/ca.pem\nserial = $dir/serial\nprivate_key = $dir/ca.key\n"
        "default_md = sha256\npolicy = p_loose\nunique_subject = no\ncopy_extensions = none\n"
        "[p_loose]\ncommonName = supplied\n[req]\ndistinguished_name = dn\n"
        "x509_extensions = v3_ca\nprompt = no\n[dn]\nCN = Wing BoGo Local CA\n"
        "[v3_ca]\nbasicConstraints = critical, CA:TRUE\n"
        "keyUsage = critical, keyCertSign, cRLSign\nsubjectKeyIdentifier = hash\n",
        encoding="utf-8",
    )
    _run_openssl(
        openssl_bin,
        ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ca_key)],
        ca_dir,
    )
    _run_openssl(
        openssl_bin,
        [
            "req", "-new", "-x509", "-key", str(ca_key), "-out", str(ca_cert),
            "-days", "3650", "-config", str(ca_cnf), "-extensions", "v3_ca",
        ],
        ca_dir,
    )
    srv_cert, srv_key = _sign_ecdsa_leaf(
        openssl_bin, ca_dir, ca_cnf, "server", "localhost",
        "DNS:localhost,IP:127.0.0.1,IP:::1", "serverAuth",
    )
    cli_cert, cli_key = _sign_ecdsa_leaf(
        openssl_bin, ca_dir, ca_cnf, "client", "bogo-client",
        "DNS:client.local", "clientAuth",
    )
    ss_key, ss_cert, ss_cnf = work_dir / "ss.key", work_dir / "ss.pem", work_dir / "ss.cnf"
    ss_cnf.write_text(
        "[req]\ndistinguished_name = dn\nx509_extensions = ext\nprompt = no\n"
        "[dn]\nCN = localhost\n[ext]\nbasicConstraints = critical, CA:FALSE\n"
        "keyUsage = critical, digitalSignature\nextendedKeyUsage = serverAuth\n"
        "subjectAltName = DNS:localhost,IP:127.0.0.1\n",
        encoding="utf-8",
    )
    _run_openssl(
        openssl_bin,
        ["ecparam", "-name", "prime256v1", "-genkey", "-noout", "-out", str(ss_key)],
        work_dir,
    )
    _run_openssl(
        openssl_bin,
        [
            "req", "-new", "-x509", "-key", str(ss_key), "-out", str(ss_cert),
            "-days", "365", "-config", str(ss_cnf), "-extensions", "ext",
        ],
        work_dir,
    )
    return BogoPki(ca_cert, srv_cert, srv_key, cli_cert, cli_key, ss_cert, ss_key)


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def _xor_bogo(data: bytes) -> bytes:
    return bytes(b ^ 0xFF for b in data)


def _open_listener(ipv6: bool = False) -> tuple[socket.socket, int]:
    family = socket.AF_INET6 if ipv6 else socket.AF_INET
    bind_host = "::1" if ipv6 else "127.0.0.1"
    lsock = socket.socket(family, socket.SOCK_STREAM)
    lsock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    lsock.bind((bind_host, 0))
    lsock.listen(4)
    lsock.settimeout(6.0)
    return lsock, int(lsock.getsockname()[1])


def run_bogo_vs_openssl_peer(
    exe: Path,
    env: dict[str, str],
    shim_id: int,
    shim_args: list[str],
    ctx: ssl.SSLContext,
    peer_is_server: bool,
    payload: bytes = b"bogo-tls13-echo-check",
    ipv6: bool = False,
    peer_sni: str | None = None,
) -> tuple[int, bool, int | None, str]:
    lsock, port = _open_listener(ipv6=ipv6)
    state: dict[str, object] = {"ok": False, "got_id": None, "detail": ""}

    def peer_worker() -> None:
        try:
            conn, _ = lsock.accept()
        except OSError as exc:
            state["detail"] = f"accept:{exc}"
            return
        try:
            conn.settimeout(4.0)
            hdr = _recv_exact(conn, 8)
            if len(hdr) != 8:
                state["detail"] = f"short_hdr:{len(hdr)}"
                return
            got_id = struct.unpack("<Q", hdr)[0]
            state["got_id"] = got_id
            kwargs: dict[str, object] = {"server_side": peer_is_server}
            if not peer_is_server and peer_sni:
                kwargs["server_hostname"] = peer_sni
            with ctx.wrap_socket(conn, **kwargs) as tls_sock:  # type: ignore[arg-type]
                tls_sock.settimeout(4.0)
                tls_sock.sendall(payload)
                resp = _recv_exact(tls_sock, len(payload))
                if resp == _xor_bogo(payload):
                    state["ok"] = True
                    state["detail"] = f"ver={tls_sock.version()} alpn={tls_sock.selected_alpn_protocol()}"
                else:
                    state["detail"] = f"echo_mismatch:{resp.hex()}"
                try:
                    tls_sock.unwrap()
                except Exception:
                    pass
        except Exception as exc:
            state["detail"] = f"tls:{exc}"
        finally:
            try:
                conn.close()
            except Exception:
                pass

    th = threading.Thread(target=peer_worker, daemon=True)
    th.start()
    cmd = [str(exe), "-port", str(port), "-shim-id", str(shim_id), *shim_args]
    if ipv6:
        cmd.append("-ipv6")
    try:
        res = subprocess.run(
            cmd, cwd=str(ROOT_DIR), env=env, capture_output=True, text=True, timeout=12.0, check=False
        )
    finally:
        th.join(timeout=5.0)
        lsock.close()
    detail = str(state["detail"])
    if res.stdout.strip():
        detail = f"{detail} | shim={res.stdout.strip()}"
    return res.returncode, bool(state["ok"]), state["got_id"], detail  # type: ignore[return-value]


def run_bogo_self_peer(
    exe: Path,
    env: dict[str, str],
    cli_id: int,
    srv_id: int,
    cli_args: list[str],
    srv_args: list[str],
    corrupt_c2s_app_record: int = 0,
) -> tuple[int, int, bool, str]:
    """Bridges two `bogo_shim` instances via BoGo shim-id relay sockets."""
    cli_lsock, cli_port = _open_listener()
    srv_lsock, srv_port = _open_listener()
    ids_ok = {"cli": False, "srv": False, "detail": ""}

    def accept_with_id(ls: socket.socket, exp_id: int, key: str) -> socket.socket | None:
        try:
            c, _ = ls.accept()
            c.settimeout(5.0)
            hdr = _recv_exact(c, 8)
            if len(hdr) == 8 and struct.unpack("<Q", hdr)[0] == exp_id:
                ids_ok[key] = True
            return c
        except Exception as exc:
            ids_ok["detail"] = f"{key}:{exc}"
            return None

    def pump(src: socket.socket, dst: socket.socket, corrupt_nth_app: int) -> None:
        app_seen = 0
        try:
            while True:
                data = src.recv(16384)
                if not data:
                    break
                if corrupt_nth_app > 0 and len(data) >= 22 and data[0] == 0x17:
                    app_seen += 1
                    if app_seen == corrupt_nth_app:
                        mut = bytearray(data)
                        mut[-1] ^= 0xFF
                        data = bytes(mut)
                dst.sendall(data)
        except Exception:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except Exception:
                pass

    cli_proc = subprocess.Popen(
        [str(exe), "-port", str(cli_port), "-shim-id", str(cli_id), *cli_args],
        cwd=str(ROOT_DIR), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    srv_proc = subprocess.Popen(
        [str(exe), "-port", str(srv_port), "-shim-id", str(srv_id), "-is-server", *srv_args],
        cwd=str(ROOT_DIR), env=env, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
    )
    c_sock = accept_with_id(cli_lsock, cli_id, "cli")
    s_sock = accept_with_id(srv_lsock, srv_id, "srv")
    try:
        if c_sock and s_sock:
            t1 = threading.Thread(
                target=pump, args=(c_sock, s_sock, corrupt_c2s_app_record), daemon=True
            )
            t2 = threading.Thread(target=pump, args=(s_sock, c_sock, 0), daemon=True)
            t1.start()
            t2.start()
            t1.join(timeout=8.0)
            t2.join(timeout=8.0)
        cli_out, _ = cli_proc.communicate(timeout=8.0)
        srv_out, _ = srv_proc.communicate(timeout=8.0)
    finally:
        for sock_obj in (c_sock, s_sock, cli_lsock, srv_lsock):
            if sock_obj:
                try:
                    sock_obj.close()
                except Exception:
                    pass
    detail = f"cli={cli_out.strip()} srv={srv_out.strip()} {ids_ok['detail']}".strip()
    return cli_proc.returncode, srv_proc.returncode, bool(ids_ok["cli"] and ids_ok["srv"]), detail


def run_bogo_raw_peer(
    exe: Path,
    env: dict[str, str],
    shim_id: int,
    shim_args: list[str],
    handler: Callable[[socket.socket], None],
) -> tuple[int, int | None, str]:
    lsock, port = _open_listener()
    got: dict[str, object] = {"id": None, "err": ""}

    def worker() -> None:
        try:
            conn, _ = lsock.accept()
        except OSError as exc:
            got["err"] = str(exc)
            return
        try:
            conn.settimeout(3.0)
            hdr = _recv_exact(conn, 8)
            if len(hdr) == 8:
                got["id"] = struct.unpack("<Q", hdr)[0]
                handler(conn)
        except Exception as exc:
            got["err"] = str(exc)
        finally:
            try:
                conn.close()
            except Exception:
                pass

    th = threading.Thread(target=worker, daemon=True)
    th.start()
    try:
        res = subprocess.run(
            [str(exe), "-port", str(port), "-shim-id", str(shim_id), *shim_args],
            cwd=str(ROOT_DIR), env=env, capture_output=True, text=True, timeout=10.0, check=False,
        )
    finally:
        th.join(timeout=4.0)
        lsock.close()
    detail = f"shim={res.stdout.strip()} peer={got['err']}".strip()
    return res.returncode, got["id"], detail  # type: ignore[return-value]


def _build_downgrade_server_hello(sentinel: bytes) -> bytes:
    body = bytearray(b"\x03\x03")
    body.extend(b"\x22" * 24 + sentinel)
    body.append(0)
    body.extend(b"\x13\x01\x00")
    ext = b"\x00\x2b\x00\x02\x03\x04\x00\x33\x00\x24\x00\x1d\x00\x20" + (b"\x09" + b"\x00" * 31)
    body.extend(struct.pack(">H", len(ext)) + ext)
    hs = bytes([0x02, (len(body) >> 16) & 0xFF, (len(body) >> 8) & 0xFF, len(body) & 0xFF]) + bytes(body)
    return bytes([0x16, 0x03, 0x03]) + struct.pack(">H", len(hs)) + hs


def _build_valid_tls13_client_hello(sni: str = "localhost") -> bytes:
    exts = bytearray()
    if sni:
        sb = sni.encode("ascii")
        se = b"\x00" + struct.pack(">H", len(sb)) + sb
        sl = struct.pack(">H", len(se)) + se
        exts.extend(struct.pack(">HH", 0, len(sl)) + sl)
    exts.extend(b"\x00\x2b\x00\x03\x02\x03\x04")  # supported_versions = 0x0304
    exts.extend(b"\x00\x0a\x00\x04\x00\x02\x00\x1d")  # supported_groups = x25519
    exts.extend(b"\x00\x0d\x00\x06\x00\x04\x04\x03\x08\x07")  # sig_algs = ecdsa_p256, ed25519
    ks_entry = b"\x00\x1d\x00\x20" + (b"\x09" + b"\x00" * 31)
    ks_list = struct.pack(">H", len(ks_entry)) + ks_entry
    exts.extend(struct.pack(">HH", 51, len(ks_list)) + ks_list)
    ch = bytearray(b"\x03\x03" + os.urandom(32) + b"\x00")
    ch.extend(b"\x00\x02\x13\x01\x01\x00")
    ch.extend(struct.pack(">H", len(exts)) + bytes(exts))
    hs = bytes([0x01, (len(ch) >> 16) & 0xFF, (len(ch) >> 8) & 0xFF, len(ch) & 0xFF]) + bytes(ch)
    return bytes([0x16, 0x03, 0x01]) + struct.pack(">H", len(hs)) + hs


def _make_server_ctx(
    cert: Path,
    key: Path,
    min_ver: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3,
    max_ver: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3,
    alpn: list[str] | None = None,
    client_ca: Path | None = None,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
    ctx.minimum_version = min_ver
    ctx.maximum_version = max_ver
    ctx.load_cert_chain(certfile=str(cert), keyfile=str(key))
    if alpn:
        ctx.set_alpn_protocols(alpn)
    if client_ca is not None:
        ctx.load_verify_locations(cafile=str(client_ca))
        ctx.verify_mode = ssl.CERT_REQUIRED
        # Isolate mTLS Certificate/CertificateVerify interop from OpenSSL's
        # >256-byte post-handshake mTLS session tickets.
        ctx.num_tickets = 0
    return ctx


def _make_client_ctx(
    ca_cert: Path | None = None,
    min_ver: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3,
    max_ver: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3,
    alpn: list[str] | None = None,
    client_cert: Path | None = None,
    client_key: Path | None = None,
) -> ssl.SSLContext:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.minimum_version = min_ver
    ctx.maximum_version = max_ver
    if ca_cert is not None:
        ctx.load_verify_locations(cafile=str(ca_cert))
    else:
        ctx.check_hostname = False
        ctx.verify_mode = ssl.CERT_NONE
    if alpn:
        ctx.set_alpn_protocols(alpn)
    if client_cert is not None and client_key is not None:
        ctx.load_cert_chain(certfile=str(client_cert), keyfile=str(client_key))
    return ctx


def _run_shim_direct(exe: Path, env: dict[str, str], args: list[str]) -> tuple[int, str]:
    res = subprocess.run(
        [str(exe), *args],
        cwd=str(ROOT_DIR), env=env, capture_output=True, text=True, timeout=10.0, check=False,
    )
    return res.returncode, (res.stdout + res.stderr).strip()


def _supports_ipv6_loopback() -> bool:
    try:
        with socket.socket(socket.AF_INET6, socket.SOCK_STREAM) as s:
            s.bind(("::1", 0))
            return True
    except OSError:
        return False


def _run_core_bogo_tests(
    exe: Path,
    env: dict[str, str],
    pki: BogoPki,
    check: Callable[[bool, str, str], None],
) -> None:
    srv_ctx = _make_server_ctx(pki.srv_cert, pki.srv_key, alpn=["h2", "http/1.1"])
    cli_ctx = _make_client_ctx(ca_cert=pki.ca_cert, alpn=["h2", "http/1.1"])

    # 1. PureGoose Client <-> OpenSSL TLS 1.3 Server (shim-id LE + XOR-0xFF echo)
    rc, ok, gid, det = run_bogo_vs_openssl_peer(
        exe, env, 1001,
        ["-host-name", "localhost", "-trust-cert", str(pki.ca_cert), "-verify-peer"],
        srv_ctx, peer_is_server=True,
    )
    check(rc == 0 and ok and gid == 1001, "BoGo/01 PureGoose client TLS 1.3 + shim-id + XOR-0xFF", det)

    # 2. PureGoose Client IPv6 ([::1] + -ipv6)
    if _supports_ipv6_loopback():
        rc, ok, gid, det = run_bogo_vs_openssl_peer(
            exe, env, 1002,
            ["-host-name", "localhost", "-trust-cert", str(pki.ca_cert), "-verify-peer"],
            srv_ctx, peer_is_server=True, ipv6=True,
        )
        check(rc == 0 and ok and gid == 1002, "BoGo/02 PureGoose client over IPv6 ([::1] -ipv6)", det)

    # 3. PureGoose Server (-is-server) <-> OpenSSL TLS 1.3 Client
    rc, ok, gid, det = run_bogo_vs_openssl_peer(
        exe, env, 1003,
        ["-is-server", "-cert-file", str(pki.srv_cert), "-key-file", str(pki.srv_key)],
        cli_ctx, peer_is_server=False, peer_sni="localhost",
    )
    check(rc == 0 and ok and gid == 1003, "BoGo/03 PureGoose server TLS 1.3 + ECDSA cert + echo", det)

    # 4. Self-peer: PureGoose Client <-> PureGoose Server
    c_rc, s_rc, ids, det = run_bogo_self_peer(
        exe, env, 1004, 1005,
        ["-host-name", "localhost", "-trust-cert", str(pki.ca_cert), "-verify-peer", "-shim-writes-first"],
        ["-cert-file", str(pki.srv_cert), "-key-file", str(pki.srv_key)],
    )
    check(c_rc == 0 and s_rc == 0 and ids, "BoGo/04 Self-peer PureGoose client <-> PureGoose server", det)

    # 5. PureGoose Client ALPN wire-format negotiation + -expect-alpn h2
    rc, ok, gid, det = run_bogo_vs_openssl_peer(
        exe, env, 1006,
        [
            "-host-name", "localhost", "-trust-cert", str(pki.ca_cert),
            "-alpn-protos", "\x02h2\x08http/1.1", "-expect-alpn", "h2",
        ],
        srv_ctx, peer_is_server=True,
    )
    check(rc == 0 and ok and gid == 1006, "BoGo/05 PureGoose client ALPN wire format + -expect-alpn h2", det)

    # 6. PureGoose Client ALPN mismatch (-expect-alpn h3 fails closed)
    rc, ok, gid, det = run_bogo_vs_openssl_peer(
        exe, env, 1007,
        [
            "-host-name", "localhost", "-trust-cert", str(pki.ca_cert),
            "-alpn-protos", "h2,http/1.1", "-expect-alpn", "h3",
        ],
        srv_ctx, peer_is_server=True,
    )
    check(rc != 0 and gid == 1007, "BoGo/06 PureGoose client -expect-alpn mismatch rejected", det)

    # 7. PureGoose Server ALPN negotiation (-alpn-protos + -expect-alpn h2)
    rc, ok, gid, det = run_bogo_vs_openssl_peer(
        exe, env, 1008,
        [
            "-is-server", "-cert-file", str(pki.srv_cert), "-key-file", str(pki.srv_key),
            "-alpn-protos", "h2,http/1.1", "-expect-alpn", "h2",
        ],
        cli_ctx, peer_is_server=False, peer_sni="localhost",
    )
    check(rc == 0 and ok and gid == 1008, "BoGo/07 PureGoose server ALPN h2 + -expect-alpn", det)

    # 8. PureGoose Client <-> PureGoose Server bidirectional KeyUpdate (RFC 8446 Section 4.6.3)
    c_rc, s_rc, ids, det = run_bogo_self_peer(
        exe, env, 1009, 1010,
        [
            "-host-name", "localhost", "-trust-cert", str(pki.ca_cert), "-verify-peer",
            "-key-update", "-shim-writes-first",
        ],
        ["-cert-file", str(pki.srv_cert), "-key-file", str(pki.srv_key)],
    )
    check(c_rc == 0 and s_rc == 0 and ids, "BoGo/08 PureGoose bidirectional KeyUpdate + post-ratchet echo", det)

    # 9. PureGoose Server initiates KeyUpdate(update_requested) -> PureGoose Client ratchets
    c_rc, s_rc, ids, det = run_bogo_self_peer(
        exe, env, 1011, 1012,
        ["-host-name", "localhost", "-trust-cert", str(pki.ca_cert), "-verify-peer", "-shim-writes-first"],
        ["-cert-file", str(pki.srv_cert), "-key-file", str(pki.srv_key), "-key-update"],
    )
    check(c_rc == 0 and s_rc == 0 and ids, "BoGo/09 PureGoose server-initiated KeyUpdate + post-ratchet echo", det)


def _run_security_bogo_tests(
    exe: Path,
    env: dict[str, str],
    pki: BogoPki,
    check: Callable[[bool, str, str], None],
) -> None:
    srv_ctx = _make_server_ctx(pki.srv_cert, pki.srv_key)
    ss_ctx = _make_server_ctx(pki.self_signed_cert, pki.self_signed_key)
    mtls_ctx = _make_server_ctx(pki.srv_cert, pki.srv_key, client_ca=pki.ca_cert)
    tls12_ctx = _make_server_ctx(
        pki.srv_cert, pki.srv_key, min_ver=ssl.TLSVersion.TLSv1_2, max_ver=ssl.TLSVersion.TLSv1_2
    )

    # 10. Untrusted self-signed cert rejected with -verify-peer
    rc, _, gid, det = run_bogo_vs_openssl_peer(
        exe, env, 2001,
        ["-host-name", "localhost", "-trust-cert", str(pki.ca_cert), "-verify-peer"],
        ss_ctx, peer_is_server=True,
    )
    check(rc != 0 and gid == 2001, "BoGo/10 PureGoose client rejects untrusted self-signed cert", det)

    # 11. Wrong hostname SAN rejected with -verify-peer
    rc, _, gid, det = run_bogo_vs_openssl_peer(
        exe, env, 2002,
        ["-host-name", "wrong.host.local", "-trust-cert", str(pki.ca_cert), "-verify-peer"],
        srv_ctx, peer_is_server=True,
    )
    check(rc != 0 and gid == 2002, "BoGo/11 PureGoose client rejects wrong hostname SAN", det)

    # 12. PureGoose Client mTLS succeeds against OpenSSL CERT_REQUIRED server
    rc, ok, gid, det = run_bogo_vs_openssl_peer(
        exe, env, 2003,
        [
            "-host-name", "localhost", "-trust-cert", str(pki.ca_cert), "-verify-peer",
            "-cert-file", str(pki.cli_cert), "-key-file", str(pki.cli_key),
        ],
        mtls_ctx, peer_is_server=True,
    )
    check(rc == 0 and ok and gid == 2003, "BoGo/12 PureGoose client mTLS succeeds (CERT_REQUIRED)", det)

    # 13. PureGoose Client without client cert rejected by mTLS server
    rc, ok, gid, det = run_bogo_vs_openssl_peer(
        exe, env, 2004,
        ["-host-name", "localhost", "-trust-cert", str(pki.ca_cert), "-verify-peer"],
        mtls_ctx, peer_is_server=True,
    )
    check((rc != 0 or not ok) and gid == 2004, "BoGo/13 PureGoose client without cert rejected by mTLS server", det)

    # 14. PureGoose Client rejects TLS 1.2-only server
    rc, ok, gid, det = run_bogo_vs_openssl_peer(
        exe, env, 2005,
        ["-host-name", "localhost", "-trust-cert", str(pki.ca_cert), "-verify-peer"],
        tls12_ctx, peer_is_server=True,
    )
    check(rc != 0 and not ok and gid == 2005, "BoGo/14 PureGoose client rejects TLS 1.2-only server", det)

    # 15. Exit code 89 (UNIMPLEMENTED) for legacy TLS <= 1.2 flags on PureGoose
    rc_max, d1 = _run_shim_direct(exe, env, ["-port", "1", "-max-version", "771"])
    rc_min, d2 = _run_shim_direct(exe, env, ["-port", "1", "-min-version", "769"])
    rc_scsv, d3 = _run_shim_direct(exe, env, ["-port", "1", "-fallback-scsv"])
    check(
        rc_max == BOGO_EXIT_UNIMPLEMENTED
        and rc_min == BOGO_EXIT_UNIMPLEMENTED
        and rc_scsv == BOGO_EXIT_UNIMPLEMENTED,
        "BoGo/15 PureGoose returns exit 89 (UNIMPLEMENTED) for legacy TLS <= 1.2 / fallback-scsv",
        f"max={rc_max}({d1}) min={rc_min}({d2}) scsv={rc_scsv}({d3})",
    )

    # 16-18. SystemOpenSsl backend checks (opt-in TLS 1.2, server mTLS, cross-backend self-peer)
    rc_o12, ok_o12, gid_o12, det_o12 = run_bogo_vs_openssl_peer(
        exe, env, 2006,
        [
            "-backend", "openssl", "-min-version", "771", "-max-version", "771",
            "-host-name", "localhost", "-trust-cert", str(pki.ca_cert), "-verify-peer",
        ],
        tls12_ctx, peer_is_server=True,
    )
    if rc_o12 != BOGO_EXIT_UNIMPLEMENTED:
        check(rc_o12 == 0 and ok_o12 and gid_o12 == 2006, "BoGo/16 SystemOpenSsl opt-in TLS 1.2 succeeds", det_o12)
        mtls_cli = _make_client_ctx(
            ca_cert=pki.ca_cert, client_cert=pki.cli_cert, client_key=pki.cli_key
        )
        rc_ms, ok_ms, gid_ms, det_ms = run_bogo_vs_openssl_peer(
            exe, env, 2007,
            [
                "-backend", "openssl", "-is-server", "-verify-peer",
                "-cert-file", str(pki.srv_cert), "-key-file", str(pki.srv_key),
                "-trust-cert", str(pki.ca_cert),
            ],
            mtls_cli, peer_is_server=False, peer_sni="localhost",
        )
        check(rc_ms == 0 and ok_ms and gid_ms == 2007, "BoGo/17 SystemOpenSsl server mTLS accepts valid client cert", det_ms)

        c_rc, s_rc, ids, det_cb = run_bogo_self_peer(
            exe, env, 2008, 2009,
            ["-host-name", "localhost", "-trust-cert", str(pki.ca_cert), "-verify-peer", "-shim-writes-first"],
            ["-backend", "openssl", "-cert-file", str(pki.srv_cert), "-key-file", str(pki.srv_key)],
        )
        check(c_rc == 0 and s_rc == 0 and ids, "BoGo/18 Cross-backend PureGoose client <-> SystemOpenSsl server", det_cb)


def _run_state_machine_bogo_tests(
    exe: Path,
    env: dict[str, str],
    pki: BogoPki,
    check: Callable[[bool, str, str], None],
) -> None:
    # 19. Downgrade sentinel DOWNGRD\x01 in ServerHello.random rejected
    def _send_dg1(conn: socket.socket) -> None:
        _ = conn.recv(4096)
        conn.sendall(_build_downgrade_server_hello(b"DOWNGRD\x01"))
        time.sleep(0.05)

    rc, gid, det = run_bogo_raw_peer(exe, env, 3001, ["-host-name", "localhost"], _send_dg1)
    check(rc != 0 and gid == 3001, "BoGo/19 PureGoose client rejects DOWNGRD\\x01 downgrade sentinel", det)

    # 20. Downgrade sentinel DOWNGRD\x00 (TLS 1.1) in ServerHello.random rejected
    def _send_dg0(conn: socket.socket) -> None:
        _ = conn.recv(4096)
        conn.sendall(_build_downgrade_server_hello(b"DOWNGRD\x00"))
        time.sleep(0.05)

    rc, gid, det = run_bogo_raw_peer(exe, env, 3002, ["-host-name", "localhost"], _send_dg0)
    check(rc != 0 and gid == 3002, "BoGo/20 PureGoose client rejects DOWNGRD\\x00 downgrade sentinel", det)

    # 21. Fatal TLS Alert (handshake_failure = 40) handled cleanly by client
    def _send_alert(conn: socket.socket) -> None:
        _ = conn.recv(4096)
        conn.sendall(b"\x15\x03\x03\x00\x02\x02\x28")
        time.sleep(0.05)

    rc, gid, det = run_bogo_raw_peer(exe, env, 3003, ["-host-name", "localhost"], _send_alert)
    check(rc != 0 and gid == 3003, "BoGo/21 PureGoose client aborts cleanly on fatal handshake_failure alert", det)

    # 22. Unexpected pre-handshake CCS rejected by PureGoose server
    def _send_bad_ccs(conn: socket.socket) -> None:
        conn.sendall(b"\x14\x03\x03\x00\x01\x02")
        time.sleep(0.05)

    rc, gid, det = run_bogo_raw_peer(
        exe, env, 3004,
        ["-is-server", "-cert-file", str(pki.srv_cert), "-key-file", str(pki.srv_key)],
        _send_bad_ccs,
    )
    check(rc != 0 and gid == 3004, "BoGo/22 PureGoose server rejects malformed CCS payload byte (0x02)", det)

    # 23. Unencrypted Finished sent after ServerHello rejected by PureGoose server
    def _send_plain_fin(conn: socket.socket) -> None:
        conn.sendall(_build_valid_tls13_client_hello("localhost"))
        _ = conn.recv(8192)
        plain_fin = b"\x16\x03\x03\x00\x24\x14\x00\x00\x20" + (b"\xAA" * 32)
        conn.sendall(plain_fin)
        time.sleep(0.05)

    rc, gid, det = run_bogo_raw_peer(
        exe, env, 3005,
        ["-is-server", "-cert-file", str(pki.srv_cert), "-key-file", str(pki.srv_key)],
        _send_plain_fin,
    )
    check(rc != 0 and gid == 3005, "BoGo/23 PureGoose server rejects unencrypted Finished after ServerHello", det)

    # 24. Corrupted AEAD record MAC in transit triggers fail-closed rejection
    c_rc, s_rc, ids, det = run_bogo_self_peer(
        exe, env, 3006, 3007,
        ["-host-name", "localhost", "-trust-cert", str(pki.ca_cert), "-verify-peer", "-shim-writes-first"],
        ["-cert-file", str(pki.srv_cert), "-key-file", str(pki.srv_key)],
        corrupt_c2s_app_record=1,
    )
    check(
        s_rc != 0 and c_rc != 0 and ids,
        "BoGo/24 Corrupted AEAD record MAC triggers fail-closed teardown",
        det,
    )


def run_local_suite(rebuild: bool = False) -> int:
    openssl_bin = find_openssl_cli()
    if not openssl_bin:
        print("[!] openssl CLI not found; required to generate local BoGo test PKI.", file=sys.stderr)
        return 1

    exe = ensure_shim_binary(force_rebuild=rebuild)
    env = prepare_runtime_env()
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

    print("\nExecuting Local BoGo TLS 1.3 Protocol Test Suite...")
    with tempfile.TemporaryDirectory(prefix="wing_bogo_local_") as td:
        pki = generate_bogo_pki(Path(td), openssl_bin)
        _run_core_bogo_tests(exe, env, pki, check)
        _run_security_bogo_tests(exe, env, pki, check)
        _run_state_machine_bogo_tests(exe, env, pki, check)

    total = passed + failed
    print(f"\nCompleted BoGo local suite: {passed}/{total} passed, {failed} failed.")
    return 0 if failed == 0 and total > 0 else 1


def run_docker_suite() -> int:
    compose_file = TOOLS_DIR / "bogo" / "docker-compose.yml"
    cmd = [
        "docker", "compose", "-f", str(compose_file),
        "up", "--build", "--abort-on-container-exit", "--exit-code-from", "bogo-runner",
    ]
    print(f"[*] Running upstream BoringSSL BoGo runner via {compose_file.name}...")
    return subprocess.run(cmd, check=False, cwd=str(ROOT_DIR)).returncode


def main() -> None:
    parser = argparse.ArgumentParser(description="BoGo TLS 1.3 protocol test runner for goose-wing")
    parser.add_argument(
        "--local",
        action="store_true",
        help="Build bogo_shim locally and run the local BoGo-style TLS 1.3 test matrix",
    )
    parser.add_argument(
        "--docker",
        action="store_true",
        help="Build and run BoringSSL's Go BoGo runner inside Docker",
    )
    parser.add_argument("--rebuild", action="store_true", help="Force rebuild bogo_shim binary")
    args = parser.parse_args()

    if args.docker:
        sys.exit(run_docker_suite())

    sys.exit(run_local_suite(rebuild=args.rebuild))


if __name__ == "__main__":
    main()
