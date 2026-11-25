#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
TLS Security & Conformance Audit Suite Runner for goose-wing.
Covers tlsfuzzer, TLS-Anvil, TLS-Attacker, and testssl.sh checks via live wire probes
against `tools/tls/server.goose` (`--local`) and upstream Docker containers (`--docker`).
"""

from __future__ import annotations

import argparse
import io
import os
import socket
import ssl
import struct
import subprocess
import sys
import threading
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable
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
SERVER_SRC = TOOLS_DIR / "tls" / "server.goose"
SERVER_EXE = BIN_DIR / ("tls_server.exe" if sys.platform == "win32" else "tls_server")
WORKFLOWS_XML = TOOLS_DIR / "tls_audit" / "attacker_workflows.xml"
VALID_X25519_BASEPOINT = b"\x09" + (b"\x00" * 31)


def ensure_server_binary(force_rebuild: bool = False) -> Path:
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    if (
        not force_rebuild
        and SERVER_EXE.is_file()
        and SERVER_EXE.stat().st_mtime >= SERVER_SRC.stat().st_mtime
    ):
        return SERVER_EXE

    print(f"[*] Building TLS audit target: {SERVER_SRC.name} -> {SERVER_EXE.name}...")
    env = os.environ.copy()
    opt_flag = "-O2"
    if sys.platform == "win32":
        opt_flag = "-O0"
        if "GOOSE_CC" not in env:
            stack_cc = ROOT_DIR / "tools" / "gcc_stack.bat"
            if stack_cc.is_file():
                env["GOOSE_CC"] = str(stack_cc)
    cmd = ["goose", "build", str(SERVER_SRC), "-o", str(SERVER_EXE), opt_flag]
    res = subprocess.run(
        cmd, check=False, cwd=str(ROOT_DIR), capture_output=True, text=True, env=env
    )
    if res.returncode != 0:
        print("[!] Failed to build tls_server:", file=sys.stderr)
        if res.stdout:
            print(res.stdout, file=sys.stderr)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        sys.exit(1)
    print(f"[+] Built {SERVER_EXE.name}")
    return SERVER_EXE


class NativeTlsServer:
    def __init__(self, binary_path: Path) -> None:
        self.binary_path = binary_path
        self.proc: subprocess.Popen[str] | None = None
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
        deadline = time.time() + timeout
        while time.time() < deadline:
            line = self.proc.stdout.readline()
            if "READY_PORT:" in line:
                self.port = int(line.strip().split("READY_PORT:")[1])
                return self.port
            if self.proc.poll() is not None:
                err = self.proc.stderr.read()
                raise RuntimeError(f"tls_server exited early ({self.proc.returncode}): {err}")
            time.sleep(0.02)
        self.stop()
        raise TimeoutError("tls_server did not emit READY_PORT")

    def stop(self) -> None:
        if not self.proc:
            return
        if self.port > 0:
            try:
                with socket.create_connection(("127.0.0.1", self.port), timeout=0.5) as s:
                    s.sendall(b"GET /shutdown HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n")
            except OSError:
                pass
        try:
            self.proc.terminate()
            self.proc.wait(timeout=1.5)
        except Exception:
            try:
                self.proc.kill()
            except Exception:
                pass
        self.proc = None


class OneByteFragmentProxy:
    """Forwards client-to-server bytes 1 byte per TCP write to test stream reassembly."""

    def __init__(self, target_host: str, target_port: int) -> None:
        self.target_host = target_host
        self.target_port = target_port
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(8)
        self.sock.settimeout(0.2)
        self.port = int(self.sock.getsockname()[1])
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()

    def _pipe(self, src: socket.socket, dst: socket.socket, split_one: bool) -> None:
        try:
            while self.running:
                data = src.recv(4096)
                if not data:
                    break
                if split_one:
                    for i in range(len(data)):
                        dst.sendall(data[i : i + 1])
                else:
                    dst.sendall(data)
        except OSError:
            pass
        finally:
            try:
                dst.shutdown(socket.SHUT_WR)
            except OSError:
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
            except OSError:
                cli.close()

    def close(self) -> None:
        self.running = False
        try:
            self.sock.close()
        except OSError:
            pass


def build_client_hello(
    *,
    legacy_version: int = 0x0303,
    ciphers: list[int] | None = None,
    compression_methods: bytes = b"\x00",
    supported_versions: list[int] | None = None,
    sig_algs: list[int] | None = None,
    key_share_group: int | None = 0x001D,
    key_share_pub: bytes = VALID_X25519_BASEPOINT,
    sni: str | None = "goose-wing.local",
    alpn: list[bytes] | None = None,
    dup_ext_type: int | None = None,
    msg_type: int = 0x01,
    synthetic_random: bool = False,
) -> bytes:
    if ciphers is None:
        ciphers = [0x1301, 0x1302, 0x1303]
    if supported_versions is None:
        supported_versions = [0x0304]
    if sig_algs is None:
        sig_algs = [0x0807, 0x0403, 0x0804]

    exts = bytearray()
    if sni:
        sb = sni.encode("ascii")
        se = b"\x00" + struct.pack(">H", len(sb)) + sb
        sl = struct.pack(">H", len(se)) + se
        sni_ext = struct.pack(">HH", 0, len(sl)) + sl
        exts.extend(sni_ext)
        if dup_ext_type == 0:
            exts.extend(sni_ext)
    if supported_versions:
        vb = b"".join(struct.pack(">H", v) for v in supported_versions)
        sv = bytes([len(vb)]) + vb
        sv_ext = struct.pack(">HH", 43, len(sv)) + sv
        exts.extend(sv_ext)
        if dup_ext_type == 43:
            exts.extend(sv_ext)
    if alpn:
        al = bytearray()
        for proto in alpn:
            al.append(len(proto))
            al.extend(proto)
        ab = struct.pack(">H", len(al)) + bytes(al)
        exts.extend(struct.pack(">HH", 16, len(ab)) + ab)
    if sig_algs:
        sab = b"".join(struct.pack(">H", sa) for sa in sig_algs)
        sal = struct.pack(">H", len(sab)) + sab
        exts.extend(struct.pack(">HH", 13, len(sal)) + sal)
    if key_share_group is not None:
        exts.extend(struct.pack(">HHHH", 10, 4, 2, key_share_group))
        ke = struct.pack(">HH", key_share_group, len(key_share_pub)) + key_share_pub
        kl = struct.pack(">H", len(ke)) + ke
        exts.extend(struct.pack(">HH", 51, len(kl)) + kl)

    rand = (b"\x42" * 32) if synthetic_random else (b"\x11" + os.urandom(31))
    cb = b"".join(struct.pack(">H", c) for c in ciphers)
    ch = bytearray(struct.pack(">H", legacy_version))
    ch.extend(rand)
    ch.append(0)
    ch.extend(struct.pack(">H", len(cb)) + cb)
    ch.append(len(compression_methods))
    ch.extend(compression_methods)
    ch.extend(struct.pack(">H", len(exts)) + bytes(exts))

    hs = bytes([msg_type, (len(ch) >> 16) & 0xFF, (len(ch) >> 8) & 0xFF, len(ch) & 0xFF]) + bytes(ch)
    return bytes([0x16, 0x03, 0x01]) + struct.pack(">H", len(hs)) + hs


def _send_wire(host: str, port: int, payload: bytes, recv_wait: float = 1.5) -> bytes:
    with socket.create_connection((host, port), timeout=3.0) as s:
        s.settimeout(recv_wait)
        s.sendall(payload)
        try:
            return s.recv(4096)
        except (TimeoutError, OSError):
            return b""


def _count_complete_tls_records(buf: bytes) -> tuple[int, int]:
    """Counts complete TLS records and 0x17 encrypted records in `buf`."""
    off = 0
    total = 0
    enc_count = 0
    while off + 5 <= len(buf):
        rec_len = struct.unpack(">H", buf[off + 3 : off + 5])[0]
        if off + 5 + rec_len > len(buf):
            break
        if buf[off] == 0x17:
            enc_count += 1
        total += 1
        off += 5 + rec_len
    return total, enc_count


def _send_after_server_hello(host: str, port: int, followup: bytes) -> tuple[bool, bytes]:
    """Completes real ClientHello->ServerHello flight then injects `followup` bytes."""
    with socket.create_connection((host, port), timeout=3.0) as s:
        s.settimeout(0.5)
        s.sendall(build_client_hello())
        sh_buf = bytearray()
        deadline = time.time() + 2.0
        while time.time() < deadline:
            try:
                chunk = s.recv(8192)
            except TimeoutError:
                break
            if not chunk:
                break
            sh_buf.extend(chunk)
            _, enc_count = _count_complete_tls_records(bytes(sh_buf))
            if enc_count >= 4:
                break
        got_sh = len(sh_buf) >= 50 and sh_buf[0] == 0x16 and sh_buf[5] == 0x02
        if not got_sh:
            return False, bytes(sh_buf)
        s.settimeout(1.5)
        s.sendall(followup)
        resp = bytearray()
        while True:
            try:
                chunk = s.recv(1024)
            except (TimeoutError, OSError):
                break
            if not chunk:
                break
            resp.extend(chunk)
        return True, bytes(resp)


def _is_fatal_alert(resp: bytes, expected_codes: tuple[int, ...] | None = None) -> bool:
    if len(resp) < 7 or resp[0] != 0x15 or resp[5] != 0x02:
        return False
    if expected_codes is None:
        return True
    return resp[6] in expected_codes


def _is_tls13_post_sh_fatal_alert(resp: bytes) -> bool:
    if _is_fatal_alert(resp):
        return True
    if len(resp) >= 24 and resp[0] == 0x17 and resp[1:3] == b"\x03\x03":
        return struct.unpack(">H", resp[3:5])[0] == 19
    return False


def _is_rejected(resp: bytes) -> bool:
    if len(resp) == 0:
        return True
    return _is_tls13_post_sh_fatal_alert(resp)


def _live_openssl_https_get(
    host: str,
    port: int,
    *,
    min_ver: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3,
    max_ver: ssl.TLSVersion = ssl.TLSVersion.TLSv1_3,
    alpn: list[str] | None = None,
) -> tuple[bool, str, str | None, str]:
    ctx = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    ctx.minimum_version = min_ver
    ctx.maximum_version = max_ver
    if alpn:
        ctx.set_alpn_protocols(alpn)
    try:
        with (
            socket.create_connection((host, port), timeout=3.0) as raw,
            ctx.wrap_socket(raw, server_hostname="goose-wing.local") as tls_s,
        ):
            tls_s.settimeout(3.0)
            tls_s.sendall(
                b"GET /secure-hello HTTP/1.1\r\nHost: goose-wing.local\r\nConnection: close\r\n\r\n"
            )
            body = b""
            while True:
                chunk = tls_s.recv(4096)
                if not chunk:
                    break
                body += chunk
            return (
                b"Hello over TLS 1.3!" in body,
                f"{tls_s.version()} {tls_s.cipher()}",
                tls_s.selected_alpn_protocol(),
                body.decode("utf-8", errors="replace"),
            )
    except Exception as exc:
        return False, str(exc), None, ""


def run_tlsfuzzer_suite(
    host: str, port: int, check: Callable[[bool, str, str], None]
) -> None:
    print("\n[Suite 1/4: tlsfuzzer] Record fragmentation, AEAD MAC, padding, alert & duplicate-ext probes")

    # 1. 1-byte TCP fragmentation proxy + full TLS 1.3 HTTPS GET
    proxy = OneByteFragmentProxy(host, port)
    try:
        ok, info, alpn, _ = _live_openssl_https_get("127.0.0.1", proxy.port, alpn=["http/1.1"])
        check(ok and alpn == "http/1.1", "tlsfuzzer/01 1-byte TCP fragmented TLS 1.3 handshake + HTTP", f"{info} alpn={alpn}")
    finally:
        proxy.close()

    # 2. Bad AEAD MAC on encrypted handshake record after ServerHello
    bad_aead = bytes([0x17, 0x03, 0x03, 0x00, 0x35]) + (b"\xDE" * 53)
    got_sh, resp = _send_after_server_hello(host, port, bad_aead)
    check(got_sh and _is_tls13_post_sh_fatal_alert(resp), "tlsfuzzer/02 Bad AEAD MAC in handshake record triggers fatal alert", resp.hex())

    # 3. Short AEAD ciphertext (< 17B tag+inner-type padding floor)
    short_pad = bytes([0x17, 0x03, 0x03, 0x00, 0x05]) + (b"\x00" * 5)
    got_sh, resp = _send_after_server_hello(host, port, short_pad)
    check(got_sh and _is_tls13_post_sh_fatal_alert(resp), "tlsfuzzer/03 Truncated AEAD padding (<17B) rejected with fatal alert", resp.hex())

    # 4. Oversized TLS record ciphertext header (> 16640 bytes, RFC 8446 Section 5.2)
    oversized = bytes([0x17, 0x03, 0x03]) + struct.pack(">H", 16641) + (b"\x00" * 64)
    got_sh, resp = _send_after_server_hello(host, port, oversized)
    check(got_sh and _is_rejected(resp), "tlsfuzzer/04 Oversized record header (>16640B) rejected fail-closed", resp.hex())

    # 5. Clean CloseNotify alert handling & server liveness after alert
    _ = _send_wire(host, port, b"\x15\x03\x03\x00\x02\x01\x00", recv_wait=0.3)
    ok_after, info_after, _, _ = _live_openssl_https_get(host, port, alpn=["http/1.1"])
    check(ok_after, "tlsfuzzer/05 CloseNotify alert terminates cleanly without harming subsequent sessions", info_after)

    # 6. Duplicate SNI extension (0x0000) -> fatal alert
    resp_dup_sni = _send_wire(host, port, build_client_hello(dup_ext_type=0))
    check(_is_fatal_alert(resp_dup_sni, (47, 50)), "tlsfuzzer/06 Duplicate SNI extension rejected with fatal alert", resp_dup_sni.hex())

    # 7. Duplicate supported_versions extension (0x002b) -> fatal alert
    resp_dup_sv = _send_wire(host, port, build_client_hello(dup_ext_type=43))
    check(_is_fatal_alert(resp_dup_sv, (47, 50)), "tlsfuzzer/07 Duplicate supported_versions extension rejected", resp_dup_sv.hex())

    # 8. Invalid record content type 0xFF -> fatal unexpected_message (10)
    resp_ct = _send_wire(host, port, b"\xFF\x03\x03\x00\x02\x01\x02")
    check(_is_fatal_alert(resp_ct, (10,)), "tlsfuzzer/08 Invalid record content type 0xFF triggers unexpected_message (10)", resp_ct.hex())


def run_tls_anvil_suite(
    host: str, port: int, check: Callable[[bool, str, str], None]
) -> None:
    print("\n[Suite 2/4: TLS-Anvil] Combinatorial ClientHello parameter matrix")

    # 1-3. Combinatorial TLS 1.3 cipher suite selection matrix (0x1301, 0x1302, 0x1303)
    for idx, (cs_id, cs_name) in enumerate(
        (
            (0x1301, "TLS_AES_128_GCM_SHA256"),
            (0x1302, "TLS_AES_256_GCM_SHA384"),
            (0x1303, "TLS_CHACHA20_POLY1305_SHA256"),
        ),
        start=1,
    ):
        resp = _send_wire(host, port, build_client_hello(ciphers=[cs_id]))
        cs_bytes = struct.pack(">H", cs_id)
        ok = len(resp) >= 50 and resp[0] == 0x16 and resp[5] == 0x02 and cs_bytes in resp[40:90]
        check(ok, f"tls-anvil/0{idx} Cipher matrix selects {cs_name} (0x{cs_id:04x})", f"len={len(resp)}")

    # 4. Non-null DEFLATE compression method (forbidden by RFC 8446 Section 4.1.2)
    resp_comp = _send_wire(host, port, build_client_hello(compression_methods=b"\x01\x00"))
    check(_is_fatal_alert(resp_comp), "tls-anvil/04 Non-null DEFLATE compression rejected with fatal alert", resp_comp.hex())

    # 5. Empty compression_methods list -> fatal alert
    resp_ec = _send_wire(host, port, build_client_hello(compression_methods=b""))
    check(_is_fatal_alert(resp_ec), "tls-anvil/05 Empty compression_methods list rejected with fatal alert", resp_ec.hex())

    # 6. Legacy version 0x0301 mismatch (RFC 8446 Section 4.1.2 requires 0x0303)
    resp_lv = _send_wire(host, port, build_client_hello(legacy_version=0x0301))
    check(_is_fatal_alert(resp_lv), "tls-anvil/06 ClientHello legacy_version=0x0301 rejected", resp_lv.hex())

    # 7. Missing signature_algorithms extension -> fatal alert
    resp_ns = _send_wire(host, port, build_client_hello(sig_algs=[]))
    check(_is_fatal_alert(resp_ns), "tls-anvil/07 Missing signature_algorithms extension rejected", resp_ns.hex())

    # 8. Forbidden legacy rsa_pkcs1_sha1 (0x0201) only -> fatal alert
    resp_sa = _send_wire(host, port, build_client_hello(sig_algs=[0x0201]))
    check(_is_fatal_alert(resp_sa), "tls-anvil/08 Legacy rsa_pkcs1_sha1-only signature_algorithms rejected", resp_sa.hex())

    # 9. Unmatched ALPN rejected with fatal no_application_protocol (120)
    resp_alpn = _send_wire(
        host, port, build_client_hello(alpn=[b"bogus-proto/99"], synthetic_random=True)
    )
    check(
        _is_fatal_alert(resp_alpn, (120,)),
        "tls-anvil/09 Unmatched ALPN rejected with no_application_protocol (120)",
        resp_alpn.hex(),
    )


def run_tls_attacker_suite(
    host: str, port: int, check: Callable[[bool, str, str], None]
) -> None:
    print("\n[Suite 3/4: TLS-Attacker] Out-of-order, unencrypted Finished, CCS flood & bad KeyShare flows")

    # 1. Validate attacker_workflows.xml schema & workflow trace names
    try:
        tree = ET.parse(WORKFLOWS_XML)
        traces = [el.attrib.get("name", "") for el in tree.getroot().findall("workflowTrace")]
        ok_xml = (
            "out_of_order_ccs_before_client_hello" in traces
            and "unencrypted_finished_after_server_hello" in traces
            and "ccs_flood_after_server_hello" in traces
            and "bad_key_share_low_order_x25519" in traces
        )
        check(ok_xml, "tls-attacker/01 attacker_workflows.xml parses with all 4 attack workflow traces", str(traces))
    except Exception as exc:
        check(False, "tls-attacker/01 attacker_workflows.xml parses cleanly", str(exc))

    # 2. Pre-handshake ChangeCipherSpec -> fatal unexpected_message (10)
    resp_ccs = _send_wire(host, port, b"\x14\x03\x03\x00\x01\x01")
    check(_is_fatal_alert(resp_ccs, (10,)), "tls-attacker/02 Pre-handshake CCS triggers unexpected_message (10)", resp_ccs.hex())

    # 3. Pre-handshake ApplicationData -> fatal unexpected_message (10)
    resp_app = _send_wire(host, port, b"\x17\x03\x03\x00\x08\x01\x02\x03\x04\x05\x06\x07\x08")
    check(_is_fatal_alert(resp_app, (10,)), "tls-attacker/03 Pre-handshake ApplicationData triggers unexpected_message (10)", resp_app.hex())

    # 4. Out-of-order ServerHello sent by client as first message -> fatal alert
    resp_sh = _send_wire(host, port, build_client_hello(msg_type=0x02))
    check(_is_fatal_alert(resp_sh), "tls-attacker/04 Client-sent ServerHello (0x02) rejected with fatal alert", resp_sh.hex())

    # 5. Out-of-order Finished sent as first handshake message -> fatal alert
    plain_fin = b"\x16\x03\x03\x00\x24\x14\x00\x00\x20" + (b"\xAA" * 32)
    resp_fin0 = _send_wire(host, port, plain_fin)
    check(_is_fatal_alert(resp_fin0), "tls-attacker/05 Client-sent Finished (0x14) as first message rejected", resp_fin0.hex())

    # 6. Unencrypted Finished injected after ServerHello flight -> fatal alert
    got_sh, resp_uf = _send_after_server_hello(host, port, plain_fin)
    check(got_sh and _is_tls13_post_sh_fatal_alert(resp_uf), "tls-attacker/06 Unencrypted Finished after ServerHello rejected", resp_uf.hex())

    # 7. CCS flood (multiple CCS after ServerHello; RFC 8446 allows max 1) -> fatal alert
    ccs_flood = b"\x14\x03\x03\x00\x01\x01" * 2
    got_sh, resp_cf = _send_after_server_hello(host, port, ccs_flood)
    check(got_sh and _is_tls13_post_sh_fatal_alert(resp_cf), "tls-attacker/07 CCS flood (2x CCS after ServerHello) rejected", resp_cf.hex())

    # 8. Malformed CCS payload byte (0x02 != 0x01) after ServerHello -> fatal alert
    bad_ccs = b"\x14\x03\x03\x00\x01\x02"
    got_sh, resp_bc = _send_after_server_hello(host, port, bad_ccs)
    check(got_sh and _is_tls13_post_sh_fatal_alert(resp_bc), "tls-attacker/08 Malformed CCS byte (0x02) after ServerHello rejected", resp_bc.hex())

    # 9. Bad KeyShare: all-zero low-order X25519 public key (RFC 7748 Section 6.1) -> fatal alert
    resp_zk = _send_wire(host, port, build_client_hello(key_share_pub=b"\x00" * 32))
    check(_is_fatal_alert(resp_zk), "tls-attacker/09 All-zero low-order X25519 KeyShare rejected", resp_zk.hex())

    # 10. Bad KeyShare: truncated 16-byte X25519 key share -> fatal alert
    resp_tk = _send_wire(host, port, build_client_hello(key_share_pub=b"\x09" * 16))
    check(_is_fatal_alert(resp_tk), "tls-attacker/10 Truncated 16-byte X25519 KeyShare rejected", resp_tk.hex())


def run_testssl_suite(
    host: str, port: int, check: Callable[[bool, str, str], None]
) -> None:
    print("\n[Suite 4/4: testssl.sh] Protocol version floor, weak cipher rejection & TLS 1.3 posture")

    # 1-4. Legacy protocol versions SSL 3.0, TLS 1.0, TLS 1.1, TLS 1.2 must all be rejected
    for idx, (ver_hex, label) in enumerate(
        ((0x0300, "SSL 3.0"), (0x0301, "TLS 1.0"), (0x0302, "TLS 1.1"), (0x0303, "TLS 1.2")),
        start=1,
    ):
        ch = build_client_hello(
            legacy_version=ver_hex,
            supported_versions=[] if ver_hex == 0x0300 else [ver_hex],
            ciphers=[0x002F, 0xC02F],
        )
        resp = _send_wire(host, port, ch)
        check(_is_fatal_alert(resp), f"testssl/0{idx} Rejects {label} (0x{ver_hex:04x}) with fatal alert", resp.hex())

    # 5. Weak & legacy cipher suites (NULL, RC4, 3DES, AES-CBC, TLS 1.2 ECDHE) rejected even under TLS 1.3
    weak_ciphers = [0x0000, 0x0005, 0x000A, 0x002F, 0x0035, 0xC02F, 0xC030]
    resp_wc = _send_wire(host, port, build_client_hello(ciphers=weak_ciphers))
    check(_is_fatal_alert(resp_wc), "testssl/05 Rejects weak/legacy ciphers (NULL/RC4/3DES/CBC/TLS1.2)", resp_wc.hex())

    # 6. Live OpenSSL TLS 1.3 client verifies negotiated protocol, AEAD cipher, ALPN & HTTP response
    ok13, info13, alpn13, _ = _live_openssl_https_get(host, port, alpn=["http/1.1"])
    check(
        ok13 and "TLSv1.3" in info13 and alpn13 == "http/1.1",
        "testssl/06 Live OpenSSL client confirms TLSv1.3 AEAD cipher + ALPN http/1.1 + HTTP 200",
        f"{info13} alpn={alpn13}",
    )

    # 7. Live OpenSSL TLS 1.2-only client must fail handshake against strict TLS 1.3 server
    ok12, info12, _, _ = _live_openssl_https_get(
        host, port, min_ver=ssl.TLSVersion.TLSv1_2, max_ver=ssl.TLSVersion.TLSv1_2
    )
    check(not ok12, "testssl/07 Live OpenSSL TLS 1.2-only client rejected by strict TLS 1.3 server", info12)


def run_local_audit(suite: str, host: str, port: int, rebuild: bool) -> int:
    srv: NativeTlsServer | None = None
    if port == 0:
        exe = ensure_server_binary(force_rebuild=rebuild)
        srv = NativeTlsServer(exe)
        port = srv.start()
        host = "127.0.0.1"
        print(f"[*] Started local goose-wing TLS 1.3 server on {host}:{port}")

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

    try:
        if suite in ("all", "tlsfuzzer"):
            run_tlsfuzzer_suite(host, port, check)
        if suite in ("all", "tls-anvil"):
            run_tls_anvil_suite(host, port, check)
        if suite in ("all", "tls-attacker"):
            run_tls_attacker_suite(host, port, check)
        if suite in ("all", "testssl"):
            run_testssl_suite(host, port, check)
    finally:
        if srv is not None:
            srv.stop()

    total = passed + failed
    print(f"\nCompleted TLS audit ({suite}): {passed}/{total} passed, {failed} failed.")
    return 0 if failed == 0 and total > 0 else 1


def run_docker_audit(suite: str) -> int:
    compose_file = TOOLS_DIR / "tls_audit" / "docker-compose.yml"
    services = (
        ["tlsfuzzer", "tls-anvil", "tls-attacker", "testssl"]
        if suite == "all"
        else [suite]
    )
    overall = 0
    for svc in services:
        cmd = [
            "docker", "compose", "-f", str(compose_file),
            "up", "--build", "--abort-on-container-exit", "--exit-code-from", svc,
            "tls-server", svc,
        ]
        print(f"[*] Running Docker audit suite '{svc}' via {compose_file.name}...")
        rc = subprocess.run(cmd, check=False, cwd=str(ROOT_DIR)).returncode
        if rc != 0:
            overall = rc
    return overall


def main() -> None:
    parser = argparse.ArgumentParser(
        description="TLS audit runner (tlsfuzzer, TLS-Anvil, TLS-Attacker, testssl.sh) for goose-wing"
    )
    parser.add_argument(
        "--suite",
        choices=("all", "tlsfuzzer", "tls-anvil", "tls-attacker", "testssl"),
        default="all",
        help="Audit suite to run (default: all)",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Build tools/tls/server.goose locally and run live wire probes",
    )
    parser.add_argument(
        "--docker",
        action="store_true",
        help="Run upstream Dockerized audit suites via tools/tls_audit/docker-compose.yml",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Target host when --port is specified")
    parser.add_argument("--port", type=int, default=0, help="Existing server port (0 = spawn local)")
    parser.add_argument("--rebuild", action="store_true", help="Force rebuild tools/tls/server.goose")
    args = parser.parse_args()

    if args.docker:
        sys.exit(run_docker_audit(args.suite))

    sys.exit(run_local_audit(args.suite, args.host, args.port, args.rebuild))


if __name__ == "__main__":
    main()
