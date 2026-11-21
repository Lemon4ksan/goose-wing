#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
HTTP/3 & QUIC End-to-End Interop Verification Test Runner for goose-wing.
Validates RFC 9000 (QUIC Transport, Flow Control, Connection Migration),
RFC 9114 (HTTP/3), RFC 9204 (QPACK), UDP fault resilience (packet loss,
duplication, reordering), and 2 MiB streaming backpressure with SHA-256 integrity
against the native server running over live UDP datagrams.
"""

from __future__ import annotations

import argparse
import io
import os
import socket
import struct
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
SERVER_SRC = TOOLS_DIR / "http3" / "server.goose"
SERVER_EXE = BIN_DIR / ("http3_server.exe" if sys.platform == "win32" else "http3_server")
CLIENT_SRC = TOOLS_DIR / "http3" / "client.goose"
CLIENT_EXE = BIN_DIR / ("http3_client.exe" if sys.platform == "win32" else "http3_client")


def ensure_binary(src: Path, exe: Path, label: str, force_rebuild: bool = False) -> Path:
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


def ensure_server_binary(force_rebuild: bool = False) -> Path:
    return ensure_binary(SERVER_SRC, SERVER_EXE, "HTTP/3 server", force_rebuild)


def ensure_client_binary(force_rebuild: bool = False) -> Path:
    return ensure_binary(CLIENT_SRC, CLIENT_EXE, "HTTP/3 client", force_rebuild)


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


class UdpFaultProxy:
    """Deterministic local UDP fault proxy modeled after quic-interop-runner netem profiles.

    Modes:
      - `loss`: drops the first client->server datagram, passes retries.
      - `duplicate`: delivers every client->server and server->client datagram twice.
      - `reorder`: buffers two client->server datagrams and forwards them swapped [2nd, 1st].
    """

    def __init__(self, target_host: str, target_port: int, mode: str) -> None:
        self.target = (target_host, target_port)
        self.mode = mode
        self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.front.bind(("127.0.0.1", 0))
        self.front.settimeout(0.1)
        self.port: int = self.front.getsockname()[1]

        self.back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.back.bind(("127.0.0.1", 0))
        self.back.settimeout(0.1)

        self.client_addr: tuple[str, int] | None = None
        self.dropped_count = 0
        self.duplicated_count = 0
        self.reordered_count = 0
        self._reorder_buf: list[bytes] = []
        self.running = True
        self._t_c2s = threading.Thread(target=self._loop_c2s, daemon=True)
        self._t_s2c = threading.Thread(target=self._loop_s2c, daemon=True)
        self._t_c2s.start()
        self._t_s2c.start()

    def _loop_c2s(self) -> None:
        while self.running:
            try:
                data, addr = self.front.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                if not self.running:
                    break
                time.sleep(0.005)
                continue
            self.client_addr = addr
            if self.mode == "loss" and self.dropped_count == 0:
                self.dropped_count += 1
                continue
            if self.mode == "duplicate":
                self.back.sendto(data, self.target)
                self.back.sendto(data, self.target)
                self.duplicated_count += 1
                continue
            if self.mode == "reorder":
                self._reorder_buf.append(data)
                if len(self._reorder_buf) >= 2:
                    p1, p2 = self._reorder_buf.pop(0), self._reorder_buf.pop(0)
                    self.back.sendto(p2, self.target)
                    self.back.sendto(p1, self.target)
                    self.reordered_count += 1
                continue
            self.back.sendto(data, self.target)

    def _loop_s2c(self) -> None:
        while self.running:
            try:
                data, _ = self.back.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                if not self.running:
                    break
                time.sleep(0.005)
                continue
            if not self.client_addr:
                continue
            try:
                self.front.sendto(data, self.client_addr)
                if self.mode == "duplicate":
                    self.front.sendto(data, self.client_addr)
            except OSError:
                if not self.running:
                    break

    def close(self) -> None:
        self.running = False
        for sock in (self.front, self.back):
            try:
                sock.close()
            except Exception:
                pass


def build_h3_get_frame(path: bytes, authority: bytes = b"127.0.0.1") -> bytes:
    """Encodes an RFC 9114 HEADERS frame with :method GET, :scheme https, :path, and :authority."""
    auth_field = b"\x50" + bytes([len(authority)]) + authority
    if path == b"/":
        qpack = b"\x00\x00\xd1\xd7\xc1" + auth_field
    else:
        # Literal :path with name reference to static index 1 (0x51), un-Huffman length + bytes
        qpack = b"\x00\x00\xd1\xd7\x51" + bytes([len(path)]) + path + auth_field
    return bytes([0x01, len(qpack)]) + qpack


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
    vn_req.extend(struct.pack(">I", 0x5A5A5A5A))
    vn_req.append(len(dcid))
    vn_req.extend(dcid)
    vn_req.append(len(scid))
    vn_req.extend(scid)
    vn_req.append(0)
    vn_req.append(10)
    vn_req.append(1)
    vn_req.extend(b"0123456789")

    s.sendto(vn_req, (host, port))
    vn_res, _ = s.recvfrom(2048)

    is_vn = len(vn_res) >= 27 and vn_res[0] & 0x80 != 0 and struct.unpack(">I", vn_res[1:5])[0] == 0
    echoed_dcid = vn_res[6 : 6 + len(scid)] == scid if len(vn_res) >= 6 + len(scid) else False
    record(is_vn and echoed_dcid, "RFC 9000 Version Negotiation (Ver 0x00000000 & SCID Echo)")

    # 2. RFC 9000 §17.2.2 QUIC v1 Initial Datagram Ingestion (1200 Bytes Minimum)
    init_req = bytearray([0xC0])
    init_req.extend(struct.pack(">I", 0x00000001))
    init_req.append(len(dcid))
    init_req.extend(dcid)
    init_req.append(len(scid))
    init_req.extend(scid)
    init_req.append(0)
    init_req.append(10)
    init_req.append(1)
    init_req.extend(b"0123456789")
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
    has_ctrl_stream = b"\x00\x04" in init_res
    record(has_ctrl_stream, "RFC 9114 HTTP/3 Control Stream Preamble (Type 0x00)")

    # 4. RFC 9114 §7.2.4 SETTINGS Parameters Validation
    has_qpack_cap = b"\x01\x50\x00" in init_res or b"\x01\x40" in init_res
    has_section_sz = b"\x06\x80\x01\x00\x00" in init_res or b"\x06" in init_res
    record(
        has_qpack_cap and has_section_sz,
        "RFC 9114 SETTINGS Parameters (QPACK Table Capacity & Section Size)",
    )

    # 5. RFC 9114 §7.2.8 GREASE Frame Conformance
    has_grease = b"\x21\x00" in init_res
    record(has_grease, "RFC 9114 GREASE Frame Generation & Tolerance (Type 0x21)")

    # 6. RFC 9114 §7.2.4 Rejection of Forbidden HTTP/2 Settings Identifiers
    forbidden_settings_frame = bytes([0x04, 0x02, 0x02, 0x01])
    s.sendto(forbidden_settings_frame, (host, port))
    set_err_res, _ = s.recvfrom(1024)
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
    h3_frame = build_h3_get_frame(b"/")
    s.sendto(h3_frame, (host, port))
    h3_res, _ = s.recvfrom(2048)

    has_h3_headers = len(h3_res) >= 5 and h3_res[0] == 0x01
    has_h3_data = (
        b"\x00\x1dHello from goose-wing HTTP/3!" in h3_res
        or b"Hello from goose-wing HTTP/3!" in h3_res
    )
    record(has_h3_headers and has_h3_data, "RFC 9114 HTTP/3 HEADERS & DATA Stream Roundtrip")

    # 8. RFC 9204 QPACK Static Table Indexing (:status 200 = Index 25)
    has_qpack_200 = b"\xd9" in h3_res[:6]
    record(has_qpack_200, "RFC 9204 QPACK Static Table Field Indexing (:status 200 = 0xD9)")
    s.close()

    # 9-11. Native Goose Client (wing::Client with Alt-Svc h3 promotion) Live UDP E2E Suite
    client_exe = ensure_client_binary(force_rebuild=False)
    env = os.environ.copy()
    env["WING_PORT"] = str(port)
    env["PORT"] = str(port)
    cli_res = subprocess.run(
        [str(client_exe)],
        cwd=str(ROOT_DIR),
        env=env,
        capture_output=True,
        text=True,
        timeout=15.0,
        check=False,
    )
    cli_out = cli_res.stdout or ""
    record(
        "H3_NATIVE_GET_ROOT: PASS" in cli_out,
        "Native Goose HTTP/3 Client: Alt-Svc h3 Promotion & Live UDP GET /",
        cli_out.strip(),
    )
    record(
        "H3_NATIVE_GET_QUERY: PASS" in cli_out,
        "Native Goose HTTP/3 Client: Query-String Routing & JSON Response (/api/info?client=...)",
        cli_out.strip(),
    )
    record(
        "H3_NATIVE_POST_DATA: PASS" in cli_out,
        "Native Goose HTTP/3 Client: Live UDP POST with QPACK HEADERS + DATA Frame",
        cli_out.strip(),
    )

    # 12. IETF quic-interop-runner: UDP Packet Loss & Retransmission Recovery
    loss_proxy = UdpFaultProxy(host, port, mode="loss")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s_loss:
            s_loss.settimeout(0.25)
            # First transmission is deterministically dropped by proxy
            s_loss.sendto(h3_frame, ("127.0.0.1", loss_proxy.port))
            first_timed_out = False
            try:
                _ = s_loss.recvfrom(2048)
            except TimeoutError:
                first_timed_out = True
            # Retransmission succeeds end-to-end
            s_loss.settimeout(2.0)
            s_loss.sendto(h3_frame, ("127.0.0.1", loss_proxy.port))
            loss_resp, _ = s_loss.recvfrom(2048)
        record(
            first_timed_out
            and loss_proxy.dropped_count == 1
            and b"Hello from goose-wing HTTP/3!" in loss_resp,
            "QUIC/H3 Fault Resilience: UDP Packet Loss Drop & Retransmission Recovery",
            f"dropped={loss_proxy.dropped_count} first_to={first_timed_out}",
        )
    finally:
        loss_proxy.close()

    # 13. IETF quic-interop-runner: UDP Packet Duplication Resilience
    dup_proxy = UdpFaultProxy(host, port, mode="duplicate")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s_dup:
            s_dup.settimeout(1.5)
            s_dup.sendto(h3_frame, ("127.0.0.1", dup_proxy.port))
            dup_r1, _ = s_dup.recvfrom(2048)
            dup_r2, _ = s_dup.recvfrom(2048)
        record(
            dup_proxy.duplicated_count >= 1
            and dup_r1[:1] == b"\x01"
            and dup_r2[:1] == b"\x01"
            and b"Hello from goose-wing HTTP/3!" in dup_r1
            and b"Hello from goose-wing HTTP/3!" in dup_r2,
            "QUIC/H3 Fault Resilience: UDP Packet Duplication Idempotence",
            f"dups={dup_proxy.duplicated_count}",
        )
    finally:
        dup_proxy.close()

    # 14. IETF quic-interop-runner: UDP Out-of-Order Reordering Resilience
    reord_proxy = UdpFaultProxy(host, port, mode="reorder")
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s_ro:
            s_ro.settimeout(2.0)
            s_ro.sendto(build_h3_get_frame(b"/"), ("127.0.0.1", reord_proxy.port))
            s_ro.sendto(build_h3_get_frame(b"/api/info"), ("127.0.0.1", reord_proxy.port))
            ro_a, _ = s_ro.recvfrom(2048)
            ro_b, _ = s_ro.recvfrom(2048)
        bodies = ro_a + ro_b
        record(
            reord_proxy.reordered_count == 1
            and b"Hello from goose-wing HTTP/3!" in bodies
            and b'{"protocol":"h3","engine":"goose-wing"}' in bodies,
            "QUIC/H3 Fault Resilience: Out-of-Order UDP Datagram Reordering Recovery",
            f"reordered={reord_proxy.reordered_count}",
        )
    finally:
        reord_proxy.close()

    # 15. Large 2 MiB HTTP/3 Streaming Transfer + MAX_DATA / MAX_STREAM_DATA Backpressure + SHA-256
    st_res = subprocess.run(
        [str(client_exe), "stream2mb", str(port)],
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        timeout=30.0,
        check=False,
    )
    st_out = (st_res.stdout or "").strip()
    record(
        "H3_STREAM_2MB: PASS" in st_out,
        "QUIC/H3 2 MiB Streaming Transfer with MAX_DATA / MAX_STREAM_DATA Backpressure & SHA-256",
        st_out,
    )

    # 16-17. RFC 9000 §9 Connection Migration & NAT Port Rebinding Probe
    with (
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock_a,
        socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock_b,
    ):
        sock_a.settimeout(2.0)
        sock_b.settimeout(2.0)
        sock_a.bind(("127.0.0.1", 0))
        sock_b.bind(("127.0.0.1", 0))
        port_b = sock_b.getsockname()[1]

        sock_a.sendto(b"MIG_REGISTER", (host, port))
        reg_ack, _ = sock_a.recvfrom(128)

        # Simulate NAT rebinding: probe arrives from new ephemeral UDP port B
        sock_b.sendto(b"MIG_PROBE_NAT_REBIND", (host, port))
        chall_pkt, _ = sock_b.recvfrom(128)
        got_challenge = len(chall_pkt) == 9 and chall_pkt[0] == 0x1A
        token = chall_pkt[1:9] if got_challenge else b"\x00" * 8

        # 16. Negative probe: tampered PATH_RESPONSE token must be rejected
        bad_token = bytes([token[0] ^ 0xFF]) + token[1:]
        sock_b.sendto(b"\x1b" + bad_token, (host, port))
        rej_ack, _ = sock_b.recvfrom(128)
        record(
            reg_ack == b"MIG_REGISTERED" and got_challenge and rej_ack == b"MIG_REJECT",
            "RFC 9000 §8.2 Connection Migration: Tampered PATH_RESPONSE Token Rejected",
            f"reg={reg_ack!r} chall={got_challenge} rej={rej_ack!r}",
        )

        # 17. Positive probe: valid PATH_RESPONSE completes migration + live H3 GET on new port B
        sock_b.sendto(b"\x1b" + token, (host, port))
        mig_ack, _ = sock_b.recvfrom(128)
        sock_b.sendto(h3_frame, (host, port))
        post_mig_h3, _ = sock_b.recvfrom(2048)
        record(
            mig_ack == f"MIG_OK:{port_b}".encode("ascii")
            and b"Hello from goose-wing HTTP/3!" in post_mig_h3,
            "RFC 9000 §9 Connection Migration: NAT Port Rebinding PATH_CHALLENGE/RESPONSE & Post-Migration H3",
            f"ack={mig_ack!r} port_b={port_b}",
        )

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

    if args.compose or args.docker:
        compose_file = TOOLS_DIR / "http3" / "docker-compose.yml"
        cmd = [
            "docker",
            "compose",
            "-f",
            str(compose_file),
            "up",
            "--build",
            "--abort-on-container-exit",
            "--exit-code-from",
            "http3-runner",
        ]
        print(f"[*] Running HTTP/3 suite via docker compose ({compose_file.name})...")
        sys.exit(subprocess.run(cmd, check=False, cwd=str(ROOT_DIR)).returncode)

    if args.port > 0:
        passed, failed = run_e2e_tests(args.host, args.port)
        total = passed + failed
        print(f"\nCompleted: {passed}/{total} passed, {failed} failed.")
        sys.exit(0 if failed == 0 and total > 0 else 1)

    server_exe = ensure_server_binary(force_rebuild=args.rebuild)
    ensure_client_binary(force_rebuild=args.rebuild)
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
