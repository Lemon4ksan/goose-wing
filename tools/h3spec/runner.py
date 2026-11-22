#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
h3spec (RFC 9114 HTTP/3 & RFC 9000 QUIC conformance) runner for `goose-wing`.

In `--local` mode, launches `tools/http3/server.goose` over live loopback UDP
and executes QUIC/H3 protocol error-handling probes (invalid QUIC version,
undersized Initial < 1200B, forbidden HTTP/2 SETTINGS, duplicate SETTINGS,
DATA before HEADERS, malformed varint/frame length, GREASE tolerance) alongside
native `http3::Connection` unidirectional/critical-stream probes
(`H3_STREAM_CREATION_ERROR`, `H3_CLOSED_CRITICAL_STREAM`, `H3_MISSING_SETTINGS`).

In `--docker` mode, orchestrates `kazu-yamamoto/h3spec` against `http3-server`
via `tools/h3spec/docker-compose.yml`.
"""

from __future__ import annotations

import argparse
import importlib.util
import io
import socket
import struct
import subprocess
import sys
from pathlib import Path
from typing import Any

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

SUITE_DIR = Path(__file__).resolve().parent
ROOT_DIR = SUITE_DIR.parent.parent
TOOLS_DIR = ROOT_DIR / "tools"

# RFC 9114 Section 8.1 HTTP/3 Application Error Codes
H3_ERR_FRAME_UNEXPECTED = 0x0105
H3_ERR_FRAME_ERROR = 0x0106
H3_ERR_SETTINGS_ERROR = 0x0109


def _load_module(name: str, path: Path) -> Any:
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


def _decode_quic_varint(buf: bytes, off: int = 0) -> tuple[int, int]:
    if off >= len(buf):
        return -1, off
    first = buf[off]
    length = 1 << (first >> 6)
    if off + length > len(buf):
        return -1, off
    val = first & 0x3F
    for b in buf[off + 1 : off + length]:
        val = (val << 8) | b
    return val, off + length


def _extract_h3_close_error(resp: bytes) -> int:
    """Extracts the application error code from a QUIC CONNECTION_CLOSE (0x1D) frame."""
    if len(resp) < 3 or resp[0] != 0x1D:
        return -1
    code, _ = _decode_quic_varint(resp, 1)
    return code


def _build_quic_initial(version: int, total_size: int) -> tuple[bytes, bytes]:
    scid = b"\x11\x22\x33\x44\x55\x66\x77\x88"
    dcid = b"\x88\x77\x66\x55\x44\x33\x22\x11"
    pkt = bytearray([0xC0])
    pkt.extend(struct.pack(">I", version))
    pkt.append(len(dcid))
    pkt.extend(dcid)
    pkt.append(len(scid))
    pkt.extend(scid)
    pkt.append(0)
    pkt.append(10)
    pkt.append(1)
    pkt.extend(b"0123456789")
    if len(pkt) < total_size:
        pkt.extend(b"\x00" * (total_size - len(pkt)))
    return bytes(pkt[:total_size]), scid


def _udp_exchange(
    sock: socket.socket,
    addr: tuple[str, int],
    payload: bytes,
    timeout: float = 0.5,
) -> bytes | None:
    sock.settimeout(timeout)
    sock.sendto(payload, addr)
    try:
        data, _ = sock.recvfrom(4096)
        return data
    except TimeoutError:
        return None


def run_live_udp_probes(host: str, port: int, build_h3_get_frame: Any) -> tuple[int, int]:
    passed = 0
    failed = 0
    addr = (host, port)

    def check(ok: bool, name: str, detail: str = "") -> None:
        nonlocal passed, failed
        if ok:
            passed += 1
            print(f"  [PASS] [udp   ] {name:42s} {detail}")
        else:
            failed += 1
            print(f"  [FAIL] [udp   ] {name:42s} {detail}")

    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        # 1. Invalid QUIC version -> Version Negotiation (version == 0x00000000)
        vn_pkt, scid = _build_quic_initial(0x5A5A5A5A, 64)
        vn_res = _udp_exchange(sock, addr, vn_pkt, timeout=1.5)
        vn_ok = (
            vn_res is not None
            and len(vn_res) >= 27
            and (vn_res[0] & 0x80) != 0
            and struct.unpack(">I", vn_res[1:5])[0] == 0
            and vn_res[6 : 6 + len(scid)] == scid
        )
        check(vn_ok, "invalid_quic_version_negotiation", "-> Version Negotiation 0x00000000")

        # 2-3. Undersized QUIC Initial (< 1200B: 512B and 1199B) -> silently discarded
        for bad_len in (512, 1199):
            short_init, _ = _build_quic_initial(0x00000001, bad_len)
            short_res = _udp_exchange(sock, addr, short_init, timeout=0.25)
            check(short_res is None, f"undersized_initial_{bad_len}b_discarded", "-> discarded")

        # 4. Valid 1200B QUIC v1 Initial -> Server Initial + Control Stream + SETTINGS + GREASE
        valid_init, _ = _build_quic_initial(0x00000001, 1200)
        init_res = _udp_exchange(sock, addr, valid_init, timeout=1.5)
        init_ok = (
            init_res is not None
            and len(init_res) >= 30
            and (init_res[0] & 0xC0) == 0xC0
            and struct.unpack(">I", init_res[1:5])[0] == 1
            and b"\x00\x04" in init_res
            and b"\x21\x00" in init_res
        )
        check(init_ok, "valid_initial_1200b_control_and_grease", "-> Server Initial + GREASE 0x21")

        # 5-6. Forbidden HTTP/2 SETTINGS (0x02 ENABLE_PUSH, 0x05 MAX_FRAME_SIZE) -> H3_SETTINGS_ERROR
        for sid, label in ((0x02, "enable_push_0x02"), (0x05, "max_frame_size_0x05")):
            resp = _udp_exchange(sock, addr, bytes([0x04, 0x02, sid, 0x01]), timeout=1.5)
            code = _extract_h3_close_error(resp or b"")
            check(
                code == H3_ERR_SETTINGS_ERROR,
                f"forbidden_h2_settings_{label}",
                f"-> err=0x{code:04x}" if code >= 0 else f"-> resp={resp!r}",
            )

        # 7. Duplicate SETTINGS identifier (0x06 twice) -> H3_SETTINGS_ERROR
        dup_set = bytes([0x04, 0x04, 0x06, 0x10, 0x06, 0x20])
        resp = _udp_exchange(sock, addr, dup_set, timeout=1.5)
        code = _extract_h3_close_error(resp or b"")
        check(code == H3_ERR_SETTINGS_ERROR, "duplicate_settings_identifier", f"-> err=0x{code:04x}")

        # 8. Truncated SETTINGS frame payload -> H3_FRAME_ERROR
        trunc_set = bytes([0x04, 0x01, 0x06])
        resp = _udp_exchange(sock, addr, trunc_set, timeout=1.5)
        code = _extract_h3_close_error(resp or b"")
        check(code == H3_ERR_FRAME_ERROR, "truncated_settings_payload", f"-> err=0x{code:04x}")

        # 9. DATA before HEADERS on request stream -> H3_FRAME_UNEXPECTED (0x0105)
        resp = _udp_exchange(sock, addr, b"\x00\x05early", timeout=1.5)
        code = _extract_h3_close_error(resp or b"")
        check(
            code == H3_ERR_FRAME_UNEXPECTED,
            "data_before_headers_request_stream",
            f"-> err=0x{code:04x}",
        )

        # 10. Malformed varint / overlong frame length -> dropped safely, server stays healthy
        r_varint = _udp_exchange(sock, addr, b"\x01\x40", timeout=0.25)
        r_overlen = _udp_exchange(sock, addr, b"\x01\x3f\x00\x00", timeout=0.25)
        h3_ok_resp = _udp_exchange(sock, addr, build_h3_get_frame(b"/"), timeout=1.5)
        check(
            r_varint is None
            and r_overlen is None
            and h3_ok_resp is not None
            and b"Hello from goose-wing HTTP/3!" in h3_ok_resp,
            "malformed_varint_and_overlong_frame_len",
            "-> dropped + post-probe GET / 200 OK",
        )

        # 11. Unknown GREASE frames (0x21 and 0x40 = 0x1F*1+0x21) appended to valid HEADERS
        grease_req = build_h3_get_frame(b"/") + b"\x21\x02\xaa\xbb" + b"\x40\x40\x00"
        grease_res = _udp_exchange(sock, addr, grease_req, timeout=1.5)
        check(
            grease_res is not None
            and grease_res[:1] == b"\x01"
            and b"Hello from goose-wing HTTP/3!" in grease_res,
            "unknown_grease_frames_tolerated",
            "-> HTTP/3 200 OK",
        )

        # 12. Valid SETTINGS followed by duplicate SETTINGS frame -> H3_FRAME_UNEXPECTED (0x0105)
        ok_set = _udp_exchange(sock, addr, b"\x04\x00", timeout=1.5)
        dup_frame = _udp_exchange(sock, addr, b"\x04\x00", timeout=1.5)
        code = _extract_h3_close_error(dup_frame or b"")
        check(
            ok_set == b"\x04\x00" and code == H3_ERR_FRAME_UNEXPECTED,
            "duplicate_settings_frame_on_control",
            f"-> err=0x{code:04x}",
        )

    return passed, failed


def run_native_h3_connection_probes(rebuild: bool = False) -> tuple[int, int]:
    qir_mod = _load_module("qir_runner_for_h3spec", TOOLS_DIR / "quic_interop" / "runner.py")
    exe = qir_mod.ensure_endpoint_binary(force_rebuild=rebuild)
    res = subprocess.run(
        [str(exe), "h3spec-probe"],
        cwd=str(ROOT_DIR),
        capture_output=True,
        text=True,
        timeout=30.0,
        check=False,
    )
    if res.returncode != 0:
        print(f"[!] h3spec-probe failed ({res.returncode}): {res.stderr}", file=sys.stderr)
        return 0, 1

    passed = 0
    failed = 0
    for line in res.stdout.splitlines():
        cols = line.strip().split("\t")
        if len(cols) >= 4 and cols[0] == "H3SPEC_PROBE":
            name, verdict, err_dec = cols[1], cols[2], int(cols[3])
            if verdict == "PASS":
                passed += 1
                print(f"  [PASS] [h3conn] {name:42s} -> err=0x{err_dec:04x}")
            else:
                failed += 1
                print(f"  [FAIL] [h3conn] {name:42s} -> err=0x{err_dec:04x}")
    return passed, failed


def main() -> None:
    parser = argparse.ArgumentParser(
        description="h3spec RFC 9114 / RFC 9000 conformance suite for goose-wing"
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Run live UDP QUIC/H3 probes against tools/http3/server.goose + native H3 FSM probes",
    )
    parser.add_argument(
        "--docker",
        action="store_true",
        help="Run kazu-yamamoto/h3spec against tools/http3/server.goose via docker compose",
    )
    parser.add_argument("--host", default="127.0.0.1", help="Target host for live UDP probes")
    parser.add_argument("--port", type=int, default=0, help="Target UDP port (0 = launch server)")
    parser.add_argument("--rebuild", action="store_true", help="Force rebuild Goose binaries")
    args = parser.parse_args()

    if args.docker:
        compose_file = SUITE_DIR / "docker-compose.yml"
        cmd = [
            "docker",
            "compose",
            "-f",
            str(compose_file),
            "up",
            "--build",
            "--abort-on-container-exit",
            "--exit-code-from",
            "h3spec-runner",
        ]
        sys.exit(subprocess.run(cmd, check=False, cwd=str(ROOT_DIR)).returncode)

    h3_mod = _load_module("http3_runner_for_h3spec", TOOLS_DIR / "http3" / "runner.py")
    print("\nExecuting h3spec RFC 9114 & RFC 9000 Conformance Probes...")
    total_pass = 0
    total_fail = 0

    if args.port > 0:
        p, f = run_live_udp_probes(args.host, args.port, h3_mod.build_h3_get_frame)
        total_pass += p
        total_fail += f
    else:
        srv_exe = h3_mod.ensure_server_binary(force_rebuild=args.rebuild)
        srv = h3_mod.NativeHttp3Server(srv_exe)
        port = srv.start()
        try:
            p, f = run_live_udp_probes("127.0.0.1", port, h3_mod.build_h3_get_frame)
            total_pass += p
            total_fail += f
        finally:
            srv.stop()

    p2, f2 = run_native_h3_connection_probes(rebuild=args.rebuild)
    total_pass += p2
    total_fail += f2

    total = total_pass + total_fail
    print(f"\nh3spec Conformance Completed: {total_pass}/{total} passed, {total_fail} failed.")
    sys.exit(0 if total_fail == 0 and total > 0 else 1)


if __name__ == "__main__":
    main()
