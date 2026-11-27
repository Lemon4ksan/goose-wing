#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
h2spec HTTP/2 Conformance Test Runner for goose-wing.
Compiles and starts the native Goose HTTP/2 server, executes h2spec (RFC 9113 / RFC 7540),
and formats test outcomes.
"""

import argparse
import io
import os
import re
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.request
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
SERVER_SRC = TOOLS_DIR / "h2spec" / "server.goose"
EDGE_SERVER_SRC = TOOLS_DIR / "h2spec" / "edge_server.goose"
SERVER_EXE = BIN_DIR / ("h2spec_server.exe" if sys.platform == "win32" else "h2spec_server")
EDGE_SERVER_EXE = BIN_DIR / ("h2spec_edge_server.exe" if sys.platform == "win32" else "h2spec_edge_server")
H2SPEC_EXE = BIN_DIR / ("h2spec.exe" if sys.platform == "win32" else "h2spec")


def ensure_server_binary(force_rebuild: bool = False, edge_session: bool = False) -> Path:
    """Ensures the native Goose HTTP/2 server is compiled and ready."""
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    server_src = EDGE_SERVER_SRC if edge_session else SERVER_SRC
    server_exe = EDGE_SERVER_EXE if edge_session else SERVER_EXE
    if not force_rebuild and server_exe.is_file() and server_exe.stat().st_mtime >= server_src.stat().st_mtime:
        return server_exe

    print(f"[*] Building native HTTP/2 h2spec server: {server_src} -> {server_exe}...")
    env = os.environ.copy()
    opt_flag = "-O2"
    if sys.platform == "win32":
        opt_flag = "-O0"
        if "GOOSE_CC" not in env:
            stack_cc = ROOT_DIR / "tools" / "gcc_stack.bat"
            if stack_cc.is_file():
                env["GOOSE_CC"] = str(stack_cc)
    cmd = ["goose", "build", str(server_src), "-o", str(server_exe), opt_flag]
    res = subprocess.run(cmd, check=False, cwd=str(ROOT_DIR), capture_output=True, text=True, env=env)
    if res.returncode != 0:
        print("[!] Failed to build h2spec server:", file=sys.stderr)
        if res.stdout:
            print(res.stdout, file=sys.stderr)
        if res.stderr:
            print(res.stderr, file=sys.stderr)
        sys.exit(1)

    print(f"[+] Successfully built {server_exe.name}")
    return server_exe


def find_h2spec() -> Path:
    """Locates h2spec binary in tools/bin or system PATH."""
    if H2SPEC_EXE.is_file() and os.access(H2SPEC_EXE, os.X_OK):
        return H2SPEC_EXE

    found = shutil.which("h2spec.exe" if sys.platform == "win32" else "h2spec")
    if found:
        return Path(found)

    print(
        "[!] h2spec binary not found! Please build or place it in tools/bin/h2spec.exe",
        file=sys.stderr,
    )
    sys.exit(1)


class GooseH2Server:
    """Coordinates lifecycle of the native Goose HTTP/2 server."""

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
                urllib.request.urlopen(f"http://127.0.0.1:{self.port}/shutdown", timeout=0.5)
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


H2_PREFACE = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
H2_FRAME_DATA = 0x00
H2_FRAME_HEADERS = 0x01
H2_FRAME_RST_STREAM = 0x03
H2_FRAME_SETTINGS = 0x04
H2_FRAME_GOAWAY = 0x07
H2_FRAME_WINDOW_UPDATE = 0x08
H2_FLAG_END_STREAM = 0x01
H2_FLAG_ACK = 0x01
H2_FLAG_END_HEADERS = 0x04
H2_ERR_FLOW_CONTROL_ERROR = 0x03


def _pack_h2_frame(frame_type: int, flags: int, stream_id: int, payload: bytes) -> bytes:
    n = len(payload)
    hdr = bytes([(n >> 16) & 0xFF, (n >> 8) & 0xFF, n & 0xFF, frame_type, flags])
    return hdr + struct.pack(">I", stream_id & 0x7FFFFFFF) + payload


def _recv_exact(sock: socket.socket, n: int) -> bytes:
    buf = bytearray()
    while len(buf) < n:
        chunk = sock.recv(n - len(buf))
        if not chunk:
            break
        buf.extend(chunk)
    return bytes(buf)


def _read_one_h2_frame(sock: socket.socket, timeout: float = 0.5) -> tuple[int, int, int, bytes] | None:
    sock.settimeout(timeout)
    try:
        hdr = _recv_exact(sock, 9)
    except (TimeoutError, OSError):
        return None
    if len(hdr) < 9:
        return None
    length = (hdr[0] << 16) | (hdr[1] << 8) | hdr[2]
    ftype = hdr[3]
    flags = hdr[4]
    sid = struct.unpack(">I", hdr[5:9])[0] & 0x7FFFFFFF
    try:
        payload = _recv_exact(sock, length) if length > 0 else b""
    except (TimeoutError, OSError):
        return None
    if len(payload) < length:
        return None
    return (ftype, flags, sid, payload)


def _read_h2_frames(
    sock: socket.socket,
    timeout: float = 0.5,
    stop_types: set[int] | None = None,
    max_frames: int = 32,
) -> list[tuple[int, int, int, bytes]]:
    frames: list[tuple[int, int, int, bytes]] = []
    cur_timeout = timeout
    for _ in range(max_frames):
        frame = _read_one_h2_frame(sock, timeout=cur_timeout)
        if frame is None:
            break
        frames.append(frame)
        if stop_types and frame[0] in stop_types:
            break
        cur_timeout = 0.05
    return frames


def _hpack_literal_without_index(name: bytes, val: bytes) -> bytes:
    return b"\x00" + bytes([len(name)]) + name + bytes([len(val)]) + val


def _build_h2_request_headers(method_idx: int, path: bytes) -> bytes:
    # Static table: :method GET=2 (0x82), POST=3 (0x83), :scheme http=6 (0x86)
    block = bytearray([0x80 | method_idx, 0x86])
    # Literal :path without indexing (index 4 = 0x04)
    block.append(0x04)
    block.append(len(path))
    block.extend(path)
    block.extend(_hpack_literal_without_index(b":authority", b"127.0.0.1"))
    return bytes(block)


def _h2_handshake(port: int, client_settings: bytes = b"") -> tuple[socket.socket, int]:
    sock = socket.create_connection(("127.0.0.1", port), timeout=3.0)
    sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
    sock.sendall(
        H2_PREFACE
        + _pack_h2_frame(H2_FRAME_SETTINGS, 0, 0, client_settings)
        + _pack_h2_frame(H2_FRAME_SETTINGS, H2_FLAG_ACK, 0, b"")
    )
    srv_init_win = 65535
    # Server emits its SETTINGS frame and SETTINGS ACK immediately upon receiving preface.
    for _ in range(2):
        frame = _read_one_h2_frame(sock, timeout=0.5)
        if frame is None:
            break
        ftype, flags, sid, payload = frame
        if ftype == H2_FRAME_SETTINGS and (flags & H2_FLAG_ACK) == 0 and sid == 0:
            for off in range(0, len(payload), 6):
                if off + 6 <= len(payload):
                    pid, pval = struct.unpack(">HI", payload[off : off + 6])
                    if pid == 0x04:
                        srv_init_win = pval
    return sock, srv_init_win


def run_window_update_backpressure_checks(port: int) -> tuple[int, int]:
    """Verifies RFC 9113 Section 6.9 streaming WINDOW_UPDATE and flow-control backpressure."""
    passed = 0
    failed = 0

    def check(ok: bool, name: str, detail: str = "") -> None:
        nonlocal passed, failed
        if ok:
            passed += 1
            print(f"  [PASS] {name}")
        else:
            failed += 1
            suffix = f" ({detail})" if detail else ""
            print(f"  [FAIL] {name}{suffix}")

    print("\n[*] Running HTTP/2 streaming WINDOW_UPDATE & backpressure checks (RFC 9113 §6.9)...")

    # 1. Streaming POST /echo > initial 8 KiB window receives conn + stream WINDOW_UPDATE
    sock, srv_win = _h2_handshake(port)
    try:
        req_hdrs = _build_h2_request_headers(3, b"/echo")
        sock.sendall(_pack_h2_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS, 1, req_hdrs))
        chunk = b"W" * 4096
        conn_wu = 0
        stream_wu = 0
        got_headers = False
        for idx in range(3):
            flags = H2_FLAG_END_STREAM if idx == 2 else 0
            sock.sendall(_pack_h2_frame(H2_FRAME_DATA, flags, 1, chunk))
            want_stop = {H2_FRAME_HEADERS} if idx == 2 else None
            max_fr = 8 if idx == 2 else 2
            for ftype, _fl, sid, payload in _read_h2_frames(
                sock, timeout=0.3, stop_types=want_stop, max_frames=max_fr
            ):
                if ftype == H2_FRAME_WINDOW_UPDATE and len(payload) == 4:
                    inc = struct.unpack(">I", payload)[0] & 0x7FFFFFFF
                    if sid == 0:
                        conn_wu += inc
                    elif sid == 1:
                        stream_wu += inc
                elif ftype == H2_FRAME_HEADERS and sid == 1:
                    got_headers = True
        check(
            conn_wu >= 4096 and stream_wu >= 4096 and got_headers,
            "Streaming ingress POST > 8 KiB emits connection & stream WINDOW_UPDATE",
            f"srv_win={srv_win}, conn_wu={conn_wu}, stream_wu={stream_wu}, hdrs={got_headers}",
        )
    finally:
        sock.close()

    # 2. WINDOW_UPDATE exceeding 2^31 - 1 window ceiling triggers GOAWAY FLOW_CONTROL_ERROR (0x03)
    sock2, _ = _h2_handshake(port)
    try:
        sock2.sendall(
            _pack_h2_frame(H2_FRAME_WINDOW_UPDATE, 0, 0, struct.pack(">I", 0x7FFFFFFF))
        )
        frames2 = _read_h2_frames(
            sock2, timeout=0.6, stop_types={H2_FRAME_GOAWAY, H2_FRAME_RST_STREAM}
        )
        saw_fc_err = False
        for ftype, _fl, _sid, payload in frames2:
            if (
                ftype == H2_FRAME_GOAWAY
                and len(payload) >= 8
                and struct.unpack(">I", payload[4:8])[0] == H2_ERR_FLOW_CONTROL_ERROR
            ) or (
                ftype == H2_FRAME_RST_STREAM
                and len(payload) == 4
                and struct.unpack(">I", payload)[0] == H2_ERR_FLOW_CONTROL_ERROR
            ):
                saw_fc_err = True
        check(
            saw_fc_err,
            "Connection WINDOW_UPDATE overflow triggers GOAWAY FLOW_CONTROL_ERROR (0x03)",
            f"frames={[(f[0], f[2]) for f in frames2]}",
        )
    finally:
        sock2.close()

    # 3. Tiny client SETTINGS_INITIAL_WINDOW_SIZE=8 clamps server egress DATA frame size
    tiny_settings = struct.pack(">HI", 0x04, 8)
    sock3, _ = _h2_handshake(port, client_settings=tiny_settings)
    try:
        req_hdrs3 = _build_h2_request_headers(2, b"/ping")
        sock3.sendall(
            _pack_h2_frame(H2_FRAME_HEADERS, H2_FLAG_END_HEADERS | H2_FLAG_END_STREAM, 1, req_hdrs3)
        )
        frames3 = _read_h2_frames(sock3, timeout=0.6, stop_types={H2_FRAME_DATA})
        data_frames = [(fl, len(p)) for ft, fl, sid, p in frames3 if ft == H2_FRAME_DATA and sid == 1]
        clamped_ok = (
            len(data_frames) == 1
            and data_frames[0][1] == 8
            and (data_frames[0][0] & H2_FLAG_END_STREAM) == 0
        )
        check(
            clamped_ok,
            "Server respects client SETTINGS_INITIAL_WINDOW_SIZE=8 egress backpressure",
            f"frames={[(f[0], f[1], f[2], len(f[3])) for f in frames3]}",
        )
    finally:
        sock3.close()

    return passed, failed


def check_h2spec_zero_skipped(stdout: str) -> bool:
    """Fails if h2spec reports any skipped tests so no spec sections are silently omitted."""
    m = re.search(r"(\d+)\s+tests,\s+(\d+)\s+passed,\s+(\d+)\s+skipped,\s+(\d+)\s+failed", stdout)
    if not m:
        return True
    skipped = int(m.group(3))
    if skipped > 0:
        print(f"[!] ERROR: h2spec silently skipped {skipped} test(s)!", file=sys.stderr)
        return False
    return True


def run_h2spec(
    spec_section: str = "all",
    strict: bool = False,
    timeout_sec: int = 2,
    verbose: bool = False,
    force_rebuild: bool = False,
    check_backpressure: bool = True,
    edge_session: bool = False,
) -> int:
    """Executes h2spec against the server and prints formatted results."""
    server_exe = ensure_server_binary(force_rebuild=force_rebuild, edge_session=edge_session)
    h2spec_bin = find_h2spec()

    server = GooseH2Server(server_exe)
    print(f"[*] Starting native Goose HTTP/2 server ({server_exe.name})...")
    port = server.start()
    print(f"[+] Server listening on 127.0.0.1:{port}")

    cmd = [
        str(h2spec_bin),
        "-h",
        "127.0.0.1",
        "-p",
        str(port),
        "-P",
        "/ping",
        "-o",
        str(timeout_sec),
    ]
    if strict:
        cmd.append("-S")
    if verbose:
        cmd.append("-v")

    if spec_section and spec_section != "all":
        cmd.append(spec_section)

    print(f"[*] Executing h2spec: {' '.join(cmd[1:])}")
    try:
        t0 = time.time()
        proc = subprocess.run(cmd, check=False, capture_output=True, text=True)
        dur = time.time() - t0
        print(f"[+] Completed in {dur:.2f}s\n")

        print(proc.stdout)
        if proc.stderr:
            print("[!] Standard Error:\n", proc.stderr, file=sys.stderr)

        rc = proc.returncode
        if not check_h2spec_zero_skipped(proc.stdout or ""):
            rc = 1
    finally:
        server.stop()
        print("[+] Server stopped cleanly.")

    if check_backpressure:
        bp_server = GooseH2Server(server_exe)
        bp_port = bp_server.start()
        try:
            bp_passed, bp_failed = run_window_update_backpressure_checks(bp_port)
            print(f"[+] Backpressure checks: {bp_passed}/{bp_passed + bp_failed} passed.")
            if bp_failed > 0:
                rc = 1
        finally:
            bp_server.stop()

    return rc


def main():
    parser = argparse.ArgumentParser(
        description="Run h2spec HTTP/2 Conformance Testing against goose-wing",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "spec",
        nargs="?",
        default="all",
        help="Spec section to test: generic, http2/3.5, http2/4.1, hpack, or all",
    )
    parser.add_argument("-S", "--strict", action="store_true", help="Run in strict mode")
    parser.add_argument(
        "-o", "--timeout", type=int, default=2, help="Timeout in seconds for each test"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose test log")
    parser.add_argument("--rebuild", action="store_true", help="Force rebuild server binary")
    parser.add_argument(
        "--no-backpressure",
        action="store_true",
        help="Skip supplemental RFC 9113 Section 6.9 WINDOW_UPDATE backpressure checks",
    )
    parser.add_argument(
        "--edge-session",
        action="store_true",
        help="Run h2spec against http2::H2EdgeSession server (tools/h2spec/edge_server.goose)",
    )

    args = parser.parse_args()
    rc = run_h2spec(
        spec_section=args.spec,
        strict=args.strict,
        timeout_sec=args.timeout,
        verbose=args.verbose,
        force_rebuild=args.rebuild,
        check_backpressure=not args.no_backpressure,
        edge_session=args.edge_session,
    )
    sys.exit(rc)


if __name__ == "__main__":
    main()
