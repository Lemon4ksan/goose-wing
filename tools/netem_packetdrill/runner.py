#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
tc netem & packetdrill verification runner for `goose-wing`.

In `--local` mode (Windows/macOS/Linux):
  1. Launches `tools/http3/server.goose` and `tools/http3/client.goose` through a
     deterministic userspace UDP chaos proxy injecting packet loss, jittered
     delay, packet duplication, and out-of-order reordering.
  2. Parses and validates syntax, timing grammar, TCP flags, sequence ranges,
     and protocol edge-case invariants of all three Google `packetdrill` `.pkt`
     scripts (`tcp_syn_retransmit.pkt`, `tcp_rst_midstream.pkt`,
     `tcp_zero_window.pkt`) and verifies `netem_quic_test.sh`.

In `--docker` mode (Linux with `--cap-add=NET_ADMIN`):
  Builds and executes `tools/netem_packetdrill/Dockerfile` running live kernel
  `tc netem` and `packetdrill`.
"""

from __future__ import annotations

import argparse
import importlib.util
import io
import os
import random
import re
import socket
import subprocess
import sys
import threading
import time
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


def _load_http3_runner() -> Any:
    spec = importlib.util.spec_from_file_location(
        "http3_runner_for_netem", TOOLS_DIR / "http3" / "runner.py"
    )
    assert spec and spec.loader
    mod = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(mod)
    return mod


class DeterministicNetemProxy:
    """Cross-platform userspace UDP chaos proxy emulating `tc netem` profiles.

    Supports deterministic packet drop (`drop_indices`), bounded delay+jitter
    (`delay_ms`, `jitter_ms`), packet duplication (`dup_indices`), and pairwise
    datagram reordering (`reorder_pairs`).
    """

    def __init__(
        self,
        target_host: str,
        target_port: int,
        *,
        drop_indices: set[int] | None = None,
        dup_indices: set[int] | None = None,
        reorder_pairs: bool = False,
        delay_ms: float = 0.0,
        jitter_ms: float = 0.0,
        seed: int = 20260420,
    ) -> None:
        self.target = (target_host, target_port)
        self.drop_indices = set(drop_indices or ())
        self.dup_indices = set(dup_indices or ())
        self.reorder_pairs = reorder_pairs
        self.delay_ms = delay_ms
        self.jitter_ms = jitter_ms
        self.rng = random.Random(seed)
        self.front = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.front.bind(("127.0.0.1", 0))
        self.front.settimeout(0.05)
        self.port: int = self.front.getsockname()[1]

        self.back = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.back.bind(("127.0.0.1", 0))
        self.back.settimeout(0.05)

        self.client_addr: tuple[str, int] | None = None
        self.c2s_seen = 0
        self.dropped = 0
        self.duplicated = 0
        self.reordered = 0
        self.delayed = 0
        self._reorder_buf: list[bytes] = []
        self._running = True
        self._t_c2s = threading.Thread(target=self._loop_c2s, daemon=True)
        self._t_s2c = threading.Thread(target=self._loop_s2c, daemon=True)
        self._t_c2s.start()
        self._t_s2c.start()

    def _sleep_jitter(self) -> None:
        if self.delay_ms <= 0.0:
            return
        delta = self.rng.uniform(-self.jitter_ms, self.jitter_ms) if self.jitter_ms > 0 else 0.0
        wait_s = max(0.001, (self.delay_ms + delta) / 1000.0)
        time.sleep(wait_s)
        self.delayed += 1

    def _forward_c2s(self, data: bytes) -> None:
        self._sleep_jitter()
        self.back.sendto(data, self.target)

    def _loop_c2s(self) -> None:
        while self._running:
            try:
                data, addr = self.front.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                if not self._running:
                    break
                continue
            self.client_addr = addr
            idx = self.c2s_seen
            self.c2s_seen += 1

            if idx in self.drop_indices:
                self.dropped += 1
                continue
            if self.reorder_pairs:
                self._reorder_buf.append(data)
                if len(self._reorder_buf) >= 2:
                    p1, p2 = self._reorder_buf.pop(0), self._reorder_buf.pop(0)
                    self._forward_c2s(p2)
                    self._forward_c2s(p1)
                    self.reordered += 1
                continue
            self._forward_c2s(data)
            if idx in self.dup_indices:
                self.back.sendto(data, self.target)
                self.duplicated += 1

    def _loop_s2c(self) -> None:
        while self._running:
            try:
                data, _ = self.back.recvfrom(4096)
            except TimeoutError:
                continue
            except OSError:
                if not self._running:
                    break
                continue
            if not self.client_addr:
                continue
            try:
                self.front.sendto(data, self.client_addr)
            except OSError:
                if not self._running:
                    break

    def close(self) -> None:
        self._running = False
        for sock in (self.front, self.back):
            try:
                sock.close()
            except Exception:
                pass


def _run_h3_client(client_exe: Path, port: int) -> tuple[bool, str]:
    env = os.environ.copy()
    env["WING_PORT"] = str(port)
    env["PORT"] = str(port)
    res = subprocess.run(
        [str(client_exe)],
        cwd=str(ROOT_DIR),
        env=env,
        capture_output=True,
        text=True,
        timeout=20.0,
        check=False,
    )
    out = res.stdout or ""
    ok = (
        res.returncode == 0
        and "H3_NATIVE_GET_ROOT: PASS" in out
        and "H3_NATIVE_GET_QUERY: PASS" in out
        and "H3_NATIVE_POST_DATA: PASS" in out
    )
    return ok, out.strip().replace("\n", " | ")


def run_udp_chaos_tests(rebuild: bool = False) -> tuple[int, int]:
    h3_mod = _load_http3_runner()
    srv_exe = h3_mod.ensure_server_binary(force_rebuild=rebuild)
    cli_exe = h3_mod.ensure_client_binary(force_rebuild=rebuild)
    build_h3_get_frame = h3_mod.build_h3_get_frame
    h3_root = build_h3_get_frame(b"/")
    h3_info = build_h3_get_frame(b"/api/info")

    srv = h3_mod.NativeHttp3Server(srv_exe)
    port = srv.start()
    passed = 0
    failed = 0

    def record(ok: bool, name: str, detail: str) -> None:
        nonlocal passed, failed
        if ok:
            passed += 1
            print(f"  [PASS] [netem ] {name:38s} -> {detail}")
        else:
            failed += 1
            print(f"  [FAIL] [netem ] {name:38s} -> {detail}")

    try:
        # 1. Packet Loss + Retransmission Recovery
        p_loss = DeterministicNetemProxy("127.0.0.1", port, drop_indices={0})
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.2)
                s.sendto(h3_root, ("127.0.0.1", p_loss.port))
                timed_out = False
                try:
                    s.recvfrom(2048)
                except TimeoutError:
                    timed_out = True
                s.settimeout(2.0)
                s.sendto(h3_root, ("127.0.0.1", p_loss.port))
                reply, _ = s.recvfrom(2048)
            record(
                timed_out and p_loss.dropped == 1 and b"Hello from goose-wing HTTP/3!" in reply,
                "udp_loss_retransmit_recovery",
                f"dropped={p_loss.dropped} recovered=true",
            )
        finally:
            p_loss.close()

        # 2. Delay + Jitter (15ms +/- 5ms) with native http3_client
        p_jit = DeterministicNetemProxy("127.0.0.1", port, delay_ms=15.0, jitter_ms=5.0)
        try:
            t0 = time.monotonic()
            cli_ok, _ = _run_h3_client(cli_exe, p_jit.port)
            elapsed_ms = (time.monotonic() - t0) * 1000.0
            record(
                cli_ok and p_jit.delayed >= 3 and elapsed_ms >= 25.0,
                "udp_delay_jitter_15ms_5ms_h3_client",
                f"delayed={p_jit.delayed} elapsed={elapsed_ms:.1f}ms",
            )
        finally:
            p_jit.close()

        # 3. Packet Duplication with native http3_client
        p_dup = DeterministicNetemProxy("127.0.0.1", port, dup_indices={0, 1, 2})
        try:
            cli_ok, _ = _run_h3_client(cli_exe, p_dup.port)
            record(
                cli_ok and p_dup.duplicated >= 3,
                "udp_duplication_idempotence_h3_client",
                f"duplicated={p_dup.duplicated}",
            )
        finally:
            p_dup.close()

        # 4. Out-of-Order Reordering
        p_reord = DeterministicNetemProxy("127.0.0.1", port, reorder_pairs=True)
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(2.0)
                s.sendto(h3_root, ("127.0.0.1", p_reord.port))
                s.sendto(h3_info, ("127.0.0.1", p_reord.port))
                r1, _ = s.recvfrom(2048)
                r2, _ = s.recvfrom(2048)
            both = r1 + r2
            record(
                p_reord.reordered == 1
                and b"Hello from goose-wing HTTP/3!" in both
                and b'{"protocol":"h3","engine":"goose-wing"}' in both,
                "udp_reorder_out_of_order_recovery",
                f"reordered={p_reord.reordered}",
            )
        finally:
            p_reord.close()

        # 5. Combined Netem Profile (loss + jitter + duplicate + reorder) + native http3_client
        p_all = DeterministicNetemProxy(
            "127.0.0.1",
            port,
            drop_indices={0},
            dup_indices={1, 4},
            delay_ms=10.0,
            jitter_ms=4.0,
        )
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                s.settimeout(0.2)
                s.sendto(h3_root, ("127.0.0.1", p_all.port))
                try:
                    s.recvfrom(2048)
                except TimeoutError:
                    pass
                s.settimeout(2.0)
                s.sendto(h3_root, ("127.0.0.1", p_all.port))
                r_rec, _ = s.recvfrom(2048)
                # Flush duplicate reply if queued
                s.settimeout(0.05)
                try:
                    s.recvfrom(2048)
                except TimeoutError:
                    pass

                p_all.reorder_pairs = True
                s.settimeout(2.0)
                s.sendto(h3_root, ("127.0.0.1", p_all.port))
                s.sendto(h3_info, ("127.0.0.1", p_all.port))
                ra, _ = s.recvfrom(2048)
                rb, _ = s.recvfrom(2048)
                p_all.reorder_pairs = False

            cli_ok, _ = _run_h3_client(cli_exe, p_all.port)
            ok_all = (
                cli_ok
                and b"Hello from goose-wing HTTP/3!" in r_rec
                and b'{"protocol":"h3","engine":"goose-wing"}' in (ra + rb)
                and p_all.dropped >= 1
                and p_all.duplicated >= 2
                and p_all.reordered >= 1
                and p_all.delayed >= 5
            )
            record(
                ok_all,
                "udp_combined_netem_chaos_h3_suite",
                f"drop={p_all.dropped} dup={p_all.duplicated} "
                f"reord={p_all.reordered} delay={p_all.delayed}",
            )
        finally:
            p_all.close()
    finally:
        srv.stop()

    return passed, failed


_TS_RE = re.compile(r"^(?:\+?\d+(?:\.\d+)?)(?:~\+?\d+(?:\.\d+)?)?$")
_OPT_RE = re.compile(r"^--[a-z_]+=\d+$")
_PKT_RE = re.compile(
    r"^(?P<dir>[<>])\s+(?P<flags>[SFPRA.]+)\s+"
    r"(?P<seq>\d+):(?P<end>\d+)\((?P<len>\d+)\)"
    r"(?:\s+ack\s+\d+)?(?:\s+win\s+\d+)?"
    r"(?:\s+<[^>]+>)?$"
)
_SYSCALL_RE = re.compile(r"^[a-z_][a-z0-9_]*\([^)]*\)\s*=\s*.+$")


def _balanced_delims(line: str) -> bool:
    pairs = {"(": ")", "[": "]", "<": ">"}
    closing = set(pairs.values())
    stack: list[str] = []
    # Packet direction token (`< ` or `> `) is not a bracket
    tokens = line.split(None, 2)
    scan = tokens[2] if len(tokens) == 3 and tokens[1] in ("<", ">") else line
    for ch in scan:
        if ch in pairs:
            stack.append(pairs[ch])
        elif ch in closing and (not stack or stack.pop() != ch):
            return False
    return not stack


def validate_packetdrill_script(pkt_path: Path) -> tuple[bool, str]:
    """Parses and validates a Google packetdrill `.pkt` script statically."""
    if not pkt_path.is_file():
        return False, "file missing"
    raw = pkt_path.read_text(encoding="utf-8")
    if "SPDX-License-Identifier: Apache-2.0" not in raw:
        return False, "missing SPDX Apache-2.0 header"

    pkt_events = 0
    syscalls = 0
    for lineno, raw_line in enumerate(raw.splitlines(), start=1):
        line = raw_line.strip()
        if not line or line.startswith("//"):
            continue
        if _OPT_RE.match(line):
            continue
        if not _balanced_delims(line):
            return False, f"line {lineno}: unbalanced delimiters: {line}"
        parts = line.split(None, 1)
        if len(parts) != 2 or not _TS_RE.match(parts[0]):
            return False, f"line {lineno}: invalid timestamp: {line}"
        body = parts[1]
        if body[0] in ("<", ">"):
            m = _PKT_RE.match(body)
            if not m:
                return False, f"line {lineno}: malformed packet event: {body}"
            seq, end, plen = int(m.group("seq")), int(m.group("end")), int(m.group("len"))
            if end - seq != plen:
                return False, f"line {lineno}: seq/len mismatch ({seq}:{end} != {plen})"
            pkt_events += 1
        elif _SYSCALL_RE.match(body):
            syscalls += 1
        else:
            return False, f"line {lineno}: unrecognized packetdrill statement: {body}"

    if pkt_events < 3 or syscalls < 3:
        return False, f"too few events (pkt={pkt_events}, syscalls={syscalls})"

    name = pkt_path.name
    if name == "tcp_syn_retransmit.pkt":
        syn_count = len(re.findall(r">\s+S\s+0:0\(0\)", raw))
        ok_sem = syn_count >= 2 and "EINPROGRESS" in raw and "SO_ERROR" in raw
        if not ok_sem:
            return False, f"missing SYN retransmit invariants (syns={syn_count})"
    elif name == "tcp_rst_midstream.pkt":
        ok_sem = "< R." in raw and "ECONNRESET" in raw and "EPIPE" in raw
        if not ok_sem:
            return False, "missing mid-stream RST / ECONNRESET / EPIPE invariants"
    elif name == "tcp_zero_window.pkt":
        ok_sem = "win 0" in raw and "4096:4096(0)" in raw and "4097:5121(1024)" in raw
        if not ok_sem:
            return False, "missing zero-window / ZWP / reopen invariants"

    return True, f"valid DSL ({pkt_events} pkt events, {syscalls} syscalls)"


def validate_packetdrill_and_scripts() -> tuple[int, int]:
    passed = 0
    failed = 0
    pkt_files = [
        SUITE_DIR / "tcp_syn_retransmit.pkt",
        SUITE_DIR / "tcp_rst_midstream.pkt",
        SUITE_DIR / "tcp_zero_window.pkt",
    ]
    for pkt in pkt_files:
        ok, detail = validate_packetdrill_script(pkt)
        if ok:
            passed += 1
            print(f"  [PASS] [pkt   ] {pkt.name:38s} -> {detail}")
        else:
            failed += 1
            print(f"  [FAIL] [pkt   ] {pkt.name:38s} -> {detail}")

    sh_path = SUITE_DIR / "netem_quic_test.sh"
    sh_ok = False
    sh_detail = "file missing"
    if sh_path.is_file():
        text = sh_path.read_text(encoding="utf-8")
        req_netem = "netem loss 5% delay 15ms 5ms duplicate 2% reorder 10%"
        sh_ok = (
            "SPDX-License-Identifier: Apache-2.0" in text
            and req_netem in text
            and "trap cleanup EXIT" in text
            and "tc qdisc del" in text
        )
        sh_detail = (
            "tc netem profile + cleanup trap verified"
            if sh_ok
            else "missing tc netem profile or cleanup trap"
        )
    if sh_ok:
        passed += 1
        print(f"  [PASS] [script] {sh_path.name:38s} -> {sh_detail}")
    else:
        failed += 1
        print(f"  [FAIL] [script] {sh_path.name:38s} -> {sh_detail}")
    return passed, failed


def main() -> None:
    parser = argparse.ArgumentParser(
        description="tc netem UDP chaos & packetdrill TCP validation suite for goose-wing"
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Run userspace UDP chaos proxy over http3 server/client + validate .pkt scripts",
    )
    parser.add_argument(
        "--validate-pkt-only",
        action="store_true",
        help="Only validate packetdrill .pkt scripts and netem_quic_test.sh",
    )
    parser.add_argument(
        "--docker",
        action="store_true",
        help="Build and run Linux tc netem + packetdrill container (--cap-add=NET_ADMIN)",
    )
    parser.add_argument("--rebuild", action="store_true", help="Force rebuild HTTP/3 binaries")
    args = parser.parse_args()

    if args.docker:
        dockerfile = SUITE_DIR / "Dockerfile"
        img = "goose-wing-netem-packetdrill"
        rc_b = subprocess.run(
            ["docker", "build", "-f", str(dockerfile), "-t", img, "."],
            cwd=str(ROOT_DIR),
            check=False,
        ).returncode
        if rc_b != 0:
            sys.exit(rc_b)
        sys.exit(
            subprocess.run(
                ["docker", "run", "--rm", "--cap-add=NET_ADMIN", img],
                cwd=str(ROOT_DIR),
                check=False,
            ).returncode
        )

    print("\nExecuting tc netem & packetdrill Verification Suite...")
    total_pass = 0
    total_fail = 0
    if not args.validate_pkt_only:
        p1, f1 = run_udp_chaos_tests(rebuild=args.rebuild)
        total_pass += p1
        total_fail += f1

    p2, f2 = validate_packetdrill_and_scripts()
    total_pass += p2
    total_fail += f2

    total = total_pass + total_fail
    print(f"\nnetem & packetdrill Completed: {total_pass}/{total} passed, {total_fail} failed.")
    sys.exit(0 if total_fail == 0 and total > 0 else 1)


if __name__ == "__main__":
    main()
