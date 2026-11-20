#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""scripts/bench_footprint.py.

Showcase C: Edge Footprint Comparison (goose-wing vs Go 1.27 stdlib)
1. Stripped binary size (KB / MB)
2. Cold start to first 200 OK HTTP response (ms, median of 15 runs)
3. Live TCP connection RSS scaling: Idle -> 256 -> 1,000 sockets + active p50/p99/p99.9
4. In-process 10,000-slot SoAConnTable + TickTimerWheel memory delta
5. Runtime zero-heap allocation proof (10,000 full-pipeline iterations) vs Go ReadMemStats
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import socket
import statistics
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent
BENCH_TOOLS_DIR = REPO_ROOT / "tools" / "bench-vs-uwebsockets"
if str(BENCH_TOOLS_DIR) not in sys.path:
    sys.path.insert(0, str(BENCH_TOOLS_DIR))

try:
    from bench_core import get_process_rss_mb
except ImportError:

    def get_process_rss_mb(pid: int) -> float:
        if not pid or pid <= 0:
            return 0.0
        try:
            if os.name == "nt":
                out = subprocess.check_output(
                    f'tasklist /FI "PID eq {pid}" /FO CSV /NH', shell=True
                ).decode("utf-8", errors="replace")
                cols = out.replace('"', "").strip().split(",")
                if len(cols) >= 5:
                    mem_str = (
                        cols[4]
                        .replace("K", "")
                        .replace(" ", "")
                        .replace("\xa0", "")
                        .replace(",", "")
                    )
                    return round(float(mem_str) / 1024, 2)
            elif os.name == "posix":
                statm_path = f"/proc/{pid}/statm"
                if os.path.exists(statm_path):
                    with open(statm_path) as f:
                        parts = f.read().split()
                        return round((int(parts[1]) * 4096) / (1024 * 1024), 2)
        except Exception:
            pass
        return 0.0


ZERO_ALLOC_RE = re.compile(
    r"^ZERO_ALLOC_PROOF\s+"
    r"iters=(?P<iters>\d+)\s+"
    r"events=(?P<events>\d+)\s+"
    r"bytes=(?P<bytes>\d+)\s+"
    r"frees=(?P<frees>\d+)\s+"
    r"stack_growth=(?P<stack_growth>-?\d+)$"
)


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_binaries(root: Path, tmp_dir: Path) -> tuple[Path, Path, Path]:
    ext = ".exe" if os.name == "nt" else ""
    src = root / "bench" / "scale_footprint_benchmark.goose"
    goose_exe = tmp_dir / f"scale_footprint_goose{ext}"
    alloc_exe = tmp_dir / f"scale_footprint_alloc{ext}"
    go_exe = tmp_dir / f"go_edge_ref{ext}"

    proc = subprocess.run(
        ["goose", "build", "--cc", "gcc", "-O2", "-o", str(goose_exe), str(src)],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0 or not goose_exe.exists():
        raise RuntimeError(f"Failed building {src}:\n{proc.stdout}\n{proc.stderr}")

    strip_bin = shutil.which("strip")
    if strip_bin:
        subprocess.run([strip_bin, "-s", str(goose_exe)], check=False)

    hook_hdr = root / "tests" / "lit" / "alloc_hook.h"
    proc_alloc = subprocess.run(
        [
            "goose",
            "build",
            "--cc",
            "gcc",
            "-O2",
            "--include",
            str(hook_hdr),
            "-o",
            str(alloc_exe),
            str(src),
        ],
        cwd=str(root),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc_alloc.returncode != 0 or not alloc_exe.exists():
        raise RuntimeError(
            f"Failed building instrumented {src}:\n{proc_alloc.stdout}\n{proc_alloc.stderr}"
        )

    env = dict(os.environ)
    env["GOPROXY"] = "off"
    proc_go = subprocess.run(
        ["go", "build", "-ldflags=-s -w", "-o", str(go_exe), "."],
        cwd=str(root / "bench" / "go_h2_tls_ref"),
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    if proc_go.returncode != 0 or not go_exe.exists():
        raise RuntimeError(f"Failed building Go ref:\n{proc_go.stdout}\n{proc_go.stderr}")

    return goose_exe, alloc_exe, go_exe


def measure_cold_start_ms(exe: Path, flag: str, runs: int = 15) -> float:
    samples_ms: list[float] = []
    req = b"GET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n"
    for _ in range(runs):
        port = find_free_port()
        t0 = time.perf_counter()
        proc = subprocess.Popen(
            [str(exe), flag, str(port)],
            cwd=str(REPO_ROOT),
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
        )
        try:
            deadline = t0 + 5.0
            ok = False
            while time.perf_counter() < deadline:
                try:
                    with socket.create_connection(("127.0.0.1", port), timeout=0.2) as sock:
                        sock.sendall(req)
                        resp = b""
                        while b"PONG" not in resp:
                            chunk = sock.recv(4096)
                            if not chunk:
                                break
                            resp += chunk
                        if b"200 OK" in resp and b"PONG" in resp:
                            samples_ms.append((time.perf_counter() - t0) * 1000.0)
                            ok = True
                            break
                except OSError:
                    time.sleep(0.0005)
            if not ok:
                raise RuntimeError(f"Cold start timed out for {exe} {flag}")
        finally:
            proc.terminate()
            try:
                proc.wait(timeout=2)
            except Exception:
                proc.kill()
    return round(statistics.median(samples_ms), 2)


def recv_http_response(sock: socket.socket) -> bytes:
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("socket closed before headers")
        buf += chunk
    hdr_end = buf.index(b"\r\n\r\n") + 4
    headers_lower = buf[:hdr_end].lower()
    content_len = 0
    for line in headers_lower.split(b"\r\n"):
        if line.startswith(b"content-length:"):
            content_len = int(line.split(b":", 1)[1].strip())
            break
    while len(buf) < hdr_end + content_len:
        chunk = sock.recv(4096)
        if not chunk:
            raise RuntimeError("socket closed before body")
        buf += chunk
    return buf


def wait_port(port: int, timeout_s: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.05):
                return True
        except OSError:
            time.sleep(0.01)
    return False


def open_keepalive_sockets(port: int, count: int, sockets_out: list[socket.socket]) -> None:
    while len(sockets_out) < count:
        for _ in range(5):
            s: socket.socket | None = None
            try:
                s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                s.settimeout(5.0)
                s.connect(("127.0.0.1", port))
                sockets_out.append(s)
                break
            except OSError:
                if s is not None:
                    s.close()
                time.sleep(0.005)
        else:
            raise RuntimeError(f"Failed to reach {count} connections (got {len(sockets_out)})")


def measure_live_conn_scaling(
    exe: Path, flag: str, is_go: bool, active_reqs: int = 2000
) -> dict[str, float]:
    port = find_free_port()
    proc = subprocess.Popen(
        [str(exe), flag, str(port)],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    conns: list[socket.socket] = []
    req = (
        b"GET /api/v1/items/42 HTTP/1.1\r\nHost: localhost\r\nX-Client-Region: eu-central-1\r\n\r\n"
    )
    try:
        if not wait_port(port):
            out, err = proc.communicate(timeout=2)
            raise RuntimeError(f"Server failed:\n{out}\n{err}")

        time.sleep(0.1)
        rss_idle = get_process_rss_mb(proc.pid)

        open_keepalive_sockets(port, 256, conns)
        for idx in range(16):
            conns[idx].sendall(req)
            recv_http_response(conns[idx])
        time.sleep(0.05)
        rss_256 = get_process_rss_mb(proc.pid)

        open_keepalive_sockets(port, 1000, conns)
        # Prime active sockets and measure Go memstats delta if Go
        mem_before = None
        if is_go:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/__memstats", timeout=5) as r:
                mem_before = json.loads(r.read().decode("utf-8"))

        lats_ms: list[float] = []
        n_active_sample = min(64, len(conns))
        for i in range(active_reqs):
            s = conns[i % n_active_sample]
            t0 = time.perf_counter()
            s.sendall(req)
            resp = recv_http_response(s)
            dt = (time.perf_counter() - t0) * 1000.0
            if b"200 OK" not in resp:
                raise RuntimeError(f"Unexpected response under 1k conns: {resp[:80]!r}")
            lats_ms.append(dt)

        rss_1000 = get_process_rss_mb(proc.pid)
        allocs_per_req = 0.0
        bytes_per_req = 0.0
        if is_go and mem_before is not None:
            with urllib.request.urlopen(f"http://127.0.0.1:{port}/__memstats", timeout=5) as r:
                mem_after = json.loads(r.read().decode("utf-8"))
            allocs_per_req = round(
                max(0, mem_after["mallocs"] - mem_before["mallocs"]) / max(active_reqs, 1), 2
            )
            bytes_per_req = round(
                max(0, mem_after["total_alloc"] - mem_before["total_alloc"]) / max(active_reqs, 1),
                1,
            )

        lats_ms.sort()
        n = len(lats_ms)
        return {
            "rss_idle_mb": rss_idle,
            "rss_256_mb": rss_256,
            "rss_1000_mb": rss_1000,
            "p50_ms": round(lats_ms[(n * 50) // 100], 3),
            "p99_ms": round(lats_ms[(n * 99) // 100], 3),
            "p999_ms": round(lats_ms[(n * 999) // 1000], 3),
            "allocs_per_req": allocs_per_req,
            "bytes_per_req": bytes_per_req,
        }
    finally:
        for s in conns:
            try:
                s.close()
            except OSError:
                pass
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except Exception:
            proc.kill()


def sample_soa_probe_rss_mb(goose_exe: Path, flag: str) -> float:
    port = find_free_port()
    proc = subprocess.Popen(
        [str(goose_exe), flag, str(port)],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        if not wait_port(port):
            out, err = proc.communicate(timeout=2)
            raise RuntimeError(f"SoA probe {flag} failed:\n{out}\n{err}")
        time.sleep(0.05)
        return get_process_rss_mb(proc.pid)
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2)
        except Exception:
            proc.kill()


def measure_soa_10k(goose_exe: Path) -> dict[str, float]:
    rss_before = sample_soa_probe_rss_mb(goose_exe, "--soa-idle")
    rss_after = sample_soa_probe_rss_mb(goose_exe, "--soa-10k")
    delta_mb = round(max(0.0, rss_after - rss_before), 2)
    bytes_per_conn = round((delta_mb * 1024.0 * 1024.0) / 10000.0, 1)
    return {
        "rss_before_mb": rss_before,
        "rss_after_mb": rss_after,
        "delta_mb": delta_mb,
        "bytes_per_conn": bytes_per_conn,
    }


def measure_zero_alloc(alloc_exe: Path, iters: int = 10000) -> dict[str, int]:
    proc = subprocess.run(
        [str(alloc_exe), "--zero-alloc-proof", "--iters", str(iters)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"Zero alloc proof failed:\n{proc.stdout}\n{proc.stderr}")
    for line in proc.stdout.splitlines():
        m = ZERO_ALLOC_RE.match(line.strip())
        if m:
            return {k: int(v) for k, v in m.groupdict().items()}
    raise RuntimeError(f"Unparseable zero alloc output:\n{proc.stdout}")


def main() -> int:
    parser = argparse.ArgumentParser(description="Showcase C: Edge Footprint Comparison")
    parser.add_argument("--active-reqs", type=int, default=2000)
    parser.add_argument("--json", action="store_true", dest="emit_json")
    args = parser.parse_args()

    with tempfile.TemporaryDirectory(prefix="gw_footprint_") as tmp:
        tmp_dir = Path(tmp)
        goose_exe, alloc_exe, go_exe = build_binaries(REPO_ROOT, tmp_dir)

        goose_size_kb = round(goose_exe.stat().st_size / 1024.0, 1)
        go_size_kb = round(go_exe.stat().st_size / 1024.0, 1)

        goose_cold_ms = measure_cold_start_ms(goose_exe, "--http-server", runs=15)
        go_cold_ms = measure_cold_start_ms(go_exe, "--http1-server", runs=15)

        goose_scale = measure_live_conn_scaling(
            goose_exe, "--http-server", is_go=False, active_reqs=args.active_reqs
        )
        go_scale = measure_live_conn_scaling(
            go_exe, "--http1-server", is_go=True, active_reqs=args.active_reqs
        )

        soa_10k = measure_soa_10k(goose_exe)
        zero_alloc = measure_zero_alloc(alloc_exe, iters=10000)

    payload = {
        "binary_size_kb": {"goose_wing": goose_size_kb, "go_1_27": go_size_kb},
        "cold_start_ms": {"goose_wing": goose_cold_ms, "go_1_27": go_cold_ms},
        "live_scaling": {"goose_wing": goose_scale, "go_1_27": go_scale},
        "soa_10k": soa_10k,
        "zero_alloc_proof": zero_alloc,
    }
    if args.emit_json:
        print(json.dumps(payload, indent=2))
        return 0

    print("### Edge Footprint Comparison (Stripped `goose-wing` vs Stripped Go 1.27)\n")
    print("| Metric | goose-wing | Go 1.27 (`net/http`) |")
    print("| :--- | ---: | ---: |")
    print(
        f"| Stripped binary size | **{goose_size_kb / 1024.0:.2f} MB** ({goose_size_kb:.0f} KB) | "
        f"{go_size_kb / 1024.0:.2f} MB ({go_size_kb:.0f} KB) |"
    )
    print(
        f"| Cold start to 1st `200 OK` (median/15) | **{goose_cold_ms:.2f} ms** | {go_cold_ms:.2f} ms |"
    )
    print(
        f"| Idle server RSS | **{goose_scale['rss_idle_mb']:.1f} MB** | {go_scale['rss_idle_mb']:.1f} MB |"
    )
    print(
        f"| 256 live TCP connections RSS | **{goose_scale['rss_256_mb']:.1f} MB** | {go_scale['rss_256_mb']:.1f} MB |"
    )
    print(
        f"| 1,000 live TCP connections RSS | **{goose_scale['rss_1000_mb']:.1f} MB** | {go_scale['rss_1000_mb']:.1f} MB |"
    )
    print(
        f"| Active p50 latency @ 1,000 conns | {goose_scale['p50_ms']:.3f} ms | {go_scale['p50_ms']:.3f} ms |"
    )
    print(
        f"| Active p99 latency @ 1,000 conns | **{goose_scale['p99_ms']:.3f} ms** | {go_scale['p99_ms']:.3f} ms |"
    )
    print(
        f"| Active p99.9 latency @ 1,000 conns | **{goose_scale['p999_ms']:.3f} ms** | {go_scale['p999_ms']:.3f} ms |"
    )
    print(
        f"| Heap allocs / bytes per `/api/v1/items/{{id}}` req | "
        f"**{zero_alloc['events']} / {zero_alloc['bytes']} B** | "
        f"{go_scale['allocs_per_req']:.1f} / {go_scale['bytes_per_req']:.0f} B |"
    )
    print(
        f"| 10,000-slot `SoAConnTable` + `TickTimerWheel` | "
        f"+**{soa_10k['delta_mb']:.1f} MB** ({soa_10k['bytes_per_conn']:.0f} B/conn) | N/A |"
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
