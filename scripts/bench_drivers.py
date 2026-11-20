#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""scripts/bench_drivers.py.

Showcase B: Kernel-Bypass & Registered-Buffer I/O Accelerator Benchmark
1. Live Windows RIO (ReactorAccelMode.Rio) vs WSAPoll (ReactorAccelMode.PollFallback)
2. L2 HTTP/3 datapath: AF_XDP UMEM vs DPDK burst ring vs UdpFallback (serve_h3_l2)
"""

from __future__ import annotations

import argparse
import json
import os
import re
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

SCRIPT_DIR = Path(__file__).resolve().parent
REPO_ROOT = SCRIPT_DIR.parent

H1_RE = re.compile(
    r"^H1_ACCEL_RESULT\s+"
    r"batches=(?P<batches>\d+)\s+"
    r"requests=(?P<requests>\d+)\s+"
    r"pipeline=(?P<pipeline>\d+)\s+"
    r"elapsed_ms=(?P<elapsed_ms>[0-9.]+)\s+"
    r"rps=(?P<rps>\d+)\s+"
    r"p50_ms=(?P<p50_ms>[0-9.]+)\s+"
    r"p99_ms=(?P<p99_ms>[0-9.]+)\s+"
    r"p999_ms=(?P<p999_ms>[0-9.]+)$"
)

L2_RE = re.compile(
    r"^L2_BENCH\s+"
    r"backend=(?P<backend>\S+)\s+"
    r"packets=(?P<packets>\d+)\s+"
    r"elapsed_ns=(?P<elapsed_ns>\d+)\s+"
    r"pps=(?P<pps>\d+)\s+"
    r"ns_per_pkt=(?P<ns_per_pkt>\d+)\s+"
    r"p50_us=(?P<p50_us>[0-9.]+)\s+"
    r"p99_us=(?P<p99_us>[0-9.]+)$"
)


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_driver_bench(root: Path, out_exe: Path) -> None:
    src = root / "bench" / "driver_accel_benchmark.goose"
    attempts = [
        ["goose", "build", "--cc", "gcc", "-O2", "-o", str(out_exe), str(src)],
        ["goose", "build", "-O2", "-o", str(out_exe), str(src)],
    ]
    last_err = ""
    for cmd in attempts:
        proc = subprocess.run(cmd, cwd=str(root), capture_output=True, text=True, check=False)
        if proc.returncode == 0 and out_exe.exists():
            return
        last_err = proc.stdout + "\n" + proc.stderr
    raise RuntimeError(f"Failed to build {src}:\n{last_err}")


def wait_port(port: int, timeout_s: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.05):
                return True
        except OSError:
            time.sleep(0.02)
    return False


def run_h1_accel(exe: Path, accel: str, batches: int, pipeline: int) -> dict[str, object]:
    port = find_free_port()
    srv = subprocess.Popen(
        [str(exe), "--rio-server", str(port), "--accel", accel],
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
    )
    try:
        if not wait_port(port):
            out, err = srv.communicate(timeout=2)
            raise RuntimeError(f"Server ({accel}) failed:\n{out}\n{err}")

        cli = subprocess.run(
            [
                str(exe),
                "--http1-client",
                str(port),
                "--iters",
                str(batches),
                "--pipeline",
                str(pipeline),
            ],
            cwd=str(REPO_ROOT),
            capture_output=True,
            text=True,
            check=False,
        )
        if cli.returncode != 0:
            raise RuntimeError(f"Client failed:\n{cli.stdout}\n{cli.stderr}")
        for line in cli.stdout.splitlines():
            m = H1_RE.match(line.strip())
            if m:
                d = m.groupdict()
                return {
                    "accel": accel,
                    "batches": int(d["batches"]),
                    "requests": int(d["requests"]),
                    "pipeline": int(d["pipeline"]),
                    "elapsed_ms": float(d["elapsed_ms"]),
                    "rps": int(d["rps"]),
                    "p50_ms": float(d["p50_ms"]),
                    "p99_ms": float(d["p99_ms"]),
                    "p999_ms": float(d["p999_ms"]),
                }
        raise RuntimeError(f"Unparseable client output:\n{cli.stdout}")
    finally:
        srv.terminate()
        try:
            srv.wait(timeout=2)
        except Exception:
            srv.kill()


def run_l2_bench(exe: Path, iters: int) -> list[dict[str, object]]:
    proc = subprocess.run(
        [str(exe), "--l2-bench", "--iters", str(iters)],
        cwd=str(REPO_ROOT),
        capture_output=True,
        text=True,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"L2 bench failed:\n{proc.stdout}\n{proc.stderr}")
    rows: list[dict[str, object]] = []
    for line in proc.stdout.splitlines():
        m = L2_RE.match(line.strip())
        if m:
            d = m.groupdict()
            rows.append(
                {
                    "backend": d["backend"],
                    "packets": int(d["packets"]),
                    "elapsed_ns": int(d["elapsed_ns"]),
                    "pps": int(d["pps"]),
                    "ns_per_pkt": int(d["ns_per_pkt"]),
                    "p50_us": float(d["p50_us"]),
                    "p99_us": float(d["p99_us"]),
                }
            )
    return rows


def main() -> int:
    parser = argparse.ArgumentParser(description="Showcase B: Driver Accelerator Benchmark")
    parser.add_argument("--batches", type=int, default=4000)
    parser.add_argument("--l2-iters", type=int, default=3200)
    parser.add_argument("--json", action="store_true", dest="emit_json")
    args = parser.parse_args()

    ext = ".exe" if os.name == "nt" else ""
    with tempfile.TemporaryDirectory(prefix="gw_drv_bench_") as tmp:
        exe = Path(tmp) / f"driver_accel_benchmark{ext}"
        build_driver_bench(REPO_ROOT, exe)

        h1_runs: list[dict[str, object]] = []
        for pipeline in (1, 16):
            for mode in ("rio", "poll"):
                h1_runs.append(run_h1_accel(exe, mode, args.batches, pipeline))

        l2_rows = run_l2_bench(exe, args.l2_iters)

    if args.emit_json:
        print(json.dumps({"h1_rio_vs_poll": h1_runs, "l2_serve_h3": l2_rows}, indent=2))
        return 0

    print("### Part 1: Windows Registered I/O (RIO) vs WSAPoll Loopback\n")
    print("| Mode | Pipeline | RPS | p50 (ms) | p99 (ms) | p99.9 (ms) |")
    print("| :--- | ---: | ---: | ---: | ---: | ---: |")
    for r in h1_runs:
        print(
            f"| `{r['accel']}` | {r['pipeline']} | {r['rps']:,} | "
            f"{r['p50_ms']:.2f} | {r['p99_ms']:.2f} | {r['p999_ms']:.2f} |"
        )

    print("\n### Part 2: L2 Packet Datapath (`serve_h3_l2`: `AF_XDP` & `DPDK` vs `UdpFallback`)\n")
    print("| Backend | Packets | PPS (pkt/s) | ns/pkt | p50 (us) | p99 (us) |")
    print("| :--- | ---: | ---: | ---: | ---: | ---: |")
    for r in l2_rows:
        print(
            f"| `{r['backend']}` | {r['packets']:,} | {r['pps']:,} | "
            f"{r['ns_per_pkt']} | {r['p50_us']:.2f} | {r['p99_us']:.2f} |"
        )
    return 0


if __name__ == "__main__":
    sys.exit(main())
