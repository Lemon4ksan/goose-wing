#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""scripts/bench_h2_tls.py.

Automated HTTP/2 over TLS 1.3 benchmark harness for goose-wing:
1. Builds bench/h2_tls_benchmark.goose with gcc -O2.
2. Spawns an isolated goose-wing TLS 1.3 + ALPN h2 server on a dynamic port.
3. Continuously tracks server process RSS memory (MB) via get_process_rss_mb.
4. Generates load across multiple concurrency configurations (1, 8, 32 parallel connections).
5. Aggregates throughput (req/s), latency distributions (min, p50, p90, p99, max), and RSS memory.
6. Emits structured Markdown comparison tables and JSON.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from dataclasses import asdict, dataclass
from pathlib import Path

# Add tools/bench-vs-uwebsockets to sys.path to access bench_core telemetry utilities
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
                    mem_str = cols[4].replace("K", "").replace(" ", "").replace("\xa0", "").replace(",", "")
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


H2_RESULT_RE = re.compile(
    r"^H2_TLS_RESULT\s+"
    r"requests=(?P<requests>\d+)\s+"
    r"elapsed_ms=(?P<elapsed_ms>\d+)\s+"
    r"req_per_sec=(?P<req_per_sec>\d+)\s+"
    r"p50_ms=(?P<p50_ms>[0-9]+(?:\.[0-9]+)?)\s+"
    r"p90_ms=(?P<p90_ms>[0-9]+(?:\.[0-9]+)?)\s+"
    r"p99_ms=(?P<p99_ms>[0-9]+(?:\.[0-9]+)?)\s+"
    r"min_ms=(?P<min_ms>[0-9]+(?:\.[0-9]+)?)\s+"
    r"max_ms=(?P<max_ms>[0-9]+(?:\.[0-9]+)?)$"
)


@dataclass
class H2ClientRun:
    requests: int
    elapsed_ms: int
    req_per_sec: int
    p50_ms: float
    p90_ms: float
    p99_ms: float
    min_ms: float
    max_ms: float


@dataclass
class H2ScenarioResult:
    scenario_name: str
    concurrency: int
    total_requests: int
    total_elapsed_ms: float
    steady_req_per_sec: float
    req_per_sec: float
    p50_ms: float
    p90_ms: float
    p99_ms: float
    server_rss_start_mb: float
    server_rss_peak_mb: float


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def build_h2_benchmark(root: Path, out_exe: Path) -> None:
    src = root / "bench" / "h2_tls_benchmark.goose"
    cached = root / "bench" / out_exe.name
    if cached.exists() and cached.stat().st_mtime >= src.stat().st_mtime:
        if cached != out_exe:
            shutil.copy2(cached, out_exe)
        return

    env = dict(os.environ)
    if platform.system() == "Windows":
        gcc_noavx = root / "tools" / "gcc_noavx.cmd"
        if gcc_noavx.exists():
            env["GOOSE_CC"] = str(gcc_noavx)
    attempts = [
        ["goose", "build", "-O2", "-o", str(out_exe), str(src)],
        ["goose", "build", "--cc", "gcc", "-O2", "-o", str(out_exe), str(src)],
    ]
    last_err = ""
    for cmd in attempts:
        proc = subprocess.run(cmd, cwd=str(root), capture_output=True, text=True, check=False, env=env)
        if proc.returncode == 0 and out_exe.exists():
            if cached != out_exe:
                try:
                    shutil.copy2(out_exe, cached)
                except Exception:
                    pass
            return
        last_err = proc.stdout + "\n" + proc.stderr
    raise RuntimeError(f"Failed to build {src}:\n{last_err}")


def run_single_client(exe_path: Path, port: int, iters: int, path: str = "/plaintext") -> H2ClientRun:
    cmd = [str(exe_path), "--client", str(port), "--iters", str(iters), "--path", path]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"Client failed (exit={proc.returncode}):\n{proc.stdout}\n{proc.stderr}")

    for line in proc.stdout.splitlines():
        m = H2_RESULT_RE.match(line.strip())
        if m:
            return H2ClientRun(
                requests=int(m.group("requests")),
                elapsed_ms=int(m.group("elapsed_ms")),
                req_per_sec=int(m.group("req_per_sec")),
                p50_ms=float(m.group("p50_ms")),
                p90_ms=float(m.group("p90_ms")),
                p99_ms=float(m.group("p99_ms")),
                min_ms=float(m.group("min_ms")),
                max_ms=float(m.group("max_ms")),
            )
    raise RuntimeError(f"Could not parse H2_TLS_RESULT from output:\n{proc.stdout}")


def execute_scenario(
    exe_path: Path,
    port: int,
    server_pid: int,
    scenario_name: str,
    concurrency: int,
    iters_per_conn: int,
    path: str = "/plaintext",
) -> H2ScenarioResult:
    rss_start = get_process_rss_mb(server_pid)
    peak_rss = rss_start

    t0 = time.perf_counter()
    runs: list[H2ClientRun] = []
    with ThreadPoolExecutor(max_workers=concurrency) as pool:
        futures = [
            pool.submit(run_single_client, exe_path, port, iters_per_conn, path)
            for _ in range(concurrency)
        ]
        while not all(f.done() for f in futures):
            curr_rss = get_process_rss_mb(server_pid)
            if curr_rss > peak_rss:
                peak_rss = curr_rss
            time.sleep(0.02)
        for f in as_completed(futures):
            runs.append(f.result())

    total_elapsed_sec = max(time.perf_counter() - t0, 0.001)
    total_elapsed_ms = total_elapsed_sec * 1000.0

    final_rss = get_process_rss_mb(server_pid)
    peak_rss = max(peak_rss, final_rss)

    total_reqs = sum(r.requests for r in runs)
    req_per_sec = total_reqs / total_elapsed_sec
    steady_req_per_sec = float(sum(r.req_per_sec for r in runs))

    # Weighted percentiles across runs
    p50_ms = sum(r.p50_ms for r in runs) / len(runs)
    p90_ms = sum(r.p90_ms for r in runs) / len(runs)
    p99_ms = max(r.p99_ms for r in runs)

    return H2ScenarioResult(
        scenario_name=scenario_name,
        concurrency=concurrency,
        total_requests=total_reqs,
        total_elapsed_ms=round(total_elapsed_ms, 2),
        steady_req_per_sec=round(steady_req_per_sec, 2),
        req_per_sec=round(req_per_sec, 2),
        p50_ms=round(p50_ms, 2),
        p90_ms=round(p90_ms, 2),
        p99_ms=round(p99_ms, 2),
        server_rss_start_mb=rss_start,
        server_rss_peak_mb=peak_rss,
    )


def format_markdown_report(results: list[H2ScenarioResult]) -> str:
    lines = [
        "## HTTP/2 over TLS 1.3 Benchmark Results",
        "",
        "Evaluated on native localhost loopback with RFC 8446 TLS 1.3 (Ed25519 X.509 DER verification,",
        "AES-128-GCM cipher suite) and RFC 9113 HTTP/2 multiplexing.",
        "",
        "### Goose-Wing HTTP/2 + TLS 1.3 Concurrency Matrix",
        "",
        "| Scenario | Concurrency | Total Requests | Steady req/s | Wall req/s (incl. startup/warmup) | Latency p50 | Latency p90 | Latency p99 | Server RSS |",
        "| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for r in results:
        lines.append(
            f"| {r.scenario_name} | {r.concurrency} | {r.total_requests:,} | "
            f"**{r.steady_req_per_sec:,.0f}** | {r.req_per_sec:,.0f} | "
            f"{r.p50_ms:.2f} ms | {r.p90_ms:.2f} ms | "
            f"**{r.p99_ms:.2f} ms** | **{r.server_rss_peak_mb:.1f} MB** |"
        )

    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Benchmark goose-wing HTTP/2 over TLS 1.3 throughput, latency, and RSS"
    )
    parser.add_argument(
        "--iters",
        type=int,
        default=500,
        help="Number of requests per client connection (default: 500)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="emit_json",
        help="Emit benchmark results as JSON",
    )
    args = parser.parse_args()

    port = find_free_port()
    exe_name = "h2_tls_benchmark.exe" if platform.system() == "Windows" else "h2_tls_benchmark"

    with tempfile.TemporaryDirectory(prefix="gw_h2_tls_bench_") as tmp_dir:
        exe_path = Path(tmp_dir) / exe_name
        build_h2_benchmark(REPO_ROOT, exe_path)

        server_proc = subprocess.Popen(
            [str(exe_path), "--server", str(port)],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            cwd=str(REPO_ROOT),
        )

        ready = False
        for _ in range(100):
            try:
                s = socket.create_connection(("127.0.0.1", port), timeout=0.05)
                s.close()
                ready = True
                break
            except Exception:
                pass
            time.sleep(0.05)

        if not ready:
            server_proc.terminate()
            stdout, stderr = server_proc.communicate()
            sys.stderr.write(f"Server failed to start on port {port}:\n{stdout}\n{stderr}\n")
            return 1

        try:
            results: list[H2ScenarioResult] = []

            # Scenario 1: Single Connection Ping-Pong (Multiplexed stream reuse)
            res1 = execute_scenario(
                exe_path,
                port,
                server_proc.pid,
                "1 Connection (Multiplexed Ping-Pong)",
                concurrency=1,
                iters_per_conn=args.iters,
            )
            results.append(res1)

            # Scenario 2: 4 Parallel Connections
            res2 = execute_scenario(
                exe_path,
                port,
                server_proc.pid,
                "4 Connections (Concurrent TLS Sessions)",
                concurrency=4,
                iters_per_conn=max(args.iters // 2, 50),
            )
            results.append(res2)

            # Scenario 3: 8 Parallel Connections
            res3 = execute_scenario(
                exe_path,
                port,
                server_proc.pid,
                "8 Connections (High Concurrency)",
                concurrency=8,
                iters_per_conn=max(args.iters // 4, 25),
            )
            results.append(res3)

        finally:
            server_proc.terminate()
            try:
                server_proc.wait(timeout=2.0)
            except Exception:
                server_proc.kill()

    if args.emit_json:
        payload = {
            "h2_tls_scenarios": [asdict(r) for r in results],
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        sys.stdout.write(format_markdown_report(results) + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
