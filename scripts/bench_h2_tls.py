#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""scripts/bench_h2_tls.py.

Showcase A: Live Full-Stack TLS 1.3 + HTTP/2 + HPACK + RadixRouter + JSON + Headers
benchmark comparing goose-wing against Go stdlib (net/http + crypto/tls).
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
from dataclasses import asdict, dataclass
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


LOADGEN_RE = re.compile(
    r"^LOADGEN_RESULT\s+"
    r"requests=(?P<requests>\d+)\s+"
    r"elapsed_ms=(?P<elapsed_ms>[0-9.]+)\s+"
    r"rps=(?P<rps>[0-9.]+)\s+"
    r"p50_ms=(?P<p50_ms>[0-9.]+)\s+"
    r"p90_ms=(?P<p90_ms>[0-9.]+)\s+"
    r"p99_ms=(?P<p99_ms>[0-9.]+)\s+"
    r"p999_ms=(?P<p999_ms>[0-9.]+)\s+"
    r"min_ms=(?P<min_ms>[0-9.]+)\s+"
    r"max_ms=(?P<max_ms>[0-9.]+)$"
)


@dataclass
class H2TierResult:
    engine: str
    scenario: str
    conns: int
    streams: int
    requests: int
    rps: float
    p50_ms: float
    p99_ms: float
    p999_ms: float
    rss_start_mb: float
    rss_peak_mb: float
    allocs_per_req: float
    alloc_bytes_per_req: float


def find_free_port() -> int:
    with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def latest_source_mtime(root: Path, extra: list[Path]) -> float:
    mtime = 0.0
    for f in extra:
        if f.exists():
            mtime = max(mtime, f.stat().st_mtime)
    for d in ("core", "http", "http2", "tls", "net", "server", "security", "wire", "shim"):
        dp = root / d
        if dp.is_dir():
            for p in dp.rglob("*"):
                if p.suffix in (".goose", ".c", ".h"):
                    mtime = max(mtime, p.stat().st_mtime)
    for top in ("core.goose", "wing.goose"):
        tp = root / top
        if tp.exists():
            mtime = max(mtime, tp.stat().st_mtime)
    return mtime


def build_goose_h2_benchmark(root: Path, out_exe: Path) -> None:
    src = root / "bench" / "h2_tls_benchmark.goose"
    cached = root / "bench" / out_exe.name
    newest = latest_source_mtime(root, [src])
    if cached.exists() and cached.stat().st_mtime >= newest:
        if cached != out_exe:
            shutil.copy2(cached, out_exe)
        return
    if cached.exists():
        cached.unlink()

    attempts = [
        ["goose", "build", "--cc", "gcc", "-O2", "-o", str(out_exe), str(src)],
        ["goose", "build", "-O2", "-o", str(out_exe), str(src)],
    ]
    last_err = ""
    for cmd in attempts:
        proc = subprocess.run(cmd, cwd=str(root), capture_output=True, text=True, check=False)
        if proc.returncode == 0 and out_exe.exists():
            if cached != out_exe:
                shutil.copy2(out_exe, cached)
            return
        last_err = proc.stdout + "\n" + proc.stderr
    raise RuntimeError(f"Failed to build {src}:\n{last_err}")


def build_go_h2_ref(root: Path, out_exe: Path) -> None:
    go_dir = root / "bench" / "go_h2_tls_ref"
    env = dict(os.environ)
    env["GOPROXY"] = "off"
    proc = subprocess.run(
        ["go", "build", "-ldflags=-s -w", "-o", str(out_exe), "."],
        cwd=str(go_dir),
        capture_output=True,
        text=True,
        check=False,
        env=env,
    )
    if proc.returncode != 0 or not out_exe.exists():
        raise RuntimeError(f"Failed to build Go H2 reference:\n{proc.stdout}\n{proc.stderr}")


def fetch_go_memstats(go_exe: Path, port: int) -> dict[str, int]:
    proc = subprocess.run(
        [str(go_exe), "--get", f"https://127.0.0.1:{port}/__memstats"],
        capture_output=True,
        text=True,
        timeout=10,
        check=False,
    )
    if proc.returncode != 0:
        raise RuntimeError(f"fetch_go_memstats failed:\n{proc.stdout}\n{proc.stderr}")
    return json.loads(proc.stdout)


def run_go_loadgen(
    go_exe: Path,
    url: str,
    conns: int,
    streams: int,
    requests: int,
    warmup: int = 16,
) -> dict[str, float]:
    cmd = [
        str(go_exe),
        "--loadgen",
        url,
        "--conns",
        str(conns),
        "--streams",
        str(streams),
        "--requests",
        str(requests),
        "--warmup",
        str(warmup),
    ]
    proc = subprocess.run(cmd, capture_output=True, text=True, check=False)
    if proc.returncode != 0:
        raise RuntimeError(f"loadgen failed:\n{proc.stdout}\n{proc.stderr}")
    for line in proc.stdout.splitlines():
        m = LOADGEN_RE.match(line.strip())
        if m:
            return {k: float(v) for k, v in m.groupdict().items()}
    raise RuntimeError(f"Unparseable loadgen output:\n{proc.stdout}")


def wait_port_ready(port: int, timeout_s: float = 5.0) -> bool:
    deadline = time.monotonic() + timeout_s
    while time.monotonic() < deadline:
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.05):
                return True
        except OSError:
            time.sleep(0.02)
    return False


def bench_engine(
    engine_label: str,
    server_cmd: list[str],
    port: int,
    go_exe: Path,
    tiers: list[tuple[str, int, int, int]],
    is_go_server: bool,
    extra_env: dict[str, str] | None = None,
) -> list[H2TierResult]:
    env = dict(os.environ)
    if extra_env:
        env.update(extra_env)
    proc = subprocess.Popen(
        server_cmd,
        cwd=str(REPO_ROOT),
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        env=env,
    )
    results: list[H2TierResult] = []
    try:
        if is_go_server:
            line = proc.stdout.readline() if proc.stdout else ""
            if "SERVER_READY" not in line:
                out, err = proc.communicate(timeout=2)
                raise RuntimeError(f"{engine_label} did not print SERVER_READY:\n{line}{out}\n{err}")
        elif not wait_port_ready(port):
            out, err = proc.communicate(timeout=2)
            raise RuntimeError(f"{engine_label} did not listen on {port}:\n{out}\n{err}")

        url = f"https://127.0.0.1:{port}/api/v1/users/42"
        rss_start = get_process_rss_mb(proc.pid)

        for label, conns, streams, reqs in tiers:
            mem_before = fetch_go_memstats(go_exe, port) if is_go_server else None

            peak_rss = max(rss_start, get_process_rss_mb(proc.pid))
            from concurrent.futures import ThreadPoolExecutor

            with ThreadPoolExecutor(max_workers=1) as ex:
                fut = ex.submit(run_go_loadgen, go_exe, url, conns, streams, reqs, 16)
                while not fut.done():
                    peak_rss = max(peak_rss, get_process_rss_mb(proc.pid))
                    time.sleep(0.02)
                stats = fut.result()
            peak_rss = max(peak_rss, get_process_rss_mb(proc.pid))

            allocs_per_req = 0.0
            bytes_per_req = 0.0
            if is_go_server and mem_before is not None:
                mem_after = fetch_go_memstats(go_exe, port)
                total_ops = max(reqs + conns * 16, 1)
                allocs_per_req = round(
                    max(0, mem_after["mallocs"] - mem_before["mallocs"]) / total_ops, 2
                )
                bytes_per_req = round(
                    max(0, mem_after["total_alloc"] - mem_before["total_alloc"]) / total_ops, 1
                )

            results.append(
                H2TierResult(
                    engine=engine_label,
                    scenario=label,
                    conns=conns,
                    streams=streams,
                    requests=int(stats["requests"]),
                    rps=stats["rps"],
                    p50_ms=stats["p50_ms"],
                    p99_ms=stats["p99_ms"],
                    p999_ms=stats["p999_ms"],
                    rss_start_mb=rss_start,
                    rss_peak_mb=peak_rss,
                    allocs_per_req=allocs_per_req,
                    alloc_bytes_per_req=bytes_per_req,
                )
            )
    finally:
        proc.terminate()
        try:
            proc.wait(timeout=2.0)
        except Exception:
            proc.kill()
    return results


def format_markdown(
    goose_res: list[H2TierResult],
    go_1t_res: list[H2TierResult],
    go_mc_res: list[H2TierResult],
) -> str:
    lines = [
        "### Live Full-Stack Comparison: TLS 1.3 + HTTP/2 + HPACK + RadixRouter + JSON (`/api/v1/users/{id}`)",
        "",
        "| Scenario | Engine | RPS | p50 (ms) | p99 (ms) | p99.9 (ms) | Peak RSS (MB) | Allocs/req | Bytes/req |",
        "| :--- | :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    for g, o1, om in zip(goose_res, go_1t_res, go_mc_res, strict=True):
        lines.append(
            f"| {g.scenario} | **{g.engine}** | **{g.rps:,.0f}** | {g.p50_ms:.2f} | "
            f"**{g.p99_ms:.2f}** | **{g.p999_ms:.2f}** | **{g.rss_peak_mb:.1f}** | **0** | **0 B** |"
        )
        lines.append(
            f"| {o1.scenario} | {o1.engine} | {o1.rps:,.0f} | {o1.p50_ms:.2f} | "
            f"{o1.p99_ms:.2f} | {o1.p999_ms:.2f} | {o1.rss_peak_mb:.1f} | "
            f"{o1.allocs_per_req:.1f} | {o1.alloc_bytes_per_req:.0f} B |"
        )
        lines.append(
            f"| {om.scenario} | {om.engine} | {om.rps:,.0f} | {om.p50_ms:.2f} | "
            f"{om.p99_ms:.2f} | {om.p999_ms:.2f} | {om.rss_peak_mb:.1f} | "
            f"{om.allocs_per_req:.1f} | {om.alloc_bytes_per_req:.0f} B |"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(description="Showcase A: Live H2 + TLS 1.3 vs Go net/http")
    parser.add_argument("--iters", type=int, default=4000, help="Base requests per tier")
    parser.add_argument("--accel", choices=("auto", "rio", "poll"), default="auto")
    parser.add_argument("--json", action="store_true", dest="emit_json")
    args = parser.parse_args()

    exe_ext = ".exe" if platform.system() == "Windows" else ""
    tiers = [
        ("1 conn x 8 streams", 1, 8, max(args.iters // 2, 1000)),
        ("4 conns x 8 streams", 4, 8, args.iters),
        ("16 conns x 4 streams", 16, 4, args.iters),
    ]

    with tempfile.TemporaryDirectory(prefix="gw_h2_showcase_") as tmp:
        tmp_dir = Path(tmp)
        goose_exe = tmp_dir / f"h2_tls_benchmark{exe_ext}"
        go_exe = tmp_dir / f"go_h2_tls_ref{exe_ext}"
        build_goose_h2_benchmark(REPO_ROOT, goose_exe)
        build_go_h2_ref(REPO_ROOT, go_exe)

        p_goose = find_free_port()
        goose_res = bench_engine(
            f"goose-wing (1T, {args.accel})",
            [str(goose_exe), "--server", str(p_goose), "--accel", args.accel],
            p_goose,
            go_exe,
            tiers,
            is_go_server=False,
        )

        p_go_1t = find_free_port()
        go_1t_res = bench_engine(
            "Go net/http 1.27 (1T)",
            [str(go_exe), "--server", str(p_go_1t)],
            p_go_1t,
            go_exe,
            tiers,
            is_go_server=True,
            extra_env={"GOMAXPROCS": "1"},
        )

        p_go_mc = find_free_port()
        go_mc_res = bench_engine(
            "Go net/http 1.27 (all cores)",
            [str(go_exe), "--server", str(p_go_mc)],
            p_go_mc,
            go_exe,
            tiers,
            is_go_server=True,
            extra_env=None,
        )

    if args.emit_json:
        print(
            json.dumps(
                {
                    "goose_wing": [asdict(r) for r in goose_res],
                    "go_net_http_1t": [asdict(r) for r in go_1t_res],
                    "go_net_http_all_cores": [asdict(r) for r in go_mc_res],
                },
                indent=2,
            )
        )
    else:
        print(format_markdown(goose_res, go_1t_res, go_mc_res))
    return 0


if __name__ == "__main__":
    sys.exit(main())
