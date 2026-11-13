#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""scripts/bench_codecs.py.

Builds and executes bench/codec_perf_benchmark.goose with gcc optimization flags,
parses structured BENCH output lines, and prints a Markdown summary table or JSON.
"""

from __future__ import annotations

import argparse
import json
import platform
import re
import shutil
import subprocess
import sys
import tempfile
from dataclasses import asdict, dataclass
from pathlib import Path

BENCH_LINE_RE = re.compile(
    r"^BENCH\s+(?P<name>\S+)\s+iters=(?P<iters>\d+)\s+"
    r"ns_op=(?P<ns_op>[0-9]+(?:\.[0-9]+)?)\s+"
    r"mb_s=(?P<mb_s>[0-9]+(?:\.[0-9]+)?)"
    r"(?:\s+checksum=(?P<checksum>\d+))?$"
)


@dataclass
class BenchResult:
    name: str
    iters: int
    ns_op: float
    ops_sec: float
    mb_s: float
    checksum: int | None = None


def find_goose_binary() -> str:
    binary = shutil.which("goose")
    if binary:
        return binary
    home = Path.home()
    pattern = ".goose/*/goose.exe" if platform.system() == "Windows" else ".goose/*/goose"
    candidates = sorted(home.glob(pattern))
    if candidates:
        return str(candidates[0])
    return "goose"


def build_benchmark(root: Path, src: Path, out_exe: Path) -> str:
    goose = find_goose_binary()
    attempts = ["-O3", "-O2"]
    last_err = ""
    for opt_flag in attempts:
        cmd = [goose, "build", "--cc", "gcc", opt_flag, "-o", str(out_exe), str(src)]
        proc = subprocess.run(
            cmd,
            cwd=str(root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if proc.returncode == 0 and out_exe.exists():
            return opt_flag
        last_err = (proc.stdout + "\n" + proc.stderr).strip()

    raise RuntimeError(f"Failed to build {src} with goose build --cc gcc:\n{last_err}")


def parse_bench_output(stdout: str) -> list[BenchResult]:
    results: list[BenchResult] = []
    for raw_line in stdout.splitlines():
        line = raw_line.strip()
        m = BENCH_LINE_RE.match(line)
        if not m:
            continue
        ns_op = float(m.group("ns_op"))
        ops_sec = (1_000_000_000.0 / ns_op) if ns_op > 0.0 else 0.0
        checksum_str = m.group("checksum")
        results.append(
            BenchResult(
                name=m.group("name"),
                iters=int(m.group("iters")),
                ns_op=ns_op,
                ops_sec=ops_sec,
                mb_s=float(m.group("mb_s")),
                checksum=int(checksum_str) if checksum_str is not None else None,
            )
        )
    return results


def format_markdown_table(results: list[BenchResult], opt_flag: str, iters: int) -> str:
    lines = [
        f"Engine Codec Microbenchmarks (gcc {opt_flag}, iters={iters})",
        "",
        "| Benchmark | Iters | ns/op | ops/sec | MB/s |",
        "| :--- | ---: | ---: | ---: | ---: |",
    ]
    for r in results:
        lines.append(
            f"| `{r.name}` | {r.iters:,} | {r.ns_op:,.2f} | {r.ops_sec:,.0f} | {r.mb_s:,.2f} |"
        )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build and run goose-wing engine codec microbenchmarks"
    )
    parser.add_argument(
        "--iters",
        type=int,
        default=10000,
        help="Number of timed iterations per codec benchmark (default: 10000)",
    )
    parser.add_argument(
        "--json",
        action="store_true",
        dest="emit_json",
        help="Emit benchmark results as JSON",
    )
    args = parser.parse_args()

    if args.iters <= 0:
        sys.stderr.write("Error: --iters must be positive.\n")
        return 2

    root = Path(__file__).resolve().parent.parent
    bench_src = root / "bench" / "codec_perf_benchmark.goose"
    if not bench_src.exists():
        sys.stderr.write(f"Error: Benchmark source not found: {bench_src}\n")
        return 1

    exe_name = (
        "codec_perf_benchmark.exe" if platform.system() == "Windows" else "codec_perf_benchmark"
    )
    with tempfile.TemporaryDirectory(prefix="goose_wing_bench_") as tmp_dir:
        out_exe = Path(tmp_dir) / exe_name
        try:
            opt_flag = build_benchmark(root, bench_src, out_exe)
        except RuntimeError as exc:
            sys.stderr.write(f"{exc}\n")
            return 1

        run_proc = subprocess.run(
            [str(out_exe), "--iters", str(args.iters)],
            cwd=str(root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if run_proc.returncode != 0:
            sys.stderr.write(
                f"Benchmark execution failed (exit={run_proc.returncode}):\n"
                f"{run_proc.stdout}\n{run_proc.stderr}\n"
            )
            return run_proc.returncode

        results = parse_bench_output(run_proc.stdout)
        if not results:
            sys.stderr.write(
                f"Error: No BENCH result lines parsed from benchmark output.\n{run_proc.stdout}\n"
            )
            return 1

    if args.emit_json:
        payload = {
            "opt_flag": opt_flag,
            "iters": args.iters,
            "results": [asdict(r) for r in results],
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        sys.stdout.write(format_markdown_table(results, opt_flag, args.iters) + "\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
