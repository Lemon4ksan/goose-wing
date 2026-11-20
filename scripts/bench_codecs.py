#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""scripts/bench_codecs.py.

Builds and executes bench/codec_perf_benchmark.goose with gcc optimization flags,
parses structured BENCH output lines, runs reference implementation benchmarks
(Python zlib, zstandard, brotli C bindings), and prints a comparative Markdown summary
table or JSON.
"""

from __future__ import annotations

import argparse
import json
import os
import platform
import re
import shutil
import subprocess
import sys
import tempfile
import time
import zlib
from dataclasses import asdict, dataclass
from pathlib import Path

try:
    import zstandard
except ImportError:
    zstandard = None

try:
    import brotli
except ImportError:
    brotli = None

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


def latest_source_mtime(root: Path, src: Path) -> float:
    mtime = src.stat().st_mtime
    for rel in ("core", "http", "http2", "crypto", "shim", "core.goose", "wing.goose"):
        target = root / rel
        if not target.exists():
            continue
        if target.is_file():
            mtime = max(mtime, target.stat().st_mtime)
            continue
        for ext in ("*.goose", "*.c", "*.h"):
            for p in target.rglob(ext):
                mtime = max(mtime, p.stat().st_mtime)
    return mtime


def build_benchmark(root: Path, src: Path, out_exe: Path) -> str:
    cached = root / "bench" / out_exe.name
    newest_src = latest_source_mtime(root, src)
    if cached.exists() and cached.stat().st_mtime >= newest_src:
        if cached != out_exe:
            shutil.copy2(cached, out_exe)
        return "-O2 (cached)"

    env = dict(os.environ)
    if platform.system() == "Windows":
        gcc_noavx = root / "tools" / "gcc_noavx.cmd"
        if gcc_noavx.exists():
            env["GOOSE_CC"] = str(gcc_noavx)
    goose = find_goose_binary()
    attempts = [
        [goose, "build", "-O2", "-o", str(out_exe), str(src)],
        [goose, "build", "--cc", "gcc", "-O3", "-o", str(out_exe), str(src)],
        [goose, "build", "--cc", "gcc", "-O2", "-o", str(out_exe), str(src)],
    ]
    last_err = ""
    for cmd in attempts:
        proc = subprocess.run(
            cmd,
            cwd=str(root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
            env=env,
        )
        if proc.returncode == 0 and out_exe.exists():
            if cached != out_exe:
                try:
                    shutil.copy2(out_exe, cached)
                except Exception:
                    pass
            return str(cmd[2])
        last_err = (proc.stdout + "\n" + proc.stderr).strip()

    raise RuntimeError(f"Failed to build {src} with goose build:\n{last_err}")


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


def format_markdown_table(results: list[BenchResult], title: str) -> str:
    lines = [
        title,
        "",
        "| Benchmark | Iters | ns/op | ops/sec | MB/s |",
        "| :--- | ---: | ---: | ---: | ---: |",
    ]
    for r in results:
        lines.append(
            f"| `{r.name}` | {r.iters:,} | {r.ns_op:,.2f} | {r.ops_sec:,.0f} | {r.mb_s:,.2f} |"
        )
    return "\n".join(lines)


def make_compression_fixture() -> bytes:
    parts = [
        b'{"status":200,"message":"ok","service":"goose-wing-gateway","timestamp":1710000000,',
        b'"user":{"id":1001,"username":"gopher_goose","roles":["admin","operator"],"active":true},',
        b'"metrics":{"requests":1054320,"p99_latency_ms":1.42,"error_rate":0.0001,"cpu":0.15},',
        b'"config":{"max_connections":4096,"keepalive":true,"timeout_sec":30,"features":["h2","tls13","zstd","br"]},',
        b'"description":"Zero-allocation high performance network engine compression fixture."}\n',
    ]
    buf = bytearray(1024)
    idx = 0
    while idx < 1024:
        for p in parts:
            rem = 1024 - idx
            if rem <= 0:
                break
            c_len = min(len(p), rem)
            buf[idx : idx + c_len] = p[:c_len]
            idx += c_len
    return bytes(buf)


def run_single_ref_bench(
    name: str,
    iters: int,
    fn,
    payload_len: int,
) -> BenchResult:
    warmup = min(max(iters >> 3, 32), 1000)
    for _ in range(warmup):
        fn()

    t0 = time.perf_counter_ns()
    for _ in range(iters):
        fn()
    dt = time.perf_counter_ns() - t0
    eff_dt = max(dt, 1)
    ns_op = eff_dt / iters
    ops_sec = (1_000_000_000.0 / ns_op) if ns_op > 0.0 else 0.0
    mb_s = (payload_len * iters * 1_000_000_000.0) / (eff_dt * 1_000_000.0)
    return BenchResult(
        name=name,
        iters=iters,
        ns_op=ns_op,
        ops_sec=ops_sec,
        mb_s=mb_s,
    )


def run_reference_benchmarks(iters: int) -> list[BenchResult]:
    payload = make_compression_fixture()
    payload_len = len(payload)
    results: list[BenchResult] = []

    # 1. zlib DEFLATE Level 1
    def zlib_deflate_l1_compress():
        co = zlib.compressobj(level=1, wbits=-zlib.MAX_WBITS)
        return co.compress(payload) + co.flush()

    c_def_l1 = zlib_deflate_l1_compress()

    def zlib_deflate_l1_decompress():
        do = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
        return do.decompress(c_def_l1)

    results.append(
        run_single_ref_bench("ref_zlib_deflate_l1_compress_1kb", iters, zlib_deflate_l1_compress, payload_len)
    )
    results.append(
        run_single_ref_bench("ref_zlib_deflate_l1_decompress_1kb", iters, zlib_deflate_l1_decompress, payload_len)
    )

    # 2. zlib DEFLATE Level 6
    def zlib_deflate_l6_compress():
        co = zlib.compressobj(level=6, wbits=-zlib.MAX_WBITS)
        return co.compress(payload) + co.flush()

    c_def_l6 = zlib_deflate_l6_compress()

    def zlib_deflate_l6_decompress():
        do = zlib.decompressobj(wbits=-zlib.MAX_WBITS)
        return do.decompress(c_def_l6)

    results.append(
        run_single_ref_bench("ref_zlib_deflate_compress_1kb", iters, zlib_deflate_l6_compress, payload_len)
    )
    results.append(
        run_single_ref_bench("ref_zlib_deflate_decompress_1kb", iters, zlib_deflate_l6_decompress, payload_len)
    )

    # 3. zstandard Level 3
    if zstandard is not None:
        zc = zstandard.ZstdCompressor(level=3)
        zd = zstandard.ZstdDecompressor()
        c_zstd = zc.compress(payload)

        def zstd_compress():
            return zc.compress(payload)

        def zstd_decompress():
            return zd.decompress(c_zstd)

        results.append(
            run_single_ref_bench("ref_zstd_compress_1kb", iters, zstd_compress, payload_len)
        )
        results.append(
            run_single_ref_bench("ref_zstd_decompress_1kb", iters, zstd_decompress, payload_len)
        )

    # 4. brotli
    if brotli is not None:
        c_br0 = brotli.compress(payload, quality=0)

        def brotli_l0_compress():
            return brotli.compress(payload, quality=0)

        def brotli_l0_decompress():
            return brotli.decompress(c_br0)

        results.append(
            run_single_ref_bench("ref_brotli_compress_1kb", iters, brotli_l0_compress, payload_len)
        )
        results.append(
            run_single_ref_bench("ref_brotli_decompress_1kb", iters, brotli_l0_decompress, payload_len)
        )

        c_br1 = brotli.compress(payload, quality=1)

        def brotli_l1_compress():
            return brotli.compress(payload, quality=1)

        def brotli_l1_decompress():
            return brotli.decompress(c_br1)

        results.append(
            run_single_ref_bench("ref_brotli_l1_compress_1kb", iters, brotli_l1_compress, payload_len)
        )
        results.append(
            run_single_ref_bench("ref_brotli_l1_decompress_1kb", iters, brotli_l1_decompress, payload_len)
        )

    return results


COMPARISON_MAP = [
    ("deflate_l1_compress_1kb", "ref_zlib_deflate_l1_compress_1kb", "DEFLATE Level 1 Compress (RFC 1951)"),
    ("deflate_l1_decompress_1kb", "ref_zlib_deflate_l1_decompress_1kb", "DEFLATE Level 1 Decompress"),
    ("deflate_compress_1kb", "ref_zlib_deflate_compress_1kb", "DEFLATE Level 6 Compress (Standard)"),
    ("deflate_decompress_1kb", "ref_zlib_deflate_decompress_1kb", "DEFLATE Level 6 Decompress"),
    ("zstd_compress_1kb", "ref_zstd_compress_1kb", "Zstandard Level 3 Compress (RFC 8878)"),
    ("zstd_decompress_1kb", "ref_zstd_decompress_1kb", "Zstandard Decompress"),
    ("brotli_compress_1kb", "ref_brotli_compress_1kb", "Brotli Level 0 Compress (RFC 7932)"),
    ("brotli_decompress_1kb", "ref_brotli_decompress_1kb", "Brotli Level 0 Decompress"),
    ("brotli_l1_compress_1kb", "ref_brotli_l1_compress_1kb", "Brotli Level 1 Compress"),
    ("brotli_l1_decompress_1kb", "ref_brotli_l1_decompress_1kb", "Brotli Level 1 Decompress"),
]


def format_comparison_table(
    native_results: list[BenchResult],
    ref_results: list[BenchResult],
) -> str:
    native_map = {r.name: r for r in native_results}
    ref_map = {r.name: r for r in ref_results}
    lines = [
        "### Compression Codec Head-to-Head Comparison (Goose-Wing Native vs Reference C)",
        "",
        "| Operation / Codec | Goose-Wing (MB/s) | Reference C (MB/s) | Ratio (Goose / Ref) | Status |",
        "| :--- | ---: | ---: | ---: | :--- |",
    ]
    for native_name, ref_name, label in COMPARISON_MAP:
        nat = native_map.get(native_name)
        ref = ref_map.get(ref_name)
        if nat and ref:
            ratio = nat.mb_s / ref.mb_s if ref.mb_s > 0 else 0.0
            status = "Faster" if ratio >= 1.05 else ("Competitive" if ratio >= 0.85 else "Deficit")
            lines.append(
                f"| {label} | {nat.mb_s:,.2f} | {ref.mb_s:,.2f} | {ratio:.2f}x | {status} |"
            )
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build and run goose-wing engine codec microbenchmarks with reference comparisons"
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
    parser.add_argument(
        "--no-reference",
        action="store_true",
        help="Skip reference C benchmark suite",
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

    ref_results: list[BenchResult] = []
    if not args.no_reference:
        ref_results = run_reference_benchmarks(args.iters)

    if args.emit_json:
        payload = {
            "opt_flag": opt_flag,
            "iters": args.iters,
            "native_results": [asdict(r) for r in results],
            "reference_results": [asdict(r) for r in ref_results],
        }
        sys.stdout.write(json.dumps(payload, indent=2) + "\n")
    else:
        native_table = format_markdown_table(
            results, f"Engine Codec Microbenchmarks (gcc {opt_flag}, iters={args.iters})"
        )
        sys.stdout.write(native_table + "\n\n")
        if ref_results:
            ref_table = format_markdown_table(
                ref_results, f"Reference Implementation Microbenchmarks (iters={args.iters})"
            )
            sys.stdout.write(ref_table + "\n\n")
            comparison_table = format_comparison_table(results, ref_results)
            sys.stdout.write(comparison_table + "\n")

    return 0


if __name__ == "__main__":
    sys.exit(main())
