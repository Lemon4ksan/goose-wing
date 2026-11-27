#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""scripts/test_lit.py.

Master test runner for goose-lit native test suites in goose-wing.
Supports parallel execution, filtering, verbose tracing, and clean exit status.
"""

import argparse
import os
import platform
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

from ratchet import find_or_build_goose_lit


def print_colored(text: str, color: str = "") -> None:
    colors = {
        "red": "\033[31m",
        "yellow": "\033[33m",
        "green": "\033[32m",
        "cyan": "\033[36m",
        "reset": "\033[0m",
    }
    if sys.stdout.isatty():
        sys.stdout.write(f"{colors.get(color, '')}{text}{colors['reset']}\n")
    else:
        sys.stdout.write(f"{text}\n")


def run_single_test(
    lit_bin: Path, test_file: Path, verbose: bool, config_path: Path | None = None
) -> tuple[Path, int, int, str, str]:
    t0 = time.perf_counter()
    cmd = [str(lit_bin), str(test_file)]
    if config_path is not None:
        cmd.extend(["--config", str(config_path)])
    if verbose:
        cmd.append("--verbose")
    proc = subprocess.run(cmd, capture_output=True, text=True)
    elapsed_ms = int((time.perf_counter() - t0) * 1000)
    return test_file, proc.returncode, elapsed_ms, proc.stdout, proc.stderr


def default_lit_jobs() -> int:
    cpu_cap = min(os.cpu_count() or 4, 4)
    avail_mb = 0
    if platform.system() == "Windows":
        try:
            import ctypes

            class MEMORYSTATUSEX(ctypes.Structure):
                _fields_ = [
                    ("dwLength", ctypes.c_ulong),
                    ("dwMemoryLoad", ctypes.c_ulong),
                    ("ullTotalPhys", ctypes.c_ulonglong),
                    ("ullAvailPhys", ctypes.c_ulonglong),
                    ("ullTotalPageFile", ctypes.c_ulonglong),
                    ("ullAvailPageFile", ctypes.c_ulonglong),
                    ("ullTotalVirtual", ctypes.c_ulonglong),
                    ("ullAvailVirtual", ctypes.c_ulonglong),
                    ("ullAvailExtendedVirtual", ctypes.c_ulonglong),
                ]

            stat = MEMORYSTATUSEX()
            stat.dwLength = ctypes.sizeof(MEMORYSTATUSEX)
            if ctypes.windll.kernel32.GlobalMemoryStatusEx(ctypes.byref(stat)):
                avail_mb = int(stat.ullAvailPageFile // (1024 * 1024))
        except Exception:
            avail_mb = 0
    elif Path("/proc/meminfo").exists():
        try:
            for line in Path("/proc/meminfo").read_text(encoding="utf-8", errors="ignore").splitlines():
                if line.startswith("MemAvailable:"):
                    avail_mb = int(line.split()[1]) // 1024
                    break
        except Exception:
            avail_mb = 0

    if avail_mb > 0:
        # `goose build -O2` (`gcc -O3`) on full `wing` peaks near ~1.8-2.2 GB commit charge per job.
        mem_cap = max(1, (avail_mb - 1536) // 2200)
        return max(1, min(cpu_cap, mem_cap))
    return cpu_cap


def main() -> int:
    parser = argparse.ArgumentParser(description="Goose-wing Native LIT Test Runner")
    parser.add_argument("pattern", nargs="?", default="*", help="File filter pattern")
    parser.add_argument("--pattern", dest="opt_pattern", default="", help="File filter pattern")
    parser.add_argument(
        "-j", "--jobs", type=int, default=default_lit_jobs(), help="Concurrency limit"
    )
    parser.add_argument("-v", "--verbose", action="store_true", help="Verbose output")
    parser.add_argument("--sequential", action="store_true", help="Run tests sequentially")
    args = parser.parse_args()

    pattern = args.opt_pattern or args.pattern
    root = Path(__file__).resolve().parent.parent
    lit_dir = root / "tests" / "lit"

    win_config: Path | None = None
    if platform.system() == "Windows":
        gcc_noavx = root / "tools" / "gcc_noavx.cmd"
        base_cfg = root / ".litconfig"
        if gcc_noavx.exists():
            os.environ.setdefault("GOOSE_CC", str(gcc_noavx))
            if base_cfg.exists():
                win_config = root / ".lit" / "cache" / "litconfig.win"
                win_config.parent.mkdir(parents=True, exist_ok=True)
                cfg_lines = base_cfg.read_text(encoding="utf-8").splitlines(keepends=True)
                win_lines = [
                    f"cc = {gcc_noavx.as_posix()}\n" if line.strip() == "cc = gcc" else line
                    for line in cfg_lines
                ]
                win_config.write_text("".join(win_lines), encoding="utf-8")

    if not lit_dir.exists():
        print_colored(f"ERROR: LIT tests directory not found at {lit_dir}", "red")
        return 1

    lit_bin = find_or_build_goose_lit(root)

    # Filter pattern
    glob_pat = pattern if pattern.endswith(".goose") else f"{pattern}.goose"
    if pattern == "*":
        glob_pat = "*.goose"

    test_files = [
        f
        for f in sorted(lit_dir.rglob(glob_pat))
        if f.suffix == ".goose" and f.name != "wire_kit.goose"
    ]

    if not test_files:
        print_colored(f"No tests found matching pattern '{pattern}' in {lit_dir}", "yellow")
        return 0

    max_workers = 1 if args.sequential else max(1, min(args.jobs, os.cpu_count() or 4))
    print_colored(
        f"Running {len(test_files)} goose-lit verification suites (concurrency: {max_workers})...",
        "cyan",
    )

    t_start = time.perf_counter()
    passed = 0
    failed = 0

    with ThreadPoolExecutor(max_workers=max_workers) as executor:
        futures = [
            executor.submit(run_single_test, lit_bin, tf, args.verbose, win_config)
            for tf in test_files
        ]
        for fut in as_completed(futures):
            tf, rc, ms, stdout, stderr = fut.result()
            if rc == 0:
                passed += 1
                print_colored(f"  [PASS] {tf.name} ({ms} ms)", "green")
                if args.verbose and stdout:
                    print(stdout)
            else:
                failed += 1
                print_colored(f"  [FAIL] {tf.name} (exit {rc}, {ms} ms)", "red")
                if stdout:
                    print_colored(stdout, "yellow")
                if stderr:
                    print_colored(stderr, "red")

    total_ms = int((time.perf_counter() - t_start) * 1000)

    # Cleanup temp artifacts
    for tmp in lit_dir.rglob("*.tmp*"):
        try:
            tmp.unlink()
        except OSError:
            pass

    print("-" * 71)
    summary_color = "green" if failed == 0 else "red"
    print_colored(f"Test Summary: {passed} passed, {failed} failed in {total_ms} ms", summary_color)

    return 1 if failed > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
