#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
goose-wing Cross-Platform High-Performance Test Runner.

Provides parallel typechecking, compilation, and execution for all test suites
and examples across Windows, Linux, and macOS.
"""

from __future__ import annotations

import argparse
import fnmatch
import os
import platform
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

# Terminal color helpers
_IS_TTY = sys.stdout.isatty() and not os.environ.get("NO_COLOR")


def _c(text: str, code: str) -> str:
    return f"\033[{code}m{text}\033[0m" if _IS_TTY else text


def cyan(text: str) -> str:
    return _c(text, "36")


def green(text: str) -> str:
    return _c(text, "32")


def yellow(text: str) -> str:
    return _c(text, "33")


def red(text: str) -> str:
    return _c(text, "31")


def bold(text: str) -> str:
    return _c(text, "1")


def find_goose_binary() -> str:
    binary = shutil.which("goose")
    if binary:
        return binary
    # Common fallback paths
    home = Path.home()
    if platform.system() == "Windows":
        candidates = list(home.glob(".goose/*/goose.exe"))
        if candidates:
            return str(candidates[0])
    else:
        candidates = list(home.glob(".goose/*/goose"))
        if candidates:
            return str(candidates[0])
    return "goose"


def run_command(cmd: list[str], cwd: Path | None = None) -> tuple[int, str, str]:
    try:
        proc = subprocess.run(
            cmd,
            cwd=str(cwd) if cwd else None,
            capture_output=True,
            text=True,
            check=False,
            encoding="utf-8",
            errors="replace",
        )
        return proc.returncode, proc.stdout, proc.stderr
    except FileNotFoundError:
        return -1, "", f"Command not found: {cmd[0]}"


def main() -> int:
    parser = argparse.ArgumentParser(description="goose-wing Cross-Platform Test Runner")
    parser.add_argument(
        "-p", "--pattern", default="*_test.goose", help="Glob pattern for test files in tests/"
    )
    parser.add_argument(
        "--check-only",
        action="store_true",
        help="Only run goose check on core, wing, examples and tests",
    )
    parser.add_argument(
        "-r", "--release", action="store_true", help="Compile test suites with -O2 optimization"
    )
    parser.add_argument(
        "-k", "--keep-binaries", action="store_true", help="Keep generated test executables on disk"
    )
    parser.add_argument(
        "-j",
        "--jobs",
        type=int,
        default=min(os.cpu_count() or 4, 8),
        help="Maximum parallel compilation/check worker threads (default: min(cores, 8))",
    )
    args = parser.parse_args()

    root_dir = Path(__file__).resolve().parent.parent
    tests_dir = root_dir / "tests"
    examples_dir = root_dir / "examples"
    core_file = root_dir / "core.goose"
    wing_file = root_dir / "wing.goose"

    goose = find_goose_binary()

    # Ensure 16-byte stack alignment and 32MB stack on Windows x64 to prevent GCC 16 AVX2 #GP faults
    if platform.system() == "Windows":
        gcc_noavx = root_dir / "tools" / "gcc_noavx.cmd"
        if gcc_noavx.exists():
            os.environ.setdefault("GOOSE_CC", str(gcc_noavx))

    print(cyan(bold(" goose-wing test runner")))

    # 1. Typecheck core, wing and examples
    print(f"\n{yellow('[1/3] Typechecking core, wing, and examples...')}")
    t0_core = time.perf_counter()

    for target in [core_file, wing_file]:
        code, out, err = run_command([goose, "check", str(target)], cwd=root_dir)
        if code != 0:
            print(red(f"FATAL: goose check {target.name} failed!"))
            if out:
                print(yellow(out))
            if err:
                print(red(err))
            return 1

    # Check examples
    example_files = sorted(examples_dir.glob("*.goose"))
    for ex in example_files:
        code, out, err = run_command([goose, "check", str(ex)], cwd=root_dir)
        if code != 0:
            print(red(f"FATAL: goose check examples/{ex.name} failed!"))
            if out:
                print(yellow(out))
            if err:
                print(red(err))
            return 1

    dt_core_ms = int((time.perf_counter() - t0_core) * 1000)
    print(
        green(
            f"  OK: core, wing & {len(example_files)} examples typechecked cleanly in {dt_core_ms}ms."
        )
    )

    # 2. Discover test suites
    if not tests_dir.exists():
        print(red(f"Tests directory not found: {tests_dir}"))
        return 1

    all_test_files = [
        f for f in sorted(tests_dir.glob("*.goose")) if fnmatch.fnmatch(f.name, args.pattern)
    ]

    if not all_test_files:
        print(yellow(f"No test files matching '{args.pattern}' found in {tests_dir}."))
        return 0

    # 3. Check-only mode
    if args.check_only:
        print(
            f"\n{yellow(f'[2/2] Parallel typechecking {len(all_test_files)} suites ({args.jobs} workers)...')}"
        )
        t0_check = time.perf_counter()
        failed = 0

        def check_file(f: Path) -> tuple[Path, int, str, str]:
            c, o, e = run_command([goose, "check", str(f)], cwd=root_dir)
            return f, c, o, e

        with ThreadPoolExecutor(max_workers=args.jobs) as executor:
            futures = [executor.submit(check_file, f) for f in all_test_files]
            for fut in as_completed(futures):
                f, code, out, err = fut.result()
                if code != 0:
                    print(red(f"FATAL: goose check {f.name} failed!"))
                    if out:
                        print(yellow(out))
                    if err:
                        print(red(err))
                    failed += 1

        dt_check = time.perf_counter() - t0_check
        if failed > 0:
            print(red(f"\nTypecheck FAILED: {failed}/{len(all_test_files)} suites had errors."))
            return 1

        print(
            green(f"  OK: All {len(all_test_files)} suites typechecked cleanly in {dt_check:.2f}s.")
        )
        print(green(bold(f"\nTypecheck Complete: 100% Valid ({dt_check:.2f}s)")))
        return 0

    # 4. Parallel compilation
    opt_flag = "-O2"
    exe_suffix = ".exe" if platform.system() == "Windows" else ""
    print(
        f"\n{yellow(f'[2/3] Compiling {len(all_test_files)} suites ({args.jobs} parallel workers, {opt_flag})...')}"
    )
    t0_build = time.perf_counter()

    build_results: list[tuple[Path, Path, int, str, str, float]] = []

    def build_test(f: Path) -> tuple[Path, Path, int, str, str, float]:
        exe_path = f.with_suffix(exe_suffix)
        t_start = time.perf_counter()
        cmd = [goose, "build", opt_flag, "-o", str(exe_path), str(f)]
        code, out, err = run_command(cmd, cwd=root_dir)
        elapsed = time.perf_counter() - t_start
        return f, exe_path, code, out, err, elapsed

    build_failed = 0
    with ThreadPoolExecutor(max_workers=args.jobs) as executor:
        futures = {executor.submit(build_test, f): f for f in all_test_files}
        for completed, fut in enumerate(as_completed(futures), 1):
            f, exe_path, code, out, err, el = fut.result()
            build_results.append((f, exe_path, code, out, err, el))
            if code == 0:
                print(green(f"  [{completed}/{len(all_test_files)}] Built {f.name} ({el:.1f}s)"))
            else:
                print(red(f"  [{completed}/{len(all_test_files)}] FAIL: {f.name} (code {code})"))
                if out:
                    print(yellow(out))
                if err:
                    print(red(err))
                build_failed += 1

    dt_build = time.perf_counter() - t0_build

    if build_failed > 0:
        print(red(f"\nFATAL: {build_failed} suite(s) failed to compile!"))
        return 1

    print(green(f"  OK: All {len(all_test_files)} suites compiled cleanly in {dt_build:.2f}s."))

    # 5. Sequential test execution
    print(f"\n{yellow('[3/3] Executing verification suites...')}")
    t0_run = time.perf_counter()
    passed_count = 0
    failed_count = 0

    # Sort results back into deterministic order by filename
    build_results.sort(key=lambda x: x[0].name)

    for f, exe_path, _, _, _, _ in build_results:
        try:
            if not exe_path.exists():
                print(red(f"  FAIL: {exe_path.name} not found"))
                failed_count += 1
                continue

            print(f"\n{cyan(f'Running tests/{f.name}...')}")
            code, out, err = run_command([str(exe_path)], cwd=root_dir)

            if out:
                sys.stdout.write(out)
                sys.stdout.flush()
            if err:
                sys.stderr.write(red(err))
                sys.stderr.flush()

            if code == 0:
                passed_count += 1
            else:
                print(red(f"  FAIL: tests/{f.name} exited with code {code}"))
                failed_count += 1
        finally:
            if not args.keep_binaries and exe_path.exists():
                try:
                    exe_path.unlink()
                except OSError:
                    pass

    dt_run = time.perf_counter() - t0_run
    total_time = time.perf_counter() - t0_core

    print()
    status_color = green if failed_count == 0 else red
    print(
        status_color(
            bold(
                f"Summary: {passed_count}/{len(all_test_files)} suites passed ({failed_count} failed)"
            )
        )
    )
    print(cyan(f"Timing:  Build: {dt_build:.2f}s | Run: {dt_run:.2f}s | Total: {total_time:.2f}s"))

    return 1 if failed_count > 0 else 0


if __name__ == "__main__":
    sys.exit(main())
