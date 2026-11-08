#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""scripts/sancov_runner.py.

Compiles tests/fuzz/c_fuzz_entry.goose and tests/fuzz/libfuzzer_driver.c with
SanitizerCoverage (-fsanitize-coverage=trace-pc) or Clang libFuzzer
(-fsanitize=fuzzer,address,undefined) and runs coverage-guided fuzzing.
"""

import argparse
import os
import subprocess
import sys
from pathlib import Path

SHIM_SOURCES = [
    "shim/rio.c",
    "shim/uring.c",
    "shim/kqueue.c",
    "shim/simd.c",
    "shim/tcp.c",
    "shim/af_xdp.c",
    "shim/dpdk.c",
    "shim/smartnic.c",
    "shim/page_ring.c",
    "shim/page_mem.c",
    "shim/spsc.c",
    "shim/profiler.c",
    "shim/crypto_fusion.c",
]


def build_fuzzer(root: Path, cc: str, use_libfuzzer: bool, debug_no_bce: bool) -> Path:
    cache_dir = root / ".lit" / "cache" / "fuzz"
    cache_dir.mkdir(parents=True, exist_ok=True)

    c_out = cache_dir / "c_fuzz_entry.c"
    h_out = cache_dir / "c_fuzz_entry.h"
    entry_goose = root / "tests" / "fuzz" / "c_fuzz_entry.goose"

    goose_cmd = ["goose", "--standalone", "--header", str(h_out), "-o", str(c_out)]
    if debug_no_bce:
        goose_cmd.extend(["--debug", "--no-bce"])
    goose_cmd.append(str(entry_goose))

    res = subprocess.run(goose_cmd, cwd=root, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(f"goose codegen failed:\n{res.stdout}\n{res.stderr}\n")
        raise RuntimeError("goose codegen failed")

    exe_name = "sancov_fuzzer.exe" if os.name == "nt" else "sancov_fuzzer"
    exe_out = cache_dir / exe_name
    driver_c = root / "tests" / "fuzz" / "libfuzzer_driver.c"
    driver_obj = cache_dir / "libfuzzer_driver.o"

    drv_cmd = [cc, "-O2", "-c", str(driver_c), "-o", str(driver_obj)]
    if use_libfuzzer:
        drv_cmd.append("-DLIBFUZZER_EXTERNAL_MAIN=1")
    res_drv = subprocess.run(drv_cmd, cwd=root, capture_output=True, text=True)
    if res_drv.returncode != 0:
        sys.stderr.write(f"Driver compilation failed:\n{res_drv.stdout}\n{res_drv.stderr}\n")
        raise RuntimeError("Driver compilation failed")

    cc_cmd = [cc, "-O2"]
    if use_libfuzzer:
        cc_cmd.extend(["-fsanitize=fuzzer,address,undefined", "-DLIBFUZZER_EXTERNAL_MAIN=1"])
    else:
        cc_cmd.append("-fsanitize-coverage=trace-pc")

    cc_cmd.extend([str(c_out), str(driver_obj)])
    for shim in SHIM_SOURCES:
        cc_cmd.append(str(root / shim))

    if os.name == "nt":
        cc_cmd.extend(["-lws2_32", "-lbcrypt"])
    else:
        cc_cmd.extend(["-lpthread", "-lm"])

    cc_cmd.extend(["-o", str(exe_out)])

    res = subprocess.run(cc_cmd, cwd=root, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(f"C compiler failed:\n{res.stdout}\n{res.stderr}\n")
        raise RuntimeError("C compilation failed")

    return exe_out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Coverage-guided SanitizerCoverage / libFuzzer runner for goose-wing"
    )
    parser.add_argument("--cc", default="gcc", help="C compiler (gcc or clang)")
    parser.add_argument(
        "--target", type=int, default=-1, help="Fuzz target ID (0..45, or -1 for all targets)"
    )
    parser.add_argument("--execs", type=int, default=5000, help="Number of fuzzing executions")
    parser.add_argument("--corpus", default="", help="Optional seed corpus directory")
    parser.add_argument(
        "--libfuzzer",
        action="store_true",
        help="Link against Clang -fsanitize=fuzzer,address,undefined",
    )
    parser.add_argument(
        "--debug-no-bce",
        action="store_true",
        help="Emit Goose C code with --debug --no-bce bounds traps enabled",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    try:
        exe_out = build_fuzzer(root, args.cc, args.libfuzzer, args.debug_no_bce)
    except RuntimeError:
        return 1

    if args.libfuzzer:
        run_cmd = [str(exe_out), f"-runs={args.execs}"]
        if args.corpus:
            run_cmd.append(args.corpus)
    else:
        run_cmd = [str(exe_out), str(args.target), str(args.execs)]
        if args.corpus:
            run_cmd.append(args.corpus)

    res = subprocess.run(run_cmd, cwd=root)
    return res.returncode


if __name__ == "__main__":
    sys.exit(main())
