#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""scripts/sancov_runner.py.

Compiles tests/fuzz/c_fuzz_entry.goose and goose-lit/shim/fuzz_driver.c with
SanitizerCoverage (-fsanitize-coverage=trace-pc) or Clang libFuzzer
(-fsanitize=fuzzer,address,undefined) and runs coverage-guided fuzzing with
constant-RAM RSS drift and O(n) time-budget enforcement.
"""

import argparse
import os
import platform
import shutil
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
    "shim/crypto_fusion.c",
    "shim/tls_backend.c",
]


def _find_lit_root(root: Path) -> Path:
    candidates = [
        root.parent / "goose-lit",
        Path.home() / ".goose" / "pkg" / "github.com" / "Lemon4ksan" / "goose-lit",
    ]
    lit_exe = shutil.which("goose-lit")
    if lit_exe:
        candidates.append(Path(lit_exe).resolve().parent.parent)
    for cand in candidates:
        if (cand / "shim" / "fuzz_driver.c").exists():
            return cand
    raise RuntimeError(
        "goose-lit repository not found; expected ../goose-lit or ~/.goose/pkg/github.com/Lemon4ksan/goose-lit"
    )


def _fuzzer_is_up_to_date(root: Path, lit_root: Path, exe_out: Path) -> bool:
    if not exe_out.exists():
        return False
    exe_mtime = exe_out.stat().st_mtime
    watch_paths = [
        root / "tests" / "fuzz" / "c_fuzz_entry.goose",
        root / "tests" / "fuzz" / "oss_fuzz.goose",
        lit_root / "shim" / "fuzz_driver.c",
        *(root / s for s in SHIM_SOURCES),
    ]
    return all(not (p.exists() and p.stat().st_mtime > exe_mtime) for p in watch_paths)


def build_fuzzer(
    root: Path,
    cc: str,
    opt: str,
    use_libfuzzer: bool,
    debug_no_bce: bool,
    use_asan_ubsan: bool = False,
    use_unsigned_overflow: bool = False,
    force: bool = True,
) -> Path:
    lit_root = _find_lit_root(root)
    cache_dir = root / ".lit" / "cache" / "fuzz"
    cache_dir.mkdir(parents=True, exist_ok=True)

    exe_name = "sancov_fuzzer.exe" if os.name == "nt" else "sancov_fuzzer"
    exe_out = cache_dir / exe_name
    if not force and _fuzzer_is_up_to_date(root, lit_root, exe_out):
        return exe_out

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

    driver_c = lit_root / "shim" / "fuzz_driver.c"
    driver_obj = cache_dir / "fuzz_driver.o"
    is_win_gcc = os.name == "nt" and "gcc" in Path(cc).name.lower()
    is_clang = "clang" in Path(cc).name.lower()
    arch = platform.machine().lower()
    is_x86 = arch in ("x86_64", "amd64", "i386", "i686")

    drv_cmd = [cc, opt, "-Wall", "-Wextra", "-Werror", "-c", str(driver_c), "-o", str(driver_obj)]
    if is_win_gcc and is_x86:
        drv_cmd.append("-mno-avx")
    if use_libfuzzer:
        drv_cmd.append("-DLIBFUZZER_EXTERNAL_MAIN=1")
    if use_libfuzzer or use_asan_ubsan:
        drv_cmd.extend(["-fsanitize=address,undefined", "-fno-sanitize-recover=all"])
    res_drv = subprocess.run(drv_cmd, cwd=root, capture_output=True, text=True)
    if res_drv.returncode != 0:
        sys.stderr.write(f"Driver compilation failed:\n{res_drv.stdout}\n{res_drv.stderr}\n")
        raise RuntimeError("Driver compilation failed")

    cc_cmd = [cc, opt]
    if is_x86:
        cc_cmd.append("-mstackrealign")
    if is_win_gcc and is_x86:
        cc_cmd.extend(
            [
                "-mno-avx",
                "-fno-ipa-cp-clone",
                "--param",
                "inline-unit-growth=15",
                "--param",
                "max-inline-insns-auto=15",
                "--param",
                "max-inline-insns-single=30",
                "--param",
                "ggc-min-expand=20",
                "--param",
                "ggc-min-heapsize=32768",
            ]
        )
    if use_libfuzzer:
        san_flags = "fuzzer,address,undefined,unsigned-integer-overflow" if is_clang else "fuzzer,address,undefined"
        cc_cmd.extend([f"-fsanitize={san_flags}", "-fno-sanitize-recover=all", "-DLIBFUZZER_EXTERNAL_MAIN=1"])
    else:
        cc_cmd.append("-fsanitize-coverage=trace-pc")
        if use_asan_ubsan:
            san_flags = "address,undefined,unsigned-integer-overflow" if (is_clang and use_unsigned_overflow) else "address,undefined"
            cc_cmd.extend([f"-fsanitize={san_flags}", "-fno-sanitize-recover=all"])

    cc_cmd.extend([str(c_out), str(driver_obj)])
    for shim in SHIM_SOURCES:
        cc_cmd.append(str(root / shim))
    profiler_c = lit_root / "shim" / "profiler.c"
    if profiler_c.exists():
        cc_cmd.append(str(profiler_c))

    if os.name == "nt":
        cc_cmd.extend(["-lws2_32", "-lmswsock", "-lbcrypt"])
        if is_win_gcc:
            cc_cmd.extend(["-Wl,--stack,33554432", "-Wl,--allow-multiple-definition"])
    elif sys.platform.startswith("linux"):
        cc_cmd.extend(["-lpthread", "-lm", "-ldl"])
    else:
        cc_cmd.extend(["-lpthread", "-lm"])

    cc_cmd.extend(["-o", str(exe_out)])

    res = subprocess.run(cc_cmd, cwd=root, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(f"C compiler failed:\n{res.stdout}\n{res.stderr}\n")
        raise RuntimeError("C compilation failed")

    return exe_out


def normalize_argv(argv: list[str]) -> list[str]:
    out: list[str] = []
    i = 0
    while i < len(argv):
        if argv[i] == "--opt" and i + 1 < len(argv):
            val = argv[i + 1]
            if not val.startswith("-"):
                val = f"-{val}" if val.startswith("O") else f"-O{val}"
            out.append(f"--opt={val}")
            i += 2
            continue
        out.append(argv[i])
        i += 1
    return out


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Coverage-guided SanitizerCoverage / libFuzzer runner for goose-wing"
    )
    parser.add_argument("--cc", default="gcc", help="C compiler (gcc or clang)")
    parser.add_argument(
        "--opt",
        default="-O2",
        help="C compiler optimization flag (default: -O2; use -O0 for low-RAM hosts)",
    )
    parser.add_argument(
        "--target",
        type=int,
        default=-1,
        help="Fuzz target ID (0..N-1, or -1 for all targets)",
    )
    parser.add_argument("--execs", type=int, default=5000, help="Number of fuzzing executions")
    parser.add_argument(
        "--seconds",
        type=int,
        default=0,
        help="Optional wall-clock budget in seconds (set --execs 0 for pure time-bounded run)",
    )
    parser.add_argument("--corpus", default="", help="Optional seed corpus directory or @manifest")
    parser.add_argument(
        "--corpus-out",
        default="",
        help="Optional directory to persist coverage-expanding inputs",
    )
    parser.add_argument(
        "--max-rss-drift-kb",
        type=int,
        default=1024,
        help="Max target-attributable RSS drift ceiling in KB (default: 1024)",
    )
    parser.add_argument(
        "--max-input-ms",
        type=int,
        default=50,
        help="Max per-input execution time ceiling in ms for <=16 KB inputs (default: 50)",
    )
    parser.add_argument(
        "--check-complexity",
        action="store_true",
        help="Run deterministic 1KB/4KB/16KB O(n) anti-quadratic complexity sweep across targets",
    )
    parser.add_argument(
        "--seed",
        type=int,
        default=None,
        help="Optional deterministic 64-bit PRNG seed for reproducible standalone runs",
    )
    parser.add_argument(
        "--libfuzzer",
        action="store_true",
        help="Link against Clang -fsanitize=fuzzer,address,undefined,unsigned-integer-overflow -fno-sanitize-recover=all",
    )
    parser.add_argument(
        "--asan-ubsan",
        action="store_true",
        help="Compile with -fsanitize=address,undefined -fno-sanitize-recover=all",
    )
    parser.add_argument(
        "--unsigned-overflow",
        action="store_true",
        help="Include Clang -fsanitize=unsigned-integer-overflow with --asan-ubsan",
    )
    parser.add_argument(
        "--debug-no-bce",
        action="store_true",
        help="Emit Goose C code with --debug --no-bce bounds traps enabled",
    )
    args = parser.parse_args(normalize_argv(sys.argv[1:]))

    root = Path(__file__).resolve().parent.parent
    try:
        exe_out = build_fuzzer(
            root,
            args.cc,
            args.opt,
            args.libfuzzer,
            args.debug_no_bce,
            use_asan_ubsan=args.asan_ubsan,
            use_unsigned_overflow=args.unsigned_overflow,
        )
    except RuntimeError:
        return 1

    env = os.environ.copy()
    env["LIT_FUZZ_MAX_RSS_DRIFT_KB"] = str(args.max_rss_drift_kb)
    env["LIT_FUZZ_MAX_INPUT_MS"] = str(args.max_input_ms)
    if args.target >= 0:
        env["LIT_FUZZ_TARGET_ID"] = str(args.target)
    if args.seed is not None:
        env["LIT_FUZZ_SEED"] = str(args.seed)

    if args.libfuzzer:
        run_cmd = [str(exe_out), f"-runs={args.execs}"]
        if args.corpus:
            run_cmd.append(args.corpus)
    else:
        run_cmd = [
            str(exe_out),
            str(args.target),
            str(args.execs),
            "--max-rss-drift-kb",
            str(args.max_rss_drift_kb),
            "--max-input-ms",
            str(args.max_input_ms),
        ]
        if args.seconds > 0:
            run_cmd.extend(["--seconds", str(args.seconds)])
        if args.corpus_out:
            Path(args.corpus_out).mkdir(parents=True, exist_ok=True)
            run_cmd.extend(["--corpus-out", args.corpus_out])
        if args.check_complexity:
            run_cmd.append("--check-complexity")
        if args.seed is not None:
            run_cmd.extend(["--seed", str(args.seed)])
        if args.corpus:
            run_cmd.append(args.corpus)

    res = subprocess.run(run_cmd, cwd=root, env=env)
    return res.returncode


if __name__ == "__main__":
    sys.exit(main())
