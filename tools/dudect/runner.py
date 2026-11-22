#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""dudect statistical constant-time timing runner for goose-wing.

Builds `dudect_target.goose` (via `goose --standalone --header`) and links it
natively with `dudect_harness.c` (plus `shim/crypto_fusion.c` scalar fallback)
to run Welch's t-test (`|t| < 4.5`) across 10 cryptographic primitives.
"""

from __future__ import annotations

import argparse
import io
import os
import platform
import subprocess
import sys
from pathlib import Path

if (
    isinstance(sys.stdout, io.TextIOWrapper)
    and sys.stdout.encoding
    and sys.stdout.encoding.lower() != "utf-8"
):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

ROOT_DIR = Path(__file__).resolve().parent.parent.parent
SUITE_DIR = Path(__file__).resolve().parent
CACHE_DIR = ROOT_DIR / ".lit" / "cache" / "dudect"
TARGET_GOOSE = SUITE_DIR / "dudect_target.goose"
HARNESS_C = SUITE_DIR / "dudect_harness.c"
HARNESS_EXE = CACHE_DIR / ("dudect_harness.exe" if sys.platform == "win32" else "dudect_harness")

# `shim/crypto_fusion.c` is included directly by `dudect_harness.c` so it can
# invoke `static wing_aes_gcm_seal_scalar` directly without duplicate symbols.
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
    "shim/tls_backend.c",
]


def _needs_rebuild() -> bool:
    if not HARNESS_EXE.exists():
        return True
    exe_mtime = HARNESS_EXE.stat().st_mtime
    watch = [TARGET_GOOSE, HARNESS_C, ROOT_DIR / "shim" / "crypto_fusion.c"]
    return any(p.exists() and p.stat().st_mtime > exe_mtime for p in watch)


def build_dudect(cc: str = "gcc", force: bool = False) -> Path:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    if not force and not _needs_rebuild():
        return HARNESS_EXE

    c_out = CACHE_DIR / "dudect_target.c"
    h_out = CACHE_DIR / "dudect_target.h"
    goose_cmd = [
        "goose",
        "--standalone",
        "--header",
        str(h_out),
        "-o",
        str(c_out),
        str(TARGET_GOOSE),
    ]
    res = subprocess.run(goose_cmd, cwd=ROOT_DIR, capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"goose codegen failed:\n{res.stdout}\n{res.stderr}")

    harness_obj = CACHE_DIR / "dudect_harness.o"
    drv_cmd = [
        cc,
        "-O2",
        "-Wall",
        "-Wextra",
        "-Werror",
        "-fno-store-merging",
        "-c",
        str(HARNESS_C),
        "-o",
        str(harness_obj),
    ]
    res_drv = subprocess.run(drv_cmd, cwd=ROOT_DIR, capture_output=True, text=True)
    if res_drv.returncode != 0:
        raise RuntimeError(f"dudect_harness.c compile failed:\n{res_drv.stdout}\n{res_drv.stderr}")

    link_cmd = [cc, "-O2", "-fno-store-merging"]
    if platform.machine().lower() in ("x86_64", "amd64", "i386", "i686"):
        link_cmd.append("-mstackrealign")
    if os.name == "nt":
        link_cmd.extend(["-Wl,--stack,33554432", "-Wl,--allow-multiple-definition"])
    link_cmd.extend([str(c_out), str(harness_obj)])
    for shim in SHIM_SOURCES:
        link_cmd.append(str(ROOT_DIR / shim))
    if os.name == "nt":
        link_cmd.extend(["-lws2_32", "-lmswsock", "-lbcrypt", "-lm"])
    elif sys.platform.startswith("linux"):
        link_cmd.extend(["-lpthread", "-lm", "-ldl"])
    else:
        link_cmd.extend(["-lpthread", "-lm"])
    link_cmd.extend(["-o", str(HARNESS_EXE)])

    res_link = subprocess.run(link_cmd, cwd=ROOT_DIR, capture_output=True, text=True)
    if res_link.returncode != 0:
        raise RuntimeError(f"dudect link failed:\n{res_link.stdout}\n{res_link.stderr}")
    return HARNESS_EXE


def run_docker(samples: int, threshold: float) -> int:
    tag = "goose-wing-dudect:local"
    build = subprocess.run(
        ["docker", "build", "-f", str(SUITE_DIR / "Dockerfile"), "-t", tag, str(ROOT_DIR)],
        cwd=ROOT_DIR,
    )
    if build.returncode != 0:
        return build.returncode
    run = subprocess.run(
        ["docker", "run", "--rm", tag, "--local", "--samples", str(samples), "--threshold", str(threshold)],
        cwd=ROOT_DIR,
    )
    return run.returncode


def main() -> None:
    parser = argparse.ArgumentParser(description="goose-wing dudect Welch t-test timing harness")
    parser.add_argument("--local", action="store_true", help="Build and run native dudect locally")
    parser.add_argument("--docker", action="store_true", help="Build and run inside Docker")
    parser.add_argument("--samples", type=int, default=2000, help="Samples per primitive (100..1000000)")
    parser.add_argument("--threshold", type=float, default=4.5, help="Welch |t| pass ceiling")
    parser.add_argument("--retries", type=int, default=3, help="Max retries on transient OS noise")
    parser.add_argument("--only", default="", help="Optional single primitive name filter")
    parser.add_argument("--cc", default="gcc", help="C compiler (default: gcc)")
    parser.add_argument("--rebuild", action="store_true", help="Force clean rebuild")
    args = parser.parse_args()

    if args.docker:
        sys.exit(run_docker(args.samples, args.threshold))

    exe = build_dudect(cc=args.cc, force=args.rebuild)
    cmd = [
        str(exe),
        "--samples",
        str(args.samples),
        "--threshold",
        str(args.threshold),
        "--retries",
        str(args.retries),
    ]
    if args.only:
        cmd.extend(["--only", args.only])

    res = subprocess.run(cmd, cwd=ROOT_DIR, capture_output=True, text=True)
    passed = 0
    failed = 0
    print(f"{'Primitive':<28} {'Status':<6} {'|t|':>8} {'Mean0':>12} {'Mean1':>12} {'N0':>7} {'N1':>7} {'Try':>4}")
    print("-" * 92)
    for line in res.stdout.splitlines():
        parts = line.split("\t")
        if len(parts) == 9 and parts[0] == "DUDECT":
            _, name, status, abs_t, m0, m1, n0, n1, att = parts
            print(f"{name:<28} {status:<6} {float(abs_t):>8.4f} {float(m0):>12.2f} {float(m1):>12.2f} {n0:>7} {n1:>7} {att:>4}")
            if status == "PASS":
                passed += 1
            else:
                failed += 1
    if res.stderr.strip():
        sys.stderr.write(res.stderr)
    print(f"[dudect] samples={args.samples} threshold={args.threshold} passed={passed} failed={failed}")
    sys.exit(0 if res.returncode == 0 and failed == 0 and passed > 0 else 1)


if __name__ == "__main__":
    main()
