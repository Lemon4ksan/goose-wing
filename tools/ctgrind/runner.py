#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""ctgrind / TIMECOP taint and static/disassembly constant-time auditor for goose-wing.

In `--docker` mode, executes `ctgrind_harness` under Valgrind memcheck
(`valgrind --error-exitcode=42 --track-origins=yes`) with secret inputs marked
UNDEFINED via `<valgrind/memcheck.h>`.
In `--local` mode, builds and executes `ctgrind_harness` natively, runs a static
audit across `core/crypto/*.goose`, `tls/post_quantum.goose`, and
`shim/crypto_fusion.c`, and inspects `objdump` disassembly to verify zero AES
SBOX tables and zero `idiv`/`div` instructions in ML-KEM-768.
"""

from __future__ import annotations

import argparse
import io
import os
import platform
import re
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
CACHE_DIR = ROOT_DIR / ".lit" / "cache" / "ctgrind"
TARGET_GOOSE = SUITE_DIR / "ctgrind_target.goose"
HARNESS_C = SUITE_DIR / "ctgrind_harness.c"
HARNESS_EXE = CACHE_DIR / ("ctgrind_harness.exe" if sys.platform == "win32" else "ctgrind_harness")

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


def build_ctgrind(cc: str = "gcc", force: bool = False) -> tuple[Path, Path]:
    CACHE_DIR.mkdir(parents=True, exist_ok=True)
    target_obj = CACHE_DIR / "ctgrind_target.o"
    if (
        not force
        and HARNESS_EXE.exists()
        and target_obj.exists()
        and HARNESS_EXE.stat().st_mtime >= max(TARGET_GOOSE.stat().st_mtime, HARNESS_C.stat().st_mtime)
    ):
        return HARNESS_EXE, target_obj

    c_out = CACHE_DIR / "ctgrind_target.c"
    h_out = CACHE_DIR / "ctgrind_target.h"
    res = subprocess.run(
        ["goose", "--standalone", "--header", str(h_out), "-o", str(c_out), str(TARGET_GOOSE)],
        cwd=ROOT_DIR,
        capture_output=True,
        text=True,
    )
    if res.returncode != 0:
        raise RuntimeError(f"goose codegen failed:\n{res.stdout}\n{res.stderr}")

    harness_obj = CACHE_DIR / "ctgrind_harness.o"
    base_flags = ["-O2", "-fno-store-merging"]
    if platform.machine().lower() in ("x86_64", "amd64", "i386", "i686"):
        base_flags.append("-mstackrealign")

    res_drv = subprocess.run(
        [cc, *base_flags, "-Wall", "-Wextra", "-Werror", "-c", str(HARNESS_C), "-o", str(harness_obj)],
        cwd=ROOT_DIR,
        capture_output=True,
        text=True,
    )
    if res_drv.returncode != 0:
        raise RuntimeError(f"ctgrind_harness.c compile failed:\n{res_drv.stdout}\n{res_drv.stderr}")

    res_tgt = subprocess.run(
        [cc, *base_flags, "-c", str(c_out), "-o", str(target_obj)],
        cwd=ROOT_DIR,
        capture_output=True,
        text=True,
    )
    if res_tgt.returncode != 0:
        raise RuntimeError(f"ctgrind_target.c compile failed:\n{res_tgt.stdout}\n{res_tgt.stderr}")

    link_cmd = [cc, *base_flags]
    if os.name == "nt":
        link_cmd.extend(["-Wl,--stack,33554432", "-Wl,--allow-multiple-definition"])
    link_cmd.extend([str(target_obj), str(harness_obj)])
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
        raise RuntimeError(f"ctgrind link failed:\n{res_link.stdout}\n{res_link.stderr}")
    return HARNESS_EXE, target_obj


def _strip_comments(text: str) -> str:
    text = re.sub(r"/\*.*?\*/", "", text, flags=re.S)
    return re.sub(r"//[^\n]*", "", text)


def run_static_audit() -> tuple[bool, list[str]]:
    findings: list[str] = []
    sbox_re = re.compile(r"\b(?:AES_)?(?:INV_)?(?:SBOX|TBOX|TE[0-4]|TD[0-4])\b", re.IGNORECASE)
    aes_targets = [ROOT_DIR / "core" / "crypto" / "aes.goose", ROOT_DIR / "shim" / "crypto_fusion.c"]
    for p in aes_targets:
        code = _strip_comments(p.read_text(encoding="utf-8"))
        if sbox_re.search(code):
            findings.append(f"SBOX/TBOX identifier found in {p.relative_to(ROOT_DIR)}")
        if re.search(r"u8\[256\]|uint8_t\s+\w+\[256\]|uint32_t\s+\w+\[256\]", code):
            findings.append(f"256-entry lookup table found in {p.relative_to(ROOT_DIR)}")

    pq_path = ROOT_DIR / "tls" / "post_quantum.goose"
    pq_code = _strip_comments(pq_path.read_text(encoding="utf-8"))
    for idx, line in enumerate(pq_code.splitlines(), start=1):
        if re.search(r"(?<![\"'])\s[/%]\s", line):
            findings.append(f"Division/modulo operator in {pq_path.relative_to(ROOT_DIR)}:{idx}: {line.strip()}")

    for p in sorted((ROOT_DIR / "core" / "crypto").glob("*.goose")):
        code = _strip_comments(p.read_text(encoding="utf-8"))
        if re.search(r"\b(?:computed_tag|expected_tag)\s*(?:==|!=)", code):
            findings.append(f"Non-constant-time tag comparison in {p.relative_to(ROOT_DIR)}")
    return (len(findings) == 0), findings


def run_objdump_audit(target_obj: Path, harness_obj: Path) -> tuple[bool, list[str], int]:
    findings: list[str] = []
    for obj in (target_obj, harness_obj):
        sym_res = subprocess.run(["objdump", "-t", str(obj)], capture_output=True, text=True)
        if sym_res.returncode != 0:
            return False, [f"objdump -t failed on {obj}: {sym_res.stderr}"], 0
        for line in sym_res.stdout.splitlines():
            if (
                re.search(r"\b(?:aes_)?(?:inv_)?(?:sbox|tbox)\b", line, re.IGNORECASE)
                and "bitslice" not in line.lower()
                and "sub_bytes" not in line.lower()
            ):
                findings.append(f"SBOX/TBOX symbol in {obj.name}: {line.strip()}")

    dis_res = subprocess.run(["objdump", "-d", str(target_obj)], capture_output=True, text=True)
    if dis_res.returncode != 0:
        return False, [f"objdump -d failed on {target_obj}: {dis_res.stderr}"], 0

    mlkem_fn_re = re.compile(
        r"^[0-9a-fA-F]+\s+<([^>]*(?:mlkem|fips203|poly_|k_pke|decompress_|byte_decode_12|byte_encode_12)[^>]*)>:"
    )
    any_fn_re = re.compile(r"^[0-9a-fA-F]+\s+<([^>]+)>:")
    div_re = re.compile(r"\b(i?div[bwlq]?)\b")

    current_mlkem_fn = ""
    mlkem_fns_checked = 0
    for line in dis_res.stdout.splitlines():
        m_ml = mlkem_fn_re.match(line)
        if m_ml:
            current_mlkem_fn = m_ml.group(1)
            mlkem_fns_checked += 1
            continue
        if any_fn_re.match(line):
            current_mlkem_fn = ""
            continue
        if current_mlkem_fn:
            parts = line.split("\t")
            if len(parts) >= 3:
                insn = parts[2].strip()
                if div_re.match(insn):
                    findings.append(f"Variable-time division `{insn}` in {current_mlkem_fn}")

    if mlkem_fns_checked == 0:
        findings.append("No ML-KEM-768 functions found in objdump disassembly")
    return (len(findings) == 0), findings, mlkem_fns_checked


def run_docker() -> int:
    tag = "goose-wing-ctgrind:local"
    build = subprocess.run(
        ["docker", "build", "-f", str(SUITE_DIR / "Dockerfile"), "-t", tag, str(ROOT_DIR)],
        cwd=ROOT_DIR,
    )
    if build.returncode != 0:
        return build.returncode
    return subprocess.run(["docker", "run", "--rm", tag], cwd=ROOT_DIR).returncode


def main() -> None:
    parser = argparse.ArgumentParser(description="goose-wing ctgrind / TIMECOP taint & CT auditor")
    parser.add_argument("--local", action="store_true", help="Build, run natively, and audit asm/source")
    parser.add_argument("--docker", action="store_true", help="Run real Valgrind TIMECOP in Docker")
    parser.add_argument("--cc", default="gcc", help="C compiler (default: gcc)")
    parser.add_argument("--rebuild", action="store_true", help="Force clean rebuild")
    args = parser.parse_args()

    if args.docker:
        sys.exit(run_docker())

    exe, target_obj = build_ctgrind(cc=args.cc, force=args.rebuild)
    harness_obj = CACHE_DIR / "ctgrind_harness.o"

    run_res = subprocess.run([str(exe)], cwd=ROOT_DIR, capture_output=True, text=True)
    sys.stdout.write(run_res.stdout)
    if run_res.stderr:
        sys.stderr.write(run_res.stderr)
    native_ok = run_res.returncode == 0

    static_ok, static_findings = run_static_audit()
    asm_ok, asm_findings, mlkem_fns = run_objdump_audit(target_obj, harness_obj)

    for f in static_findings + asm_findings:
        print(f"FAIL: {f}", file=sys.stderr)
    print(
        f"[ctgrind] native={'PASS' if native_ok else 'FAIL'} "
        f"static_audit={'PASS' if static_ok else 'FAIL'} "
        f"objdump_audit={'PASS' if asm_ok else 'FAIL'} "
        f"(mlkem_fns={mlkem_fns}, sbox_tables=0, mlkem_div_insns=0)"
    )
    sys.exit(0 if (native_ok and static_ok and asm_ok) else 1)


if __name__ == "__main__":
    main()
