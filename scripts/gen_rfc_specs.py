#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""scripts/gen_rfc_specs.py.

Automated ASD-STE100 state-machine specification (.sm.md) generator for goose-wing.
Invokes `goose2rfc compile` across specified packages or .goose files, writes outputs
into `.agents/rfc_specs/<rel_path>.sm.md`, and formats/validates them with `goosemarklint`.

Usage:
    python scripts/gen_rfc_specs.py --all
    python scripts/gen_rfc_specs.py auth http2
    python scripts/gen_rfc_specs.py auth/jwt.goose http2/connection.goose
"""

import argparse
import os
import shutil
import subprocess
import sys
import time
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

DEFAULT_PACKAGES = [
    "auth",
    "client",
    "cookie",
    "core",
    "dns",
    "fingerprint",
    "grpc",
    "http",
    "http2",
    "http3",
    "net",
    "proxy",
    "quic",
    "realtime",
    "rfc",
    "security",
    "server",
    "tls",
    "wire",
]


def find_goose2rfc(root: Path, explicit_bin: str) -> Path | None:
    if explicit_bin:
        p = Path(explicit_bin)
        return p if p.exists() else None

    env_bin = os.environ.get("GOOSE2RFC_BIN", "")
    if env_bin:
        p = Path(env_bin)
        if p.exists():
            return p

    exe_name = "goose2rfc.exe" if os.name == "nt" else "goose2rfc"
    candidates = [
        root.parent / "goose2rfc" / exe_name,
        root.parent / "goose2rfc" / "bin" / exe_name,
        root / "tools" / "bin" / exe_name,
    ]
    for cand in candidates:
        if cand.exists():
            return cand

    which_hit = shutil.which("goose2rfc")
    if which_hit:
        return Path(which_hit)

    return None


def find_goosemarklint(root: Path) -> Path | None:
    exe_name = "goosemarklint.exe" if os.name == "nt" else "goosemarklint"
    local_bin = root / "tools" / "bin" / exe_name
    if local_bin.exists():
        return local_bin
    which_hit = shutil.which("goosemarklint")
    return Path(which_hit) if which_hit else None


def collect_goose_files(root: Path, targets: list[str], run_all: bool) -> list[Path]:
    selected_targets = DEFAULT_PACKAGES if (run_all or not targets) else targets
    files: list[Path] = []
    seen: set[Path] = set()

    for raw in selected_targets:
        p = Path(raw)
        if not p.is_absolute():
            p = (root / p).resolve()
        else:
            p = p.resolve()

        if p.is_file() and p.suffix == ".goose":
            if p not in seen:
                seen.add(p)
                files.append(p)
        elif p.is_dir():
            for gf in sorted(p.rglob("*.goose")):
                gf_res = gf.resolve()
                if gf_res not in seen:
                    seen.add(gf_res)
                    files.append(gf_res)
        else:
            sys.stderr.write(f"[ERROR] Target not found: {raw}\n")
            sys.exit(1)

    return files


def compile_one_spec(
    goose2rfc_bin: Path,
    root: Path,
    out_root: Path,
    src_file: Path,
) -> tuple[Path, Path, bool, str]:
    rel = src_file.relative_to(root)
    out_file = (out_root / rel).with_suffix(".sm.md")
    out_file.parent.mkdir(parents=True, exist_ok=True)

    rel_posix = rel.as_posix()
    res = subprocess.run(
        [str(goose2rfc_bin), "compile", rel_posix, "-o", str(out_file)],
        cwd=str(root),
        capture_output=True,
        text=True,
    )
    ok = res.returncode == 0
    msg = (res.stdout + res.stderr).strip()
    return rel, out_file, ok, msg


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Generate and format .agents/rfc_specs/*.sm.md via goose2rfc"
    )
    parser.add_argument(
        "targets",
        nargs="*",
        help="Packages or .goose files to compile (default: all production packages)",
    )
    parser.add_argument(
        "--all",
        action="store_true",
        help="Compile all production packages into .agents/rfc_specs",
    )
    parser.add_argument(
        "--out-dir",
        default=".agents/rfc_specs",
        help="Output directory root relative to repo root (default: .agents/rfc_specs)",
    )
    parser.add_argument(
        "--bin",
        default="",
        help="Explicit path to goose2rfc binary",
    )
    parser.add_argument(
        "--jobs",
        "-j",
        type=int,
        default=min(8, os.cpu_count() or 4),
        help="Number of parallel compilation workers",
    )
    parser.add_argument(
        "--no-lint",
        action="store_true",
        help="Skip goosemarklint fmt/check on generated .sm.md files",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    goose2rfc_bin = find_goose2rfc(root, args.bin)
    if not goose2rfc_bin:
        sys.stderr.write(
            "[ERROR] Could not locate goose2rfc binary. Pass --bin <path> or set GOOSE2RFC_BIN.\n"
        )
        return 1

    out_root = Path(args.out_dir)
    if not out_root.is_absolute():
        out_root = Path(os.path.abspath(root / out_root))

    src_files = collect_goose_files(root, args.targets, args.all)
    if not src_files:
        sys.stderr.write("[ERROR] No .goose files matched the given targets.\n")
        return 1

    t0 = time.monotonic()
    print(f"[goose2rfc] Compiling {len(src_files)} module(s) with {goose2rfc_bin.name}...")

    generated: list[Path] = []
    failures: list[tuple[Path, str]] = []

    with ThreadPoolExecutor(max_workers=max(1, args.jobs)) as pool:
        futs = [
            pool.submit(compile_one_spec, goose2rfc_bin, root, out_root, src) for src in src_files
        ]
        for fut in as_completed(futs):
            rel, out_file, ok, msg = fut.result()
            if ok:
                generated.append(out_file)
            else:
                failures.append((rel, msg))

    if failures:
        sys.stderr.write(f"\n[FAIL] {len(failures)} module(s) failed to compile:\n")
        for rel, msg in failures:
            sys.stderr.write(f"  - {rel.as_posix()}: {msg}\n")
        return 1

    generated.sort()
    if (args.all or not args.targets) and out_root.is_dir():
        expected = {p.resolve() for p in generated}
        for existing in sorted(out_root.rglob("*.sm.md")):
            if existing.resolve() not in expected:
                existing.unlink()
                print(f"[PRUNE] Removed orphaned spec {existing.relative_to(root).as_posix()}")

    if not args.no_lint and generated:
        marklint_bin = find_goosemarklint(root)
        if marklint_bin:
            str_paths = [str(p) for p in generated]
            subprocess.run([str(marklint_bin), "fmt", *str_paths], cwd=str(root), check=False)
            chk = subprocess.run(
                [str(marklint_bin), "check", *str_paths],
                cwd=str(root),
                capture_output=True,
                text=True,
            )
            if chk.returncode != 0:
                sys.stderr.write(
                    f"[WARN] goosemarklint check reported issues:\n{chk.stdout}{chk.stderr}\n"
                )

    elapsed_ms = int((time.monotonic() - t0) * 1000)
    print(
        f"[OK] Generated and formatted {len(generated)} .sm.md specification(s) "
        f"in {out_root.relative_to(root).as_posix()} ({elapsed_ms} ms)."
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
