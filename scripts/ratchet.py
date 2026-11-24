#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""scripts/ratchet.py.

CI ratchet delta gate and baseline comparator for goose-crap.
Enforces zero regressions in unproven bce:keep bounds panics or G-CRAP complexity.
"""

import argparse
import shutil
import subprocess
import sys
from pathlib import Path


def find_or_build_goose_lit(root: Path) -> Path:
    # 1. Prefer goose-lit from PATH
    cmd = shutil.which("goose-lit")
    if cmd:
        return Path(cmd)

    # 2. Check Windows registry User / System PATH if running in an older environment
    if sys.platform == "win32":
        try:
            import winreg

            for hive, subkey in [
                (winreg.HKEY_CURRENT_USER, r"Environment"),
                (
                    winreg.HKEY_LOCAL_MACHINE,
                    r"SYSTEM\CurrentControlSet\Control\Session Manager\Environment",
                ),
            ]:
                try:
                    with winreg.OpenKey(hive, subkey) as key:
                        val, _ = winreg.QueryValueEx(key, "PATH")
                        for p in val.split(";"):
                            candidate = Path(p.strip()) / "goose-lit.exe"
                            if candidate.is_file():
                                return candidate
                except OSError:
                    pass
        except ImportError:
            pass

    exe_name = "goose-lit.exe" if sys.platform == "win32" else "goose-lit"
    candidates = [
        root / "bin" / exe_name,
        root.parent / "goose-lit" / "bin" / exe_name,
    ]
    for c in candidates:
        if c.exists():
            return c

    lit_src = root.parent / "goose-lit" / "bin.goose"
    if lit_src.exists():
        out_bin = root.parent / "goose-lit" / "bin" / exe_name
        out_bin.parent.mkdir(parents=True, exist_ok=True)
        print(f"Building native goose-lit runner at {out_bin}...")
        res = subprocess.run(
            ["goose", "build", "--cc", "gcc", "-O2", "-o", str(out_bin), str(lit_src)]
        )
        if res.returncode == 0 and out_bin.exists():
            return out_bin
        sys.exit(res.returncode)

    print(
        "Error: goose-lit binary not found in PATH or beside goose-wing.",
        file=sys.stderr,
    )
    sys.exit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Goose-wing G-CRAP Ratchet Gate")
    parser.add_argument("--save", action="store_true", help="Save G-CRAP baseline snapshot")
    parser.add_argument("--delta", type=float, default=5.0, help="Allowable G-CRAP delta tolerance")
    parser.add_argument("--cov-profile", type=str, default="", help="Path to real .gcrap-cov profile")
    parser.add_argument("--require-cov", action="store_true", help="Fail if no real coverage profile is loaded")
    parser.add_argument("--baseline-file", type=str, default="", help="Path to baseline file")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    lit_bin = find_or_build_goose_lit(root)

    baseline_file = (
        Path(args.baseline_file)
        if args.baseline_file
        else root / ".lit" / "baseline"
    )

    cov_args = []
    if args.cov_profile:
        cov_args.extend(["--cov", args.cov_profile])
    if args.require_cov:
        cov_args.append("--require-cov")

    if args.save:
        print(f"Saving G-CRAP baseline snapshot to {baseline_file}...")
        cmd = [
            str(lit_bin),
            "crap",
            ".",
            "--save-baseline",
            str(baseline_file),
            *cov_args,
        ]
        res = subprocess.run(cmd, cwd=root)
        return res.returncode
    else:
        if not baseline_file.exists():
            print(
                f"Error: Baseline file not found at {baseline_file}. Run with --save first.",
                file=sys.stderr,
            )
            return 1
        print(
            f"Evaluating CI ratchet gate against {baseline_file} (delta={args.delta})..."
        )
        cmd = [
            str(lit_bin),
            "crap",
            ".",
            "--baseline",
            str(baseline_file),
            "--delta",
            str(args.delta),
            *cov_args,
        ]
        res = subprocess.run(cmd, cwd=root)
        return res.returncode


if __name__ == "__main__":
    sys.exit(main())
