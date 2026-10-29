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
    exe_name = "goose-lit.exe" if sys.platform == "win32" else "goose-lit"
    candidates = [
        root.parent / "goose-lit" / "bin" / exe_name,
        root / "bin" / exe_name,
    ]
    for c in candidates:
        if c.exists():
            return c

    cmd = shutil.which("goose-lit")
    if cmd:
        return Path(cmd)

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
        "Error: goose-lit binary not found. Please clone goose-lit beside goose-wing.",
        file=sys.stderr,
    )
    sys.exit(1)


def main() -> int:
    parser = argparse.ArgumentParser(description="Goose-wing G-CRAP Ratchet Gate")
    parser.add_argument("--save", action="store_true", help="Save G-CRAP baseline snapshot")
    parser.add_argument("--delta", type=float, default=5.0, help="Allowable G-CRAP delta tolerance")
    parser.add_argument("--cov", type=float, default=0.85, help="Simulated branch coverage")
    parser.add_argument("--baseline-file", type=str, default="", help="Path to baseline file")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    lit_bin = find_or_build_goose_lit(root)

    baseline_file = (
        Path(args.baseline_file)
        if args.baseline_file
        else Path(__file__).resolve().parent / "gcrap_baseline.txt"
    )

    if args.save:
        print(f"Saving G-CRAP baseline snapshot to {baseline_file} (cov={args.cov})...")
        cmd = [
            str(lit_bin),
            "crap",
            str(root),
            "--save-baseline",
            str(baseline_file),
            "--cov",
            str(args.cov),
        ]
        res = subprocess.run(cmd)
        return res.returncode
    else:
        if not baseline_file.exists():
            print(
                f"Error: Baseline file not found at {baseline_file}. Run with --save first.",
                file=sys.stderr,
            )
            return 1
        print(
            f"Evaluating CI ratchet gate against {baseline_file} (delta={args.delta}, cov={args.cov})..."
        )
        cmd = [
            str(lit_bin),
            "crap",
            str(root),
            "--baseline",
            str(baseline_file),
            "--cov",
            str(args.cov),
            "--delta",
            str(args.delta),
        ]
        res = subprocess.run(cmd)
        return res.returncode


if __name__ == "__main__":
    sys.exit(main())
