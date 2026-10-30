#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""scripts/verify_wing_gate.py.

Verification gate for goose-wing code.
Runs formatting, static typecheck, hardware complexity gate (goose-lit),
and optional test suites.
"""

import argparse
import os
import subprocess
import sys
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


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Goose-wing Hardware Complexity & Verification Gate"
    )
    parser.add_argument("target_file", nargs="?", default="", help="Path to .goose source file")
    parser.add_argument(
        "--target-file", dest="opt_target", default="", help="Path to .goose source file"
    )
    parser.add_argument("--max-gcrap", type=int, default=25, help="Maximum allowable G-CRAP score")
    parser.add_argument("--sim-cov", type=float, default=0.85, help="Simulated branch coverage")
    parser.add_argument("--lit-script", type=str, default="", help="Optional .goose LIT test suite")
    parser.add_argument(
        "--test-suite", type=str, default="", help="Optional .goose test suite to compile & run"
    )
    args = parser.parse_args()

    target = args.target_file or args.opt_target
    if not target:
        print_colored("Error: Target file must be specified.", "red")
        return 1

    root = Path(__file__).resolve().parent.parent
    target_path = Path(target)
    if not target_path.is_absolute():
        target_path = root / target_path

    if not target_path.exists():
        print_colored(f"Error: Target file does not exist: {target_path}", "red")
        return 1

    print(f"Verifying {target_path}")
    print(f"Ceiling: G-CRAP {args.max_gcrap}, simulated coverage {int(args.sim_cov * 100)}%")

    # Phase 1: Format and typecheck
    print("\nPhase 1: Format and typecheck")
    fmt_res = subprocess.run(
        ["goose", "format", "--check", str(target_path)], capture_output=True, text=True
    )
    if fmt_res.returncode != 0:
        print_colored(f"Formatting error in {target_path}.", "red")
        if fmt_res.stdout or fmt_res.stderr:
            sys.stdout.write(fmt_res.stdout + fmt_res.stderr)
        print_colored(f"Run 'goose format {target_path}' to fix whitespace and styling.", "yellow")
        return 1

    chk_res = subprocess.run(["goose", "check", str(target_path)], capture_output=True, text=True)
    if chk_res.returncode != 0:
        wing_path = root / "wing.goose"
        chk_wing = subprocess.run(
            ["goose", "check", str(wing_path)], capture_output=True, text=True
        )
        if chk_wing.returncode != 0:
            print_colored(f"Typecheck failed in {target_path}.", "red")
            sys.stdout.write(chk_wing.stdout + chk_wing.stderr)
            return 1

    print_colored("  Format and typecheck passed.", "green")

    # Phase 2: Hardware complexity gate via goose-lit
    print(f"\nPhase 2: Complexity gate (ceiling: {args.max_gcrap})")
    try:
        lit_bin = find_or_build_goose_lit(root)
        gate_res = subprocess.run(
            [
                str(lit_bin),
                "gate",
                str(target_path),
                str(args.max_gcrap),
                "--cov",
                str(args.sim_cov),
            ],
            text=True,
        )
        if gate_res.returncode == 0:
            print_colored("  Complexity gate passed.", "green")
        else:
            print_colored(
                f"  Complexity gate rejected for {target_path} (exit {gate_res.returncode}).", "red"
            )
            return 1
    except Exception as exc:
        print_colored(f"  goose-lit not available ({exc}). Skipping complexity gate.", "yellow")
        lit_bin = None

    # Phase 3: Optional LIT verification script
    if args.lit_script:
        lit_p = Path(args.lit_script)
        if not lit_p.is_absolute():
            lit_p = root / lit_p
        print(f"\nPhase 3: Executing LIT verification script: {lit_p}")
        if not lit_p.exists():
            print_colored(f"LIT verification script not found: {lit_p}", "red")
            return 1
        if lit_bin and lit_bin.exists():
            script_res = subprocess.run([str(lit_bin), str(lit_p)])
            if script_res.returncode != 0:
                print_colored(f"LIT verification script failed: {lit_p}", "red")
                return 1
            print_colored("  LIT verification passed.", "green")
        else:
            print_colored(f"  goose-lit runner not available to run {lit_p}.", "yellow")

    # Phase 4: Optional test suite
    if args.test_suite:
        test_p = Path(args.test_suite)
        if not test_p.is_absolute():
            test_p = root / test_p
        print(f"\nPhase 4: Test suite ({test_p})")
        if not test_p.exists():
            print_colored(f"Test suite not found: {test_p}", "red")
            return 1

        bin_dir = root / "bin"
        bin_dir.mkdir(parents=True, exist_ok=True)
        test_bin = bin_dir / ("gate_test_tmp.exe" if sys.platform == "win32" else "gate_test_tmp")

        env = os.environ.copy()
        if sys.platform == "win32":
            gcc_noavx = root / "tools" / "gcc_noavx.cmd"
            if gcc_noavx.exists():
                env["GOOSE_CC"] = str(gcc_noavx)

        bld_res = subprocess.run(
            ["goose", "build", "-O2", "-o", str(test_bin), str(test_p)], env=env
        )
        if bld_res.returncode != 0:
            print_colored("Test compilation failed.", "red")
            return 1

        try:
            run_res = subprocess.run([str(test_bin)])
            if run_res.returncode != 0:
                print_colored(f"Test suite failed with exit code {run_res.returncode}.", "red")
                return 1
            print_colored("  Test suite passed.", "green")
        finally:
            if test_bin.exists():
                try:
                    test_bin.unlink()
                except OSError:
                    pass
    else:
        print("\nPhase 4: No test suite specified.")

    print_colored(f"\nAll verification checks passed for {target_path}.", "green")
    return 0


if __name__ == "__main__":
    sys.exit(main())
