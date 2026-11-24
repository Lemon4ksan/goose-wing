#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""Goose-Wing Stage Profiler & Benchmark CLI Runner, Comparator, and Exporter."""

from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path
from typing import Any


def _find_lit_root(repo_root: Path) -> Path:
    candidates = [
        repo_root.parent / "goose-lit",
        Path.home() / ".goose" / "pkg" / "github.com" / "Lemon4ksan" / "goose-lit",
    ]
    lit_exe = shutil.which("goose-lit")
    if lit_exe:
        candidates.append(Path(lit_exe).resolve().parent.parent)
    for cand in candidates:
        if (cand / "shim" / "prof_hook.h").exists():
            return cand
    raise RuntimeError(
        "goose-lit repository not found; expected ../goose-lit or ~/.goose/pkg/github.com/Lemon4ksan/goose-lit"
    )


def parse_profiler_output(stdout_text: str) -> dict[str, Any]:
    """Parses @LIT_BENCH and @LIT_STAGE TSV records emitted by goose-lit profiler."""
    cases: dict[str, dict[str, Any]] = {}
    suite_name = "Goose-Wing Benchmark Suite"

    for raw_line in stdout_text.splitlines():
        line = raw_line.strip()
        if line.startswith("@LIT_BENCH\t"):
            parts = line.split("\t")
            if len(parts) < 13:
                continue
            suite_name = parts[1]
            case_name = parts[2]
            cases[case_name] = {
                "suite": suite_name,
                "case": case_name,
                "n": int(parts[3]),
                "ns_per_op": float(parts[4]),
                "cycles_per_op": float(parts[5]),
                "mb_per_s": float(parts[6]),
                "net_bytes_per_op": int(parts[7]),
                "scratch_bytes_per_op": int(parts[8]),
                "peak_bytes": int(parts[9]),
                "pool_allocs_per_op": int(parts[10]),
                "custom_val": float(parts[11]),
                "custom_unit": parts[12],
                "stages": [],
            }
        elif line.startswith("@LIT_STAGE\t"):
            parts = line.split("\t")
            if len(parts) < 13:
                continue
            case_name = parts[1]
            stage_entry = {
                "stage": parts[2],
                "calls": int(parts[3]),
                "self_cycles_per_call": float(parts[4]),
                "total_cycles_per_call": float(parts[5]),
                "p50_cycles": int(parts[6]),
                "p99_cycles": int(parts[7]),
                "pct_case": float(parts[8]),
                "net_bytes_per_call": int(parts[9]),
                "scratch_bytes_per_call": int(parts[10]),
                "peak_bytes": int(parts[11]),
                "pool_allocs_per_call": int(parts[12]),
            }
            if case_name not in cases:
                cases[case_name] = {
                    "suite": suite_name,
                    "case": case_name,
                    "n": 1,
                    "ns_per_op": 0.0,
                    "cycles_per_op": 0.0,
                    "mb_per_s": 0.0,
                    "net_bytes_per_op": 0,
                    "scratch_bytes_per_op": 0,
                    "peak_bytes": 0,
                    "pool_allocs_per_op": 0,
                    "custom_val": 0.0,
                    "custom_unit": "",
                    "stages": [],
                }
            cases[case_name]["stages"].append(stage_entry)

    return {"suite": suite_name, "cases": cases}


def print_human_output(stdout_text: str) -> None:
    """Prints human-readable benchmark tables, filtering out machine @LIT_* TSV lines."""
    for line in stdout_text.splitlines():
        if line.startswith(("@LIT_BENCH\t", "@LIT_STAGE\t")):
            continue
        print(line)


def compare_reports(base_data: dict[str, Any], cur_data: dict[str, Any]) -> None:
    """Prints benchstat-style delta tables for cases and per-stage self cycles."""
    base_cases = base_data.get("cases", {})
    cur_cases = cur_data.get("cases", {})

    print(
        "\n=============================================================================================="
    )
    print("  Benchstat Delta Comparison (Baseline vs Current)")
    print(
        "=============================================================================================="
    )
    print(
        f"  {'Case / Stage':<38} | {'Base cyc':>10} | {'Cur cyc':>10} | {'Delta %':>9} | {'Scratch Delta':>14}"
    )
    print(
        "----------------------------------------------------------------------------------------------"
    )

    for case_name, cur_case in cur_cases.items():
        base_case = base_cases.get(case_name)
        if not base_case:
            continue
        b_cyc = float(base_case.get("cycles_per_op", 0.0))
        c_cyc = float(cur_case.get("cycles_per_op", 0.0))
        pct = ((c_cyc - b_cyc) / b_cyc * 100.0) if b_cyc > 0 else 0.0
        b_scr = int(base_case.get("scratch_bytes_per_op", 0))
        c_scr = int(cur_case.get("scratch_bytes_per_op", 0))
        scr_delta = c_scr - b_scr
        print(
            f"  {case_name:<38} | {b_cyc:>10.1f} | {c_cyc:>10.1f} | {pct:>+8.2f}% | {scr_delta:>+12d} B"
        )

        base_stages = {s["stage"]: s for s in base_case.get("stages", [])}
        for st in cur_case.get("stages", []):
            st_name = st["stage"]
            bst = base_stages.get(st_name)
            if not bst:
                continue
            bs_cyc = float(bst.get("self_cycles_per_call", 0.0))
            cs_cyc = float(st.get("self_cycles_per_call", 0.0))
            s_pct = ((cs_cyc - bs_cyc) / bs_cyc * 100.0) if bs_cyc > 0 else 0.0
            bs_scr = int(bst.get("scratch_bytes_per_call", 0))
            cs_scr = int(st.get("scratch_bytes_per_call", 0))
            s_scr_delta = cs_scr - bs_scr
            label = f"    -> {st_name}"
            print(
                f"  {label:<38} | {bs_cyc:>10.1f} | {cs_cyc:>10.1f} | {s_pct:>+8.2f}% | {s_scr_delta:>+12d} B"
            )
    print(
        "==============================================================================================\n"
    )


def export_markdown(report: dict[str, Any], md_path: Path) -> None:
    """Exports Markdown summary tables for benchmark cases and stage breakdowns."""
    lines: list[str] = [
        f"# {report.get('suite', 'Goose-Wing Stage Profile Report')}",
        "",
        "## Benchmark Overview",
        "",
        "| Case | Iters (`N`) | `ns/op` | `cycles/op` | `MB/s` | `net B/op` | `scratch B/op` | `peak B` | `allocs/op` |",
        "| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
    ]
    cases = report.get("cases", {})
    for c in cases.values():
        lines.append(
            f"| `{c['case']}` | {c['n']} | {c['ns_per_op']:.1f} | {c['cycles_per_op']:.1f} | "
            f"{c['mb_per_s']:.1f} | {c['net_bytes_per_op']} | {c['scratch_bytes_per_op']} | "
            f"{c['peak_bytes']} | {c['pool_allocs_per_op']} |"
        )

    for c in cases.values():
        stages = c.get("stages", [])
        if not stages:
            continue
        lines.extend(
            [
                "",
                f"### Stage Breakdown: `{c['case']}`",
                "",
                "| Stage | Calls | `self cyc` | `tot cyc` | `p50` | `p99` | `% case` | `scratch/op` | `net B` | `allocs` |",
                "| :--- | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: | ---: |",
            ]
        )
        for s in stages:
            lines.append(
                f"| `{s['stage']}` | {s['calls']} | {s['self_cycles_per_call']:.1f} | "
                f"{s['total_cycles_per_call']:.1f} | {s['p50_cycles']} | {s['p99_cycles']} | "
                f"{s['pct_case']:.1f}% | {s['scratch_bytes_per_call']} B | "
                f"{s['net_bytes_per_call']} B | {s['pool_allocs_per_call']} |"
            )

    md_path.parent.mkdir(parents=True, exist_ok=True)
    md_path.write_text("\n".join(lines) + "\n", encoding="utf-8")


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Build and run Goose-Wing stage profiler & benchmark suites."
    )
    parser.add_argument(
        "target",
        nargs="?",
        default="bench/server_profiling_benchmark.goose",
        help="Target .goose benchmark file (default: bench/server_profiling_benchmark.goose)",
    )
    parser.add_argument(
        "--filter",
        default="",
        help="Substring filter for benchmark case names (LIT_BENCH_FILTER)",
    )
    parser.add_argument(
        "--benchtime",
        type=int,
        default=0,
        help="Override target timing duration per case in milliseconds (LIT_BENCH_TARGET_MS)",
    )
    parser.add_argument(
        "--save",
        "--json",
        dest="save_json",
        default="",
        help="Save structured benchmark & stage report to JSON file",
    )
    parser.add_argument(
        "--compare",
        default="",
        help="Compare current run against a saved baseline JSON file",
    )
    parser.add_argument(
        "--md",
        default="",
        help="Export Markdown report to file",
    )
    args = parser.parse_args()

    repo_root = Path(__file__).resolve().parent.parent
    target_path = (repo_root / args.target).resolve()
    if not target_path.exists():
        print(f"[ERROR] Target benchmark file not found: {target_path}", file=sys.stderr)
        return 1

    build_dir = repo_root / "build"
    build_dir.mkdir(parents=True, exist_ok=True)
    exe_name = target_path.stem + (".exe" if os.name == "nt" else "")
    exe_path = build_dir / exe_name

    env = os.environ.copy()
    if os.name == "nt" and "GOOSE_CC" not in env:
        gcc_wrapper = repo_root / "tools" / "gcc_noavx.cmd"
        if gcc_wrapper.exists():
            env["GOOSE_CC"] = str(gcc_wrapper)

    if args.filter:
        env["LIT_BENCH_FILTER"] = args.filter
    if args.benchtime > 0:
        env["LIT_BENCH_TARGET_MS"] = str(args.benchtime)

    lit_root = _find_lit_root(repo_root)
    cmd_build = [
        "goose",
        "build",
        "--include",
        str((lit_root / "shim" / "prof_hook.h").as_posix()),
        "-o",
        str(exe_path),
        str(target_path),
    ]
    res_build = subprocess.run(cmd_build, cwd=repo_root, env=env, capture_output=True, text=True)
    if res_build.returncode != 0:
        sys.stderr.write(res_build.stdout)
        sys.stderr.write(res_build.stderr)
        return res_build.returncode

    res_run = subprocess.run(
        [str(exe_path)], cwd=repo_root, env=env, capture_output=True, text=True
    )
    if res_run.returncode != 0:
        sys.stdout.write(res_run.stdout)
        sys.stderr.write(res_run.stderr)
        return res_run.returncode

    print_human_output(res_run.stdout)
    report = parse_profiler_output(res_run.stdout)

    if args.save_json:
        save_path = Path(args.save_json)
        save_path.parent.mkdir(parents=True, exist_ok=True)
        save_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8")
        print(f"[Profile] Saved JSON report to {save_path}")

    if args.md:
        md_path = Path(args.md)
        export_markdown(report, md_path)
        print(f"[Profile] Saved Markdown report to {md_path}")

    if args.compare:
        comp_path = Path(args.compare)
        if not comp_path.exists():
            print(f"[ERROR] Baseline JSON file not found: {comp_path}", file=sys.stderr)
            return 1
        base_report = json.loads(comp_path.read_text(encoding="utf-8"))
        compare_reports(base_report, report)

    return 0


if __name__ == "__main__":
    sys.exit(main())
