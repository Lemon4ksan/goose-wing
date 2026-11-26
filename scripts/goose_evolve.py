#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""scripts/goose_evolve.py.

Goose-Evolve: compiler-informed evolutionary optimization, contract radar,
verification gate, and Pareto frontier manager for goose-wing.

Works 100% on an unpatched `goose` compiler via stock CLI flags
(`goose check --stats --bce-lines --stacks`) and automatically enriches its
analysis when the optional `--export-facts` compiler flag is available.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

BCE_SUMMARY_RE = re.compile(
    r"bce:\s+elided\s+(?P<idx_e>\d+)/(?P<idx_t>\d+)\s+index\s+and\s+"
    r"(?P<sl_e>\d+)/(?P<sl_t>\d+)\s+slice\s+checks"
)
BCE_LINE_RE = re.compile(
    r"^bce-line:\s+(?P<file>.+?):(?P<line>\d+):\s+"
    r"(?P<elided>\d+)\s+elided,\s+(?P<kept>\d+)\s+kept$"
)
MAIN_STACKS_RE = re.compile(r"^main program:\s+(?P<stacks>\d+)\s+data stacks")
FN_STACK_RE = re.compile(
    r"^fn\s+(?P<name>.+?):\s+(?P<own>\d+)\s+own,\s+(?P<need>\d+)\s+with callees$"
)
BENCH_LINE_RE = re.compile(
    r"^BENCH\s+(?P<name>\S+)\s+.*?\bns_op=(?P<ns_op>[0-9]+(?:\.[0-9]+)?)"
    r"(?:\s+mb_s=(?P<mb_s>[0-9]+(?:\.[0-9]+)?))?"
)
LIT_BENCH_RE = re.compile(
    r"@?LIT_BENCH\s+(?P<name>\S+).*?\bns_op=(?P<ns_op>[0-9]+(?:\.[0-9]+)?)"
)
GENERIC_NS_OP_RE = re.compile(r"\bns_op[=:]\s*(?P<ns_op>[0-9]+(?:\.[0-9]+)?)")


def repo_root() -> Path:
    return Path(__file__).resolve().parent.parent


def norm_key(path_str: str, root: Path) -> str:
    p = Path(path_str)
    if not p.is_absolute():
        p = root / p
    try:
        resolved = p.resolve()
    except OSError:
        resolved = p
    return os.path.normcase(resolved.as_posix())


def rel_posix(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def file_matches(candidate: str, target_abs_norm: str, target_rel_norm: str, root: Path) -> bool:
    if not candidate:
        return False
    cand_norm = norm_key(candidate, root)
    if cand_norm == target_abs_norm:
        return True
    cand_posix = os.path.normcase(Path(candidate).as_posix().lstrip("./"))
    return cand_posix == target_rel_norm or cand_norm.endswith("/" + target_rel_norm)


def find_goose_binary() -> str:
    found = shutil.which("goose")
    if found:
        return found
    home = Path.home()
    pattern = ".goose/*/goose.exe" if sys.platform == "win32" else ".goose/*/goose"
    candidates = sorted(home.glob(pattern))
    if candidates:
        return str(candidates[0])
    return "goose"


def find_goose_lit(root: Path) -> Path | None:
    cmd = shutil.which("goose-lit")
    if cmd:
        return Path(cmd)
    exe = "goose-lit.exe" if sys.platform == "win32" else "goose-lit"
    for cand in (root / "bin" / exe, root.parent / "goose-lit" / "bin" / exe):
        if cand.exists():
            return cand
    return None


def find_goose2rfc(root: Path) -> Path | None:
    cmd = shutil.which("goose2rfc")
    if cmd:
        return Path(cmd)
    exe = "goose2rfc.exe" if sys.platform == "win32" else "goose2rfc"
    for cand in (root / "bin" / exe, root.parent / "goose2rfc" / exe):
        if cand.exists():
            return cand
    return None


def compiler_supports_export_facts(goose_bin: str) -> bool:
    try:
        res = subprocess.run(
            [goose_bin, "help", "internals"],
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        return "--export-facts" in (res.stdout + "\n" + res.stderr)
    except OSError:
        return False


def auto_detect_entry(root: Path, target_path: Path) -> Path:
    try:
        src_text = target_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        src_text = ""
    if re.search(r"^\s*(?:pub\s+)?fn\s+main\s*\(", src_text, re.MULTILINE):
        return target_path
    rel = rel_posix(target_path, root)
    if (rel == "core.goose" or rel.startswith("core/")) and (root / "core.goose").exists():
        return root / "core.goose"
    if (root / "wing.goose").exists():
        return root / "wing.goose"
    return target_path


def run_cmd(
    cmd: list[str] | str,
    cwd: Path,
    *,
    shell: bool = False,
    env_overrides: dict[str, str] | None = None,
) -> subprocess.CompletedProcess[str]:
    env = dict(os.environ)
    if sys.platform == "win32" and "GOOSE_CC" not in env:
        gcc_noavx = cwd / "tools" / "gcc_noavx.cmd"
        if gcc_noavx.exists():
            env["GOOSE_CC"] = str(gcc_noavx)
    if env_overrides:
        env.update(env_overrides)
    return subprocess.run(
        cmd,
        cwd=str(cwd),
        shell=shell,
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        check=False,
        env=env,
    )


def read_source_line(path: Path, line_no: int) -> str:
    try:
        lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        if 1 <= line_no <= len(lines):
            return lines[line_no - 1].strip()
    except OSError:
        pass
    return ""


def collect_compiler_snapshot(
    root: Path,
    target_path: Path,
    entry_path: Path,
    goose_bin: str,
    force_unpatched: bool = False,
) -> dict[str, Any]:
    target_abs_norm = norm_key(str(target_path), root)
    target_rel_norm = os.path.normcase(rel_posix(target_path, root))
    use_patched = (not force_unpatched) and compiler_supports_export_facts(goose_bin)

    snapshot: dict[str, Any] = {
        "mode": "patched:--export-facts" if use_patched else "unpatched:stock-cli",
        "compiler": goose_bin,
        "entry": rel_posix(entry_path, root),
        "check_ok": False,
        "check_output": "",
        "target_bce_elided": 0,
        "target_bce_kept": 0,
        "total_bce_elided": 0,
        "total_bce_kept": 0,
        "main_data_stacks": 0,
        "bce_kept_sites": [],
        "speculation_blocks": [],
        "heavy_stack_fns": [],
        "opaque_effect_fns": [],
        "entry_bounds_fns": 0,
    }

    if use_patched:
        with tempfile.TemporaryDirectory(prefix="goose_facts_") as tmp_dir:
            facts_path = Path(tmp_dir) / "facts.json"
            proc = run_cmd(
                [goose_bin, "check", "--export-facts", str(facts_path), str(entry_path)],
                root,
            )
            snapshot["check_ok"] = proc.returncode == 0
            snapshot["check_output"] = (proc.stdout + "\n" + proc.stderr).strip()
            if proc.returncode != 0 or not facts_path.exists():
                return snapshot
            facts = json.loads(facts_path.read_text(encoding="utf-8"))

        summary = facts.get("summary", {})
        idx_e = int(summary.get("bce_index_elided", 0))
        idx_t = int(summary.get("bce_index_total", 0))
        sl_e = int(summary.get("bce_slice_elided", 0))
        sl_t = int(summary.get("bce_slice_total", 0))
        snapshot["total_bce_elided"] = idx_e + sl_e
        snapshot["total_bce_kept"] = (idx_t - idx_e) + (sl_t - sl_e)
        snapshot["main_data_stacks"] = int(summary.get("main_data_stacks", 0))

        reasons_by_line: dict[int, list[dict[str, str]]] = {}
        for item in facts.get("bce_kept", []):
            if not file_matches(item.get("file", ""), target_abs_norm, target_rel_norm, root):
                continue
            line_no = int(item.get("line", 0))
            reasons_by_line.setdefault(line_no, []).append(
                {
                    "fn": str(item.get("fn", "")),
                    "kind": str(item.get("kind", "")),
                    "why": str(item.get("why", "")),
                }
            )

        kept_sites: list[dict[str, Any]] = []
        for entry in facts.get("bce_lines", []):
            if not file_matches(entry.get("file", ""), target_abs_norm, target_rel_norm, root):
                continue
            elided = int(entry.get("elided", 0))
            kept = int(entry.get("kept", 0))
            line_no = int(entry.get("line", 0))
            snapshot["target_bce_elided"] += elided
            snapshot["target_bce_kept"] += kept
            if kept > 0:
                reasons = reasons_by_line.get(line_no, [])
                kept_sites.append(
                    {
                        "line": line_no,
                        "elided": elided,
                        "kept": kept,
                        "fn": reasons[0]["fn"] if reasons else "",
                        "kind": reasons[0]["kind"] if reasons else "",
                        "why": "; ".join(r["why"] for r in reasons if r["why"]),
                        "code": read_source_line(target_path, line_no),
                    }
                )
        kept_sites.sort(key=lambda x: x["line"])
        snapshot["bce_kept_sites"] = kept_sites

        spec_blocks = []
        for sb in facts.get("speculation_blocks", []):
            if not file_matches(sb.get("file", ""), target_abs_norm, target_rel_norm, root):
                continue
            line_no = int(sb.get("line", 0))
            spec_blocks.append(
                {
                    "line": line_no,
                    "fn": str(sb.get("fn", "")),
                    "op": str(sb.get("op", "")),
                    "code": read_source_line(target_path, line_no),
                }
            )
        spec_blocks.sort(key=lambda x: x["line"])
        snapshot["speculation_blocks"] = spec_blocks

        seen_fns: set[tuple[str, int]] = set()
        heavy_fns = []
        opaque_fns = []
        bounds_fns = 0
        for fn in facts.get("functions", []):
            if not file_matches(fn.get("file", ""), target_abs_norm, target_rel_norm, root):
                continue
            name = str(fn.get("name", ""))
            line_no = int(fn.get("line", 0))
            key = (name, line_no)
            if key in seen_fns:
                continue
            seen_fns.add(key)
            s_own = int(fn.get("stack_own", 0))
            s_need = int(fn.get("stack_need", 0))
            if s_own > 0 or s_need > 0:
                heavy_fns.append(
                    {
                        "name": name,
                        "line": line_no,
                        "stack_own": s_own,
                        "stack_need": s_need,
                        "checkfree": bool(fn.get("checkfree", False)),
                    }
                )
            eff = fn.get("effects", {})
            if eff.get("opaque") or eff.get("int_opaque"):
                opaque_fns.append(
                    {
                        "name": name,
                        "line": line_no,
                        "opaque": bool(eff.get("opaque", False)),
                        "int_opaque": bool(eff.get("int_opaque", False)),
                    }
                )
            if fn.get("entry_bounds"):
                bounds_fns += 1
        heavy_fns.sort(key=lambda x: (-x["stack_need"], -x["stack_own"], x["name"]))
        snapshot["heavy_stack_fns"] = heavy_fns
        snapshot["opaque_effect_fns"] = opaque_fns
        snapshot["entry_bounds_fns"] = bounds_fns
        return snapshot

    # Unpatched fallback using stock `goose check --stats --bce-lines --stacks`
    proc = run_cmd(
        [goose_bin, "check", "--stats", "--bce-lines", "--stacks", str(entry_path)],
        root,
    )
    combined = proc.stdout + "\n" + proc.stderr
    snapshot["check_ok"] = proc.returncode == 0
    snapshot["check_output"] = combined.strip()
    if proc.returncode != 0:
        return snapshot

    kept_sites = []
    heavy_fns = []
    for raw in combined.splitlines():
        line = raw.strip()
        m_sum = BCE_SUMMARY_RE.search(line)
        if m_sum:
            idx_e = int(m_sum.group("idx_e"))
            idx_t = int(m_sum.group("idx_t"))
            sl_e = int(m_sum.group("sl_e"))
            sl_t = int(m_sum.group("sl_t"))
            snapshot["total_bce_elided"] = idx_e + sl_e
            snapshot["total_bce_kept"] = (idx_t - idx_e) + (sl_t - sl_e)
            continue

        m_line = BCE_LINE_RE.match(line)
        if m_line:
            if file_matches(m_line.group("file"), target_abs_norm, target_rel_norm, root):
                line_no = int(m_line.group("line"))
                elided = int(m_line.group("elided"))
                kept = int(m_line.group("kept"))
                snapshot["target_bce_elided"] += elided
                snapshot["target_bce_kept"] += kept
                if kept > 0:
                    kept_sites.append(
                        {
                            "line": line_no,
                            "elided": elided,
                            "kept": kept,
                            "fn": "",
                            "kind": "",
                            "why": "",
                            "code": read_source_line(target_path, line_no),
                        }
                    )
            continue

        m_stk = MAIN_STACKS_RE.match(line)
        if m_stk:
            snapshot["main_data_stacks"] = int(m_stk.group("stacks"))
            continue

        m_fn = FN_STACK_RE.match(line)
        if m_fn:
            heavy_fns.append(
                {
                    "name": m_fn.group("name"),
                    "line": 0,
                    "stack_own": int(m_fn.group("own")),
                    "stack_need": int(m_fn.group("need")),
                    "checkfree": False,
                }
            )

    kept_sites.sort(key=lambda x: x["line"])
    heavy_fns.sort(key=lambda x: (-x["stack_need"], -x["stack_own"], x["name"]))
    snapshot["bce_kept_sites"] = kept_sites
    snapshot["heavy_stack_fns"] = heavy_fns[:15]
    return snapshot


def parse_first_json_obj(text: str) -> dict[str, Any] | None:
    start = text.find("{")
    if start < 0:
        return None
    try:
        return json.loads(text[start:])
    except json.JSONDecodeError:
        return None


def collect_lit_metrics(root: Path, target_path: Path) -> dict[str, Any]:
    lit_bin = find_goose_lit(root)
    if not lit_bin:
        return {"available": False}

    info: dict[str, Any] = {
        "available": True,
        "sloc": None,
        "stmts": None,
        "packing": None,
        "smells": None,
        "max_gcrap": None,
        "max_effcc": None,
        "worst_fn": "",
    }

    sloc_proc = run_cmd(
        [str(lit_bin), "sloc", str(target_path), "--smells", "--no-baseline", "--format", "json"],
        root,
    )
    sloc_obj = parse_first_json_obj(sloc_proc.stdout)
    if sloc_obj and isinstance(sloc_obj.get("totals"), dict):
        totals = sloc_obj["totals"]
        sloc_val = int(totals.get("sloc", 0))
        stmts_val = int(totals.get("stmts", 0))
        info["sloc"] = sloc_val
        info["stmts"] = stmts_val
        info["smells"] = int(totals.get("smells", 0))
        info["packing"] = round(stmts_val / sloc_val, 3) if sloc_val > 0 else 0.0

    crap_proc = run_cmd(
        [str(lit_bin), "crap", str(target_path), "--no-bce", "--no-baseline", "--format", "json"],
        root,
    )
    crap_obj = parse_first_json_obj(crap_proc.stdout)
    if crap_obj and isinstance(crap_obj.get("functions"), list):
        max_gcrap = 0.0
        max_effcc = 0
        worst_fn = ""
        for fn in crap_obj["functions"]:
            gcrap = float(fn.get("g_crap", 0.0))
            effcc = int(fn.get("effective_cc", 0))
            if gcrap >= max_gcrap:
                max_gcrap = gcrap
                worst_fn = str(fn.get("name", ""))
            max_effcc = max(max_effcc, effcc)
        info["max_gcrap"] = round(max_gcrap, 2)
        info["max_effcc"] = max_effcc
        info["worst_fn"] = worst_fn
    return info


def collect_rfc_spec(root: Path, target_path: Path, entry_path: Path) -> dict[str, Any]:
    rfc_bin = find_goose2rfc(root)
    if not rfc_bin:
        return {"available": False}
    proc = run_cmd(
        [
            str(rfc_bin),
            "check",
            str(target_path),
            "--root",
            str(entry_path),
            "--strict",
            "--diagnostics",
            "json",
        ],
        root,
    )
    findings: list[dict[str, Any]] = []
    for raw in (proc.stdout + "\n" + proc.stderr).splitlines():
        line = raw.strip()
        if line.startswith("{") and line.endswith("}"):
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                pass
    return {
        "available": True,
        "strict_ok": proc.returncode == 0,
        "findings": findings,
    }


def generate_hypotheses(
    compiler_snap: dict[str, Any],
    lit_info: dict[str, Any],
    rfc_info: dict[str, Any],
) -> list[dict[str, str]]:
    hyps: list[dict[str, str]] = []
    seen: set[str] = set()

    def add(priority: str, category: str, location: str, suggestion: str) -> None:
        key = f"{category}:{location}:{suggestion}"
        if key not in seen:
            seen.add(key)
            hyps.append(
                {
                    "priority": priority,
                    "category": category,
                    "location": location,
                    "suggestion": suggestion,
                }
            )

    for site in compiler_snap.get("bce_kept_sites", []):
        why = site.get("why", "")
        loc = f"line {site['line']}" + (f" ({site['fn']})" if site.get("fn") else "")
        if "u64 variable" in why:
            add(
                "HIGH",
                "bce-u64-counter",
                loc,
                "Switch u64 loop/index variable to i64 or `for i in n` so BCE tracks it.",
            )
        elif "read out of an element, a field or a call result" in why:
            add(
                "HIGH",
                "bce-index-type",
                loc,
                "Carry bounds across fields/calls using a Goose index type (`u32 in arr` or `i64 upto slice`).",
            )
        elif "nothing shows" in why or "cannot relate" in why:
            add(
                "HIGH",
                "bce-guard",
                loc,
                "Hoist a single `guard` / `assert` precondition before the loop or index expression.",
            )
        else:
            add(
                "HIGH",
                "bce-kept",
                loc,
                f"Unproven bounds check (`kept={site['kept']}`): `{site.get('code', '')}`.",
            )

    for sb in compiler_snap.get("speculation_blocks", []):
        loc = f"line {sb['line']}" + (f" ({sb['fn']})" if sb.get("fn") else "")
        add(
            "MEDIUM",
            "simd-speculation",
            loc,
            f"Right operand of `{sb['op']}` blocks C if-conversion/SIMD; split guard or prove index unconditional.",
        )

    for fn in compiler_snap.get("heavy_stack_fns", []):
        if fn.get("stack_own", 0) > 0:
            add(
                "MEDIUM",
                "data-stack",
                fn["name"],
                f"Function reserves {fn['stack_own']} own data stack(s); replace local `T[>..]` with fixed `T[..N]` or hoist buffer.",
            )

    for fn in compiler_snap.get("opaque_effect_fns", []):
        add(
            "LOW",
            "bce-opaque-effects",
            fn["name"],
            "Function has opaque BCE effects; avoid aliasing writes to help caller BCE proofs survive calls.",
        )

    if lit_info.get("available"):
        smells = lit_info.get("smells") or 0
        max_gcrap = lit_info.get("max_gcrap") or 0.0
        if smells > 0:
            add(
                "MEDIUM",
                "compiler-smells",
                "module",
                f"{smells} local compiler smell(s) reported by `goose-lit sloc --smells`.",
            )
        if max_gcrap > 20.0:
            add(
                "MEDIUM",
                "gcrap-hotspot",
                lit_info.get("worst_fn", "module"),
                f"High G-CRAP ({max_gcrap}); flatten nesting with early `guard` or simplify control flow.",
            )

    if rfc_info.get("available") and not rfc_info.get("strict_ok"):
        for f in rfc_info.get("findings", [])[:5]:
            add(
                "HIGH",
                f"rfc-{f.get('rule', 'finding')}",
                "module",
                str(f.get("message", "goose2rfc strict check failed")),
            )

    return hyps


def run_gates(
    root: Path,
    target_path: Path,
    entry_path: Path,
    goose_bin: str,
    *,
    max_gcrap: int,
    ct_check: bool,
    strict_rfc: bool,
    force_unpatched: bool,
    test_cmd: str,
) -> tuple[bool, list[dict[str, Any]], dict[str, Any], dict[str, Any]]:
    gates: list[dict[str, Any]] = []
    all_ok = True

    def record(name: str, ok: bool, detail: str = "") -> None:
        nonlocal all_ok
        if not ok:
            all_ok = False
        gates.append({"name": name, "ok": ok, "detail": detail})

    # 1. goose format --check
    fmt = run_cmd([goose_bin, "format", "--check", str(target_path)], root)
    record("goose-format", fmt.returncode == 0, (fmt.stdout + fmt.stderr).strip())

    # 2. goose check (+ optional --export-facts or stock --stats --bce-lines --stacks)
    comp = collect_compiler_snapshot(
        root, target_path, entry_path, goose_bin, force_unpatched=force_unpatched
    )
    record("goose-check", bool(comp["check_ok"]), "" if comp["check_ok"] else comp["check_output"])

    # 3. scripts/lint_invariants.py
    lint_script = root / "scripts" / "lint_invariants.py"
    if lint_script.exists():
        lint = run_cmd(
            [
                sys.executable,
                str(lint_script),
                "--target-file",
                str(target_path),
                "--strict-examples",
            ],
            root,
        )
        record("lint-invariants", lint.returncode == 0, (lint.stdout + lint.stderr).strip())

    # 4 & 5. goose-lit gate + packing guard (optional if installed)
    lit_bin = find_goose_lit(root)
    if lit_bin:
        gate = run_cmd([str(lit_bin), "gate", str(target_path), str(max_gcrap)], root)
        record("goose-lit-gate", gate.returncode == 0, (gate.stdout + gate.stderr).strip())

        pack = run_cmd(
            [str(lit_bin), "sloc", str(target_path), "--check-packing", "--no-baseline"],
            root,
        )
        record("anti-packing", pack.returncode == 0, (pack.stdout + pack.stderr).strip())

    lit_info = collect_lit_metrics(root, target_path)

    # 6. goose2rfc strict check (when --strict-rfc enabled and binary present)
    if strict_rfc:
        rfc_info = collect_rfc_spec(root, target_path, entry_path)
        if rfc_info.get("available"):
            msgs = "; ".join(f.get("message", "") for f in rfc_info.get("findings", []))
            record("goose2rfc-strict", bool(rfc_info.get("strict_ok")), msgs)

    # 7. Constant-time asm verification (when --ct-check enabled)
    if ct_check:
        ct_script = root / "scripts" / "verify_ct_asm.py"
        if ct_script.exists():
            ct_res = run_cmd([sys.executable, str(ct_script)], root)
            record("verify-ct-asm", ct_res.returncode == 0, (ct_res.stdout + ct_res.stderr).strip())

    # 8. Custom test suite command
    if test_cmd:
        t_res = run_cmd(test_cmd, root, shell=True)
        record(
            "test-cmd",
            t_res.returncode == 0,
            "" if t_res.returncode == 0 else (t_res.stdout + "\n" + t_res.stderr).strip(),
        )

    return all_ok, gates, comp, lit_info


def parse_bench_metrics(output: str, metric_name: str) -> dict[str, Any] | None:
    parsed: list[dict[str, Any]] = []
    for raw in output.splitlines():
        line = raw.strip()
        m = BENCH_LINE_RE.match(line) or LIT_BENCH_RE.match(line)
        if m:
            ns_op = float(m.group("ns_op"))
            mb_s_str = m.groupdict().get("mb_s")
            parsed.append(
                {
                    "name": m.group("name"),
                    "ns_op": ns_op,
                    "mb_s": float(mb_s_str) if mb_s_str is not None else None,
                }
            )
    if parsed:
        if metric_name:
            for item in parsed:
                if item["name"] == metric_name:
                    return item
        return parsed[0]

    json_obj = parse_first_json_obj(output)
    if json_obj:
        if "ns_op" in json_obj:
            return {"name": metric_name or "bench", "ns_op": float(json_obj["ns_op"]), "mb_s": None}
        for key in ("results", "goose_results"):
            if isinstance(json_obj.get(key), list) and json_obj[key]:
                for item in json_obj[key]:
                    if (not metric_name or item.get("name") == metric_name) and "ns_op" in item:
                        return {
                            "name": str(item.get("name", "bench")),
                            "ns_op": float(item["ns_op"]),
                            "mb_s": float(item["mb_s"]) if "mb_s" in item else None,
                        }

    m_gen = GENERIC_NS_OP_RE.search(output)
    if m_gen:
        return {"name": metric_name or "bench", "ns_op": float(m_gen.group("ns_op")), "mb_s": None}
    return None


def extract_objectives(
    comp: dict[str, Any],
    lit_info: dict[str, Any],
    bench: dict[str, Any] | None,
) -> dict[str, float]:
    obj: dict[str, float] = {
        "target_bce_kept": float(comp.get("target_bce_kept", 0)),
        "main_data_stacks": float(comp.get("main_data_stacks", 0)),
    }
    if bench and bench.get("ns_op") is not None:
        obj["ns_op"] = float(bench["ns_op"])
    if lit_info.get("available"):
        if lit_info.get("sloc") is not None:
            obj["sloc"] = float(lit_info["sloc"])
        if lit_info.get("max_gcrap") is not None:
            obj["max_gcrap"] = float(lit_info["max_gcrap"])
    return obj


def dominates(a: dict[str, float], b: dict[str, float], noise_pct: float) -> bool:
    keys = [k for k in a if k in b]
    if not keys:
        return False
    better_on_one = False
    frac = max(noise_pct, 0.0) / 100.0
    for k in keys:
        va, vb = a[k], b[k]
        if k == "ns_op":
            if va > vb * (1.0 + frac):
                return False
            if va < vb * (1.0 - frac):
                better_on_one = True
        elif k == "max_gcrap":
            if va > vb + 0.05:
                return False
            if va < vb - 0.05:
                better_on_one = True
        else:
            if va > vb:
                return False
            if va < vb:
                better_on_one = True
    return better_on_one


def same_objectives(a: dict[str, float], b: dict[str, float], noise_pct: float) -> bool:
    return not dominates(a, b, noise_pct) and not dominates(b, a, noise_pct) and all(
        abs(a[k] - b[k]) <= (b[k] * (noise_pct / 100.0) if k == "ns_op" else 0.05)
        for k in a
        if k in b
    )


def update_pareto(
    generations: list[dict[str, Any]],
    pareto_ids: list[int],
    cand: dict[str, Any],
    noise_pct: float,
) -> tuple[str, list[int]]:
    cand_obj = cand["objectives"]
    by_id = {g["id"]: g for g in generations}
    frontier = [by_id[gid] for gid in pareto_ids if gid in by_id]

    for f in frontier:
        if dominates(f["objectives"], cand_obj, noise_pct):
            return "DOMINATED", pareto_ids

    dominated_by_cand = [f["id"] for f in frontier if dominates(cand_obj, f["objectives"], noise_pct)]
    if dominated_by_cand:
        new_frontier = [gid for gid in pareto_ids if gid not in dominated_by_cand]
        new_frontier.append(cand["id"])
        return "IMPROVED_PARETO", new_frontier

    for f in frontier:
        if same_objectives(cand_obj, f["objectives"], noise_pct):
            return "DOMINATED", pareto_ids

    new_frontier = list(pareto_ids)
    new_frontier.append(cand["id"])
    return "PARETO_TRADEOFF", new_frontier


def campaign_dir(root: Path, campaign: str) -> Path:
    return root / ".lit" / "cache" / "evolve" / campaign


def load_ledger(cdir: Path) -> dict[str, Any]:
    ledger_path = cdir / "ledger.json"
    if not ledger_path.exists():
        raise FileNotFoundError(f"Campaign ledger not found: {ledger_path}")
    return json.loads(ledger_path.read_text(encoding="utf-8"))


def save_ledger(cdir: Path, ledger: dict[str, Any]) -> None:
    (cdir / "ledger.json").write_text(json.dumps(ledger, indent=2) + "\n", encoding="utf-8")


def snapshot_path(cdir: Path, gen_id: int) -> Path:
    return cdir / "snapshots" / f"gen_{gen_id:04d}.goose"


def cmd_analyze(args: argparse.Namespace) -> int:
    root = repo_root()
    target_path = (root / args.target).resolve() if not Path(args.target).is_absolute() else Path(args.target).resolve()
    if not target_path.exists():
        sys.stderr.write(f"Target not found: {target_path}\n")
        return 2
    entry_path = (
        ((root / args.entry).resolve() if not Path(args.entry).is_absolute() else Path(args.entry).resolve())
        if args.entry
        else auto_detect_entry(root, target_path)
    )
    goose_bin = find_goose_binary()
    comp = collect_compiler_snapshot(
        root, target_path, entry_path, goose_bin, force_unpatched=args.force_unpatched
    )
    lit_info = collect_lit_metrics(root, target_path)
    rfc_info = collect_rfc_spec(root, target_path, entry_path) if args.rfc else {"available": False}
    hyps = generate_hypotheses(comp, lit_info, rfc_info)

    payload = {
        "target": rel_posix(target_path, root),
        "entry": rel_posix(entry_path, root),
        "compiler": comp,
        "goose_lit": lit_info,
        "goose2rfc": rfc_info,
        "hypotheses": hyps,
    }
    if args.json:
        print(json.dumps(payload, indent=2))
        return 0 if comp["check_ok"] else 1

    print(f"# Goose-Evolve Analysis: `{payload['target']}`")
    print(f"- Compiler mode: `{comp['mode']}` (entry: `{comp['entry']}`)")
    print(f"- Typecheck & BCE checkfree: `{'PASS' if comp['check_ok'] else 'FAIL'}`")
    if not comp["check_ok"]:
        print(comp["check_output"])
        return 1
    print(
        f"- Target BCE: `{comp['target_bce_elided']}` elided, `{comp['target_bce_kept']}` kept "
        f"(entry total: {comp['total_bce_elided']} elided, {comp['total_bce_kept']} kept)"
    )
    print(f"- Main program data stacks: `{comp['main_data_stacks']}`")
    if lit_info.get("available"):
        print(
            f"- goose-lit: SLOC={lit_info['sloc']}, stmts={lit_info['stmts']}, "
            f"packing={lit_info['packing']}, smells={lit_info['smells']}, "
            f"max G-CRAP={lit_info['max_gcrap']} ({lit_info['worst_fn']})"
        )
    if comp["bce_kept_sites"]:
        print("\n## Kept Bounds Checks")
        for s in comp["bce_kept_sites"][:15]:
            why = f" - {s['why']}" if s.get("why") else ""
            code = f" `{s['code']}`" if s.get("code") else ""
            print(f"- line {s['line']} (kept={s['kept']}){why}{code}")
    if comp["speculation_blocks"]:
        print("\n## Speculation / SIMD Blockers")
        for sb in comp["speculation_blocks"][:10]:
            print(f"- line {sb['line']} ({sb['op']} in {sb['fn']}): `{sb['code']}`")
    if hyps:
        print("\n## Ranked Mutation Hypotheses")
        for h in hyps[:12]:
            print(f"- [{h['priority']}] `{h['category']}` at `{h['location']}`: {h['suggestion']}")
    else:
        print("\n## Ranked Mutation Hypotheses\n- None flagged statically; profile hot paths with `--bench-cmd`.")
    return 0


def cmd_init(args: argparse.Namespace) -> int:
    root = repo_root()
    target_path = (root / args.target).resolve() if not Path(args.target).is_absolute() else Path(args.target).resolve()
    if not target_path.exists():
        sys.stderr.write(f"Target not found: {target_path}\n")
        return 2
    entry_path = (
        ((root / args.entry).resolve() if not Path(args.entry).is_absolute() else Path(args.entry).resolve())
        if args.entry
        else auto_detect_entry(root, target_path)
    )
    goose_bin = find_goose_binary()
    all_ok, gates, comp, lit_info = run_gates(
        root,
        target_path,
        entry_path,
        goose_bin,
        max_gcrap=args.max_gcrap,
        ct_check=args.ct_check,
        strict_rfc=args.strict_rfc,
        force_unpatched=args.force_unpatched,
        test_cmd=args.test_cmd,
    )
    if not all_ok:
        print("Baseline gate FAILED:")
        for g in gates:
            if not g["ok"]:
                print(f"- {g['name']}: {g['detail']}")
        return 1

    bench_res = None
    if args.bench_cmd:
        b_proc = run_cmd(args.bench_cmd, root, shell=True)
        if b_proc.returncode != 0:
            sys.stderr.write(f"Baseline bench failed:\n{b_proc.stdout}\n{b_proc.stderr}\n")
            return 1
        bench_res = parse_bench_metrics(b_proc.stdout + "\n" + b_proc.stderr, args.bench_metric)

    cdir = campaign_dir(root, args.campaign)
    (cdir / "snapshots").mkdir(parents=True, exist_ok=True)
    shutil.copy2(target_path, snapshot_path(cdir, 0))

    objectives = extract_objectives(comp, lit_info, bench_res)
    gen0 = {
        "id": 0,
        "timestamp": datetime.now(UTC).isoformat(),
        "note": "baseline",
        "mode": comp["mode"],
        "verdict": "BASELINE",
        "gates": gates,
        "objectives": objectives,
        "bench": bench_res,
        "target_bce_elided": comp["target_bce_elided"],
        "target_bce_kept": comp["target_bce_kept"],
    }
    ledger = {
        "campaign": args.campaign,
        "config": {
            "target": rel_posix(target_path, root),
            "entry": rel_posix(entry_path, root),
            "test_cmd": args.test_cmd,
            "bench_cmd": args.bench_cmd,
            "bench_metric": args.bench_metric,
            "max_gcrap": args.max_gcrap,
            "ct_check": args.ct_check,
            "strict_rfc": args.strict_rfc,
            "noise_pct": args.noise_pct,
            "force_unpatched": args.force_unpatched,
        },
        "pareto_ids": [0],
        "generations": [gen0],
    }
    save_ledger(cdir, ledger)
    print(f"Initialized campaign `{args.campaign}` (gen 0, mode={comp['mode']})")
    print(f"Baseline objectives: {json.dumps(objectives)}")
    return 0


def cmd_eval(args: argparse.Namespace) -> int:
    root = repo_root()
    cdir = campaign_dir(root, args.campaign)
    ledger = load_ledger(cdir)
    cfg = ledger["config"]
    target_path = root / cfg["target"]
    entry_path = root / cfg["entry"]
    force_unpatched = bool(args.force_unpatched or cfg.get("force_unpatched", False))
    goose_bin = find_goose_binary()

    gen_id = len(ledger["generations"])
    all_ok, gates, comp, lit_info = run_gates(
        root,
        target_path,
        entry_path,
        goose_bin,
        max_gcrap=int(cfg["max_gcrap"]),
        ct_check=bool(cfg.get("ct_check", False)),
        strict_rfc=bool(cfg.get("strict_rfc", False)),
        force_unpatched=force_unpatched,
        test_cmd=str(cfg.get("test_cmd", "")),
    )

    baseline_kept = ledger["generations"][0]["objectives"].get("target_bce_kept", 0)
    if all_ok and not args.allow_bce_increase and comp["target_bce_kept"] > baseline_kept:
        all_ok = False
        gates.append(
            {
                "name": "bce-no-regression",
                "ok": False,
                "detail": f"target_bce_kept increased from {int(baseline_kept)} to {comp['target_bce_kept']}",
            }
        )

    if not all_ok:
        entry = {
            "id": gen_id,
            "timestamp": datetime.now(UTC).isoformat(),
            "note": args.note,
            "mode": comp["mode"],
            "verdict": "REJECTED_GATE",
            "gates": gates,
            "objectives": extract_objectives(comp, lit_info, None),
        }
        ledger["generations"].append(entry)
        save_ledger(cdir, ledger)
        print(f"Gen {gen_id}: REJECTED_GATE ({args.note})")
        for g in gates:
            if not g["ok"]:
                print(f"  FAIL {g['name']}: {g['detail']}")
        return 1

    bench_res = None
    if cfg.get("bench_cmd"):
        b_proc = run_cmd(str(cfg["bench_cmd"]), root, shell=True)
        if b_proc.returncode != 0:
            sys.stderr.write(f"Bench command failed:\n{b_proc.stdout}\n{b_proc.stderr}\n")
            return 1
        bench_res = parse_bench_metrics(
            b_proc.stdout + "\n" + b_proc.stderr, str(cfg.get("bench_metric", ""))
        )

    objectives = extract_objectives(comp, lit_info, bench_res)
    cand = {
        "id": gen_id,
        "timestamp": datetime.now(UTC).isoformat(),
        "note": args.note,
        "mode": comp["mode"],
        "verdict": "",
        "gates": gates,
        "objectives": objectives,
        "bench": bench_res,
        "target_bce_elided": comp["target_bce_elided"],
        "target_bce_kept": comp["target_bce_kept"],
    }
    verdict, new_pareto = update_pareto(
        ledger["generations"],
        ledger["pareto_ids"],
        cand,
        float(cfg.get("noise_pct", 3.0)),
    )
    cand["verdict"] = verdict
    shutil.copy2(target_path, snapshot_path(cdir, gen_id))
    ledger["pareto_ids"] = new_pareto
    ledger["generations"].append(cand)
    save_ledger(cdir, ledger)

    base_obj = ledger["generations"][0]["objectives"]
    deltas = {
        k: round(objectives[k] - base_obj[k], 3)
        for k in objectives
        if k in base_obj
    }
    print(f"Gen {gen_id}: {verdict} (mode={comp['mode']}) - {args.note}")
    print(f"  Objectives: {json.dumps(objectives)}")
    print(f"  Delta vs gen 0: {json.dumps(deltas)}")
    print(f"  Pareto frontier IDs: {new_pareto}")
    return 0


def cmd_status(args: argparse.Namespace) -> int:
    root = repo_root()
    ledger = load_ledger(campaign_dir(root, args.campaign))
    if args.json:
        print(json.dumps(ledger, indent=2))
        return 0
    print(f"# Campaign `{ledger['campaign']}` ({ledger['config']['target']})")
    print(f"Pareto frontier IDs: {ledger['pareto_ids']}")
    for g in ledger["generations"]:
        star = "*" if g["id"] in ledger["pareto_ids"] else " "
        print(
            f"{star} gen {g['id']:04d} [{g['verdict']}] ({g['mode']}) "
            f"{json.dumps(g['objectives'])} -- {g['note']}"
        )
    return 0


def cmd_restore(args: argparse.Namespace) -> int:
    root = repo_root()
    cdir = campaign_dir(root, args.campaign)
    ledger = load_ledger(cdir)
    target_path = root / ledger["config"]["target"]
    snap = snapshot_path(cdir, args.gen_id)
    if not snap.exists():
        sys.stderr.write(f"Snapshot not found: {snap}\n")
        return 2
    shutil.copy2(snap, target_path)
    print(f"Restored `{ledger['config']['target']}` from gen {args.gen_id:04d}")
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        description="Goose-Evolve: compiler-backed optimization radar and Pareto evolution loop"
    )
    sub = parser.add_subparsers(dest="command", required=True)

    p_ana = sub.add_parser("analyze", help="Analyze target file and emit optimization hypotheses")
    p_ana.add_argument("target", help="Target .goose file")
    p_ana.add_argument("--entry", default="", help="Root entry .goose file")
    p_ana.add_argument("--force-unpatched", action="store_true", help="Force stock CLI fallback")
    p_ana.add_argument("--rfc", action="store_true", help="Include goose2rfc strict findings")
    p_ana.add_argument("--json", action="store_true", help="Emit JSON output")
    p_ana.set_defaults(func=cmd_analyze)

    p_init = sub.add_parser("init", help="Initialize an evolution campaign and baseline snapshot")
    p_init.add_argument("campaign", help="Campaign name")
    p_init.add_argument("--target", required=True, help="Target .goose file")
    p_init.add_argument("--entry", default="", help="Root entry .goose file")
    p_init.add_argument("--test-cmd", default="", help="Shell command for functional verification")
    p_init.add_argument("--bench-cmd", default="", help="Shell command emitting BENCH / ns_op")
    p_init.add_argument("--bench-metric", default="", help="Specific benchmark case name")
    p_init.add_argument("--max-gcrap", type=int, default=25, help="Max G-CRAP ceiling")
    p_init.add_argument("--ct-check", action="store_true", help="Run scripts/verify_ct_asm.py gate")
    p_init.add_argument("--strict-rfc", action="store_true", help="Run goose2rfc --strict gate")
    p_init.add_argument("--noise-pct", type=float, default=3.0, help="Benchmark noise tolerance %")
    p_init.add_argument("--force-unpatched", action="store_true", help="Force stock CLI fallback")
    p_init.set_defaults(func=cmd_init)

    p_eval = sub.add_parser("eval", help="Evaluate current target against gates and Pareto frontier")
    p_eval.add_argument("campaign", help="Campaign name")
    p_eval.add_argument("--note", default="mutation", help="Short hypothesis description")
    p_eval.add_argument("--force-unpatched", action="store_true", help="Force stock CLI fallback")
    p_eval.add_argument(
        "--allow-bce-increase",
        action="store_true",
        help="Allow kept BCE checks above baseline",
    )
    p_eval.set_defaults(func=cmd_eval)

    p_stat = sub.add_parser("status", help="Show campaign generations and Pareto frontier")
    p_stat.add_argument("campaign", help="Campaign name")
    p_stat.add_argument("--json", action="store_true", help="Emit JSON output")
    p_stat.set_defaults(func=cmd_status)

    p_rest = sub.add_parser("restore", help="Restore target file from a saved generation snapshot")
    p_rest.add_argument("campaign", help="Campaign name")
    p_rest.add_argument("gen_id", type=int, help="Generation ID to restore")
    p_rest.set_defaults(func=cmd_restore)

    return parser


def main() -> int:
    args = build_parser().parse_args()
    return int(args.func(args))


if __name__ == "__main__":
    sys.exit(main())
