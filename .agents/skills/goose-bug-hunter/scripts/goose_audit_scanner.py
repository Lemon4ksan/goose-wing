#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""Project-agnostic deterministic scanner and coverage-ledger manager for Goose (.goose) codebases.

Enumerates all Goose functions, enriches them with `goose-lit crap` complexity/BCE metrics when
available, runs 12 Goose-specific static bug-pattern probes, partitions functions into bounded
review slices, and validates coverage ledgers and findings schemas.
"""

from __future__ import annotations

import argparse
import json
import re
import shutil
import subprocess
import sys
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

# Regex matching Goose function declarations at line start (after comment/string scrubbing)
FN_START_RE = re.compile(
    r"^\s*(?P<vis>pub\s+)?"
    r"(?P<mods>(?:(?:inline|checkfree|recursive)\s+)*)"
    r"(?P<kw>fn|thread_fn)\s+"
    r"(?:::)?(?P<name>[A-Za-z0-9_]+)"
)
EXTERN_FN_RE = re.compile(r"^\s*(?:pub\s+)?extern\s+fn\s+(?:::)?(?P<name>[A-Za-z0-9_]+)")

# Identifiers indicating cryptographic or authentication secrets/tags
CRYPTO_SECRET_IDENT_RE = re.compile(
    r"\b[A-Za-z0-9_]*(?:digest|mac|hmac|sig|signature|tag|secret|hash|"
    r"expected_response|verify_token|thumbprint|challenge|priv_key|"
    r"shared_key|master_secret|password| passcode|api_key)[A-Za-z0-9_]*\b",
    re.IGNORECASE,
)

ZEROIZE_MATERIAL_RE = re.compile(
    r"\b[A-Za-z0-9_]*(?:secret|priv_key|shared_key|master_secret|password|"
    r"hmac_key|symmetric_key|key_bytes|seed_bytes)[A-Za-z0-9_]*\b",
    re.IGNORECASE,
)

VERIFY_FN_NAME_RE = re.compile(
    r"^(?:verify|validate|authenticate|check|decrypt|open)_|"
    r"_(?:verify|validate|authenticate|check)$"
)

RESOURCE_ACQUIRE_RE = re.compile(
    r"\b(?:alloc_index|alloc_ref|alloc_with|alloc_index_with|alloc_slice|alloc_copy|"
    r"open|connect|accept|acquire|create_session|alloc_stream|reserve_slot)\s*\("
)
RESOURCE_RELEASE_RE = re.compile(
    r"\b(?:free|free_ref|free_slice|recycle_all|close|release|destroy|reset|cleanup|remove_stream)\s*\("
)


def scrub_comments_and_strings(line: str) -> str:
    """Replaces string literal contents and // line comments with spaces, keeping length/braces."""
    out: list[str] = []
    i = 0
    n = len(line)
    in_str = False
    while i < n:
        ch = line[i]
        if in_str:
            if ch == "\\" and i + 1 < n:
                out.append("  ")
                i += 2
                continue
            if ch == '"':
                in_str = False
                out.append('"')
            else:
                out.append(" ")
            i += 1
        else:
            if ch == "/" and i + 1 < n and line[i + 1] == "/":
                out.append(" " * (n - i))
                break
            if ch == '"':
                in_str = True
                out.append('"')
            else:
                out.append(ch)
            i += 1
    return "".join(out)


def find_repo_root(start_path: Path) -> Path:
    """Walks up from start_path to locate the repository root (.git or top-level directory)."""
    cur = start_path.resolve()
    if cur.is_file():
        cur = cur.parent
    for parent in [cur, *cur.parents]:
        if (parent / ".git").exists() or (parent / "AGENTS.md").exists():
            return parent
    return cur


def normalize_rel_path(path: Path, root: Path) -> str:
    """Returns forward-slash relative path from root."""
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.as_posix()


def detect_environment(repo_root: Path) -> dict[str, Any]:
    """Detects optional Goose toolchain binaries and repository conventions."""
    goose_bin = shutil.which("goose")
    goose_lit_bin = shutil.which("goose-lit")
    rg_bin = shutil.which("rg")
    has_agents_md = (repo_root / "AGENTS.md").exists() or (
        repo_root / ".agents" / "AGENTS.md"
    ).exists()
    has_lint_invariants = (repo_root / "scripts" / "lint_invariants.py").exists()
    has_rfc_dir = (repo_root / ".gemini" / "rfc").is_dir() or (repo_root / "docs" / "rfc").is_dir()
    return {
        "goose_available": goose_bin is not None,
        "goose_lit_available": goose_lit_bin is not None,
        "rg_available": rg_bin is not None,
        "has_agents_md": has_agents_md,
        "has_wing_lint_invariants": has_lint_invariants,
        "has_rfc_corpus": has_rfc_dir,
    }


def run_goose_lit_crap(target_path: Path, repo_root: Path) -> dict[tuple[str, int], dict[str, Any]]:
    """Runs `goose-lit crap <target_path> --format json` and indexes results by (rel_file, line)."""
    if shutil.which("goose-lit") is None:
        return {}
    try:
        proc = subprocess.run(
            ["goose-lit", "crap", str(target_path), "--format", "json"],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=30,
            check=False,
        )
    except (OSError, subprocess.SubprocessError):
        return {}

    stdout = proc.stdout or ""
    json_start = stdout.find("\n{")
    if json_start != -1:
        json_start += 1
    elif stdout.lstrip().startswith("{"):
        json_start = stdout.find("{")
    else:
        return {}

    try:
        payload = json.loads(stdout[json_start:])
    except json.JSONDecodeError:
        return {}

    result: dict[tuple[str, int], dict[str, Any]] = {}
    for fn_obj in payload.get("functions", []):
        raw_file = str(fn_obj.get("file", "")).replace("\\", "/")
        line_no = int(fn_obj.get("line", 0))
        raw_name = str(fn_obj.get("name", ""))
        short_name = raw_name.split("::")[-1] if "::" in raw_name else raw_name
        entry = {
            "short_name": short_name,
            "gcrap_score": float(fn_obj.get("g_crap", 0.0)),
            "eff_cc": int(fn_obj.get("effective_cc", 0)),
            "cyclomatic_cc": int(fn_obj.get("cyclomatic_cc", 0)),
            "risk_safety": float(fn_obj.get("risk_safety", 0.0)),
            "uncovered_bce_keep": int(fn_obj.get("uncovered_bce_keep", 0)),
            "total_bce_keep": int(fn_obj.get("total_bce_keep", 0)),
            "archetype": str(fn_obj.get("archetype", "")),
        }
        result[(raw_file, line_no)] = entry
    return result


def collect_module_globals(scrubbed_lines: list[str]) -> list[tuple[int, str]]:
    """Finds top-level (brace-depth 0) mutable `var` or `reusable var` declarations."""
    globals_found: list[tuple[int, str]] = []
    depth = 0
    for idx, sline in enumerate(scrubbed_lines):
        if depth == 0:
            m_var = re.match(
                r"^\s*(?:pub\s+)?(?P<reusable>reusable\s+)?var\s+(?P<name>[A-Za-z0-9_]+)",
                sline,
            )
            if m_var:
                globals_found.append((idx + 1, m_var.group("name")))
        depth += sline.count("{") - sline.count("}")
        if depth < 0:
            depth = 0
    return globals_found


def detect_static_signals(
    fn_name: str,
    fn_kind: str,
    signature: str,
    raw_body_lines: list[str],
    scrubbed_body_lines: list[str],
    module_globals: list[tuple[int, str]],
    crap_info: dict[str, Any] | None,
    profile: str,
) -> list[str]:
    """Runs the 12 Goose static bug-pattern probes on a single function unit."""
    signals: list[str] = []
    body_joined = "\n".join(scrubbed_body_lines)

    # 1. BOUNDED_APPEND_NO_GUARD: .append( or .push( without a capacity/length guard in the function
    has_append_or_push = bool(re.search(r"\.\s*(?:append|push)\s*\(", body_joined))
    has_cap_or_len_guard = bool(
        re.search(
            r"\bguard\b[^\{;]*(?:\.cap\b|\.len\b|<=\s*[A-Z0-9_]+|<\s*[A-Z0-9_]+)", body_joined
        )
        or re.search(r"\bif\b[^\{;]*(?:\.cap\b|\.len\b)", body_joined)
    )
    if has_append_or_push and not has_cap_or_len_guard:
        signals.append("BOUNDED_APPEND_NO_GUARD")

    # 2. NARROW_OR_FORCE_CAST: `as!` or narrowing casts (`as u8`, `as u16`, `as u32`, `as i32`, `as i16`, `as i8`)
    if re.search(r"\bas!\s*[A-Za-z0-9_]+|\bas\s+(?:u8|u16|u32|i8|i16|i32)\b", body_joined):
        signals.append("NARROW_OR_FORCE_CAST")

    # 3. BCE_OR_CHECKFREE_RISK: checkfree indexing or uncovered_bce_keep > 0
    is_checkfree = "checkfree" in fn_kind
    has_indexing = bool(re.search(r"\[[^\]:]+\]", body_joined))
    uncovered_bce = int(crap_info.get("uncovered_bce_keep", 0)) if crap_info else 0
    if (is_checkfree and has_indexing) or uncovered_bce > 0:
        signals.append("BCE_OR_CHECKFREE_RISK")

    # 4. UNBOUNDED_LOOP_GROWTH_OR_ALIAS:
    # - `var x: T[>..]` declared outside loop and grown inside loop without clear/truncate
    # - `let b = a` aliasing a `T[>..]` variable
    # - In `--profile wing`, any `var x: T[>..]` inside a loop or function
    growable_vars: set[str] = set()
    in_loop = False
    loop_depth = 0
    cur_depth = 0
    growable_before_loop: set[str] = set()
    grown_in_loop_without_clear = False
    wing_growable_in_fn = False

    for sline in scrubbed_body_lines:
        if re.search(r"\b(?:while|for)\b", sline) and not in_loop:
            in_loop = True
            loop_depth = cur_depth

        m_grow = re.search(
            r"\bvar\s+([A-Za-z0-9_]+)\s*:\s*[A-Za-z0-9_:]+\[>\.\.\]",
            sline,
        )
        if m_grow:
            vname = m_grow.group(1)
            growable_vars.add(vname)
            if not in_loop:
                growable_before_loop.add(vname)
            if profile == "wing":
                wing_growable_in_fn = True

        if in_loop:
            for gv in growable_before_loop:
                if re.search(
                    rf"\b{re.escape(gv)}\s*\.\s*(?:push|append)\s*\(", sline
                ) and not re.search(
                    rf"\b{re.escape(gv)}\s*\.\s*(?:clear|truncate)\s*\(",
                    body_joined,
                ):
                    grown_in_loop_without_clear = True

        cur_depth += sline.count("{") - sline.count("}")
        if in_loop and cur_depth <= loop_depth:
            in_loop = False

    has_growable_alias = False
    for gv in growable_vars:
        if re.search(rf"\b(?:let|var)\s+[A-Za-z0-9_]+\s*=\s*{re.escape(gv)}\s*;", body_joined):
            has_growable_alias = True

    if grown_in_loop_without_clear or has_growable_alias or wing_growable_in_fn:
        signals.append("UNBOUNDED_LOOP_GROWTH_OR_ALIAS")

    # 5. IGNORED_RETURN_TUPLE: `let x, _ =` or `let _, x =`
    if re.search(
        r"\b(?:let|var)\s+(?:[A-Za-z0-9_]+\s*,\s*_|_{1}\s*,\s*[A-Za-z0-9_]+)\s*=", body_joined
    ):
        signals.append("IGNORED_RETURN_TUPLE")

    # 6. SATURATING_OR_SIGNED_OVERFLOW: `mul_sat_*`, `add_sat_*`, or signed `%` on `i64`/`i32`
    if re.search(r"\b(?:mul_sat_|add_sat_|sub_sat_)[A-Za-z0-9_]*\s*\(", body_joined):
        signals.append("SATURATING_OR_SIGNED_OVERFLOW")

    # 7. REUSABLE_POOL_OR_GLOBAL_STATE: `slot_pool` / `slice_pool` / `reusable` pool ops or module global access
    has_reusable_ops = bool(
        re.search(
            r"\b(?:alloc_index|alloc_ref|alloc_with|alloc_index_with|alloc_slice|alloc_copy|realloc_slice|free_slice|free_ref)\s*\(|\b(?:reusable|slot_pool|slice_pool)\b",
            body_joined,
        )
    )
    uses_module_global = False
    for _, gname in module_globals:
        if re.search(rf"\b{re.escape(gname)}\b", body_joined):
            uses_module_global = True
            break
    if has_reusable_ops or uses_module_global:
        signals.append("REUSABLE_POOL_OR_GLOBAL_STATE")

    # 8. EARLY_RETURN_RESOURCE_LEAK: acquires resource/slot and has early `guard ... else { return` before release (without `defer`)
    if RESOURCE_ACQUIRE_RE.search(body_joined):
        has_early_guard_return = bool(
            re.search(r"\bguard\b[^\{]*\belse\s*\{\s*return\b|\breturn\b[^;]*\bfrom\b", body_joined)
        )
        has_defer = bool(re.search(r"\bdefer\b", body_joined))
        if has_early_guard_return and not has_defer:
            signals.append("EARLY_RETURN_RESOURCE_LEAK")

    # 9. SWAR_ARITHMETIC: 64-bit word magic masks combined with `+` or `-`
    if re.search(r"0x0*101010101010101|0x8080808080808080", body_joined):
        signals.append("SWAR_ARITHMETIC")

    # 10. EARLY_EXIT_SECRET_CMP: `==` or `!=` on crypto/auth secret/digest/tag variables
    for sline in scrubbed_body_lines:
        if "==" in sline or (
            "!=" in sline
            and CRYPTO_SECRET_IDENT_RE.search(sline)
            and "ct_eq" not in sline
            and not re.search(r"(?:==|!=)\s*(?:0|true|false|\d+)\b", sline)
        ):
            signals.append("EARLY_EXIT_SECRET_CMP")
            break

    # 11. SECRET_NO_ZEROIZE: secret/key material with early return and no zeroize call
    if ZEROIZE_MATERIAL_RE.search(signature + "\n" + body_joined):
        has_early_exit = bool(re.search(r"\bguard\b[^\{]*\belse\s*\{\s*return\b", body_joined))
        has_zeroize = bool(re.search(r"\bzeroize[A-Za-z0-9_]*\s*\(", body_joined))
        if has_early_exit and not has_zeroize:
            signals.append("SECRET_NO_ZEROIZE")

    # 12. EXTERN_FFI_OR_STUB_RETURN: `extern fn` or validation function with suspicious constant success return
    if fn_kind == "extern fn" or (
        VERIFY_FN_NAME_RE.search(fn_name)
        # Check for unconditional or stub `return true;` / `CloseNotify` / `return 0;`
        and re.search(
            r"\breturn\s+(?:true|0)\s*;|CloseNotify",
            body_joined,
        )
    ):
        signals.append("EXTERN_FFI_OR_STUB_RETURN")

    return signals


def parse_goose_file(
    file_path: Path,
    repo_root: Path,
    crap_map: dict[tuple[str, int], dict[str, Any]],
    profile: str,
) -> list[dict[str, Any]]:
    """Extracts all function units and static signals from a single .goose file."""
    try:
        raw_text = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    raw_lines = raw_text.splitlines()
    scrubbed_lines = [scrub_comments_and_strings(line) for line in raw_lines]
    rel_file = normalize_rel_path(file_path, repo_root)
    module_globals = collect_module_globals(scrubbed_lines)

    units: list[dict[str, Any]] = []
    n = len(raw_lines)
    i = 0

    while i < n:
        sline = scrubbed_lines[i]
        m_ext = EXTERN_FN_RE.match(sline)
        if m_ext:
            fn_name = m_ext.group("name")
            start_line = i + 1
            end_idx = i
            while end_idx < n and ";" not in scrubbed_lines[end_idx]:
                end_idx += 1
            if end_idx >= n:
                end_idx = i
            end_line = end_idx + 1
            sig = " ".join(s.strip() for s in raw_lines[i : end_idx + 1])
            crap_info = crap_map.get((rel_file, start_line))
            signals = detect_static_signals(
                fn_name=fn_name,
                fn_kind="extern fn",
                signature=sig,
                raw_body_lines=raw_lines[i : end_idx + 1],
                scrubbed_body_lines=scrubbed_lines[i : end_idx + 1],
                module_globals=module_globals,
                crap_info=crap_info,
                profile=profile,
            )
            units.append(
                {
                    "file": rel_file,
                    "name": fn_name,
                    "kind": "extern fn",
                    "start_line": start_line,
                    "end_line": end_line,
                    "signature": sig,
                    "gcrap_score": crap_info["gcrap_score"] if crap_info else 0.0,
                    "eff_cc": crap_info["eff_cc"] if crap_info else 1,
                    "risk_safety": crap_info["risk_safety"] if crap_info else 0.0,
                    "uncovered_bce_keep": crap_info["uncovered_bce_keep"] if crap_info else 0,
                    "static_signals": signals,
                }
            )
            i = end_idx + 1
            continue

        m_fn = FN_START_RE.match(sline)
        if m_fn:
            fn_name = m_fn.group("name")
            mods = (m_fn.group("mods") or "").strip()
            kw = m_fn.group("kw")
            fn_kind = f"{mods} {kw}".strip()
            start_line = i + 1

            # Reconstruct signature up to opening '{' or ';'
            sig_end_idx = i
            found_open_brace = False
            while sig_end_idx < min(n, i + 25):
                if "{" in scrubbed_lines[sig_end_idx]:
                    found_open_brace = True
                    break
                if ";" in scrubbed_lines[sig_end_idx]:
                    break
                sig_end_idx += 1

            if not found_open_brace:
                i += 1
                continue

            sig_raw = " ".join(
                re.sub(r"//.*$", "", raw_lines[k]).strip() for k in range(i, sig_end_idx + 1)
            )
            sig_clean = sig_raw.split("{")[0].strip()

            # Match braces from i to end of function
            brace_depth = 0
            end_idx = sig_end_idx
            for k in range(i, n):
                opens = scrubbed_lines[k].count("{")
                closes = scrubbed_lines[k].count("}")
                brace_depth += opens - closes
                if k >= sig_end_idx and brace_depth <= 0 and (opens > 0 or closes > 0):
                    end_idx = k
                    break
            else:
                end_idx = n - 1

            end_line = end_idx + 1
            crap_info = crap_map.get((rel_file, start_line))
            if crap_info is None:
                # Fallback lookup within +-2 lines for attribute/comment offsets
                for delta in (-1, 1, -2, 2):
                    crap_info = crap_map.get((rel_file, start_line + delta))
                    if crap_info and crap_info.get("short_name") == fn_name:
                        break
                else:
                    crap_info = None

            signals = detect_static_signals(
                fn_name=fn_name,
                fn_kind=fn_kind,
                signature=sig_clean,
                raw_body_lines=raw_lines[i : end_idx + 1],
                scrubbed_body_lines=scrubbed_lines[i : end_idx + 1],
                module_globals=module_globals,
                crap_info=crap_info,
                profile=profile,
            )

            units.append(
                {
                    "file": rel_file,
                    "name": fn_name,
                    "kind": fn_kind,
                    "start_line": start_line,
                    "end_line": end_line,
                    "signature": sig_clean,
                    "gcrap_score": crap_info["gcrap_score"] if crap_info else 0.0,
                    "eff_cc": crap_info["eff_cc"] if crap_info else 1,
                    "risk_safety": crap_info["risk_safety"] if crap_info else 0.0,
                    "uncovered_bce_keep": crap_info["uncovered_bce_keep"] if crap_info else 0,
                    "static_signals": signals,
                }
            )
            i = end_idx + 1
            continue

        i += 1

    return units


def partition_into_slices(
    units: list[dict[str, Any]],
    max_fns: int,
    max_lines: int,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Partitions function units into bounded slices (<= max_fns and <= max_lines per slice)."""
    slices: list[dict[str, Any]] = []
    cur_unit_ids: list[str] = []
    cur_files: list[str] = []
    cur_lines = 0
    slice_idx = 1

    for idx, unit in enumerate(units, start=1):
        unit_id = f"U{idx:04d}"
        unit["unit_id"] = unit_id
        unit["status"] = "planned"
        unit["skip_reason"] = ""
        unit["finding_ids"] = []
        fn_span = max(1, int(unit["end_line"]) - int(unit["start_line"]) + 1)

        if cur_unit_ids and (len(cur_unit_ids) >= max_fns or (cur_lines + fn_span) > max_lines):
            slice_id = f"S{slice_idx:03d}"
            slices.append(
                {
                    "slice_id": slice_id,
                    "files": sorted(set(cur_files)),
                    "unit_ids": list(cur_unit_ids),
                    "unit_count": len(cur_unit_ids),
                    "line_span": cur_lines,
                }
            )
            slice_idx += 1
            cur_unit_ids = []
            cur_files = []
            cur_lines = 0

        cur_slice_id = f"S{slice_idx:03d}"
        unit["slice_id"] = cur_slice_id
        cur_unit_ids.append(unit_id)
        cur_files.append(str(unit["file"]))
        cur_lines += fn_span

    if cur_unit_ids:
        slice_id = f"S{slice_idx:03d}"
        slices.append(
            {
                "slice_id": slice_id,
                "files": sorted(set(cur_files)),
                "unit_ids": list(cur_unit_ids),
                "unit_count": len(cur_unit_ids),
                "line_span": cur_lines,
            }
        )

    return slices, units


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.target_path).resolve()
    if not target.exists():
        print(f"[ERROR] Target path does not exist: {target}", file=sys.stderr)
        return 1

    repo_root = find_repo_root(target)
    if target.is_file():
        goose_files = [target] if target.suffix == ".goose" else []
    else:
        goose_files = sorted(
            p for p in target.rglob("*.goose") if ".gemini" not in p.parts and ".git" not in p.parts
        )

    if not goose_files:
        print(f"[ERROR] No .goose files found under: {target}", file=sys.stderr)
        return 1

    now_utc = datetime.now(UTC)
    run_id = now_utc.strftime("run_%Y%m%d_%H%M%S")
    if args.out_dir:
        out_dir = Path(args.out_dir).resolve()
    else:
        out_dir = (repo_root / ".gemini" / "goose_audit" / run_id).resolve()

    out_dir.mkdir(parents=True, exist_ok=True)
    env_caps = detect_environment(repo_root)
    profile = args.profile
    if profile == "auto":
        profile = "wing" if env_caps.get("has_wing_lint_invariants") else "universal"

    crap_map = run_goose_lit_crap(target, repo_root)

    all_units: list[dict[str, Any]] = []
    for gf in goose_files:
        file_units = parse_goose_file(gf, repo_root, crap_map, profile)
        all_units.extend(file_units)

    slices, numbered_units = partition_into_slices(
        all_units,
        max_fns=args.slice_max_fns,
        max_lines=args.slice_max_lines,
    )

    rel_target = normalize_rel_path(target, repo_root)
    recommended_mode = (
        "inline" if len(goose_files) <= 2 and len(numbered_units) <= 24 else "full_pipeline"
    )

    signal_counts: dict[str, int] = {}
    for u in numbered_units:
        for sig in u.get("static_signals", []):
            signal_counts[sig] = signal_counts.get(sig, 0) + 1

    run_metadata = {
        "run_id": run_id,
        "created_at": now_utc.isoformat(),
        "repo_root": repo_root.as_posix(),
        "finding_scope_root": rel_target,
        "context_roots": [repo_root.as_posix()],
        "profile": profile,
        "recommended_mode": recommended_mode,
        "capabilities": env_caps,
        "total_files": len(goose_files),
        "total_units": len(numbered_units),
        "total_slices": len(slices),
        "signal_summary": signal_counts,
    }

    coverage_ledger = {
        "run_id": run_id,
        "finding_scope_root": rel_target,
        "total_units": len(numbered_units),
        "total_slices": len(slices),
        "slices": slices,
        "units": numbered_units,
    }

    meta_path = out_dir / "run-metadata.json"
    ledger_path = out_dir / "coverage-ledger.json"
    findings_path = out_dir / "findings.json"

    meta_path.write_text(json.dumps(run_metadata, indent=2) + "\n", encoding="utf-8")
    ledger_path.write_text(json.dumps(coverage_ledger, indent=2) + "\n", encoding="utf-8")
    if not findings_path.exists():
        findings_path.write_text(
            json.dumps({"run_id": run_id, "findings": []}, indent=2) + "\n",
            encoding="utf-8",
        )

    print(
        json.dumps(
            {
                "status": "ok",
                "out_dir": out_dir.as_posix(),
                "run_metadata": meta_path.as_posix(),
                "coverage_ledger": ledger_path.as_posix(),
                "findings_file": findings_path.as_posix(),
                "profile": profile,
                "recommended_mode": recommended_mode,
                "total_files": len(goose_files),
                "total_units": len(numbered_units),
                "total_slices": len(slices),
                "signal_summary": signal_counts,
            },
            indent=2,
        )
    )
    return 0


def cmd_validate_ledger(args: argparse.Namespace) -> int:
    ledger_path = Path(args.ledger_path).resolve()
    if not ledger_path.exists():
        print(f"[ERROR] Ledger file not found: {ledger_path}", file=sys.stderr)
        return 1

    try:
        ledger = json.loads(ledger_path.read_text(encoding="utf-8"))
    except json.JSONDecodeError as exc:
        print(f"[ERROR] Invalid JSON in ledger: {exc}", file=sys.stderr)
        return 1

    units = ledger.get("units")
    if not isinstance(units, list):
        print("[ERROR] Ledger missing top-level 'units' list.", file=sys.stderr)
        return 1

    valid_statuses = {"planned", "covered", "skipped"}
    planned_units: list[str] = []
    invalid_units: list[str] = []

    for u in units:
        uid = str(u.get("unit_id", "<unknown>"))
        status = str(u.get("status", ""))
        if status not in valid_statuses:
            invalid_units.append(f"{uid}: invalid status '{status}'")
        elif status == "planned":
            planned_units.append(f"{uid} ({u.get('file')}:{u.get('start_line')} {u.get('name')})")
        elif status == "skipped" and not str(u.get("skip_reason", "")).strip():
            invalid_units.append(f"{uid}: status is 'skipped' but 'skip_reason' is empty")

    findings_path = (
        Path(args.findings).resolve()
        if args.findings
        else (ledger_path.parent / "findings.json").resolve()
    )
    finding_errors: list[str] = []
    if findings_path.exists():
        try:
            fdata = json.loads(findings_path.read_text(encoding="utf-8"))
            flist = fdata.get("findings", [])
            if not isinstance(flist, list):
                finding_errors.append("'findings' field in findings.json must be a list")
            else:
                required_keys = {
                    "finding_id",
                    "unit_id",
                    "file",
                    "lines",
                    "bug_class",
                    "severity",
                    "verdict",
                    "gates_passed",
                    "trigger_trace",
                    "refutation_notes",
                }
                for fitem in flist:
                    fid = str(fitem.get("finding_id", "<unknown>"))
                    missing = required_keys - set(fitem.keys())
                    if missing:
                        finding_errors.append(f"{fid}: missing keys {sorted(missing)}")
                    verdict = str(fitem.get("verdict", "")).lower()
                    if verdict not in {"confirmed", "partial", "rejected"}:
                        finding_errors.append(
                            f"{fid}: invalid verdict '{verdict}' (expected confirmed|partial|rejected)"
                        )
        except json.JSONDecodeError as exc:
            finding_errors.append(f"Invalid JSON in {findings_path}: {exc}")

    if invalid_units or planned_units or finding_errors:
        print(
            json.dumps(
                {
                    "status": "failed",
                    "planned_remaining_count": len(planned_units),
                    "planned_units": planned_units[:25],
                    "invalid_units": invalid_units,
                    "finding_errors": finding_errors,
                },
                indent=2,
            )
        )
        return 1

    print(
        json.dumps(
            {
                "status": "passed",
                "total_units": len(units),
                "covered_count": sum(1 for u in units if u.get("status") == "covered"),
                "skipped_count": sum(1 for u in units if u.get("status") == "skipped"),
            },
            indent=2,
        )
    )
    return 0


def cmd_variants(args: argparse.Namespace) -> int:
    scope = Path(args.scope).resolve() if args.scope else Path.cwd().resolve()
    repo_root = find_repo_root(scope)
    pattern = args.pattern
    try:
        regex = re.compile(pattern)
    except re.error as exc:
        print(f"[ERROR] Invalid regular expression '{pattern}': {exc}", file=sys.stderr)
        return 1

    goose_files = (
        [scope]
        if scope.is_file()
        else sorted(
            p for p in scope.rglob("*.goose") if ".gemini" not in p.parts and ".git" not in p.parts
        )
    )

    matches: list[dict[str, Any]] = []
    for gf in goose_files:
        rel_file = normalize_rel_path(gf, repo_root)
        Units = parse_goose_file(gf, repo_root, {}, "universal")
        try:
            lines = gf.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        for idx, line in enumerate(lines, start=1):
            scrubbed = scrub_comments_and_strings(line)
            if regex.search(scrubbed) or regex.search(line):
                enclosing_fn = "<module>"
                for u in Units:
                    if int(u["start_line"]) <= idx <= int(u["end_line"]):
                        enclosing_fn = str(u["name"])
                        break
                matches.append(
                    {
                        "file": rel_file,
                        "line": idx,
                        "function": enclosing_fn,
                        "snippet": line.strip(),
                    }
                )

    print(
        json.dumps(
            {
                "pattern": pattern,
                "match_count": len(matches),
                "matches": matches,
            },
            indent=2,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="goose_audit_scanner.py",
        description="Deterministic scanner and ledger validator for Goose (.goose) bug hunting.",
    )
    subparsers = parser.add_subparsers(dest="subcommand")

    # `scan` subcommand
    p_scan = subparsers.add_parser(
        "scan",
        help="Enumerate .goose functions, run static probes, and write coverage-ledger.json.",
    )
    p_scan.add_argument("target_path", help="File or directory to scan.")
    p_scan.add_argument("--out-dir", default="", help="Output directory for ledger artifacts.")
    p_scan.add_argument(
        "--slice-max-fns",
        type=int,
        default=12,
        help="Maximum functions per Hunter slice (default: 12).",
    )
    p_scan.add_argument(
        "--slice-max-lines",
        type=int,
        default=400,
        help="Maximum line span per Hunter slice (default: 400).",
    )
    p_scan.add_argument(
        "--profile",
        choices=["auto", "universal", "wing"],
        default="auto",
        help="Static probe profile: universal Goose semantics or wing strict zero-alloc.",
    )

    # `validate-ledger` subcommand
    p_val = subparsers.add_parser(
        "validate-ledger",
        help="Verify that all function units left 'planned' state and findings.json matches schema.",
    )
    p_val.add_argument("ledger_path", help="Path to coverage-ledger.json.")
    p_val.add_argument(
        "--findings",
        default="",
        help="Optional explicit path to findings.json (defaults to sibling findings.json).",
    )

    # `variants` subcommand
    p_var = subparsers.add_parser(
        "variants",
        help="Search .goose files for regex pattern and report enclosing function names.",
    )
    p_var.add_argument("pattern", help="Regular expression pattern to search.")
    p_var.add_argument(
        "--scope",
        default="",
        help="Directory or file scope to search (defaults to current working directory).",
    )

    return parser


def main(argv: list[str] | None = None) -> int:
    raw_args = list(sys.argv[1:] if argv is None else argv)
    # Normalize flag aliases (`--validate-ledger` -> `validate-ledger`, `--variants` -> `variants`)
    if raw_args and raw_args[0] == "--validate-ledger":
        raw_args[0] = "validate-ledger"
    elif raw_args and raw_args[0] == "--variants":
        raw_args[0] = "variants"

    parser = build_parser()
    args = parser.parse_args(raw_args)

    if args.subcommand == "scan":
        return cmd_scan(args)
    if args.subcommand == "validate-ledger":
        return cmd_validate_ledger(args)
    if args.subcommand == "variants":
        return cmd_variants(args)

    parser.print_help(sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
