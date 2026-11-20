#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0

"""Cross-platform deterministic recon and validation scanner for `goose-package-refactor`.

Inventories functions, structs, enums, constants, and globals in a target package
directory, computes cross-repo references, detects dead-code islands and unused
struct fields, flags API/readability/optimization signals, attaches `goose-lit crap`
metrics when available, and validates handoff ledgers and migration maps.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path
from typing import Any

FN_START_RE = re.compile(
    r"^\s*(?:pub\s+)?"
    r"(?P<mods>(?:(?:inline|checkfree|recursive)\s+)*)"
    r"(?P<kw>fn|thread_fn)\s+"
    r"(?:::)?(?P<name>[A-Za-z0-9_]+)"
)
EXTERN_FN_RE = re.compile(r"^\s*(?:pub\s+)?extern\s+fn\s+(?:::)?(?P<name>[A-Za-z0-9_]+)")
STRUCT_START_RE = re.compile(r"^\s*(?:root\s+)?struct\s+(?P<name>[A-Za-z0-9_]+)\s*(?:<[^>]+>)?\s*\{")
ENUM_START_RE = re.compile(r"^\s*enum\s+(?P<name>[A-Za-z0-9_]+)\s*\{")
CONST_RE = re.compile(r"^\s*const\s+(?P<name>[A-Za-z0-9_]+)\b")
GLOBAL_VAR_RE = re.compile(r"^\s*var\s+(?P<name>[A-Za-z0-9_]+)\b")
TYPE_ALIAS_RE = re.compile(r"^\s*type\s+(?P<name>[A-Za-z0-9_]+)\s*=")
NAMESPACE_RE = re.compile(r"^\s*namespace\s+([A-Za-z0-9_]+)\s*;")
IMPORT_RE = re.compile(r"^\s*import\s+([^;]+);")
TOKEN_RE = re.compile(r"\b[A-Za-z_][A-Za-z0-9_]*\b")

SKIP_DIRS = {".git", ".worktrees", "worktrees", "build", "bin", "vendor", "scratch", ".ruff_cache"}


def find_tool(name: str, env_var: str = "") -> str | None:
    """Finds a Goose toolchain binary on PATH, via env override, or under ~/.goose."""
    if env_var:
        override = os.environ.get(env_var)
        if override and Path(override).is_file():
            return override
    found = shutil.which(name)
    if found:
        return found
    suffix = ".exe" if os.name == "nt" else ""
    candidates = sorted((Path.home() / ".goose").glob(f"*/{name}{suffix}"))
    if candidates:
        return str(candidates[0])
    return None


def scrub_comments_and_strings(line: str) -> str:
    """Replaces string/char literal contents and // comments with spaces, preserving braces."""
    out: list[str] = []
    i = 0
    n = len(line)
    in_str = False
    in_char = False
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
        elif in_char:
            if ch == "\\" and i + 1 < n:
                out.append("  ")
                i += 2
                continue
            if ch == "'":
                in_char = False
                out.append("'")
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
            elif ch == "'":
                in_char = True
                out.append("'")
            else:
                out.append(ch)
            i += 1
    return "".join(out)


def find_repo_root(start_path: Path) -> Path:
    cur = start_path.resolve()
    if cur.is_file():
        cur = cur.parent
    for parent in [cur, *cur.parents]:
        if (parent / ".git").exists() or (parent / "AGENTS.md").exists():
            return parent
    return cur


def rel_posix(path: Path, root: Path) -> str:
    try:
        return path.resolve().relative_to(root.resolve()).as_posix()
    except ValueError:
        return path.resolve().as_posix()


def collect_repo_goose_files(repo_root: Path) -> list[Path]:
    files: list[Path] = []
    for r, dirs, names in os.walk(repo_root):
        dirs[:] = sorted(d for d in dirs if d not in SKIP_DIRS and not d.startswith("."))
        for name in sorted(names):
            if name.endswith(".goose"):
                files.append((Path(r) / name).resolve())
    return files


def classify_file_zone(rel_path: str, pkg_rel: str) -> str:
    if rel_path == pkg_rel or rel_path.startswith(pkg_rel.rstrip("/") + "/"):
        return "in_pkg"
    top = rel_path.split("/", 1)[0]
    if top in {"tests", "examples", "bench"}:
        return "test_or_example"
    if top == "tools":
        return "tools"
    return "prod_ext"


def build_token_index(
    repo_root: Path,
    pkg_rel: str,
) -> tuple[dict[str, dict[str, set[str]]], dict[str, int]]:
    """Indexes token occurrences by zone (`in_pkg`, `prod_ext`, `test_or_example`) and total count."""
    token_files: dict[str, dict[str, set[str]]] = {}
    in_pkg_counts: dict[str, int] = {}

    for gf in collect_repo_goose_files(repo_root):
        rel_p = rel_posix(gf, repo_root)
        zone = classify_file_zone(rel_p, pkg_rel)
        try:
            lines = gf.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        seen_in_file: set[str] = set()
        for line in lines:
            code = scrub_comments_and_strings(line)
            for tok in TOKEN_RE.findall(code):
                seen_in_file.add(tok)
                if zone == "in_pkg":
                    in_pkg_counts[tok] = in_pkg_counts.get(tok, 0) + 1

        for tok in seen_in_file:
            buckets = token_files.setdefault(
                tok,
                {"in_pkg": set(), "prod_ext": set(), "test_or_example": set(), "tools": set()},
            )
            buckets[zone].add(rel_p)

    return token_files, in_pkg_counts


def run_goose_lit_crap(target_dir: Path, repo_root: Path) -> dict[tuple[str, int], dict[str, Any]]:
    lit_bin = find_tool("goose-lit", "GOOSE_LIT_BIN")
    if lit_bin is None:
        return {}
    try:
        proc = subprocess.run(
            [lit_bin, "crap", str(target_dir), "--format", "json"],
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
    idx = stdout.find("\n{")
    if idx != -1:
        idx += 1
    elif stdout.lstrip().startswith("{"):
        idx = stdout.find("{")
    else:
        return {}

    try:
        payload = json.loads(stdout[idx:])
    except json.JSONDecodeError:
        return {}

    out: dict[tuple[str, int], dict[str, Any]] = {}
    items = payload.get("functions") or payload.get("items") or []
    for item in items:
        fpath = re.sub(r"^\./", "", str(item.get("file", "")).replace("\\", "/"))
        line = int(item.get("line", item.get("start_line", 0)) or 0)
        if fpath and line > 0:
            out[(fpath, line)] = {
                "gcrap_score": float(item.get("gcrap", item.get("gcrap_score", 0.0)) or 0.0),
                "eff_cc": int(item.get("eff_cc", item.get("cc", 1)) or 1),
                "uncovered_bce_keep": int(item.get("uncovered_bce_keep", 0) or 0),
            }
    return out


def detect_fn_signals(
    fn_name: str,
    signature: str,
    body_lines: list[str],
    crap_info: dict[str, Any] | None,
) -> list[str]:
    signals: list[str] = []
    joined = "\n".join(body_lines)

    sig_params = ""
    sig_ret = ""
    m_sig = re.search(r"\(([^)]*)\)\s*(?:->\s*([^{;]+))?", signature)
    if m_sig:
        sig_params = m_sig.group(1)
        sig_ret = (m_sig.group(2) or "").strip()

    if re.search(r"\bout(?:_[A-Za-z0-9_]+)?\s*:", sig_params):
        if re.search(r"out_[A-Za-z0-9_]*\s*:\s*u8\[\.\.\d+\]&", sig_params):
            signals.append("FIXED_CAP_OUT_BUF")
        elif re.search(r"out_[A-Za-z0-9_]*\s*:\s*(?:i32|i64|u32|u64)&", sig_params):
            signals.append("C_OUT_SCALAR_PARAM")
        elif not re.search(r"\bout\s*:\s*B&", sig_params):
            signals.append("C_OUT_PARAM")

    if re.search(r"^(?:i32|i64)$", sig_ret) and re.search(r"\breturn\s+-1\s*;", joined):
        signals.append("SENTINEL_MINUS_ONE")

    if re.match(r"^bool\s*,\s*[A-Za-z0-9_:]+", sig_ret):
        signals.append("TUPLE_BOOL_FIRST")

    if re.search(
        r":\s*bool(?:\s*=\s*(?:true|false))?\s*,\s*[A-Za-z0-9_]+\s*:\s*bool",
        sig_params,
    ):
        signals.append("BOOL_TRAP")

    if re.search(r"\bout(?:_[A-Za-z0-9_]+)?\.clear\s*\(", joined) and re.search(
        r"\bguard\b", joined
    ):
        clear_pos = joined.find(".clear(")
        guard_pos = joined.find("guard ")
        if 0 <= clear_pos < guard_pos:
            signals.append("OUT_MUTATION_BEFORE_GUARD")

    if re.search(
        r"\b[A-Za-z0-9_]+\s*>=\s*'A'\s*&&\s*[A-Za-z0-9_]+\s*<=\s*'Z'",
        joined,
    ) or re.search(
        r"\b[A-Za-z0-9_]+\s*>=\s*'0'\s*&&\s*[A-Za-z0-9_]+\s*<=\s*'9'",
        joined,
    ):
        signals.append("MANUAL_ASCII_LOOP")

    if re.search(r"\bfor\s+[A-Za-z0-9_]+\s+in\b", joined) and re.search(
        r"\[\s*[A-Za-z0-9_]+\s*\]\s*==\s*[A-Za-z0-9_.]+\[\s*[A-Za-z0-9_]+\s*\]",
        joined,
    ):
        signals.append("MANUAL_PREFIX_LOOP")

    if re.search(r"%\s*(?:2|4|8|16|32|64|128|256)\b", joined):
        signals.append("MODULO_POW2")

    if (
        re.search(r"\bfor\s+[A-Za-z0-9_]+\s+in\b", joined)
        and "for &" not in joined
        and re.search(r"\.\s*(?:entries|items|slots|records|cookies|streams)\b", joined)
    ):
        signals.append("VALUE_COPY_LOOP_CANDIDATE")

    if crap_info and crap_info.get("gcrap_score", 0.0) > 25.0:
        signals.append("HIGH_GCRAP")

    if len(body_lines) > 65 and re.search(r"\b(?:for|while)\b", joined):
        signals.append("LONG_LOOP_FN")

    for line in body_lines:
        if line.strip() and (len(line) - len(line.lstrip(" "))) >= 20:
            signals.append("DEEP_NESTING")
            break

    if (
        re.match(r"^(?:parse|decode|extract|scan)_", fn_name)
        and re.search(r"\b(?:idx|pos|offset|cursor)\s*:\s*(?:i64|u64|i32|u32)&", sig_params)
        and "idx" not in sig_params
    ):
        signals.append("NON_CANONICAL_CURSOR_NAME")

    return sorted(set(signals))


def analyze_package(
    pkg_dir: Path,
    repo_root: Path,
) -> dict[str, Any]:
    pkg_rel = rel_posix(pkg_dir, repo_root)
    pkg_name = pkg_rel.split("/")[0]
    token_files, in_pkg_counts = build_token_index(repo_root, pkg_rel)
    crap_map = run_goose_lit_crap(pkg_dir, repo_root)

    goose_files = sorted(
        p
        for p in pkg_dir.rglob("*.goose")
        if not any(part.startswith(".") for part in p.relative_to(pkg_dir).parts)
    )

    files_info: list[dict[str, Any]] = []
    functions: list[dict[str, Any]] = []
    structs: list[dict[str, Any]] = []
    enums: list[dict[str, Any]] = []
    consts: list[dict[str, Any]] = []
    globals_list: list[dict[str, Any]] = []
    type_aliases: list[dict[str, Any]] = []
    file_signals: list[dict[str, Any]] = []

    def ref_stats(name: str) -> dict[str, Any]:
        buckets = token_files.get(
            name, {"in_pkg": set(), "prod_ext": set(), "test_or_example": set(), "tools": set()}
        )
        prod_ext = sorted(buckets["prod_ext"])
        test_ext = sorted(buckets["test_or_example"])
        in_count = in_pkg_counts.get(name, 0)
        return {
            "in_pkg_tokens": in_count,
            "prod_ext_files": prod_ext,
            "test_ext_files": test_ext,
            "has_ext_refs": bool(prod_ext or test_ext),
        }

    for gf in goose_files:
        rel_file = rel_posix(gf, repo_root)
        raw_lines = gf.read_text(encoding="utf-8", errors="replace").splitlines()
        scrubbed = [scrub_comments_and_strings(line) for line in raw_lines]

        ns = ""
        imports_seen: dict[str, int] = {}
        dup_imports: list[str] = []

        for idx, sline in enumerate(scrubbed, start=1):
            m_ns = NAMESPACE_RE.match(sline)
            if m_ns and not ns:
                ns = m_ns.group(1)
            m_imp = IMPORT_RE.match(sline)
            if m_imp:
                imp_target = " ".join(m_imp.group(1).split())
                if imp_target in imports_seen:
                    dup_imports.append(f"{imp_target} (lines {imports_seen[imp_target]}, {idx})")
                else:
                    imports_seen[imp_target] = idx

        f_sigs: list[str] = []
        if ns == "wing" and pkg_name != "wing":
            f_sigs.append("MONOLITHIC_WING_NS")
        if dup_imports:
            f_sigs.append("DUPLICATE_IMPORT")
        if len(raw_lines) > 1500:
            f_sigs.append("LARGE_FILE")

        files_info.append(
            {
                "file": rel_file,
                "lines": len(raw_lines),
                "namespace": ns or "<none>",
                "duplicate_imports": dup_imports,
                "signals": f_sigs,
            }
        )
        if f_sigs:
            file_signals.append({"file": rel_file, "namespace": ns, "signals": f_sigs})

        n = len(raw_lines)
        i = 0
        depth = 0
        while i < n:
            sline = scrubbed[i]
            if depth == 0:
                m_fn = FN_START_RE.match(sline)
                m_ext = EXTERN_FN_RE.match(sline)
                m_st = STRUCT_START_RE.match(sline)
                m_en = ENUM_START_RE.match(sline)
                m_const = CONST_RE.match(sline)
                m_alias = TYPE_ALIAS_RE.match(sline)
                m_glob = GLOBAL_VAR_RE.match(sline)

                if m_ext:
                    fn_name = m_ext.group("name")
                    end_idx = i
                    while end_idx < n and ";" not in scrubbed[end_idx]:
                        end_idx += 1
                    sig = " ".join(x.strip() for x in raw_lines[i : min(end_idx + 1, n)])
                    functions.append(
                        {
                            "id": f"F{len(functions) + 1:04d}",
                            "file": rel_file,
                            "namespace": ns,
                            "name": fn_name,
                            "kind": "extern fn",
                            "start_line": i + 1,
                            "end_line": min(end_idx + 1, n),
                            "signature": sig,
                            "refs": ref_stats(fn_name),
                            "gcrap_score": 0.0,
                            "eff_cc": 1,
                            "signals": [],
                            "scrubbed_body": "",
                            "status": "planned",
                        }
                    )
                    i = min(end_idx + 1, n)
                    continue

                if m_fn:
                    fn_name = m_fn.group("name")
                    sig_end = i
                    while sig_end < n and "{" not in scrubbed[sig_end]:
                        sig_end += 1
                    sig = " ".join(x.strip() for x in raw_lines[i : min(sig_end + 1, n)])
                    if "{" in sig:
                        sig = sig[: sig.find("{")].strip()
                    bdepth = 0
                    started = False
                    end_idx = i
                    while end_idx < n:
                        sc = scrubbed[end_idx]
                        if "{" in sc:
                            started = True
                        bdepth += sc.count("{") - sc.count("}")
                        if started and bdepth <= 0:
                            break
                        end_idx += 1
                    end_idx = min(end_idx, n - 1)
                    crap_info = crap_map.get((rel_file, i + 1))
                    body_scrubbed = scrubbed[i : end_idx + 1]
                    sigs = detect_fn_signals(fn_name, sig, body_scrubbed, crap_info)
                    functions.append(
                        {
                            "id": f"F{len(functions) + 1:04d}",
                            "file": rel_file,
                            "namespace": ns,
                            "name": fn_name,
                            "kind": f"{m_fn.group('mods')}{m_fn.group('kw')}".strip(),
                            "start_line": i + 1,
                            "end_line": end_idx + 1,
                            "signature": sig,
                            "refs": ref_stats(fn_name),
                            "gcrap_score": crap_info["gcrap_score"] if crap_info else 0.0,
                            "eff_cc": crap_info["eff_cc"] if crap_info else 1,
                            "signals": sigs,
                            "scrubbed_body": "\n".join(body_scrubbed),
                            "status": "planned",
                        }
                    )
                    i = end_idx + 1
                    continue

                if m_st:
                    sname = m_st.group("name")
                    bdepth = 0
                    started = False
                    end_idx = i
                    fields: list[dict[str, Any]] = []
                    while end_idx < n:
                        sc = scrubbed[end_idx]
                        if "{" in sc:
                            started = True
                        elif started and bdepth == 1:
                            m_field = re.match(
                                r"^\s*([A-Za-z0-9_]+)\s*:\s*([^=,\n]+)",
                                sc,
                            )
                            if m_field:
                                fname = m_field.group(1)
                                ftype = m_field.group(2).strip()
                                f_ext = token_files.get(fname, {}).get("prod_ext", set()) | token_files.get(
                                    fname, {}
                                ).get("test_or_example", set())
                                f_in = in_pkg_counts.get(fname, 0)
                                f_sigs.clear()
                                if f_in <= 1 and not f_ext:
                                    f_sigs.append("UNUSED_FIELD")
                                fields.append(
                                    {
                                        "name": fname,
                                        "type": ftype,
                                        "line": end_idx + 1,
                                        "in_pkg_tokens": f_in,
                                        "ext_files": len(f_ext),
                                        "signals": f_sigs,
                                    }
                                )
                        bdepth += sc.count("{") - sc.count("}")
                        if started and bdepth <= 0:
                            break
                        end_idx += 1

                    field_names = {f["name"]: f for f in fields}
                    for f in fields:
                        if f["name"].endswith("_len"):
                            base = f["name"][:-4]
                            if base in field_names and "[.." in field_names[base]["type"]:
                                f["signals"].append("REDUNDANT_LEN_FIELD")

                    structs.append(
                        {
                            "id": f"S{len(structs) + 1:04d}",
                            "file": rel_file,
                            "namespace": ns,
                            "name": sname,
                            "start_line": i + 1,
                            "end_line": min(end_idx + 1, n),
                            "field_count": len(fields),
                            "fields": fields,
                            "refs": ref_stats(sname),
                            "status": "planned",
                        }
                    )
                    i = min(end_idx + 1, n)
                    continue

                if m_en:
                    ename = m_en.group("name")
                    bdepth = 0
                    started = False
                    end_idx = i
                    while end_idx < n:
                        sc = scrubbed[end_idx]
                        if "{" in sc:
                            started = True
                        bdepth += sc.count("{") - sc.count("}")
                        if started and bdepth <= 0:
                            break
                        end_idx += 1
                    enums.append(
                        {
                            "id": f"E{len(enums) + 1:04d}",
                            "file": rel_file,
                            "namespace": ns,
                            "name": ename,
                            "start_line": i + 1,
                            "end_line": min(end_idx + 1, n),
                            "refs": ref_stats(ename),
                            "status": "planned",
                        }
                    )
                    i = min(end_idx + 1, n)
                    continue

                if m_const:
                    cname = m_const.group("name")
                    consts.append(
                        {
                            "id": f"C{len(consts) + 1:04d}",
                            "file": rel_file,
                            "namespace": ns,
                            "name": cname,
                            "line": i + 1,
                            "refs": ref_stats(cname),
                        }
                    )
                elif m_alias:
                    aname = m_alias.group(1)
                    type_aliases.append(
                        {
                            "file": rel_file,
                            "namespace": ns,
                            "name": aname,
                            "line": i + 1,
                            "refs": ref_stats(aname),
                        }
                    )
                elif m_glob:
                    gname = m_glob.group("name")
                    globals_list.append(
                        {
                            "file": rel_file,
                            "namespace": ns,
                            "name": gname,
                            "line": i + 1,
                            "refs": ref_stats(gname),
                        }
                    )

            depth += sline.count("{") - sline.count("}")
            i += 1

    fn_names_set = {f["name"] for f in functions}
    roots = {
        f["name"]
        for f in functions
        if f["refs"]["has_ext_refs"]
        or f["name"] in {"main", "init"}
        or f["kind"] == "extern fn"
    }
    adj: dict[str, set[str]] = {fn: set() for fn in fn_names_set}
    for f in functions:
        body = f.pop("scrubbed_body", "")
        if not body:
            continue
        caller = f["name"]
        tokens = set(TOKEN_RE.findall(body))
        for callee in tokens & fn_names_set:
            if callee != caller:
                adj[caller].add(callee)

    reachable = set(roots)
    queue = list(roots)
    while queue:
        cur = queue.pop()
        for nxt in adj.get(cur, ()):
            if nxt not in reachable:
                reachable.add(nxt)
                queue.append(nxt)

    for f in functions:
        refs = f["refs"]
        if refs["in_pkg_tokens"] <= 1 and not refs["has_ext_refs"]:
            f["bucket"] = "DEAD_CANDIDATE"
        elif f["name"] not in reachable:
            f["bucket"] = "DEAD_ISLAND_OR_UNREACHABLE"
        elif not refs["has_ext_refs"]:
            f["bucket"] = "INTERNAL_CANDIDATE"
        else:
            f["bucket"] = "PUBLIC_API"

    for s in structs:
        refs = s["refs"]
        if refs["in_pkg_tokens"] <= 1 and not refs["has_ext_refs"]:
            s["bucket"] = "DEAD_CANDIDATE"
        elif not refs["has_ext_refs"]:
            s["bucket"] = "INTERNAL_CANDIDATE"
        else:
            s["bucket"] = "PUBLIC_API"

    return {
        "package": pkg_rel,
        "target_public_namespace": pkg_name,
        "target_internal_namespace": f"{pkg_name}_internal",
        "generated_at": time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()),
        "files": files_info,
        "file_signals": file_signals,
        "summary": {
            "total_files": len(files_info),
            "total_lines": sum(f["lines"] for f in files_info),
            "functions": len(functions),
            "structs": len(structs),
            "enums": len(enums),
            "consts": len(consts),
            "globals": len(globals_list),
            "type_aliases": len(type_aliases),
            "dead_fn_candidates": sum(1 for f in functions if f["bucket"] == "DEAD_CANDIDATE"),
            "dead_island_fns": sum(
                1 for f in functions if f["bucket"] == "DEAD_ISLAND_OR_UNREACHABLE"
            ),
            "internal_fn_candidates": sum(
                1 for f in functions if f["bucket"] == "INTERNAL_CANDIDATE"
            ),
            "public_api_fns": sum(1 for f in functions if f["bucket"] == "PUBLIC_API"),
            "unused_struct_fields": sum(
                1 for s in structs for fld in s["fields"] if "UNUSED_FIELD" in fld["signals"]
            ),
            "redundant_len_fields": sum(
                1
                for s in structs
                for fld in s["fields"]
                if "REDUNDANT_LEN_FIELD" in fld["signals"]
            ),
        },
        "functions": functions,
        "structs": structs,
        "enums": enums,
        "consts": consts,
        "globals": globals_list,
        "type_aliases": type_aliases,
    }


def default_out_dir(repo_root: Path, pkg_rel: str) -> Path:
    root_hash = hashlib.blake2b(repo_root.as_posix().encode("utf-8"), digest_size=4).hexdigest()
    safe_pkg = pkg_rel.replace("/", "_")
    return Path(tempfile.gettempdir()) / "goose-refactor" / f"{repo_root.name}_{root_hash}" / safe_pkg


def cmd_scan(args: argparse.Namespace) -> int:
    target = Path(args.target_path).resolve()
    if not target.exists():
        print(f"[ERROR] Target path not found: {target}", file=sys.stderr)
        return 1
    repo_root = find_repo_root(target)
    pkg_rel = rel_posix(target, repo_root)

    report = analyze_package(target, repo_root)

    out_dir = Path(args.out_dir).resolve() if args.out_dir else default_out_dir(repo_root, pkg_rel)
    out_dir.mkdir(parents=True, exist_ok=True)

    ledger_path = out_dir / "refactor-ledger.json"
    ledger_path.write_text(json.dumps(report, indent=2) + "\n", encoding="utf-8", newline="\n")

    mig_path = out_dir / "api-migration-map.json"
    if not mig_path.exists():
        mig_template = {
            "package": pkg_rel,
            "target_public_namespace": report["target_public_namespace"],
            "target_internal_namespace": report["target_internal_namespace"],
            "symbol_renames": [],
            "signature_changes": [],
            "removed_public_symbols": [],
            "external_files_impacted": sorted(
                {
                    ef
                    for f in report["functions"]
                    if f["bucket"] == "PUBLIC_API"
                    for ef in (f["refs"]["prod_ext_files"] + f["refs"]["test_ext_files"])
                }
                | {
                    ef
                    for s in report["structs"]
                    if s["bucket"] == "PUBLIC_API"
                    for ef in (s["refs"]["prod_ext_files"] + s["refs"]["test_ext_files"])
                }
            ),
        }
        mig_path.write_text(
            json.dumps(mig_template, indent=2) + "\n", encoding="utf-8", newline="\n"
        )

    print(
        json.dumps(
            {
                "status": "ok",
                "ledger": rel_posix(ledger_path, repo_root),
                "migration_template": rel_posix(mig_path, repo_root),
                "summary": report["summary"],
            },
            indent=2,
        )
    )
    return 0


def cmd_validate(args: argparse.Namespace) -> int:
    target = Path(args.target_path).resolve()
    if not target.exists():
        print(f"[ERROR] Target path not found: {target}", file=sys.stderr)
        return 1
    repo_root = find_repo_root(target)
    pkg_rel = rel_posix(target, repo_root)
    lint_script = repo_root / "scripts" / "lint_invariants.py"

    goose_files = sorted(
        p
        for p in target.rglob("*.goose")
        if not any(part.startswith(".") for part in p.relative_to(target).parts)
    )
    failures: list[str] = []

    goose_bin = find_tool("goose", "GOOSE_BIN")
    if goose_bin:
        fmt = subprocess.run(
            [goose_bin, "format", "--check", str(target)],
            cwd=str(repo_root),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            check=False,
        )
        if fmt.returncode != 0:
            failures.append(f"goose format --check failed:\n{fmt.stdout}{fmt.stderr}")

    if lint_script.exists():
        for gf in goose_files:
            res = subprocess.run(
                [sys.executable, str(lint_script), "--target-file", str(gf), "--check-dead-code"],
                cwd=str(repo_root),
                capture_output=True,
                text=True,
                encoding="utf-8",
                errors="replace",
                check=False,
            )
            if res.returncode != 0:
                failures.append(f"lint_invariants failed on {rel_posix(gf, repo_root)}:\n{res.stdout}")

    if args.ledger:
        lp = Path(args.ledger).resolve()
        if not lp.exists():
            failures.append(f"Missing ledger: {lp}")
        else:
            data = json.loads(lp.read_text(encoding="utf-8"))
            unreviewed = [
                f["name"]
                for f in data.get("functions", [])
                if f.get("status") not in {"refactored", "deleted", "kept"}
            ]
            if unreviewed:
                failures.append(
                    f"Unreviewed functions in ledger ({len(unreviewed)}): {unreviewed[:15]}"
                )

    if args.migration:
        mp = Path(args.migration).resolve()
        if not mp.exists():
            failures.append(f"Missing migration map: {mp}")
        else:
            mdata = json.loads(mp.read_text(encoding="utf-8"))
            for key in ("symbol_renames", "signature_changes", "removed_public_symbols"):
                if not isinstance(mdata.get(key), list):
                    failures.append(f"Migration map key '{key}' must be a list")

    if failures:
        print(json.dumps({"status": "failed", "package": pkg_rel, "failures": failures}, indent=2))
        return 1

    print(
        json.dumps(
            {"status": "passed", "package": pkg_rel, "files_checked": len(goose_files)},
            indent=2,
        )
    )
    return 0


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="goose_refactor_scanner.py",
        description="Cross-platform deterministic scanner and validation gate for package-level Goose refactoring.",
    )
    sub = parser.add_subparsers(dest="subcommand")

    p_scan = sub.add_parser("scan", help="Inventory package symbols, refs, dead islands, and signals.")
    p_scan.add_argument("target_path", help="Package directory to scan (e.g., dns, auth).")
    p_scan.add_argument(
        "--out-dir",
        default="",
        help="Output directory for ledger and migration map (defaults to OS temp dir).",
    )

    p_val = sub.add_parser("validate", help="Run format, lint_invariants, ledger, and migration checks.")
    p_val.add_argument("target_path", help="Refactored package directory.")
    p_val.add_argument("--ledger", default="", help="Path to updated refactor-ledger.json.")
    p_val.add_argument("--migration", default="", help="Path to updated api-migration-map.json.")

    return parser


def main(argv: list[str] | None = None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.subcommand == "scan":
        return cmd_scan(args)
    if args.subcommand == "validate":
        return cmd_validate(args)
    parser.print_help(sys.stderr)
    return 1


if __name__ == "__main__":
    sys.exit(main())
