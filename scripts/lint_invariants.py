#!/usr/bin/env python3
# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""scripts/lint_invariants.py.

Automated static enforcement of engineering clarity, anti-aliasing (zero pass-through wrappers),
expanded input/output contracts (// Example:), zero-alloc loop invariants, formatting geometry,
and linear git history.
"""

import argparse
import os
import re
import subprocess
import sys
from pathlib import Path


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
    parser = argparse.ArgumentParser(description="Static invariant linter for goose-wing")
    parser.add_argument("--target-file", type=str, default="", help="Single file to check")
    parser.add_argument("--staged", action="store_true", help="Inspect git staged files")
    parser.add_argument(
        "--strict-examples",
        action="store_true",
        help="Enforce // Example: input/output contracts",
    )
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    violations = 0

    # 1. Enforce Linear Git History (Reject active merge commits)
    merge_head = root / ".git" / "MERGE_HEAD"
    if merge_head.exists():
        print_colored(
            "[LINT REJECTED] Linear history violation: .git/MERGE_HEAD detected. "
            "Merge commits are prohibited; use rebase or fast-forward.",
            "red",
        )
        return 1

    # 2. Collect files to inspect
    files_to_scan: list[Path] = []
    if args.target_file:
        target_path = Path(args.target_file)
        if not target_path.is_absolute():
            target_path = root / target_path
        if target_path.exists():
            files_to_scan.append(target_path.resolve())
    elif args.staged:
        try:
            res = subprocess.run(
                ["git", "diff", "--cached", "--name-only", "--diff-filter=ACM"],
                cwd=root,
                capture_output=True,
                text=True,
                check=True,
            )
            for line in res.stdout.splitlines():
                f = line.strip()
                if f.endswith(".goose"):
                    full_p = (root / f).resolve()
                    if full_p.exists():
                        files_to_scan.append(full_p)
        except subprocess.SubprocessError:
            pass
    else:
        for p in root.rglob("*.goose"):
            s_path = str(p)
            if any(
                bad in s_path
                for bad in [
                    f"{os.sep}vendor{os.sep}",
                    f"{os.sep}scratch{os.sep}",
                    f"{os.sep}.gemini{os.sep}",
                    f"{os.sep}.git{os.sep}",
                    f"{os.sep}bin{os.sep}",
                    f"{os.sep}build{os.sep}",
                ]
            ):
                continue
            files_to_scan.append(p.resolve())

    ai_buzzwords = re.compile(
        r"\b(crucial|robust|seamlessly|comprehensive|delve|meticulously|pivotal|game-changer|plethora|tapestry|leverage)\b",
        re.IGNORECASE,
    )
    robotic_noise = re.compile(r"\b(does not panic|will not panic|never panics)\b", re.IGNORECASE)
    incomplete_markers = re.compile(
        r"\b(TODO|FIXME|HACK|XXX)\b|simplified for now|placeholder implementation"
    )

    for file_path in files_to_scan:
        try:
            rel_path = file_path.relative_to(root).as_posix()
        except ValueError:
            rel_path = file_path.as_posix()

        is_test_or_example = bool(
            re.match(r"^(tests|examples|bench|tools|core/test)/", rel_path)
            or rel_path.endswith("_test.goose")
        )

        try:
            content = file_path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue

        lines = content.splitlines()

        # Count function name occurrences in file to distinguish polymorphic overloads
        fn_counts: dict[str, int] = {}
        for ln in lines:
            m = re.match(r"^\s*(?:pub\s+)?(?:inline\s+)?fn\s+([A-Za-z0-9_]+)", ln)
            if m:
                name = m.group(1)
                fn_counts[name] = fn_counts.get(name, 0) + 1

        consecutive_blank_lines = 0
        in_function = False
        fn_start_line = 0
        fn_name = ""
        fn_brace_depth = 0
        fn_has_loop = False
        in_loop = False
        loop_brace_depth = 0
        in_wire_struct = False
        wire_struct_name = ""
        wire_struct_depth = 0

        for i, line in enumerate(lines):
            line_num = i + 1

            # Check: Consecutive blank lines & brace blank line hygiene
            if line.strip() == "":
                consecutive_blank_lines += 1
                if consecutive_blank_lines >= 2:
                    print_colored(
                        f"[LINT] {rel_path}:{line_num} -> Multiple consecutive blank lines. "
                        f"Keep vertical rhythm to at most 1 blank line.",
                        "yellow",
                    )
                    violations += 1
                if (
                    not is_test_or_example
                    and in_function
                    and i > (fn_start_line - 1)
                    and re.search(r"\{\s*$", lines[i - 1].strip())
                ):
                    print_colored(
                        f"[LINT] {rel_path}:{line_num} -> Blank line immediately after opening brace '{{' prohibited.",
                        "yellow",
                    )
                    violations += 1
            else:
                consecutive_blank_lines = 0
                if (
                    not is_test_or_example
                    and in_function
                    and line.strip() == "}"
                    and i > 0
                    and lines[i - 1].strip() == ""
                ):
                    print_colored(
                        f"[LINT] {rel_path}:{line_num} -> Blank line immediately before closing brace '}}' prohibited.",
                        "yellow",
                    )
                    violations += 1

            # Check: Tab characters (\t)
            if "\t" in line:
                print_colored(
                    f"[LINT] {rel_path}:{line_num} -> Tab character '\\t' detected. Use strictly 4 spaces per indentation level.",
                    "red",
                )
                violations += 1

            # Check: Trailing whitespace
            if re.search(r"[ \t]+$", line):
                print_colored(
                    f"[LINT] {rel_path}:{line_num} -> Trailing whitespace detected.",
                    "yellow",
                )
                violations += 1

            # Check: Hard line length ceiling (120 columns)
            if not is_test_or_example and len(line) > 120:
                is_exempt = bool(
                    "http://" in line
                    or "https://" in line
                    or re.search(r"//\s*(CHECK|RUN):", line)
                    or re.search(r'"[^"]{35,}"', line)
                    or re.search(r"^\s*//\s*(RFC|Vector|Table|https?://)", line)
                )
                if not is_exempt:
                    print_colored(
                        f"[LINT] {rel_path}:{line_num} -> Line exceeds hard ceiling of 120 columns ({len(line)} chars). Break expressions or invert guards.",
                        "yellow",
                    )
                    violations += 1

            # Rule 1: Pass-through function alias detection
            fn_alias_match = re.match(
                r"^\s*(?:pub\s+)?(?:inline\s+)?fn\s+([A-Za-z0-9_]+)\s*\(([^)]*)\)", line
            )
            if fn_alias_match:
                cur_fn = fn_alias_match.group(1)
                raw_params = fn_alias_match.group(2).strip()
                is_overload = fn_counts.get(cur_fn, 0) > 1
                is_container_trait = cur_fn in ("append", "push", "clear", "reset", "do")

                if not is_overload and not is_container_trait:
                    param_names = []
                    if raw_params:
                        for p in raw_params.split(","):
                            p_trim = p.strip()
                            pm = re.match(r"^([A-Za-z0-9_]+)\s*:", p_trim)
                            if pm:
                                param_names.append(pm.group(1))
                    expected_args = ", ".join(param_names)

                    callee = ""
                    call_args = ""
                    single_call_match = re.search(
                        r"\{\s*(?:return\s+)?([A-Za-z0-9_:]+)\s*\(([^)]*)\)\s*;\s*\}",
                        line,
                    )
                    if single_call_match:
                        callee = single_call_match.group(1)
                        call_args = ", ".join(
                            a.strip() for a in single_call_match.group(2).split(",")
                        )
                    elif (i + 2) < len(lines) and re.search(r"\{\s*$", line):
                        next_line = lines[i + 1].strip()
                        close_line = lines[i + 2].strip()
                        if close_line == "}":
                            multiline_call_match = re.match(
                                r"^(?:return\s+)?([A-Za-z0-9_:]+)\s*\(([^)]*)\)\s*;$",
                                next_line,
                            )
                            if multiline_call_match:
                                callee = multiline_call_match.group(1)
                                call_args = ", ".join(
                                    a.strip() for a in multiline_call_match.group(2).split(",")
                                )

                    if (
                        callee
                        and not re.match(r"^(native_|wing_)", callee)
                        and len(param_names) > 0
                        and call_args == expected_args
                        and callee != cur_fn
                    ):
                        print_colored(
                            f"[LINT] {rel_path}:{line_num} -> Meaningless pass-through function alias '{cur_fn}' "
                            f"simply calls '{callee}({call_args})' with identical arguments.",
                            "red",
                        )
                        violations += 1

            # Rule 1b: Redundant 0-arg struct constructor wrapper detection
            empty_ctor_match = re.match(
                r"^\s*(?:pub\s+)?(?:inline\s+)?fn\s+([A-Za-z0-9_]+)\s*\(\s*\)\s*->\s*([A-Za-z0-9_:]+)",
                line,
            )
            if empty_ctor_match:
                cur_fn = empty_ctor_match.group(1)
                ret_type = empty_ctor_match.group(2)
                base_ret = ret_type.split(":")[-1]

                struct_constructed = ""
                single_ret_match = re.search(
                    r"\{\s*(?:return\s+)?([A-Za-z0-9_:]+)\s*\{\s*\.\.\s*\}\s*;\s*\}",
                    line,
                )
                if single_ret_match:
                    struct_constructed = single_ret_match.group(1).split(":")[-1]
                elif (i + 2) < len(lines) and re.search(r"\{\s*$", line):
                    next_line = lines[i + 1].strip()
                    close_line = lines[i + 2].strip()
                    if close_line == "}":
                        m_ret = re.match(
                            r"^(?:return\s+)?([A-Za-z0-9_:]+)\s*\{\s*\.\.\s*\}\s*;$",
                            next_line,
                        )
                        if m_ret:
                            struct_constructed = m_ret.group(1).split(":")[-1]

                if struct_constructed and struct_constructed == base_ret:
                    print_colored(
                        f"[LINT] {rel_path}:{line_num} -> Redundant 0-arg struct constructor wrapper '{cur_fn}' "
                        f"merely returns '{base_ret} {{ .. }}'. Use native struct default syntax directly at call sites.",
                        "red",
                    )
                    violations += 1

            # Rule 2: No primitive or slice type aliases
            m_type = re.match(
                r"^\s*type\s+([A-Za-z0-9_]+)\s*=\s*(?:const\s+)?(u8|u16|u32|u64|i8|i16|i32|i64|bool|f32|f64|usize|isize)(\[.*\])?",
                line,
            )
            if m_type:
                print_colored(
                    f"[LINT] {rel_path}:{line_num} -> Redundant primitive/slice type alias '{m_type.group(1)}'. "
                    f"Use canonical Goose types directly.",
                    "red",
                )
                violations += 1

            # Rule 3: No import namespace aliasing
            m_imp = re.match(r"^\s*import\s+[A-Za-z0-9_.]+\s+as\s+([A-Za-z0-9_]+)", line)
            if m_imp:
                print_colored(
                    f"[LINT] {rel_path}:{line_num} -> Namespace alias 'as {m_imp.group(1)}' prohibited.",
                    "red",
                )
                violations += 1

            # Rule 4: No deprecated prefix extern syntax
            if re.match(r'^\s*extern\s+"[^"]+"\s+fn\s+', line):
                print_colored(
                    f"[LINT] {rel_path}:{line_num} -> Deprecated prefix extern syntax. "
                    f'Place symbol after signature: extern fn foo() = "sym";',
                    "red",
                )
                violations += 1

            # Rule 5: Comment hygiene
            m_comment = re.search(r"//(.*)$", line)
            if m_comment:
                c_text = m_comment.group(1)
                m_buzz = ai_buzzwords.search(c_text)
                if m_buzz:
                    print_colored(
                        f"[LINT] {rel_path}:{line_num} -> Banned AI buzzword '{m_buzz.group(1)}' in comment.",
                        "red",
                    )
                    violations += 1
                m_noise = robotic_noise.search(c_text)
                if m_noise:
                    print_colored(
                        f"[LINT] {rel_path}:{line_num} -> Robotic noise '{m_noise.group(1)}' in comment. "
                        f"Only document failure conditions, not absence of panics.",
                        "red",
                    )
                    violations += 1
                if not is_test_or_example:
                    m_inc = incomplete_markers.search(c_text)
                    if m_inc:
                        print_colored(
                            f"[LINT] {rel_path}:{line_num} -> Incomplete code marker ('{m_inc.group(0)}') prohibited in production modules.",
                            "red",
                        )
                        violations += 1

            # Multi-line function signature reconstruction
            is_fn_start = bool(
                re.match(r"^\s*(?:pub\s+)?(?:inline\s+)?fn\s+([A-Za-z0-9_:]+)", line)
                and not re.match(r"^\s*extern\b", line)
            )
            sig_fn_name = ""
            sig_params = ""
            sig_ret = ""
            is_multiline_sig = False

            if is_fn_start:
                sig_lines = []
                sig_end_idx = i
                for s in range(i, min(len(lines), i + 20)):
                    cur_clean = re.sub(r"//.*$", "", lines[s]).strip()
                    sig_lines.append(cur_clean)
                    if "{" in lines[s] or ";" in lines[s]:
                        sig_end_idx = s
                        break
                joined_sig = " ".join(sig_lines)
                m_jsig = re.match(
                    r"^\s*(?:pub\s+)?(?:inline\s+)?fn\s+(?:::)?([A-Za-z0-9_]+)(?:<[^>]+>)?\s*\(([^)]*)\)\s*(?:->\s*([^\{;]+))?",
                    joined_sig,
                )
                if m_jsig:
                    sig_fn_name = m_jsig.group(1)
                    sig_params = m_jsig.group(2)
                    sig_ret = m_jsig.group(3).strip() if m_jsig.group(3) else ""
                    is_multiline_sig = sig_end_idx > i

            # Rule 1e: Prohibition of mechanical function names
            if is_fn_start and re.match(
                r"^(add|sub|mul|div|inc|dec)_(one|two|three|four|five|ten|\d+|by_\w+)$",
                sig_fn_name,
            ):
                print_colored(
                    f"[LINT] {rel_path}:{line_num} -> Mechanical function name '{sig_fn_name}' prohibited. "
                    f"Name helper after the protocol domain invariant.",
                    "red",
                )
                violations += 1

            # Rule 3: Boolean trap detection (consecutive bool parameters)
            if (
                not is_test_or_example
                and is_fn_start
                and re.search(
                    r":\s*bool(?:\s*=\s*(?:true|false))?\s*,\s*[A-Za-z0-9_]+\s*:\s*bool",
                    sig_params,
                )
            ):
                print_colored(
                    f"[LINT] {rel_path}:{line_num} -> Boolean trap in function '{sig_fn_name}': "
                    f"consecutive 'bool' parameters detected. Use an enum, struct, or domain slice.",
                    "red",
                )
                violations += 1

            # Geometry Rule 1c: Single-line signature parameter overflow
            if not is_test_or_example and is_fn_start and not is_multiline_sig and len(line) > 100:
                p_count = len(sig_params.split(",")) if sig_params else 0
                if p_count >= 5:
                    print_colored(
                        f"[LINT] {rel_path}:{line_num} -> Single-line signature for '{sig_fn_name}' "
                        f"has {p_count} parameters and exceeds 100 columns ({len(line)} chars). "
                        f"Place each parameter on its own 4-space indented line.",
                        "yellow",
                    )
                    violations += 1

            # Rule 6: Expanded // Example: Input/Output Contract Coverage
            if args.strict_examples and not is_test_or_example and is_fn_start and sig_fn_name:
                is_exempt = bool(
                    re.match(
                        r"^(new_|is_|has_|get_|set_|len|cap|clear|reset|init_|alloc_)",
                        sig_fn_name,
                    )
                    or sig_fn_name in ("append", "push", "clear", "reset", "do", "next")
                )
                if not is_exempt:
                    needs_example = False
                    reason = ""

                    # Category A: Advances a wire cursor or SliceReader
                    if re.search(
                        r"\b(idx|pos|offset)\s*:\s*(i64|u64|usize|i32|u32)&",
                        sig_params,
                    ) or re.search(
                        r"\b(r|rd|reader|sr)\s*:\s*(?:core::)?(?:SliceReader|WireReader)&",
                        sig_params,
                    ):
                        needs_example = True
                        reason = "advances a wire cursor or SliceReader"
                    # Category B: Consumes a wire slice and returns (consumed_len, bool) or (token, bool)
                    elif re.search(
                        r"\b(s|raw|buf|src|input)\s*:\s*(?:const\s+)?u8\[:\]",
                        sig_params,
                    ) and (
                        re.search(r"\b(i64|u64|usize|i32|u32)\s*,\s*bool", sig_ret)
                        or re.search(r"(?:const\s+)?u8\[:\]\s*,\s*bool", sig_ret)
                    ):
                        needs_example = True
                        reason = "consumes a wire slice and returns (consumed_len, bool)"
                    # Category C: RFC grammar parsers, decoders, and extractors
                    elif re.match(r"^(parse|decode|extract|scan)_", sig_fn_name):
                        needs_example = True
                        reason = "parses wire tokens or RFC grammar"
                    # Category D: Wire transformers, sanitizers, and bitmask builders
                    elif re.match(r"^(unescape|escape|sanitize)_", sig_fn_name) or re.match(
                        r"^build_.*_type", sig_fn_name
                    ):
                        needs_example = True
                        reason = "transforms wire tokens or builds wire type bitmasks"

                    if needs_example:
                        has_example = False
                        lookback = max(0, i - 15)
                        for k in range(lookback, i):
                            if re.search(r"//\s*Example(?:s)?:?", lines[k]):
                                has_example = True
                                break
                        if not has_example:
                            print_colored(
                                f"[LINT] {rel_path}:{line_num} -> Function '{sig_fn_name}' {reason} "
                                f"but is missing an input/output contract block ('// Example:').",
                                "yellow",
                            )
                            violations += 1

            # Rule 9: Prohibition of intermediate out-parameters for pure computations
            if not is_test_or_example and is_fn_start:
                m_out = re.search(
                    r"out_[a-zA-Z0-9_]*(?:hex|ha\d+|response_hex)\s*:\s*[^,)]+&",
                    sig_params,
                )
                if m_out:
                    print_colored(
                        f"[LINT] {rel_path}:{line_num} -> C-style intermediate out-parameter '{m_out.group(0)}' "
                        f"prohibited in '{sig_fn_name}'. Return value directly via RVO ('-> u8[..N]').",
                        "red",
                    )
                    violations += 1

            # Rule 10: Prohibition of artificial slice/cursor wrappers in parsers
            if (
                not is_test_or_example
                and is_fn_start
                and re.match(r"^(parse|decode|demux)_", sig_fn_name)
            ):
                m_wrap = re.search(
                    r"\b([A-Za-z0-9_]+:\s*(?:core::)?(?:SliceReader|ByteCursor|WireReader)&)",
                    sig_params,
                )
                if m_wrap and not re.match(r"^(core/io|quic/frames)\.goose$", rel_path):
                    print_colored(
                        f"[LINT] {rel_path}:{line_num} -> Parser '{sig_fn_name}' takes artificial cursor wrapper '{m_wrap.group(1)}'. "
                        f"Lingua franca is 'const u8[:]' with 'idx: i64&'.",
                        "red",
                    )
                    violations += 1

            # Rule 11: Timing side-channel detector on secret/tag comparisons
            if not is_test_or_example and not re.match(r"^\s*//", line):
                code_only = re.sub(r"//.*$", "", line)
                if (
                    re.search(
                        r"\b(expected_hash|computed_hash|expected_mac|computed_mac|hmac_tag|auth_tag|expected_digest|verify_tag)\s*(?:\[\.\.\])?\s*(==|!=)",
                        code_only,
                    )
                    or re.search(
                        r"(==|!=)\s*(expected_hash|computed_hash|expected_mac|computed_mac|hmac_tag|auth_tag|expected_digest|verify_tag)\b",
                        code_only,
                    )
                ) and not re.search(r"\.len\s*(==|!=)", code_only):
                    print_colored(
                        f"[LINT] {rel_path}:{line_num} -> Potential timing side-channel: "
                        f"direct '=='/'!=' on cryptographic tag/digest. Use 'core::ct_eq_bytes'.",
                        "red",
                    )
                    violations += 1

            # Rule 12: Wire struct zero-copy layout
            if not is_test_or_example:
                m_wstruct = re.match(
                    r"^\s*(?:pub\s+)?struct\s+([A-Za-z0-9_]*(?:Frame|Packet|WireHeader))\s*\{",
                    line,
                )
                if m_wstruct:
                    in_wire_struct = True
                    wire_struct_name = m_wstruct.group(1)
                    wire_struct_depth = 1
                elif in_wire_struct:
                    if "{" in line:
                        wire_struct_depth += line.count("{")
                    if "}" in line:
                        wire_struct_depth -= line.count("}")
                        if wire_struct_depth <= 0:
                            in_wire_struct = False
                    if in_wire_struct and ": u8[>..]" in line:
                        print_colored(
                            f"[LINT] {rel_path}:{line_num} -> Dynamic heap vector 'u8[>..]' inside wire struct '{wire_struct_name}'. "
                            f"Use zero-copy slice 'const u8[:]' or stack-bounded 'u8[..N]'.",
                            "red",
                        )
                        violations += 1

            # Rule 13: Zero silent buffer drops (if len <= cap without else/error branch)
            if not is_test_or_example and not re.match(r"^\s*//", line):
                code_only_13 = re.sub(r"//.*$", "", line)
                if re.match(
                    r"^\s*if\s+[^{]*\b[A-Za-z0-9_.]+\.len\b[^{]*<=\s*[A-Za-z0-9_.]+\.cap\b\s*\{",
                    code_only_13,
                ) or re.match(
                    r"^\s*if\s+[^{]*\b[A-Za-z0-9_.]+\.len\b[^{]*<\s*[A-Za-z0-9_.]+\.cap\b\s*\{",
                    code_only_13,
                ):
                    if_depth = code_only_13.count("{") - code_only_13.count("}")
                    has_else_or_return = "return " in code_only_13 or "else" in code_only_13
                    scan_idx = i + 1
                    while scan_idx < len(lines) and if_depth > 0 and scan_idx < i + 25:
                        scan_line = re.sub(r"//.*$", "", lines[scan_idx])
                        if "return " in scan_line or "break" in scan_line:
                            has_else_or_return = True
                        if if_depth == 1 and re.search(r"\}\s*else\b", scan_line):
                            has_else_or_return = True
                            break
                        if_depth += scan_line.count("{") - scan_line.count("}")
                        if if_depth <= 0:
                            if "else" in scan_line:
                                has_else_or_return = True
                            elif scan_idx + 1 < len(lines):
                                next_clean = re.sub(r"//.*$", "", lines[scan_idx + 1]).strip()
                                if next_clean.startswith("else"):
                                    has_else_or_return = True
                            break
                        scan_idx += 1
                    if not has_else_or_return:
                        print_colored(
                            f"[LINT] {rel_path}:{line_num} -> Silent capacity overflow drop ('if ... <= ...cap' without 'else' error branch). "
                            f"Use 'guard ... <= ...cap else {{ return ..., false; }}' or handle overflow explicitly.",
                            "red",
                        )
                        violations += 1

            # Rule 14: Prohibition of naive substring searching on structured wire formats (JSON/JWT/headers)
            if not is_test_or_example and not re.match(r"^\s*//", line):
                code_only_14 = re.sub(r"//.*$", "", line)
                if re.search(
                    r'\b(?:index_of_slice|contains)\s*\([^)]*\\"[^)]*\\"',
                    code_only_14,
                ) or re.search(
                    r"\b(?:index_of_slice|contains)\s*\(\s*(?:json|payload_json|claims_json|raw_json|jwt_payload|jwk_json)\b",
                    code_only_14,
                ):
                    print_colored(
                        f"[LINT] {rel_path}:{line_num} -> Naive substring search on structured JSON/wire payload prohibited. "
                        f"Use 'json::reader' or a structured tokenizer to prevent injection and escaped-quote bugs.",
                        "red",
                    )
                    violations += 1

            # Rule 15: Exhaustive enum parsing (prohibit defaulting unknown strings to valid operational variants)
            if (
                not is_test_or_example
                and is_fn_start
                and re.match(r"^(?:parse|str_to)_[A-Za-z0-9_]+$", sig_fn_name)
                and not sig_fn_name.endswith("_unverified")
                and re.search(r"u8\[:\]", sig_params)
                and re.match(r"^[A-Z][A-Za-z0-9_]*$", sig_ret)
                and not sig_ret.endswith("Error")
            ):
                enum_type = sig_ret
                f_depth = 0
                f_started = False
                last_ret_variant = ""
                for s_idx in range(i, min(len(lines), i + 80)):
                    s_clean = re.sub(r"//.*$", "", lines[s_idx])
                    if "{" in s_clean:
                        f_started = True
                    f_depth += s_clean.count("{") - s_clean.count("}")
                    m_ret_enum = re.search(
                        rf"\breturn\s+{re.escape(enum_type)}\.([A-Za-z0-9_]+)\s*;",
                        s_clean,
                    )
                    if m_ret_enum:
                        last_ret_variant = m_ret_enum.group(1)
                    if f_started and f_depth <= 0:
                        break
                if last_ret_variant and last_ret_variant not in (
                    "Unknown",
                    "Invalid",
                    "None",
                    "Unsupported",
                    "Other",
                    "Custom",
                ):
                    print_colored(
                        f"[LINT] {rel_path}:{line_num} -> Enum parser '{sig_fn_name}' defaults unrecognized input to operational variant "
                        f"'{enum_type}.{last_ret_variant}'. Return '{enum_type}.Unknown' or '({enum_type}, bool)'.",
                        "red",
                    )
                    violations += 1

            # Rule 17: Enterprise-scale buffer limits over toy RFC examples
            if not is_test_or_example and not re.match(r"^\s*//", line):
                code_only_17 = re.sub(r"//.*$", "", line)
                m_toy_buf = re.search(
                    r"\b(auth_header|bearer_buf|token_buf|jwt_buf|dpop_buf|proof_buf|access_token|id_token)\s*:\s*u8\[\.\.(\d+)\]",
                    code_only_17,
                )
                if m_toy_buf:
                    buf_name = m_toy_buf.group(1)
                    buf_cap = int(m_toy_buf.group(2))
                    if buf_cap < 1024:
                        print_colored(
                            f"[LINT] {rel_path}:{line_num} -> Miniature auth buffer '{buf_name}: u8[..{buf_cap}]' (< 1024 bytes). "
                            f"Enterprise JWTs and auth headers require >= 2048..4096 bytes.",
                            "red",
                        )
                        violations += 1

            # Track Function Geometry, Nesting Depth, and Zero Heap Allocation in Loops
            m_fn_entry = re.match(r"^\s*(?:pub\s+)?(?:inline\s+)?fn\s+([A-Za-z0-9_]+)", line)
            if m_fn_entry:
                in_function = True
                fn_start_line = line_num
                fn_name = m_fn_entry.group(1)
                fn_brace_depth = 0
                fn_has_loop = False
                in_loop = False
                loop_brace_depth = 0

            if in_function:
                # Check Nesting Depth Ceiling (maximum 3 levels, indentation <= 16 spaces from col 0)
                if not is_test_or_example and line.strip() != "" and not re.match(r"^\s*//", line):
                    indent = len(line) - len(line.lstrip(" "))
                    if indent >= 20:
                        print_colored(
                            f"[LINT] {rel_path}:{line_num} -> Excessive nesting depth (indented {indent} spaces >= 20). "
                            f"Maximum allowed nesting is 3 levels (16 spaces). Flatten with guard clauses.",
                            "red",
                        )
                        violations += 1

                # Check loop start
                if re.match(r"^\s*(while|for)\b", line):
                    fn_has_loop = True
                    in_loop = True
                    loop_brace_depth = fn_brace_depth

                # Check Zero Heap Allocation in Loops
                if (
                    not is_test_or_example
                    and in_loop
                    and re.match(
                        r"^\s*var\s+[A-Za-z0-9_]+\s*:\s*[A-Za-z0-9_]*\[>\.\.\]",
                        line,
                    )
                ):
                    print_colored(
                        f"[LINT] {rel_path}:{line_num} -> Dynamic heap allocation inside loop ('var ...: ...[>..]'). "
                        f"Hoist buffer outside loop and call .clear().",
                        "red",
                    )
                    violations += 1

                # Rule 16: Stateful entropy in pseudo-random and identifier generators
                if (
                    not is_test_or_example
                    and re.match(
                        r"^(?:generate|create|new|next|make|build)_.*(?:jti|nonce|cnonce|id|token|rand|uuid|secret|challenge|salt)\b",
                        fn_name,
                    )
                    and re.match(
                        r"^\s*var\s+(?:state|seed|rng|prng|lcg_state)[A-Za-z0-9_]*\s*:\s*(?:u64|u32|i64|usize)\s*=\s*(?:0x[0-9a-fA-F_]+|\d+)\s*;",
                        re.sub(r"//.*$", "", line),
                    )
                ):
                    print_colored(
                        f"[LINT] {rel_path}:{line_num} -> Constant local PRNG state inside generator '{fn_name}' "
                        f"produces identical output on every call. Mix 'clock_ns()' or pass mutable 'Rng&' state.",
                        "red",
                    )
                    violations += 1

                # Rule 1d: Local variable re-aliasing (let a = x; let b = a;)
                if not is_test_or_example:
                    m_alias = re.match(
                        r"^\s*(?:let|var)\s+([A-Za-z0-9_]+)\s*(?::\s*[^=]+)?=\s*([A-Za-z0-9_]+)\s*;$",
                        line,
                    )
                    if m_alias:
                        alias_lhs = m_alias.group(1)
                        alias_rhs = m_alias.group(2)
                        if i > 0:
                            m_prev = re.match(
                                r"^\s*(?:let|var)\s+([A-Za-z0-9_]+)\s*(?::\s*[^=]+)?=\s*([^;]+);$",
                                lines[i - 1],
                            )
                            if m_prev:
                                prev_lhs = m_prev.group(1)
                                if alias_rhs == prev_lhs and alias_lhs != prev_lhs:
                                    print_colored(
                                        f"[LINT] {rel_path}:{line_num} -> Redundant local variable re-aliasing "
                                        f"('let {alias_lhs} = {prev_lhs};'). Bind the canonical name directly.",
                                        "red",
                                    )
                                    violations += 1

                # Update brace depth
                open_cnt = line.count("{")
                close_cnt = line.count("}")
                fn_brace_depth += open_cnt - close_cnt

                if in_loop and fn_brace_depth <= loop_brace_depth:
                    in_loop = False

                # Exited function
                if fn_brace_depth <= 0 and (open_cnt > 0 or close_cnt > 0):
                    fn_len = line_num - fn_start_line + 1
                    if not is_test_or_example and fn_has_loop and fn_len > 65:
                        print_colored(
                            f"[LINT] {rel_path}:{fn_start_line} -> Loop-containing function '{fn_name}' "
                            f"exceeds 65 lines ({fn_len} lines). Extract loop body to preserve cache locality and keep G-CRAP <= 25.0.",
                            "yellow",
                        )
                        violations += 1
                    in_function = False

    if violations > 0:
        print_colored(f"\n[LINT REJECTED] Found {violations} invariant violation(s).", "red")
        return 1

    print_colored(
        "[LINT PASSED] All code clarity, anti-aliasing, geometry, and history invariants satisfied.",
        "green",
    )
    return 0


if __name__ == "__main__":
    sys.exit(main())
