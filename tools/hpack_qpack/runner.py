#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""
HPACK (RFC 7541 / http2jp/hpack-test-case) and QPACK (RFC 9204 / quicwg/qpack)
interop verification runner for `goose-wing`.

Executes wire decompression and encoder->decoder roundtrip checks using native
compiled Goose harnesses (`hpack_harness.goose`, `qpack_harness.goose`).
"""

from __future__ import annotations

import argparse
import io
import json
import os
import struct
import subprocess
import sys
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any

if (
    isinstance(sys.stdout, io.TextIOWrapper)
    and sys.stdout.encoding
    and sys.stdout.encoding.lower() != "utf-8"
):
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass
if (
    isinstance(sys.stderr, io.TextIOWrapper)
    and sys.stderr.encoding
    and sys.stderr.encoding.lower() != "utf-8"
):
    try:
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

SUITE_DIR = Path(__file__).resolve().parent
ROOT_DIR = SUITE_DIR.parent.parent
BIN_DIR = ROOT_DIR / "tools" / "bin"
HPACK_SRC = SUITE_DIR / "hpack_harness.goose"
QPACK_SRC = SUITE_DIR / "qpack_harness.goose"
HPACK_EXE = BIN_DIR / ("hpack_harness.exe" if sys.platform == "win32" else "hpack_harness")
QPACK_EXE = BIN_DIR / ("qpack_harness.exe" if sys.platform == "win32" else "qpack_harness")
STORIES_HPACK = SUITE_DIR / "stories_hpack.json"
STORIES_QPACK = SUITE_DIR / "stories_qpack.json"


def ensure_binary(src: Path, exe: Path, label: str, force_rebuild: bool = False) -> Path:
    BIN_DIR.mkdir(parents=True, exist_ok=True)
    if not force_rebuild and exe.is_file() and exe.stat().st_mtime >= src.stat().st_mtime:
        return exe

    print(f"[*] Building {label}: {src.name} -> {exe.name}...")
    env = os.environ.copy()
    opt_flag = "-O2"
    if sys.platform == "win32":
        opt_flag = "-O0"
        if "GOOSE_CC" not in env:
            stack_cc = ROOT_DIR / "tools" / "gcc_stack.bat"
            if stack_cc.is_file():
                env["GOOSE_CC"] = str(stack_cc)
    cmd = ["goose", "build", opt_flag, "-o", str(exe), str(src)]
    res = subprocess.run(
        cmd, check=False, cwd=str(ROOT_DIR), capture_output=True, text=True, env=env
    )
    if res.returncode != 0:
        print(f"[!] Failed to build {label}:\n{res.stdout}\n{res.stderr}", file=sys.stderr)
        sys.exit(1)
    print(f"[+] Built {exe.name}")
    return exe


def _decode_hex_pairs(encoded: str) -> list[tuple[str, str]]:
    if not encoded or encoded == "-":
        return []
    pairs: list[tuple[str, str]] = []
    for item in encoded.split(","):
        if ":" not in item:
            continue
        k_hex, v_hex = item.split(":", 1)
        pairs.append((bytes.fromhex(k_hex).decode("latin-1"), bytes.fromhex(v_hex).decode("latin-1")))
    return pairs


def _flatten_json_headers(hdrs: list[dict[str, str]]) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []
    for entry in hdrs:
        for k, v in entry.items():
            out.append((k, v))
    return out


def _normalize_hpack_headers(pairs: list[tuple[str, str]]) -> Counter[tuple[str, str]]:
    """Normalizes cookies per RFC 9113 §8.2.3 ('; ' join) and compares header multiset."""
    cookies: list[str] = []
    other: list[tuple[str, str]] = []
    for k, v in pairs:
        if k.lower() == "cookie":
            cookies.append(v)
        else:
            other.append((k, v))
    if cookies:
        other.append(("cookie", "; ".join(cookies)))
    return Counter(other)


def load_hpack_stories(source_path: Path) -> list[dict[str, Any]]:
    """Loads bundled `stories_hpack.json` or an upstream `http2jp/hpack-test-case` dir."""
    stories: list[dict[str, Any]] = []
    json_files = [source_path] if source_path.is_file() else sorted(source_path.rglob("*.json"))
    for fp in json_files:
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict) and "stories" in data and isinstance(data["stories"], list):
            for st in data["stories"]:
                if isinstance(st, dict) and "cases" in st:
                    stories.append(st)
        elif isinstance(data, dict) and "cases" in data and isinstance(data["cases"], list):
            if data["cases"] and "wire" in data["cases"][0]:
                label = fp.stem if source_path.is_file() else f"{fp.parent.name}/{fp.stem}"
                stories.append({"name": label, "cases": data["cases"]})
    return stories


def run_hpack_suite(source_path: Path, rebuild: bool = False) -> tuple[int, int]:
    exe = ensure_binary(HPACK_SRC, HPACK_EXE, "HPACK interop harness", rebuild)
    stories = load_hpack_stories(source_path)
    if not stories:
        print(f"[!] No HPACK stories found in {source_path}", file=sys.stderr)
        return 0, 1

    tsv_lines: list[str] = []
    case_meta: dict[str, tuple[str, dict[str, Any]]] = {}
    for s_idx, story in enumerate(stories):
        sname = str(story.get("name", f"story_{s_idx}"))
        cases = story.get("cases", [])
        init_sz = 4096
        if cases and cases[0].get("header_table_size") is not None:
            init_sz = int(cases[0]["header_table_size"])
        tsv_lines.append(f"STORY\t{sname}\t{init_sz}")
        for c_idx, case in enumerate(cases):
            cid = f"{sname}#{case.get('seqno', c_idx)}"
            raw_tbl_sz = case.get("header_table_size")
            tbl_sz = int(raw_tbl_sz) if raw_tbl_sz is not None else 0
            wire_hex = str(case.get("wire", "")).replace(" ", "").strip()
            tsv_lines.append(f"CASE\t{cid}\t{tbl_sz}\t{wire_hex}")
            case_meta[cid] = (sname, case)

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".tsv", encoding="utf-8", delete=False
    ) as tmp:
        tsv_path = Path(tmp.name)
        tmp.write("\n".join(tsv_lines) + "\n")
    try:
        res = subprocess.run(
            [str(exe), str(tsv_path)],
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            timeout=60.0,
            check=False,
        )
    finally:
        tsv_path.unlink(missing_ok=True)

    if res.returncode != 0:
        print(f"[!] hpack_harness failed ({res.returncode}): {res.stderr}", file=sys.stderr)
        return 0, len(case_meta)

    rows: dict[str, list[str]] = {}
    for line in res.stdout.splitlines():
        cols = line.strip().split("\t")
        if len(cols) >= 8 and cols[0] == "RESULT":
            rows[cols[1]] = cols

    passed = 0
    failed = 0
    print("\nExecuting HPACK Interop Vector Suite (http2::DynamicTable + roundtrip)...")
    for cid, (_sname, case) in case_meta.items():
        cols = rows.get(cid)
        expect_err = bool(case.get("expect_error", False))
        if not cols:
            failed += 1
            print(f"  [FAIL] {cid}: missing harness output")
            continue
        status = cols[2]
        if expect_err:
            if status == "ERR":
                passed += 1
                print(f"  [PASS] {cid:44s} -> REJECT (err={cols[3]})")
            else:
                failed += 1
                print(f"  [FAIL] {cid:44s} -> expected error, got {status}")
            continue

        rt_ok = cols[4] == "1"
        got_pairs = _decode_hex_pairs(cols[7])
        exp_pairs = _flatten_json_headers(case.get("headers", []))
        hdrs_match = _normalize_hpack_headers(got_pairs) == _normalize_hpack_headers(exp_pairs)
        if status == "OK" and rt_ok and hdrs_match:
            passed += 1
            print(f"  [PASS] {cid:44s} -> {len(got_pairs)} hdrs, dt=({cols[5]}e/{cols[6]}B), rt=OK")
        else:
            failed += 1
            print(
                f"  [FAIL] {cid:44s} -> st={status} rt={rt_ok} got={got_pairs} exp={exp_pairs}"
            )
    return passed, failed


def _parse_qif_blocks(qif_path: Path) -> list[list[dict[str, str]]]:
    """Parses a `quicwg/qpack` `.qif` file into per-block header lists."""
    blocks: list[list[dict[str, str]]] = []
    cur: list[dict[str, str]] = []
    for raw_line in qif_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = raw_line.rstrip("\r\n")
        if not line:
            if cur:
                blocks.append(cur)
                cur = []
            continue
        if line.startswith("#"):
            continue
        if "\t" in line:
            k, v = line.split("\t", 1)
            cur.append({k: v})
    if cur:
        blocks.append(cur)
    return blocks


def _load_quicwg_enc_story(enc_path: Path, qif_path: Path) -> dict[str, Any] | None:
    """Parses official `quicwg/qpack` binary `<stream_id:u64><len:u32><payload>` framing."""
    raw = enc_path.read_bytes()
    qif_blocks = _parse_qif_blocks(qif_path)
    parts = enc_path.name.split(".")
    max_cap = 4096
    max_blk = 100
    for idx, tok in enumerate(parts):
        if tok.isdigit() and idx + 1 < len(parts) and parts[idx + 1].isdigit():
            max_cap = int(tok)
            max_blk = int(parts[idx + 1])
            break

    steps: list[dict[str, Any]] = []
    off = 0
    sec_idx = 0
    while off + 12 <= len(raw):
        stream_id, plen = struct.unpack(">QI", raw[off : off + 12])
        off += 12
        if off + plen > len(raw):
            return None
        payload_hex = raw[off : off + plen].hex()
        off += plen
        if stream_id == 0:
            steps.append({"kind": "encoder", "wire": payload_hex})
        else:
            exp_hdrs = qif_blocks[sec_idx] if sec_idx < len(qif_blocks) else []
            sec_idx += 1
            steps.append(
                {
                    "kind": "section",
                    "stream_id": stream_id,
                    "wire": payload_hex,
                    "headers": exp_hdrs,
                }
            )
    first_enc = next((s["wire"] for s in steps if s["kind"] == "encoder" and s["wire"]), "")
    starts_with_set_cap = bool(first_enc) and (int(first_enc[:2], 16) & 0xE0) == 0x20
    return {
        "name": f"{enc_path.parent.name}/{enc_path.name}",
        "max_table_capacity": max_cap,
        "max_blocked_streams": max_blk,
        "initial_capacity": 0 if starts_with_set_cap else max_cap,
        "auto_unblock": True,
        "steps": steps,
    }


def load_qpack_stories(source_path: Path) -> list[dict[str, Any]]:
    stories: list[dict[str, Any]] = []
    if source_path.is_file():
        data = json.loads(source_path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and "stories" in data:
            return list(data["stories"])
        return [data]

    for fp in sorted(source_path.rglob("*.json")):
        try:
            data = json.loads(fp.read_text(encoding="utf-8"))
        except Exception:
            continue
        if isinstance(data, dict) and "stories" in data:
            stories.extend(data["stories"])
        elif isinstance(data, dict) and "steps" in data:
            stories.append(data)

    qif_by_stem = {p.stem: p for p in source_path.rglob("*.qif")}
    for enc_fp in sorted(source_path.rglob("*.out*")):
        if not enc_fp.is_file():
            continue
        base_stem = enc_fp.name.split(".", 1)[0]
        if base_stem in qif_by_stem:
            st = _load_quicwg_enc_story(enc_fp, qif_by_stem[base_stem])
            if st and st["steps"]:
                stories.append(st)
    return stories


def run_qpack_suite(source_path: Path, rebuild: bool = False) -> tuple[int, int]:
    exe = ensure_binary(QPACK_SRC, QPACK_EXE, "QPACK interop harness", rebuild)
    stories = load_qpack_stories(source_path)
    if not stories:
        print(f"[!] No QPACK stories found in {source_path}", file=sys.stderr)
        return 0, 1

    tsv_lines: list[str] = []
    step_meta: dict[str, dict[str, Any]] = {}
    for s_idx, story in enumerate(stories):
        sname = str(story.get("name", f"qpack_{s_idx}"))
        max_cap = int(story.get("max_table_capacity", 4096))
        max_blk = int(story.get("max_blocked_streams", 16))
        init_cap = int(story.get("initial_capacity", 0))
        auto_ub = 1 if story.get("auto_unblock", False) else 0
        tsv_lines.append(f"STORY\t{sname}\t{max_cap}\t{max_blk}\t{init_cap}\t{auto_ub}")
        for idx, step in enumerate(story.get("steps", [])):
            sid_tag = f"{sname}#{idx}:{step['kind']}"
            kind = step["kind"]
            wire_hex = str(step.get("wire", "")).replace(" ", "").strip()
            if kind == "encoder":
                tsv_lines.append(f"ENC\t{sid_tag}\t{wire_hex}")
            elif kind == "decoder":
                tsv_lines.append(f"DEC\t{sid_tag}\t{wire_hex}")
            elif kind == "unblock":
                tsv_lines.append(f"UNBLOCK\t{sid_tag}\t{int(step.get('stream_id', 0))}")
            else:
                tsv_lines.append(f"SEC\t{sid_tag}\t{int(step.get('stream_id', 0))}\t{wire_hex}")
            step_meta[sid_tag] = step

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".tsv", encoding="utf-8", delete=False
    ) as tmp:
        tsv_path = Path(tmp.name)
        tmp.write("\n".join(tsv_lines) + "\n")
    try:
        res = subprocess.run(
            [str(exe), str(tsv_path)],
            cwd=str(ROOT_DIR),
            capture_output=True,
            text=True,
            timeout=60.0,
            check=False,
        )
    finally:
        tsv_path.unlink(missing_ok=True)

    if res.returncode != 0:
        print(f"[!] qpack_harness failed ({res.returncode}): {res.stderr}", file=sys.stderr)
        return 0, len(step_meta)

    rows: dict[str, list[str]] = {}
    for line in res.stdout.splitlines():
        cols = line.strip().split("\t")
        if len(cols) >= 4 and cols[0] in ("ENC_RES", "DEC_RES", "SEC_RES"):
            rows[cols[1]] = cols

    passed = 0
    failed = 0
    print("\nExecuting QPACK Interop Vector Suite (http3::QpackTable + roundtrip)...")
    for sid_tag, step in step_meta.items():
        cols = rows.get(sid_tag)
        if not cols:
            failed += 1
            print(f"  [FAIL] {sid_tag}: missing harness output")
            continue
        kind = step["kind"]
        got_err = cols[2]
        exp_err = str(step.get("expect_error", "None"))
        if kind == "encoder":
            ic_ok = "expect_insert_count" not in step or int(cols[3]) == int(
                step["expect_insert_count"]
            )
            ok = got_err == exp_err and ic_ok
            detail = f"err={got_err} ic={cols[3]}"
        elif kind == "decoder":
            kr_ok = "expect_known_rcvd" not in step or int(cols[3]) == int(
                step["expect_known_rcvd"]
            )
            ok = got_err == exp_err and kr_ok
            detail = f"err={got_err} known_rcvd={cols[3]}"
        else:
            if exp_err != "None":
                ok = got_err == exp_err
                detail = f"err={got_err}"
            else:
                rt_ok = cols[3] == "1"
                got_pairs = _decode_hex_pairs(cols[5])
                exp_pairs = _flatten_json_headers(step.get("headers", []))
                ok = got_err == "None" and rt_ok and got_pairs == exp_pairs
                detail = f"{len(got_pairs)} hdrs, ic={cols[4]}, rt={'OK' if rt_ok else 'FAIL'}"
        if ok:
            passed += 1
            print(f"  [PASS] {sid_tag:54s} -> {detail}")
        else:
            failed += 1
            print(f"  [FAIL] {sid_tag:54s} -> {detail} (row={cols})")
    return passed, failed


def fetch_upstream_vectors(cache_dir: Path) -> tuple[Path, Path]:
    cache_dir.mkdir(parents=True, exist_ok=True)
    hpack_dir = cache_dir / "hpack-test-case"
    qpack_dir = cache_dir / "qifs"
    repos = [
        ("https://github.com/http2jp/hpack-test-case.git", hpack_dir),
        ("https://github.com/qpackers/qifs.git", qpack_dir),
    ]
    for url, dst in repos:
        if dst.is_dir():
            print(f"[*] Using cached upstream vectors: {dst}")
            continue
        print(f"[*] Cloning {url} -> {dst}...")
        res = subprocess.run(
            ["git", "clone", "--depth", "1", url, str(dst)],
            check=False,
            capture_output=True,
            text=True,
        )
        if res.returncode != 0:
            print(f"[!] git clone failed for {url}: {res.stderr}", file=sys.stderr)
            sys.exit(1)
    return hpack_dir, qpack_dir


def main() -> None:
    parser = argparse.ArgumentParser(
        description="HPACK (http2jp) & QPACK (quicwg) Interop Vector Suite for goose-wing"
    )
    parser.add_argument(
        "--suite",
        choices=("all", "hpack", "qpack"),
        default="all",
        help="Select HPACK, QPACK, or both suites",
    )
    parser.add_argument(
        "--local",
        action="store_true",
        help="Run bundled RFC 7541 / RFC 9204 stories locally",
    )
    parser.add_argument(
        "--dir",
        default="",
        help="Directory of upstream http2jp/hpack-test-case or quicwg/qpack test vectors",
    )
    parser.add_argument(
        "--fetch",
        action="store_true",
        help="Clone upstream http2jp/hpack-test-case and qpackers/qifs and execute them",
    )
    parser.add_argument("--docker", action="store_true", help="Build and run inside Docker")
    parser.add_argument("--rebuild", action="store_true", help="Force rebuild Goose harnesses")
    args = parser.parse_args()

    if args.docker:
        dockerfile = SUITE_DIR / "Dockerfile"
        img = "goose-wing-hpack-qpack"
        rc_b = subprocess.run(
            ["docker", "build", "-f", str(dockerfile), "-t", img, "."],
            cwd=str(ROOT_DIR),
            check=False,
        ).returncode
        if rc_b != 0:
            sys.exit(rc_b)
        sys.exit(
            subprocess.run(
                ["docker", "run", "--rm", img, "--local", "--suite", args.suite],
                cwd=str(ROOT_DIR),
                check=False,
            ).returncode
        )

    hpack_src = STORIES_HPACK
    qpack_src = STORIES_QPACK
    if args.fetch:
        hpack_src, qpack_src = fetch_upstream_vectors(ROOT_DIR / ".cache" / "hpack_qpack")
    elif args.dir:
        custom = Path(args.dir).resolve()
        hpack_src = custom
        qpack_src = custom

    total_pass = 0
    total_fail = 0
    if args.suite in ("all", "hpack"):
        p, f = run_hpack_suite(hpack_src, rebuild=args.rebuild)
        total_pass += p
        total_fail += f
    if args.suite in ("all", "qpack"):
        p, f = run_qpack_suite(qpack_src, rebuild=args.rebuild)
        total_pass += p
        total_fail += f

    total = total_pass + total_fail
    print(f"\nHPACK/QPACK Interop Completed: {total_pass}/{total} passed, {total_fail} failed.")
    sys.exit(0 if total_fail == 0 and total > 0 else 1)


if __name__ == "__main__":
    main()
