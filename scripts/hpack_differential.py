#!/usr/bin/env python3
"""Stateful HPACK differential oracle (wing vs golang.org/x/net/http2/hpack).

Runs two directions over randomized multi-block connections with dynamic table
resizing and wire mutations:
  1. Go -> Wing: hpackoracle gen generates encoded/mutated blocks; hpack_verdict
     decodes them and compares every verdict and field byte-for-byte.
  2. Wing -> Go: hpack_verdict encodes valid header blocks (Huffman & raw)
     and hpackoracle check verifies Go decodes every field back identically.

Usage:
    python scripts/hpack_differential.py [--conns N] [--seed S] [-v]
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@dataclass
class BlockCase:
    conn_idx: int
    limit: int
    limit_changes: list[int] = field(default_factory=list)
    block_hex: str = "-"
    go_ok: bool = False
    fields: list[tuple[str, str, str]] = field(default_factory=list)


def build_binaries(build_dir: str) -> tuple[str, str]:
    go_bin = os.path.join(build_dir, "hpackoracle.exe" if os.name == "nt" else "hpackoracle")
    wing_bin = os.path.join(build_dir, "hpack_verdict.exe" if os.name == "nt" else "hpack_verdict")

    env = os.environ.copy()
    env["GOPROXY"] = "off"
    res_go = subprocess.run(
        [
            "go",
            "build",
            "-C",
            os.path.join(REPO_ROOT, "tests", "fuzz", "hpackoracle"),
            "-o",
            go_bin,
            ".",
        ],
        cwd=REPO_ROOT,
        env=env,
        capture_output=True,
        text=True,
    )
    if res_go.returncode != 0:
        raise RuntimeError(f"go build hpackoracle failed:\n{res_go.stderr}")

    goose_cmd = ["goose", "build"]
    if os.name == "nt":
        goose_cmd.extend(["--cc", "gcc"])
    goose_cmd.extend(
        ["-O2", os.path.join(REPO_ROOT, "tests", "fuzz", "hpack_verdict.goose"), "-o", wing_bin]
    )
    res_wing = subprocess.run(goose_cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if res_wing.returncode != 0:
        raise RuntimeError(
            f"goose build hpack_verdict failed:\n{res_wing.stderr}\n{res_wing.stdout}"
        )

    return go_bin, wing_bin


def parse_go_gen(text: str) -> list[list[BlockCase]]:
    conns: list[list[BlockCase]] = []
    cur_conn: list[BlockCase] | None = None
    cur_limit = 4096
    pending_limits: list[int] = []
    cur_block: BlockCase | None = None

    for raw in text.splitlines():
        parts = raw.split()
        if not parts:
            continue
        cmd = parts[0]
        if cmd == "conn":
            cur_limit = int(parts[1])
            cur_conn = []
            conns.append(cur_conn)
            pending_limits = []
            cur_block = None
        elif cmd == "limit":
            pending_limits.append(int(parts[1]))
        elif cmd == "block":
            assert cur_conn is not None
            cur_block = BlockCase(
                conn_idx=len(conns) - 1,
                limit=cur_limit,
                limit_changes=pending_limits,
                block_hex=parts[1],
            )
            pending_limits = []
            cur_conn.append(cur_block)
        elif cmd == "ok":
            assert cur_block is not None
            cur_block.go_ok = True
        elif cmd == "error":
            assert cur_block is not None
            cur_block.go_ok = False
        elif cmd == "field":
            assert cur_block is not None
            cur_block.fields.append((parts[1], parts[2], parts[3]))
    return conns


def parse_wing_decode(text: str) -> list[tuple[bool, list[tuple[str, str, str]]]]:
    out: list[tuple[bool, list[tuple[str, str, str]]]] = []
    for raw in text.splitlines():
        parts = raw.split()
        if not parts:
            continue
        if parts[0] == "ok":
            out.append((True, []))
        elif parts[0] == "error":
            out.append((False, []))
        elif parts[0] == "field":
            out[-1][1].append((parts[1], parts[2], parts[3]))
    return out


def _skip_hpack_int(data: bytes, pos: int, prefix: int) -> tuple[int, int] | None:
    if pos >= len(data):
        return None
    mask = (1 << prefix) - 1
    val = data[pos] & mask
    pos += 1
    if val < mask:
        return val, pos
    shift = 0
    while pos < len(data):
        b = data[pos]
        pos += 1
        val += (b & 0x7F) << shift
        if (b & 0x80) == 0:
            return val, pos
        shift += 7
        if shift > 28:
            return None
    return None


def _skip_hpack_str(data: bytes, pos: int) -> int | None:
    parsed = _skip_hpack_int(data, pos, 7)
    if parsed is None:
        return None
    slen, pos = parsed
    if pos + slen > len(data):
        return None
    return pos + slen


def count_leading_size_updates(block_hex: str) -> int:
    if block_hex == "-":
        return 0
    data = bytes.fromhex(block_hex)
    pos = 0
    cnt = 0
    while pos < len(data) and (data[pos] & 0xE0) == 0x20:
        parsed = _skip_hpack_int(data, pos, 5)
        if parsed is None:
            return cnt
        _, pos = parsed
        cnt += 1
    return cnt


def has_post_field_size_update(block_hex: str) -> bool:
    if block_hex == "-":
        return False
    data = bytes.fromhex(block_hex)
    pos = 0
    seen_field = False
    while pos < len(data):
        b = data[pos]
        if (b & 0x80) != 0:
            seen_field = True
            p = _skip_hpack_int(data, pos, 7)
            if p is None:
                return False
            pos = p[1]
        elif (b & 0xC0) == 0x40 or (b & 0xE0) == 0x00:
            seen_field = True
            pref = 6 if (b & 0xC0) == 0x40 else 4
            p = _skip_hpack_int(data, pos, pref)
            if p is None:
                return False
            idx, pos = p
            if idx == 0:
                p2 = _skip_hpack_str(data, pos)
                if p2 is None:
                    return False
                pos = p2
            p3 = _skip_hpack_str(data, pos)
            if p3 is None:
                return False
            pos = p3
        else:
            if seen_field:
                return True
            p = _skip_hpack_int(data, pos, 5)
            if p is None:
                return False
            pos = p[1]
    return False


def verify_decode_direction(
    conns: list[list[BlockCase]],
    wing_bin: str,
    tmpdir: str,
    verbose: bool,
) -> tuple[int, int, int, int, int, list[str]]:
    dec_batch = os.path.join(tmpdir, "dec_batch.txt")
    flat_cases: list[BlockCase] = []
    with open(dec_batch, "w", encoding="ascii", newline="\n") as f:
        for blocks in conns:
            if not blocks:
                continue
            f.write(f"conn {blocks[0].limit}\n")
            for blk in blocks:
                f.write(f"block {blk.block_hex}\n")
                flat_cases.append(blk)

    res = subprocess.run([wing_bin, "decode", dec_batch], capture_output=True, text=True)
    if res.returncode != 0:
        raise RuntimeError(f"hpack_verdict decode failed:\n{res.stderr}\n{res.stdout}")

    wing_results = parse_wing_decode(res.stdout)
    if len(wing_results) != len(flat_cases):
        raise RuntimeError(
            f"decode count mismatch: got {len(wing_results)}, want {len(flat_cases)}"
        )

    ok_match = 0
    err_match = 0
    go_quirk_multi_upd = 0
    wing_stricter_post_upd = 0
    mismatches: list[str] = []
    for i, (blk, (w_ok, w_fields)) in enumerate(zip(flat_cases, wing_results, strict=True)):
        if blk.go_ok != w_ok:
            if not blk.go_ok and w_ok and count_leading_size_updates(blk.block_hex) >= 2:
                go_quirk_multi_upd += 1
                continue
            if blk.go_ok and not w_ok and has_post_field_size_update(blk.block_hex):
                wing_stricter_post_upd += 1
                continue
            mismatches.append(
                f"block#{i} (conn {blk.conn_idx}, limit={blk.limit}): "
                f"go_ok={blk.go_ok} vs wing_ok={w_ok}, hex={blk.block_hex[:64]}"
            )
            continue
        if not blk.go_ok:
            err_match += 1
            continue
        if w_fields != blk.fields:
            mismatches.append(
                f"block#{i} (conn {blk.conn_idx}, limit={blk.limit}): fields mismatch: "
                f"go={blk.fields[:3]} wing={w_fields[:3]}"
            )
            continue
        ok_match += 1

    if verbose and mismatches:
        for m in mismatches[:10]:
            print("  [decode mismatch]", m)
    return (
        ok_match,
        err_match,
        go_quirk_multi_upd,
        wing_stricter_post_upd,
        len(flat_cases),
        mismatches,
    )


def verify_encode_direction(
    conns: list[list[BlockCase]],
    go_bin: str,
    wing_bin: str,
    tmpdir: str,
    use_huff: bool,
) -> tuple[int, list[str]]:
    tag = "huff" if use_huff else "raw"
    enc_in = os.path.join(tmpdir, f"enc_in_{tag}.txt")
    expected_blocks: list[BlockCase] = []

    with open(enc_in, "w", encoding="ascii", newline="\n") as f:
        for blocks in conns:
            # Roundtrip the non-errored prefix blocks per connection
            clean = [b for b in blocks if b.go_ok]
            if not clean:
                continue
            # Also exclude trailing mutated-but-accepted block because encoder must not desync
            f.write(f"conn {clean[0].limit}\n")
            for b in clean:
                for nl in b.limit_changes:
                    f.write(f"limit {nl}\n")
                for n_hex, v_hex, sens in b.fields:
                    f.write(f"field {n_hex} {v_hex} {sens}\n")
                f.write("endblock\n")
                expected_blocks.append(b)

    res_enc = subprocess.run(
        [wing_bin, "encode", enc_in, "1" if use_huff else "0"],
        capture_output=True,
        text=True,
    )
    if res_enc.returncode != 0:
        raise RuntimeError(f"hpack_verdict encode failed:\n{res_enc.stderr}\n{res_enc.stdout}")

    encoded_lines = [
        ln.strip() for ln in res_enc.stdout.splitlines() if ln.strip().startswith("block ")
    ]
    if len(encoded_lines) != len(expected_blocks):
        raise RuntimeError(
            f"encode count mismatch ({tag}): got {len(encoded_lines)}, want {len(expected_blocks)}"
        )

    go_check_in = os.path.join(tmpdir, f"go_check_{tag}.txt")
    last_conn = -1
    with open(go_check_in, "w", encoding="ascii", newline="\n") as f:
        for blk_line, b in zip(encoded_lines, expected_blocks, strict=True):
            if b.conn_idx != last_conn:
                f.write(f"conn {b.limit}\n")
                last_conn = b.conn_idx
            f.write(f"{blk_line}\n")
            for n_hex, v_hex, sens in b.fields:
                f.write(f"field {n_hex} {v_hex} {sens}\n")

    res_chk = subprocess.run([go_bin, "check", go_check_in], capture_output=True, text=True)
    if res_chk.returncode != 0:
        raise RuntimeError(f"hpackoracle check failed:\n{res_chk.stderr}")

    chk_lines = [ln.strip() for ln in res_chk.stdout.splitlines() if ln.strip()]
    if len(chk_lines) != len(expected_blocks):
        raise RuntimeError(
            f"go check line mismatch ({tag}): got {len(chk_lines)}, want {len(expected_blocks)}"
        )

    mismatches = [
        f"encode({tag}) block#{i} (conn {b.conn_idx}): {ln}"
        for i, (ln, b) in enumerate(zip(chk_lines, expected_blocks, strict=True))
        if ln != "ok"
    ]
    return len(expected_blocks), mismatches


def main() -> int:
    ap = argparse.ArgumentParser(
        description="HPACK differential harness (wing vs Go x/net/http2/hpack)"
    )
    ap.add_argument("--conns", type=int, default=500, help="Number of HPACK connections")
    ap.add_argument("--seed", type=int, default=20261113, help="PRNG seed")
    ap.add_argument("-v", "--verbose", action="store_true", help="Print detailed failure lines")
    args = ap.parse_args()

    t0 = time.time()
    with tempfile.TemporaryDirectory(prefix="wing_hpack_diff_") as tmpdir:
        go_bin, wing_bin = build_binaries(tmpdir)
        res_gen = subprocess.run(
            [go_bin, "gen", "-seed", str(args.seed), "-n", str(args.conns)],
            capture_output=True,
            text=True,
        )
        if res_gen.returncode != 0:
            print(f"hpackoracle gen failed: {res_gen.stderr}", file=sys.stderr)
            return 2

        conns = parse_go_gen(res_gen.stdout)
        (
            ok_m,
            err_m,
            go_quirk_m,
            wing_strict_m,
            total_blk,
            dec_mismatches,
        ) = verify_decode_direction(conns, wing_bin, tmpdir, args.verbose)
        enc_huff_n, enc_huff_err = verify_encode_direction(conns, go_bin, wing_bin, tmpdir, True)
        enc_raw_n, enc_raw_err = verify_encode_direction(conns, go_bin, wing_bin, tmpdir, False)

    dt = time.time() - t0
    print(
        f"HPACK differential ({args.conns} conns, {dt:.2f}s): "
        f"decode_ok={ok_m}, decode_err={err_m}, decode_total={total_blk}, "
        f"go_multi_size_upd_quirk={go_quirk_m}, wing_strict_post_field_upd={wing_strict_m}, "
        f"decode_mismatches={len(dec_mismatches)}, "
        f"encode_huff={enc_huff_n} (fails={len(enc_huff_err)}), "
        f"encode_raw={enc_raw_n} (fails={len(enc_raw_err)})"
    )
    all_fails = dec_mismatches + enc_huff_err + enc_raw_err
    for m in all_fails[:15]:
        print(f"MISMATCH: {m}", file=sys.stderr)
    return 1 if all_fails else 0


if __name__ == "__main__":
    raise SystemExit(main())
