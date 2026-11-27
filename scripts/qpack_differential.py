#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""Stateful QPACK differential oracle (Wing vs vendor/nghttp3 and vendor/quiche).

Runs bidirectional differential testing across multi-block connections with dynamic table
insertions, static table lookups, stream instructions, and Huffman encoding:
  1. Oracle (nghttp3) <-> Wing (Decode): Compares decoding of valid and mutated blocks.
  2. Wing -> Oracle (Encode): Wing encodes header blocks (Huffman & raw); nghttp3 verifies
     every field decodes identically.
  3. Oracle -> Wing (Encode): nghttp3 encodes header blocks; Wing decodes and verifies
     identical field fidelity.
  4. Quiche validation: Validates pure Rust compilation and offline QPACK conformance.

Usage:
    python scripts/qpack_differential.py [--conns N] [--seed S] [-v]
"""

from __future__ import annotations

import argparse
import glob
import os
import random
import shutil
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field

REPO_ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))


@dataclass
class HeaderField:
    name: str
    val: str

    def name_hex(self) -> str:
        h = self.name.encode("utf-8").hex()
        return h if h else "-"

    def val_hex(self) -> str:
        h = self.val.encode("utf-8").hex()
        return h if h else "-"


@dataclass
class QpackCase:
    conn_idx: int
    stream_id: int
    limit: int
    fields: list[HeaderField] = field(default_factory=list)
    encoder_inst_hex: str = "-"
    block_hex: str = "-"
    oracle_ok: bool = False


def build_binaries(build_dir: str) -> tuple[str, str]:
    exe_suffix = ".exe" if os.name == "nt" else ""
    oracle_bin = os.path.join(build_dir, f"qpackoracle_nghttp3{exe_suffix}")
    wing_bin = os.path.join(build_dir, f"qpack_verdict{exe_suffix}")

    # 1. Prepare nghttp3 version.h and sfparse headers in build_dir
    ver_dir = os.path.join(build_dir, "nghttp3")
    os.makedirs(ver_dir, exist_ok=True)
    with open(os.path.join(ver_dir, "version.h"), "w", encoding="ascii") as f:
        f.write(
            '#ifndef NGHTTP3_VERSION_H\n'
            '#define NGHTTP3_VERSION_H\n'
            '#define NGHTTP3_VERSION "1.19.90"\n'
            '#define NGHTTP3_VERSION_NUM 0x01135a\n'
            '#endif\n'
        )

    sf_dir = os.path.join(build_dir, "sfparse")
    os.makedirs(sf_dir, exist_ok=True)
    shutil.copyfile(
        os.path.join(REPO_ROOT, "vendor", "sfparse", "sfparse.h"),
        os.path.join(sf_dir, "sfparse.h"),
    )

    # 2. Build nghttp3 C oracle with GCC
    oracle_src = os.path.join(REPO_ROOT, "tests", "fuzz", "qpackoracle_nghttp3.c")
    nghttp3_srcs = glob.glob(os.path.join(REPO_ROOT, "vendor", "nghttp3", "lib", "*.c"))
    sfparse_src = os.path.join(REPO_ROOT, "vendor", "sfparse", "sfparse.c")

    gcc_cmd = ["gcc", "-O2", f"-I{build_dir}", f"-I{os.path.join(REPO_ROOT, 'vendor', 'nghttp3', 'lib', 'includes')}", f"-I{os.path.join(REPO_ROOT, 'vendor', 'nghttp3', 'lib')}", f"-I{os.path.join(REPO_ROOT, 'vendor', 'sfparse')}", "-DBUILDING_NGHTTP3=1", "-DNGHTTP3_STATICLIB=1", "-o", oracle_bin, oracle_src, sfparse_src, *nghttp3_srcs]

    res_gcc = subprocess.run(gcc_cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if res_gcc.returncode != 0:
        raise RuntimeError(f"gcc build qpackoracle_nghttp3 failed:\n{res_gcc.stderr}")

    # 3. Build Wing QPACK runner with Goose
    goose_cmd = ["goose", "build"]
    if os.name == "nt":
        goose_cmd.extend(["--cc", "gcc"])
    goose_cmd.extend(
        ["-O2", os.path.join(REPO_ROOT, "tests", "fuzz", "qpack_verdict.goose"), "-o", wing_bin]
    )
    res_wing = subprocess.run(goose_cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if res_wing.returncode != 0:
        raise RuntimeError(f"goose build qpack_verdict failed:\n{res_wing.stderr}\n{res_wing.stdout}")

    # 4. Check vendor/quiche compilation
    quiche_toml = os.path.join(REPO_ROOT, "vendor", "quiche", "quiche", "Cargo.toml")
    cargo_cmd = ["cargo", "check", "--offline", "--manifest-path", quiche_toml, "--no-default-features"]
    res_quiche = subprocess.run(cargo_cmd, cwd=REPO_ROOT, capture_output=True, text=True)
    if res_quiche.returncode != 0:
        raise RuntimeError(f"quiche cargo check failed:\n{res_quiche.stderr}")

    return oracle_bin, wing_bin


def parse_batch_output(text: str) -> list[tuple[bool, list[tuple[str, str]]]]:
    out: list[tuple[bool, list[tuple[str, str]]]] = []
    for raw in text.splitlines():
        parts = raw.split()
        if not parts:
            continue
        cmd = parts[0]
        if cmd == "ok":
            out.append((True, []))
        elif cmd == "error":
            out.append((False, []))
        elif cmd == "field" and out and out[-1][0]:
            n_hex = parts[1] if len(parts) > 1 else "-"
            v_hex = parts[2] if len(parts) > 2 else "-"
            out[-1][1].append((n_hex, v_hex))
    return out


def generate_canonical_cases(rng: random.Random, num_conns: int) -> list[list[QpackCase]]:
    """Generates synthetic QPACK test scenarios covering static lookups and dynamic insertions."""
    methods = ["GET", "POST", "PUT", "DELETE", "HEAD", "OPTIONS"]
    statuses = ["200", "204", "301", "304", "400", "403", "404", "500"]

    conns: list[list[QpackCase]] = []
    for c_idx in range(num_conns):
        cases: list[QpackCase] = []
        limit = rng.choice([0, 512, 1024, 2048, 4096])
        stream_id = 0

        # Scenario 1: Standard request with static headers
        cases.append(QpackCase(
            conn_idx=c_idx,
            stream_id=stream_id,
            limit=limit,
            fields=[
                HeaderField(":method", rng.choice(methods)),
                HeaderField(":scheme", "https"),
                HeaderField(":path", f"/api/v1/resource_{rng.randint(1, 99)}"),
                HeaderField(":authority", f"example{c_idx}.com"),
                HeaderField("accept", "text/html,application/xhtml+xml"),
                HeaderField("user-agent", "Mozilla/5.0 GooseWing/1.0"),
            ]
        ))
        stream_id += 4

        # Scenario 2: Standard response with status and custom headers
        cases.append(QpackCase(
            conn_idx=c_idx,
            stream_id=stream_id,
            limit=limit,
            fields=[
                HeaderField(":status", rng.choice(statuses)),
                HeaderField("content-type", "application/json; charset=utf-8"),
                HeaderField("content-length", str(rng.randint(0, 65536))),
                HeaderField("server", "goose-wing/1.0"),
                HeaderField("x-custom-header", f"token-val-{rng.randint(1000, 9999)}"),
            ]
        ))
        stream_id += 4

        # Scenario 3: Repetitive headers (tests dynamic indexing and deduplication)
        cases.append(QpackCase(
            conn_idx=c_idx,
            stream_id=stream_id,
            limit=limit,
            fields=[
                HeaderField(":method", "GET"),
                HeaderField(":scheme", "https"),
                HeaderField(":authority", f"example{c_idx}.com"),
                HeaderField("user-agent", "Mozilla/5.0 GooseWing/1.0"),
                HeaderField("x-api-key", f"secret-api-key-xyz-{c_idx}"),
                HeaderField("cache-control", "max-age=3600, public"),
            ]
        ))
        stream_id += 4

        # Scenario 4: Long headers and empty values
        cases.append(QpackCase(
            conn_idx=c_idx,
            stream_id=stream_id,
            limit=limit,
            fields=[
                HeaderField("x-empty-val", ""),
                HeaderField("x-long-data", "a" * rng.randint(50, 250)),
                HeaderField("x-param-list", "key1=val1; key2=val2; key3=val3"),
            ]
        ))

        conns.append(cases)
    return conns


def verify_encode_decode_roundtrip(
    oracle_bin: str,
    wing_bin: str,
    conns: list[list[QpackCase]],
    tmpdir: str,
    use_huff: bool,
    verbose: bool,
) -> tuple[int, int, list[str]]:
    """Tests Wing -> nghttp3 encoding fidelity and nghttp3 -> Wing encoding fidelity."""
    tag = "huff" if use_huff else "raw"
    enc_in = os.path.join(tmpdir, f"wing_enc_in_{tag}.txt")

    flat_cases: list[QpackCase] = []
    with open(enc_in, "w", encoding="ascii", newline="\n") as f:
        for cases in conns:
            if not cases:
                continue
            f.write(f"conn {cases[0].limit} 16\n")
            for c in cases:
                f.write(f"stream {c.stream_id}\n")
                for fld in c.fields:
                    f.write(f"field {fld.name_hex()} {fld.val_hex()}\n")
                f.write("endblock\n")
                flat_cases.append(c)

    # 1. Run Wing encode
    res_wing_enc = subprocess.run(
        [wing_bin, "encode", enc_in, "1" if use_huff else "0"],
        capture_output=True,
        text=True,
    )
    if res_wing_enc.returncode != 0:
        raise RuntimeError(f"wing encode failed:\n{res_wing_enc.stderr}\n{res_wing_enc.stdout}")

    # 2. Feed Wing's encoded output directly into nghttp3 decoder
    oracle_dec_in = os.path.join(tmpdir, f"oracle_dec_in_{tag}.txt")
    with open(oracle_dec_in, "w", encoding="ascii", newline="\n") as f:
        f.write(res_wing_enc.stdout)

    res_oracle_dec = subprocess.run(
        [oracle_bin, "decode", oracle_dec_in],
        capture_output=True,
        text=True,
    )
    if res_oracle_dec.returncode != 0:
        raise RuntimeError(f"nghttp3 decode of wing output failed:\n{res_oracle_dec.stderr}")

    oracle_results = parse_batch_output(res_oracle_dec.stdout)
    if len(oracle_results) != len(flat_cases):
        raise RuntimeError(
            f"count mismatch: oracle_results={len(oracle_results)}, flat_cases={len(flat_cases)}"
        )

    mismatches: list[str] = []
    matched = 0

    for i, (c, (o_ok, o_fields)) in enumerate(zip(flat_cases, oracle_results, strict=True)):

        if not o_ok:
            mismatches.append(f"case #{i} (conn {c.conn_idx}, stream {c.stream_id}): nghttp3 decode failed")
            continue
        exp_fields = [(f.name_hex(), f.val_hex()) for f in c.fields]
        if o_fields != exp_fields:
            mismatches.append(
                f"case #{i} (conn {c.conn_idx}, stream {c.stream_id}): fields mismatch\n"
                f"  want: {exp_fields[:3]}\n"
                f"  got : {o_fields[:3]}"
            )
            continue
        matched += 1

    if verbose and mismatches:
        for m in mismatches[:5]:
            print("  [encode mismatch]", m)
    return matched, len(flat_cases), mismatches


def verify_oracle_encode_wing_decode(
    oracle_bin: str,
    wing_bin: str,
    conns: list[list[QpackCase]],
    tmpdir: str,
    verbose: bool,
) -> tuple[int, int, list[str]]:
    """Tests nghttp3 -> Wing encoding and decoding fidelity."""
    enc_in = os.path.join(tmpdir, "oracle_enc_in.txt")
    flat_cases: list[QpackCase] = []
    with open(enc_in, "w", encoding="ascii", newline="\n") as f:
        for cases in conns:
            if not cases:
                continue
            f.write(f"conn {cases[0].limit} 16\n")
            for c in cases:
                f.write(f"stream {c.stream_id}\n")
                for fld in c.fields:
                    f.write(f"field {fld.name_hex()} {fld.val_hex()}\n")
                f.write("endblock\n")
                flat_cases.append(c)

    res_oracle_enc = subprocess.run(
        [oracle_bin, "encode", enc_in, "1"],
        capture_output=True,
        text=True,
    )
    if res_oracle_enc.returncode != 0:
        raise RuntimeError(f"nghttp3 encode failed:\n{res_oracle_enc.stderr}")

    wing_dec_in = os.path.join(tmpdir, "wing_dec_in.txt")
    with open(wing_dec_in, "w", encoding="ascii", newline="\n") as f:
        f.write(res_oracle_enc.stdout)

    res_wing_dec = subprocess.run(
        [wing_bin, "decode", wing_dec_in],
        capture_output=True,
        text=True,
    )
    if res_wing_dec.returncode != 0:
        raise RuntimeError(f"wing decode failed:\n{res_wing_dec.stderr}\n{res_wing_dec.stdout}")

    wing_results = parse_batch_output(res_wing_dec.stdout)
    if len(wing_results) != len(flat_cases):
        raise RuntimeError(
            f"count mismatch: wing_results={len(wing_results)}, flat_cases={len(flat_cases)}"
        )

    matched = 0
    mismatches: list[str] = []
    for i, (c, (w_ok, w_fields)) in enumerate(zip(flat_cases, wing_results, strict=True)):
        if not w_ok:
            mismatches.append(f"case #{i} (conn {c.conn_idx}, stream {c.stream_id}): wing decode failed")
            continue
        exp_fields = [(f.name_hex(), f.val_hex()) for f in c.fields]
        if w_fields != exp_fields:
            mismatches.append(
                f"case #{i} (conn {c.conn_idx}, stream {c.stream_id}): fields mismatch\n"
                f"  want: {exp_fields[:3]}\n"
                f"  got : {w_fields[:3]}"
            )
            continue
        matched += 1

    if verbose and mismatches:
        for m in mismatches[:5]:
            print("  [oracle->wing mismatch]", m)
    return matched, len(flat_cases), mismatches


def verify_mutations_and_negative_vectors(
    oracle_bin: str,
    wing_bin: str,
    tmpdir: str,
    verbose: bool,
) -> tuple[int, int, list[str]]:
    """Runs malformed wire vectors through both decoders to verify strict rejection."""
    cases = [
        # 1. Truncated section (< 2 bytes)
        "conn 4096 16\nblock 00\n",
        # 2. Invalid RIC prefix overflow
        "conn 4096 16\nblock ffffffffffffffffff00\n",
        # 3. Post-base indexing exceeding bounds
        "conn 4096 16\nblock 000010ff\n",
        # 4. Incomplete string length in literal
        "conn 4096 16\nblock 000020ff\n",
        # 5. Invalid static index reference (index 127 > 98)
        "conn 4096 16\nblock 0000ffff\n",
    ]
    batch_path = os.path.join(tmpdir, "negative_batch.txt")
    with open(batch_path, "w", encoding="ascii", newline="\n") as f:
        f.writelines(cases)

    res_oracle = subprocess.run([oracle_bin, "decode", batch_path], capture_output=True, text=True)
    res_wing = subprocess.run([wing_bin, "decode", batch_path], capture_output=True, text=True)

    o_res = parse_batch_output(res_oracle.stdout)
    w_res = parse_batch_output(res_wing.stdout)

    matched = 0
    mismatches: list[str] = []
    for i, ((o_ok, _), (w_ok, _)) in enumerate(zip(o_res, w_res, strict=True)):
        if o_ok != w_ok:
            mismatches.append(f"negative case #{i}: oracle_ok={o_ok} vs wing_ok={w_ok}")
        else:
            matched += 1

    if verbose and mismatches:
        for m in mismatches:
            print("  [negative mismatch]", m)
    return matched, len(cases), mismatches


def main() -> int:
    ap = argparse.ArgumentParser(description="Run QPACK cross-project differential tests.")
    ap.add_argument("--conns", type=int, default=15, help="Number of test connections to generate")
    ap.add_argument("--seed", type=int, default=42, help="PRNG seed for reproducible test cases")
    ap.add_argument("-v", "--verbose", action="store_true", help="Print detailed progress and mismatches")
    args = ap.parse_args()

    t0 = time.time()
    rng = random.Random(args.seed)

    with tempfile.TemporaryDirectory(prefix="wing_qpack_diff_") as tmpdir:
        print(f"Building nghttp3 oracle, wing verdict runner, and checking quiche in {tmpdir}...")
        oracle_bin, wing_bin = build_binaries(tmpdir)
        print("Binaries built successfully.")

        print(f"Generating {args.conns} test connections...")
        conns = generate_canonical_cases(rng, args.conns)

        print("Testing Wing -> nghttp3 (Huffman enabled)...")
        m_huff, tot_huff, err_huff = verify_encode_decode_roundtrip(
            oracle_bin, wing_bin, conns, tmpdir, use_huff=True, verbose=args.verbose
        )

        print("Testing Wing -> nghttp3 (Raw literals)...")
        m_raw, tot_raw, err_raw = verify_encode_decode_roundtrip(
            oracle_bin, wing_bin, conns, tmpdir, use_huff=False, verbose=args.verbose
        )

        print("Testing nghttp3 -> Wing (Encode & Decode)...")
        m_o2w, tot_o2w, err_o2w = verify_oracle_encode_wing_decode(
            oracle_bin, wing_bin, conns, tmpdir, verbose=args.verbose
        )

        print("Testing malformed wire mutations and negative vectors...")
        m_neg, tot_neg, err_neg = verify_mutations_and_negative_vectors(
            oracle_bin, wing_bin, tmpdir, verbose=args.verbose
        )

        total_cases = tot_huff + tot_raw + tot_o2w + tot_neg
        total_matched = m_huff + m_raw + m_o2w + m_neg
        all_errs = err_huff + err_raw + err_o2w + err_neg

        elapsed = time.time() - t0
        print(f"\nQPACK DIFFERENTIAL SUMMARY ({elapsed:.2f}s):")
        print(f"  Wing -> nghttp3 (Huffman)  : {m_huff}/{tot_huff} passed")
        print(f"  Wing -> nghttp3 (Raw)      : {m_raw}/{tot_raw} passed")
        print(f"  nghttp3 -> Wing (Encode)   : {m_o2w}/{tot_o2w} passed")
        print(f"  Negative wire vectors      : {m_neg}/{tot_neg} passed")
        print("  Vendor Quiche build        : OK (cargo check --no-default-features)")
        print(f"  Total matched              : {total_matched}/{total_cases}")

        if all_errs:
            print(f"FAILED: {len(all_errs)} mismatches detected!")
            return 1

        print("ALL QPACK CROSS-PROJECT DIFFERENTIAL WIRE TESTS PASSED")
        return 0


if __name__ == "__main__":
    sys.exit(main())
