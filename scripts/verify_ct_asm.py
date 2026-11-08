#!/usr/bin/env python3

# SPDX-License-Identifier: Apache-2.0
# Copyright (c) 2026 Lemon4ksan

"""scripts/verify_ct_asm.py.

Machine-level constant-time assembly and Dudect statistical timing verifier.
1. Emits C source from tests/lit/verify_constant_time_dudect.goose via `goose --standalone`.
2. Compiles to x86_64 assembly (`gcc -O3 -S`) and inspects the generated instruction
   stream of `wing_ct_eq_tag16_asm` and `wing_ct_eq_tag32_asm` to verify that after the
   initial public-length guard (`len == 16` / `len == 32`), all secret-byte comparisons
   compile to branchless bitwise XOR/OR/SHIFT/SETCC instructions with zero secret-dependent
   conditional jumps.
3. Executes the native LIT suite `tests/lit/verify_constant_time_dudect.goose` (Welch's t-test).
"""

import argparse
import re
import subprocess
import sys
from pathlib import Path

COND_BRANCH_MNEMONICS = {
    "je",
    "jne",
    "jz",
    "jnz",
    "jg",
    "jge",
    "jl",
    "jle",
    "ja",
    "jae",
    "jb",
    "jbe",
    "js",
    "jns",
    "jo",
    "jno",
    "jp",
    "jnp",
}


def extract_asm_function(asm_text: str, fn_prefix: str) -> tuple[str, list[str]]:
    lines = asm_text.splitlines()
    in_fn = False
    actual_symbol = ""
    body: list[str] = []
    start_re = re.compile(rf"^({re.escape(fn_prefix)}(?:_[a-zA-Z0-9_]+)?):")
    end_re = re.compile(
        r"^\s*\.(cfi_endproc|seh_endproc)\b|^_[a-zA-Z0-9_]+:|^[a-zA-Z_][a-zA-Z0-9_.]*:"
    )

    for line in lines:
        if not in_fn:
            m = start_re.match(line)
            if m:
                in_fn = True
                actual_symbol = m.group(1)
        else:
            if end_re.match(line):
                break
            stripped = line.strip()
            if not stripped or stripped.startswith((".", "#")):
                continue
            body.append(stripped)
    return actual_symbol, body


def analyze_tag_compare_asm(
    fn_prefix: str, symbol: str, instructions: list[str]
) -> tuple[bool, str]:
    if not instructions:
        return False, f"{fn_prefix}: symbol not found in generated assembly"

    # Fixed-length constant-time tag comparators (`core::ct_eq_tag16`, `core::ct_eq_tag32`)
    # must compile to pure straight-line SIMD/GPR bitwise instructions (movdqu/movq,
    # pxor/xorq, por/orq, negq, shrq) with zero conditional branches anywhere in the body.
    seen_xor_on_data = False
    branches: list[str] = []

    for ins in instructions:
        parts = ins.split(None, 1)
        if not parts:
            continue
        mnemonic = parts[0].lower()
        operands = parts[1] if len(parts) > 1 else ""

        if mnemonic.startswith(("xor", "pxor", "vxor")):
            ops = [op.strip() for op in operands.split(",")]
            if len(ops) == 2 and ops[0] != ops[1]:
                seen_xor_on_data = True

        if mnemonic in COND_BRANCH_MNEMONICS:
            branches.append(ins)

    if not seen_xor_on_data:
        return False, f"{symbol}: no bitwise XOR instruction found in assembly body"

    if branches:
        return (
            False,
            f"{symbol}: conditional branch instruction detected in constant-time body: {branches}",
        )

    return (
        True,
        f"{symbol}: verified 100% branchless machine code "
        f"({len(instructions)} straight-line instructions, 0 conditional branches)",
    )


def main() -> int:
    parser = argparse.ArgumentParser(
        description="Verify constant-time assembly and Dudect Welch t-test for goose-wing"
    )
    parser.add_argument("--cc", default="gcc", help="C compiler implementing -O3 -S")
    args = parser.parse_args()

    root = Path(__file__).resolve().parent.parent
    cache_dir = root / ".lit" / "cache" / "ct_asm"
    cache_dir.mkdir(parents=True, exist_ok=True)

    lit_src = root / "tests" / "lit" / "verify_constant_time_dudect.goose"
    c_out = cache_dir / "ct_asm.c"
    h_out = cache_dir / "ct_asm.h"
    s_out = cache_dir / "ct_asm.s"

    # 1. Emit standalone C from Goose
    cmd_goose = ["goose", "--standalone", "--header", str(h_out), "-o", str(c_out), str(lit_src)]
    res = subprocess.run(cmd_goose, cwd=root, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(f"goose C emission failed:\n{res.stdout}\n{res.stderr}\n")
        return 1

    # 2. Compile C to optimized x86_64 assembly (-O3 -S)
    cmd_cc = [args.cc, "-O3", "-S", str(c_out), "-o", str(s_out)]
    res = subprocess.run(cmd_cc, cwd=root, capture_output=True, text=True)
    if res.returncode != 0:
        sys.stderr.write(f"Assembly generation failed:\n{res.stdout}\n{res.stderr}\n")
        return 1

    asm_text = s_out.read_text(encoding="utf-8", errors="replace")
    for fn_prefix in ("core_ct_eq_tag16", "core_ct_eq_tag32"):
        symbol, ins = extract_asm_function(asm_text, fn_prefix)
        ok, report = analyze_tag_compare_asm(fn_prefix, symbol, ins)
        print(report)
        if not ok:
            return 1

    # 3. Execute native LIT suite (Dudect Welch t-test + KeySlot zeroization)
    res_lit = subprocess.run(["goose-lit", str(lit_src)], cwd=root, capture_output=True, text=True)
    sys.stdout.write(res_lit.stdout)
    if res_lit.returncode != 0:
        sys.stderr.write(res_lit.stderr)
        return 1

    print("OK CONSTANT_TIME_ASM_AND_DUDECT_VERIFIED")
    return 0


if __name__ == "__main__":
    sys.exit(main())
