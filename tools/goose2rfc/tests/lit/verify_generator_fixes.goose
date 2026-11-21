// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Regression test for goose2rfc generator fixes:
// 1. Free UFCS `fn ::parse_*`, inline `if ... else` inside `guard`, and exact non-bool `else { return -1; }`.
// 2. Out-ref read intrinsic (`get_u16(ulen)`) binding `ulen` rather than `ok_u` for `Read#0` and `UNCONSTRAINED_INPUT`.
// 3. String literal `"http://..."` preserved without `//` comment truncation, and `` '`' `` escaped safely.
// 4. Multi-line boolean `return` expression joined cleanly across lines.

// RUN: goose run %S/../../src/main.goose -- compile %s --max-inline-depth 3 --format sm.md -o %t.sm.md
// RUN: "%S/../../../bin/goosemarklint" check %t.sm.md
// RUN: "%S/../../../bin/goosemarklint" fmt --check %t.sm.md
// RUN: %FileCheck %s < %t.sm.md

// CHECK: ## Function `parse_custom_tok`
// CHECK: - R1: `s.len` must be at least `(if allow_empty { 0 } else { 1 })`. If `s.len`
// CHECK: is smaller, `parse_custom_tok` returns `-1`.
// CHECK: - R2: ``s.len == 0 || s[0] != '`'``
// CHECK: - R3: `s` must not equal `"http://bad"`
// CHECK: ## Function `decode_out_ref_len`
// CHECK: | `Read#0` | `always` | `be_u16` | `ulen` | `c` |
// CHECK: | `UNCONSTRAINED_INPUT` | `ulen` | `0..0xffff` |
// CHECK: ## Function `validate_multi_kind`
// CHECK: - R1: `kind == 1 || kind == 2` must be `true`.

import std;

struct ByteCursor {
    buf: const u8[:],
    pos: i64 = 0,
}

fn get_u16(c: ByteCursor&, out_val: u16&) -> bool {
    guard c.pos < c.buf.len else { return false; }
    out_val = 0;
    return true;
}

fn ::parse_custom_tok(s: const u8[:], allow_empty: bool) -> i64 {
    guard s.len >= (if allow_empty { 0 } else { 1 }) else { return -1; }
    guard s.len == 0 || s[0] != '`' else { return -1; }
    guard s != "http://bad" else { return -1; }
    return s.len;
}

fn decode_out_ref_len(c: ByteCursor&) -> bool {
    var ulen: u16 = 0;
    let ok_u = get_u16(c, ulen);
    guard ok_u else { return false; }
    return true;
}

fn validate_multi_kind(kind: u8) -> bool {
    return kind == 1
        || kind == 2;
}
