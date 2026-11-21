// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose run %S/../../src/main.goose -- check %s --strict | %FileCheck %s
// CHECK: resolved_symbol: rfc::QUIC_VARINT_MAX = 0x3fffffffffffffff
// CHECK: ufcs_desugar: core::read_u16(c) [READ be_u16]
// CHECK: cast_expr: data.len as_checked u64
// CHECK-NOT: // RFC comment should be stripped

import std;

// RFC comment should be stripped
const QUIC_VARINT_MAX: u64 = 0x3fffffffffffffff;

struct ByteCursor {
    buf: const u8[:],
    pos: i64 = 0,
}

fn read_u16(c: ByteCursor&) -> u16, bool {
    guard c.pos <= c.buf.len else { return 0, false; }
    return 0, true;
}

fn decode_sample_header(c: ByteCursor&, data: const u8[:]) -> u16, bool {
    let len_u64 = data.len as u64;
    guard len_u64 <= QUIC_VARINT_MAX else { return 0, false; }
    let hdr, ok = c.read_u16();
    guard ok else { return 0, false; }
    return hdr, true;
}
