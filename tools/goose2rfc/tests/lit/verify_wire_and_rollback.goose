// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose run %S/../../src/main.goose -- compile %s --format sm.md | %FileCheck %s
// CHECK: | `DISCARDED_WIRE_FIELD` | `Read#1` | `0..0x3fff_ffff_ffff_ffff` |
// CHECK: | `UNCONSTRAINED_INPUT` | `ack_delay_exponent` | `0..0x3fff_ffff_ffff_ffff` |
// CHECK: | `idx` | `DIRTY_EXPOSED` |
// CHECK: | `out` | `TRANSACTIONAL_SELF` |

import std;

const QUIC_VARINT_MAX: u64 = 0x3fffffffffffffff;

struct ByteCursor {
    buf: const u8[:],
    pos: i64 = 0,
}

fn quic_decode_varint_cursor(buf: const u8[:], c: ByteCursor&) -> u64, bool {
    guard c.pos < buf.len else { return 0, false; }
    return 0, true;
}

fn quic_encode_varint<B>(out: B&, val: u64) -> bool {
    guard val <= QUIC_VARINT_MAX else { return false; }
    return true;
}

fn decode_ack_ecn_sample(buf: const u8[:], c: ByteCursor&, idx: i64&) -> u64, bool {
    let ack_delay_exponent, ok0 = quic_decode_varint_cursor(buf, c);
    guard ok0 else { return 0, false; }
    let _, ok1 = quic_decode_varint_cursor(buf, c);
    guard ok1 else { return 0, false; }
    idx = 1;
    let ect1, ok2 = quic_decode_varint_cursor(buf, c);
    guard ok2 && ect1 <= QUIC_VARINT_MAX else { return 0, false; }
    return ack_delay_exponent, true;
}

fn encode_transactional_sample<B>(out: B&, val: u64) -> bool {
    guard val <= QUIC_VARINT_MAX else { return false; }
    let orig_len = out.len;
    var committed = false;
    defer if !committed { out.resize(orig_len, 0); };
    guard quic_encode_varint(out, val) else { return false; }
    committed = true;
    return true;
}
