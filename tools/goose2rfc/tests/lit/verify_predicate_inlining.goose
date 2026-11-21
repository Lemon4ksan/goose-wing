// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose run %S/../../src/main.goose -- compile %s --max-inline-depth 3 --format sm.md | %FileCheck %s
// CHECK: | `Write#0` | `always` | `varint62` | `0x08 \| (if flags.with_offset { 0x04 } else { 0 })
// CHECK: - R4: `0x3fff_ffff_ffff_ffff -_u64_wrap offset` must be at least

import std;

const QUIC_VARINT_MAX: u64 = 0x3fffffffffffffff;

struct QuicStreamFlags {
    fin:         bool = false,
    with_len:    bool = false,
    with_offset: bool = false,
}

fn quic_valid_offset_len(offset: u64, length: u64) -> bool {
    guard offset <= QUIC_VARINT_MAX else { return false; }
    guard length <= QUIC_VARINT_MAX else { return false; }
    guard QUIC_VARINT_MAX - offset >= length else { return false; }
    return true;
}

fn build_stream_frame_type(flags: QuicStreamFlags) -> u64 {
    var ftype: u64 = 0x08;
    if flags.with_offset { ftype |= 0x04; }
    if flags.with_len { ftype |= 0x02; }
    if flags.fin { ftype |= 0x01; }
    return ftype;
}

fn quic_encode_varint<B>(out: B&, val: u64) -> bool {
    guard val <= QUIC_VARINT_MAX else { return false; }
    return true;
}

fn try_append<B>(out: B&, data: const u8[:]) -> bool {
    return data.len >= 0;
}

fn encode_stream_frame_explicit<B>(
    out:       B&,
    stream_id: u64,
    offset:    u64,
    data:      const u8[:],
    flags:     QuicStreamFlags,
) -> bool {
    guard stream_id <= QUIC_VARINT_MAX else { return false; }
    guard quic_valid_offset_len(offset, data.len as u64) else { return false; }

    let orig_len = out.len;
    var committed = false;
    defer if !committed { out.resize(orig_len, 0); };

    let ftype = build_stream_frame_type(flags);
    guard quic_encode_varint(out, ftype) && quic_encode_varint(out, stream_id) else {
        return false;
    }
    if flags.with_offset {
        guard quic_encode_varint(out, offset) else { return false; }
    }
    if flags.with_len {
        guard quic_encode_varint(out, data.len as u64) else { return false; }
    }
    guard out.try_append(data) else { return false; }
    committed = true;
    return true;
}
