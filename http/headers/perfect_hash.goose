// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Minimal Perfect Hashing & O(1) Dispatcher for Well-Known HTTP Headers.
// Replaces multi-pass string comparisons and case-folding loops with a
// deterministic length + leading-byte discriminator and single-shot verification.
namespace http;

import std;
import core;

enum KnownHeaderId {
    Unknown,
    Host,
    Date,
    Accept,
    Cookie,
    Origin,
    Server,
    Connection,
    UserAgent,
    ContentType,
    ContentLength,
    Authorization,
    TransferEncoding,
    SecWebSocketKey,
    Upgrade,
    Expect,
}

// Converts a KnownHeaderId to a bit flag for 32-bit presence masks.
checkfree inline fn header_id_to_bit(id: KnownHeaderId) -> u32 {
    var bit: u32 = 0;
    const for <N, V> in variants<KnownHeaderId> {
        let v: KnownHeaderId = default<V>();
        if id == v { return if bit == 0 { 0 } else { (1 as u32) << bit }; }
        bit += 1;
    }
    return 0;
}

// Identifies hot-path HTTP headers in O(1) via (len, lowercase first byte) dispatch
// and direct ASCII case-folded comparison without scanning the 63-header table.
//
// Example:
//   name = "Content-Length"
//   returns: KnownHeaderId.ContentLength
inline fn identify_known_header(name: const u8[:]) -> KnownHeaderId {
    let n = name.len;
    guard n >= 4 && n <= 17 else { return KnownHeaderId.Unknown; }
    let key = ((n as u16) << 8) | core::to_lower_ascii_byte(name[0]);
    return match key {
        0x0468 => if name.eq_ascii_fold("host") { KnownHeaderId.Host } else { KnownHeaderId.Unknown },
        0x0464 => if name.eq_ascii_fold("date") { KnownHeaderId.Date } else { KnownHeaderId.Unknown },
        0x0661 => if name.eq_ascii_fold("accept") { KnownHeaderId.Accept } else { KnownHeaderId.Unknown },
        0x0663 => if name.eq_ascii_fold("cookie") { KnownHeaderId.Cookie } else { KnownHeaderId.Unknown },
        0x066F => if name.eq_ascii_fold("origin") { KnownHeaderId.Origin } else { KnownHeaderId.Unknown },
        0x0673 => if name.eq_ascii_fold("server") { KnownHeaderId.Server } else { KnownHeaderId.Unknown },
        0x0665 => if name.eq_ascii_fold("expect") { KnownHeaderId.Expect } else { KnownHeaderId.Unknown },
        0x0775 => if name.eq_ascii_fold("upgrade") { KnownHeaderId.Upgrade } else { KnownHeaderId.Unknown },
        0x0A63 => if name.eq_ascii_fold("connection") { KnownHeaderId.Connection } else { KnownHeaderId.Unknown },
        0x0A75 => if name.eq_ascii_fold("user-agent") { KnownHeaderId.UserAgent } else { KnownHeaderId.Unknown },
        0x0C63 => if name.eq_ascii_fold("content-type") { KnownHeaderId.ContentType } else { KnownHeaderId.Unknown },
        0x0D61 => if name.eq_ascii_fold("authorization") {
            KnownHeaderId.Authorization
        } else {
            KnownHeaderId.Unknown
        },
        0x0E63 => if name.eq_ascii_fold("content-length") {
            KnownHeaderId.ContentLength
        } else {
            KnownHeaderId.Unknown
        },
        0x1174 => if name.eq_ascii_fold("transfer-encoding") {
            KnownHeaderId.TransferEncoding
        } else {
            KnownHeaderId.Unknown
        },
        0x1173 => if name.eq_ascii_fold("sec-websocket-key") {
            KnownHeaderId.SecWebSocketKey
        } else {
            KnownHeaderId.Unknown
        },
        _ => KnownHeaderId.Unknown,
    };
}
