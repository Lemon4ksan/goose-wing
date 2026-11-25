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
checkfree fn header_id_to_bit(id: KnownHeaderId) -> u32 {
    var bit: u32 = 0;
    const for <N, V> in variants<KnownHeaderId> {
        let v: KnownHeaderId = default<V>();
        if id == v { return if bit == 0 { 0 } else { (1 as u32) << bit }; }
        bit += 1;
    }
    return 0;
}

// Identifies well-known HTTP header in O(1) time without linear search.
//
// Example:
//   name = "Content-Length"
//   returns: KnownHeaderId.ContentLength
fn identify_known_header(name: const u8[:]) -> KnownHeaderId {
    return match classify_well_known_header(name) {
        Host => KnownHeaderId.Host,
        Date => KnownHeaderId.Date,
        Accept => KnownHeaderId.Accept,
        Cookie => KnownHeaderId.Cookie,
        OriginHeader => KnownHeaderId.Origin,
        Server => KnownHeaderId.Server,
        Connection => KnownHeaderId.Connection,
        UserAgent => KnownHeaderId.UserAgent,
        ContentType => KnownHeaderId.ContentType,
        ContentLength => KnownHeaderId.ContentLength,
        Authorization => KnownHeaderId.Authorization,
        TransferEncoding => KnownHeaderId.TransferEncoding,
        Upgrade => KnownHeaderId.Upgrade,
        Expect => KnownHeaderId.Expect,
        _ => if name.eq_ascii_fold("sec-websocket-key") {
            KnownHeaderId.SecWebSocketKey
        } else {
            KnownHeaderId.Unknown
        },
    };
}
