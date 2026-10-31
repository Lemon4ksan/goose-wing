// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Minimal Perfect Hashing & O(1) Dispatcher for Well-Known HTTP Headers.
// Replaces multi-pass string comparisons and case-folding loops with a
// deterministic length + leading-byte discriminator and single-shot verification.
namespace wing;

import std;

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
}

// Converts an uppercase ASCII character to lowercase.
inline fn ascii_lower(b: u8) -> u8 {
    guard b >= 'A' && b <= 'Z' else { return b; }
    return b | 0x20;
}

// Compares header slice against expected static ASCII lowercase string case-insensitively.
inline fn eq_case_insensitive(actual: const u8[:], expected: const u8[:]) -> bool {
    guard actual.len == expected.len else { return false; }
    for i in actual.len {
        guard ascii_lower(actual[i]) == expected[i] else { return false; }
    }
    return true;
}

inline fn check_header(name: const u8[:], expected: const u8[:], id: KnownHeaderId) -> KnownHeaderId {
    return if eq_case_insensitive(name, expected) { id } else { KnownHeaderId.Unknown };
}

// Identifies well-known HTTP header in O(1) time without linear search.
//
// Example:
//   name = "Content-Length"
//   returns: KnownHeaderId.ContentLength
fn identify_known_header(name: const u8[:]) -> KnownHeaderId {
    guard name.len >= 4 && name.len <= 21 else {
        return KnownHeaderId.Unknown;
    }

    let first = ascii_lower(name[0]);

    return match name.len {
        4 => match first {
            'h' => check_header(name, "host", KnownHeaderId.Host),
            'd' => check_header(name, "date", KnownHeaderId.Date),
            _ => KnownHeaderId.Unknown,
        },
        6 => match first {
            'a' => check_header(name, "accept", KnownHeaderId.Accept),
            'c' => check_header(name, "cookie", KnownHeaderId.Cookie),
            'o' => check_header(name, "origin", KnownHeaderId.Origin),
            's' => check_header(name, "server", KnownHeaderId.Server),
            _ => KnownHeaderId.Unknown,
        },
        10 => match first {
            'c' => check_header(name, "connection", KnownHeaderId.Connection),
            'u' => check_header(name, "user-agent", KnownHeaderId.UserAgent),
            _ => KnownHeaderId.Unknown,
        },
        12 => check_header(name, "content-type", KnownHeaderId.ContentType),
        13 => check_header(name, "authorization", KnownHeaderId.Authorization),
        14 => check_header(name, "content-length", KnownHeaderId.ContentLength),
        17 => match first {
            't' => check_header(name, "transfer-encoding", KnownHeaderId.TransferEncoding),
            's' => check_header(name, "sec-websocket-key", KnownHeaderId.SecWebSocketKey),
            _ => KnownHeaderId.Unknown,
        },
        _ => KnownHeaderId.Unknown,
    };
}
