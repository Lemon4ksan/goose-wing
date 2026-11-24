// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Explicitly zeroizable byte-buffer wrapper for sensitive credentials and tokens.
namespace core;

import std;
import .crypto;

// Wrapper for sensitive byte payloads (`u8[..N]` or `u8[>..]`).
// Redacted by HTTP JSON/query encoders; callers inspect `.val[..]` directly when
// intentionally crossing a verified cryptographic or explicit wire boundary.
struct Secret<B> {
    val: B = default<B>(),
}

// Wipes underlying secret bytes and clears slice length.
fn zeroize<B>(s: Secret<B>&) {
    secure_zeroize_slice(s.val[..]);
    s.val.clear();
}

// Compares `Secret<B>` against `b` in constant time without early exit on byte mismatches.
fn ct_eq<B>(a: const Secret<B>&, b: const u8[:]) -> bool {
    return ct_eq_bytes(a.val[..], b);
}
