// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// OS-backed cryptographically secure pseudorandom byte generator (CSPRNG).
// Uses BCryptGenRandom or RtlGenRandom on Windows, getrandom(2) on Linux,
// and /dev/urandom on POSIX, failing closed and wiping output on error.
namespace core;

import std;
import core.crypto.ct;
import core.math.bits;
import core.time.sim;

extern fn native_core_csprng(out: u8[:]) -> i32 = "wing_crypto_random_bytes";

// Fills `dst` with cryptographically secure random bytes from the host OS CSPRNG,
// or from the deterministic simulation PRNG when DST entropy override is active.
// Returns false on empty slice or OS entropy failure, wiping `dst` on error.
fn csprng_fill(dst: u8[:]) -> bool {
    guard dst.len > 0 else { return false; }
    if sim_rng_is_active() {
        return sim_rng_fill(dst);
    }
    let rc = native_core_csprng(dst);
    if rc != 0 {
        secure_zeroize_slice(dst);
        return false;
    }
    return true;
}

// Returns a cryptographically secure random 64-bit unsigned integer from the host OS CSPRNG.
// Wipes the stack scratch buffer before returning.
fn csprng_u64() -> u64, bool {
    var buf: u8[8] = [0; 8];
    guard csprng_fill(buf[..]) else {
        return 0, false;
    }
    let val = read_le_u64(buf[..], 0);
    secure_zeroize_slice(buf[..]);
    return val, true;
}
