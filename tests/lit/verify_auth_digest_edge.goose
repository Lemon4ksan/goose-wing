// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
import std;
import wire_kit from ".";

// Zero-allocation Digest challenge wire validator (RFC 7616)
fn validate_digest_challenge_wire(buf: const u8[:]) -> i64 {
    let len = buf.len;
    if len <= 0 { return -1; }
    var i: i64 = 0;
    var found_realm = 0;
    var found_nonce = 0;

    while i < len {
        // Skip spaces and commas
        while i < len && (buf[i] == 32 || buf[i] == 9 || buf[i] == 44) {
            i += 1;
        }
        if i >= len { break; }

        let k_start = i;
        while i < len && buf[i] != 61 && buf[i] != 32 && buf[i] != 9 {
            i += 1;
        }
        let k_len = i - k_start;
        if k_len == 0 { return -2; }

        // Must have '=' separator
        while i < len && (buf[i] == 32 || buf[i] == 9) { i += 1; }
        if i >= len { return -1; } // incomplete before '='
        if buf[i] != 61 { return -2; } // missing '='
        i += 1; // skip '='

        while i < len && (buf[i] == 32 || buf[i] == 9) { i += 1; }
        if i >= len { return -1; } // incomplete value

        // Value parsing
        if buf[i] == 34 {
            // Quoted string
            i += 1;
            var closed = 0;
            while i < len {
                let b = buf[i];
                if b == 34 { closed = 1; i += 1; break; }
                if b == 92 && i + 1 < len { i += 1; }
                i += 1;
            }
            if closed == 0 { return -1; } // unclosed quote / incomplete
        } else {
            // Token
            while i < len && buf[i] != 32 && buf[i] != 9 && buf[i] != 44 {
                i += 1;
            }
        }

        if k_len == 5 {
            // Check "realm"
            if buf[k_start] == 114 && buf[k_start + 1] == 101 { found_realm = 1; }
            // Check "nonce"
            if buf[k_start] == 110 && buf[k_start + 1] == 111 { found_nonce = 1; }
        }
    }

    if found_realm == 1 && found_nonce == 1 { return 1; }
    return -1; // Incomplete challenge
}

fn main() {
    let challenge = "realm=\"test@example.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";
    assert(wire_kit::verify_split_stream(challenge, -1, 1, validate_digest_challenge_wire));
    assert(wire_kit::fuzz_payload(challenge, 100, validate_digest_challenge_wire));
    print("DIGEST_CHALLENGE_SPLIT: OK");

    let invalid_missing_eq = "realm \"test\", nonce=\"abc\"";
    assert(validate_digest_challenge_wire(invalid_missing_eq) == -2);
    print("DIGEST_INVALID_EQ: OK");
}

// CHECK: DIGEST_CHALLENGE_SPLIT: OK
// CHECK: DIGEST_INVALID_EQ: OK
