// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_auth_digest_edge.goose
// Verification of RFC 7616 HTTP Digest authentication challenge parsing via wing::auth.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// Wire validator for RFC 7616 Digest challenge using wing::parse_digest_challenge
fn wing_validate_digest_challenge_wire(buf: const u8[:]) -> i64 {
    let chal, ok = wing::parse_digest_challenge(buf);
    if ok {
        return 1;
    }

    // Check for explicit syntax violation (e.g. key without '=' delimiter)
    var idx: i64 = 0;
    while idx < buf.len {
        let rem = buf[idx..].trim_start_bytes(" \t,\r\n");
        idx = buf.len - rem.len;
        guard idx < buf.len else { break; }

        let key, key_ok = wing::parse_digest_param_key(buf, idx);
        guard key_ok else { break; }

        let rem_pre = buf[idx..].trim_start_bytes(" \t");
        if rem_pre.len > 0 && rem_pre[0] != '=' {
            return -2;
        }

        var val: u8[..128] = [];
        let val_ok = wing::parse_digest_param_val(buf, idx, val);
        guard val_ok else { break; }
    }

    return -1;
}

fn main() {
    let challenge = "realm=\"test@example.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";
    assert(wire_kit::verify_split_stream(challenge, -1, 1, wing_validate_digest_challenge_wire));
    assert(wire_kit::fuzz_payload(challenge, 100, wing_validate_digest_challenge_wire));

    let parsed_chal, chal_ok = wing::parse_digest_challenge(challenge);
    assert(chal_ok);
    assert(parsed_chal.realm == "test@example.com");
    assert(parsed_chal.nonce == "dcd98b7102dd2f0e8b11d0f600bfb0c093");
    print("DIGEST_CHALLENGE_SPLIT: OK");

    let invalid_missing_eq = "realm \"test\", nonce=\"abc\"";
    assert(wing_validate_digest_challenge_wire(invalid_missing_eq) == -2);
    print("DIGEST_INVALID_EQ: OK");
}

// CHECK: DIGEST_CHALLENGE_SPLIT: OK
// CHECK: DIGEST_INVALID_EQ: OK
