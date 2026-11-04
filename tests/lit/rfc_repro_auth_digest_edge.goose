// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_auth_digest_edge.goose
// RFC 7616 Digest Edge Cases, Header Injection Defense, and State Synchronization.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    // ---- 1. RFC 7616 §3.4 URI Injection Defense ----------------------------
    var uri_sink: u8[..128] = [];
    assert(!wing::append_digest_uri(uri_sink, "/path/with\\backslash"));
    assert(!wing::append_digest_uri(uri_sink, "/path/with\"quote"));
    assert(!wing::append_digest_uri(uri_sink, "/path/with\r\nCRLF"));
    assert(wing::append_digest_uri(uri_sink, "/valid/path/to/resource"));
    print("DIGEST_URI_DEFENSE: OK");

    // ---- 2. RFC 7616 §3.4 & §3.4.1 Mandatory cnonce / nc Checks ------------
    var chal = wing::DigestChallenge {
        realm:     "test_realm",
        nonce:     "test_nonce_123",
        algorithm: "SHA-256",
        qop:       "auth",
        valid:     true,
        ..
    };
    var creds = wing::DigestCredentials {
        username: "user",
        password: "pwd",
    };
    var resp_header: u8[..1024] = [];

    // Empty cnonce with active qop MUST fail
    let ok_empty_cnonce = wing::compute_digest_response(chal, creds, "GET", "/api", 1, "", "", resp_header);
    assert(!ok_empty_cnonce);

    // nc == 0 with active qop MUST fail
    let ok_zero_nc = wing::compute_digest_response(chal, creds, "GET", "/api", 0, "client_nonce_xyz", "", resp_header);
    assert(!ok_zero_nc);

    // Valid parameters MUST succeed
    let ok_valid = wing::compute_digest_response(chal, creds, "GET", "/api", 1, "client_nonce_xyz", "", resp_header);
    assert(ok_valid);
    print("DIGEST_CNONCE_NC_VALIDATION: OK");

    // ---- 3. RFC 7616 §3.3 Stale Challenge Synchronization ------------------
    var stored = wing::DigestChallenge {
        realm:     "old_realm",
        nonce:     "old_nonce",
        algorithm: "MD5",
        qop:       "auth",
        userhash:  false,
        valid:     true,
        ..
    };
    var incoming = wing::DigestChallenge {
        realm:     "new_realm",
        nonce:     "fresh_nonce_456",
        algorithm: "SHA-256",
        qop:       "auth-int",
        domain:    "https://auth.example.com",
        userhash:  true,
        stale:     true,
        valid:     true,
        ..
    };
    var nc: u32 = 42;
    assert(wing::sync_digest_stale_challenge(stored, incoming, creds, nc));
    assert(nc == 1);
    assert(stored.nonce[..] == "fresh_nonce_456");
    assert(stored.algorithm[..] == "SHA-256");
    assert(stored.qop[..] == "auth-int");
    assert(stored.domain[..] == "https://auth.example.com");
    assert(stored.userhash);
    print("DIGEST_STALE_SYNC: OK");
}

// CHECK: DIGEST_URI_DEFENSE: OK
// CHECK: DIGEST_CNONCE_NC_VALIDATION: OK
// CHECK: DIGEST_STALE_SYNC: OK
