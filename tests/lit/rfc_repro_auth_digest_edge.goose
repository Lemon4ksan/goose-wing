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

    // ---- 4. Mandatory Field & Response Hex Validation ----------------------
    var empty_user_creds = wing::DigestCredentials { username: "", password: "pwd" };
    assert(!wing::compute_digest_response(chal, empty_user_creds, "GET", "/api", 1, "cnonce123", "", resp_header));

    var sink_empty_resp: u8[..512] = [];
    assert(!wing::serialize_digest_auth("user", "realm", "nonce", "/api", "SHA-256", "", "auth", "00000001", "cnonce", "", false, sink_empty_resp));

    let ha2_bad_method = wing::calculate_digest_ha2("SHA-256", "", "/api", false, "");
    assert(ha2_bad_method.len == 0);
    let ha2_bad_uri = wing::calculate_digest_ha2("SHA-256", "GET", "", false, "");
    assert(ha2_bad_uri.len == 0);
    print("DIGEST_MANDATORY_FIELD_VALIDATION: OK");

    // ---- 5. Session Algorithm & auth-int Verification ----------------------
    assert(rfc::is_sess_digest_algo("SHA-256-sess"));
    assert(rfc::is_sess_digest_algo("MD5-sess"));
    assert(rfc::is_sess_digest_algo("SHA-512-256-sess"));
    assert(!rfc::is_sess_digest_algo("SHA-256"));
    assert(!rfc::is_sess_digest_algo("MD5"));

    let ha1_sess_no_cnonce = wing::calculate_digest_ha1("SHA-256-sess", "user", "realm", "pwd", "nonce", "");
    assert(ha1_sess_no_cnonce.len == 0);
    let ha1_sess_no_nonce = wing::calculate_digest_ha1("SHA-256-sess", "user", "realm", "pwd", "", "cnonce");
    assert(ha1_sess_no_nonce.len == 0);

    let ha2_auth = wing::calculate_digest_ha2("SHA-256", "POST", "/api", false, "body data");
    let ha2_auth_int = wing::calculate_digest_ha2("SHA-256", "POST", "/api", true, "body data");
    assert(ha2_auth.len == 64 && ha2_auth_int.len == 64);
    assert(ha2_auth[..] != ha2_auth_int[..]);
    print("DIGEST_SESS_AND_AUTH_INT: OK");

    // ---- 6. Grammar & State Invariants -------------------------------------
    let chal_empty_tok, chal_ok = wing::parse_digest_challenge("realm=, nonce=\"123\"");
    assert(!chal_ok);

    var uninit_stored = wing::DigestChallenge { valid: false, .. };
    assert(!wing::sync_digest_stale_challenge(uninit_stored, incoming, creds, nc));

    // ---- 7. F005: RFC 7616 Token Grammar, QOP Delimiters & Sink Hygiene ----
    let _, ok_ctrl_key = wing::parse_digest_challenge("Digest bad;key=\"val\", realm=\"r\", nonce=\"n\"");
    assert(!ok_ctrl_key);
    let _, ok_trailing_junk = wing::parse_digest_challenge("Digest realm=\"r\"junk, nonce=\"n\"");
    assert(!ok_trailing_junk);
    let _, ok_bad_unquoted = wing::parse_digest_challenge("Digest realm=\"r\", nonce=\"n\", algorithm=SHA\"256");
    assert(!ok_bad_unquoted);

    assert(!wing::qop_list_has_token("auth bogus", "auth"));
    assert(!wing::qop_list_has_token("bogus auth", "auth"));
    assert(wing::qop_list_has_token("auth, auth-int", "auth"));

    var tiny_sink: u8[..48] = [];
    assert(!wing::serialize_digest_auth("Mufasa", "http-auth@example.org", "nonce123", "/dir/index.html", "SHA-256", "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1", "auth", "00000001", "cnonce123", "", false, tiny_sink));
    assert(tiny_sink.len == 0);
    print("DIGEST_INVARIANTS_AND_GRAMMAR: OK");
}

// CHECK: DIGEST_URI_DEFENSE: OK
// CHECK: DIGEST_CNONCE_NC_VALIDATION: OK
// CHECK: DIGEST_STALE_SYNC: OK
// CHECK: DIGEST_MANDATORY_FIELD_VALIDATION: OK
// CHECK: DIGEST_SESS_AND_AUTH_INT: OK
// CHECK: DIGEST_INVARIANTS_AND_GRAMMAR: OK
