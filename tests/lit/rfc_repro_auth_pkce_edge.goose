// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_auth_pkce_edge.goose
// RFC 7636 PKCE & RFC 8555 ACME Edge Cases, Padding Invariants, and Strict Verification.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    // ---- 1. RFC 7636 Appendix B Official Test Vector -----------------------
    let rfc_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    var computed_chal: u8[..64] = [];
    assert(wing::compute_code_challenge(rfc_verifier, "S256", computed_chal));
    assert(computed_chal[..] == expected_challenge);
    assert(wing::validate_code_challenge(rfc_verifier, expected_challenge, "S256"));
    print("PKCE_OFFICIAL_VECTOR: OK");

    // ---- 2. RFC 7636 §4.2 Canonical S256 Padding Validation ----------------
    // 'M' at index 42 has bits 1..0 as 00 (canonical padding bits).
    assert(wing::is_valid_code_challenge(expected_challenge, "S256"));

    // Mutate the 43rd character to 'N' (bits 1..0 != 00)
    var non_canonical: u8[..64] = [];
    non_canonical.append(expected_challenge[..42]);
    non_canonical.push('N');
    assert(!wing::is_valid_code_challenge(non_canonical[..], "S256"));
    print("PKCE_CANONICAL_PADDING: OK");

    // ---- 3. RFC 7636 §4.1 Bounds and Disallowed Characters -----------------
    // Length < 43 rejected
    assert(!wing::is_valid_code_verifier("short_verifier_less_than_43_chars_long"));
    // Length > 128 rejected
    var too_long: u8[..140] = [];
    for i in 129 {
        too_long.push('a');
    }
    assert(!wing::is_valid_code_verifier(too_long[..]));
    // Disallowed chars (like padding '=' or '+' or '/')
    assert(!wing::is_valid_code_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk="));
    assert(!wing::is_valid_code_verifier("dBjftJeZ4CVP+mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
    print("PKCE_BOUNDS_AND_CHARS: OK");

    // ---- 4. RFC 7636 §4.3 Method Case-Sensitivity & OAuth 2.1 Strict -------
    var chal_out: u8[..64] = [];
    // Lowercase method must be rejected
    assert(!wing::compute_code_challenge(rfc_verifier, "s256", chal_out));
    assert(!wing::compute_code_challenge(rfc_verifier, "Plain", chal_out));
    // Strict mode rejects "plain"
    assert(!wing::is_valid_code_challenge_strict(rfc_verifier, "plain"));
    assert(!wing::validate_code_challenge_strict(rfc_verifier, rfc_verifier, "plain"));
    assert(wing::is_valid_code_challenge_strict(expected_challenge, "S256"));
    print("PKCE_METHOD_AND_STRICT: OK");

    // ---- 5. RFC 8555 §8.1 & §8.3 ACME Challenge Primitives ----------------
    var key_auth: u8[..256] = [];
    let tok = "LoGraphic_Token-123";
    let thumb = "kda76_thumbprint-456";
    let auth_len = wing::acme_key_authorization(tok, thumb, key_auth);
    assert(auth_len > 0);
    assert(key_auth[..] == "LoGraphic_Token-123.kda76_thumbprint-456");

    // ACME token traversal attempts rejected
    assert(!wing::acme_validate_token("../secret"));
    assert(!wing::acme_validate_token("token.with.dot"));
    assert(!wing::acme_validate_token("token/slash"));
    assert(!wing::acme_validate_token("token with space"));
    assert(!wing::acme_validate_token(""));

    // ACME HTTP-01 matching
    var acme_table: wing::AcmeChallenge[..8] = [];
    var ch_entry = wing::AcmeChallenge {
        token:        "challenge_tok_1",
        key_auth:     "challenge_tok_1.account_tp",
        key_auth_len: 26,
    };
    acme_table.push(ch_entry);

    var out_resp: u8[..256] = [];
    var out_len:  i32       = 0;
    assert(wing::acme_find_challenge(acme_table, "/.well-known/acme-challenge/challenge_tok_1", out_resp, out_len));
    assert(out_len == 26);
    assert(out_resp[..] == "challenge_tok_1.account_tp");

    // Path traversal or mismatched path rejected
    assert(!wing::acme_find_challenge(acme_table, "/.well-known/acme-challenge/../other", out_resp, out_len));
    assert(!wing::acme_find_challenge(acme_table, "/api/v1/challenge_tok_1", out_resp, out_len));

    // ---- 6. ACME Thumbprint Validation & PKCE Small Buffer Bounds ----------
    assert(wing::acme_key_authorization(tok, "", key_auth) == -1);
    assert(wing::acme_key_authorization(tok, "bad/thumbprint", key_auth) == -1);
    assert(wing::acme_key_authorization(tok, "bad.thumbprint", key_auth) == -1);

    var tiny_buf: u8[..32] = [];
    assert(!wing::compute_code_challenge(rfc_verifier, "S256", tiny_buf));
    assert(!wing::compute_code_challenge(rfc_verifier, "plain", tiny_buf));
    assert(!wing::generate_code_verifier(tiny_buf));
    assert(!wing::generate_code_verifier(tiny_buf, "0123456789abcdef0123456789abcdef"));
    print("ACME_PRIMITIVES: OK");
}

// CHECK: PKCE_OFFICIAL_VECTOR: OK
// CHECK: PKCE_CANONICAL_PADDING: OK
// CHECK: PKCE_BOUNDS_AND_CHARS: OK
// CHECK: PKCE_METHOD_AND_STRICT: OK
// CHECK: ACME_PRIMITIVES: OK
