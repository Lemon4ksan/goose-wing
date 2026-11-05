// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_auth_jwt_edge.goose
// RFC 7515 / RFC 7519 JWT Edge Cases, DoS Defense, and Invariant Verification.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    let secret = "my_super_secret_signing_key_32b!";
    let now_sec: i64 = 1714000000;

    // ---- 1. RFC 7515 §2: Reject '=' Padding in JWS Base64URL ---------------
    var token_with_pad: u8[>..] = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl==";
    var out_h = wing::JwtHeader { .. };
    var out_c = wing::JwtClaims { .. };
    var opts = wing::JwtValidationOptions { .. };
    let err_pad = wing::verify_jwt_hmac(token_with_pad[..], secret, opts, now_sec, out_h, out_c);
    assert(err_pad == wing::JwtError.MalformedToken);
    print("JWT_REJECT_PAD: OK");

    // ---- 2. Transactional State on Verification Failure -------------------
    var valid_hdr = wing::JwtHeader { .. };
    valid_hdr.alg = wing::JwtAlg.HS256;
    var valid_claims = wing::JwtClaims { .. };
    valid_claims.sub.append("secret_admin_user");
    valid_claims.exp = now_sec + 3600;
    var valid_token: u8[>..] = [];
    assert(wing::sign_jwt_hmac(valid_hdr, valid_claims, secret, valid_token));

    var tampered_token: u8[>..] = [];
    tampered_token.append(valid_token[..]);
    tampered_token[tampered_token.len - 1] = if tampered_token[tampered_token.len - 1] == 'a' { 'b' } else { 'a' };

    var fresh_h = wing::JwtHeader { .. };
    var fresh_c = wing::JwtClaims { .. };
    let err_sig = wing::verify_jwt_hmac(tampered_token[..], secret, opts, now_sec, fresh_h, fresh_c);
    assert(err_sig == wing::JwtError.SignatureInvalid || err_sig == wing::JwtError.InvalidBase64);
    assert(fresh_c.sub.len == 0); // Must NOT be populated with unverified claims
    print("JWT_TRANSACTIONAL_STATE: OK");

    // ---- 3. Large Signature DoS Defense -----------------------------------
    var dos_token: u8[>..] = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.";
    for _ in 500 { dos_token.push('A'); }
    var dos_h = wing::JwtHeader { .. };
    var dos_c = wing::JwtClaims { .. };
    let err_dos = wing::verify_jwt_hmac(dos_token[..], secret, opts, now_sec, dos_h, dos_c);
    assert(err_dos == wing::JwtError.SignatureInvalid || err_dos == wing::JwtError.MalformedToken);
    print("JWT_LARGE_SIG_DOS: OK");

    // ---- 4. Escaped Key Smuggling Rejection --------------------------------
    var escaped_crit_hdr = "{\"alg\":\"HS256\",\"\\u0063rit\":[\"custom\"]}";
    var crit_h = wing::JwtHeader { .. };
    assert(!wing::parse_jwt_header_json(escaped_crit_hdr, crit_h));
    print("JWT_ESCAPED_KEY_REJECT: OK");

    // ---- 5. Standard Claim Collision in set_claim -------------------------
    var claims_obj = wing::JwtClaims { .. };
    assert(!wing::set_claim(claims_obj, "exp", "1234567"));
    assert(!wing::set_claim(claims_obj, "sub", "admin"));
    assert(!wing::set_claim_int(claims_obj, "exp", 1234567));
    assert(wing::set_claim(claims_obj, "custom_role", "admin"));
    print("JWT_STANDARD_CLAIM_COLLISION: OK");

    // ---- 6. Integer Reading for Standard Claims ---------------------------
    var num_claims_json = "{\"sub\":\"user1\",\"exp\":1714000100,\"iat\":1714000000}";
    var parsed_c = wing::JwtClaims { .. };
    assert(wing::parse_jwt_claims_json(num_claims_json, parsed_c));
    assert(parsed_c.exp == 1714000100);
    assert(parsed_c.iat == 1714000000);
    assert(!wing::parse_jwt_claims_json("{\"sub\":\"user1\",\"exp\":1e100}", parsed_c));

    var tiny_tok: u8[..32] = [];
    assert(!wing::sign_jwt_hmac(valid_hdr, valid_claims, secret, tiny_tok));
    assert(parsed_c.iss.try_set("valid-issuer"));
    var long_iss: u8[..160] = [];
    for _ in 140 { long_iss.push('x'); }
    assert(!parsed_c.iss.try_set(long_iss[..]));
    assert(parsed_c.iss[..] == "valid-issuer");
    assert(!wing::add_header_crit(valid_hdr, ""));
    assert(!wing::add_header_crit(valid_hdr, "alg"));
    assert(!wing::set_claim(parsed_c, "", "val"));

    // ---- 7. F006: Transactional JSON Parsing, Empty Aud & Supported Crit ---
    var dirty_hdr = wing::JwtHeader { .. };
    assert(!wing::parse_jwt_header_json("{\"kid\":\"leaked-kid\",\"alg\":\"HS256\",\"alg\":\"RS256\"}", dirty_hdr));
    assert(dirty_hdr.kid.len == 0);

    var dirty_clm = wing::JwtClaims { .. };
    assert(!wing::parse_jwt_claims_json("{\"sub\":\"leaked-sub\",\"exp\":1e100}", dirty_clm));
    assert(dirty_clm.sub.len == 0);

    var aud_clm = wing::JwtClaims { .. };
    assert(!wing::set_audience(aud_clm, ""));
    assert(!wing::add_audience(aud_clm, ""));
    assert(aud_clm.audiences.len == 0);

    var crit_opts = wing::JwtValidationOptions { .. };
    assert(!wing::add_supported_crit(crit_opts, "alg"));
    assert(wing::add_supported_crit(crit_opts, "custom_ext"));
    assert(!wing::add_supported_crit(crit_opts, "custom_ext"));
    print("JWT_INT_CLAIMS_PARSING: OK");
}

// CHECK: JWT_REJECT_PAD: OK
// CHECK: JWT_TRANSACTIONAL_STATE: OK
// CHECK: JWT_LARGE_SIG_DOS: OK
// CHECK: JWT_ESCAPED_KEY_REJECT: OK
// CHECK: JWT_STANDARD_CLAIM_COLLISION: OK
// CHECK: JWT_INT_CLAIMS_PARSING: OK
