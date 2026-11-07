// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_auth_audit_hunter.goose
// RFC Conformance and Bug Hunter Repro for Auth Subsystem:
// 1. RFC 8725 §3.1: verify_jwt_hmac must reject non-HMAC alg with AlgorithmMismatch
// 2. RFC 7518 §6.3.2.7: parse_jwks_json must reject JWKs containing 'oth' private key parameter
// 3. RFC 7616 §3.4: sync_digest_stale_challenge must permit empty password (passwd = *OCTET)
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_jwt_hmac_alg_confusion() {
    var opts_eddsa = wing::JwtValidationOptions { .. };
    opts_eddsa.expected_alg = wing::JwtAlg.EdDSA;
    var eddsa_h = wing::JwtHeader { .. };
    var eddsa_c = wing::JwtClaims { .. };

    // Header: {"alg":"EdDSA","typ":"JWT"} -> eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9
    // Claims: {"sub":"alice"}              -> eyJzdWIiOiJhbGljZSJ9
    // Sig:    c2lnbmF0dXJl
    let eddsa_token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl";
    let err = wing::verify_jwt_hmac(
        eddsa_token,
        "dummy_key_01234567890123456789!",
        opts_eddsa,
        1714000000,
        eddsa_h,
        eddsa_c,
    );
    assert(err == wing::JwtError.AlgorithmMismatch);
    print("REPRO_JWT_HMAC_ALG_CONFUSION: PASS");
}

fn test_jwks_reject_oth_private_key() {
    let jwk_oth = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"oth\":[{\"r\":\"dummy\"}],\"kid\":\"key-oth\"}]}";
    var jwks_oth = wing::Jwks { .. };
    let parsed = wing::parse_jwks_json(jwk_oth, jwks_oth);
    assert(!parsed);
    assert(jwks_oth.keys.len == 0);
    print("REPRO_JWKS_REJECT_OTH: PASS");
}

fn test_digest_stale_empty_password() {
    var stored_chal = wing::DigestChallenge { .. };
    stored_chal.valid = true;
    stored_chal.nonce.append("old_nonce_1");
    stored_chal.realm.append("api@example.com");
    stored_chal.algorithm.clear();
    stored_chal.algorithm.append("SHA-256");
    stored_chal.has_explicit_algo = true;

    var incoming_chal = wing::DigestChallenge { .. };
    incoming_chal.valid = true;
    incoming_chal.stale = true;
    incoming_chal.nonce.append("fresh_nonce_2");
    incoming_chal.realm.append("api@example.com");
    incoming_chal.algorithm.clear();
    incoming_chal.algorithm.append("SHA-256");
    incoming_chal.has_explicit_algo = true;

    var empty_pwd_creds = wing::DigestCredentials { .. };
    empty_pwd_creds.username.append("guest_user");
    // password is intentionally empty per RFC 7616 passwd = *OCTET

    var nc: u32 = 5;
    let sync_ok = wing::sync_digest_stale_challenge(stored_chal, incoming_chal, empty_pwd_creds, nc);
    assert(sync_ok);
    assert(stored_chal.nonce == "fresh_nonce_2");
    assert(nc == 1);
    print("REPRO_DIGEST_EMPTY_PASSWORD_STALE: PASS");
}

fn test_jwe_dir_a256gcm_and_concat_kdf() {
    let z: u8[32] = [
        0x9e, 0x56, 0xd9, 0x1d, 0x81, 0x71, 0x35, 0xd3,
        0x72, 0x83, 0x42, 0x83, 0xbf, 0x84, 0x26, 0x9c,
        0xfb, 0x31, 0x6e, 0xa3, 0xda, 0x80, 0x6a, 0x48,
        0xf6, 0xda, 0xa7, 0x79, 0x8c, 0xfe, 0x90, 0xc4,
    ];
    let cek = wing::concat_kdf_sha256(z, "A256GCM", "Alice", "Bob", 256);
    let iv: u8[12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let protected_b64 = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0";
    var compact: u8[..512] = [];
    assert(wing::jwe_seal_dir_a256gcm(protected_b64, cek, iv, "top_secret_payload", compact));
    var opened: u8[..256] = [];
    assert(wing::jwe_open_dir_a256gcm(compact[..], cek, opened));
    assert(opened[..] == "top_secret_payload");

    // Non-empty encrypted key must be rejected for "dir"
    let bad_compact = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0.YWJj.AQIDBAUGBwgJCgsM.Y2lwaGVy.AAAAAAAAAAAAAAAAAAAAAA";
    assert(!wing::jwe_open_dir_a256gcm(bad_compact, cek, opened));
    print("AUTHJOSE_01_JWE_CONCATKDF: PASS");
}

fn test_jws_unencoded_b64_false() {
    var hdr = wing::new_jwt_header(wing::JwtAlg.HS256, "");
    hdr.typ.clear();
    hdr.b64 = false;
    hdr.has_b64 = true;
    assert(wing::add_header_crit(hdr, "b64"));

    var hdr_json: u8[>..] = [];
    wing::serialize_jwt_header(hdr, hdr_json);
    var hdr_b64: u8[..256] = [];
    core::base64url_encode(hdr_json[..], hdr_b64);

    let raw_payload = "$.02.raw.payload.with.dots";
    let secret = "0123456789abcdef0123456789abcdef";
    var signing_in: u8[..512] = [];
    signing_in.append(hdr_b64[..]);
    signing_in.push('.');
    signing_in.append(raw_payload);
    let mac = core::hmac_sha256(secret, signing_in[..]);
    var token: u8[..512] = [];
    token.append(signing_in[..]);
    token.push('.');
    core::base64url_encode(mac[..], token);

    assert(wing::verify_jws_unencoded_hs256(token[..], secret));
    assert(!wing::verify_jws_unencoded_hs256(token[..], "wrong_secret_key_0123456789abcdef"));
    print("AUTHJOSE_02_JWS_B64_FALSE: PASS");
}

fn test_jwks_x5c_x5t_and_key_ops() {
    let der_leaf = "0123456789abcdef";
    var x5c_b64: u8[..64] = [];
    core::base64_encode(der_leaf, x5c_b64);
    let dig = core::sha256(der_leaf);
    var x5t_b64u: u8[..44] = [];
    core::base64url_encode(dig[..], x5t_b64u);

    var jwks_doc: u8[..512] = [];
    jwks_doc.append("{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"kid\":\"k1\",\"key_ops\":[\"verify\"],\"x5c\":[\"");
    jwks_doc.append(x5c_b64[..]);
    jwks_doc.append("\"],\"x5t#S256\":\"");
    jwks_doc.append(x5t_b64u[..]);
    jwks_doc.append("\"}]}");

    var jwks = wing::Jwks { .. };
    assert(wing::parse_jwks_json(jwks_doc[..], jwks));
    assert(jwks.keys.len == 1);
    assert((jwks.keys[0].key_ops & wing::JWK_OP_VERIFY) != 0);
    assert(jwks.keys[0].x5t_s256[..] == x5t_b64u[..]);

    // Mismatched x5t#S256 must fail parsing
    var bad_doc: u8[..512] = [];
    bad_doc.append("{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"x5c\":[\"");
    bad_doc.append(x5c_b64[..]);
    bad_doc.append("\"],\"x5t#S256\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}]}");
    var bad_jwks = wing::Jwks { .. };
    assert(!wing::parse_jwks_json(bad_doc[..], bad_jwks));
    print("AUTHJOSE_03_JWKS_X5C_KEY_OPS: PASS");
}

fn test_oauth2_device_introspection_and_basic_auth() {
    let dev_json = "{\"device_code\":\"GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS\",\"user_code\":\"WDJB-MJHT\",\"verification_url\":\"https://example.com/device\",\"expires_in\":1800}";
    let dev_resp, dev_ok = wing::parse_device_auth_response(dev_json);
    assert(dev_ok);
    assert(dev_resp.user_code[..] == "WDJB-MJHT");
    assert(dev_resp.verification_uri[..] == "https://example.com/device");
    assert(dev_resp.interval_sec == 5);

    let iv1, cont1 = wing::step_device_poll_interval(5, 60, wing::DevicePollStatus.SlowDown);
    assert(cont1 && iv1 == 10);
    let iv2, cont2 = wing::step_device_poll_interval(10, 60, wing::DevicePollStatus.TransportError);
    assert(cont2 && iv2 == 20);
    let _, cont3 = wing::step_device_poll_interval(20, 60, wing::DevicePollStatus.Granted);
    assert(!cont3);

    var form: u8[..256] = [];
    assert(wing::encode_token_endpoint_form("tok/1+2", wing::TokenTypeHint.RefreshToken, form));
    assert(form[..] == "token=tok%2F1%2B2&token_type_hint=refresh_token");

    let intro_active = "{\"active\":true,\"client_id\":\"cid1\",\"sub\":\"u1\",\"aud\":[\"https://api.example.com\"],\"exp\":1800000000}";
    let ir1, ir1_ok = wing::parse_introspection_response(intro_active);
    assert(ir1_ok && ir1.active && ir1.client_id[..] == "cid1" && ir1.aud.len == 1);

    let intro_inactive = "{\"active\":false,\"client_id\":\"should_be_cleared\"}";
    let ir2, ir2_ok = wing::parse_introspection_response(intro_inactive);
    assert(ir2_ok && !ir2.active && ir2.client_id.len == 0);

    var basic_hdr: u8[..256] = [];
    assert(wing::encode_oauth2_basic_auth("my:client+id", "sec/ret%1 ", basic_hdr));
    var dec_id:  u8[..256] = [];
    var dec_sec: u8[..256] = [];
    assert(wing::decode_oauth2_basic_auth(basic_hdr[..], dec_id, dec_sec));
    assert(dec_id[..] == "my:client+id");
    assert(dec_sec[..] == "sec/ret%1 ");
    print("AUTHJOSE_04_05_07_OAUTH2: PASS");
}

fn test_jwt_strict_aud_and_transit_ttl() {
    var claims = wing::JwtClaims { .. };
    claims.iss.append("https://issuer2.example.com");
    assert(wing::set_audience(claims, "https://unexpected.service.local"));
    claims.exp = 1050;

    var opts = wing::default_jwt_validation_options(wing::JwtAlg.HS256);
    opts.validate_aud_when_present = true;
    assert(wing::validate_jwt_identity_claims(claims, opts) == wing::JwtError.AudienceMismatch);

    var iss1: u8[..128] = [];
    iss1.append("https://issuer1.example.com");
    var iss2: u8[..128] = [];
    iss2.append("https://issuer2.example.com");
    opts.allowed_issuers.push(iss1);
    opts.allowed_issuers.push(iss2);

    var aud1: u8[..128] = [];
    aud1.append("https://unexpected.service.local");
    opts.allowed_audiences.push(aud1);
    assert(wing::validate_jwt_identity_claims(claims, opts) == wing::JwtError.None);

    opts.min_remaining_ttl_seconds = 60;
    assert(wing::validate_jwt_claims_rules(claims, opts, 1000) == wing::JwtError.TokenExpired);
    assert(wing::validate_jwt_claims_rules(claims, opts, 980) == wing::JwtError.None);
    print("AUTHJOSE_06_STRICT_AUD_TTL: PASS");
}

fn test_rfind_two_way_long_needle() {
    let needle = "---boundary_token_longer_than_32_bytes_xyz---";
    let hay = "prefix---boundary_token_longer_than_32_bytes_xyz---mid---boundary_token_longer_than_32_bytes_xyz---suffix";
    let pos = core::rfind(hay, needle);
    assert(pos == 54);
    let direct_pos = core::rfind_two_way(hay, needle);
    assert(direct_pos == 54);

    let per_needle = "abababababababababababababababababab";
    let per_hay = "xxababababababababababababababababababyyababababababababababababababababababzz";
    assert(core::rfind(per_hay, per_needle) == 40);
    print("AUTHJOSE_08_RFIND_TWO_WAY: PASS");
}

fn main() {
    test_jwt_hmac_alg_confusion();
    test_jwks_reject_oth_private_key();
    test_digest_stale_empty_password();
    test_jwe_dir_a256gcm_and_concat_kdf();
    test_jws_unencoded_b64_false();
    test_jwks_x5c_x5t_and_key_ops();
    test_oauth2_device_introspection_and_basic_auth();
    test_jwt_strict_aud_and_transit_ttl();
    test_rfind_two_way_long_needle();
}

// CHECK: REPRO_JWT_HMAC_ALG_CONFUSION: PASS
// CHECK: REPRO_JWKS_REJECT_OTH: PASS
// CHECK: REPRO_DIGEST_EMPTY_PASSWORD_STALE: PASS
// CHECK: AUTHJOSE_01_JWE_CONCATKDF: PASS
// CHECK: AUTHJOSE_02_JWS_B64_FALSE: PASS
// CHECK: AUTHJOSE_03_JWKS_X5C_KEY_OPS: PASS
// CHECK: AUTHJOSE_04_05_07_OAUTH2: PASS
// CHECK: AUTHJOSE_06_STRICT_AUD_TTL: PASS
// CHECK: AUTHJOSE_08_RFIND_TWO_WAY: PASS
