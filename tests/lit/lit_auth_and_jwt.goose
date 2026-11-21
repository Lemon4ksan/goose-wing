// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Goose LIT Verification Suite: lit_auth_and_jwt
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// ============================================================================
// 1. rfc_repro_auth_audit_hunter (1/9)
// ============================================================================
// CHECK: === [1/9] rfc_repro_auth_audit_hunter ===

// tests/lit/rfc_repro_auth_audit_hunter.goose
// RFC Conformance and Bug Hunter Repro for Auth Subsystem:
// 1. RFC 8725 §3.1: verify_jwt_hmac must reject non-HMAC alg with AlgorithmMismatch
// 2. RFC 7518 §6.3.2.7: parse_jwks_json must reject JWKs containing 'oth' private key parameter
// 3. RFC 7616 §3.4: sync_digest_stale_challenge must permit empty password (passwd = *OCTET)
//

fn test_jwt_hmac_alg_confusion() {
    var opts_eddsa = auth::JwtValidationOptions { .. };
    opts_eddsa.expected_alg = auth::JwtAlg.EdDSA;
    var eddsa_h = auth::JwtHeader { .. };
    var eddsa_c = auth::JwtClaims { .. };

    // Header: {"alg":"EdDSA","typ":"JWT"} -> eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9
    // Claims: {"sub":"alice"}              -> eyJzdWIiOiJhbGljZSJ9
    // Sig:    c2lnbmF0dXJl
    let eddsa_token = "eyJhbGciOiJFZERTQSIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl";
    let err = auth::verify_jwt_hmac(
        eddsa_token,
        "dummy_key_01234567890123456789!",
        opts_eddsa,
        1714000000,
        eddsa_h,
        eddsa_c,
    );
    assert(err == auth::JwtError.AlgorithmMismatch);
    print("REPRO_JWT_HMAC_ALG_CONFUSION: PASS");
}

fn test_jwks_reject_oth_private_key() {
    let jwk_oth = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"oth\":[{\"r\":\"dummy\"}],\"kid\":\"key-oth\"}]}";
    var jwks_oth = auth::Jwks { .. };
    let parsed = auth::parse_jwks_json(jwk_oth, jwks_oth);
    assert(!parsed);
    assert(jwks_oth.keys.len == 0);
    print("REPRO_JWKS_REJECT_OTH: PASS");
}

fn test_digest_stale_empty_password() {
    var stored_chal = auth::DigestChallenge { .. };
    stored_chal.valid = true;
    stored_chal.nonce.append("old_nonce_1");
    stored_chal.realm.append("api@example.com");
    stored_chal.algorithm.clear();
    stored_chal.algorithm.append("SHA-256");
    stored_chal.has_explicit_algo = true;

    var incoming_chal = auth::DigestChallenge { .. };
    incoming_chal.valid = true;
    incoming_chal.stale = true;
    incoming_chal.nonce.append("fresh_nonce_2");
    incoming_chal.realm.append("api@example.com");
    incoming_chal.algorithm.clear();
    incoming_chal.algorithm.append("SHA-256");
    incoming_chal.has_explicit_algo = true;

    var empty_pwd_creds = auth::DigestCredentials { .. };
    empty_pwd_creds.username.append("guest_user");
    // password is intentionally empty per RFC 7616 passwd = *OCTET

    var nc: u32 = 5;
    let sync_ok = auth::sync_digest_stale_challenge(stored_chal, incoming_chal, empty_pwd_creds, nc);
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
    let cek = auth::concat_kdf_sha256(z, "A256GCM", "Alice", "Bob", 256);
    let iv: u8[12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let protected_b64 = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0";
    var compact: u8[..512] = [];
    assert(auth::jwe_seal_dir_a256gcm(protected_b64, cek, iv, "top_secret_payload", compact));
    var opened: u8[..256] = [];
    assert(auth::jwe_open_dir_a256gcm(compact[..], cek, opened));
    assert(opened[..] == "top_secret_payload");

    // Non-empty encrypted key must be rejected for "dir"
    let bad_compact = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0.YWJj.AQIDBAUGBwgJCgsM.Y2lwaGVy.AAAAAAAAAAAAAAAAAAAAAA";
    assert(!auth::jwe_open_dir_a256gcm(bad_compact, cek, opened));
    print("AUTHJOSE_01_JWE_CONCATKDF: PASS");
}

fn test_jws_unencoded_b64_false() {
    var hdr = auth::new_jwt_header(auth::JwtAlg.HS256, "");
    hdr.typ.clear();
    hdr.b64 = false;
    hdr.has_b64 = true;
    assert(auth::add_header_crit(hdr, "b64"));

    var hdr_json: u8[>..] = [];
    auth::serialize_jwt_header(hdr, hdr_json);
    var hdr_b64: u8[..256] = [];
    core::base64url_encode(hdr_json[..], hdr_b64);

    let raw_payload = "$02_raw_payload_without_dots";
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

    assert(auth::verify_jws_unencoded_hs256(token[..], secret));
    assert(!auth::verify_jws_unencoded_hs256(token[..], "wrong_secret_key_0123456789abcdef"));

    // RFC 7797 §5.2 & RFC 7515 §3.1: '.' inside unencoded compact payload must be rejected
    var bad_in: u8[..512] = [];
    bad_in.append(hdr_b64[..]);
    bad_in.push('.');
    bad_in.append("$.02.raw.payload.with.dots");
    let bad_mac = core::hmac_sha256(secret, bad_in[..]);
    var bad_tok: u8[..512] = [];
    bad_tok.append(bad_in[..]);
    bad_tok.push('.');
    core::base64url_encode(bad_mac[..], bad_tok);
    assert(!auth::verify_jws_unencoded_hs256(bad_tok[..], secret));
    print("AUTHJOSE_02_JWS_B64_FALSE: PASS");
}

fn test_jwks_x5c_x5t_and_key_ops() {
    let ed_seed: u8[32] = [
        0x9d, 0x61, 0xb1, 0x9d, 0xef, 0xfd, 0x5a, 0x60,
        0xba, 0x84, 0x4a, 0xf4, 0x92, 0xec, 0x2c, 0xc4,
        0x44, 0x49, 0xc5, 0x69, 0x7b, 0x32, 0x69, 0x19,
        0x70, 0x3b, 0xac, 0x03, 0x1c, 0xae, 0x7f, 0x60,
    ];
    var der_leaf: u8[..2048] = [];
    assert(tls::build_test_ed25519_cert_der(ed_seed, "auth.example.com", "auth.example.com", "", der_leaf));
    var x5c_b64: u8[..1024] = [];
    core::base64_encode(der_leaf[..], x5c_b64);
    let dig = core::sha256(der_leaf[..]);
    var x5t_b64u: u8[..44] = [];
    core::base64url_encode(dig[..], x5t_b64u);

    var jwks_doc: u8[..1536] = [];
    jwks_doc.append("{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"kid\":\"k1\",\"key_ops\":[\"verify\"],\"x5c\":[\"");
    jwks_doc.append(x5c_b64[..]);
    jwks_doc.append("\"],\"x5t#S256\":\"");
    jwks_doc.append(x5t_b64u[..]);
    jwks_doc.append("\"}]}");

    var jwks = auth::Jwks { .. };
    assert(auth::parse_jwks_json(jwks_doc[..], jwks));
    assert(jwks.keys.len == 1);
    assert((jwks.keys[0].key_ops & auth::JWK_OP_VERIFY) != 0);
    assert(jwks.keys[0].x5t_s256[..] == x5t_b64u[..]);

    // Non-PKIX stub in x5c[0] must fail parsing per RFC 7517 §4.7
    let stub_doc = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"x5c\":[\"MDEyMzQ1Njc4OWFiY2RlZg==\"]}]}";
    var stub_jwks = auth::Jwks { .. };
    assert(!auth::parse_jwks_json(stub_doc, stub_jwks));

    // Mismatched x5t#S256 must fail parsing
    var bad_doc: u8[..1536] = [];
    bad_doc.append("{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"x5c\":[\"");
    bad_doc.append(x5c_b64[..]);
    bad_doc.append("\"],\"x5t#S256\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}]}");
    var bad_jwks = auth::Jwks { .. };
    assert(!auth::parse_jwks_json(bad_doc[..], bad_jwks));
    print("AUTHJOSE_03_JWKS_X5C_KEY_OPS: PASS");
}

fn test_oauth2_device_introspection_and_basic_auth() {
    let dev_json = "{\"device_code\":\"GmRhmhcxhwAzkoEqiMEg_DnyEysNkuNhszIySk9eS\",\"user_code\":\"WDJB-MJHT\",\"verification_url\":\"https://example.com/device\",\"expires_in\":1800}";
    let dev_resp, dev_ok = auth::parse_device_auth_response(dev_json);
    assert(dev_ok);
    assert(dev_resp.user_code[..] == "WDJB-MJHT");
    assert(dev_resp.verification_uri[..] == "https://example.com/device");
    assert(dev_resp.interval_sec == 5);

    let iv1, cont1 = auth::step_device_poll_interval(auth::DevicePollStatus.SlowDown, 5, 60);
    assert(cont1 && iv1 == 10);
    let iv2, cont2 = auth::step_device_poll_interval(auth::DevicePollStatus.TransportError, 10, 60);
    assert(cont2 && iv2 == 20);
    let _, cont3 = auth::step_device_poll_interval(auth::DevicePollStatus.Granted, 20, 60);
    assert(!cont3);

    var form: u8[..256] = [];
    assert(auth::encode_token_endpoint_form("tok/1+2", auth::TokenTypeHint.RefreshToken, form));
    assert(form[..] == "token=tok%2F1%2B2&token_type_hint=refresh_token");

    let intro_active = "{\"active\":true,\"client_id\":\"cid1\",\"sub\":\"u1\",\"aud\":[\"https://api.example.com\"],\"exp\":1800000000}";
    let ir1, ir1_ok = auth::parse_introspection_response(intro_active);
    assert(ir1_ok && ir1.active && ir1.client_id[..] == "cid1" && ir1.aud.len == 1);

    let intro_inactive = "{\"active\":false,\"client_id\":\"should_be_cleared\"}";
    let ir2, ir2_ok = auth::parse_introspection_response(intro_inactive);
    assert(ir2_ok && !ir2.active && ir2.client_id.len == 0);

    var basic_hdr: u8[..256] = [];
    assert(auth::encode_oauth2_basic_auth("my:client+id", "sec/ret%1 ", basic_hdr));
    var dec_id:  u8[..256] = [];
    var dec_sec: u8[..256] = [];
    assert(auth::decode_oauth2_basic_auth(basic_hdr[..], dec_id, dec_sec));
    assert(dec_id[..] == "my:client+id");
    assert(dec_sec[..] == "sec/ret%1 ");
    print("AUTHJOSE_04_05_07_OAUTH2: PASS");
}

fn test_jwt_strict_aud_and_transit_ttl() {
    var claims = auth::JwtClaims { .. };
    claims.iss.append("https://issuer2.example.com");
    assert(auth::set_audience(claims, "https://unexpected.service.local"));
    claims.exp = 1050;

    var opts = auth::default_jwt_validation_options(auth::JwtAlg.HS256);
    opts.validate_aud_when_present = true;
    assert(auth::validate_jwt_identity_claims(claims, opts) == auth::JwtError.AudienceMismatch);

    var iss1: u8[..128] = [];
    iss1.append("https://issuer1.example.com");
    var iss2: u8[..128] = [];
    iss2.append("https://issuer2.example.com");
    opts.allowed_issuers.push(iss1);
    opts.allowed_issuers.push(iss2);

    var aud1: u8[..128] = [];
    aud1.append("https://unexpected.service.local");
    opts.allowed_audiences.push(aud1);
    assert(auth::validate_jwt_identity_claims(claims, opts) == auth::JwtError.None);

    opts.min_remaining_ttl_seconds = 60;
    assert(auth::validate_jwt_claims_rules(claims, opts, 1000) == auth::JwtError.TokenExpired);
    assert(auth::validate_jwt_claims_rules(claims, opts, 980) == auth::JwtError.None);
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

fn run_01_rfc_repro_auth_audit_hunter() {
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

// ============================================================================
// 2. rfc_repro_auth_cross_rfc (2/9)
// ============================================================================
// CHECK: === [2/9] rfc_repro_auth_cross_rfc ===

fn test_digest_cross_rfc() {
    // 1. RFC 9110 §11.2: Duplicate challenge parameter injection / algorithm downgrade
    let chal_dup_alg, ok1 = auth::parse_digest_challenge(
        "Digest realm=\"api\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", algorithm=SHA-256, algorithm=MD5",
    );
    let r1 = !ok1 && !chal_dup_alg.valid;

    let chal_dup_nonce, ok2 = auth::parse_digest_challenge(
        "Digest realm=\"api\", nonce=\"nonce_one_123456\", nonce=\"nonce_two_654321\"",
    );
    let r2 = !ok2 && !chal_dup_nonce.valid;

    // 2. RFC 7616 §3.3 & §4: Unsupported charset and invalid userhash
    let chal_bad_charset, ok3 = auth::parse_digest_challenge(
        "Digest realm=\"api\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", charset=ISO-8859-1",
    );
    let r3 = !ok3 && !chal_bad_charset.valid;

    let chal_good_charset, ok4 = auth::parse_digest_challenge(
        "Digest realm=\"api\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", charset=utf-8, userhash=false",
    );
    let r4 = ok4 && chal_good_charset.valid && !chal_good_charset.userhash;

    let chal_bad_userhash, ok5 = auth::parse_digest_challenge(
        "Digest realm=\"api\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", userhash=invalid",
    );
    let r5 = !ok5 && !chal_bad_userhash.valid;

    // 3. RFC 7616 §3.3: Malformed qop token list & empty qop="" downgrade
    let qop_bad_tail = !auth::qop_list_has_token("auth, bad;token", "auth");
    let chal_empty_qop, ok6 = auth::parse_digest_challenge(
        "Digest realm=\"api\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"\"",
    );
    let r6 = qop_bad_tail && !ok6 && !chal_empty_qop.valid;

    // 4. Stale challenge refresh must not silently downgrade SHA-256 to MD5 when algorithm omitted
    var stored, _ = auth::parse_digest_challenge(
        "Digest realm=\"api\", nonce=\"initial_nonce_12345\", algorithm=SHA-256, qop=\"auth\"",
    );
    let creds = auth::DigestCredentials { username: "alice", password: "secret", .. };
    var nc: u32 = 5;
    let ok_refresh = auth::refresh_digest_stale_nonce(
        stored,
        "Digest realm=\"api\", nonce=\"fresh_nonce_67890\", stale=true, qop=\"auth\"",
        creds,
        nc,
    );
    let bad_downgrade = !auth::refresh_digest_stale_nonce(
        stored,
        "Digest realm=\"api\", nonce=\"downgrade_nonce_111\", algorithm=MD5, stale=true, qop=\"auth\"",
        creds,
        nc,
    );
    let r7 = ok_refresh && stored.algorithm[..] == "SHA-256" && bad_downgrade && stored.algorithm[..] == "SHA-256";

    // 5. Control char in quoted realm rejected
    let chal_ctl, ok8 = auth::parse_digest_challenge(
        "Digest realm=\"api\x07\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"",
    );
    let r8 = !ok8 && !chal_ctl.valid;

    assert(r1);
    assert(r2);
    assert(r3);
    assert(r4);
    assert(r5);
    assert(r6);
    assert(r7);
    assert(r8);
    print("DIGEST_CROSS_RFC: true\n");
}
fn test_jwks_dpop_jwt_cross_rfc() {
    // 6. JWKS: Off-curve P-256 EC coordinates rejected in add_es256_key and parse_jwks_json
    var jwks_ec = auth::Jwks { .. };
    var zero_coord: u8[32] = [0; 32];
    let r9 = !auth::add_es256_key(jwks_ec, "ec-zero", zero_coord[..], zero_coord[..]);

    var jwks_json_ec = auth::Jwks { .. };
    let bad_ec_json = "{\"keys\":[{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"y\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}]}";
    let r10 = !auth::parse_jwks_json(bad_ec_json, jwks_json_ec);

    // 7. JWKS: Secondary key with private field "d" or invalid key in "keys" array must fail entire JWKS parse
    var jwks_mixed = auth::Jwks { .. };
    let mixed_json = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"},{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"d\":\"nWGxne_9WmC6hEr0kuwsxERJxWl7MmkZcDusAxyuf2A\"}]}";
    let r11 = !auth::parse_jwks_json(mixed_json, jwks_mixed);

    // 8. JWKS: compute_jwk_thumbprint rejects invalidated key & verify() preserves out_header on KeyNotFound
    var invalid_key = auth::JwksKey { kty: auth::JwkKeyType.OKP, crv: "Ed25519", valid: false, .. };
    var tp_out: u8[..64] = [];
    let r12 = !auth::compute_jwk_thumbprint(invalid_key, tp_out);

    var jwks_v = auth::Jwks { .. };
    let pub_ed: u8[32] = [1; 32];
    let _ = auth::add_ed25519_key(jwks_v, "real-kid", pub_ed);
    var sentinel_hdr = auth::JwtHeader { alg: auth::JwtAlg.EdDSA, kid: "sentinel-kid", .. };
    var sentinel_clm = auth::JwtClaims { .. };
    let opts = auth::default_jwt_validation_options(auth::JwtAlg.EdDSA);
    let verr = auth::verify_jwt(
        jwks_v,
        "eyJhbGciOiJFZERTQSIsImtpZCI6Im1pc3Npbmcta2lkIn0.eyJzdWIiOiJ1MSIsImV4cCI6OTk5OTk5OTk5OX0.c2ln",
        opts, 1700000000, sentinel_hdr, sentinel_clm,
    );
    let r13 = verr == auth::JwtError.KeyNotFound && sentinel_hdr.kid[..] == "sentinel-kid";

    // 9. DPoP: Header alg <-> jwk.kty mismatch, embedded jwk use="enc" / off-curve EC rejected
    let dpop_mismatch_hdr = "{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"f83OJ3D2xF1Bg8vub9tLe1gHMzV76e8Tus9uPHvRVEU\",\"y\":\"x_FEzRu9m36HLN_tue659LNpXW6pCyStikYjKIWI5a0\"}}";
    let dpop_enc_hdr = "{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"jwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"use\":\"enc\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}}";
    let dpop_offcurve_hdr = "{\"typ\":\"dpop+jwt\",\"alg\":\"ES256\",\"jwk\":{\"kty\":\"EC\",\"crv\":\"P-256\",\"x\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\",\"y\":\"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA\"}}";
    let r14 = !auth::verify_dpop_header(dpop_mismatch_hdr, "EdDSA") &&
              !auth::verify_dpop_header(dpop_enc_hdr, "EdDSA") &&
              !auth::verify_dpop_header(dpop_offcurve_hdr, "ES256");

    // 10. DPoP URI normalization: reject empty host, invalid port, and spaces in query
    var norm_u: u8[..256] = [];
    let r15 = !auth::normalize_dpop_target_uri("http://:80/resource", norm_u) &&
              !auth::normalize_dpop_target_uri("http://example.com:abc/resource", norm_u) &&
              !auth::normalize_dpop_target_uri("https://example.com/resource?q=a b", norm_u);

    // 11. JWT typ case-insensitive "APPLICATION/" prefix & RFC 7515 §4.1.9 slash check, plus empty aud rejection
    let r16 = auth::is_matching_jwt_typ("APPLICATION/at+jwt", "at+jwt") &&
              !auth::is_matching_jwt_typ("application/application/jwt", "application/jwt");
    var bad_aud_claims = auth::JwtClaims { .. };
    let r17 = !auth::parse_jwt_claims_json("{\"aud\":\"\"}", bad_aud_claims) &&
              !auth::parse_jwt_claims_json("{\"aud\":[\"\",\"api\"]}", bad_aud_claims);

    assert(r9);
    assert(r10);
    assert(r11);
    assert(r12);
    assert(r13);
    assert(r14);
    assert(r15);
    assert(r16);
    assert(r17);
    print("JWKS_DPOP_JWT_CROSS_RFC: true\n");
}

fn test_acme_pkce_dpop_jwks_seams() {
    // 12. ACME (RFC 8555 §8.1 & §8.3): acme_find_challenge rejects mismatched/corrupt key_auth slot
    // and clears out buffers on acme_key_authorization / acme_http01_path failure
    var acme_table: auth::AcmeChallenge[..8] = [];
    let acme_tok = "LoqXcYV8q5ONbJQxbmR7SC";
    let acme_tp = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
    let acme_ka = "LoqXcYV8q5ONbJQxbmR7SC.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
    acme_table.push(auth::AcmeChallenge { token: acme_tok, key_auth: "other_token_0123456789.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs" });
    acme_table.push(auth::AcmeChallenge { token: acme_tok, key_auth: "LoqXcYV8q5ONbJQxbmR7SC.bad/thumbprint_0123456789012345678901234567" });
    acme_table.push(auth::AcmeChallenge { token: acme_tok, key_auth: "LoqXcYV8q5ONbJQxbmR7SC.ShortTP" });
    acme_table.push(auth::AcmeChallenge { token: acme_tok, key_auth: acme_ka });
    var acme_body: u8[..256] = [];
    let found_acme = auth::find_acme_challenge(acme_table, "/.well-known/acme-challenge/LoqXcYV8q5ONbJQxbmR7SC", acme_body);
    var acme_out: u8[..256] = "stale_key_auth";
    let bad_ka = auth::build_acme_key_authorization("bad/tok", acme_tp, acme_out);
    var acme_path: u8[..128] = "stale_path";
    let bad_hp = auth::build_acme_http01_path("short_tok", acme_path);
    let r18 = found_acme && acme_body.len == 66 && acme_body[..] == acme_ka &&
              !bad_ka && acme_out.len == 0 && !bad_hp && acme_path.len == 0;

    // 13. PKCE (RFC 7636 §4.2): compute_code_challenge clears out on failure & create_pkce_pair clears method on error
    var pkce_out: u8[..128] = "stale_challenge";
    let ok_pkce = auth::compute_code_challenge("short", "S256", pkce_out);
    let bad_pair, ok_pair = auth::create_pkce_pair("0123456789abcdef0123456789abcdef", "invalid_method");
    let r19 = !ok_pkce && pkce_out.len == 0 && !ok_pair && bad_pair.verifier.len == 0 && bad_pair.method.len == 0;

    // 14. DPoP (RFC 9449 §4.2 / §6.1 / §8): parse_dpop_claims rejects empty ath/nonce/jkt & control chars in nonce
    var dpop_clm = auth::DPoPClaims { .. };
    let r20 = !auth::parse_dpop_claims("{\"jti\":\"j1\",\"htm\":\"GET\",\"htu\":\"https://example.com/\",\"iat\":1700000000,\"ath\":\"\"}", dpop_clm) &&
              !auth::parse_dpop_claims("{\"jti\":\"j1\",\"htm\":\"GET\",\"htu\":\"https://example.com/\",\"iat\":1700000000,\"nonce\":\"bad\\r\\nnonce\"}", dpop_clm) &&
              !auth::parse_dpop_claims("{\"jti\":\"j1\",\"htm\":\"GET\",\"htu\":\"https://example.com/\",\"iat\":1700000000,\"jkt\":\"\"}", dpop_clm);

    // 15. JWT/JWKS (RFC 7515 §4.1.4 & RFC 6598): Empty "kid":"" or "typ":"" rejected; CGNAT 100.64.0.0/10 exact bounds
    var empty_kid_hdr = auth::JwtHeader { .. };
    var empty_typ_hdr = auth::JwtHeader { .. };
    var jwks_empty_kid = auth::Jwks { .. };
    let r21 = !auth::parse_jwt_header_json("{\"alg\":\"EdDSA\",\"kid\":\"\"}", empty_kid_hdr) &&
              !auth::parse_jwt_header_json("{\"alg\":\"HS256\",\"typ\":\"\"}", empty_typ_hdr) &&
              !auth::parse_jwks_json("{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"kid\":\"\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}]}", jwks_empty_kid) &&
              !auth::is_safe_remote_jwks_url("https://100.108.0.1/jwks") &&
              auth::is_safe_remote_jwks_url("https://100.60.0.1/jwks");

    // 16. JWKS zeroize_jwks_key wipes EC and RSA key material completely
    var rsa_key = auth::JwksKey { kty: auth::JwkKeyType.RSA, valid: true, .. };
    rsa_key.ec_x.append("ec_x_bytes");
    rsa_key.rsa_n.append("rsa_n_bytes");
    rsa_key.rsa_e.append("e_bytes");
    auth::zeroize_jwks_key(rsa_key);
    let r22 = !rsa_key.valid && rsa_key.ec_x.len == 0 && rsa_key.rsa_n.len == 0 && rsa_key.rsa_e.len == 0;

    assert(r18);
    assert(r19);
    assert(r20);
    assert(r21);
    assert(r22);
    print("ACME_PKCE_DPOP_JWKS_SEAMS: true\n");
}

// CHECK: DIGEST_CROSS_RFC: true
// CHECK: JWKS_DPOP_JWT_CROSS_RFC: true
// CHECK: ACME_PKCE_DPOP_JWKS_SEAMS: true
fn run_02_rfc_repro_auth_cross_rfc() {
    test_digest_cross_rfc();
    test_jwks_dpop_jwt_cross_rfc();
    test_acme_pkce_dpop_jwks_seams();
}

// ============================================================================
// 3. rfc_repro_auth_digest_edge (3/9)
// ============================================================================
// CHECK: === [3/9] rfc_repro_auth_digest_edge ===

// tests/lit/rfc_repro_auth_digest_edge.goose
// RFC 7616 Digest Edge Cases, Header Injection Defense, and State Synchronization.
//

fn run_03_rfc_repro_auth_digest_edge() {
    // ---- 1. RFC 7616 §3.4 URI Injection Defense ----------------------------
    var uri_sink: u8[..128] = [];
    assert(!auth::append_digest_uri(uri_sink, "/path/with\\backslash"));
    assert(!auth::append_digest_uri(uri_sink, "/path/with\"quote"));
    assert(!auth::append_digest_uri(uri_sink, "/path/with\r\nCRLF"));
    assert(auth::append_digest_uri(uri_sink, "/valid/path/to/resource"));
    print("DIGEST_URI_DEFENSE: OK");

    // ---- 2. RFC 7616 §3.4 & §3.4.1 Mandatory cnonce / nc Checks ------------
    var chal = auth::DigestChallenge {
        realm:     "test_realm",
        nonce:     "test_nonce_123",
        algorithm: "SHA-256",
        qop:       "auth",
        valid:     true,
        ..
    };
    var creds = auth::DigestCredentials {
        username: "user",
        password: "pwd",
    };
    var resp_header: u8[..1024] = [];

    // Empty cnonce with active qop MUST fail
    let ok_empty_cnonce = auth::compute_digest_response(chal, creds, "GET", "/api", 1, "", "", resp_header);
    assert(!ok_empty_cnonce);

    // nc == 0 with active qop MUST fail
    let ok_zero_nc = auth::compute_digest_response(chal, creds, "GET", "/api", 0, "client_nonce_xyz", "", resp_header);
    assert(!ok_zero_nc);

    // Valid parameters MUST succeed
    let ok_valid = auth::compute_digest_response(chal, creds, "GET", "/api", 1, "client_nonce_xyz", "", resp_header);
    assert(ok_valid);
    print("DIGEST_CNONCE_NC_VALIDATION: OK");

    // ---- 3. RFC 7616 §3.3 Stale Challenge Synchronization ------------------
    var stored = auth::DigestChallenge {
        realm:     "old_realm",
        nonce:     "old_nonce",
        algorithm: "MD5",
        qop:       "auth",
        userhash:  false,
        valid:     true,
        ..
    };
    var incoming = auth::DigestChallenge {
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
    assert(auth::sync_digest_stale_challenge(stored, incoming, creds, nc));
    assert(nc == 1);
    assert(stored.nonce[..] == "fresh_nonce_456");
    assert(stored.algorithm[..] == "SHA-256");
    assert(stored.qop[..] == "auth-int");
    assert(stored.domain[..] == "https://auth.example.com");
    assert(stored.userhash);
    print("DIGEST_STALE_SYNC: OK");

    // ---- 4. Mandatory Field & Response Hex Validation ----------------------
    var empty_user_creds = auth::DigestCredentials { username: "", password: "pwd" };
    assert(!auth::compute_digest_response(chal, empty_user_creds, "GET", "/api", 1, "cnonce123", "", resp_header));

    var sink_empty_resp: u8[..512] = [];
    assert(!auth::serialize_digest_auth("user", "realm", "nonce", "/api", "SHA-256", "", "auth", "00000001", "cnonce", "", false, sink_empty_resp));

    let ha2_bad_method = auth::calculate_digest_ha2("SHA-256", "", "/api", false, "");
    assert(ha2_bad_method.len == 0);
    let ha2_bad_uri = auth::calculate_digest_ha2("SHA-256", "GET", "", false, "");
    assert(ha2_bad_uri.len == 0);
    print("DIGEST_MANDATORY_FIELD_VALIDATION: OK");

    // ---- 5. Session Algorithm & auth-int Verification ----------------------
    assert(rfc::is_sess_digest_algo("SHA-256-sess"));
    assert(rfc::is_sess_digest_algo("MD5-sess"));
    assert(rfc::is_sess_digest_algo("SHA-512-256-sess"));
    assert(!rfc::is_sess_digest_algo("SHA-256"));
    assert(!rfc::is_sess_digest_algo("MD5"));

    let ha1_sess_no_cnonce = auth::calculate_digest_ha1("SHA-256-sess", "user", "realm", "pwd", "nonce", "");
    assert(ha1_sess_no_cnonce.len == 0);
    let ha1_sess_no_nonce = auth::calculate_digest_ha1("SHA-256-sess", "user", "realm", "pwd", "", "cnonce");
    assert(ha1_sess_no_nonce.len == 0);

    let ha2_auth = auth::calculate_digest_ha2("SHA-256", "POST", "/api", false, "body data");
    let ha2_auth_int = auth::calculate_digest_ha2("SHA-256", "POST", "/api", true, "body data");
    assert(ha2_auth.len == 64 && ha2_auth_int.len == 64);
    assert(ha2_auth[..] != ha2_auth_int[..]);
    print("DIGEST_SESS_AND_AUTH_INT: OK");

    // ---- 6. Grammar & State Invariants -------------------------------------
    let chal_empty_tok, chal_ok = auth::parse_digest_challenge("realm=, nonce=\"123\"");
    assert(!chal_ok);

    var uninit_stored = auth::DigestChallenge { valid: false, .. };
    assert(!auth::sync_digest_stale_challenge(uninit_stored, incoming, creds, nc));

    // ---- 7. F005: RFC 7616 Token Grammar, QOP Delimiters & Sink Hygiene ----
    let _, ok_ctrl_key = auth::parse_digest_challenge("Digest bad;key=\"val\", realm=\"r\", nonce=\"n\"");
    assert(!ok_ctrl_key);
    let _, ok_trailing_junk = auth::parse_digest_challenge("Digest realm=\"r\"junk, nonce=\"n\"");
    assert(!ok_trailing_junk);
    let _, ok_bad_unquoted = auth::parse_digest_challenge("Digest realm=\"r\", nonce=\"n\", algorithm=SHA\"256");
    assert(!ok_bad_unquoted);

    assert(!auth::qop_list_has_token("auth bogus", "auth"));
    assert(!auth::qop_list_has_token("bogus auth", "auth"));
    assert(auth::qop_list_has_token("auth, auth-int", "auth"));

    var tiny_sink: u8[..48] = [];
    assert(!auth::serialize_digest_auth("Mufasa", "http-auth@example.org", "nonce123", "/dir/index.html", "SHA-256", "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1", "auth", "00000001", "cnonce123", "", false, tiny_sink));
    assert(tiny_sink.len == 0);
    print("DIGEST_INVARIANTS_AND_GRAMMAR: OK");
}

// CHECK: DIGEST_URI_DEFENSE: OK
// CHECK: DIGEST_CNONCE_NC_VALIDATION: OK
// CHECK: DIGEST_STALE_SYNC: OK
// CHECK: DIGEST_MANDATORY_FIELD_VALIDATION: OK
// CHECK: DIGEST_SESS_AND_AUTH_INT: OK
// CHECK: DIGEST_INVARIANTS_AND_GRAMMAR: OK

// ============================================================================
// 4. rfc_repro_auth_digest_vector (4/9)
// ============================================================================
// CHECK: === [4/9] rfc_repro_auth_digest_vector ===

// tests/lit/rfc_repro_auth_digest_vector.goose
// RFC 7616 Section 3.9.2 SHA-512-256 Digest Authentication test vector reproduction.
//

fn run_04_rfc_repro_auth_digest_vector() {
    // RFC 7616 Section 3.9.2: Example with SHA-512-256, Charset, and Userhash - Truncated SHA-512 (first 256 bits) for SHA-512-256 digest calculation.
    let username = "J\xC3\xA4s\xC3\xB8n Doe";
    let realm = "api@example.org";
    let password = "Secret, or not?";
    let uri = "/doe.json";
    let method = "GET";
    let nonce = "5TsQWLVdgBdmrQ0XsxbDODV+57QdFR34I9HAbC/RVvkK";
    let cnonce = "NTg6RKcb9boFIAS3KrFK9BGeh+iDa/sm6jUMp2wds69v";
    let nc = "00000001";
    let qop = "auth";
    let algo = "SHA-512-256";

    // 1. Verify Userhash (RFC 7616 Section 3.9.2)
    let userhash = auth::resolve_userhash(username, realm, algo);
    let expected_userhash = "488869477bf257147b804c45308cd62ac4e25eb717b12b298c79e62dcea254ec";
    assert(userhash[..] == expected_userhash);

    // 2. Calculate HA1 (A1 = username:realm:password)
    let ha1 = auth::calculate_digest_ha1(algo, username, realm, password, nonce, cnonce);

    // 3. Calculate HA2 (A2 = method:uri)
    let ha2 = auth::calculate_digest_ha2(algo, method, uri, false, "");

    // 4. Calculate Response
    let resp = auth::calculate_digest_response(algo, ha1[..], nonce, nc, cnonce, qop, ha2[..]);

    let expected_resp = "ae66e67d6b427bd3f120414a82e4acff38e8ecd9101d6c861229025f607a79dd";
    assert(resp[..] == expected_resp);

    print("RFC7616_SHA512_256_RESPONSE: OK\n");
}

// CHECK: RFC7616_SHA512_256_RESPONSE: OK

// ============================================================================
// 5. rfc_repro_auth_dpop_edge (5/9)
// ============================================================================
// CHECK: === [5/9] rfc_repro_auth_dpop_edge ===

// tests/lit/rfc_repro_auth_dpop_edge.goose
// RFC 9449 DPoP JWK Thumbprint Confirmation & JTI Replay/Entropy Verification.
//

fn run_05_rfc_repro_auth_dpop_edge() {
    let key = "super_secret_dpop_key_32_bytes!!";
    let now_sec: i64 = 1714000000;

    // ---- 1. RFC 9449 Section 4.3 & 6.1: JWK Thumbprint Confirmation --------
    // RFC 9449 Section 4.3: Checking DPoP Proofs - confirm that the public key to which the access token is bound matches the public key from the DPoP proof.
    // RFC 9449 Section 6.1: JWK Thumbprint Confirmation Method - The value of the jkt member MUST be the base64url encoding (as defined in [RFC7515]) of the JWK SHA-256 Thumbprint (according to [RFC7638]) of the DPoP public key (in JWK format) to which the access token is bound.
    var proof: u8[>..] = [];
    let ok_gen = auth::create_dpop_proof(
        key,
        "POST",
        "https://api.example.com/token",
        "",
        "",
        now_sec,
        "custom-jti-01",
        proof,
    );
    assert(ok_gen);

    // Compute expected RFC 7638 SHA-256 Thumbprint of key's public key
    var seed: u8[32] = [0; 32];
    for i in 32 { seed[i] = key[i]; }
    let pub_key = core::ed25519_public_key(seed);
    var key_obj = auth::JwksKey { .. };
    key_obj.kty = auth::JwkKeyType.OKP;
    key_obj.crv.append("Ed25519");
    key_obj.public_key = pub_key;
    var expected_jkt: u8[..64] = [];
    assert(auth::compute_jwk_thumbprint(key_obj, expected_jkt));

    // Valid standard DPoP proof (contains NO payload jkt claim) MUST verify against bound token's jkt
    let ok_verify = auth::verify_dpop_proof(
        proof[..],
        key,
        "POST",
        "https://api.example.com/token",
        "",
        "",
        now_sec,
        300,
        60,
        expected_jkt[..],
    );
    assert(ok_verify);
    print("DPOP_JKT_VERIFICATION: OK");

    // ---- 2. RFC 9449 Section 11.1 & 4.2: JTI Replay Cache Limits -----------
    // RFC 9449 Section 11.1: DPoP Proof Replay - As long as the jti value is tracked and duplicates are rejected for the lifetime of the nonce, there is no additional risk of token replay.
    var replay_cache = auth::DPoPReplayCache { .. };
    let long_jti = "jti_rfc9449_long_identifier_0123456789012345678901234567890123456789_enterprise_safe";
    assert(long_jti.len > 64 && long_jti.len <= 128);

    let recorded = auth::check_and_record_dpop_jti(replay_cache, long_jti, now_sec, 300);
    assert(recorded);
    let replayed = auth::check_and_record_dpop_jti(replay_cache, long_jti, now_sec, 300);
    assert(!replayed);
    print("DPOP_JTI_REPLAY_CACHE: OK");

    // ---- 3. RFC 9449 Section 4.2: Stateful JTI Entropy --------------------
    // RFC 9449 Section 4.2: DPoP Proof JWT Syntax - The value MUST be assigned such that there is a negligible probability that the same value will be assigned to any other DPoP proof used in the same context during the time window of validity.
    var jti1: u8[..64] = [];
    var jti2: u8[..64] = [];
    auth::generate_dpop_jti(jti1);
    auth::generate_dpop_jti(jti2);
    assert(jti1[..] != jti2[..]);
    print("DPOP_JTI_ENTROPY: OK");

    // ---- 4. DPoP Proof Length & Header Sensitivity -------------------------
    var proof_at: u8[>..] = [];
    assert(auth::create_dpop_proof(
        key,
        "POST",
        "https://api.example.com/resource/endpoint",
        "access_token_1234567890_abcdef",
        "server-nonce-12345",
        now_sec,
        "custom-jti-01",
        proof_at,
    ));
    assert(proof_at.len >= 392);

    var dpop_req = http::Request { .. };
    auth::attach_dpop(dpop_req, proof_at[..]);
    assert(dpop_req.headers.entries.len == 1);
    assert(http::header(dpop_req, "DPoP").len == proof_at.len);
    print("DPOP_ATTACH_AND_SENSITIVE: OK");

    // ---- 5. RFC 9449 §4.3 Target URI Normalization Edge Cases --------------
    var norm_buf: u8[..256] = [];
    assert(!auth::normalize_dpop_target_uri("https:///api", norm_buf));
    assert(auth::normalize_dpop_target_uri("http://[2001:db8::80]/test", norm_buf));
    assert(norm_buf[..] == "http://[2001:db8::80]/test");
    assert(auth::normalize_dpop_target_uri("http://[2001:db8::1]:80/test", norm_buf));
    assert(norm_buf[..] == "http://[2001:db8::1]/test");
    print("DPOP_URI_NORMALIZATION: OK");

    // ---- 6. RFC 9449 §4.2 Claims JSON Validation ---------------------------
    var cl_buf: u8[..512] = [];
    assert(!auth::build_dpop_claims_json("GET", "https://api.example.com/", "", "", -1, "valid_jti", cl_buf));
    assert(!auth::build_dpop_claims_json("GET", "https://api.example.com/", "", "", 0, "valid_jti", cl_buf));
    assert(!auth::build_dpop_claims_json("GET", "https://api.example.com/", "", "", now_sec, "bad\"jti", cl_buf));
    print("DPOP_CLAIMS_BUILD: OK");

    // ---- 7. RFC 9449 §4.3 Alg & Crit Header Rejection -----------------------
    assert(!auth::is_matching_dpop_alg("dir", ""));
    assert(!auth::is_matching_dpop_alg("A128GCM", ""));
    assert(!auth::is_matching_dpop_alg("HS256", ""));
    assert(auth::is_matching_dpop_alg("EdDSA", ""));
    assert(auth::is_matching_dpop_alg("ES256", ""));
    let crit_hdr = "{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"crit\":[\"foo\"],\"jwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"1234\"}}";
    assert(!auth::verify_dpop_header(crit_hdr));
    print("DPOP_HEADER_REJECTIONS: OK");

    // ---- 8. RFC 9449 §8 Nonce Header Validation ----------------------------
    var hdrs_dup = http::HeaderMap { .. };
    http::append_header(hdrs_dup, "DPoP-Nonce", "nonce1");
    http::append_header(hdrs_dup, "DPoP-Nonce", "nonce2");
    let _, ok_nonce = auth::extract_dpop_nonce(hdrs_dup);
    assert(!ok_nonce);

    var hdrs_bad = http::HeaderMap { .. };
    http::append_header(hdrs_bad, "DPoP-Nonce", "bad nonce with spaces");
    let _, ok_bad = auth::extract_dpop_nonce(hdrs_bad);
    assert(!ok_bad);
    print("DPOP_NONCE_VALIDATION: OK");

    // ---- 9. Escaped Key Smuggling, Method/JTI Validation, & Small Buffer ---
    let esc_hdr = "{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"\\u0063rit\":[\"foo\"],\"jwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"1234\"}}";
    assert(!auth::verify_dpop_header(esc_hdr));
    let esc_jwk = "{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"jwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"1234\",\"\\u0064\":\"priv\"}}";
    assert(!auth::verify_dpop_header(esc_jwk));
    var esc_claims = auth::DPoPClaims { .. };
    assert(!auth::parse_dpop_claims("{\"\\u006ati\":\"id1\",\"htm\":\"GET\",\"htu\":\"https://api.example.com/\",\"iat\":1714000000}", esc_claims));
    assert(!auth::verify_dpop_jti("{\"jti\":\"bad jti with spaces\",\"htm\":\"GET\",\"htu\":\"https://api.example.com/\",\"iat\":1714000000}"));
    assert(!auth::verify_dpop_method("{\"jti\":\"id1\",\"htm\":\"GET /\",\"htu\":\"https://api.example.com/\",\"iat\":1714000000}", "GET /"));
    assert(!auth::matches_dpop_jkt_thumbprint(pub_key, "mismatched_claims_jkt_value_123456789012345", expected_jkt[..]));
    var tiny_proof: u8[..64] = [];
    assert(!auth::create_dpop_proof(key, "POST", "https://api.example.com/token", "", "", now_sec, "jti-1", tiny_proof));

    // ---- 10. F001, F004 & F006: Padded JWS, Non-Integer IAT & Dirty Claims --
    var padded_proof: u8[>..] = [];
    padded_proof.append(proof[..]);
    padded_proof.push('=');
    assert(!auth::verify_dpop_proof(padded_proof[..], key, "POST", "https://api.example.com/token", "", "", now_sec, 300, 60, expected_jkt[..]));

    var bad_iat_claims = auth::DPoPClaims { .. };
    assert(!auth::parse_dpop_claims("{\"jti\":\"id1\",\"htm\":\"GET\",\"htu\":\"https://api.example.com/\",\"iat\":1e100}", bad_iat_claims));
    assert(!auth::parse_dpop_claims("{\"jti\":\"id1\",\"htm\":\"GET\",\"htu\":\"https://api.example.com/\",\"iat\":\"1714000000\"}", bad_iat_claims));
    assert(bad_iat_claims.jti.len == 0 && !bad_iat_claims.has_iat);
    print("DPOP_ESCAPED_AND_BOUNDS: OK");
}

// CHECK: DPOP_JKT_VERIFICATION: OK
// CHECK: DPOP_JTI_REPLAY_CACHE: OK
// CHECK: DPOP_JTI_ENTROPY: OK
// CHECK: DPOP_ATTACH_AND_SENSITIVE: OK
// CHECK: DPOP_URI_NORMALIZATION: OK
// CHECK: DPOP_CLAIMS_BUILD: OK
// CHECK: DPOP_HEADER_REJECTIONS: OK
// CHECK: DPOP_NONCE_VALIDATION: OK
// CHECK: DPOP_ESCAPED_AND_BOUNDS: OK

// ============================================================================
// 6. rfc_repro_auth_jwks_edge (6/9)
// ============================================================================
// CHECK: === [6/9] rfc_repro_auth_jwks_edge ===

// tests/lit/rfc_repro_auth_jwks_edge.goose
// RFC 7517 / RFC 8725 JWKS Edge Cases, SSRF Defense, and Private Key Rejection.
//

fn run_06_rfc_repro_auth_jwks_edge() {
    // ---- 1. RFC 8725 §3.12: Remote JWKS URL SSRF Prevention ---------------
    assert(!auth::is_safe_remote_jwks_url("https://localhost........./jwks.json"));
    assert(!auth::is_safe_remote_jwks_url("https://[::1]/jwks.json"));
    assert(!auth::is_safe_remote_jwks_url("https://[0::1]/jwks.json"));
    assert(!auth::is_safe_remote_jwks_url("https://[::ffff:169.254.169.254]/jwks.json"));
    assert(!auth::is_safe_remote_jwks_url("https://[0::ffff:169.254.169.254]/jwks.json"));
    assert(!auth::is_safe_remote_jwks_url("https://[fd01::1]/jwks.json"));
    assert(!auth::is_safe_remote_jwks_url("https://[fe81::1]/jwks.json"));
    assert(!auth::is_safe_remote_jwks_url("https://127.0.0.300/jwks.json"));
    assert(auth::is_safe_remote_jwks_url("https://auth.example.com/.well-known/jwks.json"));
    print("JWKS_SSRF_DEFENSE: OK");

    // ---- 2. RFC 7517 §4: Reject Private Key Parameters in Public JWKS -----
    let jwk_private = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"d\":\"secret_private_d_param\",\"kid\":\"key-priv\"}]}";
    var jwks_priv = auth::Jwks { .. };
    assert(!auth::parse_jwks_json(jwk_private, jwks_priv));
    assert(jwks_priv.keys.len == 0);
    print("JWKS_REJECT_PRIVATE_KEY: OK");

    // ---- 3. Duplicate Member Rejection in JWK -----------------------------
    let jwk_dup = "{\"keys\":[{\"kty\":\"OKP\",\"kty\":\"oct\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\",\"kid\":\"key-dup\"}]}";
    var jwks_dup = auth::Jwks { .. };
    assert(!auth::parse_jwks_json(jwk_dup, jwks_dup));
    assert(jwks_dup.keys.len == 0);
    print("JWKS_REJECT_DUPLICATES: OK");

    // ---- 4. Overflowing Dummy Fields, Duplicate Root Keys, & Bounds --------
    let jwk_many_fields = "{\"keys\":[{\"a1\":1,\"a2\":2,\"a3\":3,\"a4\":4,\"a5\":5,\"a6\":6,\"a7\":7,\"a8\":8,\"a9\":9,\"a10\":10,\"a11\":11,\"a12\":12,\"a13\":13,\"a14\":14,\"a15\":15,\"a16\":16,\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}]}";
    var jwks_many = auth::Jwks { .. };
    assert(!auth::parse_jwks_json(jwk_many_fields, jwks_many));

    let jwk_dup_root = "{\"keys\":[{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"11qYAYKxCrfVS_7TyWQHOg7hcvPapiMlrwIaaPcHURo\"}],\"keys\":[]}";
    assert(!auth::parse_jwks_json(jwk_dup_root, jwks_many));
    assert(jwks_many.keys.len == 0);

    var jwks_sym = auth::Jwks { .. };
    assert(!auth::add_symmetric_key(jwks_sym, "k1", auth::JwtAlg.EdDSA, "0123456789abcdef0123456789abcdef"));
    assert(!auth::add_symmetric_key(jwks_sym, "k1", auth::JwtAlg.None, "0123456789abcdef0123456789abcdef"));
    assert(auth::add_symmetric_key(jwks_sym, "k1", auth::JwtAlg.HS256, "0123456789abcdef0123456789abcdef"));
    var tiny_tp: u8[..16] = [];
    assert(!auth::compute_jwk_thumbprint(jwks_sym.keys[0], tiny_tp));

    // ---- 5. F002: Reject Non-Minimal RSA Base64urlUInt & Invalid Exponents -
    var jwks_rsa = auth::Jwks { .. };
    var valid_n: u8[256] = [0xFF; 256];
    valid_n[0] = 0x80;
    valid_n[255] = 0x01;
    let valid_e:   u8[3] = [0x01, 0x00, 0x01];
    let padded_e:  u8[4] = [0x00, 0x01, 0x00, 0x01];
    let bad_e_one: u8[1] = [0x01];
    var padded_n: u8[256] = [0xFF; 256];
    padded_n[0] = 0x00;

    assert(!auth::add_rsa_key(jwks_rsa, "rsa-pad-e", auth::JwtAlg.RS256, valid_n[..], padded_e[..]));
    assert(!auth::add_rsa_key(jwks_rsa, "rsa-bad-e", auth::JwtAlg.RS256, valid_n[..], bad_e_one[..]));
    assert(!auth::add_rsa_key(jwks_rsa, "rsa-pad-n", auth::JwtAlg.RS256, padded_n[..], valid_e[..]));
    assert(auth::add_rsa_key(jwks_rsa, "rsa-ok", auth::JwtAlg.RS256, valid_n[..], valid_e[..]));

    var n_b64: u8[..512] = [];
    core::base64url_encode(valid_n[..], n_b64);
    var jwk_rsa_pad_e: u8[..512] = [];
    jwk_rsa_pad_e.append("{\"keys\":[{\"kty\":\"RSA\",\"n\":\"");
    jwk_rsa_pad_e.append(n_b64[..]);
    jwk_rsa_pad_e.append("\",\"e\":\"AAEAAQ\"}]}");
    var parsed_rsa_jwks = auth::Jwks { .. };
    assert(!auth::parse_jwks_json(jwk_rsa_pad_e[..], parsed_rsa_jwks));
    print("JWKS_BOUNDS_AND_ALG_HARDENING: OK");
}

// CHECK: JWKS_SSRF_DEFENSE: OK
// CHECK: JWKS_REJECT_PRIVATE_KEY: OK
// CHECK: JWKS_REJECT_DUPLICATES: OK
// CHECK: JWKS_BOUNDS_AND_ALG_HARDENING: OK

// ============================================================================
// 7. rfc_repro_auth_jwt_edge (7/9)
// ============================================================================
// CHECK: === [7/9] rfc_repro_auth_jwt_edge ===

// tests/lit/rfc_repro_auth_jwt_edge.goose
// RFC 7515 / RFC 7519 JWT Edge Cases, DoS Defense, and Invariant Verification.
//

fn run_07_rfc_repro_auth_jwt_edge() {
    let secret = "my_super_secret_signing_key_32b!";
    let now_sec: i64 = 1714000000;

    // ---- 1. RFC 7515 §2: Reject '=' Padding in JWS Base64URL ---------------
    var token_with_pad: u8[>..] = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.c2lnbmF0dXJl==";
    var out_h = auth::JwtHeader { .. };
    var out_c = auth::JwtClaims { .. };
    var opts = auth::JwtValidationOptions { .. };
    let err_pad = auth::verify_jwt_hmac(token_with_pad[..], secret, opts, now_sec, out_h, out_c);
    assert(err_pad == auth::JwtError.MalformedToken);
    print("JWT_REJECT_PAD: OK");

    // ---- 2. Transactional State on Verification Failure -------------------
    var valid_hdr = auth::JwtHeader { .. };
    valid_hdr.alg = auth::JwtAlg.HS256;
    var valid_claims = auth::JwtClaims { .. };
    valid_claims.sub.append("secret_admin_user");
    valid_claims.exp = now_sec + 3600;
    var valid_token: u8[>..] = [];
    assert(auth::sign_jwt_hmac(valid_hdr, valid_claims, secret, valid_token));

    var tampered_token: u8[>..] = [];
    tampered_token.append(valid_token[..]);
    tampered_token[tampered_token.len - 1] = if tampered_token[tampered_token.len - 1] == 'a' { 'b' } else { 'a' };

    var fresh_h = auth::JwtHeader { .. };
    var fresh_c = auth::JwtClaims { .. };
    let err_sig = auth::verify_jwt_hmac(tampered_token[..], secret, opts, now_sec, fresh_h, fresh_c);
    assert(err_sig == auth::JwtError.SignatureInvalid || err_sig == auth::JwtError.InvalidBase64);
    assert(fresh_c.sub.len == 0); // Must NOT be populated with unverified claims
    print("JWT_TRANSACTIONAL_STATE: OK");

    // ---- 3. Large Signature DoS Defense -----------------------------------
    var dos_token: u8[>..] = "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJhbGljZSJ9.";
    for _ in 500 { dos_token.push('A'); }
    var dos_h = auth::JwtHeader { .. };
    var dos_c = auth::JwtClaims { .. };
    let err_dos = auth::verify_jwt_hmac(dos_token[..], secret, opts, now_sec, dos_h, dos_c);
    assert(err_dos == auth::JwtError.SignatureInvalid || err_dos == auth::JwtError.MalformedToken);
    print("JWT_LARGE_SIG_DOS: OK");

    // ---- 4. Escaped Key Smuggling Rejection --------------------------------
    var escaped_crit_hdr = "{\"alg\":\"HS256\",\"\\u0063rit\":[\"custom\"]}";
    var crit_h = auth::JwtHeader { .. };
    assert(!auth::parse_jwt_header_json(escaped_crit_hdr, crit_h));
    print("JWT_ESCAPED_KEY_REJECT: OK");

    // ---- 5. Standard Claim Collision in set_claim -------------------------
    var claims_obj = auth::JwtClaims { .. };
    assert(!auth::set_claim(claims_obj, "exp", "1234567"));
    assert(!auth::set_claim(claims_obj, "sub", "admin"));
    assert(!auth::set_claim_int(claims_obj, "exp", 1234567));
    assert(auth::set_claim(claims_obj, "custom_role", "admin"));
    print("JWT_STANDARD_CLAIM_COLLISION: OK");

    // ---- 6. Integer Reading for Standard Claims ---------------------------
    var num_claims_json = "{\"sub\":\"user1\",\"exp\":1714000100,\"iat\":1714000000}";
    var parsed_c = auth::JwtClaims { .. };
    assert(auth::parse_jwt_claims_json(num_claims_json, parsed_c));
    assert(parsed_c.exp == 1714000100);
    assert(parsed_c.iat == 1714000000);
    assert(!auth::parse_jwt_claims_json("{\"sub\":\"user1\",\"exp\":1e100}", parsed_c));

    var tiny_tok: u8[..32] = [];
    assert(!auth::sign_jwt_hmac(valid_hdr, valid_claims, secret, tiny_tok));
    assert(parsed_c.iss.try_set("valid-issuer"));
    var long_iss: u8[..160] = [];
    for _ in 140 { long_iss.push('x'); }
    assert(!parsed_c.iss.try_set(long_iss[..]));
    assert(parsed_c.iss[..] == "valid-issuer");
    assert(!auth::add_header_crit(valid_hdr, ""));
    assert(!auth::add_header_crit(valid_hdr, "alg"));
    assert(!auth::set_claim(parsed_c, "", "val"));

    // ---- 7. F006: Transactional JSON Parsing, Empty Aud & Supported Crit ---
    var dirty_hdr = auth::JwtHeader { .. };
    assert(!auth::parse_jwt_header_json("{\"kid\":\"leaked-kid\",\"alg\":\"HS256\",\"alg\":\"RS256\"}", dirty_hdr));
    assert(dirty_hdr.kid.len == 0);

    var dirty_clm = auth::JwtClaims { .. };
    assert(!auth::parse_jwt_claims_json("{\"sub\":\"leaked-sub\",\"exp\":1e100}", dirty_clm));
    assert(dirty_clm.sub.len == 0);

    var aud_clm = auth::JwtClaims { .. };
    assert(!auth::set_audience(aud_clm, ""));
    assert(!auth::add_audience(aud_clm, ""));
    assert(aud_clm.audiences.len == 0);

    var crit_opts = auth::JwtValidationOptions { .. };
    assert(!auth::add_supported_crit(crit_opts, "alg"));
    assert(auth::add_supported_crit(crit_opts, "custom_ext"));
    assert(!auth::add_supported_crit(crit_opts, "custom_ext"));
    print("JWT_INT_CLAIMS_PARSING: OK");
}

// CHECK: JWT_REJECT_PAD: OK
// CHECK: JWT_TRANSACTIONAL_STATE: OK
// CHECK: JWT_LARGE_SIG_DOS: OK
// CHECK: JWT_ESCAPED_KEY_REJECT: OK
// CHECK: JWT_STANDARD_CLAIM_COLLISION: OK
// CHECK: JWT_INT_CLAIMS_PARSING: OK

// ============================================================================
// 8. rfc_repro_auth_pkce_edge (8/9)
// ============================================================================
// CHECK: === [8/9] rfc_repro_auth_pkce_edge ===

// tests/lit/rfc_repro_auth_pkce_edge.goose
// RFC 7636 PKCE & RFC 8555 ACME Edge Cases, Padding Invariants, and Strict Verification.
//

fn run_08_rfc_repro_auth_pkce_edge() {
    // ---- 1. RFC 7636 Appendix B Official Test Vector -----------------------
    let rfc_verifier = "dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk";
    let expected_challenge = "E9Melhoa2OwvFrEMTJguCHaoeK1t8URWbuGJSstw-cM";

    var computed_chal: u8[..64] = [];
    assert(auth::compute_code_challenge(rfc_verifier, "S256", computed_chal));
    assert(computed_chal[..] == expected_challenge);
    assert(auth::validate_code_challenge(rfc_verifier, expected_challenge, "S256"));
    print("PKCE_OFFICIAL_VECTOR: OK");

    // ---- 2. RFC 7636 §4.2 Canonical S256 Padding Validation ----------------
    // 'M' at index 42 has bits 1..0 as 00 (canonical padding bits).
    assert(auth::is_valid_code_challenge(expected_challenge, "S256"));

    // Mutate the 43rd character to 'N' (bits 1..0 != 00)
    var non_canonical: u8[..64] = [];
    non_canonical.append(expected_challenge[..42]);
    non_canonical.push('N');
    assert(!auth::is_valid_code_challenge(non_canonical[..], "S256"));
    print("PKCE_CANONICAL_PADDING: OK");

    // ---- 3. RFC 7636 §4.1 Bounds and Disallowed Characters -----------------
    // Length < 43 rejected
    assert(!auth::is_valid_code_verifier("short_verifier_less_than_43_chars_long"));
    // Length > 128 rejected
    var too_long: u8[..140] = [];
    for i in 129 {
        too_long.push('a');
    }
    assert(!auth::is_valid_code_verifier(too_long[..]));
    // Disallowed chars (like padding '=' or '+' or '/')
    assert(!auth::is_valid_code_verifier("dBjftJeZ4CVP-mB92K27uhbUJU1p1r_wW1gFWFOEjXk="));
    assert(!auth::is_valid_code_verifier("dBjftJeZ4CVP+mB92K27uhbUJU1p1r_wW1gFWFOEjXk"));
    print("PKCE_BOUNDS_AND_CHARS: OK");

    // ---- 4. RFC 7636 §4.3 Method Case-Sensitivity & OAuth 2.1 Strict -------
    var chal_out: u8[..64] = [];
    // Lowercase method must be rejected
    assert(!auth::compute_code_challenge(rfc_verifier, "s256", chal_out));
    assert(!auth::compute_code_challenge(rfc_verifier, "Plain", chal_out));
    // Strict mode rejects "plain"
    assert(!auth::is_valid_code_challenge_strict(rfc_verifier, "plain"));
    assert(!auth::validate_code_challenge_strict(rfc_verifier, rfc_verifier, "plain"));
    assert(auth::is_valid_code_challenge_strict(expected_challenge, "S256"));
    print("PKCE_METHOD_AND_STRICT: OK");

    // ---- 5. RFC 8555 §8.1 & §8.3 ACME Challenge Primitives ----------------
    var key_auth: u8[..256] = [];
    let tok = "LoqXcYV8q5ONbJQxbmR7SC";
    let thumb = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
    let ok_ka = auth::build_acme_key_authorization(tok, thumb, key_auth);
    assert(ok_ka);
    assert(key_auth.len == 66);
    assert(key_auth[..] == "LoqXcYV8q5ONbJQxbmR7SC.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");

    // ACME token traversal and < 128-bit entropy attempts rejected
    assert(!auth::validate_acme_token("../secret"));
    assert(!auth::validate_acme_token("token.with.dot.long22c"));
    assert(!auth::validate_acme_token("token/slash/long22char"));
    assert(!auth::validate_acme_token("token with space 22chr"));
    assert(!auth::validate_acme_token("short_21_char_token_1"));
    assert(!auth::validate_acme_token(""));

    // ACME HTTP-01 matching
    var acme_table: auth::AcmeChallenge[..8] = [];
    var ch_entry = auth::AcmeChallenge {
        token:    "LoqXcYV8q5ONbJQxbmR7SC",
        key_auth: "LoqXcYV8q5ONbJQxbmR7SC.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
    };
    acme_table.push(ch_entry);

    var out_resp: u8[..256] = [];
    assert(auth::find_acme_challenge(acme_table, "/.well-known/acme-challenge/LoqXcYV8q5ONbJQxbmR7SC", out_resp));
    assert(out_resp.len == 66);
    assert(out_resp[..] == "LoqXcYV8q5ONbJQxbmR7SC.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");

    // Path traversal or mismatched path rejected
    assert(!auth::find_acme_challenge(acme_table, "/.well-known/acme-challenge/../LoqXcYV8q5ONbJQxbmR7SC", out_resp));
    assert(!auth::find_acme_challenge(acme_table, "/api/v1/LoqXcYV8q5ONbJQxbmR7SC", out_resp));

    // ---- 6. ACME Thumbprint Validation & PKCE Small Buffer Bounds ----------
    assert(!auth::build_acme_key_authorization(tok, "", key_auth));
    assert(!auth::build_acme_key_authorization(tok, "short_thumbprint_20c", key_auth));
    assert(!auth::build_acme_key_authorization(tok, "bad/thumbprint_0123456789012345678901234567", key_auth));
    assert(!auth::build_acme_key_authorization(tok, "bad.thumbprint_0123456789012345678901234567", key_auth));

    var tiny_buf: u8[..32] = [];
    assert(!auth::compute_code_challenge(rfc_verifier, "S256", tiny_buf));
    assert(!auth::compute_code_challenge(rfc_verifier, "plain", tiny_buf));
    assert(!auth::generate_code_verifier(tiny_buf));
    assert(!auth::generate_code_verifier(tiny_buf, "0123456789abcdef0123456789abcdef"));
    print("ACME_PRIMITIVES: OK");
}

// CHECK: PKCE_OFFICIAL_VECTOR: OK
// CHECK: PKCE_CANONICAL_PADDING: OK
// CHECK: PKCE_BOUNDS_AND_CHARS: OK
// CHECK: PKCE_METHOD_AND_STRICT: OK
// CHECK: ACME_PRIMITIVES: OK

// ============================================================================
// 9. verify_auth_digest_edge (9/9)
// ============================================================================
// CHECK: === [9/9] verify_auth_digest_edge ===

// tests/lit/verify_auth_digest_edge.goose
// Verification of RFC 7616 HTTP Digest authentication challenge parsing via wing::auth.
//

// Wire validator for RFC 7616 Digest challenge using auth::parse_digest_challenge
fn wing_validate_digest_challenge_wire(buf: const u8[:]) -> i64 {
    let chal, ok = auth::parse_digest_challenge(buf);
    if ok {
        return 1;
    }

    // Check for explicit syntax violation (e.g. key without '=' delimiter)
    var idx: i64 = 0;
    while idx < buf.len {
        let rem = buf[idx..].trim_start_bytes(" \t,\r\n");
        idx = buf.len - rem.len;
        guard idx < buf.len else { break; }

        let key, key_ok = auth::parse_digest_param_key(buf, idx);
        guard key_ok else { break; }

        let rem_pre = buf[idx..].trim_start_bytes(" \t");
        if rem_pre.len > 0 && rem_pre[0] != '=' {
            return -2;
        }

        var val: u8[..128] = [];
        let val_ok = auth::parse_digest_param_val(buf, idx, val);
        guard val_ok else { break; }
    }

    return -1;
}

fn run_09_verify_auth_digest_edge() {
    let challenge = "realm=\"test@example.com\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\"";
    assert(wire_kit::verify_split_stream(challenge, -1, 1, wing_validate_digest_challenge_wire));
    assert(wire_kit::fuzz_payload(challenge, 100, wing_validate_digest_challenge_wire));

    let parsed_chal, chal_ok = auth::parse_digest_challenge(challenge);
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

fn main() {
    print("\n=== [1/9] rfc_repro_auth_audit_hunter ===\n");
    run_01_rfc_repro_auth_audit_hunter();
    print("\n=== [2/9] rfc_repro_auth_cross_rfc ===\n");
    run_02_rfc_repro_auth_cross_rfc();
    print("\n=== [3/9] rfc_repro_auth_digest_edge ===\n");
    run_03_rfc_repro_auth_digest_edge();
    print("\n=== [4/9] rfc_repro_auth_digest_vector ===\n");
    run_04_rfc_repro_auth_digest_vector();
    print("\n=== [5/9] rfc_repro_auth_dpop_edge ===\n");
    run_05_rfc_repro_auth_dpop_edge();
    print("\n=== [6/9] rfc_repro_auth_jwks_edge ===\n");
    run_06_rfc_repro_auth_jwks_edge();
    print("\n=== [7/9] rfc_repro_auth_jwt_edge ===\n");
    run_07_rfc_repro_auth_jwt_edge();
    print("\n=== [8/9] rfc_repro_auth_pkce_edge ===\n");
    run_08_rfc_repro_auth_pkce_edge();
    print("\n=== [9/9] verify_auth_digest_edge ===\n");
    run_09_verify_auth_digest_edge();
}
