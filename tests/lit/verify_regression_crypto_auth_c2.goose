// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Goose LIT Regression Suite: Cycle 2 Crypto, Auth, TLS & Cookie Security Bugs (CAB-C2-01..04)
// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

// CAB-C2-01: X.509 ParsedCert struct reuse state leak, unverified self-issued trust anchor
// signature forgery, unvalidated SAN extension in verify_certificate_chain, and duplicate AKID/SKID.
fn test_cab_c2_01_x509_chain_and_parser() {
    let seed: u8[32] = [0x7A; 32];
    var valid_der: u8[..2048] = [];
    assert(wing::build_test_ed25519_cert_der(seed, "example.com", "example.com", "127.0.0.1", valid_der));

    var cert = wing::ParsedCert { .. };
    assert(wing::parse_x509_certificate(valid_der[..], cert));

    // 1. Reusing a dirty ParsedCert across parse_x509_certificate calls must not leak state
    // or trigger false-positive duplicate extension errors on the second parse.
    var reused_cert = cert;
    reused_cert.is_ca = true;
    reused_cert.path_len_constraint = 3;
    reused_cert.has_must_staple = true;
    let reparse_ok = wing::parse_x509_certificate(valid_der[..], reused_cert);
    let reuse_clean = reparse_ok &&
        !reused_cert.has_unsupported_critical &&
        reused_cert.path_len_constraint == -1 &&
        !reused_cert.has_must_staple;

    // 2. Self-issued trust anchor signature forgery: corrupt the Ed25519 signature byte in valid_der
    // while keeping Subject DN and SPKI intact so matches_trust_anchor returns true.
    var forged_der: u8[..2048] = [];
    assert(forged_der.try_set(valid_der[..]));
    let last_idx = forged_der.len - 1;
    forged_der[last_idx] = forged_der[last_idx] ^ 0xFF;

    var forged_cert = wing::ParsedCert { .. };
    assert(wing::parse_x509_certificate(forged_der[..], forged_cert));

    var store = wing::TrustAnchorStore { .. };
    assert(wing::add_trust_anchor_cert_der(store, valid_der[..]));

    var chain_forged: wing::ParsedCert[..8] = [];
    var raw_forged:   (const u8[:])[..8]    = [];
    let _ = chain_forged.try_push(forged_cert);
    let _ = raw_forged.try_push(forged_der[..]);
    let forged_alert = wing::verify_certificate_chain(
        chain_forged, raw_forged, store, cert.validity_not_before + 10,
    );
    let forged_rejected = (forged_alert == wing::TlsAlert.BadCertificate);

    // 3. Certificate with corrupted SAN extension bytes must be rejected by verify_certificate_chain
    // even when no CA in the chain has NameConstraints.
    var bad_san_cert = cert;
    bad_san_cert.has_san = true;
    bad_san_cert.san_raw = wing::Span16 { offset: 0, length: 2 };
    var chain_bad_san: wing::ParsedCert[..8] = [];
    var raw_bad_san:   (const u8[:])[..8]    = [];
    let _ = chain_bad_san.try_push(bad_san_cert);
    let _ = raw_bad_san.try_push(valid_der[..]);
    let bad_san_alert = wing::verify_certificate_chain(
        chain_bad_san, raw_bad_san, store, cert.validity_not_before + 10,
    );
    let bad_san_rejected = (bad_san_alert == wing::TlsAlert.BadCertificate);

    print("CAB_C2_01: ", reuse_clean && forged_rejected && bad_san_rejected);
}

// CAB-C2-02: Cookie SameSite & SiteForCookies public-suffix / empty-host / opaque-URL bypass
// and >128-byte registrable domain buffer safety.
fn test_cab_c2_02_cookie_samesite_and_psl() {
    // 1. Empty hosts, invalid hosts, or bare public suffixes must NOT be schemefully same-site.
    let empty_same = wing::is_schemeful_same_site("https", "", "https", "");
    let dots_same = wing::is_schemeful_same_site("https", "...", "https", "...");
    let psl_same1 = wing::is_schemeful_same_site("https", "github.io", "https", "github.io");
    let psl_same2 = wing::is_schemeful_same_site("https", "co.uk", "https", "co.uk");

    // 2. site_for_cookies_from_url on opaque/empty/public-suffix URLs must produce is_null = true,
    // and compute_site_for_cookies_with_ancestors must reject uppercase DATA:/ABOUT:/javascript:/blob:.
    let sfc_empty = wing::site_for_cookies_from_url("");
    let sfc_psl = wing::site_for_cookies_from_url("https://github.io/login");
    let sfc_data_upper = wing::compute_site_for_cookies_with_ancestors("DATA:text/html,hi", []);
    let sfc_about_upper = wing::compute_site_for_cookies_with_ancestors("ABOUT:blank", []);
    let sfc_js = wing::compute_site_for_cookies_with_ancestors("javascript:alert(1)", []);

    let psl_first_party = wing::is_first_party(sfc_psl, "https://github.io/api", true);

    // 3. Long hostname (180 bytes > 128 bytes) must not panic in is_schemeful_same_site or site_for_cookies.
    var long_host: u8[..256] = [];
    for _ in 3 {
        for _ in 50 { long_host.push('a'); }
        long_host.push('.');
    }
    long_host.append("com");
    let long_same = wing::is_schemeful_same_site("https", long_host[..], "https", long_host[..]);

    let ok = !empty_same && !dots_same && !psl_same1 && !psl_same2 &&
        sfc_empty.is_null && sfc_psl.is_null &&
        sfc_data_upper.is_null && sfc_about_upper.is_null && sfc_js.is_null &&
        !psl_first_party && long_same;
    print("CAB_C2_02: ", ok);
}

// CAB-C2-03: PrivateJar expired cookie decrypted plaintext leak in generic <B> out_plaintext under -O2,
// revoked KeySlot acceptance in add_key, and CORS wildcard credentials / Authorization preflight bypass.
fn test_cab_c2_03_crypto_jar_and_cors() {
    // 1. Revoked KeySlot must be rejected by add_key.
    var store = wing::KeyStore { max_age_sec: 60, clock_skew_tolerance_sec: 10, .. };
    var raw_key: u8[32] = [0x42; 32];
    let active_slot = core::new_key_slot(1, raw_key[..], 1700000000);
    assert(wing::add_key(store, active_slot));

    var revoked_slot = core::new_key_slot(99, raw_key[..], 1700000000);
    revoked_slot.revoked = true;
    let revoked_added = wing::add_key(store, revoked_slot);

    // 2. Expired cookie in PrivateJar (both XChaCha20 and HKDF-AES) must NOT leave decrypted
    // plaintext in out_plaintext when private_jar_open / private_jar_open_binary returns false!
    let pjar_x = wing::new_private_jar(store, false);
    let pjar_aes = wing::new_private_jar(store, true);

    var wire_x:   u8[..256] = [];
    var wire_aes: u8[..256] = [];
    assert(wing::private_jar_seal_binary(pjar_x, "sid", "TOP_SECRET_COOKIE_VAL", 1700000000, 111, wire_x));
    assert(wing::private_jar_seal_binary(pjar_aes, "sid", "TOP_SECRET_COOKIE_VAL", 1700000000, 222, wire_aes));

    var leaked_x:   u8[..256] = [];
    var leaked_aes: u8[..256] = [];
    let open_exp_x = wing::private_jar_open_binary(pjar_x, "sid", wire_x[..], 1700001000, leaked_x);
    let open_exp_aes = wing::private_jar_open_binary(pjar_aes, "sid", wire_aes[..], 1700001000, leaked_aes);
    let no_plaintext_leak = !open_exp_x && leaked_x.len == 0 && !open_exp_aes && leaked_aes.len == 0;

    // 3. CORS: wildcard "*" in allowed_headers must NOT cover "Authorization" without explicit listing,
    // and wildcard "*" in allowed_methods / allowed_headers must NOT match when allow_credentials = true.
    let auth_wild_allowed = wing::are_cors_request_headers_allowed("*", "Authorization");
    let empty_req_hdrs_allowed = wing::are_cors_request_headers_allowed("X-Custom", " , ");

    var cred_cors = wing::CorsPolicy {
        allow_credentials: true,
        allowed_methods:   "*",
        allowed_headers:   "*",
        ..
    };
    assert(wing::add_allowed_origin(cred_cors, "https://app.example.com"));
    var pre_req = wing::new_request("OPTIONS", "/api/data");
    wing::set_header(pre_req, "Origin", "https://app.example.com");
    wing::set_header(pre_req, "Access-Control-Request-Method", "DELETE");
    var pre_res = wing::Response { .. };
    let pre_res_code = wing::evaluate_cors(cred_cors, pre_req, pre_res);
    let cred_wild_rejected = (pre_res_code != wing::CorsResult.AllowedPreflight);

    print("CAB_C2_03: ", !revoked_added && no_plaintext_leak && !auth_wild_allowed && !empty_req_hdrs_allowed && cred_wild_rejected);
}

// CAB-C2-04: JWE direct A256GCM unvalidated protected header bypass, ConcatKDF PartyInfo
// truncation collision, and OAuth Device Grant duplicate key / unsafe URI injection.
fn test_cab_c2_04_jwe_and_device_grant() {
    let z:  u8[32] = [0x55; 32];
    let iv: u8[12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];

    // 1. ConcatKDF with 300-byte PartyUInfo must not silently drop PartyVInfo or key_bits.
    var big_apu: u8[..320] = [];
    for _ in 300 { big_apu.push('U'); }
    let kdf_bob = wing::concat_kdf_sha256(z, "A256GCM", big_apu[..], "Bob", 256);
    let kdf_mallory = wing::concat_kdf_sha256(z, "A256GCM", big_apu[..], "Mallory", 256);
    let kdf_no_collision = !core::ct_eq_tag32(kdf_bob, kdf_mallory);

    // 2. JWE must reject protected_b64 headers that are not valid JSON with alg="dir" and enc="A256GCM".
    // "eyJhbGciOiJub25lIiwiZW5jIjoiQTI1NkdDTSJ9" = {"alg":"none","enc":"A256GCM"}
    let bad_hdr_b64 = "eyJhbGciOiJub25lIiwiZW5jIjoiQTI1NkdDTSJ9";
    var bad_jwe: u8[..512] = [];
    let sealed_bad_hdr = wing::jwe_seal_dir_a256gcm(bad_hdr_b64, kdf_bob, iv, "secret", bad_jwe);

    // Also test opening a manually constructed JWE with {"alg":"none","enc":"A256GCM"} as AAD:
    var forged_ct: u8[64] = [0; 64];
    let tag, ct_len, ok_gcm = core::aes256_gcm_seal(kdf_bob, iv, "secret", bad_hdr_b64, forged_ct[..]);
    assert(ok_gcm);
    var forged_token: u8[..512] = [];
    forged_token.append(bad_hdr_b64);
    forged_token.append("..");
    core::base64url_encode(iv[..], forged_token);
    forged_token.push('.');
    core::base64url_encode(forged_ct[..ct_len], forged_token);
    forged_token.push('.');
    core::base64url_encode(tag[..], forged_token);

    var out_plain: u8[..128] = [];
    let opened_bad_hdr = wing::jwe_open_dir_a256gcm(forged_token[..], kdf_bob, out_plain);

    // 3. OAuth Device Grant must reject javascript: verification_uri and duplicate JSON keys.
    let js_dev_json = "{\"device_code\":\"dc1\",\"user_code\":\"uc1\",\"verification_uri\":\"javascript:alert(1)\",\"expires_in\":600}";
    let _, ok_js_dev = wing::parse_device_auth_response(js_dev_json);

    let dup_dev_json = "{\"device_code\":\"dc1\",\"device_code\":\"dc2\",\"user_code\":\"uc1\",\"verification_uri\":\"https://example.com/dev\",\"expires_in\":600}";
    let _, ok_dup_dev = wing::parse_device_auth_response(dup_dev_json);

    print("CAB_C2_04: ", kdf_no_collision && !sealed_bad_hdr && !opened_bad_hdr && !ok_js_dev && !ok_dup_dev);
}

fn main() {
    // CHECK: CAB_C2_01: true
    test_cab_c2_01_x509_chain_and_parser();
    // CHECK-NEXT: CAB_C2_02: true
    test_cab_c2_02_cookie_samesite_and_psl();
    // CHECK-NEXT: CAB_C2_03: true
    test_cab_c2_03_crypto_jar_and_cors();
    // CHECK-NEXT: CAB_C2_04: true
    test_cab_c2_04_jwe_and_device_grant();
}
