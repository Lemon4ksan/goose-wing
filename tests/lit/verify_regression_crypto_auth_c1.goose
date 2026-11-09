// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Cycle 1 Security Regression Suite (crypto_auth_breaker):
// 1. security/csrf.goose: Fetch Metadata SameSite sensitive navigation / embedding bypass,
//    empty Sec-Fetch-Site header smuggling, and duplicate conflicting Origin headers.
// 2. auth/dpop.goose & auth/introspection.goose: Malformed non-object / duplicate "jwk"
//    header validation bypass and enterprise 4096-byte token buffer truncation/rejection.
// 3. tls/session.goose, tls/crl.goose & tls/ticket.goose: TLS 1.3 CRL signature & issuer DN
//    verification bypass, CRL inner/outer signatureAlgorithm OID mismatch, and session ticket
//    RFC 8446 §4.6.1 lifetime cap + transactional lookup out-buffer hygiene.
// 4. auth/digest.goose: Non-transactional out_header on compute_digest_response failure
//    and secret zeroization of intermediate HA1 / A3 buffers.
//
// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

// CHECK: === CYCLE 1 CRYPTO AUTH BREAKER REGRESSION SUITE ===

fn test_bug1_csrf_fetch_metadata_bypasses() {
    var guard_cfg = wing::CrossOriginGuard { .. };
    guard_cfg.allow_same_site = false;
    guard_cfg.require_user_activation_on_sensitive_nav = true;

    // 1A. Same-site GET navigation to sensitive route (/oauth/authorize) without user activation (?1)
    // must be rejected both via evaluate_request_csrf and evaluate_fetch_metadata.
    var req_sens = wing::new_request("GET", "https://app.example.com/oauth/authorize?client_id=1");
    wing::set_header(req_sens, "Sec-Fetch-Site", "same-site");
    wing::set_header(req_sens, "Sec-Fetch-Mode", "navigate");
    wing::set_header(req_sens, "Sec-Fetch-Dest", "document");

    let dec_req_sens = wing::evaluate_request_csrf(guard_cfg, req_sens, "app.example.com", true);
    let ctx_sens = wing::extract_fetch_context(req_sens, "app.example.com", true);
    let dec_ctx_sens = wing::evaluate_fetch_metadata(guard_cfg, ctx_sens);

    // 1B. Same-site iframe embedding when allow_same_site = false must be rejected.
    var req_embed = wing::new_request("GET", "https://app.example.com/dashboard");
    wing::set_header(req_embed, "Sec-Fetch-Site", "same-site");
    wing::set_header(req_embed, "Sec-Fetch-Mode", "navigate");
    wing::set_header(req_embed, "Sec-Fetch-Dest", "iframe");
    let dec_req_embed = wing::evaluate_request_csrf(guard_cfg, req_embed, "app.example.com", false);

    // 1C. Empty Sec-Fetch-Site header followed by same-origin duplicate must not smuggle SameOrigin.
    var req_smuggle = wing::new_request("POST", "https://app.example.com/transfer");
    wing::append_header(req_smuggle.headers, "Sec-Fetch-Site", "");
    wing::append_header(req_smuggle.headers, "Sec-Fetch-Site", "same-origin");
    let ctx_smuggle = wing::extract_fetch_context(req_smuggle, "app.example.com", false);
    let dec_smuggle = wing::evaluate_request_csrf(guard_cfg, req_smuggle, "app.example.com", false);

    // 1D. Duplicate conflicting Origin headers in fallback mode must fail closed.
    var req_dup_orig = wing::new_request("POST", "https://app.example.com/transfer");
    wing::append_header(req_dup_orig.headers, "Origin", "https://app.example.com");
    wing::append_header(req_dup_orig.headers, "Origin", "https://evil.attacker.example");
    let dec_dup_orig = wing::evaluate_request_csrf(guard_cfg, req_dup_orig, "app.example.com", false);

    let ok = !wing::is_allowed(dec_req_sens) &&
             !wing::is_allowed(dec_ctx_sens) &&
             !wing::is_allowed(dec_req_embed) &&
             ctx_smuggle.site == wing::SecFetchSite.CrossSite &&
             !wing::is_allowed(dec_smuggle) &&
             !wing::is_allowed(dec_dup_orig);
    print("BUG1_CSRF_FETCH_METADATA_DEFENSE: ", ok, "\n");
    assert(ok);
}

// CHECK: BUG1_CSRF_FETCH_METADATA_DEFENSE: true

fn test_bug2_dpop_jwk_and_enterprise_token_buffers() {
    // 2A. DPoP JOSE header with valid "jwk" followed by duplicate non-object "jwk" or
    // non-object "jwk" with pre-populated DPoPJwkInfo must set out_jwk.valid = false and fail.
    let dup_non_obj_hdr =
        "{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"jwk\":{\"kty\":\"OKP\",\"crv\":\"Ed25519\",\"x\":\"1111111111111111111111111111111111111111111\"},\"jwk\":\"not-an-object\"}";
    let single_non_obj_hdr =
        "{\"typ\":\"dpop+jwt\",\"alg\":\"EdDSA\",\"jwk\":\"not-an-object\"}";

    var out_alg: u8[..16] = [];
    var out_jwk = wing::DPoPJwkInfo { .. };
    let ok_parse_non_obj = wing::parse_dpop_header_jwk_info(single_non_obj_hdr, out_alg, out_jwk);
    let ok_verify_non_obj = wing::verify_dpop_header(single_non_obj_hdr, "EdDSA");
    let ok_verify_dup = wing::verify_dpop_header(dup_non_obj_hdr, "EdDSA");

    // 2B. Enterprise-scale DPoP proof (3000 bytes) and access token (3000 bytes) up to 4096 bytes
    // (Invariant 17: MAX_AUTH_TOKEN_LEN = 4096) must be accepted by attach_dpop and encode_token_endpoint_form.
    var big_proof: u8[..4096] = [];
    var big_token: u8[..4096] = [];
    for _ in 3000 {
        big_proof.push('a');
        big_token.push('b');
    }
    var req = wing::Request { .. };
    wing::attach_dpop(req, big_proof[..], big_token[..]);
    let attached_dpop = wing::header(req, "DPoP");
    let attached_auth = wing::header(req, "Authorization");

    var form_out: u8[..8192] = [];
    let ok_form = wing::encode_token_endpoint_form(big_token[..], wing::TokenTypeHint.AccessToken, form_out);

    let ok = !ok_parse_non_obj &&
             !out_jwk.valid &&
             !ok_verify_non_obj &&
             !ok_verify_dup &&
             attached_dpop.len == 3000 &&
             attached_auth.len == 3005 &&
             ok_form;
    print("BUG2_DPOP_AND_ENTERPRISE_TOKEN_BUFFERS: ", ok, "\n");
    assert(ok);
}

// CHECK: BUG2_DPOP_AND_ENTERPRISE_TOKEN_BUFFERS: true

fn test_bug3_tls_crl_verification_and_tickets() {
    // 3A. Build a valid self-signed Ed25519 certificate for example.com (serial = 1).
    let ca_seed: u8[32] = [0x42; 32];
    var cert_der: u8[..2048] = [];
    assert(wing::build_test_ed25519_cert_der(ca_seed, "example.com", "example.com", "127.0.0.1", cert_der));
    var parsed_cert = wing::ParsedCert { .. };
    assert(wing::parse_x509_certificate(cert_der[..], parsed_cert));

    var chain_parsed: wing::ParsedCert[..8] = [];
    chain_parsed.push(parsed_cert);
    var chain_slices: (const u8[:])[..8] = [];
    chain_slices.push(cert_der[..]);

    // Build an unsigned/forged CRL whose signature is invalid (all-zero 64-byte signature)
    // and whose serial list does not revoke serial 1. verify_crl_for_chain MUST reject it!
    let leaf_issuer = wing::span_slice(cert_der[..], parsed_cert.issuer_raw);
    var b_tbs = core::builder_init();
    b_tbs.buf.push(0x30);
    assert(core::start_u8_prefix(b_tbs));
    let sig_der: u8[7] = [0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70]; // Ed25519
    core::put_bytes(b_tbs, sig_der[..]);
    b_tbs.buf.push(0x30);
    b_tbs.buf.push(leaf_issuer.len as u8);
    core::put_bytes(b_tbs, leaf_issuer);
    let time_der: u8[15] = [0x17, 0x0D, '2', '6', '0', '1', '0', '1', '0', '0', '0', '0', '0', '0', 'Z'];
    core::put_bytes(b_tbs, time_der[..]);
    assert(core::finish_u8_prefix(b_tbs));

    var forged_crl = core::builder_init();
    forged_crl.buf.push(0x30);
    assert(core::start_u8_prefix(forged_crl));
    core::put_bytes(forged_crl, b_tbs.buf[..]);
    core::put_bytes(forged_crl, sig_der[..]);
    forged_crl.buf.push(0x03);
    forged_crl.buf.push(0x41);
    forged_crl.buf.push(0x00);
    for _ in 64 { forged_crl.buf.push(0xAA); }
    assert(core::finish_u8_prefix(forged_crl));

    let forged_crl_accepted = wing::verify_crl_for_chain(forged_crl.buf[..], chain_parsed, chain_slices);

    // Build a validly signed CRL using ca_seed -> verify_crl_for_chain MUST accept it (serial 1 not revoked).
    let valid_crl_sig = core::ed25519_sign(ca_seed, b_tbs.buf[..]);
    var valid_crl = core::builder_init();
    valid_crl.buf.push(0x30);
    assert(core::start_u8_prefix(valid_crl));
    core::put_bytes(valid_crl, b_tbs.buf[..]);
    core::put_bytes(valid_crl, sig_der[..]);
    valid_crl.buf.push(0x03);
    valid_crl.buf.push(0x41);
    valid_crl.buf.push(0x00);
    core::put_bytes(valid_crl, valid_crl_sig[..]);
    assert(core::finish_u8_prefix(valid_crl));

    let valid_crl_accepted = wing::verify_crl_for_chain(valid_crl.buf[..], chain_parsed, chain_slices);

    // 3B. CRL with mismatched inner TBSCertList.signature OID vs outer signatureAlgorithm OID must fail parse_x509_crl.
    var mismatch_crl = core::builder_init();
    mismatch_crl.buf.push(0x30);
    assert(core::start_u8_prefix(mismatch_crl));
    core::put_bytes(mismatch_crl, b_tbs.buf[..]);
    let rsa_sig_der: u8[13] = [0x30, 0x0B, 0x06, 0x09, 0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x0B];
    core::put_bytes(mismatch_crl, rsa_sig_der[..]);
    mismatch_crl.buf.push(0x03);
    mismatch_crl.buf.push(0x02);
    mismatch_crl.buf.push(0x00);
    mismatch_crl.buf.push(0x01);
    assert(core::finish_u8_prefix(mismatch_crl));

    var parsed_mismatch = wing::ParsedCrl { .. };
    let mismatch_parsed_ok = wing::parse_x509_crl(mismatch_crl.buf[..], parsed_mismatch);

    // 3C. TLS 1.3 session ticket cache must reject lifetime > MAX_TICKET_LIFETIME_SECS (604800)
    // and clear out_ticket / out_psk on lookup miss.
    wing::clear_tls13_session_tickets();
    let psk32: u8[32] = [0x77; 32];
    wing::store_tls13_session_ticket("overlife.example.com", "ticket-over", psk32[..], 1, 604801);
    var out_t:   u8[..256] = [];
    var out_p:   u8[..48]  = [];
    var out_age: u32       = 99;
    var out_cs:  u16       = 0x1301;
    out_t.append("stale_ticket");
    out_p.append("stale_psk");
    let found_over = wing::lookup_tls13_session_ticket_full("overlife.example.com", out_t, out_p, out_age, out_cs);

    let ok = !forged_crl_accepted &&
             valid_crl_accepted &&
             !mismatch_parsed_ok &&
             !found_over &&
             out_t.len == 0 &&
             out_p.len == 0;
    print("BUG3_TLS_CRL_AND_TICKETS: ", ok, "\n");
    assert(ok);
}

// CHECK: BUG3_TLS_CRL_AND_TICKETS: true

fn test_bug4_digest_transactional_out_buffer() {
    var chal = wing::DigestChallenge {
        valid:     true,
        algorithm: "SHA-256",
        qop:       "auth",
        ..
    };
    chal.realm.append("api@example.com");
    chal.nonce.append("dcd98b7102dd2f0e8b11d0f600bfb0c093");

    var creds = wing::DigestCredentials { .. };
    creds.username.append("Mufasa");
    creds.password.append("Circle Of Life");

    var out_header: u8[..1024] = [];
    out_header.append("Digest username=\"stale_admin\", response=\"deadbeef\"");

    // Failing call (nc == 0 when qop="auth") must clear pre-populated out_header (Invariant 18).
    let ok_fail = wing::compute_digest_response(chal, creds, "GET", "/dir/index.html", 0, "0a4f113b", "", out_header);

    // Failing HA1-sess without cnonce must return empty slice cleanly.
    let ha1_bad_sess = wing::calculate_digest_ha1("SHA-256-sess", "Mufasa", "api@example.com", "secret", "nonce1", "");

    var tiny_sink: u8[..48] = [];
    let ok_tiny = wing::serialize_digest_auth(
        "Mufasa",
        "api@example.com",
        "dcd98b7102dd2f0e8b11d0f600bfb0c093",
        "/dir/index.html",
        "SHA-256",
        "753927fa0e85d155564e2e272a28d1802ca10daf4496794697cf8db5856cb6c1",
        "auth",
        "00000001",
        "0a4f113b",
        "",
        false,
        tiny_sink,
    );

    let ok = !ok_fail && out_header.len == 0 && ha1_bad_sess.len == 0 && !ok_tiny && tiny_sink.len == 0;
    print("BUG4_DIGEST_TRANSACTIONAL_HYGIENE: ", ok, "\n");
    assert(ok);
}

// CHECK: BUG4_DIGEST_TRANSACTIONAL_HYGIENE: true

fn main() {
    print("=== CYCLE 1 CRYPTO AUTH BREAKER REGRESSION SUITE ===\n");
    test_bug1_csrf_fetch_metadata_bypasses();
    test_bug2_dpop_jwk_and_enterprise_token_buffers();
    test_bug3_tls_crl_verification_and_tickets();
    test_bug4_digest_transactional_out_buffer();
}
