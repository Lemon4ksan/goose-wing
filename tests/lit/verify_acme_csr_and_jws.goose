// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Goose LIT Verification Suite: PKCS#10 P-256 CSR & RFC 8555 ACME Wire/JWS Codecs.
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import json;
import wing from "../..";

fn make_test_p256_priv() -> u8[32] {
    return [
        0xc9, 0xaf, 0xa9, 0xd8, 0x45, 0xba, 0x75, 0x16,
        0x6b, 0x5c, 0x21, 0x57, 0x67, 0xb1, 0xd6, 0x93,
        0x4e, 0x50, 0xc3, 0xdb, 0x36, 0xe8, 0x9b, 0x12,
        0x7b, 0x8a, 0x62, 0x2b, 0x12, 0x0f, 0x67, 0x21,
    ];
}

// 1. Widened auth::find_acme_challenge slice (12 items, matching slot 11)
// CHECK: ACME_FIND_12_SLOTS: PASS
fn test_acme_find_12_slots() {
    var table: auth::AcmeChallenge[..16] = [];
    let tp = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
    for i in 11 {
        var tok: u8[..64] = [];
        tok.append("dummy_token_slot_0000_");
        (i as u64).format_u64_dec(tok);
        var ka: u8[..256] = [];
        assert(auth::build_acme_key_authorization(tok[..], tp, ka));
        assert(table.try_push(auth::AcmeChallenge { token: tok, key_auth: ka }));
    }
    var target_ch = auth::AcmeChallenge {
        token:    "LoqXcYV8q5ONbJQxbmR7SC",
        key_auth: "LoqXcYV8q5ONbJQxbmR7SC.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs",
    };
    assert(table.try_push(target_ch));
    assert(table.len == 12);

    var out: u8[..256] = [];
    assert(auth::find_acme_challenge(table[..], "/.well-known/acme-challenge/LoqXcYV8q5ONbJQxbmR7SC", out));
    assert(out[..] == "LoqXcYV8q5ONbJQxbmR7SC.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    assert(!auth::find_acme_challenge(table[..], "/.well-known/acme-challenge/missing_token_0123456789", out));
    assert(out[..] == "LoqXcYV8q5ONbJQxbmR7SC.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    print("ACME_FIND_12_SLOTS: PASS\n");
}

// 2. PKCS#10 P-256 CSR Builder + ASN.1 DER & ECDSA signature verification
// CHECK: PKCS10_CSR_P256: PASS
fn test_pkcs10_csr_p256() {
    let priv_key = make_test_p256_priv();
    let pub_key = core::ecdsa_p256_public_key(priv_key);
    assert(pub_key[0] == 0x04);

    var domains: u8[..255][..2] = [];
    var d1:      u8[..255]      = "example.com";
    var d2:      u8[..255]      = "www.example.com";
    domains.push(d1);
    domains.push(d2);

    var csr_der: u8[>..] = [];
    assert(tls::build_pkcs10_csr_p256_der(priv_key, domains[..], csr_der));
    assert(csr_der.len > 128);

    // Parse outer CertificationRequest SEQUENCE
    var outer = core::cursor_from(csr_der[..]);
    var csr_seq = core::cursor_from(csr_der[..0]);
    assert(tls::get_asn1_element(outer, rfc::ASN1_TAG_SEQUENCE, csr_seq));
    assert(outer.buf.len == 0);

    // Capture exact CertificationRequestInfo TLV bytes
    let cri_start = csr_seq.buf;
    var cri_inner = core::cursor_from(csr_der[..0]);
    assert(tls::get_asn1_element(csr_seq, rfc::ASN1_TAG_SEQUENCE, cri_inner));
    let cri_len = cri_start.len - csr_seq.buf.len;
    let cri_bytes = cri_start[..cri_len];

    // Inspect CertificationRequestInfo fields: version, subject, SPKI, attributes [0]
    var version: i64 = -1;
    assert(tls::get_asn1_integer(cri_inner, version));
    assert(version == 0);

    var subj = core::cursor_from(csr_der[..0]);
    assert(tls::get_asn1_element(cri_inner, rfc::ASN1_TAG_SEQUENCE, subj));

    var spki = core::cursor_from(csr_der[..0]);
    assert(tls::get_asn1_element(cri_inner, rfc::ASN1_TAG_SEQUENCE, spki));
    var spki_alg = core::cursor_from(csr_der[..0]);
    assert(tls::get_asn1_element(spki, rfc::ASN1_TAG_SEQUENCE, spki_alg));
    var ec_oid = core::cursor_from(csr_der[..0]);
    var p256_oid = core::cursor_from(csr_der[..0]);
    assert(tls::get_asn1_element(spki_alg, rfc::ASN1_TAG_OID, ec_oid));
    assert(tls::get_asn1_element(spki_alg, rfc::ASN1_TAG_OID, p256_oid));
    assert(ec_oid.buf == rfc::OID_EC_PUBLIC_KEY[..]);
    assert(p256_oid.buf == rfc::OID_SECP256R1[..]);
    var spk_bits = core::cursor_from(csr_der[..0]);
    var spk_unused: u8 = 1;
    assert(tls::get_asn1_bit_string(spki, spk_bits, spk_unused));
    assert(spk_unused == 0 && spk_bits.buf == pub_key[..]);

    // Attributes [0] IMPLICIT (0xA0) -> Attribute SEQUENCE -> 1.2.840.113549.1.9.14 -> SET -> Extensions -> SAN
    var attrs = core::cursor_from(csr_der[..0]);
    assert(tls::get_asn1_element(cri_inner, 0xA0, attrs));
    assert(cri_inner.buf.len == 0);
    var attr_seq = core::cursor_from(csr_der[..0]);
    assert(tls::get_asn1_element(attrs, rfc::ASN1_TAG_SEQUENCE, attr_seq));
    var ext_req_oid = core::cursor_from(csr_der[..0]);
    assert(tls::get_asn1_element(attr_seq, rfc::ASN1_TAG_OID, ext_req_oid));
    let expected_ext_req: const u8[9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x09, 0x0E];
    assert(ext_req_oid.buf == expected_ext_req[..]);

    var ext_set = core::cursor_from(csr_der[..0]);
    assert(tls::get_asn1_element(attr_seq, rfc::ASN1_TAG_SET, ext_set));
    var exts_seq = core::cursor_from(csr_der[..0]);
    assert(tls::get_asn1_element(ext_set, rfc::ASN1_TAG_SEQUENCE, exts_seq));
    var san_ext = core::cursor_from(csr_der[..0]);
    assert(tls::get_asn1_element(exts_seq, rfc::ASN1_TAG_SEQUENCE, san_ext));
    var san_oid = core::cursor_from(csr_der[..0]);
    assert(tls::get_asn1_element(san_ext, rfc::ASN1_TAG_OID, san_oid));
    assert(san_oid.buf == rfc::OID_SUBJECT_ALT_NAME[..]);
    var san_octets = core::cursor_from(csr_der[..0]);
    assert(tls::get_asn1_element(san_ext, rfc::ASN1_TAG_OCTET_STRING, san_octets));

    var parsed_sans: tls::SanEntry[..8] = [];
    assert(tls::parse_san_extension(san_octets.buf, parsed_sans));
    assert(parsed_sans.len == 2);
    assert(parsed_sans[0].san_type == tls::SanType.Dns && parsed_sans[0].val == "example.com");
    assert(parsed_sans[1].san_type == tls::SanType.Dns && parsed_sans[1].val == "www.example.com");

    // Verify signatureAlgorithm and BIT STRING signature over CertificationRequestInfo
    var sig_alg = core::cursor_from(csr_der[..0]);
    assert(tls::get_asn1_element(csr_seq, rfc::ASN1_TAG_SEQUENCE, sig_alg));
    var sig_oid = core::cursor_from(csr_der[..0]);
    assert(tls::get_asn1_element(sig_alg, rfc::ASN1_TAG_OID, sig_oid));
    assert(sig_oid.buf == rfc::OID_SIG_ECDSA_SHA256[..]);

    var sig_bits = core::cursor_from(csr_der[..0]);
    var sig_unused: u8 = 1;
    assert(tls::get_asn1_bit_string(csr_seq, sig_bits, sig_unused));
    assert(sig_unused == 0 && csr_seq.buf.len == 0);
    assert(core::ecdsa_p256_verify_der(pub_key[..], cri_bytes, sig_bits.buf));

    // Negative cases: empty domains, bad domain, zero private key clear out_der
    csr_der.append("dirty");
    assert(!tls::build_pkcs10_csr_p256_der(priv_key, domains[..0], csr_der) && csr_der.len == 0);

    var bad_doms: u8[..255][..1] = [];
    var bad_d:    u8[..255]      = "bad domain";
    bad_doms.push(bad_d);
    csr_der.append("dirty");
    assert(!tls::build_pkcs10_csr_p256_der(priv_key, bad_doms[..], csr_der) && csr_der.len == 0);

    let zero_key: u8[32] = [0; 32];
    csr_der.append("dirty");
    assert(!tls::build_pkcs10_csr_p256_der(zero_key, domains[..], csr_der) && csr_der.len == 0);

    print("PKCS10_CSR_P256: PASS\n");
}

// 3. RFC 7638 JWK Thumbprint P-256
// CHECK: ACME_JWK_THUMBPRINT_P256: PASS
fn test_acme_jwk_thumbprint_p256() {
    let priv_key = make_test_p256_priv();
    let pub_key = core::ecdsa_p256_public_key(priv_key);

    var x_b64: u8[..64] = [];
    var y_b64: u8[..64] = [];
    core::base64url_encode(pub_key[1..33], x_b64);
    core::base64url_encode(pub_key[33..65], y_b64);

    var canonical: u8[..256] = [];
    canonical.append("{\"crv\":\"P-256\",\"kty\":\"EC\",\"x\":\"");
    canonical.append(x_b64[..]);
    canonical.append("\",\"y\":\"");
    canonical.append(y_b64[..]);
    canonical.append("\"}");
    let expected_dig = core::sha256(canonical[..]);
    var expected_tp: u8[..64] = [];
    core::base64url_encode(expected_dig[..], expected_tp);

    var tp: u8[..64] = [];
    assert(auth::acme_jwk_thumbprint_p256(priv_key, tp));
    assert(tp.len == 43);
    assert(tp[..] == expected_tp[..]);

    let zero_key: u8[32] = [0; 32];
    tp.clear();
    tp.append("stale");
    assert(!auth::acme_jwk_thumbprint_p256(zero_key, tp) && tp.len == 0);

    print("ACME_JWK_THUMBPRINT_P256: PASS\n");
}

fn verify_jws_envelope(
    jws_json:         const u8[:],
    pub_key:          const u8[:],
    expected_url:     const u8[:],
    expected_nonce:   const u8[:],
    expected_kid:     const u8[:],
    expected_payload: const u8[:],
) {
    var prot_b64:  u8[..2048] = [];
    var pay_b64:   u8[..2048] = [];
    var sig_b64:   u8[..128]  = [];
    var seen_mask: u32        = 0;

    var r = json::reader(jws_json);
    assert(json::peek(r) == '{');
    json::each_member(r) { key =>
        if key == "protected" {
            seen_mask |= 1;
            assert(core::read_json_string_into(r, prot_b64));
        } else if key == "payload" {
            seen_mask |= 2;
            assert(core::read_json_string_into(r, pay_b64));
        } else if key == "signature" {
            seen_mask |= 4;
            assert(core::read_json_string_into(r, sig_b64));
        } else {
            assert(false);
        }
    };
    assert(json::finish(r) && seen_mask == 7);

    // Verify protected JSON fields
    var prot_json: u8[..2048] = [];
    assert(core::base64url_decode(prot_b64[..], prot_json));
    var alg_val:   u8[..32]  = [];
    var nonce_val: u8[..256] = [];
    var url_val:   u8[..256] = [];
    var kid_val:   u8[..256] = [];
    var has_jwk = false;
    var has_kid = false;

    var pr = json::reader(prot_json[..]);
    assert(json::peek(pr) == '{');
    json::each_member(pr) { key =>
        if key == "alg" {
            assert(core::read_json_string_into(pr, alg_val));
        } else if key == "nonce" {
            assert(core::read_json_string_into(pr, nonce_val));
        } else if key == "url" {
            assert(core::read_json_string_into(pr, url_val));
        } else if key == "kid" {
            has_kid = true;
            assert(core::read_json_string_into(pr, kid_val));
        } else if key == "jwk" {
            has_jwk = true;
            assert(json::peek(pr) == '{');
            json::skip(pr);
        } else {
            assert(false);
        }
    };
    assert(json::finish(pr));
    assert(alg_val[..] == "ES256");
    assert(nonce_val[..] == expected_nonce);
    assert(url_val[..] == expected_url);
    if expected_kid.len == 0 {
        assert(has_jwk && !has_kid);
    } else {
        assert(has_kid && !has_jwk && kid_val[..] == expected_kid);
    }

    // Verify payload round-trip
    if expected_payload.len == 0 {
        assert(pay_b64.len == 0);
    } else {
        var dec_pay: u8[..2048] = [];
        assert(core::base64url_decode(pay_b64[..], dec_pay));
        assert(dec_pay[..] == expected_payload);
    }

    // Verify ES256 P1363 signature over protected_b64 + "." + payload_b64
    var sig_raw: u8[..128] = [];
    assert(core::base64url_decode(sig_b64[..], sig_raw) && sig_raw.len == 64);
    var signing_in: u8[..4096] = [];
    signing_in.append(prot_b64[..]);
    signing_in.push('.');
    signing_in.append(pay_b64[..]);
    assert(core::ecdsa_p256_verify_p1363(pub_key, signing_in[..], sig_raw[..]));
}

// 4. RFC 8555 §6.2 Flattened JWS ES256 signing (jwk mode, kid mode, POST-as-GET, injection safety)
// CHECK: ACME_JWS_ES256: PASS
fn test_acme_sign_jws_es256() {
    let priv_key = make_test_p256_priv();
    let pub_key = core::ecdsa_p256_public_key(priv_key);

    var jws_jwk: u8[>..] = [];
    assert(auth::acme_sign_jws_es256(
        priv_key,
        "https://acme.example/new-acct",
        "nonce-123",
        "",
        "{\"termsOfServiceAgreed\":true}",
        jws_jwk,
    ));
    verify_jws_envelope(
        jws_jwk[..],
        pub_key[..],
        "https://acme.example/new-acct",
        "nonce-123",
        "",
        "{\"termsOfServiceAgreed\":true}",
    );

    // kid mode + POST-as-GET (empty payload)
    var jws_kid: u8[>..] = [];
    assert(auth::acme_sign_jws_es256(
        priv_key,
        "https://acme.example/order/1",
        "nonce-456",
        "https://acme.example/acct/42",
        "",
        jws_kid,
    ));
    verify_jws_envelope(
        jws_kid[..],
        pub_key[..],
        "https://acme.example/order/1",
        "nonce-456",
        "https://acme.example/acct/42",
        "",
    );

    // Escaped quotes/newlines in url/nonce/kid cannot break JSON structure
    var jws_esc: u8[>..] = [];
    assert(auth::acme_sign_jws_es256(
        priv_key,
        "https://acme.example/q=\"1\"",
        "n\\1",
        "k\"id",
        "{}",
        jws_esc,
    ));
    verify_jws_envelope(
        jws_esc[..],
        pub_key[..],
        "https://acme.example/q=\"1\"",
        "n\\1",
        "k\"id",
        "{}",
    );

    // Reject empty url, empty nonce, zero key, and clear out_jws on failure
    jws_esc.append("dirty");
    assert(!auth::acme_sign_jws_es256(priv_key, "", "n", "", "{}", jws_esc) && jws_esc.len == 0);
    jws_esc.append("dirty");
    assert(!auth::acme_sign_jws_es256(priv_key, "https://acme.example/x", "", "", "{}", jws_esc) && jws_esc.len == 0);
    let zero_key: u8[32] = [0; 32];
    jws_esc.append("dirty");
    assert(!auth::acme_sign_jws_es256(zero_key, "https://acme.example/x", "n", "", "{}", jws_esc) && jws_esc.len == 0);

    print("ACME_JWS_ES256: PASS\n");
}

// 5. RFC 8555 JSON parsers (directory, order, authz http-01) & fail-closed rejections
// CHECK: ACME_JSON_PARSERS: PASS
fn test_acme_json_parsers() {
    // Directory
    let dir_json = "{\"newNonce\":\"https://acme.example/new-nonce\",\"newAccount\":\"https://acme.example/new-acct\",\"newOrder\":\"https://acme.example/new-order\",\"meta\":{\"termsOfService\":\"https://acme.example/tos\"}}";
    var dir = auth::AcmeDirectory { .. };
    assert(auth::acme_parse_directory(dir_json, dir));
    assert(dir.new_nonce[..] == "https://acme.example/new-nonce");
    assert(dir.new_account[..] == "https://acme.example/new-acct");
    assert(dir.new_order[..] == "https://acme.example/new-order");

    assert(!auth::acme_parse_directory("{\"newNonce\":\"https://acme.example/n\",\"newAccount\":\"https://acme.example/a\"}", dir));
    assert(dir.new_nonce.len == 0 && dir.new_account.len == 0 && dir.new_order.len == 0);
    assert(!auth::acme_parse_directory("{bad", dir));

    // Order
    let ord_json = "{\"status\":\"valid\",\"expires\":\"2026-12-01T00:00:00Z\",\"identifiers\":[{\"type\":\"dns\",\"value\":\"example.com\"}],\"authorizations\":[\"https://acme.example/authz/1\",\"https://acme.example/authz/2\"],\"finalize\":\"https://acme.example/finalize/1\",\"certificate\":\"https://acme.example/cert/1\"}";
    var ord = auth::AcmeOrder { .. };
    assert(auth::acme_parse_order(ord_json, ord));
    assert(ord.status == auth::AcmeOrderStatus.Valid);
    assert(ord.authz_urls.len == 2);
    assert(ord.authz_urls[0][..] == "https://acme.example/authz/1");
    assert(ord.authz_urls[1][..] == "https://acme.example/authz/2");
    assert(ord.finalize_url[..] == "https://acme.example/finalize/1");
    assert(ord.certificate_url[..] == "https://acme.example/cert/1");

    // Reject unknown status and reset out_ord
    let bad_ord_json = "{\"status\":\"bogus\",\"authorizations\":[\"https://acme.example/authz/1\"],\"finalize\":\"https://acme.example/finalize/1\"}";
    assert(!auth::acme_parse_order(bad_ord_json, ord));
    assert(ord.status == auth::AcmeOrderStatus.Unknown && ord.finalize_url.len == 0 && ord.authz_urls.len == 0);

    // Authz HTTP-01
    let tp = "NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs";
    let authz_json = "{\"status\":\"pending\",\"identifier\":{\"type\":\"dns\",\"value\":\"example.com\"},\"challenges\":[{\"type\":\"dns-01\",\"url\":\"https://acme.example/chall/dns\",\"status\":\"pending\",\"token\":\"LoqXcYV8q5ONbJQxbmR7SC\"},{\"type\":\"http-01\",\"url\":\"https://acme.example/chall/http\",\"status\":\"pending\",\"token\":\"LoqXcYV8q5ONbJQxbmR7SC\"}]}";
    var ch = auth::AcmeHttp01Challenge { .. };
    assert(auth::acme_parse_authz_http01(authz_json, tp, ch));
    assert(ch.url[..] == "https://acme.example/chall/http");
    assert(ch.token[..] == "LoqXcYV8q5ONbJQxbmR7SC");
    assert(ch.key_auth[..] == "LoqXcYV8q5ONbJQxbmR7SC.NzbLsXh8uDCcd-6MNwXF4W_7noWXFZAfHkxZsRGC9Xs");
    assert(ch.status == auth::AcmeOrderStatus.Pending);
    assert(ch.authz_status == auth::AcmeAuthzStatus.Pending);

    // Sibling dns-01 with >64B token (120 bytes), unfamiliar status, >256B url, and fields before "type" must NOT abort http-01!
    var tok120: u8[..128] = [];
    for _ in 120 { tok120.push('A'); }
    var url300: u8[..320] = "https://acme.example/chall/dns/";
    for _ in 270 { url300.push('z'); }
    let sibling_json = str(
        "{\"challenges\":[{\"token\":\"", tok120[..],
        "\",\"status\":\"custom-sibling-status\",\"url\":\"", url300[..],
        "\",\"type\":\"dns-01\"},{\"token\":\"LoqXcYV8q5ONbJQxbmR7SC\",\"status\":\"valid\",\"url\":\"https://acme.example/chall/http2\",\"type\":\"http-01\"}],\"status\":\"pending\"}",
    );
    var ch_sib = auth::AcmeHttp01Challenge { .. };
    assert(auth::acme_parse_authz_http01(sibling_json[..], tp, ch_sib));
    assert(ch_sib.url[..] == "https://acme.example/chall/http2");
    assert(ch_sib.status == auth::AcmeOrderStatus.Valid);
    assert(ch_sib.authz_status == auth::AcmeAuthzStatus.Pending);

    // Top-level deactivated / revoked / expired / valid / invalid authz statuses parsed accurately
    let deact_json = "{\"status\":\"deactivated\",\"challenges\":[{\"type\":\"http-01\",\"url\":\"https://acme.example/chall/http\",\"status\":\"valid\",\"token\":\"LoqXcYV8q5ONbJQxbmR7SC\"}]}";
    assert(auth::acme_parse_authz_http01(deact_json, tp, ch_sib));
    assert(ch_sib.authz_status == auth::AcmeAuthzStatus.Deactivated);

    let rev_json = "{\"challenges\":[{\"type\":\"http-01\",\"url\":\"https://acme.example/chall/http\",\"status\":\"pending\",\"token\":\"LoqXcYV8q5ONbJQxbmR7SC\"}],\"status\":\"revoked\"}";
    assert(auth::acme_parse_authz_http01(rev_json, tp, ch_sib));
    assert(ch_sib.authz_status == auth::AcmeAuthzStatus.Revoked);

    let exp_json = "{\"status\":\"expired\",\"challenges\":[{\"type\":\"http-01\",\"url\":\"https://acme.example/chall/http\",\"status\":\"pending\",\"token\":\"LoqXcYV8q5ONbJQxbmR7SC\"}]}";
    assert(auth::acme_parse_authz_http01(exp_json, tp, ch_sib));
    assert(ch_sib.authz_status == auth::AcmeAuthzStatus.Expired);

    // Reject unknown challenge status, bad token, missing http-01, and reset out_ch
    let bad_ch_status = "{\"status\":\"pending\",\"challenges\":[{\"type\":\"http-01\",\"url\":\"https://acme.example/chall/http\",\"status\":\"ready\",\"token\":\"LoqXcYV8q5ONbJQxbmR7SC\"}]}";
    assert(!auth::acme_parse_authz_http01(bad_ch_status, tp, ch));
    assert(ch.url.len == 0 && ch.token.len == 0 &&
        ch.status == auth::AcmeOrderStatus.Unknown &&
        ch.authz_status == auth::AcmeAuthzStatus.Unknown);

    let bad_ch_tok = "{\"status\":\"pending\",\"challenges\":[{\"type\":\"http-01\",\"url\":\"https://acme.example/chall/http\",\"status\":\"pending\",\"token\":\"bad/tok\"}]}";
    assert(!auth::acme_parse_authz_http01(bad_ch_tok, tp, ch));

    let no_http01 = "{\"status\":\"pending\",\"challenges\":[{\"type\":\"dns-01\",\"url\":\"https://acme.example/chall/dns\",\"status\":\"pending\",\"token\":\"LoqXcYV8q5ONbJQxbmR7SC\"}]}";
    assert(!auth::acme_parse_authz_http01(no_http01, tp, ch));

    let bad_authz_status = "{\"status\":\"bogus\",\"challenges\":[{\"type\":\"http-01\",\"url\":\"https://acme.example/chall/http\",\"status\":\"pending\",\"token\":\"LoqXcYV8q5ONbJQxbmR7SC\"}]}";
    assert(!auth::acme_parse_authz_http01(bad_authz_status, tp, ch));

    // Reject missing top-level authz "status"
    let missing_authz_status = "{\"challenges\":[{\"type\":\"http-01\",\"url\":\"https://acme.example/chall/http\",\"status\":\"pending\",\"token\":\"LoqXcYV8q5ONbJQxbmR7SC\"}]}";
    assert(!auth::acme_parse_authz_http01(missing_authz_status, tp, ch));
    assert(ch.url.len == 0 && ch.token.len == 0 && ch.status == auth::AcmeOrderStatus.Unknown);

    // Reject CRLF, spaces, backslashes, and embedded user:pass@ credentials in ACME URLs
    assert(!auth::acme_parse_directory("{\"newNonce\":\"https://acme.example/n\\r\\n\",\"newAccount\":\"https://acme.example/a\",\"newOrder\":\"https://acme.example/o\"}", dir));
    assert(!auth::acme_parse_directory("{\"newNonce\":\"https://acme.example/n \",\"newAccount\":\"https://acme.example/a\",\"newOrder\":\"https://acme.example/o\"}", dir));
    assert(!auth::acme_parse_directory("{\"newNonce\":\"https://acme.example\\\\n\",\"newAccount\":\"https://acme.example/a\",\"newOrder\":\"https://acme.example/o\"}", dir));
    assert(!auth::acme_parse_directory("{\"newNonce\":\"https://user:pass@acme.example/n\",\"newAccount\":\"https://acme.example/a\",\"newOrder\":\"https://acme.example/o\"}", dir));
    assert(!auth::acme_parse_order("{\"status\":\"pending\",\"authorizations\":[\"https://user:pass@acme.example/az\"],\"finalize\":\"https://acme.example/fin\"}", ord));
    assert(!auth::acme_parse_authz_http01("{\"status\":\"pending\",\"challenges\":[{\"type\":\"http-01\",\"url\":\"https://acme.example/c\\r\\n\",\"status\":\"pending\",\"token\":\"LoqXcYV8q5ONbJQxbmR7SC\"}]}", tp, ch));

    print("ACME_JSON_PARSERS: PASS\n");
}

fn main() {
    test_acme_find_12_slots();
    test_pkcs10_csr_p256();
    test_acme_jwk_thumbprint_p256();
    test_acme_sign_jws_es256();
    test_acme_json_parsers();
}
