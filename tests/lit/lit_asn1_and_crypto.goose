// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Goose LIT Verification Suite: lit_asn1_and_crypto
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// ============================================================================
// 1. verify_asn1_der (1/3)
// ============================================================================
// CHECK: === [1/3] verify_asn1_der ===

// tests/lit/verify_asn1_der.goose
// Verification of ITU-T X.690 DER encoding rules and ASN.1 wire decoding via wing::tls.
//

fn wing_check_tlv_length_prefix(buf: const u8[:]) -> i64 {
    let b1 = buf[1];
    guard (b1 & 0x80) != 0 else { return 0; }
    guard b1 != 0x80 && b1 != 0xFF else { return -2; }
    let num_octets = (b1 & 0x7F) as i64;
    guard num_octets >= 1 && num_octets <= 4 else { return -2; }
    guard buf.len >= 2 + num_octets else { return -1; }
    guard buf[2] != 0 else { return -2; }
    return 0;
}

// Wire adapter for verify_split_stream and fuzzing using wing's real get_any_asn1_element.
fn wing_parse_der_tlv(buf: const u8[:]) -> i64 {
    var c = core::cursor_from(buf);
    var tag: u8 = 0;
    var val = core::cursor_from(buf[..0]);
    if tls::get_any_asn1_element(c, tag, val) {
        return val.buf.len;
    }
    guard buf.len >= 2 else { return -1; }
    let pre_check = wing_check_tlv_length_prefix(buf);
    guard pre_check == 0 else { return pre_check; }

    var c_len = core::cursor_from(buf[1..]);
    var out_len: i64 = 0;
    guard tls::get_asn1_length(c_len, out_len) else { return -2; }
    let total_hdr = buf.len - c_len.buf.len;
    guard buf.len >= total_hdr + out_len else { return -1; }
    return -2;
}

// Wire adapter for integer validation using wing's real get_asn1_integer & validate_asn1_integer.
fn wing_validate_der_integer(buf: const u8[:]) -> i64 {
    guard buf.len >= 2 else { return -1; }
    guard buf[0] == rfc::ASN1_TAG_INTEGER else { return 0; }
    var c = core::cursor_from(buf);
    var val: i64 = 0;
    if !tls::get_asn1_integer(c, val) {
        let vlen = buf[1] as i64;
        guard buf.len >= 2 + vlen else { return -1; }
        return 0;
    }
    guard val > 0 else { return 0; }
    return 1;
}

fn calc_asn1_tag_class(tag: i64) -> i64 {
    return (tag >> 6) & 3;
}

fn derive_der_short_len(b: i64) -> i64 {
    if (b & 128) == 0 { return b; }
    return -1;
}

fn run_01_verify_asn1_der() {
    var raw_short: u8[>..] = [];
    assert(wire_kit::parse_hex("0203010001", raw_short));
    assert(wire_kit::verify_split_stream(raw_short[..], -1, 3, wing_parse_der_tlv));
    assert(wire_kit::fuzz_payload(raw_short[..], 100, wing_parse_der_tlv));
    print("ASN1_SHORT_TLV: OK");

    var raw_hdr: u8[>..] = [];
    assert(wire_kit::parse_hex("308180", raw_hdr));
    assert(wing_parse_der_tlv(raw_hdr[..]) == -1);

    var vA: u8[>..] = []; wire_kit::parse_hex("02817F", vA);
    assert(wing_parse_der_tlv(vA[..]) == -2);
    var vB: u8[>..] = []; wire_kit::parse_hex("3080", vB);
    assert(wing_parse_der_tlv(vB[..]) == -2);
    var vC: u8[>..] = []; wire_kit::parse_hex("02FF01", vC);
    assert(wing_parse_der_tlv(vC[..]) == -2);
    var vD: u8[>..] = []; wire_kit::parse_hex("02820080", vD);
    assert(wing_parse_der_tlv(vD[..]) == -2);
    print("ASN1_INVALID_TLV: OK");

    var vUnderrun: u8[>..] = []; wire_kit::parse_hex("042001020304", vUnderrun);
    assert(wing_parse_der_tlv(vUnderrun[..]) == -1);
    print("ASN1_UNDERRUN: OK");

    var i128: u8[>..] = []; wire_kit::parse_hex("02020080", i128);
    assert(wing_validate_der_integer(i128[..]) == 1);
    var iRedundant: u8[>..] = []; wire_kit::parse_hex("02020001", iRedundant);
    assert(wing_validate_der_integer(iRedundant[..]) == 0);
    var iNeg: u8[>..] = []; wire_kit::parse_hex("0202FF01", iNeg);
    assert(wing_validate_der_integer(iNeg[..]) == 0);
    var i127: u8[>..] = []; wire_kit::parse_hex("02017F", i127);
    assert(wing_validate_der_integer(i127[..]) == 1);
    var iNegSingle: u8[>..] = []; wire_kit::parse_hex("020180", iNegSingle);
    assert(wing_validate_der_integer(iNegSingle[..]) == 0);

    var iSerial: u8[>..] = []; wire_kit::parse_hex("020400AABBCC", iSerial);
    assert(wing_validate_der_integer(iSerial[..]) == 1);
    assert(wire_kit::verify_split_stream(iSerial[..], -1, 1, wing_validate_der_integer));
    assert(wire_kit::fuzz_payload(iSerial[..], 100, wing_validate_der_integer));
    print("ASN1_INT_RULES: OK");

    assert(calc_asn1_tag_class(rfc::ASN1_TAG_SEQUENCE) == 0);
    assert(derive_der_short_len(0x2A) == 42);
    print("ASN1_DER_ALL: PASS");
}

// CHECK: ASN1_SHORT_TLV: OK
// CHECK: ASN1_INVALID_TLV: OK
// CHECK: ASN1_UNDERRUN: OK
// CHECK: ASN1_INT_RULES: OK
// CHECK: ASN1_DER_ALL: PASS

// ============================================================================
// 2. verify_asn1_der_edge (2/3)
// ============================================================================
// CHECK: === [2/3] verify_asn1_der_edge ===

// tests/lit/verify_asn1_der_edge.goose
// Verification of ITU-T X.690 length boundaries and RFC 5280 serial number rules via wing::tls.
//

// Wire adapter for verify_split_stream and fuzzing using tls::get_asn1_length
fn wing_decode_der_length(buf: const u8[:]) -> i64 {
    guard buf.len > 0 else { return -1; }
    var c = core::cursor_from(buf);
    var out_len: i64 = 0;
    if tls::get_asn1_length(c, out_len) {
        return out_len;
    }
    let b0 = buf[0];
    guard (b0 & 0x80) != 0 else { return -2; }
    guard b0 != 0x80 && b0 != 0xFF else { return -2; }
    let num_bytes = (b0 & 0x7F) as i64;
    guard num_bytes >= 1 && num_bytes <= 4 else { return -2; }
    guard buf.len >= 1 + num_bytes else { return -1; }
    return -2;
}

// Validates RFC 5280 positive serial number rules and canonical padding via tls::validate_asn1_integer
fn wing_validate_asn1_serial_number(buf: const u8[:]) -> i64 {
    guard buf.len > 0 else { return -1; }
    if tls::validate_asn1_integer(buf, true) {
        return 1;
    }
    return -2;
}

fn run_02_verify_asn1_der_edge() {
    var raw_edge: u8[>..] = [];
    assert(wire_kit::parse_hex("820100", raw_edge));
    let split_ok = wire_kit::verify_split_stream(raw_edge[..], -1, 256, wing_decode_der_length);
    assert(split_ok);
    assert(wire_kit::fuzz_payload(raw_edge[..], 100, wing_decode_der_length));
    print("ASN1_DER_SPLIT: OK");

    var p80: u8[>..] = []; wire_kit::parse_hex("80", p80);
    assert(wing_decode_der_length(p80[..]) == -2);

    var p820080: u8[>..] = []; wire_kit::parse_hex("820080", p820080);
    assert(wing_decode_der_length(p820080[..]) == -2);

    var pFF: u8[>..] = []; wire_kit::parse_hex("FF", pFF);
    assert(wing_decode_der_length(pFF[..]) == -2);

    var p817F: u8[>..] = []; wire_kit::parse_hex("817F", p817F);
    assert(wing_decode_der_length(p817F[..]) == -2);
    print("ASN1_LENGTH_RULES: OK");

    var s42: u8[>..] = []; wire_kit::parse_hex("42", s42);
    assert(wing_validate_asn1_serial_number(s42[..]) == 1);

    var s0080: u8[>..] = []; wire_kit::parse_hex("0080", s0080);
    assert(wing_validate_asn1_serial_number(s0080[..]) == 1);

    var s80: u8[>..] = []; wire_kit::parse_hex("80", s80);
    assert(wing_validate_asn1_serial_number(s80[..]) == -2);

    var s0001: u8[>..] = []; wire_kit::parse_hex("0001", s0001);
    assert(wing_validate_asn1_serial_number(s0001[..]) == -2);

    var s21: u8[>..] = []; wire_kit::parse_hex("0102030405060708090A0B0C0D0E0F101112131415", s21);
    assert(wing_validate_asn1_serial_number(s21[..]) == -2);
    print("ASN1_SERIAL_RULES: OK");
}

// CHECK: ASN1_DER_SPLIT: OK
// CHECK: ASN1_LENGTH_RULES: OK
// CHECK: ASN1_SERIAL_RULES: OK

// ============================================================================
// 3. verify_crypto_audit_regressions (3/3)
// ============================================================================
// CHECK: === [3/3] verify_crypto_audit_regressions ===

// tests/lit/verify_crypto_audit_regressions.goose
// Regression verification suite for core/crypto audit findings (F001..F015).
//

fn test_f001_rsa_exponent_validation() {
    var n_be: u8[128] = [0xFF; 128];
    n_be[0] = 0x80;
    n_be[127] = 0x01;

    let msg = "forged_admin_token";
    let digest = core::sha256(msg);
    var forged_sig: u8[..512] = [];
    assert(core::build_emsa_pkcs1_v15(core::PKCS1_DIGESTINFO_SHA256[..], digest[..], 128, forged_sig));

    let e_one:  u8[1] = [0x01];
    let e_zero: u8[1] = [0x00];
    let e_two:  u8[1] = [0x02];
    let ok_pkcs1_e1 = core::rsa_pkcs1_sha256_verify(n_be[..], e_one[..], msg, forged_sig[..]);
    let ok_pkcs1_e0 = core::rsa_pkcs1_sha256_verify(n_be[..], e_zero[..], msg, forged_sig[..]);
    let ok_pkcs1_e2 = core::rsa_pkcs1_sha256_verify(n_be[..], e_two[..], msg, forged_sig[..]);

    var pss_forged: u8[..512] = [];
    let salt: u8[32] = [0xAA; 32];
    assert(core::encode_emsa_pss(digest[..], salt[..], 128, n_be[0], pss_forged));
    let ok_pss_e1 = core::rsa_pss_sha256_verify(n_be[..], e_one[..], msg, pss_forged[..]);

    assert(!ok_pkcs1_e1);
    assert(!ok_pkcs1_e0);
    assert(!ok_pkcs1_e2);
    assert(!ok_pss_e1);
    print("F001_RSA_EXP_REJECTED: 1");
}

fn test_f002_ecdsa_raw_r_0x30() {
    var pub256: u8[>..] = [];
    var sig256: u8[>..] = [];
    assert(
        wire_kit::parse_hex(
            "048e533b6fa0bf7b4625bb30667c01fb607ef9f8b8a80fef5b300628703187b2a373eb1dbde03318366d069f83a6f5900053c73633cb041b21c55e1a86c1f400b4",
            pub256,
        ),
    );
    assert(
        wire_kit::parse_hex(
            "301d9e502dc7e05da85da026a7ae9aa0fac9db7d52a95b3e3e3f9aa0a1b45b8b3bd77e3168bf94d863c36d049f6c42c0ce4edc6759148fba21c7ce181cf3b977",
            sig256,
        ),
    );
    assert(sig256.len == 64 && sig256[0] == 0x30);
    let ok256 = core::ecdsa_p256_verify(pub256[..], "test_r_starts_with_0x30", sig256[..]);

    var pub384: u8[>..] = [];
    var sig384: u8[>..] = [];
    assert(
        wire_kit::parse_hex(
            "04283c1d7365ce4788f29f8ebf234edffead6fe997fbea5ffa2d58cc9dfa7b1c508b05526f55b9ebb2040f05b48fb6d0e19475c99061e41b88ba52efdb8c1690471a61d867ed799729d9c92cd01dbd225630d84ede32a78f9e64664cdac512ef8c",
            pub384,
        ),
    );
    assert(
        wire_kit::parse_hex(
            "30e3183bff268e8260042b12bb6e32471e24ee5996377ba6f044c2c670975725fe53fbff2fd5387a55031162056fb793154455f3d828cadc8a7c7e7458dda8659431c13d7295809248f7f98ca7e495ea90dea864e78930cf1469bcb212f91d11",
            sig384,
        ),
    );
    assert(sig384.len == 96 && sig384[0] == 0x30);
    let ok384 = core::ecdsa_p384_verify(pub384[..], "test_p384_r_starts_with_0x30", sig384[..]);

    assert(ok256 && ok384);
    print("F002_ECDSA_RAW_0X30_OK: 1");
}

fn test_f003_dudect_edge_cases() {
    var ctx = core::DudectContext { .. };
    for i in 10 {
        assert(core::dudect_push_sample(ctx, 0, 100.0));
        assert(core::dudect_push_sample(ctx, 1, 500.0));
    }
    let is_ct_diff = core::dudect_is_constant_time(ctx, 4.5);
    assert(!is_ct_diff);

    var ctx_same = core::DudectContext { .. };
    for i in 10 {
        assert(core::dudect_push_sample(ctx_same, 0, 100.0));
        assert(core::dudect_push_sample(ctx_same, 1, 100.0));
    }
    assert(core::dudect_is_constant_time(ctx_same, 4.5));

    let s = core::approx_sqrt(0.000000000001);
    assert(s > 0.00000099 && s < 0.00000101);

    let nan_val = 0.0 / 0.0;
    assert(!core::dudect_push_sample(ctx_same, 0, nan_val));
    print("F003_DUDECT_FIXED: 1");
}

fn test_f004_hkdf_expand_prk_len() {
    var out: u8[32] = [0; 32];
    let short_prk: u8[16] = [0x11; 16];
    let ok256 = core::hkdf_expand_bytes_256(short_prk[..], "info", 32, out[..]);
    let ok384 = core::hkdf_expand_bytes_384(short_prk[..], "info", 32, out[..]);
    assert(!ok256 && !ok384);
    print("F004_HKDF_SHORT_PRK_REJECTED: 1");
}

fn test_f005_aes_gcm_open_cork_rollback() {
    let key32: u8[32] = [0x42; 32];
    let key16: u8[16] = [0x42; 16];
    let nonce: u8[12] = [0x07; 12];
    let pt = "0123456789ABCDEF";
    var ct256: u8[16] = [0; 16];
    let tag256, _, ok_s256 = core::aes256_gcm_seal(key32, nonce, pt, "aad", ct256[..]);
    assert(ok_s256);

    var cb = core::new_cork_buffer();
    cb.len = 16380;
    let ok_open256 = core::aes256_gcm_open(key32, nonce, ct256[..], "aad", tag256, cb);
    assert(!ok_open256 && cb.len == 0);

    var ct128: u8[16] = [0; 16];
    let tag128, _, ok_s128 = core::aes128_gcm_seal(key16, nonce, pt, "aad", ct128[..]);
    assert(ok_s128);
    cb.len = 16380;
    let ok_open128 = core::aes128_gcm_open(key16, nonce, ct128[..], "aad", tag128, cb);
    assert(!ok_open128 && cb.len == 0);
    print("F005_AES_OPEN_PREFIX_PRESERVED: 1");
}

fn test_f006_f007_der_strictness_and_transactional_cursor() {
    // 1. parse_der_tlv_header transactional idx and non-minimal BER length rejection
    let bad_ber: u8[4] = [0x02, 0x81, 0x05, 0x00];
    var idx: i64 = 0;
    let _, _, ok_tlv = core::parse_der_tlv_header(bad_ber[..], idx);
    assert(!ok_tlv && idx == 0);

    let trunc_der: u8[3] = [0x02, 0x05, 0x01];
    let _, _, ok_trunc = core::parse_der_tlv_header(trunc_der[..], idx);
    assert(!ok_trunc && idx == 0);

    // 2. parse_der_ecdsa_int transactional idx and non-minimal 0x81 seq_len rejection in ECDSA DER
    var out_int: u8[32] = [0; 32];
    let bad_ecdsa_int: u8[4] = [0x02, 0x02, 0x00, 0x05];
    var e_idx: i64 = 0;
    assert(!core::parse_der_ecdsa_int(bad_ecdsa_int[..], e_idx, out_int[..]));
    assert(e_idx == 0);

    // Non-minimal 0x30 0x81 0x06 in ecdsa_p256_decode_der_sig and ecdsa_p384_decode_der_sig
    let non_min_seq: u8[9] = [0x30, 0x81, 0x06, 0x02, 0x01, 0x01, 0x02, 0x01, 0x01];
    var raw64: u8[64] = [0; 64];
    var raw96: u8[96] = [0; 96];
    assert(!core::ecdsa_p256_decode_der_sig(non_min_seq[..], raw64));
    assert(!core::ecdsa_p384_decode_der_sig(non_min_seq[..], raw96));
    print("F006_F007_DER_STRICT_OK: 1");
}

fn test_f012_sha512_256_fips_vector() {
    let digest = core::sha512_256("abc");
    var expected: u8[>..] = [];
    assert(
        wire_kit::parse_hex(
            "53048e2681941ef99b2e29b76b4c7dabe4c2d0c634fc6d46e0e2f13107e7af23",
            expected,
        ),
    );
    assert(digest[..] == expected[..]);
    print("F012_SHA512_256_OK: 1");

    // P-384 RFC 6979 deterministic signing & Shamir verification roundtrip
    var priv384: u8[48] = [0x01; 48];
    priv384[47] = 0x05;
    let pub384 = core::ecdsa_p384_public_key(priv384);
    let sig384 = core::ecdsa_p384_sign(priv384, "p384-monty-ct-zeroize-test");
    assert(core::ecdsa_p384_verify(pub384[..], "p384-monty-ct-zeroize-test", sig384[..]));
    assert(!core::ecdsa_p384_verify(pub384[..], "tampered", sig384[..]));
}

fn run_03_verify_crypto_audit_regressions() {
    test_f001_rsa_exponent_validation();
    test_f002_ecdsa_raw_r_0x30();
    test_f003_dudect_edge_cases();
    test_f004_hkdf_expand_prk_len();
    test_f005_aes_gcm_open_cork_rollback();
    test_f006_f007_der_strictness_and_transactional_cursor();
    test_f012_sha512_256_fips_vector();
}

// CHECK: F001_RSA_EXP_REJECTED: 1
// CHECK: F002_ECDSA_RAW_0X30_OK: 1
// CHECK: F003_DUDECT_FIXED: 1
// CHECK: F004_HKDF_SHORT_PRK_REJECTED: 1
// CHECK: F005_AES_OPEN_PREFIX_PRESERVED: 1
// CHECK: F006_F007_DER_STRICT_OK: 1
// CHECK: F012_SHA512_256_OK: 1

fn main() {
    print("\n=== [1/3] verify_asn1_der ===\n");
    run_01_verify_asn1_der();
    print("\n=== [2/3] verify_asn1_der_edge ===\n");
    run_02_verify_asn1_der_edge();
    print("\n=== [3/3] verify_crypto_audit_regressions ===\n");
    run_03_verify_crypto_audit_regressions();
}
