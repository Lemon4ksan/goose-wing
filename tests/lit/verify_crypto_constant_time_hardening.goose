// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Constant-Time Cryptographic Hardening Verification Suite:
// 1. FIPS 197 AES-128 & AES-256 bitsliced S-box KAT vectors.
// 2. NIST SP 800-38D AES-128-GCM & AES-256-GCM seal/open, tamper rejection, and >2048B cross-check.
// 3. ECDSA P-256 & P-384 keygen, RFC 6979 sign/verify, and complete projective edge cases.
// 4. RSA-2048 PKCS#1 v1.5 & PSS unblinded/blinded sign/verify roundtrips and tamper rejection.
//
// RUN: goose %s | %FileCheck %s

import std;
import wing from "../..";

// CHECK: === CRYPTO CONSTANT-TIME HARDENING SUITE ===

fn test_fips197_aes_bitsliced() {
    // FIPS 197 Appendix C.1 (AES-128)
    let k128_c1: u8[16] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
    ];
    let pt_c: u8[16] = [
        0x00, 0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77,
        0x88, 0x99, 0xaa, 0xbb, 0xcc, 0xdd, 0xee, 0xff,
    ];
    let exp128_c1: u8[16] = [
        0x69, 0xc4, 0xe0, 0xd8, 0x6a, 0x7b, 0x04, 0x30,
        0xd8, 0xcd, 0xb7, 0x80, 0x70, 0xb4, 0xc5, 0x5a,
    ];
    var ks128 = core::aes128_key_schedule(k128_c1);
    let ct128_c1 = core::aes128_encrypt_block(ks128, pt_c);
    core::zeroize_aes128_ks(ks128);
    assert(ct128_c1[..] == exp128_c1[..]);

    // FIPS 197 Appendix B (AES-128)
    let k128_b: u8[16] = [
        0x2b, 0x7e, 0x15, 0x16, 0x28, 0xae, 0xd2, 0xa6,
        0xab, 0xf7, 0x15, 0x88, 0x09, 0xcf, 0x4f, 0x3c,
    ];
    let pt_b: u8[16] = [
        0x32, 0x43, 0xf6, 0xa8, 0x88, 0x5a, 0x30, 0x8d,
        0x31, 0x31, 0x98, 0xa2, 0xe0, 0x37, 0x07, 0x34,
    ];
    let exp128_b: u8[16] = [
        0x39, 0x25, 0x84, 0x1d, 0x02, 0xdc, 0x09, 0xfb,
        0xdc, 0x11, 0x85, 0x97, 0x19, 0x6a, 0x0b, 0x32,
    ];
    var ks128_b = core::aes128_key_schedule(k128_b);
    let ct128_b = core::aes128_encrypt_block(ks128_b, pt_b);
    core::zeroize_aes128_ks(ks128_b);
    assert(ct128_b[..] == exp128_b[..]);

    // FIPS 197 Appendix C.3 (AES-256)
    let k256_c3: u8[32] = [
        0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
        0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
        0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
        0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f,
    ];
    let exp256_c3: u8[16] = [
        0x8e, 0xa2, 0xb7, 0xca, 0x51, 0x67, 0x45, 0xbf,
        0xea, 0xfc, 0x49, 0x90, 0x4b, 0x49, 0x60, 0x89,
    ];
    var ks256 = core::aes256_key_schedule(k256_c3);
    let ct256_c3 = core::aes_encrypt_block(ks256, pt_c);
    core::zeroize_aes256_ks(ks256);
    assert(ct256_c3[..] == exp256_c3[..]);
    print("FIPS197_AES_BITSLICED: OK");
}

// CHECK: FIPS197_AES_BITSLICED: OK

fn test_nist_aes_gcm_hardening() {
    // NIST SP 800-38D Case 4 (AES-128-GCM, 60B PT, 20B AAD)
    let k128: u8[16] = [
        0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
        0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
    ];
    let iv12: u8[12] = [
        0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
        0xde, 0xca, 0xf8, 0x88,
    ];
    let pt60: u8[60] = [
        0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
        0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
        0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
        0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
        0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
        0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
        0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
        0xba, 0x63, 0x7b, 0x39,
    ];
    let aad20: u8[20] = [
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
        0xab, 0xad, 0xda, 0xd2,
    ];
    let exp_ct60: u8[60] = [
        0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
        0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
        0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
        0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
        0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
        0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
        0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
        0x3d, 0x58, 0xe0, 0x91,
    ];
    let exp_tag4: u8[16] = [
        0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
        0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47,
    ];
    var ct60: u8[60] = [0; 60];
    let tag4, n4, ok4 = core::aes128_gcm_seal(k128, iv12, pt60[..], aad20[..], ct60[..]);
    assert(ok4 && n4 == 60 && ct60[..] == exp_ct60[..] && tag4[..] == exp_tag4[..]);

    var dec60: u8[60] = [0; 60];
    let dn4, dok4 = core::aes128_gcm_open_into(k128, iv12, ct60[..], aad20[..], tag4, dec60[..]);
    assert(dok4 && dn4 == 60 && dec60[..] == pt60[..]);

    var bad_tag = tag4;
    bad_tag[15] ^= 0x01;
    let _, bad_ok = core::aes128_gcm_open_into(k128, iv12, ct60[..], aad20[..], bad_tag, dec60[..]);
    assert(!bad_ok);
    for i in 60 { assert(dec60[i] == 0); }

    // NIST SP 800-38D Case 14 (AES-256-GCM, 16B zero PT)
    let k256_z: u8[32] = [0; 32];
    let iv_z:   u8[12] = [0; 12];
    let pt16_z: u8[16] = [0; 16];
    let exp_ct14: u8[16] = [
        0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
        0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
    ];
    let exp_tag14: u8[16] = [
        0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
        0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19,
    ];
    var ct14: u8[16] = [0; 16];
    let tag14, n14, ok14 = core::aes256_gcm_seal(k256_z, iv_z, pt16_z[..], "", ct14[..]);
    assert(ok14 && n14 == 16 && ct14[..] == exp_ct14[..] && tag14[..] == exp_tag14[..]);

    // Cross-verify >2048B payload (hardware seal vs pure-Goose bitsliced AES-GCM + branchless GHASH open)
    var big_pt: u8[2100] = [0; 2100];
    for i in 2100 { big_pt[i] = ((i * 37 + 11) & 0xFF) as u8; }
    var big_ct128: u8[2100] = [0; 2100];
    let big_tag128, bn128, bok128 = core::aes128_gcm_seal(k128, iv12, big_pt[..], aad20[..], big_ct128[..]);
    assert(bok128 && bn128 == 2100);
    var big_out128: u8[..2100] = [];
    assert(core::aes128_gcm_open(k128, iv12, big_ct128[..], aad20[..], big_tag128, big_out128));
    assert(big_out128[..] == big_pt[..]);

    var k256: u8[32] = [0; 32];
    for i in 32 { k256[i] = (0xA0 + i) as u8; }
    var big_ct256: u8[2100] = [0; 2100];
    let big_tag256, bn256, bok256 = core::aes256_gcm_seal(k256, iv12, big_pt[..], aad20[..], big_ct256[..]);
    assert(bok256 && bn256 == 2100);
    var big_out256: u8[..2100] = [];
    assert(core::aes256_gcm_open(k256, iv12, big_ct256[..], aad20[..], big_tag256, big_out256));
    assert(big_out256[..] == big_pt[..]);

    var bad_big_tag = big_tag256;
    bad_big_tag[0] ^= 0x80;
    big_out256.clear();
    assert(!core::aes256_gcm_open(k256, iv12, big_ct256[..], aad20[..], bad_big_tag, big_out256));
    print("NIST_AES_GCM_HARDENING: OK");
}

// CHECK: NIST_AES_GCM_HARDENING: OK

fn test_ecdsa_p256_ct_edge_cases() {
    let g = core::P256Point {
        x:        core::U256 { v: core::P256_GX },
        y:        core::U256 { v: core::P256_GY },
        infinity: false,
    };
    let inf = core::P256Point { .. };
    let zero_u = core::U256 { .. };
    let neg_g = core::P256Point {
        x:        g.x,
        y:        core::u256_sub_mod(zero_u, g.y, core::P256_MOD),
        infinity: false,
    };

    // Point addition / doubling edge cases via Renes-Costello-Batina complete formulas
    assert(core::p256_point_add(inf, inf).infinity);
    let o_plus_g = core::p256_point_add(inf, g);
    assert(!o_plus_g.infinity && core::u256_cmp(o_plus_g.x, g.x.v) == 0 && core::u256_cmp(o_plus_g.y, g.y.v) == 0);
    let g_plus_o = core::p256_point_add(g, inf);
    assert(!g_plus_o.infinity && core::u256_cmp(g_plus_o.x, g.x.v) == 0 && core::u256_cmp(g_plus_o.y, g.y.v) == 0);
    let g_plus_g = core::p256_point_add(g, g);
    let two_g = core::p256_point_double(g);
    assert(!g_plus_g.infinity && core::u256_cmp(g_plus_g.x, two_g.x.v) == 0 && core::u256_cmp(g_plus_g.y, two_g.y.v) == 0);
    assert(core::p256_point_add(g, neg_g).infinity);

    // Scalar multiplication edge cases: 0*G, 1*G, (n-1)*G, n*G
    assert(core::p256_scalar_mul(g, zero_u).infinity);
    var one = core::U256 { .. };
    one.v[0] = 1;
    let one_g = core::p256_scalar_mul(g, one);
    assert(!one_g.infinity && core::u256_cmp(one_g.x, g.x.v) == 0 && core::u256_cmp(one_g.y, g.y.v) == 0);
    let order_u = core::U256 { v: core::P256_ORDER };
    let n_minus_1 = core::u256_sub_mod(order_u, one, core::P256_ORDER);
    let nm1_g = core::p256_scalar_mul(g, n_minus_1);
    assert(!nm1_g.infinity && core::u256_cmp(nm1_g.x, neg_g.x.v) == 0 && core::u256_cmp(nm1_g.y, neg_g.y.v) == 0);
    assert(core::p256_scalar_mul(g, order_u).infinity);

    // Keygen, RFC 6979 sign, raw + DER verify, tamper rejection
    var priv: u8[32] = [0; 32];
    for i in 32 { priv[i] = (0x31 + i) as u8; }
    let pub65 = core::ecdsa_p256_public_key(priv);
    let sig_raw = core::ecdsa_p256_sign(priv, "constant-time p256 payload");
    assert(core::ecdsa_p256_verify_p1363(pub65[..], "constant-time p256 payload", sig_raw[..]));
    assert(!core::ecdsa_p256_verify_p1363(pub65[..], "tampered p256 payload", sig_raw[..]));
    var sig_der: u8[..72] = [];
    assert(core::ecdsa_p256_encode_der_sig(sig_raw, sig_der));
    assert(core::ecdsa_p256_verify_der(pub65[..], "constant-time p256 payload", sig_der[..]));
    assert(!core::ecdsa_p256_verify_der(pub65[..], "tampered p256 payload", sig_der[..]));
    print("ECDSA_P256_CT: OK");
}

// CHECK: ECDSA_P256_CT: OK

fn test_ecdsa_p384_ct_edge_cases() {
    let g = core::P384Point {
        x:        core::U384 { v: core::P384_GX },
        y:        core::U384 { v: core::P384_GY },
        infinity: false,
    };
    let inf = core::P384Point { .. };
    let zero_u = core::U384 { .. };
    let neg_g = core::P384Point {
        x:        g.x,
        y:        core::u384_sub_mod(zero_u, g.y, core::P384_MOD),
        infinity: false,
    };

    assert(core::p384_point_add(inf, inf).infinity);
    let o_plus_g = core::p384_point_add(inf, g);
    assert(!o_plus_g.infinity && core::u384_cmp(o_plus_g.x, g.x.v) == 0 && core::u384_cmp(o_plus_g.y, g.y.v) == 0);
    let g_plus_o = core::p384_point_add(g, inf);
    assert(!g_plus_o.infinity && core::u384_cmp(g_plus_o.x, g.x.v) == 0 && core::u384_cmp(g_plus_o.y, g.y.v) == 0);
    let g_plus_g = core::p384_point_add(g, g);
    let two_g = core::p384_point_double(g);
    assert(!g_plus_g.infinity && core::u384_cmp(g_plus_g.x, two_g.x.v) == 0 && core::u384_cmp(g_plus_g.y, two_g.y.v) == 0);
    assert(core::p384_point_add(g, neg_g).infinity);

    assert(core::p384_scalar_mul(g, zero_u).infinity);
    var one = core::U384 { .. };
    one.v[0] = 1;
    let one_g = core::p384_scalar_mul(g, one);
    assert(!one_g.infinity && core::u384_cmp(one_g.x, g.x.v) == 0 && core::u384_cmp(one_g.y, g.y.v) == 0);
    let order_u = core::U384 { v: core::P384_ORDER };
    let n_minus_1 = core::u384_sub_mod(order_u, one, core::P384_ORDER);
    let nm1_g = core::p384_scalar_mul(g, n_minus_1);
    assert(!nm1_g.infinity && core::u384_cmp(nm1_g.x, neg_g.x.v) == 0 && core::u384_cmp(nm1_g.y, neg_g.y.v) == 0);
    assert(core::p384_scalar_mul(g, order_u).infinity);

    var priv: u8[48] = [0; 48];
    for i in 48 { priv[i] = (0x51 + i) as u8; }
    let pub97 = core::ecdsa_p384_public_key(priv);
    let sig_raw = core::ecdsa_p384_sign(priv, "constant-time p384 payload");
    assert(core::ecdsa_p384_verify_p1363(pub97[..], "constant-time p384 payload", sig_raw[..]));
    assert(!core::ecdsa_p384_verify_p1363(pub97[..], "tampered p384 payload", sig_raw[..]));
    print("ECDSA_P384_CT: OK");
}

// CHECK: ECDSA_P384_CT: OK

fn test_rsa2048_ct_and_blinding() {
    let e3_be:  u8[1]  = [0x03];
    let salt32: u8[32] = [0x42; 32];
    let salt64: u8[64] = [0x24; 64];
    var n2048: u8[256] = [0xFF; 256];
    n2048[253] = 0xE2;
    n2048[254] = 0x5C;
    n2048[255] = 0xEF;
    var d2048: u8[256] = [0xAA; 256];
    d2048[253] = 0x96;
    d2048[254] = 0xE8;
    d2048[255] = 0x9F;

    // 1. RSA-2048 PKCS#1 v1.5 sign (exponent-blinded) vs Chaum-blinded sign & tamper rejection
    var sig_pkcs1:         u8[..512] = [];
    var sig_pkcs1_blinded: u8[..512] = [];
    assert(core::rsa_pkcs1_sha256_sign(n2048[..], d2048[..], "RSA-2048 PKCS1 CT", sig_pkcs1));
    assert(core::rsa_pkcs1_sha256_sign_blinded(
        n2048[..], d2048[..], e3_be[..], "RSA-2048 PKCS1 CT", sig_pkcs1_blinded,
    ));
    assert(sig_pkcs1[..] == sig_pkcs1_blinded[..]);
    assert(core::rsa_pkcs1_sha256_verify(n2048[..], e3_be[..], "RSA-2048 PKCS1 CT", sig_pkcs1[..]));
    assert(!core::rsa_pkcs1_sha256_verify(n2048[..], e3_be[..], "RSA-2048 PKCS1 TAMPERED", sig_pkcs1[..]));
    var bad_pkcs1: u8[256] = [0; 256];
    for i in 256 { bad_pkcs1[i] = sig_pkcs1[i]; }
    bad_pkcs1[255] ^= 0x01;
    assert(!core::rsa_pkcs1_sha256_verify(n2048[..], e3_be[..], "RSA-2048 PKCS1 CT", bad_pkcs1[..]));

    // 2. RSA-2048 PSS SHA-256 sign (exponent-blinded) vs Chaum-blinded sign & tamper rejection
    var sig_pss256:         u8[..512] = [];
    var sig_pss256_blinded: u8[..512] = [];
    assert(core::rsa_pss_sha256_sign(n2048[..], d2048[..], salt32[..], "RSA-2048 PSS CT", sig_pss256));
    assert(core::rsa_pss_sha256_sign_blinded(
        n2048[..], d2048[..], e3_be[..], salt32[..], "RSA-2048 PSS CT", sig_pss256_blinded,
    ));
    assert(sig_pss256[..] == sig_pss256_blinded[..]);
    assert(core::rsa_pss_sha256_verify(n2048[..], e3_be[..], "RSA-2048 PSS CT", sig_pss256[..]));
    assert(!core::rsa_pss_sha256_verify(n2048[..], e3_be[..], "RSA-2048 PSS TAMPERED", sig_pss256[..]));

    // 3. RSA-2048 PSS SHA-512 roundtrip & tamper rejection
    var sig_pss512: u8[..512] = [];
    assert(core::rsa_pss_sha512_sign(n2048[..], d2048[..], salt64[..], "RSA-2048 PSS512 CT", sig_pss512));
    assert(core::rsa_pss_sha512_verify(n2048[..], e3_be[..], "RSA-2048 PSS512 CT", sig_pss512[..]));
    assert(!core::rsa_pss_sha512_verify(n2048[..], e3_be[..], "RSA-2048 PSS512 TAMPERED", sig_pss512[..]));

    // 4. Direct rsa_mod_exp vs rsa_mod_exp_blinded agreement
    var raw_exp:   u8[..512] = [];
    var blind_exp: u8[..512] = [];
    assert(core::rsa_mod_exp(sig_pss256[..], d2048[..], n2048[..], raw_exp));
    assert(core::rsa_mod_exp_blinded(sig_pss256[..], d2048[..], e3_be[..], n2048[..], blind_exp));
    assert(raw_exp[..] == blind_exp[..]);
    print("RSA2048_CT_BLINDING: OK");
}

// CHECK: RSA2048_CT_BLINDING: OK

fn main() {
    print("=== CRYPTO CONSTANT-TIME HARDENING SUITE ===");
    test_fips197_aes_bitsliced();
    test_nist_aes_gcm_hardening();
    test_ecdsa_p256_ct_edge_cases();
    test_ecdsa_p384_ct_edge_cases();
    test_rsa2048_ct_and_blinding();
    print("=== ALL CRYPTO CT HARDENING CHECKS PASSED ===");
}

// CHECK: === ALL CRYPTO CT HARDENING CHECKS PASSED ===
