// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_tls_bug_fixes.goose
// Regression tests for TLS bug fixes: ALPN validation, KeyUpdate bounds, and Ciphertext header type.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn main() {
    // ---- 1. Bug 1: Malformed ALPN extension in ClientHello (RFC 7301 §3.1) ----
    // Malformed 1-byte ALPN extension MUST be rejected (return false)
    let malformed_alpn_1b: u8[1] = [0x00];
    var out_alpn: u8[..32] = [];
    let ok1 = wing::select_server_alpn_from_ext(malformed_alpn_1b[..], "h2", out_alpn);
    assert(!ok1); // MUST fail on malformed 1-byte ALPN extension!
    print("TLS_ALPN_REJECT_MALFORMED_1B: OK");

    // Malformed 2-byte ALPN extension MUST also be rejected (empty list length)
    let malformed_alpn_2b: u8[2] = [0x00, 0x00];
    let ok2 = wing::select_server_alpn_from_ext(malformed_alpn_2b[..], "h2", out_alpn);
    assert(!ok2); // MUST fail on malformed 2-byte ALPN extension!
    print("TLS_ALPN_REJECT_MALFORMED_2B: OK");

    // Valid ALPN extension with "h2" (len=2: 0x00, 0x03, 0x02, 'h', '2') MUST succeed
    let valid_alpn: u8[5] = [0x00, 0x03, 0x02, 'h', '2'];
    let ok3 = wing::select_server_alpn_from_ext(valid_alpn[..], "h2", out_alpn);
    assert(ok3);
    assert(out_alpn == "h2");
    print("TLS_ALPN_ACCEPT_VALID: OK");

    // ---- 2. Bug 2: encode_key_update bounded array truncation (GOOSE-BUG-2) ----
    // Zero-capacity destination buffer MUST cause encode_key_update to fail closed (false)
    var zero_buf: u8[..0] = [];
    let ok_ku_fail = wing::encode_key_update(zero_buf, 0);
    assert(!ok_ku_fail); // MUST fail closed when buffer has no remaining capacity!
    print("TLS_KEY_UPDATE_REJECT_NOCAP: OK");

    var normal_buf: u8[..4] = [];
    let ok_ku_succ = wing::encode_key_update(normal_buf, 0);
    assert(ok_ku_succ);
    assert(normal_buf.len == 1 && normal_buf[0] == 0);
    print("TLS_KEY_UPDATE_ACCEPT_VALID: OK");

    // ---- 3. Bug 3: encode_tls_ciphertext_header rejecting ChangeCipherSpec outer type (RFC 8446 §5.2) ----
    // Outer content type in TLS 1.3 TLSCiphertext is strictly application_data (0x17).
    // ChangeCipherSpec (0x14) is an unencrypted record and MUST NOT be accepted as ciphertext header!
    var hdr_buf: u8[..16] = [];
    let ok_ccs_hdr = wing::encode_tls_ciphertext_header(hdr_buf, rfc::TLS_CONTENT_CHANGE_CIPHER_SPEC, 32);
    assert(!ok_ccs_hdr); // MUST reject ChangeCipherSpec as ciphertext header!
    print("TLS_CIPHERTEXT_HDR_REJECT_CCS: OK");

    let ok_app_hdr = wing::encode_tls_ciphertext_header(hdr_buf, rfc::TLS_CONTENT_APPLICATION_DATA, 32);
    assert(ok_app_hdr);
    print("TLS_CIPHERTEXT_HDR_ACCEPT_APP: OK");

    // ---- 4. FIPS 203 ML-KEM-768 KeyGen + Encaps + Decaps Roundtrip (TLSMOD-003) ----
    let d_seed: u8[32] = [0x42; 32];
    let z_seed: u8[32] = [0x99; 32];
    let m_rand: u8[32] = [0x77; 32];
    let ek, dk = internal::mlkem768_keygen(d_seed, z_seed);
    let ct, ss_enc, ok_enc = internal::mlkem768_encapsulate(ek, m_rand);
    assert(ok_enc);
    var ss_dec: u8[32] = [0; 32];
    let ok_dec = internal::mlkem768_decapsulate(ct[..], dk[..], ss_dec[..]);
    assert(ok_dec);
    assert(core::ct_eq_bytes(ss_enc[..], ss_dec[..]));

    // Tampered ciphertext triggers FIPS 203 implicit rejection
    var ct_bad = ct;
    ct_bad[0] ^= 0x55;
    var ss_rej: u8[32] = [0; 32];
    assert(internal::mlkem768_decapsulate(ct_bad[..], dk[..], ss_rej[..]));
    assert(!core::ct_eq_bytes(ss_enc[..], ss_rej[..]));

    // Invalid encapsulation key (modulus >= 3329) fails closed
    var bad_ek = ek;
    bad_ek[0] = 0xFF;
    bad_ek[1] = 0xFF;
    bad_ek[2] = 0xFF;
    let _, _, ok_bad_ek = internal::mlkem768_encapsulate(bad_ek, m_rand);
    assert(!ok_bad_ek);
    print("TLS_MLKEM768_ROUNDTRIP_OK: true");

    // ---- 5. RFC 9849 ECH Outer Extensions, Inner Encoding & Acceptance Confirmation (TLSMOD-001) ----
    let outer_exts: u16[3] = [
        rfc::TLS_EXT_SUPPORTED_GROUPS,
        rfc::TLS_EXT_SIGNATURE_ALGORITHMS,
        rfc::TLS_EXT_KEY_SHARE,
    ];
    var outer_ext_wire: u8[..64] = [];
    assert(wing::encode_ech_outer_extensions(outer_ext_wire, outer_exts[..]));
    assert(outer_ext_wire.len == 11);
    assert(outer_ext_wire[0] == 0xFD && outer_ext_wire[1] == 0x00 && outer_ext_wire[4] == 6);

    let inner_rand: u8[32] = [0x33; 32];
    var ch_inner_buf: u8[..512] = [];
    assert(wing::build_encoded_client_hello_inner(
        ch_inner_buf, inner_rand, "secret.example.com", "h2", outer_exts[..], 64,
    ));
    assert(ch_inner_buf.len > 0 && (ch_inner_buf.len & 31) == 0);

    var sh_wire: u8[48] = [0x11; 48];
    sh_wire[0] = rfc::TLS_HS_SERVER_HELLO;
    sh_wire[1] = 0x00;
    sh_wire[2] = 0x00;
    sh_wire[3] = 44;
    let confirm1, ok_conf1 = wing::compute_ech_accept_confirmation(inner_rand, ch_inner_buf[..], sh_wire[..], false);
    assert(ok_conf1);

    // Mutating ServerHello.random[24..32] (sh_wire[30..38]) MUST produce the identical confirmation
    var sh_wire2 = sh_wire;
    core::ct_copy_bytes(sh_wire2[30..38], confirm1[..]);
    let confirm2, ok_conf2 = wing::compute_ech_accept_confirmation(inner_rand, ch_inner_buf[..], sh_wire2[..], false);
    assert(ok_conf2 && confirm1 == confirm2);
    assert(wing::verify_ech_acceptance_confirmation(sh_wire2[30..38], confirm2));

    let hrr_confirm, ok_hrr_conf = wing::compute_ech_accept_confirmation(inner_rand, ch_inner_buf[..], sh_wire[..], true);
    assert(ok_hrr_conf && hrr_confirm != confirm1);
    print("TLS_ECH_CONFIRMATION_OK: true");

    // ---- 6. RFC 8446 §7.5 Exporters: >255B Context & Early Exporter Secret (TLSMOD-005) ----
    var ks, ok_ks = internal::ks_init(rfc::TLS_CIPHER_AES_128_GCM_SHA256);
    assert(ok_ks);
    let psk_ikm: u8[32] = [0xAA; 32];
    let ch_hash: u8[32] = [0xBB; 32];
    assert(internal::ks_init_early_secret(ks, psk_ikm[..]));
    assert(internal::ks_derive_early_traffic(ks, ch_hash[..]));
    assert(ks.early_exporter_secret.len == 32);

    let ecdhe_ss: u8[32] = [0xCC; 32];
    assert(internal::ks_advance_to_handshake(ks, ecdhe_ss[..]));
    assert(internal::ks_advance_to_master(ks, ch_hash[..]));

    var large_ctx: u8[300] = [0x5A; 300];
    var exp_out:   u8[32]  = [0; 32];
    assert(internal::ks_export_keying_material(ks, "EXPORTER-Channel-Binding", large_ctx[..], 32, exp_out[..]));
    print("TLS_EXPORTER_LARGE_CTX_OK: true");

    // ---- 7. ECDSA P-256 & P-384 Jacobian Projective & Shamir Dual-Scalar (TLSC-07) ----
    var priv256: u8[32] = [0; 32];
    priv256[31] = 7;
    let pub256 = core::ecdsa_p256_public_key(priv256);
    let q256, q256_ok = core::decode_p256_public_key(pub256[..]);
    assert(q256_ok);
    let g256 = core::P256Point {
        x:        core::U256 { v: core::P256_GX },
        y:        core::U256 { v: core::P256_GY },
        infinity: false,
    };
    var u1_256 = core::U256 { .. };
    u1_256.v[0] = 13;
    var u2_256 = core::U256 { .. };
    u2_256.v[0] = 5;
    let shamir256 = core::p256_muladd_shamir(g256, u1_256, q256, u2_256);
    let dbl256 = core::p256_point_double(g256);
    assert(!dbl256.infinity && !shamir256.infinity);
    let sep256 = core::p256_point_add(core::p256_scalar_mul(g256, u1_256), core::p256_scalar_mul(q256, u2_256));
    assert(core::u256_cmp(shamir256.x, sep256.x.v) == 0);
    let sig256 = core::ecdsa_p256_sign(priv256, "Jacobian Shamir P-256");
    assert(core::ecdsa_p256_verify(pub256[..], "Jacobian Shamir P-256", sig256[..]));
    assert(!core::ecdsa_p256_verify(pub256[..], "tampered", sig256[..]));

    var priv384: u8[48] = [0; 48];
    priv384[47] = 11;
    let pub384 = core::ecdsa_p384_public_key(priv384);
    let q384, q384_ok = core::decode_p384_public_key(pub384[..]);
    assert(q384_ok);
    let g384 = core::P384Point {
        x:        core::U384 { v: core::P384_GX },
        y:        core::U384 { v: core::P384_GY },
        infinity: false,
    };
    var u1_384 = core::U384 { .. };
    u1_384.v[0] = 9;
    var u2_384 = core::U384 { .. };
    u2_384.v[0] = 4;
    let shamir384 = core::p384_muladd_shamir(g384, u1_384, q384, u2_384);
    let dbl384 = core::p384_point_double(g384);
    assert(!dbl384.infinity && !shamir384.infinity);
    let sep384 = core::p384_point_add(core::p384_scalar_mul(g384, u1_384), core::p384_scalar_mul(q384, u2_384));
    assert(core::u384_cmp(shamir384.x, sep384.x.v) == 0);
    let sig384 = core::ecdsa_p384_sign(priv384, "Jacobian Shamir P-384");
    assert(core::ecdsa_p384_verify(pub384[..], "Jacobian Shamir P-384", sig384[..]));
    assert(!core::ecdsa_p384_verify(pub384[..], "tampered", sig384[..]));
    print("TLS_ECDSA_JACOBIAN_SHAMIR_OK: true");

    // ---- 8. RSA-2048 & RSA-4096 32-Bit Montgomery CIOS (TLSC-08) ----
    let e3_be:  u8[1]  = [0x03];
    let exp2:   u8[1]  = [0x02];
    let salt32: u8[32] = [0x42; 32];
    var n2048_prime: u8[256] = [0xFF; 256];
    n2048_prime[253] = 0xE2;
    n2048_prime[254] = 0x5C;
    n2048_prime[255] = 0xEF;
    var d2048_prime: u8[256] = [0xAA; 256];
    d2048_prime[253] = 0x96;
    d2048_prime[254] = 0xE8;
    d2048_prime[255] = 0x9F;
    var sig2048_pss: u8[..512] = [];
    assert(core::rsa_pss_sha256_sign(n2048_prime[..], d2048_prime[..], salt32[..], "RSA-2048 Montgomery", sig2048_pss));
    assert(core::rsa_pss_sha256_verify(n2048_prime[..], e3_be[..], "RSA-2048 Montgomery", sig2048_pss[..]));
    var p3:          u8[..512] = [];
    var p2:          u8[..512] = [];
    var p2_mul_base: u8[..512] = [];
    assert(core::rsa_mod_exp(sig2048_pss[..], e3_be[..], n2048_prime[..], p3));
    assert(core::rsa_mod_exp(sig2048_pss[..], exp2[..], n2048_prime[..], p2));
    core::rsa_be_mul_mod(p2[..], sig2048_pss[..], n2048_prime[..], p2_mul_base);
    assert(p3[..] == p2_mul_base[..]);
    print("TLS_RSA_MONTGOMERY_OK: true");
}

// CHECK: TLS_ALPN_REJECT_MALFORMED_1B: OK
// CHECK: TLS_ALPN_REJECT_MALFORMED_2B: OK
// CHECK: TLS_ALPN_ACCEPT_VALID: OK
// CHECK: TLS_KEY_UPDATE_REJECT_NOCAP: OK
// CHECK: TLS_KEY_UPDATE_ACCEPT_VALID: OK
// CHECK: TLS_CIPHERTEXT_HDR_REJECT_CCS: OK
// CHECK: TLS_CIPHERTEXT_HDR_ACCEPT_APP: OK
// CHECK: TLS_MLKEM768_ROUNDTRIP_OK: true
// CHECK: TLS_ECH_CONFIRMATION_OK: true
// CHECK: TLS_EXPORTER_LARGE_CTX_OK: true
// CHECK: TLS_ECDSA_JACOBIAN_SHAMIR_OK: true
// CHECK: TLS_RSA_MONTGOMERY_OK: true
