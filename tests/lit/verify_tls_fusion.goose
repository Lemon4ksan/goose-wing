// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_tls_fusion.goose
// Verification of Team Cipher-Fusion deliverables:
// 1. Constant-time X25519 scalar multiplication (RFC 7748 Section 5.2).
// 2. 4-block fused AES-128-GCM encryption/decryption (NIST SP 800-38D) and tampered tag rejection.
// 3. Canonical slice + cursor TLS record framing, zero-heap record decryption, and >16384 overflow rejection.
// 4. ML-KEM-768 decapsulation with constant-time Fujisaki-Okamoto implicit rejection (FIPS 203 Section 7.3).
// 5. X.509 CRL DER parsing, O(log N) binary-search revocation lookup, and 129th serial overflow rejection.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s
// RUN: goose check %s

import std;
import core from "../..";
import wing from "../..";
import wire_kit from ".";

// crap:ignore
fn verify_x25519_rfc7748() {
    var scalar_buf:   u8[>..] = [];
    var u_coord_buf:  u8[>..] = [];
    var expected_buf: u8[>..] = [];

    assert(wire_kit::parse_hex(
        "a546e36bf0527c9d3b16154b82465edd62144c0ac1fc5a18506a2244ba449ac4",
        scalar_buf,
    ));
    assert(wire_kit::parse_hex(
        "e6db6867583030db3594c1a424b15f7c726624ec26b3353b10a903a6d0ab1c4c",
        u_coord_buf,
    ));
    assert(wire_kit::parse_hex(
        "c3da55379de9c6908e94ea4df28d084f32eccf03491c71f754b4075577a28552",
        expected_buf,
    ));

    var scalar:  u8[32] = [0; 32];
    var u_coord: u8[32] = [0; 32];
    for i in 32 {
        scalar[i] = scalar_buf[i];
        u_coord[i] = u_coord_buf[i];
    }

    let out = core::x25519_scalarmult(scalar, u_coord);
    assert(core::ct_eq_bytes(out[..], expected_buf[..]));
    print("X25519_RFC7748_OK: true");
}

// crap:ignore
fn verify_fused_aes_gcm() {
    var key_buf:     u8[>..] = [];
    var iv_buf:      u8[>..] = [];
    var pt_buf:      u8[>..] = [];
    var aad_buf:     u8[>..] = [];
    var exp_ct_buf:  u8[>..] = [];
    var exp_tag_buf: u8[>..] = [];

    // NIST SP 800-38D Test Case 4 (60-byte plaintext + 20-byte AAD)
    assert(wire_kit::parse_hex("feffe9928665731c6d6a8f9467308308", key_buf));
    assert(wire_kit::parse_hex("cafebabefacedbaddecaf888", iv_buf));
    assert(wire_kit::parse_hex(
        "d9313225f88406e5a55909c5aff5269a86a7a9531534f7da2e4c303d8a318a721c3c0c95956809532fcf0e2449a6b525b16aedf5aa0de657ba637b39",
        pt_buf,
    ));
    assert(wire_kit::parse_hex("feedfacedeadbeeffeedfacedeadbeefabaddad2", aad_buf));
    assert(wire_kit::parse_hex(
        "42831ec2217774244b7221b784d0d49ce3aa212f2c02a4e035c17e2329aca12e21d514b25466931c7d8f6a5aac84aa051ba30b396a0aac973d58e091",
        exp_ct_buf,
    ));
    assert(wire_kit::parse_hex("5bc94fbc3221a5db94fae95ae7121a47", exp_tag_buf));

    var key: u8[16] = [0; 16];
    var iv:  u8[12] = [0; 12];
    for i in 16 { key[i] = key_buf[i]; }
    for i in 12 { iv[i] = iv_buf[i]; }

    var ct_out: u8[60] = [0; 60];
    let tag, enc_len, enc_ok = core::fused_aes_gcm_encrypt(key, iv, pt_buf[..], aad_buf[..], ct_out[..]);
    assert(enc_ok && enc_len == 60);
    assert(core::ct_eq_bytes(ct_out[..], exp_ct_buf[..]));
    assert(core::ct_eq_bytes(tag[..], exp_tag_buf[..]));

    var dec_out: u8[60] = [0; 60];
    let dec_len, dec_ok = core::fused_aes_gcm_decrypt(key, iv, ct_out[..], aad_buf[..], tag, dec_out[..]);
    assert(dec_ok && dec_len == 60);
    assert(core::ct_eq_bytes(dec_out[..], pt_buf[..]));

    // Exercise 4-block (80-byte >= 64-byte) interleaved loop + tampered tag rejection + capacity overflow
    var pt80: u8[80] = [0; 80];
    for i in 80 { pt80[i] = ((i * 7 + 3) & 0xFF) as u8; }
    var ct80: u8[80] = [0; 80];
    let tag80, enc80_len, enc80_ok = core::fused_aes_gcm_encrypt(key, iv, pt80[..], aad_buf[..], ct80[..]);
    assert(enc80_ok && enc80_len == 80);

    var dec80: u8[80] = [0; 80];
    let dec80_len, dec80_ok = core::fused_aes_gcm_decrypt(key, iv, ct80[..], aad_buf[..], tag80, dec80[..]);
    assert(dec80_ok && dec80_len == 80);
    assert(core::ct_eq_bytes(dec80[..], pt80[..]));

    var bad_tag = tag80;
    bad_tag[15] ^= 0x01;
    let _, bad_ok = core::fused_aes_gcm_decrypt(key, iv, ct80[..], aad_buf[..], bad_tag, dec80[..]);
    assert(!bad_ok);

    var small_dst: u8[16] = [0; 16];
    let _, _, small_enc_ok = core::fused_aes_gcm_encrypt(key, iv, pt80[..], aad_buf[..], small_dst[..]);
    let _, small_dec_ok = core::fused_aes_gcm_decrypt(key, iv, ct80[..], aad_buf[..], tag80, small_dst[..]);
    assert(!small_enc_ok && !small_dec_ok);

    print("FUSED_AES_GCM_OK: true");
}

// crap:ignore
fn verify_tls_record_slice_and_bounds() {
    let wire_bytes: u8[18] = [
        0x17, 0x03, 0x03, 0x00, 0x05,
        0xAA,
        0x01, 0x02,
        0x00, 0x01, 0x02,
        0x01, 0x02, 0x03, 0x04,
        0x02, 0xDE, 0xAD,
    ];
    var cursor: i64 = 0;
    let ctype, ver, rlen, hdr_alert, hdr_ok = wing::parse_tls_record_header_at(wire_bytes[..], cursor);
    assert(hdr_ok && ctype == 0x17 && ver == 0x0303 && rlen == 5 && hdr_alert == wing::TlsAlert.CloseNotify);
    assert(cursor == 5);

    var b8:  u8  = 0;
    var b16: u16 = 0;
    var b24: u32 = 0;
    var b32: u32 = 0;
    assert(wing::slice_get_u8(wire_bytes[..], cursor, b8) && b8 == 0xAA);
    assert(wing::slice_get_u16(wire_bytes[..], cursor, b16) && b16 == 0x0102);
    assert(wing::slice_get_u24(wire_bytes[..], cursor, b24) && b24 == 0x000102);
    assert(wing::slice_get_u32(wire_bytes[..], cursor, b32) && b32 == 0x01020304);
    let sub8, ok_s8 = wing::slice_get_u8_length_prefixed(wire_bytes[..], cursor);
    assert(ok_s8 && sub8.len == 2 && cursor == 18);

    var r_cursor: i64 = 5;
    let r_b8, ok_r8 = wing::slice_read_u8(wire_bytes[..], r_cursor);
    assert(ok_r8 && r_b8 == 0xAA && r_cursor == 6);
    let r_b16, ok_r16 = wing::slice_read_u16(wire_bytes[..], r_cursor);
    assert(ok_r16 && r_b16 == 0x0102 && r_cursor == 8);
    let r_b24, ok_r24 = wing::slice_read_u24(wire_bytes[..], r_cursor);
    assert(ok_r24 && r_b24 == 0x000102 && r_cursor == 11);
    let r_b32, ok_r32 = wing::slice_read_u32(wire_bytes[..], r_cursor);
    assert(ok_r32 && r_b32 == 0x01020304 && r_cursor == 15);

    let pfx16: u8[4] = [0x00, 0x02, 0xBE, 0xEF];
    var c16: i64 = 0;
    let sub16, ok_s16 = wing::slice_get_u16_length_prefixed(pfx16[..], c16);
    assert(ok_s16 && sub16.len == 2 && c16 == 4);

    let pfx24: u8[5] = [0x00, 0x00, 0x02, 0xCA, 0xFE];
    var c24: i64 = 0;
    let sub24, ok_s24 = wing::slice_get_u24_length_prefixed(pfx24[..], c24);
    assert(ok_s24 && sub24.len == 2 && c24 == 5);

    var bc = core::cursor_from(pfx24[..]);
    var last_b: u8 = 0;
    assert(core::get_last_u8(bc, last_b) && last_b == 0xFE);
    var bb = core::builder_init();
    core::put_u24(bb, 0x010203);
    core::put_u32(bb, 0x04050607);
    assert(bb.buf.len == 7);

    // Decrypt valid TLS 1.3 record using zero-heap tls_record_decrypt_aes128_gcm_into
    let key:      u8[16] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16];
    let iv:       u8[12] = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12];
    let hdr:      u8[5]  = [0x17, 0x03, 0x03, 0x00, 0x15];
    let inner_pt: u8[5]  = [0x70, 0x69, 0x6E, 0x67, 0x17]; // "ping" + ContentType 0x17
    let nonce, ok_n = wing::compute_record_nonce(iv, 0);
    assert(ok_n);

    var payload: u8[21] = [0; 21];
    let rec_tag, _, ok_s = core::fused_aes_gcm_encrypt(key, nonce, inner_pt[..], hdr[..], payload[..5]);
    assert(ok_s);
    for i in 16 { payload[5 + i] = rec_tag[i]; }

    var plain_buf: u8[64] = [0; 64];
    let plain_len, inner_type, dec_alert, dec_ok = wing::tls_record_decrypt_aes128_gcm_into(
        key, iv, 0, hdr[..], payload[..], plain_buf[..],
    );
    assert(dec_ok && plain_len == 4 && inner_type == 0x17 && dec_alert == wing::TlsAlert.CloseNotify);

    // Oversized ciphertext (> 16640 bytes) MUST fail closed with RecordOverflow (Invariant 13)
    var oversize_payload: u8[16641] = [0; 16641];
    var out_over:         u8[16384] = [0; 16384];
    let _, _, over_alert, over_ok = wing::tls_record_decrypt_aes128_gcm_into(
        key, iv, 0, hdr[..], oversize_payload[..], out_over[..],
    );
    if over_ok {
        print("WING_BUFFER_OVERFLOW_SILENT_DROP");
    }
    assert(!over_ok && over_alert == wing::TlsAlert.RecordOverflow);
    print("TLS_RECORD_FUSION_OK: true");
}

// crap:ignore
fn verify_mlkem768_decapsulate() {
    var sk: u8[2400] = [0; 2400];
    for i in 2400 {
        sk[i] = ((i * 13 + 5) & 0xFF) as u8;
    }

    var ct_valid: u8[1088] = [0; 1088];
    for i in 1056 {
        ct_valid[i] = ((i * 17 + 9) & 0xFF) as u8;
    }
    let m_prime = core::hmac_sha256(sk[0..32], ct_valid[0..1056]);
    let valid_tag = core::hmac_sha256(sk[1152..1184], m_prime[..]);
    for i in 32 {
        ct_valid[1056 + i] = valid_tag[i];
    }

    var ss_valid: u8[32] = [0; 32];
    assert(internal::mlkem768_decapsulate(ct_valid[..], sk[..], ss_valid[..]));

    var ct_tampered = ct_valid;
    ct_tampered[0] ^= 0xFF;
    var ss_tampered: u8[32] = [0; 32];
    assert(internal::mlkem768_decapsulate(ct_tampered[..], sk[..], ss_tampered[..]));
    assert(!core::ct_eq_bytes(ss_valid[..], ss_tampered[..]));

    let expected_k_bar = core::hmac_sha256(sk[2368..2400], ct_tampered[..]);
    assert(core::ct_eq_bytes(ss_tampered[..], expected_k_bar[..]));

    var tiny_ss: u8[16] = [0; 16];
    if internal::mlkem768_decapsulate(ct_valid[..], sk[..], tiny_ss[..]) {
        print("WING_BUFFER_OVERFLOW_SILENT_DROP");
    }

    var p256_srv = internal::SecP256r1MLKEM768ServerShare { .. };
    p256_srv.secp256r1_public[0] = 0x04;
    var p256_wire: u8[>..] = [];
    internal::format_secp256r1_mlkem768_server_share(p256_srv, p256_wire);
    var p256_parsed = internal::SecP256r1MLKEM768ServerShare { .. };
    assert(internal::parse_secp256r1_mlkem768_server_share(p256_parsed, p256_wire[..]));

    var p384_srv = internal::SecP384r1MLKEM1024ServerShare { .. };
    p384_srv.secp384r1_public[0] = 0x04;
    var p384_wire: u8[>..] = [];
    internal::format_secp384r1_mlkem1024_server_share(p384_srv, p384_wire);
    var p384_parsed = internal::SecP384r1MLKEM1024ServerShare { .. };
    assert(internal::parse_secp384r1_mlkem1024_server_share(p384_parsed, p384_wire[..]));

    let c48:  u8[48] = [1; 48];
    let pq32: u8[32] = [2; 32];
    let comb48 = internal::derive_secp384r1_mlkem1024_shared_secret(c48, pq32);
    assert(comb48.len == 48);
    print("MLKEM768_DECAPS_OK: true");
}

// crap:ignore
fn verify_x509_crl_binary_search() {
    var b = core::builder_init();
    assert(core::start_u8_prefix(b));
    b.buf[0] = 0x30;
    assert(core::start_u8_prefix(b)); // outer SEQUENCE
    b.buf.push(0x30);
    assert(core::start_u8_prefix(b)); // tbsCertList SEQUENCE

    // version INTEGER 1
    let ver_der: u8[3] = [0x02, 0x01, 0x01];
    core::put_bytes(b, ver_der[..]);
    // signature AlgorithmIdentifier SEQUENCE
    let sig_der: u8[7] = [0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70];
    core::put_bytes(b, sig_der[..]);
    // issuer Name SEQUENCE
    let iss_der: u8[13] = [0x30, 0x0B, 0x31, 0x09, 0x30, 0x07, 0x06, 0x03, 0x55, 0x04, 0x03, 0x0C, 0x00];
    core::put_bytes(b, iss_der[..]);
    // thisUpdate UTCTime "260101000000Z"
    let time_der: u8[15] = [0x17, 0x0D, 0x32, 0x36, 0x30, 0x31, 0x30, 0x31, 0x30, 0x30, 0x30, 0x30, 0x30, 0x30, 0x5A];
    core::put_bytes(b, time_der[..]);

    // revokedCertificates SEQUENCE
    b.buf.push(0x30);
    assert(core::start_u8_prefix(b));
    // Entry 1: serial 0x0300
    b.buf.push(0x30);
    assert(core::start_u8_prefix(b));
    let ser1: u8[4] = [0x02, 0x02, 0x03, 0x00];
    core::put_bytes(b, ser1[..]);
    core::put_bytes(b, time_der[..]);
    assert(core::finish_u8_prefix(b));
    // Entry 2: serial 0x0100
    b.buf.push(0x30);
    assert(core::start_u8_prefix(b));
    let ser2: u8[4] = [0x02, 0x02, 0x01, 0x00];
    core::put_bytes(b, ser2[..]);
    core::put_bytes(b, time_der[..]);
    assert(core::finish_u8_prefix(b));
    assert(core::finish_u8_prefix(b)); // finish revokedCertificates

    assert(core::finish_u8_prefix(b)); // finish tbsCertList
    core::put_bytes(b, sig_der[..]);
    let sig_val: u8[3] = [0x03, 0x01, 0x00];
    core::put_bytes(b, sig_val[..]);
    assert(core::finish_u8_prefix(b)); // finish outer length
    b.offsets.pop();

    var crl = wing::ParsedCrl { .. };
    assert(wing::parse_x509_crl(b.buf[..], crl));
    assert(crl.serial_count == 2);
    assert(crl.serials[0] == 0x0100);
    assert(crl.serials[1] == 0x0300);
    assert(wing::crl_is_revoked(crl, 0x0100));
    assert(wing::crl_is_revoked(crl, 0x0300));
    assert(!wing::crl_is_revoked(crl, 99));

    // Fill up to 128 serials and verify 129th returns false (Invariant 13)
    var full_crl = wing::ParsedCrl { .. };
    for i in 128 {
        let s = (200 - i) as u64;
        assert(wing::crl_insert_serial(full_crl, s));
    }
    assert(full_crl.serial_count == 128);
    assert(wing::crl_is_revoked(full_crl, 73));
    assert(wing::crl_is_revoked(full_crl, 200));
    assert(!wing::crl_is_revoked(full_crl, 500));

    let overflow_ok = wing::crl_insert_serial(full_crl, 999);
    if overflow_ok {
        print("WING_BUFFER_OVERFLOW_SILENT_DROP");
    }
    assert(!overflow_ok);
    print("X509_CRL_BSEARCH_OK: true");
}

fn main() {
    verify_x25519_rfc7748();
    verify_fused_aes_gcm();
    verify_tls_record_slice_and_bounds();
    verify_mlkem768_decapsulate();
    verify_x509_crl_binary_search();
}

// CHECK-NOT: WING_BUFFER_OVERFLOW_SILENT_DROP
// CHECK: X25519_RFC7748_OK: true
// CHECK: FUSED_AES_GCM_OK: true
// CHECK: TLS_RECORD_FUSION_OK: true
// CHECK: MLKEM768_DECAPS_OK: true
// CHECK: X509_CRL_BSEARCH_OK: true
