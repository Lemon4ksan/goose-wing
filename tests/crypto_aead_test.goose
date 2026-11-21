// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Unit tests for Vulkan-style zero-allocation symmetric AEAD ciphers:
// 1. NIST SP 800-38D AES-128-GCM and AES-256-GCM official vectors (including empty PT with AAD).
// 2. RFC 8439 ChaCha20-Poly1305 official vectors (including empty PT with AAD).
// 3. In-place AEAD encryption and decryption mutation.
// 4. Out-of-place destination slice AEAD encryption and decryption.
// 5. Automatic memory zeroization (secure_zeroize_slice) on authentication tag failure.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// ----------------------------------------------------------------------------
// 1. NIST SP 800-38D AES-128-GCM Vectors
// ----------------------------------------------------------------------------
fn test_aes128_gcm_nist_vectors(t: lit::T&) {
    t.run("NIST SP 800-38D Test Case 1: AES-128-GCM Empty Plaintext & Empty AAD") { sub =>
        let key:   u8[16]      = [0; 16];
        let iv:    u8[12]      = [0; 12];
        let empty: const u8[:] = "";
        let expected_tag: u8[16] = [
            0x58, 0xe2, 0xfc, 0xce, 0xfa, 0x7e, 0x30, 0x61,
            0x36, 0x7f, 0x1d, 0x57, 0xa4, 0xe7, 0x45, 0x5a,
        ];

        var dst: u8[16] = [0; 16];
        let tag, written, ok_seal = core::aes128_gcm_seal(key, iv, empty, empty, dst[..]);
        sub.assert_true(ok_seal, "seal succeeds");
        sub.assert_eq(written, 0, "written length is 0");
        for i in 16 {
            sub.assert_eq(tag[i], expected_tag[i], "tag byte matches NIST Case 1");
        }

        var dec_dst: u8[16] = [0; 16];
        let dec_len, ok_open = core::aes128_gcm_open_into(key, iv, empty, empty, expected_tag, dec_dst[..]);
        sub.assert_true(ok_open, "open_into succeeds");
        sub.assert_eq(dec_len, 0, "decrypted length is 0");

        var in_out: u8[..16] = [];
        let tag_ip, ok_sip = core::aes128_gcm_seal_inplace(key, iv, in_out[..], empty);
        sub.assert_true(ok_sip, "seal_inplace succeeds");
        for i in 16 {
            sub.assert_eq(tag_ip[i], expected_tag[i], "seal_inplace tag matches NIST Case 1");
        }

        let open_ip_len, ok_oip = core::aes128_gcm_open_inplace(key, iv, in_out[..], empty, expected_tag);
        sub.assert_true(ok_oip, "open_inplace succeeds");
        sub.assert_eq(open_ip_len, 0, "open_inplace len is 0");
    };

    t.run("NIST SP 800-38D Test Case 2: AES-128-GCM 16-byte Block") { sub =>
        let key:   u8[16]      = [0; 16];
        let iv:    u8[12]      = [0; 12];
        let pt:    u8[16]      = [0; 16];
        let empty: const u8[:] = "";
        let expected_ct: u8[16] = [
            0x03, 0x88, 0xda, 0xce, 0x60, 0xb6, 0xa3, 0x92,
            0xf3, 0x28, 0xc2, 0xb9, 0x71, 0xb2, 0xfe, 0x78,
        ];
        let expected_tag: u8[16] = [
            0xab, 0x6e, 0x47, 0xd4, 0x2c, 0xec, 0x13, 0xbd,
            0xf5, 0x3a, 0x67, 0xb2, 0x12, 0x57, 0xbd, 0xdf,
        ];

        var in_out = pt;
        let tag, ok_seal = core::aes128_gcm_seal_inplace(key, iv, in_out[..], empty);
        sub.assert_true(ok_seal, "seal_inplace succeeds");
        for i in 16 {
            sub.assert_eq(in_out[i], expected_ct[i], "ciphertext byte matches NIST Case 2");
            sub.assert_eq(tag[i], expected_tag[i], "tag byte matches NIST Case 2");
        }

        let dec_len, ok_open = core::aes128_gcm_open_inplace(key, iv, in_out[..], empty, expected_tag);
        sub.assert_true(ok_open, "open_inplace succeeds");
        sub.assert_eq(dec_len, 16, "decrypted length is 16");
        for i in 16 {
            sub.assert_eq(in_out[i], 0, "decrypted in-place byte is 0");
        }
    };

    t.run("NIST SP 800-38D Test Case 4: AES-128-GCM with AAD & 60-byte Plaintext") { sub =>
        let key: u8[16] = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
            0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        ];
        let iv: u8[12] = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
            0xde, 0xca, 0xf8, 0x88,
        ];
        let pt: u8[60] = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
            0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
            0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
            0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
            0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
            0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
            0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39,
        ];
        let aad: u8[20] = [
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
            0xab, 0xad, 0xda, 0xd2,
        ];
        let expected_ct: u8[60] = [
            0x42, 0x83, 0x1e, 0xc2, 0x21, 0x77, 0x74, 0x24,
            0x4b, 0x72, 0x21, 0xb7, 0x84, 0xd0, 0xd4, 0x9c,
            0xe3, 0xaa, 0x21, 0x2f, 0x2c, 0x02, 0xa4, 0xe0,
            0x35, 0xc1, 0x7e, 0x23, 0x29, 0xac, 0xa1, 0x2e,
            0x21, 0xd5, 0x14, 0xb2, 0x54, 0x66, 0x93, 0x1c,
            0x7d, 0x8f, 0x6a, 0x5a, 0xac, 0x84, 0xaa, 0x05,
            0x1b, 0xa3, 0x0b, 0x39, 0x6a, 0x0a, 0xac, 0x97,
            0x3d, 0x58, 0xe0, 0x91,
        ];
        let expected_tag: u8[16] = [
            0x5b, 0xc9, 0x4f, 0xbc, 0x32, 0x21, 0xa5, 0xdb,
            0x94, 0xfa, 0xe9, 0x5a, 0xe7, 0x12, 0x1a, 0x47,
        ];

        var in_out = pt;
        let tag, ok_seal = core::aes128_gcm_seal_inplace(key, iv, in_out[..], aad[..]);
        sub.assert_true(ok_seal, "seal_inplace with AAD succeeds");
        for i in 60 {
            sub.assert_eq(in_out[i], expected_ct[i], "ciphertext matches NIST Case 4");
        }
        for i in 16 {
            sub.assert_eq(tag[i], expected_tag[i], "tag matches NIST Case 4");
        }

        let dec_len, ok_open = core::aes128_gcm_open_inplace(key, iv, in_out[..], aad[..], expected_tag);
        sub.assert_true(ok_open, "open_inplace with AAD succeeds");
        sub.assert_eq(dec_len, 60, "decrypted len is 60");
        for i in 60 {
            sub.assert_eq(in_out[i], pt[i], "decrypted in-place matches plaintext");
        }
    };

    t.run("AES-128-GCM Empty Plaintext with AAD Round-Trip") { sub =>
        let key:   u8[16]      = [0x42; 16];
        let iv:    u8[12]      = [0x24; 12];
        let aad:   const u8[:] = "authorization_header_aad";
        let empty: const u8[:] = "";

        var in_out: u8[..16] = [];
        let tag, ok_seal = core::aes128_gcm_seal_inplace(key, iv, in_out[..], aad);
        sub.assert_true(ok_seal, "empty PT seal succeeds");

        let dec_len, ok_open = core::aes128_gcm_open_inplace(key, iv, in_out[..], aad, tag);
        sub.assert_true(ok_open, "empty PT open with valid tag succeeds");
        sub.assert_eq(dec_len, 0, "decrypted len is 0");

        // Tampered AAD must fail
        let _, ok_bad_aad = core::aes128_gcm_open_inplace(key, iv, in_out[..], "tampered_aad", tag);
        sub.assert_false(ok_bad_aad, "empty PT open with tampered AAD rejected");
    };
}

// ----------------------------------------------------------------------------
// 2. NIST SP 800-38D AES-256-GCM Vectors
// ----------------------------------------------------------------------------
fn test_aes256_gcm_nist_vectors(t: lit::T&) {
    t.run("NIST SP 800-38D Test Case 13: AES-256-GCM Empty Plaintext & Empty AAD") { sub =>
        let key:   u8[32]      = [0; 32];
        let iv:    u8[12]      = [0; 12];
        let empty: const u8[:] = "";
        let expected_tag: u8[16] = [
            0x53, 0x0f, 0x8a, 0xfb, 0xc7, 0x45, 0x36, 0xb9,
            0xa9, 0x63, 0xb4, 0xf1, 0xc4, 0xcb, 0x73, 0x8b,
        ];

        var in_out: u8[..16] = [];
        let tag, ok_seal = core::aes256_gcm_seal_inplace(key, iv, in_out[..], empty);
        sub.assert_true(ok_seal, "AES-256 seal_inplace succeeds");
        for i in 16 {
            sub.assert_eq(tag[i], expected_tag[i], "tag matches NIST Case 13");
        }

        let dec_len, ok_open = core::aes256_gcm_open_inplace(key, iv, in_out[..], empty, expected_tag);
        sub.assert_true(ok_open, "AES-256 open_inplace succeeds");
        sub.assert_eq(dec_len, 0, "decrypted len is 0");
    };

    t.run("NIST SP 800-38D Test Case 14: AES-256-GCM 16-byte Block") { sub =>
        let key:   u8[32]      = [0; 32];
        let iv:    u8[12]      = [0; 12];
        let pt:    u8[16]      = [0; 16];
        let empty: const u8[:] = "";
        let expected_ct: u8[16] = [
            0xce, 0xa7, 0x40, 0x3d, 0x4d, 0x60, 0x6b, 0x6e,
            0x07, 0x4e, 0xc5, 0xd3, 0xba, 0xf3, 0x9d, 0x18,
        ];
        let expected_tag: u8[16] = [
            0xd0, 0xd1, 0xc8, 0xa7, 0x99, 0x99, 0x6b, 0xf0,
            0x26, 0x5b, 0x98, 0xb5, 0xd4, 0x8a, 0xb9, 0x19,
        ];

        var in_out = pt;
        let tag, ok_seal = core::aes256_gcm_seal_inplace(key, iv, in_out[..], empty);
        sub.assert_true(ok_seal, "AES-256 seal_inplace succeeds");
        for i in 16 {
            sub.assert_eq(in_out[i], expected_ct[i], "ciphertext matches NIST Case 14");
            sub.assert_eq(tag[i], expected_tag[i], "tag matches NIST Case 14");
        }

        let dec_len, ok_open = core::aes256_gcm_open_inplace(key, iv, in_out[..], empty, expected_tag);
        sub.assert_true(ok_open, "AES-256 open_inplace succeeds");
        sub.assert_eq(dec_len, 16, "decrypted length is 16");
        for i in 16 {
            sub.assert_eq(in_out[i], 0, "decrypted in-place byte is 0");
        }
    };

    t.run("NIST SP 800-38D Test Case 16: AES-256-GCM with AAD & 60-byte Plaintext") { sub =>
        let key: u8[32] = [
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
            0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
            0xfe, 0xff, 0xe9, 0x92, 0x86, 0x65, 0x73, 0x1c,
            0x6d, 0x6a, 0x8f, 0x94, 0x67, 0x30, 0x83, 0x08,
        ];
        let iv: u8[12] = [
            0xca, 0xfe, 0xba, 0xbe, 0xfa, 0xce, 0xdb, 0xad,
            0xde, 0xca, 0xf8, 0x88,
        ];
        let pt: u8[60] = [
            0xd9, 0x31, 0x32, 0x25, 0xf8, 0x84, 0x06, 0xe5,
            0xa5, 0x59, 0x09, 0xc5, 0xaf, 0xf5, 0x26, 0x9a,
            0x86, 0xa7, 0xa9, 0x53, 0x15, 0x34, 0xf7, 0xda,
            0x2e, 0x4c, 0x30, 0x3d, 0x8a, 0x31, 0x8a, 0x72,
            0x1c, 0x3c, 0x0c, 0x95, 0x95, 0x68, 0x09, 0x53,
            0x2f, 0xcf, 0x0e, 0x24, 0x49, 0xa6, 0xb5, 0x25,
            0xb1, 0x6a, 0xed, 0xf5, 0xaa, 0x0d, 0xe6, 0x57,
            0xba, 0x63, 0x7b, 0x39,
        ];
        let aad: u8[20] = [
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
            0xfe, 0xed, 0xfa, 0xce, 0xde, 0xad, 0xbe, 0xef,
            0xab, 0xad, 0xda, 0xd2,
        ];
        let expected_ct: u8[60] = [
            0x52, 0x2d, 0xc1, 0xf0, 0x99, 0x56, 0x7d, 0x07,
            0xf4, 0x7f, 0x37, 0xa3, 0x2a, 0x84, 0x42, 0x7d,
            0x64, 0x3a, 0x8c, 0xdc, 0xbf, 0xe5, 0xc0, 0xc9,
            0x75, 0x98, 0xa2, 0xbd, 0x25, 0x55, 0xd1, 0xaa,
            0x8c, 0xb0, 0x8e, 0x48, 0x59, 0x0d, 0xbb, 0x3d,
            0xa7, 0xb0, 0x8b, 0x10, 0x56, 0x82, 0x88, 0x38,
            0xc5, 0xf6, 0x1e, 0x63, 0x93, 0xba, 0x7a, 0x0a,
            0xbc, 0xc9, 0xf6, 0x62,
        ];
        let expected_tag: u8[16] = [
            0x76, 0xfc, 0x6e, 0xce, 0x0f, 0x4e, 0x17, 0x68,
            0xcd, 0xdf, 0x88, 0x53, 0xbb, 0x2d, 0x55, 0x1b,
        ];

        var in_out = pt;
        let tag, ok_seal = core::aes256_gcm_seal_inplace(key, iv, in_out[..], aad[..]);
        sub.assert_true(ok_seal, "AES-256 seal_inplace with AAD succeeds");
        for i in 60 {
            sub.assert_eq(in_out[i], expected_ct[i], "ciphertext matches NIST Case 16");
        }
        for i in 16 {
            sub.assert_eq(tag[i], expected_tag[i], "tag matches NIST Case 16");
        }

        let dec_len, ok_open = core::aes256_gcm_open_inplace(key, iv, in_out[..], aad[..], expected_tag);
        sub.assert_true(ok_open, "AES-256 open_inplace with AAD succeeds");
        sub.assert_eq(dec_len, 60, "decrypted len is 60");
        for i in 60 {
            sub.assert_eq(in_out[i], pt[i], "decrypted matches original plaintext");
        }
    };

    t.run("AES-256-GCM Empty Plaintext with AAD Round-Trip") { sub =>
        let key:   u8[32]      = [0x88; 32];
        let iv:    u8[12]      = [0x33; 12];
        let aad:   const u8[:] = "bearer_token_scope_aad";
        let empty: const u8[:] = "";

        var in_out: u8[..16] = [];
        let tag, ok_seal = core::aes256_gcm_seal_inplace(key, iv, in_out[..], aad);
        sub.assert_true(ok_seal, "AES-256 empty PT seal succeeds");

        let dec_len, ok_open = core::aes256_gcm_open_inplace(key, iv, in_out[..], aad, tag);
        sub.assert_true(ok_open, "AES-256 empty PT open with valid tag succeeds");
        sub.assert_eq(dec_len, 0, "decrypted len is 0");

        // Corrupted AAD must reject
        let _, ok_corrupt = core::aes256_gcm_open_inplace(key, iv, in_out[..], "corrupted_aad", tag);
        sub.assert_false(ok_corrupt, "AES-256 empty PT open with corrupted AAD rejected");
    };
}

// ----------------------------------------------------------------------------
// 3. RFC 8439 ChaCha20-Poly1305 Vectors
// ----------------------------------------------------------------------------
fn test_chacha20_poly1305_rfc8439_vectors(t: lit::T&) {
    t.run("RFC 8439 Section 2.8.2: ChaCha20-Poly1305 AEAD In-Place & Destination Slices") { sub =>
        let key: u8[32] = [
            0x80, 0x81, 0x82, 0x83, 0x84, 0x85, 0x86, 0x87,
            0x88, 0x89, 0x8a, 0x8b, 0x8c, 0x8d, 0x8e, 0x8f,
            0x90, 0x91, 0x92, 0x93, 0x94, 0x95, 0x96, 0x97,
            0x98, 0x99, 0x9a, 0x9b, 0x9c, 0x9d, 0x9e, 0x9f,
        ];
        let nonce: u8[12] = [
            0x07, 0x00, 0x00, 0x00,
            0x40, 0x41, 0x42, 0x43,
            0x44, 0x45, 0x46, 0x47,
        ];
        let aad: u8[12] = [
            0x50, 0x51, 0x52, 0x53,
            0xc0, 0xc1, 0xc2, 0xc3,
            0xc4, 0xc5, 0xc6, 0xc7,
        ];
        let plaintext: const u8[:] = "Ladies and Gentlemen of the class of \x2799: If I could offer you only one tip for the future, sunscreen would be it.";
        let expected_tag: u8[16] = [
            0x1a, 0xe1, 0x0b, 0x59, 0x4f, 0x09, 0xe2, 0x6a,
            0x7e, 0x90, 0x2e, 0xcb, 0xd0, 0x60, 0x06, 0x91,
        ];

        // 1. Test out-of-place slice encryption
        var ct_dst: u8[..256] = [];
        for i in plaintext.len { ct_dst.push(0); }
        let tag_out, written, ok_seal = core::chacha20_poly1305_seal(key, nonce, plaintext, aad[..], ct_dst[..]);
        sub.assert_true(ok_seal, "chacha20 seal succeeds");
        sub.assert_eq(written, plaintext.len, "written length matches plaintext");
        for i in 16 {
            sub.assert_eq(tag_out[i], expected_tag[i], "tag matches RFC 8439 Section 2.8.2");
        }

        // 2. Test in-place decryption
        var in_out = ct_dst;
        let dec_len, ok_open = core::chacha20_poly1305_open_inplace(key, nonce, in_out[..], aad[..], expected_tag);
        sub.assert_true(ok_open, "chacha20 open_inplace succeeds");
        sub.assert_eq(dec_len, plaintext.len, "decrypted length matches plaintext");
        sub.assert_eq(in_out[..], plaintext, "decrypted in-place matches original plaintext");

        // 3. Test in-place encryption
        let tag_ip, ok_sip = core::chacha20_poly1305_seal_inplace(key, nonce, in_out[..], aad[..]);
        sub.assert_true(ok_sip, "chacha20 seal_inplace succeeds");
        for i in 16 {
            sub.assert_eq(tag_ip[i], expected_tag[i], "seal_inplace tag matches RFC 8439 Section 2.8.2");
        }

        // 4. Test out-of-place destination slice decryption
        var pt_dst: u8[..256] = [];
        for i in in_out.len { pt_dst.push(0); }
        let dec_into_len, ok_into = core::chacha20_poly1305_open_into(key, nonce, in_out[..], aad[..], expected_tag, pt_dst[..]);
        sub.assert_true(ok_into, "chacha20 open_into succeeds");
        sub.assert_eq(dec_into_len, plaintext.len, "open_into length matches");
        sub.assert_eq(pt_dst[..], plaintext, "open_into matches plaintext");
    };
}

// ----------------------------------------------------------------------------
// 4. In-Place Auto-Zeroization on Tamper
// ----------------------------------------------------------------------------
fn test_aead_auto_zeroization_on_tamper(t: lit::T&) {
    t.run("AES-256-GCM in-place auto-zeroization on corrupt tag") { sub =>
        let key:       u8[32]      = [0x55; 32];
        let iv:        u8[12]      = [0xAA; 12];
        let aad:       const u8[:] = "context_aad";
        let plaintext: const u8[:] = "super_secret_payload_requiring_zeroization_on_error";

        var in_out: u8[..128] = [];
        for i in plaintext.len { in_out.push(plaintext[i]); }
        let tag, ok_seal = core::aes256_gcm_seal_inplace(key, iv, in_out[..], aad);
        sub.assert_true(ok_seal, "seal succeeds");

        // Tamper with tag
        var bad_tag = tag;
        bad_tag[0] ^= 0xFF;

        let dec_len, ok_open = core::aes256_gcm_open_inplace(key, iv, in_out[..], aad, bad_tag);
        sub.assert_false(ok_open, "open_inplace fails with tampered tag");
        sub.assert_eq(dec_len, 0, "decrypted length is 0 on failure");

        // Invariant: in_out must be completely zeroed by secure_zeroize_slice
        var is_zeroed = true;
        for i in in_out.len {
            if in_out[i] != 0 {
                is_zeroed = false;
                break;
            }
        }
        sub.assert_true(is_zeroed, "in_out buffer is 100% zeroized after authentication failure");
    };

    t.run("ChaCha20-Poly1305 in-place auto-zeroization on corrupt tag") { sub =>
        let key:       u8[32]      = [0x33; 32];
        let nonce:     u8[12]      = [0x77; 12];
        let aad:       const u8[:] = "chacha_aad";
        let plaintext: const u8[:] = "confidential_session_keys_must_not_leak_on_failure";

        var in_out: u8[..128] = [];
        for i in plaintext.len { in_out.push(plaintext[i]); }
        let tag, ok_seal = core::chacha20_poly1305_seal_inplace(key, nonce, in_out[..], aad);
        sub.assert_true(ok_seal, "seal succeeds");

        var bad_tag = tag;
        bad_tag[15] ^= 0x01;

        let dec_len, ok_open = core::chacha20_poly1305_open_inplace(key, nonce, in_out[..], aad, bad_tag);
        sub.assert_false(ok_open, "open_inplace fails with corrupted tag");
        sub.assert_eq(dec_len, 0, "decrypted len is 0");

        var is_zeroed = true;
        for i in in_out.len {
            if in_out[i] != 0 {
                is_zeroed = false;
                break;
            }
        }
        sub.assert_true(is_zeroed, "chacha20 in_out buffer is 100% zeroized after tag failure");
    };
}

// ----------------------------------------------------------------------------
// 5. HKDF-SHA256 AES-256-GCM Scheme
// ----------------------------------------------------------------------------
fn test_hkdf_aes256_gcm_scheme(t: lit::T&) {
    t.run("HKDF AES-256-GCM Seal and Open Into Destination Slice") { sub =>
        let master_key: u8[32]      = [0x42; 32];
        let salt32:     u8[32]      = [0x55; 32];
        let nonce12:    u8[12]      = [0x11; 12];
        let plaintext:  const u8[:] = "hkdf_authenticated_cookie_payload";
        let aad:        const u8[:] = "jar_v1_key1";

        var ct: u8[..64] = [];
        for i in plaintext.len { ct.push(0); }

        let tag, ct_len, ok_seal = core::hkdf_aes256_gcm_seal(
            master_key, salt32, nonce12, plaintext, aad, ct[..],
        );
        sub.assert_true(ok_seal, "seal succeeds");
        sub.assert_eq(ct_len, plaintext.len, "ciphertext length matches");

        var decrypted: u8[..64] = [];
        for i in plaintext.len { decrypted.push(0); }

        let dec_len, ok_open = core::hkdf_aes256_gcm_open_into(
            master_key, salt32, nonce12, ct[..ct_len], aad, tag, decrypted[..],
        );
        sub.assert_true(ok_open, "open_into succeeds");
        sub.assert_eq(dec_len, plaintext.len, "decrypted length matches");
        sub.assert_eq(decrypted[..dec_len], plaintext, "decrypted payload matches plaintext");
    };
}

// ----------------------------------------------------------------------------
// 6. Prepared AES-128/256-GCM Key Schedule Contexts
// ----------------------------------------------------------------------------
fn test_aes_gcm_prepared_key_contexts(t: lit::T&) {
    t.run("Prepared AES-128-GCM matches one-shot and rejects tampered tag") { sub =>
        let key16: u8[16]      = [0x11; 16];
        let nonce: u8[12]      = [0x22; 12];
        let pt:    const u8[:] = "prepared-key-128-payload-covering-multi-block-aes-gcm-64-plus-bytes-tail-check!";
        let aad:   const u8[:] = "tls13-aad-hdr";

        var ctx = core::AesGcmKey { .. };
        defer core::zeroize_aes_gcm_key(ctx);
        sub.assert_true(core::aes_gcm_prepare_key(key16[..], ctx), "prepare 128 key succeeds");
        sub.assert_true(ctx.valid, "ctx.valid is true");

        var ct_prep: u8[..128] = [];
        var ct_one:  u8[..128] = [];
        for _ in pt.len {
            ct_prep.push(0);
            ct_one.push(0);
        }
        let tag_p, n_p, ok_p = core::aes_gcm_seal_prepared(ctx, nonce, pt, aad, ct_prep[..]);
        let tag_o, n_o, ok_o = core::aes128_gcm_seal(key16, nonce, pt, aad, ct_one[..]);
        sub.assert_true(ok_p && ok_o, "both seal paths succeed");
        sub.assert_eq(n_p, pt.len, "prepared sealed length matches");
        sub.assert_eq(n_o, pt.len, "one-shot sealed length matches");
        sub.assert_eq(ct_prep[..n_p], ct_one[..n_o], "ciphertext matches one-shot");
        sub.assert_eq(tag_p[..], tag_o[..], "tag matches one-shot");

        var dec: u8[..128] = [];
        for _ in pt.len { dec.push(0xAA); }
        let dec_len, ok_dec = core::aes_gcm_open_prepared_into(ctx, nonce, ct_prep[..], aad, tag_p, dec[..]);
        sub.assert_true(ok_dec && dec_len == pt.len, "prepared open succeeds");
        sub.assert_eq(dec[..dec_len], pt, "plaintext round-trip matches");

        var bad_tag = tag_p;
        bad_tag[0] ^= 0x01;
        let bad_len, ok_bad = core::aes_gcm_open_prepared_into(ctx, nonce, ct_prep[..], aad, bad_tag, dec[..]);
        sub.assert_false(ok_bad, "tampered tag must fail");
        sub.assert_eq(bad_len, 0, "tampered dec len must be 0");
        for i in pt.len { sub.assert_eq(dec[i], 0, "dst zeroized on tampered open"); }
    };

    t.run("Prepared AES-256-GCM in-place and invalid/zeroized key rejection") { sub =>
        let key32: u8[32]      = [0x33; 32];
        let nonce: u8[12]      = [0x44; 12];
        let pt:    const u8[:] = "prepared-256-in-place-payload-exceeding-64-bytes-plus-partial-tail-block";
        let aad:   const u8[:] = "aad-256";

        var bad_ctx = core::AesGcmKey { .. };
        let short_key: u8[15] = [0; 15];
        sub.assert_false(core::aes_gcm_prepare_key(short_key[..], bad_ctx), "15-byte key rejected");
        sub.assert_false(bad_ctx.valid, "bad_ctx stays invalid");

        var ctx = core::AesGcmKey { .. };
        sub.assert_true(core::aes_gcm_prepare_key(key32[..], ctx), "prepare 256 key succeeds");

        var buf: u8[..128] = [];
        buf.append(pt);
        let tag_p, n_p, ok_p = core::aes_gcm_seal_prepared_inplace(ctx, nonce, buf[..], aad);
        sub.assert_true(ok_p && n_p == pt.len, "in-place prepared seal succeeds");

        var dec: u8[..128] = [];
        for _ in pt.len { dec.push(0); }
        let dec_len, ok_o = core::aes256_gcm_open_into(key32, nonce, buf[..], aad, tag_p, dec[..]);
        sub.assert_true(ok_o && dec_len == pt.len, "one-shot open verifies prepared ciphertext");
        sub.assert_eq(dec[..dec_len], pt, "decrypted plaintext matches");

        core::zeroize_aes_gcm_key(ctx);
        sub.assert_false(ctx.valid, "zeroized ctx marked invalid");
        let _, _, ok_after = core::aes_gcm_seal_prepared(ctx, nonce, pt, aad, dec[..]);
        sub.assert_false(ok_after, "zeroized ctx rejects seal");
    };

    t.run("4-Block Interleaved AES-128-GCM Scalar Fusion Round-Trip") { sub =>
        let key16:   u8[16] = [0x42; 16];
        let nonce12: u8[12] = [0x24; 12];
        let pt64 = "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef";
        var ks = core::aes128_key_schedule(key16);
        let zero_blk: u8[16] = [0; 16];
        let h = core::aes128_encrypt_block(ks, zero_blk);
        let j0 = core::init_j0(nonce12);
        let enc_j0 = core::aes128_encrypt_block(ks, j0);

        var ctr_e = j0;
        var ghash_e: u8[16] = [0; 16];
        var ct64:    u8[64] = [0; 64];
        core::fused_aes128_gcm_encrypt_4blocks(ks, h, ctr_e, ghash_e, pt64, ct64[..], 0);
        let tag_e = core::fused_aes128_gcm_finalize_tag(h, enc_j0, ghash_e, 0, 64);

        var ctr_d = j0;
        var ghash_d: u8[16] = [0; 16];
        var dec64:   u8[64] = [0; 64];
        core::fused_aes128_gcm_decrypt_4blocks(ks, h, ctr_d, ghash_d, ct64[..], dec64[..], 0);
        let tag_d = core::fused_aes128_gcm_finalize_tag(h, enc_j0, ghash_d, 0, 64);
        core::zeroize_aes128_ks(ks);

        sub.assert_true(core::ct_eq_tag16(tag_e, tag_d), "fused finalize tags match");
        sub.assert_eq(dec64[..], pt64, "fused 4-block decryption matches plaintext");
    };
}

fn main() {
    let runner = lit::new_runner("Symmetric AEAD In-Place & Destination Slices Suite");

    lit::run_case(runner, "1. NIST SP 800-38D AES-128-GCM Vectors", test_aes128_gcm_nist_vectors);
    lit::run_case(runner, "2. NIST SP 800-38D AES-256-GCM Vectors", test_aes256_gcm_nist_vectors);
    lit::run_case(runner, "3. RFC 8439 ChaCha20-Poly1305 Vectors", test_chacha20_poly1305_rfc8439_vectors);
    lit::run_case(runner, "4. In-Place Auto-Zeroization on Tamper", test_aead_auto_zeroization_on_tamper);
    lit::run_case(runner, "5. HKDF-SHA256 AES-256-GCM Scheme", test_hkdf_aes256_gcm_scheme);
    lit::run_case(runner, "6. Prepared AES-128/256-GCM Key Schedule Contexts", test_aes_gcm_prepared_key_contexts);

    let ok = lit::finish(runner);
    assert(ok);
}
