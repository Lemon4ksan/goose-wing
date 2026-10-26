// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/hpke_test.goose
// Verification test suite for Curve25519 (RFC 7748) and HPKE (RFC 9180).
import std;
import core from "..";
import wing from "..";

fn test_x25519_rfc7748(t: core::T&) {
    t.run("X25519-01: RFC 7748 Alice/Bob Key Agreement & Test Vectors") { sub =>
        let alice_sk: u8[32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let bob_sk: u8[32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
            0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
            0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
            0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
        ];

        let alice_pk = core::x25519_base_scalarmult(alice_sk);
        let expected_alice_pk: u8[32] = [
            0x85, 0x20, 0xf0, 0x09, 0x89, 0x30, 0xa7, 0x54,
            0x74, 0x8b, 0x7d, 0xdc, 0xb4, 0x3e, 0xf7, 0x5a,
            0x0d, 0xbf, 0x3a, 0x0d, 0x26, 0x38, 0x1a, 0xf4,
            0xeb, 0xa4, 0xa9, 0x8e, 0xaa, 0x9b, 0x4e, 0x6a,
        ];
        for i in 32 {
            sub.assert_eq(alice_pk[i], expected_alice_pk[i], "Alice PK matches RFC 7748");
        }

        let bob_pk = core::x25519_base_scalarmult(bob_sk);
        let expected_bob_pk: u8[32] = [
            0xde, 0x9e, 0xdb, 0x7d, 0x7b, 0x7d, 0xc1, 0xb4,
            0xd3, 0x5b, 0x61, 0xc2, 0xec, 0xe4, 0x35, 0x37,
            0x3f, 0x83, 0x43, 0xc8, 0x5b, 0x78, 0x67, 0x4d,
            0xad, 0xfc, 0x7e, 0x14, 0x6f, 0x88, 0x2b, 0x4f,
        ];
        for i in 32 {
            sub.assert_eq(bob_pk[i], expected_bob_pk[i], "Bob PK matches RFC 7748");
        }

        let shared_alice = core::x25519_scalarmult(alice_sk, bob_pk);
        let shared_bob = core::x25519_scalarmult(bob_sk, alice_pk);
        let expected_shared: u8[32] = [
            0x4a, 0x5d, 0x9d, 0x5b, 0xa4, 0xce, 0x2d, 0xe1,
            0x72, 0x8e, 0x3b, 0xf4, 0x80, 0x35, 0x0f, 0x25,
            0xe0, 0x7e, 0x21, 0xc9, 0x47, 0xd1, 0x9e, 0x33,
            0x76, 0xf0, 0x9b, 0x3c, 0x1e, 0x16, 0x17, 0x42,
        ];
        for i in 32 {
            sub.assert_eq(shared_alice[i], expected_shared[i], "Alice shared secret matches RFC 7748");
            sub.assert_eq(shared_bob[i], expected_shared[i], "Bob shared secret matches RFC 7748");
        }
    };
}

fn test_hpke_rfc9180(t: core::T&) {
    t.run("HPKE-01: RFC 9180 Section A.1.1 DHKEM(X25519, HKDF-SHA256) + AES-128-GCM") { sub =>
        let skEm: u8[32] = [
            0x52, 0xc4, 0xa7, 0x58, 0xa8, 0x02, 0xcd, 0x8b,
            0x93, 0x6e, 0xce, 0xea, 0x31, 0x44, 0x32, 0x79,
            0x8d, 0x5b, 0xaf, 0x2d, 0x7e, 0x92, 0x35, 0xdc,
            0x08, 0x4a, 0xb1, 0xb9, 0xcf, 0xa2, 0xf7, 0x36,
        ];
        let pkRm: u8[32] = [
            0x39, 0x48, 0xcf, 0xe0, 0xad, 0x1d, 0xdb, 0x69,
            0x5d, 0x78, 0x0e, 0x59, 0x07, 0x71, 0x95, 0xda,
            0x6c, 0x56, 0x50, 0x6b, 0x02, 0x73, 0x29, 0x79,
            0x4a, 0xb0, 0x2b, 0xca, 0x80, 0x81, 0x5c, 0x4d,
        ];
        let skRm: u8[32] = [
            0x46, 0x12, 0xc5, 0x50, 0x26, 0x3f, 0xc8, 0xad,
            0x58, 0x37, 0x5d, 0xf3, 0xf5, 0x57, 0xaa, 0xc5,
            0x31, 0xd2, 0x68, 0x50, 0x90, 0x3e, 0x55, 0xa9,
            0xf2, 0x3f, 0x21, 0xd8, 0x53, 0x4e, 0x8a, 0xc8,
        ];

        let info: const u8[:] = "Ode on a Grecian Urn";
        let pt: const u8[:] = "Beauty is truth, truth beauty";
        let aad: const u8[:] = "Count-0";

        var enc: u8[32] = [0; 32];
        var ct: u8[>..] = [];

        let ok_seal = wing::hpke_seal_base(
            pkRm,
            info,
            aad,
            pt,
            skEm,
            wing::HPKE_AEAD_AES_128_GCM,
            enc,
            ct,
        );
        sub.assert_true(ok_seal, "hpke_seal_base succeeds");

        let expected_enc: u8[32] = [
            0x37, 0xfd, 0xa3, 0x56, 0x7b, 0xdb, 0xd6, 0x28,
            0xe8, 0x86, 0x68, 0xc3, 0xc8, 0xd7, 0xe9, 0x7d,
            0x1d, 0x12, 0x53, 0xb6, 0xd4, 0xea, 0x6d, 0x44,
            0xc1, 0x50, 0xf7, 0x41, 0xf1, 0xbf, 0x44, 0x31,
        ];
        for i in 32 {
            sub.assert_eq(enc[i], expected_enc[i], "enc matches RFC 9180 A.1.1");
        }

        let expected_ct: u8[45] = [
            0xf9, 0x38, 0x55, 0x8b, 0x5d, 0x72, 0xf1, 0xa2,
            0x38, 0x10, 0xb4, 0xbe, 0x2a, 0xb4, 0xf8, 0x43,
            0x31, 0xac, 0xc0, 0x2f, 0xc9, 0x7b, 0xab, 0xc5,
            0x3a, 0x52, 0xae, 0x82, 0x18, 0xa3, 0x55, 0xa9,
            0x6d, 0x87, 0x70, 0xac, 0x83, 0xd0, 0x7b, 0xea,
            0x87, 0xe1, 0x3c, 0x51, 0x2a,
        ];
        sub.assert_eq(ct.len, 45, "ct length is 45");
        for i in 45 {
            sub.assert_eq(ct[i], expected_ct[i], "ct matches RFC 9180 A.1.1");
        }

        // Test decryption roundtrip
        var decrypted: u8[>..] = [];
        let ok_open = wing::hpke_open_base(
            enc,
            skRm,
            info,
            aad,
            ct[..],
            wing::HPKE_AEAD_AES_128_GCM,
            decrypted,
        );
        sub.assert_true(ok_open, "hpke_open_base succeeds");
        sub.assert_eq(decrypted.len, pt.len, "decrypted length matches plaintext");
        for i in pt.len {
            sub.assert_eq(decrypted[i], pt[i], "decrypted byte matches");
        }

        // Test tamper resistance
        ct[5] ^= 0x40;
        var dec_tampered: u8[>..] = [];
        let ok_tamper = wing::hpke_open_base(
            enc,
            skRm,
            info,
            aad,
            ct[..],
            wing::HPKE_AEAD_AES_128_GCM,
            dec_tampered,
        );
        sub.assert_false(ok_tamper, "tampered ciphertext fails decryption");
    };

    t.run("HPKE-02: DHKEM(X25519) + ChaCha20-Poly1305 Roundtrip") { sub =>
        let alice_sk: u8[32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let bob_sk: u8[32] = [
            0x5d, 0xab, 0x08, 0x7e, 0x62, 0x4a, 0x8a, 0x4b,
            0x79, 0xe1, 0x7f, 0x8b, 0x83, 0x80, 0x0e, 0xe6,
            0x6f, 0x3b, 0xb1, 0x29, 0x26, 0x18, 0xb6, 0xfd,
            0x1c, 0x2f, 0x8b, 0x27, 0xff, 0x88, 0xe0, 0xeb,
        ];
        let bob_pk = core::x25519_base_scalarmult(bob_sk);

        let info: const u8[:] = "Wing Systems Zero-Heap ECH";
        let pt: const u8[:] = "EncryptedClientHelloInner message payload";
        let aad: const u8[:] = "ClientHelloOuterAAD";

        var enc: u8[32] = [0; 32];
        var ct: u8[>..] = [];

        let ok_seal = wing::hpke_seal_base(
            bob_pk,
            info,
            aad,
            pt,
            alice_sk,
            wing::HPKE_AEAD_CHACHA20_POLY1305,
            enc,
            ct,
        );
        sub.assert_true(ok_seal, "ChaCha20Poly1305 seal succeeds");

        var decrypted: u8[>..] = [];
        let ok_open = wing::hpke_open_base(
            enc,
            bob_sk,
            info,
            aad,
            ct[..],
            wing::HPKE_AEAD_CHACHA20_POLY1305,
            decrypted,
        );
        sub.assert_true(ok_open, "ChaCha20Poly1305 open succeeds");
        sub.assert_eq(decrypted.len, pt.len, "decrypted length matches");
        for i in pt.len {
            sub.assert_eq(decrypted[i], pt[i], "decrypted payload matches");
        }
    };
}

fn main() {
    var runner = core::new_runner("Curve25519 (RFC 7748) & HPKE (RFC 9180) Conformance Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. Curve25519 (RFC 7748) Test Vectors", test_x25519_rfc7748);
    core::run_case(runner, "2. HPKE (RFC 9180) SetupBase, Seal & Open Vectors", test_hpke_rfc9180);
    let ok = core::finish(runner);
    assert(ok);
}
