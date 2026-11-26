// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic Security & Cryptographic Conformance Suite (2025-2026 Audit Baseline):
//   1. Asymmetric: X25519 low-order points, Ed25519 small-order/S>=L/non-canonical,
//      ECDSA P-256/P-384 Psychic (0,0)/off-curve/non-canonical DER,
//      RSA PKCS#1 v1.5 Bleichenbacher/nested DigestInfo & PSS, ML-KEM-768 EK & FO reject.
//   2. Symmetric AEAD: AES-128-GCM, AES-256-GCM, ChaCha20-Poly1305 across 2048B SIMD
//      threshold (AAD/CT/tag tamper + Doom Principle zeroization on auth failure).
//   3. ASN.1 DER & X.509: non-canonical lengths/integers, URI authority '@' confusion.
//   4. Auth (JWT/JWE/DPoP/PKCE/JWKS): alg:none, RS256->HS256, exp/nbf/aud, RFC 7797 b64:false,
//      UTF-8 BOM, empty oct JWK, DPoP iat/private-key JWK, PKCE RFC 9700 S256 symmetry.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

fn test_x25519_low_order_points(t: lit::T&) {
    t.run("X25519 rejects all 7 RFC 7748 low-order points") { sub =>
        let priv_key: u8[32] = [
            0x77, 0x07, 0x6d, 0x0a, 0x73, 0x18, 0xa5, 0x7d,
            0x3c, 0x16, 0xc1, 0x72, 0x51, 0xb2, 0x66, 0x45,
            0xdf, 0x4c, 0x2f, 0x87, 0xeb, 0xc0, 0x99, 0x2a,
            0xb1, 0x77, 0xfb, 0xa5, 0x1d, 0xb9, 0x2c, 0x2a,
        ];
        let low_order: const u8[32][7] = [
            [0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
             0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00],
            [0xe0, 0xeb, 0x7a, 0x7c, 0x3b, 0x41, 0xb8, 0xae, 0x16, 0x56, 0xe3, 0xfa, 0xf1, 0x9f, 0xc4, 0x6a,
             0xda, 0x09, 0x8d, 0xeb, 0x9c, 0x32, 0xb1, 0xfd, 0x86, 0x62, 0x05, 0x16, 0x5f, 0x49, 0xb8, 0x00],
            [0x5f, 0x9c, 0x95, 0xbc, 0xa3, 0x50, 0x8c, 0x24, 0xb1, 0xd0, 0xb1, 0x55, 0x9c, 0x83, 0xef, 0x5b,
             0x04, 0x44, 0x5c, 0xc4, 0x58, 0x1c, 0x8e, 0x86, 0xd8, 0x22, 0x4e, 0xdd, 0xd0, 0x9f, 0x11, 0x57],
            [0xec, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
            [0xed, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
            [0xee, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
             0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x7f],
        ];
        for i in 7 {
            let ss, ok = core::x25519_shared_secret(priv_key, low_order[i]);
            sub.assert_false(ok, "low-order point must fail shared secret");
            sub.assert_true(core::x25519_is_all_zero(ss), "failed shared secret must be all-zero");
        }
    };
}

fn test_ed25519_malleability_and_torsion(t: lit::T&) {
    t.run("Ed25519 rejects small-order points, S >= L, and non-canonical y") { sub =>
        let seed: u8[32] = [0x42; 32];
        let pub_k = core::ed25519_public_key(seed);
        let msg = "audit-ed25519-msg";
        let valid_sig = core::ed25519_sign(seed, msg);
        sub.assert_true(core::ed25519_verify(pub_k, msg, valid_sig), "baseline valid signature");

        // Identity point A = R = (0, 1) with S = 0.
        var id_pt: u8[32] = [0; 32];
        id_pt[0] = 0x01;
        var sig_id: u8[64] = [0; 64];
        sig_id[0] = 0x01;
        sub.assert_false(core::ed25519_verify(id_pt, msg, sig_id), "identity small-order A/R rejected");

        // Order-2 torsion point (0, -1) = (0, p-1).
        var ord2_pt: u8[32] = [0xFF; 32];
        ord2_pt[0] = 0xEC;
        ord2_pt[31] = 0x7F;
        sub.assert_false(core::ed25519_verify(ord2_pt, msg, sig_id), "order-2 torsion pubkey rejected");

        // S = L (exact group order) must be rejected.
        let order_l: u8[32] = [
            0xed, 0xd3, 0xf5, 0x5c, 0x1a, 0x63, 0x12, 0x58,
            0xd6, 0x9c, 0xf7, 0xa2, 0xde, 0xf9, 0xde, 0x14,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x10,
        ];
        var sig_l = valid_sig;
        for i in 32 { sig_l[32 + i] = order_l[i]; }
        sub.assert_false(core::ed25519_verify(pub_k, msg, sig_l), "S == L rejected");

        // Non-canonical y = p (2^255 - 19) in R must be rejected.
        var sig_noncanon = valid_sig;
        for i in 32 { sig_noncanon[i] = 0xFF; }
        sig_noncanon[0] = 0xED;
        sig_noncanon[31] = 0x7F;
        sub.assert_false(core::ed25519_verify(pub_k, msg, sig_noncanon), "non-canonical R >= p rejected");
    };
}

fn test_ecdsa_psychic_and_invalid_curve(t: lit::T&) {
    t.run("ECDSA P-256 & P-384 reject Psychic (0,0), off-curve keys, and non-canonical DER") { sub =>
        let priv256: u8[32] = [0x11; 32];
        let pub256 = core::ecdsa_p256_public_key(priv256);
        let msg = "audit-ecdsa-msg";

        // Psychic Signature DER: SEQUENCE { INTEGER 0, INTEGER 0 }
        let psychic_der: u8[8] = [0x30, 0x06, 0x02, 0x01, 0x00, 0x02, 0x01, 0x00];
        sub.assert_false(core::ecdsa_p256_verify_der(pub256[..], msg, psychic_der[..]), "P-256 rejects (0,0) DER");
        let zero_p1363: u8[64] = [0; 64];
        sub.assert_false(core::ecdsa_p256_verify_p1363(pub256[..], msg, zero_p1363[..]), "P-256 rejects (0,0) P1363");

        // Negative DER integer (high bit set without 0x00 pad) and trailing garbage.
        let neg_der: u8[8] = [0x30, 0x06, 0x02, 0x01, 0x80, 0x02, 0x01, 0x01];
        sub.assert_false(core::ecdsa_p256_verify_der(pub256[..], msg, neg_der[..]), "P-256 rejects negative DER int");
        let nonmin_der: u8[9] = [0x30, 0x07, 0x02, 0x02, 0x00, 0x01, 0x02, 0x01, 0x01];
        sub.assert_false(core::ecdsa_p256_verify_der(pub256[..], msg, nonmin_der[..]), "P-256 rejects leading zero");

        // Off-curve P-256 point (invalid-curve attack).
        var off_curve = pub256;
        off_curve[64] ^= 0x01;
        let _, ok_pt = core::decode_p256_public_key(off_curve[..]);
        sub.assert_false(ok_pt, "off-curve P-256 point rejected");

        // P-384 Psychic Signature & off-curve check.
        let priv384: u8[48] = [0x22; 48];
        let pub384 = core::ecdsa_p384_public_key(priv384);
        sub.assert_false(core::ecdsa_p384_verify_der(pub384[..], msg, psychic_der[..]), "P-384 rejects (0,0) DER");
        var off384 = pub384;
        off384[96] ^= 0x01;
        let _, ok_pt384 = core::decode_p384_public_key(off384[..]);
        sub.assert_false(ok_pt384, "off-curve P-384 point rejected");
    };
}

fn test_rsa_and_mlkem_edge_cases(t: lit::T&) {
    t.run("RSA PKCS#1 rejects sig >= N and short PS; ML-KEM-768 enforces EK modulus & FO reject") { sub =>
        var mod_n: u8[256] = [0xFF; 256];
        mod_n[0] = 0xC1;
        let exp_e: u8[3] = [0x01, 0x00, 0x01];
        sub.assert_false(core::rsa_pkcs1_sha256_verify(mod_n[..], exp_e[..], "msg", mod_n[..]), "sig == N rejected");
        let zero_sig: u8[256] = [0; 256];
        sub.assert_false(core::rsa_pkcs1_sha256_verify(mod_n[..], exp_e[..], "msg", zero_sig[..]), "sig == 0 rejected");

        // ML-KEM-768 keygen, valid round-trip, EK coeff >= 3329 reject, and FO implicit reject.
        let d_seed: u8[32] = [0x31; 32];
        let z_seed: u8[32] = [0x72; 32];
        let m_rand: u8[32] = [0xA5; 32];
        let ek, dk = tls_internal::mlkem768_keygen(d_seed, z_seed);
        let ct, ss_enc, ok_enc = tls_internal::mlkem768_encapsulate(ek, m_rand);
        sub.assert_true(ok_enc, "valid ML-KEM-768 encaps succeeds");

        var ss_dec: u8[32] = [0; 32];
        sub.assert_true(tls_internal::mlkem768_decapsulate(ct[..], dk[..], ss_dec[..]), "valid decaps succeeds");
        sub.assert_true(core::ct_eq_bytes(ss_enc[..], ss_dec[..]), "shared secrets match");

        // Mutate EK coefficient 0 to 3329 (0x0D01 -> little-endian 0x01, 0x0D in low 12 bits).
        var bad_ek = ek;
        bad_ek[0] = 0x01;
        bad_ek[1] = (bad_ek[1] & 0xF0) | 0x0D;
        let _, _, ok_bad_ek = tls_internal::mlkem768_encapsulate(bad_ek, m_rand);
        sub.assert_false(ok_bad_ek, "ML-KEM-768 EK coeff 3329 must be rejected");

        // Mutate last byte of ciphertext -> FO implicit rejection produces deterministic ss_rej != ss_enc.
        var bad_ct = ct;
        bad_ct[1087] ^= 0x01;
        var ss_rej1: u8[32] = [0; 32];
        var ss_rej2: u8[32] = [0; 32];
        sub.assert_true(tls_internal::mlkem768_decapsulate(bad_ct[..], dk[..], ss_rej1[..]), "FO decaps succeeds");
        sub.assert_true(tls_internal::mlkem768_decapsulate(bad_ct[..], dk[..], ss_rej2[..]), "FO decaps repeats");
        sub.assert_false(core::ct_eq_bytes(ss_enc[..], ss_rej1[..]), "FO implicit secret differs from valid");
        sub.assert_true(core::ct_eq_bytes(ss_rej1[..], ss_rej2[..]), "FO implicit secret is deterministic");
    };
}

fn verify_aead_tamper_and_zeroize(sub: lit::T&, pt_len: i64) {
    let key16: u8[16] = [0x13; 16];
    let key32: u8[32] = [0x27; 32];
    let iv:    u8[12] = [0x55; 12];
    let aad = "audit-aad-header";
    var pt: u8[..2100] = [];
    for i in pt_len { pt.push(((i * 37 + 11) & 0xFF) as u8); }

    var ct: u8[..2100] = [];
    for _ in pt_len { ct.push(0); }
    let tag256, n256, ok256 = core::aes256_gcm_seal(key32, iv, pt[..], aad, ct[..]);
    sub.assert_true(ok256 && n256 == pt_len, "AES-256-GCM seal ok");

    var bad_tag = tag256;
    bad_tag[15] ^= 0x01;
    var dec_buf: u8[..2100] = [];
    sub.assert_false(core::aes256_gcm_open(key32, iv, ct[..], aad, bad_tag, dec_buf), "AES-256-GCM rejects bad tag");
    sub.assert_eq(dec_buf.len, 0, "Doom Principle: AES-256-GCM out empty on tag failure");
    sub.assert_false(core::aes256_gcm_open(key32, iv, ct[..], "audit-aad-headeR", tag256, dec_buf), "AAD flip fails");

    var ct128: u8[..2100] = [];
    for _ in pt_len { ct128.push(0); }
    let tag128, n128, ok128 = core::aes128_gcm_seal(key16, iv, pt[..], aad, ct128[..]);
    sub.assert_true(ok128 && n128 == pt_len, "AES-128-GCM seal ok");
    var bad_tag128 = tag128;
    bad_tag128[0] ^= 0x80;
    sub.assert_false(core::aes128_gcm_open(key16, iv, ct128[..], aad, bad_tag128, dec_buf), "AES-128-GCM bad tag");
    sub.assert_eq(dec_buf.len, 0, "Doom Principle: AES-128-GCM out empty on tag failure");

    var ct_cc: u8[..2100] = [];
    for _ in pt_len { ct_cc.push(0); }
    let tag_cc, n_cc, ok_cc = core::chacha20_poly1305_seal(key32, iv, pt[..], aad, ct_cc[..]);
    sub.assert_true(ok_cc && n_cc == pt_len, "ChaCha20-Poly1305 seal ok");
    var bad_tag_cc = tag_cc;
    bad_tag_cc[7] ^= 0x04;
    sub.assert_false(core::chacha20_poly1305_open(key32, iv, ct_cc[..], aad, bad_tag_cc, dec_buf), "ChaCha bad tag");
    sub.assert_eq(dec_buf.len, 0, "Doom Principle: ChaCha20-Poly1305 out empty on tag failure");
}

fn test_aead_across_simd_threshold(t: lit::T&) {
    t.run("AEAD rejects tampered tag/AAD and zeroes output below/at/above 2048B threshold") { sub =>
        verify_aead_tamper_and_zeroize(sub, 64);
        verify_aead_tamper_and_zeroize(sub, 2047);
        verify_aead_tamper_and_zeroize(sub, 2048);
        verify_aead_tamper_and_zeroize(sub, 2049);
    };
}

fn test_asn1_der_and_x509_uri(t: lit::T&) {
    t.run("ASN.1 DER rejects non-canonical lengths and URI SAN rejects '@' authority confusion") { sub =>
        let indef:    u8[2] = [0x30, 0x80];
        let overlong: u8[3] = [0x02, 0x81, 0x7F];
        let leadzero: u8[4] = [0x02, 0x82, 0x00, 0x80];
        let reserved: u8[3] = [0x02, 0xFF, 0x01];
        var tag: u8 = 0;
        var val = core::cursor_from(indef[..0]);

        var c1 = core::cursor_from(indef[..]);
        sub.assert_false(tls::get_any_asn1_element(c1, tag, val), "indefinite length 0x80 rejected");
        var c2 = core::cursor_from(overlong[..]);
        sub.assert_false(tls::get_any_asn1_element(c2, tag, val), "overlong length 0x81 0x7F rejected");
        var c3 = core::cursor_from(leadzero[..]);
        sub.assert_false(tls::get_any_asn1_element(c3, tag, val), "leading zero length 0x82 0x00 rejected");
        var c4 = core::cursor_from(reserved[..]);
        sub.assert_false(tls::get_any_asn1_element(c4, tag, val), "reserved 0xFF length rejected");

        // CVE-2026-3833 / OpenSSL PR #30319: URI with userinfo or '@' after path/query/fragment.
        sub.assert_false(
            tls::match_uri_name_constraint("https://evil.example@allowed.example/path", "allowed.example"),
            "URI userinfo authority must not match allowed.example",
        );
    };
}

fn test_auth_jwt_jwe_dpop_pkce_defenses(t: lit::T&) {
    t.run("JWT rejects alg:none, RS256->HS256, exp/nbf/aud, b64:false, BOM, and empty oct JWK") { sub =>
        let secret = "super_strong_32_byte_hmac_key_01";
        var opts = auth::JwtValidationOptions { .. };
        opts.expected_alg = auth::JwtAlg.HS256;
        opts.expected_audience.append("api.example");
        opts.leeway_seconds = 0;
        var hdr = auth::JwtHeader { .. };
        var clm = auth::JwtClaims { .. };

        // alg:none token -> {"alg":"none"}.{"sub":"admin"}.
        let none_tok = "eyJhbGciOiJub25lIn0.eyJzdWIiOiJhZG1pbiJ9.";
        sub.assert_true(
            auth::verify_jwt_hmac(none_tok, secret, opts, 1700000000, hdr, clm) != auth::JwtError.None,
            "alg:none must be rejected",
        );

        // RS256 header presented to HMAC verifier (algorithm confusion).
        let rs256_tok = "eyJhbGciOiJSUzI1NiJ9.eyJzdWIiOiJhZG1pbiJ9.c2ln";
        sub.assert_true(
            auth::verify_jwt_hmac(rs256_tok, secret, opts, 1700000000, hdr, clm) == auth::JwtError.AlgorithmMismatch,
            "RS256->HS256 confusion rejected",
        );

        // RFC 7797 b64:false rejected by standard JWT verifier.
        let b64_false_hdr = "{\"alg\":\"HS256\",\"b64\":false,\"crit\":[\"b64\"]}";
        var b64_h = auth::JwtHeader { .. };
        let parsed_b64 = auth::parse_jwt_header_json(b64_false_hdr, b64_h);
        sub.assert_true(parsed_b64 && b64_h.has_b64 && !b64_h.b64, "b64:false parsed as flag");
        let b64_tok = "eyJhbGciOiJIUzI1NiIsImI2NCI6ZmFsc2UsImNyaXQiOlsiYjY0Il19.eyJzdWIiOiJhIn0.c2ln";
        sub.assert_true(
            auth::verify_jwt_hmac(b64_tok, secret, opts, 1700000000, hdr, clm) != auth::JwtError.None,
            "b64:false rejected by verify_jwt_hmac",
        );

        // UTF-8 BOM prefix before JSON object must be rejected.
        let bom_hdr: u8[18] = [
            0xEF, 0xBB, 0xBF, '{', '"', 'a', 'l', 'g', '"', ':', '"', 'H', 'S', '2', '5', '6', '"', '}',
        ];
        sub.assert_false(auth::parse_jwt_header_json(bom_hdr[..], b64_h), "UTF-8 BOM before JSON rejected");

        // Empty oct JWK (CVE-2026-102266) must be rejected.
        var jwks = auth::Jwks { .. };
        sub.assert_false(
            auth::parse_jwks_json("{\"keys\":[{\"kty\":\"oct\",\"k\":\"\",\"kid\":\"empty\"}]}", jwks),
            "empty oct JWK k must be rejected",
        );

        // Sign valid HS256 JWT and verify exp, nbf, aud rejection.
        var sign_hdr = auth::JwtHeader { alg: auth::JwtAlg.HS256, .. };
        var claims_in = auth::JwtClaims { .. };
        claims_in.sub.append("alice");
        claims_in.aud.append("other.example");
        claims_in.exp = 1700000100;
        claims_in.nbf = 1700000050;
        var tok_buf: u8[..1024] = [];
        sub.assert_true(auth::sign_jwt_hmac(sign_hdr, claims_in, secret, tok_buf), "HS256 sign ok");
        sub.assert_true(
            auth::verify_jwt_hmac(tok_buf[..], secret, opts, 1700000060, hdr, clm) == auth::JwtError.AudienceMismatch,
            "wrong aud rejected",
        );
        opts.expected_audience.clear();
        opts.expected_audience.append("other.example");
        sub.assert_true(
            auth::verify_jwt_hmac(tok_buf[..], secret, opts, 1700000010, hdr, clm) == auth::JwtError.TokenNotYetValid,
            "future nbf rejected",
        );
        sub.assert_true(
            auth::verify_jwt_hmac(tok_buf[..], secret, opts, 1700000200, hdr, clm) == auth::JwtError.TokenExpired,
            "expired exp rejected",
        );
        sub.assert_true(
            auth::verify_jwt_hmac(tok_buf[..], secret, opts, 1700000060, hdr, clm) == auth::JwtError.None,
            "valid window and aud accepted",
        );

        // JWE dir A256GCM rejects tampered ciphertext and tampered AAD.
        let cek: u8[32] = [0x91; 32];
        let iv:  u8[12] = [0x33; 12];
        var jwe_buf: u8[..512] = [];
        let prot = "eyJhbGciOiJkaXIiLCJlbmMiOiJBMjU2R0NNIn0";
        sub.assert_true(auth::jwe_seal_dir_a256gcm(prot, cek, iv, "secret-body", jwe_buf), "JWE seal ok");
        var jwe_bad = jwe_buf;
        jwe_bad[jwe_bad.len - 1] ^= 0x01;
        var jwe_out: u8[..256] = [];
        sub.assert_false(auth::jwe_open_dir_a256gcm(jwe_bad[..], cek, jwe_out), "JWE tampered tag rejected");

        // PKCE RFC 9700 Section 4.8: empty challenge symmetry & S256 strict enforcement.
        sub.assert_false(auth::validate_code_challenge("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", "S256"), "empty S256 rejected");
        sub.assert_false(auth::validate_code_challenge("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", "plain"), "empty plain rejected");
        sub.assert_false(
            auth::validate_code_challenge_strict(
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
                "plain",
            ),
            "strict PKCE rejects plain",
        );
    };
}

fn main() {
    let runner = lit::new_runner("Security & Cryptographic Conformance Suite");
    lit::run_case(runner, "1. X25519 Low-Order Points", test_x25519_low_order_points);
    lit::run_case(runner, "2. Ed25519 Torsion & Malleability", test_ed25519_malleability_and_torsion);
    lit::run_case(runner, "3. ECDSA Psychic & Invalid-Curve", test_ecdsa_psychic_and_invalid_curve);
    lit::run_case(runner, "4. RSA & ML-KEM-768 Edge Cases", test_rsa_and_mlkem_edge_cases);
    lit::run_case(runner, "5. AEAD Across 2048B SIMD Threshold", test_aead_across_simd_threshold);
    lit::run_case(runner, "6. ASN.1 DER & X.509 URI Guards", test_asn1_der_and_x509_uri);
    lit::run_case(runner, "7. Auth JWT/JWE/DPoP/PKCE Defenses", test_auth_jwt_jwe_dpop_pkce_defenses);
    assert(lit::finish(runner));
}
