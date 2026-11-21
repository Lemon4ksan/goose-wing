// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification of RFC 7468 PEM decoding, PKCS#8 / SEC 1 private key parsing,
// TrustAnchorStore PEM loading, and SNI TLS server credential binding.
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn make_pem_block(label: const u8[:], der: const u8[:], out: u8[>..]&) {
    out.append("-----BEGIN ");
    out.append(label);
    out.append("-----\n");
    var b64: u8[>..] = [];
    core::base64_encode(der, b64);
    var i: i64 = 0;
    while i < b64.len {
        let end = min(i + 64, b64.len);
        out.append(b64[i..end]);
        out.push('\n');
        i = end;
    }
    out.append("-----END ");
    out.append(label);
    out.append("-----\n");
}

fn is_all_zero_32(buf: const u8[32]&) -> bool {
    for i in 32 {
        if buf[i] != 0 { return false; }
    }
    return true;
}

fn main() {
    print("=== verify_pem_pkcs8 ===");
    // CHECK: === verify_pem_pkcs8 ===

    // 1. Basic PEM block parsing with CRLF and explanatory prefix
    let raw_pem =
        "Bag Attributes\n-----BEGIN CERTIFICATE-----\r\nAQIDBA==\r\n-----END CERTIFICATE-----\r\n-----BEGIN PRIVATE KEY-----\nBQYH\n-----END PRIVATE KEY-----\n";
    var idx:   i64        = 0;
    var label: u8[..64]   = [];
    var der:   u8[..4096] = [];
    let ok1 = tls::pem_next_block(raw_pem, idx, label, der);
    assert(ok1);
    assert(label[..] == "CERTIFICATE");
    assert(der.len == 4 && der[0] == 1 && der[1] == 2 && der[2] == 3 && der[3] == 4);

    let ok2 = tls::pem_next_block(raw_pem, idx, label, der);
    assert(ok2);
    assert(label[..] == "PRIVATE KEY");
    assert(der.len == 3 && der[0] == 5 && der[1] == 6 && der[2] == 7);
    assert(idx == raw_pem.len);

    // 2. Negative PEM cases: mismatched label, bad base64, empty body, transactional rollback
    var bad_idx: i64 = 2;
    let bad_mismatch = "xx-----BEGIN CERTIFICATE-----\nAQID\n-----END PRIVATE KEY-----\n";
    assert(!tls::pem_next_block(bad_mismatch, bad_idx, label, der));
    assert(bad_idx == 2 && label.len == 0 && der.len == 0);

    let bad_b64 = "-----BEGIN CERTIFICATE-----\n!!!!\n-----END CERTIFICATE-----\n";
    var bad_b64_idx: i64 = 0;
    assert(!tls::pem_next_block(bad_b64, bad_b64_idx, label, der));
    assert(bad_b64_idx == 0 && der.len == 0);

    let bad_empty = "-----BEGIN CERTIFICATE-----\n\n-----END CERTIFICATE-----\n";
    var empty_idx: i64 = 0;
    assert(!tls::pem_next_block(bad_empty, empty_idx, label, der));
    assert(empty_idx == 0);

    print("pem_blocks_ok: true");
    // CHECK: pem_blocks_ok: true

    // 3. PKCS#8 Ed25519 PrivateKeyInfo DER & PEM (RFC 8410)
    var ed_seed: u8[32] = [0; 32];
    for i in 32 { ed_seed[i] = (0x10 + i) as u8; }
    var pkcs8_ed_der: u8[>..] = [
        0x30, 0x2E, 0x02, 0x01, 0x00,
        0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70,
        0x04, 0x22, 0x04, 0x20,
    ];
    for i in 32 { pkcs8_ed_der.push(ed_seed[i]); }

    var ed_pem: u8[>..] = [];
    make_pem_block("PRIVATE KEY", pkcs8_ed_der[..], ed_pem);
    var parsed_ed_key: u8[32] = [0; 32];
    let ed_kind, ok_ed = tls::parse_private_key_pem(ed_pem[..], parsed_ed_key);
    assert(ok_ed && ed_kind == tls::PrivateKeyKind.Ed25519);
    assert(parsed_ed_key[..] == ed_seed[..]);

    // 4. PKCS#8 ECDSA P-256 PrivateKeyInfo & SEC 1 EC PRIVATE KEY
    var p256_scalar: u8[32] = [0; 32];
    for i in 32 { p256_scalar[i] = (0xA0 + i) as u8; }
    var sec1_der: u8[>..] = [
        0x30, 0x31, 0x02, 0x01, 0x01,
        0x04, 0x20,
    ];
    for i in 32 { sec1_der.push(p256_scalar[i]); }
    sec1_der.append([0xA0, 0x0A, 0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07]);

    var sec1_pem: u8[>..] = [];
    make_pem_block("EC PRIVATE KEY", sec1_der[..], sec1_pem);
    var parsed_sec1_key: u8[32] = [0; 32];
    let sec1_kind, ok_sec1 = tls::parse_private_key_pem(sec1_pem[..], parsed_sec1_key);
    assert(ok_sec1 && sec1_kind == tls::PrivateKeyKind.EcdsaP256);
    assert(parsed_sec1_key[..] == p256_scalar[..]);

    var pkcs8_p256_der: u8[>..] = [
        0x30, 0x41, 0x02, 0x01, 0x00,
        0x30, 0x13, 0x06, 0x07, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01,
        0x06, 0x08, 0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07,
        0x04, 0x27, 0x30, 0x25, 0x02, 0x01, 0x01, 0x04, 0x20,
    ];
    for i in 32 { pkcs8_p256_der.push(p256_scalar[i]); }
    var pkcs8_p256_pem: u8[>..] = [];
    make_pem_block("PRIVATE KEY", pkcs8_p256_der[..], pkcs8_p256_pem);
    var parsed_p256_key: u8[32] = [0; 32];
    let p256_kind, ok_p256 = tls::parse_private_key_pem(pkcs8_p256_pem[..], parsed_p256_key);
    assert(ok_p256 && p256_kind == tls::PrivateKeyKind.EcdsaP256);
    assert(parsed_p256_key[..] == p256_scalar[..]);

    // Encrypted private key MUST be rejected and output zeroized
    var enc_pem: u8[>..] = [];
    make_pem_block("ENCRYPTED PRIVATE KEY", pkcs8_ed_der[..], enc_pem);
    let enc_kind, ok_enc = tls::parse_private_key_pem(enc_pem[..], parsed_ed_key);
    assert(!ok_enc && enc_kind == tls::PrivateKeyKind.Unknown);
    assert(is_all_zero_32(parsed_ed_key));

    print("pkcs8_keys_ok: true");
    // CHECK: pkcs8_keys_ok: true

    // 5. TrustAnchorStore multi-cert PEM bundle & Server SNI credential loading
    var cert1_der: u8[..2048] = [];
    assert(tls::build_test_ed25519_cert_der(ed_seed, "ca.wing.test", "ca.wing.test", "", cert1_der));
    var cert2_der: u8[..2048] = [];
    assert(tls::build_test_ed25519_cert_der(p256_scalar, "leaf.wing.test", "leaf.wing.test", "", cert2_der));

    var bundle_pem: u8[>..] = [];
    make_pem_block("CERTIFICATE", cert1_der[..], bundle_pem);
    make_pem_block("CERTIFICATE", cert2_der[..], bundle_pem);

    var store = tls::TrustAnchorStore { .. };
    let added, ok_store = tls::add_trust_anchors_pem(store, bundle_pem[..]);
    assert(ok_store && added == 2 && store.anchors.len == 2);

    var leaf_cert_pem: u8[>..] = [];
    make_pem_block("CERTIFICATE", cert1_der[..], leaf_cert_pem);
    var srv = server::new_http_server("127.0.0.1", 8443);
    assert(server::add_server_name(srv, "api.wing.test", leaf_cert_pem[..], ed_pem[..]));
    let sni_creds, ok_sni = server::resolve_sni_credentials(srv, "api.wing.test");
    assert(ok_sni);

    var tls_cfg = tls::ServerHandshakeConfig { .. };
    assert(server::sni_credentials_to_tls_config(sni_creds, tls_cfg));
    assert(tls_cfg.cert_der[..] == cert1_der[..]);
    assert(tls_cfg.priv_seed[..] == ed_seed[..]);

    // Mismatched algorithm (Ed25519 cert + P-256 key) MUST fail and wipe tls_cfg
    assert(!tls::load_server_credentials_pem(leaf_cert_pem[..], sec1_pem[..], tls_cfg));
    assert(tls_cfg.cert_der.len == 0 && is_all_zero_32(tls_cfg.priv_seed));

    print("tls_sni_pem_ok: true");
    // CHECK: tls_sni_pem_ok: true
}
