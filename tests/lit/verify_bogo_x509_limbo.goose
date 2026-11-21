// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Goose LIT Verification Suite: BoringSSL BoGo TLS 1.3 & Trail of Bits x509-limbo Adversarial Vectors
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

fn verify_bogo_tls13_record_and_ccs() {
    // 1. BoGo: ChangeCipherSpec flood & malformed CCS payload (RFC 8446 §5 & Appendix D.4)
    var filter = tls::RecordFilterState { .. };
    let valid_ccs:   u8[1] = [0x01];
    let bad_val_ccs: u8[1] = [0x02];
    let bad_len_ccs: u8[2] = [0x01, 0x01];

    // CCS outside active handshake must be rejected with UnexpectedMessage
    assert(tls::check_change_cipher_spec_record(filter, valid_ccs[..], false) == tls::Alert.UnexpectedMessage);

    // Wrong length or wrong value during handshake
    assert(tls::check_change_cipher_spec_record(filter, bad_len_ccs[..], true) == tls::Alert.DecodeError);
    assert(tls::check_change_cipher_spec_record(filter, bad_val_ccs[..], true) == tls::Alert.UnexpectedMessage);

    // First valid CCS during handshake succeeds; second triggers flood rejection (CVE-2020-1967)
    assert(tls::check_change_cipher_spec_record(filter, valid_ccs[..], true) == tls::Alert.CloseNotify);
    assert(tls::check_change_cipher_spec_record(filter, valid_ccs[..], true) == tls::Alert.UnexpectedMessage);

    // 2. BoGo: Sequence number exhaustion at 2^64 - 1 (RFC 8446 §5.3)
    let iv: u8[12] = [0x11; 12];
    let _, ok_max_seq = tls::compute_record_nonce(iv, 0xFFFFFFFFFFFFFFFF);
    assert(!ok_max_seq);
    var seq: u64 = 0xFFFFFFFFFFFFFFFE;
    assert(tls::increment_record_seq_num(seq) && seq == 0xFFFFFFFFFFFFFFFF);
    assert(!tls::increment_record_seq_num(seq));

    // 3. BoGo: All-zero TLSInnerPlaintext missing content type byte (RFC 8446 §5.4)
    let all_zero_inner: u8[16] = [0; 16];
    let _, _, alert_z = tls::unpack_inner_plaintext(all_zero_inner[..]);
    assert(alert_z == tls::Alert.UnexpectedMessage);
    print("BOGO_RECORD_AND_CCS: ok");
}

fn verify_bogo_tls13_downgrade_and_extensions() {
    // 1. BoGo: RFC 8446 §4.1.3 downgrade sentinels in ServerHello.random[24..32]
    var sh_rand_tls12: u8[32] = [0x22; 32];
    // "DOWNGRD\x01"
    let sentinel_12: u8[8] = [0x44, 0x4F, 0x57, 0x4E, 0x47, 0x52, 0x44, 0x01];
    for i in 8 { sh_rand_tls12[24 + i] = sentinel_12[i]; }
    assert(!tls::validate_server_random_downgrade(sh_rand_tls12, 0x0303, true));
    assert(!tls::validate_server_random_downgrade(sh_rand_tls12, 0x0304, true));

    var sh_rand_clean: u8[32] = [0x22; 32];
    assert(tls::validate_server_random_downgrade(sh_rand_clean, 0x0304, true));

    // 2. BoGo: Duplicate extension rejection in extension block (RFC 8446 §4.2)
    // Two identical 0x0010 (ALPN) extensions in the same block
    let dup_ext_block: u8[10] = [
        0x00, 0x08,
        0x00, 0x10, 0x00, 0x00,
        0x00, 0x10, 0x00, 0x00,
    ];
    var entries: tls::ExtensionEntry[..32] = [];
    assert(!tls::parse_extensions_block(dup_ext_block[..], entries));

    // 3. BoGo: Forbidden extensions in EncryptedExtensions (key_share 0x0033, pre_shared_key 0x0029, cookie 0x002C)
    let forbidden_types: u16[4] = [0x0033, 0x0029, 0x002C, 0x000D];
    var out_alpn: u8[..32] = [];
    for i in 4 {
        var ee_wire: u8[..16] = [];
        core::write_be_u16(ee_wire, 4);
        core::write_be_u16(ee_wire, forbidden_types[i]);
        core::write_be_u16(ee_wire, 0);
        assert(!tls::parse_encrypted_extensions_alpn(ee_wire[..], out_alpn));
    }

    // 4. BoGo: Curve / SignatureScheme binding (legacy RSA PKCS#1 v1.5 0x0401 forbidden in TLS 1.3 CertificateVerify)
    assert(!tls::verify_signature_scheme_curve_binding(0x0401, rfc::OID_RSA_ENCRYPTION[..]));
    assert(!tls::verify_signature_scheme_curve_binding(0x0804, rfc::OID_SECP256R1[..]));
    assert(tls::verify_signature_scheme_curve_binding(0x0403, rfc::OID_SECP256R1[..]));
    assert(tls::verify_signature_scheme_curve_binding(0x0807, rfc::OID_ED25519[..]));
    print("BOGO_DOWNGRADE_AND_EXTS: ok");
}

fn verify_x509_limbo_san_and_uri() {
    // Trail of Bits x509-limbo RFC 6125 §6.4.3 wildcard & NUL-byte vectors
    assert(tls::match_dns_san("*.example.com", "foo.example.com"));
    assert(tls::match_dns_san("*.EXAMPLE.COM.", "foo.example.com."));

    // Leftmost-only single-label wildcard invariants
    assert(!tls::match_dns_san("*.example.com", "example.com"));
    assert(!tls::match_dns_san("*.example.com", "a.b.example.com"));
    assert(!tls::match_dns_san("f*.example.com", "foo.example.com"));
    assert(!tls::match_dns_san("sub.*.example.com", "sub.foo.example.com"));
    assert(!tls::match_dns_san("*.com", "example.com"));
    assert(!tls::match_dns_san("*", "example.com"));
    assert(!tls::match_dns_san("*.example.com", ".example.com"));

    // Embedded NUL defense (CVE-2009-3555 / CVE-2021-3712)
    assert(!tls::match_dns_san("good.example.com\x00evil.com", "good.example.com"));
    assert(!tls::match_uri_san("example.com%25eth0", "example.com"));
    assert(!tls::match_uri_san("example.com\x00", "example.com"));
    print("X509_LIMBO_SAN_WILDCARD: ok");
}

fn verify_x509_limbo_chain_and_der() {
    let seed: u8[32] = [0x7A; 32];
    var valid_der: u8[..2048] = [];
    assert(tls::build_test_ed25519_cert_der(seed, "example.com", "example.com", "127.0.0.1", valid_der));

    var cert = tls::ParsedCert { .. };
    assert(tls::parse_x509_certificate(valid_der[..], cert));

    // 1. limbo::asn1::ber-indefinite-length rejection
    let ber_indef: u8[6] = [0x30, 0x80, 0x02, 0x01, 0x01, 0x00];
    var bad_cert = tls::ParsedCert { .. };
    assert(!tls::parse_x509_certificate(ber_indef[..], bad_cert));

    // 2. limbo::rfc5280::unsupported-critical-extension rejection
    var crit_cert = cert;
    crit_cert.has_unsupported_critical = true;
    var chain_crit: tls::ParsedCert[..8] = [];
    var raw_crit:   (const u8[:])[..8]   = [];
    let _ = chain_crit.try_push(crit_cert);
    let _ = raw_crit.try_push(valid_der[..]);
    var store = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(store, valid_der[..]));
    assert(tls::verify_certificate_chain(chain_crit, raw_crit, store, cert.validity_not_before + 10) == tls::Alert.UnsupportedExtension);

    // 3. limbo::rfc5280::validity-expired and not-yet-valid rejection
    var chain_valid: tls::ParsedCert[..8] = [];
    var raw_valid:   (const u8[:])[..8]   = [];
    let _ = chain_valid.try_push(cert);
    let _ = raw_valid.try_push(valid_der[..]);
    assert(tls::verify_certificate_chain(chain_valid, raw_valid, store, cert.validity_not_before + 10) == tls::Alert.CloseNotify);
    assert(tls::verify_certificate_chain(chain_valid, raw_valid, store, cert.validity_not_before - 1) == tls::Alert.CertificateExpired);
    assert(tls::verify_certificate_chain(chain_valid, raw_valid, store, cert.validity_not_after + 1) == tls::Alert.CertificateExpired);

    // 4. limbo::rfc5280::leaf-as-ca-bypass (non-CA certificate signing a child certificate)
    var non_ca_issuer = cert;
    non_ca_issuer.is_ca = false;
    non_ca_issuer.has_basic_constraints = true;
    var chain_leaf_ca: tls::ParsedCert[..8] = [];
    var raw_leaf_ca:   (const u8[:])[..8]   = [];
    let _ = chain_leaf_ca.try_push(cert);
    let _ = chain_leaf_ca.try_push(non_ca_issuer);
    let _ = raw_leaf_ca.try_push(valid_der[..]);
    let _ = raw_leaf_ca.try_push(valid_der[..]);
    assert(tls::verify_certificate_chain(chain_leaf_ca, raw_leaf_ca, store, cert.validity_not_before + 10) != tls::Alert.CloseNotify);
    print("X509_LIMBO_CHAIN_INVARIANTS: ok");
}

fn main() {
    // CHECK: === verify_bogo_x509_limbo ===
    print("=== verify_bogo_x509_limbo ===");
    // CHECK-NEXT: BOGO_RECORD_AND_CCS: ok
    verify_bogo_tls13_record_and_ccs();
    // CHECK-NEXT: BOGO_DOWNGRADE_AND_EXTS: ok
    verify_bogo_tls13_downgrade_and_extensions();
    // CHECK-NEXT: X509_LIMBO_SAN_WILDCARD: ok
    verify_x509_limbo_san_and_uri();
    // CHECK-NEXT: X509_LIMBO_CHAIN_INVARIANTS: ok
    verify_x509_limbo_chain_and_der();
    // CHECK-NEXT: ALL_BOGO_AND_X509_LIMBO_CHECKS_PASSED
    print("ALL_BOGO_AND_X509_LIMBO_CHECKS_PASSED");
}
