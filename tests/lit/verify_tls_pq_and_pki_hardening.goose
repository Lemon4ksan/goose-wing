// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Goose LIT Verification Suite: ML-KEM-768 Constant-Time Barrett/Compress & X.509/PKI Hardening.
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

// ---- ASN.1 DER Test Builders -----------------------------------------------

fn der_push_len<B>(out: B&, len: i64) {
    if len < 128 {
        assert(out.try_push(len as u8));
    } else if len < 256 {
        assert(out.try_push(0x81) && out.try_push(len as u8));
    } else {
        assert(
            out.try_push(0x82) &&
            out.try_push(((len >> 8) & 0xFF) as u8) &&
            out.try_push((len & 0xFF) as u8),
        );
    }
}

fn der_wrap<B>(tag: u8, body: const u8[:], out: B&) {
    out.clear();
    assert(out.try_push(tag));
    der_push_len(out, body.len);
    assert(out.try_append(body));
}

fn der_append_tlv<B>(out: B&, tag: u8, body: const u8[:]) {
    assert(out.try_push(tag));
    der_push_len(out, body.len);
    assert(out.try_append(body));
}

fn der_append_pos_int<B>(out: B&, big_endian: const u8[:]) {
    let needs_pad = big_endian.len > 0 && (big_endian[0] & 0x80) != 0;
    let total = if needs_pad { big_endian.len + 1 } else { big_endian.len };
    assert(out.try_push(rfc::ASN1_TAG_INTEGER));
    der_push_len(out, total);
    if needs_pad {
        assert(out.try_push(0x00));
    }
    assert(out.try_append(big_endian));
}

fn encode_rsa_pkcs1_pub_der<B>(n_be: const u8[:], e_be: const u8[:], out: B&) {
    var inner: u8[..600] = [];
    der_append_pos_int(inner, n_be);
    der_append_pos_int(inner, e_be);
    der_wrap(rfc::ASN1_TAG_SEQUENCE, inner[..], out);
}

fn encode_name_cn<B>(cn: const u8[:], out: B&) {
    var atv_body: u8[..128] = [];
    der_append_tlv(atv_body, rfc::ASN1_TAG_OID, rfc::OID_COMMON_NAME[..]);
    der_append_tlv(atv_body, rfc::ASN1_TAG_UTF8_STRING, cn);
    var atv: u8[..140] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, atv_body[..], atv);
    var rdn: u8[..148] = [];
    der_wrap(rfc::ASN1_TAG_SET, atv[..], rdn);
    der_wrap(rfc::ASN1_TAG_SEQUENCE, rdn[..], out);
}

fn encode_ext_entry<B>(out: B&, oid: const u8[:], critical: bool, val: const u8[:]) {
    var body: u8[..512] = [];
    der_append_tlv(body, rfc::ASN1_TAG_OID, oid);
    if critical {
        let crit_val: u8[1] = [0xFF];
        der_append_tlv(body, rfc::ASN1_TAG_BOOLEAN, crit_val[..]);
    }
    der_append_tlv(body, rfc::ASN1_TAG_OCTET_STRING, val);
    der_append_tlv(out, rfc::ASN1_TAG_SEQUENCE, body[..]);
}

// ---- 1. ML-KEM-768 Constant-Time Barrett & Compress Exactness --------------

fn test_mlkem_barrett_and_compress_exactness() {
    var v: i64 = -12000000;
    while v <= 12000000 {
        let got = tls_internal::fips203_mod_q(v);
        var exp = (v % 3329) as i32;
        if exp < 0 {
            exp += 3329;
        }
        assert(got == exp);
        v += 1;
    }

    for c in 3329 {
        let cu = c as u64;
        let ref_1 = ((((cu << 1) + 1664) / 3329) & 1) as u32;
        let ref_4 = ((((cu << 4) + 1664) / 3329) & 0x0F) as u32;
        let ref_10 = ((((cu << 10) + 1664) / 3329) & 0x3FF) as u32;
        assert(tls_internal::fips203_compress_d(c as i32, 2, 1) == ref_1);
        assert(tls_internal::fips203_compress_d(c as i32, 16, 0x0F) == ref_4);
        assert(tls_internal::fips203_compress_d(c as i32, 1024, 0x3FF) == ref_10);
        assert(tls_internal::fips203_add_q(c as i32, 3328) == (if c == 0 { 3328 } else { (c as i32) - 1 }));
        assert(tls_internal::fips203_sub_q(0, c as i32) == (if c == 0 { 0 } else { 3329 - (c as i32) }));
    }

    var d_seed: u8[32] = [0x11; 32];
    var z_seed: u8[32] = [0x22; 32];
    var m_rand: u8[32] = [0x33; 32];
    let ek, dk = tls_internal::mlkem768_keygen(d_seed, z_seed);
    let ct, ss_enc, ok_enc = tls_internal::mlkem768_encapsulate(ek, m_rand);
    assert(ok_enc);

    var ss_dec: u8[32] = [0; 32];
    assert(tls_internal::mlkem768_decapsulate(ct[..], dk[..], ss_dec[..]));
    assert(core::ct_eq_bytes(ss_enc[..], ss_dec[..]));

    var ct_bad = ct;
    ct_bad[42] ^= 0x80;
    var ss_rej: u8[32] = [0; 32];
    assert(tls_internal::mlkem768_decapsulate(ct_bad[..], dk[..], ss_rej[..]));
    let expected_rej = tls_internal::ml_kem_j(z_seed[..], ct_bad[..]);
    assert(!core::ct_eq_bytes(ss_enc[..], ss_rej[..]));
    assert(core::ct_eq_bytes(ss_rej[..], expected_rej[..]));
    print("MLKEM768_CT_BARRETT_AND_FIPS203: OK");
}

// ---- Custom X.509 v3 Ed25519 & RSA-PSS Cert Builders -----------------------

fn encode_ed25519_cert_with_exts<B>(
    issuer_seed: const u8[32]&,
    subj_seed:   const u8[32]&,
    issuer_cn:   const u8[:],
    subject_cn:  const u8[:],
    exts_body:   const u8[:],
    out_der:     B&,
    not_before:  const u8[:] = "240101000000Z",
    not_after:   const u8[:] = "350101000000Z",
) {
    let subj_pub = core::ed25519_public_key(subj_seed);
    var tbs_body: u8[..1600] = [];

    let ver_v3: u8[3] = [0x02, 0x01, 0x02];
    der_append_tlv(tbs_body, 0xA0, ver_v3[..]);
    let ser: u8[2] = [0x01, 0x42];
    der_append_tlv(tbs_body, rfc::ASN1_TAG_INTEGER, ser[..]);

    var ed_alg_inner: u8[..16] = [];
    der_append_tlv(ed_alg_inner, rfc::ASN1_TAG_OID, rfc::OID_ED25519[..]);
    der_append_tlv(tbs_body, rfc::ASN1_TAG_SEQUENCE, ed_alg_inner[..]);

    var iss_dn: u8[..160] = [];
    encode_name_cn(issuer_cn, iss_dn);
    assert(tbs_body.try_append(iss_dn[..]));

    var val_body: u8[..64] = [];
    der_append_tlv(val_body, rfc::ASN1_TAG_UTC_TIME, not_before);
    der_append_tlv(val_body, rfc::ASN1_TAG_UTC_TIME, not_after);
    der_append_tlv(tbs_body, rfc::ASN1_TAG_SEQUENCE, val_body[..]);

    var sub_dn: u8[..160] = [];
    encode_name_cn(subject_cn, sub_dn);
    assert(tbs_body.try_append(sub_dn[..]));

    var spki_body: u8[..64] = [];
    der_append_tlv(spki_body, rfc::ASN1_TAG_SEQUENCE, ed_alg_inner[..]);
    var pk_bits: u8[33] = [0; 33];
    for i in 32 { pk_bits[i + 1] = subj_pub[i]; }
    der_append_tlv(spki_body, rfc::ASN1_TAG_BIT_STRING, pk_bits[..]);
    der_append_tlv(tbs_body, rfc::ASN1_TAG_SEQUENCE, spki_body[..]);

    if exts_body.len > 0 {
        var exts_seq: u8[..800] = [];
        der_wrap(rfc::ASN1_TAG_SEQUENCE, exts_body, exts_seq);
        der_append_tlv(tbs_body, 0xA3, exts_seq[..]);
    }

    var tbs_der: u8[..1700] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, tbs_body[..], tbs_der);
    let sig = core::ed25519_sign(issuer_seed, tbs_der[..]);

    var cert_body: u8[..2048] = [];
    assert(cert_body.try_append(tbs_der[..]));
    der_append_tlv(cert_body, rfc::ASN1_TAG_SEQUENCE, ed_alg_inner[..]);
    var sig_bits: u8[65] = [0; 65];
    for i in 64 { sig_bits[i + 1] = sig[i]; }
    der_append_tlv(cert_body, rfc::ASN1_TAG_BIT_STRING, sig_bits[..]);
    der_wrap(rfc::ASN1_TAG_SEQUENCE, cert_body[..], out_der);
}

fn encode_pss_alg_id<B>(
    hash_oid:     const u8[:],
    mgf_hash_oid: const u8[:],
    salt_len:     u8,
    out_alg:      B&,
) {
    var h_inner: u8[..24] = [];
    der_append_tlv(h_inner, rfc::ASN1_TAG_OID, hash_oid);
    var h_seq: u8[..32] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, h_inner[..], h_seq);

    var mh_inner: u8[..24] = [];
    der_append_tlv(mh_inner, rfc::ASN1_TAG_OID, mgf_hash_oid);
    var mh_seq: u8[..32] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, mh_inner[..], mh_seq);

    var mgf_inner: u8[..64] = [];
    der_append_tlv(mgf_inner, rfc::ASN1_TAG_OID, tls_internal::OID_MGF1[..]);
    assert(mgf_inner.try_append(mh_seq[..]));
    var mgf_seq: u8[..72] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, mgf_inner[..], mgf_seq);

    var pss_body: u8[..128] = [];
    der_append_tlv(pss_body, 0xA0, h_seq[..]);
    der_append_tlv(pss_body, 0xA1, mgf_seq[..]);
    let s_int: u8[3] = [0x02, 0x01, salt_len];
    der_append_tlv(pss_body, 0xA2, s_int[..]);

    var pss_seq: u8[..140] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, pss_body[..], pss_seq);

    var alg_body: u8[..160] = [];
    der_append_tlv(alg_body, rfc::ASN1_TAG_OID, rfc::OID_SIG_RSASSA_PSS[..]);
    assert(alg_body.try_append(pss_seq[..]));
    der_wrap(rfc::ASN1_TAG_SEQUENCE, alg_body[..], out_alg);
}

// ---- 2. RSA >= 2048-bit Enforcement & Strict RSASSA-PSS-params -------------

fn test_rsa_min_2048_and_strict_pss() {
    let e3_be:  u8[1]  = [0x03];
    let salt32: u8[32] = [0x5A; 32];
    let msg = "TLS-1.3-RSA-Hardening-Payload";

    // Weak 1024-bit RSA prime modulus (128 bytes < 256 bytes) MUST be rejected by core & TLS
    var n1024: u8[128] = [0xFF; 128];
    n1024[127] = 0x4D;
    var d1024: u8[128] = [0xAA; 128];
    d1024[127] = 0x33;
    var pk1024_der: u8[..200] = [];
    encode_rsa_pkcs1_pub_der(n1024[..], e3_be[..], pk1024_der);

    var sig1024_pkcs1: u8[..512] = [];
    assert(!core::rsa_pkcs1_sha256_sign(n1024[..], d1024[..], msg, sig1024_pkcs1));
    assert(!core::rsa_pkcs1_sha256_verify_der(pk1024_der[..], msg, n1024[..]));
    assert(
        tls_internal::x509_verify_signature_by_oid(
            rfc::OID_SIG_SHA256_RSA[..], msg, n1024[..], pk1024_der[..], tls::Alert.BadCertificate,
        ) == tls::Alert.BadCertificate,
    );

    var sig1024_pss: u8[..512] = [];
    assert(!core::rsa_pss_sha256_sign(n1024[..], d1024[..], salt32[..], msg, sig1024_pss));
    assert(!core::rsa_pss_sha256_verify_der(pk1024_der[..], msg, n1024[..]));
    assert(
        tls_internal::x509_verify_signature_by_oid(
            rfc::OID_SIG_RSASSA_PSS[..], msg, n1024[..], pk1024_der[..],
            tls::Alert.BadCertificate, tls_internal::PSS_HASH_SHA256,
        ) == tls::Alert.BadCertificate,
    );
    assert(!tls_internal::verify_cv_sig_with_min_rsa(
        rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA256, n1024[..], pk1024_der[..], msg,
    ));

    // Valid 2048-bit RSA prime modulus (256 bytes >= 256 bytes)
    var n2048: u8[256] = [0xFF; 256];
    n2048[253] = 0xE2;
    n2048[254] = 0x5C;
    n2048[255] = 0xEF;
    var d2048: u8[256] = [0xAA; 256];
    d2048[253] = 0x96;
    d2048[254] = 0xE8;
    d2048[255] = 0x9F;
    var pk2048_der: u8[..320] = [];
    encode_rsa_pkcs1_pub_der(n2048[..], e3_be[..], pk2048_der);

    var sig2048_pkcs1: u8[..512] = [];
    assert(core::rsa_pkcs1_sha256_sign(n2048[..], d2048[..], msg, sig2048_pkcs1));
    assert(
        tls_internal::x509_verify_signature_by_oid(
            rfc::OID_SIG_SHA256_RSA[..], msg, sig2048_pkcs1[..], pk2048_der[..], tls::Alert.BadCertificate,
        ) == tls::Alert.CloseNotify,
    );

    var sig2048_pss: u8[..512] = [];
    assert(core::rsa_pss_sha256_sign(n2048[..], d2048[..], salt32[..], msg, sig2048_pss));
    assert(
        tls_internal::x509_verify_signature_by_oid(
            rfc::OID_SIG_RSASSA_PSS[..], msg, sig2048_pss[..], pk2048_der[..],
            tls::Alert.BadCertificate, tls_internal::PSS_HASH_SHA256,
        ) == tls::Alert.CloseNotify,
    );
    // Mismatched RSASSA-PSS hash parameter (SHA-384 param on SHA-256 sig) MUST be rejected!
    assert(
        tls_internal::x509_verify_signature_by_oid(
            rfc::OID_SIG_RSASSA_PSS[..], msg, sig2048_pss[..], pk2048_der[..],
            tls::Alert.BadCertificate, tls_internal::PSS_HASH_SHA384,
        ) == tls::Alert.BadCertificate,
    );
    assert(tls_internal::verify_cv_sig_with_min_rsa(
        rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA256, sig2048_pss[..], pk2048_der[..], msg,
    ));

    // Validate RSASSA-PSS-params parser: SHA-256 accepted; SHA-1, empty, or mismatched MGF1 rejected.
    var pss_alg_ok: u8[..160] = [];
    encode_pss_alg_id(tls_internal::OID_OCSP_SHA256[..], tls_internal::OID_OCSP_SHA256[..], 32, pss_alg_ok);
    var c_ok = core::cursor_from(pss_alg_ok[..]);
    var seq_ok = core::cursor_from(pss_alg_ok[..0]);
    var oid_ok = core::cursor_from(pss_alg_ok[..0]);
    assert(tls::get_asn1_element(c_ok, rfc::ASN1_TAG_SEQUENCE, seq_ok));
    assert(tls::get_asn1_element(seq_ok, rfc::ASN1_TAG_OID, oid_ok));
    let parsed_h, ok_h = tls_internal::parse_rsassa_pss_params(seq_ok);
    assert(ok_h && parsed_h == tls_internal::PSS_HASH_SHA256);

    var pss_alg_sha1: u8[..160] = [];
    encode_pss_alg_id(tls_internal::OID_OCSP_SHA1[..], tls_internal::OID_OCSP_SHA1[..], 20, pss_alg_sha1);
    var c_s1 = core::cursor_from(pss_alg_sha1[..]);
    var seq_s1 = core::cursor_from(pss_alg_sha1[..0]);
    var oid_s1 = core::cursor_from(pss_alg_sha1[..0]);
    assert(tls::get_asn1_element(c_s1, rfc::ASN1_TAG_SEQUENCE, seq_s1));
    assert(tls::get_asn1_element(seq_s1, rfc::ASN1_TAG_OID, oid_s1));
    let _, ok_s1 = tls_internal::parse_rsassa_pss_params(seq_s1);
    assert(!ok_s1);

    var pss_alg_mismatch: u8[..160] = [];
    encode_pss_alg_id(tls_internal::OID_OCSP_SHA256[..], tls_internal::OID_HASH_SHA384[..], 32, pss_alg_mismatch);
    var c_mm = core::cursor_from(pss_alg_mismatch[..]);
    var seq_mm = core::cursor_from(pss_alg_mismatch[..0]);
    var oid_mm = core::cursor_from(pss_alg_mismatch[..0]);
    assert(tls::get_asn1_element(c_mm, rfc::ASN1_TAG_SEQUENCE, seq_mm));
    assert(tls::get_asn1_element(seq_mm, rfc::ASN1_TAG_OID, oid_mm));
    let _, ok_mm = tls_internal::parse_rsassa_pss_params(seq_mm);
    assert(!ok_mm);

    let empty_pss: u8[2] = [0x30, 0x00];
    var c_empty = core::cursor_from(empty_pss[..]);
    let _, ok_empty = tls_internal::parse_rsassa_pss_params(c_empty);
    assert(!ok_empty);

    print("RSA_2048_AND_STRICT_PSS: OK");
}

// ---- 3. Role-Bound EKU Validation & mTLS Client Cert Verification ----------

fn encode_eku_ext_bytes<B>(eku_oid: const u8[:], out: B&) {
    var inner: u8[..32] = [];
    der_append_tlv(inner, rfc::ASN1_TAG_OID, eku_oid);
    var seq: u8[..40] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, inner[..], seq);
    encode_ext_entry(out, rfc::OID_EXT_KEY_USAGE[..], false, seq[..]);
}

fn encode_ca_basic_constraints<B>(out: B&) {
    let bc_true: u8[5] = [0x30, 0x03, 0x01, 0x01, 0xFF];
    encode_ext_entry(out, rfc::OID_BASIC_CONSTRAINTS[..], true, bc_true[..]);
}

fn test_role_bound_eku_and_mtls() {
    let ca_seed:  u8[32] = [0xA1; 32];
    let cli_seed: u8[32] = [0xB2; 32];
    let srv_seed: u8[32] = [0xC3; 32];
    let now_sec:  i64    = 1750000000;

    var ca_exts: u8[..64] = [];
    encode_ca_basic_constraints(ca_exts);
    var ca_der: u8[..2048] = [];
    encode_ed25519_cert_with_exts(ca_seed, ca_seed, "RoleTest Root CA", "RoleTest Root CA", ca_exts[..], ca_der);

    var store = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(store, ca_der[..]));

    // clientAuth-only leaf certificate
    var cli_exts: u8[..64] = [];
    encode_eku_ext_bytes(rfc::OID_EKU_CLIENT_AUTH[..], cli_exts);
    var cli_der: u8[..2048] = [];
    encode_ed25519_cert_with_exts(ca_seed, cli_seed, "RoleTest Root CA", "client.test", cli_exts[..], cli_der);
    var cli_cert = tls::ParsedCert { .. };
    assert(tls::parse_x509_certificate(cli_der[..], cli_cert));

    var cli_chain: tls::ParsedCert[..8] = [];
    var cli_raw:   const u8[:][..8]     = [];
    assert(cli_chain.try_push(cli_cert) && cli_raw.try_push(cli_der[..]));

    // clientAuth-only MUST be rejected for Server (and default), accepted for Client and Any
    assert(tls::verify_certificate_chain(cli_chain, cli_raw, store, now_sec) == tls::Alert.UnsupportedCertificate);
    assert(
        tls::verify_certificate_chain(
            cli_chain, cli_raw, store, now_sec, tls::CertValidationRole.Server,
        ) == tls::Alert.UnsupportedCertificate,
    );
    assert(
        tls::verify_certificate_chain(
            cli_chain, cli_raw, store, now_sec, tls::CertValidationRole.Client,
        ) == tls::Alert.CloseNotify,
    );
    assert(
        tls::verify_certificate_chain(
            cli_chain, cli_raw, store, now_sec, tls::CertValidationRole.Any,
        ) == tls::Alert.CloseNotify,
    );

    // serverAuth-only leaf certificate
    var srv_exts: u8[..64] = [];
    encode_eku_ext_bytes(rfc::OID_EKU_SERVER_AUTH[..], srv_exts);
    var srv_der: u8[..2048] = [];
    encode_ed25519_cert_with_exts(ca_seed, srv_seed, "RoleTest Root CA", "server.test", srv_exts[..], srv_der);
    var srv_cert = tls::ParsedCert { .. };
    assert(tls::parse_x509_certificate(srv_der[..], srv_cert));

    var srv_chain: tls::ParsedCert[..8] = [];
    var srv_raw:   const u8[:][..8]     = [];
    assert(srv_chain.try_push(srv_cert) && srv_raw.try_push(srv_der[..]));

    // serverAuth-only MUST be accepted for Server and Any, rejected for Client
    assert(
        tls::verify_certificate_chain(
            srv_chain, srv_raw, store, now_sec, tls::CertValidationRole.Server,
        ) == tls::Alert.CloseNotify,
    );
    assert(
        tls::verify_certificate_chain(
            srv_chain, srv_raw, store, now_sec, tls::CertValidationRole.Client,
        ) == tls::Alert.UnsupportedCertificate,
    );
    assert(
        tls::verify_certificate_chain(
            srv_chain, srv_raw, store, now_sec, tls::CertValidationRole.Any,
        ) == tls::Alert.CloseNotify,
    );

    // Verify mTLS client Certificate + CertificateVerify rejects serverAuth-only and accepts clientAuth
    let transcript_hash = core::sha256("mtls-transcript");
    var cv_msg: u8[160] = [0; 160];
    let cv_len, ok_cvm = tls::build_certificate_verify_message(false, transcript_hash[..], cv_msg[..]);
    assert(ok_cvm);

    var cli_cert_msg: u8[..4096] = [];
    assert(tls::encode_client_certificate(cli_cert_msg, "", cli_der[..]));
    let cli_sig = core::ed25519_sign(cli_seed, cv_msg[..cv_len]);
    var cli_cv_msg: u8[..256] = [];
    assert(tls::encode_client_certificate_verify(cli_cv_msg, rfc::SIG_SCHEME_ED25519, cli_sig[..]));
    assert(
        tls_internal::verify_client_cert_and_signature(
            cli_cert_msg[..], cli_cv_msg[..], transcript_hash[..], store, now_sec,
        ),
    );

    var srv_cert_msg: u8[..4096] = [];
    assert(tls::encode_client_certificate(srv_cert_msg, "", srv_der[..]));
    let srv_sig = core::ed25519_sign(srv_seed, cv_msg[..cv_len]);
    var srv_cv_msg: u8[..256] = [];
    assert(tls::encode_client_certificate_verify(srv_cv_msg, rfc::SIG_SCHEME_ED25519, srv_sig[..]));
    assert(
        !tls_internal::verify_client_cert_and_signature(
            srv_cert_msg[..], srv_cv_msg[..], transcript_hash[..], store, now_sec,
        ),
    );

    print("ROLE_BOUND_EKU_AND_MTLS: OK");
}

// ---- 4. TrustAnchor NameConstraints Enforcement ----------------------------

fn test_trust_anchor_name_constraints() {
    let root_seed: u8[32] = [0xD4; 32];
    let good_seed: u8[32] = [0xE5; 32];
    let bad_seed:  u8[32] = [0xF6; 32];
    let now_sec:   i64    = 1750000000;

    // Build NameConstraints: SEQUENCE { [0] permittedSubtrees { SEQUENCE { dNSName [2] "allowed.test" } } }
    // (RFC 5280 Section 4.2.1.10 forbids leading periods in dNSName constraints.)
    var subtree_body: u8[..32] = [];
    der_append_tlv(subtree_body, 0x82, "allowed.test");
    var subtree_seq: u8[..40] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, subtree_body[..], subtree_seq);
    var nc_body: u8[..48] = [];
    der_append_tlv(nc_body, 0xA0, subtree_seq[..]);
    var nc_der: u8[..64] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, nc_body[..], nc_der);

    var root_exts: u8[..160] = [];
    encode_ca_basic_constraints(root_exts);
    encode_ext_entry(root_exts, rfc::OID_NAME_CONSTRAINTS[..], true, nc_der[..]);
    var root_der: u8[..2048] = [];
    encode_ed25519_cert_with_exts(root_seed, root_seed, "NC Root CA", "NC Root CA", root_exts[..], root_der);

    var store = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(store, root_der[..]));
    assert(store.anchors.len == 1 && store.anchors[0].has_name_constraints);

    // Leaf 1: SAN "api.allowed.test" (root NOT sent in wire chain!)
    var good_san_body: u8[..64] = [];
    der_append_tlv(good_san_body, 0x82, "api.allowed.test");
    var good_san_seq: u8[..72] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, good_san_body[..], good_san_seq);
    var good_exts: u8[..128] = [];
    encode_ext_entry(good_exts, rfc::OID_SUBJECT_ALT_NAME[..], false, good_san_seq[..]);
    var good_der: u8[..2048] = [];
    encode_ed25519_cert_with_exts(root_seed, good_seed, "NC Root CA", "api.allowed.test", good_exts[..], good_der);
    var good_cert = tls::ParsedCert { .. };
    assert(tls::parse_x509_certificate(good_der[..], good_cert));

    var good_chain: tls::ParsedCert[..8] = [];
    var good_raw:   const u8[:][..8]     = [];
    assert(good_chain.try_push(good_cert) && good_raw.try_push(good_der[..]));
    assert(tls::verify_certificate_chain(good_chain, good_raw, store, now_sec) == tls::Alert.CloseNotify);

    // Leaf 2: SAN "evil.other.test" violates TrustAnchor NameConstraints (root NOT sent in wire chain!)
    var bad_san_body: u8[..64] = [];
    der_append_tlv(bad_san_body, 0x82, "evil.other.test");
    var bad_san_seq: u8[..72] = [];
    der_wrap(rfc::ASN1_TAG_SEQUENCE, bad_san_body[..], bad_san_seq);
    var bad_exts: u8[..128] = [];
    encode_ext_entry(bad_exts, rfc::OID_SUBJECT_ALT_NAME[..], false, bad_san_seq[..]);
    var bad_der: u8[..2048] = [];
    encode_ed25519_cert_with_exts(root_seed, bad_seed, "NC Root CA", "evil.other.test", bad_exts[..], bad_der);
    var bad_cert = tls::ParsedCert { .. };
    assert(tls::parse_x509_certificate(bad_der[..], bad_cert));

    var bad_chain: tls::ParsedCert[..8] = [];
    var bad_raw:   const u8[:][..8]     = [];
    assert(bad_chain.try_push(bad_cert) && bad_raw.try_push(bad_der[..]));
    assert(tls::verify_certificate_chain(bad_chain, bad_raw, store, now_sec) == tls::Alert.BadCertificate);

    print("TRUST_ANCHOR_NAME_CONSTRAINTS: OK");
}

// ---- 5. CRL SHA-256 Serials, 1024 Capacity & MAX_CIPHER_SLOTS=4096 ---------

fn test_crl_sha256_capacity_and_cipher_slots() {
    assert(tls::MAX_CIPHER_SLOTS == 4096);
    assert(tls_internal::MAX_CRL_SERIALS == 1024);

    // 20-byte RFC 5280 serial -> truncated SHA-256 with high bit set (NOT FNV-1a)
    let serial_20b: u8[20] = [
        0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0, 0x11, 0x22,
        0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99, 0xAA, 0xBB, 0xCC,
    ];
    let s20_id, ok_s20 = tls::parse_asn1_serial_u64(serial_20b[..]);
    let expected_h = core::sha256(serial_20b[..]);
    let expected_id = core::read_be_u64(expected_h[..], 0) | 0x8000000000000000;
    assert(ok_s20 && s20_id == expected_id);

    // Leading 0x00 sign pad + 20 significant bytes (21 bytes total) MUST hash the 20 significant bytes
    var serial_21b_padded: u8[21] = [0; 21];
    serial_21b_padded[0] = 0x00;
    serial_21b_padded[1] = 0x80;
    for i in 19 {
        serial_21b_padded[i + 2] = (i + 1) as u8;
    }
    let s21_id, ok_s21 = tls::parse_asn1_serial_u64(serial_21b_padded[..]);
    let exp21_h = core::sha256(serial_21b_padded[1..]);
    let exp21_id = core::read_be_u64(exp21_h[..], 0) | 0x8000000000000000;
    assert(ok_s21 && s21_id == exp21_id && s21_id != s20_id);

    // Insert 1024 serials (> old 128 cap), verify lookups, verify 1025th fails closed
    var crl = tls::ParsedCrl { .. };
    assert(tls_internal::crl_insert_serial(crl, s20_id));
    for i in 1023 {
        let s = (5000 - i) as u64;
        assert(tls_internal::crl_insert_serial(crl, s));
    }
    assert(crl.serial_count == 1024);
    assert(tls::crl_is_revoked(crl, s20_id));
    assert(tls::crl_is_revoked(crl, 5000));
    assert(tls::crl_is_revoked(crl, 3978));
    assert(!tls::crl_is_revoked(crl, 99999));
    assert(!tls_internal::crl_insert_serial(crl, 77777));

    print("CRL_SHA256_1024_AND_SLOTS_4096: OK");
}

// ---- 6. SCT Extension Fail-Closed & Cryptographic verify_sct_signature -----

fn encode_p256_spki_der<B>(pub_uncompressed: const u8[65]&, out_spki: B&) {
    var alg_body: u8[..32] = [];
    der_append_tlv(alg_body, rfc::ASN1_TAG_OID, rfc::OID_EC_PUBLIC_KEY[..]);
    der_append_tlv(alg_body, rfc::ASN1_TAG_OID, rfc::OID_SECP256R1[..]);
    var spki_body: u8[..128] = [];
    der_append_tlv(spki_body, rfc::ASN1_TAG_SEQUENCE, alg_body[..]);
    var pk_bits: u8[66] = [0; 66];
    for i in 65 { pk_bits[i + 1] = pub_uncompressed[i]; }
    der_append_tlv(spki_body, rfc::ASN1_TAG_BIT_STRING, pk_bits[..]);
    der_wrap(rfc::ASN1_TAG_SEQUENCE, spki_body[..], out_spki);
}

fn test_sct_hygiene_and_signature_verify() {
    let seed: u8[32] = [0x55; 32];

    // 6a. Malformed SCT extension inside X.509 cert MUST fail parse_x509_certificate (fail closed)
    let bad_sct_payload: u8[8] = [0x04, 0x06, 0x00, 0x04, 0x00, 0x02, 0xFF, 0xFF];
    var bad_exts: u8[..64] = [];
    encode_ext_entry(bad_exts, rfc::OID_CT_PRECERT_SCTS[..], false, bad_sct_payload[..]);
    var bad_cert_der: u8[..2048] = [];
    encode_ed25519_cert_with_exts(seed, seed, "BadSCT", "BadSCT", bad_exts[..], bad_cert_der);
    var parsed_bad = tls::ParsedCert { .. };
    assert(!tls::parse_x509_certificate(bad_cert_der[..], parsed_bad));

    // 6b. Real RFC 6962 §3.2 ECDSA P-256 SCT signing and verification (X.509 entry & PreCert entry)
    var cert_der: u8[..2048] = [];
    assert(tls::build_test_ed25519_cert_der(seed, "ct.example.test", "ct.example.test", "", cert_der));

    let log_priv: u8[32] = [0x29; 32];
    let log_pub = core::ecdsa_p256_public_key(log_priv);
    var log_spki: u8[..128] = [];
    encode_p256_spki_der(log_pub, log_spki);
    let log_id = core::sha256(log_spki[..]);

    let ts_ms: u64 = 1750000000123;
    var sct_stub = tls::ParsedSct {
        version:      rfc::SCT_VERSION_V1,
        log_id:       log_id,
        timestamp_ms: ts_ms,
        hash_alg:     rfc::SCT_HASH_ALG_SHA256,
        sig_alg:      rfc::SCT_SIG_ALG_ECDSA,
    };
    var signed_x509: u8[..4096] = [];
    assert(tls::build_sct_signed_data(sct_stub, "", cert_der[..], false, signed_x509));
    let raw_ecdsa_sig = core::ecdsa_p256_sign(log_priv, signed_x509[..]);
    var der_ecdsa_sig: u8[..72] = [];
    assert(core::ecdsa_p256_encode_der_sig(raw_ecdsa_sig, der_ecdsa_sig));

    // Assemble SerializedSCT wire bytes and parse with parse_sct_entry
    var raw_sct: u8[..160] = [];
    assert(raw_sct.try_push(rfc::SCT_VERSION_V1));
    assert(raw_sct.try_append(log_id[..]));
    raw_sct.append_u64_be(ts_ms);
    raw_sct.append_u16_be(0); // extensions len = 0
    assert(raw_sct.try_push(rfc::SCT_HASH_ALG_SHA256));
    assert(raw_sct.try_push(rfc::SCT_SIG_ALG_ECDSA));
    raw_sct.append_u16_be(der_ecdsa_sig.len as u16);
    assert(raw_sct.try_append(der_ecdsa_sig[..]));

    var parsed_sct = tls::ParsedSct { .. };
    assert(tls::parse_sct_entry(raw_sct[..], parsed_sct));
    assert(tls::verify_sct_signature(parsed_sct, raw_sct[..], cert_der[..], log_spki[..], false));

    // Tampered certificate or wrong log key MUST fail SCT verification
    var tampered_cert = cert_der;
    tampered_cert[tampered_cert.len - 1] ^= 0x01;
    assert(!tls::verify_sct_signature(parsed_sct, raw_sct[..], tampered_cert[..], log_spki[..], false));

    let wrong_priv: u8[32] = [0x31; 32];
    let wrong_pub = core::ecdsa_p256_public_key(wrong_priv);
    var wrong_spki: u8[..128] = [];
    encode_p256_spki_der(wrong_pub, wrong_spki);
    assert(!tls::verify_sct_signature(parsed_sct, raw_sct[..], cert_der[..], wrong_spki[..], false));

    // PreCert entry verification (is_precert = true with 32-byte issuer_key_hash)
    let issuer_kh = core::sha256("ct-issuer-spki");
    var signed_pre: u8[..4096] = [];
    assert(tls::build_sct_signed_data(sct_stub, "", cert_der[..], true, signed_pre, issuer_kh[..]));
    let pre_raw_sig = core::ecdsa_p256_sign(log_priv, signed_pre[..]);
    var pre_der_sig: u8[..72] = [];
    assert(core::ecdsa_p256_encode_der_sig(pre_raw_sig, pre_der_sig));

    var raw_pre_sct: u8[..160] = [];
    assert(raw_pre_sct.try_push(rfc::SCT_VERSION_V1));
    assert(raw_pre_sct.try_append(log_id[..]));
    raw_pre_sct.append_u64_be(ts_ms);
    raw_pre_sct.append_u16_be(0);
    assert(raw_pre_sct.try_push(rfc::SCT_HASH_ALG_SHA256));
    assert(raw_pre_sct.try_push(rfc::SCT_SIG_ALG_ECDSA));
    raw_pre_sct.append_u16_be(pre_der_sig.len as u16);
    assert(raw_pre_sct.try_append(pre_der_sig[..]));

    var parsed_pre = tls::ParsedSct { .. };
    assert(tls::parse_sct_entry(raw_pre_sct[..], parsed_pre));
    assert(tls::verify_sct_signature(parsed_pre, raw_pre_sct[..], cert_der[..], log_spki[..], true, issuer_kh[..]));
    assert(!tls::verify_sct_signature(parsed_pre, raw_pre_sct[..], cert_der[..], log_spki[..], false));

    // PKI-07: parse_sct_list offsets relative to raw_list, raw key rejected, future timestamp rejected.
    var sct_list_wire: u8[..200] = [];
    sct_list_wire.append_u16_be((raw_sct.len + 2) as u16);
    sct_list_wire.append_u16_be(raw_sct.len as u16);
    assert(sct_list_wire.try_append(raw_sct[..]));
    var scts_from_list: tls::ParsedSct[..8] = [];
    assert(tls::parse_sct_list(sct_list_wire[..], scts_from_list) && scts_from_list.len == 1);
    assert(tls::verify_sct_signature(scts_from_list[0], sct_list_wire[..], cert_der[..], log_spki[..], false, "", ts_ms));
    assert(!tls::verify_sct_signature(scts_from_list[0], sct_list_wire[..], cert_der[..], log_spki[..], false, "", ts_ms - 1));
    assert(!tls::verify_sct_signature(scts_from_list[0], sct_list_wire[..], cert_der[..], log_pub[..], false));

    print("SCT_HYGIENE_AND_VERIFY: OK");
}

fn test_wave3_pki_audit_regressions() {
    // PKI-03: Unbracketed IPv6 literal ("fd00::1") MUST NOT be accepted as URI SAN or match URI SAN.
    let v6_uri_san = tls::SanEntry { san_type: tls::SanType.Uri, val: "fd00::1" };
    assert(!tls::match_san(v6_uri_san, "fd00::1"));

    // PKI-04: Excluded URI & Email NameConstraints fail closed on userinfo, IPv4, non-canonical IPv6, dots, quoted @.
    var nc_uri_ex: tls::NameConstraintEntry[..16] = [];
    assert(nc_uri_ex.try_push(tls::NameConstraintEntry { san_type: tls::SanType.Uri, is_excluded: true, val: "evil.com" }));
    let u_userinfo = tls::SanEntry { san_type: tls::SanType.Uri, val: "https://user@evil.com/" };
    let u_ip4 = tls::SanEntry { san_type: tls::SanType.Uri, val: "https://127.0.0.1/" };
    assert(!tls::check_name_constraints(nc_uri_ex, u_userinfo));
    assert(!tls::check_name_constraints(nc_uri_ex, u_ip4));

    var nc_v6_ex: tls::NameConstraintEntry[..16] = [];
    assert(nc_v6_ex.try_push(tls::NameConstraintEntry { san_type: tls::SanType.Uri, is_excluded: true, val: "[2001:db8::1]" }));
    let u_v6 = tls::SanEntry { san_type: tls::SanType.Uri, val: "https://[2001:0db8::1]/" };
    assert(!tls::check_name_constraints(nc_v6_ex, u_v6));

    var nc_email_ex: tls::NameConstraintEntry[..16] = [];
    assert(nc_email_ex.try_push(tls::NameConstraintEntry { san_type: tls::SanType.Email, is_excluded: true, val: "evil.com" }));
    let e_dot = tls::SanEntry { san_type: tls::SanType.Email, val: "admin@evil.com." };
    let e_quoted = tls::SanEntry { san_type: tls::SanType.Email, val: "\"a@b\"@evil.com" };
    assert(!tls::check_name_constraints(nc_email_ex, e_dot));
    assert(!tls::check_name_constraints(nc_email_ex, e_quoted));

    // PKI-02: Subject DN checked against directoryName NameConstraints with RFC 5280 §7.1 canonicalization.
    var dn_upper: u8[..160] = [];
    encode_name_cn("  FORBIDDEN   CORP ", dn_upper);
    var dn_lower: u8[..160] = [];
    encode_name_cn("forbidden corp", dn_lower);
    assert(tls_internal::match_dn_name_constraint(dn_upper[..], dn_lower[..]));

    // PKI-09: Multi-byte high-tag-number (0x9F) MUST be rejected by get_any_asn1_element.
    let high_tag: u8[4] = [0x9F, 0x20, 0x01, 0x00];
    var c_ht = core::cursor_from(high_tag[..]);
    var out_t: u8 = 0;
    var out_v = core::cursor_from(high_tag[..0]);
    assert(!tls::get_any_asn1_element(c_ht, out_t, out_v));

    // PKI-13: Leading-zero IPv4 literal and mid-line PEM boundary rejected.
    var ip4: u8[4] = [0; 4];
    assert(!tls_internal::parse_ipv4_literal("010.0.0.1", ip4));
    assert(tls_internal::parse_ipv4_literal("10.0.0.1", ip4));

    let spoofed_pem = "comment -----BEGIN CERTIFICATE-----\nAQID\n-----END CERTIFICATE-----\n";
    var p_idx: i64       = 0;
    var p_lbl: u8[..64]  = [];
    var p_der: u8[..128] = [];
    assert(!tls::pem_next_block(spoofed_pem, p_idx, p_lbl, p_der));

    print("WAVE3_PKI_AUDIT_REGRESSIONS: OK");
}

fn test_bounded_expired_leaf_grace() {
    let root_seed: u8[32] = [0x31; 32];
    let int_seed:  u8[32] = [0x32; 32];
    let leaf_seed: u8[32] = [0x33; 32];

    var ca_exts: u8[..64] = [];
    encode_ca_basic_constraints(ca_exts);
    var root_der: u8[..2048] = [];
    encode_ed25519_cert_with_exts(root_seed, root_seed, "Grace Root CA", "Grace Root CA", ca_exts[..], root_der);

    var store = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(store, root_der[..]));

    // Leaf expires 2026-01-01 00:00:00Z
    var leaf_der: u8[..2048] = [];
    encode_ed25519_cert_with_exts(
        root_seed, leaf_seed, "Grace Root CA", "leaf.example", "", leaf_der, "240101000000Z", "260101000000Z",
    );
    var leaf_cert = tls::ParsedCert { .. };
    assert(tls::parse_x509_certificate(leaf_der[..], leaf_cert));

    var chain: tls::ParsedCert[..8] = [];
    var raw:   const u8[:][..8]     = [];
    assert(chain.try_push(leaf_cert) && raw.try_push(leaf_der[..]));

    let now_1d = leaf_cert.validity_not_after + 86400;
    let now_10d = leaf_cert.validity_not_after + 864000;
    let now_35d = leaf_cert.validity_not_after + 3024000;
    let grace_7d: i64 = 604800;

    // Default (grace = 0) stays strictly RFC 5280 compliant.
    assert(tls::verify_certificate_chain(chain, raw, store, now_1d) == tls::Alert.CertificateExpired);
    // Bounded grace accepts recently expired leaf, rejects beyond grace and beyond 30-day hard cap.
    assert(
        tls::verify_certificate_chain(chain, raw, store, now_1d, tls::CertValidationRole.Server, grace_7d) ==
            tls::Alert.CloseNotify,
    );
    assert(
        tls::verify_certificate_chain(chain, raw, store, now_10d, tls::CertValidationRole.Server, grace_7d) ==
            tls::Alert.CertificateExpired,
    );
    assert(
        tls::verify_certificate_chain(chain, raw, store, now_35d, tls::CertValidationRole.Server, 7776000) ==
            tls::Alert.CertificateExpired,
    );
    // Future notBefore is NEVER waived by expired-leaf grace.
    assert(
        tls::verify_certificate_chain(
            chain, raw, store, leaf_cert.validity_not_before - 1, tls::CertValidationRole.Server, grace_7d,
        ) == tls::Alert.CertificateExpired,
    );

    // Expired intermediate CA is NEVER waived by expired-leaf grace.
    var int_der: u8[..2048] = [];
    encode_ed25519_cert_with_exts(
        root_seed, int_seed, "Grace Root CA", "Expired Inter CA", ca_exts[..], int_der, "240101000000Z", "260101000000Z",
    );
    var leaf2_der: u8[..2048] = [];
    encode_ed25519_cert_with_exts(
        int_seed, leaf_seed, "Expired Inter CA", "leaf2.example", "", leaf2_der, "240101000000Z", "350101000000Z",
    );
    var int_cert = tls::ParsedCert { .. };
    var leaf2_cert = tls::ParsedCert { .. };
    assert(tls::parse_x509_certificate(int_der[..], int_cert));
    assert(tls::parse_x509_certificate(leaf2_der[..], leaf2_cert));

    var chain2: tls::ParsedCert[..8] = [];
    var raw2:   const u8[:][..8]     = [];
    assert(chain2.try_push(leaf2_cert) && chain2.try_push(int_cert));
    assert(raw2.try_push(leaf2_der[..]) && raw2.try_push(int_der[..]));
    assert(
        tls::verify_certificate_chain(chain2, raw2, store, now_1d, tls::CertValidationRole.Server, grace_7d) ==
            tls::Alert.CertificateExpired,
    );

    var sess = client::new_session();
    client::set_tls_expired_leaf_grace_sec(sess, -5);
    assert(sess.tls_expired_leaf_grace_sec == 0);
    client::set_tls_expired_leaf_grace_sec(sess, grace_7d);
    assert(sess.tls_expired_leaf_grace_sec == grace_7d);
    client::set_tls_expired_leaf_grace_sec(sess, 7776000);
    assert(sess.tls_expired_leaf_grace_sec == tls::MAX_EXPIRED_LEAF_GRACE_SEC);

    print("BOUNDED_EXPIRED_LEAF_GRACE: OK");
}

// CHECK: MLKEM768_CT_BARRETT_AND_FIPS203: OK
// CHECK: RSA_2048_AND_STRICT_PSS: OK
// CHECK: ROLE_BOUND_EKU_AND_MTLS: OK
// CHECK: TRUST_ANCHOR_NAME_CONSTRAINTS: OK
// CHECK: CRL_SHA256_1024_AND_SLOTS_4096: OK
// CHECK: SCT_HYGIENE_AND_VERIFY: OK
// CHECK: WAVE3_PKI_AUDIT_REGRESSIONS: OK
// CHECK: BOUNDED_EXPIRED_LEAF_GRACE: OK
fn main() {
    test_mlkem_barrett_and_compress_exactness();
    test_rsa_min_2048_and_strict_pss();
    test_role_bound_eku_and_mtls();
    test_trust_anchor_name_constraints();
    test_crl_sha256_capacity_and_cipher_slots();
    test_sct_hygiene_and_signature_verify();
    test_wave3_pki_audit_regressions();
    test_bounded_expired_leaf_grace();
}
