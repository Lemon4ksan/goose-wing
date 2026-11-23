// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal X.509 signature algorithm validation, SPKI extraction, and PKCS#8/SEC1 key parsers.
namespace tls_internal;

import std;
import core;
import .internal;
import .asn1;
import .record;
import .types;

// Parses a HashAlgorithm AlgorithmIdentifier inside RSASSA-PSS-params (RFC 4055 Section 3.1).
// Rejects SHA-1 and unknown digests; accepts SHA-256, SHA-384, or SHA-512 with omitted or NULL params.
//
// Example:
//   cur = SEQUENCE { OID(SHA-256), NULL }
//   returns: PSS_HASH_SHA256, ok = true
fn parse_pss_hash_alg_id(cur: core::ByteCursor&) -> u8, bool {
    var alg_seq = core::cursor_from(cur.buf[..0]);
    var oid = core::cursor_from(cur.buf[..0]);
    guard tls::get_asn1_element(cur, rfc::ASN1_TAG_SEQUENCE, alg_seq) &&
        tls::get_asn1_element(alg_seq, rfc::ASN1_TAG_OID, oid) else {
        return PSS_HASH_NONE, false;
    }
    if alg_seq.cursor_len() > 0 {
        var null_el = core::cursor_from(alg_seq.buf[..0]);
        guard tls::get_asn1_element(alg_seq, rfc::ASN1_TAG_NULL, null_el) &&
            null_el.cursor_len() == 0 && alg_seq.cursor_len() == 0 else {
            return PSS_HASH_NONE, false;
        }
    }
    if oid.buf == OID_OCSP_SHA256[..] { return PSS_HASH_SHA256, true; }
    if oid.buf == OID_HASH_SHA384[..] { return PSS_HASH_SHA384, true; }
    if oid.buf == OID_HASH_SHA512[..] { return PSS_HASH_SHA512, true; }
    return PSS_HASH_NONE, false;
}

// Parses RFC 4055 Section 3.1 `RSASSA-PSS-params` SEQUENCE and enforces matched MGF1 and saltLength.
// Rejects omitted parameters or default SHA-1 hash/MGF1 parameters.
//
// Example:
//   sig_alg_rem = SEQUENCE { [0] SHA-256, [1] MGF1(SHA-256), [2] 32 }
//   returns: PSS_HASH_SHA256, ok = true
fn parse_rsassa_pss_params(sig_alg_rem: core::ByteCursor&) -> u8, bool {
    var pss_seq = core::cursor_from(sig_alg_rem.buf[..0]);
    guard tls::get_asn1_element(sig_alg_rem, rfc::ASN1_TAG_SEQUENCE, pss_seq) &&
        sig_alg_rem.cursor_len() == 0 else {
        return PSS_HASH_NONE, false;
    }

    var hash_ctx = core::cursor_from(pss_seq.buf[..0]);
    guard tls::get_asn1_element(pss_seq, 0xA0, hash_ctx) else { return PSS_HASH_NONE, false; }
    let hash_id, ok_h = parse_pss_hash_alg_id(hash_ctx);
    guard ok_h && hash_ctx.cursor_len() == 0 else { return PSS_HASH_NONE, false; }

    var mgf_ctx = core::cursor_from(pss_seq.buf[..0]);
    var mgf_seq = core::cursor_from(pss_seq.buf[..0]);
    var mgf_oid = core::cursor_from(pss_seq.buf[..0]);
    guard tls::get_asn1_element(pss_seq, 0xA1, mgf_ctx) &&
        tls::get_asn1_element(mgf_ctx, rfc::ASN1_TAG_SEQUENCE, mgf_seq) &&
        mgf_ctx.cursor_len() == 0 &&
        tls::get_asn1_element(mgf_seq, rfc::ASN1_TAG_OID, mgf_oid) &&
        mgf_oid.buf == OID_MGF1[..] else {
        return PSS_HASH_NONE, false;
    }
    let mgf_hash_id, ok_mh = parse_pss_hash_alg_id(mgf_seq);
    guard ok_mh && mgf_seq.cursor_len() == 0 && mgf_hash_id == hash_id else {
        return PSS_HASH_NONE, false;
    }

    var salt_ctx = core::cursor_from(pss_seq.buf[..0]);
    var salt_len: i64 = 0;
    guard tls::get_asn1_element(pss_seq, 0xA2, salt_ctx) &&
        tls::get_asn1_integer(salt_ctx, salt_len) &&
        salt_ctx.cursor_len() == 0 &&
        salt_len == pss_expected_salt_len(hash_id) else {
        return PSS_HASH_NONE, false;
    }

    if pss_seq.cursor_len() > 0 {
        var tr_ctx = core::cursor_from(pss_seq.buf[..0]);
        var trailer: i64 = 0;
        guard tls::get_asn1_element(pss_seq, 0xA3, tr_ctx) &&
            tls::get_asn1_integer(tr_ctx, trailer) &&
            tr_ctx.cursor_len() == 0 &&
            trailer == 1 else {
            return PSS_HASH_NONE, false;
        }
    }
    guard pss_seq.cursor_len() == 0 else { return PSS_HASH_NONE, false; }
    return hash_id, true;
}

// RFC 5280 Section 4.1.1.2: signatureAlgorithm - Validates AlgorithmIdentifier parameters by OID.
fn validate_x509_sig_alg_params(
    sig_oid:      const u8[:],
    sig_alg_rem:  core::ByteCursor&,
    out_pss_hash: u8&,
) -> bool {
    out_pss_hash = PSS_HASH_NONE;
    if sig_oid == rfc::OID_SIG_RSASSA_PSS[..] {
        let pss_hash, ok_pss = parse_rsassa_pss_params(sig_alg_rem);
        guard ok_pss else { return false; }
        out_pss_hash = pss_hash;
        return true;
    }
    if sig_oid == rfc::OID_ED25519[..] ||
        sig_oid == rfc::OID_SIG_ECDSA_SHA256[..] ||
        sig_oid == rfc::OID_SIG_ECDSA_SHA384[..] {
        return sig_alg_rem.cursor_len() == 0;
    }
    if sig_alg_rem.cursor_len() == 0 {
        return true;
    }
    var param_tag: u8 = 0;
    var param_val = core::cursor_from(sig_alg_rem.buf[..0]);
    guard tls::get_any_asn1_element(sig_alg_rem, param_tag, param_val) && sig_alg_rem.cursor_len() == 0 else {
        return false;
    }
    if sig_oid == rfc::OID_SIG_SHA256_RSA[..] || sig_oid == rfc::OID_SIG_SHA384_RSA[..] {
        return param_tag == rfc::ASN1_TAG_NULL && param_val.cursor_len() == 0;
    }
    return true;
}

fn validate_x509_spki_alg_params(
    spki_oid:     const u8[:],
    spki_alg:     core::ByteCursor&,
    spki_alg_end: i64,
    out_alg_span: tls::Span16&,
) -> bool {
    guard spki_oid.len > 0 else { return false; }
    // RFC 5480 Section 2.1.1: Named curve OIDs are only valid as parameters to id-ecPublicKey, never bare SPKI OIDs.
    if spki_oid == rfc::OID_SECP256R1[..] || spki_oid == rfc::OID_SECP384R1[..] {
        return false;
    }
    if spki_oid == rfc::OID_EC_PUBLIC_KEY[..] {
        var spki_curve = core::cursor_from(spki_oid[..0]);
        guard tls::get_asn1_element(spki_alg, rfc::ASN1_TAG_OID, spki_curve) &&
            spki_curve.buf.len > 0 &&
            spki_alg.cursor_len() == 0 else {
            return false;
        }
        out_alg_span = tls::span_from_end(spki_alg_end, spki_alg.cursor_len(), spki_curve.buf.len);
        return true;
    }
    out_alg_span = tls::span_from_end(spki_alg_end, spki_alg.cursor_len(), spki_oid.len);
    if spki_oid == rfc::OID_ED25519[..] {
        return spki_alg.cursor_len() == 0;
    }
    if spki_oid == rfc::OID_RSA_ENCRYPTION[..] {
        guard spki_alg.cursor_len() > 0 else { return true; }
        var null_el = core::cursor_from(spki_oid[..0]);
        return tls::get_asn1_element(spki_alg, rfc::ASN1_TAG_NULL, null_el) &&
            null_el.cursor_len() == 0 &&
            spki_alg.cursor_len() == 0;
    }
    return true;
}

inline fn x509_check_cert_spki_policy(cert: const tls::ParsedCert&, raw_cert: const u8[:]) -> bool {
    let spki_oid = tls::span_slice(raw_cert, cert.spki_alg_oid);
    guard spki_oid.len > 0 else { return false; }
    if spki_oid == rfc::OID_RSA_ENCRYPTION[..] {
        var spki_pk = tls::span_slice(raw_cert, cert.spki_pubkey);
        if spki_pk.len >= 2 && spki_pk[0] == 0 {
            spki_pk = spki_pk[1..];
        }
        return is_valid_rsa_pubkey_min_bits(spki_pk);
    }
    return spki_oid == rfc::OID_SECP256R1[..] ||
        spki_oid == rfc::OID_SECP384R1[..] ||
        spki_oid == rfc::OID_ED25519[..];
}

// Extracts raw public key bytes from DER SubjectPublicKeyInfo or raw key material.
//
// Example:
//   spki_raw = DER SEQUENCE(AlgId, BIT STRING(0x00 || pubkey))
//   returns: true, out_pk = pubkey
fn extract_spki_pubkey_material(spki_raw: const u8[:], out_pk: u8[..600]&) -> bool {
    var committed = false;
    defer if !committed { out_pk.clear(); };
    guard spki_raw.len > 0 && spki_raw[0] == rfc::ASN1_TAG_SEQUENCE else {
        guard out_pk.try_set(spki_raw) else { return false; }
        committed = true;
        return true;
    }
    var top = core::cursor_from(spki_raw);
    var spki = core::cursor_from(spki_raw[..0]);
    var spki_alg = core::cursor_from(spki_raw[..0]);
    var spki_pk = core::cursor_from(spki_raw[..0]);
    guard tls::get_asn1_element(top, rfc::ASN1_TAG_SEQUENCE, spki) && top.cursor_len() == 0 else { return false; }
    guard tls::get_asn1_element(spki, rfc::ASN1_TAG_SEQUENCE, spki_alg) else { return false; }
    guard tls::get_asn1_element(spki, rfc::ASN1_TAG_BIT_STRING, spki_pk) &&
        spki.cursor_len() == 0 &&
        tls::validate_asn1_bit_string(spki_pk.buf) &&
        spki_pk.buf.len >= 2 &&
        spki_pk.buf[0] == 0 else {
        return false;
    }
    guard out_pk.try_set(spki_pk.buf[1..]) else { return false; }
    committed = true;
    return true;
}

// Extracts the RSASSA-PSS hash identifier from a DER TBSCertificate SEQUENCE
// when a caller invokes `x509_verify_signature_by_oid` without an explicit `pss_hash_id`.
//
// Example:
//   tbs_data = DER SEQUENCE { [0] v3, INTEGER serial, SEQUENCE { OID_SIG_RSASSA_PSS, params }, ... }
//   returns: PSS_HASH_SHA256 (or PSS_HASH_NONE if absent/invalid)
fn extract_tbs_pss_hash_id(tbs_data: const u8[:]) -> u8 {
    guard tbs_data.len > 0 && tbs_data[0] == rfc::ASN1_TAG_SEQUENCE else { return PSS_HASH_NONE; }
    var c = core::cursor_from(tbs_data);
    var tbs_seq = core::cursor_from(tbs_data[..0]);
    guard tls::get_asn1_element(c, rfc::ASN1_TAG_SEQUENCE, tbs_seq) && c.cursor_len() == 0 else {
        return PSS_HASH_NONE;
    }
    if tbs_seq.cursor_len() > 0 && tbs_seq.buf[0] == 0xA0 {
        var ver_el = core::cursor_from(tbs_seq.buf[..0]);
        guard tls::get_asn1_element(tbs_seq, 0xA0, ver_el) else { return PSS_HASH_NONE; }
    }
    var serial = core::cursor_from(tbs_seq.buf[..0]);
    var sig_alg = core::cursor_from(tbs_seq.buf[..0]);
    var sig_oid = core::cursor_from(tbs_seq.buf[..0]);
    guard tls::get_asn1_element(tbs_seq, rfc::ASN1_TAG_INTEGER, serial) &&
        tls::get_asn1_element(tbs_seq, rfc::ASN1_TAG_SEQUENCE, sig_alg) &&
        tls::get_asn1_element(sig_alg, rfc::ASN1_TAG_OID, sig_oid) &&
        sig_oid.buf == rfc::OID_SIG_RSASSA_PSS[..] else {
        return PSS_HASH_NONE;
    }
    let pss_hash, ok_pss = parse_rsassa_pss_params(sig_alg);
    return if ok_pss { pss_hash } else { PSS_HASH_NONE };
}

inline fn x509_verify_rsa_pss_by_hash(
    n_be:      const u8[:],
    e_be:      const u8[:],
    tbs_data:  const u8[:],
    sig_bytes: const u8[:],
    eff_hash:  u8,
) -> bool {
    if eff_hash == PSS_HASH_SHA256 {
        return core::rsa_pss_sha256_verify(n_be, e_be, tbs_data, sig_bytes);
    }
    if eff_hash == PSS_HASH_SHA384 {
        return core::rsa_pss_sha384_verify(n_be, e_be, tbs_data, sig_bytes);
    }
    if eff_hash == PSS_HASH_SHA512 {
        return core::rsa_pss_sha512_verify(n_be, e_be, tbs_data, sig_bytes);
    }
    return false;
}

fn x509_verify_rsa_signature(
    sig_oid:       const u8[:],
    tbs_data:      const u8[:],
    sig_bytes:     const u8[:],
    parent_pubkey: const u8[:],
    err_alert:     tls::Alert,
    pss_hash_id:   u8,
) -> tls::Alert {
    let n_be, e_be, ok_rsa = core::parse_rsa_public_key_der(parent_pubkey);
    guard ok_rsa && n_be.len >= MIN_RSA_MODULUS_BYTES else {
        return err_alert;
    }
    if sig_oid == rfc::OID_SIG_SHA256_RSA[..] {
        guard core::rsa_pkcs1_sha256_verify(n_be, e_be, tbs_data, sig_bytes) else {
            return err_alert;
        }
        return tls::Alert.CloseNotify;
    }
    if sig_oid == rfc::OID_SIG_SHA384_RSA[..] {
        guard core::rsa_pkcs1_sha384_verify(n_be, e_be, tbs_data, sig_bytes) else {
            return err_alert;
        }
        return tls::Alert.CloseNotify;
    }
    let eff_hash = if pss_hash_id != PSS_HASH_NONE { pss_hash_id } else { extract_tbs_pss_hash_id(tbs_data) };
    guard x509_verify_rsa_pss_by_hash(n_be, e_be, tbs_data, sig_bytes, eff_hash) else {
        return err_alert;
    }
    return tls::Alert.CloseNotify;
}

fn x509_verify_signature_by_oid(
    sig_oid:       const u8[:],
    tbs_data:      const u8[:],
    sig_bytes:     const u8[:],
    parent_pubkey: const u8[:],
    err_alert:     tls::Alert,
    pss_hash_id:   u8 = PSS_HASH_NONE,
) -> tls::Alert {
    if sig_oid == rfc::OID_ED25519[..] {
        guard parent_pubkey.len == 32 && sig_bytes.len == 64 else {
            return err_alert;
        }
        var pub_arr: u8[32] = [0; 32];
        for k in 32 { pub_arr[k] = parent_pubkey[k]; }
        var sig_arr: u8[64] = [0; 64];
        for k in 64 { sig_arr[k] = sig_bytes[k]; }

        guard core::ed25519_verify(pub_arr, tbs_data, sig_arr) else {
            return err_alert;
        }
        return tls::Alert.CloseNotify;
    }

    if sig_oid == rfc::OID_SIG_ECDSA_SHA256[..] {
        guard core::ecdsa_p256_verify_der(parent_pubkey, tbs_data, sig_bytes) else {
            return err_alert;
        }
        return tls::Alert.CloseNotify;
    }

    if sig_oid == rfc::OID_SIG_ECDSA_SHA384[..] {
        guard core::ecdsa_p384_verify_der(parent_pubkey, tbs_data, sig_bytes) else {
            return err_alert;
        }
        return tls::Alert.CloseNotify;
    }

    if sig_oid == rfc::OID_SIG_SHA256_RSA[..] ||
        sig_oid == rfc::OID_SIG_SHA384_RSA[..] ||
        sig_oid == rfc::OID_SIG_RSASSA_PSS[..] {
        return x509_verify_rsa_signature(sig_oid, tbs_data, sig_bytes, parent_pubkey, err_alert, pss_hash_id);
    }

    return tls::Alert.UnsupportedCertificate;
}

inline fn sec1_check_curve_oid(ec_seq: core::ByteCursor&, der_ref: const u8[:]) -> bool {
    if ec_seq.cursor_len() > 0 && ec_seq.buf[0] == 0xA0 {
        var opt_params = core::cursor_from(der_ref[..0]);
        var curve_oid = core::cursor_from(der_ref[..0]);
        guard tls::get_asn1_element(ec_seq, 0xA0, opt_params)
            && tls::get_asn1_element(opt_params, rfc::ASN1_TAG_OID, curve_oid)
            && opt_params.cursor_len() == 0
            && curve_oid.buf == rfc::OID_SECP256R1[..] else {
            return false;
        }
    }
    if ec_seq.cursor_len() > 0 && ec_seq.buf[0] == 0xA1 {
        var opt_pub = core::cursor_from(der_ref[..0]);
        var pub_bits = core::cursor_from(der_ref[..0]);
        var unused: u8 = 0;
        guard tls::get_asn1_element(ec_seq, 0xA1, opt_pub)
            && tls::get_asn1_bit_string(opt_pub, pub_bits, unused)
            && unused == 0
            && opt_pub.cursor_len() == 0 else {
            return false;
        }
    }
    return ec_seq.cursor_len() == 0;
}

// Parses an unencrypted SEC 1 `ECPrivateKey` DER sequence for P-256 (RFC 5915 Section 3).
// Zeroizes `out_key` on failure.
//
// Example:
//   der = [0x30, 0x31, 0x02, 0x01, 0x01, 0x04, 0x20, ...]
//   returns: ok = true, out_key = <32-byte scalar>
fn parse_sec1_ec_private_key_der(der: const u8[:], out_key: u8[32]&) -> bool {
    var committed = false;
    defer if !committed { core::secure_zeroize_32(out_key); };

    var root = core::cursor_from(der);
    var ec_seq = core::cursor_from(der[..0]);
    guard tls::get_asn1_element(root, rfc::ASN1_TAG_SEQUENCE, ec_seq) && root.cursor_len() == 0 else {
        return false;
    }

    var version: i64 = -1;
    guard tls::get_asn1_integer(ec_seq, version) && version == 1 else { return false; }

    var priv_oct = core::cursor_from(der[..0]);
    guard tls::get_asn1_element(ec_seq, rfc::ASN1_TAG_OCTET_STRING, priv_oct) else { return false; }
    guard is_valid_p256_scalar(priv_oct.buf) else { return false; }
    guard sec1_check_curve_oid(ec_seq, der) else { return false; }

    for i in 32 {
        out_key[i] = priv_oct.buf[i];
    }
    committed = true;
    return true;
}

inline fn pki_check_optional_tail(pki_seq: core::ByteCursor&) -> bool {
    if pki_seq.cursor_len() > 0 && pki_seq.buf[0] == 0xA0 {
        var attrs = core::cursor_from(pki_seq.buf[..0]);
        guard tls::get_asn1_element(pki_seq, 0xA0, attrs) else { return false; }
    }
    if pki_seq.cursor_len() > 0 && pki_seq.buf[0] == 0x81 {
        var pub_im = core::cursor_from(pki_seq.buf[..0]);
        guard tls::get_asn1_element(pki_seq, 0x81, pub_im)
            && tls::validate_asn1_bit_string(pub_im.buf)
            && pub_im.buf[0] == 0 else {
            return false;
        }
    }
    return pki_seq.cursor_len() == 0;
}

inline fn pkcs8_extract_ed25519(
    alg_seq:  core::ByteCursor&,
    priv_oct: core::ByteCursor&,
    out_key:  u8[32]&,
) -> bool {
    guard alg_seq.cursor_len() == 0 else { return false; }
    var curve_key = core::cursor_from(priv_oct.buf[..0]);
    guard tls::get_asn1_element(priv_oct, rfc::ASN1_TAG_OCTET_STRING, curve_key)
        && priv_oct.cursor_len() == 0
        && curve_key.buf.len == 32 else {
        return false;
    }
    for i in 32 {
        out_key[i] = curve_key.buf[i];
    }
    return true;
}

inline fn pkcs8_extract_p256(
    alg_seq:  core::ByteCursor&,
    priv_oct: core::ByteCursor&,
    out_key:  u8[32]&,
) -> bool {
    var curve_oid = core::cursor_from(alg_seq.buf[..0]);
    guard tls::get_asn1_element(alg_seq, rfc::ASN1_TAG_OID, curve_oid)
        && alg_seq.cursor_len() == 0
        && curve_oid.buf == rfc::OID_SECP256R1[..] else {
        return false;
    }
    return parse_sec1_ec_private_key_der(priv_oct.buf, out_key);
}

// Parses an unencrypted PKCS#8 `PrivateKeyInfo` DER sequence (RFC 5208 / RFC 5958 / RFC 8410).
// Supports Ed25519 and ECDSA P-256 keys. Zeroizes `out_key` on failure.
//
// Example:
//   der = [0x30, 0x2E, 0x02, 0x01, 0x00, 0x30, 0x05, 0x06, 0x03, 0x2B, 0x65, 0x70, 0x04, 0x22, 0x04, 0x20, ...]
//   returns: kind = PrivateKeyKind.Ed25519, ok = true
fn parse_pkcs8_private_key_der(der: const u8[:], out_key: u8[32]&) -> tls::PrivateKeyKind, bool {
    var committed = false;
    defer if !committed { core::secure_zeroize_32(out_key); };

    var root = core::cursor_from(der);
    var pki_seq = core::cursor_from(der[..0]);
    guard tls::get_asn1_element(root, rfc::ASN1_TAG_SEQUENCE, pki_seq) && root.cursor_len() == 0 else {
        return tls::PrivateKeyKind.Unknown, false;
    }

    var version: i64 = -1;
    guard tls::get_asn1_integer(pki_seq, version) && version == 0 else {
        return tls::PrivateKeyKind.Unknown, false;
    }

    var alg_seq = core::cursor_from(der[..0]);
    var alg_oid = core::cursor_from(der[..0]);
    var priv_oct = core::cursor_from(der[..0]);
    guard tls::get_asn1_element(pki_seq, rfc::ASN1_TAG_SEQUENCE, alg_seq)
        && tls::get_asn1_element(alg_seq, rfc::ASN1_TAG_OID, alg_oid)
        && tls::get_asn1_element(pki_seq, rfc::ASN1_TAG_OCTET_STRING, priv_oct)
        && pki_check_optional_tail(pki_seq) else {
        return tls::PrivateKeyKind.Unknown, false;
    }

    if alg_oid.buf == rfc::OID_ED25519[..] {
        guard pkcs8_extract_ed25519(alg_seq, priv_oct, out_key) else {
            return tls::PrivateKeyKind.Unknown, false;
        }
        committed = true;
        return tls::PrivateKeyKind.Ed25519, true;
    }

    if alg_oid.buf == rfc::OID_EC_PUBLIC_KEY[..] {
        guard pkcs8_extract_p256(alg_seq, priv_oct, out_key) else {
            return tls::PrivateKeyKind.Unknown, false;
        }
        committed = true;
        return tls::PrivateKeyKind.EcdsaP256, true;
    }

    return tls::PrivateKeyKind.Unknown, false;
}
