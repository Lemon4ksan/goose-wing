// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal X.509 DER, extension, SPKI, OCSP, CRL, and PKCS#8/SEC1 parsing helpers.
namespace tls_internal;

import std;
import core;
import .internal;
import .asn1;
import .record;
import .types;
import .sct;

inline fn is_known_pki_extension_oid(oid: const u8[:]) -> bool {
    return oid == rfc::OID_EXT_KEY_USAGE[..] ||
        oid == rfc::OID_TLS_FEATURE[..] ||
        oid == rfc::OID_CT_PRECERT_SCTS[..];
}

// id-at-commonName (2.5.4.3): 55 04 03
inline fn is_known_extension_oid(oid: const u8[:]) -> bool {
    if oid == rfc::OID_BASIC_CONSTRAINTS[..] ||
       oid == rfc::OID_KEY_USAGE[..] ||
       oid == rfc::OID_SUBJECT_ALT_NAME[..] ||
       oid == rfc::OID_NAME_CONSTRAINTS[..] ||
       oid == rfc::OID_AUTH_KEY_IDENTIFIER[..] ||
       oid == rfc::OID_SUBJECT_KEY_IDENTIFIER[..] ||
       oid == rfc::OID_POLICY_CONSTRAINTS[..] ||
       oid == rfc::OID_INHIBIT_ANY_POLICY[..] {
        return true;
    }
    return is_known_pki_extension_oid(oid);
}

fn read_tbs_serial(raw_cert: const u8[:], tbs_seq: core::ByteCursor&, out: tls::ParsedCert&) -> bool {
    var serial = core::cursor_from(raw_cert[..0]);
    if !tls::get_asn1_element(tbs_seq, rfc::ASN1_TAG_INTEGER, serial) { return false; }
    if !tls::validate_asn1_integer(serial.buf, true) { return false; }
    out.serial_number = tls::make_span(raw_cert, serial.buf);
    return true;
}

// RFC 5280 Section 4.1.1.2: signatureAlgorithm - Validates AlgorithmIdentifier parameters by OID.
fn validate_x509_sig_alg_params(sig_oid: const u8[:], sig_alg_rem: core::ByteCursor&) -> bool {
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

fn read_tbs_sig_alg(
    raw_cert: const u8[:],
    tbs_seq:  core::ByteCursor&,
    out:      tls::ParsedCert&,
) -> tls::Span16, bool {
    var sig_alg = core::cursor_from(raw_cert[..0]);
    if !tls::get_asn1_element(tbs_seq, rfc::ASN1_TAG_SEQUENCE, sig_alg) {
        return tls::Span16 { .. }, false;
    }
    let inner_span = tls::make_span(raw_cert, sig_alg.buf);
    var sig_oid = core::cursor_from(raw_cert[..0]);
    if !tls::get_asn1_element(sig_alg, rfc::ASN1_TAG_OID, sig_oid) {
        return tls::Span16 { .. }, false;
    }
    guard validate_x509_sig_alg_params(sig_oid.buf, sig_alg) else {
        return tls::Span16 { .. }, false;
    }
    out.sig_alg_oid = tls::make_span(raw_cert, sig_oid.buf);
    return inner_span, true;
}

fn read_tbs_validity(raw_cert: const u8[:], tbs_seq: core::ByteCursor&, out: tls::ParsedCert&) -> bool {
    var validity = core::cursor_from(raw_cert[..0]);
    if !tls::get_asn1_element(tbs_seq, rfc::ASN1_TAG_SEQUENCE, validity) { return false; }
    var nb_val = core::cursor_from(raw_cert[..0]);
    var nb_tag: u8 = 0;
    if !tls::get_any_asn1_element(validity, nb_tag, nb_val) { return false; }
    let nb_time, ok_nb = tls::parse_asn1_time(nb_tag, nb_val.buf);
    guard ok_nb else { return false; }
    out.validity_not_before = nb_time;

    var na_val = core::cursor_from(raw_cert[..0]);
    var na_tag: u8 = 0;
    if !tls::get_any_asn1_element(validity, na_tag, na_val) { return false; }
    let na_time, ok_na = tls::parse_asn1_time(na_tag, na_val.buf);
    guard ok_na else { return false; }
    out.validity_not_after = na_time;

    // RFC 5280 §4.1.2.5: Validity period inversion check (notBefore <= notAfter)
    guard validity.cursor_len() == 0 && out.validity_not_before <= out.validity_not_after else { return false; }
    return true;
}

fn validate_x509_spki_alg_params(
    spki_oid:     const u8[:],
    spki_alg:     core::ByteCursor&,
    out_alg_span: tls::Span16&,
    raw_cert:     const u8[:],
) -> bool {
    if spki_oid == rfc::OID_EC_PUBLIC_KEY[..] {
        var spki_curve = core::cursor_from(raw_cert[..0]);
        guard tls::get_asn1_element(spki_alg, rfc::ASN1_TAG_OID, spki_curve) && spki_alg.cursor_len() == 0 else {
            return false;
        }
        out_alg_span = tls::make_span(raw_cert, spki_curve.buf);
        return true;
    }
    out_alg_span = tls::make_span(raw_cert, spki_oid);
    if spki_oid == rfc::OID_ED25519[..] {
        return spki_alg.cursor_len() == 0;
    }
    if spki_oid == rfc::OID_RSA_ENCRYPTION[..] && spki_alg.cursor_len() > 0 {
        var null_el = core::cursor_from(raw_cert[..0]);
        return tls::get_asn1_element(spki_alg, rfc::ASN1_TAG_NULL, null_el) &&
            null_el.cursor_len() == 0 &&
            spki_alg.cursor_len() == 0;
    }
    return true;
}

fn read_tbs_spki(raw_cert: const u8[:], tbs_seq: core::ByteCursor&, out: tls::ParsedCert&) -> bool {
    var spki = core::cursor_from(raw_cert[..0]);
    if !tls::get_asn1_element(tbs_seq, rfc::ASN1_TAG_SEQUENCE, spki) { return false; }
    out.spki_raw = tls::make_span(raw_cert, spki.buf);

    var spki_alg = core::cursor_from(raw_cert[..0]);
    if !tls::get_asn1_element(spki, rfc::ASN1_TAG_SEQUENCE, spki_alg) { return false; }
    var spki_oid = core::cursor_from(raw_cert[..0]);
    if !tls::get_asn1_element(spki_alg, rfc::ASN1_TAG_OID, spki_oid) { return false; }
    guard validate_x509_spki_alg_params(spki_oid.buf, spki_alg, out.spki_alg_oid, raw_cert) else {
        return false;
    }

    var spki_pubkey = core::cursor_from(raw_cert[..0]);
    if !tls::get_asn1_element(spki, rfc::ASN1_TAG_BIT_STRING, spki_pubkey) { return false; }
    // RFC 5280 Section 4.1.2.7: Subject Public Key Info - Require unused_bits == 0 and no trailing SPKI bytes.
    guard spki.cursor_len() == 0 &&
        tls::validate_asn1_bit_string(spki_pubkey.buf) &&
        spki_pubkey.buf.len >= 2 &&
        spki_pubkey.buf[0] == 0 else {
        return false;
    }
    out.spki_pubkey = tls::make_span(raw_cert, spki_pubkey.buf);
    return true;
}

fn x509_parse_bc_ca_bool(bc_seq: core::ByteCursor&, cert: tls::ParsedCert&) {
    guard bc_seq.cursor_len() > 0 && bc_seq.buf[0] == rfc::ASN1_TAG_BOOLEAN else { return; }
    var ca_bool = core::cursor_from(bc_seq.buf[..0]);
    guard tls::get_asn1_element(bc_seq, rfc::ASN1_TAG_BOOLEAN, ca_bool) &&
        ca_bool.buf.len == 1 &&
        (ca_bool.buf[0] == 0x00 || ca_bool.buf[0] == 0xFF) else {
        cert.has_unsupported_critical = true;
        return;
    }
    if ca_bool.buf[0] == 0xFF {
        cert.is_ca = true;
    }
}

fn x509_parse_bc_path_len(bc_seq: core::ByteCursor&, cert: tls::ParsedCert&) {
    guard bc_seq.cursor_len() > 0 && bc_seq.buf[0] == rfc::ASN1_TAG_INTEGER else { return; }
    var path_len: i64 = 0;
    guard tls::get_asn1_integer(bc_seq, path_len) else {
        cert.has_unsupported_critical = true;
        return;
    }
    // RFC 5280 Section 4.2.1.9 & OpenSSL #32374:
    // pathLenConstraint MUST be greater than or equal to zero.
    // CAs MUST NOT include pathLenConstraint unless cA boolean is asserted.
    if !cert.is_ca || path_len < 0 {
        cert.has_unsupported_critical = true;
        return;
    }
    cert.path_len_constraint = min(path_len, 255) as i32;
}

fn x509_parse_basic_constraints_ext(ext_val: core::ByteCursor&, cert: tls::ParsedCert&) {
    if cert.has_basic_constraints {
        cert.has_unsupported_critical = true;
        return;
    }
    cert.has_basic_constraints = true;
    var bc_seq = core::cursor_from(ext_val.buf[..0]);
    guard tls::get_asn1_element(ext_val, rfc::ASN1_TAG_SEQUENCE, bc_seq) && ext_val.cursor_len() == 0 else {
        cert.has_unsupported_critical = true;
        return;
    }
    x509_parse_bc_ca_bool(bc_seq, cert);
    x509_parse_bc_path_len(bc_seq, cert);
    if bc_seq.cursor_len() > 0 {
        cert.has_unsupported_critical = true;
    }
}

fn x509_parse_key_usage_ext(ext_val: core::ByteCursor&, cert: tls::ParsedCert&) {
    if cert.has_key_usage {
        cert.has_unsupported_critical = true;
        return;
    }
    cert.has_key_usage = true;
    var ku_bits = core::cursor_from(ext_val.buf[..0]);
    guard tls::get_asn1_element(ext_val, rfc::ASN1_TAG_BIT_STRING, ku_bits) && ext_val.cursor_len() == 0 else {
        cert.has_unsupported_critical = true;
        return;
    }
    guard tls::validate_asn1_bit_string(ku_bits.buf) && ku_bits.buf.len >= 2 else {
        cert.has_unsupported_critical = true;
        return;
    }

    var ku: u16 = (ku_bits.buf[1] as u16) << 8;
    if ku_bits.buf.len >= 3 {
        ku = ku | ku_bits.buf[2];
    }
    cert.key_usage = ku;
}

fn x509_parse_akid_ext(raw_cert: const u8[:], ext_val: core::ByteCursor&, cert: tls::ParsedCert&) {
    if cert.has_akid {
        cert.has_unsupported_critical = true;
        return;
    }
    var akid_seq = core::cursor_from(ext_val.buf[..0]);
    guard tls::get_asn1_element(ext_val, rfc::ASN1_TAG_SEQUENCE, akid_seq) && ext_val.cursor_len() == 0 else {
        cert.has_unsupported_critical = true;
        return;
    }
    guard akid_seq.cursor_len() > 0 && akid_seq.buf[0] == 0x80 else { return; }
    var akid_key = core::cursor_from(akid_seq.buf[..0]);
    guard tls::get_asn1_element(akid_seq, 0x80, akid_key) else { return; }
    guard akid_key.buf.len > 0 && akid_key.buf.len <= 64 else { return; }
    cert.has_akid = true;
    cert.akid_key_id = tls::make_span(raw_cert, akid_key.buf);
}

fn x509_parse_skid_ext(raw_cert: const u8[:], ext_val: core::ByteCursor&, cert: tls::ParsedCert&) {
    if cert.has_skid {
        cert.has_unsupported_critical = true;
        return;
    }
    var skid_oct = core::cursor_from(ext_val.buf[..0]);
    guard tls::get_asn1_element(ext_val, rfc::ASN1_TAG_OCTET_STRING, skid_oct) && ext_val.cursor_len() == 0 else {
        cert.has_unsupported_critical = true;
        return;
    }
    guard skid_oct.buf.len > 0 && skid_oct.buf.len <= 64 else { return; }
    cert.has_skid = true;
    cert.skid_key_id = tls::make_span(raw_cert, skid_oct.buf);
}

inline fn x509_check_policy_skip_certs(elem_buf: const u8[:]) -> bool {
    return elem_buf.len > 0 && (elem_buf[0] & 0x80) == 0;
}

fn x509_parse_policy_constraints_ext(ext_val: core::ByteCursor&, cert: tls::ParsedCert&) {
    var pc_seq = core::cursor_from(ext_val.buf[..0]);
    if !tls::get_asn1_element(ext_val, rfc::ASN1_TAG_SEQUENCE, pc_seq) ||
        ext_val.cursor_len() != 0 ||
        pc_seq.cursor_len() == 0 {
        cert.has_malformed_policy_constraints = true;
        return;
    }

    while pc_seq.cursor_len() > 0 {
        var pc_tag: u8 = 0;
        var pc_elem = core::cursor_from(pc_seq.buf[..0]);
        if !tls::get_any_asn1_element(pc_seq, pc_tag, pc_elem) {
            cert.has_malformed_policy_constraints = true;
            return;
        }
        let tag_num = pc_tag & 0x1F;
        guard (tag_num == 0 || tag_num == 1) && x509_check_policy_skip_certs(pc_elem.buf) else {
            cert.has_malformed_policy_constraints = true;
            return;
        }
    }
}

// Parses RFC 7633 §4 X.509 TLS Feature extension (`Features ::= SEQUENCE OF INTEGER`).
// Sets `cert.has_must_staple = true` when feature identifier 5 (`status_request`) is present.
//
// Example:
//   ext_val = [0x30, 0x03, 0x02, 0x01, 0x05]
//   returns: true, cert.has_must_staple = true
fn x509_parse_tls_feature_ext(ext_val: const u8[:], cert: tls::ParsedCert&) -> bool {
    var c = core::cursor_from(ext_val);
    var feat_seq = core::cursor_from(ext_val[..0]);
    guard tls::get_asn1_element(c, rfc::ASN1_TAG_SEQUENCE, feat_seq) && c.cursor_len() == 0 else {
        cert.has_unsupported_critical = true;
        return false;
    }
    guard feat_seq.cursor_len() > 0 else {
        cert.has_unsupported_critical = true;
        return false;
    }
    while feat_seq.cursor_len() > 0 {
        var feat_id: i64 = 0;
        guard tls::get_asn1_integer(feat_seq, feat_id) && feat_id >= 0 && feat_id <= 65535 else {
            cert.has_unsupported_critical = true;
            return false;
        }
        if feat_id == rfc::TLS_EXT_STATUS_REQUEST {
            cert.has_must_staple = true;
        }
    }
    return true;
}

fn x509_parse_sct_ext(ext_val: core::ByteCursor&, cert: tls::ParsedCert&) -> bool {
    if cert.has_sct_list {
        cert.has_unsupported_critical = true;
        return false;
    }
    var sct_oct = core::cursor_from(ext_val.buf[..0]);
    guard tls::get_asn1_element(ext_val, rfc::ASN1_TAG_OCTET_STRING, sct_oct) && ext_val.cursor_len() == 0 else {
        cert.has_unsupported_critical = true;
        return false;
    }
    var scts: tls::ParsedSct[..8] = [];
    guard tls::parse_sct_list(sct_oct.buf, scts) else {
        cert.has_unsupported_critical = true;
        return false;
    }
    cert.has_sct_list = true;
    cert.sct_count = scts.len as u8;
    return true;
}

inline fn x509_classify_eku_oid(oid: const u8[:]) -> u8 {
    if oid == rfc::OID_EKU_SERVER_AUTH[..] {
        return rfc::EKU_SERVER_AUTH;
    }
    if oid == rfc::OID_EKU_CLIENT_AUTH[..] {
        return rfc::EKU_CLIENT_AUTH;
    }
    if oid == rfc::OID_EKU_OCSP_SIGNING[..] {
        return rfc::EKU_OCSP_SIGNING;
    }
    if oid == rfc::OID_EKU_ANY[..] {
        return rfc::EKU_ANY;
    }
    return 0;
}

// Parses RFC 5280 §4.2.1.12 ExtendedKeyUsage (`SEQUENCE SIZE (1..MAX) OF KeyPurposeId`).
// Rejects empty sequences, duplicate extensions, and non-OID elements.
//
// Example:
//   ext_val = [0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]
//   returns: true, cert.has_eku = true, cert.eku_mask = 1 (EKU_SERVER_AUTH)
fn x509_parse_eku_ext(ext_val: const u8[:], cert: tls::ParsedCert&) -> bool {
    if cert.has_eku {
        cert.has_unsupported_critical = true;
        return false;
    }
    var c = core::cursor_from(ext_val);
    var eku_seq = core::cursor_from(ext_val[..0]);
    guard tls::get_asn1_element(c, rfc::ASN1_TAG_SEQUENCE, eku_seq) && c.cursor_len() == 0 else {
        cert.has_unsupported_critical = true;
        return false;
    }
    guard eku_seq.cursor_len() > 0 else {
        cert.has_unsupported_critical = true;
        return false;
    }
    cert.has_eku = true;
    while eku_seq.cursor_len() > 0 {
        var kp_oid = core::cursor_from(eku_seq.buf[..0]);
        guard tls::get_asn1_element(eku_seq, rfc::ASN1_TAG_OID, kp_oid) && kp_oid.buf.len > 0 else {
            cert.has_unsupported_critical = true;
            return false;
        }
        cert.eku_mask = cert.eku_mask | x509_classify_eku_oid(kp_oid.buf);
    }
    return true;
}

fn x509_dispatch_pki_extension(oid: const u8[:], ext_val: core::ByteCursor&, cert: tls::ParsedCert&) {
    if oid == rfc::OID_EXT_KEY_USAGE[..] {
        let _ = x509_parse_eku_ext(ext_val.buf, cert);
    } else if oid == rfc::OID_TLS_FEATURE[..] {
        let _ = x509_parse_tls_feature_ext(ext_val.buf, cert);
    } else if oid == rfc::OID_CT_PRECERT_SCTS[..] {
        let _ = x509_parse_sct_ext(ext_val, cert);
    }
}

fn x509_dispatch_policy_extension(oid: const u8[:], ext_val: core::ByteCursor&, cert: tls::ParsedCert&) {
    if oid == rfc::OID_POLICY_CONSTRAINTS[..] {
        x509_parse_policy_constraints_ext(ext_val, cert);
    } else if oid == rfc::OID_INHIBIT_ANY_POLICY[..] {
        var val: i64 = 0;
        if !tls::get_asn1_integer(ext_val, val) || ext_val.cursor_len() != 0 || val < 0 {
            cert.has_malformed_policy_constraints = true;
        }
    } else {
        x509_dispatch_pki_extension(oid, ext_val, cert);
    }
}

fn x509_dispatch_extension(
    raw_cert: const u8[:],
    oid:      const u8[:],
    ext_val:  core::ByteCursor&,
    cert:     tls::ParsedCert&,
) {
    if oid == rfc::OID_BASIC_CONSTRAINTS[..] {
        x509_parse_basic_constraints_ext(ext_val, cert);
    } else if oid == rfc::OID_KEY_USAGE[..] {
        x509_parse_key_usage_ext(ext_val, cert);
    } else if oid == rfc::OID_SUBJECT_ALT_NAME[..] {
        if cert.has_san {
            cert.has_unsupported_critical = true;
            return;
        }
        cert.has_san = true;
        cert.san_raw = tls::make_span(raw_cert, ext_val.buf);
    } else if oid == rfc::OID_NAME_CONSTRAINTS[..] {
        if cert.has_name_constraints {
            cert.has_unsupported_critical = true;
            return;
        }
        cert.has_name_constraints = true;
        cert.name_constraints_raw = tls::make_span(raw_cert, ext_val.buf);
    } else if oid == rfc::OID_AUTH_KEY_IDENTIFIER[..] {
        x509_parse_akid_ext(raw_cert, ext_val, cert);
    } else if oid == rfc::OID_SUBJECT_KEY_IDENTIFIER[..] {
        x509_parse_skid_ext(raw_cert, ext_val, cert);
    } else {
        x509_dispatch_policy_extension(oid, ext_val, cert);
    }
}

inline fn x509_check_ext_critical(single_ext: core::ByteCursor&, out_ok: bool&) -> bool {
    out_ok = true;
    guard single_ext.cursor_len() > 0 && single_ext.buf[0] == rfc::ASN1_TAG_BOOLEAN else { return false; }
    var maybe_crit = core::cursor_from(single_ext.buf[..0]);
    guard tls::get_asn1_element(single_ext, rfc::ASN1_TAG_BOOLEAN, maybe_crit) &&
        maybe_crit.buf.len == 1 &&
        (maybe_crit.buf[0] == 0x00 || maybe_crit.buf[0] == 0xFF) else {
        out_ok = false;
        return false;
    }
    return maybe_crit.buf[0] == 0xFF;
}

fn x509_parse_single_cert_extension(
    raw_cert:   const u8[:],
    single_ext: core::ByteCursor&,
    cert:       tls::ParsedCert&,
) -> bool {
    var oid = core::cursor_from(single_ext.buf[..0]);
    if !tls::get_asn1_element(single_ext, rfc::ASN1_TAG_OID, oid) {
        cert.has_unsupported_critical = true;
        return false;
    }

    var crit_ok = true;
    let is_critical = x509_check_ext_critical(single_ext, crit_ok);
    if !crit_ok {
        cert.has_unsupported_critical = true;
        return false;
    }

    var ext_val = core::cursor_from(single_ext.buf[..0]);
    if !tls::get_asn1_element(single_ext, rfc::ASN1_TAG_OCTET_STRING, ext_val) {
        cert.has_unsupported_critical = true;
        return false;
    }

    if single_ext.cursor_len() > 0 {
        cert.has_unsupported_critical = true;
        return false;
    }

    if !is_known_extension_oid(oid.buf) {
        if is_critical {
            cert.has_unsupported_critical = true;
        }
        return true;
    }

    x509_dispatch_extension(raw_cert, oid.buf, ext_val, cert);
    return true;
}

// Parses X.509 extensions for BasicConstraints, KeyUsage, and SubjectAltName.
fn read_cert_extensions(raw_cert: const u8[:], ext_seq: core::ByteCursor&, cert: tls::ParsedCert&) -> bool {
    while ext_seq.cursor_len() > 0 {
        var single_ext = core::cursor_from(ext_seq.buf[..0]);
        if !tls::get_asn1_element(ext_seq, rfc::ASN1_TAG_SEQUENCE, single_ext) {
            cert.has_unsupported_critical = true;
            return false;
        }
        if !x509_parse_single_cert_extension(raw_cert, single_ext, cert) {
            return false;
        }
    }
    return true;
}

fn read_tbs_optional_elem(
    raw_cert:      const u8[:],
    ext_tag:       u8,
    ext_container: core::ByteCursor&,
    tbs_ver:       u8,
    last_ctx_tag:  i32&,
    out:           tls::ParsedCert&,
) -> bool {
    if ext_tag == 0x81 || ext_tag == 0x82 {
        let cur_idx: i32 = if ext_tag == 0x81 { 1 } else { 2 };
        guard tbs_ver >= 1 && last_ctx_tag < cur_idx && tls::validate_asn1_bit_string(ext_container.buf) else {
            return false;
        }
        last_ctx_tag = cur_idx;
        return true;
    }
    guard ext_tag == 0xA3 && tbs_ver == 2 && last_ctx_tag < 3 else {
        out.has_unsupported_critical = true;
        return false;
    }
    last_ctx_tag = 3;
    var ext_seq = core::cursor_from(raw_cert[..0]);
    guard tls::get_asn1_element(ext_container, rfc::ASN1_TAG_SEQUENCE, ext_seq) &&
        ext_container.cursor_len() == 0 && ext_seq.cursor_len() > 0 else {
        out.has_unsupported_critical = true;
        return false;
    }
    out.extensions_raw = tls::make_span(raw_cert, ext_seq.buf);
    return read_cert_extensions(raw_cert, ext_seq, out);
}

fn read_tbs_extensions(raw_cert: const u8[:], tbs_seq: core::ByteCursor&, tbs_ver: u8, out: tls::ParsedCert&) -> bool {
    var last_ctx_tag: i32 = 0;
    while tbs_seq.cursor_len() > 0 {
        var ext_container = core::cursor_from(raw_cert[..0]);
        var ext_tag: u8 = 0;
        if !tls::get_any_asn1_element(tbs_seq, ext_tag, ext_container) {
            out.has_unsupported_critical = true;
            return false;
        }
        if !read_tbs_optional_elem(raw_cert, ext_tag, ext_container, tbs_ver, last_ctx_tag, out) {
            return false;
        }
    }
    return true;
}

fn x509_read_outer_sequence(raw_cert: const u8[:], cert_seq: core::ByteCursor&) -> bool {
    guard raw_cert.len > 0 && raw_cert.len <= 65535 else { return false; }
    var cert_cursor = core::cursor_from(raw_cert);
    if !tls::get_asn1_element(cert_cursor, rfc::ASN1_TAG_SEQUENCE, cert_seq) { return false; }
    return cert_cursor.cursor_len() == 0;
}

fn x509_read_tbs_version(tbs_seq: core::ByteCursor&, out_ver: u8&) -> bool {
    out_ver = 0;
    if tbs_seq.cursor_len() > 0 && tbs_seq.buf[0] == 0xA0 {
        var ver_elem = core::cursor_from(tbs_seq.buf[..0]);
        var tag: u8 = 0;
        guard tls::get_any_asn1_element(tbs_seq, tag, ver_elem) else { return false; }
        var ver_int: i64 = 0;
        guard tls::get_asn1_integer(ver_elem, ver_int) && ver_elem.cursor_len() == 0 else { return false; }
        guard ver_int >= 1 && ver_int <= 2 else { return false; }
        out_ver = ver_int as u8;
    }
    return true;
}

fn read_tbs_identity(raw_cert: const u8[:], tbs_seq: core::ByteCursor&, tbs_ver: u8, out: tls::ParsedCert&) -> bool {
    var issuer = core::cursor_from(raw_cert[..0]);
    if !tls::get_asn1_element(tbs_seq, rfc::ASN1_TAG_SEQUENCE, issuer) { return false; }
    out.issuer_raw = tls::make_span(raw_cert, issuer.buf);

    if !read_tbs_validity(raw_cert, tbs_seq, out) { return false; }

    var subject = core::cursor_from(raw_cert[..0]);
    if !tls::get_asn1_element(tbs_seq, rfc::ASN1_TAG_SEQUENCE, subject) { return false; }
    let subj_hint = core::add_sat_i64(out.issuer_raw.offset, out.issuer_raw.length);
    out.subject_raw = tls::make_span(raw_cert, subject.buf, subj_hint);

    if !read_tbs_spki(raw_cert, tbs_seq, out) { return false; }
    return read_tbs_extensions(raw_cert, tbs_seq, tbs_ver, out);
}

fn x509_read_tbs_components(
    raw_cert: const u8[:],
    tbs_seq:  core::ByteCursor&,
    out:      tls::ParsedCert&,
) -> tls::Span16, bool {
    var tbs_ver: u8 = 0;
    guard x509_read_tbs_version(tbs_seq, tbs_ver) else { return tls::Span16 { .. }, false; }
    if !read_tbs_serial(raw_cert, tbs_seq, out) { return tls::Span16 { .. }, false; }
    let inner_span, ok_sig = read_tbs_sig_alg(raw_cert, tbs_seq, out);
    if !ok_sig { return tls::Span16 { .. }, false; }
    if !read_tbs_identity(raw_cert, tbs_seq, tbs_ver, out) { return tls::Span16 { .. }, false; }
    return inner_span, true;
}

fn x509_read_outer_signature(
    raw_cert:      const u8[:],
    cert_seq:      core::ByteCursor&,
    inner_sig_alg: const u8[:],
    out:           tls::ParsedCert&,
) -> bool {
    guard cert_seq.cursor_len() > 0 else { return false; }
    var outer_sig_alg = core::cursor_from(raw_cert[..0]);
    if !tls::get_asn1_element(cert_seq, rfc::ASN1_TAG_SEQUENCE, outer_sig_alg) { return false; }
    let outer_sig_alg_raw = outer_sig_alg.buf;
    var outer_sig_oid = core::cursor_from(raw_cert[..0]);
    if !tls::get_asn1_element(outer_sig_alg, rfc::ASN1_TAG_OID, outer_sig_oid) { return false; }

    // RFC 5280 Section 4.1.1.2: signatureAlgorithm - Full outer/inner AlgorithmIdentifier MUST match.
    guard outer_sig_alg_raw == inner_sig_alg else { return false; }

    var sig_bits = core::cursor_from(raw_cert[..0]);
    var unused_bits: u8 = 0;
    if !tls::get_asn1_bit_string(cert_seq, sig_bits, unused_bits) { return false; }
    guard unused_bits == 0 && sig_bits.buf.len > 0 else { return false; }
    out.signature_value = tls::make_span(raw_cert, sig_bits.buf);

    guard cert_seq.cursor_len() == 0 else { return false; }
    return true;
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

fn x509_process_ipv4_char(
    b:         u8,
    octet_idx: i64&,
    current:   u32&,
    digits:    i64&,
    out_ip:    u8[4]&,
) -> bool {
    if b == '.' {
        guard digits > 0 && current <= 255 && octet_idx < 3 else { return false; }
        out_ip[octet_idx] = current as u8;
        octet_idx++;
        current = 0;
        digits = 0;
        return true;
    }
    guard core::is_ascii_digit(b) else { return false; }
    current = current * 10 + (b - '0');
    digits++;
    return digits <= 3 && current <= 255;
}

// Parses decimal IPv4 octets into u8[4]
// Example:
//   str = "192.168.1.1"
//   returns: ok = true, out_ip = [192, 168, 1, 1]
fn parse_ipv4_literal(str: const u8[:], out_ip: u8[4]&) -> bool {
    var octet_idx: i64 = 0;
    var current:   u32 = 0;
    var digits:    i64 = 0;

    for i in str.len {
        if !x509_process_ipv4_char(str[i], octet_idx, current, digits, out_ip) {
            return false;
        }
    }

    guard digits > 0 && current <= 255 && octet_idx == 3 else { return false; }
    out_ip[3] = current as u8;
    return true;
}

inline fn x509_is_dns_label_char(b: u8) -> bool {
    let is_alnum = core::is_ascii_alphanumeric(b);
    return is_alnum || b == '-';
}

fn x509_validate_dns_label(label: const u8[:], label_idx: i64) -> bool {
    guard label.len >= 1 && label.len <= 63 else { return false; }
    if label_idx == 0 && label.len == 1 && label[0] == '*' {
        return true;
    }
    guard label[0] != '-' && label[label.len - 1] != '-' else { return false; }
    for b in label {
        guard x509_is_dns_label_char(b) else { return false; }
    }
    return true;
}

inline fn x509_has_valid_uri_scheme(uri: const u8[:]) -> bool {
    let colon_idx = uri.index_of_byte(':');
    guard colon_idx > 0 else { return false; }
    let first = uri[0];
    guard core::is_ascii_alpha(first) else { return false; }
    for i in colon_idx {
        let b = uri[i];
        guard x509_is_dns_label_char(b) || b == '+' || b == '.' else { return false; }
    }
    return true;
}

fn match_ip_san_text(san_ip: const u8[:], host: const u8[:]) -> bool {
    guard (san_ip.len == 4 || san_ip.len == 16) && host.len > 0 else { return false; }
    guard !host.contains_byte('%') && !host.contains_byte(0) else { return false; }
    if san_ip.len == 4 {
        var host_ip: u8[4] = [0; 4];
        return parse_ipv4_literal(host, host_ip) && san_ip == host_ip[..];
    }
    var h6 = host;
    let no_l, has_l = h6.strip_prefix("[");
    if has_l {
        let inner, has_r = no_l.strip_suffix("]");
        guard has_r else { return false; }
        h6 = inner;
    }
    let ip6_octets, ok_v6 = core::parse_ipv6_octets(h6);
    return ok_v6 && san_ip == ip6_octets[..];
}

// Validates that an IPv4 (4-byte) or IPv6 (16-byte) subnet mask is contiguous CIDR.
// In network byte order, once a 0 bit appears, no 1 bit may follow.
inline fn x509_check_mask_byte(b: u8, seen_zero_bit: bool&) -> bool {
    for bit_idx in 8 {
        let bit = ((b as u32) >> (7 - bit_idx)) & 1;
        if bit == 0 {
            seen_zero_bit = true;
        } else if seen_zero_bit {
            return false;
        }
    }
    return true;
}

inline fn x509_validate_dns_candidate(cand: const u8[:]) -> bool {
    guard cand.len > 0 else { return false; }
    guard cand[0] != '.' else { return false; }
    guard !cand.contains_byte(0) else { return false; }
    return find(cand, "..") < 0;
}

inline fn x509_match_dns_dotted_constraint(cand: const u8[:], cons: const u8[:]) -> bool {
    guard cons.len > 1 else { return false; }
    guard cand.len > cons.len else { return false; }
    return cand.ends_with_fold(cons);
}

fn x509_match_dns_subdomain(cand: const u8[:], cons: const u8[:]) -> bool {
    guard cons.len > 0 else { return false; }
    guard cand.len > cons.len else { return false; }
    guard cand.ends_with_fold(cons) else { return false; }
    var idx = cand.len - cons.len;
    idx--;
    guard idx >= 0 else { return false; }
    return cand[idx] == '.';
}

fn x509_extract_uri_authority(candidate_uri: const u8[:]) -> const u8[:] {
    var s = candidate_uri;
    if core::starts_with(s, "http://") {
        s = s[7..];
    } else if core::starts_with(s, "https://") {
        s = s[8..];
    } else {
        let scheme_end = find(s, "://");
        guard scheme_end >= 0 else { return s[..0]; }
        s = s[scheme_end + 3..];
    }

    let delim_idx = core::find_byteset(s, "/?#");
    let auth_end = if delim_idx >= 0 { delim_idx } else { s.len };
    return s[..auth_end];
}

fn x509_match_ipv6_uri_constraint(host_part: const u8[:], constraint: const u8[:]) -> bool {
    let close_bracket = host_part.index_of_byte(']');
    guard close_bracket > 1 else { return false; }
    var inner_ip = host_part[1..close_bracket];

    let pct_idx = inner_ip.index_of_byte('%');
    if pct_idx >= 0 {
        inner_ip = inner_ip[..pct_idx];
    }
    guard inner_ip.len > 0 else { return false; }

    var cons_cmp = constraint;
    if cons_cmp.len > 2 && cons_cmp[0] == '[' && cons_cmp[cons_cmp.len - 1] == ']' {
        cons_cmp = cons_cmp[1..^1];
    }
    return inner_ip.eq_ascii_fold(cons_cmp);
}

inline fn x509_is_ipv4_literal(host_part: const u8[:]) -> bool {
    guard host_part.len > 0 else { return false; }
    for b in host_part {
        if (b < '0' || b > '9') && b != '.' {
            return false;
        }
    }
    return true;
}

fn x509_parse_general_subtree_base(
    subtree:  core::ByteCursor&,
    out_type: tls::SanType&,
    out_val:  core::ByteCursor&,
) -> bool {
    var base_tag: u8 = 0;
    if !tls::get_any_asn1_element(subtree, base_tag, out_val) { return false; }
    let tag_num = base_tag & 0x1F;
    if tag_num == 1 { // rfc822Name [1]
        out_type = tls::SanType.Email;
        guard out_val.buf.len > 0 && !out_val.buf.contains_byte(0) else { return false; }
    } else if tag_num == 2 { // dNSName
        out_type = tls::SanType.Dns;
        guard out_val.buf.len > 0 && !out_val.buf.contains_byte(0) else { return false; }
    } else if tag_num == 7 { // iPAddress
        out_type = tls::SanType.Ip;
        guard out_val.buf.len == 8 || out_val.buf.len == 32 else { return false; }
        let half = out_val.buf.len / 2;
        guard tls::validate_cidr_mask(out_val.buf[half..]) else { return false; }
    } else if tag_num == 6 { // uniformResourceIdentifier [6]
        out_type = tls::SanType.Uri;
        guard out_val.buf.len > 0 && !out_val.buf.contains_byte(0) else { return false; }
    } else {
        out_type = tls::SanType.Other;
    }
    return true;
}

inline fn x509_validate_subtree_bound_opt(opt_tag: u8, opt_elem: core::ByteCursor&) -> bool {
    let opt_num = opt_tag & 0x1F;
    if opt_num == 0 { // minimum MUST be zero
        var min_val: i64 = 0;
        return tls::get_asn1_integer(opt_elem, min_val) && min_val == 0;
    }
    return false; // maximum (opt_num == 1) or other tags forbidden
}

inline fn x509_parse_general_subtree_bounds(subtree: core::ByteCursor&) -> bool {
    while subtree.cursor_len() > 0 {
        var opt_tag: u8 = 0;
        var opt_elem = core::cursor_from(subtree.buf[..0]);
        if !tls::get_any_asn1_element(subtree, opt_tag, opt_elem) { return false; }
        guard x509_validate_subtree_bound_opt(opt_tag, opt_elem) else { return false; }
    }
    return true;
}

fn x509_parse_general_subtree(
    nc_der:          const u8[:],
    subtree:         core::ByteCursor&,
    is_excluded:     bool,
    out_constraints: tls::NameConstraintEntry[..16]&,
) -> bool {
    var st = tls::SanType.Other;
    var base_elem = core::cursor_from(nc_der[..0]);
    guard x509_parse_general_subtree_base(subtree, st, base_elem) else { return false; }
    guard x509_parse_general_subtree_bounds(subtree) else { return false; }

    let span = tls::make_span(nc_der, base_elem.buf);
    return out_constraints.try_push(tls::NameConstraintEntry {
        san_type:    st,
        is_excluded: is_excluded,
        val:         tls::span_slice(nc_der, span),
    });
}

fn x509_parse_subtrees_sequence(
    nc_der:          const u8[:],
    subtrees_elem:   core::ByteCursor&,
    is_excluded:     bool,
    out_constraints: tls::NameConstraintEntry[..16]&,
    count:           i64&,
) -> bool {
    var subtrees_seq = subtrees_elem;
    if subtrees_elem.cursor_len() > 0 && subtrees_elem.buf[0] == rfc::ASN1_TAG_SEQUENCE {
        var probe = subtrees_elem;
        var inner = core::cursor_from(subtrees_elem.buf[..0]);
        if tls::get_asn1_element(probe, rfc::ASN1_TAG_SEQUENCE, inner) &&
            probe.cursor_len() == 0 &&
            inner.cursor_len() > 0 &&
            inner.buf[0] == rfc::ASN1_TAG_SEQUENCE {
            subtrees_seq = inner;
        }
    }
    guard subtrees_seq.cursor_len() > 0 else { return false; }

    while subtrees_seq.cursor_len() > 0 {
        var subtree = core::cursor_from(subtrees_seq.buf[..0]);
        if !tls::get_asn1_element(subtrees_seq, rfc::ASN1_TAG_SEQUENCE, subtree) { return false; }
        guard x509_parse_general_subtree(nc_der, subtree, is_excluded, out_constraints) else { return false; }
        count++;
    }
    return true;
}

fn x509_verify_signature_by_oid(
    sig_oid:       const u8[:],
    tbs_data:      const u8[:],
    sig_bytes:     const u8[:],
    parent_pubkey: const u8[:],
    err_alert:     tls::Alert,
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

    if sig_oid == rfc::OID_SIG_SHA256_RSA[..] {
        guard core::rsa_pkcs1_sha256_verify_der(parent_pubkey, tbs_data, sig_bytes) else {
            return err_alert;
        }
        return tls::Alert.CloseNotify;
    }

    if sig_oid == rfc::OID_SIG_SHA384_RSA[..] {
        guard core::rsa_pkcs1_sha384_verify_der(parent_pubkey, tbs_data, sig_bytes) else {
            return err_alert;
        }
        return tls::Alert.CloseNotify;
    }

    if sig_oid == rfc::OID_SIG_RSASSA_PSS[..] {
        let pss_ok = core::rsa_pss_sha256_verify_der(parent_pubkey, tbs_data, sig_bytes)
            || core::rsa_pss_sha384_verify_der(parent_pubkey, tbs_data, sig_bytes);
        guard pss_ok else {
            return err_alert;
        }
        return tls::Alert.CloseNotify;
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

inline fn x509_parse_ocsp_status(s_val: u8, out_status: tls::OcspResponseStatus&) -> bool {
    if s_val == rfc::OCSP_STATUS_SUCCESSFUL {
        out_status = tls::OcspResponseStatus.Successful;
        return true;
    }
    if s_val == rfc::OCSP_STATUS_MALFORMED_REQ {
        out_status = tls::OcspResponseStatus.MalformedRequest;
        return true;
    }
    if s_val == rfc::OCSP_STATUS_INTERNAL_ERROR {
        out_status = tls::OcspResponseStatus.InternalError;
        return true;
    }
    if s_val == rfc::OCSP_STATUS_TRY_LATER {
        out_status = tls::OcspResponseStatus.TryLater;
        return true;
    }
    if s_val == rfc::OCSP_STATUS_SIG_REQUIRED {
        out_status = tls::OcspResponseStatus.SigRequired;
        return true;
    }
    if s_val == rfc::OCSP_STATUS_UNAUTHORIZED {
        out_status = tls::OcspResponseStatus.Unauthorized;
        return true;
    }
    out_status = tls::OcspResponseStatus.Unknown;
    return false;
}

fn x509_parse_ocsp_cert_id(
    single_resp: core::ByteCursor&,
    raw_ocsp:    const u8[:],
    out:         tls::ParsedOcspResponse&,
) -> bool {
    var cert_id_seq = core::cursor_from(single_resp.buf[..0]);
    if !tls::get_asn1_element(single_resp, rfc::ASN1_TAG_SEQUENCE, cert_id_seq) { return false; }

    var hash_alg = core::cursor_from(cert_id_seq.buf[..0]);
    if !tls::get_asn1_element(cert_id_seq, rfc::ASN1_TAG_SEQUENCE, hash_alg) { return false; }
    if hash_alg.cursor_len() > 0 {
        var hash_oid = core::cursor_from(hash_alg.buf[..0]);
        if tls::get_asn1_element(hash_alg, rfc::ASN1_TAG_OID, hash_oid) {
            out.hash_alg_oid = tls::make_span(raw_ocsp, hash_oid.buf);
        }
    }

    var name_hash = core::cursor_from(cert_id_seq.buf[..0]);
    if !tls::get_asn1_element(cert_id_seq, rfc::ASN1_TAG_OCTET_STRING, name_hash) { return false; }
    out.issuer_name_hash = tls::make_span(raw_ocsp, name_hash.buf);

    var key_hash = core::cursor_from(cert_id_seq.buf[..0]);
    if !tls::get_asn1_element(cert_id_seq, rfc::ASN1_TAG_OCTET_STRING, key_hash) { return false; }
    out.issuer_key_hash = tls::make_span(raw_ocsp, key_hash.buf);

    var serial = core::cursor_from(cert_id_seq.buf[..0]);
    if !tls::get_asn1_element(cert_id_seq, rfc::ASN1_TAG_INTEGER, serial) { return false; }
    if !tls::validate_asn1_integer(serial.buf, true) { return false; }
    out.serial_number = tls::make_span(raw_ocsp, serial.buf);
    return true;
}

fn x509_parse_ocsp_cert_status(single_resp: core::ByteCursor&, out_status: tls::OcspCertStatus&) -> bool {
    var cert_status_tag: u8 = 0;
    var cert_status_elem = core::cursor_from(single_resp.buf[..0]);
    if !tls::get_any_asn1_element(single_resp, cert_status_tag, cert_status_elem) { return false; }
    guard (cert_status_tag & 0xC0) == 0x80 else { return false; }
    let cs_num = cert_status_tag & 0x1F;
    if cs_num == 0 {
        guard cert_status_elem.cursor_len() == 0 else { return false; }
        out_status = tls::OcspCertStatus.Good;
        return true;
    }
    if cs_num == 1 {
        guard cert_status_elem.cursor_len() > 0 else { return false; }
        out_status = tls::OcspCertStatus.Revoked;
        return true;
    }
    if cs_num == 2 {
        guard cert_status_elem.cursor_len() == 0 else { return false; }
        out_status = tls::OcspCertStatus.Unknown;
        return true;
    }
    return false;
}

fn x509_check_ocsp_ext_list(parent: core::ByteCursor&, ctx_tag: u8) -> bool {
    guard parent.cursor_len() > 0 && parent.buf[0] == ctx_tag else {
        return parent.cursor_len() == 0;
    }
    var ext_ctx = core::cursor_from(parent.buf[..0]);
    var ext_seq = core::cursor_from(parent.buf[..0]);
    guard tls::get_asn1_element(parent, ctx_tag, ext_ctx) && parent.cursor_len() == 0 else { return false; }
    guard tls::get_asn1_element(ext_ctx, rfc::ASN1_TAG_SEQUENCE, ext_seq) &&
        ext_ctx.cursor_len() == 0 && ext_seq.cursor_len() > 0 else {
        return false;
    }
    while ext_seq.cursor_len() > 0 {
        var single_ext = core::cursor_from(ext_seq.buf[..0]);
        guard tls::get_asn1_element(ext_seq, rfc::ASN1_TAG_SEQUENCE, single_ext) else { return false; }
        var oid = core::cursor_from(single_ext.buf[..0]);
        guard tls::get_asn1_element(single_ext, rfc::ASN1_TAG_OID, oid) else { return false; }
        var crit_ok = true;
        let is_crit = x509_check_ext_critical(single_ext, crit_ok);
        guard crit_ok && !is_crit else { return false; }
        var ext_val = core::cursor_from(single_ext.buf[..0]);
        guard tls::get_asn1_element(single_ext, rfc::ASN1_TAG_OCTET_STRING, ext_val) &&
            single_ext.cursor_len() == 0 else {
            return false;
        }
    }
    return true;
}

fn x509_parse_ocsp_next_update(single_resp: core::ByteCursor&, out: tls::ParsedOcspResponse&) -> bool {
    if single_resp.cursor_len() > 0 && single_resp.buf[0] == 0xA0 {
        var next_up_ctx = core::cursor_from(single_resp.buf[..0]);
        guard tls::get_asn1_element(single_resp, 0xA0, next_up_ctx) else { return false; }
        var next_up_tag: u8 = 0;
        var next_up_elem = core::cursor_from(next_up_ctx.buf[..0]);
        guard tls::get_any_asn1_element(next_up_ctx, next_up_tag, next_up_elem) &&
            next_up_ctx.cursor_len() == 0 else { return false; }
        let next_time, ok_next = tls::parse_asn1_time(next_up_tag, next_up_elem.buf);
        guard ok_next else { return false; }
        out.next_update = next_time;
        out.has_next_update = true;
    }
    return x509_check_ocsp_ext_list(single_resp, 0xA1);
}

fn x509_parse_ocsp_single_response(
    responses_seq: core::ByteCursor&,
    raw_ocsp:      const u8[:],
    out:           tls::ParsedOcspResponse&,
) -> bool {
    guard responses_seq.cursor_len() > 0 else { return false; }
    var single_resp = core::cursor_from(responses_seq.buf[..0]);
    if !tls::get_asn1_element(responses_seq, rfc::ASN1_TAG_SEQUENCE, single_resp) { return false; }

    guard x509_parse_ocsp_cert_id(single_resp, raw_ocsp, out) else { return false; }
    guard x509_parse_ocsp_cert_status(single_resp, out.cert_status) else { return false; }

    var this_up_tag: u8 = 0;
    var this_up_elem = core::cursor_from(single_resp.buf[..0]);
    if !tls::get_any_asn1_element(single_resp, this_up_tag, this_up_elem) { return false; }
    let this_time, ok_this = tls::parse_asn1_time(this_up_tag, this_up_elem.buf);
    guard ok_this else { return false; }
    out.this_update = this_time;

    return x509_parse_ocsp_next_update(single_resp, out);
}

fn x509_parse_ocsp_responses_list(
    responses_seq: core::ByteCursor&,
    raw_ocsp:      const u8[:],
    target_serial: const u8[:],
    out:           tls::ParsedOcspResponse&,
) -> bool {
    guard responses_seq.cursor_len() > 0 else { return false; }
    var selected = false;
    while responses_seq.cursor_len() > 0 {
        var cand = tls::ParsedOcspResponse {
            status:  out.status,
            tbs_raw: out.tbs_raw,
        };
        guard x509_parse_ocsp_single_response(responses_seq, raw_ocsp, cand) else { return false; }
        let cand_serial = tls::span_slice(raw_ocsp, cand.serial_number);
        let matches = if target_serial.len > 0 { cand_serial == target_serial } else { !selected };
        if matches && !selected {
            out = cand;
            selected = true;
        }
    }
    return selected;
}

fn x509_skip_ocsp_version_and_id(tbs_resp_data: core::ByteCursor&) -> bool {
    if tbs_resp_data.cursor_len() > 0 && tbs_resp_data.buf[0] == 0xA0 {
        var ver_elem = core::cursor_from(tbs_resp_data.buf[..0]);
        tls::get_asn1_element(tbs_resp_data, 0xA0, ver_elem);
    }
    var resp_id_tag: u8 = 0;
    var resp_id = core::cursor_from(tbs_resp_data.buf[..0]);
    return tls::get_any_asn1_element(tbs_resp_data, resp_id_tag, resp_id);
}

fn x509_ocsp_read_basic_sig(
    basic_seq: core::ByteCursor&,
    raw_ocsp:  const u8[:],
    out:       tls::ParsedOcspResponse&,
) -> bool {
    guard basic_seq.cursor_len() > 0 else { return true; }
    var sig_alg_seq = core::cursor_from(basic_seq.buf[..0]);
    guard tls::get_asn1_element(basic_seq, rfc::ASN1_TAG_SEQUENCE, sig_alg_seq) else { return false; }
    var sig_oid = core::cursor_from(sig_alg_seq.buf[..0]);
    guard tls::get_asn1_element(sig_alg_seq, rfc::ASN1_TAG_OID, sig_oid) else { return false; }
    out.sig_alg_oid = tls::make_span(raw_ocsp, sig_oid.buf);

    guard basic_seq.cursor_len() > 0 else { return false; }
    var sig_bits = core::cursor_from(basic_seq.buf[..0]);
    var unused_bits: u8 = 0;
    guard tls::get_asn1_bit_string(basic_seq, sig_bits, unused_bits) &&
        unused_bits == 0 && sig_bits.buf.len > 0 else { return false; }
    out.signature = tls::make_span(raw_ocsp, sig_bits.buf);
    return true;
}

fn x509_parse_ocsp_basic_response(
    resp_bytes_seq: core::ByteCursor&,
    raw_ocsp:       const u8[:],
    target_serial:  const u8[:],
    out:            tls::ParsedOcspResponse&,
) -> bool {
    var resp_type_oid = core::cursor_from(resp_bytes_seq.buf[..0]);
    if !tls::get_asn1_element(resp_bytes_seq, rfc::ASN1_TAG_OID, resp_type_oid) { return false; }
    guard resp_type_oid.buf == rfc::OID_OCSP_BASIC[..] else { return false; }

    var resp_oct = core::cursor_from(resp_bytes_seq.buf[..0]);
    if !tls::get_asn1_element(resp_bytes_seq, rfc::ASN1_TAG_OCTET_STRING, resp_oct) { return false; }
    guard resp_bytes_seq.cursor_len() == 0 else { return false; }

    var basic_seq = core::cursor_from(resp_oct.buf[..0]);
    if !tls::get_asn1_element(resp_oct, rfc::ASN1_TAG_SEQUENCE, basic_seq) { return false; }
    guard resp_oct.cursor_len() == 0 else { return false; }

    let tbs_raw_start = basic_seq.buf;
    var tbs_resp_data = core::cursor_from(basic_seq.buf[..0]);
    if !tls::get_asn1_element(basic_seq, rfc::ASN1_TAG_SEQUENCE, tbs_resp_data) { return false; }
    let tbs_tlv_len = core::sub_sat_i64(tbs_raw_start.len, basic_seq.buf.len);
    out.tbs_raw = tls::make_span(raw_ocsp, tbs_raw_start[..tbs_tlv_len]);

    guard x509_skip_ocsp_version_and_id(tbs_resp_data) else { return false; }

    var prod_time = core::cursor_from(tbs_resp_data.buf[..0]);
    if !tls::get_asn1_element(tbs_resp_data, rfc::ASN1_TAG_GENERALIZED_TIME, prod_time) { return false; }

    var responses_seq = core::cursor_from(tbs_resp_data.buf[..0]);
    if !tls::get_asn1_element(tbs_resp_data, rfc::ASN1_TAG_SEQUENCE, responses_seq) { return false; }

    guard x509_parse_ocsp_responses_list(responses_seq, raw_ocsp, target_serial, out) else { return false; }
    guard x509_check_ocsp_ext_list(tbs_resp_data, 0xA1) else { return false; }

    return x509_ocsp_read_basic_sig(basic_seq, raw_ocsp, out);
}

// Parses a DER-encoded OCSPResponse and selects the SingleResponse matching `target_serial` (RFC 6960 Section 4.2.1).
//
// Example:
//   raw_ocsp = 0x30 ... (DER encoded OCSPResponse), target_serial = "\x42"
//   returns: ok = true, out filled with matching cert status
fn parse_ocsp_response_for_serial(
    raw_ocsp:      const u8[:],
    target_serial: const u8[:],
    out:           tls::ParsedOcspResponse&,
) -> bool {
    out = tls::ParsedOcspResponse {};
    var committed = false;
    defer if !committed { out = tls::ParsedOcspResponse {}; };

    var c = core::cursor_from(raw_ocsp);
    var ocsp_seq = core::cursor_from(raw_ocsp[..0]);
    if !tls::get_asn1_element(c, rfc::ASN1_TAG_SEQUENCE, ocsp_seq) { return false; }
    guard c.cursor_len() == 0 else { return false; }

    var status_oct = core::cursor_from(ocsp_seq.buf[..0]);
    if !tls::get_asn1_element(ocsp_seq, rfc::ASN1_TAG_ENUMERATED, status_oct) { return false; }
    guard status_oct.buf.len == 1 else { return false; }

    guard x509_parse_ocsp_status(status_oct.buf[0], out.status) else { return false; }
    if out.status != tls::OcspResponseStatus.Successful {
        guard ocsp_seq.cursor_len() == 0 else { return false; }
        committed = true;
        return true;
    }

    guard ocsp_seq.cursor_len() > 0 else { return false; }
    var resp_bytes_ctx = core::cursor_from(ocsp_seq.buf[..0]);
    if !tls::get_asn1_element(ocsp_seq, 0xA0, resp_bytes_ctx) { return false; }
    guard ocsp_seq.cursor_len() == 0 else { return false; }

    var resp_bytes_seq = core::cursor_from(resp_bytes_ctx.buf[..0]);
    if !tls::get_asn1_element(resp_bytes_ctx, rfc::ASN1_TAG_SEQUENCE, resp_bytes_seq) { return false; }
    guard resp_bytes_ctx.cursor_len() == 0 else { return false; }

    guard x509_parse_ocsp_basic_response(resp_bytes_seq, raw_ocsp, target_serial, out) else { return false; }
    committed = true;
    return true;
}

fn x509_validate_ocsp_temporal(resp: const tls::ParsedOcspResponse&, now_unix: i64) -> tls::Alert {
    if resp.has_next_update && resp.this_update > resp.next_update {
        return tls::Alert.BadCertificateStatusResponse;
    }
    if now_unix < resp.this_update {
        return tls::Alert.CertificateExpired;
    }
    if resp.has_next_update && now_unix > resp.next_update {
        return tls::Alert.CertificateExpired;
    }
    return tls::Alert.CloseNotify;
}

// RFC 6960 Section 4.1.1: ASN.1 Specification of the OCSP Request - Validates CertID hashAlgorithm OID and hash lengths.
inline fn x509_validate_ocsp_cert_id_alg(resp: const tls::ParsedOcspResponse&, raw_ocsp: const u8[:]) -> bool {
    let alg_oid = tls::span_slice(raw_ocsp, resp.hash_alg_oid);
    let ocsp_nh = tls::span_slice(raw_ocsp, resp.issuer_name_hash);
    let ocsp_kh = tls::span_slice(raw_ocsp, resp.issuer_key_hash);
    if alg_oid == OID_OCSP_SHA256[..] {
        return ocsp_nh.len == 32 && ocsp_kh.len == 32;
    }
    if alg_oid == OID_OCSP_SHA1[..] {
        return ocsp_nh.len == 20 && ocsp_kh.len == 20;
    }
    return false;
}

inline fn x509_verify_ocsp_issuer_name_hash(
    alg_oid:   const u8[:],
    ocsp_nh:   const u8[:],
    issuer_dn: const u8[:],
) -> bool {
    if alg_oid == OID_OCSP_SHA256[..] && ocsp_nh.len == 32 {
        let h = core::sha256(issuer_dn);
        return core::ct_eq_bytes(ocsp_nh, h[..]);
    }
    if alg_oid == OID_OCSP_SHA1[..] && ocsp_nh.len == 20 {
        let h = core::sha1(issuer_dn);
        return core::ct_eq_bytes(ocsp_nh, h[..]);
    }
    return false;
}

// RFC 6960 Section 4.1.1: ASN.1 Specification of the OCSP Request - Verifies hashAlgorithm, issuerNameHash, and issuerKeyHash.
fn x509_verify_ocsp_cert_id_material(
    resp:              const tls::ParsedOcspResponse&,
    raw_ocsp:          const u8[:],
    issuer_subject_dn: const u8[:],
    issuer_pubkey_val: const u8[:],
) -> bool {
    guard issuer_subject_dn.len > 0 && issuer_pubkey_val.len > 0 else { return false; }
    let alg_oid = tls::span_slice(raw_ocsp, resp.hash_alg_oid);
    let ocsp_nh = tls::span_slice(raw_ocsp, resp.issuer_name_hash);
    let ocsp_kh = tls::span_slice(raw_ocsp, resp.issuer_key_hash);
    if alg_oid == OID_OCSP_SHA256[..] {
        guard ocsp_nh.len == 32 && ocsp_kh.len == 32 else { return false; }
        let nh = core::sha256(issuer_subject_dn);
        let kh = core::sha256(issuer_pubkey_val);
        return core::ct_eq_bytes(ocsp_nh, nh[..]) && core::ct_eq_bytes(ocsp_kh, kh[..]);
    }
    if alg_oid == OID_OCSP_SHA1[..] {
        guard ocsp_nh.len == 20 && ocsp_kh.len == 20 else { return false; }
        let nh = core::sha1(issuer_subject_dn);
        let kh = core::sha1(issuer_pubkey_val);
        return core::ct_eq_bytes(ocsp_nh, nh[..]) && core::ct_eq_bytes(ocsp_kh, kh[..]);
    }
    return false;
}

fn x509_verify_ocsp_cert_id_with_issuer(
    resp:           const tls::ParsedOcspResponse&,
    raw_ocsp:       const u8[:],
    leaf_cert:      const tls::ParsedCert&,
    leaf_raw:       const u8[:],
    issuer_cert:    const tls::ParsedCert&,
    issuer_raw_der: const u8[:],
) -> bool {
    let issuer_subject = tls::span_slice(issuer_raw_der, issuer_cert.subject_raw);
    if leaf_cert.issuer_raw.length > 0 {
        guard issuer_subject == tls::span_slice(leaf_raw, leaf_cert.issuer_raw) else { return false; }
    }
    let pk_bits = tls::span_slice(issuer_raw_der, issuer_cert.spki_pubkey);
    guard pk_bits.len >= 2 && pk_bits[0] == 0 else { return false; }
    return x509_verify_ocsp_cert_id_material(resp, raw_ocsp, issuer_subject, pk_bits[1..]);
}

fn x509_verify_ocsp_signature_with_pubkey(
    resp:          const tls::ParsedOcspResponse&,
    raw_ocsp:      const u8[:],
    parent_pubkey: const u8[:],
) -> tls::Alert {
    guard resp.signature.length > 0 && resp.tbs_raw.length > 0 && parent_pubkey.len > 0 else {
        return tls::Alert.BadCertificateStatusResponse;
    }
    let sig_oid = tls::span_slice(raw_ocsp, resp.sig_alg_oid);
    let tbs_data = tls::span_slice(raw_ocsp, resp.tbs_raw);
    let sig_bytes = tls::span_slice(raw_ocsp, resp.signature);
    return x509_verify_signature_by_oid(
        sig_oid, tbs_data, sig_bytes, parent_pubkey, tls::Alert.BadCertificateStatusResponse,
    );
}

inline fn validate_crl_serial_length(serial_bytes: const u8[:]) -> bool {
    guard tls::validate_asn1_integer(serial_bytes, true) else { return false; }
    var start: i64 = 0;
    if serial_bytes.len > 1 && serial_bytes[0] == 0x00 {
        start = 1;
    }
    let sig_len = core::sub_sat_i64(serial_bytes.len, start);
    return sig_len > 0 && sig_len <= 20;
}

// RFC 5280 Section 5.2: CRL Extensions - Rejects empty extension lists and unrecognized critical extensions.
fn validate_no_critical_x509_extensions(ext_seq_raw: const u8[:]) -> bool {
    guard ext_seq_raw.len > 0 else { return false; }
    var seq = core::cursor_from(ext_seq_raw);
    while seq.cursor_len() > 0 {
        var single_ext = core::cursor_from(seq.buf[..0]);
        guard tls::get_asn1_element(seq, rfc::ASN1_TAG_SEQUENCE, single_ext) else { return false; }
        var oid = core::cursor_from(single_ext.buf[..0]);
        guard tls::get_asn1_element(single_ext, rfc::ASN1_TAG_OID, oid) && oid.buf.len > 0 else { return false; }
        // RFC 5280 Section 5.3: CRL Entry Extensions - Unrecognized critical extensions MUST be rejected.
        if single_ext.cursor_len() > 0 && single_ext.buf[0] == rfc::ASN1_TAG_BOOLEAN {
            return false;
        }
        var ext_oct = core::cursor_from(single_ext.buf[..0]);
        guard tls::get_asn1_element(single_ext, rfc::ASN1_TAG_OCTET_STRING, ext_oct) &&
            single_ext.cursor_len() == 0 else {
            return false;
        }
    }
    return true;
}

// RFC 5280 Section 5.1.1.2: signatureAlgorithm - Verifies full outer/inner AlgorithmIdentifier match.
fn x509_crl_read_outer_sig(
    crl_seq:           core::ByteCursor&,
    raw_crl:           const u8[:],
    inner_sig_alg_raw: const u8[:],
    out:               tls::ParsedCrl&,
) -> bool {
    guard crl_seq.cursor_len() > 0 else { return false; }
    var outer_sig_alg = core::cursor_from(crl_seq.buf[..0]);
    guard tls::get_asn1_element(crl_seq, rfc::ASN1_TAG_SEQUENCE, outer_sig_alg) else { return false; }
    let outer_sig_alg_raw = outer_sig_alg.buf;
    var outer_sig_oid = core::cursor_from(outer_sig_alg.buf[..0]);
    guard tls::get_asn1_element(outer_sig_alg, rfc::ASN1_TAG_OID, outer_sig_oid) else { return false; }
    guard outer_sig_alg_raw == inner_sig_alg_raw else { return false; }
    out.sig_alg_oid = tls::make_span(raw_crl, outer_sig_oid.buf);

    guard crl_seq.cursor_len() > 0 else { return false; }
    var sig_bits = core::cursor_from(crl_seq.buf[..0]);
    var unused_bits: u8 = 0;
    guard tls::get_asn1_bit_string(crl_seq, sig_bits, unused_bits) && unused_bits == 0 else { return false; }
    out.signature = tls::make_span(raw_crl, sig_bits.buf);
    return crl_seq.cursor_len() == 0;
}

inline fn x509_crl_read_optional_next_update(tbs_cert_list: core::ByteCursor&, out_next: i64&) -> bool {
    out_next = 0;
    guard tbs_cert_list.cursor_len() > 0 else { return true; }
    let next_tag = tbs_cert_list.buf[0];
    guard next_tag == rfc::ASN1_TAG_UTC_TIME || next_tag == rfc::ASN1_TAG_GENERALIZED_TIME else {
        return true;
    }
    var next_up_tag: u8 = 0;
    var next_up_elem = core::cursor_from(tbs_cert_list.buf[..0]);
    guard tls::get_any_asn1_element(tbs_cert_list, next_up_tag, next_up_elem) else { return false; }
    let next_sec, ok_next = tls::parse_asn1_time(next_up_tag, next_up_elem.buf);
    guard ok_next else { return false; }
    out_next = next_sec;
    return true;
}

inline fn x509_crl_read_optional_exts(tbs_cert_list: core::ByteCursor&, is_v2: bool) -> bool {
    guard tbs_cert_list.cursor_len() > 0 else { return true; }
    var ext_ctx = core::cursor_from(tbs_cert_list.buf[..0]);
    var ext_seq = core::cursor_from(tbs_cert_list.buf[..0]);
    guard is_v2 &&
        tls::get_asn1_element(tbs_cert_list, 0xA0, ext_ctx) &&
        tls::get_asn1_element(ext_ctx, rfc::ASN1_TAG_SEQUENCE, ext_seq) &&
        ext_ctx.cursor_len() == 0 &&
        validate_no_critical_x509_extensions(ext_seq.buf) else {
        return false;
    }
    return tbs_cert_list.cursor_len() == 0;
}

// Verifies cryptographic signature on an X.509 CRL against raw issuer public key material.
fn x509_verify_crl_signature_with_pubkey(
    crl:           const tls::ParsedCrl&,
    raw_crl:       const u8[:],
    parent_pubkey: const u8[:],
) -> tls::Alert {
    guard crl.signature.length > 0 && crl.tbs_raw.length > 0 && parent_pubkey.len > 0 else {
        return tls::Alert.BadCertificate;
    }
    let sig_oid = tls::span_slice(raw_crl, crl.sig_alg_oid);
    let tbs_data = tls::span_slice(raw_crl, crl.tbs_raw);
    let sig_bytes = tls::span_slice(raw_crl, crl.signature);
    return x509_verify_signature_by_oid(sig_oid, tbs_data, sig_bytes, parent_pubkey, tls::Alert.BadCertificate);
}
