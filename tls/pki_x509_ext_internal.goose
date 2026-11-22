// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal X.509 TBSCertificate and v3 extension DER parsing helpers (RFC 5280).
namespace tls_internal;

import std;
import core;
import .internal;
import .asn1;
import .record;
import .types;
import .sct;
import .pki_sig_internal;

inline fn is_known_pki_extension_oid(oid: const u8[:]) -> bool {
    return oid == rfc::OID_EXT_KEY_USAGE[..] ||
        oid == rfc::OID_TLS_FEATURE[..] ||
        oid == rfc::OID_CT_PRECERT_SCTS[..] ||
        oid == rfc::OID_AIA[..];
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
    // RFC 5280 Section 4.1.2.2: Serial Number - Accept legacy serial 0 (e.g. GoDaddy Root G2) per interop note.
    let is_zero_serial = serial.buf.len == 1 && serial.buf[0] == 0x00;
    if !is_zero_serial && !tls::validate_asn1_integer(serial.buf, true) { return false; }
    out.serial_number = tls::make_span(raw_cert, serial.buf);
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
    guard validate_x509_sig_alg_params(sig_oid.buf, sig_alg, out.pss_hash_id) else {
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

fn x509_parse_basic_constraints_ext(
    ext_val:     core::ByteCursor&,
    cert:        tls::ParsedCert&,
    is_critical: bool = false,
) {
    if cert.has_basic_constraints {
        cert.has_unsupported_critical = true;
        return;
    }
    cert.has_basic_constraints = true;
    cert.bc_is_critical = is_critical;
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

    var ku: u16 = core::shl_sat_u64(ku_bits.buf[1], 8) as u16;
    if ku_bits.buf.len >= 3 {
        ku = ku | ku_bits.buf[2];
    }
    cert.key_usage = ku;
}

fn x509_parse_akid_ext(
    raw_cert:    const u8[:],
    ext_val:     core::ByteCursor&,
    is_critical: bool,
    cert:        tls::ParsedCert&,
) {
    // RFC 5280 Section 4.2.1.1: Authority Key Identifier - Extension MUST be non-critical.
    if cert.has_akid_ext || is_critical {
        cert.has_unsupported_critical = true;
        return;
    }
    cert.has_akid_ext = true;
    var akid_seq = core::cursor_from(ext_val.buf[..0]);
    guard tls::get_asn1_element(ext_val, rfc::ASN1_TAG_SEQUENCE, akid_seq) && ext_val.cursor_len() == 0 else {
        cert.has_unsupported_critical = true;
        return;
    }
    guard akid_seq.cursor_len() > 0 else { return; }
    if akid_seq.buf[0] != 0x80 {
        cert.akid_has_extra_fields = true;
        return;
    }
    var akid_key = core::cursor_from(akid_seq.buf[..0]);
    guard tls::get_asn1_element(akid_seq, 0x80, akid_key) else {
        cert.has_unsupported_critical = true;
        return;
    }
    if akid_seq.cursor_len() > 0 {
        cert.akid_has_extra_fields = true;
    }
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

fn x509_parse_policy_constraints_ext(
    ext_val:     core::ByteCursor&,
    is_critical: bool,
    cert:        tls::ParsedCert&,
) {
    // RFC 5280 Section 4.2.1.11: Policy Constraints - Extension MUST be marked critical.
    if !is_critical {
        cert.has_malformed_policy_constraints = true;
        return;
    }
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
fn x509_parse_eku_ext(ext_val: const u8[:], cert: tls::ParsedCert&, is_critical: bool = false) -> bool {
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
    cert.eku_is_critical = is_critical;
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

// Parses RFC 5280 Section 4.2.2.1 Authority Information Access (`SEQUENCE SIZE (1..MAX) OF AccessDescription`).
// Rejects critical AIA, empty lists, non-OID accessMethod, and malformed AccessDescription entries.
//
// Example:
//   ext_val = SEQUENCE { SEQUENCE { OID(id-ad-ocsp), [6] "http://ocsp.example.com" } }
//   returns: true
fn x509_parse_aia_ext(ext_val: const u8[:], is_critical: bool, cert: tls::ParsedCert&) -> bool {
    guard !is_critical else {
        cert.has_unsupported_critical = true;
        return false;
    }
    var c = core::cursor_from(ext_val);
    var aia_seq = core::cursor_from(ext_val[..0]);
    guard tls::get_asn1_element(c, rfc::ASN1_TAG_SEQUENCE, aia_seq) &&
        c.cursor_len() == 0 &&
        aia_seq.cursor_len() > 0 else {
        cert.has_unsupported_critical = true;
        return false;
    }
    while aia_seq.cursor_len() > 0 {
        var desc = core::cursor_from(aia_seq.buf[..0]);
        var method_oid = core::cursor_from(aia_seq.buf[..0]);
        var loc = core::cursor_from(aia_seq.buf[..0]);
        var loc_tag: u8 = 0;
        guard tls::get_asn1_element(aia_seq, rfc::ASN1_TAG_SEQUENCE, desc) &&
            tls::get_asn1_element(desc, rfc::ASN1_TAG_OID, method_oid) &&
            method_oid.buf.len > 0 &&
            tls::get_any_asn1_element(desc, loc_tag, loc) &&
            desc.cursor_len() == 0 &&
            (loc_tag & 0xC0) == 0x80 &&
            (loc_tag & 0x1F) <= 8 else {
            cert.has_unsupported_critical = true;
            return false;
        }
    }
    return true;
}

fn x509_dispatch_pki_extension(
    oid:         const u8[:],
    ext_val:     core::ByteCursor&,
    is_critical: bool,
    cert:        tls::ParsedCert&,
) -> bool {
    if oid == rfc::OID_EXT_KEY_USAGE[..] {
        return x509_parse_eku_ext(ext_val.buf, cert, is_critical);
    } else if oid == rfc::OID_AIA[..] {
        return x509_parse_aia_ext(ext_val.buf, is_critical, cert);
    } else if oid == rfc::OID_TLS_FEATURE[..] {
        return x509_parse_tls_feature_ext(ext_val.buf, cert);
    } else if oid == rfc::OID_CT_PRECERT_SCTS[..] {
        return x509_parse_sct_ext(ext_val, cert);
    }
    return true;
}

fn x509_dispatch_policy_extension(
    oid:         const u8[:],
    ext_val:     core::ByteCursor&,
    is_critical: bool,
    cert:        tls::ParsedCert&,
) -> bool {
    if oid == rfc::OID_POLICY_CONSTRAINTS[..] {
        x509_parse_policy_constraints_ext(ext_val, is_critical, cert);
        return true;
    } else if oid == rfc::OID_INHIBIT_ANY_POLICY[..] {
        var val: i64 = 0;
        if !tls::get_asn1_integer(ext_val, val) || ext_val.cursor_len() != 0 || val < 0 {
            cert.has_malformed_policy_constraints = true;
        }
        return true;
    }
    return x509_dispatch_pki_extension(oid, ext_val, is_critical, cert);
}

fn x509_dispatch_extension(
    raw_cert:    const u8[:],
    oid:         const u8[:],
    ext_val:     core::ByteCursor&,
    cert:        tls::ParsedCert&,
    is_critical: bool = false,
) -> bool {
    if oid == rfc::OID_BASIC_CONSTRAINTS[..] {
        x509_parse_basic_constraints_ext(ext_val, cert, is_critical);
        return true;
    } else if oid == rfc::OID_KEY_USAGE[..] {
        x509_parse_key_usage_ext(ext_val, cert);
        return true;
    } else if oid == rfc::OID_SUBJECT_ALT_NAME[..] {
        if cert.has_san {
            cert.has_unsupported_critical = true;
            return true;
        }
        cert.has_san = true;
        cert.san_is_critical = is_critical;
        cert.san_raw = tls::make_span(raw_cert, ext_val.buf);
        return true;
    } else if oid == rfc::OID_NAME_CONSTRAINTS[..] {
        if cert.has_name_constraints {
            cert.has_unsupported_critical = true;
            return true;
        }
        cert.has_name_constraints = true;
        cert.name_constraints_raw = tls::make_span(raw_cert, ext_val.buf);
        return true;
    } else if oid == rfc::OID_AUTH_KEY_IDENTIFIER[..] {
        x509_parse_akid_ext(raw_cert, ext_val, is_critical, cert);
        return true;
    } else if oid == rfc::OID_SUBJECT_KEY_IDENTIFIER[..] {
        x509_parse_skid_ext(raw_cert, ext_val, cert);
        return true;
    }
    return x509_dispatch_policy_extension(oid, ext_val, is_critical, cert);
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

    return x509_dispatch_extension(raw_cert, oid.buf, ext_val, cert, is_critical);
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
