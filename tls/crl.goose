// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 5280 Section 5 X.509 Certificate Revocation List (CRL) DER parser and O(log N) binary-search lookup.
namespace tls;

import std;
import core;
import .internal;
import .record;
import .asn1;
import .types;
import .x509;
import .pki_sig_internal;
import .pki_x509_ext_internal;
import .pki_nc_san_internal;
import .pki_ocsp_internal;
import .pki_crl_internal;

// Inserts a 64-bit certificate serial number into `crl.serials` in ascending
// sorted order. Fails closed with `false` if `crl.serials.len >= 1024` (Invariant 13).

// Queries whether `serial` is present in `crl.serials` using O(log N) binary search.
fn crl_is_revoked(crl: const ParsedCrl&, serial: u64) -> bool {
    let _, found = tls_internal::crl_find_serial_slot(crl.serials[..], serial);
    return found;
}

// Decodes a positive ASN.1 DER INTEGER (1..20 significant bytes, RFC 5280 Section 4.1.2.2) into a
// canonical `u64` serial identifier: exact big-endian value for 1..7 significant bytes, or a 64-bit
// truncated SHA-256 digest (with high bit set) for 8..20 significant bytes so the domains never collide.
//
// Example:
//   serial_bytes = [0x01, 0x02]
//   returns: val = 0x0102, ok = true
fn parse_asn1_serial_u64(serial_bytes: const u8[:]) -> u64, bool {
    guard tls_internal::validate_crl_serial_length(serial_bytes) else {
        return 0, false;
    }
    var start: i64 = 0;
    if serial_bytes.len > 1 && serial_bytes[0] == 0x00 {
        start = 1;
    }
    let sig_len = core::sub_sat_i64(serial_bytes.len, start);
    if sig_len <= 7 {
        var val: u64 = 0;
        for i in sig_len {
            let b = serial_bytes[core::add_sat_i64(start, i)] as u64;
            val = core::mul_sat_u64(val, 256) | b;
        }
        return val, true;
    }
    let h = core::sha256(serial_bytes[start..]);
    return core::read_be_u64(h[..], 0) | 0x8000000000000000, true;
}

// Parses an X.509 CertificateList (CRL) in ASN.1 DER format (RFC 5280 Section 5.1).
// Extracts the issuer Name slice and populates `out.serials` in ascending sorted order.
// Fails closed (`false`) on malformed DER or if revoked serials exceed 1024 (Invariant 13).
//
// Example:
//   raw_crl = [0x30, ...] (DER CertificateList)
//   returns: ok = true, out.issuer and out.serials populated
fn parse_x509_crl(raw_crl: const u8[:], out: ParsedCrl&) -> bool {
    out = ParsedCrl { .. };
    var committed = false;
    defer if !committed { out = ParsedCrl { .. }; };

    var c = core::cursor_from(raw_crl);
    var crl_seq = core::cursor_from(raw_crl[..0]);
    guard get_asn1_element(c, rfc::ASN1_TAG_SEQUENCE, crl_seq) && c.cursor_len() == 0 else {
        return false;
    }

    let tbs_raw_start = crl_seq.buf;
    var tbs_cert_list = core::cursor_from(crl_seq.buf[..0]);
    guard get_asn1_element(crl_seq, rfc::ASN1_TAG_SEQUENCE, tbs_cert_list) else {
        return false;
    }
    let tbs_tlv_len = core::sub_sat_i64(tbs_raw_start.len, crl_seq.buf.len);
    out.tbs_raw = make_span(raw_crl, tbs_raw_start[..tbs_tlv_len]);

    var is_v2 = false;
    if tbs_cert_list.cursor_len() > 0 && tbs_cert_list.buf[0] == rfc::ASN1_TAG_INTEGER {
        var crl_ver: i64 = -1;
        guard get_asn1_integer(tbs_cert_list, crl_ver) && (crl_ver == 0 || crl_ver == 1) else {
            return false;
        }
        is_v2 = crl_ver == 1;
    }

    var sig_alg = core::cursor_from(tbs_cert_list.buf[..0]);
    guard get_asn1_element(tbs_cert_list, rfc::ASN1_TAG_SEQUENCE, sig_alg) else { return false; }
    let inner_sig_alg_raw = sig_alg.buf;
    var inner_sig_oid = core::cursor_from(sig_alg.buf[..0]);
    guard get_asn1_element(sig_alg, rfc::ASN1_TAG_OID, inner_sig_oid) &&
        tls_internal::validate_x509_sig_alg_params(inner_sig_oid.buf, sig_alg, out.pss_hash_id) else {
        return false;
    }

    var issuer_seq = core::cursor_from(tbs_cert_list.buf[..0]);
    guard get_asn1_element(tbs_cert_list, rfc::ASN1_TAG_SEQUENCE, issuer_seq) else { return false; }
    out.issuer = issuer_seq.buf;

    var this_up_tag: u8 = 0;
    var this_up_elem = core::cursor_from(tbs_cert_list.buf[..0]);
    guard get_any_asn1_element(tbs_cert_list, this_up_tag, this_up_elem) else { return false; }
    let this_sec, ok_this = parse_asn1_time(this_up_tag, this_up_elem.buf);
    guard ok_this else { return false; }
    out.this_update = this_sec;
    guard tls_internal::x509_crl_read_optional_next_update(tbs_cert_list, out.next_update) else { return false; }

    if tbs_cert_list.cursor_len() > 0 && tbs_cert_list.buf[0] == rfc::ASN1_TAG_SEQUENCE {
        var revoked_seq = core::cursor_from(tbs_cert_list.buf[..0]);
        guard get_asn1_element(tbs_cert_list, rfc::ASN1_TAG_SEQUENCE, revoked_seq) &&
            tls_internal::parse_crl_revoked_entries(revoked_seq.buf, out) else {
            return false;
        }
    }

    guard tls_internal::x509_crl_read_optional_exts(tbs_cert_list, is_v2) &&
        tls_internal::x509_crl_read_outer_sig(crl_seq, raw_crl, inner_sig_alg_raw, out) else {
        return false;
    }
    committed = true;
    return true;
}

// Verifies cryptographic signature on an X.509 CRL against issuer's certificate.
fn x509_verify_crl_signature(
    crl:         const ParsedCrl&,
    raw_crl:     const u8[:],
    issuer_cert: const ParsedCert&,
    issuer_raw:  const u8[:],
) -> Alert {
    var parent_pubkey = span_slice(issuer_raw, issuer_cert.spki_pubkey);
    if parent_pubkey.len >= 2 && parent_pubkey[0] == 0 {
        parent_pubkey = parent_pubkey[1..];
    }
    return tls_internal::x509_verify_crl_signature_with_pubkey(crl, raw_crl, parent_pubkey);
}

// Streaming RFC 5280 Section 5 CRL verifier without 64 KB Span16 or 1,024-serial limits.
// Checks issuer DN, cRLSign KeyUsage, signature, validity window, and revocation status.
fn check_crl_der_revocation(
    raw_crl:       const u8[:],
    target_serial: u64,
    issuer_cert:   const ParsedCert&,
    issuer_raw:    const u8[:],
    now_unix:      i64,
) -> Alert {
    guard !issuer_cert.has_key_usage || (issuer_cert.key_usage & rfc::KEY_USAGE_CRL_SIGN) != 0 else {
        return Alert.UnsupportedCertificate;
    }
    var c = core::cursor_from(raw_crl);
    var crl_seq = core::cursor_from(raw_crl[..0]);
    guard get_asn1_element(c, rfc::ASN1_TAG_SEQUENCE, crl_seq) && c.cursor_len() == 0 else {
        return Alert.DecodeError;
    }
    let tbs_raw_start = crl_seq.buf;
    var tbs = core::cursor_from(crl_seq.buf[..0]);
    guard get_asn1_element(crl_seq, rfc::ASN1_TAG_SEQUENCE, tbs) else { return Alert.DecodeError; }
    let tbs_tlv = tbs_raw_start[..core::sub_sat_i64(tbs_raw_start.len, crl_seq.buf.len)];

    var is_v2 = false;
    var pss_hash_id: u8  = 0;
    var this_sec:    i64 = 0;
    var next_sec:    i64 = 0;
    let inner_sig_alg_raw, hdr_alert = tls_internal::crl_parse_tbs_header(
        tbs, span_slice(issuer_raw, issuer_cert.subject_raw), is_v2, pss_hash_id, this_sec, next_sec,
    );
    guard hdr_alert == Alert.CloseNotify else { return hdr_alert; }

    var revoked = false;
    guard tls_internal::crl_scan_optional_revoked(tbs, target_serial, revoked) &&
        tls_internal::x509_crl_read_optional_exts(tbs, is_v2) else {
        return Alert.DecodeError;
    }
    let sig_alert = tls_internal::crl_verify_outer_signature_raw(
        crl_seq, tbs_tlv, inner_sig_alg_raw, pss_hash_id, issuer_cert, issuer_raw,
    );
    guard sig_alert == Alert.CloseNotify else { return sig_alert; }
    guard now_unix >= this_sec && (next_sec == 0 || now_unix <= next_sec) else {
        return Alert.CertificateExpired;
    }
    return if revoked { Alert.CertificateRevoked } else { Alert.CloseNotify };
}
