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
import .pki_internal;

// Inserts a 64-bit certificate serial number into `crl.serials` in ascending
// sorted order. Fails closed with `false` if `crl.serials.len >= 1024` (Invariant 13).
fn crl_insert_serial(crl: ParsedCrl&, serial: u64) -> bool {
    guard crl.serials.len < tls_internal::MAX_CRL_SERIALS else {
        return false;
    }

    let lo, found = tls_internal::crl_find_serial_slot(crl.serials[..], serial);
    if found {
        // RFC 5280 Section 5.1.2.6: Revoked Certificates - Reject duplicate serial entries.
        return false;
    }

    crl.serials.push(serial);
    var idx = core::sub_sat_i64(crl.serials.len, 1);
    while idx > lo {
        let prev_idx = core::sub_sat_i64(idx, 1);
        crl.serials[idx] = crl.serials[prev_idx];
        idx = prev_idx;
    }
    crl.serials[lo] = serial;
    crl.serial_count = crl.serials.len as i32;
    return true;
}

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

// Parses an ASN.1 INTEGER serial from a revoked certificate entry (RFC 5280 §5.1.2.6).
//
// Example:
//   serial_bytes = [0x01, 0x02], out = ParsedCrl { .. }
//   returns: true
fn parse_crl_entry_serial(serial_bytes: const u8[:], out: ParsedCrl&) -> bool {
    let serial_u64, ok_ser = parse_asn1_serial_u64(serial_bytes);
    guard ok_ser else { return false; }
    return crl_insert_serial(out, serial_u64);
}

// Parses a single revoked certificate entry SEQUENCE (RFC 5280 §5.1.2.6).
//
// Example:
//   entry_raw = [0x02, 0x01, 0x05, 0x17, 0x0D], out = ParsedCrl { .. }
//   returns: true
fn parse_crl_single_entry_raw(entry_raw: const u8[:], out: ParsedCrl&) -> bool {
    var entry_seq = core::cursor_from(entry_raw);
    var serial_elem = core::cursor_from(entry_seq.buf[..0]);
    guard get_asn1_element(entry_seq, rfc::ASN1_TAG_INTEGER, serial_elem) else { return false; }
    guard parse_crl_entry_serial(serial_elem.buf, out) else { return false; }

    var rev_time_tag: u8 = 0;
    var rev_time_elem = core::cursor_from(entry_seq.buf[..0]);
    guard get_any_asn1_element(entry_seq, rev_time_tag, rev_time_elem) else { return false; }
    let _, ok_time = parse_asn1_time(rev_time_tag, rev_time_elem.buf);
    guard ok_time else { return false; }
    if entry_seq.cursor_len() > 0 {
        var entry_exts = core::cursor_from(entry_seq.buf[..0]);
        guard get_asn1_element(entry_seq, rfc::ASN1_TAG_SEQUENCE, entry_exts) &&
            tls_internal::validate_no_critical_x509_extensions(entry_exts.buf) else {
            return false;
        }
    }
    return entry_seq.cursor_len() == 0;
}

// Parses a sequence of revokedCertificates entries from a TBSCertList (RFC 5280 Section 5.1.2.6).
// Supports serial numbers up to 20 octets (RFC 5280 Section 4.1.2.2).
//
// Example:
//   revoked_raw = [0x30, ...] (DER SEQUENCE OF RevokedCertificate)
//   returns: ok = true, populates out.serials in sorted order
fn parse_crl_revoked_entries(revoked_raw: const u8[:], out: ParsedCrl&) -> bool {
    var revoked_seq = core::cursor_from(revoked_raw);
    while revoked_seq.cursor_len() > 0 {
        var entry_seq = core::cursor_from(revoked_seq.buf[..0]);
        guard get_asn1_element(revoked_seq, rfc::ASN1_TAG_SEQUENCE, entry_seq) else {
            return false;
        }
        guard parse_crl_single_entry_raw(entry_seq.buf, out) else {
            return false;
        }
    }
    return true;
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
            parse_crl_revoked_entries(revoked_seq.buf, out) else {
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

fn crl_track_unique_serial(seen: u64[..1024]&, track_dups: bool&, ser_u64: u64) -> bool {
    guard track_dups else { return true; }
    let lo, found = tls_internal::crl_find_serial_slot(seen[..], ser_u64);
    guard !found else { return false; }
    guard seen.len < tls_internal::MAX_CRL_SERIALS else {
        track_dups = false;
        return true;
    }
    seen.push(ser_u64);
    var idx = core::sub_sat_i64(seen.len, 1);
    while idx > lo {
        let prev_idx = core::sub_sat_i64(idx, 1);
        seen[idx] = seen[prev_idx];
        idx = prev_idx;
    }
    seen[lo] = ser_u64;
    return true;
}

fn crl_scan_single_revoked_entry(
    entry_raw:     const u8[:],
    target_serial: u64,
    seen:          u64[..1024]&,
    track_dups:    bool&,
    out_revoked:   bool&,
) -> bool {
    var entry_seq = core::cursor_from(entry_raw);
    var serial_elem = core::cursor_from(entry_seq.buf[..0]);
    guard get_asn1_element(entry_seq, rfc::ASN1_TAG_INTEGER, serial_elem) else { return false; }
    let ser_u64, ok_ser = parse_asn1_serial_u64(serial_elem.buf);
    guard ok_ser && crl_track_unique_serial(seen, track_dups, ser_u64) else { return false; }
    if ser_u64 == target_serial {
        out_revoked = true;
    }
    var rev_time_tag: u8 = 0;
    var rev_time_elem = core::cursor_from(entry_seq.buf[..0]);
    guard get_any_asn1_element(entry_seq, rev_time_tag, rev_time_elem) else { return false; }
    let _, ok_time = parse_asn1_time(rev_time_tag, rev_time_elem.buf);
    guard ok_time else { return false; }
    if entry_seq.cursor_len() > 0 {
        var entry_exts = core::cursor_from(entry_seq.buf[..0]);
        guard get_asn1_element(entry_seq, rfc::ASN1_TAG_SEQUENCE, entry_exts) &&
            tls_internal::validate_no_critical_x509_extensions(entry_exts.buf) else {
            return false;
        }
    }
    return entry_seq.cursor_len() == 0;
}

fn crl_stream_revoked_entries(
    revoked_raw:   const u8[:],
    target_serial: u64,
    out_revoked:   bool&,
) -> bool {
    var seen: u64[..1024] = [];
    var track_dups = true;
    var revoked_seq = core::cursor_from(revoked_raw);
    while revoked_seq.cursor_len() > 0 {
        var entry_seq = core::cursor_from(revoked_seq.buf[..0]);
        guard get_asn1_element(revoked_seq, rfc::ASN1_TAG_SEQUENCE, entry_seq) else { return false; }
        guard crl_scan_single_revoked_entry(
            entry_seq.buf, target_serial, seen, track_dups, out_revoked,
        ) else {
            return false;
        }
    }
    return true;
}

fn crl_verify_outer_signature_raw(
    crl_seq:           core::ByteCursor&,
    tbs_data:          const u8[:],
    inner_sig_alg_raw: const u8[:],
    pss_hash_id:       u8,
    issuer_cert:       const ParsedCert&,
    issuer_raw:        const u8[:],
) -> Alert {
    var outer_sig_alg = core::cursor_from(crl_seq.buf[..0]);
    var outer_sig_oid = core::cursor_from(crl_seq.buf[..0]);
    var sig_bits = core::cursor_from(crl_seq.buf[..0]);
    var unused_bits: u8 = 0;
    guard get_asn1_element(crl_seq, rfc::ASN1_TAG_SEQUENCE, outer_sig_alg) &&
        outer_sig_alg.buf == inner_sig_alg_raw &&
        get_asn1_element(outer_sig_alg, rfc::ASN1_TAG_OID, outer_sig_oid) &&
        get_asn1_bit_string(crl_seq, sig_bits, unused_bits) &&
        unused_bits == 0 &&
        crl_seq.cursor_len() == 0 else {
        return Alert.DecodeError;
    }
    var parent_pubkey = span_slice(issuer_raw, issuer_cert.spki_pubkey);
    if parent_pubkey.len >= 2 && parent_pubkey[0] == 0 {
        parent_pubkey = parent_pubkey[1..];
    }
    return tls_internal::x509_verify_signature_by_oid(
        outer_sig_oid.buf, tbs_data, sig_bits.buf, parent_pubkey, Alert.BadCertificate, pss_hash_id,
    );
}

fn crl_parse_tbs_header(
    tbs:          core::ByteCursor&,
    iss_subj:     const u8[:],
    out_is_v2:    bool&,
    out_pss_hash: u8&,
    out_this_sec: i64&,
    out_next_sec: i64&,
) -> const u8[:], Alert {
    let empty = tbs.buf[..0];
    out_is_v2 = false;
    if tbs.cursor_len() > 0 && tbs.buf[0] == rfc::ASN1_TAG_INTEGER {
        var ver: i64 = -1;
        guard get_asn1_integer(tbs, ver) && (ver == 0 || ver == 1) else { return empty, Alert.DecodeError; }
        out_is_v2 = ver == 1;
    }
    var sig_alg = core::cursor_from(empty);
    var sig_oid = core::cursor_from(empty);
    guard get_asn1_element(tbs, rfc::ASN1_TAG_SEQUENCE, sig_alg) else { return empty, Alert.DecodeError; }
    let inner_sig_alg_raw = sig_alg.buf;
    guard get_asn1_element(sig_alg, rfc::ASN1_TAG_OID, sig_oid) &&
        tls_internal::validate_x509_sig_alg_params(sig_oid.buf, sig_alg, out_pss_hash) else {
        return empty, Alert.DecodeError;
    }
    var issuer_seq = core::cursor_from(empty);
    guard get_asn1_element(tbs, rfc::ASN1_TAG_SEQUENCE, issuer_seq) else { return empty, Alert.DecodeError; }
    guard issuer_seq.buf.len > 0 && issuer_seq.buf == iss_subj else { return empty, Alert.UnknownCa; }

    var this_tag: u8 = 0;
    var this_el = core::cursor_from(empty);
    guard get_any_asn1_element(tbs, this_tag, this_el) else { return empty, Alert.DecodeError; }
    let this_sec, ok_this = parse_asn1_time(this_tag, this_el.buf);
    guard ok_this && tls_internal::x509_crl_read_optional_next_update(tbs, out_next_sec) else {
        return empty, Alert.DecodeError;
    }
    out_this_sec = this_sec;
    return inner_sig_alg_raw, Alert.CloseNotify;
}

fn crl_scan_optional_revoked(
    tbs:           core::ByteCursor&,
    target_serial: u64,
    out_revoked:   bool&,
) -> bool {
    guard tbs.cursor_len() > 0 && tbs.buf[0] == rfc::ASN1_TAG_SEQUENCE else { return true; }
    var rev_seq = core::cursor_from(tbs.buf[..0]);
    return get_asn1_element(tbs, rfc::ASN1_TAG_SEQUENCE, rev_seq) &&
        crl_stream_revoked_entries(rev_seq.buf, target_serial, out_revoked);
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
    let inner_sig_alg_raw, hdr_alert = crl_parse_tbs_header(
        tbs, span_slice(issuer_raw, issuer_cert.subject_raw), is_v2, pss_hash_id, this_sec, next_sec,
    );
    guard hdr_alert == Alert.CloseNotify else { return hdr_alert; }

    var revoked = false;
    guard crl_scan_optional_revoked(tbs, target_serial, revoked) &&
        tls_internal::x509_crl_read_optional_exts(tbs, is_v2) else {
        return Alert.DecodeError;
    }
    let sig_alert = crl_verify_outer_signature_raw(
        crl_seq, tbs_tlv, inner_sig_alg_raw, pss_hash_id, issuer_cert, issuer_raw,
    );
    guard sig_alert == Alert.CloseNotify else { return sig_alert; }
    guard now_unix >= this_sec && (next_sec == 0 || now_unix <= next_sec) else {
        return Alert.CertificateExpired;
    }
    return if revoked { Alert.CertificateRevoked } else { Alert.CloseNotify };
}
