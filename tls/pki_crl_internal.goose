// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal X.509 CRL (RFC 5280) DER parsing, serial tracking, and signature helpers.
namespace tls_internal;

import std;
import core;
import .internal;
import .asn1;
import .record;
import .types;
import .pki_sig_internal;
import .pki_x509_ext_internal;

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
    crl_seq_end:       i64,
    inner_sig_alg_raw: const u8[:],
    out:               tls::ParsedCrl&,
) -> bool {
    guard crl_seq.cursor_len() > 0 else { return false; }
    var outer_sig_alg = core::cursor_from(crl_seq.buf[..0]);
    guard tls::get_asn1_element(crl_seq, rfc::ASN1_TAG_SEQUENCE, outer_sig_alg) else { return false; }
    let outer_sig_alg_end = core::sub_sat_i64(crl_seq_end, crl_seq.cursor_len());
    let outer_sig_alg_raw = outer_sig_alg.buf;
    var outer_sig_oid = core::cursor_from(outer_sig_alg.buf[..0]);
    guard tls::get_asn1_element(outer_sig_alg, rfc::ASN1_TAG_OID, outer_sig_oid) &&
        outer_sig_oid.buf.len > 0 else { return false; }
    guard outer_sig_alg_raw == inner_sig_alg_raw else { return false; }
    out.sig_alg_oid = tls::span_from_end(outer_sig_alg_end, outer_sig_alg.cursor_len(), outer_sig_oid.buf.len);

    guard crl_seq.cursor_len() > 0 else { return false; }
    var sig_bits = core::cursor_from(crl_seq.buf[..0]);
    var unused_bits: u8 = 0;
    guard tls::get_asn1_bit_string(crl_seq, sig_bits, unused_bits) &&
        unused_bits == 0 && sig_bits.buf.len > 0 else { return false; }
    out.signature = tls::span_from_end(crl_seq_end, crl_seq.cursor_len(), sig_bits.buf.len);
    return crl_seq.cursor_len() == 0;
}

inline fn x509_crl_read_optional_next_update(
    tbs_cert_list: core::ByteCursor&,
    out_next:      i64&,
    out_has_next:  bool&,
) -> bool {
    out_next = 0;
    out_has_next = false;
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
    out_has_next = true;
    return true;
}

inline fn crl_validate_temporal(this_sec: i64, next_sec: i64, has_next: bool, now_unix: i64) -> tls::Alert {
    if has_next && this_sec > next_sec {
        return tls::Alert.DecodeError;
    }
    if now_unix < this_sec {
        return tls::Alert.CertificateExpired;
    }
    if has_next {
        if now_unix > next_sec {
            return tls::Alert.CertificateExpired;
        }
        return tls::Alert.CloseNotify;
    }
    // RFC 5280 Section 5.1.2.5: Omitted nextUpdate MUST NOT grant eternal validity.
    if core::sub_sat_i64(now_unix, this_sec) > MAX_REVOCATION_AGE_SECS {
        return tls::Alert.CertificateExpired;
    }
    return tls::Alert.CloseNotify;
}

// Compares two positive ASN.1 DER INTEGER serial values byte-for-byte after stripping any 0x00 sign pad.
inline fn crl_serials_equal_canonical(a: const u8[:], b: const u8[:]) -> bool {
    var sa = a;
    if sa.len > 1 && sa[0] == 0x00 { sa = sa[1..]; }
    var sb = b;
    if sb.len > 1 && sb[0] == 0x00 { sb = sb[1..]; }
    return sa.len > 0 && sa == sb;
}

// RFC 5280 Section 5.2.3: CRL Number - Validates non-negative canonical INTEGER (1..20 significant octets).
fn validate_crl_number_value(ext_oct_raw: const u8[:]) -> bool {
    var c = core::cursor_from(ext_oct_raw);
    var num_elem = core::cursor_from(ext_oct_raw[..0]);
    guard tls::get_asn1_element(c, rfc::ASN1_TAG_INTEGER, num_elem) && c.cursor_len() == 0 else {
        return false;
    }
    let is_zero = num_elem.buf.len == 1 && num_elem.buf[0] == 0x00;
    return is_zero || validate_crl_serial_length(num_elem.buf);
}

// RFC 5280 Section 5.2 & 5.2.3: Validates v2 CRL extensions and enforces mandatory non-critical cRLNumber.
fn validate_v2_crl_extensions(ext_seq_raw: const u8[:]) -> bool {
    guard ext_seq_raw.len > 0 else { return false; }
    var seq = core::cursor_from(ext_seq_raw);
    var has_crl_number = false;
    while seq.cursor_len() > 0 {
        var single_ext = core::cursor_from(seq.buf[..0]);
        guard tls::get_asn1_element(seq, rfc::ASN1_TAG_SEQUENCE, single_ext) else { return false; }
        var oid = core::cursor_from(single_ext.buf[..0]);
        guard tls::get_asn1_element(single_ext, rfc::ASN1_TAG_OID, oid) && oid.buf.len > 0 else { return false; }
        if single_ext.cursor_len() > 0 && single_ext.buf[0] == rfc::ASN1_TAG_BOOLEAN {
            return false;
        }
        var ext_oct = core::cursor_from(single_ext.buf[..0]);
        guard tls::get_asn1_element(single_ext, rfc::ASN1_TAG_OCTET_STRING, ext_oct) &&
            single_ext.cursor_len() == 0 else {
            return false;
        }
        if oid.buf == rfc::OID_CRL_NUMBER[..] {
            guard !has_crl_number && validate_crl_number_value(ext_oct.buf) else { return false; }
            has_crl_number = true;
        }
    }
    return has_crl_number;
}

inline fn x509_crl_read_optional_exts(tbs_cert_list: core::ByteCursor&, is_v2: bool) -> bool {
    if !is_v2 {
        return tbs_cert_list.cursor_len() == 0;
    }
    guard tbs_cert_list.cursor_len() > 0 else { return false; }
    var ext_ctx = core::cursor_from(tbs_cert_list.buf[..0]);
    var ext_seq = core::cursor_from(tbs_cert_list.buf[..0]);
    guard tls::get_asn1_element(tbs_cert_list, 0xA0, ext_ctx) &&
        tls::get_asn1_element(ext_ctx, rfc::ASN1_TAG_SEQUENCE, ext_seq) &&
        ext_ctx.cursor_len() == 0 &&
        validate_v2_crl_extensions(ext_seq.buf) else {
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
    return x509_verify_signature_by_oid(
        sig_oid, tbs_data, sig_bytes, parent_pubkey, tls::Alert.BadCertificate, crl.pss_hash_id,
    );
}

fn crl_insert_serial(crl: tls::ParsedCrl&, serial: u64) -> bool {
    guard crl.serials.len < MAX_CRL_SERIALS else {
        return false;
    }

    let lo, found = crl_find_serial_slot(crl.serials[..], serial);
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

// Parses an ASN.1 INTEGER serial from a revoked certificate entry (RFC 5280 §5.1.2.6).
//
// Example:
//   serial_bytes = [0x01, 0x02], out = ParsedCrl { .. }
//   returns: true
fn parse_crl_entry_serial(serial_bytes: const u8[:], out: tls::ParsedCrl&) -> bool {
    let serial_u64, ok_ser = tls::parse_asn1_serial_u64(serial_bytes);
    guard ok_ser else { return false; }
    return crl_insert_serial(out, serial_u64);
}

// Parses a single revoked certificate entry SEQUENCE (RFC 5280 §5.1.2.6).
//
// Example:
//   entry_raw = [0x02, 0x01, 0x05, 0x17, 0x0D], out = ParsedCrl { .. }
//   returns: true
fn parse_crl_single_entry_raw(entry_raw: const u8[:], is_v2: bool, out: tls::ParsedCrl&) -> bool {
    var entry_seq = core::cursor_from(entry_raw);
    var serial_elem = core::cursor_from(entry_seq.buf[..0]);
    guard tls::get_asn1_element(entry_seq, rfc::ASN1_TAG_INTEGER, serial_elem) else { return false; }
    guard parse_crl_entry_serial(serial_elem.buf, out) else { return false; }

    var rev_time_tag: u8 = 0;
    var rev_time_elem = core::cursor_from(entry_seq.buf[..0]);
    guard tls::get_any_asn1_element(entry_seq, rev_time_tag, rev_time_elem) else { return false; }
    let _, ok_time = tls::parse_asn1_time(rev_time_tag, rev_time_elem.buf);
    guard ok_time else { return false; }
    if entry_seq.cursor_len() > 0 {
        guard is_v2 else { return false; }
        var entry_exts = core::cursor_from(entry_seq.buf[..0]);
        guard tls::get_asn1_element(entry_seq, rfc::ASN1_TAG_SEQUENCE, entry_exts) &&
            validate_no_critical_x509_extensions(entry_exts.buf) else {
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
fn parse_crl_revoked_entries(revoked_raw: const u8[:], is_v2: bool, out: tls::ParsedCrl&) -> bool {
    guard revoked_raw.len > 0 else { return false; }
    var revoked_seq = core::cursor_from(revoked_raw);
    while revoked_seq.cursor_len() > 0 {
        var entry_seq = core::cursor_from(revoked_seq.buf[..0]);
        guard tls::get_asn1_element(revoked_seq, rfc::ASN1_TAG_SEQUENCE, entry_seq) else {
            return false;
        }
        guard parse_crl_single_entry_raw(entry_seq.buf, is_v2, out) else {
            return false;
        }
    }
    return true;
}

fn crl_track_unique_serial(seen: u64[..1024]&, track_dups: bool&, ser_u64: u64) -> bool {
    guard track_dups else { return true; }
    let lo, found = crl_find_serial_slot(seen[..], ser_u64);
    guard !found else { return false; }
    guard seen.len < MAX_CRL_SERIALS else {
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
    target_bytes:  const u8[:],
    is_v2:         bool,
    seen:          u64[..1024]&,
    track_dups:    bool&,
    out_revoked:   bool&,
) -> bool {
    var entry_seq = core::cursor_from(entry_raw);
    var serial_elem = core::cursor_from(entry_seq.buf[..0]);
    guard tls::get_asn1_element(entry_seq, rfc::ASN1_TAG_INTEGER, serial_elem) else { return false; }
    let ser_u64, ok_ser = tls::parse_asn1_serial_u64(serial_elem.buf);
    guard ok_ser && crl_track_unique_serial(seen, track_dups, ser_u64) else { return false; }
    if target_bytes.len > 0 {
        if crl_serials_equal_canonical(serial_elem.buf, target_bytes) {
            out_revoked = true;
        }
    } else if ser_u64 == target_serial {
        out_revoked = true;
    }
    var rev_time_tag: u8 = 0;
    var rev_time_elem = core::cursor_from(entry_seq.buf[..0]);
    guard tls::get_any_asn1_element(entry_seq, rev_time_tag, rev_time_elem) else { return false; }
    let _, ok_time = tls::parse_asn1_time(rev_time_tag, rev_time_elem.buf);
    guard ok_time else { return false; }
    if entry_seq.cursor_len() > 0 {
        guard is_v2 else { return false; }
        var entry_exts = core::cursor_from(entry_seq.buf[..0]);
        guard tls::get_asn1_element(entry_seq, rfc::ASN1_TAG_SEQUENCE, entry_exts) &&
            validate_no_critical_x509_extensions(entry_exts.buf) else {
            return false;
        }
    }
    return entry_seq.cursor_len() == 0;
}

fn crl_stream_revoked_entries(
    revoked_raw:   const u8[:],
    is_v2:         bool,
    target_serial: u64,
    target_bytes:  const u8[:],
    out_revoked:   bool&,
) -> bool {
    guard revoked_raw.len > 0 else { return false; }
    var seen: u64[..1024] = [];
    var track_dups = true;
    var revoked_seq = core::cursor_from(revoked_raw);
    while revoked_seq.cursor_len() > 0 {
        var entry_seq = core::cursor_from(revoked_seq.buf[..0]);
        guard tls::get_asn1_element(revoked_seq, rfc::ASN1_TAG_SEQUENCE, entry_seq) else { return false; }
        guard crl_scan_single_revoked_entry(
            entry_seq.buf, target_serial, target_bytes, is_v2, seen, track_dups, out_revoked,
        ) else {
            return false;
        }
    }
    return true;
}

fn crl_verify_outer_signature_with_pubkey(
    crl_seq:           core::ByteCursor&,
    tbs_data:          const u8[:],
    inner_sig_alg_raw: const u8[:],
    pss_hash_id:       u8,
    parent_pubkey:     const u8[:],
) -> tls::Alert {
    var outer_sig_alg = core::cursor_from(crl_seq.buf[..0]);
    var outer_sig_oid = core::cursor_from(crl_seq.buf[..0]);
    var sig_bits = core::cursor_from(crl_seq.buf[..0]);
    var unused_bits: u8 = 0;
    guard tls::get_asn1_element(crl_seq, rfc::ASN1_TAG_SEQUENCE, outer_sig_alg) &&
        outer_sig_alg.buf == inner_sig_alg_raw &&
        tls::get_asn1_element(outer_sig_alg, rfc::ASN1_TAG_OID, outer_sig_oid) &&
        tls::get_asn1_bit_string(crl_seq, sig_bits, unused_bits) &&
        unused_bits == 0 &&
        sig_bits.buf.len > 0 &&
        crl_seq.cursor_len() == 0 else {
        return tls::Alert.DecodeError;
    }
    return x509_verify_signature_by_oid(
        outer_sig_oid.buf, tbs_data, sig_bits.buf, parent_pubkey, tls::Alert.BadCertificate, pss_hash_id,
    );
}

fn crl_verify_outer_signature_raw(
    crl_seq:           core::ByteCursor&,
    tbs_data:          const u8[:],
    inner_sig_alg_raw: const u8[:],
    pss_hash_id:       u8,
    issuer_cert:       const tls::ParsedCert&,
    issuer_raw:        const u8[:],
) -> tls::Alert {
    var parent_pubkey = tls::span_slice(issuer_raw, issuer_cert.spki_pubkey);
    if parent_pubkey.len >= 2 && parent_pubkey[0] == 0 {
        parent_pubkey = parent_pubkey[1..];
    }
    return crl_verify_outer_signature_with_pubkey(
        crl_seq, tbs_data, inner_sig_alg_raw, pss_hash_id, parent_pubkey,
    );
}

fn crl_parse_tbs_header(
    tbs:          core::ByteCursor&,
    iss_subj:     const u8[:],
    out_is_v2:    bool&,
    out_pss_hash: u8&,
    out_this_sec: i64&,
    out_next_sec: i64&,
    out_has_next: bool&,
) -> const u8[:], tls::Alert {
    let empty = tbs.buf[..0];
    out_is_v2 = false;
    out_has_next = false;
    if tbs.cursor_len() > 0 && tbs.buf[0] == rfc::ASN1_TAG_INTEGER {
        var ver: i64 = -1;
        // RFC 5280 Section 5.1.2.1: version is optional; when present it MUST be v2 (INTEGER 1).
        guard tls::get_asn1_integer(tbs, ver) && ver == 1 else { return empty, tls::Alert.DecodeError; }
        out_is_v2 = true;
    }
    var sig_alg = core::cursor_from(empty);
    var sig_oid = core::cursor_from(empty);
    guard tls::get_asn1_element(tbs, rfc::ASN1_TAG_SEQUENCE, sig_alg) else { return empty, tls::Alert.DecodeError; }
    let inner_sig_alg_raw = sig_alg.buf;
    guard tls::get_asn1_element(sig_alg, rfc::ASN1_TAG_OID, sig_oid) &&
        validate_x509_sig_alg_params(sig_oid.buf, sig_alg, out_pss_hash) else {
        return empty, tls::Alert.DecodeError;
    }
    var issuer_seq = core::cursor_from(empty);
    guard tls::get_asn1_element(tbs, rfc::ASN1_TAG_SEQUENCE, issuer_seq) else { return empty, tls::Alert.DecodeError; }
    guard issuer_seq.buf.len > 0 && (iss_subj.len == 0 || issuer_seq.buf == iss_subj) else {
        return empty, tls::Alert.UnknownCa;
    }

    var this_tag: u8 = 0;
    var this_el = core::cursor_from(empty);
    guard tls::get_any_asn1_element(tbs, this_tag, this_el) else { return empty, tls::Alert.DecodeError; }
    let this_sec, ok_this = tls::parse_asn1_time(this_tag, this_el.buf);
    guard ok_this && x509_crl_read_optional_next_update(tbs, out_next_sec, out_has_next) else {
        return empty, tls::Alert.DecodeError;
    }
    if out_has_next && this_sec > out_next_sec {
        return empty, tls::Alert.DecodeError;
    }
    out_this_sec = this_sec;
    return inner_sig_alg_raw, tls::Alert.CloseNotify;
}

fn crl_scan_optional_revoked(
    tbs:           core::ByteCursor&,
    is_v2:         bool,
    target_serial: u64,
    target_bytes:  const u8[:],
    out_revoked:   bool&,
) -> bool {
    guard tbs.cursor_len() > 0 && tbs.buf[0] == rfc::ASN1_TAG_SEQUENCE else { return true; }
    var rev_seq = core::cursor_from(tbs.buf[..0]);
    return tls::get_asn1_element(tbs, rfc::ASN1_TAG_SEQUENCE, rev_seq) &&
        crl_stream_revoked_entries(rev_seq.buf, is_v2, target_serial, target_bytes, out_revoked);
}

// Streaming RFC 5280 Section 5 CRL verifier using exact DER serial bytes and explicit issuer material.
fn check_crl_der_revocation_with_material(
    raw_crl:        const u8[:],
    target_serial:  const u8[:],
    issuer_subject: const u8[:],
    issuer_pubkey:  const u8[:],
    issuer_has_ku:  bool,
    issuer_ku:      u16,
    now_unix:       i64,
) -> tls::Alert {
    guard target_serial.len > 0 && issuer_subject.len > 0 && issuer_pubkey.len > 0 else {
        return tls::Alert.DecodeError;
    }
    guard !issuer_has_ku || (issuer_ku & rfc::KEY_USAGE_CRL_SIGN) != 0 else {
        return tls::Alert.UnsupportedCertificate;
    }
    var c = core::cursor_from(raw_crl);
    var crl_seq = core::cursor_from(raw_crl[..0]);
    guard tls::get_asn1_element(c, rfc::ASN1_TAG_SEQUENCE, crl_seq) && c.cursor_len() == 0 else {
        return tls::Alert.DecodeError;
    }
    let tbs_raw_start = crl_seq.buf;
    var tbs = core::cursor_from(crl_seq.buf[..0]);
    guard tls::get_asn1_element(crl_seq, rfc::ASN1_TAG_SEQUENCE, tbs) else { return tls::Alert.DecodeError; }
    let tbs_tlv = tbs_raw_start[..core::sub_sat_i64(tbs_raw_start.len, crl_seq.buf.len)];

    var is_v2 = false;
    var pss_hash_id: u8  = 0;
    var this_sec:    i64 = 0;
    var next_sec:    i64 = 0;
    var has_next = false;
    let inner_sig_alg_raw, hdr_alert = crl_parse_tbs_header(
        tbs, issuer_subject, is_v2, pss_hash_id, this_sec, next_sec, has_next,
    );
    guard hdr_alert == tls::Alert.CloseNotify else { return hdr_alert; }

    var revoked = false;
    guard crl_scan_optional_revoked(tbs, is_v2, 0, target_serial, revoked) &&
        x509_crl_read_optional_exts(tbs, is_v2) else {
        return tls::Alert.DecodeError;
    }
    let sig_alert = crl_verify_outer_signature_with_pubkey(
        crl_seq, tbs_tlv, inner_sig_alg_raw, pss_hash_id, issuer_pubkey,
    );
    guard sig_alert == tls::Alert.CloseNotify else { return sig_alert; }
    let time_alert = crl_validate_temporal(this_sec, next_sec, has_next, now_unix);
    guard time_alert == tls::Alert.CloseNotify else { return time_alert; }
    return if revoked { tls::Alert.CertificateRevoked } else { tls::Alert.CloseNotify };
}

// Extracts the DER issuer Name inner slice from a raw CRL without parsing its revoked list.
fn crl_peek_issuer_dn(raw_crl: const u8[:]) -> const u8[:], bool {
    let empty = raw_crl[..0];
    var c = core::cursor_from(raw_crl);
    var crl_seq = core::cursor_from(empty);
    var tbs = core::cursor_from(empty);
    guard tls::get_asn1_element(c, rfc::ASN1_TAG_SEQUENCE, crl_seq) &&
        c.cursor_len() == 0 &&
        tls::get_asn1_element(crl_seq, rfc::ASN1_TAG_SEQUENCE, tbs) else {
        return empty, false;
    }
    if tbs.cursor_len() > 0 && tbs.buf[0] == rfc::ASN1_TAG_INTEGER {
        var ver: i64 = -1;
        guard tls::get_asn1_integer(tbs, ver) && ver == 1 else { return empty, false; }
    }
    var sig_alg = core::cursor_from(empty);
    var issuer_seq = core::cursor_from(empty);
    guard tls::get_asn1_element(tbs, rfc::ASN1_TAG_SEQUENCE, sig_alg) &&
        tls::get_asn1_element(tbs, rfc::ASN1_TAG_SEQUENCE, issuer_seq) &&
        issuer_seq.buf.len > 0 else {
        return empty, false;
    }
    return issuer_seq.buf, true;
}
