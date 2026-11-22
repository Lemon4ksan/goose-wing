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
fn parse_crl_single_entry_raw(entry_raw: const u8[:], out: tls::ParsedCrl&) -> bool {
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
fn parse_crl_revoked_entries(revoked_raw: const u8[:], out: tls::ParsedCrl&) -> bool {
    var revoked_seq = core::cursor_from(revoked_raw);
    while revoked_seq.cursor_len() > 0 {
        var entry_seq = core::cursor_from(revoked_seq.buf[..0]);
        guard tls::get_asn1_element(revoked_seq, rfc::ASN1_TAG_SEQUENCE, entry_seq) else {
            return false;
        }
        guard parse_crl_single_entry_raw(entry_seq.buf, out) else {
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
    seen:          u64[..1024]&,
    track_dups:    bool&,
    out_revoked:   bool&,
) -> bool {
    var entry_seq = core::cursor_from(entry_raw);
    var serial_elem = core::cursor_from(entry_seq.buf[..0]);
    guard tls::get_asn1_element(entry_seq, rfc::ASN1_TAG_INTEGER, serial_elem) else { return false; }
    let ser_u64, ok_ser = tls::parse_asn1_serial_u64(serial_elem.buf);
    guard ok_ser && crl_track_unique_serial(seen, track_dups, ser_u64) else { return false; }
    if ser_u64 == target_serial {
        out_revoked = true;
    }
    var rev_time_tag: u8 = 0;
    var rev_time_elem = core::cursor_from(entry_seq.buf[..0]);
    guard tls::get_any_asn1_element(entry_seq, rev_time_tag, rev_time_elem) else { return false; }
    let _, ok_time = tls::parse_asn1_time(rev_time_tag, rev_time_elem.buf);
    guard ok_time else { return false; }
    if entry_seq.cursor_len() > 0 {
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
    target_serial: u64,
    out_revoked:   bool&,
) -> bool {
    var seen: u64[..1024] = [];
    var track_dups = true;
    var revoked_seq = core::cursor_from(revoked_raw);
    while revoked_seq.cursor_len() > 0 {
        var entry_seq = core::cursor_from(revoked_seq.buf[..0]);
        guard tls::get_asn1_element(revoked_seq, rfc::ASN1_TAG_SEQUENCE, entry_seq) else { return false; }
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
    issuer_cert:       const tls::ParsedCert&,
    issuer_raw:        const u8[:],
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
        crl_seq.cursor_len() == 0 else {
        return tls::Alert.DecodeError;
    }
    var parent_pubkey = tls::span_slice(issuer_raw, issuer_cert.spki_pubkey);
    if parent_pubkey.len >= 2 && parent_pubkey[0] == 0 {
        parent_pubkey = parent_pubkey[1..];
    }
    return x509_verify_signature_by_oid(
        outer_sig_oid.buf, tbs_data, sig_bits.buf, parent_pubkey, tls::Alert.BadCertificate, pss_hash_id,
    );
}

fn crl_parse_tbs_header(
    tbs:          core::ByteCursor&,
    iss_subj:     const u8[:],
    out_is_v2:    bool&,
    out_pss_hash: u8&,
    out_this_sec: i64&,
    out_next_sec: i64&,
) -> const u8[:], tls::Alert {
    let empty = tbs.buf[..0];
    out_is_v2 = false;
    if tbs.cursor_len() > 0 && tbs.buf[0] == rfc::ASN1_TAG_INTEGER {
        var ver: i64 = -1;
        guard tls::get_asn1_integer(tbs, ver) && (ver == 0 || ver == 1) else { return empty, tls::Alert.DecodeError; }
        out_is_v2 = ver == 1;
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
    guard issuer_seq.buf.len > 0 && issuer_seq.buf == iss_subj else { return empty, tls::Alert.UnknownCa; }

    var this_tag: u8 = 0;
    var this_el = core::cursor_from(empty);
    guard tls::get_any_asn1_element(tbs, this_tag, this_el) else { return empty, tls::Alert.DecodeError; }
    let this_sec, ok_this = tls::parse_asn1_time(this_tag, this_el.buf);
    guard ok_this && x509_crl_read_optional_next_update(tbs, out_next_sec) else {
        return empty, tls::Alert.DecodeError;
    }
    out_this_sec = this_sec;
    return inner_sig_alg_raw, tls::Alert.CloseNotify;
}

fn crl_scan_optional_revoked(
    tbs:           core::ByteCursor&,
    target_serial: u64,
    out_revoked:   bool&,
) -> bool {
    guard tbs.cursor_len() > 0 && tbs.buf[0] == rfc::ASN1_TAG_SEQUENCE else { return true; }
    var rev_seq = core::cursor_from(tbs.buf[..0]);
    return tls::get_asn1_element(tbs, rfc::ASN1_TAG_SEQUENCE, rev_seq) &&
        crl_stream_revoked_entries(rev_seq.buf, target_serial, out_revoked);
}
