// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 5280 Section 5 X.509 Certificate Revocation List (CRL) DER parser and O(log N) binary-search lookup.
namespace wing;

import std;
import core from "..";
import .record;
import .asn1;
import .x509;

const MAX_CRL_SERIALS: i64 = 128;

// Parsed X.509 Certificate Revocation List (RFC 5280 Section 5.1) with sorted
// inline serial storage for O(log N) binary-search revocation lookup.
struct ParsedCrl {
    issuer:       const u8[:] = "",
    serials:      u64[..128]  = [],
    serial_count: i32         = 0,
    tbs_raw:      Span16      = Span16 { offset: 0, length: 0 },
    sig_alg_oid:  Span16      = Span16 { offset: 0, length: 0 },
    signature:    Span16      = Span16 { offset: 0, length: 0 },
}

// Computes the midpoint `lo + ((hi - lo) >> 1)` for CRL serial binary search.
inline fn crl_bsearch_midpoint(lo: i64, hi: i64) -> i64 {
    return core::add_sat_i64(lo, core::sub_sat_i64(hi, lo) >> 1);
}

// Locates `serial` or its sorted insertion index in `serials` using O(log N) binary search.
fn crl_find_serial_slot(serials: const u64[:], serial: u64) -> i64, bool {
    var lo: i64 = 0;
    var hi: i64 = serials.len;
    while lo < hi {
        let mid = crl_bsearch_midpoint(lo, hi);
        let mid_val = serials[mid];
        if mid_val == serial {
            return mid, true;
        }
        if mid_val < serial {
            lo = core::add_sat_i64(mid, 1);
        } else {
            hi = mid;
        }
    }
    return lo, false;
}

// Inserts a 64-bit certificate serial number into `crl.serials` in ascending
// sorted order. Fails closed with `false` if `crl.serials.len >= 128` (Invariant 13).
fn crl_insert_serial(crl: ParsedCrl&, serial: u64) -> bool {
    guard crl.serials.len < MAX_CRL_SERIALS else {
        return false;
    }

    let lo, found = crl_find_serial_slot(crl.serials[..], serial);
    if found {
        return true;
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
    let _, found = crl_find_serial_slot(crl.serials[..], serial);
    return found;
}

// Decodes a positive ASN.1 DER INTEGER (1..8 significant bytes) into a `u64` serial number.
//
// Example:
//   serial_bytes = [0x01, 0x02]
//   returns: val = 0x0102, ok = true
fn parse_asn1_serial_u64(serial_bytes: const u8[:]) -> u64, bool {
    guard validate_asn1_integer(serial_bytes, true) else {
        return 0, false;
    }
    var start: i64 = 0;
    if serial_bytes.len > 1 && serial_bytes[0] == 0x00 {
        start = 1;
    }
    let sig_len = core::sub_sat_i64(serial_bytes.len, start);
    guard sig_len > 0 && sig_len <= 8 else {
        return 0, false;
    }
    var val: u64 = 0;
    for i in sig_len {
        let b = serial_bytes[core::add_sat_i64(start, i)] as u64;
        val = core::mul_sat_u64(val, 256) | b;
    }
    return val, true;
}

inline fn validate_crl_serial_length(serial_bytes: const u8[:]) -> bool {
    guard validate_asn1_integer(serial_bytes, true) else { return false; }
    var start: i64 = 0;
    if serial_bytes.len > 1 && serial_bytes[0] == 0x00 {
        start = 1;
    }
    let sig_len = core::sub_sat_i64(serial_bytes.len, start);
    return sig_len > 0 && sig_len <= 20;
}

// Parses an ASN.1 INTEGER serial from a revoked certificate entry (RFC 5280 §5.1.2.6).
//
// Example:
//   serial_bytes = [0x01, 0x02], out = ParsedCrl { .. }
//   returns: true
fn parse_crl_entry_serial(serial_bytes: const u8[:], out: ParsedCrl&) -> bool {
    guard validate_crl_serial_length(serial_bytes) else { return false; }
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
    return ok_time;
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

fn x509_crl_read_outer_sig(crl_seq: ByteCursor&, raw_crl: const u8[:], out: ParsedCrl&) -> bool {
    guard crl_seq.cursor_len() > 0 else { return false; }
    var outer_sig_alg = core::cursor_from(crl_seq.buf[..0]);
    guard get_asn1_element(crl_seq, rfc::ASN1_TAG_SEQUENCE, outer_sig_alg) else { return false; }
    var outer_sig_oid = core::cursor_from(outer_sig_alg.buf[..0]);
    guard get_asn1_element(outer_sig_alg, rfc::ASN1_TAG_OID, outer_sig_oid) else { return false; }
    out.sig_alg_oid = make_span(raw_crl, outer_sig_oid.buf);

    guard crl_seq.cursor_len() > 0 else { return false; }
    var sig_bits = core::cursor_from(crl_seq.buf[..0]);
    var unused_bits: u8 = 0;
    guard get_asn1_bit_string(crl_seq, sig_bits, unused_bits) && unused_bits == 0 else { return false; }
    out.signature = make_span(raw_crl, sig_bits.buf);
    return crl_seq.cursor_len() == 0;
}

inline fn x509_crl_skip_optional_next_update(tbs_cert_list: ByteCursor&) -> bool {
    guard tbs_cert_list.cursor_len() > 0 else { return true; }
    let next_tag = tbs_cert_list.buf[0];
    guard next_tag == rfc::ASN1_TAG_UTC_TIME || next_tag == rfc::ASN1_TAG_GENERALIZED_TIME else {
        return true;
    }
    var next_up_tag: u8 = 0;
    var next_up_elem = core::cursor_from(tbs_cert_list.buf[..0]);
    guard get_any_asn1_element(tbs_cert_list, next_up_tag, next_up_elem) else { return false; }
    let _, ok_next = parse_asn1_time(next_up_tag, next_up_elem.buf);
    return ok_next;
}

// Parses an X.509 CertificateList (CRL) in ASN.1 DER format (RFC 5280 Section 5.1).
// Extracts the issuer Name slice and populates `out.serials` in ascending sorted order.
// Fails closed (`false`) on malformed DER or if revoked serials exceed 128 (Invariant 13).
//
// Example:
//   raw_crl = [0x30, ...] (DER CertificateList)
//   returns: ok = true, out.issuer and out.serials populated
fn parse_x509_crl(raw_crl: const u8[:], out: ParsedCrl&) -> bool {
    out.issuer = "";
    out.serials.clear();
    out.serial_count = 0;

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

    if tbs_cert_list.cursor_len() > 0 && tbs_cert_list.buf[0] == rfc::ASN1_TAG_INTEGER {
        var ver_elem = core::cursor_from(tbs_cert_list.buf[..0]);
        guard get_asn1_element(tbs_cert_list, rfc::ASN1_TAG_INTEGER, ver_elem) else { return false; }
    }

    var sig_alg = core::cursor_from(tbs_cert_list.buf[..0]);
    guard get_asn1_element(tbs_cert_list, rfc::ASN1_TAG_SEQUENCE, sig_alg) else { return false; }

    var issuer_seq = core::cursor_from(tbs_cert_list.buf[..0]);
    guard get_asn1_element(tbs_cert_list, rfc::ASN1_TAG_SEQUENCE, issuer_seq) else { return false; }
    out.issuer = issuer_seq.buf;

    var this_up_tag: u8 = 0;
    var this_up_elem = core::cursor_from(tbs_cert_list.buf[..0]);
    guard get_any_asn1_element(tbs_cert_list, this_up_tag, this_up_elem) else { return false; }
    let _, ok_this = parse_asn1_time(this_up_tag, this_up_elem.buf);
    guard ok_this && x509_crl_skip_optional_next_update(tbs_cert_list) else { return false; }

    if tbs_cert_list.cursor_len() > 0 && tbs_cert_list.buf[0] == rfc::ASN1_TAG_SEQUENCE {
        var revoked_seq = core::cursor_from(tbs_cert_list.buf[..0]);
        guard get_asn1_element(tbs_cert_list, rfc::ASN1_TAG_SEQUENCE, revoked_seq) &&
            parse_crl_revoked_entries(revoked_seq.buf, out) else {
            return false;
        }
    }

    return x509_crl_read_outer_sig(crl_seq, raw_crl, out);
}

// Verifies cryptographic signature on an X.509 CRL against issuer's certificate.
fn x509_verify_crl_signature(
    crl:         const ParsedCrl&,
    raw_crl:     const u8[:],
    issuer_cert: const ParsedCert&,
    issuer_raw:  const u8[:],
) -> TlsAlert {
    guard crl.signature.length > 0 && crl.tbs_raw.length > 0 else {
        return TlsAlert.BadCertificate;
    }
    let sig_oid = span_slice(raw_crl, crl.sig_alg_oid);
    let tbs_data = span_slice(raw_crl, crl.tbs_raw);
    let sig_bytes = span_slice(raw_crl, crl.signature);
    var parent_pubkey = span_slice(issuer_raw, issuer_cert.spki_pubkey);

    if parent_pubkey.len >= 2 && parent_pubkey[0] == 0 {
        parent_pubkey = parent_pubkey[1..];
    }

    return x509_verify_signature_by_oid(sig_oid, tbs_data, sig_bytes, parent_pubkey, TlsAlert.BadCertificate);
}
