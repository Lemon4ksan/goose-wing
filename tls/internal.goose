// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal leaf helpers and protocol constants for the `tls` package.
namespace tls_internal;

import std;
import core from "..";

// ---- ASN.1 DER Internal Helpers (X.690 §8 & §10) --------------------------

const ASN1_UNUSED_BITS_MASK_LUT: const u8[8] = [0x00, 0x01, 0x03, 0x07, 0x0F, 0x1F, 0x3F, 0x7F];

// Parses long-form ASN.1 DER length octets (1..4 bytes) enforcing shortest canonical encoding.
fn read_asn1_long_length(c: core::ByteCursor&, num_bytes: i64, out_len: i64&) -> bool {
    guard num_bytes >= 1 && num_bytes <= 4 else { return false; }
    var length: i64 = 0;
    var i:      i64 = 0;
    while i < num_bytes {
        var b: u8 = 0;
        guard c.get_u8(b) else { return false; }
        guard i != 0 || b != 0x00 else { return false; }
        length = core::add_sat_i64(core::mul_sat_i64(length, 256), b);
        i = core::add_sat_i64(i, 1);
    }
    guard length >= 128 && length <= 0x7FFFFFFF else { return false; }
    out_len = length;
    return true;
}

inline fn asn1_check_der_integer_padding(val: const u8[:]) -> bool {
    guard val.len >= 1 else { return false; }
    if val[0] == 0x00 && val.len > 1 {
        if (val[1] & 0x80) == 0 { return false; }
    } else if val[0] == 0xFF && val.len > 1 {
        if (val[1] & 0x80) != 0 { return false; }
    }
    return true;
}

inline fn asn1_check_serial_number_rules(val: const u8[:]) -> bool {
    guard (val[0] & 0x80) == 0 else { return false; }
    guard val.len != 1 || val[0] != 0x00 else { return false; }
    let max_len = if val[0] == 0x00 { 21 } else { 20 };
    return val.len <= max_len;
}

// Parses a 2-digit decimal integer from a slice at the given offset.
//
// Example:
//   buf = "20261028", off = 2
//   returns: val = 26, ok = true
inline fn parse_2digit(buf: const u8[:], off: i64) -> i64, bool {
    let max_off = core::sub_sat_i64(buf.len, 2);
    guard off >= 0 && off <= max_off else { return 0, false; }
    let next_off = core::add_sat_i64(off, 1);
    let c1 = buf[off];
    let c2 = buf[next_off];
    guard core::is_ascii_digit(c1) && core::is_ascii_digit(c2) else { return 0, false; }
    let d1 = core::hex_digit_to_val(c1) as i64;
    let d2 = core::hex_digit_to_val(c2) as i64;
    return core::add_sat_i64(core::mul_sat_i64(d1, 10), d2), true;
}

// Validates time fields and leap-year days in month per RFC 5280 Section 4.1.2.5.
inline fn validate_time_fields(
    year:  i64,
    month: i64,
    day:   i64,
    hour:  i64,
    min:   i64,
    sec:   i64,
) -> bool {
    guard month >= 1 && month <= 12 else { return false; }
    let max_days = core::days_in_month(year, month);
    guard max_days > 0 && day >= 1 && day <= max_days else { return false; }
    guard hour >= 0 && hour <= 23 else { return false; }
    guard min >= 0 && min <= 59 else { return false; }
    guard sec >= 0 && sec <= 59 else { return false; }
    return true;
}

fn civil_to_epoch_seconds(
    year:  i64,
    month: i64,
    day:   i64,
    hour:  i64,
    min:   i64,
    sec:   i64,
) -> i64, bool {
    guard validate_time_fields(year, month, day, hour, min, sec) else { return 0, false; }
    let days = core::civil_to_days(year, month, day);
    let day_secs = core::mul_sat_i64(days, 86400);
    let hour_secs = core::mul_sat_i64(hour, 3600);
    let min_secs = core::mul_sat_i64(min, 60);
    let hms = core::add_sat_i64(core::add_sat_i64(hour_secs, min_secs), sec);
    return core::add_sat_i64(day_secs, hms), true;
}

// ---- SCT Internal Helpers (RFC 6962 §3.2) ----------------------------------

// Packs two big-endian 32-bit halves into an RFC 6962 §3.2 64-bit millisecond timestamp.
//
// Example:
//   ts_hi = 0x0000018E, ts_lo = 0x00000001
//   returns: 0x0000018E00000001
inline fn pack_sct_timestamp_ms(ts_hi: u32, ts_lo: u32) -> u64 {
    return ((ts_hi as u64) << 32) | ts_lo;
}

// ---- Record Layer Internal Constants (RFC 8446 §5) -------------------------

const MAX_EMPTY_RECORDS:          i32 = 32;    // BoringSSL kMaxEmptyRecords DoS defense
const MAX_EARLY_DATA_SKIPPED:     i64 = 16384; // BoringSSL kMaxEarlyDataSkipped
const TLS_MIN_AEAD_PAYLOAD_LEN:   i64 = 17;
const MAX_QUIC_CRYPTO_BUFFER_LEN: i64 = 16384; // 16KB max handshake flight per encryption level

inline fn is_aes_gcm_cipher_suite(cipher_suite: u16) -> bool {
    return cipher_suite == rfc::TLS_CIPHER_AES_128_GCM_SHA256 ||
           cipher_suite == rfc::TLS_CIPHER_AES_256_GCM_SHA384;
}

// ---- Ticket Internal Helpers (RFC 8446 §4.6.1) -----------------------------

inline fn calc_ticket_lifetime_ms(lifetime: u32) -> i64 {
    let clamped = min(lifetime, rfc::MAX_TICKET_LIFETIME_SECS) as i64;
    return core::mul_sat_i64(clamped, 1000);
}

inline fn is_stateless_ticket_within_lifetime(issued_ms: i64, now_ms: i64, lifetime: u32) -> bool {
    guard issued_ms >= 0 && now_ms >= issued_ms && lifetime > 0 && lifetime <= rfc::MAX_TICKET_LIFETIME_SECS else {
        return false;
    }
    let elapsed_ms = core::sub_sat_i64(now_ms, issued_ms);
    let max_age_ms = calc_ticket_lifetime_ms(lifetime);
    return elapsed_ms <= max_age_ms;
}

// ---- ECH / PEM / CRL / OCSP Leaf Constants & Pure Helpers ------------------

const MAX_CRL_SERIALS:             i64 = 128;
const MAX_CONSECUTIVE_KEY_UPDATES: u32 = 8;
const MAX_CHAIN_DEPTH:             i64 = 8;

const OID_OCSP_SHA1:   const u8[5] = [0x2B, 0x0E, 0x03, 0x02, 0x1A];
const OID_OCSP_SHA256: const u8[9] = [0x60, 0x86, 0x48, 0x01, 0x65, 0x03, 0x04, 0x02, 0x01];
// RFC 6066 Section 8: Certificate Status Request - CertificateStatusType ocsp(1).
const CERT_STATUS_TYPE_OCSP: u8 = 1;

const PEM_PRE_EB:           const u8[:] = "-----BEGIN ";
const PEM_POST_EB:          const u8[:] = "-----END ";
const PEM_DASHES:           const u8[:] = "-----";
const PEM_MAX_DER_LEN:      i64         = 4096;
const PEM_MAX_LABEL_LEN:    i64         = 64;
const PEM_MAX_BUNDLE_BYTES: i64         = 1048576; // 1 MiB cap for PEM trust-store bundles

const P256_ORDER_BYTES: const u8[32] = [
    0xFF, 0xFF, 0xFF, 0xFF, 0x00, 0x00, 0x00, 0x00,
    0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF,
    0xBC, 0xE6, 0xFA, 0xAD, 0xA7, 0x17, 0x9E, 0x84,
    0xF3, 0xB9, 0xCA, 0xC2, 0xFC, 0x63, 0x25, 0x51,
];

inline fn pem_is_ws(b: u8) -> bool {
    return b == ' ' || b == '\t' || b == '\r' || b == '\n';
}

inline fn pem_skip_to_next_line(raw: const u8[:], pos: i64) -> i64, bool {
    var p = pos;
    while p < raw.len && (raw[p] == ' ' || raw[p] == '\t') {
        p = core::add_sat_i64(p, 1);
    }
    guard p < raw.len && (raw[p] == '\r' || raw[p] == '\n') else { return p, false; }
    while p < raw.len && (raw[p] == '\r' || raw[p] == '\n') {
        p = core::add_sat_i64(p, 1);
    }
    return p, true;
}

inline fn pem_skip_end_line(raw: const u8[:], pos: i64) -> i64, bool {
    var p = pos;
    while p < raw.len && (raw[p] == ' ' || raw[p] == '\t') {
        p = core::add_sat_i64(p, 1);
    }
    guard p == raw.len || raw[p] == '\r' || raw[p] == '\n' else { return p, false; }
    while p < raw.len && (raw[p] == '\r' || raw[p] == '\n') {
        p = core::add_sat_i64(p, 1);
    }
    return p, true;
}

inline fn pem_find_begin_line(
    raw:            const u8[:],
    start_idx:      i64,
    out_label:      u8[..64]&,
    out_body_start: i64&,
) -> bool {
    guard start_idx >= 0 && start_idx < raw.len else { return false; }
    let rel_begin = core::find(raw[start_idx..], PEM_PRE_EB);
    guard rel_begin >= 0 else { return false; }
    let begin_pos = core::add_sat_i64(start_idx, rel_begin);
    let label_start = core::add_sat_i64(begin_pos, PEM_PRE_EB.len);
    guard label_start < raw.len else { return false; }

    let rel_dash = core::find(raw[label_start..], PEM_DASHES);
    guard rel_dash > 0 && rel_dash <= PEM_MAX_LABEL_LEN else { return false; }
    let label_end = core::add_sat_i64(label_start, rel_dash);
    guard out_label.try_set(raw[label_start..label_end]) else { return false; }

    let line_pos = core::add_sat_i64(label_end, PEM_DASHES.len);
    let next_p, ok_p = pem_skip_to_next_line(raw, line_pos);
    guard ok_p else { return false; }
    out_body_start = next_p;
    return true;
}

inline fn pem_find_end_line(
    raw:          const u8[:],
    body_start:   i64,
    label:        const u8[:],
    out_body_end: i64&,
    out_next_idx: i64&,
) -> bool {
    guard body_start >= 0 && body_start < raw.len else { return false; }
    let rel_end = core::find(raw[body_start..], PEM_POST_EB);
    guard rel_end >= 0 else { return false; }
    let end_pos = core::add_sat_i64(body_start, rel_end);
    let lbl_start = core::add_sat_i64(end_pos, PEM_POST_EB.len);
    let lbl_end = core::add_sat_i64(lbl_start, label.len);
    let dash_end = core::add_sat_i64(lbl_end, PEM_DASHES.len);
    guard dash_end <= raw.len else { return false; }
    guard raw[lbl_start..lbl_end] == label && raw[lbl_end..dash_end] == PEM_DASHES else {
        return false;
    }

    let next_p, ok_p = pem_skip_end_line(raw, dash_end);
    guard ok_p else { return false; }
    out_body_end = end_pos;
    out_next_idx = next_p;
    return true;
}

inline fn pem_decode_body(body: const u8[:], out_der: u8[..4096]&) -> bool {
    var b64_clean: u8[..6144] = [];
    defer core::secure_zeroize_slice(b64_clean[..]);
    for b in body {
        if pem_is_ws(b) { continue; }
        guard b64_clean.try_push(b) else { return false; }
    }
    guard b64_clean.len > 0 else { return false; }
    out_der.clear();
    guard core::base64_decode(b64_clean[..], out_der) && out_der.len > 0 else {
        out_der.clear();
        return false;
    }
    return true;
}

inline fn is_valid_p256_scalar(scalar: const u8[:]) -> bool {
    guard scalar.len == 32 else { return false; }
    var non_zero: u8 = 0;
    var decided:  u8 = 0;
    var is_less:  u8 = 0;
    for i in 32 {
        let s = scalar[i];
        let n = P256_ORDER_BYTES[i];
        non_zero = non_zero | s;
        let lt: u8 = if s < n { 1 } else { 0 };
        let ne: u8 = if s != n { 1 } else { 0 };
        is_less = is_less | ((decided ^ 1) & lt);
        decided = decided | ne;
    }
    return non_zero != 0 && is_less == 1;
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
