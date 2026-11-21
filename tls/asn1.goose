// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Strict canonical ASN.1 DER parser (X.690 §8 & §10), zero-allocation Span16 slice descriptors,
// and RFC 5280 §4.1.2.5 UTCTime / GeneralizedTime Unix epoch parsers.
namespace tls;

import std;
import core;
import .internal;

// ---- Strict Canonical ASN.1 DER Parser -----------------------------------

// Decodes a 2-byte big-endian unsigned integer from the head of `buf` (X.690 §10.1).
checkfree inline fn asn1_read_be_u16(buf: const u8[:]) -> u16 {
    if buf.len < 2 { return 0; }
    return ((buf[0] as u16) << 8) | buf[1];
}

// Decodes a 3-byte big-endian unsigned integer from the head of `buf` (X.690 §10.1).
checkfree inline fn asn1_read_be_u24(buf: const u8[:]) -> u32 {
    if buf.len < 3 { return 0; }
    let hi = asn1_read_be_u16(buf) as u32;
    return (hi << 8) | buf[2];
}

// Decodes a 4-byte big-endian unsigned integer from the head of `buf` (X.690 §10.1).
checkfree inline fn asn1_read_be_u32(buf: const u8[:]) -> u32 {
    if buf.len < 4 { return 0; }
    let hi = asn1_read_be_u16(buf) as u32;
    let lo = asn1_read_be_u16(buf[2..]) as u32;
    return (hi << 16) | lo;
}

// Parses ASN.1 length field with canonical DER rules (X.690 Section 10.1):
// - Short form: 0..127 (1 byte)
// - Long form: byte 0 has bit 8 set, remaining 7 bits is length of length (1..4)
// - Long form with length < 128, BER indefinite length (0x80), redundant leading zeros,
//   and reserved initial octet 0xFF are strictly FORBIDDEN.
checkfree fn get_asn1_length(c: core::ByteCursor&, out_len: i64&) -> bool {
    guard c.buf.len >= 1 else { return false; }
    let b0 = c.buf[0];
    c.buf = c.buf[1..];

    if (b0 & 0x80) == 0 {
        out_len = b0;
        return true;
    }

    guard b0 != 0x80 && b0 != 0xFF else { return false; }
    let num_bytes = (b0 & 0x7F) as i64;
    guard num_bytes >= 1 && num_bytes <= 4 && c.buf.len >= num_bytes else { return false; }
    let len_bytes = c.buf[..num_bytes];
    // X.690 Section 10.1: leading zero octet in long-form length is non-canonical DER.
    guard len_bytes[0] != 0x00 else { return false; }

    let length: i64 = match num_bytes {
        1 => len_bytes[0],
        2 => asn1_read_be_u16(len_bytes),
        3 => asn1_read_be_u24(len_bytes),
        4 => asn1_read_be_u32(len_bytes),
        _ => 0,
    };
    guard length >= 128 && length <= 0x7FFFFFFF else { return false; }
    c.buf = c.buf[num_bytes..];
    out_len = length;
    return true;
}

// Consumes any ASN.1 TLV element, returning tag and value cursor.
checkfree fn get_any_asn1_element(c: core::ByteCursor&, out_tag: u8&, out_val: core::ByteCursor&) -> bool {
    guard c.buf.len >= 1 else { return false; }
    out_tag = c.buf[0];
    c.buf = c.buf[1..];
    var length: i64 = 0;
    if !get_asn1_length(c, length) { return false; }
    let rem = c.buf;
    guard length >= 0 && length <= rem.len else { return false; }
    out_val = core::ByteCursor { buf: rem[..length] };
    c.buf = rem[length..];
    return true;
}

// Consumes an ASN.1 element with an expected tag.
checkfree fn get_asn1_element(c: core::ByteCursor&, expected_tag: u8, out_val: core::ByteCursor&) -> bool {
    var tag: u8 = 0;
    if !get_any_asn1_element(c, tag, out_val) { return false; }
    return tag == expected_tag;
}

// Validates canonical DER rules for ASN.1 INTEGER (X.690 Section 8.3):
// - Length must be >= 1 (zero-length integer is forbidden).
// - No redundant leading zero padding or negative sign extension.
// - For X.509 serial numbers (RFC 5280 §4.1.2.2): MUST be positive (strictly > 0), max 20 octets.
checkfree inline fn validate_asn1_integer(val: const u8[:], is_serial_number: bool) -> bool {
    guard val.len >= 1 else { return false; }
    if val[0] == 0x00 && val.len > 1 {
        if (val[1] & 0x80) == 0 { return false; }
    } else if val[0] == 0xFF && val.len > 1 {
        if (val[1] & 0x80) != 0 { return false; }
    }
    if is_serial_number {
        guard (val[0] & 0x80) == 0 else { return false; }
        guard val.len != 1 || val[0] != 0x00 else { return false; }
        let max_len = if val[0] == 0x00 { 21 } else { 20 };
        return val.len <= max_len;
    }
    return true;
}

// Consumes an ASN.1 INTEGER element and decodes it into out_val (i64),
// enforcing strict DER canonical encoding rules (X.690 Section 8.3 & 10.1).
fn get_asn1_integer(c: core::ByteCursor&, out_val: i64&) -> bool {
    var raw = core::cursor_from(c.buf[..0]);
    if !get_asn1_element(c, rfc::ASN1_TAG_INTEGER, raw) { return false; }
    guard raw.buf.len >= 1 && raw.buf.len <= 8 else { return false; }
    guard validate_asn1_integer(raw.buf, false) else { return false; }

    let is_neg = (raw.buf[0] & 0x80) != 0;
    var acc: i64 = 0;
    for b in raw.buf {
        let part = if is_neg { core::sub_sat_i64(255, b) } else { b as i64 };
        acc = core::add_sat_i64(core::mul_sat_i64(acc, 256), part);
    }
    out_val = if is_neg { core::sub_sat_i64(-1, acc) } else { acc };
    return true;
}

// Validates canonical DER rules for ASN.1 BIT STRING (X.690 Section 8.4 & 10.2):
// - Length must be >= 1, unused bits in 0..7, empty bit string has unused == 0,
//   and trailing unused bits in the last data octet MUST be zero.
checkfree inline fn validate_asn1_bit_string(val: const u8[:]) -> bool {
    guard val.len >= 1 else { return false; }
    let unused = val[0];
    guard unused <= 7 else { return false; }
    if val.len == 1 {
        return unused == 0;
    }
    guard unused > 0 else { return true; }
    let last_slice = val[^1..];
    guard last_slice.len == 1 else { return false; }
    let last_byte = last_slice[0];
    let mask = tls_internal::ASN1_UNUSED_BITS_MASK_LUT[unused as i64];
    return (last_byte & mask) == 0;
}

// Consumes an ASN.1 BIT STRING element, validating DER unused bits rules and extracting bit payload.
checkfree fn get_asn1_bit_string(c: core::ByteCursor&, out_bits: core::ByteCursor&, out_unused: u8&) -> bool {
    var raw = core::ByteCursor { buf: c.buf[..0] };
    if !get_asn1_element(c, rfc::ASN1_TAG_BIT_STRING, raw) { return false; }
    guard validate_asn1_bit_string(raw.buf) && raw.buf.len >= 1 else { return false; }
    out_unused = raw.buf[0];
    out_bits = core::ByteCursor { buf: raw.buf[1..] };
    return true;
}

// ---- Date & Time Parser (UTCTime & GeneralizedTime) -----------------------

// Parses UTCTime ("YYMMDDHHMMSSZ") per RFC 5280 Section 4.1.2.5.1:
// - Must be exactly 13 bytes ending with 'Z'.
// - Conforming systems MUST interpret YY >= 50 as 19YY (1950..1999) and YY < 50 as 20YY (2000..2049).
// - Dates in the year 2050 or later MUST NOT be encoded in UTCTime.
// - Full date and leap-year validation.
//
// Example:
//   time_bytes = "261028000000Z"
//   returns: epoch_secs = 1793145600, ok = true
fn parse_utc_time(time_bytes: const u8[:]) -> i64, bool {
    guard time_bytes.len == 13 && time_bytes[12] == 'Z' else { return 0, false; }
    let y2, ok_y = tls_internal::parse_2digit(time_bytes, 0);
    guard ok_y else { return 0, false; }

    // RFC 5280 Section 4.1.2.5.1: YY >= 50 -> 19YY, YY < 50 -> 20YY
    let century: i64 = if y2 >= 50 { 1900 } else { 2000 };
    let year = core::add_sat_i64(century, y2);

    let month, ok_m = tls_internal::parse_2digit(time_bytes, 2);
    guard ok_m else { return 0, false; }
    let day, ok_d = tls_internal::parse_2digit(time_bytes, 4);
    guard ok_d else { return 0, false; }
    let hour, ok_h = tls_internal::parse_2digit(time_bytes, 6);
    guard ok_h else { return 0, false; }
    let min, ok_min = tls_internal::parse_2digit(time_bytes, 8);
    guard ok_min else { return 0, false; }
    let sec, ok_s = tls_internal::parse_2digit(time_bytes, 10);
    guard ok_s else { return 0, false; }

    return tls_internal::civil_to_epoch_seconds(year, month, day, hour, min, sec);
}

// Parses GeneralizedTime ("YYYYMMDDHHMMSSZ") per RFC 5280 Section 4.1.2.5.2:
// - Must be exactly 15 bytes ending with 'Z'.
// - Fractional seconds are strictly FORBIDDEN.
// - Full date and leap-year validation.
//
// Example:
//   time_bytes = "20261028000000Z"
//   returns: epoch_secs = 1793145600, ok = true
fn parse_generalized_time(time_bytes: const u8[:]) -> i64, bool {
    guard time_bytes.len == 15 && time_bytes[14] == 'Z' else { return 0, false; }
    let y1, ok_y1 = tls_internal::parse_2digit(time_bytes, 0);
    guard ok_y1 else { return 0, false; }
    let y2, ok_y2 = tls_internal::parse_2digit(time_bytes, 2);
    guard ok_y2 else { return 0, false; }
    let year = core::add_sat_i64(core::mul_sat_i64(y1, 100), y2);

    let month, ok_m = tls_internal::parse_2digit(time_bytes, 4);
    guard ok_m else { return 0, false; }
    let day, ok_d = tls_internal::parse_2digit(time_bytes, 6);
    guard ok_d else { return 0, false; }
    let hour, ok_h = tls_internal::parse_2digit(time_bytes, 8);
    guard ok_h else { return 0, false; }
    let min, ok_min = tls_internal::parse_2digit(time_bytes, 10);
    guard ok_min else { return 0, false; }
    let sec, ok_s = tls_internal::parse_2digit(time_bytes, 12);
    guard ok_s else { return 0, false; }

    return tls_internal::civil_to_epoch_seconds(year, month, day, hour, min, sec);
}

// Parses UTCTime ("YYMMDDHHMMSSZ") or GeneralizedTime ("YYYYMMDDHHMMSSZ") to Unix timestamp seconds.
//
// Example:
//   time_tag = ASN1_TAG_UTC_TIME, time_bytes = "261028000000Z"
//   returns: epoch_secs = 1793145600, ok = true
fn parse_asn1_time(time_tag: u8, time_bytes: const u8[:]) -> i64, bool {
    if time_tag == rfc::ASN1_TAG_UTC_TIME {
        return parse_utc_time(time_bytes);
    } else if time_tag == rfc::ASN1_TAG_GENERALIZED_TIME {
        return parse_generalized_time(time_bytes);
    }
    return 0, false;
}

// ---- Span16 Zero-Copy Slice Descriptor -----------------------------------

struct Span16 {
    offset: u16 = 0,
    length: u16 = 0,
}

checkfree fn span_slice(raw: const u8[:], span: Span16) -> const u8[:] {
    let start = span.offset as i64;
    guard start >= 0 && start <= raw.len else { return raw[..0]; }
    let tail = raw[start..];
    let length = span.length as i64;
    guard length >= 0 && length <= tail.len else { return raw[..0]; }
    return tail[..length];
}

fn make_span(base: const u8[:], target: const u8[:], start_hint: i64 = 0) -> Span16 {
    let target_len = target.len;
    guard target_len > 0 && target_len <= 65535 else { return Span16 { offset: 0, length: 0 }; }
    let base_len = base.len;
    guard base_len >= target_len && base_len <= 65536 else { return Span16 { offset: 0, length: 0 }; }
    let max_idx = core::sub_sat_i64(base_len, target_len);
    var i: i64 = max(0, start_hint);
    while i <= max_idx {
        let end_idx = core::add_sat_i64(i, target_len);
        if base[i..end_idx] == target {
            return Span16 { offset: i as u16, length: target_len as u16 };
        }
        i = core::add_sat_i64(i, 1);
    }
    return Span16 { offset: 0, length: 0 };
}
