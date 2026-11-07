// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation X.509 PKI, canonical ASN.1 DER parser, and RFC 5280 validator.
// Conforms to RFC 5280, RFC 6125 (SAN matching), RFC 8446 Section 4.4.3 (CertificateVerify).
namespace wing;

import std;
import core from "..";
import .record;

// ---- ASN.1 Universal Tags and OIDs ---------------------------------------

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

// ---- Strict Canonical ASN.1 DER Parser -----------------------------------

// Parses ASN.1 length field with canonical DER rules (X.690 Section 10.1):
// - Short form: 0..127 (1 byte)
// - Long form: byte 0 has bit 8 set, remaining 7 bits is length of length (1..4)
// - Long form with length < 128 is strictly FORBIDDEN (non-minimal shortest form rule).
// - BER indefinite length (0x80) is strictly FORBIDDEN.
// - Redundant leading zeros in long form (e.g. 0x82 0x00 0x80) are strictly FORBIDDEN.
// - Reserved initial octet 0xFF (11111111_2) is strictly FORBIDDEN (X.690 §8.1.3.5(c)).
// - Enforces non-negative 31-bit bounds (0..0x7FFFFFFF) to prevent integer overflows.
fn read_asn1_long_length(c: ByteCursor&, num_bytes: i64, out_len: i64&) -> bool {
    guard num_bytes >= 1 && num_bytes <= 4 else { return false; }
    var length: i64 = 0;
    var i:      i64 = 0;
    while i < num_bytes {
        var b: u8 = 0;
        guard c.get_u8(b) else { return false; }
        guard i != 0 || b != 0x00 else { return false; }
        length = (length << 8) | b;
        i++;
    }
    guard length >= 128 && length <= 0x7FFFFFFF else { return false; }
    out_len = length;
    return true;
}

fn get_asn1_length(c: ByteCursor&, out_len: i64&) -> bool {
    var b0: u8 = 0;
    if !c.get_u8(b0) { return false; }

    if (b0 & 0x80) == 0 {
        out_len = b0;
        return true;
    }

    guard b0 != 0x80 && b0 != 0xFF else { return false; }
    let num_bytes = (b0 & 0x7F) as i64;
    guard num_bytes >= 1 && num_bytes <= 4 else { return false; }
    guard c.cursor_len() >= num_bytes else { return false; }
    return read_asn1_long_length(c, num_bytes, out_len);
}

// Consumes any ASN.1 TLV element, returning tag and value cursor.
fn get_any_asn1_element(c: ByteCursor&, out_tag: u8&, out_val: ByteCursor&) -> bool {
    if !c.get_u8(out_tag) { return false; }
    var length: i64 = 0;
    if !get_asn1_length(c, length) { return false; }
    return c.get_bytes(out_val, length);
}

// Consumes an ASN.1 element with an expected tag.
fn get_asn1_element(c: ByteCursor&, expected_tag: u8, out_val: ByteCursor&) -> bool {
    var tag: u8 = 0;
    if !get_any_asn1_element(c, tag, out_val) { return false; }
    return tag == expected_tag;
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

// Validates canonical DER rules for ASN.1 INTEGER (X.690 Section 8.3):
// - Length must be >= 1 (zero-length integer is forbidden).
// - No redundant leading zero padding (if first byte is 0x00 and len > 1, next byte must have bit 7 set).
// - No redundant negative sign extension (if first byte is 0xFF and len > 1, next byte must have bit 7 clear).
// - For X.509 serial numbers (RFC 5280 §4.1.2.2): MUST be positive (strictly > 0), max 20 octets.
inline fn validate_asn1_integer(val: const u8[:], is_serial_number: bool) -> bool {
    guard asn1_check_der_integer_padding(val) else { return false; }
    if is_serial_number {
        return asn1_check_serial_number_rules(val);
    }
    return true;
}

// Consumes an ASN.1 INTEGER element and decodes it into out_val (i64),
// enforcing strict DER canonical encoding rules (X.690 Section 8.3 & 10.1):
// - Tag must be ASN1_TAG_INTEGER (0x02).
// - Length must be 1..8 bytes. Zero-length integer is strictly FORBIDDEN.
// - Redundant leading zeros forbidden: if len > 1 and byte 0 is 0x00, byte 1 bit 7 must be 1.
// - Redundant negative sign extension forbidden: if len > 1 and byte 0 is 0xFF, byte 1 bit 7 must be 0.
// - Evaluates two's complement value into signed 64-bit integer.
fn get_asn1_integer(c: ByteCursor&, out_val: i64&) -> bool {
    var raw = core::cursor_from(c.buf[..0]);
    if !get_asn1_element(c, rfc::ASN1_TAG_INTEGER, raw) { return false; }
    guard raw.buf.len >= 1 && raw.buf.len <= 8 else { return false; }
    guard asn1_check_der_integer_padding(raw.buf) else { return false; }

    var val: i64 = if (raw.buf[0] & 0x80) != 0 { -1 } else { 0 };
    for b in raw.buf {
        val = (val << 8) | b;
    }
    out_val = val;
    return true;
}

// Validates canonical DER rules for ASN.1 BIT STRING (X.690 Section 8.4 & 10.2):
// - Length must be >= 1 (initial octet encodes number of unused bits).
// - Unused bits octet MUST be in range 0..7.
// - If the bit string is empty (length == 1, 0 data octets), unused bits MUST be 0.
// - Trailing unused bits in the last data octet MUST be set to zero.
inline fn validate_asn1_bit_string(val: const u8[:]) -> bool {
    guard val.len >= 1 else { return false; }
    let unused = val[0];
    guard unused <= 7 else { return false; }
    if val.len == 1 {
        return unused == 0;
    }
    guard unused > 0 else { return true; }
    let last_byte = val[val.len - 1];
    let mask = ((1 as u16 << unused) - 1) as u8;
    return (last_byte & mask) == 0;
}

// Consumes an ASN.1 BIT STRING element, validating DER unused bits rules and extracting bit payload.
fn get_asn1_bit_string(c: ByteCursor&, out_bits: ByteCursor&, out_unused: u8&) -> bool {
    var raw = core::cursor_from(c.buf[..0]);
    if !get_asn1_element(c, rfc::ASN1_TAG_BIT_STRING, raw) { return false; }
    guard validate_asn1_bit_string(raw.buf) else { return false; }
    out_unused = raw.buf[0];
    out_bits = ByteCursor { buf: raw.buf[1..] };
    return true;
}

// ---- Date & Time Parser (UTCTime & GeneralizedTime) -----------------------

// Parses a 2-digit decimal integer from a slice at the given offset.
//
// Example:
//   buf = "20261028", off = 2
//   returns: val = 26, ok = true
inline fn parse_2digit(buf: const u8[:], off: i64) -> i64, bool {
    guard off >= 0 && off <= buf.len - 2 else { return 0, false; }
    let c1 = buf[off];
    let c2 = buf[off + 1];
    guard c1 >= '0' && c1 <= '9' else { return 0, false; }
    guard c2 >= '0' && c2 <= '9' else { return 0, false; }
    return (c1 - '0') * 10 + (c2 - '0'), true;
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
    let total_secs = days * 86400 + hour * 3600 + min * 60 + sec;
    return total_secs, true;
}

// Parses UTCTime ("YYMMDDHHMMSSZ") per RFC 5280 Section 4.1.2.5.1:
// - Must be exactly 13 bytes ending with 'Z'.
// - Conforming systems MUST interpret YY >= 50 as 19YY (1950..1999) and YY < 50 as 20YY (2000..2049).
// - Dates in the year 2050 or later MUST NOT be encoded in UTCTime.
// - Full date and leap-year validation.
// Example:
//   time_bytes = "261028000000Z"
//   returns: epoch_secs = 1793145600, ok = true
fn parse_utc_time(time_bytes: const u8[:]) -> i64, bool {
    guard time_bytes.len == 13 && time_bytes[12] == 'Z' else { return 0, false; }
    let y2, ok_y = parse_2digit(time_bytes, 0);
    guard ok_y else { return 0, false; }

    // RFC 5280 Section 4.1.2.5.1: YY >= 50 -> 19YY, YY < 50 -> 20YY
    let year = if y2 >= 50 { 1900 + y2 } else { 2000 + y2 };

    let month, ok_m = parse_2digit(time_bytes, 2);
    guard ok_m else { return 0, false; }
    let day, ok_d = parse_2digit(time_bytes, 4);
    guard ok_d else { return 0, false; }
    let hour, ok_h = parse_2digit(time_bytes, 6);
    guard ok_h else { return 0, false; }
    let min, ok_min = parse_2digit(time_bytes, 8);
    guard ok_min else { return 0, false; }
    let sec, ok_s = parse_2digit(time_bytes, 10);
    guard ok_s else { return 0, false; }

    return civil_to_epoch_seconds(year, month, day, hour, min, sec);
}

// Parses GeneralizedTime ("YYYYMMDDHHMMSSZ") per RFC 5280 Section 4.1.2.5.2:
// - Must be exactly 15 bytes ending with 'Z'.
// - Fractional seconds are strictly FORBIDDEN.
// - Full date and leap-year validation.
// Example:
//   time_bytes = "20261028000000Z"
//   returns: epoch_secs = 1793145600, ok = true
fn parse_generalized_time(time_bytes: const u8[:]) -> i64, bool {
    guard time_bytes.len == 15 && time_bytes[14] == 'Z' else { return 0, false; }
    let y1, ok_y1 = parse_2digit(time_bytes, 0);
    guard ok_y1 else { return 0, false; }
    let y2, ok_y2 = parse_2digit(time_bytes, 2);
    guard ok_y2 else { return 0, false; }
    let year = y1 * 100 + y2;

    let month, ok_m = parse_2digit(time_bytes, 4);
    guard ok_m else { return 0, false; }
    let day, ok_d = parse_2digit(time_bytes, 6);
    guard ok_d else { return 0, false; }
    let hour, ok_h = parse_2digit(time_bytes, 8);
    guard ok_h else { return 0, false; }
    let min, ok_min = parse_2digit(time_bytes, 10);
    guard ok_min else { return 0, false; }
    let sec, ok_s = parse_2digit(time_bytes, 12);
    guard ok_s else { return 0, false; }

    return civil_to_epoch_seconds(year, month, day, hour, min, sec);
}

// Parses UTCTime ("YYMMDDHHMMSSZ") or GeneralizedTime ("YYYYMMDDHHMMSSZ") to Unix timestamp seconds.
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

// ---- Span16 and ParsedCert Descriptor (Zero Heap Allocations) ------------

struct Span16 {
    offset: u16 = 0,
    length: u16 = 0,
}

fn span_slice(raw: const u8[:], span: Span16) -> const u8[:] {
    let start = span.offset as i64;
    let end = start + span.length;
    guard end <= raw.len else { return raw[..0]; }
    return raw[start..end];
}

fn make_span(base: const u8[:], target: const u8[:]) -> Span16 {
    let target_len = target.len;
    guard target_len > 0 && target_len <= 65535 else { return Span16 { offset: 0, length: 0 }; }
    let base_len = base.len;
    guard base_len >= target_len && base_len <= 65536 else { return Span16 { offset: 0, length: 0 }; }
    let max_idx = base_len - target_len;
    var i: i64 = 0;
    while i <= max_idx {
        if base[i..i + target_len] == target {
            return Span16 { offset: i as u16, length: target_len as u16 };
        }
        i++;
    }
    return Span16 { offset: 0, length: 0 };
}

const EKU_SERVER_AUTH:  u8 = 1; // RFC 5280 Section 4.2.1.12
const EKU_CLIENT_AUTH:  u8 = 2; // RFC 5280 Section 4.2.1.12
const EKU_OCSP_SIGNING: u8 = 4; // RFC 5280 Section 4.2.1.12
const EKU_ANY:          u8 = 8; // RFC 5280 Section 4.2.1.12

const SCT_VERSION_V1:        u8  = 0;  // RFC 6962 Section 3.2
const SCT_V1_HEADER_MIN_LEN: i64 = 43; // RFC 6962 Section 3.2: version(1) + log_id(32) + timestamp(8) + ext_len(2)
const SCT_LOG_ID_LEN:        i64 = 32; // RFC 6962 Section 3.2: SHA-256 log ID

struct ParsedSct {
    version:      u8     = 0,
    log_id:       u8[32] = [0; 32],
    timestamp_ms: u64    = 0,
    hash_alg:     u8     = 0,
    sig_alg:      u8     = 0,
    signature:    Span16 = Span16 { offset: 0, length: 0 },
}

struct ParsedCert {
    raw_len:                          u32    = 0,
    tbs_cert:                         Span16 = Span16 { offset: 0, length: 0 },
    serial_number:                    Span16 = Span16 { offset: 0, length: 0 },
    sig_alg_oid:                      Span16 = Span16 { offset: 0, length: 0 },
    issuer_raw:                       Span16 = Span16 { offset: 0, length: 0 },
    validity_not_before:              i64    = 0,
    validity_not_after:               i64    = 0,
    subject_raw:                      Span16 = Span16 { offset: 0, length: 0 },
    spki_raw:                         Span16 = Span16 { offset: 0, length: 0 },
    spki_alg_oid:                     Span16 = Span16 { offset: 0, length: 0 },
    spki_pubkey:                      Span16 = Span16 { offset: 0, length: 0 },
    extensions_raw:                   Span16 = Span16 { offset: 0, length: 0 },
    san_raw:                          Span16 = Span16 { offset: 0, length: 0 },
    has_san:                          bool   = false,
    is_ca:                            bool   = false,
    has_basic_constraints:            bool   = false,
    path_len_constraint:              i32    = -1,
    key_usage:                        u16    = 0,
    has_key_usage:                    bool   = false,
    has_unsupported_critical:         bool   = false,
    akid_key_id:                      Span16 = Span16 { offset: 0, length: 0 },
    has_akid:                         bool   = false,
    skid_key_id:                      Span16 = Span16 { offset: 0, length: 0 },
    has_skid:                         bool   = false,
    name_constraints_raw:             Span16 = Span16 { offset: 0, length: 0 },
    has_name_constraints:             bool   = false,
    has_malformed_policy_constraints: bool   = false,
    has_must_staple:                  bool   = false,
    has_sct_list:                     bool   = false,
    sct_count:                        u8     = 0,
    has_eku:                          bool   = false,
    eku_mask:                         u8     = 0,
    signature_value:                  Span16 = Span16 { offset: 0, length: 0 },
}

fn read_tbs_serial(raw_cert: const u8[:], tbs_seq: ByteCursor&, out: ParsedCert&) -> bool {
    var serial = core::cursor_from(raw_cert[..0]);
    if !get_asn1_element(tbs_seq, rfc::ASN1_TAG_INTEGER, serial) { return false; }
    if !validate_asn1_integer(serial.buf, true) { return false; }
    out.serial_number = make_span(raw_cert, serial.buf);
    return true;
}

fn read_tbs_sig_alg(raw_cert: const u8[:], tbs_seq: ByteCursor&, out: ParsedCert&) -> bool {
    var sig_alg = core::cursor_from(raw_cert[..0]);
    if !get_asn1_element(tbs_seq, rfc::ASN1_TAG_SEQUENCE, sig_alg) { return false; }
    var sig_oid = core::cursor_from(raw_cert[..0]);
    if !get_asn1_element(sig_alg, rfc::ASN1_TAG_OID, sig_oid) { return false; }
    out.sig_alg_oid = make_span(raw_cert, sig_oid.buf);
    return true;
}

fn read_tbs_validity(raw_cert: const u8[:], tbs_seq: ByteCursor&, out: ParsedCert&) -> bool {
    var validity = core::cursor_from(raw_cert[..0]);
    if !get_asn1_element(tbs_seq, rfc::ASN1_TAG_SEQUENCE, validity) { return false; }
    var nb_val = core::cursor_from(raw_cert[..0]);
    var nb_tag: u8 = 0;
    if !get_any_asn1_element(validity, nb_tag, nb_val) { return false; }
    let nb_time, ok_nb = parse_asn1_time(nb_tag, nb_val.buf);
    guard ok_nb else { return false; }
    out.validity_not_before = nb_time;

    var na_val = core::cursor_from(raw_cert[..0]);
    var na_tag: u8 = 0;
    if !get_any_asn1_element(validity, na_tag, na_val) { return false; }
    let na_time, ok_na = parse_asn1_time(na_tag, na_val.buf);
    guard ok_na else { return false; }
    out.validity_not_after = na_time;

    // RFC 5280 §4.1.2.5: Validity period inversion check (notBefore <= notAfter)
    guard out.validity_not_before <= out.validity_not_after else { return false; }
    return true;
}

fn read_tbs_spki(raw_cert: const u8[:], tbs_seq: ByteCursor&, out: ParsedCert&) -> bool {
    var spki = core::cursor_from(raw_cert[..0]);
    if !get_asn1_element(tbs_seq, rfc::ASN1_TAG_SEQUENCE, spki) { return false; }
    out.spki_raw = make_span(raw_cert, spki.buf);

    var spki_alg = core::cursor_from(raw_cert[..0]);
    if !get_asn1_element(spki, rfc::ASN1_TAG_SEQUENCE, spki_alg) { return false; }
    var spki_oid = core::cursor_from(raw_cert[..0]);
    if !get_asn1_element(spki_alg, rfc::ASN1_TAG_OID, spki_oid) { return false; }

    var spki_curve = core::cursor_from(raw_cert[..0]);
    if spki_oid.buf == rfc::OID_EC_PUBLIC_KEY[..] && get_asn1_element(spki_alg, rfc::ASN1_TAG_OID, spki_curve) {
        out.spki_alg_oid = make_span(raw_cert, spki_curve.buf);
    } else {
        out.spki_alg_oid = make_span(raw_cert, spki_oid.buf);
    }

    var spki_pubkey = core::cursor_from(raw_cert[..0]);
    if !get_asn1_element(spki, rfc::ASN1_TAG_BIT_STRING, spki_pubkey) { return false; }
    if !validate_asn1_bit_string(spki_pubkey.buf) { return false; }
    out.spki_pubkey = make_span(raw_cert, spki_pubkey.buf);
    return true;
}

fn read_tbs_extensions(raw_cert: const u8[:], tbs_seq: ByteCursor&, out: ParsedCert&) -> bool {
    while tbs_seq.cursor_len() > 0 {
        var ext_container = core::cursor_from(raw_cert[..0]);
        var ext_tag: u8 = 0;
        if !get_any_asn1_element(tbs_seq, ext_tag, ext_container) {
            out.has_unsupported_critical = true;
            return false;
        }
        if ext_tag == 0xA3 { // [3] EXPLICIT
            var ext_seq = core::cursor_from(raw_cert[..0]);
            guard get_asn1_element(ext_container, rfc::ASN1_TAG_SEQUENCE, ext_seq) &&
                ext_container.cursor_len() == 0 && ext_seq.cursor_len() > 0 else {
                out.has_unsupported_critical = true;
                return false;
            }
            out.extensions_raw = make_span(raw_cert, ext_seq.buf);
            if !read_cert_extensions(raw_cert, ext_seq, out) {
                return false;
            }
        }
    }
    return true;
}

fn x509_read_outer_sequence(raw_cert: const u8[:], cert_seq: ByteCursor&) -> bool {
    guard raw_cert.len > 0 && raw_cert.len <= 65535 else { return false; }
    var cert_cursor = core::cursor_from(raw_cert);
    if !get_asn1_element(cert_cursor, rfc::ASN1_TAG_SEQUENCE, cert_seq) { return false; }
    return cert_cursor.cursor_len() == 0;
}

// Parses raw X.509 certificate DER into zero-allocation ParsedCert descriptor (RFC 5280 Section 4.1).
// Extracts spans for tbsCertificate, serial, issuer, validity, subject, SPKI, and signature.
//
// Example:
//   raw_cert = "\x30\x82\x01\x20\x30\x81\xC8..." (valid X.509 DER Certificate)
//   returns: true, out.raw_len = 292, out.signature_value.length = 64
fn parse_x509_certificate(raw_cert: const u8[:], out: ParsedCert&) -> bool {
    out.raw_len = raw_cert.len as u32;
    var cert_seq = core::cursor_from(raw_cert[..0]);
    guard x509_read_outer_sequence(raw_cert, cert_seq) else { return false; }

    // TBSCertificate SEQUENCE
    let tbs_raw_start = cert_seq.buf;
    var tbs_seq = core::cursor_from(raw_cert[..0]);
    if !get_asn1_element(cert_seq, rfc::ASN1_TAG_SEQUENCE, tbs_seq) { return false; }
    let tbs_tlv_len = core::sub_sat_i64(tbs_raw_start.len, cert_seq.buf.len);
    out.tbs_cert = make_span(raw_cert, tbs_raw_start[..tbs_tlv_len]);

    guard x509_read_tbs_components(raw_cert, tbs_seq, out) else { return false; }
    return x509_read_outer_signature(raw_cert, cert_seq, out);
}

fn x509_read_tbs_components(raw_cert: const u8[:], tbs_seq: ByteCursor&, out: ParsedCert&) -> bool {
    guard x509_skip_tbs_version(tbs_seq) else { return false; }
    if !read_tbs_serial(raw_cert, tbs_seq, out) { return false; }
    if !read_tbs_sig_alg(raw_cert, tbs_seq, out) { return false; }
    return read_tbs_identity(raw_cert, tbs_seq, out);
}

fn x509_read_outer_signature(raw_cert: const u8[:], cert_seq: ByteCursor&, out: ParsedCert&) -> bool {
    guard cert_seq.cursor_len() > 0 else { return false; }
    var outer_sig_alg = core::cursor_from(raw_cert[..0]);
    if !get_asn1_element(cert_seq, rfc::ASN1_TAG_SEQUENCE, outer_sig_alg) { return false; }
    var outer_sig_oid = core::cursor_from(raw_cert[..0]);
    if !get_asn1_element(outer_sig_alg, rfc::ASN1_TAG_OID, outer_sig_oid) { return false; }

    // RFC 5280 §4.1.2.3: Outer and inner signature algorithms MUST match
    let inner_sig_oid = span_slice(raw_cert, out.sig_alg_oid);
    guard outer_sig_oid.buf == inner_sig_oid else { return false; }

    var sig_bits = core::cursor_from(raw_cert[..0]);
    var unused_bits: u8 = 0;
    if !get_asn1_bit_string(cert_seq, sig_bits, unused_bits) { return false; }
    guard unused_bits == 0 && sig_bits.buf.len > 0 else { return false; }
    out.signature_value = make_span(raw_cert, sig_bits.buf);

    guard cert_seq.cursor_len() == 0 else { return false; }
    return true;
}

fn x509_skip_tbs_version(tbs_seq: ByteCursor&) -> bool {
    if tbs_seq.cursor_len() > 0 && tbs_seq.buf[0] == 0xA0 {
        var maybe_version = core::cursor_from(tbs_seq.buf[..0]);
        var tag: u8 = 0;
        return get_any_asn1_element(tbs_seq, tag, maybe_version);
    }
    return true;
}

fn read_tbs_identity(raw_cert: const u8[:], tbs_seq: ByteCursor&, out: ParsedCert&) -> bool {
    var issuer = core::cursor_from(raw_cert[..0]);
    if !get_asn1_element(tbs_seq, rfc::ASN1_TAG_SEQUENCE, issuer) { return false; }
    out.issuer_raw = make_span(raw_cert, issuer.buf);

    if !read_tbs_validity(raw_cert, tbs_seq, out) { return false; }

    var subject = core::cursor_from(raw_cert[..0]);
    if !get_asn1_element(tbs_seq, rfc::ASN1_TAG_SEQUENCE, subject) { return false; }
    out.subject_raw = make_span(raw_cert, subject.buf);

    if !read_tbs_spki(raw_cert, tbs_seq, out) { return false; }
    return read_tbs_extensions(raw_cert, tbs_seq, out);
}

fn x509_parse_bc_ca_bool(bc_seq: ByteCursor&, cert: ParsedCert&) {
    guard bc_seq.cursor_len() > 0 && bc_seq.buf[0] == rfc::ASN1_TAG_BOOLEAN else { return; }
    var ca_bool = core::cursor_from(bc_seq.buf[..0]);
    guard get_asn1_element(bc_seq, rfc::ASN1_TAG_BOOLEAN, ca_bool) else { return; }
    if ca_bool.buf.len > 0 && ca_bool.buf[0] != 0 {
        cert.is_ca = true;
    }
}

fn x509_parse_bc_path_len(bc_seq: ByteCursor&, cert: ParsedCert&) {
    guard bc_seq.cursor_len() > 0 && bc_seq.buf[0] == rfc::ASN1_TAG_INTEGER else { return; }
    var path_len: i64 = 0;
    guard get_asn1_integer(bc_seq, path_len) else {
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

fn x509_parse_basic_constraints_ext(ext_val: ByteCursor&, cert: ParsedCert&) {
    if cert.has_basic_constraints {
        cert.has_unsupported_critical = true;
        return;
    }
    cert.has_basic_constraints = true;
    var bc_seq = core::cursor_from(ext_val.buf[..0]);
    guard get_asn1_element(ext_val, rfc::ASN1_TAG_SEQUENCE, bc_seq) else {
        cert.has_unsupported_critical = true;
        return;
    }
    x509_parse_bc_ca_bool(bc_seq, cert);
    x509_parse_bc_path_len(bc_seq, cert);
    if bc_seq.cursor_len() > 0 {
        cert.has_unsupported_critical = true;
    }
}

fn x509_parse_key_usage_ext(ext_val: ByteCursor&, cert: ParsedCert&) {
    if cert.has_key_usage {
        cert.has_unsupported_critical = true;
        return;
    }
    cert.has_key_usage = true;
    var ku_bits = core::cursor_from(ext_val.buf[..0]);
    guard get_asn1_element(ext_val, rfc::ASN1_TAG_BIT_STRING, ku_bits) else {
        cert.has_unsupported_critical = true;
        return;
    }
    guard validate_asn1_bit_string(ku_bits.buf) && ku_bits.buf.len >= 2 else {
        cert.has_unsupported_critical = true;
        return;
    }

    var ku: u16 = (ku_bits.buf[1] as u16) << 8;
    if ku_bits.buf.len >= 3 {
        ku = ku | ku_bits.buf[2];
    }
    cert.key_usage = ku;
}

fn x509_parse_akid_ext(raw_cert: const u8[:], ext_val: ByteCursor&, cert: ParsedCert&) {
    var akid_seq = core::cursor_from(ext_val.buf[..0]);
    guard get_asn1_element(ext_val, rfc::ASN1_TAG_SEQUENCE, akid_seq) else { return; }
    guard akid_seq.cursor_len() > 0 && akid_seq.buf[0] == 0x80 else { return; }
    var akid_key = core::cursor_from(akid_seq.buf[..0]);
    guard get_asn1_element(akid_seq, 0x80, akid_key) else { return; }
    guard akid_key.buf.len > 0 && akid_key.buf.len <= 64 else { return; }
    cert.has_akid = true;
    cert.akid_key_id = make_span(raw_cert, akid_key.buf);
}

fn x509_parse_skid_ext(raw_cert: const u8[:], ext_val: ByteCursor&, cert: ParsedCert&) {
    var skid_oct = core::cursor_from(ext_val.buf[..0]);
    guard get_asn1_element(ext_val, rfc::ASN1_TAG_OCTET_STRING, skid_oct) else { return; }
    guard skid_oct.buf.len > 0 && skid_oct.buf.len <= 64 else { return; }
    cert.has_skid = true;
    cert.skid_key_id = make_span(raw_cert, skid_oct.buf);
}

inline fn x509_check_policy_skip_certs(elem_buf: const u8[:]) -> bool {
    return elem_buf.len > 0 && (elem_buf[0] & 0x80) == 0;
}

fn x509_parse_policy_constraints_ext(ext_val: ByteCursor&, cert: ParsedCert&) {
    var pc_seq = core::cursor_from(ext_val.buf[..0]);
    if !get_asn1_element(ext_val, rfc::ASN1_TAG_SEQUENCE, pc_seq) || pc_seq.cursor_len() == 0 {
        cert.has_malformed_policy_constraints = true;
        return;
    }

    while pc_seq.cursor_len() > 0 {
        var pc_tag: u8 = 0;
        var pc_elem = core::cursor_from(pc_seq.buf[..0]);
        if !get_any_asn1_element(pc_seq, pc_tag, pc_elem) {
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
fn x509_parse_tls_feature_ext(ext_val: const u8[:], cert: ParsedCert&) -> bool {
    var c = core::cursor_from(ext_val);
    var feat_seq = core::cursor_from(ext_val[..0]);
    guard get_asn1_element(c, rfc::ASN1_TAG_SEQUENCE, feat_seq) && c.cursor_len() == 0 else {
        cert.has_unsupported_critical = true;
        return false;
    }
    guard feat_seq.cursor_len() > 0 else {
        cert.has_unsupported_critical = true;
        return false;
    }
    while feat_seq.cursor_len() > 0 {
        var feat_id: i64 = 0;
        guard get_asn1_integer(feat_seq, feat_id) && feat_id >= 0 && feat_id <= 65535 else {
            cert.has_unsupported_critical = true;
            return false;
        }
        if feat_id == rfc::TLS_EXT_STATUS_REQUEST {
            cert.has_must_staple = true;
        }
    }
    return true;
}

// Packs two big-endian 32-bit halves into an RFC 6962 §3.2 64-bit millisecond timestamp.
//
// Example:
//   ts_hi = 0x0000018E, ts_lo = 0x00000001
//   returns: 0x0000018E00000001
inline fn pack_sct_timestamp_ms(ts_hi: u32, ts_lo: u32) -> u64 {
    return ((ts_hi as u64) << 32) | ts_lo;
}

// Parses a single RFC 6962 §3.2 v1 SignedCertificateTimestamp entry from `raw`.
//
// Example:
//   raw = [0x00, <32B log_id>, <8B timestamp_ms>, 0x00, 0x00, 0x04, 0x03, 0x00, 0x02, 0xAA, 0xBB]
//   returns: true, out.version = 0, out.hash_alg = 4, out.sig_alg = 3, out.signature.length = 2
fn parse_sct_entry(raw: const u8[:], out: ParsedSct&) -> bool {
    guard raw.len >= SCT_V1_HEADER_MIN_LEN && raw.len <= 65535 else { return false; }
    var c = core::cursor_from(raw);
    var ver: u8 = 0;
    guard c.get_u8(ver) && ver == SCT_VERSION_V1 else { return false; }

    var log_cursor = core::cursor_from(raw[..0]);
    guard c.get_bytes(log_cursor, SCT_LOG_ID_LEN) else { return false; }

    var ts_hi: u32 = 0;
    var ts_lo: u32 = 0;
    guard c.get_u32(ts_hi) && c.get_u32(ts_lo) else { return false; }

    var ext_cursor = core::cursor_from(raw[..0]);
    guard c.get_u16_length_prefixed(ext_cursor) else { return false; }

    var hash_alg: u8 = 0;
    var sig_alg:  u8 = 0;
    guard c.get_u8(hash_alg) && c.get_u8(sig_alg) else { return false; }

    var sig_cursor = core::cursor_from(raw[..0]);
    guard c.get_u16_length_prefixed(sig_cursor) &&
        sig_cursor.buf.len > 0 && c.cursor_len() == 0 else { return false; }

    out.version = ver;
    core::ct_copy_bytes(out.log_id[..], log_cursor.buf);
    out.timestamp_ms = pack_sct_timestamp_ms(ts_hi, ts_lo);
    out.hash_alg = hash_alg;
    out.sig_alg = sig_alg;
    out.signature = make_span(raw, sig_cursor.buf);
    return true;
}

// Parses an RFC 6962 §3.3 `SignedCertificateTimestampList` into `out_scts`.
//
// Example:
//   raw_list = [0x00, 0x31, 0x00, 0x2F, <47B v1 SerializedSCT>]
//   returns: true, out_scts.len = 1
fn parse_sct_list(raw_list: const u8[:], out_scts: ParsedSct[..8]&) -> bool {
    out_scts.clear();
    var c = core::cursor_from(raw_list);
    var list_cursor = core::cursor_from(raw_list[..0]);
    guard c.get_u16_length_prefixed(list_cursor) &&
        c.cursor_len() == 0 && list_cursor.cursor_len() > 0 else { return false; }

    while list_cursor.cursor_len() > 0 {
        var sct_cursor = core::cursor_from(list_cursor.buf[..0]);
        guard list_cursor.get_u16_length_prefixed(sct_cursor) &&
            sct_cursor.buf.len > 0 && out_scts.len < out_scts.cap else { return false; }
        var sct = ParsedSct { .. };
        guard parse_sct_entry(sct_cursor.buf, sct) else { return false; }
        out_scts.push(sct);
    }
    return out_scts.len > 0;
}

fn x509_parse_sct_ext(ext_val: ByteCursor&, cert: ParsedCert&) -> bool {
    if cert.has_sct_list {
        cert.has_unsupported_critical = true;
        return false;
    }
    var sct_oct = core::cursor_from(ext_val.buf[..0]);
    guard get_asn1_element(ext_val, rfc::ASN1_TAG_OCTET_STRING, sct_oct) && ext_val.cursor_len() == 0 else {
        cert.has_unsupported_critical = true;
        return false;
    }
    var scts: ParsedSct[..8] = [];
    guard parse_sct_list(sct_oct.buf, scts) else {
        cert.has_unsupported_critical = true;
        return false;
    }
    cert.has_sct_list = true;
    cert.sct_count = scts.len as u8;
    return true;
}

inline fn x509_classify_eku_oid(oid: const u8[:]) -> u8 {
    if oid == rfc::OID_EKU_SERVER_AUTH[..] {
        return EKU_SERVER_AUTH;
    }
    if oid == rfc::OID_EKU_CLIENT_AUTH[..] {
        return EKU_CLIENT_AUTH;
    }
    if oid == rfc::OID_EKU_OCSP_SIGNING[..] {
        return EKU_OCSP_SIGNING;
    }
    if oid == rfc::OID_EKU_ANY[..] {
        return EKU_ANY;
    }
    return 0;
}

// Parses RFC 5280 §4.2.1.12 ExtendedKeyUsage (`SEQUENCE SIZE (1..MAX) OF KeyPurposeId`).
// Rejects empty sequences, duplicate extensions, and non-OID elements.
//
// Example:
//   ext_val = [0x30, 0x0A, 0x06, 0x08, 0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x03, 0x01]
//   returns: true, cert.has_eku = true, cert.eku_mask = 1 (EKU_SERVER_AUTH)
fn x509_parse_eku_ext(ext_val: const u8[:], cert: ParsedCert&) -> bool {
    if cert.has_eku {
        cert.has_unsupported_critical = true;
        return false;
    }
    var c = core::cursor_from(ext_val);
    var eku_seq = core::cursor_from(ext_val[..0]);
    guard get_asn1_element(c, rfc::ASN1_TAG_SEQUENCE, eku_seq) && c.cursor_len() == 0 else {
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
        guard get_asn1_element(eku_seq, rfc::ASN1_TAG_OID, kp_oid) && kp_oid.buf.len > 0 else {
            cert.has_unsupported_critical = true;
            return false;
        }
        cert.eku_mask = cert.eku_mask | x509_classify_eku_oid(kp_oid.buf);
    }
    return true;
}

fn x509_dispatch_pki_extension(oid: const u8[:], ext_val: ByteCursor&, cert: ParsedCert&) {
    if oid == rfc::OID_EXT_KEY_USAGE[..] {
        let _ = x509_parse_eku_ext(ext_val.buf, cert);
    } else if oid == rfc::OID_TLS_FEATURE[..] {
        let _ = x509_parse_tls_feature_ext(ext_val.buf, cert);
    } else if oid == rfc::OID_CT_PRECERT_SCTS[..] {
        let _ = x509_parse_sct_ext(ext_val, cert);
    }
}

fn x509_dispatch_policy_extension(oid: const u8[:], ext_val: ByteCursor&, cert: ParsedCert&) {
    if oid == rfc::OID_POLICY_CONSTRAINTS[..] {
        x509_parse_policy_constraints_ext(ext_val, cert);
    } else if oid == rfc::OID_INHIBIT_ANY_POLICY[..] {
        var val: i64 = 0;
        if !get_asn1_integer(ext_val, val) || val < 0 {
            cert.has_malformed_policy_constraints = true;
        }
    } else {
        x509_dispatch_pki_extension(oid, ext_val, cert);
    }
}

fn x509_dispatch_extension(raw_cert: const u8[:], oid: const u8[:], ext_val: ByteCursor&, cert: ParsedCert&) {
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
        cert.san_raw = make_span(raw_cert, ext_val.buf);
    } else if oid == rfc::OID_NAME_CONSTRAINTS[..] {
        if cert.has_name_constraints {
            cert.has_unsupported_critical = true;
            return;
        }
        cert.has_name_constraints = true;
        cert.name_constraints_raw = make_span(raw_cert, ext_val.buf);
    } else if oid == rfc::OID_AUTH_KEY_IDENTIFIER[..] {
        x509_parse_akid_ext(raw_cert, ext_val, cert);
    } else if oid == rfc::OID_SUBJECT_KEY_IDENTIFIER[..] {
        x509_parse_skid_ext(raw_cert, ext_val, cert);
    } else {
        x509_dispatch_policy_extension(oid, ext_val, cert);
    }
}

inline fn x509_check_ext_critical(single_ext: ByteCursor&) -> bool {
    guard single_ext.cursor_len() > 0 && single_ext.buf[0] == rfc::ASN1_TAG_BOOLEAN else { return false; }
    var maybe_crit = core::cursor_from(single_ext.buf[..0]);
    if get_asn1_element(single_ext, rfc::ASN1_TAG_BOOLEAN, maybe_crit) {
        return maybe_crit.buf.len > 0 && maybe_crit.buf[0] != 0;
    }
    return false;
}

fn x509_parse_single_cert_extension(raw_cert: const u8[:], single_ext: ByteCursor&, cert: ParsedCert&) -> bool {
    var oid = core::cursor_from(single_ext.buf[..0]);
    if !get_asn1_element(single_ext, rfc::ASN1_TAG_OID, oid) {
        cert.has_unsupported_critical = true;
        return false;
    }

    let is_critical = x509_check_ext_critical(single_ext);

    var ext_val = core::cursor_from(single_ext.buf[..0]);
    if !get_asn1_element(single_ext, rfc::ASN1_TAG_OCTET_STRING, ext_val) {
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
fn read_cert_extensions(raw_cert: const u8[:], ext_seq: ByteCursor&, cert: ParsedCert&) -> bool {
    while ext_seq.cursor_len() > 0 {
        var single_ext = core::cursor_from(ext_seq.buf[..0]);
        if !get_asn1_element(ext_seq, rfc::ASN1_TAG_SEQUENCE, single_ext) {
            cert.has_unsupported_critical = true;
            return false;
        }
        if !x509_parse_single_cert_extension(raw_cert, single_ext, cert) {
            return false;
        }
    }
    return true;
}

// ---- Trust Anchors and RFC 5280 Verification -----------------------------

struct TrustAnchor {
    subject_dn_sha256: u8[32] = [0; 32],
    spki_sha256:       u8[32] = [0; 32],
    is_valid:          bool   = false,
}

struct TrustAnchorStore {
    anchors: TrustAnchor[..16] = [],
}

fn add_trust_anchor(store: TrustAnchorStore&, subject_raw: const u8[:], spki_raw: const u8[:]) -> bool {
    guard store.anchors.len < store.anchors.cap else { return false; }
    let s_hash = core::sha256(subject_raw);
    let spki_hash = core::sha256(spki_raw);
    store.anchors.push(TrustAnchor {
        subject_dn_sha256: s_hash,
        spki_sha256:       spki_hash,
        is_valid:          true,
    });
    return true;
}

// Parses a DER-encoded X.509 certificate and adds its Subject DN and SPKI to the trust anchor store.
fn add_trust_anchor_cert_der(store: TrustAnchorStore&, raw_cert_der: const u8[:]) -> bool {
    var cert = ParsedCert { .. };
    guard parse_x509_certificate(raw_cert_der, cert) else { return false; }
    let subj = span_slice(raw_cert_der, cert.subject_raw);
    let spki = span_slice(raw_cert_der, cert.spki_raw);
    guard subj.len > 0 && spki.len > 0 else { return false; }
    return add_trust_anchor(store, subj, spki);
}

fn matches_trust_anchor(store: const TrustAnchorStore&, cert: const ParsedCert&, raw_cert: const u8[:]) -> bool {
    let s_slice = span_slice(raw_cert, cert.subject_raw);
    let spki_slice = span_slice(raw_cert, cert.spki_raw);
    let s_hash = core::sha256(s_slice);
    let spki_hash = core::sha256(spki_slice);

    for i in store.anchors.len {
        let a = store.anchors[i];
        if a.is_valid && core::ct_eq_tag32(a.subject_dn_sha256, s_hash) && core::ct_eq_tag32(a.spki_sha256, spki_hash) {
            return true;
        }
    }
    return false;
}

const MAX_CHAIN_DEPTH: i64 = 8;

fn validate_chain_cert_validity(cert: const ParsedCert&, now_unix: i64) -> TlsAlert {
    // RFC 5280 §4.1.2.5: Inversion check (notBefore <= notAfter)
    if cert.validity_not_before > cert.validity_not_after {
        return TlsAlert.BadCertificate;
    }
    if now_unix < cert.validity_not_before || now_unix > cert.validity_not_after {
        return TlsAlert.CertificateExpired;
    }
    return TlsAlert.CloseNotify;
}

fn validate_end_entity_constraints(cert: const ParsedCert&) -> TlsAlert {
    // RFC 5280 / RFC 8446 §4.4.2: End-entity certificate MUST NOT be a CA
    if cert.is_ca {
        return TlsAlert.BadCertificate;
    }
    // End-entity MUST NOT assert keyCertSign
    if cert.has_key_usage && (cert.key_usage & rfc::KEY_USAGE_KEY_CERT_SIGN) != 0 {
        return TlsAlert.UnsupportedCertificate;
    }
    // RFC 5280 §4.2.1.12: End-entity EKU must permit serverAuth, clientAuth, or anyExtendedKeyUsage
    if cert.has_eku && (cert.eku_mask & (EKU_SERVER_AUTH | EKU_CLIENT_AUTH | EKU_ANY)) == 0 {
        return TlsAlert.UnsupportedCertificate;
    }
    // RFC 5280 §4.2.1.10: Name constraints MUST NOT be used in end-entity certificates
    if cert.has_name_constraints {
        return TlsAlert.BadCertificate;
    }
    return TlsAlert.CloseNotify;
}

fn validate_intermediate_ca_constraints(cert: const ParsedCert&, depth: i64) -> TlsAlert {
    // Intermediate CA MUST have basicConstraints asserted with cA: TRUE
    if !cert.has_basic_constraints || !cert.is_ca {
        return TlsAlert.BadCertificate;
    }
    // Intermediate CA MUST assert keyCertSign if KeyUsage is present
    if cert.has_key_usage && (cert.key_usage & rfc::KEY_USAGE_KEY_CERT_SIGN) == 0 {
        return TlsAlert.UnsupportedCertificate;
    }
    // pathLenConstraint gives max intermediate certs that may follow this cert
    if cert.path_len_constraint >= 0 && (depth - 1) > cert.path_len_constraint {
        return TlsAlert.BadCertificate;
    }
    return TlsAlert.CloseNotify;
}

// ---- RFC 6125 SAN (Subject Alternative Name) DNS Wildcard Matching ------

// Matches a single DNS hostname against a SAN entry (RFC 6125 Section 6.4.3).
// - Wildcard '*' is only permitted in the leftmost label.
// - Must NOT match apex domain (e.g. *.example.com does not match example.com).
// - Must NOT match multi-level subdomains (e.g. *.example.com does not match a.b.example.com).
// - Case-insensitive comparison.
fn x509_strip_trailing_dot(s: const u8[:]) -> const u8[:] {
    if s.len > 1 && s[s.len - 1] == '.' {
        return s[..s.len - 1];
    }
    return s;
}

inline fn x509_is_ip_literal(host: const u8[:]) -> bool {
    var is_ip = true;
    for b in host {
        if (b < '0' || b > '9') && b != '.' {
            is_ip = false;
            break;
        }
    }
    return is_ip && core::contains_byte(host, '.');
}

fn x509_match_wildcard_san(pat: const u8[:], host: const u8[:]) -> bool {
    guard pat.len >= 3 && pat[0] == '*' && pat[1] == '.' else { return false; }
    let suffix = pat[2..];
    guard !core::contains_byte(suffix, '*') && core::contains_byte(suffix, '.') else { return false; }
    guard !x509_is_ip_literal(host) else { return false; }

    var dot_idx = -1;
    for i in host.len {
        if host[i] == '.' {
            dot_idx = i;
            break;
        }
    }
    guard dot_idx > 0 else { return false; }
    let host_remainder = host[dot_idx + 1..];
    return eq_ascii_fold(host_remainder, suffix);
}

// Matches a single DNS hostname against a SAN entry (RFC 6125 Section 6.4.3).
// - Trailing dots in presented and reference identifiers are normalized/stripped.
// - Embedded NUL bytes rejected (CVE-2009-3555 / CVE-2021-3712).
// - Wildcard '*' is only permitted in the leftmost label.
// - Must NOT match apex domain (e.g. *.example.com does not match example.com).
// - Must NOT match multi-level subdomains (e.g. *.example.com does not match a.b.example.com).
// - Case-insensitive comparison.
fn match_dns_san(san_pattern: const u8[:], host: const u8[:]) -> bool {
    guard san_pattern.len > 0 && host.len > 0 else { return false; }
    guard !core::contains_byte(san_pattern, 0) && !core::contains_byte(host, 0) else { return false; }

    let pat = x509_strip_trailing_dot(san_pattern);
    let h = x509_strip_trailing_dot(host);
    guard pat.len > 0 && h.len > 0 else { return false; }

    if eq_ascii_fold(pat, h) {
        return true;
    }

    return x509_match_wildcard_san(pat, h);
}

// Matches URI SAN and enforces RFC 5280 / CVE-2024-45341 / CVE-2021-3712 defense:
// - IPv6 zone IDs (%zone) inside URIs MUST NOT bypass URI name constraints and must be rejected.
// - Embedded NUL bytes MUST be rejected.
fn match_uri_san(san_uri_host: const u8[:], request_host: const u8[:]) -> bool {
    if core::contains_byte(san_uri_host, '%') || core::contains_byte(request_host, '%') {
        return false;
    }
    if core::contains_byte(san_uri_host, 0) || core::contains_byte(request_host, 0) {
        return false;
    }
    return eq_ascii_fold(san_uri_host, request_host);
}

enum SanType {
    Dns,
    Ip,
    Uri,
    Email,
    Other,
}

struct SanEntry {
    san_type: SanType     = SanType.Dns,
    val:      const u8[:] = [],
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
    guard b >= '0' && b <= '9' else { return false; }
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
    let is_alnum = (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9');
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

// Validates DNS name syntax for SAN (RFC 5280 §4.2.1.6, RFC 1034 §3.5, RFC 1123 §2.1, RFC 6125 §6.4.3):
// - Length between 1 and 253 octets.
// - Must not start or end with a dot.
// - No adjacent dots ('..').
// - Each label 1..63 octets.
// - Each label chars: alphanumeric or hyphen; wildcard '*' allowed only as single character in leftmost label.
// - Hyphen must not be leading or trailing character in any label.
fn validate_san_dns_name(dns: const u8[:]) -> bool {
    guard dns.len >= 1 && dns.len <= 253 else { return false; }
    guard dns[0] != '.' && dns[dns.len - 1] != '.' else { return false; }

    var label_start: i64 = 0;
    var label_idx:   i64 = 0;

    for i in dns.len + 1 {
        let is_end = (i == dns.len);
        let is_dot = !is_end && (dns[i] == '.');
        if is_end || is_dot {
            let label = dns[label_start..i];
            guard x509_validate_dns_label(label, label_idx) else { return false; }
            label_start = i + 1;
            label_idx++;
        }
    }
    return true;
}

inline fn x509_classify_san_element(tag_num: u8, elem_buf: const u8[:], out_type: SanType&) -> bool {
    if tag_num == 1 { // rfc822Name [1] IA5String
        guard elem_buf.len > 0 && !core::contains_byte(elem_buf, 0) else { return false; }
        out_type = SanType.Email;
        return true;
    }
    if tag_num == 2 { // dNSName [2] IA5String
        guard validate_san_dns_name(elem_buf) else { return false; }
        out_type = SanType.Dns;
        return true;
    }
    if tag_num == 7 { // iPAddress [7] OCTET STRING
        guard elem_buf.len == 4 || elem_buf.len == 16 else { return false; }
        out_type = SanType.Ip;
        return true;
    }
    if tag_num == 6 { // uniformResourceIdentifier [6] IA5String
        guard elem_buf.len > 0 else { return false; }
        guard !core::contains_byte(elem_buf, '%') && !core::contains_byte(elem_buf, 0) else { return false; }
        out_type = SanType.Uri;
        return true;
    }
    guard tag_num <= 8 else { return false; }
    out_type = SanType.Other;
    return true;
}

// Parses raw SubjectAltName extension DER (GeneralNames sequence) into zero-allocation SanEntry array.
// RFC 5280 Section 4.2.1.6:
// - Outer container must be a SEQUENCE.
// - SEQUENCE SIZE (1..MAX) OF GeneralName: empty SAN sequence is strictly FORBIDDEN.
// - iPAddress MUST be exactly 4 octets (IPv4) or 16 octets (IPv6).
// - dNSName MUST be valid preferred name syntax.
// Example:
fn x509_parse_single_san(names_seq: ByteCursor&, out_sans: SanEntry[..16]&) -> bool {
    var tag: u8 = 0;
    var elem = core::cursor_from(names_seq.buf[..0]);
    guard get_any_asn1_element(names_seq, tag, elem) else { return false; }

    let tag_num = tag & 0x1F;
    var st = SanType.Other;
    guard x509_classify_san_element(tag_num, elem.buf, st) else { return false; }

    guard out_sans.len < out_sans.cap else { return false; }
    out_sans.push(SanEntry {
        san_type: st,
        val:      elem.buf,
    });
    return true;
}

// Example:
//   san_der = 0x30 0x0E 0x82 0x0C "example.com"
//   returns: ok = true, out_sans contains SanType.Dns "example.com"
fn parse_san_extension(san_der: const u8[:], out_sans: SanEntry[..16]&) -> bool {
    var c = core::cursor_from(san_der);
    var names_seq = core::cursor_from(san_der[..0]);
    if !get_asn1_element(c, rfc::ASN1_TAG_SEQUENCE, names_seq) { return false; }
    guard c.cursor_len() == 0 else { return false; }
    guard names_seq.cursor_len() > 0 else { return false; }

    var count: i64 = 0;
    while names_seq.cursor_len() > 0 {
        guard x509_parse_single_san(names_seq, out_sans) else { return false; }
        count++;
    }
    return count > 0;
}

// Matches an IP SAN (binary 4 or 16 octets) against a target IP host (either decimal string or raw binary).
fn match_ip_san(san_ip: const u8[:], host: const u8[:]) -> bool {
    guard san_ip.len == 4 || san_ip.len == 16 else { return false; }

    // Direct binary match
    if host.len == san_ip.len && host == san_ip {
        return true;
    }

    // Decimal IPv4 string match
    if san_ip.len == 4 {
        var host_ip: u8[4] = [0; 4];
        if parse_ipv4_literal(host, host_ip) {
            return san_ip == host_ip[..];
        }
    }
    return false;
}

// Matches any single SAN entry against target hostname or IP address.
fn match_san(san: const SanEntry&, host: const u8[:]) -> bool {
    if san.san_type == SanType.Dns {
        return match_dns_san(san.val, host);
    } else if san.san_type == SanType.Ip {
        return match_ip_san(san.val, host);
    } else if san.san_type == SanType.Uri {
        return match_uri_san(san.val, host);
    }
    return false;
}

// Matches target host against an array of parsed SAN entries.
fn match_any_san(sans: const SanEntry[..16]&, host: const u8[:]) -> bool {
    for i in sans.len {
        if match_san(sans[i], host) {
            return true;
        }
    }
    return false;
}

// Helper to extract and parse SAN entries from a ParsedCert descriptor.
fn get_cert_san_extension(cert: const ParsedCert&, raw_cert: const u8[:], out_sans: SanEntry[..16]&) -> bool {
    guard cert.has_san else { return false; }
    let san_bytes = span_slice(raw_cert, cert.san_raw);
    return parse_san_extension(san_bytes, out_sans);
}

// ---- 6b. RFC 5280 Section 4.2.1.10 Name Constraints & Subtree Validation -----

struct NameConstraintEntry {
    san_type:    SanType     = SanType.Dns,
    is_excluded: bool        = false,
    val:         const u8[:] = [],
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

// Validates that an IPv4 (4-byte) or IPv6 (16-byte) subnet mask is contiguous CIDR.
// In network byte order, once a 0 bit appears, no 1 bit may follow.
fn validate_cidr_mask(mask: const u8[:]) -> bool {
    guard mask.len == 4 || mask.len == 16 else { return false; }
    var seen_zero_bit = false;
    for b in mask {
        guard x509_check_mask_byte(b, seen_zero_bit) else { return false; }
    }
    return true;
}

inline fn x509_validate_dns_candidate(cand: const u8[:]) -> bool {
    guard cand.len > 0 else { return false; }
    guard cand[0] != '.' else { return false; }
    guard !core::contains_byte(cand, 0) else { return false; }
    return find(cand, "..") < 0;
}

inline fn x509_match_dns_dotted_constraint(cand: const u8[:], cons: const u8[:]) -> bool {
    guard cons.len > 1 else { return false; }
    guard cand.len > cons.len else { return false; }
    return core::ends_with_fold(cand, cons);
}

fn x509_match_dns_subdomain(cand: const u8[:], cons: const u8[:]) -> bool {
    guard cons.len > 0 else { return false; }
    guard cand.len > cons.len else { return false; }
    guard core::ends_with_fold(cand, cons) else { return false; }
    var idx = cand.len - cons.len;
    idx--;
    guard idx >= 0 else { return false; }
    return cand[idx] == '.';
}

// RFC 5280 §4.2.1.10: DNS name constraint matching
// DNS name restrictions may be indicated as "example.com" or ".example.com".
// Normalizes trailing dots in candidate and constraint to prevent ExcludedSubtree bypass.
// Rejects embedded NUL bytes (CVE-2021-3712 / OpenSSL #31686).
fn match_dns_name_constraint(candidate_dns: const u8[:], constraint: const u8[:]) -> bool {
    guard candidate_dns.len > 0 && constraint.len > 0 else { return false; }
    guard !core::contains_byte(constraint, 0) else { return false; }

    let cand = x509_strip_trailing_dot(candidate_dns);
    let cons = x509_strip_trailing_dot(constraint);
    guard x509_validate_dns_candidate(cand) else { return false; }
    guard cons.len > 0 && find(cons, "..") < 0 else { return false; }

    if cons[0] == '.' {
        return x509_match_dns_dotted_constraint(cand, cons);
    }
    if eq_ascii_fold(cand, cons) {
        return true;
    }
    return x509_match_dns_subdomain(cand, cons);
}

// RFC 5280 §4.2.1.10: IP address name constraint matching
// Candidate IP is 4 octets (IPv4) or 16 octets (IPv6).
// Constraint MUST be 8 octets (IPv4) or 32 octets (IPv6): IP || Subnet Mask.
fn match_ip_name_constraint(candidate_ip: const u8[:], constraint: const u8[:]) -> bool {
    let is_ipv4 = candidate_ip.len == 4 && constraint.len == 8;
    let is_ipv6 = candidate_ip.len == 16 && constraint.len == 32;
    guard is_ipv4 || is_ipv6 else { return false; }
    let half = candidate_ip.len;
    let subnet_ip = constraint[..half];
    let mask = constraint[half..];

    for i in half {
        let cand_masked = candidate_ip[i] & mask[i];
        let sub_masked = subnet_ip[i] & mask[i];
        if cand_masked != sub_masked {
            return false;
        }
    }
    return true;
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

    var auth_end = s.len;
    let slash_idx = core::index_of_byte(s, '/');
    if slash_idx >= 0 && slash_idx < auth_end { auth_end = slash_idx; }
    let q_idx = core::index_of_byte(s, '?');
    if q_idx >= 0 && q_idx < auth_end { auth_end = q_idx; }
    let h_idx = core::index_of_byte(s, '#');
    if h_idx >= 0 && h_idx < auth_end { auth_end = h_idx; }
    return s[..auth_end];
}

fn x509_match_ipv6_uri_constraint(host_part: const u8[:], constraint: const u8[:]) -> bool {
    let close_bracket = core::index_of_byte(host_part, ']');
    guard close_bracket > 1 else { return false; }
    var inner_ip = host_part[1..close_bracket];

    let pct_idx = core::index_of_byte(inner_ip, '%');
    if pct_idx >= 0 {
        inner_ip = inner_ip[..pct_idx];
    }
    guard inner_ip.len > 0 else { return false; }

    var cons_cmp = constraint;
    if cons_cmp.len > 2 && cons_cmp[0] == '[' && cons_cmp[cons_cmp.len - 1] == ']' {
        cons_cmp = cons_cmp[1..cons_cmp.len - 1];
    }
    return eq_ascii_fold(inner_ip, cons_cmp);
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

// RFC 5280 §4.2.1.10 & OpenSSL #31392 / CVE-2024-45341 / Go #71208: URI name constraint matching
// Extracts the host component from candidate URI and matches it against the constraint.
// Rejects candidate URIs with userinfo, path/query @ smuggling, or IPv4 literals for dNSName constraints.
fn match_uri_name_constraint(candidate_uri: const u8[:], constraint: const u8[:]) -> bool {
    guard candidate_uri.len > 0 && constraint.len > 0 else { return false; }
    guard !core::contains_byte(candidate_uri, 0) && !core::contains_byte(constraint, 0) else { return false; }

    var host_part = x509_extract_uri_authority(candidate_uri);
    guard host_part.len > 0 else { return false; }

    // RFC 5280 §4.2.1.10: URI authority cannot contain userinfo (@) to satisfy DNS name constraint
    guard !core::contains_byte(host_part, '@') else { return false; }

    if host_part[0] == '[' {
        return x509_match_ipv6_uri_constraint(host_part, constraint);
    }

    let colon_idx = core::index_of_byte(host_part, ':');
    if colon_idx >= 0 {
        host_part = host_part[..colon_idx];
    }

    guard host_part.len > 0 else { return false; }
    guard !x509_is_ipv4_literal(host_part) else { return false; }

    return match_dns_name_constraint(host_part, constraint);
}

// RFC 5280 §4.2.1.10: rfc822Name (email) name constraint matching.
// - With `@`: local-part matches case-sensitively and host matches case-insensitively.
// - Leading `.`: candidate host after `@` ends with `constraint` case-insensitively.
// - Otherwise: candidate host after `@` matches `constraint` case-insensitively.
fn match_email_name_constraint(candidate_email: const u8[:], constraint: const u8[:]) -> bool {
    guard candidate_email.len > 0 && constraint.len > 0 else { return false; }
    guard !core::contains_byte(candidate_email, 0) && !core::contains_byte(constraint, 0) else { return false; }

    let cand_local, cand_host, has_cand_at = core::split_once_byte(candidate_email, '@');
    guard has_cand_at && cand_local.len > 0 && cand_host.len > 0 else { return false; }
    guard !core::contains_byte(cand_host, '@') else { return false; }

    let cons_local, cons_host, has_cons_at = core::split_once_byte(constraint, '@');
    if has_cons_at {
        guard cons_local.len > 0 && cons_host.len > 0 else { return false; }
        return cand_local == cons_local && eq_ascii_fold(cand_host, cons_host);
    }

    if core::starts_with(constraint, ".") {
        return x509_match_dns_dotted_constraint(cand_host, constraint);
    }
    return eq_ascii_fold(cand_host, constraint);
}

fn x509_parse_general_subtree_base(subtree: ByteCursor&, out_type: SanType&, out_val: ByteCursor&) -> bool {
    var base_tag: u8 = 0;
    if !get_any_asn1_element(subtree, base_tag, out_val) { return false; }
    let tag_num = base_tag & 0x1F;
    if tag_num == 1 { // rfc822Name [1]
        out_type = SanType.Email;
        guard out_val.buf.len > 0 && !core::contains_byte(out_val.buf, 0) else { return false; }
    } else if tag_num == 2 { // dNSName
        out_type = SanType.Dns;
        guard out_val.buf.len > 0 && !core::contains_byte(out_val.buf, 0) else { return false; }
    } else if tag_num == 7 { // iPAddress
        out_type = SanType.Ip;
        guard out_val.buf.len == 8 || out_val.buf.len == 32 else { return false; }
        let half = out_val.buf.len / 2;
        guard validate_cidr_mask(out_val.buf[half..]) else { return false; }
    } else if tag_num == 6 { // uniformResourceIdentifier [6]
        out_type = SanType.Uri;
        guard out_val.buf.len > 0 && !core::contains_byte(out_val.buf, 0) else { return false; }
    } else {
        out_type = SanType.Other;
    }
    return true;
}

inline fn x509_validate_subtree_bound_opt(opt_tag: u8, opt_elem: ByteCursor&) -> bool {
    let opt_num = opt_tag & 0x1F;
    if opt_num == 0 { // minimum MUST be zero
        var min_val: i64 = 0;
        return get_asn1_integer(opt_elem, min_val) && min_val == 0;
    }
    return false; // maximum (opt_num == 1) or other tags forbidden
}

inline fn x509_parse_general_subtree_bounds(subtree: ByteCursor&) -> bool {
    while subtree.cursor_len() > 0 {
        var opt_tag: u8 = 0;
        var opt_elem = core::cursor_from(subtree.buf[..0]);
        if !get_any_asn1_element(subtree, opt_tag, opt_elem) { return false; }
        guard x509_validate_subtree_bound_opt(opt_tag, opt_elem) else { return false; }
    }
    return true;
}

fn x509_parse_general_subtree(
    nc_der:          const u8[:],
    subtree:         ByteCursor&,
    is_excluded:     bool,
    out_constraints: NameConstraintEntry[..16]&,
) -> bool {
    var st = SanType.Other;
    var base_elem = core::cursor_from(nc_der[..0]);
    guard x509_parse_general_subtree_base(subtree, st, base_elem) else { return false; }
    guard x509_parse_general_subtree_bounds(subtree) else { return false; }

    guard out_constraints.len < out_constraints.cap else { return false; }
    let span = make_span(nc_der, base_elem.buf);
    out_constraints.push(NameConstraintEntry {
        san_type:    st,
        is_excluded: is_excluded,
        val:         span_slice(nc_der, span),
    });
    return true;
}

fn x509_parse_subtrees_sequence(
    nc_der:          const u8[:],
    subtrees_elem:   ByteCursor&,
    is_excluded:     bool,
    out_constraints: NameConstraintEntry[..16]&,
    count:           i64&,
) -> bool {
    var subtrees_seq = core::cursor_from(subtrees_elem.buf[..0]);
    if subtrees_elem.cursor_len() > 0 && subtrees_elem.buf[0] == rfc::ASN1_TAG_SEQUENCE {
        if !get_asn1_element(subtrees_elem, rfc::ASN1_TAG_SEQUENCE, subtrees_seq) { return false; }
    } else {
        subtrees_seq = subtrees_elem;
    }
    guard subtrees_seq.cursor_len() > 0 else { return false; }

    while subtrees_seq.cursor_len() > 0 {
        var subtree = core::cursor_from(subtrees_seq.buf[..0]);
        if !get_asn1_element(subtrees_seq, rfc::ASN1_TAG_SEQUENCE, subtree) { return false; }
        guard x509_parse_general_subtree(nc_der, subtree, is_excluded, out_constraints) else { return false; }
        count++;
    }
    return true;
}

// Parses NameConstraints extension (RFC 5280 §4.2.1.10) into bounded stack storage.
// Enforces that empty NameConstraints, non-contiguous masks, non-zero minimums, or present maximums are rejected.
// Example:
//   nc_der = 0x30 ... (DER encoded NameConstraints sequence)
//   returns: ok = true, out_constraints filled with permitted/excluded subtrees
fn parse_name_constraints(nc_der: const u8[:], out_constraints: NameConstraintEntry[..16]&) -> bool {
    var c = core::cursor_from(nc_der);
    var nc_seq = core::cursor_from(nc_der[..0]);
    if !get_asn1_element(c, rfc::ASN1_TAG_SEQUENCE, nc_seq) { return false; }
    guard c.cursor_len() == 0 else { return false; }
    guard nc_seq.cursor_len() > 0 else { return false; } // RFC 5280: empty NameConstraints is forbidden!

    var count: i64 = 0;
    while nc_seq.cursor_len() > 0 {
        var tag: u8 = 0;
        var subtrees_elem = core::cursor_from(nc_seq.buf[..0]);
        if !get_any_asn1_element(nc_seq, tag, subtrees_elem) { return false; }

        let is_excluded = (tag == 0xA1);
        let is_permitted = (tag == 0xA0);
        guard is_excluded || is_permitted else { return false; }

        guard x509_parse_subtrees_sequence(
            nc_der, subtrees_elem, is_excluded, out_constraints, count,
        ) else { return false; }
    }
    return count > 0;
}

inline fn x509_match_constraint_entry(nc: const NameConstraintEntry&, san: const SanEntry&) -> bool {
    if nc.san_type == SanType.Dns {
        return match_dns_name_constraint(san.val, nc.val);
    }
    if nc.san_type == SanType.Ip {
        return match_ip_name_constraint(san.val, nc.val);
    }
    if nc.san_type == SanType.Uri {
        return match_uri_name_constraint(san.val, nc.val);
    }
    if nc.san_type == SanType.Email {
        return match_email_name_constraint(san.val, nc.val);
    }
    return false;
}

fn x509_eval_single_nc(
    nc:                const NameConstraintEntry&,
    san:               const SanEntry&,
    has_permitted:     bool&,
    matched_permitted: bool&,
) -> bool {
    if nc.san_type != san.san_type {
        return true;
    }
    let matched = x509_match_constraint_entry(nc, san);
    if nc.is_excluded {
        return !matched;
    }
    has_permitted = true;
    if matched {
        matched_permitted = true;
    }
    return true;
}

// Matches a single SAN against parsed Name Constraints.
fn check_name_constraints(
    constraints: const NameConstraintEntry[..16]&,
    san:         const SanEntry&,
) -> bool {
    var has_permitted = false;
    var matched_permitted = false;

    for i in constraints.len {
        guard x509_eval_single_nc(constraints[i], san, has_permitted, matched_permitted) else {
            return false;
        }
    }

    return !has_permitted || matched_permitted;
}

fn x509_is_cert_duplicate(
    raw_j:  const u8[:],
    cert_j: const ParsedCert&,
    raw_k:  const u8[:],
    cert_k: const ParsedCert&,
) -> bool {
    let s_j = span_slice(raw_j, cert_j.subject_raw);
    let spki_j = span_slice(raw_j, cert_j.spki_raw);
    let s_k = span_slice(raw_k, cert_k.subject_raw);
    let spki_k = span_slice(raw_k, cert_k.spki_raw);
    return (s_j.len > 0 && s_j == s_k) || (spki_j.len > 0 && spki_j == spki_k);
}

// RFC 5280 Certificate Chain Validation.
// Returns TlsAlert.CloseNotify (0) on success, or appropriate fatal alert.
fn x509_detect_chain_cycles(chain_certs: const ParsedCert[..8]&, raw_certs: const u8[:][..8]&) -> bool {
    for j in chain_certs.len {
        for k in chain_certs.len {
            if j < k && x509_is_cert_duplicate(raw_certs[j], chain_certs[j], raw_certs[k], chain_certs[k]) {
                return true;
            }
        }
    }
    return false;
}

fn x509_validate_single_chain_cert(
    cert:                   const ParsedCert&,
    raw_cert:               const u8[:],
    i:                      i64,
    is_direct_trust_anchor: bool,
    now_unix:               i64,
) -> TlsAlert {
    if cert.has_unsupported_critical {
        return TlsAlert.UnsupportedExtension;
    }
    if cert.has_malformed_policy_constraints {
        return TlsAlert.BadCertificate;
    }

    let val_alert = validate_chain_cert_validity(cert, now_unix);
    guard val_alert == TlsAlert.CloseNotify else { return val_alert; }

    let sig_oid = span_slice(raw_cert, cert.sig_alg_oid);
    if rfc::is_forbidden_cert_signature_algorithm(sig_oid) {
        return TlsAlert.UnsupportedCertificate;
    }

    if i == 0 && !is_direct_trust_anchor {
        return validate_end_entity_constraints(cert);
    } else if i > 0 {
        return validate_intermediate_ca_constraints(cert, i);
    }
    return TlsAlert.CloseNotify;
}

fn x509_verify_signature_by_oid(
    sig_oid:       const u8[:],
    tbs_data:      const u8[:],
    sig_bytes:     const u8[:],
    parent_pubkey: const u8[:],
    err_alert:     TlsAlert,
) -> TlsAlert {
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
        return TlsAlert.CloseNotify;
    }

    if sig_oid == rfc::OID_SIG_ECDSA_SHA256[..] {
        guard core::ecdsa_p256_verify(parent_pubkey, tbs_data, sig_bytes) else {
            return err_alert;
        }
        return TlsAlert.CloseNotify;
    }

    if sig_oid == rfc::OID_SIG_ECDSA_SHA384[..] {
        guard core::ecdsa_p384_verify(parent_pubkey, tbs_data, sig_bytes) else {
            return err_alert;
        }
        return TlsAlert.CloseNotify;
    }

    if sig_oid == rfc::OID_SIG_SHA256_RSA[..] {
        guard core::rsa_pkcs1_sha256_verify_der(parent_pubkey, tbs_data, sig_bytes) else {
            return err_alert;
        }
        return TlsAlert.CloseNotify;
    }

    if sig_oid == rfc::OID_SIG_SHA384_RSA[..] {
        guard core::rsa_pkcs1_sha384_verify_der(parent_pubkey, tbs_data, sig_bytes) else {
            return err_alert;
        }
        return TlsAlert.CloseNotify;
    }

    if sig_oid == rfc::OID_SIG_RSASSA_PSS[..] {
        let pss_ok = core::rsa_pss_sha256_verify_der(parent_pubkey, tbs_data, sig_bytes)
            || core::rsa_pss_sha384_verify_der(parent_pubkey, tbs_data, sig_bytes);
        guard pss_ok else {
            return err_alert;
        }
        return TlsAlert.CloseNotify;
    }

    return TlsAlert.UnsupportedCertificate;
}

fn x509_verify_cert_signature(
    child_cert:  const ParsedCert&,
    child_raw:   const u8[:],
    parent_cert: const ParsedCert&,
    parent_raw:  const u8[:],
) -> TlsAlert {
    guard child_cert.signature_value.length > 0 && child_cert.tbs_cert.length > 0 else {
        return TlsAlert.BadCertificate;
    }

    let sig_oid = span_slice(child_raw, child_cert.sig_alg_oid);
    let tbs_data = span_slice(child_raw, child_cert.tbs_cert);
    let sig_bytes = span_slice(child_raw, child_cert.signature_value);
    var parent_pubkey = span_slice(parent_raw, parent_cert.spki_pubkey);

    if parent_pubkey.len >= 2 && parent_pubkey[0] == 0 {
        parent_pubkey = parent_pubkey[1..];
    }

    return x509_verify_signature_by_oid(sig_oid, tbs_data, sig_bytes, parent_pubkey, TlsAlert.BadCertificate);
}

fn x509_validate_chain_linkage(
    child_cert:  const ParsedCert&,
    child_raw:   const u8[:],
    parent_cert: const ParsedCert&,
    parent_raw:  const u8[:],
) -> TlsAlert {
    let issuer_slice = span_slice(child_raw, child_cert.issuer_raw);
    let next_subject_slice = span_slice(parent_raw, parent_cert.subject_raw);
    if issuer_slice != next_subject_slice {
        return TlsAlert.UnknownCa;
    }

    if child_cert.has_akid && parent_cert.has_skid {
        let child_akid = span_slice(child_raw, child_cert.akid_key_id);
        let parent_skid = span_slice(parent_raw, parent_cert.skid_key_id);
        if child_akid != parent_skid {
            return TlsAlert.UnknownCa;
        }
    }
    return x509_verify_cert_signature(child_cert, child_raw, parent_cert, parent_raw);
}

fn x509_check_child_sans_against_nc(
    nc_entries: const NameConstraintEntry[..16]&,
    child_cert: const ParsedCert&,
    child_raw:  const u8[:],
) -> bool {
    guard child_cert.has_san else { return true; }
    var child_sans: SanEntry[..16] = [];
    guard get_cert_san_extension(child_cert, child_raw, child_sans) else { return false; }
    for s_idx in child_sans.len {
        if !check_name_constraints(nc_entries, child_sans[s_idx]) {
            return false;
        }
    }
    return true;
}

fn x509_enforce_single_cert_nc(
    chain_certs: const ParsedCert[..8]&,
    raw_certs:   const u8[:][..8]&,
    k:           i64,
) -> bool {
    guard chain_certs[k].has_name_constraints else { return true; }
    var nc_entries: NameConstraintEntry[..16] = [];
    let nc_bytes = span_slice(raw_certs[k], chain_certs[k].name_constraints_raw);
    guard parse_name_constraints(nc_bytes, nc_entries) else { return false; }
    for j in k {
        guard x509_check_child_sans_against_nc(nc_entries, chain_certs[j], raw_certs[j]) else {
            return false;
        }
    }
    return true;
}

fn x509_enforce_chain_name_constraints(
    chain_certs: const ParsedCert[..8]&,
    raw_certs:   const u8[:][..8]&,
) -> TlsAlert {
    for k in chain_certs.len {
        guard x509_enforce_single_cert_nc(chain_certs, raw_certs, k) else {
            return TlsAlert.BadCertificate;
        }
    }
    return TlsAlert.CloseNotify;
}

fn x509_validate_chain_nodes(
    chain_certs:            const ParsedCert[..8]&,
    raw_certs:              const u8[:][..8]&,
    trust_store:            const TrustAnchorStore&,
    is_direct_trust_anchor: bool,
    now_unix:               i64,
) -> TlsAlert {
    let n = min(chain_certs.len, raw_certs.len);
    for i in n {
        let cert_alert = x509_validate_single_chain_cert(
            chain_certs[i], raw_certs[i], i, is_direct_trust_anchor, now_unix,
        );
        guard cert_alert == TlsAlert.CloseNotify else { return cert_alert; }
        if i + 1 == n && !matches_trust_anchor(trust_store, chain_certs[i], raw_certs[i]) {
            return TlsAlert.UnknownCa;
        }
    }
    if n > 1 {
        for i in n - 1 {
            let link_alert = x509_validate_chain_linkage(
                chain_certs[i], raw_certs[i], chain_certs[i + 1], raw_certs[i + 1],
            );
            guard link_alert == TlsAlert.CloseNotify else { return link_alert; }
        }
    }
    return TlsAlert.CloseNotify;
}

// RFC 5280 Certificate Chain Validation.
// Returns TlsAlert.CloseNotify (0) on success, or appropriate fatal alert.
fn verify_certificate_chain(
    chain_certs: const ParsedCert[..8]&,
    raw_certs:   const u8[:][..8]&,
    trust_store: const TrustAnchorStore&,
    now_unix:    i64,
) -> TlsAlert {
    guard chain_certs.len > 0 && chain_certs.len <= MAX_CHAIN_DEPTH else { return TlsAlert.BadCertificate; }
    guard raw_certs.len > 0 && raw_certs.len == chain_certs.len else { return TlsAlert.BadCertificate; }

    if x509_detect_chain_cycles(chain_certs, raw_certs) {
        return TlsAlert.BadCertificate;
    }

    let is_direct_trust_anchor = chain_certs.len == 1 &&
        matches_trust_anchor(trust_store, chain_certs[0], raw_certs[0]);

    if chain_certs.len == 1 && chain_certs[0].is_ca && !is_direct_trust_anchor {
        return TlsAlert.UnknownCa;
    }

    let nodes_alert = x509_validate_chain_nodes(chain_certs, raw_certs, trust_store, is_direct_trust_anchor, now_unix);
    guard nodes_alert == TlsAlert.CloseNotify else { return nodes_alert; }

    return x509_enforce_chain_name_constraints(chain_certs, raw_certs);
}

// ---- 6c. RFC 6066 §8 & RFC 6960 OCSP Stapling & Status Validation -----------

enum OcspResponseStatus {
    Successful,
    MalformedRequest,
    InternalError,
    TryLater,
    SigRequired,
    Unauthorized,
    Unknown,
}

enum OcspCertStatus {
    Good,
    Revoked,
    Unknown,
}

struct ParsedOcspResponse {
    status:           OcspResponseStatus = OcspResponseStatus.Unknown,
    cert_status:      OcspCertStatus     = OcspCertStatus.Unknown,
    serial_number:    Span16             = Span16 { offset: 0, length: 0 },
    issuer_name_hash: Span16             = Span16 { offset: 0, length: 0 },
    issuer_key_hash:  Span16             = Span16 { offset: 0, length: 0 },
    hash_alg_oid:     Span16             = Span16 { offset: 0, length: 0 },
    tbs_raw:          Span16             = Span16 { offset: 0, length: 0 },
    sig_alg_oid:      Span16             = Span16 { offset: 0, length: 0 },
    signature:        Span16             = Span16 { offset: 0, length: 0 },
    this_update:      i64                = 0,
    next_update:      i64                = 0,
    has_next_update:  bool               = false,
}

inline fn x509_parse_ocsp_status(s_val: u8, out_status: OcspResponseStatus&) -> bool {
    if s_val == rfc::OCSP_STATUS_SUCCESSFUL {
        out_status = OcspResponseStatus.Successful;
        return true;
    }
    if s_val == rfc::OCSP_STATUS_MALFORMED_REQ {
        out_status = OcspResponseStatus.MalformedRequest;
        return true;
    }
    if s_val == rfc::OCSP_STATUS_INTERNAL_ERROR {
        out_status = OcspResponseStatus.InternalError;
        return true;
    }
    if s_val == rfc::OCSP_STATUS_TRY_LATER {
        out_status = OcspResponseStatus.TryLater;
        return true;
    }
    if s_val == rfc::OCSP_STATUS_SIG_REQUIRED {
        out_status = OcspResponseStatus.SigRequired;
        return true;
    }
    if s_val == rfc::OCSP_STATUS_UNAUTHORIZED {
        out_status = OcspResponseStatus.Unauthorized;
        return true;
    }
    out_status = OcspResponseStatus.Unknown;
    return false;
}

fn x509_parse_ocsp_cert_id(
    single_resp: ByteCursor&,
    raw_ocsp:    const u8[:],
    out:         ParsedOcspResponse&,
) -> bool {
    var cert_id_seq = core::cursor_from(single_resp.buf[..0]);
    if !get_asn1_element(single_resp, rfc::ASN1_TAG_SEQUENCE, cert_id_seq) { return false; }

    var hash_alg = core::cursor_from(cert_id_seq.buf[..0]);
    if !get_asn1_element(cert_id_seq, rfc::ASN1_TAG_SEQUENCE, hash_alg) { return false; }
    if hash_alg.cursor_len() > 0 {
        var hash_oid = core::cursor_from(hash_alg.buf[..0]);
        if get_asn1_element(hash_alg, rfc::ASN1_TAG_OID, hash_oid) {
            out.hash_alg_oid = make_span(raw_ocsp, hash_oid.buf);
        }
    }

    var name_hash = core::cursor_from(cert_id_seq.buf[..0]);
    if !get_asn1_element(cert_id_seq, rfc::ASN1_TAG_OCTET_STRING, name_hash) { return false; }
    out.issuer_name_hash = make_span(raw_ocsp, name_hash.buf);

    var key_hash = core::cursor_from(cert_id_seq.buf[..0]);
    if !get_asn1_element(cert_id_seq, rfc::ASN1_TAG_OCTET_STRING, key_hash) { return false; }
    out.issuer_key_hash = make_span(raw_ocsp, key_hash.buf);

    var serial = core::cursor_from(cert_id_seq.buf[..0]);
    if !get_asn1_element(cert_id_seq, rfc::ASN1_TAG_INTEGER, serial) { return false; }
    if !validate_asn1_integer(serial.buf, true) { return false; }
    out.serial_number = make_span(raw_ocsp, serial.buf);
    return true;
}

fn x509_parse_ocsp_cert_status(single_resp: ByteCursor&, out_status: OcspCertStatus&) -> bool {
    var cert_status_tag: u8 = 0;
    var cert_status_elem = core::cursor_from(single_resp.buf[..0]);
    if !get_any_asn1_element(single_resp, cert_status_tag, cert_status_elem) { return false; }
    guard (cert_status_tag & 0xC0) == 0x80 else { return false; }
    let cs_num = cert_status_tag & 0x1F;
    if cs_num == 0 {
        out_status = OcspCertStatus.Good;
        return true;
    }
    if cs_num == 1 {
        out_status = OcspCertStatus.Revoked;
        return true;
    }
    if cs_num == 2 {
        out_status = OcspCertStatus.Unknown;
        return true;
    }
    return false;
}

fn x509_parse_ocsp_next_update(single_resp: ByteCursor&, out: ParsedOcspResponse&) -> bool {
    guard single_resp.cursor_len() > 0 && single_resp.buf[0] == 0xA0 else { return true; }
    var next_up_ctx = core::cursor_from(single_resp.buf[..0]);
    guard get_asn1_element(single_resp, 0xA0, next_up_ctx) else { return false; }
    var next_up_tag: u8 = 0;
    var next_up_elem = core::cursor_from(next_up_ctx.buf[..0]);
    guard get_any_asn1_element(next_up_ctx, next_up_tag, next_up_elem) else { return false; }
    let next_time, ok_next = parse_asn1_time(next_up_tag, next_up_elem.buf);
    guard ok_next else { return false; }
    out.next_update = next_time;
    out.has_next_update = true;
    return true;
}

fn x509_parse_ocsp_single_response(
    responses_seq: ByteCursor&,
    raw_ocsp:      const u8[:],
    out:           ParsedOcspResponse&,
) -> bool {
    guard responses_seq.cursor_len() > 0 else { return false; }
    var single_resp = core::cursor_from(responses_seq.buf[..0]);
    if !get_asn1_element(responses_seq, rfc::ASN1_TAG_SEQUENCE, single_resp) { return false; }

    guard x509_parse_ocsp_cert_id(single_resp, raw_ocsp, out) else { return false; }
    guard x509_parse_ocsp_cert_status(single_resp, out.cert_status) else { return false; }

    var this_up_tag: u8 = 0;
    var this_up_elem = core::cursor_from(single_resp.buf[..0]);
    if !get_any_asn1_element(single_resp, this_up_tag, this_up_elem) { return false; }
    let this_time, ok_this = parse_asn1_time(this_up_tag, this_up_elem.buf);
    guard ok_this else { return false; }
    out.this_update = this_time;

    return x509_parse_ocsp_next_update(single_resp, out);
}

fn x509_skip_ocsp_version_and_id(tbs_resp_data: ByteCursor&) -> bool {
    if tbs_resp_data.cursor_len() > 0 && tbs_resp_data.buf[0] == 0xA0 {
        var ver_elem = core::cursor_from(tbs_resp_data.buf[..0]);
        get_asn1_element(tbs_resp_data, 0xA0, ver_elem);
    }
    var resp_id_tag: u8 = 0;
    var resp_id = core::cursor_from(tbs_resp_data.buf[..0]);
    return get_any_asn1_element(tbs_resp_data, resp_id_tag, resp_id);
}

fn x509_ocsp_read_basic_sig(basic_seq: ByteCursor&, raw_ocsp: const u8[:], out: ParsedOcspResponse&) -> bool {
    guard basic_seq.cursor_len() > 0 else { return true; }
    var sig_alg_seq = core::cursor_from(basic_seq.buf[..0]);
    guard get_asn1_element(basic_seq, rfc::ASN1_TAG_SEQUENCE, sig_alg_seq) else { return false; }
    var sig_oid = core::cursor_from(sig_alg_seq.buf[..0]);
    guard get_asn1_element(sig_alg_seq, rfc::ASN1_TAG_OID, sig_oid) else { return false; }
    out.sig_alg_oid = make_span(raw_ocsp, sig_oid.buf);

    guard basic_seq.cursor_len() > 0 else { return false; }
    var sig_bits = core::cursor_from(basic_seq.buf[..0]);
    var unused_bits: u8 = 0;
    guard get_asn1_bit_string(basic_seq, sig_bits, unused_bits) &&
        unused_bits == 0 && sig_bits.buf.len > 0 else { return false; }
    out.signature = make_span(raw_ocsp, sig_bits.buf);
    return true;
}

fn x509_parse_ocsp_basic_response(
    resp_bytes_seq: ByteCursor&,
    raw_ocsp:       const u8[:],
    out:            ParsedOcspResponse&,
) -> bool {
    var resp_type_oid = core::cursor_from(resp_bytes_seq.buf[..0]);
    if !get_asn1_element(resp_bytes_seq, rfc::ASN1_TAG_OID, resp_type_oid) { return false; }
    guard resp_type_oid.buf == rfc::OID_OCSP_BASIC[..] else { return false; }

    var resp_oct = core::cursor_from(resp_bytes_seq.buf[..0]);
    if !get_asn1_element(resp_bytes_seq, rfc::ASN1_TAG_OCTET_STRING, resp_oct) { return false; }

    var basic_seq = core::cursor_from(resp_oct.buf[..0]);
    if !get_asn1_element(resp_oct, rfc::ASN1_TAG_SEQUENCE, basic_seq) { return false; }

    let tbs_raw_start = basic_seq.buf;
    var tbs_resp_data = core::cursor_from(basic_seq.buf[..0]);
    if !get_asn1_element(basic_seq, rfc::ASN1_TAG_SEQUENCE, tbs_resp_data) { return false; }
    let tbs_tlv_len = core::sub_sat_i64(tbs_raw_start.len, basic_seq.buf.len);
    out.tbs_raw = make_span(raw_ocsp, tbs_raw_start[..tbs_tlv_len]);

    guard x509_skip_ocsp_version_and_id(tbs_resp_data) else { return false; }

    var prod_time = core::cursor_from(tbs_resp_data.buf[..0]);
    if !get_asn1_element(tbs_resp_data, rfc::ASN1_TAG_GENERALIZED_TIME, prod_time) { return false; }

    var responses_seq = core::cursor_from(tbs_resp_data.buf[..0]);
    if !get_asn1_element(tbs_resp_data, rfc::ASN1_TAG_SEQUENCE, responses_seq) { return false; }

    guard x509_parse_ocsp_single_response(responses_seq, raw_ocsp, out) else { return false; }

    return x509_ocsp_read_basic_sig(basic_seq, raw_ocsp, out);
}

// Parses an OCSPResponse (RFC 6960 §4.2.1) with zero dynamic allocation.
// Example:
//   raw_ocsp = 0x30 ... (DER encoded OCSPResponse)
//   returns: ok = true, out filled with status and cert status
fn parse_ocsp_response(raw_ocsp: const u8[:], out: ParsedOcspResponse&) -> bool {
    var c = core::cursor_from(raw_ocsp);
    var ocsp_seq = core::cursor_from(raw_ocsp[..0]);
    if !get_asn1_element(c, rfc::ASN1_TAG_SEQUENCE, ocsp_seq) { return false; }
    guard c.cursor_len() == 0 else { return false; }

    var status_oct = core::cursor_from(ocsp_seq.buf[..0]);
    if !get_asn1_element(ocsp_seq, rfc::ASN1_TAG_ENUMERATED, status_oct) { return false; }
    guard status_oct.buf.len == 1 else { return false; }

    guard x509_parse_ocsp_status(status_oct.buf[0], out.status) else { return false; }
    if out.status != OcspResponseStatus.Successful {
        return true;
    }

    guard ocsp_seq.cursor_len() > 0 else { return false; }
    var resp_bytes_ctx = core::cursor_from(ocsp_seq.buf[..0]);
    if !get_asn1_element(ocsp_seq, 0xA0, resp_bytes_ctx) { return false; }

    var resp_bytes_seq = core::cursor_from(resp_bytes_ctx.buf[..0]);
    if !get_asn1_element(resp_bytes_ctx, rfc::ASN1_TAG_SEQUENCE, resp_bytes_seq) { return false; }

    return x509_parse_ocsp_basic_response(resp_bytes_seq, raw_ocsp, out);
}

fn x509_validate_ocsp_temporal(resp: const ParsedOcspResponse&, now_unix: i64) -> TlsAlert {
    if resp.has_next_update && resp.this_update > resp.next_update {
        return TlsAlert.BadCertificateStatusResponse;
    }
    if now_unix < resp.this_update {
        return TlsAlert.CertificateExpired;
    }
    if resp.has_next_update && now_unix > resp.next_update {
        return TlsAlert.CertificateExpired;
    }
    return TlsAlert.CloseNotify;
}

// Validates an OCSP stapled response against the leaf certificate (RFC 6066 §8, RFC 6960).
fn validate_ocsp_stapling(
    raw_ocsp:  const u8[:],
    leaf_cert: const ParsedCert&,
    leaf_raw:  const u8[:],
    now_unix:  i64,
) -> TlsAlert {
    var resp = ParsedOcspResponse {};
    if !parse_ocsp_response(raw_ocsp, resp) {
        return TlsAlert.BadCertificateStatusResponse;
    }

    if resp.status != OcspResponseStatus.Successful {
        return TlsAlert.BadCertificateStatusResponse;
    }

    if resp.cert_status == OcspCertStatus.Revoked {
        return TlsAlert.BadCertificate;
    }
    if resp.cert_status != OcspCertStatus.Good {
        return TlsAlert.BadCertificateStatusResponse;
    }

    let ocsp_serial = span_slice(raw_ocsp, resp.serial_number);
    let leaf_serial = span_slice(leaf_raw, leaf_cert.serial_number);
    if ocsp_serial.len == 0 || ocsp_serial != leaf_serial {
        return TlsAlert.BadCertificateStatusResponse;
    }

    if leaf_cert.issuer_raw.length > 0 {
        guard resp.issuer_name_hash.length > 0 else {
            return TlsAlert.BadCertificateStatusResponse;
        }
        let ocsp_nh = span_slice(raw_ocsp, resp.issuer_name_hash);
        let issuer_dn = span_slice(leaf_raw, leaf_cert.issuer_raw);
        if ocsp_nh.len == 32 {
            let h = core::sha256(issuer_dn);
            if !core::ct_eq_bytes(ocsp_nh, h[..]) {
                return TlsAlert.BadCertificateStatusResponse;
            }
        } else if ocsp_nh.len == 20 {
            let h = core::sha1(issuer_dn);
            if !core::ct_eq_bytes(ocsp_nh, h[..]) {
                return TlsAlert.BadCertificateStatusResponse;
            }
        } else {
            return TlsAlert.BadCertificateStatusResponse;
        }
    } else if resp.issuer_name_hash.length > 0 {
        let ocsp_nh = span_slice(raw_ocsp, resp.issuer_name_hash);
        guard ocsp_nh.len == 32 || ocsp_nh.len == 20 else {
            return TlsAlert.BadCertificateStatusResponse;
        }
    }

    return x509_validate_ocsp_temporal(resp, now_unix);
}

fn x509_verify_ocsp_signature(
    resp:        const ParsedOcspResponse&,
    raw_ocsp:    const u8[:],
    issuer_cert: const ParsedCert&,
    issuer_raw:  const u8[:],
) -> TlsAlert {
    guard resp.signature.length > 0 && resp.tbs_raw.length > 0 else {
        return TlsAlert.BadCertificateStatusResponse;
    }
    let sig_oid = span_slice(raw_ocsp, resp.sig_alg_oid);
    let tbs_data = span_slice(raw_ocsp, resp.tbs_raw);
    let sig_bytes = span_slice(raw_ocsp, resp.signature);
    var parent_pubkey = span_slice(issuer_raw, issuer_cert.spki_pubkey);

    if parent_pubkey.len >= 2 && parent_pubkey[0] == 0 {
        parent_pubkey = parent_pubkey[1..];
    }

    return x509_verify_signature_by_oid(
        sig_oid, tbs_data, sig_bytes, parent_pubkey, TlsAlert.BadCertificateStatusResponse,
    );
}

// Unwraps TLS 1.3 / TLS 1.2 status_request extension wire framing (opaque OCSPResponse<1..2^24-1>).
fn unwrap_tls_ocsp_response(ext_data: const u8[:]) -> const u8[:], bool {
    var c = core::cursor_from(ext_data);
    var resp_len: u32 = 0;
    if !c.get_u24(resp_len) { return "", false; }
    guard resp_len > 0 && resp_len == c.cursor_len() else { return "", false; }
    return c.buf, true;
}

// ---- RFC 8446 Section 4.4.3 CertificateVerify Format & Curve Binding -----

// Verifies that signature scheme is strictly bound to the public key curve/algorithm.
// Enforces that legacy PKCS#1 v1.5 RSA schemes are rejected in TLS 1.3.
fn verify_signature_scheme_curve_binding(
    sig_scheme: u16,
    spki_oid:   const u8[:],
) -> bool {
    if rfc::is_forbidden_tls13_sig_scheme(sig_scheme) {
        return false;
    }
    if sig_scheme == rfc::SIG_SCHEME_ECDSA_SECP256R1_SHA256 {
        return spki_oid == rfc::OID_SECP256R1[..];
    } else if sig_scheme == rfc::SIG_SCHEME_ECDSA_SECP384R1_SHA384 {
        return spki_oid == rfc::OID_SECP384R1[..];
    } else if sig_scheme == rfc::SIG_SCHEME_ED25519 {
        return spki_oid == rfc::OID_ED25519[..];
    } else if sig_scheme == rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA256 || sig_scheme == rfc::SIG_SCHEME_RSA_PSS_RSAE_SHA384 {
        return spki_oid == rfc::OID_RSA_ENCRYPTION[..];
    }
    return false; // Rejects legacy PKCS#1 (0x0401, 0x0501) and unknown schemes
}

// Builds the CertificateVerify signed message input (RFC 8446 Section 4.4.3):
// 64 spaces (0x20) || "TLS 1.3, " || context_string || 0x00 || Transcript-Hash
// Total length: 64 + 33 + 1 + hash_len = 98 + hash_len.
fn build_certificate_verify_message(
    is_server:       bool,
    transcript_hash: const u8[:],
    out:             u8[:],
) -> i64, bool {
    var buf: u8[..256] = [];
    for _ in 64 { buf.push(0x20); }
    let ctx = if is_server {
        "TLS 1.3, server CertificateVerify\x00"
    } else {
        "TLS 1.3, client CertificateVerify\x00"
    };
    guard buf.try_append(ctx) && buf.try_append(transcript_hash) else { return 0, false; }
    guard out.len >= buf.len else { return 0, false; }
    core::ct_copy_bytes(out[..buf.len], buf[..]);
    return buf.len, true;
}

// ---- RFC 5280 Section 5 Certificate Revocation List (CRL) & Binary Search ----

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

// Inserts a 64-bit certificate serial number into `crl.serials` in ascending
// sorted order. Fails closed with `false` if `crl.serials.len >= 128` (Invariant 13).
fn crl_insert_serial(crl: ParsedCrl&, serial: u64) -> bool {
    guard crl.serials.len < MAX_CRL_SERIALS else {
        return false;
    }

    var lo: i64 = 0;
    var hi: i64 = crl.serials.len;
    while lo < hi {
        let mid = lo + ((hi - lo) >> 1);
        let mid_val = crl.serials[mid];
        if mid_val == serial {
            return true;
        }
        if mid_val < serial {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }

    crl.serials.push(serial);
    var idx = crl.serials.len - 1;
    while idx > lo {
        crl.serials[idx] = crl.serials[idx - 1];
        idx -= 1;
    }
    crl.serials[lo] = serial;
    crl.serial_count = crl.serials.len as i32;
    return true;
}

// Queries whether `serial` is present in `crl.serials` using O(log N) binary search.
fn crl_is_revoked(crl: const ParsedCrl&, serial: u64) -> bool {
    var lo: i64 = 0;
    var hi: i64 = crl.serials.len;
    while lo < hi {
        let mid = lo + ((hi - lo) >> 1);
        let mid_val = crl.serials[mid];
        if mid_val == serial {
            return true;
        }
        if mid_val < serial {
            lo = mid + 1;
        } else {
            hi = mid;
        }
    }
    return false;
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
        val = (val << 8) | serial_bytes[core::add_sat_i64(start, i)];
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
        guard get_asn1_element(tbs_cert_list, rfc::ASN1_TAG_INTEGER, ver_elem) else {
            return false;
        }
    }

    var sig_alg = core::cursor_from(tbs_cert_list.buf[..0]);
    guard get_asn1_element(tbs_cert_list, rfc::ASN1_TAG_SEQUENCE, sig_alg) else {
        return false;
    }

    var issuer_seq = core::cursor_from(tbs_cert_list.buf[..0]);
    guard get_asn1_element(tbs_cert_list, rfc::ASN1_TAG_SEQUENCE, issuer_seq) else {
        return false;
    }
    out.issuer = issuer_seq.buf;

    var this_up_tag: u8 = 0;
    var this_up_elem = core::cursor_from(tbs_cert_list.buf[..0]);
    guard get_any_asn1_element(tbs_cert_list, this_up_tag, this_up_elem) else {
        return false;
    }
    let _, ok_this = parse_asn1_time(this_up_tag, this_up_elem.buf);
    guard ok_this else {
        return false;
    }

    if tbs_cert_list.cursor_len() > 0 {
        let next_tag = tbs_cert_list.buf[0];
        if next_tag == rfc::ASN1_TAG_UTC_TIME || next_tag == rfc::ASN1_TAG_GENERALIZED_TIME {
            var next_up_tag: u8 = 0;
            var next_up_elem = core::cursor_from(tbs_cert_list.buf[..0]);
            guard get_any_asn1_element(tbs_cert_list, next_up_tag, next_up_elem) else {
                return false;
            }
            let _, ok_next = parse_asn1_time(next_up_tag, next_up_elem.buf);
            guard ok_next else {
                return false;
            }
        }
    }

    if tbs_cert_list.cursor_len() > 0 && tbs_cert_list.buf[0] == rfc::ASN1_TAG_SEQUENCE {
        var revoked_seq = core::cursor_from(tbs_cert_list.buf[..0]);
        guard get_asn1_element(tbs_cert_list, rfc::ASN1_TAG_SEQUENCE, revoked_seq) else {
            return false;
        }
        guard parse_crl_revoked_entries(revoked_seq.buf, out) else {
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
