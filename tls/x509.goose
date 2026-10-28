// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tls/x509.goose
// Deterministic zero-allocation X.509 PKI, canonical ASN.1 DER parser, and RFC 5280 validator.
// Conforms to RFC 5280, RFC 6125 (SAN matching), RFC 8446 Section 4.4.3 (CertificateVerify).
namespace wing;

import std;
import core from "..";
import .record;

// ---- 1. ASN.1 Universal Tags and OIDs ---------------------------------------

const ASN1_TAG_BOOLEAN: u8 = 0x01;
const ASN1_TAG_INTEGER: u8 = 0x02;
const ASN1_TAG_BIT_STRING: u8 = 0x03;
const ASN1_TAG_OCTET_STRING: u8 = 0x04;
const ASN1_TAG_NULL: u8 = 0x05;
const ASN1_TAG_OID: u8 = 0x06;
const ASN1_TAG_UTF8_STRING: u8 = 0x0C;
const ASN1_TAG_PRINTABLE_STRING: u8 = 0x13;
const ASN1_TAG_IA5_STRING: u8 = 0x16;
const ASN1_TAG_UTC_TIME: u8 = 0x17;
const ASN1_TAG_GENERALIZED_TIME: u8 = 0x18;
const ASN1_TAG_SEQUENCE: u8 = 0x30;
const ASN1_TAG_SET: u8 = 0x31;

// Standard OIDs (DER byte encodings):
// id-at-commonName (2.5.4.3): 55 04 03
const OID_COMMON_NAME: u8[3] = [0x55, 0x04, 0x03];
// id-ce-basicConstraints (2.5.29.19): 55 1D 13
const OID_BASIC_CONSTRAINTS: u8[3] = [0x55, 0x1D, 0x13];
// id-ce-keyUsage (2.5.29.15): 55 1D 0F
const OID_KEY_USAGE: u8[3] = [0x55, 0x1D, 0x0F];
// id-ce-subjectAltName (2.5.29.17): 55 1D 11
const OID_SUBJECT_ALT_NAME: u8[3] = [0x55, 0x1D, 0x11];
// ecPublicKey (1.2.840.10045.2.1): 2A 86 48 CE 3D 02 01
const OID_EC_PUBLIC_KEY: u8[7] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x02, 0x01];
// secp256r1 (1.2.840.10045.3.1.7): 2A 86 48 CE 3D 03 01 07
const OID_SECP256R1: u8[8] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x03, 0x01, 0x07];
// secp384r1 (1.3.132.0.34): 2B 81 04 00 22
const OID_SECP384R1: u8[5] = [0x2B, 0x81, 0x04, 0x00, 0x22];
// rsaEncryption (1.2.840.113549.1.1.1): 2A 86 48 86 F7 0D 01 01 01
const OID_RSA_ENCRYPTION: u8[9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x01];
// ed25519 (1.3.101.112): 2B 65 70
const OID_ED25519: u8[3] = [0x2B, 0x65, 0x70];

const ASN1_TAG_ENUMERATED: u8 = 0x0A;

// id-ce-subjectKeyIdentifier (2.5.29.14): 55 1D 0E
const OID_SUBJECT_KEY_IDENTIFIER: u8[3] = [0x55, 0x1D, 0x0E];
// id-ce-nameConstraints (2.5.29.30): 55 1D 1E
const OID_NAME_CONSTRAINTS: u8[3] = [0x55, 0x1D, 0x1E];
// id-ce-authorityKeyIdentifier (2.5.29.35): 55 1D 23
const OID_AUTH_KEY_IDENTIFIER: u8[3] = [0x55, 0x1D, 0x23];
// id-ce-policyConstraints (2.5.29.36): 55 1D 24
const OID_POLICY_CONSTRAINTS: u8[3] = [0x55, 0x1D, 0x24];
// id-ce-inhibitAnyPolicy (2.5.29.54): 55 1D 36
const OID_INHIBIT_ANY_POLICY: u8[3] = [0x55, 0x1D, 0x36];
// id-pkix-ocsp-basic (1.3.6.1.5.5.7.48.1.1): 2B 06 01 05 05 07 30 01 01
const OID_OCSP_BASIC: u8[9] = [0x2B, 0x06, 0x01, 0x05, 0x05, 0x07, 0x30, 0x01, 0x01];

fn is_known_extension_oid(oid: const u8[:]) -> bool {
    if oid == OID_BASIC_CONSTRAINTS[..] ||
       oid == OID_KEY_USAGE[..] ||
       oid == OID_SUBJECT_ALT_NAME[..] ||
       oid == OID_NAME_CONSTRAINTS[..] ||
       oid == OID_AUTH_KEY_IDENTIFIER[..] ||
       oid == OID_SUBJECT_KEY_IDENTIFIER[..] ||
       oid == OID_POLICY_CONSTRAINTS[..] ||
       oid == OID_INHIBIT_ANY_POLICY[..] {
        return true;
    }
    return false;
}

// Key Usage bitmasks (byte 1)
const KEY_USAGE_DIGITAL_SIGNATURE: u16 = 0x8000;
const KEY_USAGE_KEY_ENCIPHERMENT: u16 = 0x2000;
const KEY_USAGE_KEY_CERT_SIGN: u16 = 0x0400;
const KEY_USAGE_CRL_SIGN: u16 = 0x0200;

// SignatureScheme identifiers (RFC 8446 Section 4.2.3)
const SIG_SCHEME_RSA_PKCS1_SHA256: u16 = 0x0401; // Forbidden in TLS 1.3
const SIG_SCHEME_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
const SIG_SCHEME_RSA_PKCS1_SHA384: u16 = 0x0501; // Forbidden in TLS 1.3
const SIG_SCHEME_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
const SIG_SCHEME_RSA_PKCS1_SHA512: u16 = 0x0601; // Forbidden in TLS 1.3
const SIG_SCHEME_RSA_PKCS1_SHA1: u16 = 0x0201;   // Forbidden in TLS 1.3
const SIG_SCHEME_ECDSA_SHA1: u16 = 0x0203;       // Forbidden in TLS 1.3
const SIG_SCHEME_RSA_PKCS1_MD5: u16 = 0x0101;    // Forbidden in TLS 1.3
const SIG_SCHEME_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
const SIG_SCHEME_RSA_PSS_RSAE_SHA384: u16 = 0x0805;
const SIG_SCHEME_ED25519: u16 = 0x0807;

// Forbidden Certificate Signature Algorithm OIDs (RFC 8446 Section 4.4.2.3: MD5 & SHA-1 forbidden):
// md5WithRSAEncryption (1.2.840.113549.1.1.4): 2A 86 48 86 F7 0D 01 01 04
const OID_SIG_MD5_RSA: u8[9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x04];
// sha1WithRSAEncryption (1.2.840.113549.1.1.5): 2A 86 48 86 F7 0D 01 01 05
const OID_SIG_SHA1_RSA: u8[9] = [0x2A, 0x86, 0x48, 0x86, 0xF7, 0x0D, 0x01, 0x01, 0x05];
// ecdsa-with-SHA1 (1.2.840.10045.4.1): 2A 86 48 CE 3D 04 01
const OID_SIG_SHA1_ECDSA: u8[7] = [0x2A, 0x86, 0x48, 0xCE, 0x3D, 0x04, 0x01];
// dsa-with-sha1 (1.2.840.10040.4.3): 2A 86 48 CE 38 04 03
const OID_SIG_SHA1_DSA: u8[7] = [0x2A, 0x86, 0x48, 0xCE, 0x38, 0x04, 0x03];

fn is_forbidden_tls13_sig_scheme(sig_scheme: u16) -> bool {
    if sig_scheme == SIG_SCHEME_RSA_PKCS1_SHA256 ||
       sig_scheme == SIG_SCHEME_RSA_PKCS1_SHA384 ||
       sig_scheme == SIG_SCHEME_RSA_PKCS1_SHA512 ||
       sig_scheme == SIG_SCHEME_RSA_PKCS1_SHA1 ||
       sig_scheme == SIG_SCHEME_ECDSA_SHA1 ||
       sig_scheme == SIG_SCHEME_RSA_PKCS1_MD5 {
        return true;
    }
    return false;
}

fn is_forbidden_cert_signature_algorithm(sig_alg_oid: const u8[:]) -> bool {
    if sig_alg_oid == OID_SIG_MD5_RSA[..] ||
       sig_alg_oid == OID_SIG_SHA1_RSA[..] ||
       sig_alg_oid == OID_SIG_SHA1_ECDSA[..] ||
       sig_alg_oid == OID_SIG_SHA1_DSA[..] {
        return true;
    }
    return false;
}

// ---- 2. Strict Canonical ASN.1 DER Parser -----------------------------------

// Parses ASN.1 length field with canonical DER rules (X.690 Section 10.1):
// - Short form: 0..127 (1 byte)
// - Long form: byte 0 has bit 8 set, remaining 7 bits is length of length (1..4)
// - Long form with length < 128 is strictly FORBIDDEN (non-minimal shortest form rule).
// - BER indefinite length (0x80) is strictly FORBIDDEN.
// - Redundant leading zeros in long form (e.g. 0x82 0x00 0x80) are strictly FORBIDDEN.
// - Reserved initial octet 0xFF (11111111_2) is strictly FORBIDDEN (X.690 §8.1.3.5(c)).
// - Enforces non-negative 31-bit bounds (0..0x7FFFFFFF) to prevent integer overflows.
fn parse_asn1_long_length(c: ByteCursor&, num_bytes: i64, out_len: i64&) -> bool {
    var length: i64 = 0;
    for i in num_bytes {
        var b: u8 = 0;
        if !get_u8(c, b) { return false; }
        if i == 0 && b == 0x00 { return false; }
        length = (length << 8) | b;
    }
    guard length >= 128 && length <= 0x7FFFFFFF else { return false; }
    out_len = length;
    return true;
}

fn get_asn1_length(c: ByteCursor&, out_len: i64&) -> bool {
    var b0: u8 = 0;
    if !get_u8(c, b0) { return false; }

    if (b0 & 0x80) == 0 {
        out_len = b0;
        return true;
    }

    guard b0 != 0x80 && b0 != 0xFF else { return false; }
    let num_bytes = (b0 & 0x7F) as i64;
    guard num_bytes >= 1 && num_bytes <= 4 else { return false; }
    guard cursor_len(c) >= num_bytes else { return false; }
    return parse_asn1_long_length(c, num_bytes, out_len);
}

// Consumes any ASN.1 TLV element, returning tag and value cursor.
fn get_any_asn1_element(c: ByteCursor&, out_tag: u8&, out_val: ByteCursor&) -> bool {
    if !get_u8(c, out_tag) { return false; }
    var length: i64 = 0;
    if !get_asn1_length(c, length) { return false; }
    return get_bytes(c, out_val, length);
}

// Consumes an ASN.1 element with an expected tag.
fn get_asn1_element(c: ByteCursor&, expected_tag: u8, out_val: ByteCursor&) -> bool {
    var tag: u8 = 0;
    if !get_any_asn1_element(c, tag, out_val) { return false; }
    return tag == expected_tag;
}

fn asn1_check_der_integer_padding(val: const u8[:]) -> bool {
    guard val.len >= 1 else { return false; }
    if val[0] == 0x00 && val.len > 1 {
        if (val[1] & 0x80) == 0 { return false; }
    } else if val[0] == 0xFF && val.len > 1 {
        if (val[1] & 0x80) != 0 { return false; }
    }
    return true;
}

fn asn1_check_serial_number_rules(val: const u8[:]) -> bool {
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
fn validate_asn1_integer(val: const u8[:], is_serial_number: bool) -> bool {
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
    var raw = cursor_from(c.buf[..0]);
    if !get_asn1_element(c, ASN1_TAG_INTEGER, raw) { return false; }
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
fn validate_asn1_bit_string(val: const u8[:]) -> bool {
    guard val.len >= 1 else { return false; }
    let unused = val[0];
    guard unused <= 7 else { return false; }
    if val.len == 1 {
        return unused == 0;
    }
    if unused > 0 {
        let last_byte = val[val.len - 1];
        let mask = ((1 as u16 << unused) - 1) as u8;
        guard (last_byte & mask) == 0 else { return false; }
    }
    return true;
}

// Consumes an ASN.1 BIT STRING element, validating DER unused bits rules and extracting bit payload.
fn get_asn1_bit_string(c: ByteCursor&, out_bits: ByteCursor&, out_unused: u8&) -> bool {
    var raw = cursor_from(c.buf[..0]);
    if !get_asn1_element(c, ASN1_TAG_BIT_STRING, raw) { return false; }
    guard validate_asn1_bit_string(raw.buf) else { return false; }
    out_unused = raw.buf[0];
    out_bits = ByteCursor { buf: raw.buf[1..] };
    return true;
}

// ---- 3. Date & Time Parser (UTCTime & GeneralizedTime) -----------------------

fn parse_2digit(buf: const u8[:], off: i64) -> i64, bool {
    guard off + 2 <= buf.len else { return 0, false; }
    let c1 = buf[off];
    let c2 = buf[off + 1];
    guard c1 >= '0' && c1 <= '9' && c2 >= '0' && c2 <= '9' else { return 0, false; }
    return ((c1 - '0') as i64) * 10 + (c2 - '0'), true;
}

// Validates time fields and leap-year days in month per RFC 5280 Section 4.1.2.5.
fn validate_time_fields(year: i64, month: i64, day: i64, hour: i64, min: i64, sec: i64) -> bool {
    guard month >= 1 && month <= 12 else { return false; }
    let max_days = core::days_in_month(year, month);
    guard max_days > 0 && day >= 1 && day <= max_days else { return false; }
    guard hour >= 0 && hour <= 23 else { return false; }
    guard min >= 0 && min <= 59 else { return false; }
    guard sec >= 0 && sec <= 59 else { return false; }
    return true;
}

// Parses UTCTime ("YYMMDDHHMMSSZ") per RFC 5280 Section 4.1.2.5.1:
// - Must be exactly 13 bytes ending with 'Z'.
// - Conforming systems MUST interpret YY >= 50 as 19YY (1950..1999) and YY < 50 as 20YY (2000..2049).
// - Dates in the year 2050 or later MUST NOT be encoded in UTCTime.
// - Full date and leap-year validation.
fn parse_utc_time(time_bytes: const u8[:]) -> i64, bool {
    guard time_bytes.len == 13 && time_bytes[12] == 'Z' else { return 0, false; }
    let y2, ok_y = parse_2digit(time_bytes, 0);
    guard ok_y else { return 0, false; }

    // RFC 5280 Section 4.1.2.5.1: YY >= 50 -> 19YY, YY < 50 -> 20YY
    let year = if y2 >= 50 { 1900 + y2 } else { 2000 + y2 };

    let month, ok_m = parse_2digit(time_bytes, 2);
    let day, ok_d = parse_2digit(time_bytes, 4);
    let hour, ok_h = parse_2digit(time_bytes, 6);
    let min, ok_min = parse_2digit(time_bytes, 8);
    let sec, ok_s = parse_2digit(time_bytes, 10);

    guard ok_m && ok_d && ok_h && ok_min && ok_s else { return 0, false; }
    guard validate_time_fields(year, month, day, hour, min, sec) else { return 0, false; }

    let days = core::civil_to_days(year, month, day);
    let total_secs = days * 86400 + hour * 3600 + min * 60 + sec;
    return total_secs, true;
}

// Parses GeneralizedTime ("YYYYMMDDHHMMSSZ") per RFC 5280 Section 4.1.2.5.2:
// - Must be exactly 15 bytes ending with 'Z'.
// - Fractional seconds are strictly FORBIDDEN.
// - Full date and leap-year validation.
fn parse_generalized_time(time_bytes: const u8[:]) -> i64, bool {
    guard time_bytes.len == 15 && time_bytes[14] == 'Z' else { return 0, false; }
    let y1, ok_y1 = parse_2digit(time_bytes, 0);
    let y2, ok_y2 = parse_2digit(time_bytes, 2);
    guard ok_y1 && ok_y2 else { return 0, false; }
    let year = y1 * 100 + y2;

    let month, ok_m = parse_2digit(time_bytes, 4);
    let day, ok_d = parse_2digit(time_bytes, 6);
    let hour, ok_h = parse_2digit(time_bytes, 8);
    let min, ok_min = parse_2digit(time_bytes, 10);
    let sec, ok_s = parse_2digit(time_bytes, 12);

    guard ok_m && ok_d && ok_h && ok_min && ok_s else { return 0, false; }
    guard validate_time_fields(year, month, day, hour, min, sec) else { return 0, false; }

    let days = core::civil_to_days(year, month, day);
    let total_secs = days * 86400 + hour * 3600 + min * 60 + sec;
    return total_secs, true;
}

// Parses UTCTime ("YYMMDDHHMMSSZ") or GeneralizedTime ("YYYYMMDDHHMMSSZ") to Unix timestamp seconds.
fn parse_asn1_time(time_tag: u8, time_bytes: const u8[:]) -> i64, bool {
    if time_tag == ASN1_TAG_UTC_TIME {
        return parse_utc_time(time_bytes);
    } else if time_tag == ASN1_TAG_GENERALIZED_TIME {
        return parse_generalized_time(time_bytes);
    }
    return 0, false;
}

// ---- 4. Span16 and ParsedCert Descriptor (Zero Heap Allocations) ------------

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
    // Slices in Goose have base pointer arithmetic or offset deduction
    let target_len = target.len;
    guard target_len > 0 && target_len <= 65535 else { return Span16 { offset: 0, length: 0 }; }
    // Offset calculation: compare slice bounds
    let base_len = base.len;
    guard base_len >= target_len && base_len <= 65535 else { return Span16 { offset: 0, length: 0 }; }
    for i in base_len - target_len + 1 {
        if base[i..i + target_len] == target {
            return Span16 { offset: i as u16, length: target_len as u16 };
        }
    }
    return Span16 { offset: 0, length: 0 };
}

struct ParsedCert {
    raw_len: u32 = 0,
    tbs_cert: Span16 = Span16 { offset: 0, length: 0 },
    serial_number: Span16 = Span16 { offset: 0, length: 0 },
    sig_alg_oid: Span16 = Span16 { offset: 0, length: 0 },
    issuer_raw: Span16 = Span16 { offset: 0, length: 0 },
    validity_not_before: i64 = 0,
    validity_not_after: i64 = 0,
    subject_raw: Span16 = Span16 { offset: 0, length: 0 },
    spki_raw: Span16 = Span16 { offset: 0, length: 0 },
    spki_alg_oid: Span16 = Span16 { offset: 0, length: 0 },
    spki_pubkey: Span16 = Span16 { offset: 0, length: 0 },
    extensions_raw: Span16 = Span16 { offset: 0, length: 0 },
    san_raw: Span16 = Span16 { offset: 0, length: 0 },
    has_san: bool = false,
    is_ca: bool = false,
    has_basic_constraints: bool = false,
    path_len_constraint: i32 = -1,
    key_usage: u16 = 0,
    has_key_usage: bool = false,
    has_unsupported_critical: bool = false,
    akid_key_id: Span16 = Span16 { offset: 0, length: 0 },
    has_akid: bool = false,
    skid_key_id: Span16 = Span16 { offset: 0, length: 0 },
    has_skid: bool = false,
    name_constraints_raw: Span16 = Span16 { offset: 0, length: 0 },
    has_name_constraints: bool = false,
    has_malformed_policy_constraints: bool = false,
}

fn parse_tbs_serial(raw_cert: const u8[:], tbs_seq: ByteCursor&, out: ParsedCert&) -> bool {
    var serial = cursor_from(raw_cert[..0]);
    if !get_asn1_element(tbs_seq, ASN1_TAG_INTEGER, serial) { return false; }
    if !validate_asn1_integer(serial.buf, true) { return false; }
    out.serial_number = make_span(raw_cert, serial.buf);
    return true;
}

fn parse_tbs_sig_alg(raw_cert: const u8[:], tbs_seq: ByteCursor&, out: ParsedCert&) -> bool {
    var sig_alg = cursor_from(raw_cert[..0]);
    if !get_asn1_element(tbs_seq, ASN1_TAG_SEQUENCE, sig_alg) { return false; }
    var sig_oid = cursor_from(raw_cert[..0]);
    if !get_asn1_element(sig_alg, ASN1_TAG_OID, sig_oid) { return false; }
    out.sig_alg_oid = make_span(raw_cert, sig_oid.buf);
    return true;
}

fn parse_tbs_validity(raw_cert: const u8[:], tbs_seq: ByteCursor&, out: ParsedCert&) -> bool {
    var validity = cursor_from(raw_cert[..0]);
    if !get_asn1_element(tbs_seq, ASN1_TAG_SEQUENCE, validity) { return false; }
    var nb_val = cursor_from(raw_cert[..0]);
    var nb_tag: u8 = 0;
    if !get_any_asn1_element(validity, nb_tag, nb_val) { return false; }
    let nb_time, ok_nb = parse_asn1_time(nb_tag, nb_val.buf);
    guard ok_nb else { return false; }
    out.validity_not_before = nb_time;

    var na_val = cursor_from(raw_cert[..0]);
    var na_tag: u8 = 0;
    if !get_any_asn1_element(validity, na_tag, na_val) { return false; }
    let na_time, ok_na = parse_asn1_time(na_tag, na_val.buf);
    guard ok_na else { return false; }
    out.validity_not_after = na_time;

    // RFC 5280 §4.1.2.5: Validity period inversion check (notBefore <= notAfter)
    guard out.validity_not_before <= out.validity_not_after else { return false; }
    return true;
}

fn parse_tbs_spki(raw_cert: const u8[:], tbs_seq: ByteCursor&, out: ParsedCert&) -> bool {
    var spki = cursor_from(raw_cert[..0]);
    if !get_asn1_element(tbs_seq, ASN1_TAG_SEQUENCE, spki) { return false; }
    out.spki_raw = make_span(raw_cert, spki.buf);

    var spki_alg = cursor_from(raw_cert[..0]);
    if !get_asn1_element(spki, ASN1_TAG_SEQUENCE, spki_alg) { return false; }
    var spki_oid = cursor_from(raw_cert[..0]);
    if !get_asn1_element(spki_alg, ASN1_TAG_OID, spki_oid) { return false; }
    out.spki_alg_oid = make_span(raw_cert, spki_oid.buf);

    var spki_pubkey = cursor_from(raw_cert[..0]);
    if !get_asn1_element(spki, ASN1_TAG_BIT_STRING, spki_pubkey) { return false; }
    if !validate_asn1_bit_string(spki_pubkey.buf) { return false; }
    out.spki_pubkey = make_span(raw_cert, spki_pubkey.buf);
    return true;
}

fn parse_tbs_extensions(raw_cert: const u8[:], tbs_seq: ByteCursor&, out: ParsedCert&) {
    while cursor_len(tbs_seq) > 0 {
        var ext_container = cursor_from(raw_cert[..0]);
        var ext_tag: u8 = 0;
        if !get_any_asn1_element(tbs_seq, ext_tag, ext_container) { break; }
        if ext_tag == 0xA3 { // [3] EXPLICIT
            var ext_seq = cursor_from(raw_cert[..0]);
            if get_asn1_element(ext_container, ASN1_TAG_SEQUENCE, ext_seq) {
                out.extensions_raw = make_span(raw_cert, ext_seq.buf);
                parse_cert_extensions(raw_cert, ext_seq, out);
            }
        }
    }
}

// Parses raw X.509 certificate DER into zero-allocation ParsedCert descriptor.
fn parse_x509_certificate(raw_cert: const u8[:], out: ParsedCert&) -> bool {
    out.raw_len = raw_cert.len as u32;
    var cert_cursor = cursor_from(raw_cert);

    // Outer Certificate SEQUENCE
    var cert_seq = cursor_from(raw_cert[..0]);
    if !get_asn1_element(cert_cursor, ASN1_TAG_SEQUENCE, cert_seq) { return false; }
    // No trailing bytes allowed in canonical DER certificate
    guard cursor_len(cert_cursor) == 0 else { return false; }

    // TBSCertificate SEQUENCE
    var tbs_seq = cursor_from(raw_cert[..0]);
    let tbs_start_remaining = cursor_len(cert_seq);
    if !get_asn1_element(cert_seq, ASN1_TAG_SEQUENCE, tbs_seq) { return false; }
    out.tbs_cert = make_span(raw_cert, tbs_seq.buf);

    guard x509_skip_tbs_version(tbs_seq) else { return false; }

    if !parse_tbs_serial(raw_cert, tbs_seq, out) { return false; }
    if !parse_tbs_sig_alg(raw_cert, tbs_seq, out) { return false; }
    return parse_tbs_identity(raw_cert, tbs_seq, out);
}

fn x509_skip_tbs_version(tbs_seq: ByteCursor&) -> bool {
    if cursor_len(tbs_seq) > 0 && tbs_seq.buf[0] == 0xA0 {
        var maybe_version = cursor_from(tbs_seq.buf[..0]);
        var tag: u8 = 0;
        return get_any_asn1_element(tbs_seq, tag, maybe_version);
    }
    return true;
}

fn parse_tbs_identity(raw_cert: const u8[:], tbs_seq: ByteCursor&, out: ParsedCert&) -> bool {
    var issuer = cursor_from(raw_cert[..0]);
    if !get_asn1_element(tbs_seq, ASN1_TAG_SEQUENCE, issuer) { return false; }
    out.issuer_raw = make_span(raw_cert, issuer.buf);

    if !parse_tbs_validity(raw_cert, tbs_seq, out) { return false; }

    var subject = cursor_from(raw_cert[..0]);
    if !get_asn1_element(tbs_seq, ASN1_TAG_SEQUENCE, subject) { return false; }
    out.subject_raw = make_span(raw_cert, subject.buf);

    if !parse_tbs_spki(raw_cert, tbs_seq, out) { return false; }
    parse_tbs_extensions(raw_cert, tbs_seq, out);
    return true;
}

fn x509_parse_bc_ca_bool(bc_seq: ByteCursor&, cert: ParsedCert&) {
    guard cursor_len(bc_seq) > 0 && bc_seq.buf[0] == ASN1_TAG_BOOLEAN else { return; }
    var ca_bool = cursor_from(bc_seq.buf[..0]);
    guard get_asn1_element(bc_seq, ASN1_TAG_BOOLEAN, ca_bool) else { return; }
    if ca_bool.buf.len > 0 && ca_bool.buf[0] != 0 {
        cert.is_ca = true;
    }
}

fn x509_parse_bc_path_len(bc_seq: ByteCursor&, cert: ParsedCert&) {
    guard cursor_len(bc_seq) > 0 && bc_seq.buf[0] == ASN1_TAG_INTEGER else { return; }
    var path_len: i64 = 0;
    guard get_asn1_integer(bc_seq, path_len) else { return; }
    if cert.is_ca && path_len >= 0 && path_len <= 255 {
        cert.path_len_constraint = path_len as i32;
    }
}

fn x509_parse_basic_constraints_ext(ext_val: ByteCursor&, cert: ParsedCert&) {
    cert.has_basic_constraints = true;
    var bc_seq = cursor_from(ext_val.buf[..0]);
    guard get_asn1_element(ext_val, ASN1_TAG_SEQUENCE, bc_seq) else { return; }
    x509_parse_bc_ca_bool(bc_seq, cert);
    x509_parse_bc_path_len(bc_seq, cert);
}

fn x509_parse_key_usage_ext(ext_val: ByteCursor&, cert: ParsedCert&) {
    cert.has_key_usage = true;
    var ku_bits = cursor_from(ext_val.buf[..0]);
    guard get_asn1_element(ext_val, ASN1_TAG_BIT_STRING, ku_bits) else { return; }
    guard validate_asn1_bit_string(ku_bits.buf) else { return; }

    if ku_bits.buf.len >= 2 {
        var ku: u16 = (ku_bits.buf[1] as u16) << 8;
        if ku_bits.buf.len >= 3 {
            ku = ku | ku_bits.buf[2];
        }
        cert.key_usage = ku;
    }
}

fn x509_parse_akid_ext(raw_cert: const u8[:], ext_val: ByteCursor&, cert: ParsedCert&) {
    var akid_seq = cursor_from(ext_val.buf[..0]);
    guard get_asn1_element(ext_val, ASN1_TAG_SEQUENCE, akid_seq) else { return; }
    guard cursor_len(akid_seq) > 0 && akid_seq.buf[0] == 0x80 else { return; }
    var akid_key = cursor_from(akid_seq.buf[..0]);
    guard get_asn1_element(akid_seq, 0x80, akid_key) else { return; }
    guard akid_key.buf.len > 0 && akid_key.buf.len <= 64 else { return; }
    cert.has_akid = true;
    cert.akid_key_id = make_span(raw_cert, akid_key.buf);
}

fn x509_parse_skid_ext(raw_cert: const u8[:], ext_val: ByteCursor&, cert: ParsedCert&) {
    var skid_oct = cursor_from(ext_val.buf[..0]);
    guard get_asn1_element(ext_val, ASN1_TAG_OCTET_STRING, skid_oct) else { return; }
    guard skid_oct.buf.len > 0 && skid_oct.buf.len <= 64 else { return; }
    cert.has_skid = true;
    cert.skid_key_id = make_span(raw_cert, skid_oct.buf);
}

fn x509_check_policy_skip_certs(elem_buf: const u8[:]) -> bool {
    return elem_buf.len > 0 && (elem_buf[0] & 0x80) == 0;
}

fn x509_parse_policy_constraints_ext(ext_val: ByteCursor&, cert: ParsedCert&) {
    var pc_seq = cursor_from(ext_val.buf[..0]);
    if !get_asn1_element(ext_val, ASN1_TAG_SEQUENCE, pc_seq) || cursor_len(pc_seq) == 0 {
        cert.has_malformed_policy_constraints = true;
        return;
    }

    while cursor_len(pc_seq) > 0 {
        var pc_tag: u8 = 0;
        var pc_elem = cursor_from(pc_seq.buf[..0]);
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

fn x509_dispatch_policy_extension(oid: const u8[:], ext_val: ByteCursor&, cert: ParsedCert&) {
    if oid == OID_POLICY_CONSTRAINTS[..] {
        x509_parse_policy_constraints_ext(ext_val, cert);
    } else if oid == OID_INHIBIT_ANY_POLICY[..] {
        var val: i64 = 0;
        if !get_asn1_integer(ext_val, val) || val < 0 {
            cert.has_malformed_policy_constraints = true;
        }
    }
}

fn x509_dispatch_extension(raw_cert: const u8[:], oid: const u8[:], ext_val: ByteCursor&, cert: ParsedCert&) {
    if oid == OID_BASIC_CONSTRAINTS[..] {
        x509_parse_basic_constraints_ext(ext_val, cert);
    } else if oid == OID_KEY_USAGE[..] {
        x509_parse_key_usage_ext(ext_val, cert);
    } else if oid == OID_SUBJECT_ALT_NAME[..] {
        cert.has_san = true;
        cert.san_raw = make_span(raw_cert, ext_val.buf);
    } else if oid == OID_NAME_CONSTRAINTS[..] {
        cert.has_name_constraints = true;
        cert.name_constraints_raw = make_span(raw_cert, ext_val.buf);
    } else if oid == OID_AUTH_KEY_IDENTIFIER[..] {
        x509_parse_akid_ext(raw_cert, ext_val, cert);
    } else if oid == OID_SUBJECT_KEY_IDENTIFIER[..] {
        x509_parse_skid_ext(raw_cert, ext_val, cert);
    } else {
        x509_dispatch_policy_extension(oid, ext_val, cert);
    }
}

fn x509_check_ext_critical(single_ext: ByteCursor&) -> bool {
    guard cursor_len(single_ext) > 0 && single_ext.buf[0] == ASN1_TAG_BOOLEAN else { return false; }
    var maybe_crit = cursor_from(single_ext.buf[..0]);
    if get_asn1_element(single_ext, ASN1_TAG_BOOLEAN, maybe_crit) {
        return maybe_crit.buf.len > 0 && maybe_crit.buf[0] != 0;
    }
    return false;
}

fn x509_parse_single_cert_extension(raw_cert: const u8[:], single_ext: ByteCursor&, cert: ParsedCert&) {
    var oid = cursor_from(single_ext.buf[..0]);
    if !get_asn1_element(single_ext, ASN1_TAG_OID, oid) { return; }

    let is_critical = x509_check_ext_critical(single_ext);

    var ext_val = cursor_from(single_ext.buf[..0]);
    if !get_asn1_element(single_ext, ASN1_TAG_OCTET_STRING, ext_val) { return; }

    if !is_known_extension_oid(oid.buf) {
        if is_critical {
            cert.has_unsupported_critical = true;
        }
        return;
    }

    x509_dispatch_extension(raw_cert, oid.buf, ext_val, cert);
}

// Parses X.509 extensions for BasicConstraints, KeyUsage, and SubjectAltName.
fn parse_cert_extensions(raw_cert: const u8[:], ext_seq: ByteCursor&, cert: ParsedCert&) {
    while cursor_len(ext_seq) > 0 {
        var single_ext = cursor_from(ext_seq.buf[..0]);
        if !get_asn1_element(ext_seq, ASN1_TAG_SEQUENCE, single_ext) { break; }
        x509_parse_single_cert_extension(raw_cert, single_ext, cert);
    }
}

// ---- 5. Trust Anchors and RFC 5280 Verification -----------------------------

struct TrustAnchor {
    subject_dn_sha256: u8[32] = [0; 32],
    spki_sha256: u8[32] = [0; 32],
    is_valid: bool = false,
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
        spki_sha256: spki_hash,
        is_valid: true,
    });
    return true;
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
    if cert.has_key_usage && (cert.key_usage & KEY_USAGE_KEY_CERT_SIGN) != 0 {
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
    if cert.has_key_usage && (cert.key_usage & KEY_USAGE_KEY_CERT_SIGN) == 0 {
        return TlsAlert.UnsupportedCertificate;
    }
    // pathLenConstraint gives max intermediate certs that may follow this cert
    if cert.path_len_constraint >= 0 && (depth - 1) > cert.path_len_constraint {
        return TlsAlert.BadCertificate;
    }
    return TlsAlert.CloseNotify;
}

// ---- 6. RFC 6125 SAN (Subject Alternative Name) DNS Wildcard Matching ------

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

fn x509_is_ip_literal(host: const u8[:]) -> bool {
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
    Other,
}

struct SanEntry {
    san_type: SanType = SanType.Dns,
    val: const u8[:] = [],
}

fn x509_process_ipv4_char(b: u8, octet_idx: i64&, current: u32&, digits: i64&, out_ip: u8[4]&) -> bool {
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
fn parse_ipv4_literal(str: const u8[:], out_ip: u8[4]&) -> bool {
    var octet_idx: i64 = 0;
    var current: u32 = 0;
    var digits: i64 = 0;

    for i in str.len {
        if !x509_process_ipv4_char(str[i], octet_idx, current, digits, out_ip) {
            return false;
        }
    }

    guard digits > 0 && current <= 255 && octet_idx == 3 else { return false; }
    out_ip[3] = current as u8;
    return true;
}

fn x509_is_dns_label_char(b: u8) -> bool {
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
    var label_idx: i64 = 0;

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

fn x509_classify_san_element(tag_num: u8, elem_buf: const u8[:], out_type: SanType&) -> bool {
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
fn parse_san_extension(san_der: const u8[:], out_sans: SanEntry[..16]&) -> bool {
    var c = cursor_from(san_der);
    var names_seq = cursor_from(san_der[..0]);
    if !get_asn1_element(c, ASN1_TAG_SEQUENCE, names_seq) { return false; }
    guard cursor_len(c) == 0 else { return false; }
    guard cursor_len(names_seq) > 0 else { return false; }

    var count: i64 = 0;
    while cursor_len(names_seq) > 0 {
        var tag: u8 = 0;
        var elem = cursor_from(names_seq.buf[..0]);
        if !get_any_asn1_element(names_seq, tag, elem) { return false; }

        let tag_num = tag & 0x1F;
        var st = SanType.Other;
        guard x509_classify_san_element(tag_num, elem.buf, st) else { return false; }

        if out_sans.len < out_sans.cap {
            out_sans.push(SanEntry {
                san_type: st,
                val: elem.buf,
            });
        }
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
    san_type: SanType = SanType.Dns,
    is_excluded: bool = false,
    val: const u8[:] = [],
}

// Validates that an IPv4 (4-byte) or IPv6 (16-byte) subnet mask is contiguous CIDR.
// In network byte order, once a 0 bit appears, no 1 bit may follow.
fn x509_check_mask_byte(b: u8, seen_zero_bit: bool&) -> bool {
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

// RFC 5280 §4.2.1.10: DNS name constraint matching
// DNS name restrictions may be indicated as "example.com" or ".example.com".
// Normalizes trailing dots in candidate and constraint to prevent ExcludedSubtree bypass.
// Rejects embedded NUL bytes (CVE-2021-3712 / OpenSSL #31686).
fn match_dns_name_constraint(candidate_dns: const u8[:], constraint: const u8[:]) -> bool {
    guard candidate_dns.len > 0 && constraint.len > 0 else { return false; }
    guard !core::contains_byte(candidate_dns, 0) && !core::contains_byte(constraint, 0) else { return false; }

    let cand = x509_strip_trailing_dot(candidate_dns);
    let cons = x509_strip_trailing_dot(constraint);
    guard cand.len > 0 && cons.len > 0 else { return false; }

    // If constraint has a leading dot: ".example.com"
    if cons[0] == '.' {
        let domain = cons[1..];
        guard domain.len > 0 else { return false; }
        // Candidate must be a subdomain ending with constraint (e.g. "sub.example.com")
        guard cand.len > cons.len else { return false; }
        let suffix = cand[cand.len - cons.len..];
        return eq_ascii_fold(suffix, cons);
    }

    // Constraint without leading dot: "example.com"
    // Matches exact domain
    if eq_ascii_fold(cand, cons) {
        return true;
    }

    // Matches subdomains of "example.com", e.g. "sub.example.com"
    guard cand.len > cons.len + 1 else { return false; }
    let dot_pos = cand.len - cons.len - 1;
    guard cand[dot_pos] == '.' else { return false; }
    let suffix = cand[cand.len - cons.len..];
    return eq_ascii_fold(suffix, cons);
}

// RFC 5280 §4.2.1.10: IP address name constraint matching
// Candidate IP is 4 octets (IPv4) or 16 octets (IPv6).
// Constraint MUST be 8 octets (IPv4) or 32 octets (IPv6): IP || Subnet Mask.
fn match_ip_name_constraint(candidate_ip: const u8[:], constraint: const u8[:]) -> bool {
    guard (candidate_ip.len == 4 && constraint.len == 8) || (candidate_ip.len == 16 && constraint.len == 32) else { return false; }
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

fn x509_parse_general_subtree_base(subtree: ByteCursor&, out_type: SanType&, out_val: ByteCursor&) -> bool {
    var base_tag: u8 = 0;
    if !get_any_asn1_element(subtree, base_tag, out_val) { return false; }
    let tag_num = base_tag & 0x1F;
    if tag_num == 2 { // dNSName
        out_type = SanType.Dns;
        guard out_val.buf.len > 0 else { return false; }
    } else if tag_num == 7 { // iPAddress
        out_type = SanType.Ip;
        guard out_val.buf.len == 8 || out_val.buf.len == 32 else { return false; }
        let half = out_val.buf.len / 2;
        guard validate_cidr_mask(out_val.buf[half..]) else { return false; }
    } else {
        out_type = SanType.Other;
    }
    return true;
}

fn x509_validate_subtree_bound_opt(opt_tag: u8, opt_elem: ByteCursor&) -> bool {
    let opt_num = opt_tag & 0x1F;
    if opt_num == 0 { // minimum MUST be zero
        var min_val: i64 = 0;
        return get_asn1_integer(opt_elem, min_val) && min_val == 0;
    }
    return false; // maximum (opt_num == 1) or other tags forbidden
}

fn x509_parse_general_subtree_bounds(subtree: ByteCursor&) -> bool {
    while cursor_len(subtree) > 0 {
        var opt_tag: u8 = 0;
        var opt_elem = cursor_from(subtree.buf[..0]);
        if !get_any_asn1_element(subtree, opt_tag, opt_elem) { return false; }
        guard x509_validate_subtree_bound_opt(opt_tag, opt_elem) else { return false; }
    }
    return true;
}

fn x509_parse_general_subtree(
    nc_der: const u8[:],
    subtree: ByteCursor&,
    is_excluded: bool,
    out_constraints: NameConstraintEntry[..16]&,
) -> bool {
    var st = SanType.Other;
    var base_elem = cursor_from(nc_der[..0]);
    guard x509_parse_general_subtree_base(subtree, st, base_elem) else { return false; }
    guard x509_parse_general_subtree_bounds(subtree) else { return false; }

    if out_constraints.len < out_constraints.cap {
        let span = make_span(nc_der, base_elem.buf);
        out_constraints.push(NameConstraintEntry {
            san_type: st,
            is_excluded: is_excluded,
            val: span_slice(nc_der, span),
        });
    }
    return true;
}

fn x509_parse_subtrees_sequence(
    nc_der: const u8[:],
    subtrees_elem: ByteCursor&,
    is_excluded: bool,
    out_constraints: NameConstraintEntry[..16]&,
    count: i64&,
) -> bool {
    var subtrees_seq = cursor_from(subtrees_elem.buf[..0]);
    if cursor_len(subtrees_elem) > 0 && subtrees_elem.buf[0] == ASN1_TAG_SEQUENCE {
        if !get_asn1_element(subtrees_elem, ASN1_TAG_SEQUENCE, subtrees_seq) { return false; }
    } else {
        subtrees_seq = subtrees_elem;
    }
    guard cursor_len(subtrees_seq) > 0 else { return false; }

    while cursor_len(subtrees_seq) > 0 {
        var subtree = cursor_from(subtrees_seq.buf[..0]);
        if !get_asn1_element(subtrees_seq, ASN1_TAG_SEQUENCE, subtree) { return false; }
        guard x509_parse_general_subtree(nc_der, subtree, is_excluded, out_constraints) else { return false; }
        count++;
    }
    return true;
}

// Parses NameConstraints extension (RFC 5280 §4.2.1.10) into bounded stack storage.
// Enforces that empty NameConstraints, non-contiguous masks, non-zero minimums, or present maximums are rejected.
fn parse_name_constraints(nc_der: const u8[:], out_constraints: NameConstraintEntry[..16]&) -> bool {
    var c = cursor_from(nc_der);
    var nc_seq = cursor_from(nc_der[..0]);
    if !get_asn1_element(c, ASN1_TAG_SEQUENCE, nc_seq) { return false; }
    guard cursor_len(c) == 0 else { return false; }
    guard cursor_len(nc_seq) > 0 else { return false; } // RFC 5280: empty NameConstraints is forbidden!

    var count: i64 = 0;
    while cursor_len(nc_seq) > 0 {
        var tag: u8 = 0;
        var subtrees_elem = cursor_from(nc_seq.buf[..0]);
        if !get_any_asn1_element(nc_seq, tag, subtrees_elem) { return false; }

        let is_excluded = (tag == 0xA1);
        let is_permitted = (tag == 0xA0);
        guard is_excluded || is_permitted else { return false; }

        guard x509_parse_subtrees_sequence(nc_der, subtrees_elem, is_excluded, out_constraints, count) else { return false; }
    }
    return count > 0;
}

fn x509_match_constraint_entry(nc: const NameConstraintEntry&, san: const SanEntry&) -> bool {
    if nc.san_type == SanType.Dns {
        return match_dns_name_constraint(san.val, nc.val);
    }
    if nc.san_type == SanType.Ip {
        return match_ip_name_constraint(san.val, nc.val);
    }
    return false;
}

fn x509_eval_single_nc(
    nc: const NameConstraintEntry&,
    san: const SanEntry&,
    has_permitted: bool&,
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
    san: const SanEntry&,
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

fn x509_is_cert_duplicate(raw_j: const u8[:], cert_j: const ParsedCert&, raw_k: const u8[:], cert_k: const ParsedCert&) -> bool {
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
    cert: const ParsedCert&,
    raw_cert: const u8[:],
    i: i64,
    is_direct_trust_anchor: bool,
    now_unix: i64,
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
    if is_forbidden_cert_signature_algorithm(sig_oid) {
        return TlsAlert.UnsupportedCertificate;
    }

    if i == 0 && !is_direct_trust_anchor {
        return validate_end_entity_constraints(cert);
    } else if i > 0 {
        return validate_intermediate_ca_constraints(cert, i);
    }
    return TlsAlert.CloseNotify;
}

fn x509_validate_chain_linkage(
    chain_certs: const ParsedCert[..8]&,
    raw_certs: const u8[:][..8]&,
    i: i64,
) -> TlsAlert {
    if i + 1 < chain_certs.len {
        let cert = chain_certs[i];
        let issuer_slice = span_slice(raw_certs[i], cert.issuer_raw);
        let next_subject_slice = span_slice(raw_certs[i + 1], chain_certs[i + 1].subject_raw);
        if issuer_slice != next_subject_slice {
            return TlsAlert.UnknownCa;
        }

        if cert.has_akid && chain_certs[i + 1].has_skid {
            let child_akid = span_slice(raw_certs[i], cert.akid_key_id);
            let parent_skid = span_slice(raw_certs[i + 1], chain_certs[i + 1].skid_key_id);
            if child_akid != parent_skid {
                return TlsAlert.UnknownCa;
            }
        }
    }
    return TlsAlert.CloseNotify;
}

fn x509_check_child_sans_against_nc(
    nc_entries: const NameConstraintEntry[..16]&,
    child_cert: const ParsedCert&,
    child_raw: const u8[:],
) -> bool {
    guard child_cert.has_san else { return true; }
    var child_sans: SanEntry[..16] = [];
    guard get_cert_san_extension(child_cert, child_raw, child_sans) else { return true; }
    for s_idx in child_sans.len {
        if !check_name_constraints(nc_entries, child_sans[s_idx]) {
            return false;
        }
    }
    return true;
}

fn x509_enforce_single_cert_nc(
    chain_certs: const ParsedCert[..8]&,
    raw_certs: const u8[:][..8]&,
    k: i64,
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
    raw_certs: const u8[:][..8]&,
) -> TlsAlert {
    for k in chain_certs.len {
        guard x509_enforce_single_cert_nc(chain_certs, raw_certs, k) else {
            return TlsAlert.BadCertificate;
        }
    }
    return TlsAlert.CloseNotify;
}

// RFC 5280 Certificate Chain Validation.
// Returns TlsAlert.CloseNotify (0) on success, or appropriate fatal alert.
fn verify_certificate_chain(
    chain_certs: const ParsedCert[..8]&,
    raw_certs: const u8[:][..8]&,
    trust_store: const TrustAnchorStore&,
    now_unix: i64,
) -> TlsAlert {
    guard chain_certs.len > 0 && chain_certs.len <= MAX_CHAIN_DEPTH else { return TlsAlert.BadCertificate; }
    guard raw_certs.len == chain_certs.len else { return TlsAlert.BadCertificate; }

    if x509_detect_chain_cycles(chain_certs, raw_certs) {
        return TlsAlert.BadCertificate;
    }

    let is_direct_trust_anchor = (chain_certs.len == 1 && matches_trust_anchor(trust_store, chain_certs[0], raw_certs[0]));

    for i in chain_certs.len {
        let cert_alert = x509_validate_single_chain_cert(chain_certs[i], raw_certs[i], i, is_direct_trust_anchor, now_unix);
        guard cert_alert == TlsAlert.CloseNotify else { return cert_alert; }

        let link_alert = x509_validate_chain_linkage(chain_certs, raw_certs, i);
        guard link_alert == TlsAlert.CloseNotify else { return link_alert; }
    }

    let nc_alert = x509_enforce_chain_name_constraints(chain_certs, raw_certs);
    guard nc_alert == TlsAlert.CloseNotify else { return nc_alert; }

    let top_idx = chain_certs.len - 1;
    if !matches_trust_anchor(trust_store, chain_certs[top_idx], raw_certs[top_idx]) {
        return TlsAlert.UnknownCa;
    }

    return TlsAlert.CloseNotify;
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
    status: OcspResponseStatus = OcspResponseStatus.Unknown,
    cert_status: OcspCertStatus = OcspCertStatus.Unknown,
    serial_number: Span16 = Span16 { offset: 0, length: 0 },
    this_update: i64 = 0,
    next_update: i64 = 0,
    has_next_update: bool = false,
}

fn x509_parse_ocsp_status(s_val: u8, out_status: OcspResponseStatus&) -> bool {
    if s_val == 0 {
        out_status = OcspResponseStatus.Successful;
        return true;
    }
    if s_val == 1 {
        out_status = OcspResponseStatus.MalformedRequest;
        return true;
    }
    if s_val == 2 {
        out_status = OcspResponseStatus.InternalError;
        return true;
    }
    if s_val == 3 {
        out_status = OcspResponseStatus.TryLater;
        return true;
    }
    if s_val == 5 {
        out_status = OcspResponseStatus.SigRequired;
        return true;
    }
    if s_val == 6 {
        out_status = OcspResponseStatus.Unauthorized;
        return true;
    }
    out_status = OcspResponseStatus.Unknown;
    return false;
}

fn x509_parse_ocsp_cert_id(
    single_resp: ByteCursor&,
    raw_ocsp: const u8[:],
    out: ParsedOcspResponse&,
) -> bool {
    var cert_id_seq = cursor_from(single_resp.buf[..0]);
    if !get_asn1_element(single_resp, ASN1_TAG_SEQUENCE, cert_id_seq) { return false; }

    var hash_alg = cursor_from(cert_id_seq.buf[..0]);
    if !get_asn1_element(cert_id_seq, ASN1_TAG_SEQUENCE, hash_alg) { return false; }
    var name_hash = cursor_from(cert_id_seq.buf[..0]);
    if !get_asn1_element(cert_id_seq, ASN1_TAG_OCTET_STRING, name_hash) { return false; }
    var key_hash = cursor_from(cert_id_seq.buf[..0]);
    if !get_asn1_element(cert_id_seq, ASN1_TAG_OCTET_STRING, key_hash) { return false; }

    var serial = cursor_from(cert_id_seq.buf[..0]);
    if !get_asn1_element(cert_id_seq, ASN1_TAG_INTEGER, serial) { return false; }
    if !validate_asn1_integer(serial.buf, true) { return false; }
    out.serial_number = make_span(raw_ocsp, serial.buf);
    return true;
}

fn x509_parse_ocsp_cert_status(single_resp: ByteCursor&, out_status: OcspCertStatus&) -> bool {
    var cert_status_tag: u8 = 0;
    var cert_status_elem = cursor_from(single_resp.buf[..0]);
    if !get_any_asn1_element(single_resp, cert_status_tag, cert_status_elem) { return false; }
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

fn x509_parse_ocsp_next_update(single_resp: ByteCursor&, out: ParsedOcspResponse&) {
    guard cursor_len(single_resp) > 0 && single_resp.buf[0] == 0xA0 else { return; }
    var next_up_ctx = cursor_from(single_resp.buf[..0]);
    guard get_asn1_element(single_resp, 0xA0, next_up_ctx) else { return; }
    var next_up_tag: u8 = 0;
    var next_up_elem = cursor_from(next_up_ctx.buf[..0]);
    guard get_any_asn1_element(next_up_ctx, next_up_tag, next_up_elem) else { return; }
    let next_time, ok_next = parse_asn1_time(next_up_tag, next_up_elem.buf);
    if ok_next {
        out.next_update = next_time;
        out.has_next_update = true;
    }
}

fn x509_parse_ocsp_single_response(
    responses_seq: ByteCursor&,
    raw_ocsp: const u8[:],
    out: ParsedOcspResponse&,
) -> bool {
    guard cursor_len(responses_seq) > 0 else { return false; }
    var single_resp = cursor_from(responses_seq.buf[..0]);
    if !get_asn1_element(responses_seq, ASN1_TAG_SEQUENCE, single_resp) { return false; }

    guard x509_parse_ocsp_cert_id(single_resp, raw_ocsp, out) else { return false; }
    guard x509_parse_ocsp_cert_status(single_resp, out.cert_status) else { return false; }

    var this_up_tag: u8 = 0;
    var this_up_elem = cursor_from(single_resp.buf[..0]);
    if !get_any_asn1_element(single_resp, this_up_tag, this_up_elem) { return false; }
    let this_time, ok_this = parse_asn1_time(this_up_tag, this_up_elem.buf);
    guard ok_this else { return false; }
    out.this_update = this_time;

    x509_parse_ocsp_next_update(single_resp, out);
    return true;
}

fn x509_skip_ocsp_version_and_id(tbs_resp_data: ByteCursor&) -> bool {
    if cursor_len(tbs_resp_data) > 0 && tbs_resp_data.buf[0] == 0xA0 {
        var ver_elem = cursor_from(tbs_resp_data.buf[..0]);
        get_asn1_element(tbs_resp_data, 0xA0, ver_elem);
    }
    var resp_id_tag: u8 = 0;
    var resp_id = cursor_from(tbs_resp_data.buf[..0]);
    return get_any_asn1_element(tbs_resp_data, resp_id_tag, resp_id);
}

fn x509_parse_ocsp_basic_response(
    resp_bytes_seq: ByteCursor&,
    raw_ocsp: const u8[:],
    out: ParsedOcspResponse&,
) -> bool {
    var resp_type_oid = cursor_from(resp_bytes_seq.buf[..0]);
    if !get_asn1_element(resp_bytes_seq, ASN1_TAG_OID, resp_type_oid) { return false; }
    guard resp_type_oid.buf == OID_OCSP_BASIC[..] else { return false; }

    var resp_oct = cursor_from(resp_bytes_seq.buf[..0]);
    if !get_asn1_element(resp_bytes_seq, ASN1_TAG_OCTET_STRING, resp_oct) { return false; }

    var basic_seq = cursor_from(resp_oct.buf[..0]);
    if !get_asn1_element(resp_oct, ASN1_TAG_SEQUENCE, basic_seq) { return false; }

    var tbs_resp_data = cursor_from(basic_seq.buf[..0]);
    if !get_asn1_element(basic_seq, ASN1_TAG_SEQUENCE, tbs_resp_data) { return false; }

    guard x509_skip_ocsp_version_and_id(tbs_resp_data) else { return false; }

    var prod_time = cursor_from(tbs_resp_data.buf[..0]);
    if !get_asn1_element(tbs_resp_data, ASN1_TAG_GENERALIZED_TIME, prod_time) { return false; }

    var responses_seq = cursor_from(tbs_resp_data.buf[..0]);
    if !get_asn1_element(tbs_resp_data, ASN1_TAG_SEQUENCE, responses_seq) { return false; }

    return x509_parse_ocsp_single_response(responses_seq, raw_ocsp, out);
}

// Parses an OCSPResponse (RFC 6960 §4.2.1) with zero dynamic allocation.
fn parse_ocsp_response(raw_ocsp: const u8[:], out: ParsedOcspResponse&) -> bool {
    var c = cursor_from(raw_ocsp);
    var ocsp_seq = cursor_from(raw_ocsp[..0]);
    if !get_asn1_element(c, ASN1_TAG_SEQUENCE, ocsp_seq) { return false; }
    guard cursor_len(c) == 0 else { return false; }

    var status_oct = cursor_from(ocsp_seq.buf[..0]);
    if !get_asn1_element(ocsp_seq, ASN1_TAG_ENUMERATED, status_oct) { return false; }
    guard status_oct.buf.len == 1 else { return false; }

    guard x509_parse_ocsp_status(status_oct.buf[0], out.status) else { return false; }
    if out.status != OcspResponseStatus.Successful {
        return true;
    }

    guard cursor_len(ocsp_seq) > 0 else { return false; }
    var resp_bytes_ctx = cursor_from(ocsp_seq.buf[..0]);
    if !get_asn1_element(ocsp_seq, 0xA0, resp_bytes_ctx) { return false; }

    var resp_bytes_seq = cursor_from(resp_bytes_ctx.buf[..0]);
    if !get_asn1_element(resp_bytes_ctx, ASN1_TAG_SEQUENCE, resp_bytes_seq) { return false; }

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
    raw_ocsp: const u8[:],
    leaf_cert: const ParsedCert&,
    leaf_raw: const u8[:],
    now_unix: i64,
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

    return x509_validate_ocsp_temporal(resp, now_unix);
}

// Unwraps TLS 1.3 / TLS 1.2 status_request extension wire framing (opaque OCSPResponse<1..2^24-1>).
fn unwrap_tls_ocsp_response(ext_data: const u8[:]) -> const u8[:], bool {
    var c = cursor_from(ext_data);
    var resp_len: u32 = 0;
    if !get_u24(c, resp_len) { return "", false; }
    guard resp_len > 0 && resp_len == cursor_len(c) else { return "", false; }
    return c.buf, true;
}

// ---- 7. RFC 8446 Section 4.4.3 CertificateVerify Format & Curve Binding -----

// Verifies that signature scheme is strictly bound to the public key curve/algorithm.
// Enforces that legacy PKCS#1 v1.5 RSA schemes are rejected in TLS 1.3.
fn verify_signature_scheme_curve_binding(
    sig_scheme: u16,
    spki_oid: const u8[:],
) -> bool {
    if is_forbidden_tls13_sig_scheme(sig_scheme) {
        return false;
    }
    if sig_scheme == SIG_SCHEME_ECDSA_SECP256R1_SHA256 {
        return spki_oid == OID_SECP256R1[..];
    } else if sig_scheme == SIG_SCHEME_ECDSA_SECP384R1_SHA384 {
        return spki_oid == OID_SECP384R1[..];
    } else if sig_scheme == SIG_SCHEME_ED25519 {
        return spki_oid == OID_ED25519[..];
    } else if sig_scheme == SIG_SCHEME_RSA_PSS_RSAE_SHA256 || sig_scheme == SIG_SCHEME_RSA_PSS_RSAE_SHA384 {
        return spki_oid == OID_RSA_ENCRYPTION[..];
    }
    return false; // Rejects legacy PKCS#1 (0x0401, 0x0501) and unknown schemes
}

// Builds the CertificateVerify signed message input (RFC 8446 Section 4.4.3):
// 64 spaces (0x20) || "TLS 1.3, " || context_string || 0x00 || Transcript-Hash
// Total length: 64 + 33 + 1 + hash_len = 98 + hash_len.
fn build_certificate_verify_message(
    is_server: bool,
    transcript_hash: const u8[:],
    out: u8[:],
) -> i64, bool {
    let needed = 98 + transcript_hash.len;
    guard out.len >= needed else { return 0, false; }

    // 64 spaces
    for i in 64 { out[i] = 0x20; }

    // "TLS 1.3, "
    let prefix = "TLS 1.3, ";
    for i in prefix.len { out[64 + i] = prefix[i]; }

    // Context string: "server CertificateVerify" (24 chars) or "client CertificateVerify" (24 chars)
    let ctx_str = if is_server { "server CertificateVerify" } else { "client CertificateVerify" };
    for i in ctx_str.len { out[73 + i] = ctx_str[i]; }

    // Separator 0x00
    out[73 + ctx_str.len] = 0x00;

    // Transcript Hash
    let hash_start = 74 + ctx_str.len;
    for i in transcript_hash.len {
        out[hash_start + i] = transcript_hash[i];
    }

    return hash_start + transcript_hash.len, true;
}
