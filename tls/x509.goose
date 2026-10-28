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
fn get_asn1_length(c: ByteCursor&, out_len: i64&) -> bool {
    var b0: u8 = 0;
    if !get_u8(c, b0) { return false; }

    if (b0 & 0x80) == 0 {
        out_len = b0;
        return true;
    }

    // Reject BER indefinite form (0x80)
    if b0 == 0x80 { return false; }
    // Reject 0xFF (X.690 Section 8.1.3.5(c))
    if b0 == 0xFF { return false; }

    let num_bytes = (b0 & 0x7F);
    // Maximum supported length is 4 bytes (up to 2GB in signed 32/64-bit integer)
    guard num_bytes >= 1 && num_bytes <= 4 else { return false; }
    guard cursor_len(c) >= num_bytes else { return false; }

    var length: i64 = 0;
    for i in num_bytes {
        var b: u8 = 0;
        if !get_u8(c, b) { return false; }
        // First byte of long form length MUST NOT be 0x00 (redundant leading zero rule)
        if i == 0 && b == 0x00 { return false; }
        length = (length << 8) | b;
    }

    // Canonical DER rule: length must not be encodable in short form (< 128)
    if length < 128 { return false; }
    // Bounds guard: length must be non-negative and <= 0x7FFFFFFF
    guard length >= 0 && length <= 0x7FFFFFFF else { return false; }
    out_len = length;
    return true;
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

// Validates canonical DER rules for ASN.1 INTEGER (X.690 Section 8.3):
// - Length must be >= 1 (zero-length integer is forbidden).
// - No redundant leading zero padding (if first byte is 0x00 and len > 1, next byte must have bit 7 set).
// - No redundant negative sign extension (if first byte is 0xFF and len > 1, next byte must have bit 7 clear).
// - For X.509 serial numbers (RFC 5280 §4.1.2.2): MUST be positive (strictly > 0), max 20 octets.
fn validate_asn1_integer(val: const u8[:], is_serial_number: bool) -> bool {
    guard val.len >= 1 else { return false; }

    if val[0] == 0x00 && val.len > 1 {
        // Redundant leading zero if next byte's highest bit is 0
        if (val[1] & 0x80) == 0 { return false; }
    } else if val[0] == 0xFF && val.len > 1 {
        // Redundant negative sign if next byte's highest bit is 1
        if (val[1] & 0x80) != 0 { return false; }
    }

    if is_serial_number {
        // Serial numbers in RFC 5280 MUST be positive (> 0)
        if (val[0] & 0x80) != 0 { return false; }
        // Single byte 0x00 represents 0, which is non-positive
        if val.len == 1 && val[0] == 0x00 { return false; }
        // RFC 5280 §4.1.2.2: MUST NOT be longer than 20 octets (allow 21 if leading 0x00 padding)
        if val[0] == 0x00 {
            guard val.len <= 21 else { return false; }
        } else {
            guard val.len <= 20 else { return false; }
        }
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

    let bytes = raw.buf;
    if bytes[0] == 0x00 && bytes.len > 1 {
        if (bytes[1] & 0x80) == 0 { return false; }
    } else if bytes[0] == 0xFF && bytes.len > 1 {
        if (bytes[1] & 0x80) != 0 { return false; }
    }

    var val: i64 = if (bytes[0] & 0x80) != 0 { -1 } else { 0 };
    for b in bytes {
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

    var maybe_version = cursor_from(raw_cert[..0]);
    var tag: u8 = 0;
    if tbs_seq.buf.len > 0 && tbs_seq.buf[0] == 0xA0 {
        if !get_any_asn1_element(tbs_seq, tag, maybe_version) { return false; }
    }

    if !parse_tbs_serial(raw_cert, tbs_seq, out) { return false; }
    if !parse_tbs_sig_alg(raw_cert, tbs_seq, out) { return false; }

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

// Parses X.509 extensions for BasicConstraints, KeyUsage, and SubjectAltName.
fn parse_cert_extensions(raw_cert: const u8[:], ext_seq: ByteCursor&, cert: ParsedCert&) {
    while cursor_len(ext_seq) > 0 {
        var single_ext = cursor_from(ext_seq.buf[..0]);
        if !get_asn1_element(ext_seq, ASN1_TAG_SEQUENCE, single_ext) { break; }

        var oid = cursor_from(ext_seq.buf[..0]);
        if !get_asn1_element(single_ext, ASN1_TAG_OID, oid) { continue; }

        var is_critical = false;
        var maybe_critical = cursor_from(ext_seq.buf[..0]);
        if single_ext.buf.len > 0 && single_ext.buf[0] == ASN1_TAG_BOOLEAN {
            if get_asn1_element(single_ext, ASN1_TAG_BOOLEAN, maybe_critical) {
                if maybe_critical.buf.len > 0 && maybe_critical.buf[0] != 0 {
                    is_critical = true;
                }
            }
        }

        var ext_val = cursor_from(ext_seq.buf[..0]);
        if !get_asn1_element(single_ext, ASN1_TAG_OCTET_STRING, ext_val) { continue; }

        // RFC 5280 §4.2: Unrecognized critical extensions MUST cause certificate validation failure
        if !is_known_extension_oid(oid.buf) {
            if is_critical {
                cert.has_unsupported_critical = true;
            }
            continue;
        }

        // Check for BasicConstraints (2.5.29.19)
        if oid.buf == OID_BASIC_CONSTRAINTS[..] {
            cert.has_basic_constraints = true;
            var bc_seq = cursor_from(ext_val.buf[..0]);
            if get_asn1_element(ext_val, ASN1_TAG_SEQUENCE, bc_seq) {
                if cursor_len(bc_seq) > 0 && bc_seq.buf[0] == ASN1_TAG_BOOLEAN {
                    var ca_bool = cursor_from(ext_val.buf[..0]);
                    if get_asn1_element(bc_seq, ASN1_TAG_BOOLEAN, ca_bool) {
                        if ca_bool.buf.len > 0 && ca_bool.buf[0] != 0 {
                            cert.is_ca = true;
                        }
                    }
                }
                if cursor_len(bc_seq) > 0 && bc_seq.buf[0] == ASN1_TAG_INTEGER {
                    var path_len: i64 = 0;
                    if get_asn1_integer(bc_seq, path_len) {
                        // RFC 5280 §4.2.1.9: pathLenConstraint is meaningful ONLY if cA is TRUE and non-negative
                        if cert.is_ca && path_len >= 0 && path_len <= 255 {
                            cert.path_len_constraint = path_len as i32;
                        }
                    }
                }
            }
        }

        // Check for KeyUsage (2.5.29.15)
        if oid.buf == OID_KEY_USAGE[..] {
            cert.has_key_usage = true;
            var ku_bits = cursor_from(ext_val.buf[..0]);
            if get_asn1_element(ext_val, ASN1_TAG_BIT_STRING, ku_bits) {
                if validate_asn1_bit_string(ku_bits.buf) {
                    if ku_bits.buf.len >= 2 {
                        var ku: u16 = (ku_bits.buf[1] as u16) << 8;
                        if ku_bits.buf.len >= 3 {
                            ku = ku | ku_bits.buf[2];
                        }
                        cert.key_usage = ku;
                    }
                }
            }
        }

        // Check for SubjectAltName (2.5.29.17)
        if oid.buf == OID_SUBJECT_ALT_NAME[..] {
            cert.has_san = true;
            cert.san_raw = make_span(raw_cert, ext_val.buf);
        }

        // Check for NameConstraints (2.5.29.30)
        if oid.buf == OID_NAME_CONSTRAINTS[..] {
            cert.has_name_constraints = true;
            cert.name_constraints_raw = make_span(raw_cert, ext_val.buf);
        }

        // Check for AuthorityKeyIdentifier (2.5.29.35)
        if oid.buf == OID_AUTH_KEY_IDENTIFIER[..] {
            var akid_seq = cursor_from(ext_val.buf[..0]);
            if get_asn1_element(ext_val, ASN1_TAG_SEQUENCE, akid_seq) {
                if cursor_len(akid_seq) > 0 && akid_seq.buf[0] == 0x80 {
                    var akid_key = cursor_from(akid_seq.buf[..0]);
                    if get_asn1_element(akid_seq, 0x80, akid_key) {
                        if akid_key.buf.len > 0 && akid_key.buf.len <= 64 {
                            cert.has_akid = true;
                            cert.akid_key_id = make_span(raw_cert, akid_key.buf);
                        }
                    }
                }
            }
        }

        // Check for SubjectKeyIdentifier (2.5.29.14)
        if oid.buf == OID_SUBJECT_KEY_IDENTIFIER[..] {
            var skid_oct = cursor_from(ext_val.buf[..0]);
            if get_asn1_element(ext_val, ASN1_TAG_OCTET_STRING, skid_oct) {
                if skid_oct.buf.len > 0 && skid_oct.buf.len <= 64 {
                    cert.has_skid = true;
                    cert.skid_key_id = make_span(raw_cert, skid_oct.buf);
                }
            }
        }

        // Check for PolicyConstraints (2.5.29.36)
        if oid.buf == OID_POLICY_CONSTRAINTS[..] {
            var pc_seq = cursor_from(ext_val.buf[..0]);
            if !get_asn1_element(ext_val, ASN1_TAG_SEQUENCE, pc_seq) {
                cert.has_malformed_policy_constraints = true;
            } else {
                // RFC 5280 §4.2.1.11: Must NOT be an empty sequence
                if cursor_len(pc_seq) == 0 {
                    cert.has_malformed_policy_constraints = true;
                } else {
                    while cursor_len(pc_seq) > 0 {
                        var pc_tag: u8 = 0;
                        var pc_elem = cursor_from(pc_seq.buf[..0]);
                        if !get_any_asn1_element(pc_seq, pc_tag, pc_elem) {
                            cert.has_malformed_policy_constraints = true;
                            break;
                        }
                        let tag_num = pc_tag & 0x1F;
                        if tag_num == 0 || tag_num == 1 {
                            // SkipCerts is INTEGER (0..MAX)
                            if pc_elem.buf.len == 0 || (pc_elem.buf[0] & 0x80) != 0 {
                                cert.has_malformed_policy_constraints = true;
                                break;
                            }
                        } else {
                            cert.has_malformed_policy_constraints = true;
                            break;
                        }
                    }
                }
            }
        }

        // Check for InhibitAnyPolicy (2.5.29.54)
        if oid.buf == OID_INHIBIT_ANY_POLICY[..] {
            var val: i64 = 0;
            if !get_asn1_integer(ext_val, val) || val < 0 {
                cert.has_malformed_policy_constraints = true;
            }
        }
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
fn match_dns_san(san_pattern: const u8[:], host: const u8[:]) -> bool {
    guard san_pattern.len > 0 && host.len > 0 else { return false; }

    // Exact match (case-insensitive)
    if eq_ascii_fold(san_pattern, host) {
        return true;
    }

    // Check for wildcard pattern: must start with "*."
    guard san_pattern.len >= 3 && san_pattern[0] == '*' && san_pattern[1] == '.' else {
        return false;
    }

    let suffix = san_pattern[2..]; // e.g. "example.com"
    // Suffix must not contain another wildcard
    for b in suffix {
        if b == '*' { return false; }
    }

    // Wildcards MUST NOT be issued for TLDs (e.g. *.com is forbidden per RFC 6125 §6.4.3)
    guard core::contains_byte(suffix, '.') else { return false; }

    // Wildcards MUST NOT match IPv4 or IPv6 literals (RFC 6125 §6.4.3)
    var is_ip = true;
    for b in host {
        if (b < '0' || b > '9') && b != '.' {
            is_ip = false;
            break;
        }
    }
    if is_ip && core::contains_byte(host, '.') { return false; }

    // Host must contain at least one dot separating leftmost label
    var dot_idx = -1;
    for i in host.len {
        if host[i] == '.' {
            dot_idx = i;
            break;
        }
    }

    // If host has no dot, it's an apex/single-label, no wildcard match
    guard dot_idx > 0 else { return false; }

    let host_label = host[..dot_idx];
    let host_remainder = host[dot_idx + 1..];

    // Leftmost label must not be empty
    guard host_label.len > 0 else { return false; }

    // Remaining labels must match suffix exactly
    return eq_ascii_fold(host_remainder, suffix);
}

// Matches URI SAN and enforces RFC 5280 / CVE-2024-45341 defense:
// IPv6 zone IDs (%zone) inside URIs MUST NOT bypass URI name constraints and must be rejected.
fn match_uri_san(san_uri_host: const u8[:], request_host: const u8[:]) -> bool {
    // If either contains '%', reject per CVE-2024-45341
    if core::contains_byte(san_uri_host, '%') || core::contains_byte(request_host, '%') {
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

// Parses decimal IPv4 octets into u8[4]
fn parse_ipv4_literal(str: const u8[:], out_ip: u8[4]&) -> bool {
    var octet_idx: i64 = 0;
    var current: u32 = 0;
    var digits: i64 = 0;

    for i in str.len {
        let b = str[i];
        if b == '.' {
            guard digits > 0 && current <= 255 && octet_idx < 3 else { return false; }
            out_ip[octet_idx] = current as u8;
            octet_idx++;
            current = 0;
            digits = 0;
        } else if b >= '0' && b <= '9' {
            current = current * 10 + (b - '0');
            digits++;
            guard digits <= 3 && current <= 255 else { return false; }
        } else {
            return false;
        }
    }

    guard digits > 0 && current <= 255 && octet_idx == 3 else { return false; }
    out_ip[3] = current as u8;
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
    // Must not start or end with '.'
    guard dns[0] != '.' && dns[dns.len - 1] != '.' else { return false; }

    var label_start: i64 = 0;
    var label_idx: i64 = 0;

    for i in dns.len + 1 {
        let is_end = (i == dns.len);
        let is_dot = !is_end && (dns[i] == '.');

        if is_end || is_dot {
            let label_len = i - label_start;
            // No empty label (e.g. '..') and label length <= 63
            guard label_len >= 1 && label_len <= 63 else { return false; }
            let label = dns[label_start..i];

            // Leftmost label can be wildcard "*"
            if label_idx == 0 && label.len == 1 && label[0] == '*' {
                // Wildcard label is valid
            } else {
                // Hyphen cannot be first or last character of a label
                guard label[0] != '-' && label[label.len - 1] != '-' else { return false; }

                for b in label {
                    let is_alnum = (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9');
                    let is_hyphen = (b == '-');
                    guard is_alnum || is_hyphen else { return false; }
                }
            }

            label_start = i + 1;
            label_idx++;
        }
    }
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
    // No trailing bytes allowed in DER
    guard cursor_len(c) == 0 else { return false; }

    // RFC 5280 Section 4.2.1.6: Sequence must contain at least one entry
    guard cursor_len(names_seq) > 0 else { return false; }

    var count: i64 = 0;
    while cursor_len(names_seq) > 0 {
        var tag: u8 = 0;
        var elem = cursor_from(names_seq.buf[..0]);
        if !get_any_asn1_element(names_seq, tag, elem) { return false; }

        let tag_num = tag & 0x1F;
        var st = SanType.Other;

        if tag_num == 2 { // dNSName [2] IA5String
            st = SanType.Dns;
            guard validate_san_dns_name(elem.buf) else { return false; }
        } else if tag_num == 7 { // iPAddress [7] OCTET STRING
            st = SanType.Ip;
            // RFC 5280 Section 4.2.1.6: iPAddress MUST be 4 or 16 octets
            guard elem.buf.len == 4 || elem.buf.len == 16 else { return false; }
        } else if tag_num == 6 { // uniformResourceIdentifier [6] IA5String
            st = SanType.Uri;
            guard elem.buf.len > 0 else { return false; }
            guard !core::contains_byte(elem.buf, '%') else { return false; }
        } else if tag_num <= 8 {
            st = SanType.Other;
        } else {
            return false;
        }

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
fn validate_cidr_mask(mask: const u8[:]) -> bool {
    guard mask.len == 4 || mask.len == 16 else { return false; }
    var seen_zero_bit = false;
    for b in mask {
        for bit_idx in 8 {
            let bit = ((b as u32) >> (7 - bit_idx)) & 1;
            if bit == 0 {
                seen_zero_bit = true;
            } else {
                if seen_zero_bit {
                    return false; // Non-contiguous subnet mask
                }
            }
        }
    }
    return true;
}

// RFC 5280 §4.2.1.10: DNS name constraint matching
// DNS name restrictions may be indicated as "example.com" or ".example.com".
fn match_dns_name_constraint(candidate_dns: const u8[:], constraint: const u8[:]) -> bool {
    guard candidate_dns.len > 0 && constraint.len > 0 else { return false; }

    // If constraint has a leading dot: ".example.com"
    if constraint[0] == '.' {
        let domain = constraint[1..];
        guard domain.len > 0 else { return false; }
        // Candidate must be a subdomain ending with constraint (e.g. "sub.example.com")
        guard candidate_dns.len > constraint.len else { return false; }
        let suffix = candidate_dns[candidate_dns.len - constraint.len..];
        return eq_ascii_fold(suffix, constraint);
    }

    // Constraint without leading dot: "example.com"
    // Matches exact domain
    if eq_ascii_fold(candidate_dns, constraint) {
        return true;
    }

    // Matches subdomains of "example.com", e.g. "sub.example.com"
    guard candidate_dns.len > constraint.len + 1 else { return false; }
    let dot_pos = candidate_dns.len - constraint.len - 1;
    guard candidate_dns[dot_pos] == '.' else { return false; }
    let suffix = candidate_dns[candidate_dns.len - constraint.len..];
    return eq_ascii_fold(suffix, constraint);
}

// RFC 5280 §4.2.1.10: IP address name constraint matching
// Candidate IP is 4 octets (IPv4) or 16 octets (IPv6).
// Constraint is 8 octets (IPv4) or 32 octets (IPv6): IP || Subnet Mask.
fn match_ip_name_constraint(candidate_ip: const u8[:], constraint: const u8[:]) -> bool {
    let half = constraint.len / 2;
    guard candidate_ip.len == half else { return false; }
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

            // base GeneralName
            var base_tag: u8 = 0;
            var base_elem = cursor_from(subtree.buf[..0]);
            if !get_any_asn1_element(subtree, base_tag, base_elem) { return false; }

            let tag_num = base_tag & 0x1F;
            var st = SanType.Other;
            if tag_num == 2 { // dNSName
                st = SanType.Dns;
                guard base_elem.buf.len > 0 else { return false; }
            } else if tag_num == 7 { // iPAddress
                st = SanType.Ip;
                guard base_elem.buf.len == 8 || base_elem.buf.len == 32 else { return false; }
                let half = base_elem.buf.len / 2;
                guard validate_cidr_mask(base_elem.buf[half..]) else { return false; }
            } else {
                st = SanType.Other;
            }

            // minimum MUST be zero, maximum MUST be absent (RFC 5280 §4.2.1.10)
            while cursor_len(subtree) > 0 {
                var opt_tag: u8 = 0;
                var opt_elem = cursor_from(subtree.buf[..0]);
                if !get_any_asn1_element(subtree, opt_tag, opt_elem) { return false; }
                let opt_num = opt_tag & 0x1F;
                if opt_num == 0 { // minimum
                    var min_val: i64 = 0;
                    if !get_asn1_integer(opt_elem, min_val) || min_val != 0 {
                        return false;
                    }
                } else if opt_num == 1 { // maximum
                    return false;
                }
            }

            if out_constraints.len < out_constraints.cap {
                out_constraints.push(NameConstraintEntry {
                    san_type: st,
                    is_excluded: is_excluded,
                    val: base_elem.buf,
                });
            }
            count++;
        }
    }
    return count > 0;
}

// Matches a single SAN against parsed Name Constraints.
fn check_name_constraints(
    constraints: const NameConstraintEntry[..16]&,
    san: const SanEntry&,
) -> bool {
    var has_permitted = false;
    var matched_permitted = false;

    for i in constraints.len {
        let nc = constraints[i];
        if nc.san_type != san.san_type {
            continue;
        }

        var matched = false;
        if nc.san_type == SanType.Dns {
            matched = match_dns_name_constraint(san.val, nc.val);
        } else if nc.san_type == SanType.Ip {
            matched = match_ip_name_constraint(san.val, nc.val);
        }

        if nc.is_excluded {
            if matched {
                return false; // Excluded subtree matched -> forbidden!
            }
        } else {
            has_permitted = true;
            if matched {
                matched_permitted = true;
            }
        }
    }

    if has_permitted && !matched_permitted {
        return false;
    }

    return true;
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

    // Cycle & loop detection: verify that no two certificates share the same subject DN or public key
    for j in chain_certs.len {
        let s_j = span_slice(raw_certs[j], chain_certs[j].subject_raw);
        let spki_j = span_slice(raw_certs[j], chain_certs[j].spki_raw);

        for k in chain_certs.len {
            if j < k {
                let s_k = span_slice(raw_certs[k], chain_certs[k].subject_raw);
                let spki_k = span_slice(raw_certs[k], chain_certs[k].spki_raw);
                if (s_j.len > 0 && s_j == s_k) || (spki_j.len > 0 && spki_j == spki_k) {
                    return TlsAlert.BadCertificate; // Loop or circular reference detected
                }
            }
        }
    }

    let is_direct_trust_anchor = (chain_certs.len == 1 && matches_trust_anchor(trust_store, chain_certs[0], raw_certs[0]));

    for i in chain_certs.len {
        let cert = chain_certs[i];

        // 0. Unrecognized critical extensions (RFC 5280 §4.2)
        if cert.has_unsupported_critical {
            return TlsAlert.UnsupportedExtension;
        }

        // 0b. Policy constraints syntax / bounds check (RFC 5280 §4.2.1.11, §4.2.1.14)
        if cert.has_malformed_policy_constraints {
            return TlsAlert.BadCertificate;
        }

        // 1. Validity period & inversion check
        let val_alert = validate_chain_cert_validity(cert, now_unix);
        guard val_alert == TlsAlert.CloseNotify else { return val_alert; }

        // 2. Forbidden certificate signature algorithms (RFC 8446 §4.4.2.3: no MD5 or SHA-1)
        let sig_oid = span_slice(raw_certs[i], cert.sig_alg_oid);
        if is_forbidden_cert_signature_algorithm(sig_oid) {
            return TlsAlert.UnsupportedCertificate;
        }

        // 3. End-entity vs Intermediate CA constraints
        if i == 0 && !is_direct_trust_anchor {
            let ee_alert = validate_end_entity_constraints(cert);
            guard ee_alert == TlsAlert.CloseNotify else { return ee_alert; }
        } else if i > 0 {
            let ca_alert = validate_intermediate_ca_constraints(cert, i);
            guard ca_alert == TlsAlert.CloseNotify else { return ca_alert; }
        }

        // 4. Issuer -> Next Subject linkage & AKID -> SKID matching (RFC 5280 §4.2.1.1 / §4.2.1.2)
        if i + 1 < chain_certs.len {
            let issuer_slice = span_slice(raw_certs[i], cert.issuer_raw);
            let next_subject_slice = span_slice(raw_certs[i + 1], chain_certs[i + 1].subject_raw);
            if issuer_slice != next_subject_slice {
                return TlsAlert.UnknownCa;
            }

            if cert.has_akid && chain_certs[i + 1].has_skid {
                let child_akid = span_slice(raw_certs[i], cert.akid_key_id);
                let parent_skid = span_slice(raw_certs[i + 1], chain_certs[i + 1].skid_key_id);
                if child_akid != parent_skid {
                    return TlsAlert.UnknownCa; // Key identifier mismatch
                }
            }
        }
    }

    // 5. Name Constraints enforcement down the chain (RFC 5280 §4.2.1.10)
    for k in chain_certs.len {
        if chain_certs[k].has_name_constraints {
            var nc_entries: NameConstraintEntry[..16] = [];
            let nc_bytes = span_slice(raw_certs[k], chain_certs[k].name_constraints_raw);
            if !parse_name_constraints(nc_bytes, nc_entries) {
                return TlsAlert.BadCertificate;
            }

            for j in k {
                if chain_certs[j].has_san {
                    var child_sans: SanEntry[..16] = [];
                    if get_cert_san_extension(chain_certs[j], raw_certs[j], child_sans) {
                        for s_idx in child_sans.len {
                            if !check_name_constraints(nc_entries, child_sans[s_idx]) {
                                return TlsAlert.BadCertificate; // Name constraint violation
                            }
                        }
                    }
                }
            }
        }
    }

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

// Parses an OCSPResponse (RFC 6960 §4.2.1) with zero dynamic allocation.
fn parse_ocsp_response(raw_ocsp: const u8[:], out: ParsedOcspResponse&) -> bool {
    var c = cursor_from(raw_ocsp);
    var ocsp_seq = cursor_from(raw_ocsp[..0]);
    if !get_asn1_element(c, ASN1_TAG_SEQUENCE, ocsp_seq) { return false; }
    guard cursor_len(c) == 0 else { return false; }

    // 1. responseStatus ENUMERATED (RFC 6960 §4.2.1)
    var status_oct = cursor_from(ocsp_seq.buf[..0]);
    if !get_asn1_element(ocsp_seq, ASN1_TAG_ENUMERATED, status_oct) { return false; }
    guard status_oct.buf.len == 1 else { return false; }
    let s_val = status_oct.buf[0];

    if s_val == 0 {
        out.status = OcspResponseStatus.Successful;
    } else if s_val == 1 {
        out.status = OcspResponseStatus.MalformedRequest;
        return true;
    } else if s_val == 2 {
        out.status = OcspResponseStatus.InternalError;
        return true;
    } else if s_val == 3 {
        out.status = OcspResponseStatus.TryLater;
        return true;
    } else if s_val == 5 {
        out.status = OcspResponseStatus.SigRequired;
        return true;
    } else if s_val == 6 {
        out.status = OcspResponseStatus.Unauthorized;
        return true;
    } else {
        out.status = OcspResponseStatus.Unknown;
        return false; // Out-of-bounds ENUMERATED value
    }

    // 2. responseBytes [0] EXPLICIT ResponseBytes OPTIONAL
    guard cursor_len(ocsp_seq) > 0 else { return false; }
    var resp_bytes_ctx = cursor_from(ocsp_seq.buf[..0]);
    if !get_asn1_element(ocsp_seq, 0xA0, resp_bytes_ctx) { return false; }

    var resp_bytes_seq = cursor_from(resp_bytes_ctx.buf[..0]);
    if !get_asn1_element(resp_bytes_ctx, ASN1_TAG_SEQUENCE, resp_bytes_seq) { return false; }

    var resp_type_oid = cursor_from(resp_bytes_seq.buf[..0]);
    if !get_asn1_element(resp_bytes_seq, ASN1_TAG_OID, resp_type_oid) { return false; }
    guard resp_type_oid.buf == OID_OCSP_BASIC[..] else { return false; }

    var resp_oct = cursor_from(resp_bytes_seq.buf[..0]);
    if !get_asn1_element(resp_bytes_seq, ASN1_TAG_OCTET_STRING, resp_oct) { return false; }

    // Inside response OCTET STRING is BasicOCSPResponse SEQUENCE
    var basic_seq = cursor_from(resp_oct.buf[..0]);
    if !get_asn1_element(resp_oct, ASN1_TAG_SEQUENCE, basic_seq) { return false; }

    // tbsResponseData ResponseData SEQUENCE
    var tbs_resp_data = cursor_from(basic_seq.buf[..0]);
    if !get_asn1_element(basic_seq, ASN1_TAG_SEQUENCE, tbs_resp_data) { return false; }

    // Skip optional version [0] if present
    if cursor_len(tbs_resp_data) > 0 && tbs_resp_data.buf[0] == 0xA0 {
        var ver_elem = cursor_from(tbs_resp_data.buf[..0]);
        get_asn1_element(tbs_resp_data, 0xA0, ver_elem);
    }

    // responderID (CHOICE of [1] byName or [2] byKey)
    var resp_id_tag: u8 = 0;
    var resp_id = cursor_from(tbs_resp_data.buf[..0]);
    if !get_any_asn1_element(tbs_resp_data, resp_id_tag, resp_id) { return false; }

    // producedAt GeneralizedTime
    var prod_time = cursor_from(tbs_resp_data.buf[..0]);
    if !get_asn1_element(tbs_resp_data, ASN1_TAG_GENERALIZED_TIME, prod_time) { return false; }

    // responses SEQUENCE OF SingleResponse
    var responses_seq = cursor_from(tbs_resp_data.buf[..0]);
    if !get_asn1_element(tbs_resp_data, ASN1_TAG_SEQUENCE, responses_seq) { return false; }
    guard cursor_len(responses_seq) > 0 else { return false; }

    // First SingleResponse
    var single_resp = cursor_from(responses_seq.buf[..0]);
    if !get_asn1_element(responses_seq, ASN1_TAG_SEQUENCE, single_resp) { return false; }

    // certID CertID SEQUENCE
    var cert_id_seq = cursor_from(single_resp.buf[..0]);
    if !get_asn1_element(single_resp, ASN1_TAG_SEQUENCE, cert_id_seq) { return false; }

    // hashAlgorithm
    var hash_alg = cursor_from(cert_id_seq.buf[..0]);
    if !get_asn1_element(cert_id_seq, ASN1_TAG_SEQUENCE, hash_alg) { return false; }
    // issuerNameHash
    var name_hash = cursor_from(cert_id_seq.buf[..0]);
    if !get_asn1_element(cert_id_seq, ASN1_TAG_OCTET_STRING, name_hash) { return false; }
    // issuerKeyHash
    var key_hash = cursor_from(cert_id_seq.buf[..0]);
    if !get_asn1_element(cert_id_seq, ASN1_TAG_OCTET_STRING, key_hash) { return false; }
    // serialNumber INTEGER
    var serial = cursor_from(cert_id_seq.buf[..0]);
    if !get_asn1_element(cert_id_seq, ASN1_TAG_INTEGER, serial) { return false; }
    if !validate_asn1_integer(serial.buf, true) { return false; }
    out.serial_number = make_span(raw_ocsp, serial.buf);

    // certStatus CertStatus CHOICE
    var cert_status_tag: u8 = 0;
    var cert_status_elem = cursor_from(single_resp.buf[..0]);
    if !get_any_asn1_element(single_resp, cert_status_tag, cert_status_elem) { return false; }
    let cs_num = cert_status_tag & 0x1F;
    if cs_num == 0 {
        out.cert_status = OcspCertStatus.Good;
    } else if cs_num == 1 {
        out.cert_status = OcspCertStatus.Revoked;
    } else if cs_num == 2 {
        out.cert_status = OcspCertStatus.Unknown;
    } else {
        return false;
    }

    // thisUpdate GeneralizedTime or UTCTime
    var this_up_tag: u8 = 0;
    var this_up_elem = cursor_from(single_resp.buf[..0]);
    if !get_any_asn1_element(single_resp, this_up_tag, this_up_elem) { return false; }
    let this_time, ok_this = parse_asn1_time(this_up_tag, this_up_elem.buf);
    guard ok_this else { return false; }
    out.this_update = this_time;

    // Optional nextUpdate [0] EXPLICIT
    if cursor_len(single_resp) > 0 && single_resp.buf[0] == 0xA0 {
        var next_up_ctx = cursor_from(single_resp.buf[..0]);
        if get_asn1_element(single_resp, 0xA0, next_up_ctx) {
            var next_up_tag: u8 = 0;
            var next_up_elem = cursor_from(next_up_ctx.buf[..0]);
            if get_any_asn1_element(next_up_ctx, next_up_tag, next_up_elem) {
                let next_time, ok_next = parse_asn1_time(next_up_tag, next_up_elem.buf);
                if ok_next {
                    out.next_update = next_time;
                    out.has_next_update = true;
                }
            }
        }
    }

    return true;
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

    // 1. Response status must be Successful (0)
    if resp.status != OcspResponseStatus.Successful {
        return TlsAlert.BadCertificateStatusResponse;
    }

    // 2. Cert status must be Good
    if resp.cert_status == OcspCertStatus.Revoked {
        return TlsAlert.BadCertificate; // Certificate revoked
    }
    if resp.cert_status != OcspCertStatus.Good {
        return TlsAlert.BadCertificateStatusResponse;
    }

    // 3. CertID Serial Number must match leaf certificate serial number
    let ocsp_serial = span_slice(raw_ocsp, resp.serial_number);
    let leaf_serial = span_slice(leaf_raw, leaf_cert.serial_number);
    if ocsp_serial.len == 0 || ocsp_serial != leaf_serial {
        return TlsAlert.BadCertificateStatusResponse;
    }

    // 4. Temporal inversion check: thisUpdate <= nextUpdate
    if resp.has_next_update && resp.this_update > resp.next_update {
        return TlsAlert.BadCertificateStatusResponse;
    }

    // 5. Expiration check: thisUpdate <= now <= nextUpdate
    if now_unix < resp.this_update {
        return TlsAlert.CertificateExpired; // Not yet valid
    }
    if resp.has_next_update && now_unix > resp.next_update {
        return TlsAlert.CertificateExpired; // Expired
    }

    return TlsAlert.CloseNotify;
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
