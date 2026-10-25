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

// Key Usage bitmasks (byte 1)
const KEY_USAGE_DIGITAL_SIGNATURE: u16 = 0x8000;
const KEY_USAGE_KEY_ENCIPHERMENT: u16 = 0x2000;
const KEY_USAGE_KEY_CERT_SIGN: u16 = 0x0400;
const KEY_USAGE_CRL_SIGN: u16 = 0x0200;

// SignatureScheme identifiers (RFC 8446 Section 4.2.3)
const SIG_SCHEME_RSA_PKCS1_SHA256: u16 = 0x0401; // Forbidden in TLS 1.3 CV
const SIG_SCHEME_ECDSA_SECP256R1_SHA256: u16 = 0x0403;
const SIG_SCHEME_RSA_PKCS1_SHA384: u16 = 0x0501; // Forbidden in TLS 1.3 CV
const SIG_SCHEME_ECDSA_SECP384R1_SHA384: u16 = 0x0503;
const SIG_SCHEME_RSA_PSS_RSAE_SHA256: u16 = 0x0804;
const SIG_SCHEME_RSA_PSS_RSAE_SHA384: u16 = 0x0805;
const SIG_SCHEME_ED25519: u16 = 0x0807;

// ---- 2. Strict Canonical ASN.1 DER Parser -----------------------------------

// Parses ASN.1 length field with canonical DER rules (X.690 Section 10.1):
// - Short form: 0..127 (1 byte)
// - Long form: byte 0 has bit 8 set, remaining 7 bits is length of length (1..4)
// - Long form with length < 128 is strictly FORBIDDEN (non-minimal shortest form rule).
// - BER indefinite length (0x80) is strictly FORBIDDEN.
// - Redundant leading zeros in long form (e.g. 0x82 0x00 0x80) are strictly FORBIDDEN.
fn get_asn1_length(c: ByteCursor&, out_len: i64&) -> bool {
    var b0: u8 = 0;
    if !get_u8(c, b0) { return false; }

    if (b0 & 0x80) == 0 {
        out_len = b0;
        return true;
    }

    // Reject BER indefinite form (0x80)
    if b0 == 0x80 { return false; }

    let num_bytes = (b0 & 0x7F);
    // Maximum supported length is 4 bytes (up to 4GB)
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
// - Length must be >= 1.
// - No redundant leading zero padding (if first byte is 0x00 and len > 1, next byte must have bit 7 set).
// - No redundant negative sign extension (if first byte is 0xFF and len > 1, next byte must have bit 7 clear).
// - For X.509 serial numbers: must be non-negative (first byte bit 7 must be 0 unless prefixed by 0x00).
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
        // Serial numbers in RFC 5280 MUST be positive
        if (val[0] & 0x80) != 0 { return false; }
    }
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

// Parses UTCTime ("YYMMDDHHMMSSZ") or GeneralizedTime ("YYYYMMDDHHMMSSZ") to Unix timestamp seconds.
fn parse_asn1_time(time_tag: u8, time_bytes: const u8[:]) -> i64, bool {
    var year: i64 = 0;
    var off: i64 = 0;

    if time_tag == ASN1_TAG_UTC_TIME {
        guard time_bytes.len == 13 && time_bytes[12] == 'Z' else { return 0, false; }
        let y2, ok_y = parse_2digit(time_bytes, 0);
        guard ok_y else { return 0, false; }
        // RFC 5280 Section 4.1.2.5.1: YY >= 50 -> 19YY, YY < 50 -> 20YY
        year = if y2 >= 50 { 1900 + y2 } else { 2000 + y2 };
        off = 2;
    } else if time_tag == ASN1_TAG_GENERALIZED_TIME {
        guard time_bytes.len == 15 && time_bytes[14] == 'Z' else { return 0, false; }
        let y1, ok_y1 = parse_2digit(time_bytes, 0);
        let y2, ok_y2 = parse_2digit(time_bytes, 2);
        guard ok_y1 && ok_y2 else { return 0, false; }
        year = y1 * 100 + y2;
        off = 4;
    } else {
        return 0, false;
    }

    let month, ok_m = parse_2digit(time_bytes, off);
    let day, ok_d = parse_2digit(time_bytes, off + 2);
    let hour, ok_h = parse_2digit(time_bytes, off + 4);
    let min, ok_min = parse_2digit(time_bytes, off + 6);
    let sec, ok_s = parse_2digit(time_bytes, off + 8);

    guard ok_m && ok_d && ok_h && ok_min && ok_s else { return 0, false; }
    guard month >= 1 && month <= 12 && day >= 1 && day <= 31 else { return 0, false; }
    guard hour <= 23 && min <= 59 && sec <= 59 else { return 0, false; }

    let days = core::civil_to_days(year, month, day);
    let total_secs = days * 86400 + hour * 3600 + min * 60 + sec;
    return total_secs, true;
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
    is_ca: bool = false,
    has_basic_constraints: bool = false,
    path_len_constraint: i32 = -1,
    key_usage: u16 = 0,
    has_key_usage: bool = false,
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

    // 1. Version [0] EXPLICIT INTEGER OPTIONAL
    var maybe_version = cursor_from(raw_cert[..0]);
    var tag: u8 = 0;
    if cert_seq.buf.len > 0 && cert_seq.buf[0] == 0xA0 {
        if !get_any_asn1_element(tbs_seq, tag, maybe_version) { return false; }
    }

    // 2. SerialNumber INTEGER
    var serial = cursor_from(raw_cert[..0]);
    if !get_asn1_element(tbs_seq, ASN1_TAG_INTEGER, serial) { return false; }
    if !validate_asn1_integer(serial.buf, true) { return false; }
    out.serial_number = make_span(raw_cert, serial.buf);

    // 3. Signature AlgorithmIdentifier SEQUENCE
    var sig_alg = cursor_from(raw_cert[..0]);
    if !get_asn1_element(tbs_seq, ASN1_TAG_SEQUENCE, sig_alg) { return false; }
    var sig_oid = cursor_from(raw_cert[..0]);
    if !get_asn1_element(sig_alg, ASN1_TAG_OID, sig_oid) { return false; }
    out.sig_alg_oid = make_span(raw_cert, sig_oid.buf);

    // 4. Issuer Name (SEQUENCE of SETs)
    var issuer = cursor_from(raw_cert[..0]);
    if !get_asn1_element(tbs_seq, ASN1_TAG_SEQUENCE, issuer) { return false; }
    out.issuer_raw = make_span(raw_cert, issuer.buf);

    // 5. Validity SEQUENCE { notBefore, notAfter }
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

    // 6. Subject Name (SEQUENCE of SETs)
    var subject = cursor_from(raw_cert[..0]);
    if !get_asn1_element(tbs_seq, ASN1_TAG_SEQUENCE, subject) { return false; }
    out.subject_raw = make_span(raw_cert, subject.buf);

    // 7. SubjectPublicKeyInfo SEQUENCE
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
    out.spki_pubkey = make_span(raw_cert, spki_pubkey.buf);

    // 8. Optional Extensions [3] EXPLICIT SEQUENCE OF Extension
    while cursor_len(tbs_seq) > 0 {
        var ext_container = cursor_from(raw_cert[..0]);
        var ext_tag: u8 = 0;
        if !get_any_asn1_element(tbs_seq, ext_tag, ext_container) { break; }
        if ext_tag == 0xA3 { // [3] EXPLICIT
            var ext_seq = cursor_from(raw_cert[..0]);
            if get_asn1_element(ext_container, ASN1_TAG_SEQUENCE, ext_seq) {
                out.extensions_raw = make_span(raw_cert, ext_seq.buf);
                parse_cert_extensions(ext_seq, out);
            }
        }
    }

    return true;
}

// Parses X.509 extensions for BasicConstraints and KeyUsage.
fn parse_cert_extensions(ext_seq: ByteCursor&, cert: ParsedCert&) {
    while cursor_len(ext_seq) > 0 {
        var single_ext = cursor_from(ext_seq.buf[..0]);
        if !get_asn1_element(ext_seq, ASN1_TAG_SEQUENCE, single_ext) { break; }

        var oid = cursor_from(ext_seq.buf[..0]);
        if !get_asn1_element(single_ext, ASN1_TAG_OID, oid) { continue; }

        var maybe_critical = cursor_from(ext_seq.buf[..0]);
        if single_ext.buf.len > 0 && single_ext.buf[0] == ASN1_TAG_BOOLEAN {
            get_asn1_element(single_ext, ASN1_TAG_BOOLEAN, maybe_critical);
        }

        var ext_val = cursor_from(ext_seq.buf[..0]);
        if !get_asn1_element(single_ext, ASN1_TAG_OCTET_STRING, ext_val) { continue; }

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
                    var path_len = cursor_from(ext_val.buf[..0]);
                    if get_asn1_element(bc_seq, ASN1_TAG_INTEGER, path_len) {
                        if path_len.buf.len == 1 {
                            cert.path_len_constraint = path_len.buf[0];
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
                if ku_bits.buf.len >= 2 {
                    // First byte is unused bits, second byte is bits 0..7
                    cert.key_usage = (ku_bits.buf[1] as u16) << 8;
                }
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

// RFC 5280 Certificate Chain Validation.
// Returns TlsAlert.CloseNotify (0) on success, or appropriate fatal alert.
fn verify_certificate_chain(
    chain_certs: const ParsedCert[..8]&,
    raw_certs: const u8[:][..8]&,
    trust_store: const TrustAnchorStore&,
    now_unix: i64
) -> TlsAlert {
    guard chain_certs.len > 0 else { return TlsAlert.BadCertificate; }

    for i in chain_certs.len {
        let cert = chain_certs[i];
        // 1. Validity period check
        if now_unix < cert.validity_not_before || now_unix > cert.validity_not_after {
            return TlsAlert.CertificateExpired;
        }

        // 2. Intermediate CA constraints
        if i > 0 {
            if !cert.is_ca {
                return TlsAlert.BadCertificate;
            }
            if cert.has_key_usage && (cert.key_usage & KEY_USAGE_KEY_CERT_SIGN) == 0 {
                return TlsAlert.UnsupportedCertificate;
            }
            if cert.path_len_constraint >= 0 && (i - 1) > cert.path_len_constraint {
                return TlsAlert.BadCertificate;
            }
        }

        // 3. Chaining check: cert[i].issuer must match cert[i+1].subject
        if i + 1 < chain_certs.len {
            let issuer_slice = span_slice(raw_certs[i], cert.issuer_raw);
            let next_subject_slice = span_slice(raw_certs[i + 1], chain_certs[i + 1].subject_raw);
            if issuer_slice != next_subject_slice {
                return TlsAlert.UnknownCa;
            }
        }
    }

    // 4. Root anchor check: top of chain must match trusted anchor
    let top_idx = chain_certs.len - 1;
    if !matches_trust_anchor(trust_store, chain_certs[top_idx], raw_certs[top_idx]) {
        return TlsAlert.UnknownCa;
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

// ---- 7. RFC 8446 Section 4.4.3 CertificateVerify Format & Curve Binding -----

// Verifies that signature scheme is strictly bound to the public key curve/algorithm.
// Enforces that legacy PKCS#1 v1.5 RSA schemes are rejected in TLS 1.3.
fn verify_signature_scheme_curve_binding(
    sig_scheme: u16,
    spki_oid: const u8[:]
) -> bool {
    if sig_scheme == SIG_SCHEME_ECDSA_SECP256R1_SHA256 {
        return spki_oid == OID_SECP256R1[..] || spki_oid == OID_EC_PUBLIC_KEY[..];
    } else if sig_scheme == SIG_SCHEME_ECDSA_SECP384R1_SHA384 {
        return spki_oid == OID_SECP384R1[..] || spki_oid == OID_EC_PUBLIC_KEY[..];
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
    out: u8[:]
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
