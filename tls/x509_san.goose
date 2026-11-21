// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// X.509 Subject Alternative Name (RFC 6125), Name Constraints (RFC 5280 §4.2.1.10),
// trust anchor matching, and certificate signature verification APIs.
namespace tls;

import std;
import core;
import .internal;
import .asn1;
import .record;
import .types;
import .pki_internal;

fn matches_trust_anchor(store: const TrustAnchorStore&, cert: const ParsedCert&, raw_cert: const u8[:]) -> bool {
    let s_slice = span_slice(raw_cert, cert.subject_raw);
    let spki_slice = span_slice(raw_cert, cert.spki_raw);
    let s_hash = core::sha256(s_slice);
    let spki_hash = core::sha256(spki_slice);

    for i in store.anchors.len {
        let a .= store.anchors[i];
        if a.is_valid && core::ct_eq_tag32(a.subject_dn_sha256, s_hash) && core::ct_eq_tag32(a.spki_sha256, spki_hash) {
            return true;
        }
    }
    return false;
}

// Matches a single DNS hostname against a SAN entry (RFC 6125 Section 6.4.3).
// - Wildcard '*' is only permitted in the leftmost label.
// - Must NOT match apex domain (e.g. *.example.com does not match example.com).
// - Must NOT match multi-level subdomains (e.g. *.example.com does not match a.b.example.com).
// - Case-insensitive comparison.
fn x509_strip_trailing_dot(s: const u8[:]) -> const u8[:] {
    if s.len > 1 && s[s.len - 1] == '.' {
        return s[..^1];
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
    return is_ip && host.contains_byte('.');
}

fn x509_match_wildcard_san(pat: const u8[:], host: const u8[:]) -> bool {
    guard pat.len >= 3 && pat[0] == '*' && pat[1] == '.' else { return false; }
    let suffix = pat[2..];
    guard !suffix.contains_byte('*') && suffix.contains_byte('.') else { return false; }
    guard !x509_is_ip_literal(host) else { return false; }

    let dot_idx = host.index_of_byte('.');
    guard dot_idx > 0 else { return false; }
    let host_remainder = host[dot_idx + 1..];
    return host_remainder.eq_ascii_fold(suffix);
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
    guard !san_pattern.contains_byte(0) && !host.contains_byte(0) else { return false; }

    let pat = x509_strip_trailing_dot(san_pattern);
    let h = x509_strip_trailing_dot(host);
    guard pat.len > 0 && h.len > 0 else { return false; }
    guard !x509_is_ip_literal(h) && !h.contains_byte(':') else { return false; }

    if pat.eq_ascii_fold(h) {
        return true;
    }

    return x509_match_wildcard_san(pat, h);
}

// Matches URI SAN and enforces RFC 5280 / CVE-2024-45341 / CVE-2021-3712 defense:
// - IPv6 zone IDs (%zone) inside URIs MUST NOT bypass URI name constraints and must be rejected.
// - Embedded NUL bytes MUST be rejected.
fn match_uri_san(san_uri_host: const u8[:], request_host: const u8[:]) -> bool {
    if san_uri_host.contains_byte('%') || request_host.contains_byte('%') {
        return false;
    }
    if san_uri_host.contains_byte(0) || request_host.contains_byte(0) {
        return false;
    }
    return san_uri_host.eq_ascii_fold(request_host);
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
            guard tls_internal::x509_validate_dns_label(label, label_idx) else { return false; }
            label_start = i + 1;
            label_idx++;
        }
    }
    return true;
}

inline fn x509_classify_san_element(tag_num: u8, elem_buf: const u8[:], out_type: SanType&) -> bool {
    if tag_num == 1 { // rfc822Name [1] IA5String
        guard elem_buf.len > 0 && !elem_buf.contains_byte(0) else { return false; }
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
        guard elem_buf.len > 0 && tls_internal::x509_has_valid_uri_scheme(elem_buf) else { return false; }
        guard !elem_buf.contains_byte('%') && !elem_buf.contains_byte(0) else { return false; }
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
fn x509_parse_single_san<S>(names_seq: core::ByteCursor&, out_sans: S&) -> bool {
    var tag: u8 = 0;
    var elem = core::cursor_from(names_seq.buf[..0]);
    guard get_any_asn1_element(names_seq, tag, elem) else { return false; }

    let tag_num = tag & 0x1F;
    var st = SanType.Other;
    guard x509_classify_san_element(tag_num, elem.buf, st) else { return false; }

    return out_sans.try_push(SanEntry {
        san_type: st,
        val:      elem.buf,
    });
}

// RFC 5280 Section 4.2.1.6: Subject Alternative Name - Parses GeneralNames with transactional rollback.
//
// Example:
//   san_der = 0x30 0x0E 0x82 0x0C "example.com"
//   returns: ok = true, out_sans contains SanType.Dns "example.com"
fn parse_san_extension<S>(san_der: const u8[:], out_sans: S&) -> bool {
    var committed = false;
    defer if !committed { out_sans.clear(); };

    var c = core::cursor_from(san_der);
    var names_seq = core::cursor_from(san_der[..0]);
    if !get_asn1_element(c, rfc::ASN1_TAG_SEQUENCE, names_seq) { return false; }
    guard c.cursor_len() == 0 else { return false; }
    guard names_seq.cursor_len() > 0 else { return false; }
    out_sans.clear();

    var count: i64 = 0;
    while names_seq.cursor_len() > 0 {
        guard x509_parse_single_san(names_seq, out_sans) else { return false; }
        count++;
    }
    guard count > 0 else { return false; }
    committed = true;
    return true;
}

// Matches an IP SAN (binary 4 or 16 octets) against a target IP host (either text IPv4/IPv6 or raw binary).
fn match_ip_san(san_ip: const u8[:], host: const u8[:]) -> bool {
    guard san_ip.len == 4 || san_ip.len == 16 else { return false; }
    if tls_internal::match_ip_san_text(san_ip, host) {
        return true;
    }
    return host.len == san_ip.len && host == san_ip;
}

// Matches any single SAN entry against target hostname or IP address.
fn match_san(san: const SanEntry&, host: const u8[:]) -> bool {
    if san.san_type == SanType.Dns {
        return match_dns_san(san.val, host);
    } else if san.san_type == SanType.Ip {
        return tls_internal::match_ip_san_text(san.val, host);
    } else if san.san_type == SanType.Uri {
        return host.contains_byte(':') && tls_internal::x509_has_valid_uri_scheme(host) && match_uri_san(san.val, host);
    }
    return false;
}

// Matches target host against an array of parsed SAN entries.
fn match_any_san<S>(sans: const S&, host: const u8[:]) -> bool {
    for i in sans.len {
        if match_san(sans[i], host) {
            return true;
        }
    }
    return false;
}

// Helper to extract and parse SAN entries from a ParsedCert descriptor.
fn get_cert_san_extension<S>(cert: const ParsedCert&, raw_cert: const u8[:], out_sans: S&) -> bool {
    guard cert.has_san else { return false; }
    let san_bytes = span_slice(raw_cert, cert.san_raw);
    return parse_san_extension(san_bytes, out_sans);
}

// Validates that an IPv4 (4-byte) or IPv6 (16-byte) subnet mask is contiguous CIDR.
// In network byte order, once a 0 bit appears, no 1 bit may follow.
fn validate_cidr_mask(mask: const u8[:]) -> bool {
    guard mask.len == 4 || mask.len == 16 else { return false; }
    var seen_zero_bit = false;
    for b in mask {
        guard tls_internal::x509_check_mask_byte(b, seen_zero_bit) else { return false; }
    }
    return true;
}

// RFC 5280 §4.2.1.10: DNS name constraint matching
// DNS name restrictions may be indicated as "example.com" or ".example.com".
// Normalizes trailing dots in candidate and constraint to prevent ExcludedSubtree bypass.
// Rejects embedded NUL bytes (CVE-2021-3712 / OpenSSL #31686).
fn match_dns_name_constraint(candidate_dns: const u8[:], constraint: const u8[:]) -> bool {
    guard candidate_dns.len > 0 && constraint.len > 0 else { return false; }
    guard !constraint.contains_byte(0) else { return false; }

    let cand = x509_strip_trailing_dot(candidate_dns);
    let cons = x509_strip_trailing_dot(constraint);
    guard tls_internal::x509_validate_dns_candidate(cand) else { return false; }
    guard cons.len > 0 && find(cons, "..") < 0 else { return false; }

    if cons[0] == '.' {
        return tls_internal::x509_match_dns_dotted_constraint(cand, cons);
    }
    if cand.eq_ascii_fold(cons) {
        return true;
    }
    return tls_internal::x509_match_dns_subdomain(cand, cons);
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

// RFC 5280 §4.2.1.10 & OpenSSL #31392 / CVE-2024-45341 / Go #71208: URI name constraint matching
// Extracts the host component from candidate URI and matches it against the constraint.
// Rejects candidate URIs with userinfo, path/query @ smuggling, or IPv4 literals for dNSName constraints.
fn match_uri_name_constraint(candidate_uri: const u8[:], constraint: const u8[:]) -> bool {
    guard candidate_uri.len > 0 && constraint.len > 0 else { return false; }
    guard !candidate_uri.contains_byte(0) && !constraint.contains_byte(0) else { return false; }

    var host_part = tls_internal::x509_extract_uri_authority(candidate_uri);
    guard host_part.len > 0 else { return false; }

    // RFC 5280 §4.2.1.10: URI authority cannot contain userinfo (@) to satisfy DNS name constraint
    guard !host_part.contains_byte('@') else { return false; }

    if host_part[0] == '[' {
        return tls_internal::x509_match_ipv6_uri_constraint(host_part, constraint);
    }

    let colon_idx = host_part.index_of_byte(':');
    if colon_idx >= 0 {
        host_part = host_part[..colon_idx];
    }

    guard host_part.len > 0 else { return false; }
    guard !tls_internal::x509_is_ipv4_literal(host_part) else { return false; }

    return match_dns_name_constraint(host_part, constraint);
}

// RFC 5280 §4.2.1.10: rfc822Name (email) name constraint matching.
// - With `@`: local-part matches case-sensitively and host matches case-insensitively.
// - Leading `.`: candidate host after `@` ends with `constraint` case-insensitively.
// - Otherwise: candidate host after `@` matches `constraint` case-insensitively.
fn match_email_name_constraint(candidate_email: const u8[:], constraint: const u8[:]) -> bool {
    guard candidate_email.len > 0 && constraint.len > 0 else { return false; }
    guard !candidate_email.contains_byte(0) && !constraint.contains_byte(0) else { return false; }

    let cand_local, cand_host, has_cand_at = candidate_email.split_once_byte('@');
    guard has_cand_at && cand_local.len > 0 && cand_host.len > 0 else { return false; }
    guard !cand_host.contains_byte('@') else { return false; }

    let cons_local, cons_host, has_cons_at = constraint.split_once_byte('@');
    if has_cons_at {
        guard cons_local.len > 0 && cons_host.len > 0 else { return false; }
        return cand_local == cons_local && cand_host.eq_ascii_fold(cons_host);
    }

    if core::starts_with(constraint, ".") {
        return tls_internal::x509_match_dns_dotted_constraint(cand_host, constraint);
    }
    return cand_host.eq_ascii_fold(constraint);
}

// Parses NameConstraints extension (RFC 5280 §4.2.1.10) into bounded stack storage.
// Enforces that empty NameConstraints, non-contiguous masks, non-zero minimums, or present maximums are rejected.
// Example:
//   nc_der = 0x30 ... (DER encoded NameConstraints sequence)
//   returns: ok = true, out_constraints filled with permitted/excluded subtrees
fn parse_name_constraints(nc_der: const u8[:], out_constraints: NameConstraintEntry[..16]&) -> bool {
    var committed = false;
    defer if !committed { out_constraints.clear(); };
    var c = core::cursor_from(nc_der);
    var nc_seq = core::cursor_from(nc_der[..0]);
    if !get_asn1_element(c, rfc::ASN1_TAG_SEQUENCE, nc_seq) { return false; }
    guard c.cursor_len() == 0 && nc_seq.cursor_len() > 0 else { return false; }
    out_constraints.clear();

    var count: i64 = 0;
    var seen_permitted = false;
    var seen_excluded = false;
    while nc_seq.cursor_len() > 0 {
        var tag: u8 = 0;
        var subtrees_elem = core::cursor_from(nc_seq.buf[..0]);
        if !get_any_asn1_element(nc_seq, tag, subtrees_elem) { return false; }

        let is_excluded = (tag == 0xA1);
        let is_permitted = (tag == 0xA0);
        guard (is_permitted && !seen_permitted && !seen_excluded) ||
            (is_excluded && !seen_excluded) else { return false; }
        if is_permitted { seen_permitted = true; }
        if is_excluded { seen_excluded = true; }

        guard tls_internal::x509_parse_subtrees_sequence(
            nc_der, subtrees_elem, is_excluded, out_constraints, count,
        ) else { return false; }
    }
    guard count > 0 else { return false; }
    committed = true;
    return true;
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

fn x509_verify_cert_signature(
    child_cert:  const ParsedCert&,
    child_raw:   const u8[:],
    parent_cert: const ParsedCert&,
    parent_raw:  const u8[:],
) -> Alert {
    guard child_cert.signature_value.length > 0 && child_cert.tbs_cert.length > 0 else {
        return Alert.BadCertificate;
    }

    let sig_oid = span_slice(child_raw, child_cert.sig_alg_oid);
    let tbs_data = span_slice(child_raw, child_cert.tbs_cert);
    let sig_bytes = span_slice(child_raw, child_cert.signature_value);
    var parent_pubkey = span_slice(parent_raw, parent_cert.spki_pubkey);

    if parent_pubkey.len >= 2 && parent_pubkey[0] == 0 {
        parent_pubkey = parent_pubkey[1..];
    }

    return tls_internal::x509_verify_signature_by_oid(
        sig_oid, tbs_data, sig_bytes, parent_pubkey, Alert.BadCertificate,
    );
}
