// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal X.509 Subject Alternative Name and Name Constraints parsing and matching helpers.
namespace tls_internal;

import std;
import core;
import .internal;
import .asn1;
import .record;
import .types;
import .pki_ocsp_internal;

enum NcMatchResult {
    Match,
    NoMatch,
    Invalid,
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
        octet_idx = core::add_sat_i64(octet_idx, 1);
        current = 0;
        digits = 0;
        return true;
    }
    guard core::is_ascii_digit(b) else { return false; }
    // RFC 3986 Section 3.2.2: Reject leading-zero decimal octets (e.g. "010.0.0.1") to prevent octal ambiguity.
    guard !(digits == 1 && current == 0) else { return false; }
    let digit = core::sub_sat_u64(b, '0');
    current = core::add_sat_u64(core::mul_sat_u64(current, 10), digit) as u32;
    digits = core::add_sat_i64(digits, 1);
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
    let is_alnum = core::is_ascii_alphanumeric(b);
    return is_alnum || b == '-';
}

fn x509_validate_dns_label(label: const u8[:], label_idx: i64) -> bool {
    guard label.len >= 1 && label.len <= 63 else { return false; }
    if label_idx == 0 && label.len == 1 && label[0] == '*' {
        return true;
    }
    let last_idx = core::sub_sat_i64(label.len, 1);
    guard label[0] != '-' && label[last_idx] != '-' else { return false; }
    for b in label {
        guard x509_is_dns_label_char(b) else { return false; }
    }
    return true;
}

inline fn x509_has_valid_uri_scheme(uri: const u8[:]) -> bool {
    let colon_idx = uri.index_of_byte(':');
    guard colon_idx > 0 else { return false; }
    let first = uri[0];
    guard core::is_ascii_alpha(first) else { return false; }
    for i in colon_idx {
        let b = uri[i];
        guard x509_is_dns_label_char(b) || b == '+' || b == '.' else { return false; }
    }
    // Reject unbracketed IPv6 literals (e.g. "fd00::1", "fe80::1") masquerading as URI schemes (PKI-03).
    let _, is_v6 = core::parse_ipv6_octets(uri);
    guard !is_v6 else { return false; }
    return true;
}

fn match_ip_san_text(san_ip: const u8[:], host: const u8[:]) -> bool {
    guard (san_ip.len == 4 || san_ip.len == 16) && host.len > 0 else { return false; }
    guard !host.contains_byte('%') && !host.contains_byte(0) else { return false; }
    if san_ip.len == 4 {
        var host_ip: u8[4] = [0; 4];
        return parse_ipv4_literal(host, host_ip) && san_ip == host_ip[..];
    }
    var h6 = host;
    let no_l, has_l = h6.strip_prefix("[");
    if has_l {
        let inner, has_r = no_l.strip_suffix("]");
        guard has_r else { return false; }
        h6 = inner;
    }
    let ip6_octets, ok_v6 = core::parse_ipv6_octets(h6);
    return ok_v6 && san_ip == ip6_octets[..];
}

// Validates that an IPv4 (4-byte) or IPv6 (16-byte) subnet mask is contiguous CIDR.
// In network byte order, once a 0 bit appears, no 1 bit may follow.
inline fn x509_check_mask_byte(b: u8, seen_zero_bit: bool&) -> bool {
    for bit_idx in 8 {
        let shift = core::sub_sat_u64(7, bit_idx as u64) as u32;
        let bit = ((b as u32) >> shift) & 1;
        if bit == 0 {
            seen_zero_bit = true;
        } else if seen_zero_bit {
            return false;
        }
    }
    return true;
}

inline fn x509_validate_dns_candidate(cand: const u8[:]) -> bool {
    guard cand.len > 0 else { return false; }
    guard cand[0] != '.' else { return false; }
    guard !cand.contains_byte(0) else { return false; }
    return find(cand, "..") < 0;
}

inline fn x509_match_dns_dotted_constraint(cand: const u8[:], cons: const u8[:]) -> bool {
    guard cons.len > 1 else { return false; }
    guard cand.len > cons.len else { return false; }
    return cand.ends_with_fold(cons);
}

fn x509_match_dns_subdomain(cand: const u8[:], cons: const u8[:]) -> bool {
    guard cons.len > 0 else { return false; }
    guard cand.len > cons.len else { return false; }
    guard cand.ends_with_fold(cons) else { return false; }
    let idx = core::sub_sat_i64(core::sub_sat_i64(cand.len, cons.len), 1);
    return cand[idx] == '.';
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
        let after_scheme = core::add_sat_i64(scheme_end, 3);
        guard after_scheme <= s.len else { return s[..0]; }
        s = s[after_scheme..];
    }

    let delim_idx = core::find_byteset(s, "/?#");
    let auth_end = if delim_idx >= 0 { delim_idx } else { s.len };
    return s[..auth_end];
}

fn x509_match_ipv6_uri_constraint_3state(host_part: const u8[:], constraint: const u8[:]) -> NcMatchResult {
    let close_bracket = host_part.index_of_byte(']');
    guard close_bracket > 1 else { return NcMatchResult.Invalid; }
    let after_bracket = core::add_sat_i64(close_bracket, 1);
    if after_bracket < host_part.len {
        guard host_part[after_bracket] == ':' else { return NcMatchResult.Invalid; }
    }
    var inner_ip = host_part[1..close_bracket];
    let pct_idx = inner_ip.index_of_byte('%');
    if pct_idx >= 0 {
        guard pct_idx > 0 && core::add_sat_i64(pct_idx, 1) < inner_ip.len else {
            return NcMatchResult.Invalid;
        }
        inner_ip = inner_ip[..pct_idx];
    }
    let cand_v6, ok_cand = core::parse_ipv6_octets(inner_ip);
    guard ok_cand else { return NcMatchResult.Invalid; }

    var cons_cmp = constraint;
    if cons_cmp.len > 2 {
        let last_idx = core::sub_sat_i64(cons_cmp.len, 1);
        if cons_cmp[0] == '[' && cons_cmp[last_idx] == ']' {
            cons_cmp = cons_cmp[1..^1];
        }
    }
    let cons_v6, ok_cons = core::parse_ipv6_octets(cons_cmp);
    guard ok_cons else { return NcMatchResult.NoMatch; }
    return if cand_v6[..] == cons_v6[..] { NcMatchResult.Match } else { NcMatchResult.NoMatch };
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

inline fn x509_validate_subtree_ip(buf: const u8[:]) -> bool {
    guard buf.len == 8 || buf.len == 32 else { return false; }
    let half: i64 = if buf.len == 8 { 4 } else { 16 };
    return tls::validate_cidr_mask(buf[half..]);
}

inline fn x509_validate_subtree_nonempty_text(buf: const u8[:], forbid_leading_dot: bool) -> bool {
    guard buf.len > 0 && !buf.contains_byte(0) else { return false; }
    return !forbid_leading_dot || buf[0] != '.';
}

fn x509_parse_general_subtree_base(
    subtree:  core::ByteCursor&,
    out_type: tls::SanType&,
    out_val:  core::ByteCursor&,
) -> bool {
    var base_tag: u8 = 0;
    if !tls::get_any_asn1_element(subtree, base_tag, out_val) { return false; }
    // RFC 5280 Section 4.2.1.6: GeneralName - Exact context-specific class and primitive/constructed tags.
    if base_tag == 0x81 { // rfc822Name [1] IMPLICIT IA5String
        out_type = tls::SanType.Email;
        return x509_validate_subtree_nonempty_text(out_val.buf, false);
    }
    if base_tag == 0x82 { // dNSName [2] IMPLICIT IA5String
        out_type = tls::SanType.Dns;
        // RFC 5280 Section 4.2.1.10: Name Constraints - dNSName base MUST NOT start with a leading period.
        return x509_validate_subtree_nonempty_text(out_val.buf, true);
    }
    if base_tag == 0x87 { // iPAddress [7] IMPLICIT OCTET STRING
        out_type = tls::SanType.Ip;
        return x509_validate_subtree_ip(out_val.buf);
    }
    if base_tag == 0xA4 { // directoryName [4] EXPLICIT Name
        out_type = tls::SanType.DirName;
        return out_val.buf.len > 0;
    }
    if base_tag == 0x86 { // uniformResourceIdentifier [6] IMPLICIT IA5String
        out_type = tls::SanType.Uri;
        return x509_validate_subtree_nonempty_text(out_val.buf, false);
    }
    guard base_tag == 0xA0 || base_tag == 0xA3 || base_tag == 0xA5 || base_tag == 0x88 else {
        return false;
    }
    out_type = tls::SanType.Other;
    return true;
}

inline fn x509_parse_general_subtree_bounds(subtree: core::ByteCursor&) -> bool {
    // RFC 5280 Section 4.2.1.10: GeneralSubtree minimum [0] IMPLICIT BaseDistance MUST be 0 (or omitted);
    // maximum [1] is forbidden and repeated minimum fields are malformed.
    var seen_min = false;
    while subtree.cursor_len() > 0 {
        var opt_tag: u8 = 0;
        var opt_elem = core::cursor_from(subtree.buf[..0]);
        if !tls::get_any_asn1_element(subtree, opt_tag, opt_elem) { return false; }
        guard opt_tag == 0x80 && !seen_min && opt_elem.buf.len == 1 && opt_elem.buf[0] == 0x00 else {
            return false;
        }
        seen_min = true;
    }
    return true;
}

fn x509_parse_general_subtree(
    nc_der:          const u8[:],
    subtree:         core::ByteCursor&,
    is_excluded:     bool,
    out_constraints: tls::NameConstraintEntry[..16]&,
) -> bool {
    var st = tls::SanType.Other;
    var base_elem = core::cursor_from(nc_der[..0]);
    guard x509_parse_general_subtree_base(subtree, st, base_elem) else { return false; }
    guard x509_parse_general_subtree_bounds(subtree) else { return false; }

    return out_constraints.try_push(tls::NameConstraintEntry {
        san_type:    st,
        is_excluded: is_excluded,
        val:         base_elem.buf,
    });
}

fn x509_parse_subtrees_sequence(
    nc_der:          const u8[:],
    subtrees_elem:   core::ByteCursor&,
    is_excluded:     bool,
    out_constraints: tls::NameConstraintEntry[..16]&,
    count:           i64&,
) -> bool {
    var subtrees_seq = subtrees_elem;
    if subtrees_elem.cursor_len() > 0 && subtrees_elem.buf[0] == rfc::ASN1_TAG_SEQUENCE {
        var probe = subtrees_elem;
        var inner = core::cursor_from(subtrees_elem.buf[..0]);
        if tls::get_asn1_element(probe, rfc::ASN1_TAG_SEQUENCE, inner) &&
            probe.cursor_len() == 0 &&
            inner.cursor_len() > 0 &&
            inner.buf[0] == rfc::ASN1_TAG_SEQUENCE {
            subtrees_seq = inner;
        }
    }
    guard subtrees_seq.cursor_len() > 0 else { return false; }

    while subtrees_seq.cursor_len() > 0 {
        var subtree = core::cursor_from(subtrees_seq.buf[..0]);
        if !tls::get_asn1_element(subtrees_seq, rfc::ASN1_TAG_SEQUENCE, subtree) { return false; }
        guard x509_parse_general_subtree(nc_der, subtree, is_excluded, out_constraints) else { return false; }
        count = core::add_sat_i64(count, 1);
    }
    return true;
}

inline fn x509_validate_san_uri(elem_buf: const u8[:]) -> bool {
    guard elem_buf.len > 0 && x509_has_valid_uri_scheme(elem_buf) else { return false; }
    guard !elem_buf.contains_byte('%') && !elem_buf.contains_byte(0) else { return false; }
    return core::find(elem_buf, "://") > 0;
}

inline fn x509_classify_san_element(tag: u8, elem_buf: const u8[:], out_type: tls::SanType&) -> bool {
    // RFC 5280 Section 4.2.1.6: GeneralName - Match exact context-specific tag and primitive/constructed bit.
    if tag == 0x81 { // rfc822Name [1] IMPLICIT IA5String
        out_type = tls::SanType.Email;
        return elem_buf.len > 0 && !elem_buf.contains_byte(0);
    }
    if tag == 0x82 { // dNSName [2] IMPLICIT IA5String
        out_type = tls::SanType.Dns;
        return tls::validate_san_dns_name(elem_buf);
    }
    if tag == 0x87 { // iPAddress [7] IMPLICIT OCTET STRING
        out_type = tls::SanType.Ip;
        return elem_buf.len == 4 || elem_buf.len == 16;
    }
    if tag == 0xA4 { // directoryName [4] EXPLICIT Name
        out_type = tls::SanType.DirName;
        return elem_buf.len > 0;
    }
    if tag == 0x86 { // uniformResourceIdentifier [6] IMPLICIT IA5String
        out_type = tls::SanType.Uri;
        return x509_validate_san_uri(elem_buf);
    }
    guard tag == 0xA0 || tag == 0xA3 || tag == 0xA5 || tag == 0x88 else { return false; }
    out_type = tls::SanType.Other;
    return true;
}

fn x509_open_san_sequence(san_der: const u8[:], out_seq: core::ByteCursor&) -> bool {
    var c = core::cursor_from(san_der);
    guard tls::get_asn1_element(c, rfc::ASN1_TAG_SEQUENCE, out_seq) &&
        c.cursor_len() == 0 &&
        out_seq.cursor_len() > 0 else {
        return false;
    }
    return true;
}

// Reads and classifies the next GeneralName entry from an open SubjectAltName cursor.
//
// Example:
//   names_seq = [0x82, 0x0B, "example.com"]
//   returns: SanEntry { san_type: SanType.Dns, val: "example.com" }, ok = true
fn x509_next_san_entry(names_seq: core::ByteCursor&) -> tls::SanEntry, bool {
    var tag: u8 = 0;
    var elem = core::cursor_from(names_seq.buf[..0]);
    guard tls::get_any_asn1_element(names_seq, tag, elem) else {
        return tls::SanEntry { san_type: tls::SanType.Other, val: names_seq.buf[..0] }, false;
    }

    var st = tls::SanType.Other;
    guard x509_classify_san_element(tag, elem.buf, st) else {
        return tls::SanEntry { san_type: tls::SanType.Other, val: names_seq.buf[..0] }, false;
    }
    return tls::SanEntry { san_type: st, val: elem.buf }, true;
}

fn x509_parse_single_san<S>(names_seq: core::ByteCursor&, out_sans: S&) -> bool {
    let entry, ok = x509_next_san_entry(names_seq);
    guard ok else { return false; }
    return out_sans.try_push(entry);
}

// Validates all GeneralNames in a raw SubjectAltName extension without any entry-count cap.
fn validate_san_extension(san_der: const u8[:]) -> bool {
    var names_seq = core::cursor_from(san_der[..0]);
    guard x509_open_san_sequence(san_der, names_seq) else { return false; }
    var seen_any = false;
    while names_seq.cursor_len() > 0 {
        let _, ok = x509_next_san_entry(names_seq);
        guard ok else { return false; }
        seen_any = true;
    }
    return seen_any;
}

fn validate_cert_san_extension(cert: const tls::ParsedCert&, raw_cert: const u8[:]) -> bool {
    guard cert.has_san else { return false; }
    return validate_san_extension(tls::span_slice(raw_cert, cert.san_raw));
}

inline fn x509_is_dn_foldable_string_tag(tag: u8) -> bool {
    return tag == rfc::ASN1_TAG_UTF8_STRING ||
        tag == rfc::ASN1_TAG_PRINTABLE_STRING ||
        tag == rfc::ASN1_TAG_IA5_STRING ||
        tag == 0x14; // TeletexString
}

// RFC 5280 Section 7.1: Canonicalizes a Distinguished Name string attribute by trimming outer
// spaces, collapsing internal runs of ASCII spaces to a single space, and lowercasing ASCII.
fn x509_canonicalize_dn_value(raw: const u8[:], out: u8[..256]&) -> bool {
    out.clear();
    let trimmed = raw.trim_lws();
    var in_space = false;
    for b in trimmed {
        if b == ' ' || b == '\t' {
            if !in_space {
                guard out.try_push(' ') else { return false; }
                in_space = true;
            }
            continue;
        }
        in_space = false;
        guard out.try_push(core::to_lower_ascii_byte(b)) else { return false; }
    }
    return true;
}

fn x509_dn_ava_equal(cand_ava: core::ByteCursor&, cons_ava: core::ByteCursor&) -> bool {
    var cand_oid = core::cursor_from(cand_ava.buf[..0]);
    var cons_oid = core::cursor_from(cons_ava.buf[..0]);
    guard tls::get_asn1_element(cand_ava, rfc::ASN1_TAG_OID, cand_oid) &&
        tls::get_asn1_element(cons_ava, rfc::ASN1_TAG_OID, cons_oid) &&
        cand_oid.buf == cons_oid.buf else {
        return false;
    }
    var cand_tag: u8 = 0;
    var cons_tag: u8 = 0;
    var cand_val = core::cursor_from(cand_ava.buf[..0]);
    var cons_val = core::cursor_from(cons_ava.buf[..0]);
    guard tls::get_any_asn1_element(cand_ava, cand_tag, cand_val) &&
        tls::get_any_asn1_element(cons_ava, cons_tag, cons_val) &&
        cand_ava.cursor_len() == 0 && cons_ava.cursor_len() == 0 else {
        return false;
    }
    if x509_is_dn_foldable_string_tag(cand_tag) && x509_is_dn_foldable_string_tag(cons_tag) {
        var norm_cand: u8[..256] = [];
        var norm_cons: u8[..256] = [];
        guard x509_canonicalize_dn_value(cand_val.buf, norm_cand) &&
            x509_canonicalize_dn_value(cons_val.buf, norm_cons) else {
            return false;
        }
        return norm_cand[..] == norm_cons[..];
    }
    return cand_tag == cons_tag && cand_val.buf == cons_val.buf;
}

fn x509_dn_rdn_equal(cand_rdn: core::ByteCursor&, cons_rdn: core::ByteCursor&) -> bool {
    guard cand_rdn.cursor_len() > 0 && cons_rdn.cursor_len() > 0 else { return false; }
    while cons_rdn.cursor_len() > 0 {
        var cons_ava = core::cursor_from(cons_rdn.buf[..0]);
        var cand_ava = core::cursor_from(cand_rdn.buf[..0]);
        guard tls::get_asn1_element(cons_rdn, rfc::ASN1_TAG_SEQUENCE, cons_ava) &&
            tls::get_asn1_element(cand_rdn, rfc::ASN1_TAG_SEQUENCE, cand_ava) &&
            x509_dn_ava_equal(cand_ava, cons_ava) else {
            return false;
        }
    }
    return cand_rdn.cursor_len() == 0;
}

// RFC 5280 Section 4.2.1.10 & Section 7.1: Matches DirectoryName RDNSequence prefix RDN-by-RDN.
fn match_dn_name_constraint(candidate_dn: const u8[:], constraint_dn: const u8[:]) -> bool {
    guard candidate_dn.len > 0 && constraint_dn.len > 0 else { return false; }
    var cand_c = core::cursor_from(candidate_dn);
    var cons_c = core::cursor_from(constraint_dn);
    var cand_seq = core::cursor_from(candidate_dn[..0]);
    var cons_seq = core::cursor_from(constraint_dn[..0]);
    guard tls::get_asn1_element(cand_c, rfc::ASN1_TAG_SEQUENCE, cand_seq) &&
        tls::get_asn1_element(cons_c, rfc::ASN1_TAG_SEQUENCE, cons_seq) &&
        cand_c.cursor_len() == 0 && cons_c.cursor_len() == 0 else {
        return false;
    }
    while cons_seq.cursor_len() > 0 {
        var cons_rdn = core::cursor_from(cons_seq.buf[..0]);
        var cand_rdn = core::cursor_from(cand_seq.buf[..0]);
        guard tls::get_asn1_element(cons_seq, rfc::ASN1_TAG_SET, cons_rdn) &&
            tls::get_asn1_element(cand_seq, rfc::ASN1_TAG_SET, cand_rdn) &&
            x509_dn_rdn_equal(cand_rdn, cons_rdn) else {
            return false;
        }
    }
    return true;
}

inline fn x509_match_host_constraint_3state(cand_host: const u8[:], cons_host: const u8[:]) -> NcMatchResult {
    guard cons_host.len > 0 && find(cons_host, "..") < 0 else { return NcMatchResult.Invalid; }
    // RFC 5280 Section 4.2.1.10: Leading '.' matches subdomains; without '.' matches exact host.
    let matched = if cons_host[0] == '.' {
        x509_match_dns_dotted_constraint(cand_host, cons_host)
    } else {
        cand_host.eq_ascii_fold(cons_host)
    };
    return if matched { NcMatchResult.Match } else { NcMatchResult.NoMatch };
}

fn x509_match_uri_nc_3state(candidate_uri: const u8[:], constraint: const u8[:]) -> NcMatchResult {
    guard x509_validate_subtree_nonempty_text(candidate_uri, false)
        && x509_validate_subtree_nonempty_text(constraint, false) else {
        return NcMatchResult.Invalid;
    }

    var host_part = x509_extract_uri_authority(candidate_uri);
    guard host_part.len > 0 && !host_part.contains_byte('@') else { return NcMatchResult.Invalid; }

    if host_part[0] == '[' {
        return x509_match_ipv6_uri_constraint_3state(host_part, constraint);
    }

    let colon_idx = host_part.index_of_byte(':');
    if colon_idx >= 0 {
        host_part = host_part[..colon_idx];
    }
    guard host_part.len > 0 && !x509_is_ipv4_literal(host_part) else { return NcMatchResult.Invalid; }

    let cand = tls::x509_strip_trailing_dot(host_part);
    guard x509_validate_dns_candidate(cand) else { return NcMatchResult.Invalid; }
    return x509_match_host_constraint_3state(cand, tls::x509_strip_trailing_dot(constraint));
}

fn x509_match_email_nc_3state(candidate_email: const u8[:], constraint: const u8[:]) -> NcMatchResult {
    guard x509_validate_subtree_nonempty_text(candidate_email, false)
        && x509_validate_subtree_nonempty_text(constraint, false) else {
        return NcMatchResult.Invalid;
    }

    // RFC 5321 Section 4.1.2: Split on the last '@' so quoted local-parts cannot smuggle '@'.
    let cand_local, cand_host_raw, has_cand_at = candidate_email.rsplit_once_byte('@');
    guard has_cand_at && cand_local.len > 0 && cand_host_raw.len > 0 else { return NcMatchResult.Invalid; }
    if cand_local[0] != '"' && cand_local.contains_byte('@') {
        return NcMatchResult.Invalid;
    }
    let cand_host = tls::x509_strip_trailing_dot(cand_host_raw);
    guard x509_validate_dns_candidate(cand_host) else { return NcMatchResult.Invalid; }

    let cons_local, cons_host_raw, has_cons_at = constraint.rsplit_once_byte('@');
    if has_cons_at {
        guard cons_local.len > 0 && cons_host_raw.len > 0 else { return NcMatchResult.Invalid; }
        let cons_host = tls::x509_strip_trailing_dot(cons_host_raw);
        let ok = cand_local == cons_local && cand_host.eq_ascii_fold(cons_host);
        return if ok { NcMatchResult.Match } else { NcMatchResult.NoMatch };
    }

    return x509_match_host_constraint_3state(cand_host, tls::x509_strip_trailing_dot(constraint));
}

inline fn x509_match_constraint_entry_3state(
    nc:  const tls::NameConstraintEntry&,
    san: const tls::SanEntry&,
) -> NcMatchResult {
    if nc.san_type == tls::SanType.Dns {
        return if tls::match_dns_name_constraint(san.val, nc.val) {
            NcMatchResult.Match
        } else {
            NcMatchResult.NoMatch
        };
    }
    if nc.san_type == tls::SanType.Ip {
        return if tls::match_ip_name_constraint(san.val, nc.val) {
            NcMatchResult.Match
        } else {
            NcMatchResult.NoMatch
        };
    }
    if nc.san_type == tls::SanType.Uri {
        return x509_match_uri_nc_3state(san.val, nc.val);
    }
    if nc.san_type == tls::SanType.Email {
        return x509_match_email_nc_3state(san.val, nc.val);
    }
    if nc.san_type == tls::SanType.DirName {
        return if match_dn_name_constraint(san.val, nc.val) {
            NcMatchResult.Match
        } else {
            NcMatchResult.NoMatch
        };
    }
    return NcMatchResult.Invalid;
}

fn x509_eval_single_nc(
    nc:                const tls::NameConstraintEntry&,
    san:               const tls::SanEntry&,
    has_permitted:     bool&,
    matched_permitted: bool&,
) -> bool {
    if nc.san_type != san.san_type {
        return true;
    }
    // RFC 5280 Section 4.2.1.10: Name Constraints - Unsupported name form constraints MUST reject matching SANs.
    if nc.san_type == tls::SanType.Other {
        return false;
    }
    let res = x509_match_constraint_entry_3state(nc, san);
    guard res != NcMatchResult.Invalid else { return false; }
    let matched = res == NcMatchResult.Match;
    if nc.is_excluded {
        // CVE-2025-61727: Reject wildcard DNS SAN (e.g. *.example.com) that can match an excluded DNS subtree.
        let wildcard_overlap = nc.san_type == tls::SanType.Dns && tls::match_dns_san(san.val, nc.val);
        return !matched && !wildcard_overlap;
    }
    has_permitted = true;
    if matched {
        matched_permitted = true;
    }
    return true;
}

// Checks every pkcs-9-at-emailAddress AVA inside `subject_inner` against Email NameConstraints (RFC 5280 §4.2.1.10).
fn check_subject_dn_emails_against_nc(
    nc_entries:    const tls::NameConstraintEntry[..16]&,
    subject_inner: const u8[:],
) -> bool {
    var rdn_seq = core::cursor_from(subject_inner);
    while rdn_seq.cursor_len() > 0 {
        var rdn = core::cursor_from(rdn_seq.buf[..0]);
        guard tls::get_asn1_element(rdn_seq, rfc::ASN1_TAG_SET, rdn) else { return false; }
        while rdn.cursor_len() > 0 {
            var ava = core::cursor_from(rdn.buf[..0]);
            var oid = core::cursor_from(rdn.buf[..0]);
            var val_tag: u8 = 0;
            var val = core::cursor_from(rdn.buf[..0]);
            guard tls::get_asn1_element(rdn, rfc::ASN1_TAG_SEQUENCE, ava) &&
                tls::get_asn1_element(ava, rfc::ASN1_TAG_OID, oid) &&
                tls::get_any_asn1_element(ava, val_tag, val) &&
                ava.cursor_len() == 0 else {
                return false;
            }
            if oid.buf == rfc::OID_EMAIL_ADDRESS[..] {
                let email_san = tls::SanEntry { san_type: tls::SanType.Email, val: val.buf };
                guard tls::check_name_constraints(nc_entries, email_san) else { return false; }
            }
        }
    }
    return true;
}

// Streams and enforces parsed NameConstraints against Subject DN, Subject emailAddress (when no
// rfc822Name SAN is present), and every SAN on `cert` without any entry-count cap (RFC 5280 §4.2.1.10).
fn check_cert_sans_against_nc(
    nc_entries: const tls::NameConstraintEntry[..16]&,
    cert:       const tls::ParsedCert&,
    raw_cert:   const u8[:],
) -> bool {
    let subj_inner = tls::span_slice(raw_cert, cert.subject_raw);
    if subj_inner.len > 0 {
        var dn_tlv: u8[..1024] = [];
        guard encode_der_name_tlv(subj_inner, dn_tlv) else { return false; }
        let dn_san = tls::SanEntry { san_type: tls::SanType.DirName, val: dn_tlv[..] };
        guard tls::check_name_constraints(nc_entries, dn_san) else { return false; }
    }

    var has_email_san = false;
    if cert.has_san {
        var names_seq = core::cursor_from(raw_cert[..0]);
        guard x509_open_san_sequence(tls::span_slice(raw_cert, cert.san_raw), names_seq) else { return false; }
        var seen_any = false;
        while names_seq.cursor_len() > 0 {
            let entry, ok = x509_next_san_entry(names_seq);
            guard ok else { return false; }
            if entry.san_type == tls::SanType.Email {
                has_email_san = true;
            }
            guard tls::check_name_constraints(nc_entries, entry) else { return false; }
            seen_any = true;
        }
        guard seen_any else { return false; }
    }

    if !has_email_san && subj_inner.len > 0 {
        guard check_subject_dn_emails_against_nc(nc_entries, subj_inner) else { return false; }
    }
    return true;
}
