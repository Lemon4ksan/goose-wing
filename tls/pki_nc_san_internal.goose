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

fn x509_match_ipv6_uri_constraint(host_part: const u8[:], constraint: const u8[:]) -> bool {
    let close_bracket = host_part.index_of_byte(']');
    guard close_bracket > 1 else { return false; }
    var inner_ip = host_part[1..close_bracket];

    let pct_idx = inner_ip.index_of_byte('%');
    if pct_idx >= 0 {
        inner_ip = inner_ip[..pct_idx];
    }
    guard inner_ip.len > 0 else { return false; }

    var cons_cmp = constraint;
    if cons_cmp.len > 2 {
        let last_idx = core::sub_sat_i64(cons_cmp.len, 1);
        if cons_cmp[0] == '[' && cons_cmp[last_idx] == ']' {
            cons_cmp = cons_cmp[1..^1];
        }
    }
    return inner_ip.eq_ascii_fold(cons_cmp);
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
    let tag_num = base_tag & 0x1F;
    if tag_num == 1 { // rfc822Name [1]
        out_type = tls::SanType.Email;
        return x509_validate_subtree_nonempty_text(out_val.buf, false);
    }
    if tag_num == 2 { // dNSName
        out_type = tls::SanType.Dns;
        // RFC 5280 Section 4.2.1.10: Name Constraints - dNSName base MUST NOT start with a leading period.
        return x509_validate_subtree_nonempty_text(out_val.buf, true);
    }
    if tag_num == 7 { // iPAddress
        out_type = tls::SanType.Ip;
        return x509_validate_subtree_ip(out_val.buf);
    }
    if tag_num == 4 { // directoryName [4] EXPLICIT Name
        out_type = tls::SanType.DirName;
        return out_val.buf.len > 0;
    }
    if tag_num == 6 { // uniformResourceIdentifier [6]
        out_type = tls::SanType.Uri;
        return x509_validate_subtree_nonempty_text(out_val.buf, false);
    }
    out_type = tls::SanType.Other;
    return true;
}

inline fn x509_validate_subtree_bound_opt(opt_tag: u8, opt_elem: core::ByteCursor&) -> bool {
    let opt_num = opt_tag & 0x1F;
    if opt_num == 0 { // minimum MUST be zero
        var min_val: i64 = 0;
        return tls::get_asn1_integer(opt_elem, min_val) && min_val == 0;
    }
    return false; // maximum (opt_num == 1) or other tags forbidden
}

inline fn x509_parse_general_subtree_bounds(subtree: core::ByteCursor&) -> bool {
    while subtree.cursor_len() > 0 {
        var opt_tag: u8 = 0;
        var opt_elem = core::cursor_from(subtree.buf[..0]);
        if !tls::get_any_asn1_element(subtree, opt_tag, opt_elem) { return false; }
        guard x509_validate_subtree_bound_opt(opt_tag, opt_elem) else { return false; }
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

    let span = tls::make_span(nc_der, base_elem.buf);
    return out_constraints.try_push(tls::NameConstraintEntry {
        san_type:    st,
        is_excluded: is_excluded,
        val:         tls::span_slice(nc_der, span),
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
    return !elem_buf.contains_byte('%') && !elem_buf.contains_byte(0);
}

inline fn x509_classify_san_element(tag_num: u8, elem_buf: const u8[:], out_type: tls::SanType&) -> bool {
    if tag_num == 1 { // rfc822Name [1] IA5String
        out_type = tls::SanType.Email;
        return elem_buf.len > 0 && !elem_buf.contains_byte(0);
    }
    if tag_num == 2 { // dNSName [2] IA5String
        out_type = tls::SanType.Dns;
        return tls::validate_san_dns_name(elem_buf);
    }
    if tag_num == 7 { // iPAddress [7] OCTET STRING
        out_type = tls::SanType.Ip;
        return elem_buf.len == 4 || elem_buf.len == 16;
    }
    if tag_num == 4 { // directoryName [4] EXPLICIT Name
        out_type = tls::SanType.DirName;
        return elem_buf.len > 0;
    }
    if tag_num == 6 { // uniformResourceIdentifier [6] IA5String
        out_type = tls::SanType.Uri;
        return x509_validate_san_uri(elem_buf);
    }
    guard tag_num <= 8 else { return false; }
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

    let tag_num = tag & 0x1F;
    var st = tls::SanType.Other;
    guard x509_classify_san_element(tag_num, elem.buf, st) else {
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

// RFC 5280 Section 4.2.1.10: Name Constraints - Matches DirectoryName RDNSequence prefix.
fn match_dn_name_constraint(candidate_dn: const u8[:], constraint_dn: const u8[:]) -> bool {
    guard candidate_dn.len > 0 && constraint_dn.len > 0 else { return false; }
    if candidate_dn == constraint_dn {
        return true;
    }
    var cand_c = core::cursor_from(candidate_dn);
    var cons_c = core::cursor_from(constraint_dn);
    var cand_seq = core::cursor_from(candidate_dn[..0]);
    var cons_seq = core::cursor_from(constraint_dn[..0]);
    guard tls::get_asn1_element(cand_c, rfc::ASN1_TAG_SEQUENCE, cand_seq) &&
        tls::get_asn1_element(cons_c, rfc::ASN1_TAG_SEQUENCE, cons_seq) &&
        cand_c.cursor_len() == 0 &&
        cons_c.cursor_len() == 0 else {
        return false;
    }
    return core::starts_with(cand_seq.buf, cons_seq.buf);
}

inline fn x509_match_constraint_entry(nc: const tls::NameConstraintEntry&, san: const tls::SanEntry&) -> bool {
    if nc.san_type == tls::SanType.Dns {
        return tls::match_dns_name_constraint(san.val, nc.val);
    }
    if nc.san_type == tls::SanType.Ip {
        return tls::match_ip_name_constraint(san.val, nc.val);
    }
    if nc.san_type == tls::SanType.Uri {
        return tls::match_uri_name_constraint(san.val, nc.val);
    }
    if nc.san_type == tls::SanType.Email {
        return tls::match_email_name_constraint(san.val, nc.val);
    }
    if nc.san_type == tls::SanType.DirName {
        return match_dn_name_constraint(san.val, nc.val);
    }
    return false;
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
    let matched = x509_match_constraint_entry(nc, san);
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

// Streams and enforces parsed NameConstraints against every SAN on `cert` without any entry-count cap.
fn check_cert_sans_against_nc(
    nc_entries: const tls::NameConstraintEntry[..16]&,
    cert:       const tls::ParsedCert&,
    raw_cert:   const u8[:],
) -> bool {
    guard cert.has_san else { return true; }
    var names_seq = core::cursor_from(raw_cert[..0]);
    guard x509_open_san_sequence(tls::span_slice(raw_cert, cert.san_raw), names_seq) else { return false; }
    var seen_any = false;
    while names_seq.cursor_len() > 0 {
        let entry, ok = x509_next_san_entry(names_seq);
        guard ok else { return false; }
        guard tls::check_name_constraints(nc_entries, entry) else { return false; }
        seen_any = true;
    }
    return seen_any;
}
