// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Public Suffix List rules, eTLD+1 extraction, and domain/path matching (RFC 6265 Section 5.1).
namespace wing;

import std;
import core from "..";
import .constants;
import .dafsa;

// ---- public suffix data structures and enumerations ------------------------

// RFC 1034 Section 3.1: Name space specifications and terminology - Total length <= 253 octets and labels 1..63 octets.
fn has_valid_dns_label_lengths(domain: const u8[:]) -> bool {
    guard domain.len > 0 && domain.len <= 253 else {
        return false;
    }
    var label_len: i64 = 0;
    for b in domain {
        if b == '.' {
            guard label_len >= 1 && label_len <= 63 else { return false; }
            label_len = 0;
        } else {
            label_len = core::add_sat_i64(label_len, 1);
            guard label_len <= 63 else { return false; }
        }
    }
    return label_len >= 1 && label_len <= 63;
}

// Validates that `domain` is non-empty, <= 253 ASCII bytes, valid UTF-8, has no leading
// or trailing '.', has no empty '..' labels, is not an IP literal, and normalizes to lowercase.
//
// Example:
//   domain = "Example.CO.UK", out = [] -> returns true, out = "example.co.uk"
//   domain = ".com", out = []          -> returns false (leading dot rejected)
fn validate_and_lowercase_psl_domain(domain: const u8[:], out: u8[..256]&) -> bool {
    out.clear();
    guard domain.len > 0 && domain.len <= 256 else {
        return false;
    }
    if !core::is_pure_ascii(domain) {
        guard core::punycode_encode_domain(domain, out)
            && !is_invalid_psl_domain_syntax(out[..])
            && has_valid_dns_label_lengths(out[..]) else {
            out.clear();
            return false;
        }
        return true;
    }
    let last_idx = core::sub_sat_i64(domain.len, 1);
    guard domain[0] != 0x2E && domain[last_idx] != 0x2E else {
        return false;
    }
    guard !core::is_ip_address_literal(domain)
        && !is_invalid_psl_domain_syntax(domain)
        && has_valid_dns_label_lengths(domain) else {
        return false;
    }
    guard out.try_set(domain) else {
        return false;
    }
    to_lower(out[..]);
    return true;
}

// Evaluates the compiled Chromium/libpsl DAFSA binary automaton in O(L) time.
// Returns `true` if `domain` is a public suffix (ICANN or Private), `false` if it is a
// registrable domain (e.g. `example.com`, `www.ck`, `city.kawasaki.jp`) or malformed
// (leading/trailing dots, empty labels, IP literal, or invalid UTF-8).
//
// Example:
//   domain = "co.uk"   -> returns true
//   domain = "foo.ck"  -> returns true (*.ck wildcard)
//   domain = "www.ck"  -> returns false (!www.ck exception)
//   domain = ".com"    -> returns false (leading dot rejected)
fn psl_is_public_suffix(domain: const u8[:]) -> bool {
    var norm: u8[..256] = [];
    guard validate_and_lowercase_psl_domain(domain, norm) else {
        return false;
    }
    let suffix, matched, _, _ = dafsa_find_public_suffix(norm[0..norm.len]);
    if matched {
        return suffix.len == norm.len;
    }
    return !norm.contains_byte('.');
}

enum PslRuleType {
    Normal,
    Wildcard,
    Exception,
}

enum PslSection {
    Icann,
    Private,
}

struct PslRule {
    pattern:   u8[..64]    = [],
    rule_type: PslRuleType = PslRuleType.Normal,
    section:   PslSection  = PslSection.Icann,
}

struct PslDatabase {
    use_dafsa: bool          = false,
    rules:     PslRule[..64] = [],
}

struct PslMatch {
    suffix:             u8[..256] = [],
    registrable_domain: u8[..256] = [],
    is_icann:           bool      = false,
    is_private:         bool      = false,
    is_known:           bool      = false,
}

fn new_psl_rule(pattern: const u8[:], rule_type: PslRuleType, section: PslSection) -> PslRule {
    var new_rule = PslRule { rule_type: rule_type, section: section, .. };
    guard new_rule.pattern.try_set(pattern) else { return new_rule; }
    to_lower(new_rule.pattern[..]);
    return new_rule;
}

fn add_psl_rule(db: PslDatabase&, pattern: const u8[:], rule_type: PslRuleType, section: PslSection) {
    let _ = db.rules.try_push(new_psl_rule(pattern, rule_type, section));
}

fn new_psl_database() -> PslDatabase {
    return PslDatabase { rules: [], use_dafsa: true };
}

// ---- public suffix query and matching engine -------------------------------

fn is_invalid_psl_domain_syntax(trimmed: const u8[:]) -> bool {
    if !core::is_ip_address_literal(trimmed)
        && (core::contains(trimmed, "..") || trimmed.contains_byte(':')) {
        return true;
    }
    for b in trimmed {
        if b <= 0x20 || b == 0x7F || b == '/' || b == '?' || b == '#' || b == '\\' {
            return true;
        }
    }
    return false;
}

// Normalizes domain: strips leading/trailing dots and outer IPv6 brackets, then converts to lowercase or Punycode.
fn psl_normalize_domain<B>(domain: const u8[:], out: B&) -> bool {
    out.clear();
    let trimmed = domain.trim_byte('.').trim_byte('[').trim_byte(']');
    guard trimmed.len > 0 && trimmed.len <= 256 && !is_invalid_psl_domain_syntax(trimmed) else {
        return false;
    }
    if !core::is_pure_ascii(trimmed) {
        var ace_buf: u8[..256] = [];
        guard core::punycode_encode_domain(trimmed, ace_buf)
            && !is_invalid_psl_domain_syntax(ace_buf[..])
            && has_valid_dns_label_lengths(ace_buf[..]) else {
            return false;
        }
        return out.try_set(ace_buf[..]);
    }
    if !core::is_ip_address_literal(trimmed) {
        guard has_valid_dns_label_lengths(trimmed) else { return false; }
    }
    guard out.try_set(trimmed) else { return false; }
    to_lower(out[..]);
    return true;
}

fn psl_match_exception(rule: const PslRule&, norm: const u8[:]) -> const u8[:] {
    if rule.rule_type != PslRuleType.Exception {
        return "";
    }
    let pat = rule.pattern[..];
    if norm != pat && !core::ends_with_dot_suffix(norm, pat) {
        return "";
    }
    let _, tail, has_dot = pat.split_once_byte('.');
    if !has_dot || tail.len == 0 {
        return pat;
    }
    return tail;
}

fn psl_match_normal(pat: const u8[:], norm: const u8[:], out_start: i64&, out_labels: i32&) -> bool {
    let pat_len = pat.len;
    let norm_len = norm.len;
    let dots = pat.count_byte('.');
    let num_labels = core::add_sat_i64(dots, 1) as i32;
    if norm == pat {
        out_start = 0;
        out_labels = num_labels;
        return true;
    }
    if !core::ends_with_dot_suffix(norm, pat) {
        return false;
    }
    if norm_len < pat_len {
        return false;
    }
    let suffix_start = core::sub_sat_i64(norm_len, pat_len);
    out_start = suffix_start;
    out_labels = num_labels;
    return true;
}

fn psl_match_wildcard(pat: const u8[:], norm: const u8[:], out_start: i64&, out_labels: i32&) -> bool {
    let dots = pat.count_byte('.');
    if norm == pat {
        out_start = 0;
        out_labels = core::add_sat_i64(dots, 1) as i32;
        return true;
    }
    if !core::ends_with_dot_suffix(norm, pat) {
        return false;
    }
    let n_len = norm.len;
    let p_len = pat.len;
    if n_len <= p_len {
        return false;
    }
    let rem_len = core::sub_sat_i64(n_len, p_len);
    let prefix_len = core::sub_sat_i64(rem_len, 1);
    if prefix_len < 0 || prefix_len > n_len {
        return false;
    }
    let prefix = norm[..prefix_len];
    let last_dot = prefix.last_index_of_byte('.');
    let next_dot = core::add_sat_i64(last_dot, 1);
    var start: i64 = 0;
    if last_dot >= 0 {
        start = next_dot;
    }
    let num_labels = core::add_sat_i64(dots, 2) as i32;
    out_start = start;
    out_labels = num_labels;
    return true;
}

fn psl_find_best_rule(db: const PslDatabase&, norm: const u8[:], out_start: i64&, out_sec: PslSection&) -> bool {
    var best_labels: i32 = 0;
    var best_start:  i64 = 0;
    var best_sec = PslSection.Icann;
    var found = false;

    for &rule in db.rules {
        var start_idx: i64 = 0;
        var labels:    i32 = 0;
        var matched = false;

        if rule.rule_type == PslRuleType.Normal {
            matched = psl_match_normal(rule.pattern[..], norm, start_idx, labels);
        } else if rule.rule_type == PslRuleType.Wildcard {
            matched = psl_match_wildcard(rule.pattern[..], norm, start_idx, labels);
        }

        if matched && labels > best_labels {
            best_labels = labels;
            best_start = start_idx;
            best_sec = rule.section;
            found = true;
        }
    }

    if found {
        out_start = best_start;
        out_sec = best_sec;
        return true;
    }
    return false;
}

// Evaluates custom exception rules in `db.rules` against `norm`.
//
// Example:
//   norm = "www.ck" -> returns "ck", true, true (when !www.ck rule exists in db.rules)
fn psl_find_custom_exception(db: const PslDatabase&, norm: const u8[:]) -> const u8[:], bool, bool {
    for &rule in db.rules {
        let exc_suffix = psl_match_exception(rule, norm);
        if exc_suffix.len > 0 {
            return exc_suffix, true, (rule.section == PslSection.Icann);
        }
    }
    return norm[0..0], false, false;
}

// Computes the Public Suffix for `domain` against `db` per Mozilla PSL specification.
// Returns (has_suffix, is_icann).
fn find_public_suffix<B>(db: const PslDatabase&, domain: const u8[:], out: B&) -> bool, bool {
    out.clear();
    let res, ok = match_public_suffix(db, domain);
    guard ok && out.try_append(res.suffix[..]) else {
        out.clear();
        return false, false;
    }
    return true, res.is_icann;
}

fn psl_find_known_suffix(db: const PslDatabase&, norm: const u8[:]) -> const u8[:], bool, bool {
    let exc_suf, exc_ok, exc_icann = psl_find_custom_exception(db, norm);
    if exc_ok {
        return exc_suf, true, exc_icann;
    }
    var dafsa_suf = norm[0..0];
    var dafsa_matched = false;
    var dafsa_icann = false;
    var dafsa_is_exc = false;
    if db.use_dafsa {
        let ds, dm, di, de = dafsa_find_public_suffix(norm);
        dafsa_suf = ds;
        dafsa_matched = dm;
        dafsa_icann = di;
        dafsa_is_exc = de;
    }
    if dafsa_matched && dafsa_is_exc {
        return dafsa_suf, true, dafsa_icann;
    }
    var best_start: i64 = 0;
    var best_sec = PslSection.Icann;
    if psl_find_best_rule(db, norm, best_start, best_sec) {
        let custom_suf = norm[best_start..];
        if dafsa_matched && dafsa_suf.len > custom_suf.len {
            return dafsa_suf, true, dafsa_icann;
        }
        return custom_suf, true, (best_sec == PslSection.Icann);
    }
    if dafsa_matched {
        return dafsa_suf, true, dafsa_icann;
    }
    return norm[0..0], false, false;
}

// Evaluates `domain` against `db` and returns a `PslMatch` distinguishing explicitly listed
// suffixes (`is_known == true`) from the implicit `*` fallback rule (`is_known == false`).
fn match_public_suffix(db: const PslDatabase&, domain: const u8[:]) -> PslMatch, bool {
    var m = PslMatch { .. };
    var norm_buf: u8[..256] = [];
    guard psl_normalize_domain(domain, norm_buf) else { return m, false; }
    let norm = norm_buf[..];
    guard !core::is_ip_address_literal(norm) else { return m, false; }

    let known_suf, matched_known, is_icann = psl_find_known_suffix(db, norm);
    if matched_known {
        let _ = m.suffix.try_set(known_suf);
        m.is_known = true;
        m.is_icann = is_icann;
        m.is_private = !is_icann;
    } else {
        let _, tld, has_dot = norm.rsplit_once_byte('.');
        let _ = m.suffix.try_set(if has_dot { tld } else { norm });
        m.is_known = false;
        m.is_icann = true;
        m.is_private = false;
    }

    if norm.len > m.suffix.len && norm.count_byte('.') > 0 {
        let reg_start = psl_find_registrable_start(norm, m.suffix.len);
        if reg_start >= 0 && reg_start <= norm.len {
            let _ = m.registrable_domain.try_set(norm[reg_start..]);
        }
    }
    return m, true;
}

// Whether `domain` is an explicitly listed public suffix in `db` (`PSL_TYPE_NO_STAR_RULE` / `Suffix::is_known`),
// excluding synthetic fallback `*` matches on unknown TLDs or single-label intranet hosts.
fn is_known_public_suffix(db: const PslDatabase&, domain: const u8[:]) -> bool {
    var norm_buf: u8[..256] = [];
    guard psl_normalize_domain(domain, norm_buf) else { return false; }
    let norm = norm_buf[..];
    guard !core::is_ip_address_literal(norm) else { return false; }
    let m, ok = match_public_suffix(db, norm);
    guard ok && m.is_known && m.suffix.len > 0 else { return false; }
    return norm.eq_ascii_fold(m.suffix[..]);
}

// Whether domain is itself a public suffix in the database.
fn is_public_suffix(db: const PslDatabase&, domain: const u8[:], is_icann_only: bool = false) -> bool {
    var norm_buf: u8[..256] = [];
    if !psl_normalize_domain(domain, norm_buf) {
        return false;
    }
    let norm = norm_buf[..];
    if core::is_ip_address_literal(norm) { return false; }

    var suffix: u8[..256] = [];
    let ok, is_icann = find_public_suffix(db, norm, suffix);
    if !ok || suffix.len == 0 {
        return false;
    }
    if is_icann_only && !is_icann { return false; }

    return norm.eq_ascii_fold(suffix[..]);
}

fn psl_find_registrable_start(clean_host: const u8[:], suffix_len: i64) -> i64 {
    let host_len = clean_host.len;
    let min_needed = core::add_sat_i64(suffix_len, 1);
    if host_len <= min_needed {
        return 0;
    }
    let prefix_len = core::sub_sat_i64(host_len, min_needed);
    if prefix_len < 0 || prefix_len > host_len {
        return 0;
    }
    let prefix = clean_host[..prefix_len];
    let last_dot = prefix.last_index_of_byte('.');
    let next_pos = core::add_sat_i64(last_dot, 1);
    if last_dot >= 0 {
        return next_pos;
    }
    return 0;
}

// Extracts the effective top-level domain plus one (eTLD+1 / registrable domain) using database.
//
// Example:
//   host = "sub.example.co.uk"
//   out = "example.co.uk"
fn extract_etld_plus_one<B>(db: const PslDatabase&, host: const u8[:], out: B&) {
    out.clear();
    var norm_buf: u8[..256] = [];
    guard psl_normalize_domain(host, norm_buf) else { return; }
    let clean_host = norm_buf[..];

    let has_dot = clean_host.count_byte('.') > 0;
    guard has_dot && !core::is_ip_address_literal(clean_host) else {
        let _ = out.try_append(clean_host);
        return;
    }

    var suffix: u8[..256] = [];
    let ok, _ = find_public_suffix(db, clean_host, suffix);
    guard ok && suffix.len > 0 && !clean_host.eq_ascii_fold(suffix[..]) else {
        let _ = out.try_append(clean_host);
        return;
    }

    let start_pos = psl_find_registrable_start(clean_host, suffix.len);
    guard start_pos >= 0 && start_pos <= clean_host.len else {
        let _ = out.try_append(clean_host);
        return;
    }
    let _ = out.try_append(clean_host[start_pos..]);
}

// Extracts eTLD+1 from host using the full compiled DAFSA automaton.
fn psl_extract_etld_plus_one<B>(host: const u8[:], out: B&) {
    let db = PslDatabase { use_dafsa: true, .. };
    extract_etld_plus_one(db, host, out);
}

// ---- public suffix & rfc 6265 scoping api ----------------------------------

// Whether domain is a public suffix (cannot set domain cookies for it).
fn is_public_suffix_domain(domain: const u8[:]) -> bool {
    let clean_domain = domain.trim_byte('.');
    guard clean_domain.len > 0 else { return false; }
    return psl_is_public_suffix(clean_domain);
}

// Matches host against cookie domain (RFC 6265 Section 5.1.3).
fn cookie_domain_match(host: const u8[:], cookie_domain: const u8[:]) -> bool {
    guard host.len > 0 && cookie_domain.len > 0 else { return false; }

    let clean_host = host.trim_byte('.').trim_byte('[').trim_byte(']');
    let clean_domain = cookie_domain.trim_byte('.').trim_byte('[').trim_byte(']');
    guard clean_host.len > 0 && clean_domain.len > 0 else { return false; }

    if clean_host.eq_ascii_fold(clean_domain) {
        return true;
    }
    guard !core::is_ip_address_literal(clean_host) && !core::is_ip_address_literal(clean_domain) else {
        return false;
    }
    return core::ends_with_dot_suffix(clean_host, clean_domain);
}

// Overload taking an explicit PSL database: rejects cookie_domain if it is a public suffix
fn cookie_domain_match(db: const PslDatabase&, host: const u8[:], cookie_domain: const u8[:]) -> bool {
    guard host.len > 0 && cookie_domain.len > 0 else { return false; }
    guard !is_public_suffix(db, cookie_domain) else { return false; }
    return cookie_domain_match(host, cookie_domain);
}

// Computes the default cookie path from request URI path (RFC 6265 Section 5.1.4).
fn compute_default_cookie_path<B>(uri_path: const u8[:], out: B&) {
    out.clear();
    if uri_path.len == 0 || uri_path[0] != '/' {
        let _ = out.try_push('/');
        return;
    }
    let dir_prefix, _, has_slash = uri_path.rsplit_once_byte('/');
    if !has_slash || dir_prefix.len == 0 {
        let _ = out.try_push('/');
        return;
    }
    let bounded_len = min(dir_prefix.len, out.cap);
    let prefix = if bounded_len < dir_prefix.len {
        let trunc_dir, _, has_prev = uri_path[..bounded_len].rsplit_once_byte('/');
        if has_prev && trunc_dir.len > 0 { trunc_dir } else { "/" }
    } else {
        dir_prefix
    };
    let _ = out.try_set(prefix);
}

// Whether request path matches cookie path prefix (RFC 6265 Section 5.1.4).
fn cookie_path_match(req_path: const u8[:], cookie_path: const u8[:]) -> bool {
    let req = if req_path.len == 0 { "/" } else { req_path };
    let cpath = if cookie_path.len == 0 { "/" } else { cookie_path };

    if req == cpath { return true; }
    guard starts_with(req, cpath) else { return false; }
    if core::ends_with(cpath, "/") { return true; }
    return core::starts_with(req[cpath.len..], "/");
}

// ---- runtime updatable psl database ----------------------------------------

fn strip_psl_line_comment_or_space(line: const u8[:]) -> const u8[:] {
    let before_comment, _, _ = line.split_once("//");
    for i in before_comment.len {
        if core::is_ascii_space(before_comment[i]) {
            return before_comment[..i];
        }
    }
    return before_comment;
}

// Parses a Public Suffix List rule line into a PslRule.
//
// Example:
//   line = "*.co.uk", sec = PslSection.Icann
//   returns: true, out_rule.pattern = "co.uk"
fn parse_psl_rule_line(line: const u8[:], sec: PslSection, out_rule: PslRule&) -> bool {
    let clean = strip_psl_line_comment_or_space(line.trim_ascii_space());
    guard clean.len > 0 else { return false; }
    var is_exc = false;
    var is_wild = false;
    var pat = clean;

    if starts_with(pat, "!") {
        is_exc = true;
        pat = pat[1..];
    } else if starts_with(pat, "*.") {
        is_wild = true;
        pat = pat[2..];
    }
    guard pat.len > 0 && pat.len <= 64 && !is_invalid_psl_domain_syntax(pat) else {
        return false;
    }

    let r_type = if is_exc {
        PslRuleType.Exception
    } else if is_wild {
        PslRuleType.Wildcard
    } else {
        PslRuleType.Normal
    };

    let rule = new_psl_rule(pat, r_type, sec);
    guard rule.pattern.len > 0 else { return false; }
    out_rule = rule;
    return true;
}

// Ingests official Mozilla public suffix list format, preserving ICANN vs Private sections.
fn update_with_list(db: PslDatabase&, psl_text: const u8[:]) {
    var current_section = PslSection.Icann;
    var tok = core::make_byte_tokenizer(psl_text, '\n');
    loop {
        let raw_line, ok = core::token_next(tok);
        guard ok else { break; }
        let line = raw_line.trim_ascii_space();
        if core::starts_with(line, "// ===BEGIN ICANN DOMAINS===") {
            current_section = PslSection.Icann;
        } else if core::starts_with(line, "// ===BEGIN PRIVATE DOMAINS===") {
            current_section = PslSection.Private;
        } else {
            var rule = PslRule { .. };
            if parse_psl_rule_line(line, current_section, rule) {
                let _ = db.rules.try_push(rule);
            }
        }
    }
}
