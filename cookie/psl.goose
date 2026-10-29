// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Public Suffix List rules, eTLD+1 extraction, and domain/path matching (RFC 6265 Section 5.1).
namespace wing;

import std;
import core from "..";
import .constants;

// ---- public suffix data structures and enumerations ------------------------

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
    pattern: u8[..64] = [],
    rule_type: PslRuleType = PslRuleType.Normal,
    section: PslSection = PslSection.Icann,
}

struct PslDatabase {
    rules: PslRule[>..] = [],
}

fn psl_to_lower(s: u8[:]) {
    for i in s.len {
        s[i] = core::to_lower_ascii_byte(s[i]);
    }
}

fn new_psl_rule(pattern: const u8[:], rule_type: PslRuleType, section: PslSection) -> PslRule {
    var new_rule = PslRule { rule_type: rule_type, section: section, .. };
    new_rule.pattern.append(pattern);
    psl_to_lower(new_rule.pattern[..]);
    return new_rule;
}

fn add_psl_rule(db: PslDatabase&, pattern: const u8[:], rule_type: PslRuleType, section: PslSection) {
    db.rules.push(new_psl_rule(pattern, rule_type, section));
}

fn clear_psl_rules(db: PslDatabase&) {
    db.rules.clear();
}

fn count_rules(db: const PslDatabase&) -> i64 {
    return db.rules.len;
}

fn new_psl_database() -> PslDatabase {
    var db = PslDatabase { rules: [] };
    init_default_psl_rules(db);
    return db;
}

// ---- public suffix query and matching engine -------------------------------

// Normalizes domain: strips leading/trailing dots and converts to lowercase.
fn psl_normalize_domain<B>(domain: const u8[:], out: B&) -> bool {
    out.clear();
    let trimmed = core::trim_byte(domain, '.');
    guard trimmed.len > 0 && trimmed.len <= 256 else { return false; }
    out.append(trimmed);
    psl_to_lower(out[..]);
    return true;
}

fn psl_offset_add(base: i64, delta: i64) -> i64 {
    return base + delta;
}

fn psl_offset_sub(base: i64, delta: i64) -> i64 {
    return base - delta;
}

fn psl_labels_count(dots: i32, offset: i32) -> i32 {
    return dots + offset;
}

fn psl_match_exception(rule: const PslRule&, norm: const u8[:]) -> const u8[:] {
    if rule.rule_type != PslRuleType.Exception {
        return "";
    }
    let pat = rule.pattern[..];
    if norm != pat && !core::ends_with_dot_suffix(norm, pat) {
        return "";
    }
    let first_dot = core::index_of_byte(pat, '.');
    if first_dot < 0 {
        return pat;
    }
    let start = psl_offset_add(first_dot, 1);
    if start >= pat.len {
        return pat;
    }
    return pat[start..];
}

fn psl_match_normal(pat: const u8[:], norm: const u8[:], out_start: i64&, out_labels: i32&) -> bool {
    let pat_len = pat.len;
    let norm_len = norm.len;
    let dots = core::count_byte(pat, '.') as i32;
    let num_labels = psl_labels_count(dots, 1);
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
    let suffix_start = psl_offset_sub(norm_len, pat_len);
    out_start = suffix_start;
    out_labels = num_labels;
    return true;
}

fn psl_match_wildcard(pat: const u8[:], norm: const u8[:], out_start: i64&, out_labels: i32&) -> bool {
    let dots = core::count_byte(pat, '.') as i32;
    if norm == pat {
        out_start = 0;
        out_labels = psl_labels_count(dots, 1);
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
    let rem_len = psl_offset_sub(n_len, p_len);
    let prefix_len = psl_offset_sub(rem_len, 1);
    if prefix_len < 0 || prefix_len > n_len {
        return false;
    }
    let prefix = norm[..prefix_len];
    let last_dot = core::last_index_of_byte(prefix, '.');
    let next_dot = psl_offset_add(last_dot, 1);
    var start: i64 = 0;
    if last_dot >= 0 {
        start = next_dot;
    }
    let dots = core::count_byte(pat, '.') as i32;
    let num_labels = psl_labels_count(dots, 2);
    out_start = start;
    out_labels = num_labels;
    return true;
}

fn psl_find_best_rule(db: const PslDatabase&, norm: const u8[:], out_start: i64&, out_sec: PslSection&) -> bool {
    var best_labels: i32 = 0;
    var best_start: i64 = 0;
    var best_sec = PslSection.Icann;
    var found = false;

    for &rule in db.rules {
        var start_idx: i64 = 0;
        var labels: i32 = 0;
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

// Computes the Public Suffix for `domain` against `db` per Mozilla PSL specification.
// Returns (has_suffix, is_icann).
fn find_public_suffix<B>(db: const PslDatabase&, domain: const u8[:], out: B&) -> bool, bool {
    out.clear();
    var norm_buf: u8[..256] = [];
    if !psl_normalize_domain(domain, norm_buf) {
        return false, false;
    }
    let norm = norm_buf[..];
    if core::is_ip_address_literal(norm) {
        return false, false;
    }

    // 1. Exception rules take absolute precedence (!pattern)
    for &rule in db.rules {
        let exc_suffix = psl_match_exception(rule, norm);
        if exc_suffix.len > 0 {
            out.append(exc_suffix);
            return true, (rule.section == PslSection.Icann);
        }
    }

    // 2. Normal and Wildcard rules: select matching rule with the greatest number of labels
    var best_start: i64 = 0;
    var best_sec = PslSection.Icann;
    if psl_find_best_rule(db, norm, best_start, best_sec) {
        if best_start < 0 || best_start > norm.len {
            return false, false;
        }
        out.append(norm[best_start..]);
        return true, (best_sec == PslSection.Icann);
    }

    // 3. Fallback rule: if no rules match, the default rule is * (highest-level TLD)
    let last_dot = core::last_index_of_byte(norm, '.');
    let next_dot = psl_offset_add(last_dot, 1);
    var tld_start: i64 = 0;
    if last_dot >= 0 {
        tld_start = next_dot;
    }
    if tld_start < 0 || tld_start > norm.len {
        return false, false;
    }
    out.append(norm[tld_start..]);
    return true, true;
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

    return eq_ascii_fold(norm, suffix[..]);
}

fn psl_find_registrable_start(clean_host: const u8[:], suffix_len: i64) -> i64 {
    let host_len = clean_host.len;
    let min_needed = psl_offset_add(suffix_len, 1);
    if host_len <= min_needed {
        return 0;
    }
    let prefix_len = psl_offset_sub(host_len, min_needed);
    if prefix_len < 0 || prefix_len > host_len {
        return 0;
    }
    let prefix = clean_host[..prefix_len];
    let last_dot = core::last_index_of_byte(prefix, '.');
    let next_pos = psl_offset_add(last_dot, 1);
    if last_dot >= 0 {
        return next_pos;
    }
    return 0;
}

// Extracts the effective top-level domain plus one (eTLD+1 / registrable domain) using database.
fn extract_etld_plus_one<B>(db: const PslDatabase&, host: const u8[:], out: B&) {
    out.clear();
    var norm_buf: u8[..256] = [];
    guard psl_normalize_domain(host, norm_buf) else { return; }
    let clean_host = norm_buf[..];

    let has_dot = core::count_byte(clean_host, '.') > 0;
    guard has_dot && !core::is_ip_address_literal(clean_host) else {
        out.append(clean_host);
        return;
    }

    var suffix: u8[..256] = [];
    let ok, _ = find_public_suffix(db, clean_host, suffix);
    guard ok && suffix.len > 0 && !eq_ascii_fold(clean_host, suffix[..]) else {
        out.append(clean_host);
        return;
    }

    let start_pos = psl_find_registrable_start(clean_host, suffix.len);
    guard start_pos >= 0 && start_pos <= clean_host.len else {
        out.append(clean_host);
        return;
    }
    out.append(clean_host[start_pos..]);
}

// ---- public suffix & rfc 6265 scoping api ----------------------------------

// Whether domain is a public suffix (cannot set domain cookies for it).
fn is_public_suffix_domain(domain: const u8[:]) -> bool {
    let clean_domain = core::trim_byte(domain, '.');
    guard clean_domain.len > 0 else { return false; }
    if core::is_ip_address_literal(clean_domain) { return false; }

    var suffix: u8[..128] = [];
    core::compute_public_suffix(clean_domain, suffix);
    if suffix.len == 0 { return false; }

    // If domain exactly equals its public suffix, it is a public suffix
    return eq_ascii_fold(clean_domain, suffix[..]);
}

// Overload taking an explicit PSL database
fn is_public_suffix_domain(db: const PslDatabase&, domain: const u8[:]) -> bool {
    return is_public_suffix(db, domain);
}

// Matches host against cookie domain (RFC 6265 Section 5.1.3).
fn cookie_domain_match(host: const u8[:], cookie_domain: const u8[:]) -> bool {
    guard host.len > 0 && cookie_domain.len > 0 else { return false; }

    let clean_host = core::trim_byte(host, '.');
    let clean_domain = core::trim_byte(cookie_domain, '.');

    if eq_ascii_fold(clean_host, clean_domain) {
        return true;
    }
    guard !core::is_ip_address_literal(clean_host) else { return false; }
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
        out.push('/');
        return;
    }
    let last_slash_idx = core::last_index_of_byte(uri_path, '/');
    if last_slash_idx <= 0 {
        out.push('/');
        return;
    }
    out.append(uri_path[..last_slash_idx]);
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

fn parse_psl_rule_line(line: const u8[:], sec: PslSection, out_rule: PslRule&) -> bool {
    guard line.len > 0 && !(line.len >= 2 && line[0] == '/' && line[1] == '/') else { return false; }
    var is_exc = false;
    var is_wild = false;
    var pat = line;

    if starts_with(pat, "!") {
        is_exc = true;
        pat = pat[1..];
    } else if starts_with(pat, "*.") {
        is_wild = true;
        pat = pat[2..];
    }

    let r_type = if is_exc {
        PslRuleType.Exception
    } else if is_wild {
        PslRuleType.Wildcard
    } else {
        PslRuleType.Normal
    };

    out_rule = new_psl_rule(pat, r_type, sec);
    return true;
}

// Ingests official Mozilla public suffix list format, preserving ICANN vs Private sections.
fn update_with_list(db: PslDatabase&, psl_text: const u8[:]) {
    var current_section = PslSection.Icann;

    each_split(psl_text, '\n') { raw_line =>
        let line = trim(raw_line);
        if core::starts_with(line, "// ===BEGIN ICANN DOMAINS===") {
            current_section = PslSection.Icann;
        } else if core::starts_with(line, "// ===BEGIN PRIVATE DOMAINS===") {
            current_section = PslSection.Private;
        } else {
            var rule = PslRule { .. };
            if parse_psl_rule_line(line, current_section, rule) {
                db.rules.push(rule);
            }
        }
    };
}

fn init_default_psl_rules(db: PslDatabase&) {
    // 1. Generic & infrastructure TLDs (ICANN)
    db.rules.push(new_psl_rule("com", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("org", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("net", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("edu", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("gov", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("mil", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("int", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("arpa", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("io", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("ai", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("co", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("dev", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("app", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("xyz", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("info", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("biz", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("online", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("site", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("store", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("tech", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("cloud", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("pro", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("me", PslRuleType.Normal, PslSection.Icann));

    // 2. Major Country-Code TLDs (ICANN)
    db.rules.push(new_psl_rule("uk", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("de", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("fr", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("nl", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("eu", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("us", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("ca", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("ru", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("su", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("by", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("kz", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("ua", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("ch", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("at", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("se", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("no", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("fi", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("dk", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("pl", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("cz", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("jp", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("cn", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("in", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("br", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("mx", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("au", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("nz", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("za", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("kr", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("tw", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("hk", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("sg", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("il", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("tr", PslRuleType.Normal, PslSection.Icann));

    // 3. Multi-level ccTLD rules (ICANN)
    db.rules.push(new_psl_rule("co.uk", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("org.uk", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("gov.uk", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("ac.uk", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("net.uk", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("me.uk", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("sch.uk", PslRuleType.Normal, PslSection.Icann));

    db.rules.push(new_psl_rule("com.au", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("net.au", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("org.au", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("edu.au", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("gov.au", PslRuleType.Normal, PslSection.Icann));

    db.rules.push(new_psl_rule("co.jp", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("ne.jp", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("or.jp", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("ac.jp", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("go.jp", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("ed.jp", PslRuleType.Normal, PslSection.Icann));

    db.rules.push(new_psl_rule("co.nz", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("net.nz", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("org.nz", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("govt.nz", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("ac.nz", PslRuleType.Normal, PslSection.Icann));

    db.rules.push(new_psl_rule("com.br", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("net.br", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("org.br", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("gov.br", PslRuleType.Normal, PslSection.Icann));

    db.rules.push(new_psl_rule("co.in", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("net.in", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("org.in", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("gen.in", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("gov.in", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("ac.in", PslRuleType.Normal, PslSection.Icann));

    db.rules.push(new_psl_rule("com.ru", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("net.ru", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("org.ru", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("pp.ru", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("spb.ru", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("msk.ru", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("gov.ru", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("edu.ru", PslRuleType.Normal, PslSection.Icann));

    db.rules.push(new_psl_rule("com.cn", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("net.cn", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("org.cn", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("gov.cn", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("edu.cn", PslRuleType.Normal, PslSection.Icann));

    db.rules.push(new_psl_rule("com.tw", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("org.tw", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("net.tw", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("gov.tw", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("edu.tw", PslRuleType.Normal, PslSection.Icann));

    db.rules.push(new_psl_rule("co.kr", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("ne.kr", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("or.kr", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("go.kr", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("ac.kr", PslRuleType.Normal, PslSection.Icann));

    db.rules.push(new_psl_rule("com.sg", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("edu.sg", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("gov.sg", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("net.sg", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("org.sg", PslRuleType.Normal, PslSection.Icann));

    db.rules.push(new_psl_rule("com.tr", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("edu.tr", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("gov.tr", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("org.tr", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("net.tr", PslRuleType.Normal, PslSection.Icann));

    db.rules.push(new_psl_rule("co.za", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("net.za", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("org.za", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("gov.za", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("ac.za", PslRuleType.Normal, PslSection.Icann));

    db.rules.push(new_psl_rule("co.il", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("org.il", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("net.il", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("ac.il", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("gov.il", PslRuleType.Normal, PslSection.Icann));

    db.rules.push(new_psl_rule("fed.us", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("state.us", PslRuleType.Normal, PslSection.Icann));

    // 4. Wildcards & Exceptions
    db.rules.push(new_psl_rule("ck", PslRuleType.Wildcard, PslSection.Icann));
    db.rules.push(new_psl_rule("www.ck", PslRuleType.Exception, PslSection.Icann));

    db.rules.push(new_psl_rule("kawasaki.jp", PslRuleType.Wildcard, PslSection.Icann));
    db.rules.push(new_psl_rule("city.kawasaki.jp", PslRuleType.Exception, PslSection.Icann));

    db.rules.push(new_psl_rule("kobe.jp", PslRuleType.Wildcard, PslSection.Icann));
    db.rules.push(new_psl_rule("city.kobe.jp", PslRuleType.Exception, PslSection.Icann));

    db.rules.push(new_psl_rule("bd", PslRuleType.Wildcard, PslSection.Icann));
    db.rules.push(new_psl_rule("np", PslRuleType.Wildcard, PslSection.Icann));

    // 5. Private Section (Hosting, PaaS, multi-tenant isolation)
    db.rules.push(new_psl_rule("github.io", PslRuleType.Normal, PslSection.Private));
    db.rules.push(new_psl_rule("gitlab.io", PslRuleType.Normal, PslSection.Private));
    db.rules.push(new_psl_rule("pages.dev", PslRuleType.Normal, PslSection.Private));
    db.rules.push(new_psl_rule("workers.dev", PslRuleType.Normal, PslSection.Private));
    db.rules.push(new_psl_rule("vercel.app", PslRuleType.Normal, PslSection.Private));
    db.rules.push(new_psl_rule("netlify.app", PslRuleType.Normal, PslSection.Private));
    db.rules.push(new_psl_rule("herokuapp.com", PslRuleType.Normal, PslSection.Private));
    db.rules.push(new_psl_rule("azurewebsites.net", PslRuleType.Normal, PslSection.Private));
    db.rules.push(new_psl_rule("cloudfront.net", PslRuleType.Normal, PslSection.Private));
    db.rules.push(new_psl_rule("s3.amazonaws.com", PslRuleType.Normal, PslSection.Private));
    db.rules.push(new_psl_rule("elb.amazonaws.com", PslRuleType.Normal, PslSection.Private));
    db.rules.push(new_psl_rule("compute.amazonaws.com", PslRuleType.Wildcard, PslSection.Private));
    db.rules.push(new_psl_rule("fly.dev", PslRuleType.Normal, PslSection.Private));
    db.rules.push(new_psl_rule("deno.dev", PslRuleType.Normal, PslSection.Private));
    db.rules.push(new_psl_rule("myshopify.com", PslRuleType.Normal, PslSection.Private));
    db.rules.push(new_psl_rule("blogspot.com", PslRuleType.Normal, PslSection.Private));
    db.rules.push(new_psl_rule("blogspot.co.uk", PslRuleType.Normal, PslSection.Private));
    db.rules.push(new_psl_rule("alwaysdata.net", PslRuleType.Normal, PslSection.Private));
    db.rules.push(new_psl_rule("dyndns.org", PslRuleType.Normal, PslSection.Private));
}
