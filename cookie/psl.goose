// Public Suffix List rules, eTLD+1 extraction, and domain/path matching (RFC 6265 Section 5.1).
namespace wing;

import std;
import cookie.constants;

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

fn new_psl_rule(pattern: const u8[:], rule_type: PslRuleType, section: PslSection) -> PslRule {
    var new_rule = PslRule { rule_type: rule_type, section: section, .. };
    new_rule.pattern.append(pattern);
    to_lower(new_rule.pattern[..]);
    return new_rule;
}

fn new_psl_database() -> PslDatabase {
    var db = PslDatabase { rules: [] };
    init_default_psl_rules(db);
    return db;
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

// Matches host against cookie domain (RFC 6265 Section 5.1.3).
fn cookie_domain_match(host: const u8[:], cookie_domain: const u8[:]) -> bool {
    guard host.len > 0 && cookie_domain.len > 0 else { return false; }

    let clean_host = core::trim_byte(host, '.');
    let clean_domain = core::trim_byte(cookie_domain, '.');

    if eq_ascii_fold(clean_host, clean_domain) {
        return true;
    }
    if core::is_ip_address_literal(clean_host) {
        return false;
    }
    if clean_host.len > clean_domain.len {
        let suffix_start = clean_host.len - clean_domain.len;
        let suffix = clean_host[suffix_start..];
        if eq_ascii_fold(suffix, clean_domain) && clean_host[suffix_start - 1] == '.' {
            return true;
        }
    }
    return false;
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
    let normalized_req_path = if req_path.len == 0 { "/" } else { req_path };
    let normalized_cookie_path = if cookie_path.len == 0 { "/" } else { cookie_path };

    if normalized_req_path == normalized_cookie_path { return true; }
    if starts_with(normalized_req_path, normalized_cookie_path) {
        if normalized_cookie_path[normalized_cookie_path.len - 1] == '/' { return true; }
        if normalized_req_path.len > normalized_cookie_path.len && normalized_req_path[normalized_cookie_path.len] == '/' {
            return true;
        }
    }
    return false;
}

// ---- runtime updatable psl database ----------------------------------------

fn update_with_list(db: PslDatabase&, psl_text: const u8[:]) {
    each_split(psl_text, '\n') { raw_line =>
        let line = trim(raw_line);
        if line.len > 0 && !(line.len >= 2 && line[0] == '/' && line[1] == '/') {
            var is_priv = false;
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

            let r_type = if is_exc { PslRuleType.Exception } else if is_wild { PslRuleType.Wildcard } else { PslRuleType.Normal };
            let sec = if is_priv { PslSection.Private } else { PslSection.Icann };
            db.rules.push(new_psl_rule(pat, r_type, sec));
        }
    };
}

fn count_rules(db: const PslDatabase&) -> i64 {
    return db.rules.len;
}

fn init_default_psl_rules(db: PslDatabase&) {
    db.rules.push(new_psl_rule("com", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("org", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("net", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("co.uk", PslRuleType.Normal, PslSection.Icann));
    db.rules.push(new_psl_rule("ck", PslRuleType.Wildcard, PslSection.Icann));
    db.rules.push(new_psl_rule("www.ck", PslRuleType.Exception, PslSection.Icann));
    db.rules.push(new_psl_rule("github.io", PslRuleType.Normal, PslSection.Private));
    db.rules.push(new_psl_rule("alwaysdata.net", PslRuleType.Normal, PslSection.Private));
}
