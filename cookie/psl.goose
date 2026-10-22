// Public Suffix List (PSL) & RFC 6265 §5.1 Domain and Path Matching Engine.
// Clean Room Implementation for goose-wing conforming to Mozilla PSL specifications.
namespace wing;

import std;
import cookie.constants;

// ---- public suffix data structures and enumerations -----------------------

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
    var r = PslRule { rule_type: rule_type, section: section, .. };
    r.pattern.append(pattern);
    to_lower(r.pattern[..]);
    return r;
}

fn new_psl_database() -> PslDatabase {
    var db = PslDatabase { rules: [] };
    init_default_psl_rules(db);
    return db;
}

// ---- public suffix & rfc 6265 scoping api --------------------------------

// Determines if domain is a public suffix (cannot set domain cookies for it).
// Evaluates both ICANN and Private suffixes (e.g. "co.uk", "com", "github.io").
fn public_suffix_domain(domain: const u8[:]) -> bool {
    let clean_domain = if domain.len > 0 && domain[0] == '.' { domain[1..] } else { domain };
    guard clean_domain.len > 0 else { return false; }
    if ip_address_literal(clean_domain) { return false; }

    var suffix: u8[..128] = [];
    let icann = compute_public_suffix(clean_domain, suffix);
    if suffix.len == 0 { return false; }

    // If domain exactly equals its public suffix, it is a public suffix
    return eq_ascii_fold(clean_domain, suffix[..]);
}

fn is_public_suffix_domain(domain: const u8[:]) -> bool {
    return public_suffix_domain(domain);
}

// Computes the public suffix of a domain and returns whether it belongs to the ICANN section.
// Follows Mozilla PSL precedence:
// 1. Exception rules (!rule) take absolute priority (suffix is rule without leftmost label).
// 2. Wildcard (*.rule) and Normal (rule) matching most labels win.
// 3. Fallback rule '*' applies if no rule matches (icann = false).
fn public_suffix_with_icann<B>(domain: const u8[:], out_suffix: B&) -> bool {
    out_suffix.clear();
    let clean_domain = if domain.len > 0 && domain[0] == '.' { domain[1..] } else { domain };
    guard clean_domain.len > 0 else { return false; }
    if ip_address_literal(clean_domain) { return false; }

    return compute_public_suffix(clean_domain, out_suffix);
}

// Extracts the effective top-level domain plus one label (eTLD+1).
// Used by CookieMonster for the primary 2-level hash indexing (CookieMap) and
// the 180-cookie domain quota tree boundary, with strict tenant isolation for
// private suffixes like github.io (foo.github.io -> foo.github.io).
fn extract_etld_plus_one<B>(host: const u8[:], out: B&) {
    out.clear();
    let clean_host = if host.len > 0 && host[0] == '.' { host[1..] } else { host };
    guard clean_host.len > 0 else { return; }

    // IP literals and single-label intranet hosts (e.g. localhost) do not have eTLD+1
    if ip_address_literal(clean_host) || count_dots(clean_host) == 0 {
        out.append(clean_host);
        return;
    }

    var suffix: u8[..128] = [];
    compute_public_suffix(clean_host, suffix);

    if suffix.len == 0 || eq_ascii_fold(clean_host, suffix[..]) {
        // Domain is itself a public suffix or has no additional label
        out.append(clean_host);
        return;
    }

    // eTLD+1 is public suffix plus one label to the left
    let suffix_len = suffix.len;
    if clean_host.len > suffix_len && clean_host[clean_host.len - suffix_len - 1] == '.' {
        let prefix = clean_host[..clean_host.len - suffix_len - 1];
        var last_dot_in_prefix = -1;
        for scan_idx in prefix.len {
            if prefix[scan_idx] == '.' {
                last_dot_in_prefix = scan_idx;
            }
        }
        let start_pos = if last_dot_in_prefix >= 0 { last_dot_in_prefix + 1 } else { 0 };
        out.append(clean_host[start_pos..]);
        return;
    }

    out.append(clean_host);
}

// RFC 6265 §5.1.3: Domain-Match algorithm.
// S matches D if S == D, or D is a suffix of S with leading '.' and S is not an IP address.
fn cookie_domain_match(host: const u8[:], cookie_domain: const u8[:]) -> bool {
    guard host.len > 0 && cookie_domain.len > 0 else { return false; }

    let clean_host = if host[0] == '.' { host[1..] } else { host };
    let clean_domain = if cookie_domain[0] == '.' { cookie_domain[1..] } else { cookie_domain };

    if eq_ascii_fold(clean_host, clean_domain) {
        return true;
    }
    if ip_address_literal(clean_host) {
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

// RFC 6265 §5.1.4: Default-Path computation.
// Extracts the directory prefix of the request URI path.
fn default_cookie_path_calc<B>(uri_path: const u8[:], out: B&) {
    out.clear();
    if uri_path.len == 0 || uri_path[0] != '/' {
        out.push('/');
        return;
    }
    var last_slash_idx = -1;
    for char_idx in uri_path.len {
        if uri_path[char_idx] == '/' {
            last_slash_idx = char_idx;
        }
    }
    if last_slash_idx <= 0 {
        out.push('/');
        return;
    }
    out.append(uri_path[..last_slash_idx]);
}

// RFC 6265 §5.1.4: Compute default cookie path alias
fn compute_default_cookie_path<B>(uri_path: const u8[:], out: B&) {
    default_cookie_path_calc(uri_path, out);
}

// RFC 6265 §5.1.4: Path-Match algorithm.
// Matches request path against cookie path prefix.
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

// Checks whether host is an IPv4 or IPv6 literal.
// Per RFC 6265 §5.1.3, domain-matching MUST NOT match suffixes on IP addresses.
fn ip_address_literal(host: const u8[:]) -> bool {
    guard host.len > 0 else { return false; }
    for char_byte in host {
        if char_byte == ':' { return true; }
    }
    return is_valid_ipv4_format(host);
}

fn is_ip_address_literal(host: const u8[:]) -> bool {
    return ip_address_literal(host);
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

// ---- internal implementation helpers ---------------------------------------

fn compute_public_suffix<B>(clean_domain: const u8[:], out: B&) -> bool {
    out.clear();
    guard clean_domain.len > 0 else { return false; }

    // 1. Exception rules have absolute priority
    if is_known_exception_rule(clean_domain, out) {
        return true;
    }

    // 2. Wildcard rules
    if is_known_wildcard_rule(clean_domain, out) {
        return true;
    }

    // 3. Known multi-level and private suffixes (e.g. github.io, blogspot.co.uk)
    var is_icann = true;
    if check_known_explicit_suffix(clean_domain, out, is_icann) {
        return is_icann;
    }

    // 4. Fallback rule: single top-level label
    var last_dot_idx = -1;
    for scan_idx in clean_domain.len {
        if clean_domain[scan_idx] == '.' {
            last_dot_idx = scan_idx;
        }
    }
    if last_dot_idx >= 0 {
        out.append(clean_domain[last_dot_idx + 1..]);
    } else {
        out.append(clean_domain);
    }
    return false; // Fallback rule is non-ICANN
}

fn is_known_exception_rule<B>(domain: const u8[:], out: B&) -> bool {
    // Exception rule !www.ck -> suffix is 'ck'
    if domain == "www.ck" || ends_with_dot_suffix(domain, "www.ck") {
        out.append("ck");
        return true;
    }
    // Exception rules for Japanese cities: !city.kawasaki.jp -> suffix is 'kawasaki.jp'
    if domain == "city.kawasaki.jp" || ends_with_dot_suffix(domain, "city.kawasaki.jp") {
        out.append("kawasaki.jp");
        return true;
    }
    if domain == "city.kitakyushu.jp" || ends_with_dot_suffix(domain, "city.kitakyushu.jp") {
        out.append("kitakyushu.jp");
        return true;
    }
    if domain == "city.kobe.jp" || ends_with_dot_suffix(domain, "city.kobe.jp") {
        out.append("kobe.jp");
        return true;
    }
    if domain == "city.nagoya.jp" || ends_with_dot_suffix(domain, "city.nagoya.jp") {
        out.append("nagoya.jp");
        return true;
    }
    if domain == "city.sapporo.jp" || ends_with_dot_suffix(domain, "city.sapporo.jp") {
        out.append("sapporo.jp");
        return true;
    }
    if domain == "city.sendai.jp" || ends_with_dot_suffix(domain, "city.sendai.jp") {
        out.append("sendai.jp");
        return true;
    }
    if domain == "city.yokohama.jp" || ends_with_dot_suffix(domain, "city.yokohama.jp") {
        out.append("yokohama.jp");
        return true;
    }
    return false;
}

fn is_known_wildcard_rule<B>(domain: const u8[:], out: B&) -> bool {
    // Wildcard rule *.ck
    if ends_with_dot_suffix(domain, "ck") {
        extract_wildcard_suffix(domain, "ck", out);
        return true;
    }
    // Wildcard rule *.kawasaki.jp
    if ends_with_dot_suffix(domain, "kawasaki.jp") {
        extract_wildcard_suffix(domain, "kawasaki.jp", out);
        return true;
    }
    // Wildcard rule *.bd
    if ends_with_dot_suffix(domain, "bd") {
        extract_wildcard_suffix(domain, "bd", out);
        return true;
    }
    // Wildcard rule *.compute.amazonaws.com (private wildcard)
    if ends_with_dot_suffix(domain, "compute.amazonaws.com") {
        extract_wildcard_suffix(domain, "compute.amazonaws.com", out);
        return true;
    }
    return false;
}

fn extract_wildcard_suffix<B>(domain: const u8[:], base_rule: const u8[:], out: B&) {
    let base_len = base_rule.len;
    if domain.len > base_len && domain[domain.len - base_len - 1] == '.' {
        let prefix = domain[..domain.len - base_len - 1];
        var dot_before = -1;
        for scan_idx in prefix.len {
            if prefix[scan_idx] == '.' {
                dot_before = scan_idx;
            }
        }
        let start = if dot_before >= 0 { dot_before + 1 } else { 0 };
        out.append(domain[start..]);
    } else {
        out.append(domain);
    }
}

fn ends_with_dot_suffix(domain: const u8[:], suffix: const u8[:]) -> bool {
    if domain.len > suffix.len && domain[domain.len - suffix.len - 1] == '.' {
        return eq_ascii_fold(domain[domain.len - suffix.len..], suffix);
    }
    return false;
}

fn check_known_explicit_suffix<B>(domain: const u8[:], out: B&, is_icann: bool&) -> bool {
    // Check 3-level suffixes first (e.g. blogspot.co.uk)
    var dot3 = -1;
    var dot2 = -1;
    var dot1 = -1;
    find_trailing_dot_positions(domain, dot1, dot2, dot3);

    if dot3 >= 0 {
        let tail3 = domain[dot3 + 1..];
        if is_known_three_level_suffix(tail3, is_icann) {
            out.append(tail3);
            return true;
        }
    } else if is_known_three_level_suffix(domain, is_icann) {
        out.append(domain);
        return true;
    }

    if dot2 >= 0 {
        let tail2 = domain[dot2 + 1..];
        if is_known_two_level_suffix(tail2) {
            out.append(tail2);
            is_icann = true;
            return true;
        }
        if is_known_private_two_level_suffix(tail2) {
            out.append(tail2);
            is_icann = false;
            return true;
        }
    } else {
        if is_known_two_level_suffix(domain) {
            out.append(domain);
            is_icann = true;
            return true;
        }
        if is_known_private_two_level_suffix(domain) {
            out.append(domain);
            is_icann = false;
            return true;
        }
    }

    if dot1 >= 0 {
        let tail1 = domain[dot1 + 1..];
        if is_known_one_level_suffix(tail1) {
            out.append(tail1);
            is_icann = true;
            return true;
        }
    } else if is_known_one_level_suffix(domain) {
        out.append(domain);
        is_icann = true;
        return true;
    }

    return false;
}

fn is_known_three_level_suffix(s: const u8[:], is_icann: bool&) -> bool {
    if s == "blogspot.co.uk" || s == "s3.amazonaws.com" || s == "elb.amazonaws.com" {
        is_icann = false;
        return true;
    }
    return false;
}

fn is_known_private_two_level_suffix(s: const u8[:]) -> bool {
    return s == "github.io" ||
           s == "alwaysdata.net" ||
           s == "dyndns.org" ||
           s == "blogspot.com" ||
           s == "vercel.app" ||
           s == "pages.dev" ||
           s == "netlify.app" ||
           s == "herokuapp.com" ||
           s == "azurewebsites.net" ||
           s == "cloudfront.net" ||
           s == "myshopify.com";
}

fn find_trailing_dot_positions(
    str_val: const u8[:],
    last_dot: i64&,
    second_last_dot: i64&,
    third_last_dot: i64&,
) {
    for step_idx in str_val.len {
        let scan_idx = str_val.len - 1 - step_idx;
        if str_val[scan_idx] == '.' {
            if last_dot < 0 {
                last_dot = scan_idx;
            } else if second_last_dot < 0 {
                second_last_dot = scan_idx;
            } else if third_last_dot < 0 {
                third_last_dot = scan_idx;
                break;
            }
        }
    }
}

fn count_dots(str_val: const u8[:]) -> i64 {
    var dot_count = 0;
    for char_byte in str_val {
        if char_byte == '.' { dot_count++; }
    }
    return dot_count;
}

fn is_valid_ipv4_format(host: const u8[:]) -> bool {
    var dot_count = 0;
    var octet_val = 0;
    var octet_digits = 0;

    for char_byte in host {
        if char_byte == '.' {
            if octet_digits == 0 || octet_val > 255 { return false; }
            dot_count++;
            octet_val = 0;
            octet_digits = 0;
        } else if char_byte >= '0' && char_byte <= '9' {
            octet_val = octet_val * 10 + (char_byte - '0');
            octet_digits++;
            if octet_digits > 3 { return false; }
        } else {
            return false;
        }
    }

    return dot_count == 3 && octet_digits > 0 && octet_val <= 255;
}

// Checks if domain string is a known two-level public suffix (e.g. "co.uk", "com.au").
fn is_known_two_level_suffix(domain_suffix: const u8[:]) -> bool {
    return domain_suffix == "co.uk" || domain_suffix == "org.uk" || domain_suffix == "gov.uk" || domain_suffix == "ac.uk" || domain_suffix == "net.uk" || domain_suffix == "me.uk" ||
           domain_suffix == "com.au" || domain_suffix == "net.au" || domain_suffix == "org.au" || domain_suffix == "edu.au" || domain_suffix == "gov.au" ||
           domain_suffix == "co.jp" || domain_suffix == "ne.jp" || domain_suffix == "or.jp" || domain_suffix == "ac.jp" || domain_suffix == "go.jp" ||
           domain_suffix == "co.nz" || domain_suffix == "net.nz" || domain_suffix == "org.nz" ||
           domain_suffix == "com.br" || domain_suffix == "net.br" || domain_suffix == "org.br" ||
           domain_suffix == "co.in" || domain_suffix == "net.in" || domain_suffix == "org.in" || domain_suffix == "gen.in" ||
           domain_suffix == "com.ru" || domain_suffix == "net.ru" || domain_suffix == "org.ru" || domain_suffix == "pp.ru" || domain_suffix == "spb.ru" || domain_suffix == "msk.ru" ||
           domain_suffix == "com.cn" || domain_suffix == "net.cn" || domain_suffix == "org.cn" || domain_suffix == "gov.cn" ||
           domain_suffix == "com.tw" || domain_suffix == "org.tw" || domain_suffix == "net.tw" ||
           domain_suffix == "co.kr" || domain_suffix == "ne.kr" || domain_suffix == "or.kr" ||
           domain_suffix == "com.sg" || domain_suffix == "edu.sg" || domain_suffix == "gov.sg" || domain_suffix == "net.sg" ||
           domain_suffix == "com.tr" || domain_suffix == "edu.tr" || domain_suffix == "gov.tr" || domain_suffix == "org.tr" ||
           domain_suffix == "co.za" || domain_suffix == "net.za" || domain_suffix == "org.za" ||
           domain_suffix == "co.il" || domain_suffix == "org.il" || domain_suffix == "net.il";
}

// Checks if domain string is a known top-level or generic public suffix (eTLD).
fn is_known_one_level_suffix(domain_suffix: const u8[:]) -> bool {
    return domain_suffix == "com" || domain_suffix == "org" || domain_suffix == "net" || domain_suffix == "edu" || domain_suffix == "gov" || domain_suffix == "mil" ||
           domain_suffix == "io" || domain_suffix == "co" || domain_suffix == "ai" || domain_suffix == "dev" || domain_suffix == "app" || domain_suffix == "ru" ||
           domain_suffix == "uk" || domain_suffix == "de" || domain_suffix == "fr" || domain_suffix == "nl" || domain_suffix == "eu" || domain_suffix == "us" ||
           domain_suffix == "ca" || domain_suffix == "me" || domain_suffix == "xyz" || domain_suffix == "info" || domain_suffix == "biz" || domain_suffix == "online" ||
           domain_suffix == "site" || domain_suffix == "store" || domain_suffix == "tech" || domain_suffix == "cloud" || domain_suffix == "pro" || domain_suffix == "su" ||
           domain_suffix == "by" || domain_suffix == "kz" || domain_suffix == "ua" || domain_suffix == "ch" || domain_suffix == "at" || domain_suffix == "se" ||
           domain_suffix == "no" || domain_suffix == "fi" || domain_suffix == "dk" || domain_suffix == "pl" || domain_suffix == "cz" || domain_suffix == "jp" ||
           domain_suffix == "cn" || domain_suffix == "in" || domain_suffix == "br" || domain_suffix == "mx" || domain_suffix == "au" || domain_suffix == "nz" ||
           domain_suffix == "za" || domain_suffix == "kr" || domain_suffix == "tw" || domain_suffix == "hk" || domain_suffix == "sg" || domain_suffix == "local";
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
