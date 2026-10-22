// Public Suffix List (PSL) & RFC 6265 §5.1 Domain and Path Matching Engine.
// Clean Room Implementation for goose-wing.
namespace wing;

import std;
import cookie.constants;

// ---- public suffix & rfc 6265 scoping api --------------------------------

// Determines if domain is a public suffix (cannot set domain cookies for it).
fn public_suffix_domain(domain: const u8[:]) -> bool {
    let clean_domain = if domain.len > 0 && domain[0] == '.' { domain[1..] } else { domain };
    return is_known_two_level_suffix(clean_domain) || is_known_one_level_suffix(clean_domain);
}

fn is_public_suffix_domain(domain: const u8[:]) -> bool {
    return public_suffix_domain(domain);
}

// Extracts the effective top-level domain plus one label (eTLD+1).
// Used by CookieMonster for the primary 2-level hash indexing (CookieMap) and
// the 180-cookie domain quota tree boundary.
fn extract_etld_plus_one<B>(host: const u8[:], out: B&) {
    out.clear();
    let clean_host = if host.len > 0 && host[0] == '.' { host[1..] } else { host };
    guard clean_host.len > 0 else { return; }

    // IP literals and single-label intranet hosts (e.g. localhost) do not have eTLD+1
    if ip_address_literal(clean_host) || count_dots(clean_host) == 0 {
        out.append(clean_host);
        return;
    }

    var last_dot = -1;
    var second_last_dot = -1;
    var third_last_dot = -1;
    find_trailing_dot_positions(clean_host, last_dot, second_last_dot, third_last_dot);

    let start_pos = find_etld_start(clean_host, last_dot, second_last_dot, third_last_dot);
    out.append(clean_host[start_pos..]);
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

// ---- internal implementation helpers ---------------------------------------

fn find_etld_start(clean_host: const u8[:], last_dot: i64, second_last_dot: i64, third_last_dot: i64) -> i64 {
    if second_last_dot >= 0 && is_known_two_level_suffix(clean_host[second_last_dot + 1..]) {
        return if third_last_dot >= 0 { third_last_dot + 1 } else { 0 };
    }
    if last_dot >= 0 && is_known_one_level_suffix(clean_host[last_dot + 1..]) {
        return if second_last_dot >= 0 { second_last_dot + 1 } else { 0 };
    }
    return 0;
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
