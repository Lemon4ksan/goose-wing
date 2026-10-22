// Public Suffix List (PSL) & RFC 6265 §5.1 Domain and Path Matching Engine.
// Clean Room Implementation for goose-wing.
namespace wing;

import std;
import cookie.constants;

// Checks whether host is an IPv4 or IPv6 literal.
// Per RFC 6265 §5.1.3, domain-matching MUST NOT match suffixes on IP addresses.
fn is_ip_address_literal(host: const u8[:]) -> bool {
    guard host.len > 0 else { return false; }

    // IPv6 literals contain colons
    for b in host {
        if b == ':' { return true; }
    }

    // IPv4 check: digits and dots only, exactly 3 dots, 4 valid octets [0..255]
    var dots = 0;
    var octet_val = 0;
    var octet_digits = 0;

    for b in host {
        if b == '.' {
            if octet_digits == 0 || octet_val > 255 { return false; }
            dots++;
            octet_val = 0;
            octet_digits = 0;
        } else if b >= '0' && b <= '9' {
            octet_val = octet_val * 10 + (b - '0');
            octet_digits++;
            if octet_digits > 3 { return false; }
        } else {
            return false;
        }
    }

    if dots != 3 || octet_digits == 0 || octet_val > 255 {
        return false;
    }
    return true;
}

// Checks if domain string is a known two-level public suffix (e.g. "co.uk", "com.au").
fn is_known_two_level_suffix(d: const u8[:]) -> bool {
    return d == "co.uk" || d == "org.uk" || d == "gov.uk" || d == "ac.uk" || d == "net.uk" || d == "me.uk" ||
           d == "com.au" || d == "net.au" || d == "org.au" || d == "edu.au" || d == "gov.au" ||
           d == "co.jp" || d == "ne.jp" || d == "or.jp" || d == "ac.jp" || d == "go.jp" ||
           d == "co.nz" || d == "net.nz" || d == "org.nz" ||
           d == "com.br" || d == "net.br" || d == "org.br" ||
           d == "co.in" || d == "net.in" || d == "org.in" || d == "gen.in" ||
           d == "com.ru" || d == "net.ru" || d == "org.ru" || d == "pp.ru" || d == "spb.ru" || d == "msk.ru" ||
           d == "com.cn" || d == "net.cn" || d == "org.cn" || d == "gov.cn" ||
           d == "com.tw" || d == "org.tw" || d == "net.tw" ||
           d == "co.kr" || d == "ne.kr" || d == "or.kr" ||
           d == "com.sg" || d == "edu.sg" || d == "gov.sg" || d == "net.sg" ||
           d == "com.tr" || d == "edu.tr" || d == "gov.tr" || d == "org.tr" ||
           d == "co.za" || d == "net.za" || d == "org.za" ||
           d == "co.il" || d == "org.il" || d == "net.il";
}

// Checks if domain string is a known top-level or generic public suffix (eTLD).
fn is_known_one_level_suffix(d: const u8[:]) -> bool {
    return d == "com" || d == "org" || d == "net" || d == "edu" || d == "gov" || d == "mil" ||
           d == "io" || d == "co" || d == "ai" || d == "dev" || d == "app" || d == "ru" ||
           d == "uk" || d == "de" || d == "fr" || d == "nl" || d == "eu" || d == "us" ||
           d == "ca" || d == "me" || d == "xyz" || d == "info" || d == "biz" || d == "online" ||
           d == "site" || d == "store" || d == "tech" || d == "cloud" || d == "pro" || d == "su" ||
           d == "by" || d == "kz" || d == "ua" || d == "ch" || d == "at" || d == "se" ||
           d == "no" || d == "fi" || d == "dk" || d == "pl" || d == "cz" || d == "jp" ||
           d == "cn" || d == "in" || d == "br" || d == "mx" || d == "au" || d == "nz" ||
           d == "za" || d == "kr" || d == "tw" || d == "hk" || d == "sg" || d == "local";
}

// Determines if domain is a public suffix (cannot set domain cookies for it).
fn is_public_suffix_domain(domain: const u8[:]) -> bool {
    let clean_dom = if domain.len > 0 && domain[0] == '.' { domain[1..] } else { domain };
    return is_known_two_level_suffix(clean_dom) || is_known_one_level_suffix(clean_dom);
}

// Extracts the effective top-level domain plus one label (eTLD+1).
// Used by CookieMonster for the primary 2-level hash indexing (CookieMap) and
// the 180-cookie domain quota tree boundary.
fn extract_etld_plus_one<B>(host: const u8[:], out: B&) {
    out.clear();
    let clean_host = if host.len > 0 && host[0] == '.' { host[1..] } else { host };
    guard clean_host.len > 0 else { return; }

    // IP literals and single-label intranet hosts (e.g. localhost) do not have eTLD+1
    if is_ip_address_literal(clean_host) {
        out.append(clean_host);
        return;
    }

    var dot_count = 0;
    for b in clean_host {
        if b == '.' { dot_count++; }
    }
    if dot_count == 0 {
        out.append(clean_host);
        return;
    }

    // Find dots from right to left
    var last_dot = -1;
    var second_last_dot = -1;
    var third_last_dot = -1;

    for i in clean_host.len {
        let idx = clean_host.len - 1 - i;
        if clean_host[idx] == '.' {
            if last_dot < 0 {
                last_dot = idx;
            } else if second_last_dot < 0 {
                second_last_dot = idx;
            } else if third_last_dot < 0 {
                third_last_dot = idx;
                break;
            }
        }
    }

    // Check two-level suffix (e.g. sub.example.co.uk -> co.uk is eTLD, example.co.uk is eTLD+1)
    if second_last_dot >= 0 {
        let candidate_2tld = clean_host[second_last_dot + 1..];
        if is_known_two_level_suffix(candidate_2tld) {
            let start_pos = if third_last_dot >= 0 { third_last_dot + 1 } else { 0 };
            out.append(clean_host[start_pos..]);
            return;
        }
    }

    // Check single-level suffix (e.g. sub.example.com -> com is eTLD, example.com is eTLD+1)
    if last_dot >= 0 {
        let candidate_1tld = clean_host[last_dot + 1..];
        if is_known_one_level_suffix(candidate_1tld) {
            let start_pos = if second_last_dot >= 0 { second_last_dot + 1 } else { 0 };
            out.append(clean_host[start_pos..]);
            return;
        }
    }

    // Fallback: return clean host
    out.append(clean_host);
}

// RFC 6265 §5.1.3: Domain-Match algorithm.
// S matches D if S == D, or D is a suffix of S with leading '.' and S is not an IP address.
fn cookie_domain_match(host: const u8[:], cookie_domain: const u8[:]) -> bool {
    guard host.len > 0 && cookie_domain.len > 0 else { return false; }

    let h = if host[0] == '.' { host[1..] } else { host };
    let d = if cookie_domain[0] == '.' { cookie_domain[1..] } else { cookie_domain };

    if eq_ascii_fold(h, d) {
        return true;
    }
    if is_ip_address_literal(h) {
        return false;
    }
    if h.len > d.len {
        let suffix_start = h.len - d.len;
        let suffix = h[suffix_start..];
        if eq_ascii_fold(suffix, d) {
            if h[suffix_start - 1] == '.' {
                return true;
            }
        }
    }
    return false;
}

// RFC 6265 §5.1.4: Default-Path computation.
// Extracts the path directory of request URI path.
fn default_cookie_path_calc<B>(uri_path: const u8[:], out: B&) {
    out.clear();
    if uri_path.len == 0 || uri_path[0] != '/' {
        out.push('/');
        return;
    }
    var last_slash = -1;
    for i in uri_path.len {
        if uri_path[i] == '/' {
            last_slash = i;
        }
    }
    if last_slash <= 0 {
        out.push('/');
        return;
    }
    out.append(uri_path[..last_slash]);
}

// RFC 6265 §5.1.4: Path-Match algorithm.
// Matches request path against cookie path prefix.
fn cookie_path_match(req_path: const u8[:], cookie_path: const u8[:]) -> bool {
    let r = if req_path.len == 0 { "/" } else { req_path };
    let c = if cookie_path.len == 0 { "/" } else { cookie_path };

    if r == c { return true; }
    if starts_with(r, c) {
        if c[c.len - 1] == '/' { return true; }
        if r.len > c.len && r[c.len] == '/' { return true; }
    }
    return false;
}
