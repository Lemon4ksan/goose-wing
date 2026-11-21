// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Origin model, Public Suffix List (PSL) matching, and eTLD+1 extraction.
namespace core;

import std;

// ---- origin and site derivations -------------------------------------------

inline fn is_tuple_origin_scheme(s: const u8[:]) -> bool {
    return s == "http" || s == "https" || s == "ws" || s == "wss" || s == "ftp";
}

// Formats an outgoing Host header wire string from a URL, stripping any IPv6 ZoneID (RFC 6874 §4).
//
// Example:
//   url_val = "http://[fe80::1%25eth0]:8080/path"
//   returns: out = "[fe80::1]:8080"
fn format_outgoing_host<B>(url_val: const Url&, out: B&) {
    out.clear();
    guard url_val.valid else { return; }
    let raw_h = hostname(url_val);
    strip_ipv6_zone_id(raw_h, out);
    let p_str = port_str(url_val);
    if p_str.len > 0 {
        out.push(':');
        out.append(p_str);
    }
}

fn origin_from_url(url_val: const Url&) -> Origin {
    guard url_val.valid else { return new_opaque_origin(); }
    let scheme_str = scheme(url_val);

    if is_tuple_origin_scheme(scheme_str) {
        let eff_port = effective_port(url_val);
        var clean_h: u8[..256] = [];
        strip_ipv6_zone_id(hostname(url_val), clean_h);
        return new_origin_tuple(scheme_str, clean_h[..], eff_port);
    }

    if scheme_str == "blob" {
        // WHATWG URL Section 7.1: blob: URLs inherit the origin of the embedded URL in their path
        let inner_path = pathname(url_val);
        let inner_url, parse_err = parse_url(inner_path);
        guard inner_url.valid else { return new_opaque_origin(); }
        let inner_scheme = scheme(inner_url);
        if is_tuple_origin_scheme(inner_scheme) {
            let eff_port = effective_port(inner_url);
            var clean_inner_h: u8[..256] = [];
            strip_ipv6_zone_id(hostname(inner_url), clean_inner_h);
            return new_origin_tuple(inner_scheme, clean_inner_h[..], eff_port);
        }
        return new_opaque_origin();
    }

    if scheme_str == "file" {
        return new_opaque_origin();
    }

    // data:, about: and unknown schemes produce opaque origins
    return new_opaque_origin();
}

// ---- public suffix & etld+1 extraction -------------------------------------

fn ends_with_dot_suffix(domain: const u8[:], suffix: const u8[:]) -> bool {
    let prefix, ok = strip_suffix_fold(domain, suffix);
    return ok && prefix.len > 0 && prefix[prefix.len - 1] == '.';
}

inline fn has_domain_suffix(domain: const u8[:], suffix: const u8[:]) -> bool {
    return domain == suffix || ends_with_dot_suffix(domain, suffix);
}

// Extracts a wildcard-matched domain suffix (e.g. for *.ck or *.kawasaki.jp).
//
// Example:
//   domain = "foo.bar.kawasaki.jp", base_rule = "kawasaki.jp"
//   appends: "bar.kawasaki.jp"
fn extract_wildcard_suffix<B>(domain: const u8[:], base_rule: const u8[:], out: B&) {
    let base_len = base_rule.len;
    if domain.len > base_len && domain[domain.len - base_len - 1] == '.' {
        let prefix = domain[..sub_sat_i64(sub_sat_i64(domain.len, base_len), 1)];
        let dot_before = last_index_of_byte(prefix, '.');
        let start = max(0, dot_before + 1);
        out.append(domain[start..]);
    } else {
        out.append(domain);
    }
}

struct PslException {
    pattern: const u8[:],
    suffix:  const u8[:],
}

fn is_known_exception_rule<B>(domain: const u8[:], out: B&) -> bool {
    let exceptions: PslException[8] = [
        PslException { pattern: "www.ck", suffix: "ck" },
        PslException { pattern: "city.kawasaki.jp", suffix: "kawasaki.jp" },
        PslException { pattern: "city.kitakyushu.jp", suffix: "kitakyushu.jp" },
        PslException { pattern: "city.kobe.jp", suffix: "kobe.jp" },
        PslException { pattern: "city.nagoya.jp", suffix: "nagoya.jp" },
        PslException { pattern: "city.sapporo.jp", suffix: "sapporo.jp" },
        PslException { pattern: "city.sendai.jp", suffix: "sendai.jp" },
        PslException { pattern: "city.yokohama.jp", suffix: "yokohama.jp" },
    ];
    for &rule in exceptions {
        if has_domain_suffix(domain, rule.pattern) {
            out.append(rule.suffix);
            return true;
        }
    }
    out.clear();
    return false;
}

fn is_known_wildcard_rule<B>(domain: const u8[:], out: B&) -> bool {
    let wildcards: const u8[:][5] = [
        "ck",
        "kawasaki.jp",
        "kobe.jp",
        "bd",
        "compute.amazonaws.com",
    ];
    for base in wildcards {
        if domain == base {
            out.append(base);
            return true;
        }
        if ends_with_dot_suffix(domain, base) {
            extract_wildcard_suffix(domain, base, out);
            return true;
        }
    }
    out.clear();
    return false;
}

fn is_known_three_level_suffix(suffix_str: const u8[:], is_icann: bool&) -> bool {
    if suffix_str == "blogspot.co.uk" || suffix_str == "s3.amazonaws.com" || suffix_str == "elb.amazonaws.com" {
        is_icann = false;
        return true;
    }
    return false;
}

fn is_known_private_two_level_suffix(suffix_str: const u8[:]) -> bool {
    return suffix_str == "github.io" ||
           suffix_str == "gitlab.io" ||
           suffix_str == "alwaysdata.net" ||
           suffix_str == "amazonaws.com" ||
           suffix_str == "dyndns.org" ||
           suffix_str == "blogspot.com" ||
           suffix_str == "vercel.app" ||
           suffix_str == "pages.dev" ||
           suffix_str == "workers.dev" ||
           suffix_str == "fly.dev" ||
           suffix_str == "deno.dev" ||
           suffix_str == "netlify.app" ||
           suffix_str == "herokuapp.com" ||
           suffix_str == "azurewebsites.net" ||
           suffix_str == "cloudfront.net" ||
           suffix_str == "myshopify.com" ||
           suffix_str == "onrender.com" ||
           suffix_str == "firebaseapp.com" ||
           suffix_str == "web.app" ||
           suffix_str == "run.app" ||
           suffix_str == "ngrok.io";
}

fn find_trailing_dot_positions(
    str_val:         const u8[:],
    last_dot:        i64&,
    second_last_dot: i64&,
    third_last_dot:  i64&,
) {
    for i in str_val.len {
        let idx = str_val.len - 1 - i;
        if str_val[idx] == '.' {
            if last_dot < 0 {
                last_dot = idx;
            } else if second_last_dot < 0 {
                second_last_dot = idx;
            } else {
                third_last_dot = idx;
                break;
            }
        }
    }
}

const KNOWN_TWO_LEVEL_SUFFIXES: const u8[:][78] = [
    "co.uk", "org.uk", "gov.uk", "ac.uk", "net.uk", "me.uk", "sch.uk",
    "com.au", "net.au", "org.au", "edu.au", "gov.au",
    "co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp", "ed.jp",
    "co.nz", "net.nz", "org.nz", "govt.nz", "ac.nz",
    "com.br", "net.br", "org.br", "gov.br",
    "co.in", "net.in", "org.in", "gen.in", "gov.in", "ac.in",
    "com.ru", "net.ru", "org.ru", "pp.ru", "spb.ru", "msk.ru", "gov.ru", "edu.ru",
    "com.cn", "net.cn", "org.cn", "gov.cn", "edu.cn",
    "com.tw", "org.tw", "net.tw", "gov.tw", "edu.tw",
    "co.kr", "ne.kr", "or.kr", "go.kr", "ac.kr",
    "com.sg", "edu.sg", "gov.sg", "net.sg", "org.sg",
    "com.tr", "edu.tr", "gov.tr", "org.tr", "net.tr",
    "co.za", "net.za", "org.za", "gov.za", "ac.za",
    "co.il", "org.il", "net.il", "ac.il", "gov.il",
    "fed.us", "state.us",
];

const KNOWN_ONE_LEVEL_SUFFIXES: const u8[:][54] = [
    "com", "org", "net", "edu", "gov", "mil", "io", "co", "ai",
    "dev", "app", "ru", "uk", "de", "fr", "nl", "eu", "us",
    "ca", "me", "xyz", "info", "biz", "online", "site", "store", "tech",
    "cloud", "pro", "su", "by", "kz", "ua", "ch", "at", "se",
    "no", "fi", "dk", "pl", "cz", "jp", "cn", "in", "br",
    "mx", "au", "nz", "za", "kr", "tw", "hk", "sg", "local",
];

fn is_known_two_level_suffix(domain_suffix: const u8[:]) -> bool {
    guard domain_suffix.len >= 5 && domain_suffix.len <= 8 else { return false; }
    for s in KNOWN_TWO_LEVEL_SUFFIXES {
        if s.len == domain_suffix.len && s == domain_suffix { return true; }
    }
    return false;
}

fn is_known_one_level_suffix(domain_suffix: const u8[:]) -> bool {
    guard domain_suffix.len >= 2 && domain_suffix.len <= 6 else { return false; }
    for s in KNOWN_ONE_LEVEL_SUFFIXES {
        if s.len == domain_suffix.len && s == domain_suffix { return true; }
    }
    return false;
}

fn check_known_explicit_suffix<B>(domain: const u8[:], out: B&, is_icann: bool&) -> bool {
    var dot3 = -1;
    var dot2 = -1;
    var dot1 = -1;
    find_trailing_dot_positions(domain, dot1, dot2, dot3);

    let tail3 = if dot3 >= 0 { domain[dot3 + 1..] } else { domain };
    if is_known_three_level_suffix(tail3, is_icann) {
        out.append(tail3);
        return true;
    }

    let tail2 = if dot2 >= 0 { domain[dot2 + 1..] } else { domain };
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

    let tail1 = if dot1 >= 0 { domain[dot1 + 1..] } else { domain };
    if is_known_one_level_suffix(tail1) {
        out.append(tail1);
        is_icann = true;
        return true;
    }

    out.clear();
    return false;
}

fn compute_public_suffix<B>(clean_domain: const u8[:], out: B&) -> bool {
    out.clear();
    guard clean_domain.len > 0 && clean_domain.len <= 256 else { return false; }

    var lower_domain: u8[..256] = [];
    lower_domain.append(clean_domain);
    to_lower(lower_domain[..]);
    let norm_domain = lower_domain[..];

    if is_known_exception_rule(norm_domain, out) {
        return true;
    }

    if is_known_wildcard_rule(norm_domain, out) {
        return true;
    }

    var is_icann = true;
    if check_known_explicit_suffix(norm_domain, out, is_icann) {
        return is_icann;
    }

    let last_dot_idx = last_index_of_byte(norm_domain, '.');
    if last_dot_idx >= 0 {
        out.append(norm_domain[last_dot_idx + 1..]);
    } else {
        out.append(norm_domain);
    }
    let is_icann_suffix = false;
    return is_icann_suffix;
}

// RFC 6265 Section 5.3: Storage Model - Reject bare public suffixes as registrable domains.
//
// Example:
//   host = "sub.example.co.uk"
//   appends: "example.co.uk"
fn extract_etld_plus_one<B>(host: const u8[:], out: B&) {
    out.clear();
    let trimmed = trim_byte(host, '.');
    guard trimmed.len > 0 && trimmed.len <= 256 && !contains(trimmed, "..") else { return; }
    var no_zone: u8[..256] = [];
    strip_ipv6_zone_id(trimmed, no_zone);
    let clean_host = no_zone[..];

    if is_ip_address_literal(clean_host) {
        let _ = out.try_append(clean_host);
        to_lower(out[..]);
        return;
    }

    if count_byte(clean_host, '.') == 0 {
        var lower_lbl: u8[..256] = [];
        guard lower_lbl.try_append(clean_host) else { return; }
        to_lower(lower_lbl[..]);
        if is_known_one_level_suffix(lower_lbl[..]) || lower_lbl[..] == "ck" || lower_lbl[..] == "bd" {
            return;
        }
        let _ = out.try_append(lower_lbl[..]);
        return;
    }

    var suffix: u8[..256] = [];
    compute_public_suffix(clean_host, suffix);
    guard suffix.len > 0 && !eq_ascii_fold(clean_host, suffix[..]) else { return; }

    let suffix_len = suffix.len;
    if clean_host.len > suffix_len && clean_host[clean_host.len - suffix_len - 1] == '.' {
        let prefix = clean_host[..sub_sat_i64(sub_sat_i64(clean_host.len, suffix_len), 1)];
        let last_dot_in_prefix = last_index_of_byte(prefix, '.');
        let start_pos = max(0, last_dot_in_prefix + 1);
        let _ = out.try_append(clean_host[start_pos..]);
        to_lower(out[..]);
    }
}

fn public_suffix_with_icann<B>(domain: const u8[:], out_suffix: B&) -> bool {
    out_suffix.clear();
    let clean_domain = trim_byte(domain, '.');
    guard clean_domain.len > 0 && !contains(clean_domain, "..") else { return false; }
    if is_ip_address_literal(clean_domain) { return false; }

    return compute_public_suffix(clean_domain, out_suffix);
}

fn registrable_site_from_url(url_val: const Url&) -> RegistrableSite {
    var site = RegistrableSite { .. };
    guard url_val.valid else { return site; }
    let scheme_str = scheme(url_val);
    if scheme_str == "blob" {
        let inner_url, _ = parse_url(pathname(url_val));
        guard inner_url.valid else { return site; }
        let inner_scheme = scheme(inner_url);
        guard is_tuple_origin_scheme(inner_scheme) else { return site; }
        site.scheme.append(inner_scheme);
        extract_etld_plus_one(hostname(inner_url), site.registrable_domain);
        return site;
    }
    site.scheme.append(scheme_str);

    let host_str = hostname(url_val);
    extract_etld_plus_one(host_str, site.registrable_domain);
    return site;
}

fn effective_origin_port(scheme_str: const u8[:], port: i32) -> i32 {
    if port >= 0 { return port; }
    return default_port_for_scheme(scheme_str);
}

fn is_same_origin(origin_a: Origin, origin_b: Origin) -> bool {
    if origin_a.kind == OriginKind.Opaque || origin_b.kind == OriginKind.Opaque {
        return origin_a.nonce != 0 && origin_a.nonce == origin_b.nonce;
    }
    let port_a = effective_origin_port(origin_a.scheme[..], origin_a.port);
    let port_b = effective_origin_port(origin_b.scheme[..], origin_b.port);
    return eq_ascii_fold(origin_a.scheme[..], origin_b.scheme[..]) &&
           eq_ascii_fold(origin_a.host[..], origin_b.host[..]) &&
           port_a == port_b;
}

fn is_same_origin_url(url_a: const Url&, url_b: const Url&) -> bool {
    let orig_a = origin_from_url(url_a);
    let orig_b = origin_from_url(url_b);
    return is_same_origin(orig_a, orig_b);
}

fn serialize_origin<B>(origin_val: Origin, out: B&) {
    out.clear();
    if origin_val.kind == OriginKind.Opaque {
        out.append("null");
        return;
    }
    out.append(origin_val.scheme[..]);
    out.append("://");

    var clean_host: u8[..256] = [];
    strip_ipv6_zone_id(origin_val.host[..], clean_host);
    let host_str = clean_host[..];
    if contains_byte(host_str, ':') && (host_str.len < 2 || host_str[0] != '[' || host_str[host_str.len - 1] != ']') {
        out.push('[');
        out.append(host_str);
        out.push(']');
    } else {
        out.append(host_str);
    }

    let scheme_str = origin_val.scheme[..];
    let def_port = default_port_for_scheme(scheme_str);
    let is_def_port = (origin_val.port < 0) || (def_port >= 0 && origin_val.port == def_port);
    if !is_def_port && origin_val.port >= 0 {
        out.push(':');
        format_i64_dec(origin_val.port as i64, out);
    }
}

fn is_schemeful_same_site_urls(url_a: const Url&, url_b: const Url&) -> bool {
    guard url_a.valid && url_b.valid else { return false; }
    let site_a = registrable_site_from_url(url_a);
    let site_b = registrable_site_from_url(url_b);
    guard site_a.registrable_domain.len > 0 && site_b.registrable_domain.len > 0 else {
        return false;
    }
    return eq_ascii_fold(site_a.scheme[..], site_b.scheme[..]) &&
           eq_ascii_fold(site_a.registrable_domain[..], site_b.registrable_domain[..]);
}

fn is_same_site_origin_url(origin_val: const Origin&, url_val: const Url&) -> bool {
    if origin_val.kind == OriginKind.Opaque || !url_val.valid { return false; }
    var orig_etld: u8[..256] = [];
    extract_etld_plus_one(origin_val.host[..], orig_etld);

    let site_url = registrable_site_from_url(url_val);
    guard orig_etld.len > 0 && site_url.registrable_domain.len > 0 else {
        return false;
    }
    return eq_ascii_fold(origin_val.scheme[..], site_url.scheme[..]) &&
           eq_ascii_fold(orig_etld[..], site_url.registrable_domain[..]);
}
