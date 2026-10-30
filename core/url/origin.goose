// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Origin model, Public Suffix List (PSL) matching, and eTLD+1 extraction.
namespace core;

import std;

// ---- origin and site derivations -------------------------------------------

inline fn is_tuple_origin_scheme(s: const u8[:]) -> bool {
    return s == "http" || s == "https" || s == "ws" || s == "wss" || s == "ftp";
}

fn origin_from_url(url_val: const Url&) -> Origin {
    guard url_val.valid else { return new_opaque_origin(); }
    let scheme_str = scheme(url_val);

    if is_tuple_origin_scheme(scheme_str) {
        let eff_port = effective_port(url_val);
        return new_origin_tuple(scheme_str, hostname(url_val), eff_port);
    }

    if scheme_str == "blob" {
        // WHATWG URL Section 7.1: blob: URLs inherit the origin of the embedded URL in their path
        let inner_path = pathname(url_val);
        let inner_url, parse_err = parse_url(inner_path);
        guard inner_url.valid else { return new_opaque_origin(); }
        let inner_scheme = scheme(inner_url);
        if is_tuple_origin_scheme(inner_scheme) {
            let eff_port = effective_port(inner_url);
            return new_origin_tuple(inner_scheme, hostname(inner_url), eff_port);
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

fn is_ip_address_literal(host: const u8[:]) -> bool {
    guard host.len > 0 else { return false; }
    if contains_byte(host, ':') { return true; }
    return is_valid_ipv4_format(host);
}

fn ends_with_dot_suffix(domain: const u8[:], suffix: const u8[:]) -> bool {
    if domain.len > suffix.len && domain[domain.len - suffix.len - 1] == '.' {
        return eq_ascii_fold(domain[domain.len - suffix.len..], suffix);
    }
    return false;
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
        let prefix = domain[..domain.len - base_len - 1];
        let dot_before = last_index_of_byte(prefix, '.');
        let start = if dot_before >= 0 { dot_before + 1 } else { 0 };
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
        if ends_with_dot_suffix(domain, base) {
            extract_wildcard_suffix(domain, base, out);
            return true;
        }
    }
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
           suffix_str == "myshopify.com";
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

fn is_known_two_level_suffix(domain_suffix: const u8[:]) -> bool {
    return domain_suffix == "co.uk" || domain_suffix == "org.uk" || domain_suffix == "gov.uk" ||
           domain_suffix == "ac.uk" || domain_suffix == "net.uk" || domain_suffix == "me.uk" ||
           domain_suffix == "sch.uk" || domain_suffix == "com.au" || domain_suffix == "net.au" ||
           domain_suffix == "org.au" || domain_suffix == "edu.au" || domain_suffix == "gov.au" ||
           domain_suffix == "co.jp" || domain_suffix == "ne.jp" || domain_suffix == "or.jp" ||
           domain_suffix == "ac.jp" || domain_suffix == "go.jp" || domain_suffix == "ed.jp" ||
           domain_suffix == "co.nz" || domain_suffix == "net.nz" || domain_suffix == "org.nz" ||
           domain_suffix == "govt.nz" || domain_suffix == "ac.nz" || domain_suffix == "com.br" ||
           domain_suffix == "net.br" || domain_suffix == "org.br" || domain_suffix == "gov.br" ||
           domain_suffix == "co.in" || domain_suffix == "net.in" || domain_suffix == "org.in" ||
           domain_suffix == "gen.in" || domain_suffix == "gov.in" || domain_suffix == "ac.in" ||
           domain_suffix == "com.ru" || domain_suffix == "net.ru" || domain_suffix == "org.ru" ||
           domain_suffix == "pp.ru" || domain_suffix == "spb.ru" || domain_suffix == "msk.ru" ||
           domain_suffix == "gov.ru" || domain_suffix == "edu.ru" || domain_suffix == "com.cn" ||
           domain_suffix == "net.cn" || domain_suffix == "org.cn" || domain_suffix == "gov.cn" ||
           domain_suffix == "edu.cn" || domain_suffix == "com.tw" || domain_suffix == "org.tw" ||
           domain_suffix == "net.tw" || domain_suffix == "gov.tw" || domain_suffix == "edu.tw" ||
           domain_suffix == "co.kr" || domain_suffix == "ne.kr" || domain_suffix == "or.kr" ||
           domain_suffix == "go.kr" || domain_suffix == "ac.kr" || domain_suffix == "com.sg" ||
           domain_suffix == "edu.sg" || domain_suffix == "gov.sg" || domain_suffix == "net.sg" ||
           domain_suffix == "org.sg" || domain_suffix == "com.tr" || domain_suffix == "edu.tr" ||
           domain_suffix == "gov.tr" || domain_suffix == "org.tr" || domain_suffix == "net.tr" ||
           domain_suffix == "co.za" || domain_suffix == "net.za" || domain_suffix == "org.za" ||
           domain_suffix == "gov.za" || domain_suffix == "ac.za" || domain_suffix == "co.il" ||
           domain_suffix == "org.il" || domain_suffix == "net.il" || domain_suffix == "ac.il" ||
           domain_suffix == "gov.il" || domain_suffix == "fed.us" || domain_suffix == "state.us";
}

fn is_known_one_level_suffix(domain_suffix: const u8[:]) -> bool {
    return domain_suffix == "com" || domain_suffix == "org" || domain_suffix == "net" ||
           domain_suffix == "edu" || domain_suffix == "gov" || domain_suffix == "mil" ||
           domain_suffix == "io" || domain_suffix == "co" || domain_suffix == "ai" ||
           domain_suffix == "dev" || domain_suffix == "app" || domain_suffix == "ru" ||
           domain_suffix == "uk" || domain_suffix == "de" || domain_suffix == "fr" ||
           domain_suffix == "nl" || domain_suffix == "eu" || domain_suffix == "us" ||
           domain_suffix == "ca" || domain_suffix == "me" || domain_suffix == "xyz" ||
           domain_suffix == "info" || domain_suffix == "biz" || domain_suffix == "online" ||
           domain_suffix == "site" || domain_suffix == "store" || domain_suffix == "tech" ||
           domain_suffix == "cloud" || domain_suffix == "pro" || domain_suffix == "su" ||
           domain_suffix == "by" || domain_suffix == "kz" || domain_suffix == "ua" ||
           domain_suffix == "ch" || domain_suffix == "at" || domain_suffix == "se" ||
           domain_suffix == "no" || domain_suffix == "fi" || domain_suffix == "dk" ||
           domain_suffix == "pl" || domain_suffix == "cz" || domain_suffix == "jp" ||
           domain_suffix == "cn" || domain_suffix == "in" || domain_suffix == "br" ||
           domain_suffix == "mx" || domain_suffix == "au" || domain_suffix == "nz" ||
           domain_suffix == "za" || domain_suffix == "kr" || domain_suffix == "tw" ||
           domain_suffix == "hk" || domain_suffix == "sg" || domain_suffix == "local";
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

// Extracts the effective top-level domain plus one label (eTLD+1).
//
// Example:
//   host = "sub.example.co.uk"
//   appends: "example.co.uk"
fn extract_etld_plus_one<B>(host: const u8[:], out: B&) {
    out.clear();
    let clean_host = trim_byte(host, '.');
    guard clean_host.len > 0 && clean_host.len <= 256 else { return; }

    if is_ip_address_literal(clean_host) || count_byte(clean_host, '.') == 0 {
        out.try_append(clean_host);
        return;
    }

    var suffix: u8[..256] = [];
    compute_public_suffix(clean_host, suffix);

    if suffix.len == 0 || eq_ascii_fold(clean_host, suffix[..]) {
        out.try_append(clean_host);
        return;
    }

    let suffix_len = suffix.len;
    if clean_host.len > suffix_len && clean_host[clean_host.len - suffix_len - 1] == '.' {
        let prefix = clean_host[..clean_host.len - suffix_len - 1];
        let last_dot_in_prefix = last_index_of_byte(prefix, '.');
        let start_pos = if last_dot_in_prefix >= 0 { last_dot_in_prefix + 1 } else { 0 };
        out.try_append(clean_host[start_pos..]);
        to_lower(out[..]);
        return;
    }

    out.try_append(clean_host);
    to_lower(out[..]);
}

fn public_suffix_with_icann<B>(domain: const u8[:], out_suffix: B&) -> bool {
    out_suffix.clear();
    let clean_domain = trim_byte(domain, '.');
    guard clean_domain.len > 0 else { return false; }
    if is_ip_address_literal(clean_domain) { return false; }

    return compute_public_suffix(clean_domain, out_suffix);
}

fn registrable_site_from_url(url_val: const Url&) -> RegistrableSite {
    var site = RegistrableSite { .. };
    guard url_val.valid else { return site; }
    let scheme_str = scheme(url_val);
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

    let host_str = origin_val.host[..];
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
