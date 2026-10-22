// WHATWG Canonical URL, Origin Security Model & RegistrableSite Engine.
// RFC 3986, RFC 5952, RFC 5890, and Chromium url::Origin / url::SchemeHostPort.
namespace wing;

import std;
import cookie.psl;

// ---- url parse errors and enumerations --------------------------------------

enum UrlParseError {
    None,
    EmptyInput,
    InvalidScheme,
    MissingHost,
    InvalidHost,
    InvalidIpv6,
    InvalidPort,
    ForbiddenHostCodePoint,
    RelativeWithoutBase,
    OpaqueBaseCannotResolveRelative,
}

fn is_ok(err: UrlParseError) -> bool {
    return err == UrlParseError.None;
}

// ---- canonical url model with single buffer & index offsets ----------------

// Url represents a canonical WHATWG URL with a single normalized contiguous buffer
// (href) and compact index offsets, eliminating substring heap allocations.
struct Url {
    href: u8[..512] = [],
    scheme_end: i32 = -1,     // Index of ':' separating scheme
    username_start: i32 = -1,
    username_end: i32 = -1,
    password_start: i32 = -1,
    password_end: i32 = -1,
    host_start: i32 = -1,
    host_end: i32 = -1,
    port_start: i32 = -1,
    port_end: i32 = -1,
    pathname_start: i32 = -1,
    pathname_end: i32 = -1,
    search_start: i32 = -1,
    search_end: i32 = -1,
    hash_start: i32 = -1,
    hash_end: i32 = -1,
    port: i32 = -1,           // -1 if omitted or default
    is_special: bool = false,
    has_opaque_path: bool = false,
    valid: bool = false,
}

// ---- origin and registrable site models ------------------------------------

enum OriginKind {
    Tuple,
    Opaque,
}

struct Origin {
    kind: OriginKind = OriginKind.Tuple,
    scheme: u8[..16] = [],
    host: u8[..256] = [],
    port: i32 = -1,
    nonce: u64 = 0,
}

struct RegistrableSite {
    scheme: u8[..16] = [],
    registrable_domain: u8[..128] = [],
}

// Global monotonic nonce generator for opaque origins
var g_opaque_nonce_counter: u64 = 1;

fn new_opaque_origin() -> Origin {
    var orig = Origin { kind: OriginKind.Opaque, nonce: g_opaque_nonce_counter, .. };
    g_opaque_nonce_counter += 1;
    return orig;
}

fn new_origin_tuple(scheme: const u8[:], host: const u8[:], port: i32) -> Origin {
    var orig = Origin { kind: OriginKind.Tuple, port: port, .. };
    orig.scheme.append(scheme);
    to_lower(orig.scheme[..]);
    orig.host.append(host);
    to_lower(orig.host[..]);
    return orig;
}

// ---- parsing factories and api ---------------------------------------------

fn parse_url(raw_input: const u8[:]) -> Url, UrlParseError {
    let dummy_base = Url { valid: false, .. };
    return parse_url_internal(raw_input, dummy_base, false);
}

fn parse_url_with_base(raw_input: const u8[:], base_url: const Url&) -> Url, UrlParseError {
    return parse_url_internal(raw_input, base_url, base_url.valid);
}

fn new_url(raw_input: const u8[:]) -> Url {
    let u, err = parse_url(raw_input);
    return u;
}

fn new_url(raw_input: const u8[:], base_url: const Url&) -> Url {
    let u, err = parse_url_with_base(raw_input, base_url);
    return u;
}

// ---- url component accessors (ufcs friendly) -------------------------------

fn href(url_val: const Url&) -> const u8[:] {
    guard url_val.valid else { return ""; }
    return url_val.href[..];
}

fn scheme(url_val: const Url&) -> const u8[:] {
    guard url_val.valid && url_val.scheme_end > 0 else { return ""; }
    return url_val.href[..url_val.scheme_end];
}

fn username(url_val: const Url&) -> const u8[:] {
    guard url_val.valid && url_val.username_start >= 0 && url_val.username_end >= url_val.username_start else { return ""; }
    return url_val.href[url_val.username_start..url_val.username_end];
}

fn password(url_val: const Url&) -> const u8[:] {
    guard url_val.valid && url_val.password_start >= 0 && url_val.password_end >= url_val.password_start else { return ""; }
    return url_val.href[url_val.password_start..url_val.password_end];
}

fn has_credentials(url_val: const Url&) -> bool {
    return username(url_val).len > 0 || password(url_val).len > 0;
}

fn hostname(url_val: const Url&) -> const u8[:] {
    guard url_val.valid && url_val.host_start >= 0 && url_val.host_end >= url_val.host_start else { return ""; }
    return url_val.href[url_val.host_start..url_val.host_end];
}

fn host(url_val: const Url&) -> const u8[:] {
    guard url_val.valid && url_val.host_start >= 0 else { return ""; }
    let end_pos = if url_val.port_end > url_val.host_end { url_val.port_end } else { url_val.host_end };
    return url_val.href[url_val.host_start..end_pos];
}

fn port_str(url_val: const Url&) -> const u8[:] {
    guard url_val.valid && url_val.port_start >= 0 && url_val.port_end > url_val.port_start else { return ""; }
    return url_val.href[url_val.port_start + 1..url_val.port_end];
}

fn effective_port(url_val: const Url&) -> i32 {
    guard url_val.valid else { return -1; }
    if url_val.port > 0 { return url_val.port; }
    let s = scheme(url_val);
    if s == "http" || s == "ws" { return 80; }
    if s == "https" || s == "wss" { return 443; }
    if s == "ftp" { return 21; }
    return -1;
}

fn pathname(url_val: const Url&) -> const u8[:] {
    guard url_val.valid && url_val.pathname_start >= 0 && url_val.pathname_end >= url_val.pathname_start else {
        return if url_val.is_special { "/" } else { "" };
    }
    return url_val.href[url_val.pathname_start..url_val.pathname_end];
}

fn search(url_val: const Url&) -> const u8[:] {
    guard url_val.valid && url_val.search_start >= 0 && url_val.search_end >= url_val.search_start else { return ""; }
    return url_val.href[url_val.search_start..url_val.search_end];
}

fn hash(url_val: const Url&) -> const u8[:] {
    guard url_val.valid && url_val.hash_start >= 0 && url_val.hash_end >= url_val.hash_start else { return ""; }
    return url_val.href[url_val.hash_start..url_val.hash_end];
}

fn is_special(url_val: const Url&) -> bool {
    return url_val.valid && url_val.is_special;
}

fn is_http_or_https(url_val: const Url&) -> bool {
    guard url_val.valid else { return false; }
    let s = scheme(url_val);
    return s == "http" || s == "https";
}

fn is_secure_scheme(url_val: const Url&) -> bool {
    guard url_val.valid else { return false; }
    let s = scheme(url_val);
    return s == "https" || s == "wss";
}

// ---- origin and site derivations -------------------------------------------

fn origin_from_url(url_val: const Url&) -> Origin {
    guard url_val.valid else { return new_opaque_origin(); }
    let s = scheme(url_val);

    if s == "http" || s == "https" || s == "ws" || s == "wss" || s == "ftp" {
        let eff_port = effective_port(url_val);
        return new_origin_tuple(s, hostname(url_val), eff_port);
    }

    if s == "file" {
        return new_opaque_origin();
    }

    // data:, blob:, about: and unknown schemes produce opaque origins
    return new_opaque_origin();
}

fn registrable_site_from_url(url_val: const Url&) -> RegistrableSite {
    var site = RegistrableSite { .. };
    guard url_val.valid else { return site; }
    let s = scheme(url_val);
    site.scheme.append(s);

    let h = hostname(url_val);
    extract_etld_plus_one(h, site.registrable_domain);
    return site;
}

fn is_same_origin(origin_a: const Origin&, origin_b: const Origin&) -> bool {
    if origin_a.kind == OriginKind.Opaque || origin_b.kind == OriginKind.Opaque {
        return origin_a.nonce != 0 && origin_a.nonce == origin_b.nonce;
    }
    return eq_ascii_fold(origin_a.scheme[..], origin_b.scheme[..]) &&
           eq_ascii_fold(origin_a.host[..], origin_b.host[..]) &&
           origin_a.port == origin_b.port;
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
    out.append(origin_val.host[..]);

    let s = origin_val.scheme[..];
    let is_def_port = (s == "http" && origin_val.port == 80) ||
                      (s == "https" && origin_val.port == 443) ||
                      (s == "ws" && origin_val.port == 80) ||
                      (s == "wss" && origin_val.port == 443) ||
                      (s == "ftp" && origin_val.port == 21) ||
                      (origin_val.port <= 0);
    if !is_def_port {
        out.push(':');
        format(out, origin_val.port as i64);
    }
}

fn is_schemeful_same_site_urls(url_a: const Url&, url_b: const Url&) -> bool {
    guard url_a.valid && url_b.valid else { return false; }
    let site_a = registrable_site_from_url(url_a);
    let site_b = registrable_site_from_url(url_b);
    return eq_ascii_fold(site_a.scheme[..], site_b.scheme[..]) &&
           eq_ascii_fold(site_a.registrable_domain[..], site_b.registrable_domain[..]);
}

fn is_same_site_origin_url(origin_val: const Origin&, url_val: const Url&) -> bool {
    if origin_val.kind == OriginKind.Opaque || !url_val.valid { return false; }
    var orig_etld: u8[..128] = [];
    extract_etld_plus_one(origin_val.host[..], orig_etld);

    let site_url = registrable_site_from_url(url_val);
    return eq_ascii_fold(origin_val.scheme[..], site_url.scheme[..]) &&
           eq_ascii_fold(orig_etld[..], site_url.registrable_domain[..]);
}

// ---- internal whatwg url parser implementation -----------------------------

fn is_special_scheme(scheme_str: const u8[:]) -> bool {
    return scheme_str == "http" ||
           scheme_str == "https" ||
           scheme_str == "ws" ||
           scheme_str == "wss" ||
           scheme_str == "file" ||
           scheme_str == "ftp";
}

fn default_port_for_scheme(scheme_str: const u8[:]) -> i32 {
    if scheme_str == "http" || scheme_str == "ws" { return 80; }
    if scheme_str == "https" || scheme_str == "wss" { return 443; }
    if scheme_str == "ftp" { return 21; }
    return -1;
}

// Fast-path pre-cleaner: trims C0 controls and spaces (<= 0x20) and strips 0x09, 0x0A, 0x0D
fn clean_input_string<B>(raw: const u8[:], out: B&) {
    out.clear();
    var start_idx = 0;
    while start_idx < raw.len && raw[start_idx] <= 0x20 {
        start_idx++;
    }
    var end_idx = raw.len;
    while end_idx > start_idx && raw[end_idx - 1] <= 0x20 {
        end_idx--;
    }

    for scan_idx in start_idx..end_idx {
        let b = raw[scan_idx];
        if b != 0x09 && b != 0x0A && b != 0x0D {
            out.push(b);
        }
    }
}

fn has_forbidden_host_code_point(h: const u8[:]) -> bool {
    for b in h {
        if b == 0x00 || b == 0x09 || b == 0x0A || b == 0x0D || b == 0x20 ||
           b == '#' || b == '/' || b == ':' || b == '<' || b == '>' ||
           b == '?' || b == '@' || b == '[' || b == '\\' || b == ']' ||
           b == '^' || b == '|' {
            return true;
        }
    }
    return false;
}

fn parse_url_internal(raw_input: const u8[:], base_url: const Url&, has_base: bool) -> Url, UrlParseError {
    var out_url = Url { valid: false, .. };

    var cleaned: u8[..512] = [];
    clean_input_string(raw_input, cleaned);
    guard cleaned.len > 0 else {
        return out_url, UrlParseError.EmptyInput;
    }

    let input_bytes = cleaned[..];

    // 1. Scheme state machine
    var colon_idx = -1;
    for scan_idx in input_bytes.len {
        let b = input_bytes[scan_idx];
        if b == ':' {
            colon_idx = scan_idx;
            break;
        }
        let is_scheme_char = (scan_idx == 0 && ((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z'))) ||
                             (scan_idx > 0 && ((b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') || b == '+' || b == '-' || b == '.'));
        if !is_scheme_char {
            break; // Not a valid scheme prefix
        }
    }

    var scheme_str: u8[..16] = [];
    var remainder_start = 0;

    if colon_idx > 0 {
        // Explicit scheme present
        scheme_str.append(input_bytes[..colon_idx]);
        to_lower(scheme_str[..]);
        remainder_start = colon_idx + 1;
    } else {
        // Relative URL: requires base
        guard has_base else {
            return out_url, UrlParseError.RelativeWithoutBase;
        }
        guard !base_url.has_opaque_path else {
            return out_url, UrlParseError.OpaqueBaseCannotResolveRelative;
        }
        scheme_str.append(scheme(base_url));
    }

    let is_spec = is_special_scheme(scheme_str[..]);
    out_url.is_special = is_spec;

    var remainder = input_bytes[remainder_start..];

    // Non-special scheme with opaque path (e.g. mailto:user@example.com, data:text/html,...)
    if !is_spec && (colon_idx > 0) && (remainder.len == 0 || remainder[0] != '/') {
        out_url.has_opaque_path = true;
        out_url.href.append(scheme_str[..]);
        out_url.href.push(':');
        out_url.scheme_end = scheme_str.len as i32;

        out_url.pathname_start = out_url.href.len as i32;
        var query_pos = -1;
        var hash_pos = -1;
        for scan_idx in remainder.len {
            if remainder[scan_idx] == '?' && query_pos < 0 && hash_pos < 0 {
                query_pos = scan_idx;
            } else if remainder[scan_idx] == '#' && hash_pos < 0 {
                hash_pos = scan_idx;
                break;
            }
        }

        let path_end = if query_pos >= 0 { query_pos } else if hash_pos >= 0 { hash_pos } else { remainder.len };
        out_url.href.append(remainder[..path_end]);
        out_url.pathname_end = out_url.href.len as i32;

        if query_pos >= 0 {
            out_url.search_start = out_url.href.len as i32;
            let q_end = if hash_pos >= 0 { hash_pos } else { remainder.len };
            out_url.href.append(remainder[query_pos..q_end]);
            out_url.search_end = out_url.href.len as i32;
        }

        if hash_pos >= 0 {
            out_url.hash_start = out_url.href.len as i32;
            out_url.href.append(remainder[hash_pos..]);
            out_url.hash_end = out_url.href.len as i32;
        }

        out_url.valid = true;
        return out_url, UrlParseError.None;
    }

    // Authority and Host Parsing for Special schemes (or // authority)
    var has_authority = false;
    var authority_start = 0;

    // Normalize slashes for special schemes
    if is_spec && remainder.len >= 2 && ((remainder[0] == '/' || remainder[0] == '\\') && (remainder[1] == '/' || remainder[1] == '\\')) {
        has_authority = true;
        authority_start = 2;
    } else if !is_spec && remainder.len >= 2 && remainder[0] == '/' && remainder[1] == '/' {
        has_authority = true;
        authority_start = 2;
    }

    if has_authority {
        return parse_absolute_authority_url(out_url, scheme_str[..], is_spec, remainder[authority_start..]);
    }

    // Relative path resolution against base
    guard has_base else {
        return out_url, UrlParseError.RelativeWithoutBase;
    }

    return resolve_relative_path_against_base(out_url, base_url, remainder);
}

fn parse_absolute_authority_url(
    out_url: Url&,
    scheme_str: const u8[:],
    is_spec: bool,
    auth_and_path: const u8[:],
) -> Url, UrlParseError {
    out_url.href.append(scheme_str);
    out_url.href.append("://");
    out_url.scheme_end = scheme_str.len as i32;

    var end_of_auth = auth_and_path.len;
    for scan_idx in auth_and_path.len {
        let b = auth_and_path[scan_idx];
        if b == '/' || (is_spec && b == '\\') || b == '?' || b == '#' {
            end_of_auth = scan_idx;
            break;
        }
    }

    let auth_str = auth_and_path[..end_of_auth];
    let path_and_beyond = auth_and_path[end_of_auth..];

    // Check for userinfo (username:password@)
    var at_pos = -1;
    for scan_idx in auth_str.len {
        if auth_str[scan_idx] == '@' {
            at_pos = scan_idx;
        }
    }

    var host_port_part = auth_str;
    if at_pos >= 0 {
        let userinfo = auth_str[..at_pos];
        host_port_part = auth_str[at_pos + 1..];

        var colon_pos = -1;
        for scan_idx in userinfo.len {
            if userinfo[scan_idx] == ':' {
                colon_pos = scan_idx;
                break;
            }
        }

        out_url.username_start = out_url.href.len as i32;
        if colon_pos >= 0 {
            out_url.href.append(userinfo[..colon_pos]);
            out_url.username_end = out_url.href.len as i32;
            out_url.href.push(':');
            out_url.password_start = out_url.href.len as i32;
            out_url.href.append(userinfo[colon_pos + 1..]);
            out_url.password_end = out_url.href.len as i32;
        } else {
            out_url.href.append(userinfo);
            out_url.username_end = out_url.href.len as i32;
        }
        out_url.href.push('@');
    }

    // Host & Port Parsing
    var raw_host: u8[..256] = [];
    var port_val: i32 = -1;
    let extract_err = extract_host_and_port_canonical(host_port_part, raw_host, port_val);
    guard extract_err == UrlParseError.None else {
        return out_url, extract_err;
    }

    guard raw_host.len > 0 else {
        return out_url, UrlParseError.MissingHost;
    }

    to_lower(raw_host[..]);

    out_url.host_start = out_url.href.len as i32;
    out_url.href.append(raw_host[..]);
    out_url.host_end = out_url.href.len as i32;

    let def_port = default_port_for_scheme(scheme_str);
    if port_val > 0 && port_val != def_port {
        out_url.port_start = out_url.href.len as i32;
        out_url.href.push(':');
        format(out_url.href, port_val as i64);
        out_url.port_end = out_url.href.len as i32;
        out_url.port = port_val;
    } else {
        out_url.port = -1;
    }

    // Pathname, Search, and Hash
    append_canonical_path_and_query(out_url, is_spec, path_and_beyond);

    out_url.valid = true;
    return out_url, UrlParseError.None;
}

fn extract_host_and_port_canonical<B>(
    host_port: const u8[:],
    host_out: B&,
    port_out: i32&,
) -> UrlParseError {
    host_out.clear();
    port_out = -1;
    guard host_port.len > 0 else { return UrlParseError.MissingHost; }

    // Bracketed IPv6 literal [...]
    if host_port[0] == '[' {
        var close_bracket = -1;
        for scan_idx in host_port.len {
            if host_port[scan_idx] == ']' {
                close_bracket = scan_idx;
                break;
            }
        }
        guard close_bracket > 0 else {
            return UrlParseError.InvalidIpv6;
        }

        let ipv6_body = host_port[1..close_bracket];
        var compressed_ipv6: u8[..64] = [];
        let ipv6_ok = parse_and_compress_ipv6(ipv6_body, compressed_ipv6);
        guard ipv6_ok else {
            return UrlParseError.InvalidIpv6;
        }

        host_out.push('[');
        host_out.append(compressed_ipv6[..]);
        host_out.push(']');

        if close_bracket + 1 < host_port.len {
            if host_port[close_bracket + 1] != ':' {
                return UrlParseError.InvalidPort;
            }
            let p_str = host_port[close_bracket + 2..];
            let p_num, p_ok = parse_int(p_str);
            guard p_ok && p_num > 0 && p_num <= 65535 else {
                return UrlParseError.InvalidPort;
            }
            port_out = p_num as i32;
        }
        return UrlParseError.None;
    }

    // Standard host or IPv4 with optional :port
    var colon_idx = -1;
    for scan_idx in host_port.len {
        if host_port[scan_idx] == ':' {
            colon_idx = scan_idx;
            break;
        }
    }

    let h_str = if colon_idx >= 0 { host_port[..colon_idx] } else { host_port };
    guard !has_forbidden_host_code_point(h_str) else {
        return UrlParseError.ForbiddenHostCodePoint;
    }

    host_out.append(h_str);

    if colon_idx >= 0 {
        let p_str = host_port[colon_idx + 1..];
        guard p_str.len > 0 else { return UrlParseError.None; }
        let p_num, p_ok = parse_int(p_str);
        guard p_ok && p_num > 0 && p_num <= 65535 else {
            return UrlParseError.InvalidPort;
        }
        port_out = p_num as i32;
    }

    return UrlParseError.None;
}

// RFC 5952 / WHATWG IPv6 Parser and Zero-Run Canonical Compression
fn parse_and_compress_ipv6<B>(raw_ipv6: const u8[:], out: B&) -> bool {
    out.clear();
    var pieces: u16[8] = [0, 0, 0, 0, 0, 0, 0, 0];
    var piece_count = 0;
    var double_colon_pos = -1;

    var s = raw_ipv6;
    if starts_with(s, "::") {
        double_colon_pos = 0;
        s = s[2..];
    }

    while s.len > 0 && piece_count < 8 {
        var colon_idx = -1;
        for scan_idx in s.len {
            if s[scan_idx] == ':' {
                colon_idx = scan_idx;
                break;
            }
        }

        let piece_str = if colon_idx >= 0 { s[..colon_idx] } else { s };
        if piece_str.len == 0 {
            if double_colon_pos >= 0 { return false; } // Multiple '::'
            double_colon_pos = piece_count;
            s = s[1..];
            continue;
        }

        // Check for dotted-quad IPv4 suffix e.g. ::ffff:192.0.2.1
        var has_dot = false;
        for b in piece_str {
            if b == '.' { has_dot = true; break; }
        }

        if has_dot {
            if piece_count > 6 { return false; }
            var octets: i32[4] = [0, 0, 0, 0];
            var octet_idx = 0;
            var num = 0;
            var digits = 0;
            for b in s {
                if b == '.' {
                    if digits == 0 || num > 255 || octet_idx >= 3 { return false; }
                    octets[octet_idx] = num as i32;
                    octet_idx++;
                    num = 0;
                    digits = 0;
                } else if b >= '0' && b <= '9' {
                    num = num * 10 + (b - '0');
                    digits++;
                    if digits > 3 { return false; }
                } else {
                    return false;
                }
            }
            if digits == 0 || num > 255 || octet_idx != 3 { return false; }
            octets[3] = num as i32;

            pieces[piece_count] = ((octets[0] << 8) | octets[1]) as u16;
            piece_count++;
            pieces[piece_count] = ((octets[2] << 8) | octets[3]) as u16;
            piece_count++;
            s = s[s.len..];
            break;
        }

        // Hex piece
        if piece_str.len > 4 { return false; }
        var val: u32 = 0;
        for b in piece_str {
            let h = if b >= '0' && b <= '9' { b - '0' }
                    else if b >= 'a' && b <= 'f' { b - 'a' + 10 }
                    else if b >= 'A' && b <= 'F' { b - 'A' + 10 }
                    else { return false; };
            val = (val << 4) | (h as u32);
        }
        pieces[piece_count] = val as u16;
        piece_count++;

        if colon_idx >= 0 {
            if colon_idx + 1 < s.len && s[colon_idx + 1] == ':' {
                if double_colon_pos >= 0 { return false; }
                double_colon_pos = piece_count;
                s = s[colon_idx + 2..];
            } else {
                s = s[colon_idx + 1..];
            }
        } else {
            s = s[s.len..];
        }
    }

    if s.len > 0 { return false; }

    if double_colon_pos >= 0 {
        let missing = 8 - piece_count;
        if missing <= 0 { return false; }
        // Shift pieces right
        for rev_idx in piece_count - double_colon_pos {
            let src = piece_count - 1 - rev_idx;
            pieces[src + missing] = pieces[src];
        }
        for zero_idx in missing {
            pieces[double_colon_pos + zero_idx] = 0;
        }
        piece_count = 8;
    }

    guard piece_count == 8 else { return false; }

    // Find longest run of zeros for compression
    var best_run_start = -1;
    var best_run_len = 0;
    var current_run_start = -1;
    var current_run_len = 0;

    for i in 8 {
        if pieces[i] == 0 {
            if current_run_start < 0 {
                current_run_start = i;
                current_run_len = 1;
            } else {
                current_run_len++;
            }
        } else {
            if current_run_len > best_run_len {
                best_run_start = current_run_start;
                best_run_len = current_run_len;
            }
            current_run_start = -1;
            current_run_len = 0;
        }
    }
    if current_run_len > best_run_len {
        best_run_start = current_run_start;
        best_run_len = current_run_len;
    }

    if best_run_len < 2 {
        best_run_start = -1;
        best_run_len = 0;
    }

    // Format output
    var idx = 0;
    while idx < 8 {
        if idx == best_run_start {
            out.append("::");
            idx += best_run_len;
            continue;
        }
        if idx > 0 && !(idx == best_run_start + best_run_len && best_run_start == 0) && out.len > 0 && out[out.len - 1] != ':' {
            out.push(':');
        }
        format_hex_u16(out, pieces[idx]);
        idx++;
    }
    return true;
}

fn format_hex_u16<B>(out: B&, val: u16) {
    if val == 0 {
        out.push('0');
        return;
    }
    var buf: u8[..4] = [];
    var v = val;
    while v > 0 {
        let rem = (v & 0x0F) as u8;
        buf.push(if rem < 10 { '0' + rem } else { 'a' + (rem - 10) });
        v >>= 4;
    }
    for rev in buf.len {
        out.push(buf[buf.len - 1 - rev]);
    }
}

// Dot segment normalization (. and .., %2e and %2E)
fn append_canonical_path_and_query(out_url: Url&, is_spec: bool, path_and_beyond: const u8[:]) {
    var query_pos = -1;
    var hash_pos = -1;
    for scan_idx in path_and_beyond.len {
        let b = path_and_beyond[scan_idx];
        if b == '?' && query_pos < 0 && hash_pos < 0 {
            query_pos = scan_idx;
        } else if b == '#' && hash_pos < 0 {
            hash_pos = scan_idx;
            break;
        }
    }

    let path_end = if query_pos >= 0 { query_pos } else if hash_pos >= 0 { hash_pos } else { path_and_beyond.len };
    let raw_path = path_and_beyond[..path_end];

    out_url.pathname_start = out_url.href.len as i32;

    var normalized_segments: u8[..64][..16] = [];
    parse_and_collapse_dot_segments(raw_path, is_spec, normalized_segments);

    if normalized_segments.len == 0 {
        out_url.href.push('/');
    } else {
        for &seg in normalized_segments {
            out_url.href.push('/');
            out_url.href.append(seg[..]);
        }
        if raw_path.len > 0 && (raw_path[raw_path.len - 1] == '/' || (is_spec && raw_path[raw_path.len - 1] == '\\')) {
            out_url.href.push('/');
        }
    }
    out_url.pathname_end = out_url.href.len as i32;

    if query_pos >= 0 {
        out_url.search_start = out_url.href.len as i32;
        let q_end = if hash_pos >= 0 { hash_pos } else { path_and_beyond.len };
        out_url.href.append(path_and_beyond[query_pos..q_end]);
        out_url.search_end = out_url.href.len as i32;
    }

    if hash_pos >= 0 {
        out_url.hash_start = out_url.href.len as i32;
        out_url.href.append(path_and_beyond[hash_pos..]);
        out_url.hash_end = out_url.href.len as i32;
    }
}

fn parse_and_collapse_dot_segments(raw_path: const u8[:], is_spec: bool, out_segments: u8[..64][..16]&) {
    var seg: u8[..64] = [];
    for scan_idx in raw_path.len {
        let b = raw_path[scan_idx];
        if b == '/' || (is_spec && b == '\\') {
            if seg.len > 0 {
                process_single_dot_segment(seg[..], out_segments);
                seg.clear();
            }
        } else {
            if seg.len < 64 { seg.push(b); }
        }
    }
    if seg.len > 0 {
        process_single_dot_segment(seg[..], out_segments);
    }
}

fn process_single_dot_segment(seg: const u8[:], out_segments: u8[..64][..16]&) {
    if seg == "." || eq_ascii_fold(seg, "%2e") {
        // Current directory: ignore
        return;
    }
    if seg == ".." || eq_ascii_fold(seg, ".%2e") || eq_ascii_fold(seg, "%2e.") || eq_ascii_fold(seg, "%2e%2e") {
        // Parent directory: pop segment
        if out_segments.len > 0 {
            out_segments.pop();
        }
        return;
    }
    var entry: u8[..64] = [];
    entry.append(seg);
    out_segments.push(entry);
}

fn resolve_relative_path_against_base(out_url: Url&, base_url: const Url&, rel_input: const u8[:]) -> Url, UrlParseError {
    guard rel_input.len > 0 else {
        // Empty relative input copies base URL
        out_url = copy(base_url);
        return out_url, UrlParseError.None;
    }

    let is_spec = base_url.is_special;
    out_url.is_special = is_spec;

    if rel_input[0] == '#' {
        // Hash only: keep everything except hash from base
        let base_href = href(base_url);
        let base_no_hash = if base_url.hash_start >= 0 { base_href[..base_url.hash_start] } else { base_href };
        out_url.href.append(base_no_hash);
        out_url.scheme_end = base_url.scheme_end;
        out_url.username_start = base_url.username_start;
        out_url.username_end = base_url.username_end;
        out_url.password_start = base_url.password_start;
        out_url.password_end = base_url.password_end;
        out_url.host_start = base_url.host_start;
        out_url.host_end = base_url.host_end;
        out_url.port_start = base_url.port_start;
        out_url.port_end = base_url.port_end;
        out_url.pathname_start = base_url.pathname_start;
        out_url.pathname_end = base_url.pathname_end;
        out_url.search_start = base_url.search_start;
        out_url.search_end = base_url.search_end;
        out_url.port = base_url.port;

        out_url.hash_start = out_url.href.len as i32;
        out_url.href.append(rel_input);
        out_url.hash_end = out_url.href.len as i32;
        out_url.valid = true;
        return out_url, UrlParseError.None;
    }

    if rel_input[0] == '?' {
        // Query and hash only: keep scheme, authority, and path from base
        let base_href = href(base_url);
        let base_path_end = if base_url.pathname_end >= 0 { base_url.pathname_end } else { base_url.host_end };
        out_url.href.append(base_href[..base_path_end]);
        out_url.scheme_end = base_url.scheme_end;
        out_url.username_start = base_url.username_start;
        out_url.username_end = base_url.username_end;
        out_url.password_start = base_url.password_start;
        out_url.password_end = base_url.password_end;
        out_url.host_start = base_url.host_start;
        out_url.host_end = base_url.host_end;
        out_url.port_start = base_url.port_start;
        out_url.port_end = base_url.port_end;
        out_url.pathname_start = base_url.pathname_start;
        out_url.pathname_end = base_url.pathname_end;
        out_url.port = base_url.port;

        var hash_pos = -1;
        for scan_idx in rel_input.len {
            if rel_input[scan_idx] == '#' { hash_pos = scan_idx; break; }
        }

        out_url.search_start = out_url.href.len as i32;
        let q_end = if hash_pos >= 0 { hash_pos } else { rel_input.len };
        out_url.href.append(rel_input[..q_end]);
        out_url.search_end = out_url.href.len as i32;

        if hash_pos >= 0 {
            out_url.hash_start = out_url.href.len as i32;
            out_url.href.append(rel_input[hash_pos..]);
            out_url.hash_end = out_url.href.len as i32;
        }

        out_url.valid = true;
        return out_url, UrlParseError.None;
    }

    // Path resolution
    let base_href = href(base_url);
    let auth_end = if base_url.port_end > base_url.host_end { base_url.port_end } else { base_url.host_end };
    out_url.href.append(base_href[..auth_end]);
    out_url.scheme_end = base_url.scheme_end;
    out_url.username_start = base_url.username_start;
    out_url.username_end = base_url.username_end;
    out_url.password_start = base_url.password_start;
    out_url.password_end = base_url.password_end;
    out_url.host_start = base_url.host_start;
    out_url.host_end = base_url.host_end;
    out_url.port_start = base_url.port_start;
    out_url.port_end = base_url.port_end;
    out_url.port = base_url.port;

    var combined_path: u8[..512] = [];

    if rel_input[0] == '/' || (is_spec && rel_input[0] == '\\') {
        // Root relative path
        combined_path.append(rel_input);
    } else {
        // Directory relative path
        let base_p = pathname(base_url);
        var last_slash = -1;
        for scan_idx in base_p.len {
            if base_p[scan_idx] == '/' { last_slash = scan_idx; }
        }
        if last_slash >= 0 {
            combined_path.append(base_p[..last_slash + 1]);
        } else {
            combined_path.push('/');
        }
        combined_path.append(rel_input);
    }

    append_canonical_path_and_query(out_url, is_spec, combined_path[..]);
    out_url.valid = true;
    return out_url, UrlParseError.None;
}
