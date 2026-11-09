// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// WHATWG URL Standard state machine parser and IPv6 canonicalization.
namespace core;

import std;

// ---- internal whatwg url parser implementation -----------------------------

fn is_special_scheme(scheme_str: const u8[:]) -> bool {
    let len = scheme_str.len;
    if len == 4 {
        return eq_ascii_fold(scheme_str, "http") || eq_ascii_fold(scheme_str, "file");
    }
    if len == 5 {
        return eq_ascii_fold(scheme_str, "https");
    }
    if len == 2 {
        return eq_ascii_fold(scheme_str, "ws");
    }
    if len == 3 {
        return eq_ascii_fold(scheme_str, "wss") || eq_ascii_fold(scheme_str, "ftp");
    }
    return false;
}

// Fast-path pre-cleaner: trims C0 controls and spaces (<= 0x20) and strips 0x09, 0x0A, 0x0D
fn clean_input_string<B>(raw: const u8[:], out: B&) -> bool {
    out.clear();
    var start_idx = 0;
    while start_idx < raw.len && raw[start_idx] <= 0x20 {
        start_idx++;
    }
    var end_idx = raw.len;
    while end_idx > start_idx && raw[end_idx - 1] <= 0x20 {
        end_idx--;
    }

    let trimmed = raw[start_idx..end_idx];
    guard trimmed.len <= out.cap else { return false; }
    if find_any(trimmed, URL_TAB_CRLF_SET) < 0 {
        return out.try_set(trimmed);
    }
    for char_byte in trimmed {
        guard char_byte != 0x09 && char_byte != 0x0A && char_byte != 0x0D else { continue; }
        guard out.try_push(char_byte) else {
            out.clear();
            return false;
        }
    }
    return true;
}

fn has_forbidden_host_code_point(host_str: const u8[:]) -> bool {
    return find_any(host_str, URL_FORBIDDEN_HOST_SET) >= 0;
}

// Parses an opaque path URL (such as mailto:user@example.com).
//
// Example:
//   scheme_str = "mailto", remainder = "user@example.com?subject=hi"
//   returns: out_url populated with opaque path, err = UrlParseError.None
fn parse_opaque_path_url(
    out_url:    Url&,
    scheme_str: const u8[:],
    remainder:  const u8[:],
) -> Url, UrlParseError {
    out_url.has_opaque_path = true;
    out_url.href.append(scheme_str);
    out_url.href.push(':');
    out_url.scheme_end = scheme_str.len as i32;

    out_url.pathname_start = out_url.href.len as i32;
    var query_pos: i64 = -1;
    var hash_pos:  i64 = -1;
    let first_delim = find_any(remainder, URL_QUERY_HASH_SET);
    if first_delim >= 0 {
        if remainder[first_delim] == '?' {
            query_pos = first_delim;
            let frag_rel = find_any(remainder[first_delim + 1..], URL_HASH_SET);
            if frag_rel >= 0 {
                hash_pos = first_delim + 1 + frag_rel;
            }
        } else {
            hash_pos = first_delim;
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

fn resolve_fragment_on_opaque_base(
    out_url:    Url&,
    base_url:   const Url&,
    frag_input: const u8[:],
) -> Url, UrlParseError {
    let base_href = href(base_url);
    let base_no_hash = if base_url.hash_start >= 0 { base_href[..base_url.hash_start] } else { base_href };
    guard out_url.href.try_append(base_no_hash) else {
        return out_url, UrlParseError.InputTooLong;
    }
    out_url.has_opaque_path = true;
    out_url.is_special = base_url.is_special;
    out_url.scheme_end = base_url.scheme_end;
    out_url.pathname_start = base_url.pathname_start;
    out_url.pathname_end = base_url.pathname_end;
    out_url.search_start = base_url.search_start;
    out_url.search_end = base_url.search_end;

    out_url.hash_start = out_url.href.len as i32;
    guard out_url.href.try_append(frag_input) else {
        out_url.valid = false;
        return out_url, UrlParseError.InputTooLong;
    }
    out_url.hash_end = out_url.href.len as i32;

    out_url.valid = true;
    return out_url, UrlParseError.None;
}

// Scans for a valid URL scheme terminating colon (RFC 3986 §3.1).
//
// Example:
//   input_bytes = "https://example.com"
//   returns: delim_pos = 5, ok = true
fn parse_url_scheme_delimiter(input_bytes: const u8[:]) -> i64, bool {
    let delim_pos = find_any(input_bytes, URL_SCHEME_DELIM_SET);
    guard delim_pos > 0 && input_bytes[delim_pos] == ':' else {
        return -1, true;
    }
    let scheme_cand = input_bytes[..delim_pos];
    guard is_ascii_alpha(scheme_cand[0]) else {
        return -1, false;
    }
    for char_byte in scheme_cand[1..] {
        if !is_ascii_alphanumeric(char_byte) && char_byte != '+' && char_byte != '-' && char_byte != '.' {
            return -1, false;
        }
    }
    return delim_pos, true;
}

inline fn count_scheme_trailing_slashes(remainder: const u8[:], is_spec: bool) -> i64 {
    var slash_count = 0;
    while slash_count < remainder.len {
        let b = remainder[slash_count];
        if b == '/' || (is_spec && b == '\\') {
            slash_count++;
        } else {
            break;
        }
    }
    return slash_count;
}

// Parses input string into a URL struct relative to an optional base URL.
//
// Example:
//   raw_input = "https://example.com/api", base_url = Url { .. }, has_base = false
//   returns: out_url populated, err = UrlParseError.None
fn parse_url_internal(raw_input: const u8[:], base_url: const Url&, has_base: bool) -> Url, UrlParseError {
    var out_url = Url { valid: false, .. };

    var cleaned: u8[..2048] = [];
    guard clean_input_string(raw_input, cleaned) else {
        return out_url, UrlParseError.InputTooLong;
    }
    guard cleaned.len > 0 else {
        if has_base {
            return resolve_relative_path_against_base(out_url, base_url, "");
        }
        return out_url, UrlParseError.EmptyInput;
    }

    let input_bytes = cleaned[..];

    let colon_idx, ok_scheme = parse_url_scheme_delimiter(input_bytes);
    guard ok_scheme else {
        return out_url, UrlParseError.InvalidScheme;
    }

    var scheme_str: u8[..64] = [];
    var remainder_start = 0;

    if colon_idx > 0 {
        // Explicit scheme present
        guard scheme_str.try_set(input_bytes[..colon_idx]) else {
            return out_url, UrlParseError.InvalidScheme;
        }
        to_lower(scheme_str[..]);
        remainder_start = colon_idx + 1;
    } else {
        // Relative URL: requires base
        guard has_base else {
            return out_url, UrlParseError.RelativeWithoutBase;
        }
        if base_url.has_opaque_path {
            // WHATWG URL Section 4.4: fragment-only relative URL on opaque-path base is allowed
            guard input_bytes.len > 0 && input_bytes[0] == '#' else {
                return out_url, UrlParseError.OpaqueBaseCannotResolveRelative;
            }
            return resolve_fragment_on_opaque_base(out_url, base_url, input_bytes);
        }
        scheme_str.append(scheme(base_url));
    }

    let is_spec = is_special_scheme(scheme_str[..]);
    out_url.is_special = is_spec;

    var remainder = input_bytes[remainder_start..];

    // Non-special scheme with opaque path (e.g. mailto:user@example.com, data:text/html,...)
    if !is_spec && (colon_idx > 0) && (remainder.len == 0 || remainder[0] != '/') {
        return parse_opaque_path_url(out_url, scheme_str[..], remainder);
    }

    // Slashes count after scheme:
    let slash_count = count_scheme_trailing_slashes(remainder, is_spec);

    // Special schemes or URLs with // authority
    if is_spec {
        if scheme_str == "file" && (colon_idx > 0 || slash_count >= 2) {
            let auth_start = if slash_count >= 2 { 2 } else { 0 };
            return parse_absolute_authority_url(out_url, scheme_str[..], is_spec, remainder[auth_start..]);
        }
        if slash_count == 3 {
            // Exactly 3 slashes in special scheme (e.g. https:///path): scheme:// followed by /path has empty host
            return out_url, UrlParseError.MissingHost;
        }
        if slash_count >= 2 {
            return parse_absolute_authority_url(out_url, scheme_str[..], is_spec, remainder[slash_count..]);
        }
        if colon_idx > 0 {
            if has_base && scheme_str == scheme(base_url) {
                return resolve_relative_path_against_base(out_url, base_url, remainder);
            }
            if slash_count < remainder.len {
                return parse_absolute_authority_url(out_url, scheme_str[..], is_spec, remainder[slash_count..]);
            }
            return out_url, UrlParseError.MissingHost;
        }
    } else {
        if slash_count >= 2 {
            return parse_absolute_authority_url(out_url, scheme_str[..], is_spec, remainder[2..]);
        }
        if colon_idx > 0 && slash_count == 1 {
            // Absolute path without authority: custom:/a/b/c
            out_url.href.append(scheme_str[..]);
            out_url.href.push(':');
            out_url.scheme_end = scheme_str.len as i32;
            let path_err = append_canonical_path_and_query(out_url, is_spec, remainder);
            guard path_err == UrlParseError.None else {
                return out_url, path_err;
            }
            out_url.valid = true;
            return out_url, UrlParseError.None;
        }
    }

    // Relative path resolution against base
    guard has_base else {
        return out_url, UrlParseError.RelativeWithoutBase;
    }

    return resolve_relative_path_against_base(out_url, base_url, remainder);
}

fn append_userinfo_to_url(out_url: Url&, userinfo: const u8[:]) -> bool {
    var colon_pos = -1;
    for scan_idx in userinfo.len {
        if userinfo[scan_idx] == ':' {
            colon_pos = scan_idx;
            break;
        }
    }

    let raw_user = if colon_pos >= 0 { userinfo[..colon_pos] } else { userinfo };
    let raw_pass = if colon_pos >= 0 { userinfo[colon_pos + 1..] } else { "" };

    // If both username and password are empty (e.g. :@), omit userinfo completely per WHATWG URL
    guard raw_user.len > 0 || raw_pass.len > 0 else {
        return true;
    }

    out_url.username_start = out_url.href.len as i32;
    for char_byte in raw_user {
        if char_byte == '@' {
            guard out_url.href.try_append("%40") else { return false; }
        } else {
            guard out_url.href.try_push(char_byte) else { return false; }
        }
    }
    out_url.username_end = out_url.href.len as i32;

    if raw_pass.len > 0 {
        guard out_url.href.try_push(':') else { return false; }
        out_url.password_start = out_url.href.len as i32;
        for char_byte in raw_pass {
            if char_byte == '@' {
                guard out_url.href.try_append("%40") else { return false; }
            } else {
                guard out_url.href.try_push(char_byte) else { return false; }
            }
        }
        out_url.password_end = out_url.href.len as i32;
    }

    return out_url.href.try_push('@');
}

fn apply_canonical_host_and_port(
    out_url:        Url&,
    scheme_str:     const u8[:],
    host_port_part: const u8[:],
) -> UrlParseError {
    var raw_host: u8[..256] = [];
    var port_val: i32       = -1;
    let is_file = scheme_str == "file";
    let is_spec = is_special_scheme(scheme_str);

    if host_port_part.len == 0 {
        if is_spec && !is_file {
            return UrlParseError.MissingHost;
        }
        out_url.host_start = out_url.href.len as i32;
        out_url.host_end = out_url.href.len as i32;
        out_url.port = -1;
        return UrlParseError.None;
    }

    let extract_err = extract_host_and_port_canonical(host_port_part, raw_host, port_val);
    guard extract_err == UrlParseError.None else {
        return extract_err;
    }

    if is_file && port_val >= 0 {
        return UrlParseError.InvalidPort;
    }

    to_lower(raw_host[..]);

    // In WHATWG URL, "localhost" on a file: URL normalizes to an empty host ("")
    if is_file && raw_host == "localhost" {
        raw_host.clear();
    }

    guard raw_host.len > 0 || is_file || !is_spec else {
        return UrlParseError.MissingHost;
    }

    out_url.host_start = out_url.href.len as i32;
    guard out_url.href.try_append(raw_host[..]) else {
        return UrlParseError.InputTooLong;
    }
    out_url.host_end = out_url.href.len as i32;

    let def_port = default_port_for_scheme(scheme_str);
    if !is_file && port_val >= 0 && port_val != def_port {
        guard out_url.href.len + 6 <= out_url.href.cap else {
            return UrlParseError.InputTooLong;
        }
        out_url.port_start = out_url.href.len as i32;
        out_url.href.push(':');
        format(out_url.href, port_val as i64);
        out_url.port_end = out_url.href.len as i32;
        out_url.port = port_val;
    } else {
        out_url.port = -1;
    }
    return UrlParseError.None;
}

// Parses an absolute authority URL into out_url.
//
// Example:
//   scheme_str = "https", is_spec = true, auth_and_path = "example.com/foo"
//   returns: out_url populated with authority and path, err = UrlParseError.None
fn parse_absolute_authority_url(
    out_url:       Url&,
    scheme_str:    const u8[:],
    is_spec:       bool,
    auth_and_path: const u8[:],
) -> Url, UrlParseError {
    guard out_url.href.try_append(scheme_str) && out_url.href.try_append("://") else {
        return out_url, UrlParseError.InputTooLong;
    }
    out_url.scheme_end = scheme_str.len as i32;

    let rel_delim = if is_spec {
        find_any(auth_and_path, URL_AUTH_SPECIAL_DELIM_SET)
    } else {
        find_any(auth_and_path, URL_AUTH_GENERIC_DELIM_SET)
    };
    let end_of_auth = if rel_delim >= 0 { rel_delim } else { auth_and_path.len };

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
        guard append_userinfo_to_url(out_url, userinfo) else {
            return out_url, UrlParseError.InputTooLong;
        }
    }

    // Host & Port Parsing
    let host_err = apply_canonical_host_and_port(out_url, scheme_str, host_port_part);
    guard host_err == UrlParseError.None else {
        return out_url, host_err;
    }

    // Pathname, Search, and Hash
    let path_err = append_canonical_path_and_query(out_url, is_spec, path_and_beyond);
    guard path_err == UrlParseError.None else {
        return out_url, path_err;
    }

    out_url.valid = true;
    return out_url, UrlParseError.None;
}

// Parses a decimal port number string up to 65535.
//
// Example:
//   port_str = "8080"
//   returns: 8080, ok = true
fn parse_port_number(port_str: const u8[:]) -> i32, bool {
    guard port_str.len > 0 else { return -1, false; }
    var val: i64 = 0;
    for char_byte in port_str {
        guard char_byte >= '0' && char_byte <= '9' else { return -1, false; }
        val = val * 10 + (char_byte - '0');
        if val > 65535 {
            return -1, false;
        }
    }
    return val as i32, true;
}

fn resolve_bracketed_ipv6_host(view: UrlView&, host_port_slice: const u8[:]) -> UrlParseError {
    var close_bracket = -1;
    for scan_idx in host_port_slice.len {
        if host_port_slice[scan_idx] == ']' { close_bracket = scan_idx; break; }
    }
    guard close_bracket > 0 else {
        return UrlParseError.InvalidIpv6;
    }

    let inside_brackets = host_port_slice[1..close_bracket];
    var dummy_comp: u8[..64] = [];
    let pct_pos = find(inside_brackets, "%25");
    let addr_to_check = if pct_pos >= 0 { inside_brackets[..pct_pos] } else { inside_brackets };
    guard parse_and_compress_ipv6(addr_to_check, dummy_comp) else {
        return UrlParseError.InvalidIpv6;
    }

    if pct_pos >= 0 {
        let zone_id = inside_brackets[pct_pos + 3..];
        guard validate_zone_id(zone_id) else {
            return UrlParseError.InvalidIpv6;
        }
        guard is_scoped_ipv6_for_zone_id(dummy_comp[..]) else {
            return UrlParseError.InvalidIpv6;
        }
    }

    view.host = host_port_slice[..close_bracket + 1];
    if close_bracket + 1 < host_port_slice.len {
        guard host_port_slice[close_bracket + 1] == ':' else {
            return UrlParseError.InvalidHost;
        }
        let port_str = host_port_slice[close_bracket + 2..];
        if port_str.len > 0 {
            let port_num, port_ok = parse_port_number(port_str);
            guard port_ok && !eq_ascii_fold(view.scheme, "file") else { return UrlParseError.InvalidPort; }
            view.port = port_num;
        } else {
            view.port = -1;
        }
    }
    return UrlParseError.None;
}

fn resolve_regular_host_port(view: UrlView&, host_port_slice: const u8[:]) -> UrlParseError {
    var host_colon = -1;
    for scan_idx in host_port_slice.len {
        if host_port_slice[scan_idx] == ':' { host_colon = scan_idx; break; }
    }
    if host_colon >= 0 {
        view.host = host_port_slice[..host_colon];
        let port_str = host_port_slice[host_colon + 1..];
        if port_str.len > 0 {
            let port_num, port_ok = parse_port_number(port_str);
            guard port_ok && !eq_ascii_fold(view.scheme, "file") else { return UrlParseError.InvalidPort; }
            view.port = port_num;
        } else {
            view.port = -1;
        }
    } else {
        view.host = host_port_slice;
    }
    if view.is_special && !eq_ascii_fold(view.scheme, "file") && view.host.len == 0 {
        return UrlParseError.MissingHost;
    }
    guard !has_forbidden_host_code_point(view.host) else {
        return UrlParseError.ForbiddenHostCodePoint;
    }
    guard validate_host_punycode_labels(view.host) else {
        return UrlParseError.InvalidHost;
    }
    return UrlParseError.None;
}

fn resolve_url_view_authority(view: UrlView&, authority: const u8[:]) -> UrlParseError {
    let at_idx = last_index_of_byte(authority, '@');
    var host_port_slice = authority;
    if at_idx >= 0 {
        guard !eq_ascii_fold(view.scheme, "file") else {
            return UrlParseError.ForbiddenHostCodePoint;
        }
        let userinfo = authority[..at_idx];
        host_port_slice = authority[add_sat_i64(at_idx, 1)..];
        let u_part, p_part, has_colon = split_once_byte(userinfo, ':');
        view.username = if has_colon { u_part } else { userinfo };
        if has_colon {
            view.password = p_part;
        }
    }

    if host_port_slice.len > 0 && host_port_slice[0] == '[' {
        return resolve_bracketed_ipv6_host(view, host_port_slice);
    }
    return resolve_regular_host_port(view, host_port_slice);
}

inline fn split_url_view_path_query_hash(view: UrlView&, rest: const u8[:]) {
    var q_pos: i64 = -1;
    var h_pos: i64 = -1;
    let first_qh = find_any(rest, URL_QUERY_HASH_SET);
    if first_qh >= 0 {
        if rest[first_qh] == '?' {
            q_pos = first_qh;
            let hash_offset = find_any(rest[first_qh + 1..], URL_HASH_SET);
            if hash_offset >= 0 {
                h_pos = first_qh + 1 + hash_offset;
            }
        } else {
            h_pos = first_qh;
        }
    }

    if q_pos >= 0 {
        view.pathname = rest[..q_pos];
        if h_pos >= 0 {
            view.search = rest[q_pos..h_pos];
            view.hash = rest[h_pos..];
        } else {
            view.search = rest[q_pos..];
        }
    } else if h_pos >= 0 {
        view.pathname = rest[..h_pos];
        view.hash = rest[h_pos..];
    } else {
        view.pathname = rest;
    }
}

inline fn has_unencoded_control_byte(s: const u8[:]) -> bool {
    for b in s {
        if b <= 0x20 || b == 0x7F { return true; }
    }
    return false;
}

inline fn is_valid_scheme_slice(scheme_slice: const u8[:]) -> bool {
    guard scheme_slice.len > 0 && is_ascii_alpha(scheme_slice[0]) else { return false; }
    for char_byte in scheme_slice[1..] {
        guard is_ascii_alphanumeric(char_byte) || char_byte == '+' || char_byte == '-' || char_byte == '.' else {
            return false;
        }
    }
    return true;
}

// Parses a URL of arbitrary length into a non-owning UrlView with zero heap allocations.
//
// Example:
//   raw_input = "https://example.com:8080/path?q=1#frag"
//   returns: UrlView with scheme "https", host "example.com", port 8080, ...
fn parse_url_view(raw_input: const u8[:]) -> UrlView, UrlParseError {
    var view = UrlView { valid: false, .. };
    guard raw_input.len > 0 else {
        return view, UrlParseError.EmptyInput;
    }

    // RFC 3986 §2 & CVE-2023-26159: Reject unencoded CRLF or NUL control characters (smuggling defense)
    guard !has_unencoded_control_byte(raw_input) else {
        return view, UrlParseError.ForbiddenHostCodePoint;
    }

    view.raw = raw_input;

    // Find scheme separator ':'
    let first_delim = find_any(raw_input, URL_SCHEME_DELIM_SET);
    var colon_idx: i64 = -1;
    if first_delim > 0 && raw_input[first_delim] == ':' {
        colon_idx = first_delim;
    }

    guard colon_idx > 0 else {
        return view, UrlParseError.InvalidScheme;
    }

    let scheme_slice = raw_input[..colon_idx];
    guard is_valid_scheme_slice(scheme_slice) else {
        return view, UrlParseError.InvalidScheme;
    }
    view.scheme = scheme_slice;
    view.is_special = is_special_scheme(scheme_slice);

    var cursor = colon_idx + 1;

    // Check for authority "//"
    let has_auth = cursor + 1 < raw_input.len &&
        (raw_input[cursor] == '/' || (view.is_special && raw_input[cursor] == '\\')) &&
        (raw_input[cursor + 1] == '/' || (view.is_special && raw_input[cursor + 1] == '\\'));

    if has_auth {
        cursor += 2;
        let auth_start = cursor;
        let auth_slice = raw_input[auth_start..];
        let rel_delim = if view.is_special {
            find_any(auth_slice, URL_AUTH_SPECIAL_DELIM_SET)
        } else {
            find_any(auth_slice, URL_AUTH_GENERIC_DELIM_SET)
        };
        let auth_end = if rel_delim >= 0 { auth_start + rel_delim } else { raw_input.len };
        cursor = auth_end;
        let authority = raw_input[auth_start..auth_end];

        let auth_err = resolve_url_view_authority(view, authority);
        guard auth_err == UrlParseError.None else {
            return view, auth_err;
        }
    } else if view.is_special && !eq_ascii_fold(view.scheme, "file") {
        return view, UrlParseError.MissingHost;
    }

    let rest = raw_input[cursor..];
    split_url_view_path_query_hash(view, rest);

    view.valid = true;
    return view, UrlParseError.None;
}

fn new_url_view(raw_input: const u8[:]) -> UrlView {
    let view, err = parse_url_view(raw_input);
    return view;
}

fn resolve_bracketed_ipv6<B>(
    host_port: const u8[:],
    host_out:  B&,
    port_out:  i32&,
) -> UrlParseError {
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
    let pct_pos = find(ipv6_body, "%25");

    if pct_pos >= 0 {
        let addr_to_parse = ipv6_body[..pct_pos];
        let zone_id = ipv6_body[pct_pos + 3..];
        guard validate_zone_id(zone_id) else {
            return UrlParseError.InvalidIpv6;
        }
        let ipv6_ok = parse_and_compress_ipv6(addr_to_parse, compressed_ipv6);
        guard ipv6_ok else {
            return UrlParseError.InvalidIpv6;
        }
        guard is_scoped_ipv6_for_zone_id(compressed_ipv6[..]) else {
            return UrlParseError.InvalidIpv6;
        }

        host_out.push('[');
        host_out.append(compressed_ipv6[..]);
        host_out.append("%25");
        host_out.append(zone_id);
        host_out.push(']');
    } else {
        let ipv6_ok = parse_and_compress_ipv6(ipv6_body, compressed_ipv6);
        guard ipv6_ok else {
            return UrlParseError.InvalidIpv6;
        }

        host_out.push('[');
        host_out.append(compressed_ipv6[..]);
        host_out.push(']');
    }

    if close_bracket + 1 < host_port.len {
        if host_port[close_bracket + 1] != ':' {
            return UrlParseError.InvalidPort;
        }
        let p_str = host_port[close_bracket + 2..];
        if p_str.len > 0 {
            let p_num, p_ok = parse_port_number(p_str);
            guard p_ok else {
                return UrlParseError.InvalidPort;
            }
            port_out = p_num;
        }
    }
    return UrlParseError.None;
}

// Extracts host and optional port from authority host_port token.
//
// Example:
//   host_port = "example.com:8080"
//   host_out = "example.com", port_out = 8080, returns: UrlParseError.None
fn extract_host_and_port_canonical<B>(
    host_port: const u8[:],
    host_out:  B&,
    port_out:  i32&,
) -> UrlParseError {
    host_out.clear();
    port_out = -1;
    guard host_port.len > 0 else { return UrlParseError.MissingHost; }

    // Bracketed IPv6 literal [...]
    if host_port[0] == '[' {
        return resolve_bracketed_ipv6(host_port, host_out, port_out);
    }

    // Standard host or IPv4 with optional :port
    var colon_idx = -1;
    for scan_idx in host_port.len {
        if host_port[scan_idx] == ':' {
            colon_idx = scan_idx;
            break;
        }
    }

    let host_str = if colon_idx >= 0 { host_port[..colon_idx] } else { host_port };
    guard host_str.len > 0 else {
        return UrlParseError.MissingHost;
    }
    guard !has_forbidden_host_code_point(host_str) else {
        return UrlParseError.ForbiddenHostCodePoint;
    }
    guard validate_host_punycode_labels(host_str) else {
        return UrlParseError.InvalidHost;
    }
    guard host_out.try_set(host_str) else {
        return UrlParseError.InvalidHost;
    }

    if colon_idx >= 0 {
        let p_str = host_port[colon_idx + 1..];
        if p_str.len > 0 {
            let p_num, p_ok = parse_port_number(p_str);
            guard p_ok else {
                return UrlParseError.InvalidPort;
            }
            port_out = p_num;
        }
    }

    return UrlParseError.None;
}

// Dot segment normalization (. and .., %2e and %2E)
fn is_dot_segment(seg: const u8[:]) -> bool {
    return seg == "." || eq_ascii_fold(seg, "%2e");
}

fn is_double_dot_segment(seg: const u8[:]) -> bool {
    return seg == ".." ||
           eq_ascii_fold(seg, ".%2e") ||
           eq_ascii_fold(seg, "%2e.") ||
           eq_ascii_fold(seg, "%2e%2e");
}

fn is_windows_drive_segment(seg: const u8[:]) -> bool {
    guard seg.len == 2 else { return false; }
    let is_letter = (seg[0] >= 'a' && seg[0] <= 'z') || (seg[0] >= 'A' && seg[0] <= 'Z');
    let is_separator = seg[1] == ':' || seg[1] == '|';
    return is_letter && is_separator;
}

fn handle_path_segment(
    seg:          const u8[:],
    is_file:      bool,
    out_url:      Url&,
    seg_starts:   i32[..1024]&,
    last_was_dot: bool&,
) -> UrlParseError {
    if is_dot_segment(seg) {
        last_was_dot = true;
    } else if is_double_dot_segment(seg) {
        last_was_dot = true;
        let can_pop = if is_file && seg_starts.len == 1 {
            let prev_start = seg_starts[0] as i64;
            let prev_seg = out_url.href[prev_start..];
            !is_windows_drive_segment(prev_seg)
        } else {
            seg_starts.len > 0
        };

        if can_pop {
            let pop_to = (seg_starts[seg_starts.len - 1] - 1) as i64;
            out_url.href.resize(pop_to);
            seg_starts.pop();
        }
    } else {
        last_was_dot = false;
        guard out_url.href.try_push('/') else {
            return UrlParseError.InputTooLong;
        }
        let cur_start = out_url.href.len as i32;
        if is_file && seg_starts.len == 0 && is_windows_drive_segment(seg) && seg[1] == '|' {
            guard out_url.href.try_push(seg[0]) && out_url.href.try_push(':') else {
                return UrlParseError.InputTooLong;
            }
        } else {
            guard out_url.href.try_append(seg) else {
                return UrlParseError.InputTooLong;
            }
        }
        guard seg_starts.try_push(cur_start) else {
            return UrlParseError.PathTooDeep;
        }
    }
    return UrlParseError.None;
}

inline fn is_path_delimiter_at(raw_path: const u8[:], scan_idx: i64, is_spec: bool) -> bool {
    if scan_idx == raw_path.len { return true; }
    let b = raw_path[scan_idx];
    return b == '/' || (is_spec && b == '\\');
}

fn ensure_trailing_slash_if_needed(
    out_url:           Url&,
    path_start_offset: i64,
    needs_slash:       bool,
) -> UrlParseError {
    if needs_slash && (out_url.href.len == path_start_offset || out_url.href[out_url.href.len - 1] != '/') {
        guard out_url.href.try_push('/') else {
            return UrlParseError.InputTooLong;
        }
    }
    if out_url.host_start < 0 && out_url.href.len - path_start_offset >= 2 &&
       out_url.href[path_start_offset] == '/' && out_url.href[path_start_offset + 1] == '/' {
        let old_len = out_url.href.len;
        guard old_len + 2 <= out_url.href.cap else { return UrlParseError.InputTooLong; }
        out_url.href.push(0);
        out_url.href.push(0);
        var move_idx = old_len - 1;
        while move_idx >= path_start_offset {
            out_url.href[move_idx + 2] = out_url.href[move_idx];
            move_idx--;
        }
        out_url.href[path_start_offset] = '/';
        out_url.href[path_start_offset + 1] = '.';
    }
    return UrlParseError.None;
}

fn collapse_path_directly(out_url: Url&, is_spec: bool, raw_path: const u8[:]) -> UrlParseError {
    let path_start_offset: i64 = out_url.href.len;
    guard raw_path.len > 0 else {
        if is_spec {
            guard out_url.href.try_push('/') else {
                return UrlParseError.InputTooLong;
            }
        }
        return UrlParseError.None;
    }

    let is_file = out_url.scheme_end == 4 && out_url.href.len >= 4 && out_url.href[..4] == "file";
    var seg_starts: i32[..1024] = [];

    var scan_idx = 0;
    if raw_path[0] == '/' || (is_spec && raw_path[0] == '\\') {
        scan_idx = 1;
    }

    var seg_start = scan_idx;
    var last_was_dot = false;

    while scan_idx <= raw_path.len {
        let is_delim = is_path_delimiter_at(raw_path, scan_idx, is_spec);
        if is_delim {
            let seg = raw_path[seg_start..scan_idx];
            let seg_err = handle_path_segment(seg, is_file, out_url, seg_starts, last_was_dot);
            guard seg_err == UrlParseError.None else {
                out_url.valid = false;
                return seg_err;
            }
            seg_start = scan_idx + 1;
        }
        scan_idx++;
    }

    var has_trailing_slash = false;
    if raw_path.len > 0 && (raw_path[raw_path.len - 1] == '/' || (is_spec && raw_path[raw_path.len - 1] == '\\')) {
        has_trailing_slash = true;
    }
    if last_was_dot {
        has_trailing_slash = true;
    }
    // WHATWG URL § 4.4: In a file URL, if path has a single Windows drive letter,
    // it must serialize with a trailing slash
    if is_file && seg_starts.len == 1 {
        let first_start = seg_starts[0] as i64;
        let first_seg = out_url.href[first_start..];
        if is_windows_drive_segment(first_seg) {
            has_trailing_slash = true;
        }
    }

    let needs_slash = has_trailing_slash || (out_url.href.len == path_start_offset && is_spec);
    let slash_err = ensure_trailing_slash_if_needed(out_url, path_start_offset, needs_slash);
    guard slash_err == UrlParseError.None else { return slash_err; }
    return UrlParseError.None;
}

fn append_canonical_path_and_query(out_url: Url&, is_spec: bool, path_and_beyond: const u8[:]) -> UrlParseError {
    var query_pos = -1;
    var hash_pos = -1;
    for scan_idx in path_and_beyond.len {
        let char_byte = path_and_beyond[scan_idx];
        if char_byte == '?' && query_pos < 0 && hash_pos < 0 {
            query_pos = scan_idx;
        } else if char_byte == '#' && hash_pos < 0 {
            hash_pos = scan_idx;
            break;
        }
    }

    let path_end = if query_pos >= 0 { query_pos } else if hash_pos >= 0 { hash_pos } else { path_and_beyond.len };
    let raw_path = path_and_beyond[..path_end];

    out_url.pathname_start = out_url.href.len as i32;
    let path_err = collapse_path_directly(out_url, is_spec, raw_path);
    guard path_err == UrlParseError.None else {
        out_url.valid = false;
        return path_err;
    }
    out_url.pathname_end = out_url.href.len as i32;

    if query_pos >= 0 {
        out_url.search_start = out_url.href.len as i32;
        let q_end = if hash_pos >= 0 { hash_pos } else { path_and_beyond.len };
        guard out_url.href.try_append(path_and_beyond[query_pos..q_end]) else {
            out_url.valid = false;
            return UrlParseError.InputTooLong;
        }
        out_url.search_end = out_url.href.len as i32;
    }

    if hash_pos >= 0 {
        out_url.hash_start = out_url.href.len as i32;
        guard out_url.href.try_append(path_and_beyond[hash_pos..]) else {
            out_url.valid = false;
            return UrlParseError.InputTooLong;
        }
        out_url.hash_end = out_url.href.len as i32;
    }
    return UrlParseError.None;
}

fn copy_base_authority_offsets(out_url: Url&, base_url: const Url&) {
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
}

fn resolve_relative_query_and_hash(
    out_url:   Url&,
    base_url:  const Url&,
    rel_input: const u8[:],
) -> Url, UrlParseError {
    let base_href = href(base_url);
    let base_path_end = if base_url.pathname_end >= 0 {
        base_url.pathname_end
    } else if base_url.host_end >= 0 {
        base_url.host_end
    } else {
        base_url.scheme_end + 1
    };
    guard out_url.href.try_append(base_href[..base_path_end]) else {
        return out_url, UrlParseError.InputTooLong;
    }
    copy_base_authority_offsets(out_url, base_url);
    out_url.pathname_start = base_url.pathname_start;
    out_url.pathname_end = base_url.pathname_end;

    var hash_pos = -1;
    for scan_idx in rel_input.len {
        if rel_input[scan_idx] == '#' { hash_pos = scan_idx; break; }
    }

    out_url.search_start = out_url.href.len as i32;
    let q_end = if hash_pos >= 0 { hash_pos } else { rel_input.len };
    guard out_url.href.try_append(rel_input[..q_end]) else {
        out_url.valid = false;
        return out_url, UrlParseError.InputTooLong;
    }
    out_url.search_end = out_url.href.len as i32;

    if hash_pos >= 0 {
        out_url.hash_start = out_url.href.len as i32;
        guard out_url.href.try_append(rel_input[hash_pos..]) else {
            out_url.valid = false;
            return out_url, UrlParseError.InputTooLong;
        }
        out_url.hash_end = out_url.href.len as i32;
    }

    out_url.valid = true;
    return out_url, UrlParseError.None;
}

inline fn build_file_root_relative_path(
    combined_path: u8[..2048]&,
    base_url:      const Url&,
    rel_input:     const u8[:],
) -> bool {
    let base_path = pathname(base_url);
    let has_base_drive = base_path.len >= 3 && base_path[0] == '/' && is_windows_drive_segment(base_path[1..3]);
    var rel_has_drive = false;
    let rel_start = if rel_input.len > 1 && (rel_input[1] == '/' || rel_input[1] == '\\') { 2 } else { 1 };
    if rel_input.len >= rel_start + 2 && is_windows_drive_segment(rel_input[rel_start..rel_start + 2]) {
        rel_has_drive = true;
    }
    if has_base_drive && !rel_has_drive {
        guard combined_path.try_push('/') &&
              combined_path.try_push(base_path[1]) &&
              combined_path.try_push(':') else {
            return false;
        }
    }
    return combined_path.try_append(rel_input);
}

inline fn build_dir_relative_path(
    combined_path: u8[..2048]&,
    base_url:      const Url&,
    rel_input:     const u8[:],
) -> bool {
    let base_path = pathname(base_url);
    var last_slash = -1;
    for scan_idx in base_path.len {
        if base_path[scan_idx] == '/' { last_slash = scan_idx; }
    }
    if last_slash >= 0 {
        guard combined_path.try_append(base_path[..last_slash + 1]) else {
            return false;
        }
    } else {
        guard combined_path.try_push('/') else {
            return false;
        }
    }
    return combined_path.try_append(rel_input);
}

fn resolve_relative_path_against_base(
    out_url:   Url&,
    base_url:  const Url&,
    rel_input: const u8[:],
) -> Url, UrlParseError {
    guard rel_input.len > 0 else {
        // Empty relative input copies base URL with fragment stripped per WHATWG URL Section 4.4
        let base_href = href(base_url);
        let base_no_hash = if base_url.hash_start >= 0 { base_href[..base_url.hash_start] } else { base_href };
        guard out_url.href.try_append(base_no_hash) else {
            return out_url, UrlParseError.InputTooLong;
        }
        copy_base_authority_offsets(out_url, base_url);
        out_url.pathname_start = base_url.pathname_start;
        out_url.pathname_end = base_url.pathname_end;
        out_url.search_start = base_url.search_start;
        out_url.search_end = base_url.search_end;
        out_url.hash_start = -1;
        out_url.hash_end = -1;
        out_url.has_opaque_path = base_url.has_opaque_path;
        out_url.is_special = base_url.is_special;
        out_url.valid = true;
        return out_url, UrlParseError.None;
    }

    let is_spec = base_url.is_special;
    out_url.is_special = is_spec;

    if rel_input[0] == '#' {
        // Hash only: keep everything except hash from base
        let base_href = href(base_url);
        let base_no_hash = if base_url.hash_start >= 0 { base_href[..base_url.hash_start] } else { base_href };
        guard out_url.href.try_append(base_no_hash) else {
            return out_url, UrlParseError.InputTooLong;
        }
        copy_base_authority_offsets(out_url, base_url);
        out_url.pathname_start = base_url.pathname_start;
        out_url.pathname_end = base_url.pathname_end;
        out_url.search_start = base_url.search_start;
        out_url.search_end = base_url.search_end;

        out_url.hash_start = out_url.href.len as i32;
        guard out_url.href.try_append(rel_input) else {
            out_url.valid = false;
            return out_url, UrlParseError.InputTooLong;
        }
        out_url.hash_end = out_url.href.len as i32;
        out_url.valid = true;
        return out_url, UrlParseError.None;
    }

    if rel_input[0] == '?' {
        return resolve_relative_query_and_hash(out_url, base_url, rel_input);
    }

    // Path resolution
    let base_href = href(base_url);
    var auth_end = max(base_url.port_end, base_url.host_end);
    if auth_end < 0 {
        auth_end = base_url.scheme_end + 1;
    }
    guard out_url.href.try_append(base_href[..auth_end]) else {
        return out_url, UrlParseError.InputTooLong;
    }
    copy_base_authority_offsets(out_url, base_url);

    var combined_path: u8[..2048] = [];

    if rel_input[0] == '/' || (is_spec && rel_input[0] == '\\') {
        let ok = if is_file_url(base_url) {
            build_file_root_relative_path(combined_path, base_url, rel_input)
        } else {
            combined_path.try_append(rel_input)
        };
        guard ok else { return out_url, UrlParseError.InputTooLong; }
    } else {
        guard build_dir_relative_path(combined_path, base_url, rel_input) else {
            return out_url, UrlParseError.InputTooLong;
        }
    }

    let path_err = append_canonical_path_and_query(out_url, is_spec, combined_path[..]);
    guard path_err == UrlParseError.None else {
        out_url.valid = false;
        return out_url, path_err;
    }
    out_url.valid = true;
    return out_url, UrlParseError.None;
}
