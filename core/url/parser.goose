// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// WHATWG URL Standard state machine parser and IPv6 canonicalization.
namespace core;

import std;

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
        out.append(trimmed);
    } else {
        for char_byte in trimmed {
            if char_byte != 0x09 && char_byte != 0x0A && char_byte != 0x0D {
                if out.len < out.cap {
                    out.push(char_byte);
                } else {
                    return false;
                }
            }
        }
    }
    return true;
}

fn has_forbidden_host_code_point(host_str: const u8[:]) -> bool {
    return find_any(host_str, URL_FORBIDDEN_HOST_SET) >= 0;
}

fn parse_opaque_path_url(
    out_url: Url&,
    scheme_str: const u8[:],
    remainder: const u8[:],
) -> Url, UrlParseError {
    out_url.has_opaque_path = true;
    out_url.href.append(scheme_str);
    out_url.href.push(':');
    out_url.scheme_end = scheme_str.len as i32;

    out_url.pathname_start = out_url.href.len as i32;
    var query_pos: i64 = -1;
    var hash_pos: i64 = -1;
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
    out_url: Url&,
    base_url: const Url&,
    frag_input: const u8[:],
) -> Url, UrlParseError {
    let base_href = href(base_url);
    let base_no_hash = if base_url.hash_start >= 0 { base_href[..base_url.hash_start] } else { base_href };
    out_url.href.append(base_no_hash);
    out_url.has_opaque_path = true;
    out_url.is_special = base_url.is_special;
    out_url.scheme_end = base_url.scheme_end;
    out_url.pathname_start = base_url.pathname_start;
    out_url.pathname_end = base_url.pathname_end;
    out_url.search_start = base_url.search_start;
    out_url.search_end = base_url.search_end;

    out_url.hash_start = out_url.href.len as i32;
    out_url.href.append(frag_input);
    out_url.hash_end = out_url.href.len as i32;

    out_url.valid = true;
    return out_url, UrlParseError.None;
}

fn parse_url_scheme_delimiter(input_bytes: const u8[:]) -> i64, bool {
    let delim_pos = find_any(input_bytes, URL_SCHEME_DELIM_SET);
    guard delim_pos > 0 && input_bytes[delim_pos] == ':' else {
        return -1, true;
    }
    let scheme_cand = input_bytes[..delim_pos];
    guard is_alpha_byte(scheme_cand[0]) else {
        return -1, false;
    }
    for char_byte in scheme_cand[1..] {
        if !is_alphanumeric_byte(char_byte) && char_byte != '+' && char_byte != '-' && char_byte != '.' {
            return -1, false;
        }
    }
    return delim_pos, true;
}

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
        guard colon_idx <= scheme_str.cap else {
            return out_url, UrlParseError.InvalidScheme;
        }
        scheme_str.append(input_bytes[..colon_idx]);
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
    var slash_count = 0;
    while slash_count < remainder.len && (remainder[slash_count] == '/' || (is_spec && remainder[slash_count] == '\\')) {
        slash_count++;
    }

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
            if has_base && scheme_str == scheme(base_url) && slash_count > 0 {
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

fn append_userinfo_to_url(out_url: Url&, userinfo: const u8[:]) {
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
        return;
    }

    out_url.username_start = out_url.href.len as i32;
    for char_byte in raw_user {
        if char_byte == '@' {
            out_url.href.append("%40");
        } else {
            out_url.href.push(char_byte);
        }
    }
    out_url.username_end = out_url.href.len as i32;

    if raw_pass.len > 0 {
        out_url.href.push(':');
        out_url.password_start = out_url.href.len as i32;
        for char_byte in raw_pass {
            if char_byte == '@' {
                out_url.href.append("%40");
            } else {
                out_url.href.push(char_byte);
            }
        }
        out_url.password_end = out_url.href.len as i32;
    }

    out_url.href.push('@');
}

fn apply_canonical_host_and_port(
    out_url: Url&,
    scheme_str: const u8[:],
    host_port_part: const u8[:],
) -> UrlParseError {
    var raw_host: u8[..256] = [];
    var port_val: i32 = -1;
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

    // In WHATWG URL, "localhost" on a file: URL normalizes to an empty host ("")
    if is_file && raw_host == "localhost" {
        raw_host.clear();
    }

    guard raw_host.len > 0 || is_file || !is_spec else {
        return UrlParseError.MissingHost;
    }

    to_lower(raw_host[..]);

    out_url.host_start = out_url.href.len as i32;
    out_url.href.append(raw_host[..]);
    out_url.host_end = out_url.href.len as i32;

    let def_port = default_port_for_scheme(scheme_str);
    if !is_file && port_val >= 0 && port_val != def_port {
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

fn parse_absolute_authority_url(
    out_url: Url&,
    scheme_str: const u8[:],
    is_spec: bool,
    auth_and_path: const u8[:],
) -> Url, UrlParseError {
    out_url.href.append(scheme_str);
    out_url.href.append("://");
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
        append_userinfo_to_url(out_url, userinfo);
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

fn is_alpha_byte(b: u8) -> bool {
    return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z');
}

fn is_alphanumeric_byte(b: u8) -> bool {
    return (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9');
}

// parse_url_view parses a URL of arbitrary length into a non-owning UrlView with zero heap allocations.
//
// Key Characteristics & Lifetimes:
// - Non-Owning Zero-Copy: Slices (scheme, host, path, query, hash) point directly into raw_input.
//   The caller MUST ensure raw_input outlives the UrlView.
// - Unbounded Length: Unlike the self-contained Url struct (capped at 2048 bytes), UrlView can parse
//   arbitrarily large URLs (e.g. 10KB+ data URLs or massive query strings) without copying memory.
// - Conformance: Implements the exact same RFC 3986 / WHATWG parsing rules, IPv6 bracket validation,
//   and default port identification as parse_url.
fn parse_url_view(raw_input: const u8[:]) -> UrlView, UrlParseError {
    var view = UrlView { valid: false, .. };
    guard raw_input.len > 0 else {
        return view, UrlParseError.EmptyInput;
    }

    // RFC 3986 §2 & CVE-2023-26159: Reject unencoded CRLF or NUL control characters (smuggling defense)
    for b in raw_input {
        guard b != '\r' && b != '\n' && b != 0 else {
            return view, UrlParseError.ForbiddenHostCodePoint;
        }
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
    guard is_alpha_byte(scheme_slice[0]) else {
        return view, UrlParseError.InvalidScheme;
    }
    for char_byte in scheme_slice[1..] {
        guard is_alphanumeric_byte(char_byte) || char_byte == '+' || char_byte == '-' || char_byte == '.' else {
            return view, UrlParseError.InvalidScheme;
        }
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

        var at_idx = -1;
        for scan_idx in authority.len {
            if authority[scan_idx] == '@' { at_idx = scan_idx; }
        }

        var host_port_slice = authority;
        if at_idx >= 0 {
            let userinfo = authority[..at_idx];
            host_port_slice = authority[at_idx + 1..];
            var user_colon = -1;
            for scan_idx in userinfo.len {
                if userinfo[scan_idx] == ':' { user_colon = scan_idx; break; }
            }
            if user_colon >= 0 {
                view.username = userinfo[..user_colon];
                view.password = userinfo[user_colon + 1..];
            } else {
                view.username = userinfo;
            }
        }

        if host_port_slice.len > 0 && host_port_slice[0] == '[' {
            var close_bracket = -1;
            for scan_idx in host_port_slice.len {
                if host_port_slice[scan_idx] == ']' { close_bracket = scan_idx; break; }
            }
            if close_bracket > 0 {
                let inside_brackets = host_port_slice[1..close_bracket];
                // RFC 3986 §3.2.2 & Go #75678 (CVE-2025-47912):
                // Bracketed host MUST be a valid IPv6 literal (or IPvFuture).
                // Hostnames and IPv4 addresses MUST NOT be enclosed in brackets.
                var dummy_comp: u8[..64] = [];
                guard parse_and_compress_ipv6(inside_brackets, dummy_comp) else {
                    return view, UrlParseError.InvalidIpv6;
                }
                view.host = inside_brackets;
                if close_bracket + 1 < host_port_slice.len {
                    // RFC 3986 §3.2.2 & Go #78569: Any character following ']' MUST be ':' introducing port number
                    guard host_port_slice[close_bracket + 1] == ':' else {
                        return view, UrlParseError.InvalidHost;
                    }
                    let port_str = host_port_slice[close_bracket + 2..];
                    let port_num, port_ok = parse_port_number(port_str);
                    if port_ok { view.port = port_num; } else { return view, UrlParseError.InvalidPort; }
                }
            } else {
                return view, UrlParseError.InvalidIpv6;
            }
        } else {
            var host_colon = -1;
            for scan_idx in host_port_slice.len {
                if host_port_slice[scan_idx] == ':' { host_colon = scan_idx; break; }
            }
            if host_colon >= 0 {
                view.host = host_port_slice[..host_colon];
                let port_str = host_port_slice[host_colon + 1..];
                let port_num, port_ok = parse_port_number(port_str);
                if port_ok { view.port = port_num; } else { return view, UrlParseError.InvalidPort; }
            } else {
                view.host = host_port_slice;
            }
            guard validate_host_punycode_labels(view.host) else {
                return view, UrlParseError.InvalidHost;
            }
        }
    }

    let rest = raw_input[cursor..];
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

    view.valid = true;
    return view, UrlParseError.None;
}

fn new_url_view(raw_input: const u8[:]) -> UrlView {
    let view, err = parse_url_view(raw_input);
    return view;
}

// Go #78760 / CVE-2026-39821: Reject invalid ACE/Punycode labels that contain no non-ASCII delta.
fn validate_host_punycode_labels(host_str: const u8[:]) -> bool {
    var cursor: i64 = 0;
    while cursor < host_str.len {
        var end = host_str.len;
        for i in cursor..host_str.len {
            if host_str[i] == '.' {
                end = i;
                break;
            }
        }
        let label = host_str[cursor..end];
        if label.len >= 4 && eq_ascii_fold(label[..4], "xn--") {
            if label.len == 4 || label[label.len - 1] == '-' {
                return false;
            }
        }
        cursor = end + 1;
    }
    return true;
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
        let pct_pos = index_of_slice(ipv6_body, "%25");

        if pct_pos >= 0 {
            let addr_to_parse = ipv6_body[..pct_pos];
            let zone_id = ipv6_body[pct_pos + 3..];
            guard zone_id.len > 0 && zone_id.len <= 32 else {
                return UrlParseError.InvalidIpv6;
            }
            for b in zone_id {
                let is_unreserved = (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') ||
                                    b == '-' || b == '.' || b == '_' || b == '~';
                guard is_unreserved else { return UrlParseError.InvalidIpv6; }
            }
            let ipv6_ok = parse_and_compress_ipv6(addr_to_parse, compressed_ipv6);
            guard ipv6_ok else {
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
    guard host_str.len <= host_out.cap else {
        return UrlParseError.InvalidHost;
    }

    host_out.append(host_str);

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

// Parses a dotted-quad IPv4 suffix e.g. ::ffff:192.0.2.1 into 2 x 16-bit pieces
fn parse_ipv4_mapped_pieces(
    rem_slice: const u8[:],
    pieces: u16[8]&,
    piece_count: i64&,
) -> bool {
    guard piece_count <= 6 else { return false; }
    var octets: i32[4] = [0, 0, 0, 0];
    var octet_idx = 0;
    var current_num = 0;
    var digits_count = 0;

    for char_byte in rem_slice {
        if char_byte == '.' {
            if digits_count == 0 || current_num > 255 || octet_idx >= 3 { return false; }
            octets[octet_idx] = current_num as i32;
            octet_idx++;
            current_num = 0;
            digits_count = 0;
        } else if char_byte >= '0' && char_byte <= '9' {
            if digits_count > 0 && current_num == 0 {
                return false; // Leading zero forbidden (e.g. 01, 001)
            }
            current_num = current_num * 10 + (char_byte - '0');
            digits_count++;
            if digits_count > 3 { return false; }
        } else {
            return false;
        }
    }

    if digits_count == 0 || current_num > 255 || octet_idx != 3 { return false; }
    octets[3] = current_num as i32;

    pieces[piece_count] = ((octets[0] << 8) | octets[1]) as u16;
    piece_count++;
    pieces[piece_count] = ((octets[2] << 8) | octets[3]) as u16;
    piece_count++;
    return true;
}

// Finds the longest continuous run of zero pieces for RFC 5952 canonical compression
fn find_longest_zero_run(pieces: const u16[8]&) -> i64, i64 {
    var best_run_start: i64 = -1;
    var best_run_len: i64 = 0;
    var current_run_start: i64 = -1;
    var current_run_len: i64 = 0;

    for piece_idx in 8 {
        if pieces[piece_idx] == 0 {
            if current_run_start < 0 {
                current_run_start = piece_idx;
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

    return best_run_start, best_run_len;
}

fn parse_ipv6_hex_piece(piece_str: const u8[:], out_val: u16&) -> bool {
    if piece_str.len > 4 || piece_str.len == 0 { return false; }
    var piece_val: u32 = 0;
    for char_byte in piece_str {
        let hex_digit = if char_byte >= '0' && char_byte <= '9' { char_byte - '0' }
                        else if char_byte >= 'a' && char_byte <= 'f' { char_byte - 'a' + 10 }
                        else if char_byte >= 'A' && char_byte <= 'F' { char_byte - 'A' + 10 }
                        else { return false; };
        piece_val = (piece_val << 4) | hex_digit;
    }
    out_val = piece_val as u16;
    return true;
}

fn expand_ipv6_double_colon(pieces: u16[8]&, piece_count: i64&, double_colon_pos: i64) -> bool {
    let missing = 8 - piece_count;
    if missing <= 0 { return false; }
    for rev_idx in piece_count - double_colon_pos {
        let src = piece_count - 1 - rev_idx;
        pieces[src + missing] = pieces[src];
    }
    for zero_idx in missing {
        pieces[double_colon_pos + zero_idx] = 0;
    }
    piece_count = 8;
    return true;
}

fn format_compressed_ipv6<B>(pieces: const u16[8]&, out: B&) {
    let best_run_start, best_run_len = find_longest_zero_run(pieces);
    var format_idx: i64 = 0;
    while format_idx < 8 {
        if format_idx == best_run_start {
            out.append("::");
            format_idx += best_run_len;
            continue;
        }
        if format_idx > 0 && !(format_idx == best_run_start + best_run_len && best_run_start == 0) && out.len > 0 && out[out.len - 1] != ':' {
            out.push(':');
        }
        format_hex_u16(out, pieces[format_idx]);
        format_idx++;
    }
}

// RFC 5952 / WHATWG IPv6 Parser and Zero-Run Canonical Compression
fn parse_and_compress_ipv6<B>(raw_ipv6: const u8[:], out: B&) -> bool {
    out.clear();
    var pieces: u16[8] = [0, 0, 0, 0, 0, 0, 0, 0];
    var piece_count: i64 = 0;
    var double_colon_pos: i64 = -1;

    var rem_slice = raw_ipv6;
    if rem_slice.len > 0 && rem_slice[0] == ':' {
        guard starts_with(rem_slice, "::") else {
            return false;
        }
        double_colon_pos = 0;
        rem_slice = rem_slice[2..];
    }

    while rem_slice.len > 0 && piece_count < 8 {
        var colon_idx = -1;
        for scan_idx in rem_slice.len {
            if rem_slice[scan_idx] == ':' {
                colon_idx = scan_idx;
                break;
            }
        }

        let piece_str = if colon_idx >= 0 { rem_slice[..colon_idx] } else { rem_slice };
        if piece_str.len == 0 {
            if double_colon_pos >= 0 { return false; }
            double_colon_pos = piece_count;
            rem_slice = rem_slice[1..];
            continue;
        }

        var has_dot = false;
        for char_byte in piece_str {
            if char_byte == '.' { has_dot = true; break; }
        }

        if has_dot {
            let parsed_ipv4 = parse_ipv4_mapped_pieces(rem_slice, pieces, piece_count);
            guard parsed_ipv4 else { return false; }
            rem_slice = rem_slice[rem_slice.len..];
            break;
        }

        var piece_val: u16 = 0;
        guard parse_ipv6_hex_piece(piece_str, piece_val) else { return false; }
        pieces[piece_count] = piece_val;
        piece_count++;

        if colon_idx >= 0 {
            if colon_idx + 1 < rem_slice.len && rem_slice[colon_idx + 1] == ':' {
                if double_colon_pos >= 0 { return false; }
                double_colon_pos = piece_count;
                rem_slice = rem_slice[colon_idx + 2..];
            } else {
                guard colon_idx + 1 < rem_slice.len else { return false; }
                rem_slice = rem_slice[colon_idx + 1..];
            }
        } else {
            rem_slice = rem_slice[rem_slice.len..];
        }
    }

    if rem_slice.len > 0 { return false; }

    if double_colon_pos >= 0 {
        guard expand_ipv6_double_colon(pieces, piece_count, double_colon_pos) else { return false; }
    }

    guard piece_count == 8 else { return false; }

    format_compressed_ipv6(pieces, out);
    return true;
}

fn format_hex_u16<B>(out: B&, val: u16) {
    if val == 0 {
        out.push('0');
        return;
    }
    var hex_buf: u8[..4] = [];
    var cur_val = val;
    while cur_val > 0 {
        let rem = (cur_val & 0x0F) as u8;
        hex_buf.push(if rem < 10 { '0' + rem } else { 'a' + (rem - 10) });
        cur_val >>= 4;
    }
    for rev_idx in hex_buf.len {
        out.push(hex_buf[hex_buf.len - 1 - rev_idx]);
    }
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
    if seg.len == 2 && ((seg[0] >= 'a' && seg[0] <= 'z') || (seg[0] >= 'A' && seg[0] <= 'Z')) && (seg[1] == ':' || seg[1] == '|') {
        return true;
    }
    return false;
}

fn handle_path_segment(seg: const u8[:], is_file: bool, out_url: Url&, seg_starts: i32[..1024]&, last_was_dot: bool&) -> UrlParseError {
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
        let is_delim = (scan_idx == raw_path.len) ||
                       (raw_path[scan_idx] == '/') ||
                       (is_spec && raw_path[scan_idx] == '\\');

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

    if has_trailing_slash {
        if out_url.href.len == path_start_offset {
            guard out_url.href.try_push('/') else {
                return UrlParseError.InputTooLong;
            }
        } else if out_url.href[out_url.href.len - 1] != '/' {
            guard out_url.href.try_push('/') else {
                return UrlParseError.InputTooLong;
            }
        }
    } else if out_url.href.len == path_start_offset && is_spec {
        guard out_url.href.try_push('/') else {
            return UrlParseError.InputTooLong;
        }
    }
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

fn resolve_relative_path_against_base(
    out_url: Url&,
    base_url: const Url&,
    rel_input: const u8[:],
) -> Url, UrlParseError {
    guard rel_input.len > 0 else {
        // Empty relative input copies base URL with fragment stripped per WHATWG URL Section 4.4
        let base_href = href(base_url);
        let base_no_hash = if base_url.hash_start >= 0 { base_href[..base_url.hash_start] } else { base_href };
        out_url.href.append(base_no_hash);
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
        out_url.href.append(base_no_hash);
        copy_base_authority_offsets(out_url, base_url);
        out_url.pathname_start = base_url.pathname_start;
        out_url.pathname_end = base_url.pathname_end;
        out_url.search_start = base_url.search_start;
        out_url.search_end = base_url.search_end;

        out_url.hash_start = out_url.href.len as i32;
        out_url.href.append(rel_input);
        out_url.hash_end = out_url.href.len as i32;
        out_url.valid = true;
        return out_url, UrlParseError.None;
    }

    if rel_input[0] == '?' {
        // Query and hash only: keep scheme, authority, and path from base
        let base_href = href(base_url);
        let base_path_end = if base_url.pathname_end >= 0 { base_url.pathname_end } else if base_url.host_end >= 0 { base_url.host_end } else { base_url.scheme_end + 1 };
        out_url.href.append(base_href[..base_path_end]);
        copy_base_authority_offsets(out_url, base_url);
        out_url.pathname_start = base_url.pathname_start;
        out_url.pathname_end = base_url.pathname_end;

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
    var auth_end = if base_url.port_end > base_url.host_end { base_url.port_end } else { base_url.host_end };
    if auth_end < 0 {
        auth_end = base_url.scheme_end + 1;
    }
    out_url.href.append(base_href[..auth_end]);
    copy_base_authority_offsets(out_url, base_url);

    var combined_path: u8[..2048] = [];

    if rel_input[0] == '/' || (is_spec && rel_input[0] == '\\') {
        // Root relative path
        if is_file_url(base_url) {
            let base_path = pathname(base_url);
            let has_base_drive = base_path.len >= 3 && base_path[0] == '/' && is_windows_drive_segment(base_path[1..3]);
            var rel_has_drive = false;
            let rel_start = if rel_input.len > 1 && (rel_input[1] == '/' || rel_input[1] == '\\') { 2 } else { 1 };
            if rel_input.len >= rel_start + 2 && is_windows_drive_segment(rel_input[rel_start..rel_start + 2]) {
                rel_has_drive = true;
            }
            if has_base_drive && !rel_has_drive {
                combined_path.push('/');
                combined_path.push(base_path[1]);
                combined_path.push(':');
            }
        }
        combined_path.append(rel_input);
    } else {
        // Directory relative path
        let base_path = pathname(base_url);
        var last_slash = -1;
        for scan_idx in base_path.len {
            if base_path[scan_idx] == '/' { last_slash = scan_idx; }
        }
        if last_slash >= 0 {
            combined_path.append(base_path[..last_slash + 1]);
        } else {
            combined_path.push('/');
        }
        combined_path.append(rel_input);
    }

    let path_err = append_canonical_path_and_query(out_url, is_spec, combined_path[..]);
    guard path_err == UrlParseError.None else {
        return out_url, path_err;
    }
    out_url.valid = true;
    return out_url, UrlParseError.None;
}
