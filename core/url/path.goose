// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// URL percent-decoding and endpoint resolution.
namespace core;

import std;

fn percent_decode<B>(input_bytes: const u8[:], out: B&) -> bool {
    out.clear();
    guard input_bytes.len > 0 else { return true; }
    if index_of_byte(input_bytes, '%') < 0 {
        return out.try_set(input_bytes);
    }
    var scan_idx = 0;
    while scan_idx < input_bytes.len {
        let has_hex = input_bytes[scan_idx] == '%' && scan_idx + 2 < input_bytes.len;
        let hi = if has_hex { hex_digit_to_val(input_bytes[scan_idx + 1]) } else { -1 };
        let lo = if has_hex { hex_digit_to_val(input_bytes[scan_idx + 2]) } else { -1 };
        let is_esc = hi >= 0 && lo >= 0;
        let decoded_char = if is_esc { ((hi << 4) | lo) as u8 } else { input_bytes[scan_idx] };
        guard out.try_push(decoded_char) else {
            out.clear();
            return false;
        }
        scan_idx += if is_esc { 3 } else { 1 };
    }
    return true;
}

// Determines if this URL represents a file-system URL (scheme == "file").
fn is_file_url(url_val: const Url&) -> bool {
    return url_val.valid && scheme(url_val) == "file";
}

// Resolves an API endpoint against a base URL using Backend / Service semantics (API Client behavior).
// Unlike RFC 3986 reference resolution, the base URL's pathname is treated as a permanent route prefix
// (e.g. "/api" or "/v1") regardless of whether `base_url` ends with a trailing slash.
// Examples:
//   "http://example.com/api"  + "/v1"       -> "http://example.com/api/v1"
//   "http://example.com/api"  + "v1"        -> "http://example.com/api/v1"
//   "http://example.com/api/" + "/v1"       -> "http://example.com/api/v1"
//   "http://example.com/api"  + "/v1/users?p=1#top" -> "http://example.com/api/v1/users?p=1#top"
//   "http://example.com/api"  + "https://other.com/metrics" -> "https://other.com/metrics" (absolute URL override)
fn resolve_endpoint(base_url: const Url&, endpoint: const u8[:]) -> Url {
    let res_url, err = parse_endpoint(base_url, endpoint);
    return res_url;
}

inline fn find_scheme_colon(s: const u8[:]) -> i64 {
    for scan_idx in s.len {
        let char_byte = s[scan_idx];
        if char_byte == ':' { return scan_idx; }
        if char_byte == '/' || char_byte == '\\' || char_byte == '?' || char_byte == '#' { break; }
    }
    return -1;
}

inline fn find_query_or_hash_start(s: const u8[:]) -> i64 {
    let before_q, _, _ = partition_byte(s, '?');
    let before_h, _, _ = partition_byte(before_q, '#');
    return before_h.len;
}

inline fn skip_leading_slashes(s: const u8[:]) -> i64 {
    var sub_start = 0;
    while sub_start < s.len && (s[sub_start] == '/' || s[sub_start] == '\\') {
        sub_start++;
    }
    return sub_start;
}

// parse_endpoint resolves an API endpoint against base_url using API Client / Microservice semantics.
//
// Caller Contract & Nuances:
// - If endpoint is empty (""), returns an exact copy of base_url
//   without stripping existing fragments ('#') or query strings ('?').
// - If endpoint has an explicit scheme (e.g. "https://other.com/v1"),
//   it overrides base_url completely.
// - Unlike RFC 3986 reference resolution (which treats "/api/v1" as a file and strips
//   "v1" when joining a relative reference), parse_endpoint treats base_url path as
//   a permanent service mount prefix (e.g. "/api" + "/v1" -> "/api/v1").
// - Endpoints starting with "//" inherit scheme from base_url.
// - Endpoint queries and fragments are appended/merged cleanly
//   without delimiter corruption.
//
// Example:
//   base_url = "http://example.com/api", endpoint = "/v1/users?p=1"
//   returns: url with href "http://example.com/api/v1/users?p=1", err = UrlParseError.None
fn parse_endpoint(base_url: const Url&, endpoint: const u8[:]) -> Url, UrlParseError {
    guard base_url.valid else {
        return Url { valid: false, .. }, UrlParseError.RelativeWithoutBase;
    }

    guard endpoint.len <= 2048 else {
        return Url { valid: false, .. }, UrlParseError.InputTooLong;
    }

    var cleaned_endpoint: u8[..2048] = [];
    clean_input_string(endpoint, cleaned_endpoint);
    guard cleaned_endpoint.len > 0 else {
        return copy(base_url), UrlParseError.None;
    }

    let ep_str = cleaned_endpoint[..];

    // If endpoint is an absolute URL (e.g. https://... or custom://...), it overrides base completely
    let colon_pos = find_scheme_colon(ep_str);
    if colon_pos > 0 && is_valid_scheme_slice(ep_str[..colon_pos]) {
        return parse_url(ep_str);
    }

    // Protocol-relative (//...) inherits scheme from base
    if ep_str.len >= 2 && ep_str[0] == '/' && ep_str[1] == '/' {
        return parse_url_with_base(ep_str, base_url);
    }

    // Hash-only (#frag) or Query-only (?query) delegates to reference resolution
    if ep_str[0] == '#' || ep_str[0] == '?' {
        return parse_url_with_base(ep_str, base_url);
    }

    // Split endpoint into path vs query/hash
    let path_end = find_query_or_hash_start(ep_str);
    let raw_subpath = ep_str[..path_end];
    let query_and_hash = ep_str[path_end..];

    // Build combined path: base_pathname + "/" + subpath (stripping leading slashes from subpath)
    var combined: u8[..2048] = [];
    let base_path = pathname(base_url);
    guard combined.try_append(base_path) else {
        return Url { valid: false, .. }, UrlParseError.InputTooLong;
    }

    if !ends_with(combined[..], "/") {
        guard combined.try_push('/') else {
            return Url { valid: false, .. }, UrlParseError.InputTooLong;
        }
    }
    let prefix_len = collapse_repeats_in_place(combined[..], '/');
    combined.resize(prefix_len);

    let sub_start = skip_leading_slashes(raw_subpath);
    guard combined.try_append(raw_subpath[sub_start..]) else {
        return Url { valid: false, .. }, UrlParseError.InputTooLong;
    }
    guard combined.try_append(query_and_hash) else {
        return Url { valid: false, .. }, UrlParseError.InputTooLong;
    }

    // Resolve combined path against base URL authority
    return parse_url_with_base(combined[..], base_url);
}
