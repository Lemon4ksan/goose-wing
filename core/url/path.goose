// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// URL path manipulation, percent-encoding, file URLs and reference/endpoint resolution.
namespace core;

import std;

// ---- file urls and swift-like path manipulation ----------------------------

fn percent_decode<B>(input_bytes: const u8[:], out: B&) {
    out.clear();
    var scan_idx = 0;
    while scan_idx < input_bytes.len {
        if input_bytes[scan_idx] == '%' && scan_idx + 2 < input_bytes.len {
            let high_nibble = hex_digit_to_val(input_bytes[scan_idx + 1]);
            let low_nibble = hex_digit_to_val(input_bytes[scan_idx + 2]);
            if high_nibble >= 0 && low_nibble >= 0 {
                let decoded_char = ((high_nibble << 4) | low_nibble) as u8;
                out.push(decoded_char);
                scan_idx += 3;
                continue;
            }
        }
        out.push(input_bytes[scan_idx]);
        scan_idx++;
    }
}

fn percent_encode_path_segment<B>(raw_segment: const u8[:], out: B&) {
    for char_byte in raw_segment {
        if char_byte == ' ' {
            out.append("%20");
        } else if char_byte == '#' {
            out.append("%23");
        } else if char_byte == '?' {
            out.append("%3F");
        } else if char_byte == '%' {
            out.append("%25");
        } else if char_byte < 0x20 || char_byte == 0x7F {
            out.push('%');
            let high_val = (char_byte >> 4) & 0x0F;
            let low_val = char_byte & 0x0F;
            out.push(if high_val < 10 { ('0' + high_val) as u8 } else { ('A' + high_val - 10) as u8 });
            out.push(if low_val < 10 { ('0' + low_val) as u8 } else { ('A' + low_val - 10) as u8 });
        } else {
            out.push(char_byte);
        }
    }
}

fn append_encoded_subpath<B>(raw_subpath: const u8[:], out: B&) {
    for char_byte in raw_subpath {
        if char_byte == '\\' {
            out.push('/');
        } else if char_byte == ' ' {
            out.append("%20");
        } else if char_byte == '#' {
            out.append("%23");
        } else if char_byte == '?' {
            out.append("%3F");
        } else if char_byte == '%' {
            out.append("%25");
        } else {
            out.push(char_byte);
        }
    }
}

// Constructs a file: URL from a native operating system file path (Windows or POSIX).
// Normalizes drive letters (C:\... -> file:///C:/...), UNC paths (\\server\share -> file://server/share),
// and percent-encodes spaces and special characters.
fn new_file_url(file_path: const u8[:]) -> Url {
    var raw_href: u8[..2048] = [];
    raw_href.append("file://");

    guard file_path.len > 0 else {
        raw_href.push('/');
        return new_url(raw_href[..]);
    }

    // Windows UNC path (e.g. \\server\share\file.txt or //server/share/file.txt)
    if file_path.len >= 2 && (file_path[0] == '\\' || file_path[0] == '/') && (file_path[1] == '\\' || file_path[1] == '/') {
        append_encoded_subpath(file_path[2..], raw_href);
        return new_url(raw_href[..]);
    }

    // Windows Drive letter (e.g. C:\Users\... or C:/Users/... or c:...)
    let is_windows_drive = file_path.len >= 2 &&
        ((file_path[0] >= 'a' && file_path[0] <= 'z') || (file_path[0] >= 'A' && file_path[0] <= 'Z')) &&
        (file_path[1] == ':' || file_path[1] == '|');

    if is_windows_drive {
        raw_href.push('/');
        raw_href.push(file_path[0]);
        raw_href.push(':');
        raw_href.push('/');
        let rest_start = if file_path.len > 2 && (file_path[2] == '/' || file_path[2] == '\\') { 3 } else { 2 };
        if rest_start < file_path.len {
            append_encoded_subpath(file_path[rest_start..], raw_href);
        }
        return new_url(raw_href[..]);
    }

    // POSIX absolute or relative path
    if file_path[0] != '/' && file_path[0] != '\\' {
        raw_href.push('/');
    }
    append_encoded_subpath(file_path, raw_href);
    return new_url(raw_href[..]);
}

// Determines if this URL represents a file-system URL (scheme == "file").
fn is_file_url(url_val: const Url&) -> bool {
    return url_val.valid && scheme(url_val) == "file";
}

// Extracts the native operating system file path from a file: URL.
// Decodes percent-encoded bytes (%20 -> space), drops the leading slash before Windows drive letters,
// and normalizes separators to the native Windows backslash when a drive letter is present.
fn file_path<B>(url_val: const Url&, out: B&) -> bool {
    out.clear();
    guard is_file_url(url_val) else { return false; }

    let host_str = hostname(url_val);
    let raw_pathname = pathname(url_val);
    guard raw_pathname.len > 0 else { return false; }

    var decoded: u8[..2048] = [];
    percent_decode(raw_pathname, decoded);

    // Windows UNC network path (\\server\share\file.txt)
    if host_str.len > 0 && host_str != "localhost" {
        out.append("\\\\");
        out.append(host_str);
        for char_byte in decoded {
            if char_byte == '/' {
                out.push('\\');
            } else {
                out.push(char_byte);
            }
        }
        return true;
    }

    // Check if path has a Windows drive letter, e.g. /C:/Users/... or /c:/...
    let has_windows_drive = decoded.len >= 3 &&
        decoded[0] == '/' &&
        ((decoded[1] >= 'a' && decoded[1] <= 'z') || (decoded[1] >= 'A' && decoded[1] <= 'Z')) &&
        decoded[2] == ':';

    if has_windows_drive {
        // Drop leading '/' before drive letter: C:\Users\...
        for scan_idx in 1..decoded.len {
            let char_byte = decoded[scan_idx];
            if char_byte == '/' {
                out.push('\\');
            } else {
                out.push(char_byte);
            }
        }
        return true;
    }

    // POSIX path: preserve leading '/' and forward slashes
    out.append(decoded[..]);
    return true;
}

// Returns the last path component of the URL path (like Swift url.lastPathComponent).
// Example: file:///a/b/c.pdf -> "c.pdf", file:///a/b/ -> "b", file:/// -> "/"
fn last_path_component(url_val: const Url&) -> const u8[:] {
    let raw_path = pathname(url_val);
    guard raw_path.len > 0 else { return ""; }

    var end_idx = raw_path.len;
    while end_idx > 1 && raw_path[end_idx - 1] == '/' {
        end_idx--;
    }

    if end_idx == 1 && raw_path[0] == '/' {
        return raw_path[..1]; // Root slash
    }

    var last_slash_idx = -1;
    for scan_idx in end_idx {
        if raw_path[scan_idx] == '/' {
            last_slash_idx = scan_idx;
        }
    }

    if last_slash_idx >= 0 {
        return raw_path[last_slash_idx + 1..end_idx];
    }
    return raw_path[..end_idx];
}

// Returns the path extension of the last path component (like Swift url.pathExtension).
// Example: "report.pdf" -> "pdf", "archive.tar.gz" -> "gz", ".gitignore" -> ""
fn path_extension(url_val: const Url&) -> const u8[:] {
    let component = last_path_component(url_val);
    guard component.len > 1 else { return ""; }

    var last_dot_idx = -1;
    for scan_idx in component.len {
        if component[scan_idx] == '.' {
            last_dot_idx = scan_idx;
        }
    }

    // In Swift: leading dot (.gitignore) or trailing dot (file.) has no extension
    if last_dot_idx <= 0 || last_dot_idx == (component.len - 1) {
        return "";
    }

    return component[last_dot_idx + 1..];
}

// Returns a new URL with the path extension removed from the last path component (like Swift url.deletingPathExtension()).
// Example: file:///a/b/report.pdf -> file:///a/b/report
fn deleting_path_extension(url_val: Url) -> Url {
    guard url_val.valid else { return url_val; }
    let ext = path_extension(url_val);
    guard ext.len > 0 else { return url_val; }

    let raw_path = pathname(url_val);
    var has_slash = false;
    var eff_path_len = raw_path.len;
    while eff_path_len > 1 && raw_path[eff_path_len - 1] == '/' {
        has_slash = true;
        eff_path_len--;
    }

    let dot_and_ext_len = ext.len + 1; // ".ext"
    guard eff_path_len >= dot_and_ext_len else { return url_val; }

    let path_start = url_val.pathname_start as i64;
    let path_end = url_val.pathname_end as i64;

    var new_href: u8[..2048] = [];
    new_href.append(url_val.href[..path_start]);
    new_href.append(raw_path[..eff_path_len - dot_and_ext_len]);
    if has_slash {
        new_href.push('/');
    }
    if path_end < url_val.href.len {
        new_href.append(url_val.href[path_end..]);
    }

    return new_url(new_href[..]);
}

// Returns a new URL pointing to the parent directory (like Swift url.deletingLastPathComponent()).
// Example: file:///a/b/c.txt -> file:///a/b/, file:///a/b/ -> file:///a/
fn deleting_last_path_component(url_val: Url) -> Url {
    guard url_val.valid else { return url_val; }
    let raw_path = pathname(url_val);
    guard raw_path.len > 1 else { return url_val; }

    // Protect Windows drive root in file: URL, e.g. /C:/ or /C:
    if is_file_url(url_val) && raw_path.len >= 3 && raw_path[0] == '/' && is_windows_drive_segment(raw_path[1..3]) {
        if raw_path.len == 3 || (raw_path.len == 4 && raw_path[3] == '/') {
            return url_val; // Already at drive root C:/
        }
    }

    var end_idx = raw_path.len;
    while end_idx > 1 && raw_path[end_idx - 1] == '/' {
        end_idx--;
    }

    if end_idx <= 1 {
        return url_val;
    }

    var last_slash_idx = -1;
    for scan_idx in end_idx {
        if raw_path[scan_idx] == '/' {
            last_slash_idx = scan_idx;
        }
    }

    let new_path_end = if last_slash_idx <= 0 { 1 } else { last_slash_idx + 1 };
    let path_start = url_val.pathname_start as i64;
    let path_end = url_val.pathname_end as i64;

    var new_href: u8[..2048] = [];
    new_href.append(url_val.href[..path_start]);
    new_href.append(raw_path[..new_path_end]);
    if path_end < url_val.href.len {
        new_href.append(url_val.href[path_end..]);
    }

    return new_url(new_href[..]);
}

// Appends a single path component to the URL path (like Swift url.appending(component:)).
// Safely ensures single-slash separation and percent-encodes spaces and special characters.
fn appending_path_component(url_val: Url, component: const u8[:]) -> Url {
    guard url_val.valid && component.len > 0 else { return url_val; }

    let path_end = url_val.pathname_end as i64;
    var new_href: u8[..2048] = [];
    let cur_path = pathname(url_val);

    new_href.append(url_val.href[..path_end]);
    if cur_path.len == 0 || cur_path[cur_path.len - 1] != '/' {
        new_href.push('/');
    }

    let clean_comp = if component[0] == '/' || component[0] == '\\' { component[1..] } else { component };
    percent_encode_path_segment(clean_comp, new_href);

    if path_end < url_val.href.len {
        new_href.append(url_val.href[path_end..]);
    }

    return new_url(new_href[..]);
}

// Appends a relative subpath (which may contain multiple slashes) to the URL path (like Swift url.appending(path:)).
fn appending_path(url_val: Url, subpath: const u8[:]) -> Url {
    guard url_val.valid && subpath.len > 0 else { return url_val; }

    let path_end = url_val.pathname_end as i64;
    var new_href: u8[..2048] = [];
    let cur_path = pathname(url_val);

    new_href.append(url_val.href[..path_end]);
    if cur_path.len == 0 || cur_path[cur_path.len - 1] != '/' {
        new_href.push('/');
    }

    let clean_sub = if subpath[0] == '/' || subpath[0] == '\\' { subpath[1..] } else { subpath };
    append_encoded_subpath(clean_sub, new_href);

    if path_end < url_val.href.len {
        new_href.append(url_val.href[path_end..]);
    }

    return new_url(new_href[..]);
}

// Appends a file extension to the last path component (like Swift url.appendingPathExtension()).
// Example: file:///data/report + "json" -> file:///data/report.json
fn appending_path_extension(url_val: Url, ext: const u8[:]) -> Url {
    guard url_val.valid && ext.len > 0 else { return url_val; }

    let clean_ext = if ext[0] == '.' { ext[1..] } else { ext };
    guard clean_ext.len > 0 else { return url_val; }

    let raw_path = pathname(url_val);
    var has_slash = false;
    var eff_path_len = raw_path.len;
    while eff_path_len > 1 && raw_path[eff_path_len - 1] == '/' {
        has_slash = true;
        eff_path_len--;
    }

    let path_start = url_val.pathname_start as i64;
    let path_end = url_val.pathname_end as i64;

    var new_href: u8[..2048] = [];
    new_href.append(url_val.href[..path_start]);
    new_href.append(raw_path[..eff_path_len]);
    new_href.push('.');
    percent_encode_path_segment(clean_ext, new_href);
    if has_slash {
        new_href.push('/');
    }
    if path_end < url_val.href.len {
        new_href.append(url_val.href[path_end..]);
    }

    return new_url(new_href[..]);
}

// ---- dual-mode url resolution (rfc reference vs backend endpoint) ---------

// Resolves a relative URL reference against a base URL strictly conforming to RFC 3986 / WHATWG URL Standard (Browser behavior).
// If `base_url` path does not end with '/' (e.g. "http://example.com/api"), resolving "/v1" or "v1" will replace "/api"
// with "/v1", exactly as web browsers, HTML links, and RFC specifications dictate.
// Examples:
//   "http://example.com/api"  + "/v1"  -> "http://example.com/v1"
//   "http://example.com/api"  + "v1"   -> "http://example.com/v1"
//   "http://example.com/api/" + "v1"   -> "http://example.com/api/v1"
//   "http://example.com/api/" + "/v1"  -> "http://example.com/v1"
fn resolve_reference(base_url: const Url&, relative_ref: const u8[:]) -> Url {
    return new_url(relative_ref, base_url);
}

fn parse_reference(base_url: const Url&, relative_ref: const u8[:]) -> Url, UrlParseError {
    return parse_url_with_base(relative_ref, base_url);
}

// Resolves an API endpoint against a base URL using Backend / Service semantics (API Client behavior).
// Unlike RFC 3986 reference resolution, the base URL's pathname is treated as a permanent route prefix (e.g. "/api" or "/v1")
// regardless of whether `base_url` ends with a trailing slash.
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

fn join_endpoint(base_url: const Url&, endpoint: const u8[:]) -> Url {
    return resolve_endpoint(base_url, endpoint);
}

// parse_endpoint resolves an API endpoint against base_url using API Client / Microservice semantics.
//
// Caller Contract & Nuances:
// - Empty Endpoint Preservation: If endpoint is empty (""), returns an exact copy of base_url
//   without stripping existing fragments ('#') or query strings ('?').
// - Absolute Override: If endpoint has an explicit scheme (e.g. "https://other.com/v1"),
//   it overrides base_url completely.
// - Route Prefix Semantics: Unlike RFC 3986 reference resolution (which treats "/api/v1" as a file
//   and strips "v1" when joining a relative reference), parse_endpoint treats base_url path as
//   a permanent service mount prefix (e.g. "/api" + "/v1" -> "/api/v1").
// - Protocol-Relative Inheritance: Endpoints starting with "//" inherit scheme from base_url.
// - Query and Fragment Isolation: Endpoint queries and fragments are appended/merged cleanly
//   without delimiter corruption.
fn parse_endpoint(base_url: const Url&, endpoint: const u8[:]) -> Url, UrlParseError {
    guard base_url.valid else {
        return Url { valid: false, .. }, UrlParseError.RelativeWithoutBase;
    }

    var cleaned_endpoint: u8[..2048] = [];
    clean_input_string(endpoint, cleaned_endpoint);
    guard cleaned_endpoint.len > 0 else {
        return copy(base_url), UrlParseError.None;
    }

    let ep_str = cleaned_endpoint[..];

    // If endpoint is an absolute URL (e.g. https://... or custom://...), it overrides base completely
    var colon_pos = -1;
    for scan_idx in ep_str.len {
        let char_byte = ep_str[scan_idx];
        if char_byte == ':' { colon_pos = scan_idx; break; }
        if char_byte == '/' || char_byte == '\\' || char_byte == '?' || char_byte == '#' { break; }
    }
    if colon_pos > 0 {
        let abs_url, abs_err = parse_url(ep_str);
        if abs_url.valid {
            return abs_url, UrlParseError.None;
        }
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
    var q_pos = -1;
    var h_pos = -1;
    for scan_idx in ep_str.len {
        let char_byte = ep_str[scan_idx];
        if char_byte == '?' && q_pos < 0 && h_pos < 0 {
            q_pos = scan_idx;
        } else if char_byte == '#' && h_pos < 0 {
            h_pos = scan_idx;
            break;
        }
    }

    let path_end = if q_pos >= 0 { q_pos } else if h_pos >= 0 { h_pos } else { ep_str.len };
    let raw_subpath = ep_str[..path_end];
    let query_and_hash = ep_str[path_end..];

    // Build combined path: base_pathname + "/" + subpath (stripping leading slashes from subpath)
    var combined: u8[..2048] = [];
    let base_path = pathname(base_url);
    combined.append(base_path);

    if combined.len == 0 || combined[combined.len - 1] != '/' {
        combined.push('/');
    }

    var sub_start = 0;
    while sub_start < raw_subpath.len && (raw_subpath[sub_start] == '/' || raw_subpath[sub_start] == '\\') {
        sub_start++;
    }
    combined.append(raw_subpath[sub_start..]);
    combined.append(query_and_hash);

    // Resolve combined path against base URL authority
    return parse_url_with_base(combined[..], base_url);
}

