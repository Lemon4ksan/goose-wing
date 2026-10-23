// The Goose standard URL, Origin & Path library: candidate for `std::url`.
//
// Core Types:
//   Url             - Canonical WHATWG URL with contiguous buffer and compact index offsets.
//   Origin          - Security origin model differentiating Tuple (scheme, host, port) and Opaque.
//   OriginKind      - Origin classification enum (Tuple, Opaque).
//   RegistrableSite - Schemeful Same-Site identity tuple (scheme, eTLD+1 registrable domain).
//   UrlParseError   - Explicit lexical and structural parse diagnostics enum.
//
// Standards & Specifications:
//   WHATWG URL Living Standard (single-buffer ada-url / sorug index-offset model).
//   RFC 5952 IPv6 canonical zero-run compression and IPv4-mapped IPv6 normalization.
//   RFC 6265bis Schemeful Same-Site and HTML5 Origin serialization rules.
//   Swift Foundation-style cross-platform File URL normalization and path manipulation.
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
    if g_opaque_nonce_counter == 0 { g_opaque_nonce_counter = 1; }
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
    let parsed_url, err = parse_url(raw_input);
    return parsed_url;
}

fn new_url(raw_input: const u8[:], base_url: const Url&) -> Url {
    let parsed_url, err = parse_url_with_base(raw_input, base_url);
    return parsed_url;
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
    if url_val.port >= 0 { return url_val.port; }
    let scheme_str = scheme(url_val);
    if scheme_str == "http" || scheme_str == "ws" { return 80; }
    if scheme_str == "https" || scheme_str == "wss" { return 443; }
    if scheme_str == "ftp" { return 21; }
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
    let scheme_str = scheme(url_val);
    return scheme_str == "http" || scheme_str == "https";
}

fn is_secure_scheme(url_val: const Url&) -> bool {
    guard url_val.valid else { return false; }
    let scheme_str = scheme(url_val);
    return scheme_str == "https" || scheme_str == "wss";
}

// ---- file urls and swift-like path manipulation ----------------------------

fn hex_digit_to_val(char_byte: u8) -> i32 {
    if char_byte >= '0' && char_byte <= '9' { return char_byte - '0'; }
    if char_byte >= 'a' && char_byte <= 'f' { return char_byte - 'a' + 10; }
    if char_byte >= 'A' && char_byte <= 'F' { return char_byte - 'A' + 10; }
    return -1;
}

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
    var raw_href: u8[..512] = [];
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
        file_path[1] == ':';

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

    var decoded: u8[..512] = [];
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

    var new_href: u8[..512] = [];
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

    var new_href: u8[..512] = [];
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
    var new_href: u8[..512] = [];
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
    var new_href: u8[..512] = [];
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

    var new_href: u8[..512] = [];
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

// ---- origin and site derivations -------------------------------------------

fn origin_from_url(url_val: const Url&) -> Origin {
    guard url_val.valid else { return new_opaque_origin(); }
    let scheme_str = scheme(url_val);

    if scheme_str == "http" || scheme_str == "https" || scheme_str == "ws" || scheme_str == "wss" || scheme_str == "ftp" {
        let eff_port = effective_port(url_val);
        return new_origin_tuple(scheme_str, hostname(url_val), eff_port);
    }

    if scheme_str == "blob" {
        // WHATWG URL Section 4.7: blob: URLs inherit the origin of the embedded URL in their path
        let inner_path = pathname(url_val);
        let inner_url, parse_err = parse_url(inner_path);
        if inner_url.valid && (scheme(inner_url) == "http" || scheme(inner_url) == "https") {
            let eff_port = effective_port(inner_url);
            return new_origin_tuple(scheme(inner_url), hostname(inner_url), eff_port);
        }
        return new_opaque_origin();
    }

    if scheme_str == "file" {
        return new_opaque_origin();
    }

    // data:, about: and unknown schemes produce opaque origins
    return new_opaque_origin();
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

    let scheme_str = origin_val.scheme[..];
    let is_def_port = (scheme_str == "http" && origin_val.port == 80) ||
                      (scheme_str == "https" && origin_val.port == 443) ||
                      (scheme_str == "ws" && origin_val.port == 80) ||
                      (scheme_str == "wss" && origin_val.port == 443) ||
                      (scheme_str == "ftp" && origin_val.port == 21) ||
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
    guard site_a.registrable_domain.len > 0 && site_b.registrable_domain.len > 0 else {
        return false;
    }
    return eq_ascii_fold(site_a.scheme[..], site_b.scheme[..]) &&
           eq_ascii_fold(site_a.registrable_domain[..], site_b.registrable_domain[..]);
}

fn is_same_site_origin_url(origin_val: const Origin&, url_val: const Url&) -> bool {
    if origin_val.kind == OriginKind.Opaque || !url_val.valid { return false; }
    var orig_etld: u8[..128] = [];
    extract_etld_plus_one(origin_val.host[..], orig_etld);

    let site_url = registrable_site_from_url(url_val);
    guard orig_etld.len > 0 && site_url.registrable_domain.len > 0 else {
        return false;
    }
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
        let char_byte = raw[scan_idx];
        if char_byte != 0x09 && char_byte != 0x0A && char_byte != 0x0D {
            out.push(char_byte);
        }
    }
}

fn has_forbidden_host_code_point(host_str: const u8[:]) -> bool {
    for char_byte in host_str {
        if char_byte <= 0x20 || char_byte == 0x7F ||
           char_byte == '#' || char_byte == '%' || char_byte == '/' || char_byte == ':' ||
           char_byte == '<' || char_byte == '>' || char_byte == '?' || char_byte == '@' ||
           char_byte == '[' || char_byte == '\\' || char_byte == ']' || char_byte == '^' ||
           char_byte == '|' {
            return true;
        }
    }
    return false;
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
    var invalid_scheme = false;
    for scan_idx in input_bytes.len {
        let char_byte = input_bytes[scan_idx];
        if char_byte == ':' {
            colon_idx = scan_idx;
            break;
        }
        if char_byte == '/' || char_byte == '\\' || char_byte == '?' || char_byte == '#' {
            break; // Stop looking for scheme once path/query/fragment starts
        }
        let is_scheme_char = (scan_idx == 0 && ((char_byte >= 'a' && char_byte <= 'z') || (char_byte >= 'A' && char_byte <= 'Z'))) ||
                             (scan_idx > 0 && ((char_byte >= 'a' && char_byte <= 'z') || (char_byte >= 'A' && char_byte <= 'Z') || (char_byte >= '0' && char_byte <= '9') || char_byte == '+' || char_byte == '-' || char_byte == '.'));
        if !is_scheme_char {
            invalid_scheme = true;
        }
    }

    if invalid_scheme && colon_idx > 0 {
        return out_url, UrlParseError.InvalidScheme;
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
        return parse_opaque_path_url(out_url, scheme_str[..], remainder);
    }

    // Slashes count after scheme:
    var slash_count = 0;
    while slash_count < remainder.len && (remainder[slash_count] == '/' || (is_spec && remainder[slash_count] == '\\')) {
        slash_count++;
    }

    // Special schemes or URLs with // authority
    if is_spec {
        if scheme_str == "file" {
            let auth_start = if slash_count >= 2 { 2 } else { 0 };
            return parse_absolute_authority_url(out_url, scheme_str[..], is_spec, remainder[auth_start..]);
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
            append_canonical_path_and_query(out_url, is_spec, remainder);
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

    var end_of_auth = auth_and_path.len;
    for scan_idx in auth_and_path.len {
        let char_byte = auth_and_path[scan_idx];
        if char_byte == '/' || (is_spec && char_byte == '\\') || char_byte == '?' || char_byte == '#' {
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
        append_userinfo_to_url(out_url, userinfo);
    }

    // Host & Port Parsing
    let host_err = apply_canonical_host_and_port(out_url, scheme_str, host_port_part);
    guard host_err == UrlParseError.None else {
        return out_url, host_err;
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
            if p_str.len > 0 {
                let p_num, p_ok = parse_int(p_str);
                guard p_ok && p_num >= 0 && p_num <= 65535 else {
                    return UrlParseError.InvalidPort;
                }
                port_out = p_num as i32;
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

    host_out.append(host_str);

    if colon_idx >= 0 {
        let p_str = host_port[colon_idx + 1..];
        if p_str.len > 0 {
            let p_num, p_ok = parse_int(p_str);
            guard p_ok && p_num >= 0 && p_num <= 65535 else {
                return UrlParseError.InvalidPort;
            }
            port_out = p_num as i32;
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

// RFC 5952 / WHATWG IPv6 Parser and Zero-Run Canonical Compression
fn parse_and_compress_ipv6<B>(raw_ipv6: const u8[:], out: B&) -> bool {
    out.clear();
    var pieces: u16[8] = [0, 0, 0, 0, 0, 0, 0, 0];
    var piece_count: i64 = 0;
    var double_colon_pos: i64 = -1;

    var rem_slice = raw_ipv6;
    if rem_slice.len > 0 && rem_slice[0] == ':' {
        guard starts_with(rem_slice, "::") else {
            return false; // Single leading ':' e.g. [:1:2:3:4:5:6:7] is invalid
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
            if double_colon_pos >= 0 { return false; } // Multiple '::'
            double_colon_pos = piece_count;
            rem_slice = rem_slice[1..];
            continue;
        }

        // Check for dotted-quad IPv4 suffix e.g. ::ffff:192.0.2.1
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

        // Hex piece (1 to 4 hex digits)
        if piece_str.len > 4 { return false; }
        var piece_val: u32 = 0;
        for char_byte in piece_str {
            let hex_digit = if char_byte >= '0' && char_byte <= '9' { char_byte - '0' }
                            else if char_byte >= 'a' && char_byte <= 'f' { char_byte - 'a' + 10 }
                            else if char_byte >= 'A' && char_byte <= 'F' { char_byte - 'A' + 10 }
                            else { return false; };
            piece_val = (piece_val << 4) | (hex_digit as u32);
        }
        pieces[piece_count] = piece_val as u16;
        piece_count++;

        if colon_idx >= 0 {
            if colon_idx + 1 < rem_slice.len && rem_slice[colon_idx + 1] == ':' {
                if double_colon_pos >= 0 { return false; }
                double_colon_pos = piece_count;
                rem_slice = rem_slice[colon_idx + 2..];
            } else {
                guard colon_idx + 1 < rem_slice.len else {
                    return false; // Trailing single ':' e.g. [fe80::1:] is invalid
                }
                rem_slice = rem_slice[colon_idx + 1..];
            }
        } else {
            rem_slice = rem_slice[rem_slice.len..];
        }
    }

    if rem_slice.len > 0 { return false; }

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

    let best_run_start, best_run_len = find_longest_zero_run(pieces);

    // Format canonical output string
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

fn collapse_path_directly(out_url: Url&, is_spec: bool, raw_path: const u8[:]) {
    let path_start_offset: i64 = out_url.href.len;
    guard raw_path.len > 0 else {
        if is_spec {
            out_url.href.push('/');
        }
        return;
    }

    let is_file = out_url.scheme_end == 4 && out_url.href.len >= 4 && out_url.href[..4] == "file";
    var seg_starts: i32[..64] = [];

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
            if is_dot_segment(seg) {
                last_was_dot = true;
            } else if is_double_dot_segment(seg) {
                last_was_dot = true;
                // Pop previous segment if allowed (protect Windows drive letter on file: URL)
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
                out_url.href.push('/');
                let cur_start = out_url.href.len as i32;
                out_url.href.append(seg);
                if seg_starts.len < 64 {
                    seg_starts.push(cur_start);
                }
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
            out_url.href.push('/');
        } else if out_url.href[out_url.href.len - 1] != '/' {
            out_url.href.push('/');
        }
    } else if out_url.href.len == path_start_offset && is_spec {
        out_url.href.push('/');
    }
}

fn append_canonical_path_and_query(out_url: Url&, is_spec: bool, path_and_beyond: const u8[:]) {
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
    collapse_path_directly(out_url, is_spec, raw_path);
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

    var combined_path: u8[..512] = [];

    if rel_input[0] == '/' || (is_spec && rel_input[0] == '\\') {
        // Root relative path
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

    append_canonical_path_and_query(out_url, is_spec, combined_path[..]);
    out_url.valid = true;
    return out_url, UrlParseError.None;
}
