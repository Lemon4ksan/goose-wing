// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// URL types, accessors, error codes and public factory functions.
namespace core;

import std;

// ---- url parse errors and enumerations --------------------------------------

enum UrlParseError {
    None,
    EmptyInput,
    InputTooLong,
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

let URL_SCHEME_DELIM_SET = byte_set(":/\\?#");
let URL_AUTH_SPECIAL_DELIM_SET = byte_set("/\\?#");
let URL_AUTH_GENERIC_DELIM_SET = byte_set("/?#");
let URL_QUERY_HASH_SET = byte_set("?#");
let URL_HASH_SET = byte_set("#");
let URL_COLON_SET = byte_set(":");
let URL_AT_SET = byte_set("@");
let URL_TAB_CRLF_SET = byte_set("\t\r\n");

fn make_forbidden_host_set() -> ByteSet {
    var members: bool[256] = [false; 256];
    for b in 33 { members[b] = true; }
    members[0x7F] = true;
    let forbidden_chars: const u8[:] = "#%/:<>?@[\\]^|";
    for c in forbidden_chars {
        members[c as i64] = true;
    }
    return byte_set(members);
}
let URL_FORBIDDEN_HOST_SET = make_forbidden_host_set();

// ---- canonical url model with single buffer & index offsets ----------------

// Url represents a canonical WHATWG URL with a single normalized contiguous buffer
// (href) and compact index offsets, eliminating substring heap allocations.
struct Url {
    href: u8[..2048] = [],
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

// UrlView represents a zero-copy, non-owning view of a URL of arbitrary length.
// It holds slices directly pointing into the original input without buffer capacity limits,
// making it suitable for streaming inspection and arbitrarily long URLs (e.g. data URIs or huge tokens).
struct UrlView {
    raw: const u8[:] = "",
    scheme: const u8[:] = "",
    username: const u8[:] = "",
    password: const u8[:] = "",
    host: const u8[:] = "",
    port: i32 = -1,
    pathname: const u8[:] = "",
    search: const u8[:] = "",
    hash: const u8[:] = "",
    is_special: bool = false,
    valid: bool = false,
}

fn href(view: const UrlView&) -> const u8[:] { return view.raw; }
fn scheme(view: const UrlView&) -> const u8[:] { return view.scheme; }
fn host(view: const UrlView&) -> const u8[:] { return view.host; }
fn hostname(view: const UrlView&) -> const u8[:] { return view.host; }
fn pathname(view: const UrlView&) -> const u8[:] { return view.pathname; }
fn search(view: const UrlView&) -> const u8[:] { return view.search; }
fn hash(view: const UrlView&) -> const u8[:] { return view.hash; }
fn port(view: const UrlView&) -> i32 { return view.port; }
fn is_valid(view: const UrlView&) -> bool { return view.valid; }

fn format_url(out: u8[>..]&, url_val: const Url&) {
    out.append(url_val.href[..]);
}

fn format_url_view(out: u8[>..]&, view: const UrlView&) {
    out.append(view.raw);
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

// Parses an absolute URL into a normalized Url. Schemes and hosts are
// lowercased, default ports are omitted, IPv6 literals use canonical
// compression (RFC 5952), and path dot-segments are normalized in place.
fn parse_url(raw_input: const u8[:]) -> Url, UrlParseError {
    let dummy_base = Url { valid: false, .. };
    return parse_url_internal(raw_input, dummy_base, false);
}

// parse_url_with_base parses raw_input relative to base_url according to WHATWG URL resolution.
//
// If raw_input is an absolute URL, base_url is ignored. If raw_input is relative and base_url.valid
// is false, returns UrlParseError.RelativeWithoutBase.
fn parse_url_with_base(raw_input: const u8[:], base_url: const Url&) -> Url, UrlParseError {
    return parse_url_internal(raw_input, base_url, base_url.valid);
}

// new_url parses raw_input into a Url, returning a Url with .valid == false if parsing fails.
// Convenience factory for parse_url where the caller inspects url.valid directly.
fn new_url(raw_input: const u8[:]) -> Url {
    let parsed_url, err = parse_url(raw_input);
    return parsed_url;
}

// new_url parses raw_input relative to base_url, returning a Url with .valid == false if parsing fails.
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
