// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP header parsing and storage (RFC 9110, RFC 9112).
// Stores names and values as offset slices into a contiguous buffer with
// dedicated lookup slots for frequent standard headers.
namespace wing;

import std;
import core from "..";
import .headers.lexical;
import .headers.perfect_hash;

// ---- header items & ascii helpers (RFC 9110 Section 5.6.3) ------------------

// Individual parsed or constructed HTTP header item.
struct HeaderItem {
    name:         u8[..64]  = [],
    value:        u8[..384] = [],
    is_sensitive: bool      = false,
}

// Zero-copy view into parsed wire HTTP header offsets.
struct HeaderSpan {
    name_pos: u16 = 0,
    name_len: u16 = 0,
    val_pos:  u16 = 0,
    val_len:  u16 = 0,
    id:       u8  = 0,
}

// Extracts zero-copy header name slice from backing buffer.
inline fn name_slice(s: HeaderSpan, raw: const u8[:]) -> const u8[:] {
    let start: i64 = s.name_pos;
    let end:   i64 = start + s.name_len;
    guard end <= raw.len else { return ""; }
    return raw[start..end];
}

// Extracts zero-copy header value slice from backing buffer.
inline fn val_slice(s: HeaderSpan, raw: const u8[:]) -> const u8[:] {
    let start: i64 = s.val_pos;
    let end:   i64 = start + s.val_len;
    guard end <= raw.len else { return ""; }
    return raw[start..end];
}

// Whether name is a credential or session header that should be stripped on
// cross-origin redirects or scheme downgrades.
fn is_heuristic_sensitive_header(name: const u8[:]) -> bool {
    return eq_ascii_fold(name, "authorization") ||
           eq_ascii_fold(name, "proxy-authorization") ||
           eq_ascii_fold(name, "cookie") ||
           eq_ascii_fold(name, "x-api-key") ||
           eq_ascii_fold(name, "x-auth-token") ||
           eq_ascii_fold(name, "x-access-token") ||
           eq_ascii_fold(name, "x-signature-256") ||
           eq_ascii_fold(name, "x-csrf-token") ||
           eq_ascii_fold(name, "x-xsrf-token") ||
           eq_ascii_fold(name, "www-authenticate") ||
           eq_ascii_fold(name, "proxy-authenticate") ||
           eq_ascii_fold(name, "x-amz-security-token");
}

// Appends src to out with CR, LF, and NUL bytes omitted, clamped to out.cap (RFC 9110 Section 5.5).
//
// Example:
//   src = "header\r\nvalue\0", out = []
//   out becomes "headervalue"
fn sanitize_header_bytes<B>(src: const u8[:], out: B&) {
    for b in src {
        if b != '\r' && b != '\n' && b != 0 {
            guard out.len < out.cap else { return; }
            out.push(b);
        }
    }
}

// CVE-2026-42507 & Go #79346: Escapes control characters (< 0x20 and >= 0x7F) in untrusted
// header and protocol tokens for safe diagnostic logging without CRLF injection.
//
// Example:
//   input = "foo\r\nbar\x01", out = []
//   out becomes "foo\\r\\nbar\\x01"
fn escape_diagnostic_control_chars<B>(input: const u8[:], out: B&) {
    for b in input {
        if b == '\r' {
            out.append("\\r");
        } else if b == '\n' {
            out.append("\\n");
        } else if b == '\t' {
            out.append("\\t");
        } else if b < 0x20 || b >= 0x7F {
            out.append("\\x");
            let hex_chars: const u8[:] = "0123456789ABCDEF";
            out.push(hex_chars[(b >> 4) & 0x0F]);
            out.push(hex_chars[b & 0x0F]);
        } else {
            out.push(b);
        }
    }
}

// A sanitized HeaderItem, detecting sensitive headers and stripping control bytes.
fn make_header(name: const u8[:], value: const u8[:], is_sensitive: bool = false) -> HeaderItem {
    let sens = is_sensitive || is_heuristic_sensitive_header(name);
    var header_item = HeaderItem { is_sensitive: sens, .. };
    sanitize_header_bytes(name, header_item.name);
    sanitize_header_bytes(value, header_item.value);
    return header_item;
}

// ---- 256-bit Header Bloom Filter (uWebSockets Fast-Path) -------------------

// 256-bit fast-rejection Bloom filter for HTTP headers (Alex Hultman / uWebSockets algorithm).
// Uses 4 distinct feature bytes from the header name and perfect hash multiplier 1843993368.
// Intrinsic case-insensitivity allows 3-cycle non-existence verification without string comparisons.
struct HeaderBloomFilter {
    bits: u64[4] = [0; 4],
}

fn clear(bf: HeaderBloomFilter&) {
    bf.bits[0] = 0;
    bf.bits[1] = 0;
    bf.bits[2] = 0;
    bf.bits[3] = 0;
}

inline fn is_empty(bf: const HeaderBloomFilter&) -> bool {
    return bf.bits[0] == 0 && bf.bits[1] == 0 && bf.bits[2] == 0 && bf.bits[3] == 0;
}

fn to_lower_ascii_byte(b: u8) -> u32 {
    if b >= 'A' && b <= 'Z' {
        return (b + 32);
    }
    return b;
}

fn bloom_hash(key: const u8[:]) -> u32 {
    let len = key.len;
    guard len >= 2 else { return 0; }
    let b0 = to_lower_ascii_byte(key[0]);
    let b1 = to_lower_ascii_byte(key[len - 1]);
    let b2 = to_lower_ascii_byte(key[len - 2]);
    let b3 = to_lower_ascii_byte(key[len >> 1]);
    let features: u32 = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    return features * 1843993368;
}

fn add_header(bf: HeaderBloomFilter&, key: const u8[:]) {
    guard key.len >= 2 else { return; }
    let h = bloom_hash(key);
    let p0 = (h & 0xFF) as i64;
    let p1 = ((h >> 8) & 0xFF) as i64;
    let p2 = ((h >> 16) & 0xFF) as i64;
    let p3 = ((h >> 24) & 0xFF) as i64;

    bf.bits[p0 >> 6] |= (1 as u64) << (p0 & 63);
    bf.bits[p1 >> 6] |= (1 as u64) << (p1 & 63);
    bf.bits[p2 >> 6] |= (1 as u64) << (p2 & 63);
    bf.bits[p3 >> 6] |= (1 as u64) << (p3 & 63);
}

fn might_have_header(bf: const HeaderBloomFilter&, key: const u8[:]) -> bool {
    guard key.len >= 2 else { return true; }
    let h = bloom_hash(key);
    let p0 = (h & 0xFF) as i64;
    let p1 = ((h >> 8) & 0xFF) as i64;
    let p2 = ((h >> 16) & 0xFF) as i64;
    let p3 = ((h >> 24) & 0xFF) as i64;

    let b0 = (bf.bits[p0 >> 6] & ((1 as u64) << (p0 & 63))) != 0;
    guard b0 else { return false; }
    let b1 = (bf.bits[p1 >> 6] & ((1 as u64) << (p1 & 63))) != 0;
    guard b1 else { return false; }
    let b2 = (bf.bits[p2 >> 6] & ((1 as u64) << (p2 & 63))) != 0;
    guard b2 else { return false; }
    let b3 = (bf.bits[p3 >> 6] & ((1 as u64) << (p3 & 63))) != 0;
    return b3;
}

// Case-insensitive lookup of a header value in a HeaderItem slice (RFC 9110 Section 5.6.3).
// Returns empty slice if not found.
fn find_header(headers: const HeaderItem[:], name: const u8[:]) -> const u8[:] {
    for &h in headers {
        if eq_ascii_fold(h.name[..], name) {
            return h.value[..];
        }
    }
    return "";
}

// Case-insensitive check for presence of a header in a HeaderItem slice.
fn has_header(headers: const HeaderItem[:], name: const u8[:]) -> bool {
    for &h in headers {
        if eq_ascii_fold(h.name[..], name) {
            return true;
        }
    }
    return false;
}

// Case-insensitive search for the index of a header in a HeaderItem slice.
// Returns 0-based index or -1 if not found.
fn find_header_index(headers: const HeaderItem[:], name: const u8[:]) -> i64 {
    for i in 0..headers.len {
        if eq_ascii_fold(headers[i].name[..], name) {
            return i;
        }
    }
    return -1;
}

// Sets or replaces a header in a bounded HeaderItem collection.
// Matches existing headers case-insensitively and updates value/sensitivity in-place.
fn set_header<H>(headers: H&, name: const u8[:], value: const u8[:], is_sensitive: bool = false) {
    let hdr = make_header(name, value, is_sensitive);
    for &h in headers {
        if eq_ascii_fold(h.name[..], hdr.name[..]) {
            h.value.clear();
            h.value.append(hdr.value[..]);
            h.is_sensitive = hdr.is_sensitive;
            return;
        }
    }
    guard headers.len < headers.cap else { return; }
    headers.push(hdr);
}

// Removes all occurrences of a header by name (case-insensitively) in-place.
// Returns true if at least one header was removed.
fn remove_header_by_name<H>(headers: H&, target_name: const u8[:]) -> bool {
    var write_idx = 0;
    for read_idx in headers.len {
        if !eq_ascii_fold(headers[read_idx].name[..], target_name) {
            if write_idx != read_idx {
                headers[write_idx] = copy(headers[read_idx]);
            }
            write_idx++;
        }
    }
    let removed = headers.len > write_idx;
    while headers.len > write_idx {
        headers.pop();
    }
    return removed;
}

// Purges credential and sensitive headers in-place (RFC 9110 Section 15.4).
fn remove_sensitive_headers<H>(headers: H&) {
    var write_idx = 0;
    for read_idx in headers.len {
        let is_sens = headers[read_idx].is_sensitive || is_heuristic_sensitive_header(headers[read_idx].name[..]);
        if !is_sens {
            if write_idx != read_idx {
                headers[write_idx] = copy(headers[read_idx]);
            }
            write_idx++;
        }
    }
    while headers.len > write_idx {
        headers.pop();
    }
}

// ---- header bitmask flags & persistence constants --------------------------

const HEADER_FLAG_NONE: u8 = 0;
// 0x01: Set-Cookie, WWW-Authenticate, Proxy-Authenticate (RFC 9110 Section 5.3 / RFC 6265bis)
const HEADER_FLAG_NO_COMMA_FOLD:  u8 = 1;
const HEADER_FLAG_SENSITIVE:      u8 = 2;   // 0x02: Authorization, Cookie, API Keys, etc.
const HEADER_FLAG_CONTINUATION:   u8 = 4;   // 0x04: Virtual continuation node (name_begin == name_end)
const HEADER_FLAG_CONTAINS_COMMA: u8 = 8;   // 0x08: Value contains comma (absl::InlinedVector<bool, 100> equivalent)
// 0x10: kCookieResponseHeaders (stripped on PERSIST_SANS_COOKIES & 304 merge)
const HEADER_FLAG_COOKIE_STATE: u8 = 16;
const HEADER_FLAG_CHALLENGE:    u8 = 32;    // 0x20: kChallengeResponseHeaders (stripped on PERSIST_SANS_CHALLENGES)
// 0x40: kSecurityStateHeaders (Strict-Transport-Security, x-content-*, x-webkit-*)
const HEADER_FLAG_SECURITY_STATE: u8 = 64;
// 0x80: Hop-by-hop / transient headers (connection, transfer-encoding, etc.)
const HEADER_FLAG_NON_CACHEABLE: u8 = 128;

const HEADER_INVALID_IDX: u8 = 0xFF;

// Storage source indicator for HeaderEntry.reserved
const HEADER_SRC_STACK: u8 = 0;
const HEADER_SRC_ARENA: u8 = 1;

// Storage root for oversized HTTP headers and URLs that exceed fixed stack limits.
// Allocated once per connection/session driver on the data stack.
root struct OverflowArena {
    spill_raw:     u8[>..]          = [],
    spill_entries: HeaderEntry[>..] = [],
    spill_url:     u8[>..]          = [],
}

var dummy_arena: OverflowArena = OverflowArena { .. };

fn reset_overflow_arena(arena: OverflowArena&) {
    arena.spill_raw.clear();
    arena.spill_entries.clear();
    arena.spill_url.clear();
}

// Parses an arbitrary-length URL using the arena's spill_url storage.
//
// Example:
//   raw_input = "https://example.com/long?token=...", arena = OverflowArena { .. }
//   returns: view.host = "example.com", view.valid = true, err = None
fn parse_url_with_overflow(raw_input: const u8[:], arena: OverflowArena&) -> core::UrlView, core::UrlParseError {
    arena.spill_url.clear();
    arena.spill_url.append(raw_input);
    return core::parse_url_view(arena.spill_url[..]);
}

// Cache Persistence Filter Flags (Chromium net/http/http_response_headers.h)
const PERSIST_ALL:                 u32 = 0;
const PERSIST_SANS_COOKIES:        u32 = 1;
const PERSIST_SANS_CHALLENGES:     u32 = 2;
const PERSIST_SANS_NON_CACHEABLE:  u32 = 4;
const PERSIST_SANS_SECURITY_STATE: u32 = 8;

// ---- header error enumeration ----------------------------------------------

enum HeaderParseError {
    None,
    EmptyInput,
    InvalidHeaderName,
    InvalidHeaderValue,
    EmbeddedNull,
    WhitespaceOnlyLine,
    ObsFoldForbidden,
    LeadingWhitespaceOnFirstHeader,
    CapacityExceeded,
    Incomplete,
    MalformedStatusLine,
    InvalidContentLength,
}

fn is_ok(err: HeaderParseError) -> bool {
    return err == HeaderParseError.None;
}

// CVE-2026-42507 defense: Sanitize untrusted user input before formatting into error strings or logs.
// Replaces control characters (< 0x20, CR, LF, DEL) and non-printable bytes with safe visual representation '?'.
//
// Example:
//   input = "bad\x00input\r\n", out = []
//   out becomes "bad?input??"
fn sanitize_untrusted_for_error<B>(input: const u8[:], out: B&) {
    out.clear();
    for b in input {
        if b >= 0x20 && b <= 0x7E && b != '\\' && b != '"' {
            out.push(b);
        } else {
            out.push('?');
        }
    }
}

// ---- well-known headers (64 static slots for O(1) envoy/qt dispatch) --------

enum WellKnownHeader {
    Host,                           // 0
    ContentType,                    // 1
    ContentLength,                  // 2
    ContentDisposition,             // 3
    ContentEncoding,                // 4
    ContentLanguage,                // 5
    ContentLocation,                // 6
    ContentRange,                   // 7
    Accept,                         // 8
    AcceptCharset,                  // 9
    AcceptEncoding,                 // 10
    AcceptLanguage,                 // 11
    AcceptRanges,                   // 12
    Authorization,                  // 13
    ProxyAuthorization,             // 14
    WwwAuthenticate,                // 15
    ProxyAuthenticate,              // 16
    Cookie,                         // 17
    SetCookie,                      // 18
    SetCookie2,                     // 19
    ClearSiteData,                  // 20
    CacheControl,                   // 21
    Age,                            // 22
    Expires,                        // 23
    Date,                           // 24
    ETag,                           // 25
    IfMatch,                        // 26
    IfNoneMatch,                    // 27
    IfModifiedSince,                // 28
    IfUnmodifiedSince,              // 29
    IfRange,                        // 30
    LastModified,                   // 31
    Location,                       // 32
    Range,                          // 33
    Vary,                           // 34
    Via,                            // 35
    Connection,                     // 36
    KeepAlive,                      // 37
    TransferEncoding,               // 38
    TE,                             // 39
    Trailer,                        // 40
    Upgrade,                        // 41
    UserAgent,                      // 42
    Server,                         // 43
    Referer,                        // 44
    OriginHeader,                   // 45
    StrictTransportSecurity,        // 46
    ContentSecurityPolicy,          // 47
    XContentTypeOptions,            // 48
    XFrameOptions,                  // 49
    XWebkitCsp,                     // 50
    AccessControlAllowOrigin,       // 51
    AccessControlAllowCredentials,  // 52
    AccessControlAllowHeaders,      // 53
    AccessControlAllowMethods,      // 54
    AccessControlExposeHeaders,     // 55
    AccessControlMaxAge,            // 56
    AccessControlRequestHeaders,    // 57
    AccessControlRequestMethod,     // 58
    AltSvc,                         // 59
    RetryAfter,                     // 60
    Priority,                       // 61
    Expect,                         // 62
    Unknown,                        // 63
}

fn well_known_header_name(id: WellKnownHeader) -> const u8[:] {
    return match id {
        Host => "host",
        ContentType => "content-type",
        ContentLength => "content-length",
        ContentDisposition => "content-disposition",
        ContentEncoding => "content-encoding",
        ContentLanguage => "content-language",
        ContentLocation => "content-location",
        ContentRange => "content-range",
        Accept => "accept",
        AcceptCharset => "accept-charset",
        AcceptEncoding => "accept-encoding",
        AcceptLanguage => "accept-language",
        AcceptRanges => "accept-ranges",
        Authorization => "authorization",
        ProxyAuthorization => "proxy-authorization",
        WwwAuthenticate => "www-authenticate",
        ProxyAuthenticate => "proxy-authenticate",
        Cookie => "cookie",
        SetCookie => "set-cookie",
        SetCookie2 => "set-cookie2",
        ClearSiteData => "clear-site-data",
        CacheControl => "cache-control",
        Age => "age",
        Expires => "expires",
        Date => "date",
        ETag => "etag",
        IfMatch => "if-match",
        IfNoneMatch => "if-none-match",
        IfModifiedSince => "if-modified-since",
        IfUnmodifiedSince => "if-unmodified-since",
        IfRange => "if-range",
        LastModified => "last-modified",
        Location => "location",
        Range => "range",
        Vary => "vary",
        Via => "via",
        Connection => "connection",
        KeepAlive => "keep-alive",
        TransferEncoding => "transfer-encoding",
        TE => "te",
        Trailer => "trailer",
        Upgrade => "upgrade",
        UserAgent => "user-agent",
        Server => "server",
        Referer => "referer",
        OriginHeader => "origin",
        StrictTransportSecurity => "strict-transport-security",
        ContentSecurityPolicy => "content-security-policy",
        XContentTypeOptions => "x-content-type-options",
        XFrameOptions => "x-frame-options",
        XWebkitCsp => "x-webkit-csp",
        AccessControlAllowOrigin => "access-control-allow-origin",
        AccessControlAllowCredentials => "access-control-allow-credentials",
        AccessControlAllowHeaders => "access-control-allow-headers",
        AccessControlAllowMethods => "access-control-allow-methods",
        AccessControlExposeHeaders => "access-control-expose-headers",
        AccessControlMaxAge => "access-control-max-age",
        AccessControlRequestHeaders => "access-control-request-headers",
        AccessControlRequestMethod => "access-control-request-method",
        AltSvc => "alt-svc",
        RetryAfter => "retry-after",
        Priority => "priority",
        Expect => "expect",
        _ => "",
    };
}

fn well_known_to_slot(id: WellKnownHeader) -> i64 {
    return match id {
        Host => 0,
        ContentType => 1,
        ContentLength => 2,
        ContentDisposition => 3,
        ContentEncoding => 4,
        ContentLanguage => 5,
        ContentLocation => 6,
        ContentRange => 7,
        Accept => 8,
        AcceptCharset => 9,
        AcceptEncoding => 10,
        AcceptLanguage => 11,
        AcceptRanges => 12,
        Authorization => 13,
        ProxyAuthorization => 14,
        WwwAuthenticate => 15,
        ProxyAuthenticate => 16,
        Cookie => 17,
        SetCookie => 18,
        SetCookie2 => 19,
        ClearSiteData => 20,
        CacheControl => 21,
        Age => 22,
        Expires => 23,
        Date => 24,
        ETag => 25,
        IfMatch => 26,
        IfNoneMatch => 27,
        IfModifiedSince => 28,
        IfUnmodifiedSince => 29,
        IfRange => 30,
        LastModified => 31,
        Location => 32,
        Range => 33,
        Vary => 34,
        Via => 35,
        Connection => 36,
        KeepAlive => 37,
        TransferEncoding => 38,
        TE => 39,
        Trailer => 40,
        Upgrade => 41,
        UserAgent => 42,
        Server => 43,
        Referer => 44,
        OriginHeader => 45,
        StrictTransportSecurity => 46,
        ContentSecurityPolicy => 47,
        XContentTypeOptions => 48,
        XFrameOptions => 49,
        XWebkitCsp => 50,
        AccessControlAllowOrigin => 51,
        AccessControlAllowCredentials => 52,
        AccessControlAllowHeaders => 53,
        AccessControlAllowMethods => 54,
        AccessControlExposeHeaders => 55,
        AccessControlMaxAge => 56,
        AccessControlRequestHeaders => 57,
        AccessControlRequestMethod => 58,
        AltSvc => 59,
        RetryAfter => 60,
        Priority => 61,
        Expect => 62,
        _ => 63,
    };
}

inline fn classify_cors_header(name: const u8[:], len: i64) -> WellKnownHeader {
    match len {
        22 => {
            if eq_ascii_fold(name, "access-control-max-age") {
                return WellKnownHeader.AccessControlMaxAge;
            }
        },
        27 => {
            if eq_ascii_fold(name, "access-control-allow-origin") { return WellKnownHeader.AccessControlAllowOrigin; }
            if eq_ascii_fold(name, "access-control-allow-headers") { return WellKnownHeader.AccessControlAllowHeaders; }
            if eq_ascii_fold(name, "access-control-allow-methods") { return WellKnownHeader.AccessControlAllowMethods; }
        },
        28 => {
            if eq_ascii_fold(name, "access-control-expose-headers") {
                return WellKnownHeader.AccessControlExposeHeaders;
            }
        },
        29 => {
            if eq_ascii_fold(name, "access-control-request-method") {
                return WellKnownHeader.AccessControlRequestMethod;
            }
        },
        30 => {
            if eq_ascii_fold(name, "access-control-request-headers") {
                return WellKnownHeader.AccessControlRequestHeaders;
            }
        },
        32 => {
            if eq_ascii_fold(name, "access-control-allow-credentials") {
                return WellKnownHeader.AccessControlAllowCredentials;
            }
        },
        _ => {},
    }
    return WellKnownHeader.Unknown;
}

fn classify_well_known_header(name: const u8[:]) -> WellKnownHeader {
    let len = name.len;
    guard len >= 2 && len <= 32 else { return WellKnownHeader.Unknown; }

    if starts_with_fold(name, "access-control-") {
        return classify_cors_header(name, len);
    }

    match len {
        2 => {
            let w = (core::read_le_u16(name, 0) | 0x2020) as u32;
            if w == 0x6574 { return WellKnownHeader.TE; }
        },
        3 => {
            let w = (name[0] as u32 | 0x20) | (((name[1] as u32 | 0x20)) << 8) | (((name[2] as u32 | 0x20)) << 16);
            if w == 0x656761 { return WellKnownHeader.Age; }
            if w == 0x616976 { return WellKnownHeader.Via; }
        },
        4 => {
            let w = core::read_le_u32(name, 0) | 0x20202020;
            if w == 0x74736f68 { return WellKnownHeader.Host; }
            if w == 0x65746164 { return WellKnownHeader.Date; }
            if w == 0x67617465 { return WellKnownHeader.ETag; }
            if w == 0x79726176 { return WellKnownHeader.Vary; }
        },
        5 => {
            if (core::read_le_u32(name, 0) | 0x20202020) == 0x676e6172 && ((name[4] as u32) | 0x20) == 0x65 {
                return WellKnownHeader.Range;
            }
        },
        6 => {
            let w32 = core::read_le_u32(name, 0) | 0x20202020;
            let w16 = (core::read_le_u16(name, 4) | 0x2020) as u32;
            if w32 == 0x65636361 && w16 == 0x7470 { return WellKnownHeader.Accept; }
            if w32 == 0x6b6f6f63 && w16 == 0x6569 { return WellKnownHeader.Cookie; }
            if w32 == 0x76726573 && w16 == 0x7265 { return WellKnownHeader.Server; }
            if w32 == 0x6769726f && w16 == 0x6e69 { return WellKnownHeader.OriginHeader; }
            if w32 == 0x65707865 && w16 == 0x7463 { return WellKnownHeader.Expect; }
        },
        7 => {
            let w32 = core::read_le_u32(name, 0) | 0x20202020;
            let w16 = (core::read_le_u16(name, 4) | 0x2020) as u32;
            let b6 = ((name[6] as u32) | 0x20);
            if w32 == 0x69707865 && w16 == 0x6572 && b6 == 0x73 { return WellKnownHeader.Expires; }
            if w32 == 0x65666572 && w16 == 0x6572 && b6 == 0x72 { return WellKnownHeader.Referer; }
            if w32 == 0x69617274 && w16 == 0x656c && b6 == 0x72 { return WellKnownHeader.Trailer; }
            if w32 == 0x72677075 && w16 == 0x6461 && b6 == 0x65 { return WellKnownHeader.Upgrade; }
            if w32 == 0x2d746c61 && w16 == 0x7673 && b6 == 0x63 { return WellKnownHeader.AltSvc; }
        },
        8 => {
            let w = core::read_le_u64(name, 0) | 0x2020202020202020;
            if w == 0x6e6f697461636f6c { return WellKnownHeader.Location; }
            if w == 0x686374616d2d6669 { return WellKnownHeader.IfMatch; }
            if w == 0x65676e61722d6669 { return WellKnownHeader.IfRange; }
            if w == 0x797469726f697270 { return WellKnownHeader.Priority; }
        },
        10 => {
            let w64 = core::read_le_u64(name, 0) | 0x2020202020202020;
            let w16 = (core::read_le_u16(name, 8) | 0x2020) as u32;
            if w64 == 0x697463656e6e6f63 && w16 == 0x6e6f { return WellKnownHeader.Connection; }
            if w64 == 0x696c612d7065656b && w16 == 0x6576 { return WellKnownHeader.KeepAlive; }
            if w64 == 0x6567612d72657375 && w16 == 0x746e { return WellKnownHeader.UserAgent; }
            if w64 == 0x6b6f6f632d746573 && w16 == 0x6569 { return WellKnownHeader.SetCookie; }
        },
        11 => {
            if eq_ascii_fold(name, "set-cookie2") { return WellKnownHeader.SetCookie2; }
            if eq_ascii_fold(name, "retry-after") { return WellKnownHeader.RetryAfter; }
        },
        12 => {
            let w64 = core::read_le_u64(name, 0) | 0x2020202020202020;
            let w32 = core::read_le_u32(name, 8) | 0x20202020;
            if w64 == 0x2d746e65746e6f63 && w32 == 0x65707974 { return WellKnownHeader.ContentType; }
            if eq_ascii_fold(name, "x-webkit-csp") { return WellKnownHeader.XWebkitCsp; }
        },
        13 => {
            let w64 = core::read_le_u64(name, 0) | 0x2020202020202020;
            let w32 = core::read_le_u32(name, 8) | 0x20202020;
            let b12 = ((name[12] as u32) | 0x20);
            if w64 == 0x6f632d6568636163 && w32 == 0x6f72746e && b12 == 0x6c { return WellKnownHeader.CacheControl; }
            if w64 == 0x7a69726f68747561 && w32 == 0x6f697461 && b12 == 0x6e { return WellKnownHeader.Authorization; }
            if w64 == 0x646f6d2d7473616c && w32 == 0x65696669 && b12 == 0x64 { return WellKnownHeader.LastModified; }
            if w64 == 0x2d656e6f6e2d6669 && w32 == 0x6374616d && b12 == 0x68 { return WellKnownHeader.IfNoneMatch; }
            if w64 == 0x722d747065636361 && w32 == 0x65676e61 && b12 == 0x73 { return WellKnownHeader.AcceptRanges; }
            if w64 == 0x2d746e65746e6f63 && w32 == 0x676e6172 && b12 == 0x65 { return WellKnownHeader.ContentRange; }
        },
        14 => {
            let w64 = core::read_le_u64(name, 0) | 0x2020202020202020;
            let w32 = core::read_le_u32(name, 8) | 0x20202020;
            let w16 = (core::read_le_u16(name, 12) | 0x2020) as u32;
            if w64 == 0x2d746e65746e6f63 && w32 == 0x676e656c && w16 == 0x6874 { return WellKnownHeader.ContentLength; }
            if eq_ascii_fold(name, "accept-charset") { return WellKnownHeader.AcceptCharset; }
        },
        15 => {
            if eq_ascii_fold(name, "accept-encoding") { return WellKnownHeader.AcceptEncoding; }
            if eq_ascii_fold(name, "accept-language") { return WellKnownHeader.AcceptLanguage; }
            if eq_ascii_fold(name, "clear-site-data") { return WellKnownHeader.ClearSiteData; }
            if eq_ascii_fold(name, "x-frame-options") { return WellKnownHeader.XFrameOptions; }
        },
        16 => {
            let w64_0 = core::read_le_u64(name, 0) | 0x2020202020202020;
            let w64_1 = core::read_le_u64(name, 8) | 0x2020202020202020;
            if w64_0 == 0x687475612d777777 && w64_1 == 0x6574616369746e65 { return WellKnownHeader.WwwAuthenticate; }
            if w64_0 == 0x2d746e65746e6f63 {
                if w64_1 == 0x676e69646f636e65 { return WellKnownHeader.ContentEncoding; }
                if w64_1 == 0x65676175676e616c { return WellKnownHeader.ContentLanguage; }
                if w64_1 == 0x6e6f697461636f6c { return WellKnownHeader.ContentLocation; }
            }
        },
        17 => {
            if eq_ascii_fold(name, "if-modified-since") { return WellKnownHeader.IfModifiedSince; }
            if eq_ascii_fold(name, "transfer-encoding") { return WellKnownHeader.TransferEncoding; }
        },
        18 => {
            if eq_ascii_fold(name, "proxy-authenticate") { return WellKnownHeader.ProxyAuthenticate; }
        },
        19 => {
            if eq_ascii_fold(name, "if-unmodified-since") { return WellKnownHeader.IfUnmodifiedSince; }
            if eq_ascii_fold(name, "proxy-authorization") { return WellKnownHeader.ProxyAuthorization; }
            if eq_ascii_fold(name, "content-disposition") { return WellKnownHeader.ContentDisposition; }
        },
        22 => {
            if eq_ascii_fold(name, "x-content-type-options") { return WellKnownHeader.XContentTypeOptions; }
        },
        23 => {
            if eq_ascii_fold(name, "content-security-policy") { return WellKnownHeader.ContentSecurityPolicy; }
        },
        25 => {
            if eq_ascii_fold(name, "strict-transport-security") { return WellKnownHeader.StrictTransportSecurity; }
        },
        _ => {},
    }
    return WellKnownHeader.Unknown;
}

fn well_known_header_flags(id: WellKnownHeader, name: const u8[:]) -> u8 {
    var flags: u8 = HEADER_FLAG_NONE;

    // Cookie & state exceptions
    if id == WellKnownHeader.SetCookie || id == WellKnownHeader.SetCookie2 || id == WellKnownHeader.ClearSiteData {
        flags |= HEADER_FLAG_NO_COMMA_FOLD | HEADER_FLAG_SENSITIVE | HEADER_FLAG_COOKIE_STATE;
        return flags;
    }

    // Authentication challenges
    if id == WellKnownHeader.WwwAuthenticate || id == WellKnownHeader.ProxyAuthenticate {
        flags |= HEADER_FLAG_NO_COMMA_FOLD | HEADER_FLAG_SENSITIVE | HEADER_FLAG_CHALLENGE;
        return flags;
    }

    // Credentials & auth tokens
    if id == WellKnownHeader.Authorization || id == WellKnownHeader.ProxyAuthorization || id == WellKnownHeader.Cookie {
        flags |= HEADER_FLAG_SENSITIVE;
    }

    // Security state & prefix matching (Strict-Transport-Security, x-content-*, x-webkit-*)
    let is_sec_id = id == WellKnownHeader.StrictTransportSecurity ||
        id == WellKnownHeader.XContentTypeOptions ||
        id == WellKnownHeader.XWebkitCsp;
    if is_sec_id {
        flags |= HEADER_FLAG_SECURITY_STATE;
    } else if name.len >= 10 && (starts_with_fold(name, "x-content-") || starts_with_fold(name, "x-webkit-")) {
        flags |= HEADER_FLAG_SECURITY_STATE;
    }

    // Hop-by-hop non-cacheables (RFC 9110 Section 7.6.1 + proxy-connection)
    if id == WellKnownHeader.Connection || id == WellKnownHeader.KeepAlive || id == WellKnownHeader.TransferEncoding ||
       id == WellKnownHeader.TE || id == WellKnownHeader.Trailer || id == WellKnownHeader.Upgrade ||
       id == WellKnownHeader.ProxyAuthorization || id == WellKnownHeader.ProxyAuthenticate {
        flags |= HEADER_FLAG_NON_CACHEABLE;
    } else if eq_ascii_fold(name, "proxy-connection") {
        flags |= HEADER_FLAG_NON_CACHEABLE;
    }

    return flags;
}

// ---- header entry (16 bytes aligned) ---------------------------------------

struct HeaderEntry {
    name_begin:    u16 = 0,
    name_end:      u16 = 0,
    values_begin:  u16 = 0,
    values_end:    u16 = 0,
    next_idx:      u8  = 0xFF,
    flags:         u8  = 0,
    well_known_id: u8  = 0xFF,
    reserved:      u8  = 0,
    name_hash:     u32 = 0,
}

fn is_continuation(entry: const HeaderEntry&) -> bool {
    return (entry.flags & HEADER_FLAG_CONTINUATION) != 0 || entry.name_begin == entry.name_end;
}

fn has_no_comma_fold(entry: const HeaderEntry&) -> bool {
    return (entry.flags & HEADER_FLAG_NO_COMMA_FOLD) != 0;
}

fn is_sensitive(entry: const HeaderEntry&) -> bool {
    return (entry.flags & HEADER_FLAG_SENSITIVE) != 0;
}

fn is_cookie_state(entry: const HeaderEntry&) -> bool {
    return (entry.flags & HEADER_FLAG_COOKIE_STATE) != 0;
}

fn is_challenge(entry: const HeaderEntry&) -> bool {
    return (entry.flags & HEADER_FLAG_CHALLENGE) != 0;
}

fn is_security_state(entry: const HeaderEntry&) -> bool {
    return (entry.flags & HEADER_FLAG_SECURITY_STATE) != 0;
}

fn is_non_cacheable(entry: const HeaderEntry&) -> bool {
    return (entry.flags & HEADER_FLAG_NON_CACHEABLE) != 0;
}

// ---- headermap data structure (two-phase zero-heap container) ---------------

struct HeaderMap {
    raw_buf:               u8[..8192]         = [],
    entries:               HeaderEntry[..128] = [],
    inline_slots:          u8[64]             = [0xFF; 64],
    header_contains_comma: bool[..128]        = [],
    status_code:           i32                = 200,
    http_major:            i32                = 1,
    http_minor:            i32                = 1,
    valid:                 bool               = true,
}

fn reset_for_keep_alive(map: HeaderMap&) {
    map.raw_buf.clear();
    map.entries.clear();
    map.header_contains_comma.clear();
    for i in 64 {
        map.inline_slots[i] = 0xFF;
    }
    map.status_code = 200;
    map.http_major = 1;
    map.http_minor = 1;
    map.valid = true;
}

// ---- wire parser -----------------------------------------------------------

fn link_header_entry(
    map:      HeaderMap&,
    wk_id:    WellKnownHeader,
    raw_name: const u8[:],
    hname:    u32,
    new_idx:  u8,
) {
    if wk_id != WellKnownHeader.Unknown {
        let slot = well_known_to_slot(wk_id);
        let existing = map.inline_slots[slot];
        if existing == 0xFF {
            map.inline_slots[slot] = new_idx;
            return;
        }

        var cur = existing;
        while map.entries[cur as i64].next_idx != 0xFF {
            cur = map.entries[cur as i64].next_idx;
        }

        map.entries[cur as i64].next_idx = new_idx;
        return;
    }

    for prev_i in map.entries.len {
        let pe = map.entries[prev_i];
        guard pe.name_hash == hname else { continue; }
        let prev_name = map.raw_buf[pe.name_begin..pe.name_end];
        guard eq_ascii_fold(prev_name, raw_name) else { continue; }

        var cur = prev_i as u8;
        while map.entries[cur as i64].next_idx != 0xFF {
            cur = map.entries[cur as i64].next_idx;
        }
        map.entries[cur as i64].next_idx = new_idx;
        break;
    }
}

struct ObsFoldPolicy {
    is_first_header: bool = false,
    allow_obs_fold:  bool = false,
}

fn validate_folded_framing(buf: const u8[:], begin: u16, end: u16, wk: u8) -> bool {
    let cl_slot = well_known_to_slot(WellKnownHeader.ContentLength) as u8;
    let te_slot = well_known_to_slot(WellKnownHeader.TransferEncoding) as u8;
    if wk == cl_slot {
        let full_cl = buf[begin..end];
        var dummy_cl: i64 = 0;
        return validate_content_length_value(full_cl, dummy_cl);
    }
    if wk == te_slot {
        let full_te = buf[begin..end];
        return validate_transfer_encoding_value(full_te);
    }
    return true;
}

fn handle_obs_fold_arena(
    trimmed_continuation: const u8[:],
    map:                  HeaderMap&,
    arena:                OverflowArena&,
    in_spill:             bool,
) -> HeaderParseError {
    let orig_begin: u16 = if in_spill {
        arena.spill_entries[arena.spill_entries.len - 1].values_begin
    } else {
        map.entries[map.entries.len - 1].values_begin
    };
    let orig_end: u16 = if in_spill {
        arena.spill_entries[arena.spill_entries.len - 1].values_end
    } else {
        map.entries[map.entries.len - 1].values_end
    };
    let orig_val = arena.spill_raw[orig_begin..orig_end];
    let needed = orig_val.len + 1 + trimmed_continuation.len;
    guard (arena.spill_raw.len + needed) <= 65535 else {
        map.valid = false;
        return HeaderParseError.CapacityExceeded;
    }

    let new_begin = arena.spill_raw.len as u16;
    arena.spill_raw.append(orig_val);
    arena.spill_raw.push(' ');
    arena.spill_raw.append(trimmed_continuation);
    let new_end = arena.spill_raw.len as u16;

    let prev_wk: u8 = if in_spill {
        arena.spill_entries[arena.spill_entries.len - 1].values_begin = new_begin;
        arena.spill_entries[arena.spill_entries.len - 1].values_end = new_end;
        arena.spill_entries[arena.spill_entries.len - 1].well_known_id
    } else {
        map.entries[map.entries.len - 1].values_begin = new_begin;
        map.entries[map.entries.len - 1].values_end = new_end;
        map.entries[map.entries.len - 1].well_known_id
    };

    guard validate_folded_framing(arena.spill_raw[..], new_begin, new_end, prev_wk) else {
        map.valid = false;
        return HeaderParseError.InvalidContentLength;
    }
    return HeaderParseError.None;
}

fn handle_obs_fold_stack(
    trimmed_continuation: const u8[:],
    map:                  HeaderMap&,
) -> HeaderParseError {
    let prev_idx = map.entries.len - 1;
    let orig_begin = map.entries[prev_idx].values_begin;
    let orig_end = map.entries[prev_idx].values_end;
    let orig_val = map.raw_buf[orig_begin..orig_end];

    let needed = orig_val.len + 1 + trimmed_continuation.len;
    guard (map.raw_buf.len + needed) <= map.raw_buf.cap else {
        map.valid = false;
        return HeaderParseError.CapacityExceeded;
    }

    let new_begin = map.raw_buf.len as u16;
    map.raw_buf.append(orig_val);
    map.raw_buf.push(' ');
    map.raw_buf.append(trimmed_continuation);
    let new_end = map.raw_buf.len as u16;

    map.entries[prev_idx].values_begin = new_begin;
    map.entries[prev_idx].values_end = new_end;

    let prev_wk = map.entries[prev_idx].well_known_id;
    guard validate_folded_framing(map.raw_buf[..], new_begin, new_end, prev_wk) else {
        map.valid = false;
        return HeaderParseError.InvalidContentLength;
    }
    return HeaderParseError.None;
}

fn handle_obs_fold(
    line:   const u8[:],
    policy: ObsFoldPolicy,
    map:    HeaderMap&,
    arena:  OverflowArena& = dummy_arena,
) -> HeaderParseError {
    let total_entries = map.entries.len + arena.spill_entries.len;
    if policy.is_first_header || total_entries == 0 {
        map.valid = false;
        return HeaderParseError.LeadingWhitespaceOnFirstHeader;
    }
    guard policy.allow_obs_fold else {
        map.valid = false;
        return HeaderParseError.ObsFoldForbidden;
    }

    let trimmed_continuation = trim_lws(line);
    guard is_valid_header_value(trimmed_continuation) else {
        map.valid = false;
        return HeaderParseError.InvalidHeaderValue;
    }

    let in_spill = arena.spill_entries.len > 0;
    let prev_in_arena = in_spill
        || (map.entries.len > 0 && map.entries[map.entries.len - 1].reserved == HEADER_SRC_ARENA);

    if prev_in_arena {
        return handle_obs_fold_arena(trimmed_continuation, map, arena, in_spill);
    }
    return handle_obs_fold_stack(trimmed_continuation, map);
}

fn validate_header_framing_conflicts(
    map:         HeaderMap&,
    wk_id:       WellKnownHeader,
    val_trimmed: const u8[:],
    is_dup_cl:   bool&,
) -> HeaderParseError {
    is_dup_cl = false;
    if wk_id == WellKnownHeader.ContentLength {
        if has_header(map, "transfer-encoding") {
            map.valid = false;
            return HeaderParseError.InvalidContentLength;
        }
        var parsed_cl: i64 = 0;
        guard validate_content_length_value(val_trimmed, parsed_cl) else {
            map.valid = false;
            return HeaderParseError.InvalidContentLength;
        }
        if has_header(map, "content-length") {
            let existing_str = get_header(map, "content-length");
            var existing_cl: i64 = 0;
            guard validate_content_length_value(existing_str, existing_cl) else {
                map.valid = false;
                return HeaderParseError.InvalidContentLength;
            }
            if parsed_cl != existing_cl {
                map.valid = false;
                return HeaderParseError.InvalidContentLength;
            }
            is_dup_cl = true;
            return HeaderParseError.None;
        }
    } else if wk_id == WellKnownHeader.TransferEncoding {
        if has_header(map, "content-length") || has_header(map, "transfer-encoding") {
            map.valid = false;
            return HeaderParseError.InvalidContentLength;
        }
        guard validate_transfer_encoding_value(val_trimmed) else {
            map.valid = false;
            return HeaderParseError.InvalidContentLength;
        }
    } else if wk_id == WellKnownHeader.Host {
        // RFC 9112 Section 7.2: Duplicate Host header is forbidden (request smuggling protection)
        if has_header(map, "host") {
            map.valid = false;
            return HeaderParseError.InvalidHeaderName;
        }
        // RFC 9112 Section 7.2, RFC 3986 Section 3.2.2 & uWS #1949:
        // Host MUST NOT contain path ('/'), query ('?'), fragment ('#'), userinfo ('@'),
        // whitespace, DEL (0x7F), or comma (',')
        for b in val_trimmed {
            if b <= 0x20 || b == 0x7F || b == '/' || b == '?' || b == '#' || b == '@' || b == ',' {
                map.valid = false;
                return HeaderParseError.InvalidHeaderValue;
            }
        }
    }
    return HeaderParseError.None;
}

inline fn slice_contains_comma(s: const u8[:]) -> bool {
    for b in s {
        if b == ',' { return true; }
    }
    return false;
}

// Parses a single wire header line (name: value) into HeaderMap.
//
// Example:
//   line = "Host: example.com", cursor = 0, map = HeaderMap { .. }, is_dup_cl = false
//   returns: HeaderParseError.None
fn parse_single_header_line(
    line:      const u8[:],
    cursor:    i64,
    map:       HeaderMap&,
    is_dup_cl: bool&,
) -> HeaderParseError {
    let colon_pos = find_any(line, COLON_SET);
    guard colon_pos > 0 else {
        map.valid = false;
        return HeaderParseError.InvalidHeaderName;
    }

    let raw_name = line[..colon_pos];
    if raw_name.len > 0 && (raw_name[raw_name.len - 1] == ' ' || raw_name[raw_name.len - 1] == '\t') {
        map.valid = false;
        return HeaderParseError.InvalidHeaderName;
    }
    guard is_valid_header_name(raw_name) else {
        map.valid = false;
        return HeaderParseError.InvalidHeaderName;
    }

    let raw_val = line[colon_pos + 1..];
    let val_trimmed = trim_lws(raw_val);
    guard is_valid_header_value(val_trimmed) else {
        map.valid = false;
        return HeaderParseError.InvalidHeaderValue;
    }
    guard map.entries.len < 128 else {
        map.valid = false;
        return HeaderParseError.CapacityExceeded;
    }

    let wk_id = classify_well_known_header(raw_name);
    let conflict_err = validate_header_framing_conflicts(map, wk_id, val_trimmed, is_dup_cl);
    guard is_ok(conflict_err) else { return conflict_err; }

    guard !is_dup_cl else { return HeaderParseError.None; }

    let name_begin_off = cursor as u16;
    let name_end_off = (cursor + colon_pos) as u16;

    let lws_lead = raw_val.len - trim_lws_start(raw_val).len;
    let val_start_off = (cursor + colon_pos + 1 + lws_lead) as u16;
    let val_end_off = (val_start_off + val_trimmed.len) as u16;

    let flags = well_known_header_flags(wk_id, raw_name);
    let hname = hash_header_name(raw_name);

    let contains_comma = slice_contains_comma(val_trimmed);
    let entry_flags = if contains_comma { flags | HEADER_FLAG_CONTAINS_COMMA } else { flags };

    let new_entry = HeaderEntry {
        name_begin:    name_begin_off,
        name_end:      name_end_off,
        values_begin:  val_start_off,
        values_end:    val_end_off,
        next_idx:      0xFF,
        flags:         entry_flags,
        well_known_id: if wk_id != WellKnownHeader.Unknown { well_known_to_slot(wk_id) as u8 } else { 0xFF },
        reserved:      0,
        name_hash:     hname,
    };

    let new_idx = map.entries.len as u8;
    link_header_entry(map, wk_id, raw_name, hname, new_idx);
    map.entries.push(new_entry);
    map.header_contains_comma.push(contains_comma);
    return HeaderParseError.None;
}

// Parses a single wire header line into HeaderMap or OverflowArena.
//
// Example:
//   line = "Host: example.com", cursor = 0, src_type = HEADER_SRC_STACK
//   returns: HeaderParseError.None
fn parse_single_overflow_header_line(
    line:      const u8[:],
    cursor:    i64,
    map:       HeaderMap&,
    arena:     OverflowArena&,
    src_type:  u8,
    is_dup_cl: i32&,
) -> HeaderParseError {
    is_dup_cl = 0;
    let colon_pos = find_any(line, COLON_SET);
    guard colon_pos > 0 else {
        map.valid = false;
        return HeaderParseError.InvalidHeaderName;
    }

    let raw_name = line[..colon_pos];
    if raw_name.len > 0 && (raw_name[raw_name.len - 1] == ' ' || raw_name[raw_name.len - 1] == '\t') {
        map.valid = false;
        return HeaderParseError.InvalidHeaderName;
    }
    guard is_valid_header_name(raw_name) else {
        map.valid = false;
        return HeaderParseError.InvalidHeaderName;
    }

    let raw_val = line[colon_pos + 1..];
    let val_trimmed = trim_lws(raw_val);
    guard is_valid_header_value(val_trimmed) else {
        map.valid = false;
        return HeaderParseError.InvalidHeaderValue;
    }

    let wk_id = classify_well_known_header(raw_name);
    var dup_cl_bool = false;
    let conflict_err = validate_header_framing_conflicts(map, wk_id, val_trimmed, dup_cl_bool);
    guard is_ok(conflict_err) else { return conflict_err; }

    if dup_cl_bool {
        is_dup_cl = 1;
        return HeaderParseError.None;
    }

    let name_begin_off = cursor as u16;
    let name_end_off = (cursor + colon_pos) as u16;

    let lws_lead = raw_val.len - trim_lws_start(raw_val).len;
    let val_start_off = (cursor + colon_pos + 1 + lws_lead) as u16;
    let val_end_off = (val_start_off + val_trimmed.len) as u16;

    let flags = well_known_header_flags(wk_id, raw_name);
    let hname = hash_header_name(raw_name);

    let contains_comma = slice_contains_comma(val_trimmed);
    let entry_flags = if contains_comma { flags | HEADER_FLAG_CONTAINS_COMMA } else { flags };

    let new_entry = HeaderEntry {
        name_begin:    name_begin_off,
        name_end:      name_end_off,
        values_begin:  val_start_off,
        values_end:    val_end_off,
        next_idx:      0xFF,
        flags:         entry_flags,
        well_known_id: if wk_id != WellKnownHeader.Unknown { well_known_to_slot(wk_id) as u8 } else { 0xFF },
        reserved:      src_type,
        name_hash:     hname,
    };

    if map.entries.len < 128 {
        let new_idx = map.entries.len as u8;
        link_header_entry(map, wk_id, raw_name, hname, new_idx);
        map.entries.push(new_entry);
        map.header_contains_comma.push(contains_comma);
    } else {
        arena.spill_entries.push(new_entry);
    }
    return HeaderParseError.None;
}

// Parses an HTTP/1.x header block into map (RFC 9112 Section 5.2).
// Header names and values are indexed as offsets into the map's buffer.
// Obsolete line folding (obs-fold) is rejected unless allow_obs_fold is set.
//
// Example:
//   raw_input = "Host: example.com\r\nContent-Length: 0\r\n\r\n", map = HeaderMap { .. }
//   returns: HeaderParseError.None, populates map.entries
fn parse_headers(raw_input: const u8[:], map: HeaderMap&, allow_obs_fold: bool = false) -> HeaderParseError {
    guard raw_input.len > 0 else { return HeaderParseError.EmptyInput; }
    if has_embedded_nulls(raw_input) {
        map.valid = false;
        return HeaderParseError.EmbeddedNull;
    }

    reset_for_keep_alive(map);
    guard raw_input.len <= 8192 else {
        map.valid = false;
        return HeaderParseError.CapacityExceeded;
    }
    map.raw_buf.append(raw_input);

    var cursor: i64 = 0;
    let buf_len = map.raw_buf.len;
    var is_first_header = true;
    var prev_was_dup_cl = false;

    while cursor < buf_len {
        if map.raw_buf[cursor] == '\r' {
            if cursor + 1 < buf_len && map.raw_buf[cursor + 1] == '\n' {
                cursor += 2;
                break;
            }
            map.valid = false;
            return HeaderParseError.InvalidHeaderValue;
        }
        if map.raw_buf[cursor] == '\n' {
            cursor += 1;
            break;
        }

        let rel_end = find_any(map.raw_buf[cursor..], CRLF_SET);
        let line_end = if rel_end >= 0 { cursor + rel_end } else { buf_len };
        let line = map.raw_buf[cursor..line_end];

        if is_line_whitespace_only(line) {
            map.valid = false;
            return HeaderParseError.WhitespaceOnlyLine;
        }

        let is_lead_ws = map.raw_buf[cursor] == ' ' || map.raw_buf[cursor] == '\t';
        if is_lead_ws {
            if prev_was_dup_cl {
                map.valid = false;
                return HeaderParseError.ObsFoldForbidden;
            }
            let policy = ObsFoldPolicy { is_first_header: is_first_header, allow_obs_fold: allow_obs_fold };
            let fold_err = handle_obs_fold(line, policy, map);
            guard is_ok(fold_err) else { return fold_err; }
        } else {
            var is_dup_cl = false;
            let line_err = parse_single_header_line(line, cursor, map, is_dup_cl);
            guard is_ok(line_err) else { return line_err; }
            if is_dup_cl {
                prev_was_dup_cl = true;
            } else {
                prev_was_dup_cl = false;
                is_first_header = false;
            }
        }

        guard advance_crlf(map.raw_buf[..], cursor, line_end) else {
            map.valid = false;
            return HeaderParseError.InvalidHeaderValue;
        }
    }

    map.valid = true;
    return HeaderParseError.None;
}

// Iterates and parses headers from active_buf into map or arena.
//
// Example:
//   active_buf = "Host: api\r\n\r\n", src_type = HEADER_SRC_STACK
//   returns: HeaderParseError.None
fn parse_overflow_headers_loop(
    active_buf:     const u8[:],
    src_type:       u8,
    map:            HeaderMap&,
    arena:          OverflowArena&,
    allow_obs_fold: bool,
) -> HeaderParseError {
    var cursor: i64 = 0;
    let buf_len = active_buf.len;
    var is_first_header = true;
    var prev_was_dup_cl = false;

    while cursor < buf_len {
        if active_buf[cursor] == '\r' {
            if cursor + 1 < buf_len && active_buf[cursor + 1] == '\n' {
                cursor += 2;
                break;
            }
            map.valid = false;
            return HeaderParseError.InvalidHeaderValue;
        }
        if active_buf[cursor] == '\n' {
            cursor += 1;
            break;
        }

        let rel_end = find_any(active_buf[cursor..], CRLF_SET);
        let line_end = if rel_end >= 0 { cursor + rel_end } else { buf_len };
        let line = active_buf[cursor..line_end];

        if is_line_whitespace_only(line) {
            map.valid = false;
            return HeaderParseError.WhitespaceOnlyLine;
        }

        let is_lead_ws = active_buf[cursor] == ' ' || active_buf[cursor] == '\t';
        if is_lead_ws {
            if prev_was_dup_cl {
                map.valid = false;
                return HeaderParseError.ObsFoldForbidden;
            }
            let policy = ObsFoldPolicy { is_first_header: is_first_header, allow_obs_fold: allow_obs_fold };
            let fold_err = handle_obs_fold(line, policy, map, arena);
            guard is_ok(fold_err) else { return fold_err; }
        } else {
            var is_dup_cl: i32 = 0;
            let line_err = parse_single_overflow_header_line(line, cursor, map, arena, src_type, is_dup_cl);
            guard is_ok(line_err) else { return line_err; }
            if is_dup_cl != 0 {
                prev_was_dup_cl = true;
            } else {
                prev_was_dup_cl = false;
                is_first_header = false;
            }
        }

        guard advance_crlf(active_buf, cursor, line_end) else {
            map.valid = false;
            return HeaderParseError.InvalidHeaderValue;
        }
    }

    map.valid = true;
    return HeaderParseError.None;
}

// Parses an HTTP/1.x header block into map, spilling into arena if headers exceed 8192 B or 128 entries.
//
// Example:
//   raw_input = "Host: api\r\nAuthorization: Bearer <jwt...>\r\n\r\n"
//   returns: HeaderParseError.None, headers stored in map (or arena if oversized)
fn parse_headers_with_overflow(
    raw_input:      const u8[:],
    map:            HeaderMap&,
    arena:          OverflowArena&,
    allow_obs_fold: bool = false,
) -> HeaderParseError {
    guard raw_input.len > 0 else { return HeaderParseError.EmptyInput; }
    guard raw_input.len <= 65535 else {
        map.valid = false;
        return HeaderParseError.CapacityExceeded;
    }
    if has_embedded_nulls(raw_input) {
        map.valid = false;
        return HeaderParseError.EmbeddedNull;
    }

    reset_for_keep_alive(map);
    reset_overflow_arena(arena);

    let use_arena_buf = raw_input.len > 8192;
    if use_arena_buf {
        arena.spill_raw.append(raw_input);
    } else {
        map.raw_buf.append(raw_input);
    }

    let src_type:   u8          = if use_arena_buf { HEADER_SRC_ARENA } else { HEADER_SRC_STACK };
    let active_buf: const u8[:] = if use_arena_buf { arena.spill_raw[..] } else { map.raw_buf[..] };
    return parse_overflow_headers_loop(active_buf, src_type, map, arena, allow_obs_fold);
}

// Parses an HTTP status line into major/minor versions and status code.
//
// Example:
//   status_line = "HTTP/1.1 200 OK"
//   returns: HeaderParseError.None, major = 1, minor = 1, code = 200
fn parse_http_status_line(
    status_line: const u8[:],
    major:       i32&,
    minor:       i32&,
    code:        i32&,
) -> HeaderParseError {
    guard status_line.len >= 12 else {
        return HeaderParseError.MalformedStatusLine;
    }

    guard eq_ascii_fold(status_line[..5], "HTTP/") else {
        return HeaderParseError.MalformedStatusLine;
    }

    let maj = status_line[5] - '0';
    let dot = status_line[6];
    let min = status_line[7] - '0';
    guard dot == '.' && maj >= 0 && maj <= 9 && min >= 0 && min <= 9 else {
        return HeaderParseError.MalformedStatusLine;
    }

    var sp_idx: i64 = 8;
    while sp_idx < status_line.len && status_line[sp_idx] == ' ' { sp_idx++; }
    guard sp_idx + 3 <= status_line.len else {
        return HeaderParseError.MalformedStatusLine;
    }

    let c0 = status_line[sp_idx] - '0';
    let c1 = status_line[sp_idx + 1] - '0';
    let c2 = status_line[sp_idx + 2] - '0';
    guard c0 >= 0 && c0 <= 9 && c1 >= 0 && c1 <= 9 && c2 >= 0 && c2 <= 9 else {
        return HeaderParseError.MalformedStatusLine;
    }

    major = maj;
    minor = min;
    code = c0 * 100 + c1 * 10 + c2;
    return HeaderParseError.None;
}

// Parses full HTTP/1.1 response status line and header block
//
// Example:
//   raw_input = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", map = HeaderMap { .. }
//   returns: HeaderParseError.None, map.status_code = 200
fn parse_response_headers(raw_input: const u8[:], map: HeaderMap&, allow_obs_fold: bool = false) -> HeaderParseError {
    guard raw_input.len > 0 else { return HeaderParseError.EmptyInput; }
    if has_embedded_nulls(raw_input) {
        map.valid = false;
        return HeaderParseError.EmbeddedNull;
    }

    // Status line: HTTP/1.x 200 OK
    var line_end: i64 = 0;
    while line_end < raw_input.len && raw_input[line_end] != '\r' && raw_input[line_end] != '\n' {
        line_end++;
    }

    var major: i32 = 0;
    var minor: i32 = 0;
    var code:  i32 = 0;
    let st_err = parse_http_status_line(raw_input[..line_end], major, minor, code);
    guard is_ok(st_err) else {
        map.valid = false;
        return st_err;
    }

    var header_start = line_end;
    if header_start < raw_input.len && raw_input[header_start] == '\r' {
        guard header_start + 1 < raw_input.len && raw_input[header_start + 1] == '\n' else {
            map.valid = false;
            return HeaderParseError.MalformedStatusLine;
        }
        header_start += 2;
    } else if header_start < raw_input.len && raw_input[header_start] == '\n' {
        header_start++;
    }

    let err = parse_headers(raw_input[header_start..], map, allow_obs_fold);
    map.status_code = code;
    map.http_major = major;
    map.http_minor = minor;
    return err;
}

// Parses full HTTP/1.1 response status line and header block with overflow spill fallback.
//
// Example:
//   raw_input = "HTTP/1.1 200 OK\r\nContent-Type: text/html\r\n\r\n"
//   returns: HeaderParseError.None, map.status_code = 200
fn parse_response_headers_with_overflow(
    raw_input:      const u8[:],
    map:            HeaderMap&,
    arena:          OverflowArena&,
    allow_obs_fold: bool = false,
) -> HeaderParseError {
    guard raw_input.len > 0 else { return HeaderParseError.EmptyInput; }
    if has_embedded_nulls(raw_input) {
        map.valid = false;
        return HeaderParseError.EmbeddedNull;
    }

    var line_end: i64 = 0;
    while line_end < raw_input.len && raw_input[line_end] != '\r' && raw_input[line_end] != '\n' {
        line_end++;
    }

    var major: i32 = 0;
    var minor: i32 = 0;
    var code:  i32 = 0;
    let st_err = parse_http_status_line(raw_input[..line_end], major, minor, code);
    guard is_ok(st_err) else {
        map.valid = false;
        return st_err;
    }

    var header_start = line_end;
    if header_start < raw_input.len && raw_input[header_start] == '\r' {
        guard header_start + 1 < raw_input.len && raw_input[header_start + 1] == '\n' else {
            map.valid = false;
            return HeaderParseError.MalformedStatusLine;
        }
        header_start += 2;
    } else if header_start < raw_input.len && raw_input[header_start] == '\n' {
        header_start++;
    }

    let err = parse_headers_with_overflow(raw_input[header_start..], map, arena, allow_obs_fold);
    map.status_code = code;
    map.http_major = major;
    map.http_minor = minor;
    return err;
}

// Parses full HTTP/1.1 request line (METHOD /path HTTP/1.1) and header block
//
// Example:
//   raw_input = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n", map = HeaderMap { .. }
//   returns: HeaderParseError.None, populates map.entries
fn parse_request_headers(raw_input: const u8[:], map: HeaderMap&, allow_obs_fold: bool = false) -> HeaderParseError {
    guard raw_input.len > 0 else { return HeaderParseError.EmptyInput; }
    if has_embedded_nulls(raw_input) {
        map.valid = false;
        return HeaderParseError.EmbeddedNull;
    }

    var line_end: i64 = 0;
    while line_end < raw_input.len && raw_input[line_end] != '\r' && raw_input[line_end] != '\n' {
        line_end++;
    }

    var header_start = line_end;
    if header_start < raw_input.len && raw_input[header_start] == '\r' {
        guard header_start + 1 < raw_input.len && raw_input[header_start + 1] == '\n' else {
            map.valid = false;
            return HeaderParseError.MalformedStatusLine;
        }
        header_start += 2;
    } else if header_start < raw_input.len && raw_input[header_start] == '\n' {
        header_start++;
    }

    return parse_headers(raw_input[header_start..], map, allow_obs_fold);
}

// Parses full HTTP/1.1 request line and header block with overflow spill fallback.
//
// Example:
//   raw_input = "GET / HTTP/1.1\r\nHost: example.com\r\n\r\n"
//   returns: HeaderParseError.None
fn parse_request_headers_with_overflow(
    raw_input:      const u8[:],
    map:            HeaderMap&,
    arena:          OverflowArena&,
    allow_obs_fold: bool = false,
) -> HeaderParseError {
    guard raw_input.len > 0 else { return HeaderParseError.EmptyInput; }
    if has_embedded_nulls(raw_input) {
        map.valid = false;
        return HeaderParseError.EmbeddedNull;
    }

    var line_end: i64 = 0;
    while line_end < raw_input.len && raw_input[line_end] != '\r' && raw_input[line_end] != '\n' {
        line_end++;
    }

    var header_start = line_end;
    if header_start < raw_input.len && raw_input[header_start] == '\r' {
        guard header_start + 1 < raw_input.len && raw_input[header_start + 1] == '\n' else {
            map.valid = false;
            return HeaderParseError.MalformedStatusLine;
        }
        header_start += 2;
    } else if header_start < raw_input.len && raw_input[header_start] == '\n' {
        header_start++;
    }

    return parse_headers_with_overflow(raw_input[header_start..], map, arena, allow_obs_fold);
}

// ---- headermap accessors & mutations ---------------------------------------

fn has_header(map: const HeaderMap&, name: const u8[:]) -> bool {
    let wk_id = classify_well_known_header(name);
    if wk_id != WellKnownHeader.Unknown {
        let slot = well_known_to_slot(wk_id);
        return map.inline_slots[slot] != 0xFF;
    }
    let hname = hash_header_name(name);
    for &entry in map.entries {
        if entry.name_hash == hname {
            let entry_name = map.raw_buf[entry.name_begin..entry.name_end];
            if eq_ascii_fold(entry_name, name) {
                return true;
            }
        }
    }
    return false;
}

fn get_header(map: const HeaderMap&, name: const u8[:]) -> const u8[:] {
    let wk_id = classify_well_known_header(name);
    if wk_id != WellKnownHeader.Unknown {
        let slot = well_known_to_slot(wk_id);
        let idx = map.inline_slots[slot];
        if idx != 0xFF {
            let entry = map.entries[idx as i64];
            return map.raw_buf[entry.values_begin..entry.values_end];
        }
        return "";
    }

    let hname = hash_header_name(name);
    for &entry in map.entries {
        if entry.name_hash == hname {
            let entry_name = map.raw_buf[entry.name_begin..entry.name_end];
            if eq_ascii_fold(entry_name, name) {
                return map.raw_buf[entry.values_begin..entry.values_end];
            }
        }
    }
    return "";
}

fn resolve_entry_value(entry: const HeaderEntry&, map: const HeaderMap&, arena: const OverflowArena&) -> const u8[:] {
    if entry.reserved == HEADER_SRC_ARENA {
        return arena.spill_raw[entry.values_begin..entry.values_end];
    }
    return map.raw_buf[entry.values_begin..entry.values_end];
}

fn resolve_entry_name(entry: const HeaderEntry&, map: const HeaderMap&, arena: const OverflowArena&) -> const u8[:] {
    if entry.reserved == HEADER_SRC_ARENA {
        return arena.spill_raw[entry.name_begin..entry.name_end];
    }
    return map.raw_buf[entry.name_begin..entry.name_end];
}

fn find_entry_in_entries(
    entries: const HeaderEntry[:],
    name:    const u8[:],
    hname:   u32,
    map:     const HeaderMap&,
    arena:   const OverflowArena&,
) -> const u8[:] {
    for &entry in entries {
        if entry.name_hash == hname {
            let entry_name = resolve_entry_name(entry, map, arena);
            if eq_ascii_fold(entry_name, name) {
                return resolve_entry_value(entry, map, arena);
            }
        }
    }
    return "";
}

// Case-insensitive header lookup resolving from either stack map or arena spill storage.
fn get_header_spill(map: const HeaderMap&, arena: const OverflowArena&, name: const u8[:]) -> const u8[:] {
    let wk_id = classify_well_known_header(name);
    if wk_id != WellKnownHeader.Unknown {
        let slot = well_known_to_slot(wk_id);
        let idx = map.inline_slots[slot];
        if idx != 0xFF && idx < map.entries.len {
            return resolve_entry_value(map.entries[idx as i64], map, arena);
        }
    }

    let hname = hash_header_name(name);
    let val1 = find_entry_in_entries(map.entries[..], name, hname, map, arena);
    if val1.len > 0 { return val1; }
    return find_entry_in_entries(arena.spill_entries[..], name, hname, map, arena);
}

// Case-insensitive presence check for a header resolving from either stack map or arena spill storage.
fn has_header_spill(map: const HeaderMap&, arena: const OverflowArena&, name: const u8[:]) -> bool {
    let val = get_header_spill(map, arena, name);
    return val.len > 0;
}

fn get_inline(map: const HeaderMap&, id: WellKnownHeader) -> const u8[:] {
    guard id != WellKnownHeader.Unknown else { return ""; }
    let slot = well_known_to_slot(id);
    let idx = map.inline_slots[slot];
    if idx != 0xFF {
        let entry = map.entries[idx as i64];
        return map.raw_buf[entry.values_begin..entry.values_end];
    }
    return "";
}

fn append_header(map: HeaderMap&, name: const u8[:], value: const u8[:]) -> bool {
    let valid_name = is_valid_header_name(name) || is_valid_header_name_h2(name);
    guard valid_name && is_valid_header_value(value) else { return false; }
    guard map.entries.len < 128 else { return false; }

    let trimmed = trim_lws(value);
    let needed = name.len + trimmed.len;
    guard (map.raw_buf.len + needed) <= 8192 else { return false; }

    let n_begin = map.raw_buf.len as u16;
    map.raw_buf.append(name);
    let n_end = map.raw_buf.len as u16;

    let v_begin = map.raw_buf.len as u16;
    map.raw_buf.append(trimmed);
    let v_end = map.raw_buf.len as u16;

    let wk_id = classify_well_known_header(name);
    let flags = well_known_header_flags(wk_id, name);
    let hname = hash_header_name(name);

    var contains_comma = false;
    for b in trimmed {
        if b == ',' { contains_comma = true; break; }
    }
    let entry_flags = if contains_comma { flags | HEADER_FLAG_CONTAINS_COMMA } else { flags };

    let new_idx = map.entries.len as u8;
    let entry = HeaderEntry {
        name_begin:    n_begin,
        name_end:      n_end,
        values_begin:  v_begin,
        values_end:    v_end,
        next_idx:      0xFF,
        flags:         entry_flags,
        well_known_id: if wk_id != WellKnownHeader.Unknown { well_known_to_slot(wk_id) as u8 } else { 0xFF },
        reserved:      0,
        name_hash:     hname,
    };

    link_header_entry(map, wk_id, name, hname, new_idx);
    map.entries.push(entry);
    map.header_contains_comma.push(contains_comma);
    return true;
}

fn calc_entry_match_bytes(raw: const u8[:], e: const HeaderEntry&, name: const u8[:]) -> i64 {
    guard e.reserved == HEADER_SRC_STACK && e.name_end <= raw.len as u16 else { return -1; }
    let ename = raw[e.name_begin..e.name_end];
    guard eq_ascii_fold(ename, name) else { return -1; }
    return (e.name_end - e.name_begin) + (e.values_end - e.values_begin);
}

fn can_insert_header(map: const HeaderMap&, name: const u8[:], value: const u8[:]) -> bool {
    let trimmed = trim_lws(value);
    let needed = name.len + trimmed.len;
    let hname = hash_header_name(name);
    var matching = 0;
    var reclaimed: i64 = 0;
    for &e in map.entries {
        if e.name_hash == hname {
            let b = calc_entry_match_bytes(map.raw_buf[..], e, name);
            if b >= 0 {
                matching += 1;
                reclaimed += b;
            }
        }
    }
    guard (map.entries.len - matching + 1) <= 128 else { return false; }
    return (map.raw_buf.len - reclaimed + needed) <= 8192;
}

fn insert_header(map: HeaderMap&, name: const u8[:], value: const u8[:]) -> bool {
    let valid_name = is_valid_header_name(name) || is_valid_header_name_h2(name);
    guard valid_name && is_valid_header_value(value) else { return false; }
    guard can_insert_header(map, name, value) else { return false; }

    if map.has_header(name) {
        map.remove_header(name);
    }
    return map.append_header(name, value);
}

fn set_inline(map: HeaderMap&, id: WellKnownHeader, value: const u8[:]) -> bool {
    guard id != WellKnownHeader.Unknown else { return false; }
    let name = well_known_header_name(id);
    return map.insert_header(name, value);
}

fn link_rebuilt_entry(
    inline_slots: u8[64]&,
    new_entries:  HeaderEntry[..128]&,
    raw_buf:      const u8[:],
    ename:        const u8[:],
    copy_e:       const HeaderEntry&,
    new_idx:      u8,
) {
    let cur_wk = if copy_e.well_known_id != 0xFF { copy_e.well_known_id as i64 } else { -1 };
    if cur_wk >= 0 && cur_wk < 64 {
        let ex = inline_slots[cur_wk];
        if ex == 0xFF {
            inline_slots[cur_wk] = new_idx;
            return;
        }
        var cur = ex;
        while new_entries[cur as i64].next_idx != 0xFF {
            cur = new_entries[cur as i64].next_idx;
        }
        new_entries[cur as i64].next_idx = new_idx;
        return;
    }

    for prev_i in new_entries.len {
        guard new_entries[prev_i].name_hash == copy_e.name_hash else { continue; }
        let prev_n = raw_buf[new_entries[prev_i].name_begin..new_entries[prev_i].name_end];
        guard eq_ascii_fold(prev_n, ename) else { continue; }

        var cur = prev_i as u8;
        while new_entries[cur as i64].next_idx != 0xFF {
            cur = new_entries[cur as i64].next_idx;
        }
        new_entries[cur as i64].next_idx = new_idx;
        break;
    }
}

fn remove_header(map: HeaderMap&, name: const u8[:]) -> bool {
    let wk_id = classify_well_known_header(name);
    var found = false;

    if wk_id != WellKnownHeader.Unknown {
        let slot = well_known_to_slot(wk_id);
        if map.inline_slots[slot] != 0xFF {
            map.inline_slots[slot] = 0xFF;
            found = true;
        }
    }

    // Prune entries by rebuilding and compacting raw_buf
    var new_entries: HeaderEntry[..128] = [];
    var new_commas:  bool[..128]        = [];
    var new_raw_buf: u8[..8192]         = [];
    for i in 64 { map.inline_slots[i] = 0xFF; }

    for &e, i in map.entries {
        let ename = if e.reserved == HEADER_SRC_STACK && e.name_end <= map.raw_buf.len as u16 {
            map.raw_buf[e.name_begin..e.name_end]
        } else {
            ""
        };
        if eq_ascii_fold(ename, name) {
            found = true;
            continue;
        }

        var copy_e = e;
        if e.reserved == HEADER_SRC_STACK && e.values_end <= map.raw_buf.len as u16 {
            let eval = map.raw_buf[e.values_begin..e.values_end];
            let new_n_begin = new_raw_buf.len as u16;
            new_raw_buf.append(ename);
            let new_n_end = new_raw_buf.len as u16;

            let new_v_begin = new_raw_buf.len as u16;
            new_raw_buf.append(eval);
            let new_v_end = new_raw_buf.len as u16;

            copy_e.name_begin = new_n_begin;
            copy_e.name_end = new_n_end;
            copy_e.values_begin = new_v_begin;
            copy_e.values_end = new_v_end;
        }
        let new_idx = new_entries.len as u8;
        copy_e.next_idx = 0xFF;

        let cur_raw: const u8[:] = if new_raw_buf.len > 0 { new_raw_buf[..] } else { map.raw_buf[..] };
        link_rebuilt_entry(map.inline_slots, new_entries, cur_raw, ename, copy_e, new_idx);

        new_entries.push(copy_e);
        new_commas.push(map.header_contains_comma[i]);
    }

    if map.raw_buf.len > 0 {
        map.raw_buf.clear();
        map.raw_buf.append(new_raw_buf[..]);
    }

    map.entries.clear();
    for e in new_entries { map.entries.push(e); }
    map.header_contains_comma.clear();
    for c in new_commas { map.header_contains_comma.push(c); }

    return found;
}

// RFC 9110 Section 5.3 comma combining. BLOCKS Set-Cookie & NO_COMMA_FOLD headers.
fn get_combined<B>(map: const HeaderMap&, name: const u8[:], out: B&) -> bool {
    let wk_id = classify_well_known_header(name);
    let flags = well_known_header_flags(wk_id, name);
    guard (flags & HEADER_FLAG_NO_COMMA_FOLD) == 0 else {
        // Absolute RFC 9110 Section 5.3 / RFC 6265bis prohibition on folding Set-Cookie
        return false;
    }

    var first = true;
    var found = false;
    let hname = hash_header_name(name);

    for entry in map.entries {
        guard entry.name_hash == hname else { continue; }
        let entry_name = map.raw_buf[entry.name_begin..entry.name_end];
        guard eq_ascii_fold(entry_name, name) else { continue; }
        found = true;
        if !first {
            out.push(',');
            out.push(' ');
        }
        first = false;
        let val = map.raw_buf[entry.values_begin..entry.values_end];
        out.append(val);
    }
    return found;
}

// Resolves the entry index of the first header matching name.
fn find_first_header_index(
    map:  const HeaderMap&,
    raw:  const u8[:],
    name: const u8[:],
) -> i64 {
    let wk_id = classify_well_known_header(name);
    if wk_id != WellKnownHeader.Unknown {
        let slot = well_known_to_slot(wk_id);
        let first = map.inline_slots[slot];
        if first != 0xFF && first < map.entries.len {
            return first;
        }
        return -1;
    }

    let hname = hash_header_name(name);
    for i in map.entries.len {
        let e = map.entries[i];
        guard e.name_hash == hname else { continue; }
        let ename = if raw.len > 0 && e.name_end <= raw.len {
            raw[e.name_begin..e.name_end]
        } else {
            map.raw_buf[e.name_begin..e.name_end]
        };
        if eq_ascii_fold(ename, name) {
            return i;
        }
    }
    return -1;
}

// Iterates multi-value headers by following intrusive next_idx collision chains.
// Advances cursor to the next matching entry index, or -1 when exhausted.
//
// Example:
//   map with 2 "set-cookie" headers at entries 3 and 7
//   cursor = 0 -> returns: "a=1", true, cursor = 7
//   cursor = 7 -> returns: "b=2", true, cursor = -1
//   cursor = -1 -> returns: "", false, cursor = -1
fn next_header_value(
    map:    const HeaderMap&,
    raw:    const u8[:],
    name:   const u8[:],
    cursor: i64&,
) -> const u8[:], bool {
    guard cursor >= 0 else {
        cursor = -1;
        return "", false;
    }

    let cur_idx = if cursor == 0 {
        find_first_header_index(map, raw, name)
    } else {
        cursor
    };

    guard cur_idx >= 0 && cur_idx < map.entries.len else {
        cursor = -1;
        return "", false;
    }

    let entry = map.entries[cur_idx];
    let wk_id = classify_well_known_header(name);
    if wk_id != WellKnownHeader.Unknown {
        let expected_slot = well_known_to_slot(wk_id) as u8;
        guard entry.well_known_id == expected_slot else {
            cursor = -1;
            return "", false;
        }
    } else {
        guard entry.name_hash == hash_header_name(name) else {
            cursor = -1;
            return "", false;
        }
    }

    if entry.next_idx != 0xFF && entry.next_idx < map.entries.len {
        cursor = entry.next_idx;
    } else {
        cursor = -1;
    }

    let has_raw = raw.len > 0 && entry.values_end <= raw.len;
    let has_buf = entry.values_end <= map.raw_buf.len;
    guard has_raw || has_buf else {
        cursor = -1;
        return "", false;
    }
    let val = if has_raw {
        raw[entry.values_begin..entry.values_end]
    } else {
        map.raw_buf[entry.values_begin..entry.values_end]
    };

    return val, true;
}

// Deprecated: Use zero-allocation `next_header_value` cursor iterator instead of copying into dynamic vectors.
fn get_all_values(map: const HeaderMap&, name: const u8[:], out_values: u8[..256][>..]&) {
    let hname = hash_header_name(name);
    for &entry in map.entries {
        if entry.name_hash == hname {
            let entry_name = map.raw_buf[entry.name_begin..entry.name_end];
            if eq_ascii_fold(entry_name, name) {
                let val = map.raw_buf[entry.values_begin..entry.values_end];
                var item: u8[..256] = [];
                let v_len = core::ct_min_i64(val.len, item.cap);
                item.append(val[..v_len]);
                out_values.push(item);
            }
        }
    }
}

// Retrieves all header values across both stack map and overflow arena
fn get_all_values_spill(
    map:        const HeaderMap&,
    arena:      const OverflowArena&,
    name:       const u8[:],
    out_values: u8[..256][>..]&,
) {
    let hname = hash_header_name(name);
    for &entry in map.entries {
        if entry.name_hash == hname {
            let entry_name = resolve_entry_name(entry, map, arena);
            if eq_ascii_fold(entry_name, name) {
                let val = resolve_entry_value(entry, map, arena);
                var item: u8[..256] = [];
                let v_len = core::ct_min_i64(val.len, item.cap);
                item.append(val[..v_len]);
                out_values.push(item);
            }
        }
    }
    for &entry in arena.spill_entries {
        if entry.name_hash == hname {
            let entry_name = resolve_entry_name(entry, map, arena);
            if eq_ascii_fold(entry_name, name) {
                let val = resolve_entry_value(entry, map, arena);
                var item: u8[..256] = [];
                let v_len = core::ct_min_i64(val.len, item.cap);
                item.append(val[..v_len]);
                out_values.push(item);
            }
        }
    }
}

// Zero-allocation retrieval of Set-Cookie header lines
fn get_set_cookie(map: const HeaderMap&, out_cookies: u8[..1024][>..]&) {
    let slot = well_known_to_slot(WellKnownHeader.SetCookie);
    var cur = map.inline_slots[slot];
    while cur != 0xFF {
        let entry = map.entries[cur as i64];
        let val = map.raw_buf[entry.values_begin..entry.values_end];
        var cookie_str: u8[..1024] = [];
        let copy_len = if val.len <= cookie_str.cap { val.len } else { cookie_str.cap };
        cookie_str.append(val[..copy_len]);
        out_cookies.push(cookie_str);
        cur = entry.next_idx;
    }
}

// Chromium raw_headers_ format: lines separated by \0, terminated by \0\0
fn raw_headers(map: const HeaderMap&, out: u8[>..]&) {
    for &entry in map.entries {
        let name = map.raw_buf[entry.name_begin..entry.name_end];
        let val = map.raw_buf[entry.values_begin..entry.values_end];
        out.append(name);
        out.push(':');
        out.push(' ');
        out.append(val);
        out.push(0);
    }
    out.push(0);
}

// Chromium raw_headers_ format with overflow arena support
fn raw_headers_spill(map: const HeaderMap&, arena: const OverflowArena&, out: u8[>..]&) {
    for &entry in map.entries {
        let name = resolve_entry_name(entry, map, arena);
        let val = resolve_entry_value(entry, map, arena);
        out.append(name);
        out.push(':');
        out.push(' ');
        out.append(val);
        out.push(0);
    }
    for &entry in arena.spill_entries {
        let name = resolve_entry_name(entry, map, arena);
        let val = resolve_entry_value(entry, map, arena);
        out.append(name);
        out.push(':');
        out.push(' ');
        out.append(val);
        out.push(0);
    }
    out.push(0);
}

fn append_folded_header_values(
    map:       const HeaderMap&,
    start_idx: i64,
    entry:     const HeaderEntry&,
    name:      const u8[:],
    visited:   bool[128]&,
    out:       u8[>..]&,
) {
    var first = true;
    for j in start_idx..map.entries.len {
        let other = map.entries[j];
        guard other.name_hash == entry.name_hash else { continue; }
        let other_name = map.raw_buf[other.name_begin..other.name_end];
        guard eq_ascii_fold(other_name, name) else { continue; }
        if !first {
            out.append(", ");
        }
        first = false;
        let val = map.raw_buf[other.values_begin..other.values_end];
        out.append(val);
        visited[j] = true;
    }
}

// Wire serialization with RFC 9110 comma folding for list fields and separate lines for Set-Cookie
fn serialize_headers(map: const HeaderMap&, out: u8[>..]&) {
    var visited: bool[128] = [false; 128];

    for i in map.entries.len {
        if visited[i] { continue; }

        let entry = map.entries[i];
        let name = map.raw_buf[entry.name_begin..entry.name_end];

        if has_no_comma_fold(entry) {
            // Emit as distinct lines (e.g. Set-Cookie: ...\r\n)
            let val = map.raw_buf[entry.values_begin..entry.values_end];
            out.append(name);
            out.append(": ");
            out.append(val);
            out.append("\r\n");
            visited[i] = true;
        } else {
            // Combine comma-foldable headers
            out.append(name);
            out.append(": ");
            append_folded_header_values(map, i, entry, name, visited, out);
            out.append("\r\n");
        }
    }
}

// ---- chromium 304 not modified merge & cache persistence --------------------

fn should_update_header_304(entry_flags: u8, name: const u8[:]) -> bool {
    // RFC 9110 Section 15.4.5, RFC 9111 Section 3.2 & Chromium HttpResponseHeaders::ShouldUpdateHeader
    // Never update cookies, auth challenges, security state, or hop-by-hop headers
    let blocked_flags = HEADER_FLAG_COOKIE_STATE | HEADER_FLAG_CHALLENGE |
        HEADER_FLAG_SECURITY_STATE | HEADER_FLAG_NON_CACHEABLE;
    if (entry_flags & blocked_flags) != 0 {
        return false;
    }
    if eq_ascii_fold(name, "content-range") ||
       eq_ascii_fold(name, "content-length") ||
       eq_ascii_fold(name, "content-encoding") ||
       eq_ascii_fold(name, "content-type") ||
       eq_ascii_fold(name, "content-md5") ||
       eq_ascii_fold(name, "content-language") {
        return false;
    }
    return true;
}

// Merges fresh headers from a 304 Not Modified response into cached headers
fn merge_with_headers_304(cached_headers: HeaderMap&, response_304: const HeaderMap&) {
    for &entry in response_304.entries {
        let name = response_304.raw_buf[entry.name_begin..entry.name_end];
        if should_update_header_304(entry.flags, name) {
            let val = response_304.raw_buf[entry.values_begin..entry.values_end];
            cached_headers.insert_header(name, val);
        }
    }
}

// Filters headers according to Chromium persistence flags
fn persist_headers(src: const HeaderMap&, dst: HeaderMap&, flags: u32) {
    dst.reset_for_keep_alive();
    for &entry in src.entries {
        let name = src.raw_buf[entry.name_begin..entry.name_end];
        let val = src.raw_buf[entry.values_begin..entry.values_end];

        if (flags & PERSIST_SANS_COOKIES) != 0 && (entry.flags & HEADER_FLAG_COOKIE_STATE) != 0 {
            continue;
        }
        if (flags & PERSIST_SANS_CHALLENGES) != 0 && (entry.flags & HEADER_FLAG_CHALLENGE) != 0 {
            continue;
        }
        if (flags & PERSIST_SANS_NON_CACHEABLE) != 0 && (entry.flags & HEADER_FLAG_NON_CACHEABLE) != 0 {
            continue;
        }
        if (flags & PERSIST_SANS_SECURITY_STATE) != 0 && (entry.flags & HEADER_FLAG_SECURITY_STATE) != 0 {
            continue;
        }

        dst.append_header(name, val);
    }
}

// ---- hop-by-hop stripping -------------------------------------------------

// RFC 9110 Section 7.6.1: Standard hop-by-hop headers identification
fn is_hop_by_hop_header_name(name: const u8[:]) -> bool {
    let id = classify_well_known_header(name);
    if id == WellKnownHeader.Connection || id == WellKnownHeader.KeepAlive || id == WellKnownHeader.TransferEncoding ||
       id == WellKnownHeader.TE || id == WellKnownHeader.Trailer || id == WellKnownHeader.Upgrade ||
       id == WellKnownHeader.ProxyAuthorization || id == WellKnownHeader.ProxyAuthenticate {
        return true;
    }
    if eq_ascii_fold(name, "proxy-connection") {
        return true;
    }
    return false;
}

fn collect_connection_tokens(src: const HeaderMap&, out_tokens: u8[..64][..32]&) {
    for &entry in src.entries {
        let name = src.raw_buf[entry.name_begin..entry.name_end];
        guard eq_ascii_fold(name, "connection") else { continue; }

        let val = src.raw_buf[entry.values_begin..entry.values_end];
        var cursor: i64 = 0;
        while cursor < val.len {
            var comma_idx = cursor;
            while comma_idx < val.len && val[comma_idx] != ',' {
                comma_idx++;
            }
            let token = trim_lws(val[cursor..comma_idx]);
            cursor = comma_idx + 1;
            let is_valid_token = token.len > 0 &&
                !is_hop_by_hop_header_name(token) &&
                !eq_ascii_fold(token, "close");
            guard is_valid_token else { continue; }
            guard out_tokens.len < out_tokens.cap && token.len <= 64 else { continue; }
            var tok_buf: u8[..64] = [];
            tok_buf.append(token);
            out_tokens.push(tok_buf);
        }
    }
}

fn is_token_in_connection_header_map(src: const HeaderMap&, target_name: const u8[:]) -> bool {
    for &entry in src.entries {
        let name = src.raw_buf[entry.name_begin..entry.name_end];
        guard eq_ascii_fold(name, "connection") else { continue; }

        let val = src.raw_buf[entry.values_begin..entry.values_end];
        var cursor: i64 = 0;
        while cursor < val.len {
            var comma_idx = cursor;
            while comma_idx < val.len && val[comma_idx] != ',' {
                comma_idx++;
            }
            let token = trim_lws(val[cursor..comma_idx]);
            cursor = comma_idx + 1;
            if token.len > 0 && eq_ascii_fold(token, target_name) {
                return true;
            }
        }
    }
    return false;
}

// Copies headers from src to dst, omitting standard hop-by-hop headers and
// any header listed in a Connection header token (RFC 9110 Section 7.6.1).
fn strip_hop_by_hop_headers(src: const HeaderMap&, dst: HeaderMap&) {
    dst.reset_for_keep_alive();

    for &entry in src.entries {
        let name = src.raw_buf[entry.name_begin..entry.name_end];
        let val = src.raw_buf[entry.values_begin..entry.values_end];

        if is_hop_by_hop_header_name(name) {
            // RFC 9110 §7.6.1, RFC 9113 §8.2.2 & Go #21096:
            // "An intermediary MUST remove any received TE header field prior to forwarding the message,
            // EXCEPT that the presence of the keyword 'trailers' MAY be forwarded (and is required by gRPC)."
            if eq_ascii_fold(name, "te") && eq_ascii_fold(core::trim_lws(val), "trailers") {
                dst.append_header(name, val);
            }
            continue;
        }

        if is_token_in_connection_header_map(src, name) {
            continue;
        }

        dst.append_header(name, val);
    }
}

// RFC 9112 Section 2.1: Message Format - Incrementally scans HTTP/1.1 raw bytes for the CRLFCRLF
// header block terminator starting at (last_len < 3) ? 0 : last_len - 3 to prevent O(N^2) Slowloris rescans.
// On success (ok == true), updates `cursor` to the byte offset immediately after "\r\n\r\n" and returns (cursor, true).
// On incomplete input (ok == false), advances `cursor` to the safe resume offset (raw.len < 3 ? 0 : raw.len - 3)
// and returns (0, false).
//
// Example:
//   raw = "GET / HTTP/1.1\r\nHost: a\r\n\r\n", last_len = 16, cursor = 0
//   returns: 27, true, cursor = 27
fn scan_http1_headers(raw: const u8[:], last_len: u32, cursor: i64&) -> i64, bool {
    guard raw.len >= 4 else {
        cursor = 0;
        return 0, false;
    }
    let resume_pos: i64 = if last_len < 3 { 0 } else { last_len - 3 };
    let start_pos:  i64 = if resume_pos > raw.len - 4 { raw.len - 4 } else { resume_pos };
    let rel = core::fast_find_crlfcrlf(raw[start_pos..]);
    if rel >= 0 {
        let end_offset = start_pos + rel + 4;
        cursor = end_offset;
        return end_offset, true;
    }
    cursor = raw.len - 3;
    return 0, false;
}
