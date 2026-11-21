// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP header parsing and storage (RFC 9110, RFC 9112).
// Stores names and values as offset slices into a contiguous buffer with
// dedicated lookup slots for frequent standard headers.
namespace http;

import std;
import core from "..";
import .headers.lexical;
import .headers.perfect_hash;
import http.headers.internal;

// ---- header ascii helpers (RFC 9110 Section 5.6.3) -------------------------

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
    // RFC 9421 Section 7.2.1: Insufficient Coverage - Strip Signature and Signature-Input on cross-origin redirects
    return name.eq_ascii_fold("authorization") ||
           name.eq_ascii_fold("proxy-authorization") ||
           name.eq_ascii_fold("cookie") ||
           name.eq_ascii_fold("dpop") ||
           name.eq_ascii_fold("signature") ||
           name.eq_ascii_fold("signature-input") ||
           name.eq_ascii_fold("x-api-key") ||
           name.eq_ascii_fold("x-auth-token") ||
           name.eq_ascii_fold("x-access-token") ||
           name.eq_ascii_fold("x-signature-256") ||
           name.eq_ascii_fold("x-csrf-token") ||
           name.eq_ascii_fold("x-xsrf-token") ||
           name.eq_ascii_fold("www-authenticate") ||
           name.eq_ascii_fold("proxy-authenticate") ||
           name.eq_ascii_fold("x-amz-security-token");
}

// Appends src to out with CR, LF, and NUL bytes omitted, clamped to out.cap (RFC 9110 Section 5.5).
//
// Example:
//   src = "header\r\nvalue\0", out = []
//   out becomes "headervalue"
fn sanitize_header_bytes<B>(src: const u8[:], out: B&) {
    for b in src {
        if b != '\r' && b != '\n' && b != 0 {
            guard out.try_push(b) else { return; }
        }
    }
}

// Go #79346 log/error control-char injection defense: Escapes control characters (< 0x20 and >= 0x7F)
// in untrusted header and protocol tokens for safe diagnostic logging without CRLF injection.
//
// Example:
//   input = "foo\r\nbar\x01", out = []
//   out becomes "foo\\r\\nbar\\x01"
fn escape_diagnostic_control_chars<B>(input: const u8[:], out: B&) {
    for b in input {
        if b == '\r' || b == '\n' || b == '\t' {
            let esc = if b == '\r' { "\\r" } else if b == '\n' { "\\n" } else { "\\t" };
            guard out.try_append(esc) else { return; }
        } else if b < 0x20 || b >= 0x7F {
            guard out.len + 4 <= out.cap else { return; }
            out.append("\\x");
            let hex_chars: const u8[:] = "0123456789ABCDEF";
            out.push(hex_chars[(b >> 4) & 0x0F]);
            out.push(hex_chars[b & 0x0F]);
        } else {
            guard out.try_push(b) else { return; }
        }
    }
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

fn add_header(bf: HeaderBloomFilter&, key: const u8[:]) {
    guard key.len >= 2 else { return; }
    let h = http_internal::bloom_hash(key);
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
    let h = http_internal::bloom_hash(key);
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

let EMPTY_OVERFLOW_ARENA: OverflowArena = OverflowArena { .. };

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

// Go #79346 log/error control-char injection defense: Sanitize untrusted user input
// before formatting into error strings or logs.
// Replaces control characters (< 0x20, CR, LF, DEL) and non-printable bytes with safe visual representation '?'.
//
// Example:
//   input = "bad\x00input\r\n", out = []
//   out becomes "bad?input??"
fn sanitize_untrusted_for_error<B>(input: const u8[:], out: B&) {
    out.clear();
    for b in input {
        let ch: u8 = if b >= 0x20 && b <= 0x7E && b != '\\' && b != '"' { b } else { '?' };
        guard out.try_push(ch) else { return; }
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

fn classify_well_known_header(name: const u8[:]) -> WellKnownHeader {
    let len = name.len;
    guard len >= 2 && len <= 32 && is_valid_header_name(name) else { return WellKnownHeader.Unknown; }

    if name.starts_with_fold("access-control-") {
        return http_internal::classify_cors_header(name, len);
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
            if name.eq_ascii_fold("set-cookie2") { return WellKnownHeader.SetCookie2; }
            if name.eq_ascii_fold("retry-after") { return WellKnownHeader.RetryAfter; }
        },
        12 => {
            let w64 = core::read_le_u64(name, 0) | 0x2020202020202020;
            let w32 = core::read_le_u32(name, 8) | 0x20202020;
            if w64 == 0x2d746e65746e6f63 && w32 == 0x65707974 { return WellKnownHeader.ContentType; }
            if name.eq_ascii_fold("x-webkit-csp") { return WellKnownHeader.XWebkitCsp; }
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
            if name.eq_ascii_fold("accept-charset") { return WellKnownHeader.AcceptCharset; }
        },
        15 => {
            if name.eq_ascii_fold("accept-encoding") { return WellKnownHeader.AcceptEncoding; }
            if name.eq_ascii_fold("accept-language") { return WellKnownHeader.AcceptLanguage; }
            if name.eq_ascii_fold("clear-site-data") { return WellKnownHeader.ClearSiteData; }
            if name.eq_ascii_fold("x-frame-options") { return WellKnownHeader.XFrameOptions; }
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
            if name.eq_ascii_fold("if-modified-since") { return WellKnownHeader.IfModifiedSince; }
            if name.eq_ascii_fold("transfer-encoding") { return WellKnownHeader.TransferEncoding; }
        },
        18 => {
            if name.eq_ascii_fold("proxy-authenticate") { return WellKnownHeader.ProxyAuthenticate; }
        },
        19 => {
            if name.eq_ascii_fold("if-unmodified-since") { return WellKnownHeader.IfUnmodifiedSince; }
            if name.eq_ascii_fold("proxy-authorization") { return WellKnownHeader.ProxyAuthorization; }
            if name.eq_ascii_fold("content-disposition") { return WellKnownHeader.ContentDisposition; }
        },
        22 => {
            if name.eq_ascii_fold("x-content-type-options") { return WellKnownHeader.XContentTypeOptions; }
        },
        23 => {
            if name.eq_ascii_fold("content-security-policy") { return WellKnownHeader.ContentSecurityPolicy; }
        },
        25 => {
            if name.eq_ascii_fold("strict-transport-security") { return WellKnownHeader.StrictTransportSecurity; }
        },
        _ => {},
    }
    return WellKnownHeader.Unknown;
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
    if map.entries.len > 0 && map.entries.len < 32 {
        for &e in map.entries {
            if e.well_known_id < 64 {
                map.inline_slots[e.well_known_id as i64] = 0xFF;
            }
        }
    } else if map.entries.len >= 32 {
        for i in 64 {
            map.inline_slots[i] = 0xFF;
        }
    }
    map.raw_buf.clear();
    map.entries.clear();
    map.header_contains_comma.clear();
    map.status_code = 200;
    map.http_major = 1;
    map.http_minor = 1;
    map.valid = true;
}

// ---- wire parser -----------------------------------------------------------

struct ObsFoldPolicy {
    is_first_header: bool = false,
    allow_obs_fold:  bool = false,
}

fn handle_obs_fold_arena(
    trimmed_continuation: const u8[:],
    map:                  HeaderMap&,
    arena:                OverflowArena&,
    in_spill:             bool,
) -> HeaderParseError {
    let orig_name = if in_spill {
        resolve_entry_name(arena.spill_entries[arena.spill_entries.len - 1], map, arena)
    } else {
        resolve_entry_name(map.entries[map.entries.len - 1], map, arena)
    };
    let orig_val = if in_spill {
        http_internal::resolve_entry_value(arena.spill_entries[arena.spill_entries.len - 1], map, arena)
    } else {
        http_internal::resolve_entry_value(map.entries[map.entries.len - 1], map, arena)
    };
    let migrate_name = if in_spill {
        arena.spill_entries[arena.spill_entries.len - 1].reserved != HEADER_SRC_ARENA
    } else {
        map.entries[map.entries.len - 1].reserved != HEADER_SRC_ARENA
    };
    let name_bytes = if migrate_name { orig_name.len } else { 0 };
    let needed = name_bytes + orig_val.len + 1 + trimmed_continuation.len;
    guard (arena.spill_raw.len + needed) <= 65535 else {
        map.valid = false;
        return HeaderParseError.CapacityExceeded;
    }

    let saved_spill_len = arena.spill_raw.len;
    var n_begin: u16 = 0;
    var n_end:   u16 = 0;
    if migrate_name {
        n_begin = arena.spill_raw.len as u16;
        arena.spill_raw.append(orig_name);
        n_end = arena.spill_raw.len as u16;
    }

    let new_begin = arena.spill_raw.len as u16;
    arena.spill_raw.append(orig_val);
    arena.spill_raw.push(' ');
    arena.spill_raw.append(trimmed_continuation);
    let new_end = arena.spill_raw.len as u16;

    let prev_wk: u8 = if in_spill {
        arena.spill_entries[arena.spill_entries.len - 1].well_known_id
    } else {
        map.entries[map.entries.len - 1].well_known_id
    };
    guard http_internal::validate_folded_framing(arena.spill_raw[..], new_begin, new_end, prev_wk) else {
        arena.spill_raw.resize(saved_spill_len);
        map.valid = false;
        return HeaderParseError.InvalidContentLength;
    }

    if migrate_name {
        if in_spill {
            arena.spill_entries[arena.spill_entries.len - 1].name_begin = n_begin;
            arena.spill_entries[arena.spill_entries.len - 1].name_end = n_end;
        } else {
            map.entries[map.entries.len - 1].name_begin = n_begin;
            map.entries[map.entries.len - 1].name_end = n_end;
        }
    }

    let cont_has_comma = trimmed_continuation.contains_byte(',');
    if in_spill {
        let s_idx = arena.spill_entries.len - 1;
        arena.spill_entries[s_idx].values_begin = new_begin;
        arena.spill_entries[s_idx].values_end = new_end;
        arena.spill_entries[s_idx].reserved = HEADER_SRC_ARENA;
        if cont_has_comma {
            arena.spill_entries[s_idx].flags |= HEADER_FLAG_CONTAINS_COMMA;
        }
    } else {
        let m_idx = map.entries.len - 1;
        map.entries[m_idx].values_begin = new_begin;
        map.entries[m_idx].values_end = new_end;
        map.entries[m_idx].reserved = HEADER_SRC_ARENA;
        if cont_has_comma {
            map.entries[m_idx].flags |= HEADER_FLAG_CONTAINS_COMMA;
            map.header_contains_comma[m_idx] = true;
        }
    }
    return HeaderParseError.None;
}

fn validate_header_framing_conflicts(
    map:         HeaderMap&,
    wk_id:       WellKnownHeader,
    val_trimmed: const u8[:],
    is_dup_cl:   bool&,
    arena:       const OverflowArena& = EMPTY_OVERFLOW_ARENA,
) -> HeaderParseError {
    is_dup_cl = false;
    if wk_id == WellKnownHeader.ContentLength {
        if has_header_spill(map, arena, "transfer-encoding") {
            map.valid = false;
            return HeaderParseError.InvalidContentLength;
        }
        let parsed_cl, ok_cl = validate_content_length_value(val_trimmed);
        guard ok_cl else {
            map.valid = false;
            return HeaderParseError.InvalidContentLength;
        }
        if has_header_spill(map, arena, "content-length") {
            let existing_str = get_header_spill(map, arena, "content-length");
            let existing_cl, ok_existing = validate_content_length_value(existing_str);
            guard ok_existing else {
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
        if has_header_spill(map, arena, "content-length") || has_header_spill(map, arena, "transfer-encoding") {
            map.valid = false;
            return HeaderParseError.InvalidContentLength;
        }
        guard validate_transfer_encoding_value(val_trimmed) else {
            map.valid = false;
            return HeaderParseError.InvalidContentLength;
        }
    } else if wk_id == WellKnownHeader.Host {
        // RFC 9112 Section 7.2: Duplicate Host header is forbidden (request smuggling protection)
        if has_header_spill(map, arena, "host") {
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

enum H1ResponseParseMode {
    Strict,
    ClientCompat,
}

// Parses an HTTP/1.x header block into map (RFC 9112 Section 5.2).
// Header names and values are indexed as offsets into the map's buffer.
// Obsolete line folding (obs-fold) is rejected unless allow_obs_fold is set.
//
// Example:
//   raw_input = "Host: example.com\r\nContent-Length: 0\r\n\r\n", map = HeaderMap { .. }
//   returns: HeaderParseError.None, populates map.entries
fn parse_headers(
    raw_input:      const u8[:],
    map:            HeaderMap&,
    allow_obs_fold: bool                = false,
    mode:           H1ResponseParseMode = H1ResponseParseMode.Strict,
) -> HeaderParseError {
    reset_for_keep_alive(map);
    map.valid = false;
    defer if !map.valid {
        reset_for_keep_alive(map);
        map.valid = false;
    };
    guard raw_input.len > 0 else {
        return HeaderParseError.EmptyInput;
    }
    if http_internal::has_embedded_nulls(raw_input) {
        return HeaderParseError.EmbeddedNull;
    }

    guard map.raw_buf.try_append(raw_input) else {
        return HeaderParseError.CapacityExceeded;
    }

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
        let line_err = http_internal::process_header_line(
            map.raw_buf[..], cursor, line_end, allow_obs_fold, map, is_first_header, prev_was_dup_cl, mode,
        );
        guard is_ok(line_err) else { return line_err; }

        guard advance_crlf(map.raw_buf[..], cursor, line_end) else {
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
    reset_for_keep_alive(map);
    http_internal::reset_overflow_arena(arena);
    map.valid = false;
    defer if !map.valid {
        reset_for_keep_alive(map);
        http_internal::reset_overflow_arena(arena);
        map.valid = false;
    };
    guard raw_input.len > 0 else {
        return HeaderParseError.EmptyInput;
    }
    guard raw_input.len <= 65535 else {
        return HeaderParseError.CapacityExceeded;
    }
    if http_internal::has_embedded_nulls(raw_input) {
        return HeaderParseError.EmbeddedNull;
    }

    let use_arena_buf = raw_input.len > 8192;
    if use_arena_buf {
        arena.spill_raw.append(raw_input);
    } else {
        map.raw_buf.append(raw_input);
    }

    let src_type: u8 = if use_arena_buf { HEADER_SRC_ARENA } else { HEADER_SRC_STACK };
    return http_internal::parse_overflow_headers_loop(raw_input, src_type, map, arena, allow_obs_fold);
}

// Parses full HTTP/1.1 response status line and header block with configurable compatibility mode.
//
// Example:
//   raw_input = "ICY 200 OK\r\nicy-name : stream\r\n\r\n", map = HeaderMap { .. }, mode = H1ResponseParseMode.ClientCompat
//   returns: HeaderParseError.None, map.status_code = 200
fn parse_response_headers_with_mode(
    raw_input:      const u8[:],
    map:            HeaderMap&,
    mode:           H1ResponseParseMode,
    allow_obs_fold: bool = false,
) -> HeaderParseError {
    reset_for_keep_alive(map);
    map.valid = false;
    guard raw_input.len > 0 else {
        return HeaderParseError.EmptyInput;
    }
    if http_internal::has_embedded_nulls(raw_input) {
        return HeaderParseError.EmbeddedNull;
    }

    var line_end: i64 = 0;
    while line_end < raw_input.len && raw_input[line_end] != '\r' && raw_input[line_end] != '\n' {
        line_end = core::add_sat_i64(line_end, 1);
    }

    var major: i32 = 0;
    var minor: i32 = 0;
    var code:  i32 = 0;
    let st_err = http_internal::parse_http_status_line(raw_input[..line_end], major, minor, code, mode);
    guard is_ok(st_err) else {
        return st_err;
    }

    var header_start = line_end;
    guard advance_crlf(raw_input, header_start, line_end) else {
        return HeaderParseError.MalformedStatusLine;
    }

    let err = parse_headers(raw_input[header_start..], map, allow_obs_fold, mode);
    guard is_ok(err) else { return err; }
    map.status_code = code;
    map.http_major = major;
    map.http_minor = minor;
    return HeaderParseError.None;
}

// Parses full HTTP/1.1 response status line and header block
//
// Example:
//   raw_input = "HTTP/1.1 200 OK\r\nContent-Length: 0\r\n\r\n", map = HeaderMap { .. }
//   returns: HeaderParseError.None, map.status_code = 200
fn parse_response_headers(raw_input: const u8[:], map: HeaderMap&, allow_obs_fold: bool = false) -> HeaderParseError {
    return parse_response_headers_with_mode(raw_input, map, H1ResponseParseMode.Strict, allow_obs_fold);
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
    reset_for_keep_alive(map);
    http_internal::reset_overflow_arena(arena);
    map.valid = false;
    guard raw_input.len > 0 else {
        return HeaderParseError.EmptyInput;
    }
    if http_internal::has_embedded_nulls(raw_input) {
        return HeaderParseError.EmbeddedNull;
    }

    var line_end: i64 = 0;
    while line_end < raw_input.len && raw_input[line_end] != '\r' && raw_input[line_end] != '\n' {
        line_end++;
    }

    var major: i32 = 0;
    var minor: i32 = 0;
    var code:  i32 = 0;
    let st_err = http_internal::parse_http_status_line(raw_input[..line_end], major, minor, code);
    guard is_ok(st_err) else {
        return st_err;
    }

    var header_start = line_end;
    if header_start < raw_input.len && raw_input[header_start] == '\r' {
        guard header_start + 1 < raw_input.len && raw_input[header_start + 1] == '\n' else {
            return HeaderParseError.MalformedStatusLine;
        }
        header_start += 2;
    } else if header_start < raw_input.len && raw_input[header_start] == '\n' {
        header_start++;
    }

    let err = parse_headers_with_overflow(raw_input[header_start..], map, arena, allow_obs_fold);
    guard is_ok(err) else { return err; }
    map.status_code = code;
    map.http_major = major;
    map.http_minor = minor;
    return HeaderParseError.None;
}

// Parses full HTTP/1.1 request line (METHOD /path HTTP/1.1) and header block
//
// Example:
//   raw_input = "GET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n", map = HeaderMap { .. }
//   returns: HeaderParseError.None, populates map.entries
fn parse_request_headers(raw_input: const u8[:], map: HeaderMap&, allow_obs_fold: bool = false) -> HeaderParseError {
    reset_for_keep_alive(map);
    map.valid = false;
    guard raw_input.len > 0 else {
        return HeaderParseError.EmptyInput;
    }
    if http_internal::has_embedded_nulls(raw_input) {
        return HeaderParseError.EmbeddedNull;
    }

    var line_end = http_internal::skip_single_preamble_empty_line(raw_input);
    while line_end < raw_input.len && raw_input[line_end] != '\r' && raw_input[line_end] != '\n' {
        line_end++;
    }

    var header_start = line_end;
    if header_start < raw_input.len && raw_input[header_start] == '\r' {
        guard header_start + 1 < raw_input.len && raw_input[header_start + 1] == '\n' else {
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
    reset_for_keep_alive(map);
    http_internal::reset_overflow_arena(arena);
    map.valid = false;
    guard raw_input.len > 0 else {
        return HeaderParseError.EmptyInput;
    }
    if http_internal::has_embedded_nulls(raw_input) {
        return HeaderParseError.EmbeddedNull;
    }

    var line_end = http_internal::skip_single_preamble_empty_line(raw_input);
    while line_end < raw_input.len && raw_input[line_end] != '\r' && raw_input[line_end] != '\n' {
        line_end++;
    }

    var header_start = line_end;
    if header_start < raw_input.len && raw_input[header_start] == '\r' {
        guard header_start + 1 < raw_input.len && raw_input[header_start + 1] == '\n' else {
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
            let ename = entry_name(map, entry);
            if ename.eq_ascii_fold(name) {
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
            return entry_value(map, entry);
        }
        return "";
    }

    let hname = hash_header_name(name);
    for &entry in map.entries {
        if entry.name_hash == hname {
            let ename = entry_name(map, entry);
            if ename.eq_ascii_fold(name) {
                return entry_value(map, entry);
            }
        }
    }
    return "";
}

fn resolve_entry_name(entry: const HeaderEntry&, map: const HeaderMap&, arena: const OverflowArena&) -> const u8[:] {
    if entry.reserved == HEADER_SRC_ARENA {
        return arena.spill_raw[entry.name_begin..entry.name_end];
    }
    return map.raw_buf[entry.name_begin..entry.name_end];
}

// Case-insensitive header lookup resolving from either stack map or arena spill storage.
fn get_header_spill(map: const HeaderMap&, arena: const OverflowArena&, name: const u8[:]) -> const u8[:] {
    let wk_id = classify_well_known_header(name);
    if wk_id != WellKnownHeader.Unknown {
        let slot = well_known_to_slot(wk_id);
        let idx = map.inline_slots[slot];
        if idx != 0xFF && idx < map.entries.len {
            return http_internal::resolve_entry_value(map.entries[idx as i64], map, arena);
        }
    }

    let hname = hash_header_name(name);
    let val1 = http_internal::find_entry_in_entries(map.entries[..], name, hname, map, arena);
    if val1.len > 0 { return val1; }
    return http_internal::find_entry_in_entries(arena.spill_entries[..], name, hname, map, arena);
}

// Case-insensitive presence check for a header resolving from either stack map or arena spill storage.
fn has_header_spill(map: const HeaderMap&, arena: const OverflowArena&, name: const u8[:]) -> bool {
    let wk_id = classify_well_known_header(name);
    if wk_id != WellKnownHeader.Unknown {
        let slot = well_known_to_slot(wk_id);
        let idx = map.inline_slots[slot];
        if idx != 0xFF && idx < map.entries.len {
            return true;
        }
    }
    let hname = hash_header_name(name);
    for &entry in map.entries {
        if entry.name_hash == hname && resolve_entry_name(entry, map, arena).eq_ascii_fold(name) {
            return true;
        }
    }
    for &entry in arena.spill_entries {
        if entry.name_hash == hname && resolve_entry_name(entry, map, arena).eq_ascii_fold(name) {
            return true;
        }
    }
    return false;
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

fn append_validated_header(map: HeaderMap&, name: const u8[:], trimmed: const u8[:]) -> bool {
    guard map.entries.len < 128 else { return false; }

    let needed = core::add_sat_i64(name.len, trimmed.len);
    guard core::add_sat_i64(map.raw_buf.len, needed) <= 8192 else { return false; }

    let n_begin = map.raw_buf.len as u16;
    map.raw_buf.append(name);
    let n_end = map.raw_buf.len as u16;

    let v_begin = map.raw_buf.len as u16;
    map.raw_buf.append(trimmed);
    let v_end = map.raw_buf.len as u16;

    let wk_id = classify_well_known_header(name);
    let flags = http_internal::well_known_header_flags(wk_id, name);
    let hname = hash_header_name(name);

    let contains_comma = trimmed.contains_byte(',');
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

    http_internal::link_header_entry_stack(map, wk_id, name, hname, new_idx);
    map.entries.push(entry);
    map.header_contains_comma.push(contains_comma);
    return true;
}

fn append_header(map: HeaderMap&, name: const u8[:], value: const u8[:]) -> bool {
    let valid_name = is_valid_header_name(name) || is_valid_header_name_h2(name);
    guard valid_name && is_valid_header_value(value) else { return false; }
    return append_validated_header(map, name, value.trim_lws());
}

const SLOT_CONTENT_TYPE:     u8 = 1;  // WellKnownHeader.ContentType
const SLOT_CONTENT_ENCODING: u8 = 4;  // WellKnownHeader.ContentEncoding
const SLOT_ETAG:             u8 = 25; // WellKnownHeader.ETag
const SLOT_VARY:             u8 = 34; // WellKnownHeader.Vary
const SLOT_HSTS:             u8 = 46; // WellKnownHeader.StrictTransportSecurity

const HASH_HDR_CONTENT_ENCODING: u32 = 0x03E2ED88; // "content-encoding"
const HASH_HDR_ETAG:             u32 = 0x06C857C0; // "etag"
const HASH_HDR_SERVER_TIMING:    u32 = 0x9BBE871F; // "server-timing"
const HASH_HDR_X_MATCHED_ROUTE:  u32 = 0x40F015F2; // "x-matched-route"

fn append_known_pipeline_header(
    map:            HeaderMap&,
    name:           const u8[:],
    val:            const u8[:],
    slot:           u8,
    flags:          u8,
    hname:          u32,
    contains_comma: bool,
) -> bool {
    let needed = core::add_sat_i64(name.len, val.len);
    guard map.entries.len < 128 && core::add_sat_i64(map.raw_buf.len, needed) <= 8192 else {
        return false;
    }
    if slot < 64 && map.inline_slots[slot as i64] != 0xFF {
        return false;
    }
    let n_begin = map.raw_buf.len as u16;
    map.raw_buf.append(name);
    let n_end = map.raw_buf.len as u16;
    map.raw_buf.append(val);
    let v_end = map.raw_buf.len as u16;
    let new_idx = map.entries.len as u8;
    if slot < 64 {
        map.inline_slots[slot as i64] = new_idx;
    }
    map.entries.push(HeaderEntry {
        name_begin:    n_begin,
        name_end:      n_end,
        values_begin:  n_end,
        values_end:    v_end,
        next_idx:      0xFF,
        flags:         flags,
        well_known_id: slot,
        reserved:      0,
        name_hash:     hname,
    });
    map.header_contains_comma.push(contains_comma);
    return true;
}

inline fn update_single_vary_value(map: HeaderMap&, new_val: const u8[:]) -> bool {
    let v_idx = map.inline_slots[SLOT_VARY as i64] as i64;
    guard v_idx < map.entries.len && map.entries[v_idx].next_idx == 0xFF else { return false; }
    guard core::add_sat_i64(map.raw_buf.len, new_val.len) <= 8192 else { return false; }
    let new_v_begin = map.raw_buf.len as u16;
    map.raw_buf.append(new_val);
    map.entries[v_idx].values_begin = new_v_begin;
    map.entries[v_idx].values_end = map.raw_buf.len as u16;
    map.entries[v_idx].flags |= HEADER_FLAG_CONTAINS_COMMA;
    map.header_contains_comma[v_idx] = true;
    return true;
}

fn entry_name(map: const HeaderMap&, entry: const HeaderEntry&) -> const u8[:] {
    guard entry.reserved == HEADER_SRC_STACK && entry.name_end <= map.raw_buf.len else { return ""; }
    return map.raw_buf[entry.name_begin..entry.name_end];
}

fn entry_value(map: const HeaderMap&, entry: const HeaderEntry&) -> const u8[:] {
    guard entry.reserved == HEADER_SRC_STACK && entry.values_end <= map.raw_buf.len else { return ""; }
    return map.raw_buf[entry.values_begin..entry.values_end];
}

fn clear(map: HeaderMap&) {
    reset_for_keep_alive(map);
}

fn find_header(map: const HeaderMap&, name: const u8[:]) -> const u8[:] {
    guard name.len > 0 else { return ""; }
    return get_header(map, name);
}

fn find_header_index(map: const HeaderMap&, name: const u8[:]) -> i64 {
    return http_internal::find_first_header_index(map, "", name);
}

fn shift_raw_buf_left(map: HeaderMap&, from_offset: u16, delta: u16) {
    guard delta > 0 else { return; }
    let start = from_offset as i64;
    let d = delta as i64;
    let total = map.raw_buf.len;
    var pos = start;
    while pos < total {
        map.raw_buf[pos - d] = map.raw_buf[pos];
        pos += 1;
    }
    var popped: i64 = 0;
    while popped < d && map.raw_buf.len > 0 {
        map.raw_buf.pop();
        popped += 1;
    }
    for i in map.entries.len {
        if map.entries[i].reserved == HEADER_SRC_STACK {
            if map.entries[i].name_begin >= from_offset {
                map.entries[i].name_begin -= delta;
                map.entries[i].name_end -= delta;
            }
            if map.entries[i].values_begin >= from_offset {
                map.entries[i].values_begin -= delta;
                map.entries[i].values_end -= delta;
            }
        }
    }
}

fn insert_header(map: HeaderMap&, name: const u8[:], value: const u8[:]) -> bool {
    let valid_name = is_valid_header_name(name) || is_valid_header_name_h2(name);
    guard valid_name && is_valid_header_value(value) else { return false; }
    let trimmed = value.trim_lws();
    if http_internal::try_overwrite_single_header_in_place(map, name, trimmed, false) {
        return true;
    }
    guard http_internal::can_insert_header(map, name, value) else { return false; }

    if map.has_header(name) {
        map.remove_header(name);
    }
    return map.append_header(name, value);
}

fn set_or_replace(map: HeaderMap&, name: const u8[:], value: const u8[:], is_sensitive: bool = false) -> bool {
    let valid_name = is_valid_header_name(name) || is_valid_header_name_h2(name);
    guard valid_name && is_valid_header_value(value) else { return false; }
    let trimmed = value.trim_lws();
    if http_internal::try_overwrite_single_header_in_place(map, name, trimmed, is_sensitive) {
        return true;
    }
    guard http_internal::can_insert_header(map, name, value) else { return false; }
    if map.has_header(name) {
        map.remove_header(name);
    }
    let ok = map.append_header(name, value);
    if ok && (is_sensitive || is_heuristic_sensitive_header(name)) && map.entries.len > 0 {
        map.entries[map.entries.len - 1].flags |= HEADER_FLAG_SENSITIVE;
    }
    return ok;
}

fn set_header(map: HeaderMap&, name: const u8[:], value: const u8[:], is_sensitive: bool = false) {
    if !http_internal::needs_header_byte_sanitization(name) && !http_internal::needs_header_byte_sanitization(value) {
        guard name.len > 0 else { return; }
        let cname = name[..min(name.len, 128)];
        let cval = value[..min(value.len, 4096)];
        let _ = set_or_replace(map, cname, cval, is_sensitive);
        return;
    }
    var clean_name: u8[..128]  = [];
    var clean_val:  u8[..4096] = [];
    sanitize_header_bytes(name, clean_name);
    sanitize_header_bytes(value, clean_val);
    guard clean_name.len > 0 else { return; }
    let _ = set_or_replace(map, clean_name[..], clean_val[..], is_sensitive);
}

fn set_inline(map: HeaderMap&, id: WellKnownHeader, value: const u8[:]) -> bool {
    guard id != WellKnownHeader.Unknown else { return false; }
    let name = http_internal::well_known_header_name(id);
    return map.insert_header(name, value);
}

fn compact_kept_entry_in_place(map: HeaderMap&, read_i: i64, write_entry_i: i64&, write_raw_pos: u16&) {
    var e = map.entries[read_i];
    let has_comma = map.header_contains_comma[read_i];
    if e.reserved == HEADER_SRC_STACK && e.values_end <= map.raw_buf.len {
        let n_len = e.name_end - e.name_begin;
        let v_len = e.values_end - e.values_begin;
        let old_n_begin = e.name_begin;
        let old_v_begin = e.values_begin;
        let new_n_begin = write_raw_pos;
        if new_n_begin != old_n_begin {
            for k in (n_len as i64) {
                map.raw_buf[new_n_begin + k] = map.raw_buf[old_n_begin + k];
            }
        }
        let new_n_end = new_n_begin + n_len;
        if new_n_end != old_v_begin {
            for k in (v_len as i64) {
                map.raw_buf[new_n_end + k] = map.raw_buf[old_v_begin + k];
            }
        }
        let new_v_end = new_n_end + v_len;
        write_raw_pos = new_v_end;
        e.name_begin = new_n_begin;
        e.name_end = new_n_end;
        e.values_begin = new_n_end;
        e.values_end = new_v_end;
    }
    e.next_idx = 0xFF;
    map.entries[write_entry_i] = e;
    map.header_contains_comma[write_entry_i] = has_comma;
    write_entry_i += 1;
}

fn finish_in_place_compaction(map: HeaderMap&, write_entry_i: i64, write_raw_pos: u16) {
    while map.entries.len > write_entry_i {
        map.entries.pop();
    }
    while map.header_contains_comma.len > write_entry_i {
        map.header_contains_comma.pop();
    }
    let target_raw_len = write_raw_pos as i64;
    while map.raw_buf.len > target_raw_len {
        map.raw_buf.pop();
    }
    http_internal::rebuild_inline_slots_and_chains(map);
}

fn remove_header(map: HeaderMap&, name: const u8[:]) -> bool {
    var found = false;
    var write_entry_i: i64 = 0;
    var write_raw_pos: u16 = 0;
    let total_entries = map.entries.len;

    for read_i in total_entries {
        let e .= map.entries[read_i];
        var is_match = false;
        if e.reserved == HEADER_SRC_STACK && e.name_end <= map.raw_buf.len {
            is_match = map.raw_buf[e.name_begin..e.name_end].eq_ascii_fold(name);
        }
        if is_match {
            found = true;
            continue;
        }
        compact_kept_entry_in_place(map, read_i, write_entry_i, write_raw_pos);
    }

    if found {
        finish_in_place_compaction(map, write_entry_i, write_raw_pos);
    }
    return found;
}

fn remove_header_by_name(map: HeaderMap&, target_name: const u8[:]) -> bool {
    guard target_name.len > 0 else { return false; }
    return remove_header(map, target_name);
}

fn copy_headers(src: const HeaderMap&, dst: HeaderMap&) {
    dst.reset_for_keep_alive();
    for &e in src.entries {
        let name = entry_name(src, e);
        let val = entry_value(src, e);
        if name.len > 0 {
            let ok = dst.append_header(name, val);
            if ok && (e.flags & HEADER_FLAG_SENSITIVE) != 0 && dst.entries.len > 0 {
                dst.entries[dst.entries.len - 1].flags |= HEADER_FLAG_SENSITIVE;
            }
        }
    }
}

fn append_all_headers(src: const HeaderMap&, dst: HeaderMap&) {
    for &e in src.entries {
        let name = entry_name(src, e);
        let val = entry_value(src, e);
        if name.len > 0 {
            let ok = dst.append_header(name, val);
            if ok && (e.flags & HEADER_FLAG_SENSITIVE) != 0 && dst.entries.len > 0 {
                dst.entries[dst.entries.len - 1].flags |= HEADER_FLAG_SENSITIVE;
            }
        }
    }
}

fn remove_sensitive_headers(map: HeaderMap&) {
    var found = false;
    var write_entry_i: i64 = 0;
    var write_raw_pos: u16 = 0;
    let total_entries = map.entries.len;

    for read_i in total_entries {
        let e .= map.entries[read_i];
        var is_sens = (e.flags & HEADER_FLAG_SENSITIVE) != 0;
        if !is_sens && e.reserved == HEADER_SRC_STACK && e.name_end <= map.raw_buf.len {
            is_sens = is_heuristic_sensitive_header(map.raw_buf[e.name_begin..e.name_end]);
        }
        if is_sens {
            found = true;
            continue;
        }
        compact_kept_entry_in_place(map, read_i, write_entry_i, write_raw_pos);
    }

    if found {
        finish_in_place_compaction(map, write_entry_i, write_raw_pos);
    }
}

// RFC 9110 Section 5.3 comma combining. BLOCKS Set-Cookie & NO_COMMA_FOLD headers.
fn get_combined<B>(map: const HeaderMap&, name: const u8[:], out: B&, max_out_len: i64 = 8192) -> bool {
    let wk_id = classify_well_known_header(name);
    let flags = http_internal::well_known_header_flags(wk_id, name);
    guard (flags & HEADER_FLAG_NO_COMMA_FOLD) == 0 else {
        // Absolute RFC 9110 Section 5.3 / RFC 6265bis prohibition on folding Set-Cookie
        out.clear();
        return false;
    }

    out.clear();
    var committed = false;
    defer if !committed { out.clear(); };

    var first = true;
    var found = false;
    let hname = hash_header_name(name);
    // RFC 9113 Section 8.2.3: Compressing the Cookie Header Field - Join multiple Cookie fields with "; "
    let sep_ch: u8 = if name.eq_ascii_fold("cookie") { ';' } else { ',' };

    for &entry in map.entries {
        guard entry.name_hash == hname else { continue; }
        let entry_name = map.raw_buf[entry.name_begin..entry.name_end];
        guard entry_name.eq_ascii_fold(name) else { continue; }
        found = true;
        if !first {
            guard out.len + 2 <= max_out_len else { out.clear(); return false; }
            out.push(sep_ch);
            out.push(' ');
        }
        first = false;
        let val = map.raw_buf[entry.values_begin..entry.values_end];
        guard out.len + val.len <= max_out_len else { out.clear(); return false; }
        out.append(val);
    }
    committed = found;
    return found;
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
        http_internal::find_first_header_index(map, raw, name)
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
            if entry_name.eq_ascii_fold(name) {
                let val = map.raw_buf[entry.values_begin..entry.values_end];
                var item: u8[..256] = [];
                let v_len = min(val.len, item.cap);
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
            if entry_name.eq_ascii_fold(name) {
                let val = http_internal::resolve_entry_value(entry, map, arena);
                var item: u8[..256] = [];
                let v_len = min(val.len, item.cap);
                item.append(val[..v_len]);
                out_values.push(item);
            }
        }
    }
    for &entry in arena.spill_entries {
        if entry.name_hash == hname {
            let entry_name = resolve_entry_name(entry, map, arena);
            if entry_name.eq_ascii_fold(name) {
                let val = http_internal::resolve_entry_value(entry, map, arena);
                var item: u8[..256] = [];
                let v_len = min(val.len, item.cap);
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
        let copy_len = min(val.len, cookie_str.cap);
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
        let val = http_internal::resolve_entry_value(entry, map, arena);
        out.append(name);
        out.push(':');
        out.push(' ');
        out.append(val);
        out.push(0);
    }
    for &entry in arena.spill_entries {
        let name = resolve_entry_name(entry, map, arena);
        let val = http_internal::resolve_entry_value(entry, map, arena);
        out.append(name);
        out.push(':');
        out.push(' ');
        out.append(val);
        out.push(0);
    }
    out.push(0);
}

// Wire serialization with RFC 9110 comma folding for list fields and separate lines for Set-Cookie
fn serialize_headers(map: const HeaderMap&, out: u8[>..]&) {
    var visited: bool[128] = [false; 128];

    for i in map.entries.len {
        if visited[i] { continue; }

        let entry .= map.entries[i];
        let name = map.raw_buf[entry.name_begin..entry.name_end];

        if http_internal::has_no_comma_fold(entry) {
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
            http_internal::append_folded_header_values(map, i, entry, name, visited, out);
            out.append("\r\n");
        }
    }
}

// ---- chromium 304 not modified merge & cache persistence --------------------

// Merges fresh headers from a 304 Not Modified response into cached headers
fn merge_with_headers_304(cached_headers: HeaderMap&, response_304: const HeaderMap&) {
    for &entry in response_304.entries {
        let name = response_304.raw_buf[entry.name_begin..entry.name_end];
        let val = response_304.raw_buf[entry.values_begin..entry.values_end];
        let invalid = http_internal::has_embedded_nulls(name) ||
            http_internal::has_embedded_nulls(val) || !is_valid_header_value(val);
        if invalid {
            continue;
        }
        if http_internal::should_update_header_304(entry.flags, name) && cached_headers.has_header(name) {
            cached_headers.remove_header(name);
        }
    }
    for &entry in response_304.entries {
        let name = response_304.raw_buf[entry.name_begin..entry.name_end];
        let val = response_304.raw_buf[entry.values_begin..entry.values_end];
        let invalid = http_internal::has_embedded_nulls(name) ||
            http_internal::has_embedded_nulls(val) || !is_valid_header_value(val);
        if invalid {
            continue;
        }
        if http_internal::should_update_header_304(entry.flags, name) {
            cached_headers.append_header(name, val);
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

        let ok = dst.append_header(name, val);
        if ok && (entry.flags & HEADER_FLAG_SENSITIVE) != 0 && dst.entries.len > 0 {
            dst.entries[dst.entries.len - 1].flags |= HEADER_FLAG_SENSITIVE;
        }
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
    if name.eq_ascii_fold("proxy-connection") {
        return true;
    }
    return false;
}

fn collect_connection_tokens(src: const HeaderMap&, out_tokens: u8[..64][..32]&) {
    for &entry in src.entries {
        let name = src.raw_buf[entry.name_begin..entry.name_end];
        guard name.eq_ascii_fold("connection") else { continue; }

        let val = src.raw_buf[entry.values_begin..entry.values_end];
        var tok = core::make_byte_tokenizer(val, ',');
        while true {
            let raw_tok, ok = core::token_next(tok);
            guard ok else { break; }
            let token = raw_tok.trim_lws();
            let is_valid_token = token.len > 0 &&
                !is_hop_by_hop_header_name(token) &&
                !token.eq_ascii_fold("close");
            guard is_valid_token else { continue; }
            var tok_buf: u8[..64] = [];
            guard tok_buf.try_set(token) && out_tokens.try_push(tok_buf) else { continue; }
        }
    }
}

fn is_token_in_connection_header_map(src: const HeaderMap&, target_name: const u8[:]) -> bool {
    for &entry in src.entries {
        let name = src.raw_buf[entry.name_begin..entry.name_end];
        guard name.eq_ascii_fold("connection") else { continue; }

        let val = src.raw_buf[entry.values_begin..entry.values_end];
        var tok = core::make_byte_tokenizer(val, ',');
        while true {
            let raw_tok, ok = core::token_next(tok);
            guard ok else { break; }
            let token = raw_tok.trim_lws();
            if token.len > 0 && token.eq_ascii_fold(target_name) {
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
            if name.eq_ascii_fold("te") && val.trim_lws().eq_ascii_fold("trailers") {
                dst.append_header(name, val);
            }
            continue;
        }

        if is_token_in_connection_header_map(src, name) {
            continue;
        }

        let ok = dst.append_header(name, val);
        if ok && (entry.flags & HEADER_FLAG_SENSITIVE) != 0 && dst.entries.len > 0 {
            dst.entries[dst.entries.len - 1].flags |= HEADER_FLAG_SENSITIVE;
        }
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
    let start_pos:  i64 = min(resume_pos, raw.len - 4);
    let rel = core::fast_find_crlfcrlf(raw[start_pos..]);
    if rel >= 0 {
        let end_offset = start_pos + rel + 4;
        cursor = end_offset;
        return end_offset, true;
    }
    cursor = raw.len - 3;
    return 0, false;
}
