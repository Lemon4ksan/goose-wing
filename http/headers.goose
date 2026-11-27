// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP header parsing and storage (RFC 9110, RFC 9112).
// Stores names and values as offset slices into a contiguous buffer with
// dedicated lookup slots for frequent standard headers.
namespace http;

import std;
import core;
import rfc.http;
import .headers.lexical;
import .headers.perfect_hash;
import http.headers.wire_internal;
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
checkfree inline fn name_slice(s: HeaderSpan, raw: const u8[:]) -> const u8[:] {
    let start: i64 = s.name_pos;
    let end:   i64 = start + s.name_len;
    if start < 0 || start > end || end > raw.len { return ""; }
    return raw[start..end];
}

// Extracts zero-copy header value slice from backing buffer.
checkfree inline fn val_slice(s: HeaderSpan, raw: const u8[:]) -> const u8[:] {
    let start: i64 = s.val_pos;
    let end:   i64 = start + s.val_len;
    if start < 0 || start > end || end > raw.len { return ""; }
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
checkfree fn sanitize_header_bytes<B>(src: const u8[:], out: B&) {
    for b in src {
        if b != '\r' && b != '\n' && b != 0 {
            guard out.len < out.cap else { return; }
            out.push(b);
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

checkfree fn clear(bf: HeaderBloomFilter&) {
    bf.bits = [0; 4];
}

checkfree fn is_empty(bf: const HeaderBloomFilter&) -> bool {
    return (bf.bits[0] | bf.bits[1] | bf.bits[2] | bf.bits[3]) == 0;
}

checkfree fn add_header(bf: HeaderBloomFilter&, key: const u8[:]) {
    guard key.len >= 2 else { return; }
    let h = http_internal::bloom_hash(key);
    for i in 4 {
        let p = ((h >> ((i * 8) as u32)) & 0xFF) as i64;
        bf.bits[(p >> 6) & 3] |= (1 as u64) << (p & 63);
    }
}

checkfree fn might_have_header(bf: const HeaderBloomFilter&, key: const u8[:]) -> bool {
    guard key.len >= 2 else { return true; }
    let h = http_internal::bloom_hash(key);
    for i in 4 {
        let p = ((h >> ((i * 8) as u32)) & 0xFF) as i64;
        guard (bf.bits[(p >> 6) & 3] & ((1 as u64) << (p & 63))) != 0 else { return false; }
    }
    return true;
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

// Hard ceilings for OverflowArena spill storage (prevents untrusted header/URL DoS).
const MAX_OVERFLOW_RAW_BYTES:     i64 = 65535;
const MAX_OVERFLOW_SPILL_ENTRIES: i64 = 512;
const MAX_OVERFLOW_URL_BYTES:     i64 = 65535;

// Storage root for oversized HTTP headers and URLs that exceed fixed stack limits.
// Allocated once per connection/session driver on the data stack.
root struct OverflowArena {
    spill_raw:     u8[>..]          = [],
    spill_entries: HeaderEntry[>..] = [],
    spill_url:     u8[>..]          = [],
}

let EMPTY_OVERFLOW_ARENA: OverflowArena = OverflowArena { .. };

// Clears and zeroizes all overflow spill buffers while preserving capacity for reuse.
fn reset_overflow_arena(arena: OverflowArena&) {
    if arena.spill_raw.len > 0 {
        core::secure_zeroize_slice(arena.spill_raw[..]);
    }
    arena.spill_raw.clear();
    arena.spill_entries.clear();
    if arena.spill_url.len > 0 {
        core::secure_zeroize_slice(arena.spill_url[..]);
    }
    arena.spill_url.clear();
}

// Parses an oversized URL up to MAX_OVERFLOW_URL_BYTES using the arena's spill_url storage.
//
// Example:
//   raw_input = "https://example.com/long?token=...", arena = OverflowArena { .. }
//   returns: view.host = "example.com", view.valid = true, err = None
fn parse_url_with_overflow(raw_input: const u8[:], arena: OverflowArena&) -> core::UrlView, core::UrlParseError {
    arena.spill_url.clear();
    guard raw_input.len <= MAX_OVERFLOW_URL_BYTES else {
        return core::UrlView { .. }, core::UrlParseError.InputTooLong;
    }
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

checkfree fn is_ok(err: HeaderParseError) -> bool {
    return err == HeaderParseError.None;
}

// Go #79346 log/error control-char injection defense: Sanitize untrusted user input
// before formatting into error strings or logs.
// Replaces control characters (< 0x20, CR, LF, DEL) and non-printable bytes with safe visual representation '?'.
//
// Example:
//   input = "bad\x00input\r\n", out = []
//   out becomes "bad?input??"
checkfree fn sanitize_untrusted_for_error<B>(input: const u8[:], out: B&) {
    out.clear();
    for b in input {
        let ch: u8 = if b >= 0x20 && b <= 0x7E && b != '\\' && b != '"' { b } else { '?' };
        guard out.len < out.cap else { return; }
        out.push(ch);
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

checkfree fn well_known_to_slot(id: WellKnownHeader) -> i64 {
    var idx: i64 = 0;
    const for <N, V> in variants<WellKnownHeader> {
        let v: WellKnownHeader = default<V>();
        if id == v { return idx; }
        idx += 1;
    }
    return 63;
}

checkfree fn slot_to_well_known(slot: i64) -> WellKnownHeader {
    var idx: i64 = 0;
    const for <N, V> in variants<WellKnownHeader> {
        if slot == idx { return default<V>(); }
        idx += 1;
    }
    return WellKnownHeader.Unknown;
}

const WELL_KNOWN_HEADER_NAMES: const u8[:][63] = [
    "host", "content-type", "content-length", "content-disposition",
    "content-encoding", "content-language", "content-location", "content-range",
    "accept", "accept-charset", "accept-encoding", "accept-language",
    "accept-ranges", "authorization", "proxy-authorization", "www-authenticate",
    "proxy-authenticate", "cookie", "set-cookie", "set-cookie2",
    "clear-site-data", "cache-control", "age", "expires", "date", "etag",
    "if-match", "if-none-match", "if-modified-since", "if-unmodified-since",
    "if-range", "last-modified", "location", "range", "vary", "via",
    "connection", "keep-alive", "transfer-encoding", "te", "trailer",
    "upgrade", "user-agent", "server", "referer", "origin",
    "strict-transport-security", "content-security-policy",
    "x-content-type-options", "x-frame-options", "x-webkit-csp",
    "access-control-allow-origin", "access-control-allow-credentials",
    "access-control-allow-headers", "access-control-allow-methods",
    "access-control-expose-headers", "access-control-max-age",
    "access-control-request-headers", "access-control-request-method",
    "alt-svc", "retry-after", "priority", "expect",
];

fn classify_well_known_header(name: const u8[:]) -> WellKnownHeader {
    let len = name.len;
    guard len >= 2 && len <= 32 && is_valid_header_name(name) else { return WellKnownHeader.Unknown; }
    let b0 = core::to_lower_ascii_byte(name[0]);
    for i in 63 {
        let cand = WELL_KNOWN_HEADER_NAMES[i];
        if cand.len == len && cand[0] == b0 && name.eq_ascii_fold(cand) {
            return slot_to_well_known(i);
        }
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

let EMPTY_HEADER_ENTRY: HeaderEntry = HeaderEntry { .. };
const EMPTY_HEADER_ENTRY_ARR: const HeaderEntry[1] = [HeaderEntry { .. }];

// Zero-copy read-only view over contiguous header entries and backing byte slice.
struct HeaderView {
    entries: const HeaderEntry[:] = EMPTY_HEADER_ENTRY_ARR[..0],
    raw:     const u8[:]          = "",
}

checkfree fn is_continuation(entry: const HeaderEntry&) -> bool {
    return (entry.flags & HEADER_FLAG_CONTINUATION) != 0 || entry.name_begin == entry.name_end;
}

checkfree fn is_sensitive(entry: const HeaderEntry&) -> bool {
    return (entry.flags & HEADER_FLAG_SENSITIVE) != 0;
}

checkfree fn is_cookie_state(entry: const HeaderEntry&) -> bool {
    return (entry.flags & HEADER_FLAG_COOKIE_STATE) != 0;
}

checkfree fn is_challenge(entry: const HeaderEntry&) -> bool {
    return (entry.flags & HEADER_FLAG_CHALLENGE) != 0;
}

checkfree fn is_security_state(entry: const HeaderEntry&) -> bool {
    return (entry.flags & HEADER_FLAG_SECURITY_STATE) != 0;
}

checkfree fn is_non_cacheable(entry: const HeaderEntry&) -> bool {
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

checkfree fn reset_for_keep_alive(map: HeaderMap&) {
    if map.entries.len > 0 && map.entries.len < 32 {
        for &e in map.entries {
            if e.well_known_id < 64 {
                map.inline_slots[(e.well_known_id & 63) as i64] = 0xFF;
            }
        }
    } else if map.entries.len >= 32 {
        map.inline_slots = [0xFF; 64];
    }
    map.raw_buf.clear();
    map.entries.clear();
    map.header_contains_comma.clear();
    map.status_code = rfc::STATUS_OK;
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
    var entry = if in_spill {
        arena.spill_entries[arena.spill_entries.len - 1]
    } else {
        map.entries[map.entries.len - 1]
    };
    let orig_name = entry_name_spill(map, arena, entry);
    let orig_val = entry_value_spill(map, arena, entry);
    let migrate_name = entry.reserved != HEADER_SRC_ARENA;
    let needed = (if migrate_name { orig_name.len } else { 0 }) + orig_val.len + 1 + trimmed_continuation.len;
    guard (arena.spill_raw.len + needed) <= 65535 else {
        map.valid = false;
        return HeaderParseError.CapacityExceeded;
    }

    let saved_spill_len = arena.spill_raw.len;
    if migrate_name {
        entry.name_begin = arena.spill_raw.len as u16;
        arena.spill_raw.append(orig_name);
        entry.name_end = arena.spill_raw.len as u16;
    }

    entry.values_begin = arena.spill_raw.len as u16;
    arena.spill_raw.append(orig_val);
    arena.spill_raw.push(' ');
    arena.spill_raw.append(trimmed_continuation);
    entry.values_end = arena.spill_raw.len as u16;

    guard http_internal::validate_folded_framing(
        arena.spill_raw[..], entry.values_begin, entry.values_end, entry.well_known_id,
    ) else {
        arena.spill_raw.resize(saved_spill_len);
        map.valid = false;
        return HeaderParseError.InvalidContentLength;
    }

    let cont_has_comma = trimmed_continuation.contains_byte(',');
    entry.reserved = HEADER_SRC_ARENA;
    if cont_has_comma {
        entry.flags |= HEADER_FLAG_CONTAINS_COMMA;
    }
    if in_spill {
        arena.spill_entries[arena.spill_entries.len - 1] = entry;
    } else {
        let m_idx = map.entries.len - 1;
        map.entries[m_idx] = entry;
        if cont_has_comma {
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
    guard raw_input.len > 0 else {
        return HeaderParseError.EmptyInput;
    }
    if http_internal::has_embedded_nulls(raw_input) {
        return HeaderParseError.EmbeddedNull;
    }
    return http_internal::parse_headers_body_validated(raw_input, map, allow_obs_fold, mode);
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
    reset_overflow_arena(arena);
    map.valid = false;
    defer if !map.valid {
        reset_for_keep_alive(map);
        reset_overflow_arena(arena);
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

    let total = raw_input.len;
    var line_end: i64 = 0;
    while line_end < total && raw_input[line_end] != '\r' && raw_input[line_end] != '\n' {
        line_end += 1;
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

    let err = http_internal::parse_headers_body_validated(raw_input[header_start..], map, allow_obs_fold, mode);
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
    reset_overflow_arena(arena);
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
    guard advance_crlf(raw_input, header_start, line_end) else {
        return HeaderParseError.MalformedStatusLine;
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
    guard raw_input.len > 0 else { return HeaderParseError.EmptyInput; }
    if http_internal::has_embedded_nulls(raw_input) { return HeaderParseError.EmbeddedNull; }

    var line_end = http_internal::skip_single_preamble_empty_line(raw_input);
    while line_end < raw_input.len && raw_input[line_end] != '\r' && raw_input[line_end] != '\n' {
        line_end++;
    }

    var header_start = line_end;
    guard advance_crlf(raw_input, header_start, line_end) else {
        return HeaderParseError.MalformedStatusLine;
    }

    return http_internal::parse_headers_body_validated(
        raw_input[header_start..], map, allow_obs_fold, H1ResponseParseMode.Strict,
    );
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
    reset_overflow_arena(arena);
    map.valid = false;
    guard raw_input.len > 0 else { return HeaderParseError.EmptyInput; }
    if http_internal::has_embedded_nulls(raw_input) { return HeaderParseError.EmbeddedNull; }

    var line_end = http_internal::skip_single_preamble_empty_line(raw_input);
    while line_end < raw_input.len && raw_input[line_end] != '\r' && raw_input[line_end] != '\n' {
        line_end++;
    }

    var header_start = line_end;
    guard advance_crlf(raw_input, header_start, line_end) else {
        return HeaderParseError.MalformedStatusLine;
    }

    return parse_headers_with_overflow(raw_input[header_start..], map, arena, allow_obs_fold);
}

// ---- headermap accessors & mutations ---------------------------------------

fn has_header(map: const HeaderMap&, name: const u8[:]) -> bool {
    let wk_id = classify_well_known_header(name);
    if wk_id != WellKnownHeader.Unknown {
        let slot = well_known_to_slot(wk_id);
        let idx = map.inline_slots[slot];
        guard idx != 0xFF && idx < map.entries.len else { return false; }
        return map.entries[idx as i64].reserved == HEADER_SRC_STACK;
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
        if idx != 0xFF && idx < map.entries.len {
            let entry .= map.entries[idx as i64];
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

checkfree inline fn resolve_entry_name_buf(
    stack_raw: const u8[:],
    spill_raw: const u8[:],
    entry:     const HeaderEntry&,
) -> const u8[:] {
    let b: i64 = entry.name_begin;
    let e: i64 = entry.name_end;
    if entry.reserved == HEADER_SRC_ARENA {
        guard b >= 0 && b <= e && e <= spill_raw.len else { return ""; }
        return spill_raw[b..e];
    }
    guard b >= 0 && b <= e && e <= stack_raw.len else { return ""; }
    return stack_raw[b..e];
}

checkfree inline fn resolve_entry_value_buf(
    stack_raw: const u8[:],
    spill_raw: const u8[:],
    entry:     const HeaderEntry&,
) -> const u8[:] {
    let b: i64 = entry.values_begin;
    let e: i64 = entry.values_end;
    if entry.reserved == HEADER_SRC_ARENA {
        guard b >= 0 && b <= e && e <= spill_raw.len else { return ""; }
        return spill_raw[b..e];
    }
    guard b >= 0 && b <= e && e <= stack_raw.len else { return ""; }
    return stack_raw[b..e];
}

checkfree fn entry_name_spill(
    map:   const HeaderMap&,
    arena: const OverflowArena&,
    entry: const HeaderEntry&,
) -> const u8[:] {
    return resolve_entry_name_buf(map.raw_buf[..], arena.spill_raw[..], entry);
}

checkfree fn entry_value_spill(
    map:   const HeaderMap&,
    arena: const OverflowArena&,
    entry: const HeaderEntry&,
) -> const u8[:] {
    return resolve_entry_value_buf(map.raw_buf[..], arena.spill_raw[..], entry);
}

checkfree fn header_count_spill(map: const HeaderMap&, arena: const OverflowArena&) -> i64 {
    return core::add_sat_i64(map.entries.len, arena.spill_entries.len);
}

checkfree fn header_entry_at_spill(
    map:   const HeaderMap&,
    arena: const OverflowArena&,
    idx:   i64,
) -> const HeaderEntry&, bool {
    guard idx >= 0 else { return EMPTY_HEADER_ENTRY, false; }
    let stack_len = map.entries.len;
    if idx < stack_len {
        return map.entries[idx], true;
    }
    let spill_idx = core::sub_sat_i64(idx, stack_len);
    guard spill_idx >= 0 && spill_idx < arena.spill_entries.len else { return EMPTY_HEADER_ENTRY, false; }
    return arena.spill_entries[spill_idx], true;
}

checkfree fn header_view_name(v: const HeaderView&, entry: const HeaderEntry&) -> const u8[:] {
    let b: i64 = entry.name_begin;
    let e: i64 = entry.name_end;
    guard b >= 0 && b <= e && e <= v.raw.len else { return ""; }
    return v.raw[b..e];
}

checkfree fn header_view_value(v: const HeaderView&, entry: const HeaderEntry&) -> const u8[:] {
    let b: i64 = entry.values_begin;
    let e: i64 = entry.values_end;
    guard b >= 0 && b <= e && e <= v.raw.len else { return ""; }
    return v.raw[b..e];
}

fn header_view_get(v: const HeaderView&, name: const u8[:]) -> const u8[:], bool {
    guard name.len > 0 else { return "", false; }
    let hname = hash_header_name(name);
    for &entry in v.entries {
        guard entry.name_hash == hname || entry.name_hash == 0 else { continue; }
        if header_view_name(v, entry).eq_ascii_fold(name) {
            return header_view_value(v, entry), true;
        }
    }
    return "", false;
}

fn header_view_copy_to_spill(
    v:         const HeaderView&,
    out_map:   HeaderMap&,
    out_arena: OverflowArena&,
) -> bool {
    reset_for_keep_alive(out_map);
    reset_overflow_arena(out_arena);
    var committed = false;
    defer if !committed {
        reset_for_keep_alive(out_map);
        reset_overflow_arena(out_arena);
    };
    for &entry in v.entries {
        let nb: i64 = entry.name_begin;
        let ne: i64 = entry.name_end;
        let vb: i64 = entry.values_begin;
        let ve: i64 = entry.values_end;
        guard nb >= 0 && nb <= ne && ne <= v.raw.len else { return false; }
        guard vb >= 0 && vb <= ve && ve <= v.raw.len else { return false; }
        guard append_header_spill(
            out_map, out_arena, v.raw[nb..ne], v.raw[vb..ve], entry.flags & HEADER_FLAG_SENSITIVE,
        ) else {
            return false;
        }
    }
    out_map.valid = true;
    committed = true;
    return true;
}

fn entries_have_header_name(
    entries:   const HeaderEntry[:],
    stack_raw: const u8[:],
    spill_raw: const u8[:],
    name:      const u8[:],
    hname:     u32,
) -> bool {
    for &entry in entries {
        if entry.name_hash == hname && resolve_entry_name_buf(stack_raw, spill_raw, entry).eq_ascii_fold(name) {
            return true;
        }
    }
    return false;
}

fn get_header_slices(
    map:           const HeaderMap&,
    spill_entries: const HeaderEntry[:],
    spill_raw:     const u8[:],
    name:          const u8[:],
) -> const u8[:] {
    let wk_id = classify_well_known_header(name);
    if wk_id != WellKnownHeader.Unknown {
        let slot = well_known_to_slot(wk_id);
        let idx = map.inline_slots[slot];
        if idx != 0xFF && idx < map.entries.len {
            return resolve_entry_value_buf(map.raw_buf[..], spill_raw, map.entries[idx as i64]);
        }
    }
    let hname = hash_header_name(name);
    let val1 = http_internal::find_entry_in_entries(map.entries[..], map.raw_buf[..], spill_raw, name, hname);
    if val1.len > 0 { return val1; }
    return http_internal::find_entry_in_entries(spill_entries, map.raw_buf[..], spill_raw, name, hname);
}

fn has_header_slices(
    map:           const HeaderMap&,
    spill_entries: const HeaderEntry[:],
    spill_raw:     const u8[:],
    name:          const u8[:],
) -> bool {
    let wk_id = classify_well_known_header(name);
    if wk_id != WellKnownHeader.Unknown {
        let slot = well_known_to_slot(wk_id);
        let idx = map.inline_slots[slot];
        if idx != 0xFF && idx < map.entries.len {
            return true;
        }
    }
    let hname = hash_header_name(name);
    return entries_have_header_name(map.entries[..], map.raw_buf[..], spill_raw, name, hname) ||
        entries_have_header_name(spill_entries, map.raw_buf[..], spill_raw, name, hname);
}

// Case-insensitive header lookup resolving from either stack map or arena spill storage.
fn get_header_spill(map: const HeaderMap&, arena: const OverflowArena&, name: const u8[:]) -> const u8[:] {
    return get_header_slices(map, arena.spill_entries[..], arena.spill_raw[..], name);
}

// Case-insensitive presence check for a header resolving from either stack map or arena spill storage.
fn has_header_spill(map: const HeaderMap&, arena: const OverflowArena&, name: const u8[:]) -> bool {
    return has_header_slices(map, arena.spill_entries[..], arena.spill_raw[..], name);
}

checkfree fn get_inline(map: const HeaderMap&, id: WellKnownHeader) -> const u8[:] {
    guard id != WellKnownHeader.Unknown else { return ""; }
    let slot = well_known_to_slot(id);
    guard slot >= 0 && slot < 64 else { return ""; }
    let idx = map.inline_slots[slot];
    if idx != 0xFF {
        let i: i64 = idx;
        guard i >= 0 && i < map.entries.len else { return ""; }
        let entry = map.entries[i];
        let b: i64 = entry.values_begin;
        let e: i64 = entry.values_end;
        guard entry.reserved == HEADER_SRC_STACK && b >= 0 && b <= e && e <= map.raw_buf.len else {
            return "";
        }
        return map.raw_buf[b..e];
    }
    return "";
}

fn make_header_entry(
    name:        const u8[:],
    trimmed:     const u8[:],
    n_begin:     u16,
    n_end:       u16,
    v_begin:     u16,
    v_end:       u16,
    src_type:    u8,
    extra_flags: u8,
) -> HeaderEntry, WellKnownHeader, u32 {
    let wk_id = classify_well_known_header(name);
    let flags = http_internal::well_known_header_flags(wk_id, name);
    let hname = http_internal::well_known_header_hash(wk_id, name);
    let comma_flag = if trimmed.contains_byte(',') { HEADER_FLAG_CONTAINS_COMMA } else { 0 };
    let entry_flags = flags | comma_flag | extra_flags;
    let entry = HeaderEntry {
        name_begin:    n_begin,
        name_end:      n_end,
        values_begin:  v_begin,
        values_end:    v_end,
        next_idx:      0xFF,
        flags:         entry_flags,
        well_known_id: if wk_id != WellKnownHeader.Unknown { well_known_to_slot(wk_id) as u8 } else { 0xFF },
        reserved:      src_type,
        name_hash:     hname,
    };
    return entry, wk_id, hname;
}

fn append_to_stack_raw(
    map:         HeaderMap&,
    spill_raw:   const u8[:],
    name:        const u8[:],
    trimmed:     const u8[:],
    extra_flags: u8,
) {
    let n_begin = map.raw_buf.len as u16;
    map.raw_buf.append(name);
    let n_end = map.raw_buf.len as u16;
    map.raw_buf.append(trimmed);
    let v_end = map.raw_buf.len as u16;
    let entry, wk_id, hname = make_header_entry(
        name, trimmed, n_begin, n_end, n_end, v_end, HEADER_SRC_STACK, extra_flags,
    );
    let new_idx = map.entries.len as u8;
    http_internal::link_header_entry(map, wk_id, name, hname, new_idx, spill_raw);
    map.entries.push(entry);
    map.header_contains_comma.push((entry.flags & HEADER_FLAG_CONTAINS_COMMA) != 0);
}

fn append_validated_header(map: HeaderMap&, name: const u8[:], trimmed: const u8[:]) -> bool {
    guard map.entries.len < 128 else { return false; }
    let needed = core::add_sat_i64(name.len, trimmed.len);
    guard core::add_sat_i64(map.raw_buf.len, needed) <= 8192 else { return false; }
    append_to_stack_raw(map, "", name, trimmed, 0);
    return true;
}

fn append_validated_header_spill(
    map:         HeaderMap&,
    arena:       OverflowArena&,
    name:        const u8[:],
    trimmed:     const u8[:],
    extra_flags: u8,
) -> bool {
    let needed = core::add_sat_i64(name.len, trimmed.len);
    if arena.spill_entries.len == 0 && map.entries.len < 128 && core::add_sat_i64(map.raw_buf.len, needed) <= 8192 {
        append_to_stack_raw(map, arena.spill_raw[..], name, trimmed, extra_flags);
        return true;
    }

    guard core::add_sat_i64(arena.spill_raw.len, needed) <= MAX_OVERFLOW_RAW_BYTES else {
        return false;
    }
    let use_stack_entries = arena.spill_entries.len == 0 && map.entries.len < 128;
    if !use_stack_entries {
        guard arena.spill_entries.len < MAX_OVERFLOW_SPILL_ENTRIES else { return false; }
    }

    let saved_map_entries = map.entries.len;
    let saved_spill_raw = arena.spill_raw.len;
    let saved_spill_entries = arena.spill_entries.len;
    var committed = false;
    defer if !committed {
        map.entries.resize(saved_map_entries);
        map.header_contains_comma.resize(saved_map_entries);
        arena.spill_raw.resize(saved_spill_raw);
        arena.spill_entries.resize(saved_spill_entries);
    };

    let n_begin = arena.spill_raw.len as u16;
    arena.spill_raw.append(name);
    let n_end = arena.spill_raw.len as u16;
    arena.spill_raw.append(trimmed);
    let v_end = arena.spill_raw.len as u16;
    let entry, wk_id, hname = make_header_entry(
        name, trimmed, n_begin, n_end, n_end, v_end, HEADER_SRC_ARENA, extra_flags,
    );
    if use_stack_entries {
        let new_idx = map.entries.len as u8;
        http_internal::link_header_entry(map, wk_id, name, hname, new_idx, arena.spill_raw[..]);
        map.entries.push(entry);
        map.header_contains_comma.push((entry.flags & HEADER_FLAG_CONTAINS_COMMA) != 0);
    } else {
        arena.spill_entries.push(entry);
    }
    committed = true;
    return true;
}

fn append_header(map: HeaderMap&, name: const u8[:], value: const u8[:]) -> bool {
    let valid_name = is_valid_header_name(name) || is_valid_header_name_h2(name);
    guard valid_name && is_valid_header_value(value) else { return false; }
    return append_validated_header(map, name, value.trim_lws());
}

fn append_header_spill(
    map:   HeaderMap&,
    arena: OverflowArena&,
    name:  const u8[:],
    val:   const u8[:],
    flags: u8 = 0,
) -> bool {
    let valid_name = is_valid_header_name(name) || is_valid_header_name_h2(name);
    guard valid_name && is_valid_header_value(val) else { return false; }
    return append_validated_header_spill(map, arena, name, val.trim_lws(), flags);
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

checkfree fn entry_name(map: const HeaderMap&, entry: const HeaderEntry&) -> const u8[:] {
    let b: i64 = entry.name_begin;
    let e: i64 = entry.name_end;
    guard entry.reserved == HEADER_SRC_STACK && b >= 0 && b <= e && e <= map.raw_buf.len else { return ""; }
    return map.raw_buf[b..e];
}

checkfree fn entry_value(map: const HeaderMap&, entry: const HeaderEntry&) -> const u8[:] {
    let b: i64 = entry.values_begin;
    let e: i64 = entry.values_end;
    guard entry.reserved == HEADER_SRC_STACK && b >= 0 && b <= e && e <= map.raw_buf.len else { return ""; }
    return map.raw_buf[b..e];
}

checkfree fn clear(map: HeaderMap&) {
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
    let target_len = max(total - d, 0);
    map.raw_buf.resize(target_len);
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
    http_internal::set_header_sanitized(map, name, value, is_sensitive);
}

fn set_inline(map: HeaderMap&, id: WellKnownHeader, value: const u8[:]) -> bool {
    guard id != WellKnownHeader.Unknown else { return false; }
    let name = http_internal::well_known_header_name(id);
    return map.insert_header(name, value);
}

fn compact_kept_entry_into(
    map:           HeaderMap&,
    read_i:        i64,
    write_entry_i: i64&,
    new_raw:       u8[..8192]&,
) {
    var e = map.entries[read_i];
    let has_comma = map.header_contains_comma[read_i];
    if e.reserved == HEADER_SRC_STACK && e.values_end <= map.raw_buf.len {
        let new_n_begin = new_raw.len as u16;
        let _ = new_raw.try_append(map.raw_buf[e.name_begin..e.name_end]);
        let new_n_end = new_raw.len as u16;
        let _ = new_raw.try_append(map.raw_buf[e.values_begin..e.values_end]);
        let new_v_end = new_raw.len as u16;
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

fn finish_compaction(
    map:           HeaderMap&,
    write_entry_i: i64,
    new_raw:       u8[..8192]&,
    spill_raw:     const u8[:] = "",
) {
    map.entries.resize(write_entry_i);
    map.header_contains_comma.resize(write_entry_i);
    core::secure_zeroize_slice(map.raw_buf[..]);
    let _ = map.raw_buf.try_set(new_raw[..]);
    core::secure_zeroize_slice(new_raw[..]);
    new_raw.clear();
    http_internal::rebuild_inline_slots_and_chains(map, spill_raw);
}

fn relocate_arena_entry(entry: HeaderEntry&, src_raw: const u8[:], dst_raw: u8[>..]&) {
    guard entry.reserved == HEADER_SRC_ARENA else { return; }
    let nb: i64 = entry.name_begin;
    let ne: i64 = entry.name_end;
    let vb: i64 = entry.values_begin;
    let ve: i64 = entry.values_end;
    let new_nb = dst_raw.len as u16;
    if nb >= 0 && nb <= ne && ne <= src_raw.len {
        dst_raw.append(src_raw[nb..ne]);
    }
    let new_ne = dst_raw.len as u16;
    if vb >= 0 && vb <= ve && ve <= src_raw.len {
        dst_raw.append(src_raw[vb..ve]);
    }
    let new_ve = dst_raw.len as u16;
    entry.name_begin = new_nb;
    entry.name_end = new_ne;
    entry.values_begin = new_ne;
    entry.values_end = new_ve;
}

fn compact_arena_spill_raw(map: HeaderMap&, arena: OverflowArena&, kept_map_count: i64) {
    guard arena.spill_raw.len > 0 else { return; }
    var tmp_raw: u8[>..] = [];
    for i in 0..kept_map_count {
        relocate_arena_entry(map.entries[i], arena.spill_raw[..], tmp_raw);
    }
    for si in 0..arena.spill_entries.len {
        relocate_arena_entry(arena.spill_entries[si], arena.spill_raw[..], tmp_raw);
    }
    core::secure_zeroize_slice(arena.spill_raw[..]);
    arena.spill_raw.clear();
    arena.spill_raw.append(tmp_raw[..]);
    core::secure_zeroize_slice(tmp_raw[..]);
}

fn remove_header(map: HeaderMap&, name: const u8[:]) -> bool {
    var found = false;
    var write_entry_i: i64        = 0;
    var new_raw:       u8[..8192] = [];
    defer core::secure_zeroize_slice(new_raw[..]);
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
        compact_kept_entry_into(map, read_i, write_entry_i, new_raw);
    }

    if found {
        finish_compaction(map, write_entry_i, new_raw);
    }
    return found;
}

fn remove_header_spill(map: HeaderMap&, arena: OverflowArena&, name: const u8[:]) -> bool {
    var found = false;
    var write_entry_i: i64        = 0;
    var new_raw:       u8[..8192] = [];
    defer core::secure_zeroize_slice(new_raw[..]);
    for read_i in map.entries.len {
        let e .= map.entries[read_i];
        if entry_name_spill(map, arena, e).eq_ascii_fold(name) {
            found = true;
            continue;
        }
        compact_kept_entry_into(map, read_i, write_entry_i, new_raw);
    }
    var spill_write: i64 = 0;
    for si in arena.spill_entries.len {
        let se = arena.spill_entries[si];
        if entry_name_spill(map, arena, se).eq_ascii_fold(name) {
            found = true;
            continue;
        }
        arena.spill_entries[spill_write] = se;
        spill_write += 1;
    }
    if found {
        arena.spill_entries.resize(spill_write);
        compact_arena_spill_raw(map, arena, write_entry_i);
        finish_compaction(map, write_entry_i, new_raw, arena.spill_raw[..]);
    }
    return found;
}

fn entry_byte_cost(entry: const HeaderEntry&) -> i64 {
    let n_len = core::sub_sat_i64(entry.name_end, entry.name_begin);
    let v_len = core::sub_sat_i64(entry.values_end, entry.values_begin);
    return core::add_sat_i64(n_len, v_len);
}

fn accumulate_kept_slice(
    entries:        const HeaderEntry[:],
    map:            const HeaderMap&,
    arena:          const OverflowArena&,
    target_name:    const u8[:],
    has_match:      bool&,
    kept_count:     i64&,
    kept_stack_raw: i64&,
    kept_arena_raw: i64&,
) {
    for &e in entries {
        if entry_name_spill(map, arena, e).eq_ascii_fold(target_name) {
            has_match = true;
            continue;
        }
        kept_count += 1;
        let cost = entry_byte_cost(e);
        if e.reserved == HEADER_SRC_ARENA {
            kept_arena_raw += cost;
        } else {
            kept_stack_raw += cost;
        }
    }
}

fn set_or_replace_spill(
    map:   HeaderMap&,
    arena: OverflowArena&,
    name:  const u8[:],
    value: const u8[:],
    flags: u8 = 0,
) -> bool {
    let valid_name = is_valid_header_name(name) || is_valid_header_name_h2(name);
    guard valid_name && is_valid_header_value(value) else { return false; }
    let trimmed = value.trim_lws();
    let needed = core::add_sat_i64(name.len, trimmed.len);

    var has_match = false;
    var kept_map_cnt:   i64 = 0;
    var kept_spill_cnt: i64 = 0;
    var kept_stack_raw: i64 = 0;
    var kept_arena_raw: i64 = 0;
    accumulate_kept_slice(
        map.entries[..], map, arena, name, has_match, kept_map_cnt, kept_stack_raw, kept_arena_raw,
    );
    accumulate_kept_slice(
        arena.spill_entries[..], map, arena, name, has_match, kept_spill_cnt, kept_stack_raw, kept_arena_raw,
    );

    let post_stack_raw = if has_match { kept_stack_raw } else { map.raw_buf.len };
    let post_arena_raw = if has_match { kept_arena_raw } else { arena.spill_raw.len };
    let can_stack = kept_spill_cnt == 0
        && kept_map_cnt < 128
        && core::add_sat_i64(post_stack_raw, needed) <= 8192;
    let can_spill = core::add_sat_i64(post_arena_raw, needed) <= MAX_OVERFLOW_RAW_BYTES
        && (kept_spill_cnt == 0 && kept_map_cnt < 128 || kept_spill_cnt < MAX_OVERFLOW_SPILL_ENTRIES);
    guard can_stack || can_spill else { return false; }

    if has_match {
        let _ = remove_header_spill(map, arena, name);
    }
    return append_validated_header_spill(map, arena, name, trimmed, flags);
}

fn remove_header_by_name(map: HeaderMap&, target_name: const u8[:]) -> bool {
    guard target_name.len > 0 else { return false; }
    return remove_header(map, target_name);
}

fn copy_headers(src: const HeaderMap&, dst: HeaderMap&) {
    dst.reset_for_keep_alive();
    append_all_headers(src, dst);
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
    var write_entry_i: i64        = 0;
    var new_raw:       u8[..8192] = [];
    defer core::secure_zeroize_slice(new_raw[..]);
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
        compact_kept_entry_into(map, read_i, write_entry_i, new_raw);
    }

    if found {
        finish_compaction(map, write_entry_i, new_raw);
    }
}

fn append_combined_from_entries<B>(
    entries:     const HeaderEntry[:],
    stack_raw:   const u8[:],
    spill_raw:   const u8[:],
    name:        const u8[:],
    hname:       u32,
    sep_ch:      u8,
    max_out_len: i64,
    first:       bool&,
    found:       bool&,
    out:         B&,
) -> bool {
    for &entry in entries {
        guard entry.name_hash == hname else { continue; }
        guard resolve_entry_name_buf(stack_raw, spill_raw, entry).eq_ascii_fold(name) else { continue; }
        found = true;
        if !first {
            guard out.len + 2 <= max_out_len else { out.clear(); return false; }
            out.push(sep_ch);
            out.push(' ');
        }
        first = false;
        let val = resolve_entry_value_buf(stack_raw, spill_raw, entry);
        guard out.len + val.len <= max_out_len else { out.clear(); return false; }
        out.append(val);
    }
    return true;
}

fn get_combined_slices<B>(
    map:           const HeaderMap&,
    spill_entries: const HeaderEntry[:],
    spill_raw:     const u8[:],
    name:          const u8[:],
    out:           B&,
    max_out_len:   i64,
) -> bool {
    let wk_id = classify_well_known_header(name);
    let flags = http_internal::well_known_header_flags(wk_id, name);
    guard (flags & HEADER_FLAG_NO_COMMA_FOLD) == 0 else {
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

    guard append_combined_from_entries(
        map.entries[..], map.raw_buf[..], spill_raw, name, hname, sep_ch, max_out_len, first, found, out,
    ) else {
        out.clear();
        return false;
    }
    guard append_combined_from_entries(
        spill_entries, map.raw_buf[..], spill_raw, name, hname, sep_ch, max_out_len, first, found, out,
    ) else {
        out.clear();
        return false;
    }
    if !found {
        out.clear();
        return false;
    }
    committed = true;
    return true;
}

// RFC 9110 Section 5.3 comma combining across stack map + OverflowArena. BLOCKS Set-Cookie & NO_COMMA_FOLD headers.
fn get_combined_spill<B>(
    map:         const HeaderMap&,
    arena:       const OverflowArena&,
    name:        const u8[:],
    out:         B&,
    max_out_len: i64 = 65535,
) -> bool {
    return get_combined_slices(map, arena.spill_entries[..], arena.spill_raw[..], name, out, max_out_len);
}

// RFC 9110 Section 5.3 comma combining. BLOCKS Set-Cookie & NO_COMMA_FOLD headers.
fn get_combined<B>(map: const HeaderMap&, name: const u8[:], out: B&, max_out_len: i64 = 8192) -> bool {
    return get_combined_slices(map, map.entries[..0], "", name, out, max_out_len);
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

    let entry .= map.entries[cur_idx];
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
    let total = header_count_spill(map, arena);
    for i in total {
        let entry, ok = header_entry_at_spill(map, arena, i);
        guard ok && entry.name_hash == hname else { continue; }
        guard entry_name_spill(map, arena, entry).eq_ascii_fold(name) else { continue; }
        let val = entry_value_spill(map, arena, entry);
        var item: u8[..256] = [];
        let v_len = min(val.len, item.cap);
        item.append(val[..v_len]);
        out_values.push(item);
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
    let total = header_count_spill(map, arena);
    for i in total {
        let entry, ok = header_entry_at_spill(map, arena, i);
        guard ok else { break; }
        let name = entry_name_spill(map, arena, entry);
        let val = entry_value_spill(map, arena, entry);
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

const PROTECTED_E2E_HEADER_NAMES: const u8[:][57] = [
    "host", "content-length", "content-type", "authorization", "cookie",
    "set-cookie", "set-cookie2", "origin", "referer", "vary",
    "cache-control", "date", "etag", "location", "content-encoding",
    "content-range", "range", "if-match", "if-none-match",
    "if-modified-since", "if-unmodified-since", "content-digest",
    "repr-digest", "want-content-digest", "want-repr-digest", "digest",
    "signature", "signature-input", "dpop", "dpop-nonce",
    "www-authenticate", "forwarded", "x-forwarded-for", "x-forwarded-host",
    "x-forwarded-proto", "x-forwarded-port", "x-forwarded-ssl",
    "x-forwarded-scheme", "x-real-ip", "true-client-ip", "cf-connecting-ip",
    "x-client-ip", "fastly-client-ip", "x-cluster-client-ip", "client-cert",
    "client-cert-chain", "x-ssl-client-cert", "x-client-cert",
    "x-authenticated-user", "x-api-key", "x-frame-options",
    "x-content-type-options", "x-csrf-token", "x-xsrf-token",
    "x-request-id", "strict-transport-security", "x-webkit-csp",
];

// RFC 9110 Section 7.6.1: Protects framing, security, and forwarding headers
// from client-supplied Connection header stripping.
fn is_protected_end_to_end_header(name: const u8[:]) -> bool {
    if name.starts_with_fold("access-control-")
        || name.starts_with_fold("content-security-policy")
        || name.starts_with_fold("cross-origin-") {
        return true;
    }
    if name.starts_with_fold("sec-") && !name.starts_with_fold("sec-websocket-") {
        return true;
    }
    for hdr in PROTECTED_E2E_HEADER_NAMES {
        if name.eq_ascii_fold(hdr) {
            return true;
        }
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

fn entries_have_connection_token(
    entries:   const HeaderEntry[:],
    stack_raw: const u8[:],
    spill_raw: const u8[:],
    token:     const u8[:],
) -> bool {
    for &entry in entries {
        guard resolve_entry_name_buf(stack_raw, spill_raw, entry).eq_ascii_fold("connection") else {
            continue;
        }
        let val = resolve_entry_value_buf(stack_raw, spill_raw, entry);
        if http_internal::connection_val_has_token(val, token) {
            return true;
        }
    }
    return false;
}

fn is_token_in_connection_header_spill(
    map:   const HeaderMap&,
    arena: const OverflowArena&,
    token: const u8[:],
) -> bool {
    return entries_have_connection_token(map.entries[..], map.raw_buf[..], arena.spill_raw[..], token) ||
        entries_have_connection_token(arena.spill_entries[..], map.raw_buf[..], arena.spill_raw[..], token);
}

fn is_token_in_connection_header_map(src: const HeaderMap&, target_name: const u8[:]) -> bool {
    return entries_have_connection_token(src.entries[..], src.raw_buf[..], "", target_name);
}

// Copies headers from src to dst, omitting standard hop-by-hop headers (RFC 9110 Section 7.6.1).
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
        if is_token_in_connection_header_map(src, name) && !is_protected_end_to_end_header(name) {
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
