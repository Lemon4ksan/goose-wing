// HTTP header parsing and storage (RFC 9110, RFC 9112).
// Stores names and values as offset slices into a contiguous buffer with
// dedicated lookup slots for frequent standard headers.
namespace wing;

import std;

let CRLF_BYTES: const u8[2] = ['\r', '\n'];
let CRLF_SET: ByteSet = byte_set(CRLF_BYTES[..]);

let COLON_BYTES: const u8[1] = [':'];
let COLON_SET: ByteSet = byte_set(COLON_BYTES[..]);

let NULL_BYTES: const u8[1] = [0];
let NULL_SET: ByteSet = byte_set(NULL_BYTES[..]);

// ---- header bitmask flags & persistence constants --------------------------

const HEADER_FLAG_NONE: u8 = 0;
const HEADER_FLAG_NO_COMMA_FOLD: u8 = 1;    // 0x01: Set-Cookie, WWW-Authenticate, Proxy-Authenticate (RFC 9110 Section 5.3 / RFC 6265bis)
const HEADER_FLAG_SENSITIVE: u8 = 2;        // 0x02: Authorization, Cookie, API Keys, etc.
const HEADER_FLAG_CONTINUATION: u8 = 4;     // 0x04: Virtual continuation node (name_begin == name_end)
const HEADER_FLAG_CONTAINS_COMMA: u8 = 8;   // 0x08: Value contains comma (absl::InlinedVector<bool, 100> equivalent)
const HEADER_FLAG_COOKIE_STATE: u8 = 16;    // 0x10: kCookieResponseHeaders (stripped on PERSIST_SANS_COOKIES & 304 merge)
const HEADER_FLAG_CHALLENGE: u8 = 32;       // 0x20: kChallengeResponseHeaders (stripped on PERSIST_SANS_CHALLENGES)
const HEADER_FLAG_SECURITY_STATE: u8 = 64;  // 0x40: kSecurityStateHeaders (Strict-Transport-Security, x-content-*, x-webkit-*)
const HEADER_FLAG_NON_CACHEABLE: u8 = 128;  // 0x80: Hop-by-hop / transient headers (connection, transfer-encoding, etc.)

const HEADER_INVALID_IDX: u8 = 0xFF;

// Cache Persistence Filter Flags (Chromium net/http/http_response_headers.h)
const PERSIST_ALL: u32 = 0;
const PERSIST_SANS_COOKIES: u32 = 1;
const PERSIST_SANS_CHALLENGES: u32 = 2;
const PERSIST_SANS_NON_CACHEABLE: u32 = 4;
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

fn classify_well_known_header(name: const u8[:]) -> WellKnownHeader {
    let len = name.len;
    guard len >= 2 && len <= 32 else { return WellKnownHeader.Unknown; }

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
        27 => {
            if eq_ascii_fold(name, "access-control-allow-origin") { return WellKnownHeader.AccessControlAllowOrigin; }
            if eq_ascii_fold(name, "access-control-allow-headers") { return WellKnownHeader.AccessControlAllowHeaders; }
            if eq_ascii_fold(name, "access-control-allow-methods") { return WellKnownHeader.AccessControlAllowMethods; }
        },
        28 => {
            if eq_ascii_fold(name, "access-control-expose-headers") { return WellKnownHeader.AccessControlExposeHeaders; }
        },
        32 => {
            if eq_ascii_fold(name, "access-control-allow-credentials") { return WellKnownHeader.AccessControlAllowCredentials; }
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
    if id == WellKnownHeader.StrictTransportSecurity || id == WellKnownHeader.XContentTypeOptions || id == WellKnownHeader.XWebkitCsp {
        flags |= HEADER_FLAG_SECURITY_STATE;
    } else if name.len >= 10 && (starts_with_ignore_case(name, "x-content-") || starts_with_ignore_case(name, "x-webkit-")) {
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

fn starts_with_ignore_case(s: const u8[:], prefix: const u8[:]) -> bool {
    guard s.len >= prefix.len else { return false; }
    return eq_ascii_fold(s[..prefix.len], prefix);
}

// ---- header entry (16 bytes aligned) ---------------------------------------

struct HeaderEntry {
    name_begin: u16 = 0,
    name_end: u16 = 0,
    values_begin: u16 = 0,
    values_end: u16 = 0,
    next_idx: u8 = 0xFF,
    flags: u8 = 0,
    well_known_id: u8 = 0xFF,
    reserved: u8 = 0,
    name_hash: u32 = 0,
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
    raw_buf: u8[..8192] = [],
    entries: HeaderEntry[..128] = [],
    inline_slots: u8[64] = [0xFF; 64],
    header_contains_comma: bool[..128] = [],
    status_code: i32 = 200,
    http_major: i32 = 1,
    http_minor: i32 = 1,
    valid: bool = true,
}

fn new_header_map() -> HeaderMap {
    return HeaderMap { .. };
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

// ---- lexical validation & fast word operations -----------------------------

fn is_tchar(b: u8) -> bool {
    if (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9') {
        return true;
    }
    return b == '!' || b == '#' || b == '$' || b == '%' || b == '&' || b == '\'' ||
           b == '*' || b == '+' || b == '-' || b == '.' || b == '^' || b == '_' ||
           b == '`' || b == '|' || b == '~';
}

fn is_valid_header_name(name: const u8[:]) -> bool {
    guard name.len > 0 else { return false; }
    for b in name {
        guard is_tchar(b) else { return false; }
    }
    return true;
}

// RFC 9113 Section 8.2.1: Wire lowercase ASCII validation for HTTP/2 & HTTP/3 headers
fn is_valid_header_name_h2(name: const u8[:]) -> bool {
    guard name.len > 0 else { return false; }
    let is_pseudo = name[0] == ':';
    let start_idx: i64 = if is_pseudo { 1 } else { 0 };
    guard start_idx < name.len else { return false; }
    for i in start_idx..name.len {
        let b = name[i];
        if b >= 'A' && b <= 'Z' { return false; }
        guard is_tchar(b) else { return false; }
    }
    return true;
}

fn has_embedded_nulls(data: const u8[:]) -> bool {
    return find_any(data, NULL_SET) >= 0;
}

fn is_valid_header_value(val: const u8[:]) -> bool {
    for b in val {
        // Rejects NUL, CR, LF, and all CTLs (0x00-0x08, 0x0A-0x1F, 0x7F) except HTAB (0x09)
        if b < 0x20 {
            if b != 0x09 { return false; }
        } else if b == 0x7F {
            return false;
        }
    }
    return true;
}

fn trim_lws(val: const u8[:]) -> const u8[:] {
    var start: i64 = 0;
    while start < val.len && (val[start] == ' ' || val[start] == '\t') {
        start++;
    }
    var end_pos: i64 = val.len;
    while end_pos > start && (val[end_pos - 1] == ' ' || val[end_pos - 1] == '\t') {
        end_pos--;
    }
    return val[start..end_pos];
}

// RFC 9110 Section 8.6 & RFC 9112 Section 6.3: Content-Length validation & anti-smuggling parser
fn parse_cl_digits(s: const u8[:], out_val: i64&) -> bool {
    var num: i64 = 0;
    var digits: i64 = 0;
    for b in s {
        guard b >= '0' && b <= '9' else { return false; }
        digits++;
        guard digits <= 19 else { return false; }
        let d = (b - '0') as i64;
        if digits == 19 {
            if num > 922337203685477580 || (num == 922337203685477580 && d > 7) {
                return false;
            }
        }
        num = num * 10 + d;
    }
    guard digits > 0 else { return false; }
    out_val = num;
    return true;
}

fn validate_content_length_value(val: const u8[:], out_val: i64&) -> bool {
    let trimmed = trim_lws(val);
    guard trimmed.len > 0 else { return false; }

    var has_comma = false;
    for b in trimmed {
        if b == ',' {
            has_comma = true;
            break;
        }
    }

    if !has_comma {
        return parse_cl_digits(trimmed, out_val);
    }

    guard trimmed[0] != ',' && trimmed[trimmed.len - 1] != ',' else { return false; }

    var first_parsed = false;
    var target_val: i64 = 0;
    var cursor: i64 = 0;

    while cursor < trimmed.len {
        var comma_idx = cursor;
        while comma_idx < trimmed.len && trimmed[comma_idx] != ',' {
            comma_idx++;
        }

        let piece = trim_lws(trimmed[cursor..comma_idx]);
        guard piece.len > 0 else { return false; }

        var piece_num: i64 = 0;
        guard parse_cl_digits(piece, piece_num) else { return false; }

        if !first_parsed {
            target_val = piece_num;
            first_parsed = true;
        } else {
            guard piece_num == target_val else { return false; }
        }

        cursor = comma_idx + 1;
    }

    guard first_parsed else { return false; }
    out_val = target_val;
    return true;
}

// RFC 9112 Section 7.3: Standard registered transfer codings
fn is_valid_transfer_coding(coding: const u8[:]) -> bool {
    return eq_ascii_fold(coding, "chunked") ||
           eq_ascii_fold(coding, "gzip") ||
           eq_ascii_fold(coding, "deflate") ||
           eq_ascii_fold(coding, "compress");
}

// Validates a Transfer-Encoding header value (RFC 9112 Section 6.3, Section 7.1).
// Only chunked, gzip, deflate, and compress are recognized; if chunked is
// present, it must appear last and exactly once.
fn validate_transfer_encoding_value(val: const u8[:]) -> bool {
    let trimmed = trim_lws(val);
    guard trimmed.len > 0 else { return false; }
    guard trimmed[0] != ',' && trimmed[trimmed.len - 1] != ',' else { return false; }

    var cursor: i64 = 0;
    var count: i32 = 0;
    var chunked_count: i32 = 0;
    var last_is_chunked = false;

    while cursor <= trimmed.len {
        var comma_idx = cursor;
        while comma_idx < trimmed.len && trimmed[comma_idx] != ',' {
            comma_idx++;
        }

        let piece = trim_lws(trimmed[cursor..comma_idx]);
        guard piece.len > 0 else { return false; }
        guard is_valid_transfer_coding(piece) else { return false; }

        let is_chunked = eq_ascii_fold(piece, "chunked");
        if is_chunked {
            chunked_count++;
            last_is_chunked = true;
        } else {
            last_is_chunked = false;
        }
        count++;

        if comma_idx == trimmed.len {
            break;
        }
        cursor = comma_idx + 1;
    }

    guard count > 0 else { return false; }
    // RFC 9112 Section 7.1: Chunked must not be applied more than once
    guard chunked_count <= 1 else { return false; }
    // RFC 9112 Section 6.3: If present in a request, chunked must be the final encoding
    guard last_is_chunked else { return false; }

    return true;
}

// 64-bit SWAR Little-Endian pack
fn swar_pack_u64_le(buf: const u8[:], offset: i64) -> u64 {
    var w: u64 = 0;
    for i in 8 {
        let b = buf[offset + i] as u64;
        w |= (b << ((i * 8) as u64));
    }
    return w;
}

// 64-bit SWAR zero byte check
fn swar_has_zero_byte(w: u64) -> bool {
    return ((w - 0x0101010101010101) & (~w) & 0x8080808080808080) != 0;
}

// 64-bit SWAR byte search
fn swar_has_byte(w: u64, b: u8) -> bool {
    let mask = 0x0101010101010101 * (b as u64);
    return swar_has_zero_byte(w ^ mask);
}

// 64-bit SWAR control character check (< 0x20 or == 0x7F)
fn swar_has_ctl_or_del(w: u64) -> bool {
    // Check if any byte is < 0x20
    let sub = w - 0x2020202020202020;
    let has_under_20 = (sub & (~w) & 0x8080808080808080) != 0;
    let has_del = swar_has_byte(w, 0x7F);
    return has_under_20 || has_del;
}

// Fast header name hash (FNV-1a 32-bit case-folded)
fn hash_header_name(name: const u8[:]) -> u32 {
    var h: u32 = core::FNV1A_32_OFFSET;
    for b in name {
        let folded = if b >= 'A' && b <= 'Z' { b + 32 } else { b };
        h = (h ^ folded) * core::FNV1A_32_PRIME;
    }
    return h;
}

// ---- wire parser -----------------------------------------------------------

fn is_line_whitespace_only(line: const u8[:]) -> bool {
    for b in line {
        if b != ' ' && b != '\t' {
            return false;
        }
    }
    return true;
}

fn advance_crlf(buf: const u8[:], cursor: i64&, line_end: i64) -> bool {
    cursor = line_end;
    let buf_len = buf.len;
    if cursor < buf_len && buf[cursor] == '\r' {
        guard cursor + 1 < buf_len && buf[cursor + 1] == '\n' else {
            return false;
        }
        cursor += 2;
        return true;
    }
    if cursor < buf_len && buf[cursor] == '\n' {
        cursor++;
        return true;
    }
    return true;
}

fn link_header_entry(map: HeaderMap&, wk_id: WellKnownHeader, raw_name: const u8[:], hname: u32, new_idx: u8) {
    if wk_id != WellKnownHeader.Unknown {
        let slot = well_known_to_slot(wk_id);
        let existing = map.inline_slots[slot];
        if existing == 0xFF {
            map.inline_slots[slot] = new_idx;
            return
        }

        var cur = existing;
        while map.entries[cur as i64].next_idx != 0xFF {
            cur = map.entries[cur as i64].next_idx;
        }

        map.entries[cur as i64].next_idx = new_idx;
        return
    }

    for prev_i in map.entries.len {
        let pe = map.entries[prev_i];
        if pe.name_hash == hname {
            let prev_name = map.raw_buf[pe.name_begin..pe.name_end];
            if eq_ascii_fold(prev_name, raw_name) {
                var cur = prev_i as u8;
                while map.entries[cur as i64].next_idx != 0xFF {
                    cur = map.entries[cur as i64].next_idx;
                }
                map.entries[cur as i64].next_idx = new_idx;
                break;
            }
        }
    }
}

fn handle_obs_fold(line: const u8[:], is_first_header: bool, allow_obs_fold: bool, map: HeaderMap&) -> HeaderParseError {
    if is_first_header || map.entries.len == 0 {
        map.valid = false;
        return HeaderParseError.LeadingWhitespaceOnFirstHeader;
    }
    guard allow_obs_fold else {
        map.valid = false;
        return HeaderParseError.ObsFoldForbidden;
    }

    let prev_idx = map.entries.len - 1;
    let trimmed_continuation = trim_lws(line);
    guard is_valid_header_value(trimmed_continuation) else {
        map.valid = false;
        return HeaderParseError.InvalidHeaderValue;
    }

    let orig_begin = map.entries[prev_idx].values_begin;
    let orig_end = map.entries[prev_idx].values_end;
    let orig_val = map.raw_buf[orig_begin..orig_end];

    let new_begin = map.raw_buf.len as u16;
    map.raw_buf.append(orig_val);
    map.raw_buf.push(' ');
    map.raw_buf.append(trimmed_continuation);
    let new_end = map.raw_buf.len as u16;

    map.entries[prev_idx].values_begin = new_begin;
    map.entries[prev_idx].values_end = new_end;

    let prev_wk = map.entries[prev_idx].well_known_id;
    if prev_wk == well_known_to_slot(WellKnownHeader.ContentLength) as u8 {
        let full_cl = map.raw_buf[new_begin..new_end];
        var dummy_cl: i64 = 0;
        guard validate_content_length_value(full_cl, dummy_cl) else {
            map.valid = false;
            return HeaderParseError.InvalidContentLength;
        }
    } else if prev_wk == well_known_to_slot(WellKnownHeader.TransferEncoding) as u8 {
        let full_te = map.raw_buf[new_begin..new_end];
        guard validate_transfer_encoding_value(full_te) else {
            map.valid = false;
            return HeaderParseError.InvalidContentLength;
        }
    }
    return HeaderParseError.None;
}

fn validate_header_framing_conflicts(map: HeaderMap&, wk_id: WellKnownHeader, val_trimmed: const u8[:], is_dup_cl: bool&) -> HeaderParseError {
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
    }
    return HeaderParseError.None;
}

// Parses an HTTP/1.x header block into map (RFC 9112 Section 5.2).
// Header names and values are indexed as offsets into the map's buffer.
// Obsolete line folding (obs-fold) is rejected unless allow_obs_fold is set.
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
            let fold_err = handle_obs_fold(line, is_first_header, allow_obs_fold, map);
            guard is_ok(fold_err) else { return fold_err; }
        } else {
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
            var is_dup_cl = false;
            let conflict_err = validate_header_framing_conflicts(map, wk_id, val_trimmed, is_dup_cl);
            guard is_ok(conflict_err) else { return conflict_err; }

            if is_dup_cl {
                guard advance_crlf(map.raw_buf[..], cursor, line_end) else {
                    map.valid = false;
                    return HeaderParseError.InvalidHeaderValue;
                }
                continue;
            }

            let name_begin_off = cursor as u16;
            let name_end_off = (cursor + colon_pos) as u16;

            var val_start_off = (cursor + colon_pos + 1) as u16;
            while val_start_off < (cursor + line.len) && (map.raw_buf[val_start_off as i64] == ' ' || map.raw_buf[val_start_off as i64] == '\t') {
                val_start_off++;
            }
            var val_end_off = (cursor + line.len) as u16;
            while (val_end_off as i64) > val_start_off && (map.raw_buf[(val_end_off - 1) as i64] == ' ' || map.raw_buf[(val_end_off - 1) as i64] == '\t') {
                val_end_off--;
            }

            let flags = well_known_header_flags(wk_id, raw_name);
            let hname = hash_header_name(raw_name);

            var contains_comma = false;
            for b in val_trimmed {
                if b == ',' { contains_comma = true; break; }
            }
            let entry_flags = if contains_comma { flags | HEADER_FLAG_CONTAINS_COMMA } else { flags };

            let new_entry = HeaderEntry {
                name_begin: name_begin_off,
                name_end: name_end_off,
                values_begin: val_start_off,
                values_end: val_end_off,
                next_idx: 0xFF,
                flags: entry_flags,
                well_known_id: if wk_id != WellKnownHeader.Unknown { well_known_to_slot(wk_id) as u8 } else { 0xFF },
                reserved: 0,
                name_hash: hname,
            };

            let new_idx = map.entries.len as u8;
            link_header_entry(map, wk_id, raw_name, hname, new_idx);
            map.entries.push(new_entry);
            map.header_contains_comma.push(contains_comma);
            is_first_header = false;
        }

        guard advance_crlf(map.raw_buf[..], cursor, line_end) else {
            map.valid = false;
            return HeaderParseError.InvalidHeaderValue;
        }
    }

    map.valid = true;
    return HeaderParseError.None;
}

// Parses full HTTP/1.1 response status line and header block
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

    let status_line = raw_input[..line_end];
    guard status_line.len >= 12 else {
        map.valid = false;
        return HeaderParseError.MalformedStatusLine;
    }

    guard eq_ascii_fold(status_line[..5], "HTTP/") else {
        map.valid = false;
        return HeaderParseError.MalformedStatusLine;
    }

    let major = status_line[5] - '0';
    let dot = status_line[6];
    let minor = status_line[7] - '0';
    guard dot == '.' && major >= 0 && major <= 9 && minor >= 0 && minor <= 9 else {
        map.valid = false;
        return HeaderParseError.MalformedStatusLine;
    }

    // Skip spaces to status code
    var sp_idx: i64 = 8;
    while sp_idx < status_line.len && status_line[sp_idx] == ' ' { sp_idx++; }
    guard sp_idx + 3 <= status_line.len else {
        map.valid = false;
        return HeaderParseError.MalformedStatusLine;
    }

    let c0 = status_line[sp_idx] - '0';
    let c1 = status_line[sp_idx + 1] - '0';
    let c2 = status_line[sp_idx + 2] - '0';
    guard c0 >= 0 && c0 <= 9 && c1 >= 0 && c1 <= 9 && c2 >= 0 && c2 <= 9 else {
        map.valid = false;
        return HeaderParseError.MalformedStatusLine;
    }
    let code = (c0 * 100 + c1 * 10 + c2) as i32;

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

// Parses full HTTP/1.1 request line (METHOD /path HTTP/1.1) and header block
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
    guard is_valid_header_name(name) && is_valid_header_value(value) else { return false; }
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
        name_begin: n_begin,
        name_end: n_end,
        values_begin: v_begin,
        values_end: v_end,
        next_idx: 0xFF,
        flags: entry_flags,
        well_known_id: if wk_id != WellKnownHeader.Unknown { well_known_to_slot(wk_id) as u8 } else { 0xFF },
        reserved: 0,
        name_hash: hname,
    };

    link_header_entry(map, wk_id, name, hname, new_idx);
    map.entries.push(entry);
    map.header_contains_comma.push(contains_comma);
    return true;
}

fn insert_header(map: HeaderMap&, name: const u8[:], value: const u8[:]) -> bool {
    // If already exists, overwrite value of first occurrence and prune subsequent occurrences
    guard is_valid_header_name(name) && is_valid_header_value(value) else { return false; }

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

fn remove_header(map: HeaderMap&, name: const u8[:]) -> bool {
    let wk_id = classify_well_known_header(name);
    let hname = hash_header_name(name);
    var found = false;

    if wk_id != WellKnownHeader.Unknown {
        let slot = well_known_to_slot(wk_id);
        if map.inline_slots[slot] != 0xFF {
            map.inline_slots[slot] = 0xFF;
            found = true;
        }
    }

    // Prune entries by rebuilding or marking
    // In bounded static array, filter entries that do not match name
    var new_entries: HeaderEntry[..128] = [];
    var new_commas: bool[..128] = [];
    for i in 64 { map.inline_slots[i] = 0xFF; }

    for &e, i in map.entries {
        let ename = map.raw_buf[e.name_begin..e.name_end];
        if eq_ascii_fold(ename, name) {
            found = true;
            continue;
        }

        let new_idx = new_entries.len as u8;
        var copy_e = e;
        copy_e.next_idx = 0xFF;

        let cur_wk = if copy_e.well_known_id != 0xFF { copy_e.well_known_id as i64 } else { -1 };
        if cur_wk >= 0 && cur_wk < 64 {
            let ex = map.inline_slots[cur_wk];
            if ex == 0xFF {
                map.inline_slots[cur_wk] = new_idx;
            } else {
                var cur = ex;
                while new_entries[cur as i64].next_idx != 0xFF {
                    cur = new_entries[cur as i64].next_idx;
                }
                new_entries[cur as i64].next_idx = new_idx;
            }
        } else {
            for prev_i in new_entries.len {
                if new_entries[prev_i].name_hash == copy_e.name_hash {
                    let prev_n = map.raw_buf[new_entries[prev_i].name_begin..new_entries[prev_i].name_end];
                    if eq_ascii_fold(prev_n, ename) {
                        var cur = prev_i as u8;
                        while new_entries[cur as i64].next_idx != 0xFF {
                            cur = new_entries[cur as i64].next_idx;
                        }
                        new_entries[cur as i64].next_idx = new_idx;
                        break;
                    }
                }
            }
        }

        new_entries.push(copy_e);
        new_commas.push(map.header_contains_comma[i]);
    }

    map.entries.clear();
    for e in new_entries { map.entries.push(e); }
    map.header_contains_comma.clear();
    for c in new_commas { map.header_contains_comma.push(c); }

    return found;
}

// RFC 9110 Section 5.3 comma combining. BLOCKS Set-Cookie & NO_COMMA_FOLD headers!
fn get_combined(map: const HeaderMap&, name: const u8[:], out: u8[>..]&) -> bool {
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
        if entry.name_hash == hname {
            let entry_name = map.raw_buf[entry.name_begin..entry.name_end];
            if eq_ascii_fold(entry_name, name) {
                found = true;
                if !first {
                    out.push(',');
                    out.push(' ');
                }
                first = false;
                let val = map.raw_buf[entry.values_begin..entry.values_end];
                out.append(val);
            }
        }
    }
    return found;
}

fn get_all_values(map: const HeaderMap&, name: const u8[:], out_values: u8[..256][>..]&) {
    let hname = hash_header_name(name);
    for &entry in map.entries {
        if entry.name_hash == hname {
            let entry_name = map.raw_buf[entry.name_begin..entry.name_end];
            if eq_ascii_fold(entry_name, name) {
                let val = map.raw_buf[entry.values_begin..entry.values_end];
                var item: u8[..256] = [];
                item.append(val);
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
        cookie_str.append(val);
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
            var first = true;
            for j in i..map.entries.len {
                let other = map.entries[j];
                if other.name_hash == entry.name_hash {
                    let other_name = map.raw_buf[other.name_begin..other.name_end];
                    if eq_ascii_fold(other_name, name) {
                        if !first {
                            out.append(", ");
                        }
                        first = false;
                        let val = map.raw_buf[other.values_begin..other.values_end];
                        out.append(val);
                        visited[j] = true;
                    }
                }
            }
            out.append("\r\n");
        }
    }
}

// ---- chromium 304 not modified merge & cache persistence --------------------

fn should_update_header_304(entry_flags: u8, name: const u8[:]) -> bool {
    // RFC 9110 Section 15.4.5, RFC 9111 Section 3.2 & Chromium HttpResponseHeaders::ShouldUpdateHeader
    // Never update cookies, auth challenges, security state, or hop-by-hop headers
    if (entry_flags & (HEADER_FLAG_COOKIE_STATE | HEADER_FLAG_CHALLENGE | HEADER_FLAG_SECURITY_STATE | HEADER_FLAG_NON_CACHEABLE)) != 0 {
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

fn collect_connection_tokens(src: const HeaderMap&, out_tokens: u8[..64][..16]&) {
    for &entry in src.entries {
        let name = src.raw_buf[entry.name_begin..entry.name_end];
        if eq_ascii_fold(name, "connection") {
            let val = src.raw_buf[entry.values_begin..entry.values_end];
            var cursor: i64 = 0;
            while cursor < val.len {
                var comma_idx = cursor;
                while comma_idx < val.len && val[comma_idx] != ',' {
                    comma_idx++;
                }
                let token = trim_lws(val[cursor..comma_idx]);
                // Empty connection token (e.g. trailing comma or empty header #46313) is skipped without aborting
                if token.len > 0 && !is_hop_by_hop_header_name(token) && !eq_ascii_fold(token, "close") {
                    if out_tokens.len < 16 {
                        var tok_buf: u8[..64] = [];
                        tok_buf.append(token);
                        out_tokens.push(tok_buf);
                    }
                }
                cursor = comma_idx + 1;
            }
        }
    }
}

// Copies headers from src to dst, omitting standard hop-by-hop headers and
// any header listed in a Connection header token (RFC 9110 Section 7.6.1).
fn strip_hop_by_hop_headers(src: const HeaderMap&, dst: HeaderMap&) {
    dst.reset_for_keep_alive();

    var custom_tokens: u8[..64][..16] = [];
    src.collect_connection_tokens(custom_tokens);

    for &entry in src.entries {
        let name = src.raw_buf[entry.name_begin..entry.name_end];
        let val = src.raw_buf[entry.values_begin..entry.values_end];

        if is_hop_by_hop_header_name(name) {
            continue;
        }

        let is_custom_hop = custom_tokens.any() { eq_ascii_fold(name, it[..]) };
        if is_custom_hop {
            continue;
        }

        dst.append_header(name, val);
    }
}

// ---- rfc 9112 chunked transfer coding & smuggling defense engine -----------

// RFC 9112 Section 7.1: Chunked Transfer Coding & Smuggling Defense Diagnostics
enum ChunkedDecodeError {
    None,
    EmptyInput,
    InvalidChunkSizeHex,
    BareLfInChunkSize,
    BareLfInChunkData,
    BareLfInTrailer,
    InvalidChunkExtension,
    ChunkSizeOverflow,
    UnexpectedEof,
    MalformedChunkEnding,
    DisallowedTrailer,
}

fn parse_chunk_size_hex(chunk_size_line: const u8[:], out_size: u64&) -> ChunkedDecodeError {
    // RFC 9112 Section 7.1.1 & Go #64433 / CVE-2023-39326: Chunk line / extension length bound
    guard chunk_size_line.len <= 1024 else {
        return ChunkedDecodeError.InvalidChunkExtension;
    }

    var semi_idx: i64 = -1;
    for i in chunk_size_line.len {
        let b = chunk_size_line[i];
        if b == ';' && semi_idx < 0 {
            semi_idx = i;
        }
        // RFC 9112 Section 7.1.1: Reject bare CR or non-HTAB control characters in chunk extensions
        if b == '\r' || (b < 0x20 && b != 0x09) {
            return ChunkedDecodeError.InvalidChunkExtension;
        }
    }

    let hex_slice = if semi_idx >= 0 {
        trim_lws(chunk_size_line[..semi_idx])
    } else {
        trim_lws(chunk_size_line)
    };

    guard hex_slice.len > 0 && hex_slice.len <= 16 else {
        return ChunkedDecodeError.InvalidChunkSizeHex;
    }

    var chunk_size: u64 = 0;
    for b in hex_slice {
        var val: u64 = 0;
        if b >= '0' && b <= '9' {
            val = b - '0';
        } else if b >= 'a' && b <= 'f' {
            val = b - 'a' + 10;
        } else if b >= 'A' && b <= 'F' {
            val = b - 'A' + 10;
        } else {
            return ChunkedDecodeError.InvalidChunkSizeHex;
        }
        if chunk_size > 0x0FFFFFFFFFFFFFFF {
            return ChunkedDecodeError.ChunkSizeOverflow;
        }
        chunk_size = (chunk_size << 4) | val;
    }

    out_size = chunk_size;
    return ChunkedDecodeError.None;
}

fn is_disallowed_trailer_field(hname: const u8[:]) -> bool {
    // RFC 9112 Section 7.1.2: Disallowed trailer fields threatening message framing or routing
    return eq_ascii_fold(hname, "content-length") ||
           eq_ascii_fold(hname, "transfer-encoding") ||
           eq_ascii_fold(hname, "trailer") ||
           eq_ascii_fold(hname, "host") ||
           eq_ascii_fold(hname, "authorization") ||
           eq_ascii_fold(hname, "set-cookie") ||
           eq_ascii_fold(hname, "cookie") ||
           eq_ascii_fold(hname, "content-range") ||
           eq_ascii_fold(hname, "te");
}

fn parse_chunked_trailers(raw: const u8[:], cursor: i64&) -> ChunkedDecodeError {
    var trailer_count: i32 = 0;
    var total_trailer_bytes: i64 = 0;
    let max_trailers: i32 = 16;
    let max_trailer_bytes: i64 = 4096;

    while cursor < raw.len {
        var tr_end = cursor;
        var tr_nl = false;
        while tr_end < raw.len {
            if raw[tr_end] == '\n' {
                tr_nl = true;
                break;
            }
            tr_end++;
        }
        guard tr_nl else { return ChunkedDecodeError.UnexpectedEof; }

        // RFC 9112 Section 7.1.2: Reject bare LF in trailer lines (prevent framing desync)
        if tr_end == cursor || raw[tr_end - 1] != '\r' {
            return ChunkedDecodeError.BareLfInTrailer;
        }

        let tr_line = raw[cursor..tr_end - 1];
        cursor = tr_end + 1;

        if tr_line.len == 0 {
            return ChunkedDecodeError.None;
        }

        trailer_count++;
        guard trailer_count <= max_trailers else {
            return ChunkedDecodeError.DisallowedTrailer;
        }
        total_trailer_bytes += tr_line.len;
        guard total_trailer_bytes <= max_trailer_bytes else {
            return ChunkedDecodeError.DisallowedTrailer;
        }

        var col_idx: i64 = -1;
        for i in tr_line.len {
            if tr_line[i] == ':' {
                col_idx = i;
                break;
            }
        }
        guard col_idx > 0 else {
            return ChunkedDecodeError.DisallowedTrailer;
        }

        let hname = tr_line[..col_idx];
        if is_disallowed_trailer_field(hname) {
            return ChunkedDecodeError.DisallowedTrailer;
        }
    }
    return ChunkedDecodeError.UnexpectedEof;
}

// Decodes a chunked transfer-encoded payload into out_body (RFC 9112 Section 7.1).
// Chunk size lines and data chunks must end with CRLF; bare LF returns an error.
fn decode_chunked_body(raw: const u8[:], out_body: u8[>..]&) -> ChunkedDecodeError {
    guard raw.len > 0 else { return ChunkedDecodeError.EmptyInput; }

    var cursor: i64 = 0;
    while cursor < raw.len {
        var line_end = cursor;
        var found_newline = false;
        while line_end < raw.len {
            if raw[line_end] == '\n' {
                found_newline = true;
                break;
            }
            line_end++;
        }
        guard found_newline else { return ChunkedDecodeError.UnexpectedEof; }

        if line_end == cursor || raw[line_end - 1] != '\r' {
            return ChunkedDecodeError.BareLfInChunkSize;
        }

        let chunk_size_line = raw[cursor..line_end - 1];
        var chunk_size: u64 = 0;
        let size_err = parse_chunk_size_hex(chunk_size_line, chunk_size);
        guard size_err == ChunkedDecodeError.None else { return size_err; }

        cursor = line_end + 1;

        if chunk_size == 0 {
            return parse_chunked_trailers(raw, cursor);
        }

        let csize = chunk_size as i64;
        guard cursor + csize + 2 <= raw.len else {
            return ChunkedDecodeError.UnexpectedEof;
        }

        let chunk_data = raw[cursor..cursor + csize];
        out_body.append(chunk_data);
        cursor += csize;

        if raw[cursor] == '\n' {
            return ChunkedDecodeError.BareLfInChunkData;
        }
        guard raw[cursor] == '\r' && raw[cursor + 1] == '\n' else {
            return ChunkedDecodeError.MalformedChunkEnding;
        }
        cursor += 2;
    }

    return ChunkedDecodeError.UnexpectedEof;
}
