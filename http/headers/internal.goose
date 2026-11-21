// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for `http` (http/headers/internal.goose).
namespace http_internal;

import std;
import core;
import http.headers.chunked;
import http.headers.lexical;
import http.headers.perfect_hash;
import http.headers;

// ---- http/headers/chunked.goose internal helpers ----

const H1_HEX_NIBBLE_LUT: const i8[256] = [
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    0, 1, 2, 3, 4, 5, 6, 7, 8, 9, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, 10, 11, 12, 13, 14, 15, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
    -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1, -1,
];

checkfree inline fn h1_read_le_u16(s: const u8[:]) -> u16 {
    if s.len < 2 { return 0; }
    return s[0] | ((s[1] as u16) << 8);
}

checkfree inline fn h1_read_le_u32(s: const u8[:]) -> u32 {
    if s.len < 4 { return 0; }
    let lo: u32 = h1_read_le_u16(s);
    let hi: u32 = h1_read_le_u16(s[2..]);
    return lo | (hi << 16);
}

checkfree inline fn h1_read_le_u64(s: const u8[:]) -> u64 {
    if s.len < 8 { return 0; }
    let lo: u64 = h1_read_le_u32(s);
    let hi: u64 = h1_read_le_u32(s[4..]);
    return lo | (hi << 32);
}

checkfree fn skip_bws(s: const u8[:], cursor: i64&) {
    var pos = cursor;
    guard pos >= 0 else { return; }
    while pos < s.len && (s[pos] == ' ' || s[pos] == '\t') {
        pos++;
    }
    cursor = pos;
}

// Parses a token name in a chunk extension.
// Advances cursor past the name.
//
// Example:
//   s = "ext_name=val", cursor = 0
//   returns: true, cursor = 8
checkfree fn parse_chunk_ext_name(s: const u8[:], cursor: i64&) -> bool {
    var pos = cursor;
    guard pos >= 0 else { return false; }
    let name_start = pos;
    while pos < s.len && http::is_tchar(s[pos]) {
        pos++;
    }
    cursor = pos;
    return pos > name_start;
}

// Parses a parameter value (token or quoted string) in a chunk extension.
//
// Example:
//   s = "token; next", cursor = 0
//   returns: ChunkedDecodeError.None
checkfree fn parse_chunk_ext_param_val(s: const u8[:], cursor: i64&) -> http::ChunkedDecodeError {
    var pos = cursor;
    guard pos >= 0 && pos < s.len else { return http::ChunkedDecodeError.InvalidChunkExtension; }
    if s[pos] == '"' {
        guard http::parse_chunk_ext_quoted_val(s, cursor) else {
            return http::ChunkedDecodeError.InvalidChunkExtension;
        }
        return http::ChunkedDecodeError.None;
    }
    let val_start = pos;
    while pos < s.len && http::is_tchar(s[pos]) {
        pos++;
    }
    cursor = pos;
    guard pos > val_start else {
        return http::ChunkedDecodeError.InvalidChunkExtension;
    }
    return http::ChunkedDecodeError.None;
}

// Parses a single chunk extension parameter: ;name[=val]
// Leaves `cursor` unchanged on error.
//
// Example:
//   s = ";name=val", cursor = 0
//   returns: ChunkedDecodeError.None, cursor = 9
checkfree fn parse_chunk_ext_param(s: const u8[:], cursor: i64&) -> http::ChunkedDecodeError {
    let saved_cursor = cursor;
    var committed = false;
    defer if !committed { cursor = saved_cursor; };

    let pos0 = cursor;
    guard pos0 >= 0 && pos0 < s.len && s[pos0] == ';' else {
        return http::ChunkedDecodeError.InvalidChunkExtension;
    }
    cursor = pos0 + 1; // skip ';'
    skip_bws(s, cursor);

    guard parse_chunk_ext_name(s, cursor) else {
        return http::ChunkedDecodeError.InvalidChunkExtension;
    }
    let after_name = cursor;
    skip_bws(s, cursor);
    // RFC 9112 Section 7.1.1: Chunk Extensions - Reject trailing BWS before CRLF
    let pos1 = cursor;
    guard pos1 == after_name || pos1 < s.len else {
        return http::ChunkedDecodeError.InvalidChunkExtension;
    }

    if pos1 >= 0 && pos1 < s.len && s[pos1] == '=' {
        cursor = pos1 + 1; // skip '='
        skip_bws(s, cursor);
        let val_err = parse_chunk_ext_param_val(s, cursor);
        guard val_err == http::ChunkedDecodeError.None else { return val_err; }
        let after_val = cursor;
        skip_bws(s, cursor);
        guard cursor == after_val || cursor < s.len else {
            return http::ChunkedDecodeError.InvalidChunkExtension;
        }
    }
    committed = true;
    return http::ChunkedDecodeError.None;
}

// Parses hex digits into an integer chunk size.
//
// Example:
//   chunk_size_line = "1a;ext", sig_start = 0, hex_len = 2
//   returns: ChunkedDecodeError.None, out_size = 26
checkfree fn parse_hex_chunk_value(
    chunk_size_line: const u8[:],
    sig_start:       i64,
    hex_len:         i64,
    out_size:        u64&,
) -> http::ChunkedDecodeError {
    guard sig_start >= 0 && sig_start <= hex_len && hex_len <= chunk_size_line.len else {
        return http::ChunkedDecodeError.InvalidChunkSizeHex;
    }
    var chunk_size: u64 = 0;
    for b in chunk_size_line[sig_start..hex_len] {
        let val = H1_HEX_NIBBLE_LUT[b];
        guard val >= 0 else {
            return http::ChunkedDecodeError.InvalidChunkSizeHex;
        }
        if chunk_size > 0x07FFFFFFFFFFFFFF {
            return http::ChunkedDecodeError.ChunkSizeOverflow;
        }
        chunk_size = (chunk_size << 4) | (val as u64);
    }
    out_size = chunk_size;
    return http::ChunkedDecodeError.None;
}

checkfree fn validate_chunk_size_line_chars(chunk_size_line: const u8[:]) -> http::ChunkedDecodeError {
    guard chunk_size_line.len > 0 else {
        return http::ChunkedDecodeError.InvalidChunkSizeHex;
    }
    guard chunk_size_line.len <= 1024 else {
        return http::ChunkedDecodeError.InvalidChunkExtension;
    }
    for b in chunk_size_line {
        if b == '\r' || (b < 0x20 && b != 0x09) || b == 0x7F {
            return http::ChunkedDecodeError.InvalidChunkExtension;
        }
    }
    if chunk_size_line[0] == ' ' || chunk_size_line[0] == '\t' {
        return http::ChunkedDecodeError.InvalidChunkSizeHex;
    }
    return http::ChunkedDecodeError.None;
}

checkfree fn is_hex_char(b: u8) -> bool {
    return (b >= '0' && b <= '9') || (b >= 'a' && b <= 'f') || (b >= 'A' && b <= 'F');
}

// Scans contiguous hex digits from cursor.
//
// Example:
//   s = "1a2b;ext", cursor = 0
//   returns: 4, cursor = 4
checkfree fn scan_hex_digits(s: const u8[:], cursor: i64&) -> i64 {
    var pos = cursor;
    guard pos >= 0 else { return pos; }
    while pos < s.len && is_hex_char(s[pos]) {
        pos++;
    }
    cursor = pos;
    return pos;
}

checkfree fn find_significant_hex_start(s: const u8[:], hex_len: i64) -> i64 {
    let limit = if hex_len < s.len { hex_len } else { s.len };
    guard limit > 0 && limit <= s.len else { return 0; }
    for i in limit {
        if s[i] != '0' {
            return i;
        }
    }
    return limit;
}

// Consumes `chunk_size` data bytes plus trailing CRLF into `out_body`, advancing `cursor` (RFC 9112 §7.1).
// Enforces `http::MAX_CHUNKED_BODY_BYTES` before appending and leaves `cursor` unchanged on error.
//
// Example:
//   raw = "Wiki\r\n", cursor = 0, chunk_size = 4, out_body = []
//   returns: ChunkedDecodeError.None, cursor = 6, out_body = "Wiki"
checkfree fn consume_chunk_data(
    raw:        const u8[:],
    cursor:     i64&,
    chunk_size: u64,
    out_body:   u8[>..]&,
) -> http::ChunkedDecodeError {
    let pos = cursor;
    guard pos >= 0 && pos <= raw.len else {
        return http::ChunkedDecodeError.UnexpectedEof;
    }
    let tail = raw[pos..];
    guard chunk_size <= (tail.len as u64) else {
        return http::ChunkedDecodeError.UnexpectedEof;
    }
    let csize = chunk_size as i64;
    guard csize >= 0 && csize <= tail.len else {
        return http::ChunkedDecodeError.UnexpectedEof;
    }
    guard out_body.len >= 0 && out_body.len <= http::MAX_CHUNKED_BODY_BYTES &&
          csize <= http::MAX_CHUNKED_BODY_BYTES - out_body.len else {
        return http::ChunkedDecodeError.ChunkSizeOverflow;
    }

    let after = tail[csize..];
    if after.len >= 1 && after[0] == '\n' {
        return http::ChunkedDecodeError.BareLfInChunkData;
    }
    guard after.len >= 2 else {
        return http::ChunkedDecodeError.UnexpectedEof;
    }
    guard after[0] == '\r' && after[1] == '\n' else {
        return http::ChunkedDecodeError.MalformedChunkEnding;
    }

    out_body.append(tail[..csize]);
    cursor = pos + csize + 2;
    return http::ChunkedDecodeError.None;
}

// ---- http/headers/lexical.goose internal helpers ----

fn has_embedded_nulls(data: const u8[:]) -> bool {
    return find_any(data, http::NULL_SET) >= 0;
}

// RFC 9110 Section 8.6 & RFC 9112 Section 6.3: Content-Length validation & anti-smuggling parser
//
// Example:
//   s = "1024"
//   returns: true, out_val = 1024
fn parse_cl_digits(s: const u8[:], out_val: i64&) -> bool {
    for b in s {
        guard b >= '0' && b <= '9' else { return false; }
    }
    let num, ok = s.parse_u64_dec();
    guard ok && num <= 9223372036854775807 else { return false; }
    out_val = num as! i64;
    return true;
}

// RFC 9110 Section 5.6.4: Quoted Strings - Validate qdtext and backslash quoted-pair escapes.
//
// Example:
//   v = "\"a\\\"b\"" -> true
//   v = "\"a\\\""    -> false
fn is_valid_rfc9110_quoted_string(v: const u8[:]) -> bool {
    guard v.len >= 2 && v[0] == '"' && core::ends_with(v, "\"") else { return false; }
    var idx: i64 = 1;
    let end = core::sub_sat_i64(v.len, 1);
    while idx < end {
        let b = v[idx];
        if b == '\\' {
            idx = core::add_sat_i64(idx, 1);
            guard idx < end && http::is_valid_header_value_byte(v[idx]) else { return false; }
            idx = core::add_sat_i64(idx, 1);
            continue;
        }
        guard b != '"' && http::is_valid_header_value_byte(b) else { return false; }
        idx = core::add_sat_i64(idx, 1);
    }
    return true;
}

checkfree fn is_line_whitespace_only(line: const u8[:]) -> bool {
    for b in line {
        if b != ' ' && b != '\t' {
            return false;
        }
    }
    return true;
}

// ---- http/headers.goose internal helpers ----

checkfree fn bloom_hash(key: const u8[:]) -> u32 {
    let len = key.len;
    guard len >= 2 else { return 0; }
    let c0 = key[0];
    let c1 = key[len - 1];
    let c2 = key[len - 2];
    let c3 = key[len >> 1];
    let b0:       u32 = if c0 >= 'A' && c0 <= 'Z' { c0 | 0x20 } else { c0 };
    let b1:       u32 = if c1 >= 'A' && c1 <= 'Z' { c1 | 0x20 } else { c1 };
    let b2:       u32 = if c2 >= 'A' && c2 <= 'Z' { c2 | 0x20 } else { c2 };
    let b3:       u32 = if c3 >= 'A' && c3 <= 'Z' { c3 | 0x20 } else { c3 };
    let features: u32 = b0 | (b1 << 8) | (b2 << 16) | (b3 << 24);
    return features * 1843993368;
}

checkfree fn reset_overflow_arena(arena: http::OverflowArena&) {
    arena.spill_raw.clear();
    arena.spill_entries.clear();
    arena.spill_url.clear();
}

checkfree fn well_known_header_name(id: http::WellKnownHeader) -> const u8[:] {
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

fn well_known_header_flags(id: http::WellKnownHeader, name: const u8[:]) -> u8 {
    var flags: u8 = http::HEADER_FLAG_NONE;

    // Cookie & state exceptions
    if id == http::WellKnownHeader.SetCookie ||
       id == http::WellKnownHeader.SetCookie2 ||
       id == http::WellKnownHeader.ClearSiteData {
        flags |= http::HEADER_FLAG_NO_COMMA_FOLD | http::HEADER_FLAG_SENSITIVE | http::HEADER_FLAG_COOKIE_STATE;
        return flags;
    }

    // Authentication challenges
    if id == http::WellKnownHeader.WwwAuthenticate || id == http::WellKnownHeader.ProxyAuthenticate {
        flags |= http::HEADER_FLAG_NO_COMMA_FOLD | http::HEADER_FLAG_SENSITIVE | http::HEADER_FLAG_CHALLENGE;
        if id == http::WellKnownHeader.ProxyAuthenticate {
            flags |= http::HEADER_FLAG_NON_CACHEABLE;
        }
        return flags;
    }

    // Credentials & auth tokens
    if id == http::WellKnownHeader.Authorization ||
       id == http::WellKnownHeader.ProxyAuthorization ||
       id == http::WellKnownHeader.Cookie {
        flags |= http::HEADER_FLAG_SENSITIVE;
    }

    // Security state & prefix matching (Strict-Transport-Security, X-Frame-Options, x-content-*, x-webkit-*)
    let is_sec_id = id == http::WellKnownHeader.StrictTransportSecurity ||
        id == http::WellKnownHeader.XContentTypeOptions ||
        id == http::WellKnownHeader.XFrameOptions ||
        id == http::WellKnownHeader.XWebkitCsp;
    if is_sec_id {
        flags |= http::HEADER_FLAG_SECURITY_STATE;
    } else if name.len >= 10 && (name.starts_with_fold("x-content-") || name.starts_with_fold("x-webkit-")) {
        flags |= http::HEADER_FLAG_SECURITY_STATE;
    } else if name.eq_ascii_fold("x-xss-protection") {
        flags |= http::HEADER_FLAG_SECURITY_STATE;
    }

    // Hop-by-hop non-cacheables (RFC 9110 Section 7.6.1 + proxy-connection)
    if id == http::WellKnownHeader.Connection ||
       id == http::WellKnownHeader.KeepAlive ||
       id == http::WellKnownHeader.TransferEncoding ||
       id == http::WellKnownHeader.TE || id == http::WellKnownHeader.Trailer || id == http::WellKnownHeader.Upgrade ||
       id == http::WellKnownHeader.ProxyAuthorization || id == http::WellKnownHeader.ProxyAuthenticate {
        flags |= http::HEADER_FLAG_NON_CACHEABLE;
    } else if name.eq_ascii_fold("proxy-connection") {
        flags |= http::HEADER_FLAG_NON_CACHEABLE;
    }

    return flags;
}

checkfree fn has_no_comma_fold(entry: const http::HeaderEntry&) -> bool {
    return (entry.flags & http::HEADER_FLAG_NO_COMMA_FOLD) != 0;
}

fn link_header_entry_stack(
    map:      http::HeaderMap&,
    wk_id:    http::WellKnownHeader,
    raw_name: const u8[:],
    hname:    u32,
    new_idx:  u8,
) {
    if wk_id != http::WellKnownHeader.Unknown {
        let slot = http::well_known_to_slot(wk_id);
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
        let pe .= map.entries[prev_i];
        guard pe.name_hash == hname else { continue; }
        let prev_name = map.raw_buf[pe.name_begin..pe.name_end];
        guard prev_name.eq_ascii_fold(raw_name) else { continue; }

        var cur = prev_i as u8;
        while map.entries[cur as i64].next_idx != 0xFF {
            cur = map.entries[cur as i64].next_idx;
        }
        map.entries[cur as i64].next_idx = new_idx;
        break;
    }
}

fn link_header_entry(
    map:      http::HeaderMap&,
    wk_id:    http::WellKnownHeader,
    raw_name: const u8[:],
    hname:    u32,
    new_idx:  u8,
    arena:    const http::OverflowArena& = http::EMPTY_OVERFLOW_ARENA,
) {
    if wk_id != http::WellKnownHeader.Unknown {
        let slot = http::well_known_to_slot(wk_id);
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
        let pe .= map.entries[prev_i];
        guard pe.name_hash == hname else { continue; }
        let prev_name = http::resolve_entry_name(pe, map, arena);
        guard prev_name.eq_ascii_fold(raw_name) else { continue; }

        var cur = prev_i as u8;
        while map.entries[cur as i64].next_idx != 0xFF {
            cur = map.entries[cur as i64].next_idx;
        }
        map.entries[cur as i64].next_idx = new_idx;
        break;
    }
}

fn validate_folded_framing(buf: const u8[:], begin: u16, end: u16, wk: u8) -> bool {
    let host_slot = http::well_known_to_slot(http::WellKnownHeader.Host) as u8;
    if wk == host_slot {
        return false;
    }
    let cl_slot = http::well_known_to_slot(http::WellKnownHeader.ContentLength) as u8;
    let te_slot = http::well_known_to_slot(http::WellKnownHeader.TransferEncoding) as u8;
    if wk == cl_slot {
        let full_cl = buf[begin..end];
        let _, ok_cl = http::validate_content_length_value(full_cl);
        return ok_cl;
    }
    if wk == te_slot {
        let full_te = buf[begin..end];
        return http::validate_transfer_encoding_value(full_te);
    }
    return true;
}

fn handle_obs_fold_stack(
    trimmed_continuation: const u8[:],
    map:                  http::HeaderMap&,
) -> http::HeaderParseError {
    let prev_idx = map.entries.len - 1;
    let orig_begin = map.entries[prev_idx].values_begin;
    let orig_end = map.entries[prev_idx].values_end;
    let orig_val = map.raw_buf[orig_begin..orig_end];

    let needed = orig_val.len + 1 + trimmed_continuation.len;
    guard (map.raw_buf.len + needed) <= map.raw_buf.cap else {
        map.valid = false;
        return http::HeaderParseError.CapacityExceeded;
    }

    let saved_raw_len = map.raw_buf.len;
    var committed = false;
    defer if !committed { map.raw_buf.resize(saved_raw_len); };

    let new_begin = map.raw_buf.len as u16;
    map.raw_buf.append(orig_val);
    map.raw_buf.push(' ');
    map.raw_buf.append(trimmed_continuation);
    let new_end = map.raw_buf.len as u16;

    let prev_wk = map.entries[prev_idx].well_known_id;
    guard validate_folded_framing(map.raw_buf[..], new_begin, new_end, prev_wk) else {
        map.valid = false;
        return http::HeaderParseError.InvalidContentLength;
    }

    map.entries[prev_idx].values_begin = new_begin;
    map.entries[prev_idx].values_end = new_end;
    if trimmed_continuation.contains_byte(',') {
        map.entries[prev_idx].flags |= http::HEADER_FLAG_CONTAINS_COMMA;
        map.header_contains_comma[prev_idx] = true;
    }
    committed = true;
    return http::HeaderParseError.None;
}

fn handle_obs_fold(
    line:   const u8[:],
    policy: http::ObsFoldPolicy,
    map:    http::HeaderMap&,
) -> http::HeaderParseError {
    if policy.is_first_header || map.entries.len == 0 {
        map.valid = false;
        return http::HeaderParseError.LeadingWhitespaceOnFirstHeader;
    }
    guard policy.allow_obs_fold else {
        map.valid = false;
        return http::HeaderParseError.ObsFoldForbidden;
    }

    let trimmed_continuation = line.trim_lws();
    guard http::is_valid_header_value(trimmed_continuation) else {
        map.valid = false;
        return http::HeaderParseError.InvalidHeaderValue;
    }
    return handle_obs_fold_stack(trimmed_continuation, map);
}

fn handle_obs_fold(
    line:   const u8[:],
    policy: http::ObsFoldPolicy,
    map:    http::HeaderMap&,
    arena:  http::OverflowArena&,
) -> http::HeaderParseError {
    let in_spill = arena.spill_entries.len > 0;
    let prev_in_arena = in_spill
        || (map.entries.len > 0 &&
            map.entries[core::sub_sat_i64(map.entries.len, 1)].reserved == http::HEADER_SRC_ARENA);
    if !prev_in_arena {
        return handle_obs_fold(line, policy, map);
    }
    if policy.is_first_header {
        map.valid = false;
        return http::HeaderParseError.LeadingWhitespaceOnFirstHeader;
    }
    guard policy.allow_obs_fold else {
        map.valid = false;
        return http::HeaderParseError.ObsFoldForbidden;
    }

    let trimmed_continuation = line.trim_lws();
    guard http::is_valid_header_value(trimmed_continuation) else {
        map.valid = false;
        return http::HeaderParseError.InvalidHeaderValue;
    }
    return http::handle_obs_fold_arena(trimmed_continuation, map, arena, in_spill);
}

// Parses a single wire header line (name: value) into HeaderMap.
//
// Example:
//   line = "Host: example.com", cursor = 0, map = HeaderMap { .. }, is_dup_cl = false
//   returns: HeaderParseError.None
fn parse_single_header_line(
    line:      const u8[:],
    cursor:    i64,
    map:       http::HeaderMap&,
    is_dup_cl: bool&,
    mode:      http::H1ResponseParseMode = http::H1ResponseParseMode.Strict,
) -> http::HeaderParseError {
    let colon_pos = find_any(line, http::COLON_SET);
    guard colon_pos > 0 else {
        map.valid = false;
        return http::HeaderParseError.InvalidHeaderName;
    }

    var raw_name = line[..colon_pos];
    if mode == http::H1ResponseParseMode.ClientCompat {
        raw_name = raw_name.trim_lws_end();
    } else if raw_name.len > 0 && (raw_name[raw_name.len - 1] == ' ' || raw_name[raw_name.len - 1] == '\t') {
        map.valid = false;
        return http::HeaderParseError.InvalidHeaderName;
    }
    guard http::is_valid_header_name(raw_name) else {
        map.valid = false;
        return http::HeaderParseError.InvalidHeaderName;
    }

    let raw_val = line[colon_pos + 1..];
    let val_trimmed = raw_val.trim_lws();
    guard http::is_valid_header_value(val_trimmed) else {
        map.valid = false;
        return http::HeaderParseError.InvalidHeaderValue;
    }
    guard map.entries.len < 128 else {
        map.valid = false;
        return http::HeaderParseError.CapacityExceeded;
    }

    let wk_id = http::classify_well_known_header(raw_name);
    let conflict_err = http::validate_header_framing_conflicts(map, wk_id, val_trimmed, is_dup_cl);
    guard http::is_ok(conflict_err) else { return conflict_err; }

    guard !is_dup_cl else { return http::HeaderParseError.None; }

    let name_begin_off = cursor as u16;
    let name_end_off = (cursor + raw_name.len) as u16;

    let lws_lead = raw_val.len - raw_val.trim_lws_start().len;
    let val_start_off = (cursor + colon_pos + 1 + lws_lead) as u16;
    let val_end_off = (val_start_off + val_trimmed.len) as u16;

    let flags = well_known_header_flags(wk_id, raw_name);
    let hname = http::hash_header_name(raw_name);

    let contains_comma = val_trimmed.contains_byte(',');
    let entry_flags = if contains_comma { flags | http::HEADER_FLAG_CONTAINS_COMMA } else { flags };

    let new_entry = http::HeaderEntry {
        name_begin:   name_begin_off,
        name_end:     name_end_off,
        values_begin: val_start_off,
        values_end:   val_end_off,
        next_idx:     0xFF,
        flags:        entry_flags,
        well_known_id: if wk_id != http::WellKnownHeader.Unknown {
            http::well_known_to_slot(wk_id) as u8
        } else {
            0xFF
        },
        reserved:  0,
        name_hash: hname,
    };

    let new_idx = map.entries.len as u8;
    link_header_entry(map, wk_id, raw_name, hname, new_idx);
    map.entries.push(new_entry);
    map.header_contains_comma.push(contains_comma);
    return http::HeaderParseError.None;
}

// Parses a single wire header line into HeaderMap or OverflowArena.
//
// Example:
//   line = "Host: example.com", cursor = 0, src_type = HEADER_SRC_STACK
//   returns: HeaderParseError.None
fn parse_single_overflow_header_line(
    line:      const u8[:],
    cursor:    i64,
    map:       http::HeaderMap&,
    arena:     http::OverflowArena&,
    src_type:  u8,
    is_dup_cl: i32&,
) -> http::HeaderParseError {
    is_dup_cl = 0;
    let colon_pos = find_any(line, http::COLON_SET);
    guard colon_pos > 0 else {
        map.valid = false;
        return http::HeaderParseError.InvalidHeaderName;
    }

    let raw_name = line[..colon_pos];
    if raw_name.len > 0 && (raw_name[raw_name.len - 1] == ' ' || raw_name[raw_name.len - 1] == '\t') {
        map.valid = false;
        return http::HeaderParseError.InvalidHeaderName;
    }
    guard http::is_valid_header_name(raw_name) else {
        map.valid = false;
        return http::HeaderParseError.InvalidHeaderName;
    }

    let raw_val = line[colon_pos + 1..];
    let val_trimmed = raw_val.trim_lws();
    guard http::is_valid_header_value(val_trimmed) else {
        map.valid = false;
        return http::HeaderParseError.InvalidHeaderValue;
    }

    let wk_id = http::classify_well_known_header(raw_name);
    var dup_cl_bool = false;
    let conflict_err = http::validate_header_framing_conflicts(map, wk_id, val_trimmed, dup_cl_bool, arena);
    guard http::is_ok(conflict_err) else { return conflict_err; }

    if dup_cl_bool {
        is_dup_cl = 1;
        return http::HeaderParseError.None;
    }

    let name_begin_off = cursor as u16;
    let name_end_off = (cursor + colon_pos) as u16;

    let lws_lead = raw_val.len - raw_val.trim_lws_start().len;
    let val_start_off = (cursor + colon_pos + 1 + lws_lead) as u16;
    let val_end_off = (val_start_off + val_trimmed.len) as u16;

    let flags = well_known_header_flags(wk_id, raw_name);
    let hname = http::hash_header_name(raw_name);

    let contains_comma = val_trimmed.contains_byte(',');
    let entry_flags = if contains_comma { flags | http::HEADER_FLAG_CONTAINS_COMMA } else { flags };

    let new_entry = http::HeaderEntry {
        name_begin:   name_begin_off,
        name_end:     name_end_off,
        values_begin: val_start_off,
        values_end:   val_end_off,
        next_idx:     0xFF,
        flags:        entry_flags,
        well_known_id: if wk_id != http::WellKnownHeader.Unknown {
            http::well_known_to_slot(wk_id) as u8
        } else {
            0xFF
        },
        reserved:  src_type,
        name_hash: hname,
    };

    if map.entries.len < 128 {
        let new_idx = map.entries.len as u8;
        link_header_entry(map, wk_id, raw_name, hname, new_idx, arena);
        map.entries.push(new_entry);
        map.header_contains_comma.push(contains_comma);
    } else {
        guard arena.spill_entries.len < http::MAX_OVERFLOW_SPILL_ENTRIES else {
            map.valid = false;
            return http::HeaderParseError.CapacityExceeded;
        }
        arena.spill_entries.push(new_entry);
    }
    return http::HeaderParseError.None;
}

fn process_header_line(
    raw_buf:         const u8[:],
    cursor:          i64,
    line_end:        i64,
    allow_obs_fold:  bool,
    map:             http::HeaderMap&,
    is_first_header: bool&,
    prev_was_dup_cl: bool&,
    mode:            http::H1ResponseParseMode = http::H1ResponseParseMode.Strict,
) -> http::HeaderParseError {
    let line = raw_buf[cursor..line_end];
    if is_line_whitespace_only(line) {
        map.valid = false;
        return http::HeaderParseError.WhitespaceOnlyLine;
    }

    let is_lead_ws = raw_buf[cursor] == ' ' || raw_buf[cursor] == '\t';
    if is_lead_ws {
        if prev_was_dup_cl {
            map.valid = false;
            return http::HeaderParseError.ObsFoldForbidden;
        }
        let policy = http::ObsFoldPolicy { is_first_header: is_first_header, allow_obs_fold: allow_obs_fold };
        let fold_err = handle_obs_fold(line, policy, map);
        guard http::is_ok(fold_err) else { return fold_err; }
    } else {
        var is_dup_cl = false;
        let line_err = parse_single_header_line(line, cursor, map, is_dup_cl, mode);
        guard http::is_ok(line_err) else { return line_err; }
        if is_dup_cl {
            prev_was_dup_cl = true;
        } else {
            prev_was_dup_cl = false;
            is_first_header = false;
        }
    }
    return http::HeaderParseError.None;
}

// Iterates and parses headers from active_buf into map or arena.
//
// Example:
//   active_buf = "Host: api\r\n\r\n", src_type = HEADER_SRC_STACK
//   returns: HeaderParseError.None
fn parse_overflow_headers_loop(
    active_buf:     const u8[:],
    src_type:       u8,
    map:            http::HeaderMap&,
    arena:          http::OverflowArena&,
    allow_obs_fold: bool,
) -> http::HeaderParseError {
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
            return http::HeaderParseError.InvalidHeaderValue;
        }
        if active_buf[cursor] == '\n' {
            cursor += 1;
            break;
        }

        let rel_end = find_any(active_buf[cursor..], http::CRLF_SET);
        let line_end = if rel_end >= 0 { cursor + rel_end } else { buf_len };
        let line = active_buf[cursor..line_end];

        if is_line_whitespace_only(line) {
            map.valid = false;
            return http::HeaderParseError.WhitespaceOnlyLine;
        }

        let is_lead_ws = active_buf[cursor] == ' ' || active_buf[cursor] == '\t';
        if is_lead_ws {
            if prev_was_dup_cl {
                map.valid = false;
                return http::HeaderParseError.ObsFoldForbidden;
            }
            let policy = http::ObsFoldPolicy { is_first_header: is_first_header, allow_obs_fold: allow_obs_fold };
            let fold_err = handle_obs_fold(line, policy, map, arena);
            guard http::is_ok(fold_err) else { return fold_err; }
        } else {
            var is_dup_cl: i32 = 0;
            let line_err = parse_single_overflow_header_line(line, cursor, map, arena, src_type, is_dup_cl);
            guard http::is_ok(line_err) else { return line_err; }
            if is_dup_cl != 0 {
                prev_was_dup_cl = true;
            } else {
                prev_was_dup_cl = false;
                is_first_header = false;
            }
        }

        guard http::advance_crlf(active_buf, cursor, line_end) else {
            map.valid = false;
            return http::HeaderParseError.InvalidHeaderValue;
        }
    }

    map.valid = true;
    return http::HeaderParseError.None;
}

// Parses an HTTP status line into major/minor versions and status code.
//
// RFC 9112 Section 4: Status Line - reason-phrase = 1*( HTAB / SP / VCHAR / obs-text )
checkfree inline fn is_valid_reason_phrase(s: const u8[:]) -> bool {
    for b in s {
        guard http::is_valid_header_value_byte(b) else { return false; }
    }
    return true;
}

// Parses an ICY Shoutcast compatibility status line (`ICY 200 OK`) into HTTP/1.0 status fields.
//
// Example:
//   status_line = "ICY 200 OK"
//   returns: HeaderParseError.None, major = 1, minor = 0, code = 200
fn parse_icy_status_line(
    status_line: const u8[:],
    major:       i32&,
    minor:       i32&,
    code:        i32&,
) -> http::HeaderParseError {
    let sc_slice = status_line[4..].trim_lws_start();
    guard sc_slice.len >= 3 && (sc_slice.len == 3 || sc_slice[3] == ' ') else {
        return http::HeaderParseError.MalformedStatusLine;
    }
    let sc_val, ok_sc = sc_slice[..3].parse_i32_dec();
    let reason_off = min<i64>(4, sc_slice.len);
    guard ok_sc && sc_val >= 100 && sc_val <= 599 &&
          is_valid_reason_phrase(sc_slice[reason_off..]) else {
        return http::HeaderParseError.MalformedStatusLine;
    }
    major = 1;
    minor = 0;
    code = sc_val;
    return http::HeaderParseError.None;
}

// Example:
//   status_line = "HTTP/1.1 200 OK"
//   returns: HeaderParseError.None, major = 1, minor = 1, code = 200
fn parse_http_status_line(
    status_line: const u8[:],
    major:       i32&,
    minor:       i32&,
    code:        i32&,
    mode:        http::H1ResponseParseMode = http::H1ResponseParseMode.Strict,
) -> http::HeaderParseError {
    if mode == http::H1ResponseParseMode.ClientCompat &&
       status_line.len >= 7 &&
       status_line[..4].eq_ascii_fold("ICY ") {
        return parse_icy_status_line(status_line, major, minor, code);
    }

    let min_len: i64 = if mode == http::H1ResponseParseMode.Strict { 13 } else { 12 };
    guard status_line.len >= min_len && status_line[..5] == "HTTP/" else {
        return http::HeaderParseError.MalformedStatusLine;
    }

    let maj_v, ok_maj = status_line[5..6].parse_i32_dec();
    let min_v, ok_min = status_line[7..8].parse_i32_dec();
    guard status_line[6] == '.' && ok_maj && ok_min && status_line[8] == ' ' else {
        return http::HeaderParseError.MalformedStatusLine;
    }

    var sp_idx: i64 = 9;
    if mode == http::H1ResponseParseMode.Strict {
        guard status_line[12] == ' ' else {
            return http::HeaderParseError.MalformedStatusLine;
        }
    } else {
        while sp_idx < status_line.len && status_line[sp_idx] == ' ' {
            sp_idx = core::add_sat_i64(sp_idx, 1);
        }
        let sc_end_chk = core::add_sat_i64(sp_idx, 3);
        guard sc_end_chk <= status_line.len &&
              (sc_end_chk == status_line.len || status_line[sc_end_chk] == ' ') else {
            return http::HeaderParseError.MalformedStatusLine;
        }
    }

    let sc_end = core::add_sat_i64(sp_idx, 3);
    let sc_val, ok_sc = status_line[sp_idx..sc_end].parse_i32_dec();
    let reason_off = min<i64>(core::add_sat_i64(sp_idx, 4), status_line.len);
    guard ok_sc && sc_val >= 100 && sc_val <= 599 &&
          is_valid_reason_phrase(status_line[reason_off..]) else {
        return http::HeaderParseError.MalformedStatusLine;
    }

    major = maj_v;
    minor = min_v;
    code = sc_val;
    return http::HeaderParseError.None;
}

checkfree inline fn skip_single_preamble_empty_line(raw: const u8[:]) -> i64 {
    if raw.len >= 2 && raw[0] == '\r' && raw[1] == '\n' {
        return 2;
    }
    if raw.len >= 1 && raw[0] == '\n' {
        return 1;
    }
    return 0;
}

checkfree fn resolve_entry_value(
    entry: const http::HeaderEntry&,
    map:   const http::HeaderMap&,
    arena: const http::OverflowArena&,
) -> const u8[:] {
    let b: i64 = entry.values_begin;
    let e: i64 = entry.values_end;
    if entry.reserved == http::HEADER_SRC_ARENA {
        guard b >= 0 && b <= e && e <= arena.spill_raw.len else { return ""; }
        return arena.spill_raw[b..e];
    }
    guard b >= 0 && b <= e && e <= map.raw_buf.len else { return ""; }
    return map.raw_buf[b..e];
}

fn find_entry_in_entries(
    entries: const http::HeaderEntry[:],
    name:    const u8[:],
    hname:   u32,
    map:     const http::HeaderMap&,
    arena:   const http::OverflowArena&,
) -> const u8[:] {
    for &entry in entries {
        if entry.name_hash == hname {
            let entry_name = http::resolve_entry_name(entry, map, arena);
            if entry_name.eq_ascii_fold(name) {
                return resolve_entry_value(entry, map, arena);
            }
        }
    }
    return "";
}

fn calc_entry_match_bytes(raw: const u8[:], e: const http::HeaderEntry&, name: const u8[:]) -> i64 {
    guard e.reserved == http::HEADER_SRC_STACK && e.name_end <= raw.len as u16 else { return -1; }
    let ename = raw[e.name_begin..e.name_end];
    guard ename.eq_ascii_fold(name) else { return -1; }
    return (e.name_end - e.name_begin) + (e.values_end - e.values_begin);
}

fn can_insert_header(map: const http::HeaderMap&, name: const u8[:], value: const u8[:]) -> bool {
    let trimmed = value.trim_lws();
    let needed = name.len + trimmed.len;
    let hname = http::hash_header_name(name);
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

fn try_overwrite_single_header_in_place(
    map:          http::HeaderMap&,
    name:         const u8[:],
    trimmed:      const u8[:],
    is_sensitive: bool,
) -> bool {
    let idx = find_first_header_index(map, "", name);
    guard idx >= 0 && idx < map.entries.len else { return false; }
    let e = map.entries[idx];
    guard e.next_idx == 0xFF && e.reserved == http::HEADER_SRC_STACK else { return false; }
    let old_val_begin = e.values_begin;
    let old_val_end = e.values_end;
    let old_len = (old_val_end - old_val_begin) as i64;
    guard trimmed.len <= old_len else { return false; }

    for k in trimmed.len {
        map.raw_buf[old_val_begin + k] = trimmed[k];
    }
    let new_val_end = old_val_begin + (trimmed.len as u16);
    map.entries[idx].values_end = new_val_end;

    let contains_comma = trimmed.contains_byte(',');
    map.header_contains_comma[idx] = contains_comma;
    if contains_comma {
        map.entries[idx].flags |= http::HEADER_FLAG_CONTAINS_COMMA;
    } else {
        map.entries[idx].flags &= ~http::HEADER_FLAG_CONTAINS_COMMA;
    }
    if is_sensitive || http::is_heuristic_sensitive_header(name) {
        map.entries[idx].flags |= http::HEADER_FLAG_SENSITIVE;
    }

    let shrink_delta = old_val_end - new_val_end;
    if shrink_delta > 0 {
        http::shift_raw_buf_left(map, old_val_end, shrink_delta);
    }
    return true;
}

checkfree inline fn needs_header_byte_sanitization(s: const u8[:]) -> bool {
    for b in s {
        if b == '\r' || b == '\n' || b == 0 {
            return true;
        }
    }
    return false;
}

fn rebuild_inline_slots_and_chains(map: http::HeaderMap&) {
    for i in 64 {
        map.inline_slots[i] = 0xFF;
    }
    for i in map.entries.len {
        map.entries[i].next_idx = 0xFF;
    }
    for i in map.entries.len {
        let idx_u8 = i as u8;
        let wk = map.entries[i].well_known_id;
        if wk != 0xFF && (wk as i64) < 64 {
            let slot = wk as i64;
            let first = map.inline_slots[slot];
            if first == 0xFF {
                map.inline_slots[slot] = idx_u8;
                continue;
            }
            var cur = first;
            while map.entries[cur as i64].next_idx != 0xFF {
                cur = map.entries[cur as i64].next_idx;
            }
            map.entries[cur as i64].next_idx = idx_u8;
            continue;
        }
        let hname = map.entries[i].name_hash;
        let name_i = http::entry_name(map, map.entries[i]);
        guard name_i.len > 0 else { continue; }
        for prev_i in i {
            guard map.entries[prev_i].name_hash == hname else { continue; }
            let name_p = http::entry_name(map, map.entries[prev_i]);
            let match_name = name_p.len > 0 && name_p.eq_ascii_fold(name_i);
            guard match_name else { continue; }
            var cur = prev_i as u8;
            while map.entries[cur as i64].next_idx != 0xFF {
                cur = map.entries[cur as i64].next_idx;
            }
            map.entries[cur as i64].next_idx = idx_u8;
            break;
        }
    }
}

// Resolves the entry index of the first header matching name.
fn find_first_header_index(
    map:  const http::HeaderMap&,
    raw:  const u8[:],
    name: const u8[:],
) -> i64 {
    let wk_id = http::classify_well_known_header(name);
    if wk_id != http::WellKnownHeader.Unknown {
        let slot = http::well_known_to_slot(wk_id);
        let first = map.inline_slots[slot];
        if first != 0xFF && first < map.entries.len {
            return first;
        }
        return -1;
    }

    let hname = http::hash_header_name(name);
    for i in map.entries.len {
        let e .= map.entries[i];
        guard e.name_hash == hname else { continue; }
        let ename = if raw.len > 0 && e.name_end <= raw.len {
            raw[e.name_begin..e.name_end]
        } else {
            map.raw_buf[e.name_begin..e.name_end]
        };
        if ename.eq_ascii_fold(name) {
            return i;
        }
    }
    return -1;
}

fn append_folded_header_values(
    map:       const http::HeaderMap&,
    start_idx: i64,
    entry:     const http::HeaderEntry&,
    name:      const u8[:],
    visited:   bool[128]&,
    out:       u8[>..]&,
) {
    var first = true;
    // RFC 6265 Section 5.4: The Cookie Header - Join multiple Cookie fields with "; "
    let sep: const u8[:] = if name.eq_ascii_fold("cookie") { "; " } else { ", " };
    for j in start_idx..map.entries.len {
        let other .= map.entries[j];
        guard other.name_hash == entry.name_hash else { continue; }
        let other_name = map.raw_buf[other.name_begin..other.name_end];
        guard other_name.eq_ascii_fold(name) else { continue; }
        if !first {
            out.append(sep);
        }
        first = false;
        let val = map.raw_buf[other.values_begin..other.values_end];
        out.append(val);
        visited[j] = true;
    }
}

fn should_update_header_304(entry_flags: u8, name: const u8[:]) -> bool {
    // RFC 9110 Section 15.4.5, RFC 9111 Section 3.2 & Chromium HttpResponseHeaders::ShouldUpdateHeader
    // Never update cookies, auth challenges, security state, or hop-by-hop headers
    let blocked_flags = http::HEADER_FLAG_COOKIE_STATE | http::HEADER_FLAG_CHALLENGE |
        http::HEADER_FLAG_SECURITY_STATE | http::HEADER_FLAG_NON_CACHEABLE;
    if (entry_flags & blocked_flags) != 0 {
        return false;
    }
    if name.eq_ascii_fold("content-range") ||
       name.eq_ascii_fold("content-length") ||
       name.eq_ascii_fold("content-encoding") ||
       name.eq_ascii_fold("content-type") ||
       name.eq_ascii_fold("content-md5") ||
       name.eq_ascii_fold("content-language") ||
       name.eq_ascii_fold("content-location") {
        return false;
    }
    return true;
}
