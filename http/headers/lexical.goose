// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP header lexical validation, SWAR scanning, and framing checks (RFC 9110, RFC 9112, RFC 9113).
namespace wing;

import std;

let CRLF_BYTES: const u8[2] = ['\r', '\n'];
let CRLF_SET: ByteSet = byte_set(CRLF_BYTES[..]);

let COLON_BYTES: const u8[1] = [':'];
let COLON_SET: ByteSet = byte_set(COLON_BYTES[..]);

let NULL_BYTES: const u8[1] = [0];
let NULL_SET: ByteSet = byte_set(NULL_BYTES[..]);

// ---- lexical validation & fast word operations -----------------------------

extern fn native_swar_to_lower_64(v: u64) -> u64 = "wing_swar_to_lower_64";
extern fn native_swar_to_lower(slice: u8[:]) = "wing_swar_to_lower";

// 64-bit SWAR parallel ASCII lowercase (Alex Hultman / uWebSockets HttpParser.h)
// Evaluates 8 ASCII bytes in parallel, translating 'A'..'Z' to 'a'..'z' in 4 CPU cycles without branches.
fn swar_to_lower_64(v: u64) -> u64 {
    let is_upper = (v + 0x3F3F3F3F3F3F3F3F) & ~(v + 0x2525252525252525) & 0x8080808080808080;
    return v | (is_upper >> 2);
}

// In-place SWAR/vectorized lowercase for header names and values
fn swar_to_lower(slice: u8[:]) {
    guard slice.len > 0 else { return; }
    native_swar_to_lower(slice);
}

// Fast-path header field byte lowercasing matching uWebSockets isFieldNameByteFastLowercased
inline fn is_field_name_byte_fast_lowercased(b: u8&) -> bool {
    if (b >= 'a' && b <= 'z') || b == '-' {
        return true;
    }
    if b >= 'A' && b <= 'Z' {
        b |= 32;
        return true;
    }
    return is_tchar(b);
}

// Header presence bitmask constants (O(1) duplicate & smuggling detector)
const HDR_PRESENCE_NONE: u32 = 0;
const HDR_PRESENCE_HOST: u32 = 1 << 0;
const HDR_PRESENCE_CONTENT_LENGTH: u32 = 1 << 1;
const HDR_PRESENCE_TRANSFER_ENCODING: u32 = 1 << 2;
const HDR_PRESENCE_CONNECTION: u32 = 1 << 3;
const HDR_PRESENCE_UPGRADE: u32 = 1 << 4;
const HDR_PRESENCE_SEC_WEBSOCKET_KEY: u32 = 1 << 5;
const HDR_PRESENCE_SMUGGLING_MASK: u32 = (1 << 1) | (1 << 2);

struct HeaderPresenceTracker {
    mask: u32 = 0,
    host_idx: i16 = -1,
    cl_idx: i16 = -1,
    te_idx: i16 = -1,
    conn_idx: i16 = -1,
    upgrade_idx: i16 = -1,
    parsed_cl: i64 = -1,
    has_duplicate_host: bool = false,
    has_duplicate_cl: bool = false,
    has_smuggling_conflict: bool = false,
}

fn new_header_presence_tracker() -> HeaderPresenceTracker {
    return HeaderPresenceTracker { .. };
}

// Tracks header presence and detects duplicates/smuggling in O(1) via bitmask (uWebSockets pattern)
fn track_header_presence(
    tracker: HeaderPresenceTracker&,
    name: const u8[:],
    val: const u8[:],
    hdr_idx: i16,
) -> bool {
    if eq_ascii_fold(name, "host") {
        if (tracker.mask & HDR_PRESENCE_HOST) != 0 {
            tracker.has_duplicate_host = true;
            return false; // RFC 9112 Section 3.2: Duplicate Host MUST be rejected immediately!
        }
        tracker.mask |= HDR_PRESENCE_HOST;
        tracker.host_idx = hdr_idx;
        return true;
    }

    if eq_ascii_fold(name, "content-length") {
        if (tracker.mask & HDR_PRESENCE_CONTENT_LENGTH) != 0 {
            tracker.has_duplicate_cl = true;
            // Check identical duplicate
            var parsed_val: i64 = 0;
            if validate_content_length_value(val, parsed_val) {
                if tracker.parsed_cl >= 0 && tracker.parsed_cl != parsed_val {
                    return false; // Conflicting Content-Length values -> smuggling
                }
            } else {
                return false;
            }
        } else {
            tracker.mask |= HDR_PRESENCE_CONTENT_LENGTH;
            tracker.cl_idx = hdr_idx;
            var parsed_val: i64 = 0;
            if validate_content_length_value(val, parsed_val) {
                tracker.parsed_cl = parsed_val;
            }
        }
        if (tracker.mask & HDR_PRESENCE_SMUGGLING_MASK) == HDR_PRESENCE_SMUGGLING_MASK {
            tracker.has_smuggling_conflict = true;
            return false;
        }
        return true;
    }

    if eq_ascii_fold(name, "transfer-encoding") {
        tracker.mask |= HDR_PRESENCE_TRANSFER_ENCODING;
        tracker.te_idx = hdr_idx;
        if (tracker.mask & HDR_PRESENCE_SMUGGLING_MASK) == HDR_PRESENCE_SMUGGLING_MASK {
            tracker.has_smuggling_conflict = true;
            return false;
        }
        return true;
    }

    if eq_ascii_fold(name, "connection") {
        tracker.mask |= HDR_PRESENCE_CONNECTION;
        tracker.conn_idx = hdr_idx;
        return true;
    }

    if eq_ascii_fold(name, "upgrade") {
        tracker.mask |= HDR_PRESENCE_UPGRADE;
        tracker.upgrade_idx = hdr_idx;
        return true;
    }

    return true;
}

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

// RFC 9110 Section 8.6 & RFC 9112 Section 6.3: Content-Length validation & anti-smuggling parser
fn parse_cl_digits(s: const u8[:], out_val: i64&) -> bool {
    for b in s {
        guard b >= '0' && b <= '9' else { return false; }
    }
    let num, ok = core::parse_u64_dec(s);
    guard ok && num <= 9223372036854775807 else { return false; }
    out_val = num as! i64;
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

// RFC 9112 Section 7: Validates a transfer-coding element (e.g. "chunked", "gzip", "identity", "gzip;q=1.0").
// transfer-coding = token *( OWS ";" OWS transfer-parameter )
fn is_valid_transfer_coding(coding: const u8[:]) -> bool {
    let trimmed = trim_lws(coding);
    guard trimmed.len > 0 else { return false; }

    var semi_idx: i64 = 0;
    while semi_idx < trimmed.len && trimmed[semi_idx] != ';' {
        semi_idx++;
    }

    let name = trim_lws(trimmed[..semi_idx]);
    guard name.len > 0 else { return false; }
    for b in name {
        guard is_tchar(b) else { return false; }
    }

    // RFC 9112 Section 7.1: chunked transfer-coding has no parameters
    if eq_ascii_fold(name, "chunked") {
        return semi_idx == trimmed.len;
    }

    // If parameters present, ensure valid characters (no control chars or CRLF)
    if semi_idx < trimmed.len {
        for b in trimmed[semi_idx..] {
            if b < 0x20 && b != 0x09 { return false; }
            if b == 0x7F { return false; }
        }
    }

    return true;
}

// Validates a Transfer-Encoding header value (RFC 9112 Section 6.1, Section 7.1 & uWebSockets #1941 / #1943).
// Allows comma-separated list of transfer codings (e.g. gzip, identity, br, deflate),
// but requires that 'chunked' (case-insensitive) be the final coding and appear exactly once.
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

        var semi_idx: i64 = 0;
        while semi_idx < piece.len && piece[semi_idx] != ';' {
            semi_idx++;
        }
        let coding_name = trim_lws(piece[..semi_idx]);

        let is_chunked = eq_ascii_fold(coding_name, "chunked");
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
    guard chunked_count == 1 else { return false; }
    // RFC 9112 Section 6.1: If present in a request, chunked must be the final encoding
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

// ---- wire parser lexical helpers -------------------------------------------

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
