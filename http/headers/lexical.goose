// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP header lexical validation, SWAR scanning, and framing checks (RFC 9110, RFC 9112, RFC 9113).
namespace wing;

import std;
import core from "../..";

let CRLF_BYTES: const u8[2] = ['\r', '\n'];
let CRLF_SET:   ByteSet     = byte_set(CRLF_BYTES[..]);

let COLON_BYTES: const u8[1] = [':'];
let COLON_SET:   ByteSet     = byte_set(COLON_BYTES[..]);

let NULL_BYTES: const u8[1] = [0];
let NULL_SET:   ByteSet     = byte_set(NULL_BYTES[..]);

// ---- lexical validation & fast word operations -----------------------------

extern fn native_swar_to_lower_64(v: u64) -> u64 = "wing_swar_to_lower_64";
extern fn native_swar_to_lower(slice: u8[:]) = "wing_swar_to_lower";

// 64-bit SWAR parallel ASCII lowercase (Alex Hultman / uWebSockets HttpParser.h)
// Evaluates 8 ASCII bytes in parallel, translating 'A'..'Z' to 'a'..'z' in 4 CPU cycles without branches.
fn swar_to_lower_64(v: u64) -> u64 {
    let ascii = v & 0x7F7F7F7F7F7F7F7F;
    let not_high = ~v & 0x8080808080808080;
    let is_upper = (ascii + 0x3F3F3F3F3F3F3F3F) & ~(ascii + 0x2525252525252525) & not_high;
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

// Header presence bitmask constants (O(1) duplicate & smuggling detector, aligned with header_id_to_bit)
const HDR_PRESENCE_NONE:              u32 = 0;
const HDR_PRESENCE_HOST:              u32 = 0x0002;
const HDR_PRESENCE_DATE:              u32 = 0x0004;
const HDR_PRESENCE_ACCEPT:            u32 = 0x0008;
const HDR_PRESENCE_COOKIE:            u32 = 0x0010;
const HDR_PRESENCE_ORIGIN:            u32 = 0x0020;
const HDR_PRESENCE_SERVER:            u32 = 0x0040;
const HDR_PRESENCE_CONNECTION:        u32 = 0x0080;
const HDR_PRESENCE_USER_AGENT:        u32 = 0x0100;
const HDR_PRESENCE_CONTENT_TYPE:      u32 = 0x0200;
const HDR_PRESENCE_CONTENT_LENGTH:    u32 = 0x0400;
const HDR_PRESENCE_AUTHORIZATION:     u32 = 0x0800;
const HDR_PRESENCE_TRANSFER_ENCODING: u32 = 0x1000;
const HDR_PRESENCE_SEC_WEBSOCKET_KEY: u32 = 0x2000;
const HDR_PRESENCE_UPGRADE:           u32 = 0x4000;
const HDR_PRESENCE_EXPECT:            u32 = 0x8000;
const HDR_PRESENCE_SMUGGLING_MASK:    u32 = 0x0400 | 0x1000;

struct HeaderPresenceTracker {
    mask:                   u32  = 0,
    host_idx:               i16  = -1,
    cl_idx:                 i16  = -1,
    te_idx:                 i16  = -1,
    conn_idx:               i16  = -1,
    upgrade_idx:            i16  = -1,
    parsed_cl:              i64  = -1,
    has_duplicate_host:     bool = false,
    has_duplicate_cl:       bool = false,
    has_duplicate_te:       bool = false,
    has_smuggling_conflict: bool = false,
}

// Tracks header presence and detects duplicates/smuggling in O(1) via bitmask (uWebSockets pattern)
fn track_known_header_presence(
    tracker: HeaderPresenceTracker&,
    id:      KnownHeaderId,
    val:     const u8[:],
    hdr_idx: i16,
) -> bool {
    return match id {
        Host => {
            if (tracker.mask & HDR_PRESENCE_HOST) != 0 {
                tracker.has_duplicate_host = true;
                return false; // RFC 9112 Section 3.2: Duplicate Host MUST be rejected immediately!
            }
            tracker.mask |= HDR_PRESENCE_HOST;
            tracker.host_idx = hdr_idx;
            true
        },
        ContentLength => {
            var parsed_val: i64 = 0;
            guard validate_content_length_value(val, parsed_val) else { return false; }
            if (tracker.mask & HDR_PRESENCE_CONTENT_LENGTH) != 0 {
                tracker.has_duplicate_cl = true;
                guard tracker.parsed_cl < 0 || tracker.parsed_cl == parsed_val else { return false; }
            } else {
                tracker.mask |= HDR_PRESENCE_CONTENT_LENGTH;
                tracker.cl_idx = hdr_idx;
                tracker.parsed_cl = parsed_val;
            }
            if (tracker.mask & HDR_PRESENCE_SMUGGLING_MASK) == HDR_PRESENCE_SMUGGLING_MASK {
                tracker.has_smuggling_conflict = true;
                return false;
            }
            true
        },
        TransferEncoding => {
            if (tracker.mask & HDR_PRESENCE_TRANSFER_ENCODING) != 0 {
                tracker.has_duplicate_te = true;
                return false;
            }
            guard validate_transfer_encoding_value(val) else { return false; }
            tracker.mask |= HDR_PRESENCE_TRANSFER_ENCODING;
            tracker.te_idx = hdr_idx;
            if (tracker.mask & HDR_PRESENCE_SMUGGLING_MASK) == HDR_PRESENCE_SMUGGLING_MASK {
                tracker.has_smuggling_conflict = true;
                return false;
            }
            true
        },
        Connection => {
            tracker.mask |= HDR_PRESENCE_CONNECTION;
            tracker.conn_idx = hdr_idx;
            true
        },
        Upgrade => {
            tracker.mask |= HDR_PRESENCE_UPGRADE;
            tracker.upgrade_idx = hdr_idx;
            true
        },
        _ => {
            tracker.mask |= header_id_to_bit(id);
            true
        },
    };
}

inline fn track_header_presence(
    tracker: HeaderPresenceTracker&,
    name:    const u8[:],
    val:     const u8[:],
    hdr_idx: i16,
) -> bool {
    let id = identify_known_header(name);
    return track_known_header_presence(tracker, id, val, hdr_idx);
}

const TCHAR_LUT: const bool[256] = [
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, true, false, true, true, true, true, true, false, false, true, true, false, true, true, false,
    true, true, true, true, true, true, true, true, true, true, false, false, false, false, false, false,
    false, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, false, false, false, true, true,
    true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, false, true, false, true, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
];

checkfree inline fn is_tchar(b: u8) -> bool {
    return TCHAR_LUT[b];
}

const HEADER_VAL_LUT: const bool[256] = [
    false, false, false, false, false, false, false, false, false, true, false, false, false, false, false, false,
    false, false, false, false, false, false, false, false, false, false, false, false, false, false, false, false,
    true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, false,
    true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
    true, true, true, true, true, true, true, true, true, true, true, true, true, true, true, true,
];

checkfree inline fn is_valid_header_value_byte(b: u8) -> bool {
    return HEADER_VAL_LUT[b];
}

const HTTP_METHOD_CONN_LE:   u32 = 0x4E4E4F43; // "CONN"
const HTTP_METHOD_ECT_SP_LE: u32 = 0x20544345; // "ECT "
const HTTP_METHOD_OPTI_LE:   u32 = 0x4954504F; // "OPTI"
const HTTP_METHOD_ONS_SP_LE: u32 = 0x20534E4F; // "ONS "
const HTTP_METHOD_TRAC_LE:   u32 = 0x43415254; // "TRAC"
const HTTP_METHOD_PATC_LE:   u32 = 0x43544150; // "PATC"

// RFC 9112 Section 3: Request Line - Matches common HTTP methods via 32-bit little-endian integer bitcasting.
// Returns (method_slice, consumed_len_including_space, ok).
//
// Example:
//   raw = "GET /index.html HTTP/1.1\r\n"
//   returns: "GET", 4, true
fn match_http_method_u32(raw: const u8[:]) -> const u8[:], i64, bool {
    guard raw.len >= 4 else { return "", 0, false; }
    let w = core::read_le_u32(raw, 0);
    if w == rfc::METHOD_GET_U32 || w == rfc::METHOD_PUT_U32 {
        return raw[0..3], 4, true;
    }
    if w == rfc::METHOD_POST_U32 || w == rfc::METHOD_HEAD_U32 {
        guard raw.len >= 5 && raw[4] == ' ' else { return "", 0, false; }
        return raw[0..4], 5, true;
    }
    if w == HTTP_METHOD_TRAC_LE {
        guard raw.len >= 6 && raw[4] == 'E' && raw[5] == ' ' else { return "", 0, false; }
        return raw[0..5], 6, true;
    }
    if w == HTTP_METHOD_PATC_LE {
        guard raw.len >= 6 && raw[4] == 'H' && raw[5] == ' ' else { return "", 0, false; }
        return raw[0..5], 6, true;
    }
    if w == rfc::METHOD_DELE_U32 {
        guard raw.len >= 7 && raw[4] == 'T' && raw[5] == 'E' && raw[6] == ' ' else { return "", 0, false; }
        return raw[0..6], 7, true;
    }
    if w == HTTP_METHOD_CONN_LE {
        guard raw.len >= 8 && core::read_le_u32(raw, 4) == HTTP_METHOD_ECT_SP_LE else { return "", 0, false; }
        return raw[0..7], 8, true;
    }
    if w == HTTP_METHOD_OPTI_LE {
        guard raw.len >= 8 && core::read_le_u32(raw, 4) == HTTP_METHOD_ONS_SP_LE else { return "", 0, false; }
        return raw[0..7], 8, true;
    }
    return "", 0, false;
}

// RFC 9110 Section 5.6.2: Tokens - Validates an 8-byte SWAR chunk of tchar bytes.
inline fn is_valid_token_word_swar(src: const u8[:], i: i64) -> bool {
    let w = core::read_le_u64(src, i);
    guard !core::swar_has_ctl_or_del(w) && !core::swar_has_byte(w, ' ') && !core::swar_has_byte(w, ':') else {
        return false;
    }
    guard is_tchar(src[i]) && is_tchar(src[i + 1]) && is_tchar(src[i + 2]) && is_tchar(src[i + 3]) else {
        return false;
    }
    guard is_tchar(src[i + 4]) && is_tchar(src[i + 5]) && is_tchar(src[i + 6]) && is_tchar(src[i + 7]) else {
        return false;
    }
    return true;
}

// RFC 9110 Section 5.6.2: Tokens - Validates an HTTP token using 8-byte SWAR chunks and TCHAR_LUT.
fn is_valid_token_swar(src: const u8[:]) -> bool {
    guard src.len > 0 else { return false; }
    var i: i64 = 0;
    while i + 8 <= src.len {
        guard is_valid_token_word_swar(src, i) else { return false; }
        i += 8;
    }
    while i < src.len {
        guard is_tchar(src[i]) else { return false; }
        i += 1;
    }
    return true;
}

// RFC 9110 Section 5.6.2: Tokens - Scans a valid token prefix using 8-byte SWAR acceleration.
//
// Example:
//   src = "Content-Length: 42\r\n"
//   returns: 14, true
fn scan_token_swar(src: const u8[:]) -> i64, bool {
    guard src.len > 0 else { return 0, false; }
    var i: i64 = 0;
    while i + 8 <= src.len {
        if !is_valid_token_word_swar(src, i) {
            break;
        }
        i += 8;
    }
    while i < src.len && is_tchar(src[i]) {
        i += 1;
    }
    guard i > 0 else { return 0, false; }
    return i, true;
}

fn is_valid_header_name(name: const u8[:]) -> bool {
    guard name.len > 0 && name.len <= 8192 else { return false; }
    return is_valid_token_swar(name);
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
        guard is_valid_header_value_byte(b) else { return false; }
    }
    return true;
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

fn validate_content_length_value(val: const u8[:], out_val: i64&) -> bool {
    let trimmed = val.trim_lws();
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
    var cursor:     i64 = 0;

    while cursor < trimmed.len {
        var comma_idx = cursor;
        while comma_idx < trimmed.len && trimmed[comma_idx] != ',' {
            comma_idx++;
        }

        let piece = trimmed[cursor..comma_idx].trim_lws();
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
            guard idx < end && is_valid_header_value_byte(v[idx]) else { return false; }
            idx = core::add_sat_i64(idx, 1);
            continue;
        }
        guard b != '"' && is_valid_header_value_byte(b) else { return false; }
        idx = core::add_sat_i64(idx, 1);
    }
    return true;
}

// RFC 9112 Section 7: Validates a transfer-coding element (e.g. "chunked", "gzip", "identity", "gzip;q=1.0").
// transfer-coding = token *( OWS ";" OWS transfer-parameter )
fn is_valid_transfer_coding(coding: const u8[:]) -> bool {
    let trimmed = coding.trim_lws();
    guard trimmed.len > 0 else { return false; }

    let semi_idx = trimmed.find_unquoted_byte(';');
    let name = trimmed[..semi_idx].trim_lws();
    guard name.len > 0 && is_valid_token_swar(name) else { return false; }

    // RFC 9112 Section 6.1: Reject unrecognized transfer codings (must be chunked, gzip, deflate, compress, br, zstd, or identity)
    let is_known = name.eq_ascii_fold("chunked") ||
                   name.eq_ascii_fold("gzip") ||
                   name.eq_ascii_fold("deflate") ||
                   name.eq_ascii_fold("compress") ||
                   name.eq_ascii_fold("br") ||
                   name.eq_ascii_fold("zstd") ||
                   name.eq_ascii_fold("identity");
    guard is_known else { return false; }

    // RFC 9112 Section 7.1: chunked transfer-coding has no parameters
    if name.eq_ascii_fold("chunked") {
        return semi_idx == trimmed.len;
    }

    // If parameters present, validate transfer-parameter = token BWS "=" BWS ( token / quoted-string )
    guard semi_idx < trimmed.len else { return true; }
    var rem = trimmed[semi_idx + 1..];
    while rem.len > 0 {
        let p_end = rem.find_unquoted_byte(';');
        let p_str = rem[..p_end].trim_lws();
        guard p_str.len > 0 else { return false; }
        let k_raw, v_raw, has_eq = p_str.split_once_byte('=');
        guard has_eq else { return false; }
        let k = k_raw.trim_lws();
        let v = v_raw.trim_lws();
        guard k.len > 0 && v.len > 0 && is_valid_token_swar(k) else { return false; }
        let ok_val = if v[0] == '"' { is_valid_rfc9110_quoted_string(v) } else { is_valid_token_swar(v) };
        guard ok_val else { return false; }
        if p_end >= rem.len { break; }
        rem = rem[p_end + 1..];
    }

    return true;
}

// Validates a Transfer-Encoding header value (RFC 9112 Section 6.1, Section 7.1 & uWebSockets #1941 / #1943).
// Allows comma-separated list of transfer codings (e.g. gzip, identity, br, deflate),
// but requires that 'chunked' (case-insensitive) be the final coding and appear exactly once.
fn validate_transfer_encoding_value(val: const u8[:]) -> bool {
    let trimmed = val.trim_lws();
    guard trimmed.len > 0 else { return false; }
    guard trimmed[0] != ',' && trimmed[trimmed.len - 1] != ',' else { return false; }

    var cursor:        i64 = 0;
    var count:         i32 = 0;
    var chunked_count: i32 = 0;
    var last_is_chunked = false;

    while cursor <= trimmed.len {
        let comma_idx = cursor + trimmed[cursor..].find_unquoted_byte(',');
        let piece = trimmed[cursor..comma_idx].trim_lws();
        guard piece.len > 0 && is_valid_transfer_coding(piece) else { return false; }

        let semi_idx = piece.find_unquoted_byte(';');
        let coding_name = piece[..semi_idx].trim_lws();

        let is_chunked = coding_name.eq_ascii_fold("chunked");
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
    if cursor == buf_len {
        return true;
    }
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
    return false;
}

// Scans header field name characters up to ':' or whitespace, validating RFC 9110 tchars.
// Returns consumed length up to delimiter, and ok = true if valid and stopped at ':'.
//
// Example:
//   src = "Host: example.com\r\n"
//   returns: 4, ok = true (points to ':')
fn scan_header_field_name_swar(src: const u8[:]) -> i64, bool {
    guard src.len > 0 else { return 0, false; }
    var i: i64 = 0;
    while core::add_sat_i64(i, 8) <= src.len {
        if !is_valid_token_word_swar(src, i) {
            break;
        }
        i = core::add_sat_i64(i, 8);
    }
    while i < src.len {
        let b = src[i];
        if b == ':' {
            guard i > 0 else { return 0, false; }
            return i, true;
        }
        guard is_tchar(b) else { return 0, false; }
        i = core::add_sat_i64(i, 1);
    }
    return 0, false;
}

// Scans header field value characters up to CRLF or LF, validating RFC 9110 field values.
// Returns (consumed_val_len, crlf_len, ok).
//
// Example:
//   src = "example.com\r\nNext: val"
//   returns: 11, 2, ok = true
fn scan_header_field_value_swar(src: const u8[:]) -> i64, i64, bool {
    var i: i64 = 0;
    while i + 8 <= src.len {
        let w = core::read_le_u64(src, i);
        if core::swar_has_ctl_or_del(w) || core::swar_has_byte(w, '\r') || core::swar_has_byte(w, '\n') {
            break;
        }
        i += 8;
    }
    while i < src.len {
        let b = src[i];
        if b == '\r' {
            guard i + 1 < src.len && src[i + 1] == '\n' else { return 0, 0, false; }
            return i, 2, true;
        }
        if b == '\n' {
            return i, 1, true;
        }
        if b < 0x20 {
            guard b == 0x09 else { return 0, 0, false; }
        } else if b == 0x7F {
            return 0, 0, false;
        }
        i++;
    }
    return 0, 0, false;
}

// Checks whether a semicolon-separated quality parameter string (`;q=0`, `;q=0.000`) sets q=0 (RFC 9110 §12.4.2).
fn is_zero_qvalue(params: const u8[:]) -> bool {
    var rem = params;
    while rem.len > 0 {
        let head, _, tail = rem.partition_byte(';');
        rem = tail;
        let item = head.trim_lws();
        if item.starts_with_fold("q=") {
            let qv = item[2..].trim_lws();
            if qv == "0" || qv == "0." || qv == "0.0" || qv == "0.00" || qv == "0.000" {
                return true;
            }
        }
    }
    return false;
}
