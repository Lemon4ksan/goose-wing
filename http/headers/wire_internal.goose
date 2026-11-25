// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for `http` (http/headers/wire_internal.goose).
namespace http_internal;

import std;
import core;
import http.headers.chunked;
import http.headers.lexical;
import http.headers.perfect_hash;
import http.headers;

// ---- http/headers/chunked.goose internal helpers ----

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
    let total = s.len;
    guard pos >= 0 else { return; }
    while pos < total && (s[pos] == ' ' || s[pos] == '\t') {
        pos += 1;
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
    let total = s.len;
    guard pos >= 0 else { return false; }
    let name_start = pos;
    while pos < total && core::is_tchar(s[pos]) {
        pos += 1;
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
    let total = s.len;
    guard pos >= 0 && pos < total else { return http::ChunkedDecodeError.InvalidChunkExtension; }
    if s[pos] == '"' {
        guard http::parse_chunk_ext_quoted_val(s, cursor) else {
            return http::ChunkedDecodeError.InvalidChunkExtension;
        }
        return http::ChunkedDecodeError.None;
    }
    let val_start = pos;
    while pos < total && core::is_tchar(s[pos]) {
        pos += 1;
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
    cursor = core::add_sat_i64(pos0, 1); // skip ';'
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
        cursor = core::add_sat_i64(pos1, 1); // skip '='
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
        let val = core::hex_digit_to_val(b);
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

// Scans contiguous hex digits from cursor.
//
// Example:
//   s = "1a2b;ext", cursor = 0
//   returns: 4, cursor = 4
checkfree fn scan_hex_digits(s: const u8[:], cursor: i64&) -> i64 {
    var pos = cursor;
    let total = s.len;
    guard pos >= 0 else { return pos; }
    while pos < total && core::is_ascii_hexdigit(s[pos]) {
        pos += 1;
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
          csize <= core::sub_sat_i64(http::MAX_CHUNKED_BODY_BYTES, out_body.len) else {
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
    cursor = core::add_sat_i64(core::add_sat_i64(pos, csize), 2);
    return http::ChunkedDecodeError.None;
}

// ---- http/headers/lexical.goose internal helpers ----

fn has_embedded_nulls(data: const u8[:]) -> bool {
    return data.contains_byte(0);
}

// RFC 9110 Section 8.6 & RFC 9112 Section 6.3: Content-Length validation & anti-smuggling parser
//
// Example:
//   s = "1024"
//   returns: true, out_val = 1024
fn parse_cl_digits(s: const u8[:], out_val: i64&) -> bool {
    let num, ok = s.parse_u64_dec();
    guard ok && num <= 0x7FFFFFFFFFFFFFFF else { return false; }
    out_val = num as i64;
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

// Maps a `WellKnownHeader` variant to its canonical lowercase wire name.
checkfree fn well_known_header_name(id: http::WellKnownHeader) -> const u8[:] {
    let slot = http::well_known_to_slot(id);
    return if slot >= 0 && slot < 63 { http::WELL_KNOWN_HEADER_NAMES[slot] } else { "" };
}

const WELL_KNOWN_HEADER_FLAGS_LUT: const u8[64] = [
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 2, 130, 35,
    163, 2, 19, 19, 19, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 128, 128, 128, 128,
    128, 128, 0, 0, 0, 0, 64, 0,
    64, 64, 64, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0,
];

const WELL_KNOWN_HEADER_HASH_LUT: const u32[64] = [
    0xAFFEA56F, 0xFCF70995, 0x4DF9451D, 0xE7D03E5C,
    0x03E2ED88, 0x017D1113, 0x893B4C2E, 0xD3ECFA4A,
    0x08247E29, 0xDA645C68, 0xC9715A99, 0x75F67716,
    0x6625CF66, 0x913657BE, 0xA01F18BB, 0x2E7BCF02,
    0xA17EDAEF, 0x77A740BF, 0x6E2BE738, 0x791CB4BE,
    0xC7663AD1, 0x50C8A4CD, 0x2C41499C, 0x3E8EC783,
    0xD472DC59, 0x06C857C0, 0xD67076EA, 0x972B6177,
    0x83E879A9, 0xE230478A, 0x8B887E3E, 0xC0575A6B,
    0x0BF5A9A6, 0xFADC0CD2, 0x40ABDE45, 0x69122C13,
    0x38B99ED9, 0xE18EDB80, 0xDDB4744C, 0x3C453EB2,
    0x816FEDE0, 0xDC97CC77, 0x24259BEE, 0x40AC3DD2,
    0xEC9AF966, 0xD97F9A4F, 0xF6A71E21, 0x5D85A5DC,
    0xD93B89C9, 0xEE0D1548, 0x211BF35B, 0xA1937BEC,
    0x35B4CA8C, 0x5ADB24C0, 0x81A75FAC, 0x92055AA9,
    0x9C6EFBCE, 0xD68CC290, 0x9011AF27, 0x80154303,
    0xC6DA1376, 0x94E4E309, 0x96DA6B58, 0x00000000,
];

inline fn well_known_header_flags(id: http::WellKnownHeader, name: const u8[:]) -> u8 {
    let slot = http::well_known_to_slot(id);
    if slot >= 0 && slot < 63 {
        return WELL_KNOWN_HEADER_FLAGS_LUT[slot];
    }
    if name.len >= 10 && (name.starts_with_fold("x-content-") || name.starts_with_fold("x-webkit-")) {
        return http::HEADER_FLAG_SECURITY_STATE;
    }
    if name.len == 16 && name.eq_ascii_fold("x-xss-protection") {
        return http::HEADER_FLAG_SECURITY_STATE;
    }
    if name.len == 16 && name.eq_ascii_fold("proxy-connection") {
        return http::HEADER_FLAG_NON_CACHEABLE;
    }
    return http::HEADER_FLAG_NONE;
}

inline fn well_known_header_hash(id: http::WellKnownHeader, name: const u8[:]) -> u32 {
    let slot = http::well_known_to_slot(id);
    if slot >= 0 && slot < 63 {
        return WELL_KNOWN_HEADER_HASH_LUT[slot];
    }
    return http::hash_header_name(name);
}

checkfree fn has_no_comma_fold(entry: const http::HeaderEntry&) -> bool {
    return (entry.flags & http::HEADER_FLAG_NO_COMMA_FOLD) != 0;
}

fn link_header_entry(
    map:       http::HeaderMap&,
    wk_id:     http::WellKnownHeader,
    raw_name:  const u8[:],
    hname:     u32,
    new_idx:   u8,
    spill_raw: const u8[:] = "",
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
        let prev_name = http::resolve_entry_name_buf(map.raw_buf[..], spill_raw, pe);
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
    let prev_idx = core::sub_sat_i64(map.entries.len, 1);
    let orig_begin = map.entries[prev_idx].values_begin;
    let orig_end = map.entries[prev_idx].values_end;
    let orig_val = map.raw_buf[orig_begin..orig_end];

    let needed = core::add_sat_i64(core::add_sat_i64(orig_val.len, 1), trimmed_continuation.len);
    guard core::add_sat_i64(map.raw_buf.len, needed) <= map.raw_buf.cap else {
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

fn validate_obs_fold_continuation(
    line:           const u8[:],
    policy:         http::ObsFoldPolicy,
    has_prev_entry: bool,
    map:            http::HeaderMap&,
) -> const u8[:], http::HeaderParseError {
    if policy.is_first_header || !has_prev_entry {
        map.valid = false;
        return "", http::HeaderParseError.LeadingWhitespaceOnFirstHeader;
    }
    guard policy.allow_obs_fold else {
        map.valid = false;
        return "", http::HeaderParseError.ObsFoldForbidden;
    }
    let trimmed = line.trim_lws();
    guard http::is_valid_header_value(trimmed) else {
        map.valid = false;
        return "", http::HeaderParseError.InvalidHeaderValue;
    }
    return trimmed, http::HeaderParseError.None;
}

fn handle_obs_fold(
    line:   const u8[:],
    policy: http::ObsFoldPolicy,
    map:    http::HeaderMap&,
) -> http::HeaderParseError {
    let trimmed, err = validate_obs_fold_continuation(line, policy, map.entries.len > 0, map);
    guard err == http::HeaderParseError.None else { return err; }
    return handle_obs_fold_stack(trimmed, map);
}

fn handle_obs_fold(
    line:   const u8[:],
    policy: http::ObsFoldPolicy,
    map:    http::HeaderMap&,
    arena:  http::OverflowArena&,
) -> http::HeaderParseError {
    let in_spill = arena.spill_entries.len > 0;
    let prev_in_arena = in_spill
        || (map.entries.len > 0 && map.entries[map.entries.len - 1].reserved == http::HEADER_SRC_ARENA);
    if !prev_in_arena {
        return handle_obs_fold(line, policy, map);
    }
    let trimmed, err = validate_obs_fold_continuation(line, policy, true, map);
    guard err == http::HeaderParseError.None else { return err; }
    return http::handle_obs_fold_arena(trimmed, map, arena, in_spill);
}
