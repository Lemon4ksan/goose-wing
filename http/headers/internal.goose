// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for `http` (http/headers/internal.goose).
namespace http_internal;

import std;
import core;
import http.headers.lexical;
import http.headers.perfect_hash;
import http.headers;
import http.headers.wire_internal;

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
    let colon_pos = line.index_of_byte(':');
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
    let trimmed_start = raw_val.trim_lws_start();
    let lws_lead = raw_val.len - trimmed_start.len;
    let val_trimmed = trimmed_start.trim_lws_end();
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

    let val_start_off = (cursor + colon_pos + 1 + lws_lead) as u16;
    let val_end_off = (val_start_off + val_trimmed.len) as u16;

    let flags = well_known_header_flags(wk_id, raw_name);
    let hname = well_known_header_hash(wk_id, raw_name);

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
    let colon_pos = line.index_of_byte(':');
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
    let trimmed_start = raw_val.trim_lws_start();
    let lws_lead = raw_val.len - trimmed_start.len;
    let val_trimmed = trimmed_start.trim_lws_end();
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

    let val_start_off = (cursor + colon_pos + 1 + lws_lead) as u16;
    let val_end_off = (val_start_off + val_trimmed.len) as u16;

    let flags = well_known_header_flags(wk_id, raw_name);
    let hname = well_known_header_hash(wk_id, raw_name);

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
    let is_lead_ws = line.len == 0 || raw_buf[cursor] == ' ' || raw_buf[cursor] == '\t';
    if is_lead_ws {
        if is_line_whitespace_only(line) {
            map.valid = false;
            return http::HeaderParseError.WhitespaceOnlyLine;
        }
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
        let is_lead_ws = line.len == 0 || active_buf[cursor] == ' ' || active_buf[cursor] == '\t';
        if is_lead_ws {
            if is_line_whitespace_only(line) {
                map.valid = false;
                return http::HeaderParseError.WhitespaceOnlyLine;
            }
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

// Checks whether `buf[cursor]` starts an empty CRLF/LF header-block terminator.
// Returns 1 if terminated (advancing `cursor`), 0 if regular header line, -1 on bare CR.
//
// Example:
//   buf = "\r\n", cursor = 0
//   returns: 1, cursor = 2
inline fn consume_empty_header_terminator(buf: const u8[:], cursor: i64&) -> i32 {
    let b = buf[cursor];
    if b == '\r' {
        let next_c = core::add_sat_i64(cursor, 1);
        if next_c < buf.len && buf[next_c] == '\n' {
            cursor = core::add_sat_i64(cursor, 2);
            return 1;
        }
        return -1;
    }
    if b == '\n' {
        cursor = core::add_sat_i64(cursor, 1);
        return 1;
    }
    return 0;
}

// Parses a pre-validated (NUL-free) HTTP/1.x header block into an already-reset `HeaderMap`.
//
// Example:
//   raw_input = "Host: example.com\r\nContent-Length: 0\r\n\r\n", map = HeaderMap { .. }
//   returns: HeaderParseError.None, populates map.entries
fn parse_headers_body_validated(
    raw_input:      const u8[:],
    map:            http::HeaderMap&,
    allow_obs_fold: bool,
    mode:           http::H1ResponseParseMode,
) -> http::HeaderParseError {
    defer if !map.valid {
        http::reset_for_keep_alive(map);
        map.valid = false;
    };
    guard raw_input.len > 0 else { return http::HeaderParseError.EmptyInput; }
    guard map.raw_buf.try_append(raw_input) else { return http::HeaderParseError.CapacityExceeded; }

    var cursor: i64 = 0;
    let buf_len = map.raw_buf.len;
    var is_first_header = true;
    var prev_was_dup_cl = false;

    while cursor < buf_len {
        let term = consume_empty_header_terminator(map.raw_buf[..], cursor);
        if term != 0 {
            if term < 0 { return http::HeaderParseError.InvalidHeaderValue; }
            break;
        }

        let rel_end = find_any(map.raw_buf[cursor..], http::CRLF_SET);
        let line_end = if rel_end >= 0 { core::add_sat_i64(cursor, rel_end) } else { buf_len };
        let line_err = process_header_line(
            map.raw_buf[..], cursor, line_end, allow_obs_fold, map, is_first_header, prev_was_dup_cl, mode,
        );
        guard http::is_ok(line_err) else { return line_err; }
        guard http::advance_crlf(map.raw_buf[..], cursor, line_end) else {
            return http::HeaderParseError.InvalidHeaderValue;
        }
    }

    map.valid = true;
    return http::HeaderParseError.None;
}

fn set_header_sanitized(map: http::HeaderMap&, name: const u8[:], value: const u8[:], is_sensitive: bool) {
    var clean_name: u8[..128]  = [];
    var clean_val:  u8[..4096] = [];
    http::sanitize_header_bytes(name, clean_name);
    http::sanitize_header_bytes(value, clean_val);
    guard clean_name.len > 0 else { return; }
    let _ = http::set_or_replace(map, clean_name[..], clean_val[..], is_sensitive);
}
