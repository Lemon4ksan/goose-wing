// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal HPACK dynamic table mechanics and HTTP/2 header validation helpers.
namespace h2_internal;

import std;
import core;
import rfc.h2;
import http.headers;
import .framing;
import .hpack;
import .hpack_tables_internal;

// ---- HPACK Dynamic Table & Validation Helpers ----------------------------

// Computes an 8-bit direct-mapped slot index (0..255) for an HPACK (name, val) pair.
checkfree inline fn compute_hpack_hash_slot(name: const u8[:], val: const u8[:]) -> u8 {
    let h = core::fnv1a_32(name) ^ core::rotl32(core::fnv1a_32(val), 13);
    return ((h ^ (h >> 8) ^ (h >> 16)) & 0xFF) as u8;
}

// Advances the monotonic generation counter, skipping 0 (reserved for empty/invalidated slots).
checkfree inline fn next_hpack_generation(dt: http2::DynamicTable&) -> u8 {
    let g = dt.next_generation;
    let next_g: u8 = if g == 255 { 1 } else { core::add_sat_u32(g, 1) as u8 };
    dt.next_generation = next_g;
    return if g > 1 { g } else { 1 };
}

// Invalidates any hash table slot pointing to an evicted ring index & generation in O(1).
checkfree inline fn invalidate_hpack_hash_entry(
    dt:       http2::DynamicTable&,
    ring_idx: u64,
    entry:    const http2::HpackHeaderField&,
) {
    let slot = entry.hash_slot;
    let encoded_ref = core::add_sat_u64(ring_idx, 1) as u16;
    if dt.hash_table.slots[slot] == encoded_ref && dt.hash_table.generations[slot] == entry.generation {
        dt.hash_table.slots[slot] = 0;
        dt.hash_table.generations[slot] = 0;
    }
}

// Evicts the oldest entry from the dynamic table and updates arena_tail & hash generations.
checkfree fn evict_oldest_entry(dt: http2::DynamicTable&) {
    guard dt.count > 0 else { return; }
    let head_u = dt.head & HPACK_RING_MASK;
    let head_i = head_u as i64;
    guard head_i >= 0 && head_i < 128 else { return; }
    let oldest .= dt.entries[head_i];
    let oldest_size = oldest.meta_size;
    invalidate_hpack_hash_entry(dt, head_u, oldest);
    dt.used_bytes = core::sub_sat_u64(dt.used_bytes, oldest_size);
    let next_u = core::add_sat_u64(head_u, 1) & HPACK_RING_MASK;
    dt.head = next_u;
    dt.count = core::sub_sat_u64(dt.count, 1);
    if dt.count == 0 {
        dt.arena_head = 0;
        dt.arena_tail = 0;
        dt.arena_write_pos = 0;
    } else {
        let next_i = next_u as i64;
        if next_i >= 0 && next_i < 128 {
            dt.arena_tail = dt.entries[next_i].name_off;
        }
    }
}

// RFC 7541 Section 2.3.2: Dynamic Table - O(1)-amortized FIFO boundary eviction.
checkfree fn evict_overlapping_arena_range(dt: http2::DynamicTable&, write_start: u32, write_end: u32) {
    while dt.count > 0 {
        let head_i = (dt.head & HPACK_RING_MASK) as i64;
        guard head_i >= 0 && head_i < 128 else { return; }
        let entry .= dt.entries[head_i];
        let old_start = entry.name_off;
        let old_end = core::add_sat_u32(entry.val_off, entry.val_len);
        let overlaps = (old_start < write_end) &&
            (old_end > write_start || (old_end == old_start && old_start >= write_start));
        guard overlaps else { return; }
        evict_oldest_entry(dt);
    }
}

checkfree inline fn pack_header_into_arena(dt: http2::DynamicTable&, name: const u8[:], val: const u8[:]) -> u32, u32 {
    let n_len = name.len;
    let v_len = val.len;
    let name_off = dt.arena_write_pos as i64;
    let val_off = core::add_sat_i64(name_off, n_len);
    let end_off = core::add_sat_i64(val_off, v_len);
    guard name_off >= 0 && val_off >= name_off && end_off >= val_off && end_off <= 4096 else {
        return 0, 0;
    }
    let dst_name = dt.arena[name_off..val_off];
    if dst_name.len == n_len {
        for i in n_len {
            dst_name[i] = name[i];
        }
    }
    let dst_val = dt.arena[val_off..end_off];
    if dst_val.len == v_len {
        for i in v_len {
            dst_val[i] = val[i];
        }
    }
    dt.arena_head = name_off as u32;
    dt.arena_write_pos = end_off as u32;
    return name_off as u32, val_off as u32;
}

// RFC 7541 Section 2.3.2: Dynamic Table - Direct-mapped O(1) hash lookup on HpackHashTable.
// Returns (slot_entry_ref, has_active_slot).
checkfree fn hpack_hash_lookup(tbl: const http2::HpackHashTable&, name: const u8[:], val: const u8[:]) -> u16, bool {
    let slot = compute_hpack_hash_slot(name, val);
    let entry_ref = tbl.slots[slot];
    let gen = tbl.generations[slot];
    guard entry_ref > 0 && gen > 0 else { return 0, false; }
    return entry_ref, true;
}

// RFC 7541 Section 2.3.2: Dynamic Table - Verifies O(1) direct-mapped hash hit against the dynamic table
// using constant-time byte equality (`core::ct_eq_bytes`) and generation validation, returning the
// external HPACK index (>= 62) on exact match.
fn hpack_hash_lookup(dt: const http2::DynamicTable&, name: const u8[:], val: const u8[:]) -> u16, bool {
    guard dt.count > 0 else { return 0, false; }
    let slot = compute_hpack_hash_slot(name, val);
    let entry_ref = dt.hash_table.slots[slot];
    let slot_gen = dt.hash_table.generations[slot];
    guard entry_ref > 0 && slot_gen > 0 else { return 0, false; }

    let ring_idx = core::sub_sat_u64(entry_ref, 1);
    guard ring_idx < HPACK_MAX_RING_ENTRIES else { return 0, false; }
    let dist = core::sub_sat_u64(core::add_sat_u64(ring_idx, HPACK_MAX_RING_ENTRIES), dt.head) & HPACK_RING_MASK;
    guard dist < dt.count else { return 0, false; }

    let entry .= dt.entries[ring_idx];
    guard entry.generation == slot_gen && !entry.never_index else { return 0, false; }

    let n_end = core::add_sat_u64(entry.name_off, entry.name_len);
    let v_end = core::add_sat_u64(entry.val_off, entry.val_len);
    let entry_name = dt.arena[entry.name_off..n_end];
    let entry_val = dt.arena[entry.val_off..v_end];

    guard core::ct_eq_bytes(entry_name, name) && core::ct_eq_bytes(entry_val, val) else {
        return 0, false;
    }

    let offset_from_newest = core::sub_sat_u64(core::sub_sat_u64(dt.count, 1), dist);
    return core::add_sat_u64(62, offset_from_newest) as u16, true;
}

// Looks up an external dynamic index (idx >= 62).
checkfree fn lookup_dynamic_index(dt: const http2::DynamicTable&, external_idx: u64) -> http2::HpackHeaderField, bool {
    guard external_idx >= 62 else { return http2::HpackHeaderField { .. }, false; }
    let offset = core::sub_sat_u64(external_idx, 62);
    guard offset < dt.count else { return http2::HpackHeaderField { .. }, false; }

    let tail = core::sub_sat_u64(core::add_sat_u64(dt.head, dt.count), 1);
    let pos = (core::sub_sat_u64(tail, offset) & HPACK_RING_MASK) as i64;
    guard pos >= 0 && pos < 128 else { return http2::HpackHeaderField { .. }, false; }
    return dt.entries[pos], true;
}

// Fetches indexed header name slice directly without buffer copying.
checkfree fn get_indexed_header_name_slice(dt: const http2::DynamicTable&, idx: u64) -> const u8[:], bool {
    guard idx >= 1 else { return "", false; }

    if idx <= rfc::HPACK_STATIC_TABLE_ENTRIES {
        let s, ok = get_hpack_static_field(idx);
        guard ok else { return "", false; }
        return s.name, true;
    }

    let entry, ok = lookup_dynamic_index(dt, idx);
    guard ok else { return "", false; }

    let n_off = entry.name_off as i64;
    let n_end = core::add_sat_i64(n_off, entry.name_len);
    guard n_off >= 0 && n_off <= n_end && n_end <= 4096 else { return "", false; }
    return dt.arena[n_off..n_end], true;
}

fn validate_h2_field_name(name: const u8[:]) -> bool {
    guard name.len > 0 else { return false; }

    let start: i64 = if name[0] == ':' { 1 } else { 0 };
    guard start < name.len else { return false; }

    for c in name[start..] {
        // Rejects uppercase 'A'..'Z' and non-tchar characters (RFC 9113 §8.2.1 & RFC 9110 §5.6.2)
        if (c >= 'A' && c <= 'Z') || !core::is_tchar(c) {
            return false;
        }
    }
    return true;
}

fn validate_h2_field_value(val: const u8[:]) -> bool {
    guard val.len > 0 else { return true; }
    let head = val[0];
    let tail = val[core::sub_sat_i64(val.len, 1)];
    if head == ' ' || head == '\t' || tail == ' ' || tail == '\t' {
        return false;
    }
    guard !val.contains_byte(0x7F) else { return false; }
    let ctl_idx = core::swar_find_ctl(val);
    if ctl_idx < val.len {
        for b in val[ctl_idx..] {
            if b < 0x20 && b != '\t' {
                return false;
            }
        }
    }
    return true;
}

checkfree inline fn is_forbidden_authority_byte(b: u8) -> bool {
    return b <= 0x20 || b >= 0x7F || b == '/' || b == '?' || b == '#' || b == '@' || b == ','
        || b == '\\' || b == '"' || b == '<' || b == '>' || b == '^' || b == '`'
        || b == '{' || b == '|' || b == '}';
}

checkfree inline fn is_forbidden_path_byte(b: u8) -> bool {
    return b <= 0x20 || b >= 0x7F || b == '#' || b == '<' || b == '>' || b == '"'
        || b == '\\' || b == '^' || b == '{' || b == '|' || b == '}';
}

fn is_valid_h2_token(val: const u8[:]) -> bool {
    guard val.len > 0 else { return false; }
    for b in val {
        guard core::is_tchar(b) else { return false; }
    }
    return true;
}

fn validate_pseudo_status_code(pseudo: const http2::PseudoHeaders&, val: const u8[:]) -> i32, u32 {
    let sc, ok_sc = val.parse_i32_dec();
    guard val.len == 3 && ok_sc && sc >= 100 && sc <= 599 && sc != 101 else {
        return 0, rfc::H2_ERR_PROTOCOL_ERROR;
    }
    guard !pseudo.has_method && !pseudo.has_scheme && !pseudo.has_path
          && !pseudo.has_protocol && !pseudo.has_authority else {
        return 0, rfc::H2_ERR_PROTOCOL_ERROR;
    }
    return sc, rfc::H2_ERR_NO_ERROR;
}

checkfree fn validate_pseudo_path(val: const u8[:], pseudo: const http2::PseudoHeaders&) -> u32 {
    guard http2::is_valid_path(val) else { return rfc::H2_ERR_PROTOCOL_ERROR; }
    if val.len == 1 && val[0] == '*' {
        guard !pseudo.has_method || pseudo.method[..] == "OPTIONS" else {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
    }
    return rfc::H2_ERR_NO_ERROR;
}

fn validate_content_length_pseudo(pseudo: http2::PseudoHeaders&, val: const u8[:]) -> u32 {
    guard val.len > 0 && val.len <= 19 else { return rfc::H2_ERR_PROTOCOL_ERROR; }
    let parsed_u, ok_u = val.parse_u64_dec();
    guard ok_u && parsed_u <= 9223372036854775807 else { return rfc::H2_ERR_PROTOCOL_ERROR; }
    let parsed_len = parsed_u as i64;
    if pseudo.has_content_length {
        guard pseudo.content_length_val == parsed_len else { return rfc::H2_ERR_PROTOCOL_ERROR; }
    } else {
        pseudo.has_content_length = true;
        pseudo.content_length_val = parsed_len;
    }
    return rfc::H2_ERR_NO_ERROR;
}

fn validate_h2_host_header(
    pseudo:      const http2::PseudoHeaders&,
    out_headers: const http::HeaderMap&,
    val:         const u8[:],
) -> u32 {
    guard val.len > 0 else { return rfc::H2_ERR_PROTOCOL_ERROR; }
    for b in val {
        guard !is_forbidden_authority_byte(b) else { return rfc::H2_ERR_PROTOCOL_ERROR; }
    }
    guard !http::has_header(out_headers, "host") else { return rfc::H2_ERR_PROTOCOL_ERROR; }
    if pseudo.has_authority {
        guard pseudo.authority[..].eq_ascii_fold(val) else {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
    }
    return rfc::H2_ERR_NO_ERROR;
}

// RFC 9113 Section 8.2.2: Connection-Specific Header Fields - Rejects forbidden hop-by-hop headers.
inline fn is_forbidden_h2_hop_by_hop(name: const u8[:]) -> bool {
    return match name.len {
        7 => name == "upgrade",
        10 => name == "connection" || name == "keep-alive",
        16 => name == "proxy-connection",
        17 => name == "transfer-encoding",
        _ => false,
    };
}

// RFC 9110 Section 6.5.1: Limitations on Use of Trailers - Rejects framing/routing fields in trailers.
inline fn is_forbidden_h2_trailer(name: const u8[:]) -> bool {
    return name == "content-length" || name == "host" || name == "trailer" || name == "te"
        || is_forbidden_h2_hop_by_hop(name) || rfc::is_disallowed_trailer_field(name);
}

// RFC 9113 Section 8.2.2: TE header field is forbidden in responses and must equal "trailers" in requests.
inline fn validate_h2_te_header(pseudo: const http2::PseudoHeaders&, val: const u8[:]) -> u32 {
    if pseudo.has_status || val != "trailers" {
        return rfc::H2_ERR_PROTOCOL_ERROR;
    }
    return rfc::H2_ERR_NO_ERROR;
}

fn validate_regular_header_to_map(
    pseudo:      http2::PseudoHeaders&,
    out_headers: const http::HeaderMap&,
    name:        const u8[:],
    val:         const u8[:],
) -> u32 {
    if pseudo.is_trailer {
        guard !is_forbidden_h2_trailer(name) else { return rfc::H2_ERR_PROTOCOL_ERROR; }
    }
    guard !is_forbidden_h2_hop_by_hop(name) else { return rfc::H2_ERR_PROTOCOL_ERROR; }

    let err_reg: u32 = match name.len {
        2 => if name == "te" { validate_h2_te_header(pseudo, val) } else { rfc::H2_ERR_NO_ERROR },
        4 => if name == "host" { validate_h2_host_header(pseudo, out_headers, val) } else { rfc::H2_ERR_NO_ERROR },
        14 => if name == "content-length" { validate_content_length_pseudo(pseudo, val) } else { rfc::H2_ERR_NO_ERROR },
        _ => rfc::H2_ERR_NO_ERROR,
    };
    guard err_reg == rfc::H2_ERR_NO_ERROR else { return err_reg; }

    pseudo.has_regular_header = true;
    return rfc::H2_ERR_NO_ERROR;
}

inline fn validate_h2_field_by_origin(
    name:   const u8[:],
    val:    const u8[:],
    origin: http2::FieldOrigin,
) -> bool {
    return match origin {
        StaticBoth => true,
        StaticName => validate_h2_field_value(val),
        Wire => http2::validate_field_syntax(name, val),
    };
}

enum CookieJoinStatus {
    NotCookie,
    Joined,
    Overflow,
}

// RFC 9113 Section 8.2.3: Compressing the Cookie Header Field - Concatenates extra cookie fields with "; ".
fn join_existing_cookie(
    out_headers: http::HeaderMap&,
    name:        const u8[:],
    val:         const u8[:],
) -> CookieJoinStatus {
    guard name.eq_ascii_fold("cookie") && http::has_header(out_headers, "cookie") else {
        return CookieJoinStatus.NotCookie;
    }
    let prev = http::get_header(out_headers, "cookie");
    var combined: u8[..8192] = [];
    guard combined.try_append(prev) && combined.try_append("; ") && combined.try_append(val) else {
        return CookieJoinStatus.Overflow;
    }
    if http::insert_header(out_headers, "cookie", combined[..]) {
        return CookieJoinStatus.Joined;
    }
    return CookieJoinStatus.Overflow;
}

fn append_decoded_header_to_map(
    out_pseudo:           http2::PseudoHeaders&,
    out_headers:          http::HeaderMap&,
    name:                 const u8[:],
    val:                  const u8[:],
    max_header_list_size: u32,
    validate_http2_rules: bool,
    origin:               http2::FieldOrigin = http2::FieldOrigin.Wire,
) -> u32 {
    let field_size = core::add_sat_u64(core::add_sat_u64(name.len as u64, val.len as u64), 32);
    let next_wireframe = core::add_sat_u64(out_pseudo.wireframe_size, field_size);
    guard next_wireframe <= max_header_list_size else {
        out_pseudo.wireframe_size = min(next_wireframe, 0xFFFFFFFF) as u32;
        return rfc::H2_ERR_ENHANCE_YOUR_CALM;
    }
    out_pseudo.wireframe_size = next_wireframe as u32;
    if name.len > 0 && name[0] == ':' {
        if validate_http2_rules && !validate_h2_field_by_origin(name, val, origin) {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
        return http2::validate_and_record_pseudo_header(out_pseudo, name, val, validate_http2_rules);
    }
    return http2::validate_header_ordering_and_rules(
        out_pseudo,
        out_headers,
        name,
        val,
        validate_http2_rules,
        origin,
    );
}

checkfree inline fn hpack_indexed_origin(idx: u64) -> http2::FieldOrigin {
    return if idx <= rfc::HPACK_STATIC_TABLE_ENTRIES {
        http2::FieldOrigin.StaticBoth
    } else {
        http2::FieldOrigin.Wire
    };
}

// Applies an HPACK dynamic table size update instruction at `offset` (RFC 7541 Section 6.3).
//
// Example:
//   src = [0x20], offset = 0, updates_allowed = true, update_count = 0
//   returns: next_offset = 1, error_code = ERR_NO_ERROR, update_count = 1
fn decode_hpack_table_size_update(
    dt:              http2::DynamicTable&,
    src:             const u8[:],
    offset:          u64,
    updates_allowed: bool,
    update_count:    u32&,
) -> u64, u32 {
    guard updates_allowed && update_count < 16 else {
        return offset, rfc::H2_ERR_COMPRESSION_ERROR;
    }
    update_count = core::add_sat_u64(update_count, 1) as u32;

    let new_size, next_off, ok_size = http2::hpack_decode_int(src, offset, 5);
    guard ok_size && http2::update_dynamic_table_max_size(dt, new_size) else {
        return offset, rfc::H2_ERR_COMPRESSION_ERROR;
    }
    if dt.pending_size_update_req && new_size <= dt.pending_min_table_size {
        dt.pending_size_update_req = false;
    }
    return next_off, rfc::H2_ERR_NO_ERROR;
}

// Decodes a single HPACK field using caller-supplied scratch buffers into `out_pseudo` and `out_headers`.
//
// Example:
//   src = [0x82], offset = 0, name_buf = [], val_buf = []
//   returns: next_offset = 1, error_code = ERR_NO_ERROR, out_pseudo.method = "GET"
fn decode_hpack_field_step_with_scratch(
    dt:                   http2::DynamicTable&,
    src:                  const u8[:],
    offset:               u64,
    updates_allowed:      bool&,
    update_count:         u32&,
    out_pseudo:           http2::PseudoHeaders&,
    out_headers:          http::HeaderMap&,
    max_header_list_size: u32,
    validate_http2_rules: bool,
    name_buf:             u8[..256]&,
    val_buf:              u8[..8192]&,
) -> u64, u32 {
    let b = src[offset];
    if (b & 0xE0) != 0x20 {
        // RFC 7541 Section 4.2: Maximum Table Size - Reject missing or oversized dynamic table size update.
        guard !dt.pending_size_update_req && dt.current_max_size <= dt.max_allowed_size else {
            return offset, rfc::H2_ERR_COMPRESSION_ERROR;
        }
    }

    // 1. Indexed Header Field Representation: 1xxxxxxx (7-bit prefix)
    if (b & 0x80) != 0 {
        updates_allowed = false;
        let idx, next_off, ok_int = http2::hpack_decode_int(src, offset, 7);
        guard ok_int && idx != 0 else { return offset, rfc::H2_ERR_COMPRESSION_ERROR; }

        let name_slice, val_slice, ok_get = http2::get_indexed_header_slices(dt, idx);
        guard ok_get else { return offset, rfc::H2_ERR_COMPRESSION_ERROR; }

        let origin = hpack_indexed_origin(idx);
        let err = append_decoded_header_to_map(
            out_pseudo,
            out_headers,
            name_slice,
            val_slice,
            max_header_list_size,
            validate_http2_rules,
            origin,
        );
        return next_off, err;
    }

    // 2. Literal Header Field with Incremental Indexing: 01xxxxxx (6-bit prefix)
    if (b & 0xC0) == 0x40 {
        updates_allowed = false;
        name_buf.clear();
        val_buf.clear();
        let val_next_off, name_slice, origin, err_dec = http2::decode_literal_field_slices(
            dt,
            src,
            offset,
            6,
            name_buf,
            val_buf,
        );
        guard err_dec == rfc::H2_ERR_NO_ERROR else { return offset, err_dec; }

        http2::insert_header(dt, name_slice, val_buf[..], false);
        let err = append_decoded_header_to_map(
            out_pseudo,
            out_headers,
            name_slice,
            val_buf[..],
            max_header_list_size,
            validate_http2_rules,
            origin,
        );
        return val_next_off, err;
    }

    // 3. Dynamic Table Size Update: 001xxxxx (5-bit prefix)
    if (b & 0xE0) == 0x20 {
        return decode_hpack_table_size_update(dt, src, offset, updates_allowed, update_count);
    }

    // 4. Literal Header without Indexing (0000xxxx) or Never Indexed (0001xxxx)
    updates_allowed = false;
    name_buf.clear();
    val_buf.clear();
    let val_next_off, name_slice, origin, err_dec = http2::decode_literal_field_slices(
        dt,
        src,
        offset,
        4,
        name_buf,
        val_buf,
    );
    guard err_dec == rfc::H2_ERR_NO_ERROR else { return offset, err_dec; }

    let err = append_decoded_header_to_map(
        out_pseudo,
        out_headers,
        name_slice,
        val_buf[..],
        max_header_list_size,
        validate_http2_rules,
        origin,
    );
    return val_next_off, err;
}

inline fn is_valid_connect_port(port_slice: const u8[:]) -> bool {
    guard port_slice.len >= 1 && port_slice.len <= 5 else { return false; }
    for c in port_slice {
        guard core::is_ascii_digit(c) else { return false; }
    }
    let port, ok = port_slice.parse_u32_dec();
    return ok && port >= 1 && port <= 65535;
}

inline fn is_valid_connect_ipv6_authority(auth: const u8[:]) -> bool {
    let ipv6_body, tail, has_close = auth[1..].split_once_byte(']');
    guard has_close && ipv6_body.len > 0 && tail.len >= 2 && tail[0] == ':' else {
        return false;
    }
    for b in ipv6_body {
        let ok = core::is_ascii_hexdigit(b) || b == ':' || b == '.';
        guard ok else { return false; }
    }
    return is_valid_connect_port(tail[1..]);
}

// RFC 9113 Section 8.5: The CONNECT Method - Validates authority-form `host:port` for standard CONNECT.
fn is_valid_connect_authority(auth: const u8[:]) -> bool {
    guard auth.len >= 3 else { return false; }
    if auth[0] == '[' {
        return is_valid_connect_ipv6_authority(auth);
    }
    let host, port_slice, has_colon = auth.rsplit_once_byte(':');
    guard has_colon && host.len > 0 else { return false; }
    guard !host.contains_byte(':') && !host.contains_byte('[') && !host.contains_byte(']') else {
        return false;
    }
    return is_valid_connect_port(port_slice);
}

fn find_hpack_dynamic_field(dt: const http2::DynamicTable&, name: const u8[:], val: const u8[:]) -> u64, bool {
    var d_match_idx: u64 = 0;
    var i:           u64 = 0;
    while i < dt.count {
        let ext_idx = core::add_sat_u64(62, i);
        i = core::add_sat_u64(i, 1);
        let entry, ok_e = lookup_dynamic_index(dt, ext_idx);
        guard ok_e && !entry.never_index else { continue; }
        let t_name, t_val, ok_get = http2::get_indexed_header_slices(dt, ext_idx);
        guard ok_get && core::ct_eq_bytes(t_name, name) else { continue; }
        if core::ct_eq_bytes(t_val, val) {
            return ext_idx, true;
        }
        if d_match_idx == 0 {
            d_match_idx = ext_idx;
        }
    }
    return d_match_idx, false;
}

inline fn is_hpack_volatile_header(name: const u8[:]) -> bool {
    return name.eq_ascii_fold(":path") ||
           name.eq_ascii_fold("age") ||
           name.eq_ascii_fold("content-length") ||
           name.eq_ascii_fold("etag") ||
           name.eq_ascii_fold("if-modified-since") ||
           name.eq_ascii_fold("if-none-match") ||
           name.eq_ascii_fold("location") ||
           name.eq_ascii_fold("set-cookie");
}
