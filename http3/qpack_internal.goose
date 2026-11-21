// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal QPACK arena management, eviction, unacked section tracking, and field-line decoders.
namespace h3_internal;

import std;
import core from "..";
import rfc.h3_quic;
import http.headers;
import .internal;
import .types;
import .qpack_codec;

// ---- Dynamic Table Arena & Eviction ----------------------------------------

// Compacts dynamic table arena in place to reclaim space from evicted entries.
fn qpack_compact_arena(tbl: http3::QpackTable&) {
    var new_arena: u8[16384] = [0; 16384];
    var new_pos:   u32       = 0;
    for &e in tbl.entries {
        let n_len = e.name_len as u32;
        let v_len = e.val_len as u32;
        let old_n_off = e.name_off as i64;
        let old_v_off = e.val_off as i64;
        let new_pos_i = new_pos as i64;

        for j in (n_len as i64) {
            new_arena[new_pos_i + j] = tbl.arena[old_n_off + j];
        }
        e.name_off = new_pos;
        new_pos += n_len;

        let next_pos_i = new_pos as i64;
        for j in (v_len as i64) {
            new_arena[next_pos_i + j] = tbl.arena[old_v_off + j];
        }
        e.val_off = new_pos;
        new_pos += v_len;
    }
    for k in (new_pos as i64) {
        tbl.arena[k] = new_arena[k];
    }
    tbl.arena_write_pos = new_pos;
}

// Evicts entries from the dynamic table until used_bytes <= target_bytes.
// Returns false if an eviction barrier (referenced entry) prevents eviction.
fn qpack_evict_until(tbl: http3::QpackTable&, target_bytes: u64) -> bool {
    while tbl.entries.len > 0 && tbl.used_bytes > target_bytes {
        let oldest .= tbl.entries[0];
        if oldest.ref_count > 0 {
            return false;
        }
        let cost = qpack_entry_cost(oldest.name_len, oldest.val_len);
        tbl.used_bytes = core::sub_sat_u64(tbl.used_bytes, cost);
        tbl.entries.remove_at(0);
    }
    tbl.draining_index = if tbl.entries.len > 0 { tbl.entries[0].abs_index } else { tbl.insert_count };
    if tbl.entries.len == 0 {
        tbl.arena_write_pos = 0;
    }
    return tbl.used_bytes <= target_bytes;
}

inline fn copy_to_arena(tbl: http3::QpackTable&, name: const u8[:], val: const u8[:]) -> u32, u32 {
    let n_off = tbl.arena_write_pos;
    let n_off_i = n_off as i64;
    for i in name.len {
        tbl.arena[n_off_i + i] = name[i];
    }
    tbl.arena_write_pos += name.len as u32;

    let v_off = tbl.arena_write_pos;
    let v_off_i = v_off as i64;
    for i in val.len {
        tbl.arena[v_off_i + i] = val[i];
    }
    tbl.arena_write_pos += val.len as u32;
    return n_off, v_off;
}

inline fn ensure_arena_capacity(tbl: http3::QpackTable&, raw_len: u32) -> bool {
    if tbl.arena_write_pos + raw_len > 16384 {
        qpack_compact_arena(tbl);
    }
    return tbl.arena_write_pos + raw_len <= 16384;
}

inline fn validate_literal_inputs(name: const u8[:], val: const u8[:]) -> bool {
    guard name.len > 0 && http3::validate_qpack_field_name(name) else { return false; }
    return http3::validate_qpack_field_val(val);
}

inline fn prepare_table_for_entry(tbl: http3::QpackTable&, cost: u64, raw_len: u32) -> bool {
    guard cost <= tbl.capacity_bytes else { return false; }
    guard qpack_evict_until(tbl, tbl.capacity_bytes - cost) else { return false; }
    guard tbl.entries.len < tbl.entries.cap else { return false; }
    return ensure_arena_capacity(tbl, raw_len);
}

// RFC 9204 Section 4.5.4: Literal Field Line with Name Reference - Reads only the field name from the referenced dynamic table entry.
fn qpack_lookup_name_absolute(tbl: const http3::QpackTable&, abs_idx: u64) -> const u8[:], bool {
    for &e in tbl.entries {
        if e.abs_index == abs_idx {
            let n_start = e.name_off as i64;
            let n_end = n_start + e.name_len;
            guard n_end <= 16384 else { return "", false; }
            return tbl.arena[n_start..n_end], true;
        }
    }
    return "", false;
}

// ---- Unacked Section & Blocked Stream Helpers ------------------------------

inline fn find_unacked_stream_idx(tbl: const http3::QpackTable&, stream_id: u64) -> i64, bool {
    for &sec, i in tbl.unacked_sections {
        if sec.stream_id == stream_id {
            return i, true;
        }
    }
    return 0, false;
}

inline fn release_section_refs(tbl: http3::QpackTable&, refs: const u64[:]) {
    for ref_abs in refs {
        let _ = http3::qpack_unpin_entry(tbl, ref_abs);
    }
}

inline fn release_and_remove_unacked(tbl: http3::QpackTable&, stream_id: u64) {
    var u_idx = 0;
    while u_idx < tbl.unacked_sections.len {
        if tbl.unacked_sections[u_idx].stream_id == stream_id {
            release_section_refs(tbl, tbl.unacked_sections[u_idx].ref_entries[..]);
            tbl.unacked_sections.remove_at(u_idx);
            continue;
        }
        u_idx++;
    }
}

// RFC 9204 Section 2.1.2: Blocked Streams - SETTINGS_QPACK_BLOCKED_STREAMS bounds distinct blocked streams.
fn qpack_count_blocked_streams(tbl: const http3::QpackTable&) -> u32 {
    var count: u32 = 0;
    for i in tbl.blocked_streams.len {
        if !has_blocked_stream_before(tbl.blocked_streams[..], i, tbl.blocked_streams[i].stream_id) {
            count++;
        }
    }
    return count;
}

// ---- Field Line Decoders & HeaderMap Emitter -------------------------------

inline fn clear_h3_pseudo_headers(pseudo: http3::PseudoHeaders&, preserve_is_trailer: bool = true) {
    let keep_trailer = if preserve_is_trailer { pseudo.is_trailer } else { false };
    pseudo.method.clear();
    pseudo.scheme.clear();
    pseudo.authority.clear();
    pseudo.path.clear();
    pseudo.protocol.clear();
    pseudo.status = 0;
    pseudo.has_method = false;
    pseudo.has_scheme = false;
    pseudo.has_authority = false;
    pseudo.has_path = false;
    pseudo.has_protocol = false;
    pseudo.has_status = false;
    pseudo.has_regular_header = false;
    pseudo.content_length = -1;
    pseudo.is_trailer = keep_trailer;
}

// Decodes a single QPACK field line representation.
//
// Example:
//   src = [0xD1], idx = 0
//   returns: QpackError.None, idx = 1, out_fields has decoded field
fn decode_qpack_field_line<F>(
    tbl:              const http3::QpackTable&,
    src:              const u8[:],
    idx:              u64&,
    base:             u64,
    ric:              u64,
    budget:           u64&,
    out_fields:       F&,
    max_dyn_abs_used: u64&,
    used_any_dyn:     bool&,
) -> http3::QpackError {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };

    let b = src[idx];

    // Case A: Indexed Field Line: 1Txxxxxx (6-bit prefix)
    if (b & 0x80) != 0 {
        let is_static = (b & 0x40) != 0;
        let tbl_idx, next_off, ok = http3::qpack_decode_int(src, idx, 6);
        guard ok else { return http3::QpackError.DecompressionFailed; }

        if is_static {
            let s_ent, s_ok = http3::get_qpack_static_field(tbl_idx);
            guard s_ok else { return http3::QpackError.DecompressionFailed; }
            let err = http3::emit_field_checked(out_fields, budget, s_ent.name, s_ent.val, false);
            guard err == http3::QpackError.None else { return err; }
        } else {
            guard base > tbl_idx else { return http3::QpackError.DecompressionFailed; }
            let abs_idx = base - tbl_idx - 1;
            guard abs_idx < ric else { return http3::QpackError.DecompressionFailed; } // RFC 9204 §4.5.2
            let n, v, ok_l = http3::qpack_lookup_absolute(tbl, abs_idx);
            guard ok_l else { return http3::QpackError.DecompressionFailed; }
            let err = http3::emit_field_checked(out_fields, budget, n, v, false);
            guard err == http3::QpackError.None else { return err; }
            record_dynamic_abs_used(abs_idx, max_dyn_abs_used, used_any_dyn);
        }
        idx = next_off;
        committed = true;
        return http3::QpackError.None;
    }

    // Case B: Indexed Field Line With Post-Base Index: 0001xxxx (4-bit prefix)
    if (b & 0xF0) == 0x10 {
        let post_idx, next_off, ok = http3::qpack_decode_int(src, idx, 4);
        guard ok else { return http3::QpackError.DecompressionFailed; }
        guard (0xFFFFFFFFFFFFFFFF - base) >= post_idx else { return http3::QpackError.DecompressionFailed; }
        let abs_idx = base + post_idx;
        guard abs_idx < ric else { return http3::QpackError.DecompressionFailed; } // RFC 9204 §4.5.3
        let n, v, ok_l = http3::qpack_lookup_absolute(tbl, abs_idx);
        guard ok_l else { return http3::QpackError.DecompressionFailed; }
        let err = http3::emit_field_checked(out_fields, budget, n, v, false);
        guard err == http3::QpackError.None else { return err; }
        record_dynamic_abs_used(abs_idx, max_dyn_abs_used, used_any_dyn);
        idx = next_off;
        committed = true;
        return http3::QpackError.None;
    }

    // Case C: Literal Field Line With Name Reference: 01NTxxxx (4-bit prefix)
    if (b & 0xC0) == 0x40 {
        let is_never_index = (b & 0x20) != 0;
        let is_static = (b & 0x10) != 0;
        let name_idx, val_start, ok_idx = http3::qpack_decode_int(src, idx, 4);
        guard ok_idx else { return http3::QpackError.DecompressionFailed; }

        var v: u8[..4096] = [];
        let next_off, ok_val = http3::decode_qpack_string(src, val_start, 7, v);
        guard ok_val else { return http3::QpackError.DecompressionFailed; }

        if is_static {
            let s_ent, s_ok = http3::get_qpack_static_field(name_idx);
            guard s_ok else { return http3::QpackError.DecompressionFailed; }
            let err = http3::emit_field_checked(out_fields, budget, s_ent.name, v[..], is_never_index);
            guard err == http3::QpackError.None else { return err; }
        } else {
            guard base > name_idx else { return http3::QpackError.DecompressionFailed; }
            let abs_idx = base - name_idx - 1;
            guard abs_idx < ric else { return http3::QpackError.DecompressionFailed; }
            let d_name, ok_dn = qpack_lookup_name_absolute(tbl, abs_idx);
            guard ok_dn else { return http3::QpackError.DecompressionFailed; }
            let err = http3::emit_field_checked(out_fields, budget, d_name, v[..], is_never_index);
            guard err == http3::QpackError.None else { return err; }
            record_dynamic_abs_used(abs_idx, max_dyn_abs_used, used_any_dyn);
        }
        idx = next_off;
        committed = true;
        return http3::QpackError.None;
    }

    // Case D: Literal Field Line With Post-Base Name Reference: 0000Nxxx (3-bit prefix)
    if (b & 0xF0) == 0x00 {
        let is_never_index = (b & 0x08) != 0;
        let post_name_idx, val_start, ok_idx = http3::qpack_decode_int(src, idx, 3);
        guard ok_idx else { return http3::QpackError.DecompressionFailed; }
        guard (0xFFFFFFFFFFFFFFFF - base) >= post_name_idx else { return http3::QpackError.DecompressionFailed; }
        let abs_idx = base + post_name_idx;
        guard abs_idx < ric else { return http3::QpackError.DecompressionFailed; }

        let n, ok_dn = qpack_lookup_name_absolute(tbl, abs_idx);
        guard ok_dn else { return http3::QpackError.DecompressionFailed; }
        record_dynamic_abs_used(abs_idx, max_dyn_abs_used, used_any_dyn);

        var v: u8[..4096] = [];
        let next_off, ok_val = http3::decode_qpack_string(src, val_start, 7, v);
        guard ok_val else { return http3::QpackError.DecompressionFailed; }

        let err = http3::emit_field_checked(out_fields, budget, n, v[..], is_never_index);
        guard err == http3::QpackError.None else { return err; }
        idx = next_off;
        committed = true;
        return http3::QpackError.None;
    }

    // Case E: Literal Field Line With Literal Name: 001NHxxx (3-bit prefix name)
    if (b & 0xE0) == 0x20 {
        let is_never_index = (b & 0x10) != 0;
        var n: u8[..256] = [];
        let val_start, ok_name = http3::decode_qpack_string(src, idx, 3, n);
        guard ok_name else { return http3::QpackError.DecompressionFailed; }

        var v: u8[..4096] = [];
        let next_off, ok_val = http3::decode_qpack_string(src, val_start, 7, v);
        guard ok_val else { return http3::QpackError.DecompressionFailed; }

        let err = http3::emit_field_checked(out_fields, budget, n[..], v[..], is_never_index);
        guard err == http3::QpackError.None else { return err; }
        idx = next_off;
        committed = true;
        return http3::QpackError.None;
    }

    return http3::QpackError.DecompressionFailed;
}

inline fn emit_qpack_pseudo_field(
    out_pseudo: http3::PseudoHeaders&,
    name:       const u8[:],
    val:        const u8[:],
) -> http3::QpackError {
    guard !out_pseudo.is_trailer && !out_pseudo.has_regular_header else {
        return http3::QpackError.MessageError;
    }
    if name == ":status" {
        guard !out_pseudo.has_status && val.len == 3 else { return http3::QpackError.MessageError; }
        let sc, ok_sc = val.parse_i32_dec();
        guard ok_sc && sc >= 100 && sc <= 599 && sc != 101 else { return http3::QpackError.MessageError; }
        out_pseudo.status = sc;
        out_pseudo.has_status = true;
        return http3::QpackError.None;
    }
    if name == ":method" {
        guard !out_pseudo.has_method && is_valid_http_method_token(val) && out_pseudo.method.try_set(val) else {
            return http3::QpackError.MessageError;
        }
        out_pseudo.has_method = true;
        return http3::QpackError.None;
    }
    if name == ":scheme" {
        guard !out_pseudo.has_scheme && is_valid_uri_scheme(val) && out_pseudo.scheme.try_set(val) else {
            return http3::QpackError.MessageError;
        }
        out_pseudo.has_scheme = true;
        return http3::QpackError.None;
    }
    if name == ":authority" {
        let valid_auth = is_valid_authority_or_host(val);
        guard !out_pseudo.has_authority && valid_auth && out_pseudo.authority.try_set(val) else {
            return http3::QpackError.MessageError;
        }
        out_pseudo.has_authority = true;
        return http3::QpackError.None;
    }
    if name == ":path" {
        let valid_p = is_valid_h3_path_bytes(val);
        guard !out_pseudo.has_path && valid_p && out_pseudo.path.try_set(val) else {
            return http3::QpackError.MessageError;
        }
        out_pseudo.has_path = true;
        return http3::QpackError.None;
    }
    if name == ":protocol" {
        guard !out_pseudo.has_protocol && val.len > 0 && out_pseudo.protocol.try_set(val) else {
            return http3::QpackError.MessageError;
        }
        out_pseudo.has_protocol = true;
        return http3::QpackError.None;
    }
    return http3::QpackError.MessageError;
}

inline fn emit_qpack_field_to_map(
    out_pseudo:  http3::PseudoHeaders&,
    out_headers: http::HeaderMap&,
    budget_left: u64&,
    name:        const u8[:],
    val:         const u8[:],
    never_index: bool = false,
) -> http3::QpackError {
    guard http3::validate_qpack_field_name(name) && http3::validate_qpack_field_val(val) else {
        return http3::QpackError.DecompressionFailed;
    }
    let cost = qpack_entry_cost(name.len as u64, val.len as u64);
    guard budget_left >= cost else { return http3::QpackError.HeaderListTooLarge; }
    budget_left -= cost;

    if name.len > 0 && name[0] == ':' {
        return emit_qpack_pseudo_field(out_pseudo, name, val);
    }

    guard !is_forbidden_connection_header(name, val) else { return http3::QpackError.MessageError; }
    if out_pseudo.has_status && name == "te" {
        return http3::QpackError.MessageError;
    }
    if out_pseudo.is_trailer {
        guard name != "content-length" && name != "host" && name != "trailer" && name != "te"
            && !rfc::is_disallowed_trailer_field(name) else {
            return http3::QpackError.MessageError;
        }
    }
    if name == "host" {
        guard !http::has_header(out_headers, "host") && is_valid_authority_or_host(val) else {
            return http3::QpackError.MessageError;
        }
        if out_pseudo.has_authority && !out_pseudo.authority[..].eq_ascii_fold(val) {
            return http3::QpackError.MessageError;
        }
    }

    out_pseudo.has_regular_header = true;
    if name == "content-length" {
        guard !out_pseudo.has_status || out_pseudo.status >= 200 else { return http3::QpackError.MessageError; }
        let cl, ok_cl = val.parse_i64_dec();
        let _, ok_u = val.parse_u64_dec();
        guard ok_cl && ok_u else { return http3::QpackError.MessageError; }
        if out_pseudo.content_length >= 0 && out_pseudo.content_length != cl {
            return http3::QpackError.MessageError;
        }
        out_pseudo.content_length = cl;
    }

    guard http::append_header(out_headers, name, val) else {
        return http3::QpackError.HeaderListTooLarge;
    }
    if never_index && out_headers.entries.len > 0 {
        let last_idx = out_headers.entries.len - 1;
        out_headers.entries[last_idx].flags = out_headers.entries[last_idx].flags | http::HEADER_FLAG_SENSITIVE;
    }
    return http3::QpackError.None;
}

// Decodes a single QPACK field line directly into `out_headers` (RFC 9204 §4.5.2–4.5.6).
// Advances `idx` past the decoded field line.
//
// Example:
//   src = [0xD1], idx = 0 (static index 17: ":method: GET")
//   returns: QpackError.None, idx = 1, out_pseudo.method = "GET"
fn decode_qpack_field_line_to_map(
    tbl:              const http3::QpackTable&,
    src:              const u8[:],
    idx:              u64&,
    base:             u64,
    ric:              u64,
    budget:           u64&,
    out_pseudo:       http3::PseudoHeaders&,
    out_headers:      http::HeaderMap&,
    max_dyn_abs_used: u64&,
    used_any_dyn:     bool&,
) -> http3::QpackError {
    let saved_idx = idx;
    var committed = false;
    defer if !committed { idx = saved_idx; };

    let b = src[idx];

    if (b & 0x80) != 0 {
        let is_static = (b & 0x40) != 0;
        let tbl_idx, next_off, ok = http3::qpack_decode_int(src, idx, 6);
        guard ok else { return http3::QpackError.DecompressionFailed; }

        if is_static {
            let s_ent, s_ok = http3::get_qpack_static_field(tbl_idx);
            guard s_ok else { return http3::QpackError.DecompressionFailed; }
            let err = emit_qpack_field_to_map(out_pseudo, out_headers, budget, s_ent.name, s_ent.val, false);
            guard err == http3::QpackError.None else { return err; }
        } else {
            guard base > tbl_idx else { return http3::QpackError.DecompressionFailed; }
            let abs_idx = base - tbl_idx - 1;
            guard abs_idx < ric else { return http3::QpackError.DecompressionFailed; }
            let n, v, ok_l = http3::qpack_lookup_absolute(tbl, abs_idx);
            guard ok_l else { return http3::QpackError.DecompressionFailed; }
            let err = emit_qpack_field_to_map(out_pseudo, out_headers, budget, n, v, false);
            guard err == http3::QpackError.None else { return err; }
            record_dynamic_abs_used(abs_idx, max_dyn_abs_used, used_any_dyn);
        }
        idx = next_off;
        committed = true;
        return http3::QpackError.None;
    }

    if (b & 0xF0) == 0x10 {
        let post_idx, next_off, ok = http3::qpack_decode_int(src, idx, 4);
        guard ok else { return http3::QpackError.DecompressionFailed; }
        guard (0xFFFFFFFFFFFFFFFF - base) >= post_idx else { return http3::QpackError.DecompressionFailed; }
        let abs_idx = base + post_idx;
        guard abs_idx < ric else { return http3::QpackError.DecompressionFailed; }
        let n, v, ok_l = http3::qpack_lookup_absolute(tbl, abs_idx);
        guard ok_l else { return http3::QpackError.DecompressionFailed; }
        let err = emit_qpack_field_to_map(out_pseudo, out_headers, budget, n, v, false);
        guard err == http3::QpackError.None else { return err; }
        record_dynamic_abs_used(abs_idx, max_dyn_abs_used, used_any_dyn);
        idx = next_off;
        committed = true;
        return http3::QpackError.None;
    }

    if (b & 0xC0) == 0x40 {
        let is_never_index = (b & 0x20) != 0;
        let is_static = (b & 0x10) != 0;
        let name_idx, val_start, ok_idx = http3::qpack_decode_int(src, idx, 4);
        guard ok_idx else { return http3::QpackError.DecompressionFailed; }

        var v: u8[..4096] = [];
        let next_off, ok_val = http3::decode_qpack_string(src, val_start, 7, v);
        guard ok_val else { return http3::QpackError.DecompressionFailed; }

        if is_static {
            let s_ent, s_ok = http3::get_qpack_static_field(name_idx);
            guard s_ok else { return http3::QpackError.DecompressionFailed; }
            let err = emit_qpack_field_to_map(out_pseudo, out_headers, budget, s_ent.name, v[..], is_never_index);
            guard err == http3::QpackError.None else { return err; }
        } else {
            guard base > name_idx else { return http3::QpackError.DecompressionFailed; }
            let abs_idx = base - name_idx - 1;
            guard abs_idx < ric else { return http3::QpackError.DecompressionFailed; }
            let d_name, ok_dn = qpack_lookup_name_absolute(tbl, abs_idx);
            guard ok_dn else { return http3::QpackError.DecompressionFailed; }
            let err = emit_qpack_field_to_map(out_pseudo, out_headers, budget, d_name, v[..], is_never_index);
            guard err == http3::QpackError.None else { return err; }
            record_dynamic_abs_used(abs_idx, max_dyn_abs_used, used_any_dyn);
        }
        idx = next_off;
        committed = true;
        return http3::QpackError.None;
    }

    if (b & 0xF0) == 0x00 {
        let is_never_index = (b & 0x08) != 0;
        let post_name_idx, val_start, ok_idx = http3::qpack_decode_int(src, idx, 3);
        guard ok_idx else { return http3::QpackError.DecompressionFailed; }
        guard (0xFFFFFFFFFFFFFFFF - base) >= post_name_idx else { return http3::QpackError.DecompressionFailed; }
        let abs_idx = base + post_name_idx;
        guard abs_idx < ric else { return http3::QpackError.DecompressionFailed; }

        let n, ok_dn = qpack_lookup_name_absolute(tbl, abs_idx);
        guard ok_dn else { return http3::QpackError.DecompressionFailed; }
        record_dynamic_abs_used(abs_idx, max_dyn_abs_used, used_any_dyn);

        var v: u8[..4096] = [];
        let next_off, ok_val = http3::decode_qpack_string(src, val_start, 7, v);
        guard ok_val else { return http3::QpackError.DecompressionFailed; }

        let err = emit_qpack_field_to_map(out_pseudo, out_headers, budget, n, v[..], is_never_index);
        guard err == http3::QpackError.None else { return err; }
        idx = next_off;
        committed = true;
        return http3::QpackError.None;
    }

    if (b & 0xE0) == 0x20 {
        let is_never_index = (b & 0x10) != 0;
        var n: u8[..256] = [];
        let val_start, ok_name = http3::decode_qpack_string(src, idx, 3, n);
        guard ok_name else { return http3::QpackError.DecompressionFailed; }

        var v: u8[..4096] = [];
        let next_off, ok_val = http3::decode_qpack_string(src, val_start, 7, v);
        guard ok_val else { return http3::QpackError.DecompressionFailed; }

        let err = emit_qpack_field_to_map(out_pseudo, out_headers, budget, n[..], v[..], is_never_index);
        guard err == http3::QpackError.None else { return err; }
        idx = next_off;
        committed = true;
        return http3::QpackError.None;
    }

    return http3::QpackError.DecompressionFailed;
}
