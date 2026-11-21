// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/3 QPACK Field Compression Engine (RFC 9204).
// Implements zero-allocation dynamic table ring, blocked streams manager,
// encoder/decoder stream instruction processors, and Header Accordion defenses.
namespace http3;

import std;
import core;
import rfc.h3_quic;
import http.headers;
import http2.hpack;
import .internal;
import .types;
import .qpack_codec;
import .qpack_internal;

// ---- Dynamic Table Construction, Insertion & Eviction ----------------------

fn new_qpack_table(
    max_capacity:     u64 = 4096,
    max_blocked:      u32 = 16,
    initial_capacity: u64 = 4096,
) -> QpackTable {
    let eff_cap = min(initial_capacity, max_capacity);
    return QpackTable {
        capacity_bytes:     eff_cap,
        max_capacity_bytes: max_capacity,
        max_blocked:        max_blocked,
        ..
    };
}

// Updates dynamic table capacity via Set Dynamic Table Capacity instruction.
fn qpack_set_capacity(tbl: QpackTable&, new_cap: u64) -> bool {
    guard new_cap <= tbl.max_capacity_bytes else { return false; }
    let ok = h3_internal::qpack_evict_until(tbl, new_cap);
    guard ok else { return false; }
    tbl.capacity_bytes = new_cap;
    return true;
}

// Inserts an entry into the dynamic table with literal name and value.
fn qpack_insert_literal(tbl: QpackTable&, name: const u8[:], val: const u8[:]) -> bool {
    guard h3_internal::validate_literal_inputs(name, val) else { return false; }

    let cost = h3_internal::qpack_entry_cost(name.len as u64, val.len as u64);
    let raw_len = (name.len + val.len) as u32;
    guard h3_internal::prepare_table_for_entry(tbl, cost, raw_len) else { return false; }

    let n_off, v_off = h3_internal::copy_to_arena(tbl, name, val);
    let ent = h3_internal::DynamicEntryDesc {
        abs_index: tbl.insert_count,
        ref_count: 0,
        name_off:  n_off,
        name_len:  name.len as u16,
        val_off:   v_off,
        val_len:   val.len as u16,
    };
    tbl.entries.push(ent);

    tbl.insert_count++;
    tbl.used_bytes += cost;
    return true;
}

// Inserts an entry referencing a static name index.
fn qpack_insert_named_static(tbl: QpackTable&, static_idx: u64, val: const u8[:]) -> bool {
    let s_ent, ok = get_qpack_static_field(static_idx);
    guard ok else { return false; }
    return qpack_insert_literal(tbl, s_ent.name, val);
}

// Inserts an entry referencing a dynamic name by relative index.
fn qpack_insert_named_dynamic(tbl: QpackTable&, rel_idx: u64, val: const u8[:]) -> bool {
    guard tbl.insert_count > rel_idx else { return false; }
    let target_abs = tbl.insert_count - rel_idx - 1;

    let name_slice, ok_n = h3_internal::qpack_lookup_name_absolute(tbl, target_abs);
    guard ok_n else { return false; }
    var n_buf: u8[..256] = [];
    guard n_buf.try_set(name_slice) else { return false; }
    return qpack_insert_literal(tbl, n_buf[..], val);
}

// Duplicates an existing dynamic table entry by relative index.
fn qpack_duplicate(tbl: QpackTable&, rel_idx: u64) -> bool {
    guard tbl.insert_count > rel_idx else { return false; }
    let target_abs = tbl.insert_count - rel_idx - 1;

    let name_slice, val_slice, ok_l = qpack_lookup_absolute(tbl, target_abs);
    guard ok_l else { return false; }
    var n_buf: u8[..256]  = [];
    var v_buf: u8[..4096] = [];
    guard n_buf.try_set(name_slice) && v_buf.try_set(val_slice) else { return false; }
    return qpack_insert_literal(tbl, n_buf[..], v_buf[..]);
}

// ---- Pinning, Unacked Section Tracking & Blocked Streams -------------------

// Pins an entry in the dynamic table to prevent eviction while in active use (RFC 9204 §2.1.1).
fn qpack_pin_entry(tbl: QpackTable&, abs_idx: u64) -> bool {
    for &e in tbl.entries {
        if e.abs_index == abs_idx {
            e.ref_count++;
            return true;
        }
    }
    return false;
}

// Unpins an entry in the dynamic table after active reference is released.
fn qpack_unpin_entry(tbl: QpackTable&, abs_idx: u64) -> bool {
    for &e in tbl.entries {
        if e.abs_index == abs_idx {
            if e.ref_count > 0 {
                e.ref_count--;
            }
            return true;
        }
    }
    return false;
}

// Tracks an unacknowledged stream section with its Required Insert Count (RFC 9204 §4.4.1).
fn qpack_track_unacked_stream(tbl: QpackTable&, stream_id: u64, ric: u64) -> bool {
    for &sec in tbl.unacked_sections {
        if sec.stream_id == stream_id && sec.ric == 0 {
            sec.ric = ric;
            return true;
        }
    }
    let entry = h3_internal::UnackedSection {
        stream_id:   stream_id,
        ric:         ric,
        ref_entries: [],
    };
    return tbl.unacked_sections.try_push(entry);
}

// Associates a dynamic table entry reference with an unacknowledged stream (RFC 9204 §2.1.1, §4.4.2).
// Pins the dynamic table entry and records the reference for subsequent ACK or cancellation release.
fn qpack_track_stream_ref(tbl: QpackTable&, stream_id: u64, abs_idx: u64) -> bool {
    guard qpack_pin_entry(tbl, abs_idx) else {
        return false;
    }
    for &sec in tbl.unacked_sections {
        if sec.stream_id == stream_id && sec.ric == 0 {
            guard sec.ref_entries.try_push(abs_idx) else {
                let _ = qpack_unpin_entry(tbl, abs_idx);
                return false;
            }
            return true;
        }
    }
    var entry = h3_internal::UnackedSection {
        stream_id:   stream_id,
        ric:         0,
        ref_entries: [],
    };
    entry.ref_entries.push(abs_idx);
    guard tbl.unacked_sections.try_push(entry) else {
        let _ = qpack_unpin_entry(tbl, abs_idx);
        return false;
    }
    return true;
}

// Section Acknowledgment instruction handler (Decoder -> Encoder) (RFC 9204 §4.4.1).
// Updates known_rcvd_count to max(known_rcvd_count, section.ric), releases dynamic table
// entry references, and removes the unacknowledged stream entry.
// Returns QpackError.DecoderStreamError if stream was not unacknowledged or had ric == 0.
fn qpack_ack_section(tbl: QpackTable&, stream_id: u64, ric: u64 = 0) -> QpackError {
    let found_idx, ok_found = h3_internal::find_unacked_stream_idx(tbl, stream_id);
    var effective_ric = ric;
    if ok_found {
        effective_ric = max(effective_ric, tbl.unacked_sections[found_idx].ric);
        h3_internal::release_section_refs(tbl, tbl.unacked_sections[found_idx].ref_entries[..]);
        tbl.unacked_sections.remove_at(found_idx as i32);
    } else {
        guard effective_ric > 0 else {
            return QpackError.DecoderStreamError;
        }
    }

    tbl.known_rcvd_count = max(tbl.known_rcvd_count, effective_ric);

    let _ = qpack_unblock_stream(tbl, stream_id);
    return QpackError.None;
}

// Stream Cancellation instruction handler (Decoder -> Encoder) (RFC 9204 §4.4.2).
// Releases all dynamic table entry references held by the identified stream.
fn qpack_cancel_stream(tbl: QpackTable&, stream_id: u64) {
    h3_internal::release_and_remove_unacked(tbl, stream_id);
    let _ = qpack_unblock_stream(tbl, stream_id);
}

// Insert Count Increment instruction handler (Decoder -> Encoder).
fn qpack_increment_received(tbl: QpackTable&, inc: u64) {
    tbl.known_rcvd_count += inc;
}

// Checks if a new stream can be blocked according to SETTINGS_QPACK_BLOCKED_STREAMS (RFC 9204 Section 2.1.2).
fn qpack_can_block_stream(tbl: const QpackTable&) -> bool {
    return h3_internal::qpack_count_blocked_streams(tbl) < tbl.max_blocked &&
        tbl.blocked_streams.len < tbl.blocked_streams.cap;
}

// Records a blocked field section waiting for TotalNumberOfInserts to reach req_insert_count (RFC 9204 Section 2.1.2).
fn qpack_block_stream(
    tbl:             QpackTable&,
    stream_id:       u64,
    ric:             u64,
    data:            const u8[:],
    is_push_promise: bool = false,
    push_id:         u64  = 0,
) -> bool {
    if !qpack_is_stream_blocked(tbl, stream_id) {
        guard qpack_can_block_stream(tbl) else { return false; }
    }
    guard tbl.blocked_streams.len < tbl.blocked_streams.cap else { return false; }
    var entry = h3_internal::BlockedStreamEntry {
        stream_id:        stream_id,
        req_insert_count: ric,
        is_push_promise:  is_push_promise,
        push_id:          push_id,
        ..
    };
    guard entry.encoded_data.try_set(data) else { return false; }
    return tbl.blocked_streams.try_push(entry);
}

// Checks if a stream is currently recorded as blocked.
fn qpack_is_stream_blocked(tbl: const QpackTable&, stream_id: u64) -> bool {
    for &b in tbl.blocked_streams {
        if b.stream_id == stream_id {
            return true;
        }
    }
    return false;
}

// Unblocks and removes all blocked entries for `stream_id`.
fn qpack_unblock_stream(tbl: QpackTable&, stream_id: u64) -> bool {
    var removed = false;
    var i = 0;
    while i < tbl.blocked_streams.len {
        if tbl.blocked_streams[i].stream_id == stream_id {
            tbl.blocked_streams.remove_at(i);
            removed = true;
            continue;
        }
        i++;
    }
    return removed;
}

// ---- Encoder & Decoder Stream Instruction Processors -----------------------

// Parses and applies a single instruction from Encoder Stream (RFC 9204 Section 4.3).
fn qpack_process_encoder_instruction(tbl: QpackTable&, src: const u8[:], offset: u64) -> u64, QpackError {
    guard offset < (src.len as u64) else { return offset, QpackError.EncoderStreamError; }
    let b = src[offset];

    // 1. Set Dynamic Table Capacity: 001xxxxx (5-bit prefix)
    if (b & 0xE0) == 0x20 {
        let cap, next_off, ok = qpack_decode_int(src, offset, 5);
        guard ok else { return offset, QpackError.EncoderStreamError; }
        guard qpack_set_capacity(tbl, cap) else { return offset, QpackError.EncoderStreamError; }
        return next_off, QpackError.None;
    }

    // 2. Insert with Name Reference: 1Txxxxxx (6-bit prefix)
    if (b & 0x80) != 0 {
        guard tbl.capacity_bytes > 0 else { return offset, QpackError.EncoderStreamError; }
        let is_static = (b & 0x40) != 0;
        let name_idx, val_off, ok_idx = qpack_decode_int(src, offset, 6);
        guard ok_idx else { return offset, QpackError.EncoderStreamError; }

        var val_buf: u8[..4096] = [];
        let end_off, ok_val = decode_qpack_string(src, val_off, 7, val_buf);
        guard ok_val else { return offset, QpackError.EncoderStreamError; }

        if is_static {
            guard qpack_insert_named_static(tbl, name_idx, val_buf[..]) else {
                return offset, QpackError.EncoderStreamError;
            }
        } else {
            guard qpack_insert_named_dynamic(tbl, name_idx, val_buf[..]) else {
                return offset, QpackError.EncoderStreamError;
            }
        }
        return end_off, QpackError.None;
    }

    // 3. Insert with Literal Name: 01Hxxxxx (5-bit prefix)
    if (b & 0xC0) == 0x40 {
        guard tbl.capacity_bytes > 0 else { return offset, QpackError.EncoderStreamError; }
        var name_buf: u8[..256] = [];
        let val_start, ok_name = decode_qpack_string(src, offset, 5, name_buf);
        guard ok_name else { return offset, QpackError.EncoderStreamError; }

        var val_buf: u8[..4096] = [];
        let end_off, ok_val = decode_qpack_string(src, val_start, 7, val_buf);
        guard ok_val else { return offset, QpackError.EncoderStreamError; }

        guard qpack_insert_literal(tbl, name_buf[..], val_buf[..]) else {
            return offset, QpackError.EncoderStreamError;
        }
        return end_off, QpackError.None;
    }

    // 4. Duplicate: 000xxxxx (5-bit prefix)
    if (b & 0xE0) == 0x00 {
        guard tbl.capacity_bytes > 0 else { return offset, QpackError.EncoderStreamError; }
        let rel_idx, next_off, ok = qpack_decode_int(src, offset, 5);
        guard ok else { return offset, QpackError.EncoderStreamError; }
        guard qpack_duplicate(tbl, rel_idx) else { return offset, QpackError.EncoderStreamError; }
        return next_off, QpackError.None;
    }

    return offset, QpackError.EncoderStreamError;
}

// Parses and applies a single instruction from Decoder Stream (RFC 9204 Section 4.4).
fn qpack_process_decoder_instruction(tbl: QpackTable&, src: const u8[:], offset: u64) -> u64, QpackError {
    guard offset < (src.len as u64) else { return offset, QpackError.DecoderStreamError; }
    let b = src[offset];

    // 1. Section Acknowledgment: 1xxxxxxx (7-bit prefix)
    if (b & 0x80) != 0 {
        let stream_id, next_off, ok = qpack_decode_int(src, offset, 7);
        guard ok else { return offset, QpackError.DecoderStreamError; }
        let ack_err = qpack_ack_section(tbl, stream_id, 0);
        guard ack_err == QpackError.None else { return offset, ack_err; }
        return next_off, QpackError.None;
    }

    // 2. Stream Cancellation: 01xxxxxx (6-bit prefix)
    if (b & 0xC0) == 0x40 {
        let stream_id, next_off, ok = qpack_decode_int(src, offset, 6);
        guard ok else { return offset, QpackError.DecoderStreamError; }
        qpack_cancel_stream(tbl, stream_id);
        return next_off, QpackError.None;
    }

    // 3. Insert Count Increment: 00xxxxxx (6-bit prefix)
    if (b & 0xC0) == 0x00 {
        let inc, next_off, ok = qpack_decode_int(src, offset, 6);
        guard ok && inc > 0 else { return offset, QpackError.DecoderStreamError; }
        guard (0xFFFFFFFFFFFFFFFF - tbl.known_rcvd_count) >= inc else { return offset, QpackError.DecoderStreamError; }
        guard (tbl.known_rcvd_count + inc) <= tbl.insert_count else { return offset, QpackError.DecoderStreamError; }
        qpack_increment_received(tbl, inc);
        return next_off, QpackError.None;
    }

    return offset, QpackError.DecoderStreamError;
}

// ---- Complete Field Section Decoders ---------------------------------------

// Decodes a complete QPACK Encoded Field Section (RFC 9204 Section 4.5).
// Enforces Header Accordion defenses (CVE-2026-12523 / CVE-2026-40898),
// post-decode RIC validation (ric == max_abs_used + 1), and flow-control limits.
//
// Example:
//   src = [0x00, 0x00, 0xD1], out_fields = []
//   returns: QpackError.None, out_fields has decoded entries
fn decode_qpack_section<F>(
    tbl:               const QpackTable&,
    src:               const u8[:],
    out_fields:        F&,
    max_field_section: u64 = 16384,
) -> QpackError {
    guard src.len >= 2 else { return QpackError.DecompressionFailed; }
    let enc_ric, base_off, ok_ric = qpack_decode_int(src, 0, 8);
    guard ok_ric else { return QpackError.DecompressionFailed; }

    // RFC 9204 §4.5.1.1: MaxEntries is computed from MaxTableCapacity (set by decoder), NOT current capacity_bytes.
    let ric, ric_err = decode_ric(enc_ric, tbl.insert_count, tbl.max_capacity_bytes);
    guard ric_err == QpackError.None else { return ric_err; }

    if ric > tbl.insert_count && !qpack_can_block_stream(tbl) {
        return QpackError.BlockedStreamsExhausted;
    }

    guard base_off < (src.len as u64) else { return QpackError.DecompressionFailed; }
    let sign_bit: u8 = if (src[base_off] & 0x80) != 0 { 1 } else { 0 };
    let delta_base, fields_off, ok_db = qpack_decode_int(src, base_off, 7);
    guard ok_db else { return QpackError.DecompressionFailed; }

    let base, base_err = decode_base(sign_bit, delta_base, ric);
    guard base_err == QpackError.None else { return base_err; }

    out_fields.clear();
    var budget = max_field_section;
    var offset = fields_off;
    var max_dyn_abs_used: u64 = 0;
    var used_any_dyn = false;

    while offset < (src.len as u64) {
        let f_err = h3_internal::decode_qpack_field_line(
            tbl, src, offset, base, ric, budget, out_fields, max_dyn_abs_used, used_any_dyn,
        );
        guard f_err == QpackError.None else {
            out_fields.clear();
            return f_err;
        }
    }

    let min_ric = if used_any_dyn { max_dyn_abs_used + 1 } else { 0 };
    guard ric >= min_ric && ric <= tbl.insert_count else {
        out_fields.clear();
        return QpackError.DecompressionFailed;
    }
    return QpackError.None;
}

// Decodes an Encoded Field Section or blocks the stream when RIC exceeds insert_count (RFC 9204 Section 2.1.2).
//
// Example:
//   src = [0x00, 0x00, 0xd1], stream_id = 4
//   returns: QpackError.None, out_fields contains parsed headers
fn decode_or_block_qpack_section<F>(
    tbl:               QpackTable&,
    stream_id:         u64,
    src:               const u8[:],
    out_fields:        F&,
    max_field_section: u64  = 16384,
    is_push_promise:   bool = false,
    push_id:           u64  = 0,
) -> QpackError {
    guard src.len >= 2 else { return QpackError.DecompressionFailed; }
    let enc_ric, _, ok_ric = qpack_decode_int(src, 0, 8);
    guard ok_ric else { return QpackError.DecompressionFailed; }
    let ric, ric_err = decode_ric(enc_ric, tbl.insert_count, tbl.max_capacity_bytes);
    guard ric_err == QpackError.None else { return ric_err; }

    let already_blocked = qpack_is_stream_blocked(tbl, stream_id);
    if already_blocked || ric > tbl.insert_count {
        if !already_blocked && !qpack_can_block_stream(tbl) {
            return QpackError.BlockedStreamsExhausted;
        }
        guard qpack_block_stream(tbl, stream_id, ric, src, is_push_promise, push_id) else {
            return QpackError.BlockedStreamsExhausted;
        }
        return QpackError.StreamBlocked;
    }

    return decode_qpack_section(tbl, src, out_fields, max_field_section);
}

// Decodes a complete QPACK Encoded Field Section directly into `out_pseudo` and `out_headers` (RFC 9204 §4.5).
//
// Example:
//   src = [0x00, 0x00, 0xD1], decode_qpack_to_map(tbl, src, out_pseudo, out_headers, 16384)
//   returns: QpackError.None, out_pseudo.method = "GET"
fn decode_qpack_to_map(
    tbl:               const QpackTable&,
    src:               const u8[:],
    out_pseudo:        PseudoHeaders&,
    out_headers:       http::HeaderMap&,
    max_field_section: u64 = 16384,
) -> QpackError {
    guard src.len >= 2 else { return QpackError.DecompressionFailed; }
    let enc_ric, base_off, ok_ric = qpack_decode_int(src, 0, 8);
    guard ok_ric else { return QpackError.DecompressionFailed; }

    let ric, ric_err = decode_ric(enc_ric, tbl.insert_count, tbl.max_capacity_bytes);
    guard ric_err == QpackError.None else { return ric_err; }

    if ric > tbl.insert_count && !qpack_can_block_stream(tbl) {
        return QpackError.BlockedStreamsExhausted;
    }

    guard base_off < (src.len as u64) else { return QpackError.DecompressionFailed; }
    let sign_bit: u8 = if (src[base_off] & 0x80) != 0 { 1 } else { 0 };
    let delta_base, fields_off, ok_db = qpack_decode_int(src, base_off, 7);
    guard ok_db else { return QpackError.DecompressionFailed; }

    let base, base_err = decode_base(sign_bit, delta_base, ric);
    guard base_err == QpackError.None else { return base_err; }

    h3_internal::clear_h3_pseudo_headers(out_pseudo, true);
    out_headers.clear();
    var budget = max_field_section;
    var offset = fields_off;
    var max_dyn_abs_used: u64 = 0;
    var used_any_dyn = false;

    while offset < (src.len as u64) {
        let f_err = h3_internal::decode_qpack_field_line_to_map(
            tbl, src, offset, base, ric, budget, out_pseudo, out_headers, max_dyn_abs_used, used_any_dyn,
        );
        guard f_err == QpackError.None else {
            h3_internal::clear_h3_pseudo_headers(out_pseudo, true);
            out_headers.clear();
            return f_err;
        }
    }

    let min_ric = if used_any_dyn { max_dyn_abs_used + 1 } else { 0 };
    guard ric >= min_ric && ric <= tbl.insert_count else {
        h3_internal::clear_h3_pseudo_headers(out_pseudo, true);
        out_headers.clear();
        return QpackError.DecompressionFailed;
    }
    return QpackError.None;
}

// Decodes an Encoded Field Section directly into `out_pseudo` and `out_headers`,
// or records the stream as blocked if RIC exceeds `insert_count` (RFC 9204 Section 2.1.2).
//
// Example:
//   src = [0x00, 0x00, 0xD1], stream_id = 4
//   returns: QpackError.None, out_pseudo and out_headers populated
fn decode_or_block_qpack_to_map(
    tbl:               QpackTable&,
    stream_id:         u64,
    src:               const u8[:],
    out_pseudo:        PseudoHeaders&,
    out_headers:       http::HeaderMap&,
    max_field_section: u64 = 16384,
) -> QpackError {
    guard src.len >= 2 else { return QpackError.DecompressionFailed; }
    let enc_ric, _, ok_ric = qpack_decode_int(src, 0, 8);
    guard ok_ric else { return QpackError.DecompressionFailed; }
    let ric, ric_err = decode_ric(enc_ric, tbl.insert_count, tbl.max_capacity_bytes);
    guard ric_err == QpackError.None else { return ric_err; }

    let already_blocked = qpack_is_stream_blocked(tbl, stream_id);
    if already_blocked || ric > tbl.insert_count {
        if !already_blocked && !qpack_can_block_stream(tbl) {
            return QpackError.BlockedStreamsExhausted;
        }
        guard qpack_block_stream(tbl, stream_id, ric, src) else {
            return QpackError.BlockedStreamsExhausted;
        }
        return QpackError.StreamBlocked;
    }

    return decode_qpack_to_map(tbl, src, out_pseudo, out_headers, max_field_section);
}

// ---- QPACK Field & Encoder Stream Encoding ---------------------------------

// Encodes a single field line with optional static index lookup, returning false on buffer overflow.
fn encode_qpack_field<B>(
    out:         B&,
    name:        const u8[:],
    val:         const u8[:],
    use_huffman: bool = true,
) -> bool {
    let start_len = out.len;
    var committed = false;
    defer if !committed { out.resize(start_len); };

    let s_idx, exact_s = find_qpack_static_field(name, val);
    if exact_s {
        guard http2::hpack_encode_int(out, s_idx, 6, 0xC0) else { return false; }
        committed = true;
        return true;
    }

    let s_idx_name, _ = find_qpack_static_field(name, "");
    if s_idx_name < rfc::QPACK_STATIC_TABLE_SIZE &&
       name == h3_internal::QPACK_STATIC_TABLE[s_idx_name as i64].name {
        guard http2::hpack_encode_int(out, s_idx_name, 4, 0x50) &&
              http2::encode_hpack_string_literal(out, val, use_huffman) else {
            return false;
        }
        committed = true;
        return true;
    }

    if use_huffman {
        let huff_len = http2::huff_encoded_byte_len(name);
        if huff_len < (name.len as u64) {
            guard http2::hpack_encode_int(out, huff_len, 3, 0x28) &&
                  http2::huff_encode_bytes(name, out) &&
                  http2::encode_hpack_string_literal(out, val, use_huffman) else {
                return false;
            }
            committed = true;
            return true;
        }
    }
    guard http2::hpack_encode_int(out, name.len as u64, 3, 0x20) &&
          out.try_append(name) &&
          http2::encode_hpack_string_literal(out, val, use_huffman) else {
        return false;
    }
    committed = true;
    return true;
}

// Searches the dynamic table for an entry matching `name` and `val` (or `name` only).
// Returns `(abs_index, exact_value_match, name_found)`.
fn find_qpack_dynamic_field(
    tbl:  const QpackTable&,
    name: const u8[:],
    val:  const u8[:],
) -> u64, bool, bool {
    var matched_name_abs: u64 = 0;
    var name_found = false;
    var i = tbl.entries.len - 1;
    while i >= 0 {
        let e .= tbl.entries[i];
        i--;
        let n_start = e.name_off as i64;
        let n_end = n_start + e.name_len;
        let v_start = e.val_off as i64;
        let v_end = v_start + e.val_len;
        guard n_end <= 16384 && v_end <= 16384 else { continue; }
        guard tbl.arena[n_start..n_end] == name else { continue; }
        if tbl.arena[v_start..v_end] == val {
            return e.abs_index, true, true;
        }
        if !name_found {
            matched_name_abs = e.abs_index;
            name_found = true;
        }
    }
    return matched_name_abs, false, name_found;
}

// Emits a Set Dynamic Table Capacity instruction (001xxxxx, 5-bit prefix) onto `out`
// and updates `tbl.capacity_bytes` (RFC 9204 §4.3.1).
fn encode_qpack_set_capacity<B>(tbl: QpackTable&, new_cap: u64, out: B&) -> bool {
    guard new_cap <= tbl.max_capacity_bytes else { return false; }
    var enc_buf: u8[..16] = [];
    guard http2::hpack_encode_int(enc_buf, new_cap, 5, 0x20) else { return false; }
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    guard out.try_append(enc_buf[..]) else { return false; }
    guard qpack_set_capacity(tbl, new_cap) else { return false; }
    committed = true;
    return true;
}

// Emits an Encoder Stream insertion instruction (Insert with Static Name Reference 11xxxxxx
// or Insert with Literal Name 01Hxxxxx) and inserts the entry into `tbl` (RFC 9204 §4.3.2, §4.3.3).
fn encode_qpack_dynamic_insert<B>(
    tbl:         QpackTable&,
    name:        const u8[:],
    val:         const u8[:],
    out:         B&,
    use_huffman: bool = true,
) -> u64, bool {
    guard tbl.capacity_bytes > 0 else { return 0, false; }
    let s_idx_name, _ = find_qpack_static_field(name, "");
    let has_static_name = s_idx_name < rfc::QPACK_STATIC_TABLE_SIZE
        && name == h3_internal::QPACK_STATIC_TABLE[s_idx_name as i64].name;

    var ins_buf: u8[..4096] = [];
    if has_static_name {
        let enc_ok = http2::hpack_encode_int(ins_buf, s_idx_name, 6, 0xC0) &&
            http2::encode_hpack_string_literal(ins_buf, val, use_huffman);
        guard enc_ok else { return 0, false; }
    } else {
        let huff_len = if use_huffman { http2::huff_encoded_byte_len(name) } else { name.len as u64 };
        let is_huff = use_huffman && huff_len < (name.len as u64);
        var enc_ok = false;
        if is_huff {
            enc_ok = http2::hpack_encode_int(ins_buf, huff_len, 5, 0x60);
            enc_ok = enc_ok && http2::huff_encode_bytes(name, ins_buf);
        } else {
            enc_ok = http2::hpack_encode_int(ins_buf, name.len as u64, 5, 0x40);
            enc_ok = enc_ok && ins_buf.try_append(name);
        }
        guard enc_ok && http2::encode_hpack_string_literal(ins_buf, val, use_huffman) else {
            return 0, false;
        }
    }
    let saved_enc_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_enc_len); };
    guard out.try_append(ins_buf[..]) else { return 0, false; }
    let ins_ok = if has_static_name {
        qpack_insert_named_static(tbl, s_idx_name, val)
    } else {
        qpack_insert_literal(tbl, name, val)
    };
    guard ins_ok else { return 0, false; }
    committed = true;
    return tbl.insert_count - 1, true;
}

// RFC 9204 Section 3.2: Dynamic Table - Encodes a field line using Static Table, Dynamic Table lookup/insertion,
// or Literal fallback, rolling back encoder and dynamic table state on field section overflow.
fn encode_qpack_field_dynamic<B1, B2>(
    tbl:              QpackTable&,
    stream_id:        u64,
    base:             u64,
    name:             const u8[:],
    val:              const u8[:],
    out_section:      B1&,
    out_enc_stream:   B2&,
    max_dyn_abs_used: u64&,
    used_any_dyn:     bool&,
    use_huffman:      bool = true,
) -> bool {
    let saved_sec_len = out_section.len;
    let saved_enc_len = out_enc_stream.len;
    let saved_tbl = tbl;
    let saved_max_dyn = max_dyn_abs_used;
    let saved_used_dyn = used_any_dyn;
    var committed = false;
    defer if !committed {
        out_section.resize(saved_sec_len);
        out_enc_stream.resize(saved_enc_len);
        tbl = saved_tbl;
        max_dyn_abs_used = saved_max_dyn;
        used_any_dyn = saved_used_dyn;
    };

    let s_idx, exact_s = find_qpack_static_field(name, val);
    if exact_s {
        guard http2::hpack_encode_int(out_section, s_idx, 6, 0xC0) else { return false; }
        committed = true;
        return true;
    }

    if tbl.capacity_bytes > 0 {
        let dyn_abs, exact_d, _ = find_qpack_dynamic_field(tbl, name, val);
        if exact_d && qpack_track_stream_ref(tbl, stream_id, dyn_abs) {
            h3_internal::record_dynamic_abs_used(dyn_abs, max_dyn_abs_used, used_any_dyn);
            guard h3_internal::encode_qpack_dyn_index_line(out_section, dyn_abs, base) else { return false; }
            committed = true;
            return true;
        }

        let new_abs, ins_ok = encode_qpack_dynamic_insert(tbl, name, val, out_enc_stream, use_huffman);
        if ins_ok {
            if qpack_track_stream_ref(tbl, stream_id, new_abs) {
                h3_internal::record_dynamic_abs_used(new_abs, max_dyn_abs_used, used_any_dyn);
                guard h3_internal::encode_qpack_dyn_index_line(out_section, new_abs, base) else { return false; }
                committed = true;
                return true;
            }
            out_enc_stream.resize(saved_enc_len);
            tbl = saved_tbl;
        }
    }

    guard encode_qpack_field(out_section, name, val, use_huffman) else { return false; }
    committed = true;
    return true;
}
