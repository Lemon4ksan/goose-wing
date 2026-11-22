// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/2 HPACK Header Compression and 256-State Huffman FSM (RFC 7541, RFC 9113 Section 8.2).
// Implements 16 KiB L1-cache Huffman decoding FSM, zero-allocation ring-buffer dynamic table,
// integer shift overflow protection (Trail of Bits FIND-401), and RFC 9113 header field validation.
namespace http2;

import std;
import core;
import .framing;
import .hpack_tables_internal;
import .hpack_internal;
import http.headers;

// ---- hpack public constants ----------------------------------------------

const HPACK_MAX_ARENA_BYTES: u64 = 4096;
// RFC 7541 / DoS cap on cumulative decoded Huffman bytes appended into a `u8[>..]` sink.
const HPACK_MAX_HUFF_OUT_BYTES: i64 = 65536;

// ---- huffman codec primitives --------------------------------------------

struct HuffContext {
    fstate: u8 = 0,
    flags:  u8 = 0x01, // HUFF_ACCEPTED at root
}

checkfree fn new_huff_context() -> HuffContext {
    return HuffContext { fstate: 0, flags: h2_internal::HUFF_ACCEPTED };
}

// Decodes a slice of Huffman-encoded bytes into preallocated dst.
// Processes two 4-bit nibbles per byte without dynamic allocations or branches.
//
// Example:
//   src = [0x9C, 0xC5], dst_len = 0, is_final = true
//   returns: written = 3, ok = true
checkfree fn huff_decode_step(
    ctx:      HuffContext&,
    dst:      u8[:],
    dst_len:  u64,
    src:      const u8[:],
    is_final: bool,
) -> u64, bool {
    var state = ctx.fstate;
    var flags = ctx.flags;
    var out_idx = dst_len;
    var last_sym_byte: i64 = -1;
    let dst_cap = dst.len as u64;

    for c, i in src {
        // Step 1: High nibble (bits 7..4)
        let t1 = h2_internal::huff_decode_lookup(state, c >> 4);
        if (t1.flags & h2_internal::HUFF_FAIL) != 0 {
            return out_idx, false;
        }
        if (t1.flags & h2_internal::HUFF_SYM) != 0 {
            let w1 = out_idx as i64;
            if out_idx >= dst_cap || w1 < 0 || w1 >= dst.len {
                return out_idx, false;
            }
            dst[w1] = t1.sym;
            out_idx++;
            last_sym_byte = i;
        }

        // Step 2: Low nibble (bits 3..0)
        let t2 = h2_internal::huff_decode_lookup(t1.fstate, c & 0x0F);
        if (t2.flags & h2_internal::HUFF_FAIL) != 0 {
            return out_idx, false;
        }
        if (t2.flags & h2_internal::HUFF_SYM) != 0 {
            let w2 = out_idx as i64;
            if out_idx >= dst_cap || w2 < 0 || w2 >= dst.len {
                return out_idx, false;
            }
            dst[w2] = t2.sym;
            out_idx++;
            last_sym_byte = i;
        }

        state = t2.fstate;
        flags = t2.flags;
    }
    ctx.fstate = state;
    ctx.flags = flags;

    // EOS & Padding check (RFC 7541 Section 5.2 & RFC 9204 Section 4.1.2):
    // If final, state must be one of the accepted states (all '1' padding bits)
    // and padding MUST NOT exceed 7 bits (cannot consume a full byte after last symbol).
    if is_final {
        if (flags & h2_internal::HUFF_ACCEPTED) == 0 {
            return out_idx, false;
        }
        if src.len > 0 && last_sym_byte != (src.len - 1) {
            return out_idx, false;
        }
    }
    return out_idx, true;
}

// Decodes a Huffman-encoded byte slice directly into any appendable buffer without stack scratch zeroing.
extern fn native_hpack_huff_decode(src: const u8[:], dst: u8[:], table: const u32[:]) -> i64 = "wing_hpack_huff_decode";

// Decodes a Huffman-encoded byte slice into any bounded appendable buffer without scratch zeroing.
//
// Example:
//   src = [0x9C, 0xC5], out = []
//   returns: ok = true, out = "www"
fn huff_decode_bytes<B>(src: const u8[:], out: B&) -> bool {
    if src.len == 0 {
        return true;
    }
    let start_len = out.len;
    if start_len >= out.cap {
        return false;
    }
    let avail = core::sub_sat_i64(out.cap, start_len);
    let max_out = core::add_sat_i64(src.len, src.len);
    let probe = min(avail, max_out);
    out.resize(core::add_sat_i64(start_len, probe), 0);
    let n = native_hpack_huff_decode(src, out[start_len..], h2_internal::HUFF_DECODE_TABLE_PACKED[..]);
    if n < 0 {
        out.resize(start_len);
        return false;
    }
    out.resize(core::add_sat_i64(start_len, n));
    return true;
}

// Decodes a Huffman-encoded byte slice into a resizable `u8[>..]` buffer.
//
// Example:
//   src = [0x9C, 0xC5], out = []
//   returns: ok = true, out = "www"
fn huff_decode_bytes(src: const u8[:], out: u8[>..]&) -> bool {
    if src.len == 0 {
        return true;
    }
    let start_len = out.len;
    let max_out = core::add_sat_i64(src.len, src.len);
    let max_src = HPACK_MAX_HUFF_OUT_BYTES >> 1;
    let target_len = core::add_sat_i64(start_len, max_out);
    guard src.len <= max_src && start_len >= 0 && target_len <= HPACK_MAX_HUFF_OUT_BYTES else {
        return false;
    }
    out.resize(target_len, 0);
    let n = native_hpack_huff_decode(src, out[start_len..], h2_internal::HUFF_DECODE_TABLE_PACKED[..]);
    if n < 0 {
        out.resize(start_len);
        return false;
    }
    out.resize(core::add_sat_i64(start_len, n));
    return true;
}

// Calculates the exact Huffman-encoded byte length of an uncompressed string.
checkfree fn huff_encoded_byte_len(src: const u8[:]) -> u64 {
    var total_bits: u64 = 0;
    for b in src {
        total_bits += h2_internal::HUFF_SYM_LENS[b];
    }
    return (total_bits + 7) / 8;
}

// Encodes uncompressed bytes using canonical RFC 7541 Huffman code into out.
fn huff_encode_bytes<B>(src: const u8[:], out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    var acc:   u64 = 0;
    var nbits: u32 = 0;

    for b in src {
        let code = h2_internal::HUFF_SYM_CODES[b] as u64;
        let clen = h2_internal::HUFF_SYM_LENS[b] as u32;
        acc = (acc << clen) | code;
        nbits += clen;

        while nbits >= 8 {
            nbits -= 8;
            guard out.try_push(((acc >> nbits) & 0xFF) as u8) else { return false; }
        }
    }

    // RFC 7541 Section 5.2: pad remaining bits with 1s (EOS prefix)
    if nbits > 0 {
        let pad_bits = 8 - nbits;
        acc = (acc << pad_bits) | (((1 as u64) << pad_bits) - 1);
        guard out.try_push((acc & 0xFF) as u8) else { return false; }
    }
    committed = true;
    return true;
}

// ---- integer codec with shift overflow protection -----------------------

// Decodes an HPACK integer with N-bit prefix (RFC 7541 Section 5.1).
// Guards against shift overflow (shift >= 28) and integer overflow (Trail of Bits FIND-401).
// Returns (value, next_offset, ok).
//
// Example:
//   src = [0x0A], offset = 0, prefix_bits = 5
//   returns: val = 10, next_offset = 1, ok = true
checkfree fn hpack_decode_int(src: const u8[:], offset: u64, prefix_bits: u8) -> u64, u64, bool {
    let off_i = offset as i64;
    guard off_i >= 0 && off_i < src.len else { return 0, offset, false; }
    guard prefix_bits >= 1 && prefix_bits <= 8 else { return 0, offset, false; }

    let mask = (((1 as u32) << prefix_bits) - 1) as u8;
    var val = (src[off_i] & mask) as u64;
    var idx = off_i + 1;

    if val < mask {
        return val, idx as u64, true;
    }

    // Multibyte continuation
    var shift: u32 = 0;
    while idx >= 0 && idx < src.len {
        let b = src[idx];
        let payload = (b & 0x7F) as u64;

        if shift >= h2_internal::HPACK_MAX_INT_SHIFT {
            if shift > 28 || payload > 0x0F {
                return 0, idx as u64, false;
            }
        }

        let term = payload << shift;
        if (rfc::H2_MAX_WINDOW_SIZE - val) < term {
            return 0, idx as u64, false;
        }
        val += term;
        idx += 1;

        if (b & 0x80) == 0 {
            return val, idx as u64, true;
        }
        shift += 7;
    }

    return 0, offset, false;
}

// Encodes an integer with an N-bit prefix into out.
fn hpack_encode_int<B>(out: B&, val: u64, prefix_bits: u8, prefix_mask: u8) -> bool {
    guard prefix_bits >= 1 && prefix_bits <= 8 else { return false; }
    let max_prefix = (((1 as u64) << prefix_bits) - 1);

    if val < max_prefix {
        return out.try_push(prefix_mask | (val as u8));
    }

    var tmp: u8[..12] = [];
    tmp.push(prefix_mask | (max_prefix as u8));
    var rem = val - max_prefix;
    while rem >= 128 {
        guard tmp.try_push((0x80 | (rem & 0x7F)) as u8) else { return false; }
        rem = rem >> 7;
    }
    guard tmp.try_push((rem & 0x7F) as u8) else { return false; }
    return out.try_append(tmp[..]);
}

// ---- zero-allocation dynamic table (rfc 7541 section 4) ------------------

struct HpackHeaderField {
    name_off:    u32  = 0,
    name_len:    u16  = 0,
    val_off:     u32  = 0,
    val_len:     u16  = 0,
    meta_size:   u32  = 0, // name_len + val_len + 32
    generation:  u8   = 0,
    never_index: bool = false,
}

// RFC 7541 Section 2.3.2: Dynamic Table - O(1) direct-mapped encoder hash table with generation tracking.
struct HpackHashTable {
    slots:       u16[256] = [0; 256],
    generations: u8[256]  = [0; 256],
}

struct DynamicTable {
    entries:                 HpackHeaderField[128] = [HpackHeaderField { .. }; 128],
    arena:                   u8[4096]              = [0; 4096],
    hash_table:              HpackHashTable        = HpackHashTable { .. },
    head:                    u64                   = 0, // Oldest entry index in ring
    count:                   u64                   = 0, // Current number of active entries
    arena_write_pos:         u32                   = 0, // Sequential write cursor in arena
    arena_head:              u32                   = 0, // Linearized boundary write start offset
    arena_tail:              u32                   = 0, // Linearized boundary oldest live byte offset
    next_generation:         u8                    = 1, // Monotonic non-zero generation counter
    used_bytes:              u64                   = 0, // Total protocol size (sum of meta_size)
    max_allowed_size:        u64                   = 4096, // From SETTINGS_HEADER_TABLE_SIZE
    current_max_size:        u64                   = 4096, // Set by HPACK size updates
    pending_size_update_req: bool                  = false,
    pending_min_table_size:  u64                   = 4096,
}

checkfree fn new_dynamic_table(max_allowed: u64 = 4096) -> DynamicTable {
    return DynamicTable {
        max_allowed_size:       max_allowed,
        current_max_size:       max_allowed,
        pending_min_table_size: max_allowed,
        ..
    };
}

// Evicts oldest entries from head until used_bytes <= target_size.
checkfree fn evict_until(dt: DynamicTable&, target_size: u64) {
    while dt.count > 0 && dt.used_bytes > target_size {
        h2_internal::evict_oldest_entry(dt);
    }
}

// Inserts a (name, val) pair into the dynamic table using the linearized boundary ring buffer
// and O(1) direct-mapped hash table without heap allocations or O(N) compaction copies.
checkfree fn insert_header(dt: DynamicTable&, name: const u8[:], val: const u8[:], never_index: bool = false) {
    let entry_weight = (name.len as u64) + (val.len as u64) + rfc::HPACK_ENTRY_OVERHEAD;

    // RFC 7541 Section 4.4: if entry exceeds current max size, table is emptied
    if entry_weight > dt.current_max_size {
        evict_until(dt, 0);
        return;
    }

    evict_until(dt, dt.current_max_size - entry_weight);

    let total_raw = ((name.len as u64) + (val.len as u64)) as u32;
    guard total_raw <= (HPACK_MAX_ARENA_BYTES as u32) else {
        evict_until(dt, 0);
        return;
    }

    if dt.arena_write_pos + total_raw > (HPACK_MAX_ARENA_BYTES as u32) {
        h2_internal::evict_overlapping_arena_range(dt, dt.arena_write_pos, HPACK_MAX_ARENA_BYTES as u32);
        dt.arena_write_pos = 0;
    }
    h2_internal::evict_overlapping_arena_range(dt, dt.arena_write_pos, dt.arena_write_pos + total_raw);
    while dt.count >= h2_internal::HPACK_MAX_RING_ENTRIES {
        h2_internal::evict_oldest_entry(dt);
    }

    let head_i = (dt.head & h2_internal::HPACK_RING_MASK) as i64;
    let insert_i = ((dt.head + dt.count) & h2_internal::HPACK_RING_MASK) as i64;
    guard head_i >= 0 && head_i < 128 && insert_i >= 0 && insert_i < 128 else { return; }
    let name_off, val_off = h2_internal::pack_header_into_arena(dt, name, val);
    let gen = h2_internal::next_hpack_generation(dt);
    dt.entries[insert_i] = HpackHeaderField {
        name_off:    name_off,
        name_len:    name.len as u16,
        val_off:     val_off,
        val_len:     val.len as u16,
        meta_size:   entry_weight as u32,
        generation:  gen,
        never_index: never_index,
    };
    dt.count += 1;
    dt.used_bytes += entry_weight;
    dt.arena_tail = dt.entries[head_i].name_off;

    let slot = h2_internal::compute_hpack_hash_slot(name, val);
    dt.hash_table.slots[slot] = (insert_i as u16) + 1;
    dt.hash_table.generations[slot] = gen;
}

// Fetches indexed header name and value slices directly without buffer copying.
checkfree fn get_indexed_header_slices(dt: const DynamicTable&, idx: u64) -> const u8[:], const u8[:], bool {
    guard idx >= 1 else { return "", "", false; } // Index 0 is invalid (RFC 7541 Section 6.1)

    if idx <= rfc::HPACK_STATIC_TABLE_ENTRIES {
        let s, ok = h2_internal::get_hpack_static_field(idx);
        guard ok else { return "", "", false; }
        return s.name, s.val, true;
    }

    let entry, ok = h2_internal::lookup_dynamic_index(dt, idx);
    guard ok else { return "", "", false; }

    let n_off = entry.name_off as i64;
    let n_end = n_off + entry.name_len;
    let v_off = entry.val_off as i64;
    let v_end = v_off + entry.val_len;
    guard n_off >= 0 && n_off <= n_end && n_end <= 4096 else { return "", "", false; }
    guard v_off >= 0 && v_off <= v_end && v_end <= 4096 else { return "", "", false; }

    return dt.arena[n_off..n_end], dt.arena[v_off..v_end], true;
}

// Fetches an indexed header from Static Table (1..61) or Dynamic Table (>= 62).
// Buffers are cleared only if the entry is successfully resolved and fits both capacities.
fn get_indexed_header<B1, B2>(dt: const DynamicTable&, idx: u64, out_name: B1&, out_val: B2&) -> bool {
    let name_slice, val_slice, ok = get_indexed_header_slices(dt, idx);
    guard ok && name_slice.len <= out_name.cap && val_slice.len <= out_val.cap else {
        return false;
    }
    return out_name.try_set(name_slice) && out_val.try_set(val_slice);
}

// Updates dynamic table maximum size per HPACK instruction (001xxxxx).
checkfree fn update_dynamic_table_max_size(dt: DynamicTable&, new_max: u64) -> bool {
    guard new_max <= dt.max_allowed_size else { return false; }
    dt.current_max_size = new_max;
    evict_until(dt, new_max);
    return true;
}

// ---- full hpack block decoder & rfc 9113 header validator ----------------

struct PseudoHeaders {
    method:             u8[..16]   = [],
    scheme:             u8[..16]   = [],
    authority:          u8[..256]  = [],
    path:               u8[..2048] = [],
    protocol:           u8[..64]   = [],
    status:             i32        = 0,
    has_method:         bool       = false,
    has_scheme:         bool       = false,
    has_authority:      bool       = false,
    has_path:           bool       = false,
    has_protocol:       bool       = false,
    has_status:         bool       = false,
    has_regular_header: bool       = false,
    has_content_length: bool       = false,
    content_length_val: i64        = -1,
    is_trailer:         bool       = false,
    wireframe_size:     u32        = 0,
}

checkfree fn clear_pseudo_headers(p: PseudoHeaders&, keep_trailer_flag: bool = true) {
    let tr = if keep_trailer_flag { p.is_trailer } else { false };
    p.method.clear();
    p.scheme.clear();
    p.authority.clear();
    p.path.clear();
    p.protocol.clear();
    p.status = 0;
    p.has_method = false;
    p.has_scheme = false;
    p.has_authority = false;
    p.has_path = false;
    p.has_protocol = false;
    p.has_status = false;
    p.has_regular_header = false;
    p.has_content_length = false;
    p.content_length_val = -1;
    p.is_trailer = tr;
    p.wireframe_size = 0;
}

enum FieldOrigin {
    Wire,
    StaticName,
    StaticBoth,
}

// Validates RFC 9113 Section 8.2.1 header field syntax:
// 1. Name must be lowercase ASCII token without whitespace or uppercase.
// 2. Value must not contain NUL, CR, or LF, nor leading/trailing SP/HTAB.
fn validate_field_syntax(name: const u8[:], val: const u8[:]) -> bool {
    return h2_internal::validate_h2_field_name(name) && h2_internal::validate_h2_field_value(val);
}

// Decodes string literal from HPACK stream (with Huffman or raw octets).
//
// Example:
//   src = [0x05, 'c', 'u', 's', 't', 'm'], offset = 0, out: appends "custm"
//   returns: consumed_offset = 6, ok = true
fn decode_hpack_string<B>(src: const u8[:], offset: u64, out: B&) -> u64, bool {
    guard offset < (src.len as u64) else { return offset, false; }
    let is_huff = (src[offset] & 0x80) != 0;
    let str_len, next_off, ok_len = hpack_decode_int(src, offset, 7);
    guard ok_len && str_len <= (HPACK_MAX_HUFF_OUT_BYTES as u64) else { return offset, false; }

    guard (next_off + str_len) <= (src.len as u64) else {
        return offset, false;
    }

    let raw_slice = src[next_off..next_off + str_len];
    if is_huff {
        let ok_huff = huff_decode_bytes(raw_slice, out);
        guard ok_huff else { return offset, false; }
    } else {
        guard out.try_append(raw_slice) else { return offset, false; }
    }

    return next_off + str_len, true;
}

fn is_valid_scheme(val: const u8[:]) -> bool {
    guard val.len > 0 else { return false; }
    guard core::is_ascii_alpha(val[0]) else { return false; }
    for b in val[1..] {
        let ok = core::is_ascii_alpha(b) || core::is_ascii_digit(b)
            || b == '+' || b == '-' || b == '.';
        guard ok else { return false; }
    }
    return true;
}

checkfree fn is_valid_authority(val: const u8[:]) -> bool {
    guard val.len > 0 else { return false; }
    for b in val {
        guard !h2_internal::is_forbidden_authority_byte(b) else { return false; }
    }
    return true;
}

checkfree fn is_valid_path(val: const u8[:]) -> bool {
    guard val.len > 0 else { return false; }
    if val == "*" { return true; }
    guard val[0] == '/' else { return false; }
    for b in val {
        guard !h2_internal::is_forbidden_path_byte(b) else { return false; }
    }
    return true;
}

fn validate_and_record_pseudo_header(
    pseudo:               PseudoHeaders&,
    name:                 const u8[:],
    val:                  const u8[:],
    validate_http2_rules: bool,
) -> u32 {
    if validate_http2_rules {
        guard !pseudo.is_trailer && !pseudo.has_regular_header else {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
    }

    if name == ":status" {
        if validate_http2_rules {
            guard !pseudo.has_status else { return rfc::H2_ERR_PROTOCOL_ERROR; }
            let code, err = h2_internal::validate_pseudo_status_code(pseudo, val);
            guard err == rfc::H2_ERR_NO_ERROR else { return err; }
            pseudo.status = code;
        } else {
            let parsed, ok_p = val.parse_u32_dec();
            if ok_p { pseudo.status = parsed as i32; }
        }
        pseudo.has_status = true;
        return rfc::H2_ERR_NO_ERROR;
    }

    if name == ":method" {
        if validate_http2_rules {
            guard !pseudo.has_method && !pseudo.has_status && h2_internal::is_valid_h2_token(val) else {
                return rfc::H2_ERR_PROTOCOL_ERROR;
            }
            if val != "OPTIONS" && pseudo.has_path && pseudo.path[..] == "*" {
                return rfc::H2_ERR_PROTOCOL_ERROR;
            }
        }
        guard pseudo.method.try_set(val) else { return rfc::H2_ERR_PROTOCOL_ERROR; }
        pseudo.has_method = true;
        return rfc::H2_ERR_NO_ERROR;
    }

    if name == ":scheme" {
        if validate_http2_rules {
            guard !pseudo.has_scheme && !pseudo.has_status && is_valid_scheme(val) else {
                return rfc::H2_ERR_PROTOCOL_ERROR;
            }
        }
        guard pseudo.scheme.try_set(val) else { return rfc::H2_ERR_PROTOCOL_ERROR; }
        pseudo.has_scheme = true;
        return rfc::H2_ERR_NO_ERROR;
    }

    if name == ":authority" {
        if validate_http2_rules {
            guard !pseudo.has_authority && !pseudo.has_status && is_valid_authority(val) else {
                return rfc::H2_ERR_PROTOCOL_ERROR;
            }
        }
        guard pseudo.authority.try_set(val) else { return rfc::H2_ERR_PROTOCOL_ERROR; }
        pseudo.has_authority = true;
        return rfc::H2_ERR_NO_ERROR;
    }

    if name == ":path" {
        if validate_http2_rules {
            guard !pseudo.has_path && !pseudo.has_status else {
                return rfc::H2_ERR_PROTOCOL_ERROR;
            }
            let err = h2_internal::validate_pseudo_path(val, pseudo);
            guard err == rfc::H2_ERR_NO_ERROR else { return err; }
        }
        guard pseudo.path.try_set(val) else { return rfc::H2_ERR_PROTOCOL_ERROR; }
        pseudo.has_path = true;
        return rfc::H2_ERR_NO_ERROR;
    }

    if name == ":protocol" {
        if validate_http2_rules {
            guard !pseudo.has_protocol && !pseudo.has_status && h2_internal::is_valid_h2_token(val) else {
                return rfc::H2_ERR_PROTOCOL_ERROR;
            }
        }
        guard pseudo.protocol.try_set(val) else { return rfc::H2_ERR_PROTOCOL_ERROR; }
        pseudo.has_protocol = true;
        return rfc::H2_ERR_NO_ERROR;
    }

    return if validate_http2_rules { rfc::H2_ERR_PROTOCOL_ERROR } else { rfc::H2_ERR_NO_ERROR };
}

// Validates and records a single decoded HPACK field into `out_pseudo` and `out_headers`.
fn validate_header_ordering_and_rules(
    out_pseudo:           PseudoHeaders&,
    out_headers:          http::HeaderMap&,
    name:                 const u8[:],
    val:                  const u8[:],
    validate_http2_rules: bool        = true,
    origin:               FieldOrigin = FieldOrigin.Wire,
) -> u32 {
    if validate_http2_rules {
        guard h2_internal::validate_h2_field_by_origin(name, val, origin) else {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
    } else {
        guard name.len > 0 else { return rfc::H2_ERR_PROTOCOL_ERROR; }
    }

    if name[0] == ':' {
        if validate_http2_rules && (name == ":path" || name == ":scheme") &&
           out_pseudo.has_method && out_pseudo.method[..] == "CONNECT" && !out_pseudo.has_protocol {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
        return validate_and_record_pseudo_header(out_pseudo, name, val, validate_http2_rules);
    }

    let saved_has_reg = out_pseudo.has_regular_header;
    let saved_has_cl = out_pseudo.has_content_length;
    let saved_cl_val = out_pseudo.content_length_val;
    var committed = false;
    defer if !committed {
        out_pseudo.has_regular_header = saved_has_reg;
        out_pseudo.has_content_length = saved_has_cl;
        out_pseudo.content_length_val = saved_cl_val;
    };

    if validate_http2_rules {
        let v_reg = h2_internal::validate_regular_header_to_map(out_pseudo, out_headers, name, val);
        guard v_reg == rfc::H2_ERR_NO_ERROR else { return v_reg; }
        let join_st = h2_internal::join_existing_cookie(out_headers, name, val);
        if join_st == h2_internal::CookieJoinStatus.Overflow {
            return rfc::H2_ERR_ENHANCE_YOUR_CALM;
        }
        if join_st == h2_internal::CookieJoinStatus.NotCookie {
            guard http::append_validated_header(out_headers, name, val) else {
                return rfc::H2_ERR_ENHANCE_YOUR_CALM;
            }
        }
    } else {
        out_pseudo.has_regular_header = true;
        let join_st = h2_internal::join_existing_cookie(out_headers, name, val);
        if join_st == h2_internal::CookieJoinStatus.Overflow {
            return rfc::H2_ERR_ENHANCE_YOUR_CALM;
        }
        if join_st == h2_internal::CookieJoinStatus.NotCookie {
            guard http::append_validated_header(out_headers, name, val) else {
                return rfc::H2_ERR_ENHANCE_YOUR_CALM;
            }
        }
    }
    committed = true;
    return rfc::H2_ERR_NO_ERROR;
}

// Decodes an HPACK literal header field with given prefix bits into bounded name/value buffers.
//
// Example:
//   src = [0x00, 0x04, 'n', 'a', 'm', 'e', 0x03, 'v', 'a', 'l'], offset = 0, prefix_bits = 4
//   returns: val_next_off = 10, error_code = ERR_NO_ERROR
fn decode_literal_field_slices(
    dt:          const DynamicTable&,
    src:         const u8[:],
    offset:      u64,
    prefix_bits: u8,
    name_buf:    u8[..256]&,
    val_buf:     u8[..8192]&,
) -> u64, const u8[:], FieldOrigin, u32 {
    let name_mark = name_buf.len;
    let val_mark = val_buf.len;
    var committed = false;
    defer if !committed { name_buf.resize(name_mark); val_buf.resize(val_mark); };
    let name_idx, init_off, ok_idx = hpack_decode_int(src, offset, prefix_bits);
    guard ok_idx else { return offset, "", FieldOrigin.Wire, rfc::H2_ERR_COMPRESSION_ERROR; }
    var mut_off = init_off;

    if name_idx == 0 {
        let next_name_off, ok_name = decode_hpack_string(src, mut_off, name_buf);
        guard ok_name else { return offset, "", FieldOrigin.Wire, rfc::H2_ERR_COMPRESSION_ERROR; }
        mut_off = next_name_off;
    } else if name_idx > 61 {
        let name_slice, ok_n = h2_internal::get_indexed_header_name_slice(dt, name_idx);
        guard ok_n && name_buf.try_set(name_slice) else {
            return offset, "", FieldOrigin.Wire, rfc::H2_ERR_COMPRESSION_ERROR;
        }
    }

    let val_next_off, ok_val = decode_hpack_string(src, mut_off, val_buf);
    guard ok_val else { return offset, "", FieldOrigin.Wire, rfc::H2_ERR_COMPRESSION_ERROR; }
    committed = true;
    guard name_idx >= 1 && name_idx <= 61 else {
        return val_next_off, name_buf[..], FieldOrigin.Wire, rfc::H2_ERR_NO_ERROR;
    }
    return val_next_off, h2_internal::HPACK_STATIC_TABLE[name_idx].name, FieldOrigin.StaticName, rfc::H2_ERR_NO_ERROR;
}

// Decodes a single HPACK field representation step directly into `out_pseudo` and `out_headers`.
//
// Example:
//   src = [0x82], offset = 0, dt = DynamicTable { .. }
//   returns: next_offset = 1, error_code = ERR_NO_ERROR, out_pseudo.method = "GET"
fn decode_hpack_field_step_to_map(
    dt:                   DynamicTable&,
    src:                  const u8[:],
    offset:               u64,
    updates_allowed:      bool&,
    update_count:         u32&,
    out_pseudo:           PseudoHeaders&,
    out_headers:          http::HeaderMap&,
    max_header_list_size: u32,
    validate_http2_rules: bool,
) -> u64, u32 {
    var name_buf: u8[..256]  = [];
    var val_buf:  u8[..8192] = [];
    return h2_internal::decode_hpack_field_step_with_scratch(
        dt,
        src,
        offset,
        updates_allowed,
        update_count,
        out_pseudo,
        out_headers,
        max_header_list_size,
        validate_http2_rules,
        name_buf,
        val_buf,
    );
}

// RFC 9113 Section 8.3.1 & 8.3.2: Verify mandatory pseudo-headers in non-trailer header blocks
fn validate_mandatory_pseudo_headers(pseudo: const PseudoHeaders&) -> u32 {
    if pseudo.has_status {
        guard !pseudo.has_method && !pseudo.has_scheme && !pseudo.has_path
              && !pseudo.has_authority && !pseudo.has_protocol else {
            return rfc::H2_ERR_PROTOCOL_ERROR;
        }
        return rfc::H2_ERR_NO_ERROR;
    }
    if pseudo.has_method {
        let is_connect = (pseudo.method[..] == "CONNECT");
        if is_connect && !pseudo.has_protocol {
            guard pseudo.has_authority && h2_internal::is_valid_connect_authority(pseudo.authority[..]) else {
                return rfc::H2_ERR_PROTOCOL_ERROR;
            }
            guard !pseudo.has_scheme && !pseudo.has_path else { return rfc::H2_ERR_PROTOCOL_ERROR; }
        } else if is_connect && pseudo.has_protocol {
            guard pseudo.has_scheme && pseudo.has_path && pseudo.has_authority else {
                return rfc::H2_ERR_PROTOCOL_ERROR;
            }
        } else {
            guard !pseudo.has_protocol else { return rfc::H2_ERR_PROTOCOL_ERROR; }
            guard pseudo.has_scheme && pseudo.has_path else { return rfc::H2_ERR_PROTOCOL_ERROR; }
        }
        if pseudo.has_path && pseudo.path[..] == "*" {
            guard pseudo.method[..] == "OPTIONS" else { return rfc::H2_ERR_PROTOCOL_ERROR; }
        }
        return rfc::H2_ERR_NO_ERROR;
    }
    return rfc::H2_ERR_PROTOCOL_ERROR;
}

// Decodes a complete HPACK header block directly into `out_pseudo` and `out_headers` (RFC 7541, RFC 9113 §8.2).
// Enforces RFC 9113 pseudo-header ordering, duplicate content-length checks (CVE-2026-78660),
// iterative dynamic table size updates only at the start of the block, and `max_header_list_size`.
//
// Example:
//   src = [0x82, 0x86, 0x84], out_pseudo = PseudoHeaders { .. }, out_headers = http::HeaderMap { .. }
//   returns: error_code = ERR_NO_ERROR, out_pseudo.method = "GET"
fn decode_hpack_to_map_with_scratch(
    dt:                   DynamicTable&,
    src:                  const u8[:],
    out_pseudo:           PseudoHeaders&,
    out_headers:          http::HeaderMap&,
    name_buf:             u8[..256]&,
    val_buf:              u8[..8192]&,
    max_header_list_size: u32  = 8192,
    validate_http2_rules: bool = true,
) -> u32 {
    var offset: u64 = 0;
    let src_len = src.len as u64;
    var updates_allowed = true;
    var update_count: u32 = 0;
    var first_err:    u32 = rfc::H2_ERR_NO_ERROR;
    var committed = false;

    clear_pseudo_headers(out_pseudo, true);
    out_headers.clear();
    name_buf.clear();
    val_buf.clear();
    defer if !committed {
        clear_pseudo_headers(out_pseudo, true);
        out_headers.clear();
    };

    while offset < src_len {
        let next_off, err = h2_internal::decode_hpack_field_step_with_scratch(
            dt,
            src,
            offset,
            updates_allowed,
            update_count,
            out_pseudo,
            out_headers,
            max_header_list_size,
            validate_http2_rules,
            name_buf,
            val_buf,
        );
        if err == rfc::H2_ERR_COMPRESSION_ERROR {
            return err;
        }
        if err != rfc::H2_ERR_NO_ERROR && first_err == rfc::H2_ERR_NO_ERROR {
            first_err = err;
        }
        offset = next_off;
    }

    guard !dt.pending_size_update_req && dt.current_max_size <= dt.max_allowed_size else {
        return rfc::H2_ERR_COMPRESSION_ERROR;
    }

    guard first_err == rfc::H2_ERR_NO_ERROR else { return first_err; }

    if validate_http2_rules && !out_pseudo.is_trailer {
        let v_err = validate_mandatory_pseudo_headers(out_pseudo);
        guard v_err == rfc::H2_ERR_NO_ERROR else { return v_err; }
    }

    committed = true;
    return rfc::H2_ERR_NO_ERROR;
}

// Decodes a complete HPACK header block into `out_pseudo` and `out_headers` using stack scratch buffers.
//
// Example:
//   src = [0x82, 0x86, 0x84], out_pseudo = PseudoHeaders { .. }, out_headers = http::HeaderMap { .. }
//   returns: error_code = ERR_NO_ERROR, out_pseudo.method = "GET"
fn decode_hpack_to_map(
    dt:                   DynamicTable&,
    src:                  const u8[:],
    out_pseudo:           PseudoHeaders&,
    out_headers:          http::HeaderMap&,
    max_header_list_size: u32  = 8192,
    validate_http2_rules: bool = true,
) -> u32 {
    var name_buf: u8[..256]  = [];
    var val_buf:  u8[..8192] = [];
    return decode_hpack_to_map_with_scratch(
        dt,
        src,
        out_pseudo,
        out_headers,
        name_buf,
        val_buf,
        max_header_list_size,
        validate_http2_rules,
    );
}

enum HpackIndexing {
    Incremental,
    None,
    NeverIndexed,
}

// Encodes a single HTTP/2 header field into out with optional Huffman and dynamic indexing.
fn encode_hpack_field<B>(
    dt:          DynamicTable&,
    out:         B&,
    name:        const u8[:],
    val:         const u8[:],
    indexing:    HpackIndexing = HpackIndexing.Incremental,
    use_huffman: bool          = true,
) -> bool {
    let start_len = out.len;
    var committed = false;
    defer if !committed { out.resize(start_len); };
    let is_never = (indexing == HpackIndexing.NeverIndexed);
    let is_inc = (indexing == HpackIndexing.Incremental);

    var s_idx:       u64 = 0;
    var d_match_idx: u64 = 0;
    if !is_never {
        // 1. Check for exact match in static table
        let found_s, exact_s = h2_internal::find_hpack_static_field(name, val);
        s_idx = found_s;
        if s_idx > 0 && exact_s {
            guard hpack_encode_int(out, s_idx, 7, 0x80) else { return false; }
            committed = true;
            return true;
        }

        // 2. Check for O(1) direct-mapped hash hit in dynamic table
        let fast_idx, fast_ok = h2_internal::hpack_hash_lookup(dt, name, val);
        if fast_ok && fast_idx >= 62 {
            guard hpack_encode_int(out, fast_idx as u64, 7, 0x80) else { return false; }
            committed = true;
            return true;
        }

        // 3. Fallback scan for name-only match or collision resolution in dynamic table
        let dyn_idx, d_exact = h2_internal::find_hpack_dynamic_field(dt, name, val);
        d_match_idx = dyn_idx;
        if d_exact {
            guard hpack_encode_int(out, d_match_idx, 7, 0x80) else { return false; }
            committed = true;
            return true;
        }
    } else {
        let found_s, _ = h2_internal::find_hpack_static_field(name, val);
        s_idx = found_s;
    }

    let prefix_mask: u8 = if is_inc { 0x40 } else if is_never { 0x10 } else { 0x00 };
    let prefix_bits: u8 = if is_inc { 6 } else { 4 };

    let name_ref_idx = if s_idx > 0 { s_idx } else { d_match_idx };
    if name_ref_idx > 0 {
        guard hpack_encode_int(out, name_ref_idx, prefix_bits, prefix_mask) else { return false; }
    } else {
        guard hpack_encode_int(out, 0, prefix_bits, prefix_mask) &&
              encode_hpack_string_literal(out, name, use_huffman) else {
            return false;
        }
    }

    guard encode_hpack_string_literal(out, val, use_huffman) else { return false; }

    if is_inc {
        insert_header(dt, name, val, false);
    }
    committed = true;
    return true;
}

// Selects the HPACK indexing representation for a header field (RFC 7541 §7.1).
// Protects sensitive credentials with NeverIndexed and omits volatile or oversized entries from the dynamic table.
fn select_hpack_indexing(name: const u8[:], val: const u8[:], max_table_size: i64) -> HpackIndexing {
    if name.eq_ascii_fold("authorization") || name.eq_ascii_fold("proxy-authorization") {
        return HpackIndexing.NeverIndexed;
    }
    if name.eq_ascii_fold("cookie") && val.len < 20 {
        return HpackIndexing.NeverIndexed;
    }
    let entry_size = core::add_sat_i64(core::add_sat_i64(name.len, val.len), 32);
    let q_size = max(0, max_table_size) >> 2;
    let threshold = core::add_sat_i64(core::add_sat_i64(q_size, q_size), q_size);
    if h2_internal::is_hpack_volatile_header(name) || entry_size > threshold {
        return HpackIndexing.None;
    }
    return HpackIndexing.Incremental;
}

fn encode_hpack_string_literal<B>(out: B&, raw: const u8[:], use_huffman: bool) -> bool {
    let saved_len = out.len;
    if use_huffman {
        let huff_len = huff_encoded_byte_len(raw);
        if huff_len < (raw.len as u64) {
            if hpack_encode_int(out, huff_len, 7, 0x80) && huff_encode_bytes(raw, out) {
                return true;
            }
            out.resize(saved_len);
            return false;
        }
    }
    if hpack_encode_int(out, raw.len as u64, 7, 0x00) && out.try_append(raw) {
        return true;
    }
    out.resize(saved_len);
    return false;
}
