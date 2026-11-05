// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/3 and QPACK Field Compression Engine (RFC 9204, RFC 9114).
// Implements RFC 9204 static table (99 entries), zero-allocation dynamic table ring,
// modular RIC prefix codec, blocked streams manager, and Header Accordion DoS mitigations.
namespace internal;

import std;
import core from "..";
import http.headers;

// ---- constants, error codes and limits -----------------------------------

const QPACK_DEFAULT_MAX_TABLE:   u64 = 4096;
const QPACK_MAX_BLOCKED_STREAMS: u32 = 128;

enum QpackError {
    None,
    StreamBlocked,           // Stream is blocked waiting for encoder stream
    DecompressionFailed,     // H3_ERR_QPACK_DECOMPRESSION_FAILED (0x0200)
    EncoderStreamError,      // H3_ERR_QPACK_ENCODER_STREAM_ERROR (0x0201)
    DecoderStreamError,      // H3_ERR_QPACK_DECODER_STREAM_ERROR (0x0202)
    HeaderListTooLarge,      // Exceeded SETTINGS_MAX_FIELD_SECTION_SIZE
    BlockedStreamsExhausted, // Exceeded SETTINGS_QPACK_BLOCKED_STREAMS
    ClosedCriticalStream,    // H3_ERR_CLOSED_CRITICAL_STREAM (0x0104)
    StreamCreationError,     // H3_ERR_STREAM_CREATION (0x0103)
    FrameEncodingError,      // H3_ERR_FRAME_ERROR
    MessageError,            // H3_ERR_GENERAL_PROTOCOL (0x0101) / H3_ERR_MESSAGE_ERROR (0x010E)
}

// Decoded HTTP/3 pseudo-header fields and message validation metadata (RFC 9114 §4.3).
struct H3PseudoHeaders {
    method:             u8[..16]   = [],
    scheme:             u8[..16]   = [],
    authority:          u8[..256]  = [],
    path:               u8[..1024] = [],
    protocol:           u8[..64]   = [],
    status:             i32        = 0,
    has_method:         bool       = false,
    has_scheme:         bool       = false,
    has_authority:      bool       = false,
    has_path:           bool       = false,
    has_protocol:       bool       = false,
    has_status:         bool       = false,
    has_regular_header: bool       = false,
    content_length:     i64        = -1,
    is_trailer:         bool       = false,
}

inline fn clear_h3_pseudo_headers(pseudo: H3PseudoHeaders&, preserve_is_trailer: bool = true) {
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

struct HeaderField {
    name:        u8[..256]  = [],
    value:       u8[..4096] = [],
    never_index: bool       = false,
}

struct DynamicEntryDesc {
    abs_index: u64 = 0,
    ref_count: u32 = 0,
    name_off:  u32 = 0,
    name_len:  u16 = 0,
    val_off:   u32 = 0,
    val_len:   u16 = 0,
}

struct DynamicEntry {
    abs_index: u64        = 0,
    ref_count: u32        = 0,
    name:      u8[..256]  = [],
    value:     u8[..4096] = [],
}

struct BlockedStreamEntry {
    stream_id:        u64        = 0,
    req_insert_count: u64        = 0,
    encoded_data:     u8[..4096] = [],
}

struct UnackedSection {
    stream_id:   u64       = 0,
    ric:         u64       = 0,
    ref_entries: u64[..32] = [],
}

struct QpackTable {
    head_idx:              u32                       = 0,
    capacity_bytes:        u64                       = 0,
    max_capacity_bytes:    u64                       = 0,
    used_bytes:            u64                       = 0,
    insert_count:          u64                       = 0, // TotalNumberOfInserts
    known_rcvd_count:      u64                       = 0, // Known Received Count
    draining_index:        u64                       = 0, // Active indexing lower bound
    max_blocked:           u32                       = 16,
    max_field_section:     u64                       = 16384,
    encoder_stream_opened: bool                      = false,
    decoder_stream_opened: bool                      = false,
    control_stream_opened: bool                      = false,
    blocked_streams:       BlockedStreamEntry[..128] = [],
    unacked_sections:      UnackedSection[..16]      = [],
    arena:                 u8[16384]                 = [0; 16384],
    arena_write_pos:       u32                       = 0,
    entries:               DynamicEntryDesc[..128]   = [],
}

// Calculates RFC 9204 Section 3.2.1 protocol weight (+32 byte overhead).
fn qpack_entry_cost(name_len: u64, val_len: u64) -> u64 {
    return name_len + val_len + rfc::QPACK_ENTRY_OVERHEAD;
}

// ---- rfc 9204 appendix a static table -----------------------------------

struct QpackStaticEntry {
    name: const u8[:] = "",
    val:  const u8[:] = "",
}

const QPACK_STATIC_TABLE: QpackStaticEntry[99] = [
    QpackStaticEntry { name: ":authority", val: "" }, // 0
    QpackStaticEntry { name: ":path", val: "/" },     // 1
    QpackStaticEntry { name: "age", val: "0" },       // 2
    QpackStaticEntry { name: "content-disposition", val: "" }, // 3
    QpackStaticEntry { name: "content-length", val: "0" },     // 4
    QpackStaticEntry { name: "cookie", val: "" },     // 5
    QpackStaticEntry { name: "date", val: "" },       // 6
    QpackStaticEntry { name: "etag", val: "" },       // 7
    QpackStaticEntry { name: "if-modified-since", val: "" }, // 8
    QpackStaticEntry { name: "if-none-match", val: "" },     // 9
    QpackStaticEntry { name: "last-modified", val: "" },     // 10
    QpackStaticEntry { name: "link", val: "" },       // 11
    QpackStaticEntry { name: "location", val: "" },   // 12
    QpackStaticEntry { name: "referer", val: "" },    // 13
    QpackStaticEntry { name: "set-cookie", val: "" }, // 14
    QpackStaticEntry { name: ":method", val: "CONNECT" }, // 15
    QpackStaticEntry { name: ":method", val: "DELETE" },  // 16
    QpackStaticEntry { name: ":method", val: "GET" },     // 17
    QpackStaticEntry { name: ":method", val: "HEAD" },    // 18
    QpackStaticEntry { name: ":method", val: "OPTIONS" }, // 19
    QpackStaticEntry { name: ":method", val: "POST" },    // 20
    QpackStaticEntry { name: ":method", val: "PUT" },     // 21
    QpackStaticEntry { name: ":scheme", val: "http" },    // 22
    QpackStaticEntry { name: ":scheme", val: "https" },   // 23
    QpackStaticEntry { name: ":status", val: "103" },     // 24
    QpackStaticEntry { name: ":status", val: "200" },     // 25
    QpackStaticEntry { name: ":status", val: "304" },     // 26
    QpackStaticEntry { name: ":status", val: "404" },     // 27
    QpackStaticEntry { name: ":status", val: "503" },     // 28
    QpackStaticEntry { name: "accept", val: "*/*" },      // 29
    QpackStaticEntry { name: "accept", val: "application/dns-message" }, // 30
    QpackStaticEntry { name: "accept-encoding", val: "gzip, deflate, br" }, // 31
    QpackStaticEntry { name: "accept-ranges", val: "bytes" }, // 32
    QpackStaticEntry { name: "access-control-allow-headers", val: "cache-control" }, // 33
    QpackStaticEntry { name: "access-control-allow-headers", val: "content-type" },  // 34
    QpackStaticEntry { name: "access-control-allow-origin", val: "*" }, // 35
    QpackStaticEntry { name: "cache-control", val: "max-age=0" },       // 36
    QpackStaticEntry { name: "cache-control", val: "max-age=2592000" }, // 37
    QpackStaticEntry { name: "cache-control", val: "max-age=604800" },  // 38
    QpackStaticEntry { name: "cache-control", val: "no-cache" },        // 39
    QpackStaticEntry { name: "cache-control", val: "no-store" },        // 40
    QpackStaticEntry { name: "cache-control", val: "public, max-age=31536000" }, // 41
    QpackStaticEntry { name: "content-encoding", val: "br" },   // 42
    QpackStaticEntry { name: "content-encoding", val: "gzip" }, // 43
    QpackStaticEntry { name: "content-type", val: "application/dns-message" }, // 44
    QpackStaticEntry { name: "content-type", val: "application/javascript" },  // 45
    QpackStaticEntry { name: "content-type", val: "application/json" },        // 46
    QpackStaticEntry { name: "content-type", val: "application/x-www-form-urlencoded" }, // 47
    QpackStaticEntry { name: "content-type", val: "image/gif" },  // 48
    QpackStaticEntry { name: "content-type", val: "image/jpeg" }, // 49
    QpackStaticEntry { name: "content-type", val: "image/png" },  // 50
    QpackStaticEntry { name: "content-type", val: "text/css" },   // 51
    QpackStaticEntry { name: "content-type", val: "text/html; charset=utf-8" }, // 52
    QpackStaticEntry { name: "content-type", val: "text/plain" }, // 53
    QpackStaticEntry { name: "content-type", val: "text/plain;charset=utf-8" }, // 54
    QpackStaticEntry { name: "range", val: "bytes=0-" },          // 55
    QpackStaticEntry { name: "strict-transport-security", val: "max-age=31536000" }, // 56
    QpackStaticEntry { name: "strict-transport-security", val: "max-age=31536000; includesubdomains" }, // 57
    QpackStaticEntry { name: "strict-transport-security", val: "max-age=31536000; includesubdomains; preload" }, // 58
    QpackStaticEntry { name: "vary", val: "accept-encoding" },    // 59
    QpackStaticEntry { name: "vary", val: "origin" },             // 60
    QpackStaticEntry { name: "x-content-type-options", val: "nosniff" }, // 61
    QpackStaticEntry { name: "x-xss-protection", val: "1; mode=block" }, // 62
    QpackStaticEntry { name: ":status", val: "100" }, // 63
    QpackStaticEntry { name: ":status", val: "204" }, // 64
    QpackStaticEntry { name: ":status", val: "206" }, // 65
    QpackStaticEntry { name: ":status", val: "302" }, // 66
    QpackStaticEntry { name: ":status", val: "400" }, // 67
    QpackStaticEntry { name: ":status", val: "403" }, // 68
    QpackStaticEntry { name: ":status", val: "421" }, // 69
    QpackStaticEntry { name: ":status", val: "425" }, // 70
    QpackStaticEntry { name: ":status", val: "500" }, // 71
    QpackStaticEntry { name: "accept-language", val: "" }, // 72
    QpackStaticEntry { name: "access-control-allow-credentials", val: "FALSE" }, // 73
    QpackStaticEntry { name: "access-control-allow-credentials", val: "TRUE" },  // 74
    QpackStaticEntry { name: "access-control-allow-headers", val: "*" },         // 75
    QpackStaticEntry { name: "access-control-allow-methods", val: "get" },       // 76
    QpackStaticEntry { name: "access-control-allow-methods", val: "get, post, options" }, // 77
    QpackStaticEntry { name: "access-control-allow-methods", val: "options" },    // 78
    QpackStaticEntry { name: "access-control-expose-headers", val: "content-length" }, // 79
    QpackStaticEntry { name: "access-control-request-headers", val: "content-type" },  // 80
    QpackStaticEntry { name: "access-control-request-method", val: "get" },  // 81
    QpackStaticEntry { name: "access-control-request-method", val: "post" }, // 82
    QpackStaticEntry { name: "alt-svc", val: "clear" },                      // 83
    QpackStaticEntry { name: "authorization", val: "" },                     // 84
    QpackStaticEntry { name: "content-security-policy", val: "script-src 'none'; object-src 'none'; base-uri 'none'" }, // 85
    QpackStaticEntry { name: "early-data", val: "1" },                       // 86
    QpackStaticEntry { name: "expect-ct", val: "" },                         // 87
    QpackStaticEntry { name: "forwarded", val: "" },                         // 88
    QpackStaticEntry { name: "if-range", val: "" },                          // 89
    QpackStaticEntry { name: "origin", val: "" },                            // 90
    QpackStaticEntry { name: "purpose", val: "prefetch" },                   // 91
    QpackStaticEntry { name: "server", val: "" },                            // 92
    QpackStaticEntry { name: "timing-allow-origin", val: "*" },              // 93
    QpackStaticEntry { name: "upgrade-insecure-requests", val: "1" },        // 94
    QpackStaticEntry { name: "user-agent", val: "" },                        // 95
    QpackStaticEntry { name: "x-forwarded-for", val: "" },                   // 96
    QpackStaticEntry { name: "x-frame-options", val: "deny" },               // 97
    QpackStaticEntry { name: "x-frame-options", val: "sameorigin" },         // 98
];

// Returns static table entry at 0-based index (0..98).
fn get_qpack_static_field(idx: u64) -> QpackStaticEntry, bool {
    guard idx < rfc::QPACK_STATIC_TABLE_SIZE else {
        return QpackStaticEntry { .. }, false;
    }
    return QPACK_STATIC_TABLE[idx as i64], true;
}

// Searches static table for matching name and optional value.
// Returns (0-based index, exact_value_match).
fn find_qpack_static_field(name: const u8[:], val: const u8[:]) -> u64, bool {
    var matched_name_idx: u64 = 0;
    var name_found = false;
    var idx: u64 = 0;
    while idx < rfc::QPACK_STATIC_TABLE_SIZE {
        let entry = QPACK_STATIC_TABLE[idx as i64];
        if entry.name == name {
            if entry.val == val {
                return idx, true;
            }
            if !name_found {
                matched_name_idx = idx;
                name_found = true;
            }
        }
        idx++;
    }
    return matched_name_idx, false;
}

// ---- prefix integer codec (ric and base) --------------------------------

// Decodes a QPACK prefixed integer up to 62 bits (RFC 9204 Section 4.1.1).
// Returns (value, next_offset, ok).
// Guarantees zero allocation, 62-bit boundary checks, and overflow detection.
//
// Example:
//   src = [0x0A], offset = 0, prefix_bits = 5
//   returns: 10, 1, true
fn qpack_decode_int(src: const u8[:], offset: u64, prefix_bits: u8) -> u64, u64, bool {
    guard offset < (src.len as u64) else { return 0, offset, false; }
    guard prefix_bits >= 1 && prefix_bits <= 8 else { return 0, offset, false; }

    let mask = (((1 as u32) << prefix_bits) - 1) as u8;
    var val = (src[offset] & mask) as u64;
    var idx = offset + 1;

    if val < mask {
        return val, idx, true;
    }

    // Multibyte continuation (RFC 7541 Section 5.1 & RFC 9204 Section 4.1.1)
    var shift: u32 = 0;
    while idx < (src.len as u64) {
        let b = src[idx];
        let payload = (b & 0x7F) as u64;

        // Up to 62 bits: maximum shift is 56
        if shift > 56 || (shift == 56 && (payload > 0x3F || (b & 0x80) != 0)) {
            return 0, idx, false; // Exceeds 62 bits: RFC 9204 §4.1.1 overflow
        }

        let term = payload << shift;
        if (rfc::QUIC_VARINT_MAX - val) < term {
            return 0, idx, false; // Overflow beyond 2^62 - 1
        }
        val += term;
        idx++;

        if (b & 0x80) == 0 {
            return val, idx, true;
        }
        shift += 7;
    }

    return 0, offset, false;
}

// Decodes Required Insert Count per RFC 9204 Section 4.5.1.1.
//
// Example:
//   enc_ric = 0, total_inserts = 0, max_cap = 4096
//   returns: 0, QpackError.None
fn decode_ric(enc_ric: u64, total_inserts: u64, max_cap: u64) -> u64, QpackError {
    if enc_ric == 0 {
        return 0, QpackError.None;
    }
    let max_entries = max_cap / rfc::QPACK_ENTRY_OVERHEAD;
    let full_range = 2 * max_entries;
    guard full_range > 0 && enc_ric <= full_range else {
        return 0, QpackError.DecompressionFailed;
    }
    guard (0xFFFFFFFFFFFFFFFF - total_inserts) >= max_entries else {
        return 0, QpackError.DecompressionFailed;
    }
    let max_value = total_inserts + max_entries;
    let max_wrapped = (max_value / full_range) * full_range;
    guard (0xFFFFFFFFFFFFFFFF - max_wrapped) >= (enc_ric - 1) else {
        return 0, QpackError.DecompressionFailed;
    }
    var ric = max_wrapped + enc_ric - 1;

    if ric > max_value {
        guard ric > full_range else {
            return 0, QpackError.DecompressionFailed;
        }
        ric -= full_range;
    }
    guard ric != 0 && ric <= 0x3FFFFFFFFFFFFFFF else {
        return 0, QpackError.DecompressionFailed;
    }
    return ric, QpackError.None;
}

// Encodes Required Insert Count per RFC 9204 Section 4.5.1.1.
fn encode_ric(ric: u64, max_cap: u64) -> u64 {
    if ric == 0 {
        return 0;
    }
    let max_entries = max_cap / rfc::QPACK_ENTRY_OVERHEAD;
    let full_range = 2 * max_entries;
    if full_range == 0 {
        return 0;
    }
    return (ric % full_range) + 1;
}

// Decodes Base index from sign bit S and DeltaBase (RFC 9204 Section 4.5.1.2).
// RFC 9204 §4.5.1.2: If Required Insert Count is 0, any non-negative Base is valid.
// Sign bit 1 is invalid when RIC is 0 since Base would be negative.
//
// Example:
//   sign_bit = 0, delta_base = 0, ric = 0
//   returns: 0, QpackError.None
fn decode_base(sign_bit: u8, delta_base: u64, ric: u64) -> u64, QpackError {
    guard sign_bit == 0 || sign_bit == 1 else {
        return 0, QpackError.DecompressionFailed;
    }
    if ric == 0 {
        guard sign_bit == 0 else {
            return 0, QpackError.DecompressionFailed;
        }
        guard delta_base <= 0x3FFFFFFFFFFFFFFF else {
            return 0, QpackError.DecompressionFailed;
        }
        return delta_base, QpackError.None;
    }
    if sign_bit == 0 {
        guard (0xFFFFFFFFFFFFFFFF - ric) >= delta_base else {
            return 0, QpackError.DecompressionFailed;
        }
        let base = ric + delta_base;
        guard base <= 0x3FFFFFFFFFFFFFFF else {
            return 0, QpackError.DecompressionFailed;
        }
        return base, QpackError.None;
    }
    guard ric > delta_base else {
        return 0, QpackError.DecompressionFailed;
    }
    return ric - delta_base - 1, QpackError.None;
}

// Encodes Base index relative to RIC into sign bit and DeltaBase.
fn encode_base(base: u64, ric: u64) -> u8, u64 {
    if ric == 0 {
        return 0, 0;
    }
    if base >= ric {
        return 0, base - ric;
    }
    return 1, ric - base - 1;
}

// ---- dynamic table management & eviction --------------------------------

inline fn is_qpack_token_char(c: u8) -> bool {
    if c >= 'a' && c <= 'z' { return true; }
    if c >= '0' && c <= '9' { return true; }
    return c == '!' || c == '#' || c == '$' || c == '%' || c == '&' ||
           c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' ||
           c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}

inline fn validate_qpack_entry_name(name: const u8[:]) -> bool {
    guard name.len > 0 && name.len <= 256 else { return false; }
    return validate_qpack_field_name(name);
}

inline fn validate_qpack_field_val(val: const u8[:]) -> bool {
    for b in val {
        if b == 0 || b == '\r' || b == '\n' {
            return false;
        }
    }
    if val.len > 0 {
        let first = val[0];
        let last = val[val.len - 1];
        if first == ' ' || first == '\t' || last == ' ' || last == '\t' {
            return false;
        }
    }
    return true;
}

inline fn validate_qpack_field_name(name: const u8[:]) -> bool {
    guard name.len > 0 && (name.len > 1 || name[0] != ':') else { return false; }
    for i in name.len {
        let c = name[i];
        if i == 0 && c == ':' {
            continue;
        }
        if !is_qpack_token_char(c) {
            return false;
        }
    }
    return true;
}

fn new_qpack_table(
    max_capacity:     u64 = 4096,
    max_blocked:      u32 = 16,
    initial_capacity: u64 = 4096,
) -> QpackTable {
    let eff_cap = if initial_capacity < max_capacity { initial_capacity } else { max_capacity };
    return QpackTable {
        capacity_bytes:     eff_cap,
        max_capacity_bytes: max_capacity,
        max_blocked:        max_blocked,
        ..
    };
}

// Compacts dynamic table arena in place to reclaim space from evicted entries.
fn qpack_compact_arena(tbl: QpackTable&) {
    var new_arena: u8[16384] = [0; 16384];
    var new_pos:   u32       = 0;
    for i in tbl.entries.len {
        let n_len = tbl.entries[i].name_len as u32;
        let v_len = tbl.entries[i].val_len as u32;
        let old_n_off = tbl.entries[i].name_off as i64;
        let old_v_off = tbl.entries[i].val_off as i64;
        let new_pos_i = new_pos as i64;

        for j in (n_len as i64) {
            new_arena[new_pos_i + j] = tbl.arena[old_n_off + j];
        }
        tbl.entries[i].name_off = new_pos;
        new_pos += n_len;

        let next_pos_i = new_pos as i64;
        for j in (v_len as i64) {
            new_arena[next_pos_i + j] = tbl.arena[old_v_off + j];
        }
        tbl.entries[i].val_off = new_pos;
        new_pos += v_len;
    }
    for k in (new_pos as i64) {
        tbl.arena[k] = new_arena[k];
    }
    tbl.arena_write_pos = new_pos;
}

// Evicts entries from the dynamic table until used_bytes <= target_bytes.
// Returns false if an eviction barrier (referenced entry) prevents eviction.
fn qpack_evict_until(tbl: QpackTable&, target_bytes: u64) -> bool {
    while tbl.entries.len > 0 && tbl.used_bytes > target_bytes {
        let oldest = tbl.entries[0];
        if oldest.ref_count > 0 {
            return false;
        }
        let cost = qpack_entry_cost(oldest.name_len, oldest.val_len);
        tbl.used_bytes = if tbl.used_bytes >= cost { tbl.used_bytes - cost } else { 0 };
        tbl.entries.remove_at(0);
    }
    tbl.draining_index = if tbl.entries.len > 0 { tbl.entries[0].abs_index } else { tbl.insert_count };
    if tbl.entries.len == 0 {
        tbl.arena_write_pos = 0;
    }
    return tbl.used_bytes <= target_bytes;
}

// Updates dynamic table capacity via Set Dynamic Table Capacity instruction.
fn qpack_set_capacity(tbl: QpackTable&, new_cap: u64) -> bool {
    guard new_cap <= tbl.max_capacity_bytes else { return false; }
    let ok = qpack_evict_until(tbl, new_cap);
    guard ok else { return false; }
    tbl.capacity_bytes = new_cap;
    return true;
}

inline fn copy_to_arena(tbl: QpackTable&, name: const u8[:], val: const u8[:]) -> u32, u32 {
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

inline fn ensure_arena_capacity(tbl: QpackTable&, raw_len: u32) -> bool {
    if tbl.arena_write_pos + raw_len > 16384 {
        qpack_compact_arena(tbl);
    }
    return tbl.arena_write_pos + raw_len <= 16384;
}

inline fn validate_literal_inputs(name: const u8[:], val: const u8[:]) -> bool {
    guard validate_qpack_entry_name(name) else { return false; }
    guard val.len <= 4096 else { return false; }
    return validate_qpack_field_val(val);
}

inline fn prepare_table_for_entry(tbl: QpackTable&, cost: u64, raw_len: u32) -> bool {
    guard cost <= tbl.capacity_bytes else { return false; }
    guard qpack_evict_until(tbl, tbl.capacity_bytes - cost) else { return false; }
    guard tbl.entries.len < tbl.entries.cap else { return false; }
    return ensure_arena_capacity(tbl, raw_len);
}

// Inserts an entry into the dynamic table with literal name and value.
fn qpack_insert_literal(tbl: QpackTable&, name: const u8[:], val: const u8[:]) -> bool {
    guard validate_literal_inputs(name, val) else { return false; }

    let cost = qpack_entry_cost(name.len as u64, val.len as u64);
    let raw_len = (name.len + val.len) as u32;
    guard prepare_table_for_entry(tbl, cost, raw_len) else { return false; }

    let n_off, v_off = copy_to_arena(tbl, name, val);
    var ent = DynamicEntryDesc {
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

inline fn copy_arena_entry(
    arena:    const u8[:],
    n_off:    u32,
    n_len:    u16,
    v_off:    u32,
    v_len:    u16,
    out_name: u8[..256]&,
    out_val:  u8[..4096]&,
) -> bool {
    let n_start = n_off as i64;
    let n_end = n_start + n_len;
    let v_start = v_off as i64;
    let v_end = v_start + v_len;
    guard n_end <= 16384 else { return false; }
    guard v_end <= 16384 else { return false; }
    out_name.append(arena[n_start..n_end]);
    out_val.append(arena[v_start..v_end]);
    return true;
}

// Looks up an entry by absolute index in dynamic table.
fn qpack_lookup_absolute(
    tbl:      const QpackTable&,
    abs_idx:  u64,
    out_name: u8[..256]&,
    out_val:  u8[..4096]&,
) -> bool {
    out_name.clear();
    out_val.clear();
    for &e in tbl.entries {
        if e.abs_index == abs_idx {
            return copy_arena_entry(tbl.arena[..], e.name_off, e.name_len, e.val_off, e.val_len, out_name, out_val);
        }
    }
    return false;
}

// Inserts an entry referencing a dynamic name by relative index.
fn qpack_insert_named_dynamic(tbl: QpackTable&, rel_idx: u64, val: const u8[:]) -> bool {
    guard tbl.insert_count > rel_idx else { return false; }
    let target_abs = tbl.insert_count - rel_idx - 1;

    var n_buf: u8[..256]  = [];
    var v_buf: u8[..4096] = [];
    guard qpack_lookup_absolute(tbl, target_abs, n_buf, v_buf) else { return false; }
    return qpack_insert_literal(tbl, n_buf[..], val);
}

// Duplicates an existing dynamic table entry by relative index.
fn qpack_duplicate(tbl: QpackTable&, rel_idx: u64) -> bool {
    guard tbl.insert_count > rel_idx else { return false; }
    let target_abs = tbl.insert_count - rel_idx - 1;

    var n_buf: u8[..256]  = [];
    var v_buf: u8[..4096] = [];
    guard qpack_lookup_absolute(tbl, target_abs, n_buf, v_buf) else { return false; }
    return qpack_insert_literal(tbl, n_buf[..], v_buf[..]);
}

// Pins an entry in the dynamic table to prevent eviction while in active use (RFC 9204 §2.1.1).
fn qpack_pin_entry(tbl: QpackTable&, abs_idx: u64) -> bool {
    for i in tbl.entries.len {
        if tbl.entries[i].abs_index == abs_idx {
            tbl.entries[i].ref_count++;
            return true;
        }
    }
    return false;
}

// Unpins an entry in the dynamic table after active reference is released.
fn qpack_unpin_entry(tbl: QpackTable&, abs_idx: u64) -> bool {
    for i in tbl.entries.len {
        if tbl.entries[i].abs_index == abs_idx {
            if tbl.entries[i].ref_count > 0 {
                tbl.entries[i].ref_count--;
            }
            return true;
        }
    }
    return false;
}

// Tracks an unacknowledged stream section with its Required Insert Count (RFC 9204 §4.4.1).
fn qpack_track_unacked_stream(tbl: QpackTable&, stream_id: u64, ric: u64) -> bool {
    for i in tbl.unacked_sections.len {
        if tbl.unacked_sections[i].stream_id == stream_id {
            if ric > tbl.unacked_sections[i].ric {
                tbl.unacked_sections[i].ric = ric;
            }
            return true;
        }
    }
    guard tbl.unacked_sections.len < tbl.unacked_sections.cap else {
        return false;
    }
    var entry = UnackedSection {
        stream_id:   stream_id,
        ric:         ric,
        ref_entries: [],
    };
    tbl.unacked_sections.push(entry);
    return true;
}

// Associates a dynamic table entry reference with an unacknowledged stream (RFC 9204 §2.1.1, §4.4.2).
// Pins the dynamic table entry and records the reference for subsequent ACK or cancellation release.
fn qpack_track_stream_ref(tbl: QpackTable&, stream_id: u64, abs_idx: u64) -> bool {
    guard qpack_pin_entry(tbl, abs_idx) else {
        return false;
    }
    for i in tbl.unacked_sections.len {
        if tbl.unacked_sections[i].stream_id == stream_id {
            guard tbl.unacked_sections[i].ref_entries.try_push(abs_idx) else {
                qpack_unpin_entry(tbl, abs_idx);
                return false;
            }
            return true;
        }
    }
    guard tbl.unacked_sections.len < tbl.unacked_sections.cap else {
        qpack_unpin_entry(tbl, abs_idx);
        return false;
    }
    var entry = UnackedSection {
        stream_id:   stream_id,
        ric:         0,
        ref_entries: [],
    };
    entry.ref_entries.push(abs_idx);
    tbl.unacked_sections.push(entry);
    return true;
}

inline fn find_unacked_stream_idx(tbl: const QpackTable&, stream_id: u64) -> i64 {
    for i in tbl.unacked_sections.len {
        if tbl.unacked_sections[i].stream_id == stream_id {
            return i;
        }
    }
    return -1;
}

inline fn release_section_refs(tbl: QpackTable&, refs: const u64[:]) {
    for ref_abs in refs {
        qpack_unpin_entry(tbl, ref_abs);
    }
}

inline fn release_and_remove_unacked(tbl: QpackTable&, stream_id: u64) {
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

// Section Acknowledgment instruction handler (Decoder -> Encoder) (RFC 9204 §4.4.1).
// Updates known_rcvd_count to max(known_rcvd_count, section.ric), releases dynamic table
// entry references, and removes the unacknowledged stream entry.
// Returns QpackError.DecoderStreamError if stream was not unacknowledged or had ric == 0.
fn qpack_ack_section(tbl: QpackTable&, stream_id: u64, ric: u64 = 0) -> QpackError {
    let found_idx = find_unacked_stream_idx(tbl, stream_id);
    var effective_ric = ric;
    if found_idx >= 0 {
        let u_ric = tbl.unacked_sections[found_idx].ric;
        if u_ric > effective_ric {
            effective_ric = u_ric;
        }
        release_section_refs(tbl, tbl.unacked_sections[found_idx].ref_entries[..]);
        tbl.unacked_sections.remove_at(found_idx as i32);
    } else {
        guard effective_ric > 0 else {
            return QpackError.DecoderStreamError;
        }
    }

    if effective_ric > tbl.known_rcvd_count {
        tbl.known_rcvd_count = effective_ric;
    }

    qpack_unblock_stream(tbl, stream_id);
    return QpackError.None;
}

// Stream Cancellation instruction handler (Decoder -> Encoder) (RFC 9204 §4.4.2).
// Releases all dynamic table entry references held by the identified stream.
fn qpack_cancel_stream(tbl: QpackTable&, stream_id: u64) {
    release_and_remove_unacked(tbl, stream_id);
    qpack_unblock_stream(tbl, stream_id);
}

// Insert Count Increment instruction handler (Decoder -> Encoder).
fn qpack_increment_received(tbl: QpackTable&, inc: u64) {
    tbl.known_rcvd_count += inc;
}

// Checks if a new stream can be blocked according to SETTINGS_QPACK_BLOCKED_STREAMS (RFC 9204 §2.1.2).
fn qpack_can_block_stream(tbl: const QpackTable&) -> bool {
    return tbl.blocked_streams.len < tbl.max_blocked;
}

// Records a blocked stream waiting for TotalNumberOfInserts to reach req_insert_count (RFC 9204 §2.1.2).
fn qpack_block_stream(tbl: QpackTable&, stream_id: u64, ric: u64, data: const u8[:]) -> bool {
    guard tbl.blocked_streams.len < tbl.max_blocked else { return false; }
    guard tbl.blocked_streams.len < tbl.blocked_streams.cap else { return false; }
    for &b in tbl.blocked_streams {
        if b.stream_id == stream_id {
            return false;
        }
    }
    var entry = BlockedStreamEntry {
        stream_id:        stream_id,
        req_insert_count: ric,
        ..
    };
    guard data.len <= entry.encoded_data.cap else { return false; }
    entry.encoded_data.append(data);
    tbl.blocked_streams.push(entry);
    return true;
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

// Unblocks and removes a blocked stream entry once required insert count is satisfied.
fn qpack_unblock_stream(tbl: QpackTable&, stream_id: u64) -> bool {
    var i = 0;
    while i < tbl.blocked_streams.len {
        if tbl.blocked_streams[i].stream_id == stream_id {
            tbl.blocked_streams.remove_at(i);
            return true;
        }
        i++;
    }
    return false;
}

// ---- encoder / decoder instruction dispatch ------------------------------

// Decodes string literal with Huffman or raw octets (RFC 9204 Section 4.1.2).
//
// Example:
//   src = [0x05, 0x68, 0x65, 0x6C, 0x6C, 0x6F], offset = 0, prefix_bits = 7, out = []
//   returns: 6, true, out = "hello"
fn decode_qpack_string<B>(src: const u8[:], offset: u64, prefix_bits: u8, out: B&) -> u64, bool {
    guard offset < (src.len as u64) else { return offset, false; }
    let is_huff = (src[offset] & ((1 as u8) << prefix_bits)) != 0;
    let str_len, next_off, ok_len = qpack_decode_int(src, offset, prefix_bits);
    guard ok_len else { return offset, false; }

    let noff = next_off as i64;
    let slen = str_len as i64;
    guard noff >= 0 && slen >= 0 && noff <= (src.len - slen) else { return offset, false; }

    let raw_slice = src[noff..noff + slen];
    if is_huff {
        let ok_huff = internal::huff_decode_bytes(raw_slice, out);
        guard ok_huff else { return offset, false; }
    } else {
        guard out.len + raw_slice.len <= out.cap else { return offset, false; }
        out.append(raw_slice);
    }
    return next_off + str_len, true;
}

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

// ---- incremental field emission & header accordion protection ------------

inline fn validate_field_syntax(name: const u8[:], val: const u8[:]) -> bool {
    guard validate_qpack_field_name(name) else { return false; }
    return validate_qpack_field_val(val);
}

inline fn append_header_field<F>(
    out_fields:  F&,
    name:        const u8[:],
    val:         const u8[:],
    never_index: bool,
) -> bool {
    var field = HeaderField { never_index: never_index, .. };
    guard name.len <= field.name.cap else { return false; }
    guard val.len <= field.value.cap else { return false; }
    field.name.append(name);
    field.value.append(val);
    out_fields.push(field);
    return true;
}

inline fn check_field_budget(budget_left: u64&, out_len: i64, cost: u64) -> bool {
    guard out_len < 128 else { return false; }
    guard budget_left >= cost else { return false; }
    budget_left -= cost;
    return true;
}

// Emits a parsed field line, enforcing SETTINGS_MAX_FIELD_SECTION_SIZE + 32-byte overhead.
fn emit_field_checked<F>(
    out_fields:  F&,
    budget_left: u64&,
    name:        const u8[:],
    val:         const u8[:],
    never_index: bool = false,
) -> QpackError {
    guard validate_field_syntax(name, val) else { return QpackError.DecompressionFailed; }
    let cost = qpack_entry_cost(name.len as u64, val.len as u64);
    guard check_field_budget(budget_left, out_fields.len, cost) else { return QpackError.HeaderListTooLarge; }
    guard append_header_field(out_fields, name, val, never_index) else { return QpackError.HeaderListTooLarge; }
    return QpackError.None;
}

inline fn record_dynamic_abs_used(abs_idx: u64, max_dyn_abs_used: u64&, used_any_dyn: bool&) {
    if !used_any_dyn || abs_idx > max_dyn_abs_used {
        max_dyn_abs_used = abs_idx;
        used_any_dyn = true;
    }
}

// Decodes a single QPACK field line representation.
//
// Example:
//   src = [0xD1], offset = 0
//   returns: QpackError.None, offset = 1, out_fields has decoded field
fn decode_qpack_field_line<F>(
    tbl:              const QpackTable&,
    src:              const u8[:],
    offset:           u64&,
    base:             u64,
    ric:              u64,
    budget:           u64&,
    out_fields:       F&,
    max_dyn_abs_used: u64&,
    used_any_dyn:     bool&,
) -> QpackError {
    let b = src[offset];

    // Case A: Indexed Field Line: 1Txxxxxx (6-bit prefix)
    if (b & 0x80) != 0 {
        let is_static = (b & 0x40) != 0;
        let idx, next_off, ok = qpack_decode_int(src, offset, 6);
        guard ok else { return QpackError.DecompressionFailed; }

        if is_static {
            let s_ent, s_ok = get_qpack_static_field(idx);
            guard s_ok else { return QpackError.DecompressionFailed; }
            let err = emit_field_checked(out_fields, budget, s_ent.name, s_ent.val, false);
            guard err == QpackError.None else { return err; }
        } else {
            guard base > idx else { return QpackError.DecompressionFailed; }
            let abs_idx = base - idx - 1;
            guard abs_idx < ric else { return QpackError.DecompressionFailed; } // RFC 9204 §4.5.2
            var n: u8[..256]  = [];
            var v: u8[..4096] = [];
            guard qpack_lookup_absolute(tbl, abs_idx, n, v) else {
                return QpackError.DecompressionFailed;
            }
            let err = emit_field_checked(out_fields, budget, n[..], v[..], false);
            guard err == QpackError.None else { return err; }
            record_dynamic_abs_used(abs_idx, max_dyn_abs_used, used_any_dyn);
        }
        offset = next_off;
        return QpackError.None;
    }

    // Case B: Indexed Field Line With Post-Base Index: 0001xxxx (4-bit prefix)
    if (b & 0xF0) == 0x10 {
        let post_idx, next_off, ok = qpack_decode_int(src, offset, 4);
        guard ok else { return QpackError.DecompressionFailed; }
        guard (0xFFFFFFFFFFFFFFFF - base) >= post_idx else { return QpackError.DecompressionFailed; }
        let abs_idx = base + post_idx;
        guard abs_idx < ric else { return QpackError.DecompressionFailed; } // RFC 9204 §4.5.3
        var n: u8[..256]  = [];
        var v: u8[..4096] = [];
        guard qpack_lookup_absolute(tbl, abs_idx, n, v) else {
            return QpackError.DecompressionFailed;
        }
        let err = emit_field_checked(out_fields, budget, n[..], v[..], false);
        guard err == QpackError.None else { return err; }
        record_dynamic_abs_used(abs_idx, max_dyn_abs_used, used_any_dyn);
        offset = next_off;
        return QpackError.None;
    }

    // Case C: Literal Field Line With Name Reference: 01NTxxxx (4-bit prefix)
    if (b & 0xC0) == 0x40 {
        let is_never_index = (b & 0x20) != 0;
        let is_static = (b & 0x10) != 0;
        let name_idx, val_start, ok_idx = qpack_decode_int(src, offset, 4);
        guard ok_idx else { return QpackError.DecompressionFailed; }

        var n: u8[..256] = [];
        if is_static {
            let s_ent, s_ok = get_qpack_static_field(name_idx);
            guard s_ok else { return QpackError.DecompressionFailed; }
            n.append(s_ent.name);
        } else {
            guard base > name_idx else { return QpackError.DecompressionFailed; }
            let abs_idx = base - name_idx - 1;
            guard abs_idx < ric else { return QpackError.DecompressionFailed; } // RFC 9204 §4.5.4
            var dummy_v: u8[..4096] = [];
            guard qpack_lookup_absolute(tbl, abs_idx, n, dummy_v) else {
                return QpackError.DecompressionFailed;
            }
            record_dynamic_abs_used(abs_idx, max_dyn_abs_used, used_any_dyn);
        }

        var v: u8[..4096] = [];
        let next_off, ok_val = decode_qpack_string(src, val_start, 7, v);
        guard ok_val else { return QpackError.DecompressionFailed; }

        let err = emit_field_checked(out_fields, budget, n[..], v[..], is_never_index);
        guard err == QpackError.None else { return err; }
        offset = next_off;
        return QpackError.None;
    }

    // Case D: Literal Field Line With Post-Base Name Reference: 0000Nxxx (3-bit prefix)
    if (b & 0xF0) == 0x00 {
        let is_never_index = (b & 0x08) != 0;
        let post_name_idx, val_start, ok_idx = qpack_decode_int(src, offset, 3);
        guard ok_idx else { return QpackError.DecompressionFailed; }
        guard (0xFFFFFFFFFFFFFFFF - base) >= post_name_idx else { return QpackError.DecompressionFailed; }
        let abs_idx = base + post_name_idx;
        guard abs_idx < ric else { return QpackError.DecompressionFailed; } // RFC 9204 §4.5.5

        var n:       u8[..256]  = [];
        var dummy_v: u8[..4096] = [];
        guard qpack_lookup_absolute(tbl, abs_idx, n, dummy_v) else {
            return QpackError.DecompressionFailed;
        }
        record_dynamic_abs_used(abs_idx, max_dyn_abs_used, used_any_dyn);

        var v: u8[..4096] = [];
        let next_off, ok_val = decode_qpack_string(src, val_start, 7, v);
        guard ok_val else { return QpackError.DecompressionFailed; }

        let err = emit_field_checked(out_fields, budget, n[..], v[..], is_never_index);
        guard err == QpackError.None else { return err; }
        offset = next_off;
        return QpackError.None;
    }

    // Case E: Literal Field Line With Literal Name: 001NHxxx (3-bit prefix name)
    if (b & 0xE0) == 0x20 {
        let is_never_index = (b & 0x10) != 0;
        var n: u8[..256] = [];
        let val_start, ok_name = decode_qpack_string(src, offset, 3, n);
        guard ok_name else { return QpackError.DecompressionFailed; }

        var v: u8[..4096] = [];
        let next_off, ok_val = decode_qpack_string(src, val_start, 7, v);
        guard ok_val else { return QpackError.DecompressionFailed; }

        let err = emit_field_checked(out_fields, budget, n[..], v[..], is_never_index);
        guard err == QpackError.None else { return err; }
        offset = next_off;
        return QpackError.None;
    }

    return QpackError.DecompressionFailed;
}

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
    var offset: u64 = 0;
    out_fields.clear();
    var budget = max_field_section;

    // 1. Decode EncodedInsertCount (8-bit prefix)
    let enc_ric, base_off, ok_ric = qpack_decode_int(src, offset, 8);
    guard ok_ric else { return QpackError.DecompressionFailed; }

    // RFC 9204 §4.5.1.1: MaxEntries is computed from MaxTableCapacity (set by decoder), NOT current capacity_bytes.
    let ric, ric_err = decode_ric(enc_ric, tbl.insert_count, tbl.max_capacity_bytes);
    guard ric_err == QpackError.None else { return ric_err; }

    // Blocked Streams constraint (RFC 9204 §2.1.2)
    if ric > tbl.insert_count && (tbl.max_blocked == 0 || tbl.blocked_streams.len >= tbl.max_blocked) {
        return QpackError.BlockedStreamsExhausted;
    }

    // 2. Decode Sign bit and DeltaBase (7-bit prefix)
    guard base_off < (src.len as u64) else { return QpackError.DecompressionFailed; }
    let sign_bit: u8 = if (src[base_off] & 0x80) != 0 { 1 } else { 0 };
    let delta_base, fields_off, ok_db = qpack_decode_int(src, base_off, 7);
    guard ok_db else { return QpackError.DecompressionFailed; }

    let base, base_err = decode_base(sign_bit, delta_base, ric);
    guard base_err == QpackError.None else { return base_err; }

    offset = fields_off;
    var max_dyn_abs_used: u64 = 0;
    var used_any_dyn = false;

    // 3. Decode Field Lines
    while offset < (src.len as u64) {
        let f_err = decode_qpack_field_line(
            tbl,
            src,
            offset,
            base,
            ric,
            budget,
            out_fields,
            max_dyn_abs_used,
            used_any_dyn,
        );
        guard f_err == QpackError.None else { return f_err; }
    }

    // Invariant: RFC 9204 §2.1.2 & §4.5.1: RIC must be >= min required insert count and <= insert_count.
    let min_ric = if used_any_dyn { max_dyn_abs_used + 1 } else { 0 };
    guard ric >= min_ric && ric <= tbl.insert_count else {
        return QpackError.DecompressionFailed;
    }

    return QpackError.None;
}

// Decodes an Encoded Field Section or records the stream as blocked if RIC exceeds insert_count (RFC 9204 §2.1.2).
//
// Example:
//   src = [0x00, 0x00, 0xd1], stream_id = 4
//   returns: QpackError.None, out_fields contains parsed headers
fn decode_or_block_qpack_section<F>(
    tbl:               QpackTable&,
    stream_id:         u64,
    src:               const u8[:],
    out_fields:        F&,
    max_field_section: u64 = 16384,
) -> QpackError {
    guard src.len >= 2 else { return QpackError.DecompressionFailed; }
    let enc_ric, _, ok_ric = qpack_decode_int(src, 0, 8);
    guard ok_ric else { return QpackError.DecompressionFailed; }
    let ric, ric_err = decode_ric(enc_ric, tbl.insert_count, tbl.max_capacity_bytes);
    guard ric_err == QpackError.None else { return ric_err; }

    if ric > tbl.insert_count {
        guard qpack_can_block_stream(tbl) else {
            return QpackError.BlockedStreamsExhausted;
        }
        guard qpack_block_stream(tbl, stream_id, ric, src) else {
            return QpackError.BlockedStreamsExhausted;
        }
        return QpackError.StreamBlocked;
    }

    return decode_qpack_section(tbl, src, out_fields, max_field_section);
}

inline fn emit_qpack_field_to_map(
    out_pseudo:  H3PseudoHeaders&,
    out_headers: wing::HeaderMap&,
    budget_left: u64&,
    name:        const u8[:],
    val:         const u8[:],
    never_index: bool = false,
) -> QpackError {
    guard validate_field_syntax(name, val) else { return QpackError.DecompressionFailed; }
    let cost = qpack_entry_cost(name.len as u64, val.len as u64);
    guard budget_left >= cost else { return QpackError.HeaderListTooLarge; }
    budget_left -= cost;

    let is_pseudo = name.len > 0 && name[0] == ':';
    if is_pseudo {
        guard !out_pseudo.is_trailer && !out_pseudo.has_regular_header else {
            return QpackError.MessageError;
        }
        if name == ":status" {
            guard !out_pseudo.has_status && val.len == 3 else { return QpackError.MessageError; }
            let sc, ok_sc = core::parse_i32_dec(val);
            guard ok_sc && sc >= 100 && sc <= 599 && sc != 101 else { return QpackError.MessageError; }
            out_pseudo.status = sc;
            out_pseudo.has_status = true;
            return QpackError.None;
        }
        if name == ":method" {
            guard !out_pseudo.has_method && val.len > 0 && out_pseudo.method.try_set(val) else {
                return QpackError.MessageError;
            }
            out_pseudo.has_method = true;
            return QpackError.None;
        }
        if name == ":scheme" {
            guard !out_pseudo.has_scheme && val.len > 0 && out_pseudo.scheme.try_set(val) else {
                return QpackError.MessageError;
            }
            out_pseudo.has_scheme = true;
            return QpackError.None;
        }
        if name == ":authority" {
            guard !out_pseudo.has_authority && val.len > 0 && out_pseudo.authority.try_set(val) else {
                return QpackError.MessageError;
            }
            out_pseudo.has_authority = true;
            return QpackError.None;
        }
        if name == ":path" {
            guard !out_pseudo.has_path && val.len > 0 && out_pseudo.path.try_set(val) else {
                return QpackError.MessageError;
            }
            out_pseudo.has_path = true;
            return QpackError.None;
        }
        if name == ":protocol" {
            guard !out_pseudo.has_protocol && val.len > 0 && out_pseudo.protocol.try_set(val) else {
                return QpackError.MessageError;
            }
            out_pseudo.has_protocol = true;
            return QpackError.None;
        }
        return QpackError.MessageError;
    }

    out_pseudo.has_regular_header = true;
    if name == "content-length" {
        let cl, ok_cl = core::parse_i64_dec(val);
        let _, ok_u = core::parse_u64_dec(val);
        guard ok_cl && ok_u else { return QpackError.MessageError; }
        if out_pseudo.content_length >= 0 && out_pseudo.content_length != cl {
            return QpackError.MessageError;
        }
        out_pseudo.content_length = cl;
    }

    guard wing::append_header(out_headers, name, val) else {
        return QpackError.HeaderListTooLarge;
    }
    if never_index {
        let idx = wing::find_header_index(out_headers, name);
        if idx >= 0 {
            out_headers.entries[idx].flags = out_headers.entries[idx].flags | wing::HEADER_FLAG_SENSITIVE;
        }
    }
    return QpackError.None;
}

// Decodes a single QPACK field line directly into `out_headers` (RFC 9204 §4.5.2–4.5.6).
// Advances `offset` past the decoded field line.
//
// Example:
//   src = [0xD1], offset = 0 (static index 17: ":method: GET")
//   returns: QpackError.None, offset = 1, out_pseudo.method = "GET"
fn decode_qpack_field_line_to_map(
    tbl:              const QpackTable&,
    src:              const u8[:],
    offset:           u64&,
    base:             u64,
    ric:              u64,
    budget:           u64&,
    out_pseudo:       H3PseudoHeaders&,
    out_headers:      wing::HeaderMap&,
    max_dyn_abs_used: u64&,
    used_any_dyn:     bool&,
) -> QpackError {
    let b = src[offset];

    if (b & 0x80) != 0 {
        let is_static = (b & 0x40) != 0;
        let idx, next_off, ok = qpack_decode_int(src, offset, 6);
        guard ok else { return QpackError.DecompressionFailed; }

        if is_static {
            let s_ent, s_ok = get_qpack_static_field(idx);
            guard s_ok else { return QpackError.DecompressionFailed; }
            let err = emit_qpack_field_to_map(out_pseudo, out_headers, budget, s_ent.name, s_ent.val, false);
            guard err == QpackError.None else { return err; }
        } else {
            guard base > idx else { return QpackError.DecompressionFailed; }
            let abs_idx = base - idx - 1;
            guard abs_idx < ric else { return QpackError.DecompressionFailed; }
            var n: u8[..256]  = [];
            var v: u8[..4096] = [];
            guard qpack_lookup_absolute(tbl, abs_idx, n, v) else {
                return QpackError.DecompressionFailed;
            }
            let err = emit_qpack_field_to_map(out_pseudo, out_headers, budget, n[..], v[..], false);
            guard err == QpackError.None else { return err; }
            record_dynamic_abs_used(abs_idx, max_dyn_abs_used, used_any_dyn);
        }
        offset = next_off;
        return QpackError.None;
    }

    if (b & 0xF0) == 0x10 {
        let post_idx, next_off, ok = qpack_decode_int(src, offset, 4);
        guard ok else { return QpackError.DecompressionFailed; }
        guard (0xFFFFFFFFFFFFFFFF - base) >= post_idx else { return QpackError.DecompressionFailed; }
        let abs_idx = base + post_idx;
        guard abs_idx < ric else { return QpackError.DecompressionFailed; }
        var n: u8[..256]  = [];
        var v: u8[..4096] = [];
        guard qpack_lookup_absolute(tbl, abs_idx, n, v) else {
            return QpackError.DecompressionFailed;
        }
        let err = emit_qpack_field_to_map(out_pseudo, out_headers, budget, n[..], v[..], false);
        guard err == QpackError.None else { return err; }
        record_dynamic_abs_used(abs_idx, max_dyn_abs_used, used_any_dyn);
        offset = next_off;
        return QpackError.None;
    }

    if (b & 0xC0) == 0x40 {
        let is_never_index = (b & 0x20) != 0;
        let is_static = (b & 0x10) != 0;
        let name_idx, val_start, ok_idx = qpack_decode_int(src, offset, 4);
        guard ok_idx else { return QpackError.DecompressionFailed; }

        var n: u8[..256] = [];
        if is_static {
            let s_ent, s_ok = get_qpack_static_field(name_idx);
            guard s_ok else { return QpackError.DecompressionFailed; }
            n.append(s_ent.name);
        } else {
            guard base > name_idx else { return QpackError.DecompressionFailed; }
            let abs_idx = base - name_idx - 1;
            guard abs_idx < ric else { return QpackError.DecompressionFailed; }
            var dummy_v: u8[..4096] = [];
            guard qpack_lookup_absolute(tbl, abs_idx, n, dummy_v) else {
                return QpackError.DecompressionFailed;
            }
            record_dynamic_abs_used(abs_idx, max_dyn_abs_used, used_any_dyn);
        }

        var v: u8[..4096] = [];
        let next_off, ok_val = decode_qpack_string(src, val_start, 7, v);
        guard ok_val else { return QpackError.DecompressionFailed; }

        let err = emit_qpack_field_to_map(out_pseudo, out_headers, budget, n[..], v[..], is_never_index);
        guard err == QpackError.None else { return err; }
        offset = next_off;
        return QpackError.None;
    }

    if (b & 0xF0) == 0x00 {
        let is_never_index = (b & 0x08) != 0;
        let post_name_idx, val_start, ok_idx = qpack_decode_int(src, offset, 3);
        guard ok_idx else { return QpackError.DecompressionFailed; }
        guard (0xFFFFFFFFFFFFFFFF - base) >= post_name_idx else { return QpackError.DecompressionFailed; }
        let abs_idx = base + post_name_idx;
        guard abs_idx < ric else { return QpackError.DecompressionFailed; }

        var n:       u8[..256]  = [];
        var dummy_v: u8[..4096] = [];
        guard qpack_lookup_absolute(tbl, abs_idx, n, dummy_v) else {
            return QpackError.DecompressionFailed;
        }
        record_dynamic_abs_used(abs_idx, max_dyn_abs_used, used_any_dyn);

        var v: u8[..4096] = [];
        let next_off, ok_val = decode_qpack_string(src, val_start, 7, v);
        guard ok_val else { return QpackError.DecompressionFailed; }

        let err = emit_qpack_field_to_map(out_pseudo, out_headers, budget, n[..], v[..], is_never_index);
        guard err == QpackError.None else { return err; }
        offset = next_off;
        return QpackError.None;
    }

    if (b & 0xE0) == 0x20 {
        let is_never_index = (b & 0x10) != 0;
        var n: u8[..256] = [];
        let val_start, ok_name = decode_qpack_string(src, offset, 3, n);
        guard ok_name else { return QpackError.DecompressionFailed; }

        var v: u8[..4096] = [];
        let next_off, ok_val = decode_qpack_string(src, val_start, 7, v);
        guard ok_val else { return QpackError.DecompressionFailed; }

        let err = emit_qpack_field_to_map(out_pseudo, out_headers, budget, n[..], v[..], is_never_index);
        guard err == QpackError.None else { return err; }
        offset = next_off;
        return QpackError.None;
    }

    return QpackError.DecompressionFailed;
}

// Decodes a complete QPACK Encoded Field Section directly into `out_pseudo` and `out_headers` (RFC 9204 §4.5).
//
// Example:
//   src = [0x00, 0x00, 0xD1], decode_qpack_to_map(tbl, src, out_pseudo, out_headers, 16384)
//   returns: QpackError.None, out_pseudo.method = "GET"
fn decode_qpack_to_map(
    tbl:               const QpackTable&,
    src:               const u8[:],
    out_pseudo:        H3PseudoHeaders&,
    out_headers:       wing::HeaderMap&,
    max_field_section: u64 = 16384,
) -> QpackError {
    guard src.len >= 2 else { return QpackError.DecompressionFailed; }
    var offset: u64 = 0;
    clear_h3_pseudo_headers(out_pseudo, true);
    out_headers.clear();
    var budget = max_field_section;

    let enc_ric, base_off, ok_ric = qpack_decode_int(src, offset, 8);
    guard ok_ric else { return QpackError.DecompressionFailed; }

    let ric, ric_err = decode_ric(enc_ric, tbl.insert_count, tbl.max_capacity_bytes);
    guard ric_err == QpackError.None else { return ric_err; }

    if ric > tbl.insert_count && (tbl.max_blocked == 0 || tbl.blocked_streams.len >= tbl.max_blocked) {
        return QpackError.BlockedStreamsExhausted;
    }

    guard base_off < (src.len as u64) else { return QpackError.DecompressionFailed; }
    let sign_bit: u8 = if (src[base_off] & 0x80) != 0 { 1 } else { 0 };
    let delta_base, fields_off, ok_db = qpack_decode_int(src, base_off, 7);
    guard ok_db else { return QpackError.DecompressionFailed; }

    let base, base_err = decode_base(sign_bit, delta_base, ric);
    guard base_err == QpackError.None else { return base_err; }

    offset = fields_off;
    var max_dyn_abs_used: u64 = 0;
    var used_any_dyn = false;

    while offset < (src.len as u64) {
        let f_err = decode_qpack_field_line_to_map(
            tbl,
            src,
            offset,
            base,
            ric,
            budget,
            out_pseudo,
            out_headers,
            max_dyn_abs_used,
            used_any_dyn,
        );
        guard f_err == QpackError.None else { return f_err; }
    }

    let min_ric = if used_any_dyn { max_dyn_abs_used + 1 } else { 0 };
    guard ric >= min_ric && ric <= tbl.insert_count else {
        return QpackError.DecompressionFailed;
    }

    return QpackError.None;
}

// Decodes an Encoded Field Section directly into `out_pseudo` and `out_headers`,
// or records the stream as blocked if RIC exceeds `insert_count` (RFC 9204 §2.1.2).
//
// Example:
//   src = [0x00, 0x00, 0xD1], stream_id = 4
//   returns: QpackError.None, out_pseudo and out_headers populated
fn decode_or_block_qpack_to_map(
    tbl:               QpackTable&,
    stream_id:         u64,
    src:               const u8[:],
    out_pseudo:        H3PseudoHeaders&,
    out_headers:       wing::HeaderMap&,
    max_field_section: u64 = 16384,
) -> QpackError {
    guard src.len >= 2 else { return QpackError.DecompressionFailed; }
    let enc_ric, _, ok_ric = qpack_decode_int(src, 0, 8);
    guard ok_ric else { return QpackError.DecompressionFailed; }
    let ric, ric_err = decode_ric(enc_ric, tbl.insert_count, tbl.max_capacity_bytes);
    guard ric_err == QpackError.None else { return ric_err; }

    if ric > tbl.insert_count {
        guard qpack_can_block_stream(tbl) else {
            return QpackError.BlockedStreamsExhausted;
        }
        guard qpack_block_stream(tbl, stream_id, ric, src) else {
            return QpackError.BlockedStreamsExhausted;
        }
        return QpackError.StreamBlocked;
    }

    return decode_qpack_to_map(tbl, src, out_pseudo, out_headers, max_field_section);
}

// Encodes a single field line with optional static index lookup.
fn encode_qpack_field<B>(
    out:         B&,
    name:        const u8[:],
    val:         const u8[:],
    use_huffman: bool = true,
) {
    let s_idx, exact_s = find_qpack_static_field(name, val);
    if exact_s {
        // Indexed Field Line, Static: 11xxxxxx (6-bit prefix)
        internal::hpack_encode_int(out, s_idx, 6, 0xC0);
        return;
    }

    let s_idx_name, _ = find_qpack_static_field(name, "");
    if s_idx_name < rfc::QPACK_STATIC_TABLE_SIZE && name == QPACK_STATIC_TABLE[s_idx_name as i64].name {
        // Literal with Static Name: 01NTxxxx (4-bit prefix, T=1)
        internal::hpack_encode_int(out, s_idx_name, 4, 0x50);
        internal::encode_hpack_string_literal(out, val, use_huffman);
        return;
    }

    // Literal Name + Literal Value: 001NHxxx (3-bit prefix name)
    if use_huffman {
        let huff_len = internal::huff_encoded_byte_len(name);
        if huff_len < (name.len as u64) {
            internal::hpack_encode_int(out, huff_len, 3, 0x28);
            internal::huff_encode_bytes(name, out);
        } else {
            internal::hpack_encode_int(out, name.len as u64, 3, 0x20);
            out.append(name);
        }
    } else {
        internal::hpack_encode_int(out, name.len as u64, 3, 0x20);
        out.append(name);
    }
    internal::encode_hpack_string_literal(out, val, use_huffman);
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
        let e = tbl.entries[i];
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

// Emits a Set Dynamic Table Capacity instruction (001xxxxx, 5-bit prefix) onto `out_enc`
// and updates `tbl.capacity_bytes` (RFC 9204 §4.3.1).
fn encode_qpack_set_capacity<B>(tbl: QpackTable&, new_cap: u64, out_enc: B&) -> bool {
    guard qpack_set_capacity(tbl, new_cap) else { return false; }
    internal::hpack_encode_int(out_enc, new_cap, 5, 0x20);
    return true;
}

// Emits an Encoder Stream insertion instruction (Insert with Static Name Reference 11xxxxxx
// or Insert with Literal Name 01Hxxxxx) and inserts the entry into `tbl` (RFC 9204 §4.3.2, §4.3.3).
fn encode_qpack_dynamic_insert<B>(
    tbl:         QpackTable&,
    name:        const u8[:],
    val:         const u8[:],
    out_enc:     B&,
    use_huffman: bool = true,
) -> u64, bool {
    guard tbl.capacity_bytes > 0 else { return 0, false; }
    let s_idx_name, _ = find_qpack_static_field(name, "");
    let has_static_name = s_idx_name < rfc::QPACK_STATIC_TABLE_SIZE
        && name == QPACK_STATIC_TABLE[s_idx_name as i64].name;

    if has_static_name {
        guard qpack_insert_named_static(tbl, s_idx_name, val) else { return 0, false; }
        internal::hpack_encode_int(out_enc, s_idx_name, 6, 0xC0);
        internal::encode_hpack_string_literal(out_enc, val, use_huffman);
        return tbl.insert_count - 1, true;
    }

    guard qpack_insert_literal(tbl, name, val) else { return 0, false; }
    if use_huffman {
        let huff_len = internal::huff_encoded_byte_len(name);
        if huff_len < (name.len as u64) {
            internal::hpack_encode_int(out_enc, huff_len, 5, 0x60);
            internal::huff_encode_bytes(name, out_enc);
        } else {
            internal::hpack_encode_int(out_enc, name.len as u64, 5, 0x40);
            out_enc.append(name);
        }
    } else {
        internal::hpack_encode_int(out_enc, name.len as u64, 5, 0x40);
        out_enc.append(name);
    }
    internal::encode_hpack_string_literal(out_enc, val, use_huffman);
    return tbl.insert_count - 1, true;
}

// Encodes a single field line using Static Table, Dynamic Table lookup/insertion, or Literal fallback (RFC 9204 §4.5).
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
) {
    let s_idx, exact_s = find_qpack_static_field(name, val);
    if exact_s {
        internal::hpack_encode_int(out_section, s_idx, 6, 0xC0);
        return;
    }

    if tbl.capacity_bytes > 0 {
        let dyn_abs, exact_d, _ = find_qpack_dynamic_field(tbl, name, val);
        if exact_d {
            let _ = qpack_track_stream_ref(tbl, stream_id, dyn_abs);
            record_dynamic_abs_used(dyn_abs, max_dyn_abs_used, used_any_dyn);
            if dyn_abs < base {
                let rel_idx = base - dyn_abs - 1;
                internal::hpack_encode_int(out_section, rel_idx, 6, 0x80);
            } else {
                let post_idx = dyn_abs - base;
                internal::hpack_encode_int(out_section, post_idx, 4, 0x10);
            }
            return;
        }

        let new_abs, ins_ok = encode_qpack_dynamic_insert(tbl, name, val, out_enc_stream, use_huffman);
        if ins_ok {
            let _ = qpack_track_stream_ref(tbl, stream_id, new_abs);
            record_dynamic_abs_used(new_abs, max_dyn_abs_used, used_any_dyn);
            if new_abs < base {
                let rel_idx = base - new_abs - 1;
                internal::hpack_encode_int(out_section, rel_idx, 6, 0x80);
            } else {
                let post_idx = new_abs - base;
                internal::hpack_encode_int(out_section, post_idx, 4, 0x10);
            }
            return;
        }
    }

    encode_qpack_field(out_section, name, val, use_huffman);
}
