// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP/3 and QPACK Field Compression Engine (RFC 9204, RFC 9114).
// Implements RFC 9204 static table (99 entries), zero-allocation dynamic table ring,
// modular RIC prefix codec, blocked streams manager, and Header Accordion DoS mitigations.
namespace internal;

import std;

// ---- 1. constants, error codes and limits -----------------------------------

const QPACK_STATIC_TABLE_SIZE:   u64 = 99;
const QPACK_ENTRY_OVERHEAD:      u64 = 32; // RFC 9204 Section 3.2.1 (+32 bytes per entry)
const QPACK_DEFAULT_MAX_TABLE:   u64 = 4096;
const QPACK_MAX_BLOCKED_STREAMS: u32 = 128;

// HTTP/3 Error Codes (RFC 9114 Section 8.1 & RFC 9204 Section 2.2.3)
const H3_ERR_NO_ERROR:                   u64 = 0x0100;
const H3_ERR_GENERAL_PROTOCOL:           u64 = 0x0101;
const H3_ERR_INTERNAL:                   u64 = 0x0102;
const H3_ERR_STREAM_CREATION:            u64 = 0x0103;
const H3_ERR_CLOSED_CRITICAL_STREAM:     u64 = 0x0104;
const H3_ERR_FRAME_UNEXPECTED:           u64 = 0x0105;
const H3_ERR_FRAME_ERROR:                u64 = 0x0106;
const H3_ERR_EXCESSIVE_LOAD:             u64 = 0x0107;
const H3_ERR_ID_ERROR:                   u64 = 0x0108;
const H3_ERR_SETTINGS_ERROR:             u64 = 0x0109;
const H3_ERR_MISSING_SETTINGS:           u64 = 0x010A;
const H3_ERR_REQUEST_REJECTED:           u64 = 0x010B;
const H3_ERR_REQUEST_CANCELLED:          u64 = 0x010C;
const H3_ERR_REQUEST_INCOMPLETE:         u64 = 0x010D;
const H3_ERR_CONNECT_ERROR:              u64 = 0x010F;
const H3_ERR_VERSION_FALLBACK:           u64 = 0x0110;
const H3_ERR_QPACK_DECOMPRESSION_FAILED: u64 = 0x0200;
const H3_ERR_QPACK_ENCODER_STREAM_ERROR: u64 = 0x0201;
const H3_ERR_QPACK_DECODER_STREAM_ERROR: u64 = 0x0202;

// HTTP/3 Frame Types (RFC 9114 Section 7.2)
const H3_FRAME_DATA:                    u64 = 0x00;
const H3_FRAME_HEADERS:                 u64 = 0x01;
const H3_FRAME_CANCEL_PUSH:             u64 = 0x03;
const H3_FRAME_SETTINGS:                u64 = 0x04;
const H3_FRAME_PUSH_PROMISE:            u64 = 0x05;
const H3_FRAME_GOAWAY:                  u64 = 0x07;
const H3_FRAME_MAX_PUSH_ID:             u64 = 0x0D;
const H3_FRAME_PRIORITY_UPDATE_REQUEST: u64 = 0xF0700; // RFC 9218 Section 7.2
const H3_FRAME_PRIORITY_UPDATE_PUSH:    u64 = 0xF0701; // RFC 9218 Section 7.2

// HTTP/3 Unidirectional Stream Types (RFC 9114 Section 6.2)
const H3_STREAM_CONTROL:       u64 = 0x00;
const H3_STREAM_PUSH:          u64 = 0x01;
const H3_STREAM_QPACK_ENCODER: u64 = 0x02;
const H3_STREAM_QPACK_DECODER: u64 = 0x03;

// HTTP/3 Settings Identifiers (RFC 9114 Section 7.2.4.1 & RFC 9204 Section 5)
const H3_SETTING_QPACK_MAX_TABLE_CAPACITY: u64 = 0x01; // default 0
const H3_SETTING_MAX_FIELD_SECTION_SIZE:   u64 = 0x06; // unlimited default
const H3_SETTING_QPACK_BLOCKED_STREAMS:    u64 = 0x07; // default 0
const H3_SETTING_ENABLE_CONNECT_PROTOCOL:  u64 = 0x08; // RFC 9220 Extended CONNECT

enum QpackError {
    None,
    DecompressionFailed,     // H3_ERR_QPACK_DECOMPRESSION_FAILED (0x0200)
    EncoderStreamError,      // H3_ERR_QPACK_ENCODER_STREAM_ERROR (0x0201)
    DecoderStreamError,      // H3_ERR_QPACK_DECODER_STREAM_ERROR (0x0202)
    HeaderListTooLarge,      // Exceeded SETTINGS_MAX_FIELD_SECTION_SIZE
    BlockedStreamsExhausted, // Exceeded SETTINGS_QPACK_BLOCKED_STREAMS
    ClosedCriticalStream,    // H3_ERR_CLOSED_CRITICAL_STREAM (0x0104)
    StreamCreationError,     // H3_ERR_STREAM_CREATION (0x0103)
    FrameEncodingError,      // H3_ERR_FRAME_ERROR
}

struct HeaderField {
    name:        u8[..256]  = [],
    value:       u8[..4096] = [],
    never_index: bool       = false,
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
    stream_id:   u64      = 0,
    ric:         u64      = 0,
    ref_entries: u64[..8] = [],
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
    entries:               DynamicEntry[>..<]        = [], // Must be last!
}

// Calculates RFC 9204 Section 3.2.1 protocol weight (+32 byte overhead).
fn qpack_entry_cost(name_len: u64, val_len: u64) -> u64 {
    return name_len + val_len + QPACK_ENTRY_OVERHEAD;
}

// ---- 2. rfc 9204 appendix a static table -----------------------------------

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
    guard idx < QPACK_STATIC_TABLE_SIZE else {
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
    while idx < QPACK_STATIC_TABLE_SIZE {
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

// ---- 3. prefix integer codec (ric and base) --------------------------------

const QPACK_MAX_INT_VAL: u64 = 0x3FFFFFFFFFFFFFFF; // 62 bits (RFC 9204 Section 4.1.1)

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
        if (QPACK_MAX_INT_VAL - val) < term {
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
    let max_entries = max_cap / QPACK_ENTRY_OVERHEAD;
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
    let max_entries = max_cap / QPACK_ENTRY_OVERHEAD;
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

// ---- 4. dynamic table management & eviction --------------------------------

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

// Evicts entries from the dynamic table until used_bytes <= target_bytes.
// Returns false if an eviction barrier (referenced entry) prevents eviction.
fn qpack_evict_until(tbl: QpackTable&, target_bytes: u64) -> bool {
    while tbl.entries.len > 0 && tbl.used_bytes > target_bytes {
        let oldest = tbl.entries[0];
        if oldest.ref_count > 0 {
            return false;
        }
        let cost = qpack_entry_cost(oldest.name.len as u64, oldest.value.len as u64);
        tbl.used_bytes = if tbl.used_bytes >= cost { tbl.used_bytes - cost } else { 0 };
        tbl.entries.remove_at(0);
    }
    tbl.draining_index = if tbl.entries.len > 0 { tbl.entries[0].abs_index } else { tbl.insert_count };
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

// Inserts an entry into the dynamic table with literal name and value.
fn qpack_insert_literal(tbl: QpackTable&, name: const u8[:], val: const u8[:]) -> bool {
    // RFC 9114 Section 4.2 & RFC 9204 Section 4.1: Field names MUST be lowercase
    for c in name {
        if c >= 'A' && c <= 'Z' {
            return false;
        }
    }

    let cost = qpack_entry_cost(name.len as u64, val.len as u64);
    guard cost <= tbl.capacity_bytes else { return false; }
    guard qpack_evict_until(tbl, tbl.capacity_bytes - cost) else { return false; }

    var ent = DynamicEntry {
        abs_index: tbl.insert_count,
        ref_count: 0,
        ..
    };
    ent.name.append(name);
    ent.value.append(val);
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

    var n_buf: u8[..256] = [];
    var found = false;
    for &e in tbl.entries {
        if e.abs_index == target_abs {
            n_buf.append(e.name[..]);
            found = true;
            break;
        }
    }
    guard found else { return false; }
    return qpack_insert_literal(tbl, n_buf[..], val);
}

// Duplicates an existing dynamic table entry by relative index.
fn qpack_duplicate(tbl: QpackTable&, rel_idx: u64) -> bool {
    guard tbl.insert_count > rel_idx else { return false; }
    let target_abs = tbl.insert_count - rel_idx - 1;

    var n_buf: u8[..256]  = [];
    var v_buf: u8[..4096] = [];
    var found = false;
    for &e in tbl.entries {
        if e.abs_index == target_abs {
            n_buf.append(e.name[..]);
            v_buf.append(e.value[..]);
            found = true;
            break;
        }
    }
    guard found else { return false; }
    return qpack_insert_literal(tbl, n_buf[..], v_buf[..]);
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
            out_name.append(e.name[..]);
            out_val.append(e.value[..]);
            return true;
        }
    }
    out_name.clear();
    out_val.clear();
    return false;
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
            if tbl.unacked_sections[i].ref_entries.len < tbl.unacked_sections[i].ref_entries.cap {
                tbl.unacked_sections[i].ref_entries.push(abs_idx);
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

// ---- 5. encoder / decoder instruction dispatch ------------------------------

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

// ---- 6. incremental field emission & header accordion protection ------------

inline fn is_qpack_token_char(c: u8) -> bool {
    if c >= 'a' && c <= 'z' { return true; }
    if c >= '0' && c <= '9' { return true; }
    return c == '!' || c == '#' || c == '$' || c == '%' || c == '&' ||
           c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' ||
           c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}

// Emits a parsed field line, enforcing SETTINGS_MAX_FIELD_SECTION_SIZE + 32-byte overhead.
fn emit_field_checked(
    out_fields:  HeaderField[>..]&,
    budget_left: u64&,
    name:        const u8[:],
    val:         const u8[:],
    never_index: bool = false,
) -> QpackError {
    // RFC 9114 Section 4.2 & RFC 9204 Section 4.1: Field names MUST be lowercase valid token chars or pseudo-header
    guard name.len > 0 && (name.len > 1 || name[0] != ':') else { return QpackError.DecompressionFailed; }
    for i in name.len {
        let c = name[i];
        if i == 0 && c == ':' {
            continue; // pseudo header prefix
        }
        if !is_qpack_token_char(c) {
            return QpackError.DecompressionFailed;
        }
    }

    // RFC 9114 Section 4.2 & Go #80683: Field values MUST NOT contain NUL, CR, or LF
    for b in val {
        if b == 0 || b == '\r' || b == '\n' {
            return QpackError.DecompressionFailed;
        }
    }

    let cost = qpack_entry_cost(name.len as u64, val.len as u64);
    guard budget_left >= cost else {
        return QpackError.HeaderListTooLarge;
    }
    budget_left -= cost;

    var field = HeaderField { never_index: never_index, .. };
    field.name.append(name);
    field.value.append(val);
    out_fields.push(field);
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
fn decode_qpack_field_line(
    tbl:              const QpackTable&,
    src:              const u8[:],
    offset:           u64&,
    base:             u64,
    ric:              u64,
    budget:           u64&,
    out_fields:       HeaderField[>..]&,
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
fn decode_qpack_section(
    tbl:               const QpackTable&,
    src:               const u8[:],
    out_fields:        HeaderField[>..]&,
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

    // Invariant: RFC 9204 §2.1.2 & §4.5.1: RIC must equal min required insert count and <= insert_count.
    let min_ric = if used_any_dyn { max_dyn_abs_used + 1 } else { 0 };
    guard ric == min_ric && ric <= tbl.insert_count else {
        return QpackError.DecompressionFailed;
    }

    return QpackError.None;
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

    if s_idx < QPACK_STATIC_TABLE_SIZE && name == QPACK_STATIC_TABLE[s_idx as i64].name {
        // Literal with Static Name: 0101xxxx (4-bit prefix)
        internal::hpack_encode_int(out, s_idx, 4, 0x50);
        internal::encode_hpack_string_literal(out, val, use_huffman);
        return;
    }

    // Literal Name + Literal Value: 001NHxxx (3-bit prefix name)
    if use_huffman {
        let huff_len = internal::huff_encoded_byte_len(name);
        if huff_len < (name.len as u64) {
            internal::hpack_encode_int(out, huff_len, 3, 0x28); // 0x20 | 0x08 (H bit)
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
