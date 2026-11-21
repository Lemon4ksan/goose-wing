// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal constants, tables, bounded arena descriptors, and shared helpers for `http3`.
namespace h3_internal;

import std;
import core;
import rfc.h3_quic;
import http.headers;
import http.priority;
import fingerprint.profile;
import quic.packet;
import http2.hpack;

// ---- Framing Internal Constants & Helpers ----------------------------------

const H3_SETTINGS_H3_DATAGRAM_DRAFT00:       u64 = 0x276;      // draft-ietf-masque-h3-datagram-00
const H3_SETTINGS_ENABLE_WEBTRANSPORT:       u64 = 0x2b603742; // draft-ietf-webtrans-http3
const H3_SETTINGS_WEBTRANSPORT_MAX_SESSIONS: u64 = 0xc671706a; // draft-ietf-webtrans-http3 §3.1
const H3_MAX_SETTINGS_PAYLOAD_SIZE:          i64 = 256;        // RFC 9114 §7.2.4

inline fn append_h3_frame_parts(out: u8[>..]&, hdr: const u8[:], payload: const u8[:]) -> bool {
    out.append(hdr);
    out.append(payload);
    return true;
}

inline fn append_h3_frame_parts<B>(out: B&, hdr: const u8[:], payload: const u8[:]) -> bool {
    let need = core::add_sat_i64(hdr.len, payload.len);
    guard core::add_sat_i64(out.len, need) <= out.cap else { return false; }
    out.append(hdr);
    out.append(payload);
    return true;
}

// RFC 9114 Section 7.2.4: SETTINGS - Each setting identifier MUST NOT appear more than once.
fn record_setting_identifier(seen: u64[..128]&, id: u64) -> bool {
    for s in seen {
        if s == id {
            return false;
        }
    }
    return seen.try_push(id);
}

inline fn apply_parsed_h3_setting(id: u64, val: u64, settings: fingerprint::H3Settings&) -> bool {
    if id == rfc::H3_SETTING_QPACK_MAX_TABLE_CAPACITY {
        settings.qpack_max_table_capacity = val;
        return true;
    }
    if id == rfc::H3_SETTING_MAX_FIELD_SECTION_SIZE {
        settings.max_field_section_size = val;
        return true;
    }
    if id == rfc::H3_SETTING_QPACK_BLOCKED_STREAMS {
        settings.qpack_blocked_streams = val;
        return true;
    }
    if id == rfc::H3_SETTING_ENABLE_CONNECT_PROTOCOL {
        guard val <= 1 else { return false; }
        settings.enable_connect_protocol = val;
        return true;
    }
    if id == rfc::H3_SETTING_H3_DATAGRAM || id == H3_SETTINGS_H3_DATAGRAM_DRAFT00 {
        guard val <= 1 else { return false; }
        settings.h3_datagram = val;
        return true;
    }
    if id == H3_SETTINGS_ENABLE_WEBTRANSPORT {
        guard val <= 1 else { return false; }
        settings.enable_webtransport = val;
        return true;
    }
    if id == H3_SETTINGS_WEBTRANSPORT_MAX_SESSIONS {
        settings.webtransport_max_sessions = val;
        return true;
    }
    return true;
}

inline fn apply_h3_priority_entry(
    entry: const http::SfDictEntry&,
    prio:  http::PriorityParam&,
) -> bool {
    if entry.key == "u" {
        if !entry.is_inner_list &&
           entry.item.kind == http::SfType.Integer &&
           http::is_valid_urgency(entry.item.int_val) {
            prio.urgency = entry.item.int_val as u8;
        }
        return true;
    }
    if entry.key == "i" {
        if !entry.is_inner_list && entry.item.kind == http::SfType.Boolean {
            prio.incremental = entry.item.bool_val;
        }
        return true;
    }
    return true;
}

// RFC 9218 Section 4: Priority Parameters - Receivers MUST ignore unrecognized parameters and out-of-range urgency values.
//
// Example:
//   field_value = "u=1, i", default_incremental = false
//   returns: { urgency: 1, incremental: true }, true
fn parse_h3_priority_field_value(
    field_value:         const u8[:],
    default_incremental: bool = false,
) -> http::PriorityParam, bool {
    var prio = http::PriorityParam { urgency: 3, incremental: default_incremental };
    let trimmed = field_value.trim_ascii_space();
    if trimmed.len == 0 {
        return prio, true;
    }
    var entries: http::SfDictEntry[..16] = [];
    guard http::parse_sf_dict(trimmed, entries) else { return prio, false; }
    for &entry in entries {
        guard apply_h3_priority_entry(entry, prio) else { return prio, false; }
    }
    return prio, true;
}

inline fn is_valid_ascii_origin(entry: const u8[:]) -> bool {
    guard entry.len > 0 else { return false; }
    for b in entry {
        guard core::is_ascii_vchar(b) else { return false; }
    }
    return true;
}

// ---- QPACK Internal Constants, Tables & Arena Descriptors ----------------

const QPACK_DEFAULT_MAX_TABLE:   u64 = 4096;
const QPACK_MAX_BLOCKED_STREAMS: u32 = 128;
const QPACK_MIN_STATIC_NAME_LEN: i64 = 3;
const QPACK_MAX_STATIC_NAME_LEN: i64 = 32;

struct DynamicEntryDesc {
    abs_index: u64 = 0,
    ref_count: u32 = 0,
    name_off:  u32 = 0,
    name_len:  u16 = 0,
    val_off:   u32 = 0,
    val_len:   u16 = 0,
}

struct BlockedStreamEntry {
    stream_id:        u64        = 0,
    req_insert_count: u64        = 0,
    is_push_promise:  bool       = false,
    push_id:          u64        = 0,
    encoded_data:     u8[..4096] = [],
}

struct UnackedSection {
    stream_id:   u64       = 0,
    ric:         u64       = 0,
    ref_entries: u64[..32] = [],
}

struct QpackStaticRow {
    name: const u8[:] = "",
    val:  const u8[:] = "",
}

const QPACK_STATIC_TABLE: QpackStaticRow[99] = [
    QpackStaticRow { name: ":authority", val: "" }, // 0
    QpackStaticRow { name: ":path", val: "/" }, // 1
    QpackStaticRow { name: "age", val: "0" }, // 2
    QpackStaticRow { name: "content-disposition", val: "" }, // 3
    QpackStaticRow { name: "content-length", val: "0" }, // 4
    QpackStaticRow { name: "cookie", val: "" }, // 5
    QpackStaticRow { name: "date", val: "" }, // 6
    QpackStaticRow { name: "etag", val: "" }, // 7
    QpackStaticRow { name: "if-modified-since", val: "" }, // 8
    QpackStaticRow { name: "if-none-match", val: "" }, // 9
    QpackStaticRow { name: "last-modified", val: "" }, // 10
    QpackStaticRow { name: "link", val: "" }, // 11
    QpackStaticRow { name: "location", val: "" }, // 12
    QpackStaticRow { name: "referer", val: "" }, // 13
    QpackStaticRow { name: "set-cookie", val: "" }, // 14
    QpackStaticRow { name: ":method", val: "CONNECT" }, // 15
    QpackStaticRow { name: ":method", val: "DELETE" }, // 16
    QpackStaticRow { name: ":method", val: "GET" }, // 17
    QpackStaticRow { name: ":method", val: "HEAD" }, // 18
    QpackStaticRow { name: ":method", val: "OPTIONS" }, // 19
    QpackStaticRow { name: ":method", val: "POST" }, // 20
    QpackStaticRow { name: ":method", val: "PUT" }, // 21
    QpackStaticRow { name: ":scheme", val: "http" }, // 22
    QpackStaticRow { name: ":scheme", val: "https" }, // 23
    QpackStaticRow { name: ":status", val: "103" }, // 24
    QpackStaticRow { name: ":status", val: "200" }, // 25
    QpackStaticRow { name: ":status", val: "304" }, // 26
    QpackStaticRow { name: ":status", val: "404" }, // 27
    QpackStaticRow { name: ":status", val: "503" }, // 28
    QpackStaticRow { name: "accept", val: "*/*" }, // 29
    QpackStaticRow { name: "accept", val: "application/dns-message" }, // 30
    QpackStaticRow { name: "accept-encoding", val: "gzip, deflate, br" }, // 31
    QpackStaticRow { name: "accept-ranges", val: "bytes" }, // 32
    QpackStaticRow { name: "access-control-allow-headers", val: "cache-control" }, // 33
    QpackStaticRow { name: "access-control-allow-headers", val: "content-type" }, // 34
    QpackStaticRow { name: "access-control-allow-origin", val: "*" }, // 35
    QpackStaticRow { name: "cache-control", val: "max-age=0" }, // 36
    QpackStaticRow { name: "cache-control", val: "max-age=2592000" }, // 37
    QpackStaticRow { name: "cache-control", val: "max-age=604800" }, // 38
    QpackStaticRow { name: "cache-control", val: "no-cache" }, // 39
    QpackStaticRow { name: "cache-control", val: "no-store" }, // 40
    QpackStaticRow { name: "cache-control", val: "public, max-age=31536000" }, // 41
    QpackStaticRow { name: "content-encoding", val: "br" }, // 42
    QpackStaticRow { name: "content-encoding", val: "gzip" }, // 43
    QpackStaticRow { name: "content-type", val: "application/dns-message" }, // 44
    QpackStaticRow { name: "content-type", val: "application/javascript" }, // 45
    QpackStaticRow { name: "content-type", val: "application/json" }, // 46
    QpackStaticRow { name: "content-type", val: "application/x-www-form-urlencoded" }, // 47
    QpackStaticRow { name: "content-type", val: "image/gif" }, // 48
    QpackStaticRow { name: "content-type", val: "image/jpeg" }, // 49
    QpackStaticRow { name: "content-type", val: "image/png" }, // 50
    QpackStaticRow { name: "content-type", val: "text/css" }, // 51
    QpackStaticRow { name: "content-type", val: "text/html; charset=utf-8" }, // 52
    QpackStaticRow { name: "content-type", val: "text/plain" }, // 53
    QpackStaticRow { name: "content-type", val: "text/plain;charset=utf-8" }, // 54
    QpackStaticRow { name: "range", val: "bytes=0-" }, // 55
    QpackStaticRow { name: "strict-transport-security", val: "max-age=31536000" }, // 56
    // 57
    QpackStaticRow {
        name: "strict-transport-security",
        val:  "max-age=31536000; includesubdomains",
    },
    // 58
    QpackStaticRow {
        name: "strict-transport-security",
        val:  "max-age=31536000; includesubdomains; preload",
    },
    QpackStaticRow { name: "vary", val: "accept-encoding" }, // 59
    QpackStaticRow { name: "vary", val: "origin" }, // 60
    QpackStaticRow { name: "x-content-type-options", val: "nosniff" }, // 61
    QpackStaticRow { name: "x-xss-protection", val: "1; mode=block" }, // 62
    QpackStaticRow { name: ":status", val: "100" }, // 63
    QpackStaticRow { name: ":status", val: "204" }, // 64
    QpackStaticRow { name: ":status", val: "206" }, // 65
    QpackStaticRow { name: ":status", val: "302" }, // 66
    QpackStaticRow { name: ":status", val: "400" }, // 67
    QpackStaticRow { name: ":status", val: "403" }, // 68
    QpackStaticRow { name: ":status", val: "421" }, // 69
    QpackStaticRow { name: ":status", val: "425" }, // 70
    QpackStaticRow { name: ":status", val: "500" }, // 71
    QpackStaticRow { name: "accept-language", val: "" }, // 72
    QpackStaticRow { name: "access-control-allow-credentials", val: "FALSE" }, // 73
    QpackStaticRow { name: "access-control-allow-credentials", val: "TRUE" }, // 74
    QpackStaticRow { name: "access-control-allow-headers", val: "*" }, // 75
    QpackStaticRow { name: "access-control-allow-methods", val: "get" }, // 76
    QpackStaticRow { name: "access-control-allow-methods", val: "get, post, options" }, // 77
    QpackStaticRow { name: "access-control-allow-methods", val: "options" }, // 78
    QpackStaticRow { name: "access-control-expose-headers", val: "content-length" }, // 79
    QpackStaticRow { name: "access-control-request-headers", val: "content-type" }, // 80
    QpackStaticRow { name: "access-control-request-method", val: "get" }, // 81
    QpackStaticRow { name: "access-control-request-method", val: "post" }, // 82
    QpackStaticRow { name: "alt-svc", val: "clear" }, // 83
    QpackStaticRow { name: "authorization", val: "" }, // 84
    // 85
    QpackStaticRow {
        name: "content-security-policy",
        val:  "script-src 'none'; object-src 'none'; base-uri 'none'",
    },
    QpackStaticRow { name: "early-data", val: "1" }, // 86
    QpackStaticRow { name: "expect-ct", val: "" }, // 87
    QpackStaticRow { name: "forwarded", val: "" }, // 88
    QpackStaticRow { name: "if-range", val: "" }, // 89
    QpackStaticRow { name: "origin", val: "" }, // 90
    QpackStaticRow { name: "purpose", val: "prefetch" }, // 91
    QpackStaticRow { name: "server", val: "" }, // 92
    QpackStaticRow { name: "timing-allow-origin", val: "*" }, // 93
    QpackStaticRow { name: "upgrade-insecure-requests", val: "1" }, // 94
    QpackStaticRow { name: "user-agent", val: "" }, // 95
    QpackStaticRow { name: "x-forwarded-for", val: "" }, // 96
    QpackStaticRow { name: "x-frame-options", val: "deny" }, // 97
    QpackStaticRow { name: "x-frame-options", val: "sameorigin" }, // 98
];

// Candidate index slices in `QPACK_LENGTH_CANDIDATES` grouped by header name length (0..32).
// Packed as `(offset << 8) | count`.
const QPACK_NAME_BUCKET_OFFSETS: u16[33] = [
    0x0000, 0x0000, 0x0000, 0x0001, 0x0105, 0x0602, 0x0805, 0x0D1A,
    0x2702, 0x2902, 0x2B04, 0x2F00, 0x2F0B, 0x3A0A, 0x4401, 0x4505,
    0x4A03, 0x4D01, 0x4E00, 0x4E02, 0x5000, 0x5000, 0x5001, 0x5101,
    0x5200, 0x5204, 0x5600, 0x5601, 0x5706, 0x5D03, 0x6001, 0x6100,
    0x6102,
];

// Static table indices (0..98) ordered by `name.len` and ascending static table index.
const QPACK_LENGTH_CANDIDATES: u8[99] = [
    2,
    6, 7, 11, 59, 60,
    1, 55,
    5, 29, 30, 90, 92,
    13, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 63, 64, 65, 66, 67, 68, 69, 70, 71, 83, 91,
    12, 89,
    87, 88,
    0, 14, 86, 95,
    44, 45, 46, 47, 48, 49, 50, 51, 52, 53, 54,
    9, 10, 32, 36, 37, 38, 39, 40, 41, 84,
    4,
    31, 72, 96, 97, 98,
    42, 43, 62,
    8,
    3, 93,
    61,
    85,
    56, 57, 58, 94,
    35,
    33, 34, 75, 76, 77, 78,
    79, 81, 82,
    80,
    73, 74,
];

// Resolves the candidate slice bounds `[start, end)` in `QPACK_LENGTH_CANDIDATES` for `name_len`.
inline fn qpack_candidate_range(name_len: i64) -> i64, i64 {
    guard name_len >= QPACK_MIN_STATIC_NAME_LEN && name_len <= QPACK_MAX_STATIC_NAME_LEN else {
        return 0, 0;
    }
    let bucket: u16 = QPACK_NAME_BUCKET_OFFSETS[name_len];
    let start:  i64 = bucket >> 8;
    let end:    i64 = core::add_sat_i64(start, bucket & 0xFF);
    return start, min(end, 99);
}

// Calculates RFC 9204 Section 3.2.1 protocol weight (+32 byte overhead).
fn qpack_entry_cost(name_len: u64, val_len: u64) -> u64 {
    return name_len + val_len + rfc::QPACK_ENTRY_OVERHEAD;
}

inline fn is_qpack_token_char(c: u8) -> bool {
    if c >= 'a' && c <= 'z' { return true; }
    if core::is_ascii_digit(c) { return true; }
    return c == '!' || c == '#' || c == '$' || c == '%' || c == '&' ||
           c == '\'' || c == '*' || c == '+' || c == '-' || c == '.' ||
           c == '^' || c == '_' || c == '`' || c == '|' || c == '~';
}

inline fn has_blocked_stream_before(
    entries:   const BlockedStreamEntry[:],
    limit:     i64,
    stream_id: u64,
) -> bool {
    for j in limit {
        if entries[j].stream_id == stream_id {
            return true;
        }
    }
    return false;
}

inline fn record_dynamic_abs_used(abs_idx: u64, max_dyn_abs_used: u64&, used_any_dyn: bool&) {
    if !used_any_dyn || abs_idx > max_dyn_abs_used {
        max_dyn_abs_used = abs_idx;
        used_any_dyn = true;
    }
}

inline fn encode_qpack_dyn_index_line<B>(out_section: B&, abs_idx: u64, base: u64) -> bool {
    if abs_idx < base {
        let rel_idx = base - abs_idx - 1;
        return http2::hpack_encode_int(out_section, rel_idx, 6, 0x80);
    }
    let post_idx = abs_idx - base;
    return http2::hpack_encode_int(out_section, post_idx, 4, 0x10);
}

// ---- Shared HTTP/3 Field & Connection Internal Types -----------------------

const MAX_H3_EMPTY_FRAME_STREAK: u32 = 32;

struct PromisedPushRecord {
    push_id:    u64 = 0,
    field_hash: u64 = 0,
}

struct H3HeaderCounts {
    pseudo_status:    i32  = 0,
    pseudo_method:    i32  = 0,
    pseudo_scheme:    i32  = 0,
    pseudo_authority: i32  = 0,
    pseudo_path:      i32  = 0,
    pseudo_protocol:  i32  = 0,
    host:             i32  = 0,
    is_connect:       bool = false,
}

inline fn is_valid_h3_path_bytes(val: const u8[:]) -> bool {
    guard val.len > 0 && (val[0] == '/' || (val[0] == '*' && val.len == 1)) else {
        return false;
    }
    for b in val {
        if b <= 0x20 || b >= 0x7F || b == '#' || b == '<' || b == '>' || b == '"'
            || b == '\\' || b == '^' || b == '{' || b == '|' || b == '}' {
            return false;
        }
    }
    return true;
}

fn is_valid_authority_or_host(val: const u8[:]) -> bool {
    guard val.len > 0 && val.len <= 256 else { return false; }
    for b in val {
        if b <= 0x20 || b >= 0x7F || b == '/' || b == '?' || b == '#' || b == '@' || b == ','
            || b == '\\' || b == '"' || b == '<' || b == '>' || b == '^' || b == '`'
            || b == '{' || b == '|' || b == '}' {
            return false;
        }
    }
    return true;
}

fn has_ctl_chars(val: const u8[:]) -> bool {
    for b in val {
        if (b < 0x20 && b != 0x09) || b == 0x7F {
            return true;
        }
    }
    return false;
}

fn is_forbidden_connection_header(name: const u8[:], value: const u8[:]) -> bool {
    if name.eq_ascii_fold("connection") ||
       name.eq_ascii_fold("keep-alive") ||
       name.eq_ascii_fold("proxy-connection") ||
       name.eq_ascii_fold("transfer-encoding") ||
       name.eq_ascii_fold("upgrade") {
        return true;
    }
    if name.eq_ascii_fold("te") && !value.eq_ascii_fold("trailers") {
        return true;
    }
    return false;
}

fn is_valid_http_method_token(val: const u8[:]) -> bool {
    guard val.len > 0 && val.len <= 16 else { return false; }
    for b in val {
        if !core::is_tchar(b) {
            return false;
        }
    }
    return true;
}

fn is_valid_uri_scheme(val: const u8[:]) -> bool {
    guard val.len > 0 && val.len <= 16 else { return false; }
    guard core::is_ascii_alpha(val[0]) else { return false; }
    for b in val {
        if !core::is_ascii_alphanumeric(b) && b != '+' && b != '-' && b != '.' {
            return false;
        }
    }
    return true;
}
