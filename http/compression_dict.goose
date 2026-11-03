// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9842: Compression Dictionary Transport (September 2025).
// Implements shared dictionary transport for HTTP:
// - `Use-As-Dictionary` response header parser and cache manager
// - `Available-Dictionary` request header generator (RFC 9651 Structured Field Byte Sequence)
// - `Dictionary-ID` request header generator (RFC 9842 Section 2.3)
// - `dcz` (Dictionary-Compressed Zstandard) frame codec and validator (RFC 9842 Section 5)
// - `dcb` (Dictionary-Compressed Brotli) frame header codec (RFC 9842 Section 4)
namespace wing;

import std;
import core from "..";
import http.headers;

// ---- Normative Constants & Wire Magics (RFC 9842) ------------------------

// 4-byte magic headers per RFC 9842 Section 4 (DCB) and Section 5 (DCZ):
// DCZ: 0xFF, 'D', 'C', 'Z' (0xFF, 0x44, 0x43, 0x5A)
// DCB: 0xFF, 'D', 'C', 'B' (0xFF, 0x44, 0x43, 0x42)

struct DictionaryParams {
    match_pattern: u8[..128] = [],
    id:            u8[..64]  = [],
    ttl_sec:       u32       = 86400,
    dict_type:     u8[..16]  = "raw",
    valid:         bool      = false,
}

struct DictionaryEntry {
    origin:        u8[..128] = [],
    match_pattern: u8[..128] = [],
    id:            u8[..64]  = [],
    sha256_hash: u8[32] = [
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    ],
    sha256_base64:   u8[..64]   = [], // RFC 8941 Structured Field Byte Sequence: `:<base64>:`
    content:         u8[..2048] = [],
    inserted_at_sec: i64        = 0,
    ttl_sec:         u32        = 86400,
    valid:           bool       = false,
}

struct DictionaryCache {
    entries: DictionaryEntry[..8] = [],
}

// ---- URL Pattern Matching (draft Section 2.1) ---------------------------

// Matches path against pattern (e.g. `/assets/*` or `/api/*`) per RFC 9842 Section 2.1
fn url_path_matches_pattern(path: const u8[:], pattern: const u8[:]) -> bool {
    guard pattern.len > 0 else { return true; }
    guard pattern[0] == '/' else { return false; }

    if pattern[pattern.len - 1] == '*' {
        let prefix = pattern[..pattern.len - 1];
        return starts_with(path, prefix);
    }
    return path == pattern;
}

// ---- Header Parsers & Serializers ---------------------------------------

fn find_dict_item_end(s: const u8[:]) -> i64 {
    var in_quotes = false;
    for i in s.len {
        let b = s[i];
        if b == '"' {
            in_quotes = !in_quotes;
        } else if !in_quotes && (b == ',' || b == ';') {
            return i;
        }
    }
    return s.len;
}

fn apply_dictionary_param(p: DictionaryParams&, item: const u8[:]) {
    let k_raw, v_raw, has_eq = item.split_once_byte('=');
    guard has_eq else { return; }
    let k = k_raw.trim_lws();
    let v = v_raw.trim_lws().trim_byte('"');

    if core::eq_ascii_fold(k, "match") {
        p.match_pattern.clear();
        p.match_pattern.append(v);
        p.valid = (v.len > 0 && v[0] == '/');
    } else if core::eq_ascii_fold(k, "id") {
        p.id.clear();
        p.id.append(v);
    } else if core::eq_ascii_fold(k, "ttl") {
        let ttl_val, ttl_ok = v.parse_u32_dec();
        if ttl_ok { p.ttl_sec = ttl_val; }
    } else if core::eq_ascii_fold(k, "type") {
        p.dict_type.clear();
        p.dict_type.append(v);
    }
}

// Parses `Use-As-Dictionary` header value (e.g. `match="/assets/*", id="v1", ttl=86400, type=raw`).
//
// Example:
//   header_val = "match=\"/assets/*\", id=\"v1\""
//   returns: p with match_pattern="/assets/*", id="v1", ok = true
fn parse_use_as_dictionary_header(header_val: const u8[:]) -> DictionaryParams, bool {
    var p = DictionaryParams { .. };
    var rem = header_val.trim_lws();
    guard rem.len > 0 else { return p, false; }

    while rem.len > 0 {
        rem = rem.trim_start_bytes(" \t,;");
        guard rem.len > 0 else { break; }

        let item_len = find_dict_item_end(rem);
        let item = rem[..item_len].trim_lws();
        rem = rem[item_len..];

        apply_dictionary_param(p, item);
    }

    return p, p.valid;
}

// Formats `Use-As-Dictionary` header string
fn format_use_as_dictionary_header<B>(
    out:           B&,
    match_pattern: const u8[:],
    id_str:        const u8[:] = "",
    ttl_sec:       u32         = 86400,
) {
    out.append("match=\"");
    out.append(match_pattern);
    out.append("\"");
    if id_str.len > 0 {
        out.append(", id=\"");
        out.append(id_str);
        out.append("\"");
    }
    if ttl_sec != 86400 {
        out.append(", ttl=");
        format(out, ttl_sec);
    }
}

// Formats `Available-Dictionary` Structured Fields Byte Sequence: `:<base64>:`
fn format_available_dictionary_header<B>(out: B&, sha256_hash: const u8[32]&) {
    out.push(':');
    core::base64_encode(sha256_hash[..], out);
    out.push(':');
}

// Formats `Dictionary-ID` header string (RFC 9842 Section 2.3)
fn format_dictionary_id_header<B>(out: B&, id_str: const u8[:]) {
    out.push('"');
    out.append(id_str);
    out.push('"');
}

// ---- DCZ / DCB Wire Format Codec (draft Section 7) -----------------------

// Encodes a DCZ (Dictionary-Compressed Zstandard) frame:
// [0xFF, 'D', 'C', 'Z'] || [32-byte Dictionary SHA-256] || [Compressed Zstandard Payload]
fn encode_dcz_frame<B>(out: B&, dict_hash: const u8[32]&, compressed_payload: const u8[:]) -> bool {
    out.push(rfc::DCZ_MAGIC_BYTE0);
    out.push(rfc::DCZ_MAGIC_BYTE1);
    out.push(rfc::DCZ_MAGIC_BYTE2);
    out.push(rfc::DCZ_MAGIC_BYTE3);
    for b in dict_hash {
        out.push(b);
    }
    out.append(compressed_payload);
    return true;
}

// Encodes a DCB (Dictionary-Compressed Brotli) frame:
// [0xFF, 'D', 'C', 'B'] || [32-byte Dictionary SHA-256] || [Compressed Brotli Payload]
fn encode_dcb_frame<B>(out: B&, dict_hash: const u8[32]&, compressed_payload: const u8[:]) -> bool {
    out.push(rfc::DCB_MAGIC_BYTE0);
    out.push(rfc::DCB_MAGIC_BYTE1);
    out.push(rfc::DCB_MAGIC_BYTE2);
    out.push(rfc::DCB_MAGIC_BYTE3);
    for b in dict_hash {
        out.push(b);
    }
    out.append(compressed_payload);
    return true;
}

// Decodes a DCZ header from wire bytes:
// Verifies 4-byte magic, extracts 32-byte dict hash and returns the compressed payload slice.
//
// Example:
//   wire = [0xFF, 'D', 'C', 'Z', ...32 hash bytes..., ...payload...]
//   returns: payload slice, out_hash populated, ok = true
fn decode_dcz_header(wire: const u8[:], out_hash: u8[32]&) -> const u8[:], bool {
    guard wire.len >= 36 else { return wire[..0], false; }
    guard wire[0] == rfc::DCZ_MAGIC_BYTE0 && wire[1] == rfc::DCZ_MAGIC_BYTE1 &&
          wire[2] == rfc::DCZ_MAGIC_BYTE2 && wire[3] == rfc::DCZ_MAGIC_BYTE3 else {
        return wire[..0], false;
    }

    for idx in 32 {
        out_hash[idx] = wire[4 + idx];
    }
    return wire[36..], true;
}

// Decodes a DCB header from wire bytes.
//
// Example:
//   wire = [0xFF, 'D', 'C', 'B', ...32 hash bytes..., ...payload...]
//   returns: payload slice, out_hash populated, ok = true
fn decode_dcb_header(wire: const u8[:], out_hash: u8[32]&) -> const u8[:], bool {
    guard wire.len >= 36 else { return wire[..0], false; }
    guard wire[0] == rfc::DCB_MAGIC_BYTE0 && wire[1] == rfc::DCB_MAGIC_BYTE1 &&
          wire[2] == rfc::DCB_MAGIC_BYTE2 && wire[3] == rfc::DCB_MAGIC_BYTE3 else {
        return wire[..0], false;
    }

    for idx in 32 {
        out_hash[idx] = wire[4 + idx];
    }
    return wire[36..], true;
}

// ---- Dictionary Cache Operations -----------------------------------------

fn find_matching_dict_entry_index(
    cache:         const DictionaryCache&,
    origin:        const u8[:],
    id_str:        const u8[:],
    match_pattern: const u8[:],
) -> i64 {
    for i in cache.entries.len {
        let entry = &cache.entries[i];
        if entry.valid && entry.origin[..] == origin &&
           (entry.id[..] == id_str || entry.match_pattern[..] == match_pattern) {
            return i;
        }
    }
    return -1;
}

fn find_oldest_dict_entry_index(cache: const DictionaryCache&) -> i64 {
    var oldest_idx: i64 = 0;
    guard cache.entries.len > 0 else { return 0; }
    var oldest_time = cache.entries[0].inserted_at_sec;
    for i in cache.entries.len {
        let entry = &cache.entries[i];
        if !entry.valid {
            return i;
        }
        if entry.inserted_at_sec < oldest_time {
            oldest_time = entry.inserted_at_sec;
            oldest_idx = i;
        }
    }
    return oldest_idx;
}

fn populate_dict_entry(
    entry:         DictionaryEntry&,
    origin:        const u8[:],
    match_pattern: const u8[:],
    id_str:        const u8[:],
    body:          const u8[:],
    hash:          const u8[32]&,
    b64_hash:      const u8[:],
    ttl_sec:       u32,
    now_sec:       i64,
) -> bool {
    guard origin.len <= 128 && match_pattern.len <= 256 && id_str.len <= 128 && body.len <= 2048 else { return false; }
    entry.valid = true;
    entry.origin.clear();
    entry.origin.append(origin);
    entry.match_pattern.clear();
    entry.match_pattern.append(match_pattern);
    entry.id.clear();
    entry.id.append(id_str);
    entry.sha256_hash = hash;
    entry.sha256_base64.clear();
    entry.sha256_base64.append(b64_hash);
    entry.content.clear();
    entry.content.append(body);
    entry.inserted_at_sec = now_sec;
    entry.ttl_sec = ttl_sec;
    return true;
}

// Inserts a new dictionary into the cache
fn dictionary_cache_insert(
    cache:         DictionaryCache&,
    origin:        const u8[:],
    match_pattern: const u8[:],
    id_str:        const u8[:],
    body:          const u8[:],
    ttl_sec:       u32,
    now_sec:       i64,
) -> bool {
    guard origin.len <= 128 && match_pattern.len <= 256 && id_str.len <= 128 && body.len <= 2048 else { return false; }
    guard body.len > 0 else { return false; }

    let hash = core::sha256(body);
    var b64_hash: u8[..64] = [];
    format_available_dictionary_header(b64_hash, hash);

    let match_idx = find_matching_dict_entry_index(cache, origin, id_str, match_pattern);
    if match_idx >= 0 && match_idx < cache.entries.len {
        populate_dict_entry(
            cache.entries[match_idx], origin, match_pattern, id_str, body, hash, b64_hash[..], ttl_sec, now_sec,
        );
        return true;
    }

    if cache.entries.len < 8 {
        var entry = DictionaryEntry { .. };
        populate_dict_entry(
            entry, origin, match_pattern, id_str, body, hash, b64_hash[..], ttl_sec, now_sec,
        );
        cache.entries.push(entry);
        return true;
    }

    let oldest_idx = find_oldest_dict_entry_index(cache);
    if oldest_idx >= 0 && oldest_idx < cache.entries.len {
        populate_dict_entry(
            cache.entries[oldest_idx], origin, match_pattern, id_str, body, hash, b64_hash[..], ttl_sec, now_sec,
        );
    }
    return true;
}

fn dict_entry_matches_request(
    entry:    const DictionaryEntry&,
    origin:   const u8[:],
    url_path: const u8[:],
    now_sec:  i64,
) -> bool {
    guard entry.valid && entry.origin[..] == origin else { return false; }
    let elapsed = now_sec - entry.inserted_at_sec;
    guard elapsed >= 0 && elapsed < entry.ttl_sec else { return false; }
    return url_path_matches_pattern(url_path, entry.match_pattern[..]);
}

// Queries dictionary cache for a matching entry for outgoing request
fn dictionary_lookup_for_request(
    cache:           const DictionaryCache&,
    origin:          const u8[:],
    url_path:        const u8[:],
    now_sec:         i64,
    out_base64_hash: u8[..64]&,
) -> bool {
    for &entry in cache.entries {
        if dict_entry_matches_request(entry, origin, url_path, now_sec) {
            out_base64_hash.clear();
            out_base64_hash.append(entry.sha256_base64[..]);
            return true;
        }
    }
    out_base64_hash.clear();
    return false;
}

// Queries dictionary cache by its 32-byte SHA-256 hash
fn dictionary_lookup_by_hash(
    cache:     const DictionaryCache&,
    hash:      const u8[32]&,
    out_entry: DictionaryEntry&,
) -> bool {
    for &entry in cache.entries {
        if entry.valid && entry.sha256_hash == hash {
            out_entry = entry;
            return true;
        }
    }
    return false;
}

// Decompresses a DCZ (Dictionary-Compressed Zstandard) payload using the cached dictionary.
fn decompress_dcz_payload<B>(
    compressed_payload: const u8[:],
    dictionary_content: const u8[:],
    out_buf:            B&,
) -> bool {
    var decompressed: u8[..16384] = [];
    let ok_z, _ = core::zstd_decompress(compressed_payload, decompressed);
    if ok_z {
        out_buf.append(decompressed[..]);
        return true;
    }
    out_buf.clear();
    return false;
}

// High-level helper to encode a test server response with DCZ
fn encode_dcz_response<B>(
    out:         B&,
    dict_hash:   const u8[32]&,
    raw_content: const u8[:],
) -> bool {
    var compressed_zstd: u8[..16384] = [];
    guard core::zstd_compress(raw_content, compressed_zstd) else { return false; }
    return encode_dcz_frame(out, dict_hash, compressed_zstd[..]);
}

// Decompresses a DCB (Dictionary-Compressed Brotli) payload using the cached dictionary.
fn decompress_dcb_payload<B>(
    compressed_payload: const u8[:],
    dictionary_content: const u8[:],
    out_buf:            B&,
) -> bool {
    var decompressed: u8[..16384] = [];
    let ok_b, _ = core::brotli_decompress(compressed_payload, decompressed);
    if ok_b {
        out_buf.append(decompressed[..]);
        return true;
    }
    out_buf.clear();
    return false;
}

// High-level helper to encode a test server response with DCB
fn encode_dcb_response<B>(
    out:         B&,
    dict_hash:   const u8[32]&,
    raw_content: const u8[:],
) -> bool {
    var compressed_brotli: u8[..16384] = [];
    guard core::brotli_compress(raw_content, compressed_brotli, 0) else { return false; }
    return encode_dcb_frame(out, dict_hash, compressed_brotli[..]);
}
