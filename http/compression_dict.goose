// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9842: Compression Dictionary Transport (September 2025).
// Implements shared dictionary transport for HTTP:
// - `Use-As-Dictionary` response header parser and cache manager
// - `Available-Dictionary` request header generator (RFC 9651 Structured Field Byte Sequence)
// - `Dictionary-ID` request header generator (RFC 9842 Section 2.3)
// - `dcz` (Dictionary-Compressed Zstandard) frame codec and validator (RFC 9842 Section 5)
// - `dcb` (Dictionary-Compressed Brotli) frame header codec (RFC 9842 Section 4)
namespace http;

import std;
import core;
import rfc.http;
import http.headers;
import http.sfv;
import .request;
import .response;
import http.codec_internal;

// ---- Normative Constants & Wire Magics (RFC 9842) ------------------------

// RFC 9842 Section 4 (DCB): 4-byte magic [0xFF, 'D', 'C', 'B'] + 32-byte SHA-256 (36 bytes).
// RFC 9842 Section 5 (DCZ): 8-byte magic [0x5E, 0x2A, 0x4D, 0x18, 0x20, 0x00, 0x00, 0x00] + 32-byte SHA-256 (40 bytes).

struct DictionaryParams {
    match_pattern: u8[..128]      = [],
    match_dest:    u8[..64][..16] = [],
    id:            u8[..64]       = [],
    ttl_sec:       u32            = 86400,
    dict_type:     u8[..16]       = "raw",
    valid:         bool           = false,
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
        let prefix = pattern[..^1];
        return starts_with(path, prefix);
    }
    return path == pattern;
}

// ---- Header Parsers & Serializers ---------------------------------------

// Parses `Use-As-Dictionary` header value (e.g. `match="/assets/*", id="v1", ttl=86400, type=raw`).
//
// Example:
//   header_val = "match=\"/assets/*\", id=\"v1\""
//   returns: p with match_pattern="/assets/*", id="v1", ok = true
fn parse_use_as_dictionary_header(header_val: const u8[:]) -> DictionaryParams, bool {
    var p = DictionaryParams { .. };
    var entries: SfDictEntry[..16] = [];
    guard header_val.trim_lws().len > 0 && parse_sf_dict(header_val, entries) else {
        return DictionaryParams { .. }, false;
    }

    for &entry in entries {
        guard http_internal::apply_dictionary_entry(p, entry) else {
            return DictionaryParams { .. }, false;
        }
    }

    guard p.valid else { return DictionaryParams { .. }, false; }
    return p, true;
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

// ---- DCZ / DCB Wire Format Codec (RFC 9842 Section 4 & Section 5) ---------

// RFC 9842 Section 5: Dictionary-Compressed Zstandard - Encodes a 40-byte DCZ header + compressed Zstandard payload.
fn encode_dcz_frame<B>(out: B&, dict_hash: const u8[32]&, compressed_payload: const u8[:]) -> bool {
    let needed = core::add_sat_i64(core::add_sat_i64(out.len, 40), compressed_payload.len);
    guard needed <= out.cap else { return false; }
    out.push(rfc::DCZ_RFC9842_MAGIC0);
    out.push(rfc::DCZ_RFC9842_MAGIC1);
    out.push(rfc::DCZ_RFC9842_MAGIC2);
    out.push(rfc::DCZ_RFC9842_MAGIC3);
    out.push(rfc::DCZ_RFC9842_MAGIC4);
    out.push(rfc::DCZ_RFC9842_MAGIC5);
    out.push(rfc::DCZ_RFC9842_MAGIC6);
    out.push(rfc::DCZ_RFC9842_MAGIC7);
    for b in dict_hash {
        out.push(b);
    }
    out.append(compressed_payload);
    return true;
}

fn encode_dcz_frame(out: u8[>..]&, dict_hash: const u8[32]&, compressed_payload: const u8[:]) -> bool {
    out.push(rfc::DCZ_RFC9842_MAGIC0);
    out.push(rfc::DCZ_RFC9842_MAGIC1);
    out.push(rfc::DCZ_RFC9842_MAGIC2);
    out.push(rfc::DCZ_RFC9842_MAGIC3);
    out.push(rfc::DCZ_RFC9842_MAGIC4);
    out.push(rfc::DCZ_RFC9842_MAGIC5);
    out.push(rfc::DCZ_RFC9842_MAGIC6);
    out.push(rfc::DCZ_RFC9842_MAGIC7);
    for b in dict_hash {
        out.push(b);
    }
    out.append(compressed_payload);
    return true;
}

// Encodes a DCB (Dictionary-Compressed Brotli) frame:
// [0xFF, 'D', 'C', 'B'] || [32-byte Dictionary SHA-256] || [Compressed Brotli Payload]
fn encode_dcb_frame<B>(out: B&, dict_hash: const u8[32]&, compressed_payload: const u8[:]) -> bool {
    let needed = core::add_sat_i64(core::add_sat_i64(out.len, 36), compressed_payload.len);
    guard needed <= out.cap else { return false; }
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

fn encode_dcb_frame(out: u8[>..]&, dict_hash: const u8[32]&, compressed_payload: const u8[:]) -> bool {
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
// Verifies 8-byte RFC 9842 §5 magic (or 4-byte draft magic), extracts 32-byte dict hash
// and returns the compressed payload slice.
//
// Example:
//   wire = [0xFF, 'D', 'C', 'Z', ...32 hash bytes..., ...payload...]
//   returns: payload slice, out_hash populated, ok = true
fn decode_dcz_header(wire: const u8[:], out_hash: u8[32]&) -> const u8[:], bool {
    if http_internal::is_dcz_rfc9842_magic(wire) {
        let hash_slice = wire[8..40];
        for b, idx in hash_slice {
            out_hash[idx] = b;
        }
        return wire[40..], true;
    }
    guard http_internal::is_dcz_legacy_magic(wire) else { return wire[..0], false; }

    let hash_slice = wire[4..36];
    for b, idx in hash_slice {
        out_hash[idx] = b;
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

// RFC 9842 Section 4 & Section 5: Verifies the 4-byte DCZ (`\xFFDCZ`) or DCB (`\xFFDCB`) magic header
// and validates that the 32-byte SHA-256 dictionary hash matches `expected_hash` in constant time.
//
// Example:
//   wire = [0xFF, 'D', 'C', 'Z', ...32-byte expected_hash..., ...payload...], is_dcz = true
//   returns: payload slice, ok = true
fn verify_dcz_dcb_magic(wire: const u8[:], is_dcz: bool, expected_hash: const u8[32]&) -> const u8[:], bool {
    var actual_hash: u8[32] = [0; 32];
    if is_dcz {
        let payload, ok = decode_dcz_header(wire, actual_hash);
        guard ok else { return wire[..0], false; }
        guard core::ct_eq_bytes(actual_hash[..], expected_hash[..]) else {
            return wire[..0], false;
        }
        return payload, true;
    }
    let payload, ok = decode_dcb_header(wire, actual_hash);
    guard ok else { return wire[..0], false; }
    guard core::ct_eq_bytes(actual_hash[..], expected_hash[..]) else {
        return wire[..0], false;
    }
    return payload, true;
}

// ---- Dictionary Cache Operations -----------------------------------------

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
    guard origin.len <= 128 && match_pattern.len <= 128 && id_str.len <= 64 && body.len <= 2048 else { return false; }
    guard body.len > 0 else { return false; }

    let hash = core::sha256(body);
    var b64_hash: u8[..64] = [];
    format_available_dictionary_header(b64_hash, hash);

    let match_idx = http_internal::find_matching_dict_entry_index(cache, origin, id_str, match_pattern);
    if match_idx >= 0 && match_idx < cache.entries.len {
        http_internal::populate_dict_entry(
            cache.entries[match_idx], origin, match_pattern, id_str, body, hash, b64_hash[..], ttl_sec, now_sec,
        );
        return true;
    }

    if cache.entries.len < 8 {
        var entry = DictionaryEntry { .. };
        http_internal::populate_dict_entry(
            entry, origin, match_pattern, id_str, body, hash, b64_hash[..], ttl_sec, now_sec,
        );
        cache.entries.push(entry);
        return true;
    }

    let oldest_idx = http_internal::find_oldest_dict_entry_index(cache);
    if oldest_idx >= 0 && oldest_idx < cache.entries.len {
        http_internal::populate_dict_entry(
            cache.entries[oldest_idx], origin, match_pattern, id_str, body, hash, b64_hash[..], ttl_sec, now_sec,
        );
    }
    return true;
}

fn find_best_matching_dict_idx(
    dict_cache: const DictionaryCache&,
    origin_buf: const u8[:],
    curr_path:  const u8[:],
    now_sec:    i64,
) -> i64 {
    var best_idx:  i64 = -1;
    var best_len:  i64 = -1;
    var best_time: i64 = -1;
    for &entry, idx in dict_cache.entries {
        if http_internal::dict_entry_matches_request(entry, origin_buf, curr_path, now_sec) {
            let pat_len = entry.match_pattern.len;
            if pat_len > best_len || (pat_len == best_len && entry.inserted_at_sec >= best_time) {
                best_idx = idx;
                best_len = pat_len;
                best_time = entry.inserted_at_sec;
            }
        }
    }
    return best_idx;
}

// Queries dictionary cache for a matching entry for outgoing request.
fn dictionary_lookup_for_request(
    cache:    const DictionaryCache&,
    origin:   const u8[:],
    url_path: const u8[:],
    now_sec:  i64,
) -> u8[..64], bool {
    var out_hash: u8[..64] = [];
    let best_idx = find_best_matching_dict_idx(cache, origin, url_path, now_sec);
    if best_idx >= 0 && best_idx < cache.entries.len {
        let ok = out_hash.try_set(cache.entries[best_idx].sha256_base64[..]);
        return out_hash, ok;
    }
    return out_hash, false;
}

// Queries dictionary cache by its 32-byte SHA-256 hash
fn dictionary_lookup_by_hash(
    cache:     const DictionaryCache&,
    hash:      const u8[32]&,
    out_entry: DictionaryEntry&,
) -> bool {
    for &entry in cache.entries {
        if entry.valid && core::ct_eq_bytes(entry.sha256_hash[..], hash[..]) {
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
    if out_buf.len == 0 {
        let ok_z, _ = core::zstd_decompress_with_dict(compressed_payload, dictionary_content, out_buf, 10485760);
        if !ok_z { out_buf.clear(); }
        return ok_z;
    }
    var decompressed: u8[..16384] = [];
    let ok_z, _ = core::zstd_decompress_with_dict(compressed_payload, dictionary_content, decompressed, 16384);
    guard ok_z else { return false; }
    return out_buf.try_append(decompressed[..]);
}

// Compresses a payload with Zstandard using `dictionary_content` for RFC 9842 `dcz` encoding.
fn compress_dcz_payload<B>(
    raw_content:        const u8[:],
    dictionary_content: const u8[:],
    out_buf:            B&,
    level:              i32 = 3,
) -> bool {
    return core::zstd_compress_with_dict(raw_content, dictionary_content, out_buf, level);
}

// High-level helper to encode a test server response with DCZ
fn encode_dcz_response<B>(
    out:                B&,
    dict_hash:          const u8[32]&,
    raw_content:        const u8[:],
    dictionary_content: const u8[:] = "",
) -> bool {
    var compressed_zstd: u8[..16384] = [];
    guard compress_dcz_payload(raw_content, dictionary_content, compressed_zstd, 3) else { return false; }
    return encode_dcz_frame(out, dict_hash, compressed_zstd[..]);
}

// Decompresses a DCB (Dictionary-Compressed Brotli) payload using the cached dictionary.
fn decompress_dcb_payload<B>(
    compressed_payload: const u8[:],
    dictionary_content: const u8[:],
    out_buf:            B&,
) -> bool {
    if out_buf.len == 0 {
        let ok_b, _ = core::brotli_decompress_with_dict(compressed_payload, dictionary_content, out_buf, 10485760);
        if !ok_b { out_buf.clear(); }
        return ok_b;
    }
    var decompressed: u8[..16384] = [];
    let ok_b, _ = core::brotli_decompress_with_dict(compressed_payload, dictionary_content, decompressed, 16384);
    guard ok_b else { return false; }
    return out_buf.try_append(decompressed[..]);
}

// High-level helper to encode a test server response with DCB
fn encode_dcb_response<B>(
    out:                B&,
    dict_hash:          const u8[32]&,
    raw_content:        const u8[:],
    dictionary_content: const u8[:] = "",
) -> bool {
    var compressed_brotli: u8[..16384] = [];
    let level: i32 = if dictionary_content.len > 0 { 1 } else { 0 };
    guard http_internal::compress_dcb_payload(
        raw_content, dictionary_content, compressed_brotli, level,
    ) else {
        return false;
    }
    return encode_dcb_frame(out, dict_hash, compressed_brotli[..]);
}

// ---- RFC 9842 Server-Side Dictionary Negotiation -------------------------

// RFC 9842 Section 2.1: Use-As-Dictionary - Attaches `Use-As-Dictionary` response header advertising
// the current response payload as a shared compression dictionary for future matching requests.
fn set_use_as_dictionary_response(
    res:           Response&,
    match_pattern: const u8[:],
    id_str:        const u8[:] = "",
    ttl_sec:       u32         = 86400,
) {
    guard match_pattern.len > 0 && match_pattern.len <= 128 && id_str.len <= 64 else { return; }
    guard http_internal::is_valid_sf_string_value(match_pattern) &&
        http_internal::is_valid_sf_string_value(id_str) else {
        return;
    }
    var hdr_val: u8[..512] = [];
    format_use_as_dictionary_header(hdr_val, match_pattern, id_str, ttl_sec);
    set_header(res, "Use-As-Dictionary", hdr_val[..]);
}

// RFC 9842 Section 6: Checks whether a comma-separated `Accept-Encoding` header list contains `target_token`.
fn accept_encoding_has_token(ae: const u8[:], target_token: const u8[:]) -> bool {
    var cursor: i64 = 0;
    while cursor < ae.len {
        var comma_idx = cursor;
        while comma_idx < ae.len && ae[comma_idx] != ',' {
            comma_idx = core::add_sat_i64(comma_idx, 1);
        }
        let item = ae[cursor..comma_idx].trim_lws();
        var semi_idx: i64 = 0;
        while semi_idx < item.len && item[semi_idx] != ';' {
            semi_idx = core::add_sat_i64(semi_idx, 1);
        }
        let coding = item[..semi_idx].trim_lws();
        if coding.len > 0 && coding.eq_ascii_fold(target_token) && !is_zero_qvalue(item[semi_idx..]) {
            return true;
        }
        cursor = core::add_sat_i64(comma_idx, 1);
    }
    return false;
}

// RFC 9842 Section 4 & Section 5: Encodes a server `Response` body using `dcz` (`\xFFDCZ` + 32-byte SHA-256)
// or `dcb` (`\xFFDCB` + 32-byte SHA-256) when negotiated by `negotiate_compression_dictionary`.
fn apply_negotiated_dictionary_response(
    req:                const Request&,
    res:                Response&,
    dict_hash:          const u8[32]&,
    raw_content:        const u8[:],
    expected_id:        const u8[:] = "",
    dictionary_content: const u8[:] = "",
) -> bool {
    let enc, ok = http_internal::negotiate_compression_dictionary(req, dict_hash, expected_id);
    guard ok && raw_content.len <= 16300 else { return false; }

    var encoded_body: u8[..16420] = [];
    if enc == rfc::ENCODING_DCZ {
        guard encode_dcz_response(encoded_body, dict_hash, raw_content, dictionary_content) else { return false; }
        res.body.clear();
        res.body.append(encoded_body[..]);
        set_header(res, "Content-Encoding", rfc::ENCODING_DCZ);
        set_header(res, "Vary", "Accept-Encoding, Available-Dictionary");
        return true;
    }
    if enc == rfc::ENCODING_DCB {
        guard encode_dcb_response(encoded_body, dict_hash, raw_content, dictionary_content) else { return false; }
        res.body.clear();
        res.body.append(encoded_body[..]);
        set_header(res, "Content-Encoding", rfc::ENCODING_DCB);
        set_header(res, "Vary", "Accept-Encoding, Available-Dictionary");
        return true;
    }
    return false;
}
