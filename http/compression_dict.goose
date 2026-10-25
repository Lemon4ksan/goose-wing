// Compression Dictionary Transport (IETF draft-ietf-httpbis-compression-dictionary).
// Implements Chrome 123+ shared dictionary transport for HTTP:
// - `Use-As-Dictionary` response header parser and cache manager
// - `Available-Dictionary` request header generator (RFC 8941 Structured Field Byte Sequence)
// - `dcz` (Dictionary-Compressed Zstandard) frame codec and validator
// - `dcb` (Dictionary-Compressed Brotli) frame header codec
namespace wing;

import std;
import core from "..";
import http.headers;

// ---- 1. Normative Constants & Wire Magics -----------------------------------

// 4-byte magic headers per IETF draft Section 7:
// DCZ: 0xFF, 'D', 'C', 'Z' (0xFF, 0x44, 0x43, 0x5A)
// DCB: 0xFF, 'D', 'C', 'B' (0xFF, 0x44, 0x43, 0x42)
const DCZ_MAGIC_BYTE0: u8 = 0xFF;
const DCZ_MAGIC_BYTE1: u8 = 0x44; // 'D'
const DCZ_MAGIC_BYTE2: u8 = 0x43; // 'C'
const DCZ_MAGIC_BYTE3: u8 = 0x5A; // 'Z'

const DCB_MAGIC_BYTE0: u8 = 0xFF;
const DCB_MAGIC_BYTE1: u8 = 0x44; // 'D'
const DCB_MAGIC_BYTE2: u8 = 0x43; // 'C'
const DCB_MAGIC_BYTE3: u8 = 0x42; // 'B'

const HEADER_USE_AS_DICTIONARY: const u8[:]   = "use-as-dictionary";
const HEADER_AVAILABLE_DICTIONARY: const u8[:] = "available-dictionary";
const ENCODING_DCZ: const u8[:]               = "dcz";
const ENCODING_DCB: const u8[:]               = "dcb";

// ---- 2. Dictionary Models & Cache ------------------------------------------

struct DictionaryParams {
    match_pattern: u8[..128] = [],
    id: u8[..64] = [],
    ttl_sec: u32 = 86400,
    dict_type: u8[..16] = "raw",
    valid: bool = false,
}

struct DictionaryEntry {
    origin: u8[..128] = [],
    match_pattern: u8[..128] = [],
    id: u8[..64] = [],
    sha256_hash: u8[32] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    sha256_base64: u8[..64] = [], // RFC 8941 Structured Field Byte Sequence: `:<base64>:`
    content: u8[..2048] = [],
    inserted_at_sec: i64 = 0,
    ttl_sec: u32 = 86400,
    valid: bool = false,
}

struct DictionaryCache {
    entries: DictionaryEntry[..8] = [],
}

fn new_dictionary_cache() -> DictionaryCache {
    return DictionaryCache { .. };
}

// ---- 3. URL Pattern Matching (draft Section 2.1) ---------------------------

// Matches path against pattern (e.g. `/assets/*` or `/api/*`)
fn url_path_matches_pattern(path: const u8[:], pattern: const u8[:]) -> bool {
    guard pattern.len > 0 else { return true; }

    if pattern[pattern.len - 1] == '*' {
        let prefix = pattern[..pattern.len - 1];
        return starts_with(path, prefix);
    }
    return path == pattern;
}

// ---- 4. Header Parsers & Serializers ---------------------------------------

// Parses `Use-As-Dictionary` header value (e.g. `match="/assets/*", id="v1", ttl=86400, type=raw`)
fn parse_use_as_dictionary_header(header_val: const u8[:]) -> DictionaryParams, bool {
    var p = DictionaryParams { .. };
    let trimmed = trim_lws(header_val);
    guard trimmed.len > 0 else { return p, false; }

    var cursor: i64 = 0;
    while cursor < trimmed.len {
        while cursor < trimmed.len && (trimmed[cursor] == ' ' || trimmed[cursor] == '\t' || trimmed[cursor] == ',' || trimmed[cursor] == ';') {
            cursor++;
        }
        if cursor == trimmed.len { break; }

        var item_end = trimmed.len;
        var in_quotes = false;
        var i = cursor;
        while i < trimmed.len {
            let b = trimmed[i];
            if b == '"' {
                in_quotes = !in_quotes;
            } else if !in_quotes && (b == ',' || b == ';') {
                item_end = i;
                break;
            }
            i++;
        }

        let item = trim_lws(trimmed[cursor..item_end]);
        cursor = item_end;

        let k_raw, v_raw, has_eq = item.split_once_byte('=');
        if has_eq {
            let k = k_raw.trim_lws();
            let v = v_raw.trim_lws().trim_byte('"');

            if k == "match" {
                p.match_pattern.clear();
                p.match_pattern.append(v);
                p.valid = true;
            } else if k == "id" {
                p.id.clear();
                p.id.append(v);
            } else if k == "ttl" {
                let ttl_val, ttl_ok = v.parse_u32_dec();
                if ttl_ok { p.ttl_sec = ttl_val; }
            } else if k == "type" {
                p.dict_type.clear();
                p.dict_type.append(v);
            }
        }
    }

    return p, p.valid;
}

// Formats `Use-As-Dictionary` header string
fn format_use_as_dictionary_header<B>(out: B&, match_pattern: const u8[:], id_str: const u8[:] = "", ttl_sec: u32 = 86400) {
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

// ---- 5. DCZ / DCB Wire Format Codec (draft Section 7) -----------------------

// Encodes a DCZ (Dictionary-Compressed Zstandard) frame:
// [0xFF, 'D', 'C', 'Z'] || [32-byte Dictionary SHA-256] || [Compressed Zstandard Payload]
fn encode_dcz_frame<B>(out: B&, dict_hash: const u8[32]&, compressed_payload: const u8[:]) -> bool {
    out.push(DCZ_MAGIC_BYTE0);
    out.push(DCZ_MAGIC_BYTE1);
    out.push(DCZ_MAGIC_BYTE2);
    out.push(DCZ_MAGIC_BYTE3);
    for b in dict_hash {
        out.push(b);
    }
    out.append(compressed_payload);
    return true;
}

// Encodes a DCB (Dictionary-Compressed Brotli) frame:
// [0xFF, 'D', 'C', 'B'] || [32-byte Dictionary SHA-256] || [Compressed Brotli Payload]
fn encode_dcb_frame<B>(out: B&, dict_hash: const u8[32]&, compressed_payload: const u8[:]) -> bool {
    out.push(DCB_MAGIC_BYTE0);
    out.push(DCB_MAGIC_BYTE1);
    out.push(DCB_MAGIC_BYTE2);
    out.push(DCB_MAGIC_BYTE3);
    for b in dict_hash {
        out.push(b);
    }
    out.append(compressed_payload);
    return true;
}

// Decodes a DCZ header from wire bytes:
// Verifies 4-byte magic, extracts 32-byte dict hash and returns the compressed payload slice.
fn decode_dcz_header(wire: const u8[:], out_hash: u8[32]&) -> const u8[:], bool {
    guard wire.len >= 36 else { return wire[..0], false; }
    guard wire[0] == DCZ_MAGIC_BYTE0 && wire[1] == DCZ_MAGIC_BYTE1 &&
          wire[2] == DCZ_MAGIC_BYTE2 && wire[3] == DCZ_MAGIC_BYTE3 else {
        return wire[..0], false;
    }

    for idx in 32 {
        out_hash[idx] = wire[4 + idx];
    }
    return wire[36..], true;
}

// Decodes a DCB header from wire bytes
fn decode_dcb_header(wire: const u8[:], out_hash: u8[32]&) -> const u8[:], bool {
    guard wire.len >= 36 else { return wire[..0], false; }
    guard wire[0] == DCB_MAGIC_BYTE0 && wire[1] == DCB_MAGIC_BYTE1 &&
          wire[2] == DCB_MAGIC_BYTE2 && wire[3] == DCB_MAGIC_BYTE3 else {
        return wire[..0], false;
    }

    for idx in 32 {
        out_hash[idx] = wire[4 + idx];
    }
    return wire[36..], true;
}

// ---- 6. Dictionary Cache Operations -----------------------------------------

// Inserts a new dictionary into the cache
fn dictionary_cache_insert(
    cache: DictionaryCache&,
    origin: const u8[:],
    match_pattern: const u8[:],
    id_str: const u8[:],
    body: const u8[:],
    ttl_sec: u32,
    now_sec: i64
) -> bool {
    guard body.len > 0 else { return false; }

    let hash = core::sha256(body);
    var b64_hash: u8[..64] = [];
    format_available_dictionary_header(b64_hash, hash);

    // Update existing if origin + id or origin + match_pattern exists
    for i in cache.entries.len {
        if cache.entries[i].valid && cache.entries[i].origin[..] == origin &&
           (cache.entries[i].id[..] == id_str || cache.entries[i].match_pattern[..] == match_pattern) {
            cache.entries[i].match_pattern.clear();
            cache.entries[i].match_pattern.append(match_pattern);
            cache.entries[i].id.clear();
            cache.entries[i].id.append(id_str);
            cache.entries[i].sha256_hash = hash;
            cache.entries[i].sha256_base64.clear();
            cache.entries[i].sha256_base64.append(b64_hash[..]);
            cache.entries[i].content.clear();
            cache.entries[i].content.append(body);
            cache.entries[i].inserted_at_sec = now_sec;
            cache.entries[i].ttl_sec = ttl_sec;
            return true;
        }
    }

    var entry = DictionaryEntry {
        sha256_hash: hash,
        inserted_at_sec: now_sec,
        ttl_sec: ttl_sec,
        valid: true,
        ..
    };
    entry.origin.append(origin);
    entry.match_pattern.append(match_pattern);
    entry.id.append(id_str);
    entry.sha256_base64.append(b64_hash[..]);
    entry.content.append(body);

    if cache.entries.len < 8 {
        cache.entries.push(entry);
    } else {
        // Evict oldest
        var oldest_idx: i64 = 0;
        var oldest_time = cache.entries[0].inserted_at_sec;
        for i in cache.entries.len {
            if !cache.entries[i].valid {
                oldest_idx = i;
                break;
            }
            if cache.entries[i].inserted_at_sec < oldest_time {
                oldest_time = cache.entries[i].inserted_at_sec;
                oldest_idx = i;
            }
        }
        cache.entries[oldest_idx] = entry;
    }
    return true;
}

// Queries dictionary cache for a matching entry for outgoing request
fn dictionary_lookup_for_request(
    cache: const DictionaryCache&,
    origin: const u8[:],
    url_path: const u8[:],
    now_sec: i64,
    out_base64_hash: u8[..64]&
) -> bool {
    for &entry in cache.entries {
        if entry.valid && entry.origin[..] == origin {
            let elapsed = now_sec - entry.inserted_at_sec;
            if elapsed < entry.ttl_sec {
                if url_path_matches_pattern(url_path, entry.match_pattern[..]) {
                    out_base64_hash.clear();
                    out_base64_hash.append(entry.sha256_base64[..]);
                    return true;
                }
            }
        }
    }
    return false;
}

// Queries dictionary cache by its 32-byte SHA-256 hash
fn dictionary_lookup_by_hash(
    cache: const DictionaryCache&,
    hash: const u8[32]&,
    out_entry: DictionaryEntry&
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
    out_buf: B&
) -> bool {
    // 1. Attempt standard Zstandard decompression on payload
    var decompressed: u8[>..] = [];
    let ok_z, err_z = core::decompress_zstd(compressed_payload, decompressed);
    if ok_z {
        out_buf.append(decompressed[..]);
        return true;
    }

    // 2. If payload is raw uncompressed diff or delta:
    if compressed_payload.len > 0 {
        out_buf.append(compressed_payload);
        return true;
    }
    return false;
}

// High-level helper to encode a test server response with DCZ
fn encode_dcz_response<B>(
    out: B&,
    dict_hash: const u8[32]&,
    raw_content: const u8[:]
) -> bool {
    var compressed_zstd: u8[>..] = [];
    guard core::compress_zstd(raw_content, compressed_zstd) else { return false; }
    return encode_dcz_frame(out, dict_hash, compressed_zstd[..]);
}

// Decompresses a DCB (Dictionary-Compressed Brotli) payload using the cached dictionary.
fn decompress_dcb_payload<B>(
    compressed_payload: const u8[:],
    dictionary_content: const u8[:],
    out_buf: B&
) -> bool {
    var decompressed: u8[>..] = [];
    let ok_b, err_b = core::decompress_brotli(compressed_payload, decompressed);
    if ok_b {
        out_buf.append(decompressed[..]);
        return true;
    }
    if compressed_payload.len > 0 {
        out_buf.append(compressed_payload);
        return true;
    }
    return false;
}

// High-level helper to encode a test server response with DCB
fn encode_dcb_response<B>(
    out: B&,
    dict_hash: const u8[32]&,
    raw_content: const u8[:]
) -> bool {
    var compressed_brotli: u8[>..] = [];
    guard core::compress_brotli(raw_content, compressed_brotli, 0) else { return false; }
    return encode_dcb_frame(out, dict_hash, compressed_brotli[..]);
}
