// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for `http` (http/codec_internal.goose).
namespace http_internal;

import std;
import core;
import http.bhttp;
import http.client_cert;
import http.compression_dict;
import http.digest_fields;
import http.headers.chunked_fsm;
import http.headers;
import http.ohttp;
import http.request;
import http.response;
import http.sfv;
import rfc.http;
import security.hpke;

// ---- http/bhttp.goose internal helpers ----

// Encoded byte length of a bhttp length prefix (QUIC-style varint).
fn bhttp_varint_size(v: u64) -> u64 {
    if v <= 63 {
        return 1;
    }
    if v <= 16383 {
        return 2;
    }
    if v <= 1073741823 {
        return 4;
    }
    return 8;
}

// Appends one length-prefixed byte string (varint length + bytes) with an
// explicit capacity guard; returns false when the output would overflow.
fn bhttp_put_len_bytes(out: u8[..8192]&, val: const u8[:]) -> bool {
    let need = bhttp_varint_size(val.len as u64) + (val.len as u64);
    guard out.len + (need as i64) <= out.cap else { return false; }
    guard quic::encode_varint(val.len as u64, out) else { return false; }
    out.append(val);
    return true;
}

// Serialized size in bytes of all field lines in a header map (Section 3.6).
fn bhttp_field_section_size(map: const http::HeaderMap&) -> u64 {
    var total: u64 = 0;
    for &entry in map.entries {
        let name = map.raw_buf[entry.name_begin..entry.name_end];
        if name.len == 0 {
            continue;
        }
        let val = map.raw_buf[entry.values_begin..entry.values_end];
        total += bhttp_varint_size(name.len as u64) + (name.len as u64);
        total += bhttp_varint_size(val.len as u64) + (val.len as u64);
    }
    return total;
}

// Writes header section (length prefix + field lines), content, and empty
// trailers after control data; returns false on capacity overflow.
fn bhttp_encode_tail(map: const http::HeaderMap&, body: const u8[:], out: u8[..8192]&) -> bool {
    let section_len = bhttp_field_section_size(map);
    let section_need = bhttp_varint_size(section_len) + section_len;
    let content_need = bhttp_varint_size(body.len as u64) + (body.len as u64);
    // Pre-validate total capacity (section + content + 1-byte empty trailers)
    // so no partial write can occur on overflow.
    guard out.len + (section_need as i64) + (content_need as i64) + 1 <= out.cap else { return false; }
    guard quic::encode_varint(section_len, out) else { return false; }
    for &entry in map.entries {
        let name = map.raw_buf[entry.name_begin..entry.name_end];
        if name.len == 0 {
            continue;
        }
        let val = map.raw_buf[entry.values_begin..entry.values_end];
        guard bhttp_put_len_bytes(out, name) else { return false; }
        guard bhttp_put_len_bytes(out, val) else { return false; }
    }

    guard bhttp_put_len_bytes(out, body) else { return false; } // content
    guard bhttp_put_len_bytes(out, "") else { return false; }   // empty trailers
    return true;
}

// Parses one field line at idx within the bounded view `sec`, appending it to
// `headers`. Enforces name length >= 1, bounds, pseudo-field ordering, and
// rejects the reserved pseudo-fields (RFC 9292 Section 3.6).
// Advances idx past the field line on success; idx is unchanged on failure.
//
// Example:
//   sec = [0x06, 'a', 'c', 'c', 'e', 'p', 't', 0x03, '*', '/', '*'], idx = 0
//   returns: ok = true, headers gains ("accept", "*/*"), idx = 11
fn bhttp_decode_field_line(
    sec:          const u8[:],
    idx:          i64&,
    headers:      http::HeaderMap&,
    seen_regular: bool&,
) -> bool {
    var scan = idx;
    let name_len, ok1 = quic::decode_varint_cursor(sec, scan);
    guard ok1 && name_len >= 1 && name_len <= ((sec.len - scan) as u64) else { return false; }
    let name_end = scan + (name_len as i64);
    let name = sec[scan..name_end];
    scan = name_end;

    let val_len, ok2 = quic::decode_varint_cursor(sec, scan);
    guard ok2 && val_len <= ((sec.len - scan) as u64) else { return false; }
    let val_end = scan + (val_len as i64);
    let val = sec[scan..val_end];

    if name[0] == ':' {
        // Pseudo-fields must precede regular fields; reserved names are invalid (Section 3.6).
        guard !seen_regular else { return false; }
        guard !rfc::bhttp_is_reserved_pseudo(name) else { return false; }
        guard http::is_valid_header_name_h2(name) && http::is_valid_header_value(val) else { return false; }
    } else {
        seen_regular = true;
        guard http::is_valid_header_name_h2(name) && http::is_valid_header_value(val) else { return false; }
    }
    guard headers.append_header(name, val) else { return false; }
    idx = val_end;
    return true;
}

// Shared tail of every known-length decode: field section, content, trailers,
// and zero-padding validation after control data (RFC 9292 Sections 3.1, 3.8).
// Truncated missing lengths are treated as zero (Section 3.8).
//
// Example:
//   raw = [0x03,'G','E','T',0x00,0x00,0x00,0x00,0x00,0x00], idx = 7
//   returns: ok = true, empty headers/body, idx = 10 (all sections zero-length)
fn bhttp_decode_tail(
    raw:      const u8[:],
    idx:      i64&,
    headers:  http::HeaderMap&,
    body:     u8[..4096]&,
    body_len: i32&,
) -> bool {
    var scan = idx;
    if scan < raw.len {
        let sec_len, ok = quic::decode_varint_cursor(raw, scan);
        guard ok && sec_len <= ((raw.len - scan) as u64) else { return false; }
        let sec_end = scan + (sec_len as i64);
        let sec = raw[scan..sec_end];
        var jdx: i64 = 0;
        var seen_regular = false;
        while jdx < sec.len {
            guard bhttp_decode_field_line(sec, jdx, headers, seen_regular) else { return false; }
        }
        scan = sec_end;
    }

    if scan < raw.len {
        let clen, ok = quic::decode_varint_cursor(raw, scan);
        guard ok && clen <= ((raw.len - scan) as u64) else { return false; }
        let cend = scan + (clen as i64);
        guard body.try_set(raw[scan..cend]) else { return false; }
        body_len = clen as i32;
        scan = cend;
    }

    if scan < raw.len {
        let tlen, ok = quic::decode_varint_cursor(raw, scan);
        guard ok && tlen <= ((raw.len - scan) as u64) else { return false; }
        let tend = scan + (tlen as i64);
        let trailers = raw[scan..tend];
        var jdx: i64 = 0;
        while jdx < trailers.len {
            // Trailer field lines are validated but discarded (Section 3.1).
            guard http::bhttp_decode_trailer_line(trailers, jdx) else { return false; }
        }
        scan = tend;
    }

    // Remaining bytes are padding and must be zero-valued (Section 3.8).
    while scan < raw.len {
        guard raw[scan] == 0 else { return false; }
        scan += 1;
    }
    idx = scan;
    return true;
}

inline fn is_valid_bhttp_uri_part(s: const u8[:]) -> bool {
    for b in s {
        guard b > 0x20 && b < 0x7F else { return false; }
    }
    return true;
}

// RFC 9292 Section 3.4: Request Control Data - Scheme follows RFC 3986 ALPHA *( ALPHA / DIGIT / "+" / "-" / "." ).
inline fn is_valid_bhttp_scheme(s: const u8[:]) -> bool {
    guard s.len > 0 && s.len <= 16 && core::is_ascii_alpha(s[0]) else { return false; }
    for b in s[1..] {
        guard core::is_ascii_alpha(b) || core::is_ascii_digit(b) || b == '+' || b == '-' || b == '.' else {
            return false;
        }
    }
    return true;
}

fn resolve_bhttp_full_url_control(
    raw_url:    const u8[:],
    scheme_out: u8[..16]&,
    auth_out:   u8[..256]&,
    path_out:   u8[..2048]&,
) -> bool {
    let view, _ = core::parse_url_view(raw_url);
    guard view.valid && is_valid_bhttp_scheme(view.scheme) && scheme_out.try_set(view.scheme) else {
        return false;
    }
    guard auth_out.try_set(view.host) else { return false; }
    if view.port > 0 {
        var pbuf: u8[..16] = [];
        view.port.format_i64_dec(pbuf);
        guard auth_out.try_push(':') && auth_out.try_append(pbuf[..]) else { return false; }
    }
    let p = if view.pathname.len > 0 { view.pathname } else { "/" };
    guard path_out.try_set(p) && (view.search.len == 0 || path_out.try_append(view.search)) else {
        return false;
    }
    return is_valid_bhttp_uri_part(auth_out[..]) && is_valid_bhttp_uri_part(path_out[..]);
}

fn resolve_bhttp_request_control(
    req:        const http::BhttpRequest&,
    scheme_out: u8[..16]&,
    auth_out:   u8[..256]&,
    path_out:   u8[..2048]&,
) -> bool {
    if core::contains(req.target[..], "://") {
        return resolve_bhttp_full_url_control(req.target[..], scheme_out, auth_out, path_out);
    }
    if req.method[..] == "CONNECT" {
        let auth_src = if req.authority.len > 0 {
            req.authority[..]
        } else if req.target.len > 0 {
            req.target[..]
        } else {
            req.headers.get_header("host")
        };
        return auth_src.len > 0 && is_valid_bhttp_uri_part(auth_src) && auth_out.try_set(auth_src);
    }
    guard is_valid_bhttp_scheme(req.scheme[..]) && scheme_out.try_set(req.scheme[..]) else {
        return false;
    }
    let auth_src = if req.authority.len > 0 { req.authority[..] } else { req.headers.get_header("host") };
    guard is_valid_bhttp_uri_part(auth_src) && auth_out.try_set(auth_src) else { return false; }
    return req.target.len > 0 && is_valid_bhttp_uri_part(req.target[..]) && path_out.try_set(req.target[..]);
}

inline fn reset_bhttp_request(out: http::BhttpRequest&) {
    out.method.clear();
    out.scheme.clear();
    out.authority.clear();
    out.target.clear();
    out.headers.reset_for_keep_alive();
    out.body.clear();
    out.body_len = 0;
}

inline fn validate_bhttp_decoded_control(
    method:    const u8[:],
    scheme:    const u8[:],
    authority: const u8[:],
    path:      const u8[:],
) -> bool {
    if method == "CONNECT" {
        return scheme.len == 0 && path.len == 0 &&
               authority.len > 0 && authority.len <= 256 && is_valid_bhttp_uri_part(authority);
    }
    return is_valid_bhttp_scheme(scheme) &&
           authority.len <= 256 && is_valid_bhttp_uri_part(authority) &&
           path.len > 0 && path.len <= 2048 && is_valid_bhttp_uri_part(path);
}

// ---- http/client_cert.goose internal helpers ----

// Decodes one Byte Sequence item into the next chain slot (RFC 9440 §2.3).
fn append_client_cert_chain_item(
    sf_item:   const http::SfItem&,
    out_certs: u8[..4096][..4]&,
) -> bool {
    guard out_certs.len < http::CLIENT_CERT_CHAIN_MAX_ITEMS else { return false; }

    var item: u8[..4096] = [];
    guard sf_decode_byte_sequence(sf_item, item) else { return false; }
    guard item.len > 0 && item.len <= http::CLIENT_CERT_MAX_DER_LEN else { return false; }

    out_certs.push(item);
    return true;
}

// ---- http/compression_dict.goose internal helpers ----

fn apply_dict_match_dest(p: http::DictionaryParams&, entry: const http::SfDictEntry&) -> bool {
    guard entry.is_inner_list else {
        p.valid = false;
        return false;
    }
    p.match_dest.clear();
    for &inner in entry.inner_items {
        guard inner.kind == http::SfType.String else {
            p.valid = false;
            return false;
        }
        var dest: u8[..64] = [];
        guard http::sf_unescape_string(inner.str_val, dest) && p.match_dest.try_push(dest) else {
            p.valid = false;
            return false;
        }
    }
    return true;
}

fn apply_dict_ttl(p: http::DictionaryParams&, item: const http::SfItem&) -> bool {
    guard item.kind == http::SfType.Integer && item.int_val >= 0 && item.int_val <= 4294967295 else {
        p.valid = false;
        return false;
    }
    p.ttl_sec = item.int_val as u32;
    return true;
}

// RFC 9842 Section 2.1.4: "type" - Value MUST be an SF Token ("raw").
fn apply_dict_type(p: http::DictionaryParams&, item: const http::SfItem&) -> bool {
    guard item.kind == http::SfType.Token && item.str_val == "raw" && p.dict_type.try_set(item.str_val) else {
        p.valid = false;
        return false;
    }
    return true;
}

// RFC 9842 Section 2.1.1: "match" - URLPattern regexp groups are prohibited in Use-As-Dictionary match patterns.
inline fn has_unescaped_urlpattern_regexp(pat: const u8[:]) -> bool {
    var escaped = false;
    for b in pat {
        if escaped {
            escaped = false;
            continue;
        }
        if b == '\\' {
            escaped = true;
            continue;
        }
        if b == '(' || b == ')' {
            return true;
        }
    }
    return false;
}

fn apply_dictionary_kv(p: http::DictionaryParams&, key: const u8[:], item: const http::SfItem&) -> bool {
    if key == "match" {
        guard item.kind == http::SfType.String && http::sf_unescape_string(item.str_val, p.match_pattern) else {
            p.match_pattern.clear();
            p.valid = false;
            return false;
        }
        guard p.match_pattern.len > 0 && p.match_pattern[0] == '/' &&
              !has_unescaped_urlpattern_regexp(p.match_pattern[..]) else {
            p.match_pattern.clear();
            p.valid = false;
            return false;
        }
        p.valid = true;
    } else if key == "id" {
        guard item.kind == http::SfType.String && http::sf_unescape_string(item.str_val, p.id) else {
            p.id.clear();
            p.valid = false;
            return false;
        }
    } else if key == "ttl" {
        return apply_dict_ttl(p, item);
    } else if key == "type" {
        return apply_dict_type(p, item);
    }
    return true;
}

// RFC 9842 Section 2.1: Use-As-Dictionary - Ignore unrecognized SF member parameters.
fn apply_dictionary_entry(p: http::DictionaryParams&, entry: const http::SfDictEntry&) -> bool {
    if entry.key == "match-dest" {
        return apply_dict_match_dest(p, entry);
    }
    guard !entry.is_inner_list && apply_dictionary_kv(p, entry.key, entry.item) else {
        p.valid = false;
        return false;
    }
    return true;
}

inline fn is_dcz_rfc9842_magic(wire: const u8[:]) -> bool {
    guard wire.len >= 40 else { return false; }
    return wire[0] == rfc::DCZ_RFC9842_MAGIC0 && wire[1] == rfc::DCZ_RFC9842_MAGIC1 &&
           wire[2] == rfc::DCZ_RFC9842_MAGIC2 && wire[3] == rfc::DCZ_RFC9842_MAGIC3 &&
           wire[4] == rfc::DCZ_RFC9842_MAGIC4 && wire[5] == rfc::DCZ_RFC9842_MAGIC5 &&
           wire[6] == rfc::DCZ_RFC9842_MAGIC6 && wire[7] == rfc::DCZ_RFC9842_MAGIC7;
}

inline fn is_dcz_legacy_magic(wire: const u8[:]) -> bool {
    guard wire.len >= 36 else { return false; }
    return wire[0] == rfc::DCZ_MAGIC_BYTE0 && wire[1] == rfc::DCZ_MAGIC_BYTE1 &&
           wire[2] == rfc::DCZ_MAGIC_BYTE2 && wire[3] == rfc::DCZ_MAGIC_BYTE3;
}

fn find_matching_dict_entry_index(
    cache:         const http::DictionaryCache&,
    origin:        const u8[:],
    id_str:        const u8[:],
    match_pattern: const u8[:],
) -> i64 {
    for i in cache.entries.len {
        let entry = &cache.entries[i];
        if entry.valid && entry.origin[..] == origin &&
           ((id_str.len > 0 && entry.id[..] == id_str) || entry.match_pattern[..] == match_pattern) {
            return i;
        }
    }
    return -1;
}

fn find_oldest_dict_entry_index(cache: const http::DictionaryCache&) -> i64 {
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
    entry:         http::DictionaryEntry&,
    origin:        const u8[:],
    match_pattern: const u8[:],
    id_str:        const u8[:],
    body:          const u8[:],
    hash:          const u8[32]&,
    b64_hash:      const u8[:],
    ttl_sec:       u32,
    now_sec:       i64,
) -> bool {
    guard entry.origin.try_set(origin) &&
          entry.match_pattern.try_set(match_pattern) &&
          entry.id.try_set(id_str) &&
          entry.sha256_base64.try_set(b64_hash) &&
          entry.content.try_set(body) else { return false; }
    entry.valid = true;
    entry.sha256_hash = hash;
    entry.inserted_at_sec = now_sec;
    entry.ttl_sec = ttl_sec;
    return true;
}

fn dict_entry_matches_request(
    entry:    const http::DictionaryEntry&,
    origin:   const u8[:],
    url_path: const u8[:],
    now_sec:  i64,
) -> bool {
    guard entry.valid && entry.origin[..] == origin else { return false; }
    let elapsed = now_sec - entry.inserted_at_sec;
    guard elapsed >= 0 && elapsed < entry.ttl_sec else { return false; }
    return http::url_path_matches_pattern(url_path, entry.match_pattern[..]);
}

// Scans `raw_content` against `dict` with a 4096-entry greedy hash table and records LZ77 commands into `cmds`.
//
// Example:
//   dict = "shared_prefix_data", raw_content = "shared_prefix_data_tail", cmds = []
//   returns: 18
fn scan_dcb_dict_commands(
    dict:        const u8[:],
    raw_content: const u8[:],
    cmds:        core::BrotliLz77Cmd[..512]&,
) -> i64 {
    cmds.clear();
    let d_len = min(dict.len, 16384);
    let d_slice = dict[core::sub_sat_i64(dict.len, d_len)..];
    var combined: u8[..32768] = [];
    guard combined.try_append(d_slice) && combined.try_append(raw_content) else { return 0; }

    var htable: i32[4096] = [-1; 4096];
    var d_pos:  i64       = 0;
    while core::add_sat_i64(d_pos, 4) <= d_len {
        let h = core::hash4_brotli(combined[..], d_pos);
        htable[h] = d_pos as i32;
        d_pos = core::add_sat_i64(d_pos, 1);
    }

    var pos:           i64 = 0;
    var lit_start:     i64 = 0;
    var matched_bytes: i64 = 0;
    while core::add_sat_i64(pos, 4) <= raw_content.len {
        let c_pos = core::add_sat_i64(d_len, pos);
        let h = core::hash4_brotli(combined[..], c_pos);
        let cand = htable[h] as i64;
        let mlen = core::measure_lz77_match(combined[..], cand, c_pos);
        if mlen >= 4 {
            let cmd = core::BrotliLz77Cmd {
                ins_start: lit_start as u32,
                ins_len:   core::sub_sat_i64(pos, lit_start) as u32,
                copy_len:  mlen as u32,
                distance:  core::sub_sat_i64(c_pos, cand) as u32,
            };
            guard cmds.try_push(cmd) else { break; }
            htable[h] = c_pos as i32;
            matched_bytes = core::add_sat_i64(matched_bytes, mlen);
            pos = core::add_sat_i64(pos, mlen);
            lit_start = pos;
            continue;
        }
        htable[h] = c_pos as i32;
        pos = core::add_sat_i64(pos, 1);
    }

    if lit_start < raw_content.len && cmds.len > 0 {
        let tail_cmd = core::BrotliLz77Cmd {
            ins_start: lit_start as u32,
            ins_len:   core::sub_sat_i64(raw_content.len, lit_start) as u32,
            copy_len:  2,
            distance:  1,
        };
        guard cmds.try_push(tail_cmd) else { return 0; }
    }
    return matched_bytes;
}

// Compresses a payload with Brotli using `dictionary_content` for RFC 9842 `dcb` encoding.
fn compress_dcb_payload<B>(
    raw_content:        const u8[:],
    dictionary_content: const u8[:],
    out_buf:            B&,
    level:              i32 = 1,
) -> bool {
    if dictionary_content.len < 4 || raw_content.len < 4 || raw_content.len > 16384 || level <= 0 {
        return core::brotli_compress(raw_content, out_buf, level);
    }
    var cmds: core::BrotliLz77Cmd[..512] = [];
    let matched = scan_dcb_dict_commands(dictionary_content, raw_content, cmds);
    if cmds.len == 0 || matched < 4 {
        return core::brotli_compress(raw_content, out_buf, 0);
    }
    var w = core::new_brotli_bit_writer();
    var dist_ring: u32[4] = [4, 11, 15, 16];
    core::emit_brotli_stream_header(w, out_buf);
    core::emit_brotli_compressed_chunk(w, raw_content, cmds[..], dist_ring, out_buf);
    core::emit_brotli_final_empty_metablock(w, out_buf);
    return true;
}

inline fn is_valid_sf_string_value(s: const u8[:]) -> bool {
    for b in s {
        if b < 0x20 || b >= 0x7F || b == '"' || b == '\\' {
            return false;
        }
    }
    return true;
}

// RFC 9842 Section 2.2 & Section 6: Negotiates Compression Dictionary Transport on an incoming `Request`
// by verifying `Available-Dictionary` (RFC 9651 `:base64:` byte sequence), `Dictionary-ID`, and `Accept-Encoding`
// (`dcz` or `dcb`), returning the negotiated Content-Encoding (`"dcz"` or `"dcb"`) and `ok == true`.
fn negotiate_compression_dictionary(
    req:           const http::Request&,
    expected_hash: const u8[32]&,
    expected_id:   const u8[:] = "",
) -> const u8[:], bool {
    guard expected_id.len <= 126 else { return "", false; }
    let avail_hdr = http::find_header(req.headers, "Available-Dictionary").trim_lws();
    let last_idx = core::sub_sat_i64(avail_hdr.len, 1);
    guard avail_hdr.len >= 3 && avail_hdr[0] == ':' && avail_hdr[last_idx] == ':' else {
        return "", false;
    }

    var expected_b64: u8[..64] = [];
    http::format_available_dictionary_header(expected_b64, expected_hash);
    guard core::ct_eq_bytes(avail_hdr, expected_b64[..]) else {
        return "", false;
    }

    let id_hdr = http::find_header(req.headers, "Dictionary-ID").trim_lws();
    if expected_id.len > 0 {
        var exp_id_wire: u8[..128] = [];
        http::format_dictionary_id_header(exp_id_wire, expected_id);
        guard id_hdr == exp_id_wire[..] else { return "", false; }
    } else {
        guard id_hdr.len == 0 else { return "", false; }
    }

    let ae = http::find_header(req.headers, "Accept-Encoding");
    if http::accept_encoding_has_token(ae, rfc::ENCODING_DCZ) {
        return rfc::ENCODING_DCZ, true;
    }
    if http::accept_encoding_has_token(ae, rfc::ENCODING_DCB) {
        return rfc::ENCODING_DCB, true;
    }
    return "", false;
}

// ---- http/digest_fields.goose internal helpers ----

inline fn compute_sha256_digest(data: const u8[:]) -> u8[..64] {
    var out: u8[..64] = [];
    let hash = core::sha256(data);
    out.append(hash[..]);
    return out;
}

inline fn compute_sha512_digest(data: const u8[:]) -> u8[..64] {
    var out: u8[..64] = [];
    let hash = core::sha512(data);
    out.append(hash[..]);
    return out;
}

// Computes raw RFC 9530 digest bytes (SHA-256 or SHA-512) returning bounded array via RVO.
//
// Example:
//   data = "hello world", alg = "sha-256"
//   returns: [185, 91, 154, ...], ok = true
fn compute_digest_bytes(data: const u8[:], alg: const u8[:]) -> u8[..64], bool {
    if alg.eq_ascii_fold(rfc::DIGEST_ALG_SHA256) {
        return compute_sha256_digest(data), true;
    }
    if alg.eq_ascii_fold(rfc::DIGEST_ALG_SHA512) {
        return compute_sha512_digest(data), true;
    }
    var empty: u8[..64] = [];
    return empty, false;
}

fn check_digest_match(expected_b64: const u8[:], alg: const u8[:], data: const u8[:]) -> bool {
    var expected_hash: u8[..64] = [];
    guard core::base64_decode(expected_b64, expected_hash) else { return false; }
    let computed_hash, ok_hash = compute_digest_bytes(data, alg);
    guard ok_hash else { return false; }
    guard computed_hash.len == expected_hash.len else { return false; }
    return core::ct_eq_bytes(computed_hash[..], expected_hash[..]);
}

fn verify_single_digest_entry(entry: const http::SfDictEntry&, data: const u8[:]) -> bool {
    guard entry.item.kind == http::SfType.Binary else { return false; }
    return check_digest_match(entry.item.str_val[..], entry.key[..], data);
}

// RFC 9530 Section 4: Integrity Preference Fields - Parse Want-*-Digest SF Dictionary weights (0..10).
fn accumulate_want_digest_weights(
    raw:   const u8[:],
    w_256: i64&,
    w_512: i64&,
) -> bool {
    guard raw.len > 0 else { return true; }
    var entries: http::SfDictEntry[..16] = [];
    guard http::parse_sf_dict(raw, entries) else { return false; }
    for &e in entries {
        guard !e.is_inner_list && e.item.kind == http::SfType.Integer &&
              e.item.int_val >= 0 && e.item.int_val <= 10 else {
            return false;
        }
        if e.key.eq_ascii_fold(rfc::DIGEST_ALG_SHA256) {
            w_256 = e.item.int_val;
        } else if e.key.eq_ascii_fold(rfc::DIGEST_ALG_SHA512) {
            w_512 = e.item.int_val;
        }
    }
    return true;
}

inline fn apply_streaming_digest_entry(v: http::StreamingDigestVerifier&, entry: const http::SfDictEntry&) -> bool {
    let is_sha256 = entry.key[..].eq_ascii_fold(rfc::DIGEST_ALG_SHA256);
    let is_sha512 = entry.key[..].eq_ascii_fold(rfc::DIGEST_ALG_SHA512);
    guard is_sha256 || is_sha512 else { return true; }
    guard entry.item.kind == http::SfType.Binary else { return false; }

    var decoded: u8[..64] = [];
    guard core::base64_decode(entry.item.str_val[..], decoded) else { return false; }
    let req_len: i64 = if is_sha512 { 64 } else { 32 };
    guard decoded.len == req_len else { return false; }

    if !v.is_valid_init || is_sha512 {
        v.algo = if is_sha512 { http::StreamingDigestAlgo.Sha512 } else { http::StreamingDigestAlgo.Sha256 };
        v.expected_hash.clear();
        v.expected_hash.append(decoded[..]);
        v.is_valid_init = true;
    }
    return true;
}

// ---- http/ohttp.goose internal helpers ----

// Suite restriction for this engine: DHKEM(X25519, HKDF-SHA256) paired with
// AES-128-GCM or ChaCha20-Poly1305 (RFC 9458 Section 4.3 selection rules).
fn ohttp_suite_supported(kem_id: u16, kdf_id: u16, aead_id: u16) -> bool {
    if kem_id != rfc::HPKE_KEM_DHKEM_X25519_HKDF_SHA256 {
        return false;
    }
    if kdf_id != rfc::HPKE_KDF_HKDF_SHA256 {
        return false;
    }
    return aead_id == rfc::HPKE_AEAD_AES_128_GCM || aead_id == rfc::HPKE_AEAD_CHACHA20_POLY1305;
}

// Builds the 7-byte message header hdr = key_id || kem_id || kdf_id || aead_id
// in network byte order (RFC 9458 Section 4.3 step 1).
fn ohttp_build_hdr(cfg: const http::OhttpKeyConfig&, out: u8[7]&) {
    out[0] = cfg.key_id;
    core::write_be_u16_at(out[..], 1, cfg.kem_id);
    core::write_be_u16_at(out[..], 3, cfg.kdf_id);
    core::write_be_u16_at(out[..], 5, cfg.aead_id);
}

// Builds info = "message/bhttp request" || 0x00 || hdr (RFC 9458 Section 4.3 step 2):
// 21-byte label + 1 zero byte + 7-byte hdr = 29 bytes (Appendix A info vector).
fn ohttp_request_info(hdr: const u8[:], out: u8[..30]&) -> bool {
    out.clear();
    out.append(rfc::OHTTP_INFO_REQUEST);
    out.push(0);
    out.append(hdr);
    return out.len == 29;
}

// Derives the response AEAD key and nonce (RFC 9458 Section 4.4 steps 1-5):
// secret = context.Export("message/bhttp response", max(Nn, Nk));
// prk = Extract(salt = enc || response_nonce, ikm = secret);
// key = Expand(prk, "key", Nk); nonce = Expand(prk, "nonce", Nn).
// Raw HKDF from RFC 5869, not TLS-style labeled expand.
fn ohttp_derive_response_aead(
    session:        const http::OhttpSession&,
    response_nonce: const u8[:],
    out_key:        u8[32]&,
    out_nonce:      u8[12]&,
) -> bool {
    let nk = session.ctx.key_len;
    let nn = session.ctx.nonce_len;
    let exp_len = max(nk, nn);
    guard nk > 0 && nk <= 32 && nn > 0 && nn <= 12 else { return false; }
    guard response_nonce.len == exp_len else { return false; }
    guard session.enc_len == 32 && session.enc.len == 32 else { return false; }

    var secret: u8[32] = [0; 32];
    guard security::hpke_export(session.ctx, rfc::OHTTP_INFO_RESPONSE, secret[..exp_len]) else { return false; }

    var salt: u8[..64] = [];
    salt.append(session.enc[..]);
    salt.append(response_nonce);
    let prk = core::hkdf_extract(salt[..], secret[..exp_len]);
    core::secure_zeroize_32(secret);

    let ok_k = core::hkdf_expand_bytes_256(prk[..], "key", nk, out_key[..nk]);
    let ok_n = core::hkdf_expand_bytes_256(prk[..], "nonce", nn, out_nonce[..nn]);
    core::secure_zeroize_32(prk);
    return ok_k && ok_n;
}

// Scans supported OHTTP symmetric suites and extracts the first supported pair (RFC 9458 §3.1).
//
// Example:
// RFC 9458 Section 3.1: Key Configuration Encoding - Select the first supported (KDF, AEAD) pair and skip unsupported pairs.
//
// Example:
//   raw = key_config_bytes, kem_id = 0x0020, sym_len = 4
//   returns: true, out_kdf = 0x0001, out_aead = 0x0001
fn scan_supported_ohttp_sym_suite(
    raw:      const u8[:],
    kem_id:   u16,
    sym_len:  u16,
    out_kdf:  u16&,
    out_aead: u16&,
) -> bool {
    let limit = sym_len as i64;
    let sym_end = core::add_sat_i64(37, limit);
    guard sym_end <= raw.len else { return false; }
    var cur = core::cursor_from(raw[37..sym_end]);
    while cur.buf.len >= 4 {
        let kdf, ok_kdf = cur.read_u16();
        let aead, ok_aead = cur.read_u16();
        guard ok_kdf && ok_aead else { return false; }
        if ohttp_suite_supported(kem_id, kdf, aead) {
            out_kdf = kdf;
            out_aead = aead;
            return true;
        }
    }
    return false;
}

fn ohttp_rfc9180_kem_pk_len(kem_id: u16) -> i64 {
    if kem_id == 0x0010 { return 65; }
    if kem_id == 0x0011 { return 97; }
    if kem_id == 0x0012 { return 133; }
    if kem_id == 0x0020 { return 32; }
    if kem_id == 0x0021 { return 56; }
    return 0;
}

// RFC 9458 Section 3.2: Key Configuration Media Type - Well-formed configs with unsupported KEM/AEAD are skipped.
fn is_skippable_ohttp_key_config(raw: const u8[:]) -> bool {
    var cur = core::cursor_from(raw);
    let _, ok_kid = cur.read_u8();
    let kem_id, ok_kem = cur.read_u16();
    let pk_len = ohttp_rfc9180_kem_pk_len(kem_id);
    guard ok_kid && ok_kem && pk_len > 0 else { return false; }
    let _, ok_pk = cur.read_bytes(pk_len);
    let sym_bytes, ok_sym = cur.read_u16_prefixed();
    return ok_pk && ok_sym && cur.buf.len == 0 && sym_bytes.len >= 4 && (sym_bytes.len & 3) == 0;
}
