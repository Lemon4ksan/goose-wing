// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP response representation, header inspectors, and JSON decoding (RFC 9110).
namespace wing;

import std;
import core from "..";
import json;
import client.request;
import http.compression_dict;
import http.early_hints;
import http.headers;

// ---- error model & diagnostics ---------------------------------------------

enum ErrorKind {
    None,
    Transport,
    Tls,
    Mock,
    SsrfGuard,
    Protocol,
    Timeout,
    Stream,
    InvalidUrl,
    Redirect,
}

struct Error {
    kind:    ErrorKind = ErrorKind.None,
    code:    i32       = 0,
    stage:   u8[..64]  = [],
    message: u8[..256] = [],
}

fn error_stage_to_kind(stage: const u8[:]) -> ErrorKind {
    if stage.eq_ascii_fold("transport") { return ErrorKind.Transport; }
    if stage.eq_ascii_fold("tls") { return ErrorKind.Tls; }
    if stage.eq_ascii_fold("mock") { return ErrorKind.Mock; }
    if stage.eq_ascii_fold("ssrf_guard") { return ErrorKind.SsrfGuard; }
    if stage.eq_ascii_fold("protocol") { return ErrorKind.Protocol; }
    if stage.eq_ascii_fold("timeout") { return ErrorKind.Timeout; }
    if stage.eq_ascii_fold("stream") { return ErrorKind.Stream; }
    if stage.eq_ascii_fold("url") || stage.eq_ascii_fold("invalid_url") { return ErrorKind.InvalidUrl; }
    if stage.eq_ascii_fold("redirect") { return ErrorKind.Redirect; }
    return ErrorKind.None;
}

fn make_error(code: i32, stage: const u8[:], message: const u8[:], kind: ErrorKind = ErrorKind.None) -> Error {
    let resolved_kind = if kind != ErrorKind.None { kind } else { error_stage_to_kind(stage) };
    var err = Error { kind: resolved_kind, code: code, .. };
    err.stage.append(stage);
    err.message.append(message);
    return err;
}

fn ok(err: const Error&) -> bool {
    return err.code == 0 && err.kind == ErrorKind.None;
}

// RFC 9110 §15.2 & Go #65035: Validates that consecutive informational 1xx responses
// do not exceed the configured threshold (default: 5) to prevent infinite loops.
fn validate_informational_response_count(count: i32, max_limit: i32 = 5) -> bool {
    guard count >= 0 && count <= max_limit else { return false; }
    return true;
}

// ---- response model & inspectors -------------------------------------------

const RES_PRESENCE_DATE:              u16 = 1 << 0;
const RES_PRESENCE_CONTENT_LENGTH:    u16 = 1 << 1;
const RES_PRESENCE_CONTENT_TYPE:      u16 = 1 << 2;
const RES_PRESENCE_CONNECTION:        u16 = 1 << 3;
const RES_PRESENCE_TRANSFER_ENCODING: u16 = 1 << 4;
const RES_PRESENCE_SERVER:            u16 = 1 << 5;

struct Response {
    status_code:    i32                = 0,
    effective_url:  u8[..2048]         = [],
    headers:        HeaderMap          = HeaderMap { .. },
    trailers:       HeaderMap          = HeaderMap { .. },
    presence_mask:  u16                = 0,
    redirect_count: i64                = 0,
    url_chain:      u8[..256][..16]    = [],
    final_method:   u8[..16]           = "GET",
    protocol:       u8[..16]           = "HTTP/1.1",
    sent_headers:   HeaderMap          = HeaderMap { .. },
    early_hints:    EarlyHintsResponse = EarlyHintsResponse { .. },
    body:           u8[>..]            = [],
}

fn reset_response(res: Response&) {
    res.status_code = rfc::STATUS_OK;
    res.effective_url.clear();
    res.headers.clear();
    res.trailers.clear();
    res.presence_mask = 0;
    res.early_hints = EarlyHintsResponse { .. };
    res.redirect_count = 0;
    res.url_chain.clear();
    let _ = res.final_method.try_set("GET");
    let _ = res.protocol.try_set("HTTP/1.1");
    res.sent_headers.clear();
    res.body.clear();
}

fn protocol(res: const Response&) -> const u8[:] {
    return res.protocol[..];
}

fn is_http3(res: const Response&) -> bool {
    return res.protocol[..] == "h3" || res.protocol[..] == "HTTP/3";
}

fn is_http1(res: const Response&) -> bool {
    return res.protocol[..] == "HTTP/1.1" || res.protocol[..] == "HTTP/1.0" || res.protocol[..] == "h1";
}

// Returns true if the HTTP response status code is within the 2xx Successful range [200, 299] (RFC 9110 Section 15.3).
fn is_success(res: const Response&) -> bool {
    return res.status_code >= rfc::STATUS_OK && res.status_code < 300;
}

fn status(res: const Response&) -> i32 {
    return res.status_code;
}

// Returns true if the HTTP response status code indicates a redirect (RFC 9110 Section 15.4):
// 301, 302, 303, 307, or 308.
fn is_redirect(res: const Response&) -> bool {
    return rfc::is_redirect_status(res.status_code);
}

fn header(res: const Response&, name: const u8[:]) -> const u8[:] {
    return get_header(res.headers, name);
}

fn has_header(res: const Response&, name: const u8[:]) -> bool {
    return has_header(res.headers, name);
}

// Returns the value of a response trailer by name (case-insensitive lookup)
fn trailer(res: const Response&, name: const u8[:]) -> const u8[:] {
    return get_header(res.trailers, name);
}

fn has_trailer(res: const Response&, name: const u8[:]) -> bool {
    return has_header(res.trailers, name);
}

fn add_trailer(res: Response&, name: const u8[:], value: const u8[:]) {
    guard !rfc::is_disallowed_trailer_field(name) else { return; }
    set_header(res.trailers, name, value, false);
}

fn update_response_presence(res: Response&, name: const u8[:]) {
    if name.eq_ascii_fold("date") {
        res.presence_mask = res.presence_mask | RES_PRESENCE_DATE;
    } else if name.eq_ascii_fold("content-length") {
        res.presence_mask = res.presence_mask | RES_PRESENCE_CONTENT_LENGTH;
    } else if name.eq_ascii_fold("content-type") {
        res.presence_mask = res.presence_mask | RES_PRESENCE_CONTENT_TYPE;
    } else if name.eq_ascii_fold("connection") {
        res.presence_mask = res.presence_mask | RES_PRESENCE_CONNECTION;
    } else if name.eq_ascii_fold("transfer-encoding") {
        res.presence_mask = res.presence_mask | RES_PRESENCE_TRANSFER_ENCODING;
    } else if name.eq_ascii_fold("server") {
        res.presence_mask = res.presence_mask | RES_PRESENCE_SERVER;
    }
}

fn set_header(res: Response&, name: const u8[:], value: const u8[:]) {
    set_header(res.headers, name, value, false);
    if has_header(res.headers, name) {
        update_response_presence(res, name);
    }
}

fn remove_header(res: Response&, name: const u8[:]) -> bool {
    let removed = remove_header(res.headers, name);
    if removed {
        if name.eq_ascii_fold("date") {
            res.presence_mask = res.presence_mask & (~RES_PRESENCE_DATE);
        } else if name.eq_ascii_fold("content-length") {
            res.presence_mask = res.presence_mask & (~RES_PRESENCE_CONTENT_LENGTH);
        } else if name.eq_ascii_fold("content-type") {
            res.presence_mask = res.presence_mask & (~RES_PRESENCE_CONTENT_TYPE);
        } else if name.eq_ascii_fold("connection") {
            res.presence_mask = res.presence_mask & (~RES_PRESENCE_CONNECTION);
        } else if name.eq_ascii_fold("transfer-encoding") {
            res.presence_mask = res.presence_mask & (~RES_PRESENCE_TRANSFER_ENCODING);
        } else if name.eq_ascii_fold("server") {
            res.presence_mask = res.presence_mask & (~RES_PRESENCE_SERVER);
        }
    }
    return removed;
}

fn sent_header(res: const Response&, name: const u8[:]) -> const u8[:] {
    return get_header(res.sent_headers, name);
}

fn has_sent_header(res: const Response&, name: const u8[:]) -> bool {
    return has_header(res.sent_headers, name);
}

fn text(res: const Response&) -> const u8[:] {
    return res.body[..];
}

fn clear_decompressed_headers(res: Response&) {
    let _ = remove_header(res.headers, "content-encoding");
    let _ = remove_header(res.headers, "content-length");
    res.presence_mask = res.presence_mask & (~RES_PRESENCE_CONTENT_LENGTH);
}

// Parses a comma-separated Content-Encoding header into up to 4 ordered tokens (RFC 9110 §8.4).
//
// Example:
//   enc_hdr = "deflate, gzip"
//   returns: ok = true, out_tokens = ["deflate", "gzip"]
fn parse_content_encoding_chain(
    enc_hdr:    const u8[:],
    out_tokens: u8[..16][..4]&,
) -> bool {
    out_tokens.clear();
    var rem = enc_hdr.trim_lws();
    guard rem.len > 0 else { return true; }
    while rem.len > 0 {
        let head, tail, has_comma = rem.split_once_byte(',');
        let tok = head.trim_lws();
        guard tok.len > 0 else { return false; }
        var item: u8[..16] = [];
        guard item.try_set(tok) && out_tokens.try_push(item) else { return false; }
        if !has_comma { break; }
        rem = tail.trim_lws();
        guard rem.len > 0 else { return false; }
    }
    return true;
}

// Decodes a single standard Content-Encoding layer (`identity`, `zstd`, `gzip`, `br`, `deflate`) in place.
//
// Example:
//   tok = "gzip", res.body = <gzipped "ok">
//   returns: true, res.body = "ok"
fn decode_single_standard_encoding(tok: const u8[:], res: Response&) -> bool {
    if tok.eq_ascii_fold("identity") {
        return true;
    }
    if tok.eq_ascii_fold("zstd") {
        var uncompressed: u8[>..] = [];
        let ok_z, _ = core::zstd_decompress(res.body[..], uncompressed);
        guard ok_z else { return false; }
        res.body.clear();
        res.body.append(uncompressed[..]);
        return true;
    }
    if tok.eq_ascii_fold("gzip") || tok.eq_ascii_fold("x-gzip") {
        var uncompressed: u8[>..] = [];
        let ok_d, _ = core::gzip_decompress(res.body[..], uncompressed);
        guard ok_d else { return false; }
        res.body.clear();
        res.body.append(uncompressed[..]);
        return true;
    }
    if tok.eq_ascii_fold("br") {
        var uncompressed: u8[>..] = [];
        let ok_b, _ = core::brotli_decompress(res.body[..], uncompressed);
        guard ok_b else { return false; }
        res.body.clear();
        res.body.append(uncompressed[..]);
        return true;
    }
    if tok.eq_ascii_fold("deflate") {
        var uncompressed: u8[>..] = [];
        let ok_z, _ = core::zlib_decompress(res.body[..], uncompressed);
        if ok_z {
            res.body.clear();
            res.body.append(uncompressed[..]);
            return true;
        }
        uncompressed.clear();
        let ok_d, _ = core::inflate(res.body[..], uncompressed);
        guard ok_d else { return false; }
        res.body.clear();
        res.body.append(uncompressed[..]);
        return true;
    }
    return true;
}

fn find_matching_dict_entry(
    dict_cache: const DictionaryCache&,
    dict_hash:  const u8[:],
) -> i64 {
    for &entry, idx in dict_cache.entries {
        if entry.valid && core::ct_eq_bytes(entry.sha256_hash[..], dict_hash) {
            return idx;
        }
    }
    return -1;
}

// Decodes a single RFC 9842 shared-dictionary Content-Encoding layer (`dcz` or `dcb`) in place.
//
// Example:
//   tok = "dcz", res.body = <40-byte DCZ header + zstd frame>
//   returns: true, res.body = <decompressed payload>
fn decode_single_dict_encoding(
    tok:        const u8[:],
    res:        Response&,
    dict_cache: const DictionaryCache&,
) -> bool {
    if tok.eq_ascii_fold("dcz") {
        var dict_hash: u8[32] = [0; 32];
        let p_slice, ok_hdr = decode_dcz_header(res.body[..], dict_hash);
        guard ok_hdr else { return false; }
        let idx = find_matching_dict_entry(dict_cache, dict_hash[..]);
        guard idx >= 0 && idx < dict_cache.entries.len else { return false; }
        var decompressed: u8[>..] = [];
        guard decompress_dcz_payload(p_slice, dict_cache.entries[idx].content[..], decompressed) else { return false; }
        res.body.clear();
        res.body.append(decompressed[..]);
        return true;
    }
    if tok.eq_ascii_fold("dcb") {
        var dict_hash: u8[32] = [0; 32];
        let p_slice, ok_hdr = decode_dcb_header(res.body[..], dict_hash);
        guard ok_hdr else { return false; }
        let idx = find_matching_dict_entry(dict_cache, dict_hash[..]);
        guard idx >= 0 && idx < dict_cache.entries.len else { return false; }
        var decompressed: u8[>..] = [];
        guard decompress_dcb_payload(p_slice, dict_cache.entries[idx].content[..], decompressed) else { return false; }
        res.body.clear();
        res.body.append(decompressed[..]);
        return true;
    }
    return decode_single_standard_encoding(tok, res);
}

// Automatically decompresses response.body across single or multi-token Content-Encoding chains
// in reverse application order (RFC 9110 §8.4: gzip, x-gzip, deflate, br, zstd, identity).
// Replaces res.body in-place with decompressed bytes and clears the Content-Encoding header.
//
// Example:
//   res.headers = [("content-encoding", "gzip")], res.body = <gzip_bytes>
//   returns: true, res.body = <decompressed_bytes>
fn decode_body(res: Response&) -> bool {
    let enc = header(res, "content-encoding");
    guard enc.len > 0 else { return true; }
    if res.body.len == 0 && rfc::is_empty_body_status(res.status_code) {
        clear_decompressed_headers(res);
        return true;
    }
    var tokens: u8[..16][..4] = [];
    guard parse_content_encoding_chain(enc, tokens) else { return false; }
    var rev_idx = tokens.len;
    while rev_idx > 0 {
        rev_idx = core::sub_sat_i64(rev_idx, 1);
        guard decode_single_standard_encoding(tokens[rev_idx][..], res) else { return false; }
    }
    clear_decompressed_headers(res);
    return true;
}

// Automatically decompresses response.body across single or multi-token Content-Encoding chains,
// supporting standard encodings (gzip, deflate, br, zstd) and Chrome 123+ shared dictionary
// encodings (dcz, dcb) in reverse application order (RFC 9110 §8.4, RFC 9842).
//
// Example:
//   res.headers = [("content-encoding", "dcz")], res.body = <dcz_payload>
//   returns: true, res.body = <decompressed_bytes>
fn decode_body_with_dictionary(res: Response&, dict_cache: const DictionaryCache&) -> bool {
    let enc = header(res, "content-encoding");
    guard enc.len > 0 else { return true; }
    if res.body.len == 0 && rfc::is_empty_body_status(res.status_code) {
        clear_decompressed_headers(res);
        return true;
    }
    var tokens: u8[..16][..4] = [];
    guard parse_content_encoding_chain(enc, tokens) else { return false; }
    var rev_idx = tokens.len;
    while rev_idx > 0 {
        rev_idx = core::sub_sat_i64(rev_idx, 1);
        guard decode_single_dict_encoding(tokens[rev_idx][..], res, dict_cache) else { return false; }
    }
    clear_decompressed_headers(res);
    return true;
}

// ---- json reflection readers -----------------------------------------------

fn read_json_field(reader: json::Reader&, dst: i64&) {
    dst = json::read_int(reader);
}

fn read_json_field(reader: json::Reader&, dst: i32&) {
    dst = core::clamp_i64(json::read_int(reader), -2147483648, 2147483647) as i32;
}

fn read_json_field(reader: json::Reader&, dst: f64&) {
    dst = json::read_number(reader);
}

fn read_json_field(reader: json::Reader&, dst: bool&) {
    dst = json::read_bool(reader);
}

fn read_json_field(reader: json::Reader&, dst) {
    dst.clear();
    guard json::peek(reader) == '"' else {
        json::fail(reader, "expected a string");
        return;
    }
    let start = core::add_sat_i64(reader.pos, 1);
    let end, escaped = json::scan_string(reader.text, start);
    guard end >= 0 else {
        json::fail(reader, "bad string");
        return;
    }
    reader.pos = core::add_sat_i64(end, 1);
    if !escaped {
        let raw = reader.text[start..end];
        let n = min(raw.len, dst.cap);
        dst.append(raw[..n]);
        return;
    }
    if !core::decode_json_string_into(reader.text, start, end, dst) && !json::valid_escapes(reader.text, start, end) {
        reader.pos = core::sub_sat_i64(start, 1);
        json::fail(reader, "bad escape");
    }
}

// ---- json response decoding -------------------------------------------------

fn json<T>(res: const Response&, out: T&) -> Error {
    var reader = json::reader(res.body[..]);
    json::each_member(reader) { key =>
        var matched = false;
        const for <Name, Acc> in fields<T> {
            if !matched && key == Name {
                read_json_field(reader, &out.Acc);
                matched = true;
            }
        }
        if !matched {
            json::skip(reader);
        }
    };
    if !json::finish(reader) {
        let msg = json::message(reader);
        return make_error(rfc::STATUS_UNPROCESSABLE_CONTENT, "json_decode", msg[..]);
    }
    return Error { .. };
}

// Decodes JSON response body into target struct T.
//
// Example:
//   res.body = "{\"status\":\"ok\"}"
//   returns: out = T { status = "ok" }, err.code = 0
fn decode_json<T>(res: const Response&) -> T, Error {
    var out = T { .. };
    let err = json(res, out);
    return out, err;
}

// ---- response builders -----------------------------------------------------

// Populates an HTTP response with a plain-text body and Content-Type header.
fn respond_text(res: Response&, status_code: i32, body_str: const u8[:]) {
    res.status_code = status_code;
    set_header(res, "Content-Type", "text/plain; charset=utf-8");
    res.body.clear();
    res.body.append(body_str);
}

// Populates an HTTP response with a pre-serialized JSON string and Content-Type header.
fn respond_json_str(res: Response&, status_code: i32, json_str: const u8[:]) {
    res.status_code = status_code;
    set_header(res, "Content-Type", "application/json");
    res.body.clear();
    res.body.append(json_str);
}

// Serializes struct `payload` as a JSON object into the HTTP response body.
fn respond_json<T>(res: Response&, status_code: i32, payload: const T&) {
    res.status_code = status_code;
    set_header(res, "Content-Type", "application/json");
    res.body.clear();
    res.body.push('{');
    var first = true;
    const for <Name, Acc> in fields<T> {
        if !first { res.body.push(','); }
        first = false;
        json::format_key(res.body, Name);
        write_json_field(res.body, payload.Acc);
    }
    res.body.push('}');
}
