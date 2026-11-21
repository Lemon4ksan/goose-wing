// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP response representation, header inspectors, and JSON decoding (RFC 9110).
namespace http;

import std;
import core;
import json;
import .request;
import http.compression_dict;
import http.early_hints;
import http.headers;
import http.internal;

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

fn make_error(code: i32, stage: const u8[:], message: const u8[:], kind: ErrorKind = ErrorKind.None) -> Error {
    let resolved_kind = if kind != ErrorKind.None { kind } else { http_internal::error_stage_to_kind(stage) };
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
    status_code:        i32                = 0,
    effective_url:      u8[..2048]         = [],
    headers:            HeaderMap          = HeaderMap { .. },
    trailers:           HeaderMap          = HeaderMap { .. },
    presence_mask:      u16                = 0,
    redirect_count:     i64                = 0,
    url_chain:          u8[..256][..16]    = [],
    final_method:       u8[..16]           = "GET",
    protocol:           u8[..16]           = "HTTP/1.1",
    sent_headers:       HeaderMap          = HeaderMap { .. },
    early_hints:        EarlyHintsResponse = EarlyHintsResponse { .. },
    had_te_cl_conflict: bool               = false,
    body:               u8[>..]            = [],
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
    res.had_te_cl_conflict = false;
    res.body.clear();
}

enum HttpVersion {
    Unknown,
    Http10,
    Http11,
    Http2,
    Http3,
}

fn protocol(res: const Response&) -> const u8[:] {
    return res.protocol[..];
}

fn http_version(res: const Response&) -> HttpVersion {
    return http_internal::parse_http_version(protocol(res));
}

fn is_http3(res: const Response&) -> bool {
    return res.http_version() == HttpVersion.Http3;
}

fn is_http1(res: const Response&) -> bool {
    let ver = res.http_version();
    return ver == HttpVersion.Http10 || ver == HttpVersion.Http11;
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
    guard is_valid_header_name(name) && is_valid_header_value(value) && !rfc::is_disallowed_trailer_field(name) else {
        return;
    }
    set_header(res.trailers, name, value, false);
}

fn update_response_presence(res: Response&, name: const u8[:]) {
    let bit = http_internal::classify_response_presence_bit(name);
    if bit != 0 {
        res.presence_mask = res.presence_mask | bit;
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
        let bit = http_internal::classify_response_presence_bit(name);
        if bit != 0 {
            res.presence_mask = res.presence_mask & (~bit);
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
    var committed = false;
    defer if !committed { out_tokens.clear(); };
    var rem = enc_hdr.trim_lws();
    if rem.len == 0 {
        committed = true;
        return true;
    }
    while rem.len > 0 {
        let head, tail, has_comma = rem.split_once_byte(',');
        let tok = head.trim_lws();
        guard http_internal::is_valid_coding_token(tok) else { return false; }
        var item: u8[..16] = [];
        guard item.try_set(tok) && out_tokens.try_push(item) else { return false; }
        if !has_comma { break; }
        rem = tail.trim_lws();
        guard rem.len > 0 else { return false; }
    }
    committed = true;
    return true;
}

fn find_matching_dict_entry(
    dict_cache: const DictionaryCache&,
    dict_hash:  const u8[:],
    eff_url:    const u8[:] = "",
    now_sec:    i64         = 0,
) -> i64 {
    for &entry, idx in dict_cache.entries {
        if core::ct_eq_bytes(entry.sha256_hash[..], dict_hash) &&
            http_internal::dict_entry_matches_response_origin(entry, eff_url, now_sec) {
            return idx;
        }
    }
    return -1;
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
    let saved_body = copy(res.body);
    var committed = false;
    defer if !committed { res.body = copy(saved_body); };
    var rev_idx = tokens.len;
    while rev_idx > 0 {
        rev_idx = core::sub_sat_i64(rev_idx, 1);
        guard http_internal::decode_single_standard_encoding(tokens[rev_idx][..], res) else { return false; }
    }
    committed = true;
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
fn decode_body_with_dictionary(
    res:        Response&,
    dict_cache: const DictionaryCache&,
    now_sec:    i64 = 0,
) -> bool {
    let enc = header(res, "content-encoding");
    guard enc.len > 0 else { return true; }
    if res.body.len == 0 && rfc::is_empty_body_status(res.status_code) {
        clear_decompressed_headers(res);
        return true;
    }
    var tokens: u8[..16][..4] = [];
    guard parse_content_encoding_chain(enc, tokens) else { return false; }
    let saved_body = copy(res.body);
    var committed = false;
    defer if !committed { res.body = copy(saved_body); };
    var rev_idx = tokens.len;
    while rev_idx > 0 {
        rev_idx = core::sub_sat_i64(rev_idx, 1);
        guard http_internal::decode_single_dict_encoding(
            tokens[rev_idx][..], res, dict_cache, now_sec,
        ) else {
            return false;
        }
    }
    committed = true;
    clear_decompressed_headers(res);
    return true;
}

enum ErrorBodyDecompressMode {
    Skip4xxAnd5xx,
    DecompressAll,
}

struct DecompressGuardPolicy {
    max_decompressed_bytes: u64                     = 16777216,
    error_mode:             ErrorBodyDecompressMode = ErrorBodyDecompressMode.Skip4xxAnd5xx,
}

// Determines whether a client HTTP response body should be automatically decompressed (RFC 9110 Section 8.4).
// Skips decompression for `HEAD` requests, status codes without a message body (`1xx`, `204`, `304`),
// and `4xx`/`5xx` error responses when `policy.error_mode == ErrorBodyDecompressMode.Skip4xxAnd5xx`.
fn should_auto_decompress(
    method: const u8[:],
    status: i32,
    policy: const DecompressGuardPolicy&,
) -> bool {
    guard policy.max_decompressed_bytes > 0 else { return false; }
    guard !method.eq_ascii_fold("HEAD") else { return false; }
    guard status >= rfc::STATUS_OK && !rfc::is_empty_body_status(status) else { return false; }
    if policy.error_mode == ErrorBodyDecompressMode.Skip4xxAnd5xx && status >= rfc::STATUS_BAD_REQUEST {
        return false;
    }
    return true;
}

// ---- json reflection readers -----------------------------------------------

// ---- json response decoding -------------------------------------------------

fn json<T>(res: const Response&, out: T&) -> Error {
    let saved = copy(out);
    var committed = false;
    defer if !committed { out = copy(saved); };
    var reader = json::reader(res.body[..]);
    json::each_member(reader) { key =>
        var matched = false;
        const for <Name, Acc> in fields<T> {
            if !matched && key == Name {
                http_internal::read_json_field(reader, out.Acc);
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
    committed = true;
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
        http_internal::write_json_field(res.body, payload.Acc);
    }
    res.body.push('}');
}

// Populates an HTTP response with an HTML body and `text/html; charset=utf-8` Content-Type header.
fn respond_html(res: Response&, status_code: i32, html_str: const u8[:]) {
    res.status_code = status_code;
    set_header(res, "Content-Type", "text/html; charset=utf-8");
    res.body.clear();
    res.body.append(html_str);
}

// Populates an HTTP response with a binary payload and `Content-Type` header.
fn respond_bytes(
    res:          Response&,
    status_code:  i32,
    raw_bytes:    const u8[:],
    content_type: const u8[:] = "application/octet-stream",
) {
    res.status_code = status_code;
    set_header(res, "Content-Type", content_type);
    res.body.clear();
    res.body.append(raw_bytes);
}

// Populates a `204 No Content` HTTP response with an empty body (RFC 9110 Section 15.3.5).
fn respond_no_content(res: Response&) {
    res.status_code = rfc::STATUS_NO_CONTENT;
    res.body.clear();
    let _ = remove_header(res, "Content-Type");
    let _ = remove_header(res, "Content-Length");
    if res.is_http1() {
        let _ = remove_header(res, "Transfer-Encoding");
    }
}

// Populates a `404 Not Found` plain-text HTTP response.
fn respond_not_found(res: Response&, message: const u8[:] = "Not Found") {
    respond_text(res, rfc::STATUS_NOT_FOUND, message);
}

// Populates `res` as an HTTP redirect (`301`, `302`, `303`, `307`, `308`) with a CRLF-validated `Location` header.
fn respond_redirect(
    res:         Response&,
    location:    const u8[:],
    status_code: i32 = rfc::STATUS_FOUND,
) -> bool {
    guard rfc::is_redirect_status(status_code) && location.len > 0 else { return false; }
    for b in location {
        guard b >= 0x20 && b != 0x7F else { return false; }
    }
    res.status_code = status_code;
    set_header(res, "Location", location);
    res.body.clear();
    return true;
}

// Appends `field_name` to the `Vary` response header without duplicating
// existing case-insensitive tokens (RFC 9110 Section 12.5.5).
fn append_vary(res: Response&, field_name: const u8[:]) -> bool {
    let clean = field_name.trim_lws();
    guard clean.len > 0 else { return false; }
    if clean != "*" {
        for b in clean {
            guard core::is_tchar(b) else { return false; }
        }
    }
    let existing = header(res, "Vary").trim_lws();
    if existing == "*" || http_internal::vary_list_contains_token(existing, clean) {
        return true;
    }
    if clean == "*" || existing.len == 0 {
        set_header(res, "Vary", clean);
        return true;
    }
    var combined: u8[..256] = [];
    guard combined.try_append(existing) && combined.try_append(", ") && combined.try_append(clean) else {
        return false;
    }
    set_header(res, "Vary", combined[..]);
    return true;
}
