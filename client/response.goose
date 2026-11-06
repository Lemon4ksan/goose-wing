// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP response representation, header inspectors, and JSON decoding (RFC 9110).
namespace wing;

import std;
import json;
import client.request;
import http.compression_dict;
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
    if eq_ascii_fold(stage, "transport") { return ErrorKind.Transport; }
    if eq_ascii_fold(stage, "tls") { return ErrorKind.Tls; }
    if eq_ascii_fold(stage, "mock") { return ErrorKind.Mock; }
    if eq_ascii_fold(stage, "ssrf_guard") { return ErrorKind.SsrfGuard; }
    if eq_ascii_fold(stage, "protocol") { return ErrorKind.Protocol; }
    if eq_ascii_fold(stage, "timeout") { return ErrorKind.Timeout; }
    if eq_ascii_fold(stage, "stream") { return ErrorKind.Stream; }
    if eq_ascii_fold(stage, "url") || eq_ascii_fold(stage, "invalid_url") { return ErrorKind.InvalidUrl; }
    if eq_ascii_fold(stage, "redirect") { return ErrorKind.Redirect; }
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
    status_code:    i32             = 0,
    effective_url:  u8[..2048]      = [],
    headers:        HeaderMap       = HeaderMap { .. },
    trailers:       HeaderMap       = HeaderMap { .. },
    presence_mask:  u16             = 0,
    redirect_count: i64             = 0,
    url_chain:      u8[..256][..16] = [],
    final_method:   u8[..16]        = "GET",
    protocol:       u8[..16]        = "HTTP/1.1",
    sent_headers:   HeaderMap       = HeaderMap { .. },
    body:           u8[>..]         = [],
}

fn reset_response(res: Response&) {
    res.status_code = rfc::STATUS_OK;
    res.effective_url.clear();
    res.headers.clear();
    res.trailers.clear();
    res.presence_mask = 0;
    res.redirect_count = 0;
    res.url_chain.clear();
    res.final_method.clear();
    res.final_method.append("GET");
    res.protocol.clear();
    res.protocol.append("HTTP/1.1");
    res.sent_headers.clear();
    res.body.clear();
}

fn protocol(res: const Response&) -> const u8[:] {
    return res.protocol[..];
}

fn is_http3(res: const Response&) -> bool {
    return res.protocol[..] == "h3" || res.protocol[..] == "HTTP/3";
}

fn is_http2(res: const Response&) -> bool {
    return res.protocol[..] == "h2" || res.protocol[..] == "HTTP/2";
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
    if core::eq_ascii_fold(name, "date") {
        res.presence_mask = res.presence_mask | RES_PRESENCE_DATE;
    } else if core::eq_ascii_fold(name, "content-length") {
        res.presence_mask = res.presence_mask | RES_PRESENCE_CONTENT_LENGTH;
    } else if core::eq_ascii_fold(name, "content-type") {
        res.presence_mask = res.presence_mask | RES_PRESENCE_CONTENT_TYPE;
    } else if core::eq_ascii_fold(name, "connection") {
        res.presence_mask = res.presence_mask | RES_PRESENCE_CONNECTION;
    } else if core::eq_ascii_fold(name, "transfer-encoding") {
        res.presence_mask = res.presence_mask | RES_PRESENCE_TRANSFER_ENCODING;
    } else if core::eq_ascii_fold(name, "server") {
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
        if core::eq_ascii_fold(name, "date") {
            res.presence_mask = res.presence_mask & (~RES_PRESENCE_DATE);
        } else if core::eq_ascii_fold(name, "content-length") {
            res.presence_mask = res.presence_mask & (~RES_PRESENCE_CONTENT_LENGTH);
        } else if core::eq_ascii_fold(name, "content-type") {
            res.presence_mask = res.presence_mask & (~RES_PRESENCE_CONTENT_TYPE);
        } else if core::eq_ascii_fold(name, "connection") {
            res.presence_mask = res.presence_mask & (~RES_PRESENCE_CONNECTION);
        } else if core::eq_ascii_fold(name, "transfer-encoding") {
            res.presence_mask = res.presence_mask & (~RES_PRESENCE_TRANSFER_ENCODING);
        } else if core::eq_ascii_fold(name, "server") {
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

// Automatically decompresses response.body if Content-Encoding is gzip or deflate.
// Replaces res.body in-place with decompressed bytes and clears the Content-Encoding header.
// Returns true if body was successfully decompressed or if uncompressed; false on corrupted stream.
//
// Example:
//   res.headers = [("content-encoding", "gzip")], res.body = <gzip_bytes>
//   returns: true, res.body = <decompressed_bytes>
fn decode_body(res: Response&) -> bool {
    let enc = header(res, "content-encoding");
    if eq_ascii_fold(enc, "zstd") {
        var uncompressed: u8[>..] = [];
        let ok_z, err_z = core::zstd_decompress(res.body[..], uncompressed);
        if ok_z {
            res.body.clear();
            res.body.append(uncompressed[..]);
            clear_decompressed_headers(res);
            return true;
        }
        return false;
    } else if eq_ascii_fold(enc, "gzip") {
        var uncompressed: u8[>..] = [];
        let ok_d, err = core::gzip_decompress(res.body[..], uncompressed);
        if ok_d {
            res.body.clear();
            res.body.append(uncompressed[..]);
            clear_decompressed_headers(res);
            return true;
        }
        return false;
    } else if eq_ascii_fold(enc, "br") {
        var uncompressed: u8[>..] = [];
        let ok_b, err_b = core::brotli_decompress(res.body[..], uncompressed);
        if ok_b {
            res.body.clear();
            res.body.append(uncompressed[..]);
            clear_decompressed_headers(res);
            return true;
        }
        return false;
    } else if eq_ascii_fold(enc, "deflate") {
        var uncompressed: u8[>..] = [];
        let ok_z, err_z = core::zlib_decompress(res.body[..], uncompressed);
        if ok_z {
            res.body.clear();
            res.body.append(uncompressed[..]);
            clear_decompressed_headers(res);
            return true;
        }
        uncompressed.clear();
        let ok_d, err_d = core::inflate(res.body[..], uncompressed);
        if ok_d {
            res.body.clear();
            res.body.append(uncompressed[..]);
            clear_decompressed_headers(res);
            return true;
        }
        return false;
    }
    return true;
}

// Automatically decompresses response.body, supporting standard encodings (gzip, deflate, zstd)
// as well as Chrome 123+ shared dictionary compression (dcz) using the client's dictionary cache.
//
// Example:
//   res.headers = [("content-encoding", "dcz")], res.body = <dcz_payload>
//   returns: true, res.body = <decompressed_bytes>
fn decode_body_with_dictionary(res: Response&, dict_cache: const DictionaryCache&) -> bool {
    let enc = header(res, "content-encoding");
    if eq_ascii_fold(enc, "dcz") {
        var dict_hash: u8[32] = [0; 32];
        let p_slice, ok_hdr = decode_dcz_header(res.body[..], dict_hash);
        guard ok_hdr else { return false; }

        var found = false;
        var decompressed: u8[>..] = [];
        for &entry in dict_cache.entries {
            if entry.valid && core::ct_eq_bytes(entry.sha256_hash[..], dict_hash[..]) {
                let ok_dec = decompress_dcz_payload(p_slice, entry.content[..], decompressed);
                guard ok_dec else { return false; }
                found = true;
                break;
            }
        }
        guard found else { return false; }

        res.body.clear();
        res.body.append(decompressed[..]);
        clear_decompressed_headers(res);
        return true;
    } else if eq_ascii_fold(enc, "dcb") {
        var dict_hash: u8[32] = [0; 32];
        let p_slice, ok_hdr = decode_dcb_header(res.body[..], dict_hash);
        guard ok_hdr else { return false; }

        var found = false;
        var decompressed: u8[>..] = [];
        for &entry in dict_cache.entries {
            if entry.valid && core::ct_eq_bytes(entry.sha256_hash[..], dict_hash[..]) {
                let ok_dec = decompress_dcb_payload(p_slice, entry.content[..], decompressed);
                guard ok_dec else { return false; }
                found = true;
                break;
            }
        }
        guard found else { return false; }

        res.body.clear();
        res.body.append(decompressed[..]);
        clear_decompressed_headers(res);
        return true;
    }
    return decode_body(res);
}

// ---- json reflection readers -----------------------------------------------

fn read_json_field(reader: json::Reader&, dst: i64&) {
    dst = json::read_int(reader);
}

fn read_json_field(reader: json::Reader&, dst: i32&) {
    dst = core::clamp_i64(json::read_int(reader), -2147483648, 2147483647) as! i32;
}

fn read_json_field(reader: json::Reader&, dst: f64&) {
    dst = json::read_number(reader);
}

fn read_json_field(reader: json::Reader&, dst: bool&) {
    dst = json::read_bool(reader);
}

fn read_json_field(reader: json::Reader&, dst) {
    var scratch: u8[>..] = [];
    let str_val = json::read_string(reader, scratch);
    dst.clear();
    let n = core::ct_min_i64(str_val.len, dst.cap);
    dst.append(str_val[..n]);
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
