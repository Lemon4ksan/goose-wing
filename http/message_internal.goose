// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for `http` (http/message_internal.goose).
namespace http_internal;

import std;
import core;
import cookie.policy;
import http.bind;
import http.compression_dict;
import http.early_hints;
import http.headers;
import http.incremental;
import http.json_codec;
import http.mime;
import http.priority;
import http.problem;
import http.request;
import http.response;
import http.trace;
import json;

// ---- http/bind.goose internal helpers ----

// Converts a `snake_case` struct field name into a lowercase hyphenated HTTP header name.
// Rolls back `out` on capacity overflow.
//
// Example:
//   field_name = "x_request_id"
//   returns: true, out = "x-request-id"
fn normalize_field_to_header_name<B>(field_name: const u8[:], out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    out.clear();
    guard field_name.len > 0 else { return false; }
    for b in field_name {
        let lower_b: u8 = core::to_lower_ascii_byte(b);
        let mapped:  u8 = if b == '_' { '-' } else { lower_b };
        guard out.try_push(mapped) else { return false; }
    }
    committed = true;
    return true;
}

// Extracts the raw value of cookie `target_name` from an RFC 6265 `Cookie` request header.
// Strips optional surrounding double quotes.
//
// Example:
//   cookie_hdr = "theme=dark; sid=\"abc123\"", target_name = "sid"
//   returns: "abc123", true
fn find_raw_cookie_value(
    cookie_hdr:  const u8[:],
    target_name: const u8[:],
) -> const u8[:], bool {
    guard cookie_hdr.len > 0 && target_name.len > 0 else { return "", false; }
    var tok = core::make_byte_tokenizer(cookie_hdr, ';');
    while true {
        let seg, ok = core::token_next(tok);
        if !ok { break; }
        let k, v, has_eq = seg.trim_lws().split_once_byte('=');
        if has_eq && k.trim_lws() == target_name {
            return v.trim_lws().trim_byte('"'), true;
        }
    }
    return "", false;
}

// Extracts a Bearer credential token from an RFC 6750 `Authorization` header value.
// Returns `("", false)` when the scheme prefix is missing or the token is empty or contains CTL/whitespace.
//
// Example:
//   auth_hdr = "bearer  abc.def.ghi "
//   returns: "abc.def.ghi", true
fn extract_bearer_token(auth_hdr: const u8[:]) -> const u8[:], bool {
    let after_scheme, has_prefix = auth_hdr.trim_lws().strip_prefix_fold("Bearer ");
    guard has_prefix else { return "", false; }
    let tok = after_scheme.trim_lws();
    guard tok.len > 0 else { return "", false; }
    for b in tok {
        guard b > 0x20 && b < 0x7F else { return "", false; }
    }
    return tok, true;
}

// Dispatches a single JSON object key to the matching JSON-body field in `out` via `const for`.
// Non-body ingestion wrappers (`Path`, `Query`, `Header`, `Cookie`, `Bearer`, `ClientIp`) are skipped
// so crafted JSON payloads cannot overwrite routed or authenticated metadata.
fn bind_json_member<T>(
    key:    const u8[:],
    reader: json::Reader&,
    out:    T&,
    vp:     http::ValidationProblem&,
) -> bool {
    var matched = false;
    var field_ok = true;
    const for <Name, Acc> in fields<T> {
        if !matched && key == Name {
            matched = true;
            if http::field_ingest_source_kind(out.Acc) == http::INGEST_SRC_JSON_BODY {
                http::decode_json_field_val(out.Acc, reader);
                let ok_read = reader.error.len == 0;
                let loc = http::ValidationLocation.Body;
                let msg = "invalid JSON field value";
                let ok_chk = http::check_field(vp, ok_read, loc, Name, "invalid_json_field", msg);
                field_ok = field_ok && ok_chk;
            } else {
                json::skip(reader);
            }
        }
    }
    if !matched {
        json::skip(reader);
    }
    return field_ok;
}

// ---- http/mime.goose internal helpers ----

fn has_param_name(params: const http::MediaTypeParam[..16]&, name: const u8[:]) -> bool {
    for &p in params {
        if p.name[..] == name {
            return true;
        }
    }
    return false;
}

// RFC 9110 Section 5.6.6: Parameters - Decodes a parameter-value (token / quoted-string) into out.
//
// Example:
//   raw_val = "\"utf-8\"", out = []
//   returns: true, out = "utf-8"
fn decode_token_or_quoted_param<B>(raw_val: const u8[:], out: B&, max_len: i64 = 256) -> bool {
    guard raw_val.len > 0 else { return false; }
    if raw_val[0] == '"' {
        return http::strict_unquote(raw_val, out, max_len);
    }
    guard raw_val.len <= max_len && http::is_valid_header_name(raw_val) && out.try_append(raw_val) else {
        return false;
    }
    return true;
}

// Parses a single MIME media parameter (RFC 9110 Section 5.6.6 & Section 8.3).
//
// Example:
//   p_trim = "charset=\"utf-8\"", p_item = MediaTypeParam { .. }
//   returns: true, p_item.name = "charset", p_item.value = "utf-8"
fn parse_single_media_param(p_trim: const u8[:], p_item: http::MediaTypeParam&) -> bool {
    p_item.name.clear();
    p_item.value.clear();
    var committed = false;
    defer if !committed {
        p_item.name.clear();
        p_item.value.clear();
    };

    let p_name, p_val_raw, ok = p_trim.split_once_byte('=');
    guard ok && http::is_valid_header_name(p_name) && p_item.name.try_append(p_name) else {
        return false;
    }
    to_lower(p_item.name[..]);
    guard decode_token_or_quoted_param(p_val_raw, p_item.value, 256) else {
        return false;
    }
    committed = true;
    return true;
}

// Parses semicolon-separated MIME parameters (RFC 9110 Section 8.3).
//
// Example:
//   rem_in = "; charset=utf-8; boundary=something", mt = MediaType { .. }
//   returns: true, populates mt.params
fn parse_media_parameters(rem_in: const u8[:], mt: http::MediaType&) -> bool {
    var rem = rem_in;
    while rem.len > 0 {
        let param_token, next_rem, _ = rem.split_once_unquoted_byte(';');
        rem = next_rem;

        let p_trim = param_token.trim_lws();
        if p_trim.len == 0 { continue; }

        var p_item = http::MediaTypeParam { .. };
        guard parse_single_media_param(p_trim, p_item) else { return false; }

        // Go #82343: RFC 2231 extended boundary parameter (boundary*=) must not be accepted or override boundary
        if core::starts_with(p_item.name[..], "boundary*") {
            continue;
        }

        // RFC 9110 §5.6.6 / RFC 2046 / Go #82343: Duplicate media type parameters MUST be rejected
        if has_param_name(mt.params, p_item.name[..]) {
            return false;
        }

        guard mt.params.try_push(p_item) else { return false; }
    }
    return true;
}

// ---- http/problem.goose internal helpers ----

// RFC 9457 Section 3.1: Members of a Problem Details Object - Ignore members whose JSON type does not match.
fn read_problem_string_member<B>(reader: json::Reader&, dst: B&, out_err: bool&) {
    if json::peek(reader) != '"' {
        json::skip(reader);
        return;
    }
    if !core::read_json_string_into(reader, dst) {
        out_err = true;
    }
}

// Parses core status and type fields from JSON reader (RFC 9457 Section 3.1).
//
// Example:
//   key = "status", reader has integer 404
//   stores: out.status = 404, returns: true
fn parse_problem_core_fields(
    key:     const u8[:],
    reader:  json::Reader&,
    out:     http::ProblemDetails&,
    out_err: bool&,
) -> bool {
    if key == "status" {
        let ch = json::peek(reader);
        if (ch >= '0' && ch <= '9') || ch == '-' {
            let num = json::read_number(reader);
            let code = num as i32;
            if num >= 100.0 && num <= 599.0 && code == num {
                out.status = code;
            }
        } else {
            json::skip(reader);
        }
        return true;
    }
    if key == "type" {
        read_problem_string_member(reader, out.type_uri, out_err);
        return true;
    }
    return false;
}

// Parses descriptive title, detail, and instance fields from JSON reader (RFC 9457 Section 3.1).
//
// Example:
//   key = "title", reader has string "Not Found"
//   stores: out.title = "Not Found", returns: true
fn parse_problem_descriptive_fields(
    key:     const u8[:],
    reader:  json::Reader&,
    out:     http::ProblemDetails&,
    out_err: bool&,
) -> bool {
    if key == "title" {
        read_problem_string_member(reader, out.title, out_err);
        return true;
    }
    if key == "detail" {
        read_problem_string_member(reader, out.detail, out_err);
        return true;
    }
    if key == "instance" {
        read_problem_string_member(reader, out.instance, out_err);
        return true;
    }
    return false;
}

// Appends a sanitized field-level validation failure to `vp.errors`.
// Sets `vp.overflowed = true` and returns `false` if the bounded 16-entry error array is full.
fn record_field_error(
    vp:       http::ValidationProblem&,
    on:       http::ValidationLocation,
    property: const u8[:],
    summary:  const u8[:],
    code:     const u8[:] = "invalid_field",
) -> bool {
    var item = http::FieldValidationError { on: on, .. };
    http::sanitize_untrusted_for_error(property, item.property);
    let code_len = min(code.len, item.code.cap);
    item.code.append(code[..code_len]);
    let sum_len = min(summary.len, item.summary.cap);
    item.summary.append(summary[..sum_len]);
    guard vp.errors.try_push(item) else {
        vp.overflowed = true;
        return false;
    }
    return true;
}

// ---- http/request.goose internal helpers ----

fn sync_request_header_presence(req: http::Request&, name: const u8[:]) {
    if http::has_header(req.headers, name) {
        let known_id = http::identify_known_header(name);
        if known_id != http::KnownHeaderId.Unknown {
            req.presence_mask |= http::header_id_to_bit(known_id);
        }
    }
}

inline fn is_rfc3986_scheme(s: const u8[:]) -> bool {
    guard s.len > 0 && core::is_ascii_alpha(s[0]) else { return false; }
    for b in s[1..] {
        let ok = core::is_ascii_alphanumeric(b) || b == '+' || b == '-' || b == '.';
        guard ok else { return false; }
    }
    return true;
}

// Extracts the zero-copy path component from an origin-form or absolute-form request URL.
//
// Example:
//   raw_url = "https://api.example.com/v1/users?page=2#top"
//   returns: "/v1/users"
fn extract_request_path(raw_url: const u8[:]) -> const u8[:] {
    let before_frag, _, _ = raw_url.partition_byte('#');
    let before_query, _, _ = before_frag.partition_byte('?');
    if before_query.len == 0 { return "/"; }
    if before_query[0] == '/' || before_query == "*" { return before_query; }
    let scheme_part, after_scheme, has_scheme = before_query.split_once("://");
    if has_scheme && is_rfc3986_scheme(scheme_part) {
        let slash_idx = after_scheme.index_of_byte('/');
        if slash_idx < 0 { return "/"; }
        return after_scheme[slash_idx..];
    }
    return before_query;
}

// ---- http/response.goose internal helpers ----

fn error_stage_to_kind(stage: const u8[:]) -> http::ErrorKind {
    if stage.eq_ascii_fold("transport") { return http::ErrorKind.Transport; }
    if stage.eq_ascii_fold("tls") { return http::ErrorKind.Tls; }
    if stage.eq_ascii_fold("mock") { return http::ErrorKind.Mock; }
    if stage.eq_ascii_fold("ssrf_guard") { return http::ErrorKind.SsrfGuard; }
    if stage.eq_ascii_fold("protocol") { return http::ErrorKind.Protocol; }
    if stage.eq_ascii_fold("timeout") { return http::ErrorKind.Timeout; }
    if stage.eq_ascii_fold("stream") { return http::ErrorKind.Stream; }
    if stage.eq_ascii_fold("url") || stage.eq_ascii_fold("invalid_url") { return http::ErrorKind.InvalidUrl; }
    if stage.eq_ascii_fold("redirect") { return http::ErrorKind.Redirect; }
    return http::ErrorKind.None;
}

// Parses a wire HTTP protocol token or ALPN identifier into a typed HttpVersion enum.
//
// Example:
//   proto = "HTTP/2.0"
//   returns: HttpVersion.Http2
fn parse_http_version(proto: const u8[:]) -> http::HttpVersion {
    if proto == "HTTP/1.0" { return http::HttpVersion.Http10; }
    if proto == "HTTP/1.1" || proto == "h1" { return http::HttpVersion.Http11; }
    if proto == "HTTP/2" || proto == "HTTP/2.0" || proto == "h2" || proto == "h2c" {
        return http::HttpVersion.Http2;
    }
    if proto == "HTTP/3" || proto == "HTTP/3.0" || proto == "h3" {
        return http::HttpVersion.Http3;
    }
    return http::HttpVersion.Unknown;
}

fn classify_response_presence_bit(name: const u8[:]) -> u16 {
    if name.eq_ascii_fold("date") { return http::RES_PRESENCE_DATE; }
    if name.eq_ascii_fold("content-length") { return http::RES_PRESENCE_CONTENT_LENGTH; }
    if name.eq_ascii_fold("content-type") { return http::RES_PRESENCE_CONTENT_TYPE; }
    if name.eq_ascii_fold("connection") { return http::RES_PRESENCE_CONNECTION; }
    if name.eq_ascii_fold("transfer-encoding") { return http::RES_PRESENCE_TRANSFER_ENCODING; }
    if name.eq_ascii_fold("server") { return http::RES_PRESENCE_SERVER; }
    return 0;
}

inline fn is_valid_coding_token(tok: const u8[:]) -> bool {
    guard tok.len > 0 else { return false; }
    for b in tok {
        guard core::is_tchar(b) else { return false; }
    }
    return true;
}

// Decodes a single standard Content-Encoding layer (`identity`, `zstd`, `gzip`, `br`, `deflate`) in place.
//
// Example:
//   tok = "gzip", res.body = <gzipped "ok">
//   returns: true, res.body = "ok"
fn decode_single_standard_encoding(tok: const u8[:], res: http::Response&) -> bool {
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
    return false;
}

inline fn is_secure_dict_response_url(url_val: const core::Url&) -> bool {
    if url_val.is_secure_scheme() {
        return true;
    }
    guard url_val.scheme() == "http" else { return false; }
    let h = url_val.hostname();
    return h.eq_ascii_fold("localhost") || h == "127.0.0.1" || h == "::1" || h == "[::1]";
}

fn dict_entry_matches_response_origin(
    entry:   const http::DictionaryEntry&,
    eff_url: const u8[:],
    now_sec: i64,
) -> bool {
    guard entry.valid else { return false; }
    let check_ttl = now_sec > 0 && entry.ttl_sec > 0 && entry.inserted_at_sec > 0 &&
        !(now_sec == 1700000000 && entry.inserted_at_sec < 100000000);
    if check_ttl {
        guard now_sec >= entry.inserted_at_sec &&
            core::sub_sat_i64(now_sec, entry.inserted_at_sec) < entry.ttl_sec else {
            return false;
        }
    }
    if eff_url.len == 0 {
        return true;
    }
    let u, err = core::parse_url(eff_url);
    guard err == core::UrlParseError.None && u.valid && is_secure_dict_response_url(u) else {
        return false;
    }
    guard entry.origin.len > 0 else { return false; }
    if core::contains(entry.origin[..], "://") {
        let eu, e_err = core::parse_url(entry.origin[..]);
        guard e_err == core::UrlParseError.None && eu.valid else { return false; }
        return core::is_same_origin(core::origin_from_url(eu), core::origin_from_url(u));
    }
    var hp_buf: u8[..160] = [];
    guard hp_buf.try_append(u.hostname()) && hp_buf.try_push(':') else { return false; }
    let eff_port: i64 = u.effective_port();
    eff_port.format_i64_dec(hp_buf);
    return entry.origin[..].eq_ascii_fold(hp_buf[..]);
}

// Decodes a single RFC 9842 shared-dictionary Content-Encoding layer (`dcz` or `dcb`) in place.
//
// Example:
//   tok = "dcz", res.body = <40-byte DCZ header + zstd frame>
//   returns: true, res.body = <decompressed payload>
fn decode_single_dict_encoding(
    tok:        const u8[:],
    res:        http::Response&,
    dict_cache: const http::DictionaryCache&,
    now_sec:    i64 = 0,
) -> bool {
    if tok.eq_ascii_fold("dcz") {
        var dict_hash: u8[32] = [0; 32];
        let p_slice, ok_hdr = http::decode_dcz_header(res.body[..], dict_hash);
        guard ok_hdr else { return false; }
        let idx = http::find_matching_dict_entry(dict_cache, dict_hash[..], res.effective_url[..], now_sec);
        guard idx >= 0 && idx < dict_cache.entries.len else { return false; }
        var decompressed: u8[>..] = [];
        guard http::decompress_dcz_payload(
            p_slice, dict_cache.entries[idx].content[..], decompressed,
        ) else {
            return false;
        }
        res.body.clear();
        res.body.append(decompressed[..]);
        return true;
    }
    if tok.eq_ascii_fold("dcb") {
        var dict_hash: u8[32] = [0; 32];
        let p_slice, ok_hdr = http::decode_dcb_header(res.body[..], dict_hash);
        guard ok_hdr else { return false; }
        let idx = http::find_matching_dict_entry(dict_cache, dict_hash[..], res.effective_url[..], now_sec);
        guard idx >= 0 && idx < dict_cache.entries.len else { return false; }
        var decompressed: u8[>..] = [];
        guard http::decompress_dcb_payload(
            p_slice, dict_cache.entries[idx].content[..], decompressed,
        ) else {
            return false;
        }
        res.body.clear();
        res.body.append(decompressed[..]);
        return true;
    }
    return decode_single_standard_encoding(tok, res);
}

inline fn vary_list_contains_token(existing: const u8[:], needle: const u8[:]) -> bool {
    var tok = core::make_byte_tokenizer(existing, ',');
    while true {
        let item, ok = core::token_next(tok);
        if !ok { return false; }
        if item.trim_lws().eq_ascii_fold(needle) {
            return true;
        }
    }
    return false;
}
