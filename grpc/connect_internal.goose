// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for Connect-RPC query decoding, JSON error codecs, and EndStream envelopes.
namespace grpc_internal;

import std;
import json;
import core;
import rfc.http;
import rfc.grpc;
import http.headers;
import http.request;
import .constants;
import .status;
import .connect;
import .internal;

// ---- Connect Protocol Internal Helpers ----------------------------------

const CONNECT_STATUS_NAMES: const u8[:][17] = [
    "ok", "canceled", "unknown", "invalid_argument", "deadline_exceeded",
    "not_found", "already_exists", "permission_denied", "resource_exhausted",
    "failed_precondition", "aborted", "out_of_range", "unimplemented",
    "internal", "unavailable", "data_loss", "unauthenticated",
];

checkfree fn connect_status_name(code: grpc::StatusCode) -> const u8[:] {
    let idx = grpc::status_to_code(code) as i64;
    return if idx < 17 { CONNECT_STATUS_NAMES[idx] } else { "unknown" };
}

// Parses a Connect Protocol snake_case error code string into a grpc::StatusCode.
//
// Example:
//   name = "resource_exhausted"
//   returns: grpc::StatusCode.ResourceExhausted, true
fn parse_connect_status_code(name: const u8[:]) -> grpc::StatusCode, bool {
    if name == "canceled" || name == "cancelled" {
        return grpc::StatusCode.Cancelled, true;
    }
    for i in 1..17 {
        if name == CONNECT_STATUS_NAMES[i] {
            return grpc::status_from_code(i as u32), true;
        }
    }
    return grpc::StatusCode.Unknown, false;
}

// Percent-decodes a Connect query component (`%XX` only; `+` remains literal `+`).
//
// Example:
//   src = "hello%20world%2B1", max_out = 64
//   returns: grpc::StatusCode.Ok, out = "hello world+1"
fn percent_decode_connect_component<B>(src: const u8[:], out: B&, max_out: u64) -> grpc::StatusCode {
    var committed = false;
    defer if !committed { out.clear(); };
    out.clear();
    var idx: i64 = 0;
    while idx < src.len {
        guard (out.len as u64) < max_out else { return grpc::StatusCode.ResourceExhausted; }
        let b = src[idx];
        if b != '%' {
            guard out.try_push(b) else { return grpc::StatusCode.ResourceExhausted; }
            idx = core::add_sat_i64(idx, 1);
            continue;
        }
        let i1 = core::add_sat_i64(idx, 1);
        let i2 = core::add_sat_i64(idx, 2);
        guard i2 < src.len else { return grpc::StatusCode.InvalidArgument; }
        let hi = core::hex_digit_to_val(src[i1]);
        let lo = core::hex_digit_to_val(src[i2]);
        guard hi >= 0 && lo >= 0 else { return grpc::StatusCode.InvalidArgument; }
        let decoded = (core::shl_sat_u64(hi as u64, 4) | (lo as u64)) as u8;
        guard out.try_push(decoded) else { return grpc::StatusCode.ResourceExhausted; }
        idx = core::add_sat_i64(idx, 3);
    }
    committed = true;
    return grpc::StatusCode.Ok;
}

inline fn is_valid_percent_encoded_component(src: const u8[:]) -> bool {
    var idx: i64 = 0;
    while idx < src.len {
        if src[idx] == '%' {
            let i2 = core::add_sat_i64(idx, 2);
            guard i2 < src.len else { return false; }
            let hi = core::hex_digit_to_val(src[core::add_sat_i64(idx, 1)]);
            let lo = core::hex_digit_to_val(src[i2]);
            guard hi >= 0 && lo >= 0 else { return false; }
            idx = core::add_sat_i64(idx, 3);
        } else {
            idx = core::add_sat_i64(idx, 1);
        }
    }
    return true;
}

inline fn load_connect_codec_param(raw_v: const u8[:], dst: u8[..16]&) -> grpc::StatusCode {
    let st = percent_decode_connect_component(raw_v, dst, 16);
    return if st == grpc::StatusCode.ResourceExhausted { grpc::StatusCode.Unimplemented } else { st };
}

fn apply_connect_query_param(
    raw_k:      const u8[:],
    raw_v:      const u8[:],
    val_start:  i64,
    val_end:    i64,
    out_params: grpc::ConnectUnaryGetParams&,
    msg_start:  i64&,
    msg_end:    i64&,
) -> grpc::StatusCode {
    var key_buf: u8[..64] = [];
    let key_st = percent_decode_connect_component(raw_k, key_buf, 64);
    guard key_st == grpc::StatusCode.Ok else { return grpc::StatusCode.InvalidArgument; }
    let k = key_buf[..];
    if k == "connect" {
        var ver_buf: u8[..16] = [];
        let ver_st = percent_decode_connect_component(raw_v, ver_buf, 16);
        guard ver_st == grpc::StatusCode.Ok && ver_buf[..] == "v1" else {
            return grpc::StatusCode.InvalidArgument;
        }
        out_params.has_version = true;
        return grpc::StatusCode.Ok;
    }
    if k == "encoding" { return load_connect_codec_param(raw_v, out_params.encoding); }
    if k == "compression" { return load_connect_codec_param(raw_v, out_params.compression); }
    if k == "base64" {
        var b64_buf: u8[..8] = [];
        let b64_st = percent_decode_connect_component(raw_v, b64_buf, 8);
        guard b64_st == grpc::StatusCode.Ok && (b64_buf[..] == "1" || b64_buf[..] == "0") else {
            return grpc::StatusCode.InvalidArgument;
        }
        out_params.base64 = b64_buf[..] == "1";
        return grpc::StatusCode.Ok;
    }
    if k == "message" {
        let max_msg_u64: u64 = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE;
        let max_raw = core::mul_sat_u64(max_msg_u64, 3);
        guard (raw_v.len as u64) <= max_raw else {
            return grpc::StatusCode.ResourceExhausted;
        }
        msg_start = val_start;
        msg_end = val_end;
        return grpc::StatusCode.Ok;
    }
    guard is_valid_percent_encoded_component(raw_v) else {
        return grpc::StatusCode.InvalidArgument;
    }
    return grpc::StatusCode.Ok;
}

// Decodes a percent-decoded Base64 or Base64url Connect GET payload into `out_payload`.
//
// Example:
//   pct_decoded = "cGluZw", out_payload = []
//   returns: true, out_payload = "ping"
inline fn decode_connect_base64_payload(pct_decoded: u8[>..]&, out_payload: u8[>..]&) -> bool {
    if core::base64url_decode(pct_decoded[..], out_payload) {
        return true;
    }
    guard (pct_decoded.len & 3) != 1 else { return false; }
    while (pct_decoded.len & 3) != 0 {
        pct_decoded.push('=');
    }
    return core::base64_decode(pct_decoded[..], out_payload);
}

fn decompress_connect_get_payload(comp: const u8[:], payload: u8[>..]&) -> grpc::StatusCode {
    guard comp.len > 0 && !comp.eq_ascii_fold("identity") else { return grpc::StatusCode.Ok; }
    guard comp.eq_ascii_fold("gzip") else { return grpc::StatusCode.Unimplemented; }
    var decomp_buf: u8[>..] = [];
    let ok_gz, gz_err = core::gzip_decompress_with_limit(
        payload[..], decomp_buf, rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE,
    );
    guard ok_gz else {
        return if gz_err == core::CompressError.OutputBufferOverflow {
            grpc::StatusCode.ResourceExhausted
        } else {
            grpc::StatusCode.InvalidArgument
        };
    }
    payload.clear();
    payload.append(decomp_buf[..]);
    return grpc::StatusCode.Ok;
}

// Decodes and optionally decompresses a Connect Protocol unary GET message payload.
//
// Example:
//   raw_msg = "cGluZw", params.base64 = true, params.compression = ""
//   returns: grpc::StatusCode.Ok, out_payload = "ping"
fn decode_connect_get_payload(
    raw_msg:     const u8[:],
    params:      const grpc::ConnectUnaryGetParams&,
    out_payload: u8[>..]&,
) -> grpc::StatusCode {
    var tmp_payload: u8[>..] = [];
    let max_msg_u64: u64 = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE;
    if raw_msg.len > 0 {
        var pct_decoded: u8[>..] = [];
        let max_encoded = core::mul_sat_u64(max_msg_u64, 2);
        let pct_st = percent_decode_connect_component(raw_msg, pct_decoded, max_encoded);
        guard pct_st == grpc::StatusCode.Ok else { return pct_st; }
        if params.base64 {
            guard decode_connect_base64_payload(pct_decoded, tmp_payload) else {
                return grpc::StatusCode.InvalidArgument;
            }
        } else {
            tmp_payload.append(pct_decoded[..]);
        }
        guard (tmp_payload.len as u64) <= max_msg_u64 else {
            return grpc::StatusCode.ResourceExhausted;
        }
    }

    let gz_st = decompress_connect_get_payload(params.compression[..], tmp_payload);
    guard gz_st == grpc::StatusCode.Ok else { return gz_st; }
    if params.encoding[..] == "json" {
        guard tmp_payload[..].validate_utf8() else { return grpc::StatusCode.InvalidArgument; }
    }
    out_payload.clear();
    out_payload.append(tmp_payload[..]);
    return grpc::StatusCode.Ok;
}

// Consumes `&`-delimited query parameters from `rem_in` into `out_params` and `msg_start..msg_end`.
//
// Example:
//   rem_in = "connect=v1&encoding=proto"
//   returns: grpc::StatusCode.Ok, out_params.has_version = true, out_params.encoding = "proto"
fn scan_connect_query_pairs(
    rem_in:     const u8[:],
    out_params: grpc::ConnectUnaryGetParams&,
    msg_start:  i64&,
    msg_end:    i64&,
) -> grpc::StatusCode {
    var pos: i64 = 0;
    while pos < rem_in.len {
        let sub = rem_in[pos..];
        let amp_rel = sub.index_of_byte('&');
        let pair_end = if amp_rel >= 0 { core::add_sat_i64(pos, amp_rel) } else { rem_in.len };
        let item = rem_in[pos..pair_end];
        let eq_rel = item.index_of_byte('=');
        if eq_rel >= 0 {
            let val_start = core::add_sat_i64(pos, core::add_sat_i64(eq_rel, 1));
            let st = apply_connect_query_param(
                item[..eq_rel],
                rem_in[val_start..pair_end],
                val_start,
                pair_end,
                out_params,
                msg_start,
                msg_end,
            );
            guard st == grpc::StatusCode.Ok else { return st; }
        }
        pos = if amp_rel >= 0 { core::add_sat_i64(pair_end, 1) } else { rem_in.len };
    }
    guard out_params.has_version && out_params.encoding.len > 0 else {
        return grpc::StatusCode.InvalidArgument;
    }
    guard out_params.encoding[..] == "proto" || out_params.encoding[..] == "json" else {
        return grpc::StatusCode.Unimplemented;
    }
    return grpc::StatusCode.Ok;
}

fn append_connect_json_quoted<B>(raw: const u8[:], out: B&) -> bool {
    let body_bound = if core::is_json_plain_string(raw) {
        raw.len
    } else {
        core::mul_sat_i64(raw.len, 6)
    };
    let max_needed = core::add_sat_i64(out.len, core::add_sat_i64(body_bound, 2));
    guard max_needed <= out.cap else { return false; }
    core::format_json_string(out, raw);
    return true;
}

inline fn has_prior_trailer_key_fold(trailers: const http::HeaderMap&, limit_idx: i64, key: const u8[:]) -> bool {
    for j in limit_idx {
        let e .= trailers.entries[j];
        if http::entry_name(trailers, e).eq_ascii_fold(key) {
            return true;
        }
    }
    return false;
}

fn append_connect_trailer_value_array<B>(
    trailers:  const http::HeaderMap&,
    start_idx: i64,
    key:       const u8[:],
    json_buf:  B&,
) -> bool {
    guard json_buf.try_push('[') else { return false; }
    var first_val = true;
    var j = start_idx;
    while j < trailers.entries.len {
        let e .= trailers.entries[j];
        if http::entry_name(trailers, e).eq_ascii_fold(key) {
            if !first_val {
                guard json_buf.try_push(',') else { return false; }
            }
            guard append_connect_json_quoted(http::entry_value(trailers, e), json_buf) else { return false; }
            first_val = false;
        }
        j = core::add_sat_i64(j, 1);
    }
    return json_buf.try_push(']');
}

fn append_connect_end_stream_metadata<B>(trailers: const http::HeaderMap&, json_buf: B&) -> bool {
    guard json_buf.try_append("\"metadata\":{") else { return false; }
    var first_meta = true;
    var lower_key: u8[..128] = [];
    for &e, i in trailers.entries {
        let k = http::entry_name(trailers, e);
        if k.len == 0 || has_prior_trailer_key_fold(trailers, i, k) {
            continue;
        }
        guard k.len <= lower_key.cap else { return false; }
        lower_key.clear();
        k.to_lower_ascii(lower_key);
        if !first_meta {
            guard json_buf.try_push(',') else { return false; }
        }
        guard append_connect_json_quoted(lower_key[..], json_buf)
            && json_buf.try_push(':')
            && append_connect_trailer_value_array(trailers, i, k, json_buf) else {
            return false;
        }
        first_meta = false;
    }
    return json_buf.try_push('}');
}

fn append_connect_end_stream_error<B>(
    code:     grpc::StatusCode,
    message:  const u8[:],
    json_buf: B&,
) -> bool {
    guard json_buf.try_append("\"error\":{\"code\":")
        && append_connect_json_quoted(connect_status_name(code), json_buf) else {
        return false;
    }
    if message.len > 0 {
        guard json_buf.try_append(",\"message\":")
            && append_connect_json_quoted(message, json_buf) else {
            return false;
        }
    }
    return json_buf.try_push('}');
}

// Decodes a JSON object member key `raw_key` (including `\uXXXX` escapes) into `out_key`.
//
// Example:
//   raw_key = "x-custom", out_key = []
//   returns: true, out_key = "x-custom"
inline fn decode_connect_member_key<B>(raw_key: const u8[:], out_key: B&) -> bool {
    if !raw_key.contains_byte('\\') {
        return raw_key.validate_utf8() && out_key.try_set(raw_key);
    }
    guard json::valid_escapes(raw_key, 0, raw_key.len) else { return false; }
    return core::decode_json_string_into(raw_key, 0, raw_key.len, out_key);
}

inline fn is_valid_connect_metadata_entry(key: const u8[:], val: const u8[:]) -> bool {
    guard key.len > 0 && key[0] != ':' else { return false; }
    for b in key {
        guard core::is_tchar(b) else { return false; }
    }
    for v in val {
        guard v == '\t' || (v >= 0x20 && v <= 0x7E) || v >= 0x80 else { return false; }
    }
    return true;
}

// Parses a single `"key":["val1",...]` array value in a Connect metadata object.
//
// Example:
//   reader at "[\"val1\"]", lower_key = "x-custom"
//   appends: out_trailers["x-custom"] = "val1"
fn parse_connect_metadata_array(
    reader:       json::Reader&,
    lower_key:    const u8[:],
    out_trailers: http::HeaderMap&,
    had_error:    bool&,
) {
    if json::peek(reader) != '[' {
        had_error = true;
        json::skip(reader);
        return;
    }
    var val_buf: u8[..1024] = [];
    json::each_element(reader) {
        if !core::read_json_string_into(reader, val_buf)
            || !is_valid_connect_metadata_entry(lower_key, val_buf[..])
            || !out_trailers.append_header(lower_key, val_buf[..]) {
            had_error = true;
        }
    };
}

// Parses Connect `"metadata":{...}` object entries from `reader` into `out_trailers`.
//
// Example:
//   reader at "{\"x-custom\":[\"val1\"]}"
//   populates: out_trailers["x-custom"] = "val1"
fn parse_connect_metadata_member(
    reader:       json::Reader&,
    seen_meta:    bool&,
    out_trailers: http::HeaderMap&,
    had_error:    bool&,
) {
    if seen_meta || json::peek(reader) != '{' {
        had_error = true;
        json::skip(reader);
        return;
    }
    seen_meta = true;
    var key_buf:   u8[..128] = [];
    var lower_key: u8[..128] = [];
    json::each_member(reader) { raw_key =>
        if !decode_connect_member_key(raw_key, key_buf) || key_buf.len == 0 {
            had_error = true;
            json::skip(reader);
        } else {
            lower_key.clear();
            key_buf[..].to_lower_ascii(lower_key);
            parse_connect_metadata_array(reader, lower_key[..], out_trailers, had_error);
        }
    };
}

// Validates and skips a Connect `"details":[{...},...]` JSON array of error detail objects.
//
// Example:
//   reader at "[{\"type\":\"pkg.Detail\"}]"
//   advances `reader` past the array, had_error = false
inline fn parse_connect_error_details_array(reader: json::Reader&, had_error: bool&) {
    if json::peek(reader) != '[' {
        had_error = true;
        json::skip(reader);
        return;
    }
    json::each_element(reader) {
        if json::peek(reader) != '{' {
            had_error = true;
        }
        json::skip(reader);
    };
}

fn dispatch_connect_error_field<B>(
    reader:     json::Reader&,
    field_key:  const u8[:],
    saw_code:   bool&,
    out_status: grpc::StatusCode&,
    out_msg:    B&,
    had_error:  bool&,
) {
    if field_key == "code" {
        var code_buf: u8[..64] = [];
        if saw_code || !core::read_json_string_into(reader, code_buf) || code_buf.len == 0 || code_buf[..] == "ok" {
            had_error = true;
            return;
        }
        saw_code = true;
        let parsed_code, ok_c = parse_connect_status_code(code_buf[..]);
        out_status = if ok_c { parsed_code } else { grpc::StatusCode.Unknown };
        return;
    }
    if field_key == "message" {
        var full_msg: u8[..4096] = [];
        if !core::read_json_string_into(reader, full_msg) {
            had_error = true;
            return;
        }
        let take_len = clamp_utf8_prefix_len(full_msg[..], out_msg.cap);
        let _ = out_msg.try_set(full_msg[..take_len]);
        return;
    }
    if field_key == "details" {
        parse_connect_error_details_array(reader, had_error);
        return;
    }
    json::skip(reader);
}

// Parses Connect `"error":{"code":"...","message":"...","details":[...]}` object fields.
//
// Example:
//   reader at "{\"code\":\"unauthenticated\",\"message\":\"bad token\"}"
//   sets: out_status = grpc::StatusCode.Unauthenticated, out_msg = "bad token"
fn parse_connect_error_member<B>(
    reader:     json::Reader&,
    seen_error: bool&,
    out_status: grpc::StatusCode&,
    out_msg:    B&,
    had_error:  bool&,
) {
    if seen_error || json::peek(reader) != '{' {
        had_error = true;
        json::skip(reader);
        return;
    }
    seen_error = true;
    out_status = grpc::StatusCode.Unknown;
    var saw_code = false;
    var key_buf: u8[..64] = [];
    json::each_member(reader) { raw_key =>
        if !decode_connect_member_key(raw_key, key_buf) {
            had_error = true;
            json::skip(reader);
        } else {
            dispatch_connect_error_field(reader, key_buf[..], saw_code, out_status, out_msg, had_error);
        }
    };
    if !saw_code {
        had_error = true;
    }
}

fn is_connect_get_request(req: const http::Request&) -> bool {
    guard req.method[..].eq_ascii_fold("GET") else { return false; }
    let _, query, has_q = req.url[..].split_once_byte('?');
    guard has_q else { return false; }
    var tok = core::make_byte_tokenizer(query, '&');
    var key_buf: u8[..16] = [];
    while true {
        let item, ok_tok = core::token_next(tok);
        if !ok_tok { break; }
        let k, _, ok_eq = item.split_once_byte('=');
        if !ok_eq { continue; }
        if k == "connect" { return true; }
        if percent_decode_connect_component(k, key_buf, 16) == grpc::StatusCode.Ok && key_buf[..] == "connect" {
            return true;
        }
    }
    return false;
}

inline fn connect_error_http_status(code: grpc::StatusCode) -> i32 {
    return match code {
        InvalidArgument => rfc::STATUS_BAD_REQUEST,
        Unauthenticated => rfc::STATUS_UNAUTHORIZED,
        PermissionDenied => rfc::STATUS_FORBIDDEN,
        NotFound => rfc::STATUS_NOT_FOUND,
        Unimplemented => rfc::STATUS_NOT_FOUND,
        AlreadyExists => rfc::STATUS_CONFLICT,
        Aborted => rfc::STATUS_CONFLICT,
        ResourceExhausted => rfc::STATUS_TOO_MANY_REQUESTS,
        Cancelled => 499,
        DeadlineExceeded => rfc::STATUS_GATEWAY_TIMEOUT,
        Unavailable => rfc::STATUS_SERVICE_UNAVAILABLE,
        _ => rfc::STATUS_INTERNAL_SERVER_ERROR,
    };
}

fn encode_connect_unary_error_json<B>(st: const grpc::Status&, out_body: B&) {
    var json_buf: u8[..2048] = [];
    let _ = json_buf.try_append("{\"code\":");
    let _ = append_connect_json_quoted(connect_status_name(st.code), json_buf);
    if st.message.len > 0 {
        let _ = json_buf.try_append(",\"message\":");
        let _ = append_connect_json_quoted(st.message[..], json_buf);
    }
    let _ = json_buf.try_push('}');
    let _ = out_body.try_append(json_buf[..]);
}
