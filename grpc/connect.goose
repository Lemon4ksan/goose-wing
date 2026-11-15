// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Connect Protocol (connectrpc.com) status mapping, unary HTTP GET query codec,
// and streaming EndStream (`0x02`) JSON envelope framer.
namespace wing;

import std;
import json;
import core from "..";
import rfc.http;
import rfc.grpc;
import grpc.constants;
import grpc.framing;
import grpc.status;
import http.headers;
import http.request;
import http.response;

const CONNECT_FLAG_END_STREAM: u8          = 0x02; // Connect Protocol streaming EndStream envelope flag
const CONNECT_CONTENT_PREFIX:  const u8[:] = "application/connect+";
const CONNECT_MIME_PROTO:      const u8[:] = "application/proto";
const CONNECT_MIME_JSON:       const u8[:] = "application/json";

// Converts a GrpcStatusCode to its Connect Protocol snake_case error code string.
fn connect_status_name(code: GrpcStatusCode) -> const u8[:] {
    return match code {
        Ok => "ok",
        Cancelled => "canceled",
        Unknown => "unknown",
        InvalidArgument => "invalid_argument",
        DeadlineExceeded => "deadline_exceeded",
        NotFound => "not_found",
        AlreadyExists => "already_exists",
        PermissionDenied => "permission_denied",
        ResourceExhausted => "resource_exhausted",
        FailedPrecondition => "failed_precondition",
        Aborted => "aborted",
        OutOfRange => "out_of_range",
        Unimplemented => "unimplemented",
        Internal => "internal",
        Unavailable => "unavailable",
        DataLoss => "data_loss",
        Unauthenticated => "unauthenticated",
        _ => "unknown",
    };
}

// Parses a Connect Protocol snake_case error code string into a GrpcStatusCode.
//
// Example:
//   name = "resource_exhausted"
//   returns: GrpcStatusCode.ResourceExhausted, true
fn parse_connect_status_code(name: const u8[:]) -> GrpcStatusCode, bool {
    if name == "canceled" || name == "cancelled" {
        return GrpcStatusCode.Cancelled, true;
    }
    var i: u32 = 1;
    while i <= 16 {
        let candidate = grpc_status_from_code(i);
        if name == connect_status_name(candidate) {
            return candidate, true;
        }
        i = core::add_sat_u32(i, 1);
    }
    return GrpcStatusCode.Unknown, false;
}

// ---- Connect Protocol Unary GET Query & EndStream Envelope Codec --------

struct ConnectUnaryGetParams {
    encoding:    u8[..16] = [],
    compression: u8[..16] = [],
    base64:      bool     = false,
    has_version: bool     = false,
}

// Percent-decodes a Connect query component (`%XX` only; `+` remains literal `+`).
//
// Example:
//   src = "hello%20world%2B1", max_out = 64
//   returns: GrpcStatusCode.Ok, out = "hello world+1"
fn percent_decode_connect_component<B>(src: const u8[:], out: B&, max_out: u64) -> GrpcStatusCode {
    out.clear();
    var idx: i64 = 0;
    while idx < src.len {
        guard (out.len as u64) < max_out else {
            out.clear();
            return GrpcStatusCode.ResourceExhausted;
        }
        let b = src[idx];
        if b == '%' {
            let i1 = core::add_sat_i64(idx, 1);
            let i2 = core::add_sat_i64(idx, 2);
            guard i2 < src.len else {
                out.clear();
                return GrpcStatusCode.InvalidArgument;
            }
            let hi = core::hex_digit_to_val(src[i1]);
            let lo = core::hex_digit_to_val(src[i2]);
            guard hi >= 0 && lo >= 0 else {
                out.clear();
                return GrpcStatusCode.InvalidArgument;
            }
            let decoded = (core::shl_sat_u64(hi as u64, 4) | (lo as u64)) as u8;
            guard out.try_push(decoded) else {
                out.clear();
                return GrpcStatusCode.ResourceExhausted;
            }
            idx = core::add_sat_i64(idx, 3);
        } else {
            guard out.try_push(b) else {
                out.clear();
                return GrpcStatusCode.ResourceExhausted;
            }
            idx = core::add_sat_i64(idx, 1);
        }
    }
    return GrpcStatusCode.Ok;
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

// Applies a single key=value query parameter from a Connect Protocol unary GET request.
fn apply_connect_query_param(
    raw_k:      const u8[:],
    raw_v:      const u8[:],
    val_start:  i64,
    val_end:    i64,
    out_params: ConnectUnaryGetParams&,
    msg_start:  i64&,
    msg_end:    i64&,
) -> GrpcStatusCode {
    var key_buf: u8[..64] = [];
    let key_st = percent_decode_connect_component(raw_k, key_buf, 64);
    guard key_st == GrpcStatusCode.Ok else { return GrpcStatusCode.InvalidArgument; }
    let k = key_buf[..];
    if k == "connect" {
        var ver_buf: u8[..16] = [];
        let ver_st = percent_decode_connect_component(raw_v, ver_buf, 16);
        guard ver_st == GrpcStatusCode.Ok && ver_buf[..] == "v1" else {
            return GrpcStatusCode.InvalidArgument;
        }
        out_params.has_version = true;
        return GrpcStatusCode.Ok;
    }
    if k == "encoding" {
        let enc_st = percent_decode_connect_component(raw_v, out_params.encoding, 16);
        if enc_st == GrpcStatusCode.ResourceExhausted {
            return GrpcStatusCode.Unimplemented;
        }
        return enc_st;
    }
    if k == "compression" {
        let comp_st = percent_decode_connect_component(raw_v, out_params.compression, 16);
        if comp_st == GrpcStatusCode.ResourceExhausted {
            return GrpcStatusCode.Unimplemented;
        }
        return comp_st;
    }
    if k == "base64" {
        var b64_buf: u8[..8] = [];
        let b64_st = percent_decode_connect_component(raw_v, b64_buf, 8);
        guard b64_st == GrpcStatusCode.Ok && (b64_buf[..] == "1" || b64_buf[..] == "0") else {
            return GrpcStatusCode.InvalidArgument;
        }
        out_params.base64 = b64_buf[..] == "1";
        return GrpcStatusCode.Ok;
    }
    if k == "message" {
        let max_msg_u64: u64 = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE;
        let max_raw = core::mul_sat_u64(max_msg_u64, 3);
        guard (raw_v.len as u64) <= max_raw else {
            return GrpcStatusCode.ResourceExhausted;
        }
        msg_start = val_start;
        msg_end = val_end;
        return GrpcStatusCode.Ok;
    }
    guard is_valid_percent_encoded_component(raw_v) else {
        return GrpcStatusCode.InvalidArgument;
    }
    return GrpcStatusCode.Ok;
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

// Decodes and optionally decompresses a Connect Protocol unary GET message payload.
//
// Example:
//   raw_msg = "cGluZw", params.base64 = true, params.compression = ""
//   returns: GrpcStatusCode.Ok, out_payload = "ping"
fn decode_connect_get_payload(
    raw_msg:     const u8[:],
    params:      const ConnectUnaryGetParams&,
    out_payload: u8[>..]&,
) -> GrpcStatusCode {
    var committed = false;
    defer if !committed { out_payload.clear(); };
    let max_msg_u64: u64 = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE;
    if raw_msg.len > 0 {
        var pct_decoded: u8[>..] = [];
        let max_encoded = core::mul_sat_u64(max_msg_u64, 2);
        let pct_st = percent_decode_connect_component(raw_msg, pct_decoded, max_encoded);
        guard pct_st == GrpcStatusCode.Ok else { return pct_st; }
        if params.base64 {
            guard decode_connect_base64_payload(pct_decoded, out_payload) else {
                return GrpcStatusCode.InvalidArgument;
            }
            guard (out_payload.len as u64) <= max_msg_u64 else {
                return GrpcStatusCode.ResourceExhausted;
            }
        } else {
            guard (pct_decoded.len as u64) <= max_msg_u64 else {
                return GrpcStatusCode.ResourceExhausted;
            }
            out_payload.append(pct_decoded[..]);
        }
    }

    let comp = params.compression[..];
    if comp.len > 0 && !comp.eq_ascii_fold("identity") {
        guard comp.eq_ascii_fold("gzip") else { return GrpcStatusCode.Unimplemented; }
        var decomp_buf: u8[>..] = [];
        let ok_gz, gz_err = core::gzip_decompress_with_limit(
            out_payload[..], decomp_buf, rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE,
        );
        guard ok_gz else {
            return if gz_err == core::CompressError.OutputBufferOverflow {
                GrpcStatusCode.ResourceExhausted
            } else {
                GrpcStatusCode.InvalidArgument
            };
        }
        out_payload.clear();
        out_payload.append(decomp_buf[..]);
    }
    if params.encoding[..] == "json" {
        guard out_payload[..].validate_utf8() else { return GrpcStatusCode.InvalidArgument; }
    }
    committed = true;
    return GrpcStatusCode.Ok;
}

// Consumes `&`-delimited query parameters from `rem_in` into `out_params` and `msg_start..msg_end`.
//
// Example:
//   rem_in = "connect=v1&encoding=proto"
//   returns: GrpcStatusCode.Ok, out_params.has_version = true, out_params.encoding = "proto"
fn scan_connect_query_pairs(
    rem_in:     const u8[:],
    out_params: ConnectUnaryGetParams&,
    msg_start:  i64&,
    msg_end:    i64&,
) -> GrpcStatusCode {
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
            guard st == GrpcStatusCode.Ok else { return st; }
        }
        pos = if amp_rel >= 0 { core::add_sat_i64(pair_end, 1) } else { rem_in.len };
    }
    guard out_params.has_version && out_params.encoding.len > 0 else {
        return GrpcStatusCode.InvalidArgument;
    }
    guard out_params.encoding[..] == "proto" || out_params.encoding[..] == "json" else {
        return GrpcStatusCode.Unimplemented;
    }
    return GrpcStatusCode.Ok;
}

// Parses a Connect Protocol unary HTTP GET query string (`connect=v1&encoding=proto&base64=1&message=...`).
//
// Example:
//   query = "connect=v1&encoding=proto&base64=1&message=cGluZw"
//   returns: GrpcStatusCode.Ok, out_params.encoding = "proto", out_payload = "ping"
fn parse_connect_get_query(
    query:       const u8[:],
    out_params:  ConnectUnaryGetParams&,
    out_payload: u8[>..]&,
) -> GrpcStatusCode {
    var tmp_params = ConnectUnaryGetParams { .. };
    var msg_start: i64 = 0;
    var msg_end:   i64 = 0;
    let rem = if query.len > 0 && query[0] == '?' { query[1..] } else { query };
    let scan_st = scan_connect_query_pairs(rem, tmp_params, msg_start, msg_end);
    guard scan_st == GrpcStatusCode.Ok else { return scan_st; }
    var decoded_payload: u8[>..] = [];
    let pay_st = decode_connect_get_payload(rem[msg_start..msg_end], tmp_params, decoded_payload);
    if pay_st == GrpcStatusCode.Ok {
        out_params = tmp_params;
        out_payload.clear();
        out_payload.append(decoded_payload[..]);
    }
    return pay_st;
}

// Appends a JSON-escaped string (`"..."`) into bounded buffer `out`.
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

inline fn has_prior_trailer_key_fold(trailers: const HeaderMap&, limit_idx: i64, key: const u8[:]) -> bool {
    for j in limit_idx {
        if entry_name(trailers, trailers.entries[j]).eq_ascii_fold(key) {
            return true;
        }
    }
    return false;
}

fn append_connect_trailer_value_array<B>(
    trailers:  const HeaderMap&,
    start_idx: i64,
    key:       const u8[:],
    json_buf:  B&,
) -> bool {
    guard json_buf.try_push('[') else { return false; }
    var first_val = true;
    var j = start_idx;
    while j < trailers.entries.len {
        let e .= trailers.entries[j];
        if entry_name(trailers, e).eq_ascii_fold(key) {
            if !first_val {
                guard json_buf.try_push(',') else { return false; }
            }
            guard append_connect_json_quoted(entry_value(trailers, e), json_buf) else { return false; }
            first_val = false;
        }
        j = core::add_sat_i64(j, 1);
    }
    return json_buf.try_push(']');
}

// Appends `"metadata":{...}` entries from `trailers` into `json_buf`, coalescing duplicate keys.
fn append_connect_end_stream_metadata<B>(trailers: const HeaderMap&, json_buf: B&) -> bool {
    guard json_buf.try_append("\"metadata\":{") else { return false; }
    var first_meta = true;
    var lower_key: u8[..128] = [];
    for i in trailers.entries.len {
        let k = entry_name(trailers, trailers.entries[i]);
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

// Appends `"error":{"code":"...","message":"..."}` into `json_buf`.
fn append_connect_end_stream_error<B>(
    code:     GrpcStatusCode,
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

// Encodes a Connect Protocol streaming `EndStream` envelope frame (`flag = 0x02`) containing
// JSON error and trailer metadata (`{"error":{"code":"...","message":"..."},"metadata":{...}}`).
fn encode_connect_end_stream<B>(
    code:     GrpcStatusCode,
    message:  const u8[:],
    trailers: const HeaderMap&,
    out:      B&,
) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    var json_buf: u8[..8192] = [];
    guard json_buf.try_push('{') else { return false; }
    let has_err = code != GrpcStatusCode.Ok;
    if has_err {
        guard append_connect_end_stream_error(code, message, json_buf) else { return false; }
    }
    if trailers.entries.len > 0 {
        if has_err {
            guard json_buf.try_push(',') else { return false; }
        }
        guard append_connect_end_stream_metadata(trailers, json_buf) else { return false; }
    }
    guard json_buf.try_push('}') else { return false; }
    var hdr: u8[..8] = [];
    hdr.push(CONNECT_FLAG_END_STREAM);
    hdr.append_u32_be(json_buf.len as u32);
    guard out.try_append(hdr[..]) && out.try_append(json_buf[..]) else { return false; }
    committed = true;
    return true;
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
    out_trailers: HeaderMap&,
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
            || !append_header(out_trailers, lower_key, val_buf[..]) {
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
    out_trailers: HeaderMap&,
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

fn dispatch_connect_error_field(
    reader:     json::Reader&,
    field_key:  const u8[:],
    saw_code:   bool&,
    out_status: GrpcStatusCode&,
    out_msg:    u8[..256]&,
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
        out_status = if ok_c { parsed_code } else { GrpcStatusCode.Unknown };
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
//   sets: out_status = GrpcStatusCode.Unauthenticated, out_msg = "bad token"
fn parse_connect_error_member(
    reader:     json::Reader&,
    seen_error: bool&,
    out_status: GrpcStatusCode&,
    out_msg:    u8[..256]&,
    had_error:  bool&,
) {
    if seen_error || json::peek(reader) != '{' {
        had_error = true;
        json::skip(reader);
        return;
    }
    seen_error = true;
    out_status = GrpcStatusCode.Unknown;
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

// Parses a Connect Protocol streaming `EndStream` JSON payload (`flag = 0x02`) into status,
// message, and trailer headers.
//
// Example:
//   json_bytes = "{\"error\":{\"code\":\"unauthenticated\",\"message\":\"bad token\"}}"
//   returns: true, out_status = GrpcStatusCode.Unauthenticated, out_message = "bad token"
fn parse_connect_end_stream(
    json_bytes:   const u8[:],
    out_status:   GrpcStatusCode&,
    out_message:  u8[..256]&,
    out_trailers: HeaderMap&,
) -> bool {
    guard json_bytes.validate_utf8() else { return false; }
    var reader = json::reader(json_bytes);
    guard json::peek(reader) == '{' else { return false; }

    var tmp_status = GrpcStatusCode.Ok;
    var tmp_msg: u8[..256] = [];
    var tmp_trailers = HeaderMap { .. };
    var seen_error = false;
    var seen_meta = false;
    var had_error = false;
    var top_key: u8[..64] = [];

    json::each_member(reader) { raw_key =>
        if !decode_connect_member_key(raw_key, top_key) {
            had_error = true;
            json::skip(reader);
        } else if top_key[..] == "error" {
            parse_connect_error_member(reader, seen_error, tmp_status, tmp_msg, had_error);
        } else if top_key[..] == "metadata" {
            parse_connect_metadata_member(reader, seen_meta, tmp_trailers, had_error);
        } else {
            json::skip(reader);
        }
    };

    guard json::finish(reader) && !had_error else { return false; }
    out_status = tmp_status;
    let _ = out_message.try_set(tmp_msg[..]);
    out_trailers = tmp_trailers;
    return true;
}

// ---- Connect Protocol Server Unary HTTP GET Dispatcher -------------------

// Returns true if `req` is a Connect Protocol unary HTTP GET request (`connect` key in query).
fn is_connect_get_request(req: const Request&) -> bool {
    guard req.method[..].eq_ascii_fold("GET") else { return false; }
    let q_idx = req.url[..].index_of_byte('?');
    guard q_idx >= 0 else { return false; }
    var rem = req.url[core::add_sat_i64(q_idx, 1)..];
    var key_buf: u8[..16] = [];
    while rem.len > 0 {
        let pair, rest, has_amp = rem.split_once_byte('&');
        let item = if has_amp { pair } else { rem };
        rem = if has_amp { rest } else { "" };
        let k, _, ok_eq = item.split_once_byte('=');
        if ok_eq {
            if k == "connect" { return true; }
            if percent_decode_connect_component(k, key_buf, 16) == GrpcStatusCode.Ok && key_buf[..] == "connect" {
                return true;
            }
        }
    }
    return false;
}

// Maps a `GrpcStatusCode` to its Connect Protocol HTTP status code for unary errors.
inline fn connect_error_http_status(code: GrpcStatusCode) -> i32 {
    return match code {
        InvalidArgument => 400,
        Unauthenticated => 401,
        PermissionDenied => 403,
        NotFound => 404,
        Unimplemented => 404,
        AlreadyExists => 409,
        Aborted => 409,
        ResourceExhausted => 429,
        Cancelled => 499,
        DeadlineExceeded => 504,
        Unavailable => 503,
        _ => 500,
    };
}

// Encodes a Connect Protocol unary error JSON object (`{"code":"...","message":"..."}`) into `out_body`.
fn encode_connect_unary_error_json<B>(st: const GrpcStatus&, out_body: B&) {
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
