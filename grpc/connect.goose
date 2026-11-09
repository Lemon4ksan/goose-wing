// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Connect Protocol (connectrpc.com) status mapping, unary HTTP GET query codec,
// and streaming EndStream (`0x02`) JSON envelope framer.
namespace wing;

import std;
import core from "..";
import rfc.http;
import rfc.grpc;
import grpc.constants;
import grpc.framing;
import grpc.status;
import http.headers;
import client.request;
import client.response;

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

// Applies a single key=value query parameter from a Connect Protocol unary GET request.
fn apply_connect_query_param(
    k:           const u8[:],
    v:           const u8[:],
    out_params:  ConnectUnaryGetParams&,
    out_raw_msg: u8[..4096]&,
) -> bool {
    if k == "connect" {
        guard v == "v1" else { return false; }
        out_params.has_version = true;
        return true;
    }
    if k == "encoding" {
        return out_params.encoding.try_set(v);
    }
    if k == "compression" {
        return out_params.compression.try_set(v);
    }
    if k == "base64" {
        guard v == "1" || v == "0" else { return false; }
        out_params.base64 = v == "1";
        return true;
    }
    if k == "message" {
        return out_raw_msg.try_set(v);
    }
    return true;
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
    if raw_msg.len > 0 && params.base64 {
        var raw_msg_copy: u8[..4096] = [];
        guard raw_msg_copy.try_set(raw_msg) else { return GrpcStatusCode.InvalidArgument; }
        var ok_b64 = core::base64url_decode(raw_msg_copy[..], out_payload);
        if !ok_b64 {
            ok_b64 = core::base64_decode(raw_msg_copy[..], out_payload);
        }
        guard ok_b64 else { return GrpcStatusCode.InvalidArgument; }
    } else if raw_msg.len > 0 {
        var dec_buf: u8[..4096] = [];
        guard core::percent_decode_query(raw_msg, dec_buf) else { return GrpcStatusCode.InvalidArgument; }
        out_payload.append(dec_buf[..]);
    }

    let comp = params.compression[..];
    if comp.len == 0 || comp.eq_ascii_fold("identity") {
        committed = true;
        return GrpcStatusCode.Ok;
    }
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
    committed = true;
    return GrpcStatusCode.Ok;
}

// Consumes `&`-delimited query parameters from `rem` into `out_params` and `out_raw_msg`.
//
// Example:
//   rem = "connect=v1&encoding=proto"
//   returns: true, out_params.has_version = true, out_params.encoding = "proto"
fn scan_connect_query_pairs(
    rem_in:      const u8[:],
    out_params:  ConnectUnaryGetParams&,
    out_raw_msg: u8[..4096]&,
) -> bool {
    var rem = rem_in;
    while rem.len > 0 {
        let pair, rest, has_amp = rem.split_once_byte('&');
        let item = if has_amp { pair } else { rem };
        rem = if has_amp { rest } else { "" };
        let k, v, ok_eq = item.split_once_byte('=');
        if ok_eq {
            guard apply_connect_query_param(k, v, out_params, out_raw_msg) else { return false; }
        }
    }
    return true;
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
    out_params.encoding.clear();
    out_params.compression.clear();
    out_params.base64 = false;
    out_params.has_version = false;
    out_payload.clear();

    var err_code = GrpcStatusCode.InvalidArgument;
    var raw_msg: u8[..4096] = [];
    let rem = if query.len > 0 && query[0] == '?' { query[1..] } else { query };
    guard scan_connect_query_pairs(rem, out_params, raw_msg)
        && out_params.has_version
        && out_params.encoding.len > 0 else {
        return err_code;
    }
    guard out_params.encoding[..] == "proto" || out_params.encoding[..] == "json" else {
        err_code = GrpcStatusCode.Unimplemented;
        return err_code;
    }
    return decode_connect_get_payload(raw_msg[..], out_params, out_payload);
}

// Appends a single JSON-escaped ASCII byte into `out`.
fn append_connect_json_byte<B>(b: u8, out: B&) -> bool {
    if b == '"' || b == '\\' {
        return out.try_push('\\') && out.try_push(b);
    }
    if b == '\n' { return out.try_append("\\n"); }
    if b == '\r' { return out.try_append("\\r"); }
    if b == '\t' { return out.try_append("\\t"); }
    if b >= 0x20 && b < 0x7F { return out.try_push(b); }
    return true;
}

// Appends a JSON-escaped string (`"..."`) into `out`.
fn append_connect_json_quoted<B>(raw: const u8[:], out: B&) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    guard out.try_push('"') else { return false; }
    for b in raw {
        guard append_connect_json_byte(b, out) else { return false; }
    }
    guard out.try_push('"') else { return false; }
    committed = true;
    return true;
}

// Appends `"metadata":{...}` entries from `trailers` into `json_buf`.
fn append_connect_end_stream_metadata<B>(trailers: const HeaderMap&, json_buf: B&) -> bool {
    guard json_buf.try_append("\"metadata\":{") else { return false; }
    var first_meta = true;
    for &e in trailers.entries {
        let k = entry_name(trailers, e);
        let v = entry_value(trailers, e);
        if k.len == 0 { continue; }
        if !first_meta {
            guard json_buf.try_push(',') else { return false; }
        }
        guard append_connect_json_quoted(k, json_buf)
            && json_buf.try_append(":[")
            && append_connect_json_quoted(v, json_buf)
            && json_buf.try_push(']') else {
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
    var json_buf: u8[..2048] = [];
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

// Translates a single JSON escape char following `\` in a Connect JSON string.
//
// Example:
//   esc = 'n'
//   returns: '\n'
fn decode_connect_json_escape(esc: u8) -> u8 {
    if esc == 'n' { return '\n'; }
    if esc == 'r' { return '\r'; }
    if esc == 't' { return '\t'; }
    return esc;
}

// Extracts the next quoted JSON string starting at or after `pos` in `s`, unescaping into `out`.
//
// Example:
//   s = ":\"invalid_argument\"}", pos = 0
//   returns: true, out = "invalid_argument", pos = 19
fn scan_connect_json_string<B>(s: const u8[:], pos: i64&, out: B&) -> bool {
    out.clear();
    var committed = false;
    defer if !committed { out.clear(); };
    let q_rel = s[pos..].index_of_byte('"');
    guard q_rel >= 0 else { return false; }
    var idx = core::add_sat_i64(pos, core::add_sat_i64(q_rel, 1));
    while idx < s.len {
        let b = s[idx];
        if b == '"' {
            pos = core::add_sat_i64(idx, 1);
            committed = true;
            return true;
        }
        if b == '\\' {
            let next_idx = core::add_sat_i64(idx, 1);
            guard next_idx < s.len && out.try_push(decode_connect_json_escape(s[next_idx])) else {
                return false;
            }
            idx = core::add_sat_i64(next_idx, 1);
        } else {
            guard out.try_push(b) else { return false; }
            idx = core::add_sat_i64(idx, 1);
        }
    }
    return false;
}

// Parses a single `"key":["val1",...]` array value in a Connect metadata object.
//
// Example:
//   meta_slice = ":[\"val1\"]}", pos = 0, key = "x-custom"
//   returns: true, pos = 9, out_trailers["x-custom"] = "val1"
fn parse_connect_metadata_values(
    meta_slice:   const u8[:],
    pos:          i64&,
    key:          const u8[:],
    out_trailers: HeaderMap&,
) -> bool {
    let br_rel = meta_slice[pos..].index_of_byte('[');
    guard br_rel >= 0 else { return false; }
    pos = core::add_sat_i64(pos, core::add_sat_i64(br_rel, 1));
    var val_buf: u8[..256] = [];
    while pos < meta_slice.len && meta_slice[pos] != ']' {
        if meta_slice[pos] == '"' {
            guard scan_connect_json_string(meta_slice, pos, val_buf) else { return false; }
            let _ = append_header(out_trailers, key, val_buf[..]);
        } else {
            pos = core::add_sat_i64(pos, 1);
        }
    }
    guard pos < meta_slice.len && meta_slice[pos] == ']' else { return false; }
    pos = core::add_sat_i64(pos, 1);
    return true;
}

// Parses Connect `"metadata":{...}` object entries starting after `"metadata"`, advancing `pos`.
//
// Example:
//   s = ":{\"x-custom\":[\"val1\"]}}", pos = 0
//   returns: true, pos = 22, out_trailers["x-custom"] = "val1"
fn parse_connect_metadata_object(
    s:            const u8[:],
    pos:          i64&,
    out_trailers: HeaderMap&,
) -> bool {
    let saved_pos = pos;
    var committed = false;
    defer if !committed { pos = saved_pos; };
    let br_rel = s[pos..].index_of_byte('{');
    guard br_rel >= 0 else { return false; }
    pos = core::add_sat_i64(pos, core::add_sat_i64(br_rel, 1));
    var key_buf: u8[..64] = [];
    while pos < s.len {
        while pos < s.len && s[pos] != '"' && s[pos] != '}' {
            pos = core::add_sat_i64(pos, 1);
        }
        if pos < s.len && s[pos] == '}' {
            pos = core::add_sat_i64(pos, 1);
            committed = true;
            return true;
        }
        guard pos < s.len
            && scan_connect_json_string(s, pos, key_buf)
            && parse_connect_metadata_values(s, pos, key_buf[..], out_trailers) else {
            return false;
        }
    }
    return false;
}

// Applies a single key/value pair from a Connect `"error":{...}` object.
fn apply_connect_error_field(
    key:        const u8[:],
    val:        const u8[:],
    out_status: GrpcStatusCode&,
    out_msg:    u8[..256]&,
) {
    if key == "code" {
        let parsed_code, ok_c = parse_connect_status_code(val);
        out_status = if ok_c { parsed_code } else { GrpcStatusCode.Unknown };
    } else if key == "message" {
        let _ = out_msg.try_set(val);
    }
}

// Parses Connect `"error":{"code":"...","message":"..."}` object fields starting after `"error"`.
//
// Example:
//   s = ":{\"code\":\"unauthenticated\",\"message\":\"bad token\"}}", pos = 0
//   returns: true, out_status = GrpcStatusCode.Unauthenticated, out_msg = "bad token"
fn parse_connect_error_object(
    s:          const u8[:],
    pos:        i64&,
    out_status: GrpcStatusCode&,
    out_msg:    u8[..256]&,
) -> bool {
    let saved_pos = pos;
    var committed = false;
    defer if !committed {
        pos = saved_pos;
        out_status = GrpcStatusCode.Unknown;
        out_msg.clear();
    };
    let br_rel = s[pos..].index_of_byte('{');
    guard br_rel >= 0 else { return false; }
    pos = core::add_sat_i64(pos, core::add_sat_i64(br_rel, 1));
    out_status = GrpcStatusCode.Unknown;
    var key_buf: u8[..32]  = [];
    var val_buf: u8[..256] = [];
    while pos < s.len {
        while pos < s.len && s[pos] != '"' && s[pos] != '}' {
            pos = core::add_sat_i64(pos, 1);
        }
        if pos >= s.len || s[pos] == '}' {
            pos = core::add_sat_i64(pos, 1);
            break;
        }
        guard scan_connect_json_string(s, pos, key_buf)
            && scan_connect_json_string(s, pos, val_buf) else {
            return false;
        }
        apply_connect_error_field(key_buf[..], val_buf[..], out_status, out_msg);
    }
    committed = true;
    return true;
}

// Dispatches a single top-level key (`"error"` or `"metadata"`) in a Connect EndStream object.
fn dispatch_connect_end_stream_key(
    trimmed:      const u8[:],
    pos:          i64&,
    key:          const u8[:],
    out_status:   GrpcStatusCode&,
    out_msg:      u8[..256]&,
    out_trailers: HeaderMap&,
) -> bool {
    if key == "error" {
        return parse_connect_error_object(trimmed, pos, out_status, out_msg);
    }
    if key == "metadata" {
        return parse_connect_metadata_object(trimmed, pos, out_trailers);
    }
    return true;
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
    out_status = GrpcStatusCode.Ok;
    out_message.clear();
    out_trailers.clear();
    var committed = false;
    defer if !committed { out_trailers.clear(); };
    let trimmed = json_bytes.trim_lws();
    guard trimmed.len >= 2 && trimmed[0] == '{' && trimmed[^1..] == "}" else {
        return false;
    }

    var tmp_status = GrpcStatusCode.Ok;
    var tmp_msg: u8[..256] = [];
    var top_key: u8[..32]  = [];
    var pos:     i64       = 1;
    while pos < trimmed.len {
        while pos < trimmed.len && trimmed[pos] != '"' && trimmed[pos] != '}' {
            pos = core::add_sat_i64(pos, 1);
        }
        if pos >= trimmed.len || trimmed[pos] == '}' { break; }
        guard scan_connect_json_string(trimmed, pos, top_key)
            && dispatch_connect_end_stream_key(trimmed, pos, top_key[..], tmp_status, tmp_msg, out_trailers) else {
            return false;
        }
    }

    committed = true;
    out_status = tmp_status;
    let _ = out_message.try_set(tmp_msg[..]);
    return true;
}

// ---- Connect Protocol Server Unary HTTP GET Dispatcher -------------------

// Returns true if `req` is a Connect Protocol unary HTTP GET request (`connect=v1` in query).
fn is_connect_get_request(req: const Request&) -> bool {
    guard req.method[..].eq_ascii_fold("GET") else { return false; }
    let q_idx = req.url[..].index_of_byte('?');
    guard q_idx >= 0 else { return false; }
    let query = req.url[core::add_sat_i64(q_idx, 1)..];
    return core::find(query, "connect=v1") >= 0 || core::find(query, "connect=") >= 0;
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
    out_body.append("{\"code\":\"");
    out_body.append(connect_status_name(st.code));
    out_body.append("\"");
    if st.message.len > 0 {
        out_body.append(",\"message\":");
        var msg_json: u8[..512] = [];
        let _ = append_connect_json_quoted(st.message[..], msg_json);
        out_body.append(msg_json[..]);
    }
    out_body.push('}');
}
