// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Connect Protocol (connectrpc.com) status mapping, unary HTTP GET query codec,
// and streaming EndStream (`0x02`) JSON envelope framer.
namespace grpc;

import std;
import json;
import core from "..";
import http.headers;
import .constants;
import .internal;

const CONNECT_FLAG_END_STREAM: u8          = 0x02; // Connect Protocol streaming EndStream envelope flag
const CONNECT_CONTENT_PREFIX:  const u8[:] = "application/connect+";
const CONNECT_MIME_PROTO:      const u8[:] = "application/proto";
const CONNECT_MIME_JSON:       const u8[:] = "application/json";

// ---- Connect Protocol Unary GET Query & EndStream Envelope Codec --------

struct ConnectUnaryGetParams {
    encoding:    u8[..16] = [],
    compression: u8[..16] = [],
    base64:      bool     = false,
    has_version: bool     = false,
}

// Parses a Connect Protocol unary HTTP GET query string (`connect=v1&encoding=proto&base64=1&message=...`).
//
// Example:
//   query = "connect=v1&encoding=proto&base64=1&message=cGluZw"
//   returns: StatusCode.Ok, out_params.encoding = "proto", out_payload = "ping"
fn parse_connect_get_query(
    query:       const u8[:],
    out_params:  ConnectUnaryGetParams&,
    out_payload: u8[>..]&,
) -> StatusCode {
    var tmp_params = ConnectUnaryGetParams { .. };
    var msg_start: i64 = 0;
    var msg_end:   i64 = 0;
    let rem = if query.len > 0 && query[0] == '?' { query[1..] } else { query };
    let scan_st = grpc_internal::scan_connect_query_pairs(rem, tmp_params, msg_start, msg_end);
    guard scan_st == StatusCode.Ok else { return scan_st; }
    var decoded_payload: u8[>..] = [];
    let pay_st = grpc_internal::decode_connect_get_payload(rem[msg_start..msg_end], tmp_params, decoded_payload);
    if pay_st == StatusCode.Ok {
        out_params = tmp_params;
        out_payload.clear();
        out_payload.append(decoded_payload[..]);
    }
    return pay_st;
}

// Encodes a Connect Protocol streaming `EndStream` envelope frame (`flag = 0x02`) containing
// JSON error and trailer metadata (`{"error":{"code":"...","message":"..."},"metadata":{...}}`).
fn encode_connect_end_stream<B>(
    code:     StatusCode,
    message:  const u8[:],
    trailers: const wing::HeaderMap&,
    out:      B&,
) -> bool {
    let saved_len = out.len;
    var committed = false;
    defer if !committed { out.resize(saved_len); };
    var json_buf: u8[..8192] = [];
    guard json_buf.try_push('{') else { return false; }
    let has_err = code != StatusCode.Ok;
    if has_err {
        guard grpc_internal::append_connect_end_stream_error(code, message, json_buf) else { return false; }
    }
    if trailers.entries.len > 0 {
        if has_err {
            guard json_buf.try_push(',') else { return false; }
        }
        guard grpc_internal::append_connect_end_stream_metadata(trailers, json_buf) else { return false; }
    }
    guard json_buf.try_push('}') else { return false; }
    var hdr: u8[..8] = [];
    hdr.push(CONNECT_FLAG_END_STREAM);
    hdr.append_u32_be(json_buf.len as u32);
    guard out.try_append(hdr[..]) && out.try_append(json_buf[..]) else { return false; }
    committed = true;
    return true;
}

// Parses a Connect Protocol streaming `EndStream` JSON payload (`flag = 0x02`) into status,
// message, and trailer headers.
//
// Example:
//   json_bytes = "{\"error\":{\"code\":\"unauthenticated\",\"message\":\"bad token\"}}"
//   returns: true, out_status = StatusCode.Unauthenticated, out_message = "bad token"
fn parse_connect_end_stream<B>(
    json_bytes:   const u8[:],
    out_status:   StatusCode&,
    out_message:  B&,
    out_trailers: wing::HeaderMap&,
) -> bool {
    guard json_bytes.validate_utf8() else { return false; }
    var reader = json::reader(json_bytes);
    guard json::peek(reader) == '{' else { return false; }

    var tmp_status = StatusCode.Ok;
    var tmp_msg: u8[..256] = [];
    var tmp_trailers = wing::HeaderMap { .. };
    var seen_error = false;
    var seen_meta = false;
    var had_error = false;
    var top_key: u8[..64] = [];

    json::each_member(reader) { raw_key =>
        if !grpc_internal::decode_connect_member_key(raw_key, top_key) {
            had_error = true;
            json::skip(reader);
        } else if top_key[..] == "error" {
            grpc_internal::parse_connect_error_member(reader, seen_error, tmp_status, tmp_msg, had_error);
        } else if top_key[..] == "metadata" {
            grpc_internal::parse_connect_metadata_member(reader, seen_meta, tmp_trailers, had_error);
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
