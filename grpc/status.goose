// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// gRPC status code management, percent-encoded grpc-message, and grpc-timeout codecs.
// Conforms to gRPC Over HTTP/2 Specification and RFC 3986.
namespace grpc;

import std;
import core;
import rfc.grpc;
import http.headers;
import .constants;
import .internal;

// ---- Value-Returned Status Constructors ---------------------------------

fn ok() -> Status {
    return Status {
        code:    StatusCode.Ok,
        message: [],
    };
}

fn error(code: StatusCode, message: const u8[:]) -> Status {
    var status = Status {
        code:    code,
        message: [],
    };
    let take_len = min(message.len, status.message.cap);
    let _ = status.message.try_set(message[..take_len]);
    return status;
}

// ---- Percent Codec for grpc-message -------------------------------------

// Percent-encodes message string for `grpc-message` header.
// Characters in 0x20..0x7E except '%' remain unescaped; all others are %XX encoded.
fn encode_message<B>(raw: const u8[:], out: B&, max_out_len: i64 = -1) {
    for b in raw {
        if grpc_internal::is_message_unencoded(b) {
            if max_out_len >= 0 && out.len >= max_out_len { break; }
            guard out.try_push(b) else { break; }
            continue;
        }
        if max_out_len >= 0 && core::add_sat_i64(out.len, 3) > max_out_len { break; }
        var esc: u8[..4] = ['%'];
        b.format_u8_hex(esc, true);
        guard out.try_append(esc[..]) else { break; }
    }
}

// Percent-decodes `grpc-message` header value into raw message bytes.
// Clamps decoded output to 256 bytes and target buffer capacity to prevent overflow.
//
// Example:
//   encoded = "unknown%20error"
//   returns: out = "unknown error"
fn decode_message<B>(encoded: const u8[:], out: B&) {
    guard encoded.len > 0 else {
        out.clear();
        return;
    }
    out.clear();
    var i: u64 = 0;
    let total = encoded.len as u64;
    while i < total {
        guard out.len < 256 else { break; }
        let idx = i as i64;
        if encoded[idx] == '%' && core::add_sat_u64(i, 2) < total {
            let i1 = core::add_sat_u64(i, 1) as i64;
            let i2 = core::add_sat_u64(i, 2) as i64;
            let h = core::hex_digit_to_val(encoded[i1]);
            let l = core::hex_digit_to_val(encoded[i2]);
            if h >= 0 && l >= 0 {
                guard out.try_push((((h as u8) << 4) | (l as u8))) else { break; }
                i = core::add_sat_u64(i, 3);
                continue;
            }
        }
        guard out.try_push(encoded[idx]) else { break; }
        i = core::add_sat_u64(i, 1);
    }
}

// ---- grpc-timeout Codec (Units: H, M, S, m, u, n) -----------------------

// Formats millisecond duration into standard gRPC timeout string (max 8 digits per gRPC spec).
fn encode_timeout<B>(timeout_ms: u64, out: B&) {
    if timeout_ms == 0 {
        let _ = out.try_append("0m");
        return;
    }

    var tmp: u8[..16] = [];
    let max_val: u64 = 99999999;
    let hours = grpc_internal::div_u64(timeout_ms, 3600000);
    if hours <= max_val && core::mul_sat_u64(hours, 3600000) == timeout_ms {
        hours.format_u64_dec(tmp);
        tmp.push('H');
        let _ = out.try_append(tmp[..]);
        return;
    }

    let mins = grpc_internal::div_u64(timeout_ms, 60000);
    if mins <= max_val && core::mul_sat_u64(mins, 60000) == timeout_ms {
        mins.format_u64_dec(tmp);
        tmp.push('M');
        let _ = out.try_append(tmp[..]);
        return;
    }

    let secs = grpc_internal::div_u64(timeout_ms, 1000);
    if secs <= max_val && core::mul_sat_u64(secs, 1000) == timeout_ms {
        secs.format_u64_dec(tmp);
        tmp.push('S');
        let _ = out.try_append(tmp[..]);
        return;
    }

    if timeout_ms <= max_val {
        timeout_ms.format_u64_dec(tmp);
        tmp.push('m');
        let _ = out.try_append(tmp[..]);
        return;
    }

    let ceil_secs = grpc_internal::div_u64(core::add_sat_u64(timeout_ms, 999), 1000);
    if ceil_secs <= max_val {
        ceil_secs.format_u64_dec(tmp);
        tmp.push('S');
        let _ = out.try_append(tmp[..]);
        return;
    }

    let ceil_mins = grpc_internal::div_u64(core::add_sat_u64(timeout_ms, 59999), 60000);
    if ceil_mins <= max_val {
        ceil_mins.format_u64_dec(tmp);
        tmp.push('M');
        let _ = out.try_append(tmp[..]);
        return;
    }

    let ceil_hours = min(grpc_internal::div_u64(core::add_sat_u64(timeout_ms, 3599999), 3600000), max_val);
    ceil_hours.format_u64_dec(tmp);
    tmp.push('H');
    let _ = out.try_append(tmp[..]);
}

// Parses standard gRPC timeout string into milliseconds.
// Supports H (Hours), M (Minutes), S (Seconds), m (Millis), u (Micros), n (Nanos).
//
// Example:
//   val = "100m"
//   returns: 100, true
fn parse_timeout(val: const u8[:]) -> u64, bool {
    let trimmed = val.trim_lws();
    guard trimmed.len >= 2 else { return 0, false; }

    let last_idx = (core::sub_sat_u64(trimmed.len as u64, 1)) as i64;
    let unit = trimmed[last_idx];
    let num_slice = trimmed[..^1];

    guard num_slice.len <= 8 else { return 0, false; } // gRPC spec max 8 digits
    let num, ok_num = num_slice.parse_u64_dec();
    guard ok_num else { return 0, false; }

    return grpc_internal::convert_timeout_unit(num, unit);
}

// ---- Status Extraction from Headers & Trailers --------------------------

// Extracts gRPC status and message from trailers (or headers in Trailers-Only responses).
// Returns true if a wire grpc-status header was explicitly found.
// If absent, falls back to mapping the HTTP status code and returns false.
//
// Example:
//   headers = { ":status": "200" }, trailers = { "grpc-status": "0" }
//   returns: true, out_status = StatusCode.Ok
fn extract_status<B>(
    headers:     const http::HeaderMap&,
    trailers:    const http::HeaderMap&,
    out_status:  StatusCode&,
    out_message: B&,
) -> bool {
    out_message.clear();
    let http_code = grpc_internal::resolve_effective_http_status(headers);

    let trailer_status = trailers.get_header(rfc::HEADER_GRPC_STATUS);
    if trailer_status.len > 0 || trailers.has_header(rfc::HEADER_GRPC_STATUS) {
        let code_int, ok_code = trailer_status.trim_lws().parse_u32_dec();
        out_status = if ok_code { status_from_code(code_int) } else { StatusCode.Unknown };
        if http_code != 200 && out_status == StatusCode.Ok {
            out_status = status_from_http(http_code);
        }

        let trailer_msg = trailers.get_header(rfc::HEADER_GRPC_MESSAGE);
        if trailer_msg.len > 0 {
            decode_message(trailer_msg, out_message);
        }
        return true;
    }

    let header_status = headers.get_header(rfc::HEADER_GRPC_STATUS);
    if header_status.len > 0 || headers.has_header(rfc::HEADER_GRPC_STATUS) {
        let code_int, ok_code = header_status.trim_lws().parse_u32_dec();
        out_status = if ok_code { status_from_code(code_int) } else { StatusCode.Unknown };
        if http_code != 200 && out_status == StatusCode.Ok {
            out_status = status_from_http(http_code);
        }

        let header_msg = headers.get_header(rfc::HEADER_GRPC_MESSAGE);
        if header_msg.len > 0 {
            decode_message(header_msg, out_message);
        }
        return true;
    }

    out_status = status_from_http(http_code);
    return false;
}

// ---- Protowire Status Serialization (grpc-status-details-bin) ------------

// Serializes `google.rpc.Status` (`field 1 = code (varint, tag 0x08)`,
// `field 2 = message (length-delimited, tag 0x12)`) directly into `dst` without
// heap allocation or external `protoc` codegen.
// Enforces Invariant 13: returns `(0, false)` when `dst` capacity is insufficient.
//
// Example:
//   code = 3, msg = "bad", dst = [0; 16]
//   returns: (7, true), dst[0..7] = [0x08, 0x03, 0x12, 0x03, 'b', 'a', 'd']
fn build_status_details(code: i32, msg: const u8[:], dst: u8[:]) -> i32, bool {
    guard code >= 0 else { return 0, false; }
    let code_u64 = code as u64;
    let code_len = if code != 0 {
        core::add_sat_u64(1, grpc_internal::protowire_varint_len(code_u64))
    } else {
        2
    };
    let msg_len_u64 = msg.len as u64;
    let msg_total = if msg.len > 0 {
        core::add_sat_u64(
            core::add_sat_u64(1, grpc_internal::protowire_varint_len(msg_len_u64)),
            msg_len_u64,
        )
    } else {
        0
    };
    let required = core::add_sat_u64(code_len, msg_total);

    guard (dst.len as u64) >= required else { return 0, false; }

    var pos: u64 = 0;
    dst[pos as i64] = rfc::PROTO_TAG_STATUS_CODE;
    pos = core::add_sat_u64(pos, 1);
    grpc_internal::write_protowire_varint(code_u64, dst, pos);

    if msg.len > 0 {
        dst[pos as i64] = rfc::PROTO_TAG_STATUS_MESSAGE;
        pos = core::add_sat_u64(pos, 1);
        grpc_internal::write_protowire_varint(msg_len_u64, dst, pos);
        for i in msg.len {
            dst[pos as i64] = msg[i];
            pos = core::add_sat_u64(pos, 1);
        }
    }

    return pos as i32, true;
}

// Decodes Base64-encoded `grpc-status-details-bin` (`google.rpc.Status`) trailer.
// Enforces the `grpc-go` security invariant: if `google.rpc.Status.code` disagrees with
// `expected_code` (`grpc-status` trailer), `out_status` is overridden to `StatusCode.Internal`.
//
// Example:
//   b64_val = "CAMSA2JhZA==", expected_code = StatusCode.InvalidArgument
//   returns: true, out_status = InvalidArgument, out_msg = "bad"
fn decode_status_details<B>(
    b64_val:       const u8[:],
    expected_code: StatusCode,
    out_status:    StatusCode&,
    out_msg:       B&,
    out_details:   ErrorDetail[..4]&,
) -> bool {
    let trimmed = b64_val.trim_lws();
    guard trimmed.len > 0 else { return false; }
    var raw_pb: u8[..1024] = [];
    guard grpc_internal::decode_base64_into(trimmed, raw_pb) else { return false; }

    var proto_code:  u32              = 0;
    var tmp_msg:     u8[..256]        = [];
    var tmp_details: ErrorDetail[..4] = [];
    let wire = raw_pb[..];
    var idx: i64 = 0;
    while idx < wire.len {
        guard grpc_internal::parse_status_proto_field(wire, idx, proto_code, tmp_msg, tmp_details) else {
            return false;
        }
    }

    if proto_code != status_to_code(expected_code) {
        guard out_msg.try_set("grpc: status code mismatch in grpc-status-details-bin") else {
            return false;
        }
        out_status = StatusCode.Internal;
        out_details.clear();
        return true;
    }
    if tmp_msg.len > 0 {
        guard out_msg.try_set(tmp_msg[..]) else { return false; }
    }
    out_status = expected_code;
    out_details.clear();
    for &d in tmp_details {
        out_details.push(d);
    }
    return true;
}
