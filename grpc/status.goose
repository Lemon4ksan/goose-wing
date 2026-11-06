// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// gRPC status code management, percent-encoded grpc-message, and grpc-timeout codecs.
// Conforms to gRPC Over HTTP/2 Specification and RFC 3986.
namespace wing;

import std;
import core from "..";
import grpc.constants;
import http.headers;

// ---- Value-Returned GrpcStatus Constructors -----------------------------

fn grpc_ok() -> GrpcStatus {
    return GrpcStatus {
        code:    GrpcStatusCode.Ok,
        message: [],
    };
}

fn grpc_error(code: GrpcStatusCode, message: const u8[:]) -> GrpcStatus {
    var status = GrpcStatus {
        code:    code,
        message: [],
    };
    let take_len = min(message.len, 256);
    if take_len > 0 {
        status.message.append(message[..take_len]);
    }
    return status;
}

// ---- Hex Helpers & Percent Codec for grpc-message ------------------------

inline fn grpc_hex_val(c: u8) -> i32 {
    if c >= '0' && c <= '9' { return (core::sub_sat_u64(c, '0')) as i32; }
    if c >= 'a' && c <= 'f' { return (core::add_sat_u64(core::sub_sat_u64(c, 'a'), 10)) as i32; }
    if c >= 'A' && c <= 'F' { return (core::add_sat_u64(core::sub_sat_u64(c, 'A'), 10)) as i32; }
    return -1;
}

inline fn grpc_hex_char(n: u8) -> u8 {
    guard n < 10 else {
        return (core::add_sat_u64('A', core::sub_sat_u64(n, 10))) as u8;
    }
    return (core::add_sat_u64('0', n)) as u8;
}

inline fn is_grpc_message_unencoded(b: u8) -> bool {
    return b >= 0x20 && b <= 0x7E && b != '%';
}

// Percent-encodes message string for `grpc-message` header.
// Characters in 0x20..0x7E except '%' remain unescaped; all others are %XX encoded.
fn encode_grpc_message<B>(raw: const u8[:], out: B&, max_out_len: i64 = -1) {
    for b in raw {
        if is_grpc_message_unencoded(b) {
            if max_out_len >= 0 && out.len >= max_out_len { break; }
            out.push(b);
            continue;
        }
        if max_out_len >= 0 && core::add_sat_i64(out.len, 3) > max_out_len { break; }
        out.push('%');
        out.push(grpc_hex_char((b >> 4) & 0x0F));
        out.push(grpc_hex_char(b & 0x0F));
    }
}

inline fn combine_hex_nibbles(h: i32, l: i32) -> u8 {
    return (((h as u8) << 4) | (l as u8));
}

// Percent-decodes `grpc-message` header value into raw message bytes.
// Clamps decoded output to 256 bytes to prevent bounded-array overflow.
//
// Example:
//   encoded = "unknown%20error"
//   returns: out = "unknown error"
fn decode_grpc_message<B>(encoded: const u8[:], out: B&) {
    out.clear();
    var i: u64 = 0;
    let total = encoded.len as u64;
    while i < total {
        guard out.len < 256 else { break; }
        let idx = i as i64;
        if encoded[idx] == '%' && core::add_sat_u64(i, 2) < total {
            let i1 = core::add_sat_u64(i, 1) as i64;
            let i2 = core::add_sat_u64(i, 2) as i64;
            let h = grpc_hex_val(encoded[i1]);
            let l = grpc_hex_val(encoded[i2]);
            if h >= 0 && l >= 0 {
                out.push(combine_hex_nibbles(h, l));
                i = core::add_sat_u64(i, 3);
                continue;
            }
        }
        out.push(encoded[idx]);
        i = core::add_sat_u64(i, 1);
    }
}

// ---- grpc-timeout Codec (Units: H, M, S, m, u, n) -----------------------

// Zero-allocation binary division without arithmetic operator hazards.
fn grpc_div_u64(n: u64, d: u64) -> u64 {
    guard d > 0 else { return 0; }
    guard n >= d else { return 0; }

    var cur_d = d;
    var cur_q: u64 = 1;
    let half_n = n >> 1;

    while cur_d <= half_n {
        cur_d = core::add_sat_u64(cur_d, cur_d);
        cur_q = core::add_sat_u64(cur_q, cur_q);
    }

    var rem_n = n;
    var quotient: u64 = 0;

    while cur_q > 0 {
        if rem_n >= cur_d {
            rem_n = core::sub_sat_u64(rem_n, cur_d);
            quotient = quotient | cur_q;
        }
        cur_d = cur_d >> 1;
        cur_q = cur_q >> 1;
    }

    return quotient;
}

// Formats millisecond duration into standard gRPC timeout string.
fn encode_grpc_timeout<B>(timeout_ms: u64, out: B&) {
    guard timeout_ms > 0 else { return; }

    let hours = grpc_div_u64(timeout_ms, 3600000);
    if core::mul_sat_u64(hours, 3600000) == timeout_ms {
        core::format_u64_dec(hours, out);
        out.push('H');
        return;
    }

    let mins = grpc_div_u64(timeout_ms, 60000);
    if core::mul_sat_u64(mins, 60000) == timeout_ms {
        core::format_u64_dec(mins, out);
        out.push('M');
        return;
    }

    let secs = grpc_div_u64(timeout_ms, 1000);
    if core::mul_sat_u64(secs, 1000) == timeout_ms {
        core::format_u64_dec(secs, out);
        out.push('S');
        return;
    }

    core::format_u64_dec(timeout_ms, out);
    out.push('m');
}

// Converts parsed numeric timeout and unit character into milliseconds.
inline fn convert_grpc_timeout_unit(num: u64, unit: u8) -> u64, bool {
    if unit == 'H' { return core::mul_sat_u64(num, 3600000), true; }
    if unit == 'M' { return core::mul_sat_u64(num, 60000), true; }
    if unit == 'S' { return core::mul_sat_u64(num, 1000), true; }
    if unit == 'm' { return num, true; }
    if unit == 'u' {
        let ms = if num > 0 && num < 1000 { 1 } else { grpc_div_u64(num, 1000) };
        return ms, true;
    }
    if unit == 'n' {
        let ms = if num > 0 && num < 1000000 { 1 } else { grpc_div_u64(num, 1000000) };
        return ms, true;
    }
    return 0, false;
}

// Parses standard gRPC timeout string into milliseconds.
// Supports H (Hours), M (Minutes), S (Seconds), m (Millis), u (Micros), n (Nanos).
//
// Example:
//   val = "100m"
//   returns: 100, true
fn parse_grpc_timeout(val: const u8[:]) -> u64, bool {
    let trimmed = trim_lws(val);
    guard trimmed.len >= 2 else { return 0, false; }

    let last_idx = (core::sub_sat_u64(trimmed.len as u64, 1)) as i64;
    let unit = trimmed[last_idx];
    let num_slice = trimmed[..last_idx];

    guard num_slice.len <= 8 else { return 0, false; } // gRPC spec max 8 digits
    let num, ok_num = core::parse_u64_dec(num_slice);
    guard ok_num else { return 0, false; }

    return convert_grpc_timeout_unit(num, unit);
}

// ---- Status Extraction from Headers & Trailers --------------------------

// Extracts gRPC status and message from trailers (or headers in Trailers-Only responses).
// Returns true if a wire grpc-status header was explicitly found.
// If absent, falls back to mapping the HTTP status code and returns false.
//
// Example:
//   headers = { ":status": "200" }, trailers = { "grpc-status": "0" }
//   returns: true, out_status = GrpcStatusCode.Ok
fn extract_grpc_status(
    headers:     const HeaderMap&,
    trailers:    const HeaderMap&,
    out_status:  GrpcStatusCode&,
    out_message: u8[..256]&,
) -> bool {
    out_message.clear();

    // 1. Check trailers first
    let trailer_status = get_header(trailers, rfc::HEADER_GRPC_STATUS);
    if trailer_status.len > 0 {
        let code_int, ok_code = core::parse_u32_dec(trim_lws(trailer_status));
        if ok_code {
            out_status = grpc_status_from_code(code_int);
        } else {
            out_status = GrpcStatusCode.Unknown;
        }

        let trailer_msg = get_header(trailers, rfc::HEADER_GRPC_MESSAGE);
        if trailer_msg.len > 0 {
            decode_grpc_message(trailer_msg, out_message);
        }
        return true;
    }

    // 2. Check headers (Trailers-Only response)
    let header_status = get_header(headers, rfc::HEADER_GRPC_STATUS);
    if header_status.len > 0 {
        let code_int, ok_code = core::parse_u32_dec(trim_lws(header_status));
        if ok_code {
            out_status = grpc_status_from_code(code_int);
        } else {
            out_status = GrpcStatusCode.Unknown;
        }

        let header_msg = get_header(headers, rfc::HEADER_GRPC_MESSAGE);
        if header_msg.len > 0 {
            decode_grpc_message(header_msg, out_message);
        }
        return true;
    }

    // 3. Fallback to HTTP status mapping
    out_status = grpc_status_from_http(headers.status_code);
    return false;
}

// ---- Protowire Status Serialization (grpc-status-details-bin) ------------

// Computes encoded byte length of an unsigned 64-bit Protobuf Base-128 VarInt.
inline fn protowire_varint_len(val: u64) -> u64 {
    var v = val;
    var n: u64 = 1;
    while v >= 0x80 {
        v = v >> 7;
        n = core::add_sat_u64(n, 1);
    }
    return n;
}

// Writes an unsigned 64-bit Protobuf Base-128 VarInt into `dst` starting at `pos`.
inline fn write_protowire_varint(val: u64, dst: u8[:], pos: u64&) {
    var v = val;
    while v >= 0x80 {
        dst[pos as i64] = ((v & 0x7F) as u8) | 0x80;
        pos = core::add_sat_u64(pos, 1);
        v = v >> 7;
    }
    dst[pos as i64] = (v & 0x7F) as u8;
    pos = core::add_sat_u64(pos, 1);
}

// Serializes `google.rpc.Status` (`field 1 = code (varint, tag 0x08)`,
// `field 2 = message (length-delimited, tag 0x12)`) directly into `dst` without
// heap allocation or external `protoc` codegen.
// Enforces Invariant 13: returns `(0, false)` when `dst` capacity is insufficient.
//
// Example:
//   code = 3, msg = "bad", dst = [0; 16]
//   returns: (7, true), dst[0..7] = [0x08, 0x03, 0x12, 0x03, 'b', 'a', 'd']
fn build_grpc_status_details(code: i32, msg: const u8[:], dst: u8[:]) -> i32, bool {
    guard code >= 0 else { return 0, false; }
    let code_u64 = code as u64;
    let code_len = if code != 0 { core::add_sat_u64(1, protowire_varint_len(code_u64)) } else { 2 };
    let msg_len_u64 = msg.len as u64;
    let msg_total = if msg.len > 0 {
        core::add_sat_u64(core::add_sat_u64(1, protowire_varint_len(msg_len_u64)), msg_len_u64)
    } else {
        0
    };
    let required = core::add_sat_u64(code_len, msg_total);

    guard (dst.len as u64) >= required else { return 0, false; }

    var pos: u64 = 0;
    dst[pos as i64] = rfc::PROTO_TAG_STATUS_CODE;
    pos = core::add_sat_u64(pos, 1);
    write_protowire_varint(code_u64, dst, pos);

    if msg.len > 0 {
        dst[pos as i64] = rfc::PROTO_TAG_STATUS_MESSAGE;
        pos = core::add_sat_u64(pos, 1);
        write_protowire_varint(msg_len_u64, dst, pos);
        for i in msg.len {
            dst[pos as i64] = msg[i];
            pos = core::add_sat_u64(pos, 1);
        }
    }

    return pos as i32, true;
}
