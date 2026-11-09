// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// gRPC status code management, percent-encoded grpc-message, and grpc-timeout codecs.
// Conforms to gRPC Over HTTP/2 Specification and RFC 3986.
namespace wing;

import std;
import core from "..";
import grpc.constants;
import grpc.framing;
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
    let take_len = min(message.len, status.message.cap);
    let _ = status.message.try_set(message[..take_len]);
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
            guard out.try_push(b) else { break; }
            continue;
        }
        if max_out_len >= 0 && core::add_sat_i64(out.len, 3) > max_out_len { break; }
        var esc: u8[3] = ['%', grpc_hex_char((b >> 4) & 0x0F), grpc_hex_char(b & 0x0F)];
        guard out.try_append(esc[..]) else { break; }
    }
}

inline fn combine_hex_nibbles(h: i32, l: i32) -> u8 {
    return (((h as u8) << 4) | (l as u8));
}

// Percent-decodes `grpc-message` header value into raw message bytes.
// Clamps decoded output to 256 bytes and target buffer capacity to prevent overflow.
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
                guard out.try_push(combine_hex_nibbles(h, l)) else { break; }
                i = core::add_sat_u64(i, 3);
                continue;
            }
        }
        guard out.try_push(encoded[idx]) else { break; }
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

// Formats millisecond duration into standard gRPC timeout string (max 8 digits per gRPC spec).
fn encode_grpc_timeout<B>(timeout_ms: u64, out: B&) {
    guard timeout_ms > 0 else { return; }

    var tmp: u8[..16] = [];
    let max_val: u64 = 99999999;
    let hours = grpc_div_u64(timeout_ms, 3600000);
    if hours <= max_val && core::mul_sat_u64(hours, 3600000) == timeout_ms {
        hours.format_u64_dec(tmp);
        tmp.push('H');
        let _ = out.try_append(tmp[..]);
        return;
    }

    let mins = grpc_div_u64(timeout_ms, 60000);
    if mins <= max_val && core::mul_sat_u64(mins, 60000) == timeout_ms {
        mins.format_u64_dec(tmp);
        tmp.push('M');
        let _ = out.try_append(tmp[..]);
        return;
    }

    let secs = grpc_div_u64(timeout_ms, 1000);
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

    let ceil_secs = grpc_div_u64(core::add_sat_u64(timeout_ms, 999), 1000);
    if ceil_secs <= max_val {
        ceil_secs.format_u64_dec(tmp);
        tmp.push('S');
        let _ = out.try_append(tmp[..]);
        return;
    }

    let ceil_mins = grpc_div_u64(core::add_sat_u64(timeout_ms, 59999), 60000);
    if ceil_mins <= max_val {
        ceil_mins.format_u64_dec(tmp);
        tmp.push('M');
        let _ = out.try_append(tmp[..]);
        return;
    }

    let ceil_hours = min(grpc_div_u64(core::add_sat_u64(timeout_ms, 3599999), 3600000), max_val);
    ceil_hours.format_u64_dec(tmp);
    tmp.push('H');
    let _ = out.try_append(tmp[..]);
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
    let trimmed = val.trim_lws();
    guard trimmed.len >= 2 else { return 0, false; }

    let last_idx = (core::sub_sat_u64(trimmed.len as u64, 1)) as i64;
    let unit = trimmed[last_idx];
    let num_slice = trimmed[..^1];

    guard num_slice.len <= 8 else { return 0, false; } // gRPC spec max 8 digits
    let num, ok_num = num_slice.parse_u64_dec();
    guard ok_num else { return 0, false; }

    return convert_grpc_timeout_unit(num, unit);
}

// ---- Status Extraction from Headers & Trailers --------------------------

inline fn resolve_effective_http_status(headers: const HeaderMap&) -> i32 {
    if headers.status_code != 200 {
        return headers.status_code as u16;
    }
    let pseudo_st = get_header(headers, ":status").trim_lws();
    if pseudo_st.len > 0 {
        let code_u32, ok_st = pseudo_st.parse_u32_dec();
        if ok_st && code_u32 >= 100 && code_u32 <= 599 {
            return code_u32 as i32;
        }
        return 500;
    }
    return 200;
}

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
    let http_code = resolve_effective_http_status(headers);

    // 1. Check trailers first
    let trailer_status = get_header(trailers, rfc::HEADER_GRPC_STATUS);
    if trailer_status.len > 0 || has_header(trailers, rfc::HEADER_GRPC_STATUS) {
        let code_int, ok_code = trailer_status.trim_lws().parse_u32_dec();
        if ok_code {
            out_status = grpc_status_from_code(code_int);
        } else {
            out_status = GrpcStatusCode.Unknown;
        }
        if http_code != 200 && out_status == GrpcStatusCode.Ok {
            out_status = grpc_status_from_http(http_code);
        }

        let trailer_msg = get_header(trailers, rfc::HEADER_GRPC_MESSAGE);
        if trailer_msg.len > 0 {
            decode_grpc_message(trailer_msg, out_message);
        }
        return true;
    }

    // 2. Check headers (Trailers-Only response)
    let header_status = get_header(headers, rfc::HEADER_GRPC_STATUS);
    if header_status.len > 0 || has_header(headers, rfc::HEADER_GRPC_STATUS) {
        let code_int, ok_code = header_status.trim_lws().parse_u32_dec();
        if ok_code {
            out_status = grpc_status_from_code(code_int);
        } else {
            out_status = GrpcStatusCode.Unknown;
        }
        if http_code != 200 && out_status == GrpcStatusCode.Ok {
            out_status = grpc_status_from_http(http_code);
        }

        let header_msg = get_header(headers, rfc::HEADER_GRPC_MESSAGE);
        if header_msg.len > 0 {
            decode_grpc_message(header_msg, out_message);
        }
        return true;
    }

    // 3. Fallback to HTTP status mapping
    out_status = grpc_status_from_http(http_code);
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

// Decodes a single `google.protobuf.Any` submessage (`field 1 = type_url`, `field 2 = value`).
//
// Example:
//   wire = [0x0A, 0x04, 't', 'y', 'p', 'e', 0x12, 0x02, 0x01, 0x02]
//   returns: true, out_detail.type_url = "type", out_detail.value = [0x01, 0x02]
fn decode_grpc_any_detail(wire: const u8[:], out_detail: GrpcErrorDetail&) -> bool {
    out_detail.type_url.clear();
    out_detail.value.clear();
    var committed = false;
    defer if !committed {
        out_detail.type_url.clear();
        out_detail.value.clear();
    };
    let type_slice, ok_type = pb_read_bytes_field(wire, 1);
    if ok_type {
        guard out_detail.type_url.try_set(type_slice) else { return false; }
    }
    let val_slice, ok_val = pb_read_bytes_field(wire, 2);
    if ok_val {
        guard out_detail.value.try_set(val_slice) else { return false; }
    }
    guard ok_type || ok_val else { return false; }
    committed = true;
    return true;
}

// Parses a single wire field from a `google.rpc.Status` protobuf payload.
//
// Example:
//   wire = [0x08, 0x03], pos = 0
//   returns: true, pos = 2, out_code = 3
fn parse_grpc_status_proto_field(
    wire:        const u8[:],
    pos:         i64&,
    out_code:    u32&,
    out_msg:     u8[..256]&,
    out_details: GrpcErrorDetail[..4]&,
) -> bool {
    let saved_pos = pos;
    var committed = false;
    defer if !committed { pos = saved_pos; };
    let tag, ok_tag = pb_read_varint(wire, pos);
    let raw_fnum = tag >> 3;
    guard ok_tag && raw_fnum >= 1 && raw_fnum <= PB_MAX_FIELD_NUM else { return false; }
    let fnum = raw_fnum as u32;
    let wtype = (tag & 0x07) as u32;
    if fnum == 1 && wtype == PB_WIRE_VARINT {
        let v, ok_v = pb_read_varint(wire, pos);
        guard ok_v && v <= 16 else { return false; }
        out_code = v as u32;
        committed = true;
        return true;
    }
    guard (fnum == 2 || fnum == 3) && wtype == PB_WIRE_LEN else {
        guard pb_skip_field(wire, pos, wtype) else { return false; }
        committed = true;
        return true;
    }
    let len_u64, ok_l = pb_read_varint(wire, pos);
    let rem = core::sub_sat_i64(wire.len, pos);
    guard ok_l && len_u64 <= (rem as u64) else { return false; }
    let end_pos = core::add_sat_i64(pos, len_u64 as i64);
    let slice = wire[pos..end_pos];
    pos = end_pos;
    committed = true;
    if fnum == 2 {
        let take_len = min(slice.len, out_msg.cap);
        let _ = out_msg.try_set(slice[..take_len]);
        return true;
    }
    guard out_details.len < out_details.cap else { return true; }
    var detail = GrpcErrorDetail { .. };
    if decode_grpc_any_detail(slice, detail) {
        let _ = out_details.try_push(detail);
    }
    return true;
}

// Decodes Base64-encoded `grpc-status-details-bin` (`google.rpc.Status`) trailer.
// Enforces the `grpc-go` security invariant: if `google.rpc.Status.code` disagrees with
// `expected_code` (`grpc-status` trailer), `out_status` is overridden to `GrpcStatusCode.Internal`.
//
// Example:
//   b64_val = "CAMSA2JhZA==", expected_code = GrpcStatusCode.InvalidArgument
//   returns: true, out_status = InvalidArgument, out_msg = "bad"
fn decode_grpc_status_details(
    b64_val:       const u8[:],
    expected_code: GrpcStatusCode,
    out_status:    GrpcStatusCode&,
    out_msg:       u8[..256]&,
    out_details:   GrpcErrorDetail[..4]&,
) -> bool {
    let trimmed = b64_val.trim_lws();
    guard trimmed.len > 0 else { return false; }
    var raw_pb: u8[..1024] = [];
    var ok_b64 = core::base64_decode(trimmed, raw_pb);
    if !ok_b64 {
        ok_b64 = core::base64url_decode(trimmed, raw_pb);
    }
    guard ok_b64 else { return false; }

    var proto_code:  u32                  = 0;
    var tmp_msg:     u8[..256]            = [];
    var tmp_details: GrpcErrorDetail[..4] = [];
    let wire = raw_pb[..];
    var pos: i64 = 0;
    while pos < wire.len {
        guard parse_grpc_status_proto_field(wire, pos, proto_code, tmp_msg, tmp_details) else {
            return false;
        }
    }

    if proto_code != grpc_status_to_code(expected_code) {
        out_status = GrpcStatusCode.Internal;
        let _ = out_msg.try_set("grpc: status code mismatch in grpc-status-details-bin");
        out_details.clear();
        return true;
    }
    out_status = expected_code;
    if tmp_msg.len > 0 {
        let _ = out_msg.try_set(tmp_msg[..]);
    }
    out_details.clear();
    for &d in tmp_details {
        out_details.push(d);
    }
    return true;
}
