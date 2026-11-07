// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// gRPC Length-Prefixed Message (LPM) binary framer and gRPC-Web codec.
// Conforms to gRPC HTTP/2 Wire Protocol Specification and gRPC-Web Protocol.
namespace wing;

import std;
import core from "..";
import grpc.constants;
import grpc.status;
import http.headers;
import http.mime;

// ---- Length-Prefixed Message (LPM) Framing ------------------------------

// Encodes a payload into a 5-byte Length-Prefixed Message (LPM):
// [1-byte Flag] [4-byte Big-Endian Length] [Payload]
// When `compressed` is true, `payload` is Gzip-compressed before framing.
fn encode_grpc_lpm<B>(payload: const u8[:], out: B&, compressed: bool = false) {
    if compressed {
        var gz_buf: u8[>..] = [];
        if core::gzip_compress(payload, gz_buf, 6) {
            var hdr_c: u8[..8] = [];
            hdr_c.push(rfc::GRPC_FLAG_COMPRESSED);
            core::write_be_u32(hdr_c, gz_buf.len as u32);
            guard out.try_append(hdr_c[..]) else { return; }
            let _ = out.try_append(gz_buf[..]);
            return;
        }
    }
    var hdr_u: u8[..8] = [];
    hdr_u.push(0x00);
    core::write_be_u32(hdr_u, payload.len as u32);
    guard out.try_append(hdr_u[..]) else { return; }
    let _ = out.try_append(payload);
}

// Decodes a single LPM frame starting at offset in wire bytes without buffer copying.
// Returns (payload_slice, is_compressed, bytes_consumed, ok).
//
// Example:
//   wire = [0x00, 0x00, 0x00, 0x00, 0x05, "hello"], offset = 0
//   returns: payload = "hello", is_comp = false, consumed = 10, ok = true
fn decode_grpc_lpm_slice(wire: const u8[:], offset: u32) -> const u8[:], bool, u32, bool {
    let off = offset as i64;
    guard off >= 0 && off <= wire.len else { return "", false, 0, false; }
    guard wire.len - off >= rfc::GRPC_LPM_HEADER_LEN else { return "", false, 0, false; }

    let flag = wire[off];
    guard (flag & ~rfc::GRPC_FLAG_COMPRESSED) == 0 else { return "", false, 0, false; }
    let is_compressed = (flag & rfc::GRPC_FLAG_COMPRESSED) != 0;

    let len_val_i64 = (core::read_be_u32(wire, off + 1)) as i64;
    guard (wire.len - off - rfc::GRPC_LPM_HEADER_LEN) >= len_val_i64 else { return "", false, 0, false; }

    let p_start = off + rfc::GRPC_LPM_HEADER_LEN;
    let total_consumed = (rfc::GRPC_LPM_HEADER_LEN + len_val_i64) as u32;
    return wire[p_start..p_start + len_val_i64], is_compressed, total_consumed, true;
}

// Decodes a single LPM frame starting at offset in wire bytes.
// Target buffer is cleared only after wire format validation succeeds.
//
// Example:
//   wire = [0x00, 0x00, 0x00, 0x00, 0x05, "hello"], offset = 0
//   returns: ok = true, consumed = 10, out_payload = "hello", out_compressed = false
fn decode_grpc_lpm<B>(wire: const u8[:], offset: u32, out_payload: B&, out_compressed: bool&) -> bool, u32 {
    let payload_slice, is_comp, consumed, ok = decode_grpc_lpm_slice(wire, offset);
    guard ok else { return false, 0; }
    out_payload.clear();
    guard out_payload.try_append(payload_slice) else { return false, 0; }
    out_compressed = is_comp;
    return true, consumed;
}

// ---- Incremental Streaming LPM Parser -----------------------------------

// Reassembles LPM messages arriving across fragmented HTTP/2 or HTTP/3 DATA chunks.
struct GrpcStreamParser {
    max_size: u32     = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE,
    read_pos: i64     = 0,
    buf:      u8[>..] = [],
}

fn new_grpc_stream_parser(max_msg_size: u32 = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE) -> GrpcStreamParser {
    return GrpcStreamParser {
        max_size: max_msg_size,
        read_pos: 0,
        buf:      [],
    };
}

fn reset(p: GrpcStreamParser&) {
    p.read_pos = 0;
    p.buf.clear();
}

fn feed(p: GrpcStreamParser&, chunk: const u8[:]) -> bool {
    let unread_len = core::sub_sat_i64(p.buf.len, p.read_pos) as u64;
    let cur_total = core::add_sat_u64(unread_len, chunk.len as u64);
    let max_wire = core::add_sat_u64(p.max_size, rfc::GRPC_LPM_HEADER_LEN);
    guard cur_total <= max_wire else { return false; }
    if p.read_pos > 0 {
        if p.read_pos >= p.buf.len {
            p.buf.clear();
            p.read_pos = 0;
        } else if core::add_sat_u64(p.buf.len as u64, chunk.len as u64) > max_wire {
            core::compact_wire_buffer(p.buf, p.read_pos);
            p.read_pos = 0;
        }
    }
    p.buf.append(chunk);
    return true;
}

// Extracts the next available message. Returns true if a full message was consumed.
fn next_message<B>(p: GrpcStreamParser&, out_payload: B&, out_compressed: bool&) -> bool {
    let rem = core::sub_sat_i64(p.buf.len, p.read_pos);
    guard p.read_pos >= 0 && rem >= (rfc::GRPC_LPM_HEADER_LEN as i64) else { return false; }

    let pos = p.read_pos;
    let flag = p.buf[pos];
    guard (flag & ~rfc::GRPC_FLAG_COMPRESSED) == 0 else { return false; }

    let len_val_i64 = (core::read_be_u32(p.buf[..], core::add_sat_i64(pos, 1))) as i64;
    let total_len = core::add_sat_i64(rfc::GRPC_LPM_HEADER_LEN, len_val_i64);
    guard len_val_i64 <= (p.max_size as i64) && rem >= total_len else { return false; }

    out_payload.clear();
    let payload_start = core::add_sat_i64(pos, rfc::GRPC_LPM_HEADER_LEN);
    let payload_end = core::add_sat_i64(pos, total_len);
    guard out_payload.try_append(p.buf[payload_start..payload_end]) else { return false; }
    out_compressed = (flag & rfc::GRPC_FLAG_COMPRESSED) != 0;
    p.read_pos = payload_end;
    if p.read_pos >= p.buf.len {
        p.buf.clear();
        p.read_pos = 0;
    }
    return true;
}

// ---- gRPC-Web Framing (Trailers-in-Body) ---------------------------------

// Returns true when `key` and `val` are safe custom gRPC metadata / trailer fields
// (valid HTTP token key, printable HTTP field value without CR/LF/NUL, and not a
// reserved protocol control header).
fn is_valid_grpc_custom_metadata(key: const u8[:], val: const u8[:]) -> bool {
    guard key.len > 0 && key[0] != ':' else { return false; }
    guard !core::eq_ascii_fold(key, rfc::HEADER_GRPC_STATUS) else { return false; }
    guard !core::eq_ascii_fold(key, rfc::HEADER_GRPC_MESSAGE) else { return false; }
    guard !core::eq_ascii_fold(key, rfc::HEADER_GRPC_STATUS_DETAILS_BIN) else { return false; }
    guard !core::eq_ascii_fold(key, "content-type") else { return false; }
    guard !core::eq_ascii_fold(key, "te") else { return false; }
    for b in key {
        guard core::is_tchar(b) else { return false; }
    }
    for v in val {
        guard v == '\t' || (v >= 0x20 && v <= 0x7E) || v >= 0x80 else { return false; }
    }
    return true;
}

// Encodes gRPC-Web trailers frame into body payload with flag 0x80.
// Trailer format: "grpc-status: <status>\r\ngrpc-message: <message>\r\n[custom-trailers]\r\n"
fn encode_grpc_web_trailers_with_meta<B>(
    status:         GrpcStatusCode,
    message:        const u8[:],
    extra_trailers: const GrpcMetadata[:],
    out:            B&,
) {
    var trailer_body: u8[..1024] = [];
    trailer_body.append("grpc-status: ");
    core::format_i64_dec(grpc_status_to_code(status) as i64, trailer_body);
    trailer_body.append("\r\n");

    if message.len > 0 {
        var enc_msg: u8[>..] = [];
        encode_grpc_message(message, enc_msg);
        let max_msg_bytes = (trailer_body.cap - trailer_body.len - 18) as i64;
        var take_len = min(enc_msg.len, max_msg_bytes);
        if take_len < enc_msg.len && take_len >= 1 && enc_msg[take_len - 1] == '%' {
            take_len -= 1;
        } else if take_len < enc_msg.len && take_len >= 2 && enc_msg[take_len - 2] == '%' {
            take_len -= 2;
        }
        if take_len > 0 {
            trailer_body.append("grpc-message: ");
            trailer_body.append(enc_msg[..take_len]);
            trailer_body.append("\r\n");
        }
    }

    for &m in extra_trailers {
        let line_len = core::add_sat_i64(core::add_sat_i64(m.key.len, m.value.len), 4);
        let rem_cap = core::sub_sat_i64(trailer_body.cap, trailer_body.len);
        if is_valid_grpc_custom_metadata(m.key[..], m.value[..]) && rem_cap >= line_len {
            trailer_body.append(m.key[..]);
            trailer_body.append(": ");
            trailer_body.append(m.value[..]);
            trailer_body.append("\r\n");
        }
    }

    var tr_hdr: u8[..8] = [];
    tr_hdr.push(rfc::GRPC_WEB_FLAG_TRAILERS);
    core::write_be_u32(tr_hdr, trailer_body.len as u32);
    guard out.try_append(tr_hdr[..]) else { return; }
    let _ = out.try_append(trailer_body[..]);
}

fn encode_grpc_web_trailers<B>(status: GrpcStatusCode, message: const u8[:], out: B&) {
    let empty_trailers: GrpcMetadata[0] = [];
    encode_grpc_web_trailers_with_meta(status, message, empty_trailers[..], out);
}

// Decodes a gRPC-Web frame (distinguishing data messages from trailer frames).
//
// Example:
//   wire = [0x80, 0x00, 0x00, 0x00, 0x0B, "grpc-status"], offset = 0
//   returns: ok = true, total_len = 16, out_is_trailers = true, out_compressed = false
fn decode_grpc_web_frame<B>(
    wire:            const u8[:],
    offset:          u32,
    out_payload:     B&,
    out_is_trailers: bool&,
    out_compressed:  bool&,
) -> bool, u32 {
    let off = offset as i64;
    let rem = core::sub_sat_i64(wire.len, off);
    guard off >= 0 && rem >= 5 else { return false, 0; }

    let flag = wire[off];
    guard (flag & ~(rfc::GRPC_FLAG_COMPRESSED | rfc::GRPC_WEB_FLAG_TRAILERS)) == 0 else { return false, 0; }

    let len_val_i64 = (core::read_be_u32(wire, core::add_sat_i64(off, 1))) as i64;
    let total_len = core::add_sat_i64(5, len_val_i64);
    guard len_val_i64 <= 0xFFFFFFFA && rem >= total_len else { return false, 0; }

    out_payload.clear();
    let start_idx = core::add_sat_i64(off, 5);
    let end_idx = core::add_sat_i64(off, total_len);
    guard out_payload.try_append(wire[start_idx..end_idx]) else { return false, 0; }
    out_is_trailers = (flag & rfc::GRPC_WEB_FLAG_TRAILERS) != 0;
    out_compressed = (flag & rfc::GRPC_FLAG_COMPRESSED) != 0;

    return true, total_len as u32;
}

// Parses a single gRPC-Web trailer header line ("name: value").
//
// Example:
//   line = "grpc-status: 0"
//   returns: true, out_status = GrpcStatusCode.Ok
fn parse_grpc_web_trailer_line(
    line:        const u8[:],
    out_status:  GrpcStatusCode&,
    out_message: u8[..256]&,
) -> bool {
    let name, raw_val, ok_split = core::split_once_byte(line, ':');
    guard ok_split && name.len > 0 else { return false; }
    let val = core::trim_lws(raw_val);
    if core::eq_ascii_fold(name, "grpc-status") {
        let status_int, ok_code = core::parse_u32_dec(val);
        if !ok_code {
            if val.len > 0 {
                out_status = GrpcStatusCode.Unknown;
            }
            return false;
        }
        out_status = grpc_status_from_code(status_int);
        return true;
    }
    if core::eq_ascii_fold(name, "grpc-message") {
        out_message.clear();
        decode_grpc_message(val, out_message);
    }
    return false;
}

// Parses gRPC-Web body trailers block (HTTP/1-style headers) to extract status and message.
//
// Example:
//   trailer_bytes = "grpc-status: 0\r\ngrpc-message: OK\r\n"
//   returns: true, out_status = GrpcStatusCode.Ok, out_message = "OK"
fn parse_grpc_web_trailers(
    trailer_bytes: const u8[:],
    out_status:    GrpcStatusCode&,
    out_message:   u8[..256]&,
) -> bool {
    out_status = GrpcStatusCode.Ok;
    out_message.clear();

    var cursor: i64 = 0;
    var found_status = false;

    while cursor < trailer_bytes.len {
        let rel_nl = core::index_of_byte(trailer_bytes[cursor..], '\n');
        let line_end = if rel_nl >= 0 { cursor + rel_nl } else { trailer_bytes.len };

        var line = trailer_bytes[cursor..line_end];
        if core::ends_with(line, "\r") {
            line = line[..(line.len - 1)];
        }

        if parse_grpc_web_trailer_line(line, out_status, out_message) {
            found_status = true;
        }

        cursor = line_end + 1;
    }

    return found_status;
}

// ---- gRPC-Web Text Base64 Codec -----------------------------------------

// Encodes binary LPM wire stream into standard Base64 for application/grpc-web-text.
fn encode_grpc_web_text<B>(binary_lpm: const u8[:], out: B&) {
    core::base64_encode(binary_lpm, out);
}

// Decodes application/grpc-web-text Base64 stream into raw binary LPM stream.
// Supports both single Base64 blocks and concatenated 4-byte-aligned padded chunks.
//
// Example:
//   b64_stream = "AAAAAAA="
//   returns: true, out = [0, 0, 0, 0, 0]
fn decode_grpc_web_text<B>(b64_stream: const u8[:], out: B&) -> bool {
    out.clear();
    let total = b64_stream.len as u64;
    guard (total & 3) == 0 else { return false; }
    guard total > 0 else { return true; }

    var seg_start: i64     = 0;
    var chunk_buf: u8[>..] = [];
    var q:         u64     = 0;
    while q < total {
        let idx2 = core::add_sat_u64(q, 2) as i64;
        let idx3 = core::add_sat_u64(q, 3) as i64;
        let is_padded_end = b64_stream[idx3] == '=' || b64_stream[idx2] == '=';
        q = core::add_sat_u64(q, 4);
        if is_padded_end || q == total {
            let seg_end = q as i64;
            chunk_buf.clear();
            if !core::base64_decode(b64_stream[seg_start..seg_end], chunk_buf) || !out.try_append(chunk_buf[..]) {
                out.clear();
                return false;
            }
            seg_start = seg_end;
        }
    }
    return true;
}

// ---- Zero-Copy Base-128 Varint Protobuf Wire Primitives -----------------

const PB_WIRE_VARINT:   u32 = 0;
const PB_WIRE_I64:      u32 = 1;
const PB_WIRE_LEN:      u32 = 2;
const PB_WIRE_I32:      u32 = 5;
const PB_MAX_FIELD_NUM: u32 = 0x1FFFFFFF;

inline fn merge_varint_septet(acc: u64, b: u8, shift: u64) -> u64 {
    return acc | (((b & 0x7F) as u64) << (shift & 63));
}

// Reads a Base-128 Varint from `wire` starting at `pos`.
// Advances `pos` only when a complete, valid 64-bit varint is decoded.
//
// Example:
//   wire = [0xAC, 0x02], pos = 0
//   returns: val = 300, ok = true, pos = 2
fn pb_read_varint(wire: const u8[:], pos: i64&) -> u64, bool {
    let rem = core::sub_sat_i64(wire.len, pos);
    guard pos >= 0 && rem > 0 else { return 0, false; }
    let max_steps = min(rem, 10);
    var result: u64 = 0;
    var shift:  u64 = 0;
    var step:   i64 = 0;
    while step < max_steps {
        let idx = core::add_sat_i64(pos, step);
        let b = wire[idx];
        if step == 9 && b > 1 { return 0, false; }
        result = merge_varint_septet(result, b, shift);
        if (b & 0x80) == 0 {
            pos = core::add_sat_i64(idx, 1);
            return result, true;
        }
        shift = core::add_sat_u64(shift, 7);
        step = core::add_sat_i64(step, 1);
    }
    return 0, false;
}

// Appends a Base-128 Varint representation of `val` into `out`.
fn pb_write_varint<B>(val: u64, out: B&) -> bool {
    let req_len = protowire_varint_len(val) as i64;
    let needed = core::add_sat_i64(out.len, req_len);
    guard needed <= out.cap else { return false; }
    var v = val;
    while v >= 0x80 {
        out.push(((v & 0x7F) as u8) | 0x80);
        v = v >> 7;
    }
    out.push((v & 0x7F) as u8);
    return true;
}

// Advances `pos` past a single Protobuf field value of type `wire_type`.
// Leaves `pos` unchanged if the field is truncated or `wire_type` is unsupported.
//
// Example:
//   wire = [0x03, 'a', 'b', 'c'], pos = 0, wire_type = 2
//   returns: true, pos = 4
fn pb_skip_field(wire: const u8[:], pos: i64&, wire_type: u32) -> bool {
    let rem = core::sub_sat_i64(wire.len, pos);
    guard pos >= 0 && rem > 0 else { return false; }
    if wire_type == PB_WIRE_VARINT {
        var cur = pos;
        let _, ok = pb_read_varint(wire, cur);
        if ok { pos = cur; }
        return ok;
    }
    if wire_type == PB_WIRE_I64 {
        guard rem >= 8 else { return false; }
        pos = core::add_sat_i64(pos, 8);
        return true;
    }
    if wire_type == PB_WIRE_LEN {
        var cur = pos;
        let len_u64, ok = pb_read_varint(wire, cur);
        let tail = core::sub_sat_i64(wire.len, cur);
        guard ok && len_u64 <= (tail as u64) else { return false; }
        pos = core::add_sat_i64(cur, len_u64 as i64);
        return true;
    }
    if wire_type == PB_WIRE_I32 {
        guard rem >= 4 else { return false; }
        pos = core::add_sat_i64(pos, 4);
        return true;
    }
    return false;
}

// Scans Protobuf TLV records in `wire` and returns the varint value for `field_num`.
//
// Example:
//   wire = [0x08, 0x96, 0x01], field_num = 1
//   returns: val = 150, ok = true
fn pb_read_varint_field(wire: const u8[:], field_num: u32) -> u64, bool {
    guard field_num >= 1 && field_num <= PB_MAX_FIELD_NUM else { return 0, false; }
    var pos: i64 = 0;
    while pos < wire.len {
        let tag, ok_tag = pb_read_varint(wire, pos);
        let raw_fnum = tag >> 3;
        guard ok_tag && raw_fnum >= 1 && raw_fnum <= PB_MAX_FIELD_NUM else { return 0, false; }
        let fnum = raw_fnum as u32;
        let wtype = (tag & 0x07) as u32;
        if fnum == field_num && wtype == PB_WIRE_VARINT {
            return pb_read_varint(wire, pos);
        }
        guard pb_skip_field(wire, pos, wtype) else { return 0, false; }
    }
    return 0, false;
}

// Encodes a Protobuf varint field (`wire_type = 0`) for `field_num` into `out`.
fn pb_write_varint_field<B>(field_num: u32, val: u64, out: B&) -> bool {
    let tag = (((field_num & PB_MAX_FIELD_NUM) as u64) << 3) | (PB_WIRE_VARINT as u64);
    let total_len = core::add_sat_u64(protowire_varint_len(tag), protowire_varint_len(val)) as i64;
    let needed = core::add_sat_i64(out.len, total_len);
    guard field_num >= 1 && field_num <= PB_MAX_FIELD_NUM && needed <= out.cap else { return false; }
    let _ = pb_write_varint(tag, out);
    return pb_write_varint(val, out);
}

// Scans Protobuf TLV records in `wire` and returns a zero-copy byte slice for `field_num`.
//
// Example:
//   wire = [0x0A, 0x05, 'A', 'l', 'i', 'c', 'e'], field_num = 1
//   returns: slice = "Alice", ok = true
fn pb_read_bytes_field(wire: const u8[:], field_num: u32) -> const u8[:], bool {
    guard field_num >= 1 && field_num <= PB_MAX_FIELD_NUM else { return "", false; }
    var pos: i64 = 0;
    while pos < wire.len {
        let tag, ok_tag = pb_read_varint(wire, pos);
        let raw_fnum = tag >> 3;
        guard ok_tag && raw_fnum >= 1 && raw_fnum <= PB_MAX_FIELD_NUM else { return "", false; }
        let fnum = raw_fnum as u32;
        let wtype = (tag & 0x07) as u32;
        if fnum == field_num && wtype == PB_WIRE_LEN {
            let len_u64, ok_len = pb_read_varint(wire, pos);
            let rem = core::sub_sat_i64(wire.len, pos);
            guard ok_len && len_u64 <= (rem as u64) else { return "", false; }
            let end_pos = core::add_sat_i64(pos, len_u64 as i64);
            return wire[pos..end_pos], true;
        }
        guard pb_skip_field(wire, pos, wtype) else { return "", false; }
    }
    return "", false;
}

// Encodes a length-delimited Protobuf string/bytes field (`wire_type = 2`) into `out`.
fn pb_write_bytes_field<B>(field_num: u32, payload: const u8[:], out: B&) -> bool {
    let tag = (((field_num & PB_MAX_FIELD_NUM) as u64) << 3) | (PB_WIRE_LEN as u64);
    let len_u64 = payload.len as u64;
    let hdr_len = core::add_sat_u64(protowire_varint_len(tag), protowire_varint_len(len_u64)) as i64;
    let needed = core::add_sat_i64(core::add_sat_i64(out.len, hdr_len), payload.len);
    guard field_num >= 1 && field_num <= PB_MAX_FIELD_NUM && needed <= out.cap else { return false; }
    let _ = pb_write_varint(tag, out);
    let _ = pb_write_varint(len_u64, out);
    out.append(payload);
    return true;
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
    guard comp.len > 0 && !core::eq_ascii_fold(comp, "identity") else { return GrpcStatusCode.Ok; }
    guard core::eq_ascii_fold(comp, "gzip") else { return GrpcStatusCode.Unimplemented; }
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
        let pair, rest, has_amp = core::split_once_byte(rem, '&');
        let item = if has_amp { pair } else { rem };
        rem = if has_amp { rest } else { "" };
        let k, v, ok_eq = core::split_once_byte(item, '=');
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
    guard out.try_push('"') else { return false; }
    for b in raw {
        guard append_connect_json_byte(b, out) else { return false; }
    }
    return out.try_push('"');
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
    core::write_be_u32(hdr, json_buf.len as u32);
    return out.try_append(hdr[..]) && out.try_append(json_buf[..]);
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
    let q_rel = core::index_of_byte(s[pos..], '"');
    guard q_rel >= 0 else { return false; }
    var idx = core::add_sat_i64(pos, core::add_sat_i64(q_rel, 1));
    while idx < s.len {
        let b = s[idx];
        if b == '"' {
            pos = core::add_sat_i64(idx, 1);
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
    let br_rel = core::index_of_byte(meta_slice[pos..], '[');
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
    if pos < meta_slice.len { pos = core::add_sat_i64(pos, 1); }
    return true;
}

// Parses Connect `"metadata":{...}` object entries into `out_trailers`.
//
// Example:
//   meta_slice = "{\"x-custom\":[\"val1\"]}"
//   returns: true, out_trailers["x-custom"] = "val1"
fn parse_connect_metadata_object(meta_slice: const u8[:], out_trailers: HeaderMap&) -> bool {
    var pos:     i64      = 0;
    var key_buf: u8[..64] = [];
    while pos < meta_slice.len {
        while pos < meta_slice.len && meta_slice[pos] != '"' && meta_slice[pos] != '}' {
            pos = core::add_sat_i64(pos, 1);
        }
        if pos >= meta_slice.len || meta_slice[pos] == '}' { break; }
        guard scan_connect_json_string(meta_slice, pos, key_buf)
            && parse_connect_metadata_values(meta_slice, pos, key_buf[..], out_trailers) else {
            return false;
        }
    }
    return true;
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
    let br_rel = core::index_of_byte(s[pos..], '{');
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
        let br_rel = core::index_of_byte(trimmed[pos..], '{');
        guard br_rel >= 0 else { return false; }
        pos = core::add_sat_i64(pos, core::add_sat_i64(br_rel, 1));
        guard parse_connect_metadata_object(trimmed[pos..], out_trailers) else { return false; }
        pos = trimmed.len;
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
    let trimmed = core::trim_lws(json_bytes);
    guard trimmed.len >= 2 && trimmed[0] == '{' && trimmed[core::sub_sat_i64(trimmed.len, 1)] == '}' else {
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

    out_status = tmp_status;
    let _ = out_message.try_set(tmp_msg[..]);
    return true;
}
