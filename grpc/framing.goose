// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// gRPC Length-Prefixed Message (LPM) binary framer and gRPC-Web codec.
// Conforms to gRPC HTTP/2 Wire Protocol Specification and gRPC-Web Protocol.
namespace wing;

import std;
import core from "..";
import grpc.constants;
import grpc.status;
import http.mime;

// ---- Length-Prefixed Message (LPM) Framing ------------------------------

// Encodes a payload into a 5-byte Length-Prefixed Message (LPM):
// [1-byte Flag] [4-byte Big-Endian Length] [Payload]
// When `compressed` is true, `payload` is Gzip-compressed before framing.
fn encode_grpc_lpm<B>(payload: const u8[:], out: B&, compressed: bool = false) {
    if compressed {
        var gz_buf: u8[>..] = [];
        if core::gzip_compress(payload, gz_buf, 6) {
            out.push(rfc::GRPC_FLAG_COMPRESSED);
            core::write_be_u32(out, gz_buf.len as u32);
            out.append(gz_buf[..]);
            return;
        }
    }
    out.push(0x00);
    core::write_be_u32(out, payload.len as u32);
    out.append(payload);
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
    out_payload.append(payload_slice);
    out_compressed = is_comp;
    return true, consumed;
}

// ---- Incremental Streaming LPM Parser -----------------------------------

// Reassembles LPM messages arriving across fragmented HTTP/2 or HTTP/3 DATA chunks.
struct GrpcStreamParser {
    max_size: u32     = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE,
    buf:      u8[>..] = [],
}

fn new_grpc_stream_parser(max_msg_size: u32 = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE) -> GrpcStreamParser {
    return GrpcStreamParser {
        max_size: max_msg_size,
        buf:      [],
    };
}

fn reset(p: GrpcStreamParser&) {
    p.buf.clear();
}

fn feed(p: GrpcStreamParser&, chunk: const u8[:]) -> bool {
    guard ((p.buf.len + chunk.len) as u64) <= p.max_size else { return false; }
    p.buf.append(chunk);
    return true;
}

// Extracts the next available message. Returns true if a full message was consumed.
fn next_message<B>(p: GrpcStreamParser&, out_payload: B&, out_compressed: bool&) -> bool {
    guard p.buf.len >= (rfc::GRPC_LPM_HEADER_LEN as i64) else { return false; }

    let flag = p.buf[0];
    guard (flag & ~rfc::GRPC_FLAG_COMPRESSED) == 0 else { return false; }
    out_compressed = (flag & rfc::GRPC_FLAG_COMPRESSED) != 0;

    let len_val_i64 = (core::read_be_u32(p.buf[..], 1)) as i64;
    let total_len = rfc::GRPC_LPM_HEADER_LEN + len_val_i64;
    guard p.buf.len >= total_len else { return false; }

    out_payload.clear();
    let hdr_len_i64: i64 = rfc::GRPC_LPM_HEADER_LEN;
    out_payload.append(p.buf[hdr_len_i64..total_len]);
    core::compact_wire_buffer(p.buf, total_len);
    return true;
}

// ---- gRPC-Web Framing (Trailers-in-Body) ---------------------------------

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
        var take_len = if enc_msg.len > max_msg_bytes { max_msg_bytes } else { enc_msg.len };
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
        let line_len = m.key.len + m.value.len + 4;
        if (trailer_body.cap - trailer_body.len) as i64 >= (line_len as i64) {
            trailer_body.append(m.key[..]);
            trailer_body.append(": ");
            trailer_body.append(m.value[..]);
            trailer_body.append("\r\n");
        }
    }

    out.push(rfc::GRPC_WEB_FLAG_TRAILERS);
    core::write_be_u32(out, trailer_body.len as u32);
    out.append(trailer_body[..]);
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
    guard off >= 0 && (wire.len - off) >= 5 else { return false, 0; }

    let flag = wire[off];
    guard (flag & ~(rfc::GRPC_FLAG_COMPRESSED | rfc::GRPC_WEB_FLAG_TRAILERS)) == 0 else { return false, 0; }
    out_is_trailers = (flag & rfc::GRPC_WEB_FLAG_TRAILERS) != 0;
    out_compressed = (flag & rfc::GRPC_FLAG_COMPRESSED) != 0;

    let len_val_i64 = (core::read_be_u32(wire, off + 1)) as i64;
    let total_len = 5 + len_val_i64;
    guard (wire.len - off) >= total_len else { return false, 0; }

    out_payload.clear();
    let start_idx = off + 5;
    let end_idx = off + total_len;
    out_payload.append(wire[start_idx..end_idx]);

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
        guard ok_code else { return false; }
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
//
// Example:
//   b64_stream = "AAAAAAA="
//   returns: true, out = [0, 0, 0, 0, 0]
fn decode_grpc_web_text<B>(b64_stream: const u8[:], out: B&) -> bool {
    return core::base64_decode(b64_stream, out);
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
        guard ok_tag && tag > 0 else { return 0, false; }
        let fnum = (tag >> 3) as u32;
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
        guard ok_tag && tag > 0 else { return "", false; }
        let fnum = (tag >> 3) as u32;
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
