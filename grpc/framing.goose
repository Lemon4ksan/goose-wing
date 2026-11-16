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
    guard (payload.len as u64) <= 0xFFFFFFFF else { return; }
    let orig_len = out.len;
    if compressed {
        let max_gz = min(core::add_sat_i64(core::add_sat_i64(payload.len, payload.len), 128), 0xFFFFFFFF);
        var gz_buf: u8[..] = [..max_gz];
        guard core::gzip_compress(payload, gz_buf, 6) && (gz_buf.len as u64) <= 0xFFFFFFFF else {
            return;
        }
        var hdr_c: u8[..8] = [];
        hdr_c.push(rfc::GRPC_FLAG_COMPRESSED);
        hdr_c.append_u32_be(gz_buf.len as u32);
        guard out.try_append(hdr_c[..]) && out.try_append(gz_buf[..]) else {
            out.resize(orig_len, 0);
            return;
        }
        return;
    }
    var hdr_u: u8[..8] = [];
    hdr_u.push(0x00);
    hdr_u.append_u32_be(payload.len as u32);
    guard out.try_append(hdr_u[..]) && out.try_append(payload) else {
        out.resize(orig_len, 0);
        return;
    }
}

// Decodes a single LPM frame starting at offset in wire bytes without buffer copying.
// Returns (payload_slice, is_compressed, bytes_consumed, ok).
//
// Example:
//   wire = [0x00, 0x00, 0x00, 0x00, 0x05, "hello"], offset = 0
//   returns: payload = "hello", is_comp = false, consumed = 10, ok = true
fn decode_grpc_lpm_slice(wire: const u8[:], offset: u32) -> const u8[:], bool, u32, bool {
    let off = offset as i64;
    let rem = core::sub_sat_i64(wire.len, off);
    guard off >= 0 && rem >= rfc::GRPC_LPM_HEADER_LEN else { return "", false, 0, false; }

    let flag = wire[off];
    guard (flag & ~rfc::GRPC_FLAG_COMPRESSED) == 0 else { return "", false, 0, false; }
    let is_compressed = (flag & rfc::GRPC_FLAG_COMPRESSED) != 0;

    let len_val_i64 = (core::read_be_u32(wire, core::add_sat_i64(off, 1))) as i64;
    guard len_val_i64 <= 0xFFFFFFFA && core::sub_sat_i64(rem, rfc::GRPC_LPM_HEADER_LEN) >= len_val_i64 else {
        return "", false, 0, false;
    }

    let p_start = core::add_sat_i64(off, rfc::GRPC_LPM_HEADER_LEN);
    let p_end = core::add_sat_i64(p_start, len_val_i64);
    let total_consumed = core::add_sat_i64(rfc::GRPC_LPM_HEADER_LEN, len_val_i64) as u32;
    return wire[p_start..p_end], is_compressed, total_consumed, true;
}

// Decodes a single LPM frame starting at offset in wire bytes.
// Target buffer is replaced only after wire format and capacity validation succeed.
//
// Example:
//   wire = [0x00, 0x00, 0x00, 0x00, 0x05, "hello"], offset = 0
//   returns: ok = true, consumed = 10, out_payload = "hello", out_compressed = false
fn decode_grpc_lpm<B>(wire: const u8[:], offset: u32, out_payload: B&, out_compressed: bool&) -> bool, u32 {
    let payload_slice, is_comp, consumed, ok = decode_grpc_lpm_slice(wire, offset);
    guard ok && out_payload.try_set(payload_slice) else { return false, 0; }
    out_compressed = is_comp;
    return true, consumed;
}

// ---- Incremental Streaming LPM Parser -----------------------------------

// Reassembles LPM messages arriving across fragmented HTTP/2 or HTTP/3 DATA chunks.
struct GrpcStreamParser {
    max_size:  u32     = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE,
    read_pos:  i64     = 0,
    has_error: bool    = false,
    buf:       u8[>..] = [],
}

fn new_grpc_stream_parser(max_msg_size: u32 = rfc::GRPC_DEFAULT_MAX_MESSAGE_SIZE) -> GrpcStreamParser {
    return GrpcStreamParser {
        max_size:  max_msg_size,
        read_pos:  0,
        has_error: false,
        buf:       [],
    };
}

fn reset(p: GrpcStreamParser&) {
    p.read_pos = 0;
    p.has_error = false;
    p.buf.clear();
}

fn feed(p: GrpcStreamParser&, chunk: const u8[:]) -> bool {
    guard !p.has_error else { return false; }
    let unread_len = core::sub_sat_i64(p.buf.len, p.read_pos) as u64;
    let cur_total = core::add_sat_u64(unread_len, chunk.len as u64);
    let max_wire = core::add_sat_u64(p.max_size, rfc::GRPC_LPM_HEADER_LEN);
    let max_buf_wire = max(core::mul_sat_u64(max_wire, 4), 65536);
    guard cur_total <= max_buf_wire else {
        p.has_error = true;
        return false;
    }
    if p.read_pos > 0 {
        if p.read_pos >= p.buf.len {
            p.buf.clear();
            p.read_pos = 0;
        } else if core::add_sat_u64(p.buf.len as u64, chunk.len as u64) > max_wire {
            p.buf.compact_wire_buffer(p.read_pos);
            p.read_pos = 0;
        }
    }
    p.buf.append(chunk);
    return true;
}

// Extracts the next available message. Returns true if a full message was consumed.
fn next_message<B>(p: GrpcStreamParser&, out_payload: B&, out_compressed: bool&) -> bool {
    guard !p.has_error else { return false; }
    let rem = core::sub_sat_i64(p.buf.len, p.read_pos);
    guard p.read_pos >= 0 && rem >= (rfc::GRPC_LPM_HEADER_LEN as i64) else { return false; }

    let pos = p.read_pos;
    let flag = p.buf[pos];
    guard (flag & ~rfc::GRPC_FLAG_COMPRESSED) == 0 else {
        p.has_error = true;
        return false;
    }

    let len_val_i64 = (core::read_be_u32(p.buf[..], core::add_sat_i64(pos, 1))) as i64;
    guard len_val_i64 <= (p.max_size as i64) else {
        p.has_error = true;
        return false;
    }
    let total_len = core::add_sat_i64(rfc::GRPC_LPM_HEADER_LEN, len_val_i64);
    guard rem >= total_len else { return false; }

    let payload_start = core::add_sat_i64(pos, rfc::GRPC_LPM_HEADER_LEN);
    let payload_end = core::add_sat_i64(pos, total_len);
    guard out_payload.try_set(p.buf[payload_start..payload_end]) else { return false; }
    out_compressed = (flag & rfc::GRPC_FLAG_COMPRESSED) != 0;
    p.read_pos = payload_end;
    if p.read_pos >= p.buf.len {
        p.buf.clear();
        p.read_pos = 0;
    }
    return true;
}

// ---- gRPC-Web Framing (Trailers-in-Body) ---------------------------------

inline fn is_grpc_metadata_key_char(b: u8) -> bool {
    return (b >= 'a' && b <= 'z') || (b >= '0' && b <= '9') || b == '-' || b == '_' || b == '.';
}

// Returns true when `key` and `val` are safe custom gRPC metadata / trailer fields
// (lowercase gRPC Metadata-Header key, printable HTTP field value without CR/LF/NUL, and not a
// reserved protocol control header).
fn is_valid_grpc_custom_metadata(key: const u8[:], val: const u8[:]) -> bool {
    guard key.len > 0 && key[0] != ':' else { return false; }
    guard !key.eq_ascii_fold(rfc::HEADER_GRPC_STATUS) else { return false; }
    guard !key.eq_ascii_fold(rfc::HEADER_GRPC_MESSAGE) else { return false; }
    guard !key.eq_ascii_fold(rfc::HEADER_GRPC_STATUS_DETAILS_BIN) else { return false; }
    guard !key.eq_ascii_fold("content-type") else { return false; }
    guard !key.eq_ascii_fold("te") else { return false; }
    for b in key {
        guard is_grpc_metadata_key_char(b) else { return false; }
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
    var trailer_body: u8[..8192] = [];
    trailer_body.append("grpc-status: ");
    let code = grpc_status_to_code(status);
    code.format_u32_dec(trailer_body);
    trailer_body.append("\r\n");

    if message.len > 0 {
        var enc_msg: u8[>..] = [];
        encode_grpc_message(message, enc_msg);
        let max_msg_bytes = core::sub_sat_i64(core::sub_sat_i64(trailer_body.cap, trailer_body.len), 18);
        var take_len = min(enc_msg.len, max_msg_bytes);
        if take_len < enc_msg.len && take_len >= 1 && enc_msg[core::sub_sat_i64(take_len, 1)] == '%' {
            take_len = core::sub_sat_i64(take_len, 1);
        } else if take_len < enc_msg.len && take_len >= 2 && enc_msg[core::sub_sat_i64(take_len, 2)] == '%' {
            take_len = core::sub_sat_i64(take_len, 2);
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

    let orig_len = out.len;
    var tr_hdr: u8[..8] = [];
    tr_hdr.push(rfc::GRPC_WEB_FLAG_TRAILERS);
    tr_hdr.append_u32_be(trailer_body.len as u32);
    guard out.try_append(tr_hdr[..]) && out.try_append(trailer_body[..]) else {
        out.resize(orig_len, 0);
        return;
    }
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

    let start_idx = core::add_sat_i64(off, 5);
    let end_idx = core::add_sat_i64(off, total_len);
    guard out_payload.try_set(wire[start_idx..end_idx]) else { return false, 0; }
    out_is_trailers = (flag & rfc::GRPC_WEB_FLAG_TRAILERS) != 0;
    out_compressed = (flag & rfc::GRPC_FLAG_COMPRESSED) != 0;

    return true, total_len as u32;
}

// Parses a single gRPC-Web trailer header line ("name: value").
//
// Example:
//   line = "grpc-status: 0"
//   returns: true, out_status = GrpcStatusCode.Ok, found_valid_status = true
fn parse_grpc_web_trailer_line(
    line:               const u8[:],
    saw_status_key:     bool&,
    found_valid_status: bool&,
    out_status:         GrpcStatusCode&,
    out_message:        u8[..256]&,
) -> bool {
    let name, raw_val, ok_split = line.split_once_byte(':');
    guard ok_split && name.len > 0 else { return true; }
    let val = raw_val.trim_lws();
    if name.eq_ascii_fold("grpc-status") {
        if saw_status_key {
            out_status = GrpcStatusCode.Unknown;
            return false;
        }
        saw_status_key = true;
        if val.len == 0 {
            return true;
        }
        let status_int, ok_code = val.parse_u32_dec();
        if !ok_code {
            out_status = GrpcStatusCode.Unknown;
            return false;
        }
        out_status = grpc_status_from_code(status_int);
        found_valid_status = true;
        return true;
    }
    if name.eq_ascii_fold("grpc-message") {
        out_message.clear();
        decode_grpc_message(val, out_message);
    }
    return true;
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

    var cursor:             i64       = 0;
    var saw_status_key:     bool      = false;
    var found_valid_status: bool      = false;
    var tmp_msg:            u8[..256] = [];

    while cursor < trailer_bytes.len {
        let rel_nl = trailer_bytes[cursor..].index_of_byte('\n');
        let line_end = if rel_nl >= 0 { core::add_sat_i64(cursor, rel_nl) } else { trailer_bytes.len };

        var line = trailer_bytes[cursor..line_end];
        if core::ends_with(line, "\r") {
            line = line[..^1];
        }
        if line.len > 0 {
            guard parse_grpc_web_trailer_line(line, saw_status_key, found_valid_status, out_status, tmp_msg) else {
                return false;
            }
        }
        cursor = core::add_sat_i64(line_end, 1);
    }

    guard found_valid_status else { return false; }
    let _ = out_message.try_set(tmp_msg[..]);
    return true;
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
    var committed = false;
    defer if !committed { out.clear(); };
    let total = b64_stream.len as u64;
    guard (total & 3) == 0 else { return false; }
    guard total > 0 else {
        committed = true;
        return true;
    }

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
            guard core::base64_decode(b64_stream[seg_start..seg_end], chunk_buf)
                && out.try_append(chunk_buf[..]) else {
                return false;
            }
            seg_start = seg_end;
        }
    }
    committed = true;
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
    var pos:   i64  = 0;
    var found: bool = false;
    var best:  u64  = 0;
    while pos < wire.len {
        let tag, ok_tag = pb_read_varint(wire, pos);
        let raw_fnum = tag >> 3;
        guard ok_tag && raw_fnum >= 1 && raw_fnum <= PB_MAX_FIELD_NUM else { return 0, false; }
        let fnum = raw_fnum as u32;
        let wtype = (tag & 0x07) as u32;
        if fnum == field_num {
            guard wtype == PB_WIRE_VARINT else { return 0, false; }
            let val, ok_val = pb_read_varint(wire, pos);
            guard ok_val else { return 0, false; }
            best = val;
            found = true;
        } else {
            guard pb_skip_field(wire, pos, wtype) else { return 0, false; }
        }
    }
    return best, found;
}

// Encodes a Protobuf varint field (`wire_type = 0`) for `field_num` into `out`.
fn pb_write_varint_field<B>(field_num: u32, val: u64, out: B&) -> bool {
    guard field_num >= 1 && field_num <= PB_MAX_FIELD_NUM else { return false; }
    let tag = core::shl_sat_u64(field_num, 3) | (PB_WIRE_VARINT as u64);
    let total_len = core::add_sat_u64(protowire_varint_len(tag), protowire_varint_len(val)) as i64;
    let needed = core::add_sat_i64(out.len, total_len);
    guard needed <= out.cap else { return false; }
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
    var pos:        i64  = 0;
    var found:      bool = false;
    var best_start: i64  = 0;
    var best_end:   i64  = 0;
    while pos < wire.len {
        let tag, ok_tag = pb_read_varint(wire, pos);
        let raw_fnum = tag >> 3;
        guard ok_tag && raw_fnum >= 1 && raw_fnum <= PB_MAX_FIELD_NUM else { return "", false; }
        let fnum = raw_fnum as u32;
        let wtype = (tag & 0x07) as u32;
        if fnum == field_num {
            guard wtype == PB_WIRE_LEN else { return "", false; }
            let len_u64, ok_len = pb_read_varint(wire, pos);
            let rem = core::sub_sat_i64(wire.len, pos);
            guard ok_len && len_u64 <= (rem as u64) else { return "", false; }
            let end_pos = core::add_sat_i64(pos, len_u64 as i64);
            best_start = pos;
            best_end = end_pos;
            found = true;
            pos = end_pos;
        } else {
            guard pb_skip_field(wire, pos, wtype) else { return "", false; }
        }
    }
    return wire[best_start..best_end], found;
}

// Encodes a length-delimited Protobuf string/bytes field (`wire_type = 2`) into `out`.
fn pb_write_bytes_field<B>(field_num: u32, payload: const u8[:], out: B&) -> bool {
    guard field_num >= 1 && field_num <= PB_MAX_FIELD_NUM else { return false; }
    let tag = core::shl_sat_u64(field_num, 3) | (PB_WIRE_LEN as u64);
    let len_u64 = payload.len as u64;
    let hdr_len = core::add_sat_u64(protowire_varint_len(tag), protowire_varint_len(len_u64)) as i64;
    let needed = core::add_sat_i64(core::add_sat_i64(out.len, hdr_len), payload.len);
    guard needed <= out.cap else { return false; }
    let _ = pb_write_varint(tag, out);
    let _ = pb_write_varint(len_u64, out);
    out.append(payload);
    return true;
}
