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

// ---- 1. Length-Prefixed Message (LPM) Framing ------------------------------

// Encodes a payload into a 5-byte Length-Prefixed Message (LPM):
// [1-byte Flag] [4-byte Big-Endian Length] [Payload]
fn encode_grpc_lpm<B>(payload: const u8[:], out: B&, compressed: bool = false) {
    let flag: u8 = if compressed { GRPC_FLAG_COMPRESSED } else { 0x00 };
    out.push(flag);
    core::write_be_u32(out, payload.len as u32);
    out.append(payload);
}

// Decodes a single LPM frame starting at offset in wire bytes without buffer copying.
// Returns (payload_slice, is_compressed, bytes_consumed, ok).
fn decode_grpc_lpm_slice(wire: const u8[:], offset: u32) -> const u8[:], bool, u32, bool {
    let off = offset as i64;
    guard off >= 0 && off <= wire.len else { return "", false, 0, false; }
    guard wire.len - off >= GRPC_LPM_HEADER_LEN else { return "", false, 0, false; }

    let flag = wire[off];
    guard (flag & ~GRPC_FLAG_COMPRESSED) == 0 else { return "", false, 0, false; }
    let is_compressed = (flag & GRPC_FLAG_COMPRESSED) != 0;

    let len_val_i64 = (core::read_be_u32(wire, off + 1)) as i64;
    guard (wire.len - off - GRPC_LPM_HEADER_LEN) >= len_val_i64 else { return "", false, 0, false; }

    let p_start = off + GRPC_LPM_HEADER_LEN;
    let total_consumed = (GRPC_LPM_HEADER_LEN + len_val_i64) as u32;
    return wire[p_start..p_start + len_val_i64], is_compressed, total_consumed, true;
}

// Decodes a single LPM frame starting at offset in wire bytes.
// Target buffer is cleared only after wire format validation succeeds.
fn decode_grpc_lpm<B>(wire: const u8[:], offset: u32, out_payload: B&, out_compressed: bool&) -> bool, u32 {
    let payload_slice, is_comp, consumed, ok = decode_grpc_lpm_slice(wire, offset);
    guard ok else { return false, 0; }
    out_payload.clear();
    out_payload.append(payload_slice);
    out_compressed = is_comp;
    return true, consumed;
}

// ---- 2. Incremental Streaming LPM Parser -----------------------------------

// Reassembles LPM messages arriving across fragmented HTTP/2 or HTTP/3 DATA chunks.
struct GrpcStreamParser {
    max_size: u32 = GRPC_DEFAULT_MAX_MESSAGE_SIZE,
    buf: u8[>..] = [],
}

fn new_grpc_stream_parser(max_msg_size: u32 = GRPC_DEFAULT_MAX_MESSAGE_SIZE) -> GrpcStreamParser {
    return GrpcStreamParser {
        max_size: max_msg_size,
        buf: [],
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
    guard p.buf.len >= (GRPC_LPM_HEADER_LEN as i64) else { return false; }

    let flag = p.buf[0];
    guard (flag & ~GRPC_FLAG_COMPRESSED) == 0 else { return false; }
    out_compressed = (flag & GRPC_FLAG_COMPRESSED) != 0;

    let len_val_i64 = (core::read_be_u32(p.buf[..], 1)) as i64;
    let total_len = GRPC_LPM_HEADER_LEN + len_val_i64;
    guard p.buf.len >= total_len else { return false; }

    out_payload.clear();
    let hdr_len_i64: i64 = GRPC_LPM_HEADER_LEN;
    out_payload.append(p.buf[hdr_len_i64..total_len]);

    let remaining_bytes = p.buf.len - total_len;
    if remaining_bytes == 0 {
        p.buf.clear();
    } else {
        var temp: u8[>..] = [];
        temp.append(p.buf[total_len..]);
        p.buf.clear();
        p.buf.append(temp[..]);
    }

    return true;
}

// ---- 3. gRPC-Web Framing (Trailers-in-Body) ---------------------------------

// Encodes gRPC-Web trailers frame into body payload with flag 0x80.
// Trailer format: "grpc-status: <status>\r\ngrpc-message: <message>\r\n[custom-trailers]\r\n"
fn encode_grpc_web_trailers_with_meta<B>(
    status: GrpcStatusCode,
    message: const u8[:],
    extra_trailers: const GrpcMetadata[:],
    out: B&,
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

    out.push(GRPC_WEB_FLAG_TRAILERS);
    core::write_be_u32(out, trailer_body.len as u32);
    out.append(trailer_body[..]);
}

fn encode_grpc_web_trailers<B>(status: GrpcStatusCode, message: const u8[:], out: B&) {
    let empty_trailers: GrpcMetadata[0] = [];
    encode_grpc_web_trailers_with_meta(status, message, empty_trailers[..], out);
}

// Decodes a gRPC-Web frame (distinguishing data messages from trailer frames).
fn decode_grpc_web_frame<B>(
    wire: const u8[:],
    offset: u32,
    out_payload: B&,
    out_is_trailers: bool&,
    out_compressed: bool&,
) -> bool, u32 {
    let off = offset as i64;
    guard off >= 0 && (wire.len - off) >= 5 else { return false, 0; }

    let flag = wire[off];
    guard (flag & ~(GRPC_FLAG_COMPRESSED | GRPC_WEB_FLAG_TRAILERS)) == 0 else { return false, 0; }
    out_is_trailers = (flag & GRPC_WEB_FLAG_TRAILERS) != 0;
    out_compressed = (flag & GRPC_FLAG_COMPRESSED) != 0;

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
fn parse_grpc_web_trailer_line(
    line: const u8[:],
    out_status: GrpcStatusCode&,
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
fn parse_grpc_web_trailers(
    trailer_bytes: const u8[:],
    out_status: GrpcStatusCode&,
    out_message: u8[..256]&,
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

// ---- 4. gRPC-Web Text Base64 Codec -----------------------------------------

// Encodes binary LPM wire stream into standard Base64 for application/grpc-web-text.
fn encode_grpc_web_text<B>(binary_lpm: const u8[:], out: B&) {
    core::base64_encode(binary_lpm, out);
}

// Decodes application/grpc-web-text Base64 stream into raw binary LPM stream.
fn decode_grpc_web_text<B>(b64_stream: const u8[:], out: B&) -> bool {
    return core::base64_decode(b64_stream, out);
}
