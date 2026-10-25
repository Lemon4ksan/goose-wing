// gRPC Length-Prefixed Message (LPM) binary framer and gRPC-Web codec.
// Conforms to gRPC HTTP/2 Wire Protocol Specification and gRPC-Web Protocol.
namespace wing;

import std;
import grpc.constants;
import http.mime;

// ---- 1. Length-Prefixed Message (LPM) Framing ------------------------------

// Encodes a payload into a 5-byte Length-Prefixed Message (LPM):
// [1-byte Flag] [4-byte Big-Endian Length] [Payload]
fn encode_grpc_lpm<B>(payload: const u8[:], out: B&, compressed: bool = false) {
    let flag: u8 = if compressed { GRPC_FLAG_COMPRESSED } else { 0x00 };
    out.push(flag);

    let len_val = payload.len as u32;
    out.push(((len_val >> 24) & 0xFF) as u8);
    out.push(((len_val >> 16) & 0xFF) as u8);
    out.push(((len_val >> 8) & 0xFF) as u8);
    out.push((len_val & 0xFF) as u8);

    out.append(payload);
}

// Decodes a single LPM frame starting at offset in wire bytes.
// Returns (ok, bytes_consumed). When true, out_payload contains the message bytes.
fn decode_grpc_lpm<B>(wire: const u8[:], offset: u32, out_payload: B&, out_compressed: bool&) -> bool, u32 {
    let off = offset as i64;
    guard (wire.len - off) >= 5 else { return false, 0; }

    let flag = wire[off];
    out_compressed = (flag & GRPC_FLAG_COMPRESSED) != 0;

    let len_val = ((wire[off + 1] as u32) << 24) |
                  ((wire[off + 2] as u32) << 16) |
                  ((wire[off + 3] as u32) << 8) |
                  (wire[off + 4] as u32);

    let total_frame_len = 5 + len_val;
    guard (wire.len - off) >= (total_frame_len as i64) else { return false, 0; }

    out_payload.clear();
    let start_idx = off + 5;
    let end_idx = off + (total_frame_len as i64);
    out_payload.append(wire[start_idx..end_idx]);

    return true, total_frame_len;
}

// ---- 2. Incremental Streaming LPM Parser -----------------------------------

// Reassembles LPM messages arriving across fragmented HTTP/2 or HTTP/3 DATA chunks.
struct GrpcStreamParser {
    buf: u8[..65536] = [],
}

fn new_grpc_stream_parser() -> GrpcStreamParser {
    return GrpcStreamParser { .. };
}

fn reset(p: GrpcStreamParser&) {
    p.buf.clear();
}

fn feed(p: GrpcStreamParser&, chunk: const u8[:]) -> bool {
    guard p.buf.len + chunk.len <= 65536 else { return false; }
    p.buf.append(chunk);
    return true;
}

// Extracts the next available message. Returns true if a full message was consumed.
fn next_message<B>(p: GrpcStreamParser&, out_payload: B&, out_compressed: bool&) -> bool {
    guard p.buf.len >= 5 else { return false; }

    let flag = p.buf[0];
    out_compressed = (flag & GRPC_FLAG_COMPRESSED) != 0;

    let len_val = ((p.buf[1] as u32) << 24) |
                  ((p.buf[2] as u32) << 16) |
                  ((p.buf[3] as u32) << 8) |
                  (p.buf[4] as u32);

    let total_len = (5 + len_val) as i64;
    guard p.buf.len >= total_len else { return false; }

    out_payload.clear();
    out_payload.append(p.buf[5..total_len]);

    let remaining = p.buf.len - total_len;
    if remaining == 0 {
        p.buf.clear();
    } else {
        var temp: u8[..65536] = [];
        temp.append(p.buf[total_len..]);
        p.buf.clear();
        p.buf.append(temp[..]);
    }

    return true;
}

// ---- 3. gRPC-Web Framing (Trailers-in-Body) ---------------------------------

// Encodes gRPC-Web trailers frame into body payload with flag 0x80.
// Trailer format: "grpc-status: <status>\r\ngrpc-message: <message>\r\n"
fn encode_grpc_web_trailers<B>(status: GrpcStatusCode, message: const u8[:], out: B&) {
    var trailer_body: u8[..1024] = [];
    trailer_body.append("grpc-status: ");
    format(trailer_body, grpc_status_to_code(status) as i64);
    trailer_body.append("\r\n");

    if message.len > 0 {
        trailer_body.append("grpc-message: ");
        trailer_body.append(message);
        trailer_body.append("\r\n");
    }

    let flag: u8 = GRPC_WEB_FLAG_TRAILERS;
    out.push(flag);

    let len_val = trailer_body.len as u32;
    out.push(((len_val >> 24) & 0xFF) as u8);
    out.push(((len_val >> 16) & 0xFF) as u8);
    out.push(((len_val >> 8) & 0xFF) as u8);
    out.push((len_val & 0xFF) as u8);

    out.append(trailer_body[..]);
}

// Decodes a gRPC-Web frame (distinguishing data messages from trailer frames).
fn decode_grpc_web_frame<B>(
    wire: const u8[:],
    offset: u32,
    out_payload: B&,
    out_is_trailers: bool&,
    out_compressed: bool&
) -> bool, u32 {
    let off = offset as i64;
    guard (wire.len - off) >= 5 else { return false, 0; }

    let flag = wire[off];
    out_is_trailers = (flag & GRPC_WEB_FLAG_TRAILERS) != 0;
    out_compressed = (flag & GRPC_FLAG_COMPRESSED) != 0;

    let len_val = ((wire[off + 1] as u32) << 24) |
                  ((wire[off + 2] as u32) << 16) |
                  ((wire[off + 3] as u32) << 8) |
                  (wire[off + 4] as u32);

    let total_len = 5 + len_val;
    guard (wire.len - off) >= (total_len as i64) else { return false, 0; }

    out_payload.clear();
    let start_idx = off + 5;
    let end_idx = off + (total_len as i64);
    out_payload.append(wire[start_idx..end_idx]);

    return true, total_len;
}

// Parses gRPC-Web body trailers block (HTTP/1-style headers) to extract status and message.
fn parse_grpc_web_trailers(
    trailer_bytes: const u8[:],
    out_status: GrpcStatusCode&,
    out_message: u8[..256]&
) -> bool {
    out_status = GrpcStatusCode.Ok;
    out_message.clear();

    var cursor: i64 = 0;
    var found_status = false;

    while cursor < trailer_bytes.len {
        var line_end = cursor;
        while line_end < trailer_bytes.len && trailer_bytes[line_end] != '\n' {
            line_end++;
        }

        var line = trailer_bytes[cursor..line_end];
        if line.len > 0 && line[line.len - 1] == '\r' {
            line = line[..(line.len - 1)];
        }

        if line.len > 0 {
            var colon_idx: i64 = -1;
            for i in line.len {
                if line[i] == ':' {
                    colon_idx = i;
                    break;
                }
            }

            if colon_idx > 0 {
                let name = line[..colon_idx];
                var val_start = colon_idx + 1;
                while val_start < line.len && (line[val_start] == ' ' || line[val_start] == '\t') {
                    val_start++;
                }
                let val = line[val_start..];

                if eq_ascii_fold(name, "grpc-status") {
                    var status_int: u32 = 0;
                    for b in val {
                        if b >= '0' && b <= '9' {
                            status_int = status_int * 10 + (b - '0');
                        }
                    }
                    out_status = grpc_status_from_code(status_int);
                    found_status = true;
                } else if eq_ascii_fold(name, "grpc-message") {
                    out_message.clear();
                    out_message.append(val);
                }
            }
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
