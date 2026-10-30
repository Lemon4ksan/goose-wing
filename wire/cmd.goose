// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Vulkan-style zero-allocation wire command buffer recording and frame staging.
namespace wire;

import std;
import core from "..";
import .types;
import .hpack;
import .h2;

// Maximum capacity for a stack-allocated wire command buffer (RFC 9113 / enterprise frames).
const WIRE_CMD_BUFFER_CAP: i64 = 4096;

// Bounded in-place binary command recorder with zero dynamic allocations.
struct WireCommandBuffer {
    buf:                   u8[..4096] = [],
    hpack_staging:         u8[..2048] = [],
    has_error:             bool       = false,
    active_headers_stream: u32        = 0,
    active_headers_flags:  u8         = 0,
}

// Instantiates a new zero-allocation command buffer.
fn new_command_buffer() -> WireCommandBuffer {
    return WireCommandBuffer {
        buf:                   [],
        hpack_staging:         [],
        has_error:             false,
        active_headers_stream: 0,
        active_headers_flags:  0,
    };
}

// Returns recorded byte count.
inline fn len(cmd: const WireCommandBuffer&) -> i64 {
    return cmd.buf.len;
}

// Returns remaining capacity in underlying buffer.
inline fn available(cmd: const WireCommandBuffer&) -> i64 {
    let rem = cmd.buf.cap - cmd.buf.len;
    return if rem > 0 { rem } else { 0 };
}

// Resets recording cursor to reuse buffer.
fn reset(cmd: WireCommandBuffer&) {
    cmd.buf.clear();
    cmd.hpack_staging.clear();
    cmd.has_error = false;
    cmd.active_headers_stream = 0;
    cmd.active_headers_flags = 0;
}

// ---- Primitive serialization operations -------------------------------------

// Writes an octet to buffer.
fn write_u8(cmd: WireCommandBuffer&, val: u8) -> bool {
    guard cmd.buf.try_push(val) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Writes a 16-bit big-endian unsigned integer.
fn write_u16_be(cmd: WireCommandBuffer&, val: u16) -> bool {
    guard cmd.buf.try_push(((val >> 8) & 0xFF) as u8) &&
          cmd.buf.try_push((val & 0xFF) as u8) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Writes a 24-bit big-endian unsigned integer.
fn write_u24_be(cmd: WireCommandBuffer&, val: u32) -> bool {
    guard cmd.buf.try_push(((val >> 16) & 0xFF) as u8) &&
          cmd.buf.try_push(((val >> 8) & 0xFF) as u8) &&
          cmd.buf.try_push((val & 0xFF) as u8) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Writes a 32-bit big-endian unsigned integer.
fn write_u32_be(cmd: WireCommandBuffer&, val: u32) -> bool {
    guard cmd.buf.try_push(((val >> 24) & 0xFF) as u8) &&
          cmd.buf.try_push(((val >> 16) & 0xFF) as u8) &&
          cmd.buf.try_push(((val >> 8) & 0xFF) as u8) &&
          cmd.buf.try_push((val & 0xFF) as u8) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Writes a raw byte sequence into buffer.
fn write_raw(cmd: WireCommandBuffer&, data: const u8[:]) -> bool {
    guard cmd.buf.try_append(data) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// ---- HTTP/2 Protocol Frame Commands -----------------------------------------

// Writes the 24-byte HTTP/2 client connection preface (RFC 9113 Section 3.4).
fn write_h2_preface(cmd: WireCommandBuffer&) -> bool {
    return write_raw(cmd, H2_CLIENT_PREFACE[..]);
}

// Writes a 9-byte binary frame header.
fn write_h2_frame_header(cmd: WireCommandBuffer&, hdr: const WireFrameHeader&) -> bool {
    guard encode_frame_header(hdr, cmd.buf) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Writes an HTTP/2 SETTINGS frame (RFC 9113 Section 6.5).
fn write_h2_settings(cmd: WireCommandBuffer&, settings: const WireSetting[:]) -> bool {
    guard encode_settings_frame(settings, cmd.buf) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Writes a WINDOW_UPDATE frame (RFC 9113 Section 6.9).
fn write_h2_window_update(cmd: WireCommandBuffer&, stream_id: u32, increment: u32) -> bool {
    guard encode_window_update_frame(stream_id, increment, cmd.buf) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Writes an RFC 9218 PRIORITY_UPDATE frame on stream 0 (RFC 9218 Section 7.1).
fn write_h2_priority_update(
    cmd:                   WireCommandBuffer&,
    prioritized_stream_id: u32,
    urgency:               u8,
    incremental:           bool,
) -> bool {
    guard encode_priority_update_frame(prioritized_stream_id, urgency, incremental, cmd.buf) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Writes a RST_STREAM frame (RFC 9113 Section 6.4).
fn write_h2_rst_stream(cmd: WireCommandBuffer&, stream_id: u32, error_code: u32) -> bool {
    guard encode_rst_stream_frame(stream_id, error_code, cmd.buf) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Writes a PING frame with an 8-byte payload (RFC 9113 Section 6.7).
fn write_h2_ping(cmd: WireCommandBuffer&, payload: const u8[8], is_ack: bool) -> bool {
    guard encode_ping_frame(payload, is_ack, cmd.buf) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Writes a DATA frame (RFC 9113 Section 6.1).
fn write_h2_data(cmd: WireCommandBuffer&, stream_id: u32, payload: const u8[:], end_stream: bool) -> bool {
    guard encode_data_frame(stream_id, payload, end_stream, cmd.buf) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// ---- Vulkan-style Dynamic HEADERS Frame Recording with Staged HPACK ----------

// Begins a dynamic HEADERS frame block using isolated staging buffer.
fn begin_h2_headers(cmd: WireCommandBuffer&, stream_id: u32, flags: u8) -> bool {
    cmd.hpack_staging.clear();
    cmd.active_headers_stream = stream_id;
    cmd.active_headers_flags = flags;
    return true;
}

// Encodes an indexed header field representation into the active HEADERS block (RFC 7541 Section 6.1).
fn hpack_indexed(cmd: WireCommandBuffer&, index: u64) -> bool {
    guard hpack_encode_indexed(cmd.hpack_staging, index) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Encodes a literal header field without indexing into the active HEADERS block (RFC 7541 Section 6.2.2).
fn hpack_literal_without_indexing(cmd: WireCommandBuffer&, name: const u8[:], val: const u8[:]) -> bool {
    guard hpack_encode_literal_without_indexing(cmd.hpack_staging, name, val) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Encodes a literal header field never indexed into the active HEADERS block (RFC 7541 Section 6.2.3).
fn hpack_literal_never_indexed(cmd: WireCommandBuffer&, name: const u8[:], val: const u8[:]) -> bool {
    guard hpack_encode_literal_never_indexed(cmd.hpack_staging, name, val) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Completes active HEADERS block, emitting 9-byte frame header and staged HPACK payload.
fn end_h2_headers(cmd: WireCommandBuffer&) -> bool {
    let payload_len = cmd.hpack_staging.len as u32;
    let hdr = WireFrameHeader {
        length:     payload_len,
        frame_type: H2_FRAME_HEADERS,
        flags:      cmd.active_headers_flags,
        stream_id:  cmd.active_headers_stream,
    };
    guard encode_frame_header(hdr, cmd.buf) else {
        cmd.has_error = true;
        return false;
    }
    guard cmd.buf.try_append(cmd.hpack_staging[..]) else {
        cmd.has_error = true;
        return false;
    }
    cmd.hpack_staging.clear();
    return true;
}
