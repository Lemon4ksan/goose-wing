// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Vulkan-style zero-allocation wire command buffer recording and in-place frame backpatching.
namespace wire;

import std;
import core from "..";
import http.headers;
import http2.hpack;
import http3.qpack;
import .result;
import .types;
import .pool;
import .h1;
import .hpack;
import .h2;
import .h3;

// Maximum capacity for a stack-allocated wire command buffer (RFC 9113 / enterprise frames).
const WIRE_CMD_BUFFER_CAP: i64 = 16384;

// Maximum capacity of a WireCommandPool arena in bytes (4 x 16384-byte command buffer regions).
const WIRE_POOL_ARENA_CAP: i64 = 65536;

// Maximum concurrent 16384-byte command buffers carved from a single 64 KB WireCommandPool arena.
const WIRE_POOL_MAX_BUFFERS: u32 = 4;

// Command buffer lifecycle states (VkCommandBufferState).
enum WireCommandBufferState {
    Initial,
    Recording,
    RecordingHeaders,
    Executable,
    Pending,
    Invalid,
}

// Command Buffer Usage Flags (matching VkCommandBufferUsageFlagBits).
const WIRE_COMMAND_BUFFER_USAGE_ONE_TIME_SUBMIT_BIT:  u32 = 0x00000001;
const WIRE_COMMAND_BUFFER_USAGE_SIMULTANEOUS_USE_BIT: u32 = 0x00000002;

// Parameter structure for beginning command buffer recording (VkCommandBufferBeginInfo).
struct WireCommandBufferBeginInfo {
    flags: u32 = 0,
}

// Bounded in-place binary command recorder with zero dynamic allocations and 9-byte header backpatching.
struct WireCommandBuffer {
    buf:                   u8[..16384]            = [],
    has_error:             bool                   = false,
    state:                 WireCommandBufferState = WireCommandBufferState.Initial,
    flags:                 u32                    = 0,
    pool_generation:       u32                    = 0,
    headers_frame_offset:  i64                    = -1,
    active_headers_stream: u32                    = 0,
    active_headers_flags:  u8                     = 0,
    arena_offset:          i64                    = -1,
    arena_capacity:        i64                    = WIRE_CMD_BUFFER_CAP,
}

inline fn find_free_pool_slot_offset(slot_mask: u8) -> i64, i64, u8 {
    if (slot_mask & 1) == 0 {
        return 0, 16384, 1;
    }
    if (slot_mask & 2) == 0 {
        return 16384, 32768, 2;
    }
    if (slot_mask & 4) == 0 {
        return 32768, 49152, 4;
    }
    if (slot_mask & 8) == 0 {
        return 49152, 65536, 8;
    }
    return -1, -1, 0;
}

inline fn pool_slot_bit_for_offset(offset: i64) -> u8 {
    if offset == 0 {
        return 1;
    }
    if offset == 16384 {
        return 2;
    }
    if offset == 32768 {
        return 4;
    }
    if offset == 49152 {
        return 8;
    }
    return 0;
}

// Carves a contiguous zero-copy slice of `req_bytes` directly from `pool.arena` (u8[..65536]).
// Fails closed with `(false)` when `pool.arena` capacity (65536) is exceeded (Invariant 13).
fn allocate_pool_arena_slice(pool: WireCommandPool&, req_bytes: i64) -> const u8[:], i64, bool {
    let start_off = pool.arena.len;
    let next_len = start_off + req_bytes;
    guard pool.is_valid && req_bytes > 0 && next_len <= WIRE_POOL_ARENA_CAP else {
        return "", -1, false;
    }
    pool.arena.resize(next_len, 0);
    pool.allocated_count += 1;
    let view = pool.arena[start_off..next_len];
    return view, start_off, true;
}

inline fn is_valid_pool_slot_for_cmd(pool: const WireCommandPool&, cmd: const WireCommandBuffer&) -> bool {
    if cmd.pool_generation == 0 {
        return true;
    }
    guard cmd.pool_generation == pool.generation else { return false; }
    let bit = pool_slot_bit_for_offset(cmd.arena_offset);
    return bit != 0 && (pool.slot_mask & bit) != 0;
}

// Commits a recorded command buffer's wire frames directly into its carved region in `pool.arena`,
// returning the zero-copy arena slice view (`const u8[:]`).
fn commit_command_buffer_to_arena(
    pool: WireCommandPool&,
    cmd:  const WireCommandBuffer&,
) -> const u8[:], bool {
    let end_off = cmd.arena_offset + cmd.buf.len;
    guard pool.is_valid &&
          is_valid_pool_slot_for_cmd(pool, cmd) &&
          !cmd.has_error &&
          (cmd.state == WireCommandBufferState.Executable || cmd.state == WireCommandBufferState.Recording) &&
          cmd.arena_offset >= 0 &&
          cmd.buf.len <= cmd.arena_capacity &&
          end_off <= pool.arena.len else {
        return "", false;
    }
    core::ct_copy_bytes(pool.arena[cmd.arena_offset..end_off], cmd.buf[..]);
    return pool.arena[cmd.arena_offset..end_off], true;
}

inline fn clear_pool_slot_bit(slot_mask: u8, offset: i64) -> u8 {
    if offset == 0 {
        return slot_mask & 0xFE;
    }
    if offset == 16384 {
        return slot_mask & 0xFD;
    }
    if offset == 32768 {
        return slot_mask & 0xFB;
    }
    if offset == 49152 {
        return slot_mask & 0xF7;
    }
    return slot_mask;
}

fn claim_pool_command_slot(pool: WireCommandPool&, next_len: i64, bit: u8) {
    pool.allocated_count += 1;
    pool.slot_mask = pool.slot_mask | bit;
    if pool.arena.len < next_len {
        pool.arena.resize(next_len, 0);
    }
}

// Allocates a command buffer backed by a 16 KB region in `pool.arena` (VkAllocateCommandBuffers).
// Fails closed with `WireResult.ErrorOutOfDeviceMemory` if all 65,536 bytes of `pool.arena` are exhausted.
fn allocate_command_buffer(pool: WireCommandPool&) -> WireCommandBuffer, WireResult {
    guard pool.is_valid else {
        return WireCommandBuffer { .. }, WireResult.ErrorInitializationFailed;
    }
    let start_off, next_len, bit = find_free_pool_slot_offset(pool.slot_mask);
    guard bit != 0 else {
        return WireCommandBuffer { .. }, WireResult.ErrorOutOfDeviceMemory;
    }
    claim_pool_command_slot(pool, next_len, bit);
    return WireCommandBuffer {
        buf:                   [],
        has_error:             false,
        state:                 WireCommandBufferState.Initial,
        flags:                 0,
        pool_generation:       pool.generation,
        headers_frame_offset:  -1,
        active_headers_stream: 0,
        active_headers_flags:  0,
        arena_offset:          start_off,
        arena_capacity:        WIRE_CMD_BUFFER_CAP,
    }, WireResult.Success;
}

// Frees a command buffer back to its parent pool, reclaiming its arena region (VkFreeCommandBuffers).
fn free_command_buffer(pool: WireCommandPool&, cmd: WireCommandBuffer&) {
    let expected_end = cmd.arena_offset + cmd.arena_capacity;
    let prev_offset = cmd.arena_offset;
    let slot_valid = is_valid_pool_slot_for_cmd(pool, cmd);
    cmd.state = WireCommandBufferState.Invalid;
    cmd.buf.clear();
    cmd.has_error = false;
    cmd.headers_frame_offset = -1;
    cmd.active_headers_stream = 0;
    cmd.active_headers_flags = 0;
    cmd.arena_offset = -1;
    cmd.pool_generation = 0;

    guard pool.is_valid && slot_valid && prev_offset >= 0 && pool.allocated_count > 0 else { return; }
    pool.slot_mask = clear_pool_slot_bit(pool.slot_mask, prev_offset);
    pool.allocated_count -= 1;
    if pool.allocated_count == 0 {
        pool.slot_mask = 0;
        pool.arena.clear();
        return;
    }
    if expected_end == pool.arena.len && pool.slot_mask == 0 {
        pool.arena.resize(prev_offset);
    }
}

// Instantiates a new zero-allocation command buffer ready for direct recording.
fn new_command_buffer() -> WireCommandBuffer {
    return WireCommandBuffer {
        buf:                   [],
        has_error:             false,
        state:                 WireCommandBufferState.Recording,
        flags:                 0,
        headers_frame_offset:  -1,
        active_headers_stream: 0,
        active_headers_flags:  0,
        arena_offset:          -1,
        arena_capacity:        WIRE_CMD_BUFFER_CAP,
    };
}

// Begins recording on a command buffer (VkBeginCommandBuffer).
fn begin_command_buffer(
    cmd:  WireCommandBuffer&,
    info: const WireCommandBufferBeginInfo&,
) -> WireResult {
    guard cmd.state == WireCommandBufferState.Initial || cmd.state == WireCommandBufferState.Executable else {
        cmd.has_error = true;
        return WireResult.ErrorCommandRecordingActive;
    }
    cmd.buf.clear();
    cmd.has_error = false;
    cmd.headers_frame_offset = -1;
    cmd.active_headers_stream = 0;
    cmd.active_headers_flags = 0;
    cmd.flags = info.flags;
    cmd.state = WireCommandBufferState.Recording;
    return WireResult.Success;
}

// Completes recording of a command buffer (VkEndCommandBuffer).
fn end_command_buffer(cmd: WireCommandBuffer&) -> WireResult {
    guard cmd.state == WireCommandBufferState.Recording else {
        cmd.has_error = true;
        return WireResult.ErrorCommandNotRecording;
    }
    guard !cmd.has_error else {
        cmd.state = WireCommandBufferState.Invalid;
        return WireResult.ErrorCommandBufferLocked;
    }
    cmd.state = WireCommandBufferState.Executable;
    return WireResult.Success;
}

// Resets a command buffer to the Initial state (VkResetCommandBuffer).
fn reset_command_buffer(cmd: WireCommandBuffer&, flags: u32) -> WireResult {
    cmd.buf.clear();
    cmd.has_error = false;
    cmd.state = WireCommandBufferState.Initial;
    cmd.flags = 0;
    cmd.headers_frame_offset = -1;
    cmd.active_headers_stream = 0;
    cmd.active_headers_flags = 0;
    return WireResult.Success;
}

// Returns remaining capacity in underlying buffer.
inline fn available(cmd: const WireCommandBuffer&) -> i64 {
    let rem = cmd.buf.cap - cmd.buf.len;
    return if rem > 0 { rem } else { 0 };
}

// Resets recording cursor to reuse buffer.
fn reset(cmd: WireCommandBuffer&) {
    cmd.buf.clear();
    cmd.has_error = false;
    cmd.state = WireCommandBufferState.Initial;
    cmd.flags = 0;
    cmd.headers_frame_offset = -1;
    cmd.active_headers_stream = 0;
    cmd.active_headers_flags = 0;
}

// ---- Primitive serialization operations -------------------------------------

// Writes an octet to buffer.
fn write_u8(cmd: WireCommandBuffer&, val: u8) -> bool {
    guard cmd.state == WireCommandBufferState.Recording else {
        cmd.has_error = true;
        return false;
    }
    guard cmd.buf.try_push(val) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Writes a 16-bit big-endian unsigned integer.
fn write_u16_be(cmd: WireCommandBuffer&, val: u16) -> bool {
    guard cmd.state == WireCommandBufferState.Recording else {
        cmd.has_error = true;
        return false;
    }
    let bytes: u8[2] = [
        ((val >> 8) & 0xFF) as u8,
        (val & 0xFF) as u8,
    ];
    guard cmd.buf.try_append(bytes[..]) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Writes a 24-bit big-endian unsigned integer (RFC 9113 Section 4.1).
fn write_u24_be(cmd: WireCommandBuffer&, val: u32) -> bool {
    guard cmd.state == WireCommandBufferState.Recording else {
        cmd.has_error = true;
        return false;
    }
    guard val <= rfc::H2_MAX_FRAME_SIZE_LIMIT else {
        cmd.has_error = true;
        return false;
    }
    let bytes: u8[3] = [
        ((val >> 16) & 0xFF) as u8,
        ((val >> 8) & 0xFF) as u8,
        (val & 0xFF) as u8,
    ];
    guard cmd.buf.try_append(bytes[..]) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Writes a 32-bit big-endian unsigned integer.
fn write_u32_be(cmd: WireCommandBuffer&, val: u32) -> bool {
    guard cmd.state == WireCommandBufferState.Recording else {
        cmd.has_error = true;
        return false;
    }
    let bytes: u8[4] = [
        ((val >> 24) & 0xFF) as u8,
        ((val >> 16) & 0xFF) as u8,
        ((val >> 8) & 0xFF) as u8,
        (val & 0xFF) as u8,
    ];
    guard cmd.buf.try_append(bytes[..]) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Writes a raw byte sequence into buffer.
fn write_raw(cmd: WireCommandBuffer&, data: const u8[:]) -> bool {
    guard cmd.state == WireCommandBufferState.Recording else {
        cmd.has_error = true;
        return false;
    }
    guard cmd.buf.try_append(data) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// ---- HTTP/2 Protocol Frame Commands -----------------------------------------

// Writes the 24-byte HTTP/2 client connection preface (RFC 9113 Section 3.4).
fn write_h2_preface(cmd: WireCommandBuffer&) -> bool {
    return write_raw(cmd, rfc::H2_CLIENT_PREFACE[..]);
}

// Writes a 9-byte binary frame header.
fn write_h2_frame_header(cmd: WireCommandBuffer&, hdr: const WireFrameHeader&) -> bool {
    guard cmd.state == WireCommandBufferState.Recording else {
        cmd.has_error = true;
        return false;
    }
    guard encode_frame_header(hdr, cmd.buf) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Writes an HTTP/2 SETTINGS frame (RFC 9113 Section 6.5).
fn write_h2_settings(cmd: WireCommandBuffer&, settings: const WireSetting[:]) -> bool {
    guard cmd.state == WireCommandBufferState.Recording else {
        cmd.has_error = true;
        return false;
    }
    guard encode_settings_frame(settings, cmd.buf) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Writes a WINDOW_UPDATE frame (RFC 9113 Section 6.9).
fn write_h2_window_update(cmd: WireCommandBuffer&, stream_id: u32, increment: u32) -> bool {
    guard cmd.state == WireCommandBufferState.Recording else {
        cmd.has_error = true;
        return false;
    }
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
    guard cmd.state == WireCommandBufferState.Recording else {
        cmd.has_error = true;
        return false;
    }
    guard encode_priority_update_frame(prioritized_stream_id, urgency, incremental, cmd.buf) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Writes a RST_STREAM frame (RFC 9113 Section 6.4).
fn write_h2_rst_stream(cmd: WireCommandBuffer&, stream_id: u32, error_code: u32) -> bool {
    guard cmd.state == WireCommandBufferState.Recording else {
        cmd.has_error = true;
        return false;
    }
    guard encode_rst_stream_frame(stream_id, error_code, cmd.buf) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Writes a PING frame with an 8-byte payload (RFC 9113 Section 6.7).
fn write_h2_ping(cmd: WireCommandBuffer&, payload: const u8[8], is_ack: bool) -> bool {
    guard cmd.state == WireCommandBufferState.Recording else {
        cmd.has_error = true;
        return false;
    }
    guard encode_ping_frame(payload, is_ack, cmd.buf) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Writes a DATA frame (RFC 9113 Section 6.1).
fn write_h2_data(
    cmd:        WireCommandBuffer&,
    stream_id:  u32,
    payload:    const u8[:],
    end_stream: bool,
) -> bool {
    guard cmd.state == WireCommandBufferState.Recording else {
        cmd.has_error = true;
        return false;
    }
    guard encode_data_frame(stream_id, payload, end_stream, cmd.buf) else {
        cmd.has_error = true;
        return false;
    }
    return true;
}

// ---- Vulkan-style Dynamic HEADERS Frame Recording with In-Place Backpatching -

inline fn rollback_headers_frame_on_error(cmd: WireCommandBuffer&) {
    if cmd.headers_frame_offset >= 0 && cmd.headers_frame_offset <= cmd.buf.len {
        cmd.buf.resize(cmd.headers_frame_offset);
    }
    cmd.headers_frame_offset = -1;
    cmd.active_headers_stream = 0;
    cmd.active_headers_flags = 0;
    cmd.has_error = true;
    if cmd.state == WireCommandBufferState.RecordingHeaders {
        cmd.state = WireCommandBufferState.Recording;
    }
}

// Begins a dynamic HEADERS frame block by reserving 9 bytes in-place at `cmd.headers_frame_offset`.
fn begin_h2_headers(cmd: WireCommandBuffer&, stream_id: u32, flags: u8) -> bool {
    guard cmd.state == WireCommandBufferState.Recording &&
          !cmd.has_error &&
          stream_id > 0 &&
          stream_id <= 0x7FFFFFFF else {
        cmd.has_error = true;
        return false;
    }
    let start_off = cmd.buf.len;
    let zero_hdr: u8[9] = [0; 9];
    guard cmd.buf.try_append(zero_hdr[..]) else {
        cmd.has_error = true;
        return false;
    }
    cmd.headers_frame_offset = start_off;
    cmd.active_headers_stream = stream_id;
    cmd.active_headers_flags = flags;
    cmd.state = WireCommandBufferState.RecordingHeaders;
    return true;
}

// Encodes an indexed header field representation directly into `cmd.buf` (RFC 7541 Section 6.1).
fn hpack_indexed(cmd: WireCommandBuffer&, index: u64) -> bool {
    guard cmd.state == WireCommandBufferState.RecordingHeaders && !cmd.has_error else {
        cmd.has_error = true;
        return false;
    }
    guard hpack_encode_indexed(cmd.buf, index) else {
        rollback_headers_frame_on_error(cmd);
        return false;
    }
    return true;
}

// Encodes a literal header field without indexing directly into `cmd.buf` (RFC 7541 Section 6.2.2).
fn hpack_literal_without_indexing(cmd: WireCommandBuffer&, name: const u8[:], val: const u8[:]) -> bool {
    guard cmd.state == WireCommandBufferState.RecordingHeaders && !cmd.has_error else {
        cmd.has_error = true;
        return false;
    }
    guard hpack_encode_literal_without_indexing(cmd.buf, name, val) else {
        rollback_headers_frame_on_error(cmd);
        return false;
    }
    return true;
}

// Encodes a literal header field never indexed directly into `cmd.buf` (RFC 7541 Section 6.2.3).
fn hpack_literal_never_indexed(cmd: WireCommandBuffer&, name: const u8[:], val: const u8[:]) -> bool {
    guard cmd.state == WireCommandBufferState.RecordingHeaders && !cmd.has_error else {
        cmd.has_error = true;
        return false;
    }
    guard hpack_encode_literal_never_indexed(cmd.buf, name, val) else {
        rollback_headers_frame_on_error(cmd);
        return false;
    }
    return true;
}

// Completes active HEADERS block by backpatching the 9-byte frame header at `cmd.headers_frame_offset`.
fn end_h2_headers(cmd: WireCommandBuffer&) -> bool {
    guard cmd.state == WireCommandBufferState.RecordingHeaders && !cmd.has_error else {
        rollback_headers_frame_on_error(cmd);
        return false;
    }
    guard patch_frame_header_slice(
        cmd.buf[..],
        cmd.headers_frame_offset,
        rfc::H2_FRAME_HEADERS,
        cmd.active_headers_flags,
        cmd.active_headers_stream,
    ) else {
        rollback_headers_frame_on_error(cmd);
        return false;
    }
    cmd.headers_frame_offset = -1;
    cmd.state = WireCommandBufferState.Recording;
    return true;
}

// ---- Multi-Protocol Command Recording (HTTP/1.1, HTTP/2, HTTP/3) -------------

// Records an HTTP/1.1 request head and optional body into `cmd.buf` (RFC 9112 §3–§6).
fn cmd_encode_h1_request(
    cmd:         WireCommandBuffer&,
    method:      const u8[:],
    target:      const u8[:],
    host:        const u8[:],
    headers:     const wing::HeaderMap&,
    body:        const u8[:],
    filter_mode: H1HeaderFilterMode = H1HeaderFilterMode.PreserveAll,
) -> bool {
    guard cmd.state == WireCommandBufferState.Recording && !cmd.has_error else {
        cmd.has_error = true;
        return false;
    }
    let start_len = cmd.buf.len;
    guard encode_h1_request(method, target, host, headers, body, filter_mode, cmd.buf) else {
        cmd.buf.resize(start_len);
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Records an HTTP/1.1 response head and body into `cmd.buf` (RFC 9112 §4).
fn cmd_encode_h1_response(
    cmd:             WireCommandBuffer&,
    status_code:     u16,
    reason:          const u8[:],
    server_name:     const u8[:],
    headers:         const wing::HeaderMap&,
    body:            const u8[:],
    is_head_request: bool = false,
) -> bool {
    guard cmd.state == WireCommandBufferState.Recording && !cmd.has_error else {
        cmd.has_error = true;
        return false;
    }
    let start_len = cmd.buf.len;
    guard encode_h1_response(status_code, reason, server_name, headers, body, is_head_request, cmd.buf) else {
        cmd.buf.resize(start_len);
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Records an HTTP/2 HEADERS frame (and any CONTINUATION frames) from `pseudo` and `headers` into `cmd.buf`.
fn cmd_encode_h2_headers_map(
    cmd:            WireCommandBuffer&,
    dt:             internal::DynamicTable&,
    stream_id:      u32,
    pseudo:         const internal::H2PseudoHeaders&,
    headers:        const wing::HeaderMap&,
    end_stream:     bool,
    max_frame_size: u32 = 16384,
) -> bool {
    guard cmd.state == WireCommandBufferState.Recording && !cmd.has_error else {
        cmd.has_error = true;
        return false;
    }
    let start_len = cmd.buf.len;
    guard encode_h2_headers_frame_from_map(dt, stream_id, pseudo, headers, end_stream, cmd.buf, max_frame_size) else {
        cmd.buf.resize(start_len);
        cmd.has_error = true;
        return false;
    }
    return true;
}

// Records an HTTP/3 HEADERS frame from `pseudo` and `headers` into `cmd.buf` using QPACK `tbl` (RFC 9114 §7.2.2).
fn cmd_encode_h3_headers_map<B>(
    cmd:            WireCommandBuffer&,
    tbl:            internal::QpackTable&,
    stream_id:      u64,
    pseudo:         const internal::H3PseudoHeaders&,
    headers:        const wing::HeaderMap&,
    out_enc_stream: B&,
) -> bool {
    guard cmd.state == WireCommandBufferState.Recording && !cmd.has_error else {
        cmd.has_error = true;
        return false;
    }
    let start_len = cmd.buf.len;
    let start_enc = out_enc_stream.len;
    guard encode_h3_headers_from_map(tbl, stream_id, pseudo, headers, out_enc_stream, cmd.buf) else {
        cmd.buf.resize(start_len);
        out_enc_stream.resize(start_enc);
        cmd.has_error = true;
        return false;
    }
    return true;
}
