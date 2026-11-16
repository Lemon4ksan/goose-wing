// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// WebSocket Protocol Framing and Handshake Engine (RFC 6455 & RFC 8441).
// Features:
// - Zero-copy in-place 64-bit unrolled payload masking / unmasking
// - Complete frame header parser, serializer, and control frame invariant enforcer
// - RFC 6455 Section 4.2.2 Sec-WebSocket-Key / Accept handshake verification via SHA-1
// - Close frame payload encoding and status code validation
namespace wing;

import std;
import core from "..";
import .ws_deflate;
import .ws_handshake;

// Native CSPRNG & SIMD shims
extern fn native_crypto_random_bytes(out: u8[:]) -> i32 = "wing_crypto_random_bytes";
extern fn native_simd_mask_websocket(data: u8[:], mask: const u8[4]&) = "wing_simd_mask_websocket";
extern fn native_simd_unmask_shifted(
    slice:       u8[:],
    header_len:  i64,
    payload_len: i64,
    mask:        const u8[4]&,
) = "wing_simd_unmask_shifted";

// In-place zero-copy unmasking that shifts the unmasked payload back over the frame header
// (uWebSockets unmaskImprecise8). Overwrites header directly in slice and returns payload slice.
fn unmask_websocket_shifted(frame: u8[:], header_len: i64, payload_len: i64, mask_key: const u8[4]&) -> u8[:] {
    guard payload_len > 0 && header_len > 0 && header_len <= frame.len && payload_len <= frame.len - header_len else {
        return frame[..0];
    }
    native_simd_unmask_shifted(frame, header_len, payload_len, mask_key);
    return frame[..payload_len];
}

// ---- Frame Header Structure and Invariants ------------------------------

struct WsFrameHeader {
    fin:         bool  = true,
    rsv1:        bool  = false,
    rsv2:        bool  = false,
    rsv3:        bool  = false,
    opcode:      u8    = rfc::WS_OPCODE_TEXT,
    masked:      bool  = false,
    mask_key:    u8[4] = [0; 4],
    payload_len: u64   = 0,
    header_len:  u16   = 0,
}

// RFC 6455 Section 5.2: Base Framing Protocol - Frame header bitmasks and length sentinels.
const WS_FIN_BIT:          u8  = 0x80;
const WS_RSV1_BIT:         u8  = 0x40;
const WS_RSV2_BIT:         u8  = 0x20;
const WS_RSV3_BIT:         u8  = 0x10;
const WS_OPCODE_MASK:      u8  = 0x0F;
const WS_MASK_BIT:         u8  = 0x80;
const WS_PAYLOAD_LEN_MASK: u8  = 0x7F;
const WS_LEN16_SENTINEL:   u64 = 126;
const WS_MAX_CONTROL_LEN:  u64 = 125;

// Packs the first byte of an RFC 6455 Section 5.2 frame header (`FIN | RSV1..3 | Opcode`).
//
// Example:
//   hdr = WsFrameHeader { fin: true, opcode: 1, .. }, eff_fin = true
//   returns: 0x81
inline fn pack_ws_frame_b0(hdr: const WsFrameHeader&, eff_fin: bool) -> u8 {
    var b0: u8 = hdr.opcode & WS_OPCODE_MASK;
    if eff_fin { b0 |= WS_FIN_BIT; }
    if hdr.rsv1 { b0 |= WS_RSV1_BIT; }
    if hdr.rsv2 { b0 |= WS_RSV2_BIT; }
    if hdr.rsv3 { b0 |= WS_RSV3_BIT; }
    return b0;
}

// In-place SWAR 64-bit/32-bit XOR masking loop (RFC 6455 Section 5.3)
// Vectorizes payload masking in pure Goose using 64-bit word iterations without heap allocations
// or out-of-bounds reads.
fn apply_mask_in_place(data: u8[:], mask_key: const u8[4]&) {
    let n = data.len;
    guard n > 0 else { return; }

    let m0 = mask_key[0] as u64;
    let m1 = mask_key[1] as u64;
    let m2 = mask_key[2] as u64;
    let m3 = mask_key[3] as u64;

    let m32_be = (m0 << 24) | (m1 << 16) | (m2 << 8) | m3;
    let m64_be = (m32_be << 32) | m32_be;

    var i: i64 = 0;

    // 64-bit SWAR loop: process 8 bytes per iteration
    while core::add_sat_i64(i, 8) <= n {
        let w = core::read_be_u64(data, i);
        core::write_be_u64_at(data, i, w ^ m64_be);
        i = core::add_sat_i64(i, 8);
    }

    // 32-bit SWAR tail: process remaining 4 bytes if present
    if core::add_sat_i64(i, 4) <= n {
        let w = core::read_be_u32(data, i);
        core::write_be_u32_at(data, i, w ^ (m32_be as u32));
        i = core::add_sat_i64(i, 4);
    }

    // Scalar byte-by-byte tail (0..3 bytes)
    while i < n {
        data[i] = data[i] ^ mask_key[i % 4];
        i = core::add_sat_i64(i, 1);
    }
}

// In-place masking / unmasking using vectorized SIMD acceleration with 64-bit unrolled fallback (RFC 6455 Section 5.3)
fn mask_websocket_payload(data: u8[:], mask_key: const u8[4]&) {
    let n = data.len;
    guard n > 0 else { return; }
    if n >= 64 {
        native_simd_mask_websocket(data, mask_key);
    } else {
        apply_mask_in_place(data, mask_key);
    }
}

// Parses RFC 6455 Frame Header with strict protocol validation
//
// Example:
//   src = [0x81, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F]
//   returns: WsFrameHeader { fin: true, opcode: 1, payload_len: 5, header_len: 2, ... }, ok = true
fn parse_ws_frame_header(src: const u8[:]) -> WsFrameHeader, bool {
    var hdr = WsFrameHeader { .. };
    guard src.len >= 2 else { return hdr, false; }

    let b0 = src[0];
    let b1 = src[1];

    let fin = (b0 & WS_FIN_BIT) != 0;
    let rsv1 = (b0 & WS_RSV1_BIT) != 0;
    let rsv2 = (b0 & WS_RSV2_BIT) != 0;
    let rsv3 = (b0 & WS_RSV3_BIT) != 0;
    let opcode = b0 & WS_OPCODE_MASK;

    guard rfc::is_valid_ws_opcode(opcode) else { return hdr, false; }

    let masked = (b1 & WS_MASK_BIT) != 0;
    let raw_len = (b1 & WS_PAYLOAD_LEN_MASK) as u64;

    // Control frame invariants (RFC 6455 Section 5.5):
    // 1. MUST NOT be fragmented (FIN MUST be 1)
    // 2. Payload length MUST be <= 125 (extended length encodings 126/127 are forbidden)
    if rfc::is_ws_control_opcode(opcode) {
        guard fin && raw_len <= WS_MAX_CONTROL_LEN else { return hdr, false; }
    }

    var offset:      i64 = 2;
    var payload_len: u64 = 0;

    if raw_len <= WS_MAX_CONTROL_LEN {
        payload_len = raw_len;
    } else if raw_len == WS_LEN16_SENTINEL {
        guard src.len >= core::add_sat_i64(offset, 2) else { return hdr, false; }
        payload_len = core::read_be_u16(src, offset);
        // RFC 6455 Section 5.2: minimal encoding check (must be >= 126)
        guard payload_len >= WS_LEN16_SENTINEL else { return hdr, false; }
        offset = core::add_sat_i64(offset, 2);
    } else {
        // raw_len == 127
        guard src.len >= core::add_sat_i64(offset, 8) else { return hdr, false; }
        // High bit must be 0 per RFC 6455 Section 5.2
        guard (src[offset] & WS_FIN_BIT) == 0 else { return hdr, false; }
        payload_len = core::read_be_u64(src, offset);
        // Minimal encoding check (must be > 65535)
        guard payload_len > 65535 else { return hdr, false; }
        offset = core::add_sat_i64(offset, 8);
    }

    // Control frames payload length must not exceed 125 bytes
    if rfc::is_ws_control_opcode(opcode) {
        guard payload_len <= WS_MAX_CONTROL_LEN else { return hdr, false; }
    }

    var mask_key: u8[4] = [0; 4];
    if masked {
        guard src.len >= core::add_sat_i64(offset, 4) else { return hdr, false; }
        mask_key = [
            src[offset],
            src[core::add_sat_i64(offset, 1)],
            src[core::add_sat_i64(offset, 2)],
            src[core::add_sat_i64(offset, 3)],
        ];
        offset = core::add_sat_i64(offset, 4);
    }

    hdr.fin = fin;
    hdr.rsv1 = rsv1;
    hdr.rsv2 = rsv2;
    hdr.rsv3 = rsv3;
    hdr.opcode = opcode;
    hdr.masked = masked;
    hdr.mask_key = mask_key;
    hdr.payload_len = payload_len;
    hdr.header_len = offset as u16;

    return hdr, true;
}

// Encodes an RFC 6455 frame header into `out`, rolling back on insufficient capacity.
fn try_encode_ws_header<B>(hdr: const WsFrameHeader&, out: B&) -> bool {
    var hdr_buf: u8[..14] = [];
    let eff_fin = if rfc::is_ws_control_opcode(hdr.opcode) { true } else { hdr.fin };
    hdr_buf.push(pack_ws_frame_b0(hdr, eff_fin));

    let mask_bit: u8 = if hdr.masked { WS_MASK_BIT } else { 0x00 };

    // RFC 6455 §5.5 & uWS #1407: Control frames MUST NOT exceed 125 bytes and MUST NEVER use extended length
    let eff_len = if rfc::is_ws_control_opcode(hdr.opcode) {
        min(hdr.payload_len, WS_MAX_CONTROL_LEN)
    } else {
        hdr.payload_len
    };

    if eff_len <= WS_MAX_CONTROL_LEN {
        hdr_buf.push(mask_bit | (eff_len as u8));
    } else if eff_len <= 65535 {
        hdr_buf.push(mask_bit | 126);
        hdr_buf.append_u16_be(eff_len as u16);
    } else {
        hdr_buf.push(mask_bit | 127);
        hdr_buf.append_u64_be(eff_len);
    }

    if hdr.masked {
        hdr_buf.append(hdr.mask_key[..]);
    }
    return out.try_append(hdr_buf[..]);
}

// Encodes RFC 6455 Frame Header
fn encode<B>(hdr: const WsFrameHeader&, out: B&) {
    let _ = try_encode_ws_header(hdr, out);
}

// Serializes an RFC 6455 frame (header + optional masked payload) with atomic rollback on overflow.
fn try_encode_ws_frame<B>(
    out:       B&,
    opcode:    u8,
    payload:   const u8[:],
    is_client: bool        = true,
    mask_key:  const u8[4] = [0 as u8; 4],
    fin:       bool        = true,
) -> bool {
    let eff_payload = if rfc::is_ws_control_opcode(opcode) && payload.len > 125 { payload[..125] } else { payload };
    let eff_fin = if rfc::is_ws_control_opcode(opcode) { true } else { fin };

    let hdr = WsFrameHeader {
        fin:         eff_fin,
        opcode:      opcode,
        masked:      is_client,
        mask_key:    mask_key,
        payload_len: eff_payload.len as u64,
        ..
    };
    let saved_len = out.len;
    guard try_encode_ws_header(hdr, out) else { return false; }

    let payload_start = out.len;
    guard out.try_append(eff_payload) else {
        out.resize(saved_len);
        return false;
    }
    if is_client {
        mask_websocket_payload(out[payload_start..out.len], mask_key);
    }
    return true;
}

// High-level frame serializer: writes header + payload (masked if is_client)
fn encode_ws_frame<B>(
    out:       B&,
    opcode:    u8,
    payload:   const u8[:],
    is_client: bool        = true,
    mask_key:  const u8[4] = [0 as u8; 4],
    fin:       bool        = true,
) {
    let _ = try_encode_ws_frame(out, opcode, payload, is_client, mask_key, fin);
}

// Computes exact WebSocket frame wire length including header, extended length, mask key, and payload
fn calc_ws_frame_len(payload_len: u64, is_client: bool) -> u64 {
    let ext_len:  u64 = if payload_len > 65535 { 8 } else if payload_len > 125 { 2 } else { 0 };
    let mask_len: u64 = if is_client { 4 } else { 0 };
    return 2 + ext_len + mask_len + payload_len;
}

// ---- Close Frame Helpers (RFC 6455 Section 5.5.1) -----------------------

// Encodes a Close frame payload (2-byte status code + optional UTF-8 reason)
fn encode_close_payload<B>(out: B&, status_code: u16, reason: const u8[:]) {
    guard rfc::is_valid_ws_close_code(status_code) else { return; }
    // RFC 6455 §5.5 & §5.5.1 / uWS #1407: Control frame payload must NOT exceed 125 bytes.
    // Close payload contains 2-byte status code, so reason is clamped to at most 123 bytes.
    var eff_len = min(reason.len, 123);
    if reason.len > 123 {
        // Avoid truncating in the middle of a multi-byte UTF-8 sequence:
        // A cut at eff_len splits a UTF-8 codepoint iff reason[eff_len] is a continuation byte (10xxxxxx).
        while eff_len > 0 && (reason[eff_len] & 0xC0) == 0x80 {
            eff_len = core::sub_sat_i64(eff_len, 1);
        }
    }
    let reason_slice = reason[..eff_len];
    guard reason_slice.len == 0 || reason_slice.validate_utf8() else { return; }

    var code_be: u8[2] = [((status_code >> 8) & 0xFF) as u8, (status_code & 0xFF) as u8];
    let saved_len = out.len;
    if !out.try_append(code_be[..]) || !out.try_append(reason_slice) {
        out.resize(saved_len);
    }
}

// Parses a Close frame payload into (status_code, reason_slice, ok)
//
// Example:
//   payload = [0x03, 0xE8, 'b', 'y', 'e']
//   returns: status_code = 1000, reason = "bye", ok = true
fn parse_close_payload(payload: const u8[:]) -> u16, const u8[:], bool {
    if payload.len == 0 {
        return rfc::WS_STATUS_NO_STATUS, "", true;
    }
    guard payload.len >= 2 else { return 0, "", false; }
    // RFC 6455 Section 5.5 & 5.5.1: Control frame payload must not exceed 125 bytes
    guard payload.len <= 125 else { return 0, "", false; }

    let status_code = core::read_be_u16(payload, 0);
    let reason = payload[2..];

    // RFC 6455 Section 7.4.1 & 7.4.2: Validate permitted status codes on wire
    guard rfc::is_valid_ws_close_code(status_code) else { return 0, "", false; }

    return status_code, reason, true;
}

// ---- High-Level Ergonomic WebSocket Client Session -----------------------

// Backpressure and Send Status Codes (uWebSockets pattern)
enum WsSendStatus {
    Success,      // Sent immediately or queued below backpressure threshold
    Backpressure, // Queued successfully, but socket has active backpressure (buffered_amount > 0)
    Dropped,      // Message dropped because max_backpressure limit was exceeded
    Closed,       // Socket was closed or aborted due to backpressure overflow
}

// Declarative WebSocket Endpoint Behavior Specification (uWebSockets App::ws pattern)
struct WsBehavior {
    compression:                 u16      = WS_COMPRESS_DISABLED, // WS_COMPRESS_SHARED_COMPRESSOR
    max_payload_length:          u64      = 65536,
    idle_timeout_s:              u32      = 120,
    max_lifetime_s:              u32      = 0, // Maximum session duration in seconds (0 = unlimited)
    max_backpressure:            u64      = 1048576, // 1 MB default
    close_on_backpressure_limit: bool     = false,
    reset_idle_timeout_on_send:  bool     = true,
    send_pings_automatically:    bool     = false,
    subprotocol:                 u8[..64] = [],
    handler_id:                  i32      = -1,
}

fn new_ws_behavior(handler_id: i32 = -1) -> WsBehavior {
    return WsBehavior { handler_id: handler_id, .. };
}

struct WebSocketSession {
    is_client:          bool     = true,
    subprotocol:        u8[..64] = [],
    is_closed:          bool     = false,
    close_sent:         bool     = false, // RFC 6455 §5.5.1: Local close frame sent
    close_received:     bool     = false, // RFC 6455 §5.5.1: Peer close frame received
    close_code:         u16      = 0,
    close_sent_ms:      u64      = 0,
    close_timeout_ms:   u64      = 5000,
    max_payload_length: u64      = 65536,      // Maximum allowed frame payload length (0 = unlimited)
    mask_rng_state:     u32      = 0x9E3779B9, // Fast linear congruential PRNG for 4-byte client masking keys

    // Multi-frame fragmented message assembly (RFC 6455 §5.4 & RFC 7692 §5.1)
    tx_fragmented:    bool        = false, // Outbound fragmented message currently in flight
    frag_opcode:      u8          = 0,     // 0 if no active fragmentation; WS_OPCODE_TEXT or WS_OPCODE_BINARY
    frag_compressed:  bool        = false, // RFC 7692: remembers if initial fragment had RSV1 set
    frag_utf8_offset: i64         = 0,     // Validated UTF-8 prefix byte offset across streaming fragments
    utf8_dfa_state:   u8          = 0,     // Bjoern Hoehrmann 364-byte DFA state across streaming text fragments
    frag_buffer:      u8[..65536] = [],    // Assembly buffer for fragmented messages

    // RFC 7692 PerMessageDeflate configuration (uWebSockets pattern)
    compress_mode:              u16  = WS_COMPRESS_DISABLED,
    permessage_deflate:         bool = false,
    server_no_context_takeover: bool = true,
    client_no_context_takeover: bool = true,

    // Per-socket UserData / Typed User Context (uWebSockets getUserData pattern)
    user_tag:  u64       = 0,
    user_data: u8[..128] = [],

    // Backpressure & Dynamic Flow Control (uWebSockets Backpressure pattern)
    buffered_amount:             u64  = 0,
    max_backpressure:            u64  = 1048576, // 1 MB default
    close_on_backpressure_limit: bool = false,
    is_backpressured:            bool = false,
    dropped_messages_count:      u64  = 0,

    // Keep-Alive & Auto-Ping Heartbeat (uWebSockets sendPingsAutomatically & idleTimeout)
    idle_timeout_s:             u32  = 120,
    max_lifetime_s:             u32  = 0,
    elapsed_lifetime_s:         u32  = 0,
    send_pings_automatically:   bool = false,
    reset_idle_timeout_on_send: bool = true,
    timeout_slot:               u8   = core::TICK_TIMER_DISARMED,
    ping_slot:                  u8   = core::TICK_TIMER_DISARMED,
    pings_sent:                 u64  = 0,
    pongs_received:             u64  = 0,
}

fn new_websocket_session(is_client: bool = true) -> WebSocketSession {
    return WebSocketSession { is_client: is_client, .. };
}

fn set_max_payload_length(ws: WebSocketSession&, max_len: u64) {
    ws.max_payload_length = max_len;
}

// Heartbeat action result for WebSocket keep-alive / auto-ping daemon
enum WsHeartbeatAction {
    None,
    SendPing,
    CloseIdle,
    CloseMaxLifetime,
}

// Arms connection slot timeouts in modular tick wheel (uSockets loop.c / uWebSockets pattern)
fn arm_heartbeat(ws: WebSocketSession&, wheel: const core::TickTimerWheel&) {
    if ws.idle_timeout_s > 0 {
        let idle_sec = min(ws.idle_timeout_s, 239) as u8;
        ws.timeout_slot = core::tick_timer_arm(wheel, idle_sec);
        if ws.send_pings_automatically && ws.idle_timeout_s > 1 {
            let ping_delay = max(1, idle_sec / 2);
            ws.ping_slot = core::tick_timer_arm(wheel, ping_delay);
        } else {
            ws.ping_slot = core::TICK_TIMER_DISARMED;
        }
    } else {
        ws.timeout_slot = core::TICK_TIMER_DISARMED;
        ws.ping_slot = core::TICK_TIMER_DISARMED;
    }
}

// Disarms heartbeat timers
fn disarm_heartbeat(ws: WebSocketSession&) {
    ws.timeout_slot = core::TICK_TIMER_DISARMED;
    ws.ping_slot = core::TICK_TIMER_DISARMED;
}

// Advances session lifetime counter by elapsed_seconds (uWebSockets maxLifetime sweeper).
fn ws_advance_lifetime(ws: WebSocketSession&, elapsed_seconds: u32 = 1) {
    ws.elapsed_lifetime_s += elapsed_seconds;
}

// Touches the session to reset idle timeout on incoming frame or send
fn touch(ws: WebSocketSession&, wheel: const core::TickTimerWheel&) {
    if ws.timeout_slot != core::TICK_TIMER_DISARMED {
        arm_heartbeat(ws, wheel);
    }
}

// Evaluates heartbeat tick without serializing wire bytes
fn check_heartbeat(ws: WebSocketSession&, wheel: const core::TickTimerWheel&) -> WsHeartbeatAction {
    if ws.is_closed { return WsHeartbeatAction.None; }
    if ws.max_lifetime_s > 0 && ws.elapsed_lifetime_s >= ws.max_lifetime_s {
        return WsHeartbeatAction.CloseMaxLifetime;
    }
    if ws.timeout_slot != core::TICK_TIMER_DISARMED && core::tick_timer_is_expired(wheel, ws.timeout_slot) {
        return WsHeartbeatAction.CloseIdle;
    }
    if !ws.close_received && !ws.close_sent && ws.send_pings_automatically &&
        ws.ping_slot != core::TICK_TIMER_DISARMED && core::tick_timer_is_expired(wheel, ws.ping_slot) {
        return WsHeartbeatAction.SendPing;
    }
    return WsHeartbeatAction.None;
}

// Executes periodic heartbeat check and automatically writes Ping or Close frame
fn tick_heartbeat<B>(ws: WebSocketSession&, wheel: const core::TickTimerWheel&, out_wire: B&) -> WsHeartbeatAction {
    let action = check_heartbeat(ws, wheel);
    if action == WsHeartbeatAction.SendPing {
        send_ping(ws, "", out_wire);
        let idle_sec = min(ws.idle_timeout_s, 239) as u8;
        let ping_delay = if ws.idle_timeout_s > 1 { max(1, idle_sec / 2) } else { 1 };
        ws.ping_slot = core::tick_timer_arm(wheel, ping_delay);
    } else if action == WsHeartbeatAction.CloseIdle {
        close(ws, rfc::WS_STATUS_NORMAL, "Idle timeout", out_wire);
        ws.is_closed = true;
        ws.close_code = rfc::WS_STATUS_NORMAL;
    } else if action == WsHeartbeatAction.CloseMaxLifetime {
        close(ws, rfc::WS_STATUS_NORMAL, "Max lifetime reached", out_wire);
        ws.is_closed = true;
        ws.close_code = rfc::WS_STATUS_NORMAL;
    }
    return action;
}

// Asynchronous WebSocket Upgrade Pending Context (uWebSockets res->onAborted & res->upgrade pattern)
struct WsPendingUpgrade {
    sock_fd:     i64       = -1,
    route_idx:   i32       = -1,
    client_key:  u8[..64]  = [],
    subprotocol: u8[..64]  = [],
    extensions:  u8[..256] = [],
    user_tag:    u64       = 0,
    user_data:   u8[..128] = [],
    is_aborted:  bool      = false,
    in_use:      bool      = false,
}

fn new_ws_pending_upgrade(
    sock_fd:     i64,
    client_key:  const u8[:],
    route_idx:   i32         = -1,
    subprotocol: const u8[:] = "",
    extensions:  const u8[:] = "",
) -> WsPendingUpgrade {
    var p = WsPendingUpgrade {
        sock_fd:    sock_fd,
        route_idx:  route_idx,
        is_aborted: false,
        in_use:     true,
        ..
    };
    let k_len = min(client_key.len, p.client_key.cap);
    p.client_key.append(client_key[..k_len]);
    if subprotocol.len > 0 {
        let s_len = min(subprotocol.len, p.subprotocol.cap);
        p.subprotocol.append(subprotocol[..s_len]);
    }
    if extensions.len > 0 {
        let e_len = min(extensions.len, p.extensions.cap);
        p.extensions.append(extensions[..e_len]);
    }
    return p;
}

fn abort(pending: WsPendingUpgrade&) {
    pending.is_aborted = true;
    pending.in_use = false;
}

fn abort_with_hook<AbortFn: fn(i64, u64)>(pending: WsPendingUpgrade&) {
    pending.is_aborted = true;
    pending.in_use = false;
    AbortFn(pending.sock_fd, pending.user_tag);
}

fn set_user_data(pending: WsPendingUpgrade&, data: const u8[:]) -> bool {
    return pending.user_data.try_set(data);
}

fn set_user_tag(pending: WsPendingUpgrade&, tag: u64) {
    pending.user_tag = tag;
}

// Per-Socket UserData accessors (zero-alloc inline context)
fn set_user_data(ws: WebSocketSession&, data: const u8[:]) -> bool {
    return ws.user_data.try_set(data);
}

fn set_user_tag(ws: WebSocketSession&, tag: u64) {
    ws.user_tag = tag;
}

fn set_max_backpressure(ws: WebSocketSession&, max_bytes: u64, close_on_limit: bool = false) {
    ws.max_backpressure = max_bytes;
    ws.close_on_backpressure_limit = close_on_limit;
}

// Notifies the session of outbound bytes buffered for delivery.
// Enforces max_backpressure and overflow drop/close policies.
fn notify_buffered<B>(ws: WebSocketSession&, bytes_added: u64, out_close: B&) -> WsSendStatus {
    guard !ws.is_closed && !ws.close_sent && !ws.close_received else { return WsSendStatus.Closed; }
    if bytes_added > ws.max_backpressure || ws.buffered_amount > ws.max_backpressure - bytes_added {
        if ws.close_on_backpressure_limit {
            close(ws, rfc::WS_STATUS_POLICY_VIOLATION, "backpressure limit exceeded", out_close);
            return WsSendStatus.Closed;
        } else {
            ws.dropped_messages_count += 1;
            return WsSendStatus.Dropped;
        }
    }
    ws.buffered_amount += bytes_added;
    if ws.buffered_amount > 0 {
        ws.is_backpressured = true;
        return WsSendStatus.Backpressure;
    }
    return WsSendStatus.Success;
}

// Notifies the session of completed network buffer drainage.
// Returns true when the buffer drops to 0 from a backpressured state, triggering the 'drain' event.
fn notify_drained(ws: WebSocketSession&, bytes_drained: u64) -> bool {
    if bytes_drained >= ws.buffered_amount {
        ws.buffered_amount = 0;
    } else {
        ws.buffered_amount -= bytes_drained;
    }
    if ws.buffered_amount == 0 && ws.is_backpressured {
        ws.is_backpressured = false;
        return true;
    }
    return false;
}

// Configures PerMessageDeflate (RFC 7692) on the WebSocket session
fn enable_permessage_deflate(
    ws:   WebSocketSession&,
    mode: u16 = WS_COMPRESS_SHARED_COMPRESSOR,
    opts: WsContextTakeoverOptions = WsContextTakeoverOptions {
        server_no_context: true,
        client_no_context: true,
    },
) {
    ws.permessage_deflate = true;
    ws.compress_mode = mode;
    ws.server_no_context_takeover = opts.server_no_context;
    ws.client_no_context_takeover = opts.client_no_context;
}

// Generates cryptographically secure 4-byte masking key for client frames per RFC 6455 Section 5.3.
fn ws_next_mask_key(ws: WebSocketSession&) -> u8[4] {
    var mask: u8[4] = [0; 4];
    if native_crypto_random_bytes(mask[..]) == 0 {
        return mask;
    }
    // High-entropy fallback if OS CSPRNG is unavailable
    ws.mask_rng_state = ws.mask_rng_state * 1664525 + 1013904223;
    let s = ws.mask_rng_state;
    return [
        ((s >> 24) & 0xFF) as u8,
        ((s >> 16) & 0xFF) as u8,
        ((s >> 8) & 0xFF) as u8,
        (s & 0xFF) as u8,
    ];
}

inline fn has_ws_header_ctl(s: const u8[:]) -> bool {
    for b in s {
        if b < 0x20 || b == 0x7F {
            return true;
        }
    }
    return false;
}

// Formats outbound RFC 6455 Handshake HTTP/1.1 Upgrade Request
fn build_handshake_request<B>(
    ws:         const WebSocketSession&,
    host:       const u8[:],
    path:       const u8[:],
    client_key: const u8[:],
    out:        B&,
) {
    // RFC 6455 §4.1 & RFC 9112 §3.2.1 & Go #76635: If path is empty, default to '/'
    let eff_path = if path.len > 0 { path } else { "/" };
    guard !has_ws_header_ctl(host) &&
        !has_ws_header_ctl(eff_path) &&
        !eff_path.contains_byte(' ') &&
        !has_ws_header_ctl(client_key) &&
        !has_ws_header_ctl(ws.subprotocol[..]) else {
        return;
    }
    format(out, "GET ", eff_path, " HTTP/1.1\r\nHost: ", host);
    format(
        out,
        "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ",
        client_key,
    );
    if ws.subprotocol.len > 0 {
        format(out, "\r\nSec-WebSocket-Protocol: ", ws.subprotocol[..]);
    }
    out.append("\r\n\r\n");
}

// High-level method: sends UTF-8 text message
fn send_text<B>(ws: WebSocketSession&, text: const u8[:], out: B&) {
    // RFC 6455 §5.5.1 & uWS #1932: Once closed or close sent/received, drop outgoing message writes
    guard !ws.is_closed && !ws.close_sent && !ws.close_received && !ws.tx_fragmented else { return; }
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    encode_ws_frame(out, rfc::WS_OPCODE_TEXT, text, ws.is_client, mask, true);
}

// Sends UTF-8 text message with backpressure tracking and status code (uWebSockets sendStatus pattern)
fn send_text_with_status<B>(
    ws:       WebSocketSession&,
    text:     const u8[:],
    out:      B&,
    compress: bool = false,
) -> WsSendStatus {
    guard !ws.is_closed && !ws.close_sent && !ws.close_received else { return WsSendStatus.Closed; }
    guard !ws.tx_fragmented else { return WsSendStatus.Dropped; }
    let frame_len = calc_ws_frame_len(text.len as u64, ws.is_client);
    let status = notify_buffered(ws, frame_len, out);
    if status == WsSendStatus.Dropped || status == WsSendStatus.Closed {
        return status;
    }
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    encode_ws_frame(out, rfc::WS_OPCODE_TEXT, text, ws.is_client, mask, true);
    return status;
}

// Sends UTF-8 text message with shared compressor and backpressure tracking
fn send_text_compressed_with_status<B>(
    ws:          WebSocketSession&,
    text:        const u8[:],
    shared_comp: SharedWsCompressor&,
    out:         B&,
    compress:    bool = true,
) -> WsSendStatus {
    guard !ws.is_closed && !ws.close_sent && !ws.close_received else { return WsSendStatus.Closed; }
    guard !ws.tx_fragmented else { return WsSendStatus.Dropped; }
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };

    if compress && ws.permessage_deflate && text.len > 0 {
        let reset_win = ws_should_reset_compressor(ws);
        let comp_wire, ok_comp = ws_deflate_message_slice(shared_comp, text, reset_win);
        if ok_comp && comp_wire.len < text.len {
            let frame_len = calc_ws_frame_len(comp_wire.len as u64, ws.is_client);
            let status = notify_buffered(ws, frame_len, out);
            if status == WsSendStatus.Dropped || status == WsSendStatus.Closed {
                return status;
            }
            encode_ws_frame_compressed(out, rfc::WS_OPCODE_TEXT, comp_wire, ws.is_client, mask, true);
            return status;
        }
    }

    let frame_len = calc_ws_frame_len(text.len as u64, ws.is_client);
    let status = notify_buffered(ws, frame_len, out);
    if status == WsSendStatus.Dropped || status == WsSendStatus.Closed {
        return status;
    }
    encode_ws_frame(out, rfc::WS_OPCODE_TEXT, text, ws.is_client, mask, true);
    return status;
}

// High-level method: sends binary message
fn send_binary<B>(ws: WebSocketSession&, data: const u8[:], out: B&) {
    // RFC 6455 §5.5.1 & uWS #1932: Once closed or close sent/received, drop outgoing message writes
    guard !ws.is_closed && !ws.close_sent && !ws.close_received && !ws.tx_fragmented else { return; }
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    encode_ws_frame(out, rfc::WS_OPCODE_BINARY, data, ws.is_client, mask, true);
}

// Sends binary message with backpressure tracking and status code (uWebSockets sendStatus pattern)
fn send_binary_with_status<B>(
    ws:       WebSocketSession&,
    data:     const u8[:],
    out:      B&,
    compress: bool = false,
) -> WsSendStatus {
    guard !ws.is_closed && !ws.close_sent && !ws.close_received else { return WsSendStatus.Closed; }
    guard !ws.tx_fragmented else { return WsSendStatus.Dropped; }
    let frame_len = calc_ws_frame_len(data.len as u64, ws.is_client);
    let status = notify_buffered(ws, frame_len, out);
    if status == WsSendStatus.Dropped || status == WsSendStatus.Closed {
        return status;
    }
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    encode_ws_frame(out, rfc::WS_OPCODE_BINARY, data, ws.is_client, mask, true);
    return status;
}

// Sends binary message with shared compressor and backpressure tracking
fn send_binary_compressed_with_status<B>(
    ws:          WebSocketSession&,
    data:        const u8[:],
    shared_comp: SharedWsCompressor&,
    out:         B&,
    compress:    bool = true,
) -> WsSendStatus {
    guard !ws.is_closed && !ws.close_sent && !ws.close_received else { return WsSendStatus.Closed; }
    guard !ws.tx_fragmented else { return WsSendStatus.Dropped; }
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };

    if compress && ws.permessage_deflate && data.len > 0 {
        let reset_win = ws_should_reset_compressor(ws);
        let comp_wire, ok_comp = ws_deflate_message_slice(shared_comp, data, reset_win);
        if ok_comp && comp_wire.len < data.len {
            let frame_len = calc_ws_frame_len(comp_wire.len as u64, ws.is_client);
            let status = notify_buffered(ws, frame_len, out);
            if status == WsSendStatus.Dropped || status == WsSendStatus.Closed {
                return status;
            }
            encode_ws_frame_compressed(out, rfc::WS_OPCODE_BINARY, comp_wire, ws.is_client, mask, true);
            return status;
        }
    }

    let frame_len = calc_ws_frame_len(data.len as u64, ws.is_client);
    let status = notify_buffered(ws, frame_len, out);
    if status == WsSendStatus.Dropped || status == WsSendStatus.Closed {
        return status;
    }
    encode_ws_frame(out, rfc::WS_OPCODE_BINARY, data, ws.is_client, mask, true);
    return status;
}

// High-level method: sends Ping heartbeat
fn send_ping<B>(ws: WebSocketSession&, ping_payload: const u8[:], out: B&) {
    // RFC 6455 §5.5.1 & uWS #1932: Once closed or close sent/received, drop outgoing heartbeat writes
    guard !ws.is_closed && !ws.close_sent && !ws.close_received else { return; }
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    encode_ws_frame(out, rfc::WS_OPCODE_PING, ping_payload, ws.is_client, mask, true);
    ws.pings_sent += 1;
}

// High-level method: sends Pong heartbeat response
fn send_pong<B>(ws: WebSocketSession&, pong_payload: const u8[:], out: B&) {
    // RFC 6455 §5.5.1 & uWS #1932: Once closed or close sent/received, drop outgoing heartbeat writes
    guard !ws.is_closed && !ws.close_sent && !ws.close_received else { return; }
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    encode_ws_frame(out, rfc::WS_OPCODE_PONG, pong_payload, ws.is_client, mask, true);
}

// High-level method: sends a fragmented message frame (initial or continuation fragment)
fn send_fragment<B>(ws: WebSocketSession&, opcode: u8, payload: const u8[:], fin: bool, out: B&) {
    guard !ws.is_closed && !ws.close_sent && !ws.close_received else { return; }
    if ws.tx_fragmented {
        guard opcode == rfc::WS_OPCODE_CONTINUATION else { return; }
    } else {
        guard opcode == rfc::WS_OPCODE_TEXT || opcode == rfc::WS_OPCODE_BINARY else { return; }
    }
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    if try_encode_ws_frame(out, opcode, payload, ws.is_client, mask, fin) {
        ws.tx_fragmented = !fin;
    }
}

// High-level method: initiates active Close handshake (half-closed CloseSent state) and records timestamp
fn close_at<B>(ws: WebSocketSession&, status_code: u16, reason: const u8[:], now_ms: u64, out: B&) {
    guard !ws.is_closed && !ws.close_sent else { return; }
    var payload: u8[..128] = [];
    if rfc::is_valid_ws_close_code(status_code) {
        let eff_reason = if reason.len > 0 && reason.validate_utf8() { reason } else { "" };
        encode_close_payload(payload, status_code, eff_reason);
    }
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    encode_ws_frame(out, rfc::WS_OPCODE_CLOSE, payload[..], ws.is_client, mask, true);
    ws.close_sent = true;
    ws.close_sent_ms = now_ms;
    ws.is_closed = ws.close_received;
    ws.close_code = status_code;
}

// Returns true when an active Close handshake has been waiting for the peer's Close ACK
// longer than `ws.close_timeout_ms` (RFC 6455 §7.1.2).
fn is_close_handshake_expired(ws: const WebSocketSession&, now_ms: u64) -> bool {
    return ws.close_sent && !ws.close_received && now_ms > ws.close_sent_ms &&
        (now_ms - ws.close_sent_ms) >= ws.close_timeout_ms;
}

// High-level method: sends Close handshake
fn close<B>(ws: WebSocketSession&, status_code: u16, reason: const u8[:], out: B&) {
    guard !ws.is_closed && !ws.close_sent else { return; }
    var payload: u8[..128] = [];
    // RFC 6455 §7.4.1 / Autobahn 7.1.x:
    // Status codes 1005 (No Status), 1006 (Abnormal), and 0 are internal and MUST NOT be sent on the wire.
    // Invalid codes (<1000, >=5000, 1016..2999, 1004, 1015) MUST NOT be sent on the wire.
    if rfc::is_valid_ws_close_code(status_code) {
        // RFC 6455 §5.5.1: Close reason MUST be valid UTF-8
        let eff_reason = if reason.len > 0 && reason.validate_utf8() { reason } else { "" };
        encode_close_payload(payload, status_code, eff_reason);
    }
    let mask: u8[4] = if ws.is_client { ws_next_mask_key(ws) } else { [0, 0, 0, 0] };
    encode_ws_frame(out, rfc::WS_OPCODE_CLOSE, payload[..], ws.is_client, mask, true);
    ws.close_sent = true;
    ws.is_closed = true;
    ws.close_code = status_code;
    ws.frag_opcode = 0;
    ws.frag_compressed = false;
    ws.frag_utf8_offset = 0;
    ws.utf8_dfa_state = 0;
    ws.frag_buffer.clear();
}

// ---- High-Level Message Dispatcher & Server Upgrade ---------------------

struct WsMessage {
    opcode:       u8          = rfc::WS_OPCODE_TEXT,
    data:         u8[..16384] = [],
    close_code:   u16         = 0,
    close_reason: u8[..128]   = [],
    is_valid:     bool        = false,
}

// Zero-copy non-owning view of a WebSocket message pointing directly into the ingress buffer.
// Matches uWebSockets std::string_view on_message callback pattern with 0 heap allocs and 0 memcpy.
struct WsMessageView {
    opcode:        u8          = rfc::WS_OPCODE_TEXT,
    payload:       const u8[:] = "",
    close_code:    u16         = 0,
    close_reason:  const u8[:] = "",
    is_valid:      bool        = false,
    is_compressed: bool        = false,
}

enum WsRole {
    Client,
    Server,
}

fn is_ws_masking_valid(role: WsRole, masked: bool) -> bool {
    if role == WsRole.Client && masked {
        return false;
    }
    if role == WsRole.Server && !masked {
        return false;
    }
    return true;
}

// Dispatches incoming raw frame wire bytes using zero-copy non-owning payload views:
// unmasks payload in-place, handles Ping/Pong and Close echoes, validates strict streaming UTF-8,
// and returns (handled, view) with a direct slice of the wire ingress buffer into view without copying.
fn receive_view_into<B, F>(
    ws:           WebSocketSession&,
    wire:         u8[:],
    frag_buf:     F&,
    max_frag_cap: i64,
    out_reply:    B&,
) -> bool, WsMessageView {
    var out_view = WsMessageView { .. };

    // RFC 6455 §5.5 & uWS #1407: Fail connection with PROTOCOL_ERROR (1002) upon fatal header invariant violations
    if wire.len >= 2 {
        let b0 = wire[0];
        let b1 = wire[1];
        let fin = (b0 & 0x80) != 0;
        let opcode = b0 & 0x0F;
        let raw_len = (b1 & 0x7F);

        if !rfc::is_valid_ws_opcode(opcode) {
            close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "unknown opcode", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return true, out_view;
        }

        if rfc::is_ws_control_opcode(opcode) && !fin {
            close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "fragmented control frame", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return true, out_view;
        }

        if rfc::is_ws_control_opcode(opcode) && raw_len > 125 {
            close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "control frame payload > 125", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return true, out_view;
        }

        // RFC 6455 §5.4: Interleaved data frame during fragmentation
        if (opcode == rfc::WS_OPCODE_TEXT || opcode == rfc::WS_OPCODE_BINARY) && ws.frag_opcode != 0 {
            close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "interleaved data frame during fragmentation", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            ws.frag_opcode = 0;
            ws.frag_compressed = false;
            ws.frag_utf8_offset = 0;
            frag_buf.clear();
            return true, out_view;
        }

        // RFC 6455 §5.4: Continuation frame without starting fragment
        if opcode == rfc::WS_OPCODE_CONTINUATION && ws.frag_opcode == 0 {
            close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "continuation frame without starting fragment", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return true, out_view;
        }

        // RFC 6455 §5.1: Masking enforcement - check immediately upon receiving header
        let masked = (b1 & 0x80) != 0;
        let role = if ws.is_client { WsRole.Client } else { WsRole.Server };
        if !is_ws_masking_valid(role, masked) {
            let reason = if ws.is_client {
                "masked frame received by client"
            } else {
                "unmasked frame received by server"
            };
            close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, reason, out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return true, out_view;
        }

        // RFC 6455 §5.2 & RFC 7692 §5.1: RSV bit enforcement - check immediately upon receiving header
        let rsv1_bit = (b0 & 0x40) != 0;
        let rsv2_bit = (b0 & 0x20) != 0;
        let rsv3_bit = (b0 & 0x10) != 0;
        let rsv1_allowed = ws.permessage_deflate && (opcode == rfc::WS_OPCODE_TEXT || opcode == rfc::WS_OPCODE_BINARY);
        if (rsv1_bit && !rsv1_allowed) || rsv2_bit || rsv3_bit {
            close(
                ws, rfc::WS_STATUS_PROTOCOL_ERROR,
                "RSV bits set without extension or on non-initial data frame", out_reply,
            );
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return true, out_view;
        }

        // RFC 6455 §5.2 & Autobahn Cases 3.1..3.4:
        // Fail connection with 1002 on non-minimal length representations or high bit set in 64-bit length
        if raw_len == 126 && wire.len >= 4 {
            let p_len = core::read_be_u16(wire, 2);
            if p_len < 126 {
                close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "non-minimal 16-bit length encoding", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
                return true, out_view;
            }
        } else if raw_len == 127 && wire.len >= 10 {
            if (wire[2] & 0x80) != 0 {
                close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "high bit set in 64-bit length", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
                return true, out_view;
            }
            let p_len = core::read_be_u64(wire, 2);
            if p_len <= 65535 {
                close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "non-minimal 64-bit length encoding", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
                return true, out_view;
            }
        }
    }

    let hdr, ok = parse_ws_frame_header(wire);
    guard ok else { return false, out_view; }

    // RFC 6455 §5.5.1: If connection is closing or closed, incoming data frames MUST be discarded
    if ws.is_closed || ws.close_received {
        if !rfc::is_ws_control_opcode(hdr.opcode) {
            out_view.is_valid = false;
            return false, out_view;
        }
    }

    // RFC 6455 §7.4.1 (1009) & Memory Safety:
    // Fast-fail oversized frames immediately from header without waiting to buffer the full wire payload
    if !rfc::is_ws_control_opcode(hdr.opcode) && ws.max_payload_length > 0 && hdr.payload_len > ws.max_payload_length {
        close(ws, rfc::WS_STATUS_MESSAGE_TOO_BIG, "payload length exceeds max_payload_length", out_reply);
        ws.is_closed = true;
        ws.close_code = rfc::WS_STATUS_MESSAGE_TOO_BIG;
        ws.frag_opcode = 0;
        ws.frag_compressed = false;
        ws.frag_utf8_offset = 0;
        frag_buf.clear();
        return true, out_view;
    }

    let wire_len = wire.len as u64;
    let p_start_u = hdr.header_len as u64;
    guard p_start_u <= wire_len && hdr.payload_len <= (wire_len - p_start_u) else { return false, out_view; }
    let p_start = hdr.header_len as i64;
    let p_len = hdr.payload_len as i64;
    let payload = wire[p_start..core::add_sat_i64(p_start, p_len)];

    if hdr.masked {
        mask_websocket_payload(payload, hdr.mask_key);
    }

    // Control frames (RFC 6455 §5.5) - can arrive interleaved in fragmented messages
    if rfc::is_ws_control_opcode(hdr.opcode) {
        if hdr.opcode == rfc::WS_OPCODE_PING {
            send_pong(ws, payload, out_reply);
            out_view.opcode = rfc::WS_OPCODE_PING;
            out_view.payload = payload;
            out_view.is_valid = true;
            return true, out_view;
        } else if hdr.opcode == rfc::WS_OPCODE_PONG {
            ws.pongs_received += 1;
            out_view.opcode = rfc::WS_OPCODE_PONG;
            out_view.payload = payload;
            out_view.is_valid = true;
            return true, out_view;
        } else if hdr.opcode == rfc::WS_OPCODE_CLOSE {
            if ws.close_received {
                // RFC 6455 §5.5.1: Duplicate Close frame received; ignore/discard
                out_view.is_valid = false;
                return false, out_view;
            }
            ws.close_received = true;
            let code, reason, ok_close = parse_close_payload(payload);
            if !ok_close {
                close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "invalid close frame payload", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
                ws.frag_opcode = 0;
                ws.frag_compressed = false;
                ws.frag_utf8_offset = 0;
                frag_buf.clear();
                return true, out_view;
            }
            // RFC 6455 §5.5.1 / §8.1 / §7.4.1 / Autobahn 6.4.1: Close reason MUST be valid UTF-8
            if reason.len > 0 && !reason.validate_utf8() {
                close(ws, rfc::WS_STATUS_INVALID_PAYLOAD, "invalid UTF-8 in close reason", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_INVALID_PAYLOAD;
                ws.frag_opcode = 0;
                ws.frag_compressed = false;
                ws.frag_utf8_offset = 0;
                frag_buf.clear();
                return true, out_view;
            }
            out_view.opcode = rfc::WS_OPCODE_CLOSE;
            out_view.close_code = code;
            out_view.close_reason = reason;
            out_view.is_valid = true;
            if !ws.is_closed && !ws.close_sent {
                // RFC 6455 §7.1.5: If received close contains no body (code 1005), response contains no body
                let reply_code = if code == rfc::WS_STATUS_NO_STATUS { rfc::WS_STATUS_NO_STATUS } else { code };
                close(ws, reply_code, reason, out_reply);
            }
            ws.is_closed = true;
            ws.close_code = code;
            ws.frag_opcode = 0;
            ws.frag_compressed = false;
            ws.frag_utf8_offset = 0;
            ws.utf8_dfa_state = 0;
            frag_buf.clear();
            return true, out_view;
        }
    }

    // Data frames (RFC 6455 §5.4 & §5.6)
    if hdr.opcode == rfc::WS_OPCODE_TEXT || hdr.opcode == rfc::WS_OPCODE_BINARY {
        if ws.frag_opcode != 0 {
            close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "interleaved data frame during fragmentation", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            ws.frag_opcode = 0;
            ws.frag_compressed = false;
            ws.frag_utf8_offset = 0;
            frag_buf.clear();
            return true, out_view;
        }

        if hdr.fin {
            // Unfragmented single-frame message: Zero-copy direct slice!
            if ws.max_payload_length > 0 && (payload.len as u64) > ws.max_payload_length {
                close(ws, rfc::WS_STATUS_MESSAGE_TOO_BIG, "payload exceeds capacity", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_MESSAGE_TOO_BIG;
                out_view.is_valid = false;
                return true, out_view;
            }
            // RFC 7692 Section 6.1: Compression - UTF-8 validation only applies to uncompressed plaintext payload
            let need_utf8 = hdr.opcode == rfc::WS_OPCODE_TEXT && !hdr.rsv1;
            if need_utf8 && !payload.validate_utf8() {
                close(ws, rfc::WS_STATUS_INVALID_PAYLOAD, "invalid UTF-8 in text frame", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_INVALID_PAYLOAD;
                return true, out_view;
            }
            out_view.opcode = hdr.opcode;
            out_view.payload = payload;
            out_view.is_valid = true;
            out_view.is_compressed = hdr.rsv1;
            return true, out_view;
        }

        // Initial fragment of a multi-frame message
        ws.frag_opcode = hdr.opcode;
        ws.frag_compressed = hdr.rsv1;
        ws.frag_utf8_offset = 0;
        ws.utf8_dfa_state = 0;
        frag_buf.clear();
        let max_len_i64 = min(ws.max_payload_length, 0x7FFFFFFFFFFFFFFF) as i64;
        let eff_cap = if ws.max_payload_length > 0 { min(max_len_i64, max_frag_cap) } else { max_frag_cap };
        if eff_cap <= 0 || payload.len > eff_cap {
            close(ws, rfc::WS_STATUS_MESSAGE_TOO_BIG, "fragment exceeds capacity", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_MESSAGE_TOO_BIG;
            ws.frag_opcode = 0;
            ws.frag_compressed = false;
            ws.frag_utf8_offset = 0;
            ws.utf8_dfa_state = 0;
            frag_buf.clear();
            return true, out_view;
        }
        frag_buf.append(payload);

        // RFC 6455 §8.1 / Autobahn 6.4.x: Fast streaming UTF-8 DFA validation on initial fragment
        if ws.frag_opcode == rfc::WS_OPCODE_TEXT && !ws.frag_compressed {
            let ok_u8 = core::validate_utf8_dfa_chunk(payload, ws.utf8_dfa_state, false);
            if !ok_u8 {
                close(ws, rfc::WS_STATUS_INVALID_PAYLOAD, "invalid UTF-8 in initial fragment", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_INVALID_PAYLOAD;
                ws.frag_opcode = 0;
                ws.frag_compressed = false;
                ws.frag_utf8_offset = 0;
                ws.utf8_dfa_state = 0;
                frag_buf.clear();
                return true, out_view;
            }
            ws.frag_utf8_offset = frag_buf.len;
        }

        out_view.is_valid = false;
        return true, out_view;
    } else if hdr.opcode == rfc::WS_OPCODE_CONTINUATION {
        if ws.frag_opcode == 0 {
            close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "continuation frame without starting fragment", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return true, out_view;
        }

        let max_len_i64 = min(ws.max_payload_length, 0x7FFFFFFFFFFFFFFF) as i64;
        let eff_cap = if ws.max_payload_length > 0 { min(max_len_i64, max_frag_cap) } else { max_frag_cap };
        if eff_cap <= 0 || payload.len > core::sub_sat_i64(eff_cap, frag_buf.len) {
            close(ws, rfc::WS_STATUS_MESSAGE_TOO_BIG, "assembled payload exceeds capacity", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_MESSAGE_TOO_BIG;
            ws.frag_opcode = 0;
            ws.frag_compressed = false;
            ws.frag_utf8_offset = 0;
            ws.utf8_dfa_state = 0;
            frag_buf.clear();
            return true, out_view;
        }
        frag_buf.append(payload);

        // RFC 6455 §8.1 / Autobahn 6.4.x: Fast streaming UTF-8 DFA validation across fragment boundary
        if ws.frag_opcode == rfc::WS_OPCODE_TEXT && !ws.frag_compressed {
            let ok_u8 = core::validate_utf8_dfa_chunk(payload, ws.utf8_dfa_state, hdr.fin);
            if !ok_u8 {
                let err_msg = if hdr.fin { "invalid UTF-8 in assembled message" } else { "invalid UTF-8 in fragment" };
                close(ws, rfc::WS_STATUS_INVALID_PAYLOAD, err_msg, out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_INVALID_PAYLOAD;
                ws.frag_opcode = 0;
                ws.frag_compressed = false;
                ws.frag_utf8_offset = 0;
                ws.utf8_dfa_state = 0;
                frag_buf.clear();
                return true, out_view;
            }
            ws.frag_utf8_offset = frag_buf.len;
        }

        if hdr.fin {
            let was_compressed = ws.frag_compressed;
            out_view.opcode = ws.frag_opcode;
            out_view.payload = frag_buf[..];
            out_view.is_valid = true;
            out_view.is_compressed = was_compressed;

            ws.frag_opcode = 0;
            ws.frag_compressed = false;
            ws.frag_utf8_offset = 0;
            ws.utf8_dfa_state = 0;
            return true, out_view;
        } else {
            out_view.is_valid = false;
            return true, out_view;
        }
    }

    return true, out_view;
}

// Dispatches incoming raw frame wire bytes using zero-copy non-owning payload views:
// unmasks payload in-place, handles Ping/Pong and Close echoes, validates strict UTF-8,
// and yields a direct slice of the wire ingress buffer into out_view without copying.
fn receive_view<B>(ws: WebSocketSession&, wire: u8[:], out_view: WsMessageView&, out_reply: B&) -> bool {
    let handled, view = receive_view_into(ws, wire, ws.frag_buffer, ws.frag_buffer.cap, out_reply);
    out_view = view;
    return handled;
}

// Streams and dispatches a single WebSocket frame from the front of `wire` into a caller-supplied assembly buffer:
// - Returns `(0, false, view)` when `wire` contains an incomplete frame header or payload.
// - Returns `(consumed, true, view)` when a complete frame was processed or a fatal violation closed the session.
fn consume_frame_view_into<B, F>(
    ws:           WebSocketSession&,
    wire:         u8[:],
    frag_buf:     F&,
    max_frag_cap: i64,
    out_reply:    B&,
) -> i64, bool, WsMessageView {
    guard !ws.is_closed && wire.len >= 2 else { return 0, false, WsMessageView { .. }; }

    let hdr, ok_hdr = parse_ws_frame_header(wire);
    if ok_hdr {
        let hdr_len = hdr.header_len as u64;
        let wire_len = wire.len as u64;
        if hdr_len <= wire_len && hdr.payload_len <= (wire_len - hdr_len) {
            let total_len = (hdr_len + hdr.payload_len) as i64;
            let handled, view = receive_view_into(ws, wire[..total_len], frag_buf, max_frag_cap, out_reply);
            return total_len, handled || ws.is_closed, view;
        }
    }

    // Incomplete frame header or payload: check if header already violates RFC 6455 invariants
    let handled, view = receive_view_into(ws, wire, frag_buf, max_frag_cap, out_reply);
    if handled || ws.is_closed {
        return wire.len, true, view;
    }
    return 0, false, view;
}

// Streams and dispatches a single WebSocket frame from the front of `wire`:
// - Returns `(0, false)` when `wire` contains an incomplete frame header or payload and more socket bytes are needed.
// - Returns `(consumed, true)` when a complete frame was processed or a fatal header violation closed the session.
fn consume_frame_view<B>(ws: WebSocketSession&, wire: u8[:], out_view: WsMessageView&, out_reply: B&) -> i64, bool {
    let consumed, handled, view = consume_frame_view_into(ws, wire, ws.frag_buffer, ws.frag_buffer.cap, out_reply);
    out_view = view;
    return consumed, handled;
}

// Dispatches incoming raw frame wire bytes: unmasks payload, automatically prepares Pong for Ping,
// answers Close with Close echo, reassembles multi-frame fragmented messages (RFC 6455 §5.4),
// validates strict UTF-8 on text and close frames, and populates out_msg upon message completion.
fn receive<B>(ws: WebSocketSession&, wire: u8[:], out_msg: WsMessage&, out_reply: B&) -> bool {
    out_msg.is_valid = false;
    out_msg.close_code = 0;
    out_msg.close_reason.clear();
    out_msg.data.clear();

    var view = WsMessageView { .. };
    let ok = receive_view(ws, wire, view, out_reply);
    guard ok else { return false; }

    if view.payload.len > out_msg.data.cap {
        close(ws, rfc::WS_STATUS_MESSAGE_TOO_BIG, "message exceeds buffer capacity", out_reply);
        ws.is_closed = true;
        ws.close_code = rfc::WS_STATUS_MESSAGE_TOO_BIG;
        out_msg.is_valid = false;
        return false;
    }

    out_msg.is_valid = view.is_valid;
    out_msg.opcode = view.opcode;
    out_msg.close_code = view.close_code;
    guard out_msg.close_reason.try_set(view.close_reason) else { return false; }
    guard out_msg.data.try_set(view.payload) else { return false; }
    return true;
}

// ---- WebSocket Session Drivers & Message Stage Hook ----------------------

// Default WebSocket message stage hook (RFC 6455 echo).
fn on_ws_message<Stage, B>(_stage: Stage&, ws: WebSocketSession&, view: const WsMessageView&, out_wire: B&) {
    if view.opcode == rfc::WS_OPCODE_TEXT {
        send_text(ws, view.payload, out_wire);
    } else if view.opcode == rfc::WS_OPCODE_BINARY {
        send_binary(ws, view.payload, out_wire);
    }
}

// Drains trailing socket bytes after sending a Close frame so the peer receives
// the Close frame instead of an immediate TCP RST (RFC 6455 §7.1.1).
fn ws_drain_and_close(conn_fd: i64) {
    var drain_buf: u8[..4096] = [];
    var step:      i64        = 0;
    while step < 10 {
        step = core::add_sat_i64(step, 1);
        drain_buf.clear();
        let dn = tcp_recv(conn_fd, drain_buf, 20);
        if dn <= 0 {
            break;
        }
    }
    tcp_close(conn_fd);
}

// Returns true if the decoded WebSocket message view is a complete valid data frame (text or binary).
inline fn is_ws_data_message(view: const WsMessageView&) -> bool {
    return view.is_valid && (view.opcode == rfc::WS_OPCODE_TEXT || view.opcode == rfc::WS_OPCODE_BINARY);
}

// Sends buffered WebSocket wire bytes over `conn_fd` when `wire` is non-empty.
inline fn flush_ws_wire(conn_fd: i64, wire: const u8[:]) {
    if wire.len > 0 {
        let _ = tcp_send(conn_fd, wire);
    }
}

inline fn ws_buf_cap<B>(b: const B&) -> i64 {
    return b.cap;
}

inline fn ws_buf_cap(b: const u8[>..]&) -> i64 {
    return 0x7FFFFFFF;
}

fn dispatch_ws_data_turn<Stage, OutBuf, ReplyBuf>(
    ws:        WebSocketSession&,
    stage:     Stage&,
    view:      const WsMessageView&,
    pmd_comp:  SharedWsCompressor&,
    pmd_plain: u8[..65536]&,
    out_wire:  OutBuf&,
    reply:     ReplyBuf&,
) {
    if !view.is_compressed {
        out_wire.clear();
        on_ws_message(stage, ws, view, out_wire);
        return;
    }
    let max_pay = if ws.max_payload_length > 0 {
        min(ws.max_payload_length, 65536) as i64
    } else {
        65536
    };
    let reset_win = ws_should_reset_decompressor(ws);
    if !ws_inflate_message(pmd_comp, view.payload, pmd_plain, max_pay, reset_win) {
        close(ws, rfc::WS_STATUS_PROTOCOL_ERROR, "invalid permessage-deflate stream", reply);
        return;
    }
    if view.opcode == rfc::WS_OPCODE_TEXT && !pmd_plain[..].validate_utf8() {
        close(ws, rfc::WS_STATUS_INVALID_PAYLOAD, "invalid UTF-8 in compressed text frame", reply);
        return;
    }
    let inflated_view = WsMessageView {
        opcode:        view.opcode,
        payload:       pmd_plain[..],
        is_valid:      true,
        is_compressed: false,
        ..
    };
    out_wire.clear();
    on_ws_message(stage, ws, inflated_view, out_wire);
}

// Consumes and dispatches all complete WebSocket frames currently buffered in `in_slice`.
// Returns the total number of bytes consumed from `in_slice`.
fn drain_ws_session_frames<Stage, FragBuf, OutBuf>(
    conn_fd:  i64,
    ws:       WebSocketSession&,
    stage:    Stage&,
    in_slice: u8[:],
    frag_buf: FragBuf&,
    out_wire: OutBuf&,
) -> i64 {
    var cursor: i64        = 0;
    var reply:  u8[..1024] = [];
    var pmd_comp = SharedWsCompressor { .. };
    var pmd_plain: u8[..65536] = [];
    while core::add_sat_i64(cursor, 2) <= in_slice.len && !ws.is_closed {
        reply.clear();
        let max_pay_i64 = min(ws.max_payload_length, 0x7FFFFFFFFFFFFFFF) as i64;
        let eff_frag_cap = if max_pay_i64 > 0 { min(ws_buf_cap(frag_buf), max_pay_i64) } else { ws_buf_cap(frag_buf) };
        let consumed, handled, view = consume_frame_view_into(
            ws, in_slice[cursor..], frag_buf, eff_frag_cap, reply,
        );
        if !handled || consumed <= 0 {
            break;
        }
        cursor = core::add_sat_i64(cursor, consumed);
        flush_ws_wire(conn_fd, reply[..]);
        if is_ws_data_message(view) {
            reply.clear();
            dispatch_ws_data_turn(ws, stage, view, pmd_comp, pmd_plain, out_wire, reply);
            flush_ws_wire(conn_fd, reply[..]);
            if !ws.is_closed {
                flush_ws_wire(conn_fd, out_wire[..]);
            }
        }
        if ws.is_closed {
            ws_drain_and_close(conn_fd);
            break;
        }
    }
    return cursor;
}

// Drives an upgraded RFC 6455 WebSocket session using caller-supplied wire and fragment buffers.
fn serve_ws_session_buf<Stage, InBuf, FragBuf, OutBuf>(
    conn_fd:  i64,
    ws:       WebSocketSession&,
    stage:    Stage&,
    in_buf:   InBuf&,
    frag_buf: FragBuf&,
    out_wire: OutBuf&,
) {
    var chunk_buf:   u8[..65536] = [];
    var close_reply: u8[..256]   = [];
    loop {
        let consumed = drain_ws_session_frames(conn_fd, ws, stage, in_buf[..], frag_buf, out_wire);
        if ws.is_closed {
            return;
        }
        in_buf.compact_wire_buffer(consumed);
        chunk_buf.clear();
        let recvd = tcp_recv(conn_fd, chunk_buf, 100);
        if recvd < 0 {
            tcp_close(conn_fd);
            return;
        }
        if recvd == 0 {
            continue;
        }
        let max_pay_i64 = min(ws.max_payload_length, 0x7FFFFFFFFFFFFFFF) as i64;
        let max_wire_cap = if max_pay_i64 > 0 {
            min(ws_buf_cap(in_buf), core::add_sat_i64(max_pay_i64, 65536))
        } else {
            ws_buf_cap(in_buf)
        };
        guard core::add_sat_i64(in_buf.len, recvd) <= max_wire_cap else {
            close_reply.clear();
            close(ws, rfc::WS_STATUS_MESSAGE_TOO_BIG, "frame exceeds wire buffer capacity", close_reply);
            if close_reply.len > 0 {
                let _ = tcp_send(conn_fd, close_reply[..]);
            }
            ws_drain_and_close(conn_fd);
            return;
        }
        in_buf.append(chunk_buf[..recvd]);
    }
}

// Drives an upgraded RFC 6455 WebSocket session with default echo behavior on wire::NoOpStage.
fn serve_ws_session_buf<InBuf, FragBuf, OutBuf>(
    conn_fd:  i64,
    ws:       WebSocketSession&,
    in_buf:   InBuf&,
    frag_buf: FragBuf&,
    out_wire: OutBuf&,
) {
    var stage = wire::NoOpStage {};
    serve_ws_session_buf(conn_fd, ws, stage, in_buf, frag_buf, out_wire);
}

// Drives an upgraded RFC 6455 WebSocket session with 64 KB stack-allocated buffers.
fn serve_ws_session<Stage>(conn_fd: i64, ws: WebSocketSession&, stage: Stage&) {
    var in_buf:   u8[..65536] = [];
    var frag_buf: u8[..65536] = [];
    var out_wire: u8[..65536] = [];
    serve_ws_session_buf(conn_fd, ws, stage, in_buf, frag_buf, out_wire);
}

// Drives an upgraded RFC 6455 WebSocket session with 64 KB stack buffers and default echo behavior.
fn serve_ws_session(conn_fd: i64, ws: WebSocketSession&) {
    var stage = wire::NoOpStage {};
    serve_ws_session(conn_fd, ws, stage);
}
