// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// WebSocket Protocol Framing and Session Engine (RFC 6455 & RFC 8441).
// Features:
// - Zero-copy in-place 64-bit unrolled payload masking / unmasking
// - Complete frame header parser, serializer, and control frame invariant enforcer
// - Multi-frame fragmented message reassembly with streaming UTF-8 DFA validation
// - Heartbeat tick-wheel timers and backpressure flow control
namespace realtime;

import std;
import core;
import rfc.ws;
import wire.pipeline;
import net.tcp;
import .internal;
import .ws_pmd_internal;
import .ws_deflate;
import .ws_handshake;

// In-place zero-copy unmasking that shifts the unmasked payload back over the frame header
// (uWebSockets unmaskImprecise8). Overwrites header directly in slice and returns payload slice.
fn unmask_websocket_shifted(frame: u8[:], header_len: i64, payload_len: i64, mask_key: const u8[4]&) -> u8[:] {
    guard payload_len > 0 && header_len > 0 && header_len <= frame.len && payload_len <= frame.len - header_len else {
        return frame[..0];
    }
    let m32_be = ((mask_key[0] as u64) << 24) |
                 ((mask_key[1] as u64) << 16) |
                 ((mask_key[2] as u64) << 8) |
                 mask_key[3];
    let m64_be = (m32_be << 32) | m32_be;
    var i: i64 = 0;
    while i + 8 <= payload_len {
        let w = core::read_be_u64(frame, header_len + i);
        core::write_be_u64_at(frame, i, w ^ m64_be);
        i += 8;
    }
    while i < payload_len {
        frame[i] = frame[header_len + i] ^ mask_key[i & 3];
        i += 1;
    }
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

// In-place SWAR 64-bit/32-bit XOR masking loop (RFC 6455 Section 5.3).
// Vectorizes payload masking in pure Goose using 4x-unrolled 64-bit word iterations without heap allocations
// or out-of-bounds reads.
fn apply_mask_in_place(data: u8[:], mask_key: const u8[4]&) {
    let n = data.len;
    guard n > 0 else { return; }

    let m32_be = ((mask_key[0] as u64) << 24) |
                 ((mask_key[1] as u64) << 16) |
                 ((mask_key[2] as u64) << 8) |
                 mask_key[3];
    let m64_be = (m32_be << 32) | m32_be;

    var i: i64 = 0;

    // 4x-unrolled 64-bit SWAR loop: process 32 bytes per iteration
    while i + 32 <= n {
        core::write_be_u64_at(data, i, core::read_be_u64(data, i) ^ m64_be);
        core::write_be_u64_at(data, i + 8, core::read_be_u64(data, i + 8) ^ m64_be);
        core::write_be_u64_at(data, i + 16, core::read_be_u64(data, i + 16) ^ m64_be);
        core::write_be_u64_at(data, i + 24, core::read_be_u64(data, i + 24) ^ m64_be);
        i += 32;
    }

    // 64-bit SWAR loop: process 8 bytes per iteration
    while i + 8 <= n {
        core::write_be_u64_at(data, i, core::read_be_u64(data, i) ^ m64_be);
        i += 8;
    }

    // 32-bit SWAR tail: process remaining 4 bytes if present
    if i + 4 <= n {
        core::write_be_u32_at(data, i, core::read_be_u32(data, i) ^ (m32_be as u32));
        i += 4;
    }

    // Scalar byte-by-byte tail (0..3 bytes)
    while i < n {
        data[i] = data[i] ^ mask_key[i & 3];
        i += 1;
    }
}

// In-place masking / unmasking using pure-Goose 4x-unrolled 64-bit SWAR (RFC 6455 Section 5.3).
fn mask_websocket_payload(data: u8[:], mask_key: const u8[4]&) {
    guard data.len > 0 else { return; }
    apply_mask_in_place(data, mask_key);
}

// Parses RFC 6455 Frame Header with strict protocol validation.
//
// Example:
//   src = [0x81, 0x05, 0x48, 0x65, 0x6C, 0x6C, 0x6F]
//   returns: WsFrameHeader { fin: true, opcode: 1, payload_len: 5, header_len: 2, ... }, ok = true
fn parse_ws_frame_header(src: const u8[:]) -> WsFrameHeader, bool {
    var hdr = WsFrameHeader { .. };
    guard src.len >= 2 else { return hdr, false; }

    let b0 = src[0];
    let b1 = src[1];

    let fin = (b0 & rfc::WS_FIN_BIT) != 0;
    let rsv1 = (b0 & rfc::WS_RSV1_BIT) != 0;
    let rsv2 = (b0 & rfc::WS_RSV2_BIT) != 0;
    let rsv3 = (b0 & rfc::WS_RSV3_BIT) != 0;
    let opcode = b0 & rfc::WS_OPCODE_MASK;

    guard rfc::is_valid_ws_opcode(opcode) else { return hdr, false; }

    let masked = (b1 & rfc::WS_MASK_BIT) != 0;
    let raw_len = (b1 & rfc::WS_PAYLOAD_LEN_MASK) as u64;

    // Control frame invariants (RFC 6455 Section 5.5):
    // 1. MUST NOT be fragmented (FIN MUST be 1)
    // 2. Payload length MUST be <= 125 (extended length encodings 126/127 are forbidden)
    if rfc::is_ws_control_opcode(opcode) {
        guard fin && raw_len <= rfc::WS_MAX_CONTROL_LEN else { return hdr, false; }
    }

    var offset:      i64 = 2;
    var payload_len: u64 = 0;

    if raw_len <= rfc::WS_MAX_CONTROL_LEN {
        payload_len = raw_len;
    } else if raw_len == rfc::WS_LEN16_SENTINEL {
        guard src.len >= core::add_sat_i64(offset, 2) else { return hdr, false; }
        payload_len = core::read_be_u16(src, offset);
        // RFC 6455 Section 5.2: minimal encoding check (must be >= 126)
        guard payload_len >= rfc::WS_LEN16_SENTINEL else { return hdr, false; }
        offset = core::add_sat_i64(offset, 2);
    } else {
        // raw_len == 127
        guard src.len >= core::add_sat_i64(offset, 8) else { return hdr, false; }
        // High bit must be 0 per RFC 6455 Section 5.2
        guard (src[offset] & rfc::WS_FIN_BIT) == 0 else { return hdr, false; }
        payload_len = core::read_be_u64(src, offset);
        // Minimal encoding check (must be > 65535)
        guard payload_len > 65535 else { return hdr, false; }
        offset = core::add_sat_i64(offset, 8);
    }

    if rfc::is_ws_control_opcode(opcode) {
        guard payload_len <= rfc::WS_MAX_CONTROL_LEN else { return hdr, false; }
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

// Encodes RFC 6455 Frame Header.
fn encode<B>(hdr: const WsFrameHeader&, out: B&) {
    let _ = realtime_internal::try_encode_ws_header(hdr, out);
}

// High-level frame serializer: writes header + payload (masked if is_client).
fn encode_ws_frame<B>(
    out:       B&,
    opcode:    u8,
    payload:   const u8[:],
    is_client: bool        = true,
    mask_key:  const u8[4] = [0 as u8; 4],
    fin:       bool        = true,
) {
    let _ = realtime_internal::try_encode_ws_frame(out, opcode, payload, is_client, mask_key, fin);
}

// ---- Close Frame Helpers (RFC 6455 Section 5.5.1) -----------------------

// Encodes a Close frame payload (2-byte status code + optional UTF-8 reason).
fn encode_close_payload<B>(out: B&, status_code: u16, reason: const u8[:]) {
    guard rfc::is_valid_ws_close_code(status_code) else { return; }
    // RFC 6455 §5.5 & §5.5.1 / uWS #1407: Control frame payload must NOT exceed 125 bytes.
    // Close payload contains 2-byte status code, so reason is clamped to at most 123 bytes.
    var eff_len = min(reason.len, 123);
    if reason.len > 123 {
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

// Parses a Close frame payload into (status_code, reason_slice, ok).
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
    compression:                 u16      = WS_COMPRESS_DISABLED,
    max_payload_length:          u64      = 65536,
    idle_timeout_s:              u32      = 120,
    max_lifetime_s:              u32      = 0,
    max_backpressure:            u64      = 1048576,
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
    max_payload_length: u64      = 65536,
    mask_rng_state:     u32      = 0x9E3779B9,

    // Multi-frame fragmented message assembly (RFC 6455 §5.4 & RFC 7692 §5.1)
    tx_fragmented:    bool        = false,
    frag_opcode:      u8          = 0,
    frag_compressed:  bool        = false,
    frag_utf8_offset: i64         = 0,
    utf8_dfa_state:   u8          = 0,
    frag_buffer:      u8[..65536] = [],

    // RFC 7692 PerMessageDeflate configuration (uWebSockets pattern)
    compress_mode:              u16  = WS_COMPRESS_DISABLED,
    permessage_deflate:         bool = false,
    server_no_context_takeover: bool = true,
    client_no_context_takeover: bool = true,
    server_max_window_bits:     u8   = 15,
    client_max_window_bits:     u8   = 15,

    // Per-socket UserData / Typed User Context (uWebSockets getUserData pattern)
    user_tag:  u64       = 0,
    user_data: u8[..128] = [],

    // Backpressure & Dynamic Flow Control (uWebSockets Backpressure pattern)
    buffered_amount:             u64  = 0,
    max_backpressure:            u64  = 1048576,
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

// Arms connection slot timeouts in modular tick wheel (uSockets loop.c / uWebSockets pattern).
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

// Disarms heartbeat timers.
fn disarm_heartbeat(ws: WebSocketSession&) {
    ws.timeout_slot = core::TICK_TIMER_DISARMED;
    ws.ping_slot = core::TICK_TIMER_DISARMED;
}

// Advances session lifetime counter by elapsed_seconds (uWebSockets maxLifetime sweeper).
fn ws_advance_lifetime(ws: WebSocketSession&, elapsed_seconds: u32 = 1) {
    ws.elapsed_lifetime_s += elapsed_seconds;
}

// Touches the session to reset idle timeout on incoming frame or send.
fn touch(ws: WebSocketSession&, wheel: const core::TickTimerWheel&) {
    if ws.timeout_slot != core::TICK_TIMER_DISARMED {
        arm_heartbeat(ws, wheel);
    }
}

// Evaluates heartbeat tick without serializing wire bytes.
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

// Executes periodic heartbeat check and automatically writes Ping or Close frame.
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

// Configures PerMessageDeflate (RFC 7692) on the WebSocket session.
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

// Formats outbound RFC 6455 Handshake HTTP/1.1 Upgrade Request.
fn build_handshake_request<B>(
    ws:         const WebSocketSession&,
    host:       const u8[:],
    path:       const u8[:],
    client_key: const u8[:],
    out:        B&,
) {
    // RFC 6455 §4.1 & RFC 9112 §3.2.1 & Go #76635: If path is empty, default to '/'
    let eff_path = if path.len > 0 { path } else { "/" };
    guard !realtime_internal::has_ws_header_ctl(host) &&
        !realtime_internal::has_ws_header_ctl(eff_path) &&
        !eff_path.contains_byte(' ') &&
        !realtime_internal::has_ws_header_ctl(client_key) &&
        !realtime_internal::has_ws_header_ctl(ws.subprotocol[..]) else {
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

// High-level method: sends UTF-8 text message.
fn send_text<B>(ws: WebSocketSession&, text: const u8[:], out: B&) {
    // RFC 6455 §5.5.1 & uWS #1932: Once closed or close sent/received, drop outgoing message writes
    guard !ws.is_closed && !ws.close_sent && !ws.close_received && !ws.tx_fragmented else { return; }
    let mask, ok_mask = realtime_internal::ws_next_mask_key(ws);
    guard ok_mask else { return; }
    encode_ws_frame(out, rfc::WS_OPCODE_TEXT, text, ws.is_client, mask, true);
}

// Sends UTF-8 text message with backpressure tracking and status code (uWebSockets sendStatus pattern).
fn send_text_with_status<B>(
    ws:       WebSocketSession&,
    text:     const u8[:],
    out:      B&,
    compress: bool = false,
) -> WsSendStatus {
    guard !ws.is_closed && !ws.close_sent && !ws.close_received else { return WsSendStatus.Closed; }
    guard !ws.tx_fragmented else { return WsSendStatus.Dropped; }
    let mask, ok_mask = realtime_internal::ws_next_mask_key(ws);
    guard ok_mask else { return WsSendStatus.Dropped; }
    let frame_len = realtime_internal::calc_ws_frame_len(text.len as u64, ws.is_client);
    let status = notify_buffered(ws, frame_len, out);
    if status == WsSendStatus.Dropped || status == WsSendStatus.Closed {
        return status;
    }
    encode_ws_frame(out, rfc::WS_OPCODE_TEXT, text, ws.is_client, mask, true);
    return status;
}

// Sends UTF-8 text message with shared compressor and backpressure tracking.
fn send_text_compressed_with_status<B>(
    ws:          WebSocketSession&,
    text:        const u8[:],
    shared_comp: SharedWsCompressor&,
    out:         B&,
    compress:    bool = true,
) -> WsSendStatus {
    guard !ws.is_closed && !ws.close_sent && !ws.close_received else { return WsSendStatus.Closed; }
    guard !ws.tx_fragmented else { return WsSendStatus.Dropped; }
    let mask, ok_mask = realtime_internal::ws_next_mask_key(ws);
    guard ok_mask else { return WsSendStatus.Dropped; }

    if compress && ws.permessage_deflate && text.len > 0 {
        let reset_win = ws_should_reset_compressor(ws);
        let comp_wire, ok_comp = ws_deflate_message_slice(shared_comp, text, reset_win);
        if ok_comp && comp_wire.len < text.len {
            let frame_len = realtime_internal::calc_ws_frame_len(comp_wire.len as u64, ws.is_client);
            let status = notify_buffered(ws, frame_len, out);
            if status == WsSendStatus.Dropped || status == WsSendStatus.Closed {
                return status;
            }
            encode_ws_frame_compressed(out, rfc::WS_OPCODE_TEXT, comp_wire, ws.is_client, mask, true);
            return status;
        }
    }

    let frame_len = realtime_internal::calc_ws_frame_len(text.len as u64, ws.is_client);
    let status = notify_buffered(ws, frame_len, out);
    if status == WsSendStatus.Dropped || status == WsSendStatus.Closed {
        return status;
    }
    encode_ws_frame(out, rfc::WS_OPCODE_TEXT, text, ws.is_client, mask, true);
    return status;
}

// High-level method: sends binary message.
fn send_binary<B>(ws: WebSocketSession&, data: const u8[:], out: B&) {
    // RFC 6455 §5.5.1 & uWS #1932: Once closed or close sent/received, drop outgoing message writes
    guard !ws.is_closed && !ws.close_sent && !ws.close_received && !ws.tx_fragmented else { return; }
    let mask, ok_mask = realtime_internal::ws_next_mask_key(ws);
    guard ok_mask else { return; }
    encode_ws_frame(out, rfc::WS_OPCODE_BINARY, data, ws.is_client, mask, true);
}

// Sends binary message with backpressure tracking and status code (uWebSockets sendStatus pattern).
fn send_binary_with_status<B>(
    ws:       WebSocketSession&,
    data:     const u8[:],
    out:      B&,
    compress: bool = false,
) -> WsSendStatus {
    guard !ws.is_closed && !ws.close_sent && !ws.close_received else { return WsSendStatus.Closed; }
    guard !ws.tx_fragmented else { return WsSendStatus.Dropped; }
    let mask, ok_mask = realtime_internal::ws_next_mask_key(ws);
    guard ok_mask else { return WsSendStatus.Dropped; }
    let frame_len = realtime_internal::calc_ws_frame_len(data.len as u64, ws.is_client);
    let status = notify_buffered(ws, frame_len, out);
    if status == WsSendStatus.Dropped || status == WsSendStatus.Closed {
        return status;
    }
    encode_ws_frame(out, rfc::WS_OPCODE_BINARY, data, ws.is_client, mask, true);
    return status;
}

// Sends binary message with shared compressor and backpressure tracking.
fn send_binary_compressed_with_status<B>(
    ws:          WebSocketSession&,
    data:        const u8[:],
    shared_comp: SharedWsCompressor&,
    out:         B&,
    compress:    bool = true,
) -> WsSendStatus {
    guard !ws.is_closed && !ws.close_sent && !ws.close_received else { return WsSendStatus.Closed; }
    guard !ws.tx_fragmented else { return WsSendStatus.Dropped; }
    let mask, ok_mask = realtime_internal::ws_next_mask_key(ws);
    guard ok_mask else { return WsSendStatus.Dropped; }

    if compress && ws.permessage_deflate && data.len > 0 {
        let reset_win = ws_should_reset_compressor(ws);
        let comp_wire, ok_comp = ws_deflate_message_slice(shared_comp, data, reset_win);
        if ok_comp && comp_wire.len < data.len {
            let frame_len = realtime_internal::calc_ws_frame_len(comp_wire.len as u64, ws.is_client);
            let status = notify_buffered(ws, frame_len, out);
            if status == WsSendStatus.Dropped || status == WsSendStatus.Closed {
                return status;
            }
            encode_ws_frame_compressed(out, rfc::WS_OPCODE_BINARY, comp_wire, ws.is_client, mask, true);
            return status;
        }
    }

    let frame_len = realtime_internal::calc_ws_frame_len(data.len as u64, ws.is_client);
    let status = notify_buffered(ws, frame_len, out);
    if status == WsSendStatus.Dropped || status == WsSendStatus.Closed {
        return status;
    }
    encode_ws_frame(out, rfc::WS_OPCODE_BINARY, data, ws.is_client, mask, true);
    return status;
}

// High-level method: sends Ping heartbeat.
fn send_ping<B>(ws: WebSocketSession&, ping_payload: const u8[:], out: B&) {
    // RFC 6455 §5.5.1 & uWS #1932: Once closed or close sent/received, drop outgoing heartbeat writes
    guard !ws.is_closed && !ws.close_sent && !ws.close_received else { return; }
    let mask, ok_mask = realtime_internal::ws_next_mask_key(ws);
    guard ok_mask else { return; }
    encode_ws_frame(out, rfc::WS_OPCODE_PING, ping_payload, ws.is_client, mask, true);
    ws.pings_sent += 1;
}

// High-level method: sends Pong heartbeat response.
fn send_pong<B>(ws: WebSocketSession&, pong_payload: const u8[:], out: B&) {
    // RFC 6455 §5.5.1 & uWS #1932: Once closed or close sent/received, drop outgoing heartbeat writes
    guard !ws.is_closed && !ws.close_sent && !ws.close_received else { return; }
    let mask, ok_mask = realtime_internal::ws_next_mask_key(ws);
    guard ok_mask else { return; }
    encode_ws_frame(out, rfc::WS_OPCODE_PONG, pong_payload, ws.is_client, mask, true);
}

// High-level method: sends a fragmented message frame (initial or continuation fragment).
fn send_fragment<B>(ws: WebSocketSession&, opcode: u8, payload: const u8[:], fin: bool, out: B&) {
    guard !ws.is_closed && !ws.close_sent && !ws.close_received else { return; }
    if ws.tx_fragmented {
        guard opcode == rfc::WS_OPCODE_CONTINUATION else { return; }
    } else {
        guard opcode == rfc::WS_OPCODE_TEXT || opcode == rfc::WS_OPCODE_BINARY else { return; }
    }
    let mask, ok_mask = realtime_internal::ws_next_mask_key(ws);
    guard ok_mask else { return; }
    if realtime_internal::try_encode_ws_frame(out, opcode, payload, ws.is_client, mask, fin) {
        ws.tx_fragmented = !fin;
    }
}

// High-level method: initiates active Close handshake (half-closed CloseSent state) and records timestamp.
fn close_at<B>(ws: WebSocketSession&, status_code: u16, reason: const u8[:], now_ms: u64, out: B&) {
    guard !ws.is_closed && !ws.close_sent else { return; }
    let mask, ok_mask = realtime_internal::ws_next_mask_key(ws);
    guard ok_mask else { return; }
    var payload: u8[..128] = [];
    if rfc::is_valid_ws_close_code(status_code) {
        let eff_reason = if reason.len > 0 && reason.validate_utf8() { reason } else { "" };
        encode_close_payload(payload, status_code, eff_reason);
    }
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

// High-level method: sends Close handshake.
fn close<B>(ws: WebSocketSession&, status_code: u16, reason: const u8[:], out: B&) {
    guard !ws.is_closed && !ws.close_sent else { return; }
    let mask, ok_mask = realtime_internal::ws_next_mask_key(ws);
    guard ok_mask else { return; }
    var payload: u8[..128] = [];
    // RFC 6455 §7.4.1 / Autobahn 7.1.x:
    // Status codes 1005 (No Status), 1006 (Abnormal), and 0 are internal and MUST NOT be sent on the wire.
    if rfc::is_valid_ws_close_code(status_code) {
        // RFC 6455 §5.5.1: Close reason MUST be valid UTF-8
        let eff_reason = if reason.len > 0 && reason.validate_utf8() { reason } else { "" };
        encode_close_payload(payload, status_code, eff_reason);
    }
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
// unmasks payload in-place, handles Ping/Pong and Close echoes, validates strict UTF-8,
// and yields a direct slice of the wire ingress buffer into out_view without copying.
fn receive_view<B>(ws: WebSocketSession&, wire: u8[:], out_view: WsMessageView&, out_reply: B&) -> bool {
    let view, handled = realtime_internal::receive_view_into(ws, wire, ws.frag_buffer, ws.frag_buffer.cap, out_reply);
    out_view = view;
    return handled;
}

// Streams and dispatches a single WebSocket frame from the front of `wire`:
// - Returns `(0, false)` when `wire` contains an incomplete frame header or payload and more socket bytes are needed.
// - Returns `(consumed, true)` when a complete frame was processed or a fatal header violation closed the session.
fn consume_frame_view<B>(ws: WebSocketSession&, wire: u8[:], out_view: WsMessageView&, out_reply: B&) -> i64, bool {
    let consumed, handled, view = realtime_internal::consume_frame_view_into(
        ws, wire, ws.frag_buffer, ws.frag_buffer.cap, out_reply,
    );
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

// ---- WebSocket Session Drivers -------------------------------------------

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
    var pmd = realtime_internal::WsPmdSessionState { .. };
    loop {
        let consumed = realtime_internal::drain_ws_session_frames_pmd(
            conn_fd, ws, stage, in_buf[..], frag_buf, pmd, out_wire,
        );
        if ws.is_closed {
            return;
        }
        in_buf.compact_wire_buffer(consumed);
        chunk_buf.clear();
        let recvd = net::tcp_recv(conn_fd, chunk_buf, 16384, 100);
        if recvd == -2 {
            continue;
        }
        if recvd <= 0 {
            net::tcp_close(conn_fd);
            return;
        }
        let max_pay_i64 = min(ws.max_payload_length, 0x7FFFFFFFFFFFFFFF) as i64;
        let max_wire_cap = if max_pay_i64 > 0 {
            min(realtime_internal::ws_buf_cap(in_buf), core::add_sat_i64(max_pay_i64, 65536))
        } else {
            realtime_internal::ws_buf_cap(in_buf)
        };
        guard core::add_sat_i64(in_buf.len, recvd) <= max_wire_cap else {
            close_reply.clear();
            close(ws, rfc::WS_STATUS_MESSAGE_TOO_BIG, "frame exceeds wire buffer capacity", close_reply);
            if close_reply.len > 0 {
                let _ = net::tcp_send(conn_fd, close_reply[..]);
            }
            realtime_internal::ws_drain_and_close(conn_fd);
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
