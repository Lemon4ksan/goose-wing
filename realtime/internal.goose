// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Native shims and WebSocket framing and session core internal helpers.
namespace realtime_internal;

import std;
import core;
import rfc.ws;
import net.tcp;
import .websocket;

// ---- Shared Buffer Capacity Helpers --------------------------------------

inline fn ws_buf_cap<B>(b: const B&) -> i64 {
    return b.cap;
}

inline fn ws_buf_cap(b: const u8[>..]&) -> i64 {
    return 0x7FFFFFFF;
}

// ---- WebSocket Framing & Session Internal Helpers ------------------------

// Packs the first byte of an RFC 6455 Section 5.2 frame header (`FIN | RSV1..3 | Opcode`).
//
// Example:
//   hdr = WsFrameHeader { fin: true, opcode: 1, .. }, eff_fin = true
//   returns: 0x81
inline fn pack_ws_frame_b0(hdr: const realtime::WsFrameHeader&, eff_fin: bool) -> u8 {
    var b0: u8 = hdr.opcode & rfc::WS_OPCODE_MASK;
    if eff_fin { b0 |= rfc::WS_FIN_BIT; }
    if hdr.rsv1 { b0 |= rfc::WS_RSV1_BIT; }
    if hdr.rsv2 { b0 |= rfc::WS_RSV2_BIT; }
    if hdr.rsv3 { b0 |= rfc::WS_RSV3_BIT; }
    return b0;
}

// Encodes an RFC 6455 frame header into `out`, rolling back on insufficient capacity.
fn try_encode_ws_header<B>(hdr: const realtime::WsFrameHeader&, out: B&) -> bool {
    var hdr_buf: u8[..14] = [];
    let eff_fin = if rfc::is_ws_control_opcode(hdr.opcode) { true } else { hdr.fin };
    hdr_buf.push(pack_ws_frame_b0(hdr, eff_fin));

    let mask_bit: u8 = if hdr.masked { rfc::WS_MASK_BIT } else { 0x00 };

    // RFC 6455 §5.5 & uWS #1407: Control frames MUST NOT exceed 125 bytes and MUST NEVER use extended length
    let eff_len = if rfc::is_ws_control_opcode(hdr.opcode) {
        min(hdr.payload_len, rfc::WS_MAX_CONTROL_LEN)
    } else {
        hdr.payload_len
    };

    if eff_len <= rfc::WS_MAX_CONTROL_LEN {
        hdr_buf.push(mask_bit | (eff_len as u8));
    } else if eff_len <= 65535 {
        hdr_buf.push(mask_bit | (rfc::WS_LEN16_SENTINEL as u8));
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

    let hdr = realtime::WsFrameHeader {
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
        realtime::mask_websocket_payload(out[payload_start..out.len], mask_key);
    }
    return true;
}

// Generates cryptographically secure 4-byte masking key for client frames per RFC 6455 Section 5.3.
// Returns `([0; 4], true)` for server sessions; fails closed `([0; 4], false)` on CSPRNG error.
fn ws_next_mask_key(ws: const realtime::WebSocketSession&) -> u8[4], bool {
    guard ws.is_client else { return [0, 0, 0, 0], true; }
    var mask: u8[4] = [0; 4];
    if core::sim_rng_is_active() {
        return mask, core::sim_rng_fill(mask[..]);
    }
    return mask, core::csprng_fill(mask[..]);
}

inline fn has_ws_header_ctl(s: const u8[:]) -> bool {
    for b in s {
        if b < 0x20 || b == 0x7F {
            return true;
        }
    }
    return false;
}

// Dispatches incoming raw frame wire bytes using zero-copy non-owning payload views:
// unmasks payload in-place, handles Ping/Pong and Close echoes, validates strict streaming UTF-8,
// and returns (view, handled) with a direct slice of the wire ingress buffer into view without copying.
fn receive_view_into<B, F>(
    ws:           realtime::WebSocketSession&,
    wire:         u8[:],
    frag_buf:     F&,
    max_frag_cap: i64,
    out_reply:    B&,
) -> realtime::WsMessageView, bool {
    var out_view = realtime::WsMessageView { .. };

    // RFC 6455 §5.5 & uWS #1407: Fail connection with PROTOCOL_ERROR (1002) upon fatal header invariant violations
    if wire.len >= 2 {
        let b0 = wire[0];
        let b1 = wire[1];
        let fin = (b0 & 0x80) != 0;
        let opcode = b0 & 0x0F;
        let raw_len = (b1 & 0x7F);

        if !rfc::is_valid_ws_opcode(opcode) {
            ws.close(rfc::WS_STATUS_PROTOCOL_ERROR, "unknown opcode", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return out_view, true;
        }

        if rfc::is_ws_control_opcode(opcode) && !fin {
            ws.close(rfc::WS_STATUS_PROTOCOL_ERROR, "fragmented control frame", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return out_view, true;
        }

        if rfc::is_ws_control_opcode(opcode) && raw_len > 125 {
            ws.close(rfc::WS_STATUS_PROTOCOL_ERROR, "control frame payload > 125", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return out_view, true;
        }

        // RFC 6455 §5.4: Interleaved data frame during fragmentation
        if (opcode == rfc::WS_OPCODE_TEXT || opcode == rfc::WS_OPCODE_BINARY) && ws.frag_opcode != 0 {
            ws.close(rfc::WS_STATUS_PROTOCOL_ERROR, "interleaved data frame during fragmentation", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            ws.frag_opcode = 0;
            ws.frag_compressed = false;
            ws.frag_utf8_offset = 0;
            frag_buf.clear();
            return out_view, true;
        }

        // RFC 6455 §5.4: Continuation frame without starting fragment
        if opcode == rfc::WS_OPCODE_CONTINUATION && ws.frag_opcode == 0 {
            ws.close(rfc::WS_STATUS_PROTOCOL_ERROR, "continuation frame without starting fragment", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return out_view, true;
        }

        // RFC 6455 §5.1: Masking enforcement - check immediately upon receiving header
        let masked = (b1 & 0x80) != 0;
        let role = if ws.is_client { realtime::WsRole.Client } else { realtime::WsRole.Server };
        if !realtime::is_ws_masking_valid(role, masked) {
            let reason = if ws.is_client {
                "masked frame received by client"
            } else {
                "unmasked frame received by server"
            };
            ws.close(rfc::WS_STATUS_PROTOCOL_ERROR, reason, out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return out_view, true;
        }

        // RFC 6455 §5.2 & RFC 7692 §5.1: RSV bit enforcement - check immediately upon receiving header
        let rsv1_bit = (b0 & 0x40) != 0;
        let rsv2_bit = (b0 & 0x20) != 0;
        let rsv3_bit = (b0 & 0x10) != 0;
        let rsv1_allowed = ws.permessage_deflate && (opcode == rfc::WS_OPCODE_TEXT || opcode == rfc::WS_OPCODE_BINARY);
        if (rsv1_bit && !rsv1_allowed) || rsv2_bit || rsv3_bit {
            ws.close(
                rfc::WS_STATUS_PROTOCOL_ERROR,
                "RSV bits set without extension or on non-initial data frame", out_reply,
            );
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return out_view, true;
        }

        // RFC 6455 §5.2 & Autobahn Cases 3.1..3.4:
        // Fail connection with 1002 on non-minimal length representations or high bit set in 64-bit length
        if raw_len == 126 && wire.len >= 4 {
            let p_len = core::read_be_u16(wire, 2);
            if p_len < 126 {
                ws.close(rfc::WS_STATUS_PROTOCOL_ERROR, "non-minimal 16-bit length encoding", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
                return out_view, true;
            }
        } else if raw_len == 127 && wire.len >= 10 {
            if (wire[2] & 0x80) != 0 {
                ws.close(rfc::WS_STATUS_PROTOCOL_ERROR, "high bit set in 64-bit length", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
                return out_view, true;
            }
            let p_len = core::read_be_u64(wire, 2);
            if p_len <= 65535 {
                ws.close(rfc::WS_STATUS_PROTOCOL_ERROR, "non-minimal 64-bit length encoding", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
                return out_view, true;
            }
        }
    }

    let hdr, ok = realtime::parse_ws_frame_header(wire);
    guard ok else { return out_view, false; }

    // RFC 6455 §5.5.1: If connection is closing or closed, incoming data frames MUST be discarded
    if ws.is_closed || ws.close_received {
        if !rfc::is_ws_control_opcode(hdr.opcode) {
            out_view.is_valid = false;
            return out_view, false;
        }
    }

    // RFC 6455 §7.4.1 (1009) & Memory Safety:
    // Fast-fail oversized frames immediately from header without waiting to buffer the full wire payload
    if !rfc::is_ws_control_opcode(hdr.opcode) && ws.max_payload_length > 0 && hdr.payload_len > ws.max_payload_length {
        ws.close(rfc::WS_STATUS_MESSAGE_TOO_BIG, "payload length exceeds max_payload_length", out_reply);
        ws.is_closed = true;
        ws.close_code = rfc::WS_STATUS_MESSAGE_TOO_BIG;
        ws.frag_opcode = 0;
        ws.frag_compressed = false;
        ws.frag_utf8_offset = 0;
        frag_buf.clear();
        return out_view, true;
    }

    let wire_len = wire.len as u64;
    let p_start_u = hdr.header_len as u64;
    guard p_start_u <= wire_len && hdr.payload_len <= (wire_len - p_start_u) else { return out_view, false; }
    let p_start = hdr.header_len as i64;
    let p_len = hdr.payload_len as i64;
    let payload = wire[p_start..core::add_sat_i64(p_start, p_len)];

    if hdr.masked {
        realtime::mask_websocket_payload(payload, hdr.mask_key);
    }

    // Control frames (RFC 6455 §5.5) - can arrive interleaved in fragmented messages
    if rfc::is_ws_control_opcode(hdr.opcode) {
        if hdr.opcode == rfc::WS_OPCODE_PING {
            ws.send_pong(payload, out_reply);
            out_view.opcode = rfc::WS_OPCODE_PING;
            out_view.payload = payload;
            out_view.is_valid = true;
            return out_view, true;
        } else if hdr.opcode == rfc::WS_OPCODE_PONG {
            ws.pongs_received += 1;
            out_view.opcode = rfc::WS_OPCODE_PONG;
            out_view.payload = payload;
            out_view.is_valid = true;
            return out_view, true;
        } else if hdr.opcode == rfc::WS_OPCODE_CLOSE {
            if ws.close_received {
                out_view.is_valid = false;
                return out_view, false;
            }
            ws.close_received = true;
            let code, reason, ok_close = realtime::parse_close_payload(payload);
            if !ok_close {
                ws.close(rfc::WS_STATUS_PROTOCOL_ERROR, "invalid close frame payload", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
                ws.frag_opcode = 0;
                ws.frag_compressed = false;
                ws.frag_utf8_offset = 0;
                frag_buf.clear();
                return out_view, true;
            }
            if reason.len > 0 && !reason.validate_utf8() {
                ws.close(rfc::WS_STATUS_INVALID_PAYLOAD, "invalid UTF-8 in close reason", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_INVALID_PAYLOAD;
                ws.frag_opcode = 0;
                ws.frag_compressed = false;
                ws.frag_utf8_offset = 0;
                frag_buf.clear();
                return out_view, true;
            }
            out_view.opcode = rfc::WS_OPCODE_CLOSE;
            out_view.close_code = code;
            out_view.close_reason = reason;
            out_view.is_valid = true;
            if !ws.is_closed && !ws.close_sent {
                let reply_code = if code == rfc::WS_STATUS_NO_STATUS { rfc::WS_STATUS_NO_STATUS } else { code };
                ws.close(reply_code, reason, out_reply);
            }
            ws.is_closed = true;
            ws.close_code = code;
            ws.frag_opcode = 0;
            ws.frag_compressed = false;
            ws.frag_utf8_offset = 0;
            ws.utf8_dfa_state = 0;
            frag_buf.clear();
            return out_view, true;
        }
    }

    // Data frames (RFC 6455 §5.4 & §5.6)
    if hdr.opcode == rfc::WS_OPCODE_TEXT || hdr.opcode == rfc::WS_OPCODE_BINARY {
        if ws.frag_opcode != 0 {
            ws.close(rfc::WS_STATUS_PROTOCOL_ERROR, "interleaved data frame during fragmentation", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            ws.frag_opcode = 0;
            ws.frag_compressed = false;
            ws.frag_utf8_offset = 0;
            frag_buf.clear();
            return out_view, true;
        }

        if hdr.fin {
            if ws.max_payload_length > 0 && (payload.len as u64) > ws.max_payload_length {
                ws.close(rfc::WS_STATUS_MESSAGE_TOO_BIG, "payload exceeds capacity", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_MESSAGE_TOO_BIG;
                out_view.is_valid = false;
                return out_view, true;
            }
            let need_utf8 = hdr.opcode == rfc::WS_OPCODE_TEXT && !hdr.rsv1;
            if need_utf8 && !payload.validate_utf8() {
                ws.close(rfc::WS_STATUS_INVALID_PAYLOAD, "invalid UTF-8 in text frame", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_INVALID_PAYLOAD;
                return out_view, true;
            }
            out_view.opcode = hdr.opcode;
            out_view.payload = payload;
            out_view.is_valid = true;
            out_view.is_compressed = hdr.rsv1;
            return out_view, true;
        }

        ws.frag_opcode = hdr.opcode;
        ws.frag_compressed = hdr.rsv1;
        ws.frag_utf8_offset = 0;
        ws.utf8_dfa_state = 0;
        frag_buf.clear();
        let max_len_i64 = min(ws.max_payload_length, 0x7FFFFFFFFFFFFFFF) as i64;
        let eff_cap = if ws.max_payload_length > 0 { min(max_len_i64, max_frag_cap) } else { max_frag_cap };
        if eff_cap <= 0 || payload.len > eff_cap {
            ws.close(rfc::WS_STATUS_MESSAGE_TOO_BIG, "fragment exceeds capacity", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_MESSAGE_TOO_BIG;
            ws.frag_opcode = 0;
            ws.frag_compressed = false;
            ws.frag_utf8_offset = 0;
            ws.utf8_dfa_state = 0;
            frag_buf.clear();
            return out_view, true;
        }
        frag_buf.append(payload);

        if ws.frag_opcode == rfc::WS_OPCODE_TEXT && !ws.frag_compressed {
            let ok_u8 = core::validate_utf8_dfa_chunk(payload, ws.utf8_dfa_state, false);
            if !ok_u8 {
                ws.close(rfc::WS_STATUS_INVALID_PAYLOAD, "invalid UTF-8 in initial fragment", out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_INVALID_PAYLOAD;
                ws.frag_opcode = 0;
                ws.frag_compressed = false;
                ws.frag_utf8_offset = 0;
                ws.utf8_dfa_state = 0;
                frag_buf.clear();
                return out_view, true;
            }
            ws.frag_utf8_offset = frag_buf.len;
        }

        out_view.is_valid = false;
        return out_view, true;
    } else if hdr.opcode == rfc::WS_OPCODE_CONTINUATION {
        if ws.frag_opcode == 0 {
            ws.close(rfc::WS_STATUS_PROTOCOL_ERROR, "continuation frame without starting fragment", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_PROTOCOL_ERROR;
            return out_view, true;
        }

        let max_len_i64 = min(ws.max_payload_length, 0x7FFFFFFFFFFFFFFF) as i64;
        let eff_cap = if ws.max_payload_length > 0 { min(max_len_i64, max_frag_cap) } else { max_frag_cap };
        if eff_cap <= 0 || payload.len > core::sub_sat_i64(eff_cap, frag_buf.len) {
            ws.close(rfc::WS_STATUS_MESSAGE_TOO_BIG, "assembled payload exceeds capacity", out_reply);
            ws.is_closed = true;
            ws.close_code = rfc::WS_STATUS_MESSAGE_TOO_BIG;
            ws.frag_opcode = 0;
            ws.frag_compressed = false;
            ws.frag_utf8_offset = 0;
            ws.utf8_dfa_state = 0;
            frag_buf.clear();
            return out_view, true;
        }
        frag_buf.append(payload);

        if ws.frag_opcode == rfc::WS_OPCODE_TEXT && !ws.frag_compressed {
            let ok_u8 = core::validate_utf8_dfa_chunk(payload, ws.utf8_dfa_state, hdr.fin);
            if !ok_u8 {
                let err_msg = if hdr.fin { "invalid UTF-8 in assembled message" } else { "invalid UTF-8 in fragment" };
                ws.close(rfc::WS_STATUS_INVALID_PAYLOAD, err_msg, out_reply);
                ws.is_closed = true;
                ws.close_code = rfc::WS_STATUS_INVALID_PAYLOAD;
                ws.frag_opcode = 0;
                ws.frag_compressed = false;
                ws.frag_utf8_offset = 0;
                ws.utf8_dfa_state = 0;
                frag_buf.clear();
                return out_view, true;
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
            return out_view, true;
        } else {
            out_view.is_valid = false;
            return out_view, true;
        }
    }

    return out_view, true;
}

// Streams and dispatches a single WebSocket frame from the front of `wire` into `frag_buf`.
// Returns `(0, false, view)` when `wire` contains an incomplete frame header or payload.
fn consume_frame_view_into<B, F>(
    ws:           realtime::WebSocketSession&,
    wire:         u8[:],
    frag_buf:     F&,
    max_frag_cap: i64,
    out_reply:    B&,
) -> i64, bool, realtime::WsMessageView {
    guard !ws.is_closed && wire.len >= 2 else { return 0, false, realtime::WsMessageView { .. }; }

    let hdr, ok_hdr = realtime::parse_ws_frame_header(wire);
    if ok_hdr {
        let hdr_len = hdr.header_len as u64;
        let wire_len = wire.len as u64;
        if hdr_len <= wire_len && hdr.payload_len <= (wire_len - hdr_len) {
            let total_len = (hdr_len + hdr.payload_len) as i64;
            let view, handled = receive_view_into(ws, wire[..total_len], frag_buf, max_frag_cap, out_reply);
            return total_len, handled || ws.is_closed, view;
        }
    }

    let view, handled = receive_view_into(ws, wire, frag_buf, max_frag_cap, out_reply);
    if handled || ws.is_closed {
        return wire.len, true, view;
    }
    return 0, false, view;
}

// Default WebSocket message stage hook (RFC 6455 echo).
fn on_ws_message<Stage, B>(
    _stage:   Stage&,
    ws:       realtime::WebSocketSession&,
    view:     const realtime::WsMessageView&,
    out_wire: B&,
) {
    if view.opcode == rfc::WS_OPCODE_TEXT {
        ws.send_text(view.payload, out_wire);
    } else if view.opcode == rfc::WS_OPCODE_BINARY {
        ws.send_binary(view.payload, out_wire);
    }
}

// Drains trailing socket bytes after sending a Close frame so the peer receives
// the Close frame instead of an immediate TCP RST (RFC 6455 §7.1.1).
fn ws_drain_and_close(conn_fd: i64) {
    let _ = net::tcp_shutdown(conn_fd, net::SHUT_WR);
    var drain_buf: u8[..4096] = [];
    var step:      i64        = 0;
    while step < 10 {
        step = core::add_sat_i64(step, 1);
        drain_buf.clear();
        let dn = net::tcp_recv(conn_fd, drain_buf, 4096, 20);
        if dn <= 0 {
            break;
        }
    }
    net::tcp_close(conn_fd);
}

inline fn is_ws_data_message(view: const realtime::WsMessageView&) -> bool {
    return view.is_valid && (view.opcode == rfc::WS_OPCODE_TEXT || view.opcode == rfc::WS_OPCODE_BINARY);
}

inline fn flush_ws_wire(conn_fd: i64, wire: const u8[:]) {
    if wire.len > 0 {
        let _ = net::tcp_send(conn_fd, wire);
    }
}

// Session-scoped RFC 7692 permessage-deflate scratch and sliding-window state.
// Allocated once per WebSocket session outside the frame loop (0B per-frame allocation).

// Computes exact WebSocket frame wire length including header, extended length, mask key, and payload.
fn calc_ws_frame_len(payload_len: u64, is_client: bool) -> u64 {
    let ext_len:  u64 = if payload_len > 65535 { 8 } else if payload_len > 125 { 2 } else { 0 };
    let mask_len: u64 = if is_client { 4 } else { 0 };
    return core::add_sat_u64(core::add_sat_u64(2, ext_len), core::add_sat_u64(mask_len, payload_len));
}
