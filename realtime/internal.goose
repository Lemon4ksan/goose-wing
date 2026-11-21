// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal constants, state helpers, and protocol plumbing for package `realtime`.
namespace realtime_internal;

import std;
import core;
import rfc.http;
import rfc.ws;
import rfc.h3_quic;
import http.headers;
import http.request;
import http.response;
import net.tcp;
import .sse;
import .topic_tree;
import .websocket;
import .ws_deflate;
import .ws_handshake;
import .webtransport;

// ---- Native CSPRNG & SIMD Shims ------------------------------------------

extern fn native_crypto_random_bytes(out: u8[:]) -> i32 = "wing_crypto_random_bytes";
extern fn native_simd_mask_websocket(data: u8[:], mask: const u8[4]&) = "wing_simd_mask_websocket";
extern fn native_simd_unmask_shifted(
    slice:       u8[:],
    header_len:  i64,
    payload_len: i64,
    mask:        const u8[4]&,
) = "wing_simd_unmask_shifted";

// ---- Shared Buffer Capacity Helpers --------------------------------------

inline fn ws_buf_cap<B>(b: const B&) -> i64 {
    return b.cap;
}

inline fn ws_buf_cap(b: const u8[>..]&) -> i64 {
    return 0x7FFFFFFF;
}

// ---- SSE Internal Helpers (W3C EventSource) ------------------------------

const SSE_MAX_DATA_LEN: i64 = 4096;
const SSE_MAX_LINE_LEN: i64 = 4112;

// Parses an SSE retry milliseconds field value.
//
// Example:
//   field_val = "3000"
//   returns: 3000, true
fn parse_sse_retry(field_val: const u8[:]) -> u32, bool {
    guard field_val.len > 0 else { return 0, false; }
    var num: u32 = 0;
    for b in field_val {
        guard core::is_ascii_digit(b) else { return 0, false; }
        let digit = (b - '0') as u32;
        num = core::add_sat_u32(core::mul_sat_u32(num, 10), digit);
    }
    return num, true;
}

fn sse_process_field(
    p:          realtime::SseParser&,
    field_name: const u8[:],
    field_val:  const u8[:],
) {
    if field_name == "event" {
        let copy_len = min(field_val.len, p.cur_event.cap);
        let _ = p.cur_event.try_set(field_val[..copy_len]);
    } else if field_name == "data" {
        if p.has_data && p.cur_data.len < SSE_MAX_DATA_LEN {
            let _ = p.cur_data.try_push('\n');
        }
        p.has_data = true;
        let rem = core::sub_sat_i64(SSE_MAX_DATA_LEN, p.cur_data.len);
        let copy_len = min(field_val.len, rem);
        if copy_len > 0 {
            let _ = p.cur_data.try_append(field_val[..copy_len]);
        }
    } else if field_name == "id" {
        // Must not contain NUL byte (W3C EventSource §9.2.6)
        if !field_val.contains_byte(0) {
            let copy_len = min(field_val.len, p.pending_id.cap);
            let _ = p.pending_id.try_set(field_val[..copy_len]);
            p.has_pending_id = true;
        }
    } else if field_name == "retry" {
        let num, ok = parse_sse_retry(field_val);
        if ok {
            p.retry_ms = num;
        }
    }
}

fn sse_process_line<E>(p: realtime::SseParser&, out_events: E&) {
    var line = p.line_buf[..];

    // W3C EventSource §9.2.5: One leading U+FEFF BOM (0xEF 0xBB 0xBF) must be stripped if present
    if !p.bom_checked {
        p.bom_checked = true;
        if line.len >= 3 && line[0] == 0xEF && line[1] == 0xBB && line[2] == 0xBF {
            line = line[3..];
        }
    }

    // Empty line indicates event boundary (W3C Section 6 / §9.2.6: dispatch the event)
    if line.len == 0 {
        if p.has_pending_id {
            let _ = p.last_event_id.try_set(p.pending_id[..]);
            p.has_pending_id = false;
        }
        if p.has_data {
            var ev = realtime::SseEvent {
                retry_ms: p.retry_ms,
                is_valid: true,
                ..
            };
            if p.cur_event.len > 0 {
                ev.event.append(p.cur_event[..]);
            } else {
                ev.event.append("message");
            }
            ev.data.append(p.cur_data[..]);
            ev.id.append(p.last_event_id[..]);

            p.cur_event.clear();
            p.cur_data.clear();
            p.has_data = false;

            let _ = out_events.try_push(ev);
        } else {
            p.cur_event.clear();
        }
        return;
    }

    if line[0] == ':' {
        return;
    }

    // Split on first colon separating field name from value (W3C EventSource §9.2.6)
    let field_name, raw_val, has_colon = line.split_once_byte(':');
    if has_colon {
        let field_val = if raw_val.len > 0 && raw_val[0] == ' ' { raw_val[1..] } else { raw_val };
        sse_process_field(p, field_name, field_val);
    } else {
        sse_process_field(p, line, "");
    }
}

// Scans for the first line break or NUL byte in an SSE header token.
//
// Example:
//   s = "id-42\r\ninjected"
//   returns: 5
fn sse_clean_token_len(s: const u8[:]) -> i64 {
    for i in s.len {
        if s[i] == '\r' || s[i] == '\n' || s[i] == 0 {
            return i;
        }
    }
    return s.len;
}

fn sse_format_data_lines<B>(out: B&, data: const u8[:]) {
    var start: i64 = 0;
    var i:     i64 = 0;
    while i < data.len {
        if data[i] == '\r' || data[i] == '\n' {
            out.append("data: ");
            out.append(data[start..i]);
            out.push('\n');
            let next_i = core::add_sat_i64(i, 1);
            if data[i] == '\r' && next_i < data.len && data[next_i] == '\n' {
                i = core::add_sat_i64(i, 2);
            } else {
                i = next_i;
            }
            start = i;
        } else {
            i = core::add_sat_i64(i, 1);
        }
    }
    out.append("data: ");
    out.append(data[start..]);
    out.push('\n');
}

// ---- WebSocket Framing & Session Internal Helpers ------------------------

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
inline fn pack_ws_frame_b0(hdr: const realtime::WsFrameHeader&, eff_fin: bool) -> u8 {
    var b0: u8 = hdr.opcode & WS_OPCODE_MASK;
    if eff_fin { b0 |= WS_FIN_BIT; }
    if hdr.rsv1 { b0 |= WS_RSV1_BIT; }
    if hdr.rsv2 { b0 |= WS_RSV2_BIT; }
    if hdr.rsv3 { b0 |= WS_RSV3_BIT; }
    return b0;
}

// Encodes an RFC 6455 frame header into `out`, rolling back on insufficient capacity.
fn try_encode_ws_header<B>(hdr: const realtime::WsFrameHeader&, out: B&) -> bool {
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
fn ws_next_mask_key(ws: realtime::WebSocketSession&) -> u8[4] {
    var mask: u8[4] = [0; 4];
    if core::sim_rng_fill(mask[..]) || native_crypto_random_bytes(mask[..]) == 0 {
        return mask;
    }
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
    var drain_buf: u8[..4096] = [];
    var step:      i64        = 0;
    while step < 10 {
        step = core::add_sat_i64(step, 1);
        drain_buf.clear();
        let dn = net::tcp_recv(conn_fd, drain_buf, 20);
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

fn dispatch_ws_data_turn<Stage, OutBuf, ReplyBuf>(
    ws:        realtime::WebSocketSession&,
    stage:     Stage&,
    view:      const realtime::WsMessageView&,
    pmd_comp:  realtime::SharedWsCompressor&,
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
    let reset_win = realtime::ws_should_reset_decompressor(ws);
    if !pmd_comp.ws_inflate_message(view.payload, pmd_plain, max_pay, reset_win) {
        ws.close(rfc::WS_STATUS_PROTOCOL_ERROR, "invalid permessage-deflate stream", reply);
        return;
    }
    if view.opcode == rfc::WS_OPCODE_TEXT && !pmd_plain[..].validate_utf8() {
        ws.close(rfc::WS_STATUS_INVALID_PAYLOAD, "invalid UTF-8 in compressed text frame", reply);
        return;
    }
    let inflated_view = realtime::WsMessageView {
        opcode:        view.opcode,
        payload:       pmd_plain[..],
        is_valid:      true,
        is_compressed: false,
        ..
    };
    out_wire.clear();
    on_ws_message(stage, ws, inflated_view, out_wire);
}

// ---- PerMessage-Deflate Internal Helpers (RFC 7692) ----------------------

const PMD_SEEN_SERVER_NO_CTX:  u8 = 1;
const PMD_SEEN_CLIENT_NO_CTX:  u8 = 2;
const PMD_SEEN_SERVER_MAX_WIN: u8 = 4;
const PMD_SEEN_CLIENT_MAX_WIN: u8 = 8;

// Strips the 4-byte RFC 7692 §7.2.1 sync-flush tail (`0x00 0x00 0xFF 0xFF`) if present.
inline fn strip_pmd_sync_flush_tail(buf: const u8[:]) -> i64 {
    let eff_len = buf.len;
    guard eff_len >= 4 else { return eff_len; }
    let base_idx = core::sub_sat_i64(eff_len, 4);
    if core::read_be_u32(buf, base_idx) == 0x0000FFFF {
        return base_idx;
    }
    return eff_len;
}

// Updates the sliding dictionary window with new uncompressed bytes up to `window_kb * 1024` (max 32 KB).
fn update_dedicated_history(dedicated: realtime::DedicatedWsCompressor&, raw: const u8[:]) {
    let win_bytes = if dedicated.window_kb > 0 { core::mul_sat_i64(dedicated.window_kb, 1024) } else { 32768 };
    let max_win = min(win_bytes, min(32768, dedicated.history.cap));
    guard max_win > 0 && raw.len > 0 else { return; }

    if raw.len >= max_win {
        let tail_start = core::sub_sat_i64(raw.len, max_win);
        let _ = dedicated.history.try_set(raw[tail_start..]);
        return;
    }

    let total = core::add_sat_i64(dedicated.history.len, raw.len);
    if total > max_win {
        let drop_len = core::sub_sat_i64(total, max_win);
        let keep_len = core::sub_sat_i64(dedicated.history.len, drop_len);
        for i in keep_len {
            let src_idx = core::add_sat_i64(drop_len, i);
            dedicated.history[i] = dedicated.history[src_idx];
        }
        dedicated.history.resize(keep_len);
    }
    dedicated.history.append(raw);
}

// Unescapes an RFC 6455 Section 9.1 quoted extension parameter value into `out`.
//
// Example:
//   quoted = "\"\\1\\2\"", out = []
//   returns: true, out = "12"
fn unescape_pmd_quoted_val(quoted: const u8[:], out: u8[..8]&) -> bool {
    guard quoted.len >= 2 && quoted[0] == '"' && quoted[quoted.len - 1] == '"' else {
        return false;
    }
    let inner = quoted[1..^1];
    var i: i64 = 0;
    while i < inner.len {
        let b = inner[i];
        if b == '\\' {
            let esc_idx = core::add_sat_i64(i, 1);
            guard esc_idx < inner.len else { return false; }
            let esc = inner[esc_idx];
            guard core::is_tchar(esc) && out.try_push(esc) else { return false; }
            i = core::add_sat_i64(i, 2);
            continue;
        }
        guard b != '"' && core::is_tchar(b) && out.try_push(b) else { return false; }
        i = core::add_sat_i64(i, 1);
    }
    return true;
}

// Parses a strict RFC 7692 §7.1 window_bits value (base-10 integer in 8..15, no leading '0' or '+').
// Clamps window_bits == 8 to 9 for raw deflate compatibility (uWebSockets / libwebsockets pattern).
//
// Example:
//   raw = "\"12\""
//   returns: bits = 12, ok = true
fn parse_pmd_window_bits(raw: const u8[:]) -> u8, bool {
    let trimmed = raw.trim_lws();
    var unescaped: u8[..8] = [];
    if trimmed.len > 0 && trimmed[0] == '"' {
        guard unescape_pmd_quoted_val(trimmed, unescaped) else { return 0, false; }
    } else {
        guard !trimmed.contains_byte('"') && !trimmed.contains_byte('\\') else { return 0, false; }
        guard unescaped.try_set(trimmed) else { return 0, false; }
    }
    if unescaped.len == 1 {
        let b0 = unescaped[0];
        guard b0 == '8' || b0 == '9' else { return 0, false; }
        return 9, true;
    }
    guard unescaped.len == 2 else { return 0, false; }
    let b0 = unescaped[0];
    let b1 = unescaped[1];
    guard b0 == '1' && b1 >= '0' && b1 <= '5' else { return 0, false; }
    return (core::add_sat_i64(10, core::sub_sat_i64(b1, '0'))) as u8, true;
}

inline fn apply_pmd_window_param(
    key:        const u8[:],
    val:        const u8[:],
    has_eq:     bool,
    server_cfg: const realtime::PerMessageDeflateConfig&,
    seen_mask:  u8&,
    out_cfg:    realtime::PerMessageDeflateConfig&,
) -> bool {
    if key == "server_max_window_bits" {
        guard has_eq && (seen_mask & PMD_SEEN_SERVER_MAX_WIN) == 0 else { return false; }
        let bits, ok_b = parse_pmd_window_bits(val);
        guard ok_b else { return false; }
        seen_mask |= PMD_SEEN_SERVER_MAX_WIN;
        out_cfg.server_max_window_bits = min(out_cfg.server_max_window_bits, bits);
        return true;
    }
    if key == "client_max_window_bits" {
        guard (seen_mask & PMD_SEEN_CLIENT_MAX_WIN) == 0 else { return false; }
        if has_eq {
            let bits, ok_b = parse_pmd_window_bits(val);
            guard ok_b else { return false; }
            seen_mask |= PMD_SEEN_CLIENT_MAX_WIN;
            out_cfg.client_max_window_bits = min(server_cfg.client_max_window_bits, bits);
        } else {
            seen_mask |= PMD_SEEN_CLIENT_MAX_WIN;
            let capped = min(server_cfg.client_max_window_bits, rfc::WS_PMD_MAX_WINDOW_BITS);
            out_cfg.client_max_window_bits = max(9, capped);
        }
        return true;
    }
    return false;
}

inline fn apply_pmd_param(
    key:        const u8[:],
    val:        const u8[:],
    has_eq:     bool,
    server_cfg: const realtime::PerMessageDeflateConfig&,
    seen_mask:  u8&,
    out_cfg:    realtime::PerMessageDeflateConfig&,
) -> bool {
    guard key.len > 0 else { return false; }
    if key == "server_no_context_takeover" {
        guard !has_eq && (seen_mask & PMD_SEEN_SERVER_NO_CTX) == 0 else { return false; }
        seen_mask |= PMD_SEEN_SERVER_NO_CTX;
        out_cfg.server_no_context_takeover = true;
        return true;
    }
    if key == "client_no_context_takeover" {
        guard !has_eq && (seen_mask & PMD_SEEN_CLIENT_NO_CTX) == 0 else { return false; }
        seen_mask |= PMD_SEEN_CLIENT_NO_CTX;
        out_cfg.client_no_context_takeover = true;
        return true;
    }
    return apply_pmd_window_param(key, val, has_eq, server_cfg, seen_mask, out_cfg);
}

// Parses a single RFC 7692 `permessage-deflate` extension offer and its `;`-delimited parameters.
//
// Example:
//   offer_raw = "permessage-deflate; server_no_context_takeover", server_cfg = PerMessageDeflateConfig { .. }
//   returns: PerMessageDeflateConfig { server_no_context_takeover: true, .. }, ok = true
inline fn parse_single_pmd_offer(
    offer_raw:  const u8[:],
    server_cfg: const realtime::PerMessageDeflateConfig&,
) -> realtime::PerMessageDeflateConfig, bool {
    let offer = offer_raw.trim_lws();
    let ext_name, rest_params, has_params = offer.split_once_unquoted_byte(';');
    guard ext_name.trim_lws() == rfc::WS_PMD_EXTENSION_NAME else {
        return realtime::PerMessageDeflateConfig { .. }, false;
    }

    var cfg = realtime::PerMessageDeflateConfig {
        server_max_window_bits:     max(9, min(server_cfg.server_max_window_bits, rfc::WS_PMD_MAX_WINDOW_BITS)),
        client_max_window_bits:     rfc::WS_PMD_MAX_WINDOW_BITS,
        server_no_context_takeover: server_cfg.server_no_context_takeover,
        client_no_context_takeover: server_cfg.client_no_context_takeover,
    };

    var seen_mask: u8 = 0;
    var rem = rest_params;
    var more = has_params;
    while more {
        let param_raw, next_rem, has_next = rem.split_once_unquoted_byte(';');
        let param = param_raw.trim_lws();
        guard param.len > 0 else { return realtime::PerMessageDeflateConfig { .. }, false; }
        let k_raw, v_raw, has_eq = param.split_once_unquoted_byte('=');
        guard apply_pmd_param(k_raw.trim_lws(), v_raw.trim_lws(), has_eq, server_cfg, seen_mask, cfg) else {
            return realtime::PerMessageDeflateConfig { .. }, false;
        }
        rem = next_rem;
        more = has_next;
    }
    return cfg, true;
}

// ---- WebSocket Handshake Internal Helpers (RFC 6455 / 8441) --------------

// Block 1: 24 bytes client key + 36 bytes GUID + 0x80 padding + 3 zero bytes = 64 bytes.
let WS_SHA1_BLOCK1_GUID: const u8[40] = [
    '2', '5', '8', 'E', 'A', 'F', 'A', '5', '-', 'E', '9', '1', '4', '-', '4', '7', 'D', 'A',
    '-', '9', '5', 'C', 'A', '-', 'C', '5', 'A', 'B', '0', 'D', 'C', '8', '5', 'B', '1', '1',
    0x80, 0, 0, 0,
];

// Block 2: 56 zero bytes + big-endian 480 bit length (0x01E0) = 64 bytes.
let WS_SHA1_BLOCK2_TEMPLATE: const u8[64] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xE0,
];

fn has_header_token_fold(list: const u8[:], target: const u8[:]) -> bool {
    guard list.len > 0 && target.len > 0 else { return false; }
    var tok = core::make_byte_tokenizer(list, ',');
    loop {
        let part, ok = tok.token_next();
        guard ok else { break; }
        if part.trim_lws().eq_ascii_fold(target) {
            return true;
        }
    }
    return false;
}

fn req_count_header(req: const http::Request&, header_name: const u8[:]) -> i64 {
    var count: i64 = 0;
    for &e in req.headers.entries {
        if http::entry_name(req.headers, e).eq_ascii_fold(header_name) {
            count = core::add_sat_i64(count, 1);
        }
    }
    return count;
}

fn req_has_header_token(req: const http::Request&, header_name: const u8[:], token: const u8[:]) -> bool {
    for &e in req.headers.entries {
        if http::entry_name(req.headers, e).eq_ascii_fold(header_name) {
            if has_header_token_fold(http::entry_value(req.headers, e), token) {
                return true;
            }
        }
    }
    return false;
}

fn req_has_subprotocol(req: const http::Request&, subprotocol: const u8[:]) -> bool {
    for &e in req.headers.entries {
        if http::entry_name(req.headers, e).eq_ascii_fold("sec-websocket-protocol") {
            if realtime::has_subprotocol_token(http::entry_value(req.headers, e), subprotocol) {
                return true;
            }
        }
    }
    return false;
}

inline fn resolve_hdr_entry_name(
    map:     const http::HeaderMap&,
    raw_buf: const u8[:],
    e:       const http::HeaderEntry&,
) -> const u8[:] {
    if raw_buf.len > 0 && e.name_end <= raw_buf.len {
        return raw_buf[(e.name_begin as i64)..(e.name_end as i64)];
    }
    if e.name_end <= map.raw_buf.len {
        return map.raw_buf[(e.name_begin as i64)..(e.name_end as i64)];
    }
    return "";
}

inline fn resolve_hdr_entry_val(
    map:     const http::HeaderMap&,
    raw_buf: const u8[:],
    e:       const http::HeaderEntry&,
) -> const u8[:] {
    if raw_buf.len > 0 && e.values_end <= raw_buf.len {
        return raw_buf[(e.values_begin as i64)..(e.values_end as i64)];
    }
    if e.values_end <= map.raw_buf.len {
        return map.raw_buf[(e.values_begin as i64)..(e.values_end as i64)];
    }
    return "";
}

fn map_has_header_token(
    map:         const http::HeaderMap&,
    raw_buf:     const u8[:],
    header_name: const u8[:],
    token:       const u8[:],
) -> bool {
    for &e in map.entries {
        if resolve_hdr_entry_name(map, raw_buf, e).eq_ascii_fold(header_name) {
            if has_header_token_fold(resolve_hdr_entry_val(map, raw_buf, e), token) {
                return true;
            }
        }
    }
    return false;
}

// Extracts the first trimmed value and occurrence count of `header_name` in `map`.
//
// Example:
//   header_name = "sec-websocket-accept"
//   returns: ("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", 1)
fn map_extract_single_header(
    map:         const http::HeaderMap&,
    raw_buf:     const u8[:],
    header_name: const u8[:],
) -> const u8[:], i64 {
    var first_idx: i64 = -1;
    var count:     i64 = 0;
    for &e, i in map.entries {
        if resolve_hdr_entry_name(map, raw_buf, e).eq_ascii_fold(header_name) {
            count = core::add_sat_i64(count, 1);
            if count == 1 {
                first_idx = i;
            }
        }
    }
    if first_idx >= 0 {
        let first_e .= map.entries[first_idx];
        return resolve_hdr_entry_val(map, raw_buf, first_e).trim_lws(), count;
    }
    return "", count;
}

inline fn is_valid_ws_token_slice(s: const u8[:]) -> bool {
    guard s.len > 0 else { return false; }
    for b in s {
        guard core::is_tchar(b) else { return false; }
    }
    return true;
}

fn has_offered_ws_extension_name(offered: const u8[:], ext_name: const u8[:]) -> bool {
    guard offered.len > 0 && is_valid_ws_token_slice(ext_name) else { return false; }
    var rem = offered;
    while rem.len > 0 {
        let head, tail, has_comma = rem.split_once_unquoted_byte(',');
        let name_part, _, _ = head.split_once_unquoted_byte(';');
        if name_part.trim_lws() == ext_name {
            return true;
        }
        if !has_comma { break; }
        rem = tail;
    }
    return false;
}

inline fn validate_single_response_ws_ext(
    head:               const u8[:],
    offered_extensions: const u8[:],
    saw_pmd:            bool&,
) -> bool {
    let name_part, _, _ = head.split_once_unquoted_byte(';');
    let ext_name = name_part.trim_lws();
    guard has_offered_ws_extension_name(offered_extensions, ext_name) else {
        return false;
    }
    if ext_name == rfc::WS_PMD_EXTENSION_NAME {
        guard !saw_pmd else { return false; }
        let default_pmd = realtime::PerMessageDeflateConfig { .. };
        let _, ok_pmd = parse_single_pmd_offer(head, default_pmd);
        guard ok_pmd else { return false; }
        saw_pmd = true;
    }
    return true;
}

fn validate_response_ws_extensions(
    headers:            const http::HeaderMap&,
    raw_buf:            const u8[:],
    offered_extensions: const u8[:],
) -> bool {
    var saw_pmd = false;
    for &e in headers.entries {
        if !resolve_hdr_entry_name(headers, raw_buf, e).eq_ascii_fold("sec-websocket-extensions") {
            continue;
        }
        guard offered_extensions.len > 0 else { return false; }
        var rem = resolve_hdr_entry_val(headers, raw_buf, e).trim_lws();
        guard rem.len > 0 else { return false; }
        while rem.len > 0 {
            let head, tail, has_comma = rem.split_once_unquoted_byte(',');
            guard validate_single_response_ws_ext(head, offered_extensions, saw_pmd) else {
                return false;
            }
            if !has_comma { break; }
            rem = tail;
        }
    }
    return true;
}

inline fn req_has_ws_host_authority(req: const http::Request&) -> bool {
    let host_cnt = req_count_header(req, "host");
    if host_cnt > 1 {
        return false;
    }
    if host_cnt == 1 {
        return req.headers.find_header("Host").trim_lws().len > 0;
    }
    guard req.url.len > 0 else { return false; }
    let u = core::new_url(req.url[..]);
    return u.valid && u.host().len > 0;
}

fn append_unique_ws_subprotocols(raw_val: const u8[:], seen: (const u8[:])[..32]&) -> bool {
    guard raw_val.len > 0 else { return false; }
    var tok = core::make_byte_tokenizer(raw_val, ',');
    while true {
        let part, ok = tok.token_next();
        guard ok else { break; }
        let item = part.trim_lws();
        guard is_valid_ws_token_slice(item) else { return false; }
        for prev in seen {
            guard prev != item else { return false; }
        }
        guard seen.try_push(item) else { return false; }
    }
    return true;
}

fn req_has_valid_ws_subprotocols(req: const http::Request&) -> bool {
    var seen: (const u8[:])[..32] = [];
    for &e in req.headers.entries {
        if http::entry_name(req.headers, e).eq_ascii_fold("sec-websocket-protocol") {
            let raw_val = http::entry_value(req.headers, e).trim_lws();
            guard append_unique_ws_subprotocols(raw_val, seen) else { return false; }
        }
    }
    return true;
}

fn validate_ws_upgrade_headers(req: const http::Request&, out_resp: http::Response&) -> const u8[:], bool {
    guard req_has_ws_host_authority(req) &&
        req_has_header_token(req, "upgrade", "websocket") &&
        req_has_header_token(req, "connection", "upgrade") else {
        out_resp.status_code = rfc::STATUS_BAD_REQUEST;
        return "", false;
    }
    guard req_count_header(req, "sec-websocket-version") == 1 &&
        req_count_header(req, "sec-websocket-key") == 1 &&
        req_has_valid_ws_subprotocols(req) else {
        out_resp.status_code = rfc::STATUS_BAD_REQUEST;
        return "", false;
    }
    if req.headers.find_header("Sec-WebSocket-Version") != rfc::WS_RFC6455_VERSION {
        out_resp.status_code = rfc::STATUS_UPGRADE_REQUIRED;
        out_resp.set_header("Sec-WebSocket-Version", rfc::WS_RFC6455_VERSION);
        return "", false;
    }
    let client_key = req.headers.find_header("Sec-WebSocket-Key");
    guard realtime::is_valid_websocket_key(client_key) else {
        out_resp.status_code = rfc::STATUS_BAD_REQUEST;
        return "", false;
    }
    return client_key, true;
}

inline fn is_forbidden_h2_ws_header(name: const u8[:]) -> bool {
    return name.eq_ascii_fold("connection") ||
           name.eq_ascii_fold("upgrade") ||
           name.eq_ascii_fold("keep-alive") ||
           name.eq_ascii_fold("transfer-encoding") ||
           name.eq_ascii_fold("proxy-connection") ||
           name.eq_ascii_fold("sec-websocket-key");
}

fn format_h2_websocket_response(res: http::Response&, subprotocol: const u8[:] = "") {
    res.status_code = rfc::STATUS_OK;
    if subprotocol.len > 0 {
        res.set_header("sec-websocket-protocol", subprotocol);
    }
}

// ---- TopicTree Internal Helpers (OASIS MQTT v5.0 §4.7) -------------------

const TOPIC_TREE_MAX_BUCKETS:           i64 = 256;
const TOPIC_TREE_MAX_SUBSCRIPTIONS:     i64 = 4096;
const TOPIC_PALETTE_CAP:                i64 = 64;
const TOPIC_MAX_SUBSCRIBERS_PER_BUCKET: i32 = 512;

enum BatchSeenResult {
    Added,
    AlreadySeen,
    CapacityExceeded,
}

// Scans forward from `start` until '/' or end of slice (OASIS MQTT v5.0 §4.7).
//
// Example:
//   raw = "sensors/temp", start = 0
//   returns: 7
fn scan_topic_segment_end(raw: const u8[:], start: i64) -> i64 {
    var next = start;
    while next < raw.len && raw[next] != '/' {
        next = core::add_sat_i64(next, 1);
    }
    return next;
}

inline fn is_valid_wildcard_char(pattern: const u8[:], i: i64, b: u8) -> bool {
    guard b != 0 else { return false; }
    if b == '#' {
        guard i == core::sub_sat_i64(pattern.len, 1) else { return false; }
        if i > 0 {
            guard pattern[core::sub_sat_i64(i, 1)] == '/' else { return false; }
        }
        return true;
    }
    if b == '+' {
        if i > 0 {
            guard pattern[core::sub_sat_i64(i, 1)] == '/' else { return false; }
        }
        let next_i = core::add_sat_i64(i, 1);
        if next_i < pattern.len {
            guard pattern[next_i] == '/' else { return false; }
        }
    }
    return true;
}

inline fn compute_topic_first_seg_hash(s: const u8[:]) -> u32 {
    let seg_end = scan_topic_segment_end(s, 0);
    let seg = s[..seg_end];
    if seg == "+" || seg == "#" {
        return 0;
    }
    return core::fnv1a_32(seg);
}

inline fn does_bucket_match_topic(
    b_entry:    const realtime::TopicBucket&,
    topic:      const u8[:],
    t_hash:     u32,
    t_seg_hash: u32,
) -> bool {
    if !b_entry.has_wildcard {
        return b_entry.pattern_hash == t_hash && b_entry.topic_pattern[..] == topic;
    }
    if b_entry.first_seg_hash != 0 && b_entry.first_seg_hash != t_seg_hash {
        return false;
    }
    return realtime::match_topic(b_entry.topic_pattern[..], topic);
}

// Finds the index of a bucket matching the given topic pattern.
//
// Example:
//   pattern = "chat/general"
//   returns: idx = 0, ok = true (or 0, false if not found)
fn find_topic_bucket(tree: const realtime::TopicTree&, pattern: const u8[:]) -> i32, bool {
    let p_hash = core::fnv1a_32(pattern);
    for &b_entry, i in tree.buckets {
        if b_entry.in_use && b_entry.pattern_hash == p_hash && b_entry.topic_pattern[..] == pattern {
            return i as i32, true;
        }
    }
    return 0, false;
}

// Allocates or retrieves a topic bucket for the given pattern.
fn get_or_create_topic_bucket(tree: realtime::TopicTree&, pattern: const u8[:]) -> i32, bool {
    guard realtime::is_valid_topic_filter(pattern) else { return 0, false; }

    let existing, found = find_topic_bucket(tree, pattern);
    if found {
        return existing, true;
    }

    let p_hash = core::fnv1a_32(pattern);
    let seg_hash = compute_topic_first_seg_hash(pattern);
    for &b_entry, i in tree.buckets {
        if !b_entry.in_use {
            let _ = b_entry.topic_pattern.try_set(pattern);
            b_entry.pattern_hash = p_hash;
            b_entry.first_seg_hash = seg_hash;
            b_entry.head_sub = -1;
            b_entry.subscriber_count = 0;
            b_entry.has_wildcard = pattern.contains_byte('+') || pattern.contains_byte('#');
            b_entry.in_use = true;
            tree.active_buckets = core::add_sat_i64(tree.active_buckets, 1) as i32;
            return i as i32, true;
        }
    }

    return 0, false;
}

fn is_subscribed_in_bucket(tree: const realtime::TopicTree&, b: i64, sock_fd: i64) -> bool {
    var cur = tree.buckets[b].head_sub;
    while cur >= 0 {
        let cur_i64 = cur as i64;
        let node .= tree.nodes[cur_i64];
        if node.in_use && node.sock_fd == sock_fd {
            return true;
        }
        cur = node.next_sub;
    }
    return false;
}

fn unlink_drainable_node(tree: realtime::TopicTree&, node_idx: i32) {
    guard node_idx >= 0 && node_idx < tree.nodes.len as i32 else { return; }
    let n_i64 = node_idx as i64;
    let prev = tree.nodes[n_i64].prev_drainable;
    let next = tree.nodes[n_i64].next_drainable;

    if prev >= 0 {
        tree.nodes[prev as i64].next_drainable = next;
    }
    if next >= 0 {
        tree.nodes[next as i64].prev_drainable = prev;
    }
    if tree.drainable_head == node_idx {
        tree.drainable_head = next;
    }
    tree.nodes[n_i64].prev_drainable = -1;
    tree.nodes[n_i64].next_drainable = -1;
}

fn link_drainable_head(tree: realtime::TopicTree&, cur: i32, c_i64: i64) {
    tree.nodes[c_i64].next_drainable = tree.drainable_head;
    tree.nodes[c_i64].prev_drainable = -1;
    if tree.drainable_head >= 0 {
        tree.nodes[tree.drainable_head as i64].prev_drainable = cur;
    }
    tree.drainable_head = cur;
}

fn migrate_drainable_queue_if_subscribed(
    tree:    realtime::TopicTree&,
    cur:     i32,
    cur_i64: i64,
    fd:      i64,
) {
    let count = tree.nodes[cur_i64].num_message_indices;
    unlink_drainable_node(tree, cur);
    tree.nodes[cur_i64].num_message_indices = 0;
    for i in tree.nodes.len {
        if i != cur_i64 && tree.nodes[i].in_use && tree.nodes[i].sock_fd == fd &&
            tree.nodes[i].num_message_indices == 0 {
            for m in count as i64 {
                tree.nodes[i].message_indices[m] = tree.nodes[cur_i64].message_indices[m];
            }
            tree.nodes[i].num_message_indices = count;
            link_drainable_head(tree, i as i32, i);
            return;
        }
    }
}

fn release_subscription_node(
    tree: realtime::TopicTree&,
    b:    i64,
    prev: i32,
    cur:  i32,
) -> i32, i32 {
    let cur_i64 = cur as i64;
    let fd = tree.nodes[cur_i64].sock_fd;
    let next = tree.nodes[cur_i64].next_sub;
    if prev < 0 {
        tree.buckets[b].head_sub = next;
    } else {
        tree.nodes[prev as i64].next_sub = next;
    }

    if tree.nodes[cur_i64].num_message_indices > 0 {
        migrate_drainable_queue_if_subscribed(tree, cur, cur_i64, fd);
    }

    tree.nodes[cur_i64].in_use = false;
    tree.nodes[cur_i64].sock_fd = -1;
    tree.nodes[cur_i64].next_sub = -1;

    let old_cnt = tree.buckets[b].subscriber_count;
    tree.buckets[b].subscriber_count = old_cnt - 1;
    tree.active_subscriptions -= 1;
    return next, old_cnt;
}

fn reclaim_empty_bucket(tree: realtime::TopicTree&, b: i64) {
    if tree.buckets[b].subscriber_count <= 0 {
        tree.buckets[b].in_use = false;
        tree.buckets[b].head_sub = -1;
        tree.active_buckets -= 1;
    }
}

inline fn hash_fd_bucket(fd: i64) -> u64 {
    let u = fd as u64;
    return (u ^ (u >> 8)) & 255;
}

inline fn record_publish_stats(tree: realtime::TopicTree&, delivered: i64) {
    tree.total_publishes += 1;
    tree.total_messages_delivered += (delivered as u64);
}

fn flush_node_palette_messages(
    tree:  const realtime::TopicTree&,
    n_i64: i64,
    fd:    i64,
    count: i64,
) -> i64 {
    var sent_total: i64 = 0;
    for i in count {
        let msg_idx = tree.nodes[n_i64].message_indices[i] as i64;
        if msg_idx >= 0 && msg_idx < tree.palette_len {
            let sent = net::tcp_send(fd, tree.palette[msg_idx].wire[..]);
            if sent > 0 {
                sent_total += 1;
            }
        }
    }
    return sent_total;
}

fn check_and_mark_batch_seen(
    fd:        i64,
    seen_fds:  i64[..512]&,
    seen_mask: u64[4]&,
) -> BatchSeenResult {
    guard fd > 0 else { return BatchSeenResult.CapacityExceeded; }
    let h = hash_fd_bucket(fd);
    let word_idx = (h >> 6) as i64;
    let bit = (1 as u64) << (h & 63);

    if (seen_mask[word_idx] & bit) == 0 {
        guard seen_fds.try_push(fd) else { return BatchSeenResult.CapacityExceeded; }
        seen_mask[word_idx] |= bit;
        return BatchSeenResult.Added;
    }

    for s_fd in seen_fds {
        if s_fd == fd {
            return BatchSeenResult.AlreadySeen;
        }
    }
    guard seen_fds.try_push(fd) else { return BatchSeenResult.CapacityExceeded; }
    return BatchSeenResult.Added;
}

fn find_drainable_node_for_fd(
    tree:     const realtime::TopicTree&,
    fd:       i64,
    fallback: i32,
) -> i32 {
    var d_cur = tree.drainable_head;
    while d_cur >= 0 {
        let d_i64 = d_cur as i64;
        let node .= tree.nodes[d_i64];
        if node.in_use && node.sock_fd == fd {
            return d_cur;
        }
        d_cur = node.next_drainable;
    }
    return fallback;
}

fn queue_subscriber_batch(
    tree:      realtime::TopicTree&,
    cur:       i32,
    msg_idx:   i64,
    sender_fd: i64,
    seen_fds:  i64[..512]&,
    seen_mask: u64[4]&,
) -> bool {
    let raw_i64 = cur as i64;
    guard tree.nodes[raw_i64].in_use && tree.nodes[raw_i64].sock_fd != sender_fd else { return false; }
    let fd = tree.nodes[raw_i64].sock_fd;

    let seen_res = check_and_mark_batch_seen(fd, seen_fds, seen_mask);
    guard seen_res != BatchSeenResult.CapacityExceeded else { return false; }
    var already_queued = seen_res == BatchSeenResult.AlreadySeen;

    let target_node = find_drainable_node_for_fd(tree, fd, cur);
    let c_i64 = target_node as i64;
    let num = tree.nodes[c_i64].num_message_indices as i64;
    if num > 0 {
        if tree.nodes[c_i64].message_indices[num - 1] == (msg_idx as u16) {
            already_queued = true;
        }
    }

    guard !already_queued else { return false; }

    if tree.nodes[c_i64].num_message_indices >= 32 {
        tree.drain_subscriber(target_node);
    }

    let cur_num = tree.nodes[c_i64].num_message_indices as i64;
    tree.nodes[c_i64].message_indices[cur_num] = msg_idx as u16;
    tree.nodes[c_i64].num_message_indices += 1;

    if tree.nodes[c_i64].num_message_indices == 1 {
        link_drainable_head(tree, target_node, c_i64);
    }
    return true;
}

inline fn find_retained_slot_for_topic(
    tree:  const realtime::TopicTree&,
    topic: const u8[:],
) -> i64 {
    var free_slot: i64 = -1;
    for i in tree.retained.len {
        let entry .= tree.retained[i];
        if entry.active && entry.topic[..] == topic {
            return i;
        }
        if !entry.active && free_slot < 0 {
            free_slot = i;
        }
    }
    return free_slot;
}

inline fn enqueue_retained_to_subscriber(
    tree:      realtime::TopicTree&,
    sub_fd:    i64,
    payload:   const u8[:],
    is_binary: bool,
) {
    var node_idx: i32 = -1;
    for &n_entry, i in tree.nodes {
        if n_entry.in_use && n_entry.sock_fd == sub_fd {
            node_idx = i as i32;
            break;
        }
    }
    guard node_idx >= 0 else { return; }

    if tree.palette_len >= (tree.palette.cap as i32) {
        tree.drain();
    }

    let msg_idx = tree.palette_len as i64;
    tree.palette[msg_idx].wire.clear();
    let opcode = if is_binary { rfc::WS_OPCODE_BINARY } else { rfc::WS_OPCODE_TEXT };
    let no_mask: u8[4] = [0, 0, 0, 0];
    realtime::encode_ws_frame(tree.palette[msg_idx].wire, opcode, payload, false, no_mask, true);
    tree.palette_len = (core::add_sat_i64(msg_idx, 1)) as i32;

    var seen_fds:  i64[..512] = [];
    var seen_mask: u64[4]     = [0, 0, 0, 0];
    let _ = queue_subscriber_batch(tree, node_idx, msg_idx, -1, seen_fds, seen_mask);
}

// ---- WebTransport Internal Helpers (draft-16 & RFC 9000) -----------------

struct WebTransportDemuxHeader {
    kind:       realtime::WebTransportStreamKind = realtime::WebTransportStreamKind.Unknown,
    session_id: u64                              = 0,
    header_len: i64                              = 0,
}

fn write_varint<B>(out: B&, val: u64) {
    guard val <= 0x3FFFFFFFFFFFFFFF else { return; }
    if val <= 63 {
        out.push(val as u8);
    } else if val <= 16383 {
        out.push((0x40 | ((val >> 8) & 0x3F)) as u8);
        out.push((val & 0xFF) as u8);
    } else if val <= 1073741823 {
        out.push((0x80 | ((val >> 24) & 0x3F)) as u8);
        out.push(((val >> 16) & 0xFF) as u8);
        out.push(((val >> 8) & 0xFF) as u8);
        out.push((val & 0xFF) as u8);
    } else {
        out.push((0xC0 | ((val >> 56) & 0x3F)) as u8);
        out.push(((val >> 48) & 0xFF) as u8);
        out.push(((val >> 40) & 0xFF) as u8);
        out.push(((val >> 32) & 0xFF) as u8);
        out.push(((val >> 24) & 0xFF) as u8);
        out.push(((val >> 16) & 0xFF) as u8);
        out.push(((val >> 8) & 0xFF) as u8);
        out.push((val & 0xFF) as u8);
    }
}

// RFC 9000 Section 2.1: Stream Types and Identifiers - Client-initiated bidirectional stream IDs have low bits 0x00.
inline fn is_valid_webtransport_session_id(session_id: u64) -> bool {
    return session_id <= rfc::QUIC_VARINT_MAX && (session_id & 0x03) == 0;
}

// draft-ietf-webtrans-overview Section 4.2: Bidirectional Streams - WebTransport Stream Header Demux
// Demuxes a WebTransport stream header from incoming QUIC stream wire bytes.
//
// Example:
//   wire = [0x40, 0x54, 0x10], is_bidi = false
//   returns: WebTransportDemuxHeader { kind: Unidirectional, session_id: 16, header_len: 3 }, ok = true
fn demux_webtransport_stream_header(
    wire:    const u8[:],
    is_bidi: bool,
) -> WebTransportDemuxHeader, bool {
    if is_bidi {
        let bidi, ok = realtime::decode_webtransport_bidi_stream_header(wire);
        guard ok else { return WebTransportDemuxHeader { .. }, false; }
        return WebTransportDemuxHeader {
            kind:       realtime::WebTransportStreamKind.Bidirectional,
            session_id: bidi.session_id,
            header_len: bidi.header_len,
        }, true;
    }

    let uni, ok = realtime::decode_webtransport_uni_stream_header(wire);
    guard ok else { return WebTransportDemuxHeader { .. }, false; }
    return WebTransportDemuxHeader {
        kind:       realtime::WebTransportStreamKind.Unidirectional,
        session_id: uni.session_id,
        header_len: uni.header_len,
    }, true;
}

fn find_stream_route_index(demuxer: const realtime::WebTransportDemuxer&, stream_id: u64) -> i64, bool {
    for &r, i in demuxer.streams {
        if r.stream_id == stream_id && r.is_open {
            return i, true;
        }
    }
    return -1, false;
}

fn find_session_entry_index(demuxer: const realtime::WebTransportDemuxer&, session_id: u64) -> i64, bool {
    for &s, i in demuxer.sessions {
        if s.session_id == session_id {
            return i, true;
        }
    }
    return -1, false;
}

fn close_session_streams(demuxer: realtime::WebTransportDemuxer&, session_id: u64) {
    for &r in demuxer.streams {
        if r.session_id == session_id {
            r.is_open = false;
        }
    }
}

inline fn is_session_routable(state: realtime::WebTransportSessionState) -> bool {
    return state == realtime::WebTransportSessionState.Active ||
           state == realtime::WebTransportSessionState.Draining;
}

fn record_new_stream_route(
    demuxer:         realtime::WebTransportDemuxer&,
    stream_id:       u64,
    session_id:      u64,
    kind:            realtime::WebTransportStreamKind,
    bytes_delivered: u64,
) -> bool {
    let route = realtime::WebTransportStreamRoute {
        stream_id:       stream_id,
        session_id:      session_id,
        kind:            kind,
        is_open:         true,
        bytes_delivered: bytes_delivered,
    };
    for &r in demuxer.streams {
        if !r.is_open {
            r = route;
            return true;
        }
    }
    return demuxer.streams.try_push(route);
}

fn route_existing_stream(
    demuxer:   realtime::WebTransportDemuxer&,
    route_idx: i64,
    wire:      const u8[:],
    fin:       bool,
    out:       realtime::WebTransportStreamPayload&,
) -> bool {
    guard route_idx >= 0 && route_idx < demuxer.streams.len else { return false; }
    let route .= demuxer.streams[route_idx];
    let sid = route.session_id;

    let s_idx, has_session = find_session_entry_index(demuxer, sid);
    guard has_session && s_idx >= 0 && s_idx < demuxer.sessions.len else {
        demuxer.dropped_frames = core::add_sat_u64(demuxer.dropped_frames, 1);
        return false;
    }

    let sess .= demuxer.sessions[s_idx];
    guard is_session_routable(sess.state) else {
        demuxer.dropped_frames = core::add_sat_u64(demuxer.dropped_frames, 1);
        return false;
    }

    sess.frames_received = core::add_sat_u64(sess.frames_received, 1);
    if fin {
        route.is_open = false;
    }

    out.kind = route.kind;
    out.stream_id = route.stream_id;
    out.session_id = sid;
    out.payload = wire;
    out.fin = fin;

    sess.bytes_received = core::add_sat_u64(sess.bytes_received, wire.len as u64);
    route.bytes_delivered = core::add_sat_u64(route.bytes_delivered, wire.len as u64);
    demuxer.total_dispatched = core::add_sat_u64(demuxer.total_dispatched, 1);
    return true;
}

fn route_new_stream(
    demuxer:   realtime::WebTransportDemuxer&,
    stream_id: u64,
    wire:      const u8[:],
    fin:       bool,
    out:       realtime::WebTransportStreamPayload&,
) -> bool {
    let is_bidi = (stream_id & 0x02) == 0;
    let hdr, ok_hdr = demux_webtransport_stream_header(wire, is_bidi);
    guard ok_hdr else {
        demuxer.dropped_frames = core::add_sat_u64(demuxer.dropped_frames, 1);
        return false;
    }

    let s_idx, has_session = find_session_entry_index(demuxer, hdr.session_id);
    guard has_session && s_idx >= 0 && s_idx < demuxer.sessions.len else {
        demuxer.dropped_frames = core::add_sat_u64(demuxer.dropped_frames, 1);
        return false;
    }

    let sess .= demuxer.sessions[s_idx];
    guard sess.state == realtime::WebTransportSessionState.Active else {
        demuxer.dropped_frames = core::add_sat_u64(demuxer.dropped_frames, 1);
        return false;
    }

    guard hdr.header_len >= 0 && hdr.header_len <= wire.len else { return false; }
    let payload = wire[hdr.header_len..];

    if !fin {
        guard record_new_stream_route(demuxer, stream_id, hdr.session_id, hdr.kind, payload.len as u64) else {
            demuxer.dropped_frames = core::add_sat_u64(demuxer.dropped_frames, 1);
            return false;
        }
    }

    sess.streams_count = core::add_sat_u32(sess.streams_count, 1);
    sess.frames_received = core::add_sat_u64(sess.frames_received, 1);
    sess.bytes_received = core::add_sat_u64(sess.bytes_received, payload.len as u64);

    out.kind = hdr.kind;
    out.stream_id = stream_id;
    out.session_id = hdr.session_id;
    out.payload = payload;
    out.fin = fin;

    demuxer.total_dispatched = core::add_sat_u64(demuxer.total_dispatched, 1);
    return true;
}
