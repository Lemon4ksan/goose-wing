// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for WebSocket PMD sessions, RFC 7692 permessage-deflate, and handshakes.
namespace realtime_internal;

import std;
import core;
import rfc.http;
import rfc.h2;
import rfc.ws;
import security.cors;
import http.headers;
import http.request;
import http.response;
import net.tcp;
import .internal;
import .websocket;
import .ws_deflate;
import .ws_handshake;

root struct WsPmdSessionState {
    rx_history:   u8[..32768] = [],
    tx_history:   u8[..32768] = [],
    rx_comp_buf:  u8[>..]     = [],
    rx_plain_buf: u8[>..]     = [],
    tx_comp_buf:  u8[>..]     = [],
}

inline fn pmd_window_bits_to_bytes(bits: u8) -> i64 {
    let clamped = max(8, min(bits as i64, 15)) as u32;
    return core::shl_sat_u64(1, clamped) as i64;
}

fn update_pmd_window_history(hist: u8[..32768]&, raw: const u8[:], win_bytes: i64) {
    let cap_win = max(256, min(win_bytes, 32768));
    guard raw.len > 0 else { return; }
    if raw.len >= cap_win {
        let _ = hist.try_set(raw[core::sub_sat_i64(raw.len, cap_win)..]);
        return;
    }
    let keep = core::sub_sat_i64(cap_win, raw.len);
    if hist.len > keep {
        let drop_n = core::sub_sat_i64(hist.len, keep);
        hist.compact_wire_buffer(drop_n);
    }
    let _ = hist.try_append(raw);
}

fn inflate_ws_pmd_frame(
    ws:      const realtime::WebSocketSession&,
    payload: const u8[:],
    pmd:     WsPmdSessionState&,
    max_pay: i64,
) -> core::CompressError {
    pmd.rx_plain_buf.clear();
    pmd.rx_comp_buf.clear();
    guard payload.len > 0 && max_pay > 0 else { return core::CompressError.CorruptedBitstream; }

    let tail: u8[6] = [0x00, 0x00, 0xFF, 0xFF, 0x03, 0x00];
    pmd.rx_comp_buf.append(payload);
    pmd.rx_comp_buf.append(tail[..]);

    let rx_bits = if ws.is_client { ws.server_max_window_bits } else { ws.client_max_window_bits };
    let rx_win = pmd_window_bits_to_bytes(rx_bits);
    let reset_rx = realtime::ws_should_reset_decompressor(ws);
    let dict = if reset_rx { "" } else { pmd.rx_history[..] };

    let err, _ = core::inflate_ex(pmd.rx_comp_buf[..], pmd.rx_plain_buf, dict, max_pay, rx_win);
    if err != core::CompressError.None {
        pmd.rx_plain_buf.clear();
        guard err != core::CompressError.OutputBufferOverflow else {
            return core::CompressError.OutputBufferOverflow;
        }
        let err_raw, _ = core::inflate_ex(payload, pmd.rx_plain_buf, dict, max_pay, rx_win);
        guard err_raw == core::CompressError.None else { return err_raw; }
    }

    if reset_rx {
        pmd.rx_history.clear();
    } else {
        update_pmd_window_history(pmd.rx_history, pmd.rx_plain_buf[..], rx_win);
    }
    return core::CompressError.None;
}

fn send_ws_pmd_echo<OutBuf>(
    ws:       realtime::WebSocketSession&,
    opcode:   u8,
    plain:    const u8[:],
    pmd:      WsPmdSessionState&,
    out_wire: OutBuf&,
) -> bool {
    guard ws.permessage_deflate && !ws.is_closed && !ws.close_sent && !ws.close_received else {
        return false;
    }
    let tx_bits = if ws.is_client { ws.client_max_window_bits } else { ws.server_max_window_bits };
    let tx_win = pmd_window_bits_to_bytes(tx_bits);
    let reset_tx = realtime::ws_should_reset_compressor(ws);
    let dict = if reset_tx { "" } else { pmd.tx_history[..] };
    pmd.tx_comp_buf.clear();
    guard core::deflate_sync_flush_with_dict(plain, pmd.tx_comp_buf, 4, dict, tx_win) else {
        return false;
    }
    let eff_len = strip_pmd_sync_flush_tail(pmd.tx_comp_buf[..]);
    guard eff_len > 0 else { return false; }

    let mask, ok_mask = ws_next_mask_key(ws);
    guard ok_mask else { return false; }
    realtime::encode_ws_frame_compressed(out_wire, opcode, pmd.tx_comp_buf[..eff_len], ws.is_client, mask, true);
    if reset_tx {
        pmd.tx_history.clear();
    } else {
        update_pmd_window_history(pmd.tx_history, plain, tx_win);
    }
    return true;
}

fn dispatch_ws_data_turn<Stage, OutBuf, ReplyBuf>(
    conn_fd:  i64,
    ws:       realtime::WebSocketSession&,
    stage:    Stage&,
    view:     const realtime::WsMessageView&,
    pmd:      WsPmdSessionState&,
    out_wire: OutBuf&,
    reply:    ReplyBuf&,
) {
    reply.clear();
    out_wire.clear();
    if !view.is_compressed {
        if !ws.permessage_deflate || !send_ws_pmd_echo(ws, view.opcode, view.payload, pmd, out_wire) {
            on_ws_message(stage, ws, view, out_wire);
        }
        flush_ws_wire(conn_fd, out_wire[..]);
        return;
    }
    let raw_max = if ws.max_payload_length > 0 {
        min(ws.max_payload_length, 0x7FFFFFFFFFFFFFFF) as i64
    } else {
        16777216
    };
    let ratio_cap = max(1048576, core::mul_sat_i64(view.payload.len, 200));
    let max_pay = min(raw_max, ratio_cap);
    let inf_err = inflate_ws_pmd_frame(ws, view.payload, pmd, max_pay);
    if inf_err == core::CompressError.OutputBufferOverflow {
        ws.close(rfc::WS_STATUS_MESSAGE_TOO_BIG, "compressed message exceeds max payload", reply);
        flush_ws_wire(conn_fd, reply[..]);
        return;
    }
    if inf_err != core::CompressError.None {
        ws.close(rfc::WS_STATUS_PROTOCOL_ERROR, "invalid permessage-deflate stream", reply);
        flush_ws_wire(conn_fd, reply[..]);
        return;
    }
    if view.opcode == rfc::WS_OPCODE_TEXT && !pmd.rx_plain_buf[..].validate_utf8() {
        ws.close(rfc::WS_STATUS_INVALID_PAYLOAD, "invalid UTF-8 in compressed text frame", reply);
        flush_ws_wire(conn_fd, reply[..]);
        return;
    }
    let inflated_view = realtime::WsMessageView {
        opcode:        view.opcode,
        payload:       pmd.rx_plain_buf[..],
        is_valid:      true,
        is_compressed: false,
        ..
    };
    if !send_ws_pmd_echo(ws, inflated_view.opcode, inflated_view.payload, pmd, out_wire) {
        on_ws_message(stage, ws, inflated_view, out_wire);
    }
    flush_ws_wire(conn_fd, out_wire[..]);
}

fn drain_ws_session_frames_pmd<Stage, FragBuf, OutBuf>(
    conn_fd:  i64,
    ws:       realtime::WebSocketSession&,
    stage:    Stage&,
    in_slice: u8[:],
    frag_buf: FragBuf&,
    pmd:      WsPmdSessionState&,
    out_wire: OutBuf&,
) -> i64 {
    var cursor: i64        = 0;
    var reply:  u8[..1024] = [];
    let max_pay_i64 = min(ws.max_payload_length, 0x7FFFFFFFFFFFFFFF) as i64;
    let eff_frag_cap = if max_pay_i64 > 0 {
        min(ws_buf_cap(frag_buf), max_pay_i64)
    } else {
        ws_buf_cap(frag_buf)
    };
    while core::add_sat_i64(cursor, 2) <= in_slice.len && !ws.is_closed {
        reply.clear();
        let consumed, handled, view = consume_frame_view_into(
            ws, in_slice[cursor..], frag_buf, eff_frag_cap, reply,
        );
        if !handled || consumed <= 0 {
            break;
        }
        cursor = core::add_sat_i64(cursor, consumed);
        flush_ws_wire(conn_fd, reply[..]);
        if is_ws_data_message(view) {
            dispatch_ws_data_turn(conn_fd, ws, stage, view, pmd, out_wire, reply);
        }
        if ws.is_closed {
            ws_drain_and_close(conn_fd);
            break;
        }
    }
    return cursor;
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
    let last_idx = core::sub_sat_i64(quoted.len, 1);
    guard quoted.len >= 2 && quoted[0] == '"' && quoted[last_idx] == '"' else {
        return false;
    }
    let inner = quoted[1..last_idx];
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

// Parses a strict RFC 7692 Section 7.1 window_bits value (base-10 integer in 8..15, no leading '0' or '+').
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
        if b0 == '8' { return 8, true; }
        if b0 == '9' { return 9, true; }
        return 0, false;
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
            out_cfg.client_max_window_bits = max(8, capped);
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
        server_max_window_bits:     max(8, min(server_cfg.server_max_window_bits, rfc::WS_PMD_MAX_WINDOW_BITS)),
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

fn validate_ws_upgrade_headers(
    req:            const http::Request&,
    out_resp:       http::Response&,
    allowed_origin: const u8[:] = "",
) -> const u8[:], bool {
    guard req_has_ws_host_authority(req) &&
        req_has_header_token(req, "upgrade", "websocket") &&
        req_has_header_token(req, "connection", "upgrade") else {
        out_resp.status_code = rfc::STATUS_BAD_REQUEST;
        return "", false;
    }
    let origin_cnt = req_count_header(req, "origin");
    guard origin_cnt <= 1 else {
        out_resp.status_code = rfc::STATUS_BAD_REQUEST;
        return "", false;
    }
    if allowed_origin.len > 0 {
        let origin_val = req.headers.find_header("Origin").trim_lws();
        guard origin_cnt == 1 && security::match_cors_origin_pattern(origin_val, allowed_origin) else {
            out_resp.status_code = rfc::STATUS_FORBIDDEN;
            return "", false;
        }
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
    return rfc::is_connection_specific_header(name) || name.eq_ascii_fold("sec-websocket-key");
}

fn format_h2_websocket_response(res: http::Response&, subprotocol: const u8[:] = "") {
    res.status_code = rfc::STATUS_OK;
    if subprotocol.len > 0 {
        res.set_header("sec-websocket-protocol", subprotocol);
    }
}

// Consumes and dispatches all complete WebSocket frames currently buffered in `in_slice`.
// Returns the total number of bytes consumed from `in_slice`.
fn drain_ws_session_frames<Stage, FragBuf, OutBuf>(
    conn_fd:  i64,
    ws:       realtime::WebSocketSession&,
    stage:    Stage&,
    in_slice: u8[:],
    frag_buf: FragBuf&,
    out_wire: OutBuf&,
) -> i64 {
    var pmd = WsPmdSessionState { .. };
    return drain_ws_session_frames_pmd(
        conn_fd, ws, stage, in_slice, frag_buf, pmd, out_wire,
    );
}
