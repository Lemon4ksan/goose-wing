// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Live RFC 6455 WebSocket transport (`WsConn`) over TCP or TLS 1.3 `net::Transport`.
namespace realtime;

import std;
import os;
import core;
import rfc.ws;
import net.transport;
import .ws_handshake;
import .websocket;

const WS_LIVE_MAX_RX_WIRE_BYTES: i64 = 131072;
const WS_LIVE_MAX_CTRL_FRAMES:   u64 = 16;
const WS_LIVE_HEAD_MAX_BYTES:    i64 = 8192;

// Live RFC 6455 WebSocket connection owning a `net::Transport` (TCP or TLS 1.3) and frame state.
struct WsConn {
    tr:                     net::Transport   = net::Transport.Disconnected,
    ws:                     WebSocketSession = new_websocket_session(true),
    negotiated_subprotocol: u8[..64]         = [],
    open:                   bool             = false,
    rx_buf:                 u8[>..]          = [],
}

// Writes all bytes of `data` to `t`, looping on partial writes until completion or transport error.
fn send_all_transport(t: net::Transport, data: const u8[:]) -> bool {
    var off: i64 = 0;
    while off < data.len {
        let n = t.send(data[off..]);
        guard n > 0 else { return false; }
        off = core::add_sat_i64(off, n);
    }
    return true;
}

// Reads HTTP/1.1 headers up to `\r\n\r\n` into `out_head`, saving trailing bytes in `out_leftover`.
//
// Example:
//   wire = "HTTP/1.1 101 Switching Protocols\r\n...\r\n\r\n<frame>"
//   returns: true, out_head = "HTTP/1.1 101 ...", out_leftover = "<frame>"
fn read_http1_head(
    t:            net::Transport,
    out_head:     u8[..8192]&,
    out_leftover: u8[>..]&,
    timeout_ms:   u32,
) -> bool {
    out_head.clear();
    out_leftover.clear();
    var raw: u8[>..]  = [];
    var buf: u8[1024] = [0; 1024];

    while raw.len < WS_LIVE_HEAD_MAX_BYTES {
        let n = t.recv_slice(buf[..], timeout_ms);
        guard n > 0 else { return false; }
        raw.append(buf[..n]);
        let end_idx = core::fast_find_crlfcrlf(raw[..]);
        if end_idx >= 0 {
            guard out_head.try_set(raw[..end_idx]) else { return false; }
            let trail_off = core::add_sat_i64(end_idx, 4);
            if trail_off < raw.len {
                out_leftover.append(raw[trail_off..]);
            }
            return true;
        }
    }
    return false;
}

// Parses the 3-digit HTTP/1.1 status code from a raw response header block.
//
// Example:
//   head = "HTTP/1.1 101 Switching Protocols\r\n..." -> returns (101, true)
fn parse_http1_status_code(head: const u8[:]) -> i32, bool {
    let first_line, _, has_nl = head.split_once("\r\n");
    let line = if has_nl { first_line } else { head };
    let after_ver, ok_sp = line.strip_prefix("HTTP/1.");
    guard ok_sp && after_ver.len >= 5 && after_ver[1] == ' ' else { return 0, false; }
    let code_val, ok_c = after_ver[2..5].parse_i32_dec();
    return code_val, ok_c;
}

// Scans raw CRLF-separated HTTP/1.1 headers for `name` (case-insensitive) and returns the first
// trimmed value together with total occurrence count (RFC 9110 Section 5.3).
//
// Example:
//   head = "HTTP/1.1 101...\r\nSec-WebSocket-Accept: abc=\r\n", name = "Sec-WebSocket-Accept"
//   returns: ("abc=", 1)
fn find_http1_header_counted(head: const u8[:], name: const u8[:]) -> const u8[:], i64 {
    var pos: i64 = 0;
    let first_nl = core::find_crlf(head);
    if first_nl >= 0 { pos = core::add_sat_i64(first_nl, 2); }

    var first_val = head[..0];
    var count: i64 = 0;
    while pos < head.len {
        let rel = core::find_crlf(head[pos..]);
        let end = if rel >= 0 { core::add_sat_i64(pos, rel) } else { head.len };
        let line = head[pos..end];
        let k, v, ok_col = line.split_once_byte(':');
        if ok_col && k.trim_lws().eq_ascii_fold(name) {
            if count == 0 { first_val = v.trim_lws(); }
            count = core::add_sat_i64(count, 1);
        }
        if rel < 0 { break; }
        pos = core::add_sat_i64(end, 2);
    }
    return first_val, count;
}

fn header_value_contains_token(val: const u8[:], token: const u8[:]) -> bool {
    var tok = core::make_byte_tokenizer(val, ',');
    while true {
        let part, has_part = core::token_next(tok);
        if !has_part { return false; }
        if part.trim_lws().eq_ascii_fold(token) { return true; }
    }
    return false;
}

// Checks whether a comma-separated HTTP/1.1 header contains `token` (case-insensitive).
//
// Example:
//   head = "...\r\nConnection: keep-alive, Upgrade\r\n", name = "Connection", token = "upgrade" -> true
fn http1_head_has_token(head: const u8[:], name: const u8[:], token: const u8[:]) -> bool {
    var pos: i64 = 0;
    let first_nl = core::find_crlf(head);
    if first_nl >= 0 { pos = core::add_sat_i64(first_nl, 2); }

    while pos < head.len {
        let rel = core::find_crlf(head[pos..]);
        let end = if rel >= 0 { core::add_sat_i64(pos, rel) } else { head.len };
        let k, v, ok_col = head[pos..end].split_once_byte(':');
        if ok_col && k.trim_lws().eq_ascii_fold(name) && header_value_contains_token(v, token) {
            return true;
        }
        if rel < 0 { break; }
        pos = core::add_sat_i64(end, 2);
    }
    return false;
}

fn ws_reset_conn(conn: WsConn&) {
    if conn.open || net::is_connected(conn.tr) {
        conn.tr.close();
    }
    conn.tr = net::Transport.Disconnected;
    conn.ws = new_websocket_session(true);
    conn.negotiated_subprotocol.clear();
    conn.open = false;
    conn.rx_buf.clear();
}

fn is_valid_ws_upgrade_req_line(req_head: const u8[:]) -> bool {
    let first_line, _, has_nl = req_head.split_once("\r\n");
    guard has_nl else { return false; }
    let rest, is_get = first_line.strip_prefix("GET ");
    guard is_get else { return false; }
    let target, proto, ok_sp = rest.split_once_byte(' ');
    return ok_sp && target.len > 0 && target[0] == '/' && proto == "HTTP/1.1";
}

fn validate_ws_upgrade_headers(req_head: const u8[:]) -> const u8[:], bool {
    guard is_valid_ws_upgrade_req_line(req_head) else { return "", false; }
    let host_val, host_cnt = find_http1_header_counted(req_head, "Host");
    let ver, ver_cnt = find_http1_header_counted(req_head, "Sec-WebSocket-Version");
    let key, key_cnt = find_http1_header_counted(req_head, "Sec-WebSocket-Key");
    guard host_cnt >= 1 && host_val.len > 0 && ver_cnt == 1 && ver == "13" else { return "", false; }
    guard http1_head_has_token(req_head, "Upgrade", "websocket") &&
        http1_head_has_token(req_head, "Connection", "upgrade") else {
        return "", false;
    }
    guard key_cnt == 1 && is_valid_websocket_key(key) else { return "", false; }
    return key, true;
}

// Completes a server-side RFC 6455 handshake on a connected TCP or TLS 1.3 `net::Transport`.
// Transfers ownership of `t` into `conn` on `true`; leaves `t` untouched on `false`.
//
// Example:
//   ws_accept_transport(conn, tr, "GET /ws HTTP/1.1\r\nHost: h\r\nUpgrade: websocket\r\n...", "")
//   returns: true (after writing 101 Switching Protocols)
fn ws_accept_transport(
    conn:        WsConn&,
    t:           net::Transport,
    req_head:    const u8[:],
    leftover:    const u8[:] = "",
    subprotocol: const u8[:] = "",
) -> bool {
    ws_reset_conn(conn);
    let key, ok_hdrs = validate_ws_upgrade_headers(req_head);
    guard ok_hdrs else { return false; }

    var accept_key: u8[..64] = [];
    compute_websocket_accept(key, accept_key);
    guard accept_key.len == 28 else { return false; }

    var neg_proto: u8[..64]  = [];
    var resp:      u8[..512] = [];
    guard resp.try_append("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\n") &&
        resp.try_append("Connection: Upgrade\r\nSec-WebSocket-Accept: ") &&
        resp.try_append(accept_key[..]) else {
        return false;
    }
    if subprotocol.len > 0 {
        let offered, off_cnt = find_http1_header_counted(req_head, "Sec-WebSocket-Protocol");
        if off_cnt >= 1 && has_subprotocol_token(offered, subprotocol) {
            guard neg_proto.try_set(subprotocol) &&
                resp.try_append("\r\nSec-WebSocket-Protocol: ") &&
                resp.try_append(subprotocol) else {
                return false;
            }
        }
    }
    guard resp.try_append("\r\n\r\n") && send_all_transport(t, resp[..]) else { return false; }

    conn.tr = t;
    conn.ws = new_websocket_session(false);
    if neg_proto.len > 0 {
        let _ = conn.negotiated_subprotocol.try_set(neg_proto[..]);
        let _ = conn.ws.subprotocol.try_set(neg_proto[..]);
    }
    if leftover.len > 0 { conn.rx_buf.append(leftover); }
    conn.open = true;
    return true;
}

// Sends an RFC 6455 UTF-8 text frame over `conn`.
fn ws_send_text(conn: WsConn&, text: const u8[:]) -> bool {
    guard conn.open && !conn.ws.is_closed else { return false; }
    if text.len <= 4000 {
        var wire_stack: u8[..4096] = [];
        send_text(conn.ws, text, wire_stack);
        guard wire_stack.len > 0 else { return false; }
        return send_all_transport(conn.tr, wire_stack[..]);
    }
    var wire_out: u8[>..] = [];
    send_text(conn.ws, text, wire_out);
    guard wire_out.len > 0 else { return false; }
    return send_all_transport(conn.tr, wire_out[..]);
}

// Sends an RFC 6455 binary frame over `conn`.
fn ws_send_binary(conn: WsConn&, data: const u8[:]) -> bool {
    guard conn.open && !conn.ws.is_closed else { return false; }
    if data.len <= 4000 {
        var wire_stack: u8[..4096] = [];
        send_binary(conn.ws, data, wire_stack);
        guard wire_stack.len > 0 else { return false; }
        return send_all_transport(conn.tr, wire_stack[..]);
    }
    var wire_out: u8[>..] = [];
    send_binary(conn.ws, data, wire_out);
    guard wire_out.len > 0 else { return false; }
    return send_all_transport(conn.tr, wire_out[..]);
}

// Sends an RFC 6455 Ping control frame over `conn`.
fn ws_send_ping(conn: WsConn&, payload: const u8[:]) -> bool {
    guard conn.open && !conn.ws.is_closed else { return false; }
    var wire_out: u8[..256] = [];
    send_ping(conn.ws, payload, wire_out);
    guard wire_out.len > 0 else { return false; }
    return send_all_transport(conn.tr, wire_out[..]);
}

// Sends an RFC 6455 Close frame and closes the underlying transport.
fn ws_close(conn: WsConn&, status_code: u16 = 1000, reason: const u8[:] = "") {
    if conn.open && !conn.ws.is_closed {
        var wire_out: u8[..256] = [];
        close(conn.ws, status_code, reason, wire_out);
        if wire_out.len > 0 {
            let _ = send_all_transport(conn.tr, wire_out[..]);
        }
    }
    ws_reset_conn(conn);
}

inline fn is_clean_ws_close_code(code: u16) -> bool {
    return code == 0 || code == rfc::WS_STATUS_NORMAL ||
        code == rfc::WS_STATUS_GOING_AWAY || code == rfc::WS_STATUS_NO_STATUS;
}

inline fn is_ws_data_message(view: const WsMessageView&) -> bool {
    return view.is_valid &&
        (view.opcode == rfc::WS_OPCODE_TEXT || view.opcode == rfc::WS_OPCODE_BINARY);
}

// Attempts to consume one buffered RFC 6455 frame from `conn.rx_buf`.
// Returns: `1` = data frame populated, `0` = clean close, `-1` = protocol error,
// `2` = control frame handled (keep reading), `-3` = need more bytes.
fn try_consume_buffered_ws_frame(
    conn:        WsConn&,
    out_opcode:  u8&,
    out_payload: u8[>..]&,
    reply:       u8[..256]&,
) -> i32 {
    guard conn.rx_buf.len >= 2 else { return -3; }
    reply.clear();
    var view = WsMessageView { .. };
    let consumed, handled = consume_frame_view(conn.ws, conn.rx_buf[..], view, reply);
    guard handled && consumed > 0 else { return -3; }

    if reply.len > 0 { let _ = send_all_transport(conn.tr, reply[..]); }
    let is_data = is_ws_data_message(view);
    if is_data {
        out_opcode = view.opcode;
        out_payload.append(view.payload);
    }
    conn.rx_buf.compact_wire_buffer(consumed);
    if conn.ws.is_closed {
        conn.open = false;
        if is_data { return 1; }
        return if is_clean_ws_close_code(conn.ws.close_code) { 0 } else { -1 };
    }
    return if is_data { 1 } else { 2 };
}

// crap:ignore
fn calc_remaining_deadline_ms(start_ns: i64, timeout_ms: u32) -> u32, bool {
    if timeout_ms == 0 { return 0, true; }
    let budget_ns = core::mul_sat_u64(timeout_ms, 1000000);
    let elapsed_ns = max(0, core::sub_sat_i64(time_ns(), start_ns)) as u64;
    guard elapsed_ns < budget_ns else { return 0, false; }
    let rem_ns = core::sub_sat_u64(budget_ns, elapsed_ns);
    let rem_ms = min(max(1, core::add_sat_u64(rem_ns, 999999) / 1000000), timeout_ms);
    return rem_ms as u32, true;
}

fn read_ws_wire_chunk(conn: WsConn&, chunk: u8[4096]&, rem_ms: u32) -> i32 {
    let n = conn.tr.recv_slice(chunk[..], rem_ms);
    if n > 0 {
        if core::add_sat_i64(conn.rx_buf.len, n) > WS_LIVE_MAX_RX_WIRE_BYTES {
            ws_close(conn, rfc::WS_STATUS_MESSAGE_TOO_BIG, "rx limit");
            return -1;
        }
        conn.rx_buf.append(chunk[..n]);
        return 1;
    }
    if n == -2 { return -2; }
    conn.open = false;
    return if n == 0 { 0 } else { -1 };
}

// Receives the next TEXT or BINARY message (auto-replying to Ping and echoing Close).
// Enforces a bounded `timeout_ms` deadline across control frames to resist ping floods.
// Returns: `1` = message ready, `0` = clean close/EOF, `-2` = timeout, `-1` = error.
fn ws_recv_frame(
    conn:        WsConn&,
    out_opcode:  u8&,
    out_payload: u8[>..]&,
    timeout_ms:  u32 = 10000,
) -> i32 {
    out_opcode = 0;
    out_payload.clear();
    guard conn.open else { return 0; }

    let start_ns = time_ns();
    var ctrl_frames: u64       = 0;
    var reply:       u8[..256] = [];
    var chunk:       u8[4096]  = [0; 4096];

    while true {
        let step = try_consume_buffered_ws_frame(conn, out_opcode, out_payload, reply);
        if step == 1 || step == 0 || step == -1 { return step; }
        if step == 2 {
            ctrl_frames = core::add_sat_u64(ctrl_frames, 1);
            guard ctrl_frames < WS_LIVE_MAX_CTRL_FRAMES else { return -2; }
            continue;
        }
        let rem_ms, has_budget = calc_remaining_deadline_ms(start_ns, timeout_ms);
        guard has_budget else { return -2; }
        let rd = read_ws_wire_chunk(conn, chunk, rem_ms);
        if rd != 1 { return rd; }
    }
    return -1;
}
