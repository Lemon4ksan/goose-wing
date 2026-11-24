// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Dedicated TCP server driving http2::H2EdgeSession for h2spec conformance testing (RFC 9113).
import std;
import wing from "../..";

const MAX_EDGE_CONNS:       i64 = 16;
const EDGE_CONN_IDLE_MS:    u64 = 1500;
const EDGE_CLOSE_LINGER_MS: u64 = 40;
const EDGE_POLL_WAIT_MS:    u32 = 5;

const ROUTE_NOT_FOUND: u8 = 0;
const ROUTE_ROOT_GET:  u8 = 1;
const ROUTE_ROOT_HEAD: u8 = 2;
const ROUTE_PING_GET:  u8 = 3;
const ROUTE_PING_HEAD: u8 = 4;
const ROUTE_PING_POST: u8 = 5;
const ROUTE_ECHO_POST: u8 = 6;
const ROUTE_SHUTDOWN:  u8 = 7;

const BODY_ROOT:        const u8[:] = "OK_H2SPEC_DATA";
const BODY_PING:        const u8[:] = "PONG_H2SPEC_DATA";
const BODY_SHUTDOWN:    const u8[:] = "BYE\n";
const H1_SHUTDOWN_RESP: const u8[:] =
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: 4\r\nConnection: close\r\n\r\nBYE\n";

struct EdgeConnSlot {
    active:      bool                 = false,
    closing:     bool                 = false,
    shutdown_wr: bool                 = false,
    h2_started:  bool                 = false,
    fd:          i64                  = -1,
    last_rx_ms:  u64                  = 0,
    close_at_ms: u64                  = 0,
    sess:        http2::H2EdgeSession = http2::H2EdgeSession { .. },
    tx_buf:      u8[..163840]         = [],
}

struct EdgeStreamState {
    active:       bool        = false,
    conn_idx:     i64         = -1,
    stream_id:    u32         = 0,
    route_kind:   u8          = ROUTE_NOT_FOUND,
    headers_sent: bool        = false,
    resp_off:     i64         = 0,
    data_buf:     u8[..65536] = [],
}

var g_running:  bool                 = true;
var g_conns:    EdgeConnSlot[16]     = [EdgeConnSlot { .. }; 16];
var g_streams:  EdgeStreamState[>..] = [];
var g_wire_out: u8[>..]              = [];

fn strip_query(raw_path: const u8[:]) -> const u8[:] {
    let head, _, found = raw_path.split_once_byte('?');
    if found { return head; }
    return raw_path;
}

fn classify_route(method: const u8[:], raw_path: const u8[:]) -> u8 {
    let path = strip_query(raw_path);
    if path == "/shutdown" { return ROUTE_SHUTDOWN; }
    if path == "/" {
        if method == "HEAD" { return ROUTE_ROOT_HEAD; }
        if method == "GET" { return ROUTE_ROOT_GET; }
        return ROUTE_NOT_FOUND;
    }
    if path == "/ping" {
        if method == "HEAD" { return ROUTE_PING_HEAD; }
        if method == "POST" { return ROUTE_PING_POST; }
        if method == "GET" { return ROUTE_PING_GET; }
        return ROUTE_NOT_FOUND;
    }
    if path == "/echo" && method == "POST" { return ROUTE_ECHO_POST; }
    return ROUTE_NOT_FOUND;
}

fn flush_slot_wire(slot: EdgeConnSlot&) -> bool {
    guard slot.h2_started else { return true; }
    g_wire_out.clear();
    let n = http2::h2_edge_drain_wire(slot.sess, g_wire_out);
    if n > 0 {
        guard slot.tx_buf.try_append(g_wire_out[..]) else {
            g_wire_out.clear();
            slot.tx_buf.clear();
            return false;
        }
    }
    g_wire_out.clear();
    guard slot.tx_buf.len > 0 else { return true; }

    var sent_off: i64 = 0;
    while sent_off < slot.tx_buf.len {
        let rc = net::tcp_send(slot.fd, slot.tx_buf[sent_off..]);
        if rc > 0 {
            sent_off = core::add_sat_i64(sent_off, rc);
        } else if rc == -2 {
            slot.tx_buf.compact_wire_buffer(sent_off);
            return true;
        } else {
            slot.tx_buf.clear();
            return false;
        }
    }
    slot.tx_buf.clear();
    return true;
}

fn free_conn_streams(conn_idx: i64) {
    for &st in g_streams {
        if st.active && st.conn_idx == conn_idx {
            st.active = false;
            st.data_buf.clear();
        }
    }
}

fn find_stream_slot(conn_idx: i64, stream_id: u32) -> i64 {
    for i in g_streams.len {
        if g_streams[i].active && g_streams[i].conn_idx == conn_idx && g_streams[i].stream_id == stream_id {
            return i;
        }
    }
    return -1;
}

fn alloc_stream_slot(conn_idx: i64, stream_id: u32, route_kind: u8) -> i64 {
    for i in g_streams.len {
        if !g_streams[i].active {
            g_streams[i] = EdgeStreamState {
                active:     true,
                conn_idx:   conn_idx,
                stream_id:  stream_id,
                route_kind: route_kind,
                ..
            };
            return i;
        }
    }
    let idx = g_streams.len;
    g_streams.push(EdgeStreamState {
        active:     true,
        conn_idx:   conn_idx,
        stream_id:  stream_id,
        route_kind: route_kind,
        ..
    });
    return idx;
}

fn route_static_body(route_kind: u8) -> i32, const u8[:], bool {
    if route_kind == ROUTE_ROOT_GET { return 200, BODY_ROOT, true; }
    if route_kind == ROUTE_ROOT_HEAD { return 200, BODY_ROOT, false; }
    if route_kind == ROUTE_PING_GET || route_kind == ROUTE_PING_POST { return 200, BODY_PING, true; }
    if route_kind == ROUTE_PING_HEAD { return 200, BODY_PING, false; }
    if route_kind == ROUTE_SHUTDOWN { return 200, BODY_SHUTDOWN, true; }
    return 404, "Not Found", true;
}

fn pump_stream_response(slot: EdgeConnSlot&, st: EdgeStreamState&) {
    guard st.active && st.headers_sent else { return; }
    let body = st.data_buf[..];
    if st.resp_off >= body.len {
        st.active = false;
        st.data_buf.clear();
        return;
    }
    let sent, ok = http2::h2_edge_send_data(slot.sess, st.stream_id, body[st.resp_off..], true);
    if !ok {
        st.active = false;
        st.data_buf.clear();
        return;
    }
    st.resp_off = core::add_sat_i64(st.resp_off, sent);
    if st.resp_off >= body.len {
        st.active = false;
        st.data_buf.clear();
    }
}

fn start_stream_response(slot: EdgeConnSlot&, st_idx: i64) {
    let st .= g_streams[st_idx];
    if st.route_kind == ROUTE_SHUTDOWN {
        g_running = false;
    }
    var status: i32 = 200;
    var send_body = true;
    if st.route_kind != ROUTE_ECHO_POST {
        let s, b, has_body = route_static_body(st.route_kind);
        status = s;
        send_body = has_body;
        let _ = st.data_buf.try_set(b);
    }

    var hdrs = http::HeaderMap { .. };
    http::set_header(hdrs, "content-type", "text/plain");
    var cl_buf: u8[..24] = [];
    let blen: i64 = st.data_buf.len;
    blen.format_i64_dec(cl_buf);
    http::set_header(hdrs, "content-length", cl_buf[..]);

    let hdr_only = !send_body;
    guard http2::h2_edge_send_headers(slot.sess, st.stream_id, status, hdrs, hdr_only) else {
        st.active = false;
        st.data_buf.clear();
        return;
    }
    st.headers_sent = true;
    st.resp_off = 0;
    if hdr_only {
        st.active = false;
        st.data_buf.clear();
        return;
    }
    if st.data_buf.len == 0 {
        let _, _ = http2::h2_edge_send_data(slot.sess, st.stream_id, "", true);
        st.active = false;
        return;
    }
    pump_stream_response(slot, st);
}

fn handle_edge_request_data(slot: EdgeConnSlot&, conn_idx: i64, stream_id: u32, chunk: const u8[:]) {
    let st_idx = find_stream_slot(conn_idx, stream_id);
    guard st_idx >= 0 && g_streams[st_idx].route_kind == ROUTE_ECHO_POST && chunk.len > 0 else {
        return;
    }
    if !g_streams[st_idx].data_buf.try_append(chunk) {
        let _ = http2::h2_edge_reset_stream(slot.sess, stream_id, rfc::H2_ERR_CANCEL);
        g_streams[st_idx].active = false;
        g_streams[st_idx].data_buf.clear();
    }
}

fn handle_edge_event(conn_idx: i64, slot: EdgeConnSlot&, ev: const http2::H2EdgeEvent&) {
    if ev.kind == http2::H2EdgeEventKind.RequestHead {
        let method = http::get_header(ev.headers, ":method");
        let path = http::get_header(ev.headers, ":path");
        let st_idx = alloc_stream_slot(conn_idx, ev.stream_id, classify_route(method, path));
        if ev.end_stream {
            start_stream_response(slot, st_idx);
        }
        return;
    }
    if ev.kind == http2::H2EdgeEventKind.RequestData {
        handle_edge_request_data(slot, conn_idx, ev.stream_id, ev.data);
        return;
    }
    if ev.kind == http2::H2EdgeEventKind.RequestEnd {
        let st_idx = find_stream_slot(conn_idx, ev.stream_id);
        if st_idx >= 0 {
            start_stream_response(slot, st_idx);
        }
        return;
    }
    if ev.kind == http2::H2EdgeEventKind.StreamReset {
        let st_idx = find_stream_slot(conn_idx, ev.stream_id);
        if st_idx >= 0 {
            g_streams[st_idx].active = false;
            g_streams[st_idx].data_buf.clear();
        }
    }
}

fn drain_conn_events(conn_idx: i64, slot: EdgeConnSlot&) {
    var ev = http2::H2EdgeEvent { .. };
    while http2::h2_edge_poll_event(slot.sess, ev) {
        handle_edge_event(conn_idx, slot, ev);
    }
    for &st in g_streams {
        if st.active && st.conn_idx == conn_idx && st.headers_sent {
            pump_stream_response(slot, st);
        }
    }
}

fn begin_conn_linger_close(conn_idx: i64, slot: EdgeConnSlot&, now_ms: u64) {
    let _ = flush_slot_wire(slot);
    if slot.tx_buf.len == 0 && !slot.shutdown_wr {
        let _ = net::tcp_shutdown(slot.fd, net::SHUT_WR);
        slot.shutdown_wr = true;
    }
    slot.closing = true;
    slot.close_at_ms = core::add_sat_u64(now_ms, EDGE_CLOSE_LINGER_MS);
    free_conn_streams(conn_idx);
}

fn close_conn_slot(conn_idx: i64, slot: EdgeConnSlot&) {
    guard slot.active else { return; }
    free_conn_streams(conn_idx);
    if slot.h2_started {
        http2::h2_edge_close(slot.sess);
    }
    if slot.fd > 0 {
        net::tcp_close(slot.fd);
    }
    slot = EdgeConnSlot { .. };
}

fn open_conn_slot(fd: i64, now_ms: u64) -> bool {
    for i in MAX_EDGE_CONNS {
        if !g_conns[i].active {
            let _ = net::tcp_set_nodelay(fd, true);
            let _ = net::tcp_set_nonblocking(fd, true);
            g_conns[i] = EdgeConnSlot {
                active:     true,
                fd:         fd,
                last_rx_ms: now_ms,
                ..
            };
            return true;
        }
    }
    return false;
}

fn count_active_conns() -> i64 {
    var cnt: i64 = 0;
    for i in MAX_EDGE_CONNS {
        if g_conns[i].active { cnt = core::add_sat_i64(cnt, 1); }
    }
    return cnt;
}

fn handle_h1_shutdown_if_matched(conn_idx: i64, slot: EdgeConnSlot&, chunk: const u8[:], now_ms: u64) -> bool {
    guard !slot.h2_started && chunk.starts_with("GET /shutdown") else { return false; }
    let _ = net::tcp_send(slot.fd, H1_SHUTDOWN_RESP);
    let _ = net::tcp_shutdown(slot.fd, net::SHUT_WR);
    g_running = false;
    slot.closing = true;
    slot.close_at_ms = core::add_sat_u64(now_ms, EDGE_CLOSE_LINGER_MS);
    free_conn_streams(conn_idx);
    return true;
}

fn step_closing_conn_slot(conn_idx: i64, slot: EdgeConnSlot&, n: i32, now_ms: u64) {
    if !flush_slot_wire(slot) {
        close_conn_slot(conn_idx, slot);
        return;
    }
    if slot.tx_buf.len == 0 && !slot.shutdown_wr {
        let _ = net::tcp_shutdown(slot.fd, net::SHUT_WR);
        slot.shutdown_wr = true;
    }
    if n == 0 || n == -1 || now_ms >= slot.close_at_ms {
        close_conn_slot(conn_idx, slot);
    }
}

fn step_conn_slot(conn_idx: i64, slot: EdgeConnSlot&, now_ms: u64) {
    guard slot.active else { return; }
    var rx_buf: u8[16384] = [0; 16384];
    let n = net::tcp_recv_nonblocking_slice(slot.fd, rx_buf[..]);
    if slot.closing {
        step_closing_conn_slot(conn_idx, slot, n, now_ms);
        return;
    }
    if n == 0 || n == -1 {
        let _ = flush_slot_wire(slot);
        close_conn_slot(conn_idx, slot);
        return;
    }
    if n == -2 {
        if !flush_slot_wire(slot) {
            close_conn_slot(conn_idx, slot);
            return;
        }
        if slot.tx_buf.len == 0 && core::sub_sat_u64(now_ms, slot.last_rx_ms) >= EDGE_CONN_IDLE_MS {
            close_conn_slot(conn_idx, slot);
        }
        return;
    }

    slot.last_rx_ms = now_ms;
    let chunk = rx_buf[..n];
    if handle_h1_shutdown_if_matched(conn_idx, slot, chunk, now_ms) {
        return;
    }
    if !slot.h2_started {
        slot.sess = http2::h2_edge_open(128, 16384);
        slot.h2_started = true;
    }
    let _, ok_feed = http2::h2_edge_feed(slot.sess, chunk);
    drain_conn_events(conn_idx, slot);
    if !ok_feed {
        begin_conn_linger_close(conn_idx, slot, now_ms);
        return;
    }
    if !flush_slot_wire(slot) {
        close_conn_slot(conn_idx, slot);
    }
}

fn accept_pending_conns(listener: i64, now_ms: u64) {
    var accepted: i64 = 0;
    while accepted < 4 {
        let conn = if accepted == 0 && count_active_conns() == 0 {
            net::tcp_accept(listener, EDGE_POLL_WAIT_MS)
        } else {
            net::tcp_accept_nonblocking(listener)
        };
        guard conn > 0 else { break; }
        if !open_conn_slot(conn, now_ms) {
            net::tcp_close(conn);
        }
        accepted = core::add_sat_i64(accepted, 1);
    }
}

inline fn current_wall_ms() -> u64 {
    let ns = max(0, core::monotonic_now().as_nanos());
    return div_euclid(ns, 1000000);
}

fn main() {
    let listener = net::tcp_listen("127.0.0.1", 0, 128);
    if listener <= 0 {
        print("ERROR_FAILED_TO_LISTEN\n");
        return;
    }
    let _ = net::tcp_set_nonblocking(listener, true);
    let port = net::tcp_getsockname_port(listener);
    print("READY_PORT:", port, "\n");

    while g_running {
        let now_ms = current_wall_ms();
        accept_pending_conns(listener, now_ms);
        let step_ms = current_wall_ms();
        for i in MAX_EDGE_CONNS {
            if g_conns[i].active {
                step_conn_slot(i, g_conns[i], step_ms);
            }
        }
        if count_active_conns() > 0 {
            core::sleep(core::Duration { nanos: 1000000 });
        }
    }

    for i in MAX_EDGE_CONNS {
        close_conn_slot(i, g_conns[i]);
    }
    net::tcp_close(listener);
}
