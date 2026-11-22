// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal AsyncServerReactor connection lifecycle, parked requests, and H1/H2/wake event dispatch.
namespace server_internal;

import std;
import slice_pool;
import core;
import rfc.http;
import rfc.h3_quic;
import http.headers;
import http.request;
import http.response;
import net.tcp;
import net.udp;
import net.transport;
import net.poller;
import net.accel;
import net.io_host;
import net.driver;
import tls.session;
import tls.handshake;
import quic.packet;
import quic.frames;
import quic.connection;
import http3.types;
import http3.framing;
import http3.connection;
import wire.pipeline;
import .router;
import .router_internal;
import .router_l0_internal;
import .pool;
import .pipeline;
import .pipeline_internal;
import .h1_codec;
import .h1_codec_internal;
import .h1_serialize_internal;
import .h2_mux_types_internal;
import .h2_mux_frames_internal;
import .h2_mux_streams_internal;
import .soa_timer;
import .internal;
import .cork;
import .sni;
import .server;
import .server_h1_internal;
import .server_fast_l0_internal;
import .server_transport_internal;
import .reactor;
import .async_reactor;
import .reactor_conn_internal;

const ASYNC_REACTOR_MAX_RX_CAP: i64 = 16384;

const ASYNC_REACTOR_MAX_TX_CAP: i64 = 65536;

const ASYNC_REACTOR_MIN_RX_CAP: i64 = 512;

const ASYNC_REACTOR_MIN_TX_CAP: i64 = 1024;

struct AsyncHttpConn {
    link:            core::IoLink = core::IoLink { .. },
    h2_session_idx:  i32          = -1,
    req_seq:         u32          = 1,
    rx_off:          i32          = -1,
    rx_cap:          i32          = 0,
    rx_len:          i32          = 0,
    tx_off:          i32          = -1,
    tx_cap:          i32          = 0,
    tx_len:          i32          = 0,
    parked_count:    u16          = 0,
    in_use:          bool         = false,
    is_h2:           bool         = false,
    h2_init:         bool         = false,
    close_after_tx:  bool         = false,
    pending_h1_sync: bool         = false,
}

struct ParkedHttpRequest {
    in_use:        bool                   = false,
    gen:           u16                    = 1,
    conn_idx:      i32                    = -1,
    link:          core::IoLink           = core::IoLink { .. },
    conn_seq:      u32                    = 0,
    is_h2:         bool                   = false,
    stream_id:     u32                    = 0,
    method:        u8[..16]               = "GET",
    url:           u8[..2048]             = [],
    headers:       http::HeaderMap        = http::HeaderMap { .. },
    presence_mask: u32                    = 0,
    query_params:  http::QueryItem[..16]  = [],
    is_http10:     bool                   = false,
    req_body:      u8[..4096]             = [],
    sctx:          server::ServerStageCtx = server::ServerStageCtx { .. },
}

fn find_conn_idx_by_link(reactor: const server::AsyncServerReactor&, link: core::IoLink) -> i64 {
    guard core::io_link_is_valid(link) else { return -1; }
    let lslot = core::io_link_slot(link);
    guard lslot >= 0 && lslot < reactor.link_to_conn.len else { return -1; }
    let idx: i64 = reactor.link_to_conn[lslot];
    guard idx >= 0 && idx < reactor.conns.len else { return -1; }
    guard reactor.conns[idx].in_use && reactor.conns[idx].link.raw == link.raw else { return -1; }
    return idx;
}

fn alloc_async_h2_session(
    reactor:     server::AsyncServerReactor&,
    server_name: const u8[:],
    now_ms:      u64,
) -> i32 {
    for i in reactor.h2_in_use.len {
        if !reactor.h2_in_use[i] {
            server_internal::reset_h2_server_session_inplace(reactor.h2_sessions[i], server_name, now_ms);
            reactor.h2_in_use[i] = true;
            return i as i32;
        }
    }
    guard reactor.h2_in_use.len < server::ASYNC_REACTOR_MAX_H2 else { return -1; }
    let idx = reactor.h2_in_use.len;
    reactor.h2_sessions.push(server_internal::H2ServerSession { .. });
    reactor.h2_in_use.push(true);
    server_internal::reset_h2_server_session_inplace(reactor.h2_sessions[idx], server_name, now_ms);
    return idx as i32;
}

fn free_async_h2_session(reactor: server::AsyncServerReactor&, server: server::HttpServer&, h2_idx: i32) {
    let idx: i64 = h2_idx;
    guard idx >= 0 && idx < reactor.h2_in_use.len && idx < reactor.h2_sessions.len else { return; }
    if reactor.h2_in_use[idx] {
        server_internal::cleanup_h2_server_session(reactor.h2_sessions[idx], server.pipeline);
        reactor.h2_in_use[idx] = false;
    }
}

fn close_async_http_conn<H>(
    host:     H&,
    server:   server::HttpServer&,
    reactor:  server::AsyncServerReactor&,
    conn_idx: i64,
) {
    guard conn_idx >= 0 && conn_idx < reactor.conns.len && reactor.conns[conn_idx].in_use else { return; }
    let link = reactor.conns[conn_idx].link;
    let lslot = core::io_link_slot(link);
    if lslot >= 0 && lslot < reactor.link_to_conn.len && reactor.link_to_conn[lslot] == (conn_idx as i32) {
        reactor.link_to_conn[lslot] = -1;
    }
    pooled_buf_free(
        reactor.buf_items,
        reactor.buf_free,
        reactor.conns[conn_idx].rx_off,
        reactor.conns[conn_idx].rx_cap,
        reactor.conns[conn_idx].rx_len,
    );
    pooled_buf_free(
        reactor.buf_items,
        reactor.buf_free,
        reactor.conns[conn_idx].tx_off,
        reactor.conns[conn_idx].tx_cap,
        reactor.conns[conn_idx].tx_len,
    );
    if reactor.conns[conn_idx].h2_session_idx >= 0 {
        free_async_h2_session(reactor, server, reactor.conns[conn_idx].h2_session_idx);
    }
    reactor.conns[conn_idx] = AsyncHttpConn { .. };
    reactor.free_conns.push(conn_idx as i32);
    reactor.total_served = core::add_sat_i64(reactor.total_served, 1);
    let _ = core::host_close(host, link);
}

fn reserve_parked_http_slot(
    reactor:   server::AsyncServerReactor&,
    conn_idx:  i64,
    is_h2:     bool,
    stream_id: u32,
) -> i64, core::WakeToken {
    var slot: i64 = -1;
    if reactor.free_parked.len > 0 {
        let top = core::sub_sat_i64(reactor.free_parked.len, 1);
        slot = reactor.free_parked[top];
        reactor.free_parked.resize(top);
    } else {
        guard reactor.parked.len < server::ASYNC_REACTOR_MAX_PARKED else {
            return -1, core::WakeToken { .. };
        }
        slot = reactor.parked.len;
        reactor.parked.push(ParkedHttpRequest { .. });
    }
    let gen = next_non_zero_gen_u16(reactor.parked[slot].gen);
    let c_seq = reactor.conns[conn_idx].req_seq;
    reactor.parked[slot].in_use = true;
    reactor.parked[slot].gen = gen;
    reactor.parked[slot].conn_idx = conn_idx as i32;
    reactor.parked[slot].link = reactor.conns[conn_idx].link;
    reactor.parked[slot].conn_seq = c_seq;
    reactor.parked[slot].is_h2 = is_h2;
    reactor.parked[slot].stream_id = stream_id;
    reactor.conns[conn_idx].parked_count = core::add_sat_u64(reactor.conns[conn_idx].parked_count, 1) as u16;
    let tok = core::WakeToken {
        owner:     core::IO_OWNER_HTTP_SERVER,
        gen:       gen,
        slot:      slot as u32,
        stream_id: stream_id,
        req_seq:   c_seq,
    };
    return slot, tok;
}

fn stash_parked_request(dst: ParkedHttpRequest&, src: const http::Request&) {
    let _ = dst.method.try_set(src.method[..]);
    let _ = dst.url.try_set(src.url[..]);
    dst.headers = src.headers;
    dst.presence_mask = src.presence_mask;
    dst.query_params.clear();
    for i in src.query_params.len {
        let _ = dst.query_params.try_push(src.query_params[i]);
    }
    dst.is_http10 = src.is_http10;
    let body_take = min(src.body.len, dst.req_body.cap);
    let _ = dst.req_body.try_set(src.body[..body_take]);
}

fn restore_parked_request(src: const ParkedHttpRequest&, dst: http::Request&) {
    server::reset_server_request_fast(dst);
    let _ = dst.method.try_set(src.method[..]);
    let _ = dst.url.try_set(src.url[..]);
    dst.headers = src.headers;
    dst.presence_mask = src.presence_mask;
    dst.query_params.clear();
    for i in src.query_params.len {
        let _ = dst.query_params.try_push(src.query_params[i]);
    }
    dst.is_http10 = src.is_http10;
    dst.body.clear();
    dst.body.append(src.req_body[..]);
}

fn release_parked_http_slot(reactor: server::AsyncServerReactor&, slot: i64) {
    guard slot >= 0 && slot < reactor.parked.len && reactor.parked[slot].in_use else { return; }
    let c_idx: i64 = reactor.parked[slot].conn_idx;
    if c_idx >= 0 &&
        c_idx < reactor.conns.len &&
        reactor.conns[c_idx].in_use &&
        reactor.conns[c_idx].link.raw == reactor.parked[slot].link.raw &&
        reactor.conns[c_idx].req_seq == reactor.parked[slot].conn_seq &&
        reactor.conns[c_idx].parked_count > 0 {
        reactor.conns[c_idx].parked_count = core::sub_sat_u64(reactor.conns[c_idx].parked_count, 1) as u16;
    }
    let next_gen = next_non_zero_gen_u16(reactor.parked[slot].gen);
    reactor.parked[slot].in_use = false;
    reactor.parked[slot].gen = next_gen;
    reactor.parked[slot].conn_idx = -1;
    reactor.parked[slot].link = core::IoLink { .. };
    reactor.free_parked.push(slot as i32);
}

fn send_async_http_bytes<H>(
    host:     H&,
    server:   server::HttpServer&,
    reactor:  server::AsyncServerReactor&,
    conn_idx: i64,
    bytes:    const u8[:],
) -> bool {
    guard conn_idx >= 0 && conn_idx < reactor.conns.len && reactor.conns[conn_idx].in_use else { return false; }
    guard bytes.len > 0 else { return true; }
    let conn .= reactor.conns[conn_idx];
    if conn.tx_len == 0 {
        let sent, err = core::host_send(host, conn.link, bytes);
        if err == core::IoError.None && (sent as i64) >= bytes.len {
            return true;
        }
        if err == core::IoError.WouldBlock || err == core::IoError.ShortWrite {
            let skip = max(sent as i64, 0);
            let ok_buf = pooled_buf_append(
                reactor.buf_items,
                reactor.buf_free,
                conn.tx_off,
                conn.tx_cap,
                conn.tx_len,
                bytes[skip..],
                ASYNC_REACTOR_MIN_TX_CAP,
                ASYNC_REACTOR_MAX_TX_CAP,
            );
            if ok_buf {
                return true;
            }
        }
        close_async_http_conn(host, server, reactor, conn_idx);
        return false;
    }
    let ok_append = pooled_buf_append(
        reactor.buf_items,
        reactor.buf_free,
        conn.tx_off,
        conn.tx_cap,
        conn.tx_len,
        bytes,
        ASYNC_REACTOR_MIN_TX_CAP,
        ASYNC_REACTOR_MAX_TX_CAP,
    );
    guard ok_append else {
        close_async_http_conn(host, server, reactor, conn_idx);
        return false;
    }
    return true;
}

fn flush_async_http_tx<H>(
    host:     H&,
    server:   server::HttpServer&,
    reactor:  server::AsyncServerReactor&,
    conn_idx: i64,
) {
    guard conn_idx >= 0 && conn_idx < reactor.conns.len && reactor.conns[conn_idx].in_use else { return; }
    let conn .= reactor.conns[conn_idx];
    if conn.tx_len > 0 {
        let sent, err = core::host_send(
            host, conn.link, pooled_buf_slice(reactor.buf_items[..], conn.tx_off, conn.tx_len),
        );
        if sent > 0 {
            pooled_buf_consume(
                reactor.buf_items, reactor.buf_free, conn.tx_off, conn.tx_cap, conn.tx_len, sent,
            );
        } else if err != core::IoError.WouldBlock && err != core::IoError.ShortWrite && err != core::IoError.None {
            close_async_http_conn(host, server, reactor, conn_idx);
            return;
        }
    }
    if conn.tx_len == 0 && conn.close_after_tx {
        close_async_http_conn(host, server, reactor, conn_idx);
    }
}

inline fn emit_app_pump<H, App>(host: H&, app: App&) {
    let ev = core::LinkEvent { kind: core::LinkEventKind.Pump, .. };
    core::on_link_event(app, host, ev);
}

fn step_async_h2_ready_stream<H, App>(
    host:     H&,
    server:   server::HttpServer&,
    reactor:  server::AsyncServerReactor&,
    app:      App&,
    conn_idx: i64,
    h2_idx:   i64,
    now_ms:   u64,
) -> bool {
    let st_idx = server_internal::next_ready_h2_stream(reactor.h2_sessions[h2_idx]);
    guard st_idx >= 0 else { return false; }

    let target_sid = reactor.h2_sessions[h2_idx].streams[st_idx].stream_id;
    let p_slot, tok = reserve_parked_http_slot(reactor, conn_idx, true, target_sid);
    guard p_slot >= 0 else { return false; }

    reactor.tx_scratch.clear();
    let outcome = server_internal::execute_h2_stream_async(
        reactor.h2_sessions[h2_idx],
        st_idx,
        server.pipeline,
        server.timer,
        "127.0.0.1",
        now_ms,
        tok,
        reactor.req_scratch,
        reactor.parked[p_slot].sctx,
        reactor.tx_scratch,
        app,
    );
    if outcome == server::PipelineOutcome.Pending {
        stash_parked_request(reactor.parked[p_slot], reactor.req_scratch);
        emit_app_pump(host, app);
        return true;
    }
    release_parked_http_slot(reactor, p_slot);
    server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
    if reactor.tx_scratch.len > 0 {
        if !send_async_http_bytes(host, server, reactor, conn_idx, reactor.tx_scratch[..]) {
            return false;
        }
    }
    return reactor.conns[conn_idx].in_use;
}

fn process_async_h2_conn<H, App>(
    host:     H&,
    server:   server::HttpServer&,
    reactor:  server::AsyncServerReactor&,
    app:      App&,
    conn_idx: i64,
) {
    let conn .= reactor.conns[conn_idx];
    let now_ms, _ = core::div_rem_u64(reactor.cur_now_ns, 1000000);
    if conn.h2_session_idx < 0 {
        let allocated = alloc_async_h2_session(reactor, server.server_name[..], now_ms);
        guard allocated >= 0 else {
            close_async_http_conn(host, server, reactor, conn_idx);
            return;
        }
        conn.h2_session_idx = allocated;
    }
    let h2_idx = conn.h2_session_idx as i64;
    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }

    reactor.tx_scratch.clear();
    let consumed, ok_h2 = server_internal::ingest_h2_server_frames(
        reactor.h2_sessions[h2_idx],
        server.pipeline,
        pooled_buf_slice(reactor.buf_items[..], conn.rx_off, conn.rx_len),
        now_ms,
        reactor.tx_scratch,
    );
    if consumed > 0 {
        pooled_buf_consume(
            reactor.buf_items, reactor.buf_free, conn.rx_off, conn.rx_cap, conn.rx_len, consumed,
        );
    }
    if reactor.tx_scratch.len > 0 {
        guard send_async_http_bytes(host, server, reactor, conn_idx, reactor.tx_scratch[..]) else {
            return;
        }
    }
    guard ok_h2 else {
        close_async_http_conn(host, server, reactor, conn_idx);
        return;
    }

    reactor.tx_scratch.clear();
    server_internal::flush_h2_stream_tails(reactor.h2_sessions[h2_idx], server.pipeline, reactor.tx_scratch);
    if reactor.tx_scratch.len > 0 {
        guard send_async_http_bytes(host, server, reactor, conn_idx, reactor.tx_scratch[..]) else {
            return;
        }
    }

    for _ in 16 {
        if !step_async_h2_ready_stream(host, server, reactor, app, conn_idx, h2_idx, now_ms) {
            break;
        }
    }
}

fn send_async_h1_400_bad_request<H>(
    host:     H&,
    server:   server::HttpServer&,
    reactor:  server::AsyncServerReactor&,
    conn_idx: i64,
) {
    reactor.tx_scratch.clear();
    reactor.res_scratch = http::Response { status_code: 400, .. };
    http::respond_problem(reactor.res_scratch, 400, "Bad Request", "Malformed HTTP request");
    server::serialize_http1_response(reactor.res_scratch, server.server_name[..], reactor.tx_scratch);
    let _ = send_async_http_bytes(host, server, reactor, conn_idx, reactor.tx_scratch[..]);
    guard reactor.conns[conn_idx].in_use else { return; }
    reactor.conns[conn_idx].close_after_tx = true;
    if reactor.conns[conn_idx].tx_len == 0 {
        close_async_http_conn(host, server, reactor, conn_idx);
    }
}

fn emit_h1_response_and_check_close<H>(
    host:        H&,
    server:      server::HttpServer&,
    reactor:     server::AsyncServerReactor&,
    conn_idx:    i64,
    wants_close: bool,
) -> bool {
    reactor.tx_scratch.clear();
    server::serialize_http1_response(reactor.res_scratch, server.server_name[..], reactor.tx_scratch);
    server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
    reactor.total_served = core::add_sat_i64(reactor.total_served, 1);
    guard send_async_http_bytes(host, server, reactor, conn_idx, reactor.tx_scratch[..]) else {
        return false;
    }
    if wants_close {
        reactor.conns[conn_idx].close_after_tx = true;
    }
    if reactor.conns[conn_idx].close_after_tx {
        if reactor.conns[conn_idx].tx_len == 0 && !reactor.conns[conn_idx].pending_h1_sync {
            close_async_http_conn(host, server, reactor, conn_idx);
        }
        return false;
    }
    return reactor.conns[conn_idx].in_use && reactor.conns[conn_idx].rx_len > 0;
}

fn step_async_h1_request<H, App>(
    host:     H&,
    server:   server::HttpServer&,
    reactor:  server::AsyncServerReactor&,
    app:      App&,
    conn_idx: i64,
) -> bool {
    let conn .= reactor.conns[conn_idx];
    guard conn.rx_len > 0 && !conn.pending_h1_sync && !conn.close_after_tx else { return false; }

    let hdr_end = core::fast_find_crlfcrlf(pooled_buf_slice(reactor.buf_items[..], conn.rx_off, conn.rx_len));
    if hdr_end < 0 {
        if conn.rx_len > 8192 {
            close_async_http_conn(host, server, reactor, conn_idx);
        }
        return false;
    }
    guard server::is_http1_request_ready(
        pooled_buf_slice(reactor.buf_items[..], conn.rx_off, conn.rx_len), hdr_end,
    ) else {
        return false;
    }

    let p_slot, tok = reserve_parked_http_slot(reactor, conn_idx, false, 0);
    guard p_slot >= 0 else { return false; }
    server::reset_server_request_fast(reactor.req_scratch);
    let ok_parse, consumed = server::parse_http1_wire_request(
        pooled_buf_slice(reactor.buf_items[..], conn.rx_off, conn.rx_len), reactor.req_scratch,
    );
    if !ok_parse || consumed <= 0 {
        release_parked_http_slot(reactor, p_slot);
        send_async_h1_400_bad_request(host, server, reactor, conn_idx);
        return false;
    }

    pooled_buf_consume(reactor.buf_items, reactor.buf_free, conn.rx_off, conn.rx_cap, conn.rx_len, consumed);
    reactor.res_scratch = http::Response { .. };
    var future = server_internal::new_inline_handler_future(0);
    reactor.parked[p_slot].sctx = server::ServerStageCtx {
        wake_token: tok,
        now_ns:     reactor.cur_now_ns,
        ..
    };
    let outcome = server::execute_server_pipeline_async(
        server.pipeline,
        server.timer,
        "127.0.0.1",
        reactor.req_scratch,
        reactor.cur_now_ns,
        reactor.res_scratch,
        future,
        reactor.parked[p_slot].sctx,
        app,
    );
    if outcome == server::PipelineOutcome.Pending {
        stash_parked_request(reactor.parked[p_slot], reactor.req_scratch);
        conn.pending_h1_sync = true;
        let _ = core::host_set_rx_paused(host, conn.link, true);
        emit_app_pump(host, app);
        return false;
    }

    let wants_close = check_and_apply_connection_close(reactor.req_scratch, reactor.res_scratch);
    release_parked_http_slot(reactor, p_slot);
    return emit_h1_response_and_check_close(host, server, reactor, conn_idx, wants_close);
}

fn drain_async_h1_requests<H, App>(
    host:     H&,
    server:   server::HttpServer&,
    reactor:  server::AsyncServerReactor&,
    app:      App&,
    conn_idx: i64,
) {
    for _ in 16 {
        if !step_async_h1_request(host, server, reactor, app, conn_idx) {
            break;
        }
    }
}

fn handle_http_data_event<H, App>(
    host:    H&,
    server:  server::HttpServer&,
    reactor: server::AsyncServerReactor&,
    app:     App&,
    link:    core::IoLink,
    data:    const u8[:],
) {
    let conn_idx = find_conn_idx_by_link(reactor, link);
    guard conn_idx >= 0 else { return; }
    let conn .= reactor.conns[conn_idx];
    let ok_rx = pooled_buf_append(
        reactor.buf_items,
        reactor.buf_free,
        conn.rx_off,
        conn.rx_cap,
        conn.rx_len,
        data,
        ASYNC_REACTOR_MIN_RX_CAP,
        ASYNC_REACTOR_MAX_RX_CAP,
    );
    guard ok_rx else {
        close_async_http_conn(host, server, reactor, conn_idx);
        return;
    }
    if !conn.h2_init {
        if conn.rx_len < 24 && server::is_partial_h2_client_preface(
            pooled_buf_slice(reactor.buf_items[..], conn.rx_off, conn.rx_len),
        ) {
            return;
        }
        if conn.rx_len >= 24 && server::is_h2_client_preface(
            pooled_buf_slice(reactor.buf_items[..], conn.rx_off, conn.rx_len),
        ) {
            conn.is_h2 = true;
            conn.h2_init = true;
        } else if core::fast_find_crlfcrlf(
            pooled_buf_slice(reactor.buf_items[..], conn.rx_off, conn.rx_len),
        ) >= 0 {
            conn.h2_init = true;
        }
    }
    if conn.is_h2 {
        process_async_h2_conn(host, server, reactor, app, conn_idx);
        return;
    }
    drain_async_h1_requests(host, server, reactor, app, conn_idx);
}

fn handle_stale_http_wake<App>(
    server:  server::HttpServer&,
    reactor: server::AsyncServerReactor&,
    app:     App&,
    p_slot:  i64,
) {
    reactor.total_stale_wakes = core::add_sat_i64(reactor.total_stale_wakes, 1);
    restore_parked_request(reactor.parked[p_slot], reactor.req_scratch);
    reactor.res_scratch = http::Response { .. };
    let _ = server::on_server_stage(
        app,
        wire::ServerHookPhase.ResumeHandler,
        server.pipeline,
        reactor.req_scratch,
        reactor.parked[p_slot].sctx,
        reactor.res_scratch,
    );
    release_parked_http_slot(reactor, p_slot);
}

fn resume_parked_h2_wake<H, App>(
    host:    H&,
    server:  server::HttpServer&,
    reactor: server::AsyncServerReactor&,
    app:     App&,
    p_slot:  i64,
    c_idx:   i64,
    now_ns:  u64,
) {
    let stream_id = reactor.parked[p_slot].stream_id;
    let h2_idx = reactor.conns[c_idx].h2_session_idx as i64;
    let now_ms, _ = core::div_rem_u64(now_ns, 1000000);
    reactor.tx_scratch.clear();
    let ok_res = h2_idx >= 0 && server_internal::complete_pending_h2_stream_response(
        reactor.h2_sessions[h2_idx],
        stream_id,
        server.pipeline,
        now_ms,
        reactor.req_scratch,
        reactor.parked[p_slot].sctx,
        reactor.tx_scratch,
        app,
    );
    release_parked_http_slot(reactor, p_slot);
    if ok_res && reactor.tx_scratch.len > 0 {
        let _ = send_async_http_bytes(host, server, reactor, c_idx, reactor.tx_scratch[..]);
        server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
        reactor.total_served = core::add_sat_i64(reactor.total_served, 1);
    }
    if reactor.conns[c_idx].in_use &&
        reactor.conns[c_idx].close_after_tx &&
        reactor.conns[c_idx].tx_len == 0 &&
        !has_parked_req_on_conn(reactor, c_idx) {
        close_async_http_conn(host, server, reactor, c_idx);
    }
}

fn resume_parked_h1_wake<H, App>(
    host:    H&,
    server:  server::HttpServer&,
    reactor: server::AsyncServerReactor&,
    app:     App&,
    p_slot:  i64,
    c_idx:   i64,
    now_ns:  u64,
) {
    let link = reactor.conns[c_idx].link;
    reactor.conns[c_idx].pending_h1_sync = false;
    let _ = core::host_set_rx_paused(host, link, false);
    reactor.res_scratch = http::Response { .. };
    let _ = server::resume_server_pipeline_egress(
        server.pipeline,
        reactor.req_scratch,
        now_ns,
        reactor.parked[p_slot].sctx,
        reactor.res_scratch,
        app,
    );
    let wants_close = check_and_apply_connection_close(reactor.req_scratch, reactor.res_scratch);
    release_parked_http_slot(reactor, p_slot);
    if emit_h1_response_and_check_close(host, server, reactor, c_idx, wants_close) {
        drain_async_h1_requests(host, server, reactor, app, c_idx);
    }
}

fn handle_http_wake_event<H, App>(
    host:    H&,
    server:  server::HttpServer&,
    reactor: server::AsyncServerReactor&,
    app:     App&,
    token:   core::WakeToken,
    now_ns:  u64,
) {
    let p_slot = token.slot as i64;
    guard p_slot >= 0 && p_slot < reactor.parked.len else {
        reactor.total_stale_wakes = core::add_sat_i64(reactor.total_stale_wakes, 1);
        return;
    }
    guard reactor.parked[p_slot].in_use && reactor.parked[p_slot].gen == token.gen else {
        reactor.total_stale_wakes = core::add_sat_i64(reactor.total_stale_wakes, 1);
        return;
    }
    let c_idx = reactor.parked[p_slot].conn_idx as i64;
    let is_live = c_idx >= 0 &&
        c_idx < reactor.conns.len &&
        reactor.conns[c_idx].in_use &&
        reactor.conns[c_idx].link.raw == reactor.parked[p_slot].link.raw &&
        reactor.conns[c_idx].req_seq == reactor.parked[p_slot].conn_seq;
    guard is_live else {
        handle_stale_http_wake(server, reactor, app, p_slot);
        return;
    }

    reactor.total_wakes_delivered = core::add_sat_i64(reactor.total_wakes_delivered, 1);
    restore_parked_request(reactor.parked[p_slot], reactor.req_scratch);
    if reactor.parked[p_slot].is_h2 {
        resume_parked_h2_wake(host, server, reactor, app, p_slot, c_idx, now_ns);
        return;
    }
    resume_parked_h1_wake(host, server, reactor, app, p_slot, c_idx, now_ns);
}

fn handle_http_eof_event<H>(
    host:    H&,
    server:  server::HttpServer&,
    reactor: server::AsyncServerReactor&,
    link:    core::IoLink,
) {
    let idx = find_conn_idx_by_link(reactor, link);
    guard idx >= 0 else { return; }
    let has_pending = reactor.conns[idx].pending_h1_sync ||
        reactor.conns[idx].tx_len > 0 ||
        has_parked_req_on_conn(reactor, idx);
    if has_pending {
        reactor.conns[idx].close_after_tx = true;
    } else {
        close_async_http_conn(host, server, reactor, idx);
    }
}

fn handle_http_owner_link_event<H, App>(
    host:    H&,
    server:  server::HttpServer&,
    reactor: server::AsyncServerReactor&,
    app:     App&,
    ev:      const core::LinkEvent&,
) {
    match ev.kind {
        Accepted => {
            if server::async_reactor_register_client_link(reactor, ev.link) < 0 {
                let _ = core::host_close(host, ev.link);
            }
        },
        Data => {
            handle_http_data_event(host, server, reactor, app, ev.link, ev.data);
        },
        Writable => {
            let idx = find_conn_idx_by_link(reactor, ev.link);
            if idx >= 0 {
                flush_async_http_tx(host, server, reactor, idx);
            }
        },
        Closed => {
            let idx = find_conn_idx_by_link(reactor, ev.link);
            if idx >= 0 {
                close_async_http_conn(host, server, reactor, idx);
            }
        },
        Eof => {
            handle_http_eof_event(host, server, reactor, ev.link);
        },
        _ => {},
    };
}

fn handle_async_reactor_event<H, App>(
    host:    H&,
    server:  server::HttpServer&,
    reactor: server::AsyncServerReactor&,
    app:     App&,
    ev:      const core::LinkEvent&,
) {
    if ev.kind == core::LinkEventKind.Wake {
        if ev.token.owner == core::IO_OWNER_HTTP_SERVER {
            handle_http_wake_event(host, server, reactor, app, ev.token, reactor.cur_now_ns);
            return;
        }
        core::on_link_event(app, host, ev);
        return;
    }
    if ev.kind == core::LinkEventKind.Pump || core::io_link_owner(ev.link) != core::IO_OWNER_HTTP_SERVER {
        core::on_link_event(app, host, ev);
        return;
    }
    handle_http_owner_link_event(host, server, reactor, app, ev);
}

fn has_parked_req_on_conn(reactor: const server::AsyncServerReactor&, conn_idx: i64) -> bool {
    guard conn_idx >= 0 && conn_idx < reactor.conns.len && reactor.conns[conn_idx].in_use else {
        return false;
    }
    return reactor.conns[conn_idx].parked_count > 0;
}

const REACTOR_LEFTOVER_CAP: i64 = 8192;

const REACTOR_INGRESS_CAP: i64 = 65536;

const REACTOR_MAX_DYNAMIC_SLOTS: i64 = 65536;
