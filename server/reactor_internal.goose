// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal epoll/io_uring/RIO/kqueue reactor loops, TLS slot unsealing, H3 framing, and async reactor helpers.
namespace server_internal;

import std;
import slice_pool;
import core from "..";
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
import .pool;
import .pipeline;
import .pipeline_internal;
import .h1_codec;
import .h1_codec_internal;
import .h2_multiplexer;
import .soa_timer;
import .internal;
import .cork;
import .sni;
import .server;
import .server_internal;
import .reactor;
import .async_reactor;

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

struct PooledBufSpan {
    off: i32 = 0,
    cap: i32 = 0,
}

inline fn next_non_zero_gen_u16(cur: u16) -> u16 {
    let nxt: u16 = cur + 1;
    return if nxt == 0 { 1 } else { nxt };
}

inline fn next_non_zero_seq_u32(cur: u32) -> u32 {
    let nxt: u32 = cur + 1;
    return if nxt == 0 { 1 } else { nxt };
}

inline fn pooled_buf_slice(items: const u8[:], off: i32, len: i32) -> const u8[:] {
    let base_off: i64 = off;
    let cur_len:  i64 = len;
    guard base_off >= 0 && cur_len > 0 else { return ""; }
    let end = core::add_sat_i64(base_off, cur_len);
    guard end <= items.len else { return ""; }
    return items[base_off..end];
}

fn coalesce_and_trim_buf_pool(items: u8[>..]&, free_spans: PooledBufSpan[>..<]&, pos: i64) {
    let next_idx = core::add_sat_i64(pos, 1);
    if next_idx < free_spans.len {
        let cur_end = core::add_sat_i64(free_spans[pos].off, free_spans[pos].cap);
        if cur_end == free_spans[next_idx].off {
            free_spans[pos].cap = core::add_sat_i64(free_spans[pos].cap, free_spans[next_idx].cap) as i32;
            let _ = remove_at(free_spans, next_idx);
        }
    }
    if pos > 0 {
        let prev = core::sub_sat_i64(pos, 1);
        let prev_end = core::add_sat_i64(free_spans[prev].off, free_spans[prev].cap);
        if prev_end == free_spans[pos].off {
            free_spans[prev].cap = core::add_sat_i64(free_spans[prev].cap, free_spans[pos].cap) as i32;
            let _ = remove_at(free_spans, pos);
        }
    }
    if free_spans.len > 0 {
        let last_idx = core::sub_sat_i64(free_spans.len, 1);
        let tail_off: i64 = free_spans[last_idx].off;
        if core::add_sat_i64(tail_off, free_spans[last_idx].cap) == items.len {
            items.resize(tail_off);
            free_spans.resize(last_idx);
        }
    }
}

fn pooled_buf_free(
    items:      u8[>..]&,
    free_spans: PooledBufSpan[>..<]&,
    off:        i32&,
    cap:        i32&,
    len:        i32&,
) {
    let cur_off = off;
    let cur_cap = cap;
    off = -1;
    cap = 0;
    len = 0;
    guard cur_off >= 0 && cur_cap > 0 else { return; }
    var pos: i64 = 0;
    while pos < free_spans.len && free_spans[pos].off < cur_off {
        pos = core::add_sat_i64(pos, 1);
    }
    insert_at(free_spans, pos, PooledBufSpan { off: cur_off, cap: cur_cap });
    coalesce_and_trim_buf_pool(items, free_spans, pos);
}

fn alloc_from_buf_pool(
    items:      u8[>..]&,
    free_spans: PooledBufSpan[>..<]&,
    need_cap:   i64,
) -> i32 {
    for i in free_spans.len {
        let span_cap: i64 = free_spans[i].cap;
        if span_cap >= need_cap {
            let out_off = free_spans[i].off;
            let rem = core::sub_sat_i64(span_cap, need_cap);
            if rem == 0 {
                let _ = remove_at(free_spans, i);
            } else {
                free_spans[i].off = core::add_sat_i64(out_off, need_cap) as i32;
                free_spans[i].cap = rem as i32;
            }
            return out_off;
        }
    }
    let out_off = items.len as i32;
    push_n(items, 0 as u8, need_cap);
    return out_off;
}

fn grow_pooled_buf_cap(
    items:      u8[>..]&,
    free_spans: PooledBufSpan[>..<]&,
    off:        i32&,
    cap:        i32&,
    used_len:   i64,
    new_cap:    i64,
) {
    let cur_cap: i64 = cap;
    if cur_cap <= 0 || off < 0 {
        off = alloc_from_buf_pool(items, free_spans, new_cap);
        cap = new_cap as i32;
        return;
    }
    let old_off: i64 = off;
    if core::add_sat_i64(old_off, cur_cap) == items.len {
        push_n(items, 0 as u8, core::sub_sat_i64(new_cap, cur_cap));
        cap = new_cap as i32;
        return;
    }
    let new_off = alloc_from_buf_pool(items, free_spans, new_cap);
    for i in used_len {
        items[core::add_sat_i64(new_off, i)] = items[core::add_sat_i64(old_off, i)];
    }
    var unused_len: i32 = 0;
    pooled_buf_free(items, free_spans, off, cap, unused_len);
    off = new_off;
    cap = new_cap as i32;
}

fn pooled_buf_append(
    items:      u8[>..]&,
    free_spans: PooledBufSpan[>..<]&,
    off:        i32&,
    cap:        i32&,
    len:        i32&,
    data:       const u8[:],
    min_cap:    i64,
    max_cap:    i64,
) -> bool {
    guard data.len > 0 else { return true; }
    let cur_len: i64 = len;
    let needed = core::add_sat_i64(cur_len, data.len);
    guard needed <= max_cap else { return false; }
    if needed > cap {
        let new_cap = min(max(next_pow2(needed), min_cap), max_cap);
        grow_pooled_buf_cap(items, free_spans, off, cap, cur_len, new_cap);
    }
    let write_off = core::add_sat_i64(off, cur_len);
    for i in data.len {
        items[core::add_sat_i64(write_off, i)] = data[i];
    }
    len = needed as i32;
    return true;
}

fn pooled_buf_consume(
    items:      u8[>..]&,
    free_spans: PooledBufSpan[>..<]&,
    off:        i32&,
    cap:        i32&,
    len:        i32&,
    consumed:   i64,
) {
    guard consumed > 0 else { return; }
    let cur_len: i64 = len;
    if consumed >= cur_len {
        pooled_buf_free(items, free_spans, off, cap, len);
        return;
    }
    let rem = core::sub_sat_i64(cur_len, consumed);
    let base_off: i64 = off;
    let src_off = core::add_sat_i64(base_off, consumed);
    for i in rem {
        items[core::add_sat_i64(base_off, i)] = items[core::add_sat_i64(src_off, i)];
    }
    len = rem as i32;
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

struct ReactorIngressBuf {
    len:   i64     = 0,
    bytes: u8[>..] = [],
}

struct ReactorSlotPool {
    next_slot:  i64       = 0,
    max_slots:  i64       = REACTOR_MAX_DYNAMIC_SLOTS,
    free_slots: i64[>..<] = [],
}

struct ReactorState {
    h2_in_use:             bool[128]                             = [false; 128],
    leftover_leased_bytes: i64                                   = 0,
    leftover_leased_slots: i64                                   = 0,
    leftover_pool_hwm:     i64                                   = 0,
    h2_sessions:           server_internal::H2ServerSession[>..] = [],
}

inline fn ensure_reactor_ingress_buf(chunk: ReactorIngressBuf&) {
    if chunk.bytes.len < REACTOR_INGRESS_CAP {
        chunk.bytes.resize(REACTOR_INGRESS_CAP, 0);
    }
}

inline fn ensure_reactor_cork_buf() {
    if server::g_reactor_cork_bufs.len == 0 {
        server::g_reactor_cork_bufs.push([]);
    }
}

inline fn reactor_tls_plain_scratch() -> u8[..32768]& {
    if server::g_reactor_tls_plain_bufs.len == 0 {
        server::g_reactor_tls_plain_bufs.push([]);
    }
    return server::g_reactor_tls_plain_bufs[0];
}

inline fn reactor_tls_seal_scratch() -> u8[..65536]& {
    if server::g_reactor_tls_seal_bufs.len == 0 {
        server::g_reactor_tls_seal_bufs.push([]);
    }
    return server::g_reactor_tls_seal_bufs[0];
}

fn alloc_reactor_conn_slot(pool: ReactorSlotPool&, table: server::SoAConnTable&) -> i64 {
    if pool.free_slots.len > 0 {
        let top_idx = core::sub_sat_i64(pool.free_slots.len, 1);
        let reused = pool.free_slots[top_idx];
        pool.free_slots.pop();
        if server::soa_table_ensure_slot(table, reused) {
            return reused;
        }
    }
    guard pool.next_slot < pool.max_slots else { return -1; }
    let fresh = pool.next_slot;
    guard server::soa_table_ensure_slot(table, fresh) else { return -1; }
    pool.next_slot = core::add_sat_i64(fresh, 1);
    return fresh;
}

inline fn free_reactor_conn_slot(pool: ReactorSlotPool&, slot: i64) {
    if slot >= 0 && slot < pool.next_slot {
        pool.free_slots.push(slot);
    }
}

fn reactor_free_slot_leftover(
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot:          i64,
) {
    guard slot >= 0 && slot < table.leftover_lens.len && slot < table.leftover_offs.len else { return; }
    let prev_len = table.leftover_lens[slot] as i64;
    let prev_off = table.leftover_offs[slot];
    let end_off = core::add_sat_i64(prev_off, prev_len);
    if prev_len > 0 && prev_off >= 0 && end_off >= prev_off && end_off <= leftover_pool.items.len {
        leftover_pool.free_slice(leftover_pool.items[prev_off..end_off]);
        server::g_default_reactor.leftover_leased_bytes = max(
            core::sub_sat_i64(server::g_default_reactor.leftover_leased_bytes, prev_len), 0,
        );
        server::g_default_reactor.leftover_leased_slots = max(
            core::sub_sat_i64(server::g_default_reactor.leftover_leased_slots, 1), 0,
        );
    }
    table.leftover_lens[slot] = 0;
    table.leftover_offs[slot] = -1;
}

fn reactor_free_slot_tls_ct(
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot:          i64,
) {
    guard slot >= 0 && slot < table.tls_ct_lens.len && slot < table.tls_ct_offs.len else { return; }
    let prev_len = table.tls_ct_lens[slot] as i64;
    let prev_off = table.tls_ct_offs[slot];
    let end_off = core::add_sat_i64(prev_off, prev_len);
    if prev_len > 0 && prev_off >= 0 && end_off >= prev_off && end_off <= leftover_pool.items.len {
        leftover_pool.free_slice(leftover_pool.items[prev_off..end_off]);
    }
    table.tls_ct_lens[slot] = 0;
    table.tls_ct_offs[slot] = -1;
}

fn reactor_append_slot_tls_ct(
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot:          i64,
    rx_raw:        const u8[:],
) -> bool {
    guard slot >= 0 && slot < table.tls_ct_lens.len && slot < table.tls_ct_offs.len else { return false; }
    guard rx_raw.len > 0 else { return true; }
    let old_len = table.tls_ct_lens[slot] as i64;
    let new_len = core::add_sat_i64(old_len, rx_raw.len);
    guard new_len <= net::REACTOR_TLS_CT_CAP else { return false; }
    let old_off = table.tls_ct_offs[slot];
    let old_end = core::add_sat_i64(old_off, old_len);
    if old_len <= 0 || old_off < 0 || old_end < old_off || old_end > leftover_pool.items.len {
        let leased = leftover_pool.alloc_slice(rx_raw.len);
        for i in rx_raw.len {
            if i < leased.len {
                leased[i] = rx_raw[i];
            }
        }
        table.tls_ct_offs[slot] = leftover_pool.items.range_index(
            leased, "reactor_append_slot_tls_ct: invalid pool slice",
        );
        table.tls_ct_lens[slot] = rx_raw.len as u16;
        return true;
    }
    let grown = leftover_pool.realloc_slice(
        leftover_pool.items[old_off..old_end], new_len,
    );
    for i in rx_raw.len {
        let dst_idx = core::add_sat_i64(old_len, i);
        if dst_idx >= 0 && dst_idx < grown.len {
            grown[dst_idx] = rx_raw[i];
        }
    }
    table.tls_ct_offs[slot] = leftover_pool.items.range_index(
        grown, "reactor_append_slot_tls_ct: invalid grown slice",
    );
    table.tls_ct_lens[slot] = new_len as u16;
    return true;
}

fn reactor_consume_slot_tls_ct(
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot:          i64,
    consumed:      i64,
) {
    guard slot >= 0 && slot < table.tls_ct_lens.len && slot < table.tls_ct_offs.len && consumed > 0 else {
        return;
    }
    let old_len = table.tls_ct_lens[slot] as i64;
    let old_off = table.tls_ct_offs[slot];
    let old_end = core::add_sat_i64(old_off, old_len);
    guard old_len > 0 && old_off >= 0 && old_end >= old_off && old_end <= leftover_pool.items.len else {
        return;
    }
    if consumed >= old_len {
        reactor_free_slot_tls_ct(table, leftover_pool, slot);
        return;
    }
    let rem_len = core::sub_sat_i64(old_len, consumed);
    let src_base = core::add_sat_i64(old_off, consumed);
    for i in rem_len {
        let dst_idx = core::add_sat_i64(old_off, i);
        let src_idx = core::add_sat_i64(src_base, i);
        if dst_idx >= 0 && dst_idx < leftover_pool.items.len &&
            src_idx >= 0 && src_idx < leftover_pool.items.len {
            leftover_pool.items[dst_idx] = leftover_pool.items[src_idx];
        }
    }
    let shrunk = leftover_pool.realloc_slice(
        leftover_pool.items[old_off..old_end], rem_len,
    );
    table.tls_ct_offs[slot] = leftover_pool.items.range_index(
        shrunk, "reactor_consume_slot_tls_ct: invalid shrunk slice",
    );
    table.tls_ct_lens[slot] = rem_len as u16;
}

// Cleans up a connection slot, detaches driver state, closes transport, and returns slot to free pool.
fn reactor_cleanup_slot(
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_idx:      i64,
    slot_pool:     ReactorSlotPool&,
) {
    guard is_valid_slot(table, slot_idx) else { return; }
    let fd = table.fds[slot_idx];
    reactor_free_slot_leftover(table, leftover_pool, slot_idx);
    reactor_free_slot_tls_ct(table, leftover_pool, slot_idx);
    if fd > 0 {
        if server::g_reactor_accel.kq_fd >= 0 {
            net::reactor_queue_kq_change(server::g_reactor_accel, fd, net_internal::EV_DELETE, slot_idx as u64);
        }
        if epfd >= 0 {
            if net::epoll_del(epfd, fd) {
                let prev_reg = server::g_reactor_accel.epfd_registered_count;
                server::g_reactor_accel.epfd_registered_count = max(0, prev_reg - 1);
            }
        }
        net::reactor_reset_accel_slot(server::g_reactor_accel, slot_idx);
        var tr = table.slot_transport(slot_idx);
        tr.close();
        if table.h2_slot_map[slot_idx] >= 0 {
            let h2_i = table.h2_slot_map[slot_idx] as i64;
            if h2_i >= 0 && h2_i < server::REACTOR_MAX_H2_SESSIONS {
                server::g_default_reactor.h2_in_use[h2_i] = false;
            }
        }
        if table.conn_slots[slot_idx] >= 0 {
            server_internal::free_connection_slot(server::g_reactor_conn_pool, table.conn_slots[slot_idx]);
        }
        table.soa_table_free(slot_idx);
        free_reactor_conn_slot(slot_pool, slot_idx);
    } else {
        net::reactor_reset_accel_slot(server::g_reactor_accel, slot_idx);
    }
}

// 1-second Tick Wheel Connection Timeout Sweeper (Slowloris defense & slot reclamation).
// Sweeps contiguous 1-byte timeout ticks entirely in L1D cache via SoAConnTable.
fn reactor_sweep_timeouts(
    epfd:           i64,
    table:          server::SoAConnTable&,
    leftover_pool:  slice_pool<u8>&,
    slot_pool:      ReactorSlotPool&,
    timer_wheel:    core::TickTimerWheel&,
    now_sec:        i64,
    last_sweep_sec: i64&,
    total_served:   i64&,
) {
    guard now_sec > last_sweep_sec else { return; }
    let elapsed = if last_sweep_sec == 0 { 1 } else { (now_sec - last_sweep_sec) as u32 };
    last_sweep_sec = now_sec;
    core::tick_timer_advance(timer_wheel, elapsed);

    var expired: i64[256] = [0; 256];
    loop {
        let n_expired = table.soa_table_sweep_expired(timer_wheel, expired[..]);
        guard n_expired > 0 else { break; }
        for i in n_expired {
            let slot = expired[i];
            reactor_cleanup_slot(epfd, table, leftover_pool, slot, slot_pool);
            total_served = core::add_sat_i64(total_served, 1);
        }
        if n_expired < expired.len {
            break;
        }
    }
}

// Reclaims one expired connection slot during emergency saturation via fast SoA sweep.
fn reactor_evict_stale_slot(
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    total_served:  i64&,
) -> i64 {
    var expired: i64[1] = [0];
    let n = table.soa_table_sweep_expired(timer_wheel, expired[..]);
    if n > 0 {
        let slot = expired[0];
        reactor_cleanup_slot(epfd, table, leftover_pool, slot, slot_pool);
        total_served = core::add_sat_i64(total_served, 1);
        return alloc_reactor_conn_slot(slot_pool, table);
    }
    return -1;
}

inline fn reactor_init_slot_record(
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    client_fd:     i64,
    slot:          i64,
    timer_wheel:   core::TickTimerWheel&,
) {
    net::reactor_reset_accel_slot(server::g_reactor_accel, slot);
    reactor_free_slot_leftover(table, leftover_pool, slot);
    reactor_free_slot_tls_ct(table, leftover_pool, slot);
    table.fds[slot] = client_fd;
    table.timeout_ticks[slot] = core::tick_timer_arm(timer_wheel, 15);
    table.is_h2[slot] = false;
    table.h2_slot_map[slot] = -1;
    table.has_tls[slot] = false;
    table.tls_slots[slot] = 0xFFFF;
    table.has_peer_ip[slot] = false;
    table.peer_ip_hashes[slot] = 0;
    table.peer_ips[slot].clear();
    table.count = advance_high_water_mark(table.count, slot);
    table.conn_slots[slot] = server_internal::alloc_connection_slot(
        server::g_reactor_conn_pool, client_fd, 0,
    );
}

// Registers an accepted non-blocking client connection into an allocated slot.
inline fn reactor_register_client_slot(
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    client_fd:     i64,
    slot:          i64,
    timer_wheel:   core::TickTimerWheel&,
) {
    let _ = epfd;
    reactor_init_slot_record(table, leftover_pool, client_fd, slot, timer_wheel);
    net::reactor_bind_slot_backend(server::g_reactor_accel, slot, client_fd);
}

// Lazily resolves and caches the peer IP for a connection slot in SoAConnTable.
inline fn reactor_resolve_slot_peer_ip(table: server::SoAConnTable&, slot: i64, conn: i64) -> const u8[:] {
    if !table.has_peer_ip[slot] {
        var resolved_ip: u8[..64] = [];
        net::tcp_get_peer_ip(conn, resolved_ip);
        table.soa_table_set_peer_ip(slot, resolved_ip[..]);
    }
    return table.soa_table_get_peer_ip(slot);
}

fn reactor_accept_plain_fd(
    client_fd:     i64,
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    total_served:  i64&,
) {
    var slot = alloc_reactor_conn_slot(slot_pool, table);
    if slot < 0 {
        slot = reactor_evict_stale_slot(epfd, table, leftover_pool, slot_pool, timer_wheel, total_served);
    }
    if slot >= 0 {
        reactor_register_client_slot(epfd, table, leftover_pool, client_fd, slot, timer_wheel);
    } else {
        net::tcp_close(client_fd);
    }
}

// Drains non-blocking listener queue and accepts ready incoming connections into free slots.
fn reactor_drain_listener(
    listener_fd:   i64,
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    total_served:  i64&,
) {
    loop {
        let client_fd = net::tcp_accept_nonblocking(listener_fd);
        if client_fd <= 0 { break; }
        reactor_accept_plain_fd(client_fd, epfd, table, leftover_pool, slot_pool, timer_wheel, total_served);
    }
}

// Drains incoming client connection tasks from lock-free SPSC ring queue.
fn reactor_drain_worker_ring(
    ring:          const core::SpscRing&,
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    total_served:  i64&,
) {
    guard ring.is_open && ring.handle != 0 else { return; }
    loop {
        var client_val: u64 = 0;
        let popped = ring.spsc_pop(client_val);
        if !popped { break; }
        let client_fd = client_val as i64;
        guard client_fd > 0 else { continue; }
        reactor_accept_plain_fd(client_fd, epfd, table, leftover_pool, slot_pool, timer_wheel, total_served);
    }
}

inline fn reactor_read_single_turn(conn: i64, chunk: ReactorIngressBuf&, available: i64) -> i32 {
    let offset = chunk.len;
    guard offset >= 0 && offset + available <= chunk.bytes.len else { return -2; }
    let recvd = net::tcp_recv_nonblocking_slice(conn, chunk.bytes[offset..(offset + available)]);
    if recvd > 0 {
        chunk.len += recvd;
    }
    return recvd;
}

// Drains up to 4 turns of non-blocking TCP ingress into chunk buffer.
// Returns (any_recvd, is_closed).
fn reactor_read_bounded_turns(conn: i64, chunk: ReactorIngressBuf&) -> bool, bool {
    var any_recvd = false;
    for _ in 4 {
        let available = REACTOR_INGRESS_CAP - chunk.len;
        guard available > 0 else { break; }
        let recvd = reactor_read_single_turn(conn, chunk, available);
        if recvd == 0 || recvd == -1 {
            if any_recvd {
                return true, false;
            }
            return chunk.len > 0, true;
        }
        if recvd < 0 {
            break;
        }
        any_recvd = true;
        if recvd < available {
            break;
        }
    }
    return any_recvd, false;
}

// Restores buffered leftover bytes into active chunk and frees the pooled slice immediately.
fn reactor_load_leftover(
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot:          i64,
    chunk:         ReactorIngressBuf&,
) {
    guard slot >= 0 && slot < table.leftover_lens.len && slot < table.leftover_offs.len else { return; }
    let prev_len = table.leftover_lens[slot] as i64;
    let prev_off = table.leftover_offs[slot];
    let end_off = core::add_sat_i64(prev_off, prev_len);
    guard prev_len > 0 && prev_len <= REACTOR_LEFTOVER_CAP && prev_len <= chunk.bytes.len &&
        prev_off >= 0 && end_off <= leftover_pool.items.len else {
        table.leftover_lens[slot] = 0;
        table.leftover_offs[slot] = -1;
        return;
    }
    for p in prev_len {
        let src_idx = core::add_sat_i64(prev_off, p);
        if p < chunk.bytes.len && src_idx >= 0 && src_idx < leftover_pool.items.len {
            chunk.bytes[p] = leftover_pool.items[src_idx];
        }
    }
    chunk.len = prev_len;
    reactor_free_slot_leftover(table, leftover_pool, slot);
}

// Leases exact byte length from `slice_pool<u8>` to carry unconsumed wire bytes across turns.
fn reactor_save_leftover(
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot:          i64,
    rem:           const u8[:],
) -> bool {
    guard is_valid_slot(table, slot) && rem.len <= REACTOR_LEFTOVER_CAP else { return false; }
    reactor_free_slot_leftover(table, leftover_pool, slot);
    guard rem.len > 0 else { return true; }
    let leased = leftover_pool.alloc_slice(rem.len);
    for m in rem.len {
        leased[m] = rem[m];
    }
    table.leftover_offs[slot] = leftover_pool.items.range_index(
        leased, "reactor_save_leftover: invalid pool slice",
    );
    table.leftover_lens[slot] = rem.len as u16;
    server::g_default_reactor.leftover_leased_bytes = core::add_sat_i64(
        server::g_default_reactor.leftover_leased_bytes, rem.len,
    );
    server::g_default_reactor.leftover_leased_slots = core::add_sat_i64(
        server::g_default_reactor.leftover_leased_slots, 1,
    );
    server::g_default_reactor.leftover_pool_hwm = leftover_pool.items.len;
    return true;
}

fn reactor_send_slot_wire(table: const server::SoAConnTable&, slot: i64, conn: i64, wire: const u8[:]) -> bool {
    let in_accel_range = slot >= 0 && slot < net::REACTOR_ACCEL_SLOTS;
    if in_accel_range && server::g_reactor_accel.slot_ktls_rx[slot] {
        return net_internal::smartnic_send_record(conn, wire, rfc::TLS_CONTENT_APPLICATION_DATA) > 0;
    }
    if in_accel_range && server::g_reactor_accel.slot_accel[slot] {
        if table.has_tls[slot] && table.tls_slots[slot] != 0xFFFF {
            let seal_buf .= reactor_tls_seal_scratch();
            seal_buf.clear();
            if !tls::cipher_slot_seal_app_data(table.tls_slots[slot], wire, seal_buf) {
                return false;
            }
            return net::reactor_submit_accel_tx(server::g_reactor_accel, slot, conn, seal_buf[..]);
        }
        return net::reactor_submit_accel_tx(server::g_reactor_accel, slot, conn, wire);
    }
    if table.has_tls[slot] && table.tls_slots[slot] != 0xFFFF {
        let tr = table.slot_transport(slot);
        return tr.send(wire) > 0;
    }
    return net::reactor_drain_cork_wire(conn, wire);
}

fn reactor_handle_h2_ingress<Stage>(
    server:        server::HttpServer&,
    conn:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot:          i64,
    now_ns:        u64,
    chunk:         ReactorIngressBuf&,
    cork_wire:     u8[..65536]&,
    stage:         Stage&,
) -> bool {
    let now_ms = now_ns / 1000000;
    cork_wire.clear();
    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }
    let h2_idx = table.ensure_h2_session(slot, server.pipeline, server.server_name[..], now_ms);
    guard h2_idx >= 0 && h2_idx < server::g_default_reactor.h2_sessions.len else { return false; }
    let peer_ip_slice = reactor_resolve_slot_peer_ip(table, slot, conn);
    let consumed_h2, ok_h2 = server_internal::handle_h2_server_ingress(
        server::g_default_reactor.h2_sessions[h2_idx], server.pipeline, server.timer,
        peer_ip_slice, chunk.bytes[..chunk.len], now_ms, cork_wire, stage,
    );
    if cork_wire.len > 0 {
        if !reactor_send_slot_wire(table, slot, conn, cork_wire[..]) {
            return false;
        }
    }
    guard ok_h2 else { return false; }
    server.requests_processed = core::add_sat_u64(server.requests_processed, 1);
    if consumed_h2 < chunk.len {
        guard reactor_save_leftover(table, leftover_pool, slot, chunk.bytes[consumed_h2..chunk.len]) else {
            return false;
        }
    }
    return true;
}

inline fn reactor_close_and_inc(
    server:        server::HttpServer&,
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot:          i64,
    slot_pool:     ReactorSlotPool&,
    total_served:  i64&,
) {
    table.release_h2_session(slot, server.pipeline);
    reactor_cleanup_slot(epfd, table, leftover_pool, slot, slot_pool);
    total_served = core::add_sat_i64(total_served, 1);
}

inline fn reactor_request_slot_close(
    server:        server::HttpServer&,
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot:          i64,
    slot_pool:     ReactorSlotPool&,
    total_served:  i64&,
) {
    if slot >= 0 && slot < net::REACTOR_ACCEL_SLOTS && server::g_reactor_accel.slot_tx_inflight[slot] {
        server::g_reactor_accel.slot_close_after_tx[slot] = true;
        return;
    }
    reactor_close_and_inc(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
}

fn reactor_read_ktls_slot(conn: i64, chunk: ReactorIngressBuf&) -> bool, bool {
    guard chunk.len < REACTOR_INGRESS_CAP && chunk.len < chunk.bytes.len else { return false, false; }
    let start = chunk.len;
    let recvd, rtype = net_internal::smartnic_recv_record(conn, chunk.bytes[start..REACTOR_INGRESS_CAP]);
    let added, any_recvd, should_close = server::classify_ktls_recv_turn(
        recvd, rtype, chunk.bytes[start..REACTOR_INGRESS_CAP], start,
    );
    if added > 0 {
        chunk.len = core::add_sat_i64(start, added);
    }
    return any_recvd, should_close;
}

fn reactor_read_slot_turns(
    table: const server::SoAConnTable&,
    slot:  i64,
    conn:  i64,
    chunk: ReactorIngressBuf&,
) -> bool, bool {
    if slot >= 0 && slot < net::REACTOR_ACCEL_SLOTS && server::g_reactor_accel.slot_ktls_rx[slot] {
        return reactor_read_ktls_slot(conn, chunk);
    }
    if table.has_tls[slot] && table.tls_slots[slot] != 0xFFFF {
        let available = REACTOR_INGRESS_CAP - chunk.len;
        guard available > 0 && chunk.len < chunk.bytes.len else { return false, false; }
        let tr = table.slot_transport(slot);
        let recvd = tr.recv_slice(chunk.bytes[chunk.len..REACTOR_INGRESS_CAP], 50);
        if recvd == 0 || recvd == -1 {
            return chunk.len > 0, chunk.len == 0;
        }
        if recvd < 0 {
            return chunk.len > 0, false;
        }
        chunk.len += recvd;
        return true, false;
    }
    return reactor_read_bounded_turns(conn, chunk);
}

fn reactor_select_slot_peer_ip(
    server: const server::HttpServer&,
    table:  server::SoAConnTable&,
    slot:   i64,
    conn:   i64,
) -> const u8[:] {
    if server.pipeline.enable_rate_limiter || server.trust_proxy_headers || server.pipeline.trust_proxy_headers {
        return reactor_resolve_slot_peer_ip(table, slot, conn);
    }
    return "127.0.0.1";
}

fn reactor_process_slot_plaintext<Stage>(
    server:        server::HttpServer&,
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot:          i64,
    conn:          i64,
    slot_pool:     ReactorSlotPool&,
    now_ns:        u64,
    chunk:         ReactorIngressBuf&,
    cork_wire:     u8[..65536]&,
    total_served:  i64&,
    stage:         Stage&,
) {
    if table.is_h2[slot] || server::is_h2_client_preface(chunk.bytes[..chunk.len]) {
        if !reactor_handle_h2_ingress(server, conn, table, leftover_pool, slot, now_ns, chunk, cork_wire, stage) {
            reactor_request_slot_close(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        }
        return;
    }
    if server::is_partial_h2_client_preface(chunk.bytes[..chunk.len]) {
        if !reactor_save_leftover(table, leftover_pool, slot, chunk.bytes[..chunk.len]) {
            reactor_request_slot_close(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        }
        return;
    }

    let client_ip_slice = reactor_select_slot_peer_ip(server, table, slot, conn);
    cork_wire.clear();
    let _, consumed, ok, wants_close = server::handle_connection_wire_pipelined_stream(
        server, client_ip_slice, chunk.bytes[..chunk.len], now_ns, cork_wire, stage,
    );
    if cork_wire.len > 0 && !reactor_send_slot_wire(table, slot, conn, cork_wire[..]) {
        reactor_close_and_inc(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        return;
    }
    if !ok || wants_close {
        reactor_request_slot_close(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        return;
    }
    if consumed < chunk.len &&
        !reactor_save_leftover(table, leftover_pool, slot, chunk.bytes[consumed..chunk.len]) {
        reactor_request_slot_close(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
    }
}

// Processes non-blocking ingress traffic on a connection slot via bounded capacity-guarded read loop.
fn reactor_handle_ingress<Stage>(
    server:        server::HttpServer&,
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot:          i64,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    now_ns:        u64,
    chunk:         ReactorIngressBuf&,
    cork_wire:     u8[..65536]&,
    total_served:  i64&,
    stage:         Stage&,
) {
    let conn = table.fds[slot];
    let prev_len = table.leftover_lens[slot] as i64;
    if server.pipeline.enable_slowloris_timer {
        table.soa_table_touch(slot, core::tick_timer_arm(timer_wheel, 15));
    }

    chunk.len = 0;
    reactor_load_leftover(table, leftover_pool, slot, chunk);

    let any_recvd, is_closed = reactor_read_slot_turns(table, slot, conn, chunk);
    if is_closed {
        reactor_close_and_inc(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        return;
    }
    if !any_recvd && prev_len == 0 {
        return;
    }
    reactor_process_slot_plaintext(
        server, epfd, table, leftover_pool, slot, conn, slot_pool, now_ns, chunk, cork_wire, total_served, stage,
    );
}

fn reactor_append_chunk_bytes(chunk: ReactorIngressBuf&, src: const u8[:]) -> bool {
    let end_len = core::add_sat_i64(chunk.len, src.len);
    guard end_len <= REACTOR_INGRESS_CAP && end_len <= chunk.bytes.len else { return false; }
    for i in src.len {
        chunk.bytes[core::add_sat_i64(chunk.len, i)] = src[i];
    }
    chunk.len = end_len;
    return true;
}

inline fn reactor_slot_tls_ct_view(
    table:         const server::SoAConnTable&,
    leftover_pool: const slice_pool<u8>&,
    slot:          i64,
) -> const u8[:] {
    guard slot >= 0 && slot < table.tls_ct_offs.len && slot < table.tls_ct_lens.len else {
        return "";
    }
    let ct_off = table.tls_ct_offs[slot];
    let ct_len = table.tls_ct_lens[slot] as i64;
    let ct_end = core::add_sat_i64(ct_off, ct_len);
    guard ct_len > 0 && ct_off >= 0 && ct_end >= ct_off && ct_end <= leftover_pool.items.len else {
        return "";
    }
    return leftover_pool.items[ct_off..ct_end];
}

fn reactor_unseal_tls_slot_into_plain<B>(
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot:          i64,
    rx_raw:        const u8[:],
    plain_buf:     B&,
) -> tls::SliceUnsealStatus, bool {
    if slot < table.tls_ct_lens.len && table.tls_ct_lens[slot] == 0 {
        let cons, st = tls::cipher_slot_unseal_records(table.tls_slots[slot], rx_raw, plain_buf);
        if st != tls::SliceUnsealStatus.Error && st != tls::SliceUnsealStatus.Closed && cons < rx_raw.len {
            return st, reactor_append_slot_tls_ct(table, leftover_pool, slot, rx_raw[cons..]);
        }
        return st, true;
    }
    guard reactor_append_slot_tls_ct(table, leftover_pool, slot, rx_raw) else {
        return tls::SliceUnsealStatus.Error, false;
    }
    let cons, st = tls::cipher_slot_unseal_records(
        table.tls_slots[slot],
        reactor_slot_tls_ct_view(table, leftover_pool, slot),
        plain_buf,
    );
    reactor_consume_slot_tls_ct(table, leftover_pool, slot, cons);
    return st, true;
}

fn reactor_unseal_completed_tls_rx<Stage>(
    server:        server::HttpServer&,
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot:          i64,
    conn:          i64,
    rx_raw:        const u8[:],
    slot_pool:     ReactorSlotPool&,
    now_ns:        u64,
    chunk:         ReactorIngressBuf&,
    cork_wire:     u8[..65536]&,
    total_served:  i64&,
    stage:         Stage&,
) {
    let plain_buf .= reactor_tls_plain_scratch();
    plain_buf.clear();
    let st, ok = reactor_unseal_tls_slot_into_plain(table, leftover_pool, slot, rx_raw, plain_buf);
    if !ok || st == tls::SliceUnsealStatus.Error {
        reactor_close_and_inc(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        return;
    }
    if plain_buf.len > 0 {
        guard reactor_append_chunk_bytes(chunk, plain_buf[..]) else {
            reactor_close_and_inc(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
            return;
        }
        reactor_process_slot_plaintext(
            server, epfd, table, leftover_pool, slot, conn, slot_pool,
            now_ns, chunk, cork_wire, total_served, stage,
        );
    }
    if st == tls::SliceUnsealStatus.Closed && table.fds[slot] > 0 {
        reactor_request_slot_close(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
    }
}

fn reactor_handle_completed_rx<Stage>(
    server:        server::HttpServer&,
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot:          i64,
    rx_raw:        const u8[:],
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    now_ns:        u64,
    chunk:         ReactorIngressBuf&,
    cork_wire:     u8[..65536]&,
    total_served:  i64&,
    stage:         Stage&,
) {
    guard slot >= 0 && slot < table.fds.len else { return; }
    let conn = table.fds[slot];
    guard conn > 0 else { return; }
    if server.pipeline.enable_slowloris_timer {
        table.soa_table_touch(slot, core::tick_timer_arm(timer_wheel, 15));
    }
    chunk.len = 0;
    reactor_load_leftover(table, leftover_pool, slot, chunk);

    if slot < table.has_tls.len && slot < table.tls_slots.len &&
        table.has_tls[slot] && table.tls_slots[slot] != 0xFFFF {
        reactor_unseal_completed_tls_rx(
            server, epfd, table, leftover_pool, slot, conn, rx_raw, slot_pool,
            now_ns, chunk, cork_wire, total_served, stage,
        );
        return;
    }

    guard reactor_append_chunk_bytes(chunk, rx_raw) else {
        reactor_close_and_inc(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        return;
    }
    if chunk.len > 0 {
        reactor_process_slot_plaintext(
            server, epfd, table, leftover_pool, slot, conn, slot_pool, now_ns, chunk, cork_wire, total_served, stage,
        );
    }
}

// Dispatches ready epoll/kqueue events for reactor connection slots with `<Stage>`.
fn reactor_dispatch_events<Stage>(
    server:        server::HttpServer&,
    epfd:          i64,
    listener_fd:   i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    ready_udata:   const u64[:],
    now_ns:        u64,
    chunk:         ReactorIngressBuf&,
    cork_wire:     u8[..65536]&,
    total_served:  i64&,
    stage:         Stage&,
) {
    for i in ready_udata.len {
        let udata = ready_udata[i];
        if udata == net::EPOLL_LISTENER_TAG {
            reactor_drain_listener(
                listener_fd, epfd, table, leftover_pool, slot_pool, timer_wheel, total_served,
            );
            continue;
        }

        let slot = udata as i64;
        if !is_active_slot(table, slot) {
            continue;
        }

        reactor_handle_ingress(
            server,
            epfd,
            table,
            leftover_pool,
            slot,
            slot_pool,
            timer_wheel,
            now_ns,
            chunk,
            cork_wire,
            total_served,
            stage,
        );
    }
}

// Computes dynamic wait timeout depending on worker ring state.
inline fn reactor_epoll_timeout(ring: const core::SpscRing&) -> i32 {
    guard ring.is_open else { return 200; }
    return if ring.spsc_count() > 0 { 0 } else { 10 };
}

fn reactor_dispatch_single_rio_result<Stage>(
    server:        server::HttpServer&,
    res:           const net_internal::RioResult&,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    now_ns:        u64,
    chunk:         ReactorIngressBuf&,
    cork_wire:     u8[..65536]&,
    total_served:  i64&,
    stage:         Stage&,
) {
    let slot, ok_tok = net::reactor_accel_match_token(server::g_reactor_accel, res.socket_context);
    guard ok_tok && is_active_slot(table, slot) else { return; }
    let epfd = server::g_reactor_accel.epfd;

    if res.request_context == net::REACTOR_REQ_TX_TAG {
        server::g_reactor_accel.slot_tx_inflight[slot] = false;
        if res.status != 0 || server::g_reactor_accel.slot_close_after_tx[slot] {
            reactor_close_and_inc(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        }
        return;
    }
    guard res.request_context == net::REACTOR_REQ_RX_TAG else { return; }
    if res.status != 0 || res.bytes_transferred == 0 {
        reactor_request_slot_close(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        return;
    }

    let rx_len = min(res.bytes_transferred as i64, net::REACTOR_ACCEL_BUF_SIZE);
    let rx_off = (core::shl_sat_u64(slot as u64, 13) as u32) as i64;
    let rx_end = core::add_sat_i64(rx_off, rx_len);
    reactor_handle_completed_rx(
        server, epfd, table, leftover_pool, slot, server::g_reactor_accel.slab[rx_off..rx_end],
        slot_pool, timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
    );
    if is_active_slot(table, slot) && !server::g_reactor_accel.slot_close_after_tx[slot] {
        if !net::reactor_post_rio_slot_rx(server::g_reactor_accel, slot) {
            reactor_request_slot_close(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        }
    }
}

fn reactor_accept_rio_tls_fd<Stage>(
    server:        server::HttpServer&,
    client_fd:     i64,
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    tls_config:    const tls::ServerHandshakeConfig&,
    now_ns:        u64,
    chunk:         ReactorIngressBuf&,
    cork_wire:     u8[..65536]&,
    total_served:  i64&,
    stage:         Stage&,
) {
    var slot = alloc_reactor_conn_slot(slot_pool, table);
    if slot < 0 {
        slot = reactor_evict_stale_slot(epfd, table, leftover_pool, slot_pool, timer_wheel, total_served);
    }
    guard slot >= 0 && slot < net::REACTOR_ACCEL_SLOTS else {
        net::tcp_close(client_fd);
        total_served = core::add_sat_i64(total_served, 1);
        return;
    }
    reactor_init_slot_record(table, leftover_pool, client_fd, slot, timer_wheel);
    net::ensure_reactor_accel_slab(server::g_reactor_accel);
    let tok = net::reactor_accel_slot_token(server::g_reactor_accel, slot);
    let rq = net_internal::native_rio_create_rq_ctx(
        client_fd, 16, 16, server::g_reactor_accel.rio_cq, server::g_reactor_accel.rio_tx_cq, tok,
    );
    guard rq != 0 else {
        reactor_cleanup_slot(epfd, table, leftover_pool, slot, slot_pool);
        total_served = core::add_sat_i64(total_served, 1);
        return;
    }
    server::g_reactor_accel.slot_rio_rq[slot] = rq;
    server::g_reactor_accel.slot_accel[slot] = true;
    server::g_reactor_accel.active_accel_slots = core::add_sat_i64(server::g_reactor_accel.active_accel_slots, 1);

    let rx_off = core::shl_sat_u64(slot as u64, 13) as u32;
    let tx_off = rx_off | 4096;
    net_internal::native_rio_hs_begin(
        client_fd, rq, server::g_reactor_accel.rio_cq, server::g_reactor_accel.rio_tx_cq,
        server::g_reactor_accel.rio_buf_id, server::g_reactor_accel.slab[..],
        rx_off, tx_off, net::REACTOR_ACCEL_BUF_SIZE as u32, tok,
    );
    let tls_slot, ok_hs = tls::server_handshake(client_fd, tls_config);
    var hs_leftover: u8[4096] = [0; 4096];
    let hs_rem = net_internal::native_rio_hs_end(hs_leftover[..]);
    guard ok_hs else {
        reactor_cleanup_slot(epfd, table, leftover_pool, slot, slot_pool);
        total_served = core::add_sat_i64(total_served, 1);
        return;
    }
    table.has_tls[slot] = true;
    table.tls_slots[slot] = tls_slot;
    if hs_rem > 0 {
        let rem_n = min(hs_rem as i64, 4096);
        reactor_handle_completed_rx(
            server, epfd, table, leftover_pool, slot, hs_leftover[..rem_n],
            slot_pool, timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
        );
    }
    if is_active_slot(table, slot) && !server::g_reactor_accel.slot_close_after_tx[slot] {
        if !net::reactor_post_rio_slot_rx(server::g_reactor_accel, slot) {
            reactor_request_slot_close(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        }
    }
}

fn reactor_poll_rio_listener<Stage>(
    server:        server::HttpServer&,
    draining:      bool,
    tls_config:    const tls::ServerHandshakeConfig&,
    is_tls:        bool,
    timeout_ms:    i32,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    now_ns:        u64,
    chunk:         ReactorIngressBuf&,
    cork_wire:     u8[..65536]&,
    total_served:  i64&,
    stage:         Stage&,
) {
    let lfd = server::g_reactor_accel.rio_listener_fd;
    guard !draining && lfd > 0 else { return; }
    let initial_wait_ms = if server::g_reactor_accel.active_accel_slots == 0 && timeout_ms > 0 {
        min(timeout_ms, 5)
    } else {
        0
    };
    let epfd = server::g_reactor_accel.epfd;
    for attempt in 16 {
        let wait_ms = if attempt == 0 { initial_wait_ms } else { 0 };
        let cfd = net_internal::native_rio_poll_accept(lfd, wait_ms);
        if cfd <= 0 { break; }
        if is_tls {
            reactor_accept_rio_tls_fd(
                server, cfd, epfd, table, leftover_pool, slot_pool, timer_wheel,
                tls_config, now_ns, chunk, cork_wire, total_served, stage,
            );
        } else {
            reactor_accept_plain_fd(cfd, epfd, table, leftover_pool, slot_pool, timer_wheel, total_served);
        }
    }
}

fn reactor_flush_rio_tx_closes(
    server:        server::HttpServer&,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    total_served:  i64&,
) {
    let epfd = server::g_reactor_accel.epfd;
    for i in server::g_reactor_accel.rio_tx_close_queue.len {
        let s = server::g_reactor_accel.rio_tx_close_queue[i];
        if is_active_slot(table, s) {
            reactor_close_and_inc(server, epfd, table, leftover_pool, s, slot_pool, total_served);
        }
    }
    server::g_reactor_accel.rio_tx_close_queue.clear();
}

fn reactor_step_rio_completions<Stage>(
    server:        server::HttpServer&,
    draining:      bool,
    tls_config:    const tls::ServerHandshakeConfig&,
    is_tls:        bool,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    timeout_ms:    i32,
    now_ns:        u64,
    chunk:         ReactorIngressBuf&,
    cork_wire:     u8[..65536]&,
    total_served:  i64&,
    stage:         Stage&,
) -> u32 {
    guard server::g_reactor_accel.mode == net::ReactorAccelMode.Rio &&
        server::g_reactor_accel.rio_cq != 0 else {
        return 0;
    }
    reactor_poll_rio_listener(
        server, draining, tls_config, is_tls, timeout_ms,
        table, leftover_pool, slot_pool, timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
    );
    guard server::g_reactor_accel.active_accel_slots > 0 else { return 0; }
    let tx_n = net::reactor_drain_rio_tx_cq(server::g_reactor_accel);
    reactor_flush_rio_tx_closes(server, table, leftover_pool, slot_pool, total_served);
    var rio_results: net_internal::RioResult[..64] = [];
    var n = net_internal::rio_drain_completions(server::g_reactor_accel.rio_cq, rio_results);
    if n == 0 && tx_n == 0 && timeout_ms > 0 {
        let _ = net_internal::rio_wait_cq(server::g_reactor_accel.rio_cq, min(timeout_ms, 5));
        n = net_internal::rio_drain_completions(server::g_reactor_accel.rio_cq, rio_results);
    }
    for i in rio_results.len {
        reactor_dispatch_single_rio_result(
            server, rio_results[i], table, leftover_pool, slot_pool,
            timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
        );
    }
    let _ = net::reactor_drain_rio_tx_cq(server::g_reactor_accel);
    reactor_flush_rio_tx_closes(server, table, leftover_pool, slot_pool, total_served);
    return n;
}

fn reactor_accept_single_tls_fd(
    server:        const server::HttpServer&,
    client_fd:     i64,
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    tls_config:    const tls::ServerHandshakeConfig&,
    total_served:  i64&,
) {
    let tls_slot, ok_hs = tls::server_handshake(client_fd, tls_config);
    if !ok_hs {
        net::tcp_close(client_fd);
        total_served = core::add_sat_i64(total_served, 1);
        return;
    }
    var slot = alloc_reactor_conn_slot(slot_pool, table);
    if slot < 0 {
        slot = reactor_evict_stale_slot(epfd, table, leftover_pool, slot_pool, timer_wheel, total_served);
    }
    if slot >= 0 {
        reactor_init_slot_record(table, leftover_pool, client_fd, slot, timer_wheel);
        table.has_tls[slot] = true;
        table.tls_slots[slot] = tls_slot;
        if server.enable_ktls_offload && slot < net::REACTOR_ACCEL_SLOTS {
            let sess, ok_ktls = tls::try_enable_ktls(tls_slot, client_fd);
            if ok_ktls && sess.rx_offloaded && sess.tx_offloaded {
                server::g_reactor_accel.slot_ktls_rx[slot] = true;
            }
        }
        net::reactor_bind_slot_backend(server::g_reactor_accel, slot, client_fd);
    } else {
        tls::transport_close(client_fd, tls_slot);
        total_served = core::add_sat_i64(total_served, 1);
    }
}

fn reactor_dispatch_uring_recv_cqe<Stage>(
    server:        server::HttpServer&,
    cqe:           const net_internal::UringCqe&,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    now_ns:        u64,
    chunk:         ReactorIngressBuf&,
    cork_wire:     u8[..65536]&,
    total_served:  i64&,
    stage:         Stage&,
) {
    let has_buf = (cqe.flags & net_internal::URING_CQE_F_BUFFER) != 0;
    let bid = ((cqe.flags >> 16) & 0xFFFF) as u16;
    let slot, ok_tok = net::reactor_accel_match_token(server::g_reactor_accel, cqe.user_data);
    guard ok_tok && is_active_slot(table, slot) else {
        if has_buf {
            net_internal::uring_recycle_pbuf(server::g_reactor_accel.uring_pbuf, bid);
        }
        return;
    }
    if cqe.res <= 0 {
        if has_buf {
            net_internal::uring_recycle_pbuf(server::g_reactor_accel.uring_pbuf, bid);
        }
        reactor_request_slot_close(
            server, server::g_reactor_accel.epfd, table, leftover_pool, slot, slot_pool, total_served,
        );
        return;
    }

    var rx_tmp: u8[4096] = [0; 4096];
    var copied: i32      = 0;
    if has_buf {
        copied = net_internal::uring_read_pbuf(server::g_reactor_accel.uring_pbuf, bid, cqe.res, rx_tmp[..]);
        net_internal::uring_recycle_pbuf(server::g_reactor_accel.uring_pbuf, bid);
    }
    if copied > 0 {
        reactor_handle_completed_rx(
            server, server::g_reactor_accel.epfd, table, leftover_pool, slot, rx_tmp[..copied],
            slot_pool, timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
        );
    }
    if (cqe.flags & net_internal::URING_CQE_F_MORE) == 0 &&
        is_active_slot(table, slot) &&
        !server::g_reactor_accel.slot_close_after_tx[slot] {
        net::reactor_arm_uring_slot_rx(server::g_reactor_accel, slot, table.fds[slot]);
    }
}

fn reactor_dispatch_uring_accept_cqe(
    server:        const server::HttpServer&,
    listener_fd:   i64,
    draining:      bool,
    tls_config:    const tls::ServerHandshakeConfig&,
    is_tls:        bool,
    cqe:           const net_internal::UringCqe&,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    total_served:  i64&,
) {
    let epfd = server::g_reactor_accel.epfd;
    if cqe.res > 0 {
        let cfd = cqe.res as i64;
        net::tcp_set_nonblocking(cfd, true);
        if is_tls {
            reactor_accept_single_tls_fd(
                server, cfd, epfd, table, leftover_pool, slot_pool, timer_wheel, tls_config, total_served,
            );
        } else {
            reactor_accept_plain_fd(cfd, epfd, table, leftover_pool, slot_pool, timer_wheel, total_served);
        }
    }
    if (cqe.flags & net_internal::URING_CQE_F_MORE) == 0 && !draining && listener_fd > 0 {
        net::reactor_arm_uring_accept(server::g_reactor_accel, listener_fd);
    }
}

fn reactor_dispatch_uring_send_cqe(
    server:        server::HttpServer&,
    cqe:           const net_internal::UringCqe&,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    total_served:  i64&,
) {
    let slot, ok_tok = net::reactor_accel_match_token(server::g_reactor_accel, cqe.user_data);
    guard ok_tok && is_active_slot(table, slot) else { return; }
    if (cqe.flags & net_internal::URING_CQE_F_NOTIF) != 0 { return; }
    server::g_reactor_accel.slot_tx_inflight[slot] = false;
    if cqe.res <= 0 || server::g_reactor_accel.slot_close_after_tx[slot] {
        reactor_close_and_inc(
            server, server::g_reactor_accel.epfd, table, leftover_pool, slot, slot_pool, total_served,
        );
    }
}

fn reactor_dispatch_uring_poll_cqe<Stage>(
    server:        server::HttpServer&,
    cqe:           const net_internal::UringCqe&,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    now_ns:        u64,
    chunk:         ReactorIngressBuf&,
    cork_wire:     u8[..65536]&,
    total_served:  i64&,
    stage:         Stage&,
) {
    let slot, ok_tok = net::reactor_accel_match_token(server::g_reactor_accel, cqe.user_data);
    guard ok_tok && is_active_slot(table, slot) else { return; }
    let epfd = server::g_reactor_accel.epfd;
    if cqe.res < 0 {
        reactor_close_and_inc(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        return;
    }
    reactor_handle_ingress(
        server, epfd, table, leftover_pool, slot, slot_pool,
        timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
    );
    if is_active_slot(table, slot) && !server::g_reactor_accel.slot_close_after_tx[slot] {
        net::reactor_arm_uring_slot_rx(server::g_reactor_accel, slot, table.fds[slot]);
    }
}

fn reactor_dispatch_single_uring_cqe<Stage>(
    server:        server::HttpServer&,
    listener_fd:   i64,
    draining:      bool,
    tls_config:    const tls::ServerHandshakeConfig&,
    is_tls:        bool,
    cqe:           const net_internal::UringCqe&,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    now_ns:        u64,
    chunk:         ReactorIngressBuf&,
    cork_wire:     u8[..65536]&,
    total_served:  i64&,
    stage:         Stage&,
) {
    let kind = cqe.user_data & net::REACTOR_URING_TAG_KIND_MASK;
    if kind == net::REACTOR_URING_TAG_ACCEPT {
        reactor_dispatch_uring_accept_cqe(
            server, listener_fd, draining, tls_config, is_tls, cqe,
            table, leftover_pool, slot_pool, timer_wheel, total_served,
        );
    } else if kind == net::REACTOR_URING_TAG_SEND {
        reactor_dispatch_uring_send_cqe(server, cqe, table, leftover_pool, slot_pool, total_served);
    } else if kind == net::REACTOR_URING_TAG_POLL {
        reactor_dispatch_uring_poll_cqe(
            server, cqe, table, leftover_pool, slot_pool,
            timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
        );
    } else if kind == net::REACTOR_URING_TAG_RECV {
        reactor_dispatch_uring_recv_cqe(
            server, cqe, table, leftover_pool, slot_pool,
            timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
        );
    }
}

fn reactor_step_uring_completions<Stage>(
    server:        server::HttpServer&,
    listener_fd:   i64,
    draining:      bool,
    tls_config:    const tls::ServerHandshakeConfig&,
    is_tls:        bool,
    timeout_ms:    i32,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    now_ns:        u64,
    chunk:         ReactorIngressBuf&,
    cork_wire:     u8[..65536]&,
    total_served:  i64&,
    stage:         Stage&,
) -> i32 {
    guard server::g_reactor_accel.mode == net::ReactorAccelMode.IoUring &&
        server::g_reactor_accel.uring_fd >= 0 else {
        return 0;
    }
    var cqes: net_internal::UringCqe[64] = [net_internal::UringCqe { .. }; 64];
    let min_c: u32 = if timeout_ms > 0 { 1 } else { 0 };
    let timeout_ns = net_internal::timeout_ms_to_ns(timeout_ms);
    let n = net_internal::uring_wait_cqes(server::g_reactor_accel.uring_fd, cqes[..], min_c, timeout_ns);
    guard n > 0 else { return 0; }
    let limit = min(n as i64, 64);
    for i in limit {
        reactor_dispatch_single_uring_cqe(
            server, listener_fd, draining, tls_config, is_tls, cqes[i], table,
            leftover_pool, slot_pool, timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
        );
    }
    return n;
}

inline fn reactor_emit_slot_goaway(table: const server::SoAConnTable&, slot: i64, cork_wire: u8[..65536]&) {
    guard is_active_slot(table, slot) && table.is_h2[slot] else { return; }
    let fd = table.fds[slot];
    let h2_idx = table.h2_slot_map[slot] as i64;
    guard h2_idx >= 0 && h2_idx < server::g_default_reactor.h2_sessions.len else { return; }
    cork_wire.clear();
    server_internal::initiate_graceful_shutdown(server::g_default_reactor.h2_sessions[h2_idx], cork_wire);
    guard cork_wire.len > 0 else { return; }
    let _ = reactor_send_slot_wire(table, slot, fd, cork_wire[..]);
}

fn reactor_step_drain_gate(
    server:            server::HttpServer&,
    epfd:              i64,
    listener_fd:       i64,
    table:             const server::SoAConnTable&,
    cork_wire:         u8[..65536]&,
    draining:          bool&,
    drain_deadline_ns: u64&,
) -> bool {
    let _ = epfd;
    if !draining && server::should_stop(server) {
        draining = true;
        server.is_running = false;
        net::reactor_detach_listener(server::g_reactor_accel, listener_fd);
        let limit = min(max(table.count, 0), table.fds.len);
        for s in limit {
            reactor_emit_slot_goaway(table, s, cork_wire);
        }
        drain_deadline_ns = core::add_sat_u64(core::monotonic_now().as_nanos(), server.shutdown_grace_ns);
    }
    guard draining else { return false; }
    return table.count <= 0 || core::monotonic_now().as_nanos() >= drain_deadline_ns;
}

// Cleans up all active connection slots when shutting down reactor loop.
fn reactor_cleanup_all(
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
) {
    for s in table.fds.len {
        if table.fds[s] > 0 {
            reactor_cleanup_slot(epfd, table, leftover_pool, s, slot_pool);
        }
    }
}

inline fn reactor_poll_sweep(
    epfd:           i64,
    table:          server::SoAConnTable&,
    leftover_pool:  slice_pool<u8>&,
    slot_pool:      ReactorSlotPool&,
    timer_wheel:    core::TickTimerWheel&,
    n:              i32,
    turn:           i64,
    last_sweep_sec: i64&,
    total_served:   i64&,
    cached_ns:      u64&,
    cached_sec:     i64&,
    enable_timer:   bool,
) {
    if n > 0 && (turn & 511) != 0 && cached_sec > 0 { return; }
    let now_mono = core::monotonic_now();
    cached_ns = now_mono.as_nanos();
    cached_sec = (cached_ns / 1000000000) as i64;
    if enable_timer {
        reactor_sweep_timeouts(
            epfd, table, leftover_pool, slot_pool, timer_wheel, cached_sec, last_sweep_sec, total_served,
        );
    }
}

inline fn reset_reactor_state(state: ReactorState&) {
    for i in state.h2_sessions.len {
        state.h2_in_use[i] = false;
    }
    state.leftover_leased_bytes = 0;
    state.leftover_leased_slots = 0;
    state.leftover_pool_hwm = 0;
    server_internal::reset_connection_pool_inplace(server::g_reactor_conn_pool);
    ensure_reactor_ingress_buf(server::g_reactor_chunk);
    server::g_reactor_chunk.len = 0;
    ensure_reactor_cork_buf();
    server::g_reactor_cork_bufs[0].clear();
}

inline fn reactor_prepare_loop(server: server::HttpServer&, listener_fd: i64) -> bool {
    reset_reactor_state(server::g_default_reactor);
    guard net::reactor_init_accel(server::g_reactor_accel, server.accel_mode, listener_fd) else {
        return false;
    }
    server::init_run_state(server);
    return true;
}

fn reactor_accept_tls_client(
    server:        const server::HttpServer&,
    listener_fd:   i64,
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    tls_config:    const tls::ServerHandshakeConfig&,
    total_served:  i64&,
) {
    loop {
        let client_fd = net::tcp_accept_nonblocking(listener_fd);
        if client_fd <= 0 { break; }
        reactor_accept_single_tls_fd(
            server, client_fd, epfd, table, leftover_pool, slot_pool, timer_wheel, tls_config, total_served,
        );
    }
}

fn reactor_dispatch_tls_events<Stage>(
    server:        server::HttpServer&,
    epfd:          i64,
    listener_fd:   i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    tls_config:    const tls::ServerHandshakeConfig&,
    ready_udata:   const u64[:],
    now_ns:        u64,
    chunk:         ReactorIngressBuf&,
    cork_wire:     u8[..65536]&,
    total_served:  i64&,
    stage:         Stage&,
) {
    for i in ready_udata.len {
        let udata = ready_udata[i];
        if udata == net::EPOLL_LISTENER_TAG {
            reactor_accept_tls_client(
                server, listener_fd, epfd, table, leftover_pool, slot_pool,
                timer_wheel, tls_config, total_served,
            );
            continue;
        }
        let slot = udata as i64;
        if is_active_slot(table, slot) {
            reactor_handle_ingress(
                server, epfd, table, leftover_pool, slot, slot_pool,
                timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
            );
        }
    }
}

inline fn dispatch_h3_udp_datagram(
    server:    server::HttpServer&,
    udp_fd:    i64,
    h3_conn:   http3::Connection&,
    served:    i64,
    peer_ip4:  u32,
    peer_port: u16,
    rx_slice:  const u8[:],
    now_ns:    u64,
    tx_wire:   u8[..1472]&,
    tx_queue:  net::UdpBatchQueue&,
) {
    let stream_id = core::shl_sat_u64((served & 15) as u64, 2);
    for st_i in h3_conn.streams.len {
        if h3_conn.streams[st_i].stream_id == stream_id {
            h3_conn.streams[st_i] = http3::StreamEntry { stream_id: stream_id, .. };
        }
    }
    var peer_ip_str: u8[..32] = [];
    core::format_u64_dec((peer_ip4 >> 24) & 0xFF, peer_ip_str);
    let _ = peer_ip_str.try_push('.');
    core::format_u64_dec((peer_ip4 >> 16) & 0xFF, peer_ip_str);
    let _ = peer_ip_str.try_push('.');
    core::format_u64_dec((peer_ip4 >> 8) & 0xFF, peer_ip_str);
    let _ = peer_ip_str.try_push('.');
    core::format_u64_dec(peer_ip4 & 0xFF, peer_ip_str);
    let _ = server_internal::with_connection_slot(server::g_reactor_conn_pool, udp_fd, now_ns as i64) { conn_slot =>
        server_internal::notify_request_start(conn_slot.timer);
        if server.handle_h3_server_datagram(h3_conn, stream_id, peer_ip_str[..], rx_slice, now_ns, tx_wire) {
            let dgram, ok_dg = net::build_udp_datagram(tx_wire[..], peer_ip4, peer_port);
            if ok_dg {
                let _, _ = net::enqueue_udp_datagram(tx_queue, udp_fd as i32, dgram);
            }
        }
        server_internal::notify_request_end(conn_slot.timer);
    };
}

fn encode_h3_connection_close<B>(err_code: u64, out_wire: B&) {
    out_wire.clear();
    quic::encode_varint(0x1D, out_wire);
    quic::encode_varint(err_code, out_wire);
    quic::encode_varint(0, out_wire);
}

inline fn is_h3_wire_frame_bounded(datagram: const u8[:], hdr: const http3::FrameHeader&) -> bool {
    return ((hdr.header_len + hdr.payload_len) as i64) <= datagram.len;
}

fn handle_h3_endpoint_settings<B>(
    ep:       server::H3ServerEndpoint&,
    hdr:      const http3::FrameHeader&,
    payload:  const u8[:],
    out_wire: B&,
) -> bool {
    let err = http3::handle_peer_control_frame(ep.conn, hdr, payload);
    guard err == rfc::H3_ERR_NO_ERROR else {
        encode_h3_connection_close(err, out_wire);
        return true;
    }
    out_wire.clear();
    out_wire.push(0x04);
    out_wire.push(0x00);
    return true;
}

fn handle_h3_endpoint_request<B>(
    server:    server::HttpServer&,
    ep:        server::H3ServerEndpoint&,
    client_ip: const u8[:],
    datagram:  const u8[:],
    now_ns:    u64,
    out_wire:  B&,
) -> bool {
    for st_i in ep.conn.streams.len {
        if ep.conn.streams[st_i].stream_id == 0 {
            ep.conn.streams[st_i] = http3::StreamEntry { stream_id: 0, .. };
        }
    }
    ep.conn.state = http3::ConnState.Active;
    ep.conn.error_code = rfc::H3_ERR_NO_ERROR;

    let ok = server::handle_h3_server_datagram(server, ep.conn, 0, client_ip, datagram, now_ns, out_wire);
    if ok && out_wire.len > 0 {
        return true;
    }
    let err_code = if ep.conn.error_code != rfc::H3_ERR_NO_ERROR {
        ep.conn.error_code
    } else {
        rfc::H3_ERR_GENERAL_PROTOCOL
    };
    encode_h3_connection_close(err_code, out_wire);
    return true;
}

fn handle_h3_endpoint_frame<B>(
    server:    server::HttpServer&,
    ep:        server::H3ServerEndpoint&,
    client_ip: const u8[:],
    datagram:  const u8[:],
    now_ns:    u64,
    out_wire:  B&,
) -> bool {
    let hdr, ok_hdr = http3::parse_frame_header(datagram, 0);
    guard ok_hdr && is_h3_wire_frame_bounded(datagram, hdr) else { return false; }

    let start = hdr.header_len as i64;
    let end = (hdr.header_len + hdr.payload_len) as i64;
    let payload = datagram[start..end];

    if hdr.frame_type == rfc::H3_FRAME_SETTINGS {
        return handle_h3_endpoint_settings(ep, hdr, payload, out_wire);
    }
    if hdr.frame_type == rfc::H3_FRAME_HEADERS || hdr.frame_type == rfc::H3_FRAME_DATA {
        return handle_h3_endpoint_request(server, ep, client_ip, datagram, now_ns, out_wire);
    }
    return false;
}

fn encode_quic_version_negotiation<B>(hdr: const quic::QuicHeader&, out_wire: B&) {
    out_wire.clear();
    out_wire.push(0xC0);
    out_wire.append_u32_be(rfc::QUIC_VERSION_NEGOTIATION);
    out_wire.push(hdr.scid.len as u8);
    out_wire.append(hdr.scid[..]);
    out_wire.push(hdr.dcid.len as u8);
    out_wire.append(hdr.dcid[..]);
    out_wire.append_u32_be(rfc::QUIC_VERSION_1);
}

fn encode_quic_server_initial<B>(
    ep:       const server::H3ServerEndpoint&,
    hdr:      const quic::QuicHeader&,
    out_wire: B&,
) {
    out_wire.clear();
    out_wire.push(0xC1);
    out_wire.append_u32_be(rfc::QUIC_VERSION_1);
    out_wire.push(hdr.scid.len as u8);
    out_wire.append(hdr.scid[..]);
    let srv_cid: const u8[:] = "\x01\x02\x03\x04\x05\x06\x07\x08";
    out_wire.push(srv_cid.len as u8);
    out_wire.append(srv_cid);
    out_wire.push(0);

    var h3_ctrl: u8[..128] = [];
    quic::encode_varint(rfc::H3_STREAM_CONTROL, h3_ctrl);
    http3::encode_settings_frame(h3_ctrl, ep.conn.local_settings);
    http3::encode_frame_header(h3_ctrl, 0x21, 0);

    let payload_len = (2 + h3_ctrl.len) as u64;
    quic::encode_varint(payload_len, out_wire);
    out_wire.append_u16_be(1);
    out_wire.append(h3_ctrl[..]);
}

fn format_l2_client_ip(ep: const net_internal::L2UdpEndpoint&) -> u8[..48] {
    var out_ip: u8[..48] = [];
    if ep.is_ipv6 {
        let _ = out_ip.try_append("ipv6-l2");
        return out_ip;
    }
    core::format_u64_dec(ep.ip[0], out_ip);
    let _ = out_ip.try_push('.');
    core::format_u64_dec(ep.ip[1], out_ip);
    let _ = out_ip.try_push('.');
    core::format_u64_dec(ep.ip[2], out_ip);
    let _ = out_ip.try_push('.');
    core::format_u64_dec(ep.ip[3], out_ip);
    return out_ip;
}

fn process_h3_l2_frame<B>(
    server:       server::HttpServer&,
    ep:           server::H3ServerEndpoint&,
    local_ep:     const net_internal::L2UdpEndpoint&,
    rx_frame:     const u8[:],
    ip_id:        u16,
    now_ns:       u64,
    out_tx_frame: B&,
) -> bool {
    let parsed, ok_dec = net_internal::decode_l2_udp_frame(rx_frame);
    guard ok_dec else { return false; }
    guard local_ep.port == 0 || parsed.dst.port == local_ep.port else { return false; }
    let pay_end = core::add_sat_i64(parsed.payload_offset, parsed.payload_len);
    guard pay_end <= rx_frame.len else { return false; }
    let cli_ip = format_l2_client_ip(parsed.src);
    var udp_reply: u8[..1472] = [];
    guard server::handle_h3_quic_datagram(
        server,
        ep,
        cli_ip[..],
        rx_frame[parsed.payload_offset..pay_end],
        now_ns,
        udp_reply,
    ) else {
        return false;
    }
    out_tx_frame.clear();
    return net_internal::encode_l2_udp_frame(parsed.dst, parsed.src, udp_reply[..], ip_id, out_tx_frame);
}

fn recycle_af_xdp_completions(xsk: net_internal::AfXdpSocket&) {
    for _ in 64 {
        let comp_addr, ok_c = net_internal::af_xdp_complete_pop(xsk);
        guard ok_c else { break; }
        let _ = net_internal::af_xdp_fill_push(xsk, comp_addr);
    }
}

fn serve_h3_af_xdp(
    server:      server::HttpServer&,
    ep:          server::H3ServerEndpoint&,
    cfg:         const server::H3L2Config&,
    xsk:         net_internal::AfXdpSocket&,
    max_packets: i64,
) -> i64 {
    var rx_frame: u8[..2048] = [];
    var tx_frame: u8[..2048] = [];
    var served:   i64        = 0;
    var ip_seq:   u64        = 1;

    while max_packets == 0 || served < max_packets {
        recycle_af_xdp_completions(xsk);
        let desc, ok_rx = net_internal::af_xdp_rx_poll(xsk);
        guard ok_rx else { break; }
        if !net_internal::af_xdp_umem_read(xsk, desc.addr, desc.len, rx_frame) {
            let _ = net_internal::af_xdp_fill_push(xsk, desc.addr);
            continue;
        }
        let now_ns = core::monotonic_now().as_nanos();
        let pkt_id = (ip_seq & 0xFFFF) as u16;
        if process_h3_l2_frame(server, ep, cfg.local_ep, rx_frame[..], pkt_id, now_ns, tx_frame) {
            if net_internal::af_xdp_umem_write(xsk, desc.addr, tx_frame[..]) {
                let tx_desc = net_internal::XdpDesc { addr: desc.addr, len: tx_frame.len as u32, options: 0 };
                let _ = net_internal::af_xdp_tx_submit(xsk, tx_desc);
                served = core::add_sat_i64(served, 1);
            } else {
                let _ = net_internal::af_xdp_fill_push(xsk, desc.addr);
            }
        } else {
            let _ = net_internal::af_xdp_fill_push(xsk, desc.addr);
        }
        ip_seq = core::add_sat_u64(ip_seq, 1);
    }
    return served;
}

fn serve_h3_dpdk(
    server:      server::HttpServer&,
    ep:          server::H3ServerEndpoint&,
    cfg:         const server::H3L2Config&,
    max_packets: i64,
) -> i64 {
    var rx_burst: u8[..2048][..32] = [];
    var tx_frame: u8[..2048]       = [];
    var served:   i64              = 0;
    var ip_seq:   u64              = 1;

    while max_packets == 0 || served < max_packets {
        let n_rx = net_internal::dpdk_rx_burst_read(cfg.dpdk_port_id, cfg.dpdk_queue_id, rx_burst);
        guard n_rx > 0 else { break; }
        let now_ns = core::monotonic_now().as_nanos();
        for i in n_rx {
            if max_packets > 0 && served >= max_packets { break; }
            let pkt_id = (ip_seq & 0xFFFF) as u16;
            let encoded = process_h3_l2_frame(server, ep, cfg.local_ep, rx_burst[i][..], pkt_id, now_ns, tx_frame);
            if encoded && net_internal::dpdk_tx_packet_push(cfg.dpdk_port_id, cfg.dpdk_queue_id, tx_frame[..]) {
                served = core::add_sat_i64(served, 1);
            }
            ip_seq = core::add_sat_u64(ip_seq, 1);
        }
    }
    return served;
}
