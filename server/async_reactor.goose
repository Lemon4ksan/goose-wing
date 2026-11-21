// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Inversion-of-control async HTTP/1.1 & HTTP/2 server reactor built over `core::host_*` push links.
// Coexists with external protocol drivers (DB pools, timers, custom sockets) on one `NetHost` loop,
// suspending async route handlers via `WakeToken` and resuming HTTP egress on `LinkEventKind.Wake`.
namespace server;

import std;
import core;
import net.driver;
import net.io_host;
import .router;
import .pool;
import .pipeline;
import .h1_codec;
import .h2_multiplexer;
import .server;
import .reactor_internal;
import .server_internal;
import .pipeline_internal;
import .h1_codec_internal;

const ASYNC_REACTOR_MAX_CONNS: i64 = 1048576;

const ASYNC_REACTOR_MAX_H2: i64 = 4096;

const ASYNC_REACTOR_MAX_PARKED: i64 = 65536;

root struct AsyncServerReactor {
    listener_link:         core::IoLink                            = core::IoLink { .. },
    cur_now_ns:            u64                                     = 0,
    next_conn_seq:         u32                                     = 1,
    buf_items:             u8[>..]                                 = [],
    buf_free:              server_internal::PooledBufSpan[>..<]    = [],
    link_to_conn:          i32[>..]                                = [],
    conns:                 server_internal::AsyncHttpConn[>..]     = [],
    free_conns:            i32[>..<]                               = [],
    h2_sessions:           server_internal::H2ServerSession[>..]   = [],
    h2_in_use:             bool[>..]                               = [],
    parked:                server_internal::ParkedHttpRequest[>..] = [],
    free_parked:           i32[>..<]                               = [],
    tx_scratch:            u8[..65536]                             = [],
    req_scratch:           http::Request                           = http::Request { .. },
    res_scratch:           http::Response                          = http::Response { .. },
    total_served:          i64                                     = 0,
    total_wakes_delivered: i64                                     = 0,
    total_stale_wakes:     i64                                     = 0,
}

// Adapter combining an HTTP `<Stage>` with an external `<Driver>` for `serve_reactor_with_io`.
struct StageDriverBridge<Stage, Driver> {
    stage:  Stage,
    driver: Driver,
}

inline fn on_server_stage<Stage, Driver>(
    bridge: StageDriverBridge<Stage, Driver>&,
    phase:  wire::ServerHookPhase,
    cfg:    ServerPipelineConfig&,
    req:    const http::Request&,
    ctx:    ServerStageCtx&,
    res:    http::Response&,
) -> wire::StageVerdict {
    return on_server_stage(bridge.stage, phase, cfg, req, ctx, res);
}

inline fn core::on_link_event<Stage, Driver, H>(
    bridge: server::StageDriverBridge<Stage, Driver>&,
    host:   H&,
    ev:     const core::LinkEvent&,
) {
    core::on_link_event(bridge.driver, host, ev);
}

// Registers a pre-established HTTP client `IoLink` (e.g. a virtual pair endpoint) on `reactor`.
fn async_reactor_register_client_link(reactor: AsyncServerReactor&, link: core::IoLink) -> i64 {
    guard core::io_link_is_valid(link) else { return -1; }
    let lslot = core::io_link_slot(link);
    guard lslot >= 0 && lslot < net_internal::NET_HOST_MAX_LINKS else { return -1; }

    var idx: i64 = -1;
    if reactor.free_conns.len > 0 {
        let top = core::sub_sat_i64(reactor.free_conns.len, 1);
        idx = reactor.free_conns[top];
        reactor.free_conns.resize(top);
    } else {
        guard reactor.conns.len < ASYNC_REACTOR_MAX_CONNS else { return -1; }
        idx = reactor.conns.len;
        reactor.conns.push(server_internal::AsyncHttpConn { .. });
    }
    if lslot >= reactor.link_to_conn.len {
        let need_map = core::sub_sat_i64(core::add_sat_i64(lslot, 1), reactor.link_to_conn.len);
        push_n(reactor.link_to_conn, -1 as i32, need_map);
    }

    let seq = server_internal::next_non_zero_seq_u32(reactor.next_conn_seq);
    reactor.next_conn_seq = seq;
    reactor.conns[idx] = server_internal::AsyncHttpConn {
        link:    link,
        req_seq: seq,
        in_use:  true,
        ..
    };
    reactor.link_to_conn[lslot] = idx as i32;
    return idx;
}

inline fn dispatch_host_ctx_event<App>(
    reactor: AsyncServerReactor&,
    host:    net::Host&,
    server:  HttpServer&,
    app:     App&,
    ev:      const core::LinkEvent&,
) {
    server_internal::handle_async_reactor_event(host, server, reactor, app, ev);
}

// Opens an HTTP listener (TCP or Unix domain) managed by `reactor` on `host`.
fn async_reactor_listen_http(
    host:    net::Host&,
    reactor: AsyncServerReactor&,
    addr:    core::ConnectAddr,
    backlog: i32 = 128,
) -> bool {
    let lnk, err = core::host_listen(host, addr, core::IO_OWNER_HTTP_SERVER, 0, backlog);
    guard err == core::IoError.None && core::io_link_is_valid(lnk) else { return false; }
    reactor.listener_link = lnk;
    return true;
}

// Runs one non-blocking event-loop pass across HTTP connections and external `<App>` drivers.
fn async_reactor_step<App>(
    host:       net::Host&,
    server:     HttpServer&,
    reactor:    AsyncServerReactor&,
    app:        App&,
    timeout_ms: i64,
    now_ns:     u64,
) -> i32 {
    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }
    reactor.cur_now_ns = now_ns;
    server_internal::emit_app_pump(host, app);
    return net::link_poll_dispatch_ctx(host, reactor, server, app, timeout_ms, now_ns);
}

// Runs an integrated event loop serving HTTP on `addr` using a mutable `<App>`
// implementing both `on_server_stage` and `on_link_event` with zero copying.
fn serve_reactor_with_app<App>(
    host:            net::Host&,
    server:          HttpServer&,
    reactor:         AsyncServerReactor&,
    addr:            core::ConnectAddr,
    app:             App&,
    backlog:         i32 = 128,
    max_iters:       i64 = 0,
    poll_timeout_ms: i64 = 10,
) -> bool {
    guard async_reactor_listen_http(host, reactor, addr, backlog) else { return false; }
    server.is_running = true;
    var iter: i64 = 0;
    while server.is_running {
        if max_iters > 0 && iter >= max_iters {
            break;
        }
        let now_ns = core::monotonic_now().as_nanos();
        let _ = async_reactor_step(host, server, reactor, app, poll_timeout_ms, now_ns);
        iter = core::add_sat_i64(iter, 1);
    }
    if core::io_link_is_valid(reactor.listener_link) {
        let _ = core::host_close(host, reactor.listener_link);
        reactor.listener_link = core::IoLink { .. };
    }
    return true;
}

// Runs an integrated event loop serving HTTP on `addr` while driving `<Stage>` and `<Driver>` together.
fn serve_reactor_with_io<Stage, Driver>(
    host:            net::Host&,
    server:          HttpServer&,
    reactor:         AsyncServerReactor&,
    addr:            core::ConnectAddr,
    stage:           Stage,
    driver:          Driver,
    backlog:         i32 = 128,
    max_iters:       i64 = 0,
    poll_timeout_ms: i64 = 10,
) -> bool {
    var bridge = StageDriverBridge<Stage, Driver> { stage: stage, driver: driver };
    return serve_reactor_with_app(host, server, reactor, addr, bridge, backlog, max_iters, poll_timeout_ms);
}
