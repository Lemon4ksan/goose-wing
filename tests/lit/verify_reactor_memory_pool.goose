// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Goose LIT Verification Suite: Lazy Reactor Memory Footprint, Dynamic SoAConnTable Scaling (>4096),
// and Zero-Pinning `slice_pool<u8>` Keep-Alive Leftover Preservation.
// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

struct SplitKeepAliveStage {
    c1_fd:                 i64 = -1,
    c2_fd:                 i64 = -1,
    observed_leased_bytes: i64 = -1,
    observed_leased_slots: i64 = -1,
    observed_hwm_after_1:  i64 = -1,
    mid_turn_leased_bytes: i64 = -1,
    hits_first:            i32 = 0,
    hits_second:           i32 = 0,
    hits_third:            i32 = 0,
}

fn wing::on_server_stage(
    stage: SplitKeepAliveStage&,
    phase: wire::ServerHookPhase,
    _cfg:  wing::ServerPipelineConfig&,
    req:   const wing::Request&,
    _ctx:  wing::ServerStageCtx&,
    res:   wing::Response&,
) -> wire::StageVerdict {
    guard phase == wire::ServerHookPhase.RouteHandler else {
        return wire::StageVerdict.Continue;
    }
    if req.url[..] == "/first" {
        stage.hits_first += 1;
        let n = wing::tcp_send(stage.c2_fd, "GET /trigger HTTP/1.1\r\nHost: localhost\r\n\r\n");
        assert(n > 0);
        res.status_code = 200;
        res.body.clear();
        res.body.append("FIRST_OK");
        return wire::StageVerdict.ShortCircuit { status_code: 200 };
    }
    if req.url[..] == "/trigger" {
        stage.observed_leased_bytes = wing::g_default_reactor.leftover_leased_bytes;
        stage.observed_leased_slots = wing::g_default_reactor.leftover_leased_slots;
        stage.observed_hwm_after_1 = wing::g_default_reactor.leftover_pool_hwm;
        let n = wing::tcp_send(stage.c1_fd, "HTTP/1.1\r\nHost: localhost\r\n\r\nGET /third ");
        assert(n > 0);
        res.status_code = 200;
        res.body.clear();
        res.body.append("TRIGGER_OK");
        return wire::StageVerdict.ShortCircuit { status_code: 200 };
    }
    if req.url[..] == "/second" {
        stage.hits_second += 1;
        stage.mid_turn_leased_bytes = wing::g_default_reactor.leftover_leased_bytes;
        let n = wing::tcp_send(stage.c1_fd, "HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        assert(n > 0);
        res.status_code = 200;
        res.body.clear();
        res.body.append("SECOND_OK");
        return wire::StageVerdict.ShortCircuit { status_code: 200 };
    }
    if req.url[..] == "/third" {
        stage.hits_third += 1;
        let n = wing::tcp_send(stage.c2_fd, "GET /done HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n");
        assert(n > 0);
        res.status_code = 200;
        res.body.clear();
        res.body.append("THIRD_OK");
        return wire::StageVerdict.ShortCircuit { status_code: 200 };
    }
    if req.url[..] == "/done" {
        res.status_code = 200;
        res.body.clear();
        res.body.append("DONE_OK");
        return wire::StageVerdict.ShortCircuit { status_code: 200 };
    }
    return wire::StageVerdict.Continue;
}

fn verify_startup_lazy_footprint() {
    assert(wing::SOA_TABLE_CAP == 4096);
    assert(wing::REACTOR_MAX_H2_SESSIONS == 128);
    assert(wing::g_default_reactor.h2_sessions.len == 0);
    assert(wing::g_reactor_chunk.bytes.len == 0);
    assert(wing::g_reactor_cork_bufs.len == 0);
    assert(wing::g_reactor_tls_plain_bufs.len == 0);
    assert(wing::g_reactor_tls_seal_bufs.len == 0);
    assert(wing::g_reactor_conn_pool.slots.len == 0);
    assert(wing::g_reactor_accel.slab.len == 0);
    print("STARTUP_LAZY_FOOTPRINT: OK");
}

fn verify_soa_dynamic_scaling_beyond_4096() {
    var table = wing::SoAConnTable { .. };
    assert(table.fds.len == 0 && table.count == 0 && table.max_slots == 4096);

    wing::soa_table_set_peer_ip(table, 0, "10.0.0.1");
    assert(wing::soa_table_get_peer_ip(table, 0) == "");
    wing::soa_table_touch(table, 0, 77);
    assert(table.timeout_ticks[0] == wing::SOA_INVALID_TICK);

    var wheel = core::TickTimerWheel { idle_timeout_sec: 15, .. };
    let short_tick = core::tick_timer_arm(wheel, 5);
    let long_tick = core::tick_timer_arm(wheel, 25);

    for i in 4096 {
        let tick = if (i & 1) == 0 { short_tick } else { long_tick };
        let s = wing::soa_table_alloc(table, 1000 + i, tick);
        assert(s == i);
    }
    assert(table.count == 4096 && table.fds.len == 4096);
    assert(wing::soa_table_alloc(table, 999999, short_tick) == wing::SOA_INVALID_FD);

    assert(wing::soa_table_ensure_slot(table, 5119));
    for extra in 1024 {
        let target = 4096 + extra;
        let tick = if (extra & 1) == 0 { short_tick } else { long_tick };
        let s = wing::soa_table_alloc(table, 20000 + extra, tick);
        assert(s == target);
    }
    assert(table.count == 5120 && table.fds.len == 5120);

    wing::soa_table_set_peer_ip(table, 5000, "203.0.113.77");
    assert(wing::soa_table_get_peer_ip(table, 5000) == "203.0.113.77");
    wing::soa_table_touch(table, 5000, long_tick);
    assert(table.timeout_ticks[5000] == long_tick);

    core::tick_timer_advance(wheel, 6);
    var expired: i64[5120] = [0; 5120];
    let n_exp = wing::soa_table_sweep_expired(table, wheel, expired[..]);
    assert(n_exp == 2559);
    for k in n_exp {
        wing::soa_table_free(table, expired[k]);
    }

    var rev: i64 = 5119;
    while rev >= 0 {
        if table.fds[rev] > 0 {
            wing::soa_table_free(table, rev);
        }
        rev -= 1;
    }
    assert(table.count == 0);
    assert(wing::soa_table_get_peer_ip(table, 5000) == "");
    print("SOA_DYNAMIC_SCALING_5120: OK");
}

fn drain_client_socket(fd: i64, out: u8[..4096]&) {
    out.clear();
    var scratch: u8[1024] = [0; 1024];
    for _ in 8 {
        let nr = wing::tcp_recv_slice(fd, scratch[..]);
        if nr <= 0 {
            break;
        }
        let _ = out.try_append(scratch[..nr]);
    }
}

fn run_split_keepalive_round(srv: wing::HttpServer&) {
    let lfd = wing::tcp_listen("127.0.0.1", 0);
    assert(lfd > 0);
    let port = wing::tcp_getsockname_port(lfd);
    assert(port > 0);

    let c1 = wing::tcp_connect("127.0.0.1", port);
    let c2 = wing::tcp_connect("127.0.0.1", port);
    assert(c1 > 0 && c2 > 0);

    let initial_wire = "GET /first HTTP/1.1\r\nHost: localhost\r\n\r\nGET /second ";
    assert(wing::tcp_send(c1, initial_wire) == (initial_wire.len as i32));

    var stage = SplitKeepAliveStage { c1_fd: c1, c2_fd: c2, .. };
    let served = wing::serve_reactor_with_stage(srv, lfd, stage, 2);
    assert(served == 2);
    assert(stage.hits_first == 1 && stage.hits_second == 1 && stage.hits_third == 1);
    assert(stage.observed_leased_slots == 1);
    assert(stage.observed_leased_bytes == 12);
    assert(stage.observed_hwm_after_1 == 12);
    assert(stage.mid_turn_leased_bytes == 0);
    assert(wing::g_default_reactor.leftover_pool_hwm == 12);
    assert(wing::g_default_reactor.leftover_leased_bytes == 0);
    assert(wing::g_default_reactor.leftover_leased_slots == 0);

    var rx1: u8[..4096] = [];
    var rx2: u8[..4096] = [];
    drain_client_socket(c1, rx1);
    drain_client_socket(c2, rx2);
    assert(core::contains(rx1[..], "FIRST_OK"));
    assert(core::contains(rx1[..], "SECOND_OK"));
    assert(core::contains(rx1[..], "THIRD_OK"));
    assert(core::contains(rx2[..], "TRIGGER_OK"));
    assert(core::contains(rx2[..], "DONE_OK"));

    wing::tcp_close(c1);
    wing::tcp_close(c2);
    wing::tcp_close(lfd);
}

fn verify_split_keepalive_and_lazy_h2() {
    var srv = wing::new_http_server("127.0.0.1", 0);
    srv.accel_mode = wing::ReactorAccelMode.PollFallback;
    wing::add_get_route(srv, "/first", 1);
    wing::add_get_route(srv, "/second", 2);
    wing::add_get_route(srv, "/third", 3);
    wing::add_get_route(srv, "/trigger", 4);
    wing::add_get_route(srv, "/done", 5);

    run_split_keepalive_round(srv);
    assert(wing::g_default_reactor.h2_sessions.len == 0);
    assert(wing::g_reactor_accel.slab.len == 0);

    var static_srv = wing::new_http_server("127.0.0.1", 0);
    wing::add_static_get_route(static_srv, "/ping", "text/plain", "PONG_KEEPALIVE", 1);
    let lfd_direct = wing::reactor_listen_accelerated(static_srv, 32);
    assert(lfd_direct > 0);
    let port_direct = wing::tcp_getsockname_port(lfd_direct);
    let cli_direct = wing::tcp_connect("127.0.0.1", port_direct);
    assert(cli_direct > 0);
    let pipelined_wire =
        "GET /ping HTTP/1.1\r\nHost: localhost\r\n\r\nGET /ping HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
    assert(wing::tcp_send(cli_direct, pipelined_wire) == (pipelined_wire.len as i32));
    assert(wing::serve_reactor(static_srv, lfd_direct, 1) == 1);
    var rx_direct: u8[..4096] = [];
    drain_client_socket(cli_direct, rx_direct);
    assert(core::contains(rx_direct[..], "PONG_KEEPALIVE"));
    assert(wing::g_default_reactor.leftover_leased_bytes == 0);
    assert(wing::g_default_reactor.h2_sessions.len == 0);
    wing::tcp_close(cli_direct);
    wing::tcp_close(lfd_direct);

    let h2_0 = wing::alloc_reactor_h2_session(srv.pipeline, "localhost", 1000);
    assert(h2_0 == 0);
    assert(wing::g_default_reactor.h2_sessions.len == 1);
    wing::free_reactor_h2_session(h2_0, srv.pipeline);

    let h2_reused = wing::alloc_reactor_h2_session(srv.pipeline, "localhost", 2000);
    assert(h2_reused == 0);
    assert(wing::g_default_reactor.h2_sessions.len == 1);
    wing::free_reactor_h2_session(h2_reused, srv.pipeline);
    print("SPLIT_KEEPALIVE_SLICE_POOL: OK");
    print("LAZY_H2_SESSION_GROWTH: OK");
}

// CHECK: STARTUP_LAZY_FOOTPRINT: OK
// CHECK: SOA_DYNAMIC_SCALING_5120: OK
// CHECK: SPLIT_KEEPALIVE_SLICE_POOL: OK
// CHECK: LAZY_H2_SESSION_GROWTH: OK
fn main() {
    verify_startup_lazy_footprint();
    verify_soa_dynamic_scaling_beyond_4096();
    verify_split_keepalive_and_lazy_h2();
}
