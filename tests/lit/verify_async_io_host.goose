// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification of the generic TCP / AF_UNIX / Virtual async push I/O contract (`core::host_*`),
// non-blocking connect completion + SO_ERROR failure, `rx_paused` / `Writable` backpressure,
// and Inversion-of-Control HTTP/1.1 + HTTP/2 server integration with simulated async Postgres.
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe %t.sock | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

const OWNER_TCP_TEST:     u16 = core::IO_OWNER_USER_START;
const OWNER_UDS_TEST:     u16 = core::IO_OWNER_USER_START + 1;
const OWNER_BP_A:         u16 = core::IO_OWNER_USER_START + 2;
const OWNER_BP_B:         u16 = core::IO_OWNER_USER_START + 3;
const OWNER_PG_SRV:       u16 = core::IO_OWNER_USER_START + 4;
const OWNER_PG_CLI:       u16 = core::IO_OWNER_USER_START + 5;
const OWNER_HTTP_CLI:     u16 = core::IO_OWNER_USER_START + 6;
const OWNER_SCALE_CLI:    u16 = core::IO_OWNER_USER_START + 7;
const SCALE_CONN_COUNT:   i64 = 320;
const BIG_BODY_BYTES:     i64 = 12288;
const TIMER_TEST_VALID:   u64 = 1001;
const TIMER_TEST_CANCEL:  u64 = 1002;
const TIMER_PG_SIM_DELAY: u64 = 2001;

// ---- Test 1 & 2 Shared Socket Roundtrip Probe Driver ----------------------

struct RoundtripProbeDriver {
    target_owner:    u16          = 0,
    srv_link:        core::IoLink = core::IoLink { .. },
    cli_link:        core::IoLink = core::IoLink { .. },
    refused_link:    core::IoLink = core::IoLink { .. },
    accepted:        bool         = false,
    connected:       bool         = false,
    srv_rx:          u8[..256]    = [],
    cli_rx:          u8[..256]    = [],
    srv_got_eof:     bool         = false,
    refused_closed:  bool         = false,
    refused_connect: bool         = false,
    valid_timer_ok:  bool         = false,
    cancel_timer_ok: bool         = true,
    srv_replied:     bool         = false,
    reply_msg:       const u8[:]  = "",
}

fn core::on_link_event(drv: RoundtripProbeDriver&, host: wing::NetHost&, ev: const core::LinkEvent&) {
    if ev.kind == core::LinkEventKind.Timer {
        if ev.timer_id == TIMER_TEST_VALID { drv.valid_timer_ok = true; }
        if ev.timer_id == TIMER_TEST_CANCEL { drv.cancel_timer_ok = false; }
        return;
    }
    guard core::io_link_owner(ev.link) == drv.target_owner else { return; }
    match ev.kind {
        Accepted => {
            drv.srv_link = ev.link;
            drv.accepted = true;
        },
        Connected => {
            if ev.link.raw == drv.cli_link.raw {
                drv.connected = true;
            } else if ev.link.raw == drv.refused_link.raw {
                drv.refused_connect = true;
            }
        },
        Data => {
            if ev.link.raw == drv.srv_link.raw {
                let _ = drv.srv_rx.try_append(ev.data);
                if !drv.srv_replied && drv.srv_rx.len >= 4 {
                    drv.srv_replied = true;
                    let _ = core::host_send(host, drv.srv_link, drv.reply_msg);
                }
            } else if ev.link.raw == drv.cli_link.raw {
                let _ = drv.cli_rx.try_append(ev.data);
            }
        },
        Eof => {
            if ev.link.raw == drv.srv_link.raw {
                drv.srv_got_eof = true;
            }
        },
        Closed => {
            if ev.link.raw == drv.refused_link.raw {
                drv.refused_closed = true;
            }
        },
        _ => {},
    };
}

fn test_tcp_nonblocking_connect_and_refused() {
    var dcfg = net_internal::TransportDriverConfig {
        active_kind: net_internal::TransportDriverKind.Standard,
        is_probed:   true,
        ..
    };
    var host = wing::new_net_host(dcfg);
    defer wing::close_net_host(host);

    // Invalid connect port == 0 rejected; valid listen port == 0 binds ephemeral OS port.
    let _, bad_st = core::host_connect(host, core::ConnectAddr.Tcp { host: "127.0.0.1", port: 0 }, OWNER_TCP_TEST, 1);
    assert(bad_st == core::ConnectStatus.InvalidArgument);

    let l_link, l_err = core::host_listen(host, core::ConnectAddr.Tcp { host: "127.0.0.1", port: 0 }, OWNER_TCP_TEST, 10, 16);
    assert(l_err == core::IoError.None && core::io_link_is_valid(l_link));
    let port = wing::link_local_port(host, l_link);
    assert(port > 0);

    // Prepare a refused port by opening and immediately closing a second ephemeral listener.
    let dead_listen, dead_err = core::host_listen(host, core::ConnectAddr.Tcp { host: "127.0.0.1", port: 0 }, OWNER_TCP_TEST, 11, 4);
    assert(dead_err == core::IoError.None);
    let dead_port = wing::link_local_port(host, dead_listen);
    assert(dead_port > 0);
    assert(core::host_close(host, dead_listen));

    var drv = RoundtripProbeDriver { target_owner: OWNER_TCP_TEST, reply_msg: "PONG_TCP", .. };
    let cli_link, c_st = core::host_connect(host, core::ConnectAddr.Tcp { host: "127.0.0.1", port: port }, OWNER_TCP_TEST, 20);
    assert(core::io_link_is_valid(cli_link));
    assert(c_st == core::ConnectStatus.Connected || c_st == core::ConnectStatus.InProgress);
    drv.cli_link = cli_link;
    if c_st == core::ConnectStatus.Connected {
        drv.connected = true;
    }

    let r_link, r_st = core::host_connect(host, core::ConnectAddr.Tcp { host: "127.0.0.1", port: dead_port }, OWNER_TCP_TEST, 21);
    if r_st == core::ConnectStatus.Failed {
        drv.refused_closed = true;
    } else {
        assert(r_st == core::ConnectStatus.InProgress && core::io_link_is_valid(r_link));
        drv.refused_link = r_link;
    }

    // Timer firing + cancelled timer suppression check.
    assert(core::host_add_timer(host, TIMER_TEST_VALID, 5, OWNER_TCP_TEST, 1, false, 1000000000));
    assert(core::host_add_timer(host, TIMER_TEST_CANCEL, 5, OWNER_TCP_TEST, 2, false, 1000000000));
    assert(core::host_cancel_timer(host, TIMER_TEST_CANCEL));

    var sent_ping = false;
    var sent_eof = false;
    var now_ns: u64 = 1000000000;
    for _ in 250 {
        let _ = core::host_step(host, drv, 20, now_ns);
        now_ns = core::add_sat_u64(now_ns, 5000000);
        if drv.connected && !sent_ping {
            let s_n, s_err = core::host_send(host, drv.cli_link, "PING_TCP");
            assert(s_n == 8 && s_err == core::IoError.None);
            sent_ping = true;
        }
        if drv.cli_rx[..] == "PONG_TCP" && !sent_eof {
            assert(core::host_shutdown_write(host, drv.cli_link));
            sent_eof = true;
        }
        if drv.accepted && drv.connected && drv.srv_got_eof && drv.refused_closed && drv.valid_timer_ok {
            break;
        }
    }
    assert(drv.accepted && drv.connected);
    assert(drv.srv_rx[..] == "PING_TCP");
    assert(drv.cli_rx[..] == "PONG_TCP");
    assert(drv.srv_got_eof);
    assert(drv.refused_closed && !drv.refused_connect);
    assert(drv.valid_timer_ok && drv.cancel_timer_ok);

    // Generation guard: closing link twice is idempotent and returns false on stale handle.
    assert(core::host_close(host, l_link));
    assert(!core::host_close(host, l_link));
    print("TASK1_TCP_NONBLOCKING_SO_ERROR: OK");
}

fn test_af_unix_listen_connect_roundtrip(uds_path: const u8[:]) {
    var dcfg = net_internal::TransportDriverConfig {
        active_kind: net_internal::TransportDriverKind.Standard,
        is_probed:   true,
        ..
    };
    var host = wing::new_net_host(dcfg);
    defer wing::close_net_host(host);

    let l_link, l_err = core::host_listen(host, core::ConnectAddr.Unix { path: uds_path }, OWNER_UDS_TEST, 30, 8);
    assert(l_err == core::IoError.None && core::io_link_is_valid(l_link));

    var drv = RoundtripProbeDriver { target_owner: OWNER_UDS_TEST, reply_msg: "PONG_UDS", .. };
    let cli_link, c_st = core::host_connect(host, core::ConnectAddr.Unix { path: uds_path }, OWNER_UDS_TEST, 31);
    assert(core::io_link_is_valid(cli_link));
    assert(c_st == core::ConnectStatus.Connected || c_st == core::ConnectStatus.InProgress);
    drv.cli_link = cli_link;
    if c_st == core::ConnectStatus.Connected {
        drv.connected = true;
    }

    var sent_ping = false;
    var sent_eof = false;
    var now_ns: u64 = 2000000000;
    for _ in 100 {
        let _ = core::host_step(host, drv, 20, now_ns);
        now_ns = core::add_sat_u64(now_ns, 5000000);
        if drv.connected && !sent_ping {
            let s_n, s_err = core::host_send(host, drv.cli_link, "PING_UDS");
            assert(s_n == 8 && s_err == core::IoError.None);
            sent_ping = true;
        }
        if drv.cli_rx[..] == "PONG_UDS" && !sent_eof {
            assert(core::host_shutdown_write(host, drv.cli_link));
            sent_eof = true;
        }
        if drv.accepted && drv.connected && drv.srv_got_eof {
            break;
        }
    }
    assert(drv.accepted && drv.connected);
    assert(drv.srv_rx[..] == "PING_UDS");
    assert(drv.cli_rx[..] == "PONG_UDS");
    assert(drv.srv_got_eof);
    print("TASK2_AF_UNIX_ROUNDTRIP: OK");
}

// ---- Test 3: Backpressure (`rx_paused` + `WouldBlock` -> `Writable` + `IoDriverChain`) ----

struct BackpressureDriver {
    link_a:        core::IoLink = core::IoLink { .. },
    link_b:        core::IoLink = core::IoLink { .. },
    rx_b_bytes:    i64          = 0,
    writable_a:    i64          = 0,
    last_rx_slice: u8[..64]     = [],
}

fn core::on_link_event(drv: BackpressureDriver&, _host: wing::NetHost&, ev: const core::LinkEvent&) {
    if ev.link.raw == drv.link_b.raw && ev.kind == core::LinkEventKind.Data {
        drv.rx_b_bytes = core::add_sat_i64(drv.rx_b_bytes, ev.data.len);
        if drv.last_rx_slice.len == 0 {
            let take = min(ev.data.len, 64);
            let _ = drv.last_rx_slice.try_set(ev.data[..take]);
        }
        return;
    }
    if ev.link.raw == drv.link_a.raw && ev.kind == core::LinkEventKind.Writable {
        drv.writable_a = core::add_sat_i64(drv.writable_a, 1);
    }
}

fn test_virtual_backpressure_and_driver_chain() {
    var dcfg = net_internal::TransportDriverConfig {
        active_kind: net_internal::TransportDriverKind.Standard,
        is_probed:   true,
        ..
    };
    var host = wing::new_net_host(dcfg);
    defer wing::close_net_host(host);

    let la, lb, ok_pair = wing::host_open_virtual_pair(host, OWNER_BP_A, OWNER_BP_B, 1, 2);
    assert(ok_pair && core::io_link_is_valid(la) && core::io_link_is_valid(lb));

    var chained = core::chain_io_drivers(
        BackpressureDriver { link_a: la, link_b: lb, .. },
        core::NoOpIoDriver {},
    );

    assert(core::host_set_rx_paused(host, lb, true));
    let n0, e0 = core::host_send(host, la, "HELD_WHILE_PAUSED");
    assert(n0 == 17 && e0 == core::IoError.None);
    let _ = core::host_step(host, chained, 0, 100);
    assert(chained.first.rx_b_bytes == 0);

    assert(core::host_set_rx_paused(host, lb, false));
    let _ = core::host_step(host, chained, 0, 200);
    assert(chained.first.rx_b_bytes == 17 && chained.first.last_rx_slice[..] == "HELD_WHILE_PAUSED");

    // Pause B again, saturate 4096-byte pipe ring to trigger WouldBlock, then verify Writable fires on drain.
    assert(core::host_set_rx_paused(host, lb, true));
    var big_chunk: u8[4096] = [0x41; 4096];
    let nf, ef = core::host_send(host, la, big_chunk[..]);
    assert(nf == 4096 && ef == core::IoError.None);
    let n_over, e_over = core::host_send(host, la, "OVERFLOW");
    assert(n_over == 0 && e_over == core::IoError.WouldBlock);

    assert(core::host_set_rx_paused(host, lb, false));
    for _ in 4 {
        let _ = core::host_step(host, chained, 0, 300);
    }
    assert(chained.first.rx_b_bytes == 17 + 4096);
    assert(chained.first.writable_a >= 1);
    print("TASK3_BACKPRESSURE_AND_CHAIN: OK");
}

// ---- Test 4: Full HTTP Server (H1 + H2) + Mock Async Postgres Wire Driver ----

enum PgConnState {
    Idle,
    Connecting,
    Ready,
}

struct PendingSqlSlot {
    in_use:     bool            = false,
    sent_wire:  bool            = false,
    reply_done: bool            = false,
    cleaned_up: bool            = false,
    wake_token: core::WakeToken = core::WakeToken { .. },
    key:        u8[..32]        = [],
    row_val:    u8[..128]       = [],
}

struct MockPgSrvJob {
    active:   bool     = false,
    timer_id: u64      = 0,
    key:      u8[..32] = [],
}

struct PgHttpApp {
    pg_addr:       core::ConnectAddr  = core::ConnectAddr.Tcp { host: "127.0.0.1", port: 0 },
    pg_srv_listen: core::IoLink       = core::IoLink { .. },
    pg_srv_conn:   core::IoLink       = core::IoLink { .. },
    pg_srv_rx:     u8[..512]          = [],
    pg_srv_job:    MockPgSrvJob       = MockPgSrvJob { .. },
    pg_cli_link:   core::IoLink       = core::IoLink { .. },
    pg_state:      PgConnState        = PgConnState.Idle,
    pg_cli_rx:     u8[..1024]         = [],
    next_timer_id: u64                = 5000,
    slots:         PendingSqlSlot[16] = [PendingSqlSlot { .. }; 16],
    slots_cleaned: i64                = 0,
    now_ns:        u64                = 10000000000,
    // Test HTTP client links (H1 pipelined, H2 multiplexed, Disconnect probe).
    h1_cli:       core::IoLink = core::IoLink { .. },
    h1_connected: bool         = false,
    h1_rx:        u8[..4096]   = [],
    h2_cli:       core::IoLink = core::IoLink { .. },
    h2_connected: bool         = false,
    h2_rx:        u8[..4096]   = [],
    disc_cli:     core::IoLink = core::IoLink { .. },
    disc_cond:    bool         = false,
}

fn wake_tokens_match(a: core::WakeToken, b: core::WakeToken) -> bool {
    return a.owner == b.owner &&
        a.gen == b.gen &&
        a.slot == b.slot &&
        a.stream_id == b.stream_id &&
        a.req_seq == b.req_seq;
}

fn pg_enqueue_query(app: PgHttpApp&, tok: core::WakeToken, key: const u8[:]) -> bool {
    for i in 16 {
        if !app.slots[i].in_use {
            app.slots[i] = PendingSqlSlot {
                in_use:     true,
                wake_token: tok,
                ..
            };
            let _ = app.slots[i].key.try_set(key);
            return true;
        }
    }
    return false;
}

fn wing::on_server_stage(
    app:   PgHttpApp&,
    phase: wire::ServerHookPhase,
    _cfg:  wing::ServerPipelineConfig&,
    req:   const wing::Request&,
    sctx:  wing::ServerStageCtx&,
    res:   wing::Response&,
) -> wire::StageVerdict {
    if phase == wire::ServerHookPhase.RouteHandler {
        if req.url[..] == "/db" || req.url[..] == "/db_drop" {
            let key: const u8[:] = if req.url[..] == "/db" { "row42" } else { "drop99" };
            assert(pg_enqueue_query(app, sctx.wake_token, key));
            assert(wing::suspend_server_request(sctx));
            return wire::StageVerdict.Continue;
        }
        if req.url[..] == "/fast" {
            res.status_code = 200;
            res.body.clear();
            res.body.append("FAST_SYNC");
            return wire::StageVerdict.ShortCircuit { status_code: 200 };
        }
        return wire::StageVerdict.Continue;
    }
    if phase == wire::ServerHookPhase.ResumeHandler {
        for i in 16 {
            if app.slots[i].in_use && wake_tokens_match(app.slots[i].wake_token, sctx.wake_token) {
                res.status_code = 200;
                res.body.clear();
                res.body.append(app.slots[i].row_val[..]);
                app.slots[i].in_use = false;
                app.slots[i].cleaned_up = true;
                app.slots_cleaned = core::add_sat_i64(app.slots_cleaned, 1);
                return wire::StageVerdict.ShortCircuit { status_code: 200 };
            }
        }
        res.status_code = 500;
        return wire::StageVerdict.ShortCircuit { status_code: 500 };
    }
    return wire::StageVerdict.Continue;
}

fn pg_pump_outbound(app: PgHttpApp&, host: wing::NetHost&) {
    var pending_idx: i64 = -1;
    for i in 16 {
        if app.slots[i].in_use && !app.slots[i].sent_wire {
            pending_idx = i;
            break;
        }
    }
    guard pending_idx >= 0 else { return; }

    if app.pg_state == PgConnState.Idle {
        let lnk, st = core::host_connect(host, app.pg_addr, OWNER_PG_CLI, 1);
        assert(core::io_link_is_valid(lnk));
        app.pg_cli_link = lnk;
        if st == core::ConnectStatus.Connected {
            app.pg_state = PgConnState.Ready;
        } else {
            app.pg_state = PgConnState.Connecting;
            return;
        }
    }
    guard app.pg_state == PgConnState.Ready else { return; }

    var wire_q: u8[..64] = [];
    let _ = wire_q.try_append("SQL:");
    let _ = wire_q.try_append(app.slots[pending_idx].key[..]);
    let _ = wire_q.try_append("\n");
    let sn, err = core::host_send(host, app.pg_cli_link, wire_q[..]);
    if err == core::IoError.None && sn == (wire_q.len as i32) {
        app.slots[pending_idx].sent_wire = true;
    }
}

fn pg_handle_srv_event(app: PgHttpApp&, host: wing::NetHost&, ev: const core::LinkEvent&) {
    if ev.kind == core::LinkEventKind.Accepted {
        app.pg_srv_conn = ev.link;
        return;
    }
    if ev.kind == core::LinkEventKind.Data && ev.link.raw == app.pg_srv_conn.raw {
        let _ = app.pg_srv_rx.try_append(ev.data);
        let nl = app.pg_srv_rx[..].index_of_byte('\n');
        guard nl >= 4 else { return; }
        let line = app.pg_srv_rx[..nl];
        let rest, has_sql = line.strip_prefix("SQL:");
        if has_sql {
            let tid = app.next_timer_id;
            app.next_timer_id = core::add_sat_u64(app.next_timer_id, 1);
            app.pg_srv_job = MockPgSrvJob { active: true, timer_id: tid, .. };
            let _ = app.pg_srv_job.key.try_set(rest);
            assert(core::host_add_timer(host, tid, 4, OWNER_PG_SRV, 0, false, app.now_ns));
        }
        core::compact_wire_buffer(app.pg_srv_rx, nl + 1);
    }
}

fn pg_handle_cli_event(app: PgHttpApp&, host: wing::NetHost&, ev: const core::LinkEvent&) {
    if ev.kind == core::LinkEventKind.Connected && ev.link.raw == app.pg_cli_link.raw {
        app.pg_state = PgConnState.Ready;
        pg_pump_outbound(app, host);
        return;
    }
    if ev.kind == core::LinkEventKind.Data && ev.link.raw == app.pg_cli_link.raw {
        let _ = app.pg_cli_rx.try_append(ev.data);
        let nl = app.pg_cli_rx[..].index_of_byte('\n');
        guard nl >= 4 else { return; }
        let line = app.pg_cli_rx[..nl];
        for i in 16 {
            if app.slots[i].in_use && app.slots[i].sent_wire && !app.slots[i].reply_done {
                app.slots[i].reply_done = true;
                let _ = app.slots[i].row_val.try_set(line);
                assert(core::host_wake(host, app.slots[i].wake_token));
                break;
            }
        }
        core::compact_wire_buffer(app.pg_cli_rx, nl + 1);
        pg_pump_outbound(app, host);
    }
}

fn pg_handle_test_client_event(app: PgHttpApp&, ev: const core::LinkEvent&) {
    if ev.link.raw == app.h1_cli.raw {
        if ev.kind == core::LinkEventKind.Connected { app.h1_connected = true; }
        if ev.kind == core::LinkEventKind.Data { let _ = app.h1_rx.try_append(ev.data); }
        return;
    }
    if ev.link.raw == app.h2_cli.raw {
        if ev.kind == core::LinkEventKind.Connected { app.h2_connected = true; }
        if ev.kind == core::LinkEventKind.Data { let _ = app.h2_rx.try_append(ev.data); }
        return;
    }
    if ev.link.raw == app.disc_cli.raw && ev.kind == core::LinkEventKind.Connected {
        app.disc_cond = true;
    }
}

fn core::on_link_event(app: PgHttpApp&, host: wing::NetHost&, ev: const core::LinkEvent&) {
    if ev.kind == core::LinkEventKind.Pump {
        pg_pump_outbound(app, host);
        return;
    }
    if ev.kind == core::LinkEventKind.Timer {
        if core::io_link_owner(ev.link) == OWNER_PG_SRV && app.pg_srv_job.active &&
           ev.timer_id == app.pg_srv_job.timer_id {
            app.pg_srv_job.active = false;
            var resp_line: u8[..64] = [];
            let _ = resp_line.try_append("ROW:");
            let _ = resp_line.try_append(app.pg_srv_job.key[..]);
            let _ = resp_line.try_append("=verified\n");
            let _ = core::host_send(host, app.pg_srv_conn, resp_line[..]);
        }
        return;
    }
    let owner = core::io_link_owner(ev.link);
    if owner == OWNER_PG_SRV {
        pg_handle_srv_event(app, host, ev);
        return;
    }
    if owner == OWNER_PG_CLI {
        pg_handle_cli_event(app, host, ev);
        return;
    }
    if owner == OWNER_HTTP_CLI {
        pg_handle_test_client_event(app, ev);
    }
}

fn encode_test_h2_get_frame<B>(
    dt:        http2::DynamicTable&,
    stream_id: u32,
    path:      const u8[:],
    out:       B&,
) {
    var hblk: u8[..256] = [];
    http2::encode_hpack_field(dt, hblk, ":method", "GET", http2::HpackIndexing.Incremental, false);
    http2::encode_hpack_field(dt, hblk, ":path", path, http2::HpackIndexing.Incremental, false);
    http2::encode_hpack_field(dt, hblk, ":scheme", "http", http2::HpackIndexing.Incremental, false);
    http2::encode_hpack_field(dt, hblk, ":authority", "localhost", http2::HpackIndexing.Incremental, false);
    let fh = http2::FrameHeader {
        length:     hblk.len as u32,
        frame_type: rfc::H2_FRAME_HEADERS,
        flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
        stream_id:  stream_id,
    };
    http2::encode_frame_header_to(fh, out);
    let _ = out.try_append(hblk[..]);
}

var g_async_http_server: wing::HttpServer = wing::new_http_server("127.0.0.1", 0);

fn test_http_plus_async_pg_full_integration() {
    var dcfg = net_internal::TransportDriverConfig {
        active_kind: net_internal::TransportDriverKind.Standard,
        is_probed:   true,
        ..
    };
    var host = wing::new_net_host(dcfg);
    defer wing::close_net_host(host);

    g_async_http_server = wing::new_http_server("127.0.0.1", 0);
    var reactor = wing::AsyncServerReactor { .. };
    wing::add_get_route(g_async_http_server, "/db", 10);
    wing::add_get_route(g_async_http_server, "/db_drop", 11);
    wing::add_get_route(g_async_http_server, "/fast", 12);

    assert(wing::async_reactor_listen_http(
        host, reactor, core::ConnectAddr.Tcp { host: "127.0.0.1", port: 0 }, 32,
    ));
    let http_port = wing::link_local_port(host, reactor.listener_link);
    assert(http_port > 0);

    var app = PgHttpApp { .. };
    let pg_l, pg_err = core::host_listen(
        host, core::ConnectAddr.Tcp { host: "127.0.0.1", port: 0 }, OWNER_PG_SRV, 1, 16,
    );
    assert(pg_err == core::IoError.None && core::io_link_is_valid(pg_l));
    let pg_port = wing::link_local_port(host, pg_l);
    assert(pg_port > 0);
    app.pg_srv_listen = pg_l;
    app.pg_addr = core::ConnectAddr.Tcp { host: "127.0.0.1", port: pg_port };

    // A. Pipelined HTTP/1.1: GET /db (suspended on PG) followed immediately by GET /fast
    let h1_l, h1_st = core::host_connect(
        host, core::ConnectAddr.Tcp { host: "127.0.0.1", port: http_port }, OWNER_HTTP_CLI, 100,
    );
    assert(core::io_link_is_valid(h1_l));
    app.h1_cli = h1_l;
    if h1_st == core::ConnectStatus.Connected { app.h1_connected = true; }

    var sent_h1 = false;
    for _ in 120 {
        app.now_ns = core::add_sat_u64(app.now_ns, 2000000);
        let _ = wing::async_reactor_step(host, g_async_http_server, reactor, app, 10, app.now_ns);
        if app.h1_connected && !sent_h1 {
            let wire_h1 = "GET /db HTTP/1.1\r\nHost: localhost\r\n\r\nGET /fast HTTP/1.1\r\nHost: localhost\r\nConnection: close\r\n\r\n";
            let sn, se = core::host_send(host, app.h1_cli, wire_h1);
            assert(sn == (wire_h1.len as i32) && se == core::IoError.None);
            sent_h1 = true;
        }
        if core::contains(app.h1_rx[..], "FAST_SYNC") {
            break;
        }
    }
    let idx_row = core::find(app.h1_rx[..], "ROW:row42=verified");
    let idx_fast = core::find(app.h1_rx[..], "FAST_SYNC");
    assert(idx_row > 0 && idx_fast > idx_row);
    print("TASK4A_HTTP1_PIPELINED_PG_WAKE: OK");

    // B. HTTP/2 Multiplexing: Stream 1 (/db) parked on PG while Stream 3 (/fast) completes immediately.
    let h2_l, h2_st = core::host_connect(
        host, core::ConnectAddr.Tcp { host: "127.0.0.1", port: http_port }, OWNER_HTTP_CLI, 101,
    );
    assert(core::io_link_is_valid(h2_l));
    app.h2_cli = h2_l;
    if h2_st == core::ConnectStatus.Connected { app.h2_connected = true; }

    var sent_h2 = false;
    var stream3_before_stream1 = false;
    for _ in 120 {
        app.now_ns = core::add_sat_u64(app.now_ns, 2000000);
        let _ = wing::async_reactor_step(host, g_async_http_server, reactor, app, 10, app.now_ns);
        if app.h2_connected && !sent_h2 {
            var cli_hpack = http2::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
            var h2_req: u8[..1024] = [];
            let _ = h2_req.try_append(rfc::H2_CLIENT_PREFACE[..]);
            encode_test_h2_get_frame(cli_hpack, 1, "/db", h2_req);
            encode_test_h2_get_frame(cli_hpack, 3, "/fast", h2_req);
            let sn2, se2 = core::host_send(host, app.h2_cli, h2_req[..]);
            assert(sn2 == (h2_req.len as i32) && se2 == core::IoError.None);
            sent_h2 = true;
        }
        if !stream3_before_stream1 && core::contains(app.h2_rx[..], "FAST_SYNC") {
            if !core::contains(app.h2_rx[..], "ROW:row42=verified") {
                stream3_before_stream1 = true;
            }
        }
        if core::contains(app.h2_rx[..], "ROW:row42=verified") {
            break;
        }
    }
    assert(stream3_before_stream1);
    assert(core::contains(app.h2_rx[..], "ROW:row42=verified"));
    let _ = core::host_close(host, app.h2_cli);
    print("TASK4B_HTTP2_MULTIPLEX_PG_WAKE: OK");

    // C. Client disconnect mid-query -> Postgres finishes -> Wake safely rejected as stale.
    let d_l, d_st = core::host_connect(
        host, core::ConnectAddr.Tcp { host: "127.0.0.1", port: http_port }, OWNER_HTTP_CLI, 102,
    );
    assert(core::io_link_is_valid(d_l));
    app.disc_cli = d_l;
    if d_st == core::ConnectStatus.Connected { app.disc_cond = true; }

    var sent_drop = false;
    var closed_cli_early = false;
    for _ in 120 {
        app.now_ns = core::add_sat_u64(app.now_ns, 2000000);
        let _ = wing::async_reactor_step(host, g_async_http_server, reactor, app, 10, app.now_ns);
        if app.disc_cond && !sent_drop {
            let req_drop = "GET /db_drop HTTP/1.1\r\nHost: localhost\r\n\r\n";
            let sn3, se3 = core::host_send(host, app.disc_cli, req_drop);
            assert(sn3 == (req_drop.len as i32) && se3 == core::IoError.None);
            sent_drop = true;
        }
        if sent_drop && !closed_cli_early && app.slots_cleaned == 2 && app.pg_srv_job.active {
            assert(wing::link_abort(host, app.disc_cli));
            closed_cli_early = true;
        }
        if reactor.total_stale_wakes >= 1 {
            break;
        }
    }
    assert(closed_cli_early);
    assert(reactor.total_stale_wakes >= 1);
    assert(reactor.total_wakes_delivered >= 2);
    assert(app.slots_cleaned == 3);
    print("TASK4C_STALE_WAKE_SAFETY: OK");

    var loop_host = wing::new_net_host(dcfg);
    defer wing::close_net_host(loop_host);
    var loop_reactor = wing::AsyncServerReactor { .. };
    assert(wing::serve_reactor_with_io(
        loop_host,
        g_async_http_server,
        loop_reactor,
        core::ConnectAddr.Tcp { host: "127.0.0.1", port: 0 },
        wire::NoOpStage {},
        core::NoOpIoDriver {},
        16,
        2,
        1,
    ));
    assert(!core::io_link_is_valid(loop_reactor.listener_link));
    print("TASK5_SERVE_REACTOR_WITH_IO: OK");
}

// ---- Test 6: 320+ Scale + Split Keep-Alive RX + Backpressured TX + Zero-Idle Buffers ----

struct ScaleProbeApp {
    cli_links:  core::IoLink[320] = [core::IoLink { .. }; 320],
    cli_ready:  bool[320]         = [false; 320],
    cli_resps:  i32[320]          = [0; 320],
    bp_cli:     core::IoLink      = core::IoLink { .. },
    bp_rx_len:  i64               = 0,
    bp_z_count: i64               = 0,
}

fn wing::on_server_stage(
    _app:  ScaleProbeApp&,
    phase: wire::ServerHookPhase,
    _cfg:  wing::ServerPipelineConfig&,
    req:   const wing::Request&,
    _sctx: wing::ServerStageCtx&,
    res:   wing::Response&,
) -> wire::StageVerdict {
    guard phase == wire::ServerHookPhase.RouteHandler else {
        return wire::StageVerdict.Continue;
    }
    if req.url[..] == "/scale" {
        res.status_code = 200;
        res.body.clear();
        res.body.append("SCALE_OK");
        return wire::StageVerdict.ShortCircuit { status_code: 200 };
    }
    if req.url[..] == "/big" {
        res.status_code = 200;
        res.body.clear();
        push_n(res.body, 'Z' as u8, BIG_BODY_BYTES);
        return wire::StageVerdict.ShortCircuit { status_code: 200 };
    }
    return wire::StageVerdict.Continue;
}

fn core::on_link_event(app: ScaleProbeApp&, _host: wing::NetHost&, ev: const core::LinkEvent&) {
    guard core::io_link_owner(ev.link) == OWNER_SCALE_CLI else { return; }
    if ev.link.raw == app.bp_cli.raw && ev.kind == core::LinkEventKind.Data {
        app.bp_rx_len = core::add_sat_i64(app.bp_rx_len, ev.data.len);
        app.bp_z_count = core::add_sat_i64(app.bp_z_count, ev.data.count_byte('Z'));
        return;
    }
    let idx = ev.tag as i64;
    guard idx >= 0 && idx < SCALE_CONN_COUNT && ev.link.raw == app.cli_links[idx].raw else { return; }
    if ev.kind == core::LinkEventKind.Connected {
        app.cli_ready[idx] = true;
    } else if ev.kind == core::LinkEventKind.Data && core::contains(ev.data, "SCALE_OK") {
        app.cli_resps[idx] += 1;
    }
}

fn assert_all_reactor_conns_idle_zero_buf(reactor: const wing::AsyncServerReactor&, expected_open: i64) {
    var open_count: i64 = 0;
    for i in reactor.conns.len {
        if reactor.conns[i].in_use {
            open_count += 1;
            assert(reactor.conns[i].rx_len == 0 && reactor.conns[i].rx_cap == 0);
            assert(reactor.conns[i].tx_len == 0 && reactor.conns[i].tx_cap == 0);
        }
    }
    assert(open_count == expected_open);
    assert(reactor.buf_items.len == 0 && reactor.buf_free.len == 0);
}

fn open_scale_tcp_connections(
    host:      wing::NetHost&,
    reactor:   wing::AsyncServerReactor&,
    app:       ScaleProbeApp&,
    http_port: u16,
    now_ns:    u64&,
) {
    for wave in 10 {
        for j in 32 {
            let idx = wave * 32 + j;
            let lnk, st = core::host_connect(
                host,
                core::ConnectAddr.Tcp { host: "127.0.0.1", port: http_port },
                OWNER_SCALE_CLI,
                idx as u64,
            );
            assert(core::io_link_is_valid(lnk));
            app.cli_links[idx] = lnk;
            if st == core::ConnectStatus.Connected {
                app.cli_ready[idx] = true;
            }
        }
        for _ in 8 {
            now_ns = core::add_sat_u64(now_ns, 1000000);
            let _ = wing::async_reactor_step(host, g_async_http_server, reactor, app, 2, now_ns);
        }
    }
    for _ in 60 {
        var ready_cnt: i64 = 0;
        for i in SCALE_CONN_COUNT {
            if app.cli_ready[i] { ready_cnt += 1; }
        }
        if ready_cnt == SCALE_CONN_COUNT && reactor.conns.len >= SCALE_CONN_COUNT {
            break;
        }
        now_ns = core::add_sat_u64(now_ns, 2000000);
        let _ = wing::async_reactor_step(host, g_async_http_server, reactor, app, 5, now_ns);
    }
    assert(host.active_links >= SCALE_CONN_COUNT * 2 + 1);
    assert(reactor.conns.len == SCALE_CONN_COUNT);
    assert(reactor.link_to_conn.len > 256);
    assert_all_reactor_conns_idle_zero_buf(reactor, SCALE_CONN_COUNT);
}

fn verify_split_h1_keepalive_scale(
    host:    wing::NetHost&,
    reactor: wing::AsyncServerReactor&,
    app:     ScaleProbeApp&,
    now_ns:  u64&,
) {
    let half_a = "GET /scale HTTP/1.1\r\n";
    let half_b = "Host: localhost\r\n\r\n";
    for i in SCALE_CONN_COUNT {
        let sn, se = core::host_send(host, app.cli_links[i], half_a);
        assert(sn == (half_a.len as i32) && se == core::IoError.None);
    }
    for _ in 20 {
        now_ns = core::add_sat_u64(now_ns, 1000000);
        let _ = wing::async_reactor_step(host, g_async_http_server, reactor, app, 2, now_ns);
    }
    assert(reactor.buf_items.len >= SCALE_CONN_COUNT * 512);

    for batch in 4 {
        now_ns = core::add_sat_u64(now_ns, 250000000);
        for k in 80 {
            let idx = batch * 80 + k;
            let sn, se = core::host_send(host, app.cli_links[idx], half_b);
            assert(sn == (half_b.len as i32) && se == core::IoError.None);
        }
        for _ in 25 {
            now_ns = core::add_sat_u64(now_ns, 2000000);
            let _ = wing::async_reactor_step(host, g_async_http_server, reactor, app, 2, now_ns);
        }
    }
    for _ in 40 {
        var done_cnt: i64 = 0;
        for i in SCALE_CONN_COUNT {
            if app.cli_resps[i] >= 1 { done_cnt += 1; }
        }
        if done_cnt == SCALE_CONN_COUNT { break; }
        now_ns = core::add_sat_u64(now_ns, 5000000);
        let _ = wing::async_reactor_step(host, g_async_http_server, reactor, app, 5, now_ns);
    }
    for i in SCALE_CONN_COUNT {
        assert(app.cli_resps[i] == 1);
    }
    assert_all_reactor_conns_idle_zero_buf(reactor, SCALE_CONN_COUNT);

    // Second keep-alive roundtrip on high-slot connections (> 256 link index, > 128 conn index).
    now_ns = core::add_sat_u64(now_ns, 250000000);
    let full_req = "GET /scale HTTP/1.1\r\nHost: localhost\r\n\r\n";
    for i in 300..SCALE_CONN_COUNT {
        let sn, se = core::host_send(host, app.cli_links[i], full_req);
        assert(sn == (full_req.len as i32) && se == core::IoError.None);
    }
    for _ in 30 {
        if app.cli_resps[319] >= 2 && app.cli_resps[300] >= 2 { break; }
        now_ns = core::add_sat_u64(now_ns, 1000000);
        let _ = wing::async_reactor_step(host, g_async_http_server, reactor, app, 2, now_ns);
    }
    for i in 300..SCALE_CONN_COUNT {
        assert(app.cli_resps[i] == 2);
    }
    assert_all_reactor_conns_idle_zero_buf(reactor, SCALE_CONN_COUNT);
}

fn verify_backpressured_tx_pool_lease_and_release(
    host:    wing::NetHost&,
    reactor: wing::AsyncServerReactor&,
    app:     ScaleProbeApp&,
    now_ns:  u64&,
) {
    let cli_end, srv_end, ok_pair = wing::host_open_virtual_pair(
        host, OWNER_SCALE_CLI, core::IO_OWNER_HTTP_SERVER, 999, 0,
    );
    assert(ok_pair);
    app.bp_cli = cli_end;
    let v_idx = wing::async_reactor_register_client_link(reactor, srv_end);
    assert(v_idx >= SCALE_CONN_COUNT);

    assert(core::host_set_rx_paused(host, cli_end, true));
    let req_big = "GET /big HTTP/1.1\r\nHost: localhost\r\n\r\n";
    let sn, se = core::host_send(host, cli_end, req_big);
    assert(sn == (req_big.len as i32) && se == core::IoError.None);

    now_ns = core::add_sat_u64(now_ns, 250000000);
    let _ = wing::async_reactor_step(host, g_async_http_server, reactor, app, 0, now_ns);
    assert(reactor.conns[v_idx].rx_cap == 0 && reactor.conns[v_idx].rx_len == 0);
    assert(reactor.conns[v_idx].tx_len > 8000 && reactor.conns[v_idx].tx_cap >= 8192);
    assert(reactor.buf_items.len >= 8192);

    assert(core::host_set_rx_paused(host, cli_end, false));
    for _ in 12 {
        now_ns = core::add_sat_u64(now_ns, 1000000);
        let _ = wing::async_reactor_step(host, g_async_http_server, reactor, app, 0, now_ns);
        if app.bp_z_count == BIG_BODY_BYTES && reactor.conns[v_idx].tx_len == 0 {
            break;
        }
    }
    assert(app.bp_z_count == BIG_BODY_BYTES && app.bp_rx_len > BIG_BODY_BYTES);
    assert_all_reactor_conns_idle_zero_buf(reactor, SCALE_CONN_COUNT + 1);
}

fn test_scale_320_conns_and_zero_idle_buffers() {
    var dcfg = net_internal::TransportDriverConfig {
        active_kind: net_internal::TransportDriverKind.Standard,
        is_probed:   true,
        ..
    };
    var host = wing::new_net_host(dcfg);
    defer wing::close_net_host(host);

    g_async_http_server = wing::new_http_server("127.0.0.1", 0);
    wing::add_get_route(g_async_http_server, "/scale", 20);
    wing::add_get_route(g_async_http_server, "/big", 21);

    var reactor = wing::AsyncServerReactor { .. };
    assert(wing::async_reactor_listen_http(
        host, reactor, core::ConnectAddr.Tcp { host: "127.0.0.1", port: 0 }, 128,
    ));
    let http_port = wing::link_local_port(host, reactor.listener_link);
    assert(http_port > 0);

    var app = ScaleProbeApp { .. };
    var now_ns: u64 = 50000000000;
    open_scale_tcp_connections(host, reactor, app, http_port, now_ns);
    verify_split_h1_keepalive_scale(host, reactor, app, now_ns);
    verify_backpressured_tx_pool_lease_and_release(host, reactor, app, now_ns);
    print("TASK6_SCALE_320_ZERO_IDLE_BUF: OK");
}

fn main() {
    let cli_args = args();
    var uds_path: u8[..104] = [];
    if cli_args.len > 1 && cli_args[1].len > 0 && cli_args[1].len < 100 {
        let _ = uds_path.try_set(cli_args[1]);
    } else {
        let _ = uds_path.try_set("./wing_async_io_host_test.sock");
    }

    test_tcp_nonblocking_connect_and_refused();
    test_af_unix_listen_connect_roundtrip(uds_path[..]);
    test_virtual_backpressure_and_driver_chain();
    test_http_plus_async_pg_full_integration();
    test_scale_320_conns_and_zero_idle_buffers();
}

// CHECK: TASK1_TCP_NONBLOCKING_SO_ERROR: OK
// CHECK: TASK2_AF_UNIX_ROUNDTRIP: OK
// CHECK: TASK3_BACKPRESSURE_AND_CHAIN: OK
// CHECK: TASK4A_HTTP1_PIPELINED_PG_WAKE: OK
// CHECK: TASK4B_HTTP2_MULTIPLEX_PG_WAKE: OK
// CHECK: TASK4C_STALE_WAKE_SAFETY: OK
// CHECK: TASK5_SERVE_REACTOR_WITH_IO: OK
// CHECK: TASK6_SCALE_320_ZERO_IDLE_BUF: OK
