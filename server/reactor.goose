// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Share-nothing non-blocking epoll/IOCP/kqueue reactor, TLS 1.3 slot multiplexer,
// and HTTP/3 UDP datagram server engine.
// Encapsulates worker-local SoAConnTable, slice_pool<u8> leftover preservation,
// and lazily materialized HTTP/2 session slots behind zero-cost UFCS methods.
namespace server;

import std;
import slice_pool;
import core;
import .router;
import .pool;
import .pipeline;
import .h2_mux_types_internal;
import .h2_mux_frames_internal;
import .h2_mux_streams_internal;
import .soa_timer;
import .server;
import net.accel;
import .reactor_async_internal;
import .reactor_conn_internal;
import .reactor_io_internal;
import .reactor_accel_internal;
import .server_h1_internal;
import .server_fast_l0_internal;
import .server_transport_internal;
import .h1_codec;
import .h1_codec_internal;
import .internal;
import .cork;

const REACTOR_MAX_H2_SESSIONS: i64 = 128;

var g_default_reactor: server_internal::ReactorState = server_internal::ReactorState { .. };

var g_reactor_chunk: server_internal::ReactorIngressBuf = server_internal::ReactorIngressBuf { .. };

var g_reactor_cork_bufs: u8[..65536][>..] = [];

var g_reactor_tls_plain_bufs: u8[..32768][>..] = [];

var g_reactor_tls_seal_bufs: u8[..65536][>..] = [];

var g_reactor_tls_rx_bufs: u8[16384][>..] = [];

var g_reactor_conn_pool: server_internal::ReactorConnectionPool = server_internal::ReactorConnectionPool { .. };

var g_reactor_accel: net::ReactorAccelRuntime = net::ReactorAccelRuntime { .. };

// Opens a listening TCP socket configured for OS completion accelerators when supported.
fn reactor_listen_accelerated(server: const HttpServer&, backlog: i32 = 0) -> i64 {
    let eff_backlog = if backlog > 0 {
        backlog
    } else if server.listen_backlog > 0 {
        server.listen_backlog
    } else {
        128
    };
    let fd = net::listen_accelerated_tcp(server.host[..], server.port, server.accel_mode, eff_backlog);
    guard fd > 0 else { return -1; }
    if server.so_reuseport {
        let _ = net::tcp_set_reuseport(fd, true);
    }
    let _ = net::tcp_set_nodelay(fd, server.tcp_nodelay);
    if server.tcp_user_timeout_ms > 0 {
        let _ = net::tcp_set_user_timeout(fd, server.tcp_user_timeout_ms);
    }
    return fd;
}

fn alloc_reactor_h2_session(
    pipeline:    ServerPipelineConfig&,
    server_name: const u8[:],
    now_ms:      u64,
    max_streams: u32 = 0,
) -> i16 {
    let eff_streams = min(
        if max_streams > 0 {
            max_streams
        } else if pipeline.max_h2_concurrent_streams > 0 {
            pipeline.max_h2_concurrent_streams
        } else {
            16
        },
        16,
    );
    let eff_hdr_list = if pipeline.max_header_bytes > 0 {
        min(pipeline.max_header_bytes, 0x7FFFFFFF) as u32
    } else {
        16384
    };
    for i in REACTOR_MAX_H2_SESSIONS {
        guard !g_default_reactor.h2_in_use[i] else { continue; }
        while g_default_reactor.h2_sessions.len <= i {
            g_default_reactor.h2_sessions.push(server_internal::H2ServerSession { .. });
        }
        server_internal::cleanup_h2_server_session(g_default_reactor.h2_sessions[i], pipeline);
        g_default_reactor.h2_in_use[i] = true;
        server_internal::reset_h2_server_session_inplace(
            g_default_reactor.h2_sessions[i], server_name, now_ms,
        );
        g_default_reactor.h2_sessions[i].conn.max_concurrent_streams = eff_streams;
        g_default_reactor.h2_sessions[i].conn.max_header_list_size = eff_hdr_list;
        return i as i16;
    }
    return -1;
}

fn free_reactor_h2_session(h2_idx: i16, pipeline: ServerPipelineConfig&) {
    let idx = h2_idx as i64;
    guard idx >= 0 && idx < g_default_reactor.h2_sessions.len &&
        idx < REACTOR_MAX_H2_SESSIONS && g_default_reactor.h2_in_use[idx] else {
        return;
    }
    server_internal::cleanup_h2_server_session(g_default_reactor.h2_sessions[idx], pipeline);
    g_default_reactor.h2_in_use[idx] = false;
}

// Encapsulated UFCS method on SoAConnTable: acquires or returns the persistent H2ServerSession index for `slot`.
fn ensure_h2_session(
    table:       SoAConnTable&,
    slot:        i64,
    pipeline:    ServerPipelineConfig&,
    server_name: const u8[:],
    now_ms:      u64,
) -> i64 {
    guard server_internal::is_valid_slot(table, slot) else { return -1; }
    var h2_idx = table.h2_slot_map[slot];
    if !table.is_h2[slot] || h2_idx < 0 || h2_idx >= REACTOR_MAX_H2_SESSIONS {
        h2_idx = alloc_reactor_h2_session(pipeline, server_name, now_ms);
        if h2_idx < 0 {
            return -1;
        }
        table.h2_slot_map[slot] = h2_idx;
        table.is_h2[slot] = true;
    }
    return h2_idx;
}

// Encapsulated UFCS method on SoAConnTable: detaches and cleans up any H2ServerSession bound to `slot`.
fn release_h2_session(table: SoAConnTable&, slot: i64, pipeline: ServerPipelineConfig&) {
    guard server_internal::is_valid_slot(table, slot) else { return; }
    if table.h2_slot_map[slot] >= 0 {
        free_reactor_h2_session(table.h2_slot_map[slot], pipeline);
        table.h2_slot_map[slot] = -1;
        table.is_h2[slot] = false;
    }
}

// Encapsulated UFCS method on SoAConnTable: construct a polymorphic net::Transport for `slot`.
// Unifies plain TCP and TLS 1.3 record channels under Liskov Substitution (LSP).
fn slot_transport(table: const SoAConnTable&, slot: i64) -> net::Transport {
    guard server_internal::is_active_slot(table, slot) else { return net::Transport.Disconnected; }
    let fd = table.fds[slot];
    if table.has_tls[slot] && table.tls_slots[slot] != 0xFFFF {
        return net::Transport.Tls {
            fd:            fd,
            record_seq_rx: 0,
            record_seq_tx: 0,
            cipher_slot:   table.tls_slots[slot],
        };
    }
    return net::Transport.Tcp { fd: fd };
}

inline fn resolve_accel_wait_ms(n_ready: i32, wait_ms: i32) -> i32 {
    guard n_ready <= 0 else { return 0; }
    if g_reactor_accel.epfd_registered_count > 0 && !g_reactor_accel.uring_epoll_armed {
        return min(wait_ms, 1);
    }
    return wait_ms;
}

inline fn step_plain_reactor_turn<Stage>(
    server:         HttpServer&,
    epfd:           i64,
    listener_fd:    i64,
    draining:       bool,
    table:          SoAConnTable&,
    leftover_pool:  slice_pool<u8>&,
    slot_pool:      server_internal::ReactorSlotPool&,
    timer_wheel:    core::TickTimerWheel&,
    dummy_tls_cfg:  const tls::ServerHandshakeConfig&,
    ready_udata:    u64[4096]&,
    turn_counter:   i64&,
    last_sweep_sec: i64&,
    total_served:   i64&,
    cached_now_ns:  u64&,
    cached_now_sec: i64&,
    prev_had_work:  bool&,
    stage:          Stage&,
) {
    let wait_ms: i32 = 200;
    let n_ready = net::reactor_wait_readiness_events(g_reactor_accel, ready_udata[..], wait_ms);
    turn_counter = core::add_sat_i64(turn_counter, 1);
    let poll_hint: i32 = if n_ready > 0 || prev_had_work { 1 } else { 0 };
    server_internal::reactor_poll_sweep(
        epfd, table, leftover_pool, slot_pool, server.pipeline, timer_wheel, poll_hint, turn_counter,
        last_sweep_sec, total_served, cached_now_ns, cached_now_sec, server.pipeline.enable_slowloris_timer,
    );
    if n_ready > 0 {
        server_internal::reactor_dispatch_events(
            server, epfd, listener_fd, table, leftover_pool,
            slot_pool, timer_wheel, ready_udata[..n_ready], cached_now_ns,
            g_reactor_chunk, g_reactor_cork_bufs[0], total_served, stage,
        );
    }
    let accel_wait_ms = resolve_accel_wait_ms(n_ready, wait_ms);
    let n_rio = server_internal::reactor_step_rio_completions(
        server, draining, dummy_tls_cfg, false, table, leftover_pool,
        slot_pool, timer_wheel, accel_wait_ms, cached_now_ns,
        g_reactor_chunk, g_reactor_cork_bufs[0], total_served, stage,
    );
    let n_uring = server_internal::reactor_step_uring_completions(
        server, listener_fd, draining, dummy_tls_cfg, false, accel_wait_ms, table, leftover_pool,
        slot_pool, timer_wheel, cached_now_ns,
        g_reactor_chunk, g_reactor_cork_bufs[0], total_served, stage,
    );
    prev_had_work = n_ready > 0 || n_rio > 0 || n_uring > 0;
}

// Executes a share-nothing reactor loop with OS completion/readiness acceleration and a `<Stage>` hook.
fn serve_reactor_with_stage<Stage>(
    server:          HttpServer&,
    listener_fd:     i64,
    stage:           Stage&,
    max_connections: i64 = 0,
) -> i64 {
    guard listener_fd > 0 else { return 0; }
    guard server_internal::reactor_prepare_loop(server, listener_fd) else { return 0; }
    defer net::reactor_close_accel(g_reactor_accel);

    let slot_cap = server_internal::resolve_reactor_slot_cap(server);
    var table = SoAConnTable { max_slots: slot_cap, .. };
    var slot_pool = server_internal::ReactorSlotPool { max_slots: slot_cap, .. };
    var leftover_pool = slice_pool<u8> {};

    let dummy_tls_cfg = tls::ServerHandshakeConfig { .. };
    var ready_udata:  u64[4096] = [0; 4096];
    var total_served: i64       = 0;
    var timer_wheel = core::TickTimerWheel { idle_timeout_sec: server_internal::resolve_reactor_idle_sec(server), .. };
    var last_sweep_sec:    i64  = 0;
    var turn_counter:      i64  = 0;
    var cached_now_ns:     u64  = 0;
    var cached_now_sec:    i64  = 0;
    var draining:          bool = false;
    var drain_deadline_ns: u64  = 0;
    var prev_had_work:     bool = false;

    while max_connections == 0 || total_served < max_connections {
        let epfd = g_reactor_accel.epfd;
        if server_internal::reactor_step_drain_gate(
            server, epfd, listener_fd, table, g_reactor_cork_bufs[0], draining, drain_deadline_ns,
        ) { break; }
        step_plain_reactor_turn(
            server, epfd, listener_fd, draining, table, leftover_pool, slot_pool, timer_wheel, dummy_tls_cfg,
            ready_udata, turn_counter, last_sweep_sec, total_served, cached_now_ns, cached_now_sec,
            prev_had_work, stage,
        );
    }
    let _ = net::reactor_flush_uring_sqes(g_reactor_accel);
    server_internal::reactor_cleanup_all(
        g_reactor_accel.epfd, table, leftover_pool, slot_pool, server.pipeline,
    );
    return total_served;
}

// Executes a share-nothing reactor loop with automatic OS accelerator selection.
fn serve_reactor(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64 {
    var noop = wire::NoOpStage {};
    return serve_reactor_with_stage(server, listener_fd, noop, max_connections);
}

inline fn step_tls_reactor_turn<Stage>(
    server:         HttpServer&,
    epfd:           i64,
    listener_fd:    i64,
    draining:       bool,
    table:          SoAConnTable&,
    leftover_pool:  slice_pool<u8>&,
    slot_pool:      server_internal::ReactorSlotPool&,
    timer_wheel:    core::TickTimerWheel&,
    tls_config:     const tls::ServerHandshakeConfig&,
    ready_udata:    u64[4096]&,
    turn_counter:   i64&,
    last_sweep_sec: i64&,
    total_served:   i64&,
    cached_now_ns:  u64&,
    cached_now_sec: i64&,
    prev_had_work:  bool&,
    stage:          Stage&,
) {
    let n_ready = net::reactor_wait_readiness_events(g_reactor_accel, ready_udata[..], 10);
    turn_counter = core::add_sat_i64(turn_counter, 1);
    let poll_hint: i32 = if n_ready > 0 || prev_had_work { 1 } else { 0 };
    server_internal::reactor_poll_sweep(
        epfd, table, leftover_pool, slot_pool, server.pipeline, timer_wheel, poll_hint, turn_counter,
        last_sweep_sec, total_served, cached_now_ns, cached_now_sec, server.pipeline.enable_slowloris_timer,
    );
    if n_ready > 0 {
        server_internal::reactor_dispatch_tls_events(
            server, epfd, listener_fd, table, leftover_pool,
            slot_pool, timer_wheel, tls_config, ready_udata[..n_ready as i64],
            cached_now_ns, g_reactor_chunk, g_reactor_cork_bufs[0], total_served, stage,
        );
    }
    let accel_wait_ms = resolve_accel_wait_ms(n_ready, 10);
    let n_rio = server_internal::reactor_step_rio_completions(
        server, draining, tls_config, true, table, leftover_pool,
        slot_pool, timer_wheel, accel_wait_ms, cached_now_ns,
        g_reactor_chunk, g_reactor_cork_bufs[0], total_served, stage,
    );
    let n_uring = server_internal::reactor_step_uring_completions(
        server, listener_fd, draining, tls_config, true, accel_wait_ms,
        table, leftover_pool,
        slot_pool, timer_wheel, cached_now_ns,
        g_reactor_chunk, g_reactor_cork_bufs[0], total_served, stage,
    );
    prev_had_work = n_ready > 0 || n_rio > 0 || n_uring > 0;
}

// Executes a TLS 1.3 reactor loop with opportunistic kTLS, completion rings, and a `<Stage>` hook.
fn serve_reactor_tls_with_stage<Stage>(
    server:          HttpServer&,
    listener_fd:     i64,
    tls_config:      const tls::ServerHandshakeConfig&,
    stage:           Stage&,
    max_connections: i64 = 0,
) -> i64 {
    guard listener_fd > 0 else { return 0; }
    guard server_internal::reactor_prepare_loop(server, listener_fd) else { return 0; }
    defer net::reactor_close_accel(g_reactor_accel);

    let slot_cap = server_internal::resolve_reactor_slot_cap(server);
    var table = SoAConnTable { max_slots: slot_cap, .. };
    var slot_pool = server_internal::ReactorSlotPool { max_slots: slot_cap, .. };
    var leftover_pool = slice_pool<u8> {};

    var ready_udata:  u64[4096] = [0; 4096];
    var total_served: i64       = 0;
    var timer_wheel = core::TickTimerWheel { idle_timeout_sec: server_internal::resolve_reactor_idle_sec(server), .. };
    var last_sweep_sec:    i64  = 0;
    var turn_counter:      i64  = 0;
    var cached_now_ns:     u64  = 0;
    var cached_now_sec:    i64  = 0;
    var draining:          bool = false;
    var drain_deadline_ns: u64  = 0;
    var prev_had_work:     bool = false;

    while max_connections == 0 || total_served < max_connections {
        let epfd = g_reactor_accel.epfd;
        if server_internal::reactor_step_drain_gate(
            server, epfd, listener_fd, table, g_reactor_cork_bufs[0], draining, drain_deadline_ns,
        ) {
            break;
        }
        step_tls_reactor_turn(
            server, epfd, listener_fd, draining, table, leftover_pool, slot_pool, timer_wheel, tls_config,
            ready_udata, turn_counter, last_sweep_sec, total_served, cached_now_ns, cached_now_sec,
            prev_had_work, stage,
        );
    }
    let _ = net::reactor_flush_uring_sqes(g_reactor_accel);
    server_internal::reactor_cleanup_all(
        g_reactor_accel.epfd, table, leftover_pool, slot_pool, server.pipeline,
    );
    return total_served;
}

// Executes a TLS 1.3 reactor loop with opportunistic kTLS and completion-ring cipher slots.
fn serve_reactor_tls(
    server:          HttpServer&,
    listener_fd:     i64,
    tls_config:      const tls::ServerHandshakeConfig&,
    max_connections: i64 = 0,
) -> i64 {
    var noop = wire::NoOpStage {};
    return serve_reactor_tls_with_stage(server, listener_fd, tls_config, noop, max_connections);
}

// Processes an incoming HTTP/3 request stream payload through `H3Connection` and `server.pipeline` (RFC 9114).
fn handle_h3_server_datagram<B>(
    server:    HttpServer&,
    h3_conn:   http3::Connection&,
    stream_id: u64,
    client_ip: const u8[:],
    rx_wire:   const u8[:],
    now_ns:    u64,
    tx_wire:   B&,
    tls_sni:   const u8[:] = "",
) -> bool {
    tx_wire.clear();
    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }
    let h_err = http3::handle_stream_data(h3_conn, stream_id, true, rx_wire, true);
    guard h_err == rfc::H3_ERR_NO_ERROR else { return false; }

    let s_idx, found = http3::find_stream_idx(h3_conn, stream_id);
    guard found && s_idx >= 0 && s_idx < h3_conn.streams.len else { return false; }
    guard h3_conn.streams[s_idx].headers_received else { return false; }

    let method = if h3_conn.streams[s_idx].req_method.len > 0 { h3_conn.streams[s_idx].req_method[..] } else { "GET" };
    let path = if h3_conn.streams[s_idx].req_path.len > 0 { h3_conn.streams[s_idx].req_path[..] } else { "/" };
    var req = http::new_request(method, path);
    if h3_conn.streams[s_idx].req_authority.len > 0 {
        let _ = http::append_header(req.headers, "host", h3_conn.streams[s_idx].req_authority[..]);
        req.presence_mask |= http::HDR_PRESENCE_HOST;
    }
    let _ = http3::copy_stream_headers(h3_conn, stream_id, req.headers);
    for &e in req.headers.entries {
        let known_id = http::identify_known_header(http::entry_name(req.headers, e));
        req.presence_mask |= http::header_id_to_bit(known_id);
    }
    if tls_sni.len > 0 && server_internal::h2_stream_conflicts_with_sni(
        tls_sni, h3_conn.streams[s_idx].req_authority[..], req.headers,
    ) {
        let empty_hdrs = http::HeaderMap { .. };
        let empty_trl = http::HeaderMap { .. };
        return http3::send_response_headers_body_and_trailers(
            h3_conn, stream_id, rfc::STATUS_MISDIRECTED_REQUEST, empty_hdrs, "", empty_trl, tx_wire,
        );
    }
    let _ = http3::copy_stream_trailers(h3_conn, stream_id, req.trailers);
    if h3_conn.streams[s_idx].received_body.len > 0 {
        req.body.append(h3_conn.streams[s_idx].received_body[..]);
    }

    var res = http::Response { .. };
    var future = server_internal::new_inline_handler_future(0);
    execute_pipeline(server.pipeline, server.timer, client_ip, req, now_ns, res, future);
    server.requests_processed++;

    var extra_map = http::HeaderMap { .. };
    for &e in res.headers.entries {
        let hdr_name = http::entry_name(res.headers, e);
        let hdr_val = http::entry_value(res.headers, e);
        var lname: u8[..256] = [];
        guard hdr_name.len <= lname.cap else { continue; }
        hdr_name.to_lower_ascii(lname);
        let _ = extra_map.append_header(lname[..], hdr_val);
    }
    return http3::send_response_headers_body_and_trailers(
        h3_conn, stream_id, res.status_code, extra_map, res.body[..], res.trailers, tx_wire,
    );
}

// Executes an Unencrypted H3 over UDP (Datagram Direct) server loop (RFC 9114 framing + QPACK)
// using batched `recvmmsg` / `sendmmsg` transitions up to 32 datagrams per syscall.
fn serve_h3(server: HttpServer&, udp_fd: i64, max_datagrams: i64 = 1) -> i64 {
    guard udp_fd > 0 else { return 0; }
    let h3_settings = fingerprint::H3Settings { .. };
    var h3_conn = http3::new_server_connection(h3_settings);
    var rx_queue = net::UdpBatchQueue { .. };
    var tx_queue = net::UdpBatchQueue { .. };
    var tx_wire:    u8[..1472] = [];
    var served:     i64        = 0;
    var idle_spins: i64        = 0;

    while max_datagrams == 0 || served < max_datagrams {
        let recvd, ok_rx = net::batch_recv_messages(rx_queue, udp_fd as i32);
        if !ok_rx || recvd <= 0 {
            idle_spins = core::add_sat_i64(idle_spins, 1);
            if max_datagrams > 0 && idle_spins >= 25 { break; }
            continue;
        }
        idle_spins = 0;
        let now_ns = core::monotonic_now().as_nanos();
        for i in rx_queue.msgs.len {
            if max_datagrams > 0 && served >= max_datagrams { break; }
            server_internal::dispatch_h3_udp_datagram(
                server,
                udp_fd,
                h3_conn,
                served,
                rx_queue.msgs[i].peer_ip4,
                rx_queue.msgs[i].peer_port,
                rx_queue.msgs[i].payload[..],
                now_ns,
                tx_wire,
                tx_queue,
            );
            served = core::add_sat_i64(served, 1);
        }
        if tx_queue.msgs.len > 0 {
            let _, _ = net::batch_send_messages(tx_queue, udp_fd as i32);
        }
    }
    return served;
}

// Public HTTP/3 and QUIC server endpoint state (RFC 9000, RFC 9114, RFC 9204).
// Encapsulates HTTP/3 connection state, QPACK tables, and QUIC handshake framing.
struct H3ServerEndpoint {
    conn:               http3::Connection = http3::Connection { .. },
    allow_plaintext_h3: bool              = false,
    tls_sni:            u8[..255]         = [],
}

fn new_h3_server_endpoint(
    settings: fingerprint::H3Settings = fingerprint::H3Settings { .. },
) -> H3ServerEndpoint {
    var ep = H3ServerEndpoint {
        conn: http3::new_server_connection(settings),
    };
    ep.conn.qpack_table.capacity_bytes = 0;
    return ep;
}

// Processes an incoming QUIC / HTTP/3 UDP datagram through `H3ServerEndpoint` and `server.pipeline`.
// Supports both Unencrypted H3 over UDP (Datagram Direct, `(datagram[0] & 0xC0) == 0`) and
// QUIC v1 Version Negotiation / Initial packet demultiplexing (RFC 9000 Section 17.2).
// Populates `out_wire` with the serialized QUIC or HTTP/3 response datagram when `true` is returned.
fn handle_h3_quic_datagram<B>(
    server:    HttpServer&,
    ep:        H3ServerEndpoint&,
    client_ip: const u8[:],
    datagram:  const u8[:],
    now_ns:    u64,
    out_wire:  B&,
) -> bool {
    guard datagram.len > 0 else { return false; }
    out_wire.clear();

    if ep.allow_plaintext_h3 && (datagram[0] & 0xC0) == 0 {
        if server_internal::handle_h3_endpoint_frame(server, ep, client_ip, datagram, now_ns, out_wire) {
            return out_wire.len > 0;
        }
    }

    let quic_hdr, ok_qhdr = quic::parse_header(datagram);
    guard ok_qhdr else { return false; }

    if quic_hdr.version != rfc::QUIC_VERSION_1 && quic_hdr.version != rfc::QUIC_VERSION_NEGOTIATION {
        // RFC 9000 Section 6.1: Version Negotiation - Only respond to packets >= 1200 bytes.
        guard ep.allow_plaintext_h3 || datagram.len >= (rfc::QUIC_MIN_INITIAL_DATAGRAM_LEN as i64) else {
            return false;
        }
        server_internal::encode_quic_version_negotiation(quic_hdr, out_wire);
        return out_wire.len > 0;
    }

    if quic_hdr.header_type == quic::QuicHeaderType.Initial && ep.allow_plaintext_h3 {
        // RFC 9000 Section 14.1: Initial Datagram Size - server MUST discard client Initial < 1200 bytes
        guard datagram.len >= (rfc::QUIC_MIN_INITIAL_DATAGRAM_LEN as i64) else {
            return false;
        }
        server_internal::encode_quic_server_initial(ep, quic_hdr, out_wire);
        return out_wire.len > 0;
    }

    return false;
}

// Kernel-bypass L2 datapath backend selection for `serve_h3_l2`.
enum H3L2Backend {
    UdpFallback,
    AfXdp,
    Dpdk,
}

// L2/L3/L4 binding parameters for `serve_h3_l2` over `AF_XDP`, `DPDK`, or `UdpFallback`.
struct H3L2Config {
    backend:       H3L2Backend                 = H3L2Backend.UdpFallback,
    local_ep:      net_internal::L2UdpEndpoint = net_internal::L2UdpEndpoint { .. },
    udp_fd:        i64                         = -1,
    dpdk_port_id:  u16                         = 0,
    dpdk_queue_id: u16                         = 0,
}

// Serves Direct-H3 and QUIC Initial/Version-Negotiation packets over L2 `AF_XDP`, `DPDK`,
// or `UdpFallback` (`serve_h3` batched `recvmmsg` / `sendmmsg`).
fn serve_h3_l2(
    server:      HttpServer&,
    ep:          H3ServerEndpoint&,
    cfg:         const H3L2Config&,
    xsk:         net_internal::AfXdpSocket&,
    max_packets: i64 = 64,
) -> i64 {
    match cfg.backend {
        UdpFallback => {
            return serve_h3(server, cfg.udp_fd, max_packets);
        },
        AfXdp => {
            return server_internal::serve_h3_af_xdp(server, ep, cfg, xsk, max_packets);
        },
        Dpdk => {
            return server_internal::serve_h3_dpdk(server, ep, cfg, max_packets);
        },
    }
}
