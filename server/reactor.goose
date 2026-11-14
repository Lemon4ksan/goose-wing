// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Share-nothing non-blocking epoll/IOCP/kqueue reactor, TLS 1.3 slot multiplexer,
// and HTTP/3 UDP datagram server engine.
// Encapsulates SoAConnTable, leftover preservation buffers, and persistent HTTP/2
// session slots behind zero-cost UFCS lifecycle methods.
namespace wing;

import std;
import core from "..";
import .router;
import .pool;
import .pipeline;
import .h2_multiplexer;
import .soa_timer;
import .server;

const REACTOR_LEFTOVER_CAP:    i64 = 8192;
const REACTOR_MAX_H2_SESSIONS: i64 = 128;

struct ReactorLeftoverBuf {
    bytes: u8[8192] = [0; 8192],
}

struct ReactorIngressBuf {
    bytes: u8[65536] = [0; 65536],
    len:   i64       = 0,
}

struct ReactorState {
    h2_sessions: internal::H2ServerSession[128]  = [internal::H2ServerSession { .. }; 128],
    h2_in_use:   bool[128]                       = [false; 128],
    leftovers:   ReactorLeftoverBuf[4096]        = [ReactorLeftoverBuf { .. }; 4096],
    table:       SoAConnTable                    = SoAConnTable { .. },
    chunk:       ReactorIngressBuf               = ReactorIngressBuf { .. },
    cork:        u8[..65536]                     = [],
    free_slots:  FreeSlotStack                   = FreeSlotStack { .. },
    conn_pool:   internal::ReactorConnectionPool = internal::ReactorConnectionPool { .. },
}

var g_default_reactor: ReactorState = ReactorState { .. };

fn alloc_reactor_h2_session(
    pipeline:    ServerPipelineConfig&,
    server_name: const u8[:],
    now_ms:      u64,
) -> i16 {
    for i in REACTOR_MAX_H2_SESSIONS {
        if !g_default_reactor.h2_in_use[i] {
            internal::cleanup_h2_server_session(g_default_reactor.h2_sessions[i], pipeline);
            g_default_reactor.h2_in_use[i] = true;
            internal::reset_h2_server_session_inplace(g_default_reactor.h2_sessions[i], server_name, now_ms);
            return i as i16;
        }
    }
    return -1;
}

fn free_reactor_h2_session(h2_idx: i16, pipeline: ServerPipelineConfig&) {
    let idx = h2_idx as i64;
    guard idx >= 0 && idx < REACTOR_MAX_H2_SESSIONS && g_default_reactor.h2_in_use[idx] else { return; }
    internal::cleanup_h2_server_session(g_default_reactor.h2_sessions[idx], pipeline);
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
    guard slot >= 0 && slot < SOA_TABLE_CAP else { return; }
    if table.h2_slot_map[slot] >= 0 {
        free_reactor_h2_session(table.h2_slot_map[slot], pipeline);
        table.h2_slot_map[slot] = -1;
        table.is_h2[slot] = false;
    }
}

// Encapsulated UFCS method on SoAConnTable: construct a polymorphic wing::Transport for `slot`.
// Unifies plain TCP and TLS 1.3 record channels under Liskov Substitution (LSP).
fn slot_transport(table: const SoAConnTable&, slot: i64) -> Transport {
    let fd = table.fds[slot];
    guard fd > 0 else { return Transport.Disconnected; }
    if table.has_tls[slot] && table.tls_slots[slot] != 0xFFFF {
        return Transport.Tls {
            fd:            fd,
            record_seq_rx: 0,
            record_seq_tx: 0,
            cipher_slot:   table.tls_slots[slot],
        };
    }
    return Transport.Tcp { fd: fd };
}

// Cleans up a connection slot, removes from epoll, closes transport, and returns slot to free stack.
fn reactor_cleanup_slot(
    epfd:       i64,
    table:      SoAConnTable&,
    slot_idx:   i64,
    free_slots: FreeSlotStack&,
) {
    let fd = table.fds[slot_idx];
    if fd > 0 {
        epoll_del(epfd, fd);
        var tr = table.slot_transport(slot_idx);
        tr.close();
        if table.h2_slot_map[slot_idx] >= 0 {
            let h2_i = table.h2_slot_map[slot_idx] as i64;
            if h2_i >= 0 && h2_i < REACTOR_MAX_H2_SESSIONS {
                g_default_reactor.h2_in_use[h2_i] = false;
            }
        }
        internal::free_connection_slot(g_default_reactor.conn_pool, slot_idx as i32);
        table.soa_table_free(slot_idx);
    }
    push_free_slot(free_slots, slot_idx);
}

// 1-second Tick Wheel Connection Timeout Sweeper (Slowloris defense & slot reclamation).
// Sweeps contiguous 1-byte timeout ticks entirely in L1D cache via SoAConnTable.
fn reactor_sweep_timeouts(
    epfd:           i64,
    table:          SoAConnTable&,
    free_slots:     FreeSlotStack&,
    timer_wheel:    core::TickTimerWheel&,
    now_sec:        i64,
    last_sweep_sec: i64&,
    total_served:   i64&,
) {
    guard now_sec > last_sweep_sec else { return; }
    let elapsed = if last_sweep_sec == 0 { 1 } else { (now_sec - last_sweep_sec) as u32 };
    last_sweep_sec = now_sec;
    core::tick_timer_advance(timer_wheel, elapsed);

    var expired: i64[4096] = [0; 4096];
    let n_expired = table.soa_table_sweep_expired(timer_wheel, expired[..]);
    for i in n_expired {
        let slot = expired[i];
        reactor_cleanup_slot(epfd, table, slot, free_slots);
        total_served++;
    }
}

// Reclaims one expired connection slot during emergency saturation via fast SoA sweep.
fn reactor_evict_stale_slot(
    epfd:         i64,
    table:        SoAConnTable&,
    free_slots:   FreeSlotStack&,
    timer_wheel:  core::TickTimerWheel&,
    total_served: i64&,
) -> i64 {
    var expired: i64[1] = [0];
    let n = table.soa_table_sweep_expired(timer_wheel, expired[..]);
    if n > 0 {
        let slot = expired[0];
        reactor_cleanup_slot(epfd, table, slot, free_slots);
        total_served++;
        return pop_free_slot(free_slots);
    }
    return -1;
}

// Registers an accepted non-blocking client connection into an allocated slot.
inline fn reactor_register_client_slot(
    epfd:        i64,
    table:       SoAConnTable&,
    client_fd:   i64,
    slot:        i64,
    timer_wheel: core::TickTimerWheel&,
) {
    table.fds[slot] = client_fd;
    table.timeout_ticks[slot] = core::tick_timer_arm(timer_wheel, 15);
    table.leftover_lens[slot] = 0;
    table.is_h2[slot] = false;
    table.h2_slot_map[slot] = -1;
    table.has_tls[slot] = false;
    table.tls_slots[slot] = 0xFFFF;
    table.has_peer_ip[slot] = false;
    table.peer_ip_hashes[slot] = 0;
    table.peer_ips[slot].clear();
    table.count = advance_high_water_mark(table.count, slot);
    let _ = internal::alloc_connection_slot(g_default_reactor.conn_pool, client_fd, 0);
    epoll_add(epfd, client_fd, EPOLL_READ, slot as u64);
}

// Lazily resolves and caches the peer IP for a connection slot in SoAConnTable.
inline fn reactor_resolve_slot_peer_ip(table: SoAConnTable&, slot: i64, conn: i64) -> const u8[:] {
    if !table.has_peer_ip[slot] {
        var resolved_ip: u8[..64] = [];
        tcp_get_peer_ip(conn, resolved_ip);
        table.soa_table_set_peer_ip(slot, resolved_ip[..]);
    }
    return table.soa_table_get_peer_ip(slot);
}

// Drains non-blocking listener queue and accepts ready incoming connections into free slots.
fn reactor_drain_listener(
    listener_fd:  i64,
    epfd:         i64,
    table:        SoAConnTable&,
    free_slots:   FreeSlotStack&,
    timer_wheel:  core::TickTimerWheel&,
    total_served: i64&,
) {
    loop {
        let client_fd = tcp_accept_nonblocking(listener_fd);
        if client_fd <= 0 { break; }

        var slot = pop_free_slot(free_slots);
        if slot < 0 {
            slot = reactor_evict_stale_slot(epfd, table, free_slots, timer_wheel, total_served);
        }
        if slot >= 0 {
            reactor_register_client_slot(epfd, table, client_fd, slot, timer_wheel);
        } else {
            tcp_close(client_fd);
        }
    }
}

// Drains incoming client connection tasks from lock-free SPSC ring queue.
fn reactor_drain_worker_ring(
    ring:         const core::SpscRing&,
    epfd:         i64,
    table:        SoAConnTable&,
    free_slots:   FreeSlotStack&,
    timer_wheel:  core::TickTimerWheel&,
    total_served: i64&,
) {
    guard ring.is_open && ring.handle != 0 else { return; }
    loop {
        var client_val: u64 = 0;
        let popped = ring.spsc_pop(client_val);
        if !popped { break; }
        let client_fd = client_val as i64;
        guard client_fd > 0 else { continue; }

        var slot = pop_free_slot(free_slots);
        if slot < 0 {
            slot = reactor_evict_stale_slot(epfd, table, free_slots, timer_wheel, total_served);
        }
        if slot >= 0 {
            reactor_register_client_slot(epfd, table, client_fd, slot, timer_wheel);
        } else {
            tcp_close(client_fd);
        }
    }
}

inline fn reactor_read_single_turn(conn: i64, chunk: ReactorIngressBuf&, available: i64) -> i32 {
    let offset = chunk.len;
    guard offset >= 0 && offset + available <= 65536 else { return -2; }
    let recvd = tcp_recv_nonblocking_slice(conn, chunk.bytes[offset..(offset + available)]);
    if recvd > 0 {
        chunk.len += recvd;
    }
    return recvd;
}

// Drains up to 4 turns of non-blocking TCP ingress into chunk buffer.
// Returns (any_recvd, is_closed).
fn reactor_read_bounded_turns(conn: i64, chunk: ReactorIngressBuf&) -> bool, bool {
    var any_recvd = false;
    for turn in 4 {
        let available = 65536 - chunk.len;
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

// Restores buffered leftover bytes into active chunk.
fn reactor_load_leftover(
    table:    SoAConnTable&,
    leftover: const ReactorLeftoverBuf&,
    slot:     i64,
    chunk:    ReactorIngressBuf&,
) {
    let prev_len = table.leftover_lens[slot] as i64;
    guard prev_len > 0 && prev_len <= REACTOR_LEFTOVER_CAP else { return; }
    for p in prev_len {
        chunk.bytes[p] = leftover.bytes[p];
    }
    chunk.len = prev_len;
    table.leftover_lens[slot] = 0;
}

// Copies leftover bytes into slot preservation buffer.
fn reactor_save_leftover(
    table:    SoAConnTable&,
    leftover: ReactorLeftoverBuf&,
    slot:     i64,
    rem:      const u8[:],
) -> bool {
    guard rem.len <= REACTOR_LEFTOVER_CAP else { return false; }
    table.leftover_lens[slot] = rem.len as u16;
    for m in rem.len {
        leftover.bytes[m] = rem[m];
    }
    return true;
}

inline fn inc_sent_total(total: i64, sent: i32) -> i64 {
    return total + sent;
}

// Flushes cork aggregation buffer to connection via bounded non-blocking send loop.
inline fn reactor_drain_cork_wire(conn: i64, wire: const u8[:]) -> bool {
    var sent_total: i64 = 0;
    while sent_total < wire.len {
        let sent = tcp_send(conn, wire[sent_total..]);
        if sent <= 0 { return false; }
        sent_total = inc_sent_total(sent_total, sent);
    }
    return true;
}

inline fn reactor_send_slot_wire(table: const SoAConnTable&, slot: i64, conn: i64, wire: const u8[:]) -> bool {
    if table.has_tls[slot] && table.tls_slots[slot] != 0xFFFF {
        let tr = table.slot_transport(slot);
        return tr.send(wire) > 0;
    }
    return reactor_drain_cork_wire(conn, wire);
}

fn reactor_handle_h2_ingress<Stage>(
    server:    HttpServer&,
    conn:      i64,
    table:     SoAConnTable&,
    leftovers: ReactorLeftoverBuf[:],
    slot:      i64,
    now_ns:    u64,
    chunk:     ReactorIngressBuf&,
    cork_wire: u8[..65536]&,
    stage:     Stage&,
) -> bool {
    let now_ms = now_ns / 1000000;
    cork_wire.clear();
    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }
    let h2_idx = table.ensure_h2_session(slot, server.pipeline, server.server_name[..], now_ms);
    guard h2_idx >= 0 && h2_idx < REACTOR_MAX_H2_SESSIONS else { return false; }
    let peer_ip_slice = reactor_resolve_slot_peer_ip(table, slot, conn);
    let consumed_h2, ok_h2 = internal::handle_h2_server_ingress(
        g_default_reactor.h2_sessions[h2_idx], server.pipeline, server.timer,
        peer_ip_slice, chunk.bytes[..chunk.len], now_ms, cork_wire, stage,
    );
    if cork_wire.len > 0 {
        if !reactor_send_slot_wire(table, slot, conn, cork_wire[..]) {
            return false;
        }
    }
    guard ok_h2 else { return false; }
    server.requests_processed++;
    if consumed_h2 < chunk.len {
        guard reactor_save_leftover(table, leftovers[slot], slot, chunk.bytes[consumed_h2..chunk.len]) else {
            return false;
        }
    }
    return true;
}

inline fn reactor_close_and_inc(
    server:       HttpServer&,
    epfd:         i64,
    table:        SoAConnTable&,
    slot:         i64,
    free_slots:   FreeSlotStack&,
    total_served: i64&,
) {
    table.release_h2_session(slot, server.pipeline);
    reactor_cleanup_slot(epfd, table, slot, free_slots);
    total_served++;
}

fn reactor_read_slot_turns(table: const SoAConnTable&, slot: i64, conn: i64, chunk: ReactorIngressBuf&) -> bool, bool {
    if table.has_tls[slot] && table.tls_slots[slot] != 0xFFFF {
        let available = 65536 - chunk.len;
        guard available > 0 else { return false, false; }
        let tr = table.slot_transport(slot);
        let recvd = tr.recv_slice(chunk.bytes[chunk.len..], 50);
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

// Processes non-blocking ingress traffic on a connection slot via bounded capacity-guarded read loop.
fn reactor_handle_ingress<Stage>(
    server:       HttpServer&,
    epfd:         i64,
    table:        SoAConnTable&,
    leftovers:    ReactorLeftoverBuf[:],
    slot:         i64,
    free_slots:   FreeSlotStack&,
    timer_wheel:  core::TickTimerWheel&,
    now_ns:       u64,
    chunk:        ReactorIngressBuf&,
    cork_wire:    u8[..65536]&,
    total_served: i64&,
    stage:        Stage&,
) {
    let conn = table.fds[slot];
    let prev_len = table.leftover_lens[slot] as i64;
    if server.pipeline.enable_slowloris_timer {
        table.soa_table_touch(slot, core::tick_timer_arm(timer_wheel, 15));
    }

    chunk.len = 0;
    reactor_load_leftover(table, leftovers[slot], slot, chunk);

    let any_recvd, is_closed = reactor_read_slot_turns(table, slot, conn, chunk);
    if is_closed {
        reactor_close_and_inc(server, epfd, table, slot, free_slots, total_served);
        return;
    }
    if !any_recvd && prev_len == 0 {
        return;
    }

    if table.is_h2[slot] || is_h2_client_preface(chunk.bytes[..chunk.len]) {
        let ok_h2 = reactor_handle_h2_ingress(server, conn, table, leftovers, slot, now_ns, chunk, cork_wire, stage);
        if !ok_h2 {
            reactor_close_and_inc(server, epfd, table, slot, free_slots, total_served);
        }
        return;
    }
    if is_partial_h2_client_preface(chunk.bytes[..chunk.len]) {
        if !reactor_save_leftover(table, leftovers[slot], slot, chunk.bytes[..chunk.len]) {
            reactor_close_and_inc(server, epfd, table, slot, free_slots, total_served);
        }
        return;
    }

    let need_peer_ip = server.pipeline.enable_rate_limiter
        || server.trust_proxy_headers
        || server.pipeline.trust_proxy_headers;
    let client_ip_slice: const u8[:] = if need_peer_ip {
        reactor_resolve_slot_peer_ip(table, slot, conn)
    } else {
        "127.0.0.1"
    };
    cork_wire.clear();
    let count, consumed, ok, wants_close = handle_connection_wire_pipelined_stream(
        server, client_ip_slice, chunk.bytes[..chunk.len], now_ns, cork_wire, stage,
    );

    let should_close = !ok || wants_close;
    if cork_wire.len > 0 {
        if !reactor_send_slot_wire(table, slot, conn, cork_wire[..]) || should_close {
            reactor_close_and_inc(server, epfd, table, slot, free_slots, total_served);
            return;
        }
    }
    if should_close {
        reactor_close_and_inc(server, epfd, table, slot, free_slots, total_served);
        return;
    }

    // Preserve unconsumed bytes for the next epoll turn
    if consumed < chunk.len {
        if !reactor_save_leftover(table, leftovers[slot], slot, chunk.bytes[consumed..chunk.len]) {
            reactor_close_and_inc(server, epfd, table, slot, free_slots, total_served);
        }
    }
}

// Dispatches ready epoll events for reactor connection slots with `<Stage>`.
fn reactor_dispatch_events<Stage>(
    server:       HttpServer&,
    epfd:         i64,
    listener_fd:  i64,
    table:        SoAConnTable&,
    leftovers:    ReactorLeftoverBuf[:],
    free_slots:   FreeSlotStack&,
    timer_wheel:  core::TickTimerWheel&,
    ready_udata:  const u64[:],
    now_ns:       u64,
    chunk:        ReactorIngressBuf&,
    cork_wire:    u8[..65536]&,
    total_served: i64&,
    stage:        Stage&,
) {
    for i in ready_udata.len {
        let udata = ready_udata[i];
        if udata == EPOLL_LISTENER_TAG {
            reactor_drain_listener(listener_fd, epfd, table, free_slots, timer_wheel, total_served);
            continue;
        }

        let slot = udata as i64;
        if slot < 0 || slot >= SOA_TABLE_CAP || table.fds[slot] <= 0 {
            continue;
        }

        reactor_handle_ingress(
            server,
            epfd,
            table,
            leftovers,
            slot,
            free_slots,
            timer_wheel,
            now_ns,
            chunk,
            cork_wire,
            total_served,
            stage,
        );
    }
}

// Computes dynamic epoll wait timeout depending on worker ring state.
inline fn reactor_epoll_timeout(ring: const core::SpscRing&) -> i32 {
    guard ring.is_open else { return 200; }
    return if ring.spsc_count() > 0 { 0 } else { 10 };
}

inline fn reactor_emit_slot_goaway(table: const SoAConnTable&, slot: i64, cork_wire: u8[..65536]&) {
    let fd = table.fds[slot];
    guard fd > 0 && table.is_h2[slot] else { return; }
    let h2_idx = table.h2_slot_map[slot] as i64;
    guard h2_idx >= 0 && h2_idx < REACTOR_MAX_H2_SESSIONS else { return; }
    cork_wire.clear();
    internal::initiate_graceful_shutdown(g_default_reactor.h2_sessions[h2_idx], cork_wire);
    guard cork_wire.len > 0 else { return; }
    if table.has_tls[slot] {
        let _ = tls_transport_send(fd, table.tls_slots[slot], cork_wire[..]);
    } else {
        let _ = tcp_send(fd, cork_wire[..]);
    }
}

fn reactor_step_drain_gate(
    server:            HttpServer&,
    epfd:              i64,
    listener_fd:       i64,
    table:             const SoAConnTable&,
    cork_wire:         u8[..65536]&,
    draining:          bool&,
    drain_deadline_ns: u64&,
) -> bool {
    if !draining && server_should_stop(server) {
        draining = true;
        server.is_running = false;
        if listener_fd > 0 {
            let _ = epoll_del(epfd, listener_fd);
        }
        let limit = min(max(table.count, 0), SOA_TABLE_CAP);
        for s in limit {
            reactor_emit_slot_goaway(table, s, cork_wire);
        }
        drain_deadline_ns = core::add_sat_u64(core::monotonic_now().as_nanos(), server.shutdown_grace_ns);
    }
    guard draining else { return false; }
    return table.count <= 0 || core::monotonic_now().as_nanos() >= drain_deadline_ns;
}

// Cleans up all active connection slots when shutting down reactor loop.
fn reactor_cleanup_all(epfd: i64, table: SoAConnTable&, free_slots: FreeSlotStack&) {
    for s in SOA_TABLE_CAP {
        if table.fds[s] > 0 {
            reactor_cleanup_slot(epfd, table, s, free_slots);
        }
    }
}

inline fn reactor_poll_sweep(
    epfd:           i64,
    table:          SoAConnTable&,
    free_slots:     FreeSlotStack&,
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
            epfd, table, free_slots, timer_wheel, cached_sec, last_sweep_sec, total_served,
        );
    }
}

inline fn reset_reactor_state(state: ReactorState&) {
    reset_soa_table_inplace(state.table);
    internal::reset_connection_pool_inplace(state.conn_pool);
    state.cork.clear();
    state.chunk.len = 0;
    init_free_slots(state.free_slots, SOA_TABLE_CAP);
}

inline fn reactor_prepare_loop(server: HttpServer&, epfd: i64, listener_fd: i64) {
    if listener_fd > 0 {
        tcp_set_nonblocking(listener_fd, true);
        epoll_add(epfd, listener_fd, EPOLL_READ, EPOLL_LISTENER_TAG);
    }
    reset_reactor_state(g_default_reactor);
    server_init_run_state(server);
}

// Executes a share-nothing reactor loop with epoll and a custom `<Stage>` hook.
fn serve_reactor_with_stage<Stage>(
    server:          HttpServer&,
    listener_fd:     i64,
    stage:           Stage&,
    max_connections: i64 = 0,
) -> i64 {
    guard listener_fd > 0 || server.worker_ring.is_open else { return 0; }

    let epfd = epoll_create();
    guard epfd >= 0 else { return 0; }
    defer epoll_close(epfd);

    reactor_prepare_loop(server, epfd, listener_fd);

    var empty_fds:    i64[0]    = [];
    var ready_udata:  u64[4096] = [0; 4096];
    var total_served: i64       = 0;
    var timer_wheel = core::TickTimerWheel { idle_timeout_sec: 15, .. };
    var last_sweep_sec:    i64  = 0;
    var turn_counter:      i64  = 0;
    var cached_now_ns:     u64  = 0;
    var cached_now_sec:    i64  = 0;
    var draining:          bool = false;
    var drain_deadline_ns: u64  = 0;

    while max_connections == 0 || total_served < max_connections {
        if reactor_step_drain_gate(
            server, epfd, listener_fd, g_default_reactor.table, g_default_reactor.cork, draining, drain_deadline_ns,
        ) {
            break;
        }
        if !draining && server.worker_ring.is_open {
            reactor_drain_worker_ring(
                server.worker_ring, epfd, g_default_reactor.table,
                g_default_reactor.free_slots, timer_wheel, total_served,
            );
        }

        let epoll_timeout = reactor_epoll_timeout(server.worker_ring);
        let n = epoll_wait_direct(epfd, empty_fds[..], ready_udata[..], epoll_timeout);

        turn_counter++;
        reactor_poll_sweep(
            epfd, g_default_reactor.table, g_default_reactor.free_slots, timer_wheel, n, turn_counter,
            last_sweep_sec, total_served, cached_now_ns, cached_now_sec,
            server.pipeline.enable_slowloris_timer,
        );

        if n > 0 {
            reactor_dispatch_events(
                server, epfd, listener_fd, g_default_reactor.table, g_default_reactor.leftovers[..],
                g_default_reactor.free_slots, timer_wheel, ready_udata[..n], cached_now_ns,
                g_default_reactor.chunk, g_default_reactor.cork, total_served, stage,
            );
        }
    }

    reactor_cleanup_all(epfd, g_default_reactor.table, g_default_reactor.free_slots);
    return total_served;
}

// Executes a share-nothing reactor loop with epoll.
// Multiplexes all accepted connections within 1 thread, maintaining ~3.1 MB RSS footprint.
fn serve_reactor(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64 {
    var noop = wire::NoOpStage {};
    return serve_reactor_with_stage(server, listener_fd, noop, max_connections);
}

fn reactor_accept_tls_client(
    listener_fd:  i64,
    epfd:         i64,
    table:        SoAConnTable&,
    free_slots:   FreeSlotStack&,
    timer_wheel:  core::TickTimerWheel&,
    tls_config:   const TlsServerHandshakeConfig&,
    total_served: i64&,
) {
    loop {
        let client_fd = tcp_accept_nonblocking(listener_fd);
        if client_fd <= 0 { break; }
        let tls_slot, ok_hs = tls_server_handshake(client_fd, tls_config);
        if !ok_hs {
            tcp_close(client_fd);
            total_served++;
            continue;
        }
        var slot = pop_free_slot(free_slots);
        if slot < 0 {
            slot = reactor_evict_stale_slot(epfd, table, free_slots, timer_wheel, total_served);
        }
        if slot >= 0 {
            reactor_register_client_slot(epfd, table, client_fd, slot, timer_wheel);
            table.has_tls[slot] = true;
            table.tls_slots[slot] = tls_slot;
        } else {
            tls_transport_close(client_fd, tls_slot);
            total_served++;
        }
    }
}

fn reactor_dispatch_tls_events(
    server:       HttpServer&,
    epfd:         i64,
    listener_fd:  i64,
    table:        SoAConnTable&,
    leftovers:    ReactorLeftoverBuf[:],
    free_slots:   FreeSlotStack&,
    timer_wheel:  core::TickTimerWheel&,
    tls_config:   const TlsServerHandshakeConfig&,
    ready_udata:  const u64[:],
    now_ns:       u64,
    chunk:        ReactorIngressBuf&,
    cork_wire:    u8[..65536]&,
    total_served: i64&,
) {
    for i in ready_udata.len {
        let udata = ready_udata[i];
        if udata == EPOLL_LISTENER_TAG {
            reactor_accept_tls_client(
                listener_fd, epfd, table, free_slots,
                timer_wheel, tls_config, total_served,
            );
            continue;
        }
        let slot = udata as i64;
        if slot >= 0 && slot < SOA_TABLE_CAP && table.fds[slot] > 0 {
            var noop = wire::NoOpStage {};
            reactor_handle_ingress(
                server, epfd, table, leftovers, slot, free_slots,
                timer_wheel, now_ns, chunk, cork_wire, total_served, noop,
            );
        }
    }
}

// Executes a non-blocking TLS 1.3 reactor loop with epoll (Section 4.3).
fn serve_reactor_tls(
    server:          HttpServer&,
    listener_fd:     i64,
    tls_config:      const TlsServerHandshakeConfig&,
    max_connections: i64 = 0,
) -> i64 {
    guard listener_fd > 0 else { return 0; }
    let epfd = epoll_create();
    guard epfd >= 0 else { return 0; }
    defer epoll_close(epfd);

    reactor_prepare_loop(server, epfd, listener_fd);

    var empty_fds:    i64[0]    = [];
    var ready_udata:  u64[4096] = [0; 4096];
    var total_served: i64       = 0;
    var timer_wheel = core::TickTimerWheel { idle_timeout_sec: 15, .. };
    var last_sweep_sec:    i64  = 0;
    var turn_counter:      i64  = 0;
    var cached_now_ns:     u64  = 0;
    var cached_now_sec:    i64  = 0;
    var draining:          bool = false;
    var drain_deadline_ns: u64  = 0;

    while max_connections == 0 || total_served < max_connections {
        if reactor_step_drain_gate(
            server, epfd, listener_fd, g_default_reactor.table, g_default_reactor.cork, draining, drain_deadline_ns,
        ) {
            break;
        }
        let n = epoll_wait_direct(epfd, empty_fds[..], ready_udata[..], 10);
        turn_counter++;
        reactor_poll_sweep(
            epfd, g_default_reactor.table, g_default_reactor.free_slots, timer_wheel, n, turn_counter,
            last_sweep_sec, total_served, cached_now_ns, cached_now_sec,
            server.pipeline.enable_slowloris_timer,
        );
        if n > 0 {
            reactor_dispatch_tls_events(
                server, epfd, listener_fd, g_default_reactor.table, g_default_reactor.leftovers[..],
                g_default_reactor.free_slots, timer_wheel, tls_config, ready_udata[..n as i64],
                cached_now_ns, g_default_reactor.chunk, g_default_reactor.cork, total_served,
            );
        }
    }
    reactor_cleanup_all(epfd, g_default_reactor.table, g_default_reactor.free_slots);
    return total_served;
}

// Processes an incoming HTTP/3 request stream payload through `H3Connection` and `server.pipeline` (RFC 9114).
fn handle_h3_server_datagram<B>(
    server:    HttpServer&,
    h3_conn:   internal::H3Connection&,
    stream_id: u64,
    client_ip: const u8[:],
    rx_wire:   const u8[:],
    now_ns:    u64,
    tx_wire:   B&,
) -> bool {
    tx_wire.clear();
    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }
    let h_err = internal::handle_stream_data(h3_conn, stream_id, true, rx_wire, true);
    guard h_err == rfc::H3_ERR_NO_ERROR else { return false; }

    let s_idx, found = internal::find_h3_stream_idx(h3_conn, stream_id);
    guard found && s_idx >= 0 && s_idx < h3_conn.streams.len else { return false; }
    guard h3_conn.streams[s_idx].headers_received else { return false; }

    let method = if h3_conn.streams[s_idx].req_method.len > 0 { h3_conn.streams[s_idx].req_method[..] } else { "GET" };
    let path = if h3_conn.streams[s_idx].req_path.len > 0 { h3_conn.streams[s_idx].req_path[..] } else { "/" };
    var req = new_request(method, path);
    if h3_conn.streams[s_idx].req_authority.len > 0 {
        let _ = append_header(req.headers, "host", h3_conn.streams[s_idx].req_authority[..]);
        req.presence_mask |= HDR_PRESENCE_HOST;
    }
    let _ = internal::copy_stream_headers(h3_conn, stream_id, req.headers);
    for &e in req.headers.entries {
        let known_id = identify_known_header(entry_name(req.headers, e));
        req.presence_mask |= header_id_to_bit(known_id);
    }
    let _ = internal::copy_stream_trailers(h3_conn, stream_id, req.trailers);
    if h3_conn.streams[s_idx].received_body.len > 0 {
        req.body.append(h3_conn.streams[s_idx].received_body[..]);
    }

    var res = Response { .. };
    var future = internal::new_inline_handler_future(0);
    execute_pipeline(server.pipeline, server.timer, client_ip, req, now_ns, res, future);
    server.requests_processed++;

    var extra_map = HeaderMap { .. };
    for &e in res.headers.entries {
        let hdr_name = entry_name(res.headers, e);
        let hdr_val = entry_value(res.headers, e);
        var lname: u8[..256] = [];
        guard hdr_name.len <= lname.cap else { continue; }
        hdr_name.to_lower_ascii(lname);
        let _ = extra_map.append_header(lname[..], hdr_val);
    }
    return internal::send_response_headers_body_and_trailers(
        h3_conn, stream_id, res.status_code, extra_map, res.body[..], res.trailers, tx_wire,
    );
}

inline fn dispatch_h3_udp_datagram(
    server:    HttpServer&,
    udp_fd:    i64,
    h3_conn:   internal::H3Connection&,
    served:    i64,
    peer_ip4:  u32,
    peer_port: u16,
    rx_slice:  const u8[:],
    now_ns:    u64,
    tx_wire:   u8[..1472]&,
) {
    let stream_id = ((served & 15) * 4) as u64;
    for st_i in h3_conn.streams.len {
        if h3_conn.streams[st_i].stream_id == stream_id {
            h3_conn.streams[st_i] = internal::H3StreamEntry { stream_id: stream_id, .. };
        }
    }
    var peer_ip_str: u8[..32] = [];
    format(peer_ip_str, ((peer_ip4 >> 24) & 0xFF) as i64);
    peer_ip_str.push('.');
    format(peer_ip_str, ((peer_ip4 >> 16) & 0xFF) as i64);
    peer_ip_str.push('.');
    format(peer_ip_str, ((peer_ip4 >> 8) & 0xFF) as i64);
    peer_ip_str.push('.');
    format(peer_ip_str, (peer_ip4 & 0xFF) as i64);
    let _ = internal::with_connection_slot(g_default_reactor.conn_pool, udp_fd, now_ns as i64) { conn_slot =>
        internal::notify_request_start(conn_slot.timer);
        if server.handle_h3_server_datagram(h3_conn, stream_id, peer_ip_str[..], rx_slice, now_ns, tx_wire) {
            let udp_tr = Transport.Udp { fd: udp_fd, peer_ip4: peer_ip4, peer_port: peer_port };
            let _ = udp_tr.send(tx_wire[..]);
        }
        internal::notify_request_end(conn_slot.timer);
    };
}

// Executes an Unencrypted H3 over UDP (Datagram Direct) server loop (RFC 9114 framing + QPACK).
// Demultiplexes direct HTTP/3 `HEADERS`/`DATA`/`SETTINGS` frames carried in raw UDP datagrams
// for zero-handshake internal/loopback hops; for encrypted RFC 9000 + RFC 9001 TLS 1.3 QUIC v1
// packets, use `QuicConnection` (`quic/connection.goose`) + `H3Connection` (`http3/connection.goose`).
fn serve_h3(server: HttpServer&, udp_fd: i64, max_datagrams: i64 = 1) -> i64 {
    guard udp_fd > 0 else { return 0; }
    let h3_settings = H3Settings { .. };
    var h3_conn = internal::new_h3_server_connection(h3_settings);
    var rx_buf:  u8[1472]   = [0; 1472];
    var tx_wire: u8[..1472] = [];
    var served:  i64        = 0;

    while max_datagrams == 0 || served < max_datagrams {
        var peer_ip4:  u32 = 0;
        var peer_port: u16 = 0;
        let recvd = native_udp_recvfrom(udp_fd, rx_buf[..], 250, peer_ip4, peer_port);
        if recvd <= 0 {
            if max_datagrams > 0 { break; }
            continue;
        }
        let now_ns = core::monotonic_now().as_nanos();
        dispatch_h3_udp_datagram(
            server, udp_fd, h3_conn, served, peer_ip4, peer_port, rx_buf[..recvd], now_ns, tx_wire,
        );
        served++;
    }
    return served;
}

// Public HTTP/3 and QUIC server endpoint state (RFC 9000, RFC 9114, RFC 9204).
// Encapsulates HTTP/3 connection state, QPACK tables, and QUIC handshake framing.
struct H3ServerEndpoint {
    conn: internal::H3Connection = internal::H3Connection { .. },
}

fn new_h3_server_endpoint(settings: H3Settings = H3Settings { .. }) -> H3ServerEndpoint {
    var ep = H3ServerEndpoint {
        conn: internal::new_h3_server_connection(settings),
    };
    ep.conn.qpack_table.capacity_bytes = 0;
    return ep;
}

fn encode_h3_connection_close<B>(err_code: u64, out_wire: B&) {
    out_wire.clear();
    internal::quic_encode_varint(out_wire, 0x1D);
    internal::quic_encode_varint(out_wire, err_code);
    internal::quic_encode_varint(out_wire, 0);
}

inline fn is_h3_wire_frame_bounded(datagram: const u8[:], hdr: const internal::H3FrameHeader&) -> bool {
    return ((hdr.header_len + hdr.payload_len) as i64) <= datagram.len;
}

fn handle_h3_endpoint_settings<B>(
    ep:       H3ServerEndpoint&,
    hdr:      const internal::H3FrameHeader&,
    payload:  const u8[:],
    out_wire: B&,
) -> bool {
    let err = internal::handle_peer_control_frame(ep.conn, hdr, payload);
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
    server:    HttpServer&,
    ep:        H3ServerEndpoint&,
    client_ip: const u8[:],
    datagram:  const u8[:],
    now_ns:    u64,
    out_wire:  B&,
) -> bool {
    for st_i in ep.conn.streams.len {
        if ep.conn.streams[st_i].stream_id == 0 {
            ep.conn.streams[st_i] = internal::H3StreamEntry { stream_id: 0, .. };
        }
    }
    ep.conn.state = internal::H3ConnState.Active;
    ep.conn.error_code = rfc::H3_ERR_NO_ERROR;

    let ok = handle_h3_server_datagram(server, ep.conn, 0, client_ip, datagram, now_ns, out_wire);
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
    server:    HttpServer&,
    ep:        H3ServerEndpoint&,
    client_ip: const u8[:],
    datagram:  const u8[:],
    now_ns:    u64,
    out_wire:  B&,
) -> bool {
    let hdr, ok_hdr = internal::parse_h3_frame_header(datagram, 0);
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

fn encode_quic_version_negotiation<B>(hdr: const internal::QuicHeader&, out_wire: B&) {
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
    ep:       const H3ServerEndpoint&,
    hdr:      const internal::QuicHeader&,
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
    internal::quic_encode_varint(h3_ctrl, rfc::H3_STREAM_CONTROL);
    internal::encode_h3_settings_frame(h3_ctrl, ep.conn.local_settings);
    internal::encode_h3_frame_header(h3_ctrl, 0x21, 0);

    let payload_len = (2 + h3_ctrl.len) as u64;
    internal::quic_encode_varint(out_wire, payload_len);
    out_wire.append_u16_be(1);
    out_wire.append(h3_ctrl[..]);
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
    out_wire.clear();
    guard datagram.len > 0 else { return false; }

    if (datagram[0] & 0xC0) == 0 {
        if handle_h3_endpoint_frame(server, ep, client_ip, datagram, now_ns, out_wire) {
            return out_wire.len > 0;
        }
    }

    let quic_hdr, ok_qhdr = internal::parse_quic_header(datagram);
    guard ok_qhdr else { return false; }

    if quic_hdr.version != rfc::QUIC_VERSION_1 && quic_hdr.version != rfc::QUIC_VERSION_NEGOTIATION {
        encode_quic_version_negotiation(quic_hdr, out_wire);
        return out_wire.len > 0;
    }

    if quic_hdr.header_type == internal::QuicHeaderType.Initial {
        // RFC 9000 Section 14.1: Initial Datagram Size - server MUST discard client Initial < 1200 bytes
        guard datagram.len >= (rfc::QUIC_MIN_INITIAL_DATAGRAM_LEN as i64) else {
            return false;
        }
        encode_quic_server_initial(ep, quic_hdr, out_wire);
        return out_wire.len > 0;
    }

    return false;
}
