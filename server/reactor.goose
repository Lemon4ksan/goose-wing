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

const REACTOR_LEFTOVER_CAP: i64 = 8192;

struct ReactorLeftoverBuf {
    bytes: u8[8192] = [0; 8192],
}

struct ReactorIngressBuf {
    bytes: u8[65536] = [0; 65536],
    len:   i64       = 0,
}

var g_reactor_h2_sessions: internal::H2ServerSession[8] = [internal::H2ServerSession { .. }; 8];
var g_reactor_h2_in_use:   bool[8]                      = [false; 8];
var g_reactor_leftovers:   ReactorLeftoverBuf[1024]     = [ReactorLeftoverBuf { .. }; 1024];
var g_reactor_table:       SoAConnTable                 = SoAConnTable { .. };
var g_reactor_chunk:       ReactorIngressBuf            = ReactorIngressBuf { .. };
var g_reactor_cork:        u8[..65536]                  = [];
var g_reactor_free_slots:  FreeSlotStack                = FreeSlotStack { .. };

fn alloc_reactor_h2_session(
    pipeline:    ServerPipelineConfig&,
    server_name: const u8[:],
    now_ms:      u64,
) -> i16 {
    for i in 8 {
        if !g_reactor_h2_in_use[i] {
            g_reactor_h2_in_use[i] = true;
            internal::reset_h2_server_session_inplace(g_reactor_h2_sessions[i], server_name, now_ms);
            return i as i16;
        }
    }
    internal::cleanup_h2_server_session(g_reactor_h2_sessions[0], pipeline);
    g_reactor_h2_in_use[0] = true;
    internal::reset_h2_server_session_inplace(g_reactor_h2_sessions[0], server_name, now_ms);
    return 0;
}

fn free_reactor_h2_session(h2_idx: i16, pipeline: ServerPipelineConfig&) {
    let idx = h2_idx as i64;
    guard idx >= 0 && idx < 8 && g_reactor_h2_in_use[idx] else { return; }
    internal::cleanup_h2_server_session(g_reactor_h2_sessions[idx], pipeline);
    g_reactor_h2_in_use[idx] = false;
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
    if !table.is_h2[slot] || h2_idx < 0 || h2_idx >= 8 {
        h2_idx = alloc_reactor_h2_session(pipeline, server_name, now_ms);
        table.h2_slot_map[slot] = h2_idx;
        table.is_h2[slot] = true;
    }
    return clamp(h2_idx as i64, 0, 7);
}

// Encapsulated UFCS method on SoAConnTable: detaches and cleans up any H2ServerSession bound to `slot`.
fn release_h2_session(table: SoAConnTable&, slot: i64, pipeline: ServerPipelineConfig&) {
    guard slot >= 0 && slot < 1024 else { return; }
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
            if h2_i >= 0 && h2_i < 8 {
                g_reactor_h2_in_use[h2_i] = false;
            }
        }
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
    timer_wheel:    TickTimerWheel&,
    now_sec:        i64,
    last_sweep_sec: i64&,
    total_served:   i64&,
) {
    guard now_sec > last_sweep_sec else { return; }
    let elapsed = if last_sweep_sec == 0 { 1 } else { (now_sec - last_sweep_sec) as u32 };
    last_sweep_sec = now_sec;
    tick_timer_advance(timer_wheel, elapsed);

    var expired: i64[1024] = [0; 1024];
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
    timer_wheel:  TickTimerWheel&,
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
    timer_wheel: TickTimerWheel&,
) {
    table.fds[slot] = client_fd;
    table.timeout_ticks[slot] = tick_timer_arm(timer_wheel, 15);
    table.leftover_lens[slot] = 0;
    table.is_h2[slot] = false;
    table.h2_slot_map[slot] = -1;
    table.has_tls[slot] = false;
    table.tls_slots[slot] = 0xFFFF;
    table.count = advance_high_water_mark(table.count, slot);
    epoll_add(epfd, client_fd, EPOLL_READ, slot as u64);
}

// Drains non-blocking listener queue and accepts ready incoming connections into free slots.
fn reactor_drain_listener(
    listener_fd:  i64,
    epfd:         i64,
    table:        SoAConnTable&,
    free_slots:   FreeSlotStack&,
    timer_wheel:  TickTimerWheel&,
    total_served: i64&,
) {
    while true {
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
    timer_wheel:  TickTimerWheel&,
    total_served: i64&,
) {
    guard ring.is_open && ring.handle != 0 else { return; }
    while true {
        var client_val: u64 = 0;
        let popped = core::spsc_pop(ring, client_val);
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
            return false, true;
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

fn reactor_handle_h2_ingress(
    server:    HttpServer&,
    conn:      i64,
    table:     SoAConnTable&,
    leftovers: ReactorLeftoverBuf[:],
    slot:      i64,
    now_ns:    u64,
    chunk:     ReactorIngressBuf&,
    cork_wire: u8[..65536]&,
) -> bool {
    let now_ms = now_ns / 1000000;
    cork_wire.clear();
    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }
    let h2_idx = table.ensure_h2_session(slot, server.pipeline, server.server_name[..], now_ms);
    var peer_ip: u8[..64] = [];
    tcp_get_peer_ip(conn, peer_ip);
    let consumed_h2, ok_h2 = internal::handle_h2_server_ingress(
        g_reactor_h2_sessions[h2_idx], server.pipeline, server.timer,
        peer_ip[..], chunk.bytes[..chunk.len], now_ms, cork_wire,
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
        if recvd <= 0 {
            return false, true;
        }
        chunk.len += recvd;
        return true, false;
    }
    return reactor_read_bounded_turns(conn, chunk);
}

// Processes non-blocking ingress traffic on a connection slot via bounded capacity-guarded read loop.
fn reactor_handle_ingress(
    server:       HttpServer&,
    epfd:         i64,
    table:        SoAConnTable&,
    leftovers:    ReactorLeftoverBuf[:],
    slot:         i64,
    free_slots:   FreeSlotStack&,
    timer_wheel:  TickTimerWheel&,
    now_ns:       u64,
    chunk:        ReactorIngressBuf&,
    cork_wire:    u8[..65536]&,
    total_served: i64&,
) {
    let conn = table.fds[slot];
    let prev_len = table.leftover_lens[slot] as i64;
    table.soa_table_touch(slot, tick_timer_arm(timer_wheel, 15));

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
        let ok_h2 = reactor_handle_h2_ingress(server, conn, table, leftovers, slot, now_ns, chunk, cork_wire);
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

    var peer_ip: u8[..64] = [];
    tcp_get_peer_ip(conn, peer_ip);
    cork_wire.clear();
    let count, consumed, ok, wants_close = handle_connection_wire_pipelined_stream(
        server, peer_ip[..], chunk.bytes[..chunk.len], now_ns, cork_wire,
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

// Dispatches ready epoll events for reactor connection slots.
fn reactor_dispatch_events(
    server:       HttpServer&,
    epfd:         i64,
    listener_fd:  i64,
    table:        SoAConnTable&,
    leftovers:    ReactorLeftoverBuf[:],
    free_slots:   FreeSlotStack&,
    timer_wheel:  TickTimerWheel&,
    ready_udata:  const u64[:],
    now_ns:       u64,
    chunk:        ReactorIngressBuf&,
    cork_wire:    u8[..65536]&,
    total_served: i64&,
) {
    for i in ready_udata.len {
        let udata = ready_udata[i];
        if udata == EPOLL_LISTENER_TAG {
            reactor_drain_listener(listener_fd, epfd, table, free_slots, timer_wheel, total_served);
            continue;
        }

        let slot = udata as i64;
        if slot < 0 || slot >= 1024 || table.fds[slot] <= 0 {
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
        );
    }
}

// Computes dynamic epoll wait timeout depending on worker ring state.
inline fn reactor_epoll_timeout(ring: const core::SpscRing&) -> i32 {
    guard ring.is_open else { return 1000; }
    return if core::spsc_count(ring) > 0 { 0 } else { 10 };
}

// Cleans up all active connection slots when shutting down reactor loop.
fn reactor_cleanup_all(epfd: i64, table: SoAConnTable&, free_slots: FreeSlotStack&) {
    for s in 1024 {
        if table.fds[s] > 0 {
            reactor_cleanup_slot(epfd, table, s, free_slots);
        }
    }
}

inline fn reactor_poll_sweep(
    epfd:           i64,
    table:          SoAConnTable&,
    free_slots:     FreeSlotStack&,
    timer_wheel:    TickTimerWheel&,
    n:              i32,
    turn:           i64,
    last_sweep_sec: i64&,
    total_served:   i64&,
    cached_ns:      u64&,
    cached_sec:     i64&,
) {
    if n > 0 && (turn & 511) != 0 && cached_sec > 0 { return; }
    let now_mono = core::monotonic_now();
    cached_ns = core::as_nanos(now_mono);
    cached_sec = (cached_ns / 1000000000) as i64;
    reactor_sweep_timeouts(
        epfd, table, free_slots, timer_wheel, cached_sec, last_sweep_sec, total_served,
    );
}

// Executes a share-nothing reactor loop with epoll.
// Multiplexes all accepted connections within 1 thread, maintaining ~3.1 MB RSS footprint.
fn serve_reactor(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64 {
    guard listener_fd > 0 || server.worker_ring.is_open else { return 0; }

    let epfd = epoll_create();
    guard epfd >= 0 else { return 0; }
    defer epoll_close(epfd);

    if listener_fd > 0 {
        tcp_set_nonblocking(listener_fd, true);
        epoll_add(epfd, listener_fd, EPOLL_READ, EPOLL_LISTENER_TAG);
    }

    var ready_fds:    i64[1024] = [0; 1024];
    var ready_udata:  u64[1024] = [0; 1024];
    var total_served: i64       = 0;

    g_reactor_table = SoAConnTable { .. };
    g_reactor_cork.clear();
    g_reactor_chunk.len = 0;
    init_free_slots(g_reactor_free_slots, 1024);
    var timer_wheel = new_tick_timer_wheel(15);
    var last_sweep_sec: i64 = 0;
    var turn_counter:   i64 = 0;
    var cached_now_ns:  u64 = 0;
    var cached_now_sec: i64 = 0;

    while max_connections == 0 || total_served < max_connections {
        if server.worker_ring.is_open {
            reactor_drain_worker_ring(
                server.worker_ring, epfd, g_reactor_table, g_reactor_free_slots, timer_wheel, total_served,
            );
        }

        let epoll_timeout = reactor_epoll_timeout(server.worker_ring);
        let n = epoll_wait_direct(epfd, ready_fds[..], ready_udata[..], epoll_timeout);

        turn_counter++;
        reactor_poll_sweep(
            epfd, g_reactor_table, g_reactor_free_slots, timer_wheel, n, turn_counter,
            last_sweep_sec, total_served, cached_now_ns, cached_now_sec,
        );

        if n > 0 {
            reactor_dispatch_events(
                server, epfd, listener_fd, g_reactor_table, g_reactor_leftovers[..], g_reactor_free_slots,
                timer_wheel, ready_udata[..n], cached_now_ns, g_reactor_chunk, g_reactor_cork, total_served,
            );
        }
    }

    reactor_cleanup_all(epfd, g_reactor_table, g_reactor_free_slots);
    return total_served;
}

fn reactor_accept_tls_client(
    listener_fd:  i64,
    epfd:         i64,
    table:        SoAConnTable&,
    free_slots:   FreeSlotStack&,
    timer_wheel:  TickTimerWheel&,
    tls_config:   const TlsServerHandshakeConfig&,
    total_served: i64&,
) {
    while true {
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
    timer_wheel:  TickTimerWheel&,
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
        if slot >= 0 && slot < 1024 && table.fds[slot] > 0 {
            reactor_handle_ingress(
                server, epfd, table, leftovers, slot, free_slots,
                timer_wheel, now_ns, chunk, cork_wire, total_served,
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

    tcp_set_nonblocking(listener_fd, true);
    epoll_add(epfd, listener_fd, EPOLL_READ, EPOLL_LISTENER_TAG);

    var ready_fds:    i64[1024] = [0; 1024];
    var ready_udata:  u64[1024] = [0; 1024];
    var total_served: i64       = 0;
    g_reactor_table = SoAConnTable { .. };
    g_reactor_cork.clear();
    g_reactor_chunk.len = 0;
    init_free_slots(g_reactor_free_slots, 1024);
    var timer_wheel = new_tick_timer_wheel(15);
    var last_sweep_sec: i64 = 0;
    var turn_counter:   i64 = 0;
    var cached_now_ns:  u64 = 0;
    var cached_now_sec: i64 = 0;

    while max_connections == 0 || total_served < max_connections {
        let n = epoll_wait_direct(epfd, ready_fds[..], ready_udata[..], 10);
        turn_counter++;
        reactor_poll_sweep(
            epfd, g_reactor_table, g_reactor_free_slots, timer_wheel, n, turn_counter,
            last_sweep_sec, total_served, cached_now_ns, cached_now_sec,
        );
        if n > 0 {
            reactor_dispatch_tls_events(
                server, epfd, listener_fd, g_reactor_table, g_reactor_leftovers[..],
                g_reactor_free_slots, timer_wheel, tls_config, ready_udata[..n as i64],
                cached_now_ns, g_reactor_chunk, g_reactor_cork, total_served,
            );
        }
    }
    reactor_cleanup_all(epfd, g_reactor_table, g_reactor_free_slots);
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

    let method = if h3_conn.streams[s_idx].req_method.len > 0 {
        h3_conn.streams[s_idx].req_method[..]
    } else {
        "GET"
    };
    let path = if h3_conn.streams[s_idx].req_path.len > 0 {
        h3_conn.streams[s_idx].req_path[..]
    } else {
        "/"
    };
    var req = new_request(method, path);
    if h3_conn.streams[s_idx].req_authority.len > 0 {
        req.headers.push(make_header("host", h3_conn.streams[s_idx].req_authority[..]));
        add_header(req.bloom_filter, "host");
        req.presence_mask |= HDR_PRESENCE_HOST;
    }
    if h3_conn.streams[s_idx].received_body.len > 0 {
        req.body.append(h3_conn.streams[s_idx].received_body[..]);
    }

    var res = Response { .. };
    var future = internal::new_inline_handler_future(0);
    execute_pipeline(server.pipeline, server.timer, client_ip, req, now_ns, res, future);
    server.requests_processed++;

    var extra_map = HeaderMap { .. };
    for &hdr in res.headers {
        var lname: u8[..128] = [];
        for b in hdr.name {
            let c = if b >= 'A' && b <= 'Z' { b + 32 } else { b };
            lname.push(c);
        }
        let _ = extra_map.append_header(lname[..], hdr.value[..]);
    }
    return internal::send_response_headers_and_body(
        h3_conn, stream_id, res.status_code, extra_map, res.body[..], tx_wire,
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
    if server.handle_h3_server_datagram(h3_conn, stream_id, peer_ip_str[..], rx_slice, now_ns, tx_wire) {
        let udp_tr = Transport.Udp { fd: udp_fd, peer_ip4: peer_ip4, peer_port: peer_port };
        let _ = udp_tr.send(tx_wire[..]);
    }
}

// Executes a UDP HTTP/3 datagram server loop (Section 4.3).
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
        let now_ns = core::as_nanos(core::monotonic_now());
        dispatch_h3_udp_datagram(
            server, udp_fd, h3_conn, served, peer_ip4, peer_port, rx_buf[..recvd], now_ns, tx_wire,
        );
        served++;
    }
    return served;
}
