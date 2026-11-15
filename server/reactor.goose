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
import net.accel;

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
    h2_sessions: server_internal::H2ServerSession[..128] = [],
    h2_in_use:   bool[128]                               = [false; 128],
    leftovers:   ReactorLeftoverBuf[..4096]              = [],
    table:       SoAConnTable                            = SoAConnTable { .. },
    chunk:       ReactorIngressBuf                       = ReactorIngressBuf { .. },
    cork:        u8[..65536]                             = [],
    free_slots:  FreeSlotStack                           = FreeSlotStack { .. },
    conn_pool:   server_internal::ReactorConnectionPool  = server_internal::ReactorConnectionPool { .. },
    accel:       ReactorAccelRuntime                     = ReactorAccelRuntime { .. },
}

var g_default_reactor: ReactorState = ReactorState { .. };

fn ensure_reactor_h2_capacity(state: ReactorState&) {
    if state.h2_sessions.len < REACTOR_MAX_H2_SESSIONS {
        state.h2_sessions.resize(REACTOR_MAX_H2_SESSIONS, server_internal::H2ServerSession { .. });
    }
}

fn ensure_reactor_leftovers_capacity(state: ReactorState&) {
    if state.leftovers.len < SOA_TABLE_CAP {
        state.leftovers.resize(SOA_TABLE_CAP, ReactorLeftoverBuf { .. });
    }
}

// Opens a listening TCP socket configured for OS completion accelerators when supported.
fn reactor_listen_accelerated(server: const HttpServer&, backlog: i32 = 128) -> i64 {
    return listen_accelerated_tcp(server.host[..], server.port, server.accel_mode, backlog);
}

fn alloc_reactor_h2_session(
    pipeline:    ServerPipelineConfig&,
    server_name: const u8[:],
    now_ms:      u64,
) -> i16 {
    ensure_reactor_h2_capacity(g_default_reactor);
    for i in REACTOR_MAX_H2_SESSIONS {
        if !g_default_reactor.h2_in_use[i] {
            server_internal::cleanup_h2_server_session(g_default_reactor.h2_sessions[i], pipeline);
            g_default_reactor.h2_in_use[i] = true;
            server_internal::reset_h2_server_session_inplace(g_default_reactor.h2_sessions[i], server_name, now_ms);
            return i as i16;
        }
    }
    return -1;
}

fn free_reactor_h2_session(h2_idx: i16, pipeline: ServerPipelineConfig&) {
    let idx = h2_idx as i64;
    guard idx >= 0 && idx < REACTOR_MAX_H2_SESSIONS && g_default_reactor.h2_in_use[idx] else { return; }
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

// Cleans up a connection slot, detaches driver state, closes transport, and returns slot to free stack.
fn reactor_cleanup_slot(
    epfd:       i64,
    table:      SoAConnTable&,
    slot_idx:   i64,
    free_slots: FreeSlotStack&,
) {
    let fd = table.fds[slot_idx];
    if fd > 0 {
        if g_default_reactor.accel.kq_fd >= 0 {
            reactor_queue_kq_change(g_default_reactor.accel, fd, net_internal::EV_DELETE, slot_idx as u64);
        }
        if epfd >= 0 {
            epoll_del(epfd, fd);
        }
        reactor_reset_accel_slot(g_default_reactor.accel, slot_idx);
        var tr = table.slot_transport(slot_idx);
        tr.close();
        if table.h2_slot_map[slot_idx] >= 0 {
            let h2_i = table.h2_slot_map[slot_idx] as i64;
            if h2_i >= 0 && h2_i < REACTOR_MAX_H2_SESSIONS {
                g_default_reactor.h2_in_use[h2_i] = false;
            }
        }
        server_internal::free_connection_slot(g_default_reactor.conn_pool, slot_idx as i32);
        table.soa_table_free(slot_idx);
    } else {
        reactor_reset_accel_slot(g_default_reactor.accel, slot_idx);
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
        total_served = core::add_sat_i64(total_served, 1);
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
        total_served = core::add_sat_i64(total_served, 1);
        return pop_free_slot(free_slots);
    }
    return -1;
}

inline fn reactor_init_slot_record(
    table:       SoAConnTable&,
    client_fd:   i64,
    slot:        i64,
    timer_wheel: core::TickTimerWheel&,
) {
    reactor_reset_accel_slot(g_default_reactor.accel, slot);
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
    let _ = server_internal::alloc_connection_slot(g_default_reactor.conn_pool, client_fd, 0);
}

// Registers an accepted non-blocking client connection into an allocated slot.
inline fn reactor_register_client_slot(
    epfd:        i64,
    table:       SoAConnTable&,
    client_fd:   i64,
    slot:        i64,
    timer_wheel: core::TickTimerWheel&,
) {
    let _ = epfd;
    reactor_init_slot_record(table, client_fd, slot, timer_wheel);
    reactor_bind_slot_backend(g_default_reactor.accel, slot, client_fd);
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

fn reactor_accept_plain_fd(
    client_fd:    i64,
    epfd:         i64,
    table:        SoAConnTable&,
    free_slots:   FreeSlotStack&,
    timer_wheel:  core::TickTimerWheel&,
    total_served: i64&,
) {
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
        reactor_accept_plain_fd(client_fd, epfd, table, free_slots, timer_wheel, total_served);
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

fn reactor_send_slot_wire(table: const SoAConnTable&, slot: i64, conn: i64, wire: const u8[:]) -> bool {
    let in_accel_range = slot >= 0 && slot < REACTOR_ACCEL_SLOTS;
    if in_accel_range && g_default_reactor.accel.slot_ktls_rx[slot] {
        return net_internal::smartnic_send_record(conn, wire, rfc::TLS_CONTENT_APPLICATION_DATA) > 0;
    }
    if in_accel_range && g_default_reactor.accel.slot_accel[slot] {
        if table.has_tls[slot] && table.tls_slots[slot] != 0xFFFF {
            g_default_reactor.accel.tls_seal_scratch.clear();
            if !tls_cipher_slot_seal_app_data(
                table.tls_slots[slot], wire, g_default_reactor.accel.tls_seal_scratch,
            ) {
                return false;
            }
            return reactor_submit_accel_tx(
                g_default_reactor.accel, slot, conn, g_default_reactor.accel.tls_seal_scratch[..],
            );
        }
        return reactor_submit_accel_tx(g_default_reactor.accel, slot, conn, wire);
    }
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
    let consumed_h2, ok_h2 = server_internal::handle_h2_server_ingress(
        g_default_reactor.h2_sessions[h2_idx], server.pipeline, server.timer,
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
    total_served = core::add_sat_i64(total_served, 1);
}

inline fn reactor_request_slot_close(
    server:       HttpServer&,
    epfd:         i64,
    table:        SoAConnTable&,
    slot:         i64,
    free_slots:   FreeSlotStack&,
    total_served: i64&,
) {
    if slot >= 0 && slot < REACTOR_ACCEL_SLOTS && g_default_reactor.accel.slot_tx_inflight[slot] {
        g_default_reactor.accel.slot_close_after_tx[slot] = true;
        return;
    }
    reactor_close_and_inc(server, epfd, table, slot, free_slots, total_served);
}

// Classifies a single kTLS `smartnic_recv_record` outcome into `(app_bytes, any_recvd, should_close)`.
fn classify_ktls_recv_turn(
    recvd:        i32,
    rtype:        u8,
    rec_bytes:    const u8[:],
    buffered_len: i64,
) -> i64, bool, bool {
    if recvd == -2 {
        return 0, buffered_len > 0, false;
    }
    if recvd <= 0 || rtype == rfc::TLS_CONTENT_ALERT {
        return 0, buffered_len > 0, buffered_len == 0;
    }
    if rtype == rfc::TLS_CONTENT_APPLICATION_DATA {
        return recvd, true, false;
    }
    if rtype == rfc::TLS_CONTENT_HANDSHAKE {
        let hs_len = min(recvd as i64, rec_bytes.len);
        let ctl = inspect_unsealed_handshake_control(rec_bytes[..hs_len]);
        return 0, buffered_len > 0, ctl != TlsSliceUnsealStatus.ControlHandled;
    }
    return 0, buffered_len > 0, false;
}

fn reactor_read_ktls_slot(conn: i64, chunk: ReactorIngressBuf&) -> bool, bool {
    guard chunk.len < 65536 else { return false, false; }
    let start = chunk.len;
    let recvd, rtype = net_internal::smartnic_recv_record(conn, chunk.bytes[start..]);
    let added, any_recvd, should_close = classify_ktls_recv_turn(
        recvd, rtype, chunk.bytes[start..], start,
    );
    if added > 0 {
        chunk.len = core::add_sat_i64(start, added);
    }
    return any_recvd, should_close;
}

fn reactor_read_slot_turns(table: const SoAConnTable&, slot: i64, conn: i64, chunk: ReactorIngressBuf&) -> bool, bool {
    if slot >= 0 && slot < REACTOR_ACCEL_SLOTS && g_default_reactor.accel.slot_ktls_rx[slot] {
        return reactor_read_ktls_slot(conn, chunk);
    }
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

fn reactor_select_slot_peer_ip(
    server: const HttpServer&,
    table:  SoAConnTable&,
    slot:   i64,
    conn:   i64,
) -> const u8[:] {
    if server.pipeline.enable_rate_limiter || server.trust_proxy_headers || server.pipeline.trust_proxy_headers {
        return reactor_resolve_slot_peer_ip(table, slot, conn);
    }
    return "127.0.0.1";
}

fn reactor_process_slot_plaintext<Stage>(
    server:       HttpServer&,
    epfd:         i64,
    table:        SoAConnTable&,
    leftovers:    ReactorLeftoverBuf[:],
    slot:         i64,
    conn:         i64,
    free_slots:   FreeSlotStack&,
    now_ns:       u64,
    chunk:        ReactorIngressBuf&,
    cork_wire:    u8[..65536]&,
    total_served: i64&,
    stage:        Stage&,
) {
    if table.is_h2[slot] || is_h2_client_preface(chunk.bytes[..chunk.len]) {
        if !reactor_handle_h2_ingress(server, conn, table, leftovers, slot, now_ns, chunk, cork_wire, stage) {
            reactor_request_slot_close(server, epfd, table, slot, free_slots, total_served);
        }
        return;
    }
    if is_partial_h2_client_preface(chunk.bytes[..chunk.len]) {
        if !reactor_save_leftover(table, leftovers[slot], slot, chunk.bytes[..chunk.len]) {
            reactor_request_slot_close(server, epfd, table, slot, free_slots, total_served);
        }
        return;
    }

    let client_ip_slice = reactor_select_slot_peer_ip(server, table, slot, conn);
    cork_wire.clear();
    let _, consumed, ok, wants_close = handle_connection_wire_pipelined_stream(
        server, client_ip_slice, chunk.bytes[..chunk.len], now_ns, cork_wire, stage,
    );
    if cork_wire.len > 0 && !reactor_send_slot_wire(table, slot, conn, cork_wire[..]) {
        reactor_close_and_inc(server, epfd, table, slot, free_slots, total_served);
        return;
    }
    if !ok || wants_close {
        reactor_request_slot_close(server, epfd, table, slot, free_slots, total_served);
        return;
    }
    if consumed < chunk.len && !reactor_save_leftover(table, leftovers[slot], slot, chunk.bytes[consumed..chunk.len]) {
        reactor_request_slot_close(server, epfd, table, slot, free_slots, total_served);
    }
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
    reactor_process_slot_plaintext(
        server, epfd, table, leftovers, slot, conn, free_slots, now_ns, chunk, cork_wire, total_served, stage,
    );
}

fn reactor_append_chunk_bytes(chunk: ReactorIngressBuf&, src: const u8[:]) -> bool {
    let end_len = core::add_sat_i64(chunk.len, src.len);
    guard end_len <= 65536 else { return false; }
    for i in src.len {
        chunk.bytes[core::add_sat_i64(chunk.len, i)] = src[i];
    }
    chunk.len = end_len;
    return true;
}

fn reactor_handle_completed_rx<Stage>(
    server:       HttpServer&,
    epfd:         i64,
    table:        SoAConnTable&,
    leftovers:    ReactorLeftoverBuf[:],
    slot:         i64,
    rx_raw:       const u8[:],
    free_slots:   FreeSlotStack&,
    timer_wheel:  core::TickTimerWheel&,
    now_ns:       u64,
    chunk:        ReactorIngressBuf&,
    cork_wire:    u8[..65536]&,
    total_served: i64&,
    stage:        Stage&,
) {
    let conn = table.fds[slot];
    guard conn > 0 else { return; }
    if server.pipeline.enable_slowloris_timer {
        table.soa_table_touch(slot, core::tick_timer_arm(timer_wheel, 15));
    }
    chunk.len = 0;
    reactor_load_leftover(table, leftovers[slot], slot, chunk);

    if table.has_tls[slot] && table.tls_slots[slot] != 0xFFFF {
        guard g_default_reactor.accel.tls_ct_leftover[slot].try_append(rx_raw) else {
            reactor_close_and_inc(server, epfd, table, slot, free_slots, total_served);
            return;
        }
        g_default_reactor.accel.tls_plain_scratch.clear();
        let cons, st = tls_cipher_slot_unseal_records(
            table.tls_slots[slot],
            g_default_reactor.accel.tls_ct_leftover[slot][..],
            g_default_reactor.accel.tls_plain_scratch,
        );
        g_default_reactor.accel.tls_ct_leftover[slot].compact_wire_buffer(cons);
        if st == TlsSliceUnsealStatus.Error {
            reactor_close_and_inc(server, epfd, table, slot, free_slots, total_served);
            return;
        }
        if g_default_reactor.accel.tls_plain_scratch.len > 0 {
            guard reactor_append_chunk_bytes(chunk, g_default_reactor.accel.tls_plain_scratch[..]) else {
                reactor_close_and_inc(server, epfd, table, slot, free_slots, total_served);
                return;
            }
            reactor_process_slot_plaintext(
                server, epfd, table, leftovers, slot, conn, free_slots, now_ns, chunk, cork_wire, total_served, stage,
            );
        }
        if st == TlsSliceUnsealStatus.Closed && table.fds[slot] > 0 {
            reactor_request_slot_close(server, epfd, table, slot, free_slots, total_served);
        }
        return;
    }

    guard reactor_append_chunk_bytes(chunk, rx_raw) else {
        reactor_close_and_inc(server, epfd, table, slot, free_slots, total_served);
        return;
    }
    if chunk.len > 0 {
        reactor_process_slot_plaintext(
            server, epfd, table, leftovers, slot, conn, free_slots, now_ns, chunk, cork_wire, total_served, stage,
        );
    }
}

// Dispatches ready epoll/kqueue events for reactor connection slots with `<Stage>`.
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

// Computes dynamic wait timeout depending on worker ring state.
inline fn reactor_epoll_timeout(ring: const core::SpscRing&) -> i32 {
    guard ring.is_open else { return 200; }
    return if ring.spsc_count() > 0 { 0 } else { 10 };
}

fn reactor_dispatch_single_rio_result<Stage>(
    server:       HttpServer&,
    res:          const net_internal::RioResult&,
    table:        SoAConnTable&,
    leftovers:    ReactorLeftoverBuf[:],
    free_slots:   FreeSlotStack&,
    timer_wheel:  core::TickTimerWheel&,
    now_ns:       u64,
    chunk:        ReactorIngressBuf&,
    cork_wire:    u8[..65536]&,
    total_served: i64&,
    stage:        Stage&,
) {
    let slot = res.socket_context as i64;
    guard slot >= 0 && slot < REACTOR_ACCEL_SLOTS && table.fds[slot] > 0 else { return; }
    let epfd = g_default_reactor.accel.epfd;

    if res.request_context == REACTOR_REQ_TX_TAG {
        g_default_reactor.accel.slot_tx_inflight[slot] = false;
        if res.status != 0 || g_default_reactor.accel.slot_close_after_tx[slot] {
            reactor_close_and_inc(server, epfd, table, slot, free_slots, total_served);
        }
        return;
    }
    guard res.request_context == REACTOR_REQ_RX_TAG else { return; }
    if res.status != 0 || res.bytes_transferred == 0 {
        reactor_request_slot_close(server, epfd, table, slot, free_slots, total_served);
        return;
    }

    let rx_len = min(res.bytes_transferred as i64, REACTOR_ACCEL_BUF_SIZE);
    let rx_off = (core::shl_sat_u64(slot as u64, 13) as u32) as i64;
    var local_rx: u8[4096] = [0; 4096];
    for i in rx_len {
        local_rx[i] = g_default_reactor.accel.slab[core::add_sat_i64(rx_off, i)];
    }
    reactor_handle_completed_rx(
        server, epfd, table, leftovers, slot, local_rx[..rx_len],
        free_slots, timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
    );
    if table.fds[slot] > 0 && !g_default_reactor.accel.slot_close_after_tx[slot] {
        if !reactor_post_rio_slot_rx(g_default_reactor.accel, slot) {
            reactor_request_slot_close(server, epfd, table, slot, free_slots, total_served);
        }
    }
}

fn reactor_poll_rio_listener(
    server:       const HttpServer&,
    draining:     bool,
    tls_config:   const TlsServerHandshakeConfig&,
    is_tls:       bool,
    timeout_ms:   i32,
    table:        SoAConnTable&,
    free_slots:   FreeSlotStack&,
    timer_wheel:  core::TickTimerWheel&,
    total_served: i64&,
) {
    let lfd = g_default_reactor.accel.rio_listener_fd;
    guard !draining && lfd > 0 else { return; }
    let wait_ms = if g_default_reactor.accel.active_accel_slots == 0 && timeout_ms > 0 {
        min(timeout_ms, 5)
    } else {
        0
    };
    let cfd = net_internal::native_rio_poll_accept(lfd, wait_ms);
    guard cfd > 0 else { return; }
    let epfd = g_default_reactor.accel.epfd;
    if is_tls {
        reactor_accept_single_tls_fd(
            server, cfd, epfd, table, free_slots, timer_wheel, tls_config, total_served,
        );
    } else {
        reactor_accept_plain_fd(cfd, epfd, table, free_slots, timer_wheel, total_served);
    }
}

fn reactor_step_rio_completions<Stage>(
    server:       HttpServer&,
    draining:     bool,
    tls_config:   const TlsServerHandshakeConfig&,
    is_tls:       bool,
    table:        SoAConnTable&,
    leftovers:    ReactorLeftoverBuf[:],
    free_slots:   FreeSlotStack&,
    timer_wheel:  core::TickTimerWheel&,
    timeout_ms:   i32,
    now_ns:       u64,
    chunk:        ReactorIngressBuf&,
    cork_wire:    u8[..65536]&,
    total_served: i64&,
    stage:        Stage&,
) -> u32 {
    guard g_default_reactor.accel.mode == ReactorAccelMode.Rio &&
        g_default_reactor.accel.rio_cq != 0 else {
        return 0;
    }
    reactor_poll_rio_listener(
        server, draining, tls_config, is_tls, timeout_ms, table, free_slots, timer_wheel, total_served,
    );
    guard g_default_reactor.accel.active_accel_slots > 0 else { return 0; }
    var rio_results: net_internal::RioResult[..64] = [];
    var n = net_internal::rio_drain_completions(g_default_reactor.accel.rio_cq, rio_results);
    if n == 0 && timeout_ms > 0 {
        let _ = net_internal::rio_wait_cq(g_default_reactor.accel.rio_cq, min(timeout_ms, 5));
        n = net_internal::rio_drain_completions(g_default_reactor.accel.rio_cq, rio_results);
    }
    for i in rio_results.len {
        reactor_dispatch_single_rio_result(
            server, rio_results[i], table, leftovers, free_slots,
            timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
        );
    }
    return n;
}

fn reactor_accept_single_tls_fd(
    server:       const HttpServer&,
    client_fd:    i64,
    epfd:         i64,
    table:        SoAConnTable&,
    free_slots:   FreeSlotStack&,
    timer_wheel:  core::TickTimerWheel&,
    tls_config:   const TlsServerHandshakeConfig&,
    total_served: i64&,
) {
    let tls_slot, ok_hs = tls_server_handshake(client_fd, tls_config);
    if !ok_hs {
        tcp_close(client_fd);
        total_served = core::add_sat_i64(total_served, 1);
        return;
    }
    var slot = pop_free_slot(free_slots);
    if slot < 0 {
        slot = reactor_evict_stale_slot(epfd, table, free_slots, timer_wheel, total_served);
    }
    if slot >= 0 {
        reactor_init_slot_record(table, client_fd, slot, timer_wheel);
        table.has_tls[slot] = true;
        table.tls_slots[slot] = tls_slot;
        if server.enable_ktls_offload && slot < REACTOR_ACCEL_SLOTS {
            let sess, ok_ktls = tls_try_enable_ktls(tls_slot, client_fd);
            if ok_ktls && sess.rx_offloaded && sess.tx_offloaded {
                g_default_reactor.accel.slot_ktls_rx[slot] = true;
            }
        }
        reactor_bind_slot_backend(g_default_reactor.accel, slot, client_fd);
    } else {
        tls_transport_close(client_fd, tls_slot);
        total_served = core::add_sat_i64(total_served, 1);
    }
}

fn reactor_dispatch_uring_recv_cqe<Stage>(
    server:       HttpServer&,
    cqe:          const net_internal::UringCqe&,
    slot:         i64,
    table:        SoAConnTable&,
    leftovers:    ReactorLeftoverBuf[:],
    free_slots:   FreeSlotStack&,
    timer_wheel:  core::TickTimerWheel&,
    now_ns:       u64,
    chunk:        ReactorIngressBuf&,
    cork_wire:    u8[..65536]&,
    total_served: i64&,
    stage:        Stage&,
) {
    let has_buf = (cqe.flags & net_internal::URING_CQE_F_BUFFER) != 0;
    let bid = ((cqe.flags >> 16) & 0xFFFF) as u16;
    if cqe.res <= 0 {
        if has_buf {
            net_internal::uring_recycle_pbuf(g_default_reactor.accel.uring_pbuf, bid);
        }
        if slot >= 0 && slot < REACTOR_ACCEL_SLOTS && table.fds[slot] > 0 {
            reactor_request_slot_close(
                server, g_default_reactor.accel.epfd, table, slot, free_slots, total_served,
            );
        }
        return;
    }
    guard slot >= 0 && slot < REACTOR_ACCEL_SLOTS && table.fds[slot] > 0 else {
        if has_buf {
            net_internal::uring_recycle_pbuf(g_default_reactor.accel.uring_pbuf, bid);
        }
        return;
    }

    var rx_tmp: u8[4096] = [0; 4096];
    var copied: i32      = 0;
    if has_buf {
        copied = net_internal::uring_read_pbuf(g_default_reactor.accel.uring_pbuf, bid, cqe.res, rx_tmp[..]);
        net_internal::uring_recycle_pbuf(g_default_reactor.accel.uring_pbuf, bid);
    }
    if copied > 0 {
        reactor_handle_completed_rx(
            server, g_default_reactor.accel.epfd, table, leftovers, slot, rx_tmp[..copied],
            free_slots, timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
        );
    }
    if (cqe.flags & net_internal::URING_CQE_F_MORE) == 0 &&
        table.fds[slot] > 0 &&
        !g_default_reactor.accel.slot_close_after_tx[slot] {
        reactor_arm_uring_slot_rx(g_default_reactor.accel, slot, table.fds[slot]);
    }
}

fn reactor_dispatch_uring_accept_cqe(
    server:       const HttpServer&,
    listener_fd:  i64,
    draining:     bool,
    tls_config:   const TlsServerHandshakeConfig&,
    is_tls:       bool,
    cqe:          const net_internal::UringCqe&,
    table:        SoAConnTable&,
    free_slots:   FreeSlotStack&,
    timer_wheel:  core::TickTimerWheel&,
    total_served: i64&,
) {
    let epfd = g_default_reactor.accel.epfd;
    if cqe.res > 0 {
        let cfd = cqe.res as i64;
        tcp_set_nonblocking(cfd, true);
        if is_tls {
            reactor_accept_single_tls_fd(
                server, cfd, epfd, table, free_slots, timer_wheel, tls_config, total_served,
            );
        } else {
            reactor_accept_plain_fd(cfd, epfd, table, free_slots, timer_wheel, total_served);
        }
    }
    if (cqe.flags & net_internal::URING_CQE_F_MORE) == 0 && !draining && listener_fd > 0 {
        reactor_arm_uring_accept(g_default_reactor.accel, listener_fd);
    }
}

fn reactor_dispatch_uring_send_cqe(
    server:       HttpServer&,
    cqe:          const net_internal::UringCqe&,
    slot:         i64,
    table:        SoAConnTable&,
    free_slots:   FreeSlotStack&,
    total_served: i64&,
) {
    guard slot >= 0 && slot < REACTOR_ACCEL_SLOTS else { return; }
    g_default_reactor.accel.slot_tx_inflight[slot] = false;
    if (cqe.res <= 0 || g_default_reactor.accel.slot_close_after_tx[slot]) && table.fds[slot] > 0 {
        reactor_close_and_inc(server, g_default_reactor.accel.epfd, table, slot, free_slots, total_served);
    }
}

fn reactor_dispatch_uring_poll_cqe<Stage>(
    server:       HttpServer&,
    cqe:          const net_internal::UringCqe&,
    slot:         i64,
    table:        SoAConnTable&,
    leftovers:    ReactorLeftoverBuf[:],
    free_slots:   FreeSlotStack&,
    timer_wheel:  core::TickTimerWheel&,
    now_ns:       u64,
    chunk:        ReactorIngressBuf&,
    cork_wire:    u8[..65536]&,
    total_served: i64&,
    stage:        Stage&,
) {
    guard slot >= 0 && slot < REACTOR_ACCEL_SLOTS && table.fds[slot] > 0 else { return; }
    let epfd = g_default_reactor.accel.epfd;
    if cqe.res < 0 {
        reactor_close_and_inc(server, epfd, table, slot, free_slots, total_served);
        return;
    }
    reactor_handle_ingress(
        server, epfd, table, leftovers, slot, free_slots,
        timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
    );
    if table.fds[slot] > 0 && !g_default_reactor.accel.slot_close_after_tx[slot] {
        reactor_arm_uring_slot_rx(g_default_reactor.accel, slot, table.fds[slot]);
    }
}

fn reactor_dispatch_single_uring_cqe<Stage>(
    server:       HttpServer&,
    listener_fd:  i64,
    draining:     bool,
    tls_config:   const TlsServerHandshakeConfig&,
    is_tls:       bool,
    cqe:          const net_internal::UringCqe&,
    table:        SoAConnTable&,
    leftovers:    ReactorLeftoverBuf[:],
    free_slots:   FreeSlotStack&,
    timer_wheel:  core::TickTimerWheel&,
    now_ns:       u64,
    chunk:        ReactorIngressBuf&,
    cork_wire:    u8[..65536]&,
    total_served: i64&,
    stage:        Stage&,
) {
    let kind = cqe.user_data & REACTOR_URING_TAG_KIND_MASK;
    let slot = (cqe.user_data & 0xFFFFFFFF) as i64;
    if kind == REACTOR_URING_TAG_ACCEPT {
        reactor_dispatch_uring_accept_cqe(
            server, listener_fd, draining, tls_config, is_tls, cqe, table, free_slots, timer_wheel, total_served,
        );
    } else if kind == REACTOR_URING_TAG_SEND {
        reactor_dispatch_uring_send_cqe(server, cqe, slot, table, free_slots, total_served);
    } else if kind == REACTOR_URING_TAG_POLL {
        reactor_dispatch_uring_poll_cqe(
            server, cqe, slot, table, leftovers, free_slots, timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
        );
    } else if kind == REACTOR_URING_TAG_RECV {
        reactor_dispatch_uring_recv_cqe(
            server, cqe, slot, table, leftovers, free_slots, timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
        );
    }
}

fn reactor_step_uring_completions<Stage>(
    server:       HttpServer&,
    listener_fd:  i64,
    draining:     bool,
    tls_config:   const TlsServerHandshakeConfig&,
    is_tls:       bool,
    timeout_ms:   i32,
    table:        SoAConnTable&,
    leftovers:    ReactorLeftoverBuf[:],
    free_slots:   FreeSlotStack&,
    timer_wheel:  core::TickTimerWheel&,
    now_ns:       u64,
    chunk:        ReactorIngressBuf&,
    cork_wire:    u8[..65536]&,
    total_served: i64&,
    stage:        Stage&,
) -> i32 {
    guard g_default_reactor.accel.mode == ReactorAccelMode.IoUring &&
        g_default_reactor.accel.uring_fd >= 0 else {
        return 0;
    }
    var cqes: net_internal::UringCqe[64] = [net_internal::UringCqe { .. }; 64];
    let min_c: u32 = if timeout_ms > 0 { 1 } else { 0 };
    let timeout_ns = net_internal::timeout_ms_to_ns(timeout_ms);
    let n = net_internal::uring_wait_cqes(g_default_reactor.accel.uring_fd, cqes[..], min_c, timeout_ns);
    guard n > 0 else { return 0; }
    let limit = min(n as i64, 64);
    for i in limit {
        reactor_dispatch_single_uring_cqe(
            server, listener_fd, draining, tls_config, is_tls, cqes[i], table,
            leftovers, free_slots, timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
        );
    }
    return n;
}

inline fn reactor_emit_slot_goaway(table: const SoAConnTable&, slot: i64, cork_wire: u8[..65536]&) {
    let fd = table.fds[slot];
    guard fd > 0 && table.is_h2[slot] else { return; }
    let h2_idx = table.h2_slot_map[slot] as i64;
    guard h2_idx >= 0 && h2_idx < REACTOR_MAX_H2_SESSIONS else { return; }
    cork_wire.clear();
    server_internal::initiate_graceful_shutdown(g_default_reactor.h2_sessions[h2_idx], cork_wire);
    guard cork_wire.len > 0 else { return; }
    let _ = reactor_send_slot_wire(table, slot, fd, cork_wire[..]);
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
    let _ = epfd;
    if !draining && server_should_stop(server) {
        draining = true;
        server.is_running = false;
        reactor_detach_listener(g_default_reactor.accel, listener_fd);
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
    ensure_reactor_h2_capacity(state);
    ensure_reactor_leftovers_capacity(state);
    reset_soa_table_inplace(state.table);
    server_internal::reset_connection_pool_inplace(state.conn_pool);
    state.cork.clear();
    state.chunk.len = 0;
    init_free_slots(state.free_slots, SOA_TABLE_CAP);
}

inline fn reactor_prepare_loop(server: HttpServer&, listener_fd: i64) -> bool {
    reset_reactor_state(g_default_reactor);
    guard reactor_init_accel(g_default_reactor.accel, server.accel_mode, listener_fd) else {
        return false;
    }
    server_init_run_state(server);
    return true;
}

// Executes a share-nothing reactor loop with OS completion/readiness acceleration and a `<Stage>` hook.
fn serve_reactor_with_stage<Stage>(
    server:          HttpServer&,
    listener_fd:     i64,
    stage:           Stage&,
    max_connections: i64 = 0,
) -> i64 {
    guard listener_fd > 0 || server.worker_ring.is_open else { return 0; }
    guard reactor_prepare_loop(server, listener_fd) else { return 0; }
    defer reactor_close_accel(g_default_reactor.accel);

    let dummy_tls_cfg = TlsServerHandshakeConfig { .. };
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
        let epfd = g_default_reactor.accel.epfd;
        if reactor_step_drain_gate(
            server, epfd, listener_fd, g_default_reactor.table, g_default_reactor.cork, draining, drain_deadline_ns,
        ) { break; }
        if !draining && server.worker_ring.is_open {
            reactor_drain_worker_ring(
                server.worker_ring, epfd, g_default_reactor.table,
                g_default_reactor.free_slots, timer_wheel, total_served,
            );
        }
        let wait_ms = reactor_epoll_timeout(server.worker_ring);
        let n_ready = reactor_wait_readiness_events(g_default_reactor.accel, ready_udata[..], wait_ms);
        turn_counter = core::add_sat_i64(turn_counter, 1);
        reactor_poll_sweep(
            epfd, g_default_reactor.table, g_default_reactor.free_slots, timer_wheel, n_ready, turn_counter,
            last_sweep_sec, total_served, cached_now_ns, cached_now_sec, server.pipeline.enable_slowloris_timer,
        );
        if n_ready > 0 {
            reactor_dispatch_events(
                server, epfd, listener_fd, g_default_reactor.table, g_default_reactor.leftovers[..],
                g_default_reactor.free_slots, timer_wheel, ready_udata[..n_ready], cached_now_ns,
                g_default_reactor.chunk, g_default_reactor.cork, total_served, stage,
            );
        }
        let _ = reactor_step_rio_completions(
            server, draining, dummy_tls_cfg, false, g_default_reactor.table, g_default_reactor.leftovers[..],
            g_default_reactor.free_slots, timer_wheel, wait_ms, cached_now_ns,
            g_default_reactor.chunk, g_default_reactor.cork, total_served, stage,
        );
        let _ = reactor_step_uring_completions(
            server, listener_fd, draining, dummy_tls_cfg, false, wait_ms, g_default_reactor.table,
            g_default_reactor.leftovers[..], g_default_reactor.free_slots, timer_wheel, cached_now_ns,
            g_default_reactor.chunk, g_default_reactor.cork, total_served, stage,
        );
    }
    reactor_cleanup_all(g_default_reactor.accel.epfd, g_default_reactor.table, g_default_reactor.free_slots);
    return total_served;
}

// Executes a share-nothing reactor loop with automatic OS accelerator selection.
fn serve_reactor(server: HttpServer&, listener_fd: i64, max_connections: i64 = 0) -> i64 {
    var noop = wire::NoOpStage {};
    return serve_reactor_with_stage(server, listener_fd, noop, max_connections);
}

fn reactor_accept_tls_client(
    server:       const HttpServer&,
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
        reactor_accept_single_tls_fd(
            server, client_fd, epfd, table, free_slots, timer_wheel, tls_config, total_served,
        );
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
                server, listener_fd, epfd, table, free_slots,
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

// Executes a TLS 1.3 reactor loop with opportunistic kTLS and completion-ring cipher slots.
fn serve_reactor_tls(
    server:          HttpServer&,
    listener_fd:     i64,
    tls_config:      const TlsServerHandshakeConfig&,
    max_connections: i64 = 0,
) -> i64 {
    guard listener_fd > 0 else { return 0; }
    guard reactor_prepare_loop(server, listener_fd) else { return 0; }
    defer reactor_close_accel(g_default_reactor.accel);

    var noop = wire::NoOpStage {};
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
        let epfd = g_default_reactor.accel.epfd;
        if reactor_step_drain_gate(
            server, epfd, listener_fd, g_default_reactor.table, g_default_reactor.cork, draining, drain_deadline_ns,
        ) {
            break;
        }
        let n_ready = reactor_wait_readiness_events(g_default_reactor.accel, ready_udata[..], 10);
        turn_counter = core::add_sat_i64(turn_counter, 1);
        reactor_poll_sweep(
            epfd, g_default_reactor.table, g_default_reactor.free_slots, timer_wheel, n_ready, turn_counter,
            last_sweep_sec, total_served, cached_now_ns, cached_now_sec,
            server.pipeline.enable_slowloris_timer,
        );
        if n_ready > 0 {
            reactor_dispatch_tls_events(
                server, epfd, listener_fd, g_default_reactor.table, g_default_reactor.leftovers[..],
                g_default_reactor.free_slots, timer_wheel, tls_config, ready_udata[..n_ready as i64],
                cached_now_ns, g_default_reactor.chunk, g_default_reactor.cork, total_served,
            );
        }
        let _ = reactor_step_rio_completions(
            server, draining, tls_config, true, g_default_reactor.table, g_default_reactor.leftovers[..],
            g_default_reactor.free_slots, timer_wheel, 10, cached_now_ns,
            g_default_reactor.chunk, g_default_reactor.cork, total_served, noop,
        );
        let _ = reactor_step_uring_completions(
            server, listener_fd, draining, tls_config, true, 10,
            g_default_reactor.table, g_default_reactor.leftovers[..],
            g_default_reactor.free_slots, timer_wheel, cached_now_ns,
            g_default_reactor.chunk, g_default_reactor.cork, total_served, noop,
        );
    }
    reactor_cleanup_all(g_default_reactor.accel.epfd, g_default_reactor.table, g_default_reactor.free_slots);
    return total_served;
}

// Processes an incoming HTTP/3 request stream payload through `H3Connection` and `server.pipeline` (RFC 9114).
fn handle_h3_server_datagram<B>(
    server:    HttpServer&,
    h3_conn:   h3_internal::H3Connection&,
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
    let h_err = h3_internal::handle_stream_data(h3_conn, stream_id, true, rx_wire, true);
    guard h_err == rfc::H3_ERR_NO_ERROR else { return false; }

    let s_idx, found = h3_internal::find_h3_stream_idx(h3_conn, stream_id);
    guard found && s_idx >= 0 && s_idx < h3_conn.streams.len else { return false; }
    guard h3_conn.streams[s_idx].headers_received else { return false; }

    let method = if h3_conn.streams[s_idx].req_method.len > 0 { h3_conn.streams[s_idx].req_method[..] } else { "GET" };
    let path = if h3_conn.streams[s_idx].req_path.len > 0 { h3_conn.streams[s_idx].req_path[..] } else { "/" };
    var req = new_request(method, path);
    if h3_conn.streams[s_idx].req_authority.len > 0 {
        let _ = append_header(req.headers, "host", h3_conn.streams[s_idx].req_authority[..]);
        req.presence_mask |= HDR_PRESENCE_HOST;
    }
    let _ = h3_internal::copy_stream_headers(h3_conn, stream_id, req.headers);
    for &e in req.headers.entries {
        let known_id = identify_known_header(entry_name(req.headers, e));
        req.presence_mask |= header_id_to_bit(known_id);
    }
    let _ = h3_internal::copy_stream_trailers(h3_conn, stream_id, req.trailers);
    if h3_conn.streams[s_idx].received_body.len > 0 {
        req.body.append(h3_conn.streams[s_idx].received_body[..]);
    }

    var res = Response { .. };
    var future = server_internal::new_inline_handler_future(0);
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
    return h3_internal::send_response_headers_body_and_trailers(
        h3_conn, stream_id, res.status_code, extra_map, res.body[..], res.trailers, tx_wire,
    );
}

inline fn dispatch_h3_udp_datagram(
    server:    HttpServer&,
    udp_fd:    i64,
    h3_conn:   h3_internal::H3Connection&,
    served:    i64,
    peer_ip4:  u32,
    peer_port: u16,
    rx_slice:  const u8[:],
    now_ns:    u64,
    tx_wire:   u8[..1472]&,
    tx_queue:  UdpBatchQueue&,
) {
    let stream_id = core::shl_sat_u64((served & 15) as u64, 2);
    for st_i in h3_conn.streams.len {
        if h3_conn.streams[st_i].stream_id == stream_id {
            h3_conn.streams[st_i] = h3_internal::H3StreamEntry { stream_id: stream_id, .. };
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
    let _ = server_internal::with_connection_slot(g_default_reactor.conn_pool, udp_fd, now_ns as i64) { conn_slot =>
        server_internal::notify_request_start(conn_slot.timer);
        if server.handle_h3_server_datagram(h3_conn, stream_id, peer_ip_str[..], rx_slice, now_ns, tx_wire) {
            let dgram, ok_dg = build_udp_datagram(tx_wire[..], peer_ip4, peer_port);
            if ok_dg {
                let _, _ = enqueue_udp_datagram(udp_fd as i32, tx_queue, dgram);
            }
        }
        server_internal::notify_request_end(conn_slot.timer);
    };
}

// Executes an Unencrypted H3 over UDP (Datagram Direct) server loop (RFC 9114 framing + QPACK)
// using batched `recvmmsg` / `sendmmsg` transitions up to 32 datagrams per syscall.
fn serve_h3(server: HttpServer&, udp_fd: i64, max_datagrams: i64 = 1) -> i64 {
    guard udp_fd > 0 else { return 0; }
    let h3_settings = H3Settings { .. };
    var h3_conn = h3_internal::new_h3_server_connection(h3_settings);
    var rx_queue = UdpBatchQueue { .. };
    var tx_queue = UdpBatchQueue { .. };
    var tx_wire:    u8[..1472] = [];
    var served:     i64        = 0;
    var idle_spins: i64        = 0;

    while max_datagrams == 0 || served < max_datagrams {
        let recvd, ok_rx = batch_recv_messages(udp_fd as i32, rx_queue);
        if !ok_rx || recvd <= 0 {
            idle_spins = core::add_sat_i64(idle_spins, 1);
            if max_datagrams > 0 && idle_spins >= 25 { break; }
            continue;
        }
        idle_spins = 0;
        let now_ns = core::monotonic_now().as_nanos();
        for i in rx_queue.msgs.len {
            if max_datagrams > 0 && served >= max_datagrams { break; }
            dispatch_h3_udp_datagram(
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
            let _, _ = batch_send_messages(udp_fd as i32, tx_queue);
        }
    }
    return served;
}

// Public HTTP/3 and QUIC server endpoint state (RFC 9000, RFC 9114, RFC 9204).
// Encapsulates HTTP/3 connection state, QPACK tables, and QUIC handshake framing.
struct H3ServerEndpoint {
    conn: h3_internal::H3Connection = h3_internal::H3Connection { .. },
}

fn new_h3_server_endpoint(settings: H3Settings = H3Settings { .. }) -> H3ServerEndpoint {
    var ep = H3ServerEndpoint {
        conn: h3_internal::new_h3_server_connection(settings),
    };
    ep.conn.qpack_table.capacity_bytes = 0;
    return ep;
}

fn encode_h3_connection_close<B>(err_code: u64, out_wire: B&) {
    out_wire.clear();
    quic_internal::quic_encode_varint(out_wire, 0x1D);
    quic_internal::quic_encode_varint(out_wire, err_code);
    quic_internal::quic_encode_varint(out_wire, 0);
}

inline fn is_h3_wire_frame_bounded(datagram: const u8[:], hdr: const h3_internal::H3FrameHeader&) -> bool {
    return ((hdr.header_len + hdr.payload_len) as i64) <= datagram.len;
}

fn handle_h3_endpoint_settings<B>(
    ep:       H3ServerEndpoint&,
    hdr:      const h3_internal::H3FrameHeader&,
    payload:  const u8[:],
    out_wire: B&,
) -> bool {
    let err = h3_internal::handle_peer_control_frame(ep.conn, hdr, payload);
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
            ep.conn.streams[st_i] = h3_internal::H3StreamEntry { stream_id: 0, .. };
        }
    }
    ep.conn.state = h3_internal::H3ConnState.Active;
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
    let hdr, ok_hdr = h3_internal::parse_h3_frame_header(datagram, 0);
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

fn encode_quic_version_negotiation<B>(hdr: const quic_internal::QuicHeader&, out_wire: B&) {
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
    hdr:      const quic_internal::QuicHeader&,
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
    quic_internal::quic_encode_varint(h3_ctrl, rfc::H3_STREAM_CONTROL);
    h3_internal::encode_h3_settings_frame(h3_ctrl, ep.conn.local_settings);
    h3_internal::encode_h3_frame_header(h3_ctrl, 0x21, 0);

    let payload_len = (2 + h3_ctrl.len) as u64;
    quic_internal::quic_encode_varint(out_wire, payload_len);
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

    let quic_hdr, ok_qhdr = quic_internal::parse_quic_header(datagram);
    guard ok_qhdr else { return false; }

    if quic_hdr.version != rfc::QUIC_VERSION_1 && quic_hdr.version != rfc::QUIC_VERSION_NEGOTIATION {
        encode_quic_version_negotiation(quic_hdr, out_wire);
        return out_wire.len > 0;
    }

    if quic_hdr.header_type == quic_internal::QuicHeaderType.Initial {
        // RFC 9000 Section 14.1: Initial Datagram Size - server MUST discard client Initial < 1200 bytes
        guard datagram.len >= (rfc::QUIC_MIN_INITIAL_DATAGRAM_LEN as i64) else {
            return false;
        }
        encode_quic_server_initial(ep, quic_hdr, out_wire);
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

fn format_l2_client_ip(ep: const net_internal::L2UdpEndpoint&, out_ip: u8[..48]&) {
    out_ip.clear();
    if ep.is_ipv6 {
        let _ = out_ip.try_append("ipv6-l2");
        return;
    }
    core::format_u64_dec(ep.ip[0], out_ip);
    let _ = out_ip.try_push('.');
    core::format_u64_dec(ep.ip[1], out_ip);
    let _ = out_ip.try_push('.');
    core::format_u64_dec(ep.ip[2], out_ip);
    let _ = out_ip.try_push('.');
    core::format_u64_dec(ep.ip[3], out_ip);
}

fn process_h3_l2_frame(
    server:       HttpServer&,
    ep:           H3ServerEndpoint&,
    local_ep:     const net_internal::L2UdpEndpoint&,
    rx_frame:     const u8[:],
    ip_id:        u16,
    now_ns:       u64,
    out_tx_frame: u8[..2048]&,
) -> bool {
    out_tx_frame.clear();
    let parsed, ok_dec = net_internal::decode_l2_udp_frame(rx_frame);
    guard ok_dec else { return false; }
    guard local_ep.port == 0 || parsed.dst.port == local_ep.port else { return false; }
    let pay_end = core::add_sat_i64(parsed.payload_offset, parsed.payload_len);
    guard pay_end <= rx_frame.len else { return false; }
    var cli_ip: u8[..48] = [];
    format_l2_client_ip(parsed.src, cli_ip);
    var udp_reply: u8[..1472] = [];
    guard handle_h3_quic_datagram(
        server,
        ep,
        cli_ip[..],
        rx_frame[parsed.payload_offset..pay_end],
        now_ns,
        udp_reply,
    ) else {
        return false;
    }
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
    server:      HttpServer&,
    ep:          H3ServerEndpoint&,
    cfg:         const H3L2Config&,
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
    server:      HttpServer&,
    ep:          H3ServerEndpoint&,
    cfg:         const H3L2Config&,
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
            return serve_h3_af_xdp(server, ep, cfg, xsk, max_packets);
        },
        Dpdk => {
            return serve_h3_dpdk(server, ep, cfg, max_packets);
        },
    }
}
