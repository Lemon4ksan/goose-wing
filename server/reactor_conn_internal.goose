// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal reactor state, pooled buffers, SoA slot lifecycle, TLS ciphertext ring, timeouts, and accept/drain.
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
import .reactor_io_internal;

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

const REACTOR_ZERO_PAD: u8[1024] = [0; 1024];

inline fn ensure_reactor_ingress_buf(chunk: ReactorIngressBuf&) {
    while chunk.bytes.len < REACTOR_INGRESS_CAP {
        let rem = core::sub_sat_i64(REACTOR_INGRESS_CAP, chunk.bytes.len);
        chunk.bytes.append(REACTOR_ZERO_PAD[..min(rem, REACTOR_ZERO_PAD.len)]);
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

inline fn reactor_tls_rx_scratch() -> u8[16384]& {
    if server::g_reactor_tls_rx_bufs.len == 0 {
        server::g_reactor_tls_rx_bufs.push([0; 16384]);
    }
    return server::g_reactor_tls_rx_bufs[0];
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
    guard fd > 0 else {
        net::reactor_reset_accel_slot(server::g_reactor_accel, slot_idx);
        return;
    }
    if server::g_reactor_accel.kq_fd >= 0 {
        net::reactor_queue_kq_change(server::g_reactor_accel, fd, net_internal::EV_DELETE, slot_idx as u64);
    }
    if epfd >= 0 && net::epoll_del(epfd, fd) {
        let prev_reg = server::g_reactor_accel.epfd_registered_count;
        server::g_reactor_accel.epfd_registered_count = max(0, core::sub_sat_i64(prev_reg, 1)) as i32;
    }
    var tr = table.slot_transport(slot_idx);
    tr.close();
    let accel_freed = net::reactor_quarantine_or_reset_slot(server::g_reactor_accel, slot_idx);
    let h2_i = table.h2_slot_map[slot_idx] as i64;
    if h2_i >= 0 && h2_i < server::REACTOR_MAX_H2_SESSIONS {
        server::g_default_reactor.h2_in_use[h2_i] = false;
    }
    if table.conn_slots[slot_idx] >= 0 {
        server_internal::free_connection_slot(server::g_reactor_conn_pool, table.conn_slots[slot_idx]);
    }
    table.soa_table_free(slot_idx);
    if accel_freed {
        free_reactor_conn_slot(slot_pool, slot_idx);
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
    let elapsed = if last_sweep_sec == 0 { 1 } else { core::sub_sat_i64(now_sec, last_sweep_sec) as u32 };
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
    server_internal::reset_soa_slot_fields(table, slot, client_fd, core::tick_timer_arm(timer_wheel, 15));
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
    cached_sec = nanos_to_http_date_sec(cached_ns);
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

inline fn resolve_reactor_slot_cap(server: const server::HttpServer&) -> i64 {
    if server.max_connections > 0 {
        return min(server.max_connections as i64, REACTOR_MAX_DYNAMIC_SLOTS);
    }
    return REACTOR_MAX_DYNAMIC_SLOTS;
}

inline fn resolve_reactor_idle_sec(server: const server::HttpServer&) -> u8 {
    guard server.idle_timeout_ms > 0 else { return 15; }
    let sec = max(div_euclid(core::add_sat_u64(server.idle_timeout_ms, 999), 1000), 1);
    return min(sec, core::TICK_TIMER_MAX_DELTA) as u8;
}
