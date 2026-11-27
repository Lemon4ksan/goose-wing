// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal reactor socket/kTLS/TLS ingress reads, H1/H2 dispatch, TLS unsealing, and readiness event loops.
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
import tls.backend;
import tls.server_handshake;
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

inline fn reactor_read_single_turn(conn: i64, chunk: ReactorIngressBuf&, available: i64) -> i32 {
    let offset = chunk.len;
    let end = core::add_sat_i64(offset, available);
    guard offset >= 0 && end <= chunk.bytes.len else { return -2; }
    let recvd = net::tcp_recv_nonblocking_slice(conn, chunk.bytes[offset..end]);
    if recvd > 0 {
        chunk.len = core::add_sat_i64(chunk.len, recvd);
    }
    return recvd;
}

// Drains up to 4 turns of non-blocking TCP ingress into chunk buffer.
// Returns (any_recvd, is_closed).
fn reactor_read_bounded_turns(conn: i64, chunk: ReactorIngressBuf&) -> bool, bool {
    var any_recvd = false;
    for _ in 4 {
        let available = core::sub_sat_i64(REACTOR_INGRESS_CAP, chunk.len);
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
    core::copy_bytes_fast(chunk.bytes[..], 0, leftover_pool.items[prev_off..end_off]);
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
    if leased.len >= rem.len {
        core::copy_bytes_fast(leased, 0, rem);
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
    let now_ms = div_euclid(now_ns, 1000000);
    cork_wire.clear();
    if server.trust_proxy_headers {
        server.pipeline.trust_proxy_headers = true;
    }
    let h2_idx = table.ensure_h2_session(slot, server.pipeline, server.server_name[..], now_ms);
    guard h2_idx >= 0 && h2_idx < server::g_default_reactor.h2_sessions.len else { return false; }
    if slot < table.tls_snis.len && table.tls_snis[slot].len > 0 &&
        server::g_default_reactor.h2_sessions[h2_idx].tls_sni.len == 0 {
        let _ = server::g_default_reactor.h2_sessions[h2_idx].tls_sni.try_set(table.tls_snis[slot][..]);
    }
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
    reactor_cleanup_slot(epfd, table, leftover_pool, slot, slot_pool, server.pipeline);
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
        if slot < table.half_close_deadlines_ms.len &&
            server.half_close_timeout_ms > 0 &&
            table.half_close_deadlines_ms[slot] == 0 {
            let now_ms = (core::monotonic_now().as_nanos() / 1000000) as i64;
            table.half_close_deadlines_ms[slot] = core::add_sat_i64(now_ms, server.half_close_timeout_ms);
        }
        return;
    }
    reactor_close_and_inc(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
}

fn reactor_read_ktls_slot(conn: i64, chunk: ReactorIngressBuf&) -> bool, bool {
    guard chunk.len < REACTOR_INGRESS_CAP && chunk.len < chunk.bytes.len else { return false, false; }
    let start = chunk.len;
    let recvd, rtype = net_internal::smartnic_recv_record(conn, chunk.bytes[start..REACTOR_INGRESS_CAP]);
    let added, any_recvd, should_close = classify_ktls_recv_turn(
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
        let available = core::sub_sat_i64(REACTOR_INGRESS_CAP, chunk.len);
        guard available > 0 && chunk.len < chunk.bytes.len else { return false, false; }
        let tr = table.slot_transport(slot);
        let recvd = tr.recv_slice(chunk.bytes[chunk.len..REACTOR_INGRESS_CAP], 50);
        if recvd == 0 || recvd == -1 {
            return chunk.len > 0, chunk.len == 0;
        }
        if recvd < 0 {
            return chunk.len > 0, false;
        }
        chunk.len = core::add_sat_i64(chunk.len, recvd);
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
        let phase_sec = resolve_slot_phase_timeout_sec(server, table, slot);
        table.soa_table_touch(slot, core::tick_timer_arm(timer_wheel, phase_sec));
    }

    chunk.len = 0;
    reactor_load_leftover(table, leftover_pool, slot, chunk);

    let any_recvd, is_closed = reactor_read_slot_turns(table, slot, conn, chunk);
    if is_closed {
        reactor_close_and_inc(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        return;
    }
    guard any_recvd || prev_len > 0 else { return; }
    if slot < table.tls_hs_map.len && table.tls_hs_map[slot] >= 0 {
        let rx_tmp .= reactor_tls_rx_scratch();
        guard chunk.len > 0 && chunk.len <= rx_tmp.len else {
            reactor_request_slot_close(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
            return;
        }
        let rx_len = chunk.len;
        core::copy_bytes_fast(rx_tmp[..], 0, chunk.bytes[..rx_len]);
        chunk.len = 0;
        reactor_step_async_tls_handshake(
            server, epfd, table, leftover_pool, slot, conn, rx_tmp[..rx_len],
            slot_pool, now_ns, chunk, cork_wire, total_served, stage,
        );
        return;
    }
    reactor_process_slot_plaintext(
        server, epfd, table, leftover_pool, slot, conn, slot_pool, now_ns, chunk, cork_wire, total_served, stage,
    );
}

fn reactor_append_chunk_bytes(chunk: ReactorIngressBuf&, src: const u8[:]) -> bool {
    let end_len = core::add_sat_i64(chunk.len, src.len);
    guard end_len <= REACTOR_INGRESS_CAP && end_len <= chunk.bytes.len else { return false; }
    core::copy_bytes_fast(chunk.bytes[..], chunk.len, src);
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

inline fn reactor_try_attach_ktls(
    server:   const server::HttpServer&,
    slot:     i64,
    fd:       i64,
    tls_slot: u16,
) {
    guard server.enable_ktls_offload && slot >= 0 && slot < net::REACTOR_ACCEL_SLOTS &&
        !server::g_reactor_accel.slot_rx_armed[slot] else {
        return;
    }
    if server::g_default_reactor.ktls_probe_state == 0 {
        server::g_default_reactor.ktls_probe_state = if net_internal::smartnic_probe_ktls() { 1 } else { -1 };
    }
    guard server::g_default_reactor.ktls_probe_state > 0 else { return; }
    let sess, ok_ktls = tls::try_enable_ktls(tls_slot, fd);
    if ok_ktls && sess.rx_offloaded && sess.tx_offloaded {
        server::g_reactor_accel.slot_ktls_rx[slot] = true;
    }
}

inline fn reactor_send_slot_raw_wire(slot: i64, conn: i64, wire: const u8[:]) -> bool {
    guard wire.len > 0 else { return true; }
    if slot >= 0 && slot < net::REACTOR_ACCEL_SLOTS && server::g_reactor_accel.slot_accel[slot] {
        return net::reactor_submit_accel_tx(server::g_reactor_accel, slot, conn, wire);
    }
    return net::reactor_drain_cork_wire(conn, wire);
}

inline fn reactor_drain_tls_hs_tx(slot: i64, conn: i64, ep: tls::TlsEndpoint&) -> bool {
    var tx_buf: u8[8192] = [0; 8192];
    for _ in 8 {
        let n, dst = tls::tls_endpoint_drain_wire(ep, tx_buf[..]);
        guard dst == tls::TlsBackendStatus.Ok else { return false; }
        if n <= 0 { return true; }
        guard n <= tx_buf.len && reactor_send_slot_raw_wire(slot, conn, tx_buf[..n]) else { return false; }
    }
    return true;
}

inline fn reactor_finish_async_tls_hs<Stage>(
    server:        server::HttpServer&,
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot:          i64,
    conn:          i64,
    hs_i:          i64,
    ep:            tls::TlsEndpoint&,
    rem:           const u8[:],
    slot_pool:     ReactorSlotPool&,
    now_ns:        u64,
    chunk:         ReactorIngressBuf&,
    cork_wire:     u8[..65536]&,
    total_served:  i64&,
    stage:         Stage&,
) {
    let trailing_buf .= reactor_tls_seal_scratch();
    trailing_buf.resize(16648, 0);
    let sni_host = tls::tls_endpoint_client_sni(ep);
    let tls_slot, trailing_len, ok_fin = tls::server_handshake_finish_slot(ep, trailing_buf[..]);
    server::g_default_reactor.tls_hs_in_use[hs_i] = false;
    table.tls_hs_map[slot] = -1;
    guard ok_fin else {
        trailing_buf.clear();
        reactor_request_slot_close(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        return;
    }
    table.has_tls[slot] = true;
    table.tls_slots[slot] = tls_slot;
    if slot < table.tls_snis.len && sni_host.len > 0 {
        let _ = table.tls_snis[slot].try_set(sni_host[..]);
    }
    if trailing_len == 0 && rem.len == 0 {
        trailing_buf.clear();
        reactor_try_attach_ktls(server, slot, conn, tls_slot);
        return;
    }
    var app_ct: u8[..32768] = [];
    if trailing_len > 0 && (trailing_len > trailing_buf.len || !app_ct.try_append(trailing_buf[..trailing_len])) {
        trailing_buf.clear();
        reactor_request_slot_close(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        return;
    }
    trailing_buf.clear();
    if rem.len > 0 && !app_ct.try_append(rem) {
        reactor_request_slot_close(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        return;
    }
    chunk.len = 0;
    reactor_unseal_completed_tls_rx(
        server, epfd, table, leftover_pool, slot, conn, app_ct[..], slot_pool,
        now_ns, chunk, cork_wire, total_served, stage,
    );
}

fn reactor_step_async_tls_handshake<Stage>(
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
    let hs_i = table.tls_hs_map[slot] as i64;
    guard hs_i >= 0 && hs_i < REACTOR_MAX_TLS_HANDSHAKES &&
        server::g_default_reactor.tls_hs_in_use[hs_i] else {
        reactor_request_slot_close(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        return;
    }
    var hs_in: u8[..32768] = [];
    guard hs_in.try_set(rx_raw) else {
        reactor_request_slot_close(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        return;
    }
    let ep .= server::g_default_reactor.tls_hs_eps[hs_i];
    var rem: const u8[:] = hs_in[..];
    for _ in 8 {
        if rem.len > 0 {
            let fed, fst = tls::tls_endpoint_feed_wire(ep, rem);
            if fst == tls::TlsBackendStatus.Ok {
                rem = rem[fed..];
            } else if fst != tls::TlsBackendStatus.WantWrite {
                reactor_request_slot_close(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
                return;
            }
        }
        let hst = tls::tls_endpoint_step_handshake(ep);
        guard reactor_drain_tls_hs_tx(slot, conn, ep) else {
            reactor_request_slot_close(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
            return;
        }
        if hst == tls::TlsBackendStatus.Ok || tls::tls_endpoint_is_established(ep) {
            reactor_finish_async_tls_hs(
                server, epfd, table, leftover_pool, slot, conn, hs_i, ep, rem,
                slot_pool, now_ns, chunk, cork_wire, total_served, stage,
            );
            return;
        }
        if hst == tls::TlsBackendStatus.WantRead {
            if rem.len == 0 { return; }
            continue;
        }
        if hst == tls::TlsBackendStatus.WantWrite { continue; }
        reactor_request_slot_close(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        return;
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
        let phase_sec = resolve_slot_phase_timeout_sec(server, table, slot);
        table.soa_table_touch(slot, core::tick_timer_arm(timer_wheel, phase_sec));
    }
    if slot < table.tls_hs_map.len && table.tls_hs_map[slot] >= 0 {
        reactor_step_async_tls_handshake(
            server, epfd, table, leftover_pool, slot, conn, rx_raw,
            slot_pool, now_ns, chunk, cork_wire, total_served, stage,
        );
        return;
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
                server, listener_fd, epfd, table, leftover_pool, slot_pool, timer_wheel, total_served,
            );
            continue;
        }

        let slot = (udata & 0xFFFFFFFF) as i64;
        let gen = ((udata >> 32) & 0xFFFFFFFF) as u32;
        guard slot >= 0 && slot < table.generations.len else { continue; }
        guard gen == 0 || table.generations[slot] == gen else { continue; }
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

inline fn reactor_try_start_async_tls_hs(
    server:        server::HttpServer&,
    client_fd:     i64,
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    tls_config:    const tls::ServerHandshakeConfig&,
    hdr_sec:       u8,
    total_served:  i64&,
) -> bool {
    var ep, ok_start = tls::server_handshake_start(tls_config);
    guard ok_start else { return false; }
    let hs_idx = alloc_reactor_tls_hs_slot(ep);
    guard hs_idx >= 0 else {
        tls::tls_endpoint_close(ep);
        return false;
    }
    var slot = alloc_reactor_conn_slot(slot_pool, table);
    if slot < 0 {
        slot = reactor_evict_stale_slot(
            epfd, table, leftover_pool, slot_pool, server.pipeline, timer_wheel, total_served,
        );
    }
    if slot >= 0 {
        reactor_init_slot_record(table, leftover_pool, client_fd, slot, timer_wheel, hdr_sec);
        table.tls_hs_map[slot] = hs_idx;
        net::reactor_bind_slot_backend(server::g_reactor_accel, slot, client_fd);
        return true;
    }
    server::g_default_reactor.tls_hs_in_use[hs_idx as i64] = false;
    tls::tls_endpoint_close(ep);
    net::tcp_close(client_fd);
    return true;
}

fn reactor_accept_single_tls_fd(
    server:        server::HttpServer&,
    client_fd:     i64,
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    tls_config:    const tls::ServerHandshakeConfig&,
    total_served:  i64&,
) {
    if server.tcp_user_timeout_ms > 0 {
        let _ = net::tcp_set_user_timeout(client_fd, server.tcp_user_timeout_ms);
    }
    let hdr_sec = resolve_reactor_header_sec(server);
    if reactor_try_start_async_tls_hs(
        server, client_fd, epfd, table, leftover_pool, slot_pool,
        timer_wheel, tls_config, hdr_sec, total_served,
    ) {
        return;
    }

    let tls_slot, ok_hs = tls::server_handshake(client_fd, tls_config);
    if !ok_hs {
        net::tcp_close(client_fd);
        total_served = core::add_sat_i64(total_served, 1);
        return;
    }
    var slot = alloc_reactor_conn_slot(slot_pool, table);
    if slot < 0 {
        slot = reactor_evict_stale_slot(
            epfd, table, leftover_pool, slot_pool, server.pipeline, timer_wheel, total_served,
        );
    }
    if slot >= 0 {
        reactor_init_slot_record(table, leftover_pool, client_fd, slot, timer_wheel, hdr_sec);
        table.has_tls[slot] = true;
        table.tls_slots[slot] = tls_slot;
        reactor_try_attach_ktls(server, slot, client_fd, tls_slot);
        net::reactor_bind_slot_backend(server::g_reactor_accel, slot, client_fd);
    } else {
        tls::transport_close(client_fd, tls_slot);
        total_served = core::add_sat_i64(total_served, 1);
    }
}

fn reactor_accept_tls_client(
    server:        server::HttpServer&,
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
        let slot = (udata & 0xFFFFFFFF) as i64;
        let gen = ((udata >> 32) & 0xFFFFFFFF) as u32;
        guard slot >= 0 && slot < table.generations.len else { continue; }
        guard gen == 0 || table.generations[slot] == gen else { continue; }
        if is_active_slot(table, slot) {
            reactor_handle_ingress(
                server, epfd, table, leftover_pool, slot, slot_pool,
                timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
            );
        }
    }
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
        let ctl = tls::inspect_unsealed_handshake_control(rec_bytes[..hs_len]);
        return 0, buffered_len > 0, ctl != tls::SliceUnsealStatus.ControlHandled;
    }
    return 0, buffered_len > 0, false;
}
