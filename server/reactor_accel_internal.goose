// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal OS/NIC accelerated datapaths: Windows RIO, Linux io_uring, HTTP/3 UDP/QUIC, and AF_XDP/DPDK L2.
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
import .reactor_conn_internal;
import .reactor_io_internal;

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
    let slot, ok_tok, is_quarantined = net::reactor_accel_match_any_token(
        server::g_reactor_accel, res.socket_context,
    );
    guard ok_tok else { return; }
    let epfd = server::g_reactor_accel.epfd;

    if res.request_context == net::REACTOR_REQ_TX_TAG {
        server::g_reactor_accel.slot_tx_inflight[slot] = false;
        if is_quarantined {
            if net::reactor_finalize_quarantined_slot(server::g_reactor_accel, slot) {
                free_reactor_conn_slot(slot_pool, slot);
            }
            return;
        }
        guard is_active_slot(table, slot) else { return; }
        if res.status != 0 || server::g_reactor_accel.slot_close_after_tx[slot] {
            reactor_close_and_inc(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        }
        return;
    }
    guard res.request_context == net::REACTOR_REQ_RX_TAG else { return; }
    server::g_reactor_accel.slot_rx_inflight[slot] = false;
    if is_quarantined {
        if net::reactor_finalize_quarantined_slot(server::g_reactor_accel, slot) {
            free_reactor_conn_slot(slot_pool, slot);
        }
        return;
    }
    guard is_active_slot(table, slot) else { return; }
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
    guard slot >= 0 && slot < net::REACTOR_RIO_SLOTS else {
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
    let hs_rx_inflight = net_internal::native_rio_hs_is_rx_inflight() != 0;
    var hs_leftover: u8[4096] = [0; 4096];
    let hs_rem = net_internal::native_rio_hs_end(hs_leftover[..]);
    guard ok_hs else {
        if hs_rx_inflight {
            server::g_reactor_accel.slot_rx_inflight[slot] = true;
        }
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

fn reactor_release_finished_rio_quarantine(slot_pool: ReactorSlotPool&) {
    for q in net::REACTOR_RIO_SLOTS {
        if server::g_reactor_accel.slot_quarantined[q] &&
            net::reactor_finalize_quarantined_slot(server::g_reactor_accel, q) {
            free_reactor_conn_slot(slot_pool, q);
        }
    }
}

fn reactor_handle_corrupt_rio_cq(
    server:        server::HttpServer&,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot_pool:     ReactorSlotPool&,
    total_served:  i64&,
) {
    let epfd = server::g_reactor_accel.epfd;
    for s in net::REACTOR_RIO_SLOTS {
        if is_active_slot(table, s) && server::g_reactor_accel.slot_rio_rq[s] != 0 {
            server::g_reactor_accel.slot_rx_inflight[s] = false;
            server::g_reactor_accel.slot_tx_inflight[s] = false;
            reactor_close_and_inc(server, epfd, table, leftover_pool, s, slot_pool, total_served);
        } else if server::g_reactor_accel.slot_quarantined[s] {
            net::reactor_reset_accel_slot(server::g_reactor_accel, s);
            free_reactor_conn_slot(slot_pool, s);
        }
    }
    if server::g_reactor_accel.rio_buf_id != 0 {
        net_internal::native_rio_deregister_buffer(server::g_reactor_accel.rio_buf_id);
        server::g_reactor_accel.rio_buf_id = 0;
    }
    if server::g_reactor_accel.rio_cq != 0 {
        net_internal::native_rio_close_cq(server::g_reactor_accel.rio_cq);
        server::g_reactor_accel.rio_cq = 0;
    }
    if server::g_reactor_accel.rio_tx_cq != 0 {
        net_internal::native_rio_close_cq(server::g_reactor_accel.rio_tx_cq);
        server::g_reactor_accel.rio_tx_cq = 0;
    }
}

inline fn reactor_has_quarantined_rio_slot() -> bool {
    for q in net::REACTOR_RIO_SLOTS {
        if server::g_reactor_accel.slot_quarantined[q] {
            return true;
        }
    }
    return false;
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
    guard server::g_reactor_accel.active_accel_slots > 0 || reactor_has_quarantined_rio_slot() else {
        return 0;
    }
    let tx_n = net::reactor_drain_rio_tx_cq(server::g_reactor_accel);
    reactor_flush_rio_tx_closes(server, table, leftover_pool, slot_pool, total_served);
    reactor_release_finished_rio_quarantine(slot_pool);
    if tx_n < 0 {
        reactor_handle_corrupt_rio_cq(server, table, leftover_pool, slot_pool, total_served);
        return 0;
    }
    var rio_results: net_internal::RioResult[..64] = [];
    var n = net_internal::rio_drain_completions(server::g_reactor_accel.rio_cq, rio_results);
    if n == 0 && tx_n == 0 && timeout_ms > 0 && server::g_reactor_accel.active_accel_slots > 0 {
        let wait_rc = net_internal::rio_wait_cq(server::g_reactor_accel.rio_cq, min(timeout_ms, 5));
        if wait_rc < 0 {
            n = -1;
        } else {
            n = net_internal::rio_drain_completions(server::g_reactor_accel.rio_cq, rio_results);
        }
    }
    if n < 0 {
        reactor_handle_corrupt_rio_cq(server, table, leftover_pool, slot_pool, total_served);
        return 0;
    }
    for i in rio_results.len {
        reactor_dispatch_single_rio_result(
            server, rio_results[i], table, leftover_pool, slot_pool,
            timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
        );
    }
    if net::reactor_drain_rio_tx_cq(server::g_reactor_accel) < 0 {
        reactor_handle_corrupt_rio_cq(server, table, leftover_pool, slot_pool, total_served);
        return n as u32;
    }
    reactor_flush_rio_tx_closes(server, table, leftover_pool, slot_pool, total_served);
    reactor_release_finished_rio_quarantine(slot_pool);
    return n as u32;
}

inline fn reactor_dispatch_uring_tls_recv_cqe<Stage>(
    server:        server::HttpServer&,
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot:          i64,
    has_buf:       bool,
    bid:           u16,
    cqe_res:       i32,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    now_ns:        u64,
    chunk:         ReactorIngressBuf&,
    cork_wire:     u8[..65536]&,
    total_served:  i64&,
    stage:         Stage&,
) {
    let rx_tmp .= reactor_tls_rx_scratch();
    var copied: i32 = 0;
    if has_buf {
        copied = net_internal::uring_read_pbuf(server::g_reactor_accel.uring_pbuf, bid, cqe_res, rx_tmp[..]);
        net_internal::uring_recycle_pbuf(server::g_reactor_accel.uring_pbuf, bid);
    }
    if copied > 0 {
        reactor_handle_completed_rx(
            server, epfd, table, leftover_pool, slot, rx_tmp[..copied],
            slot_pool, timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
        );
    }
}

inline fn reactor_dispatch_uring_plain_recv_cqe<Stage>(
    server:        server::HttpServer&,
    epfd:          i64,
    table:         server::SoAConnTable&,
    leftover_pool: slice_pool<u8>&,
    slot:          i64,
    has_buf:       bool,
    bid:           u16,
    cqe_res:       i32,
    slot_pool:     ReactorSlotPool&,
    timer_wheel:   core::TickTimerWheel&,
    now_ns:        u64,
    chunk:         ReactorIngressBuf&,
    cork_wire:     u8[..65536]&,
    total_served:  i64&,
    stage:         Stage&,
) {
    let conn = table.fds[slot];
    guard conn > 0 else {
        if has_buf {
            net_internal::uring_recycle_pbuf(server::g_reactor_accel.uring_pbuf, bid);
        }
        return;
    }
    if server.pipeline.enable_slowloris_timer {
        table.soa_table_touch(slot, core::tick_timer_arm(timer_wheel, 15));
    }
    chunk.len = 0;
    reactor_load_leftover(table, leftover_pool, slot, chunk);
    if has_buf {
        let can_fit = chunk.len < REACTOR_INGRESS_CAP && chunk.len < chunk.bytes.len;
        if !can_fit {
            net_internal::uring_recycle_pbuf(server::g_reactor_accel.uring_pbuf, bid);
            reactor_close_and_inc(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
            return;
        }
        let copied = net_internal::uring_read_pbuf(
            server::g_reactor_accel.uring_pbuf, bid, cqe_res, chunk.bytes[chunk.len..REACTOR_INGRESS_CAP],
        );
        net_internal::uring_recycle_pbuf(server::g_reactor_accel.uring_pbuf, bid);
        if copied > 0 {
            chunk.len = core::add_sat_i64(chunk.len, copied);
        }
    }
    if chunk.len > 0 {
        reactor_process_slot_plaintext(
            server, epfd, table, leftover_pool, slot, conn, slot_pool, now_ns, chunk, cork_wire, total_served, stage,
        );
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
    let slot, ok_tok, is_quarantined = net::reactor_accel_match_any_token(
        server::g_reactor_accel, cqe.user_data,
    );
    guard ok_tok else {
        if has_buf {
            net_internal::uring_recycle_pbuf(server::g_reactor_accel.uring_pbuf, bid);
        }
        return;
    }
    if (cqe.flags & net_internal::URING_CQE_F_MORE) == 0 {
        server::g_reactor_accel.slot_rx_armed[slot] = false;
        server::g_reactor_accel.slot_rx_canceling[slot] = false;
    }
    if is_quarantined {
        if has_buf {
            net_internal::uring_recycle_pbuf(server::g_reactor_accel.uring_pbuf, bid);
        }
        if net::reactor_finalize_quarantined_slot(server::g_reactor_accel, slot) {
            free_reactor_conn_slot(slot_pool, slot);
        }
        return;
    }
    guard is_active_slot(table, slot) else {
        if has_buf {
            net_internal::uring_recycle_pbuf(server::g_reactor_accel.uring_pbuf, bid);
        }
        return;
    }
    let epfd = server::g_reactor_accel.epfd;
    if cqe.res == net_internal::URING_ERR_ENOBUFS || cqe.res == net_internal::URING_ERR_ECANCELED {
        if has_buf {
            net_internal::uring_recycle_pbuf(server::g_reactor_accel.uring_pbuf, bid);
        }
        if (cqe.flags & net_internal::URING_CQE_F_MORE) == 0 && !server::g_reactor_accel.slot_close_after_tx[slot] {
            net::reactor_arm_uring_slot_rx(server::g_reactor_accel, slot, table.fds[slot]);
        }
        return;
    }
    if cqe.res <= 0 {
        if has_buf {
            net_internal::uring_recycle_pbuf(server::g_reactor_accel.uring_pbuf, bid);
        }
        reactor_request_slot_close(server, epfd, table, leftover_pool, slot, slot_pool, total_served);
        return;
    }

    let is_tls = slot < table.has_tls.len
        && slot < table.tls_slots.len
        && table.has_tls[slot]
        && table.tls_slots[slot] != 0xFFFF;
    if is_tls {
        reactor_dispatch_uring_tls_recv_cqe(
            server, epfd, table, leftover_pool, slot, has_buf, bid, cqe.res,
            slot_pool, timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
        );
    } else {
        reactor_dispatch_uring_plain_recv_cqe(
            server, epfd, table, leftover_pool, slot, has_buf, bid, cqe.res,
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
    let slot, ok_tok, is_quarantined = net::reactor_accel_match_any_token(
        server::g_reactor_accel, cqe.user_data,
    );
    guard ok_tok else { return; }
    let is_notif = (cqe.flags & net_internal::URING_CQE_F_NOTIF) != 0;
    if is_notif {
        server::g_reactor_accel.slot_tx_notif_pending[slot] = false;
    } else {
        server::g_reactor_accel.slot_tx_inflight[slot] = false;
        if (cqe.flags & net_internal::URING_CQE_F_MORE) != 0 {
            server::g_reactor_accel.slot_tx_notif_pending[slot] = true;
        }
    }
    if is_quarantined {
        if net::reactor_finalize_quarantined_slot(server::g_reactor_accel, slot) {
            free_reactor_conn_slot(slot_pool, slot);
        }
        return;
    }
    guard is_active_slot(table, slot) else { return; }
    if is_notif {
        if server::g_reactor_accel.slot_close_after_tx[slot] &&
            !server::g_reactor_accel.slot_tx_inflight[slot] {
            reactor_close_and_inc(
                server, server::g_reactor_accel.epfd, table, leftover_pool, slot, slot_pool, total_served,
            );
        }
        return;
    }
    if (cqe.res <= 0 || server::g_reactor_accel.slot_close_after_tx[slot]) &&
        !server::g_reactor_accel.slot_tx_notif_pending[slot] {
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
    let slot, ok_tok, is_quarantined = net::reactor_accel_match_any_token(
        server::g_reactor_accel, cqe.user_data,
    );
    guard ok_tok else { return; }
    if (cqe.flags & net_internal::URING_CQE_F_MORE) == 0 {
        server::g_reactor_accel.slot_rx_armed[slot] = false;
        server::g_reactor_accel.slot_rx_canceling[slot] = false;
    }
    if is_quarantined {
        if net::reactor_finalize_quarantined_slot(server::g_reactor_accel, slot) {
            free_reactor_conn_slot(slot_pool, slot);
        }
        return;
    }
    guard is_active_slot(table, slot) else { return; }
    let epfd = server::g_reactor_accel.epfd;
    if cqe.res == net_internal::URING_ERR_ECANCELED {
        return;
    }
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
    } else if kind == net::REACTOR_URING_TAG_EPOLL {
        server::g_reactor_accel.uring_epoll_armed = false;
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
    net::reactor_arm_uring_epoll_poll(server::g_reactor_accel);
    let _ = net::reactor_stage_uring_sqes(server::g_reactor_accel);
    var cqes: net_internal::UringCqe[256] = [net_internal::UringCqe { .. }; 256];
    let min_c: u32 = if timeout_ms > 0 { 1 } else { 0 };
    let timeout_ns = net_internal::timeout_ms_to_ns(timeout_ms);
    let n = net_internal::uring_wait_cqes(server::g_reactor_accel.uring_fd, cqes[..], min_c, timeout_ns);
    guard n > 0 else { return 0; }
    let limit = min(n as i64, 256);
    for i in limit {
        reactor_dispatch_single_uring_cqe(
            server, listener_fd, draining, tls_config, is_tls, cqes[i], table,
            leftover_pool, slot_pool, timer_wheel, now_ns, chunk, cork_wire, total_served, stage,
        );
    }
    return n;
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
    return (core::add_sat_u64(hdr.header_len, hdr.payload_len) as i64) <= datagram.len;
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
    let end = core::add_sat_u64(hdr.header_len, hdr.payload_len) as i64;
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
        ip_seq = core::add_sat_u64(ip_seq, 1);
        let built = process_h3_l2_frame(server, ep, cfg.local_ep, rx_frame[..], pkt_id, now_ns, tx_frame);
        guard built && net_internal::af_xdp_umem_write(xsk, desc.addr, tx_frame[..]) else {
            let _ = net_internal::af_xdp_fill_push(xsk, desc.addr);
            continue;
        }
        let tx_desc = net_internal::XdpDesc { addr: desc.addr, len: tx_frame.len as u32, options: 0 };
        if net_internal::af_xdp_tx_submit(xsk, tx_desc) {
            served = core::add_sat_i64(served, 1);
        } else {
            let _ = net_internal::af_xdp_fill_push(xsk, desc.addr);
        }
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
