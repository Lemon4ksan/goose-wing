// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal socket-bridged transport adapter slots and fd handshake loops for TlsEndpoint.
namespace tls_internal;

import std;
import core;
import .types;
import .backend;
import .backend_native_internal;
import .backend_pure_internal;
import .backend_pure_hs_internal;
import net.tcp;
import net.transport;

const MAX_BACKEND_TRANSPORT_SLOTS: i64 = 4096;

struct TlsBackendTransportSlot {
    in_use:     bool             = false,
    ep:         tls::TlsEndpoint = tls::TlsEndpoint { .. },
    rx_pending: u8[..16640]      = [],
    rx_pos:     i64              = 0,
}

var g_backend_transport_slots: TlsBackendTransportSlot[>..] = [];

var g_backend_transport_active: i64 = 0;

fn alloc_backend_transport_slot(ep: tls::TlsEndpoint) -> i64 {
    if g_backend_transport_active == g_backend_transport_slots.len {
        guard g_backend_transport_slots.len < MAX_BACKEND_TRANSPORT_SLOTS else { return -1; }
        let idx = g_backend_transport_slots.len;
        g_backend_transport_slots.push(TlsBackendTransportSlot { in_use: true, ep: ep, .. });
        g_backend_transport_active = core::add_sat_i64(g_backend_transport_active, 1);
        return idx;
    }
    for i in g_backend_transport_slots.len {
        let slot .= g_backend_transport_slots[i];
        if !slot.in_use {
            slot.ep = ep;
            slot.rx_pending.clear();
            slot.rx_pos = 0;
            slot.in_use = true;
            g_backend_transport_active = core::add_sat_i64(g_backend_transport_active, 1);
            return i;
        }
    }
    return -1;
}

fn release_backend_transport_slot(slot_id: i64) {
    guard slot_id >= 0 && slot_id < g_backend_transport_slots.len else { return; }
    let slot .= g_backend_transport_slots[slot_id];
    guard slot.in_use else { return; }
    tls::tls_endpoint_close(slot.ep);
    core::secure_zeroize_slice(slot.rx_pending[..]);
    slot.rx_pending.clear();
    slot.rx_pos = 0;
    slot.in_use = false;
    g_backend_transport_active = core::sub_sat_i64(g_backend_transport_active, 1);
}

recursive fn endpoint_fd_send_all(fd: i64, data: const u8[:]) -> bool {
    guard fd > 0 else { return false; }
    var off: i64 = 0;
    while off < data.len {
        let sent = net::fd_send(fd, data[off..]);
        guard sent > 0 else { return false; }
        off = core::add_sat_i64(off, sent);
    }
    return true;
}

recursive fn endpoint_drain_to_fd(ep: tls::TlsEndpoint&, fd: i64) -> bool {
    var wire: u8[16640] = [0; 16640];
    for _ in 64 {
        let n, st = tls::tls_endpoint_drain_wire(ep, wire[..]);
        guard st == tls::TlsBackendStatus.Ok else { return false; }
        if n <= 0 { return true; }
        guard n <= wire.len && endpoint_fd_send_all(fd, wire[..n]) else { return false; }
    }
    return true;
}

fn endpoint_feed_staged_rx(slot: TlsBackendTransportSlot&) -> i64, tls::TlsBackendStatus {
    let pos = slot.rx_pos;
    let total = slot.rx_pending.len;
    guard pos >= 0 && pos < total && total <= slot.rx_pending.cap else {
        slot.rx_pending.clear();
        slot.rx_pos = 0;
        return 0, tls::TlsBackendStatus.Ok;
    }
    let fed, fst = tls::tls_endpoint_feed_wire(slot.ep, slot.rx_pending[pos..total]);
    if fed > 0 {
        let next_pos = core::add_sat_i64(pos, fed);
        if next_pos >= total {
            slot.rx_pending.clear();
            slot.rx_pos = 0;
        } else {
            slot.rx_pos = next_pos;
        }
    }
    return fed, fst;
}

recursive fn endpoint_feed_slot_rx(slot: TlsBackendTransportSlot&, fd: i64, timeout_ms: u32) -> i32 {
    if slot.rx_pos < slot.rx_pending.len {
        let fed0, fst0 = endpoint_feed_staged_rx(slot);
        guard fst0 == tls::TlsBackendStatus.Ok || fst0 == tls::TlsBackendStatus.WantWrite else { return -1; }
        if fed0 > 0 || fst0 == tls::TlsBackendStatus.WantWrite { return 1; }
    }
    var rx: u8[16640] = [0; 16640];
    let recvd = net::fd_recv(fd, rx[..], timeout_ms);
    if recvd <= 0 { return recvd; }
    guard recvd <= rx.len else { return -1; }
    let fed, fst = tls::tls_endpoint_feed_wire(slot.ep, rx[..recvd]);
    guard fst == tls::TlsBackendStatus.Ok || fst == tls::TlsBackendStatus.WantWrite else { return -1; }
    if fed >= 0 && fed < recvd {
        let _ = slot.rx_pending.try_set(rx[fed..recvd]);
        slot.rx_pos = 0;
    }
    return 1;
}

inline fn endpoint_slot_is_ready(slot_id: i64) -> bool {
    guard slot_id >= 0 && slot_id < g_backend_transport_slots.len else { return false; }
    let slot .= g_backend_transport_slots[slot_id];
    return slot.in_use && !slot.ep.closed && tls::tls_endpoint_is_established(slot.ep);
}

fn endpoint_try_read_buffered(slot: TlsBackendTransportSlot&, fd: i64, dst: u8[:]) -> i64, tls::TlsBackendStatus {
    for _ in 4 {
        let nr, st = tls::tls_endpoint_read_app(slot.ep, dst);
        if nr > 0 { return nr, tls::TlsBackendStatus.Ok; }
        if st == tls::TlsBackendStatus.WantWrite {
            guard endpoint_drain_to_fd(slot.ep, fd) else { return 0, tls::TlsBackendStatus.Error; }
            continue;
        }
        if st != tls::TlsBackendStatus.WantRead { return 0, st; }
        if slot.rx_pos < slot.rx_pending.len {
            let _, fst = endpoint_feed_staged_rx(slot);
            guard fst == tls::TlsBackendStatus.Ok || fst == tls::TlsBackendStatus.WantWrite else {
                return 0, fst;
            }
        }
    }
    return 0, tls::TlsBackendStatus.WantRead;
}

fn endpoint_run_handshake_fd(
    fd:         i64,
    cfg:        const tls::TlsBackendConfig&,
    is_server:  bool,
    timeout_ms: u32,
) -> i64, u8[..64], tls::TlsBackendStatus {
    var alpn: u8[..64] = [];
    guard fd > 0 else { return -1, alpn, tls::TlsBackendStatus.Error; }
    var ep, open_st = open_endpoint_with_role(cfg, is_server);
    guard open_st == tls::TlsBackendStatus.Ok else { return -1, alpn, open_st; }

    let slot_id = alloc_backend_transport_slot(ep);
    guard slot_id >= 0 else {
        tls::tls_endpoint_close(ep);
        return -1, alpn, tls::TlsBackendStatus.Error;
    }
    var committed = false;
    defer if !committed { release_backend_transport_slot(slot_id); };

    let slot .= g_backend_transport_slots[slot_id];
    for _ in 64 {
        let st = tls::tls_endpoint_step_handshake(slot.ep);
        let flushed = endpoint_drain_to_fd(slot.ep, fd);
        if st == tls::TlsBackendStatus.Ok {
            guard flushed else { return -1, alpn, tls::TlsBackendStatus.Error; }
            alpn = tls::tls_endpoint_selected_alpn(slot.ep);
            committed = true;
            return slot_id, alpn, tls::TlsBackendStatus.Ok;
        }
        guard flushed else { return -1, alpn, tls::TlsBackendStatus.Error; }
        if st == tls::TlsBackendStatus.WantWrite { continue; }
        guard st == tls::TlsBackendStatus.WantRead else { return -1, alpn, st; }
        let fed = endpoint_feed_slot_rx(slot, fd, timeout_ms);
        guard fed > 0 else { return -1, alpn, tls::TlsBackendStatus.HandshakeError; }
    }
    return -1, alpn, tls::TlsBackendStatus.HandshakeError;
}
