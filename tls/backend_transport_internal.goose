// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal socket-bridged transport adapter slots and fd handshake loops for TlsEndpoint.
namespace tls_internal;

import std;
import core;
import .types;
import .record;
import .backend;
import .backend_native_internal;
import .backend_pure_internal;
import .backend_pure_hs_internal;
import .handshake_io_server_internal;
import .session_internal;
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

fn pure_queue_endpoint_alert(ep: tls::TlsEndpoint&, alert: tls::Alert) {
    guard !ep.closed && ep.active_kind == tls::TlsBackendKind.PureGoose else { return; }
    let idx = ep.pure_slot as i64;
    guard idx >= 0 &&
        idx < g_pure_tls_slots.len &&
        is_live_pure_slot(g_pure_tls_slots[idx], ep.pure_gen) else {
        return;
    }
    pure_queue_fatal_alert(g_pure_tls_slots[idx], alert);
}

fn pure_open_blocking_client_endpoint(
    cfg:             const tls::ClientHandshakeConfig&,
    pre_cipher_slot: u16,
) -> tls::TlsEndpoint, bool {
    let idx, gen = alloc_pure_tls_slot();
    guard idx >= 0 else { return tls::TlsEndpoint { .. }, false; }
    let slot .= g_pure_tls_slots[idx as i64];
    slot.is_server = false;
    slot.cipher_slot = pre_cipher_slot;
    slot.stage = PureHsStage.ClientInit;
    slot.client_cfg = cfg;
    let _ = slot.server_name.try_set(cfg.server_name[..]);
    let _ = slot.alpn_csv.try_set(cfg.alpn[..]);
    let _ = slot.keylog_file.try_set(cfg.keylog_file[..]);
    return tls::TlsEndpoint {
        kind:        tls::TlsBackendKind.PureGoose,
        active_kind: tls::TlsBackendKind.PureGoose,
        is_server:   false,
        established: false,
        closed:      false,
        pure_slot:   idx,
        pure_gen:    gen,
        native_id:   -1,
    }, true;
}

fn pure_open_blocking_server_endpoint(
    cfg:             const tls::ServerHandshakeConfig&,
    ch_msg:          const u8[:],
    pre_cipher_slot: u16,
) -> tls::TlsEndpoint, bool {
    let idx, gen = alloc_pure_tls_slot();
    guard idx >= 0 else { return tls::TlsEndpoint { .. }, false; }
    let slot .= g_pure_tls_slots[idx as i64];
    slot.is_server = true;
    slot.defer_sni_credentials = false;
    slot.require_client_cert = cfg.require_client_cert;
    slot.psk_policy = ServerPskPolicy.AllowResumption;
    slot.cipher_slot = pre_cipher_slot;
    slot.stage = PureHsStage.ServerWaitClientHello;

    var committed = false;
    defer if !committed {
        slot.cipher_slot = 0xFFFF;
        reset_and_wipe_pure_slot(slot);
    };
    guard slot.cert_der.try_set(cfg.cert_der[..]) &&
        slot.alpn_csv.try_set(cfg.alpn[..]) &&
        slot.compressed_cert_data.try_set(cfg.compressed_cert_data[..]) &&
        slot.keylog_file.try_set(cfg.keylog_file[..]) else {
        return tls::TlsEndpoint { .. }, false;
    }
    if ch_msg.len > 0 {
        guard slot.pending_ch_msg.try_set(ch_msg) else { return tls::TlsEndpoint { .. }, false; }
    }
    slot.extra_certs_der = copy(cfg.extra_certs_der);
    slot.priv_seed = cfg.priv_seed;
    slot.key_kind = cfg.key_kind;
    slot.rsa_key_slot = cfg.rsa_key_slot;
    slot.rsa_key_gen = cfg.rsa_key_gen;
    slot.owns_rsa_key_slot = false;
    slot.compressed_cert_algo = cfg.compressed_cert_algo;
    slot.client_cfg.trust_store = cfg.client_trust_store;
    committed = true;
    return tls::TlsEndpoint {
        kind:        tls::TlsBackendKind.PureGoose,
        active_kind: tls::TlsBackendKind.PureGoose,
        is_server:   true,
        established: false,
        closed:      false,
        pure_slot:   idx,
        pure_gen:    gen,
        native_id:   -1,
    }, true;
}

recursive fn pure_blocking_drain_to_fd(fd: i64, ep: tls::TlsEndpoint&) -> bool {
    var wire: u8[16640] = [0; 16640];
    for _ in 64 {
        let n, st = tls::tls_endpoint_drain_wire(ep, wire[..]);
        guard st == tls::TlsBackendStatus.Ok else { return false; }
        if n <= 0 { return true; }
        guard n <= wire.len && tls_write_all(fd, wire[..n]) else { return false; }
    }
    return true;
}

recursive fn pure_blocking_feed_one_record(
    fd:         i64,
    ep:         tls::TlsEndpoint&,
    timeout_ms: u32,
) -> bool {
    var rec: u8[16645] = [0; 16645];
    guard tls_read_exact(fd, rec[..5], timeout_ms) else { return false; }
    let _, _, plen_u16, alert, ok_hdr = tls::parse_record_header(rec[..5]);
    guard ok_hdr else {
        if alert != tls::Alert.CloseNotify {
            pure_queue_endpoint_alert(ep, alert);
        }
        return false;
    }
    let plen = plen_u16 as i64;
    guard plen <= rfc::TLS_MAX_RECORD_CIPHERTEXT_LEN else {
        pure_queue_endpoint_alert(ep, tls::Alert.RecordOverflow);
        return false;
    }
    let total = core::add_sat_i64(5, plen);
    if plen > 0 {
        guard total <= rec.len && tls_read_exact(fd, rec[5..total], timeout_ms) else {
            return false;
        }
    }
    let fed, fst = tls::tls_endpoint_feed_wire(ep, rec[..total]);
    return fst == tls::TlsBackendStatus.Ok && fed == total;
}

recursive fn tls_drive_blocking_endpoint_handshake(
    fd:         i64,
    ep:         tls::TlsEndpoint&,
    timeout_ms: u32,
) -> bool {
    guard fd > 0 && !ep.closed else { return false; }
    for _ in 64 {
        let st = tls::tls_endpoint_step_handshake(ep);
        let flushed = pure_blocking_drain_to_fd(fd, ep);
        if st == tls::TlsBackendStatus.Ok || tls::tls_endpoint_is_established(ep) {
            return flushed;
        }
        if st == tls::TlsBackendStatus.WantWrite {
            guard flushed else { return false; }
            continue;
        }
        if st != tls::TlsBackendStatus.WantRead {
            return false;
        }
        guard flushed && pure_blocking_feed_one_record(fd, ep, timeout_ms) else {
            let _ = pure_blocking_drain_to_fd(fd, ep);
            return false;
        }
    }
    return false;
}
