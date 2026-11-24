// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Sans-IO multi-client QUIC server endpoint with DCID demultiplexing, RFC 9001 TLS CRYPTO
// handshake, deferred SNI credentials, flow-controlled bidirectional/unidirectional streams,
// 3x anti-amplification, and RFC 9002 PTO/loss recovery (RFC 9000, RFC 9001, RFC 9002).
namespace quic;

import std;
import core;
import rfc.h3_quic;
import .packet;
import .packet_internal;
import .frames;
import .frames_internal;
import .stream;
import .flow_control;
import .AckFrame;
import .bbr;
import .internal;
import .conn_internal;
import .conn_crypto_internal;
import .connection;
import tls.types;
import tls.record;
import tls.quic_handshake;

// ---- Public Endpoint Limits & Constants ------------------------------------

const QUIC_SRV_CID_LEN:           i64 = 8;
const QUIC_SRV_SHORT_PKT_MIN_LEN: i64 = 9;
const QUIC_SRV_MAX_ENDPOINTS:     i64 = 256;
const QUIC_SRV_MAX_CONNS_CAP:     i32 = 1024;
const QUIC_SRV_DEFAULT_WINDOW:    u64 = 65536;
const QUIC_SRV_MAX_STREAM_TX_BUF: u64 = 262144;
const QUIC_SRV_SLAB_BYTES:        u64 = 4096;
const QUIC_SRV_SLAB_SHIFT:        u64 = 12;
const QUIC_SRV_SLAB_MASK:         u64 = 4095;
const QUIC_SRV_MAX_DGRAM_OUT:     u64 = 1280;
const QUIC_CRYPTO_ERROR_BASE:     u64 = 0x0100; // RFC 9000 Section 20.1

// ---- Public Event & Handle Types -------------------------------------------

enum QuicServerEventKind {
    None,
    NeedSniCredentials,
    HandshakeComplete,
    StreamReadable,
    StreamReset,
    ConnectionClosed,
}

struct QuicServerEvent {
    kind:       QuicServerEventKind = QuicServerEventKind.None,
    conn_id:    u64                 = 0,
    stream_id:  u64                 = 0,
    sni:        u8[..255]           = [],
    error_code: u64                 = 0,
}

struct QuicServerEndpoint {
    slot_idx:   i64 = -1,
    generation: u64 = 0,
}

// ---- Thread-Local Pools & Internal State -----------------------------------

enum QuicSentChunkKind {
    CryptoInitial,
    CryptoHandshake,
    HandshakeDone,
    NewConnectionId,
    StreamData,
    MaxData,
    MaxStreamData,
}

struct QuicSentChunk {
    active:     bool              = false,
    in_flight:  bool              = false,
    retransmit: bool              = false,
    space:      PnSpaceId         = PnSpaceId.Initial,
    pn:         u64               = 0,
    kind:       QuicSentChunkKind = QuicSentChunkKind.CryptoInitial,
    stream_id:  u64               = 0,
    offset:     u64               = 0,
    length:     u64               = 0,
    fin:        bool              = false,
    val:        u64               = 0,
}

struct QuicSrvEventNode {
    active:     bool                = false,
    kind:       QuicServerEventKind = QuicServerEventKind.None,
    conn_id:    u64                 = 0,
    stream_id:  u64                 = 0,
    sni:        u8[..255]           = [],
    error_code: u64                 = 0,
    next_idx:   i64                 = -1,
}

struct QuicSrvEndpointSlot {
    active:          bool      = false,
    generation:      u64       = 0,
    max_conns:       i32       = 256,
    active_conns:    u32       = 0,
    idle_timeout_ms: u64       = 30000,
    alpn_wire:       u8[..255] = [],
    ev_head:         i64       = -1,
    ev_tail:         i64       = -1,
    tx_rr_cursor:    i64       = 0,
}

struct QuicSrvSlab {
    active:   bool     = false,
    next_idx: i64      = -1,
    data:     u8[4096] = [0; 4096],
}

struct QuicSrvStreamRxSlot {
    active:             bool           = false,
    conn_idx:           i64            = -1,
    conn_id:            u64            = 0,
    stream_id:          u64            = 0,
    rx_base_offset:     u64            = 0,
    rx_contiguous_end:  u64            = 0,
    rx_final_size:      u64            = 0,
    rx_fin_received:    bool           = false,
    rx_fin_delivered:   bool           = false,
    rx_reset_received:  bool           = false,
    rx_reset_delivered: bool           = false,
    rx_reset_error:     u64            = 0,
    rx_readable_queued: bool           = false,
    need_max_sd_tx:     bool           = false,
    max_sd_tx_val:      u64            = 0,
    rx_intervals:       Interval[..64] = [],
    rx_head_off:        u64            = 0,
    rx_buf_len:         u64            = 0,
    rx_slabs:           i64[..66]      = [],
}

struct QuicSrvStreamTxSlot {
    active:          bool      = false,
    tx_unacked_base: u64       = 0,
    tx_next_offset:  u64       = 0,
    tx_fin_queued:   bool      = false,
    tx_fin_sent:     bool      = false,
    tx_fin_acked:    bool      = false,
    tx_head_off:     u64       = 0,
    tx_buf_len:      u64       = 0,
    tx_slabs:        i64[..66] = [],
}

struct QuicSrvConnSlot {
    active:                      bool                 = false,
    ep_idx:                      i64                  = -1,
    ep_gen:                      u64                  = 0,
    conn_id:                     u64                  = 0,
    conn:                        QuicConnection       = QuicConnection { .. },
    tls_srv:                     tls::QuicTlsServer   = tls::QuicTlsServer { .. },
    peer_ip:                     u8[..64]             = [],
    peer_port:                   u16                  = 0,
    peer_tp_applied:             bool                 = false,
    need_sni_creds:              bool                 = false,
    sni_event_emitted:           bool                 = false,
    hs_complete_emitted:         bool                 = false,
    close_event_emitted:         bool                 = false,
    handshake_done_queued:       bool                 = false,
    new_cid_queued:              bool                 = false,
    init_keys_discarded:         bool                 = false,
    hs_keys_discarded:           bool                 = false,
    pending_close_tx:            bool                 = false,
    close_is_app:                bool                 = false,
    close_error:                 u64                  = 0,
    close_reason:                u8[..128]            = [],
    needs_ack_initial:           bool                 = false,
    needs_ack_hs:                bool                 = false,
    needs_ack_app:               bool                 = false,
    has_path_resp:               bool                 = false,
    pending_path_resp:           u8[8]                = [0; 8],
    ping_probe_pending:          bool                 = false,
    ping_probe_space:            PnSpaceId            = PnSpaceId.Initial,
    next_tx_pn_init:             u64                  = 0,
    next_tx_pn_hs:               u64                  = 0,
    next_tx_pn_app:              u64                  = 0,
    pto_count:                   u32                  = 0,
    idle_timeout_ms:             u64                  = 30000,
    last_activity_ns:            u64                  = 0,
    ack_eliciting_sent_since_rx: bool                 = false,
    drain_deadline_ns:           u64                  = 0,
    peer_init_sd_bidi_local:     u64                  = 0,
    peer_init_sd_bidi_remote:    u64                  = 0,
    peer_init_sd_uni:            u64                  = 0,
    peer_max_udp_payload:        u64                  = 1200,
    peer_active_cid_limit:       u64                  = 2,
    need_max_data_tx:            bool                 = false,
    max_data_tx_val:             u64                  = 0,
    tx_init_crypto:              u8[..4096]           = [],
    tx_init_crypto_sent:         u64                  = 0,
    tx_hs_crypto:                u8[..24576]          = [],
    tx_hs_crypto_sent:           u64                  = 0,
    sent_chunks:                 QuicSentChunk[..128] = [],
    alt_cid:                     u8[..20]             = [],
    alt_reset_token:             u8[16]               = [0; 16],
}

var g_quic_srv_endpoints:    QuicSrvEndpointSlot[>..] = [];
var g_quic_srv_ep_next_gen:  u64                      = 0;
var g_quic_srv_conns:        QuicSrvConnSlot[>..]     = [];
var g_quic_srv_next_conn_id: u64                      = 0;
var g_quic_srv_events:       QuicSrvEventNode[>..]    = [];
var g_quic_srv_free_ev:      i64                      = -1;
var g_quic_srv_stream_rx:    QuicSrvStreamRxSlot[>..] = [];
var g_quic_srv_stream_tx:    QuicSrvStreamTxSlot[>..] = [];
var g_quic_srv_slabs:        QuicSrvSlab[>..]         = [];
var g_quic_srv_free_slab:    i64                      = -1;

// ---- Generation & Arena Lookup Helpers -------------------------------------

fn next_srv_gen(counter: u64&) -> u64 {
    counter = counter + 1;
    if counter == 0 {
        counter = 1;
    }
    return counter;
}

fn lookup_live_ep_idx(ep: const QuicServerEndpoint&) -> i64 {
    guard ep.generation != 0 && ep.slot_idx >= 0 && ep.slot_idx < g_quic_srv_endpoints.len else {
        return -1;
    }
    let eslot .= g_quic_srv_endpoints[ep.slot_idx];
    guard eslot.active && eslot.generation == ep.generation else { return -1; }
    return ep.slot_idx;
}

fn find_conn_idx_by_id(ep_idx: i64, ep_gen: u64, conn_id: u64) -> i64 {
    guard conn_id != 0 else { return -1; }
    for i in g_quic_srv_conns.len {
        let cslot .= g_quic_srv_conns[i];
        if cslot.active && cslot.ep_idx == ep_idx && cslot.ep_gen == ep_gen && cslot.conn_id == conn_id {
            return i;
        }
    }
    return -1;
}

fn alloc_srv_event_node() -> i64 {
    if g_quic_srv_free_ev >= 0 {
        let idx = g_quic_srv_free_ev;
        g_quic_srv_free_ev = g_quic_srv_events[idx].next_idx;
        g_quic_srv_events[idx] = QuicSrvEventNode { active: true, .. };
        return idx;
    }
    let idx = g_quic_srv_events.len;
    g_quic_srv_events.push(QuicSrvEventNode { active: true, .. });
    return idx;
}

fn free_srv_event_node(ev_idx: i64) {
    guard ev_idx >= 0 && ev_idx < g_quic_srv_events.len else { return; }
    g_quic_srv_events[ev_idx] = QuicSrvEventNode { next_idx: g_quic_srv_free_ev, .. };
    g_quic_srv_free_ev = ev_idx;
}

fn clear_ep_event_queue(eslot: QuicSrvEndpointSlot&) {
    var cur = eslot.ev_head;
    while cur >= 0 {
        let nxt = g_quic_srv_events[cur].next_idx;
        free_srv_event_node(cur);
        cur = nxt;
    }
    eslot.ev_head = -1;
    eslot.ev_tail = -1;
}

fn enqueue_srv_event(
    eslot:      QuicSrvEndpointSlot&,
    kind:       QuicServerEventKind,
    conn_id:    u64,
    stream_id:  u64,
    sni:        const u8[:],
    error_code: u64,
) {
    let ev_idx = alloc_srv_event_node();
    let node .= g_quic_srv_events[ev_idx];
    node.kind = kind;
    node.conn_id = conn_id;
    node.stream_id = stream_id;
    node.error_code = error_code;
    if sni.len > 0 {
        let _ = node.sni.try_set(sni[..min(sni.len, node.sni.cap)]);
    }
    node.next_idx = -1;
    if eslot.ev_tail >= 0 {
        g_quic_srv_events[eslot.ev_tail].next_idx = ev_idx;
    } else {
        eslot.ev_head = ev_idx;
    }
    eslot.ev_tail = ev_idx;
}

// ---- Slab Pool & Stream Slot Lifecycle -------------------------------------

fn alloc_srv_slab() -> i64 {
    if g_quic_srv_free_slab >= 0 {
        let idx = g_quic_srv_free_slab;
        let slab .= g_quic_srv_slabs[idx];
        g_quic_srv_free_slab = slab.next_idx;
        slab.active = true;
        slab.next_idx = -1;
        return idx;
    }
    let idx = g_quic_srv_slabs.len;
    g_quic_srv_slabs.push(QuicSrvSlab { active: true, .. });
    return idx;
}

fn free_srv_slab(idx: i64) {
    guard idx >= 0 && idx < g_quic_srv_slabs.len else { return; }
    let slab .= g_quic_srv_slabs[idx];
    core::secure_zeroize_slice(slab.data[..]);
    slab.active = false;
    slab.next_idx = g_quic_srv_free_slab;
    g_quic_srv_free_slab = idx;
}

fn slab_free_all(slabs: i64[..66]&, head_off: u64&, buf_len: u64&) {
    for k in slabs.len {
        free_srv_slab(slabs[k]);
    }
    slabs.clear();
    head_off = 0;
    buf_len = 0;
}

fn slab_write_at(
    slabs:    i64[..66]&,
    head_off: u64,
    buf_len:  u64&,
    rel_off:  u64,
    src:      const u8[:],
) -> bool {
    let src_len = src.len as u64;
    let end_rel = core::add_sat_u64(rel_off, src_len);
    let needed_abs = core::add_sat_u64(head_off, end_rel);
    let needed_slabs = if needed_abs == 0 {
        0
    } else {
        core::add_sat_u64(needed_abs, QUIC_SRV_SLAB_MASK) >> QUIC_SRV_SLAB_SHIFT
    };
    guard needed_slabs <= (slabs.cap as u64) else { return false; }
    while (slabs.len as u64) < needed_slabs {
        let sid = alloc_srv_slab();
        guard slabs.try_push(sid) else {
            free_srv_slab(sid);
            return false;
        }
    }
    var src_pos: u64 = 0;
    while src_pos < src_len {
        let abs_pos = core::add_sat_u64(head_off, core::add_sat_u64(rel_off, src_pos));
        let si = (abs_pos >> QUIC_SRV_SLAB_SHIFT) as i64;
        let in_off = abs_pos & QUIC_SRV_SLAB_MASK;
        let chunk = min(core::sub_sat_u64(src_len, src_pos), core::sub_sat_u64(QUIC_SRV_SLAB_BYTES, in_off));
        let slab .= g_quic_srv_slabs[slabs[si]];
        for k in (chunk as i64) {
            slab.data[core::add_sat_u64(in_off, k as u64) as i64] = src[core::add_sat_u64(src_pos, k as u64) as i64];
        }
        src_pos = core::add_sat_u64(src_pos, chunk);
    }
    if end_rel > buf_len {
        buf_len = end_rel;
    }
    return true;
}

fn slab_read_to_out(
    slabs:    const i64[..66]&,
    head_off: u64,
    buf_len:  u64,
    rel_off:  u64,
    count:    u64,
    out:      u8[>..]&,
) -> bool {
    guard core::add_sat_u64(rel_off, count) <= buf_len else { return false; }
    var pos: u64 = 0;
    while pos < count {
        let abs_pos = core::add_sat_u64(head_off, core::add_sat_u64(rel_off, pos));
        let si = (abs_pos >> QUIC_SRV_SLAB_SHIFT) as i64;
        let in_off = abs_pos & QUIC_SRV_SLAB_MASK;
        let chunk = min(core::sub_sat_u64(count, pos), core::sub_sat_u64(QUIC_SRV_SLAB_BYTES, in_off));
        let end_off = core::add_sat_u64(in_off, chunk);
        let slab .= g_quic_srv_slabs[slabs[si]];
        out.append(slab.data[(in_off as i64)..(end_off as i64)]);
        pos = core::add_sat_u64(pos, chunk);
    }
    return true;
}

fn slab_copy_slice(
    slabs:    const i64[..66]&,
    head_off: u64,
    buf_len:  u64,
    rel_off:  u64,
    count:    u64,
    out:      u8[..1500]&,
) -> bool {
    out.clear();
    guard core::add_sat_u64(rel_off, count) <= buf_len && count <= (out.cap as u64) else {
        return false;
    }
    var pos: u64 = 0;
    while pos < count {
        let abs_pos = core::add_sat_u64(head_off, core::add_sat_u64(rel_off, pos));
        let si = (abs_pos >> QUIC_SRV_SLAB_SHIFT) as i64;
        let in_off = abs_pos & QUIC_SRV_SLAB_MASK;
        let chunk = min(core::sub_sat_u64(count, pos), core::sub_sat_u64(QUIC_SRV_SLAB_BYTES, in_off));
        let end_off = core::add_sat_u64(in_off, chunk);
        let slab .= g_quic_srv_slabs[slabs[si]];
        guard out.try_append(slab.data[(in_off as i64)..(end_off as i64)]) else {
            out.clear();
            return false;
        }
        pos = core::add_sat_u64(pos, chunk);
    }
    return true;
}

fn slab_consume_front(slabs: i64[..66]&, head_off: u64&, buf_len: u64&, drop_n: u64) {
    guard drop_n > 0 else { return; }
    if drop_n >= buf_len {
        slab_free_all(slabs, head_off, buf_len);
        return;
    }
    let new_abs = core::add_sat_u64(head_off, drop_n);
    let drop_slabs = new_abs >> QUIC_SRV_SLAB_SHIFT;
    if drop_slabs > 0 {
        for k in (drop_slabs as i64) {
            free_srv_slab(slabs[k]);
        }
        let rem_slabs = core::sub_sat_u64(slabs.len as u64, drop_slabs);
        for k in (rem_slabs as i64) {
            slabs[k] = slabs[core::add_sat_u64(k as u64, drop_slabs) as i64];
        }
        slabs.resize(rem_slabs as i64);
    }
    head_off = new_abs & QUIC_SRV_SLAB_MASK;
    buf_len = core::sub_sat_u64(buf_len, drop_n);
}

fn find_or_alloc_stream_slot(conn_idx: i64, conn_id: u64, stream_id: u64, create: bool) -> i64 {
    var free_idx: i64 = -1;
    for i in g_quic_srv_stream_rx.len {
        let rx .= g_quic_srv_stream_rx[i];
        if !rx.active {
            if free_idx < 0 { free_idx = i; }
            continue;
        }
        if rx.conn_idx == conn_idx && rx.conn_id == conn_id && rx.stream_id == stream_id {
            return i;
        }
    }
    guard create else { return -1; }
    if free_idx < 0 {
        free_idx = g_quic_srv_stream_rx.len;
        g_quic_srv_stream_rx.push(QuicSrvStreamRxSlot { .. });
        g_quic_srv_stream_tx.push(QuicSrvStreamTxSlot { .. });
    }
    let rx .= g_quic_srv_stream_rx[free_idx];
    let tx .= g_quic_srv_stream_tx[free_idx];
    rx = QuicSrvStreamRxSlot {
        active:    true,
        conn_idx:  conn_idx,
        conn_id:   conn_id,
        stream_id: stream_id,
        ..
    };
    tx = QuicSrvStreamTxSlot { active: true, .. };
    return free_idx;
}

fn free_conn_stream_slots(conn_idx: i64, conn_id: u64) {
    for i in g_quic_srv_stream_rx.len {
        let rx .= g_quic_srv_stream_rx[i];
        let tx .= g_quic_srv_stream_tx[i];
        if rx.active && rx.conn_idx == conn_idx && rx.conn_id == conn_id {
            slab_free_all(rx.rx_slabs, rx.rx_head_off, rx.rx_buf_len);
            slab_free_all(tx.tx_slabs, tx.tx_head_off, tx.tx_buf_len);
            rx.active = false;
            tx.active = false;
            rx.conn_idx = -1;
            rx.conn_id = 0;
            rx.rx_intervals.clear();
        }
    }
}

fn zeroize_and_free_conn_slot(c_idx: i64) {
    let cslot .= g_quic_srv_conns[c_idx];
    guard cslot.active else { return; }
    let eslot .= g_quic_srv_endpoints[cslot.ep_idx];
    if eslot.active && eslot.generation == cslot.ep_gen && eslot.active_conns > 0 {
        eslot.active_conns = core::sub_sat_u32(eslot.active_conns, 1);
    }
    free_conn_stream_slots(c_idx, cslot.conn_id);
    tls::quic_tls_server_close(cslot.tls_srv);
    zeroize_connection_secrets(cslot.conn);
    core::secure_zeroize_slice(cslot.tx_init_crypto[..]);
    core::secure_zeroize_slice(cslot.tx_hs_crypto[..]);
    core::secure_zeroize_16(cslot.alt_reset_token);
    cslot.tx_init_crypto.clear();
    cslot.tx_hs_crypto.clear();
    cslot.sent_chunks.clear();
    cslot.conn = QuicConnection { .. };
    cslot.active = false;
    cslot.ep_idx = -1;
    cslot.ep_gen = 0;
    cslot.conn_id = 0;
}

// ---- Connection Slot Initialization & CID Demuxing -------------------------

fn cid_matches_conn(cslot: const QuicSrvConnSlot&, cid: const u8[:], is_initial: bool) -> bool {
    if cid.len > 0 && core::ct_eq_bytes(cid, cslot.conn.scid[..]) {
        return true;
    }
    if cid.len == 0 && cslot.conn.scid.len == 0 {
        return true;
    }
    for i in cslot.conn.alt_scids.len {
        if cslot.conn.alt_scids[i].len > 0 && core::ct_eq_bytes(cid, cslot.conn.alt_scids[i][..]) {
            return true;
        }
    }
    if is_initial && cslot.conn.original_dcid.len > 0 && core::ct_eq_bytes(cid, cslot.conn.original_dcid[..]) {
        return true;
    }
    return false;
}

fn find_conn_by_dcid(ep_idx: i64, ep_gen: u64, cid: const u8[:], is_initial: bool) -> i64 {
    for i in g_quic_srv_conns.len {
        let cslot .= g_quic_srv_conns[i];
        if cslot.active && cslot.ep_idx == ep_idx && cslot.ep_gen == ep_gen {
            if cid_matches_conn(cslot, cid, is_initial) {
                return i;
            }
        }
    }
    return -1;
}

fn generate_unique_server_cid(ep_idx: i64, ep_gen: u64, out_cid: u8[..20]&) -> bool {
    out_cid.clear();
    var buf: u8[8] = [0; 8];
    for _ in 16 {
        guard core::csprng_fill(buf[..]) else { return false; }
        if find_conn_by_dcid(ep_idx, ep_gen, buf[..], true) < 0 {
            return out_cid.try_set(buf[..]);
        }
    }
    return false;
}

fn init_conn_inplace(conn: QuicConnection&, scid: const u8[:], version: u32) {
    conn = QuicConnection {
        role:              QuicRole.Server,
        state:             QuicConnState.Initial,
        version:           version,
        stream_table:      new_stream_table(QuicRole.Server),
        flow_ctrl:         new_flow_control(QUIC_SRV_DEFAULT_WINDOW, QUIC_SRV_DEFAULT_WINDOW),
        validated_address: false,
        ..
    };
    conn.pacer = conn.bbr.pacer;
    let _ = conn.scid.try_set(scid[..min(scid.len, conn.scid.cap)]);
}

fn build_server_local_tp(
    odcid:           const u8[:],
    iscid:           const u8[:],
    idle_timeout_ms: u64,
    reset_token:     const u8[16]&,
    out_tp:          u8[..2048]&,
) -> bool {
    out_tp.clear();
    var tp = QuicTransportParams {
        max_idle_timeout:                    idle_timeout_ms,
        stateless_reset_token:               reset_token,
        has_stateless_reset_token:           true,
        max_udp_payload_size:                1500,
        initial_max_data:                    QUIC_SRV_DEFAULT_WINDOW,
        initial_max_stream_data_bidi_local:  QUIC_SRV_DEFAULT_WINDOW,
        initial_max_stream_data_bidi_remote: QUIC_SRV_DEFAULT_WINDOW,
        initial_max_stream_data_uni:         QUIC_SRV_DEFAULT_WINDOW,
        initial_max_streams_bidi:            100,
        initial_max_streams_uni:             100,
        active_connection_id_limit:          4,
        ..
    };
    guard tp.original_destination_connection_id.try_set(odcid)
        && tp.initial_source_connection_id.try_set(iscid) else {
        return false;
    }
    return encode_transport_params(tp, true, out_tp);
}

fn reset_conn_slot_for_initial(
    c_idx:     i64,
    ep_idx:    i64,
    hdr:       const QuicHeader&,
    peer_ip:   const u8[:],
    peer_port: u16,
    now_ns:    u64,
) -> bool {
    let eslot .= g_quic_srv_endpoints[ep_idx];
    var scid:      u8[..20] = [];
    var reset_tok: u8[16]   = [0; 16];
    guard generate_unique_server_cid(ep_idx, eslot.generation, scid) && core::csprng_fill(reset_tok[..]) else {
        return false;
    }
    var local_tp: u8[..2048] = [];
    guard build_server_local_tp(hdr.dcid[..], scid[..], eslot.idle_timeout_ms, reset_tok, local_tp) else {
        return false;
    }
    let tls_srv = tls::quic_tls_server_open(eslot.alpn_wire[..], local_tp[..], true);
    guard tls_srv.generation != 0 else { return false; }

    let cslot .= g_quic_srv_conns[c_idx];
    cslot.active = true;
    cslot.ep_idx = ep_idx;
    cslot.ep_gen = eslot.generation;
    cslot.conn_id = next_srv_gen(g_quic_srv_next_conn_id);
    init_conn_inplace(cslot.conn, scid[..], hdr.version);
    cslot.tls_srv = tls_srv;
    guard cslot.peer_ip.try_set(peer_ip) && install_initial_keys(cslot.conn, hdr.dcid[..], hdr.version) else {
        zeroize_and_free_conn_slot(c_idx);
        return false;
    }
    cslot.peer_port = peer_port;
    cslot.peer_tp_applied = false;
    cslot.need_sni_creds = false;
    cslot.sni_event_emitted = false;
    cslot.hs_complete_emitted = false;
    cslot.close_event_emitted = false;
    cslot.handshake_done_queued = false;
    cslot.new_cid_queued = false;
    cslot.init_keys_discarded = false;
    cslot.hs_keys_discarded = false;
    cslot.pending_close_tx = false;
    cslot.close_is_app = false;
    cslot.close_error = 0;
    cslot.close_reason.clear();
    cslot.needs_ack_initial = false;
    cslot.needs_ack_hs = false;
    cslot.needs_ack_app = false;
    cslot.has_path_resp = false;
    cslot.ping_probe_pending = false;
    cslot.next_tx_pn_init = 0;
    cslot.next_tx_pn_hs = 0;
    cslot.next_tx_pn_app = 0;
    cslot.pto_count = 0;
    cslot.idle_timeout_ms = eslot.idle_timeout_ms;
    cslot.last_activity_ns = now_ns;
    cslot.ack_eliciting_sent_since_rx = false;
    cslot.drain_deadline_ns = 0;
    cslot.need_max_data_tx = false;
    cslot.tx_init_crypto.clear();
    cslot.tx_init_crypto_sent = 0;
    cslot.tx_hs_crypto.clear();
    cslot.tx_hs_crypto_sent = 0;
    cslot.sent_chunks.clear();
    cslot.alt_cid.clear();
    eslot.active_conns = core::add_sat_u32(eslot.active_conns, 1);
    return true;
}

fn accept_new_initial_conn(
    ep_idx:    i64,
    pkt:       const u8[:],
    hdr:       const QuicHeader&,
    peer_ip:   const u8[:],
    peer_port: u16,
    now_ns:    u64,
) -> i64 {
    let eslot .= g_quic_srv_endpoints[ep_idx];
    // RFC 9000 Section 14.1: Initial Datagram Size - Discard unvalidated Initial datagrams < 1200 bytes.
    guard pkt.len >= (rfc::QUIC_MIN_INITIAL_DATAGRAM_LEN as i64) else { return -1; }
    guard hdr.dcid.len >= QUIC_SRV_CID_LEN && eslot.active_conns < (eslot.max_conns as u32) else { return -1; }

    var c_idx: i64 = -1;
    for i in g_quic_srv_conns.len {
        if !g_quic_srv_conns[i].active {
            c_idx = i;
            break;
        }
    }
    if c_idx < 0 {
        c_idx = g_quic_srv_conns.len;
        g_quic_srv_conns.push(QuicSrvConnSlot { .. });
    }
    guard reset_conn_slot_for_initial(c_idx, ep_idx, hdr, peer_ip, peer_port, now_ns) else {
        return -1;
    }
    return c_idx;
}

// ---- Sent Chunk Tracking, ACK Retirement & Loss Detection ------------------

fn track_tx_chunk(
    cslot:     QuicSrvConnSlot&,
    space:     PnSpaceId,
    pn:        u64,
    kind:      QuicSentChunkKind,
    stream_id: u64,
    offset:    u64,
    length:    u64,
    fin:       bool,
    val:       u64,
) {
    let chunk = QuicSentChunk {
        active:     true,
        in_flight:  true,
        retransmit: false,
        space:      space,
        pn:         pn,
        kind:       kind,
        stream_id:  stream_id,
        offset:     offset,
        length:     length,
        fin:        fin,
        val:        val,
    };
    for i in cslot.sent_chunks.len {
        if !cslot.sent_chunks[i].active {
            cslot.sent_chunks[i] = chunk;
            return;
        }
    }
    let _ = cslot.sent_chunks.try_push(chunk);
}

fn retire_space_chunks(cslot: QuicSrvConnSlot&, space_id: PnSpaceId) {
    for i in cslot.sent_chunks.len {
        if cslot.sent_chunks[i].active && cslot.sent_chunks[i].space == space_id {
            cslot.sent_chunks[i].active = false;
        }
    }
}

fn is_pn_in_ack_ranges(ranges: const AckInterval[..65]&, pn: u64) -> bool {
    for i in ranges.len {
        if pn >= ranges[i].smallest && pn <= ranges[i].largest {
            return true;
        }
    }
    return false;
}

fn is_pn_in_sent_packets(space: const PnSpaceState&, pn: u64) -> bool {
    for i in space.sent_packets.len {
        if space.sent_packets[i].pn == pn {
            return true;
        }
    }
    return false;
}

fn compact_stream_tx_buffer(cslot: QuicSrvConnSlot&, c_idx: i64, stream_id: u64) {
    let s_slot = find_or_alloc_stream_slot(c_idx, cslot.conn_id, stream_id, false);
    guard s_slot >= 0 else { return; }
    let tx .= g_quic_srv_stream_tx[s_slot];
    var min_unacked = tx.tx_next_offset;
    for i in cslot.sent_chunks.len {
        let ch .= cslot.sent_chunks[i];
        if ch.active && ch.kind == QuicSentChunkKind.StreamData && ch.stream_id == stream_id {
            if ch.offset < min_unacked {
                min_unacked = ch.offset;
            }
        }
    }
    if min_unacked > tx.tx_unacked_base {
        let drop_n = core::sub_sat_u64(min_unacked, tx.tx_unacked_base);
        slab_consume_front(tx.tx_slabs, tx.tx_head_off, tx.tx_buf_len, drop_n);
        tx.tx_unacked_base = min_unacked;
    }
    if tx.tx_fin_acked {
        let st_idx, found = find_stream(cslot.conn.stream_table, stream_id);
        if found {
            let _ = on_send_ack(cslot.conn.stream_table.streams[st_idx], true);
        }
    }
}

fn retire_matching_sibling_chunks(cslot: QuicSrvConnSlot&, ref_ch: const QuicSentChunk&) {
    for j in cslot.sent_chunks.len {
        let sib .= cslot.sent_chunks[j];
        if !sib.active || sib.kind != ref_ch.kind || sib.space != ref_ch.space {
            continue;
        }
        if sib.stream_id == ref_ch.stream_id && sib.offset == ref_ch.offset && sib.length == ref_ch.length {
            sib.active = false;
        }
    }
}

fn retire_acked_chunks_in_space(
    cslot:    QuicSrvConnSlot&,
    c_idx:    i64,
    space_id: PnSpaceId,
    ranges:   const AckInterval[..65]&,
) {
    for i in cslot.sent_chunks.len {
        let ch .= cslot.sent_chunks[i];
        guard ch.active && ch.space == space_id && is_pn_in_ack_ranges(ranges, ch.pn) else { continue; }
        let copy_ch = ch;
        ch.active = false;
        retire_matching_sibling_chunks(cslot, copy_ch);
        if copy_ch.kind == QuicSentChunkKind.StreamData {
            if copy_ch.fin {
                let s_slot = find_or_alloc_stream_slot(c_idx, cslot.conn_id, copy_ch.stream_id, false);
                if s_slot >= 0 { g_quic_srv_stream_tx[s_slot].tx_fin_acked = true; }
            }
            compact_stream_tx_buffer(cslot, c_idx, copy_ch.stream_id);
        }
    }
}

fn mark_lost_chunks_in_space(cslot: QuicSrvConnSlot&, space_id: PnSpaceId) {
    var space .= cslot.conn.app_space;
    if space_id == PnSpaceId.Initial {
        space .= cslot.conn.initial_space;
    } else if space_id == PnSpaceId.Handshake {
        space .= cslot.conn.handshake_space;
    }
    for i in cslot.sent_chunks.len {
        let ch .= cslot.sent_chunks[i];
        if ch.active && ch.space == space_id && ch.in_flight {
            if !is_pn_in_sent_packets(space, ch.pn) {
                ch.in_flight = false;
                ch.retransmit = true;
            }
        }
    }
}

fn handle_inbound_ack_retirement(
    cslot: QuicSrvConnSlot&,
    c_idx: i64,
    htype: QuicHeaderType,
    frame: const QuicFrame&,
) {
    let space_id = quic_internal::header_type_to_space_id(htype);
    var space .= cslot.conn.app_space;
    if space_id == PnSpaceId.Initial {
        space .= cslot.conn.initial_space;
    } else if space_id == PnSpaceId.Handshake {
        space .= cslot.conn.handshake_space;
    }
    var ack_f = AckFrame {
        is_ecn:          frame.frame_type == QuicFrameType.AckEcn,
        largest_acked:   frame.offset,
        ack_delay:       frame.max_data,
        first_ack_range: frame.length,
        ..
    };
    if frame.payload.len > 0 {
        let dec, _, ok_d = decode_ack_frame(frame.payload, 0);
        if ok_d { ack_f = dec; }
    }
    var ranges: AckInterval[..65] = [];
    guard parse_and_validate_ack(space, ack_f, ranges) else { return; }
    retire_acked_chunks_in_space(cslot, c_idx, space_id, ranges);
    cslot.pto_count = 0;
}

// ---- Inbound Stream Buffering & Event Dispatch -----------------------------

fn sync_stream_send_limit(cslot: const QuicSrvConnSlot&, qstream: QuicStream&) {
    guard cslot.peer_tp_applied else { return; }
    let stype = qstream.stream_id & 0x03;
    var init_lim = cslot.peer_init_sd_bidi_local;
    if stype == 1 {
        init_lim = cslot.peer_init_sd_bidi_remote;
    } else if stype == 3 {
        init_lim = cslot.peer_init_sd_uni;
    }
    if qstream.bytes_sent == 0 && qstream.send_max_data == 65536 {
        qstream.send_max_data = init_lim;
    }
}

fn merge_rx_stream_interval(rx: QuicSrvStreamRxSlot&, start_off: u64, end_off: u64) -> bool {
    var cur_s = start_off;
    var cur_e = end_off;
    var i: i64 = 0;
    while i < rx.rx_intervals.len {
        let it = rx.rx_intervals[i];
        if cur_e < it.start {
            guard rx.rx_intervals.len < rx.rx_intervals.cap else { return false; }
            rx.rx_intervals.insert_at(i, Interval { start: cur_s, end: cur_e });
            break;
        }
        if cur_s > it.end {
            i = core::add_sat_i64(i, 1);
            continue;
        }
        cur_s = min(cur_s, it.start);
        cur_e = max(cur_e, it.end);
        rx.rx_intervals.remove_at(i);
    }
    if i == rx.rx_intervals.len {
        guard rx.rx_intervals.try_push(Interval { start: cur_s, end: cur_e }) else { return false; }
    }
    if rx.rx_intervals.len > 0 && rx.rx_intervals[0].start == rx.rx_base_offset {
        rx.rx_contiguous_end = rx.rx_intervals[0].end;
    }
    return true;
}

fn ingest_stream_frame_bytes(
    eslot:     QuicSrvEndpointSlot&,
    cslot:     QuicSrvConnSlot&,
    c_idx:     i64,
    stream_id: u64,
    offset:    u64,
    data:      const u8[:],
    fin:       bool,
) {
    let s_slot = find_or_alloc_stream_slot(c_idx, cslot.conn_id, stream_id, true);
    guard s_slot >= 0 else { return; }
    let st_idx, found_st = find_stream(cslot.conn.stream_table, stream_id);
    if found_st {
        sync_stream_send_limit(cslot, cslot.conn.stream_table.streams[st_idx]);
    }
    let rx .= g_quic_srv_stream_rx[s_slot];
    let end_off = core::add_sat_u64(offset, data.len as u64);
    if data.len > 0 && end_off > rx.rx_base_offset {
        let eff_start = max(offset, rx.rx_base_offset);
        let skip = core::sub_sat_u64(eff_start, offset) as i64;
        let dst_off = core::sub_sat_u64(eff_start, rx.rx_base_offset);
        guard slab_write_at(rx.rx_slabs, rx.rx_head_off, rx.rx_buf_len, dst_off, data[skip..])
            && merge_rx_stream_interval(rx, eff_start, end_off) else {
            close_conn_with_error(eslot, cslot, rfc::QUIC_ERR_FLOW_CONTROL, "stream buffer exceeded", false);
            return;
        }
    }
    if fin {
        rx.rx_fin_received = true;
        rx.rx_final_size = end_off;
    }
    let has_data = rx.rx_contiguous_end > rx.rx_base_offset;
    let has_fin = rx.rx_fin_received && !rx.rx_fin_delivered && rx.rx_contiguous_end == rx.rx_final_size;
    if (has_data || has_fin) && !rx.rx_readable_queued {
        rx.rx_readable_queued = true;
        enqueue_srv_event(eslot, QuicServerEventKind.StreamReadable, cslot.conn_id, stream_id, "", 0);
    }
}

fn handle_reset_stream_frame(
    eslot:     QuicSrvEndpointSlot&,
    cslot:     QuicSrvConnSlot&,
    c_idx:     i64,
    stream_id: u64,
    err_code:  u64,
) {
    let s_slot = find_or_alloc_stream_slot(c_idx, cslot.conn_id, stream_id, true);
    guard s_slot >= 0 else { return; }
    let rx .= g_quic_srv_stream_rx[s_slot];
    rx.rx_reset_received = true;
    rx.rx_reset_error = err_code;
    if !rx.rx_reset_delivered {
        rx.rx_reset_delivered = true;
        enqueue_srv_event(eslot, QuicServerEventKind.StreamReset, cslot.conn_id, stream_id, "", err_code);
    }
}

fn handle_decrypted_plain_frames(
    eslot: QuicSrvEndpointSlot&,
    cslot: QuicSrvConnSlot&,
    c_idx: i64,
    htype: QuicHeaderType,
    plain: const u8[:],
) {
    var idx: i64 = 0;
    while idx < plain.len {
        let frame, ok = decode_frame_cursor(plain, idx);
        guard ok else { return; }
        if frame.frame_type == QuicFrameType.Ack || frame.frame_type == QuicFrameType.AckEcn {
            handle_inbound_ack_retirement(cslot, c_idx, htype, frame);
        } else if frame.frame_type == QuicFrameType.Stream {
            ingest_stream_frame_bytes(eslot, cslot, c_idx, frame.stream_id, frame.offset, frame.payload, frame.fin);
        } else if frame.frame_type == QuicFrameType.ResetStream {
            handle_reset_stream_frame(eslot, cslot, c_idx, frame.stream_id, frame.error_code);
        } else if frame.frame_type == QuicFrameType.PathChallenge && frame.payload.len == 8 {
            for k in 8 { cslot.pending_path_resp[k] = frame.payload[k]; }
            cslot.has_path_resp = true;
        }
    }
    mark_lost_chunks_in_space(cslot, quic_internal::header_type_to_space_id(htype));
}

// ---- TLS CRYPTO Pumping, Transport Params & Key Transitions ----------------

fn close_conn_with_error(
    eslot:    QuicSrvEndpointSlot&,
    cslot:    QuicSrvConnSlot&,
    err_code: u64,
    reason:   const u8[:],
    is_app:   bool,
) {
    if cslot.conn.state != QuicConnState.Closing && cslot.conn.state != QuicConnState.Draining {
        close(cslot.conn, err_code);
        cslot.pending_close_tx = true;
        cslot.close_is_app = is_app;
        cslot.close_error = err_code;
        let _ = cslot.close_reason.try_set(reason[..min(reason.len, cslot.close_reason.cap)]);
    }
    if !cslot.close_event_emitted {
        cslot.close_event_emitted = true;
        enqueue_srv_event(eslot, QuicServerEventKind.ConnectionClosed, cslot.conn_id, 0, "", err_code);
    }
}

fn apply_peer_transport_params_once(eslot: QuicSrvEndpointSlot&, cslot: QuicSrvConnSlot&) -> bool {
    guard !cslot.peer_tp_applied else { return true; }
    let raw_tp = tls::quic_tls_server_peer_tp(cslot.tls_srv);
    guard raw_tp.len > 0 else { return true; }
    let tp, ok_tp = decode_transport_params(raw_tp, false);
    // RFC 9000 Section 7.3: Authenticating Connection IDs - Verify client initial_source_connection_id matches SCID.
    guard ok_tp && core::ct_eq_bytes(tp.initial_source_connection_id[..], cslot.conn.dcid[..]) else {
        close_conn_with_error(eslot, cslot, rfc::QUIC_ERR_TRANSPORT_PARAMETER, "bad transport params", false);
        return false;
    }
    cslot.peer_tp_applied = true;
    cslot.conn.flow_ctrl.max_data_remote = min(tp.initial_max_data, rfc::QUIC_VARINT_MAX);
    cslot.conn.stream_table.remote_max_streams_bidi = tp.initial_max_streams_bidi;
    cslot.conn.stream_table.has_remote_max_streams_bidi = true;
    cslot.conn.stream_table.remote_max_streams_uni = tp.initial_max_streams_uni;
    cslot.conn.stream_table.has_remote_max_streams_uni = true;
    cslot.conn.rtt.max_ack_delay_us = core::mul_sat_u64(tp.max_ack_delay, 1000);
    cslot.peer_init_sd_bidi_local = tp.initial_max_stream_data_bidi_local;
    cslot.peer_init_sd_bidi_remote = tp.initial_max_stream_data_bidi_remote;
    cslot.peer_init_sd_uni = tp.initial_max_stream_data_uni;
    cslot.peer_max_udp_payload = max(min(tp.max_udp_payload_size, 1500), rfc::QUIC_MIN_INITIAL_DATAGRAM_LEN);
    cslot.peer_active_cid_limit = max(tp.active_connection_id_limit, 2);

    if tp.max_idle_timeout > 0 {
        if cslot.idle_timeout_ms == 0 || tp.max_idle_timeout < cslot.idle_timeout_ms {
            cslot.idle_timeout_ms = tp.max_idle_timeout;
        }
    }
    return true;
}

fn drain_tls_secrets_and_crypto(cslot: QuicSrvConnSlot&) -> bool {
    var sec = tls::QuicTlsSecrets { .. };
    defer {
        core::secure_zeroize_48(sec.read_secret);
        core::secure_zeroize_48(sec.write_secret);
    };
    while tls::quic_tls_server_take_secrets(cslot.tls_srv, sec) {
        if sec.has_read {
            guard install_tls_secret(
                cslot.conn, sec.level, true, sec.read_secret[..], sec.cipher_suite,
            ) else {
                return false;
            }
        }
        if sec.has_write {
            guard install_tls_secret(
                cslot.conn, sec.level, false, sec.write_secret[..], sec.cipher_suite,
            ) else {
                return false;
            }
        }
    }
    var tmp_crypto: u8[>..] = [];
    let n_init = tls::quic_tls_server_drain_crypto(cslot.tls_srv, tls::QuicTlsLevel.Initial, tmp_crypto);
    if n_init > 0 {
        guard cslot.tx_init_crypto.try_append(tmp_crypto[..]) else { return false; }
    }
    tmp_crypto.clear();
    let n_hs = tls::quic_tls_server_drain_crypto(cslot.tls_srv, tls::QuicTlsLevel.Handshake, tmp_crypto);
    if n_hs > 0 {
        guard cslot.tx_hs_crypto.try_append(tmp_crypto[..]) else { return false; }
    }
    return true;
}

fn on_tls_handshake_established(eslot: QuicSrvEndpointSlot&, cslot: QuicSrvConnSlot&) {
    cslot.conn.state = QuicConnState.Established;
    cslot.handshake_done_queued = true;
    if cslot.peer_active_cid_limit >= 2 && cslot.alt_cid.len == 0 {
        var new_cid: u8[..20] = [];
        var new_tok: u8[16]   = [0; 16];
        if generate_unique_server_cid(cslot.ep_idx, cslot.ep_gen, new_cid) && core::csprng_fill(new_tok[..]) {
            if cslot.conn.alt_scids.try_push(new_cid) && cslot.alt_cid.try_set(new_cid[..]) {
                cslot.alt_reset_token = new_tok;
                cslot.new_cid_queued = true;
            }
        }
    }
    if !cslot.hs_complete_emitted {
        cslot.hs_complete_emitted = true;
        let sni = tls::quic_tls_server_client_sni(cslot.tls_srv);
        enqueue_srv_event(eslot, QuicServerEventKind.HandshakeComplete, cslot.conn_id, 0, sni[..], 0);
    }
}

fn apply_tls_status(
    eslot: QuicSrvEndpointSlot&,
    cslot: QuicSrvConnSlot&,
    st:    tls::QuicTlsStatus,
) -> bool {
    if st == tls::QuicTlsStatus.AlertError {
        let alert = tls::quic_tls_server_last_alert(cslot.tls_srv);
        let qerr = core::add_sat_u64(QUIC_CRYPTO_ERROR_BASE, tls::alert_to_u8(alert));
        close_conn_with_error(eslot, cslot, qerr, "tls alert", false);
        return false;
    }
    guard apply_peer_transport_params_once(eslot, cslot) else { return false; }
    guard drain_tls_secrets_and_crypto(cslot) else {
        close_conn_with_error(eslot, cslot, rfc::QUIC_ERR_INTERNAL, "crypto buffer", false);
        return false;
    }
    if st == tls::QuicTlsStatus.NeedSniCredentials {
        cslot.need_sni_creds = true;
        if !cslot.sni_event_emitted {
            cslot.sni_event_emitted = true;
            let sni = tls::quic_tls_server_client_sni(cslot.tls_srv);
            enqueue_srv_event(eslot, QuicServerEventKind.NeedSniCredentials, cslot.conn_id, 0, sni[..], 0);
        }
        return true;
    }
    if st == tls::QuicTlsStatus.Established {
        on_tls_handshake_established(eslot, cslot);
    }
    return true;
}

fn pump_conn_tls_crypto(eslot: QuicSrvEndpointSlot&, cslot: QuicSrvConnSlot&) -> bool {
    if cslot.conn.initial_crypto.buf.len > 0 {
        let st = tls::quic_tls_server_provide_crypto(
            cslot.tls_srv, tls::QuicTlsLevel.Initial, cslot.conn.initial_crypto.buf[..],
        );
        core::secure_zeroize_slice(cslot.conn.initial_crypto.buf[..]);
        cslot.conn.initial_crypto.buf.clear();
        guard apply_tls_status(eslot, cslot, st) else { return false; }
    }
    if cslot.conn.handshake_crypto.buf.len > 0 {
        let st = tls::quic_tls_server_provide_crypto(
            cslot.tls_srv, tls::QuicTlsLevel.Handshake, cslot.conn.handshake_crypto.buf[..],
        );
        core::secure_zeroize_slice(cslot.conn.handshake_crypto.buf[..]);
        cslot.conn.handshake_crypto.buf.clear();
        guard apply_tls_status(eslot, cslot, st) else { return false; }
    }
    return true;
}

fn discard_initial_space_on_handshake(cslot: QuicSrvConnSlot&) {
    guard !cslot.init_keys_discarded else { return; }
    // RFC 9001 Section 4.9.1: Discarding Initial Keys - Server discards Initial keys on first Handshake packet.
    clear_space_keys(cslot.conn.initial_space);
    clear_space_keys(cslot.conn.tx_initial_space);
    core::secure_zeroize_slice(cslot.tx_init_crypto[..]);
    cslot.tx_init_crypto.clear();
    cslot.tx_init_crypto_sent = 0;
    cslot.needs_ack_initial = false;
    retire_space_chunks(cslot, PnSpaceId.Initial);
    cslot.init_keys_discarded = true;
}

fn discard_handshake_space_if_confirmed(cslot: QuicSrvConnSlot&) {
    guard !cslot.hs_keys_discarded && cslot.conn.state == QuicConnState.Established else { return; }
    guard !cslot.needs_ack_hs && cslot.tx_hs_crypto_sent >= (cslot.tx_hs_crypto.len as u64) else { return; }
    // RFC 9001 Section 4.9.2: Discarding Handshake Keys - Discard Handshake keys when handshake is confirmed.
    clear_space_keys(cslot.conn.handshake_space);
    clear_space_keys(cslot.conn.tx_handshake_space);
    core::secure_zeroize_slice(cslot.tx_hs_crypto[..]);
    cslot.tx_hs_crypto.clear();
    cslot.tx_hs_crypto_sent = 0;
    retire_space_chunks(cslot, PnSpaceId.Handshake);
    cslot.hs_keys_discarded = true;
}

// ---- Ingress Datagram Processing -------------------------------------------

fn mark_space_ack_needed(cslot: QuicSrvConnSlot&, htype: QuicHeaderType) {
    if htype == QuicHeaderType.Initial {
        cslot.needs_ack_initial = true;
    } else if htype == QuicHeaderType.Handshake {
        cslot.needs_ack_hs = true;
    } else if htype == QuicHeaderType.OneRtt {
        cslot.needs_ack_app = true;
    }
}

fn handle_post_packet_transition(
    eslot: QuicSrvEndpointSlot&,
    cslot: QuicSrvConnSlot&,
    htype: QuicHeaderType,
) -> bool {
    if htype == QuicHeaderType.Handshake {
        discard_initial_space_on_handshake(cslot);
    }
    if cslot.conn.state == QuicConnState.Draining || cslot.conn.state == QuicConnState.Closing {
        close_conn_with_error(
            eslot, cslot, cslot.conn.close_code, "", cslot.conn.state == QuicConnState.Draining,
        );
        cslot.pending_close_tx = cslot.conn.state == QuicConnState.Closing;
        return false;
    }
    return pump_conn_tls_crypto(eslot, cslot);
}

// Processes one coalesced packet at `offset`, advancing `offset` when handled or leaving it unchanged on false.
//
// Example:
//   pkt = <Initial + Handshake>, offset = 0
//   returns: true, offset = consumed Initial length
fn step_coalesced_srv_packet(
    eslot:       QuicSrvEndpointSlot&,
    cslot:       QuicSrvConnSlot&,
    c_idx:       i64,
    pkt:         const u8[:],
    now_us:      u64,
    plain:       u8[..16384]&,
    offset:      i64&,
    any_handled: bool&,
) -> bool {
    var ack = AckFrame { .. };
    var htype = QuicHeaderType.Initial;
    let consumed, res = process_coalesced_packet(cslot.conn, pkt[offset..], pkt.len, now_us, ack, plain, htype);
    if !res.handled || consumed <= 0 {
        if cslot.conn.state == QuicConnState.Closing && !cslot.close_event_emitted {
            close_conn_with_error(eslot, cslot, cslot.conn.close_code, "protocol error", false);
        }
        return false;
    }
    any_handled = true;
    if res.needs_ack { mark_space_ack_needed(cslot, htype); }
    handle_decrypted_plain_frames(eslot, cslot, c_idx, htype, plain[..]);
    offset = core::add_sat_i64(offset, consumed);
    return handle_post_packet_transition(eslot, cslot, htype);
}

fn process_conn_datagram_packets(
    eslot:  QuicSrvEndpointSlot&,
    c_idx:  i64,
    pkt:    const u8[:],
    now_ns: u64,
    is_new: bool,
) -> bool {
    let cslot .= g_quic_srv_conns[c_idx];
    let now_us, _ = core::div_rem_u64(now_ns, 1000);
    cslot.conn.bytes_received = core::add_sat_u64(cslot.conn.bytes_received, pkt.len as u64);

    var offset: i64 = 0;
    var any_handled = false;
    var plain: u8[..16384] = [];
    while offset < pkt.len {
        if !step_coalesced_srv_packet(eslot, cslot, c_idx, pkt, now_us, plain, offset, any_handled) {
            break;
        }
    }

    if is_new && !any_handled {
        zeroize_and_free_conn_slot(c_idx);
        return false;
    }
    if any_handled {
        cslot.last_activity_ns = now_ns;
        cslot.ack_eliciting_sent_since_rx = false;
    }
    return any_handled;
}

// ---- Outbound Packet Assembly & Transmit Scheduler -------------------------

inline fn calc_total_in_flight_bytes(conn: const QuicConnection&) -> u64 {
    var total: u64 = 0;
    for i in conn.initial_space.sent_packets.len {
        if conn.initial_space.sent_packets[i].in_flight {
            total = core::add_sat_u64(total, conn.initial_space.sent_packets[i].size_bytes);
        }
    }
    for i in conn.handshake_space.sent_packets.len {
        if conn.handshake_space.sent_packets[i].in_flight {
            total = core::add_sat_u64(total, conn.handshake_space.sent_packets[i].size_bytes);
        }
    }
    for i in conn.app_space.sent_packets.len {
        if conn.app_space.sent_packets[i].in_flight {
            total = core::add_sat_u64(total, conn.app_space.sent_packets[i].size_bytes);
        }
    }
    return total;
}

inline fn calc_remaining_aa_budget(conn: const QuicConnection&, max_budget: u64) -> u64 {
    if conn.validated_address {
        return max_budget;
    }
    let lim = quic_internal::calc_amplification_limit(conn.bytes_received);
    let rem = core::sub_sat_u64(lim, conn.bytes_sent);
    return min(rem, max_budget);
}

fn find_pending_retransmit_chunk(cslot: const QuicSrvConnSlot&, space_id: PnSpaceId) -> i64 {
    for i in cslot.sent_chunks.len {
        let ch .= cslot.sent_chunks[i];
        if ch.active && ch.retransmit && ch.space == space_id {
            return i;
        }
    }
    return -1;
}

fn seal_and_track_packet(
    cslot:         QuicSrvConnSlot&,
    space_id:      PnSpaceId,
    hdr:           const QuicHeader&,
    plain:         u8[..1500]&,
    ack_eliciting: bool,
    now_us:        u64,
    out_pkt:       u8[..1500]&,
) -> bool {
    let pn_len: u8 = 2;
    // RFC 9001 Section 5.4.2: Header Protection Sample - Pad payload + PN to >= 4 bytes for 16-byte sample.
    while core::add_sat_u64(plain.len as u64, pn_len as u64) < 4 {
        guard plain.try_push(0) else { return false; }
    }
    let before_len = out_pkt.len;
    var ok_seal = false;
    if space_id == PnSpaceId.Initial {
        ok_seal = seal_packet_tracked(cslot.conn.tx_initial_space, hdr, pn_len, plain[..], out_pkt);
    } else if space_id == PnSpaceId.Handshake {
        ok_seal = seal_packet_tracked(cslot.conn.tx_handshake_space, hdr, pn_len, plain[..], out_pkt);
    } else {
        ok_seal = seal_packet_tracked(cslot.conn.tx_app_space, hdr, pn_len, plain[..], out_pkt);
    }
    guard ok_seal else {
        out_pkt.resize(before_len);
        return false;
    }
    let pkt_sz = core::sub_sat_u64(out_pkt.len as u64, before_len as u64);
    record_sent(cslot.conn, space_id, hdr.packet_number, pkt_sz, ack_eliciting, now_us);
    return true;
}

fn select_close_space_and_pn(cslot: const QuicSrvConnSlot&) -> PnSpaceId, QuicHeaderType, u64, bool {
    if cslot.conn.tx_app_space.keys_installed {
        return PnSpaceId.ApplicationData, QuicHeaderType.OneRtt, cslot.next_tx_pn_app, true;
    }
    if cslot.conn.tx_handshake_space.keys_installed {
        return PnSpaceId.Handshake, QuicHeaderType.Handshake, cslot.next_tx_pn_hs, true;
    }
    if cslot.conn.tx_initial_space.keys_installed {
        return PnSpaceId.Initial, QuicHeaderType.Initial, cslot.next_tx_pn_init, true;
    }
    return PnSpaceId.Initial, QuicHeaderType.Initial, 0, false;
}

fn advance_space_tx_pn(cslot: QuicSrvConnSlot&, space_id: PnSpaceId) {
    if space_id == PnSpaceId.Initial {
        cslot.next_tx_pn_init = core::add_sat_u64(cslot.next_tx_pn_init, 1);
    } else if space_id == PnSpaceId.Handshake {
        cslot.next_tx_pn_hs = core::add_sat_u64(cslot.next_tx_pn_hs, 1);
    } else {
        cslot.next_tx_pn_app = core::add_sat_u64(cslot.next_tx_pn_app, 1);
    }
}

fn try_emit_close_packet(cslot: QuicSrvConnSlot&, now_us: u64, out_pkt: u8[..1500]&) -> bool {
    let space_id, htype, pn, has_keys = select_close_space_and_pn(cslot);
    guard has_keys else {
        cslot.pending_close_tx = false;
        return false;
    }
    var plain: u8[..1500] = [];
    let is_app = cslot.close_is_app && space_id == PnSpaceId.ApplicationData;
    let err = if cslot.close_is_app && !is_app { rfc::QUIC_ERR_APPLICATION_ERROR } else { cslot.close_error };
    guard encode_connection_close_frame(err, 0, cslot.close_reason[..], plain, is_app) else {
        cslot.pending_close_tx = false;
        return false;
    }
    var hdr = QuicHeader { header_type: htype, version: cslot.conn.version, packet_number: pn, .. };
    guard hdr.dcid.try_set(cslot.conn.dcid[..]) else { return false; }
    if htype != QuicHeaderType.OneRtt {
        guard hdr.scid.try_set(cslot.conn.scid[..]) else { return false; }
    }
    let budget = calc_remaining_aa_budget(cslot.conn, QUIC_SRV_MAX_DGRAM_OUT);
    guard budget >= core::add_sat_u64(plain.len as u64, 64) else { return false; }
    guard seal_and_track_packet(cslot, space_id, hdr, plain, false, now_us, out_pkt) else { return false; }
    advance_space_tx_pn(cslot, space_id);
    cslot.pending_close_tx = false;
    return true;
}

fn try_emit_crypto_retx_frame(
    cslot:      QuicSrvConnSlot&,
    is_initial: bool,
    retx_idx:   i64,
    pn:         u64,
    max_plain:  u64,
    plain:      u8[..1500]&,
    out_ack_el: bool&,
) {
    guard retx_idx >= 0 else { return; }
    let ch .= cslot.sent_chunks[retx_idx];
    let need_plain = core::add_sat_u64(plain.len as u64, core::add_sat_u64(8, ch.length));
    guard need_plain <= max_plain else { return; }

    let end_off = core::add_sat_u64(ch.offset, ch.length);
    let space_id = if is_initial { PnSpaceId.Initial } else { PnSpaceId.Handshake };
    let kind = if is_initial { QuicSentChunkKind.CryptoInitial } else { QuicSentChunkKind.CryptoHandshake };
    let total_len = if is_initial { cslot.tx_init_crypto.len as u64 } else { cslot.tx_hs_crypto.len as u64 };
    guard end_off <= total_len else { return; }

    let ok_enc = if is_initial {
        encode_crypto_frame(ch.offset, cslot.tx_init_crypto[(ch.offset as i64)..(end_off as i64)], plain)
    } else {
        encode_crypto_frame(ch.offset, cslot.tx_hs_crypto[(ch.offset as i64)..(end_off as i64)], plain)
    };
    guard ok_enc else { return; }
    ch.retransmit = false;
    track_tx_chunk(cslot, space_id, pn, kind, 0, ch.offset, ch.length, false, 0);
    out_ack_el = true;
}

fn has_crypto_space_tx_work(cslot: const QuicSrvConnSlot&, is_initial: bool) -> i64, bool, bool {
    let space_id = if is_initial { PnSpaceId.Initial } else { PnSpaceId.Handshake };
    let keys_ok = if is_initial {
        cslot.conn.tx_initial_space.keys_installed
    } else {
        cslot.conn.tx_handshake_space.keys_installed
    };
    guard keys_ok else { return -1, false, false; }
    let retx_idx = find_pending_retransmit_chunk(cslot, space_id);
    let unsent = if is_initial {
        core::sub_sat_u64(cslot.tx_init_crypto.len as u64, cslot.tx_init_crypto_sent)
    } else {
        core::sub_sat_u64(cslot.tx_hs_crypto.len as u64, cslot.tx_hs_crypto_sent)
    };
    let needs_ack = if is_initial { cslot.needs_ack_initial } else { cslot.needs_ack_hs };
    let has_probe = cslot.ping_probe_pending && cslot.ping_probe_space == space_id;
    let has_work = retx_idx >= 0 || unsent > 0 || needs_ack || has_probe;
    return retx_idx, has_probe, has_work;
}

fn encode_crypto_space_ack(cslot: QuicSrvConnSlot&, is_initial: bool, plain: u8[..1500]&) {
    if is_initial && cslot.needs_ack_initial && cslot.conn.initial_space.recv_ranges.len > 0 {
        let ack, ok_a = build_ack_frame(cslot.conn.initial_space.recv_ranges, 0);
        if ok_a && encode_ack_frame(ack, plain) { cslot.needs_ack_initial = false; }
    } else if !is_initial && cslot.needs_ack_hs && cslot.conn.handshake_space.recv_ranges.len > 0 {
        let ack, ok_a = build_ack_frame(cslot.conn.handshake_space.recv_ranges, 0);
        if ok_a && encode_ack_frame(ack, plain) { cslot.needs_ack_hs = false; }
    }
}

fn try_emit_crypto_new_frame(
    cslot:      QuicSrvConnSlot&,
    is_initial: bool,
    pn:         u64,
    max_plain:  u64,
    plain:      u8[..1500]&,
    out_ack_el: bool&,
) {
    let space_id = if is_initial { PnSpaceId.Initial } else { PnSpaceId.Handshake };
    let kind = if is_initial { QuicSentChunkKind.CryptoInitial } else { QuicSentChunkKind.CryptoHandshake };
    let sent_off = if is_initial { cslot.tx_init_crypto_sent } else { cslot.tx_hs_crypto_sent };
    let total_len = if is_initial { cslot.tx_init_crypto.len as u64 } else { cslot.tx_hs_crypto.len as u64 };
    let hdr_room = core::add_sat_u64(plain.len as u64, 8);
    let unsent = core::sub_sat_u64(total_len, sent_off);
    let room = core::sub_sat_u64(max_plain, hdr_room);
    let take = min(unsent, room);
    guard take > 0 && max_plain > hdr_room else { return; }

    let end_i = core::add_sat_u64(sent_off, take) as i64;
    let ok_enc = if is_initial {
        encode_crypto_frame(sent_off, cslot.tx_init_crypto[(sent_off as i64)..end_i], plain)
    } else {
        encode_crypto_frame(sent_off, cslot.tx_hs_crypto[(sent_off as i64)..end_i], plain)
    };
    guard ok_enc else { return; }
    track_tx_chunk(cslot, space_id, pn, kind, 0, sent_off, take, false, 0);
    if is_initial {
        cslot.tx_init_crypto_sent = core::add_sat_u64(sent_off, take);
    } else {
        cslot.tx_hs_crypto_sent = core::add_sat_u64(sent_off, take);
    }
    out_ack_el = true;
}

fn seal_crypto_space_packet(
    cslot:          QuicSrvConnSlot&,
    is_initial:     bool,
    pn:             u64,
    hdr_overhead:   u64,
    pad_target_len: u64,
    budget:         u64,
    now_us:         u64,
    plain:          u8[..1500]&,
    out_ack_el:     bool,
    out_pkt:        u8[..1500]&,
) -> bool {
    let total_est = core::add_sat_u64(hdr_overhead, plain.len as u64);
    if out_ack_el && pad_target_len > total_est && pad_target_len <= budget {
        let _ = encode_padding_frame(plain, core::sub_sat_u64(pad_target_len, total_est));
    }
    let space_id = if is_initial { PnSpaceId.Initial } else { PnSpaceId.Handshake };
    let htype = if is_initial { QuicHeaderType.Initial } else { QuicHeaderType.Handshake };
    var hdr = QuicHeader { header_type: htype, version: cslot.conn.version, packet_number: pn, .. };
    guard hdr.dcid.try_set(cslot.conn.dcid[..]) && hdr.scid.try_set(cslot.conn.scid[..]) else { return false; }
    guard seal_and_track_packet(cslot, space_id, hdr, plain, out_ack_el, now_us, out_pkt) else { return false; }
    advance_space_tx_pn(cslot, space_id);
    return true;
}

fn emit_crypto_space_packet(
    cslot:          QuicSrvConnSlot&,
    is_initial:     bool,
    budget:         u64,
    now_us:         u64,
    out_pkt:        u8[..1500]&,
    pad_target_len: u64,
    out_ack_el:     bool&,
) -> bool {
    out_ack_el = false;
    let retx_idx, has_probe, has_work = has_crypto_space_tx_work(cslot, is_initial);
    guard has_work else { return false; }

    let base_ov: u64 = if is_initial { 28 } else { 27 };
    let cid_len = core::add_sat_u64(cslot.conn.dcid.len as u64, cslot.conn.scid.len as u64);
    let hdr_overhead = core::add_sat_u64(base_ov, cid_len);
    guard budget > core::add_sat_u64(hdr_overhead, 16) else { return false; }
    let max_plain = core::sub_sat_u64(budget, hdr_overhead);

    var plain: u8[..1500] = [];
    encode_crypto_space_ack(cslot, is_initial, plain);
    let pn = if is_initial { cslot.next_tx_pn_init } else { cslot.next_tx_pn_hs };
    if retx_idx >= 0 {
        try_emit_crypto_retx_frame(cslot, is_initial, retx_idx, pn, max_plain, plain, out_ack_el);
    } else {
        try_emit_crypto_new_frame(cslot, is_initial, pn, max_plain, plain, out_ack_el);
    }
    if has_probe && (plain.len as u64) < max_plain && encode_ping_frame(plain) {
        cslot.ping_probe_pending = false;
        out_ack_el = true;
    }
    guard plain.len > 0 && (plain.len as u64) <= max_plain else { return false; }
    return seal_crypto_space_packet(
        cslot, is_initial, pn, hdr_overhead, pad_target_len, budget, now_us, plain, out_ack_el, out_pkt,
    );
}

fn encode_app_window_frames(
    cslot:     QuicSrvConnSlot&,
    pn:        u64,
    plain:     u8[..1500]&,
    max_plain: u64,
    ack_el:    bool&,
) {
    if cslot.has_path_resp && core::add_sat_u64(plain.len as u64, 10) <= max_plain {
        if encode_path_response_frame(cslot.pending_path_resp, plain) {
            cslot.has_path_resp = false;
            ack_el = true;
        }
    }
    if cslot.need_max_data_tx && core::add_sat_u64(plain.len as u64, 10) <= max_plain {
        if encode_max_data_frame(cslot.max_data_tx_val, plain) {
            cslot.need_max_data_tx = false;
            track_tx_chunk(
                cslot, PnSpaceId.ApplicationData, pn, QuicSentChunkKind.MaxData, 0, 0, 0, false, cslot.max_data_tx_val,
            );
            ack_el = true;
        }
    }
}

fn encode_app_control_frames(
    cslot:     QuicSrvConnSlot&,
    pn:        u64,
    plain:     u8[..1500]&,
    max_plain: u64,
    ack_el:    bool&,
) {
    if cslot.needs_ack_app && cslot.conn.app_space.recv_ranges.len > 0 {
        let ack, ok_a = build_ack_frame(cslot.conn.app_space.recv_ranges, 0);
        if ok_a && encode_ack_frame(ack, plain) { cslot.needs_ack_app = false; }
    }
    if cslot.handshake_done_queued && (plain.len as u64) < max_plain {
        if encode_handshake_done_frame(plain) {
            cslot.handshake_done_queued = false;
            track_tx_chunk(cslot, PnSpaceId.ApplicationData, pn, QuicSentChunkKind.HandshakeDone, 0, 0, 0, false, 0);
            ack_el = true;
        }
    }
    if cslot.new_cid_queued && cslot.alt_cid.len > 0 && core::add_sat_u64(plain.len as u64, 32) <= max_plain {
        if encode_new_conn_id_frame(1, 0, cslot.alt_cid[..], cslot.alt_reset_token, plain) {
            cslot.new_cid_queued = false;
            track_tx_chunk(cslot, PnSpaceId.ApplicationData, pn, QuicSentChunkKind.NewConnectionId, 1, 0, 0, false, 0);
            ack_el = true;
        }
    }
    encode_app_window_frames(cslot, pn, plain, max_plain, ack_el);
}

fn encode_app_stream_window_updates(
    cslot:     QuicSrvConnSlot&,
    c_idx:     i64,
    pn:        u64,
    plain:     u8[..1500]&,
    max_plain: u64,
    ack_el:    bool&,
) {
    for i in g_quic_srv_stream_rx.len {
        let rx .= g_quic_srv_stream_rx[i];
        guard rx.active && rx.conn_idx == c_idx && rx.conn_id == cslot.conn_id && rx.need_max_sd_tx else {
            continue;
        }
        guard core::add_sat_u64(plain.len as u64, 16) <= max_plain else { return; }
        if encode_max_stream_data_frame(rx.stream_id, rx.max_sd_tx_val, plain) {
            rx.need_max_sd_tx = false;
            track_tx_chunk(
                cslot, PnSpaceId.ApplicationData, pn, QuicSentChunkKind.MaxStreamData,
                rx.stream_id, 0, 0, false, rx.max_sd_tx_val,
            );
            ack_el = true;
        }
    }
}

fn try_retx_stream_data_chunk(
    cslot:     QuicSrvConnSlot&,
    c_idx:     i64,
    ch_idx:    i64,
    pn:        u64,
    plain:     u8[..1500]&,
    max_plain: u64,
    ack_el:    bool&,
) -> bool {
    let ch .= cslot.sent_chunks[ch_idx];
    let copy_ch = ch;
    let s_slot = find_or_alloc_stream_slot(c_idx, cslot.conn_id, copy_ch.stream_id, false);
    guard s_slot >= 0 else { ch.active = false; return false; }
    let tx .= g_quic_srv_stream_tx[s_slot];
    guard copy_ch.offset >= tx.tx_unacked_base else { return false; }
    let rel = core::sub_sat_u64(copy_ch.offset, tx.tx_unacked_base);
    let clen = copy_ch.length;
    let need_plain = core::add_sat_u64(plain.len as u64, core::add_sat_u64(20, clen));
    guard core::add_sat_u64(rel, clen) <= tx.tx_buf_len && need_plain <= max_plain else { return false; }

    var slice_buf: u8[..1500] = [];
    guard slab_copy_slice(tx.tx_slabs, tx.tx_head_off, tx.tx_buf_len, rel, clen, slice_buf) else { return false; }
    let flags = QuicStreamFlags { fin: copy_ch.fin, with_len: true, .. };
    guard encode_stream_frame(copy_ch.stream_id, copy_ch.offset, slice_buf[..], plain, flags) else { return false; }
    ch.retransmit = false;
    track_tx_chunk(
        cslot, PnSpaceId.ApplicationData, pn, QuicSentChunkKind.StreamData,
        copy_ch.stream_id, copy_ch.offset, copy_ch.length, copy_ch.fin, 0,
    );
    ack_el = true;
    return true;
}

fn try_retx_single_app_chunk(
    cslot:     QuicSrvConnSlot&,
    c_idx:     i64,
    ch_idx:    i64,
    pn:        u64,
    plain:     u8[..1500]&,
    max_plain: u64,
    ack_el:    bool&,
) -> bool {
    let ch .= cslot.sent_chunks[ch_idx];
    let copy_ch = ch;
    let plen = plain.len as u64;
    if copy_ch.kind == QuicSentChunkKind.HandshakeDone && plen < max_plain {
        guard encode_handshake_done_frame(plain) else { return false; }
        ch.retransmit = false;
        track_tx_chunk(cslot, PnSpaceId.ApplicationData, pn, QuicSentChunkKind.HandshakeDone, 0, 0, 0, false, 0);
        ack_el = true;
        return true;
    }
    if copy_ch.kind == QuicSentChunkKind.NewConnectionId
        && cslot.alt_cid.len > 0 && core::add_sat_u64(plen, 32) <= max_plain {
        guard encode_new_conn_id_frame(1, 0, cslot.alt_cid[..], cslot.alt_reset_token, plain) else { return false; }
        ch.retransmit = false;
        track_tx_chunk(cslot, PnSpaceId.ApplicationData, pn, QuicSentChunkKind.NewConnectionId, 1, 0, 0, false, 0);
        ack_el = true;
        return true;
    }
    if copy_ch.kind == QuicSentChunkKind.MaxData && core::add_sat_u64(plen, 10) <= max_plain {
        guard encode_max_data_frame(cslot.conn.flow_ctrl.max_data_local, plain) else { return false; }
        ch.retransmit = false;
        ack_el = true;
        return true;
    }
    if copy_ch.kind == QuicSentChunkKind.MaxStreamData && core::add_sat_u64(plen, 16) <= max_plain {
        guard encode_max_stream_data_frame(copy_ch.stream_id, copy_ch.val, plain) else { return false; }
        ch.retransmit = false;
        ack_el = true;
        return true;
    }
    guard copy_ch.kind == QuicSentChunkKind.StreamData else { return false; }
    return try_retx_stream_data_chunk(cslot, c_idx, ch_idx, pn, plain, max_plain, ack_el);
}

fn encode_app_retransmit_chunks(
    cslot:     QuicSrvConnSlot&,
    c_idx:     i64,
    pn:        u64,
    plain:     u8[..1500]&,
    max_plain: u64,
    ack_el:    bool&,
) -> bool {
    var sent_any = false;
    for i in cslot.sent_chunks.len {
        let ch .= cslot.sent_chunks[i];
        guard ch.active && ch.retransmit && ch.space == PnSpaceId.ApplicationData else { continue; }
        let is_stream = ch.kind == QuicSentChunkKind.StreamData;
        if try_retx_single_app_chunk(cslot, c_idx, i, pn, plain, max_plain, ack_el) {
            sent_any = true;
            if is_stream { break; }
        }
    }
    return sent_any;
}

fn query_tx_stream_send_window(
    cslot:        QuicSrvConnSlot&,
    stream_id:    u64,
    conn_cred:    u64,
    unsent_bytes: u64,
    need_fin:     bool,
) -> i32, u64, bool {
    let st_idx, found_st = find_stream(cslot.conn.stream_table, stream_id);
    guard found_st else { return -1, 0, false; }
    let qstream .= cslot.conn.stream_table.streams[st_idx];
    sync_stream_send_limit(cslot, qstream);
    let avail_fc = min(conn_cred, remaining_stream_credit(qstream));
    guard unsent_bytes == 0 || avail_fc > 0 else { return -1, 0, false; }
    if !need_fin && avail_fc == 0 { return -1, 0, false; }
    return st_idx, avail_fc, true;
}

fn try_emit_stream_tx_slot(
    cslot:     QuicSrvConnSlot&,
    c_idx:     i64,
    slot_idx:  i64,
    pn:        u64,
    conn_cred: u64,
    plain:     u8[..1500]&,
    max_plain: u64,
    ack_el:    bool&,
) -> bool {
    let rx .= g_quic_srv_stream_rx[slot_idx];
    guard rx.active && rx.conn_idx == c_idx && rx.conn_id == cslot.conn_id else { return false; }
    let tx .= g_quic_srv_stream_tx[slot_idx];
    let unsent_rel = core::sub_sat_u64(tx.tx_next_offset, tx.tx_unacked_base);
    let unsent_bytes = core::sub_sat_u64(tx.tx_buf_len, unsent_rel);
    let need_fin_only = unsent_bytes == 0 && tx.tx_fin_queued && !tx.tx_fin_sent;
    guard unsent_bytes > 0 || need_fin_only else { return false; }

    let st_idx, avail_fc, ok_fc = query_tx_stream_send_window(
        cslot, rx.stream_id, conn_cred, unsent_bytes, need_fin_only,
    );
    guard ok_fc else { return false; }

    let used = core::add_sat_u64(plain.len as u64, 20);
    guard used <= max_plain else { return false; }
    let send_len = min(unsent_bytes, min(avail_fc, core::sub_sat_u64(max_plain, used)));
    guard send_len > 0 || need_fin_only else { return false; }

    let send_fin = tx.tx_fin_queued && !tx.tx_fin_sent && (send_len == unsent_bytes);
    var slice_buf: u8[..1500] = [];
    guard slab_copy_slice(tx.tx_slabs, tx.tx_head_off, tx.tx_buf_len, unsent_rel, send_len, slice_buf) else {
        return false;
    }
    let flags = QuicStreamFlags { fin: send_fin, with_len: true, .. };
    guard encode_stream_frame(rx.stream_id, tx.tx_next_offset, slice_buf[..], plain, flags) else { return false; }
    let qstream .= cslot.conn.stream_table.streams[st_idx];
    if send_len > 0 {
        let _ = record_send(cslot.conn.flow_ctrl, qstream, tx.tx_next_offset, send_len);
    }
    let _, _ = on_send_data(qstream, tx.tx_next_offset, send_len, send_fin);
    track_tx_chunk(
        cslot, PnSpaceId.ApplicationData, pn, QuicSentChunkKind.StreamData,
        rx.stream_id, tx.tx_next_offset, send_len, send_fin, 0,
    );
    tx.tx_next_offset = core::add_sat_u64(tx.tx_next_offset, send_len);
    if send_fin { tx.tx_fin_sent = true; }
    ack_el = true;
    return true;
}

fn encode_app_unsent_stream_data(
    cslot:     QuicSrvConnSlot&,
    c_idx:     i64,
    pn:        u64,
    plain:     u8[..1500]&,
    max_plain: u64,
    ack_el:    bool&,
) {
    let conn_cred = remaining_conn_credit(cslot.conn.flow_ctrl);
    for i in g_quic_srv_stream_rx.len {
        if try_emit_stream_tx_slot(cslot, c_idx, i, pn, conn_cred, plain, max_plain, ack_el) {
            return;
        }
    }
}

fn try_emit_app_packet(
    cslot:      QuicSrvConnSlot&,
    c_idx:      i64,
    budget:     u64,
    now_us:     u64,
    out_pkt:    u8[..1500]&,
    out_ack_el: bool&,
) -> bool {
    out_ack_el = false;
    guard cslot.conn.tx_app_space.keys_installed && cslot.conn.state == QuicConnState.Established else {
        return false;
    }
    let hdr_overhead = core::add_sat_u64(19, cslot.conn.dcid.len as u64);
    guard budget > core::add_sat_u64(hdr_overhead, 8) else { return false; }
    let max_plain = core::sub_sat_u64(budget, hdr_overhead);

    let pn = cslot.next_tx_pn_app;
    var plain: u8[..1500] = [];
    encode_app_control_frames(cslot, pn, plain, max_plain, out_ack_el);
    encode_app_stream_window_updates(cslot, c_idx, pn, plain, max_plain, out_ack_el);
    let sent_retx = encode_app_retransmit_chunks(cslot, c_idx, pn, plain, max_plain, out_ack_el);

    let in_flight = calc_total_in_flight_bytes(cslot.conn);
    if !sent_retx && in_flight < cslot.conn.bbr.cwnd_bytes && cslot.conn.app_space.sent_packets.len < 120 {
        encode_app_unsent_stream_data(cslot, c_idx, pn, plain, max_plain, out_ack_el);
    }
    if cslot.ping_probe_pending
        && cslot.ping_probe_space == PnSpaceId.ApplicationData && (plain.len as u64) < max_plain {
        if encode_ping_frame(plain) {
            cslot.ping_probe_pending = false;
            out_ack_el = true;
        }
    }
    guard plain.len > 0 else { return false; }

    var hdr = QuicHeader { header_type: QuicHeaderType.OneRtt, packet_number: pn, .. };
    guard hdr.dcid.try_set(cslot.conn.dcid[..]) else { return false; }
    guard seal_and_track_packet(cslot, PnSpaceId.ApplicationData, hdr, plain, out_ack_el, now_us, out_pkt) else {
        return false;
    }
    cslot.next_tx_pn_app = core::add_sat_u64(cslot.next_tx_pn_app, 1);
    return true;
}

fn calc_initial_pad_target(cslot: const QuicSrvConnSlot&, rem_budget: u64) -> u64 {
    let has_hs_to_coalesce = cslot.conn.tx_handshake_space.keys_installed && (
        cslot.needs_ack_hs || cslot.tx_hs_crypto_sent < (cslot.tx_hs_crypto.len as u64)
        || find_pending_retransmit_chunk(cslot, PnSpaceId.Handshake) >= 0
        || (cslot.ping_probe_pending && cslot.ping_probe_space == PnSpaceId.Handshake)
    );
    if !has_hs_to_coalesce && rem_budget >= rfc::QUIC_MIN_INITIAL_DATAGRAM_LEN {
        return rfc::QUIC_MIN_INITIAL_DATAGRAM_LEN;
    }
    return 0;
}

fn emit_conn_closing_datagram(cslot: QuicSrvConnSlot&, now_us: u64, out_pkt: u8[..1500]&) -> bool {
    guard cslot.pending_close_tx else { return false; }
    guard cslot.conn.validated_address || can_send(cslot.conn, 128) else {
        cslot.pending_close_tx = false;
        return false;
    }
    return try_emit_close_packet(cslot, now_us, out_pkt);
}

fn try_build_conn_datagram(c_idx: i64, now_ns: u64, out_pkt: u8[..1500]&) -> bool {
    let cslot .= g_quic_srv_conns[c_idx];
    let now_us, _ = core::div_rem_u64(now_ns, 1000);
    guard cslot.conn.state != QuicConnState.Draining && cslot.conn.state != QuicConnState.Closed else {
        return false;
    }
    if cslot.conn.state == QuicConnState.Closing {
        return emit_conn_closing_datagram(cslot, now_us, out_pkt);
    }
    guard !cslot.need_sni_creds else { return false; }

    let dgram_cap = min(QUIC_SRV_MAX_DGRAM_OUT, cslot.peer_max_udp_payload);
    var rem_budget = calc_remaining_aa_budget(cslot.conn, dgram_cap);
    guard rem_budget > 32 else { return false; }

    var init_ack_el = false;
    let init_pad = calc_initial_pad_target(cslot, rem_budget);
    let sent_init = emit_crypto_space_packet(cslot, true, rem_budget, now_us, out_pkt, init_pad, init_ack_el);
    rem_budget = calc_remaining_aa_budget(cslot.conn, core::sub_sat_u64(dgram_cap, out_pkt.len as u64));

    var hs_ack_el = false;
    let min_pad = if sent_init && init_ack_el {
        core::sub_sat_u64(rfc::QUIC_MIN_INITIAL_DATAGRAM_LEN, out_pkt.len as u64)
    } else {
        0
    };
    let sent_hs = emit_crypto_space_packet(cslot, false, rem_budget, now_us, out_pkt, min_pad, hs_ack_el);

    rem_budget = calc_remaining_aa_budget(cslot.conn, core::sub_sat_u64(dgram_cap, out_pkt.len as u64));
    var app_ack_el = false;
    let sent_app = try_emit_app_packet(cslot, c_idx, rem_budget, now_us, out_pkt, app_ack_el);
    discard_handshake_space_if_confirmed(cslot);

    let any_ack_el = init_ack_el || hs_ack_el || app_ack_el;
    if any_ack_el && !cslot.ack_eliciting_sent_since_rx {
        cslot.last_activity_ns = now_ns;
        cslot.ack_eliciting_sent_since_rx = true;
    }
    return sent_init || sent_hs || sent_app;
}

// ---- Timer & Idle Timeout Helpers ------------------------------------------

inline fn eval_conn_pto(cslot: const QuicSrvConnSlot&, now_us: u64) -> PtoTimerDecision {
    let spaces: PnSpaceState[3] = [
        cslot.conn.initial_space,
        cslot.conn.handshake_space,
        cslot.conn.app_space,
    ];
    let aa_limited = !cslot.conn.validated_address && !can_send(cslot.conn, 128);
    let ctx = PtoContext {
        is_server:                      true,
        is_amplification_limited:       aa_limited,
        peer_completed_addr_validation: cslot.conn.validated_address,
        handshake_confirmed:            cslot.conn.state == QuicConnState.Established,
    };
    return evaluate_pto_timer(spaces, cslot.conn.rtt, cslot.pto_count, now_us, ctx);
}

inline fn calc_conn_idle_deadline_ns(cslot: const QuicSrvConnSlot&) -> u64 {
    guard cslot.idle_timeout_ms > 0 && cslot.last_activity_ns > 0 else { return 0; }
    let pto_us = compute_pto_duration(cslot.conn.rtt, 0, cslot.conn.state == QuicConnState.Established);
    let min_idle_ns = core::mul_sat_u64(core::mul_sat_u64(pto_us, 3), 1000);
    let cfg_idle_ns = core::mul_sat_u64(cslot.idle_timeout_ms, 1000000);
    let eff_idle_ns = max(cfg_idle_ns, min_idle_ns);
    return core::add_sat_u64(cslot.last_activity_ns, eff_idle_ns);
}

fn schedule_pto_probe_in_space(cslot: QuicSrvConnSlot&, space_id: PnSpaceId) {
    var marked: u32 = 0;
    for i in cslot.sent_chunks.len {
        let ch .= cslot.sent_chunks[i];
        if ch.active && ch.space == space_id && ch.in_flight && !ch.retransmit {
            ch.retransmit = true;
            marked = core::add_sat_u32(marked, 1);
            if marked >= 2 { return; }
        }
    }
    if marked == 0 {
        cslot.ping_probe_pending = true;
        cslot.ping_probe_space = space_id;
    }
}

fn run_conn_loss_detection(cslot: QuicSrvConnSlot&, space_id: PnSpaceId, now_us: u64) {
    var lost_pkts: SentPacketMeta[..128] = [];
    if space_id == PnSpaceId.Initial {
        let _ = detect_lost_packets(cslot.conn.initial_space, cslot.conn.rtt, now_us, lost_pkts);
    } else if space_id == PnSpaceId.Handshake {
        let _ = detect_lost_packets(cslot.conn.handshake_space, cslot.conn.rtt, now_us, lost_pkts);
    } else {
        let _ = detect_lost_packets(cslot.conn.app_space, cslot.conn.rtt, now_us, lost_pkts);
    }
    mark_lost_chunks_in_space(cslot, space_id);
}

fn process_conn_timeout(eslot: QuicSrvEndpointSlot&, c_idx: i64, now_ns: u64) {
    let cslot .= g_quic_srv_conns[c_idx];
    if cslot.conn.state == QuicConnState.Closing || cslot.conn.state == QuicConnState.Draining {
        if cslot.drain_deadline_ns > 0 && now_ns >= cslot.drain_deadline_ns {
            zeroize_and_free_conn_slot(c_idx);
        }
        return;
    }
    let idle_dl = calc_conn_idle_deadline_ns(cslot);
    if idle_dl > 0 && now_ns >= idle_dl {
        // RFC 9000 Section 10.1: Idle Timeout - Silently close and discard connection state.
        if !cslot.close_event_emitted {
            cslot.close_event_emitted = true;
            enqueue_srv_event(eslot, QuicServerEventKind.ConnectionClosed, cslot.conn_id, 0, "", 0);
        }
        zeroize_and_free_conn_slot(c_idx);
        return;
    }
    let now_us, _ = core::div_rem_u64(now_ns, 1000);
    let dec = eval_conn_pto(cslot, now_us);
    if dec.mode == PtoTimerMode.LossTime && dec.target_time_us > 0 && now_us >= dec.target_time_us {
        run_conn_loss_detection(cslot, dec.space_id, now_us);
        return;
    }
    if dec.mode == PtoTimerMode.StandardPto && dec.target_time_us > 0 && now_us >= dec.target_time_us {
        // RFC 9002 Section 6.2.4: Sending Probe Packets - Retransmit unacked data or emit PING probe on PTO.
        cslot.pto_count = min(core::add_sat_u32(cslot.pto_count, 1), 16);
        schedule_pto_probe_in_space(cslot, dec.space_id);
    }
}

// ---- Public Sans-IO QUIC Server Endpoint API ------------------------------

// Opens a thread-local multi-client sans-IO QUIC server endpoint.
fn quic_server_open(
    alpn_wire:       const u8[:],
    max_conns:       i32 = 256,
    idle_timeout_ms: u64 = 30000,
) -> QuicServerEndpoint {
    guard alpn_wire.len <= 255 && max_conns > 0 else { return QuicServerEndpoint { .. }; }
    var idx: i64 = -1;
    for i in g_quic_srv_endpoints.len {
        if !g_quic_srv_endpoints[i].active {
            idx = i;
            break;
        }
    }
    if idx < 0 {
        guard g_quic_srv_endpoints.len < QUIC_SRV_MAX_ENDPOINTS else { return QuicServerEndpoint { .. }; }
        idx = g_quic_srv_endpoints.len;
        g_quic_srv_endpoints.push(QuicSrvEndpointSlot { .. });
    }
    let gen = next_srv_gen(g_quic_srv_ep_next_gen);
    let eslot .= g_quic_srv_endpoints[idx];
    eslot = QuicSrvEndpointSlot {
        active:          true,
        generation:      gen,
        max_conns:       min(max_conns, QUIC_SRV_MAX_CONNS_CAP),
        idle_timeout_ms: idle_timeout_ms,
        ..
    };
    guard eslot.alpn_wire.try_set(alpn_wire) else {
        eslot = QuicSrvEndpointSlot { .. };
        return QuicServerEndpoint { .. };
    }
    return QuicServerEndpoint { slot_idx: idx, generation: gen };
}

// Closes `ep`, releasing all connections and zeroizing all QUIC and TLS cryptographic secrets.
fn quic_server_close(ep: QuicServerEndpoint&) {
    let ep_idx = lookup_live_ep_idx(ep);
    ep = QuicServerEndpoint { .. };
    guard ep_idx >= 0 else { return; }
    let eslot .= g_quic_srv_endpoints[ep_idx];
    for i in g_quic_srv_conns.len {
        let cslot .= g_quic_srv_conns[i];
        if cslot.active && cslot.ep_idx == ep_idx && cslot.ep_gen == eslot.generation {
            zeroize_and_free_conn_slot(i);
        }
    }
    clear_ep_event_queue(eslot);
    eslot = QuicSrvEndpointSlot { .. };
}

// Feeds an inbound UDP datagram from `(peer_ip, peer_port)` into `ep`, demultiplexing by DCID.
fn quic_server_feed_datagram(
    ep:        QuicServerEndpoint&,
    pkt:       const u8[:],
    peer_ip:   const u8[:],
    peer_port: u16,
    now_ns:    u64,
) -> bool {
    let ep_idx = lookup_live_ep_idx(ep);
    guard ep_idx >= 0 && pkt.len > 0 && peer_ip.len > 0 && peer_ip.len <= 64 && peer_port != 0 else {
        return false;
    }
    let eslot .= g_quic_srv_endpoints[ep_idx];

    if (pkt[0] & 0x80) == 0 {
        guard pkt.len >= QUIC_SRV_SHORT_PKT_MIN_LEN else { return false; }
        let dcid = pkt[1..QUIC_SRV_SHORT_PKT_MIN_LEN];
        let c_idx = find_conn_by_dcid(ep_idx, eslot.generation, dcid, false);
        guard c_idx >= 0 else { return false; }
        return process_conn_datagram_packets(eslot, c_idx, pkt, now_ns, false);
    }

    let hdr, ok_h = quic_internal::parse_quic_long_header(
        pkt, pkt[0], quic_internal::QuicHeaderOptions { is_masked: true, .. },
    );
    guard ok_h && (hdr.version == rfc::QUIC_VERSION_1 || hdr.version == rfc::QUIC_VERSION_2) else {
        return false;
    }
    let is_init = hdr.header_type == QuicHeaderType.Initial;
    var c_idx = find_conn_by_dcid(ep_idx, eslot.generation, hdr.dcid[..], is_init);
    var is_new = false;
    if c_idx < 0 {
        guard is_init else { return false; }
        c_idx = accept_new_initial_conn(ep_idx, pkt, hdr, peer_ip, peer_port, now_ns);
        guard c_idx >= 0 else { return false; }
        is_new = true;
    }
    return process_conn_datagram_packets(eslot, c_idx, pkt, now_ns, is_new);
}

// Pops the next pending connection or stream event into `out_ev`.
fn quic_server_poll_event(ep: QuicServerEndpoint&, out_ev: QuicServerEvent&) -> bool {
    out_ev = QuicServerEvent { .. };
    let ep_idx = lookup_live_ep_idx(ep);
    guard ep_idx >= 0 else { return false; }
    let eslot .= g_quic_srv_endpoints[ep_idx];
    let ev_idx = eslot.ev_head;
    guard ev_idx >= 0 else { return false; }

    let node = g_quic_srv_events[ev_idx];
    eslot.ev_head = node.next_idx;
    if eslot.ev_head < 0 {
        eslot.ev_tail = -1;
    }
    out_ev = QuicServerEvent {
        kind:       node.kind,
        conn_id:    node.conn_id,
        stream_id:  node.stream_id,
        sni:        node.sni,
        error_code: node.error_code,
    };
    free_srv_event_node(ev_idx);
    return true;
}

// Supplies leaf/fullchain PEM certificate and private key for a connection paused on `NeedSniCredentials`.
fn quic_server_set_credentials_pem(
    ep:       QuicServerEndpoint&,
    conn_id:  u64,
    cert_pem: const u8[:],
    key_pem:  const u8[:],
) -> bool {
    let ep_idx = lookup_live_ep_idx(ep);
    guard ep_idx >= 0 else { return false; }
    let eslot .= g_quic_srv_endpoints[ep_idx];
    let c_idx = find_conn_idx_by_id(ep_idx, eslot.generation, conn_id);
    guard c_idx >= 0 else { return false; }
    let cslot .= g_quic_srv_conns[c_idx];
    guard cslot.need_sni_creds else { return false; }

    cslot.need_sni_creds = false;
    let st = tls::quic_tls_server_set_credentials_pem(cslot.tls_srv, cert_pem, key_pem);
    return apply_tls_status(eslot, cslot, st);
}

fn try_poll_conn_slot_transmit(
    eslot:         const QuicSrvEndpointSlot&,
    ep_idx:        i64,
    c_idx:         i64,
    now_ns:        u64,
    out_pkt:       u8[..1500]&,
    out_peer_ip:   u8[..64]&,
    out_peer_port: u16&,
) -> bool {
    let cslot .= g_quic_srv_conns[c_idx];
    guard cslot.active && cslot.ep_idx == ep_idx && cslot.ep_gen == eslot.generation else { return false; }
    guard try_build_conn_datagram(c_idx, now_ns, out_pkt) else { return false; }
    guard out_peer_ip.try_set(cslot.peer_ip[..]) else { return false; }
    out_peer_port = cslot.peer_port;
    return true;
}

// Serializes the next ready encrypted UDP datagram (Initial, Handshake, and/or 1-RTT) for any connection.
fn quic_server_poll_transmit(
    ep:            QuicServerEndpoint&,
    now_ns:        u64,
    out_pkt:       u8[..1500]&,
    out_peer_ip:   u8[..64]&,
    out_peer_port: u16&,
) -> bool {
    out_pkt.clear();
    out_peer_ip.clear();
    out_peer_port = 0;
    var committed = false;
    defer if !committed {
        out_pkt.clear();
        out_peer_ip.clear();
        out_peer_port = 0;
    };

    let ep_idx = lookup_live_ep_idx(ep);
    guard ep_idx >= 0 && g_quic_srv_conns.len > 0 else { return false; }
    let eslot .= g_quic_srv_endpoints[ep_idx];
    let total = g_quic_srv_conns.len;
    var c_idx = if eslot.tx_rr_cursor >= 0 && eslot.tx_rr_cursor < total { eslot.tx_rr_cursor } else { 0 };

    for _ in total {
        let next_idx = core::add_sat_i64(c_idx, 1);
        let wrapped_next = if next_idx >= total { 0 } else { next_idx };
        if try_poll_conn_slot_transmit(eslot, ep_idx, c_idx, now_ns, out_pkt, out_peer_ip, out_peer_port) {
            eslot.tx_rr_cursor = wrapped_next;
            committed = true;
            return true;
        }
        c_idx = wrapped_next;
    }
    return false;
}

inline fn calc_single_conn_deadline_ns(cslot: const QuicSrvConnSlot&) -> u64 {
    if cslot.conn.state == QuicConnState.Closing || cslot.conn.state == QuicConnState.Draining {
        return cslot.drain_deadline_ns;
    }
    let idle_dl = calc_conn_idle_deadline_ns(cslot);
    let dec = eval_conn_pto(cslot, 0);
    let pto_dl = if dec.target_time_us > 0 { core::mul_sat_u64(dec.target_time_us, 1000) } else { 0 };
    if idle_dl > 0 && pto_dl > 0 {
        return min(idle_dl, pto_dl);
    }
    return max(idle_dl, pto_dl);
}

// Returns the earliest absolute monotonic timeout deadline in nanoseconds across all connections, or 0.
fn quic_server_next_timeout_ns(ep: const QuicServerEndpoint&) -> u64 {
    let ep_idx = lookup_live_ep_idx(ep);
    guard ep_idx >= 0 else { return 0; }
    let eslot .= g_quic_srv_endpoints[ep_idx];
    var earliest: u64 = 0;

    for i in g_quic_srv_conns.len {
        let cslot .= g_quic_srv_conns[i];
        guard cslot.active && cslot.ep_idx == ep_idx && cslot.ep_gen == eslot.generation else { continue; }
        let conn_dl = calc_single_conn_deadline_ns(cslot);
        if conn_dl > 0 && (earliest == 0 || conn_dl < earliest) {
            earliest = conn_dl;
        }
    }
    return earliest;
}

// Fires expired loss-detection, PTO retransmission, draining, and idle-timeout timers at `now_ns`.
fn quic_server_on_timeout(ep: QuicServerEndpoint&, now_ns: u64) {
    let ep_idx = lookup_live_ep_idx(ep);
    guard ep_idx >= 0 else { return; }
    let eslot .= g_quic_srv_endpoints[ep_idx];
    for i in g_quic_srv_conns.len {
        let cslot .= g_quic_srv_conns[i];
        if cslot.active && cslot.ep_idx == ep_idx && cslot.ep_gen == eslot.generation {
            process_conn_timeout(eslot, i, now_ns);
        }
    }
}

fn advance_rx_after_consume(
    cslot:     QuicSrvConnSlot&,
    rx:        QuicSrvStreamRxSlot&,
    stream_id: u64,
    avail:     u64,
) {
    slab_consume_front(rx.rx_slabs, rx.rx_head_off, rx.rx_buf_len, avail);
    rx.rx_base_offset = core::add_sat_u64(rx.rx_base_offset, avail);
    if rx.rx_intervals.len > 0 {
        if rx.rx_base_offset >= rx.rx_intervals[0].end {
            rx.rx_intervals.remove_at(0);
        } else {
            rx.rx_intervals[0].start = rx.rx_base_offset;
        }
    }
    let st_idx, found_st = find_stream(cslot.conn.stream_table, stream_id);
    guard found_st else { return; }
    let qstream .= cslot.conn.stream_table.streams[st_idx];
    on_app_read(cslot.conn.flow_ctrl, qstream, avail);
    let _ = on_app_read(qstream, avail);
    let new_md, need_md = check_conn_window_update(cslot.conn.flow_ctrl);
    if need_md {
        cslot.need_max_data_tx = true;
        cslot.max_data_tx_val = new_md;
    }
    let new_msd, need_msd = check_stream_window_update(qstream, QUIC_SRV_DEFAULT_WINDOW);
    if need_msd {
        rx.need_max_sd_tx = true;
        rx.max_sd_tx_val = new_msd;
    }
}

// Reads contiguous received bytes from `stream_id` into `out`, setting `out_fin` on stream EOF.
fn quic_server_stream_read(
    ep:        QuicServerEndpoint&,
    conn_id:   u64,
    stream_id: u64,
    out:       u8[>..]&,
    out_fin:   bool&,
) -> i64 {
    out_fin = false;
    let ep_idx = lookup_live_ep_idx(ep);
    guard ep_idx >= 0 else { return -1; }
    let eslot .= g_quic_srv_endpoints[ep_idx];
    let c_idx = find_conn_idx_by_id(ep_idx, eslot.generation, conn_id);
    guard c_idx >= 0 else { return -1; }
    let cslot .= g_quic_srv_conns[c_idx];
    guard !quic_internal::quic_conn_is_closing_or_closed(cslot.conn.state) else { return -1; }

    let s_slot = find_or_alloc_stream_slot(c_idx, conn_id, stream_id, false);
    guard s_slot >= 0 else { return -1; }
    let rx .= g_quic_srv_stream_rx[s_slot];
    guard !rx.rx_reset_received else { return -1; }

    let avail = core::sub_sat_u64(rx.rx_contiguous_end, rx.rx_base_offset);
    if avail > 0 && avail <= rx.rx_buf_len {
        guard slab_read_to_out(rx.rx_slabs, rx.rx_head_off, rx.rx_buf_len, 0, avail, out) else {
            return -1;
        }
        advance_rx_after_consume(cslot, rx, stream_id, avail);
    }
    rx.rx_readable_queued = false;
    if rx.rx_fin_received && rx.rx_base_offset >= rx.rx_final_size {
        out_fin = true;
        rx.rx_fin_delivered = true;
    }
    return avail as i64;
}

inline fn calc_peer_stream_limit(tbl: const QuicStreamTable&, is_bidi: bool) -> u64 {
    if is_bidi {
        return if tbl.has_remote_max_streams_bidi { tbl.remote_max_streams_bidi } else { tbl.max_streams_bidi };
    }
    return if tbl.has_remote_max_streams_uni { tbl.remote_max_streams_uni } else { tbl.max_streams_uni };
}

fn ensure_server_writable_stream(cslot: QuicSrvConnSlot&, stream_id: u64) -> i32, bool {
    guard quic_internal::quic_stream_can_send(stream_id, QuicRole.Server) else { return -1, false; }
    let st_idx, found = find_stream(cslot.conn.stream_table, stream_id);
    if found {
        return st_idx, true;
    }
    // RFC 9000 Section 2.1: Stream Types and Identifiers - Server initiates odd stream IDs (1, 3, ...).
    guard !quic_internal::is_peer_initiated_stream(stream_id, QuicRole.Server) else { return -1, false; }
    let is_bidi = (stream_id & 2) == 0;
    let tbl .= cslot.conn.stream_table;
    let limit = calc_peer_stream_limit(tbl, is_bidi);
    guard stream_id <= rfc::QUIC_VARINT_MAX && (stream_id >> 2) < limit else { return -1, false; }
    guard tbl.streams.len < tbl.streams.cap else { return -1, false; }
    let new_idx = quic_internal::quic_table_insert_stream(tbl, stream_id, cslot.conn.flow_ctrl.local_window_size);
    sync_stream_send_limit(cslot, tbl.streams[new_idx]);
    let next_id = core::add_sat_u64(stream_id, 4);
    if is_bidi {
        tbl.next_local_bidi_id = max(tbl.next_local_bidi_id, next_id);
    } else {
        tbl.next_local_uni_id = max(tbl.next_local_uni_id, next_id);
    }
    return new_idx, true;
}

// Enqueues stream data (and optional FIN) for flow-controlled transmission on `stream_id`.
fn quic_server_stream_write(
    ep:        QuicServerEndpoint&,
    conn_id:   u64,
    stream_id: u64,
    data:      const u8[:],
    fin:       bool,
) -> i64, bool {
    let ep_idx = lookup_live_ep_idx(ep);
    guard ep_idx >= 0 else { return 0, false; }
    let eslot .= g_quic_srv_endpoints[ep_idx];
    let c_idx = find_conn_idx_by_id(ep_idx, eslot.generation, conn_id);
    guard c_idx >= 0 else { return 0, false; }
    let cslot .= g_quic_srv_conns[c_idx];
    guard cslot.conn.state == QuicConnState.Established && cslot.conn.tx_app_space.keys_installed else {
        return 0, false;
    }
    let st_idx, ok_st = ensure_server_writable_stream(cslot, stream_id);
    guard ok_st else { return 0, false; }
    let qstream .= cslot.conn.stream_table.streams[st_idx];
    guard qstream.send_state == QuicSendState.Ready || qstream.send_state == QuicSendState.Send else {
        return 0, false;
    }

    let s_slot = find_or_alloc_stream_slot(c_idx, conn_id, stream_id, true);
    guard s_slot >= 0 else { return 0, false; }
    let tx .= g_quic_srv_stream_tx[s_slot];
    guard !tx.tx_fin_queued else { return 0, false; }

    let cap_rem = core::sub_sat_u64(QUIC_SRV_MAX_STREAM_TX_BUF, tx.tx_buf_len);
    let take = min(data.len as u64, cap_rem);
    let take_i = take as i64;
    if take > 0 {
        guard slab_write_at(tx.tx_slabs, tx.tx_head_off, tx.tx_buf_len, tx.tx_buf_len, data[..take_i]) else {
            return 0, false;
        }
    }
    if fin && take == (data.len as u64) {
        tx.tx_fin_queued = true;
    }
    return take_i, true;
}

// Closes connection `conn_id` cleanly by queuing an immediate RFC 9000 Section 10.2 `CONNECTION_CLOSE`.
fn quic_server_close_conn(
    ep:        QuicServerEndpoint&,
    conn_id:   u64,
    app_error: u64,
    reason:    const u8[:],
) {
    let ep_idx = lookup_live_ep_idx(ep);
    guard ep_idx >= 0 else { return; }
    let eslot .= g_quic_srv_endpoints[ep_idx];
    let c_idx = find_conn_idx_by_id(ep_idx, eslot.generation, conn_id);
    guard c_idx >= 0 else { return; }
    let cslot .= g_quic_srv_conns[c_idx];
    close_conn_with_error(eslot, cslot, app_error, reason, true);
    if cslot.last_activity_ns > 0 {
        let pto_us = compute_pto_duration(cslot.conn.rtt, 0, true);
        let drain_ns = core::mul_sat_u64(core::mul_sat_u64(pto_us, 3), 1000);
        cslot.drain_deadline_ns = core::add_sat_u64(cslot.last_activity_ns, drain_ns);
    }
}
