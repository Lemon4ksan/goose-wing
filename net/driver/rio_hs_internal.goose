// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Synchronous TLS-over-RIO handshake bridge and CQ completion deferral queue.
// Uses a thread-local page-locked 8 KB slab registered lazily on first handshake so
// tls::server_handshake can drive blocking TCP sends/recvs over an accepted RIO RQ.
namespace net_internal;

import std;
import os;
import core;
import net.driver.rio;

const RIO_HS_SLAB_BYTES: i64 = 8192;
const RIO_HS_BUF_SIZE:   u32 = 4096;
const RIO_HS_DEFER_CAP:  i64 = 256;
const RIO_CORRUPT_CQ_RC: i32 = -1;

struct RioHsCtx {
    active:       bool                  = false,
    fd:           i64                   = -1,
    rq:           u64                   = 0,
    rx_cq:        u64                   = 0,
    tx_cq:        u64                   = 0,
    hs_buf_id:    u64                   = 0,
    hs_slab:      u8[RIO_HS_SLAB_BYTES] = [0; RIO_HS_SLAB_BYTES],
    sock_ctx:     u64                   = 0,
    rx_stash:     u8[4096]              = [0; 4096],
    rx_stash_pos: i64                   = 0,
    rx_stash_len: i64                   = 0,
    rx_inflight:  bool                  = false,
    def_rx_cq:    u64                   = 0,
    def_rx:       RioResult[..256]      = [],
    def_tx_cq:    u64                   = 0,
    def_tx:       RioResult[..256]      = [],
}

var g_rio_hs: RioHsCtx = RioHsCtx { .. };

inline fn rio_hs_is_active(fd: i64) -> bool {
    return g_rio_hs.active && fd > 0 && fd == g_rio_hs.fd;
}

inline fn rio_hs_ensure_registered() -> bool {
    if g_rio_hs.hs_buf_id != 0 {
        return true;
    }
    let bid = native_rio_register_slice(g_rio_hs.hs_slab[..]);
    guard bid != 0 else { return false; }
    g_rio_hs.hs_buf_id = bid;
    return true;
}

inline fn rio_hs_defer_push_rx(cq: u64, res: const RioResult&) {
    if g_rio_hs.def_rx_cq != cq {
        g_rio_hs.def_rx_cq = cq;
        g_rio_hs.def_rx.clear();
    }
    if g_rio_hs.def_rx.len < RIO_HS_DEFER_CAP {
        let _ = g_rio_hs.def_rx.try_push(res);
    }
}

inline fn rio_hs_defer_push_tx(cq: u64, res: const RioResult&) {
    if g_rio_hs.def_tx_cq != cq {
        g_rio_hs.def_tx_cq = cq;
        g_rio_hs.def_tx.clear();
    }
    if g_rio_hs.def_tx.len < RIO_HS_DEFER_CAP {
        let _ = g_rio_hs.def_tx.try_push(res);
    }
}

// Begins TLS handshake I/O interception over an accepted Windows RIO request queue.
fn rio_hs_begin(sock_fd: i64, rq_id: u64, rx_cq: u64, tx_cq: u64, sock_ctx: u64) {
    let buf_ok = rio_hs_ensure_registered();
    g_rio_hs.active = buf_ok && sock_fd > 0 && rq_id != 0 && rx_cq != 0 && tx_cq != 0;
    g_rio_hs.fd = sock_fd;
    g_rio_hs.rq = rq_id;
    g_rio_hs.rx_cq = rx_cq;
    g_rio_hs.tx_cq = tx_cq;
    g_rio_hs.sock_ctx = sock_ctx;
    g_rio_hs.rx_stash_pos = 0;
    g_rio_hs.rx_stash_len = 0;
    g_rio_hs.rx_inflight = false;
}

inline fn rio_hs_is_rx_inflight() -> bool {
    return g_rio_hs.rx_inflight;
}

// Ends TLS handshake I/O interception and copies any unread stashed bytes into `out_leftover`.
// Returns number of leftover bytes copied.
fn rio_hs_end(out_leftover: u8[:]) -> i32 {
    var rem: i64 = 0;
    if g_rio_hs.active && g_rio_hs.rx_stash_pos < g_rio_hs.rx_stash_len {
        let avail = g_rio_hs.rx_stash_len - g_rio_hs.rx_stash_pos;
        if out_leftover.len > 0 {
            rem = min(avail, out_leftover.len);
            for i in rem {
                out_leftover[i] = g_rio_hs.rx_stash[g_rio_hs.rx_stash_pos + i];
            }
        }
    }
    g_rio_hs.active = false;
    g_rio_hs.fd = -1;
    g_rio_hs.rx_stash_pos = 0;
    g_rio_hs.rx_stash_len = 0;
    g_rio_hs.rx_inflight = false;
    return rem as i32;
}

inline fn rio_hs_copy_from_stash(dst: u8[:]) -> i32 {
    let avail = g_rio_hs.rx_stash_len - g_rio_hs.rx_stash_pos;
    let take = min(dst.len, avail);
    for i in take {
        dst[i] = g_rio_hs.rx_stash[g_rio_hs.rx_stash_pos + i];
    }
    g_rio_hs.rx_stash_pos += take;
    return take as i32;
}

inline fn rio_hs_scan_rx_batch(batch: const RioResult[64]&, count: i64) -> RioResult, bool {
    var matched = false;
    var mres = RioResult { .. };
    for i in count {
        if !matched && batch[i].socket_context == g_rio_hs.sock_ctx {
            matched = true;
            mres = batch[i];
        } else {
            rio_hs_defer_push_rx(g_rio_hs.rx_cq, batch[i]);
        }
    }
    return mres, matched;
}

inline fn rio_hs_stash_rx_result(mres: const RioResult&, dst: u8[:]) -> i32 {
    g_rio_hs.rx_inflight = false;
    if mres.status != 0 || mres.bytes_transferred == 0 {
        return 0;
    }
    let got = min(mres.bytes_transferred as i64, RIO_HS_BUF_SIZE);
    for i in got {
        g_rio_hs.rx_stash[i] = g_rio_hs.hs_slab[i];
    }
    g_rio_hs.rx_stash_pos = 0;
    g_rio_hs.rx_stash_len = got;
    return rio_hs_copy_from_stash(dst);
}

// Blocking receive over Windows RIO during TLS server handshake.
fn rio_hs_recv(sock_fd: i64, dst: u8[:], timeout_ms: u32) -> i32 {
    guard g_rio_hs.active && sock_fd == g_rio_hs.fd && dst.len > 0 else { return -1; }
    if g_rio_hs.rx_stash_pos < g_rio_hs.rx_stash_len {
        return rio_hs_copy_from_stash(dst);
    }
    guard g_rio_hs.hs_buf_id != 0 else { return -1; }
    if !g_rio_hs.rx_inflight {
        let rc = native_rio_post_recv(g_rio_hs.rq, g_rio_hs.hs_buf_id, 0, RIO_HS_BUF_SIZE, 1);
        guard rc == 0 else { return -1; }
        g_rio_hs.rx_inflight = true;
    }

    let eff_ms: u64 = if timeout_ms > 0 { timeout_ms } else { 5000 };
    let deadline_ns = (clock_ns() as u64) + eff_ms * 1000000;
    var batch: RioResult[64] = [RioResult { .. }; 64];

    while true {
        let n = native_rio_dequeue_slice(g_rio_hs.rx_cq, batch[..]);
        if n == RIO_CORRUPT_CQ_RC {
            return -1;
        }
        if n > 0 {
            let mres, matched = rio_hs_scan_rx_batch(batch, min(n as i64, 64));
            if matched {
                return rio_hs_stash_rx_result(mres, dst);
            }
            continue;
        }
        let now_ns = clock_ns() as u64;
        if now_ns >= deadline_ns {
            return -2;
        }
        let rem_ms = min((deadline_ns - now_ns) / 1000000, 5) as i32;
        let _ = rio_wait_cq(g_rio_hs.rx_cq, max(rem_ms, 1));
    }
    return -1;
}

inline fn rio_hs_scan_tx_batch(batch: const RioResult[64]&, count: i64) -> i32 {
    var state: i32 = 0;
    for i in count {
        if state == 0 && batch[i].socket_context == g_rio_hs.sock_ctx {
            state = if batch[i].status != 0 { -1 } else { 1 };
        } else {
            rio_hs_defer_push_tx(g_rio_hs.tx_cq, batch[i]);
        }
    }
    return state;
}

inline fn rio_hs_wait_tx_completion(batch: RioResult[64]&) -> bool {
    let deadline_ns = (clock_ns() as u64) + 5000000000;
    while true {
        let n = native_rio_dequeue_slice(g_rio_hs.tx_cq, batch[..]);
        if n == RIO_CORRUPT_CQ_RC { return false; }
        if n > 0 {
            let st = rio_hs_scan_tx_batch(batch, min(n as i64, 64));
            if st < 0 { return false; }
            if st > 0 { return true; }
            continue;
        }
        if (clock_ns() as u64) >= deadline_ns { return false; }
        let _ = rio_wait_cq(g_rio_hs.tx_cq, 2);
    }
    return false;
}

// Blocking send over Windows RIO during TLS server handshake.
fn rio_hs_send(sock_fd: i64, data: const u8[:]) -> i32 {
    guard g_rio_hs.active && sock_fd == g_rio_hs.fd && data.len > 0 else { return -1; }
    guard g_rio_hs.hs_buf_id != 0 else { return -1; }
    var off:   i64           = 0;
    var batch: RioResult[64] = [RioResult { .. }; 64];

    while off < data.len {
        let chunk = min(data.len - off, RIO_HS_BUF_SIZE);
        for i in chunk {
            g_rio_hs.hs_slab[4096 + i] = data[off + i];
        }
        let rc = native_rio_post_send(g_rio_hs.rq, g_rio_hs.hs_buf_id, 4096, chunk as u32, 2);
        guard rc == 0 else { return -1; }
        guard rio_hs_wait_tx_completion(batch) else { return -1; }
        off += chunk;
    }
    return off as i32;
}

inline fn drain_deferred_queue(
    cq_id:       u64,
    def_cq:      u64&,
    def_q:       RioResult[..256]&,
    out_results: RioResult[..64]&,
) {
    guard cq_id == def_cq && def_q.len > 0 else { return; }
    let space = 64 - out_results.len;
    let take = min(def_q.len, space);
    for i in take {
        let _ = out_results.try_push(def_q[i]);
    }
    if take >= def_q.len {
        def_q.clear();
        return;
    }
    let rem = def_q.len - take;
    for i in rem {
        def_q[i] = def_q[take + i];
    }
    def_q.resize(rem);
}

// Drains completed Windows RIO operations into a bounded `RioResult[..64]` slice.
// Returns `-1` if the CQ latched `RIO_CORRUPT_CQ`.
fn rio_drain_completions(cq_id: u64, out_results: RioResult[..64]&) -> i32 {
    guard cq_id != 0 else { return 0; }
    out_results.clear();
    drain_deferred_queue(cq_id, g_rio_hs.def_rx_cq, g_rio_hs.def_rx, out_results);
    if out_results.len == 0 {
        drain_deferred_queue(cq_id, g_rio_hs.def_tx_cq, g_rio_hs.def_tx, out_results);
    }
    let rem = 64 - out_results.len;
    guard rem > 0 else { return out_results.len as i32; }
    var raw: RioResult[64] = [RioResult { .. }; 64];
    let n = native_rio_dequeue_slice(cq_id, raw[..rem]);
    guard n >= 0 else { return -1; }
    guard n > 0 else { return out_results.len as i32; }
    let count = min(n as i64, rem);
    for i in count {
        let _ = out_results.try_push(raw[i]);
    }
    return out_results.len as i32;
}
