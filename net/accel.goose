// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// OS completion and readiness accelerator runtime for share-nothing reactors.
// Encapsulates Linux io_uring, Windows RIO, macOS kqueue, and epoll/WSAPoll
// registration, lazy slab buffer ownership, and transmit/receive submission behind
// `ReactorAccelRuntime` so server engines stay independent of driver rings.
namespace net;

import std;
import core from "..";
import net.driver;
import .tcp;
import .internal;

enum ReactorAccelMode {
    Auto,
    IoUring,
    Rio,
    Kqueue,
    PollFallback,
}

const REACTOR_ACCEL_SLOTS:      i64 = 64;
const REACTOR_ACCEL_BUF_SIZE:   i64 = 4096;
const REACTOR_ACCEL_SLAB_BYTES: i64 = 524288;
const REACTOR_TLS_CT_CAP:       i64 = 16648;

const REACTOR_REQ_RX_TAG: u64 = 1;
const REACTOR_REQ_TX_TAG: u64 = 2;

const REACTOR_URING_TAG_ACCEPT:    u64 = 0x100000000;
const REACTOR_URING_TAG_RECV:      u64 = 0x200000000;
const REACTOR_URING_TAG_SEND:      u64 = 0x300000000;
const REACTOR_URING_TAG_POLL:      u64 = 0x400000000;
const REACTOR_URING_TAG_KIND_MASK: u64 = 0xF00000000;
const REACTOR_ACCEL_SLOT_MASK:     u64 = 0xFFFF;
const REACTOR_ACCEL_GEN_SHIFT:     u32 = 16;
const REACTOR_ACCEL_GEN_MASK:      u64 = 0xFFFF;
const REACTOR_URING_PBUF_BGID:     u16 = 1;
const REACTOR_KQUEUE_EV_ERROR:     u16 = 0x4000;

struct ReactorAccelRuntime {
    mode:                  ReactorAccelMode           = ReactorAccelMode.PollFallback,
    epfd:                  i64                        = -1,
    kq_fd:                 i64                        = -1,
    kq_changes:            net_internal::Kevent[..16] = [],
    uring_fd:              i64                        = -1,
    uring_pbuf:            u64                        = 0,
    rio_cq:                u64                        = 0,
    rio_tx_cq:             u64                        = 0,
    rio_buf_id:            u64                        = 0,
    rio_listener_fd:       i64                        = -1,
    active_accel_slots:    i64                        = 0,
    epfd_registered_count: i32                        = 0,
    slot_accel:            bool[64]                   = [false; 64],
    slot_ktls_rx:          bool[64]                   = [false; 64],
    slot_rio_rq:           u64[64]                    = [0; 64],
    slot_gen:              u16[64]                    = [1; 64],
    slot_tx_inflight:      bool[64]                   = [false; 64],
    slot_close_after_tx:   bool[64]                   = [false; 64],
    rio_tx_close_queue:    i64[..64]                  = [],
    slab:                  u8[>..]                    = [],
}

inline fn ensure_reactor_accel_slab(accel: ReactorAccelRuntime&) {
    if accel.slab.len < REACTOR_ACCEL_SLAB_BYTES {
        accel.slab.resize(REACTOR_ACCEL_SLAB_BYTES, 0);
    }
}

inline fn reactor_accel_slot_token(accel: const ReactorAccelRuntime&, slot: i64) -> u64 {
    return core::shl_sat_u64(accel.slot_gen[slot], REACTOR_ACCEL_GEN_SHIFT) | (slot as u64);
}

inline fn reactor_accel_match_token(accel: const ReactorAccelRuntime&, token: u64) -> i64, bool {
    let slot = (token & REACTOR_ACCEL_SLOT_MASK) as i64;
    guard slot >= 0 && slot < REACTOR_ACCEL_SLOTS && accel.slot_accel[slot] else { return -1, false; }
    let gen = ((token >> REACTOR_ACCEL_GEN_SHIFT) & REACTOR_ACCEL_GEN_MASK) as u16;
    guard gen != 0 && gen == accel.slot_gen[slot] else { return -1, false; }
    return slot, true;
}

// Opens a listening TCP socket configured for OS completion accelerators when supported.
fn listen_accelerated_tcp(
    host:       const u8[:],
    port:       u16,
    accel_mode: ReactorAccelMode,
    backlog:    i32 = 128,
) -> i64 {
    let plat = net_internal::detect_target_platform();
    let want_rio = accel_mode == ReactorAccelMode.Auto || accel_mode == ReactorAccelMode.Rio;
    if plat == net_internal::TargetPlatform.Windows && want_rio && net_internal::native_rio_available() == 1 {
        let fd = net_internal::rio_listen(host, port, backlog);
        if fd > 0 {
            return fd;
        }
    }
    return tcp_listen(host, port);
}

fn reactor_queue_kq_change(accel: ReactorAccelRuntime&, fd: i64, flags: u16, udata: u64) {
    guard accel.kq_fd >= 0 && fd > 0 else { return; }
    let ev = net_internal::Kevent {
        ident:  fd as u64,
        filter: net_internal::EVFILT_READ,
        flags:  flags,
        fflags: 0,
        data:   0,
        udata:  udata,
    };
    if !accel.kq_changes.try_push(ev) {
        var ignored: net_internal::Kevent[1] = [net_internal::Kevent { .. }];
        let _ = net_internal::kqueue_poll_slice(accel.kq_fd, accel.kq_changes[..], ignored[..], 0);
        accel.kq_changes.clear();
        let _ = accel.kq_changes.try_push(ev);
    }
}

fn reactor_arm_uring_accept(accel: ReactorAccelRuntime&, listener_fd: i64) {
    guard accel.uring_fd >= 0 && listener_fd > 0 else { return; }
    var sqe = net_internal::UringSqe { .. };
    net_internal::uring_prep_accept_multishot(sqe, listener_fd as i32, REACTOR_URING_TAG_ACCEPT);
    var batch: net_internal::UringSqe[1] = [sqe];
    let _ = net_internal::uring_submit_sqes(accel.uring_fd, batch[..]);
}

fn reactor_arm_uring_slot_rx(accel: ReactorAccelRuntime&, slot: i64, fd: i64) {
    guard accel.uring_fd >= 0 && slot >= 0 && slot < REACTOR_ACCEL_SLOTS && fd > 0 else { return; }
    var sqe = net_internal::UringSqe { .. };
    let tok = reactor_accel_slot_token(accel, slot);
    if accel.slot_ktls_rx[slot] {
        net_internal::uring_prep_poll_add(sqe, fd as i32, 1, REACTOR_URING_TAG_POLL | tok);
    } else {
        net_internal::uring_prep_sqe_recv_multishot(
            sqe, fd as i32, REACTOR_URING_PBUF_BGID, REACTOR_URING_TAG_RECV | tok,
        );
    }
    var batch: net_internal::UringSqe[1] = [sqe];
    let _ = net_internal::uring_submit_sqes(accel.uring_fd, batch[..]);
}

fn reactor_post_rio_slot_rx(accel: ReactorAccelRuntime&, slot: i64) -> bool {
    guard slot >= 0 && slot < REACTOR_ACCEL_SLOTS && accel.slot_rio_rq[slot] != 0 else { return false; }
    let rx_off = core::shl_sat_u64(slot as u64, 13) as u32;
    return net_internal::native_rio_post_recv(
        accel.slot_rio_rq[slot],
        accel.rio_buf_id,
        rx_off,
        REACTOR_ACCEL_BUF_SIZE as u32,
        REACTOR_REQ_RX_TAG,
    ) == 0;
}

fn reactor_reset_accel_slot(accel: ReactorAccelRuntime&, slot: i64) {
    guard slot >= 0 && slot < REACTOR_ACCEL_SLOTS else { return; }
    net_internal::reactor_cancel_uring_slot(accel, slot);
    if accel.slot_accel[slot] {
        accel.active_accel_slots = max(core::sub_sat_i64(accel.active_accel_slots, 1), 0);
    }
    accel.slot_accel[slot] = false;
    accel.slot_ktls_rx[slot] = false;
    accel.slot_rio_rq[slot] = 0;
    accel.slot_tx_inflight[slot] = false;
    accel.slot_close_after_tx[slot] = false;
    accel.slot_gen[slot] = if accel.slot_gen[slot] >= 65535 {
        1
    } else {
        core::add_sat_u64(accel.slot_gen[slot], 1) as u16
    };
}

fn reactor_close_accel(accel: ReactorAccelRuntime&) {
    if accel.rio_listener_fd > 0 {
        let _ = net_internal::native_rio_cancel_accept(accel.rio_listener_fd);
        accel.rio_listener_fd = -1;
    }
    if accel.rio_buf_id != 0 {
        net_internal::native_rio_deregister_buffer(accel.rio_buf_id);
        accel.rio_buf_id = 0;
    }
    if accel.rio_cq != 0 {
        net_internal::native_rio_close_cq(accel.rio_cq);
        accel.rio_cq = 0;
    }
    if accel.rio_tx_cq != 0 {
        net_internal::native_rio_close_cq(accel.rio_tx_cq);
        accel.rio_tx_cq = 0;
    }
    accel.rio_tx_close_queue.clear();
    if accel.uring_pbuf != 0 {
        net_internal::uring_free_pbuf_ring(accel.uring_pbuf);
        accel.uring_pbuf = 0;
    }
    if accel.uring_fd >= 0 {
        net_internal::native_uring_close(accel.uring_fd);
        accel.uring_fd = -1;
    }
    if accel.kq_fd >= 0 {
        net_internal::native_kqueue_close(accel.kq_fd);
        accel.kq_fd = -1;
    }
    if accel.epfd >= 0 {
        epoll_close(accel.epfd);
        accel.epfd = -1;
    }
    accel.kq_changes.clear();
    accel.active_accel_slots = 0;
    accel.epfd_registered_count = 0;
    accel.mode = ReactorAccelMode.PollFallback;
}

fn reactor_init_accel(accel: ReactorAccelRuntime&, requested: ReactorAccelMode, listener_fd: i64) -> bool {
    reactor_close_accel(accel);
    for s in REACTOR_ACCEL_SLOTS {
        reactor_reset_accel_slot(accel, s);
    }
    accel.epfd = epoll_create();
    let plat = net_internal::detect_target_platform();

    if plat == net_internal::TargetPlatform.Linux &&
        (requested == ReactorAccelMode.Auto || requested == ReactorAccelMode.IoUring) &&
        net_internal::reactor_try_open_uring(accel, listener_fd) {
        return true;
    }
    if plat == net_internal::TargetPlatform.Windows &&
        (requested == ReactorAccelMode.Auto || requested == ReactorAccelMode.Rio) &&
        net_internal::reactor_try_open_rio(accel, listener_fd) {
        return true;
    }
    if plat == net_internal::TargetPlatform.Darwin &&
        (requested == ReactorAccelMode.Auto || requested == ReactorAccelMode.Kqueue) &&
        net_internal::reactor_try_open_kqueue(accel, listener_fd) {
        return true;
    }

    guard accel.epfd >= 0 else {
        reactor_close_accel(accel);
        return false;
    }
    accel.mode = ReactorAccelMode.PollFallback;
    if listener_fd > 0 {
        tcp_set_nonblocking(listener_fd, true);
        if epoll_add(accel.epfd, listener_fd, EPOLL_READ, EPOLL_LISTENER_TAG) {
            accel.epfd_registered_count = core::add_sat_i64(accel.epfd_registered_count, 1) as i32;
        }
    }
    return true;
}

fn reactor_bind_slot_backend(accel: ReactorAccelRuntime&, slot: i64, client_fd: i64) {
    if accel.mode == ReactorAccelMode.Rio && slot >= 0 && slot < REACTOR_ACCEL_SLOTS && !accel.slot_ktls_rx[slot] {
        let tok = reactor_accel_slot_token(accel, slot);
        let rq = net_internal::native_rio_create_rq_ctx(client_fd, 16, 16, accel.rio_cq, accel.rio_tx_cq, tok);
        if rq != 0 {
            accel.slot_rio_rq[slot] = rq;
            accel.slot_accel[slot] = true;
            if reactor_post_rio_slot_rx(accel, slot) {
                accel.active_accel_slots = core::add_sat_i64(accel.active_accel_slots, 1);
                return;
            }
            accel.slot_accel[slot] = false;
            accel.slot_rio_rq[slot] = 0;
        }
    } else if accel.mode == ReactorAccelMode.IoUring && slot >= 0 && slot < REACTOR_ACCEL_SLOTS {
        accel.slot_accel[slot] = true;
        accel.active_accel_slots = core::add_sat_i64(accel.active_accel_slots, 1);
        reactor_arm_uring_slot_rx(accel, slot, client_fd);
        return;
    } else if accel.mode == ReactorAccelMode.Kqueue && accel.kq_fd >= 0 {
        reactor_queue_kq_change(accel, client_fd, net_internal::EV_ADD | net_internal::EV_ENABLE, slot as u64);
        return;
    }
    if accel.epfd >= 0 {
        if epoll_add(accel.epfd, client_fd, EPOLL_READ, slot as u64) {
            accel.epfd_registered_count = core::add_sat_i64(accel.epfd_registered_count, 1) as i32;
        }
    }
}

// Flushes cork aggregation buffer to connection via bounded non-blocking send loop.
inline fn reactor_drain_cork_wire(conn: i64, wire: const u8[:]) -> bool {
    var sent_total: i64 = 0;
    var retries:    i32 = 0;
    while sent_total < wire.len {
        let sent = tcp_send(conn, wire[sent_total..]);
        if sent > 0 {
            sent_total = core::add_sat_i64(sent_total, sent);
            retries = 0;
            continue;
        }
        guard sent == -2 && retries < 2000 else { return false; }
        retries = core::add_sat_i64(retries, 1) as i32;
        if retries > 64 {
            sleep_ms(1);
        }
    }
    return true;
}

fn reactor_drain_rio_tx_cq(accel: ReactorAccelRuntime&) -> u32 {
    guard accel.rio_tx_cq != 0 else { return 0; }
    var tx_results: net_internal::RioResult[..64] = [];
    let n = net_internal::rio_drain_completions(accel.rio_tx_cq, tx_results);
    for i in tx_results.len {
        let s, ok_tok = reactor_accel_match_token(accel, tx_results[i].socket_context);
        if !ok_tok { continue; }
        accel.slot_tx_inflight[s] = false;
        if tx_results[i].status != 0 {
            accel.slot_close_after_tx[s] = true;
        }
        if accel.slot_close_after_tx[s] {
            let _ = accel.rio_tx_close_queue.try_push(s);
        }
    }
    return n;
}

fn reactor_wait_rio_slot_tx(accel: ReactorAccelRuntime&, slot: i64) -> bool {
    guard slot >= 0 && slot < REACTOR_ACCEL_SLOTS && accel.rio_tx_cq != 0 else { return false; }
    var spins: i32 = 0;
    while accel.slot_tx_inflight[slot] && spins < 500 {
        let _ = reactor_drain_rio_tx_cq(accel);
        if !accel.slot_tx_inflight[slot] {
            break;
        }
        let _ = net_internal::rio_wait_cq(accel.rio_tx_cq, 2);
        spins = core::add_sat_i64(spins, 1) as i32;
    }
    return !accel.slot_tx_inflight[slot] && !accel.slot_close_after_tx[slot];
}

fn reactor_submit_rio_tx(accel: ReactorAccelRuntime&, slot: i64, wire: const u8[:]) -> bool {
    guard slot >= 0 && slot < REACTOR_ACCEL_SLOTS && accel.slot_rio_rq[slot] != 0 else { return false; }
    ensure_reactor_accel_slab(accel);
    let tx_off_u32 = (core::shl_sat_u64(slot as u64, 13) as u32) | 4096;
    let tx_off = tx_off_u32 as i64;
    var off: i64 = 0;
    while off < wire.len {
        if accel.slot_tx_inflight[slot] {
            guard reactor_wait_rio_slot_tx(accel, slot) else { return false; }
        }
        let rem = core::sub_sat_i64(wire.len, off);
        let chunk_len = min(rem, REACTOR_ACCEL_BUF_SIZE);
        for i in chunk_len {
            accel.slab[core::add_sat_i64(tx_off, i)] = wire[core::add_sat_i64(off, i)];
        }
        let rc = net_internal::native_rio_post_send(
            accel.slot_rio_rq[slot], accel.rio_buf_id, tx_off_u32, chunk_len as u32, REACTOR_REQ_TX_TAG,
        );
        guard rc == 0 else { return false; }
        accel.slot_tx_inflight[slot] = true;
        off = core::add_sat_i64(off, chunk_len);
    }
    return true;
}

fn reactor_submit_accel_tx(accel: ReactorAccelRuntime&, slot: i64, conn: i64, wire: const u8[:]) -> bool {
    if accel.mode == ReactorAccelMode.Rio && accel.slot_rio_rq[slot] != 0 {
        return reactor_submit_rio_tx(accel, slot, wire);
    }
    let can_uring = accel.mode == ReactorAccelMode.IoUring && accel.uring_fd >= 0;
    if can_uring && wire.len <= REACTOR_ACCEL_BUF_SIZE && !accel.slot_tx_inflight[slot] {
        ensure_reactor_accel_slab(accel);
        let tx_off_u32 = (core::shl_sat_u64(slot as u64, 13) as u32) | 4096;
        let tx_off = tx_off_u32 as i64;
        let tx_end = core::add_sat_i64(tx_off, wire.len);
        for i in wire.len {
            accel.slab[core::add_sat_i64(tx_off, i)] = wire[i];
        }
        var sqe = net_internal::UringSqe { .. };
        let tok = reactor_accel_slot_token(accel, slot);
        net_internal::uring_prep_send_slice(
            sqe, conn as i32, accel.slab[tx_off..tx_end], REACTOR_URING_TAG_SEND | tok,
        );
        var batch: net_internal::UringSqe[1] = [sqe];
        if net_internal::uring_submit_sqes(accel.uring_fd, batch[..]) > 0 {
            accel.slot_tx_inflight[slot] = true;
            return true;
        }
    }
    return reactor_drain_cork_wire(conn, wire);
}

fn reactor_wait_readiness_events(
    accel:       ReactorAccelRuntime&,
    ready_udata: u64[:],
    timeout_ms:  i32,
) -> i32 {
    if accel.mode == ReactorAccelMode.Kqueue && accel.kq_fd >= 0 {
        var kev_out: net_internal::Kevent[128] = [net_internal::Kevent { .. }; 128];
        let timeout_ns = net_internal::timeout_ms_to_ns(timeout_ms);
        let n_kq = net_internal::kqueue_poll_slice(accel.kq_fd, accel.kq_changes[..], kev_out[..], timeout_ns);
        accel.kq_changes.clear();
        guard n_kq > 0 else { return 0; }
        let limit = min(min(n_kq as i64, 128), ready_udata.len);
        var out_idx: i64 = 0;
        for i in limit {
            if (kev_out[i].flags & REACTOR_KQUEUE_EV_ERROR) == 0 {
                ready_udata[out_idx] = kev_out[i].udata;
                out_idx = core::add_sat_i64(out_idx, 1);
            }
        }
        return out_idx as i32;
    }

    guard accel.epfd >= 0 else { return 0; }
    let rio_has_work = accel.active_accel_slots > 0 || accel.rio_listener_fd > 0;
    if accel.epfd_registered_count == 0 &&
        ((accel.mode == ReactorAccelMode.Rio && rio_has_work) || accel.mode == ReactorAccelMode.IoUring) {
        return 0;
    }
    var empty_fds: i64[0] = [];
    let eff_timeout = if accel.mode == ReactorAccelMode.IoUring ||
        (accel.mode == ReactorAccelMode.Rio && rio_has_work) {
        0
    } else {
        timeout_ms
    };
    return net_internal::epoll_wait_direct(accel.epfd, empty_fds[..], ready_udata, eff_timeout);
}

fn reactor_detach_listener(accel: ReactorAccelRuntime&, listener_fd: i64) {
    guard listener_fd > 0 else { return; }
    if accel.rio_listener_fd == listener_fd {
        net_internal::native_rio_cancel_accept(listener_fd);
        accel.rio_listener_fd = -1;
    }
    if accel.kq_fd >= 0 {
        reactor_queue_kq_change(accel, listener_fd, net_internal::EV_DELETE, EPOLL_LISTENER_TAG);
    }
    if accel.uring_fd >= 0 {
        var sqe = net_internal::UringSqe { .. };
        net_internal::uring_prep_cancel(sqe, REACTOR_URING_TAG_ACCEPT);
        var batch: net_internal::UringSqe[1] = [sqe];
        let _ = net_internal::uring_submit_sqes(accel.uring_fd, batch[..]);
    }
    if accel.epfd >= 0 {
        if epoll_del(accel.epfd, listener_fd) {
            accel.epfd_registered_count = max(0, core::sub_sat_i64(accel.epfd_registered_count, 1)) as i32;
        }
    }
}
