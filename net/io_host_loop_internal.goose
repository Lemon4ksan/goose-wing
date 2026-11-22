// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Event dispatch and backend poll loops for net::Host.
namespace net_internal;

import std;
import core;
import net.driver;
import .tcp;
import .transport;
import .internal;
import .io_host;
import .io_host_internal;

struct UnusedHostArg {}

inline fn dispatch_host_ctx_event<D>(
    driver: D&,
    host:   net::Host&,
    _a:     UnusedHostArg&,
    _b:     UnusedHostArg&,
    ev:     const core::LinkEvent&,
) {
    core::on_link_event(driver, host, ev);
}

inline fn emit_host_event<D, CtxA, CtxB>(
    host:   net::Host&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    ev:     const core::LinkEvent&,
    count:  i32&,
) {
    driver.dispatch_host_ctx_event(host, arg_a, arg_b, ev);
    count = core::add_sat_i64(count, 1) as i32;
}

fn dispatch_host_wakes<D, CtxA, CtxB>(
    host:   net::Host&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    count:  i32&,
) {
    let pending = host.wake_queue.len;
    guard pending > 0 else { return; }
    for i in pending {
        guard host.is_open && i < host.wake_queue.len else { break; }
        let tok = host.wake_queue[i];
        let ev = core::LinkEvent {
            kind:  core::LinkEventKind.Wake,
            tag:   tok.slot,
            token: tok,
            ..
        };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
    }
    guard host.is_open else { return; }
    if host.wake_queue.len <= pending {
        host.wake_queue.clear();
        return;
    }
    let rem = core::sub_sat_i64(host.wake_queue.len, pending);
    for j in rem {
        host.wake_queue[j] = host.wake_queue[core::add_sat_i64(pending, j)];
    }
    host.wake_queue.resize(rem);
}

fn dispatch_host_timers<D, CtxA, CtxB>(
    host:   net::Host&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    now_ns: u64,
    count:  i32&,
) {
    guard host.active_timers > 0 else { return; }
    let n_timers = host.timers.len;
    for i in n_timers {
        guard host.is_open && i < host.timers.len else { break; }
        guard host.timers[i].active && now_ns >= host.timers[i].deadline_ns else { continue; }
        let tid = host.timers[i].timer_id;
        let tag = host.timers[i].tag;
        let owner = host.timers[i].owner;
        if host.timers[i].interval_ns > 0 {
            host.timers[i].deadline_ns = core::add_sat_u64(now_ns, host.timers[i].interval_ns);
        } else {
            host.timers[i].active = false;
            host.timers[i].timer_id = 0;
            host.timers[i].next_free = host.free_timer_head;
            host.free_timer_head = i as i32;
            if host.active_timers > 0 {
                host.active_timers = core::sub_sat_i64(host.active_timers, 1);
            }
        }
        let ev = core::LinkEvent {
            kind:     core::LinkEventKind.Timer,
            link:     core::make_io_link(owner, 1, 0),
            tag:      tag,
            timer_id: tid,
            ..
        };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
    }
}

fn drain_virtual_slot<D, CtxA, CtxB>(
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    slot:       i64,
    count:      i32&,
) {
    let gen = host.links[slot].gen;
    let link = host_slot_link(host, slot);
    let pidx = host.links[slot].virtual_pair;
    guard pidx >= 0 && pidx < net::MAX_VIRTUAL_PIPES else { return; }
    let is_b = host.links[slot].is_b_end;
    if host.links[slot].want_write {
        let tx_avail = if is_b {
            core::available(net::g_virtual_pipes[pidx].b_to_a)
        } else {
            core::available(net::g_virtual_pipes[pidx].a_to_b)
        };
        if tx_avail > 0 {
            host.links[slot].want_write = false;
            let ev = core::LinkEvent {
                kind: core::LinkEventKind.Writable, link: link, tag: host.links[slot].tag, ..
            };
            emit_host_event(host, driver, arg_a, arg_b, ev, count);
            guard host.links[slot].in_use && host.links[slot].gen == gen else { return; }
        }
    }
    guard !host.links[slot].rx_paused else { return; }
    ensure_rx_scratch(rx_scratch);
    let rc = net::virtual_pipe_recv(pidx as u16, is_b, rx_scratch[..]);
    if rc > 0 {
        let ev = core::LinkEvent {
            kind: core::LinkEventKind.Data,
            link: link,
            tag:  host.links[slot].tag,
            data: rx_scratch[..rc],
            ..
        };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
    } else if rc == 0 && !host.links[slot].virtual_eof_sent {
        host.links[slot].virtual_eof_sent = true;
        let ev = core::LinkEvent {
            kind: core::LinkEventKind.Eof, link: link, tag: host.links[slot].tag, ..
        };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
    } else if rc == -1 {
        let tag = host.links[slot].tag;
        release_host_slot(host, slot);
        let ev = core::LinkEvent {
            kind: core::LinkEventKind.Closed,
            link: link,
            tag:  tag,
            err:  core::IoError.Closed,
            ..
        };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
    }
}

fn dispatch_virtual_links<D, CtxA, CtxB>(
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    count:      i32&,
) {
    guard host.virt_head >= 0 else { return; }
    var batch: i32[>..] = [];
    var cur:   i64      = host.virt_head;
    while cur >= 0 && cur < host.links.len {
        batch.push(cur as i32);
        cur = host.links[cur].virt_next;
    }
    for i in batch.len {
        let slot: i64 = batch[i];
        guard host.is_open else { break; }
        if slot >= 0 && slot < host.links.len &&
           host.links[slot].in_use && host.links[slot].kind == LinkKind.Virtual {
            drain_virtual_slot(host, driver, arg_a, arg_b, rx_scratch, slot, count);
        }
    }
}

fn handle_accepted_fd<D, CtxA, CtxB>(
    host:   net::Host&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    l_slot: i64,
    l_gen:  u16,
    cfd:    i64,
    is_rio: bool,
    count:  i32&,
) {
    let owner = host.links[l_slot].owner;
    let tag = host.links[l_slot].tag;
    let kind = host.links[l_slot].kind;
    let c_slot = alloc_host_slot(host, owner, tag, kind);
    guard c_slot >= 0 else {
        net::tcp_close(cfd);
        return;
    }
    if !is_rio {
        let _ = net::tcp_set_nonblocking(cfd, true);
    }
    host.links[c_slot].fd = cfd;
    host.links[c_slot].state = LinkSlotState.Open;
    if is_rio && c_slot < NET_HOST_ACCEL_SLOTS && host.rio_cq != 0 {
        let c_link = host_slot_link(host, c_slot);
        let rq = native_rio_create_rq_ctx(cfd, 16, 16, host.rio_cq, host.rio_cq, c_link.raw);
        if rq != 0 {
            host.links[c_slot].rio_rq = rq;
            host.links[c_slot].is_rio = true;
            if !post_rio_slot_recv(host, c_slot) {
                release_host_slot(host, c_slot);
                return;
            }
        } else {
            let _ = net::tcp_set_nonblocking(cfd, true);
            sync_slot_interest(host, c_slot);
        }
    } else {
        sync_slot_interest(host, c_slot);
    }
    let ev = core::LinkEvent {
        kind:     core::LinkEventKind.Accepted,
        link:     host_slot_link(host, c_slot),
        listener: core::make_io_link(owner, l_gen, l_slot as u32),
        tag:      tag,
        ..
    };
    emit_host_event(host, driver, arg_a, arg_b, ev, count);
}

fn accept_ready_listener<D, CtxA, CtxB>(
    host:   net::Host&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    slot:   i64,
    gen:    u16,
    count:  i32&,
) {
    let lfd = host.links[slot].fd;
    let is_rio = host.links[slot].is_rio;
    for _ in 16 {
        guard host.links[slot].in_use && host.links[slot].gen == gen else { break; }
        let cfd = if is_rio {
            native_rio_poll_accept(lfd, 0)
        } else {
            net::tcp_accept_nonblocking(lfd)
        };
        if cfd <= 0 { break; }
        handle_accepted_fd(host, driver, arg_a, arg_b, slot, gen, cfd, is_rio, count);
    }
}

fn finish_connecting_slot<D, CtxA, CtxB>(
    host:     net::Host&,
    driver:   D&,
    arg_a:    CtxA&,
    arg_b:    CtxB&,
    slot:     i64,
    gen:      u16,
    ev_flags: u32,
    count:    i32&,
) {
    let link = host_slot_link(host, slot);
    let tag = host.links[slot].tag;
    let has_err = (ev_flags & core::POLL_ERROR) != 0;
    if !has_err && tcp_connect_finish(host.links[slot].fd) {
        host.links[slot].state = LinkSlotState.Open;
        sync_slot_interest(host, slot);
        let ev = core::LinkEvent { kind: core::LinkEventKind.Connected, link: link, tag: tag, .. };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
        return;
    }
    release_host_slot(host, slot);
    let closed_ev = core::LinkEvent {
        kind: core::LinkEventKind.Closed, link: link, tag: tag, err: core::IoError.Closed, ..
    };
    emit_host_event(host, driver, arg_a, arg_b, closed_ev, count);
}

fn step_socket_read<D, CtxA, CtxB>(
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    slot:       i64,
    gen:        u16,
    count:      i32&,
) -> bool {
    guard host.links[slot].in_use && host.links[slot].gen == gen && !host.links[slot].rx_paused else {
        return false;
    }
    let link = host_slot_link(host, slot);
    let tag = host.links[slot].tag;
    ensure_rx_scratch(rx_scratch);
    let recvd = net::tcp_recv_nonblocking_slice(host.links[slot].fd, rx_scratch[..]);
    if recvd > 0 {
        let ev = core::LinkEvent {
            kind: core::LinkEventKind.Data,
            link: link,
            tag:  tag,
            data: rx_scratch[..recvd],
            ..
        };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
        return recvd >= NET_HOST_RX_CAP;
    }
    if recvd == 0 {
        host.links[slot].eof_received = true;
        sync_slot_interest(host, slot);
        let ev = core::LinkEvent { kind: core::LinkEventKind.Eof, link: link, tag: tag, .. };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
        return false;
    }
    if recvd == -2 { return false; }
    release_host_slot(host, slot);
    let closed_ev = core::LinkEvent {
        kind: core::LinkEventKind.Closed, link: link, tag: tag, err: core::IoError.Closed, ..
    };
    emit_host_event(host, driver, arg_a, arg_b, closed_ev, count);
    return false;
}

fn drain_ready_socket_reads<D, CtxA, CtxB>(
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    slot:       i64,
    gen:        u16,
    count:      i32&,
) {
    for _ in 4 {
        if !step_socket_read(host, driver, arg_a, arg_b, rx_scratch, slot, gen, count) {
            break;
        }
    }
}

fn handle_readiness_slot_event<D, CtxA, CtxB>(
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    slot:       i64,
    gen:        u16,
    ev_flags:   u32,
    count:      i32&,
) {
    if host.links[slot].state == LinkSlotState.Listening {
        accept_ready_listener(host, driver, arg_a, arg_b, slot, gen, count);
        return;
    }
    if host.links[slot].state == LinkSlotState.Connecting {
        finish_connecting_slot(host, driver, arg_a, arg_b, slot, gen, ev_flags, count);
        return;
    }
    guard host.links[slot].state == LinkSlotState.Open else { return; }
    let link = host_slot_link(host, slot);
    let tag = host.links[slot].tag;
    if (ev_flags & core::POLL_WRITE) != 0 && host.links[slot].want_write {
        host.links[slot].want_write = false;
        sync_slot_interest(host, slot);
        let ev = core::LinkEvent { kind: core::LinkEventKind.Writable, link: link, tag: tag, .. };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
        guard host.links[slot].in_use && host.links[slot].gen == gen else { return; }
    }
    if (ev_flags & core::POLL_ERROR) != 0 && (host.links[slot].rx_paused || host.links[slot].eof_received) {
        release_host_slot(host, slot);
        let closed_ev = core::LinkEvent {
            kind: core::LinkEventKind.Closed, link: link, tag: tag, err: core::IoError.Closed, ..
        };
        emit_host_event(host, driver, arg_a, arg_b, closed_ev, count);
        return;
    }
    if (ev_flags & core::POLL_HANGUP) != 0 && host.links[slot].rx_paused && !host.links[slot].eof_received {
        host.links[slot].eof_received = true;
        sync_slot_interest(host, slot);
        let ev = core::LinkEvent { kind: core::LinkEventKind.Eof, link: link, tag: tag, .. };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
        return;
    }
    if (ev_flags & (core::POLL_READ | core::POLL_HANGUP | core::POLL_ERROR)) != 0 &&
       !host.links[slot].rx_paused && !host.links[slot].eof_received {
        drain_ready_socket_reads(host, driver, arg_a, arg_b, rx_scratch, slot, gen, count);
    }
}

fn poll_single_epoll_shard<D, CtxA, CtxB>(
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    shard_fd:   i64,
    timeout_ms: i64,
    count:      i32&,
) -> i32 {
    var raw_fds:    i64[64] = [0; 64];
    var raw_udata:  u64[64] = [0; 64];
    var raw_events: u32[64] = [0; 64];
    let t_clamped = min(max(timeout_ms, -1), 2147483647) as i32;
    let n = epoll_wait_events_direct(shard_fd, raw_fds[..], raw_udata[..], raw_events[..], t_clamped);
    guard n > 0 else { return 0; }
    let limit = min(n as i64, 64);
    for k in limit {
        let link = core::IoLink { raw: raw_udata[k] };
        let slot, ok = host_match_link(host, link);
        guard ok else { continue; }
        handle_readiness_slot_event(
            host, driver, arg_a, arg_b, rx_scratch, slot, core::io_link_gen(link), raw_events[k], count,
        );
    }
    return n;
}

fn poll_epoll_backend<D, CtxA, CtxB>(
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    timeout_ms: i64,
    count:      i32&,
) {
    guard host.epfd_count > 0 && host.epfd_shards.len > 0 else { return; }
    if host.epfd_shards.len == 1 {
        let _ = poll_single_epoll_shard(
            host, driver, arg_a, arg_b, rx_scratch, host.epfd_shards[0].fd, timeout_ms, count,
        );
        return;
    }
    var total_ready: i64 = 0;
    let n_shards = host.epfd_shards.len;
    for i in n_shards {
        guard i < host.epfd_shards.len else { return; }
        if host.epfd_shards[i].count > 0 {
            let n = poll_single_epoll_shard(
                host, driver, arg_a, arg_b, rx_scratch, host.epfd_shards[i].fd, 0, count,
            );
            total_ready = core::add_sat_i64(total_ready, n);
        }
    }
    if total_ready == 0 && timeout_ms != 0 && host.epfd_shards.len > 0 {
        let _ = poll_single_epoll_shard(
            host, driver, arg_a, arg_b, rx_scratch, host.epfd_shards[0].fd, max(min(timeout_ms, 2), 1), count,
        );
    }
}

fn dispatch_single_kevent<D, CtxA, CtxB>(
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    kev:        const Kevent&,
    count:      i32&,
) {
    guard (kev.flags & HOST_KQ_EV_ERROR) == 0 else { return; }
    let link = core::IoLink { raw: kev.udata };
    let slot, ok = host_match_link(host, link);
    guard ok else { return; }
    var flags: u32 = core::POLL_NONE;
    if kev.filter == EVFILT_READ { flags |= core::POLL_READ; }
    if kev.filter == EVFILT_WRITE { flags |= core::POLL_WRITE; }
    if (kev.flags & EV_EOF) != 0 {
        flags |= core::POLL_HANGUP;
        if kev.fflags != 0 { flags |= core::POLL_ERROR; }
    }
    handle_readiness_slot_event(host, driver, arg_a, arg_b, rx_scratch, slot, core::io_link_gen(link), flags, count);
}

fn poll_kqueue_backend<D, CtxA, CtxB>(
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    timeout_ms: i64,
    count:      i32&,
) {
    guard host.kq_fd >= 0 else { return; }
    var kev_out: Kevent[64] = [Kevent { .. }; 64];
    let t_ns = timeout_ms_to_ns(timeout_ms);
    let n = kqueue_poll_slice(host.kq_fd, host.kq_changes[..], kev_out[..], t_ns);
    host.kq_changes.clear();
    guard n > 0 else { return; }
    let limit = min(n as i64, 64);
    for k in limit {
        dispatch_single_kevent(host, driver, arg_a, arg_b, rx_scratch, kev_out[k], count);
    }
}

fn dispatch_single_rio_result<D, CtxA, CtxB>(
    host:   net::Host&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    res:    const RioResult&,
    count:  i32&,
) {
    let link = core::IoLink { raw: res.socket_context };
    let slot, ok = host_match_link(host, link);
    guard ok else { return; }
    let tag = host.links[slot].tag;
    if res.request_context == HOST_RIO_REQ_TX {
        host.links[slot].tx_inflight = false;
        if res.status != 0 {
            release_host_slot(host, slot);
            let ev = core::LinkEvent {
                kind: core::LinkEventKind.Closed, link: link, tag: tag, err: core::IoError.Closed, ..
            };
            emit_host_event(host, driver, arg_a, arg_b, ev, count);
            return;
        }
        if host.links[slot].want_write {
            host.links[slot].want_write = false;
            let ev = core::LinkEvent { kind: core::LinkEventKind.Writable, link: link, tag: tag, .. };
            emit_host_event(host, driver, arg_a, arg_b, ev, count);
        }
        return;
    }
    if res.status != 0 {
        release_host_slot(host, slot);
        let ev = core::LinkEvent {
            kind: core::LinkEventKind.Closed, link: link, tag: tag, err: core::IoError.Closed, ..
        };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
        return;
    }
    if res.bytes_transferred == 0 {
        host.links[slot].eof_received = true;
        let ev = core::LinkEvent { kind: core::LinkEventKind.Eof, link: link, tag: tag, .. };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
        return;
    }
    let rx_off = host_rio_rx_offset(slot) as i64;
    let rx_len = min(res.bytes_transferred as i64, NET_HOST_ACCEL_CHUNK);
    let rx_end = core::add_sat_i64(rx_off, rx_len);
    let gen = host.links[slot].gen;
    if rx_end <= host.accel_slab.len {
        let ev = core::LinkEvent {
            kind: core::LinkEventKind.Data, link: link, tag: tag, data: host.accel_slab[rx_off..rx_end], ..
        };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
    }
    if host.links[slot].in_use && host.links[slot].gen == gen && !host.links[slot].rx_paused {
        let _ = post_rio_slot_recv(host, slot);
    }
}

fn poll_rio_backend<D, CtxA, CtxB>(
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    timeout_ms: i64,
    count:      i32&,
) {
    guard host.rio_cq != 0 else { return; }
    let n_links = host.links.len;
    for i in n_links {
        guard host.is_open && i < host.links.len else { break; }
        if host.links[i].in_use && host.links[i].is_rio && host.links[i].state == LinkSlotState.Listening {
            accept_ready_listener(host, driver, arg_a, arg_b, i, host.links[i].gen, count);
        }
    }
    var rio_results: RioResult[..64] = [];
    var n = rio_drain_completions(host.rio_cq, rio_results);
    if n == 0 && timeout_ms > 0 && host.epfd_count == 0 {
        let _ = rio_wait_cq(host.rio_cq, min(timeout_ms, 5) as i32);
        n = rio_drain_completions(host.rio_cq, rio_results);
    }
    for k in rio_results.len {
        dispatch_single_rio_result(host, driver, arg_a, arg_b, rio_results[k], count);
    }
}

fn dispatch_uring_send_cqe<D, CtxA, CtxB>(
    host:   net::Host&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    slot:   i64,
    cqe:    const UringCqe&,
    count:  i32&,
) {
    guard (cqe.flags & URING_CQE_F_NOTIF) == 0 else { return; }
    let link = host_slot_link(host, slot);
    let tag = host.links[slot].tag;
    host.links[slot].tx_inflight = false;
    if cqe.res <= 0 {
        release_host_slot(host, slot);
        let closed_ev = core::LinkEvent {
            kind: core::LinkEventKind.Closed, link: link, tag: tag, err: core::IoError.Closed, ..
        };
        emit_host_event(host, driver, arg_a, arg_b, closed_ev, count);
        return;
    }
    if host.links[slot].want_write {
        host.links[slot].want_write = false;
        let ev = core::LinkEvent { kind: core::LinkEventKind.Writable, link: link, tag: tag, .. };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
    }
}

fn dispatch_uring_recv_cqe<D, CtxA, CtxB>(
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    slot:       i64,
    gen:        u16,
    cqe:        const UringCqe&,
    has_buf:    bool,
    bid:        u16,
    count:      i32&,
) {
    let link = host_slot_link(host, slot);
    let tag = host.links[slot].tag;
    if cqe.res == 0 {
        if has_buf { uring_recycle_pbuf(host.uring_pbuf, bid); }
        host.links[slot].eof_received = true;
        host.links[slot].epoll_mask &= ~net::EPOLL_READ;
        let ev = core::LinkEvent { kind: core::LinkEventKind.Eof, link: link, tag: tag, .. };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
        return;
    }
    if cqe.res < 0 {
        if has_buf { uring_recycle_pbuf(host.uring_pbuf, bid); }
        release_host_slot(host, slot);
        let closed_ev = core::LinkEvent {
            kind: core::LinkEventKind.Closed, link: link, tag: tag, err: core::IoError.Closed, ..
        };
        emit_host_event(host, driver, arg_a, arg_b, closed_ev, count);
        return;
    }
    var copied: i32 = 0;
    if has_buf {
        ensure_rx_scratch(rx_scratch);
        copied = uring_read_pbuf(host.uring_pbuf, bid, cqe.res, rx_scratch[..]);
        uring_recycle_pbuf(host.uring_pbuf, bid);
    }
    if copied > 0 {
        let ev = core::LinkEvent {
            kind: core::LinkEventKind.Data, link: link, tag: tag, data: rx_scratch[..copied], ..
        };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
    }
    if (cqe.flags & URING_CQE_F_MORE) == 0 &&
        host.links[slot].in_use &&
        host.links[slot].gen == gen &&
        !host.links[slot].rx_paused &&
        !host.links[slot].eof_received {
        host.links[slot].epoll_mask &= ~net::EPOLL_READ;
        sync_slot_interest(host, slot);
    }
}

fn dispatch_uring_accept_cqe<D, CtxA, CtxB>(
    host:   net::Host&,
    driver: D&,
    arg_a:  CtxA&,
    arg_b:  CtxB&,
    slot:   i64,
    gen:    u16,
    cqe:    const UringCqe&,
    count:  i32&,
) {
    if cqe.res > 0 {
        handle_accepted_fd(host, driver, arg_a, arg_b, slot, gen, cqe.res as i64, false, count);
    }
    if (cqe.flags & URING_CQE_F_MORE) == 0 && host.links[slot].in_use && host.links[slot].gen == gen {
        host.links[slot].epoll_mask = 0;
        sync_slot_interest(host, slot);
    }
}

fn dispatch_uring_cqe<D, CtxA, CtxB>(
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    cqe:        const UringCqe&,
    count:      i32&,
) {
    let has_buf = (cqe.flags & URING_CQE_F_BUFFER) != 0;
    let bid = ((cqe.flags >> 16) & 0xFFFF) as u16;
    let op, slot, ok = host_match_uring_tag(host, cqe.user_data);
    guard ok else {
        if has_buf { uring_recycle_pbuf(host.uring_pbuf, bid); }
        return;
    }
    if op == HOST_URING_OP_RECV {
        dispatch_uring_recv_cqe(
            host, driver, arg_a, arg_b, rx_scratch, slot, host.links[slot].gen, cqe, has_buf, bid, count,
        );
        return;
    }
    if has_buf { uring_recycle_pbuf(host.uring_pbuf, bid); }
    let gen = host.links[slot].gen;
    if op == HOST_URING_OP_ACCEPT {
        dispatch_uring_accept_cqe(host, driver, arg_a, arg_b, slot, gen, cqe, count);
        return;
    }
    if op == HOST_URING_OP_CONNECT {
        let ev_flags: u32 = if cqe.res < 0 { core::POLL_ERROR } else { core::POLL_WRITE };
        finish_connecting_slot(host, driver, arg_a, arg_b, slot, gen, ev_flags, count);
        return;
    }
    if op == HOST_URING_OP_SEND {
        dispatch_uring_send_cqe(host, driver, arg_a, arg_b, slot, cqe, count);
        return;
    }
    if op == HOST_URING_OP_POLL_W && host.links[slot].want_write {
        host.links[slot].want_write = false;
        host.links[slot].epoll_mask &= ~net::EPOLL_WRITE;
        let ev = core::LinkEvent {
            kind: core::LinkEventKind.Writable, link: host_slot_link(host, slot), tag: host.links[slot].tag, ..
        };
        emit_host_event(host, driver, arg_a, arg_b, ev, count);
    }
}

fn poll_uring_backend<D, CtxA, CtxB>(
    host:       net::Host&,
    driver:     D&,
    arg_a:      CtxA&,
    arg_b:      CtxB&,
    rx_scratch: u8[>..]&,
    timeout_ms: i64,
    count:      i32&,
) {
    guard host.uring_fd >= 0 else { return; }
    var cqes: UringCqe[64] = [UringCqe { .. }; 64];
    let min_c: u32 = if timeout_ms == 0 { 0 } else { 1 };
    let t_ns = timeout_ms_to_ns(timeout_ms);
    let n = uring_wait_cqes(host.uring_fd, cqes[..], min_c, t_ns);
    guard n > 0 else { return; }
    let limit = min(n as i64, 64);
    for k in limit {
        dispatch_uring_cqe(host, driver, arg_a, arg_b, rx_scratch, cqes[k], count);
    }
}
