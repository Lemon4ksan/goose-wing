// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for ReactorAccelRuntime, Poller, UringPoller, and EventLoop.
namespace net_internal;

import std;
import core;
import .driver;
import .tcp;
import .accel;
import .poller;
import .internal;

// ---- Reactor Accelerator Helpers -------------------------------------------

inline fn reactor_cancel_uring_slot(accel: net::ReactorAccelRuntime&, slot: i64) {
    guard accel.slot_accel[slot] && accel.mode == net::ReactorAccelMode.IoUring && accel.uring_fd >= 0 else { return; }
    let tok = net::reactor_accel_slot_token(accel, slot);
    let rx_tag = if accel.slot_ktls_rx[slot] {
        net::REACTOR_URING_TAG_POLL | tok
    } else {
        net::REACTOR_URING_TAG_RECV | tok
    };
    var cancel_sqes: UringSqe[..2] = [];
    var rx_cancel = UringSqe { .. };
    uring_prep_cancel(rx_cancel, rx_tag);
    let _ = cancel_sqes.try_push(rx_cancel);
    if accel.slot_tx_inflight[slot] {
        var tx_cancel = UringSqe { .. };
        uring_prep_cancel(tx_cancel, net::REACTOR_URING_TAG_SEND | tok);
        let _ = cancel_sqes.try_push(tx_cancel);
    }
    let _ = uring_submit_sqes(accel.uring_fd, cancel_sqes[..]);
}

fn reactor_try_open_uring(accel: net::ReactorAccelRuntime&, listener_fd: i64) -> bool {
    let rfd = native_uring_create(1024, 0);
    guard rfd >= 0 else { return false; }
    let pbuf, ok_pb = uring_alloc_pbuf_ring(rfd, net::REACTOR_URING_PBUF_BGID, 1024, 8192);
    if !ok_pb || pbuf == 0 {
        native_uring_close(rfd);
        return false;
    }
    accel.mode = net::ReactorAccelMode.IoUring;
    accel.uring_fd = rfd;
    accel.uring_pbuf = pbuf;
    if listener_fd > 0 {
        net::tcp_set_nonblocking(listener_fd, true);
        net::reactor_arm_uring_accept(accel, listener_fd);
    }
    return true;
}

fn reactor_try_open_rio(accel: net::ReactorAccelRuntime&, listener_fd: i64) -> bool {
    guard native_rio_available() == 1 && accel.epfd >= 0 else { return false; }
    let cq = native_rio_create_cq(512);
    guard cq != 0 else { return false; }
    let tx_cq = native_rio_create_cq(512);
    if tx_cq == 0 {
        native_rio_close_cq(cq);
        return false;
    }
    net::ensure_reactor_accel_slab(accel);
    let bid = native_rio_register_slice(accel.slab[..]);
    if bid == 0 {
        native_rio_close_cq(tx_cq);
        native_rio_close_cq(cq);
        return false;
    }
    accel.mode = net::ReactorAccelMode.Rio;
    accel.rio_cq = cq;
    accel.rio_tx_cq = tx_cq;
    accel.rio_buf_id = bid;
    if listener_fd > 0 {
        if native_rio_is_listener(listener_fd) == 1 {
            accel.rio_listener_fd = listener_fd;
        } else {
            net::tcp_set_nonblocking(listener_fd, true);
            if net::epoll_add(accel.epfd, listener_fd, net::EPOLL_READ, net::EPOLL_LISTENER_TAG) {
                accel.epfd_registered_count = core::add_sat_i64(accel.epfd_registered_count, 1) as i32;
            }
        }
    }
    return true;
}

fn reactor_try_open_kqueue(accel: net::ReactorAccelRuntime&, listener_fd: i64) -> bool {
    let kq = native_kqueue_create();
    guard kq >= 0 else { return false; }
    accel.mode = net::ReactorAccelMode.Kqueue;
    accel.kq_fd = kq;
    if listener_fd > 0 {
        net::tcp_set_nonblocking(listener_fd, true);
        let r_flags = EV_ADD | EV_ENABLE;
        net::reactor_queue_kq_change(accel, listener_fd, r_flags, net::EPOLL_LISTENER_TAG);
    }
    return true;
}

// ---- Poller & EventLoop Helpers --------------------------------------------

const URING_INTERNAL_CANCEL_TAG: u64 = 0xFFFFFFFFFFFFFFFF;
const URING_POLLIN_MASK:         u32 = 1;
const URING_POLLOUT_MASK:        u32 = 4;
const URING_POLLERR_MASK:        u32 = 8;
const URING_POLLHUP_MASK:        u32 = 16;
const KQUEUE_EV_ERROR_FLAG:      u16 = 0x4000;
const NS_TO_MS_MULHI_RECIP:      u64 = 0x10C6F7A0B5EE;
const MAX_POLL_TIMEOUT_NS:       u64 = 2147483647000000;

inline fn apply_trigger_clear_mask(t: core::PollTrigger.Edge, sim: net::SimulatedReadyState&, triggered: u32) {
    sim.ready.clear_flag(triggered);
    sim.bytes = 0;
}

inline fn apply_trigger_clear_mask(t: core::PollTrigger.Level, sim: net::SimulatedReadyState&, triggered: u32) {
    sim.ready.clear_flag(core::POLL_WRITE);
}

fn poll_flags_to_interest(events: u32) -> core::PollInterest {
    let want_read = (events & core::POLL_READ) != 0;
    let want_write = (events & core::POLL_WRITE) != 0;
    if want_read && want_write { return core::PollInterest.ReadWrite; }
    if want_read { return core::PollInterest.Read; }
    if want_write { return core::PollInterest.Write; }
    return core::PollInterest.None;
}

fn interest_to_epoll_flags(interest: core::PollInterest) -> u32 {
    return match interest {
        Read => net::EPOLL_READ,
        Write => net::EPOLL_WRITE,
        ReadWrite => net::EPOLL_READ | net::EPOLL_WRITE,
        None => 0,
    };
}

fn interest_to_uring_poll_mask(interest: core::PollInterest) -> u32 {
    return match interest {
        Read => URING_POLLIN_MASK,
        Write => URING_POLLOUT_MASK,
        ReadWrite => URING_POLLIN_MASK | URING_POLLOUT_MASK,
        None => 0,
    };
}

inline fn is_live_os_socket_fd(fd: i32) -> bool {
    guard fd > 0 else { return false; }
    if detect_target_platform() == TargetPlatform.Windows {
        return native_tcp_get_readable_bytes(fd) >= 0;
    }
    return true;
}

inline fn poller_push_kqueue_change(p: net::Poller&, ev: Kevent) {
    if p.kqueue_changes.len >= p.kqueue_changes.cap {
        var empty_out: Kevent[1] = [Kevent { .. }];
        let _ = kqueue_poll_slice(p.kqueue_fd, p.kqueue_changes[..], empty_out[..0], 0);
        p.kqueue_changes.clear();
    }
    let _ = p.kqueue_changes.try_push(ev);
}

inline fn poller_queue_kqueue_interest(
    p:        net::Poller&,
    fd:       i32,
    tag:      u64,
    interest: core::PollInterest,
    trigger:  core::PollTrigger,
) {
    let edge = trigger == core::PollTrigger.Edge;
    if interest == core::PollInterest.Read || interest == core::PollInterest.ReadWrite {
        var ev_r = Kevent { .. };
        kevent_prep_read(ev_r, fd, tag, edge);
        poller_push_kqueue_change(p, ev_r);
    }
    if interest == core::PollInterest.Write || interest == core::PollInterest.ReadWrite {
        var ev_w = Kevent { .. };
        kevent_prep_write(ev_w, fd, tag, edge);
        poller_push_kqueue_change(p, ev_w);
    }
}

inline fn poller_queue_kqueue_delete(p: net::Poller&, fd: i32, interest: core::PollInterest) {
    if interest == core::PollInterest.Read || interest == core::PollInterest.ReadWrite {
        poller_push_kqueue_change(p, Kevent {
            ident: fd as u64, filter: EVFILT_READ, flags: EV_DELETE, ..
        });
    }
    if interest == core::PollInterest.Write || interest == core::PollInterest.ReadWrite {
        poller_push_kqueue_change(p, Kevent {
            ident: fd as u64, filter: EVFILT_WRITE, flags: EV_DELETE, ..
        });
    }
}

inline fn poller_submit_uring_poll_add(ring_fd: i64, fd: i32, interest: core::PollInterest, tag: u64) {
    let mask = interest_to_uring_poll_mask(interest);
    guard mask != 0 else { return; }
    var sqe = UringSqe { .. };
    uring_prep_poll_add(sqe, fd, mask, tag);
    var batch: UringSqe[1] = [sqe];
    let _ = uring_submit_sqes(ring_fd, batch[..]);
}

inline fn poller_submit_uring_poll_remove(ring_fd: i64, old_tag: u64) {
    var rm_sqe = UringSqe { .. };
    uring_prep_poll_remove(rm_sqe, old_tag, URING_INTERNAL_CANCEL_TAG);
    var rm_batch: UringSqe[1] = [rm_sqe];
    let _ = uring_submit_sqes(ring_fd, rm_batch[..]);
}

inline fn poller_bind_native_registration(
    p:        net::Poller&,
    fd:       i32,
    tag:      u64,
    interest: core::PollInterest,
    trigger:  core::PollTrigger,
) {
    if p.epoll_fd >= 0 && is_live_os_socket_fd(fd) {
        let _ = net::epoll_add(p.epoll_fd, fd, interest_to_epoll_flags(interest), tag);
    }
    if p.kqueue_fd >= 0 {
        poller_queue_kqueue_interest(p, fd, tag, interest, trigger);
    }
    if p.uring_ring_fd >= 0 {
        poller_submit_uring_poll_add(p.uring_ring_fd, fd, interest, tag);
    }
}

inline fn poller_mod_native_registration(
    p:            net::Poller&,
    fd:           i32,
    old_tag:      u64,
    old_interest: core::PollInterest,
    tag:          u64,
    interest:     core::PollInterest,
    trigger:      core::PollTrigger,
) {
    if p.epoll_fd >= 0 && is_live_os_socket_fd(fd) {
        let flags = interest_to_epoll_flags(interest);
        if !net::epoll_mod(p.epoll_fd, fd, flags, tag) {
            let _ = net::epoll_add(p.epoll_fd, fd, flags, tag);
        }
    }
    if p.kqueue_fd >= 0 {
        poller_queue_kqueue_delete(p, fd, old_interest);
        poller_queue_kqueue_interest(p, fd, tag, interest, trigger);
    }
    if p.uring_ring_fd >= 0 {
        poller_submit_uring_poll_remove(p.uring_ring_fd, old_tag);
        poller_submit_uring_poll_add(p.uring_ring_fd, fd, interest, tag);
    }
}

inline fn poller_bind_native_deregister(
    p:            net::Poller&,
    fd:           i32,
    old_tag:      u64,
    old_interest: core::PollInterest,
) {
    if p.epoll_fd >= 0 {
        let _ = net::epoll_del(p.epoll_fd, fd);
    }
    if p.kqueue_fd >= 0 {
        poller_queue_kqueue_delete(p, fd, old_interest);
    }
    if p.uring_ring_fd >= 0 {
        poller_submit_uring_poll_remove(p.uring_ring_fd, old_tag);
    }
}

fn check_expired_timers(p: net::Poller&, now_ns: u64, out_events: core::PollReadyEvent[..64]&) -> i32 {
    var fired_count: i64 = 0;
    for i in p.timers.len {
        guard p.timers[i].active && now_ns >= p.timers[i].deadline_ns else { continue; }
        let ev = core::PollReadyEvent {
            tag:             p.timers[i].tag,
            fd:              -1,
            events:          core::POLL_TIMER,
            bytes_available: 0,
            is_eof:          false,
            is_timer:        true,
        };
        guard out_events.try_push(ev) else { break; }
        fired_count = core::add_sat_i64(fired_count, 1);

        if p.timers[i].interval_ns > 0 {
            p.timers[i].deadline_ns = core::add_sat_u64(now_ns, p.timers[i].interval_ns);
        } else {
            p.timers[i].active = false;
            if p.active_timer_count > 0 {
                p.active_timer_count = core::sub_sat_u64(p.active_timer_count, 1) as u32;
            }
        }
    }
    return fired_count as i32;
}

inline fn is_coarse_timeout_expired(t: u8, old_tick: u64, elapsed_ticks: u64) -> bool {
    guard t != net::COARSE_TIMEOUT_DISABLED else { return false; }
    guard elapsed_ticks < 240 else { return true; }
    let _, dist = core::div_rem_u64(core::sub_sat_u64(core::add_sat_u64(t, 240), old_tick), 240);
    return dist > 0 && dist <= elapsed_ticks;
}

inline fn dispatch_expired_registration(
    reg:           net::SocketRegistration&,
    old_tick:      u64,
    elapsed_ticks: u64,
    out_events:    core::PollReadyEvent[..64]&,
) -> bool {
    guard reg.in_use else { return false; }
    guard is_coarse_timeout_expired(reg.timeout, old_tick, elapsed_ticks) else { return false; }
    guard out_events.try_push(core::PollReadyEvent {
        tag:             reg.tag,
        fd:              reg.fd,
        events:          core::POLL_TIMER,
        bytes_available: 0,
        is_eof:          false,
        is_timer:        true,
    }) else { return false; }
    reg.timeout = net::COARSE_TIMEOUT_DISABLED;
    return true;
}

inline fn advance_coarse_clock(p: net::Poller&, now_ns: u64) -> u64, u64, bool {
    guard p.last_coarse_tick_ns > 0 else {
        p.last_coarse_tick_ns = now_ns;
        return 0, 0, false;
    }
    let next_tick_ns = core::add_sat_u64(p.last_coarse_tick_ns, net::COARSE_TIMEOUT_GRANULARITY_NS);
    guard now_ns >= next_tick_ns else {
        return 0, 0, false;
    }
    let delta_ns = core::sub_sat_u64(now_ns, p.last_coarse_tick_ns);
    let el, _ = core::div_rem_u64(delta_ns, net::COARSE_TIMEOUT_GRANULARITY_NS);
    p.last_coarse_tick_ns = core::add_sat_u64(
        p.last_coarse_tick_ns,
        core::mul_sat_u64(el, net::COARSE_TIMEOUT_GRANULARITY_NS),
    );
    let old_tick: u64 = p.global_coarse_tick;
    let _, next_tick = core::div_rem_u64(core::add_sat_u64(old_tick, el), 240);
    p.global_coarse_tick = (next_tick & 0xFF) as u8;
    return old_tick, el, true;
}

fn check_wake_events(p: net::Poller&, out_events: core::PollReadyEvent[..64]&) -> i32 {
    guard p.wake_tags.len > 0 else { return 0; }
    var emitted: i64 = 0;
    for tag in p.wake_tags {
        let ev = core::PollReadyEvent {
            tag:             tag,
            fd:              -1,
            events:          core::POLL_WAKE,
            bytes_available: 0,
            is_eof:          false,
            is_timer:        false,
        };
        guard out_events.try_push(ev) else { break; }
        emitted = core::add_sat_i64(emitted, 1);
        p.total_events_dispatched = core::add_sat_u64(p.total_events_dispatched, 1);
    }
    p.wake_tags.compact_wire_buffer(emitted);
    return (emitted & 0x7FFFFFFF) as i32;
}

fn has_pending_simulated_ready(p: const net::Poller&) -> bool {
    guard p.active_fd_count > 0 else { return false; }
    for i in p.registrations.len {
        guard p.registrations[i].in_use else { continue; }
        let mask = core::interest_to_poll_flags(p.registrations[i].interest) |
            core::POLL_ERROR | core::POLL_HANGUP;
        if (p.registrations[i].sim.ready & mask) != core::POLL_NONE {
            return true;
        }
    }
    return false;
}

fn find_earliest_timer_deadline_ns(p: const net::Poller&) -> u64, bool {
    guard p.active_timer_count > 0 else { return 0, false; }
    var found = false;
    var earliest_ns: u64 = 0xFFFFFFFFFFFFFFFF;
    for i in p.timers.len {
        guard p.timers[i].active else { continue; }
        found = true;
        earliest_ns = min(earliest_ns, p.timers[i].deadline_ns);
    }
    return earliest_ns, found;
}

fn clamp_timeout_to_timers(p: const net::Poller&, timeout_ms: i64, now_ns: u64) -> i64 {
    let earliest_ns, has_timer = find_earliest_timer_deadline_ns(p);
    let rem_ns = min(core::add_sat_u64(core::sub_sat_u64(earliest_ns, now_ns), 999999), MAX_POLL_TIMEOUT_NS);
    let rem_ms_u64 = min(core::mulhi_u64(rem_ns, NS_TO_MS_MULHI_RECIP), 2147483647);
    let rem_ms = (rem_ms_u64 as i32) as i64;
    if timeout_ms == 0 || p.wake_tags.len > 0 || has_pending_simulated_ready(p) {
        return 0;
    }
    guard has_timer else { return timeout_ms; }
    if now_ns >= earliest_ns {
        return 0;
    }
    if timeout_ms < 0 {
        return rem_ms;
    }
    return min(timeout_ms, rem_ms);
}

inline fn resolve_epoll_ready_flags(raw_ev: u32, interest: core::PollInterest) -> u32 {
    if raw_ev != core::POLL_NONE {
        return raw_ev;
    }
    let fallback = core::interest_to_poll_flags(interest);
    return if fallback != core::POLL_NONE { fallback } else { core::POLL_READ };
}

fn poller_collect_epoll_events(
    p:          net::Poller&,
    timeout_ms: i64,
    out_events: core::PollReadyEvent[..64]&,
) {
    var raw_fds:    i64[64] = [0; 64];
    var raw_udata:  u64[64] = [0; 64];
    var raw_events: u32[64] = [0; 64];
    let t_clamped = min(max(timeout_ms, -1), 2147483647);
    let n = epoll_wait_events_direct(p.epoll_fd, raw_fds[..], raw_udata[..], raw_events[..], t_clamped as i32);
    guard n > 0 else { return; }

    let limit = min(n as i64, 64);
    for k in limit {
        let tag = raw_udata[k];
        let reg_idx = net::find_by_tag(p, tag);
        guard reg_idx >= 0 else { continue; }
        let fd_val = p.registrations[reg_idx].fd;
        let ev_flags = resolve_epoll_ready_flags(raw_events[k], p.registrations[reg_idx].interest);
        let avail_raw = if (ev_flags & core::POLL_READ) != 0 {
            native_tcp_get_readable_bytes(fd_val)
        } else {
            0
        };
        let ev = core::PollReadyEvent {
            tag:             tag,
            fd:              fd_val,
            events:          ev_flags,
            bytes_available: max(avail_raw, 0),
            is_eof:          (ev_flags & core::POLL_HANGUP) != 0,
            is_timer:        false,
        };
        guard out_events.try_push(ev) else { break; }
        p.total_events_dispatched = core::add_sat_u64(p.total_events_dispatched, 1);
    }
}

fn poller_collect_kqueue_events(
    p:          net::Poller&,
    timeout_ms: i64,
    out_events: core::PollReadyEvent[..64]&,
) {
    var kev_out: Kevent[64] = [Kevent { .. }; 64];
    let timeout_ns = timeout_ms_to_ns(timeout_ms);
    let n = kqueue_poll_slice(p.kqueue_fd, p.kqueue_changes[..], kev_out[..], timeout_ns);
    p.kqueue_changes.clear();
    guard n > 0 else { return; }

    let limit = min(n as i64, 64);
    for k in limit {
        let kev = kev_out[k];
        guard (kev.flags & KQUEUE_EV_ERROR_FLAG) == 0 else { continue; }
        let reg_idx = net::find_by_tag(p, kev.udata);
        guard reg_idx >= 0 else { continue; }
        let flags, is_eof = map_kevent_to_poll_flags(kev);
        guard flags != core::POLL_NONE else { continue; }
        let ev = core::PollReadyEvent {
            tag:             kev.udata,
            fd:              p.registrations[reg_idx].fd,
            events:          flags,
            bytes_available: kevent_bytes_available(kev),
            is_eof:          is_eof,
            is_timer:        false,
        };
        guard out_events.try_push(ev) else { break; }
        p.total_events_dispatched = core::add_sat_u64(p.total_events_dispatched, 1);
    }
}

inline fn map_uring_revents_to_poll_flags(revents: u32) -> u32 {
    var flags: u32 = core::POLL_NONE;
    if (revents & URING_POLLIN_MASK) != 0 { flags |= core::POLL_READ; }
    if (revents & URING_POLLOUT_MASK) != 0 { flags |= core::POLL_WRITE; }
    if (revents & URING_POLLERR_MASK) != 0 { flags |= core::POLL_ERROR; }
    if (revents & URING_POLLHUP_MASK) != 0 { flags |= core::POLL_HANGUP; }
    return flags;
}

fn poller_collect_uring_events(
    p:          net::Poller&,
    timeout_ms: i64,
    out_events: core::PollReadyEvent[..64]&,
) {
    var cqes: UringCqe[64] = [UringCqe { .. }; 64];
    let min_complete: u32 = if timeout_ms == 0 { 0 } else { 1 };
    let timeout_ns = timeout_ms_to_ns(timeout_ms);
    let n = uring_wait_cqes(p.uring_ring_fd, cqes[..], min_complete, timeout_ns);
    guard n > 0 else { return; }

    let limit = min(n as i64, 64);
    for k in limit {
        let cqe = cqes[k];
        guard cqe.user_data != URING_INTERNAL_CANCEL_TAG &&
            cqe.res >= 0 &&
            (cqe.flags & URING_CQE_F_NOTIF) == 0 else { continue; }
        let reg_idx = net::find_by_tag(p, cqe.user_data);
        guard reg_idx >= 0 else { continue; }
        let flags = map_uring_revents_to_poll_flags(cqe.res as u32);
        let fd_val = p.registrations[reg_idx].fd;
        if p.registrations[reg_idx].trigger == core::PollTrigger.Level {
            poller_submit_uring_poll_add(
                p.uring_ring_fd, fd_val, p.registrations[reg_idx].interest, cqe.user_data,
            );
        }
        guard flags != core::POLL_NONE else { continue; }
        let ev = core::PollReadyEvent {
            tag:             cqe.user_data,
            fd:              fd_val,
            events:          flags,
            bytes_available: 0,
            is_eof:          (flags & core::POLL_HANGUP) != 0,
            is_timer:        false,
        };
        guard out_events.try_push(ev) else { break; }
        p.total_events_dispatched = core::add_sat_u64(p.total_events_dispatched, 1);
    }
}

inline fn poller_drain_rio_cq(p: net::Poller&, out_events: core::PollReadyEvent[..64]&) {
    var rio_results: RioResult[..64] = [];
    if rio_drain_completions(p.rio_cq_id, rio_results) > 0 {
        let _ = rio_map_completions_to_events(p, rio_results[..], out_events);
    }
}

inline fn poller_poll_native_drivers(
    p:          net::Poller&,
    timeout_ms: i64,
    out_events: core::PollReadyEvent[..64]&,
) {
    if p.rio_cq_id != 0 {
        poller_drain_rio_cq(p, out_events);
    }
    let eff_timeout = if out_events.len > 0 { 0 } else { timeout_ms };
    if p.uring_ring_fd >= 0 {
        poller_collect_uring_events(p, eff_timeout, out_events);
    } else if p.kqueue_fd >= 0 {
        poller_collect_kqueue_events(p, eff_timeout, out_events);
    } else if p.epoll_fd >= 0 {
        poller_collect_epoll_events(p, eff_timeout, out_events);
    }
    let can_wait_rio = p.rio_cq_id != 0 && out_events.len == 0 && (p.epoll_fd < 0 || p.active_fd_count == 0);
    if can_wait_rio && eff_timeout != 0 {
        let wait_ms = min(max(eff_timeout, -1), 2147483647) as i32;
        if rio_wait_cq(p.rio_cq_id, wait_ms) >= 0 {
            poller_drain_rio_cq(p, out_events);
        }
    }
}

inline fn flush_socket_writes(fd: i32, buf: u8[..4096]&) -> i64 {
    guard buf.len > 0 else { return 0; }
    guard fd >= 0 else {
        let count = buf.len;
        buf.clear();
        return count;
    }
    let sent = net::tcp_send2(fd, buf[..], "");
    if sent == -2 {
        return 0;
    }
    if sent <= 0 {
        let count = buf.len;
        buf.clear();
        return count;
    }
    let sent_i64 = sent as i64;
    buf.compact_wire_buffer(sent_i64);
    return sent_i64;
}

fn reactor_wait_rio_slot_tx(accel: net::ReactorAccelRuntime&, slot: i64) -> bool {
    guard slot >= 0 && slot < net::REACTOR_RIO_SLOTS && accel.rio_tx_cq != 0 else { return false; }
    var spins: i32 = 0;
    while accel.slot_tx_inflight[slot] && spins < 500 {
        let _ = net::reactor_drain_rio_tx_cq(accel);
        if !accel.slot_tx_inflight[slot] {
            break;
        }
        let _ = rio_wait_cq(accel.rio_tx_cq, 2);
        spins = core::add_sat_i64(spins, 1) as i32;
    }
    return !accel.slot_tx_inflight[slot] && !accel.slot_close_after_tx[slot];
}

fn reactor_submit_rio_tx(accel: net::ReactorAccelRuntime&, slot: i64, wire: const u8[:]) -> bool {
    guard slot >= 0 && slot < net::REACTOR_RIO_SLOTS && accel.slot_rio_rq[slot] != 0 else { return false; }
    net::ensure_reactor_accel_slab(accel);
    let tx_off_u32 = (core::shl_sat_u64(slot as u64, 13) as u32) | 4096;
    let tx_off = tx_off_u32 as i64;
    var off: i64 = 0;
    while off < wire.len {
        if accel.slot_tx_inflight[slot] {
            guard reactor_wait_rio_slot_tx(accel, slot) else { return false; }
        }
        let rem = core::sub_sat_i64(wire.len, off);
        let chunk_len = min(rem, net::REACTOR_ACCEL_BUF_SIZE);
        for i in chunk_len {
            accel.slab[core::add_sat_i64(tx_off, i)] = wire[core::add_sat_i64(off, i)];
        }
        let rc = native_rio_post_send(
            accel.slot_rio_rq[slot], accel.rio_buf_id, tx_off_u32, chunk_len as u32, net::REACTOR_REQ_TX_TAG,
        );
        guard rc == 0 else { return false; }
        accel.slot_tx_inflight[slot] = true;
        off = core::add_sat_i64(off, chunk_len);
    }
    return true;
}

// Maps a slice of Windows RIO `RioResult` items into `PollReadyEvent` entries on `out_events`.
fn rio_map_completions_to_events(
    p:          net::Poller&,
    results:    const RioResult[:],
    out_events: core::PollReadyEvent[..64]&,
) -> u64 {
    var added: u64 = 0;
    for &res in results {
        guard out_events.len < out_events.cap else { break; }
        let reg_idx = net::find_by_tag(p, res.socket_context);
        let fd_val: i32 = if reg_idx >= 0 && reg_idx < p.registrations.len { p.registrations[reg_idx].fd } else { -1 };
        let ev_flags: u32 = if res.status != 0 {
            core::POLL_ERROR
        } else if res.bytes_transferred == 0 {
            core::POLL_READ | core::POLL_HANGUP
        } else {
            core::POLL_READ
        };
        let _ = out_events.try_push(core::PollReadyEvent {
            tag:             res.socket_context,
            fd:              fd_val,
            events:          ev_flags,
            bytes_available: res.bytes_transferred,
            is_eof:          res.status == 0 && res.bytes_transferred == 0,
            is_timer:        false,
        });
        p.total_events_dispatched = core::add_sat_u64(p.total_events_dispatched, 1);
        added = core::add_sat_u64(added, 1);
    }
    return added;
}

inline fn map_kevent_to_poll_flags(kev: const Kevent&) -> u32, bool {
    var flags: u32 = core::POLL_NONE;
    if kev.filter == EVFILT_READ {
        flags |= core::POLL_READ;
    } else if kev.filter == EVFILT_WRITE {
        flags |= core::POLL_WRITE;
    }
    let is_eof = (kev.flags & EV_EOF) != 0;
    if is_eof {
        flags |= core::POLL_HANGUP;
    }
    if is_eof && kev.fflags != 0 {
        flags |= core::POLL_ERROR;
    }
    return flags, is_eof;
}

fn uring_events_to_poll_mask(events: u32) -> u32 {
    var mask: u32 = 0;
    if (events & net::EPOLL_READ) != 0 { mask |= URING_POLLIN_MASK; }
    if (events & net::EPOLL_WRITE) != 0 { mask |= URING_POLLOUT_MASK; }
    return mask;
}

inline fn uring_submit_fd_poll(ring_fd: i64, fd: i32, events: u32) {
    let mask = uring_events_to_poll_mask(events);
    guard mask != 0 else { return; }
    var sqe = UringSqe { .. };
    uring_prep_poll_add(sqe, fd, mask, fd as u64);
    var batch: UringSqe[1] = [sqe];
    let _ = uring_submit_sqes(ring_fd, batch[..]);
}

fn uring_poll_mask_to_events(revents: u32) -> u32 {
    var mask: u32 = 0;
    if (revents & URING_POLLIN_MASK) != 0 { mask |= 1; }
    if (revents & URING_POLLOUT_MASK) != 0 { mask |= 2; }
    if (revents & URING_POLLERR_MASK) != 0 { mask |= 4; }
    if (revents & URING_POLLHUP_MASK) != 0 { mask |= 8; }
    return mask;
}

inline fn uring_consume_poll_cqe(
    up:         net::UringPoller&,
    cqe:        const UringCqe&,
    ready:      i64&,
    out_fds:    i64[:],
    out_udata:  u64[:],
    out_events: u32[:],
) {
    guard cqe.user_data != URING_INTERNAL_CANCEL_TAG &&
        cqe.res >= 0 &&
        (cqe.flags & URING_CQE_F_NOTIF) == 0 else { return; }
    let fd = cqe.user_data as i64;
    guard fd >= 0 && fd < up.watches.len && up.watches[fd].active else { return; }
    guard ready >= 0 && ready < out_udata.len && ready < out_events.len else { return; }

    let w = up.watches[fd];
    uring_submit_fd_poll(up.ring_fd, w.fd, w.events);
    let mask = uring_poll_mask_to_events(cqe.res as u32);
    guard mask != 0 else { return; }

    if ready < out_fds.len { out_fds[ready] = w.fd; }
    out_udata[ready] = w.udata;
    out_events[ready] = mask;
    ready = core::add_sat_i64(ready, 1);
}
