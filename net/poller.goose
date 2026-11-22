// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Non-blocking I/O multiplexer and event loop engine over Layer 4 drivers.
// Manages I/O readiness notifications and high-resolution timer queues
// across Windows RIO, Linux io_uring, macOS kqueue, and Standard POSIX sockets.
namespace net;

import std;
import net.driver;
import .tcp;
import .internal;
import .poller_internal;
import core;

// Time conversion constants
const NANOS_PER_MILLI: u64 = 1000000;
const NANOS_PER_SEC:   u64 = 1000000000;

// Poller capacity limits (Scaled for High-Density Concurrency)
const POLLER_MAX_REGISTRATIONS: i64 = 512;
const POLLER_MAX_TIMERS:        i64 = 64;

// Coarse 4-second timer constants (uSockets / uWebSockets pattern)
const COARSE_TIMEOUT_GRANULARITY_NS: u64 = 4000000000; // 4 seconds per tick
const COARSE_TIMEOUT_DISABLED:       u8  = 255;

// ---- Socket Registration & Simulated State ------------------------------

// Simulated readiness state for in-memory and testing multiplexing
struct SimulatedReadyState {
    ready: u32  = core::POLL_NONE,
    bytes: i64  = 0,
    eof:   bool = false,
}

struct SocketRegistration {
    fd:            i32                 = -1,
    tag:           u64                 = 0,
    interest:      core::PollInterest  = core::PollInterest.None,
    trigger:       core::PollTrigger   = core::PollTrigger.Level,
    in_use:        bool                = false,
    active_events: u32                 = core::POLL_NONE,
    timeout:       u8                  = COARSE_TIMEOUT_DISABLED, // 1-byte coarse timeout tick (0..239, 255 = none)
    sim:           SimulatedReadyState = SimulatedReadyState { .. },
}

// ---- High-Resolution Timer Wheel ----------------------------------------

struct PollerTimer {
    timer_id:    u64  = 0,
    tag:         u64  = 0,
    deadline_ns: u64  = 0,
    interval_ns: u64  = 0, // 0 = one-shot, >0 = periodic
    active:      bool = false,
}

// ---- Poller Structure ---------------------------------------------------

struct Poller {
    driver_cfg:              net_internal::TransportDriverConfig = net_internal::TransportDriverConfig { .. },
    registrations:           SocketRegistration[..512]           = [SocketRegistration { .. }; 512],
    fd_index:                core::FlatIndexBucket[1024]         = [core::FlatIndexBucket { .. }; 1024],
    tag_index:               core::FlatIndexBucket[1024]         = [core::FlatIndexBucket { .. }; 1024],
    timers:                  PollerTimer[..64]                   = [PollerTimer { .. }; 64],
    wake_tags:               u64[..64]                           = [],
    kqueue_changes:          net_internal::Kevent[..64]          = [],
    active_fd_count:         u32                                 = 0,
    active_timer_count:      u32                                 = 0,
    total_polls:             u64                                 = 0,
    total_events_dispatched: u64                                 = 0,
    global_coarse_tick:      u8                                  = 0,
    last_coarse_tick_ns:     u64                                 = 0,
    kqueue_fd:               i64                                 = -1,
    uring_ring_fd:           i64                                 = -1,
    rio_cq_id:               u64                                 = 0,
    epoll_fd:                i64                                 = -1,
    is_open:                 bool                                = false,
}

fn new_poller(driver_cfg: const net_internal::TransportDriverConfig&) -> Poller {
    var p = Poller {
        driver_cfg: driver_cfg,
        is_open:    true,
        ..
    };

    let plat = net_internal::detect_target_platform();
    if driver_cfg.active_kind == net_internal::TransportDriverKind.WindowsRIO {
        if plat == net_internal::TargetPlatform.Windows && driver_cfg.enable_kernel_bypass {
            p.rio_cq_id = net_internal::native_rio_create_cq(driver_cfg.ring_size);
        }
        p.epoll_fd = epoll_create();
    } else if driver_cfg.active_kind == net_internal::TransportDriverKind.IoUring {
        if plat == net_internal::TargetPlatform.Linux {
            p.uring_ring_fd = net_internal::native_uring_create(driver_cfg.ring_size, 0);
        }
        if p.uring_ring_fd < 0 {
            p.epoll_fd = epoll_create();
        }
    } else if driver_cfg.active_kind == net_internal::TransportDriverKind.Kqueue {
        if plat == net_internal::TargetPlatform.Darwin {
            p.kqueue_fd = net_internal::native_kqueue_create();
        }
        if p.kqueue_fd < 0 {
            p.epoll_fd = epoll_create();
        }
    } else {
        p.epoll_fd = epoll_create();
    }

    return p;
}

// Opts a Poller into live OS socket multiplexing (Linux epoll / Windows WSAPoll).
fn enable_os_multiplexing(p: Poller&) -> bool {
    guard p.is_open else { return false; }
    if p.epoll_fd >= 0 { return true; }
    let ep = epoll_create();
    guard ep >= 0 else { return false; }
    p.epoll_fd = ep;
    return true;
}

fn close_poller(p: Poller&) {
    if !p.is_open { return; }

    if p.epoll_fd >= 0 {
        epoll_close(p.epoll_fd);
        p.epoll_fd = -1;
    }
    if p.rio_cq_id != 0 {
        net_internal::native_rio_close_cq(p.rio_cq_id);
        p.rio_cq_id = 0;
    }
    if p.uring_ring_fd >= 0 {
        net_internal::native_uring_close(p.uring_ring_fd);
        p.uring_ring_fd = -1;
    }
    if p.kqueue_fd >= 0 {
        net_internal::native_kqueue_close(p.kqueue_fd);
        p.kqueue_fd = -1;
    }

    for i in p.registrations.len {
        p.registrations[i].in_use = false;
    }
    core::flat_index_clear(p.fd_index[..]);
    core::flat_index_clear(p.tag_index[..]);
    for i in p.timers.len {
        p.timers[i].active = false;
    }
    p.wake_tags.clear();
    p.kqueue_changes.clear();

    p.active_fd_count = 0;
    p.active_timer_count = 0;
    p.global_coarse_tick = 0;
    p.last_coarse_tick_ns = 0;
    p.is_open = false;
}

// ---- Registration Management --------------------------------------------

fn find_registration(p: const Poller&, fd: i32) -> i64 {
    guard fd >= 0 else { return -1; }
    let res = core::flat_index_get(p.fd_index[..], fd as u64);
    guard res.found && res.slot_idx >= 0 && res.slot_idx < p.registrations.len else { return -1; }
    guard p.registrations[res.slot_idx].in_use && p.registrations[res.slot_idx].fd == fd else { return -1; }
    return res.slot_idx;
}

fn find_by_tag(p: const Poller&, tag: u64) -> i64 {
    let res = core::flat_index_get(p.tag_index[..], tag);
    guard res.found && res.slot_idx >= 0 && res.slot_idx < p.registrations.len else { return -1; }
    guard p.registrations[res.slot_idx].in_use && p.registrations[res.slot_idx].tag == tag else { return -1; }
    return res.slot_idx;
}

fn register_socket(
    p:        Poller&,
    fd:       i32,
    tag:      u64,
    interest: core::PollInterest,
    trigger:  core::PollTrigger = core::PollTrigger.Level,
) -> bool {
    guard fd >= 0 else { return false; }
    let fd_probe = core::flat_index_get_or_put(p.fd_index[..], fd as u64);
    guard !fd_probe.found && fd_probe.bucket_idx >= 0 else { return false; }

    for i in p.registrations.len {
        if !p.registrations[i].in_use {
            p.registrations[i].fd = fd;
            p.registrations[i].tag = tag;
            p.registrations[i].interest = interest;
            p.registrations[i].trigger = trigger;
            p.registrations[i].in_use = true;
            p.registrations[i].active_events = core::POLL_NONE;
            p.registrations[i].timeout = COARSE_TIMEOUT_DISABLED;
            p.registrations[i].sim.ready = core::POLL_NONE;
            p.registrations[i].sim.bytes = 0;
            p.registrations[i].sim.eof = false;
            p.active_fd_count = core::add_sat_u64(p.active_fd_count, 1) as u32;
            let _, _ = core::flat_index_commit_put(p.fd_index[..], fd_probe.bucket_idx, fd as u64, i as u16);
            let tag_probe = core::flat_index_get_or_put(p.tag_index[..], tag);
            if !tag_probe.found && tag_probe.bucket_idx >= 0 {
                let _, _ = core::flat_index_commit_put(p.tag_index[..], tag_probe.bucket_idx, tag, i as u16);
            }
            net_internal::poller_bind_native_registration(p, fd, tag, interest, trigger);
            return true;
        }
    }
    return false; // Table full
}

fn modify_socket(
    p:        Poller&,
    fd:       i32,
    tag:      u64,
    interest: core::PollInterest,
    trigger:  core::PollTrigger = core::PollTrigger.Level,
) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }

    let old_tag = p.registrations[idx].tag;
    let old_interest = p.registrations[idx].interest;
    if old_tag != tag {
        let _ = core::flat_index_remove(p.tag_index[..], old_tag);
        let tag_probe = core::flat_index_get_or_put(p.tag_index[..], tag);
        if !tag_probe.found && tag_probe.bucket_idx >= 0 {
            let _, _ = core::flat_index_commit_put(p.tag_index[..], tag_probe.bucket_idx, tag, idx as u16);
        }
    }
    p.registrations[idx].tag = tag;
    p.registrations[idx].interest = interest;
    p.registrations[idx].trigger = trigger;
    net_internal::poller_mod_native_registration(p, fd, old_tag, old_interest, tag, interest, trigger);
    return true;
}

fn deregister_socket(p: Poller&, fd: i32) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }

    let old_tag = p.registrations[idx].tag;
    let old_interest = p.registrations[idx].interest;
    let _ = core::flat_index_remove(p.fd_index[..], fd as u64);
    let _ = core::flat_index_remove(p.tag_index[..], old_tag);
    p.registrations[idx].in_use = false;
    p.registrations[idx].fd = -1;
    p.registrations[idx].tag = 0;
    p.registrations[idx].interest = core::PollInterest.None;
    p.registrations[idx].timeout = COARSE_TIMEOUT_DISABLED;
    p.registrations[idx].sim.ready = core::POLL_NONE;
    if p.active_fd_count > 0 {
        p.active_fd_count = core::sub_sat_u64(p.active_fd_count, 1) as u32;
    }
    net_internal::poller_bind_native_deregister(p, fd, old_tag, old_interest);
    return true;
}

// ---- High-Resolution Timer Management -----------------------------------

fn add_timer(
    p:        Poller&,
    timer_id: u64,
    delay_ms: u64,
    tag:      u64,
    periodic: bool = false,
    now_ns:   u64  = 0,
) -> bool {
    guard timer_id != 0 else { return false; }

    let delay_ns = core::mul_sat_u64(delay_ms, NANOS_PER_MILLI);
    let deadline = core::add_sat_u64(now_ns, delay_ns);
    let interval: u64 = if periodic { delay_ns } else { 0 };

    // Check existing timer
    for i in p.timers.len {
        if p.timers[i].active && p.timers[i].timer_id == timer_id {
            p.timers[i].tag = tag;
            p.timers[i].deadline_ns = deadline;
            p.timers[i].interval_ns = interval;
            return true;
        }
    }

    for i in p.timers.len {
        if !p.timers[i].active {
            p.timers[i].timer_id = timer_id;
            p.timers[i].tag = tag;
            p.timers[i].deadline_ns = deadline;
            p.timers[i].interval_ns = interval;
            p.timers[i].active = true;
            p.active_timer_count = core::add_sat_u64(p.active_timer_count, 1) as u32;
            return true;
        }
    }
    return false;
}

fn cancel_timer(p: Poller&, timer_id: u64) -> bool {
    for i in p.timers.len {
        if p.timers[i].active && p.timers[i].timer_id == timer_id {
            p.timers[i].active = false;
            p.timers[i].timer_id = 0;
            if p.active_timer_count > 0 {
                p.active_timer_count = core::sub_sat_u64(p.active_timer_count, 1) as u32;
            }
            return true;
        }
    }
    return false;
}

// ---- Coarse Socket Timeout Management (uWebSockets 15-bit / 4s pattern) ----

// Sets or clears a coarse timeout (in seconds, 4-second granularity) on a registered socket.
// If seconds == 0, the timeout is disabled.
fn set_socket_timeout(p: Poller&, fd: i32, seconds: u32) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }
    if seconds == 0 {
        p.registrations[idx].timeout = COARSE_TIMEOUT_DISABLED;
    } else {
        let ticks_raw = core::add_sat_u64(seconds, 3) >> 2;
        let delta_ticks = min(max(ticks_raw, 1), 239);
        p.registrations[idx].timeout = (core::add_sat_u64(p.global_coarse_tick, delta_ticks) % 240) as u8;
    }
    return true;
}

// Retrieves the remaining timeout tick value or 255 if disabled
fn get_socket_timeout(p: const Poller&, fd: i32) -> u8 {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return COARSE_TIMEOUT_DISABLED; }
    return p.registrations[idx].timeout;
}

// Advances the coarse clock and dispatches expired coarse socket timeouts.
fn check_coarse_timeouts(p: Poller&, now_ns: u64, out_events: core::PollReadyEvent[..64]&) -> i32 {
    let old_tick, elapsed_ticks, ok_adv = net_internal::advance_coarse_clock(p, now_ns);
    guard ok_adv else { return 0; }

    var fired: i64 = 0;
    for i in p.registrations.len {
        if net_internal::dispatch_expired_registration(p.registrations[i], old_tick, elapsed_ticks, out_events) {
            fired = core::add_sat_i64(fired, 1);
        }
    }
    return fired as i32;
}

// ---- Wake Notification & Simulated Events (Testing & In-Memory Multiplexing)

// Queues a non-blocking wake notification for `tag` to be delivered as `POLL_WAKE`.
fn wake_tag(p: Poller&, tag: u64) -> bool {
    guard p.is_open else { return false; }
    for existing in p.wake_tags {
        if existing == tag {
            return true;
        }
    }
    return p.wake_tags.try_push(tag);
}

fn simulate_read_ready(p: Poller&, fd: i32, bytes_avail: i64 = 0) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }
    p.registrations[idx].sim.ready.set_flag(core::POLL_READ);
    p.registrations[idx].sim.bytes = bytes_avail;
    return true;
}

fn simulate_write_ready(p: Poller&, fd: i32) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }
    p.registrations[idx].sim.ready.set_flag(core::POLL_WRITE);
    return true;
}

fn simulate_error(p: Poller&, fd: i32) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }
    p.registrations[idx].sim.ready.set_flag(core::POLL_ERROR);
    return true;
}

fn simulate_hangup(p: Poller&, fd: i32) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }
    p.registrations[idx].sim.ready.set_flag(core::POLL_HANGUP);
    p.registrations[idx].sim.eof = true;
    return true;
}

// ---- Polling Execution --------------------------------------------------

// Gathers readiness events and expired timers into out_events without heap allocations.
// Returns total number of ready events harvested.
fn poll_events(
    p:          Poller&,
    timeout_ms: i64,
    now_ns:     u64,
    out_events: core::PollReadyEvent[..64]&,
) -> i32 {
    out_events.clear();
    p.total_polls = core::add_sat_u64(p.total_polls, 1);
    let eff_timeout = net_internal::clamp_timeout_to_timers(p, timeout_ms, now_ns);
    net_internal::poller_poll_native_drivers(p, eff_timeout, out_events);
    net_internal::check_wake_events(p, out_events);
    net_internal::check_expired_timers(p, now_ns, out_events);
    check_coarse_timeouts(p, now_ns, out_events);

    for i in p.registrations.len {
        guard p.registrations[i].in_use else { continue; }

        let interest_mask = core::interest_to_poll_flags(p.registrations[i].interest)
            | core::POLL_ERROR
            | core::POLL_HANGUP;
        let ready = p.registrations[i].sim.ready;
        let triggered: u32 = ready & interest_mask;

        if triggered != core::POLL_NONE {
            let ev = core::PollReadyEvent {
                tag:             p.registrations[i].tag,
                fd:              p.registrations[i].fd,
                events:          triggered,
                bytes_available: p.registrations[i].sim.bytes,
                is_eof:          p.registrations[i].sim.eof,
                is_timer:        false,
            };
            guard out_events.try_push(ev) else { break; }
            p.total_events_dispatched = core::add_sat_u64(p.total_events_dispatched, 1);
            net_internal::apply_trigger_clear_mask(p.registrations[i].trigger, p.registrations[i].sim, triggered);
        }
    }

    return out_events.len as i32;
}

// ---- Dynamic io_uring Readiness Poller (unbounded fd scale for Linux) ------

struct UringWatchSlot {
    fd:     i32  = -1,
    events: u32  = 0,
    udata:  u64  = 0,
    active: bool = false,
}

struct UringPoller {
    ring_fd: i64                 = -1,
    watches: UringWatchSlot[>..] = [],
}

// Probes whether the Linux kernel supports io_uring.
fn uring_is_available() -> bool {
    guard net_internal::detect_target_platform() == net_internal::TargetPlatform.Linux else {
        return false;
    }
    return net_internal::native_uring_probe() == 0;
}

fn uring_poll_open(up: UringPoller&, entries: u32 = 1024) -> bool {
    up.ring_fd = -1;
    up.watches.clear();
    guard uring_is_available() else { return false; }
    let rfd = net_internal::native_uring_create(entries, 0);
    guard rfd >= 0 else { return false; }
    up.ring_fd = rfd;
    return true;
}

fn uring_poll_close(up: UringPoller&) {
    if up.ring_fd >= 0 {
        net_internal::native_uring_close(up.ring_fd);
        up.ring_fd = -1;
    }
    up.watches.clear();
}

fn uring_poll_add(up: UringPoller&, fd: i64, events: u32, udata: u64) -> bool {
    guard up.ring_fd >= 0 && fd >= 0 && fd < 1048576 else { return false; }
    while up.watches.len <= fd {
        up.watches.push(UringWatchSlot { .. });
    }
    up.watches[fd] = UringWatchSlot {
        fd:     fd as i32,
        events: events,
        udata:  udata,
        active: true,
    };
    net_internal::uring_submit_fd_poll(up.ring_fd, fd as i32, events);
    return true;
}

fn uring_poll_mod(up: UringPoller&, fd: i64, events: u32, udata: u64) -> bool {
    guard up.ring_fd >= 0 && fd >= 0 && fd < up.watches.len && up.watches[fd].active else {
        return uring_poll_add(up, fd, events, udata);
    }
    net_internal::poller_submit_uring_poll_remove(up.ring_fd, fd as u64);
    up.watches[fd].events = events;
    up.watches[fd].udata = udata;
    net_internal::uring_submit_fd_poll(up.ring_fd, up.watches[fd].fd, events);
    return true;
}

fn uring_poll_del(up: UringPoller&, fd: i64) -> bool {
    guard up.ring_fd >= 0 && fd >= 0 && fd < up.watches.len else { return false; }
    if up.watches[fd].active {
        net_internal::poller_submit_uring_poll_remove(up.ring_fd, fd as u64);
        up.watches[fd].active = false;
    }
    return true;
}

fn uring_poll_wait_events(
    up:         UringPoller&,
    out_fds:    i64[:],
    out_udata:  u64[:],
    out_events: u32[:],
    timeout_ms: i32,
) -> i32 {
    guard up.ring_fd >= 0 && out_udata.len > 0 && out_events.len > 0 else { return 0; }
    var cqes: net_internal::UringCqe[64] = [net_internal::UringCqe { .. }; 64];
    let min_complete: u32 = if timeout_ms == 0 { 0 } else { 1 };
    let timeout_ns = net_internal::timeout_ms_to_ns(timeout_ms);
    let n = net_internal::uring_wait_cqes(up.ring_fd, cqes[..], min_complete, timeout_ns);
    guard n > 0 else { return 0; }

    var ready: i64 = 0;
    let max_out = min(out_udata.len, out_events.len);
    let limit = min(n, 64);
    for k in limit {
        guard ready < max_out else { break; }
        net_internal::uring_consume_poll_cqe(up, cqes[k], ready, out_fds, out_udata, out_events);
    }
    return ready as i32;
}
