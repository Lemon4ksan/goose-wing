// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Non-blocking I/O multiplexer and event loop engine over Layer 4 drivers.
// Manages I/O readiness notifications and high-resolution timer queues
// across Windows RIO, Linux io_uring, macOS kqueue, and Standard POSIX sockets.
namespace wing;

import std;
import net.driver;
import .tcp;
import core from "..";

// Time conversion constants
const NANOS_PER_MILLI: u64 = 1000000;
const NANOS_PER_SEC:   u64 = 1000000000;

// Poller capacity limits (Scaled for High-Density Concurrency)
const POLLER_MAX_REGISTRATIONS: i64 = 512;
const POLLER_MAX_TIMERS:        i64 = 64;

// Coarse 4-second timer constants (uSockets / uWebSockets pattern)
const COARSE_TIMEOUT_GRANULARITY_NS: u64 = 4000000000; // 4 seconds per tick
const COARSE_TIMEOUT_DISABLED:       u8  = 255;

// ---- Readiness Event Trigger Helpers ------------------------------------

inline fn apply_trigger_clear_mask(t: core::PollTrigger.Edge, sim: SimulatedReadyState&, triggered: u32) {
    sim.ready.clear_flag(triggered);
    sim.bytes = 0;
}

inline fn apply_trigger_clear_mask(t: core::PollTrigger.Level, sim: SimulatedReadyState&, triggered: u32) {
    sim.ready.clear_flag(core::POLL_WRITE);
}

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
    driver_cfg:              internal::TransportDriverConfig = internal::TransportDriverConfig { .. },
    registrations:           SocketRegistration[..512]       = [SocketRegistration { .. }; 512],
    fd_index:                core::FlatIndexBucket[1024]     = [core::FlatIndexBucket { .. }; 1024],
    tag_index:               core::FlatIndexBucket[1024]     = [core::FlatIndexBucket { .. }; 1024],
    timers:                  PollerTimer[..64]               = [PollerTimer { .. }; 64],
    wake_tags:               u64[..64]                       = [],
    kqueue_changes:          internal::Kevent[..64]          = [],
    active_fd_count:         u32                             = 0,
    active_timer_count:      u32                             = 0,
    total_polls:             u64                             = 0,
    total_events_dispatched: u64                             = 0,
    global_coarse_tick:      u8                              = 0,
    last_coarse_tick_ns:     u64                             = 0,
    kqueue_fd:               i64                             = -1,
    uring_ring_fd:           i64                             = -1,
    rio_cq_id:               u64                             = 0,
    epoll_fd:                i64                             = -1,
    is_open:                 bool                            = false,
}

fn new_poller(driver_cfg: const internal::TransportDriverConfig&) -> Poller {
    var p = Poller {
        driver_cfg: driver_cfg,
        is_open:    true,
        ..
    };

    let plat = internal::detect_target_platform();
    if driver_cfg.active_kind == internal::TransportDriverKind.WindowsRIO {
        if plat == internal::TargetPlatform.Windows && driver_cfg.enable_kernel_bypass {
            p.rio_cq_id = internal::native_rio_create_cq(driver_cfg.ring_size);
        }
        p.epoll_fd = epoll_create();
    } else if driver_cfg.active_kind == internal::TransportDriverKind.IoUring {
        if plat == internal::TargetPlatform.Linux {
            p.uring_ring_fd = internal::native_uring_create(driver_cfg.ring_size, 0);
        }
        if p.uring_ring_fd < 0 {
            p.epoll_fd = epoll_create();
        }
    } else if driver_cfg.active_kind == internal::TransportDriverKind.Kqueue {
        if plat == internal::TargetPlatform.Darwin {
            p.kqueue_fd = internal::native_kqueue_create();
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
        internal::native_rio_close_cq(p.rio_cq_id);
        p.rio_cq_id = 0;
    }
    if p.uring_ring_fd >= 0 {
        internal::native_uring_close(p.uring_ring_fd);
        p.uring_ring_fd = -1;
    }
    if p.kqueue_fd >= 0 {
        internal::native_kqueue_close(p.kqueue_fd);
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

const URING_INTERNAL_CANCEL_TAG: u64 = 0xFFFFFFFFFFFFFFFF;
const URING_POLLIN_MASK:         u32 = 1;
const URING_POLLOUT_MASK:        u32 = 4;
const URING_POLLERR_MASK:        u32 = 8;
const URING_POLLHUP_MASK:        u32 = 16;
const KQUEUE_EV_ERROR_FLAG:      u16 = 0x4000;

fn interest_to_epoll_flags(interest: core::PollInterest) -> u32 {
    return match interest {
        Read => EPOLL_READ,
        Write => EPOLL_WRITE,
        ReadWrite => EPOLL_READ | EPOLL_WRITE,
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
    if internal::detect_target_platform() == internal::TargetPlatform.Windows {
        return native_tcp_get_readable_bytes(fd) >= 0;
    }
    return true;
}

inline fn poller_push_kqueue_change(p: Poller&, ev: internal::Kevent) {
    if p.kqueue_changes.len >= p.kqueue_changes.cap {
        var empty_out: internal::Kevent[1] = [internal::Kevent { .. }];
        let _ = internal::kqueue_poll_slice(p.kqueue_fd, p.kqueue_changes[..], empty_out[..0], 0);
        p.kqueue_changes.clear();
    }
    let _ = p.kqueue_changes.try_push(ev);
}

inline fn poller_queue_kqueue_interest(
    p:        Poller&,
    fd:       i32,
    tag:      u64,
    interest: core::PollInterest,
    trigger:  core::PollTrigger,
) {
    let edge = trigger == core::PollTrigger.Edge;
    if interest == core::PollInterest.Read || interest == core::PollInterest.ReadWrite {
        var ev_r = internal::Kevent { .. };
        internal::kevent_prep_read(ev_r, fd, tag, edge);
        poller_push_kqueue_change(p, ev_r);
    }
    if interest == core::PollInterest.Write || interest == core::PollInterest.ReadWrite {
        var ev_w = internal::Kevent { .. };
        internal::kevent_prep_write(ev_w, fd, tag, edge);
        poller_push_kqueue_change(p, ev_w);
    }
}

inline fn poller_submit_uring_poll_add(ring_fd: i64, fd: i32, interest: core::PollInterest, tag: u64) {
    let mask = interest_to_uring_poll_mask(interest);
    guard mask != 0 else { return; }
    var sqe = internal::UringSqe { .. };
    internal::uring_prep_poll_add(sqe, fd, mask, tag);
    var batch: internal::UringSqe[1] = [sqe];
    let _ = internal::uring_submit_sqes(ring_fd, batch[..]);
}

inline fn poller_bind_native_registration(
    p:        Poller&,
    fd:       i32,
    tag:      u64,
    interest: core::PollInterest,
    trigger:  core::PollTrigger,
) {
    if p.epoll_fd >= 0 && is_live_os_socket_fd(fd) {
        let _ = epoll_add(p.epoll_fd, fd, interest_to_epoll_flags(interest), tag);
    }
    if p.kqueue_fd >= 0 {
        poller_queue_kqueue_interest(p, fd, tag, interest, trigger);
    }
    if p.uring_ring_fd >= 0 {
        poller_submit_uring_poll_add(p.uring_ring_fd, fd, interest, tag);
    }
}

inline fn poller_mod_native_registration(
    p:        Poller&,
    fd:       i32,
    old_tag:  u64,
    tag:      u64,
    interest: core::PollInterest,
    trigger:  core::PollTrigger,
) {
    if p.epoll_fd >= 0 && is_live_os_socket_fd(fd) {
        let flags = interest_to_epoll_flags(interest);
        if !epoll_mod(p.epoll_fd, fd, flags, tag) {
            let _ = epoll_add(p.epoll_fd, fd, flags, tag);
        }
    }
    if p.kqueue_fd >= 0 {
        poller_push_kqueue_change(p, internal::Kevent {
            ident: fd as u64, filter: internal::EVFILT_READ, flags: internal::EV_DELETE, ..
        });
        poller_push_kqueue_change(p, internal::Kevent {
            ident: fd as u64, filter: internal::EVFILT_WRITE, flags: internal::EV_DELETE, ..
        });
        poller_queue_kqueue_interest(p, fd, tag, interest, trigger);
    }
    if p.uring_ring_fd >= 0 {
        var rm_sqe = internal::UringSqe { .. };
        internal::uring_prep_poll_remove(rm_sqe, old_tag, URING_INTERNAL_CANCEL_TAG);
        var rm_batch: internal::UringSqe[1] = [rm_sqe];
        let _ = internal::uring_submit_sqes(p.uring_ring_fd, rm_batch[..]);
        poller_submit_uring_poll_add(p.uring_ring_fd, fd, interest, tag);
    }
}

inline fn poller_bind_native_deregister(p: Poller&, fd: i32, old_tag: u64) {
    if p.epoll_fd >= 0 {
        let _ = epoll_del(p.epoll_fd, fd);
    }
    if p.kqueue_fd >= 0 {
        poller_push_kqueue_change(p, internal::Kevent {
            ident: fd as u64, filter: internal::EVFILT_READ, flags: internal::EV_DELETE, ..
        });
        poller_push_kqueue_change(p, internal::Kevent {
            ident: fd as u64, filter: internal::EVFILT_WRITE, flags: internal::EV_DELETE, ..
        });
    }
    if p.uring_ring_fd >= 0 {
        var rm_sqe = internal::UringSqe { .. };
        internal::uring_prep_poll_remove(rm_sqe, old_tag, URING_INTERNAL_CANCEL_TAG);
        var rm_batch: internal::UringSqe[1] = [rm_sqe];
        let _ = internal::uring_submit_sqes(p.uring_ring_fd, rm_batch[..]);
    }
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
            p.active_fd_count += 1;
            let _, _ = core::flat_index_commit_put(p.fd_index[..], fd_probe.bucket_idx, fd as u64, i as u16);
            let tag_probe = core::flat_index_get_or_put(p.tag_index[..], tag);
            if !tag_probe.found && tag_probe.bucket_idx >= 0 {
                let _, _ = core::flat_index_commit_put(p.tag_index[..], tag_probe.bucket_idx, tag, i as u16);
            }
            poller_bind_native_registration(p, fd, tag, interest, trigger);
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
    poller_mod_native_registration(p, fd, old_tag, tag, interest, trigger);
    return true;
}

fn deregister_socket(p: Poller&, fd: i32) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }

    let old_tag = p.registrations[idx].tag;
    let _ = core::flat_index_remove(p.fd_index[..], fd as u64);
    let _ = core::flat_index_remove(p.tag_index[..], old_tag);
    p.registrations[idx].in_use = false;
    p.registrations[idx].fd = -1;
    p.registrations[idx].tag = 0;
    p.registrations[idx].interest = core::PollInterest.None;
    p.registrations[idx].timeout = COARSE_TIMEOUT_DISABLED;
    p.registrations[idx].sim.ready = core::POLL_NONE;
    if p.active_fd_count > 0 {
        p.active_fd_count -= 1;
    }
    poller_bind_native_deregister(p, fd, old_tag);
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

    // Check existing timer
    for i in p.timers.len {
        if p.timers[i].active && p.timers[i].timer_id == timer_id {
            // Update existing timer deadline and interval
            p.timers[i].tag = tag;
            p.timers[i].deadline_ns = now_ns + (delay_ms * NANOS_PER_MILLI);
            p.timers[i].interval_ns = if periodic { delay_ms * NANOS_PER_MILLI } else { 0 };
            return true;
        }
    }

    for i in p.timers.len {
        if !p.timers[i].active {
            p.timers[i].timer_id = timer_id;
            p.timers[i].tag = tag;
            p.timers[i].deadline_ns = now_ns + (delay_ms * NANOS_PER_MILLI);
            p.timers[i].interval_ns = if periodic { delay_ms * NANOS_PER_MILLI } else { 0 };
            p.timers[i].active = true;
            p.active_timer_count += 1;
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
                p.active_timer_count -= 1;
            }
            return true;
        }
    }
    return false;
}

fn check_expired_timers(p: Poller&, now_ns: u64, out_events: core::PollReadyEvent[..64]&) -> i32 {
    var fired_count: i32 = 0;
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
        fired_count += 1;

        if p.timers[i].interval_ns > 0 {
            // Periodic timer: schedule next occurrence
            p.timers[i].deadline_ns = now_ns + p.timers[i].interval_ns;
        } else {
            // One-shot timer: deactivate
            p.timers[i].active = false;
            if p.active_timer_count > 0 {
                p.active_timer_count -= 1;
            }
        }
    }
    return fired_count;
}

// ---- 6b. Coarse Socket Timeout Management (uWebSockets 15-bit / 4s pattern) -

// Sets or clears a coarse timeout (in seconds, 4-second granularity) on a registered socket.
// If seconds == 0, the timeout is disabled.
fn set_socket_timeout(p: Poller&, fd: i32, seconds: u32) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }
    if seconds == 0 {
        p.registrations[idx].timeout = COARSE_TIMEOUT_DISABLED;
    } else {
        let delta_ticks: u32 = min(max((seconds + 3) >> 2, 1), 239);
        p.registrations[idx].timeout = ((p.global_coarse_tick + delta_ticks) % 240) as u8;
    }
    return true;
}

// Retrieves the remaining timeout tick value or 255 if disabled
fn get_socket_timeout(p: const Poller&, fd: i32) -> u8 {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return COARSE_TIMEOUT_DISABLED; }
    return p.registrations[idx].timeout;
}

inline fn is_coarse_timeout_expired(t: u8, old_tick: u64, elapsed_ticks: u64) -> bool {
    guard t != COARSE_TIMEOUT_DISABLED else { return false; }
    guard elapsed_ticks < 240 else { return true; }
    let dist = (t as u64 + 240 - old_tick) % 240;
    return dist > 0 && dist <= elapsed_ticks;
}

inline fn dispatch_expired_registration(
    reg:           SocketRegistration&,
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
    reg.timeout = COARSE_TIMEOUT_DISABLED;
    return true;
}

inline fn advance_coarse_clock(p: Poller&, now_ns: u64, old_tick: u64&, elapsed_ticks: u64&) -> bool {
    guard p.last_coarse_tick_ns > 0 else {
        p.last_coarse_tick_ns = now_ns;
        return false;
    }
    guard now_ns >= p.last_coarse_tick_ns + COARSE_TIMEOUT_GRANULARITY_NS else {
        return false;
    }
    let el = (now_ns - p.last_coarse_tick_ns) / COARSE_TIMEOUT_GRANULARITY_NS;
    elapsed_ticks = el;
    p.last_coarse_tick_ns += el * COARSE_TIMEOUT_GRANULARITY_NS;
    old_tick = p.global_coarse_tick;
    p.global_coarse_tick = ((old_tick + elapsed_ticks) % 240) as u8;
    return true;
}

// Advances the coarse clock and dispatches expired coarse socket timeouts.
fn check_coarse_timeouts(p: Poller&, now_ns: u64, out_events: core::PollReadyEvent[..64]&) -> i32 {
    var old_tick:      u64 = 0;
    var elapsed_ticks: u64 = 0;
    guard advance_coarse_clock(p, now_ns, old_tick, elapsed_ticks) else { return 0; }

    var fired: i32 = 0;
    for i in p.registrations.len {
        if dispatch_expired_registration(p.registrations[i], old_tick, elapsed_ticks, out_events) {
            fired += 1;
        }
    }
    return fired;
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

fn check_wake_events(p: Poller&, out_events: core::PollReadyEvent[..64]&) -> i32 {
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

// Maps a slice of Windows RIO `RioResult` items into `PollReadyEvent` entries on `out_events`.
fn rio_map_completions_to_events(
    p:          Poller&,
    results:    const internal::RioResult[:],
    out_events: core::PollReadyEvent[..64]&,
) -> u64 {
    var added: u64 = 0;
    for res in results {
        guard out_events.len < out_events.cap else { break; }
        let reg_idx = find_by_tag(p, res.socket_context);
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

fn has_pending_simulated_ready(p: const Poller&) -> bool {
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

// Exact reciprocal ceil(2^64 / 1_000_000) for shift-free mulhi_u64 ns -> ms conversion.
const NS_TO_MS_MULHI_RECIP: u64 = 0x10C6F7A0B5EE;
const MAX_POLL_TIMEOUT_NS:  u64 = 2147483647000000;

fn find_earliest_timer_deadline_ns(p: const Poller&) -> u64, bool {
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

fn clamp_timeout_to_timers(p: const Poller&, timeout_ms: i64, now_ns: u64) -> i64 {
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

fn poller_collect_epoll_events(
    p:          Poller&,
    timeout_ms: i64,
    out_events: core::PollReadyEvent[..64]&,
) {
    var raw_fds:   i64[64] = [0; 64];
    var raw_udata: u64[64] = [0; 64];
    let t_clamped = min(max(timeout_ms, -1), 2147483647);
    let n = epoll_wait_direct(p.epoll_fd, raw_fds[..], raw_udata[..], t_clamped as i32);
    guard n > 0 else { return; }

    let limit = min(n as i64, 64);
    for k in limit {
        let tag = raw_udata[k];
        let reg_idx = find_by_tag(p, tag);
        guard reg_idx >= 0 else { continue; }
        let fd_val = p.registrations[reg_idx].fd;
        let ev_flags = core::interest_to_poll_flags(p.registrations[reg_idx].interest);
        let avail_raw = if (ev_flags & core::POLL_READ) != 0 {
            native_tcp_get_readable_bytes(fd_val)
        } else {
            0
        };
        let ev = core::PollReadyEvent {
            tag:             tag,
            fd:              fd_val,
            events:          if ev_flags != core::POLL_NONE { ev_flags } else { core::POLL_READ },
            bytes_available: max(avail_raw, 0),
            is_eof:          false,
            is_timer:        false,
        };
        guard out_events.try_push(ev) else { break; }
        p.total_events_dispatched = core::add_sat_u64(p.total_events_dispatched, 1);
    }
}

inline fn map_kevent_to_poll_flags(kev: const internal::Kevent&) -> u32, bool {
    var flags: u32 = core::POLL_NONE;
    if kev.filter == internal::EVFILT_READ {
        flags |= core::POLL_READ;
    } else if kev.filter == internal::EVFILT_WRITE {
        flags |= core::POLL_WRITE;
    }
    let is_eof = (kev.flags & internal::EV_EOF) != 0;
    if is_eof {
        flags |= core::POLL_HANGUP;
    }
    return flags, is_eof;
}

fn poller_collect_kqueue_events(
    p:          Poller&,
    timeout_ms: i64,
    out_events: core::PollReadyEvent[..64]&,
) {
    var kev_out: internal::Kevent[64] = [internal::Kevent { .. }; 64];
    let n = internal::kqueue_poll_slice(p.kqueue_fd, p.kqueue_changes[..], kev_out[..], timeout_ms);
    p.kqueue_changes.clear();
    guard n > 0 else { return; }

    let limit = min(n as i64, 64);
    for k in limit {
        let kev = kev_out[k];
        guard (kev.flags & KQUEUE_EV_ERROR_FLAG) == 0 else { continue; }
        let reg_idx = find_by_tag(p, kev.udata);
        guard reg_idx >= 0 else { continue; }
        let flags, is_eof = map_kevent_to_poll_flags(kev);
        guard flags != core::POLL_NONE else { continue; }
        let ev = core::PollReadyEvent {
            tag:             kev.udata,
            fd:              p.registrations[reg_idx].fd,
            events:          flags,
            bytes_available: max(kev.data, 0),
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
    p:          Poller&,
    timeout_ms: i64,
    out_events: core::PollReadyEvent[..64]&,
) {
    var cqes: internal::UringCqe[64] = [internal::UringCqe { .. }; 64];
    let min_complete: u32 = if timeout_ms == 0 { 0 } else { 1 };
    let n = internal::uring_wait_cqes(p.uring_ring_fd, cqes[..], min_complete, timeout_ms);
    guard n > 0 else { return; }

    let limit = min(n as i64, 64);
    for k in limit {
        let cqe = cqes[k];
        guard cqe.user_data != URING_INTERNAL_CANCEL_TAG && cqe.res >= 0 else { continue; }
        let reg_idx = find_by_tag(p, cqe.user_data);
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

inline fn poller_poll_native_drivers(
    p:          Poller&,
    timeout_ms: i64,
    out_events: core::PollReadyEvent[..64]&,
) {
    if p.rio_cq_id != 0 {
        var rio_results: internal::RioResult[..64] = [];
        let n = internal::rio_drain_completions(p.rio_cq_id, rio_results);
        if n > 0 {
            let _ = rio_map_completions_to_events(p, rio_results[..], out_events);
        }
    }
    let eff_timeout = if out_events.len > 0 { 0 } else { timeout_ms };
    if p.uring_ring_fd >= 0 {
        poller_collect_uring_events(p, eff_timeout, out_events);
    } else if p.kqueue_fd >= 0 {
        poller_collect_kqueue_events(p, eff_timeout, out_events);
    } else if p.epoll_fd >= 0 {
        poller_collect_epoll_events(p, eff_timeout, out_events);
    }
}

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
    let eff_timeout = clamp_timeout_to_timers(p, timeout_ms, now_ns);
    poller_poll_native_drivers(p, eff_timeout, out_events);
    check_wake_events(p, out_events);
    check_expired_timers(p, now_ns, out_events);
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
            apply_trigger_clear_mask(p.registrations[i].trigger, p.registrations[i].sim, triggered);
        }
    }

    return out_events.len as i32;
}
