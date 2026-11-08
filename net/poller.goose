// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Non-blocking I/O multiplexer and event loop engine over Layer 4 drivers.
// Manages I/O readiness notifications and high-resolution timer queues
// across Windows RIO, Linux io_uring, macOS kqueue, and Standard POSIX sockets.
namespace wing;

import std;
import net.driver;
import core from "..";

// Time conversion constants
const NANOS_PER_MILLI: u64 = 1000000;
const NANOS_PER_SEC:   u64 = 1000000000;

// Poller and event loop capacity limits (Scaled for High-Density Concurrency)
const POLLER_MAX_REGISTRATIONS: i64 = 512;
const POLLER_MAX_TIMERS:        i64 = 64;
const EVENT_LOOP_MAX_BUFFERS:   i64 = 64;
const CONNECTION_BUFFER_CAP:    i64 = 4096;

// Coarse 4-second timer constants (uSockets / uWebSockets pattern)
const COARSE_TIMEOUT_GRANULARITY_NS: u64 = 4000000000; // 4 seconds per tick
const COARSE_TIMEOUT_DISABLED:       u8  = 255;

// ---- Readiness Event Flags & Types --------------------------------------

const POLL_NONE:   u32 = 0;
const POLL_READ:   u32 = 1 << 0;  // Ready to read / incoming connection ready to accept
const POLL_WRITE:  u32 = 1 << 1;  // Socket buffer space available for write
const POLL_ERROR:  u32 = 1 << 2;  // Error condition on descriptor
const POLL_HANGUP: u32 = 1 << 3;  // Connection terminated / remote EOF
const POLL_TIMER:  u32 = 1 << 4;  // High-resolution timer or coarse socket timeout fired

enum PollInterest {
    None,
    Read,
    Write,
    ReadWrite,
}

inline fn interest_to_poll_flags(i: PollInterest.None) -> u32 { return POLL_NONE; }
inline fn interest_to_poll_flags(i: PollInterest.Read) -> u32 { return POLL_READ; }
inline fn interest_to_poll_flags(i: PollInterest.Write) -> u32 { return POLL_WRITE; }
inline fn interest_to_poll_flags(i: PollInterest.ReadWrite) -> u32 { return POLL_READ | POLL_WRITE; }

enum PollTrigger {
    Level, // Level-triggered: persists until condition drained
    Edge,  // Edge-triggered: notified only on state transition (EPOLLET / EV_CLEAR)
}

inline fn apply_trigger_clear_mask(t: PollTrigger.Edge, sim: SimulatedReadyState&, triggered: u32) {
    sim.ready &= ~triggered;
    sim.bytes = 0;
}

inline fn apply_trigger_clear_mask(t: PollTrigger.Level, sim: SimulatedReadyState&, triggered: u32) {
    sim.ready &= ~POLL_WRITE;
}

struct PollReadyEvent {
    tag:             u64  = 0,
    fd:              i32  = -1,
    events:          u32  = POLL_NONE,
    bytes_available: i64  = 0, // Exact unread bytes (from kqueue data / io_uring CQE)
    is_eof:          bool = false,
    is_timer:        bool = false,
}

// ---- Socket Registration & Simulated State ------------------------------

// Simulated readiness state for in-memory and testing multiplexing
struct SimulatedReadyState {
    ready: u32  = POLL_NONE,
    bytes: i64  = 0,
    eof:   bool = false,
}

struct SocketRegistration {
    fd:            i32                 = -1,
    tag:           u64                 = 0,
    interest:      PollInterest        = PollInterest.None,
    trigger:       PollTrigger         = PollTrigger.Level,
    in_use:        bool                = false,
    active_events: u32                 = POLL_NONE,
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
    timers:                  PollerTimer[..64]               = [PollerTimer { .. }; 64],
    active_fd_count:         u32                             = 0,
    active_timer_count:      u32                             = 0,
    total_polls:             u64                             = 0,
    total_events_dispatched: u64                             = 0,
    global_coarse_tick:      u8                              = 0,
    last_coarse_tick_ns:     u64                             = 0,
    kqueue_fd:               i64                             = -1,
    uring_ring_fd:           i64                             = -1,
    rio_cq_id:               u64                             = 0,
    is_open:                 bool                            = false,
}

fn new_poller(driver_cfg: const internal::TransportDriverConfig&) -> Poller {
    var p = Poller {
        driver_cfg: driver_cfg,
        is_open:    true,
        ..
    };

    // Initialize native OS polling handles if available on platform
    let plat = internal::detect_target_platform();
    if driver_cfg.active_kind == internal::TransportDriverKind.WindowsRIO {
        if plat == internal::TargetPlatform.Windows && driver_cfg.enable_kernel_bypass {
            let cq = internal::native_rio_create_cq(driver_cfg.ring_size);
            p.rio_cq_id = cq;
        }
    } else if driver_cfg.active_kind == internal::TransportDriverKind.IoUring {
        if plat == internal::TargetPlatform.Linux {
            let fd = internal::native_uring_create(driver_cfg.ring_size, 0);
            p.uring_ring_fd = fd;
        }
    } else if driver_cfg.active_kind == internal::TransportDriverKind.Kqueue {
        if plat == internal::TargetPlatform.Darwin {
            let fd = internal::native_kqueue_create();
            p.kqueue_fd = fd;
        }
    }

    return p;
}

fn close_poller(p: Poller&) {
    if !p.is_open { return; }

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
    for i in p.timers.len {
        p.timers[i].active = false;
    }

    p.active_fd_count = 0;
    p.active_timer_count = 0;
    p.global_coarse_tick = 0;
    p.last_coarse_tick_ns = 0;
    p.is_open = false;
}

// ---- Registration Management --------------------------------------------

fn find_registration(p: const Poller&, fd: i32) -> i64 {
    for i in p.registrations.len {
        if p.registrations[i].in_use && p.registrations[i].fd == fd {
            return i;
        }
    }
    return -1;
}

fn find_by_tag(p: const Poller&, tag: u64) -> i64 {
    for i in p.registrations.len {
        if p.registrations[i].in_use && p.registrations[i].tag == tag {
            return i;
        }
    }
    return -1;
}

inline fn poller_bind_native_registration(
    p:        Poller&,
    fd:       i32,
    tag:      u64,
    interest: PollInterest,
    trigger:  PollTrigger,
) {
    if p.kqueue_fd >= 0 {
        var ev = internal::Kevent { .. };
        let edge = trigger == PollTrigger.Edge;
        if interest == PollInterest.Read || interest == PollInterest.ReadWrite {
            internal::kevent_prep_read(ev, fd, tag, edge);
        } else if interest == PollInterest.Write {
            internal::kevent_prep_write(ev, fd, tag, edge);
        }
    }
}

inline fn poller_bind_native_deregister(p: Poller&, fd: i32) {
    if p.kqueue_fd >= 0 {
        var ev = internal::Kevent { ident: fd as u64, filter: internal::EVFILT_READ, flags: internal::EV_DELETE, .. };
    }
}

fn register_socket(
    p:        Poller&,
    fd:       i32,
    tag:      u64,
    interest: PollInterest,
    trigger:  PollTrigger = PollTrigger.Level,
) -> bool {
    guard fd >= 0 else { return false; }
    guard find_registration(p, fd) < 0 else { return false; } // Already registered

    for i in p.registrations.len {
        if !p.registrations[i].in_use {
            p.registrations[i].fd = fd;
            p.registrations[i].tag = tag;
            p.registrations[i].interest = interest;
            p.registrations[i].trigger = trigger;
            p.registrations[i].in_use = true;
            p.registrations[i].active_events = POLL_NONE;
            p.registrations[i].timeout = COARSE_TIMEOUT_DISABLED;
            p.registrations[i].sim.ready = POLL_NONE;
            p.registrations[i].sim.bytes = 0;
            p.registrations[i].sim.eof = false;
            p.active_fd_count += 1;
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
    interest: PollInterest,
    trigger:  PollTrigger = PollTrigger.Level,
) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }

    p.registrations[idx].tag = tag;
    p.registrations[idx].interest = interest;
    p.registrations[idx].trigger = trigger;
    poller_bind_native_registration(p, fd, tag, interest, trigger);
    return true;
}

fn deregister_socket(p: Poller&, fd: i32) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }

    p.registrations[idx].in_use = false;
    p.registrations[idx].fd = -1;
    p.registrations[idx].tag = 0;
    p.registrations[idx].interest = PollInterest.None;
    p.registrations[idx].timeout = COARSE_TIMEOUT_DISABLED;
    p.registrations[idx].sim.ready = POLL_NONE;
    if p.active_fd_count > 0 {
        p.active_fd_count -= 1;
    }
    poller_bind_native_deregister(p, fd);
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

fn check_expired_timers(p: Poller&, now_ns: u64, out_events: PollReadyEvent[..64]&) -> i32 {
    var fired_count: i32 = 0;
    for i in p.timers.len {
        guard p.timers[i].active && now_ns >= p.timers[i].deadline_ns else { continue; }
        let ev = PollReadyEvent {
            tag:             p.timers[i].tag,
            fd:              -1,
            events:          POLL_TIMER,
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
    out_events:    PollReadyEvent[..64]&,
) -> bool {
    guard reg.in_use else { return false; }
    guard is_coarse_timeout_expired(reg.timeout, old_tick, elapsed_ticks) else { return false; }
    guard out_events.try_push(PollReadyEvent {
        tag:             reg.tag,
        fd:              reg.fd,
        events:          POLL_TIMER,
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
fn check_coarse_timeouts(p: Poller&, now_ns: u64, out_events: PollReadyEvent[..64]&) -> i32 {
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

// ---- Simulated Events (Testing & In-Memory Multiplexing) -----------------

fn simulate_read_ready(p: Poller&, fd: i32, bytes_avail: i64 = 0) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }
    p.registrations[idx].sim.ready |= POLL_READ;
    p.registrations[idx].sim.bytes = bytes_avail;
    return true;
}

fn simulate_write_ready(p: Poller&, fd: i32) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }
    p.registrations[idx].sim.ready |= POLL_WRITE;
    return true;
}

fn simulate_error(p: Poller&, fd: i32) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }
    p.registrations[idx].sim.ready |= POLL_ERROR;
    return true;
}

fn simulate_hangup(p: Poller&, fd: i32) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }
    p.registrations[idx].sim.ready |= POLL_HANGUP;
    p.registrations[idx].sim.eof = true;
    return true;
}

// ---- Polling Execution --------------------------------------------------

// Maps a slice of Windows RIO `RioResult` items into `PollReadyEvent` entries on `out_events`.
fn rio_map_completions_to_events(
    p:          Poller&,
    results:    const internal::RioResult[:],
    out_events: PollReadyEvent[..64]&,
) -> u64 {
    var added: u64 = 0;
    for res in results {
        guard out_events.len < out_events.cap else { break; }
        let reg_idx = find_by_tag(p, res.socket_context);
        let fd_val: i32 = if reg_idx >= 0 && reg_idx < p.registrations.len { p.registrations[reg_idx].fd } else { -1 };
        let ev_flags: u32 = if res.status != 0 {
            POLL_ERROR
        } else if res.bytes_transferred == 0 {
            POLL_READ | POLL_HANGUP
        } else {
            POLL_READ
        };
        let _ = out_events.try_push(PollReadyEvent {
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

inline fn poller_poll_native_drivers(p: Poller&, timeout_ms: i64, out_events: PollReadyEvent[..64]&) {
    if p.kqueue_fd >= 0 {
        internal::native_kqueue_kevent(p.kqueue_fd, 0, 0, 0, 64, timeout_ms * 1000000);
    } else if p.uring_ring_fd >= 0 {
        internal::native_uring_enter(p.uring_ring_fd, 0, 1, 0);
    } else if p.rio_cq_id != 0 {
        var rio_results: internal::RioResult[..64] = [];
        let n = internal::rio_drain_completions(p.rio_cq_id, rio_results);
        if n > 0 {
            let _ = rio_map_completions_to_events(p, rio_results[..], out_events);
        }
    }
}

// Gathers readiness events and expired timers into out_events without heap allocations.
// Returns total number of ready events harvested.
fn poll_events(
    p:          Poller&,
    timeout_ms: i64,
    now_ns:     u64,
    out_events: PollReadyEvent[..64]&,
) -> i32 {
    out_events.clear();
    p.total_polls = core::add_sat_u64(p.total_polls, 1);
    poller_poll_native_drivers(p, timeout_ms, out_events);
    check_expired_timers(p, now_ns, out_events);
    check_coarse_timeouts(p, now_ns, out_events);

    for i in p.registrations.len {
        guard p.registrations[i].in_use else { continue; }

        let interest_mask = interest_to_poll_flags(p.registrations[i].interest) | POLL_ERROR | POLL_HANGUP;
        let ready = p.registrations[i].sim.ready;
        let triggered: u32 = ready & interest_mask;

        if triggered != POLL_NONE {
            let ev = PollReadyEvent {
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

// ---- Connection Buffers & Non-blocking Event Loop -----------------------

enum LoopState {
    Created,
    Running,
    Stopped,
}

struct ConnectionBuffer {
    fd:           i32        = -1,
    tag:          u64        = 0,
    read_buf:     u8[..4096] = [],
    write_buf:    u8[..4096] = [],
    write_offset: i64        = 0,
    closed:       bool       = false,
    in_use:       bool       = false,
}

// Deferred cross-thread or asynchronous task (uWebSockets / uSockets loop->defer pattern)
struct DeferredTask {
    tag:       u64  = 0,
    user_data: u64  = 0,
    task_id:   u32  = 0,
    in_use:    bool = false,
}

struct EventLoop {
    poller:                  Poller                          = Poller { .. },
    driver_cfg:              internal::TransportDriverConfig = internal::TransportDriverConfig { .. },
    buffers:                 ConnectionBuffer[..64]          = [ConnectionBuffer { .. }; 64],
    deferred_tasks:          DeferredTask[..64]              = [DeferredTask { .. }; 64],
    deferred_count:          u32                             = 0,
    state:                   LoopState                       = LoopState.Created,
    iteration_count:         u64                             = 0,
    events_dispatched_total: u64                             = 0,
}

fn new_event_loop(driver_cfg: const internal::TransportDriverConfig&) -> EventLoop {
    var p = new_poller(driver_cfg);
    return EventLoop {
        poller:     p,
        driver_cfg: driver_cfg,
        state:      LoopState.Created,
        ..
    };
}

fn close_event_loop(ev_loop: EventLoop&) {
    close_poller(ev_loop.poller);
    for i in ev_loop.buffers.len {
        ev_loop.buffers[i].in_use = false;
        ev_loop.buffers[i].read_buf.clear();
        ev_loop.buffers[i].write_buf.clear();
    }
    ev_loop.state = LoopState.Stopped;
}

fn find_connection_buffer(ev_loop: const EventLoop&, tag: u64) -> i64 {
    for i in ev_loop.buffers.len {
        if ev_loop.buffers[i].in_use && ev_loop.buffers[i].tag == tag {
            return i;
        }
    }
    return -1;
}

// Binds a socket to the event loop, allocating zero-heap connection buffers
fn bind_connection(
    ev_loop:  EventLoop&,
    fd:       i32,
    tag:      u64,
    interest: PollInterest,
    trigger:  PollTrigger = PollTrigger.Level,
) -> bool {
    guard register_socket(ev_loop.poller, fd, tag, interest, trigger) else { return false; }
    var committed = false;
    defer if !committed { deregister_socket(ev_loop.poller, fd); };

    for i in ev_loop.buffers.len {
        if !ev_loop.buffers[i].in_use {
            ev_loop.buffers[i].fd = fd;
            ev_loop.buffers[i].tag = tag;
            ev_loop.buffers[i].read_buf.clear();
            ev_loop.buffers[i].write_buf.clear();
            ev_loop.buffers[i].write_offset = 0;
            ev_loop.buffers[i].closed = false;
            ev_loop.buffers[i].in_use = true;
            committed = true;
            return true;
        }
    }

    return false;
}

fn unbind_connection(ev_loop: EventLoop&, tag: u64) -> bool {
    let b_idx = find_connection_buffer(ev_loop, tag);
    if b_idx >= 0 {
        let fd = ev_loop.buffers[b_idx].fd;
        deregister_socket(ev_loop.poller, fd);
        ev_loop.buffers[b_idx].in_use = false;
        ev_loop.buffers[b_idx].read_buf.clear();
        ev_loop.buffers[b_idx].write_buf.clear();
        return true;
    }
    return false;
}

// Sets or clears a coarse timeout for an active connection in the event loop.
fn set_connection_timeout(ev_loop: EventLoop&, tag: u64, seconds: u32) -> bool {
    let b_idx = find_connection_buffer(ev_loop, tag);
    guard b_idx >= 0 else { return false; }
    return set_socket_timeout(ev_loop.poller, ev_loop.buffers[b_idx].fd, seconds);
}

// Queues data to be sent on socket when writable
fn queue_write(ev_loop: EventLoop&, tag: u64, data: const u8[:]) -> bool {
    let b_idx = find_connection_buffer(ev_loop, tag);
    guard b_idx >= 0 else { return false; }
    guard ev_loop.buffers[b_idx].write_buf.try_append(data) else {
        return false; // Buffer overflow
    }
    simulate_write_ready(ev_loop.poller, ev_loop.buffers[b_idx].fd);
    return true;
}

// Feeds incoming data into the connection read buffer (e.g. from NIC, socket, or mock)
fn feed_read(ev_loop: EventLoop&, tag: u64, data: const u8[:]) -> bool {
    let b_idx = find_connection_buffer(ev_loop, tag);
    guard b_idx >= 0 else { return false; }
    guard ev_loop.buffers[b_idx].read_buf.try_append(data) else {
        return false;
    }
    simulate_read_ready(ev_loop.poller, ev_loop.buffers[b_idx].fd, ev_loop.buffers[b_idx].read_buf.len);
    return true;
}

// Reads available data from the connection buffer
fn consume_read<B>(ev_loop: EventLoop&, tag: u64, out: B&) -> i64 {
    let b_idx = find_connection_buffer(ev_loop, tag);
    guard b_idx >= 0 else { return 0; }
    let avail = ev_loop.buffers[b_idx].read_buf.len;
    let space = max(0, out.cap - out.len);
    let to_copy = min(avail, space);
    if to_copy > 0 {
        out.append(ev_loop.buffers[b_idx].read_buf[..to_copy]);
        ev_loop.buffers[b_idx].read_buf.compact_wire_buffer(to_copy);
    }

    let remaining = ev_loop.buffers[b_idx].read_buf.len;
    let fd = ev_loop.buffers[b_idx].fd;
    let r_idx = find_registration(ev_loop.poller, fd);
    if r_idx >= 0 {
        if remaining == 0 {
            ev_loop.poller.registrations[r_idx].sim.ready &= ~POLL_READ;
            ev_loop.poller.registrations[r_idx].sim.bytes = 0;
        } else {
            ev_loop.poller.registrations[r_idx].sim.bytes = remaining;
        }
    }

    return to_copy;
}

inline fn flush_socket_writes(fd: i32, buf: u8[..4096]&) -> i64 {
    guard fd >= 0 else {
        let count = buf.len;
        buf.clear();
        return count;
    }
    let sent = tcp_send(fd, buf[..]);
    if sent <= 0 {
        let count = buf.len;
        buf.clear();
        return count;
    }
    let sent_i64 = sent as i64;
    buf.compact_wire_buffer(sent_i64);
    return sent_i64;
}

// Flushes outgoing queued write buffer
fn flush_writes(ev_loop: EventLoop&, tag: u64) -> i64 {
    let b_idx = find_connection_buffer(ev_loop, tag);
    guard b_idx >= 0 else { return 0; }
    ev_loop.buffers[b_idx].write_offset = 0;
    return flush_socket_writes(ev_loop.buffers[b_idx].fd, ev_loop.buffers[b_idx].write_buf);
}

// Runs a single non-blocking event loop iteration, dispatching harvested events to handler
fn run_loop_once<HandlerFn: fn(u64, const PollReadyEvent&, EventLoop&)>(
    ev_loop:    EventLoop&,
    timeout_ms: i64,
    now_ns:     u64,
) -> i32 {
    ev_loop.state = LoopState.Running;
    ev_loop.iteration_count += 1;

    var events: PollReadyEvent[..64] = [];
    let count = poll_events(ev_loop.poller, timeout_ms, now_ns, events);

    for i in events.len {
        let ev = events[i];
        HandlerFn(ev.tag, ev, ev_loop);
        ev_loop.events_dispatched_total += 1;
    }

    return count;
}

// Defers execution of a task to the event loop thread (uWebSockets / uSockets loop->defer pattern)
fn defer_task(ev_loop: EventLoop&, tag: u64, user_data: u64, task_id: u32 = 0) -> bool {
    guard ev_loop.deferred_count < ev_loop.deferred_tasks.len as u32 else { return false; }
    let idx = ev_loop.deferred_count as i64;
    ev_loop.deferred_tasks[idx].tag = tag;
    ev_loop.deferred_tasks[idx].user_data = user_data;
    ev_loop.deferred_tasks[idx].task_id = task_id;
    ev_loop.deferred_tasks[idx].in_use = true;
    ev_loop.deferred_count += 1;
    return true;
}

fn has_deferred_tasks(ev_loop: const EventLoop&) -> bool {
    return ev_loop.deferred_count > 0;
}

// Drains all pending deferred tasks in single pass, dispatching to TaskFn callback
fn drain_deferred_tasks<TaskFn: fn(u64, u64, u32, EventLoop&)>(ev_loop: EventLoop&) -> u32 {
    let count = ev_loop.deferred_count;
    guard count > 0 else { return 0; }

    for i in count as i64 {
        if ev_loop.deferred_tasks[i].in_use {
            let tag = ev_loop.deferred_tasks[i].tag;
            let user_data = ev_loop.deferred_tasks[i].user_data;
            let task_id = ev_loop.deferred_tasks[i].task_id;
            ev_loop.deferred_tasks[i].in_use = false;
            TaskFn(tag, user_data, task_id, ev_loop);
        }
    }
    let total_now = ev_loop.deferred_count;
    if total_now > count {
        let added = (total_now - count) as i64;
        let offset = count as i64;
        for i in added {
            ev_loop.deferred_tasks[i] = ev_loop.deferred_tasks[offset + i];
            ev_loop.deferred_tasks[offset + i].in_use = false;
        }
        ev_loop.deferred_count = total_now - count;
    } else {
        ev_loop.deferred_count = 0;
    }
    return count;
}
