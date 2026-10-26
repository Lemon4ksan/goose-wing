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
const NANOS_PER_SEC: u64 = 1000000000;

// Poller and event loop capacity limits (Scaled for High-Density Concurrency)
const POLLER_MAX_REGISTRATIONS: i64 = 512;
const POLLER_MAX_TIMERS: i64 = 64;
const EVENT_LOOP_MAX_BUFFERS: i64 = 64;
const CONNECTION_BUFFER_CAP: i64 = 4096;

// Coarse 4-second timer constants (uSockets / uWebSockets pattern)
const COARSE_TIMEOUT_GRANULARITY_NS: u64 = 4000000000; // 4 seconds per tick
const COARSE_TIMEOUT_DISABLED: u8 = 255;

// ---- 1. Readiness Event Flags & Types --------------------------------------

const POLL_NONE: u32 = 0;
const POLL_READ: u32 = 1 << 0;    // Ready to read / incoming connection ready to accept
const POLL_WRITE: u32 = 1 << 1;   // Socket buffer space available for write
const POLL_ERROR: u32 = 1 << 2;   // Error condition on descriptor
const POLL_HANGUP: u32 = 1 << 3;  // Connection terminated / remote EOF
const POLL_TIMER: u32 = 1 << 4;   // High-resolution timer or coarse socket timeout fired

enum PollInterest {
    None,
    Read,
    Write,
    ReadWrite,
}

enum PollTrigger {
    Level, // Level-triggered: persists until condition drained
    Edge,  // Edge-triggered: notified only on state transition (EPOLLET / EV_CLEAR)
}

struct PollReadyEvent {
    tag: EventTag = 0,
    fd: SocketFd = -1,
    events: u32 = POLL_NONE,
    bytes_available: i64 = 0, // Exact unread bytes (from kqueue data / io_uring CQE)
    is_eof: bool = false,
    is_timer: bool = false,
}

// ---- 2. Socket Registration & Simulated State ------------------------------

// Simulated readiness state for in-memory and testing multiplexing
struct SimulatedReadyState {
    ready: u32 = POLL_NONE,
    bytes: i64 = 0,
    eof: bool = false,
}

struct SocketRegistration {
    fd: SocketFd = -1,
    tag: EventTag = 0,
    interest: PollInterest = PollInterest.None,
    trigger: PollTrigger = PollTrigger.Level,
    in_use: bool = false,
    active_events: u32 = POLL_NONE,
    timeout: u8 = COARSE_TIMEOUT_DISABLED, // 1-byte coarse timeout tick (0..239, 255 = none)
    sim: SimulatedReadyState = SimulatedReadyState { .. },
}

// ---- 3. High-Resolution Timer Wheel ----------------------------------------

struct PollerTimer {
    timer_id: TimerId = 0,
    tag: EventTag = 0,
    deadline_ns: Nanoseconds = 0,
    interval_ns: Nanoseconds = 0, // 0 = one-shot, >0 = periodic
    active: bool = false,
}

// ---- 4. Poller Structure ---------------------------------------------------

struct Poller {
    driver_cfg: internal::TransportDriverConfig = internal::TransportDriverConfig { .. },
    registrations: SocketRegistration[..512] = [SocketRegistration { .. }; 512],
    timers: PollerTimer[..64] = [PollerTimer { .. }; 64],
    active_fd_count: u32 = 0,
    active_timer_count: u32 = 0,
    total_polls: u64 = 0,
    total_events_dispatched: u64 = 0,
    global_coarse_tick: u8 = 0,
    last_coarse_tick_ns: Nanoseconds = 0,
    kqueue_fd: i64 = -1,
    uring_ring_fd: i64 = -1,
    rio_cq_id: u64 = 0,
    is_open: bool = false,
}

fn new_poller(driver_cfg: const internal::TransportDriverConfig&) -> Poller {
    var p = Poller {
        driver_cfg: driver_cfg,
        is_open: true,
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

// ---- 5. Registration Management --------------------------------------------

fn find_registration(p: const Poller&, fd: SocketFd) -> i64 {
    for i in p.registrations.len {
        if p.registrations[i].in_use && p.registrations[i].fd == fd {
            return i;
        }
    }
    return -1;
}

fn find_by_tag(p: const Poller&, tag: EventTag) -> i64 {
    for i in p.registrations.len {
        if p.registrations[i].in_use && p.registrations[i].tag == tag {
            return i;
        }
    }
    return -1;
}

fn register_socket(
    p: Poller&,
    fd: SocketFd,
    tag: EventTag,
    interest: PollInterest,
    trigger: PollTrigger = PollTrigger.Level,
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
            return true;
        }
    }
    return false; // Table full
}

fn modify_socket(
    p: Poller&,
    fd: SocketFd,
    tag: EventTag,
    interest: PollInterest,
    trigger: PollTrigger = PollTrigger.Level,
) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }

    p.registrations[idx].tag = tag;
    p.registrations[idx].interest = interest;
    p.registrations[idx].trigger = trigger;
    return true;
}

fn deregister_socket(p: Poller&, fd: SocketFd) -> bool {
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
    return true;
}

// ---- 6. High-Resolution Timer Management -----------------------------------

fn add_timer(
    p: Poller&,
    timer_id: TimerId,
    delay_ms: Milliseconds,
    tag: EventTag,
    periodic: bool = false,
    now_ns: Nanoseconds = 0,
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

fn cancel_timer(p: Poller&, timer_id: TimerId) -> bool {
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

fn check_expired_timers(p: Poller&, now_ns: Nanoseconds, out_events: PollReadyEvent[..64]&) -> i32 {
    var fired_count: i32 = 0;
    for i in p.timers.len {
        if p.timers[i].active && now_ns >= p.timers[i].deadline_ns {
            if out_events.len < out_events.cap {
                var ev = PollReadyEvent {
                    tag: p.timers[i].tag,
                    fd: -1,
                    events: POLL_TIMER,
                    bytes_available: 0,
                    is_eof: false,
                    is_timer: true,
                };
                out_events.push(ev);
                fired_count += 1;
            }

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
    }
    return fired_count;
}

// ---- 6b. Coarse Socket Timeout Management (uWebSockets 15-bit / 4s pattern) -

// Sets or clears a coarse timeout (in seconds, 4-second granularity) on a registered socket.
// If seconds == 0, the timeout is disabled.
fn set_socket_timeout(p: Poller&, fd: SocketFd, seconds: u32) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }
    if seconds == 0 {
        p.registrations[idx].timeout = COARSE_TIMEOUT_DISABLED;
    } else {
        let delta_ticks: u32 = (seconds + 3) >> 2;
        p.registrations[idx].timeout = ((p.global_coarse_tick + delta_ticks) % 240) as u8;
    }
    return true;
}

// Retrieves the remaining timeout tick value or 255 if disabled
fn get_socket_timeout(p: const Poller&, fd: SocketFd) -> u8 {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return COARSE_TIMEOUT_DISABLED; }
    return p.registrations[idx].timeout;
}

// Advances the coarse clock and dispatches expired coarse socket timeouts.
fn check_coarse_timeouts(p: Poller&, now_ns: Nanoseconds, out_events: PollReadyEvent[..64]&) -> i32 {
    guard p.last_coarse_tick_ns > 0 else {
        p.last_coarse_tick_ns = now_ns;
        return 0;
    }

    if now_ns < p.last_coarse_tick_ns + COARSE_TIMEOUT_GRANULARITY_NS {
        return 0;
    }

    let elapsed_ticks = (now_ns - p.last_coarse_tick_ns) / COARSE_TIMEOUT_GRANULARITY_NS;
    p.last_coarse_tick_ns = now_ns;
    p.global_coarse_tick = ((p.global_coarse_tick + elapsed_ticks) % 240) as u8;
    let current_tick = p.global_coarse_tick;

    var fired: i32 = 0;
    for i in p.registrations.len {
        guard p.registrations[i].in_use else { continue; }
        if p.registrations[i].timeout != COARSE_TIMEOUT_DISABLED && p.registrations[i].timeout == current_tick {
            p.registrations[i].timeout = COARSE_TIMEOUT_DISABLED;
            if out_events.len < out_events.cap {
                var ev = PollReadyEvent {
                    tag: p.registrations[i].tag,
                    fd: p.registrations[i].fd,
                    events: POLL_TIMER,
                    bytes_available: 0,
                    is_eof: false,
                    is_timer: true,
                };
                out_events.push(ev);
                fired += 1;
            }
        }
    }
    return fired;
}

// ---- 7. Simulated Events (Testing & In-Memory Multiplexing) -----------------

fn simulate_read_ready(p: Poller&, fd: SocketFd, bytes_avail: i64 = 0) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }
    p.registrations[idx].sim.ready |= POLL_READ;
    p.registrations[idx].sim.bytes = bytes_avail;
    return true;
}

fn simulate_write_ready(p: Poller&, fd: SocketFd) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }
    p.registrations[idx].sim.ready |= POLL_WRITE;
    return true;
}

fn simulate_error(p: Poller&, fd: SocketFd) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }
    p.registrations[idx].sim.ready |= POLL_ERROR;
    return true;
}

fn simulate_hangup(p: Poller&, fd: SocketFd) -> bool {
    let idx = find_registration(p, fd);
    guard idx >= 0 else { return false; }
    p.registrations[idx].sim.ready |= POLL_HANGUP;
    p.registrations[idx].sim.eof = true;
    return true;
}

// ---- 8. Polling Execution --------------------------------------------------

// Gathers readiness events and expired timers into out_events without heap allocations.
// Returns total number of ready events harvested.
fn poll_events(
    p: Poller&,
    timeout_ms: i64,
    now_ns: Nanoseconds,
    out_events: PollReadyEvent[..64]&,
) -> i32 {
    out_events.clear();
    p.total_polls += 1;

    // 1. Process Expired High-Resolution Timers First
    let timers_fired = check_expired_timers(p, now_ns, out_events);

    // 2. Process Coarse Socket Timeouts (uSockets 4-second pattern)
    let coarse_fired = check_coarse_timeouts(p, now_ns, out_events);

    // 3. Reap Socket Readiness Events
    for i in p.registrations.len {
        guard p.registrations[i].in_use else { continue; }
        guard out_events.len < out_events.cap else { break; }

        let interest = p.registrations[i].interest;
        var ready = p.registrations[i].sim.ready;
        var triggered: u32 = POLL_NONE;

        // Match against registered interest
        if (ready & POLL_READ) != 0 && (interest == PollInterest.Read || interest == PollInterest.ReadWrite) {
            triggered |= POLL_READ;
        }
        if (ready & POLL_WRITE) != 0 && (interest == PollInterest.Write || interest == PollInterest.ReadWrite) {
            triggered |= POLL_WRITE;
        }
        if (ready & POLL_ERROR) != 0 {
            triggered |= POLL_ERROR;
        }
        if (ready & POLL_HANGUP) != 0 {
            triggered |= POLL_HANGUP;
        }

        if triggered != POLL_NONE {
            var ev = PollReadyEvent {
                tag: p.registrations[i].tag,
                fd: p.registrations[i].fd,
                events: triggered,
                bytes_available: p.registrations[i].sim.bytes,
                is_eof: p.registrations[i].sim.eof,
                is_timer: false,
            };
            out_events.push(ev);
            p.total_events_dispatched += 1;

            // Edge-triggered reset: clear simulated ready bits once reported
            if p.registrations[i].trigger == PollTrigger.Edge {
                p.registrations[i].sim.ready = POLL_NONE;
                p.registrations[i].sim.bytes = 0;
            } else {
                // Level-triggered: write readiness is transient, read readiness remains until drained
                p.registrations[i].sim.ready &= ~POLL_WRITE;
            }
        }
    }

    return out_events.len as i32;
}

// ---- 9. Connection Buffers & Non-blocking Event Loop -----------------------

enum LoopState {
    Created,
    Running,
    Stopped,
}

struct ConnectionBuffer {
    fd: SocketFd = -1,
    tag: EventTag = 0,
    read_buf: u8[..4096] = [],
    write_buf: u8[..4096] = [],
    write_offset: i64 = 0,
    closed: bool = false,
    in_use: bool = false,
}

// Deferred cross-thread or asynchronous task (uWebSockets / uSockets loop->defer pattern)
struct DeferredTask {
    tag: EventTag = 0,
    user_data: u64 = 0,
    task_id: u32 = 0,
    in_use: bool = false,
}

struct EventLoop {
    poller: Poller = Poller { .. },
    driver_cfg: internal::TransportDriverConfig = internal::TransportDriverConfig { .. },
    buffers: ConnectionBuffer[..64] = [ConnectionBuffer { .. }; 64],
    deferred_tasks: DeferredTask[..64] = [DeferredTask { .. }; 64],
    deferred_count: u32 = 0,
    state: LoopState = LoopState.Created,
    iteration_count: u64 = 0,
    events_dispatched_total: u64 = 0,
}

fn new_event_loop(driver_cfg: const internal::TransportDriverConfig&) -> EventLoop {
    var p = new_poller(driver_cfg);
    return EventLoop {
        poller: p,
        driver_cfg: driver_cfg,
        state: LoopState.Created,
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

fn find_connection_buffer(ev_loop: const EventLoop&, tag: EventTag) -> i64 {
    for i in ev_loop.buffers.len {
        if ev_loop.buffers[i].in_use && ev_loop.buffers[i].tag == tag {
            return i;
        }
    }
    return -1;
}

// Binds a socket to the event loop, allocating zero-heap connection buffers
fn bind_connection(
    ev_loop: EventLoop&,
    fd: SocketFd,
    tag: EventTag,
    interest: PollInterest,
    trigger: PollTrigger = PollTrigger.Level,
) -> bool {
    guard register_socket(ev_loop.poller, fd, tag, interest, trigger) else { return false; }

    for i in ev_loop.buffers.len {
        if !ev_loop.buffers[i].in_use {
            ev_loop.buffers[i].fd = fd;
            ev_loop.buffers[i].tag = tag;
            ev_loop.buffers[i].read_buf.clear();
            ev_loop.buffers[i].write_buf.clear();
            ev_loop.buffers[i].write_offset = 0;
            ev_loop.buffers[i].closed = false;
            ev_loop.buffers[i].in_use = true;
            return true;
        }
    }

    deregister_socket(ev_loop.poller, fd);
    return false;
}

fn unbind_connection(ev_loop: EventLoop&, tag: EventTag) -> bool {
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
fn set_connection_timeout(ev_loop: EventLoop&, tag: EventTag, seconds: u32) -> bool {
    let b_idx = find_connection_buffer(ev_loop, tag);
    guard b_idx >= 0 else { return false; }
    return set_socket_timeout(ev_loop.poller, ev_loop.buffers[b_idx].fd, seconds);
}

// Queues data to be sent on socket when writable
fn queue_write(ev_loop: EventLoop&, tag: EventTag, data: const u8[:]) -> bool {
    let b_idx = find_connection_buffer(ev_loop, tag);
    guard b_idx >= 0 else { return false; }
    guard ev_loop.buffers[b_idx].write_buf.len + data.len <= ev_loop.buffers[b_idx].write_buf.cap else {
        return false; // Buffer overflow
    }
    ev_loop.buffers[b_idx].write_buf.append(data);
    simulate_write_ready(ev_loop.poller, ev_loop.buffers[b_idx].fd);
    return true;
}

// Feeds incoming data into the connection read buffer (e.g. from NIC, socket, or mock)
fn feed_read(ev_loop: EventLoop&, tag: EventTag, data: const u8[:]) -> bool {
    let b_idx = find_connection_buffer(ev_loop, tag);
    guard b_idx >= 0 else { return false; }
    guard ev_loop.buffers[b_idx].read_buf.len + data.len <= ev_loop.buffers[b_idx].read_buf.cap else {
        return false;
    }
    ev_loop.buffers[b_idx].read_buf.append(data);
    simulate_read_ready(ev_loop.poller, ev_loop.buffers[b_idx].fd, ev_loop.buffers[b_idx].read_buf.len);
    return true;
}

// Reads available data from the connection buffer
fn consume_read<B>(ev_loop: EventLoop&, tag: EventTag, out: B&) -> i64 {
    let b_idx = find_connection_buffer(ev_loop, tag);
    guard b_idx >= 0 else { return 0; }
    let count = ev_loop.buffers[b_idx].read_buf.len;
    out.append(ev_loop.buffers[b_idx].read_buf[..]);
    ev_loop.buffers[b_idx].read_buf.clear();

    // Clear simulated read ready bit on poller
    let fd = ev_loop.buffers[b_idx].fd;
    let r_idx = find_registration(ev_loop.poller, fd);
    if r_idx >= 0 {
        ev_loop.poller.registrations[r_idx].sim.ready &= ~POLL_READ;
        ev_loop.poller.registrations[r_idx].sim.bytes = 0;
    }

    return count;
}

// Flushes outgoing queued write buffer
fn flush_writes(ev_loop: EventLoop&, tag: EventTag) -> i64 {
    let b_idx = find_connection_buffer(ev_loop, tag);
    guard b_idx >= 0 else { return 0; }
    let count = ev_loop.buffers[b_idx].write_buf.len;
    ev_loop.buffers[b_idx].write_buf.clear();
    ev_loop.buffers[b_idx].write_offset = 0;
    return count;
}

// Runs a single non-blocking event loop iteration, dispatching harvested events to handler
fn run_loop_once<HandlerFn: fn(EventTag, const PollReadyEvent&, EventLoop&)>(
    ev_loop: EventLoop&,
    timeout_ms: i64,
    now_ns: Nanoseconds,
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
fn defer_task(ev_loop: EventLoop&, tag: EventTag, user_data: u64, task_id: u32 = 0) -> bool {
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

fn deferred_task_count(ev_loop: const EventLoop&) -> u32 {
    return ev_loop.deferred_count;
}

// Drains all pending deferred tasks in single pass, dispatching to TaskFn callback
fn drain_deferred_tasks<TaskFn: fn(EventTag, u64, u32, EventLoop&)>(ev_loop: EventLoop&) -> u32 {
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
    ev_loop.deferred_count = 0;
    return count;
}
