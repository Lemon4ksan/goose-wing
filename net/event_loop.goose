// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Buffered connection event loop and deferred task queue over Poller.
namespace wing;

import std;
import core from "..";
import .driver;
import .poller;
import .tcp;

const EVENT_LOOP_MAX_BUFFERS: i64 = 64;
const CONNECTION_BUFFER_CAP:  i64 = 4096;

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
    poller:                  Poller                              = Poller { .. },
    driver_cfg:              net_internal::TransportDriverConfig = net_internal::TransportDriverConfig { .. },
    buffers:                 ConnectionBuffer[..64]              = [ConnectionBuffer { .. }; 64],
    deferred_tasks:          DeferredTask[..64]                  = [DeferredTask { .. }; 64],
    deferred_count:          i64                                 = 0,
    state:                   LoopState                           = LoopState.Created,
    iteration_count:         u64                                 = 0,
    events_dispatched_total: u64                                 = 0,
}

fn new_event_loop(driver_cfg: const net_internal::TransportDriverConfig&) -> EventLoop {
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
    interest: core::PollInterest,
    trigger:  core::PollTrigger = core::PollTrigger.Level,
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
        return false;
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
    let space = max(0, core::sub_sat_i64(out.cap, out.len));
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
            ev_loop.poller.registrations[r_idx].sim.ready &= ~core::POLL_READ;
            ev_loop.poller.registrations[r_idx].sim.bytes = 0;
        } else {
            ev_loop.poller.registrations[r_idx].sim.bytes = remaining;
        }
    }

    return to_copy;
}

inline fn flush_socket_writes(fd: i32, buf: u8[..4096]&) -> i64 {
    guard buf.len > 0 else { return 0; }
    guard fd >= 0 else {
        let count = buf.len;
        buf.clear();
        return count;
    }
    let sent = tcp_send2(fd, buf[..], "");
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

// Flushes outgoing queued write buffer
fn flush_writes(ev_loop: EventLoop&, tag: u64) -> i64 {
    let b_idx = find_connection_buffer(ev_loop, tag);
    guard b_idx >= 0 else { return 0; }
    ev_loop.buffers[b_idx].write_offset = 0;
    return flush_socket_writes(ev_loop.buffers[b_idx].fd, ev_loop.buffers[b_idx].write_buf);
}

// Runs a single non-blocking event loop iteration, dispatching harvested events to handler
fn run_loop_once<HandlerFn: fn(u64, const core::PollReadyEvent&, EventLoop&)>(
    ev_loop:    EventLoop&,
    timeout_ms: i64,
    now_ns:     u64,
) -> i32 {
    ev_loop.state = LoopState.Running;
    ev_loop.iteration_count = core::add_sat_u64(ev_loop.iteration_count, 1);

    var events: core::PollReadyEvent[..64] = [];
    let count = poll_events(ev_loop.poller, timeout_ms, now_ns, events);

    for i in events.len {
        let ev = events[i];
        if (ev.events & core::POLL_WRITE) != 0 {
            let b_idx = find_connection_buffer(ev_loop, ev.tag);
            if b_idx >= 0 && ev_loop.buffers[b_idx].write_buf.len > 0 &&
                is_live_os_socket_fd(ev_loop.buffers[b_idx].fd) {
                let _ = flush_socket_writes(ev_loop.buffers[b_idx].fd, ev_loop.buffers[b_idx].write_buf);
            }
        }
        HandlerFn(ev.tag, ev, ev_loop);
        ev_loop.events_dispatched_total = core::add_sat_u64(ev_loop.events_dispatched_total, 1);
    }

    return count;
}

// Queues a wake tag for delivery as `core::POLL_WAKE` on the next poll pass.
fn wake_tag(ev_loop: EventLoop&, tag: u64) -> bool {
    guard ev_loop.state != LoopState.Stopped else { return false; }
    return wake_tag(ev_loop.poller, tag);
}

// Opts the loop's underlying poller into live OS socket multiplexing (epoll / WSAPoll).
fn enable_os_multiplexing(ev_loop: EventLoop&) -> bool {
    guard ev_loop.state != LoopState.Stopped else { return false; }
    return enable_os_multiplexing(ev_loop.poller);
}

fn register_socket(
    ev_loop:  EventLoop&,
    fd:       i32,
    tag:      u64,
    interest: core::PollInterest,
    trigger:  core::PollTrigger = core::PollTrigger.Level,
) -> bool {
    guard ev_loop.state != LoopState.Stopped else { return false; }
    return register_socket(ev_loop.poller, fd, tag, interest, trigger);
}

fn modify_socket(
    ev_loop:  EventLoop&,
    fd:       i32,
    tag:      u64,
    interest: core::PollInterest,
    trigger:  core::PollTrigger = core::PollTrigger.Level,
) -> bool {
    guard ev_loop.state != LoopState.Stopped else { return false; }
    return modify_socket(ev_loop.poller, fd, tag, interest, trigger);
}

fn deregister_socket(ev_loop: EventLoop&, fd: i32) -> bool {
    guard ev_loop.state != LoopState.Stopped else { return false; }
    return deregister_socket(ev_loop.poller, fd);
}

fn add_timer(
    ev_loop:  EventLoop&,
    timer_id: u64,
    delay_ms: u64,
    tag:      u64,
    periodic: bool = false,
    now_ns:   u64  = 0,
) -> bool {
    guard ev_loop.state != LoopState.Stopped else { return false; }
    return add_timer(ev_loop.poller, timer_id, delay_ms, tag, periodic, now_ns);
}

fn cancel_timer(ev_loop: EventLoop&, timer_id: u64) -> bool {
    guard ev_loop.state != LoopState.Stopped else { return false; }
    return cancel_timer(ev_loop.poller, timer_id);
}

fn poll_events(
    ev_loop:    EventLoop&,
    timeout_ms: i64,
    now_ns:     u64,
    out_events: core::PollReadyEvent[..64]&,
) -> i32 {
    guard ev_loop.state != LoopState.Stopped else {
        out_events.clear();
        return 0;
    }
    ev_loop.state = LoopState.Running;
    ev_loop.iteration_count = core::add_sat_u64(ev_loop.iteration_count, 1);
    let cnt = poll_events(ev_loop.poller, timeout_ms, now_ns, out_events);
    if cnt > 0 {
        ev_loop.events_dispatched_total = core::add_sat_u64(ev_loop.events_dispatched_total, cnt as u64);
    }
    return cnt;
}

// Defers execution of a task to the event loop thread (uWebSockets / uSockets loop->defer pattern)
fn defer_task(ev_loop: EventLoop&, tag: u64, user_data: u64, task_id: u32 = 0) -> bool {
    guard ev_loop.deferred_count < ev_loop.deferred_tasks.len else { return false; }
    let idx = ev_loop.deferred_count;
    ev_loop.deferred_tasks[idx].tag = tag;
    ev_loop.deferred_tasks[idx].user_data = user_data;
    ev_loop.deferred_tasks[idx].task_id = task_id;
    ev_loop.deferred_tasks[idx].in_use = true;
    ev_loop.deferred_count = core::add_sat_i64(idx, 1);
    return true;
}

fn has_deferred_tasks(ev_loop: const EventLoop&) -> bool {
    return ev_loop.deferred_count > 0;
}

// Drains all pending deferred tasks in single pass, dispatching to TaskFn callback
fn drain_deferred_tasks<TaskFn: fn(u64, u64, u32, EventLoop&)>(ev_loop: EventLoop&) -> u32 {
    let count = ev_loop.deferred_count;
    guard count > 0 else { return 0; }

    for i in count {
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
        let added = core::sub_sat_i64(total_now, count);
        for i in added {
            let src_idx = core::add_sat_i64(count, i);
            ev_loop.deferred_tasks[i] = ev_loop.deferred_tasks[src_idx];
            ev_loop.deferred_tasks[src_idx].in_use = false;
        }
        ev_loop.deferred_count = added;
    } else {
        ev_loop.deferred_count = 0;
    }
    return count as u32;
}
