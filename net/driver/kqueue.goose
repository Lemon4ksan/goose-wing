// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// macOS / Darwin kqueue event multiplexing driver.
namespace internal;

import std;

// Native macOS kqueue C shims (sys/event.h)
extern fn native_kqueue_probe() -> i32 = "wing_kqueue_probe";
extern fn native_kqueue_create() -> i64 = "wing_kqueue_create";
extern fn native_kqueue_kevent(kq: i64, changelist: u64, nchanges: i32, eventlist: u64, nevents: i32, timeout_ns: i64) -> i32 = "wing_kqueue_kevent";
extern fn native_kqueue_close(kq: i64) = "wing_kqueue_close";

// kqueue filter constants
const EVFILT_READ: i16 = -1;
const EVFILT_WRITE: i16 = -2;
const EVFILT_TIMER: i16 = -7;

// kqueue action and event flags
const EV_ADD: u16 = 0x0001;
const EV_DELETE: u16 = 0x0002;
const EV_ENABLE: u16 = 0x0004;
const EV_DISABLE: u16 = 0x0008;
const EV_ONESHOT: u16 = 0x0010;
const EV_CLEAR: u16 = 0x0020;    // Edge-triggered notification
const EV_EOF: u16 = 0x8000;      // Connection disconnected / EOF

struct Kevent {
    ident: u64 = 0,
    filter: i16 = 0,
    flags: u16 = 0,
    fflags: u32 = 0,
    data: i64 = 0,
    udata: u64 = 0,
}

// Prepares a kqueue event for socket read notification
fn kevent_prep_read(ev: Kevent&, fd: i32, tag: u64, edge_triggered: bool) {
    ev.ident = fd as u64;
    ev.filter = EVFILT_READ;
    ev.flags = EV_ADD | EV_ENABLE | (if edge_triggered { EV_CLEAR } else { 0 });
    ev.fflags = 0;
    ev.data = 0;
    ev.udata = tag;
}

// Prepares a kqueue event for socket write notification
fn kevent_prep_write(ev: Kevent&, fd: i32, tag: u64, edge_triggered: bool) {
    ev.ident = fd as u64;
    ev.filter = EVFILT_WRITE;
    ev.flags = EV_ADD | EV_ENABLE | (if edge_triggered { EV_CLEAR } else { 0 });
    ev.fflags = 0;
    ev.data = 0;
    ev.udata = tag;
}

// Prepares a high-resolution timer event without extra file descriptors
fn kevent_prep_timer(ev: Kevent&, timer_id: u64, ms: i64, tag: u64) {
    ev.ident = timer_id;
    ev.filter = EVFILT_TIMER;
    ev.flags = EV_ADD | EV_ENABLE | EV_ONESHOT;
    ev.fflags = 0;
    ev.data = ms;
    ev.udata = tag;
}

// Returns the exact number of bytes waiting in the kernel socket receive buffer
fn kevent_bytes_available(ev: const Kevent&) -> i64 {
    return if ev.filter == EVFILT_READ && ev.data > 0 { ev.data } else { 0 };
}

// Checks if the peer closed or half-closed the connection
fn kevent_is_eof(ev: const Kevent&) -> bool {
    return (ev.flags & EV_EOF) != 0;
}
