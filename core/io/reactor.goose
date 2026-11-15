// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-shim generic UFCS async stream and reactor contract.
// Allows database drivers, connection pools, and protocol engines to run across
// any socket transport or event loop without heap closures or vtable shims.
namespace core;

import std;
import core.io.types;
import core.io.ring;
import core.io.pipe;

// Translates raw non-blocking send status codes into typed (bytes, IoError) pairs.
// Convention across transports:
//   rc > 0   -> bytes accepted (ShortWrite if fewer than requested_len)
//   rc == 0  -> peer or channel closed (Closed)
//   rc == -2 -> non-blocking backpressure (WouldBlock)
//   rc < 0   -> transport error or closed descriptor (Closed)
fn translate_send_result(rc: i32, requested_len: i64) -> i32, IoError {
    guard requested_len > 0 else { return 0, IoError.None; }
    if rc == -2 {
        return 0, IoError.WouldBlock;
    }
    if rc <= 0 {
        return 0, IoError.Closed;
    }
    if rc < requested_len {
        return rc, IoError.ShortWrite;
    }
    return rc, IoError.None;
}

// Translates raw non-blocking receive status codes into typed (bytes, IoError) pairs.
// Convention across transports:
//   rc > 0   -> bytes read into destination slice
//   rc == 0  -> clean end-of-stream (Eof)
//   rc == -2 -> no data currently available (WouldBlock)
//   rc < 0   -> transport error or closed descriptor (Closed)
fn translate_recv_result(rc: i32) -> i32, IoError {
    if rc > 0 {
        return rc, IoError.None;
    }
    if rc == 0 {
        return 0, IoError.Eof;
    }
    if rc == -2 {
        return 0, IoError.WouldBlock;
    }
    return 0, IoError.Closed;
}

// RingBuffer <Io> adapter with non-blocking backpressure (-2 WouldBlock).
fn send(rb: RingBuffer&, data: const u8[:]) -> i32 {
    guard data.len > 0 else { return 0; }
    guard available(rb) > 0 else { return -2; }
    let written, _ = write(rb, data);
    return (written & 0x7FFFFFFF) as i32;
}

fn recv_slice(rb: RingBuffer&, dst: u8[:], timeout_ms: u32 = 0) -> i32 {
    let _ = timeout_ms;
    guard dst.len > 0 else { return 0; }
    guard !is_empty(rb) else { return -2; }
    let n, _ = read(rb, dst);
    return (n & 0x7FFFFFFF) as i32;
}

fn close(rb: RingBuffer&) {
    clear(rb);
}

// PipeBuffer <Io> adapter with non-blocking backpressure (-2 WouldBlock) and EOF signaling.
fn send(p: PipeBuffer&, data: const u8[:]) -> i32 {
    guard !p.is_completed else { return -1; }
    guard data.len > 0 else { return 0; }
    let avail = total_available(p);
    guard avail > 0 else { return -2; }
    let chunk = min(data.len, avail);
    let written, _ = write(p, data[..chunk]);
    return (written & 0x7FFFFFFF) as i32;
}

fn recv_slice(p: PipeBuffer&, dst: u8[:], timeout_ms: u32 = 0) -> i32 {
    let _ = timeout_ms;
    guard dst.len > 0 else { return 0; }
    if readable_len(p) == 0 {
        if p.is_completed {
            return 0;
        }
        return -2;
    }
    let n, _ = read(p, dst);
    return (n & 0x7FFFFFFF) as i32;
}

fn close(p: PipeBuffer&) {
    complete_pipe(p);
}

// Generic compile-time stream contract: any type `Io` implementing `send`,
// `recv_slice`, and `close` in its own namespace satisfies these operations.
fn stream_send<Io>(io: Io&, data: const u8[:]) -> i32 {
    guard data.len > 0 else { return 0; }
    return io.send(data);
}

fn stream_recv<Io>(io: Io&, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    guard dst.len > 0 else { return 0; }
    return io.recv_slice(dst, timeout_ms);
}

fn stream_close<Io>(io: Io&) {
    io.close();
}

// Non-blocking stream send with explicit backpressure (`IoError.WouldBlock`)
// and partial-write (`IoError.ShortWrite`) classification.
fn stream_try_send<Io>(io: Io&, data: const u8[:]) -> i32, IoError {
    guard data.len > 0 else { return 0, IoError.None; }
    let rc = io.send(data);
    return translate_send_result(rc, data.len);
}

// Non-blocking stream receive (`timeout_ms = 0`) classifying `WouldBlock` vs `Eof`.
fn stream_try_recv<Io>(io: Io&, dst: u8[:]) -> i32, IoError {
    guard dst.len > 0 else { return 0, IoError.None; }
    let rc = io.recv_slice(dst, 0);
    return translate_recv_result(rc);
}

// Generic dialer contract: any type `D` implementing `dial_endpoint(target)`
// in its own namespace can establish outbound connections for driver pools.
fn reactor_dial<D>(dialer: D&, target: DialTarget) -> i64, IoError {
    guard target.host.len > 0 && target.port != 0 else {
        return -1, IoError.InvalidArgument;
    }
    let handle = dialer.dial_endpoint(target);
    if handle == -2 {
        return -1, IoError.WouldBlock;
    }
    if handle < 0 {
        return -1, IoError.Closed;
    }
    return handle, IoError.None;
}

// Generic reactor registration and readiness polling contract: any event loop
// or poller `R` implementing `register_socket`, `modify_socket`,
// `deregister_socket`, `add_timer`, `cancel_timer`, `wake_tag`, and
// `poll_events` in its namespace satisfies this zero-shim interface.
fn reactor_register<R>(
    r:        R&,
    fd:       i32,
    tag:      u64,
    interest: PollInterest,
    trigger:  PollTrigger = PollTrigger.Level,
) -> bool {
    guard fd >= 0 else { return false; }
    return r.register_socket(fd, tag, interest, trigger);
}

fn reactor_modify<R>(
    r:        R&,
    fd:       i32,
    tag:      u64,
    interest: PollInterest,
    trigger:  PollTrigger = PollTrigger.Level,
) -> bool {
    guard fd >= 0 else { return false; }
    return r.modify_socket(fd, tag, interest, trigger);
}

fn reactor_deregister<R>(r: R&, fd: i32) -> bool {
    guard fd >= 0 else { return false; }
    return r.deregister_socket(fd);
}

fn reactor_add_timer<R>(
    r:        R&,
    timer_id: u64,
    delay_ms: u64,
    tag:      u64,
    periodic: bool = false,
    now_ns:   u64  = 0,
) -> bool {
    guard timer_id != 0 else { return false; }
    return r.add_timer(timer_id, delay_ms, tag, periodic, now_ns);
}

fn reactor_cancel_timer<R>(r: R&, timer_id: u64) -> bool {
    guard timer_id != 0 else { return false; }
    return r.cancel_timer(timer_id);
}

fn reactor_wake<R>(r: R&, tag: u64) -> bool {
    return r.wake_tag(tag);
}

fn reactor_poll<R>(
    r:          R&,
    timeout_ms: i64,
    now_ns:     u64,
    out_events: PollReadyEvent[..64]&,
) -> i32 {
    out_events.clear();
    guard timeout_ms >= -1 else { return 0; }
    return r.poll_events(timeout_ms, now_ns, out_events);
}
