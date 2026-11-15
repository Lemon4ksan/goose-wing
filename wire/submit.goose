// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Vulkan-style transport queue batch submission and wire poll execution.
namespace wire;

import std;
import core from "..";
import net.driver;
import net.poller;
import net.tcp;
import net.transport;
import .result;
import .types;
import .cmd;
import .sync;

// Physical transport queue wrapping L4 socket descriptor and batch tracking.
struct WireQueue {
    fd:              i64              = -1,
    driver:          WireDriverKind   = WireDriverKind.Standard,
    config:          WireDeviceConfig = WireDeviceConfig { .. },
    bytes_sent:      u64              = 0,
    bytes_received:  u64              = 0,
    poller_tag:      u64              = 0,
    poller_attached: bool             = false,
    is_connected:    bool             = false,
}

fn queue_attach_poller(q: WireQueue&, poller_tag: u64) {
    q.poller_tag = poller_tag;
    q.poller_attached = true;
}

// Obtains a physical transport queue from the logical device (VkGetDeviceQueue).
fn get_device_queue(
    device:             const WireDevice&,
    queue_family_index: u32,
    queue_index:        u32,
) -> WireQueue {
    return WireQueue {
        fd:             -1,
        driver:         device.physical_device.properties.driver_kind,
        config:         device.config,
        bytes_sent:     0,
        bytes_received: 0,
        is_connected:   false,
    };
}

// Instantiates a new wire queue configured with target device parameters.
fn new_wire_queue(cfg: const WireDeviceConfig&) -> WireQueue {
    return WireQueue {
        fd:             -1,
        driver:         cfg.driver,
        config:         cfg,
        bytes_sent:     0,
        bytes_received: 0,
        is_connected:   false,
    };
}

// Establishes physical transport connection and applies low-level socket options.
fn connect_wire_queue(
    q:          WireQueue&,
    host:       const u8[:],
    port:       u16,
    timeout_ms: u32 = 5000,
) -> bool {
    if q.fd >= 0 {
        close_wire_queue(q);
    }
    let sock = wing::native_tcp_connect(host, port, timeout_ms);
    guard sock >= 0 else { return false; }

    q.fd = sock;
    q.is_connected = true;

    if q.config.tcp_nodelay {
        wing::native_tcp_set_nodelay(q.fd, 1);
    }
    return true;
}

fn wait_wire_socket_writable(fd: i64, poller_tag: u64, timeout_ms: i64) -> bool {
    guard fd > 0 else { return false; }
    var cfg = internal::TransportDriverConfig { .. };
    let _ = internal::init_transport_driver(cfg);
    var p = wing::new_poller(cfg);
    defer wing::close_poller(p);
    let tag = if poller_tag != 0 { poller_tag } else { 1 };
    guard wing::register_socket(p, fd as i32, tag, core::PollInterest.Write) else { return false; }
    var evs: core::PollReadyEvent[..64] = [];
    let n = wing::poll_events(p, timeout_ms, 0, evs);
    return n > 0;
}

// Full-drain TCP transmission loop ensuring complete delivery of frame octets.
fn drain_send_slice(fd: i64, data: const u8[:], poller_tag: u64 = 1) -> i64, bool {
    var total_sent: i64 = 0;
    var waits:      i64 = 0;
    while total_sent < data.len {
        let n = wing::native_tcp_send(fd, data[total_sent..]);
        if n == -2 {
            guard waits < 8 && wait_wire_socket_writable(fd, poller_tag, 1000) else {
                return total_sent, false;
            }
            waits = core::add_sat_i64(waits, 1);
            continue;
        }
        guard n > 0 else { return total_sent, false; }
        let rem_len = core::sub_sat_i64(data.len, total_sent);
        let n_i64 = min(n as i64, rem_len);
        total_sent = core::add_sat_i64(total_sent, n_i64);
        waits = 0;
    }
    return total_sent, true;
}

// Dispatches wire bytes to the appropriate transport driver.
fn dispatch_queue_send(q: WireQueue&, data: const u8[:]) -> i64, bool {
    if q.driver == WireDriverKind.Mock {
        return data.len, true;
    }
    let tag = if q.poller_attached { q.poller_tag } else { 1 };
    let sent, ok = drain_send_slice(q.fd, data, tag);
    if !ok {
        q.bytes_sent = core::add_sat_u64(q.bytes_sent, sent as u64);
        close_wire_queue(q);
    }
    return sent, ok;
}

inline fn is_submittable_cmd(cmd: const WireCommandBuffer&) -> bool {
    return !cmd.has_error &&
        (cmd.state == WireCommandBufferState.Executable || cmd.state == WireCommandBufferState.Recording);
}

// Submits a recorded command buffer to the physical transport queue (RFC 9113).
fn submit(q: WireQueue&, cmd: const WireCommandBuffer&) -> i64, bool {
    guard q.is_connected && is_submittable_cmd(cmd) else { return 0, false; }
    let data = cmd.buf[..];
    guard data.len > 0 else { return 0, true; }

    let sent, ok = dispatch_queue_send(q, data);
    guard ok else { return 0, false; }

    q.bytes_sent = core::add_sat_u64(q.bytes_sent, sent as u64);
    return sent, true;
}

// Submits a recorded command buffer over a polymorphic `wing::Transport` (TCP, Unix, TLS, UDP, or Mock).
fn submit_to_transport(q: WireQueue&, cmd: const WireCommandBuffer&, transport: wing::Transport&) -> WireResult {
    guard wing::is_connected(transport) else {
        return WireResult.ErrorInitializationFailed;
    }
    guard is_submittable_cmd(cmd) else {
        return WireResult.ErrorCommandBufferLocked;
    }
    let data = cmd.buf[..];
    guard data.len > 0 else { return WireResult.Success; }

    let n = transport.send(data) as i64;
    guard n == data.len else {
        return WireResult.ErrorDeviceLost;
    }

    q.bytes_sent = core::add_sat_u64(q.bytes_sent, n as u64);
    return WireResult.Success;
}

// Overload accepting argument order (q, transport, cmd) returning (bytes_sent, ok).
fn submit_to_transport(q: WireQueue&, t: wing::Transport&, cmd: const WireCommandBuffer&) -> i64, bool {
    let res = submit_to_transport(q, cmd, t);
    guard res == WireResult.Success else { return 0, false; }
    return cmd.buf.len, true;
}

// Appends a recorded command buffer's wire frames directly into a `core::CorkBuffer` for zero-copy coalescing.
fn submit_to_cork(cmd: const WireCommandBuffer&, cork: core::CorkBuffer&) -> bool {
    guard is_submittable_cmd(cmd) else { return false; }
    let data = cmd.buf[..];
    guard data.len > 0 else { return true; }
    return cork.cork_write_exact(data) == core::IoError.None;
}

// Batches outgoing server frames through `wing::ServerCork` and flushes over `transport` if needed.
fn submit_to_cork(
    q:         WireQueue&,
    cmd:       const WireCommandBuffer&,
    cork:      wing::ServerCork&,
    transport: wing::Transport&,
) -> WireResult {
    guard wing::is_connected(transport) && is_submittable_cmd(cmd) else {
        return WireResult.ErrorCommandBufferLocked;
    }
    let data = cmd.buf[..];
    guard data.len > 0 else { return WireResult.Success; }

    if cork.sock_fd > 0 {
        let n_cork = wing::server_cork_write(cork, data);
        guard n_cork >= 0 else { return WireResult.ErrorDeviceLost; }
        q.bytes_sent = core::add_sat_u64(q.bytes_sent, n_cork as u64);
        return WireResult.Success;
    }

    let avail = cork.buffer.cork_available();
    if data.len <= avail {
        let written, _ = cork.buffer.cork_write(data);
        q.bytes_sent = core::add_sat_u64(q.bytes_sent, written as u64);
        return WireResult.Success;
    }

    let pending = cork.buffer.cork_as_slice();
    if pending.len > 0 {
        let n_flush = transport.send(pending) as i64;
        if n_flush > 0 && n_flush < pending.len {
            cork.buffer.cork_consume(n_flush);
        }
        guard n_flush == pending.len else { return WireResult.ErrorDeviceLost; }
    }
    cork.buffer.cork_reset();

    if data.len >= core::CORK_BUFFER_CAP {
        let n_direct = transport.send(data) as i64;
        guard n_direct == data.len else { return WireResult.ErrorDeviceLost; }
        q.bytes_sent = core::add_sat_u64(q.bytes_sent, n_direct as u64);
        return WireResult.Success;
    }

    let written, _ = cork.buffer.cork_write(data);
    q.bytes_sent = core::add_sat_u64(q.bytes_sent, written as u64);
    return WireResult.Success;
}

// Submits a raw byte slice directly to the queue without command buffer recording.
fn submit_slice(q: WireQueue&, data: const u8[:]) -> i64, bool {
    guard q.is_connected else { return 0, false; }
    guard data.len > 0 else { return 0, true; }

    let sent, ok = dispatch_queue_send(q, data);
    guard ok else { return 0, false; }

    q.bytes_sent = core::add_sat_u64(q.bytes_sent, sent as u64);
    return sent, true;
}

inline fn submit_single_batch_cmd(q: WireQueue&, cmd: const WireCommandBuffer&) -> i64, bool {
    guard is_submittable_cmd(cmd) else { return 0, false; }
    let data = cmd.buf[..];
    guard data.len > 0 else { return 0, true; }
    return dispatch_queue_send(q, data);
}

inline fn signal_submit_fence(fence: WireFence&) {
    guard fence.is_valid else { return; }
    fence.status = WireFenceStatus.Signaled;
    fence.signaled_val = 1;
}

inline fn submit_cmd_pair_vectored(
    q:  WireQueue&,
    c0: const WireCommandBuffer&,
    c1: const WireCommandBuffer&,
) -> i64, bool {
    let b0 = c0.buf[..];
    let b1 = c1.buf[..];
    if q.driver == WireDriverKind.Mock {
        return core::add_sat_i64(b0.len, b1.len), true;
    }
    if b0.len == 0 { return dispatch_queue_send(q, b1); }
    if b1.len == 0 { return dispatch_queue_send(q, b0); }

    let total_want = core::add_sat_i64(b0.len, b1.len);
    let n2 = wing::tcp_send2(q.fd, b0, b1);
    if n2 >= 0 && n2 == total_want {
        return total_want, true;
    }
    if n2 > 0 {
        let written = n2 as i64;
        if written < b0.len {
            let s0, ok0 = dispatch_queue_send(q, b0[written..]);
            guard ok0 else { return core::add_sat_i64(written, s0), false; }
            let s1, ok1 = dispatch_queue_send(q, b1);
            return core::add_sat_i64(b0.len, s1), ok1;
        }
        let b1_off = core::sub_sat_i64(written, b0.len);
        let s1, ok1 = dispatch_queue_send(q, b1[b1_off..]);
        return core::add_sat_i64(written, s1), ok1;
    }
    let s0, ok0 = dispatch_queue_send(q, b0);
    guard ok0 else { return s0, false; }
    let s1, ok1 = dispatch_queue_send(q, b1);
    return core::add_sat_i64(s0, s1), ok1;
}

// Submits a batch of command buffers atomically to the queue (VkQueueSubmit2).
fn queue_submit_batch(
    q:        WireQueue&,
    cmd_bufs: const WireCommandBuffer[:],
    info:     const WireSubmitInfo&,
    fence:    WireFence&,
) -> i64, WireResult {
    guard q.is_connected && (!fence.is_valid || fence.status == WireFenceStatus.Unsignaled) else {
        return 0, WireResult.ErrorInitializationFailed;
    }
    for i in 0..cmd_bufs.len {
        guard is_submittable_cmd(cmd_bufs[i]) else {
            return 0, WireResult.ErrorCommandBufferLocked;
        }
    }
    var total_batch_bytes: i64 = 0;
    var rem_cmds = cmd_bufs;
    while rem_cmds.len >= 2 {
        let sent, ok = submit_cmd_pair_vectored(q, rem_cmds[0], rem_cmds[1]);
        guard ok else {
            total_batch_bytes = core::add_sat_i64(total_batch_bytes, sent);
            return total_batch_bytes, WireResult.ErrorDeviceLost;
        }
        total_batch_bytes = core::add_sat_i64(total_batch_bytes, sent);
        q.bytes_sent = core::add_sat_u64(q.bytes_sent, sent as u64);
        rem_cmds = rem_cmds[2..];
    }
    if rem_cmds.len == 1 {
        let sent, ok = submit_single_batch_cmd(q, rem_cmds[0]);
        guard ok else {
            total_batch_bytes = core::add_sat_i64(total_batch_bytes, sent);
            return total_batch_bytes, WireResult.ErrorDeviceLost;
        }
        total_batch_bytes = core::add_sat_i64(total_batch_bytes, sent);
        q.bytes_sent = core::add_sat_u64(q.bytes_sent, sent as u64);
    }
    signal_submit_fence(fence);
    return total_batch_bytes, WireResult.Success;
}

// Polls transport queue for incoming wire octets into caller-owned buffer.
fn poll_recv(q: WireQueue&, out: u8[:], timeout_ms: u32 = 0) -> i64, bool {
    guard q.is_connected else { return 0, false; }
    guard out.len > 0 else { return 0, true; }

    let recvd = wing::native_tcp_recv(q.fd, out, timeout_ms);
    guard recvd >= 0 else { return 0, false; }

    q.bytes_received = core::add_sat_u64(q.bytes_received, recvd as u64);
    return recvd, true;
}

// Shuts down transport descriptor and resets queue state (RFC 9113).
fn close_wire_queue(q: WireQueue&) {
    if q.fd >= 0 {
        wing::native_tcp_close(q.fd);
    }
    q.fd = -1;
    q.is_connected = false;
}
