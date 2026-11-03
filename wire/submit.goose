// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Vulkan-style transport queue batch submission and wire poll execution.
namespace wire;

import std;
import core from "..";
import .result;
import .types;
import .cmd;
import .sync;

// Physical transport queue wrapping L4 socket descriptor and batch tracking.
struct WireQueue {
    fd:             i64              = -1,
    driver:         WireDriverKind   = WireDriverKind.Standard,
    config:         WireDeviceConfig = WireDeviceConfig { .. },
    bytes_sent:     u64              = 0,
    bytes_received: u64              = 0,
    is_connected:   bool             = false,
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
    let sock = wing::native_tcp_connect(host, port, timeout_ms);
    guard sock >= 0 else { return false; }

    q.fd = sock;
    q.is_connected = true;

    if q.config.tcp_nodelay {
        wing::native_tcp_set_nodelay(q.fd, 1);
    }
    return true;
}

// Full-drain TCP transmission loop ensuring complete delivery of frame octets.
fn drain_send_slice(fd: i64, data: const u8[:]) -> i64, bool {
    var total_sent: i64 = 0;
    while total_sent < data.len {
        let chunk = data[total_sent..];
        let n = wing::native_tcp_send(fd, chunk);
        guard n > 0 else {
            return total_sent, false;
        }
        total_sent += n;
    }
    return total_sent, true;
}

// Dispatches wire bytes to the appropriate transport driver.
fn dispatch_queue_send(q: WireQueue&, data: const u8[:]) -> i64, bool {
    if q.driver == WireDriverKind.Mock {
        return data.len, true;
    }
    return drain_send_slice(q.fd, data);
}

// Submits a recorded command buffer to the physical transport queue (RFC 9113).
fn submit(q: WireQueue&, cmd: const WireCommandBuffer&) -> i64, bool {
    guard q.is_connected else { return 0, false; }
    guard !cmd.has_error && cmd.hpack_staging.len == 0 else { return 0, false; }
    let data = cmd.buf[..];
    guard data.len > 0 else { return 0, true; }

    let sent, ok = dispatch_queue_send(q, data);
    guard ok else { return 0, false; }

    q.bytes_sent = q.bytes_sent + (sent as u64);
    return sent, true;
}

// Submits a raw byte slice directly to the queue without command buffer recording.
fn submit_slice(q: WireQueue&, data: const u8[:]) -> i64, bool {
    guard q.is_connected else { return 0, false; }
    guard data.len > 0 else { return 0, true; }

    let sent, ok = dispatch_queue_send(q, data);
    guard ok else { return 0, false; }

    q.bytes_sent = q.bytes_sent + (sent as u64);
    return sent, true;
}

inline fn submit_single_batch_cmd(q: WireQueue&, cmd: const WireCommandBuffer&) -> i64, bool {
    guard !cmd.has_error && cmd.hpack_staging.len == 0 else { return 0, false; }
    let data = cmd.buf[..];
    guard data.len > 0 else { return 0, true; }
    return dispatch_queue_send(q, data);
}

inline fn signal_submit_fence(fence: WireFence&) {
    guard fence.is_valid else { return; }
    fence.status = WireFenceStatus.Signaled;
    fence.signaled_val = 1;
}

// Submits a batch of command buffers atomically to the queue (VkQueueSubmit2).
fn queue_submit_batch(
    q:        WireQueue&,
    cmd_bufs: const WireCommandBuffer[:],
    info:     const WireSubmitInfo&,
    fence:    WireFence&,
) -> i64, WireResult {
    guard q.is_connected else {
        return 0, WireResult.ErrorInitializationFailed;
    }
    var total_batch_bytes: i64 = 0;
    for i in 0..cmd_bufs.len {
        let sent, ok = submit_single_batch_cmd(q, cmd_bufs[i]);
        guard ok else {
            return total_batch_bytes, WireResult.ErrorCommandBufferLocked;
        }
        total_batch_bytes += sent;
        q.bytes_sent = q.bytes_sent + (sent as u64);
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

    q.bytes_received = q.bytes_received + (recvd as u64);
    return recvd, true;
}

inline fn native_close_socket(fd: i64) {
    if fd >= 0 {
        wing::native_tcp_close(fd);
    }
}

// Shuts down transport descriptor and resets queue state (RFC 9113).
fn close_wire_queue(q: WireQueue&) {
    native_close_socket(q.fd);
    q.fd = -1;
    q.is_connected = false;
}
