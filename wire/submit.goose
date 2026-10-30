// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Vulkan-style transport queue batch submission and wire poll execution.
namespace wire;

import std;
import core from "..";
import .types;
import .cmd;

// Physical transport queue wrapping L4 socket descriptor and batch tracking.
struct WireQueue {
    fd:             i64              = -1,
    driver:         WireDriverKind   = WireDriverKind.Standard,
    config:         WireDeviceConfig = WireDeviceConfig { .. },
    bytes_sent:     u64              = 0,
    bytes_received: u64              = 0,
    is_connected:   bool             = false,
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
fn connect_wire_queue(q: WireQueue&, host: const u8[:], port: u16, timeout_ms: u32 = 5000) -> bool {
    let sock = wing::native_tcp_connect(host, port, timeout_ms);
    guard sock >= 0 else { return false; }

    q.fd = sock;
    q.is_connected = true;

    if q.config.tcp_nodelay {
        wing::native_tcp_set_nodelay(q.fd, 1);
    }
    return true;
}

inline fn accumulate_transferred_bytes(current: u64, delta: i32) -> u64 {
    return current + (delta as u64);
}

// Submits a recorded command buffer to the physical transport queue (RFC 9113).
fn submit(q: WireQueue&, cmd: const WireCommandBuffer&) -> i64, bool {
    guard q.is_connected else { return 0, false; }
    guard !cmd.has_error else { return 0, false; }
    let data = cmd.buf[..];
    guard data.len > 0 else { return 0, true; }

    let sent = wing::native_tcp_send(q.fd, data);
    guard sent >= 0 else { return 0, false; }

    q.bytes_sent = accumulate_transferred_bytes(q.bytes_sent, sent);
    return sent, true;
}

// Submits a raw byte slice directly to the queue without command buffer recording.
fn submit_slice(q: WireQueue&, data: const u8[:]) -> i64, bool {
    guard q.is_connected else { return 0, false; }
    guard data.len > 0 else { return 0, true; }

    let sent = wing::native_tcp_send(q.fd, data);
    guard sent >= 0 else { return 0, false; }

    q.bytes_sent = accumulate_transferred_bytes(q.bytes_sent, sent);
    return sent, true;
}

// Polls transport queue for incoming wire octets into caller-owned buffer.
fn poll_recv(q: WireQueue&, out: u8[:], timeout_ms: u32 = 0) -> i64, bool {
    guard q.is_connected else { return 0, false; }
    guard out.len > 0 else { return 0, true; }

    let recvd = wing::native_tcp_recv(q.fd, out, timeout_ms);
    guard recvd >= 0 else { return 0, false; }

    q.bytes_received = accumulate_transferred_bytes(q.bytes_received, recvd);
    return recvd, true;
}

inline fn native_close_socket(fd: i64) {
    if fd > 0 {
        wing::native_tcp_close(fd);
    }
}

// Shuts down transport descriptor and resets queue state.
fn close_wire_queue(q: WireQueue&) {
    native_close_socket(q.fd);
    q.fd = 0;
    q.is_connected = false;
}
