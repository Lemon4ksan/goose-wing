// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Minimal L4 TCP and in-memory zero-copy stream transport for the modular HTTP/1.1 pipeline.
// Binds directly to shim/tcp.c without importing net.pool, http2, dns, cookie, or tls.
namespace h1;

import std;
import core.math.arithmetic;
import core.io.types;
import core.io.ring;
import core.io.reactor;

extern fn native_h1_tcp_init() -> i32 = "wing_tcp_init";
extern fn native_h1_tcp_listen(host: const u8[:], port: u16, backlog: i32) -> i64 = "wing_tcp_listen";
extern fn native_h1_tcp_getsockname_port(sock_fd: i64) -> u16 = "wing_tcp_getsockname_port";
extern fn native_h1_tcp_accept(listener_fd: i64, timeout_ms: u32) -> i64 = "wing_tcp_accept";
extern fn native_h1_tcp_connect_ex(
    host:            const u8[:],
    port:            u16,
    timeout_ms:      u32,
    ip_family:       i32,
    local_bind_addr: const u8[:],
) -> i64 = "wing_tcp_connect_ex";
extern fn native_h1_tcp_send(sock_fd: i64, data: const u8[:]) -> i32 = "wing_tcp_send";
extern fn native_h1_tcp_send2(sock_fd: i64, hdr: const u8[:], body: const u8[:]) -> i32 = "wing_tcp_send2";
extern fn native_h1_tcp_recv(sock_fd: i64, buf: u8[:], timeout_ms: u32) -> i32 = "wing_tcp_recv";
extern fn native_h1_tcp_close(sock_fd: i64) = "wing_tcp_close";
extern fn native_h1_tcp_set_nodelay(sock_fd: i64, enable: i32) -> i32 = "wing_tcp_set_nodelay";

struct TcpListener {
    fd:   i64 = -1,
    port: u16 = 0,
}

struct TcpStream {
    fd: i64 = -1,
}

// Opens a TCP listener bound to `host:port` (port 0 selects an ephemeral OS port).
fn tcp_listen(host: const u8[:], port: u16 = 0, backlog: i32 = 128) -> TcpListener, bool {
    guard host.len > 0 && backlog > 0 else { return TcpListener { .. }, false; }
    guard native_h1_tcp_init() == 0 else { return TcpListener { .. }, false; }
    let fd = native_h1_tcp_listen(host, port, backlog);
    guard fd > 0 else { return TcpListener { .. }, false; }
    let bound_port = native_h1_tcp_getsockname_port(fd);
    return TcpListener { fd: fd, port: bound_port }, true;
}

// Accepts one incoming TCP connection within `timeout_ms` and enables TCP_NODELAY.
fn accept(lis: const TcpListener&, timeout_ms: u32 = 1000) -> TcpStream, bool {
    guard lis.fd > 0 else { return TcpStream { .. }, false; }
    let fd = native_h1_tcp_accept(lis.fd, timeout_ms);
    guard fd > 0 else { return TcpStream { .. }, false; }
    let _ = native_h1_tcp_set_nodelay(fd, 1);
    return TcpStream { fd: fd }, true;
}

// Idempotently closes `lis`.
fn close(lis: TcpListener&) {
    guard lis.fd > 0 else { return; }
    native_h1_tcp_close(lis.fd);
    lis.fd = -1;
    lis.port = 0;
}

// Connects to `host:port` within `timeout_ms` and enables TCP_NODELAY.
fn tcp_connect(host: const u8[:], port: u16, timeout_ms: u32 = 5000) -> TcpStream, bool {
    guard host.len > 0 && port > 0 else { return TcpStream { .. }, false; }
    guard native_h1_tcp_init() == 0 else { return TcpStream { .. }, false; }
    let fd = native_h1_tcp_connect_ex(host, port, timeout_ms, 0, "");
    guard fd > 0 else { return TcpStream { .. }, false; }
    let _ = native_h1_tcp_set_nodelay(fd, 1);
    return TcpStream { fd: fd }, true;
}

// Sends `data` over `s`. Satisfies `core::stream_send<Io>`.
fn send(s: TcpStream&, data: const u8[:]) -> i32 {
    guard s.fd > 0 && data.len > 0 else { return 0; }
    return native_h1_tcp_send(s.fd, data);
}

// Sends all bytes of `data` over any stream `<Io>` until completion or error.
fn send_all<Io>(io: Io&, data: const u8[:]) -> bool {
    var sent_total: i64 = 0;
    while sent_total < data.len {
        let n = io.send(data[sent_total..]);
        guard n > 0 else { return false; }
        sent_total = core::add_sat_i64(sent_total, n as i64);
    }
    return true;
}

// Vectored zero-copy send of `hdr` and `body` in a single syscall (`WSASend` / `writev`).
fn send2(s: TcpStream&, hdr: const u8[:], body: const u8[:]) -> i32 {
    guard s.fd > 0 else { return -1; }
    if body.len == 0 {
        return send(s, hdr);
    }
    if hdr.len == 0 {
        return send(s, body);
    }
    return native_h1_tcp_send2(s.fd, hdr, body);
}

// Receives wire bytes directly into caller slice `dst`. Satisfies `core::stream_recv<Io>`.
fn recv_slice(s: TcpStream&, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    guard s.fd > 0 && dst.len > 0 else { return -1; }
    return native_h1_tcp_recv(s.fd, dst, timeout_ms);
}

// Idempotently closes `s`. Satisfies `core::stream_close<Io>`.
fn close(s: TcpStream&) {
    guard s.fd > 0 else { return; }
    native_h1_tcp_close(s.fd);
    s.fd = -1;
}

// Receives directly from `<Io>` into `rb`'s writable span without an intermediate copy.
// Returns > 0 bytes received, 0 on EOF, -2 on timeout/would-block, or -1 on error/full ring.
fn recv_into_ring<Io>(io: Io&, rb: core::RingBuffer&, timeout_ms: u32 = 5000) -> i32 {
    let span1, _ = core::write_slices(rb);
    guard span1.len > 0 else { return -1; }
    let recvd = io.recv_slice(span1, timeout_ms);
    if recvd > 0 {
        let _ = core::commit_written(rb, recvd as i64);
    }
    return recvd;
}

// Stack-bounded in-memory stream (~8 KB) backed by two `core::RingBuffer`s.
// Satisfies `<Io>` (`send`, `recv_slice`, `close`) for deterministic zero-socket testing.
struct MemoryStream {
    rx:     core::RingBuffer = core::RingBuffer { .. },
    tx:     core::RingBuffer = core::RingBuffer { .. },
    closed: bool             = false,
}

// Enqueues inbound wire bytes into `ms.rx` for server or client reads.
fn feed_input(ms: MemoryStream&, data: const u8[:]) -> bool {
    let written, err = core::write(ms.rx, data);
    return err == core::IoError.None && written == data.len;
}

// Reads and removes outbound bytes written into `ms.tx` into `out`.
fn drain_output(ms: MemoryStream&, out: u8[:]) -> i64 {
    let n, _ = core::read(ms.tx, out);
    return n;
}

// Writes `data` into `ms.tx`. Satisfies `core::stream_send<Io>`.
fn send(ms: MemoryStream&, data: const u8[:]) -> i32 {
    guard !ms.closed else { return -1; }
    guard data.len > 0 else { return 0; }
    guard core::available(ms.tx) > 0 else { return -2; }
    let written, _ = core::write(ms.tx, data);
    return (written & 0x7FFFFFFF) as i32;
}

// Reads unread bytes from `ms.rx` into `dst`. Returns 0 on EOF when `ms.rx` is empty.
fn recv_slice(ms: MemoryStream&, dst: u8[:], timeout_ms: u32 = 0) -> i32 {
    let _ = timeout_ms;
    guard dst.len > 0 else { return -1; }
    if core::is_empty(ms.rx) {
        return 0;
    }
    let n, _ = core::read(ms.rx, dst);
    return (n & 0x7FFFFFFF) as i32;
}

// Marks `ms` closed. Satisfies `core::stream_close<Io>`.
fn close(ms: MemoryStream&) {
    ms.closed = true;
}
