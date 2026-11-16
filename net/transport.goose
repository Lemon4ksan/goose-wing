// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-allocation polymorphic transport representation and case functions.
// Provides closed polymorphism over live L4 TCP sockets, Unix domain sockets,
// TLS record channels, and synthetic mock exchanges without vtable indirection.
namespace wing;

import std;
import core from "..";
import .tcp;

const VIRTUAL_FD_TAG:       i64 = 0x40000000;
const VIRTUAL_FD_B_END_BIT: i64 = 0x20000000;
const MAX_VIRTUAL_PIPES:    i64 = 32;

struct VirtualPipeSlot {
    a_to_b:   core::RingBuffer = core::RingBuffer { .. },
    b_to_a:   core::RingBuffer = core::RingBuffer { .. },
    closed_a: bool             = false,
    closed_b: bool             = false,
    in_use:   bool             = false,
}

var g_virtual_pipes: VirtualPipeSlot[32] = [VirtualPipeSlot { .. }; 32];

extern fn native_udp_bind(host: const u8[:], port: u16) -> i64 = "wing_udp_bind";
extern fn native_udp_sendto(sock_fd: i64, data: const u8[:], host: const u8[:], port: u16) -> i32 = "wing_udp_sendto";
extern fn native_udp_sendto_ip4(
    sock_fd:   i64,
    data:      const u8[:],
    peer_ip4:  u32,
    peer_port: u16,
) -> i32 = "wing_udp_sendto_ip4";
extern fn native_udp_recvfrom(
    sock_fd:    i64,
    buf:        u8[:],
    timeout_ms: u32,
    peer_ip4:   u32&,
    peer_port:  u16&,
) -> i32 = "wing_udp_recvfrom";

// Binds a UDP socket on `host:port` after initializing the platform socket subsystem.
// If `port` is 0, the OS allocates an ephemeral UDP port (retrieve with `tcp_getsockname_port`).
fn udp_bind(host: const u8[:], port: u16 = 0) -> i64 {
    tcp_init();
    return native_udp_bind(host, port);
}

// Receives a UDP datagram into `buf` with `timeout_ms` timeout, populating `peer_ip4` and `peer_port`.
fn udp_recvfrom(
    sock_fd:    i64,
    buf:        u8[:],
    timeout_ms: u32,
    peer_ip4:   u32&,
    peer_port:  u16&,
) -> i32 {
    guard sock_fd > 0 && buf.len > 0 else { return -1; }
    return native_udp_recvfrom(sock_fd, buf, timeout_ms, peer_ip4, peer_port);
}

// Closed polymorphism for L4 and security transports (24 bytes inline POD).
enum Transport {
    Disconnected,
    Tcp { fd: i64 },
    Unix { fd: i64 },
    Tls { fd: i64, record_seq_rx: u64, record_seq_tx: u64, cipher_slot: u16 },
    Udp { fd: i64, peer_ip4: u32, peer_port: u16 },
    Mock { route_idx: u16, cursor: u32 },
    Virtual { pipe_slot: u16, is_b_end: bool },
}

// ---- In-Memory Duplex Virtual Pipe Lifecycle & Descriptors -----------------

fn alloc_virtual_pipe_slot() -> u16, bool {
    for i in MAX_VIRTUAL_PIPES {
        let slot .= g_virtual_pipes[i];
        if !slot.in_use {
            core::clear(slot.a_to_b);
            core::clear(slot.b_to_a);
            slot.closed_a = false;
            slot.closed_b = false;
            slot.in_use = true;
            return i as u16, true;
        }
    }
    return 0xFFFF, false;
}

fn free_virtual_pipe_slot(pipe_slot: u16) {
    let idx = pipe_slot as i64;
    guard idx >= 0 && idx < MAX_VIRTUAL_PIPES else { return; }
    let slot .= g_virtual_pipes[idx];
    core::clear(slot.a_to_b);
    core::clear(slot.b_to_a);
    slot.closed_a = true;
    slot.closed_b = true;
    slot.in_use = false;
}

fn open_virtual_pipe_pair() -> Transport, Transport, bool {
    let slot_idx, ok = alloc_virtual_pipe_slot();
    guard ok else {
        return Transport.Disconnected, Transport.Disconnected, false;
    }
    let end_a = Transport.Virtual { pipe_slot: slot_idx, is_b_end: false };
    let end_b = Transport.Virtual { pipe_slot: slot_idx, is_b_end: true };
    return end_a, end_b, true;
}

fn with_virtual_pipe_pair<F>() -> bool {
    let slot_idx, ok = alloc_virtual_pipe_slot();
    guard ok else { return false; }
    defer free_virtual_pipe_slot(slot_idx);
    var end_a: Transport = Transport.Virtual { pipe_slot: slot_idx, is_b_end: false };
    var end_b: Transport = Transport.Virtual { pipe_slot: slot_idx, is_b_end: true };
    F(end_a, end_b);
    return true;
}

inline fn virtual_pipe_to_fd(pipe_slot: u16, is_b_end: bool) -> i64 {
    let slot_i64 = (pipe_slot as i64) & 0xFFFF;
    let end_bit = if is_b_end { VIRTUAL_FD_B_END_BIT } else { 0 };
    return VIRTUAL_FD_TAG | end_bit | slot_i64;
}

inline fn is_virtual_pipe_fd(fd: i64) -> bool {
    return fd > 0 && (fd & VIRTUAL_FD_TAG) != 0;
}

// Decodes a tagged virtual pipe descriptor into `(pipe_slot, is_b_end, ok)`.
//
// Example:
//   fd = 0x60000003
//   returns: 3, true, true
fn decode_virtual_pipe_fd(fd: i64) -> u16, bool, bool {
    guard is_virtual_pipe_fd(fd) else { return 0xFFFF, false, false; }
    let slot_i64 = fd & 0xFFFF;
    guard slot_i64 >= 0 && slot_i64 < MAX_VIRTUAL_PIPES else { return 0xFFFF, false, false; }
    let is_b_end = (fd & VIRTUAL_FD_B_END_BIT) != 0;
    return slot_i64 as u16, is_b_end, true;
}

fn virtual_pipe_send(pipe_slot: u16, is_b_end: bool, data: const u8[:]) -> i32 {
    let idx = pipe_slot as i64;
    guard idx >= 0 && idx < MAX_VIRTUAL_PIPES && data.len > 0 else { return 0; }
    let slot .= g_virtual_pipes[idx];
    guard slot.in_use && !slot.closed_a && !slot.closed_b else { return -1; }
    var rb .= slot.a_to_b;
    if is_b_end {
        rb .= slot.b_to_a;
    }
    guard core::available(rb) > 0 else { return -2; }
    let span1, _ = core::write_slices(rb);
    if span1.len > 0 && data.len <= span1.len {
        for i in data.len {
            span1[i] = data[i];
        }
        guard core::commit_written(rb, data.len) == core::IoError.None else { return -1; }
        return (data.len & 0x7FFFFFFF) as i32;
    }
    let written, _ = core::write(rb, data);
    guard written > 0 else { return -2; }
    return (written & 0x7FFFFFFF) as i32;
}

fn virtual_pipe_recv(pipe_slot: u16, is_b_end: bool, dst: u8[:]) -> i32 {
    let idx = pipe_slot as i64;
    guard idx >= 0 && idx < MAX_VIRTUAL_PIPES && dst.len > 0 else { return 0; }
    let slot .= g_virtual_pipes[idx];
    guard slot.in_use else { return -1; }
    var rb .= slot.b_to_a;
    if is_b_end {
        guard !slot.closed_b else { return 0; }
        rb .= slot.a_to_b;
    } else {
        guard !slot.closed_a else { return 0; }
    }
    let readable = core::contiguous_readable_slice(rb);
    if readable.len == 0 {
        let peer_closed = if is_b_end { slot.closed_a } else { slot.closed_b };
        if peer_closed {
            return 0;
        }
        return -2;
    }
    if dst.len <= readable.len {
        for i in dst.len {
            dst[i] = readable[i];
        }
        let consumed = core::discard(rb, dst.len);
        return (consumed & 0x7FFFFFFF) as i32;
    }
    let n_read, _ = core::read(rb, dst);
    return (n_read & 0x7FFFFFFF) as i32;
}

fn virtual_pipe_close(pipe_slot: u16, is_b_end: bool) {
    let idx = pipe_slot as i64;
    guard idx >= 0 && idx < MAX_VIRTUAL_PIPES else { return; }
    let slot .= g_virtual_pipes[idx];
    guard slot.in_use else { return; }
    if is_b_end {
        slot.closed_b = true;
    } else {
        slot.closed_a = true;
    }
    if slot.closed_a && slot.closed_b {
        free_virtual_pipe_slot(pipe_slot);
    }
}

fn virtual_fd_send(fd: i64, data: const u8[:]) -> i32 {
    let pipe_slot, is_b_end, ok = decode_virtual_pipe_fd(fd);
    guard ok else { return -1; }
    return virtual_pipe_send(pipe_slot, is_b_end, data);
}

fn virtual_fd_recv(fd: i64, dst: u8[:]) -> i32 {
    let pipe_slot, is_b_end, ok = decode_virtual_pipe_fd(fd);
    guard ok else { return -1; }
    return virtual_pipe_recv(pipe_slot, is_b_end, dst);
}

fn virtual_fd_close(fd: i64) {
    let pipe_slot, is_b_end, ok = decode_virtual_pipe_fd(fd);
    guard ok else { return; }
    virtual_pipe_close(pipe_slot, is_b_end);
}

// ---- Transport Status & Predicates -----------------------------------------

fn is_connected(t: Transport) -> bool {
    return match t {
        Disconnected => false,
        _ => true,
    };
}

// ---- Case Functions: send --------------------------------------------------

fn send(t: Transport.Disconnected, data: const u8[:]) -> i32 {
    return 0;
}

fn send(t: Transport.Tcp, data: const u8[:]) -> i32 {
    guard t.fd > 0 else { return 0; }
    return tcp_send(t.fd, data);
}

fn send(t: Transport.Unix, data: const u8[:]) -> i32 {
    guard t.fd > 0 else { return 0; }
    return tcp_send(t.fd, data);
}

fn send(t: Transport.Tls, data: const u8[:]) -> i32 {
    guard t.fd > 0 else { return 0; }
    return tls_transport_send(t.fd, t.cipher_slot, data);
}

fn send(t: Transport.Udp, data: const u8[:]) -> i32 {
    guard t.fd > 0 else { return 0; }
    return native_udp_sendto_ip4(t.fd, data, t.peer_ip4, t.peer_port);
}

fn send(t: Transport.Mock, data: const u8[:]) -> i32 {
    return data.len as i32;
}

fn send(t: Transport.Virtual, data: const u8[:]) -> i32 {
    return virtual_pipe_send(t.pipe_slot, t.is_b_end, data);
}

// Polymorphic dispatch via CPU branch prediction without vtable
fn send(t: Transport, data: const u8[:]) -> i32 {
    return match t {
        Disconnected => 0,
        Tcp tcp => tcp.send(data),
        Unix u => u.send(data),
        Tls tls => tls.send(data),
        Udp udp => udp.send(data),
        Mock m => m.send(data),
        Virtual v => v.send(data),
    };
}

// ---- Case Functions: recv_slice --------------------------------------------

fn recv_slice(t: Transport.Disconnected, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    return 0;
}

fn recv_slice(t: Transport.Tcp, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    guard dst.len > 0 else { return 0; }
    guard t.fd > 0 else { return -1; }
    if timeout_ms == 0 {
        return tcp_recv_nonblocking_slice(t.fd, dst);
    }
    return tcp_recv_slice(t.fd, dst, timeout_ms);
}

fn recv_slice(t: Transport.Unix, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    guard dst.len > 0 else { return 0; }
    guard t.fd > 0 else { return -1; }
    if timeout_ms == 0 {
        return tcp_recv_nonblocking_slice(t.fd, dst);
    }
    return tcp_recv_slice(t.fd, dst, timeout_ms);
}

fn recv_slice(t: Transport.Tls, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    guard dst.len > 0 else { return 0; }
    guard t.fd > 0 else { return -1; }
    return tls_transport_recv_slice(t.fd, t.cipher_slot, dst, timeout_ms);
}

fn recv_slice(t: Transport.Udp, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    guard dst.len > 0 else { return 0; }
    guard t.fd > 0 else { return -1; }
    var peer_ip4:  u32 = 0;
    var peer_port: u16 = 0;
    return udp_recvfrom(t.fd, dst, timeout_ms, peer_ip4, peer_port);
}

fn recv_slice(t: Transport.Mock, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    return 0;
}

fn recv_slice(t: Transport.Virtual, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    return virtual_pipe_recv(t.pipe_slot, t.is_b_end, dst);
}

// Polymorphic dispatch via CPU branch prediction without vtable
fn recv_slice(t: Transport, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    return match t {
        Disconnected => 0,
        Tcp tcp => tcp.recv_slice(dst, timeout_ms),
        Unix u => u.recv_slice(dst, timeout_ms),
        Tls tls => tls.recv_slice(dst, timeout_ms),
        Udp udp => udp.recv_slice(dst, timeout_ms),
        Mock m => m.recv_slice(dst, timeout_ms),
        Virtual v => v.recv_slice(dst, timeout_ms),
    };
}

// ---- Case Functions: close -------------------------------------------------

fn close(t: Transport.Disconnected) {
}

fn close(t: Transport.Tcp) {
    if t.fd > 0 {
        tcp_close(t.fd);
    }
}

fn close(t: Transport.Unix) {
    if t.fd > 0 {
        tcp_close(t.fd);
    }
}

fn close(t: Transport.Tls) {
    tls_transport_close(t.fd, t.cipher_slot);
}

fn close(t: Transport.Udp) {
    if t.fd > 0 {
        tcp_close(t.fd);
    }
}

fn close(t: Transport.Mock) {
}

fn close(t: Transport.Virtual) {
    virtual_pipe_close(t.pipe_slot, t.is_b_end);
}

// Polymorphic close and state reset
fn close(t: Transport&) {
    match t {
        Disconnected => {},
        Tcp tcp => tcp.close(),
        Unix u => u.close(),
        Tls tls => tls.close(),
        Udp udp => udp.close(),
        Mock m => m.close(),
        Virtual v => v.close(),
    };
    t = Transport.Disconnected;
}

// ---- Zero-Shim TCP Dialer (<D>) Adapter ------------------------------------

struct TcpDialer {
    default_timeout_ms: u32 = 5000,
}

fn dial_endpoint(d: const TcpDialer&, target: core::DialTarget) -> i64 {
    if target.unix_path.len > 0 {
        let ufd = tcp_connect_unix(target.unix_path);
        guard ufd > 0 else { return -1; }
        if target.non_blocking {
            let _ = tcp_set_nonblocking(ufd, true);
        }
        return ufd;
    }
    let timeout_ms: u32 = if target.timeout_ms > 0 { target.timeout_ms } else { d.default_timeout_ms };
    let fd = tcp_connect(target.host, target.port, timeout_ms);
    guard fd > 0 else { return -1; }
    if target.non_blocking {
        let _ = tcp_set_nonblocking(fd, true);
    }
    return fd;
}
