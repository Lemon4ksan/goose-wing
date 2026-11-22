// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-allocation polymorphic transport representation and case functions.
// Provides closed polymorphism over live L4 TCP sockets, Unix domain sockets,
// TLS record channels, and synthetic mock exchanges without vtable indirection.
namespace net;

import std;
import core;
import .tcp;
import .internal;
import .tunnel_internal;

const VIRTUAL_FD_TAG:       i64 = 0x40000000;
const VIRTUAL_FD_B_END_BIT: i64 = 0x20000000;
const TUNNEL_FD_TAG:        i64 = 0x10000000;
const MAX_VIRTUAL_PIPES:    i64 = 32;
const MAX_TUNNEL_SLOTS:     i64 = 32;

enum TunnelOuterKind {
    None,
    PureTls,
    BackendTls,
    Virtual,
}

struct TunnelTransportSlot {
    kind:      TunnelOuterKind = TunnelOuterKind.None,
    raw_fd:    i64             = -1,
    tls_slot:  i64             = -1,
    pipe_slot: u16             = 0,
    is_b_end:  bool            = false,
    in_use:    bool            = false,
}

var g_tunnel_slots: TunnelTransportSlot[>..] = [];

struct VirtualPipeSlot {
    a_to_b:   core::RingBuffer = core::RingBuffer { .. },
    b_to_a:   core::RingBuffer = core::RingBuffer { .. },
    closed_a: bool             = false,
    closed_b: bool             = false,
    rst_a:    bool             = false,
    rst_b:    bool             = false,
    in_use:   bool             = false,
}

var g_virtual_pipes: VirtualPipeSlot[>..] = [];

// Binds a UDP socket on `host:port` after initializing the platform socket subsystem.
// If `port` is 0, the OS allocates an ephemeral UDP port (retrieve with `tcp_getsockname_port`).
fn udp_bind(host: const u8[:], port: u16 = 0) -> i64 {
    tcp_init();
    return net_internal::native_udp_bind(host, port);
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
    return net_internal::native_udp_recvfrom(sock_fd, buf, timeout_ms, peer_ip4, peer_port);
}

// Closed polymorphism for L4 and security transports (24 bytes inline POD).
enum Transport {
    Disconnected,
    Tcp { fd: i64 },
    Unix { fd: i64 },
    Tls { fd: i64, record_seq_rx: u64, record_seq_tx: u64, cipher_slot: u16 },
    TlsBackend { fd: i64, endpoint_slot: i64 },
    Udp { fd: i64, peer_ip4: u32, peer_port: u16 },
    Mock { route_idx: u16, cursor: u32 },
    Virtual { pipe_slot: u16, is_b_end: bool },
}

// ---- In-Memory Duplex Virtual Pipe Lifecycle & Descriptors -----------------

fn alloc_virtual_pipe_slot() -> u16, bool {
    for i in g_virtual_pipes.len {
        let slot .= g_virtual_pipes[i];
        if !slot.in_use {
            core::clear(slot.a_to_b);
            core::clear(slot.b_to_a);
            slot.closed_a = false;
            slot.closed_b = false;
            slot.rst_a = false;
            slot.rst_b = false;
            slot.in_use = true;
            return (i & 0xFFFF) as u16, true;
        }
    }
    guard g_virtual_pipes.len < MAX_VIRTUAL_PIPES else {
        return 0xFFFF, false;
    }
    let new_idx = g_virtual_pipes.len;
    g_virtual_pipes.push(VirtualPipeSlot { in_use: true, .. });
    return (new_idx & 0xFFFF) as u16, true;
}

fn free_virtual_pipe_slot(pipe_slot: u16) {
    let idx = pipe_slot as i64;
    guard idx >= 0 && idx < g_virtual_pipes.len else { return; }
    let slot .= g_virtual_pipes[idx];
    core::secure_zeroize_slice(slot.a_to_b.storage[..]);
    core::secure_zeroize_slice(slot.b_to_a.storage[..]);
    core::clear(slot.a_to_b);
    core::clear(slot.b_to_a);
    slot.closed_a = true;
    slot.closed_b = true;
    slot.rst_a = false;
    slot.rst_b = false;
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

// Decodes an allocated virtual pipe descriptor into `(pipe_slot, is_b_end, ok)`.
//
// Example:
//   fd = 0x60000000 (when g_virtual_pipes.len >= 1)
//   returns: 0, true, true
fn decode_virtual_pipe_fd(fd: i64) -> u16, bool, bool {
    guard is_virtual_pipe_fd(fd) else { return 0xFFFF, false, false; }
    let slot_i64 = fd & 0xFFFF;
    guard slot_i64 >= 0 && slot_i64 < g_virtual_pipes.len else { return 0xFFFF, false, false; }
    let is_b_end = (fd & VIRTUAL_FD_B_END_BIT) != 0;
    return (slot_i64 & 0xFFFF) as u16, is_b_end, true;
}

fn virtual_pipe_send(pipe_slot: u16, is_b_end: bool, data: const u8[:]) -> i32 {
    guard data.len > 0 else { return 0; }
    let idx = pipe_slot as i64;
    guard idx >= 0 && idx < g_virtual_pipes.len else { return -1; }
    let slot .= g_virtual_pipes[idx];
    guard slot.in_use && !slot.closed_a && !slot.closed_b && !slot.rst_a && !slot.rst_b else { return -1; }
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
    guard dst.len > 0 else { return 0; }
    let idx = pipe_slot as i64;
    guard idx >= 0 && idx < g_virtual_pipes.len else { return -1; }
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
        let peer_rst = if is_b_end { slot.rst_a } else { slot.rst_b };
        if peer_rst {
            return -1;
        }
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
    guard idx >= 0 && idx < g_virtual_pipes.len else { return; }
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

// Marks a virtual pipe endpoint as abruptly reset (simulates TCP RST for peer reads/writes).
fn virtual_pipe_inject_rst(pipe_slot: u16, is_b_end: bool) -> bool {
    let idx = pipe_slot as i64;
    guard idx >= 0 && idx < g_virtual_pipes.len else { return false; }
    let slot .= g_virtual_pipes[idx];
    guard slot.in_use else { return false; }
    if is_b_end {
        slot.rst_b = true;
    } else {
        slot.rst_a = true;
    }
    return true;
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

// ---- Layered TLS-in-TLS Tunnel Descriptors ---------------------------------

inline fn is_tunnel_fd(fd: i64) -> bool {
    return fd > 0 && (fd & TUNNEL_FD_TAG) != 0;
}

// Registers an outer transport (e.g. TLS to an HTTPS forward proxy) as a tagged descriptor.
// Rejects disconnected or already-tunneled outer transports to keep nesting strictly bounded.
fn alloc_tunnel_fd(outer: Transport) -> i64, bool {
    var rec = TunnelTransportSlot { in_use: true, .. };
    let can_wrap = match outer {
        Tls t => {
            rec.kind = TunnelOuterKind.PureTls;
            rec.raw_fd = t.fd;
            rec.tls_slot = t.cipher_slot;
            t.fd > 0 && !is_tunnel_fd(t.fd)
        },
        TlsBackend tb => {
            rec.kind = TunnelOuterKind.BackendTls;
            rec.raw_fd = tb.fd;
            rec.tls_slot = tb.endpoint_slot;
            tb.fd > 0 && tb.endpoint_slot >= 0 && !is_tunnel_fd(tb.fd)
        },
        Virtual v => {
            rec.kind = TunnelOuterKind.Virtual;
            rec.pipe_slot = v.pipe_slot;
            rec.is_b_end = v.is_b_end;
            true
        },
        _ => false,
    };
    guard can_wrap else { return -1, false; }
    for i in g_tunnel_slots.len {
        let slot .= g_tunnel_slots[i];
        if !slot.in_use {
            slot = rec;
            return net_internal::tunnel_slot_to_fd(i), true;
        }
    }
    guard g_tunnel_slots.len < MAX_TUNNEL_SLOTS else { return -1, false; }
    let idx = g_tunnel_slots.len;
    g_tunnel_slots.push(rec);
    return net_internal::tunnel_slot_to_fd(idx), true;
}

recursive fn tunnel_fd_send(fd: i64, data: const u8[:]) -> i32 {
    guard is_tunnel_fd(fd) else { return -1; }
    let idx = fd & 0xFFFF;
    guard idx >= 0 && idx < g_tunnel_slots.len && g_tunnel_slots[idx].in_use else { return -1; }
    let s = g_tunnel_slots[idx];
    return match s.kind {
        PureTls => tls::transport_send(s.raw_fd, (s.tls_slot & 0xFFFF) as u16, data),
        BackendTls => tls::endpoint_transport_send(s.raw_fd, s.tls_slot, data),
        Virtual => virtual_pipe_send(s.pipe_slot, s.is_b_end, data),
        None => -1,
    };
}

recursive fn tunnel_fd_recv(fd: i64, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    guard is_tunnel_fd(fd) else { return -1; }
    let idx = fd & 0xFFFF;
    guard idx >= 0 && idx < g_tunnel_slots.len && g_tunnel_slots[idx].in_use else { return -1; }
    let s = g_tunnel_slots[idx];
    return match s.kind {
        PureTls => tls::transport_recv_slice(s.raw_fd, (s.tls_slot & 0xFFFF) as u16, dst, timeout_ms),
        BackendTls => tls::endpoint_transport_recv_slice(s.raw_fd, s.tls_slot, dst, timeout_ms),
        Virtual => virtual_pipe_recv(s.pipe_slot, s.is_b_end, dst),
        None => -1,
    };
}

recursive fn tunnel_fd_close(fd: i64) {
    guard is_tunnel_fd(fd) else { return; }
    let idx = fd & 0xFFFF;
    guard idx >= 0 && idx < g_tunnel_slots.len && g_tunnel_slots[idx].in_use else { return; }
    let s = g_tunnel_slots[idx];
    g_tunnel_slots[idx] = TunnelTransportSlot { .. };
    match s.kind {
        PureTls => { tls::transport_close(s.raw_fd, (s.tls_slot & 0xFFFF) as u16); },
        BackendTls => { tls::endpoint_transport_close(s.raw_fd, s.tls_slot); },
        Virtual => { virtual_pipe_close(s.pipe_slot, s.is_b_end); },
        None => {},
    };
}

// Unified descriptor send/recv/close across OS TCP, virtual pipes, and TLS tunnel fds.
recursive fn fd_send(fd: i64, data: const u8[:]) -> i32 {
    if is_virtual_pipe_fd(fd) {
        return virtual_fd_send(fd, data);
    }
    if is_tunnel_fd(fd) {
        return tunnel_fd_send(fd, data);
    }
    return tcp_send(fd, data);
}

recursive fn fd_recv(fd: i64, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    if is_virtual_pipe_fd(fd) {
        return virtual_fd_recv(fd, dst);
    }
    if is_tunnel_fd(fd) {
        return tunnel_fd_recv(fd, dst, timeout_ms);
    }
    if timeout_ms == 0 {
        return tcp_recv_nonblocking_slice(fd, dst);
    }
    return tcp_recv_slice(fd, dst, timeout_ms);
}

recursive fn fd_close(fd: i64) {
    guard fd > 0 else { return; }
    if is_virtual_pipe_fd(fd) {
        virtual_fd_close(fd);
    } else if is_tunnel_fd(fd) {
        tunnel_fd_close(fd);
    } else {
        tcp_close(fd);
    }
}

// Executes an HTTP CONNECT tunnel handshake over any connected `Transport` (TCP, TLS, or Virtual).
//
// Example:
//   t = Transport.Tls { .. }, target_host = "api.telegram.org", target_port = 443
//   returns: ConnectTunnelError.None when proxy answers 200 Connection Established
fn http_connect_transport_handshake(
    t:           Transport,
    target_host: const u8[:],
    target_port: u16,
    proxy_auth:  const u8[:],
    user_agent:  const u8[:],
    timeout_ms:  u32 = 5000,
) -> ConnectTunnelError {
    guard is_connected(t) else { return ConnectTunnelError.ConnectFailed; }
    var req_buf: u8[..1024] = [];
    build_http_connect_request(target_host, target_port, proxy_auth, user_agent, req_buf);
    guard req_buf.len > 0 && t.send(req_buf[..]) == (req_buf.len as i32) else {
        return ConnectTunnelError.ConnectFailed;
    }
    var resp_buf: u8[..4096] = [];
    var chunk:    u8[1024]   = [0; 1024];
    for _ in 8 {
        let n = t.recv_slice(chunk[..], timeout_ms);
        guard n > 0 else { break; }
        guard resp_buf.try_append(chunk[..n]) else { return ConnectTunnelError.TunnelBufferedTooManyBytes; }
        if net_internal::has_final_connect_header_terminator(resp_buf[..]) {
            break;
        }
    }
    return verify_connect_tunnel_response(resp_buf[..], 0);
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
    return fd_send(t.fd, data);
}

fn send(t: Transport.Unix, data: const u8[:]) -> i32 {
    guard t.fd > 0 else { return 0; }
    return tcp_send(t.fd, data);
}

fn send(t: Transport.Tls, data: const u8[:]) -> i32 {
    guard t.fd > 0 else { return 0; }
    return tls::transport_send(t.fd, t.cipher_slot, data);
}

fn send(t: Transport.TlsBackend, data: const u8[:]) -> i32 {
    guard t.fd > 0 && t.endpoint_slot >= 0 else { return 0; }
    return tls::endpoint_transport_send(t.fd, t.endpoint_slot, data);
}

fn send(t: Transport.Udp, data: const u8[:]) -> i32 {
    guard t.fd > 0 else { return 0; }
    return net_internal::native_udp_sendto_ip4(t.fd, data, t.peer_ip4, t.peer_port);
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
        TlsBackend tb => tb.send(data),
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
    return fd_recv(t.fd, dst, timeout_ms);
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
    return tls::transport_recv_slice(t.fd, t.cipher_slot, dst, timeout_ms);
}

fn recv_slice(t: Transport.TlsBackend, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    guard dst.len > 0 else { return 0; }
    guard t.fd > 0 && t.endpoint_slot >= 0 else { return -1; }
    return tls::endpoint_transport_recv_slice(t.fd, t.endpoint_slot, dst, timeout_ms);
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
        TlsBackend tb => tb.recv_slice(dst, timeout_ms),
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
        fd_close(t.fd);
    }
}

fn close(t: Transport.Unix) {
    if t.fd > 0 {
        tcp_close(t.fd);
    }
}

fn close(t: Transport.Tls) {
    tls::transport_close(t.fd, t.cipher_slot);
}

fn close(t: Transport.TlsBackend) {
    tls::endpoint_transport_close(t.fd, t.endpoint_slot);
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
        TlsBackend tb => tb.close(),
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
