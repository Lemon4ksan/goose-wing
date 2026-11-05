// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-allocation polymorphic transport representation and case functions.
// Provides closed polymorphism over live L4 TCP sockets, Unix domain sockets,
// TLS record channels, and synthetic mock exchanges without vtable indirection.
namespace wing;

import std;
import core from "..";
import .tcp;

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

// Closed polymorphism for L4 and security transports (24 bytes inline POD).
enum Transport {
    Disconnected,
    Tcp { fd: i64 },
    Unix { fd: i64 },
    Tls { fd: i64, record_seq_rx: u64, record_seq_tx: u64, cipher_slot: u16 },
    Udp { fd: i64, peer_ip4: u32, peer_port: u16 },
    Mock { route_idx: u16, cursor: u32 },
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

// Polymorphic dispatch via CPU branch prediction without vtable
fn send(t: Transport, data: const u8[:]) -> i32 {
    return match t {
        Disconnected => 0,
        Tcp tcp => tcp.send(data),
        Unix u => u.send(data),
        Tls tls => tls.send(data),
        Udp udp => udp.send(data),
        Mock m => m.send(data),
    };
}

// ---- Case Functions: recv_slice --------------------------------------------

fn recv_slice(t: Transport.Disconnected, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    return 0;
}

fn recv_slice(t: Transport.Tcp, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    guard t.fd > 0 else { return 0; }
    return tcp_recv_slice(t.fd, dst, timeout_ms);
}

fn recv_slice(t: Transport.Unix, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    guard t.fd > 0 else { return 0; }
    return tcp_recv_slice(t.fd, dst, timeout_ms);
}

fn recv_slice(t: Transport.Tls, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    guard t.fd > 0 else { return 0; }
    return tls_transport_recv_slice(t.fd, t.cipher_slot, dst, timeout_ms);
}

fn recv_slice(t: Transport.Udp, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    guard t.fd > 0 else { return 0; }
    var peer_ip4:  u32 = 0;
    var peer_port: u16 = 0;
    return native_udp_recvfrom(t.fd, dst, timeout_ms, peer_ip4, peer_port);
}

fn recv_slice(t: Transport.Mock, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    return 0;
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

// Polymorphic close and state reset
fn close(t: Transport&) {
    match t {
        Disconnected => {},
        Tcp tcp => tcp.close(),
        Unix u => u.close(),
        Tls tls => tls.close(),
        Udp udp => udp.close(),
        Mock m => m.close(),
    };
    t = Transport.Disconnected;
}
