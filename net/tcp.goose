// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Cross-Platform TCP Socket Engine for goose-wing.
// Synchronous and non-blocking socket wrappers
// supporting live OS TCP connections over Windows Winsock2 and POSIX.
namespace net;

import std;
import core from "..";
import .internal;

// Public environment & signal C shims (shim/tcp.c)
extern fn get_env_port(default_port: u16) -> u16 = "wing_get_env_port";
extern fn get_env_workers(default_workers: i64) -> i64 = "wing_get_env_workers";
extern fn request_shutdown() = "wing_request_shutdown";
extern fn reset_shutdown_signals() = "wing_reset_shutdown_signals";

// Event flags for epoll multiplexer
const EPOLL_READ:         u32 = 1;
const EPOLL_WRITE:        u32 = 4;
const EPOLL_ERR:          u32 = 8;
const EPOLL_HUP:          u32 = 16;
const EPOLL_ET:           u32 = 0x80000000;
const EPOLL_LISTENER_TAG: u64 = 0xFFFFFFFFFFFFFFFF;

// Initializes socket subsystem (WSAStartup on Windows).
fn tcp_init() -> bool {
    if !net_internal::g_tcp_initialized {
        let res = net_internal::native_tcp_init();
        if res == 0 {
            net_internal::g_tcp_initialized = true;
        }
        return res == 0;
    }
    return true;
}

// Cleans up socket subsystem.
fn tcp_cleanup() {
    if net_internal::g_tcp_initialized {
        net_internal::native_tcp_cleanup();
        net_internal::g_tcp_initialized = false;
    }
}

// Installs OS shutdown/reload signal handlers (SIGINT/SIGTERM on POSIX & ConsoleCtrl/CRT signals on Windows).
fn install_shutdown_signals() -> bool {
    return net_internal::native_install_shutdown_signals() == 0;
}

// Returns true once SIGINT, SIGTERM, or `request_shutdown()` has been triggered.
fn shutdown_requested() -> bool {
    return net_internal::native_shutdown_requested() != 0;
}

// Atomically reads and clears a pending SIGHUP reload signal (POSIX).
fn consume_reload_signal() -> bool {
    return net_internal::native_consume_reload_signal() != 0;
}

// Listens for incoming TCP connections on host:port.
// If port is 0, OS allocates an ephemeral port (retrieve with tcp_getsockname_port).
// Returns listening socket handle, or -1 on error.
fn tcp_listen(host: const u8[:], port: u16 = 0, backlog: i32 = 128) -> i64 {
    tcp_init();
    return net_internal::native_tcp_listen(host, port, backlog);
}

// Listens on a Unix Domain Socket (AF_UNIX) path (uWebSockets us_socket_context_listen_unix pattern).
// Returns listening socket handle, or -1 on error.
fn tcp_listen_unix(path: const u8[:], backlog: i32 = 128) -> i64 {
    tcp_init();
    return net_internal::native_tcp_listen_unix(path, backlog);
}

// Connects to a Unix Domain Socket (AF_UNIX) path (uWebSockets us_socket_context_connect_unix pattern).
// Returns connected socket handle (> 0), or -1 on error.
fn tcp_connect_unix(path: const u8[:]) -> i64 {
    tcp_init();
    return net_internal::native_tcp_connect_unix(path);
}

// Adopts an externally accepted or inherited socket descriptor (uWebSockets us_adopt_accepted_socket pattern).
// Sets non-blocking mode, disables handle inheritance, and configures TCP_NODELAY & SO_KEEPALIVE.
// Returns sanitized socket handle, or -1 on error.
fn adopt_socket(raw_fd: i64) -> i64 {
    tcp_init();
    return net_internal::native_adopt_socket(raw_fd);
}

// Retrieves the locally bound port for a socket.
fn tcp_getsockname_port(fd: i64) -> u16 {
    guard fd > 0 else { return 0; }
    return net_internal::native_tcp_getsockname_port(fd);
}

// Retrieves the connected peer IPv4 address string for a socket (or "127.0.0.1" fallback).
fn tcp_get_peer_ip(fd: i64, out_ip: u8[..64]&) {
    var raw: u8[64] = [0; 64];
    let n = net_internal::native_tcp_get_peer_ip(fd, raw[..]);
    if n > 0 && n <= 64 {
        let _ = out_ip.try_set(raw[..n]);
    } else {
        let _ = out_ip.try_set("127.0.0.1");
    }
}

// Accepts an incoming connection with an optional timeout in milliseconds.
// Returns accepted socket handle (> 0), 0 on timeout, or -1 on error.
fn tcp_accept(listener_fd: i64, timeout_ms: u32 = 0) -> i64 {
    guard listener_fd > 0 else { return -1; }
    return net_internal::native_tcp_accept(listener_fd, timeout_ms);
}

// Connects to a remote TCP endpoint with timeout in milliseconds.
// Returns connected socket handle (> 0), or -1 on error/timeout.
fn tcp_connect(host: const u8[:], port: u16, timeout_ms: u32 = 5000) -> i64 {
    tcp_init();
    return net_internal::native_tcp_connect(host, port, timeout_ms);
}

// Sends bytes over TCP socket.
// Returns bytes sent (> 0), or -1 on error.
fn tcp_send(fd: i64, data: const u8[:]) -> i32 {
    guard fd > 0 && data.len > 0 else { return 0; }
    return net_internal::native_tcp_send(fd, data);
}

// Sends two slices (e.g. HTTP headers and body) in a single syscall via vectored I/O (WSASend / writev).
// Eliminates buffer concatenation in user space, matching uWebSockets bsd_write2.
// Returns bytes sent (> 0), or -1 on error.
fn tcp_send2(fd: i64, hdr: const u8[:], payload: const u8[:]) -> i32 {
    guard fd > 0 else { return 0; }
    if payload.len == 0 {
        return tcp_send(fd, hdr);
    }
    if hdr.len == 0 {
        return tcp_send(fd, payload);
    }
    return net_internal::native_tcp_send2(fd, hdr, payload);
}

// Sends an IoVecArray of up to 16 chunks over TCP socket using zero-allocation scatter/gather.
// Dispatches to native tcp_send2 and tcp_send, updating arr with iovec_consume on partial writes.
// Returns total bytes sent, 0 if empty/no-op, or -1 on error.
fn tcp_sendv(fd: i64, arr: core::IoVecArray&) -> i32 {
    guard fd > 0 else { return 0; }
    let count = arr.iovec_count();
    guard count > 0 else { return 0; }
    if count == 1 { return net_internal::tcp_sendv_one(fd, arr); }
    if count == 2 { return net_internal::tcp_sendv_two(fd, arr); }
    return net_internal::tcp_sendv_multi(fd, arr);
}

// Global shared 64 KB receive loop buffer (LIBUS_RECV_BUFFER_LENGTH = 65536) in .bss
// Eliminates the 4 KB stack memset [0; 4096] on every single recv call.
const RECV_BUFFER_CAP: i64 = 65536;

// Receives bytes from TCP socket directly into the provided destination slice (zero-copy, zero-heap).
// Returns bytes received (> 0), 0 on clean EOF, -2 on timeout, or -1 on error.
fn tcp_recv_slice(fd: i64, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    guard fd > 0 && dst.len > 0 else { return -1; }
    return net_internal::native_tcp_recv(fd, dst, timeout_ms);
}

// Receives bytes directly into the caller-provided receive buffer without allocating or zeroing stack memory.
// Returns (bytes_received, readable_slice).
fn tcp_recv_shared(fd: i64, buf: u8[..65536]&, max_len: i32 = 65536, timeout_ms: u32 = 5000) -> i32, const u8[:] {
    guard fd > 0 else { return -1, ""; }
    let eff_max = min(RECV_BUFFER_CAP as i32, max(1, max_len));
    net_internal::ensure_shared_buf_len(buf, eff_max);
    let recvd = net_internal::native_tcp_recv(fd, buf[..eff_max], timeout_ms);
    if recvd > 0 {
        return recvd, buf[..recvd];
    }
    return recvd, "";
}

// Receives bytes from TCP socket into a local stack buffer and appends to out.
// Returns:
//   > 0 : bytes received
//     0 : peer closed connection cleanly (EOF / FIN)
//    -2 : read timeout expired
//    -1 : socket error (e.g. connection reset)
fn tcp_recv<B>(fd: i64, out: B&, max_len: i32 = 4096, timeout_ms: u32 = 5000) -> i32 {
    guard fd > 0 else { return -1; }
    var buf: u8[16384] = [0; 16384];
    let eff_max = min(16384, max(1, max_len));
    let recvd = net_internal::native_tcp_recv(fd, buf[..eff_max], timeout_ms);
    if recvd > 0 {
        let copy_len = min(recvd as i64, max(0, core::sub_sat_i64(out.cap, out.len)));
        out.append(buf[..copy_len]);
    }
    return recvd;
}

// Closes socket handle.
fn tcp_close(fd: i64) {
    if fd > 0 {
        net_internal::native_tcp_close(fd);
    }
}

// Abruptly terminates the TCP connection with an immediate TCP RST segment (RFC 1122 Section 4.2.2.13).
// Discards all unsent/unreceived data and bypasses TIME_WAIT state.
fn tcp_abort(fd: i64) -> bool {
    guard fd > 0 else { return false; }
    tcp_set_linger(fd, true, 0);
    tcp_close(fd);
    return true;
}

// Channel shutdown modes
const SHUT_RD:   i32 = 0;
const SHUT_WR:   i32 = 1;
const SHUT_RDWR: i32 = 2;

// Shuts down socket send/receive channels.
fn tcp_shutdown(fd: i64, how: i32 = SHUT_WR) -> bool {
    guard fd > 0 else { return false; }
    return net_internal::native_tcp_shutdown(fd, how) == 0;
}

// Configures SO_LINGER on socket (RFC 1122 Section 4.2.2.13).
fn tcp_set_linger(fd: i64, onoff: bool, linger_sec: i32 = 0) -> bool {
    guard fd > 0 else { return false; }
    return net_internal::native_tcp_set_linger(fd, if onoff { 1 } else { 0 }, linger_sec) == 0;
}

// Configures TCP_NODELAY (Nagle algorithm bypass) on socket.
fn tcp_set_nodelay(fd: i64, enable: bool = true) -> bool {
    guard fd > 0 else { return false; }
    return net_internal::native_tcp_set_nodelay(fd, if enable { 1 } else { 0 }) == 0;
}

// Configures SO_REUSEADDR on socket.
fn tcp_set_reuseaddr(fd: i64, enable: bool = true) -> bool {
    guard fd > 0 else { return false; }
    return net_internal::native_tcp_set_reuseaddr(fd, if enable { 1 } else { 0 }) == 0;
}

// Configures SO_REUSEPORT on socket (Linux / FreeBSD).
fn tcp_set_reuseport(fd: i64, enable: bool = true) -> bool {
    guard fd > 0 else { return false; }
    return net_internal::native_tcp_set_reuseport(fd, if enable { 1 } else { 0 }) == 0;
}

// Configures TCP_DEFER_ACCEPT to eliminate context switches on empty connections.
fn tcp_set_defer_accept(fd: i64, timeout_sec: i32 = 1) -> bool {
    guard fd > 0 else { return false; }
    return net_internal::native_tcp_set_defer_accept(fd, timeout_sec) == 0;
}

// Configures TCP_USER_TIMEOUT (e.g. 5000ms) to abort dead peers in 5s instead of 15m.
fn tcp_set_user_timeout(fd: i64, timeout_ms: u32 = 5000) -> bool {
    guard fd > 0 else { return false; }
    return net_internal::native_tcp_set_user_timeout(fd, timeout_ms) == 0;
}

// Configures aggressive SO_KEEPALIVE profile with strict boundary validation (RFC 1122 Section 4.2.3.6).
// Limits: idle_sec in 1..7200, intvl_sec in 1..300, cnt in 1..127.
fn tcp_set_keepalive(fd: i64, idle_sec: i32 = 1, intvl_sec: i32 = 11, cnt: i32 = 3) -> bool {
    guard fd > 0 else { return false; }
    guard idle_sec >= 1 && idle_sec <= 7200 else { return false; }
    guard intvl_sec >= 1 && intvl_sec <= 300 else { return false; }
    guard cnt >= 1 && cnt <= 127 else { return false; }
    return net_internal::native_tcp_set_keepalive_params(fd, idle_sec, intvl_sec, cnt) == 0;
}

// Limits SYN retransmissions on connect to abort unreachable hosts quickly.
fn tcp_set_syn_retries(fd: i64, count: i32 = 3) -> bool {
    guard fd > 0 else { return false; }
    return net_internal::native_tcp_set_syn_retries(fd, count) == 0;
}

// RFC 7413 Section 5.1: TCP Fast Open Server Configuration - Default TFO queue length
const TCP_FASTOPEN_DEFAULT_QLEN: i32 = 512;
// RFC 7413 Section 5.2: TCP Fast Open Client Operation - MSG_FASTOPEN flag for sendto
const MSG_FASTOPEN: i32 = 0x20000000;

// RFC 7413 Section 5.1: TCP Fast Open Server Configuration - Enables TFO on listening socket
fn tcp_set_fastopen(fd: i64, qlen: i32 = TCP_FASTOPEN_DEFAULT_QLEN) -> bool {
    guard fd > 0 else { return false; }
    return net_internal::native_tcp_set_fastopen(fd, qlen) == 0;
}

// RFC 7413 Section 5.2: TCP Fast Open Client Operation - Sends initial data payload with SYN
fn tcp_send_fastopen(fd: i64, data: const u8[:]) -> i32 {
    guard fd > 0 && data.len > 0 else { return 0; }
    return net_internal::native_tcp_send_fastopen(fd, data);
}

// RFC 3168 Section 5: The ECN Field in IP - Extracts 2-bit ECN codepoint from IP TOS octet
inline fn ecn_from_tos(tos: u8) -> u8 {
    return tos & rfc::ECN_MASK;
}

// RFC 3168 Section 5: The ECN Field in IP - Checks whether IP TOS indicates ECN capability (ECT(0) or ECT(1))
inline fn ecn_is_capable(tos: u8) -> bool {
    let cp = tos & rfc::ECN_MASK;
    return cp == rfc::ECN_ECT_0 || cp == rfc::ECN_ECT_1;
}

// RFC 3168 Section 5: The ECN Field in IP - Checks whether IP TOS indicates Congestion Experienced (CE)
inline fn ecn_is_congestion_experienced(tos: u8) -> bool {
    return (tos & rfc::ECN_MASK) == rfc::ECN_CE;
}

// RFC 3168 Section 6.1.1: ECN-Capable TCP - Configures IP_TOS octet on IPv4 socket
fn tcp_set_tos(fd: i64, tos: u8) -> bool {
    guard fd > 0 else { return false; }
    return net_internal::native_tcp_set_tos(fd, tos) == 0;
}

// RFC 3168 Section 6.1.1: ECN-Capable TCP - Configures IPV6_TCLASS octet on IPv6 socket
fn tcp_set_ipv6_tclass(fd: i64, tclass: u8) -> bool {
    guard fd > 0 else { return false; }
    return net_internal::native_tcp_set_tclass(fd, tclass) == 0;
}

// RFC 3168 Section 6.1.1: ECN-Capable TCP - Configures ECN codepoint on IPv4 socket
fn tcp_set_ecn(fd: i64, codepoint: u8) -> bool {
    guard fd > 0 && codepoint <= rfc::ECN_MASK else { return false; }
    return net_internal::native_tcp_set_tos(fd, codepoint) == 0;
}

// Retrieves number of unsent / unacknowledged bytes in socket write queue (tcpi_notsent_bytes).
fn tcp_get_notsent_bytes(fd: i64) -> i64 {
    guard fd > 0 else { return 0; }
    return net_internal::native_tcp_get_notsent_bytes(fd);
}

// Retrieves number of immediately readable bytes in socket receive queue.
fn tcp_get_readable_bytes(fd: i64) -> i64 {
    guard fd > 0 else { return 0; }
    return net_internal::native_tcp_get_readable_bytes(fd);
}

// Flushes buffered data from CorkBuffer directly to TCP socket.
// Returns bytes sent, or -1 on socket error.
fn tcp_flush_cork(fd: i64, cb: core::CorkBuffer&) -> i32 {
    let pending = cb.cork_pending();
    guard fd > 0 && pending > 0 else { return 0; }
    let sent = tcp_send(fd, cb.cork_as_slice());
    if sent > 0 {
        cb.cork_consume(sent);
    }
    return sent;
}

// ---- uWebSockets AsyncSocket BackPressure & Zero-Copy Cork Transition Engine

// Bounded zero-allocation backpressure queue for outbound socket traffic.
// Matches uWebSockets AsyncSocketData / BackPressure amortized compaction pattern.
struct BackPressure {
    data:              u8[..65536] = [],
    pending_cork:      u8[..4096]  = [],
    pending_removal:   i64         = 0,
    total_buffered:    u64         = 0,
    total_drained:     u64         = 0,
    drop_count:        u64         = 0,
    shutdown_pending:  bool        = false,
    write_shut:        bool        = false,
    peer_fin_received: bool        = false,
}

fn backpressure_len(bp: const BackPressure&) -> i64 {
    return core::sub_sat_i64(bp.data.len, bp.pending_removal);
}

// Queries whether outbound flow control is active (unsent data buffered in backpressure).
fn tcp_is_flow_controlled(bp: const BackPressure&) -> bool {
    return backpressure_len(bp) > 0;
}

fn backpressure_clear(bp: BackPressure&) {
    bp.data.clear();
    bp.pending_removal = 0;
}

// Appends data to the backpressure buffer, performing compaction if pending_removal > 0
fn backpressure_append(bp: BackPressure&, bytes: const u8[:]) -> bool {
    guard bytes.len > 0 else { return true; }

    if core::add_sat_i64(bp.data.len, bytes.len) > bp.data.cap {
        net_internal::backpressure_compact(bp);
    }

    guard bp.data.try_append(bytes) else {
        bp.drop_count = core::add_sat_u64(bp.drop_count, 1);
        return false;
    }

    bp.total_buffered = core::add_sat_u64(bp.total_buffered, bytes.len as u64);
    return true;
}

// Three-level prioritized async write matching uWebSockets AsyncSocket::write:
// 1. If backpressure exists, drain it first.
// 2. If no backpressure and cork fits, buffer directly in CorkBuffer (zero-copy into shared reactor buffer).
// 3. Otherwise flush cork and send directly via syscall. Any unsent remainder spills into BackPressure.
// Returns (bytes_written, needs_writable_poll).
fn async_socket_write(
    fd:         i64,
    cork:       core::CorkBuffer&,
    bp:         BackPressure&,
    data:       const u8[:],
    optionally: bool = false,
) -> i32, bool {
    guard fd > 0 else { return 0, false; }
    guard !bp.write_shut && !bp.shutdown_pending else {
        bp.drop_count = core::add_sat_u64(bp.drop_count, 1);
        return 0, false;
    }

    let written_bp, poll_bp, handled_bp = net_internal::async_write_drain_existing(fd, bp, data, optionally);
    guard !handled_bp else { return written_bp, poll_bp; }

    guard data.len > 0 else { return 0, false; }

    if data.len <= cork.cork_available() {
        cork.cork_write_exact(data);
        return data.len as i32, false;
    }

    let written_cork, poll_cork, handled_cork = net_internal::async_write_spill_cork(fd, cork, bp, data, optionally);
    guard !handled_cork else { return written_cork, poll_cork; }

    return net_internal::async_write_direct(fd, bp, data, optionally);
}

// Spills remaining cork buffer into backpressure.
fn uncork_spill_to_bp(cork: core::CorkBuffer&, bp: BackPressure&) {
    guard cork.cork_pending() > 0 else { return; }
    if backpressure_append(bp, cork.cork_as_slice()) {
        cork.cork_reset();
    }
}

// Uncorks the socket and flushes cork buffer while strictly preserving FIFO stream order.
// If backpressure is already active, cork data is appended behind backpressure without out-of-order sending.
// Returns (bytes_written, needs_writable_poll).
fn async_socket_uncork(fd: i64, cork: core::CorkBuffer&, bp: BackPressure&) -> i32, bool {
    guard fd > 0 else { return 0, false; }

    var total_sent: i64 = 0;

    // 1. Drain existing backpressure first to maintain strict TCP FIFO stream ordering
    if backpressure_len(bp) > 0 {
        let sent_bp = tcp_send(fd, net_internal::backpressure_data(bp));
        if sent_bp > 0 {
            net_internal::backpressure_erase(bp, sent_bp);
            total_sent = core::add_sat_i64(total_sent, sent_bp);
        }
    }

    // 2. If backpressure is still active, append cork to backpressure without sending ahead of it
    if backpressure_len(bp) > 0 {
        uncork_spill_to_bp(cork, bp);
        return total_sent as i32, true;
    }

    // 3. Backpressure is clear; flush cork buffer directly to socket
    let sent_cork, needs_poll = net_internal::uncork_flush_direct(fd, cork, bp);
    return core::add_sat_i64(total_sent, sent_cork) as i32, needs_poll;
}

// Drains backpressure queue upon writable event (POLL_WRITE).
// If a shutdown was deferred, executes tcp_shutdown(SHUT_WR) once the queue is fully drained.
// If an I/O error occurs (sent < 0), aborts socket and clears backpressure
// to prevent poll deadlock (RFC 1122 §4.2.2.13).
// Returns (bytes_drained, is_fully_empty).
fn async_socket_drain(fd: i64, bp: BackPressure&) -> i32, bool {
    guard fd > 0 else { return 0, true; }
    if backpressure_len(bp) == 0 && bp.pending_cork.len > 0 {
        if backpressure_append(bp, bp.pending_cork[..]) {
            bp.pending_cork.clear();
        }
    }
    let bp_active = backpressure_len(bp);
    guard bp_active > 0 else {
        net_internal::check_execute_deferred_shutdown(fd, bp);
        return 0, true;
    }

    let sent = tcp_send(fd, net_internal::backpressure_data(bp));
    if sent < 0 {
        async_socket_abort(fd, bp);
        return sent, true;
    }
    if sent > 0 {
        net_internal::backpressure_erase(bp, sent);
    }

    if backpressure_len(bp) == 0 && bp.pending_cork.len > 0 {
        if backpressure_append(bp, bp.pending_cork[..]) {
            bp.pending_cork.clear();
        }
    }
    let is_empty = backpressure_len(bp) == 0 && bp.pending_cork.len == 0;
    if is_empty {
        net_internal::check_execute_deferred_shutdown(fd, bp);
    }
    return sent, is_empty;
}

// Initiates graceful shutdown of socket write side (SHUT_WR / SD_SEND).
// If backpressure is active, defers shutdown until queue is completely drained (uSockets #148 / Go #82375).
// If peer FIN was already received, both directions are terminated; completes full socket teardown (RFC 9293 §3.5).
// Returns (did_shutdown_now, is_deferred).
fn async_socket_shutdown(fd: i64, bp: BackPressure&, cork: core::CorkBuffer&) -> bool, bool {
    guard fd > 0 else { return false, false; }
    guard !bp.write_shut else { return true, false; }

    if cork.cork_pending() > 0 {
        async_socket_uncork(fd, cork, bp);
        if cork.cork_pending() > 0 {
            let rem = cork.cork_as_slice();
            let copy_len = min(rem.len, bp.pending_cork.cap);
            let _ = bp.pending_cork.try_set(rem[0..copy_len]);
            cork.cork_reset();
            if copy_len < rem.len {
                cork.cork_write(rem[copy_len..]);
            }
        }
    }

    guard backpressure_len(bp) == 0 && bp.pending_cork.len == 0 else {
        bp.shutdown_pending = true;
        return false, true;
    }

    let ok = tcp_shutdown(fd, SHUT_WR);
    bp.write_shut = true;
    bp.shutdown_pending = false;
    if bp.peer_fin_received {
        tcp_close(fd);
    }
    return ok, false;
}

// Records peer half-close (FIN received) in socket state (Go #18527, RFC 9293 Section 3.5).
// If local write direction is already shut down, the connection is fully closed; tears down socket FD.
fn async_socket_on_peer_fin(fd: i64, bp: BackPressure&) {
    bp.peer_fin_received = true;
    if bp.write_shut && fd > 0 {
        tcp_close(fd);
    }
}

// Discards all queued backpressure and abruptly terminates socket with a TCP RST (RFC 1122 Section 4.2.2.13).
fn async_socket_abort(fd: i64, bp: BackPressure&) -> bool {
    guard fd > 0 else { return false; }
    backpressure_clear(bp);
    bp.shutdown_pending = false;
    bp.write_shut = true;
    return tcp_abort(fd);
}

// Closes the socket conforming strictly to RFC 1122 Section 4.2.2.13.
// If unread bytes remain in the receive queue, triggers an abortive RST close to signal data loss.
// Otherwise performs clean socket close.
fn async_socket_close(fd: i64, bp: BackPressure&) -> bool {
    guard fd > 0 else { return false; }
    let unread = tcp_get_readable_bytes(fd);
    if unread > 0 {
        return async_socket_abort(fd, bp);
    }
    backpressure_clear(bp);
    bp.shutdown_pending = false;
    bp.write_shut = true;
    tcp_close(fd);
    return true;
}

// Receives data directly into a PipeBuffer without intermediate scratch copies.
// Returns bytes read (> 0), 0 on clean EOF, -2 on timeout, or -1 on error.
fn tcp_recv_pipe(fd: i64, pipe: core::PipeBuffer&, min_span: i64 = 4096, timeout_ms: u32 = 5000) -> i32 {
    guard fd > 0 else { return -1; }
    let span, err = pipe.get_write_span(min_span);
    if err != core::IoError.None {
        return -1;
    }
    let recvd = net_internal::native_tcp_recv(fd, span, timeout_ms);
    if recvd > 0 {
        pipe.commit_write(recvd);
    }
    return recvd;
}

// Configures socket non-blocking mode.
fn tcp_set_nonblocking(fd: i64, nonblocking: bool = true) -> bool {
    guard fd > 0 else { return false; }
    return net_internal::native_tcp_set_nonblocking(fd, if nonblocking { 1 } else { 0 }) == 0;
}

// Sets TCP_QUICKACK (Linux delayed ACK bypass) to eliminate 40ms delayed ACK stalls.
fn tcp_set_quickack(fd: i64, enable: bool = true) -> bool {
    guard fd > 0 else { return false; }
    return net_internal::native_tcp_set_quickack(fd, if enable { 1 } else { 0 }) == 0;
}

// Sets TCP_CORK (Linux) to coalesce frames at the kernel TCP stack level.
fn tcp_set_cork(fd: i64, enable: bool = true) -> bool {
    guard fd > 0 else { return false; }
    return net_internal::native_tcp_set_cork(fd, if enable { 1 } else { 0 }) == 0;
}

// Accepts an incoming connection in non-blocking mode.
// Returns socket handle (> 0), 0 if no connection pending (EAGAIN), or -1 on error.
fn tcp_accept_nonblocking(listener_fd: i64) -> i64 {
    guard listener_fd > 0 else { return -1; }
    return net_internal::native_tcp_accept_nonblocking(listener_fd);
}

// Receives bytes from non-blocking socket into out buffer without zeroing memory.
// Returns:
//   > 0 : bytes received
//     0 : peer closed connection cleanly (EOF / FIN)
//    -2 : WouldBlock / EAGAIN (no data ready right now)
//    -1 : socket error / connection reset
fn tcp_recv_nonblocking<B>(fd: i64, out: B&) -> i32 {
    guard fd > 0 else { return -1; }
    var buf: u8[16384] = [0; 16384];
    let recvd = net_internal::native_tcp_recv_nonblocking(fd, buf[..16384]);
    if recvd > 0 {
        let copy_len = min(recvd as i64, max(0, core::sub_sat_i64(out.cap, out.len)));
        out.append(buf[..copy_len]);
    }
    return recvd;
}

// Receives bytes from non-blocking socket directly into destination slice.
fn tcp_recv_nonblocking_slice(fd: i64, dst: u8[:]) -> i32 {
    guard fd > 0 && dst.len > 0 else { return -1; }
    return net_internal::native_tcp_recv_nonblocking(fd, dst);
}

// Creates an epoll/reactor handle (native epoll_create1 on Linux, WSAPoll on Windows).
fn epoll_create() -> i64 {
    tcp_init();
    return net_internal::native_epoll_create();
}

// Registers a socket descriptor in the epoll multiplexer.
fn epoll_add(epfd: i64, sock_fd: i64, events: u32 = EPOLL_READ, udata: u64 = 0) -> bool {
    guard epfd >= 0 && sock_fd > 0 else { return false; }
    return net_internal::native_epoll_add(epfd, sock_fd, events, udata) == 0;
}

// Modifies interest flags for a registered socket descriptor.
fn epoll_mod(epfd: i64, sock_fd: i64, events: u32, udata: u64) -> bool {
    guard epfd >= 0 && sock_fd > 0 else { return false; }
    return net_internal::native_epoll_mod(epfd, sock_fd, events, udata) == 0;
}

// Removes a socket descriptor from the epoll multiplexer.
fn epoll_del(epfd: i64, sock_fd: i64) -> bool {
    guard epfd >= 0 && sock_fd > 0 else { return false; }
    return net_internal::native_epoll_del(epfd, sock_fd) == 0;
}

// Waits for I/O events on the epoll multiplexer.
// Clears and populates out_fds and out_udata with ready event descriptors and udata tags.
fn epoll_wait<F, U>(epfd: i64, out_fds: F&, out_udata: U&, timeout_ms: i32 = -1) -> i32 {
    guard epfd >= 0 else { return 0; }
    out_fds.clear();
    out_udata.clear();
    var raw_fds:   i64[256] = [0; 256];
    var raw_udata: u64[256] = [0; 256];
    let n = net_internal::native_epoll_wait(epfd, raw_fds[..], raw_udata[..], timeout_ms);
    guard n > 0 else { return 0; }
    let limit = min(n as i64, min(out_fds.cap, out_udata.cap));
    for i in limit {
        out_fds.push(raw_fds[i]);
        out_udata.push(raw_udata[i]);
    }
    return limit as i32;
}

// Closes epoll/reactor handle.
fn epoll_close(epfd: i64) {
    if epfd >= 0 {
        net_internal::native_epoll_close(epfd);
    }
}

// Pins calling thread to specific CPU core ID.
fn set_cpu_affinity(cpu_id: i64) -> bool {
    guard cpu_id >= 0 else { return false; }
    return net_internal::native_set_cpu_affinity(cpu_id) == 0;
}

// Binds listener incoming socket queue to specific CPU core (SO_INCOMING_CPU).
fn tcp_set_incoming_cpu(sock_fd: i64, cpu_id: i64) -> bool {
    guard sock_fd > 0 && cpu_id >= 0 else { return false; }
    return net_internal::native_tcp_set_incoming_cpu(sock_fd, cpu_id) == 0;
}

// Deterministic O(1) connection slot index allocator for reactor loops.
// Bounded to 4096 slots without dynamic heap allocations.
const FREE_SLOT_STACK_CAP: i64 = 4096;

struct FreeSlotStack {
    indices:  u16[4096] = [0; 4096],
    top:      i64       = 0,
    capacity: i64       = 4096,
}

// Pre-populates the stack so slot 0 is popped first.
fn init_free_slots(stack: FreeSlotStack&, count: i64) {
    let n = min(max(count, 0), FREE_SLOT_STACK_CAP);
    stack.top = n;
    stack.capacity = n;
    let last = core::sub_sat_i64(n, 1);
    for i in n {
        stack.indices[i] = core::sub_sat_i64(last, i) as u16;
    }
}

// Pops next free slot index in O(1). Returns -1 if no slots available.
fn pop_free_slot(stack: FreeSlotStack&) -> i64 {
    let top = stack.top;
    guard top > 0 && top <= FREE_SLOT_STACK_CAP else { return -1; }
    let next_top = core::sub_sat_i64(top, 1);
    stack.top = next_top;
    return stack.indices[next_top];
}

// Restores slot index back into the free stack in O(1).
fn push_free_slot(stack: FreeSlotStack&, slot: i64) -> bool {
    guard slot >= 0 && slot < stack.capacity && stack.top < stack.capacity else { return false; }
    stack.indices[stack.top] = slot as u16;
    stack.top = core::add_sat_i64(stack.top, 1);
    return true;
}

// Bounded zero-allocation backpressure slot for non-blocking reactor connection.
// Buffers partial socket writes when send() returns EAGAIN/EWOULDBLOCK.
struct BackpressureSlot {
    buf:       u8[16384] = [0; 16384],
    len:       i64       = 0,
    offset:    i64       = 0,
    is_active: bool      = false,
}

// Resets the backpressure slot state.
fn clear_backpressure_slot(bp: BackpressureSlot&) {
    bp.len = 0;
    bp.offset = 0;
    bp.is_active = false;
}

// Buffers unsent payload bytes when socket send() cannot complete immediately.
// Returns true if buffered, false if unsent data exceeds 16384 buffer capacity.
fn buffer_backpressure(bp: BackpressureSlot&, unsent: const u8[:]) -> bool {
    guard unsent.len > 0 && unsent.len <= 16384 else { return false; }
    for i in unsent.len {
        bp.buf[i] = unsent[i];
    }
    bp.len = unsent.len;
    bp.offset = 0;
    bp.is_active = true;
    return true;
}

// Drains pending backpressure bytes to sock_fd.
// Returns (bytes_written, is_fully_drained).
fn drain_backpressure(bp: BackpressureSlot&, sock_fd: i64) -> i64, bool {
    guard bp.is_active else { return 0, true; }
    guard bp.offset < bp.len && bp.len <= 16384 else {
        clear_backpressure_slot(bp);
        return 0, true;
    }
    guard sock_fd > 0 else { return -1, false; }
    let pending = bp.buf[bp.offset..bp.len];
    let sent = tcp_send(sock_fd, pending);
    guard sent > 0 else { return sent, false; }
    bp.offset = core::add_sat_i64(bp.offset, sent);
    guard bp.offset >= bp.len else { return sent, false; }
    clear_backpressure_slot(bp);
    return sent, true;
}

// ---- Dual-stack TCP/UDP, transparent proxy, kernel splice, and host utils --

// Listens on an IPv4 or IPv6 address (flags: bit 0 = IP_TRANSPARENT, bit 1 = force IPv6).
fn tcp_listen_dual(
    host:    const u8[:],
    port:    u16,
    backlog: i32 = 512,
    flags:   i32 = 0,
) -> i64 {
    let _ = tcp_init();
    return net_internal::native_tcp_listen_dual(host, port, backlog, flags);
}

// Non-blockingly accepts a connection and extracts peer and local/original-dst endpoints.
// mode_flags: 0 = direct, 1 = tproxy, 2 = redirect (SO_ORIGINAL_DST / IP6T_SO_ORIGINAL_DST).
fn tcp_accept_info(
    listener_fd:     i64,
    mode_flags:      i32,
    out_peer_ip:     u8[:],
    out_peer_ip_len: i32&,
    out_peer_port:   u16&,
    out_dst_ip:      u8[:],
    out_dst_ip_len:  i32&,
    out_dst_port:    u16&,
) -> i64 {
    guard listener_fd > 0 else { return -1; }
    return net_internal::native_tcp_accept_info(
        listener_fd,
        mode_flags,
        out_peer_ip,
        out_peer_ip_len,
        out_peer_port,
        out_dst_ip,
        out_dst_ip_len,
        out_dst_port,
    );
}

// Begins a non-blocking IPv4/IPv6 TCP connect optionally bound to `src_ip` with `so_mark`.
// Sets out_state (0 = connected, 1 = in progress, -1 = failed) and out_err (mapped errno).
fn tcp_connect_bound_begin(
    src_ip:    const u8[:],
    dst_ip:    const u8[:],
    dst_port:  u16,
    so_mark:   u32,
    out_state: i32&,
    out_err:   i32&,
) -> i64 {
    guard dst_ip.len > 0 && dst_port != 0 else {
        out_state = -1;
        out_err = -1;
        return -1;
    }
    let _ = tcp_init();
    return net_internal::native_tcp_connect_bound_begin(src_ip, dst_ip, dst_port, so_mark, out_state, out_err);
}

// Reads async connect completion status via SO_ERROR (0 = ok, 1 = refused, 2 = unreach, 3 = timeout).
fn tcp_connect_status(sock_fd: i64) -> i32 {
    guard sock_fd > 0 else { return -1; }
    return net_internal::native_tcp_connect_status(sock_fd);
}

// Non-destructively peeks bytes from a socket using MSG_PEEK (-2 on WouldBlock).
fn tcp_recv_peek(sock_fd: i64, dst: u8[:]) -> i32 {
    guard sock_fd > 0 && dst.len > 0 else { return -1; }
    return net_internal::native_tcp_recv_peek(sock_fd, dst);
}

// Configures IP_TTL (or IPV6_UNICAST_HOPS) on an outbound socket.
fn tcp_set_ttl(sock_fd: i64, ttl: i32, is_ipv6: bool = false) -> bool {
    guard sock_fd > 0 && ttl >= 1 && ttl <= 255 else { return false; }
    return net_internal::native_tcp_set_ttl(sock_fd, ttl, if is_ipv6 { 1 } else { 0 }) == 0;
}

// Creates a non-blocking kernel pipe pair for splice(2) forwarding (Linux only).
fn pipe_create(out_read_fd: i64&, out_write_fd: i64&) -> bool {
    return net_internal::native_pipe_create(out_read_fd, out_write_fd) == 0;
}

// Closes a kernel pipe pair created by pipe_create.
fn pipe_close(read_fd: i64, write_fd: i64) {
    net_internal::native_pipe_close(read_fd, write_fd);
}

// Relays up to `max_bytes` from `src_fd` to `dst_fd` via a kernel pipe (Linux splice).
// Returns bytes transferred (> 0), 0 on EOF, -2 on WouldBlock, or -1 if unsupported/error.
fn tcp_splice_chunk(
    src_fd:        i64,
    dst_fd:        i64,
    pipe_r:        i64,
    pipe_w:        i64,
    max_bytes:     i64,
    in_pipe_bytes: i64&,
) -> i64 {
    guard src_fd > 0 && dst_fd > 0 && pipe_r >= 0 && pipe_w >= 0 && max_bytes > 0 else {
        return -1;
    }
    return net_internal::native_tcp_splice_chunk(src_fd, dst_fd, pipe_r, pipe_w, max_bytes, in_pipe_bytes);
}

// Writes newline-separated local host IPv4/IPv6 addresses into `out_buf`.
fn net_get_local_ips(out_buf: u8[:]) -> i32 {
    guard out_buf.len > 0 else { return -1; }
    let _ = tcp_init();
    return net_internal::native_net_get_local_ips(out_buf);
}

// Opens a non-blocking dual-stack UDP socket (flags: bit 1 = force IPv6, bit 2 = IP_FREEBIND).
fn udp_open_dual(bind_ip: const u8[:] = "", bind_port: u16 = 0, flags: i32 = 0) -> i64 {
    let _ = tcp_init();
    return net_internal::native_udp_open_dual(bind_ip, bind_port, flags);
}

// Sends a non-blocking UDP datagram to an IPv4 or IPv6 literal (`-2` on WouldBlock).
fn udp_sendto_dual(sock_fd: i64, data: const u8[:], dst_ip: const u8[:], dst_port: u16) -> i32 {
    guard sock_fd > 0 && dst_ip.len > 0 && dst_port != 0 else { return -1; }
    return net_internal::native_udp_sendto_dual(sock_fd, data, dst_ip, dst_port);
}

// Non-blockingly receives a UDP datagram and extracts sender IP + port (`-2` on WouldBlock).
fn udp_recvfrom_dual(
    sock_fd:         i64,
    out_buf:         u8[:],
    out_peer_ip:     u8[:],
    out_peer_ip_len: i32&,
    out_peer_port:   u16&,
) -> i32 {
    guard sock_fd > 0 && out_buf.len > 0 else { return -1; }
    return net_internal::native_udp_recvfrom_dual(sock_fd, out_buf, out_peer_ip, out_peer_ip_len, out_peer_port);
}

// Executes a bounded-timeout synchronous UDP request/response to an IPv4 or IPv6 server.
fn udp_exchange_dual(
    server_ip:   const u8[:],
    server_port: u16,
    query:       const u8[:],
    out_resp:    u8[:],
    timeout_ms:  u32 = 1500,
) -> i32 {
    guard server_ip.len > 0 && server_port != 0 && query.len > 0 && out_resp.len > 0 else {
        return -1;
    }
    let _ = tcp_init();
    return net_internal::native_udp_exchange_dual(server_ip, server_port, query, out_resp, timeout_ms);
}

// Returns filesystem disk usage percentage (0..100) for `path`, or -1 on error.
fn fs_disk_usage_percent(path: const u8[:]) -> i32 {
    guard path.len > 0 && path.len < 1024 else { return -1; }
    return net_internal::native_fs_disk_usage_percent(path);
}

// Returns last modification Unix timestamp in seconds for `path`, or -1 if missing.
fn fs_file_mtime(path: const u8[:]) -> i64 {
    guard path.len > 0 && path.len < 1024 else { return -1; }
    return net_internal::native_fs_file_mtime(path);
}
