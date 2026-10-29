// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 4 Cross-Platform TCP Socket Engine for goose-wing.
// Synchronous and non-blocking socket wrappers
// supporting live OS TCP connections over Windows Winsock2 and POSIX.
namespace wing;

import std;
import core from "..";

// Native C shims (shim/tcp.c)
extern fn native_tcp_init() -> i32 = "wing_tcp_init";
extern fn native_tcp_cleanup() = "wing_tcp_cleanup";
extern fn native_tcp_listen(host: const u8[:], port: u16, backlog: i32) -> i64 = "wing_tcp_listen";
extern fn native_tcp_getsockname_port(sock_fd: i64) -> u16 = "wing_tcp_getsockname_port";
extern fn native_tcp_accept(listener_fd: i64, timeout_ms: u32) -> i64 = "wing_tcp_accept";
extern fn native_tcp_connect(host: const u8[:], port: u16, timeout_ms: u32) -> i64 = "wing_tcp_connect";
extern fn native_tcp_send(sock_fd: i64, data: const u8[:]) -> i32 = "wing_tcp_send";
extern fn native_tcp_send2(sock_fd: i64, hdr: const u8[:], payload: const u8[:]) -> i32 = "wing_tcp_send2";
extern fn native_tcp_recv(sock_fd: i64, buf: u8[:], timeout_ms: u32) -> i32 = "wing_tcp_recv";
extern fn native_tcp_close(sock_fd: i64) = "wing_tcp_close";
extern fn native_tcp_shutdown(sock_fd: i64, how: i32) -> i32 = "wing_tcp_shutdown";
extern fn native_tcp_set_linger(sock_fd: i64, onoff: i32, linger_sec: i32) -> i32 = "wing_tcp_set_linger";
extern fn native_tcp_set_nodelay(sock_fd: i64, enable: i32) -> i32 = "wing_tcp_set_nodelay";
extern fn native_tcp_set_reuseaddr(sock_fd: i64, enable: i32) -> i32 = "wing_tcp_set_reuseaddr";
extern fn native_tcp_set_reuseport(sock_fd: i64, enable: i32) -> i32 = "wing_tcp_set_reuseport";
extern fn native_tcp_set_defer_accept(sock_fd: i64, timeout_sec: i32) -> i32 = "wing_tcp_set_defer_accept";
extern fn native_tcp_set_user_timeout(sock_fd: i64, timeout_ms: u32) -> i32 = "wing_tcp_set_user_timeout";
extern fn native_tcp_set_keepalive_params(sock_fd: i64, idle_sec: i32, intvl_sec: i32, cnt: i32) -> i32 = "wing_tcp_set_keepalive_params";
extern fn native_tcp_set_syn_retries(sock_fd: i64, count: i32) -> i32 = "wing_tcp_set_syn_retries";
extern fn native_tcp_get_notsent_bytes(sock_fd: i64) -> i64 = "wing_tcp_get_notsent_bytes";
extern fn native_tcp_get_readable_bytes(sock_fd: i64) -> i64 = "wing_tcp_get_readable_bytes";
extern fn get_env_port(default_port: u16) -> u16 = "wing_get_env_port";
extern fn get_env_workers(default_workers: i64) -> i64 = "wing_get_env_workers";
extern fn native_tcp_set_nonblocking(sock_fd: i64, nonblocking: i32) -> i32 = "wing_tcp_set_nonblocking";
extern fn native_tcp_set_quickack(sock_fd: i64, enable: i32) -> i32 = "wing_tcp_set_quickack";
extern fn native_tcp_set_cork(sock_fd: i64, enable: i32) -> i32 = "wing_tcp_set_cork";
extern fn native_tcp_accept_nonblocking(listener_fd: i64) -> i64 = "wing_tcp_accept_nonblocking";
extern fn native_tcp_recv_nonblocking(sock_fd: i64, buf: u8[:]) -> i32 = "wing_tcp_recv_nonblocking";
extern fn native_epoll_create() -> i64 = "wing_epoll_create";
extern fn native_epoll_add(epfd: i64, sock_fd: i64, events: u32, udata: u64) -> i32 = "wing_epoll_add";
extern fn native_epoll_mod(epfd: i64, sock_fd: i64, events: u32, udata: u64) -> i32 = "wing_epoll_mod";
extern fn native_epoll_del(epfd: i64, sock_fd: i64) -> i32 = "wing_epoll_del";
extern fn native_epoll_wait(epfd: i64, out_fds: i64[:], out_udata: u64[:], timeout_ms: i32) -> i32 = "wing_epoll_wait";
extern fn native_epoll_close(epfd: i64) = "wing_epoll_close";
extern fn native_fast_cork_append(conn: i64, cork_buf: u8[:], cork_len: i64, resp: const u8[:]) -> i64 = "wing_fast_cork_append";
extern fn native_set_cpu_affinity(cpu_id: i64) -> i32 = "wing_set_cpu_affinity";
extern fn native_tcp_set_incoming_cpu(sock_fd: i64, cpu_id: i64) -> i32 = "wing_tcp_set_incoming_cpu";
extern fn native_tcp_set_fastopen(sock_fd: i64, qlen: i32) -> i32 = "wing_tcp_set_fastopen";
extern fn native_tcp_send_fastopen(sock_fd: i64, data: const u8[:]) -> i32 = "wing_tcp_send_fastopen";
extern fn native_tcp_set_tos(sock_fd: i64, tos: i32) -> i32 = "wing_tcp_set_tos";
extern fn native_tcp_set_tclass(sock_fd: i64, tclass: i32) -> i32 = "wing_tcp_set_tclass";

// Event flags for epoll multiplexer
const EPOLL_READ: u32 = 1;
const EPOLL_WRITE: u32 = 4;
const EPOLL_ERR: u32 = 8;
const EPOLL_HUP: u32 = 16;
const EPOLL_ET: u32 = 0x80000000;
const EPOLL_LISTENER_TAG: u64 = 0xFFFFFFFFFFFFFFFF;

// Global initialization flag
var g_tcp_initialized: bool = false;

// Initializes socket subsystem (WSAStartup on Windows).
fn tcp_init() -> bool {
    if !g_tcp_initialized {
        let res = native_tcp_init();
        if res == 0 {
            g_tcp_initialized = true;
        }
        return res == 0;
    }
    return true;
}

// Cleans up socket subsystem.
fn tcp_cleanup() {
    if g_tcp_initialized {
        native_tcp_cleanup();
        g_tcp_initialized = false;
    }
}

// Listens for incoming TCP connections on host:port.
// If port is 0, OS allocates an ephemeral port (retrieve with tcp_getsockname_port).
// Returns listening socket handle, or -1 on error.
fn tcp_listen(host: const u8[:], port: u16 = 0, backlog: i32 = 128) -> i64 {
    tcp_init();
    return native_tcp_listen(host, port, backlog);
}

// Retrieves the locally bound port for a socket.
fn tcp_getsockname_port(fd: i64) -> u16 {
    return native_tcp_getsockname_port(fd);
}

// Accepts an incoming connection with an optional timeout in milliseconds.
// Returns accepted socket handle (> 0), 0 on timeout, or -1 on error.
fn tcp_accept(listener_fd: i64, timeout_ms: u32 = 0) -> i64 {
    return native_tcp_accept(listener_fd, timeout_ms);
}

// Connects to a remote TCP endpoint with timeout in milliseconds.
// Returns connected socket handle (> 0), or -1 on error/timeout.
fn tcp_connect(host: const u8[:], port: u16, timeout_ms: u32 = 5000) -> i64 {
    tcp_init();
    return native_tcp_connect(host, port, timeout_ms);
}

// Sends bytes over TCP socket.
// Returns bytes sent (> 0), or -1 on error.
fn tcp_send(fd: i64, data: const u8[:]) -> i32 {
    guard fd > 0 && data.len > 0 else { return 0; }
    return native_tcp_send(fd, data);
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
    return native_tcp_send2(fd, hdr, payload);
}

fn tcp_sendv_one(fd: i64, arr: core::IoVecArray&) -> i32 {
    let chunk = core::iovec_get(arr, 0);
    let sent = tcp_send(fd, chunk);
    if sent > 0 {
        core::iovec_consume(arr, sent);
    }
    return sent;
}

fn tcp_sendv_two(fd: i64, arr: core::IoVecArray&) -> i32 {
    let c0 = core::iovec_get(arr, 0);
    let c1 = core::iovec_get(arr, 1);
    let sent = tcp_send2(fd, c0, c1);
    if sent > 0 {
        core::iovec_consume(arr, sent);
    }
    return sent;
}

fn tcp_sendv_multi(fd: i64, arr: core::IoVecArray&) -> i32 {
    var total_sent: i32 = 0;
    while !core::iovec_is_empty(arr) {
        let c = core::iovec_get(arr, 0);
        let sent = tcp_send(fd, c);
        guard sent > 0 else {
            return if total_sent > 0 { total_sent } else { sent };
        }
        core::iovec_consume(arr, sent);
        total_sent = total_sent + sent;
    }
    return total_sent;
}

// Sends an IoVecArray of up to 16 chunks over TCP socket using zero-allocation scatter/gather.
// Dispatches to native tcp_send2 and tcp_send, updating arr with iovec_consume on partial writes.
// Returns total bytes sent, 0 if empty/no-op, or -1 on error.
fn tcp_sendv(fd: i64, arr: core::IoVecArray&) -> i32 {
    guard fd > 0 else { return 0; }
    let count = core::iovec_count(arr);
    guard count > 0 else { return 0; }
    if count == 1 { return tcp_sendv_one(fd, arr); }
    if count == 2 { return tcp_sendv_two(fd, arr); }
    return tcp_sendv_multi(fd, arr);
}

// Global shared 64 KB receive loop buffer (LIBUS_RECV_BUFFER_LENGTH = 65536) in .bss
// Eliminates the 4 KB stack memset [0; 4096] on every single recv call.
const RECV_BUFFER_CAP: i64 = 65536;
var g_shared_recv_buf: u8[65536] = [0; 65536];

// Receives bytes from TCP socket directly into the provided destination slice (zero-copy, zero-heap).
// Returns bytes received (> 0), 0 on clean EOF, -2 on timeout, or -1 on error.
fn tcp_recv_slice(fd: i64, dst: u8[:], timeout_ms: u32 = 5000) -> i32 {
    guard fd > 0 && dst.len > 0 else { return -1; }
    return native_tcp_recv(fd, dst, timeout_ms);
}

// Receives bytes directly into the shared 512 KB receive loop buffer without allocating or zeroing stack memory.
// Returns (bytes_received, readable_slice).
fn tcp_recv_shared(fd: i64, max_len: i32 = 65536, timeout_ms: u32 = 5000) -> i32, const u8[:] {
    guard fd > 0 else { return -1, ""; }
    let eff_max = if max_len > RECV_BUFFER_CAP as i32 { RECV_BUFFER_CAP as i32 } else if max_len < 1 { 1 } else { max_len };
    let recvd = native_tcp_recv(fd, g_shared_recv_buf[..eff_max], timeout_ms);
    if recvd > 0 {
        return recvd, g_shared_recv_buf[..recvd];
    }
    return recvd, "";
}

// Receives bytes from TCP socket into the shared loop buffer and appends to out.
// Returns:
//   > 0 : bytes received
//     0 : peer closed connection cleanly (EOF / FIN)
//    -2 : read timeout expired
//    -1 : socket error (e.g. connection reset)
fn tcp_recv<B>(fd: i64, out: B&, max_len: i32 = 4096, timeout_ms: u32 = 5000) -> i32 {
    guard fd > 0 else { return -1; }
    let eff_max = if max_len > RECV_BUFFER_CAP as i32 { RECV_BUFFER_CAP as i32 } else if max_len < 1 { 1 } else { max_len };
    let recvd = native_tcp_recv(fd, g_shared_recv_buf[..eff_max], timeout_ms);
    if recvd > 0 {
        out.append(g_shared_recv_buf[..recvd]);
    }
    return recvd;
}

// Closes socket handle.
fn tcp_close(fd: i64) {
    if fd > 0 {
        native_tcp_close(fd);
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
const SHUT_RD: i32 = 0;
const SHUT_WR: i32 = 1;
const SHUT_RDWR: i32 = 2;

// Shuts down socket send/receive channels.
fn tcp_shutdown(fd: i64, how: i32 = SHUT_WR) -> bool {
    guard fd > 0 else { return false; }
    return native_tcp_shutdown(fd, how) == 0;
}

// Configures SO_LINGER on socket (RFC 1122 Section 4.2.2.13).
fn tcp_set_linger(fd: i64, onoff: bool, linger_sec: i32 = 0) -> bool {
    guard fd > 0 else { return false; }
    return native_tcp_set_linger(fd, if onoff { 1 } else { 0 }, linger_sec) == 0;
}

// Configures TCP_NODELAY (Nagle algorithm bypass) on socket.
fn tcp_set_nodelay(fd: i64, enable: bool = true) -> bool {
    guard fd > 0 else { return false; }
    return native_tcp_set_nodelay(fd, if enable { 1 } else { 0 }) == 0;
}

// Configures SO_REUSEADDR on socket.
fn tcp_set_reuseaddr(fd: i64, enable: bool = true) -> bool {
    guard fd > 0 else { return false; }
    return native_tcp_set_reuseaddr(fd, if enable { 1 } else { 0 }) == 0;
}

// Configures SO_REUSEPORT on socket (Linux / FreeBSD).
fn tcp_set_reuseport(fd: i64, enable: bool = true) -> bool {
    guard fd > 0 else { return false; }
    return native_tcp_set_reuseport(fd, if enable { 1 } else { 0 }) == 0;
}

// Configures TCP_DEFER_ACCEPT to eliminate context switches on empty connections.
fn tcp_set_defer_accept(fd: i64, timeout_sec: i32 = 1) -> bool {
    guard fd > 0 else { return false; }
    return native_tcp_set_defer_accept(fd, timeout_sec) == 0;
}

// Configures TCP_USER_TIMEOUT (e.g. 5000ms) to abort dead peers in 5s instead of 15m.
fn tcp_set_user_timeout(fd: i64, timeout_ms: u32 = 5000) -> bool {
    guard fd > 0 else { return false; }
    return native_tcp_set_user_timeout(fd, timeout_ms) == 0;
}

// Configures aggressive SO_KEEPALIVE profile with strict boundary validation (RFC 1122 Section 4.2.3.6).
// Limits: idle_sec in 1..7200, intvl_sec in 1..300, cnt in 1..127.
fn tcp_set_keepalive(fd: i64, idle_sec: i32 = 1, intvl_sec: i32 = 11, cnt: i32 = 3) -> bool {
    guard fd > 0 else { return false; }
    guard idle_sec >= 1 && idle_sec <= 7200 else { return false; }
    guard intvl_sec >= 1 && intvl_sec <= 300 else { return false; }
    guard cnt >= 1 && cnt <= 127 else { return false; }
    return native_tcp_set_keepalive_params(fd, idle_sec, intvl_sec, cnt) == 0;
}

// Limits SYN retransmissions on connect to abort unreachable hosts quickly.
fn tcp_set_syn_retries(fd: i64, count: i32 = 3) -> bool {
    guard fd > 0 else { return false; }
    return native_tcp_set_syn_retries(fd, count) == 0;
}

// RFC 7413 Section 5.1: TCP Fast Open Server Configuration - Default TFO queue length
const TCP_FASTOPEN_DEFAULT_QLEN: i32 = 512;
// RFC 7413 Section 5.2: TCP Fast Open Client Operation - MSG_FASTOPEN flag for sendto
const MSG_FASTOPEN: i32 = 0x20000000;

// RFC 3168 Section 5: The ECN Field in IP - Explicit Congestion Notification codepoints
const ECN_NOT_ECT: u8 = 0x00; // Not ECN-Capable Transport
const ECN_ECT_1: u8 = 0x01;   // ECN-Capable Transport (1)
const ECN_ECT_0: u8 = 0x02;   // ECN-Capable Transport (0)
const ECN_CE: u8 = 0x03;      // Congestion Experienced
const ECN_MASK: u8 = 0x03;    // Bitmask for ECN field in IP TOS / TCLASS

// RFC 7413 Section 5.1: TCP Fast Open Server Configuration - Enables TFO on listening socket
fn tcp_set_fastopen(fd: i64, qlen: i32 = TCP_FASTOPEN_DEFAULT_QLEN) -> bool {
    guard fd > 0 else { return false; }
    return native_tcp_set_fastopen(fd, qlen) == 0;
}

// RFC 7413 Section 5.2: TCP Fast Open Client Operation - Sends initial data payload with SYN
fn tcp_send_fastopen(fd: i64, data: const u8[:]) -> i32 {
    guard fd > 0 && data.len > 0 else { return 0; }
    return native_tcp_send_fastopen(fd, data);
}

// RFC 3168 Section 5: The ECN Field in IP - Extracts 2-bit ECN codepoint from IP TOS octet
//
// Example:
//   tos = 0x02
//   returns: ECN_ECT_0 (0x02)
inline fn ecn_from_tos(tos: u8) -> u8 {
    return tos & ECN_MASK;
}

// RFC 3168 Section 5: The ECN Field in IP - Checks whether IP TOS indicates ECN capability (ECT(0) or ECT(1))
inline fn ecn_is_capable(tos: u8) -> bool {
    let cp = tos & ECN_MASK;
    return cp == ECN_ECT_0 || cp == ECN_ECT_1;
}

// RFC 3168 Section 5: The ECN Field in IP - Checks whether IP TOS indicates Congestion Experienced (CE)
inline fn ecn_is_congestion_experienced(tos: u8) -> bool {
    return (tos & ECN_MASK) == ECN_CE;
}

// RFC 3168 Section 6.1.1: ECN-Capable TCP - Configures IP_TOS octet on IPv4 socket
fn tcp_set_tos(fd: i64, tos: u8) -> bool {
    guard fd > 0 else { return false; }
    return native_tcp_set_tos(fd, tos) == 0;
}

// RFC 3168 Section 6.1.1: ECN-Capable TCP - Configures IPV6_TCLASS octet on IPv6 socket
fn tcp_set_ipv6_tclass(fd: i64, tclass: u8) -> bool {
    guard fd > 0 else { return false; }
    return native_tcp_set_tclass(fd, tclass) == 0;
}

// RFC 3168 Section 6.1.1: ECN-Capable TCP - Configures ECN codepoint on IPv4 socket
fn tcp_set_ecn(fd: i64, codepoint: u8) -> bool {
    guard fd > 0 && codepoint <= ECN_MASK else { return false; }
    return native_tcp_set_tos(fd, codepoint) == 0;
}

// Retrieves number of unsent / unacknowledged bytes in socket write queue (tcpi_notsent_bytes).
fn tcp_get_notsent_bytes(fd: i64) -> i64 {
    guard fd > 0 else { return 0; }
    return native_tcp_get_notsent_bytes(fd);
}

// Retrieves number of immediately readable bytes in socket receive queue.
fn tcp_get_readable_bytes(fd: i64) -> i64 {
    guard fd > 0 else { return 0; }
    return native_tcp_get_readable_bytes(fd);
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
    data: u8[..65536] = [],
    pending_removal: i64 = 0,
    total_buffered: u64 = 0,
    total_drained: u64 = 0,
    drop_count: u64 = 0,
    shutdown_pending: bool = false,
    write_shut: bool = false,
    peer_fin_received: bool = false,
}

fn new_backpressure() -> BackPressure {
    return BackPressure { .. };
}

fn backpressure_len(bp: const BackPressure&) -> i64 {
    return bp.data.len - bp.pending_removal;
}

// Queries whether outbound flow control is active (unsent data buffered in backpressure).
fn tcp_is_flow_controlled(bp: const BackPressure&) -> bool {
    return backpressure_len(bp) > 0;
}

fn backpressure_data(bp: const BackPressure&) -> const u8[:] {
    guard bp.pending_removal < bp.data.len else { return ""; }
    return bp.data[bp.pending_removal..];
}

fn backpressure_clear(bp: BackPressure&) {
    bp.data.clear();
    bp.pending_removal = 0;
}

fn backpressure_compact(bp: BackPressure&) {
    guard bp.pending_removal > 0 else { return; }
    let active_len = bp.data.len - bp.pending_removal;
    for i in active_len {
        bp.data[i] = bp.data[bp.pending_removal + i];
    }
    while bp.data.len > active_len {
        bp.data.pop();
    }
    bp.pending_removal = 0;
}

// Appends data to the backpressure buffer, performing compaction if pending_removal > 0
fn backpressure_append(bp: BackPressure&, bytes: const u8[:]) -> bool {
    guard bytes.len > 0 else { return true; }

    if bp.data.len + bytes.len > bp.data.cap {
        backpressure_compact(bp);
    }

    guard bp.data.len + bytes.len <= bp.data.cap else {
        bp.drop_count += 1;
        return false;
    }

    bp.data.append(bytes);
    bp.total_buffered += bytes.len as u64;
    return true;
}

// Advances pending removal and amortizes compaction only when pendingRemoval > (data.len >> 5).
// Eliminates O(N^2) memory moves on frequent partial packet sends (Alex Hultman / uWS pattern).
fn backpressure_erase(bp: BackPressure&, n: i64) {
    guard n > 0 else { return; }
    bp.pending_removal += n;
    bp.total_drained += n as u64;

    if bp.pending_removal >= bp.data.len {
        bp.data.clear();
        bp.pending_removal = 0;
    } else if bp.pending_removal > (bp.data.len >> 5) {
        backpressure_compact(bp);
    }
}

// Attempts to drain active backpressure during write. Returns (handled, bytes_written, needs_poll).
fn async_write_drain_existing(
    fd: i64,
    bp: BackPressure&,
    data: const u8[:],
    optionally: bool,
) -> bool, i32, bool {
    guard backpressure_len(bp) > 0 else { return false, 0, false; }
    let sent = tcp_send(fd, backpressure_data(bp));
    if sent > 0 {
        backpressure_erase(bp, sent);
    }
    guard backpressure_len(bp) > 0 else { return false, 0, false; }
    if optionally {
        return true, 0, true;
    }
    backpressure_append(bp, data);
    return true, data.len as i32, true;
}

// Flushes cork buffer during write. If cork cannot be fully sent, spills cork and optional data to backpressure.
fn async_write_spill_cork(
    fd: i64,
    cork: core::CorkBuffer&,
    bp: BackPressure&,
    data: const u8[:],
    optionally: bool,
) -> bool, i32, bool {
    guard core::cork_pending(cork) > 0 else { return false, 0, false; }
    let cork_sent = tcp_send(fd, core::cork_as_slice(cork));
    if cork_sent > 0 {
        core::cork_consume(cork, cork_sent);
    }
    guard core::cork_pending(cork) > 0 else { return false, 0, false; }
    backpressure_append(bp, core::cork_as_slice(cork));
    core::cork_reset(cork);
    if !optionally && data.len > 0 {
        backpressure_append(bp, data);
        return true, data.len as i32, true;
    }
    return true, 0, true;
}

// Writes unsent wire remainder directly to socket or queues to backpressure.
fn async_write_direct(
    fd: i64,
    bp: BackPressure&,
    data: const u8[:],
    optionally: bool,
) -> i32, bool {
    let sent = tcp_send(fd, data);
    guard sent < (data.len as i32) else { return sent, false; }
    if optionally {
        let sent_clamped = if sent > 0 { sent } else { 0 };
        return sent_clamped, true;
    }
    let unsent_offset = if sent > 0 { sent as i64 } else { 0 };
    backpressure_append(bp, data[unsent_offset..]);
    return data.len as i32, true;
}

// Three-level prioritized async write matching uWebSockets AsyncSocket::write:
// 1. If backpressure exists, drain it first.
// 2. If no backpressure and cork fits, buffer directly in CorkBuffer (zero-copy into shared reactor buffer).
// 3. Otherwise flush cork and send directly via syscall. Any unsent remainder spills into BackPressure.
// Returns (bytes_written, needs_writable_poll).
fn async_socket_write(
    fd: i64,
    cork: core::CorkBuffer&,
    bp: BackPressure&,
    data: const u8[:],
    optionally: bool = false,
) -> i32, bool {
    guard fd > 0 else { return 0, false; }
    guard !bp.write_shut && !bp.shutdown_pending else {
        bp.drop_count += 1;
        return 0, false;
    }

    let handled_bp, written_bp, poll_bp = async_write_drain_existing(fd, bp, data, optionally);
    guard !handled_bp else { return written_bp, poll_bp; }

    guard data.len > 0 else { return 0, false; }

    if data.len <= core::cork_available(cork) {
        core::cork_write_exact(cork, data);
        return data.len as i32, false;
    }

    let handled_cork, written_cork, poll_cork = async_write_spill_cork(fd, cork, bp, data, optionally);
    guard !handled_cork else { return written_cork, poll_cork; }

    return async_write_direct(fd, bp, data, optionally);
}

// Spills remaining cork buffer into backpressure.
fn uncork_spill_to_bp(cork: core::CorkBuffer&, bp: BackPressure&) {
    guard core::cork_pending(cork) > 0 else { return; }
    backpressure_append(bp, core::cork_as_slice(cork));
    core::cork_reset(cork);
}

// Directly flushes cork buffer to wire, spilling to backpressure if partially sent.
fn uncork_flush_direct(fd: i64, cork: core::CorkBuffer&, bp: BackPressure&) -> i32, bool {
    guard core::cork_pending(cork) > 0 else { return 0, false; }
    let sent_cork = tcp_send(fd, core::cork_as_slice(cork));
    if sent_cork > 0 {
        core::cork_consume(cork, sent_cork);
    }
    guard core::cork_pending(cork) > 0 else {
        return sent_cork, false;
    }
    backpressure_append(bp, core::cork_as_slice(cork));
    core::cork_reset(cork);
    return sent_cork, true;
}

// Uncorks the socket and flushes cork buffer while strictly preserving FIFO stream order.
// If backpressure is already active, cork data is appended behind backpressure without out-of-order sending.
// Returns (bytes_written, needs_writable_poll).
fn async_socket_uncork(fd: i64, cork: core::CorkBuffer&, bp: BackPressure&) -> i32, bool {
    guard fd > 0 else { return 0, false; }

    var total_sent: i32 = 0;

    // 1. Drain existing backpressure first to maintain strict TCP FIFO stream ordering
    if backpressure_len(bp) > 0 {
        let sent_bp = tcp_send(fd, backpressure_data(bp));
        if sent_bp > 0 {
            backpressure_erase(bp, sent_bp);
            total_sent += sent_bp;
        }
    }

    // 2. If backpressure is still active, append cork to backpressure without sending ahead of it
    if backpressure_len(bp) > 0 {
        uncork_spill_to_bp(cork, bp);
        return total_sent, true;
    }

    // 3. Backpressure is clear; flush cork buffer directly to socket
    let sent_cork, needs_poll = uncork_flush_direct(fd, cork, bp);
    return total_sent + sent_cork, needs_poll;
}

// Executes deferred shutdown if backpressure is clear and shutdown was requested.
// If peer FIN was already received, both directions are terminated; completes full socket teardown (RFC 9293 §3.5).
fn check_execute_deferred_shutdown(fd: i64, bp: BackPressure&) {
    guard bp.shutdown_pending else { return; }
    tcp_shutdown(fd, SHUT_WR);
    bp.write_shut = true;
    bp.shutdown_pending = false;
    if bp.peer_fin_received && fd > 0 {
        tcp_close(fd);
    }
}

// Drains backpressure queue upon writable event (POLL_WRITE).
// If a shutdown was deferred, executes tcp_shutdown(SHUT_WR) once the queue is fully drained.
// If an I/O error occurs (sent < 0), aborts socket and clears backpressure to prevent poll deadlock (RFC 1122 §4.2.2.13).
// Returns (bytes_drained, is_fully_empty).
fn async_socket_drain(fd: i64, bp: BackPressure&) -> i32, bool {
    guard fd > 0 else { return 0, true; }
    let bp_active = backpressure_len(bp);
    guard bp_active > 0 else {
        check_execute_deferred_shutdown(fd, bp);
        return 0, true;
    }

    let sent = tcp_send(fd, backpressure_data(bp));
    if sent < 0 {
        async_socket_abort(fd, bp);
        return sent, true;
    }
    if sent > 0 {
        backpressure_erase(bp, sent);
    }

    let is_empty = backpressure_len(bp) == 0;
    if is_empty {
        check_execute_deferred_shutdown(fd, bp);
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

    if core::cork_pending(cork) > 0 {
        async_socket_uncork(fd, cork, bp);
    }

    guard backpressure_len(bp) == 0 else {
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
    let span, err = core::get_write_span(pipe, min_span);
    if err != core::IoError.None {
        return -1;
    }
    let recvd = native_tcp_recv(fd, span, timeout_ms);
    if recvd > 0 {
        core::commit_write(pipe, recvd);
    }
    return recvd;
}

// Configures socket non-blocking mode.
fn tcp_set_nonblocking(fd: i64, nonblocking: bool = true) -> bool {
    guard fd > 0 else { return false; }
    return native_tcp_set_nonblocking(fd, if nonblocking { 1 } else { 0 }) == 0;
}

// Sets TCP_QUICKACK (Linux delayed ACK bypass) to eliminate 40ms delayed ACK stalls.
fn tcp_set_quickack(fd: i64, enable: bool = true) -> bool {
    guard fd > 0 else { return false; }
    return native_tcp_set_quickack(fd, if enable { 1 } else { 0 }) == 0;
}

// Sets TCP_CORK (Linux) to coalesce frames at the kernel TCP stack level.
fn tcp_set_cork(fd: i64, enable: bool = true) -> bool {
    guard fd > 0 else { return false; }
    return native_tcp_set_cork(fd, if enable { 1 } else { 0 }) == 0;
}

// Accepts an incoming connection in non-blocking mode.
// Returns socket handle (> 0), 0 if no connection pending (EAGAIN), or -1 on error.
fn tcp_accept_nonblocking(listener_fd: i64) -> i64 {
    guard listener_fd > 0 else { return -1; }
    return native_tcp_accept_nonblocking(listener_fd);
}

// Receives bytes from non-blocking socket into out buffer without zeroing memory.
// Returns:
//   > 0 : bytes received
//     0 : peer closed connection cleanly (EOF / FIN)
//    -2 : WouldBlock / EAGAIN (no data ready right now)
//    -1 : socket error / connection reset
fn tcp_recv_nonblocking<B>(fd: i64, out: B&) -> i32 {
    guard fd > 0 else { return -1; }
    let recvd = native_tcp_recv_nonblocking(fd, g_shared_recv_buf[..65536]);
    if recvd > 0 {
        out.append(g_shared_recv_buf[..recvd]);
    }
    return recvd;
}

// Receives bytes from non-blocking socket directly into destination slice.
fn tcp_recv_nonblocking_slice(fd: i64, dst: u8[:]) -> i32 {
    guard fd > 0 && dst.len > 0 else { return -1; }
    return native_tcp_recv_nonblocking(fd, dst);
}

// Creates an epoll/reactor handle (native epoll_create1 on Linux, WSAPoll on Windows).
fn epoll_create() -> i64 {
    tcp_init();
    return native_epoll_create();
}

// Registers a socket descriptor in the epoll multiplexer.
fn epoll_add(epfd: i64, sock_fd: i64, events: u32 = EPOLL_READ, udata: u64 = 0) -> bool {
    guard epfd >= 0 && sock_fd > 0 else { return false; }
    return native_epoll_add(epfd, sock_fd, events, udata) == 0;
}

// Modifies interest flags for a registered socket descriptor.
fn epoll_mod(epfd: i64, sock_fd: i64, events: u32, udata: u64) -> bool {
    guard epfd >= 0 && sock_fd > 0 else { return false; }
    return native_epoll_mod(epfd, sock_fd, events, udata) == 0;
}

// Removes a socket descriptor from the epoll multiplexer.
fn epoll_del(epfd: i64, sock_fd: i64) -> bool {
    guard epfd >= 0 && sock_fd > 0 else { return false; }
    return native_epoll_del(epfd, sock_fd) == 0;
}

// Waits for I/O events on the epoll multiplexer directly into fixed-size slices.
// Avoids allocations, stack memsets, and push overhead (uWebSockets loop.c pattern).
fn epoll_wait_direct(epfd: i64, raw_fds: i64[:], raw_udata: u64[:], timeout_ms: i32 = -1) -> i32 {
    guard epfd >= 0 && (raw_fds.len > 0 || raw_udata.len > 0) else { return 0; }
    return native_epoll_wait(epfd, raw_fds, raw_udata, timeout_ms);
}

// Waits for I/O events on the epoll multiplexer.
// Clears and populates out_fds and out_udata with ready event descriptors and udata tags.
fn epoll_wait<F, U>(epfd: i64, out_fds: F&, out_udata: U&, timeout_ms: i32 = -1) -> i32 {
    guard epfd >= 0 else { return 0; }
    out_fds.clear();
    out_udata.clear();
    var raw_fds: i64[256] = [0; 256];
    var raw_udata: u64[256] = [0; 256];
    let n = native_epoll_wait(epfd, raw_fds[..], raw_udata[..], timeout_ms);
    for i in n {
        out_fds.push(raw_fds[i]);
        out_udata.push(raw_udata[i]);
    }
    return n;
}

// Closes epoll/reactor handle.
fn epoll_close(epfd: i64) {
    if epfd >= 0 {
        native_epoll_close(epfd);
    }
}

// Appends HTTP response directly to cork buffer using AVX2 SIMD instructions and flushes if full.
fn fast_cork_append(conn: i64, cork_buf: u8[:], cork_len: i64, resp: const u8[:]) -> i64 {
    return native_fast_cork_append(conn, cork_buf, cork_len, resp);
}

// Pins calling thread to specific CPU core ID.
fn set_cpu_affinity(cpu_id: i64) -> bool {
    guard cpu_id >= 0 else { return false; }
    return native_set_cpu_affinity(cpu_id) == 0;
}

// Binds listener incoming socket queue to specific CPU core (SO_INCOMING_CPU).
fn tcp_set_incoming_cpu(sock_fd: i64, cpu_id: i64) -> bool {
    guard sock_fd > 0 && cpu_id >= 0 else { return false; }
    return native_tcp_set_incoming_cpu(sock_fd, cpu_id) == 0;
}
