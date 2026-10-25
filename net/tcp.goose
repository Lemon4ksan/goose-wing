// Layer 4 Cross-Platform TCP Socket Engine for goose-wing.
// Zero-allocation, high-performance synchronous & non-blocking socket wrappers
// supporting live OS TCP connections over Windows Winsock2 and POSIX.
namespace wing;

import std;
import core from "..";

// Native C shims (shim/tcp.c)
extern "wing_tcp_init" fn native_tcp_init() -> i32;
extern "wing_tcp_cleanup" fn native_tcp_cleanup();
extern "wing_tcp_listen" fn native_tcp_listen(host: const u8[:], port: u16, backlog: i32) -> i64;
extern "wing_tcp_getsockname_port" fn native_tcp_getsockname_port(sock_fd: i64) -> u16;
extern "wing_tcp_accept" fn native_tcp_accept(listener_fd: i64, timeout_ms: u32) -> i64;
extern "wing_tcp_connect" fn native_tcp_connect(host: const u8[:], port: u16, timeout_ms: u32) -> i64;
extern "wing_tcp_send" fn native_tcp_send(sock_fd: i64, data: const u8[:]) -> i32;
extern "wing_tcp_recv" fn native_tcp_recv(sock_fd: i64, buf: u8[:], timeout_ms: u32) -> i32;
extern "wing_tcp_close" fn native_tcp_close(sock_fd: i64);
extern "wing_tcp_set_defer_accept" fn native_tcp_set_defer_accept(sock_fd: i64, timeout_sec: i32) -> i32;
extern "wing_tcp_set_user_timeout" fn native_tcp_set_user_timeout(sock_fd: i64, timeout_ms: u32) -> i32;
extern "wing_tcp_set_keepalive_params" fn native_tcp_set_keepalive_params(sock_fd: i64, idle_sec: i32, intvl_sec: i32, cnt: i32) -> i32;
extern "wing_tcp_set_syn_retries" fn native_tcp_set_syn_retries(sock_fd: i64, count: i32) -> i32;
extern "wing_tcp_get_notsent_bytes" fn native_tcp_get_notsent_bytes(sock_fd: i64) -> i64;
extern "wing_tcp_get_readable_bytes" fn native_tcp_get_readable_bytes(sock_fd: i64) -> i64;
extern "wing_get_env_port" fn get_env_port(default_port: u16) -> u16;

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

// Receives bytes from TCP socket into a scratch buffer and appends to out.
// Returns:
//   > 0 : bytes received
//     0 : peer closed connection cleanly (EOF / FIN)
//    -2 : read timeout expired
//    -1 : socket error (e.g. connection reset)
fn tcp_recv<B>(fd: i64, out: B&, max_len: i32 = 4096, timeout_ms: u32 = 5000) -> i32 {
    guard fd > 0 else { return -1; }
    var scratch: u8[4096] = [0; 4096];
    let eff_max = if max_len > 4096 { 4096 } else if max_len < 1 { 1 } else { max_len };
    let recvd = native_tcp_recv(fd, scratch[..eff_max], timeout_ms);
    if recvd > 0 {
        out.append(scratch[..recvd]);
    }
    return recvd;
}

// Closes socket handle.
fn tcp_close(fd: i64) {
    if fd > 0 {
        native_tcp_close(fd);
    }
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

// Configures aggressive SO_KEEPALIVE profile.
fn tcp_set_keepalive(fd: i64, idle_sec: i32 = 1, intvl_sec: i32 = 11, cnt: i32 = 3) -> bool {
    guard fd > 0 else { return false; }
    return native_tcp_set_keepalive_params(fd, idle_sec, intvl_sec, cnt) == 0;
}

// Limits SYN retransmissions on connect to abort unreachable hosts quickly.
fn tcp_set_syn_retries(fd: i64, count: i32 = 3) -> bool {
    guard fd > 0 else { return false; }
    return native_tcp_set_syn_retries(fd, count) == 0;
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
