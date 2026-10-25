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
