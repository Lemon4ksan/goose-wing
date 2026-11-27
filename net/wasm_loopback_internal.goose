// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Pure-Goose in-memory loopback virtual sockets and epoll multiplexer for WebAssembly.
// Lazily allocates a 512 KB shared ring slab on first use so native Windows/Linux builds
// incur zero static BSS overhead.
namespace net_internal;

import std;
import core;

const WASM_MAX_SOCKETS:   i64 = 32;
const WASM_SOCK_BUF_SIZE: i64 = 16384;
const WASM_MAX_EPOLLS:    i64 = 8;
const WASM_MAX_EPOLL_FDS: i64 = 32;
const WASM_EPOLL_READ:    u32 = 1;
const WASM_EPOLL_WRITE:   u32 = 4;

var g_is_wasm_target: bool = false;

struct WasmSocket {
    active:        bool     = false,
    is_listener:   bool     = false,
    nonblocking:   bool     = false,
    backlog:       i32      = 16,
    port:          u16      = 0,
    host:          u8[..64] = [],
    rx_head:       i64      = 0,
    rx_tail:       i64      = 0,
    peer_slot:     i64      = -1,
    write_shut:    bool     = false,
    pending_conns: i64[16]  = [0; 16],
    pending_head:  i64      = 0,
    pending_tail:  i64      = 0,
}

struct WasmEpollSlot {
    active: bool    = false,
    fds:    i64[32] = [0; 32],
    events: u32[32] = [0; 32],
    udata:  u64[32] = [0; 32],
    count:  i64     = 0,
}

struct WasmSocketTable {
    sockets:             WasmSocket[32]   = [WasmSocket { .. }; 32],
    epolls:              WasmEpollSlot[8] = [WasmEpollSlot { .. }; 8],
    next_ephemeral_port: u16              = 49152,
}

var g_wasm_table:   WasmSocketTable = WasmSocketTable { .. };
var g_wasm_rx_slab: u8[>..]         = [];

inline fn wasm_ensure_slab() {
    let want_bytes = WASM_MAX_SOCKETS * WASM_SOCK_BUF_SIZE;
    while g_wasm_rx_slab.len < want_bytes {
        g_wasm_rx_slab.push(0);
    }
}

inline fn wasm_next_port() -> u16 {
    let p = g_wasm_table.next_ephemeral_port;
    g_wasm_table.next_ephemeral_port = if p >= 65000 { 49152 } else { p + 1 };
    return p;
}

inline fn wasm_slot_valid(fd: i64) -> bool {
    return fd > 0 && fd < WASM_MAX_SOCKETS && g_wasm_table.sockets[fd].active;
}

inline fn wasm_alloc_slot() -> i64 {
    for i in 1..WASM_MAX_SOCKETS {
        if !g_wasm_table.sockets[i].active {
            return i;
        }
    }
    return -1;
}

// Opens a virtual loopback TCP listener on `host:port` (assigns ephemeral port if `port == 0`).
fn wasm_tcp_listen(host: const u8[:], port: u16, backlog: i32) -> i64 {
    guard host.len <= 64 else { return -1; }
    wasm_ensure_slab();
    let slot = wasm_alloc_slot();
    guard slot > 0 else { return -1; }
    var host_buf: u8[..64] = [];
    guard host_buf.try_set(host) else { return -1; }
    let eff_port = if port == 0 { wasm_next_port() } else { port };
    let eff_backlog = if backlog > 0 && backlog <= 16 { backlog } else { 16 };
    g_wasm_table.sockets[slot] = WasmSocket {
        active:      true,
        is_listener: true,
        backlog:     eff_backlog,
        port:        eff_port,
        host:        host_buf,
        ..
    };
    return slot;
}

// Accepts a queued loopback connection from listener `listener_fd` (`0` if queue is empty).
fn wasm_tcp_accept(listener_fd: i64) -> i64 {
    guard wasm_slot_valid(listener_fd) && g_wasm_table.sockets[listener_fd].is_listener else {
        return -1;
    }
    let lis .= g_wasm_table.sockets[listener_fd];
    guard lis.pending_head < lis.pending_tail else { return 0; }
    let idx = lis.pending_head % 16;
    let server_fd = lis.pending_conns[idx];
    lis.pending_head += 1;
    return server_fd;
}

fn wasm_find_listener_by_port(port: u16) -> i64 {
    for i in 1..WASM_MAX_SOCKETS {
        let s .= g_wasm_table.sockets[i];
        if s.active && s.is_listener && s.port == port {
            return i;
        }
    }
    return -1;
}

fn wasm_find_pair_slots() -> i64, i64 {
    var c_slot: i64 = -1;
    var s_slot: i64 = -1;
    for i in 1..WASM_MAX_SOCKETS {
        if !g_wasm_table.sockets[i].active {
            if c_slot < 0 {
                c_slot = i;
            } else {
                s_slot = i;
                break;
            }
        }
    }
    return c_slot, s_slot;
}

// Connects to an active WASM loopback listener on `host:port`, rejecting saturated backlogs.
fn wasm_tcp_connect(host: const u8[:], port: u16) -> i64 {
    guard host.len <= 64 else { return -1; }
    wasm_ensure_slab();
    let lis_idx = wasm_find_listener_by_port(port);
    guard lis_idx > 0 else { return -1; }
    let lis .= g_wasm_table.sockets[lis_idx];
    let pending = lis.pending_tail - lis.pending_head;
    guard pending < lis.backlog && pending < 16 else { return -1; }

    let c_slot, s_slot = wasm_find_pair_slots();
    guard c_slot > 0 && s_slot > 0 else { return -1; }
    var host_buf: u8[..64] = [];
    guard host_buf.try_set(host) else { return -1; }

    g_wasm_table.sockets[c_slot] = WasmSocket {
        active:    true,
        port:      wasm_next_port(),
        host:      host_buf,
        peer_slot: s_slot,
        ..
    };
    g_wasm_table.sockets[s_slot] = WasmSocket {
        active:    true,
        port:      port,
        host:      host_buf,
        peer_slot: c_slot,
        ..
    };
    let q_idx = lis.pending_tail % 16;
    lis.pending_conns[q_idx] = s_slot;
    lis.pending_tail += 1;
    return c_slot;
}

// Writes `data` into the peer socket's 16 KB loopback ring (`-2` if full, `-1` if disconnected).
fn wasm_tcp_send(fd: i64, data: const u8[:]) -> i32 {
    guard wasm_slot_valid(fd) && data.len > 0 else { return 0; }
    let s .= g_wasm_table.sockets[fd];
    guard !s.write_shut else { return -1; }
    let peer = s.peer_slot;
    guard wasm_slot_valid(peer) else { return -1; }

    let p .= g_wasm_table.sockets[peer];
    let used = p.rx_tail - p.rx_head;
    let avail = WASM_SOCK_BUF_SIZE - used;
    guard avail > 0 else { return -2; }

    let to_write = min(data.len, avail);
    let base = peer * WASM_SOCK_BUF_SIZE;
    for i in to_write {
        let ring_off = (p.rx_tail + i) % WASM_SOCK_BUF_SIZE;
        g_wasm_rx_slab[base + ring_off] = data[i];
    }
    p.rx_tail += to_write;
    return to_write as i32;
}

// Receives (or peeks) bytes from virtual socket `fd`'s RX ring (`0` on EOF, `-2` on WouldBlock).
fn wasm_tcp_recv(fd: i64, dst: u8[:], peek: bool) -> i32 {
    guard wasm_slot_valid(fd) && dst.len > 0 else { return -1; }
    let s .= g_wasm_table.sockets[fd];
    let readable = s.rx_tail - s.rx_head;
    if readable <= 0 {
        let peer_shut = s.peer_slot > 0 && s.peer_slot < WASM_MAX_SOCKETS &&
            g_wasm_table.sockets[s.peer_slot].write_shut;
        if s.peer_slot < 0 || peer_shut {
            return 0;
        }
        return -2;
    }
    let to_read = min(dst.len, readable);
    let base = fd * WASM_SOCK_BUF_SIZE;
    for i in to_read {
        let ring_off = (s.rx_head + i) % WASM_SOCK_BUF_SIZE;
        dst[i] = g_wasm_rx_slab[base + ring_off];
    }
    if !peek {
        s.rx_head += to_read;
        if s.rx_head == s.rx_tail {
            s.rx_head = 0;
            s.rx_tail = 0;
        } else if s.rx_head >= WASM_SOCK_BUF_SIZE {
            s.rx_head = s.rx_head % WASM_SOCK_BUF_SIZE;
            s.rx_tail = s.rx_tail % WASM_SOCK_BUF_SIZE;
            if s.rx_tail < s.rx_head {
                s.rx_tail += WASM_SOCK_BUF_SIZE;
            }
        }
    }
    return to_read as i32;
}

fn wasm_drain_listener_pending(fd: i64) {
    guard g_wasm_table.sockets[fd].is_listener else { return; }
    while g_wasm_table.sockets[fd].pending_head < g_wasm_table.sockets[fd].pending_tail {
        let q_idx = g_wasm_table.sockets[fd].pending_head % 16;
        let srv_fd = g_wasm_table.sockets[fd].pending_conns[q_idx];
        g_wasm_table.sockets[fd].pending_head += 1;
        if wasm_slot_valid(srv_fd) {
            let c_peer = g_wasm_table.sockets[srv_fd].peer_slot;
            if wasm_slot_valid(c_peer) {
                g_wasm_table.sockets[c_peer].peer_slot = -1;
            }
            g_wasm_table.sockets[srv_fd] = WasmSocket { .. };
        }
    }
}

// Closes a virtual WASM socket, draining queued unaccepted children if it is a listener.
fn wasm_tcp_close(fd: i64) {
    guard wasm_slot_valid(fd) else { return; }
    wasm_drain_listener_pending(fd);
    let peer = g_wasm_table.sockets[fd].peer_slot;
    if wasm_slot_valid(peer) {
        g_wasm_table.sockets[peer].peer_slot = -1;
    }
    g_wasm_table.sockets[fd] = WasmSocket { .. };
}

inline fn wasm_tcp_shutdown(fd: i64, how: i32) -> bool {
    guard wasm_slot_valid(fd) else { return false; }
    if how == 1 || how == 2 {
        g_wasm_table.sockets[fd].write_shut = true;
    }
    return true;
}

inline fn wasm_tcp_getsockname_port(fd: i64) -> u16 {
    guard wasm_slot_valid(fd) else { return 0; }
    return g_wasm_table.sockets[fd].port;
}

inline fn wasm_tcp_get_readable_bytes(fd: i64) -> i64 {
    guard wasm_slot_valid(fd) else { return 0; }
    let s .= g_wasm_table.sockets[fd];
    return max(0, s.rx_tail - s.rx_head);
}

inline fn wasm_tcp_set_nonblocking(fd: i64, nonblocking: bool) -> bool {
    guard wasm_slot_valid(fd) else { return false; }
    g_wasm_table.sockets[fd].nonblocking = nonblocking;
    return true;
}

fn wasm_epoll_create() -> i64 {
    for i in WASM_MAX_EPOLLS {
        if !g_wasm_table.epolls[i].active {
            g_wasm_table.epolls[i] = WasmEpollSlot { active: true, .. };
            return i + 1;
        }
    }
    return -1;
}

fn wasm_epoll_add(epfd: i64, sock_fd: i64, events: u32, udata: u64) -> bool {
    let idx = epfd - 1;
    guard idx >= 0 && idx < WASM_MAX_EPOLLS && g_wasm_table.epolls[idx].active && sock_fd > 0 else {
        return false;
    }
    let ep .= g_wasm_table.epolls[idx];
    for i in ep.count {
        if ep.fds[i] == sock_fd {
            ep.events[i] = events;
            ep.udata[i] = udata;
            return true;
        }
    }
    guard ep.count < WASM_MAX_EPOLL_FDS else { return false; }
    ep.fds[ep.count] = sock_fd;
    ep.events[ep.count] = events;
    ep.udata[ep.count] = udata;
    ep.count += 1;
    return true;
}

fn wasm_epoll_mod(epfd: i64, sock_fd: i64, events: u32, udata: u64) -> bool {
    let idx = epfd - 1;
    guard idx >= 0 && idx < WASM_MAX_EPOLLS && g_wasm_table.epolls[idx].active && sock_fd > 0 else {
        return false;
    }
    let ep .= g_wasm_table.epolls[idx];
    for i in ep.count {
        if ep.fds[i] == sock_fd {
            ep.events[i] = events;
            ep.udata[i] = udata;
            return true;
        }
    }
    return false;
}

fn wasm_epoll_del(epfd: i64, sock_fd: i64) -> bool {
    let idx = epfd - 1;
    guard idx >= 0 && idx < WASM_MAX_EPOLLS && g_wasm_table.epolls[idx].active && sock_fd > 0 else {
        return false;
    }
    let ep .= g_wasm_table.epolls[idx];
    for i in ep.count {
        if ep.fds[i] == sock_fd {
            let last = ep.count - 1;
            ep.fds[i] = ep.fds[last];
            ep.events[i] = ep.events[last];
            ep.udata[i] = ep.udata[last];
            ep.count = last;
            return true;
        }
    }
    return false;
}

inline fn wasm_socket_ready_mask(fd: i64, interest: u32) -> u32 {
    guard wasm_slot_valid(fd) else { return 0; }
    let s .= g_wasm_table.sockets[fd];
    var ready: u32 = 0;
    if (interest & WASM_EPOLL_READ) != 0 {
        if s.is_listener && s.pending_head < s.pending_tail {
            ready |= 1;
        } else if !s.is_listener && ((s.rx_tail - s.rx_head) > 0 || s.peer_slot < 0) {
            ready |= 1;
        }
    }
    if (interest & WASM_EPOLL_WRITE) != 0 && !s.is_listener && wasm_slot_valid(s.peer_slot) {
        let p .= g_wasm_table.sockets[s.peer_slot];
        if (p.rx_tail - p.rx_head) < WASM_SOCK_BUF_SIZE {
            ready |= 2;
        }
    }
    return ready;
}

// Polls readiness events from registered WASM loopback sockets without blocking.
fn wasm_epoll_wait(
    epfd:       i64,
    out_fds:    i64[:],
    out_udata:  u64[:],
    out_events: u32[:],
) -> i32 {
    let idx = epfd - 1;
    guard idx >= 0 && idx < WASM_MAX_EPOLLS && g_wasm_table.epolls[idx].active else { return 0; }
    guard out_udata.len > 0 else { return 0; }
    let ep .= g_wasm_table.epolls[idx];
    var cap = out_udata.len;
    if out_events.len > 0 {
        cap = min(cap, out_events.len);
    }
    var ready_n: i64 = 0;
    for i in ep.count {
        if ready_n >= cap { break; }
        let mask = wasm_socket_ready_mask(ep.fds[i], ep.events[i]);
        guard mask != 0 else { continue; }
        if ready_n < out_fds.len {
            out_fds[ready_n] = ep.fds[i];
        }
        out_udata[ready_n] = ep.udata[i];
        if ready_n < out_events.len {
            out_events[ready_n] = mask;
        }
        ready_n += 1;
    }
    return ready_n as i32;
}

inline fn wasm_epoll_close(epfd: i64) {
    let idx = epfd - 1;
    guard idx >= 0 && idx < WASM_MAX_EPOLLS else { return; }
    g_wasm_table.epolls[idx] = WasmEpollSlot { .. };
}
