// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Native C shims (shim/tcp.c) and internal TCP, UDP batch, and transport helpers.
namespace net_internal;

import std;
import core;
import .tcp;
import .transport;
import .udp;

// ---- Native TCP, Epoll, Signal, & UDP C Shims (shim/tcp.c) -----------------

extern fn native_tcp_init() -> i32 = "wing_tcp_init";
extern fn native_tcp_cleanup() = "wing_tcp_cleanup";
extern fn native_tcp_listen(host: const u8[:], port: u16, backlog: i32) -> i64 = "wing_tcp_listen";
extern fn native_tcp_listen_unix(path: const u8[:], backlog: i32) -> i64 = "wing_tcp_listen_unix";
extern fn native_tcp_connect_unix(path: const u8[:]) -> i64 = "wing_tcp_connect_unix";
extern fn native_tcp_connect_unix_begin(path: const u8[:], out_state: i32&) -> i64 = "wing_tcp_connect_unix_begin";
extern fn native_adopt_socket(raw_fd: i64) -> i64 = "wing_adopt_socket";
extern fn native_tcp_getsockname_port(sock_fd: i64) -> u16 = "wing_tcp_getsockname_port";
extern fn native_tcp_get_peer_ip(sock_fd: i64, out_ip: u8[:]) -> i32 = "wing_tcp_get_peer_ip";
extern fn native_tcp_accept(listener_fd: i64, timeout_ms: u32) -> i64 = "wing_tcp_accept";
extern fn native_tcp_connect(host: const u8[:], port: u16, timeout_ms: u32) -> i64 = "wing_tcp_connect";
extern fn native_tcp_connect_ex(
    host:            const u8[:],
    port:            u16,
    timeout_ms:      u32,
    ip_family:       i32,
    local_bind_addr: const u8[:],
) -> i64 = "wing_tcp_connect_ex";
extern fn native_tcp_connect_ip(
    ip:              const u8[:],
    port:            u16,
    timeout_ms:      u32,
    ip_family:       i32,
    local_bind_addr: const u8[:],
) -> i64 = "wing_tcp_connect_ip";
extern fn native_net_resolve_host(host: const u8[:], ip_family: i32, out_buf: u8[:]) -> i32 = "wing_net_resolve_host";
extern fn native_tcp_connect_begin(host: const u8[:], port: u16, out_state: i32&) -> i64 = "wing_tcp_connect_begin";
extern fn native_tcp_connect_finish(sock_fd: i64) -> i32 = "wing_tcp_connect_finish";
extern fn native_tcp_connect_poll(sock_fd: i64) -> i32 = "wing_tcp_connect_poll";
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
extern fn native_tcp_set_keepalive_params(
    sock_fd:   i64,
    idle_sec:  i32,
    intvl_sec: i32,
    cnt:       i32,
) -> i32 = "wing_tcp_set_keepalive_params";
extern fn native_tcp_set_syn_retries(sock_fd: i64, count: i32) -> i32 = "wing_tcp_set_syn_retries";
extern fn native_tcp_get_notsent_bytes(sock_fd: i64) -> i64 = "wing_tcp_get_notsent_bytes";
extern fn native_tcp_get_readable_bytes(sock_fd: i64) -> i64 = "wing_tcp_get_readable_bytes";
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
extern fn native_epoll_wait_events(
    epfd:       i64,
    out_fds:    i64[:],
    out_udata:  u64[:],
    out_events: u32[:],
    timeout_ms: i32,
) -> i32 = "wing_epoll_wait_events";
extern fn native_epoll_close(epfd: i64) = "wing_epoll_close";
extern fn native_set_cpu_affinity(cpu_id: i64) -> i32 = "wing_set_cpu_affinity";
extern fn native_tcp_set_incoming_cpu(sock_fd: i64, cpu_id: i64) -> i32 = "wing_tcp_set_incoming_cpu";
extern fn native_tcp_set_fastopen(sock_fd: i64, qlen: i32) -> i32 = "wing_tcp_set_fastopen";
extern fn native_tcp_send_fastopen(sock_fd: i64, data: const u8[:]) -> i32 = "wing_tcp_send_fastopen";
extern fn native_tcp_set_tos(sock_fd: i64, tos: i32) -> i32 = "wing_tcp_set_tos";
extern fn native_tcp_set_tclass(sock_fd: i64, tclass: i32) -> i32 = "wing_tcp_set_tclass";
extern fn native_install_shutdown_signals() -> i32 = "wing_install_shutdown_signals";
extern fn native_shutdown_requested() -> i32 = "wing_shutdown_requested";
extern fn native_consume_reload_signal() -> i32 = "wing_consume_reload_signal";
extern fn native_tcp_listen_dual(
    host:    const u8[:],
    port:    u16,
    backlog: i32,
    flags:   i32,
) -> i64 = "wing_tcp_listen_dual";
extern fn native_tcp_accept_info(
    listener_fd:     i64,
    mode_flags:      i32,
    out_peer_ip:     u8[:],
    out_peer_ip_len: i32&,
    out_peer_port:   u16&,
    out_dst_ip:      u8[:],
    out_dst_ip_len:  i32&,
    out_dst_port:    u16&,
) -> i64 = "wing_tcp_accept_info";
extern fn native_tcp_connect_bound_begin(
    src_ip:    const u8[:],
    dst_ip:    const u8[:],
    dst_port:  u16,
    so_mark:   u32,
    out_state: i32&,
    out_err:   i32&,
) -> i64 = "wing_tcp_connect_bound_begin";
extern fn native_tcp_connect_opts_begin(
    src_ip:          const u8[:],
    dst_ip:          const u8[:],
    dst_port:        u16,
    so_mark:         u32,
    ttl:             i32,
    mss:             i32,
    rcvbuf:          i32,
    tcp_nodelay:     i32,
    ka_idle:         i32,
    ka_intvl:        i32,
    ka_cnt:          i32,
    user_timeout_ms: u32,
    out_state:       i32&,
    out_err:         i32&,
) -> i64 = "wing_tcp_connect_opts_begin";
extern fn native_tcp_connect_status(sock_fd: i64) -> i32 = "wing_tcp_connect_status";
extern fn native_tcp_recv_peek(sock_fd: i64, dst: u8[:]) -> i32 = "wing_tcp_recv_peek";
extern fn native_tcp_set_ttl(sock_fd: i64, ttl: i32, is_ipv6: i32) -> i32 = "wing_tcp_set_ttl";
extern fn native_tcp_set_mss(sock_fd: i64, mss: i32) -> i32 = "wing_tcp_set_mss";
extern fn native_tcp_set_rcvbuf(sock_fd: i64, bytes: i32) -> i32 = "wing_tcp_set_rcvbuf";
extern fn native_pipe_create(out_read_fd: i64&, out_write_fd: i64&) -> i32 = "wing_pipe_create";
extern fn native_pipe_close(read_fd: i64, write_fd: i64) = "wing_pipe_close";
extern fn native_tcp_splice_chunk(
    src_fd:        i64,
    dst_fd:        i64,
    pipe_r:        i64,
    pipe_w:        i64,
    max_bytes:     i64,
    in_pipe_bytes: i64&,
) -> i64 = "wing_tcp_splice_chunk";
extern fn native_net_get_local_ips(out_buf: u8[:]) -> i32 = "wing_net_get_local_ips";
extern fn native_udp_open_dual(bind_ip: const u8[:], bind_port: u16, flags: i32) -> i64 = "wing_udp_open_dual";
extern fn native_udp_sendto_dual(
    sock_fd:  i64,
    data:     const u8[:],
    dst_ip:   const u8[:],
    dst_port: u16,
) -> i32 = "wing_udp_sendto_dual";
extern fn native_udp_recvfrom_dual(
    sock_fd:         i64,
    out_buf:         u8[:],
    out_peer_ip:     u8[:],
    out_peer_ip_len: i32&,
    out_peer_port:   u16&,
) -> i32 = "wing_udp_recvfrom_dual";
extern fn native_udp_exchange_dual(
    server_ip:   const u8[:],
    server_port: u16,
    query:       const u8[:],
    out_resp:    u8[:],
    timeout_ms:  u32,
) -> i32 = "wing_udp_exchange_dual";
extern fn native_fs_disk_usage_percent(path: const u8[:]) -> i32 = "wing_fs_disk_usage_percent";
extern fn native_fs_file_mtime(path: const u8[:]) -> i64 = "wing_fs_file_mtime";

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
extern fn native_udp_sendmmsg(
    sock_fd:  i64,
    payloads: const u8[:],
    lengths:  const i32[:],
    ips:      const u32[:],
    ports:    const u16[:],
    count:    i32,
) -> i32 = "wing_udp_sendmmsg";
extern fn native_udp_recvmmsg(
    sock_fd:    i64,
    payloads:   u8[:],
    lengths:    i32[:],
    ips:        u32[:],
    ports:      u16[:],
    max_count:  i32,
    timeout_ms: u32,
) -> i32 = "wing_udp_recvmmsg";

var g_tcp_initialized: bool = false;

// ---- Shared IPv4 Literal Parser (SOCKS5 & PROXY Protocol) ------------------

// Parses a strict dotted-decimal IPv4 literal (no leading zeros) into 4 network-order octets.
//
// Example:
//   raw = "127.0.0.1"
//   returns: [127, 0, 0, 1], true
fn parse_ipv4_literal(raw: const u8[:]) -> u8[4], bool {
    var out: u8[4] = [0; 4];
    var rest = raw;
    for i in 4 {
        let part, rem, has_dot = rest.split_once_byte('.');
        if i < 3 {
            guard has_dot else { return out, false; }
        } else {
            guard !has_dot else { return out, false; }
        }
        guard part.len >= 1 && (part.len == 1 || part[0] != '0') else { return out, false; }
        let val, ok_v = part.parse_u32_dec();
        guard ok_v && val <= 255 else { return out, false; }
        out[i] = val as u8;
        rest = rem;
    }
    return out, true;
}

// ---- TCP & Async BackPressure Helpers --------------------------------------

inline fn ip_family_to_native_i32(fam: net::IpFamily) -> i32 {
    return match fam {
        Auto => 0,
        Ipv4Only => 1,
        Ipv6Only => 2,
    };
}

fn tcp_connect_unix_begin(path: const u8[:], out_state: i32&) -> i64 {
    guard path.len > 0 && path.len < 108 else {
        out_state = -1;
        return -1;
    }
    net::tcp_init();
    return native_tcp_connect_unix_begin(path, out_state);
}

fn tcp_connect_finish(fd: i64) -> bool {
    guard fd > 0 else { return false; }
    return native_tcp_connect_finish(fd) == 0;
}

fn tcp_sendv_one(fd: i64, arr: core::IoVecArray&) -> i32 {
    let chunk = arr.iovec_get(0);
    let sent = net::tcp_send(fd, chunk);
    if sent > 0 {
        arr.iovec_consume(sent);
    }
    return sent;
}

fn tcp_sendv_two(fd: i64, arr: core::IoVecArray&) -> i32 {
    let c0 = arr.iovec_get(0);
    let c1 = arr.iovec_get(1);
    let sent = net::tcp_send2(fd, c0, c1);
    if sent > 0 {
        arr.iovec_consume(sent);
    }
    return sent;
}

fn tcp_sendv_multi(fd: i64, arr: core::IoVecArray&) -> i32 {
    var total_sent: i64 = 0;
    while !arr.iovec_is_empty() {
        let c = arr.iovec_get(0);
        let sent = net::tcp_send(fd, c);
        guard sent > 0 else {
            return if total_sent > 0 { total_sent as i32 } else { sent };
        }
        arr.iovec_consume(sent);
        total_sent = core::add_sat_i64(total_sent, sent);
    }
    return total_sent as i32;
}

inline fn ensure_shared_buf_len(buf: u8[..65536]&, eff_max: i32) {
    if (buf.len as i32) < eff_max {
        buf.resize(eff_max as i64, 0);
    }
}

fn backpressure_data(bp: const net::BackPressure&) -> const u8[:] {
    guard bp.pending_removal < bp.data.len else { return ""; }
    return bp.data[bp.pending_removal..];
}

fn backpressure_compact(bp: net::BackPressure&) {
    guard bp.pending_removal > 0 else { return; }
    bp.data.compact_wire_buffer(bp.pending_removal);
    bp.pending_removal = 0;
}

fn backpressure_erase(bp: net::BackPressure&, n: i64) {
    guard n > 0 else { return; }
    bp.pending_removal = core::add_sat_i64(bp.pending_removal, n);
    bp.total_drained = core::add_sat_u64(bp.total_drained, n as u64);

    if bp.pending_removal >= bp.data.len {
        bp.data.clear();
        bp.pending_removal = 0;
    } else if bp.pending_removal > (bp.data.len >> 5) {
        backpressure_compact(bp);
    }
}

// Attempts to drain active backpressure during write. Returns (bytes_written, needs_poll, handled).
fn async_write_drain_existing(
    fd:         i64,
    bp:         net::BackPressure&,
    data:       const u8[:],
    optionally: bool,
) -> i32, bool, bool {
    guard net::backpressure_len(bp) > 0 else { return 0, false, false; }
    let sent = net::tcp_send(fd, backpressure_data(bp));
    if sent < 0 {
        return -1, false, true;
    }
    if sent > 0 {
        backpressure_erase(bp, sent);
    }
    guard net::backpressure_len(bp) > 0 else { return 0, false, false; }
    if optionally {
        return 0, true, true;
    }
    guard net::backpressure_append(bp, data) else {
        return 0, true, true;
    }
    return data.len as i32, true, true;
}

// Flushes cork buffer during write. Returns (bytes_written, needs_poll, handled).
fn async_write_spill_cork(
    fd:         i64,
    cork:       core::CorkBuffer&,
    bp:         net::BackPressure&,
    data:       const u8[:],
    optionally: bool,
) -> i32, bool, bool {
    guard cork.cork_pending() > 0 else { return 0, false, false; }
    let cork_sent = net::tcp_send(fd, cork.cork_as_slice());
    if cork_sent < 0 {
        return -1, false, true;
    }
    if cork_sent > 0 {
        cork.cork_consume(cork_sent);
    }
    guard cork.cork_pending() > 0 else { return 0, false, false; }
    guard net::backpressure_append(bp, cork.cork_as_slice()) else {
        return 0, true, true;
    }
    cork.cork_reset();
    if !optionally && data.len > 0 {
        guard net::backpressure_append(bp, data) else {
            return 0, true, true;
        }
        return data.len as i32, true, true;
    }
    return 0, true, true;
}

fn async_write_direct(
    fd:         i64,
    bp:         net::BackPressure&,
    data:       const u8[:],
    optionally: bool,
) -> i32, bool {
    let sent = net::tcp_send(fd, data);
    if sent < 0 {
        return -1, false;
    }
    guard sent < (data.len as i32) else { return sent, false; }
    let sent_clamped = max(sent, 0);
    if optionally {
        return sent_clamped, true;
    }
    let unsent_offset = sent_clamped as i64;
    guard net::backpressure_append(bp, data[unsent_offset..]) else {
        return sent_clamped, true;
    }
    return data.len as i32, true;
}

fn uncork_flush_direct(fd: i64, cork: core::CorkBuffer&, bp: net::BackPressure&) -> i32, bool {
    guard cork.cork_pending() > 0 else { return 0, false; }
    let sent_cork = net::tcp_send(fd, cork.cork_as_slice());
    if sent_cork > 0 {
        cork.cork_consume(sent_cork);
    }
    guard cork.cork_pending() > 0 else {
        return sent_cork, false;
    }
    if net::backpressure_append(bp, cork.cork_as_slice()) {
        cork.cork_reset();
    }
    return sent_cork, true;
}

fn check_execute_deferred_shutdown(fd: i64, bp: net::BackPressure&) {
    guard bp.shutdown_pending else { return; }
    net::tcp_shutdown(fd, net::SHUT_WR);
    bp.write_shut = true;
    bp.shutdown_pending = false;
    if bp.peer_fin_received && fd > 0 {
        net::tcp_close(fd);
    }
}

fn epoll_wait_direct(epfd: i64, raw_fds: i64[:], raw_udata: u64[:], timeout_ms: i32 = -1) -> i32 {
    guard epfd >= 0 && (raw_fds.len > 0 || raw_udata.len > 0) else { return 0; }
    return native_epoll_wait(epfd, raw_fds, raw_udata, timeout_ms);
}

fn epoll_wait_events_direct(
    epfd:       i64,
    raw_fds:    i64[:],
    raw_udata:  u64[:],
    raw_events: u32[:],
    timeout_ms: i32 = -1,
) -> i32 {
    guard epfd >= 0 && raw_udata.len > 0 && raw_events.len > 0 else { return 0; }
    return native_epoll_wait_events(epfd, raw_fds, raw_udata, raw_events, timeout_ms);
}

// Spills remaining cork buffer into backpressure.
fn uncork_spill_to_bp(cork: core::CorkBuffer&, bp: net::BackPressure&) {
    guard cork.cork_pending() > 0 else { return; }
    if net::backpressure_append(bp, cork.cork_as_slice()) {
        cork.cork_reset();
    }
}

inline fn tunnel_slot_to_fd(slot_idx: i64) -> i64 {
    return net::TUNNEL_FD_TAG | (slot_idx & 0xFFFF);
}

// ---- Batched UDP Helpers ---------------------------------------------------

inline fn shift_unsent_messages(queue: net::UdpBatchQueue&, sent_count: i32, count: i32) {
    let remaining = core::sub_sat_i64(count, sent_count);
    let sent_i64 = sent_count as i64;
    for i in remaining {
        queue.msgs[i] = queue.msgs[core::add_sat_i64(sent_i64, i)];
    }
    while queue.msgs.len > remaining {
        queue.msgs.pop();
    }
    queue.count = remaining as i32;
}

inline fn record_batch_sent_stats(queue: net::UdpBatchQueue&, sent_count: i32) {
    queue.flushed_batches = core::add_sat_u64(queue.flushed_batches, 1);
    queue.total_sent = core::add_sat_u64(queue.total_sent, sent_count as u64);
    let count = queue.msgs.len as i32;
    if sent_count >= count {
        queue.msgs.clear();
        queue.count = 0;
    } else if sent_count > 0 {
        shift_unsent_messages(queue, sent_count, count);
    }
}

inline fn record_batch_recv_stats(queue: net::UdpBatchQueue&, recv_count: i32) {
    queue.total_recvd = core::add_sat_u64(queue.total_recvd, recv_count as u64);
    queue.count = recv_count;
}

inline fn copy_datagram_to_arena(
    dgram:   const net::UdpDatagram&,
    slot:    i64,
    arena:   u8[47104]&,
    lengths: i32[32]&,
    ips:     u32[32]&,
    ports:   u16[32]&,
) {
    let base_off = core::mul_sat_u64(slot as u64, net::UDP_MAX_PAYLOAD_LEN as u64) as i64;
    let plen = dgram.payload.len;
    lengths[slot] = plen as i32;
    ips[slot] = dgram.peer_ip4;
    ports[slot] = dgram.peer_port;
    for b_idx in plen {
        arena[core::add_sat_i64(base_off, b_idx)] = dgram.payload[b_idx];
    }
}

inline fn unpack_arena_to_datagram(
    slot:    i64,
    arena:   const u8[:],
    pkt_len: i32,
    ip4:     u32,
    port:    u16,
) -> net::UdpDatagram, bool {
    let base_off = core::mul_sat_u64(slot as u64, net::UDP_MAX_PAYLOAD_LEN as u64) as i64;
    let safe_len = min(net::UDP_MAX_PAYLOAD_LEN, max(0, pkt_len as i64));
    let end_off = core::add_sat_i64(base_off, safe_len);
    guard end_off <= arena.len else {
        return net::UdpDatagram { .. }, false;
    }
    var dgram = net::UdpDatagram {
        peer_ip4:  ip4,
        peer_port: port,
        gso_size:  0,
        ..
    };
    let slice = arena[base_off..end_off];
    guard dgram.payload.try_append(slice) else {
        return net::UdpDatagram { .. }, false;
    }
    return dgram, true;
}
