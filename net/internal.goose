// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal FFI bindings and package-private helpers for package `net`.
namespace net_internal;

import std;
import core;
import dns.svcb;
import cookie.psl;
import .driver;
import .want_queue;
import .slowloris;
import .proxy;
import .socks5;
import .http_connect;
import .tcp;
import .transport;
import .udp;
import .pool;
import .upstream_pool;
import .happy_eyeballs;
import .retry;
import .masque;
import .accel;
import .poller;

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

// ---- WantQueue Helpers -----------------------------------------------------

inline fn compact_want_queue(q: net::WantQueue&) {
    var new_head: net::WantConn[..32] = [];
    if q.head_pos < q.head.len {
        for &item in q.head[q.head_pos..] {
            if !item.cancelled {
                new_head.push(copy(item));
            }
        }
    }
    var new_tail: net::WantConn[..32] = [];
    for &t_item in q.tail {
        if !t_item.cancelled {
            if new_head.len < 32 {
                new_head.push(copy(t_item));
            } else {
                new_tail.push(copy(t_item));
            }
        }
    }
    q.head = new_head;
    q.head_pos = 0;
    q.tail = new_tail;
}

// ---- Slowloris Helpers -----------------------------------------------------

fn check_slowloris_deadlines(reader: net::HeaderReader&, elapsed_ns: i64) -> net::SlowlorisViolation {
    if elapsed_ns >= reader.config.response_header_timeout_ns {
        reader.poison_connection = true;
        return net::SlowlorisViolation.HeaderTimeoutExpired;
    }
    return net::SlowlorisViolation.None;
}

inline fn detect_header_end_across_chunks(reader: net::HeaderReader&, chunk: const u8[:]) -> bool {
    if core::find(chunk, "\r\n\r\n") >= 0 {
        return true;
    }
    var window: u8[..6] = [];
    window.append(reader.tail_bytes[..]);
    let take_head = min(chunk.len, 3);
    if take_head > 0 {
        window.append(chunk[..take_head]);
    }
    if core::find(window[..], "\r\n\r\n") >= 0 {
        return true;
    }
    var combined: u8[..6] = [];
    combined.append(reader.tail_bytes[..]);
    if chunk.len >= 3 {
        let _ = combined.try_set(chunk[^3..]);
    } else if chunk.len > 0 {
        combined.append(chunk);
    }
    let keep = min(combined.len, 3);
    if keep > 0 {
        let _ = reader.tail_bytes.try_set(combined[^keep..]);
    } else {
        reader.tail_bytes.clear();
    }
    return false;
}

// ---- HTTP CONNECT Helpers --------------------------------------------------

inline fn has_crlf_or_null(s: const u8[:]) -> bool {
    for b in s {
        if b == '\r' || b == '\n' || b == 0 {
            return true;
        }
    }
    return false;
}

inline fn is_valid_connect_host(host: const u8[:]) -> bool {
    return host.len > 0 && !has_crlf_or_null(host) && !host.contains_byte(' ') && !host.contains_byte('\t');
}

fn append_connect_line(out: u8[..1024]&, host: const u8[:], port: u16) {
    if is_valid_connect_host(host) {
        format(out, "CONNECT ", host, ":", port, " HTTP/1.1\r\n");
        format(out, "Host: ", host, ":", port, "\r\n");
    }
}

fn append_sanitized_header(out: u8[..1024]&, prefix: const u8[:], val: const u8[:]) {
    if val.len > 0 && !has_crlf_or_null(val) {
        out.append(prefix);
        out.append(val);
        out.append("\r\n");
    }
}

fn is_token_in_connection_headers(headers: const http::HeaderMap&, target_name: const u8[:]) -> bool {
    for idx in 0..headers.entries.len {
        let e = headers.entries[idx];
        guard http::entry_name(headers, e).eq_ascii_fold("connection") else { continue; }
        var rest: const u8[:] = http::entry_value(headers, e);
        while rest.len > 0 {
            let token_raw, remaining, has_comma = rest.split_once_byte(',');
            let token = token_raw.trim_lws();
            if token.len > 0 && token.eq_ascii_fold(target_name) {
                return true;
            }
            if !has_comma { break; }
            rest = remaining;
        }
    }
    return false;
}

inline fn is_valid_connect_reason_phrase(reason: const u8[:]) -> bool {
    for b in reason {
        let valid = (b >= 0x20 || b == '\t') && b != 0x7F;
        guard valid else { return false; }
    }
    return true;
}

// Parses a single HTTP/1.x status-line + header block from `buf` for CONNECT (RFC 9112 Section 4).
//
// Example:
//   buf = "HTTP/1.1 200 OK\r\n\r\n"
//   returns: status_code = 200, block_end = 19, err = net::ConnectTunnelError.None
fn parse_connect_response_block(buf: const u8[:]) -> i32, i64, net::ConnectTunnelError {
    guard buf.len >= 12 else { return 0, 0, net::ConnectTunnelError.InvalidStatusLine; }
    guard buf.starts_with("HTTP/1.") else { return 0, 0, net::ConnectTunnelError.InvalidStatusLine; }

    let delim_idx = find(buf, "\r\n\r\n");
    guard delim_idx >= 0 else { return 0, 0, net::ConnectTunnelError.MalformedHeaders; }
    let header_end_pos = core::add_sat_i64(delim_idx, 4);

    let first_crlf = find(buf[..header_end_pos], "\r\n");
    guard first_crlf >= 12 else { return 0, 0, net::ConnectTunnelError.MalformedHeaders; }

    let minor_ver = buf[7];
    guard (minor_ver == '0' || minor_ver == '1') && buf[8] == ' ' else {
        return 0, 0, net::ConnectTunnelError.InvalidStatusLine;
    }

    let d0 = buf[9];
    let d1 = buf[10];
    let d2 = buf[11];
    guard core::is_ascii_digit(d0) && core::is_ascii_digit(d1) && core::is_ascii_digit(d2) else {
        return 0, 0, net::ConnectTunnelError.InvalidStatusLine;
    }
    // RFC 9112 Section 4: Status Line - 3-digit status-code MUST be followed by a single SP
    guard first_crlf >= 13 && buf[12] == ' ' && is_valid_connect_reason_phrase(buf[13..first_crlf]) else {
        return 0, 0, net::ConnectTunnelError.InvalidStatusLine;
    }

    let code, ok_code = buf[9..12].parse_i32_dec();
    guard ok_code else { return 0, 0, net::ConnectTunnelError.InvalidStatusLine; }
    return code, header_end_pos, net::ConnectTunnelError.None;
}

fn has_final_connect_header_terminator(buf: const u8[:]) -> bool {
    var cur = buf;
    for _ in 5 {
        let delim = find(cur, "\r\n\r\n");
        guard delim >= 0 else { return false; }
        let block_end = core::add_sat_i64(delim, 4);
        if cur.len >= 13 && cur.starts_with("HTTP/1.") && cur[9] == '1' && !(cur[10] == '0' && cur[11] == '1') {
            cur = cur[block_end..];
            continue;
        }
        return true;
    }
    return true;
}

// ---- SOCKS5 Helpers --------------------------------------------------------

fn socks5_needed_length(buf: const u8[:], atyp: u8) -> i64, net::Socks5Error {
    if buf[2] != 0 {
        return 0, net::Socks5Error.InvalidReplyHeader;
    }
    if atyp != rfc::SOCKS5_ATYP_IPV4 && atyp != rfc::SOCKS5_ATYP_IPV6 && atyp != rfc::SOCKS5_ATYP_DOMAIN {
        return 0, net::Socks5Error.AddressTypeNotSupported;
    }
    if atyp == rfc::SOCKS5_ATYP_DOMAIN && buf.len < 5 {
        return 0, net::Socks5Error.BufferTruncated;
    }
    if buf.len >= 5 {
        let expected_len = core::socks5_expected_frame_len_ct(buf);
        if expected_len > 0 {
            return expected_len, net::Socks5Error.None;
        }
    }
    if atyp == rfc::SOCKS5_ATYP_IPV4 { return 10, net::Socks5Error.None; }
    if atyp == rfc::SOCKS5_ATYP_IPV6 { return 22, net::Socks5Error.None; }
    return 0, net::Socks5Error.AddressTypeNotSupported;
}

fn socks5_rep_to_error(rep: u8) -> net::Socks5Error {
    if rep == rfc::SOCKS5_REP_SUCCEEDED { return net::Socks5Error.None; }
    if rep == rfc::SOCKS5_REP_GENERAL_FAILURE { return net::Socks5Error.ServerFailure; }
    if rep == rfc::SOCKS5_REP_NOT_ALLOWED { return net::Socks5Error.ConnectionNotAllowed; }
    if rep == rfc::SOCKS5_REP_NET_UNREACHABLE { return net::Socks5Error.NetworkUnreachable; }
    if rep == rfc::SOCKS5_REP_HOST_UNREACHABLE { return net::Socks5Error.HostUnreachable; }
    if rep == rfc::SOCKS5_REP_CONN_REFUSED { return net::Socks5Error.ConnectionRefused; }
    if rep == rfc::SOCKS5_REP_TTL_EXPIRED { return net::Socks5Error.TtlExpired; }
    if rep == rfc::SOCKS5_REP_CMD_NOT_SUPPORTED { return net::Socks5Error.CommandNotSupported; }
    return net::Socks5Error.AddressTypeNotSupported;
}

fn recv_exact_socks5_bytes(sock_fd: i64, dst: u8[:], timeout_ms: u32) -> bool {
    var off: i64 = 0;
    while off < dst.len {
        let n = net::tcp_recv_slice(sock_fd, dst[off..], timeout_ms);
        guard n > 0 else { return false; }
        off = core::add_sat_i64(off, n);
    }
    return true;
}

fn recv_socks5_connect_reply_wire(
    sock_fd:    i64,
    buf:        u8[300]&,
    timeout_ms: u32,
) -> i64, net::Socks5Error {
    // RFC 1928 Section 6: Replies - read 4-octet header, then exact BND.ADDR + BND.PORT without over-reading tunnel
    guard recv_exact_socks5_bytes(sock_fd, buf[..4], timeout_ms) else {
        return 0, net::Socks5Error.BufferTruncated;
    }
    var have: i64 = 4;
    if buf[3] == rfc::SOCKS5_ATYP_DOMAIN {
        guard recv_exact_socks5_bytes(sock_fd, buf[4..5], timeout_ms) else {
            return 0, net::Socks5Error.BufferTruncated;
        }
        have = 5;
    }
    let needed_len, len_err = socks5_needed_length(buf[..have], buf[3]);
    guard len_err == net::Socks5Error.None else { return 0, len_err; }
    guard needed_len >= have && needed_len <= 300 else {
        return 0, net::Socks5Error.InvalidReplyHeader;
    }
    if needed_len > have {
        guard recv_exact_socks5_bytes(sock_fd, buf[have..needed_len], timeout_ms) else {
            return 0, net::Socks5Error.BufferTruncated;
        }
    }
    return needed_len, net::Socks5Error.None;
}

// ---- TCP & Async BackPressure Helpers --------------------------------------

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

// ---- UpstreamPool Helpers --------------------------------------------------

inline fn is_epoll_rdhup_signaled(events: u32) -> bool {
    return (events & net::EPOLLRDHUP) != 0;
}

inline fn matches_upstream_partition(
    entry:           const net::UpstreamConnEntry&,
    endpoint:        const net::OriginEndpoint&,
    tls_fingerprint: u64,
    nik:             u64,
) -> bool {
    return entry.nik == nik &&
           entry.tls_fingerprint == tls_fingerprint &&
           entry.endpoint.origin_endpoint_equals(endpoint);
}

inline fn close_upstream_entry_fd(entry: net::UpstreamConnEntry&) {
    if entry.fd >= 0 {
        if net::is_virtual_pipe_fd(entry.fd) {
            net::virtual_fd_close(entry.fd);
        } else {
            net::tcp_close(entry.fd);
        }
        entry.fd = -1;
    }
}

inline fn evict_upstream_rdhup(pool: net::UpstreamPool&, cur: net::UpstreamConnEntry&) {
    close_upstream_entry_fd(cur);
    cur.healthy = false;
    pool.evicted_rdhup = core::add_sat_u64(pool.evicted_rdhup, 1);
}

// ---- Happy Eyeballs Helpers ------------------------------------------------

fn populate_svcb_alpn_flags(rec: const dns::HttpsRecord&, meta: net::ConnectionEndpointMetadata&) {
    for &alpn_tok in rec.alpns {
        let tok = alpn_tok[..];
        if tok == "h3" || tok.starts_with("h3-") {
            meta.alpn_h3 = true;
        } else if tok == "h2" {
            meta.alpn_h2 = true;
        }
    }
}

fn populate_svcb_ip_hints(rec: const dns::HttpsRecord&, meta: net::ConnectionEndpointMetadata&) {
    var ip6_buf: u8[..64] = [];
    for &ip6 in rec.ipv6_hints {
        core::format_ipv6_bytes(ip6, ip6_buf);
        guard meta.ipv6_hints.try_push(ip6_buf) else { break; }
    }
    var ip4_buf: u8[..64] = [];
    for ip4 in rec.ipv4_hints {
        core::format_ipv4_u32(ip4, ip4_buf);
        guard meta.ipv4_hints.try_push(ip4_buf) else { break; }
    }
}

inline fn maybe_arm_last_resort_nat64(
    manager: net::AttemptManager&,
    cand:    const net::DnsCandidate&,
    now_ms:  i64,
) {
    guard manager.enable_nat64_synthesis && cand.family == net::AddressFamily.IPv6 && !manager.last_resort_armed else {
        return;
    }
    var has_more_ipv6 = false;
    for i in manager.current_attempt_idx..manager.pending_candidates.len {
        if manager.pending_candidates[i].family == net::AddressFamily.IPv6 {
            has_more_ipv6 = true;
            break;
        }
    }
    if !has_more_ipv6 {
        manager.last_resort_armed = true;
        manager.last_resort_deadline_ms = core::add_sat_i64(now_ms, rfc::HE_LAST_RESORT_SYNTHESIS_DELAY_MS);
    }
}

fn launch_next_candidate_attempt(manager: net::AttemptManager&, now_ms: i64) -> bool {
    guard manager.current_attempt_idx < manager.pending_candidates.len else { return false; }
    guard manager.attempts.len < 16 else { return false; }

    let cand = manager.pending_candidates[manager.current_attempt_idx];
    manager.current_attempt_idx = core::add_sat_i64(manager.current_attempt_idx, 1);

    let aid = manager.next_id;
    manager.next_id = core::add_sat_i64(aid, 1) as i32;

    var attempt = net::ConnectionAttempt {
        attempt_id:    aid,
        candidate:     copy(cand),
        start_time_ms: now_ms,
        state:         net::AttemptState.Connecting,
    };
    manager.attempts.push(attempt);

    manager.next_attempt_start_ms = core::add_sat_i64(now_ms, manager.effective_cad_ms);

    maybe_arm_last_resort_nat64(manager, cand, now_ms);

    return true;
}

fn synthesize_nat64_candidate(manager: net::AttemptManager&) {
    guard manager.pending_candidates.len < manager.pending_candidates.cap else { return; }
    var v4_ip:   u8[..256] = [];
    var v4_port: u16       = 443;
    var v4_proto = net::L4Protocol.Tcp;
    var v4_prec: i32 = 30;
    var found_v4 = false;

    for &c in manager.pending_candidates {
        if c.family == net::AddressFamily.IPv4 {
            v4_ip.append(c.ip[..]);
            v4_port = c.port;
            v4_proto = c.l4_proto;
            v4_prec = c.precedence;
            found_v4 = true;
            break;
        }
    }
    if !found_v4 {
        for &att in manager.attempts {
            if att.candidate.family == net::AddressFamily.IPv4 {
                v4_ip.append(att.candidate.ip[..]);
                v4_port = att.candidate.port;
                v4_proto = att.candidate.l4_proto;
                v4_prec = att.candidate.precedence;
                found_v4 = true;
                break;
            }
        }
    }
    var syn_ip: u8[..256] = [];
    if found_v4 {
        syn_ip.append("64:ff9b::");
        let _ = syn_ip.try_append(v4_ip[..]);
    } else {
        syn_ip.append("64:ff9b::192.0.2.1");
    }
    var nat64_cand = net::new_dns_candidate(
        net::AddressFamily.IPv6,
        syn_ip[..],
        v4_port,
        v4_proto,
        v4_prec,
    );
    let _ = manager.pending_candidates.try_push(nat64_cand);
}

// ---- MASQUE Helpers --------------------------------------------------------

inline fn is_forbidden_connect_udp_host_byte(b: u8) -> bool {
    return b <= 0x20 || b == 0x7F || b == '/' || b == '\\' || b == '?' || b == '#' || b == '@' || b == '[' || b == ']';
}

// Decodes and validates a MASQUE CONNECT-UDP target_host path segment (RFC 9298 Section 3).
// Rolls back `out_host` on failure.
//
// Example:
//   host_part = "2001%3Adb8%3A%3A1"
//   returns: true, out_host = "2001:db8::1"
fn decode_connect_udp_target_host(host_part: const u8[:], out_host: u8[..256]&) -> bool {
    let saved_len = out_host.len;
    var committed = false;
    defer if !committed { out_host.resize(saved_len); };
    var idx: i64 = 0;
    while idx < host_part.len {
        let b = host_part[idx];
        // RFC 9298 Section 3: Tunneling UDP over HTTP - literal colons in IPv6 MUST be percent-encoded
        guard b != ':' else { return false; }
        if b == '%' {
            let p1 = core::add_sat_i64(idx, 1);
            let p2 = core::add_sat_i64(idx, 2);
            let p3 = core::add_sat_i64(idx, 3);
            guard p2 < host_part.len &&
                  core::is_ascii_hexdigit(host_part[p1]) &&
                  core::is_ascii_hexdigit(host_part[p2]) else {
                return false;
            }
            let decoded, ok_hex = host_part[p1..p3].parse_u8_hex();
            guard ok_hex && !is_forbidden_connect_udp_host_byte(decoded) && out_host.try_push(decoded) else {
                return false;
            }
            idx = p3;
        } else {
            guard !is_forbidden_connect_udp_host_byte(b) && out_host.try_push(b) else { return false; }
            idx = core::add_sat_i64(idx, 1);
        }
    }
    guard out_host.len > saved_len else { return false; }
    committed = true;
    return true;
}

fn assemble_datagram_body(body: u8[..2048]&, context_id: u64, udp_packet: const u8[:]) -> bool {
    guard context_id != 0 || udp_packet.len <= net::MAX_CONNECT_UDP_PAYLOAD_LEN else { return false; }
    guard quic::encode_varint(context_id, body) else { return false; }
    return body.try_append(udp_packet);
}

fn host_mask_for_rem_bits(rem: i64) -> u8 {
    return match rem {
        0 => 0xFF,
        1 => 0x7F,
        2 => 0x3F,
        3 => 0x1F,
        4 => 0x0F,
        5 => 0x07,
        6 => 0x03,
        7 => 0x01,
        _ => 0x00,
    };
}

// RFC 9484 §4.7.1 & §4.7.2: Lower bits of IP Address not covered by prefix length MUST be 0.
fn has_zero_host_bits(ip: const u8[:], prefix_len: u8) -> bool {
    var rem: i64 = prefix_len;
    for b in ip {
        let mask = host_mask_for_rem_bits(rem);
        guard (b & mask) == 0 else { return false; }
        rem = max(core::sub_sat_i64(rem, 8), 0);
    }
    return true;
}

// Decodes a single IP Address Request entry and advances `cur` (RFC 9484 §4.7.2).
// Leaves `cur` unchanged on failure.
//
// Example:
//   payload = [0x01, 4, 10, 0, 0, 1, 32], cur = 0
//   returns: true, cur = 7
fn decode_address_request_entry(payload: const u8[:], cur: i64&, out_req: net::IpAddressRequest&) -> bool {
    let req_id, off, ok = quic::decode_varint(payload, cur as u64);
    guard ok && req_id != 0 && (off as i64) < payload.len else { return false; }
    let ver_idx = off as i64;
    let ip_ver = payload[ver_idx];
    let ip_start = core::add_sat_i64(ver_idx, 1);
    let ip_len: i64 = if ip_ver == 4 { 4 } else if ip_ver == 6 { 16 } else { 0 };
    guard ip_len > 0 else { return false; }
    let max_prefix: u8 = if ip_ver == 4 { 32 } else { 128 };
    let ip_end = core::add_sat_i64(ip_start, ip_len);
    let entry_end = core::add_sat_i64(ip_end, 1);
    guard entry_end <= payload.len else { return false; }
    let ip_slice = payload[ip_start..ip_end];
    let p_len = payload[ip_end];
    guard p_len <= max_prefix && has_zero_host_bits(ip_slice, p_len) else { return false; }
    if out_req.requested_ip.len == 0 {
        out_req.request_id = req_id;
        out_req.ip_version = ip_ver;
        out_req.requested_ip.append(ip_slice);
        out_req.prefix_len = p_len;
    }
    cur = entry_end;
    return true;
}

// Decodes a single IP Address Assign entry and advances `cur` (RFC 9484 §4.7.1).
// Leaves `cur` unchanged on failure.
//
// Example:
//   payload = [0x01, 4, 10, 0, 0, 2, 32], cur = 0
//   returns: true, cur = 7
fn decode_address_assign_entry(payload: const u8[:], cur: i64&, out_assign: net::IpAddressAssign&) -> bool {
    let req_id, off, ok = quic::decode_varint(payload, cur as u64);
    guard ok && (off as i64) < payload.len else { return false; }
    let ver_idx = off as i64;
    let ip_ver = payload[ver_idx];
    let ip_start = core::add_sat_i64(ver_idx, 1);
    let ip_len: i64 = if ip_ver == 4 { 4 } else if ip_ver == 6 { 16 } else { 0 };
    guard ip_len > 0 else { return false; }
    let max_prefix: u8 = if ip_ver == 4 { 32 } else { 128 };
    let ip_end = core::add_sat_i64(ip_start, ip_len);
    let entry_end = core::add_sat_i64(ip_end, 1);
    guard entry_end <= payload.len else { return false; }
    let ip_slice = payload[ip_start..ip_end];
    let p_len = payload[ip_end];
    guard p_len <= max_prefix && has_zero_host_bits(ip_slice, p_len) else { return false; }
    if out_assign.assigned_ip.len == 0 {
        out_assign.request_id = req_id;
        out_assign.ip_version = ip_ver;
        out_assign.assigned_ip.append(ip_slice);
        out_assign.prefix_len = p_len;
    }
    cur = entry_end;
    return true;
}

fn is_valid_ip_range(start_ip: const u8[:], end_ip: const u8[:]) -> bool {
    guard start_ip.len > 0 && start_ip.len == end_ip.len else { return false; }
    for i in start_ip.len {
        if start_ip[i] < end_ip[i] { return true; }
        if start_ip[i] > end_ip[i] { return false; }
    }
    return true;
}

// Decodes a single Route Advertisement entry and advances `cur` (RFC 9484 §4.7.3).
// Leaves `cur` unchanged on failure.
//
// Example:
//   payload = [4, 10, 0, 0, 0, 10, 0, 0, 255, 6], cur = 0
//   returns: true, cur = 10
fn decode_route_entry(payload: const u8[:], cur: i64&, out_route: net::RouteAdvertisement&) -> bool {
    guard cur < payload.len else { return false; }
    let ip_ver = payload[cur];
    let ip_len: i64 = if ip_ver == 4 { 4 } else if ip_ver == 6 { 16 } else { 0 };
    guard ip_len > 0 else { return false; }
    let start_beg = core::add_sat_i64(cur, 1);
    let start_end = core::add_sat_i64(start_beg, ip_len);
    let end_end = core::add_sat_i64(start_end, ip_len);
    let entry_end = core::add_sat_i64(end_end, 1);
    guard entry_end <= payload.len else { return false; }
    let start_slice = payload[start_beg..start_end];
    let end_slice = payload[start_end..end_end];
    guard is_valid_ip_range(start_slice, end_slice) else { return false; }
    if out_route.start_ip.len == 0 {
        out_route.ip_version = ip_ver;
        out_route.start_ip.append(start_slice);
        out_route.end_ip.append(end_slice);
        out_route.ip_protocol = payload[end_end];
    }
    cur = entry_end;
    return true;
}

inline fn is_all_zero_ip_bytes(ip: const u8[:]) -> bool {
    for b in ip {
        if b != 0 {
            return false;
        }
    }
    return true;
}

// ---- StreamPool Helpers ----------------------------------------------------

inline fn set_canonical_host<B>(dst: B&, raw_host: const u8[:]) -> bool {
    guard dst.try_set(raw_host) else { return false; }
    to_lower(dst[..]);
    return true;
}

fn pool_scheme_to_u64(s: net::PoolScheme) -> u64 {
    return match s {
        Http => 1,
        Https => 2,
        Ws => 3,
        Wss => 4,
        H2c => 5,
    };
}

inline fn wyhash64_ascii_fold(data: const u8[:], seed: u64) -> u64 {
    var folded: u8[..256] = [];
    for b in data {
        guard folded.try_push(core::to_lower_ascii_byte(b)) else { break; }
    }
    return core::wyhash64(folded[..], seed);
}

inline fn has_empty_dns_label(name: const u8[:]) -> bool {
    if name.len == 0 || name.starts_with(".") || name.ends_with(".") {
        return true;
    }
    return core::contains(name, "..");
}

inline fn is_all_numeric_dot_host(host: const u8[:]) -> bool {
    var saw_digit = false;
    for b in host {
        if b == '.' {
            continue;
        }
        if !core::is_ascii_digit(b) {
            return false;
        }
        saw_digit = true;
    }
    return saw_digit;
}

fn find_closed_connection_slot(pool: const net::StreamPool&) -> i32 {
    for &c, idx in pool.conns {
        if c.closed {
            return idx as i32;
        }
    }
    return -1;
}

fn acquire_connection_slot(pool: net::StreamPool&, now_ns: i64) -> i32 {
    guard pool.conns.len >= 64 else { return -1; }
    let closed_idx = find_closed_connection_slot(pool);
    if closed_idx >= 0 {
        return closed_idx;
    }
    guard evict_oldest_idle_connection(pool, now_ns) else { return -2; }
    return find_closed_connection_slot(pool);
}

fn group_record_closed(pool: net::StreamPool&, key: const net::PoolKey&, active: bool) {
    let grp_idx = pool.find_group_index(key);
    guard grp_idx >= 0 else { return; }
    let grp .= pool.groups[grp_idx];
    if active {
        if grp.active_conns > 0 {
            grp.active_conns = core::sub_sat_i64(grp.active_conns, 1) as i32;
        }
    } else {
        if grp.idle_conns > 0 {
            grp.idle_conns = core::sub_sat_i64(grp.idle_conns, 1) as i32;
        }
    }
}

fn group_record_acquired(pool: net::StreamPool&, key: const net::PoolKey&) {
    let grp_idx = pool.find_group_index(key);
    guard grp_idx >= 0 else { return; }
    let grp .= pool.groups[grp_idx];
    grp.active_conns = core::add_sat_i64(grp.active_conns, 1) as i32;
    if grp.idle_conns > 0 {
        grp.idle_conns = core::sub_sat_i64(grp.idle_conns, 1) as i32;
    }
}

fn group_record_released(pool: net::StreamPool&, key: const net::PoolKey&) {
    let grp_idx = pool.find_group_index(key);
    guard grp_idx >= 0 else { return; }
    let grp .= pool.groups[grp_idx];
    if grp.active_conns > 0 {
        grp.active_conns = core::sub_sat_i64(grp.active_conns, 1) as i32;
    }
    grp.idle_conns = core::add_sat_i64(grp.idle_conns, 1) as i32;
}

fn evict_oldest_idle_connection(pool: net::StreamPool&, now_ns: i64) -> bool {
    var oldest_idx = -1;
    var oldest_idle_ns: i64 = 0;

    for &c, idx in pool.conns {
        if !c.closed && c.active_allocations == 0 {
            if oldest_idx == -1 || c.idle_at_ns < oldest_idle_ns {
                oldest_idx = idx as i32;
                oldest_idle_ns = c.idle_at_ns;
            }
        }
    }

    if oldest_idx >= 0 {
        let victim .= pool.conns[oldest_idx];
        group_record_closed(pool, victim.key, false);
        victim.transport.close();
        net::release_hpack_slot(victim);
        victim.rx_buf.clear();
        victim.closed = true;
        victim.no_new_exchanges = true;
        return true;
    }
    return false;
}

fn evict_oldest_idle_in_group(pool: net::StreamPool&, key: const net::PoolKey&) -> bool {
    var oldest_idx = -1;
    var oldest_idle_ns: i64 = 0;

    for &c, idx in pool.conns {
        if !c.closed && c.active_allocations == 0 && c.key.pool_key_equals(key) {
            if oldest_idx == -1 || c.idle_at_ns < oldest_idle_ns {
                oldest_idx = idx as i32;
                oldest_idle_ns = c.idle_at_ns;
            }
        }
    }

    guard oldest_idx >= 0 else { return false; }
    let victim .= pool.conns[oldest_idx];
    group_record_closed(pool, victim.key, false);
    victim.transport.close();
    net::release_hpack_slot(victim);
    victim.rx_buf.clear();
    victim.closed = true;
    victim.no_new_exchanges = true;
    return true;
}

fn count_proxy_chain_sockets(pool: const net::StreamPool&, proxy_chain: const net::ProxyChain&) -> i64, i64 {
    var active: i64 = 0;
    var idle:   i64 = 0;
    for &c in pool.conns {
        if !c.closed && c.key.proxy_chain.proxy_chain_equals(proxy_chain) {
            if c.active_allocations > 0 {
                active = core::add_sat_i64(active, 1);
            } else {
                idle = core::add_sat_i64(idle, 1);
            }
        }
    }
    return active, idle;
}

fn evict_oldest_idle_for_proxy(pool: net::StreamPool&, proxy_chain: const net::ProxyChain&) -> bool {
    var oldest_idx = -1;
    var oldest_idle_ns: i64 = 0;

    for &c, idx in pool.conns {
        if !c.closed && c.active_allocations == 0 && c.key.proxy_chain.proxy_chain_equals(proxy_chain) {
            if oldest_idx == -1 || c.idle_at_ns < oldest_idle_ns {
                oldest_idx = idx as i32;
                oldest_idle_ns = c.idle_at_ns;
            }
        }
    }

    guard oldest_idx >= 0 else { return false; }
    let victim .= pool.conns[oldest_idx];
    group_record_closed(pool, victim.key, false);
    victim.transport.close();
    net::release_hpack_slot(victim);
    victim.rx_buf.clear();
    victim.closed = true;
    victim.no_new_exchanges = true;
    return true;
}

fn enforce_group_socket_quota(pool: net::StreamPool&, key: const net::PoolKey&) -> bool {
    let grp_idx = pool.find_group_index(key);
    guard grp_idx >= 0 && pool.max_sockets_per_group > 0 else { return true; }
    let grp .= pool.groups[grp_idx];
    let total_grp = core::add_sat_i64(grp.active_conns, grp.idle_conns);
    guard total_grp >= pool.max_sockets_per_group else { return true; }
    if grp.idle_conns > 0 {
        let _ = evict_oldest_idle_in_group(pool, key);
    }
    return grp.active_conns < pool.max_sockets_per_group;
}

fn enforce_proxy_chain_socket_quota(pool: net::StreamPool&, key: const net::PoolKey&) -> bool {
    guard !key.proxy_chain.is_direct && pool.max_sockets_per_proxy > 0 else { return true; }
    let p_active, p_idle = count_proxy_chain_sockets(pool, key.proxy_chain);
    let total_proxy = core::add_sat_i64(p_active, p_idle);
    guard total_proxy >= pool.max_sockets_per_proxy else { return true; }
    if p_idle > 0 {
        let _ = evict_oldest_idle_for_proxy(pool, key.proxy_chain);
    }
    return p_active < pool.max_sockets_per_proxy;
}

inline fn mark_multiplexed_acquired(c: net::PooledConnection&) {
    c.active_allocations = core::add_sat_i64(c.active_allocations, 1) as i32;
    c.use_count = core::add_sat_i64(c.use_count, 1);
}

inline fn try_acquire_direct_conn(
    pool:                net::StreamPool&,
    c:                   net::PooledConnection&,
    key:                 const net::PoolKey&,
    now_ns:              i64,
    do_extensive_checks: bool,
) -> i32, bool {
    guard !c.closed && c.key.pool_key_equals(key) else { return -1, false; }
    let was_idle = c.active_allocations == 0;
    let is_h2_h3 = c.protocol == net::NegotiatedProtocol.Http2 || c.protocol == net::NegotiatedProtocol.Http3Quic;
    if is_h2_h3 {
        guard c.active_allocations < c.max_concurrent_streams else { return -1, false; }
        let healthy = c.is_connection_healthy(
            now_ns, do_extensive_checks, net::IDLE_CONNECTION_HEALTHY_NS, pool.idle_timeout_ns,
        );
        if !healthy {
            if c.closed {
                group_record_closed(pool, c.key, !was_idle);
            }
            return -1, false;
        }
        mark_multiplexed_acquired(c);
        if was_idle {
            group_record_acquired(pool, c.key);
        }
        return c.conn_id, true;
    }

    guard was_idle else { return -1, false; }
    let healthy = c.is_connection_healthy(
        now_ns, do_extensive_checks, net::IDLE_CONNECTION_HEALTHY_NS, pool.idle_timeout_ns,
    );
    if !healthy {
        if c.closed {
            group_record_closed(pool, c.key, false);
        }
        return -1, false;
    }
    c.active_allocations = 1;
    c.use_count = core::add_sat_i64(c.use_count, 1);
    group_record_acquired(pool, c.key);
    return c.conn_id, true;
}

inline fn try_acquire_coalesced_conn(
    pool:                net::StreamPool&,
    c:                   net::PooledConnection&,
    key:                 const net::PoolKey&,
    target_resolved_ip:  const u8[:],
    now_ns:              i64,
    do_extensive_checks: bool,
) -> i32, bool {
    guard !c.closed && c.active_allocations < c.max_concurrent_streams else { return -1, false; }
    let can_coalesce, is_negative = c.can_coalesce_h2_connection(key, target_resolved_ip);
    if is_negative {
        pool.negative_ip_pool_result_count = core::add_sat_i64(pool.negative_ip_pool_result_count, 1);
    }
    guard can_coalesce else { return -1, false; }
    let was_idle = c.active_allocations == 0;
    let healthy = c.is_connection_healthy(
        now_ns, do_extensive_checks, net::IDLE_CONNECTION_HEALTHY_NS, pool.idle_timeout_ns,
    );
    if !healthy {
        if c.closed {
            group_record_closed(pool, c.key, !was_idle);
        }
        return -1, false;
    }
    mark_multiplexed_acquired(c);
    if was_idle {
        group_record_acquired(pool, c.key);
    }
    return c.conn_id, true;
}

fn try_handoff_to_group_waiter(
    pool:       net::StreamPool&,
    c:          net::PooledConnection&,
    out_waiter: net::WantConn&,
) -> bool {
    guard !c.no_new_exchanges && !c.remote_rst && !c.source_exhausted else { return false; }
    let grp_idx = pool.find_group_index(c.key);
    guard grp_idx >= 0 && !pool.groups[grp_idx].wait_queue.is_queue_empty() else { return false; }
    let w_item, ok_w = pool.groups[grp_idx].wait_queue.pop_want();
    guard ok_w else { return false; }
    c.use_count = core::add_sat_i64(c.use_count, 1);
    out_waiter = w_item;
    out_waiter.ready = true;
    out_waiter.assigned_conn_id = c.conn_id;
    out_waiter.reused = true;
    return true;
}

fn finalize_idle_or_draining_conn(pool: net::StreamPool&, c: net::PooledConnection&, now_ns: i64) {
    if c.no_new_exchanges || c.remote_rst || c.source_exhausted {
        group_record_closed(pool, c.key, true);
        c.transport.close();
        net::release_hpack_slot(c);
        c.rx_buf.clear();
        c.closed = true;
        c.no_new_exchanges = true;
        return;
    }
    c.idle_at_ns = now_ns;
    group_record_released(pool, c.key);
}

inline fn is_origin_group_unused(grp: const net::ConnectionGroup&) -> bool {
    return grp.active_conns <= 0 &&
           grp.idle_conns <= 0 &&
           grp.dials_in_progress <= 0 &&
           grp.wait_queue.is_queue_empty();
}

// ---- Retry-After Helpers ---------------------------------------------------

fn try_parse_retry_after_seconds(clean: const u8[:]) -> i64, bool {
    for ch in clean {
        guard core::is_ascii_digit(ch) else { return 0, false; }
    }
    let secs, ok_s = core::parse_digits(clean);
    guard ok_s && secs >= 0 else { return 0, false; }
    return core::retry_after_sec_to_ms_sat(secs), true;
}

fn try_parse_retry_after_http_date(clean: const u8[:], now_unix_ms: i64) -> i64, bool {
    let parsed_time, ok_t = core::parse_http_date(clean);
    guard ok_t else { return 0, false; }

    let target_unix_ms = parsed_time.unix_milli();
    if target_unix_ms <= now_unix_ms {
        return 0, true;
    }
    return core::sub_sat_i64(target_unix_ms, now_unix_ms), true;
}

// ---- Reactor Accelerator Helpers -------------------------------------------

inline fn reactor_cancel_uring_slot(accel: net::ReactorAccelRuntime&, slot: i64) {
    guard accel.slot_accel[slot] && accel.mode == net::ReactorAccelMode.IoUring && accel.uring_fd >= 0 else { return; }
    let tok = net::reactor_accel_slot_token(accel, slot);
    let rx_tag = if accel.slot_ktls_rx[slot] {
        net::REACTOR_URING_TAG_POLL | tok
    } else {
        net::REACTOR_URING_TAG_RECV | tok
    };
    var cancel_sqes: UringSqe[..2] = [];
    var rx_cancel = UringSqe { .. };
    uring_prep_cancel(rx_cancel, rx_tag);
    let _ = cancel_sqes.try_push(rx_cancel);
    if accel.slot_tx_inflight[slot] {
        var tx_cancel = UringSqe { .. };
        uring_prep_cancel(tx_cancel, net::REACTOR_URING_TAG_SEND | tok);
        let _ = cancel_sqes.try_push(tx_cancel);
    }
    let _ = uring_submit_sqes(accel.uring_fd, cancel_sqes[..]);
}

fn reactor_try_open_uring(accel: net::ReactorAccelRuntime&, listener_fd: i64) -> bool {
    let rfd = native_uring_create(256, 0);
    guard rfd >= 0 else { return false; }
    let pbuf, ok_pb = uring_alloc_pbuf_ring(rfd, net::REACTOR_URING_PBUF_BGID, 256, 4096);
    if !ok_pb || pbuf == 0 {
        native_uring_close(rfd);
        return false;
    }
    accel.mode = net::ReactorAccelMode.IoUring;
    accel.uring_fd = rfd;
    accel.uring_pbuf = pbuf;
    if listener_fd > 0 {
        net::tcp_set_nonblocking(listener_fd, true);
        net::reactor_arm_uring_accept(accel, listener_fd);
    }
    return true;
}

fn reactor_try_open_rio(accel: net::ReactorAccelRuntime&, listener_fd: i64) -> bool {
    guard native_rio_available() == 1 && accel.epfd >= 0 else { return false; }
    let cq = native_rio_create_cq(512);
    guard cq != 0 else { return false; }
    let tx_cq = native_rio_create_cq(512);
    if tx_cq == 0 {
        native_rio_close_cq(cq);
        return false;
    }
    net::ensure_reactor_accel_slab(accel);
    let bid = native_rio_register_slice(accel.slab[..]);
    if bid == 0 {
        native_rio_close_cq(tx_cq);
        native_rio_close_cq(cq);
        return false;
    }
    accel.mode = net::ReactorAccelMode.Rio;
    accel.rio_cq = cq;
    accel.rio_tx_cq = tx_cq;
    accel.rio_buf_id = bid;
    if listener_fd > 0 {
        if native_rio_is_listener(listener_fd) == 1 {
            accel.rio_listener_fd = listener_fd;
        } else {
            net::tcp_set_nonblocking(listener_fd, true);
            if net::epoll_add(accel.epfd, listener_fd, net::EPOLL_READ, net::EPOLL_LISTENER_TAG) {
                accel.epfd_registered_count = core::add_sat_i64(accel.epfd_registered_count, 1) as i32;
            }
        }
    }
    return true;
}

fn reactor_try_open_kqueue(accel: net::ReactorAccelRuntime&, listener_fd: i64) -> bool {
    let kq = native_kqueue_create();
    guard kq >= 0 else { return false; }
    accel.mode = net::ReactorAccelMode.Kqueue;
    accel.kq_fd = kq;
    if listener_fd > 0 {
        net::tcp_set_nonblocking(listener_fd, true);
        let r_flags = EV_ADD | EV_ENABLE;
        net::reactor_queue_kq_change(accel, listener_fd, r_flags, net::EPOLL_LISTENER_TAG);
    }
    return true;
}

// ---- Poller & EventLoop Helpers --------------------------------------------

const URING_INTERNAL_CANCEL_TAG: u64 = 0xFFFFFFFFFFFFFFFF;
const URING_POLLIN_MASK:         u32 = 1;
const URING_POLLOUT_MASK:        u32 = 4;
const URING_POLLERR_MASK:        u32 = 8;
const URING_POLLHUP_MASK:        u32 = 16;
const KQUEUE_EV_ERROR_FLAG:      u16 = 0x4000;
const NS_TO_MS_MULHI_RECIP:      u64 = 0x10C6F7A0B5EE;
const MAX_POLL_TIMEOUT_NS:       u64 = 2147483647000000;

inline fn apply_trigger_clear_mask(t: core::PollTrigger.Edge, sim: net::SimulatedReadyState&, triggered: u32) {
    sim.ready.clear_flag(triggered);
    sim.bytes = 0;
}

inline fn apply_trigger_clear_mask(t: core::PollTrigger.Level, sim: net::SimulatedReadyState&, triggered: u32) {
    sim.ready.clear_flag(core::POLL_WRITE);
}

fn interest_to_epoll_flags(interest: core::PollInterest) -> u32 {
    return match interest {
        Read => net::EPOLL_READ,
        Write => net::EPOLL_WRITE,
        ReadWrite => net::EPOLL_READ | net::EPOLL_WRITE,
        None => 0,
    };
}

fn interest_to_uring_poll_mask(interest: core::PollInterest) -> u32 {
    return match interest {
        Read => URING_POLLIN_MASK,
        Write => URING_POLLOUT_MASK,
        ReadWrite => URING_POLLIN_MASK | URING_POLLOUT_MASK,
        None => 0,
    };
}

inline fn is_live_os_socket_fd(fd: i32) -> bool {
    guard fd > 0 else { return false; }
    if detect_target_platform() == TargetPlatform.Windows {
        return native_tcp_get_readable_bytes(fd) >= 0;
    }
    return true;
}

inline fn poller_push_kqueue_change(p: net::Poller&, ev: Kevent) {
    if p.kqueue_changes.len >= p.kqueue_changes.cap {
        var empty_out: Kevent[1] = [Kevent { .. }];
        let _ = kqueue_poll_slice(p.kqueue_fd, p.kqueue_changes[..], empty_out[..0], 0);
        p.kqueue_changes.clear();
    }
    let _ = p.kqueue_changes.try_push(ev);
}

inline fn poller_queue_kqueue_interest(
    p:        net::Poller&,
    fd:       i32,
    tag:      u64,
    interest: core::PollInterest,
    trigger:  core::PollTrigger,
) {
    let edge = trigger == core::PollTrigger.Edge;
    if interest == core::PollInterest.Read || interest == core::PollInterest.ReadWrite {
        var ev_r = Kevent { .. };
        kevent_prep_read(ev_r, fd, tag, edge);
        poller_push_kqueue_change(p, ev_r);
    }
    if interest == core::PollInterest.Write || interest == core::PollInterest.ReadWrite {
        var ev_w = Kevent { .. };
        kevent_prep_write(ev_w, fd, tag, edge);
        poller_push_kqueue_change(p, ev_w);
    }
}

inline fn poller_queue_kqueue_delete(p: net::Poller&, fd: i32, interest: core::PollInterest) {
    if interest == core::PollInterest.Read || interest == core::PollInterest.ReadWrite {
        poller_push_kqueue_change(p, Kevent {
            ident: fd as u64, filter: EVFILT_READ, flags: EV_DELETE, ..
        });
    }
    if interest == core::PollInterest.Write || interest == core::PollInterest.ReadWrite {
        poller_push_kqueue_change(p, Kevent {
            ident: fd as u64, filter: EVFILT_WRITE, flags: EV_DELETE, ..
        });
    }
}

inline fn poller_submit_uring_poll_add(ring_fd: i64, fd: i32, interest: core::PollInterest, tag: u64) {
    let mask = interest_to_uring_poll_mask(interest);
    guard mask != 0 else { return; }
    var sqe = UringSqe { .. };
    uring_prep_poll_add(sqe, fd, mask, tag);
    var batch: UringSqe[1] = [sqe];
    let _ = uring_submit_sqes(ring_fd, batch[..]);
}

inline fn poller_submit_uring_poll_remove(ring_fd: i64, old_tag: u64) {
    var rm_sqe = UringSqe { .. };
    uring_prep_poll_remove(rm_sqe, old_tag, URING_INTERNAL_CANCEL_TAG);
    var rm_batch: UringSqe[1] = [rm_sqe];
    let _ = uring_submit_sqes(ring_fd, rm_batch[..]);
}

inline fn poller_bind_native_registration(
    p:        net::Poller&,
    fd:       i32,
    tag:      u64,
    interest: core::PollInterest,
    trigger:  core::PollTrigger,
) {
    if p.epoll_fd >= 0 && is_live_os_socket_fd(fd) {
        let _ = net::epoll_add(p.epoll_fd, fd, interest_to_epoll_flags(interest), tag);
    }
    if p.kqueue_fd >= 0 {
        poller_queue_kqueue_interest(p, fd, tag, interest, trigger);
    }
    if p.uring_ring_fd >= 0 {
        poller_submit_uring_poll_add(p.uring_ring_fd, fd, interest, tag);
    }
}

inline fn poller_mod_native_registration(
    p:            net::Poller&,
    fd:           i32,
    old_tag:      u64,
    old_interest: core::PollInterest,
    tag:          u64,
    interest:     core::PollInterest,
    trigger:      core::PollTrigger,
) {
    if p.epoll_fd >= 0 && is_live_os_socket_fd(fd) {
        let flags = interest_to_epoll_flags(interest);
        if !net::epoll_mod(p.epoll_fd, fd, flags, tag) {
            let _ = net::epoll_add(p.epoll_fd, fd, flags, tag);
        }
    }
    if p.kqueue_fd >= 0 {
        poller_queue_kqueue_delete(p, fd, old_interest);
        poller_queue_kqueue_interest(p, fd, tag, interest, trigger);
    }
    if p.uring_ring_fd >= 0 {
        poller_submit_uring_poll_remove(p.uring_ring_fd, old_tag);
        poller_submit_uring_poll_add(p.uring_ring_fd, fd, interest, tag);
    }
}

inline fn poller_bind_native_deregister(
    p:            net::Poller&,
    fd:           i32,
    old_tag:      u64,
    old_interest: core::PollInterest,
) {
    if p.epoll_fd >= 0 {
        let _ = net::epoll_del(p.epoll_fd, fd);
    }
    if p.kqueue_fd >= 0 {
        poller_queue_kqueue_delete(p, fd, old_interest);
    }
    if p.uring_ring_fd >= 0 {
        poller_submit_uring_poll_remove(p.uring_ring_fd, old_tag);
    }
}

fn check_expired_timers(p: net::Poller&, now_ns: u64, out_events: core::PollReadyEvent[..64]&) -> i32 {
    var fired_count: i64 = 0;
    for i in p.timers.len {
        guard p.timers[i].active && now_ns >= p.timers[i].deadline_ns else { continue; }
        let ev = core::PollReadyEvent {
            tag:             p.timers[i].tag,
            fd:              -1,
            events:          core::POLL_TIMER,
            bytes_available: 0,
            is_eof:          false,
            is_timer:        true,
        };
        guard out_events.try_push(ev) else { break; }
        fired_count = core::add_sat_i64(fired_count, 1);

        if p.timers[i].interval_ns > 0 {
            p.timers[i].deadline_ns = core::add_sat_u64(now_ns, p.timers[i].interval_ns);
        } else {
            p.timers[i].active = false;
            if p.active_timer_count > 0 {
                p.active_timer_count = core::sub_sat_u64(p.active_timer_count, 1) as u32;
            }
        }
    }
    return fired_count as i32;
}

inline fn is_coarse_timeout_expired(t: u8, old_tick: u64, elapsed_ticks: u64) -> bool {
    guard t != net::COARSE_TIMEOUT_DISABLED else { return false; }
    guard elapsed_ticks < 240 else { return true; }
    let dist = core::sub_sat_u64(core::add_sat_u64(t, 240), old_tick) % 240;
    return dist > 0 && dist <= elapsed_ticks;
}

inline fn dispatch_expired_registration(
    reg:           net::SocketRegistration&,
    old_tick:      u64,
    elapsed_ticks: u64,
    out_events:    core::PollReadyEvent[..64]&,
) -> bool {
    guard reg.in_use else { return false; }
    guard is_coarse_timeout_expired(reg.timeout, old_tick, elapsed_ticks) else { return false; }
    guard out_events.try_push(core::PollReadyEvent {
        tag:             reg.tag,
        fd:              reg.fd,
        events:          core::POLL_TIMER,
        bytes_available: 0,
        is_eof:          false,
        is_timer:        true,
    }) else { return false; }
    reg.timeout = net::COARSE_TIMEOUT_DISABLED;
    return true;
}

inline fn advance_coarse_clock(p: net::Poller&, now_ns: u64) -> u64, u64, bool {
    guard p.last_coarse_tick_ns > 0 else {
        p.last_coarse_tick_ns = now_ns;
        return 0, 0, false;
    }
    let next_tick_ns = core::add_sat_u64(p.last_coarse_tick_ns, net::COARSE_TIMEOUT_GRANULARITY_NS);
    guard now_ns >= next_tick_ns else {
        return 0, 0, false;
    }
    let delta_ns = core::sub_sat_u64(now_ns, p.last_coarse_tick_ns);
    let el = delta_ns / net::COARSE_TIMEOUT_GRANULARITY_NS;
    p.last_coarse_tick_ns = core::add_sat_u64(
        p.last_coarse_tick_ns,
        core::mul_sat_u64(el, net::COARSE_TIMEOUT_GRANULARITY_NS),
    );
    let old_tick: u64 = p.global_coarse_tick;
    p.global_coarse_tick = (core::add_sat_u64(old_tick, el) % 240) as u8;
    return old_tick, el, true;
}

fn check_wake_events(p: net::Poller&, out_events: core::PollReadyEvent[..64]&) -> i32 {
    guard p.wake_tags.len > 0 else { return 0; }
    var emitted: i64 = 0;
    for tag in p.wake_tags {
        let ev = core::PollReadyEvent {
            tag:             tag,
            fd:              -1,
            events:          core::POLL_WAKE,
            bytes_available: 0,
            is_eof:          false,
            is_timer:        false,
        };
        guard out_events.try_push(ev) else { break; }
        emitted = core::add_sat_i64(emitted, 1);
        p.total_events_dispatched = core::add_sat_u64(p.total_events_dispatched, 1);
    }
    p.wake_tags.compact_wire_buffer(emitted);
    return (emitted & 0x7FFFFFFF) as i32;
}

fn has_pending_simulated_ready(p: const net::Poller&) -> bool {
    guard p.active_fd_count > 0 else { return false; }
    for i in p.registrations.len {
        guard p.registrations[i].in_use else { continue; }
        let mask = core::interest_to_poll_flags(p.registrations[i].interest) |
            core::POLL_ERROR | core::POLL_HANGUP;
        if (p.registrations[i].sim.ready & mask) != core::POLL_NONE {
            return true;
        }
    }
    return false;
}

fn find_earliest_timer_deadline_ns(p: const net::Poller&) -> u64, bool {
    guard p.active_timer_count > 0 else { return 0, false; }
    var found = false;
    var earliest_ns: u64 = 0xFFFFFFFFFFFFFFFF;
    for i in p.timers.len {
        guard p.timers[i].active else { continue; }
        found = true;
        earliest_ns = min(earliest_ns, p.timers[i].deadline_ns);
    }
    return earliest_ns, found;
}

fn clamp_timeout_to_timers(p: const net::Poller&, timeout_ms: i64, now_ns: u64) -> i64 {
    let earliest_ns, has_timer = find_earliest_timer_deadline_ns(p);
    let rem_ns = min(core::add_sat_u64(core::sub_sat_u64(earliest_ns, now_ns), 999999), MAX_POLL_TIMEOUT_NS);
    let rem_ms_u64 = min(core::mulhi_u64(rem_ns, NS_TO_MS_MULHI_RECIP), 2147483647);
    let rem_ms = (rem_ms_u64 as i32) as i64;
    if timeout_ms == 0 || p.wake_tags.len > 0 || has_pending_simulated_ready(p) {
        return 0;
    }
    guard has_timer else { return timeout_ms; }
    if now_ns >= earliest_ns {
        return 0;
    }
    if timeout_ms < 0 {
        return rem_ms;
    }
    return min(timeout_ms, rem_ms);
}

fn poller_collect_epoll_events(
    p:          net::Poller&,
    timeout_ms: i64,
    out_events: core::PollReadyEvent[..64]&,
) {
    var raw_fds:    i64[64] = [0; 64];
    var raw_udata:  u64[64] = [0; 64];
    var raw_events: u32[64] = [0; 64];
    let t_clamped = min(max(timeout_ms, -1), 2147483647);
    let n = epoll_wait_events_direct(p.epoll_fd, raw_fds[..], raw_udata[..], raw_events[..], t_clamped as i32);
    guard n > 0 else { return; }

    let limit = min(n as i64, 64);
    for k in limit {
        let tag = raw_udata[k];
        let reg_idx = net::find_by_tag(p, tag);
        guard reg_idx >= 0 else { continue; }
        let fd_val = p.registrations[reg_idx].fd;
        let fallback_flags = core::interest_to_poll_flags(p.registrations[reg_idx].interest);
        let ev_flags = if raw_events[k] != core::POLL_NONE { raw_events[k] } else { fallback_flags };
        let avail_raw = if (ev_flags & core::POLL_READ) != 0 {
            native_tcp_get_readable_bytes(fd_val)
        } else {
            0
        };
        let ev = core::PollReadyEvent {
            tag:             tag,
            fd:              fd_val,
            events:          if ev_flags != core::POLL_NONE { ev_flags } else { core::POLL_READ },
            bytes_available: max(avail_raw, 0),
            is_eof:          (ev_flags & core::POLL_HANGUP) != 0,
            is_timer:        false,
        };
        guard out_events.try_push(ev) else { break; }
        p.total_events_dispatched = core::add_sat_u64(p.total_events_dispatched, 1);
    }
}

fn poller_collect_kqueue_events(
    p:          net::Poller&,
    timeout_ms: i64,
    out_events: core::PollReadyEvent[..64]&,
) {
    var kev_out: Kevent[64] = [Kevent { .. }; 64];
    let timeout_ns = timeout_ms_to_ns(timeout_ms);
    let n = kqueue_poll_slice(p.kqueue_fd, p.kqueue_changes[..], kev_out[..], timeout_ns);
    p.kqueue_changes.clear();
    guard n > 0 else { return; }

    let limit = min(n as i64, 64);
    for k in limit {
        let kev = kev_out[k];
        guard (kev.flags & KQUEUE_EV_ERROR_FLAG) == 0 else { continue; }
        let reg_idx = net::find_by_tag(p, kev.udata);
        guard reg_idx >= 0 else { continue; }
        let flags, is_eof = net::map_kevent_to_poll_flags(kev);
        guard flags != core::POLL_NONE else { continue; }
        let ev = core::PollReadyEvent {
            tag:             kev.udata,
            fd:              p.registrations[reg_idx].fd,
            events:          flags,
            bytes_available: kevent_bytes_available(kev),
            is_eof:          is_eof,
            is_timer:        false,
        };
        guard out_events.try_push(ev) else { break; }
        p.total_events_dispatched = core::add_sat_u64(p.total_events_dispatched, 1);
    }
}

inline fn map_uring_revents_to_poll_flags(revents: u32) -> u32 {
    var flags: u32 = core::POLL_NONE;
    if (revents & URING_POLLIN_MASK) != 0 { flags |= core::POLL_READ; }
    if (revents & URING_POLLOUT_MASK) != 0 { flags |= core::POLL_WRITE; }
    if (revents & URING_POLLERR_MASK) != 0 { flags |= core::POLL_ERROR; }
    if (revents & URING_POLLHUP_MASK) != 0 { flags |= core::POLL_HANGUP; }
    return flags;
}

fn poller_collect_uring_events(
    p:          net::Poller&,
    timeout_ms: i64,
    out_events: core::PollReadyEvent[..64]&,
) {
    var cqes: UringCqe[64] = [UringCqe { .. }; 64];
    let min_complete: u32 = if timeout_ms == 0 { 0 } else { 1 };
    let timeout_ns = timeout_ms_to_ns(timeout_ms);
    let n = uring_wait_cqes(p.uring_ring_fd, cqes[..], min_complete, timeout_ns);
    guard n > 0 else { return; }

    let limit = min(n as i64, 64);
    for k in limit {
        let cqe = cqes[k];
        guard cqe.user_data != URING_INTERNAL_CANCEL_TAG &&
            cqe.res >= 0 &&
            (cqe.flags & URING_CQE_F_NOTIF) == 0 else { continue; }
        let reg_idx = net::find_by_tag(p, cqe.user_data);
        guard reg_idx >= 0 else { continue; }
        let flags = map_uring_revents_to_poll_flags(cqe.res as u32);
        let fd_val = p.registrations[reg_idx].fd;
        if p.registrations[reg_idx].trigger == core::PollTrigger.Level {
            poller_submit_uring_poll_add(
                p.uring_ring_fd, fd_val, p.registrations[reg_idx].interest, cqe.user_data,
            );
        }
        guard flags != core::POLL_NONE else { continue; }
        let ev = core::PollReadyEvent {
            tag:             cqe.user_data,
            fd:              fd_val,
            events:          flags,
            bytes_available: 0,
            is_eof:          (flags & core::POLL_HANGUP) != 0,
            is_timer:        false,
        };
        guard out_events.try_push(ev) else { break; }
        p.total_events_dispatched = core::add_sat_u64(p.total_events_dispatched, 1);
    }
}

inline fn poller_drain_rio_cq(p: net::Poller&, out_events: core::PollReadyEvent[..64]&) {
    var rio_results: RioResult[..64] = [];
    if rio_drain_completions(p.rio_cq_id, rio_results) > 0 {
        let _ = net::rio_map_completions_to_events(p, rio_results[..], out_events);
    }
}

inline fn poller_poll_native_drivers(
    p:          net::Poller&,
    timeout_ms: i64,
    out_events: core::PollReadyEvent[..64]&,
) {
    if p.rio_cq_id != 0 {
        poller_drain_rio_cq(p, out_events);
    }
    let eff_timeout = if out_events.len > 0 { 0 } else { timeout_ms };
    if p.uring_ring_fd >= 0 {
        poller_collect_uring_events(p, eff_timeout, out_events);
    } else if p.kqueue_fd >= 0 {
        poller_collect_kqueue_events(p, eff_timeout, out_events);
    } else if p.epoll_fd >= 0 {
        poller_collect_epoll_events(p, eff_timeout, out_events);
    }
    let can_wait_rio = p.rio_cq_id != 0 && out_events.len == 0 && (p.epoll_fd < 0 || p.active_fd_count == 0);
    if can_wait_rio && eff_timeout != 0 {
        let wait_ms = min(max(eff_timeout, -1), 2147483647) as i32;
        if rio_wait_cq(p.rio_cq_id, wait_ms) >= 0 {
            poller_drain_rio_cq(p, out_events);
        }
    }
}

inline fn flush_socket_writes(fd: i32, buf: u8[..4096]&) -> i64 {
    guard buf.len > 0 else { return 0; }
    guard fd >= 0 else {
        let count = buf.len;
        buf.clear();
        return count;
    }
    let sent = net::tcp_send2(fd, buf[..], "");
    if sent == -2 {
        return 0;
    }
    if sent <= 0 {
        let count = buf.len;
        buf.clear();
        return count;
    }
    let sent_i64 = sent as i64;
    buf.compact_wire_buffer(sent_i64);
    return sent_i64;
}
