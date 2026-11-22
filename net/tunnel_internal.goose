// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal helpers for Slowloris defense, HTTP CONNECT, SOCKS4/5, and MASQUE tunnels.
namespace net_internal;

import std;
import core;
import rfc.http;
import http.headers;
import .slowloris;
import .proxy;
import .http_connect;
import .socks5;
import .tcp;
import .masque;
import .internal;

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

inline fn has_ctrl_or_space_bytes(s: const u8[:]) -> bool {
    guard s.len > 0 else { return true; }
    for b in s {
        if b <= 0x20 || b >= 0x7F { return true; }
    }
    return false;
}

// Parses a strictly decimal TCP/UDP port string in 1..65535.
//
// Example:
//   port_slice = "8443"
//   returns: 8443, true
inline fn parse_strict_port_u16(port_slice: const u8[:]) -> u16, bool {
    guard port_slice.len > 0 && port_slice.len <= 5 else { return 0, false; }
    for b in port_slice {
        guard b >= '0' && b <= '9' else { return 0, false; }
    }
    let p_val, ok_p = port_slice.parse_u32_dec();
    guard ok_p && p_val >= 1 && p_val <= 65535 else { return 0, false; }
    return p_val as u16, true;
}

// Parses a bracketed IPv6 authority ("[::1]:443" or "[::1]" when port is optional).
//
// Example:
//   trimmed = "[2001:db8::1]:8443", default_port = 443, port_rule = net::PortRequirement.Required
//   returns: "2001:db8::1", 8443, true
inline fn parse_bracketed_authority(
    trimmed:      const u8[:],
    default_port: u16,
    port_rule:    net::PortRequirement,
) -> u8[..256], u16, bool {
    var host_out: u8[..256] = [];
    let close_i = trimmed.index_of_byte(']');
    guard close_i > 1 else { return host_out, 0, false; }
    let inner = trimmed[1..close_i];
    var comp_buf: u8[..64] = [];
    guard core::parse_and_compress_ipv6(inner, comp_buf) && host_out.try_set(inner) else {
        return host_out, 0, false;
    }
    let after_bracket = core::add_sat_i64(close_i, 1);
    if after_bracket == trimmed.len {
        guard port_rule == net::PortRequirement.Optional && default_port > 0 else {
            return host_out, 0, false;
        }
        return host_out, default_port, true;
    }
    let port_start = core::add_sat_i64(close_i, 2);
    guard port_start < trimmed.len && trimmed[after_bracket] == ':' else {
        return host_out, 0, false;
    }
    let port, ok_p = parse_strict_port_u16(trimmed[port_start..]);
    guard ok_p else { return host_out, 0, false; }
    return host_out, port, true;
}

fn is_valid_socks_domain(dom: const u8[:]) -> bool {
    guard dom.len >= 1 && dom.len <= 255 else { return false; }
    for b in dom {
        guard b > 0x20 && b < 0x7F else { return false; }
    }
    return true;
}

// Decodes a 4-byte IPv4 address + 2-byte port starting at `addr_off`.
//
// Example:
//   buf = [0x01, 127, 0, 0, 1, 0x00, 0x50], addr_off = 1
//   returns: net::SocksParseStatus.Ok, out.host = "127.0.0.1", out.port = 80
inline fn decode_socks5_atyp_ipv4(buf: const u8[:], addr_off: i64, out: net::SocksTarget&) -> net::SocksParseStatus {
    let total = core::add_sat_i64(addr_off, 6);
    guard buf.len >= total else { return net::SocksParseStatus.NeedMore; }
    let o0 = buf[addr_off];
    let o1 = buf[core::add_sat_i64(addr_off, 1)];
    let o2 = buf[core::add_sat_i64(addr_off, 2)];
    let o3 = buf[core::add_sat_i64(addr_off, 3)];
    out.ip = core::IpAddr {
        family: core::IpFamily.V4,
        bytes:  [o0, o1, o2, o3, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    };
    out.is_ip_literal = true;
    out.port = core::read_be_u16(buf, core::add_sat_i64(addr_off, 4));
    out.consumed = total;
    guard core::format_ip_addr(out.ip, out.host) else { return net::SocksParseStatus.Invalid; }
    return net::SocksParseStatus.Ok;
}

// Decodes a 16-byte IPv6 address + 2-byte port starting at `addr_off`.
//
// Example:
//   buf = [0x04, ...16 bytes..., 0x01, 0xBB], addr_off = 1
//   returns: net::SocksParseStatus.Ok, out.port = 443
inline fn decode_socks5_atyp_ipv6(buf: const u8[:], addr_off: i64, out: net::SocksTarget&) -> net::SocksParseStatus {
    let total = core::add_sat_i64(addr_off, 18);
    guard buf.len >= total else { return net::SocksParseStatus.NeedMore; }
    var ip = core::IpAddr { family: core::IpFamily.V6, .. };
    for i in 16 {
        ip.bytes[i] = buf[core::add_sat_i64(addr_off, i)];
    }
    out.ip = ip;
    out.is_ip_literal = true;
    out.port = core::read_be_u16(buf, core::add_sat_i64(addr_off, 16));
    out.consumed = total;
    guard core::format_ip_addr(out.ip, out.host) else { return net::SocksParseStatus.Invalid; }
    return net::SocksParseStatus.Ok;
}

// Decodes a length-prefixed domain name + 2-byte port starting at `addr_off`.
//
// Example:
//   buf = [0x03, 0x03, 'a', '.', 'b', 0x00, 0x50], addr_off = 1
//   returns: net::SocksParseStatus.Ok, out.host = "a.b", out.port = 80
inline fn decode_socks5_atyp_domain(buf: const u8[:], addr_off: i64, out: net::SocksTarget&) -> net::SocksParseStatus {
    guard buf.len > addr_off else { return net::SocksParseStatus.NeedMore; }
    let dlen = buf[addr_off] as i64;
    guard dlen >= 1 && dlen <= 255 else { return net::SocksParseStatus.Invalid; }
    let d_start = core::add_sat_i64(addr_off, 1);
    let p_off = core::add_sat_i64(d_start, dlen);
    let total = core::add_sat_i64(p_off, 2);
    guard buf.len >= total else { return net::SocksParseStatus.NeedMore; }

    let dom = buf[d_start..p_off];
    guard is_valid_socks_domain(dom) && out.host.try_set(dom) else { return net::SocksParseStatus.Invalid; }
    let lit_ip, is_lit = core::parse_ip_addr(dom);
    if is_lit {
        out.is_ip_literal = true;
        out.ip = lit_ip;
    }
    out.port = core::read_be_u16(buf, p_off);
    out.consumed = total;
    return net::SocksParseStatus.Ok;
}

// Decodes a SOCKS5 [ATYP DST.ADDR DST.PORT] body starting at `atyp_off`.
//
// Example:
//   buf = [0x01, 93, 184, 216, 34, 0x01, 0xBB], atyp_off = 0
//   returns: out populated with 93.184.216.34:443, consumed = 7, net::SocksParseStatus.Ok
fn decode_socks5_atyp_target(buf: const u8[:], atyp_off: i64, out: net::SocksTarget&) -> net::SocksParseStatus {
    guard atyp_off >= 0 && atyp_off < buf.len else { return net::SocksParseStatus.NeedMore; }
    let atyp = buf[atyp_off];
    let addr_off = core::add_sat_i64(atyp_off, 1);

    if atyp == rfc::SOCKS5_ATYP_IPV4 {
        return decode_socks5_atyp_ipv4(buf, addr_off, out);
    }
    if atyp == rfc::SOCKS5_ATYP_IPV6 {
        return decode_socks5_atyp_ipv6(buf, addr_off, out);
    }
    if atyp == rfc::SOCKS5_ATYP_DOMAIN {
        return decode_socks5_atyp_domain(buf, addr_off, out);
    }
    return net::SocksParseStatus.Unsupported;
}

inline fn append_socks5_addr_and_port(ip: const core::IpAddr&, port: u16, out: u8[..32]&) -> bool {
    if ip.family == core::IpFamily.V6 {
        let _ = out.try_push(rfc::SOCKS5_ATYP_IPV6);
        let _ = out.try_append(ip.bytes[..]);
    } else if ip.family == core::IpFamily.V4 {
        let _ = out.try_push(rfc::SOCKS5_ATYP_IPV4);
        let _ = out.try_append(ip.bytes[..4]);
    } else {
        let _ = out.try_push(rfc::SOCKS5_ATYP_IPV4);
        let z4: u8[4] = [0, 0, 0, 0];
        let _ = out.try_append(z4[..]);
    }
    let port_be: u8[2] = [((port >> 8) & 0xFF) as u8, (port & 0xFF) as u8];
    return out.try_append(port_be[..]);
}

fn find_null_byte_bounded(buf: const u8[:], start: i64, max_len: i64) -> i64 {
    guard start >= 0 && max_len >= 0 else { return -1; }
    let limit = min(buf.len, core::add_sat_i64(start, max_len));
    var pos = start;
    while pos < limit {
        if buf[pos] == 0 { return pos; }
        pos = core::add_sat_i64(pos, 1);
    }
    return -1;
}

inline fn read_socks4a_domain_target(
    buf:       const u8[:],
    dom_start: i64,
    out:       net::SocksTarget&,
) -> net::SocksParseStatus {
    let dom_null = find_null_byte_bounded(buf, dom_start, 256);
    if dom_null < 0 {
        if buf.len >= core::add_sat_i64(dom_start, 256) { return net::SocksParseStatus.Invalid; }
        return net::SocksParseStatus.NeedMore;
    }
    let dom = buf[dom_start..dom_null];
    guard is_valid_socks_domain(dom) && out.host.try_set(dom) else {
        return net::SocksParseStatus.Invalid;
    }
    let lit_ip, is_lit = core::parse_ip_addr(dom);
    if is_lit {
        out.is_ip_literal = true;
        out.ip = lit_ip;
    }
    out.consumed = core::add_sat_i64(dom_null, 1);
    return net::SocksParseStatus.Ok;
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

// RFC 9484 Section 4.7.1: ADDRESS_ASSIGN Capsule - empty payload removes all assigned addresses
fn apply_assigned_ip(tunnel: net::MasqueTunnelSession&, payload: const u8[:]) -> bool {
    let assign, ok_a = net::decode_address_assign_capsule(payload);
    guard ok_a else { return false; }
    if payload.len == 0 {
        tunnel.assigned_ip.clear();
        tunnel.assigned_prefix_len = 0;
        return true;
    }
    guard assign.assigned_ip.len > 0 && !is_all_zero_ip_bytes(assign.assigned_ip[..]) else {
        return false;
    }
    guard tunnel.assigned_ip.try_set(assign.assigned_ip[..]) else { return false; }
    tunnel.assigned_prefix_len = assign.prefix_len;
    return true;
}
