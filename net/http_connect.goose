// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9110 §9.3.6 HTTP CONNECT tunnel codec and header sanitizer.
namespace net;

import std;
import core from "..";
import .tcp;
import .internal;

enum ConnectTunnelError {
    None,
    InvalidStatusLine,
    ProxyAuthRequired,
    ConnectFailed,
    TunnelBufferedTooManyBytes, // OkHttp leftover buffer defense
    MalformedHeaders,
}

// Builds an isolated HTTP CONNECT request for tunneling through proxy.
fn build_http_connect_request(
    target_host: const u8[:],
    target_port: u16,
    proxy_auth:  const u8[:],
    user_agent:  const u8[:],
    out:         u8[..1024]&,
) {
    guard net_internal::is_valid_connect_host(target_host) else { return; }
    out.clear();
    net_internal::append_connect_line(out, target_host, target_port);
    net_internal::append_sanitized_header(out, "Proxy-Authorization: ", proxy_auth);
    net_internal::append_sanitized_header(out, "User-Agent: ", user_agent);
    out.append("Proxy-Connection: Keep-Alive\r\n\r\n");
}

// Strips Proxy-Authorization, Proxy-Connection, standard hop-by-hop headers,
// and Connection tokens so credentials never leak to origin (RFC 9110 §7.6.1 & Go #16875).
//
// Example:
//   headers contains [("Proxy-Authorization", "Basic ..."), ("Host", "example.com")]
//   after: headers contains only [("Host", "example.com")]
fn sanitize_tunnel_headers_for_origin(headers: http::HeaderMap&) {
    let orig_headers = headers;
    var write_entry_i: i64 = 0;
    var write_raw_pos: u16 = 0;
    let total_entries = orig_headers.entries.len;
    for read_i in total_entries {
        let h_name = http::entry_name(orig_headers, orig_headers.entries[read_i]);
        let drop = http::is_hop_by_hop_header_name(h_name) ||
            net_internal::is_token_in_connection_headers(orig_headers, h_name);
        if !drop {
            http::compact_kept_entry_in_place(headers, read_i, write_entry_i, write_raw_pos);
        }
    }
    if write_entry_i < total_entries {
        http::finish_in_place_compaction(headers, write_entry_i, write_raw_pos);
    }
}

// Inspects HTTP CONNECT response and defends against data injection before TLS handshake.
// OkHttp RealConnection parity: "TLS tunnel buffered too many bytes".
fn verify_connect_tunnel_response(
    raw_response:        const u8[:],
    sink_buffered_bytes: i64 = 0,
) -> ConnectTunnelError {
    var cur = raw_response;
    var code:      i32 = 0;
    var block_end: i64 = 0;
    for _ in 5 {
        let st, end_pos, err = net_internal::parse_connect_response_block(cur);
        guard err == ConnectTunnelError.None else { return err; }
        code = st;
        block_end = end_pos;
        // RFC 9110 Section 15.2: Informational 1xx - skip interim 1xx (excluding 101) before final status
        if code >= 100 && code < 200 && code != 101 {
            cur = cur[block_end..];
            guard cur.len > 0 else { return ConnectTunnelError.MalformedHeaders; }
            continue;
        }
        break;
    }
    guard !(code >= 100 && code < 200) else { return ConnectTunnelError.ConnectFailed; }

    if code == 407 {
        return ConnectTunnelError.ProxyAuthRequired;
    }
    // RFC 9110 Section 9.3.6: CONNECT - any 2xx (Successful) response switches to tunnel mode
    if code < 200 || code >= 300 {
        return ConnectTunnelError.ConnectFailed;
    }

    if cur.len > block_end || sink_buffered_bytes > 0 {
        return ConnectTunnelError.TunnelBufferedTooManyBytes;
    }

    return ConnectTunnelError.None;
}

// CVE-2026-56866 defense: Whether a failed or rejected CONNECT response requires
// the underlying transport connection to be closed immediately rather than returned to pool.
fn should_close_connection_on_connect_error(err: ConnectTunnelError) -> bool {
    return err != ConnectTunnelError.None;
}

// Executes a live HTTP CONNECT client tunnel handshake over an open TCP socket (RFC 9110 Section 9.3.6).
fn http_connect_client_handshake(
    sock_fd:     i64,
    target_host: const u8[:],
    target_port: u16,
    proxy_auth:  const u8[:],
    user_agent:  const u8[:],
    timeout_ms:  u32 = 5000,
) -> ConnectTunnelError {
    guard sock_fd > 0 else { return ConnectTunnelError.ConnectFailed; }
    var req_buf: u8[..1024] = [];
    build_http_connect_request(target_host, target_port, proxy_auth, user_agent, req_buf);
    guard req_buf.len > 0 && tcp_send(sock_fd, req_buf[..]) == (req_buf.len as i32) else {
        return ConnectTunnelError.ConnectFailed;
    }

    var resp_buf: u8[..4096] = [];
    var chunk:    u8[1024]   = [0; 1024];
    for _ in 8 {
        let n = tcp_recv_slice(sock_fd, chunk[..], timeout_ms);
        guard n > 0 else { break; }
        guard resp_buf.try_append(chunk[..n]) else { return ConnectTunnelError.TunnelBufferedTooManyBytes; }
        if net_internal::has_final_connect_header_terminator(resp_buf[..]) {
            break;
        }
    }
    return verify_connect_tunnel_response(resp_buf[..], 0);
}

// ---- Authority Host:Port & Basic Proxy-Auth Decoders ---------------------

enum PortRequirement {
    Optional,
    Required,
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
//   trimmed = "[2001:db8::1]:8443", default_port = 443, port_rule = PortRequirement.Required
//   returns: "2001:db8::1", 8443, true
inline fn parse_bracketed_authority(
    trimmed:      const u8[:],
    default_port: u16,
    port_rule:    PortRequirement,
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
        guard port_rule == PortRequirement.Optional && default_port > 0 else {
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

// Parses `host:port`, `[ipv6]:port`, or bare `host`/`[ipv6]` using `default_port` when optional.
//
// Example:
//   raw = "[2001:db8::1]:8443", default_port = 443, port_rule = PortRequirement.Required
//   returns: "2001:db8::1", 8443, true
fn parse_authority_host_port(
    raw:          const u8[:],
    default_port: u16,
    port_rule:    PortRequirement,
) -> u8[..256], u16, bool {
    var host_out: u8[..256] = [];
    let trimmed = raw.trim_lws();
    guard trimmed.len > 0 && !has_ctrl_or_space_bytes(trimmed) else { return host_out, 0, false; }

    if trimmed[0] == '[' {
        return parse_bracketed_authority(trimmed, default_port, port_rule);
    }

    let col = trimmed.index_of_byte(':');
    if col < 0 {
        guard port_rule == PortRequirement.Optional && default_port > 0 else {
            return host_out, 0, false;
        }
        guard !trimmed.contains_byte(']') && host_out.try_set(trimmed) else { return host_out, 0, false; }
        return host_out, default_port, true;
    }
    let p_start = core::add_sat_i64(col, 1);
    let h_part = trimmed[..col];
    let p_part = trimmed[p_start..];
    guard h_part.len > 0 && !h_part.contains_byte(']') && !p_part.contains_byte(':') else {
        return host_out, 0, false;
    }
    let port, ok_p = parse_strict_port_u16(p_part);
    guard ok_p && host_out.try_set(h_part) else { return host_out, 0, false; }
    return host_out, port, true;
}

// Decodes an HTTP `Proxy-Authorization: Basic <base64(login:password)>` credential header.
// Wipes intermediate buffers and resets outputs on any malformed input.
//
// Example:
//   header_val = "Basic dXNlcjpwYXNz"
//   returns: true, out_login = "user", out_pwd = "pass"
fn decode_basic_proxy_auth(
    header_val: const u8[:],
    out_login:  u8[..128]&,
    out_pwd:    u8[..256]&,
) -> bool {
    out_login.clear();
    if out_pwd.len > 0 {
        core::secure_zeroize_slice(out_pwd[..]);
        out_pwd.clear();
    }

    let b64_raw, has_basic = header_val.trim_lws().strip_prefix_fold("Basic ");
    guard has_basic else { return false; }
    let b64 = b64_raw.trim_lws();
    guard b64.len >= 4 && b64.len <= 1024 else { return false; }

    var decoded_buf: u8[..1024] = [];
    defer core::secure_zeroize_slice(decoded_buf[..]);
    guard core::base64_decode(b64, decoded_buf) else { return false; }

    let user, pwd, has_col = decoded_buf[..].split_once_byte(':');
    guard has_col && user.len > 0 else { return false; }
    guard out_login.try_set(user) else { return false; }
    guard out_pwd.try_set(pwd) else {
        out_login.clear();
        return false;
    }
    return true;
}
