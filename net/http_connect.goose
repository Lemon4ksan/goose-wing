// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 9110 §9.3.6 HTTP CONNECT tunnel codec and header sanitizer.
namespace wing;

import std;
import core from "..";
import .tcp;

enum ConnectTunnelError {
    None,
    InvalidStatusLine,
    ProxyAuthRequired,
    ConnectFailed,
    TunnelBufferedTooManyBytes, // OkHttp leftover buffer defense
    MalformedHeaders,
}

inline fn has_crlf_or_null(s: const u8[:]) -> bool {
    for b in s {
        if b == '\r' || b == '\n' || b == 0 {
            return true;
        }
    }
    return false;
}

fn append_connect_line(out: u8[..1024]&, host: const u8[:], port: u16) {
    if host.len > 0 && !has_crlf_or_null(host) && !host.contains_byte(' ') && !host.contains_byte('\t') {
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

// Builds an isolated HTTP CONNECT request for tunneling through proxy.
fn build_http_connect_request(
    target_host: const u8[:],
    target_port: u16,
    proxy_auth:  const u8[:],
    user_agent:  const u8[:],
    out:         u8[..1024]&,
) {
    out.clear();
    append_connect_line(out, target_host, target_port);
    guard out.len > 0 else { return; }
    append_sanitized_header(out, "Proxy-Authorization: ", proxy_auth);
    append_sanitized_header(out, "User-Agent: ", user_agent);
    out.append("Proxy-Connection: Keep-Alive\r\n\r\n");
}

fn is_token_in_connection_headers(headers: const HeaderMap&, target_name: const u8[:]) -> bool {
    for idx in 0..headers.entries.len {
        let e = headers.entries[idx];
        guard entry_name(headers, e).eq_ascii_fold("connection") else { continue; }
        var rest: const u8[:] = entry_value(headers, e);
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

// Strips Proxy-Authorization, Proxy-Connection, standard hop-by-hop headers,
// and Connection tokens so credentials never leak to origin (RFC 9110 §7.6.1 & Go #16875).
//
// Example:
//   headers contains [("Proxy-Authorization", "Basic ..."), ("Host", "example.com")]
//   after: headers contains only [("Host", "example.com")]
fn sanitize_tunnel_headers_for_origin(headers: HeaderMap&) {
    let orig_headers = headers;
    var write_entry_i: i64 = 0;
    var write_raw_pos: u16 = 0;
    let total_entries = orig_headers.entries.len;
    for read_i in total_entries {
        let h_name = entry_name(orig_headers, orig_headers.entries[read_i]);
        let drop = is_hop_by_hop_header_name(h_name) || is_token_in_connection_headers(orig_headers, h_name);
        if !drop {
            compact_kept_entry_in_place(headers, read_i, write_entry_i, write_raw_pos);
        }
    }
    if write_entry_i < total_entries {
        finish_in_place_compaction(headers, write_entry_i, write_raw_pos);
    }
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
//   returns: status_code = 200, block_end = 19, err = ConnectTunnelError.None
fn parse_connect_response_block(buf: const u8[:]) -> i32, i64, ConnectTunnelError {
    guard buf.len >= 12 else { return 0, 0, ConnectTunnelError.InvalidStatusLine; }
    guard buf.starts_with("HTTP/1.") else { return 0, 0, ConnectTunnelError.InvalidStatusLine; }

    let delim_idx = find(buf, "\r\n\r\n");
    guard delim_idx >= 0 else { return 0, 0, ConnectTunnelError.MalformedHeaders; }
    let header_end_pos = core::add_sat_i64(delim_idx, 4);

    let first_crlf = find(buf[..header_end_pos], "\r\n");
    guard first_crlf >= 12 else { return 0, 0, ConnectTunnelError.MalformedHeaders; }

    let minor_ver = buf[7];
    guard (minor_ver == '0' || minor_ver == '1') && buf[8] == ' ' else {
        return 0, 0, ConnectTunnelError.InvalidStatusLine;
    }

    let d0 = buf[9];
    let d1 = buf[10];
    let d2 = buf[11];
    guard core::is_ascii_digit(d0) && core::is_ascii_digit(d1) && core::is_ascii_digit(d2) else {
        return 0, 0, ConnectTunnelError.InvalidStatusLine;
    }
    // RFC 9112 Section 4: Status Line - 3-digit status-code MUST be followed by a single SP
    guard first_crlf >= 13 && buf[12] == ' ' && is_valid_connect_reason_phrase(buf[13..first_crlf]) else {
        return 0, 0, ConnectTunnelError.InvalidStatusLine;
    }

    let code, ok_code = buf[9..12].parse_i32_dec();
    guard ok_code else { return 0, 0, ConnectTunnelError.InvalidStatusLine; }
    return code, header_end_pos, ConnectTunnelError.None;
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
        let st, end_pos, err = parse_connect_response_block(cur);
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
        if has_final_connect_header_terminator(resp_buf[..]) {
            break;
        }
    }
    return verify_connect_tunnel_response(resp_buf[..], 0);
}
