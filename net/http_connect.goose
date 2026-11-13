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

// Inspects HTTP CONNECT response and defends against data injection before TLS handshake.
// OkHttp RealConnection parity: "TLS tunnel buffered too many bytes".
fn verify_connect_tunnel_response(
    raw_response:        const u8[:],
    sink_buffered_bytes: i64 = 0,
) -> ConnectTunnelError {
    guard raw_response.len >= 12 else { return ConnectTunnelError.InvalidStatusLine; }
    guard raw_response.starts_with("HTTP/1.") else { return ConnectTunnelError.InvalidStatusLine; }

    let delim_idx = find(raw_response, "\r\n\r\n");
    guard delim_idx >= 0 else { return ConnectTunnelError.MalformedHeaders; }
    let header_end_pos = core::add_sat_i64(delim_idx, 4);

    let first_crlf = find(raw_response[..header_end_pos], "\r\n");
    guard first_crlf >= 12 else { return ConnectTunnelError.MalformedHeaders; }

    let minor_ver = raw_response[7];
    guard (minor_ver == '0' || minor_ver == '1') && raw_response[8] == ' ' else {
        return ConnectTunnelError.InvalidStatusLine;
    }

    let d0 = raw_response[9];
    let d1 = raw_response[10];
    let d2 = raw_response[11];
    guard d0 >= '0' && d0 <= '9' && d1 >= '0' && d1 <= '9' && d2 >= '0' && d2 <= '9' else {
        return ConnectTunnelError.InvalidStatusLine;
    }
    if first_crlf > 12 {
        guard raw_response[12] == ' ' else {
            return ConnectTunnelError.InvalidStatusLine;
        }
    }

    let status_code_str = raw_response[9..12];
    if status_code_str == "407" {
        return ConnectTunnelError.ProxyAuthRequired;
    }
    if status_code_str != "200" {
        return ConnectTunnelError.ConnectFailed;
    }

    if raw_response.len > header_end_pos || sink_buffered_bytes > 0 {
        return ConnectTunnelError.TunnelBufferedTooManyBytes;
    }

    return ConnectTunnelError.None;
}

// CVE-2026-56866 defense: Whether a failed or rejected CONNECT response requires
// the underlying transport connection to be closed immediately rather than returned to pool.
fn should_close_connection_on_connect_error(err: ConnectTunnelError) -> bool {
    return err != ConnectTunnelError.None;
}

// Executes a live HTTP CONNECT client tunnel handshake over an open TCP socket (RFC 9110 §9.3.6).
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
    guard tcp_send(sock_fd, req_buf[..]) == (req_buf.len as i32) else { return ConnectTunnelError.ConnectFailed; }

    var resp_buf: u8[..4096] = [];
    var chunk:    u8[1024]   = [0; 1024];
    for step in 8 {
        let n = tcp_recv_slice(sock_fd, chunk[..], timeout_ms);
        guard n > 0 else { break; }
        guard resp_buf.try_append(chunk[..n]) else { return ConnectTunnelError.TunnelBufferedTooManyBytes; }
        if find(resp_buf[..], "\r\n\r\n") >= 0 {
            break;
        }
    }
    return verify_connect_tunnel_response(resp_buf[..], 0);
}
