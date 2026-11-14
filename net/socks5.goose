// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 1928 & RFC 1929 SOCKS5/5h wire codecs and client handshake.
namespace wing;

import std;
import core from "..";
import .proxy;
import .tcp;

enum Socks5Error {
    None,
    InvalidVersion,
    NoAcceptableAuth,
    AuthFailed,
    InvalidAuthResponse,
    InvalidReplyHeader,
    ServerFailure,
    ConnectionNotAllowed,
    NetworkUnreachable,
    HostUnreachable,
    ConnectionRefused,
    TtlExpired,
    CommandNotSupported,
    AddressTypeNotSupported,
    BufferTruncated,
}

// Options for SOCKS5 greeting negotiation.
struct Socks5GreetingOptions {
    has_credentials: bool = false,
    enable_gssapi:   bool = false,
}

// Builds Phase 1 Greeting frame [VER, NAUTH, AUTH...].
fn build_socks5_greeting(
    opts: Socks5GreetingOptions,
    out:  u8[..16]&,
) {
    out.clear();
    out.push(rfc::SOCKS5_VER);
    out.push(0); // NAUTH placeholder
    out.push(rfc::SOCKS5_AUTH_NONE);
    if opts.has_credentials {
        out.push(rfc::SOCKS5_AUTH_USERPASS);
    }
    if opts.enable_gssapi {
        out.push(rfc::SOCKS5_AUTH_GSSAPI);
    }
    out[1] = core::sub_sat_i64(out.len, 2) as u8;
}

// Parses Phase 1 Server Greeting Reply [VER, METHOD] (RFC 1928 Section 3).
//
// Example:
//   buf = [0x05, 0x00]
//   returns: 0x00, Socks5Error.None
fn parse_socks5_greeting_reply(buf: const u8[:]) -> u8, Socks5Error {
    guard buf.len >= 2 else { return 0xFF, Socks5Error.BufferTruncated; }
    // RFC 1928 Section 3: Procedure for TCP-based clients - server selection message is 2 octets
    guard buf.len == 2 else { return 0xFF, Socks5Error.InvalidReplyHeader; }
    guard buf[0] == rfc::SOCKS5_VER else { return 0xFF, Socks5Error.InvalidVersion; }
    let selected_method = buf[1];
    if selected_method == rfc::SOCKS5_AUTH_NO_ACCEPTABLE {
        return 0xFF, Socks5Error.NoAcceptableAuth;
    }
    return selected_method, Socks5Error.None;
}

// Builds Phase 2 RFC 1929 Username/Password Subnegotiation [0x01, ULEN, UNAME, PLEN, PASSWD].
// Invariant: First byte MUST be 0x01, NOT 0x05!
fn build_socks5_rfc1929_auth(
    username: const u8[:],
    password: const u8[:],
    out:      u8[..520]&,
) -> Socks5Error {
    out.clear();
    guard username.len >= 1 && username.len <= 255 else { return Socks5Error.AuthFailed; }
    guard password.len >= 1 && password.len <= 255 else { return Socks5Error.AuthFailed; }

    out.push(rfc::SOCKS5_RFC1929_VER);
    out.push(username.len as u8);
    out.append(username);
    out.push(password.len as u8);
    out.append(password);

    return Socks5Error.None;
}

// Parses Phase 2 RFC 1929 Reply [0x01, STATUS] (RFC 1929 Section 2).
//
// Example:
//   buf = [0x01, 0x00]
//   returns: Socks5Error.None
fn parse_socks5_rfc1929_reply(buf: const u8[:]) -> Socks5Error {
    guard buf.len >= 2 else { return Socks5Error.BufferTruncated; }
    // RFC 1929 Section 2: Initial negotiation - authentication reply frame is exactly 2 octets
    guard buf.len == 2 else { return Socks5Error.InvalidReplyHeader; }
    guard buf[0] == rfc::SOCKS5_RFC1929_VER else { return Socks5Error.InvalidAuthResponse; }
    if buf[1] != 0x00 {
        return Socks5Error.AuthFailed;
    }
    return Socks5Error.None;
}

// Builds Phase 3 Connect Request [VER=0x05, CMD=0x01, RSV=0x00, ATYP, DST.ADDR, DST.PORT].
// Enforces socks5:// (local DNS ATYP=0x01/0x04) vs socks5h:// (proxy DNS ATYP=0x03) distinction.
fn build_socks5_connect_request(
    scheme:        ProxyScheme,
    host_str:      const u8[:],
    resolved_ipv4: const u8[4]&,
    has_ipv4:      bool,
    port:          u16,
    out:           u8[..300]&,
) -> Socks5Error {
    out.clear();
    out.push(rfc::SOCKS5_VER);
    out.push(rfc::SOCKS5_CMD_CONNECT);
    out.push(0x00);

    if scheme == ProxyScheme.Socks5h {
        guard host_str.len >= 1 && host_str.len <= 255 else { return Socks5Error.AddressTypeNotSupported; }
        out.push(rfc::SOCKS5_ATYP_DOMAIN);
        out.push(host_str.len as u8);
        out.append(host_str);
    } else if has_ipv4 {
        out.push(rfc::SOCKS5_ATYP_IPV4);
        out.append(resolved_ipv4[..]);
    } else {
        return Socks5Error.AddressTypeNotSupported;
    }

    out.append_u16_be(port);
    return Socks5Error.None;
}

// Builds a binary SOCKS5 CONNECT request with IPv6 or domain destination (RFC 1928 §4).
//
// Example:
//   scheme = Socks5, resolved_ipv6 = [0; 16], port = 80
//   returns: Socks5Error.None, out populated with SOCKS5 connect frame
fn build_socks5_connect_request_v6(
    scheme:        ProxyScheme,
    host_str:      const u8[:],
    resolved_ipv6: const u8[16]&,
    has_ipv6:      bool,
    port:          u16,
    out:           u8[..300]&,
) -> Socks5Error {
    out.clear();
    out.push(rfc::SOCKS5_VER);
    out.push(rfc::SOCKS5_CMD_CONNECT);
    out.push(0x00);

    if scheme == ProxyScheme.Socks5h {
        guard host_str.len >= 1 && host_str.len <= 255 else { return Socks5Error.AddressTypeNotSupported; }
        out.push(rfc::SOCKS5_ATYP_DOMAIN);
        out.push(host_str.len as u8);
        out.append(host_str);
    } else if has_ipv6 {
        out.push(rfc::SOCKS5_ATYP_IPV6);
        out.append(resolved_ipv6[..]);
    } else {
        return Socks5Error.AddressTypeNotSupported;
    }

    out.append_u16_be(port);
    return Socks5Error.None;
}

struct Socks5Reply {
    reply_code:     u8  = 0,
    atyp:           u8  = 0,
    bound_port:     u16 = 0,
    bytes_consumed: i64 = 0,
}

// Calculates expected wire length of SOCKS5 connect reply based on ATYP (RFC 1928 Section 5).
fn socks5_needed_length(buf: const u8[:], atyp: u8) -> i64, Socks5Error {
    if buf[2] != 0 {
        return 0, Socks5Error.InvalidReplyHeader;
    }
    if atyp != rfc::SOCKS5_ATYP_IPV4 && atyp != rfc::SOCKS5_ATYP_IPV6 && atyp != rfc::SOCKS5_ATYP_DOMAIN {
        return 0, Socks5Error.AddressTypeNotSupported;
    }
    if atyp == rfc::SOCKS5_ATYP_DOMAIN && buf.len < 5 {
        return 0, Socks5Error.BufferTruncated;
    }
    if buf.len >= 5 {
        let expected_len = core::socks5_expected_frame_len_ct(buf);
        if expected_len > 0 {
            return expected_len, Socks5Error.None;
        }
    }
    if atyp == rfc::SOCKS5_ATYP_IPV4 { return 10, Socks5Error.None; }
    if atyp == rfc::SOCKS5_ATYP_IPV6 { return 22, Socks5Error.None; }
    return 0, Socks5Error.AddressTypeNotSupported;
}

// Maps RFC 1928 REP octet to corresponding Socks5Error variant.
fn socks5_rep_to_error(rep: u8) -> Socks5Error {
    if rep == rfc::SOCKS5_REP_SUCCEEDED { return Socks5Error.None; }
    if rep == rfc::SOCKS5_REP_GENERAL_FAILURE { return Socks5Error.ServerFailure; }
    if rep == rfc::SOCKS5_REP_NOT_ALLOWED { return Socks5Error.ConnectionNotAllowed; }
    if rep == rfc::SOCKS5_REP_NET_UNREACHABLE { return Socks5Error.NetworkUnreachable; }
    if rep == rfc::SOCKS5_REP_HOST_UNREACHABLE { return Socks5Error.HostUnreachable; }
    if rep == rfc::SOCKS5_REP_CONN_REFUSED { return Socks5Error.ConnectionRefused; }
    if rep == rfc::SOCKS5_REP_TTL_EXPIRED { return Socks5Error.TtlExpired; }
    if rep == rfc::SOCKS5_REP_CMD_NOT_SUPPORTED { return Socks5Error.CommandNotSupported; }
    return Socks5Error.AddressTypeNotSupported;
}

// Parses Phase 4 Server Connect Reply [VER=0x05, REP, RSV=0x00, ATYP, BND.ADDR, BND.PORT].
// Completely consumes bound address and port to ensure no leftover protocol bytes.
//
// Example:
//   buf = [0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x1f, 0x90]
//   returns: Socks5Reply { reply_code: 0, bound_port: 8080 }, Socks5Error.None
fn parse_socks5_connect_reply(buf: const u8[:]) -> Socks5Reply, Socks5Error {
    guard buf.len >= 4 else { return Socks5Reply { .. }, Socks5Error.BufferTruncated; }
    guard buf[0] == rfc::SOCKS5_VER else { return Socks5Reply { .. }, Socks5Error.InvalidVersion; }

    let rep = buf[1];
    let atyp = buf[3];
    let needed_len, err = socks5_needed_length(buf, atyp);
    guard err == Socks5Error.None else { return Socks5Reply { .. }, err; }
    guard buf.len >= needed_len else { return Socks5Reply { .. }, Socks5Error.BufferTruncated; }
    // RFC 1928 Section 6: Replies - reject trailing bytes beyond the reply frame boundary
    guard buf.len == needed_len else { return Socks5Reply { .. }, Socks5Error.InvalidReplyHeader; }

    let bnd_port = core::read_be_u16(buf, core::sub_sat_i64(needed_len, 2));

    let res = Socks5Reply {
        reply_code:     rep,
        atyp:           atyp,
        bound_port:     bnd_port,
        bytes_consumed: needed_len,
    };

    return res, socks5_rep_to_error(rep);
}

// Parses a dotted-decimal IPv4 literal (e.g. "127.0.0.1") into 4 network-order octets.
//
// Example:
//   raw = "127.0.0.1"
//   returns: [127, 0, 0, 1], true
fn parse_socks5_ipv4_literal(raw: const u8[:]) -> u8[4], bool {
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

fn recv_exact_socks5_bytes(sock_fd: i64, dst: u8[:], timeout_ms: u32) -> bool {
    var off: i64 = 0;
    while off < dst.len {
        let n = tcp_recv_slice(sock_fd, dst[off..], timeout_ms);
        guard n > 0 else { return false; }
        off = core::add_sat_i64(off, n);
    }
    return true;
}

fn recv_socks5_connect_reply_wire(
    sock_fd:    i64,
    buf:        u8[300]&,
    timeout_ms: u32,
) -> i64, Socks5Error {
    // RFC 1928 Section 6: Replies - read 4-octet header, then exact BND.ADDR + BND.PORT without over-reading tunnel
    guard recv_exact_socks5_bytes(sock_fd, buf[..4], timeout_ms) else {
        return 0, Socks5Error.BufferTruncated;
    }
    var have: i64 = 4;
    if buf[3] == rfc::SOCKS5_ATYP_DOMAIN {
        guard recv_exact_socks5_bytes(sock_fd, buf[4..5], timeout_ms) else {
            return 0, Socks5Error.BufferTruncated;
        }
        have = 5;
    }
    let needed_len, len_err = socks5_needed_length(buf[..have], buf[3]);
    guard len_err == Socks5Error.None else { return 0, len_err; }
    guard needed_len >= have && needed_len <= 300 else {
        return 0, Socks5Error.InvalidReplyHeader;
    }
    if needed_len > have {
        guard recv_exact_socks5_bytes(sock_fd, buf[have..needed_len], timeout_ms) else {
            return 0, Socks5Error.BufferTruncated;
        }
    }
    return needed_len, Socks5Error.None;
}

// Executes a live SOCKS5/SOCKS5h client handshake over an open TCP socket (RFC 1928 & RFC 1929).
fn socks5_client_handshake(
    sock_fd:     i64,
    scheme:      ProxyScheme,
    target_host: const u8[:],
    target_port: u16,
    username:    const u8[:],
    password:    const u8[:],
    timeout_ms:  u32 = 5000,
) -> Socks5Error {
    guard sock_fd > 0 else { return Socks5Error.ServerFailure; }
    var greet: u8[..16] = [];
    build_socks5_greeting(Socks5GreetingOptions { has_credentials: username.len > 0, .. }, greet);
    guard tcp_send(sock_fd, greet[..]) == (greet.len as i32) else { return Socks5Error.ServerFailure; }

    var reply_raw: u8[2] = [0; 2];
    guard recv_exact_socks5_bytes(sock_fd, reply_raw[..], timeout_ms) else {
        return Socks5Error.BufferTruncated;
    }
    let method, g_err = parse_socks5_greeting_reply(reply_raw[..]);
    guard g_err == Socks5Error.None else { return g_err; }

    if method == rfc::SOCKS5_AUTH_USERPASS {
        var auth_buf: u8[..520] = [];
        let a_err = build_socks5_rfc1929_auth(username, password, auth_buf);
        defer core::secure_zeroize_slice(auth_buf[..]);
        guard a_err == Socks5Error.None else { return a_err; }
        guard tcp_send(sock_fd, auth_buf[..]) == (auth_buf.len as i32) else { return Socks5Error.AuthFailed; }
        guard recv_exact_socks5_bytes(sock_fd, reply_raw[..], timeout_ms) else {
            return Socks5Error.BufferTruncated;
        }
        let auth_res = parse_socks5_rfc1929_reply(reply_raw[..]);
        guard auth_res == Socks5Error.None else { return auth_res; }
    } else if method != rfc::SOCKS5_AUTH_NONE {
        return Socks5Error.NoAcceptableAuth;
    }

    var req_buf: u8[..300] = [];
    let ip4, has_ip4 = parse_socks5_ipv4_literal(target_host);
    var effective_scheme = scheme;
    if scheme == ProxyScheme.Socks5 && !has_ip4 {
        effective_scheme = ProxyScheme.Socks5h;
    }
    let req_err = build_socks5_connect_request(effective_scheme, target_host, ip4, has_ip4, target_port, req_buf);
    guard req_err == Socks5Error.None else { return req_err; }
    guard tcp_send(sock_fd, req_buf[..]) == (req_buf.len as i32) else { return Socks5Error.ServerFailure; }

    var conn_reply_raw: u8[300] = [0; 300];
    let exact_len, r_err = recv_socks5_connect_reply_wire(sock_fd, conn_reply_raw, timeout_ms);
    guard r_err == Socks5Error.None else { return r_err; }
    let _, c_err = parse_socks5_connect_reply(conn_reply_raw[..exact_len]);
    return c_err;
}
