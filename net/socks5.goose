// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RFC 1928 & RFC 1929 SOCKS5/5h wire codecs and client handshake.
namespace net;

import std;
import core from "..";
import .proxy;
import .tcp;
import .internal;

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
    guard username.len >= 1 && username.len <= 255 else { return Socks5Error.AuthFailed; }
    guard password.len >= 1 && password.len <= 255 else { return Socks5Error.AuthFailed; }

    out.clear();
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
    let is_domain = scheme == ProxyScheme.Socks5h;
    if is_domain {
        guard host_str.len >= 1 && host_str.len <= 255 else { return Socks5Error.AddressTypeNotSupported; }
    } else {
        guard has_ipv4 else { return Socks5Error.AddressTypeNotSupported; }
    }

    out.clear();
    out.push(rfc::SOCKS5_VER);
    out.push(rfc::SOCKS5_CMD_CONNECT);
    out.push(0x00);

    if is_domain {
        out.push(rfc::SOCKS5_ATYP_DOMAIN);
        out.push(host_str.len as u8);
        out.append(host_str);
    } else {
        out.push(rfc::SOCKS5_ATYP_IPV4);
        out.append(resolved_ipv4[..]);
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
    let is_domain = scheme == ProxyScheme.Socks5h;
    if is_domain {
        guard host_str.len >= 1 && host_str.len <= 255 else { return Socks5Error.AddressTypeNotSupported; }
    } else {
        guard has_ipv6 else { return Socks5Error.AddressTypeNotSupported; }
    }

    out.clear();
    out.push(rfc::SOCKS5_VER);
    out.push(rfc::SOCKS5_CMD_CONNECT);
    out.push(0x00);

    if is_domain {
        out.push(rfc::SOCKS5_ATYP_DOMAIN);
        out.push(host_str.len as u8);
        out.append(host_str);
    } else {
        out.push(rfc::SOCKS5_ATYP_IPV6);
        out.append(resolved_ipv6[..]);
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
    let needed_len, err = net_internal::socks5_needed_length(buf, atyp);
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

    return res, net_internal::socks5_rep_to_error(rep);
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
    guard net_internal::recv_exact_socks5_bytes(sock_fd, reply_raw[..], timeout_ms) else {
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
        guard net_internal::recv_exact_socks5_bytes(sock_fd, reply_raw[..], timeout_ms) else {
            return Socks5Error.BufferTruncated;
        }
        let auth_res = parse_socks5_rfc1929_reply(reply_raw[..]);
        guard auth_res == Socks5Error.None else { return auth_res; }
    } else if method != rfc::SOCKS5_AUTH_NONE {
        return Socks5Error.NoAcceptableAuth;
    }

    var req_buf: u8[..300] = [];
    let ip4, has_ip4 = core::parse_ipv4_octets(target_host);
    var effective_scheme = scheme;
    if scheme == ProxyScheme.Socks5 && !has_ip4 {
        effective_scheme = ProxyScheme.Socks5h;
    }
    let req_err = build_socks5_connect_request(effective_scheme, target_host, ip4, has_ip4, target_port, req_buf);
    guard req_err == Socks5Error.None else { return req_err; }
    guard tcp_send(sock_fd, req_buf[..]) == (req_buf.len as i32) else { return Socks5Error.ServerFailure; }

    var conn_reply_raw: u8[300] = [0; 300];
    let exact_len, r_err = net_internal::recv_socks5_connect_reply_wire(sock_fd, conn_reply_raw, timeout_ms);
    guard r_err == Socks5Error.None else { return r_err; }
    let _, c_err = parse_socks5_connect_reply(conn_reply_raw[..exact_len]);
    return c_err;
}

// ---- Server-side SOCKS5, UDP ASSOCIATE, and SOCKS4/4a codecs --------------

const SOCKS4_VER:          u8 = 0x04;
const SOCKS4_REP_GRANTED:  u8 = 0x5A;
const SOCKS4_REP_REJECTED: u8 = 0x5B;

enum SocksParseStatus {
    NeedMore,
    Ok,
    Invalid,
    Unsupported,
}

struct Socks5ClientGreeting {
    has_no_auth:  bool = false,
    has_userpass: bool = false,
    consumed:     i64  = 0,
}

struct Socks5UserPassCreds {
    username: u8[..256] = [],
    password: u8[..256] = [],
    consumed: i64       = 0,
}

struct SocksTarget {
    host:          u8[..256]    = [],
    port:          u16          = 0,
    is_ip_literal: bool         = false,
    ip:            core::IpAddr = core::IpAddr { .. },
    cmd:           u8           = rfc::SOCKS5_CMD_CONNECT,
    consumed:      i64          = 0,
}

struct Socks5UdpHeader {
    frag:       u8          = 0,
    target:     SocksTarget = SocksTarget { .. },
    header_len: i64         = 0,
}

fn zeroize_socks5_creds(creds: Socks5UserPassCreds&) {
    if creds.password.len > 0 {
        core::secure_zeroize_slice(creds.password[..]);
        creds.password.clear();
    }
}

// Parses a SOCKS5 client greeting frame (`VER NMETHODS METHODS...`, RFC 1928 Section 3).
//
// Example:
//   buf = [0x05, 0x02, 0x00, 0x02]
//   returns: Socks5ClientGreeting { has_no_auth: true, has_userpass: true, consumed: 4 }, SocksParseStatus.Ok
fn parse_socks5_client_greeting(buf: const u8[:]) -> Socks5ClientGreeting, SocksParseStatus {
    var out = Socks5ClientGreeting { .. };
    guard buf.len >= 2 else { return out, SocksParseStatus.NeedMore; }
    guard buf[0] == rfc::SOCKS5_VER else { return out, SocksParseStatus.Invalid; }

    let nmethods = buf[1] as i64;
    guard nmethods >= 1 else { return out, SocksParseStatus.Invalid; }
    let total = core::add_sat_i64(2, nmethods);
    guard buf.len >= total else { return out, SocksParseStatus.NeedMore; }

    for i in nmethods {
        let m = buf[core::add_sat_i64(2, i)];
        if m == rfc::SOCKS5_AUTH_NONE { out.has_no_auth = true; }
        if m == rfc::SOCKS5_AUTH_USERPASS { out.has_userpass = true; }
    }
    out.consumed = total;
    return out, SocksParseStatus.Ok;
}

fn encode_socks5_method_selection(method: u8) -> u8[2] {
    return [rfc::SOCKS5_VER, method];
}

// Parses an RFC 1929 SOCKS5 username/password subnegotiation packet (`0x01 ULEN UNAME PLEN PASSWD`).
//
// Example:
//   buf = [0x01, 0x04, 'u', 's', 'e', 'r', 0x04, 'p', 'a', 's', 's']
//   returns: Socks5UserPassCreds { username: "user", password: "pass", consumed: 11 }, SocksParseStatus.Ok
fn parse_socks5_userpass_request(buf: const u8[:]) -> Socks5UserPassCreds, SocksParseStatus {
    var out = Socks5UserPassCreds { .. };
    guard buf.len >= 2 else { return out, SocksParseStatus.NeedMore; }
    guard buf[0] == rfc::SOCKS5_RFC1929_VER else { return out, SocksParseStatus.Invalid; }

    let ulen = buf[1] as i64;
    guard ulen >= 1 else { return out, SocksParseStatus.Invalid; }
    let p_len_off = core::add_sat_i64(2, ulen);
    let min_hdr = core::add_sat_i64(p_len_off, 1);
    guard buf.len >= min_hdr else { return out, SocksParseStatus.NeedMore; }

    let plen = buf[p_len_off] as i64;
    guard plen >= 1 else { return out, SocksParseStatus.Invalid; }
    let p_start = core::add_sat_i64(p_len_off, 1);
    let total = core::add_sat_i64(p_start, plen);
    guard buf.len >= total else { return out, SocksParseStatus.NeedMore; }

    guard out.username.try_set(buf[2..p_len_off]) else {
        zeroize_socks5_creds(out);
        return out, SocksParseStatus.Invalid;
    }
    guard out.password.try_set(buf[p_start..total]) else {
        zeroize_socks5_creds(out);
        return out, SocksParseStatus.Invalid;
    }
    out.consumed = total;
    return out, SocksParseStatus.Ok;
}

fn encode_socks5_userpass_reply(ok: bool) -> u8[2] {
    let status: u8 = if ok { 0x00 } else { 0x01 };
    return [rfc::SOCKS5_RFC1929_VER, status];
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
//   returns: SocksParseStatus.Ok, out.host = "127.0.0.1", out.port = 80
inline fn decode_socks5_atyp_ipv4(buf: const u8[:], addr_off: i64, out: SocksTarget&) -> SocksParseStatus {
    let total = core::add_sat_i64(addr_off, 6);
    guard buf.len >= total else { return SocksParseStatus.NeedMore; }
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
    guard core::format_ip_addr(out.ip, out.host) else { return SocksParseStatus.Invalid; }
    return SocksParseStatus.Ok;
}

// Decodes a 16-byte IPv6 address + 2-byte port starting at `addr_off`.
//
// Example:
//   buf = [0x04, ...16 bytes..., 0x01, 0xBB], addr_off = 1
//   returns: SocksParseStatus.Ok, out.port = 443
inline fn decode_socks5_atyp_ipv6(buf: const u8[:], addr_off: i64, out: SocksTarget&) -> SocksParseStatus {
    let total = core::add_sat_i64(addr_off, 18);
    guard buf.len >= total else { return SocksParseStatus.NeedMore; }
    var ip = core::IpAddr { family: core::IpFamily.V6, .. };
    for i in 16 {
        ip.bytes[i] = buf[core::add_sat_i64(addr_off, i)];
    }
    out.ip = ip;
    out.is_ip_literal = true;
    out.port = core::read_be_u16(buf, core::add_sat_i64(addr_off, 16));
    out.consumed = total;
    guard core::format_ip_addr(out.ip, out.host) else { return SocksParseStatus.Invalid; }
    return SocksParseStatus.Ok;
}

// Decodes a length-prefixed domain name + 2-byte port starting at `addr_off`.
//
// Example:
//   buf = [0x03, 0x03, 'a', '.', 'b', 0x00, 0x50], addr_off = 1
//   returns: SocksParseStatus.Ok, out.host = "a.b", out.port = 80
inline fn decode_socks5_atyp_domain(buf: const u8[:], addr_off: i64, out: SocksTarget&) -> SocksParseStatus {
    guard buf.len > addr_off else { return SocksParseStatus.NeedMore; }
    let dlen = buf[addr_off] as i64;
    guard dlen >= 1 && dlen <= 255 else { return SocksParseStatus.Invalid; }
    let d_start = core::add_sat_i64(addr_off, 1);
    let p_off = core::add_sat_i64(d_start, dlen);
    let total = core::add_sat_i64(p_off, 2);
    guard buf.len >= total else { return SocksParseStatus.NeedMore; }

    let dom = buf[d_start..p_off];
    guard is_valid_socks_domain(dom) && out.host.try_set(dom) else { return SocksParseStatus.Invalid; }
    let lit_ip, is_lit = core::parse_ip_addr(dom);
    if is_lit {
        out.is_ip_literal = true;
        out.ip = lit_ip;
    }
    out.port = core::read_be_u16(buf, p_off);
    out.consumed = total;
    return SocksParseStatus.Ok;
}

// Decodes a SOCKS5 [ATYP DST.ADDR DST.PORT] body starting at `atyp_off`.
//
// Example:
//   buf = [0x01, 93, 184, 216, 34, 0x01, 0xBB], atyp_off = 0
//   returns: out populated with 93.184.216.34:443, consumed = 7, SocksParseStatus.Ok
fn decode_socks5_atyp_target(buf: const u8[:], atyp_off: i64, out: SocksTarget&) -> SocksParseStatus {
    guard atyp_off >= 0 && atyp_off < buf.len else { return SocksParseStatus.NeedMore; }
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
    return SocksParseStatus.Unsupported;
}

// Parses a SOCKS5 client command request (`VER CMD RSV ATYP DST.ADDR DST.PORT`, RFC 1928 Section 4).
// Supports CONNECT (0x01) and UDP ASSOCIATE (0x03).
//
// Example:
//   buf = [0x05, 0x01, 0x00, 0x01, 93, 184, 216, 34, 0x01, 0xBB]
//   returns: SocksTarget { host: "93.184.216.34", port: 443, cmd: 1, consumed: 10 }, SocksParseStatus.Ok
fn parse_socks5_client_request(buf: const u8[:]) -> SocksTarget, SocksParseStatus {
    var out = SocksTarget { .. };
    guard buf.len >= 4 else { return out, SocksParseStatus.NeedMore; }
    guard buf[0] == rfc::SOCKS5_VER && buf[2] == 0x00 else { return out, SocksParseStatus.Invalid; }

    let cmd = buf[1];
    out.cmd = cmd;
    guard cmd == rfc::SOCKS5_CMD_CONNECT || cmd == rfc::SOCKS5_CMD_UDP_ASSOCIATE else {
        return out, SocksParseStatus.Unsupported;
    }
    let st = decode_socks5_atyp_target(buf, 3, out);
    return out, st;
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

fn encode_socks5_server_reply(
    rep_code:  u8,
    bind_ip:   const core::IpAddr&,
    bind_port: u16,
    out:       u8[..32]&,
) -> bool {
    out.clear();
    let needed: i64 = if bind_ip.family == core::IpFamily.V6 { 22 } else { 10 };
    guard out.cap >= needed else { return false; }
    let _ = out.try_push(rfc::SOCKS5_VER);
    let _ = out.try_push(rep_code);
    let _ = out.try_push(0x00);
    return append_socks5_addr_and_port(bind_ip, bind_port, out);
}

// Parses a SOCKS5 UDP relay header (`RSV RSV FRAG ATYP DST.ADDR DST.PORT`, RFC 1928 Section 7).
// Rejects fragmented datagrams (`FRAG != 0`) as Unsupported per RFC 1928 Section 7.
//
// Example:
//   pkt = [0x00, 0x00, 0x00, 0x01, 8, 8, 8, 8, 0x00, 0x35, 'h', 'i']
//   returns: Socks5UdpHeader { frag: 0, header_len: 10, .. }, SocksParseStatus.Ok
fn parse_socks5_udp_header(pkt: const u8[:]) -> Socks5UdpHeader, SocksParseStatus {
    var out = Socks5UdpHeader { .. };
    guard pkt.len >= 4 else { return out, SocksParseStatus.NeedMore; }
    guard pkt[0] == 0x00 && pkt[1] == 0x00 else { return out, SocksParseStatus.Invalid; }
    out.frag = pkt[2];
    guard out.frag == 0 else { return out, SocksParseStatus.Unsupported; }
    out.target.cmd = rfc::SOCKS5_CMD_UDP_ASSOCIATE;
    let st = decode_socks5_atyp_target(pkt, 3, out.target);
    guard st == SocksParseStatus.Ok else { return out, st; }
    out.header_len = out.target.consumed;
    return out, SocksParseStatus.Ok;
}

fn encode_socks5_udp_header(src_ip: const core::IpAddr&, src_port: u16, out: u8[..32]&) -> bool {
    out.clear();
    let needed: i64 = if src_ip.family == core::IpFamily.V6 { 22 } else { 10 };
    guard out.cap >= needed else { return false; }
    let _ = out.try_push(0x00);
    let _ = out.try_push(0x00);
    let _ = out.try_push(0x00);
    return append_socks5_addr_and_port(src_ip, src_port, out);
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

inline fn read_socks4a_domain_target(buf: const u8[:], dom_start: i64, out: SocksTarget&) -> SocksParseStatus {
    let dom_null = find_null_byte_bounded(buf, dom_start, 256);
    if dom_null < 0 {
        if buf.len >= core::add_sat_i64(dom_start, 256) { return SocksParseStatus.Invalid; }
        return SocksParseStatus.NeedMore;
    }
    let dom = buf[dom_start..dom_null];
    guard is_valid_socks_domain(dom) && out.host.try_set(dom) else {
        return SocksParseStatus.Invalid;
    }
    let lit_ip, is_lit = core::parse_ip_addr(dom);
    if is_lit {
        out.is_ip_literal = true;
        out.ip = lit_ip;
    }
    out.consumed = core::add_sat_i64(dom_null, 1);
    return SocksParseStatus.Ok;
}

// Parses a SOCKS4 or SOCKS4a client request (`VN CD DSTPORT DSTIP USERID\0 [HOST\0]`).
// Returns `(target, is_socks4a, status)`.
//
// Example:
//   buf = [0x04, 0x01, 0x00, 0x50, 93, 184, 216, 34, 'u', 0x00]
//   returns: SocksTarget { host: "93.184.216.34", port: 80, consumed: 10 }, false, SocksParseStatus.Ok
fn parse_socks4_client_request(buf: const u8[:]) -> SocksTarget, bool, SocksParseStatus {
    var out = SocksTarget { .. };
    guard buf.len >= 8 else { return out, false, SocksParseStatus.NeedMore; }
    guard buf[0] == SOCKS4_VER else { return out, false, SocksParseStatus.Invalid; }

    out.cmd = buf[1];
    guard buf[1] == rfc::SOCKS5_CMD_CONNECT else { return out, false, SocksParseStatus.Unsupported; }
    out.port = core::read_be_u16(buf, 2);

    let uid_null = find_null_byte_bounded(buf, 8, 256);
    if uid_null < 0 {
        if buf.len >= core::add_sat_i64(8, 256) { return out, false, SocksParseStatus.Invalid; }
        return out, false, SocksParseStatus.NeedMore;
    }

    let is_4a = buf[4] == 0 && buf[5] == 0 && buf[6] == 0 && buf[7] != 0;
    if is_4a {
        let st = read_socks4a_domain_target(buf, core::add_sat_i64(uid_null, 1), out);
        return out, true, st;
    }

    out.ip = core::IpAddr {
        family: core::IpFamily.V4,
        bytes:  [buf[4], buf[5], buf[6], buf[7], 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0],
    };
    out.is_ip_literal = true;
    out.consumed = core::add_sat_i64(uid_null, 1);
    guard core::format_ip_addr(out.ip, out.host) else { return out, false, SocksParseStatus.Invalid; }
    return out, false, SocksParseStatus.Ok;
}

fn encode_socks4_server_reply(granted: bool) -> u8[8] {
    let cd: u8 = if granted { SOCKS4_REP_GRANTED } else { SOCKS4_REP_REJECTED };
    return [0x00, cd, 0, 0, 0, 0, 0, 0];
}
