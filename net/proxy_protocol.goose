// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation HAProxy PROXY Protocol v1 (text) and v2 (binary) parser & serializer.
// Conforms to the official HAProxy PROXY Protocol specification (Versions 1 and 2),
// supporting IPv4, IPv6, UNIX domain, and Type-Length-Value (TLV) metadata (ALPN, SNI, Unique ID, SSL/TLS).
namespace wing;

import std;
import core from "..";

// ---- Data Structures -----------------------------------------------------

enum ProxyProtocolVersion {
    None,
    V1,
    V2,
}

enum ProxyCommand {
    Local,
    Proxy,
}

enum ProxyAddressFamily {
    Unspec,
    Inet4,
    Inet6,
    Unix,
}

enum ProxyTransportProtocol {
    Unspec,
    Stream,
    Datagram,
}

struct ProxySslInfo {
    has_ssl:       bool      = false,
    client_flags:  u8        = 0,
    verify_result: u32       = 0,
    version:       u8[..16]  = [],
    cipher:        u8[..64]  = [],
    client_cn:     u8[..128] = [],
    sig_alg:       u8[..32]  = [],
    key_alg:       u8[..32]  = [],
}

struct ProxyHeader {
    version:    ProxyProtocolVersion   = ProxyProtocolVersion.None,
    command:    ProxyCommand           = ProxyCommand.Proxy,
    family:     ProxyAddressFamily     = ProxyAddressFamily.Unspec,
    transport:  ProxyTransportProtocol = ProxyTransportProtocol.Stream,
    src_ip_str: u8[..64]               = [],
    dst_ip_str: u8[..64]               = [],
    src_ipv4:   u8[4]                  = [0; 4],
    dst_ipv4:   u8[4]                  = [0; 4],
    src_ipv6:   u8[16]                 = [0; 16],
    dst_ipv6:   u8[16]                 = [0; 16],
    src_unix:   u8[..108]              = [],
    dst_unix:   u8[..108]              = [],
    src_port:   u16                    = 0,
    dst_port:   u16                    = 0,
    alpn:       u8[..32]               = [],
    authority:  u8[..256]              = [],
    unique_id:  u8[..128]              = [],
    netns:      u8[..64]               = [],
    ssl:        ProxySslInfo           = ProxySslInfo { .. },
}

// ---- Helper Codecs -------------------------------------------------------

// Formats an IPv4 address into dotted decimal string notation (e.g. "192.168.0.1")
fn format_ipv4<B>(ip: const u8[4]&, out: B&) {
    format(out, ip[0] as i64);
    out.push('.');
    format(out, ip[1] as i64);
    out.push('.');
    format(out, ip[2] as i64);
    out.push('.');
    format(out, ip[3] as i64);
}

// Appends 4-nibble hex string for a 16-bit integer without leading zeros unless zero.
fn push_hex_u16<B>(val: u16, out: B&) {
    if val == 0 {
        out.push('0');
        return;
    }
    const hex: const u8[16] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
    var shift: i32 = 12;
    var started = false;
    while shift >= 0 {
        let nibble = ((val >> shift) & 0x0F) as i64;
        if nibble != 0 || started || shift == 0 {
            out.push(hex[nibble]);
            started = true;
        }
        shift -= 4;
    }
}

// Formats an IPv6 address into hex notation
fn format_ipv6<B>(ip: const u8[16]&, out: B&) {
    for i in 8 {
        if i > 0 { out.push(':'); }
        let hi = ip[i * 2];
        let lo = ip[i * 2 + 1];
        let val = ((hi as u16) << 8) | lo;
        push_hex_u16(val, out);
    }
}

// Parses decimal u16 port (0..65535).
//
// Example:
//   str = "8080"
//   returns: ok = true, out_port = 8080
fn parse_port_decimal(str: const u8[:], out_port: u16&) -> bool {
    guard str.len > 0 && str.len <= 5 else { return false; }
    guard str.len == 1 || str[0] != '0' else { return false; }
    var acc: u32 = 0;
    for b in str {
        guard b >= '0' && b <= '9' else { return false; }
        acc = acc * 10 + (b - '0');
        guard acc <= 65535 else { return false; }
    }
    out_port = acc as u16;
    return true;
}

// Parses decimal IPv4 octets into u8[4].
//
// Example:
//   str = "192.168.0.1"
//   returns: ok = true, out_ip = [192, 168, 0, 1]
fn parse_ipv4_decimal(str: const u8[:], out_ip: u8[4]&) -> bool {
    var tmp:       u8[4] = [0; 4];
    var octet_idx: i64   = 0;
    var current:   u32   = 0;
    var digits:    i64   = 0;

    for i in str.len {
        let b = str[i];
        if b == '.' {
            guard digits > 0 && current <= 255 && octet_idx < 3 else { return false; }
            tmp[octet_idx] = current as u8;
            octet_idx++;
            current = 0;
            digits = 0;
        } else if b >= '0' && b <= '9' {
            if digits == 1 && current == 0 {
                return false;
            }
            current = current * 10 + (b - '0');
            digits++;
            guard digits <= 3 && current <= 255 else { return false; }
        } else {
            return false;
        }
    }

    guard digits > 0 && current <= 255 && octet_idx == 3 else { return false; }
    tmp[3] = current as u8;
    out_ip = tmp;
    return true;
}

// Parses 1-4 hex characters into u16 (RFC 4291 §2.2).
//
// Example:
//   str = "1a2f"
//   returns: out_val = 0x1a2f, ok = true
fn parse_hex_u16(str: const u8[:], out_val: u16&) -> bool {
    guard str.len > 0 && str.len <= 4 else { return false; }
    var acc: u32 = 0;
    for b in str {
        var digit: u32 = 0;
        if b >= '0' && b <= '9' {
            digit = b - '0';
        } else if b >= 'a' && b <= 'f' {
            digit = b - 'a' + 10;
        } else if b >= 'A' && b <= 'F' {
            digit = b - 'A' + 10;
        } else {
            return false;
        }
        acc = (acc << 4) | digit;
    }
    out_val = acc as u16;
    return true;
}

// Extracts colon-delimited hex groups into target buffer.
//
// Example:
//   part = "2001:db8", groups = []
//   returns: ok = true, groups = [0x2001, 0x0db8]
fn parse_colon_groups(part: const u8[:], groups: u16[..8]&) -> bool {
    guard part.len > 0 else { return true; }
    var tok_start: i64 = 0;
    for i in part.len {
        guard part[i] == ':' else { continue; }
        let seg = part[tok_start..i];
        var val: u16 = 0;
        guard parse_hex_u16(seg, val) && groups.try_push(val) else { return false; }
        tok_start = i + 1;
    }
    let seg = part[tok_start..];
    var val: u16 = 0;
    guard parse_hex_u16(seg, val) && groups.try_push(val) else { return false; }
    return true;
}

// Parses standard IPv6 hex notation (RFC 4291 §2.2 / RFC 5952) into u8[16].
//
// Example:
//   str = "2001:db8::1"
//   returns: out_ip = [0x20, 0x01, 0x0d, 0xb8, ...], ok = true
fn parse_ipv6_hex(str: const u8[:], out_ip: u8[16]&) -> bool {
    guard str.len >= 2 && str.len <= 39 else { return false; }

    let dcolon_idx = find(str, "::");
    if dcolon_idx >= 0 {
        let second_dcolon = find(str[dcolon_idx + 2..], "::");
        guard second_dcolon < 0 else { return false; }
    }

    var head_groups: u16[..8] = [];
    var tail_groups: u16[..8] = [];

    if dcolon_idx >= 0 {
        let head_part = str[..dcolon_idx];
        let tail_part = str[dcolon_idx + 2..];
        guard parse_colon_groups(head_part, head_groups) else { return false; }
        guard parse_colon_groups(tail_part, tail_groups) else { return false; }

        let total_present = head_groups.len + tail_groups.len;
        guard total_present < 8 else { return false; }
        let zeros_needed = 8 - total_present;

        var byte_idx: i64 = 0;
        for v in head_groups {
            out_ip[byte_idx] = ((v >> 8) & 0xFF) as u8;
            out_ip[byte_idx + 1] = (v & 0xFF) as u8;
            byte_idx += 2;
        }
        for z in zeros_needed {
            out_ip[byte_idx] = 0;
            out_ip[byte_idx + 1] = 0;
            byte_idx += 2;
        }
        for v in tail_groups {
            out_ip[byte_idx] = ((v >> 8) & 0xFF) as u8;
            out_ip[byte_idx + 1] = (v & 0xFF) as u8;
            byte_idx += 2;
        }
        return true;
    }

    guard parse_colon_groups(str, head_groups) else { return false; }
    guard head_groups.len == 8 else { return false; }

    var byte_idx: i64 = 0;
    for v in head_groups {
        out_ip[byte_idx] = ((v >> 8) & 0xFF) as u8;
        out_ip[byte_idx + 1] = (v & 0xFF) as u8;
        byte_idx += 2;
    }
    return true;
}

// ---- PROXY Protocol v1 Parser & Serializer (Text) ------------------------

struct ProxyTokenSpan {
    offset: u16 = 0,
    length: u16 = 0,
}

fn proxy_span_slice(raw: const u8[:], span: ProxyTokenSpan) -> const u8[:] {
    let start: i64 = span.offset;
    let end:   i64 = start + span.length;
    guard start <= raw.len && end <= raw.len else { return raw[..0]; }
    return raw[start..end];
}

// Tokenizes space-separated spans in a PROXY v1 line.
//
// Example:
//   line = "TCP4 1.2.3.4 5.6.7.8 123 456"
//   returns: ok = true, tokens has 5 spans
fn tokenize_proxy_v1_spans(line: const u8[:], tokens: ProxyTokenSpan[..8]&) -> bool {
    guard line.len > 0 && line[0] != ' ' && line[line.len - 1] != ' ' else { return false; }
    var tok_start: i64 = 0;

    for i in line.len {
        if line[i] == ' ' {
            guard i > tok_start &&
                  tokens.try_push(ProxyTokenSpan { offset: tok_start as u16, length: (i - tok_start) as u16 }) else {
                return false;
            }
            tok_start = i + 1;
        }
    }
    guard tok_start < line.len &&
          tokens.try_push(ProxyTokenSpan { offset: tok_start as u16, length: (line.len - tok_start) as u16 }) else {
        return false;
    }
    return true;
}

// Parses an incoming PROXY v1 line:
// PROXY <INET_PROTOCOL> <SRC_IP> <DST_IP> <SRC_PORT> <DST_PORT>\r\n
//
// Example:
//   wire = "PROXY TCP4 1.2.3.4 5.6.7.8 443 80\r\n"
//   returns: hdr.family = Inet4, consumed = 33, ok = true
fn parse_proxy_v1(wire: const u8[:]) -> ProxyHeader, i64, bool {
    var hdr = ProxyHeader { version: ProxyProtocolVersion.V1, .. };
    guard wire.len >= 8 && wire[..6] == internal::PROXY_V1_PREFIX[..] else { return hdr, 0, false; }

    // Locate CRLF terminator within maximum allowed length (107 bytes)
    var crlf_idx: i64 = -1;
    let scan_limit = min(wire.len, internal::PROXY_V1_MAX_LEN);
    for i in 6..scan_limit {
        if wire[i] == '\r' && i + 1 < wire.len && wire[i + 1] == '\n' {
            crlf_idx = i;
            break;
        }
    }
    guard crlf_idx >= 6 else { return hdr, 0, false; }
    let line = wire[6..crlf_idx];
    let consumed = crlf_idx + 2;

    // Check for "UNKNOWN" protocol (must be "UNKNOWN" or followed by space)
    if (line == "UNKNOWN" || line.starts_with("UNKNOWN ")) && !line.contains_byte(0) {
        hdr.command = ProxyCommand.Local;
        hdr.family = ProxyAddressFamily.Unspec;
        hdr.transport = ProxyTransportProtocol.Unspec;
        return hdr, consumed, true;
    }

    // Tokenize space-separated tokens: PROTO SRC_IP DST_IP SRC_PORT DST_PORT
    var tokens: ProxyTokenSpan[..8] = [];
    guard tokenize_proxy_v1_spans(line, tokens) else { return hdr, 0, false; }

    // Must have exactly 5 tokens for TCP4 / TCP6
    guard tokens.len == 5 else { return hdr, 0, false; }

    let proto_str = proxy_span_slice(line, tokens[0]);
    let src_ip_str = proxy_span_slice(line, tokens[1]);
    let dst_ip_str = proxy_span_slice(line, tokens[2]);
    let src_port_str = proxy_span_slice(line, tokens[3]);
    let dst_port_str = proxy_span_slice(line, tokens[4]);

    if proto_str == "TCP4" {
        hdr.family = ProxyAddressFamily.Inet4;
        hdr.transport = ProxyTransportProtocol.Stream;
        guard parse_ipv4_decimal(src_ip_str, hdr.src_ipv4) else { return hdr, 0, false; }
        guard parse_ipv4_decimal(dst_ip_str, hdr.dst_ipv4) else { return hdr, 0, false; }
    } else if proto_str == "TCP6" {
        hdr.family = ProxyAddressFamily.Inet6;
        hdr.transport = ProxyTransportProtocol.Stream;
        guard parse_ipv6_hex(src_ip_str, hdr.src_ipv6) else { return hdr, 0, false; }
        guard parse_ipv6_hex(dst_ip_str, hdr.dst_ipv6) else { return hdr, 0, false; }
    } else {
        return hdr, 0, false;
    }

    guard hdr.src_ip_str.try_set(src_ip_str) && hdr.dst_ip_str.try_set(dst_ip_str) else { return hdr, 0, false; }

    guard parse_port_decimal(src_port_str, hdr.src_port) else { return hdr, 0, false; }
    guard parse_port_decimal(dst_port_str, hdr.dst_port) else { return hdr, 0, false; }

    return hdr, consumed, true;
}

// Formats a PROXY protocol v1 text header
fn format_proxy_v1<B>(hdr: const ProxyHeader&, out: B&) -> bool {
    let is_local_or_unspec = hdr.command == ProxyCommand.Local || hdr.family == ProxyAddressFamily.Unspec;
    guard is_local_or_unspec || hdr.family == ProxyAddressFamily.Inet4 || hdr.family == ProxyAddressFamily.Inet6 else {
        return false;
    }

    var scratch: u8[..128] = [];
    scratch.append("PROXY ");

    if is_local_or_unspec {
        scratch.append("UNKNOWN\r\n");
        return out.try_append(scratch[..]);
    }

    if hdr.family == ProxyAddressFamily.Inet4 {
        scratch.append("TCP4 ");
        if hdr.src_ip_str.len > 0 {
            scratch.append(hdr.src_ip_str[..]);
        } else {
            format_ipv4(hdr.src_ipv4, scratch);
        }
        scratch.push(' ');
        if hdr.dst_ip_str.len > 0 {
            scratch.append(hdr.dst_ip_str[..]);
        } else {
            format_ipv4(hdr.dst_ipv4, scratch);
        }
        scratch.push(' ');
        format(scratch, hdr.src_port as i64);
        scratch.push(' ');
        format(scratch, hdr.dst_port as i64);
        scratch.append("\r\n");
        return out.try_append(scratch[..]);
    }

    scratch.append("TCP6 ");
    if hdr.src_ip_str.len > 0 {
        scratch.append(hdr.src_ip_str[..]);
    } else {
        format_ipv6(hdr.src_ipv6, scratch);
    }
    scratch.push(' ');
    if hdr.dst_ip_str.len > 0 {
        scratch.append(hdr.dst_ip_str[..]);
    } else {
        format_ipv6(hdr.dst_ipv6, scratch);
    }
    scratch.push(' ');
    format(scratch, hdr.src_port as i64);
    scratch.push(' ');
    format(scratch, hdr.dst_port as i64);
    scratch.append("\r\n");
    return out.try_append(scratch[..]);
}

// ---- PROXY Protocol v2 Parser & Serializer (Binary) ----------------------

// Parses an incoming PROXY v2 binary header:
// 12-byte preamble + ver_cmd(1B) + fam_trans(1B) + len(2B) + addr_block + TLVs
fn validate_proxy_v2_preamble(wire: const u8[:]) -> bool {
    guard wire.len >= 16 else { return false; }
    for i in 12 {
        guard wire[i] == internal::PROXY_V2_PREAMBLE[i] else { return false; }
    }
    return true;
}

// Parses the 4-bit command nibble of a PROXY v2 header (HAProxy §2.2).
//
// Example:
//   ver_cmd = 0x21 (version 2, command PROXY)
//   returns: ok = true, out_cmd = ProxyCommand.Proxy
fn parse_proxy_v2_command(ver_cmd: u8, out_cmd: ProxyCommand&) -> bool {
    let ver = (ver_cmd >> 4) & 0x0F;
    guard ver == 0x2 else { return false; }
    let cmd = ver_cmd & 0x0F;
    if cmd == internal::PP2_CMD_LOCAL {
        out_cmd = ProxyCommand.Local;
        return true;
    } else if cmd == internal::PP2_CMD_PROXY {
        out_cmd = ProxyCommand.Proxy;
        return true;
    }
    return false;
}

// Parses family and transport protocol nibbles of a PROXY v2 header (HAProxy §2.2).
//
// Example:
//   fam_trans = 0x11 (AF_INET, STREAM)
//   returns: ok = true, out_fam = Inet4, out_trans = Stream
fn parse_proxy_v2_family_transport(
    fam_trans: u8,
    out_fam:   ProxyAddressFamily&,
    out_trans: ProxyTransportProtocol&,
) -> bool {
    // HAProxy PROXY Protocol v2 Specification §2.2 & uWS #1948:
    // Only exact defined combinations (0x00, 0x11, 0x12, 0x21, 0x22, 0x31, 0x32) are valid.
    // All other values are unspecified and MUST be rejected immediately.
    if fam_trans == 0x00 {
        out_fam = ProxyAddressFamily.Unspec;
        out_trans = ProxyTransportProtocol.Unspec;
        return true;
    } else if fam_trans == 0x11 {
        out_fam = ProxyAddressFamily.Inet4;
        out_trans = ProxyTransportProtocol.Stream;
        return true;
    } else if fam_trans == 0x12 {
        out_fam = ProxyAddressFamily.Inet4;
        out_trans = ProxyTransportProtocol.Datagram;
        return true;
    } else if fam_trans == 0x21 {
        out_fam = ProxyAddressFamily.Inet6;
        out_trans = ProxyTransportProtocol.Stream;
        return true;
    } else if fam_trans == 0x22 {
        out_fam = ProxyAddressFamily.Inet6;
        out_trans = ProxyTransportProtocol.Datagram;
        return true;
    } else if fam_trans == 0x31 {
        out_fam = ProxyAddressFamily.Unix;
        out_trans = ProxyTransportProtocol.Stream;
        return true;
    } else if fam_trans == 0x32 {
        out_fam = ProxyAddressFamily.Unix;
        out_trans = ProxyTransportProtocol.Datagram;
        return true;
    }
    return false;
}

// Parses UNIX socket path addresses from PROXY v2 address block (HAProxy §2.2).
//
// Example:
//   wire = [0; 232], hdr = ProxyHeader { .. }
//   populates: hdr.src_unix, hdr.dst_unix
fn parse_unix_addresses(wire: const u8[:], hdr: ProxyHeader&) {
    let src_slice = wire[16..124];
    let dst_slice = wire[124..232];
    hdr.src_unix.clear();
    for b in src_slice {
        if b == 0 { break; }
        hdr.src_unix.push(b);
    }
    hdr.dst_unix.clear();
    for b in dst_slice {
        if b == 0 { break; }
        hdr.dst_unix.push(b);
    }
}

// Parses IP addresses and ports from PROXY v2 address block (HAProxy §2.2).
//
// Example:
//   wire = "\x01\x02\x03\x04\x05\x06\x07\x08\x00\x50\x01\xbb", fam = Inet4
//   returns: ok = true, out_addr_len = 12
fn parse_proxy_v2_addresses(
    wire:         const u8[:],
    payload_len:  i64,
    fam:          ProxyAddressFamily,
    hdr:          ProxyHeader&,
    out_addr_len: i64&,
) -> bool {
    // HAProxy PROXY Protocol v2 Specification §2.2 & uWS #1948:
    // For command LOCAL (0x00), the receiver MUST NOT interpret addresses and MUST NOT report
    // any address information, preserving the real connection endpoint address.
    let is_local = hdr.command == ProxyCommand.Local;

    if fam == ProxyAddressFamily.Inet4 {
        guard payload_len >= 12 else { return false; }
        if !is_local {
            for i in 4 {
                hdr.src_ipv4[i] = wire[16 + i];
                hdr.dst_ipv4[i] = wire[20 + i];
            }
            hdr.src_port = core::read_be_u16(wire, 24);
            hdr.dst_port = core::read_be_u16(wire, 26);
            format_ipv4(hdr.src_ipv4, hdr.src_ip_str);
            format_ipv4(hdr.dst_ipv4, hdr.dst_ip_str);
        }
        out_addr_len = 12;
        return true;
    } else if fam == ProxyAddressFamily.Inet6 {
        guard payload_len >= 36 else { return false; }
        if !is_local {
            for i in 16 {
                hdr.src_ipv6[i] = wire[16 + i];
                hdr.dst_ipv6[i] = wire[32 + i];
            }
            hdr.src_port = core::read_be_u16(wire, 48);
            hdr.dst_port = core::read_be_u16(wire, 50);
            format_ipv6(hdr.src_ipv6, hdr.src_ip_str);
            format_ipv6(hdr.dst_ipv6, hdr.dst_ip_str);
        }
        out_addr_len = 36;
        return true;
    } else if fam == ProxyAddressFamily.Unix {
        guard payload_len >= 216 else { return false; }
        if !is_local {
            parse_unix_addresses(wire, hdr);
        }
        out_addr_len = 216;
        return true;
    }
    out_addr_len = 0;
    return true;
}

// Parses SSL TLV and its sub-TLVs (HAProxy §2.2).
//
// Example:
//   val = "\x01\x00\x00\x00\x00\x21\x00\x07TLSv1.3"
//   returns: ok = true, ssl.has_ssl = true, ssl.version = "TLSv1.3"
fn parse_proxy_v2_ssl_tlv(val: const u8[:], ssl: ProxySslInfo&) -> bool {
    let saved_ssl = ssl;
    var committed = false;
    defer if !committed { ssl = saved_ssl; };
    guard val.len >= 5 else { return false; }
    ssl.has_ssl = true;
    ssl.client_flags = val[0];
    ssl.verify_result = core::read_be_u32(val, 1);

    var sub_offset: i64 = 5;
    while sub_offset + 3 <= val.len {
        let sub_type = val[sub_offset];
        let sub_len_u16 = core::read_be_u16(val, sub_offset + 1);
        let sub_len = sub_len_u16 as i64;
        let sub_start = sub_offset + 3;
        let sub_end = sub_start + sub_len;
        guard sub_end <= val.len else { return false; }

        let sub_val = val[sub_start..sub_end];
        if sub_type == internal::PP2_SUBTYPE_SSL_VERSION {
            guard ssl.version.try_set(sub_val) else { return false; }
        } else if sub_type == internal::PP2_SUBTYPE_SSL_CN {
            guard ssl.client_cn.try_set(sub_val) else { return false; }
        } else if sub_type == internal::PP2_SUBTYPE_SSL_CIPHER {
            guard ssl.cipher.try_set(sub_val) else { return false; }
        } else if sub_type == internal::PP2_SUBTYPE_SSL_SIG_ALG {
            guard ssl.sig_alg.try_set(sub_val) else { return false; }
        } else if sub_type == internal::PP2_SUBTYPE_SSL_KEY_ALG {
            guard ssl.key_alg.try_set(sub_val) else { return false; }
        }
        sub_offset = sub_end;
    }
    committed = sub_offset == val.len;
    return committed;
}

// Updates a CRC32c (Castagnoli, reflected polynomial 0x82F63B78) accumulator over `slice`.
const CRC32C_CASTAGNOLI_POLY: u32 = 0x82F63B78;

fn crc32c_update_bytes(crc_in: u32, slice: const u8[:]) -> u32 {
    var crc = crc_in;
    for b in slice {
        crc = crc ^ b;
        for _ in 8 {
            let mask: u32 = if (crc & 1) != 0 { CRC32C_CASTAGNOLI_POLY } else { 0 };
            crc = (crc >> 1) ^ mask;
        }
    }
    return crc;
}

// Computes the PROXYv2 CRC32c checksum over `frame[..tlv_limit]` with the 4-byte field at `zero_offset` zeroed.
fn compute_proxy_v2_crc32c(frame: const u8[:], tlv_limit: i64, zero_offset: i64) -> u32 {
    guard zero_offset >= 0 && core::add_sat_i64(zero_offset, 4) <= tlv_limit && tlv_limit <= frame.len else {
        return 0;
    }
    let zeros: const u8[4] = [0, 0, 0, 0];
    var crc: u32 = 0xFFFFFFFF;
    crc = crc32c_update_bytes(crc, frame[..zero_offset]);
    crc = crc32c_update_bytes(crc, zeros[..]);
    crc = crc32c_update_bytes(crc, frame[core::add_sat_i64(zero_offset, 4)..tlv_limit]);
    return crc ^ 0xFFFFFFFF;
}

// Parses PROXY v2 TLV vector from tlv_offset up to tlv_limit (HAProxy §2.2).
//
// Example:
//   wire = "\x01\x00\x02h2", tlv_offset = 0, tlv_limit = 5
//   returns: ok = true, hdr.alpn = "h2", tlv_offset = 5
fn parse_proxy_v2_tlvs(
    wire:       const u8[:],
    tlv_offset: i64&,
    tlv_limit:  i64,
    hdr:        ProxyHeader&,
) -> bool {
    while tlv_offset + 3 <= tlv_limit {
        let tlv_type = wire[tlv_offset];
        let tlv_len_u16 = core::read_be_u16(wire, tlv_offset + 1);
        let tlv_len = tlv_len_u16 as i64;
        let val_start = tlv_offset + 3;
        let val_end = val_start + tlv_len;
        guard val_end <= tlv_limit else { return false; }

        let val = wire[val_start..val_end];

        if tlv_type == internal::PP2_TYPE_ALPN {
            guard hdr.alpn.try_set(val) else { return false; }
        } else if tlv_type == internal::PP2_TYPE_AUTHORITY {
            guard hdr.authority.try_set(val) else { return false; }
        } else if tlv_type == internal::PP2_TYPE_CRC32C {
            guard tlv_len == 4 else { return false; }
            let expected_crc = core::read_be_u32(val, 0);
            let actual_crc = compute_proxy_v2_crc32c(wire, tlv_limit, val_start);
            guard actual_crc == expected_crc else { return false; }
        } else if tlv_type == internal::PP2_TYPE_UNIQUE_ID {
            guard hdr.unique_id.try_set(val) else { return false; }
        } else if tlv_type == internal::PP2_TYPE_NETNS {
            guard hdr.netns.try_set(val) else { return false; }
        } else if tlv_type == internal::PP2_TYPE_SSL {
            guard parse_proxy_v2_ssl_tlv(val, hdr.ssl) else { return false; }
        }

        tlv_offset = val_end;
    }
    return tlv_offset == tlv_limit;
}

// Parses an incoming PROXY v2 binary header (HAProxy §2.2).
//
// Example:
//   wire = "\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a\x21\x11\x00\x0c..."
//   returns: hdr.version = V2, consumed = 28, ok = true
fn parse_proxy_v2(wire: const u8[:]) -> ProxyHeader, i64, bool {
    var hdr = ProxyHeader { version: ProxyProtocolVersion.V2, .. };
    guard validate_proxy_v2_preamble(wire) else { return hdr, 0, false; }
    guard parse_proxy_v2_command(wire[12], hdr.command) else { return hdr, 0, false; }
    guard parse_proxy_v2_family_transport(wire[13], hdr.family, hdr.transport) else { return hdr, 0, false; }

    let payload_len_u16 = core::read_be_u16(wire, 14);
    let payload_len = payload_len_u16 as i64;
    let total_required = 16 + payload_len;
    guard wire.len >= total_required else { return hdr, 0, false; }

    var addr_len: i64 = 0;
    guard parse_proxy_v2_addresses(wire, payload_len, hdr.family, hdr, addr_len) else {
        return hdr, 0, false;
    }

    var tlv_offset = 16 + addr_len;
    let tlv_limit = 16 + payload_len;

    guard parse_proxy_v2_tlvs(wire, tlv_offset, tlv_limit, hdr) else {
        return hdr, 0, false;
    }

    return hdr, total_required, true;
}

fn format_unix_addresses<B>(hdr: const ProxyHeader&, out: B&) {
    let src_len = hdr.src_unix.len;
    for b in hdr.src_unix { out.push(b); }
    for i in (108 - src_len) { out.push(0); }

    let dst_len = hdr.dst_unix.len;
    for b in hdr.dst_unix { out.push(b); }
    for i in (108 - dst_len) { out.push(0); }
}

fn format_proxy_v2_addresses<B>(hdr: const ProxyHeader&, out: B&) {
    if hdr.family == ProxyAddressFamily.Inet4 {
        for b in hdr.src_ipv4 { out.push(b); }
        for b in hdr.dst_ipv4 { out.push(b); }
        out.append_u16_be(hdr.src_port);
        out.append_u16_be(hdr.dst_port);
    } else if hdr.family == ProxyAddressFamily.Inet6 {
        for b in hdr.src_ipv6 { out.push(b); }
        for b in hdr.dst_ipv6 { out.push(b); }
        out.append_u16_be(hdr.src_port);
        out.append_u16_be(hdr.dst_port);
    } else if hdr.family == ProxyAddressFamily.Unix {
        format_unix_addresses(hdr, out);
    }
}

inline fn calc_proxy_v2_sub_tlv_len(val: const u8[:]) -> i64 {
    if val.len > 0 { return 3 + val.len; }
    return 0;
}

inline fn append_proxy_v2_sub_tlv<B>(out: B&, sub_type: u8, val: const u8[:]) {
    guard val.len > 0 else { return; }
    out.push(sub_type);
    out.append_u16_be(val.len as u16);
    out.append(val);
}

fn format_proxy_v2_ssl_tlv<B>(ssl: const ProxySslInfo&, out: B&) {
    out.push(internal::PP2_TYPE_SSL);

    var sub_len: i64 = 5;
    sub_len += calc_proxy_v2_sub_tlv_len(ssl.version[..]);
    sub_len += calc_proxy_v2_sub_tlv_len(ssl.cipher[..]);
    sub_len += calc_proxy_v2_sub_tlv_len(ssl.sig_alg[..]);
    sub_len += calc_proxy_v2_sub_tlv_len(ssl.key_alg[..]);
    sub_len += calc_proxy_v2_sub_tlv_len(ssl.client_cn[..]);

    out.append_u16_be(sub_len as u16);
    out.push(ssl.client_flags);
    out.append_u32_be(ssl.verify_result);

    append_proxy_v2_sub_tlv(out, internal::PP2_SUBTYPE_SSL_VERSION, ssl.version[..]);
    append_proxy_v2_sub_tlv(out, internal::PP2_SUBTYPE_SSL_CIPHER, ssl.cipher[..]);
    append_proxy_v2_sub_tlv(out, internal::PP2_SUBTYPE_SSL_SIG_ALG, ssl.sig_alg[..]);
    append_proxy_v2_sub_tlv(out, internal::PP2_SUBTYPE_SSL_KEY_ALG, ssl.key_alg[..]);
    append_proxy_v2_sub_tlv(out, internal::PP2_SUBTYPE_SSL_CN, ssl.client_cn[..]);
}

fn format_proxy_v2_tlvs<B>(hdr: const ProxyHeader&, out: B&) {
    if hdr.alpn.len > 0 {
        out.push(internal::PP2_TYPE_ALPN);
        out.append_u16_be(hdr.alpn.len as u16);
        out.append(hdr.alpn[..]);
    }

    if hdr.authority.len > 0 {
        out.push(internal::PP2_TYPE_AUTHORITY);
        out.append_u16_be(hdr.authority.len as u16);
        out.append(hdr.authority[..]);
    }

    if hdr.unique_id.len > 0 {
        out.push(internal::PP2_TYPE_UNIQUE_ID);
        out.append_u16_be(hdr.unique_id.len as u16);
        out.append(hdr.unique_id[..]);
    }

    if hdr.netns.len > 0 {
        out.push(internal::PP2_TYPE_NETNS);
        out.append_u16_be(hdr.netns.len as u16);
        out.append(hdr.netns[..]);
    }

    if hdr.ssl.has_ssl {
        format_proxy_v2_ssl_tlv(hdr.ssl, out);
    }
}

// Formats a PROXY protocol v2 binary header
fn format_proxy_v2<B>(hdr: const ProxyHeader&, out: B&) -> bool {
    var payload_buf: u8[..1024] = [];
    format_proxy_v2_addresses(hdr, payload_buf);
    format_proxy_v2_tlvs(hdr, payload_buf);

    let total_needed = 16 + payload_buf.len;
    guard out.len + total_needed <= out.cap else { return false; }

    for b in internal::PROXY_V2_PREAMBLE { out.push(b); }

    let cmd_nibble: u8 = if hdr.command == ProxyCommand.Local {
        internal::PP2_CMD_LOCAL
    } else {
        internal::PP2_CMD_PROXY
    };
    out.push(0x20 | cmd_nibble);

    var fam_nibble: u8 = internal::PP2_FAM_UNSPEC;
    if hdr.family == ProxyAddressFamily.Inet4 {
        fam_nibble = internal::PP2_FAM_INET4;
    } else if hdr.family == ProxyAddressFamily.Inet6 {
        fam_nibble = internal::PP2_FAM_INET6;
    } else if hdr.family == ProxyAddressFamily.Unix {
        fam_nibble = internal::PP2_FAM_UNIX;
    }

    var trans_nibble: u8 = internal::PP2_TRANS_UNSPEC;
    if hdr.family == ProxyAddressFamily.Unspec {
        trans_nibble = internal::PP2_TRANS_UNSPEC;
    } else if hdr.transport == ProxyTransportProtocol.Stream {
        trans_nibble = internal::PP2_TRANS_STREAM;
    } else if hdr.transport == ProxyTransportProtocol.Datagram {
        trans_nibble = internal::PP2_TRANS_DGRAM;
    }

    out.push((fam_nibble << 4) | trans_nibble);

    out.append_u16_be(payload_buf.len as u16);
    out.append(payload_buf[..]);

    return true;
}

// Appends a 7-byte `PP2_TYPE_CRC32C` (`0x03`) TLV to an already-formatted PROXYv2 header in `out`
// and updates the 16-bit payload length at `out[14..16]` (HAProxy §2.2.7).
fn append_proxy_v2_crc32c<B>(out: B&) -> bool {
    guard out.len >= 16 && core::add_sat_u64(out.len as u64, 7) <= (out.cap as u64) else {
        return false;
    }
    let old_payload = core::read_be_u16(out[..], 14) as u64;
    let expected_len = core::add_sat_u64(old_payload, 16);
    let next_payload_u64 = core::add_sat_u64(old_payload, 7);
    guard expected_len == (out.len as u64) && next_payload_u64 <= 65535 else {
        return false;
    }
    let new_payload = next_payload_u64 as u16;
    out[14] = ((new_payload >> 8) & 0xFF) as u8;
    out[15] = (new_payload & 0xFF) as u8;
    out.push(internal::PP2_TYPE_CRC32C);
    out.push(0x00);
    out.push(0x04);
    let crc_offset = out.len;
    out.push(0);
    out.push(0);
    out.push(0);
    out.push(0);
    let crc = compute_proxy_v2_crc32c(out[..], out.len, crc_offset);
    out[crc_offset] = ((crc >> 24) & 0xFF) as u8;
    out[core::add_sat_i64(crc_offset, 1)] = ((crc >> 16) & 0xFF) as u8;
    out[core::add_sat_i64(crc_offset, 2)] = ((crc >> 8) & 0xFF) as u8;
    out[core::add_sat_i64(crc_offset, 3)] = (crc & 0xFF) as u8;
    return true;
}

// ---- Auto-Detection and Stream Stripping ----------------------------------

// Detects whether an incoming wire buffer starts with a PROXY protocol header
fn detect_proxy_protocol(wire: const u8[:]) -> ProxyProtocolVersion {
    if wire.len >= 12 {
        var is_v2 = true;
        for i in 12 {
            if wire[i] != internal::PROXY_V2_PREAMBLE[i] {
                is_v2 = false;
                break;
            }
        }
        if is_v2 { return ProxyProtocolVersion.V2; }
    }

    if wire.len >= 6 && wire[..6] == internal::PROXY_V1_PREFIX[..] {
        return ProxyProtocolVersion.V1;
    }

    return ProxyProtocolVersion.None;
}

// Parses an incoming wire stream, automatically determining if it is PROXY v1 or v2.
// Returns (ProxyHeader, bytes_consumed, success)
//
// Example:
//   wire = "PROXY TCP4 1.2.3.4 5.6.7.8 443 80\r\n"
//   returns: hdr.family = Inet4, consumed = 33, ok = true
fn parse_proxy_header(wire: const u8[:]) -> ProxyHeader, i64, bool {
    let ver = detect_proxy_protocol(wire);
    if ver == ProxyProtocolVersion.V2 {
        return parse_proxy_v2(wire);
    } else if ver == ProxyProtocolVersion.V1 {
        return parse_proxy_v1(wire);
    }
    var none_hdr = ProxyHeader { .. };
    return none_hdr, 0, false;
}

// Transparently strips a PROXY protocol header if present, returning the rest of the stream.
// If no PROXY header is detected, returns (original_wire, false).
fn detect_and_strip_proxy_header(wire: const u8[:], out_hdr: ProxyHeader&) -> const u8[:], bool {
    let hdr, consumed, ok = parse_proxy_header(wire);
    if ok && consumed > 0 && consumed <= wire.len {
        out_hdr = hdr;
        return wire[consumed..], true;
    }
    return wire, false;
}
