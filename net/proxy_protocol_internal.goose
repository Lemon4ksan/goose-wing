// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal PROXY protocol wire constants, nibbles, magic preambles, TLV subtypes,
// and internal v1/v2 parsing and serialization helpers.
namespace net_internal;

import std;
import core;
import .proxy_protocol;

// PROXY protocol version 1 prefix: "PROXY "
const PROXY_V1_PREFIX:  const u8[6] = ['P', 'R', 'O', 'X', 'Y', ' '];
const PROXY_V1_MAX_LEN: i64         = 107; // RFC / HAProxy specification maximum v1 line length

// PROXY protocol version 2 12-byte constant preamble:
// \x0D \x0A \x0D \x0A \x00 \x0D \x0A \x51 \x55 \x49 \x54 \x0A ("\r\n\r\n\0\r\nQUIT\n")
const PROXY_V2_PREAMBLE: const u8[12] = [
    0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A,
];

// Protocol Commands (v2 nibble 0..3)
const PP2_CMD_LOCAL: u8 = 0x00; // Connection initiated by proxy (health check / discard address)
const PP2_CMD_PROXY: u8 = 0x01; // Forwarded connection (contains original address)

// Address Families (v2 upper nibble)
const PP2_FAM_UNSPEC: u8 = 0x00;
const PP2_FAM_INET4:  u8 = 0x01; // IPv4 (12 bytes: 4B src + 4B dst + 2B sport + 2B dport)
const PP2_FAM_INET6:  u8 = 0x02; // IPv6 (36 bytes: 16B src + 16B dst + 2B sport + 2B dport)
const PP2_FAM_UNIX:   u8 = 0x03; // Unix (216 bytes: 108B src + 108B dst)

// Transport Protocols (v2 lower nibble)
const PP2_TRANS_UNSPEC: u8 = 0x00;
const PP2_TRANS_STREAM: u8 = 0x01; // TCP
const PP2_TRANS_DGRAM:  u8 = 0x02; // UDP

// Type-Length-Value (TLV) Types
const PP2_TYPE_ALPN:      u8 = 0x01; // Application-Layer Protocol Negotiation (e.g. "h2")
const PP2_TYPE_AUTHORITY: u8 = 0x02; // Host name passed by the client (SNI / Host)
const PP2_TYPE_CRC32C:    u8 = 0x03; // CRC32c checksum
const PP2_TYPE_NOOP:      u8 = 0x04; // Ignored padding
const PP2_TYPE_UNIQUE_ID: u8 = 0x05; // Unique connection ID for tracing
const PP2_TYPE_SSL:       u8 = 0x20; // SSL/TLS client information
const PP2_TYPE_NETNS:     u8 = 0x30; // Network namespace name

// SSL Sub-TLV Types
const PP2_SUBTYPE_SSL_VERSION: u8 = 0x21; // TLS version string (e.g. "TLSv1.3")
const PP2_SUBTYPE_SSL_CN:      u8 = 0x22; // Client Common Name
const PP2_SUBTYPE_SSL_CIPHER:  u8 = 0x23; // Cipher name (e.g. "ECDHE-RSA-AES128-GCM-SHA256")
const PP2_SUBTYPE_SSL_SIG_ALG: u8 = 0x24; // Signature algorithm
const PP2_SUBTYPE_SSL_KEY_ALG: u8 = 0x25; // Key exchange algorithm

// SSL Client Bitmask Flags
const PP2_CLIENT_SSL:       u8 = 0x01; // Connection was over TLS
const PP2_CLIENT_CERT_CONN: u8 = 0x02; // Client provided a certificate in this connection
const PP2_CLIENT_CERT_SESS: u8 = 0x04; // Client provided a certificate in this session

// CRC32c Castagnoli reflected polynomial.
const CRC32C_CASTAGNOLI_POLY: u32 = 0x82F63B78;

// ---- Helper Codecs ---------------------------------------------------------

fn format_ipv4<B>(ip: const u8[4]&, out: B&) {
    format(out, ip[0] as i64);
    out.push('.');
    format(out, ip[1] as i64);
    out.push('.');
    format(out, ip[2] as i64);
    out.push('.');
    format(out, ip[3] as i64);
}

fn push_hex_u16<B>(val: u16, out: B&) {
    if val == 0 {
        out.push('0');
        return;
    }
    const hex: const u8[16] = ['0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b', 'c', 'd', 'e', 'f'];
    var started = false;
    for step in 4 {
        let shift = core::sub_sat_u64(12, core::shl_sat_u64(step as u64, 2)) as u32;
        let nibble = ((val >> shift) & 0x0F) as i64;
        if nibble != 0 || started || shift == 0 {
            out.push(hex[nibble]);
            started = true;
        }
    }
}

fn format_ipv6<B>(ip: const u8[16]&, out: B&) {
    for i in 8 {
        if i > 0 { out.push(':'); }
        let off = core::shl_sat_u64(i as u64, 1) as i64;
        let hi = ip[off];
        let lo = ip[core::add_sat_i64(off, 1)];
        let val = ((hi as u16) << 8) | lo;
        push_hex_u16(val, out);
    }
}

// Parses decimal u16 port (0..65535) without leading zeros.
//
// Example:
//   str = "8080"
//   returns: 8080, true
fn parse_port_decimal(str: const u8[:]) -> u16, bool {
    guard str.len > 0 && str.len <= 5 else { return 0, false; }
    guard str.len == 1 || str[0] != '0' else { return 0, false; }
    let val, ok = str.parse_u32_dec();
    guard ok && val <= 65535 else { return 0, false; }
    return val as u16, true;
}

// Parses 1-4 hex characters into u16 (RFC 4291 §2.2).
//
// Example:
//   str = "1a2f"
//   returns: 0x1a2f, true
fn parse_hex_u16(str: const u8[:]) -> u16, bool {
    guard str.len > 0 && str.len <= 4 else { return 0, false; }
    let val, ok = str.parse_u32_hex();
    guard ok && val <= 65535 else { return 0, false; }
    return val as u16, true;
}

// Extracts colon-delimited hex groups into target buffer.
//
// Example:
//   part = "2001:db8", groups = []
//   returns: ok = true, groups = [0x2001, 0x0db8]
fn parse_colon_groups(part: const u8[:], groups: u16[..8]&) -> bool {
    guard part.len > 0 else { return true; }
    let saved_len = groups.len;
    var committed = false;
    defer if !committed { groups.resize(saved_len); };
    var tok_start: i64 = 0;
    for i in part.len {
        guard part[i] == ':' else { continue; }
        let seg = part[tok_start..i];
        let val, ok_v = parse_hex_u16(seg);
        guard ok_v && groups.try_push(val) else { return false; }
        tok_start = core::add_sat_i64(i, 1);
    }
    let seg = part[tok_start..];
    let val, ok_v = parse_hex_u16(seg);
    guard ok_v && groups.try_push(val) else { return false; }
    committed = true;
    return true;
}

inline fn write_ipv6_group_be(out_ip: u8[16]&, byte_idx: i64&, v: u16) {
    out_ip[byte_idx] = ((v >> 8) & 0xFF) as u8;
    out_ip[core::add_sat_i64(byte_idx, 1)] = (v & 0xFF) as u8;
    byte_idx = core::add_sat_i64(byte_idx, 2);
}

// Parses standard IPv6 hex notation (RFC 4291 §2.2 / RFC 5952) into u8[16].
//
// Example:
//   str = "2001:db8::1"
//   returns: [0x20, 0x01, 0x0d, 0xb8, ...], true
fn parse_ipv6_hex(str: const u8[:]) -> u8[16], bool {
    var out_ip: u8[16] = [0; 16];
    guard str.len >= 2 && str.len <= 39 else { return out_ip, false; }

    let dcolon_idx = find(str, "::");
    if dcolon_idx >= 0 {
        let after_dcolon = core::add_sat_i64(dcolon_idx, 2);
        guard find(str[after_dcolon..], "::") < 0 else { return out_ip, false; }

        var head_groups: u16[..8] = [];
        var tail_groups: u16[..8] = [];
        guard parse_colon_groups(str[..dcolon_idx], head_groups) else { return out_ip, false; }
        guard parse_colon_groups(str[after_dcolon..], tail_groups) else { return out_ip, false; }

        let total_present = core::add_sat_i64(head_groups.len, tail_groups.len);
        guard total_present < 8 else { return out_ip, false; }
        let zeros_needed = core::sub_sat_i64(8, total_present);

        var byte_idx: i64 = 0;
        for v in head_groups {
            write_ipv6_group_be(out_ip, byte_idx, v);
        }
        for _ in zeros_needed {
            write_ipv6_group_be(out_ip, byte_idx, 0);
        }
        for v in tail_groups {
            write_ipv6_group_be(out_ip, byte_idx, v);
        }
        return out_ip, true;
    }

    var all_groups: u16[..8] = [];
    guard parse_colon_groups(str, all_groups) && all_groups.len == 8 else { return out_ip, false; }
    var byte_idx: i64 = 0;
    for v in all_groups {
        write_ipv6_group_be(out_ip, byte_idx, v);
    }
    return out_ip, true;
}

// ---- PROXY v1 Tokenizer Helpers --------------------------------------------

struct ProxyTokenSpan {
    offset: u16 = 0,
    length: u16 = 0,
}

fn proxy_span_slice(raw: const u8[:], span: ProxyTokenSpan) -> const u8[:] {
    let start: i64 = span.offset;
    let end:   i64 = core::add_sat_i64(start, span.length);
    guard start <= raw.len && end <= raw.len else { return raw[..0]; }
    return raw[start..end];
}

// Tokenizes space-separated spans in a PROXY v1 line.
//
// Example:
//   line = "TCP4 1.2.3.4 5.6.7.8 123 456"
//   returns: ok = true, tokens has 5 spans
fn tokenize_proxy_v1_spans(line: const u8[:], tokens: ProxyTokenSpan[..8]&) -> bool {
    guard line.len > 0 && line[0] != ' ' && line[core::sub_sat_i64(line.len, 1)] != ' ' else { return false; }
    var tok_start: i64 = 0;

    for i in line.len {
        if line[i] == ' ' {
            let span_len = core::sub_sat_i64(i, tok_start);
            guard i > tok_start &&
                  tokens.try_push(ProxyTokenSpan { offset: tok_start as u16, length: span_len as u16 }) else {
                return false;
            }
            tok_start = core::add_sat_i64(i, 1);
        }
    }
    let tail_len = core::sub_sat_i64(line.len, tok_start);
    guard tok_start < line.len &&
          tokens.try_push(ProxyTokenSpan { offset: tok_start as u16, length: tail_len as u16 }) else {
        return false;
    }
    return true;
}

// ---- PROXY v2 Binary Helpers -----------------------------------------------

fn validate_proxy_v2_preamble(wire: const u8[:]) -> bool {
    guard wire.len >= 16 else { return false; }
    for i in 12 {
        guard wire[i] == PROXY_V2_PREAMBLE[i] else { return false; }
    }
    return true;
}

// Parses the 4-bit command nibble of a PROXY v2 header (HAProxy §2.2).
//
// Example:
//   ver_cmd = 0x21 (version 2, command PROXY)
//   returns: ProxyCommand.Proxy, true
fn parse_proxy_v2_command(ver_cmd: u8) -> net::ProxyCommand, bool {
    let ver = (ver_cmd >> 4) & 0x0F;
    guard ver == 0x2 else { return net::ProxyCommand.Local, false; }
    let cmd = ver_cmd & 0x0F;
    if cmd == PP2_CMD_LOCAL {
        return net::ProxyCommand.Local, true;
    } else if cmd == PP2_CMD_PROXY {
        return net::ProxyCommand.Proxy, true;
    }
    return net::ProxyCommand.Local, false;
}

// Parses family and transport protocol nibbles of a PROXY v2 header (HAProxy §2.2).
//
// Example:
//   fam_trans = 0x11 (AF_INET, STREAM)
//   returns: Inet4, Stream, true
fn parse_proxy_v2_family_transport(fam_trans: u8) -> net::ProxyAddressFamily, net::ProxyTransportProtocol, bool {
    // HAProxy PROXY Protocol v2 Specification §2.2 & uWS #1948:
    // Only exact defined combinations (0x00, 0x11, 0x12, 0x21, 0x22, 0x31, 0x32) are valid.
    if fam_trans == 0x00 {
        return net::ProxyAddressFamily.Unspec, net::ProxyTransportProtocol.Unspec, true;
    } else if fam_trans == 0x11 {
        return net::ProxyAddressFamily.Inet4, net::ProxyTransportProtocol.Stream, true;
    } else if fam_trans == 0x12 {
        return net::ProxyAddressFamily.Inet4, net::ProxyTransportProtocol.Datagram, true;
    } else if fam_trans == 0x21 {
        return net::ProxyAddressFamily.Inet6, net::ProxyTransportProtocol.Stream, true;
    } else if fam_trans == 0x22 {
        return net::ProxyAddressFamily.Inet6, net::ProxyTransportProtocol.Datagram, true;
    } else if fam_trans == 0x31 {
        return net::ProxyAddressFamily.Unix, net::ProxyTransportProtocol.Stream, true;
    } else if fam_trans == 0x32 {
        return net::ProxyAddressFamily.Unix, net::ProxyTransportProtocol.Datagram, true;
    }
    return net::ProxyAddressFamily.Unspec, net::ProxyTransportProtocol.Unspec, false;
}

// Parses UNIX socket path addresses from PROXY v2 address block (HAProxy §2.2).
//
// Example:
//   wire = [0; 232], hdr = ProxyHeader { .. }
//   populates: hdr.src_unix, hdr.dst_unix
fn parse_unix_addresses(wire: const u8[:], hdr: net::ProxyHeader&) {
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
//   returns: addr_len = 12, ok = true
fn parse_proxy_v2_addresses(
    wire:        const u8[:],
    payload_len: i64,
    fam:         net::ProxyAddressFamily,
    hdr:         net::ProxyHeader&,
) -> i64, bool {
    guard payload_len >= 0 && wire.len >= core::add_sat_i64(16, payload_len) else { return 0, false; }
    // HAProxy PROXY Protocol v2 Specification §2.2 & uWS #1948:
    // For command LOCAL (0x00), the receiver MUST NOT interpret addresses.
    let is_local = hdr.command == net::ProxyCommand.Local;

    if fam == net::ProxyAddressFamily.Inet4 {
        guard payload_len >= 12 else { return 0, false; }
        if !is_local {
            for i in 4 {
                hdr.src_ipv4[i] = wire[core::add_sat_i64(16, i)];
                hdr.dst_ipv4[i] = wire[core::add_sat_i64(20, i)];
            }
            hdr.src_port = core::read_be_u16(wire, 24);
            hdr.dst_port = core::read_be_u16(wire, 26);
            format_ipv4(hdr.src_ipv4, hdr.src_ip_str);
            format_ipv4(hdr.dst_ipv4, hdr.dst_ip_str);
        }
        return 12, true;
    } else if fam == net::ProxyAddressFamily.Inet6 {
        guard payload_len >= 36 else { return 0, false; }
        if !is_local {
            for i in 16 {
                hdr.src_ipv6[i] = wire[core::add_sat_i64(16, i)];
                hdr.dst_ipv6[i] = wire[core::add_sat_i64(32, i)];
            }
            hdr.src_port = core::read_be_u16(wire, 48);
            hdr.dst_port = core::read_be_u16(wire, 50);
            format_ipv6(hdr.src_ipv6, hdr.src_ip_str);
            format_ipv6(hdr.dst_ipv6, hdr.dst_ip_str);
        }
        return 36, true;
    } else if fam == net::ProxyAddressFamily.Unix {
        guard payload_len >= 216 else { return 0, false; }
        if !is_local {
            parse_unix_addresses(wire, hdr);
        }
        return 216, true;
    }
    return 0, true;
}

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

// Parses PROXY v2 TLV vector from tlv_offset up to tlv_limit (HAProxy §2.2).
//
// Example:
//   wire = "\x01\x00\x02h2", tlv_offset = 0, tlv_limit = 5
//   returns: ok = true, hdr.alpn = "h2", tlv_offset = 5
fn parse_proxy_v2_tlvs(
    wire:       const u8[:],
    tlv_offset: i64&,
    tlv_limit:  i64,
    hdr:        net::ProxyHeader&,
) -> bool {
    while core::add_sat_i64(tlv_offset, 3) <= tlv_limit {
        let tlv_type = wire[tlv_offset];
        let tlv_len_u16 = core::read_be_u16(wire, core::add_sat_i64(tlv_offset, 1));
        let tlv_len = tlv_len_u16 as i64;
        let val_start = core::add_sat_i64(tlv_offset, 3);
        let val_end = core::add_sat_i64(val_start, tlv_len);
        guard val_end <= tlv_limit else { return false; }

        let val = wire[val_start..val_end];

        if tlv_type == PP2_TYPE_ALPN {
            guard hdr.alpn.try_set(val) else { return false; }
        } else if tlv_type == PP2_TYPE_AUTHORITY {
            guard hdr.authority.try_set(val) else { return false; }
        } else if tlv_type == PP2_TYPE_CRC32C {
            guard tlv_len == 4 else { return false; }
            let expected_crc = core::read_be_u32(val, 0);
            let actual_crc = net::compute_proxy_v2_crc32c(wire, tlv_limit, val_start);
            guard actual_crc == expected_crc else { return false; }
        } else if tlv_type == PP2_TYPE_UNIQUE_ID {
            guard hdr.unique_id.try_set(val) else { return false; }
        } else if tlv_type == PP2_TYPE_NETNS {
            guard hdr.netns.try_set(val) else { return false; }
        } else if tlv_type == PP2_TYPE_SSL {
            guard net::parse_proxy_v2_ssl_tlv(val, hdr.ssl) else { return false; }
        }

        tlv_offset = val_end;
    }
    return tlv_offset == tlv_limit;
}

fn format_unix_addresses<B>(hdr: const net::ProxyHeader&, out: B&) {
    let src_pad = core::sub_sat_i64(108, hdr.src_unix.len);
    for b in hdr.src_unix { out.push(b); }
    for _ in src_pad { out.push(0); }

    let dst_pad = core::sub_sat_i64(108, hdr.dst_unix.len);
    for b in hdr.dst_unix { out.push(b); }
    for _ in dst_pad { out.push(0); }
}

fn format_proxy_v2_addresses<B>(hdr: const net::ProxyHeader&, out: B&) {
    if hdr.family == net::ProxyAddressFamily.Inet4 {
        for b in hdr.src_ipv4 { out.push(b); }
        for b in hdr.dst_ipv4 { out.push(b); }
        out.append_u16_be(hdr.src_port);
        out.append_u16_be(hdr.dst_port);
    } else if hdr.family == net::ProxyAddressFamily.Inet6 {
        for b in hdr.src_ipv6 { out.push(b); }
        for b in hdr.dst_ipv6 { out.push(b); }
        out.append_u16_be(hdr.src_port);
        out.append_u16_be(hdr.dst_port);
    } else if hdr.family == net::ProxyAddressFamily.Unix {
        format_unix_addresses(hdr, out);
    }
}

inline fn calc_proxy_v2_sub_tlv_len(val: const u8[:]) -> i64 {
    if val.len > 0 { return core::add_sat_i64(3, val.len); }
    return 0;
}

inline fn append_proxy_v2_sub_tlv<B>(out: B&, sub_type: u8, val: const u8[:]) {
    guard val.len > 0 else { return; }
    out.push(sub_type);
    out.append_u16_be(val.len as u16);
    out.append(val);
}

fn format_proxy_v2_ssl_tlv<B>(ssl: const net::ProxySslInfo&, out: B&) {
    out.push(PP2_TYPE_SSL);

    var sub_len: i64 = 5;
    sub_len = core::add_sat_i64(sub_len, calc_proxy_v2_sub_tlv_len(ssl.version[..]));
    sub_len = core::add_sat_i64(sub_len, calc_proxy_v2_sub_tlv_len(ssl.cipher[..]));
    sub_len = core::add_sat_i64(sub_len, calc_proxy_v2_sub_tlv_len(ssl.sig_alg[..]));
    sub_len = core::add_sat_i64(sub_len, calc_proxy_v2_sub_tlv_len(ssl.key_alg[..]));
    sub_len = core::add_sat_i64(sub_len, calc_proxy_v2_sub_tlv_len(ssl.client_cn[..]));

    out.append_u16_be(sub_len as u16);
    out.push(ssl.client_flags);
    out.append_u32_be(ssl.verify_result);

    append_proxy_v2_sub_tlv(out, PP2_SUBTYPE_SSL_VERSION, ssl.version[..]);
    append_proxy_v2_sub_tlv(out, PP2_SUBTYPE_SSL_CIPHER, ssl.cipher[..]);
    append_proxy_v2_sub_tlv(out, PP2_SUBTYPE_SSL_SIG_ALG, ssl.sig_alg[..]);
    append_proxy_v2_sub_tlv(out, PP2_SUBTYPE_SSL_KEY_ALG, ssl.key_alg[..]);
    append_proxy_v2_sub_tlv(out, PP2_SUBTYPE_SSL_CN, ssl.client_cn[..]);
}

fn format_proxy_v2_tlvs<B>(hdr: const net::ProxyHeader&, out: B&) {
    if hdr.alpn.len > 0 {
        out.push(PP2_TYPE_ALPN);
        out.append_u16_be(hdr.alpn.len as u16);
        out.append(hdr.alpn[..]);
    }

    if hdr.authority.len > 0 {
        out.push(PP2_TYPE_AUTHORITY);
        out.append_u16_be(hdr.authority.len as u16);
        out.append(hdr.authority[..]);
    }

    if hdr.unique_id.len > 0 {
        out.push(PP2_TYPE_UNIQUE_ID);
        out.append_u16_be(hdr.unique_id.len as u16);
        out.append(hdr.unique_id[..]);
    }

    if hdr.netns.len > 0 {
        out.push(PP2_TYPE_NETNS);
        out.append_u16_be(hdr.netns.len as u16);
        out.append(hdr.netns[..]);
    }

    if hdr.ssl.has_ssl {
        format_proxy_v2_ssl_tlv(hdr.ssl, out);
    }
}
