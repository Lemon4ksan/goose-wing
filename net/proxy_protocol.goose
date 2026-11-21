// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Deterministic zero-allocation HAProxy PROXY Protocol v1 (text) and v2 (binary) parser & serializer.
// Conforms to the official HAProxy PROXY Protocol specification (Versions 1 and 2),
// supporting IPv4, IPv6, UNIX domain, and Type-Length-Value (TLV) metadata (ALPN, SNI, Unique ID, SSL/TLS).
namespace net;

import std;
import core from "..";
import .internal;
import .proxy_protocol_internal;

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

// ---- PROXY Protocol v1 Parser & Serializer (Text) ------------------------

// Parses an incoming PROXY v1 line:
// PROXY <INET_PROTOCOL> <SRC_IP> <DST_IP> <SRC_PORT> <DST_PORT>\r\n
//
// Example:
//   wire = "PROXY TCP4 1.2.3.4 5.6.7.8 443 80\r\n"
//   returns: hdr.family = Inet4, consumed = 33, ok = true
fn parse_proxy_v1(wire: const u8[:]) -> ProxyHeader, i64, bool {
    var hdr = ProxyHeader { version: ProxyProtocolVersion.V1, .. };
    guard wire.len >= 8 && wire[..6] == net_internal::PROXY_V1_PREFIX[..] else { return hdr, 0, false; }

    // Locate CRLF terminator within maximum allowed length (107 bytes including \r\n)
    let body_window = wire[6..min(wire.len, net_internal::PROXY_V1_MAX_LEN)];
    let rel_crlf = core::find(body_window, "\r\n");
    guard rel_crlf >= 0 else { return hdr, 0, false; }
    let line = body_window[..rel_crlf];
    let consumed = core::add_sat_i64(rel_crlf, 8);
    guard core::swar_find_ctl(line) == line.len && !line.contains_byte(0x7F) else {
        return hdr, 0, false;
    }

    // Check for "UNKNOWN" protocol (must be "UNKNOWN" or followed by space)
    if line == "UNKNOWN" || line.starts_with("UNKNOWN ") {
        hdr.command = ProxyCommand.Local;
        hdr.family = ProxyAddressFamily.Unspec;
        hdr.transport = ProxyTransportProtocol.Unspec;
        return hdr, consumed, true;
    }

    // Tokenize space-separated tokens: PROTO SRC_IP DST_IP SRC_PORT DST_PORT
    var tokens: net_internal::ProxyTokenSpan[..8] = [];
    guard net_internal::tokenize_proxy_v1_spans(line, tokens) else { return hdr, 0, false; }
    guard tokens.len == 5 else { return hdr, 0, false; }

    let proto_str = net_internal::proxy_span_slice(line, tokens[0]);
    let src_ip_str = net_internal::proxy_span_slice(line, tokens[1]);
    let dst_ip_str = net_internal::proxy_span_slice(line, tokens[2]);
    let src_port_str = net_internal::proxy_span_slice(line, tokens[3]);
    let dst_port_str = net_internal::proxy_span_slice(line, tokens[4]);

    if proto_str == "TCP4" {
        hdr.family = ProxyAddressFamily.Inet4;
        hdr.transport = ProxyTransportProtocol.Stream;
        let sip, ok_s = net_internal::parse_ipv4_literal(src_ip_str);
        let dip, ok_d = net_internal::parse_ipv4_literal(dst_ip_str);
        guard ok_s && ok_d else { return hdr, 0, false; }
        hdr.src_ipv4 = sip;
        hdr.dst_ipv4 = dip;
    } else if proto_str == "TCP6" {
        hdr.family = ProxyAddressFamily.Inet6;
        hdr.transport = ProxyTransportProtocol.Stream;
        let sip6, ok_s6 = net_internal::parse_ipv6_hex(src_ip_str);
        let dip6, ok_d6 = net_internal::parse_ipv6_hex(dst_ip_str);
        guard ok_s6 && ok_d6 else { return hdr, 0, false; }
        hdr.src_ipv6 = sip6;
        hdr.dst_ipv6 = dip6;
    } else {
        return hdr, 0, false;
    }

    guard hdr.src_ip_str.try_set(src_ip_str) && hdr.dst_ip_str.try_set(dst_ip_str) else { return hdr, 0, false; }

    let sport, ok_sp = net_internal::parse_port_decimal(src_port_str);
    let dport, ok_dp = net_internal::parse_port_decimal(dst_port_str);
    guard ok_sp && ok_dp else { return hdr, 0, false; }
    hdr.src_port = sport;
    hdr.dst_port = dport;

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
            net_internal::format_ipv4(hdr.src_ipv4, scratch);
        }
        scratch.push(' ');
        if hdr.dst_ip_str.len > 0 {
            scratch.append(hdr.dst_ip_str[..]);
        } else {
            net_internal::format_ipv4(hdr.dst_ipv4, scratch);
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
        net_internal::format_ipv6(hdr.src_ipv6, scratch);
    }
    scratch.push(' ');
    if hdr.dst_ip_str.len > 0 {
        scratch.append(hdr.dst_ip_str[..]);
    } else {
        net_internal::format_ipv6(hdr.dst_ipv6, scratch);
    }
    scratch.push(' ');
    format(scratch, hdr.src_port as i64);
    scratch.push(' ');
    format(scratch, hdr.dst_port as i64);
    scratch.append("\r\n");
    return out.try_append(scratch[..]);
}

// ---- PROXY Protocol v2 Parser & Serializer (Binary) ----------------------

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
    while core::add_sat_i64(sub_offset, 3) <= val.len {
        let sub_type = val[sub_offset];
        let sub_len_u16 = core::read_be_u16(val, core::add_sat_i64(sub_offset, 1));
        let sub_len = sub_len_u16 as i64;
        let sub_start = core::add_sat_i64(sub_offset, 3);
        let sub_end = core::add_sat_i64(sub_start, sub_len);
        guard sub_end <= val.len else { return false; }

        let sub_val = val[sub_start..sub_end];
        if sub_type == net_internal::PP2_SUBTYPE_SSL_VERSION {
            guard ssl.version.try_set(sub_val) else { return false; }
        } else if sub_type == net_internal::PP2_SUBTYPE_SSL_CN {
            guard ssl.client_cn.try_set(sub_val) else { return false; }
        } else if sub_type == net_internal::PP2_SUBTYPE_SSL_CIPHER {
            guard ssl.cipher.try_set(sub_val) else { return false; }
        } else if sub_type == net_internal::PP2_SUBTYPE_SSL_SIG_ALG {
            guard ssl.sig_alg.try_set(sub_val) else { return false; }
        } else if sub_type == net_internal::PP2_SUBTYPE_SSL_KEY_ALG {
            guard ssl.key_alg.try_set(sub_val) else { return false; }
        }
        sub_offset = sub_end;
    }
    committed = sub_offset == val.len;
    return committed;
}

// Computes the PROXYv2 CRC32c checksum over `frame[..tlv_limit]` with the 4-byte field at `zero_offset` zeroed.
fn compute_proxy_v2_crc32c(frame: const u8[:], tlv_limit: i64, zero_offset: i64) -> u32 {
    guard zero_offset >= 0 && core::add_sat_i64(zero_offset, 4) <= tlv_limit && tlv_limit <= frame.len else {
        return 0;
    }
    let zeros: const u8[4] = [0, 0, 0, 0];
    var crc: u32 = 0xFFFFFFFF;
    crc = net_internal::crc32c_update_bytes(crc, frame[..zero_offset]);
    crc = net_internal::crc32c_update_bytes(crc, zeros[..]);
    crc = net_internal::crc32c_update_bytes(crc, frame[core::add_sat_i64(zero_offset, 4)..tlv_limit]);
    return crc ^ 0xFFFFFFFF;
}

// Parses an incoming PROXY v2 binary header (HAProxy §2.2).
//
// Example:
//   wire = "\x0d\x0a\x0d\x0a\x00\x0d\x0a\x51\x55\x49\x54\x0a\x21\x11\x00\x0c..."
//   returns: hdr.version = V2, consumed = 28, ok = true
fn parse_proxy_v2(wire: const u8[:]) -> ProxyHeader, i64, bool {
    var hdr = ProxyHeader { version: ProxyProtocolVersion.V2, .. };
    guard net_internal::validate_proxy_v2_preamble(wire) else { return hdr, 0, false; }
    let cmd, ok_cmd = net_internal::parse_proxy_v2_command(wire[12]);
    guard ok_cmd else { return hdr, 0, false; }
    hdr.command = cmd;
    let fam, trans, ok_ft = net_internal::parse_proxy_v2_family_transport(wire[13]);
    guard ok_ft else { return hdr, 0, false; }
    hdr.family = fam;
    hdr.transport = trans;

    let payload_len_u16 = core::read_be_u16(wire, 14);
    let payload_len = payload_len_u16 as i64;
    let total_required = core::add_sat_i64(16, payload_len);
    guard wire.len >= total_required else { return hdr, 0, false; }

    let addr_len, ok_addr = net_internal::parse_proxy_v2_addresses(wire, payload_len, hdr.family, hdr);
    guard ok_addr else { return hdr, 0, false; }

    var tlv_offset = core::add_sat_i64(16, addr_len);
    let tlv_limit = total_required;

    guard net_internal::parse_proxy_v2_tlvs(wire, tlv_offset, tlv_limit, hdr) else {
        return hdr, 0, false;
    }

    return hdr, total_required, true;
}

// Formats a PROXY protocol v2 binary header
fn format_proxy_v2<B>(hdr: const ProxyHeader&, out: B&) -> bool {
    var payload_buf: u8[..1024] = [];
    net_internal::format_proxy_v2_addresses(hdr, payload_buf);
    net_internal::format_proxy_v2_tlvs(hdr, payload_buf);

    let total_needed = core::add_sat_i64(16, payload_buf.len);
    guard core::add_sat_i64(out.len, total_needed) <= out.cap else { return false; }

    for b in net_internal::PROXY_V2_PREAMBLE { out.push(b); }

    let cmd_nibble: u8 = if hdr.command == ProxyCommand.Local {
        net_internal::PP2_CMD_LOCAL
    } else {
        net_internal::PP2_CMD_PROXY
    };
    out.push(0x20 | cmd_nibble);

    var fam_nibble: u8 = net_internal::PP2_FAM_UNSPEC;
    if hdr.family == ProxyAddressFamily.Inet4 {
        fam_nibble = net_internal::PP2_FAM_INET4;
    } else if hdr.family == ProxyAddressFamily.Inet6 {
        fam_nibble = net_internal::PP2_FAM_INET6;
    } else if hdr.family == ProxyAddressFamily.Unix {
        fam_nibble = net_internal::PP2_FAM_UNIX;
    }

    var trans_nibble: u8 = net_internal::PP2_TRANS_UNSPEC;
    if hdr.family == ProxyAddressFamily.Unspec {
        trans_nibble = net_internal::PP2_TRANS_UNSPEC;
    } else if hdr.transport == ProxyTransportProtocol.Stream {
        trans_nibble = net_internal::PP2_TRANS_STREAM;
    } else if hdr.transport == ProxyTransportProtocol.Datagram {
        trans_nibble = net_internal::PP2_TRANS_DGRAM;
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
    out.push(net_internal::PP2_TYPE_CRC32C);
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
            if wire[i] != net_internal::PROXY_V2_PREAMBLE[i] {
                is_v2 = false;
                break;
            }
        }
        if is_v2 { return ProxyProtocolVersion.V2; }
    }

    if wire.len >= 6 && wire[..6] == net_internal::PROXY_V1_PREFIX[..] {
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
