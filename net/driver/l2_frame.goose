// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Zero-allocation Layer 2/3/4 Ethernet II + IPv4/IPv6 + UDP packet codec
// for AF_XDP UMEM and DPDK mbuf kernel-bypass datapaths.
namespace internal;

import std;
import core from "../..";

const ETH_HDR_LEN:            i64 = 14;
const ETH_TYPE_IPV4:          u16 = 0x0800;
const ETH_TYPE_IPV6:          u16 = 0x86DD;
const IP_PROTO_UDP:           u8  = 17;
const IPV4_MIN_HDR_LEN:       i64 = 20;
const IPV6_HDR_LEN:           i64 = 40;
const UDP_HDR_LEN:            i64 = 8;
const IPV4_DF_FLAG:           u16 = 0x4000;
const IPV4_FRAG_MASK:         u16 = 0x3FFF;
const IPV4_DEFAULT_TTL:       u8  = 64;
const IPV6_DEFAULT_HOP_LIMIT: u8  = 64;
const L2_MAX_FRAME_BYTES:     i64 = 2048;

struct L2UdpEndpoint {
    mac:     u8[6]  = [0; 6],
    ip:      u8[16] = [0; 16],
    is_ipv6: bool   = false,
    port:    u16    = 0,
}

struct L2ParsedUdpFrame {
    src:            L2UdpEndpoint = L2UdpEndpoint { .. },
    dst:            L2UdpEndpoint = L2UdpEndpoint { .. },
    payload_offset: i64           = 0,
    payload_len:    i64           = 0,
}

fn sum_be16_slice(acc_in: u64, data: const u8[:]) -> u64 {
    var acc = acc_in;
    var idx: i64 = 0;
    while core::add_sat_i64(idx, 2) <= data.len {
        let hi = core::shl_sat_u64(data[idx] as u64, 8);
        let lo = data[core::add_sat_i64(idx, 1)] as u64;
        acc = core::add_sat_u64(acc, hi | lo);
        idx = core::add_sat_i64(idx, 2);
    }
    if idx < data.len {
        acc = core::add_sat_u64(acc, core::shl_sat_u64(data[idx] as u64, 8));
    }
    return acc;
}

inline fn fold_internet_checksum(acc: u64) -> u16 {
    let f1 = core::add_sat_u64(acc & 0xFFFF, acc >> 16);
    let f2 = core::add_sat_u64(f1 & 0xFFFF, f1 >> 16);
    return ((f2 ^ 0xFFFF) & 0xFFFF) as u16;
}

fn calc_udp_pseudo_acc(
    src:     const L2UdpEndpoint&,
    dst:     const L2UdpEndpoint&,
    udp_len: u16,
) -> u64 {
    var acc: u64 = 0;
    if src.is_ipv6 {
        acc = sum_be16_slice(acc, src.ip[..16]);
        acc = sum_be16_slice(acc, dst.ip[..16]);
        acc = core::add_sat_u64(acc, udp_len as u64);
        acc = core::add_sat_u64(acc, IP_PROTO_UDP as u64);
    } else {
        acc = sum_be16_slice(acc, src.ip[..4]);
        acc = sum_be16_slice(acc, dst.ip[..4]);
        acc = core::add_sat_u64(acc, IP_PROTO_UDP as u64);
        acc = core::add_sat_u64(acc, udp_len as u64);
    }
    return acc;
}

fn verify_udp_segment_checksum(
    src:             const L2UdpEndpoint&,
    dst:             const L2UdpEndpoint&,
    udp_seg:         const u8[:],
    udp_csum:        u16,
    require_nonzero: bool,
) -> bool {
    if udp_csum == 0 {
        return !require_nonzero;
    }
    let pseudo = calc_udp_pseudo_acc(src, dst, udp_seg.len as u16);
    let total = sum_be16_slice(pseudo, udp_seg);
    return fold_internet_checksum(total) == 0;
}

// Decodes and checksum-verifies the 8-byte UDP header and payload slice bounds.
//
// Example:
//   frame = [14B Eth | 20B IPv4 | 8B UDP | "PING"], l4_off = 34, ip_end = 46, is_ipv6 = false
//   returns: true, out_pkt.payload_offset = 42, out_pkt.payload_len = 4
fn decode_udp_transport_tail(
    frame:   const u8[:],
    l4_off:  i64,
    ip_end:  i64,
    is_ipv6: bool,
    out_pkt: L2ParsedUdpFrame&,
) -> bool {
    guard core::add_sat_i64(l4_off, UDP_HDR_LEN) <= ip_end && ip_end <= frame.len else {
        return false;
    }
    var cur = core::cursor_from(frame[l4_off..ip_end]);
    let sport, ok_sp = core::read_u16(cur);
    let dport, ok_dp = core::read_u16(cur);
    let udp_len, ok_ul = core::read_u16(cur);
    let udp_csum, ok_uc = core::read_u16(cur);
    guard ok_sp && ok_dp && ok_ul && ok_uc && (udp_len as i64) >= UDP_HDR_LEN else {
        return false;
    }
    let udp_end = core::add_sat_i64(l4_off, udp_len as i64);
    guard udp_end <= ip_end else { return false; }
    out_pkt.src.is_ipv6 = is_ipv6;
    out_pkt.dst.is_ipv6 = is_ipv6;
    out_pkt.src.port = sport;
    out_pkt.dst.port = dport;
    guard verify_udp_segment_checksum(out_pkt.src, out_pkt.dst, frame[l4_off..udp_end], udp_csum, is_ipv6) else {
        return false;
    }
    out_pkt.payload_offset = core::add_sat_i64(l4_off, UDP_HDR_LEN);
    out_pkt.payload_len = core::sub_sat_i64(udp_len as i64, UDP_HDR_LEN);
    return true;
}

// Decodes an IPv4 + UDP header/payload following an Ethernet II header.
//
// Example:
//   frame = [14B Eth | 20B IPv4 (proto=17, DF) | 8B UDP | "PING"]
//   returns: ok = true, out_pkt.payload_offset = 42, out_pkt.payload_len = 4
fn decode_ipv4_udp_body(frame: const u8[:], out_pkt: L2ParsedUdpFrame&) -> bool {
    guard frame.len >= core::add_sat_i64(ETH_HDR_LEN, IPV4_MIN_HDR_LEN) else { return false; }
    var cur = core::cursor_from(frame[ETH_HDR_LEN..]);
    let ver_ihl, ok_vi = core::read_u8(cur);
    let _, ok_tos = core::read_u8(cur);
    let total_len, ok_tl = core::read_u16(cur);
    let _, ok_id = core::read_u16(cur);
    let flags_frag, ok_ff = core::read_u16(cur);
    let _, ok_ttl = core::read_u8(cur);
    let proto, ok_pr = core::read_u8(cur);
    let _, ok_hc = core::read_u16(cur);
    let src_ip, ok_si = core::read_bytes(cur, 4);
    let dst_ip, ok_di = core::read_bytes(cur, 4);
    guard ok_vi && ok_tos && ok_tl && ok_id && ok_ff && ok_ttl && ok_pr && ok_hc && ok_si && ok_di else {
        return false;
    }
    let ihl_words = (ver_ihl & 0x0F) as u64;
    let ihl_bytes = (core::shl_sat_u64(ihl_words, 2) as i32) as i64;
    guard (ver_ihl >> 4) == 4 && ihl_bytes >= IPV4_MIN_HDR_LEN && proto == IP_PROTO_UDP else {
        return false;
    }
    guard (flags_frag & IPV4_FRAG_MASK) == 0 else { return false; }
    let ip_end = core::add_sat_i64(ETH_HDR_LEN, total_len as i64);
    let l4_off = core::add_sat_i64(ETH_HDR_LEN, ihl_bytes);
    guard l4_off <= ip_end && ip_end <= frame.len else { return false; }
    guard fold_internet_checksum(sum_be16_slice(0, frame[ETH_HDR_LEN..l4_off])) == 0 else {
        return false;
    }
    for i in 4 {
        out_pkt.src.ip[i] = src_ip[i];
        out_pkt.dst.ip[i] = dst_ip[i];
    }
    return decode_udp_transport_tail(frame, l4_off, ip_end, false, out_pkt);
}

// Decodes an IPv6 + UDP header/payload following an Ethernet II header.
//
// Example:
//   frame = [14B Eth | 40B IPv6 (nh=17) | 8B UDP | "H3"]
//   returns: ok = true, out_pkt.payload_offset = 62, out_pkt.payload_len = 2
fn decode_ipv6_udp_body(frame: const u8[:], out_pkt: L2ParsedUdpFrame&) -> bool {
    guard frame.len >= core::add_sat_i64(ETH_HDR_LEN, IPV6_HDR_LEN) else { return false; }
    var cur = core::cursor_from(frame[ETH_HDR_LEN..]);
    let vtf, ok_vtf = core::read_u32(cur);
    let plen, ok_pl = core::read_u16(cur);
    let nh, ok_nh = core::read_u8(cur);
    let _, ok_hl = core::read_u8(cur);
    let src_ip, ok_si = core::read_bytes(cur, 16);
    let dst_ip, ok_di = core::read_bytes(cur, 16);
    guard ok_vtf && ok_pl && ok_nh && ok_hl && ok_si && ok_di else { return false; }
    guard (vtf >> 28) == 6 && nh == IP_PROTO_UDP && (plen as i64) >= UDP_HDR_LEN else {
        return false;
    }
    let l4_off = core::add_sat_i64(ETH_HDR_LEN, IPV6_HDR_LEN);
    let ip_end = core::add_sat_i64(l4_off, plen as i64);
    guard ip_end <= frame.len else { return false; }
    for i in 16 {
        out_pkt.src.ip[i] = src_ip[i];
        out_pkt.dst.ip[i] = dst_ip[i];
    }
    return decode_udp_transport_tail(frame, l4_off, ip_end, true, out_pkt);
}

// Decodes an Ethernet II + IPv4/IPv6 + UDP frame without heap allocation.
// Rejects non-UDP frames, IPv4 fragments, bad checksums, and truncated lengths.
//
// Example:
//   frame = [6B dst_mac | 6B src_mac | 0x0800 | 20B IPv4 | 8B UDP | "QUIC_PING"]
//   returns: parsed (payload_offset = 42, payload_len = 9), ok = true
fn decode_l2_udp_frame(frame: const u8[:]) -> L2ParsedUdpFrame, bool {
    var out_pkt = L2ParsedUdpFrame { .. };
    guard frame.len >= core::add_sat_i64(ETH_HDR_LEN, core::add_sat_i64(IPV4_MIN_HDR_LEN, UDP_HDR_LEN)) else {
        return L2ParsedUdpFrame { .. }, false;
    }
    var cur = core::cursor_from(frame[..ETH_HDR_LEN]);
    let dmac, ok_dm = core::read_bytes(cur, 6);
    let smac, ok_sm = core::read_bytes(cur, 6);
    let ethertype, ok_et = core::read_u16(cur);
    guard ok_dm && ok_sm && ok_et else { return L2ParsedUdpFrame { .. }, false; }
    for i in 6 {
        out_pkt.dst.mac[i] = dmac[i];
        out_pkt.src.mac[i] = smac[i];
    }
    if ethertype == ETH_TYPE_IPV4 {
        guard decode_ipv4_udp_body(frame, out_pkt) else {
            return L2ParsedUdpFrame { .. }, false;
        }
        return out_pkt, true;
    }
    if ethertype == ETH_TYPE_IPV6 {
        guard decode_ipv6_udp_body(frame, out_pkt) else {
            return L2ParsedUdpFrame { .. }, false;
        }
        return out_pkt, true;
    }
    return L2ParsedUdpFrame { .. }, false;
}

fn append_l3_ip_header(
    src:       const L2UdpEndpoint&,
    dst:       const L2UdpEndpoint&,
    udp_len:   u16,
    ip_id:     u16,
    out_frame: u8[..2048]&,
) -> bool {
    let mark = out_frame.len;
    var ok = false;
    defer if !ok { out_frame.resize(mark); };
    if src.is_ipv6 {
        out_frame.append_u32_be(0x60000000);
        out_frame.append_u16_be(udp_len);
        guard out_frame.try_push(IP_PROTO_UDP) else { return false; }
        guard out_frame.try_push(IPV6_DEFAULT_HOP_LIMIT) else { return false; }
        guard out_frame.try_append(src.ip[..16]) else { return false; }
        guard out_frame.try_append(dst.ip[..16]) else { return false; }
        ok = true;
        return true;
    }
    let ipv4_total = core::add_sat_i64(IPV4_MIN_HDR_LEN, udp_len as i64) as u16;
    var ip4: u8[20] = [
        0x45,
        0x00,
        (ipv4_total >> 8) as u8,
        (ipv4_total & 0xFF) as u8,
        (ip_id >> 8) as u8,
        (ip_id & 0xFF) as u8,
        (IPV4_DF_FLAG >> 8) as u8,
        (IPV4_DF_FLAG & 0xFF) as u8,
        IPV4_DEFAULT_TTL,
        IP_PROTO_UDP,
        0,
        0,
        src.ip[0], src.ip[1], src.ip[2], src.ip[3],
        dst.ip[0], dst.ip[1], dst.ip[2], dst.ip[3],
    ];
    let hdr_csum = fold_internet_checksum(sum_be16_slice(0, ip4[..]));
    ip4[10] = (hdr_csum >> 8) as u8;
    ip4[11] = (hdr_csum & 0xFF) as u8;
    guard out_frame.try_append(ip4[..]) else { return false; }
    ok = true;
    return true;
}

fn append_udp_header_and_payload(
    src:       const L2UdpEndpoint&,
    dst:       const L2UdpEndpoint&,
    payload:   const u8[:],
    out_frame: u8[..2048]&,
) -> bool {
    let mark = out_frame.len;
    var ok = false;
    defer if !ok { out_frame.resize(mark); };
    let udp_len_i64 = core::add_sat_i64(UDP_HDR_LEN, payload.len);
    guard udp_len_i64 <= 65535 else { return false; }
    let udp_len = udp_len_i64 as u16;
    var udp_hdr_zero: u8[8] = [
        (src.port >> 8) as u8,
        (src.port & 0xFF) as u8,
        (dst.port >> 8) as u8,
        (dst.port & 0xFF) as u8,
        (udp_len >> 8) as u8,
        (udp_len & 0xFF) as u8,
        0,
        0,
    ];
    var acc = calc_udp_pseudo_acc(src, dst, udp_len);
    acc = sum_be16_slice(acc, udp_hdr_zero[..]);
    acc = sum_be16_slice(acc, payload);
    let raw_csum = fold_internet_checksum(acc);
    let wire_csum: u16 = if raw_csum == 0 { 0xFFFF } else { raw_csum };
    udp_hdr_zero[6] = (wire_csum >> 8) as u8;
    udp_hdr_zero[7] = (wire_csum & 0xFF) as u8;
    guard out_frame.try_append(udp_hdr_zero[..]) else { return false; }
    guard out_frame.try_append(payload) else { return false; }
    ok = true;
    return true;
}

// Encodes an Ethernet II + IPv4/IPv6 + UDP frame into `out_frame` with checksums.
// Clears `out_frame` on failure so partial frames are never exposed.
//
// Example:
//   src = 10.0.0.1:54321, dst = 10.0.0.2:443, payload = "QUIC_PING"
//   returns: true, out_frame.len = 51 (14B Eth + 20B IPv4 + 8B UDP + 9B payload)
fn encode_l2_udp_frame(
    src:       const L2UdpEndpoint&,
    dst:       const L2UdpEndpoint&,
    payload:   const u8[:],
    ip_id:     u16,
    out_frame: u8[..2048]&,
) -> bool {
    out_frame.clear();
    guard src.is_ipv6 == dst.is_ipv6 else { return false; }
    let l3_len = if src.is_ipv6 { IPV6_HDR_LEN } else { IPV4_MIN_HDR_LEN };
    let udp_total = core::add_sat_i64(UDP_HDR_LEN, payload.len);
    let total_frame = core::add_sat_i64(ETH_HDR_LEN, core::add_sat_i64(l3_len, udp_total));
    guard total_frame <= L2_MAX_FRAME_BYTES else { return false; }

    var committed = false;
    defer if !committed { out_frame.clear(); };

    guard out_frame.try_append(dst.mac[..]) else { return false; }
    guard out_frame.try_append(src.mac[..]) else { return false; }
    let ethertype: u16 = if src.is_ipv6 { ETH_TYPE_IPV6 } else { ETH_TYPE_IPV4 };
    out_frame.append_u16_be(ethertype);

    let udp_len = udp_total as u16;
    guard append_l3_ip_header(src, dst, udp_len, ip_id, out_frame) else { return false; }
    guard append_udp_header_and_payload(src, dst, payload, out_frame) else { return false; }
    committed = true;
    return true;
}
