// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP Datagrams and Capsules (RFC 9297), MASQUE CONNECT-UDP (RFC 9298), & MASQUE CONNECT-IP (RFC 9484).
// Zero-heap protocol codec for modern privacy proxies and UDP/IP tunneling over HTTP/2 and HTTP/3.
namespace net;

import std;
import core;
import .internal;

// ---- Capsule Types & Constants (RFC 9297 Section 3, RFC 9484 Section 4) ---

struct HttpCapsule {
    capsule_type: u64         = 0,
    payload:      const u8[:] = [],
    header_len:   u64         = 0,
}

// ---- Capsule Codec (RFC 9297 Section 3.1) -------------------------------

// Parses an HTTP Capsule header and value from wire stream (RFC 9297 §3.1).
// Capsule format: Type (VarInt) || Length (VarInt) || Value (bytes)
//
// Example:
//   src = "\x00\x05hello"
//   returns: capsule_type = 0, payload = "hello", ok = true
fn parse_http_capsule(src: const u8[:]) -> HttpCapsule, bool {
    var c = HttpCapsule { payload: src[..0], .. };
    guard src.len > 0 else { return c, false; }

    let ctype, off1, ok1 = quic::decode_varint(src, 0);
    guard ok1 else { return c, false; }

    let clen, off2, ok2 = quic::decode_varint(src, off1);
    guard ok2 else { return c, false; }

    let total_len = core::add_sat_u64(off2, clen);
    guard clen <= (src.len as u64) && total_len <= (src.len as u64) else { return c, false; }

    let start_idx = off2 as i64;
    let end_idx = total_len as i64;
    c.capsule_type = ctype;
    c.payload = src[start_idx..end_idx];
    c.header_len = off2;
    return c, true;
}

// Encodes an HTTP Capsule into buffer: Type (VarInt) || Length (VarInt) || Value
fn encode_http_capsule<B>(out: B&, capsule_type: u64, payload: const u8[:]) -> bool {
    var hdr: u8[..16] = [];
    guard quic::encode_varint(capsule_type, hdr) else { return false; }
    guard quic::encode_varint(payload.len as u64, hdr) else { return false; }
    let needed = core::add_sat_i64(core::add_sat_i64(out.len, hdr.len), payload.len);
    guard needed <= out.cap else { return false; }
    out.append(hdr[..]);
    out.append(payload);
    return true;
}

// Checks if Capsule-Protocol header value matches boolean `?1` (RFC 9297 Section 3.4 / RFC 8941)
fn is_capsule_protocol_negotiated(header_val: const u8[:]) -> bool {
    let trimmed = header_val.trim_lws();
    if trimmed == "?1" {
        return true;
    }
    return trimmed.starts_with("?1;") && !trimmed.contains_byte(',');
}

// Checks if Capsule-Protocol header is negotiated in a HeaderMap
fn has_capsule_protocol(headers: const http::HeaderMap&) -> bool {
    let val = headers.get_header("capsule-protocol");
    return is_capsule_protocol_negotiated(val);
}

// ---- HTTP Datagrams (RFC 9297 Section 2) --------------------------------

// Encodes an HTTP Datagram payload for QUIC DATAGRAM frame (RFC 9297 Section 2.1):
// Format: Quarter Stream ID (VarInt) || Context ID (VarInt) || HTTP Datagram Payload
fn encode_http_datagram<B>(out: B&, quarter_stream_id: u64, context_id: u64, payload: const u8[:]) -> bool {
    var hdr: u8[..16] = [];
    guard quarter_stream_id <= 0x0FFFFFFFFFFFFFFF &&
          quic::encode_varint(quarter_stream_id, hdr) else { return false; }
    guard quic::encode_varint(context_id, hdr) else { return false; }
    let needed = core::add_sat_i64(core::add_sat_i64(out.len, hdr.len), payload.len);
    guard needed <= out.cap else { return false; }
    out.append(hdr[..]);
    out.append(payload);
    return true;
}

// Decodes an HTTP Datagram payload from QUIC DATAGRAM frame (RFC 9297 §2.1).
// Returns (Quarter Stream ID, Context ID, Payload, Ok)
//
// Example:
//   wire = "\x00\x00data"
//   returns: quarter_stream_id = 0, context_id = 0, payload = "data", ok = true
fn decode_http_datagram(wire: const u8[:]) -> u64, u64, const u8[:], bool {
    guard wire.len > 0 else { return 0, 0, wire[..0], false; }
    let q_id, off1, ok1 = quic::decode_varint(wire, 0);
    guard ok1 && q_id <= 0x0FFFFFFFFFFFFFFF else { return 0, 0, wire[..0], false; }
    let ctx_id, off2, ok2 = quic::decode_varint(wire, off1);
    guard ok2 else { return 0, 0, wire[..0], false; }
    let payload = wire[(off2 as i64)..];
    return q_id, ctx_id, payload, true;
}

// ---- MASQUE CONNECT-UDP (RFC 9298) --------------------------------------

// Formats a MASQUE URI template path for target host and port (RFC 9298 Section 2):
// e.g. `/.well-known/masque/udp/1.1.1.1/53/`
fn format_connect_udp_path<B>(out: B&, target_host: const u8[:], target_port: u16) {
    out.append("/.well-known/masque/udp/");
    for b in target_host {
        if b == ':' {
            out.append("%3A");
        } else {
            out.push(b);
        }
    }
    out.push('/');
    target_port.format_u64_dec(out);
    out.push('/');
}

// Parses a MASQUE CONNECT-UDP URI template path into (host, port, ok) (RFC 9298 Section 3).
//
// Example:
//   path = "/.well-known/masque/udp/1.1.1.1/53/"
//   returns: host = "1.1.1.1", port = 53, ok = true
fn parse_connect_udp_path(path: const u8[:]) -> u8[..256], u16, bool {
    var out_host: u8[..256] = [];
    var out_port: u16       = 0;
    let prefix = "/.well-known/masque/udp/";
    guard path.starts_with(prefix) else { return out_host, 0, false; }

    let rem = path[prefix.len..];
    let host_part, rem_after_host, host_ok = rem.split_once_byte('/');
    guard host_ok && host_part.len > 0 else { return out_host, 0, false; }
    guard net_internal::decode_connect_udp_target_host(host_part, out_host) else { return out_host, 0, false; }

    var port_part = rem_after_host;
    if port_part.len > 0 && port_part[core::sub_sat_i64(port_part.len, 1)] == '/' {
        port_part = port_part[..^1];
    }
    guard port_part.len > 0 && port_part.index_of_byte('/') < 0 else { return out_host, 0, false; }

    let p_val, parse_ok = port_part.parse_u32_dec();
    // RFC 9298 Section 3: Tunneling UDP over HTTP - target_port MUST be between 1 and 65535
    guard parse_ok && p_val >= 1 && p_val <= 65535 else { return out_host, 0, false; }
    out_port = p_val as u16;
    return out_host, out_port, true;
}

const MAX_CONNECT_UDP_PAYLOAD_LEN: i64 = 65527; // RFC 9298 §5

// Encodes a UDP payload into a DATAGRAM capsule (RFC 9297 / RFC 9298 Section 5):
// Format: Context ID (VarInt = 0) || UDP Payload
fn encode_connect_udp_datagram_capsule<B>(out: B&, context_id: u64, udp_packet: const u8[:]) -> bool {
    var datagram_body: u8[..2048] = [];
    guard net_internal::assemble_datagram_body(datagram_body, context_id, udp_packet) else { return false; }
    return encode_http_capsule(out, rfc::CAPSULE_DATAGRAM, datagram_body[..]);
}

// Parses a DATAGRAM capsule payload into (context_id, udp_packet, ok) (RFC 9298 §5).
//
// Example:
//   capsule_payload = "\x00dns-wire-bytes"
//   returns: context_id = 0, packet = "dns-wire-bytes", ok = true
fn parse_connect_udp_datagram(capsule_payload: const u8[:]) -> u64, const u8[:], bool {
    guard capsule_payload.len > 0 else { return 0, capsule_payload[..0], false; }
    let context_id, off, ok = quic::decode_varint(capsule_payload, 0);
    guard ok else { return 0, capsule_payload[..0], false; }
    let start_idx = off as i64;
    let packet = capsule_payload[start_idx..];
    // RFC 9298 §5: Context ID 0 UDP Proxying Payload longer than 65527 bytes MUST abort stream
    guard context_id != 0 || packet.len <= MAX_CONNECT_UDP_PAYLOAD_LEN else {
        return 0, capsule_payload[..0], false;
    }
    return context_id, packet, true;
}

// ---- MASQUE CONNECT-IP (RFC 9484) ---------------------------------------

struct IpAddressRequest {
    request_id:   u64      = 0,
    ip_version:   u8       = 4,
    prefix_len:   u8       = 32,
    requested_ip: u8[..16] = [],
}

struct IpAddressAssign {
    request_id:  u64      = 0,
    ip_version:  u8       = 4,
    prefix_len:  u8       = 32,
    assigned_ip: u8[..16] = [],
}

struct RouteAdvertisement {
    ip_version:  u8       = 4,
    start_ip:    u8[..16] = [],
    end_ip:      u8[..16] = [],
    ip_protocol: u8       = 0,
}

// Encodes an ADDRESS_REQUEST Capsule (RFC 9484 Section 4.7.2):
// Format: Request ID (VarInt) || IP Version (u8) || IP bytes (4 or 16) || Prefix Len (u8)
fn encode_address_request_capsule<B>(out: B&, req: const IpAddressRequest&) -> bool {
    guard req.request_id != 0 else { return false; }
    var body: u8[..128] = [];
    guard quic::encode_varint(req.request_id, body) else { return false; }
    body.push(req.ip_version);
    if req.ip_version == 4 {
        guard req.prefix_len <= 32 else { return false; }
        if req.requested_ip.len == 4 {
            guard net_internal::has_zero_host_bits(req.requested_ip[..], req.prefix_len) else { return false; }
            body.append(req.requested_ip[..]);
        } else if req.requested_ip.len == 0 {
            let zeros: u8[4] = [0, 0, 0, 0];
            body.append(zeros[..]);
        } else {
            return false;
        }
    } else if req.ip_version == 6 {
        guard req.prefix_len <= 128 else { return false; }
        if req.requested_ip.len == 16 {
            guard net_internal::has_zero_host_bits(req.requested_ip[..], req.prefix_len) else { return false; }
            body.append(req.requested_ip[..]);
        } else if req.requested_ip.len == 0 {
            let zeros: u8[16] = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
            body.append(zeros[..]);
        } else {
            return false;
        }
    } else {
        return false;
    }
    body.push(req.prefix_len);
    return encode_http_capsule(out, rfc::CAPSULE_ADDRESS_REQUEST, body[..]);
}

// Decodes an ADDRESS_REQUEST Capsule payload (RFC 9484 §4.7.2).
//
// Example:
//   payload = "\x01\x04\x0a\x00\x00\x01\x20"
//   returns: req.request_id = 1, req.ip_version = 4, req.requested_ip = [10, 0, 0, 1], req.prefix_len = 32, ok = true
fn decode_address_request_capsule(payload: const u8[:]) -> IpAddressRequest, bool {
    var req = IpAddressRequest { .. };
    guard payload.len > 0 else { return req, false; }
    var cur: i64 = 0;
    while cur < payload.len {
        guard net_internal::decode_address_request_entry(payload, cur, req) else { return req, false; }
    }
    return req, cur == payload.len && req.requested_ip.len > 0;
}

// Encodes an ADDRESS_ASSIGN Capsule (RFC 9484 Section 4.7.1):
// Format: Request ID (VarInt) || IP Version (u8) || Assigned IP (4 or 16 bytes) || Prefix Len (u8)
fn encode_address_assign_capsule<B>(out: B&, assign: const IpAddressAssign&) -> bool {
    var body: u8[..128] = [];
    guard quic::encode_varint(assign.request_id, body) else { return false; }
    body.push(assign.ip_version);
    if assign.ip_version == 4 {
        guard assign.prefix_len <= 32 && assign.assigned_ip.len == 4 else { return false; }
        guard net_internal::has_zero_host_bits(assign.assigned_ip[..], assign.prefix_len) else { return false; }
        body.append(assign.assigned_ip[..]);
    } else if assign.ip_version == 6 {
        guard assign.prefix_len <= 128 && assign.assigned_ip.len == 16 else { return false; }
        guard net_internal::has_zero_host_bits(assign.assigned_ip[..], assign.prefix_len) else { return false; }
        body.append(assign.assigned_ip[..]);
    } else {
        return false;
    }
    body.push(assign.prefix_len);
    return encode_http_capsule(out, rfc::CAPSULE_ADDRESS_ASSIGN, body[..]);
}

// RFC 9484 Section 4.7.1: ADDRESS_ASSIGN Capsule - empty capsule withdraws all assigned addresses
//
// Example:
//   payload = "\x01\x04\x0a\x00\x00\x01\x20"
//   returns: assign.request_id = 1, assign.ip_version = 4,
//            assign.assigned_ip = [10, 0, 0, 1], assign.prefix_len = 32, ok = true
fn decode_address_assign_capsule(payload: const u8[:]) -> IpAddressAssign, bool {
    var assign = IpAddressAssign { .. };
    if payload.len == 0 {
        assign.prefix_len = 0;
        return assign, true;
    }
    var cur: i64 = 0;
    while cur < payload.len {
        guard net_internal::decode_address_assign_entry(payload, cur, assign) else { return assign, false; }
    }
    return assign, cur == payload.len && assign.assigned_ip.len > 0;
}

// Encodes a ROUTE_ADVERTISEMENT Capsule (RFC 9484 Section 4.7.3):
// Format: IP Version (u8) || Start IP (4 or 16) || End IP (4 or 16) || IP Protocol (u8)
fn encode_route_advertisement_capsule<B>(out: B&, route: const RouteAdvertisement&) -> bool {
    guard net_internal::is_valid_ip_range(route.start_ip[..], route.end_ip[..]) else { return false; }
    var body: u8[..128] = [];
    body.push(route.ip_version);
    if route.ip_version == 4 {
        guard route.start_ip.len == 4 && route.end_ip.len == 4 else { return false; }
        body.append(route.start_ip[..]);
        body.append(route.end_ip[..]);
    } else if route.ip_version == 6 {
        guard route.start_ip.len == 16 && route.end_ip.len == 16 else { return false; }
        body.append(route.start_ip[..]);
        body.append(route.end_ip[..]);
    } else {
        return false;
    }
    body.push(route.ip_protocol);
    return encode_http_capsule(out, rfc::CAPSULE_ROUTE_ADVERTISEMENT, body[..]);
}

// RFC 9484 Section 4.7.3: ROUTE_ADVERTISEMENT Capsule - empty capsule withdraws all advertised routes
//
// Example:
//   payload = "\x04\x0a\x00\x00\x00\x0a\x00\x00\xff\x00"
//   returns: route.ip_version = 4, start_ip = 10.0.0.0, end_ip = 10.0.0.255, ip_protocol = 0, ok = true
fn decode_route_advertisement_capsule(payload: const u8[:]) -> RouteAdvertisement, bool {
    var route = RouteAdvertisement { .. };
    if payload.len == 0 {
        return route, true;
    }
    var cur: i64 = 0;
    while cur < payload.len {
        guard net_internal::decode_route_entry(payload, cur, route) else { return route, false; }
    }
    return route, cur == payload.len && net_internal::is_valid_ip_range(route.start_ip[..], route.end_ip[..]);
}

// ---- MASQUE Tunnel Session Manager ---------------------------------------

enum MasqueTunnelState {
    Idle,
    Connecting,
    Established,
    Closed,
    Failed,
}

enum MasqueProtocolMode {
    ConnectUdp,
    ConnectIp,
}

struct MasqueTunnelConfig {
    proxy_url:          u8[..256]          = [],
    mode:               MasqueProtocolMode = MasqueProtocolMode.ConnectUdp,
    target_host:        u8[..256]          = [],
    target_port:        u16                = 53,
    use_quic_datagrams: bool               = true,
}

struct MasqueTunnelSession {
    config:              MasqueTunnelConfig = MasqueTunnelConfig { .. },
    stream_id:           u64                = 0,
    quarter_stream_id:   u64                = 0,
    state:               MasqueTunnelState  = MasqueTunnelState.Idle,
    assigned_ip:         u8[..16]           = [],
    assigned_prefix_len: u8                 = 32,
    packets_sent:        u64                = 0,
    packets_received:    u64                = 0,
    bytes_sent:          u64                = 0,
    bytes_received:      u64                = 0,
}

fn new_connect_udp_tunnel(
    proxy_url:     const u8[:],
    target_host:   const u8[:],
    target_port:   u16,
    stream_id:     u64  = 0,
    use_datagrams: bool = true,
) -> MasqueTunnelSession {
    var s = MasqueTunnelSession {
        stream_id:         stream_id,
        quarter_stream_id: stream_id >> 2,
        state:             MasqueTunnelState.Idle,
        ..
    };
    let _ = s.config.proxy_url.try_append(proxy_url);
    s.config.mode = MasqueProtocolMode.ConnectUdp;
    let _ = s.config.target_host.try_append(target_host);
    s.config.target_port = target_port;
    s.config.use_quic_datagrams = use_datagrams;
    return s;
}

fn new_connect_ip_tunnel(
    proxy_url:     const u8[:],
    stream_id:     u64  = 0,
    use_datagrams: bool = true,
) -> MasqueTunnelSession {
    var s = MasqueTunnelSession {
        stream_id:         stream_id,
        quarter_stream_id: stream_id >> 2,
        state:             MasqueTunnelState.Idle,
        ..
    };
    let _ = s.config.proxy_url.try_append(proxy_url);
    s.config.mode = MasqueProtocolMode.ConnectIp;
    s.config.use_quic_datagrams = use_datagrams;
    return s;
}

// Builds the HTTP Extended CONNECT request headers and path for MASQUE handshake (RFC 9298 & RFC 9484)
fn build_masque_connect_request(
    tunnel:      const MasqueTunnelSession&,
    out_headers: http::HeaderMap&,
    out_path:    u8[..256]&,
) {
    out_headers.clear();
    out_path.clear();
    if tunnel.config.mode == MasqueProtocolMode.ConnectUdp {
        format_connect_udp_path(out_path, tunnel.config.target_host[..], tunnel.config.target_port);
    } else {
        out_path.append("/.well-known/masque/ip/");
    }

    let view, err = core::parse_url_view(tunnel.config.proxy_url[..]);
    var scheme_buf: u8[..16]  = [];
    var auth_buf:   u8[..256] = [];
    if view.valid && view.scheme.len > 0 {
        let _ = scheme_buf.try_append(view.scheme);
    } else {
        scheme_buf.append("https");
    }

    if view.valid && view.host.len > 0 {
        let _ = auth_buf.try_append(view.host);
        if view.port > 0 && auth_buf.len <= 249 {
            auth_buf.push(':');
            view.port.format_i64_dec(auth_buf);
        }
    } else if tunnel.config.proxy_url.len > 0 {
        let _ = auth_buf.try_append(tunnel.config.proxy_url[..]);
    }

    out_headers.set_header(":method", "CONNECT");
    if tunnel.config.mode == MasqueProtocolMode.ConnectUdp {
        out_headers.set_header(":protocol", rfc::MASQUE_PROTOCOL_CONNECT_UDP);
    } else {
        out_headers.set_header(":protocol", rfc::MASQUE_PROTOCOL_CONNECT_IP);
    }
    out_headers.set_header(":scheme", scheme_buf[..]);
    out_headers.set_header(":authority", auth_buf[..]);
    out_headers.set_header(":path", out_path[..]);
    out_headers.set_header("capsule-protocol", rfc::MASQUE_CAPSULE_VALUE);
}

// Sends a packet through the tunnel: either as a QUIC DATAGRAM frame or as an in-stream DATAGRAM capsule.
fn send_packet<B>(tunnel: MasqueTunnelSession&, packet: const u8[:], out_wire: B&) -> bool {
    guard tunnel.state == MasqueTunnelState.Established else { return false; }

    var ok = false;
    if tunnel.config.use_quic_datagrams {
        var dgram_body: u8[..2048] = [];
        guard encode_http_datagram(dgram_body, tunnel.quarter_stream_id, 0, packet) else { return false; }
        ok = quic::encode_datagram_frame(dgram_body[..], out_wire, true);
    } else {
        ok = encode_connect_udp_datagram_capsule(out_wire, 0, packet);
    }

    if ok {
        tunnel.packets_sent = core::add_sat_u64(tunnel.packets_sent, 1);
        tunnel.bytes_sent = core::add_sat_u64(tunnel.bytes_sent, packet.len as u64);
    }
    return ok;
}

// RFC 9484 Section 4.7.1: ADDRESS_ASSIGN Capsule - empty payload removes all assigned addresses
fn apply_assigned_ip(tunnel: MasqueTunnelSession&, payload: const u8[:]) -> bool {
    let assign, ok_a = decode_address_assign_capsule(payload);
    guard ok_a else { return false; }
    if payload.len == 0 {
        tunnel.assigned_ip.clear();
        tunnel.assigned_prefix_len = 0;
        return true;
    }
    guard assign.assigned_ip.len > 0 && !net_internal::is_all_zero_ip_bytes(assign.assigned_ip[..]) else {
        return false;
    }
    guard tunnel.assigned_ip.try_set(assign.assigned_ip[..]) else { return false; }
    tunnel.assigned_prefix_len = assign.prefix_len;
    return true;
}

// Ingests an incoming in-stream Capsule from the tunnel wire stream.
fn receive_capsule<B>(tunnel: MasqueTunnelSession&, capsule_wire: const u8[:], out_packet: B&) -> bool {
    guard tunnel.state == MasqueTunnelState.Established else { return false; }

    let c, ok_c = parse_http_capsule(capsule_wire);
    // RFC 9297 Section 3.2: The Capsule Protocol - capsule buffer must match exact Type+Length+Value size
    guard ok_c && core::add_sat_i64(c.header_len as i64, c.payload.len) == capsule_wire.len else {
        return false;
    }

    if c.capsule_type == rfc::CAPSULE_DATAGRAM {
        let ctx_id, pkt, ok_pkt = parse_connect_udp_datagram(c.payload);
        guard ok_pkt && ctx_id == 0 else { return false; }
        guard out_packet.try_set(pkt) else { return false; }
        tunnel.packets_received = core::add_sat_u64(tunnel.packets_received, 1);
        tunnel.bytes_received = core::add_sat_u64(tunnel.bytes_received, pkt.len as u64);
        return true;
    }

    if c.capsule_type == rfc::CAPSULE_ADDRESS_ASSIGN || c.capsule_type == rfc::CAPSULE_DRAFT_ADDRESS_ASSIGN {
        guard apply_assigned_ip(tunnel, c.payload) else { return false; }
        out_packet.clear();
        return true;
    }

    if c.capsule_type == rfc::CAPSULE_ROUTE_ADVERTISEMENT || c.capsule_type == rfc::CAPSULE_DRAFT_ROUTE_ADVERTISEMENT {
        let _, ok_r = decode_route_advertisement_capsule(c.payload);
        guard ok_r else { return false; }
        out_packet.clear();
        return true;
    }

    // RFC 9297 §3.2: Endpoints which receive a capsule with an unknown capsule type MUST silently ignore that capsule.
    out_packet.clear();
    return true;
}

// Ingests an incoming QUIC DATAGRAM frame from the tunnel.
fn receive_quic_datagram<B>(
    tunnel:                 MasqueTunnelSession&,
    datagram_frame_payload: const u8[:],
    out_packet:             B&,
) -> bool {
    guard tunnel.state == MasqueTunnelState.Established else { return false; }

    let q_id, ctx_id, pkt, ok = decode_http_datagram(datagram_frame_payload);
    guard ok && q_id == tunnel.quarter_stream_id &&
          ctx_id == 0 && pkt.len <= MAX_CONNECT_UDP_PAYLOAD_LEN else { return false; }

    guard out_packet.try_set(pkt) else { return false; }
    tunnel.packets_received = core::add_sat_u64(tunnel.packets_received, 1);
    tunnel.bytes_received = core::add_sat_u64(tunnel.bytes_received, pkt.len as u64);
    return true;
}
