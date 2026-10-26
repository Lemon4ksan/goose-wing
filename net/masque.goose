// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// HTTP Datagrams and Capsules (RFC 9297), MASQUE CONNECT-UDP (RFC 9298), & MASQUE CONNECT-IP (RFC 9484).
// Zero-heap protocol codec for modern privacy proxies and UDP/IP tunneling over HTTP/2 and HTTP/3.
namespace wing;

import std;

// ---- 1. Capsule Types & Constants (RFC 9297 Section 3, RFC 9484 Section 4) ---

const CAPSULE_DATAGRAM: u64 = 0x00;                   // RFC 9297 Section 3.5
const CAPSULE_PADDING: u64 = 0x01;                    // RFC 9297 Section 3.6
const CAPSULE_ADDRESS_ASSIGN: u64 = 0x1E;             // RFC 9484 CONNECT-IP Section 4.1
const CAPSULE_ADDRESS_REQUEST: u64 = 0x1F;            // RFC 9484 CONNECT-IP Section 4.2
const CAPSULE_ROUTE_ADVERTISEMENT: u64 = 0x20;        // RFC 9484 CONNECT-IP Section 4.3
const CAPSULE_WT_RESET_STREAM: u64 = 0x2841;          // WebTransport
const CAPSULE_WT_STOP_SENDING: u64 = 0x2842;          // WebTransport
const CAPSULE_CLOSE_WEBTRANSPORT: u64 = 0x2843;       // WebTransport
const CAPSULE_DRAIN_WEBTRANSPORT: u64 = 0x78AE;       // WebTransport

// Legacy draft backward-compatibility constants
const CAPSULE_DRAFT_ADDRESS_ASSIGN: u64 = 0x3861;
const CAPSULE_DRAFT_ADDRESS_REQUEST: u64 = 0x3862;
const CAPSULE_DRAFT_ROUTE_ADVERTISEMENT: u64 = 0x3863;

const MASQUE_PROTOCOL_CONNECT_UDP: const u8[:] = "connect-udp";
const MASQUE_PROTOCOL_CONNECT_IP: const u8[:] = "connect-ip";
const MASQUE_CAPSULE_HEADER: const u8[:] = "capsule-protocol";
const MASQUE_CAPSULE_VALUE: const u8[:] = "?1";

struct HttpCapsule {
    capsule_type: u64 = 0,
    payload: const u8[:] = [],
    header_len: u64 = 0,
}

// ---- 2. Capsule Codec (RFC 9297 Section 3.1) -------------------------------

// Parses an HTTP Capsule header and value from wire stream:
// Capsule format: Type (VarInt) || Length (VarInt) || Value (bytes)
fn parse_http_capsule(src: const u8[:]) -> HttpCapsule, bool {
    var c = HttpCapsule { payload: src[..0], .. };
    guard src.len > 0 else { return c, false; }

    let ctype, off1, ok1 = quic_decode_varint(src, 0);
    guard ok1 else { return c, false; }

    let clen, off2, ok2 = quic_decode_varint(src, off1);
    guard ok2 else { return c, false; }

    let total_len = off2 + clen;
    guard src.len >= (total_len as i64) else { return c, false; }

    let start_idx = off2 as i64;
    let end_idx = total_len as i64;
    c.capsule_type = ctype;
    c.payload = src[start_idx..end_idx];
    c.header_len = off2;
    return c, true;
}

// Encodes an HTTP Capsule into buffer: Type (VarInt) || Length (VarInt) || Value
fn encode_http_capsule<B>(out: B&, capsule_type: u64, payload: const u8[:]) -> bool {
    guard quic_encode_varint(out, capsule_type) else { return false; }
    guard quic_encode_varint(out, payload.len as u64) else { return false; }
    out.append(payload);
    return true;
}

// Checks if Capsule-Protocol header value matches boolean `?1` (RFC 9297 Section 3.4 / RFC 8941)
fn is_capsule_protocol_negotiated(header_val: const u8[:]) -> bool {
    let trimmed = trim_lws(header_val);
    if trimmed == "?1" {
        return true;
    }
    if starts_with(trimmed, "?1;") || starts_with(trimmed, "?1,") {
        return true;
    }
    return false;
}

// Checks if Capsule-Protocol header is negotiated in a HeaderMap
fn has_capsule_protocol(headers: const HeaderMap&) -> bool {
    let val = headers.get_header("capsule-protocol");
    return is_capsule_protocol_negotiated(val);
}

// Checks if Capsule-Protocol header is negotiated in a HeaderItem slice
fn has_capsule_protocol(headers: const HeaderItem[:]) -> bool {
    let val = headers.find_header("capsule-protocol");
    return is_capsule_protocol_negotiated(val);
}

// ---- 3. HTTP Datagrams (RFC 9297 Section 2) --------------------------------

// Encodes an HTTP Datagram payload for QUIC DATAGRAM frame (RFC 9297 Section 2.1):
// Format: Quarter Stream ID (VarInt) || Context ID (VarInt) || HTTP Datagram Payload
fn encode_http_datagram<B>(out: B&, quarter_stream_id: u64, context_id: u64, payload: const u8[:]) -> bool {
    guard quic_encode_varint(out, quarter_stream_id) else { return false; }
    guard quic_encode_varint(out, context_id) else { return false; }
    out.append(payload);
    return true;
}

// Decodes an HTTP Datagram payload from QUIC DATAGRAM frame:
// Returns (Quarter Stream ID, Context ID, Payload, Ok)
fn decode_http_datagram(wire: const u8[:]) -> u64, u64, const u8[:], bool {
    guard wire.len > 0 else { return 0, 0, wire[..0], false; }
    let q_id, off1, ok1 = quic_decode_varint(wire, 0);
    guard ok1 else { return 0, 0, wire[..0], false; }
    let ctx_id, off2, ok2 = quic_decode_varint(wire, off1);
    guard ok2 else { return 0, 0, wire[..0], false; }
    let payload = wire[(off2 as i64)..];
    return q_id, ctx_id, payload, true;
}

// ---- 4. MASQUE CONNECT-UDP (RFC 9298) --------------------------------------

// Formats a MASQUE URI template path for target host and port (RFC 9298 Section 2):
// e.g. `/.well-known/masque/udp/1.1.1.1/53/`
fn format_connect_udp_path<B>(out: B&, target_host: const u8[:], target_port: u16) {
    out.append("/.well-known/masque/udp/");
    out.append(target_host);
    out.push('/');
    core::format_u64_dec(target_port as u64, out);
    out.push('/');
}

// Parses a MASQUE CONNECT-UDP URI template path into (host, port, ok)
fn parse_connect_udp_path(path: const u8[:]) -> u8[..128], u16, bool {
    var out_host: u8[..128] = [];
    var out_port: u16 = 0;
    let prefix = "/.well-known/masque/udp/";
    guard starts_with(path, prefix) else { return out_host, 0, false; }

    let rem = path[prefix.len..];
    let host_part, rem_after_host, host_ok = core::split_once_byte(rem, '/');
    guard host_ok && host_part.len > 0 else { return out_host, 0, false; }
    guard host_part.len <= out_host.cap else { return out_host, 0, false; }
    out_host.append(host_part);

    var port_part = rem_after_host;
    if port_part.len > 0 && port_part[port_part.len - 1] == '/' {
        port_part = port_part[..port_part.len - 1];
    }
    guard port_part.len > 0 else { return out_host, 0, false; }

    let p_val, parse_ok = core::parse_u32_dec(port_part);
    guard parse_ok && p_val <= 65535 else { return out_host, 0, false; }
    out_port = p_val as u16;
    return out_host, out_port, true;
}

// Encodes a UDP payload into a DATAGRAM capsule (RFC 9297 / RFC 9298 Section 5):
// Format: Context ID (VarInt = 0) || UDP Payload
fn encode_connect_udp_datagram_capsule<B>(out: B&, context_id: u64, udp_packet: const u8[:]) -> bool {
    var datagram_body: u8[>..] = [];
    guard quic_encode_varint(datagram_body, context_id) else { return false; }
    datagram_body.append(udp_packet);
    return encode_http_capsule(out, CAPSULE_DATAGRAM, datagram_body[..]);
}

// Parses a DATAGRAM capsule payload into (context_id, udp_packet, ok)
fn parse_connect_udp_datagram(capsule_payload: const u8[:]) -> u64, const u8[:], bool {
    guard capsule_payload.len > 0 else { return 0, capsule_payload[..0], false; }
    let context_id, off, ok = quic_decode_varint(capsule_payload, 0);
    guard ok else { return 0, capsule_payload[..0], false; }
    let start_idx = off as i64;
    let packet = capsule_payload[start_idx..];
    return context_id, packet, true;
}

// ---- 5. MASQUE CONNECT-IP (RFC 9484) ---------------------------------------

struct IpAddressRequest {
    request_id: u64 = 0,
    ip_version: u8 = 4,
    prefix_len: u8 = 32,
    requested_ip: u8[..16] = [],
}

struct IpAddressAssign {
    request_id: u64 = 0,
    ip_version: u8 = 4,
    prefix_len: u8 = 32,
    assigned_ip: u8[..16] = [],
}

struct RouteAdvertisement {
    ip_version: u8 = 4,
    prefix_len: u8 = 0,
    ip_prefix: u8[..16] = [],
}

// Encodes an ADDRESS_REQUEST Capsule (RFC 9484 Section 4.2):
// Format: Request ID (VarInt) || IP Version (u8) || Prefix Len (u8) || IP bytes (optional)
fn encode_address_request_capsule<B>(out: B&, req: const IpAddressRequest&) -> bool {
    var body: u8[>..] = [];
    guard quic_encode_varint(body, req.request_id) else { return false; }
    body.push(req.ip_version);
    body.push(req.prefix_len);
    body.append(req.requested_ip[..]);
    return encode_http_capsule(out, CAPSULE_ADDRESS_REQUEST, body[..]);
}

// Decodes an ADDRESS_REQUEST Capsule payload
fn decode_address_request_capsule(payload: const u8[:]) -> IpAddressRequest, bool {
    var req = IpAddressRequest { .. };
    guard payload.len >= 2 else { return req, false; }
    let req_id, off, ok = quic_decode_varint(payload, 0);
    guard ok && (payload.len as u64) >= (off + 2) else { return req, false; }

    req.request_id = req_id;
    req.ip_version = payload[off as i64];
    req.prefix_len = payload[(off + 1) as i64];
    let ip_bytes = payload[((off + 2) as i64)..];
    guard ip_bytes.len <= req.requested_ip.cap else { return req, false; }
    req.requested_ip.append(ip_bytes);
    return req, true;
}

// Encodes an ADDRESS_ASSIGN Capsule (RFC 9484 Section 4.1):
// Format: Request ID (VarInt) || IP Version (u8) || Prefix Len (u8) || Assigned IP (4 or 16 bytes)
fn encode_address_assign_capsule<B>(out: B&, assign: const IpAddressAssign&) -> bool {
    var body: u8[>..] = [];
    guard quic_encode_varint(body, assign.request_id) else { return false; }
    body.push(assign.ip_version);
    body.push(assign.prefix_len);
    body.append(assign.assigned_ip[..]);
    return encode_http_capsule(out, CAPSULE_ADDRESS_ASSIGN, body[..]);
}

// Decodes an ADDRESS_ASSIGN Capsule payload
fn decode_address_assign_capsule(payload: const u8[:]) -> IpAddressAssign, bool {
    var assign = IpAddressAssign { .. };
    guard payload.len >= 2 else { return assign, false; }
    let req_id, off, ok = quic_decode_varint(payload, 0);
    guard ok && (payload.len as u64) >= (off + 2) else { return assign, false; }

    assign.request_id = req_id;
    assign.ip_version = payload[off as i64];
    assign.prefix_len = payload[(off + 1) as i64];
    let ip_bytes = payload[((off + 2) as i64)..];
    guard ip_bytes.len <= assign.assigned_ip.cap else { return assign, false; }
    assign.assigned_ip.append(ip_bytes);
    return assign, true;
}

// Encodes a ROUTE_ADVERTISEMENT Capsule (RFC 9484 Section 4.3)
fn encode_route_advertisement_capsule<B>(out: B&, route: const RouteAdvertisement&) -> bool {
    var body: u8[>..] = [];
    body.push(route.ip_version);
    body.push(route.prefix_len);
    body.append(route.ip_prefix[..]);
    return encode_http_capsule(out, CAPSULE_ROUTE_ADVERTISEMENT, body[..]);
}

// Decodes a ROUTE_ADVERTISEMENT Capsule payload
fn decode_route_advertisement_capsule(payload: const u8[:]) -> RouteAdvertisement, bool {
    var route = RouteAdvertisement { .. };
    guard payload.len >= 2 else { return route, false; }
    route.ip_version = payload[0];
    route.prefix_len = payload[1];
    let p_bytes = payload[2..];
    guard p_bytes.len <= route.ip_prefix.cap else { return route, false; }
    route.ip_prefix.append(p_bytes);
    return route, true;
}

// Encapsulates an IP packet into a stream DATAGRAM capsule (Context ID = 0)
fn encode_connect_ip_datagram_capsule<B>(out: B&, context_id: u64, ip_packet: const u8[:]) -> bool {
    return encode_connect_udp_datagram_capsule(out, context_id, ip_packet);
}

// Parses an IP packet from a stream DATAGRAM capsule
fn parse_connect_ip_datagram(capsule_payload: const u8[:]) -> u64, const u8[:], bool {
    return parse_connect_udp_datagram(capsule_payload);
}

// ---- 6. MASQUE Tunnel Session Manager ---------------------------------------

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
    proxy_url: u8[..256] = [],
    mode: MasqueProtocolMode = MasqueProtocolMode.ConnectUdp,
    target_host: u8[..128] = [],
    target_port: u16 = 53,
    use_quic_datagrams: bool = true,
}

struct MasqueTunnelSession {
    config: MasqueTunnelConfig = MasqueTunnelConfig { .. },
    stream_id: u64 = 0,
    quarter_stream_id: u64 = 0,
    state: MasqueTunnelState = MasqueTunnelState.Idle,
    assigned_ip: u8[..16] = [],
    assigned_prefix_len: u8 = 32,
    packets_sent: u64 = 0,
    packets_received: u64 = 0,
    bytes_sent: u64 = 0,
    bytes_received: u64 = 0,
}

fn new_connect_udp_tunnel(
    proxy_url: const u8[:],
    target_host: const u8[:],
    target_port: u16,
    stream_id: u64 = 0,
    use_datagrams: bool = true,
) -> MasqueTunnelSession {
    var s = MasqueTunnelSession {
        stream_id: stream_id,
        quarter_stream_id: stream_id / 4,
        state: MasqueTunnelState.Idle,
        ..
    };
    s.config.proxy_url.append(proxy_url);
    s.config.mode = MasqueProtocolMode.ConnectUdp;
    s.config.target_host.append(target_host);
    s.config.target_port = target_port;
    s.config.use_quic_datagrams = use_datagrams;
    return s;
}

fn new_connect_ip_tunnel(
    proxy_url: const u8[:],
    stream_id: u64 = 0,
    use_datagrams: bool = true,
) -> MasqueTunnelSession {
    var s = MasqueTunnelSession {
        stream_id: stream_id,
        quarter_stream_id: stream_id / 4,
        state: MasqueTunnelState.Idle,
        ..
    };
    s.config.proxy_url.append(proxy_url);
    s.config.mode = MasqueProtocolMode.ConnectIp;
    s.config.use_quic_datagrams = use_datagrams;
    return s;
}

// Builds the HTTP Extended CONNECT request headers and path for MASQUE handshake
fn build_masque_connect_request(
    tunnel: const MasqueTunnelSession&,
    out_headers: HeaderItem[..16]&,
    out_path: u8[..256]&,
) {
    out_headers.clear();
    out_headers.set_header(":method", "CONNECT");
    if tunnel.config.mode == MasqueProtocolMode.ConnectUdp {
        out_headers.set_header(":protocol", MASQUE_PROTOCOL_CONNECT_UDP);
        format_connect_udp_path(out_path, tunnel.config.target_host[..], tunnel.config.target_port);
    } else {
        out_headers.set_header(":protocol", MASQUE_PROTOCOL_CONNECT_IP);
        out_path.append("/.well-known/masque/ip/");
    }
    out_headers.set_header("capsule-protocol", MASQUE_CAPSULE_VALUE);
}

// Sends a packet through the tunnel: either as a QUIC DATAGRAM frame or as an in-stream DATAGRAM capsule.
fn send_packet<B>(tunnel: MasqueTunnelSession&, packet: const u8[:], out_wire: B&) -> bool {
    guard tunnel.state == MasqueTunnelState.Established else { return false; }

    var ok = false;
    if tunnel.config.use_quic_datagrams {
        var dgram_body: u8[>..] = [];
        guard encode_http_datagram(dgram_body, tunnel.quarter_stream_id, 0, packet) else { return false; }
        ok = encode_quic_datagram_frame(out_wire, dgram_body[..], true);
    } else {
        ok = encode_connect_udp_datagram_capsule(out_wire, 0, packet);
    }

    if ok {
        tunnel.packets_sent++;
        tunnel.bytes_sent += packet.len as u64;
    }
    return ok;
}

// Ingests an incoming in-stream Capsule from the tunnel wire stream.
fn receive_capsule<B>(tunnel: MasqueTunnelSession&, capsule_wire: const u8[:], out_packet: B&) -> bool {
    guard tunnel.state == MasqueTunnelState.Established else { return false; }

    let c, ok_c = parse_http_capsule(capsule_wire);
    guard ok_c else { return false; }

    if c.capsule_type == CAPSULE_DATAGRAM {
        let ctx_id, pkt, ok_pkt = parse_connect_udp_datagram(c.payload);
        guard ok_pkt && ctx_id == 0 else { return false; }
        out_packet.append(pkt);
        tunnel.packets_received++;
        tunnel.bytes_received += pkt.len as u64;
        return true;
    } else if c.capsule_type == CAPSULE_ADDRESS_ASSIGN || c.capsule_type == CAPSULE_DRAFT_ADDRESS_ASSIGN {
        let assign, ok_a = decode_address_assign_capsule(c.payload);
        guard ok_a else { return false; }
        tunnel.assigned_ip.clear();
        tunnel.assigned_ip.append(assign.assigned_ip[..]);
        tunnel.assigned_prefix_len = assign.prefix_len;
        return true;
    }
    return false;
}

// Ingests an incoming QUIC DATAGRAM frame from the tunnel.
fn receive_quic_datagram<B>(tunnel: MasqueTunnelSession&, datagram_frame_payload: const u8[:], out_packet: B&) -> bool {
    guard tunnel.state == MasqueTunnelState.Established else { return false; }

    let q_id, ctx_id, pkt, ok = decode_http_datagram(datagram_frame_payload);
    guard ok && q_id == tunnel.quarter_stream_id && ctx_id == 0 else { return false; }

    out_packet.append(pkt);
    tunnel.packets_received++;
    tunnel.bytes_received += pkt.len as u64;
    return true;
}
