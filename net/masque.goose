// HTTP Datagrams and Capsules (RFC 9297) & MASQUE CONNECT-UDP Tunneling (RFC 9298).
// Zero-heap protocol codec for modern privacy proxies and UDP tunneling over HTTP/2 and HTTP/3.
namespace wing;

import std;
import quic.packet;

// ---- 1. Capsule Types (RFC 9297 Section 3) ---------------------------------

const CAPSULE_DATAGRAM: u64                 = 0x00;   // RFC 9297 Section 3.5
const CAPSULE_PADDING: u64                  = 0x01;   // RFC 9297 Section 3.6
const CAPSULE_WT_RESET_STREAM: u64          = 0x2841; // WebTransport
const CAPSULE_WT_STOP_SENDING: u64          = 0x2842; // WebTransport
const CAPSULE_CLOSE_WEBTRANSPORT: u64       = 0x2843; // WebTransport
const CAPSULE_ADDRESS_ASSIGN: u64           = 0x3861; // RFC 9484 CONNECT-IP
const CAPSULE_ADDRESS_REQUEST: u64          = 0x3862; // RFC 9484 CONNECT-IP
const CAPSULE_ROUTE_ADVERTISEMENT: u64      = 0x3863; // RFC 9484 CONNECT-IP

struct HttpCapsule {
    capsule_type: u64 = 0,
    payload: const u8[:] = [],
    header_len: u64 = 0,
}

// ---- 2. Capsule Codec ------------------------------------------------------

// Parses an HTTP Capsule header and value from wire stream (RFC 9297 Section 3.1)
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
    c.payload = src[start_idx .. end_idx];
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

// ---- 3. MASQUE CONNECT-UDP (RFC 9298) Datagram Framing ---------------------

// Formats a MASQUE URI template path for target host and port:
// e.g. `/.well-known/masque/udp/1.1.1.1/53/`
fn format_connect_udp_path<B>(out: B&, target_host: const u8[:], target_port: u16) {
    out.append("/.well-known/masque/udp/");
    out.append(target_host);
    out.push('/');
    format(out, target_port);
    out.push('/');
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
