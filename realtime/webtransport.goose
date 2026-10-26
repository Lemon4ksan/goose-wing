// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// W3C / IETF draft-ietf-webtrans-http3-16 (WebTransport over HTTP/3)
// and RFC 9221 (An Unreliable Datagram Extension to QUIC).
// Implements extended CONNECT session bootstrapping (:protocol = webtransport),
// HTTP/3 settings negotiation, unidirectional stream typing (0x54), and unreliable datagram framing.
namespace wing;

import std;
import client.profile;
import client.request;
import client.response;

// ---- 1. WebTransport & RFC 9221 Constants (draft-16) -------------------------

const WEBTRANSPORT_PROTOCOL: const u8[:] = "webtransport";
const SETTINGS_WEBTRANSPORT_MAX_SESSIONS: u64 = 0x2b603742;
const SETTINGS_H3_DATAGRAM: u64 = 0x33;

const STREAM_TYPE_WEBTRANSPORT: u64 = 0x54;

// ---- 2. WebTransport Models -------------------------------------------------

struct WebTransportSession {
    session_id: u64 = 0,
    is_active: bool = false,
    max_sessions: u64 = 16,
    datagrams_enabled: bool = true,
}

struct WebTransportDatagram {
    session_id: u64 = 0,
    payload: u8[..1500] = [],
}

// ---- 3. Varint Helper (RFC 9000 Section 16) ---------------------------------

fn write_varint<B>(out: B&, val: u64) {
    if val <= 63 {
        out.push(val as u8);
    } else if val <= 16383 {
        out.push((0x40 | ((val >> 8) & 0x3F)) as u8);
        out.push((val & 0xFF) as u8);
    } else if val <= 1073741823 {
        out.push((0x80 | ((val >> 24) & 0x3F)) as u8);
        out.push(((val >> 16) & 0xFF) as u8);
        out.push(((val >> 8) & 0xFF) as u8);
        out.push((val & 0xFF) as u8);
    } else {
        out.push((0xC0 | ((val >> 56) & 0x3F)) as u8);
        out.push(((val >> 48) & 0xFF) as u8);
        out.push(((val >> 40) & 0xFF) as u8);
        out.push(((val >> 32) & 0xFF) as u8);
        out.push(((val >> 24) & 0xFF) as u8);
        out.push(((val >> 16) & 0xFF) as u8);
        out.push(((val >> 8) & 0xFF) as u8);
        out.push((val & 0xFF) as u8);
    }
}

fn read_varint(wire: const u8[:], idx: i64&) -> u64, bool {
    guard idx < wire.len else { return 0, false; }
    let first = wire[idx];
    idx += 1;
    let prefix = first >> 6;

    if prefix == 0 {
        return (first & 0x3F), true;
    } else if prefix == 1 {
        guard idx < wire.len else { return 0, false; }
        let b1 = wire[idx];
        idx += 1;
        let v = (((first & 0x3F) as u64) << 8) | b1;
        return v, true;
    } else if prefix == 2 {
        guard idx + 2 < wire.len else { return 0, false; }
        var v = ((first & 0x3F) as u64) << 24;
        v |= (wire[idx] as u64) << 16;
        v |= (wire[idx + 1] as u64) << 8;
        v |= wire[idx + 2];
        idx += 3;
        return v, true;
    } else {
        guard idx + 6 < wire.len else { return 0, false; }
        var v = ((first & 0x3F) as u64) << 56;
        for i in 7 {
            v |= (wire[idx + i] as u64) << (8 * (6 - i));
        }
        idx += 7;
        return v, true;
    }
}

// ---- 4. Session Initiation (Extended CONNECT :protocol = webtransport) ------

// Formats an HTTP/3 Extended CONNECT request to open a WebTransport session
fn format_webtransport_connect_request(
    req: Request&,
    url_target: const u8[:],
) {
    req.method.clear();
    req.method.append("CONNECT");
    req.url.clear();
    req.url.append(url_target);

    // RFC 8441 / RFC 9220 / WebTransport draft-16:
    // :protocol = webtransport
    set_header(req, ":protocol", WEBTRANSPORT_PROTOCOL);
    set_header(req, "sec-webtransport-http3-draft", "draft16");
}

// Validates whether server response accepts the WebTransport session
fn handle_webtransport_response(res: const Response&, session: WebTransportSession&) -> bool {
    guard res.status_code >= 200 && res.status_code < 300 else {
        session.is_active = false;
        return false;
    }
    session.is_active = true;
    return true;
}

// ---- 5. Datagram Framing (draft-16 Section 5 & RFC 9221) ---------------------

// Encodes a WebTransport datagram:
// Quarter-Stream-ID / Session ID (varint) || Datagram Payload
fn encode_webtransport_datagram<B>(
    session_id: u64,
    payload: const u8[:],
    out: B&,
) {
    write_varint(out, session_id);
    out.append(payload);
}

// Decodes a WebTransport datagram from wire bytes
fn decode_webtransport_datagram(
    wire: const u8[:],
    out: WebTransportDatagram&,
) -> bool {
    out.payload.clear();
    var idx: i64 = 0;
    let s_id, ok = read_varint(wire, idx);
    guard ok else { return false; }

    out.session_id = s_id;
    guard idx <= wire.len else { return false; }

    for i in (wire.len - idx) {
        out.payload.push(wire[idx + i]);
    }

    return true;
}

// Encodes an RFC 9221 QUIC DATAGRAM frame (Type 0x31 with varint length)
fn encode_quic_datagram_frame<B>(
    datagram_payload: const u8[:],
    out: B&,
) {
    write_varint(out, QUIC_FRAME_DATAGRAM_LEN);
    write_varint(out, datagram_payload.len as u64);
    out.append(datagram_payload);
}

// Decodes an RFC 9221 QUIC DATAGRAM frame
fn decode_quic_datagram_frame(
    wire: const u8[:],
    out_payload: u8[>..]&,
) -> bool {
    out_payload.clear();
    var idx: i64 = 0;
    let frame_type, ok_t = read_varint(wire, idx);
    guard ok_t else { return false; }

    if frame_type == QUIC_FRAME_DATAGRAM {
        // Unbounded to end of wire
        for i in (wire.len - idx) {
            out_payload.push(wire[idx + i]);
        }
        return true;
    } else if frame_type == QUIC_FRAME_DATAGRAM_LEN {
        let len, ok_l = read_varint(wire, idx);
        guard ok_l && idx + (len as i64) <= wire.len else { return false; }
        for i in (len as i64) {
            out_payload.push(wire[idx + i]);
        }
        return true;
    }

    return false;
}
