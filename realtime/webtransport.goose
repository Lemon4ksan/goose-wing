// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// W3C / IETF draft-ietf-webtrans-http3-16 (WebTransport over HTTP/3)
// and RFC 9221 (An Unreliable Datagram Extension to QUIC).
// Implements extended CONNECT session bootstrapping (:protocol = webtransport),
// HTTP/3 settings negotiation, unidirectional (0x54) and bidirectional (0x41) stream framing,
// unreliable datagram framing, HTTP/3 error code translation, and session capsules (draft-16 Section 8).
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
const WEBTRANSPORT_BIDI_SIGNAL: u64 = 0x41;

// WebTransport Capsules (draft-16 Section 8 & RFC 9297) are defined in net/masque.goose:
// CAPSULE_WT_RESET_STREAM (0x2841), CAPSULE_WT_STOP_SENDING (0x2842),
// CAPSULE_CLOSE_WEBTRANSPORT (0x2843), CAPSULE_DRAIN_WEBTRANSPORT (0x78AE).

// HTTP/3 Error Code Mapping bounds (draft-16 Section 4.3)
const WEBTRANSPORT_ERROR_FIRST: u64 = 0x52e4a40fa8db;
const WEBTRANSPORT_ERROR_LAST: u64 = 0x52e5ac983162;

// ---- 2. WebTransport Models -------------------------------------------------

struct WebTransportSession {
    session_id: u64 = 0,
    is_active: bool = false,
    is_draining: bool = false,
    close_code: u32 = 0,
    close_reason: u8[..1024] = [],
    max_sessions: u64 = 16,
    datagrams_enabled: bool = true,
}

struct WebTransportDatagram {
    session_id: u64 = 0,
    payload: u8[..1500] = [],
}

struct WebTransportUniStreamHeader {
    session_id: u64 = 0,
    header_len: i64 = 0,
}

struct WebTransportBidiStreamHeader {
    session_id: u64 = 0,
    header_len: i64 = 0,
}

struct WebTransportCloseSession {
    error_code: u32 = 0,
    reason: u8[..1024] = [],
}

struct WebTransportStreamReset {
    stream_id: u64 = 0,
    error_code: u32 = 0,
}

struct WebTransportStreamStopSending {
    stream_id: u64 = 0,
    error_code: u32 = 0,
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

// Validates whether an incoming HTTP request is an Extended CONNECT WebTransport request
fn is_webtransport_connect_request(req: const Request&) -> bool {
    if req.method[..] != "CONNECT" { return false; }
    if !req.has_header(":protocol") { return false; }
    if req.header(":protocol") != WEBTRANSPORT_PROTOCOL { return false; }
    return true;
}

// Formats an HTTP/3 response accepting a WebTransport session
fn format_webtransport_connect_response(res: Response&) {
    res.status_code = 200;
    set_header(res, "sec-webtransport-http3-draft", "draft16");
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

// ---- 5. Stream Framing (draft-16 Section 4.1 & Section 4.2) -----------------

// Encodes a WebTransport unidirectional stream header:
// Stream Type (0x54) || Session ID (varint)
fn encode_webtransport_uni_stream_header<B>(
    session_id: u64,
    out: B&,
) {
    write_varint(out, STREAM_TYPE_WEBTRANSPORT);
    write_varint(out, session_id);
}

// Decodes a WebTransport unidirectional stream header from wire bytes
fn decode_webtransport_uni_stream_header(
    wire: const u8[:],
    out: WebTransportUniStreamHeader&,
) -> bool {
    out.session_id = 0;
    out.header_len = 0;
    var idx: i64 = 0;
    let stype, ok1 = read_varint(wire, idx);
    guard ok1 && stype == STREAM_TYPE_WEBTRANSPORT else { return false; }

    let sid, ok2 = read_varint(wire, idx);
    guard ok2 else { return false; }

    out.session_id = sid;
    out.header_len = idx;
    return true;
}

// Encodes a WebTransport bidirectional stream opening header:
// Signal Value (0x41) || Session ID (varint)
fn encode_webtransport_bidi_stream_header<B>(
    session_id: u64,
    out: B&,
) {
    write_varint(out, WEBTRANSPORT_BIDI_SIGNAL);
    write_varint(out, session_id);
}

// Decodes a WebTransport bidirectional stream opening header from wire bytes
fn decode_webtransport_bidi_stream_header(
    wire: const u8[:],
    out: WebTransportBidiStreamHeader&,
) -> bool {
    out.session_id = 0;
    out.header_len = 0;
    var idx: i64 = 0;
    let signal, ok1 = read_varint(wire, idx);
    guard ok1 && signal == WEBTRANSPORT_BIDI_SIGNAL else { return false; }

    let sid, ok2 = read_varint(wire, idx);
    guard ok2 else { return false; }

    out.session_id = sid;
    out.header_len = idx;
    return true;
}

// ---- 6. Datagram Framing (draft-16 Section 5 & RFC 9221) ---------------------

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

// ---- 7. HTTP/3 Error Code Mapping (draft-16 Section 4.3) ---------------------

// Maps a 32-bit WebTransport application error code to HTTP/3 error code space,
// skipping HTTP/3 GREASE code points (0x1f * N + 0x21).
fn webtransport_code_to_http_code(app_err: u32) -> u64 {
    let n = app_err as u64;
    return WEBTRANSPORT_ERROR_FIRST + n + (n / 0x1E);
}

// Translates an HTTP/3 error code back to a 32-bit WebTransport application error code.
fn http_code_to_webtransport_code(h3_err: u64) -> u32, bool {
    guard h3_err >= WEBTRANSPORT_ERROR_FIRST && h3_err <= WEBTRANSPORT_ERROR_LAST else {
        return 0, false;
    }
    if h3_err >= 0x21 && ((h3_err - 0x21) % 0x1F) == 0 {
        return 0, false;
    }
    let shifted = h3_err - WEBTRANSPORT_ERROR_FIRST;
    let app_err = shifted - (shifted / 0x1F);
    return app_err as u32, true;
}

// ---- 8. WebTransport Capsule Codecs (draft-16 Section 8 & RFC 9297) ----------

// Encodes a CLOSE_WEBTRANSPORT_SESSION capsule:
// Capsule Type (varint 0x2843) || Length (varint: 4 + reason.len) || Error Code (4B BE) || Reason
fn encode_webtransport_close_session<B>(
    error_code: u32,
    reason: const u8[:],
    out: B&,
) {
    write_varint(out, CAPSULE_CLOSE_WEBTRANSPORT);
    let payload_len = 4 + reason.len;
    write_varint(out, payload_len as u64);

    out.push(((error_code >> 24) & 0xFF) as u8);
    out.push(((error_code >> 16) & 0xFF) as u8);
    out.push(((error_code >> 8) & 0xFF) as u8);
    out.push((error_code & 0xFF) as u8);

    out.append(reason);
}

// Decodes a CLOSE_WEBTRANSPORT_SESSION capsule from its payload
fn decode_webtransport_close_session(
    payload: const u8[:],
    out: WebTransportCloseSession&,
) -> bool {
    guard payload.len >= 4 else { return false; }
    out.reason.clear();

    var code: u32 = (payload[0] as u32) << 24;
    code |= (payload[1] as u32) << 16;
    code |= (payload[2] as u32) << 8;
    code |= payload[3];
    out.error_code = code;

    let reason_len = payload.len - 4;
    guard reason_len <= 1024 else { return false; }

    for i in reason_len {
        out.reason.push(payload[4 + i]);
    }
    return true;
}

// Encodes a DRAIN_WEBTRANSPORT_SESSION capsule:
// Capsule Type (varint 0x78AE) || Length (varint 0)
fn encode_webtransport_drain_session<B>(out: B&) {
    write_varint(out, CAPSULE_DRAIN_WEBTRANSPORT);
    write_varint(out, 0);
}

// Validates a DRAIN_WEBTRANSPORT_SESSION capsule payload (length must be 0)
fn decode_webtransport_drain_session(payload: const u8[:]) -> bool {
    return payload.len == 0;
}

// Encodes a WT_RESET_STREAM capsule:
// Capsule Type (varint 0x2841) || Length (varint) || Stream ID (varint) || Error Code (4B BE)
fn encode_webtransport_reset_stream<B>(
    stream_id: u64,
    error_code: u32,
    out: B&,
) {
    write_varint(out, CAPSULE_WT_RESET_STREAM);
    var tmp_body: u8[..32] = [];
    write_varint(tmp_body, stream_id);
    tmp_body.push(((error_code >> 24) & 0xFF) as u8);
    tmp_body.push(((error_code >> 16) & 0xFF) as u8);
    tmp_body.push(((error_code >> 8) & 0xFF) as u8);
    tmp_body.push((error_code & 0xFF) as u8);

    write_varint(out, tmp_body.len as u64);
    out.append(tmp_body[..]);
}

// Decodes a WT_RESET_STREAM capsule from its payload
fn decode_webtransport_reset_stream(
    payload: const u8[:],
    out: WebTransportStreamReset&,
) -> bool {
    var idx: i64 = 0;
    let sid, ok = read_varint(payload, idx);
    guard ok && payload.len == idx + 4 else { return false; }

    out.stream_id = sid;
    var code: u32 = (payload[idx] as u32) << 24;
    code |= (payload[idx + 1] as u32) << 16;
    code |= (payload[idx + 2] as u32) << 8;
    code |= payload[idx + 3];
    out.error_code = code;
    return true;
}

// Encodes a WT_STOP_SENDING capsule:
// Capsule Type (varint 0x2842) || Length (varint) || Stream ID (varint) || Error Code (4B BE)
fn encode_webtransport_stop_sending<B>(
    stream_id: u64,
    error_code: u32,
    out: B&,
) {
    write_varint(out, CAPSULE_WT_STOP_SENDING);
    var tmp_body: u8[..32] = [];
    write_varint(tmp_body, stream_id);
    tmp_body.push(((error_code >> 24) & 0xFF) as u8);
    tmp_body.push(((error_code >> 16) & 0xFF) as u8);
    tmp_body.push(((error_code >> 8) & 0xFF) as u8);
    tmp_body.push((error_code & 0xFF) as u8);

    write_varint(out, tmp_body.len as u64);
    out.append(tmp_body[..]);
}

// Decodes a WT_STOP_SENDING capsule from its payload
fn decode_webtransport_stop_sending(
    payload: const u8[:],
    out: WebTransportStreamStopSending&,
) -> bool {
    var idx: i64 = 0;
    let sid, ok = read_varint(payload, idx);
    guard ok && payload.len == idx + 4 else { return false; }

    out.stream_id = sid;
    var code: u32 = (payload[idx] as u32) << 24;
    code |= (payload[idx + 1] as u32) << 16;
    code |= (payload[idx + 2] as u32) << 8;
    code |= payload[idx + 3];
    out.error_code = code;
    return true;
}

// ---- 9. Session State Management --------------------------------------------

fn close_webtransport_session(session: WebTransportSession&, code: u32, reason: const u8[:]) {
    session.is_active = false;
    session.close_code = code;
    session.close_reason.clear();
    session.close_reason.append(reason);
}

fn drain_webtransport_session(session: WebTransportSession&) {
    session.is_draining = true;
}

fn is_webtransport_session_open(session: const WebTransportSession&) -> bool {
    return session.is_active && !session.is_draining;
}
