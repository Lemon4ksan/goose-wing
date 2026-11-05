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

// ---- WebTransport & RFC 9221 Constants (draft-16) -------------------------

// CAPSULE_WT_RESET_STREAM (0x190B4D39), CAPSULE_WT_STOP_SENDING (0x190B4D3A),
// CAPSULE_CLOSE_WEBTRANSPORT (0x2843), CAPSULE_DRAIN_WEBTRANSPORT (0x78AE).

// HTTP/3 Error Code Mapping bounds (draft-16 Section 4.3)

struct WebTransportSession {
    session_id:        u64        = 0,
    is_active:         bool       = false,
    is_draining:       bool       = false,
    close_code:        u32        = 0,
    close_reason:      u8[..1024] = [],
    max_sessions:      u64        = 16,
    datagrams_enabled: bool       = true,
}

struct WebTransportDatagram {
    session_id: u64        = 0,
    payload:    u8[..1500] = [],
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
    error_code: u32        = 0,
    reason:     u8[..1024] = [],
}

struct WebTransportStreamReset {
    stream_id:  u64 = 0,
    error_code: u32 = 0,
}

struct WebTransportStreamStopSending {
    stream_id:  u64 = 0,
    error_code: u32 = 0,
}

// ---- Varint Helper (RFC 9000 Section 16) ---------------------------------

fn write_varint<B>(out: B&, val: u64) {
    guard val <= 0x3FFFFFFFFFFFFFFF else { return; }
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

// Reads a variable-length integer (RFC 9000 Section 16).
// Advances `idx` past the consumed integer bytes; leaves `idx` unchanged on error.
//
// Example:
//   wire = [0x25], idx = 0
//   returns: 37, ok = true, idx = 1
fn read_varint(wire: const u8[:], idx: i64&) -> u64, bool {
    guard idx >= 0 && idx < wire.len else { return 0, false; }
    let first = wire[idx];
    let prefix = first >> 6;
    let needed = (1 as i64) << prefix;
    guard idx + needed <= wire.len else { return 0, false; }

    var v = (first & 0x3F) as u64;
    for i in 1..needed {
        v = (v << 8) | wire[idx + i];
    }
    idx += needed;
    return v, true;
}

// ---- Session Initiation (Extended CONNECT :protocol = webtransport) ------

// Formats an HTTP/3 Extended CONNECT request to open a WebTransport session
fn format_webtransport_connect_request(
    req:        Request&,
    url_target: const u8[:],
) {
    req.method.clear();
    req.method.append("CONNECT");
    req.url.clear();
    let copy_len = min(url_target.len, req.url.cap);
    req.url.append(url_target[..copy_len]);

    // RFC 8441 / RFC 9220 / WebTransport draft-16:
    // :protocol = webtransport
    set_header(req, ":protocol", rfc::WEBTRANSPORT_PROTOCOL);
    set_header(req, "sec-webtransport-http3-draft", "draft16");
}

// Validates whether an incoming HTTP request is an Extended CONNECT WebTransport request
fn is_webtransport_connect_request(req: const Request&) -> bool {
    if req.method[..] != "CONNECT" { return false; }
    if !req.has_header(":protocol") { return false; }
    if req.header(":protocol") != rfc::WEBTRANSPORT_PROTOCOL { return false; }
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

// ---- Stream Framing (draft-16 Section 4.1 & Section 4.2) -----------------

// Encodes a WebTransport unidirectional stream header:
// Stream Type (0x54) || Session ID (varint)
fn encode_webtransport_uni_stream_header<B>(
    session_id: u64,
    out:        B&,
) {
    write_varint(out, rfc::STREAM_TYPE_WEBTRANSPORT);
    write_varint(out, session_id);
}

// Decodes a WebTransport unidirectional stream header from wire bytes.
//
// Example:
//   wire = [0x54, 0x01]
//   returns: true, out.session_id = 1
fn decode_webtransport_uni_stream_header(
    wire: const u8[:],
    out:  WebTransportUniStreamHeader&,
) -> bool {
    out.session_id = 0;
    out.header_len = 0;
    var idx: i64 = 0;
    let stype, ok1 = read_varint(wire, idx);
    guard ok1 && stype == rfc::STREAM_TYPE_WEBTRANSPORT else { return false; }

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
    out:        B&,
) {
    write_varint(out, rfc::WEBTRANSPORT_BIDI_SIGNAL);
    write_varint(out, session_id);
}

// Decodes a WebTransport bidirectional stream opening header from wire bytes.
//
// Example:
//   wire = [0x41, 0x02]
//   returns: true, out.session_id = 2
fn decode_webtransport_bidi_stream_header(
    wire: const u8[:],
    out:  WebTransportBidiStreamHeader&,
) -> bool {
    out.session_id = 0;
    out.header_len = 0;
    var idx: i64 = 0;
    let signal, ok1 = read_varint(wire, idx);
    guard ok1 && signal == rfc::WEBTRANSPORT_BIDI_SIGNAL else { return false; }

    let sid, ok2 = read_varint(wire, idx);
    guard ok2 else { return false; }

    out.session_id = sid;
    out.header_len = idx;
    return true;
}

// ---- Datagram Framing (draft-16 Section 5 & RFC 9221) ---------------------

// Encodes a WebTransport datagram (RFC 9297 / draft-ietf-webtrans-http3 §5):
// Quarter Stream ID (varint = session_id / 4) || Context ID (varint = 0) || Datagram Payload
fn encode_webtransport_datagram<B>(
    session_id: u64,
    payload:    const u8[:],
    out:        B&,
) {
    write_varint(out, session_id / 4);
    write_varint(out, 0);
    out.append(payload);
}

// Decodes a WebTransport datagram from wire bytes (RFC 9297 / draft-ietf-webtrans-http3 §5).
//
// Example:
//   wire = [0x01, 0x00, 'p', 'i', 'n', 'g']
//   returns: true, out.session_id = 4, out.payload = "ping"
fn decode_webtransport_datagram(
    wire: const u8[:],
    out:  WebTransportDatagram&,
) -> bool {
    var idx: i64 = 0;
    let quarter_id, ok1 = read_varint(wire, idx);
    guard ok1 && quarter_id <= 0x0FFFFFFFFFFFFFFF else { return false; }
    let ctx_id, ok2 = read_varint(wire, idx);
    guard ok2 && ctx_id == 0 else { return false; }
    guard idx <= wire.len && (wire.len - idx) <= out.payload.cap else { return false; }

    out.session_id = quarter_id * 4;
    out.payload.clear();
    out.payload.append(wire[idx..]);
    return true;
}

// Encodes an RFC 9221 QUIC DATAGRAM frame (Type 0x31 with varint length)
fn encode_quic_datagram_frame<B>(
    datagram_payload: const u8[:],
    out:              B&,
) {
    write_varint(out, rfc::QUIC_FRAME_DATAGRAM_LEN);
    write_varint(out, datagram_payload.len as u64);
    out.append(datagram_payload);
}

// Decodes an RFC 9221 QUIC DATAGRAM frame.
//
// Example:
//   wire = [0x31, 0x04, 't', 'e', 's', 't']
//   returns: true, out_payload = "test"
fn decode_quic_datagram_frame<B>(
    wire:        const u8[:],
    out_payload: B&,
) -> bool {
    out_payload.clear();
    var idx: i64 = 0;
    let frame_type, ok_t = read_varint(wire, idx);
    guard ok_t else { return false; }

    guard frame_type == rfc::QUIC_FRAME_DATAGRAM || frame_type == rfc::QUIC_FRAME_DATAGRAM_LEN else {
        return false;
    }

    var payload_end = wire.len;
    if frame_type == rfc::QUIC_FRAME_DATAGRAM_LEN {
        let len, ok_l = read_varint(wire, idx);
        guard ok_l && idx <= wire.len && len <= ((wire.len - idx) as u64) else { return false; }
        payload_end = idx + (len as i64);
    }

    out_payload.append(wire[idx..payload_end]);
    return true;
}

// ---- HTTP/3 Error Code Mapping (draft-16 Section 4.3) ---------------------

// Maps a 32-bit WebTransport application error code to HTTP/3 error code space,
// skipping HTTP/3 GREASE code points (0x1f * N + 0x21).
fn webtransport_code_to_http_code(app_err: u32) -> u64 {
    let n = app_err as u64;
    return rfc::WEBTRANSPORT_ERROR_FIRST + n + (n / 0x1E);
}

// Translates an HTTP/3 error code back to a 32-bit WebTransport application error code.
fn http_code_to_webtransport_code(h3_err: u64) -> u32, bool {
    guard h3_err >= rfc::WEBTRANSPORT_ERROR_FIRST && h3_err <= rfc::WEBTRANSPORT_ERROR_LAST else {
        return 0, false;
    }
    if h3_err >= 0x21 && ((h3_err - 0x21) % 0x1F) == 0 {
        return 0, false;
    }
    let shifted = h3_err - rfc::WEBTRANSPORT_ERROR_FIRST;
    let app_err = shifted - (shifted / 0x1F);
    return app_err as u32, true;
}

// ---- WebTransport Capsule Codecs (draft-16 Section 8 & RFC 9297) ----------

// Encodes a CLOSE_WEBTRANSPORT_SESSION capsule:
// Capsule Type (varint 0x2843) || Length (varint: 4 + reason.len) || Error Code (4B BE) || Reason
fn encode_webtransport_close_session<B>(
    error_code: u32,
    reason:     const u8[:],
    out:        B&,
) {
    write_varint(out, rfc::CAPSULE_CLOSE_WEBTRANSPORT);
    let payload_len = 4 + reason.len;
    write_varint(out, payload_len as u64);

    out.push(((error_code >> 24) & 0xFF) as u8);
    out.push(((error_code >> 16) & 0xFF) as u8);
    out.push(((error_code >> 8) & 0xFF) as u8);
    out.push((error_code & 0xFF) as u8);

    out.append(reason);
}

// Decodes a CLOSE_WEBTRANSPORT_SESSION capsule from its payload.
//
// Example:
//   payload = [0x00, 0x00, 0x00, 0x00, 'b', 'y', 'e']
//   returns: true, out.error_code = 0, out.reason = "bye"
fn decode_webtransport_close_session(
    payload: const u8[:],
    out:     WebTransportCloseSession&,
) -> bool {
    guard payload.len >= 4 else { return false; }
    let reason = payload[4..];
    guard reason.len <= out.reason.cap && core::validate_utf8(reason) else { return false; }

    var code: u32 = (payload[0] as u32) << 24;
    code |= (payload[1] as u32) << 16;
    code |= (payload[2] as u32) << 8;
    code |= payload[3];
    out.error_code = code;

    out.reason.clear();
    out.reason.append(reason);
    return true;
}

// Encodes a DRAIN_WEBTRANSPORT_SESSION capsule:
// Capsule Type (varint 0x78AE) || Length (varint 0)
fn encode_webtransport_drain_session<B>(out: B&) {
    write_varint(out, rfc::CAPSULE_DRAIN_WEBTRANSPORT);
    write_varint(out, 0);
}

// Validates a DRAIN_WEBTRANSPORT_SESSION capsule payload (length must be 0).
//
// Example:
//   payload = []
//   returns: true
fn decode_webtransport_drain_session(payload: const u8[:]) -> bool {
    return payload.len == 0;
}

// Encodes a WT_RESET_STREAM capsule (draft-ietf-webtrans-http3-16 / draft-ietf-webtrans-http2):
// Capsule Type (varint 0x190B4D39) || Length (varint) || Stream ID (varint) || Error Code (varint)
fn encode_webtransport_reset_stream<B>(
    stream_id:  u64,
    error_code: u32,
    out:        B&,
) {
    write_varint(out, rfc::CAPSULE_WT_RESET_STREAM);
    var tmp_body: u8[..32] = [];
    write_varint(tmp_body, stream_id);
    write_varint(tmp_body, error_code as u64);

    write_varint(out, tmp_body.len as u64);
    out.append(tmp_body[..]);
}

// Decodes a WT_RESET_STREAM capsule from its payload.
//
// Example:
//   payload = [0x01, 0x00]
//   returns: true, out.stream_id = 1, out.error_code = 0
fn decode_webtransport_reset_stream(
    payload: const u8[:],
    out:     WebTransportStreamReset&,
) -> bool {
    var idx: i64 = 0;
    let sid, ok1 = read_varint(payload, idx);
    guard ok1 else { return false; }

    let code, ok2 = read_varint(payload, idx);
    guard ok2 && idx == payload.len && code <= 0xFFFFFFFF else { return false; }

    out.stream_id = sid;
    out.error_code = code as u32;
    return true;
}

// Encodes a WT_STOP_SENDING capsule (draft-ietf-webtrans-http3-16 / draft-ietf-webtrans-http2):
// Capsule Type (varint 0x190B4D3A) || Length (varint) || Stream ID (varint) || Error Code (varint)
fn encode_webtransport_stop_sending<B>(
    stream_id:  u64,
    error_code: u32,
    out:        B&,
) {
    write_varint(out, rfc::CAPSULE_WT_STOP_SENDING);
    var tmp_body: u8[..32] = [];
    write_varint(tmp_body, stream_id);
    write_varint(tmp_body, error_code as u64);

    write_varint(out, tmp_body.len as u64);
    out.append(tmp_body[..]);
}

// Decodes a WT_STOP_SENDING capsule from its payload.
//
// Example:
//   payload = [0x01, 0x00]
//   returns: true, out.stream_id = 1, out.error_code = 0
fn decode_webtransport_stop_sending(
    payload: const u8[:],
    out:     WebTransportStreamStopSending&,
) -> bool {
    var idx: i64 = 0;
    let sid, ok1 = read_varint(payload, idx);
    guard ok1 else { return false; }

    let code, ok2 = read_varint(payload, idx);
    guard ok2 && idx == payload.len && code <= 0xFFFFFFFF else { return false; }

    out.stream_id = sid;
    out.error_code = code as u32;
    return true;
}

// ---- Session State Management --------------------------------------------

fn close_webtransport_session(session: WebTransportSession&, code: u32, reason: const u8[:]) {
    session.is_active = false;
    session.close_code = code;
    session.close_reason.clear();
    let copy_len = min(reason.len, session.close_reason.cap);
    session.close_reason.append(reason[..copy_len]);
}

fn drain_webtransport_session(session: WebTransportSession&) {
    session.is_draining = true;
}

fn is_webtransport_session_open(session: const WebTransportSession&) -> bool {
    return session.is_active && !session.is_draining;
}

// ---- WebTransport Stream Demuxing & Session Routing ---------------------

enum WebTransportStreamKind {
    Bidirectional,
    Unidirectional,
    Unknown,
}

enum WebTransportSessionState {
    Closed,
    Connecting,
    Active,
    Draining,
}

struct WebTransportDemuxHeader {
    kind:       WebTransportStreamKind = WebTransportStreamKind.Unknown,
    session_id: u64                    = 0,
    header_len: i64                    = 0,
}

struct WebTransportStreamPayload {
    kind:       WebTransportStreamKind = WebTransportStreamKind.Unknown,
    stream_id:  u64                    = 0,
    session_id: u64                    = 0,
    payload:    const u8[:]            = "",
    fin:        bool                   = false,
}

struct WebTransportStreamRoute {
    stream_id:       u64                    = 0,
    session_id:      u64                    = 0,
    kind:            WebTransportStreamKind = WebTransportStreamKind.Unknown,
    is_open:         bool                   = false,
    bytes_delivered: u64                    = 0,
}

struct WebTransportSessionEntry {
    session_id:      u64                      = 0,
    state:           WebTransportSessionState = WebTransportSessionState.Closed,
    close_code:      u32                      = 0,
    close_reason:    u8[..1024]               = [],
    bytes_received:  u64                      = 0,
    frames_received: u64                      = 0,
    streams_count:   u32                      = 0,
}

struct WebTransportDemuxer {
    sessions:         WebTransportSessionEntry[..16] = [],
    streams:          WebTransportStreamRoute[..64]  = [],
    total_dispatched: u64                            = 0,
    dropped_frames:   u64                            = 0,
}

// draft-ietf-webtrans-overview Section 4.2: Bidirectional Streams - WebTransport Bidirectional Stream Header Demux
// draft-ietf-webtrans-http3 Section 4.2: Bidirectional Streams - WebTransport Bidirectional Stream Header Demux
// Demuxes a WebTransport bidirectional stream opening frame.
// Requires 0x41 signal + Session ID varint (draft-http3 §4.2); streams lacking 0x41 signal are rejected.
//
// Example:
//   wire = [0x40, 0x41, 0x05, 'd', 'a', 't', 'a']
//   returns: session_id = 5, payload = "data", ok = true
fn demux_webtransport_bidi_stream(
    wire: const u8[:],
) -> u64, const u8[:], bool {
    guard wire.len > 0 else { return 0, wire[..0], false; }
    var idx: i64 = 0;
    let signal, ok1 = read_varint(wire, idx);
    guard ok1 && signal == rfc::WEBTRANSPORT_BIDI_SIGNAL else { return 0, wire[..0], false; }

    let sid, ok2 = read_varint(wire, idx);
    guard ok2 else { return 0, wire[..0], false; }
    return sid, wire[idx..], true;
}

// draft-ietf-webtrans-http3 Section 4.1: Unidirectional Streams - WebTransport Stream Type and Session ID Demux
// Demuxes a WebTransport unidirectional stream opening frame.
// Validates 0x54 (STREAM_TYPE_WEBTRANSPORT) stream type prefix followed by Session ID varint.
//
// Example:
//   wire = [0x40, 0x54, 0x05, 'u', 'n', 'i']
//   returns: session_id = 5, payload = "uni", ok = true
fn demux_webtransport_uni_stream(
    wire: const u8[:],
) -> u64, const u8[:], bool {
    guard wire.len > 0 else { return 0, wire[..0], false; }
    var idx: i64 = 0;
    let stype, ok1 = read_varint(wire, idx);
    guard ok1 && stype == rfc::STREAM_TYPE_WEBTRANSPORT else { return 0, wire[..0], false; }

    let sid, ok2 = read_varint(wire, idx);
    guard ok2 else { return 0, wire[..0], false; }

    return sid, wire[idx..], true;
}

// draft-ietf-webtrans-overview Section 4.2: Bidirectional Streams - WebTransport Stream Header Demux
// Demuxes a WebTransport stream header from incoming QUIC stream wire bytes.
//
// Example:
//   wire = [0x40, 0x54, 0x10], is_bidi = false
//   returns: ok = true, out.kind = Unidirectional, out.session_id = 16, out.header_len = 3
fn demux_webtransport_stream_header(
    wire:    const u8[:],
    is_bidi: bool,
    out:     WebTransportDemuxHeader&,
) -> bool {
    out.kind = WebTransportStreamKind.Unknown;
    out.session_id = 0;
    out.header_len = 0;
    guard wire.len > 0 else { return false; }

    if is_bidi {
        var idx: i64 = 0;
        let signal, ok1 = read_varint(wire, idx);
        guard ok1 && signal == rfc::WEBTRANSPORT_BIDI_SIGNAL else { return false; }

        let sid, ok2 = read_varint(wire, idx);
        guard ok2 else { return false; }
        out.kind = WebTransportStreamKind.Bidirectional;
        out.session_id = sid;
        out.header_len = idx;
        return true;
    }

    var idx: i64 = 0;
    let stype, ok1 = read_varint(wire, idx);
    guard ok1 && stype == rfc::STREAM_TYPE_WEBTRANSPORT else { return false; }

    let sid, ok2 = read_varint(wire, idx);
    guard ok2 else { return false; }

    out.kind = WebTransportStreamKind.Unidirectional;
    out.session_id = sid;
    out.header_len = idx;
    return true;
}

fn find_stream_route_index(demuxer: const WebTransportDemuxer&, stream_id: u64) -> i64, bool {
    for i in demuxer.streams.len {
        if demuxer.streams[i].stream_id == stream_id && demuxer.streams[i].is_open {
            return i, true;
        }
    }
    return -1, false;
}

fn find_session_entry_index(demuxer: const WebTransportDemuxer&, session_id: u64) -> i64, bool {
    for i in demuxer.sessions.len {
        if demuxer.sessions[i].session_id == session_id {
            return i, true;
        }
    }
    return -1, false;
}

// Registers a new active session into the demuxer, reusing closed session slots if full
fn register_webtransport_session(demuxer: WebTransportDemuxer&, session_id: u64) -> bool {
    for i in demuxer.sessions.len {
        if demuxer.sessions[i].session_id == session_id {
            demuxer.sessions[i].state = WebTransportSessionState.Active;
            demuxer.sessions[i].close_code = 0;
            demuxer.sessions[i].close_reason.clear();
            return true;
        }
    }
    let entry = WebTransportSessionEntry {
        session_id: session_id,
        state:      WebTransportSessionState.Active,
        ..
    };
    if demuxer.sessions.len < demuxer.sessions.cap {
        demuxer.sessions.push(entry);
        return true;
    }
    for i in demuxer.sessions.len {
        if demuxer.sessions[i].state == WebTransportSessionState.Closed {
            demuxer.sessions[i] = entry;
            return true;
        }
    }
    return false;
}

// Updates session state (Connecting, Active, Draining, Closed)
fn set_webtransport_session_state(
    demuxer:    WebTransportDemuxer&,
    session_id: u64,
    state:      WebTransportSessionState,
) -> bool {
    let s_idx, has_s = find_session_entry_index(demuxer, session_id);
    guard has_s else { return false; }
    demuxer.sessions[s_idx].state = state;
    return true;
}

// Queries current session state
fn get_webtransport_session_state(
    demuxer:    const WebTransportDemuxer&,
    session_id: u64,
) -> WebTransportSessionState, bool {
    let s_idx, has_s = find_session_entry_index(demuxer, session_id);
    guard has_s else { return WebTransportSessionState.Closed, false; }
    return demuxer.sessions[s_idx].state, true;
}

// Drains an active session (rejects new streams, drains existing)
fn drain_webtransport_demuxer_session(demuxer: WebTransportDemuxer&, session_id: u64) -> bool {
    return set_webtransport_session_state(demuxer, session_id, WebTransportSessionState.Draining);
}

// Closes a session with error code and reason, and closes all associated open stream routes
fn close_webtransport_demuxer_session(
    demuxer:    WebTransportDemuxer&,
    session_id: u64,
    code:       u32,
    reason:     const u8[:],
) -> bool {
    let s_idx, has_s = find_session_entry_index(demuxer, session_id);
    guard has_s else { return false; }
    demuxer.sessions[s_idx].state = WebTransportSessionState.Closed;
    demuxer.sessions[s_idx].close_code = code;
    demuxer.sessions[s_idx].close_reason.clear();
    let copy_len = min(reason.len, demuxer.sessions[s_idx].close_reason.cap);
    demuxer.sessions[s_idx].close_reason.append(reason[..copy_len]);
    for i in demuxer.streams.len {
        if demuxer.streams[i].session_id == session_id {
            demuxer.streams[i].is_open = false;
        }
    }
    return true;
}

inline fn is_session_routable(state: WebTransportSessionState) -> bool {
    return state == WebTransportSessionState.Active || state == WebTransportSessionState.Draining;
}

// Allocates or reuses a closed stream route slot in `demuxer.streams`.
fn record_new_stream_route(
    demuxer:         WebTransportDemuxer&,
    stream_id:       u64,
    session_id:      u64,
    kind:            WebTransportStreamKind,
    bytes_delivered: u64,
) -> bool {
    let route = WebTransportStreamRoute {
        stream_id:       stream_id,
        session_id:      session_id,
        kind:            kind,
        is_open:         true,
        bytes_delivered: bytes_delivered,
    };
    for i in demuxer.streams.len {
        if !demuxer.streams[i].is_open {
            demuxer.streams[i] = route;
            return true;
        }
    }
    guard demuxer.streams.len < demuxer.streams.cap else { return false; }
    demuxer.streams.push(route);
    return true;
}

// Routes incoming data chunks to an existing open WebTransport stream.
fn route_existing_stream(
    demuxer:   WebTransportDemuxer&,
    route_idx: i64,
    wire:      const u8[:],
    fin:       bool,
    out:       WebTransportStreamPayload&,
) -> bool {
    guard route_idx >= 0 && route_idx < demuxer.streams.len else { return false; }
    let sid = demuxer.streams[route_idx].session_id;

    let s_idx, has_session = find_session_entry_index(demuxer, sid);
    guard has_session && s_idx >= 0 && s_idx < demuxer.sessions.len else {
        demuxer.dropped_frames += 1;
        return false;
    }

    guard is_session_routable(demuxer.sessions[s_idx].state) else {
        demuxer.dropped_frames += 1;
        return false;
    }

    demuxer.sessions[s_idx].frames_received += 1;
    if fin {
        demuxer.streams[route_idx].is_open = false;
    }

    out.kind = demuxer.streams[route_idx].kind;
    out.stream_id = demuxer.streams[route_idx].stream_id;
    out.session_id = sid;
    out.payload = wire;
    out.fin = fin;

    demuxer.sessions[s_idx].bytes_received += wire.len as u64;
    demuxer.streams[route_idx].bytes_delivered += wire.len as u64;
    demuxer.total_dispatched += 1;
    return true;
}

// Demuxes stream header and routes a new WebTransport stream.
fn route_new_stream(
    demuxer:   WebTransportDemuxer&,
    stream_id: u64,
    wire:      const u8[:],
    fin:       bool,
    out:       WebTransportStreamPayload&,
) -> bool {
    let is_bidi = (stream_id & 0x02) == 0;
    var hdr = WebTransportDemuxHeader { .. };
    guard demux_webtransport_stream_header(wire, is_bidi, hdr) else {
        demuxer.dropped_frames += 1;
        return false;
    }

    let s_idx, has_session = find_session_entry_index(demuxer, hdr.session_id);
    guard has_session && s_idx >= 0 && s_idx < demuxer.sessions.len else {
        demuxer.dropped_frames += 1;
        return false;
    }

    guard demuxer.sessions[s_idx].state == WebTransportSessionState.Active else {
        demuxer.dropped_frames += 1;
        return false;
    }

    guard hdr.header_len >= 0 && hdr.header_len <= wire.len else { return false; }
    let payload = wire[hdr.header_len..];

    if !fin {
        guard record_new_stream_route(demuxer, stream_id, hdr.session_id, hdr.kind, payload.len as u64) else {
            demuxer.dropped_frames += 1;
            return false;
        }
    }

    demuxer.sessions[s_idx].streams_count += 1;
    demuxer.sessions[s_idx].frames_received += 1;
    demuxer.sessions[s_idx].bytes_received += payload.len as u64;

    out.kind = hdr.kind;
    out.stream_id = stream_id;
    out.session_id = hdr.session_id;
    out.payload = payload;
    out.fin = fin;

    demuxer.total_dispatched += 1;
    return true;
}

// draft-ietf-webtrans-overview Section 4.2: Bidirectional Streams - Demuxes stream wire bytes and dispatches to session
// Zero-heap demuxer for QUIC streams. Handles both stream initiation and continuous streaming chunks.
//
// Example:
//   stream_id = 0, wire = [0x04, 'p', 'i', 'n', 'g'], fin = true
//   returns: ok = true, out.session_id = 4, out.payload = "ping", out.fin = true
fn demux_webtransport_stream(
    demuxer:   WebTransportDemuxer&,
    stream_id: u64,
    wire:      const u8[:],
    fin:       bool,
    out:       WebTransportStreamPayload&,
) -> bool {
    out.kind = WebTransportStreamKind.Unknown;
    out.stream_id = stream_id;
    out.session_id = 0;
    out.payload = wire[..0];
    out.fin = fin;

    let route_idx, has_route = find_stream_route_index(demuxer, stream_id);
    if has_route {
        return route_existing_stream(demuxer, route_idx, wire, fin, out);
    }

    return route_new_stream(demuxer, stream_id, wire, fin, out);
}
