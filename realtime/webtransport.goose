// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// W3C / IETF draft-ietf-webtrans-http3-16 (WebTransport over HTTP/3)
// and RFC 9221 (An Unreliable Datagram Extension to QUIC).
// Implements extended CONNECT session bootstrapping (:protocol = webtransport),
// HTTP/3 settings negotiation, unidirectional (0x54) and bidirectional (0x41) stream framing,
// unreliable datagram framing, HTTP/3 error code translation, and session capsules (draft-16 Section 8).
namespace realtime;

import std;
import core from "..";
import rfc.h3_quic;
import http.request;
import http.response;
import .internal;

// ---- WebTransport Session & Framing Types (draft-16) ---------------------

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

// ---- Varint Reader (RFC 9000 Section 16) ---------------------------------

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
    let needed = ((1 as u64) << prefix) as i64;
    let end_idx = core::add_sat_i64(idx, needed);
    guard end_idx <= wire.len else { return 0, false; }

    var v = (first & 0x3F) as u64;
    for i in 1..needed {
        let byte_idx = core::add_sat_i64(idx, i);
        v = (v << 8) | wire[byte_idx];
    }
    idx = end_idx;
    return v, true;
}

// ---- Session Initiation (Extended CONNECT :protocol = webtransport) ------

// Formats an HTTP/3 Extended CONNECT request to open a WebTransport session.
fn format_webtransport_connect_request(
    req:        wing::Request&,
    url_target: const u8[:],
) {
    let _ = req.method.try_set("CONNECT");
    let copy_len = min(url_target.len, req.url.cap);
    let _ = req.url.try_set(url_target[..copy_len]);

    // RFC 8441 / RFC 9220 / WebTransport draft-16:
    // :protocol = webtransport
    wing::set_header(req, ":protocol", rfc::WEBTRANSPORT_PROTOCOL);
    wing::set_header(req, "sec-webtransport-http3-draft", "draft16");
}

// Validates whether an incoming HTTP request is an Extended CONNECT WebTransport request.
fn is_webtransport_connect_request(req: const wing::Request&) -> bool {
    if req.method[..] != "CONNECT" { return false; }
    if !req.has_header(":protocol") { return false; }
    if req.header(":protocol") != rfc::WEBTRANSPORT_PROTOCOL { return false; }
    let view, err = core::parse_url_view(req.url[..]);
    if !core::is_ok(err) || !view.valid { return false; }
    return view.scheme.eq_ascii_fold("https") && view.host.len > 0 && view.pathname.len > 0;
}

// Formats an HTTP/3 response accepting a WebTransport session.
fn format_webtransport_connect_response(res: wing::Response&) {
    res.status_code = 200;
    wing::set_header(res, "sec-webtransport-http3-draft", "draft16");
}

// Validates whether server response accepts the WebTransport session.
fn handle_webtransport_response(session: WebTransportSession&, res: const wing::Response&) -> bool {
    let status_ok = res.status_code >= 200 && res.status_code < 300 &&
        res.status_code != 204 && res.status_code != 205 && res.status_code != 206;
    let hdrs_ok = !res.has_header("content-length") &&
        !res.has_header("content-type") &&
        !res.has_header("transfer-encoding");
    guard realtime_internal::is_valid_webtransport_session_id(session.session_id) && status_ok && hdrs_ok else {
        session.is_active = false;
        return false;
    }
    session.is_active = true;
    session.is_draining = false;
    session.close_code = 0;
    session.close_reason.clear();
    return true;
}

// ---- Stream Framing (draft-16 Section 4.1 & Section 4.2) -----------------

// Encodes a WebTransport unidirectional stream header:
// Stream Type (0x54) || Session ID (varint)
fn encode_webtransport_uni_stream_header<B>(
    session_id: u64,
    out:        B&,
) {
    guard realtime_internal::is_valid_webtransport_session_id(session_id) else { return; }
    realtime_internal::write_varint(out, rfc::STREAM_TYPE_WEBTRANSPORT);
    realtime_internal::write_varint(out, session_id);
}

// Decodes a WebTransport unidirectional stream header from wire bytes.
//
// Example:
//   wire = [0x40, 0x54, 0x04]
//   returns: WebTransportUniStreamHeader { session_id: 4, header_len: 3 }, ok = true
fn decode_webtransport_uni_stream_header(
    wire: const u8[:],
) -> WebTransportUniStreamHeader, bool {
    var idx: i64 = 0;
    let stype, ok1 = read_varint(wire, idx);
    guard ok1 && stype == rfc::STREAM_TYPE_WEBTRANSPORT else {
        return WebTransportUniStreamHeader { .. }, false;
    }

    let sid, ok2 = read_varint(wire, idx);
    guard ok2 && realtime_internal::is_valid_webtransport_session_id(sid) else {
        return WebTransportUniStreamHeader { .. }, false;
    }

    return WebTransportUniStreamHeader { session_id: sid, header_len: idx }, true;
}

// Encodes a WebTransport bidirectional stream opening header:
// Signal Value (0x41) || Session ID (varint)
fn encode_webtransport_bidi_stream_header<B>(
    session_id: u64,
    out:        B&,
) {
    guard realtime_internal::is_valid_webtransport_session_id(session_id) else { return; }
    realtime_internal::write_varint(out, rfc::WEBTRANSPORT_BIDI_SIGNAL);
    realtime_internal::write_varint(out, session_id);
}

// Decodes a WebTransport bidirectional stream opening header from wire bytes.
//
// Example:
//   wire = [0x40, 0x41, 0x04]
//   returns: WebTransportBidiStreamHeader { session_id: 4, header_len: 3 }, ok = true
fn decode_webtransport_bidi_stream_header(
    wire: const u8[:],
) -> WebTransportBidiStreamHeader, bool {
    var idx: i64 = 0;
    let signal, ok1 = read_varint(wire, idx);
    guard ok1 && signal == rfc::WEBTRANSPORT_BIDI_SIGNAL else {
        return WebTransportBidiStreamHeader { .. }, false;
    }

    let sid, ok2 = read_varint(wire, idx);
    guard ok2 && realtime_internal::is_valid_webtransport_session_id(sid) else {
        return WebTransportBidiStreamHeader { .. }, false;
    }

    return WebTransportBidiStreamHeader { session_id: sid, header_len: idx }, true;
}

// ---- Datagram Framing (draft-16 Section 5 & RFC 9221) ---------------------

// Encodes a WebTransport datagram (RFC 9297 / draft-ietf-webtrans-http3 §5):
// Quarter Stream ID (varint = session_id / 4) || Context ID (varint = 0) || Datagram Payload
fn encode_webtransport_datagram<B>(
    session_id: u64,
    payload:    const u8[:],
    out:        B&,
) {
    guard realtime_internal::is_valid_webtransport_session_id(session_id) else { return; }
    realtime_internal::write_varint(out, session_id >> 2);
    realtime_internal::write_varint(out, 0);
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
    guard idx <= wire.len && out.payload.try_set(wire[idx..]) else { return false; }

    out.session_id = core::mul_sat_u64(quarter_id, 4);
    return true;
}

// Encodes an RFC 9221 QUIC DATAGRAM frame (Type 0x31 with varint length).
fn encode_quic_datagram_frame<B>(
    datagram_payload: const u8[:],
    out:              B&,
) {
    realtime_internal::write_varint(out, rfc::QUIC_FRAME_DATAGRAM_LEN);
    realtime_internal::write_varint(out, datagram_payload.len as u64);
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
    var idx: i64 = 0;
    let frame_type, ok_t = read_varint(wire, idx);
    guard ok_t else { return false; }

    guard frame_type == rfc::QUIC_FRAME_DATAGRAM || frame_type == rfc::QUIC_FRAME_DATAGRAM_LEN else {
        return false;
    }

    var payload_end = wire.len;
    if frame_type == rfc::QUIC_FRAME_DATAGRAM_LEN {
        let len, ok_l = read_varint(wire, idx);
        let rem_len = core::sub_sat_i64(wire.len, idx) as u64;
        guard ok_l && idx <= wire.len && len == rem_len else {
            return false;
        }
        payload_end = core::add_sat_i64(idx, len as i64);
    }

    guard core::sub_sat_i64(payload_end, idx) <= realtime_internal::ws_buf_cap(out_payload) else {
        return false;
    }
    out_payload.clear();
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
    var eff_len = min(reason.len, 1024);
    if reason.len > 1024 {
        while eff_len > 0 && (reason[eff_len] & 0xC0) == 0x80 {
            eff_len = core::sub_sat_i64(eff_len, 1);
        }
    }
    let eff_reason = if eff_len > 0 && reason[..eff_len].validate_utf8() { reason[..eff_len] } else { "" };

    realtime_internal::write_varint(out, rfc::CAPSULE_CLOSE_WEBTRANSPORT);
    let payload_len = core::add_sat_i64(4, eff_reason.len);
    realtime_internal::write_varint(out, payload_len as u64);

    out.append_u32_be(error_code);
    out.append(eff_reason);
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
    guard reason.validate_utf8() && out.reason.try_set(reason) else { return false; }

    let code = core::read_be_u32(payload, 0);
    out.error_code = code;
    return true;
}

// Encodes a DRAIN_WEBTRANSPORT_SESSION capsule:
// Capsule Type (varint 0x78AE) || Length (varint 0)
fn encode_webtransport_drain_session<B>(out: B&) {
    realtime_internal::write_varint(out, rfc::CAPSULE_DRAIN_WEBTRANSPORT);
    realtime_internal::write_varint(out, 0);
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
    realtime_internal::write_varint(out, rfc::CAPSULE_WT_RESET_STREAM);
    var tmp_body: u8[..32] = [];
    realtime_internal::write_varint(tmp_body, stream_id);
    realtime_internal::write_varint(tmp_body, error_code as u64);

    realtime_internal::write_varint(out, tmp_body.len as u64);
    out.append(tmp_body[..]);
}

// Decodes a WT_RESET_STREAM capsule from its payload.
//
// Example:
//   payload = [0x01, 0x00]
//   returns: WebTransportStreamReset { stream_id: 1, error_code: 0 }, ok = true
fn decode_webtransport_reset_stream(
    payload: const u8[:],
) -> WebTransportStreamReset, bool {
    var idx: i64 = 0;
    let sid, ok1 = read_varint(payload, idx);
    guard ok1 else { return WebTransportStreamReset { .. }, false; }

    let code, ok2 = read_varint(payload, idx);
    guard ok2 && idx == payload.len && code <= 0xFFFFFFFF else {
        return WebTransportStreamReset { .. }, false;
    }

    return WebTransportStreamReset { stream_id: sid, error_code: code as u32 }, true;
}

// Encodes a WT_STOP_SENDING capsule (draft-ietf-webtrans-http3-16 / draft-ietf-webtrans-http2):
// Capsule Type (varint 0x190B4D3A) || Length (varint) || Stream ID (varint) || Error Code (varint)
fn encode_webtransport_stop_sending<B>(
    stream_id:  u64,
    error_code: u32,
    out:        B&,
) {
    realtime_internal::write_varint(out, rfc::CAPSULE_WT_STOP_SENDING);
    var tmp_body: u8[..32] = [];
    realtime_internal::write_varint(tmp_body, stream_id);
    realtime_internal::write_varint(tmp_body, error_code as u64);

    realtime_internal::write_varint(out, tmp_body.len as u64);
    out.append(tmp_body[..]);
}

// Decodes a WT_STOP_SENDING capsule from its payload.
//
// Example:
//   payload = [0x01, 0x00]
//   returns: WebTransportStreamStopSending { stream_id: 1, error_code: 0 }, ok = true
fn decode_webtransport_stop_sending(
    payload: const u8[:],
) -> WebTransportStreamStopSending, bool {
    var idx: i64 = 0;
    let sid, ok1 = read_varint(payload, idx);
    guard ok1 else { return WebTransportStreamStopSending { .. }, false; }

    let code, ok2 = read_varint(payload, idx);
    guard ok2 && idx == payload.len && code <= 0xFFFFFFFF else {
        return WebTransportStreamStopSending { .. }, false;
    }

    return WebTransportStreamStopSending { stream_id: sid, error_code: code as u32 }, true;
}

// ---- Session State Management --------------------------------------------

fn close_webtransport_session(session: WebTransportSession&, code: u32, reason: const u8[:]) {
    session.is_active = false;
    session.close_code = code;
    let copy_len = min(reason.len, session.close_reason.cap);
    let _ = session.close_reason.try_set(reason[..copy_len]);
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
// Requires 0x41 signal + client-initiated bidirectional Session ID varint (4*N); invalid frames are rejected.
//
// Example:
//   wire = [0x40, 0x41, 0x04, 'd', 'a', 't', 'a']
//   returns: session_id = 4, payload = "data", ok = true
fn demux_webtransport_bidi_stream(
    wire: const u8[:],
) -> u64, const u8[:], bool {
    let hdr, ok = decode_webtransport_bidi_stream_header(wire);
    guard ok else { return 0, wire[..0], false; }
    return hdr.session_id, wire[hdr.header_len..], true;
}

// draft-ietf-webtrans-http3 Section 4.1: Unidirectional Streams - WebTransport Stream Type and Session ID Demux
// Demuxes a WebTransport unidirectional stream opening frame.
// Validates 0x54 (STREAM_TYPE_WEBTRANSPORT) stream type prefix followed by client bidi Session ID varint (4*N).
//
// Example:
//   wire = [0x40, 0x54, 0x04, 'u', 'n', 'i']
//   returns: session_id = 4, payload = "uni", ok = true
fn demux_webtransport_uni_stream(
    wire: const u8[:],
) -> u64, const u8[:], bool {
    let hdr, ok = decode_webtransport_uni_stream_header(wire);
    guard ok else { return 0, wire[..0], false; }
    return hdr.session_id, wire[hdr.header_len..], true;
}

// Registers a new active session into the demuxer, reusing closed session slots if full.
fn register_webtransport_session(demuxer: WebTransportDemuxer&, session_id: u64) -> bool {
    guard realtime_internal::is_valid_webtransport_session_id(session_id) else { return false; }
    let entry = WebTransportSessionEntry {
        session_id: session_id,
        state:      WebTransportSessionState.Active,
        ..
    };
    for &s in demuxer.sessions {
        if s.session_id == session_id {
            s = entry;
            realtime_internal::close_session_streams(demuxer, session_id);
            return true;
        }
    }
    if demuxer.sessions.try_push(entry) {
        realtime_internal::close_session_streams(demuxer, session_id);
        return true;
    }
    for &s in demuxer.sessions {
        if s.state == WebTransportSessionState.Closed {
            let old_sid = s.session_id;
            realtime_internal::close_session_streams(demuxer, old_sid);
            realtime_internal::close_session_streams(demuxer, session_id);
            s = entry;
            return true;
        }
    }
    return false;
}

// Updates session state (Connecting, Active, Draining, Closed).
fn set_webtransport_session_state(
    demuxer:    WebTransportDemuxer&,
    session_id: u64,
    state:      WebTransportSessionState,
) -> bool {
    let s_idx, has_s = realtime_internal::find_session_entry_index(demuxer, session_id);
    guard has_s else { return false; }
    demuxer.sessions[s_idx].state = state;
    if state == WebTransportSessionState.Closed {
        realtime_internal::close_session_streams(demuxer, session_id);
    }
    return true;
}

// Queries current session state.
fn get_webtransport_session_state(
    demuxer:    const WebTransportDemuxer&,
    session_id: u64,
) -> WebTransportSessionState, bool {
    let s_idx, has_s = realtime_internal::find_session_entry_index(demuxer, session_id);
    guard has_s else { return WebTransportSessionState.Closed, false; }
    return demuxer.sessions[s_idx].state, true;
}

// Drains an active session (rejects new streams, drains existing).
fn drain_webtransport_demuxer_session(demuxer: WebTransportDemuxer&, session_id: u64) -> bool {
    return set_webtransport_session_state(demuxer, session_id, WebTransportSessionState.Draining);
}

// Closes a session with error code and reason, and closes all associated open stream routes.
fn close_webtransport_demuxer_session(
    demuxer:    WebTransportDemuxer&,
    session_id: u64,
    code:       u32,
    reason:     const u8[:],
) -> bool {
    let s_idx, has_s = realtime_internal::find_session_entry_index(demuxer, session_id);
    guard has_s else { return false; }
    let sess .= demuxer.sessions[s_idx];
    sess.state = WebTransportSessionState.Closed;
    sess.close_code = code;
    let copy_len = min(reason.len, sess.close_reason.cap);
    let _ = sess.close_reason.try_set(reason[..copy_len]);
    realtime_internal::close_session_streams(demuxer, session_id);
    return true;
}

// draft-ietf-webtrans-overview Section 4.2: Bidirectional Streams - Demuxes stream wire bytes and dispatches to session
// Zero-heap demuxer for QUIC streams. Handles both stream initiation and continuous streaming chunks.
//
// Example:
//   stream_id = 4, wire = [0x40, 0x41, 0x04, 'p', 'i', 'n', 'g'], fin = true
//   returns: ok = true, out.session_id = 4, out.payload = "ping", out.fin = true
fn demux_webtransport_stream(
    demuxer:   WebTransportDemuxer&,
    stream_id: u64,
    wire:      const u8[:],
    fin:       bool,
    out:       WebTransportStreamPayload&,
) -> bool {
    let route_idx, has_route = realtime_internal::find_stream_route_index(demuxer, stream_id);
    if has_route {
        return realtime_internal::route_existing_stream(demuxer, route_idx, wire, fin, out);
    }

    return realtime_internal::route_new_stream(demuxer, stream_id, wire, fin, out);
}
