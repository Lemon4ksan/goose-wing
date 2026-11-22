// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// WebSocket opening handshake and Extended CONNECT upgrade engines across HTTP/1.1 (RFC 6455),
// HTTP/2 (RFC 8441), and HTTP/3 (RFC 9220).
namespace realtime;

import std;
import core;
import rfc.http;
import rfc.ws;
import http.headers;
import http.request;
import http.response;
import .internal;
import .ws_pmd_internal;
import .websocket;
import .ws_deflate;

// ---- Handshake Engine (RFC 6455 Section 4.2.2 & RFC 8441) ---------------

// Computes standard `Sec-WebSocket-Accept` from `Sec-WebSocket-Key`.
// Uses zero-allocation unrolled 2-block SHA-1 compression for 24-byte keys (Alex Hultman / uWebSockets pattern).
fn compute_websocket_accept<B>(client_key: const u8[:], out: B&) {
    if client_key.len == 24 {
        var blk1: u8[64] = [0; 64];
        for i in 24 {
            blk1[i] = client_key[i];
        }
        for i in 40 {
            let dst_idx = core::add_sat_i64(24, i);
            blk1[dst_idx] = realtime_internal::WS_SHA1_BLOCK1_GUID[i];
        }

        var state: u32[5] = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        ];
        core::sha1_compress(state, blk1[..]);
        core::sha1_compress(state, realtime_internal::WS_SHA1_BLOCK2_TEMPLATE[..]);

        var digest: u8[20] = [0; 20];
        for i in 5 {
            let base = core::mul_sat_i64(i, 4);
            core::write_be_u32_at(digest[..], base, state[i]);
        }
        core::base64_encode(digest[..], out);
        return;
    }

    // Generic fallback for non-standard key lengths
    var combined: u8[..128] = [];
    guard combined.try_set(client_key) && combined.try_append(rfc::WS_HANDSHAKE_GUID) else { return; }
    let digest = core::sha1(combined[..]);
    core::base64_encode(digest[..], out);
}

// Validates an RFC 6455 §4.2.1 client Sec-WebSocket-Key:
// Must be exactly 24 characters, end in "==", and contain valid Base64 characters representing a 16-byte nonce.
fn is_valid_websocket_key(key: const u8[:]) -> bool {
    guard key.len == 24 else { return false; }
    guard key[22] == '=' && key[23] == '=' else { return false; }

    for i in 22 {
        guard core::base64_val(key[i]) >= 0 else { return false; }
    }
    // RFC 4648 §3.5 / RFC 6455 §4.2.1: 16 bytes (128 bits) encoded in 22 Base64 sextets (132 bits)
    // must have the 4 trailing padding bits of the 22nd character equal to zero.
    return (core::base64_val(key[21]) & 0x0F) == 0;
}

// Validates server `Sec-WebSocket-Accept` against client key.
fn validate_websocket_accept(client_key: const u8[:], server_accept: const u8[:]) -> bool {
    guard server_accept.len == 28 else { return false; }
    var expected: u8[..64] = [];
    compute_websocket_accept(client_key, expected);
    guard expected.len == 28 else { return false; }
    return core::ct_eq_bytes(expected[..], server_accept);
}

// Formats a 16-byte random nonce into a 24-character Base64 client key.
fn generate_websocket_key<B>(random_16: const u8[16]&, out: B&) {
    core::base64_encode(random_16[..], out);
}

// Checks if a requested subprotocol is present in the comma-separated Sec-WebSocket-Protocol
// header list and consists exclusively of valid RFC 6455 §4.2.1 / RFC 9110 `tchar` token characters.
fn has_subprotocol_token(list: const u8[:], target: const u8[:]) -> bool {
    guard list.len > 0 && target.len > 0 else { return false; }
    for b in target {
        guard core::is_tchar(b) else { return false; }
    }
    var tok = core::make_byte_tokenizer(list, ',');
    loop {
        let part, ok = tok.token_next();
        guard ok else { break; }
        if part.trim_lws() == target {
            return true;
        }
    }
    return false;
}

// Client-side RFC 6455 §4.1 handshake verification error codes.
enum WsError {
    None,
    InvalidStatusCode,
    MissingUpgradeHeader,
    MissingConnectionHeader,
    InvalidAcceptKey,
    InvalidSubprotocol,
    InvalidExtension,
}

// Validates an HTTP/1.1 101 Switching Protocols server response for a client WebSocket handshake (RFC 6455 §4.1).
// Returns `(negotiated_subprotocol, WsError.None)` on success.
fn validate_client_upgrade_response(
    status_code:        u16,
    headers:            const http::HeaderMap&,
    raw_buf:            const u8[:],
    client_key:         const u8[:],
    offered_protocols:  const u8[:],
    offered_extensions: const u8[:] = "",
) -> const u8[:], WsError {
    guard status_code == 101 else { return "", WsError.InvalidStatusCode; }
    guard realtime_internal::map_has_header_token(headers, raw_buf, "upgrade", "websocket") else {
        return "", WsError.MissingUpgradeHeader;
    }
    guard realtime_internal::map_has_header_token(headers, raw_buf, "connection", "upgrade") else {
        return "", WsError.MissingConnectionHeader;
    }

    let accept_val, accept_cnt = realtime_internal::map_extract_single_header(
        headers, raw_buf, "sec-websocket-accept",
    );
    guard accept_cnt == 1 && validate_websocket_accept(client_key, accept_val) else {
        return "", WsError.InvalidAcceptKey;
    }

    guard realtime_internal::validate_response_ws_extensions(headers, raw_buf, offered_extensions) else {
        return "", WsError.InvalidExtension;
    }

    let proto_val, proto_cnt = realtime_internal::map_extract_single_header(
        headers, raw_buf, "sec-websocket-protocol",
    );
    guard proto_cnt <= 1 else { return "", WsError.InvalidSubprotocol; }
    if proto_cnt == 1 {
        guard proto_val.len > 0 && offered_protocols.len > 0 else {
            return "", WsError.InvalidSubprotocol;
        }
        guard !proto_val.contains_byte(',') && has_subprotocol_token(offered_protocols, proto_val) else {
            return "", WsError.InvalidSubprotocol;
        }
        return proto_val, WsError.None;
    }

    return "", WsError.None;
}

// Server-side WebSocket upgrade handler (RFC 6455). Validates client request and populates 101 response.
fn ws_upgrade_request(
    req:         const http::Request&,
    out_resp:    http::Response&,
    subprotocol: const u8[:] = "",
) -> WebSocketSession, bool {
    guard req.method[..] == "GET" else {
        out_resp.status_code = rfc::STATUS_METHOD_NOT_ALLOWED;
        return WebSocketSession { .. }, false;
    }
    guard !req.is_http10 else {
        out_resp.status_code = rfc::STATUS_BAD_REQUEST;
        return WebSocketSession { .. }, false;
    }

    let client_key, ok_hdrs = realtime_internal::validate_ws_upgrade_headers(req, out_resp);
    guard ok_hdrs else {
        return WebSocketSession { .. }, false;
    }

    var session = new_websocket_session(false);
    if subprotocol.len > 0 {
        guard subprotocol.len <= session.subprotocol.cap else {
            out_resp.status_code = rfc::STATUS_BAD_REQUEST;
            return WebSocketSession { .. }, false;
        }
    }

    var accept_key: u8[..64] = [];
    compute_websocket_accept(client_key, accept_key);

    out_resp.status_code = rfc::STATUS_SWITCHING_PROTOCOLS;
    out_resp.set_header("Upgrade", "websocket");
    out_resp.set_header("Connection", "Upgrade");
    out_resp.set_header("Sec-WebSocket-Accept", accept_key[..]);

    if subprotocol.len > 0 && realtime_internal::req_has_subprotocol(req, subprotocol) {
        out_resp.set_header("Sec-WebSocket-Protocol", subprotocol);
        let _ = session.subprotocol.try_set(subprotocol);
    }

    return session, true;
}

// Inspects an incoming HTTP Request to determine if it is an RFC 6455 WebSocket Upgrade request.
fn is_websocket_upgrade_request(req: const http::Request&) -> bool {
    guard req.method[..] == "GET" && !req.is_http10 else { return false; }
    let ws_mask = http::HDR_PRESENCE_HOST |
                  http::HDR_PRESENCE_UPGRADE |
                  http::HDR_PRESENCE_CONNECTION |
                  http::HDR_PRESENCE_SEC_WEBSOCKET_KEY;
    if req.presence_mask != 0 {
        guard (req.presence_mask & ws_mask) == ws_mask else { return false; }
    }
    let host_cnt = realtime_internal::req_count_header(req, "host");
    let host = req.headers.find_header("Host").trim_lws();
    guard host_cnt == 1 && host.len > 0 else { return false; }
    guard realtime_internal::req_has_header_token(req, "upgrade", "websocket") else { return false; }
    guard realtime_internal::req_has_header_token(req, "connection", "upgrade") else { return false; }
    guard realtime_internal::req_count_header(req, "sec-websocket-version") == 1 &&
        realtime_internal::req_count_header(req, "sec-websocket-key") == 1 &&
        realtime_internal::req_has_valid_ws_subprotocols(req) else {
        return false;
    }
    guard req.headers.find_header("Sec-WebSocket-Version") == rfc::WS_RFC6455_VERSION else { return false; }
    let key = req.headers.find_header("Sec-WebSocket-Key");
    return is_valid_websocket_key(key);
}

// ---- Bootstrapping WebSockets with HTTP/2 (RFC 8441) ---------------------

// Inspects an incoming HTTP Request to determine if it is an RFC 8441 WebSocket Extended CONNECT request.
fn is_h2_websocket_request(req: const http::Request&) -> bool {
    guard req.method[..] == "CONNECT" else { return false; }
    let proto = req.headers.find_header(":protocol");
    guard proto.eq_ascii_fold("websocket") else { return false; }
    guard realtime_internal::req_count_header(req, "sec-websocket-version") == 1 else { return false; }
    let ver = req.headers.find_header("sec-websocket-version");
    return ver == rfc::WS_RFC6455_VERSION;
}

// Validates an RFC 8441 WebSocket Extended CONNECT request according to strict protocol rules:
// - :method MUST be CONNECT
// - :protocol MUST be websocket
// - :scheme MUST be http or https
// - :path and :authority MUST be present
// - sec-websocket-version MUST be 13
// - MUST NOT contain connection, upgrade, keep-alive, transfer-encoding, proxy-connection, or sec-websocket-key
fn validate_h2_websocket_request(req: const http::Request&) -> bool {
    guard is_h2_websocket_request(req) else { return false; }

    let scheme = req.headers.find_header(":scheme");
    guard scheme.eq_ascii_fold("http") || scheme.eq_ascii_fold("https") else { return false; }
    let path = req.headers.find_header(":path");
    guard path.len > 0 else { return false; }
    let auth = req.headers.find_header(":authority");
    guard auth.len > 0 else { return false; }

    // RFC 8441 §4: Connection-specific headers and Sec-WebSocket-Key MUST NOT be present
    for &e in req.headers.entries {
        if realtime_internal::is_forbidden_h2_ws_header(http::entry_name(req.headers, e)) {
            return false;
        }
    }
    return true;
}

// Formats an outbound RFC 8441 WebSocket Extended CONNECT Request for HTTP/2.
fn format_h2_websocket_request(
    req:         http::Request&,
    path:        const u8[:],
    authority:   const u8[:],
    scheme:      const u8[:] = "https",
    subprotocol: const u8[:] = "",
) {
    req = http::new_request("CONNECT", path);
    http::set_header(req, ":method", "CONNECT");
    http::set_header(req, ":protocol", "websocket");
    http::set_header(req, ":scheme", scheme);
    http::set_header(req, ":authority", authority);
    http::set_header(req, ":path", path);
    http::set_header(req, "sec-websocket-version", rfc::WS_RFC6455_VERSION);

    if subprotocol.len > 0 {
        http::set_header(req, "sec-websocket-protocol", subprotocol);
    }
}

// Server-side RFC 8441 WebSocket Extended CONNECT upgrade handler.
// Validates client request and populates 200 OK response (NOT 101 per RFC 8441 §5).
fn ws_h2_upgrade_request(
    req:         const http::Request&,
    out_resp:    http::Response&,
    subprotocol: const u8[:] = "",
) -> WebSocketSession, bool {
    guard validate_h2_websocket_request(req) else {
        out_resp.status_code = rfc::STATUS_BAD_REQUEST;
        return WebSocketSession { .. }, false;
    }

    var session = new_websocket_session(false);
    if subprotocol.len > 0 {
        guard subprotocol.len <= session.subprotocol.cap else {
            out_resp.status_code = rfc::STATUS_BAD_REQUEST;
            return WebSocketSession { .. }, false;
        }
    }

    out_resp.status_code = rfc::STATUS_OK;

    if subprotocol.len > 0 && realtime_internal::req_has_subprotocol(req, subprotocol) {
        out_resp.set_header("sec-websocket-protocol", subprotocol);
        let _ = session.subprotocol.try_set(subprotocol);
    }

    return session, true;
}

// Inspects an HTTP/2 Response to determine if it accepted an RFC 8441 WebSocket session.
fn is_h2_websocket_response(res: const http::Response&) -> bool {
    return res.status_code == rfc::STATUS_OK;
}

// ---- RFC 9220 Bootstrapping WebSockets with HTTP/3 ---------------------

// Formats an outbound RFC 9220 WebSocket Extended CONNECT Request for HTTP/3.
fn format_h3_websocket_request(
    req:         http::Request&,
    path:        const u8[:],
    authority:   const u8[:],
    scheme:      const u8[:] = "https",
    subprotocol: const u8[:] = "",
) {
    format_h2_websocket_request(req, path, authority, scheme, subprotocol);
    req.is_http10 = false;
}

// Validates an RFC 9220 WebSocket Extended CONNECT request over HTTP/3.
// Follows exact same validation rules as RFC 8441 per RFC 9220 Section 3.
fn validate_h3_websocket_request(req: const http::Request&) -> bool {
    guard req.method == "CONNECT" else { return false; }
    return validate_h2_websocket_request(req);
}

// Server-side RFC 9220 WebSocket Extended CONNECT upgrade handler for HTTP/3.
fn ws_h3_upgrade_request(
    req:         const http::Request&,
    out_resp:    http::Response&,
    subprotocol: const u8[:] = "",
) -> WebSocketSession, bool {
    guard validate_h3_websocket_request(req) else {
        out_resp.status_code = rfc::STATUS_BAD_REQUEST;
        return WebSocketSession { .. }, false;
    }
    return ws_h2_upgrade_request(req, out_resp, subprotocol);
}

// Formats an HTTP/3 response accepting an RFC 9220 WebSocket session (200 OK).
fn format_h3_websocket_response(res: http::Response&, subprotocol: const u8[:] = "") {
    res.status_code = rfc::STATUS_OK;
    realtime_internal::format_h2_websocket_response(res, subprotocol);
}

// Inspects an HTTP/3 Response to determine if it accepted an RFC 9220 WebSocket session.
fn is_h3_websocket_response(res: const http::Response&) -> bool {
    guard res.status_code == rfc::STATUS_OK else { return false; }
    return is_h2_websocket_response(res);
}

// Checks if an arbitrary HTTP request is an RFC 8441 / RFC 9220 Extended CONNECT request.
fn is_extended_connect_request(req: const http::Request&) -> bool {
    guard req.method == "CONNECT" else { return false; }
    let proto = req.headers.find_header(":protocol");
    return proto.len > 0;
}

// Encapsulates a WebSocket message into an HTTP/2 or HTTP/3 stream DATA frame payload.
fn ws_encapsulate_stream_data<B>(
    out:       B&,
    opcode:    u8,
    payload:   const u8[:],
    is_client: bool,
    mask_key:  const u8[4] = [0x11, 0x22, 0x33, 0x44],
) {
    if is_client {
        encode_ws_frame(out, opcode, payload, true, mask_key);
    } else {
        let empty_mask: const u8[4] = [0, 0, 0, 0];
        encode_ws_frame(out, opcode, payload, false, empty_mask);
    }
}
