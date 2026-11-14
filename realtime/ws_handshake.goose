// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// WebSocket opening handshake and Extended CONNECT upgrade engines across HTTP/1.1 (RFC 6455),
// HTTP/2 (RFC 8441), and HTTP/3 (RFC 9220).
namespace wing;

import std;
import core from "..";
import .websocket;

// ---- Handshake Engine (RFC 6455 Section 4.2.2 & RFC 8441) ---------------

// Fast-path template blocks for 24-byte RFC 6455 client key hashing (uWebSockets WebSocketHandshake pattern).
// Block 1: 24 bytes client key + 36 bytes GUID + 0x80 padding + 3 zero bytes = 64 bytes.
let WS_SHA1_BLOCK1_GUID: const u8[40] = [
    '2', '5', '8', 'E', 'A', 'F', 'A', '5', '-', 'E', '9', '1', '4', '-', '4', '7', 'D', 'A',
    '-', '9', '5', 'C', 'A', '-', 'C', '5', 'A', 'B', '0', 'D', 'C', '8', '5', 'B', '1', '1',
    0x80, 0, 0, 0,
];

// Block 2: 56 zero bytes + big-endian 480 bit length (0x01E0) = 64 bytes.
let WS_SHA1_BLOCK2_TEMPLATE: const u8[64] = [
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
    0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0x01, 0xE0,
];

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
            blk1[dst_idx] = WS_SHA1_BLOCK1_GUID[i];
        }

        var state: u32[5] = [
            0x67452301,
            0xEFCDAB89,
            0x98BADCFE,
            0x10325476,
            0xC3D2E1F0,
        ];
        core::sha1_compress(state, blk1[..]);
        core::sha1_compress(state, WS_SHA1_BLOCK2_TEMPLATE[..]);

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

// Validates server `Sec-WebSocket-Accept` against client key
fn validate_websocket_accept(client_key: const u8[:], server_accept: const u8[:]) -> bool {
    guard server_accept.len == 28 else { return false; }
    var expected: u8[..64] = [];
    compute_websocket_accept(client_key, expected);
    guard expected.len == 28 else { return false; }
    return core::ct_eq_bytes(expected[..], server_accept);
}

// Formats a 16-byte random nonce into a 24-character Base64 client key
fn generate_websocket_key<B>(random_16: const u8[16]&, out: B&) {
    core::base64_encode(random_16[..], out);
}

// Checks if a requested token is present in the comma-separated header value list (RFC 6455 §4.2.1).
fn has_header_token_fold(list: const u8[:], target: const u8[:]) -> bool {
    guard list.len > 0 && target.len > 0 else { return false; }
    var tok = core::make_byte_tokenizer(list, ',');
    loop {
        let part, ok = tok.token_next();
        guard ok else { break; }
        if part.trim_lws().eq_ascii_fold(target) {
            return true;
        }
    }
    return false;
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

// Counts the number of header fields in `req` matching `header_name` (case-insensitive).
fn req_count_header(req: const Request&, header_name: const u8[:]) -> i64 {
    var count: i64 = 0;
    for &e in req.headers.entries {
        if entry_name(req.headers, e).eq_ascii_fold(header_name) {
            count = core::add_sat_i64(count, 1);
        }
    }
    return count;
}

// Helper to search for a token inside a specified HTTP header across all matching lines.
fn req_has_header_token(req: const Request&, header_name: const u8[:], token: const u8[:]) -> bool {
    for &e in req.headers.entries {
        if entry_name(req.headers, e).eq_ascii_fold(header_name) {
            if has_header_token_fold(entry_value(req.headers, e), token) {
                return true;
            }
        }
    }
    return false;
}

// Helper to determine if a subprotocol is requested by the client in Sec-WebSocket-Protocol.
fn req_has_subprotocol(req: const Request&, subprotocol: const u8[:]) -> bool {
    for &e in req.headers.entries {
        if entry_name(req.headers, e).eq_ascii_fold("sec-websocket-protocol") {
            if has_subprotocol_token(entry_value(req.headers, e), subprotocol) {
                return true;
            }
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

inline fn resolve_hdr_entry_name(map: const HeaderMap&, raw_buf: const u8[:], e: const HeaderEntry&) -> const u8[:] {
    if raw_buf.len > 0 && e.name_end <= raw_buf.len {
        return raw_buf[(e.name_begin as i64)..(e.name_end as i64)];
    }
    if e.name_end <= map.raw_buf.len {
        return map.raw_buf[(e.name_begin as i64)..(e.name_end as i64)];
    }
    return "";
}

inline fn resolve_hdr_entry_val(map: const HeaderMap&, raw_buf: const u8[:], e: const HeaderEntry&) -> const u8[:] {
    if raw_buf.len > 0 && e.values_end <= raw_buf.len {
        return raw_buf[(e.values_begin as i64)..(e.values_end as i64)];
    }
    if e.values_end <= map.raw_buf.len {
        return map.raw_buf[(e.values_begin as i64)..(e.values_end as i64)];
    }
    return "";
}

fn map_has_header_token(
    map:         const HeaderMap&,
    raw_buf:     const u8[:],
    header_name: const u8[:],
    token:       const u8[:],
) -> bool {
    for &e in map.entries {
        if resolve_hdr_entry_name(map, raw_buf, e).eq_ascii_fold(header_name) {
            if has_header_token_fold(resolve_hdr_entry_val(map, raw_buf, e), token) {
                return true;
            }
        }
    }
    return false;
}

// Extracts the first trimmed value and occurrence count of `header_name` in `map`.
//
// Example:
//   header_name = "sec-websocket-accept"
//   returns: ("s3pPLMBiTxaQ9kYGzzhZRbK+xOo=", 1)
fn map_extract_single_header(
    map:         const HeaderMap&,
    raw_buf:     const u8[:],
    header_name: const u8[:],
) -> const u8[:], i64 {
    var first_idx: i64 = -1;
    var count:     i64 = 0;
    for i in map.entries.len {
        let e = map.entries[i];
        if resolve_hdr_entry_name(map, raw_buf, e).eq_ascii_fold(header_name) {
            count = core::add_sat_i64(count, 1);
            if count == 1 {
                first_idx = i;
            }
        }
    }
    if first_idx >= 0 {
        let first_e = map.entries[first_idx];
        return resolve_hdr_entry_val(map, raw_buf, first_e).trim_lws(), count;
    }
    return "", count;
}

inline fn is_valid_ws_token_slice(s: const u8[:]) -> bool {
    guard s.len > 0 else { return false; }
    for b in s {
        guard core::is_tchar(b) else { return false; }
    }
    return true;
}

fn has_offered_ws_extension_name(offered: const u8[:], ext_name: const u8[:]) -> bool {
    guard offered.len > 0 && is_valid_ws_token_slice(ext_name) else { return false; }
    var rem = offered;
    while rem.len > 0 {
        let head, tail, has_comma = rem.split_once_unquoted_byte(',');
        let name_part, _, _ = head.split_once_unquoted_byte(';');
        if name_part.trim_lws() == ext_name {
            return true;
        }
        if !has_comma { break; }
        rem = tail;
    }
    return false;
}

fn validate_response_ws_extensions(
    headers:            const HeaderMap&,
    raw_buf:            const u8[:],
    offered_extensions: const u8[:],
) -> bool {
    for &e in headers.entries {
        if !resolve_hdr_entry_name(headers, raw_buf, e).eq_ascii_fold("sec-websocket-extensions") {
            continue;
        }
        guard offered_extensions.len > 0 else { return false; }
        var rem = resolve_hdr_entry_val(headers, raw_buf, e).trim_lws();
        guard rem.len > 0 else { return false; }
        while rem.len > 0 {
            let head, tail, has_comma = rem.split_once_unquoted_byte(',');
            let name_part, _, _ = head.split_once_unquoted_byte(';');
            guard has_offered_ws_extension_name(offered_extensions, name_part.trim_lws()) else {
                return false;
            }
            if !has_comma { break; }
            rem = tail;
        }
    }
    return true;
}

// Validates an HTTP/1.1 101 Switching Protocols server response for a client WebSocket handshake (RFC 6455 §4.1).
// Returns `(negotiated_subprotocol, WsError.None)` on success.
fn validate_client_upgrade_response(
    status_code:        u16,
    headers:            const HeaderMap&,
    raw_buf:            const u8[:],
    client_key:         const u8[:],
    offered_protocols:  const u8[:],
    offered_extensions: const u8[:] = "",
) -> const u8[:], WsError {
    guard status_code == 101 else { return "", WsError.InvalidStatusCode; }
    guard map_has_header_token(headers, raw_buf, "upgrade", "websocket") else {
        return "", WsError.MissingUpgradeHeader;
    }
    guard map_has_header_token(headers, raw_buf, "connection", "upgrade") else {
        return "", WsError.MissingConnectionHeader;
    }

    let accept_val, accept_cnt = map_extract_single_header(headers, raw_buf, "sec-websocket-accept");
    guard accept_cnt == 1 && validate_websocket_accept(client_key, accept_val) else {
        return "", WsError.InvalidAcceptKey;
    }

    guard validate_response_ws_extensions(headers, raw_buf, offered_extensions) else {
        return "", WsError.InvalidExtension;
    }

    let proto_val, proto_cnt = map_extract_single_header(headers, raw_buf, "sec-websocket-protocol");
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

// Checks whether an HTTP/1.1 request provides a single non-empty Host header or an absolute-URI authority.
inline fn req_has_ws_host_authority(req: const Request&) -> bool {
    let host_cnt = req_count_header(req, "host");
    if host_cnt > 1 {
        return false;
    }
    if host_cnt == 1 {
        return req.headers.find_header("Host").trim_lws().len > 0;
    }
    guard req.url.len > 0 else { return false; }
    let u = core::new_url(req.url[..]);
    return u.valid && u.host().len > 0;
}

fn append_unique_ws_subprotocols(raw_val: const u8[:], seen: (const u8[:])[..32]&) -> bool {
    guard raw_val.len > 0 else { return false; }
    var tok = core::make_byte_tokenizer(raw_val, ',');
    while true {
        let part, ok = tok.token_next();
        guard ok else { break; }
        let item = part.trim_lws();
        guard is_valid_ws_token_slice(item) else { return false; }
        for prev in seen {
            guard prev != item else { return false; }
        }
        guard seen.try_push(item) else { return false; }
    }
    return true;
}

fn req_has_valid_ws_subprotocols(req: const Request&) -> bool {
    var seen: (const u8[:])[..32] = [];
    for &e in req.headers.entries {
        if entry_name(req.headers, e).eq_ascii_fold("sec-websocket-protocol") {
            let raw_val = entry_value(req.headers, e).trim_lws();
            guard append_unique_ws_subprotocols(raw_val, seen) else { return false; }
        }
    }
    return true;
}

// Validates RFC 6455 §4.2.1 client upgrade headers (`Upgrade`, `Connection`,
// `Sec-WebSocket-Version`, `Sec-WebSocket-Key`, and `Sec-WebSocket-Protocol`).
fn validate_ws_upgrade_headers(req: const Request&, out_resp: Response&) -> const u8[:], bool {
    guard req_has_ws_host_authority(req) &&
        req_has_header_token(req, "upgrade", "websocket") &&
        req_has_header_token(req, "connection", "upgrade") else {
        out_resp.status_code = rfc::STATUS_BAD_REQUEST;
        return "", false;
    }
    guard req_count_header(req, "sec-websocket-version") == 1 &&
        req_count_header(req, "sec-websocket-key") == 1 &&
        req_has_valid_ws_subprotocols(req) else {
        out_resp.status_code = rfc::STATUS_BAD_REQUEST;
        return "", false;
    }
    if req.headers.find_header("Sec-WebSocket-Version") != rfc::WS_RFC6455_VERSION {
        out_resp.status_code = rfc::STATUS_UPGRADE_REQUIRED;
        out_resp.set_header("Sec-WebSocket-Version", rfc::WS_RFC6455_VERSION);
        return "", false;
    }
    let client_key = req.headers.find_header("Sec-WebSocket-Key");
    guard is_valid_websocket_key(client_key) else {
        out_resp.status_code = rfc::STATUS_BAD_REQUEST;
        return "", false;
    }
    return client_key, true;
}

// Server-side WebSocket upgrade handler (RFC 6455). Validates client request and populates 101 response.
fn ws_upgrade_request(
    req:         const Request&,
    out_resp:    Response&,
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

    let client_key, ok_hdrs = validate_ws_upgrade_headers(req, out_resp);
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

    if subprotocol.len > 0 && req_has_subprotocol(req, subprotocol) {
        out_resp.set_header("Sec-WebSocket-Protocol", subprotocol);
        let _ = session.subprotocol.try_set(subprotocol);
    }

    return session, true;
}

// Inspects an incoming HTTP Request to determine if it is an RFC 6455 WebSocket Upgrade request
fn is_websocket_upgrade_request(req: const Request&) -> bool {
    guard req.method[..] == "GET" && !req.is_http10 else { return false; }
    let ws_mask = HDR_PRESENCE_HOST | HDR_PRESENCE_UPGRADE | HDR_PRESENCE_CONNECTION | HDR_PRESENCE_SEC_WEBSOCKET_KEY;
    if req.presence_mask != 0 {
        guard (req.presence_mask & ws_mask) == ws_mask else { return false; }
    }
    let host_cnt = req_count_header(req, "host");
    let host = req.headers.find_header("Host").trim_lws();
    guard host_cnt == 1 && host.len > 0 else { return false; }
    guard req_has_header_token(req, "upgrade", "websocket") else { return false; }
    guard req_has_header_token(req, "connection", "upgrade") else { return false; }
    guard req_count_header(req, "sec-websocket-version") == 1 &&
        req_count_header(req, "sec-websocket-key") == 1 &&
        req_has_valid_ws_subprotocols(req) else {
        return false;
    }
    guard req.headers.find_header("Sec-WebSocket-Version") == rfc::WS_RFC6455_VERSION else { return false; }
    let key = req.headers.find_header("Sec-WebSocket-Key");
    return is_valid_websocket_key(key);
}

// ---- Bootstrapping WebSockets with HTTP/2 (RFC 8441) ---------------------

// Inspects an incoming HTTP Request to determine if it is an RFC 8441 WebSocket Extended CONNECT request
fn is_h2_websocket_request(req: const Request&) -> bool {
    guard req.method[..] == "CONNECT" else { return false; }
    let proto = req.headers.find_header(":protocol");
    guard proto.eq_ascii_fold("websocket") else { return false; }
    guard req_count_header(req, "sec-websocket-version") == 1 else { return false; }
    let ver = req.headers.find_header("sec-websocket-version");
    return ver == rfc::WS_RFC6455_VERSION;
}

inline fn is_forbidden_h2_ws_header(name: const u8[:]) -> bool {
    return name.eq_ascii_fold("connection") ||
           name.eq_ascii_fold("upgrade") ||
           name.eq_ascii_fold("keep-alive") ||
           name.eq_ascii_fold("transfer-encoding") ||
           name.eq_ascii_fold("proxy-connection") ||
           name.eq_ascii_fold("sec-websocket-key");
}

// Validates an RFC 8441 WebSocket Extended CONNECT request according to strict protocol rules:
// - :method MUST be CONNECT
// - :protocol MUST be websocket
// - :scheme MUST be http or https
// - :path and :authority MUST be present
// - sec-websocket-version MUST be 13
// - MUST NOT contain connection, upgrade, keep-alive, transfer-encoding, proxy-connection, or sec-websocket-key
fn validate_h2_websocket_request(req: const Request&) -> bool {
    guard is_h2_websocket_request(req) else { return false; }

    let scheme = req.headers.find_header(":scheme");
    guard scheme.eq_ascii_fold("http") || scheme.eq_ascii_fold("https") else { return false; }
    let path = req.headers.find_header(":path");
    guard path.len > 0 else { return false; }
    let auth = req.headers.find_header(":authority");
    guard auth.len > 0 else { return false; }

    // RFC 8441 §4: Connection-specific headers and Sec-WebSocket-Key MUST NOT be present
    for &e in req.headers.entries {
        if is_forbidden_h2_ws_header(entry_name(req.headers, e)) {
            return false;
        }
    }
    return true;
}

// Formats an outbound RFC 8441 WebSocket Extended CONNECT Request for HTTP/2
fn format_h2_websocket_request(
    req:         Request&,
    path:        const u8[:],
    authority:   const u8[:],
    scheme:      const u8[:] = "https",
    subprotocol: const u8[:] = "",
) {
    req = new_request("CONNECT", path);
    set_header(req, ":method", "CONNECT");
    set_header(req, ":protocol", "websocket");
    set_header(req, ":scheme", scheme);
    set_header(req, ":authority", authority);
    set_header(req, ":path", path);
    set_header(req, "sec-websocket-version", rfc::WS_RFC6455_VERSION);

    if subprotocol.len > 0 {
        set_header(req, "sec-websocket-protocol", subprotocol);
    }
}

// Server-side RFC 8441 WebSocket Extended CONNECT upgrade handler.
// Validates client request and populates 200 OK response (NOT 101 per RFC 8441 §5).
fn ws_h2_upgrade_request(
    req:         const Request&,
    out_resp:    Response&,
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

    if subprotocol.len > 0 && req_has_subprotocol(req, subprotocol) {
        out_resp.set_header("sec-websocket-protocol", subprotocol);
        let _ = session.subprotocol.try_set(subprotocol);
    }

    return session, true;
}

// Formats an HTTP/2 response accepting an RFC 8441 WebSocket session
fn format_h2_websocket_response(res: Response&, subprotocol: const u8[:] = "") {
    res.status_code = rfc::STATUS_OK;
    if subprotocol.len > 0 {
        res.set_header("sec-websocket-protocol", subprotocol);
    }
}

// Inspects an HTTP/2 Response to determine if it accepted an RFC 8441 WebSocket session
fn is_h2_websocket_response(res: const Response&) -> bool {
    return res.status_code == rfc::STATUS_OK;
}

// ---- RFC 9220 Bootstrapping WebSockets with HTTP/3 ---------------------

// Formats an outbound RFC 9220 WebSocket Extended CONNECT Request for HTTP/3
fn format_h3_websocket_request(
    req:         Request&,
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
fn validate_h3_websocket_request(req: const Request&) -> bool {
    guard req.method == "CONNECT" else { return false; }
    return validate_h2_websocket_request(req);
}

// Server-side RFC 9220 WebSocket Extended CONNECT upgrade handler for HTTP/3.
fn ws_h3_upgrade_request(
    req:         const Request&,
    out_resp:    Response&,
    subprotocol: const u8[:] = "",
) -> WebSocketSession, bool {
    guard validate_h3_websocket_request(req) else {
        out_resp.status_code = rfc::STATUS_BAD_REQUEST;
        return WebSocketSession { .. }, false;
    }
    return ws_h2_upgrade_request(req, out_resp, subprotocol);
}

// Formats an HTTP/3 response accepting an RFC 9220 WebSocket session (200 OK)
fn format_h3_websocket_response(res: Response&, subprotocol: const u8[:] = "") {
    res.status_code = rfc::STATUS_OK;
    format_h2_websocket_response(res, subprotocol);
}

// Inspects an HTTP/3 Response to determine if it accepted an RFC 9220 WebSocket session
fn is_h3_websocket_response(res: const Response&) -> bool {
    guard res.status_code == rfc::STATUS_OK else { return false; }
    return is_h2_websocket_response(res);
}

// Checks if an arbitrary HTTP request is an RFC 8441 / RFC 9220 Extended CONNECT request
fn is_extended_connect_request(req: const Request&) -> bool {
    guard req.method == "CONNECT" else { return false; }
    let proto = req.headers.find_header(":protocol");
    return proto.len > 0;
}

// Encapsulates a WebSocket message into an HTTP/2 or HTTP/3 stream DATA frame payload
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
