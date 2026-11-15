// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// High-level HTTP verbs, streaming uploads/downloads, and realtime protocol sessions (WebSocket, SSE, MASQUE).
namespace wing;

import std;
import core from "../..";
import http.request;
import http.response;
import client.stream;
import realtime.websocket;
import realtime.sse;
import net.masque;
import client.session.ssrf;
import client.session.mock;
import client.client;
import client.session.exec;

// ---- high-level dispatch entry points --------------------------------------

fn do(session: Session&, req: const Request&) -> Response, Error {
    return execute_request(session, req);
}

// Last-mile closure overload: clones `req`, applies `F(&copy_req)`, and dispatches
fn do<F: fn(Request&)>(session: Session&, req: const Request&) -> Response, Error {
    var modified = copy(req);
    F(&modified);
    return do(session, modified);
}

// ---- okhttp/tower-style interceptor execution ------------------------------

struct InterceptorChain {
    request:         Request&,
    response:        Response&,
    err:             Error = Error { .. },
    proceeded:       bool  = false,
    short_circuited: bool  = false,
}

fn proceed(chain: InterceptorChain&, session: Session&) {
    chain.proceeded = true;
    let resp, err = execute_request(session, chain.request);
    chain.response = copy(resp);
    chain.err = err;
}

fn do_intercepted<F: fn(InterceptorChain&, Session&)>(session: Session&, req: const Request&) -> Response, Error {
    var req_copy = copy(req);
    var resp = Response { .. };
    var chain = InterceptorChain {
        request:  req_copy,
        response: resp,
        ..
    };
    F(&chain, &session);
    if !chain.proceeded && !chain.short_circuited {
        proceed(chain, session);
    }
    return copy(chain.response), chain.err;
}

// ---- express verbs ---------------------------------------------------------

fn get(session: Session&, url: const u8[:]) -> Response, Error {
    let req = new_request("GET", url);
    return do(session, req);
}

fn get<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("GET", url);
    F(&req);
    return do(session, req);
}

fn post<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("POST", url);
    F(&req);
    return do(session, req);
}

fn put<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("PUT", url);
    F(&req);
    return do(session, req);
}

fn delete(session: Session&, url: const u8[:]) -> Response, Error {
    let req = new_request("DELETE", url);
    return do(session, req);
}

fn delete<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("DELETE", url);
    F(&req);
    return do(session, req);
}

// Executes an HTTP QUERY request (RFC 10008 Section 2).
// Servers MUST fail the request if Content-Type is missing or inconsistent.
fn query(session: Session&, url: const u8[:], body: const u8[:], content_type: const u8[:]) -> Response, Error {
    var req = new_query(url, body, content_type);
    return do(session, req);
}

fn query<F: fn(Request&)>(
    session:      Session&,
    url:          const u8[:],
    body:         const u8[:],
    content_type: const u8[:],
) -> Response, Error {
    var req = new_query(url, body, content_type);
    F(&req);
    return do(session, req);
}

// ---- chunked uploads and download streaming --------------------------------

fn post_chunked<F: fn(ChunkWriter&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var writer = ChunkWriter { .. };
    F(&writer);
    finish_chunk_writer(writer);

    var req = new_request("POST", url);
    set_header(req, "Transfer-Encoding", "chunked");
    req.body_prechunked = true;
    req.body.append(writer.buffer[..]);
    req.rewindable = req.rewind_buf.try_set(writer.buffer[..]);
    return do(session, req);
}

fn download_stream<F: fn(const StreamProgress&)>(
    session:    Session&,
    url:        const u8[:],
    chunk_size: i64,
    out_body:   u8[>..]&,
) -> Response, Error {
    out_body.clear();
    let resp, err = get(session, url);
    guard ok(err) else { return resp, err; }

    var reader = new_stream_reader(resp);
    var chunk_buf: u8[>..] = [];

    loop {
        let st, is_eof = read_chunk(reader, chunk_size, chunk_buf);
        if st == StreamReadStatus.Error {
            out_body.clear();
            var resp_err = resp;
            let err = make_error(
                rfc::STATUS_BAD_GATEWAY, "stream", "chunked stream decode failure", ErrorKind.Stream,
            );
            return copy(resp_err), err;
        }
        if st == StreamReadStatus.Data {
            out_body.append(chunk_buf[..]);
            let p = stream_progress(reader);
            F(&p);
        }
        if is_eof || st == StreamReadStatus.Eof {
            break;
        }
    }
    var resp_out = resp;
    copy_trailers_to_response(reader, resp_out);
    return copy(resp_out), Error { .. };
}

// ---- realtime & streaming (aoni-style ergonomics) -------------------------

// Normalizes ws:// and wss:// into http:// and https:// for HTTP pipeline
fn normalize_realtime_url(url: const u8[:], out: u8[..2048]&) {
    out.clear();
    if url.starts_with_fold("ws://") {
        let _ = out.try_append("http://");
        let _ = out.try_append(url[5..]);
    } else if url.starts_with_fold("wss://") {
        let _ = out.try_append("https://");
        let _ = out.try_append(url[6..]);
    } else {
        let _ = out.try_append(url);
    }
}

// Checks whether a comma-separated header value contains the target token (case-insensitive).
//
// Example:
//   hdr = "gzip, deflate, br", token = "deflate"
//   returns: true
fn header_has_token(hdr: const u8[:], token: const u8[:]) -> bool {
    var offset: i64 = 0;
    while offset < hdr.len {
        let comma = hdr[offset..].index_of_byte(',');
        let token_end = if comma >= 0 { offset + comma } else { hdr.len };
        let tok = hdr[offset..token_end].trim_lws();
        if tok.eq_ascii_fold(token) {
            return true;
        }
        offset = token_end + 1;
    }
    return false;
}

fn ws_perform_handshake(
    session:    Session&,
    req:        Request&,
    client_key: const u8[:],
) -> WebSocketSession, Response, Error {
    let resp, err = do(session, req);
    guard ok(err) else {
        return new_websocket_session(true), resp, err;
    }

    // Validate 101 Switching Protocols (RFC 6455 Section 4.2.2, RFC 9931 Section 3)
    if resp.status_code != rfc::STATUS_SWITCHING_PROTOCOLS {
        return new_websocket_session(true), resp, make_error(
            resp.status_code,
            "websocket_handshake",
            "server did not return 101 Switching Protocols",
        );
    }

    // Validate Upgrade: websocket (RFC 6455 §4.2.2)
    let upg = header(resp, "Upgrade");
    if !header_has_token(upg, "websocket") {
        return new_websocket_session(true), resp, make_error(
            rfc::STATUS_BAD_REQUEST,
            "websocket_handshake",
            "missing or invalid Upgrade header in server response",
        );
    }

    // Validate Connection header contains Upgrade
    let conn = header(resp, "Connection");
    if !header_has_token(conn, "upgrade") {
        return new_websocket_session(true), resp, make_error(
            rfc::STATUS_BAD_REQUEST,
            "websocket_handshake",
            "missing Connection: Upgrade header in server response",
        );
    }

    // Validate Sec-WebSocket-Accept
    let server_accept = header(resp, "Sec-WebSocket-Accept");
    if !validate_websocket_accept(client_key, server_accept) {
        return new_websocket_session(true), resp, make_error(
            rfc::STATUS_BAD_REQUEST,
            "websocket_handshake",
            "invalid Sec-WebSocket-Accept key in server response",
        );
    }

    var ws_sess = new_websocket_session(true);
    let proto = header(resp, "Sec-WebSocket-Protocol");
    if proto.len > 0 {
        let req_proto = header(req, "Sec-WebSocket-Protocol");
        let valid_proto = req_proto.len > 0 &&
            !proto.contains_byte(',') &&
            has_subprotocol_token(req_proto, proto) &&
            ws_sess.subprotocol.try_set(proto);
        if !valid_proto {
            return new_websocket_session(true), resp, make_error(
                rfc::STATUS_BAD_REQUEST,
                "websocket_handshake",
                "server returned Sec-WebSocket-Protocol not offered by client",
            );
        }
    }

    return ws_sess, resp, Error { .. };
}

// Initiates a WebSocket connection with automatic RFC 6455 handshake negotiation
fn ws(session: Session&, url: const u8[:]) -> WebSocketSession, Response, Error {
    var eff_url: u8[..2048] = [];
    normalize_realtime_url(url, eff_url);

    var req = new_request("GET", eff_url[..]);
    set_header(req, "Upgrade", "websocket");
    set_header(req, "Connection", "Upgrade");
    set_header(req, "Sec-WebSocket-Version", "13");

    var nonce: u8[16] = [0; 16];
    let _ = native_crypto_random_bytes(nonce[..]);
    var seed: u64 = (session.virtual_clock_us as u64) ^ session.creds.nonce_counter ^ 0x5DEECE66D;
    for &b in nonce {
        seed ^= core::shl_sat_u64(seed, 13);
        seed ^= seed >> 7;
        seed ^= core::shl_sat_u64(seed, 17);
        b ^= (seed & 0xFF) as u8;
    }
    session.creds.nonce_counter = core::add_sat_u64(session.creds.nonce_counter, 1) as u32;
    var client_key: u8[..32] = [];
    generate_websocket_key(nonce, client_key);
    set_header(req, "Sec-WebSocket-Key", client_key[..]);

    return ws_perform_handshake(session, req, client_key[..]);
}

// Initiates a WebSocket connection with custom request configuration
fn ws<F: fn(Request&)>(session: Session&, url: const u8[:]) -> WebSocketSession, Response, Error {
    var eff_url: u8[..2048] = [];
    normalize_realtime_url(url, eff_url);

    var req = new_request("GET", eff_url[..]);
    set_header(req, "Upgrade", "websocket");
    set_header(req, "Connection", "Upgrade");
    set_header(req, "Sec-WebSocket-Version", "13");

    var nonce: u8[16] = [0; 16];
    let _ = native_crypto_random_bytes(nonce[..]);
    var seed: u64 = (session.virtual_clock_us as u64) ^ (session.creds.nonce_counter as u64) ^ 0x5DEECE66D;
    for &b in nonce {
        seed ^= core::shl_sat_u64(seed, 13);
        seed ^= seed >> 7;
        seed ^= core::shl_sat_u64(seed, 17);
        b ^= (seed & 0xFF) as u8;
    }
    session.creds.nonce_counter = core::add_sat_u64(session.creds.nonce_counter, 1) as u32;
    var client_key: u8[..32] = [];
    generate_websocket_key(nonce, client_key);
    set_header(req, "Sec-WebSocket-Key", client_key[..]);

    F(&req);

    let eff_key = header(req, "Sec-WebSocket-Key");
    return ws_perform_handshake(session, req, if eff_key.len > 0 { eff_key } else { client_key[..] });
}

fn is_sse_content_type(ct: const u8[:]) -> bool {
    guard ct.starts_with_fold("text/event-stream") else { return false; }
    guard ct.len == 17 || ct[17] == ';' || ct[17] == ' ' || ct[17] == '\t' else { return false; }
    return true;
}

fn sse_perform_connect(
    session: Session&,
    sub:     SseSubscription,
    req:     Request&,
) -> SseSubscription, Response, Error {
    var eff_sub = sub;
    let resp, err = do(session, req);
    guard ok(err) else {
        return eff_sub, resp, err;
    }

    if resp.status_code != rfc::STATUS_OK {
        return eff_sub, resp, make_error(
            resp.status_code,
            "sse_connect",
            "server returned non-200 status for SSE stream",
        );
    }

    let ct = header(resp, "Content-Type");
    if !is_sse_content_type(ct) {
        return eff_sub, resp, make_error(
            rfc::STATUS_UNSUPPORTED_MEDIA_TYPE,
            "sse_connect",
            "server response is not text/event-stream",
        );
    }

    eff_sub.connected = true;
    return eff_sub, resp, Error { .. };
}

// Initiates a Server-Sent Events (SSE) stream subscription per W3C EventSource
fn sse(session: Session&, url: const u8[:]) -> SseSubscription, Response, Error {
    var sub = new_sse_subscription(url);
    var req = new_request("GET", url);
    sub.prepare_request(req);
    return sse_perform_connect(session, sub, req);
}

// Initiates an SSE stream subscription with custom request configuration
fn sse<F: fn(Request&)>(session: Session&, url: const u8[:]) -> SseSubscription, Response, Error {
    var sub = new_sse_subscription(url);
    var req = new_request("GET", url);
    sub.prepare_request(req);
    F(&req);
    return sse_perform_connect(session, sub, req);
}

// Reconnects an existing SSE subscription with Last-Event-ID
fn sse_reconnect(session: Session&, sub: SseSubscription&) -> Response, Error {
    var dummy_events: SseEvent[..1] = [];
    sse_flush(sub.parser, dummy_events);
    let eff_url = if sub.url.len > 0 { sub.url[..] } else { "" };
    var req = new_request("GET", eff_url);
    sub.prepare_request(req);

    let resp, err = do(session, req);
    guard ok(err) else {
        sub.connected = false;
        return resp, err;
    }

    if resp.status_code != rfc::STATUS_OK {
        sub.connected = false;
        return resp, make_error(
            resp.status_code,
            "sse_reconnect",
            "server returned non-200 status during reconnection",
        );
    }

    let ct = header(resp, "Content-Type");
    if !is_sse_content_type(ct) {
        sub.connected = false;
        return resp, make_error(
            rfc::STATUS_UNSUPPORTED_MEDIA_TYPE,
            "sse_reconnect",
            "server response is not text/event-stream",
        );
    }

    sub.connected = true;
    return resp, Error { .. };
}

// ---- masque connect-udp & connect-ip tunnels (rfc 9298, rfc 9484) -----------

inline fn is_masque_reg_name_char(b: u8) -> bool {
    return core::is_uri_unreserved(b) ||
           b == '!' || b == '$' || b == '&' || b == '\'' ||
           b == '(' || b == ')' || b == '*' || b == '+' ||
           b == ',' || b == ';' || b == '=';
}

inline fn append_masque_ipv6_encoded(v6_raw: const u8[:], out_host: u8[..128]&) -> bool {
    var comp_v6: u8[..64] = [];
    guard core::parse_and_compress_ipv6(v6_raw, comp_v6) else { return false; }
    for b in v6_raw {
        let ok_b = if b == ':' { out_host.try_append("%3A") } else { out_host.try_push(b) };
        guard ok_b else { return false; }
    }
    return true;
}

// Normalizes a MASQUE target host by stripping IPv6 brackets and percent-encoding ':' as '%3A' (RFC 9298 §2).
//
// Example:
//   target_host = "[2001:db8::1]"
//   returns: out_host = "2001%3Adb8%3A%3A1", ok = true
fn encode_masque_target_host(target_host: const u8[:], out_host: u8[..128]&) -> bool {
    guard target_host.len > 0 && !target_host.contains_byte('%') else { return false; }
    let saved_len = out_host.len;
    var committed = false;
    defer if !committed { out_host.resize(saved_len); };
    out_host.clear();

    if core::starts_with(target_host, "[") || core::ends_with(target_host, "]") {
        let after_l, ok_l = target_host.strip_prefix("[");
        let inner, ok_r = after_l.strip_suffix("]");
        guard ok_l && ok_r && inner.len >= 2 && append_masque_ipv6_encoded(inner, out_host) else {
            return false;
        }
        committed = true;
        return true;
    }

    if target_host.contains_byte(':') {
        guard append_masque_ipv6_encoded(target_host, out_host) else { return false; }
        committed = true;
        return true;
    }

    for b in target_host {
        guard is_masque_reg_name_char(b) else { return false; }
    }
    guard out_host.try_set(target_host) else { return false; }
    committed = true;
    return true;
}

fn connect_udp(
    session:       Session&,
    proxy_url:     const u8[:],
    target_host:   const u8[:],
    target_port:   u16,
    stream_id:     u64  = 0,
    use_datagrams: bool = true,
) -> MasqueTunnelSession, Response, Error {
    var enc_host: u8[..128] = [];
    guard encode_masque_target_host(target_host, enc_host) else {
        var bad_tun = MasqueTunnelSession { state: MasqueTunnelState.Failed, .. };
        return bad_tun, Response { .. }, make_error(rfc::STATUS_BAD_REQUEST, "masque", "target_host exceeds capacity");
    }
    var tunnel = new_connect_udp_tunnel(proxy_url, enc_host[..], target_port, stream_id, use_datagrams);
    tunnel.state = MasqueTunnelState.Connecting;

    var req_path:    u8[..256] = [];
    var req_headers: HeaderMap = HeaderMap { .. };
    build_masque_connect_request(tunnel, req_headers, req_path);

    var full_url: u8[..2048] = [];
    guard proxy_url.len > 0 && proxy_url.len <= 256 &&
          enc_host.len > 0 && enc_host.len <= 128 &&
          target_port > 0 &&
          proxy_url.len + req_path.len <= full_url.cap else {
        tunnel.state = MasqueTunnelState.Failed;
        return tunnel, Response { .. }, make_error(rfc::STATUS_BAD_REQUEST, "masque", "proxy_url exceeds capacity");
    }
    full_url.append(proxy_url);
    if full_url.len > 0 && full_url[full_url.len - 1] == '/' {
        full_url.pop();
    }
    full_url.append(req_path[..]);

    var req = new_request("CONNECT", full_url[..]);
    for &e in req_headers.entries {
        set_header(req, entry_name(req_headers, e), entry_value(req_headers, e));
    }

    let resp, err = do(session, req);
    if !ok(err) || !is_success(resp) {
        tunnel.state = MasqueTunnelState.Failed;
        let ret_err = if !ok(err) {
            err
        } else {
            make_error(resp.status_code, "masque", "proxy rejected CONNECT-UDP")
        };
        return tunnel, resp, ret_err;
    }

    let caps_val = header(resp, "capsule-protocol");
    if !is_capsule_protocol_negotiated(caps_val) {
        tunnel.state = MasqueTunnelState.Failed;
        return tunnel, resp, make_error(rfc::STATUS_BAD_GATEWAY, "masque", "proxy missing required Capsule-Protocol: ?1 header");
    }

    tunnel.state = MasqueTunnelState.Established;
    return tunnel, resp, Error { .. };
}

fn connect_ip(
    session:       Session&,
    proxy_url:     const u8[:],
    stream_id:     u64  = 0,
    use_datagrams: bool = true,
) -> MasqueTunnelSession, Response, Error {
    var tunnel = new_connect_ip_tunnel(proxy_url, stream_id, use_datagrams);
    tunnel.state = MasqueTunnelState.Connecting;

    var req_path:    u8[..256] = [];
    var req_headers: HeaderMap = HeaderMap { .. };
    build_masque_connect_request(tunnel, req_headers, req_path);

    var full_url: u8[..2048] = [];
    guard proxy_url.len > 0 && proxy_url.len <= 256 &&
          proxy_url.len + req_path.len <= full_url.cap else {
        tunnel.state = MasqueTunnelState.Failed;
        return tunnel, Response { .. }, make_error(rfc::STATUS_BAD_REQUEST, "masque", "proxy_url exceeds capacity");
    }
    full_url.append(proxy_url);
    if full_url.len > 0 && full_url[full_url.len - 1] == '/' {
        full_url.pop();
    }
    full_url.append(req_path[..]);

    var req = new_request("CONNECT", full_url[..]);
    for &e in req_headers.entries {
        set_header(req, entry_name(req_headers, e), entry_value(req_headers, e));
    }

    let resp, err = do(session, req);
    if !ok(err) || !is_success(resp) {
        tunnel.state = MasqueTunnelState.Failed;
        let ret_err = if !ok(err) {
            err
        } else {
            make_error(resp.status_code, "masque", "proxy rejected CONNECT-IP")
        };
        return tunnel, resp, ret_err;
    }

    let caps_val = header(resp, "capsule-protocol");
    if !is_capsule_protocol_negotiated(caps_val) {
        tunnel.state = MasqueTunnelState.Failed;
        return tunnel, resp, make_error(rfc::STATUS_BAD_GATEWAY, "masque", "proxy missing required Capsule-Protocol: ?1 header");
    }

    tunnel.state = MasqueTunnelState.Established;
    return tunnel, resp, Error { .. };
}
