// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// High-level HTTP verbs, streaming uploads/downloads, and realtime protocol sessions (WebSocket, SSE, MASQUE).
namespace wing;

import std;
import client.request;
import client.response;
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
    request: Request&,
    response: Response&,
    err: Error = Error { .. },
    proceeded: bool = false,
    short_circuited: bool = false,
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
        request: req_copy,
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

fn post_json<T>(session: Session&, url: const u8[:], payload: const T&) -> Response, Error {
    var req = new_request("POST", url);
    json(req, payload);
    return do(session, req);
}

fn put<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("PUT", url);
    F(&req);
    return do(session, req);
}

fn put_json<T>(session: Session&, url: const u8[:], payload: const T&) -> Response, Error {
    var req = new_request("PUT", url);
    json(req, payload);
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

// ---- chunked uploads and download streaming --------------------------------

fn post_chunked<F: fn(ChunkWriter&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var writer = ChunkWriter { .. };
    F(&writer);
    finish_chunk_writer(writer);

    var req = new_request("POST", url);
    req.headers.push(make_header("Transfer-Encoding", "chunked"));
    req.body.append(writer.buffer[..]);
    return do(session, req);
}

fn put_chunked<F: fn(ChunkWriter&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var writer = ChunkWriter { .. };
    F(&writer);
    finish_chunk_writer(writer);

    var req = new_request("PUT", url);
    req.headers.push(make_header("Transfer-Encoding", "chunked"));
    req.body.append(writer.buffer[..]);
    return do(session, req);
}

fn download_stream<F: fn(const StreamProgress&)>(
    session: Session&,
    url: const u8[:],
    chunk_size: i64,
    out_body: u8[>..]&,
) -> Response, Error {
    let resp, err = get(session, url);
    guard ok(err) else { return resp, err; }

    var reader = new_stream_reader(resp);
    var chunk_buf: u8[>..] = [];

    while true {
        let has_data, is_eof = read_chunk(reader, chunk_size, chunk_buf);
        if has_data {
            out_body.append(chunk_buf[..]);
            let p = stream_progress(reader);
            F(&p);
        }
        if is_eof {
            break;
        }
    }
    return resp, Error { .. };
}

// ---- realtime & streaming (aoni-style ergonomics) -------------------------

// Normalizes ws:// and wss:// into http:// and https:// for HTTP pipeline
fn normalize_realtime_url(url: const u8[:], out: u8[..2048]&) {
    out.clear();
    if starts_with(url, "ws://") {
        out.append("http://");
        out.append(url[5..]);
    } else if starts_with(url, "wss://") {
        out.append("https://");
        out.append(url[6..]);
    } else {
        out.append(url);
    }
}

fn connection_has_upgrade(conn: const u8[:]) -> bool {
    if eq_ascii_fold(conn, "upgrade") { return true; }
    guard conn.len >= 7 else { return false; }
    for t in 0..conn.len - 6 {
        if eq_ascii_fold(conn[t..t + 7], "upgrade") {
            return true;
        }
    }
    return false;
}

fn ws_perform_handshake(
    session: Session&,
    req: Request&,
    client_key: const u8[:],
) -> WebSocketSession, Response, Error {
    let resp, err = do(session, req);
    guard ok(err) else {
        return new_websocket_session(true), resp, err;
    }

    // Validate 101 Switching Protocols
    if resp.status_code != 101 {
        return new_websocket_session(true), resp, make_error(
            resp.status_code,
            "websocket_handshake",
            "server did not return 101 Switching Protocols",
        );
    }

    // Validate Upgrade: websocket
    let upg = header(resp, "Upgrade");
    if !eq_ascii_fold(upg, "websocket") {
        return new_websocket_session(true), resp, make_error(
            400,
            "websocket_handshake",
            "missing or invalid Upgrade header in server response",
        );
    }

    // Validate Connection header contains Upgrade
    let conn = header(resp, "Connection");
    if !connection_has_upgrade(conn) {
        return new_websocket_session(true), resp, make_error(
            400,
            "websocket_handshake",
            "missing Connection: Upgrade header in server response",
        );
    }

    // Validate Sec-WebSocket-Accept
    let server_accept = header(resp, "Sec-WebSocket-Accept");
    if !validate_websocket_accept(client_key, server_accept) {
        return new_websocket_session(true), resp, make_error(
            400,
            "websocket_handshake",
            "invalid Sec-WebSocket-Accept key in server response",
        );
    }

    var ws_sess = new_websocket_session(true);
    let proto = header(resp, "Sec-WebSocket-Protocol");
    if proto.len > 0 {
        ws_sess.subprotocol.append(proto);
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
    var seed: u64 = (session.virtual_clock_us as u64) ^ 0x5DEECE66D;
    for i in 16 {
        seed = seed * 6364136223846793005 + 1442695040888963407;
        nonce[i] = ((seed >> 33) & 0xFF) as u8;
    }
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
    var seed: u64 = (session.virtual_clock_us as u64) ^ 0x5DEECE66D;
    for i in 16 {
        seed = seed * 6364136223846793005 + 1442695040888963407;
        nonce[i] = ((seed >> 33) & 0xFF) as u8;
    }
    var client_key: u8[..32] = [];
    generate_websocket_key(nonce, client_key);
    set_header(req, "Sec-WebSocket-Key", client_key[..]);

    F(&req);

    return ws_perform_handshake(session, req, client_key[..]);
}

fn sse_perform_connect(
    session: Session&,
    sub: SseSubscription,
    req: Request&,
) -> SseSubscription, Response, Error {
    var eff_sub = sub;
    let resp, err = do(session, req);
    guard ok(err) else {
        return eff_sub, resp, err;
    }

    if resp.status_code != 200 {
        return eff_sub, resp, make_error(
            resp.status_code,
            "sse_connect",
            "server returned non-200 status for SSE stream",
        );
    }

    let ct = header(resp, "Content-Type");
    if !starts_with(ct, "text/event-stream") {
        return eff_sub, resp, make_error(
            415,
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
    let eff_url = if sub.url.len > 0 { sub.url[..] } else { "" };
    var req = new_request("GET", eff_url);
    sub.prepare_request(req);

    let resp, err = do(session, req);
    guard ok(err) else {
        sub.connected = false;
        return resp, err;
    }

    if resp.status_code != 200 {
        sub.connected = false;
        return resp, make_error(
            resp.status_code,
            "sse_reconnect",
            "server returned non-200 status during reconnection",
        );
    }

    let ct = header(resp, "Content-Type");
    if !starts_with(ct, "text/event-stream") {
        sub.connected = false;
        return resp, make_error(
            415,
            "sse_reconnect",
            "server response is not text/event-stream",
        );
    }

    sub.connected = true;
    return resp, Error { .. };
}

// ---- masque connect-udp & connect-ip tunnels (rfc 9298, rfc 9484) -----------

fn connect_udp(
    session: Session&,
    proxy_url: const u8[:],
    target_host: const u8[:],
    target_port: u16,
    stream_id: u64 = 0,
    use_datagrams: bool = true,
) -> MasqueTunnelSession, Response, Error {
    var tunnel = new_connect_udp_tunnel(proxy_url, target_host, target_port, stream_id, use_datagrams);
    tunnel.state = MasqueTunnelState.Connecting;

    var req_path: u8[..256] = [];
    var req_headers: HeaderItem[..16] = [];
    build_masque_connect_request(tunnel, req_headers, req_path);

    var full_url: u8[..512] = [];
    full_url.append(proxy_url);
    if full_url.len > 0 && full_url[full_url.len - 1] == '/' {
        full_url.pop();
    }
    full_url.append(req_path[..]);

    var req = new_request("CONNECT", full_url[..]);
    for &h in req_headers {
        req.headers.push(copy(h));
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
        return tunnel, resp, make_error(502, "masque", "proxy missing required Capsule-Protocol: ?1 header");
    }

    tunnel.state = MasqueTunnelState.Established;
    return tunnel, resp, Error { .. };
}

fn connect_ip(
    session: Session&,
    proxy_url: const u8[:],
    stream_id: u64 = 0,
    use_datagrams: bool = true,
) -> MasqueTunnelSession, Response, Error {
    var tunnel = new_connect_ip_tunnel(proxy_url, stream_id, use_datagrams);
    tunnel.state = MasqueTunnelState.Connecting;

    var req_path: u8[..256] = [];
    var req_headers: HeaderItem[..16] = [];
    build_masque_connect_request(tunnel, req_headers, req_path);

    var full_url: u8[..512] = [];
    full_url.append(proxy_url);
    if full_url.len > 0 && full_url[full_url.len - 1] == '/' {
        full_url.pop();
    }
    full_url.append(req_path[..]);

    var req = new_request("CONNECT", full_url[..]);
    for &h in req_headers {
        req.headers.push(copy(h));
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
        return tunnel, resp, make_error(502, "masque", "proxy missing required Capsule-Protocol: ?1 header");
    }

    tunnel.state = MasqueTunnelState.Established;
    return tunnel, resp, Error { .. };
}
