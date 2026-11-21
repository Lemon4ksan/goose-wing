// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// High-level HTTP verbs, streaming uploads/downloads, and realtime protocol sessions (WebSocket, SSE, MASQUE).
namespace client;

import std;
import core;
import rfc.http;
import http.request;
import http.response;
import http.headers;
import client.stream;
import realtime.websocket;
import realtime.sse;
import net.masque;
import client.client;
import client.session.exec;
import .internal;

// ---- high-level dispatch entry points --------------------------------------

fn do(session: Session&, req: const http::Request&) -> http::Response, http::Error {
    return execute_request(session, req);
}

// Last-mile closure overload: clones `req`, applies `F(&copy_req)`, and dispatches.
fn do<F: fn(http::Request&)>(session: Session&, req: const http::Request&) -> http::Response, http::Error {
    var modified = copy(req);
    F(&modified);
    return do(session, modified);
}

// ---- okhttp/tower-style interceptor execution ------------------------------

struct InterceptorChain {
    request:         http::Request&,
    response:        http::Response&,
    err:             http::Error = http::Error { .. },
    proceeded:       bool        = false,
    short_circuited: bool        = false,
}

fn proceed(chain: InterceptorChain&, session: Session&) {
    chain.proceeded = true;
    let resp, err = execute_request(session, chain.request);
    chain.response = copy(resp);
    chain.err = err;
}

fn do_intercepted<F: fn(InterceptorChain&, Session&)>(
    session: Session&,
    req:     const http::Request&,
) -> http::Response, http::Error {
    var req_copy = copy(req);
    var resp = http::Response { .. };
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

fn get(session: Session&, url: const u8[:]) -> http::Response, http::Error {
    let req = http::new_request("GET", url);
    return do(session, req);
}

fn get<F: fn(http::Request&)>(session: Session&, url: const u8[:]) -> http::Response, http::Error {
    var req = http::new_request("GET", url);
    F(&req);
    return do(session, req);
}

fn post<F: fn(http::Request&)>(session: Session&, url: const u8[:]) -> http::Response, http::Error {
    var req = http::new_request("POST", url);
    F(&req);
    return do(session, req);
}

fn put<F: fn(http::Request&)>(session: Session&, url: const u8[:]) -> http::Response, http::Error {
    var req = http::new_request("PUT", url);
    F(&req);
    return do(session, req);
}

fn delete(session: Session&, url: const u8[:]) -> http::Response, http::Error {
    let req = http::new_request("DELETE", url);
    return do(session, req);
}

fn delete<F: fn(http::Request&)>(session: Session&, url: const u8[:]) -> http::Response, http::Error {
    var req = http::new_request("DELETE", url);
    F(&req);
    return do(session, req);
}

// Executes an HTTP QUERY request (RFC 10008 Section 2).
// Servers MUST fail the request if Content-Type is missing or inconsistent.
fn query(
    session:      Session&,
    url:          const u8[:],
    body:         const u8[:],
    content_type: const u8[:],
) -> http::Response, http::Error {
    var req = http::new_query(url, body, content_type);
    return do(session, req);
}

fn query<F: fn(http::Request&)>(
    session:      Session&,
    url:          const u8[:],
    body:         const u8[:],
    content_type: const u8[:],
) -> http::Response, http::Error {
    var req = http::new_query(url, body, content_type);
    F(&req);
    return do(session, req);
}

// ---- chunked uploads and download streaming --------------------------------

fn post_chunked<F: fn(ChunkWriter&)>(session: Session&, url: const u8[:]) -> http::Response, http::Error {
    var writer = ChunkWriter { .. };
    F(&writer);
    finish_chunk_writer(writer);

    var req = http::new_request("POST", url);
    http::set_header(req, "Transfer-Encoding", "chunked");
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
) -> http::Response, http::Error {
    var resp, err = get(session, url);
    guard http::ok(err) else { return resp, err; }

    out_body.clear();
    var reader = new_stream_reader(resp);
    var chunk_buf: u8[>..] = [];

    loop {
        let st, is_eof = read_chunk(reader, chunk_size, chunk_buf);
        if st == StreamReadStatus.Error {
            out_body.clear();
            let s_err = http::make_error(
                rfc::STATUS_BAD_GATEWAY, "stream", "chunked stream decode failure", http::ErrorKind.Stream,
            );
            return resp, s_err;
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
    copy_trailers_to_response(reader, resp);
    return resp, http::Error { .. };
}

// ---- realtime & streaming (WebSocket, SSE) ---------------------------------

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

// Initiates a WebSocket connection with automatic RFC 6455 handshake negotiation.
fn ws(session: Session&, url: const u8[:]) -> realtime::WebSocketSession, http::Response, http::Error {
    var client_key: u8[..32] = [];
    var req = client_internal::prepare_ws_upgrade_request(session, url, client_key);
    return client_internal::ws_perform_handshake(session, req, client_key[..]);
}

// Initiates a WebSocket connection with custom request configuration.
fn ws<F: fn(http::Request&)>(
    session: Session&,
    url:     const u8[:],
) -> realtime::WebSocketSession, http::Response, http::Error {
    var client_key: u8[..32] = [];
    var req = client_internal::prepare_ws_upgrade_request(session, url, client_key);
    F(&req);
    let eff_key = http::header(req, "Sec-WebSocket-Key");
    return client_internal::ws_perform_handshake(session, req, if eff_key.len > 0 { eff_key } else { client_key[..] });
}

fn is_sse_content_type(ct: const u8[:]) -> bool {
    guard ct.starts_with_fold("text/event-stream") else { return false; }
    return ct.len == 17 || ct[17] == ';' || ct[17] == ' ' || ct[17] == '\t';
}

// Initiates a Server-Sent Events (SSE) stream subscription per W3C EventSource.
fn sse(session: Session&, url: const u8[:]) -> realtime::SseSubscription, http::Response, http::Error {
    var sub = realtime::new_sse_subscription(url);
    var req = http::new_request("GET", url);
    sub.prepare_request(req);
    return client_internal::sse_perform_connect(session, sub, req);
}

// Initiates an SSE stream subscription with custom request configuration.
fn sse<F: fn(http::Request&)>(
    session: Session&,
    url:     const u8[:],
) -> realtime::SseSubscription, http::Response, http::Error {
    var sub = realtime::new_sse_subscription(url);
    var req = http::new_request("GET", url);
    sub.prepare_request(req);
    F(&req);
    return client_internal::sse_perform_connect(session, sub, req);
}

// ---- masque connect-udp & connect-ip tunnels (rfc 9298, rfc 9484) -----------

fn connect_udp(
    session:       Session&,
    proxy_url:     const u8[:],
    target_host:   const u8[:],
    target_port:   u16,
    stream_id:     u64  = 0,
    use_datagrams: bool = true,
) -> net::MasqueTunnelSession, http::Response, http::Error {
    var enc_host: u8[..128] = [];
    guard client_internal::encode_masque_target_host(target_host, enc_host) else {
        var bad_tun = net::MasqueTunnelSession { state: net::MasqueTunnelState.Failed, .. };
        return bad_tun, http::Response { .. }, http::make_error(
            rfc::STATUS_BAD_REQUEST, "masque", "target_host exceeds capacity",
        );
    }
    var tunnel = net::new_connect_udp_tunnel(proxy_url, enc_host[..], target_port, stream_id, use_datagrams);
    guard enc_host.len > 0 && enc_host.len <= 128 && target_port > 0 else {
        tunnel.state = net::MasqueTunnelState.Failed;
        return tunnel, http::Response { .. }, http::make_error(
            rfc::STATUS_BAD_REQUEST, "masque", "proxy_url exceeds capacity",
        );
    }
    return client_internal::execute_masque_connect(session, tunnel, proxy_url, "proxy rejected CONNECT-UDP");
}

fn connect_ip(
    session:       Session&,
    proxy_url:     const u8[:],
    stream_id:     u64  = 0,
    use_datagrams: bool = true,
) -> net::MasqueTunnelSession, http::Response, http::Error {
    var tunnel = net::new_connect_ip_tunnel(proxy_url, stream_id, use_datagrams);
    return client_internal::execute_masque_connect(session, tunnel, proxy_url, "proxy rejected CONNECT-IP");
}
