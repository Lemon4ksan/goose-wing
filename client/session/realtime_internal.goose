// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal WebSocket upgrade handshake, SSE connection setup, and MASQUE tunnel CONNECT helpers.
namespace client_internal;

import std;
import core;
import rfc.http;
import http.request;
import http.response;
import http.headers;
import realtime.websocket;
import realtime.sse;
import net.masque;
import client.client;
import .verbs;

fn normalize_realtime_url<B>(url: const u8[:], out: B&) {
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

fn prepare_ws_upgrade_request<B>(
    session:        client::Session&,
    url:            const u8[:],
    out_client_key: B&,
) -> http::Request, bool {
    var eff_url: u8[..2048] = [];
    normalize_realtime_url(url, eff_url);

    var req = http::new_request("GET", eff_url[..]);
    http::set_header(req, "Upgrade", "websocket");
    http::set_header(req, "Connection", "Upgrade");
    http::set_header(req, "Sec-WebSocket-Version", "13");

    var nonce: u8[16] = [0; 16];
    defer core::secure_zeroize_16(nonce);
    let got_rng = if core::sim_rng_is_active() {
        core::sim_rng_fill(nonce[..])
    } else {
        core::csprng_fill(nonce[..])
    };
    guard got_rng else {
        out_client_key.clear();
        return req, false;
    }
    session.creds.nonce_counter = core::add_sat_u64(session.creds.nonce_counter as u64, 1) as u32;
    out_client_key.clear();
    realtime::generate_websocket_key(nonce, out_client_key);
    http::set_header(req, "Sec-WebSocket-Key", out_client_key[..]);
    return req, true;
}

fn ws_perform_handshake(
    session:    client::Session&,
    req:        http::Request&,
    client_key: const u8[:],
) -> realtime::WebSocketSession, http::Response, http::Error {
    let resp, err = client::do(session, req);
    guard http::ok(err) else {
        return realtime::new_websocket_session(true), resp, err;
    }

    // Validate 101 Switching Protocols (RFC 6455 Section 4.2.2, RFC 9931 Section 3).
    if resp.status_code != rfc::STATUS_SWITCHING_PROTOCOLS {
        return realtime::new_websocket_session(true), resp, http::make_error(
            resp.status_code,
            "websocket_handshake",
            "server did not return 101 Switching Protocols",
        );
    }

    let upg = http::header(resp, "Upgrade");
    if !client::header_has_token(upg, "websocket") {
        return realtime::new_websocket_session(true), resp, http::make_error(
            rfc::STATUS_BAD_REQUEST,
            "websocket_handshake",
            "missing or invalid Upgrade header in server response",
        );
    }

    let conn = http::header(resp, "Connection");
    if !client::header_has_token(conn, "upgrade") {
        return realtime::new_websocket_session(true), resp, http::make_error(
            rfc::STATUS_BAD_REQUEST,
            "websocket_handshake",
            "missing Connection: Upgrade header in server response",
        );
    }

    let server_accept = http::header(resp, "Sec-WebSocket-Accept");
    if !realtime::validate_websocket_accept(client_key, server_accept) {
        return realtime::new_websocket_session(true), resp, http::make_error(
            rfc::STATUS_BAD_REQUEST,
            "websocket_handshake",
            "invalid Sec-WebSocket-Accept key in server response",
        );
    }

    var ws_sess = realtime::new_websocket_session(true);
    let proto = http::header(resp, "Sec-WebSocket-Protocol");
    if proto.len > 0 {
        let req_proto = http::header(req, "Sec-WebSocket-Protocol");
        let valid_proto = req_proto.len > 0 &&
            !proto.contains_byte(',') &&
            realtime::has_subprotocol_token(req_proto, proto) &&
            ws_sess.subprotocol.try_set(proto);
        if !valid_proto {
            return realtime::new_websocket_session(true), resp, http::make_error(
                rfc::STATUS_BAD_REQUEST,
                "websocket_handshake",
                "server returned Sec-WebSocket-Protocol not offered by client",
            );
        }
    }

    return ws_sess, resp, http::Error { .. };
}

fn sse_perform_connect(
    session: client::Session&,
    sub:     const realtime::SseSubscription&,
    req:     http::Request&,
) -> realtime::SseSubscription, http::Response, http::Error {
    var eff_sub = sub;
    let resp, err = client::do(session, req);
    guard http::ok(err) else {
        return eff_sub, resp, err;
    }

    if resp.status_code != rfc::STATUS_OK {
        return eff_sub, resp, http::make_error(
            resp.status_code,
            "sse_connect",
            "server returned non-200 status for SSE stream",
        );
    }

    let ct = http::header(resp, "Content-Type");
    if !client::is_sse_content_type(ct) {
        return eff_sub, resp, http::make_error(
            rfc::STATUS_UNSUPPORTED_MEDIA_TYPE,
            "sse_connect",
            "server response is not text/event-stream",
        );
    }

    eff_sub.connected = true;
    return eff_sub, resp, http::Error { .. };
}

inline fn is_masque_reg_name_char(b: u8) -> bool {
    return core::is_uri_unreserved(b) ||
           b == '!' || b == '$' || b == '&' || b == '\'' ||
           b == '(' || b == ')' || b == '*' || b == '+' ||
           b == ',' || b == ';' || b == '=';
}

inline fn append_masque_ipv6_encoded<B>(v6_raw: const u8[:], out: B&) -> bool {
    var comp_v6: u8[..64] = [];
    guard core::parse_and_compress_ipv6(v6_raw, comp_v6) else { return false; }
    for b in v6_raw {
        let ok_b = if b == ':' { out.try_append("%3A") } else { out.try_push(b) };
        guard ok_b else { return false; }
    }
    return true;
}

// Normalizes a MASQUE target host by stripping IPv6 brackets and percent-encoding ':' as '%3A' (RFC 9298 Section 2).
//
// Example:
//   target_host = "[2001:db8::1]"
//   returns: out = "2001%3Adb8%3A%3A1", ok = true
fn encode_masque_target_host<B>(target_host: const u8[:], out: B&) -> bool {
    guard target_host.len > 0 && !target_host.contains_byte('%') else { return false; }
    var committed = false;
    defer if !committed { out.clear(); };
    out.clear();

    if core::starts_with(target_host, "[") || core::ends_with(target_host, "]") {
        let after_l, ok_l = target_host.strip_prefix("[");
        let inner, ok_r = after_l.strip_suffix("]");
        guard ok_l && ok_r && inner.len >= 2 && append_masque_ipv6_encoded(inner, out) else {
            return false;
        }
        committed = true;
        return true;
    }

    if target_host.contains_byte(':') {
        guard append_masque_ipv6_encoded(target_host, out) else { return false; }
        committed = true;
        return true;
    }

    for b in target_host {
        guard is_masque_reg_name_char(b) else { return false; }
    }
    guard out.try_set(target_host) else { return false; }
    committed = true;
    return true;
}

fn execute_masque_connect(
    session:    client::Session&,
    tunnel:     net::MasqueTunnelSession&,
    proxy_url:  const u8[:],
    reject_msg: const u8[:],
) -> net::MasqueTunnelSession, http::Response, http::Error {
    tunnel.state = net::MasqueTunnelState.Connecting;

    var req_path:    u8[..256]       = [];
    var req_headers: http::HeaderMap = http::HeaderMap { .. };
    net::build_masque_connect_request(tunnel, req_headers, req_path);

    var full_url: u8[..2048] = [];
    guard proxy_url.len > 0 && proxy_url.len <= 256 &&
          proxy_url.len + req_path.len <= full_url.cap else {
        tunnel.state = net::MasqueTunnelState.Failed;
        return tunnel, http::Response { .. }, http::make_error(
            rfc::STATUS_BAD_REQUEST, "masque", "proxy_url exceeds capacity",
        );
    }
    full_url.append(proxy_url.trim_end_byte('/'));
    full_url.append(req_path[..]);

    var req = http::new_request("CONNECT", full_url[..]);
    for &e in req_headers.entries {
        http::set_header(req, http::entry_name(req_headers, e), http::entry_value(req_headers, e));
    }

    let resp, err = client::do(session, req);
    if !http::ok(err) || !http::is_success(resp) {
        tunnel.state = net::MasqueTunnelState.Failed;
        let ret_err = if !http::ok(err) {
            err
        } else {
            http::make_error(resp.status_code, "masque", reject_msg)
        };
        return tunnel, resp, ret_err;
    }

    let caps_val = http::header(resp, "capsule-protocol");
    if !net::is_capsule_protocol_negotiated(caps_val) {
        tunnel.state = net::MasqueTunnelState.Failed;
        return tunnel, resp, http::make_error(
            rfc::STATUS_BAD_GATEWAY, "masque", "proxy missing required Capsule-Protocol: ?1 header",
        );
    }

    tunnel.state = net::MasqueTunnelState.Established;
    return tunnel, resp, http::Error { .. };
}
