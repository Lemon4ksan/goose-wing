// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Live WebSocket (`dial_ws`) and streaming SSE (`dial_sse`) client connections over `client::Session`.
// Reuses `Session` proxy (`socks5`/`socks5h`/`http`/`https`), `trust_store`, and timeout settings.
namespace client;

import std;
import core;
import http.response;
import http.hsts;
import security.ssrf;
import net.tcp;
import net.socks5;
import net.http_connect;
import net.transport;
import tls.types;
import tls.session;
import tls.client_handshake;
import realtime.ws_handshake;
import realtime.websocket;
import realtime.ws_live;
import realtime.sse;
import .redirect;
import .client;
import .session.ssrf;
import .session.tls_hop_internal;
import .session.dns_dial_internal;

const LIVE_DEFAULT_TIMEOUT_MS: u32 = 10000;
const SSE_MAX_CHUNK_BYTES:     u64 = 65536;
const SSE_MAX_CHUNK_BUF_BYTES: i64 = 131072;

// Facade struct alias exposing `realtime::WsConn` directly under `client::WsConn`.
type WsConn = realtime::WsConn;

fn has_live_header_ctl(s: const u8[:]) -> bool {
    return core::swar_find_ctl(s) < s.len || s.contains_byte(0x7F);
}

fn resolve_live_connect_timeout_ms(sess: const Session&) -> u32 {
    if sess.connect_timeout_ms > 0 { return sess.connect_timeout_ms as u32; }
    if sess.timeout_ms > 0 { return sess.timeout_ms as u32; }
    return LIVE_DEFAULT_TIMEOUT_MS;
}

fn resolve_live_read_timeout_ms(sess: const Session&) -> u32 {
    if sess.read_timeout_ms > 0 { return sess.read_timeout_ms as u32; }
    if sess.timeout_ms > 0 { return sess.timeout_ms as u32; }
    return LIVE_DEFAULT_TIMEOUT_MS;
}

fn build_live_request_target(u: const core::Url&, out: u8[..1024]&) -> bool {
    out.clear();
    let path = u.pathname();
    if path.len > 0 {
        guard out.try_append(path) else { return false; }
    } else {
        guard out.try_push('/') else { return false; }
    }
    let q = u.search();
    if q.len > 0 {
        if q[0] != '?' { guard out.try_push('?') else { return false; } }
        guard out.try_append(q) else { return false; }
    }
    return true;
}

fn format_live_basic_auth(user: const u8[:], pass: const u8[:], out: u8[..512]&) -> bool {
    out.clear();
    var raw: u8[..384] = [];
    defer core::secure_zeroize_slice(raw[..]);
    guard raw.try_append(user) && raw.try_push(':') && raw.try_append(pass) else { return false; }
    guard out.try_append("Basic ") else { return false; }
    var b64: u8[..512] = [];
    defer core::secure_zeroize_slice(b64[..]);
    core::base64_encode(raw[..], b64);
    return out.try_append(b64[..]);
}

fn upgrade_live_tls_fd(
    fd:         i64,
    sni:        const u8[:],
    sess:       const Session&,
    timeout_ms: u32,
) -> net::Transport, bool {
    let now_sec = div_euclid(effective_clock_us(sess), 1000000);
    let tr, err = client_internal::establish_https_proxy_transport(sess, fd, sni, timeout_ms, now_sec);
    return tr, http::ok(err);
}

fn dial_live_http_connect_proxy(
    sess:        const Session&,
    pfd:         i64,
    proxy_host:  const u8[:],
    use_https:   bool,
    target_host: const u8[:],
    target_port: u16,
    pauth:       const u8[:],
    timeout_ms:  u32,
) -> i64, bool {
    if !use_https {
        let cerr = net::http_connect_client_handshake(
            pfd, target_host, target_port, pauth, "goose-wing/0.1", timeout_ms,
        );
        guard cerr == net::ConnectTunnelError.None else { net::tcp_close(pfd); return -1, false; }
        return pfd, true;
    }
    var outer_tr, ok_ot = upgrade_live_tls_fd(pfd, proxy_host, sess, timeout_ms);
    guard ok_ot else { net::tcp_close(pfd); return -1, false; }
    let cerr = net::http_connect_transport_handshake(
        outer_tr, target_host, target_port, pauth, "goose-wing/0.1", timeout_ms,
    );
    guard cerr == net::ConnectTunnelError.None else { outer_tr.close(); return -1, false; }
    let tfd, ok_tfd = net::alloc_tunnel_fd(outer_tr);
    guard ok_tfd else { outer_tr.close(); return -1, false; }
    return tfd, true;
}

// Percent-decodes optional proxy username and password fields from `purl`.
//
// Example:
//   purl = "socks5h://u%3A1:p%40ss@127.0.0.1:1080" -> returns true, out_user = "u:1", out_pass = "p@ss"
fn decode_proxy_credentials(
    purl:     const core::Url&,
    out_user: u8[..128]&,
    out_pass: u8[..256]&,
) -> bool {
    if purl.username().len > 0 && !core::percent_decode(purl.username(), out_user) {
        return false;
    }
    if purl.password().len > 0 && !core::percent_decode(purl.password(), out_pass) {
        return false;
    }
    return true;
}

fn resolve_proxy_default_port(pscheme: const u8[:], explicit_port: i32) -> u16 {
    if explicit_port > 0 && explicit_port <= 65535 { return explicit_port as u16; }
    if pscheme == "https" { return 443; }
    if pscheme == "http" { return 80; }
    return 1080;
}

fn dial_live_socks5_proxy(
    pfd:         i64,
    is_socks5h:  bool,
    target_host: const u8[:],
    target_port: u16,
    puser:       const u8[:],
    ppass:       const u8[:],
    timeout_ms:  u32,
) -> i64, bool {
    let sk = if is_socks5h { net::ProxyScheme.Socks5h } else { net::ProxyScheme.Socks5 };
    let serr = net::socks5_client_handshake(pfd, sk, target_host, target_port, puser, ppass, timeout_ms);
    guard serr == net::Socks5Error.None else { net::tcp_close(pfd); return -1, false; }
    return pfd, true;
}

fn dial_live_via_proxy(
    sess:        const Session&,
    target_host: const u8[:],
    target_port: u16,
    timeout_ms:  u32,
) -> i64, bool {
    let purl, _ = core::parse_url(sess.proxy_url[..]);
    let pscheme = purl.scheme();
    let is_socks = pscheme == "socks5" || pscheme == "socks5h";
    let is_http = pscheme == "http" || pscheme == "https";
    guard purl.valid && purl.hostname().len > 0 && (is_socks || is_http) else { return -1, false; }

    let pport = resolve_proxy_default_port(pscheme, purl.port);
    let pfd = net::tcp_connect(purl.hostname(), pport, timeout_ms);
    guard pfd > 0 else { return -1, false; }

    var puser: u8[..128] = [];
    var ppass: u8[..256] = [];
    defer core::secure_zeroize_slice(ppass[..]);
    guard decode_proxy_credentials(purl, puser, ppass) else { net::tcp_close(pfd); return -1, false; }

    if is_socks {
        return dial_live_socks5_proxy(
            pfd, pscheme == "socks5h", target_host, target_port, puser[..], ppass[..], timeout_ms,
        );
    }

    var pauth: u8[..512] = [];
    defer core::secure_zeroize_slice(pauth[..]);
    if (puser.len > 0 || ppass.len > 0) && !format_live_basic_auth(puser[..], ppass[..], pauth) {
        net::tcp_close(pfd);
        return -1, false;
    }
    return dial_live_http_connect_proxy(
        sess, pfd, purl.hostname(), pscheme == "https", target_host, target_port, pauth[..], timeout_ms,
    );
}

fn dial_live_direct_fd(
    sess:        const Session&,
    target_host: const u8[:],
    target_port: u16,
    timeout_ms:  u32,
) -> i64 {
    guard sess.ssrf_guard.enabled else {
        return net::tcp_connect(target_host, target_port, timeout_ms);
    }
    var resolved_ips: u8[..64][..16] = [];
    guard net::resolve_host_ips(target_host, resolved_ips, sess.ip_family) && resolved_ips.len > 0 else {
        return -1;
    }
    for &ip in resolved_ips {
        guard security::is_valid_resolved_ip_literal(ip[..]) &&
            !client_internal::is_ssrf_blocked_ip(sess.ssrf_guard, ip[..]) else {
            return -1;
        }
    }
    return net::tcp_connect(resolved_ips[0][..], target_port, timeout_ms);
}

fn dial_live_transport(
    sess:         const Session&,
    target_host:  const u8[:],
    target_port:  u16,
    use_tls:      bool,
    sni_override: const u8[:] = "",
) -> net::Transport, bool {
    guard use_tls || !sess.https_only else { return net::Transport.Disconnected, false; }
    let now_sec = div_euclid(effective_clock_us(sess), 1000000);
    guard use_tls || !sess.enable_hsts || !sess.hsts.is_hsts_host(target_host, now_sec) else {
        return net::Transport.Disconnected, false;
    }
    if sess.ssrf_guard.enabled {
        guard !security::is_cloud_metadata_domain(target_host) else {
            return net::Transport.Disconnected, false;
        }
        if sess.ssrf_guard.deny_local_network {
            guard !security::is_forbidden_internal_host(target_host) else {
                return net::Transport.Disconnected, false;
            }
        }
    }
    let timeout_ms = resolve_live_connect_timeout_ms(sess);
    var fd: i64 = -1;
    if sess.proxy_url.len > 0 {
        let pfd, ok_p = dial_live_via_proxy(sess, target_host, target_port, timeout_ms);
        guard ok_p && pfd > 0 else { return net::Transport.Disconnected, false; }
        fd = pfd;
    } else {
        fd = dial_live_direct_fd(sess, target_host, target_port, timeout_ms);
        guard fd > 0 else { return net::Transport.Disconnected, false; }
    }
    if !use_tls {
        return net::Transport.Tcp { fd: fd }, true;
    }
    let sni = if sni_override.len > 0 { sni_override } else { target_host };
    let tr, ok_t = upgrade_live_tls_fd(fd, sni, sess, timeout_ms);
    guard ok_t else { net::fd_close(fd); return net::Transport.Disconnected, false; }
    return tr, true;
}

fn build_ws_client_upgrade_wire(
    host:        const u8[:],
    target:      const u8[:],
    client_key:  const u8[:],
    auth_header: const u8[:],
    subprotocol: const u8[:],
    out:         u8[..2048]&,
) -> bool {
    out.clear();
    var committed = false;
    defer if !committed { core::secure_zeroize_slice(out[..]); out.clear(); };
    guard !has_live_header_ctl(host) && !has_live_header_ctl(target) &&
        !has_live_header_ctl(auth_header) && !has_live_header_ctl(subprotocol) else {
        return false;
    }
    guard out.try_append("GET ") && out.try_append(target) &&
        out.try_append(" HTTP/1.1\r\nHost: ") && out.try_append(host) &&
        out.try_append("\r\nUpgrade: websocket\r\nConnection: Upgrade\r\n") &&
        out.try_append("Sec-WebSocket-Version: 13\r\nSec-WebSocket-Key: ") &&
        out.try_append(client_key) else {
        return false;
    }
    if subprotocol.len > 0 {
        guard out.try_append("\r\nSec-WebSocket-Protocol: ") && out.try_append(subprotocol) else {
            return false;
        }
    }
    if auth_header.len > 0 {
        guard out.try_append("\r\nAuthorization: ") && out.try_append(auth_header) else {
            return false;
        }
    }
    guard out.try_append("\r\n\r\n") else { return false; }
    committed = true;
    return true;
}

fn validate_ws_client_upgrade_head(
    head:        const u8[:],
    client_key:  const u8[:],
    subprotocol: const u8[:],
    out_proto:   u8[..64]&,
) -> bool {
    out_proto.clear();
    let status, ok_st = realtime::parse_http1_status_code(head);
    let acc, acc_cnt = realtime::find_http1_header_counted(head, "Sec-WebSocket-Accept");
    let _, ext_cnt = realtime::find_http1_header_counted(head, "Sec-WebSocket-Extensions");
    guard ok_st && status == 101 && ext_cnt == 0 && acc_cnt == 1 else { return false; }
    guard realtime::http1_head_has_token(head, "Upgrade", "websocket") &&
        realtime::http1_head_has_token(head, "Connection", "upgrade") &&
        realtime::validate_websocket_accept(client_key, acc) else {
        return false;
    }
    let proto_val, proto_cnt = realtime::find_http1_header_counted(head, "Sec-WebSocket-Protocol");
    guard proto_cnt <= 1 else { return false; }
    if proto_cnt == 1 {
        guard subprotocol.len > 0 && realtime::has_subprotocol_token(subprotocol, proto_val) &&
            out_proto.try_set(proto_val) else {
            out_proto.clear();
            return false;
        }
    }
    return true;
}

fn finalize_client_ws_conn(
    out_conn:  realtime::WsConn&,
    tr:        net::Transport,
    neg_proto: const u8[:],
    leftover:  const u8[:],
) {
    out_conn.tr = tr;
    out_conn.ws = realtime::new_websocket_session(true);
    if neg_proto.len > 0 {
        let _ = out_conn.negotiated_subprotocol.try_set(neg_proto);
        let _ = out_conn.ws.subprotocol.try_set(neg_proto);
    }
    if leftover.len > 0 { out_conn.rx_buf.append(leftover); }
    out_conn.open = true;
}

// Dials a live `ws://` or `wss://` WebSocket endpoint reusing `sess` proxy, TLS trust store,
// and timeout configuration (RFC 6455 Section 4.1).
//
// Example:
//   var conn = client::WsConn { .. };
//   let ok = client::dial_ws(sess, "wss://example.com/ws", conn, "Bearer tok", "binary");
fn dial_ws(
    sess:         const Session&,
    url:          const u8[:],
    out_conn:     realtime::WsConn&,
    auth_header:  const u8[:] = "",
    subprotocol:  const u8[:] = "",
    sni_override: const u8[:] = "",
) -> bool {
    realtime::ws_close(out_conn);
    let u, _ = core::parse_url(url);
    let use_tls = u.scheme() == "wss";
    let eff_port = u.effective_port();
    guard u.valid && u.hostname().len > 0 && (use_tls || u.scheme() == "ws") &&
        eff_port > 0 && eff_port <= 65535 else {
        return false;
    }
    guard validate_url_against_ssrf(u, sess.ssrf_guard) == RedirectError.None else {
        return false;
    }

    var target: u8[..1024] = [];
    var nonce:  u8[16]     = [0; 16];
    defer core::secure_zeroize_16(nonce);
    let got_rng = if core::sim_rng_is_active() {
        core::sim_rng_fill(nonce[..])
    } else {
        core::csprng_fill(nonce[..])
    };
    guard build_live_request_target(u, target) && got_rng else { return false; }
    var client_key: u8[..64] = [];
    realtime::generate_websocket_key(nonce, client_key);

    var req_wire: u8[..2048] = [];
    defer core::secure_zeroize_slice(req_wire[..]);
    guard build_ws_client_upgrade_wire(u.host(), target[..], client_key[..], auth_header, subprotocol, req_wire) else {
        return false;
    }

    var tr, ok_d = dial_live_transport(sess, u.hostname(), eff_port as u16, use_tls, sni_override);
    guard ok_d else { return false; }
    var committed = false;
    defer if !committed { tr.close(); };

    var head:      u8[..8192] = [];
    var leftover:  u8[>..]    = [];
    var neg_proto: u8[..64]   = [];
    guard realtime::send_all_transport(tr, req_wire[..]) &&
        realtime::read_http1_head(tr, head, leftover, resolve_live_read_timeout_ms(sess)) &&
        validate_ws_client_upgrade_head(head[..], client_key[..], subprotocol, neg_proto) else {
        return false;
    }
    finalize_client_ws_conn(out_conn, tr, neg_proto[..], leftover[..]);
    committed = true;
    return true;
}

// ---- Streaming Server-Sent Events (`SseConn` / `dial_sse`) -----------------

// Live W3C EventSource (SSE) connection streaming incremental events without buffering to EOF.
root struct SseConn {
    tr:           net::Transport          = net::Transport.Disconnected,
    parser:       realtime::SseParser     = realtime::SseParser { .. },
    pending:      realtime::SseEvent[>..] = [],
    pending_head: i64                     = 0,
    is_chunked:   bool                    = false,
    open:         bool                    = false,
    failed:       bool                    = false,
    chunk_buf:    u8[>..]                 = [],
}

// Closes the underlying SSE transport and resets all buffered parser/chunk state.
fn sse_close(conn: SseConn&) {
    if conn.open || net::is_connected(conn.tr) {
        conn.tr.close();
    }
    conn.tr = net::Transport.Disconnected;
    conn.parser = realtime::SseParser { .. };
    conn.pending.clear();
    conn.pending_head = 0;
    conn.is_chunked = false;
    conn.open = false;
    conn.failed = false;
    conn.chunk_buf.clear();
}

fn sse_feed_into_queue(conn: SseConn&, data: const u8[:]) {
    var batch: realtime::SseEvent[..8] = [];
    var off:   i64                     = 0;
    while off < data.len {
        let end = min(core::add_sat_i64(off, 32), data.len);
        batch.clear();
        realtime::sse_feed(conn.parser, data[off..end], batch);
        for &ev in batch {
            conn.pending.push(ev);
        }
        off = end;
    }
}

// Parses a strict RFC 9112 Section 7.1 hexadecimal chunk size (ASCII hex digits only).
//
// Example:
//   raw_hex = "1a" -> returns (26, true)
fn parse_sse_chunk_size(raw_hex: const u8[:]) -> u64, bool {
    guard raw_hex.len > 0 && raw_hex.len <= 16 else { return 0, false; }
    for b in raw_hex {
        guard core::is_ascii_hexdigit(b) else { return 0, false; }
    }
    return raw_hex.parse_u64_hex();
}

// Consumes one RFC 9112 chunk from `conn.chunk_buf`.
// Returns: `1` = chunk decoded, `0` = need more bytes, `2` = terminating 0-chunk, `-1` = malformed.
fn consume_one_sse_chunk(conn: SseConn&) -> i32 {
    let crlf = core::find_crlf(conn.chunk_buf[..]);
    guard crlf >= 0 else { return 0; }
    let size_line = conn.chunk_buf[..crlf];
    let hex_part, _, has_ext = size_line.split_once_byte(';');
    let sz_u64, ok_sz = parse_sse_chunk_size((if has_ext { hex_part } else { size_line }).trim_lws());
    guard ok_sz && sz_u64 <= SSE_MAX_CHUNK_BYTES else {
        conn.failed = true;
        conn.open = false;
        return -1;
    }
    if sz_u64 == 0 {
        conn.open = false;
        return 2;
    }
    let body_off = core::add_sat_i64(crlf, 2);
    let body_end = core::add_sat_i64(body_off, sz_u64 as i64);
    let cr_next = core::add_sat_i64(body_end, 1);
    let need = core::add_sat_i64(body_end, 2);
    guard conn.chunk_buf.len >= need else { return 0; }
    guard conn.chunk_buf[body_end] == '\r' && conn.chunk_buf[cr_next] == '\n' else {
        conn.failed = true;
        conn.open = false;
        return -1;
    }
    sse_feed_into_queue(conn, conn.chunk_buf[body_off..body_end]);
    conn.chunk_buf.compact_wire_buffer(need);
    return 1;
}

fn sse_feed_decoded_bytes(conn: SseConn&, raw: const u8[:]) -> bool {
    if !conn.is_chunked {
        sse_feed_into_queue(conn, raw);
        return true;
    }
    if raw.len > 0 {
        guard core::add_sat_i64(conn.chunk_buf.len, raw.len) <= SSE_MAX_CHUNK_BUF_BYTES else {
            conn.failed = true;
            conn.open = false;
            return false;
        }
        conn.chunk_buf.append(raw);
    }
    while true {
        let step = consume_one_sse_chunk(conn);
        if step == 1 { continue; }
        return step >= 0;
    }
    return true;
}

fn build_sse_request_wire(
    host:          const u8[:],
    target:        const u8[:],
    bearer_token:  const u8[:],
    last_event_id: const u8[:],
    out:           u8[..2048]&,
) -> bool {
    out.clear();
    var committed = false;
    defer if !committed { core::secure_zeroize_slice(out[..]); out.clear(); };
    guard !has_live_header_ctl(bearer_token) && !has_live_header_ctl(last_event_id) else { return false; }
    guard out.try_append("GET ") && out.try_append(target) &&
        out.try_append(" HTTP/1.1\r\nHost: ") && out.try_append(host) &&
        out.try_append("\r\nAccept: text/event-stream\r\nCache-Control: no-cache\r\nConnection: close") else {
        return false;
    }
    if bearer_token.len > 0 {
        guard out.try_append("\r\nAuthorization: Bearer ") && out.try_append(bearer_token) else { return false; }
    }
    if last_event_id.len > 0 {
        guard out.try_append("\r\nLast-Event-ID: ") && out.try_append(last_event_id) else { return false; }
    }
    guard out.try_append("\r\n\r\n") else { return false; }
    committed = true;
    return true;
}

fn validate_sse_response_head(head: const u8[:]) -> bool, bool {
    let status, ok_st = realtime::parse_http1_status_code(head);
    let ctype, ct_cnt = realtime::find_http1_header_counted(head, "Content-Type");
    guard ok_st && status == 200 && ct_cnt >= 1 && ctype.starts_with_fold("text/event-stream") else {
        return false, false;
    }
    guard ctype.len == 17 || ctype[17] == ';' || core::is_lws(ctype[17]) else {
        return false, false;
    }
    return true, realtime::http1_head_has_token(head, "Transfer-Encoding", "chunked");
}

// Dials a streaming HTTP/1.1 Server-Sent Events endpoint (`http://` or `https://`),
// reusing `sess` proxy, TLS trust store, and timeouts. Supports `Transfer-Encoding: chunked`
// and `Last-Event-ID` resumption.
//
// Example:
//   var conn = client::SseConn { .. };
//   let ok = client::dial_sse(sess, "http://127.0.0.1:8090/v1/events", conn, "tok", "42");
fn dial_sse(
    sess:          const Session&,
    url:           const u8[:],
    out_conn:      SseConn&,
    bearer_token:  const u8[:] = "",
    last_event_id: const u8[:] = "",
) -> bool {
    sse_close(out_conn);
    let u, _ = core::parse_url(url);
    let use_tls = u.scheme() == "https";
    let eff_port = u.effective_port();
    guard u.valid && u.hostname().len > 0 && (use_tls || u.scheme() == "http") &&
        eff_port > 0 && eff_port <= 65535 else {
        return false;
    }
    guard validate_url_against_ssrf(u, sess.ssrf_guard) == RedirectError.None else {
        return false;
    }

    var target: u8[..1024] = [];
    var req:    u8[..2048] = [];
    defer core::secure_zeroize_slice(req[..]);
    guard build_live_request_target(u, target) &&
        build_sse_request_wire(u.host(), target[..], bearer_token, last_event_id, req) else {
        return false;
    }

    var tr, ok_d = dial_live_transport(sess, u.hostname(), eff_port as u16, use_tls);
    guard ok_d else { return false; }
    var committed = false;
    defer if !committed { tr.close(); };

    var head:     u8[..8192] = [];
    var leftover: u8[>..]    = [];
    guard realtime::send_all_transport(tr, req[..]) &&
        realtime::read_http1_head(tr, head, leftover, resolve_live_read_timeout_ms(sess)) else {
        return false;
    }

    let ok_head, is_chunked = validate_sse_response_head(head[..]);
    guard ok_head else { return false; }
    if last_event_id.len > 0 && !out_conn.parser.last_event_id.try_set(last_event_id) {
        return false;
    }
    out_conn.is_chunked = is_chunked;
    out_conn.tr = tr;
    out_conn.open = true;
    if leftover.len > 0 && !sse_feed_decoded_bytes(out_conn, leftover[..]) {
        out_conn.tr = net::Transport.Disconnected;
        out_conn.open = false;
        return false;
    }
    committed = true;
    return true;
}

fn pop_pending_sse_event(conn: SseConn&, out_ev: realtime::SseEvent&) -> bool {
    guard conn.pending_head < conn.pending.len else { return false; }
    out_ev = conn.pending[conn.pending_head];
    conn.pending_head = core::add_sat_i64(conn.pending_head, 1);
    if conn.pending_head >= conn.pending.len {
        conn.pending.clear();
        conn.pending_head = 0;
    }
    return true;
}

fn read_sse_wire_chunk(conn: SseConn&, chunk: u8[2048]&, timeout_ms: u32) -> i32 {
    let n = conn.tr.recv_slice(chunk[..], timeout_ms);
    if n > 0 {
        return if sse_feed_decoded_bytes(conn, chunk[..n]) { 1 } else { -1 };
    }
    if n == -2 { return -2; }
    if n == 0 { realtime::sse_flush(conn.parser); }
    conn.open = false;
    return if n == 0 { 0 } else { -1 };
}

// Reads the next decoded `realtime::SseEvent` from `conn`.
// Returns: `1` = event ready, `0` = EOF, `-2` = timeout, `-1` = protocol or transport error.
fn sse_recv_event(conn: SseConn&, out_ev: realtime::SseEvent&, timeout_ms: u32 = 10000) -> i32 {
    var chunk: u8[2048] = [0; 2048];
    while true {
        if pop_pending_sse_event(conn, out_ev) { return 1; }
        if conn.failed { return -1; }
        guard conn.open else { return 0; }
        let rd = read_sse_wire_chunk(conn, chunk, timeout_ms);
        if rd != 1 { return rd; }
    }
    return -1;
}
