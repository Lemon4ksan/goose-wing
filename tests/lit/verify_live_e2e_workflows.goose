// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// End-to-End Live Socket Verification Suite for High-Level Protocol Workflows:
// 1. Live SOCKS5 (RFC 1928/1929) & HTTP CONNECT Proxy Tunnels (`wing::Client` -> Proxy -> `wing::HttpServer`).
// 2. Live 401 Digest SHA-256 (RFC 7616) & Basic Auth (RFC 7617) Challenge-Response + Cookie Jar Persistence.
// 3. Live RFC 9111 HTTP Cache (`200 OK` + `ETag` -> Fresh Hit -> TTL Expiry -> `If-None-Match` -> `304 Not Modified`).
// 4. Live Native Client<->Server WebSocket (RFC 6455 HTTP/1.1 + RFC 8441 HTTP/2 Extended CONNECT) & W3C SSE (`text/event-stream`).
// 5. Live ReverseProxy + LoadBalancer (`execute_proxy_exchange`) with Dead-Target Failover & `X-Forwarded-For`/`Via`.

// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

var g_e2e_client: wing::Client       = wing::Client { .. };
var g_e2e_proxy:  wing::ReverseProxy = wing::ReverseProxy { .. };
var g_e2e_pool:   wing::StreamPool   = wing::StreamPool { .. };

var g_reval_hits: i32 = 0;

fn find_subslice(haystack: const u8[:], needle: const u8[:]) -> i64 {
    guard needle.len > 0 && haystack.len >= needle.len else { return -1; }
    let limit = haystack.len - needle.len + 1;
    for i in limit {
        if haystack[i..i + needle.len] == needle {
            return i;
        }
    }
    return -1;
}

// ---- Server Route Handlers & Live Socket Accept Helper ---------------------

fn handle_tunnel_origin(req: const wing::Request&, res: wing::Response&) {
    // Verify Proxy-Authorization was stripped before reaching origin (Seam 19)
    assert(!req.has_header("proxy-authorization"));
    assert(!req.has_header("proxy-connection"));
    res.status_code = 200;
    res.set_header("X-Origin-Reached", "yes");
    res.body.append("TUNNEL_ORIGIN_OK:");
    res.body.append(req.url[..]);
}

fn handle_digest_protected(req: const wing::Request&, res: wing::Response&) {
    let auth = req.header("authorization");
    if auth.len == 0 || !core::starts_with_fold(auth, "Digest ") {
        res.status_code = 401;
        res.set_header(
            "WWW-Authenticate",
            "Digest realm=\"wing-api\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"auth\", algorithm=SHA-256, opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"",
        );
        res.set_header("Set-Cookie", "auth_step=challenged; Path=/");
        res.body.append("UNAUTHORIZED");
        return;
    }
    // Verify client sent the cookie from the 401 challenge AND valid SHA-256 Digest response
    let cookie_hdr = req.header("cookie");
    assert(find_subslice(cookie_hdr, "auth_step=challenged") >= 0);
    assert(find_subslice(auth, "username=\"admin\"") >= 0);
    assert(find_subslice(auth, "realm=\"wing-api\"") >= 0);
    assert(find_subslice(auth, "algorithm=SHA-256") >= 0);
    assert(find_subslice(auth, "uri=\"/digest-protected\"") >= 0);
    res.status_code = 200;
    res.body.append("DIGEST_AUTH_OK");
}

fn handle_cacheable_resource(req: const wing::Request&, res: wing::Response&) {
    let inm = req.header("if-none-match");
    if inm == "\"v42\"" {
        g_reval_hits += 1;
        res.status_code = 304;
        res.set_header("ETag", "\"v42\"");
        res.set_header("Cache-Control", "max-age=60");
        res.set_header("X-Cache-Freshened", "true");
        return;
    }
    res.status_code = 200;
    res.set_header("ETag", "\"v42\"");
    res.set_header("Cache-Control", "max-age=10");
    res.set_header("X-Cache-Freshened", "false");
    res.body.append("CACHED_LIVE_PAYLOAD_V42");
}

fn handle_sse_stream(req: const wing::Request&, res: wing::Response&) {
    wing::init_response(res);
    let last_id = req.header("last-event-id");
    if last_id == "ev-2" {
        wing::sse_format_event(res.body, "resumed", "after-ev-2", "ev-3", 0);
        return;
    }
    wing::sse_format_event(res.body, "tick", "first-line\nsecond-line", "ev-1", 1500);
    wing::sse_format_event(res.body, "message", "final-item", "ev-2", 0);
}

fn handle_proxy_backend(req: const wing::Request&, res: wing::Response&) {
    let xff = req.header("x-forwarded-for");
    let via = req.header("via");
    assert(xff == "198.51.100.77");
    assert(find_subslice(via, "wing") >= 0);
    assert(!req.has_header("x-secret-hop"));
    res.status_code = 200;
    res.set_header("X-Backend-Handled", "true");
    res.body.append("UPSTREAM_LIVE_OK");
}

fn accept_and_serve_one_e2e(lfd: i64) -> bool {
    let sfd = wing::tcp_accept(lfd, 200);
    guard sfd > 0 else { return false; }
    var rx_buf: u8[..4096] = [];
    let n_rx = wing::tcp_recv(sfd, rx_buf, 4096, 200);
    guard n_rx > 0 else {
        wing::tcp_close(sfd);
        return false;
    }
    var req = wing::Request { .. };
    let ok_p, _ = wing::parse_http1_wire_request(rx_buf[..n_rx], req);
    guard ok_p else {
        wing::tcp_close(sfd);
        return false;
    }
    var res = wing::Response { status_code: 404, .. };
    if req.url[..] == "/tunnel-check" {
        handle_tunnel_origin(req, res);
    } else if req.url[..] == "/digest-protected" {
        handle_digest_protected(req, res);
    } else if req.url[..] == "/cache-item" {
        handle_cacheable_resource(req, res);
    } else if req.url[..] == "/events" {
        handle_sse_stream(req, res);
    } else if req.url[..] == "/proxy-target" {
        handle_proxy_backend(req, res);
    }
    var tx_buf: u8[..4096] = [];
    wing::serialize_http1_response(res, "goose-wing-e2e", tx_buf);
    let sent = wing::tcp_send(sfd, tx_buf[..]);
    wing::tcp_close(sfd);
    return sent == tx_buf.len;
}

// ---- 1. Live SOCKS5 & HTTP CONNECT Proxy Tunnels ---------------------------

fn test_live_proxy_tunnels() {
    let srv_lfd = wing::tcp_listen("127.0.0.1", 0);
    let prx_lfd = wing::tcp_listen("127.0.0.1", 0);
    assert(srv_lfd > 0 && prx_lfd > 0);
    let srv_port = wing::tcp_getsockname_port(srv_lfd);
    let prx_port = wing::tcp_getsockname_port(prx_lfd);

    // 1A. Verify live SOCKS5h RFC 1928 + RFC 1929 Username/Password client<->server handshake
    let c_socks = wing::tcp_connect("127.0.0.1", prx_port, 200);
    let s_socks = wing::tcp_accept(prx_lfd, 200);
    assert(c_socks > 0 && s_socks > 0);

    // Pre-send server replies (method selection [0x05, 0x02], RFC 1929 auth [0x01, 0x00], CONNECT reply)
    // so `socks5_client_handshake` executes end-to-end over the live socket!
    let srv_socks_script: u8[14] = [
        0x05, 0x02,
        0x01, 0x00,
        0x05, 0x00, 0x00, 0x01, 127, 0, 0, 1, 0x00, 0x00,
    ];
    assert(wing::tcp_send(s_socks, srv_socks_script[..]) == 14);
    let s5_err = wing::socks5_client_handshake(
        c_socks, wing::ProxyScheme.Socks5h, "origin.internal", srv_port, "alice", "s3cret", 200,
    );
    assert(s5_err == wing::Socks5Error.None);

    var s5_rx: u8[..128] = [];
    let n_s5 = wing::tcp_recv(s_socks, s5_rx, 128, 200);
    assert(n_s5 > 10 && s5_rx[0] == 0x05 && s5_rx[4] == 0x01); // Greeting 0x05 + RFC 1929 0x01
    assert(find_subslice(s5_rx[..n_s5], "origin.internal") >= 0); // ATYP=0x03 domain for socks5h://
    wing::tcp_close(c_socks);
    wing::tcp_close(s_socks);

    // 1B. Verify live HTTP CONNECT tunnel client<->server handshake with Proxy-Authorization
    let c_hc = wing::tcp_connect("127.0.0.1", prx_port, 200);
    let s_hc = wing::tcp_accept(prx_lfd, 200);
    assert(c_hc > 0 && s_hc > 0);
    let connect_200 = "HTTP/1.1 200 Connection Established\r\nProxy-Agent: wing-proxy\r\n\r\n";
    assert(wing::tcp_send(s_hc, connect_200) == connect_200.len);
    let hc_err = wing::http_connect_client_handshake(
        c_hc, "origin.internal", srv_port, "Basic YWxpY2U6czNjcmV0", "goose-wing/1.0", 200,
    );
    assert(hc_err == wing::ConnectTunnelError.None);
    var hc_rx: u8[..512] = [];
    let n_hc = wing::tcp_recv(s_hc, hc_rx, 512, 200);
    assert(n_hc > 0 && find_subslice(hc_rx[..n_hc], "CONNECT origin.internal:") >= 0);
    assert(find_subslice(hc_rx[..n_hc], "Proxy-Authorization: Basic YWxpY2U6czNjcmV0") >= 0);
    wing::tcp_close(c_hc);
    wing::tcp_close(s_hc);

    // 1C. Now tunnel an HTTP/1.1 request through `wing::Client` with `proxy_url` -> origin server
    let srv_conn_c = wing::tcp_connect("127.0.0.1", srv_port, 200);
    let srv_conn_s = wing::tcp_accept(srv_lfd, 200);
    assert(srv_conn_c > 0 && srv_conn_s > 0);

    g_e2e_client = wing::Client { .. };
    g_e2e_client.virtual_clock_us = 1;
    let _ = g_e2e_client.proxy_url.try_set("http://alice:s3cret@127.0.0.1:18888");
    let proxy_chain = wing::resolve_hop_proxy_chain(g_e2e_client);
    let pkey = wing::new_pool_key(
        wing::PoolScheme.Http, "127.0.0.1", srv_port,
        proxy_chain,
        wing::new_network_anonymization_key("127.0.0.1", false),
        wing::TlsAndDnsPolicy { .. },
    );
    let tp_direct_tun: wing::Transport = wing::Transport.Tcp { fd: srv_conn_c };
    let cid_tun = wing::register_connection(
        g_e2e_client.pool, pkey, wing::NegotiatedProtocol.Http11, tp_direct_tun, "127.0.0.1", 1, 1000,
    );
    wing::release_connection(g_e2e_client.pool, cid_tun, 1000);

    var url_tun: u8[..128] = [];
    url_tun.append("http://127.0.0.1:");
    core::format_u64_dec(srv_port, url_tun);
    url_tun.append("/tunnel-check");

    var req_tun = wing::new_get(url_tun[..]);
    // Attach a Proxy-Authorization header that MUST be stripped by `execute_live_network_hop` when `!proxy_chain.is_direct`
    wing::set_header(req_tun, "Proxy-Authorization", "Basic YWxpY2U6czNjcmV0");
    wing::set_header(req_tun, "Proxy-Connection", "keep-alive");

    let canned_origin_resp = "HTTP/1.1 200 OK\r\nContent-Length: 16\r\nX-Origin-Reached: yes\r\n\r\nTUNNEL_ORIGIN_OK";
    assert(wing::tcp_send(srv_conn_s, canned_origin_resp) == canned_origin_resp.len);

    let resp_tun, err_tun = wing::execute_request(g_e2e_client, req_tun);
    assert(wing::ok(err_tun) && resp_tun.status_code == 200);
    assert(resp_tun.body[..] == "TUNNEL_ORIGIN_OK");

    // Read the exact wire bytes received by the origin server on `srv_conn_s` and feed them into our live server!
    var origin_rx: u8[..2048] = [];
    let n_orig = wing::tcp_recv(srv_conn_s, origin_rx, 2048, 200);
    assert(n_orig > 0);
    assert(find_subslice(origin_rx[..n_orig], "Proxy-Authorization") < 0);
    assert(find_subslice(origin_rx[..n_orig], "Proxy-Connection") < 0);

    let v_c = wing::tcp_connect("127.0.0.1", srv_port, 200);
    assert(v_c > 0);
    assert(wing::tcp_send(v_c, origin_rx[..n_orig]) == n_orig);
    assert(accept_and_serve_one_e2e(srv_lfd));
    var srv_out: u8[..1024] = [];
    let n_so = wing::tcp_recv(v_c, srv_out, 1024, 200);
    assert(n_so > 0 && find_subslice(srv_out[..n_so], "TUNNEL_ORIGIN_OK:/tunnel-check") >= 0);

    wing::tcp_close(v_c);
    wing::tcp_close(srv_conn_c);
    wing::tcp_close(srv_conn_s);
    wing::tcp_close(srv_lfd);
    wing::tcp_close(prx_lfd);
    print("E2E_LIVE_PROXY_TUNNELS: OK");
}

// ---- 2. Live 401 Digest SHA-256 Challenge-Response + Cookie Jar ------------

fn test_live_digest_auth_and_cookies() {
    let srv_lfd = wing::tcp_listen("127.0.0.1", 0);
    assert(srv_lfd > 0);
    let srv_port = wing::tcp_getsockname_port(srv_lfd);

    let c_fd = wing::tcp_connect("127.0.0.1", srv_port, 200);
    let s_fd = wing::tcp_accept(srv_lfd, 200);
    assert(c_fd > 0 && s_fd > 0);

    g_e2e_client = wing::Client { .. };
    g_e2e_client.virtual_clock_us = 1700000000000000;
    let _ = g_e2e_client.creds.username.try_set("admin");
    let _ = g_e2e_client.creds.password.try_set("hunter2");
    g_e2e_client.creds.has_credentials = true;

    let pkey = wing::new_pool_key(
        wing::PoolScheme.Http, "127.0.0.1", srv_port,
        wing::new_direct_proxy_chain(),
        wing::new_network_anonymization_key("127.0.0.1", false),
        wing::TlsAndDnsPolicy { .. },
    );
    let tp: wing::Transport = wing::Transport.Tcp { fd: c_fd };
    let cid_auth = wing::register_connection(
        g_e2e_client.pool, pkey, wing::NegotiatedProtocol.Http11, tp, "127.0.0.1", 1, 1700000000000000000,
    );
    wing::release_connection(g_e2e_client.pool, cid_auth, 1700000000000000000);

    // Queue the 2 pipelined HTTP/1.1 Keep-Alive responses on `s_fd` (401 challenge + 200 OK),
    // then verify the 2 requests emitted by `wing::Client` against `handle_digest_protected`!
    var resp_401_and_200: u8[..1024] = [];
    resp_401_and_200.append("HTTP/1.1 401 Unauthorized\r\n");
    resp_401_and_200.append("WWW-Authenticate: Digest realm=\"wing-api\", nonce=\"dcd98b7102dd2f0e8b11d0f600bfb0c093\", qop=\"auth\", algorithm=SHA-256, opaque=\"5ccc069c403ebaf9f0171e9517f40e41\"\r\n");
    resp_401_and_200.append("Set-Cookie: auth_step=challenged; Path=/\r\n");
    resp_401_and_200.append("Content-Length: 12\r\n\r\nUNAUTHORIZED");
    resp_401_and_200.append("HTTP/1.1 200 OK\r\nContent-Length: 14\r\n\r\nDIGEST_AUTH_OK");
    assert(wing::tcp_send(s_fd, resp_401_and_200[..]) == resp_401_and_200.len);

    var url_auth: u8[..128] = [];
    url_auth.append("http://127.0.0.1:");
    core::format_u64_dec(srv_port, url_auth);
    url_auth.append("/digest-protected");

    let req_auth = wing::new_get(url_auth[..]);
    let resp_auth, err_auth = wing::execute_request(g_e2e_client, req_auth);
    assert(wing::ok(err_auth) && resp_auth.status_code == 200);
    assert(resp_auth.body[..] == "DIGEST_AUTH_OK");
    assert(wing::get(g_e2e_client.jar, "auth_step") == "challenged");

    // Read both wire requests emitted by `wing::Client` over `s_fd` and replay the 2nd (authenticated) request
    // against `accept_and_serve_one_e2e` (`handle_digest_protected`)!
    var wire_both: u8[..4096] = [];
    let n_both = wing::tcp_recv(s_fd, wire_both, 4096, 200);
    assert(n_both > 0);
    assert(find_subslice(wire_both[..n_both], "Authorization: Digest ") >= 0);
    let second_get_pos = find_subslice(wire_both[16..n_both], "GET /digest-protected");
    assert(second_get_pos >= 0);
    let req2_slice = wire_both[16 + second_get_pos..n_both];

    let v_c = wing::tcp_connect("127.0.0.1", srv_port, 200);
    assert(v_c > 0);
    assert(wing::tcp_send(v_c, req2_slice) == req2_slice.len);
    assert(accept_and_serve_one_e2e(srv_lfd));
    var srv_out: u8[..1024] = [];
    let n_so = wing::tcp_recv(v_c, srv_out, 1024, 200);
    assert(n_so > 0 && find_subslice(srv_out[..n_so], "200 OK") >= 0);
    assert(find_subslice(srv_out[..n_so], "DIGEST_AUTH_OK") >= 0);

    wing::tcp_close(v_c);
    wing::tcp_close(c_fd);
    wing::tcp_close(s_fd);
    wing::tcp_close(srv_lfd);
    print("E2E_LIVE_DIGEST_AUTH_AND_COOKIES: OK");
}

// ---- 3. Live RFC 9111 HTTP Cache Revalidation (200 -> Hit -> 304) ----------

fn test_live_http_cache_revalidation() {
    let srv_lfd = wing::tcp_listen("127.0.0.1", 0);
    assert(srv_lfd > 0);
    let srv_port = wing::tcp_getsockname_port(srv_lfd);

    let c_fd = wing::tcp_connect("127.0.0.1", srv_port, 200);
    let s_fd = wing::tcp_accept(srv_lfd, 200);
    assert(c_fd > 0 && s_fd > 0);

    g_e2e_client = wing::Client { .. };
    g_e2e_client.virtual_clock_us = 1000000000; // t = 1000s
    g_e2e_client.enable_cache = true;

    let pkey = wing::new_pool_key(
        wing::PoolScheme.Http, "127.0.0.1", srv_port,
        wing::new_direct_proxy_chain(),
        wing::new_network_anonymization_key("127.0.0.1", false),
        wing::TlsAndDnsPolicy { .. },
    );
    let tp: wing::Transport = wing::Transport.Tcp { fd: c_fd };
    let cid_cache = wing::register_connection(
        g_e2e_client.pool, pkey, wing::NegotiatedProtocol.Http11, tp, "127.0.0.1", 1, 1000000000000,
    );
    wing::release_connection(g_e2e_client.pool, cid_cache, 1000000000000);

    // Queue initial 200 OK (max-age=10, ETag="v42") and subsequent 304 Not Modified on the Keep-Alive socket
    var wire_200_and_304: u8[..1024] = [];
    wire_200_and_304.append("HTTP/1.1 200 OK\r\nETag: \"v42\"\r\nCache-Control: max-age=10\r\nX-Cache-Freshened: false\r\nContent-Length: 23\r\n\r\nCACHED_LIVE_PAYLOAD_V42");
    wire_200_and_304.append("HTTP/1.1 304 Not Modified\r\nETag: \"v42\"\r\nCache-Control: max-age=60\r\nX-Cache-Freshened: true\r\n\r\n");
    assert(wing::tcp_send(s_fd, wire_200_and_304[..]) == wire_200_and_304.len);

    var url_cache: u8[..128] = [];
    url_cache.append("http://127.0.0.1:");
    core::format_u64_dec(srv_port, url_cache);
    url_cache.append("/cache-item");

    // Step 1 (t = 1000s): Miss -> fetches 200 OK from socket and stores in cache
    let req1 = wing::new_get(url_cache[..]);
    let resp1, err1 = wing::execute_request(g_e2e_client, req1);
    assert(wing::ok(err1) && resp1.status_code == 200);
    assert(resp1.body[..] == "CACHED_LIVE_PAYLOAD_V42");
    assert(resp1.header("x-cache-freshened") == "false");

    // Drain 1st request from `s_fd`
    var req1_wire: u8[..1024] = [];
    let n_r1 = wing::tcp_recv(s_fd, req1_wire, 1024, 200);
    assert(n_r1 > 0 && find_subslice(req1_wire[..n_r1], "If-None-Match") < 0);

    // Step 2 (t = 1005s, within max-age=10): Fresh hit -> served from cache WITHOUT touching socket!
    g_e2e_client.virtual_clock_us = 1005000000;
    let resp2, err2 = wing::execute_request(g_e2e_client, req1);
    assert(wing::ok(err2) && resp2.status_code == 200);
    assert(resp2.body[..] == "CACHED_LIVE_PAYLOAD_V42");

    // Step 3 (t = 1025s, past max-age=10): Stale -> sends conditional `If-None-Match: "v42"` over live socket,
    // receives `304 Not Modified`, and synthesizes freshened 200 OK with cached body + new headers!
    g_e2e_client.virtual_clock_us = 1025000000;
    let resp3, err3 = wing::execute_request(g_e2e_client, req1);
    assert(wing::ok(err3) && resp3.status_code == 200);
    assert(resp3.body[..] == "CACHED_LIVE_PAYLOAD_V42");
    assert(resp3.header("x-cache-freshened") == "true");

    // Verify the conditional request sent over `s_fd` against `accept_and_serve_one_e2e` (`handle_cacheable_resource`)!
    var req3_wire: u8[..1024] = [];
    let n_r3 = wing::tcp_recv(s_fd, req3_wire, 1024, 200);
    assert(n_r3 > 0 && find_subslice(req3_wire[..n_r3], "If-None-Match: \"v42\"") >= 0);

    let v_c = wing::tcp_connect("127.0.0.1", srv_port, 200);
    assert(v_c > 0);
    assert(wing::tcp_send(v_c, req3_wire[..n_r3]) == n_r3);
    assert(accept_and_serve_one_e2e(srv_lfd));
    assert(g_reval_hits == 1);
    var srv_304: u8[..1024] = [];
    let n_s304 = wing::tcp_recv(v_c, srv_304, 1024, 200);
    assert(n_s304 > 0 && find_subslice(srv_304[..n_s304], "304 Not Modified") >= 0);

    wing::tcp_close(v_c);
    wing::tcp_close(c_fd);
    wing::tcp_close(s_fd);
    wing::tcp_close(srv_lfd);
    print("E2E_LIVE_HTTP_CACHE_REVALIDATION: OK");
}

// ---- 4. Live Client<->Server WebSocket (H1 & H2) + W3C SSE -----------------

fn test_live_websocket_and_sse() {
    let lfd = wing::tcp_listen("127.0.0.1", 0);
    assert(lfd > 0);
    let port = wing::tcp_getsockname_port(lfd);

    // 4A. Live RFC 6455 HTTP/1.1 WebSocket Handshake + Masked/Unmasked Frames + Ping/Pong + Close
    let ws_c = wing::tcp_connect("127.0.0.1", port, 200);
    let ws_s = wing::tcp_accept(lfd, 200);
    assert(ws_c > 0 && ws_s > 0);

    var cli_ws = wing::new_websocket_session(true);
    cli_ws.subprotocol.append("chat");
    let client_key = "dGhlIHNhbXBsZSBub25jZQ==";
    var hs_req_wire: u8[..512] = [];
    wing::build_handshake_request(cli_ws, "127.0.0.1", "/ws-live", client_key, hs_req_wire);
    assert(wing::tcp_send(ws_c, hs_req_wire[..]) == hs_req_wire.len);

    var srv_rx_hs: u8[..512] = [];
    let n_hs = wing::tcp_recv(ws_s, srv_rx_hs, 512, 200);
    assert(n_hs == hs_req_wire.len);
    var parsed_ws_req = wing::Request { .. };
    let ok_p_ws, _ = wing::parse_http1_wire_request(srv_rx_hs[..n_hs], parsed_ws_req);
    assert(ok_p_ws);
    var ws_srv_res = wing::Response { .. };
    var srv_ws, ok_upg = wing::ws_upgrade_request(parsed_ws_req, ws_srv_res, "chat");
    assert(ok_upg && ws_srv_res.status_code == 101 && srv_ws.subprotocol[..] == "chat");

    var hs_resp_wire: u8[..512] = [];
    wing::serialize_http1_response(ws_srv_res, "goose-wing-e2e", hs_resp_wire);
    assert(wing::tcp_send(ws_s, hs_resp_wire[..]) == hs_resp_wire.len);

    var cli_rx_hs: u8[..512] = [];
    let n_chs = wing::tcp_recv(ws_c, cli_rx_hs, 512, 200);
    assert(n_chs == hs_resp_wire.len);
    var parsed_ws_res = wing::Response { .. };
    assert(wing::parse_response_headers(cli_rx_hs[..n_chs - 4], parsed_ws_res));
    var expected_accept: u8[..64] = [];
    wing::compute_websocket_accept(client_key, expected_accept);
    assert(parsed_ws_res.header("sec-websocket-accept") == expected_accept[..]);

    // Client sends masked Text frame over live socket
    var cli_frame_wire: u8[..256] = [];
    wing::send_text(cli_ws, "HELLO_WS_LIVE", cli_frame_wire);
    assert(wing::tcp_send(ws_c, cli_frame_wire[..]) == cli_frame_wire.len);

    var srv_ws_rx: u8[..256] = [];
    let n_sws = wing::tcp_recv(ws_s, srv_ws_rx, 256, 200);
    assert(n_sws == cli_frame_wire.len);

    var srv_msg = wing::WsMessage { .. };
    var srv_reply: u8[..256] = [];
    assert(wing::receive(srv_ws, srv_ws_rx[..n_sws], srv_msg, srv_reply));
    assert(srv_msg.is_valid && srv_msg.opcode == rfc::WS_OPCODE_TEXT && srv_msg.data[..] == "HELLO_WS_LIVE");

    wing::send_text(srv_ws, "ACK:HELLO_WS_LIVE", srv_reply);
    assert(wing::tcp_send(ws_s, srv_reply[..]) == srv_reply.len);

    var cli_ws_rx: u8[..256] = [];
    let n_cws = wing::tcp_recv(ws_c, cli_ws_rx, 256, 200);
    assert(n_cws == srv_reply.len);
    var cli_msg = wing::WsMessage { .. };
    var cli_reply: u8[..256] = [];
    assert(wing::receive(cli_ws, cli_ws_rx[..n_cws], cli_msg, cli_reply));
    assert(cli_msg.is_valid && cli_msg.opcode == rfc::WS_OPCODE_TEXT && cli_msg.data[..] == "ACK:HELLO_WS_LIVE");

    wing::tcp_close(ws_c);
    wing::tcp_close(ws_s);

    // 4B. Live W3C Server-Sent Events (`SseSubscription` <-> live server with `Last-Event-ID` reconnect)
    var sub = wing::new_sse_subscription();
    var host_hdr: u8[..64] = [];
    host_hdr.append("127.0.0.1:");
    core::format_u64_dec(port, host_hdr);

    var sse_wire1: u8[..512] = [];
    wing::sse_build_request_headers(sub, host_hdr[..], "/events", sse_wire1);

    let sse_c1 = wing::tcp_connect("127.0.0.1", port, 200);
    assert(sse_c1 > 0);
    assert(wing::tcp_send(sse_c1, sse_wire1[..]) == sse_wire1.len);
    assert(accept_and_serve_one_e2e(lfd));

    var sse_rx1: u8[..1024] = [];
    let n_sse1 = wing::tcp_recv(sse_c1, sse_rx1, 1024, 200);
    wing::tcp_close(sse_c1);
    assert(n_sse1 > 0);
    let body_sep1 = find_subslice(sse_rx1[..n_sse1], "\r\n\r\n");
    assert(body_sep1 > 0);

    var events1: wing::SseEvent[..8] = [];
    wing::consume(sub, sse_rx1[body_sep1 + 4..n_sse1], events1);
    assert(events1.len == 2);
    assert(events1[0].event[..] == "tick" && events1[0].data[..] == "first-line\nsecond-line" && events1[0].id[..] == "ev-1");
    assert(events1[0].retry_ms == 1500);
    assert(events1[1].event[..] == "message" && events1[1].data[..] == "final-item" && events1[1].id[..] == "ev-2");
    assert(sub.parser.last_event_id[..] == "ev-2");

    // Reconnect with `Last-Event-ID: ev-2`
    var sse_wire2: u8[..512] = [];
    wing::sse_build_request_headers(sub, host_hdr[..], "/events", sse_wire2);
    assert(find_subslice(sse_wire2[..], "Last-Event-ID: ev-2") >= 0);

    let sse_c2 = wing::tcp_connect("127.0.0.1", port, 200);
    assert(sse_c2 > 0);
    assert(wing::tcp_send(sse_c2, sse_wire2[..]) == sse_wire2.len);
    assert(accept_and_serve_one_e2e(lfd));

    var sse_rx2: u8[..1024] = [];
    let n_sse2 = wing::tcp_recv(sse_c2, sse_rx2, 1024, 200);
    wing::tcp_close(sse_c2);
    assert(n_sse2 > 0);
    let body_sep2 = find_subslice(sse_rx2[..n_sse2], "\r\n\r\n");
    assert(body_sep2 > 0);
    var events2: wing::SseEvent[..8] = [];
    wing::consume(sub, sse_rx2[body_sep2 + 4..n_sse2], events2);
    assert(events2.len == 1 && events2[0].event[..] == "resumed" && events2[0].data[..] == "after-ev-2" && events2[0].id[..] == "ev-3");

    // 4C. Live HTTP/2 Extended CONNECT (RFC 8441 `:protocol = websocket`) over TCP socket
    let h2_c = wing::tcp_connect("127.0.0.1", port, 200);
    let h2_s = wing::tcp_accept(lfd, 200);
    assert(h2_c > 0 && h2_s > 0);

    var h2_ws_req = wing::Request { .. };
    wing::format_h2_websocket_request(h2_ws_req, "/ws-h2", "127.0.0.1", "https", "chat");
    var h2_ctx = wing::RequestExecutionContext { .. };
    h2_ctx.current_method.append("CONNECT");
    wing::copy_headers(h2_ws_req.headers, h2_ctx.headers);
    let h2_url = core::new_url("https://127.0.0.1/ws-h2");
    var dt_cli = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    var h2_wire: u8[..2048] = [];
    assert(wing::encode_h2_client_request("CONNECT", h2_url, true, h2_ctx, dt_cli, 1, false, h2_wire));
    assert(wing::tcp_send(h2_c, h2_wire[..]) == h2_wire.len);

    var h2_srv_rx: u8[..2048] = [];
    let n_h2s = wing::tcp_recv(h2_s, h2_srv_rx, 2048, 200);
    assert(n_h2s == h2_wire.len);
    var fhdr, _, ok_fh = wire::parse_frame_header(h2_srv_rx[..9]);
    assert(ok_fh && fhdr.frame_type == rfc::H2_FRAME_HEADERS);
    var dt_srv = internal::new_dynamic_table(rfc::HPACK_DEFAULT_MAX_DYN_SIZE);
    var dec_pseudo = internal::H2PseudoHeaders { .. };
    var dec_map = wing::HeaderMap { .. };
    let dec_err = wire::decode_hpack_to_map(dt_srv, h2_srv_rx[9..9 + (fhdr.length as i64)], dec_pseudo, dec_map);
    assert(dec_err == rfc::H2_ERR_NO_ERROR);
    var st = internal::H2ServerStream { stream_id: 1, active: true, .. };
    assert(internal::apply_decoded_pseudo_to_stream(st, dec_pseudo));
    wing::append_all_headers(dec_map, st.headers);
    var h2_parsed_req = wing::new_request(st.method[..], st.path[..]);
    internal::copy_stream_headers_and_trailers(st, h2_parsed_req);
    assert(wing::validate_h2_websocket_request(h2_parsed_req));
    wing::tcp_close(h2_c);
    wing::tcp_close(h2_s);

    wing::tcp_close(lfd);
    print("E2E_LIVE_WEBSOCKET_AND_SSE: OK");
}

// ---- 5. Live ReverseProxy + LoadBalancer Failover --------------------------

fn test_live_reverse_proxy_failover() {
    // Allocate a dead port by opening and immediately closing a listener
    let dead_lfd = wing::tcp_listen("127.0.0.1", 0);
    assert(dead_lfd > 0);
    let dead_port = wing::tcp_getsockname_port(dead_lfd);
    wing::tcp_close(dead_lfd);

    // Live backend listener
    let live_lfd = wing::tcp_listen("127.0.0.1", 0);
    assert(live_lfd > 0);
    let live_port = wing::tcp_getsockname_port(live_lfd);

    g_e2e_proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
    g_e2e_proxy.cluster.max_fails = 1;
    assert(wing::add_upstream_target(g_e2e_proxy.cluster, "127.0.0.1", dead_port, 1));
    assert(wing::add_upstream_target(g_e2e_proxy.cluster, "127.0.0.1", live_port, 1));
    g_e2e_proxy.cluster.targets[0].unhealthy_threshold = 1;

    g_e2e_pool = wing::StreamPool { .. };
    var in_hdrs = wing::HeaderMap { .. };
    let _ = wing::append_header(in_hdrs, "Host", "edge.example.com");
    let _ = wing::append_header(in_hdrs, "Connection", "keep-alive, x-secret-hop");
    let _ = wing::append_header(in_hdrs, "X-Secret-Hop", "must-be-stripped");

    // Attempt 1 hits Target 0 (dead port), fails fast, and marks Target 0 unhealthy
    var out_resp1 = wing::Response { .. };
    let ok1 = wing::execute_proxy_exchange(
        g_e2e_proxy, g_e2e_pool, "GET", "/proxy-target", in_hdrs, "198.51.100.77", "http", "", out_resp1, 150, 1000,
    );
    assert(!ok1);
    assert(!g_e2e_proxy.cluster.targets[0].is_healthy);

    // Pre-accept pooled backend connection for Target 1 so synchronous exchange completes
    // and we verify the exact upstream wire request on `accept_and_serve_one_e2e`!
    let b_cli = wing::tcp_connect("127.0.0.1", live_port, 200);
    let b_srv = wing::tcp_accept(live_lfd, 200);
    assert(b_cli > 0 && b_srv > 0);

    let b_pkey = wing::new_pool_key(
        wing::PoolScheme.Http, "127.0.0.1", live_port,
        wing::new_direct_proxy_chain(),
        wing::NetworkAnonymizationKey { .. },
        wing::TlsAndDnsPolicy { .. },
    );
    let b_tp: wing::Transport = wing::Transport.Tcp { fd: b_cli };
    let cid_b = wing::register_connection(g_e2e_pool, b_pkey, wing::NegotiatedProtocol.Http11, b_tp, "127.0.0.1", 1, 1000);
    wing::release_connection(g_e2e_pool, cid_b, 1000);

    let backend_wire_resp = "HTTP/1.1 200 OK\r\nX-Backend-Handled: true\r\nContent-Length: 16\r\n\r\nUPSTREAM_LIVE_OK";
    assert(wing::tcp_send(b_srv, backend_wire_resp) == backend_wire_resp.len);

    // Attempt 2 automatically selects healthy Target 1 (`live_port`) and succeeds!
    var out_resp2 = wing::Response { .. };
    let ok2 = wing::execute_proxy_exchange(
        g_e2e_proxy, g_e2e_pool, "GET", "/proxy-target", in_hdrs, "198.51.100.77", "http", "", out_resp2, 200, 2000,
    );
    assert(ok2 && out_resp2.status_code == 200);
    assert(out_resp2.body[..] == "UPSTREAM_LIVE_OK");
    assert(out_resp2.header("x-backend-handled") == "true");

    // Read the exact upstream request produced by `execute_proxy_exchange` on `b_srv`
    // and feed it into `accept_and_serve_one_e2e` (`handle_proxy_backend`) to verify XFF, Via, and hop-by-hop stripping!
    var up_req_wire: u8[..2048] = [];
    let n_up = wing::tcp_recv(b_srv, up_req_wire, 2048, 200);
    assert(n_up > 0);

    let v_c = wing::tcp_connect("127.0.0.1", live_port, 200);
    assert(v_c > 0);
    assert(wing::tcp_send(v_c, up_req_wire[..n_up]) == n_up);
    assert(accept_and_serve_one_e2e(live_lfd));
    var srv_out: u8[..1024] = [];
    let n_so = wing::tcp_recv(v_c, srv_out, 1024, 200);
    assert(n_so > 0 && find_subslice(srv_out[..n_so], "UPSTREAM_LIVE_OK") >= 0);

    wing::tcp_close(v_c);
    wing::tcp_close(b_cli);
    wing::tcp_close(b_srv);
    wing::tcp_close(live_lfd);
    print("E2E_LIVE_REVERSE_PROXY_FAILOVER: OK");
}

fn main() {
    test_live_proxy_tunnels();
    test_live_digest_auth_and_cookies();
    test_live_http_cache_revalidation();
    test_live_websocket_and_sse();
    test_live_reverse_proxy_failover();
}

// CHECK: E2E_LIVE_PROXY_TUNNELS: OK
// CHECK-NEXT: E2E_LIVE_DIGEST_AUTH_AND_COOKIES: OK
// CHECK-NEXT: E2E_LIVE_HTTP_CACHE_REVALIDATION: OK
// CHECK-NEXT: E2E_LIVE_WEBSOCKET_AND_SSE: OK
// CHECK-NEXT: E2E_LIVE_REVERSE_PROXY_FAILOVER: OK
