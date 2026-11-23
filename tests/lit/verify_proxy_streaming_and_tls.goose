// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build -O0 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s
//
// Verification suite for Task 5: StreamRelayState, >16 KiB requests,
// WebSocket/SSE head parsing & UpgradePolicy, and upstream TLS + overflow.

import std;
import wing from "../..";

fn send_all_plain(fd: i64, data: const u8[:]) -> bool {
    var sent_total: i64 = 0;
    while sent_total < data.len {
        let n = net::tcp_send(fd, data[sent_total..]);
        guard n > 0 else { return false; }
        sent_total = core::add_sat_i64(sent_total, n);
    }
    return true;
}

fn extract_mock_content_length(head: const u8[:]) -> i64 {
    var tok = core::make_byte_tokenizer(head, '\n');
    loop {
        let raw_line, ok = core::token_next(tok);
        guard ok else { break; }
        let line = raw_line.trim_end_byte('\r');
        let name, val, has_col = line.split_once_byte(':');
        if has_col && name.trim_lws().eq_ascii_fold("content-length") {
            let cl_val, ok_cl = val.trim_lws().parse_i64_dec();
            if ok_cl {
                return cl_val;
            }
        }
    }
    return -1;
}

fn read_http_request_and_echo_len(fd: i64) {
    var buf:     u8[>..]  = [];
    var chunk:   u8[4096] = [0; 4096];
    var hdr_end: i64      = -1;
    while hdr_end < 0 {
        let n = net::tcp_recv_slice(fd, chunk[..], 5000);
        assert(n > 0);
        buf.append(chunk[..n]);
        hdr_end = core::fast_find_crlfcrlf(buf[..]);
    }
    let body_start = hdr_end + 4;
    let cl_val = extract_mock_content_length(buf[..hdr_end]);
    assert(cl_val >= 0);

    let need_total = body_start + cl_val;
    while buf.len < need_total {
        let n = net::tcp_recv_slice(fd, chunk[..], 5000);
        assert(n > 0);
        buf.append(chunk[..n]);
    }

    let body = buf[body_start..need_total];
    assert(body.len == cl_val);

    // Build response echoing back first 4 bytes, last 4 bytes, and total body length.
    var resp_body: u8[..64] = [];
    assert(resp_body.try_append("len="));
    cl_val.format_i64_dec(resp_body);
    if body.len >= 4 {
        assert(resp_body.try_append(":"));
        assert(resp_body.try_append(body[..4]));
        assert(resp_body.try_append(":"));
        assert(resp_body.try_append(body[^4..]));
    }

    var resp_wire: u8[..256] = [];
    assert(resp_wire.try_append("HTTP/1.1 200 OK\r\nContent-Length: "));
    resp_body.len.format_i64_dec(resp_wire);
    assert(resp_wire.try_append("\r\nConnection: close\r\n\r\n"));
    assert(resp_wire.try_append(resp_body[..]));
    assert(send_all_plain(fd, resp_wire[..]));
}

thread_fn mock_http_echo_server(listener_fd: i64) {
    // Expect 2 requests: (1) 64 KiB POST body, (2) 64-entry overflow fallback request.
    for _ in 2 {
        let conn = net::tcp_accept(listener_fd, 5000);
        assert(conn > 0);
        read_http_request_and_echo_len(conn);
        net::tcp_close(conn);
    }
}

thread_fn mock_https_upstream_server(listener_fd: i64) {
    let seed: u8[32] = [0x57; 32];
    var cert_der: u8[..2048] = [];
    assert(tls::build_test_ed25519_cert_der(
        seed,
        "upstream.internal.test",
        "upstream.internal.test",
        "127.0.0.1",
        cert_der,
    ));

    var srv_cfg = tls::ServerHandshakeConfig {
        priv_seed:            seed,
        handshake_timeout_ms: 5000,
        ..
    };
    assert(srv_cfg.cert_der.try_set(cert_der[..]));
    assert(srv_cfg.alpn.try_set("http/1.1"));

    // Conn 1: Pooled TLS upstream (serves 2 keep-alive requests on same TLS session).
    let conn1 = net::tcp_accept(listener_fd, 5000);
    assert(conn1 > 0);
    let slot1, ok_hs1 = tls::server_handshake(conn1, srv_cfg);
    assert(ok_hs1);
    assert(tls::g_tls_cipher_slots[slot1].server_name[..] == "upstream.internal.test");
    var trans1: net::Transport = net::Transport.Tls {
        fd:            conn1,
        record_seq_rx: 0,
        record_seq_tx: 0,
        cipher_slot:   slot1,
    };
    for _ in 2 {
        var rx1: u8[2048] = [0; 2048];
        let n1 = trans1.recv_slice(rx1[..], 5000);
        assert(n1 > 0);
        assert(core::starts_with(rx1[..n1], "GET /tls-hello HTTP/1.1\r\n"));
        assert(core::contains(rx1[..n1], "Host: 127.0.0.1:"));
        let ka_resp = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\n\r\ntls-ok-body";
        assert(wing::send_all(trans1, ka_resp));
    }
    trans1.close();

    // Conn 2: Full-pool overflow TLS upstream request.
    let conn2 = net::tcp_accept(listener_fd, 5000);
    assert(conn2 > 0);
    let slot2, ok_hs2 = tls::server_handshake(conn2, srv_cfg);
    assert(ok_hs2);
    assert(tls::g_tls_cipher_slots[slot2].server_name[..] == "upstream.internal.test");
    var trans2: net::Transport = net::Transport.Tls {
        fd:            conn2,
        record_seq_rx: 0,
        record_seq_tx: 0,
        cipher_slot:   slot2,
    };
    var rx2: u8[2048] = [0; 2048];
    let n2 = trans2.recv_slice(rx2[..], 5000);
    assert(n2 > 0);
    assert(core::starts_with(rx2[..n2], "GET /tls-hello HTTP/1.1\r\n"));
    assert(core::contains(rx2[..n2], "Host: 127.0.0.1:"));
    let close_resp = "HTTP/1.1 200 OK\r\nContent-Length: 11\r\nConnection: close\r\n\r\ntls-ok-body";
    assert(wing::send_all(trans2, close_resp));
    trans2.close();

    // Conn 3: Untrusted CA store -> client aborts handshake cleanly.
    let conn3 = net::tcp_accept(listener_fd, 5000);
    assert(conn3 > 0);
    let slot3, ok_hs3 = tls::server_handshake(conn3, srv_cfg);
    if ok_hs3 {
        tls::transport_close(conn3, slot3);
    } else {
        net::tcp_close(conn3);
    }
}

fn count_active_tls_slots() -> i64 {
    var active: i64 = 0;
    for &slot in tls::g_tls_cipher_slots {
        if slot.in_use {
            active = core::add_sat_i64(active, 1);
        }
    }
    return active;
}

fn fill_pool_with_64_active_slots(pool: net::StreamPool&) {
    let dummy_key = net::new_pool_key(
        net::PoolScheme.Http,
        "occupied.internal",
        8080,
        net::new_direct_proxy_chain(),
        net::NetworkAnonymizationKey { .. },
        net::TlsAndDnsPolicy { .. },
    );
    for i in 64 {
        let cid = net::register_connection(
            pool,
            dummy_key,
            net::NegotiatedProtocol.Http11,
            net::Transport.Mock { route_idx: 0, cursor: 0 },
            "",
            1,
            1000 + i,
        );
        assert(cid > 0);
    }
    assert(pool.conns.len == 64);
}

fn test_64k_post_body_and_pool_overflow() {
    let listener = net::tcp_listen("127.0.0.1", 0, 16);
    assert(listener > 0);
    let port = net::tcp_getsockname_port(listener);
    assert(port > 0);

    let tid = thread_spawn(mock_http_echo_server, listener);

    var rp = proxy::new_reverse_proxy(proxy::LbPolicy.RoundRobin);
    assert(proxy::add_upstream_target(rp.cluster, "127.0.0.1", port, 1));
    assert(proxy::register_target_for_probing(rp.health_checker, 0));

    var body_64k: u8[>..] = [];
    assert(body_64k.try_append("HEAD"));
    for _ in 65528 {
        body_64k.push('Z');
    }
    assert(body_64k.try_append("TAIL"));
    assert(body_64k.len == 65536);

    var in_headers = http::HeaderMap { .. };
    assert(http::append_header(in_headers, "Host", "edge.example.com"));

    var pool = net::new_stream_pool(6, 32, 64);
    var out_resp = http::Response { .. };
    assert(proxy::execute_proxy_exchange_with_key(
        rp,
        pool,
        "POST",
        "/upload",
        in_headers,
        "192.0.2.50",
        "https",
        "key-64k",
        body_64k[..],
        out_resp,
        5000,
        1000000000,
    ));
    assert(out_resp.status_code == 200);
    assert(out_resp.body[..] == "len=65536:HEAD:TAIL");

    // Verify max_buffered_body_bytes cap rejects oversized body without dialing.
    rp.config.max_buffered_body_bytes = 1024;
    var capped_resp = http::Response { .. };
    assert(!proxy::execute_proxy_exchange_with_key(
        rp,
        pool,
        "POST",
        "/upload",
        in_headers,
        "192.0.2.50",
        "https",
        "key-cap",
        body_64k[..],
        capped_resp,
        5000,
        1000000001,
    ));

    // Verify full 64-entry StreamPool falls back to non-pooled connection cleanly.
    rp.config.max_buffered_body_bytes = 1048576;
    var full_pool = net::new_stream_pool(64, 64, 64);
    net::configure_stream_pool(full_pool, 64, false);
    fill_pool_with_64_active_slots(full_pool);

    var overflow_resp = http::Response { .. };
    assert(proxy::execute_proxy_exchange_with_key(
        rp,
        full_pool,
        "POST",
        "/overflow",
        in_headers,
        "192.0.2.50",
        "http",
        "key-ovf",
        "ABCD1234",
        overflow_resp,
        5000,
        1000000002,
    ));
    assert(overflow_resp.status_code == 200);
    assert(overflow_resp.body[..] == "len=8:ABCD:1234");
    assert(full_pool.conns.len == 64);

    assert(thread_wait(tid));
    net::tcp_close(listener);

    print("PROXY_64K_POST_AND_OVERFLOW: ok\n");
    // CHECK: PROXY_64K_POST_AND_OVERFLOW: ok
}

fn test_websocket_upgrade_policy_and_prepare_head() {
    var rp = proxy::new_reverse_proxy(proxy::LbPolicy.ConsistentHash);
    assert(proxy::add_upstream_target(rp.cluster, "ws-backend.internal", 8080, 1));
    rp.config.upgrade_policy = proxy::UpgradePolicy.AllowWebSocket;

    var in_hdrs = http::HeaderMap { .. };
    assert(http::append_header(in_hdrs, "Host", "edge.example.com"));
    assert(http::append_header(in_hdrs, "Connection", "Upgrade, X-Secret-Hop"));
    assert(http::append_header(in_hdrs, "Upgrade", "websocket"));
    assert(http::append_header(in_hdrs, "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="));
    assert(http::append_header(in_hdrs, "Sec-WebSocket-Version", "13"));
    assert(http::append_header(in_hdrs, "Sec-WebSocket-Protocol", "chat"));
    assert(http::append_header(in_hdrs, "X-Secret-Hop", "must-be-stripped"));
    assert(http::append_header(in_hdrs, "Keep-Alive", "timeout=5"));

    var head_wire: u8[>..] = [];
    let t_idx, ok = proxy::prepare_proxy_head_with_key_at(
        rp,
        "GET",
        "/ws",
        in_hdrs,
        "203.0.113.9",
        "https",
        "room-1",
        head_wire,
        1000000000,
    );
    assert(ok && t_idx == 0);
    assert(core::contains(head_wire[..], "Connection: Upgrade\r\n"));
    assert(core::contains(head_wire[..], "Upgrade: websocket\r\n"));
    assert(core::contains(head_wire[..], "Sec-WebSocket-Key: dGhlIHNhbXBsZSBub25jZQ==\r\n"));
    assert(core::contains(head_wire[..], "Sec-WebSocket-Version: 13\r\n"));
    assert(core::contains(head_wire[..], "Sec-WebSocket-Protocol: chat\r\n"));
    assert(!core::contains(head_wire[..], "X-Secret-Hop"));
    assert(!core::contains(head_wire[..], "must-be-stripped"));
    assert(!core::contains(head_wire[..], "Keep-Alive"));
    proxy::release_upstream_connection(rp.cluster, t_idx);

    // Strip policy (default) strips Connection and Upgrade even on valid WS headers.
    rp.config.upgrade_policy = proxy::UpgradePolicy.Strip;
    var strip_wire: u8[>..] = [];
    let s_idx, ok_strip = proxy::prepare_proxy_head_with_key_at(
        rp,
        "GET",
        "/ws",
        in_hdrs,
        "203.0.113.9",
        "https",
        "room-1",
        strip_wire,
        1000000001,
    );
    assert(ok_strip && s_idx == 0);
    assert(!core::contains(strip_wire[..], "Upgrade: websocket"));
    assert(!core::contains(strip_wire[..], "Connection: Upgrade"));
    proxy::release_upstream_connection(rp.cluster, s_idx);

    // Invalid WebSocket version ("12") under AllowWebSocket strips Connection/Upgrade.
    rp.config.upgrade_policy = proxy::UpgradePolicy.AllowWebSocket;
    var bad_ws_hdrs = http::HeaderMap { .. };
    assert(http::append_header(bad_ws_hdrs, "Host", "edge.example.com"));
    assert(http::append_header(bad_ws_hdrs, "Connection", "Upgrade"));
    assert(http::append_header(bad_ws_hdrs, "Upgrade", "websocket"));
    assert(http::append_header(bad_ws_hdrs, "Sec-WebSocket-Key", "dGhlIHNhbXBsZSBub25jZQ=="));
    assert(http::append_header(bad_ws_hdrs, "Sec-WebSocket-Version", "12"));
    var bad_wire: u8[>..] = [];
    let b_idx, ok_bad = proxy::prepare_proxy_head_with_key_at(
        rp,
        "GET",
        "/ws",
        bad_ws_hdrs,
        "203.0.113.9",
        "https",
        "room-1",
        bad_wire,
        1000000002,
    );
    assert(ok_bad && b_idx == 0);
    assert(!core::contains(bad_wire[..], "Upgrade: websocket"));
    assert(!core::contains(bad_wire[..], "Connection: Upgrade"));
    proxy::release_upstream_connection(rp.cluster, b_idx);

    // Streaming request head with Content-Length: 65536 succeeds without buffering body.
    var stream_hdrs = http::HeaderMap { .. };
    assert(http::append_header(stream_hdrs, "Host", "edge.example.com"));
    assert(http::append_header(stream_hdrs, "Content-Length", "65536"));
    var stream_head: u8[>..] = [];
    let st_idx, ok_st = proxy::prepare_proxy_head_with_key_at(
        rp,
        "POST",
        "/stream-in",
        stream_hdrs,
        "203.0.113.9",
        "https",
        "stream-1",
        stream_head,
        1000000003,
    );
    assert(ok_st && st_idx == 0);
    assert(core::contains(stream_head[..], "Content-Length: 65536\r\n"));
    assert(core::ends_with(stream_head[..], "\r\n\r\n"));
    proxy::release_upstream_connection(rp.cluster, st_idx);

    print("WS_UPGRADE_AND_PREPARE_HEAD: ok\n");
    // CHECK: WS_UPGRADE_AND_PREPARE_HEAD: ok
}

fn test_parse_upstream_response_head() {
    var res = proxy::UpstreamHeadResult { .. };

    // 1. Incomplete head -> 0.
    assert(proxy::parse_upstream_response_head("HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n", "GET", res) == 0);

    // 2. 101 Switching Protocols -> 1, is_upgrade_101 == true, preserves Upgrade/Connection.
    let ws_101 = "HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: s3pPLMBiTxaQ9kYGzzhZRbK+xOo=\r\n\r\nWS_DATA";
    assert(proxy::parse_upstream_response_head(ws_101, "GET", res) == 1);
    assert(res.status_code == 101);
    assert(res.is_upgrade_101);
    assert(!res.keep_alive);
    assert(ws_101[res.body_offset..] == "WS_DATA");
    assert(http::get_header(res.headers, "Connection") == "Upgrade");
    assert(http::get_header(res.headers, "Upgrade") == "websocket");
    assert(http::get_header(res.headers, "Sec-WebSocket-Accept") == "s3pPLMBiTxaQ9kYGzzhZRbK+xOo=");

    // 3. 200 OK + Content-Type: text/event-stream; charset=utf-8 -> is_sse == true, disable_buffering == true.
    let sse_raw = "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream; charset=utf-8\r\nTransfer-Encoding: chunked\r\n\r\n5\r\ndata\n\r\n0\r\n\r\n";
    assert(proxy::parse_upstream_response_head(sse_raw, "GET", res) == 1);
    assert(res.status_code == 200);
    assert(res.is_sse);
    assert(res.accel.disable_buffering);
    assert(res.is_chunked);
    assert(res.content_length == -1);
    assert(res.keep_alive);
    assert(core::starts_with(sse_raw[res.body_offset..], "5\r\ndata\n\r\n"));

    // 4. Skipping 100 Continue + 103 Early Hints before 200 OK computes exact body_offset & hints.
    let hints_raw = "HTTP/1.1 100 Continue\r\n\r\nHTTP/1.1 103 Early Hints\r\nLink: </style.css>; rel=preload; as=style\r\n\r\nHTTP/1.1 200 OK\r\nContent-Length: 4\r\nX-Accel-Buffering: no\r\n\r\nPONG";
    assert(proxy::parse_upstream_response_head(hints_raw, "GET", res) == 1);
    assert(res.status_code == 200);
    assert(res.has_early_hints);
    assert(res.early_hints.links.len == 1);
    assert(res.early_hints.links[0].uri[..] == "/style.css");
    assert(res.accel.disable_buffering);
    assert(res.content_length == 4);
    assert(!res.is_chunked);
    assert(hints_raw[res.body_offset..] == "PONG");

    // 5. HEAD and 204/304 have no body on wire (content_length = 0, is_chunked = false).
    let head_raw = "HTTP/1.1 200 OK\r\nContent-Length: 4096\r\n\r\n";
    assert(proxy::parse_upstream_response_head(head_raw, "HEAD", res) == 1);
    assert(res.content_length == 0);
    assert(!res.is_chunked);
    assert(http::get_header(res.headers, "Content-Length") == "4096");

    let no_content_raw = "HTTP/1.1 204 No Content\r\n\r\n";
    assert(proxy::parse_upstream_response_head(no_content_raw, "GET", res) == 1);
    assert(res.status_code == 204);
    assert(res.content_length == 0);
    assert(!res.is_chunked);

    // 6. TE + CL conflict MUST return -1 (RFC 9112 Section 6.3) and reset out_res.
    let smuggle_raw = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Length: 5\r\n\r\n5\r\nhello\r\n0\r\n\r\n";
    assert(proxy::parse_upstream_response_head(smuggle_raw, "GET", res) == -1);
    assert(res.status_code == 0);

    // 7. Conflicting duplicate Content-Length values MUST return -1.
    let dup_cl_raw = "HTTP/1.1 200 OK\r\nContent-Length: 5\r\nContent-Length: 10\r\n\r\nhello";
    assert(proxy::parse_upstream_response_head(dup_cl_raw, "GET", res) == -1);

    // 8. Oversized header block (> 64 KiB without terminator) MUST return -1.
    var oversized_raw: u8[>..] = [];
    assert(oversized_raw.try_append("HTTP/1.1 200 OK\r\nX-Big: "));
    for _ in 65540 {
        oversized_raw.push('A');
    }
    assert(proxy::parse_upstream_response_head(oversized_raw[..], "GET", res) == -1);

    print("PARSE_UPSTREAM_RESPONSE_HEAD: ok\n");
    // CHECK: PARSE_UPSTREAM_RESPONSE_HEAD: ok
}

fn test_stream_relay_state_modes_and_wraparound() {
    // 1. FixedLength > 16 KiB across partial writes and ring wraparounds.
    let total_fixed: i64 = 24000;
    var payload: u8[>..] = [];
    for i in total_fixed {
        payload.push(('A' + (i % 26)) as u8);
    }
    var st_fixed = proxy::relay_init(
        proxy::StreamBodyMode.FixedLength, total_fixed,
        proxy::StreamBodyMode.UntilEof, 0,
    );
    var fed_c:     i64     = 0;
    var relayed_u: u8[>..] = [];
    while !st_fixed.req_done {
        if fed_c < payload.len {
            let acc, ok_f = proxy::relay_feed_client(st_fixed, payload[fed_c..]);
            assert(ok_f);
            fed_c = core::add_sat_i64(fed_c, acc);
        }
        let drain_slice = proxy::relay_drain_to_upstream(st_fixed);
        if drain_slice.len > 0 {
            let step = min(drain_slice.len, 5000);
            relayed_u.append(drain_slice[..step]);
            assert(proxy::relay_advance_upstream(st_fixed, step));
        }
    }
    while proxy::relay_drain_to_upstream(st_fixed).len > 0 {
        let rem = proxy::relay_drain_to_upstream(st_fixed);
        relayed_u.append(rem);
        assert(proxy::relay_advance_upstream(st_fixed, rem.len));
    }
    assert(fed_c == total_fixed);
    assert(st_fixed.req_remaining == 0);
    assert(st_fixed.req_done);
    assert(relayed_u[..] == payload[..]);

    // 2. Chunked > 16 KiB across ring wraparounds + malformed rejection.
    var big_chunk_wire: u8[>..] = [];
    assert(big_chunk_wire.try_append("2710\r\n")); // 10000 bytes
    for i in 10000 {
        big_chunk_wire.push(('a' + (i % 26)) as u8);
    }
    assert(big_chunk_wire.try_append("\r\n2710\r\n")); // another 10000 bytes
    for i in 10000 {
        big_chunk_wire.push(('0' + (i % 10)) as u8);
    }
    assert(big_chunk_wire.try_append("\r\n0\r\n\r\n"));

    var st_chunk = proxy::relay_init(
        proxy::StreamBodyMode.FixedLength, 0,
        proxy::StreamBodyMode.Chunked, 0,
    );
    assert(st_chunk.req_done);
    var fed_u:         i64     = 0;
    var relayed_chunk: u8[>..] = [];
    while !st_chunk.resp_done {
        if fed_u < big_chunk_wire.len {
            let acc, ok_fu = proxy::relay_feed_upstream(st_chunk, big_chunk_wire[fed_u..]);
            assert(ok_fu);
            fed_u = core::add_sat_i64(fed_u, acc);
        }
        let d = proxy::relay_drain_to_client(st_chunk);
        if d.len > 0 {
            let take = min(d.len, 4096);
            relayed_chunk.append(d[..take]);
            assert(proxy::relay_advance_client(st_chunk, take));
        }
    }
    while proxy::relay_drain_to_client(st_chunk).len > 0 {
        let rem = proxy::relay_drain_to_client(st_chunk);
        relayed_chunk.append(rem);
        assert(proxy::relay_advance_client(st_chunk, rem.len));
    }
    assert(fed_u == big_chunk_wire.len);
    assert(st_chunk.resp_done);
    assert(relayed_chunk[..] == big_chunk_wire[..]);

    // Malformed chunk framing MUST fail closed (0, false).
    var st_bad = proxy::relay_init(
        proxy::StreamBodyMode.Chunked, 0,
        proxy::StreamBodyMode.FixedLength, 0,
    );
    let bad_acc, bad_ok = proxy::relay_feed_client(st_bad, "ZZZZ\r\n");
    assert(!bad_ok && bad_acc == 0);

    // 3. Full-duplex RawTunnel across > 16 KiB ring wraparounds.
    var st_tun = proxy::relay_init(
        proxy::StreamBodyMode.RawTunnel, 0,
        proxy::StreamBodyMode.RawTunnel, 0,
    );
    var c2u_in: u8[>..] = [];
    var u2c_in: u8[>..] = [];
    for i in 20000 {
        c2u_in.push((i & 0xFF) as u8);
        u2c_in.push(((i ^ 0xA5) & 0xFF) as u8);
    }
    var c2u_fed: i64     = 0;
    var u2c_fed: i64     = 0;
    var c2u_out: u8[>..] = [];
    var u2c_out: u8[>..] = [];
    while c2u_out.len < c2u_in.len || u2c_out.len < u2c_in.len {
        if c2u_fed < c2u_in.len {
            let n, ok_c = proxy::relay_feed_client(st_tun, c2u_in[c2u_fed..]);
            assert(ok_c);
            c2u_fed = core::add_sat_i64(c2u_fed, n);
        }
        if u2c_fed < u2c_in.len {
            let n, ok_u = proxy::relay_feed_upstream(st_tun, u2c_in[u2c_fed..]);
            assert(ok_u);
            u2c_fed = core::add_sat_i64(u2c_fed, n);
        }
        let du = proxy::relay_drain_to_upstream(st_tun);
        if du.len > 0 {
            let step = min(du.len, 3000);
            c2u_out.append(du[..step]);
            assert(proxy::relay_advance_upstream(st_tun, step));
        }
        let dc = proxy::relay_drain_to_client(st_tun);
        if dc.len > 0 {
            let step = min(dc.len, 3500);
            u2c_out.append(dc[..step]);
            assert(proxy::relay_advance_client(st_tun, step));
        }
    }
    assert(c2u_out[..] == c2u_in[..]);
    assert(u2c_out[..] == u2c_in[..]);

    // 4. UntilEof mode + exact partial ring fill (16384 accepted out of 20000, zero silent drops).
    var st_eof = proxy::relay_init(
        proxy::StreamBodyMode.FixedLength, 0,
        proxy::StreamBodyMode.UntilEof, 0,
    );
    let acc1, ok1 = proxy::relay_feed_upstream(st_eof, u2c_in[..]);
    assert(ok1 && acc1 == 16384);
    let acc_full, ok_full = proxy::relay_feed_upstream(st_eof, u2c_in[acc1..]);
    assert(ok_full && acc_full == 0);

    var eof_out: u8[>..] = [];
    let d1 = proxy::relay_drain_to_client(st_eof);
    assert(d1.len == 16384);
    eof_out.append(d1);
    assert(proxy::relay_advance_client(st_eof, d1.len));

    let acc2, ok2 = proxy::relay_feed_upstream(st_eof, u2c_in[acc1..]);
    assert(ok2 && acc2 == 3616);
    let d2 = proxy::relay_drain_to_client(st_eof);
    assert(d2.len == 3616);
    eof_out.append(d2);
    assert(proxy::relay_advance_client(st_eof, d2.len));
    assert(eof_out[..] == u2c_in[..]);

    print("STREAM_RELAY_MODES_WRAPAROUND: ok\n");
    // CHECK: STREAM_RELAY_MODES_WRAPAROUND: ok
}

fn test_upstream_tls_exchange_and_overflow() {
    let seed: u8[32] = [0x57; 32];
    var cert_der: u8[..2048] = [];
    assert(tls::build_test_ed25519_cert_der(
        seed,
        "upstream.internal.test",
        "upstream.internal.test",
        "127.0.0.1",
        cert_der,
    ));
    var trust = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(trust, cert_der[..]));

    let other_seed: u8[32] = [0x88; 32];
    var other_cert: u8[..2048] = [];
    assert(tls::build_test_ed25519_cert_der(
        other_seed,
        "wrong.internal.test",
        "wrong.internal.test",
        "",
        other_cert,
    ));
    var wrong_trust = tls::TrustAnchorStore { .. };
    assert(tls::add_trust_anchor_cert_der(wrong_trust, other_cert[..]));

    let listener = net::tcp_listen("127.0.0.1", 0, 16);
    assert(listener > 0);
    let port = net::tcp_getsockname_port(listener);
    assert(port > 0);

    let tid = thread_spawn(mock_https_upstream_server, listener);

    var rp = proxy::new_reverse_proxy(proxy::LbPolicy.RoundRobin);
    rp.ca_store .= trust;
    assert(proxy::add_upstream_target_tls(
        rp.cluster, "127.0.0.1", port, 1, true, "upstream.internal.test",
    ));

    var in_hdr = http::HeaderMap { .. };
    assert(http::append_header(in_hdr, "Host", "edge.example.com"));

    // 1. Pooled TLS 1.3 exchange + keep-alive reuse keyed by PoolScheme.Https and sni_host.
    var pool = net::new_stream_pool(6, 32, 64);
    var resp1 = http::Response { .. };
    assert(proxy::execute_proxy_exchange_with_key(
        rp, pool, "GET", "/tls-hello", in_hdr, "192.0.2.1", "https", "tls-k1", "", resp1, 5000, 1000000000,
    ));
    assert(resp1.status_code == 200);
    assert(resp1.body[..] == "tls-ok-body");
    assert(pool.conns.len == 1);
    assert(pool.conns[0].key.scheme == net::PoolScheme.Https);
    assert(pool.conns[0].key.origin_endpoint.host[..] == "upstream.internal.test");

    var resp1_reuse = http::Response { .. };
    assert(proxy::execute_proxy_exchange_with_key(
        rp, pool, "GET", "/tls-hello", in_hdr, "192.0.2.1", "https", "tls-k1", "", resp1_reuse, 5000, 1000000000,
    ));
    assert(resp1_reuse.status_code == 200);
    assert(resp1_reuse.body[..] == "tls-ok-body");
    assert(pool.conns.len == 1);
    assert(pool.conns[0].use_count == 2);
    net::drain_stream_pool(pool);

    // 2. Full 64-entry StreamPool overflow over TLS -> succeeds and closes TLS slot cleanly.
    var full_pool = net::new_stream_pool(64, 64, 64);
    net::configure_stream_pool(full_pool, 64, false);
    fill_pool_with_64_active_slots(full_pool);
    var resp2 = http::Response { .. };
    assert(proxy::execute_proxy_exchange_with_key(
        rp, full_pool, "GET", "/tls-hello", in_hdr, "192.0.2.1", "https", "tls-k2", "", resp2, 5000, 1000000001,
    ));
    assert(resp2.status_code == 200);
    assert(resp2.body[..] == "tls-ok-body");
    assert(full_pool.conns.len == 64);

    // 3. Untrusted CA store fails closed and leaks 0 TLS cipher slots.
    rp.ca_store .= wrong_trust;
    var resp3 = http::Response { .. };
    assert(!proxy::execute_proxy_exchange_with_key(
        rp, pool, "GET", "/tls-hello", in_hdr, "192.0.2.1", "https", "tls-k3", "", resp3, 5000, 1000000002,
    ));

    assert(thread_wait(tid));
    net::tcp_close(listener);
    assert(count_active_tls_slots() == 0);

    print("UPSTREAM_TLS_EXCHANGE_AND_OVERFLOW: ok\n");
    // CHECK: UPSTREAM_TLS_EXCHANGE_AND_OVERFLOW: ok
}

fn main() {
    test_64k_post_body_and_pool_overflow();
    test_websocket_upgrade_policy_and_prepare_head();
    test_parse_upstream_response_head();
    test_stream_relay_state_modes_and_wraparound();
    test_upstream_tls_exchange_and_overflow();
}
