// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Standalone Native Goose-Wing Client for Toxiproxy Chaos & Resilience Testing.
// Exercises real `wing::Session` (HTTP/1.1, chunked, redirects, CookieJar, Keep-Alive pool,
// automatic retries, and HTTP/2 client multiplexing) through live Toxiproxy fault injection.
import std;
import core from "../..";
import wing from "../..";

var g_chaos_proxy: proxy::ReverseProxy = proxy::ReverseProxy { .. };
var g_chaos_pool:  wing::StreamPool    = wing::StreamPool { .. };

fn make_chaos_client(port: u16) -> wing::Client {
    var base: u8[..128] = [];
    base.append("http://127.0.0.1:");
    core::format_u64_dec(port, base);

    var s = wing::new_client(wing::ClientConfig {
        base_url:         base[..],
        timeout_ms:       4000,
        follow_redirects: true,
        cookie_jar:       true,
        ..
    });
    s.ssrf_guard.enabled = false;
    return s;
}

// Mode 1: HTTP/1.1 GET, POST, POST chunked, and chunked response + trailer decoding under SlicerToxic
fn run_mode_h1_slicer_and_chunked(port: u16) -> bool {
    var s = make_chaos_client(port);

    let r1, e1 = wing::get(s, "/ping");
    guard wing::ok(e1) && r1.status_code == 200 && r1.body[..] == "OK" else {
        print("FAIL:MODE1_GET_PING\n");
        return false;
    }

    let r2, e2 = wing::post(s, "/echo") { req =>
        wing::text(req, "NativeGooseClientPostBody_12345");
    };
    guard wing::ok(e2) && r2.status_code == 200 && r2.body[..] == "ECHO:NativeGooseClientPostBody_12345" else {
        print("FAIL:MODE1_POST_ECHO status=", r2.status_code, " err=", e2.message[..], " body=", r2.body[..], "\n");
        return false;
    }

    let r3, e3 = wing::post_chunked(s, "/echo") { w =>
        wing::write_chunk(w, "ChunkPartOne_");
        wing::write_chunk(w, "ChunkPartTwo_99");
    };
    guard wing::ok(e3) && r3.status_code == 200 && r3.body[..] == "ECHO:ChunkPartOne_ChunkPartTwo_99" else {
        print("FAIL:MODE1_POST_CHUNKED status=", r3.status_code, " err=", e3.message[..], " body=", r3.body[..], "\n");
        return false;
    }

    let r4, e4 = wing::get(s, "/chunked-resp");
    let tr_val = wing::get_header(r4.trailers, "X-Chaos-Trailer");
    guard wing::ok(e4) && r4.status_code == 200 && r4.body[..] == "CHUNK_A_CHUNK_B" && tr_val == "verified" else {
        print("FAIL:MODE1_RECV_CHUNKED_TRAILER status=", r4.status_code, " err=", e4.message[..], " body=", r4.body[..], " tr=", tr_val, "\n");
        return false;
    }

    print("PASS:MODE1_H1_SLICER_AND_CHUNKED\n");
    return true;
}

// Mode 2: 302 Redirect chain + Set-Cookie persistence in CookieJar under SlicerToxic + LatencyToxic
fn run_mode_redirect_and_cookies(port: u16) -> bool {
    var s = make_chaos_client(port);
    let r, err = wing::get(s, "/redirect-start");
    guard wing::ok(err) && r.status_code == 200 && r.redirect_count == 1 && r.body[..] == "REDIRECT_COOKIE_OK" else {
        print("FAIL:MODE2_REDIRECT_COOKIE status=", r.status_code, " redir=", r.redirect_count, " err=", err.message[..], " body=", r.body[..], "\n");
        return false;
    }
    guard s.jar.cookies.len == 1 && s.jar.cookies[0].value[..] == "token_99" else {
        print("FAIL:MODE2_JAR_STATE len=", s.jar.cookies.len, "\n");
        return false;
    }
    print("PASS:MODE2_REDIRECT_AND_COOKIES\n");
    return true;
}

// Mode 3: Keep-Alive connection pool socket reuse under BandwidthToxic + SlowCloseToxic
fn run_mode_keepalive_pool(port: u16) -> bool {
    var s = make_chaos_client(port);
    let r1, e1 = wing::get(s, "/keepalive");
    guard wing::ok(e1) && r1.status_code == 200 && r1.body[..] == "KEEPALIVE_OK" else {
        print("FAIL:MODE3_KA_FIRST status=", r1.status_code, " err=", e1.message[..], "\n");
        return false;
    }
    let r2, e2 = wing::get(s, "/keepalive");
    guard wing::ok(e2) && r2.status_code == 200 && r2.body[..] == "KEEPALIVE_OK" else {
        print("FAIL:MODE3_KA_SECOND status=", r2.status_code, " err=", e2.message[..], "\n");
        return false;
    }
    guard s.pool.conns.len == 1 && s.pool.conns[0].use_count >= 2 else {
        print("FAIL:MODE3_POOL_NOT_REUSED conns=", s.pool.conns.len, "\n");
        return false;
    }
    print("PASS:MODE3_KEEPALIVE_POOL\n");
    return true;
}

// Mode 4: Automatic retry policy recovering from 503 Service Unavailable under SlicerToxic
fn run_mode_retry_recovery(port: u16) -> bool {
    var s = make_chaos_client(port);
    wing::add_retry(s.pipeline, 3, true);
    let r, err = wing::get(s, "/flaky");
    guard wing::ok(err) && r.status_code == 200 && r.body[..] == "RETRY_RECOVERED_OK" else {
        print("FAIL:MODE4_RETRY_RECOVERY status=", r.status_code, " err=", err.message[..], " body=", r.body[..], "\n");
        return false;
    }
    print("PASS:MODE4_RETRY_RECOVERY\n");
    return true;
}

// Mode 5: Native HTTP/2 client (prior knowledge) multi-stream reuse under SlicerToxic
fn run_mode_h2_client_slicer(port: u16) -> bool {
    var s = make_chaos_client(port);
    s.http2_prior_knowledge = true;

    let r1, e1 = wing::post(s, "/echo") { req =>
        wing::text(req, "H2ClientSlicedPayload_777");
    };
    guard wing::ok(e1) && r1.status_code == 200 && r1.protocol[..] == "HTTP/2" &&
          r1.body[..] == "ECHO:H2ClientSlicedPayload_777" else {
        print("FAIL:MODE5_H2_POST status=", r1.status_code, " err=", e1.message[..], " body=", r1.body[..], "\n");
        return false;
    }

    let r2, e2 = wing::get(s, "/ping");
    guard wing::ok(e2) && r2.status_code == 200 && r2.protocol[..] == "HTTP/2" && r2.body[..] == "OK" else {
        print("FAIL:MODE5_H2_GET status=", r2.status_code, " err=", e2.message[..], " body=", r2.body[..], "\n");
        return false;
    }
    guard s.pool.conns.len == 1 && s.pool.conns[0].next_h2_stream_id == 5 else {
        print("FAIL:MODE5_H2_STREAM_REUSE\n");
        return false;
    }
    print("PASS:MODE5_H2_CLIENT_SLICER\n");
    return true;
}

// Mode 6: Truncated response / ResetPeer detection and pool eviction under LimitDataToxic
fn run_mode_truncation_eviction(port: u16) -> bool {
    var s = make_chaos_client(port);
    s.timeout_ms = 1500;
    let _, err = wing::post(s, "/echo") { req =>
        wing::text(req, "PayloadThatWillBeTruncatedMidStreamByLimitDataToxic_1234567890");
    };
    guard !wing::ok(err) && s.pool.conns.len == 1 && s.pool.conns[0].closed else {
        print("FAIL:MODE6_TRUNCATION_NOT_DETECTED ok=", wing::ok(err), " len=", s.pool.conns.len, "\n");
        return false;
    }
    print("PASS:MODE6_TRUNCATION_EVICTION\n");
    return true;
}

// Mode 7: TimeoutToxic (Blackhole) read-deadline enforcement & dead socket eviction from pool
fn run_mode_timeout_eviction(port: u16) -> bool {
    var s = make_chaos_client(port);
    s.timeout_ms = 350;
    let _, err = wing::get(s, "/ping");
    guard !wing::ok(err) && s.pool.conns.len == 1 && s.pool.conns[0].closed else {
        print("FAIL:MODE7_TIMEOUT_EVICTION ok=", wing::ok(err), " len=", s.pool.conns.len, "\n");
        return false;
    }
    print("PASS:MODE7_TIMEOUT_EVICTION\n");
    return true;
}

// Mode 8: POST with Idempotency-Key + rewind_buf body rewind across 503 failure under Slicer + Latency
fn run_mode_idempotent_post_rewind(port: u16) -> bool {
    var s = make_chaos_client(port);
    wing::add_retry(s.pipeline, 3, true);
    let r, err = wing::post(s, "/flaky-post") { req =>
        wing::set_header(req, "Idempotency-Key", "idem-chaos-88");
        wing::text(req, "RewindablePostBodyUnderChaos_42");
    };
    guard wing::ok(err) && r.status_code == 200 &&
          r.body[..] == "IDEM_POST_OK:RewindablePostBodyUnderChaos_42" else {
        print("FAIL:MODE8_IDEM_POST status=", r.status_code, " err=", err.message[..], " body=", r.body[..], "\n");
        return false;
    }
    print("PASS:MODE8_IDEM_POST_REWIND\n");
    return true;
}

// Mode 9: 401 Digest SHA-256 Challenge-Response + Set-Cookie persistence over Keep-Alive under Slicer + Latency
fn run_mode_digest_auth_and_cookies(port: u16) -> bool {
    var s = make_chaos_client(port);
    let _ = s.creds.username.try_set("admin");
    let _ = s.creds.password.try_set("hunter2");
    s.creds.has_credentials = true;

    let r, err = wing::get(s, "/digest-chaos");
    guard wing::ok(err) && r.status_code == 200 && r.body[..] == "DIGEST_CHAOS_OK" else {
        print("FAIL:MODE9_DIGEST status=", r.status_code, " err=", err.message[..], " body=", r.body[..], "\n");
        return false;
    }
    guard cookie::get(s.jar, "auth_sid") == "dig_77" &&
          s.pool.conns.len == 1 && s.pool.conns[0].use_count >= 2 else {
        print("FAIL:MODE9_JAR_OR_POOL\n");
        return false;
    }
    print("PASS:MODE9_DIGEST_AUTH_SLICER\n");
    return true;
}

// Mode 10: RFC 9111 HTTP Cache (200 -> FreshHit -> 304 Conditional Revalidation) under Slicer + Bandwidth
fn run_mode_cache_revalidation(port: u16) -> bool {
    var s = make_chaos_client(port);
    s.enable_cache = true;
    s.virtual_clock_us = 1000000000;

    let r1, e1 = wing::get(s, "/cache-chaos");
    guard wing::ok(e1) && r1.status_code == 200 && r1.body[..] == "CACHED_CHAOS_BODY_V1" &&
          r1.header("x-revalidated") == "no" else {
        print("FAIL:MODE10_CACHE_MISS status=", r1.status_code, "\n");
        return false;
    }
    s.virtual_clock_us = 1005000000;
    let r2, e2 = wing::get(s, "/cache-chaos");
    guard wing::ok(e2) && r2.status_code == 200 && r2.body[..] == "CACHED_CHAOS_BODY_V1" &&
          s.pool.conns[0].use_count == 1 else {
        print("FAIL:MODE10_CACHE_FRESH\n");
        return false;
    }
    s.virtual_clock_us = 1025000000;
    let r3, e3 = wing::get(s, "/cache-chaos");
    guard wing::ok(e3) && r3.status_code == 200 && r3.body[..] == "CACHED_CHAOS_BODY_V1" &&
          r3.header("x-revalidated") == "yes" && s.pool.conns[0].use_count >= 2 else {
        print("FAIL:MODE10_CACHE_REVAL status=", r3.status_code, " rev=", r3.header("x-revalidated"), "\n");
        return false;
    }
    print("PASS:MODE10_CACHE_REVAL_SLICER\n");
    return true;
}

// Mode 11: Large Multi-Frame HTTP/2 Upload (> 20 KB across multiple DATA frames + slab promotion) under Slicer
fn run_mode_h2_large_multiframe(port: u16) -> bool {
    var s = make_chaos_client(port);
    s.http2_prior_knowledge = true;

    var big_body: u8[..24576] = [];
    while big_body.len < 20480 {
        big_body.append("0123456789abcdef0123456789ABCDEF");
    }
    let r1, e1 = wing::post(s, "/h2-large") { req =>
        wing::text(req, big_body[..]);
    };
    guard wing::ok(e1) && r1.status_code == 200 && r1.protocol[..] == "HTTP/2" &&
          r1.body[..] == "H2_LARGE_MULTIFRAME_OK" else {
        print("FAIL:MODE11_H2_LARGE status=", r1.status_code, " err=", e1.message[..], " body=", r1.body[..], "\n");
        return false;
    }
    print("PASS:MODE11_H2_LARGE_MULTIFRAME\n");
    return true;
}

// Mode 12: Half-closed stale Keep-Alive socket eviction & transparent reconnect on 3rd request
fn run_mode_stale_keepalive_reconnect(port: u16) -> bool {
    var s = make_chaos_client(port);
    wing::add_retry(s.pipeline, 3, true);

    let r1, e1 = wing::get(s, "/keepalive");
    let r2, e2 = wing::get(s, "/keepalive");
    guard wing::ok(e1) && wing::ok(e2) && r1.status_code == 200 && r2.status_code == 200 else {
        print("FAIL:MODE12_INITIAL_KA\n");
        return false;
    }
    // Server closes socket after 2nd `/keepalive` response; 3rd request hits stale pooled socket,
    // evicts it, and automatically retries on a fresh TCP connection!
    let r3, e3 = wing::get(s, "/keepalive");
    guard wing::ok(e3) && r3.status_code == 200 && r3.body[..] == "KEEPALIVE_OK" &&
          s.pool.next_conn_id >= 3 else {
        print("FAIL:MODE12_STALE_RECONNECT status=", r3.status_code, " next_id=", s.pool.next_conn_id, "\n");
        return false;
    }
    print("PASS:MODE12_STALE_KA_RECONNECT\n");
    return true;
}

// Mode 13: Native ReverseProxy + LoadBalancer dead-target failover into Toxiproxy Slicer upstream
fn run_mode_reverse_proxy_failover(port: u16) -> bool {
    let dead_lfd = wing::tcp_listen("127.0.0.1", 0);
    guard dead_lfd > 0 else { return false; }
    let dead_port = wing::tcp_getsockname_port(dead_lfd);
    wing::tcp_close(dead_lfd);

    g_chaos_proxy = proxy::new_reverse_proxy(proxy::LbPolicy.RoundRobin);
    g_chaos_proxy.cluster.max_fails = 1;
    let _ = g_chaos_proxy.cluster.add_upstream_target("127.0.0.1", dead_port, 1);
    let _ = g_chaos_proxy.cluster.add_upstream_target("127.0.0.1", port, 1);
    g_chaos_proxy.cluster.targets[0].unhealthy_threshold = 1;
    g_chaos_pool = wing::StreamPool { .. };

    var in_hdrs = wing::HeaderMap { .. };
    let _ = wing::append_header(in_hdrs, "Host", "edge.chaos.local");
    let _ = wing::append_header(in_hdrs, "Connection", "keep-alive, x-hop-drop");
    let _ = wing::append_header(in_hdrs, "X-Hop-Drop", "secret-internal");

    var out1 = wing::Response { .. };
    let ok1 = g_chaos_proxy.execute_proxy_exchange(
        g_chaos_pool, "GET", "/proxy-up", in_hdrs, "203.0.113.9", "http", "", out1, 200, 1000,
    );
    guard !ok1 && !g_chaos_proxy.cluster.targets[0].is_healthy else {
        print("FAIL:MODE13_DEAD_TARGET_NOT_MARKED\n");
        return false;
    }
    var out2 = wing::Response { .. };
    let ok2 = g_chaos_proxy.execute_proxy_exchange(
        g_chaos_pool, "GET", "/proxy-up", in_hdrs, "203.0.113.9", "http", "", out2, 2000, 2000,
    );
    guard ok2 && out2.status_code == 200 && out2.body[..] == "PROXY_FAILOVER_OK" else {
        print("FAIL:MODE13_FAILOVER status=", out2.status_code, " body=", out2.body[..], "\n");
        return false;
    }
    print("PASS:MODE13_REVERSE_PROXY_FAILOVER\n");
    return true;
}

fn recv_all_chaos_socket(fd: i64, out: u8[..2048]&) {
    out.clear();
    var chunk: u8[..256] = [];
    for step in 64 {
        chunk.clear();
        let n = wing::tcp_recv(fd, chunk, 256, 300);
        if n <= 0 { break; }
        let _ = out.try_append(chunk[..n]);
    }
}

// Mode 14: Native W3C SSE (`SseSubscription`) under 1..4B SlicerToxic + Last-Event-ID reconnect
fn run_mode_sse_sliced_reconnect(port: u16) -> bool {
    var sub = realtime::new_sse_subscription();
    var host_hdr: u8[..64] = [];
    host_hdr.append("127.0.0.1:");
    core::format_u64_dec(port, host_hdr);

    var wire1: u8[..512] = [];
    sub.sse_build_request_headers(host_hdr[..], "/sse-chaos", wire1);
    let c1 = wing::tcp_connect("127.0.0.1", port, 500);
    guard c1 > 0 && wing::tcp_send(c1, wire1[..]) == wire1.len else { return false; }
    var rx1: u8[..2048] = [];
    recv_all_chaos_socket(c1, rx1);
    wing::tcp_close(c1);
    var ev1: realtime::SseEvent[..8] = [];
    sub.consume(rx1[..], ev1);
    guard ev1.len == 1 && ev1[0].id[..] == "ev-chaos-1" && ev1[0].data[..] == "line1\nline2" &&
          sub.parser.last_event_id[..] == "ev-chaos-1" else {
        print("FAIL:MODE14_SSE_FIRST len=", ev1.len, "\n");
        return false;
    }

    var wire2: u8[..512] = [];
    sub.sse_build_request_headers(host_hdr[..], "/sse-chaos", wire2);
    let c2 = wing::tcp_connect("127.0.0.1", port, 500);
    guard c2 > 0 && wing::tcp_send(c2, wire2[..]) == wire2.len else { return false; }
    var rx2: u8[..2048] = [];
    recv_all_chaos_socket(c2, rx2);
    wing::tcp_close(c2);
    var ev2: realtime::SseEvent[..8] = [];
    sub.consume(rx2[..], ev2);
    guard ev2.len == 1 && ev2[0].id[..] == "ev-chaos-2" && ev2[0].data[..] == "resumed-part" else {
        print("FAIL:MODE14_SSE_RESUME len=", ev2.len, "\n");
        return false;
    }
    print("PASS:MODE14_SSE_SLICED_RECONNECT\n");
    return true;
}

fn main() {
    let port = wing::get_env_port(0);
    let mode = wing::get_env_workers(1);
    guard port > 0 else {
        print("FAIL:NO_PORT\n");
        return;
    }
    if mode == 1 { let _ = run_mode_h1_slicer_and_chunked(port); }
    else if mode == 2 { let _ = run_mode_redirect_and_cookies(port); }
    else if mode == 3 { let _ = run_mode_keepalive_pool(port); }
    else if mode == 4 { let _ = run_mode_retry_recovery(port); }
    else if mode == 5 { let _ = run_mode_h2_client_slicer(port); }
    else if mode == 6 { let _ = run_mode_truncation_eviction(port); }
    else if mode == 7 { let _ = run_mode_timeout_eviction(port); }
    else if mode == 8 { let _ = run_mode_idempotent_post_rewind(port); }
    else if mode == 9 { let _ = run_mode_digest_auth_and_cookies(port); }
    else if mode == 10 { let _ = run_mode_cache_revalidation(port); }
    else if mode == 11 { let _ = run_mode_h2_large_multiframe(port); }
    else if mode == 12 { let _ = run_mode_stale_keepalive_reconnect(port); }
    else if mode == 13 { let _ = run_mode_reverse_proxy_failover(port); }
    else if mode == 14 { let _ = run_mode_sse_sliced_reconnect(port); }
}
