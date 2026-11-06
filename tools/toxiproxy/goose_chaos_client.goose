// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Standalone Native Goose-Wing Client for Toxiproxy Chaos & Resilience Testing.
// Exercises real `wing::Session` (HTTP/1.1, chunked, redirects, CookieJar, Keep-Alive pool,
// automatic retries, and HTTP/2 client multiplexing) through live Toxiproxy fault injection.
import std;
import core from "../..";
import wing from "../..";

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
}
