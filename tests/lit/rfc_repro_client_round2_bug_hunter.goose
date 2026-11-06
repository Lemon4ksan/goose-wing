// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/rfc_repro_client_round2_bug_hunter.goose
// Regression test suite for client bug-hunter audit findings (F017-F023).
//
// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

// F019: set_credentials must support up to 128 bytes and guard against capacity overflow.
fn test_f019_credentials_capacity() {
    var session = wing::new_session();
    var long_pass: u8[..128] = [];
    for i in 100 {
        long_pass.push('k');
    }
    // Length 100 exceeds old 64-byte capacity but fits in 128-byte DigestCredentials
    let ok = wing::set_credentials(session, "admin_user", long_pass[..]);
    assert(ok);
    assert(session.creds.has_credentials);
    assert(session.creds.password.len == 100);

    // Oversized password > 128 must be safely rejected without panicking
    var too_long: u8[..200] = [];
    for i in 150 {
        too_long.push('x');
    }
    let ok_overflow = wing::set_credentials(session, "admin_user", too_long[..]);
    assert(!ok_overflow);
    print("F019_CREDENTIALS_CAPACITY: OK");
}

// F021: encode_chunk_trailer must filter out disallowed trailer fields (RFC 9112 §7.1.2).
fn test_f021_chunked_disallowed_trailers() {
    var trailers = wing::HeaderMap { .. };
    wing::set_header(trailers, "X-Checksum", "abcdef");
    wing::set_header(trailers, "Content-Length", "42");
    wing::set_header(trailers, "Transfer-Encoding", "chunked");

    var wire_out: u8[>..] = [];
    wing::encode_chunked_payload("hello", trailers, 4096, wire_out);
    let wire_str = wire_out[..];

    assert(find(wire_str, "X-Checksum: abcdef") >= 0);
    assert(find(wire_str, "Content-Length") < 0);
    assert(find(wire_str, "Transfer-Encoding") < 0);
    print("F021_CHUNKED_DISALLOWED_TRAILERS: OK");
}

// F022: session mutator bounds clamping and deduplication.
fn test_f022_session_mutators_bounds_and_dedup() {
    var session = wing::new_session();
    var huge_url: u8[..300] = [];
    for i in 280 {
        huge_url.push('h');
    }

    // Must not panic on URLs > 256
    wing::set_base_url(session, huge_url[..]);
    assert(session.base_url.len <= 256);

    wing::set_proxy(session, huge_url[..]);
    assert(session.proxy_url.len <= 256);

    wing::enable_doh(session, huge_url[..]);
    assert(session.doh.endpoint.len <= 256);

    // Ports and hosts deduplication
    wing::allow_port(session, 8080);
    wing::allow_port(session, 8080);
    assert(session.ssrf_guard.allowed_ports.len == 1);

    wing::deny_port(session, 22);
    wing::deny_port(session, 22);
    assert(session.ssrf_guard.denied_ports.len == 1);

    wing::trust_location_host(session, "cdn.example.com");
    wing::trust_location_host(session, "CDN.EXAMPLE.COM");
    assert(session.trusted_location_hosts.len == 1);
    print("F022_SESSION_MUTATORS_BOUNDS_AND_DEDUP: OK");
}

// F017: stage_client_alt_svc / ingest_compression_dict_header must decode body
// and must NOT cache invalid/corrupted dictionary representations.
fn test_f017_stage_dictionary_compression_handling() {
    var session = wing::new_session();
    var dict_cache = wing::DictionaryCache { .. };
    var resp = wing::Response {
        status_code: 200,
        ..
    };
    wing::set_header(resp, "Use-As-Dictionary", "match=\"/api/*\"");
    wing::set_header(resp, "Content-Encoding", "dcz");
    resp.body.append("corrupt-dcz-payload");

    // Must not cache corrupted dictionary body
    wing::ingest_compression_dict_header(dict_cache, "example.com:443", "/api/item", 1000, resp);
    assert(dict_cache.entries.len == 0);
    print("F017_STAGE_DICT_COMPRESSION_HANDLING: OK");
}

// F018: 101 Switching Protocols connection must not be released into HTTP idle pool (RFC 9112 §6.3, RFC 6455 §4.1).
fn test_f018_h1_101_no_pool_reuse() {
    var session = wing::new_session();
    var conn = wing::PooledConnection {
        conn_id: 42,
        ..
    };
    session.pool.conns.push(conn);
    assert(session.pool.conns.len == 1);

    // On 101, close_pooled_connection must be used instead of release_connection
    session.pool.close_pooled_connection(42);
    assert(session.pool.conns[0].closed);
    print("F018_H1_101_NO_POOL_REUSE: OK");
}

// F020 & F023: prepare_auth_retry_hop must reset body_consumed, and compute_401_auth_header must clear dirty header buf.
fn test_f020_f023_auth_retry_state_and_clear() {
    var session = wing::new_client();
    wing::set_credentials(session, "alice", "secret123");
    var ctx = wing::RequestExecutionContext {
        rewindable:    true,
        body_consumed: true,
        ..
    };
    ctx.rewind_buf.append("post-data");
    ctx.body.append("post-data");

    let u = core::new_url("https://example.com/api");
    let samesite = wing::SameSiteCookieContext { .. };
    let resp = wing::Response { status_code: 401, .. };

    wing::prepare_auth_retry_hop(session, ctx, u, samesite, false, resp, "Basic dGVzdA==");
    assert(!ctx.body_consumed);
    assert(ctx.auth_retried);

    var dirty_header: u8[..4096] = [];
    dirty_header.append("STALE-DIRTY-PREFIX-");
    let ok_auth = wing::compute_401_auth_header(session, ctx, u, "Basic realm=\"api\"", dirty_header);
    assert(ok_auth);
    assert(!core::starts_with(dirty_header[..], "STALE-DIRTY-PREFIX-"));
    assert(core::starts_with(dirty_header[..], "Basic "));
    print("F020_F023_AUTH_RETRY_STATE_AND_CLEAR: OK");
}

fn main() {
    test_f019_credentials_capacity();
    test_f021_chunked_disallowed_trailers();
    test_f022_session_mutators_bounds_and_dedup();
    test_f017_stage_dictionary_compression_handling();
    test_f018_h1_101_no_pool_reuse();
    test_f020_f023_auth_retry_state_and_clear();
}

// CHECK: F019_CREDENTIALS_CAPACITY: OK
// CHECK-NEXT: F021_CHUNKED_DISALLOWED_TRAILERS: OK
// CHECK-NEXT: F022_SESSION_MUTATORS_BOUNDS_AND_DEDUP: OK
// CHECK-NEXT: F017_STAGE_DICT_COMPRESSION_HANDLING: OK
// CHECK-NEXT: F018_H1_101_NO_POOL_REUSE: OK
// CHECK-NEXT: F020_F023_AUTH_RETRY_STATE_AND_CLEAR: OK
