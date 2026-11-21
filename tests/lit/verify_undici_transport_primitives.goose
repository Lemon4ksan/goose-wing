// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s

import std;
import wing from "../..";

fn test_h1_exchange_primitives() {
    var hdrs = http::HeaderMap { .. };
    let _ = http::append_header(hdrs, "Content-Length", "42");
    let rogue_204 = wing::has_rogue_empty_status_framing("GET", 204, hdrs);
    let head_204 = wing::has_rogue_empty_status_framing("HEAD", 204, hdrs);

    var te_hdrs = http::HeaderMap { .. };
    let _ = http::append_header(te_hdrs, "Transfer-Encoding", "chunked");
    let rogue_304_te = wing::has_rogue_empty_status_framing("GET", 304, te_hdrs);

    var clean_hdrs = http::HeaderMap { .. };
    let _ = http::append_header(clean_hdrs, "Content-Length", "0");
    let clean_204 = wing::has_rogue_empty_status_framing("GET", 204, clean_hdrs);

    var conn = net::PooledConnection { .. };
    var req = http::Request { .. };
    let _ = req.method.try_set("GET");
    var resp = http::Response { status_code: 204, .. };
    let _ = resp.protocol.try_set("HTTP/1.1");
    resp.headers = hdrs;
    let ok_pump, ka_rogue = wing::pump_response_body(conn, req, resp, "", 100);
    resp.headers = clean_hdrs;
    let _, ka_clean = wing::pump_response_body(conn, req, resp, "NEXT", 100);

    print("rogue_204:", rogue_204, " head_204:", head_204, " rogue_304_te:", rogue_304_te, " clean_204:", clean_204);
    print("pump_rogue_ka:", ok_pump, " ", ka_rogue, " clean_ka:", ka_clean, " rx_len:", conn.rx_buf.len);

    let hints = wing::parse_keep_alive_header("timeout=5, max=\"100\", ext=ignore");
    let cfg = wing::ExchangeTimeouts { .. };
    let idle_ns, allow_ka = wing::resolve_peer_keep_alive_budget(hints, 10, cfg);
    let _, exhausted_ka = wing::resolve_peer_keep_alive_budget(hints, 100, cfg);
    let short_hints = wing::parse_keep_alive_header("timeout=1");
    let _, short_ka = wing::resolve_peer_keep_alive_budget(short_hints, 1, cfg);
    let rem_ms, rem_ok = wing::remaining_deadline_ms(1000000000, 250000000);
    let _, expired_ok = wing::remaining_deadline_ms(250000000, 1000000000);

    print("ka_hints:", hints.has_timeout, " ", hints.timeout_sec, " ", hints.has_max_reqs, " ", hints.max_reqs);
    print("ka_budget:", idle_ns, " ", allow_ka, " ", exhausted_ka, " ", short_ka, " rem_ms:", rem_ms, " ", rem_ok, " ", expired_ok);

    var sink_resp = http::Response { .. };
    var sink = wing::BufferedBodySink { resp: sink_resp, max_response_bytes: 16 };
    var head = wing::ResponseHead { status_code: 200, .. };
    let _ = http::append_header(head.headers, "Content-Length", "11");
    let v_hdr = wing::on_headers(sink, head);
    var stream_conn = net::PooledConnection { .. };
    let ok_stream = wing::stream_h1_fixed_body(stream_conn, 11, "hello worldEXTRA", 100, sink);
    let v_overflow = wing::on_data(sink, "0123456789");
    let ok_drain = wing::drain_h1_fixed_body_bounded(stream_conn, 5, 5, 1024, 100);
    let fail_drain = wing::drain_h1_fixed_body_bounded(stream_conn, 2048, 0, 1024, 100);

    print("stream_sink:", v_hdr == wing::StreamSinkVerdict.Continue, " ", ok_stream, " body:", sink_resp.body[..], " leftover:", stream_conn.rx_buf[..]);
    print("overflow_abort:", v_overflow == wing::StreamSinkVerdict.AbortExchange, " drain:", ok_drain, " ", fail_drain);
}

fn test_pool_and_lifecycle_primitives() {
    var gate: net::ProbeGateState = net::ProbeGateState.Probing { probe_conn_id: 7 };
    let hold_https = net::should_hold_for_alpn_probe(net::PoolScheme.Https, true, gate, 1);
    let hold_http = net::should_hold_for_alpn_probe(net::PoolScheme.Http, true, gate, 1);
    net::settle_alpn_probe(gate, 7, true, net::NegotiatedProtocol.Http2);
    let resolved_h2 = match gate {
        ResolvedHttp2 => true,
        _ => false,
    };

    let pol = net::ConnLifecyclePolicy {
        max_requests_per_conn: 10,
        max_conn_ttl_ns:       5000000000,
        max_pipelining:        2,
    };
    let can_first = net::can_dispatch_on_h1_conn(0, pol, net::H1RequestSafety.NonIdempotent);
    let can_pipe_get = net::can_dispatch_on_h1_conn(1, pol, net::H1RequestSafety.SafeIdempotent);
    let can_pipe_post = net::can_dispatch_on_h1_conn(1, pol, net::H1RequestSafety.NonIdempotent);
    let can_over_cap = net::can_dispatch_on_h1_conn(2, pol, net::H1RequestSafety.SafeIdempotent);

    let retire_fresh = net::should_retire_connection(3, 1000, 2000, pol);
    let retire_reqs = net::should_retire_connection(10, 1000, 2000, pol);
    let retire_ttl = net::should_retire_connection(1, 1000, 6000002000, pol);

    var pool = net::new_stream_pool();
    let k1 = net::new_pool_key(
        net::PoolScheme.Https,
        "idle.example.com",
        443,
        net::new_direct_proxy_chain(),
        net::new_network_anonymization_key("https://app.example"),
        net::TlsAndDnsPolicy { .. },
    );
    let k2 = net::new_pool_key(
        net::PoolScheme.Https,
        "active.example.com",
        443,
        net::new_direct_proxy_chain(),
        net::new_network_anonymization_key("https://app.example"),
        net::TlsAndDnsPolicy { .. },
    );
    let _ = net::find_or_create_group(pool, k1);
    let g2 = net::find_or_create_group(pool, k2);
    pool.groups[g2 as i64].active_conns = 1;
    let reclaimed = net::reclaim_idle_origin_groups(pool);

    print("alpn_gate:", hold_https, " ", hold_http, " ", resolved_h2);
    print("h1_pipe:", can_first, " ", can_pipe_get, " ", can_pipe_post, " ", can_over_cap);
    print("retire:", retire_fresh, " ", retire_reqs, " ", retire_ttl, " reclaimed:", reclaimed, " rem_groups:", pool.groups.len);
}

fn test_retry_redirect_and_balancer() {
    let strong_ok = net::is_strong_etag_validator("\"v1-strong\"");
    let weak_ok = net::is_strong_etag_validator("W/\"v1-weak\"");

    var resp_hdrs = http::HeaderMap { .. };
    let _ = http::append_header(resp_hdrs, "ETag", "\"etag-42\"");
    let _ = http::append_header(resp_hdrs, "Content-Length", "8192");

    var tracker = net::RangeResumeTracker { .. };
    net::arm_range_resume(tracker, "GET", 200, resp_hdrs);
    tracker.bytes_received = 4096;
    var req_hdrs = http::HeaderMap { .. };
    let built_ok = net::build_range_resume_headers(tracker, req_hdrs);

    var taint = client::RedirectHopCacheTaint { .. };
    var hop_hdrs = http::HeaderMap { .. };
    let _ = http::append_header(hop_hdrs, "Cache-Control", "max-age=0, private, no-store");
    client::record_redirect_hop_cache_headers(taint, hop_hdrs);

    var custom_pol = client::CustomRedirectStripPolicy { .. };
    var s1: u8[..64] = [];
    let _ = s1.try_set("X-Trace-Token");
    let _ = custom_pol.always_strip.try_push(s1);
    var s2: u8[..64] = [];
    let _ = s2.try_set("X-Internal-Auth");
    let _ = custom_pol.cross_origin_strip.try_push(s2);

    var redir_hdrs = http::HeaderMap { .. };
    let _ = http::append_header(redir_hdrs, "X-Trace-Token", "t1");
    let _ = http::append_header(redir_hdrs, "X-Internal-Auth", "secret");
    client::apply_custom_redirect_strip(redir_hdrs, true, custom_pol);

    var bal = proxy::DynamicWeightBalancer { error_penalty: 20, max_weight_per_server: 100, .. };
    let _ = bal.entries.try_push(proxy::DynamicWeightEntry { effective_weight: 100, .. });
    let _ = bal.entries.try_push(proxy::DynamicWeightEntry { effective_weight: 100, .. });
    bal.recompute_balancer_ratios();
    bal.penalize_upstream_weight(0);
    let w_after_pen = bal.entries[0].effective_weight;
    let gcd_after_pen = bal.weight_gcd;
    let sel0, sel_ok = bal.select_weighted_upstream();
    bal.reward_upstream_weight(0);
    let w_after_rew = bal.entries[0].effective_weight;

    print("etag:", strong_ok, " ", weak_ok, " resume:", built_ok, " range:", http::get_header(req_hdrs, "Range"), " if_match:", http::get_header(req_hdrs, "If-Match"));
    print("taint:", taint.saw_no_store, " ", taint.saw_private, " stripped:", !http::has_header(redir_hdrs, "X-Trace-Token"), " ", !http::has_header(redir_hdrs, "X-Internal-Auth"));
    print("balancer:", w_after_pen, " gcd:", gcd_after_pen, " sel:", sel0, " ", sel_ok, " restored:", w_after_rew);
}

fn main() {
    test_h1_exchange_primitives();
    test_pool_and_lifecycle_primitives();
    test_retry_redirect_and_balancer();
}

// CHECK: rogue_204:true head_204:false rogue_304_te:true clean_204:false
// CHECK-NEXT: pump_rogue_ka:true false clean_ka:true rx_len:4
// CHECK-NEXT: ka_hints:true 5 true 100
// CHECK-NEXT: ka_budget:4000000000 true false false rem_ms:750 true false
// CHECK-NEXT: stream_sink:true true body:hello world leftover:EXTRA
// CHECK-NEXT: overflow_abort:true drain:true false
// CHECK-NEXT: alpn_gate:true false true
// CHECK-NEXT: h1_pipe:true true false false
// CHECK-NEXT: retire:false true true reclaimed:1 rem_groups:1
// CHECK-NEXT: etag:true false resume:true range:bytes=4096-8191 if_match:"etag-42"
// CHECK-NEXT: taint:true true stripped:true true
// CHECK-NEXT: balancer:80 gcd:20 sel:1 true restored:100
