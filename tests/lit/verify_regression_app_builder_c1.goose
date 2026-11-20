// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

struct AppUserProfile {
    id:   i64      = 0,
    name: u8[..32] = [],
}

fn build_h2_frame_hdr(out: u8[>..]&, length: u32, ftype: u8, flags: u8, stream_id: u32) {
    out.push(((length >> 16) & 0xFF) as! u8);
    out.push(((length >> 8) & 0xFF) as! u8);
    out.push((length & 0xFF) as! u8);
    out.push(ftype);
    out.push(flags);
    out.append_u32_be(stream_id & 0x7FFFFFFF);
}

fn count_active_slabs(pool: const server_internal::SpillSlabPool&) -> i64 {
    var n: i64 = 0;
    for &s in pool.slabs {
        if s.in_use {
            n += 1;
        }
    }
    return n;
}

// 1. Bug 1: Content-Encoding unknown token rejection, multi-layer rollback, and Content-Digest pre-decompress order
fn test_bug1_response_content_decoding_and_digest() {
    // 1a. Unknown Content-Encoding token must return false and preserve Content-Encoding header
    var res_unknown = wing::Response { status_code: 200, .. };
    wing::set_header(res_unknown, "Content-Encoding", "lz4");
    wing::set_header(res_unknown, "Content-Length", "11");
    res_unknown.body.append("RAW_LZ4_DAT");
    let ok_unknown = wing::decode_body(res_unknown);
    let hdr_preserved = wing::header(res_unknown, "Content-Encoding") == "lz4";
    let body_intact = res_unknown.body[..] == "RAW_LZ4_DAT";

    // 1b. Multi-layer Content-Encoding ("gzip, deflate"): outer deflate succeeds, inner gzip fails -> must roll back res.body
    var outer_deflate: u8[>..] = [];
    let ok_comp = core::zlib_compress("NOT_VALID_GZIP_STREAM", outer_deflate);
    assert(ok_comp);
    var res_chain = wing::Response { status_code: 200, .. };
    wing::set_header(res_chain, "Content-Encoding", "gzip, deflate");
    res_chain.body.append(outer_deflate[..]);
    let ok_chain = wing::decode_body(res_chain);
    let chain_rolled_back = !ok_chain && res_chain.body[..] == outer_deflate[..];

    // 1c. Client with verify_content_digest = true receiving gzipped response + valid RFC 9530 Content-Digest over wire bytes
    var gz_wire: u8[>..] = [];
    let ok_gz = core::gzip_compress("digest-verified-payload", gz_wire);
    assert(ok_gz);
    var cd_hdr: u8[..128] = [];
    let ok_cd = wing::format_digest_field_value("sha-256", gz_wire[..], cd_hdr);
    assert(ok_cd);

    var cli = wing::new_client("https://api.example.com");
    cli.verify_content_digest = true;
    cli.strict_content_decoding = true;
    var route_ok = wing::MockExchange {
        status_code: 200,
        ..
    };
    let _ = route_ok.method.try_set("GET");
    let _ = route_ok.pattern_url.try_set("https://api.example.com/compressed");
    wing::add_mock_header(route_ok, "Content-Encoding", "gzip");
    wing::add_mock_header(route_ok, "Content-Digest", cd_hdr[..]);
    let _ = route_ok.body.try_set(gz_wire[..]);
    let _ = cli.mock_routes.try_push(route_ok);

    var route_bad_enc = wing::MockExchange {
        status_code: 200,
        ..
    };
    let _ = route_bad_enc.method.try_set("GET");
    let _ = route_bad_enc.pattern_url.try_set("https://api.example.com/unknown-enc");
    wing::add_mock_header(route_bad_enc, "Content-Encoding", "snappy");
    let _ = route_bad_enc.body.try_set("RAW_SNAPPY");
    let _ = cli.mock_routes.try_push(route_bad_enc);

    let req1 = wing::new_request("GET", "https://api.example.com/compressed");
    let resp1, err1 = wing::execute_request(cli, req1);
    let cd_gz_ok = wing::ok(err1) && resp1.status_code == 200 && resp1.body[..] == "digest-verified-payload";

    let req2 = wing::new_request("GET", "https://api.example.com/unknown-enc");
    let _, err2 = wing::execute_request(cli, req2);
    let strict_unknown_rejected = !wing::ok(err2) && err2.code == 502;

    print(
        "BUG1_CONTENT_DECODE: unknown_rejected=", !ok_unknown,
        " hdr_preserved=", hdr_preserved,
        " body_intact=", body_intact,
        " chain_rollback=", chain_rolled_back,
        " cd_gz_ok=", cd_gz_ok,
        " strict_unknown_rejected=", strict_unknown_rejected, "\n",
    );
    // CHECK: BUG1_CONTENT_DECODE: unknown_rejected=true hdr_preserved=true body_intact=true chain_rollback=true cd_gz_ok=true strict_unknown_rejected=true
}

// 2. Bug 2: Response json<T> transactional rollback on partial/malformed JSON
fn test_bug2_response_json_transactional_rollback() {
    var profile = AppUserProfile { id: 7 };
    let _ = profile.name.try_set("alice");

    var bad_res = wing::Response { status_code: 200, .. };
    bad_res.body.append("{\"id\":999,\"name\":12345}");

    let err = wing::json(bad_res, profile);
    let rejected = !wing::ok(err);
    let rolled_back = profile.id == 7 && profile.name[..] == "alice";

    print("BUG2_JSON_ROLLBACK: rejected=", rejected, " rolled_back=", rolled_back, "\n");
    // CHECK: BUG2_JSON_ROLLBACK: rejected=true rolled_back=true
}

// 3. Bug 3: HTTP/2 server SpillSlabPool leak when connection aborts with GOAWAY mid-stream
fn test_bug3_h2_spill_slab_reclaimed_on_goaway() {
    var sess = server_internal::new_h2_server_session("goose-wing/1.0", 1000);
    var pipeline = wing::new_server_pipeline_config("127.0.0.1", security::new_gcra_quota(1000, wing::secs(1), 100));
    var timer = server_internal::new_connection_timer(30000000000, 1000000000);
    wing::add_route(pipeline.router, "POST", "/upload", 1);

    var init_wire: u8[>..] = [];
    init_wire.append(rfc::H2_CLIENT_PREFACE);
    build_h2_frame_hdr(init_wire, 0, rfc::H2_FRAME_SETTINGS, 0, 0);
    var wire_out: u8[>..] = [];
    let _, ok_init = server_internal::handle_h2_server_ingress(
        sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, wire_out,
    );
    assert(ok_init);

    var dt = h2_internal::new_dynamic_table(4096);
    var h_block: u8[>..] = [];
    h2_internal::encode_hpack_field(dt, h_block, ":method", "POST", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, ":scheme", "https", h2_internal::HpackIndexing.Incremental, false);
    h2_internal::encode_hpack_field(dt, h_block, ":path", "/upload", h2_internal::HpackIndexing.Incremental, false);

    var stream_wire: u8[>..] = [];
    build_h2_frame_hdr(stream_wire, h_block.len as u32, rfc::H2_FRAME_HEADERS, rfc::H2_FLAG_END_HEADERS, 1);
    stream_wire.append(h_block[..]);

    var chunk8k: u8[>..] = [];
    for _ in 8192 { chunk8k.push('A'); }
    build_h2_frame_hdr(stream_wire, 8192, rfc::H2_FRAME_DATA, 0, 1);
    stream_wire.append(chunk8k[..]);
    build_h2_frame_hdr(stream_wire, 8192, rfc::H2_FRAME_DATA, 0, 1);
    stream_wire.append(chunk8k[..]);

    wire_out.clear();
    let _, ok_data = server_internal::handle_h2_server_ingress(
        sess, pipeline, timer, "127.0.0.1", stream_wire[..], 1001, wire_out,
    );
    let leased_during_stream = ok_data && count_active_slabs(pipeline.slab_pool) == 1;

    // Peer sends illegal PUSH_PROMISE frame -> fatal connection error (GOAWAY)
    var fatal_wire: u8[>..] = [];
    build_h2_frame_hdr(fatal_wire, 4, rfc::H2_FRAME_PUSH_PROMISE, rfc::H2_FLAG_END_HEADERS, 1);
    fatal_wire.append("\x00\x00\x00\x02");

    wire_out.clear();
    let _, ok_fatal = server_internal::handle_h2_server_ingress(
        sess, pipeline, timer, "127.0.0.1", fatal_wire[..], 1002, wire_out,
    );
    let reclaimed_after_goaway = !ok_fatal && count_active_slabs(pipeline.slab_pool) == 0;

    print(
        "BUG3_H2_SLAB_GOAWAY: leased=", leased_during_stream,
        " reclaimed=", reclaimed_after_goaway, "\n",
    );
    // CHECK: BUG3_H2_SLAB_GOAWAY: leased=true reclaimed=true
}

// 4. Bug 4: ReverseProxy & ClusterHealthChecker sync_cluster_target_health counter preservation
fn test_bug4_proxy_health_sync_counters() {
    var proxy = wing::new_reverse_proxy(wing::LbPolicy.RoundRobin);
    proxy.cluster.max_fails = 0;
    assert(wing::add_upstream_target(proxy.cluster, "10.0.0.1", 8080, 1));
    assert(wing::set_target_health_thresholds(proxy.cluster, 0, 3, 3));
    proxy.health_checker = wing::new_cluster_health_checker(wing::new_health_check_config(1000, 500, 3, 3));
    assert(wing::register_target_for_probing(proxy.health_checker, 0));

    // 4a. Single failed upstream exchange (502) while Up (unhealthy_threshold = 3) must NOT reset fails to 0
    proxy.cluster.targets[0].active_conns = 1;
    wing::complete_upstream_exchange(proxy, 0, 502, true);
    let fails_preserved = proxy.cluster.targets[0].fails == 1 && proxy.cluster.targets[0].is_healthy;

    // Trip to Down with 2 more failures
    proxy.cluster.targets[0].active_conns = 1;
    wing::complete_upstream_exchange(proxy, 0, 502, true);
    proxy.cluster.targets[0].active_conns = 1;
    wing::complete_upstream_exchange(proxy, 0, 502, true);
    let tripped_down = proxy.cluster.targets[0].health_state == wing::UpstreamHealthState.Down;

    // 4b. Two probe successes with healthy_threshold = 3 must record successes = 2 in Probing (not hardcode 1)
    let st1 = wing::on_probe_success(proxy.health_checker, proxy.cluster, 0, 150);
    let st2 = wing::on_probe_success(proxy.health_checker, proxy.cluster, 0, 150);
    let probing_count_two = st1 == wing::HealthState.Probing &&
        st2 == wing::HealthState.Probing &&
        proxy.cluster.targets[0].successes == 2 &&
        !proxy.cluster.targets[0].is_healthy;

    // 3rd success via passive upstream success reaches healthy_threshold = 3 -> transitions to Up!
    wing::record_upstream_success(proxy.cluster, 0);
    let recovered_at_three = proxy.cluster.targets[0].health_state == wing::UpstreamHealthState.Up &&
        proxy.cluster.targets[0].is_healthy;

    print(
        "BUG4_PROXY_HEALTH_SYNC: fails_preserved=", fails_preserved,
        " tripped_down=", tripped_down,
        " probing_count_two=", probing_count_two,
        " recovered_at_three=", recovered_at_three, "\n",
    );
    // CHECK: BUG4_PROXY_HEALTH_SYNC: fails_preserved=true tripped_down=true probing_count_two=true recovered_at_three=true
}

fn main() {
    test_bug1_response_content_decoding_and_digest();
    test_bug2_response_json_transactional_rollback();
    test_bug3_h2_spill_slab_reclaimed_on_goaway();
    test_bug4_proxy_health_sync_counters();
}
