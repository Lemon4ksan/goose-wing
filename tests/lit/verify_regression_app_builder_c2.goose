// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
//
// Cycle 2 AppBuilder Regression Suite (AB-C2-01 .. AB-C2-04):
// Verifies end-user routing, transactional request decoders, load balancer recovery,
// and WebSocket session lifecycle invariants across server/*, client/*, proxy/*, and realtime/*.

import std;
import core from "../..";
import wing from "../..";

struct C2GrowableDto {
    id:   i64     = 0,
    name: u8[>..] = [],
}

// AB-C2-01: RadixTree matches_static_suffix_chain partial-prefix & internal-node split regression.
fn test_ab_c2_01_router_suffix_chain() {
    var tree = wing::new_radix_tree();
    // Register suffixed route and fallback route on the same parameter segment
    let ok_gz = wing::insert_route(tree, "/files/{name}.tar.gz", 10);
    let ok_bz2 = wing::insert_route(tree, "/files/{name}.tar.bz2", 11);
    let ok_fb = wing::insert_route(tree, "/files/{name}", 12);
    // Register multi-segment suffixed route and multi-segment fallback route
    let ok_png = wing::insert_route(tree, "/assets/{item}.png/info", 20);
    let ok_afb = wing::insert_route(tree, "/assets/{item}/info", 21);

    // 1. Exact ".tar.gz" match must route to handler 10 with name="archive"
    var p_gz = wing::ZeroAllocParams { .. };
    let res_gz = wing::match_path(tree, "/files/archive.tar.gz", p_gz);
    let id_gz = match res_gz { Found f => f.handler_id, _ => -1 };
    let val_gz, _ = wing::param_by_name(p_gz, "name", "/files/archive.tar.gz");

    // 2. Partial suffix ".tar" (prefix of ".tar.gz"/".tar.bz2" with no handler at ".tar")
    //    must fall back to handler 12 with name="archive.tar", NOT 404!
    var p_tar = wing::ZeroAllocParams { .. };
    let res_tar = wing::match_path(tree, "/files/archive.tar", p_tar);
    let id_tar = match res_tar { Found f => f.handler_id, _ => -1 };
    let val_tar, _ = wing::param_by_name(p_tar, "name", "/files/archive.tar");

    // 3. Partial suffix ".t" (strict prefix inside node ".tar") must fall back to handler 12
    var p_t = wing::ZeroAllocParams { .. };
    let res_t = wing::match_path(tree, "/files/archive.t", p_t);
    let id_t = match res_t { Found f => f.handler_id, _ => -1 };
    let val_t, _ = wing::param_by_name(p_t, "name", "/files/archive.t");

    // 4. Multi-segment partial suffix ".p" before "/info" must route to handler 21 with item="icon.p"
    var p_p = wing::ZeroAllocParams { .. };
    let res_p = wing::match_path(tree, "/assets/icon.p/info", p_p);
    let id_p = match res_p { Found f => f.handler_id, _ => -1 };
    let val_p, _ = wing::param_by_name(p_p, "item", "/assets/icon.p/info");

    print(
        "AB-C2-01:",
        " setup=", ok_gz && ok_bz2 && ok_fb && ok_png && ok_afb,
        " gz=", id_gz, ":", val_gz,
        " tar=", id_tar, ":", val_tar,
        " t=", id_t, ":", val_t,
        " p=", id_p, ":", val_p,
    );
}

// AB-C2-02: Request query_param and decode_json_body transactional rollback on pre-populated buffers.
fn test_ab_c2_02_request_transactional_rollback() {
    var req = wing::new_get("https://example.com/search?region=0123456789abcdef_overflow&flag");
    let _ = wing::query(req, "local_big", "0123456789abcdef_overflow");

    // 1. Pre-populated bounded buffer must remain intact ("fallback") on missing key and overflow
    var bounded_out: u8[..16] = [];
    bounded_out.append("fallback");
    let ok_missing = wing::query_param(req, "missing_key", bounded_out);
    let preserved_missing = bounded_out[..] == "fallback";

    var ovf_out1: u8[..16] = [];
    ovf_out1.append("fallback");
    let ok_url_ovf = wing::query_param(req, "region", ovf_out1);
    let preserved_url_ovf = ovf_out1[..] == "fallback";

    var ovf_out2: u8[..16] = [];
    ovf_out2.append("fallback");
    let ok_loc_ovf = wing::query_param(req, "local_big", ovf_out2);
    let preserved_loc_ovf = ovf_out2[..] == "fallback";

    // 2. Valueless URL query parameter ("?flag") must succeed with empty string ""
    var flag_out: u8[..16] = [];
    flag_out.append("stale");
    let ok_flag = wing::query_param(req, "flag", flag_out);
    let flag_empty = ok_flag && flag_out.len == 0;

    // 3. decode_json_body into struct with growable u8[>..] field must roll back on malformed trailing JSON
    var dto = C2GrowableDto { id: 77, .. };
    dto.name.append("initial_name");
    var bad_req = wing::new_post("https://example.com/items");
    wing::raw_json(bad_req, "{\"name\":\"mutated_before_error\",\"id\":invalid_json}");
    let dec_err = wing::decode_json_body(bad_req, dto);
    let dto_rolled_back = !wing::ok(dec_err) && dto.id == 77 && dto.name[..] == "initial_name";

    print(
        "AB-C2-02:",
        " miss=", !ok_missing && preserved_missing,
        " url_ovf=", !ok_url_ovf && preserved_url_ovf,
        " loc_ovf=", !ok_loc_ovf && preserved_loc_ovf,
        " flag_ok=", flag_empty,
        " json_rollback=", dto_rolled_back,
    );
}

// AB-C2-03: Load balancer Probing circuit-breaker recovery, Ketama failover, and DynamicWeightBalancer.
fn test_ab_c2_03_load_balancer_recovery() {
    // 1. Full cluster failure opens circuit; set_upstream_probing must allow half-open probe selection
    var cluster = wing::new_upstream_cluster(wing::LbPolicy.RoundRobin, 2);
    let _ = wing::add_upstream_target(cluster, "10.0.0.1", 8080);
    let _ = wing::add_upstream_target(cluster, "10.0.0.2", 8080);
    wing::record_upstream_failure(cluster, 0);
    wing::record_upstream_failure(cluster, 0);
    wing::record_upstream_failure(cluster, 1);
    wing::record_upstream_failure(cluster, 1);
    let tripped = cluster.circuit_open;

    let probe_ok = wing::set_upstream_probing(cluster, 1);
    let sel_probe, ok_sel_probe = wing::select_upstream(cluster);

    // 2. ConsistentHash lazy ring build via select_upstream
    var ch_cluster = wing::new_upstream_cluster(wing::LbPolicy.ConsistentHash, 3);
    let _ = wing::add_upstream_target(ch_cluster, "10.0.1.1", 8080, 4);
    let _ = wing::add_upstream_target(ch_cluster, "10.0.1.2", 8080, 1);
    let ch_idx, ok_ch = wing::select_upstream(ch_cluster);
    let ch_built = ok_ch && ch_idx >= 0 && ch_cluster.ketama_ring.points.len > 32;

    // 3. DynamicWeightBalancer with custom initial weights < 100 and draining high-weight node
    var bal = wing::DynamicWeightBalancer { .. };
    let _ = bal.entries.try_push(wing::DynamicWeightEntry { effective_weight: 40, need_drain: false, .. });
    let _ = bal.entries.try_push(wing::DynamicWeightEntry { effective_weight: 100, need_drain: true, .. });
    let w_idx, ok_w = wing::select_weighted_upstream(bal);

    print(
        "AB-C2-03:",
        " tripped=", tripped,
        " probe_transition=", probe_ok,
        " probe_selectable=", ok_sel_probe && sel_probe == 1,
        " ch_built=", ch_built,
        " weighted_ok=", ok_w && w_idx == 0,
    );
}

// AB-C2-04: WebSocket unlimited max_payload_length=0 fragmentation, CloseSent heartbeat, and receive() hygiene.
fn test_ab_c2_04_websocket_session_invariants() {
    // 1. drain_ws_session_frames with max_payload_length == 0 (unlimited) must assemble fragmented messages
    var ws = wing::new_websocket_session(false);
    wing::set_max_payload_length(ws, 0);
    let mask_k: u8[4] = [0x12, 0x34, 0x56, 0x78];
    var in_wire: u8[..256] = [];
    wing::encode_ws_frame(in_wire, rfc::WS_OPCODE_TEXT, "Hel", true, mask_k, false);
    wing::encode_ws_frame(in_wire, rfc::WS_OPCODE_CONTINUATION, "lo!", true, mask_k, true);

    var frag_buf: u8[..1024] = [];
    var out_wire: u8[..1024] = [];
    var stage = wire::NoOpStage {};
    let consumed = wing::drain_ws_session_frames(-1, ws, stage, in_wire[..], frag_buf, out_wire);
    let frag_unlimited_ok = !ws.is_closed && consumed == in_wire.len && frag_buf[..] == "Hello!";

    // 2. check_heartbeat must not emit SendPing after close_at (CloseSent half-closed state)
    var ws_hb = wing::new_websocket_session(false);
    ws_hb.idle_timeout_s = 10;
    ws_hb.send_pings_automatically = true;
    var wheel = core::TickTimerWheel { current_tick: 0, .. };
    wing::arm_heartbeat(ws_hb, wheel);
    var close_wire: u8[..64] = [];
    wing::close_at(ws_hb, rfc::WS_STATUS_NORMAL, "closing", 1000, close_wire);
    // Advance wheel to ping_slot
    wheel.current_tick = ws_hb.ping_slot;
    var hb_wire: u8[..64] = [];
    let hb_action = wing::tick_heartbeat(ws_hb, wheel, hb_wire);
    let no_ghost_ping = hb_action == wing::WsHeartbeatAction.None && hb_wire.len == 0;

    // 3. receive() on reused WsMessage must clear stale valid state when frame is incomplete
    var ws_rx = wing::new_websocket_session(false);
    var msg_wire: u8[..64] = [];
    wing::encode_ws_frame(msg_wire, rfc::WS_OPCODE_TEXT, "first_msg", true, mask_k, true);
    var reused_msg = wing::WsMessage { .. };
    var rx_reply: u8[..64] = [];
    let ok1 = wing::receive(ws_rx, msg_wire[..], reused_msg, rx_reply);
    var trunc_wire: u8[..4] = [0x81, 0x85, 0x01]; // truncated frame
    let ok2 = wing::receive(ws_rx, trunc_wire[..], reused_msg, rx_reply);
    let msg_cleaned = ok1 && !ok2 && !reused_msg.is_valid && reused_msg.data.len == 0;

    print(
        "AB-C2-04:",
        " frag_unlimited=", frag_unlimited_ok,
        " no_ghost_ping=", no_ghost_ping,
        " msg_cleaned=", msg_cleaned,
    );
}

fn main() {
    test_ab_c2_01_router_suffix_chain();
    test_ab_c2_02_request_transactional_rollback();
    test_ab_c2_03_load_balancer_recovery();
    test_ab_c2_04_websocket_session_invariants();
}

// CHECK: AB-C2-01: setup=true gz=10:archive tar=12:archive.tar t=12:archive.t p=21:icon.p
// CHECK-NEXT: AB-C2-02: miss=true url_ovf=true loc_ovf=true flag_ok=true json_rollback=true
// CHECK-NEXT: AB-C2-03: tripped=true probe_transition=true probe_selectable=true ch_built=true weighted_ok=true
// CHECK-NEXT: AB-C2-04: frag_unlimited=true no_ghost_ping=true msg_cleaned=true
