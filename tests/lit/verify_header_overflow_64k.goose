// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification of 64 KiB `http::OverflowArena` spill, zero-copy `http::HeaderView`,
// reverse proxy 64 KiB header forwarding, and HTTP/2 + HTTP/3 streaming edge 64 KiB support.
//
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import wing from "../..";

fn fill_pattern(dst: u8[:], ch: u8) {
    for i in dst.len {
        dst[i] = ch;
    }
}

fn append_numbered_headers(
    map:    http::HeaderMap&,
    arena:  http::OverflowArena&,
    count:  i64,
    prefix: const u8[:],
) {
    var name_buf: u8[..32] = [];
    var val_buf:  u8[..32] = [];
    for i in count {
        name_buf.clear();
        val_buf.clear();
        assert(name_buf.try_append(prefix));
        i.format_i64_dec(name_buf);
        assert(val_buf.try_append("val-"));
        i.format_i64_dec(val_buf);
        assert(http::append_header_spill(map, arena, name_buf[..], val_buf[..]));
    }
}

fn test_overflow_arena_stack_spill_and_rollback() {
    var map = http::HeaderMap { .. };
    var arena = http::OverflowArena { .. };
    http::reset_overflow_arena(arena);

    // 1. Fast path: <= 8192 B and < 128 entries performs zero arena mutations.
    assert(http::append_header_spill(map, arena, "X-Short-1", "alpha"));
    assert(http::append_header_spill(map, arena, "X-Short-2", "beta"));
    assert(arena.spill_raw.len == 0 && arena.spill_entries.len == 0);
    assert(http::header_count_spill(map, arena) == 2);

    // 2. Spill raw bytes (> 8192 B) while keeping mixed stack entries cleanly addressable.
    var big_auth: u8[24000] = ['A'; 24000];
    big_auth[0] = 'B';
    big_auth[23999] = 'Z';
    assert(http::append_header_spill(
        map, arena, "Authorization", big_auth[..], http::HEADER_FLAG_SENSITIVE,
    ));
    assert(map.entries.len == 3 && arena.spill_entries.len == 0);
    assert(map.entries[2].reserved == http::HEADER_SRC_ARENA);
    assert(http::is_sensitive(map.entries[2]));
    assert(arena.spill_raw.len == 13 + 24000);

    // Mixed stack entry inserted after an arena raw spill still lands in stack map.
    assert(http::append_header_spill(map, arena, "X-After-Big", "still-stack"));
    assert(map.entries[3].reserved == http::HEADER_SRC_STACK);
    assert(http::get_header_spill(map, arena, "Authorization") == big_auth[..]);
    assert(http::get_header_spill(map, arena, "x-after-big") == "still-stack");

    // 3. Spill > 128 entries cleanly across map.entries and arena.spill_entries.
    append_numbered_headers(map, arena, 196, "X-H-");
    assert(http::header_count_spill(map, arena) == 200);
    assert(map.entries.len == 128 && arena.spill_entries.len == 72);
    assert(http::has_header_spill(map, arena, "x-h-195"));
    assert(http::get_header_spill(map, arena, "x-h-195") == "val-195");

    let e0, ok0 = http::header_entry_at_spill(map, arena, 0);
    assert(ok0 && http::entry_name_spill(map, arena, e0) == "X-Short-1");
    assert(http::entry_value_spill(map, arena, e0) == "alpha");
    let e199, ok199 = http::header_entry_at_spill(map, arena, 199);
    assert(ok199 && http::entry_name_spill(map, arena, e199) == "X-H-195");
    assert(http::entry_value_spill(map, arena, e199) == "val-195");
    let _, ok_oob = http::header_entry_at_spill(map, arena, 200);
    let _, ok_neg = http::header_entry_at_spill(map, arena, -1);
    assert(!ok_oob && !ok_neg);

    // 4. Connection token check & comma combining across spill storage.
    assert(http::append_header_spill(map, arena, "Connection", "keep-alive, X-H-195"));
    assert(http::is_token_in_connection_header_spill(map, arena, "x-h-195"));
    assert(!http::is_token_in_connection_header_spill(map, arena, "x-short-1"));
    assert(http::append_header_spill(map, arena, "X-Multi", "one"));
    assert(http::append_header_spill(map, arena, "x-multi", "two"));
    var comb_buf: u8[..64] = [];
    assert(http::get_combined_spill(map, arena, "X-Multi", comb_buf));
    assert(comb_buf[..] == "one, two");
    assert(http::append_header_spill(map, arena, "Set-Cookie", "a=1"));
    assert(!http::get_combined_spill(map, arena, "Set-Cookie", comb_buf));

    // 5. Capacity exhaustion (> 65535 spill raw bytes) rolls back map + arena cleanly.
    let saved_map_entries = map.entries.len;
    let saved_map_raw = map.raw_buf.len;
    let saved_spill_entries = arena.spill_entries.len;
    let saved_spill_raw = arena.spill_raw.len;
    var giant: u8[45000] = ['G'; 45000];
    assert(!http::append_header_spill(map, arena, "X-Overflow", giant[..]));
    assert(map.entries.len == saved_map_entries && map.raw_buf.len == saved_map_raw);
    assert(arena.spill_entries.len == saved_spill_entries);
    assert(arena.spill_raw.len == saved_spill_raw);

    // 6. Entry spill ceiling (> 512 spill entries) rolls back cleanly.
    var many_map = http::HeaderMap { .. };
    var many_arena = http::OverflowArena { .. };
    append_numbered_headers(many_map, many_arena, 640, "x-m-");
    assert(many_map.entries.len == 128);
    assert(many_arena.spill_entries.len == http::MAX_OVERFLOW_SPILL_ENTRIES);
    let sr_before = many_arena.spill_raw.len;
    assert(!http::append_header_spill(many_map, many_arena, "x-m-640", "v"));
    assert(many_arena.spill_entries.len == http::MAX_OVERFLOW_SPILL_ENTRIES);
    assert(many_arena.spill_raw.len == sr_before);

    print("HTTP_OVERFLOW_ARENA: OK\n");
    // CHECK: HTTP_OVERFLOW_ARENA: OK
}

fn test_header_view_fast_spill_and_rollback() {
    var entries: http::HeaderEntry[..512] = [];
    var raw:     u8[..65536]              = [];

    // Helper closure-style builder: populate view directly with 1 fast and 1 20 KiB header.
    let n1 = "Host";
    let v1 = "view.example.test";
    let nb1 = raw.len as u16;
    raw.append(n1);
    let ne1 = raw.len as u16;
    raw.append(v1);
    let ve1 = raw.len as u16;
    entries.push(http::HeaderEntry {
        name_begin:   nb1,
        name_end:     ne1,
        values_begin: ne1,
        values_end:   ve1,
        name_hash:    http::hash_header_name(n1),
    });

    var dst_fast = http::HeaderMap { .. };
    var arena_fast = http::OverflowArena { .. };
    let v_fast = http::HeaderView { entries: entries[..], raw: raw[..] };
    assert(http::header_view_name(v_fast, entries[0]) == "Host");
    assert(http::header_view_value(v_fast, entries[0]) == "view.example.test");
    let got_host, ok_host = http::header_view_get(v_fast, "HOST");
    assert(ok_host && got_host == "view.example.test");
    let _, ok_miss = http::header_view_get(v_fast, "X-Missing");
    assert(!ok_miss);
    assert(http::header_view_copy_to_spill(v_fast, dst_fast, arena_fast));
    assert(arena_fast.spill_raw.len == 0 && arena_fast.spill_entries.len == 0);
    assert(http::get_header(dst_fast, "host") == "view.example.test");

    // Append 20 KiB header to the view and copy with spill.
    var big_v: u8[20480] = ['V'; 20480];
    let n2 = "X-Large-Token";
    let nb2 = raw.len as u16;
    raw.append(n2);
    let ne2 = raw.len as u16;
    raw.append(big_v[..]);
    let ve2 = raw.len as u16;
    entries.push(http::HeaderEntry {
        name_begin:   nb2,
        name_end:     ne2,
        values_begin: ne2,
        values_end:   ve2,
        flags:        http::HEADER_FLAG_SENSITIVE,
        name_hash:    http::hash_header_name(n2),
    });
    let v_big = http::HeaderView { entries: entries[..], raw: raw[..] };
    let got_big, ok_big = http::header_view_get(v_big, "x-large-token");
    assert(ok_big && got_big.len == 20480);

    var dst_spill = http::HeaderMap { .. };
    var arena_spill = http::OverflowArena { .. };
    assert(http::header_view_copy_to_spill(v_big, dst_spill, arena_spill));
    assert(http::get_header_spill(dst_spill, arena_spill, "X-Large-Token") == big_v[..]);
    assert(http::is_sensitive(dst_spill.entries[1]));

    // Invalid entry triggers rollback of both out_map and out_arena.
    let nb3 = raw.len as u16;
    raw.append("Bad Name");
    let ne3 = raw.len as u16;
    entries.push(http::HeaderEntry {
        name_begin:   nb3,
        name_end:     ne3,
        values_begin: ne3,
        values_end:   ne3,
        name_hash:    http::hash_header_name("Bad Name"),
    });
    let v_bad = http::HeaderView { entries: entries[..], raw: raw[..] };
    assert(!http::header_view_copy_to_spill(v_bad, dst_spill, arena_spill));
    assert(dst_spill.entries.len == 0 && dst_spill.raw_buf.len == 0);
    assert(arena_spill.spill_entries.len == 0 && arena_spill.spill_raw.len == 0);

    print("HTTP_HEADER_VIEW: OK\n");
    // CHECK: HTTP_HEADER_VIEW: OK
}

fn test_proxy_64k_spill() {
    var rp = proxy::new_reverse_proxy(proxy::LbPolicy.RoundRobin);
    assert(proxy::add_upstream_target(rp.cluster, "backend.internal", 8443, 1));
    rp.config.preserve_host = false;
    rp.config.append_forwarded = true;
    rp.config.strip_hop_by_hop = true;

    var in_map = http::HeaderMap { .. };
    var in_arena = http::OverflowArena { .. };
    assert(http::append_header_spill(in_map, in_arena, "Host", "edge.example.test"));
    assert(http::append_header_spill(in_map, in_arena, "Connection", "X-Private-Hop"));
    assert(http::append_header_spill(in_map, in_arena, "X-Private-Hop", "drop-me"));

    var big_auth: u8[24000] = ['K'; 24000];
    assert(http::append_header_spill(in_map, in_arena, "Authorization", big_auth[..]));
    var big_ext: u8[12000] = ['X'; 12000];
    assert(http::append_header_spill(in_map, in_arena, "X-Big-Ext", big_ext[..]));
    append_numbered_headers(in_map, in_arena, 140, "X-Meta-");

    var out_map = http::HeaderMap { .. };
    var out_arena = http::OverflowArena { .. };
    assert(proxy::filter_and_forward_headers_spill(
        in_map,
        in_arena,
        out_map,
        out_arena,
        "192.0.2.55",
        "https",
        "backend.internal:8443",
        rp.config,
    ));
    assert(!http::has_header_spill(out_map, out_arena, "X-Private-Hop"));
    assert(!http::has_header_spill(out_map, out_arena, "Connection"));
    assert(http::get_header_spill(out_map, out_arena, "Authorization") == big_auth[..]);
    assert(http::get_header_spill(out_map, out_arena, "X-Big-Ext") == big_ext[..]);
    assert(http::get_header_spill(out_map, out_arena, "X-Meta-139") == "val-139");
    assert(http::get_header_spill(out_map, out_arena, "X-Forwarded-For") == "192.0.2.55");
    assert(http::get_header_spill(out_map, out_arena, "Host") == "backend.internal:8443");

    var wire_req: u8[>..] = [];
    assert(proxy::serialize_upstream_request_spill(
        "POST", "/big-upload", out_map, out_arena, "payload", wire_req,
    ));
    assert(core::starts_with(wire_req[..], "POST /big-upload HTTP/1.1\r\n"));
    assert(core::contains(wire_req[..], "X-Meta-139: val-139\r\n"));
    assert(core::contains(wire_req[..], "Content-Length: 7\r\n"));
    assert(core::ends_with(wire_req[..], "\r\n\r\npayload"));
    assert(wire_req.len > 36000);

    var head_wire: u8[>..] = [];
    let t_idx, ok_head = proxy::prepare_proxy_head_with_key_at_spill(
        rp, "GET", "/stream", in_map, in_arena, "192.0.2.55", "https", "rk1", head_wire, 1000,
    );
    assert(ok_head && t_idx == 0);
    assert(core::starts_with(head_wire[..], "GET /stream HTTP/1.1\r\n"));
    assert(core::contains(head_wire[..], "X-Meta-139: val-139\r\n"));
    assert(!core::contains(head_wire[..], "X-Private-Hop"));
    assert(head_wire.len > 36000);

    print("PROXY_64K_SPILL: OK\n");
    // CHECK: PROXY_64K_SPILL: OK
}

fn append_h2_frame_local(
    out:        u8[>..]&,
    frame_type: u8,
    flags:      u8,
    stream_id:  u32,
    payload:    const u8[:],
) {
    let hdr = wire::WireFrameHeader {
        length:     payload.len as u32,
        frame_type: frame_type,
        flags:      flags,
        stream_id:  stream_id,
    };
    assert(wire::encode_frame_header(hdr, out));
    out.append(payload);
}

fn encode_h2_req_block(
    dt:        http2::DynamicTable&,
    path:      const u8[:],
    big_val:   const u8[:],
    extra_cnt: i64,
    out_hpack: u8[>..]&,
) {
    out_hpack.clear();
    assert(http2::encode_hpack_field(dt, out_hpack, ":method", "GET", http2::HpackIndexing.None, false));
    assert(http2::encode_hpack_field(dt, out_hpack, ":scheme", "https", http2::HpackIndexing.None, false));
    assert(http2::encode_hpack_field(dt, out_hpack, ":authority", "h2.example.test", http2::HpackIndexing.None, false));
    assert(http2::encode_hpack_field(dt, out_hpack, ":path", path, http2::HpackIndexing.None, false));
    if big_val.len > 0 {
        assert(http2::encode_hpack_field(dt, out_hpack, "authorization", big_val, http2::HpackIndexing.None, false));
    }
    var nm: u8[..24] = [];
    for i in extra_cnt {
        nm.clear();
        assert(nm.try_append("x-hdr-"));
        i.format_i64_dec(nm);
        assert(http2::encode_hpack_field(dt, out_hpack, nm[..], "ok", http2::HpackIndexing.None, false));
    }
}

fn append_h2_fragmented_req(out_wire: u8[>..]&, stream_id: u32, hpack_block: const u8[:], end_stream: bool) {
    var off: i64 = 0;
    while off < hpack_block.len {
        let take = min(16384, hpack_block.len - off);
        let next_off = off + take;
        let ft = if off == 0 { rfc::H2_FRAME_HEADERS } else { rfc::H2_FRAME_CONTINUATION };
        var fl: u8 = 0;
        if off == 0 && end_stream {
            fl |= rfc::H2_FLAG_END_STREAM;
        }
        if next_off == hpack_block.len {
            fl |= rfc::H2_FLAG_END_HEADERS;
        }
        append_h2_frame_local(out_wire, ft, fl, stream_id, hpack_block[off..next_off]);
        off = next_off;
    }
}

fn test_http2_64k_spill_and_view() {
    // 1. Standalone HPACK spill decode > 24 KiB + > 128 headers + split Cookie spill.
    var enc_dt = http2::new_dynamic_table(4096);
    var dec_dt = http2::new_dynamic_table(4096);
    var big_auth: u8[24000] = ['H'; 24000];
    var hblk:     u8[>..]   = [];
    encode_h2_req_block(enc_dt, "/h2-spill", big_auth[..], 140, hblk);
    var ck1: u8[5000] = ['c'; 5000];
    var ck2: u8[5000] = ['d'; 5000];
    assert(http2::encode_hpack_field(enc_dt, hblk, "cookie", ck1[..], http2::HpackIndexing.None, false));
    assert(http2::encode_hpack_field(enc_dt, hblk, "cookie", ck2[..], http2::HpackIndexing.None, false));

    var dec_pseudo = http2::PseudoHeaders { .. };
    var dec_map = http::HeaderMap { .. };
    var dec_arena = http::OverflowArena { .. };
    let herr = http2::decode_hpack_to_map_spill(dec_dt, hblk[..], dec_pseudo, dec_map, dec_arena, 65535, true);
    assert(herr == rfc::H2_ERR_NO_ERROR);
    assert(http::get_header_spill(dec_map, dec_arena, "authorization") == big_auth[..]);
    assert(http::get_header_spill(dec_map, dec_arena, "x-hdr-139") == "ok");
    let ck_got = http::get_header_spill(dec_map, dec_arena, "cookie");
    assert(ck_got.len == 5000 + 2 + 5000);

    // 2. H2EdgeSession: HeaderView zero-copy, Spill poll, legacy behavior, and send_headers_spill.
    var sess = http2::h2_edge_open(128, 65535);
    defer http2::h2_edge_close(sess);
    var srv_init: u8[>..] = [];
    let _ = http2::h2_edge_drain_wire(sess, srv_init);

    var cli_wire: u8[>..] = [];
    cli_wire.append(rfc::H2_CLIENT_PREFACE[..]);
    let cli_set: wire::WireSetting[2] = [
        wire::WireSetting { id: rfc::H2_SETTING_MAX_CONCURRENT_STREAMS, val: 128 },
        wire::WireSetting { id: rfc::H2_SETTING_MAX_HEADER_LIST_SIZE, val: 65535 },
    ];
    assert(wire::encode_settings_frame(cli_set[..], cli_wire));
    append_h2_frame_local(cli_wire, rfc::H2_FRAME_SETTINGS, rfc::H2_FLAG_ACK, 0, "");

    var cli_dt = http2::new_dynamic_table(4096);
    var blk1: u8[>..] = [];
    encode_h2_req_block(cli_dt, "/view-64k", big_auth[..], 4, blk1);
    append_h2_fragmented_req(cli_wire, 1, blk1[..], true);

    var blk3: u8[>..] = [];
    encode_h2_req_block(cli_dt, "/spill-64k", big_auth[..], 140, blk3);
    append_h2_fragmented_req(cli_wire, 3, blk3[..], true);

    var blk5: u8[>..] = [];
    encode_h2_req_block(cli_dt, "/legacy-fail", big_auth[..], 2, blk5);
    append_h2_fragmented_req(cli_wire, 5, blk5[..], true);

    var blk7: u8[>..] = [];
    encode_h2_req_block(cli_dt, "/legacy-ok", "", 2, blk7);
    append_h2_fragmented_req(cli_wire, 7, blk7[..], true);

    let fed, ok_fed = http2::h2_edge_feed(sess, cli_wire[..]);
    assert(ok_fed && fed == cli_wire.len);

    var ev_view = http2::H2EdgeEventView { .. };
    assert(http2::h2_edge_poll_event_view(sess, ev_view));
    assert(ev_view.kind == http2::H2EdgeEventKind.RequestHead && ev_view.stream_id == 1);
    let auth_v, ok_av = http::header_view_get(ev_view.headers, "authorization");
    assert(ok_av && auth_v == big_auth[..]);
    let path_v, ok_pv = http::header_view_get(ev_view.headers, ":path");
    assert(ok_pv && path_v == "/view-64k");

    var ev_spill = http2::H2EdgeEvent { .. };
    var poll_arena = http::OverflowArena { .. };
    assert(http2::h2_edge_poll_event_spill(sess, ev_spill, poll_arena));
    assert(ev_spill.kind == http2::H2EdgeEventKind.RequestHead && ev_spill.stream_id == 3);
    assert(http::get_header_spill(ev_spill.headers, poll_arena, "authorization") == big_auth[..]);
    assert(http::get_header_spill(ev_spill.headers, poll_arena, "x-hdr-139") == "ok");

    // Stream 5 (> 8 KiB) fails cleanly on legacy h2_edge_poll_event; stream 7 (<= 8 KiB) succeeds.
    assert(!http2::h2_edge_poll_event(sess, ev_spill));
    assert(ev_spill.kind == http2::H2EdgeEventKind.None && ev_spill.headers.entries.len == 0);
    assert(http2::h2_edge_poll_event(sess, ev_spill));
    assert(ev_spill.kind == http2::H2EdgeEventKind.RequestHead && ev_spill.stream_id == 7);
    assert(http::get_header(ev_spill.headers, ":path") == "/legacy-ok");

    // 3. Response 24 KiB send via h2_edge_send_headers_spill emits HEADERS + CONTINUATION.
    var resp_map = http::HeaderMap { .. };
    var resp_arena = http::OverflowArena { .. };
    assert(http::append_header_spill(resp_map, resp_arena, "x-big-resp", big_auth[..]));
    append_numbered_headers(resp_map, resp_arena, 140, "x-r-");
    assert(http2::h2_edge_send_headers_spill(sess, 7, 200, resp_map, resp_arena, true));
    var out_w: u8[>..] = [];
    let drained = http2::h2_edge_drain_wire(sess, out_w);
    assert(drained > 16384);
    var fr = wire::new_wire_h2_frame_reader(out_w[..]);
    var hpack_resp: u8[>..] = [];
    var cont_count: i32     = 0;
    while wire::has_next(fr) {
        let fh, fp, f_ok = wire::next_frame(fr);
        assert(f_ok);
        if fh.stream_id == 7 && (fh.frame_type == rfc::H2_FRAME_HEADERS || fh.frame_type == rfc::H2_FRAME_CONTINUATION) {
            if fh.frame_type == rfc::H2_FRAME_CONTINUATION {
                cont_count += 1;
            }
            hpack_resp.append(fp);
        }
    }
    assert(cont_count >= 1);
    var cli_resp_dt = http2::new_dynamic_table(4096);
    var r_ps = http2::PseudoHeaders { .. };
    var r_map = http::HeaderMap { .. };
    var r_arena = http::OverflowArena { .. };
    assert(http2::decode_hpack_to_map_spill(cli_resp_dt, hpack_resp[..], r_ps, r_map, r_arena, 65535, true) == 0);
    assert(r_ps.status == 200);
    assert(http::get_header_spill(r_map, r_arena, "x-big-resp") == big_auth[..]);
    assert(http::get_header_spill(r_map, r_arena, "x-r-139") == "val-139");

    print("HTTP2_64K_SPILL_VIEW: OK\n");
    // CHECK: HTTP2_64K_SPILL_VIEW: OK
}

fn encode_h3_req_section(path: const u8[:], big_val: const u8[:], extra_cnt: i64, out_sec: u8[>..]&) {
    out_sec.clear();
    out_sec.push(0x00);
    out_sec.push(0x00);
    assert(http3::encode_qpack_field(out_sec, ":method", "GET"));
    assert(http3::encode_qpack_field(out_sec, ":scheme", "https"));
    assert(http3::encode_qpack_field(out_sec, ":authority", "h3.example.test"));
    assert(http3::encode_qpack_field(out_sec, ":path", path));
    if big_val.len > 0 {
        assert(http3::encode_qpack_field(out_sec, "authorization", big_val, false));
    }
    var nm: u8[..24] = [];
    for i in extra_cnt {
        nm.clear();
        assert(nm.try_append("x-q-"));
        i.format_i64_dec(nm);
        assert(http3::encode_qpack_field(out_sec, nm[..], "ok", false));
    }
}

fn feed_h3_req_stream(sess: http3::H3EdgeSession&, sid: u64, qsec: const u8[:]) {
    var wire: u8[>..] = [];
    assert(http3::encode_headers_frame(wire, qsec));
    assert(http3::h3_edge_feed_bidi_stream(sess, sid, wire[..], true));
}

fn test_http3_64k_spill_and_view() {
    var big_auth: u8[24000] = ['Q'; 24000];
    var qsec:     u8[>..]   = [];
    encode_h3_req_section("/qpack-spill", big_auth[..], 140, qsec);

    var tbl = http3::new_qpack_table(0, 0);
    var ps = http3::PseudoHeaders { .. };
    var qmap = http::HeaderMap { .. };
    var qarena = http::OverflowArena { .. };
    let qerr = http3::decode_or_track_blocked_qpack_to_map_spill(
        tbl, 0, qsec[..], ps, qmap, qarena, 65535,
    );
    assert(qerr == http3::QpackError.None);
    assert(http::get_header_spill(qmap, qarena, "authorization") == big_auth[..]);
    assert(http::get_header_spill(qmap, qarena, "x-q-139") == "ok");

    var sess = http3::h3_edge_open();
    defer http3::h3_edge_close(sess);
    var peer_set = fingerprint::H3Settings { max_field_section_size: 65536, .. };
    var ctrl: u8[..64] = [];
    assert(quic::encode_varint(rfc::H3_STREAM_CONTROL, ctrl));
    assert(http3::encode_settings_frame(ctrl, peer_set));
    assert(http3::h3_edge_feed_uni_stream(sess, 2, ctrl[..], false));

    var sec0: u8[>..] = [];
    encode_h3_req_section("/h3-view", big_auth[..], 4, sec0);
    feed_h3_req_stream(sess, 0, sec0[..]);

    var sec4: u8[>..] = [];
    encode_h3_req_section("/h3-spill", big_auth[..], 140, sec4);
    feed_h3_req_stream(sess, 4, sec4[..]);

    var sec8: u8[>..] = [];
    encode_h3_req_section("/h3-legacy-fail", big_auth[..], 2, sec8);
    feed_h3_req_stream(sess, 8, sec8[..]);

    var sec12: u8[>..] = [];
    encode_h3_req_section("/h3-legacy-ok", "", 2, sec12);
    var leg_tbl = http3::new_qpack_table(0, 0);
    var leg_ps = http3::PseudoHeaders { .. };
    var leg_map = http::HeaderMap { .. };
    assert(http3::decode_or_track_blocked_qpack_to_map(
        leg_tbl, 12, sec12[..], leg_ps, leg_map, 8192,
    ) == http3::QpackError.None);
    assert(http::get_header(leg_map, "x-q-1") == "ok");
    feed_h3_req_stream(sess, 12, sec12[..]);

    var ev_v = http3::H3EdgeEventView { .. };
    assert(http3::h3_edge_poll_event_view(sess, ev_v));
    assert(ev_v.kind == http3::H3EdgeEventKind.RequestHead && ev_v.stream_id == 0);
    let av3, ok_av3 = http::header_view_get(ev_v.headers, "authorization");
    assert(ok_av3 && av3 == big_auth[..]);

    var ev_s = http3::H3EdgeEvent { .. };
    var h3_arena = http::OverflowArena { .. };
    assert(http3::h3_edge_poll_event_spill(sess, ev_s, h3_arena));
    assert(ev_s.kind == http3::H3EdgeEventKind.RequestHead && ev_s.stream_id == 4);
    assert(http::get_header_spill(ev_s.headers, h3_arena, "authorization") == big_auth[..]);
    assert(http::get_header_spill(ev_s.headers, h3_arena, "x-q-139") == "ok");

    assert(!http3::h3_edge_poll_event(sess, ev_s));
    assert(ev_s.kind == http3::H3EdgeEventKind.None && ev_s.headers.entries.len == 0);
    assert(http3::h3_edge_poll_event(sess, ev_s));
    assert(ev_s.kind == http3::H3EdgeEventKind.RequestHead && ev_s.stream_id == 12);
    assert(http::get_header(ev_s.headers, ":path") == "/h3-legacy-ok");

    var resp_map = http::HeaderMap { .. };
    var resp_arena = http::OverflowArena { .. };
    assert(http::append_header_spill(resp_map, resp_arena, "x-h3-big-resp", big_auth[..]));
    append_numbered_headers(resp_map, resp_arena, 140, "x-r3-");
    var out_wire: u8[>..] = [];
    assert(http3::h3_edge_encode_response_headers_spill(sess, 200, resp_map, resp_arena, out_wire));
    assert(out_wire.len > 16384);

    var rdec_tbl = http3::new_qpack_table(0, 0);
    var rdec_ps = http3::PseudoHeaders { .. };
    var rdec_map = http::HeaderMap { .. };
    var rdec_arena = http::OverflowArena { .. };
    // Skip HTTP/3 HEADERS frame type (0x01) + varint length prefix via read_varint.
    let _, f_off1, ok_t = quic::decode_varint(out_wire[..], 0);
    let flen, f_off2, ok_l = quic::decode_varint(out_wire[..], f_off1);
    assert(ok_t && ok_l && (f_off2 + flen) <= (out_wire.len as u64));
    let rdec_err = http3::decode_or_track_blocked_qpack_to_map_spill(
        rdec_tbl,
        0,
        out_wire[(f_off2 as i64)..((f_off2 + flen) as i64)],
        rdec_ps,
        rdec_map,
        rdec_arena,
        65535,
    );
    assert(rdec_err == http3::QpackError.None && rdec_ps.status == 200);
    assert(http::get_header_spill(rdec_map, rdec_arena, "x-h3-big-resp") == big_auth[..]);
    assert(http::get_header_spill(rdec_map, rdec_arena, "x-r3-139") == "val-139");

    print("HTTP3_64K_SPILL_VIEW: OK\n");
    // CHECK: HTTP3_64K_SPILL_VIEW: OK
}

fn main() {
    test_overflow_arena_stack_spill_and_rollback();
    test_header_view_fast_spill_and_rollback();
    test_proxy_64k_spill();
    test_http2_64k_spill_and_view();
    test_http3_64k_spill_and_view();
}
