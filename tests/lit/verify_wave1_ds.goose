// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose %s | %FileCheck %s
// Wave 1 Data Structures Verification:
// 1. SWAR 8-way control-tag index (`core::swar_index_*`)
// 2. HTTP/2 Connection SWAR stream lookup + `ctz` slot bitmap
// 3. `SoAConnTable` hashed timing wheel (`wheel_mask: u64[4]`) + 2-level free-slot bitmap
// 4. Zero-copy canonical route borrow + Goose-exclusive `PackedRoute..[>..]` + `from_bytes`

import std;
import wing from "../..";

fn test_swar_index() {
    var ctrl:  u8[256]  = [core::SWAR_CTRL_EMPTY; 256];
    var keys:  u64[256] = [0; 256];
    var slots: u16[256] = [0; 256];
    var gens:  u16[256] = [0; 256];

    // Insert 180 keys (~70% load factor) with non-trivial strided IDs
    for i in 180 {
        let k = (i as u64) * 131 + 7;
        let probe = core::swar_index_get_or_put(ctrl[..], keys[..], slots[..], gens[..], k);
        assert(!probe.found && probe.bucket_idx >= 0);
        let gen, ok = core::swar_index_commit_put(
            ctrl[..], keys[..], slots[..], gens[..], probe.bucket_idx, k, i as u16,
        );
        assert(ok && gen == 1);
    }

    // Delete every even key (tests both EMPTY and DELETED tombstones)
    for i in 180 {
        if (i & 1) == 0 {
            let k = (i as u64) * 131 + 7;
            let rem = core::swar_index_remove(ctrl[..], keys[..], slots[..], gens[..], k);
            assert(rem.found && rem.slot_idx == (i as i32));
            let miss = core::swar_index_get(ctrl[..], keys[..], slots[..], gens[..], k);
            assert(!miss.found);
        }
    }

    // All odd keys must still hit exact slot
    for i in 180 {
        let k = (i as u64) * 131 + 7;
        let hit = core::swar_index_get(ctrl[..], keys[..], slots[..], gens[..], k);
        if (i & 1) == 1 {
            assert(hit.found && hit.slot_idx == (i as i32));
        } else {
            assert(!hit.found);
        }
    }

    // Re-insert 90 fresh keys and verify ABA generation increments on reused slots
    for i in 90 {
        let k = 100000 + (i as u64) * 17;
        let probe = core::swar_index_get_or_put(ctrl[..], keys[..], slots[..], gens[..], k);
        assert(!probe.found && probe.bucket_idx >= 0);
        let gen, ok = core::swar_index_commit_put(
            ctrl[..], keys[..], slots[..], gens[..], probe.bucket_idx, k, (200 + i) as u16,
        );
        assert(ok && gen >= 1);
        let check = core::swar_index_get(ctrl[..], keys[..], slots[..], gens[..], k);
        assert(check.found && check.slot_idx == (200 + i) as i32);
    }

    core::swar_index_clear(ctrl[..], keys[..]);
    let after_clr = core::swar_index_get(ctrl[..], keys[..], slots[..], gens[..], 7);
    assert(!after_clr.found);
    // CHECK: swar_index: PASS
    print("swar_index: PASS\n");
}

fn test_h2_stream_bitmap_and_swar() {
    var conn = http2::new_h2_connection(1000, 8192, false);
    for i in 128 {
        let sid = ((i as u32) * 2) + 1;
        http2::open_stream(conn, sid, true);
    }
    assert(conn.active_stream_count == 128);

    // Close 64 streams (every second one) via local close + RST
    for i in 64 {
        let sid = ((i as u32) * 4) + 1;
        if (i & 1) == 0 {
            http2::close_local_stream(conn, sid);
        } else {
            http2::reset_stream(conn, sid);
        }
        let _, found = http2::find_stream_idx(conn, sid);
        assert(!found);
    }
    assert(conn.active_stream_count == 64);

    // Open 64 replacement streams; `ctz` bitmap must reuse freed slots without exceeding 128 capacity
    for i in 64 {
        let sid = 1001 + ((i as u32) * 2);
        http2::open_stream(conn, sid, false);
        let s_idx, found = http2::find_stream_idx(conn, sid);
        assert(found && s_idx >= 0 && s_idx < 128);
    }
    assert(conn.active_stream_count == 128);
    assert(conn.streams.len == 128);
    // CHECK: h2_swar_bitmap: PASS
    print("h2_swar_bitmap: PASS\n");
}

fn test_soa_wheel_and_free_bitmap() {
    var table = server::SoAConnTable { max_slots: 6000, .. };
    var wheel = core::TickTimerWheel { current_tick: 238, idle_timeout_sec: 10, .. };

    // Arm slots at tick 239 (delay 1 -> wraps near 240), tick 1 (delay 3), and tick 20 (delay 22)
    let s0 = server::soa_table_alloc(table, 100, core::tick_timer_arm(wheel, 1));
    let s1 = server::soa_table_alloc(table, 101, core::tick_timer_arm(wheel, 3));
    let s2 = server::soa_table_alloc(table, 102, core::tick_timer_arm(wheel, 22));
    assert(s0 == 0 && s1 == 1 && s2 == 2);

    // Re-arm s1 to delay 30 (tick 28); old bucket (1) must not fire when crossing 239..2
    server::soa_table_touch(table, s1, core::tick_timer_arm(wheel, 30));

    // Advance 4 seconds across the 240 wrap boundary: prev=238, current=2 -> expired buckets {239, 0, 1, 2}
    let _ = core::tick_timer_advance(wheel, 4);
    var exp: i64[16] = [0; 16];
    let n_wrap = server::soa_table_sweep_expired(table, wheel, exp[..]);
    assert(n_wrap == 1 && exp[0] == s0);
    server::soa_table_free(table, s0);

    // Lowest free index after freeing s0 must be s0 == 0 on next alloc
    let s_reused = server::soa_table_alloc(table, 200, core::tick_timer_arm(wheel, 50));
    assert(s_reused == s0);

    // Idle step with elapsed = 0 returns 0 in O(1)
    let _ = core::tick_timer_advance(wheel, 0);
    assert(server::soa_table_sweep_expired(table, wheel, exp[..]) == 0);

    // Non-overlapping 1-second tick (2 -> 3) finds 0 expired sockets via wheel_mask AND
    let _ = core::tick_timer_advance(wheel, 1);
    assert(server::soa_table_sweep_expired(table, wheel, exp[..]) == 0);

    // Full wrap advance (elapsed >= 240) expires all active armed connections
    let _ = core::tick_timer_advance(wheel, 240);
    let n_all = server::soa_table_sweep_expired(table, wheel, exp[..]);
    assert(n_all == 3);
    // CHECK: soa_wheel_bitmap: PASS
    print("soa_wheel_bitmap: PASS\n");
}

fn check_route_parity(
    tree:   const server::RadixTree&,
    packed: const server::PackedRoute..[>..]&,
    path:   const u8[:],
    want:   i32,
) {
    var p_radix = http::ZeroAllocParams { .. };
    var p_packed = http::ZeroAllocParams { .. };
    let r1 = server::match_path(tree, path, p_radix);
    let r2 = server::match_packed_route(packed, path, p_packed);

    let id1 = match r1 {
        Found f => f.handler_id,
        _ => -1,
    };
    let id2 = match r2 {
        Found f => f.handler_id,
        _ => -1,
    };
    assert(id1 == want && id2 == want);
    assert(p_radix.len == p_packed.len);
    for i in p_radix.len {
        assert(http::param_key(p_radix, i, "") == http::param_key(p_packed, i, ""));
        assert(p_radix.spans[i].val_start == p_packed.spans[i].val_start);
        assert(p_radix.spans[i].val_end == p_packed.spans[i].val_end);
    }
}

fn test_packed_route_and_from_bytes() {
    var tree = server::new_radix_tree();
    assert(server::insert_route(tree, "/", 1));
    assert(server::insert_route(tree, "/health", 2));
    assert(server::insert_route(tree, "/api/v1/users", 3));
    assert(server::insert_route(tree, "/users/profile", 4));
    assert(server::insert_route(tree, "/users/{id}", 5));
    assert(server::insert_route(tree, "/users/{id}/settings", 6));
    assert(server::insert_route(tree, "/files/{name}.json", 7));
    assert(server::insert_route(tree, "/static/{*filepath}", 8));

    var packed: server::PackedRoute..[>..] = [];
    assert(server::compile_packed_route_tree(tree, packed));

    let payload = packed.bytes_of();
    assert(payload.len > 0 && payload.len < 2048);
    print("packed_bytes:", payload.len, "\n");

    check_route_parity(tree, packed, "/", 1);
    check_route_parity(tree, packed, "/health", 2);
    check_route_parity(tree, packed, "/api/v1/users", 3);
    check_route_parity(tree, packed, "/users/profile", 4);
    check_route_parity(tree, packed, "/users/42", 5);
    check_route_parity(tree, packed, "/users/42/settings", 6);
    check_route_parity(tree, packed, "/users/profile/settings", 6);
    check_route_parity(tree, packed, "/files/report.json", 7);
    check_route_parity(tree, packed, "/static/css/app.min.css", 8);
    check_route_parity(tree, packed, "/api/v1/../users//42?active=1", -1);
    check_route_parity(tree, packed, "/api//v1/./users?ok=1", 3);
    check_route_parity(tree, packed, "/missing/route", -1);

    // Verified zero-copy snapshot serialization and reload
    var image: u8[>..] = packed.to_bytes();
    var reloaded, ok = from_bytes<server::PackedRoute..[>..]>(image);
    assert(ok);
    check_route_parity(tree, reloaded, "/users/99/settings", 6);
    check_route_parity(tree, reloaded, "/static/js/main.js", 8);

    // Tampered image & truncated image must be rejected
    var cut: u8[>..] = [];
    cut.append(image);
    cut.pop();
    var _, ok_cut = from_bytes<server::PackedRoute..[>..]>(cut);
    assert(!ok_cut);

    var bad: u8[>..] = [];
    bad.append(image);
    bad[image.len - 2] = bad[image.len - 2] ^ 0xFF;
    var _, ok_bad = from_bytes<server::PackedRoute..[>..]>(bad);
    assert(!ok_bad);

    // CHECK: packed_route: PASS
    print("packed_route: PASS\n");
}

fn main() {
    test_swar_index();
    test_h2_stream_bitmap_and_swar();
    test_soa_wheel_and_free_bitmap();
    test_packed_route_and_from_bytes();
}
