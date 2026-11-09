// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Goose LIT Verification Suite: SoAConnTable 10,240-Slot Churn, TickTimerWheel Slowloris Reaping & Pool Soak
// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn verify_soa_conn_table_churn() {
    var table = wing::SoAConnTable { .. };
    var wheel = wing::new_tick_timer_wheel(10);
    var expired: i64[4096] = [0; 4096];

    for wave in 10 {
        let short_tick = wing::tick_timer_arm(wheel, 5);
        let long_tick = wing::tick_timer_arm(wheel, 20);

        for i in 4096 {
            let fd = (wave + 1) * 10000 + i + 1;
            let tick = if (i & 1) == 0 { short_tick } else { long_tick };
            let slot = wing::soa_table_alloc(table, fd, tick);
            assert(slot == i);
            wing::soa_table_set_peer_ip(table, slot, "198.51.100.42");
            assert(wing::soa_table_get_peer_ip(table, slot) == "198.51.100.42");
        }
        assert(table.count == 4096);

        // 4097th slot allocation under saturation must fail closed with SOA_INVALID_FD (-1)
        assert(wing::soa_table_alloc(table, 999999, short_tick) == wing::SOA_INVALID_FD);

        // Advance tick wheel by 6 seconds: all 2048 short_tick (5s) Slowloris slots must expire
        let _ = wing::tick_timer_advance(wheel, 6);
        let n_exp = wing::soa_table_sweep_expired(table, wheel, expired[..]);
        assert(n_exp == 2048);
        for k in n_exp {
            wing::soa_table_free(table, expired[k]);
        }

        // Release remaining 2048 active slots in reverse order to exercise high-water mark trimming
        var rev: i64 = 4095;
        while rev >= 0 {
            if table.fds[rev] > 0 {
                wing::soa_table_free(table, rev);
            }
            rev -= 1;
        }
        assert(table.count == 0);
        assert(wing::soa_table_get_peer_ip(table, 0) == "");
    }
    print("SOA_CONN_TABLE_10240_CHURN: ok");
}

fn verify_server_pools_saturation_and_zeroize() {
    var hdr_pool = internal::HeaderMapPool { .. };
    var ext_pool = internal::ExtensionsPool { .. };
    var slab_pool = internal::SpillSlabPool { .. };

    for _ in 32 {
        for i in 16 {
            let h_idx = internal::acquire_header_map(hdr_pool);
            let e_idx = internal::acquire_extensions(ext_pool);
            let s_idx = internal::acquire_spill_slab(slab_pool);
            assert(h_idx == i && e_idx == i && s_idx == i);
            ext_pool.slots[e_idx].populated_entries = internal::ENTRY_COOKIES | internal::ENTRY_SECURITY;
            ext_pool.slots[e_idx].session_data.append("secret-session-cookie-material");
            ext_pool.slots[e_idx].jwt_claims.sub.append("admin-user");
        }
        // Pool saturation must return -1
        assert(internal::acquire_header_map(hdr_pool) == -1);
        assert(internal::acquire_extensions(ext_pool) == -1);
        assert(internal::acquire_spill_slab(slab_pool) == -1);

        for i in 16 {
            let idx = i as i32;
            internal::release_header_map(hdr_pool, idx);
            internal::release_extensions(ext_pool, idx);
            internal::release_spill_slab(slab_pool, idx);
            assert(ext_pool.slots[i].session_data.len == 0);
            assert(ext_pool.slots[i].jwt_claims.sub.len == 0);
        }
    }
    print("SERVER_POOLS_SATURATION_ZEROIZE: ok");
}

fn verify_wire_soak_mixed_traffic() {
    var srv = wing::new_http_server("127.0.0.1", 18080);
    wing::add_static_get_route(srv, "/healthz", "text/plain", "ok", 1);

    var wire_out: u8[..4096] = [];
    for iter in 200 {
        let now_ns = ((iter + 1) * 1000000) as u64;

        // 1. Malformed smuggling frame (CL + TE conflict)
        wire_out.clear();
        let _, _ = wing::handle_connection_wire(
            srv,
            "127.0.0.1",
            "POST /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nContent-Length: 4\r\nTransfer-Encoding: chunked\r\n\r\n0\r\n\r\n",
            now_ns,
            wire_out,
        );

        // 2. Truncated Slowloris header fragment
        wire_out.clear();
        let _, ok_trunc = wing::handle_connection_wire(
            srv,
            "127.0.0.1",
            "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\nX-Incomplete: val",
            now_ns,
            wire_out,
        );
        assert(!ok_trunc);

        // 3. Valid health check request must always succeed cleanly right after malformed/truncated frames
        wire_out.clear();
        let outcome, ok_valid = wing::handle_connection_wire(
            srv,
            "127.0.0.1",
            "GET /healthz HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n",
            now_ns,
            wire_out,
        );
        assert(ok_valid && outcome == wing::PipelineOutcome.Handled);
        assert(find(wire_out[..], "200 OK") >= 0);
    }
    print("WIRE_SOAK_MIXED_TRAFFIC: ok");
}

fn main() {
    // CHECK: === verify_reactor_soa_soak ===
    print("=== verify_reactor_soa_soak ===");
    // CHECK-NEXT: SOA_CONN_TABLE_10240_CHURN: ok
    verify_soa_conn_table_churn();
    // CHECK-NEXT: SERVER_POOLS_SATURATION_ZEROIZE: ok
    verify_server_pools_saturation_and_zeroize();
    // CHECK-NEXT: WIRE_SOAK_MIXED_TRAFFIC: ok
    verify_wire_soak_mixed_traffic();
    // CHECK-NEXT: ALL_REACTOR_SOA_SOAK_CHECKS_PASSED
    print("ALL_REACTOR_SOA_SOAK_CHECKS_PASSED");
}
