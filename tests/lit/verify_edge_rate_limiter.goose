// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// RUN: goose build -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s
// CHECK: EDGE_RL_1500_ISOLATION: OK
// CHECK: EDGE_RL_CAPACITY_EVICT: OK
// CHECK: EDGE_RL_4096_DEFAULT: OK
// CHECK: EDGE_RL_IDLE_EVICT: OK
// CHECK: EDGE_RL_FALLBACK_AND_VEC: OK
// CHECK: EDGE_RL_ABA_AND_THREAD_FN: OK
import std;
import wing from "../..";

fn format_ipv4_10_0(idx: i64, out: u8[..64]&) {
    out.clear();
    let _ = out.try_append("10.0.");
    let oct3 = (idx >> 8) as u64;
    let oct4 = (idx & 255) as u64;
    oct3.format_u64_dec(out);
    let _ = out.try_push('.');
    oct4.format_u64_dec(out);
}

fn test_1500_clients_and_eviction() {
    assert(security::DEFAULT_EDGE_RL_MAX_CLIENTS == 4096);
    var lim = security::new_edge_rate_limiter(10, 2, 1500);
    let t0: u64 = 1000000000;
    var ip_buf: u8[..64] = [];

    // 1,500 distinct IPs each get 1 base + 2 burst = 3 allowed, 4th rejected independently.
    for i in 1500 {
        format_ipv4_10_0(i, ip_buf);
        let d1 = security::check_edge_rate_limit(lim, ip_buf[..], 1, t0);
        let d2 = security::check_edge_rate_limit(lim, ip_buf[..], 1, t0);
        let d3 = security::check_edge_rate_limit(lim, ip_buf[..], 1, t0);
        let d4 = security::check_edge_rate_limit(lim, ip_buf[..], 1, t0);
        assert(d1.allowed && d2.allowed && d3.allowed);
        assert(!d4.allowed);
    }
    assert(lim.total_allowed == 4500);
    assert(lim.total_rejected == 1500);
    assert(lim.evictions == 0);
    print("EDGE_RL_1500_ISOLATION: OK");

    // Advance past idle window; IP #1501 evicts an idle slot and gets its own full burst.
    let t1: u64 = 10000000000;
    let extra_a = security::check_edge_rate_limit(lim, "10.1.0.1", 1, t1);
    assert(extra_a.allowed);
    assert(lim.evictions >= 1);
    let extra_b = security::check_edge_rate_limit(lim, "10.1.0.1", 1, t1);
    let extra_c = security::check_edge_rate_limit(lim, "10.1.0.1", 1, t1);
    let extra_d = security::check_edge_rate_limit(lim, "10.1.0.1", 1, t1);
    assert(extra_b.allowed && extra_c.allowed);
    assert(!extra_d.allowed);
    assert(lim.fallback_cell.tat_ns == 0);

    // Ensure fallback_cell was not used and a fresh IP #1502 gets its own burst too.
    let extra2 = security::check_edge_rate_limit(lim, "10.1.0.2", 1, t1);
    assert(extra2.allowed);
    assert(lim.evictions >= 2);
    security::release_edge_rate_limiter(lim);
    print("EDGE_RL_CAPACITY_EVICT: OK");
}

fn test_4096_default_capacity() {
    var lim = security::new_edge_rate_limiter(10, 1);
    assert(lim.max_clients == 4096);
    let t0: u64 = 1000000000;
    var ip_buf: u8[..64] = [];

    for i in 4096 {
        format_ipv4_10_0(i, ip_buf);
        let d1 = security::check_edge_rate_limit(lim, ip_buf[..], 1, t0);
        let d2 = security::check_edge_rate_limit(lim, ip_buf[..], 1, t0);
        let d3 = security::check_edge_rate_limit(lim, ip_buf[..], 1, t0);
        assert(d1.allowed && d2.allowed);
        assert(!d3.allowed);
    }
    assert(lim.evictions == 0);
    assert(lim.fallback_cell.tat_ns == 0);

    // 4097th..4100th IPs after idle window trigger evictions without fallback collision.
    let t1: u64 = 5000000000;
    for j in 4 {
        format_ipv4_10_0(4096 + j, ip_buf);
        assert(security::check_edge_rate_limit(lim, ip_buf[..], 1, t1).allowed);
    }
    assert(lim.evictions == 4);
    assert(lim.fallback_cell.tat_ns == 0);
    security::release_edge_rate_limiter(lim);
    print("EDGE_RL_4096_DEFAULT: OK");
}

fn test_idle_eviction_keeps_active() {
    var lim = security::new_edge_rate_limiter(10, 1, 64);
    let t_stale:  u64 = 1000000000;
    let t_active: u64 = 5000000000;
    var ip_buf: u8[..64] = [];

    for i in 20 {
        format_ipv4_10_0(i, ip_buf);
        let d = security::check_edge_rate_limit(lim, ip_buf[..], 1, t_stale);
        assert(d.allowed);
    }

    // Consume full burst (2 requests) for 5 active clients at t_active.
    for j in 5 {
        format_ipv4_10_0(100 + j, ip_buf);
        let a1 = security::check_edge_rate_limit(lim, ip_buf[..], 1, t_active);
        let a2 = security::check_edge_rate_limit(lim, ip_buf[..], 1, t_active);
        assert(a1.allowed && a2.allowed);
    }

    // Evict entries idle > 2s at t = 5.5s: 20 stale evicted, 5 active retained.
    let t_sweep: u64 = 5500000000;
    let evicted = security::evict_idle_edge_clients(lim, 2000000000, t_sweep);
    assert(evicted == 20);

    // Active client still exhausted if checked immediately at t_active + 10ms.
    format_ipv4_10_0(100, ip_buf);
    let active_chk = security::check_edge_rate_limit(lim, ip_buf[..], 1, t_active + 10000000);
    assert(!active_chk.allowed);

    // Evicted client starts fresh when returning at t_sweep.
    format_ipv4_10_0(0, ip_buf);
    let fresh1 = security::check_edge_rate_limit(lim, ip_buf[..], 1, t_sweep);
    let fresh2 = security::check_edge_rate_limit(lim, ip_buf[..], 1, t_sweep);
    let fresh3 = security::check_edge_rate_limit(lim, ip_buf[..], 1, t_sweep);
    assert(fresh1.allowed && fresh2.allowed);
    assert(!fresh3.allowed);

    security::release_edge_rate_limiter(lim);
    print("EDGE_RL_IDLE_EVICT: OK");
}

fn test_fallback_vec_and_slot_reuse() {
    var lims: security::EdgeRateLimiter[>..] = [];
    lims.push(security::new_edge_rate_limiter(10, 1, 1500));
    lims.push(security::new_edge_rate_limiter(10, 1, 128));

    let t0: u64 = 2000000000;
    // Empty and >64-byte keys route safely to fallback_cell without polluting tracked slots.
    let long_id = "oversized-client-identifier-exceeding-sixty-four-bytes-0123456789abcdef";
    assert(long_id.len > 64);
    assert(security::check_edge_rate_limit(lims[0], "", 1, t0).allowed);
    assert(security::check_edge_rate_limit(lims[0], long_id, 1, t0).allowed);
    assert(!security::check_edge_rate_limit(lims[0], long_id, 1, t0).allowed);
    assert(lims[0].fallback_cell.tat_ns > 0);

    // Independent isolation across lims[0] and lims[1].
    assert(security::check_edge_rate_limit(lims[1], "192.168.1.10", 1, t0).allowed);
    assert(security::check_edge_rate_limit(lims[1], "192.168.1.10", 1, t0).allowed);
    assert(!security::check_edge_rate_limit(lims[1], "192.168.1.10", 1, t0).allowed);
    assert(security::check_edge_rate_limit(lims[0], "192.168.1.10", 1, t0).allowed);

    // Release and verify slot reuse works cleanly.
    let old_slot = lims[0].arena_slot;
    security::release_edge_rate_limiter(lims[0]);
    assert(lims[0].arena_slot == -1);
    security::release_edge_rate_limiter(lims[0]); // idempotent

    var reused = security::new_edge_rate_limiter(10, 1, 1500);
    assert(reused.arena_slot == old_slot);
    assert(security::check_edge_rate_limit(reused, "192.168.1.10", 1, t0).allowed);

    security::release_edge_rate_limiter(reused);
    security::release_edge_rate_limiter(lims[1]);
    print("EDGE_RL_FALLBACK_AND_VEC: OK");
}

thread_fn edge_rl_worker(client_count: i64) {
    var wlim = security::new_edge_rate_limiter(10, 1, 64);
    let t0: u64 = 3000000000;
    var ip_buf: u8[..64] = [];
    for i in client_count {
        format_ipv4_10_0(i, ip_buf);
        assert(security::check_edge_rate_limit(wlim, ip_buf[..], 1, t0).allowed);
        assert(security::check_edge_rate_limit(wlim, ip_buf[..], 1, t0).allowed);
        assert(!security::check_edge_rate_limit(wlim, ip_buf[..], 1, t0).allowed);
    }
    assert(wlim.total_allowed == (client_count * 2) as u64);
    assert(wlim.total_rejected == client_count as u64);
    assert(security::evict_idle_edge_clients(wlim, 1000000000, t0 + 5000000000) == client_count as i32);
    security::release_edge_rate_limiter(wlim);
}

fn test_aba_generation_and_thread_fn() {
    var lim = security::new_edge_rate_limiter(10, 1, 64);
    let old_slot = lim.arena_slot;
    let old_gen = lim.generation;
    assert(old_slot >= 0 && old_gen != 0);

    let t0: u64 = 4000000000;
    assert(security::check_edge_rate_limit(lim, "198.51.100.1", 1, t0).allowed);
    var stale_copy = lim;

    // Release original handle; stale_copy before reuse routes to fallback_cell and cannot evict.
    security::release_edge_rate_limiter(lim);
    assert(lim.arena_slot == -1 && lim.generation == 0);
    assert(security::evict_idle_edge_clients(stale_copy, 100, t0 + 5000000000) == 0);
    assert(security::check_edge_rate_limit(stale_copy, "198.51.100.2", 1, t0).allowed);
    assert(stale_copy.fallback_cell.tat_ns > 0);
    assert(stale_copy.total_allowed == 2);

    // Reallocate same arena_slot with a fresh generation.
    var live = security::new_edge_rate_limiter(10, 1, 64);
    assert(live.arena_slot == old_slot && live.generation != 0 && live.generation != old_gen);
    assert(security::check_edge_rate_limit(live, "198.51.100.9", 1, t0).allowed);
    assert(security::check_edge_rate_limit(live, "198.51.100.9", 1, t0).allowed);
    assert(!security::check_edge_rate_limit(live, "198.51.100.9", 1, t0).allowed);

    // Stale copy AFTER slot reuse (ABA) MUST NOT check, evict, or release the live slot.
    assert(security::check_edge_rate_limit(stale_copy, "198.51.100.9", 1, t0).allowed);
    assert(!security::check_edge_rate_limit(stale_copy, "198.51.100.9", 1, t0).allowed);
    assert(security::evict_idle_edge_clients(stale_copy, 100, t0 + 9000000000) == 0);
    security::release_edge_rate_limiter(stale_copy);
    assert(stale_copy.arena_slot == -1 && stale_copy.generation == 0);

    // Live handle remains active and still enforces rate limit for 198.51.100.9.
    assert(!security::check_edge_rate_limit(live, "198.51.100.9", 1, t0).allowed);
    security::release_edge_rate_limiter(live);

    // Verify real thread_fn worker compilation and execution with top-level EdgeRateLimiter globals.
    let tid = thread_spawn(edge_rl_worker, 32);
    assert(thread_wait(tid));
    print("EDGE_RL_ABA_AND_THREAD_FN: OK");
}

fn main() {
    test_1500_clients_and_eviction();
    test_4096_default_capacity();
    test_idle_eviction_keeps_active();
    test_fallback_vec_and_slot_reuse();
    test_aba_generation_and_thread_fn();
}
