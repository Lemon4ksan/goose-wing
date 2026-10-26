// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for net/happy_eyeballs: RFC 8305 and HEv3 connection racing,
// CAD calculations, 50 ms Resolution Delay, candidate interleaving, and AttemptManager coordination.
// Defenses for Go #59494 / #35122 (Windows leaked dial timers) and RFC 8305 congestion collapse.
import std;
import core from "..";
import wing from "..";

fn test_cad_calculation_and_absolute_floor(t: core::T&) {
    t.run("CAD Clamping and Strict Absolute Floor >= 10 ms") { sub =>
        // Default when RTT is unknown: 250 ms
        let cad_default = wing::compute_effective_cad_ms(0, false);
        sub.assert_eq(cad_default, 250, "Default CAD is 250 ms (RFC 8305)");

        // Observed RTT within normal window [100 ms, 2000 ms]
        let cad_normal = wing::compute_effective_cad_ms(180, true);
        sub.assert_eq(cad_normal, 180, "Observed RTT 180 ms preserved");

        // Observed RTT below recommended minimum 100 ms
        let cad_clamped_min = wing::compute_effective_cad_ms(45, true, 100, 2000);
        sub.assert_eq(cad_clamped_min, 100, "RTT 45 ms clamped to min 100 ms");

        // Observed RTT above max 2000 ms
        let cad_clamped_max = wing::compute_effective_cad_ms(4500, true, 100, 2000);
        sub.assert_eq(cad_clamped_max, 2000, "RTT 4500 ms clamped to max 2000 ms");

        // Normative safety barrier: MUST NOT be less than 10 ms even with caller override
        let cad_floor1 = wing::compute_effective_cad_ms(2, true, 4, 1000);
        sub.assert_eq(cad_floor1, 10, "CAD strictly clamped to absolute floor >= 10 ms");

        // 0 ms RTT (e.g. localhost or loopback)
        let cad_zero = wing::compute_effective_cad_ms(0, true, 0, 1000);
        sub.assert_eq(cad_zero, 10, "0 ms RTT clamped to 10 ms absolute floor");

        // Negative RTT (clock jump backwards or uncalibrated timer)
        let cad_neg = wing::compute_effective_cad_ms(-250, true, 0, 1000);
        sub.assert_eq(cad_neg, 10, "Negative RTT clamped safely to 10 ms absolute floor");

        // Custom bounds [500 ms, 1500 ms]
        let cad_custom = wing::compute_effective_cad_ms(200, true, 500, 1500);
        sub.assert_eq(cad_custom, 500, "Custom min 500 ms applied");

        let cad_custom_high = wing::compute_effective_cad_ms(1800, true, 500, 1500);
        sub.assert_eq(cad_custom_high, 1500, "Custom max 1500 ms applied");
    };
}

fn test_rfc6724_and_hev3_interleaving(t: core::T&) {
    t.run("First Address Family Count = 1 Interleaving Matrix") { sub =>
        var ipv6_list: wing::DnsCandidate[..8] = [];
        ipv6_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::1", 443));
        ipv6_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::2", 443));

        var ipv4_list: wing::DnsCandidate[..8] = [];
        ipv4_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv4, "198.51.100.1", 443));
        ipv4_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv4, "198.51.100.2", 443));

        var interleaved: wing::DnsCandidate[..32] = [];
        wing::interleave_candidates_he(ipv6_list[..], ipv4_list[..], interleaved, 1);

        sub.assert_eq(interleaved.len, 4, "4 candidates interleaved");
        sub.assert_true(interleaved[0].family == wing::AddressFamily.IPv6, "Candidate 0 is IPv6_1");
        sub.assert_true(interleaved[1].family == wing::AddressFamily.IPv4, "Candidate 1 is IPv4_1");
        sub.assert_true(interleaved[2].family == wing::AddressFamily.IPv6, "Candidate 2 is IPv6_2");
        sub.assert_true(interleaved[3].family == wing::AddressFamily.IPv4, "Candidate 3 is IPv4_2");
    };

    t.run("Asymmetric Candidate Interleaving (IPv6 Heavily Dominates)") { sub =>
        var ipv6_list: wing::DnsCandidate[..8] = [];
        ipv6_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::1", 443));
        ipv6_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::2", 443));
        ipv6_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::3", 443));
        ipv6_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::4", 443));

        var ipv4_list: wing::DnsCandidate[..8] = [];
        ipv4_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv4, "198.51.100.1", 443));

        var interleaved: wing::DnsCandidate[..32] = [];
        wing::interleave_candidates_he(ipv6_list[..], ipv4_list[..], interleaved, 1);

        sub.assert_eq(interleaved.len, 5, "5 candidates total");
        sub.assert_true(interleaved[0].family == wing::AddressFamily.IPv6, "0 is IPv6");
        sub.assert_true(interleaved[1].family == wing::AddressFamily.IPv4, "1 is IPv4");
        sub.assert_true(interleaved[2].family == wing::AddressFamily.IPv6, "2 is IPv6");
        sub.assert_true(interleaved[3].family == wing::AddressFamily.IPv6, "3 is IPv6");
        sub.assert_true(interleaved[4].family == wing::AddressFamily.IPv6, "4 is IPv6");
    };

    t.run("Asymmetric Candidate Interleaving (IPv4 Heavily Dominates)") { sub =>
        var ipv6_list: wing::DnsCandidate[..8] = [];
        ipv6_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::1", 443));

        var ipv4_list: wing::DnsCandidate[..8] = [];
        ipv4_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv4, "198.51.100.1", 443));
        ipv4_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv4, "198.51.100.2", 443));
        ipv4_list.push(wing::new_dns_candidate(wing::AddressFamily.IPv4, "198.51.100.3", 443));

        var interleaved: wing::DnsCandidate[..32] = [];
        wing::interleave_candidates_he(ipv6_list[..], ipv4_list[..], interleaved, 1);

        sub.assert_eq(interleaved.len, 4, "4 candidates total");
        sub.assert_true(interleaved[0].family == wing::AddressFamily.IPv6, "0 is IPv6");
        sub.assert_true(interleaved[1].family == wing::AddressFamily.IPv4, "1 is IPv4");
        sub.assert_true(interleaved[2].family == wing::AddressFamily.IPv4, "2 is IPv4");
        sub.assert_true(interleaved[3].family == wing::AddressFamily.IPv4, "3 is IPv4");
    };

    t.run("Single-Stack Fallbacks (0 IPv6 or 0 IPv4)") { sub =>
        var ipv6_only: wing::DnsCandidate[..8] = [];
        ipv6_only.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::1", 443));
        ipv6_only.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::2", 443));
        var empty_ipv4: wing::DnsCandidate[..8] = [];

        var res_v6: wing::DnsCandidate[..32] = [];
        wing::interleave_candidates_he(ipv6_only[..], empty_ipv4[..], res_v6, 1);
        sub.assert_eq(res_v6.len, 2, "IPv6-only preserved 2 candidates");
        sub.assert_true(res_v6[0].family == wing::AddressFamily.IPv6, "Res 0 is IPv6");
        sub.assert_true(res_v6[1].family == wing::AddressFamily.IPv6, "Res 1 is IPv6");

        var empty_ipv6: wing::DnsCandidate[..8] = [];
        var ipv4_only: wing::DnsCandidate[..8] = [];
        ipv4_only.push(wing::new_dns_candidate(wing::AddressFamily.IPv4, "1.1.1.1", 80));
        var res_v4: wing::DnsCandidate[..32] = [];
        wing::interleave_candidates_he(empty_ipv6[..], ipv4_only[..], res_v4, 1);
        sub.assert_eq(res_v4.len, 1, "IPv4-only preserved 1 candidate");
        sub.assert_true(res_v4[0].family == wing::AddressFamily.IPv4, "Res 0 is IPv4");
    };

    t.run("HEv3 Protocol Interleaving (QUIC vs TCP)") { sub =>
        var list: wing::DnsCandidate[..8] = [];
        list.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::1", 443));
        list.push(wing::new_dns_candidate(wing::AddressFamily.IPv4, "198.51.100.1", 443));

        var proto_interleaved: wing::DnsCandidate[..32] = [];
        wing::interleave_protocols_hev3(list[..], proto_interleaved);

        sub.assert_eq(proto_interleaved.len, 4, "4 protocol attempts generated (QUIC + TCP for both)");
        sub.assert_true(proto_interleaved[0].l4_proto == wing::L4Protocol.QuicUdp, "Attempt 0 is QUIC/UDP IPv6");
        sub.assert_true(proto_interleaved[1].l4_proto == wing::L4Protocol.Tcp, "Attempt 1 is TCP IPv6");
        sub.assert_true(proto_interleaved[2].l4_proto == wing::L4Protocol.QuicUdp, "Attempt 2 is QUIC/UDP IPv4");
        sub.assert_true(proto_interleaved[3].l4_proto == wing::L4Protocol.Tcp, "Attempt 3 is TCP IPv4");
    };
}

fn test_dns_race_and_resolution_delay(t: core::T&) {
    t.run("Asymmetric Priority: AAAA First Cancels Delay") { sub =>
        var task = wing::new_dns_race_task();
        let ip6: const u8[:][1] = ["2001:db8::1"];
        wing::on_dns_aaaa_response(task, ip6[..], 100);

        sub.assert_true(task.ready_to_connect, "Ready to connect immediately on AAAA");
        sub.assert_false(task.rd_timer_armed, "RD timer NOT armed when AAAA arrives first");
        sub.assert_eq(task.ipv6_candidates.len, 1, "IPv6 candidate ready");
    };

    t.run("A First Arms 50 ms Resolution Delay Timer") { sub =>
        var task = wing::new_dns_race_task();
        let ip4: const u8[:][1] = ["198.51.100.1"];
        wing::on_dns_a_response(task, ip4[..], 100);

        sub.assert_false(task.ready_to_connect, "Not ready immediately: waiting for AAAA in RD window");
        sub.assert_true(task.rd_timer_armed, "RD timer armed for 50 ms");
        sub.assert_eq(task.rd_deadline_ms, 150, "RD deadline set to now + 50 ms");

        // Positive AAAA arrives at t=120 (< 150)
        let ip6: const u8[:][1] = ["2001:db8::1"];
        wing::on_dns_aaaa_response(task, ip6[..], 120);
        sub.assert_true(task.ready_to_connect, "Unblocked by late AAAA before RD deadline");
        sub.assert_false(task.rd_timer_armed, "RD timer cancelled on positive AAAA");
    };

    t.run("RD Expiration Unblocks IPv4") { sub =>
        var task = wing::new_dns_race_task();
        let ip4: const u8[:][1] = ["198.51.100.1"];
        wing::on_dns_a_response(task, ip4[..], 100);

        // Tick before deadline
        let unblocked_early = wing::check_dns_resolution_delay_tick(task, 140);
        sub.assert_false(unblocked_early, "Not unblocked at t=140");

        // Tick at deadline (t=150)
        let unblocked = wing::check_dns_resolution_delay_tick(task, 150);
        sub.assert_true(unblocked, "Unblocked at t=150 (50 ms RD expired)");
        sub.assert_true(task.ready_to_connect, "Ready to connect with IPv4");
    };

    t.run("Negative AAAA Immediately Unblocks IPv4") { sub =>
        var task = wing::new_dns_race_task();
        let ip4: const u8[:][1] = ["198.51.100.1"];
        wing::on_dns_a_response(task, ip4[..], 100);

        // Empty AAAA response (NODATA / negative)
        let empty_ip6: const u8[:][0] = [];
        wing::on_dns_aaaa_response(task, empty_ip6[..], 110);
        sub.assert_true(task.ready_to_connect, "Negative AAAA immediately unblocks IPv4 without waiting for 50 ms");
        sub.assert_false(task.rd_timer_armed, "RD timer disarmed");
    };
}

fn test_attempt_manager_racing_and_winner(t: core::T&) {
    t.run("Staggered Connection Racing, Winner Binding & Loser Cancellation (Go #59494)") { sub =>
        var mgr = wing::new_attempt_manager(250); // CAD = 250 ms

        var candidates: wing::DnsCandidate[..4] = [];
        candidates.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::1", 443));
        candidates.push(wing::new_dns_candidate(wing::AddressFamily.IPv4, "198.51.100.1", 443));
        candidates.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::2", 443));

        wing::start_attempt_race(mgr, candidates[..], 0);

        sub.assert_eq(mgr.attempts.len, 1, "First attempt launched at t=0");
        sub.assert_eq(mgr.attempts[0].attempt_id, 1, "Attempt 1 launched");

        // Tick at t=100 (< CAD 250 ms) -> no new attempt
        let launched_early = wing::tick_attempt_manager(mgr, 100);
        sub.assert_false(launched_early, "No attempt launched at t=100");
        sub.assert_eq(mgr.attempts.len, 1, "Still 1 attempt");

        // Tick at t=250 (= CAD) -> launches second attempt (IPv4)
        let launched_cad = wing::tick_attempt_manager(mgr, 250);
        sub.assert_true(launched_cad, "Second attempt launched at t=250");
        sub.assert_eq(mgr.attempts.len, 2, "2 attempts now active");

        // Tick at t=500 (= 2*CAD) -> launches third attempt (IPv6_2)
        let launched_third = wing::tick_attempt_manager(mgr, 500);
        sub.assert_true(launched_third, "Third attempt launched at t=500");
        sub.assert_eq(mgr.attempts.len, 3, "3 attempts now active");

        // Attempt 2 (IPv4) wins at t=550
        // Crucial defense (Go #59494, #35122): All other attempts (1 and 3) must be cancelled immediately to prevent leaked dials on Windows!
        let won = wing::bind_winner_attempt(mgr, 2);
        sub.assert_true(won, "Attempt 2 bound as winner");
        sub.assert_true(mgr.has_winner, "Manager marked has_winner");
        sub.assert_true(mgr.attempts[0].state == wing::AttemptState.Cancelled, "Attempt 1 cancelled");
        sub.assert_true(mgr.attempts[1].state == wing::AttemptState.Connected, "Attempt 2 connected");
        sub.assert_true(mgr.attempts[2].state == wing::AttemptState.Cancelled, "Attempt 3 cancelled");

        // Attempting to tick after winner does not launch further attempts
        let tick_post_winner = wing::tick_attempt_manager(mgr, 750);
        sub.assert_false(tick_post_winner, "No attempts launched after winner is bound");
    };

    t.run("Last Resort Local Synthesis Delay (2000 ms)") { sub =>
        var mgr = wing::new_attempt_manager(250);
        var candidates: wing::DnsCandidate[..2] = [];
        candidates.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::99", 443));

        wing::start_attempt_race(mgr, candidates[..], 0);
        sub.assert_true(mgr.last_resort_armed, "Last resort synthesis armed for last IPv6 attempt");
        sub.assert_eq(mgr.last_resort_deadline_ms, 2000, "Deadline set to 2000 ms");

        // Tick at t=1999 -> not triggered
        wing::tick_attempt_manager(mgr, 1999);
        sub.assert_false(mgr.last_resort_triggered, "Not triggered before 2000 ms");

        // Tick at t=2000 -> triggers RFC 7050 NAT64 synthesis
        wing::tick_attempt_manager(mgr, 2000);
        sub.assert_true(mgr.last_resort_triggered, "Last resort synthesis triggered at 2000 ms");
        sub.assert_true(mgr.pending_candidates.len >= 2, "Synthesized NAT64 candidate injected into pending queue");
    };

    t.run("Chromium JobController Creation Rules and Waiting Delay") { sub =>
        // dns_alpn_h3_job rules: HTTPS + QUIC + no proxy + no active QUIC session
        sub.assert_true(wing::should_create_dns_alpn_h3_job(true, true, false, false), "Created on HTTPS, QUIC, direct, no active session");
        sub.assert_false(wing::should_create_dns_alpn_h3_job(false, true, false, false), "Not created on plain HTTP");
        sub.assert_false(wing::should_create_dns_alpn_h3_job(true, false, false, false), "Not created when QUIC disabled");
        sub.assert_false(wing::should_create_dns_alpn_h3_job(true, true, true, false), "Not created when proxy is configured");
        sub.assert_false(wing::should_create_dns_alpn_h3_job(true, true, false, true), "Not created when active QUIC session can be reused");

        // Waiting delay cancelled when open TCP socket already exists in pool
        let delay_open_tcp = wing::compute_main_job_waiting_delay_ms(true, false, 200);
        sub.assert_eq(delay_open_tcp, 0, "Waiting delay cancelled (0 ms) when open TCP socket exists");

        // Waiting delay cancelled when DNS confirms no HTTP/3 ALPN support
        let delay_no_h3 = wing::compute_main_job_waiting_delay_ms(false, true, 200);
        sub.assert_eq(delay_no_h3, 0, "Waiting delay cancelled (0 ms) when DNS confirms no HTTP/3");

        // Default waiting delay when cold
        let delay_cold = wing::compute_main_job_waiting_delay_ms(false, false, 200);
        sub.assert_eq(delay_cold, 200, "Default waiting delay applied when cold");
    };
}

fn main() {
    var runner = core::new_runner("net/happy_eyeballs RFC 8305 & HEv3 Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. CAD Calculation & Absolute Floor", test_cad_calculation_and_absolute_floor);
    core::run_case(runner, "2. RFC 6724 & HEv3 Interleaving", test_rfc6724_and_hev3_interleaving);
    core::run_case(runner, "3. DNS Race & Resolution Delay", test_dns_race_and_resolution_delay);
    core::run_case(runner, "4. AttemptManager Racing & Winner", test_attempt_manager_racing_and_winner);
    let ok = core::finish(runner);
    assert(ok);
}
