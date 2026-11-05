// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_net_audit.goose
// Regression test suite for net/ bug-hunter findings F001..F011.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

var g_reentrant_ran: i32 = 0;

fn reentrant_task_cb(tag: u64, user_data: u64, task_id: u32, el: wing::EventLoop&) {
    if tag == 101 {
        let _ = wing::defer_task(el, 202, 0, 2);
    } else if tag == 202 {
        g_reentrant_ran = 1;
    }
}

fn main() {
    // F001: tick_timer_arm u8 wrap-around when current_tick + delay_sec >= 256
    var wheel = wing::TickTimerWheel { current_tick: 200, .. };
    let target_slot = wing::tick_timer_arm(wheel, 60);
    assert(target_slot == 20);
    print("F001_TICK_SLOT: ", target_slot);

    // F002: uniform_random i64 overflow when max_val - min_val == i64::MAX
    var seed: u64 = 42;
    let ur = wing::uniform_random(seed, 0, 9223372036854775807);
    assert(ur >= 0);
    let cfg_neg = wing::BackoffConfig {
        base_ms:  0,
        cap_ms:   -500,
        strategy: wing::JitterStrategy.DecorrelatedJitter,
    };
    var prev_sleep: i64 = 4000000000000000000;
    let backoff_neg = wing::compute_backoff_jitter_ms(cfg_neg, 1, prev_sleep, seed);
    assert(backoff_neg == 0);
    print("F002_BACKOFF_OK: ", backoff_neg);

    // F003: CircuitBreaker expired slot reclamation on 17th host and >256B host rejection
    var breaker = wing::new_host_circuit_breaker(1000);
    for i in 16 {
        var h: u8[..32] = [];
        h.append("host-");
        h.push(('a' + i) as u8);
        h.append(".example.com");
        let tripped = wing::trip_circuit_breaker_if_exceeded(breaker, h[..], 2000, 1000);
        assert(tripped);
    }
    // At t = 5000000000 (5s > 2s cooldown), all 16 entries have expired.
    // Tripping a 17th host must reclaim an expired slot so is_host_circuit_broken returns true.
    let tripped17 = wing::trip_circuit_breaker_if_exceeded(breaker, "host-17.example.com", 2000, 5000000000);
    assert(tripped17);
    let broken17 = wing::is_host_circuit_broken(breaker, "host-17.example.com", 5500000000);
    assert(broken17);
    print("F003_BREAKER_17: ", if broken17 { 1 } else { 0 });

    // F004: Pool active connection protection on EPOLLRDHUP, release idempotency, and case-folded hash
    var up_pool = wing::UpstreamPool { .. };
    var ep = wing::OriginEndpoint { port: 8080, .. };
    ep.host.append("10.0.0.1");
    assert(wing::register_upstream_conn(up_pool, 0, ep, 111, 222));
    let acq_fd, acq_ok = wing::acquire_upstream_conn(up_pool, ep, 111, 222);
    assert(acq_ok && acq_fd == 0);
    // Delivering EPOLLRDHUP while in_use == true must NOT evict the active entry while borrowed
    let _ = wing::notify_upstream_epoll_events(up_pool, 0, wing::EPOLLRDHUP);
    assert(up_pool.entries[0].in_use && up_pool.entries[0].healthy);

    // Case-insensitive pool_key_hash when PoolKey constructed with mixed-case host
    var pk_upper = wing::PoolKey { scheme: wing::PoolScheme.Https, .. };
    pk_upper.origin_endpoint.host.append("API.EXAMPLE.COM");
    pk_upper.origin_endpoint.port = 443;
    var pk_lower = wing::PoolKey { scheme: wing::PoolScheme.Https, .. };
    pk_lower.origin_endpoint.host.append("api.example.com");
    pk_lower.origin_endpoint.port = 443;
    assert(wing::pool_key_equals(pk_upper, pk_lower));
    assert(wing::pool_key_hash(pk_upper) == wing::pool_key_hash(pk_lower));

    // Double release_connection must not underflow active_conns or double-increment idle_conns
    var sp = wing::new_stream_pool(6, 32, 4);
    let cid = wing::register_connection(sp, pk_lower, wing::NegotiatedProtocol.Http11, "1.1.1.1", 1, 1000);
    wing::release_connection(sp, cid, 2000);
    wing::release_connection(sp, cid, 3000);
    let g_idx = wing::find_group_index(sp, pk_lower);
    assert(g_idx >= 0);
    assert(sp.groups[g_idx].active_conns == 0);
    assert(sp.groups[g_idx].idle_conns == 1);
    print("F004_POOL_OK: ", sp.groups[g_idx].idle_conns);

    // F005: Poller coarse timeout preserved when out_events full, re-entrant defer_task, and bounded consume_read
    var p_cfg = internal::auto_transport_driver_config();
    var poller = wing::new_poller(p_cfg);
    wing::register_socket(poller, 50, 7001, wing::PollInterest.Read, wing::PollTrigger.Level);
    wing::set_socket_timeout(poller, 50, 4);
    var full_evs: wing::PollReadyEvent[..64] = [];
    let _ = wing::poll_events(poller, 0, 1000000000, full_evs);
    for _ in 64 {
        full_evs.push(wing::PollReadyEvent { .. });
    }
    // Advance 5 seconds with full (64/64) event buffer: timeout must NOT be lost!
    let c_full = wing::check_coarse_timeouts(poller, 6000000000, full_evs);
    assert(c_full == 0);
    assert(wing::get_socket_timeout(poller, 50) != wing::COARSE_TIMEOUT_DISABLED);
    wing::close_poller(poller);

    var el = wing::new_event_loop(p_cfg);
    let _ = wing::bind_connection(el, 30, 5001, wing::PollInterest.Read);
    let _ = wing::feed_read(el, 5001, "0123456789");
    var small_out: u8[..4] = [];
    let consumed1 = wing::consume_read(el, 5001, small_out);
    assert(consumed1 == 4 && small_out[..] == "0123");
    var rest_out: u8[..16] = [];
    let consumed2 = wing::consume_read(el, 5001, rest_out);
    assert(consumed2 == 6 && rest_out[..] == "456789");

    let _ = wing::defer_task(el, 101, 0, 1);
    let _ = wing::drain_deferred_tasks(el, reentrant_task_cb);
    let _ = wing::drain_deferred_tasks(el, reentrant_task_cb);
    assert(g_reentrant_ran == 1);
    wing::close_event_loop(el);
    print("F005_POLLER_OK: ", g_reentrant_ran);

    // F006: MASQUE transactional capacity check on encode_http_capsule and out_packet clear in receive_capsule
    var tiny_cap: u8[..4] = [];
    let cap_ok = wing::encode_http_capsule(tiny_cap, rfc::CAPSULE_DATAGRAM, "0123456789");
    assert(!cap_ok && tiny_cap.len == 0);

    var tun = wing::new_connect_udp_tunnel("https://proxy.org", "1.1.1.1", 53);
    tun.state = wing::MasqueTunnelState.Established;
    var wire_dg: u8[..64] = [];
    assert(wing::encode_connect_udp_datagram_capsule(wire_dg, 0, "hello"));
    var recv_buf: u8[..16] = [];
    recv_buf.append("STALE_PREFIX_");
    assert(wing::receive_capsule(tun, wire_dg[..], recv_buf));
    assert(recv_buf[..] == "hello");
    print("F006_MASQUE_LEN: ", recv_buf.len);

    // F007: HTTP CONNECT status line space in header and split-chunk CRLFCRLF in HeaderReader
    let spoofed_connect = "HTTP/1.1\r\nX-Spoof: 200 OK\r\n\r\n";
    let spoof_err = wing::verify_connect_tunnel_response(spoofed_connect, 0);
    assert(spoof_err == wing::ConnectTunnelError.MalformedHeaders);

    let sl_cfg = wing::SlowlorisDefenseConfig { .. };
    var h_reader = wing::new_header_reader(sl_cfg, 0);
    let v_part1 = wing::feed_header_bytes(h_reader, "HTTP/1.1 200 OK\r\nHost: a\r\n", 1000000);
    assert(v_part1 == wing::SlowlorisViolation.None && !h_reader.headers_complete);
    let v_part2 = wing::feed_header_bytes(h_reader, "\r\n", 2000000);
    assert(v_part2 == wing::SlowlorisViolation.None && h_reader.headers_complete);
    print("F007_CONNECT_OK: ", if h_reader.headers_complete { 1 } else { 0 });

    // F008: PROXY v1 leading zeros / double spaces rejection and format_proxy_v2 bounded buffer guard
    let _, _, ok_lead_zero_ip = wing::parse_proxy_v1("PROXY TCP4 010.0.0.1 10.0.0.2 5000 80\r\n");
    assert(!ok_lead_zero_ip);
    let _, _, ok_lead_zero_port = wing::parse_proxy_v1("PROXY TCP4 10.0.0.1 10.0.0.2 05000 80\r\n");
    assert(!ok_lead_zero_port);
    let _, _, ok_double_space = wing::parse_proxy_v1("PROXY  TCP4 10.0.0.1 10.0.0.2 5000 80\r\n");
    assert(!ok_double_space);

    var phdr = wing::ProxyHeader {
        version:   wing::ProxyProtocolVersion.V2,
        command:   wing::ProxyCommand.Proxy,
        family:    wing::ProxyAddressFamily.Inet4,
        transport: wing::ProxyTransportProtocol.Stream,
        src_ipv4:  [10, 0, 0, 1],
        dst_ipv4:  [10, 0, 0, 2],
        src_port:  1234,
        dst_port:  80,
        ..
    };
    var tiny_v2: u8[..8] = [];
    let v2_ok = wing::format_proxy_v2(phdr, tiny_v2);
    assert(!v2_ok && tiny_v2.len == 0);
    print("F008_PROXY_OK: 1");

    // F009: DNS label validation, RFC 9460 mandatory SvcParam verification, and DnsResponse reuse
    assert(!wing::validate_idna_domain_bounds("-bad.example.com"));
    assert(!wing::validate_idna_domain_bounds("bad-.example.com"));
    assert(!wing::validate_idna_domain_bounds("bad space.example.com"));

    // Mandatory key 0x0003 (port) declared in Key 0, but Key 3 is missing from SvcParams
    let missing_mandatory_params: const u8[6] = [0x00, 0x00, 0x00, 0x02, 0x00, 0x03];
    var h_rec = wing::HttpsRecord { .. };
    let mand_ok = wing::parse_https_svc_params(missing_mandatory_params[..], h_rec);
    assert(!mand_ok);
    print("F009_DNS_OK: ", if !mand_ok { 1 } else { 0 });

    // F010: Happy Eyeballs start_attempt_race state reset on reuse & Isolation key content comparison
    var he_mgr = wing::new_attempt_manager(250);
    var cands: wing::DnsCandidate[..2] = [];
    cands.push(wing::new_dns_candidate(wing::AddressFamily.IPv6, "2001:db8::1", 443));
    wing::start_attempt_race(he_mgr, cands[..], 0);
    assert(he_mgr.attempts.len == 1);
    wing::start_attempt_race(he_mgr, cands[..], 100);
    assert(he_mgr.attempts.len == 1);

    var site1: u8[..32] = [];
    site1.append("https://example.com");
    var site2: u8[..32] = [];
    site2.append("https://example.com");
    let nik = wing::new_network_isolation_key(site1[..], site2[..]);
    assert(!nik.is_cross_site);

    // Exercise late DNS candidate injection, MASQUE QUIC datagram ingress, Poller helpers, and L4 driver APIs
    var late_q: wing::DnsCandidate[..32] = [];
    wing::inject_late_dns_candidates(late_q, cands[..]);
    assert(late_q.len == 1);

    var dgram_wire: u8[..64] = [];
    let dgram_enc_ok = wing::encode_http_datagram(dgram_wire, tun.quarter_stream_id, 0, "quux");
    assert(dgram_enc_ok);
    var dgram_out: u8[..32] = [];
    let dgram_rx_ok = wing::receive_quic_datagram(tun, dgram_wire[..], dgram_out);
    assert(dgram_rx_ok && dgram_out[..] == "quux");

    var p2 = wing::new_poller(p_cfg);
    wing::register_socket(p2, 60, 8001, wing::PollInterest.Read, wing::PollTrigger.Level);
    assert(wing::find_by_tag(p2, 8001) >= 0);
    assert(wing::simulate_error(p2, 60));
    wing::close_poller(p2);

    var el2 = wing::new_event_loop(p_cfg);
    let _ = wing::bind_connection(el2, 61, 8002, wing::PollInterest.Read);
    assert(wing::set_connection_timeout(el2, 8002, 8));
    wing::close_event_loop(el2);

    assert(!wing::tcp_set_reuseport(-1, true));
    assert(!wing::epoll_mod(-1, 1, wing::EPOLL_READ, 0));
    wing::tcp_cleanup();

    let probe_res = internal::probe_transport_driver(internal::TransportDriverKind.Standard);
    assert(probe_res.available);
    assert(internal::platform_name(internal::TargetPlatform.Windows) == "Windows");

    var xsk, _ = internal::af_xdp_open_socket(1, 0, 0, 4096);
    internal::af_xdp_close(xsk);

    var sqe = internal::UringSqe { .. };
    internal::uring_prep_accept_multishot(sqe, 10, 99);
    assert(sqe.ioprio == internal::URING_ACCEPT_MULTISHOT);
    var iov: internal::UringIovec[1] = [internal::UringIovec { iov_base: 0, iov_len: 4096 }];
    assert(internal::uring_register_buffers(-1, iov[..]) == -1);
    assert(internal::uring_unregister_buffers(-1) == -1);
    let _ = internal::uring_has_fast_poll(-1);

    print("F010_HE_ISO_OK: ", he_mgr.attempts.len);
}

// CHECK: F001_TICK_SLOT: 20
// CHECK: F002_BACKOFF_OK: 0
// CHECK: F003_BREAKER_17: 1
// CHECK: F004_POOL_OK: 1
// CHECK: F005_POLLER_OK: 1
// CHECK: F006_MASQUE_LEN: 5
// CHECK: F007_CONNECT_OK: 1
// CHECK: F008_PROXY_OK: 1
// CHECK: F009_DNS_OK: 1
// CHECK: F010_HE_ISO_OK: 1
