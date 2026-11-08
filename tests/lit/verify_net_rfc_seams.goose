// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// tests/lit/verify_net_rfc_seams.goose
// Regression test suite for cross-component seams and RFC edge cases in net/.
//
// RUN: goose build --cc gcc -O2 -o %t.exe %s
// RUN: %t.exe | %FileCheck %s

import std;
import core from "../..";
import wing from "../..";

fn test_r001_dns_rfc_edge_cases() {
    // 1. RFC 9460 §7.1.1 & §2.4.3: no-default-alpn (key 2) without alpn (key 1) must be rejected
    let no_def_only: const u8[4] = [0x00, 0x02, 0x00, 0x00];
    var rec_nodef = wing::HttpsRecord { .. };
    assert(!wing::parse_https_svc_params(no_def_only[..], rec_nodef));

    // 2. RFC 9460: empty ech (key 5, len 0) must be rejected
    let empty_ech: const u8[4] = [0x00, 0x05, 0x00, 0x00];
    var rec_ech = wing::HttpsRecord { .. };
    assert(!wing::parse_https_svc_params(empty_ech[..], rec_ech));

    // 3. RFC 9460 §2.4.2: AliasMode (priority == 0) MUST ignore SvcParams
    let alias_wire: const u8[50] = [
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x41, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x09,
        0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x02, 0x20, 0xfb,
    ];
    var resp_alias = wing::DnsResponse { .. };
    assert(wing::parse_dns_response(alias_wire[..], resp_alias));
    assert(resp_alias.https_records.len == 1);
    assert(resp_alias.https_records[0].priority == 0);
    assert(resp_alias.https_records[0].port == 443);

    // 4. RFC 9460 §9: SVCB (type 64 = 0x0040) must NOT be accepted into https_records
    var svcb_wire = alias_wire;
    svcb_wire[31] = 0x00;
    svcb_wire[32] = 0x40;
    svcb_wire[41] = 0x01;
    var resp_svcb = wing::DnsResponse { .. };
    assert(wing::parse_dns_response(svcb_wire[..], resp_svcb));
    assert(resp_svcb.https_records.len == 0);

    // 5. RFC 2181 §8: TTL with MSB set (0x80000001) must be treated as 0
    var msb_ttl_wire: const u8[45] = [
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x80, 0x00, 0x00, 0x01, 0x00, 0x04,
        127, 0, 0, 1,
    ];
    var resp_ttl = wing::DnsResponse { .. };
    assert(wing::parse_dns_response(msb_ttl_wire[..], resp_ttl));
    assert(resp_ttl.min_ttl_sec == 0);

    // 6. RFC 1035 §3.2.1: ttl_sec == 0 must not be served Stale from DnsCache
    var dcache = wing::DnsCache { .. };
    var zero_ttl_entry = wing::DnsCacheEntry {
        qtype:           1,
        inserted_at_sec: 1000,
        ttl_sec:         0,
        stale_ttl_sec:   86400,
        ..
    };
    zero_ttl_entry.domain.append("zero.example.com");
    wing::dns_cache_insert(dcache, zero_ttl_entry);
    var out_zero = wing::DnsCacheEntry { .. };
    assert(wing::dns_cache_lookup(dcache, "zero.example.com", 1, 1000, out_zero) == wing::DnsCacheStatus.Expired);

    // 7. RFC 5891 §4.2.3.1 & CVE-2026-39821 Punycode validation
    assert(!core::validate_idna_domain_bounds("xn--test-.example.com"));
    assert(!core::validate_idna_domain_bounds("xn---a.example.com"));
    assert(!core::validate_idna_domain_bounds("xn--a_b.example.com"));
    assert(!core::validate_idna_domain_bounds("ab--cd.example.com"));
    print("R001_DNS_RFC: 1");
}

fn test_r002_happy_eyeballs_seams() {
    // 1. 100-byte FQDN passed into new_dns_candidate (client/session/exec.goose seam)
    var fqdn_100: u8[..128] = [];
    for _ in 20 { fqdn_100.append("sub."); }
    fqdn_100.append("example.com");
    let cand = wing::new_dns_candidate(wing::AddressFamily.IPv4, fqdn_100[..], 443);
    assert(cand.ip[..] == fqdn_100[..]);

    // 2. on_dns_a_response when AAAA already Failed must NOT wait 50ms RD delay
    var task = wing::new_dns_race_task(50);
    task.aaaa_status = wing::DnsQueryStatus.Failed;
    let a_ips: (const u8[:])[1] = ["93.184.216.34"];
    wing::on_dns_a_response(task, a_ips[..], 20);
    assert(task.ready_to_connect && !task.rd_timer_armed);

    // 3. new_attempt_manager clamps cad_ms to >= 10ms (RFC 8305 §5)
    let mgr = wing::new_attempt_manager(2);
    assert(mgr.effective_cad_ms >= 10);
    print("R002_HE_SEAMS: 1");
}

fn test_r003_proxy_hop_by_hop_and_handshake() {
    // 1. RFC 9110 §7.6.1: sanitize_tunnel_headers_for_origin must not overwrite Connection
    //    entry in place before checking later headers nominated by Connection!
    var hdrs = wing::HeaderMap { .. };
    wing::append_header(hdrs, "Connection", "X-Secret-Token");
    wing::append_header(hdrs, "Host", "origin.example.com");
    wing::append_header(hdrs, "X-Secret-Token", "leaked-secret-value");
    wing::sanitize_tunnel_headers_for_origin(hdrs);
    assert(!wing::has_header(hdrs, "X-Secret-Token"));
    assert(wing::has_header(hdrs, "Host"));

    // 2. RFC 1928 §6: SOCKS5 connect reply with non-zero RSV byte must be rejected
    let bad_rsv_reply: const u8[10] = [0x05, 0x00, 0x01, 0x01, 127, 0, 0, 1, 0x04, 0x38];
    let _, rsv_err = wing::parse_socks5_connect_reply(bad_rsv_reply[..]);
    assert(rsv_err == wing::Socks5Error.InvalidReplyHeader);

    // 3. Slowloris HeaderReader: bare \n\n must not disarm Slowloris checks
    let sl_cfg = wing::SlowlorisDefenseConfig { .. };
    var reader = wing::new_header_reader(sl_cfg, 0);
    let v1 = wing::feed_header_bytes(reader, "HTTP/1.1 200 OK\n\n", 1000000);
    assert(v1 == wing::SlowlorisViolation.None && !reader.headers_complete);

    // 4. build_http_connect_request rejects whitespace in target_host
    var req_out: u8[..1024] = [];
    wing::build_http_connect_request("bad host.com", 443, "", "", req_out);
    assert(req_out.len == 0);
    print("R003_PROXY_SEAMS: 1");
}

fn test_r004_masque_rfc_invariants() {
    // 1. RFC 9297 §3.4: Capsule-Protocol SFV List (?1, ?0) must be rejected
    assert(!wing::is_capsule_protocol_negotiated("?1, ?0"));
    assert(!wing::is_capsule_protocol_negotiated("?1; a=1, ?1"));

    // 2. RFC 9297 §2.1: quarter_stream_id > 2^60 - 1 rejected
    var dg_out: u8[..64] = [];
    assert(!wing::encode_http_datagram(dg_out, 0x1000000000000000, 0, "pkt"));

    // 3. RFC 9298 §3: IPv6 colons percent-encoded in format_connect_udp_path and decoded in parse_connect_udp_path
    var v6_path: u8[..256] = [];
    wing::format_connect_udp_path(v6_path, "2001:db8::1", 443);
    assert(v6_path[..] == "/.well-known/masque/udp/2001%3Adb8%3A%3A1/443/");
    let dec_h, dec_p, dec_ok = wing::parse_connect_udp_path(v6_path[..]);
    assert(dec_ok && dec_p == 443 && dec_h[..] == "2001:db8::1");
    let _, _, raw_colon_ok = wing::parse_connect_udp_path("/.well-known/masque/udp/2001:db8::1/443/");
    assert(!raw_colon_ok);

    // 4. RFC 9484 §4.7.3: Inverted route range (start_ip > end_ip) rejected in decode and receive_capsule
    var inv_route = wing::RouteAdvertisement { ip_version: 4, ip_protocol: 0, .. };
    inv_route.start_ip.append([10, 0, 0, 255]);
    inv_route.end_ip.append([10, 0, 0, 0]);
    var route_wire: u8[..64] = [];
    assert(!wing::encode_route_advertisement_capsule(route_wire, inv_route));
    let raw_inv_payload: const u8[10] = [4, 10, 0, 0, 255, 10, 0, 0, 0, 0];
    let _, inv_dec_ok = wing::decode_route_advertisement_capsule(raw_inv_payload[..]);
    assert(!inv_dec_ok);
    print("R004_MASQUE_RFC: 1");
}

fn test_r005_proxy_protocol_roundtrip_and_bounds() {
    // 1. HAProxy v2 LOCAL + AF_UNSPEC default ProxyHeader round-trip
    var local_hdr = wing::ProxyHeader {
        version: wing::ProxyProtocolVersion.V2,
        command: wing::ProxyCommand.Local,
        family:  wing::ProxyAddressFamily.Unspec,
        ..
    };
    var v2_out: u8[..64] = [];
    assert(wing::format_proxy_v2(local_hdr, v2_out));
    let parsed_v2, consumed_v2, ok_v2 = wing::parse_proxy_v2(v2_out[..]);
    assert(ok_v2 && consumed_v2 == 16 && parsed_v2.command == wing::ProxyCommand.Local);

    // 2. HAProxy v1 UNKNOWN with embedded NUL rejected
    let _, _, bad_v1 = wing::parse_proxy_v1("PROXY UNKNOWN bad\x00char\r\n");
    assert(!bad_v1);
    print("R005_PROXY_PROTO: 1");
}

fn test_r006_pool_h2_coalescing_and_queues() {
    // 1. RFC 9110 §4.3.1: H2 coalescing MUST NOT coalesce across different origin ports
    let nak = wing::new_network_anonymization_key("https://example.com");
    let chain = wing::new_direct_proxy_chain();
    let pol = wing::TlsAndDnsPolicy { .. };
    let key_443 = wing::new_pool_key(wing::PoolScheme.Https, "a.example.com", 443, chain, nak, pol);
    let key_8443 = wing::new_pool_key(wing::PoolScheme.Https, "b.example.com", 8443, chain, nak, pol);
    var conn = wing::PooledConnection {
        key:                    key_443,
        protocol:               wing::NegotiatedProtocol.Http2,
        max_concurrent_streams: 100,
        cert_valid:             true,
        ..
    };
    conn.resolved_ip.append("93.184.216.34");
    var san: u8[..128] = [];
    san.append("*.example.com");
    conn.san_hosts.push(san);
    assert(!wing::can_coalesce_h2_connection(conn, key_8443, "93.184.216.34"));

    // 2. RFC 6125: matches_san_pattern rejects trailing-dot TLD wildcard and IPv4 wildcard
    assert(!wing::matches_san_pattern("", ""));
    assert(!wing::matches_san_pattern("*.com.", "evil.com."));
    assert(!wing::matches_san_pattern("*.0.0.1", "127.0.0.1"));

    // 3. WantQueue compaction drops cancelled items so 65th push succeeds
    var wq = wing::WantQueue { .. };
    for i in 64 {
        let req_id = (i + 1) as u64;
        assert(wing::push_want(wq, wing::WantConn { req_id: req_id, .. }));
        assert(wing::cancel_want(wq, req_id));
    }
    assert(wing::queue_len(wq) == 0);
    assert(wing::push_want(wq, wing::WantConn { req_id: 65, .. }));

    // 4. UpstreamPool bitwise-OR epoll_events preserves EPOLLRDHUP across subsequent events
    var up = wing::UpstreamPool { .. };
    let ep = wing::new_origin_endpoint("10.0.0.1", 8080);
    assert(wing::register_upstream_conn(up, 55, ep, 1, 1));
    let _, acq_ok = wing::acquire_upstream_conn(up, ep, 1, 1);
    assert(acq_ok);
    let _ = wing::notify_upstream_epoll_events(up, 55, wing::EPOLLRDHUP);
    let _ = wing::notify_upstream_epoll_events(up, 55, wing::EPOLL_READ);
    assert(!wing::release_upstream_conn(up, 55, 0));
    print("R006_POOL_SEAMS: 1");
}

fn test_r007_isolation_and_retry_rfc() {
    // 1. NetworkIsolationKey empty check, case folding, and fail-closed on >128B site
    let empty_nik = wing::new_network_isolation_key("", "");
    assert(empty_nik.is_empty);
    let upper_nik = wing::new_network_isolation_key("HTTPS://EXAMPLE.COM", "https://example.com");
    let lower_nik = wing::new_network_isolation_key("https://example.com", "https://example.com");
    assert(upper_nik.top_level_site[..] == lower_nik.top_level_site[..]);

    // 2. RFC 9110 §5.6.7: Retry-After accepts obsolete RFC 850 and asctime HTTP-dates
    let _, ok_rfc850 = wing::parse_retry_after_ms("Sunday, 06-Nov-94 08:49:37 GMT", 784111770000);
    assert(ok_rfc850);
    let _, ok_asctime = wing::parse_retry_after_ms("Sun Nov  6 08:49:37 1994", 784111770000);
    assert(ok_asctime);

    // 3. CircuitBreaker must not shorten an active longer block
    var cb = wing::new_host_circuit_breaker(60000);
    assert(wing::trip_circuit_breaker_if_exceeded(cb, "api.test", 300000, 1000000000));
    assert(wing::trip_circuit_breaker_if_exceeded(cb, "api.test", 70000, 1000000000));
    assert(wing::is_host_circuit_broken(cb, "api.test", 200000000000));
    print("R007_ISO_RETRY: 1");
}

fn test_r008_poller_timer_tcp_and_drivers() {
    // 1. Edge-triggered Poller preserves unreported readiness bits
    var p_cfg = internal::auto_transport_driver_config();
    var p = wing::new_poller(p_cfg);
    wing::register_socket(p, 10, 100, wing::PollInterest.Read, wing::PollTrigger.Edge);
    let _ = wing::simulate_read_ready(p, 10, 64);
    let _ = wing::simulate_write_ready(p, 10);
    var evs: wing::PollReadyEvent[..64] = [];
    let n1 = wing::poll_events(p, 0, 1000, evs);
    assert(n1 == 1 && (evs[0].events & wing::POLL_READ) != 0 && (evs[0].events & wing::POLL_WRITE) == 0);
    let _ = wing::modify_socket(p, 10, 100, wing::PollInterest.Write, wing::PollTrigger.Edge);
    evs.clear();
    let n2 = wing::poll_events(p, 0, 2000, evs);
    assert(n2 == 1 && (evs[0].events & wing::POLL_WRITE) != 0);
    wing::close_poller(p);

    // 2. TickTimerWheel u32 addition wrap-around when current_tick + elapsed >= 2^32 (2^32 % 240 == 16 != 0)
    var wheel = wing::TickTimerWheel { current_tick: 200, .. };
    let next_tick = wing::tick_timer_advance(wheel, 0xFFFFFFFF);
    assert(next_tick == 215);

    // 3. UringSqe reuse clears stale ioprio and RIO sub-buffer guards u64 overflow
    var sqe = internal::UringSqe { .. };
    internal::uring_prep_accept_multishot(sqe, 5, 1);
    internal::uring_prep_accept(sqe, 5, 2);
    assert(sqe.ioprio == 0);
    let rio_buf = internal::new_rio_buffer(1, 4096);
    let rio_oob = internal::rio_sub_buffer(rio_buf, 0xFFFFFFFFFFFFFFFF, 1);
    assert(!rio_oob.is_registered);
    print("R008_REACTOR_DRV: 1");
}

fn main() {
    test_r001_dns_rfc_edge_cases();
    test_r002_happy_eyeballs_seams();
    test_r003_proxy_hop_by_hop_and_handshake();
    test_r004_masque_rfc_invariants();
    test_r005_proxy_protocol_roundtrip_and_bounds();
    test_r006_pool_h2_coalescing_and_queues();
    test_r007_isolation_and_retry_rfc();
    test_r008_poller_timer_tcp_and_drivers();
}

// CHECK: R001_DNS_RFC: 1
// CHECK: R002_HE_SEAMS: 1
// CHECK: R003_PROXY_SEAMS: 1
// CHECK: R004_MASQUE_RFC: 1
// CHECK: R005_PROXY_PROTO: 1
// CHECK: R006_POOL_SEAMS: 1
// CHECK: R007_ISO_RETRY: 1
// CHECK: R008_REACTOR_DRV: 1
