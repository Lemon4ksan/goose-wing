// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Security invariant tests for MASQUE (RFC 9297, RFC 9298, RFC 9484) and DNS (RFC 1035, RFC 9460).
import std;
import core from "..";
import wing from "..";

fn test_masque_connect_udp_path_parsing(t: core::T&) {
    // 1. Valid RFC 9298 paths
    let h1, p1, ok1 = wing::parse_connect_udp_path("/.well-known/masque/udp/1.1.1.1/53/");
    t.assert_true(ok1, "valid template with trailing slash should pass");
    t.assert_eq(p1, 53, "port should be 53");
    t.assert_true(h1[..] == "1.1.1.1", "host should match");

    let h2, p2, ok2 = wing::parse_connect_udp_path("/.well-known/masque/udp/example.com/443");
    t.assert_true(ok2, "valid template without trailing slash should pass");
    t.assert_eq(p2, 443, "port should be 443");
    t.assert_true(h2[..] == "example.com", "host should match");

    // 2. RFC 9298 Section 3: target_port MUST be 1..65535, port 0 strictly forbidden
    let _, _, ok_zero = wing::parse_connect_udp_path("/.well-known/masque/udp/1.1.1.1/0/");
    t.assert_false(ok_zero, "port 0 must be rejected");

    let _, _, ok_big = wing::parse_connect_udp_path("/.well-known/masque/udp/1.1.1.1/65536/");
    t.assert_false(ok_big, "port > 65535 must be rejected");

    // 3. Characters forbidden in host part
    let _, _, ok_bad1 = wing::parse_connect_udp_path("/.well-known/masque/udp/bad?host/53/");
    t.assert_false(ok_bad1, "host with query delimiter must be rejected");

    let _, _, ok_bad2 = wing::parse_connect_udp_path("/.well-known/masque/udp/bad#host/53/");
    t.assert_false(ok_bad2, "host with hash fragment delimiter must be rejected");

    let _, _, ok_bad3 = wing::parse_connect_udp_path("/.well-known/masque/udp/bad host/53/");
    t.assert_false(ok_bad3, "host with space must be rejected");

    // 4. Extra path segments
    let _, _, ok_extra = wing::parse_connect_udp_path("/.well-known/masque/udp/1.1.1.1/53/extra");
    t.assert_false(ok_extra, "extra segments after port must be rejected");
}

fn test_masque_capsule_codecs(t: core::T&) {
    // 1. DATAGRAM capsule encode & decode
    var cap_out: u8[..128] = [];
    let enc_ok = wing::encode_connect_udp_datagram_capsule(cap_out, 0, "ping");
    t.assert_true(enc_ok, "datagram capsule encode should succeed");

    let cap, parse_ok = wing::parse_http_capsule(cap_out[..]);
    t.assert_true(parse_ok, "http capsule parse should succeed");
    t.assert_true(cap.capsule_type == wing::CAPSULE_DATAGRAM, "capsule type should be DATAGRAM");

    let ctx_id, pkt, pkt_ok = wing::parse_connect_udp_datagram(cap.payload);
    t.assert_true(pkt_ok, "connect udp datagram parse should succeed");
    t.assert_eq(ctx_id, 0, "context id should be 0");
    t.assert_true(pkt == "ping", "payload should match");

    // 2. CONNECT-IP ADDRESS_ASSIGN IPv4 (RFC 9484)
    var assign4 = wing::IpAddressAssign { request_id: 42, ip_version: 4, prefix_len: 32, .. };
    assign4.assigned_ip.append([10, 0, 0, 1]);
    var wire4: u8[..128] = [];
    t.assert_true(wing::encode_address_assign_capsule(wire4, assign4), "encode address assign v4");

    let cap4, cap4_ok = wing::parse_http_capsule(wire4[..]);
    t.assert_true(cap4_ok, "parse assign capsule");
    t.assert_true(cap4.capsule_type == wing::CAPSULE_ADDRESS_ASSIGN, "type matches address assign");

    let dec4, dec4_ok = wing::decode_address_assign_capsule(cap4.payload);
    t.assert_true(dec4_ok, "decode address assign v4");
    t.assert_eq(dec4.request_id, 42, "req id matches");
    t.assert_eq(dec4.ip_version, 4, "version is 4");
    t.assert_eq(dec4.prefix_len, 32, "prefix is 32");
    t.assert_true(dec4.assigned_ip.len == 4 && dec4.assigned_ip[0] == 10 && dec4.assigned_ip[3] == 1, "assigned ip matches");

    // 3. CONNECT-IP ADDRESS_ASSIGN invalid versions / bounds
    // Invalid IP version 5
    let bad_ver_wire: u8[7] = [0x01, 0x05, 0x20, 10, 0, 0, 1];
    let _, bad_ver_ok = wing::decode_address_assign_capsule(bad_ver_wire[..]);
    t.assert_false(bad_ver_ok, "invalid IP version 5 must be rejected");

    // IPv4 prefix length > 32
    let bad_pre_wire: u8[7] = [0x01, 0x04, 0x21, 10, 0, 0, 1];
    let _, bad_pre_wire_ok = wing::decode_address_assign_capsule(bad_pre_wire[..]);
    t.assert_false(bad_pre_wire_ok, "IPv4 prefix length > 32 must be rejected");

    // IPv4 with wrong byte count (3 bytes instead of 4)
    let bad_len_wire: u8[6] = [0x01, 0x04, 0x20, 10, 0, 1];
    let _, bad_len_ok = wing::decode_address_assign_capsule(bad_len_wire[..]);
    t.assert_false(bad_len_ok, "IPv4 address with rdlength != 4 must be rejected");
}

fn test_dns_pointer_security(t: core::T&) {
    // Valid backward pointer response
    // Header 12B, Question 17B (example.com A IN), Answer 16B (pointer 0xC00C -> example.com)
    let valid_wire: const u8[45] = [
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
        0x5d, 0xb8, 0xd8, 0x22,
    ];
    var resp1 = wing::DnsResponse { .. };
    let ok1 = wing::parse_dns_response(valid_wire[..], resp1);
    t.assert_true(ok1, "valid backward pointer must succeed");
    t.assert_eq(resp1.a_records.len, 1, "parsed 1 A record");
    t.assert_true(resp1.a_records[0] == 0x5db8d822, "IP address matches");

    // Forward pointer rejected (RFC 1035 §4.1.4: ptr_off >= current_off)
    var fwd_wire = valid_wire;
    fwd_wire[29] = 0xc0;
    fwd_wire[30] = 0x23; // points to offset 35 > 29
    var resp2 = wing::DnsResponse { .. };
    let ok2 = wing::parse_dns_response(fwd_wire[..], resp2);
    t.assert_false(ok2, "forward pointer must be rejected");

    // Pointer into header rejected (ptr_off < 12)
    var hdr_wire = valid_wire;
    hdr_wire[29] = 0xc0;
    hdr_wire[30] = 0x04; // points to offset 4 < 12
    var resp3 = wing::DnsResponse { .. };
    let ok3 = wing::parse_dns_response(hdr_wire[..], resp3);
    t.assert_false(ok3, "pointer into header must be rejected");
}

fn test_dns_record_bounds_and_https_target(t: core::T&) {
    // Malformed A record: rdlength != 4
    let bad_a_wire: const u8[44] = [
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x01, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x03,
        0x5d, 0xb8, 0xd8,
    ];
    var resp_a = wing::DnsResponse { .. };
    let ok_a = wing::parse_dns_response(bad_a_wire[..], resp_a);
    t.assert_false(ok_a, "A record with rdlength != 4 must be rejected");

    // RFC 9460 §2.5.1: HTTPS TargetName containing compression pointer (0xC00C) must be rejected
    let bad_https_wire: const u8[45] = [
        0x12, 0x34, 0x81, 0x80, 0x00, 0x01, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00,
        0x07, 'e', 'x', 'a', 'm', 'p', 'l', 'e', 0x03, 'c', 'o', 'm', 0x00,
        0x00, 0x41, 0x00, 0x01,
        0xc0, 0x0c, 0x00, 0x41, 0x00, 0x01, 0x00, 0x00, 0x00, 0x3c, 0x00, 0x04,
        0x00, 0x01, 0xc0, 0x0c,
    ];
    var resp_h = wing::DnsResponse { .. };
    let ok_h = wing::parse_dns_response(bad_https_wire[..], resp_h);
    t.assert_false(ok_h, "HTTPS TargetName with compression pointer must be rejected");
}

fn main() {
    var runner = core::new_runner("MASQUE & DNS Security Invariants Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. MASQUE CONNECT-UDP Path Parsing", test_masque_connect_udp_path_parsing);
    core::run_case(runner, "2. MASQUE Capsule Codecs", test_masque_capsule_codecs);
    core::run_case(runner, "3. DNS Pointer Security", test_dns_pointer_security);
    core::run_case(runner, "4. DNS Record Bounds & HTTPS Target", test_dns_record_bounds_and_https_target);
    let ok = core::finish(runner);
    assert(ok);
}
