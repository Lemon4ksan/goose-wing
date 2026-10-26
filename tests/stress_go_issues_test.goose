// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Regression and stress tests for Go issue tracker / CVE vulnerabilities
import std;
import core from "..";
import wing from "..";

fn test_chunked_cve_2019_16276(t: core::T&) {
    // Space before colon in trailers must be rejected
    var wire: u8[..64] = [];
    wire.append("Content-Length : 100\r\n\r\n");
    var out_trailers: wing::HeaderItem[..16] = [];
    var cursor: i64 = 0;
    let err = wing::parse_chunked_trailers_with_out(wire[..], cursor, out_trailers);
    t.assert_true(err != wing::ChunkedDecodeError.None, "Space before colon in trailer must fail per CVE-2019-16276");

    // Negative / overflow chunk size
    var bad_chunk: u8[..64] = [];
    bad_chunk.append("FFFFFFFFFFFFFFFF\r\n");
    var out_body: u8[>..] = [];
    var trailers: wing::HeaderItem[..16] = [];
    let b_err, b_consumed = wing::decode_chunked_body_with_trailers(bad_chunk[..], out_body, trailers);
    t.assert_true(b_err != wing::ChunkedDecodeError.None, "Overflow chunk size FFFFFFFFFFFFFFFF must be rejected");
}

fn test_dns_name_length_overflow(t: core::T&) {
    // Malformed pointer chain pointing beyond end of packet
    let bad_dns: u8[12] = [
        0x00, 0x01, 0x81, 0x80,
        0x00, 0x01, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00
    ];
    var resp = wing::DnsResponse {};
    let ok = wing::parse_dns_response(bad_dns[..], resp);
    t.assert_false(ok, "Truncated DNS packet must return false without panic");
}

fn test_websocket_length_overflow(t: core::T&) {
    // Header with extended payload length 0x7FFFFFFFFFFFFFFF
    let bad_ws_hdr: u8[10] = [
        0x81, 0x7F,
        0x7F, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF, 0xFF
    ];
    var session = wing::new_websocket_session(true);
    var msg = wing::WsMessage {};
    var reply: u8[..64] = [];
    let ok = wing::ws_receive(session, bad_ws_hdr[..], msg, reply);
    t.assert_false(ok, "Huge 64-bit length frame without wire bytes must return false without overflow");

    // Close frame with illegal 1-byte payload must close with PROTOCOL_ERROR
    let bad_close: u8[3] = [0x88, 0x01, 0x00];
    var session2 = wing::new_websocket_session(false);
    var msg2 = wing::WsMessage {};
    var reply2: u8[..64] = [];
    let ok2 = wing::ws_receive(session2, bad_close[..], msg2, reply2);
    t.assert_true(ok2 && session2.is_closed && session2.close_code == wing::WS_STATUS_PROTOCOL_ERROR, "Close frame with 1-byte payload must trigger WS_STATUS_PROTOCOL_ERROR");
}

fn test_proxy_protocol_overflow(t: core::T&) {
    // PROXY v1 with >8 space-separated tokens
    let bad_line: const u8[:] = "PROXY TCP4 1.1.1.1 2.2.2.2 80 80 EXTRA1 EXTRA2 EXTRA3 EXTRA4\r\n";
    let hdr, consumed, ok = wing::parse_proxy_v1(bad_line);
    t.assert_false(ok, "PROXY v1 with >8 tokens must fail safely without buffer overflow");
}

fn test_masque_address_capsule_bounds(t: core::T&) {
    // Address capsule with oversized IP bytes (>16 bytes)
    var payload: u8[..32] = [];
    payload.push(1); // request_id = 1
    payload.push(4); // ip_version = 4
    payload.push(32);// prefix_len = 32
    for i in 20 { payload.push(0xAA); } // 20 bytes (> 16 cap)

    let req, ok = wing::decode_address_request_capsule(payload[..]);
    t.assert_false(ok, "Address request capsule with >16 IP bytes must fail without panic");
}

fn test_jwt_exp_overflow(t: core::T&) {
    var claims = wing::new_jwt_claims();
    // Expiry near i64::MAX
    wing::set_expiry(claims, 9223372036854775800);
    var opts = wing::JwtValidationOptions {};
    opts.leeway_seconds = 60;
    // Current time 1000 should NOT consider this expired despite addition overflow
    let err = wing::validate_jwt_claims_rules(claims, opts, 1000);
    t.assert_eq(err, wing::JwtError.None, "Far future exp must not overflow to expired");
}

fn test_quic_ack_underflow(t: core::T&) {
    var ack = wing::AckFrame {};
    ack.largest_acked = 10;
    ack.first_ack_range = 10;
    // Malicious huge gap that would wrap around in gap + 2
    ack.ranges.push(wing::AckRange { gap: 0xFFFFFFFFFFFFFFFF, ack_range: 0 });

    var space = wing::PnSpaceState {};
    space.has_sent_packets = true;
    space.largest_sent_pn = 100;
    var out_intervals: wing::AckInterval[..64] = [];

    let ok = wing::parse_and_validate_ack(space, ack, out_intervals);
    t.assert_false(ok, "Huge gap wrapping in gap + 2 must be safely rejected");
}

fn test_x509_san_tld_wildcard(t: core::T&) {
    // TLD wildcard *.com must NOT match evil.com (RFC 6125 §6.4.3)
    t.assert_false(wing::match_dns_san("*.com", "evil.com"), "*.com must not match evil.com");
    // Valid wildcard *.example.com must match sub.example.com
    t.assert_true(wing::match_dns_san("*.example.com", "sub.example.com"), "*.example.com matches sub.example.com");
    // Wildcard must not match IPv4
    t.assert_false(wing::match_dns_san("*.168.1.1", "192.168.1.1"), "Wildcard must not match IPv4 literal");
}

fn test_ipv6_mapped_ipv4_ssrf_cve_2024_24790(t: core::T&) {
    // CVE-2024-24790: IPv4-mapped IPv6 loopback & private addresses must be detected
    t.assert_true(wing::is_private_or_reserved_ip("::ffff:127.0.0.1"), "::ffff:127.0.0.1 must be private");
    t.assert_true(wing::is_private_or_reserved_ip("0:0:0:0:0:ffff:10.0.0.1"), "0:0:0:0:0:ffff:10.0.0.1 must be private");
    t.assert_true(wing::is_private_or_reserved_ip("::ffff:192.168.1.1"), "::ffff:192.168.1.1 must be private");
    t.assert_true(wing::is_private_or_reserved_ip("::ffff:169.254.169.254"), "::ffff:169.254.169.254 must be private");
    // Public IP must not be flagged
    t.assert_false(wing::is_private_or_reserved_ip("::ffff:8.8.8.8"), "::ffff:8.8.8.8 is public");
}

fn test_connect_tunnel_rejection_cve_2026_56866(t: core::T&) {
    // CVE-2026-56866: Failed or rejected CONNECT responses must poison/close connection
    t.assert_true(wing::should_close_connection_on_connect_error(wing::ConnectTunnelError.ProxyAuthRequired), "407 must close");
    t.assert_true(wing::should_close_connection_on_connect_error(wing::ConnectTunnelError.ConnectFailed), "Failed connect must close");
    t.assert_false(wing::should_close_connection_on_connect_error(wing::ConnectTunnelError.None), "Success connect must not close");
}

fn test_http2_initial_window_flood_cve_2026_78669(t: core::T&) {
    // CVE-2026-78669: Excessive SETTINGS INITIAL_WINDOW_SIZE changes must be throttled
    var conn = wing::new_h2_connection(1000);
    for i in 16 {
        let err = wing::apply_peer_initial_window_size_delta(conn, (65535 + (i % 2)) as u32);
        t.assert_eq(err, wing::ERR_NO_ERROR, "Initial updates <= 16 must succeed");
    }
    let flood_err = wing::apply_peer_initial_window_size_delta(conn, 65536);
    t.assert_eq(flood_err, wing::ERR_ENHANCE_YOUR_CALM, "17th window change must return ERR_ENHANCE_YOUR_CALM");
}

fn test_query_param_limit_cve_2026_39825(t: core::T&) {
    // CVE-2026-39825: Query parameter count limiter
    let normal_query: const u8[:] = "user=alice&action=login&lang=en";
    t.assert_true(core::validate_query_param_count(normal_query, 5), "Normal query <= 5 passes");

    var flood_query: u8[..128] = [];
    for i in 10 {
        flood_query.append("p=1&");
    }
    t.assert_false(core::validate_query_param_count(flood_query[..], 5), "Flooded query > 5 must fail");
}

fn test_punycode_validation_cve_2026_39821_and_97044(t: core::T&) {
    // CVE-2026-39821: Pure ASCII Punycode label (e.g. xn--test-) must be rejected
    t.assert_false(wing::validate_punycode_label("xn--test-"), "Pure ASCII xn--test- must be rejected");
    t.assert_true(wing::validate_punycode_label("xn--fsqu00a"), "Valid Punycode label must pass");

    // CVE-2026-97044: IDNA domain bounds validation
    t.assert_true(wing::validate_idna_domain_bounds("example.com"), "Standard domain passes");
    t.assert_false(wing::validate_idna_domain_bounds("xn--test-.com"), "Domain with pure ASCII Punycode rejected");
}

fn test_x509_uri_zone_id_cve_2024_45341(t: core::T&) {
    // CVE-2024-45341: IPv6 zone IDs in URI SAN must not bypass name constraints
    t.assert_true(wing::match_uri_san("example.com", "example.com"), "Identical URI SAN matches");
    t.assert_false(wing::match_uri_san("fe80::1%eth0", "fe80::1%eth0"), "Zone ID in URI SAN must be rejected");
}

fn test_error_sanitization_cve_2026_42507(t: core::T&) {
    // CVE-2026-42507: Unescaped inputs in errors must be sanitized against CRLF injection
    let untrusted: const u8[:] = "Bad\r\nSet-Cookie: evil\x00";
    var clean_buf: u8[..64] = [];
    wing::sanitize_untrusted_for_error(untrusted, clean_buf);
    t.assert_false(core::contains_byte(clean_buf[..], '\r'), "CR must be removed/replaced");
    t.assert_false(core::contains_byte(clean_buf[..], '\n'), "LF must be removed/replaced");
    t.assert_false(core::contains_byte(clean_buf[..], 0), "NUL must be removed/replaced");
}

fn main() {
    var runner = core::new_runner("Go Bug Tracker Stress Regression Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. CVE-2019-16276 Space-before-colon & Chunk Size Overflow", test_chunked_cve_2019_16276);
    core::run_case(runner, "2. DNS Name Decoding Length Overflow", test_dns_name_length_overflow);
    core::run_case(runner, "3. WebSocket Extended Length & Close Frame Invariants", test_websocket_length_overflow);
    core::run_case(runner, "4. PROXY Protocol v1 Token Capacity Guard", test_proxy_protocol_overflow);
    core::run_case(runner, "5. MASQUE Address Request Capsule Bounds", test_masque_address_capsule_bounds);
    core::run_case(runner, "6. JWT Expiry Integer Overflow Defense", test_jwt_exp_overflow);
    core::run_case(runner, "7. QUIC ACK Frame Gap Addition Overflow Defense", test_quic_ack_underflow);
    core::run_case(runner, "8. X.509 DNS SAN TLD Wildcard & IP Literal Defense", test_x509_san_tld_wildcard);
    core::run_case(runner, "9. CVE-2024-24790 IPv4-Mapped IPv6 SSRF Filter Defense", test_ipv6_mapped_ipv4_ssrf_cve_2024_24790);
    core::run_case(runner, "10. CVE-2026-56866 Client CONNECT Tunnel Rejection Poisoning", test_connect_tunnel_rejection_cve_2026_56866);
    core::run_case(runner, "11. CVE-2026-78669 HTTP/2 Initial Window Size Flood Defense", test_http2_initial_window_flood_cve_2026_78669);
    core::run_case(runner, "12. CVE-2026-39825 URL Query Parameter Flooding Limit", test_query_param_limit_cve_2026_39825);
    core::run_case(runner, "13. CVE-2026-39821 & CVE-2026-97044 Punycode & IDNA Bounds", test_punycode_validation_cve_2026_39821_and_97044);
    core::run_case(runner, "14. CVE-2024-45341 X.509 URI SAN Zone ID Rejection", test_x509_uri_zone_id_cve_2024_45341);
    core::run_case(runner, "15. CVE-2026-42507 Error Message Untrusted Input Sanitization", test_error_sanitization_cve_2026_42507);

    let ok = core::finish(runner);
    assert(ok);
}
