// tests/proxy_protocol_test.goose
// Verification test suite for HAProxy PROXY Protocol v1 (text) and v2 (binary).
import std;
import core from "..";
import wing from "..";

// ============================================================================
// 1. PROXY Protocol v1 (Text) Conformance
// ============================================================================
fn test_proxy_v1_conformance(t: core::T&) {
    t.run("PROXY-v1-01: Valid TCP4 line parsing") { sub =>
        let raw = "PROXY TCP4 192.168.0.1 10.0.0.1 56324 443\r\nGET / HTTP/1.1\r\n";
        let hdr, consumed, ok = wing::parse_proxy_v1(raw);
        sub.assert_true(ok, "parse_proxy_v1 succeeds on valid TCP4");
        sub.assert_eq(consumed, 43, "consumed exact 43 bytes of PROXY v1 line");
        sub.assert_true(hdr.version == wing::ProxyProtocolVersion.V1, "version is V1");
        sub.assert_true(hdr.command == wing::ProxyCommand.Proxy, "command is Proxy");
        sub.assert_true(hdr.family == wing::ProxyAddressFamily.Inet4, "family is Inet4");
        sub.assert_true(hdr.transport == wing::ProxyTransportProtocol.Stream, "transport is Stream");
        sub.assert_bytes_eq(hdr.src_ip_str[..], "192.168.0.1", "src_ip_str matches");
        sub.assert_bytes_eq(hdr.dst_ip_str[..], "10.0.0.1", "dst_ip_str matches");
        sub.assert_eq(hdr.src_port, 56324, "src_port matches");
        sub.assert_eq(hdr.dst_port, 443, "dst_port matches");
        sub.assert_eq(hdr.src_ipv4[0], 192, "IPv4 octet 0 matches");
        sub.assert_eq(hdr.src_ipv4[3], 1, "IPv4 octet 3 matches");
    };

    t.run("PROXY-v1-02: Valid TCP6 line parsing") { sub =>
        let raw = "PROXY TCP6 2001:db8::1 2001:db8::2 56324 443\r\n";
        let hdr, consumed, ok = wing::parse_proxy_v1(raw);
        sub.assert_true(ok, "parse_proxy_v1 succeeds on valid TCP6");
        sub.assert_eq(consumed, raw.len, "consumed full line");
        sub.assert_true(hdr.family == wing::ProxyAddressFamily.Inet6, "family is Inet6");
        sub.assert_bytes_eq(hdr.src_ip_str[..], "2001:db8::1", "IPv6 src matches");
        sub.assert_bytes_eq(hdr.dst_ip_str[..], "2001:db8::2", "IPv6 dst matches");
        sub.assert_eq(hdr.src_port, 56324, "src port matches");
        sub.assert_eq(hdr.dst_port, 443, "dst port matches");
    };

    t.run("PROXY-v1-03: UNKNOWN protocol parsing") { sub =>
        let raw = "PROXY UNKNOWN\r\n";
        let hdr, consumed, ok = wing::parse_proxy_v1(raw);
        sub.assert_true(ok, "parse_proxy_v1 succeeds on UNKNOWN");
        sub.assert_eq(consumed, 15, "consumed exact 15 bytes");
        sub.assert_true(hdr.command == wing::ProxyCommand.Local, "command is Local for UNKNOWN");
        sub.assert_true(hdr.family == wing::ProxyAddressFamily.Unspec, "family is Unspec");
    };

    t.run("PROXY-v1-04: Serialization round-trip") { sub =>
        var hdr = wing::ProxyHeader {
            version: wing::ProxyProtocolVersion.V1,
            command: wing::ProxyCommand.Proxy,
            family: wing::ProxyAddressFamily.Inet4,
            transport: wing::ProxyTransportProtocol.Stream,
            src_ipv4: [172, 16, 1, 25],
            dst_ipv4: [10, 0, 0, 2],
            src_port: 41234,
            dst_port: 8080,
            ..
        };
        hdr.src_ip_str.append("172.16.1.25");
        hdr.dst_ip_str.append("10.0.0.2");

        var out: u8[..128] = [];
        let ok_fmt = wing::format_proxy_v1(hdr, out);
        sub.assert_true(ok_fmt, "format_proxy_v1 succeeds");
        sub.assert_bytes_eq(out[..], "PROXY TCP4 172.16.1.25 10.0.0.2 41234 8080\r\n", "serialized v1 format matches spec");

        // Parse back
        let back_hdr, consumed, ok_back = wing::parse_proxy_v1(out[..]);
        sub.assert_true(ok_back, "parse back succeeds");
        sub.assert_eq(consumed, out.len, "consumed all bytes");
        sub.assert_eq(back_hdr.src_port, 41234, "round-trip port matches");
        sub.assert_bytes_eq(back_hdr.src_ip_str[..], "172.16.1.25", "round-trip IP matches");
    };

    t.run("PROXY-v1-05: Rejection of invalid and truncated lines") { sub =>
        // Missing CRLF
        let truncated = "PROXY TCP4 192.168.0.1 10.0.0.1 56324 443";
        let _, _, ok_trunc = wing::parse_proxy_v1(truncated);
        sub.assert_false(ok_trunc, "truncated line without CRLF rejected");

        // Wrong prefix
        let wrong_prefix = "PROX2 TCP4 192.168.0.1 10.0.0.1 56324 443\r\n";
        let _, _, ok_pref = wing::parse_proxy_v1(wrong_prefix);
        sub.assert_false(ok_pref, "wrong prefix rejected");

        // Invalid IP octet > 255
        let bad_ip = "PROXY TCP4 300.168.0.1 10.0.0.1 56324 443\r\n";
        let _, _, ok_bad_ip = wing::parse_proxy_v1(bad_ip);
        sub.assert_false(ok_bad_ip, "octet > 255 rejected");

        // Invalid Port > 65535
        let bad_port = "PROXY TCP4 192.168.0.1 10.0.0.1 70000 443\r\n";
        let _, _, ok_bad_port = wing::parse_proxy_v1(bad_port);
        sub.assert_false(ok_bad_port, "port > 65535 rejected");

        // Missing tokens
        let missing_tok = "PROXY TCP4 192.168.0.1 10.0.0.1 443\r\n";
        let _, _, ok_mis = wing::parse_proxy_v1(missing_tok);
        sub.assert_false(ok_mis, "line with missing tokens rejected");
    };
}

// ============================================================================
// 2. PROXY Protocol v2 (Binary) Conformance
// ============================================================================
fn test_proxy_v2_conformance(t: core::T&) {
    t.run("PROXY-v2-01: IPv4 TCP binary header parsing") { sub =>
        // Preamble (12) + 0x21 (v2, PROXY) + 0x11 (INET4, STREAM) + len 12 (0x000C)
        var wire: u8[..64] = [];
        for b in wing::PROXY_V2_PREAMBLE { wire.push(b); }
        wire.push(0x21); // version 2, PROXY command
        wire.push(0x11); // INET4, STREAM (TCP)
        wire.push(0x00); wire.push(12); // payload length = 12

        // IPv4 addresses: 192.168.1.10 -> 10.0.0.1
        wire.push(192); wire.push(168); wire.push(1); wire.push(10);
        wire.push(10); wire.push(0); wire.push(0); wire.push(1);
        // Ports: src 50000 (0xC350), dst 443 (0x01BB)
        wire.push(0xC3); wire.push(0x50);
        wire.push(0x01); wire.push(0xBB);

        let hdr, consumed, ok = wing::parse_proxy_v2(wire[..]);
        sub.assert_true(ok, "parse_proxy_v2 succeeds on IPv4 TCP");
        sub.assert_eq(consumed, 28, "consumed exact 28 bytes (16 header + 12 addr)");
        sub.assert_true(hdr.version == wing::ProxyProtocolVersion.V2, "version is V2");
        sub.assert_true(hdr.command == wing::ProxyCommand.Proxy, "command is Proxy");
        sub.assert_true(hdr.family == wing::ProxyAddressFamily.Inet4, "family is Inet4");
        sub.assert_true(hdr.transport == wing::ProxyTransportProtocol.Stream, "transport is Stream");
        sub.assert_bytes_eq(hdr.src_ip_str[..], "192.168.1.10", "formatted src IPv4 matches");
        sub.assert_bytes_eq(hdr.dst_ip_str[..], "10.0.0.1", "formatted dst IPv4 matches");
        sub.assert_eq(hdr.src_port, 50000, "src port matches");
        sub.assert_eq(hdr.dst_port, 443, "dst port matches");
    };

    t.run("PROXY-v2-02: Command LOCAL (health checks)") { sub =>
        var wire: u8[..32] = [];
        for b in wing::PROXY_V2_PREAMBLE { wire.push(b); }
        wire.push(0x20); // version 2, LOCAL command
        wire.push(0x00); // UNSPEC, UNSPEC
        wire.push(0x00); wire.push(0x00); // payload length = 0

        let hdr, consumed, ok = wing::parse_proxy_v2(wire[..]);
        sub.assert_true(ok, "parse_proxy_v2 succeeds on LOCAL");
        sub.assert_eq(consumed, 16, "consumed exact 16 bytes");
        sub.assert_true(hdr.command == wing::ProxyCommand.Local, "command is Local");
        sub.assert_true(hdr.family == wing::ProxyAddressFamily.Unspec, "family is Unspec");
    };

    t.run("PROXY-v2-03: IPv6 TCP binary header parsing") { sub =>
        var wire: u8[..64] = [];
        for b in wing::PROXY_V2_PREAMBLE { wire.push(b); }
        wire.push(0x21); // version 2, PROXY command
        wire.push(0x21); // INET6, STREAM (TCP)
        wire.push(0x00); wire.push(36); // payload length = 36

        // 16 bytes src IPv6
        for i in 16 { wire.push(i as u8); }
        // 16 bytes dst IPv6
        for i in 16 { wire.push((0x10 + i) as u8); }
        // Ports: 8080 (0x1F90), 443 (0x01BB)
        wire.push(0x1F); wire.push(0x90);
        wire.push(0x01); wire.push(0xBB);

        let hdr, consumed, ok = wing::parse_proxy_v2(wire[..]);
        sub.assert_true(ok, "parse_proxy_v2 succeeds on IPv6");
        sub.assert_eq(consumed, 52, "consumed 16 header + 36 addr = 52 bytes");
        sub.assert_true(hdr.family == wing::ProxyAddressFamily.Inet6, "family is Inet6");
        sub.assert_eq(hdr.src_port, 8080, "src port matches");
        sub.assert_eq(hdr.dst_port, 443, "dst port matches");
    };

    t.run("PROXY-v2-04: Rejection of invalid v2 headers") { sub =>
        // Corrupted preamble
        var bad_preamble: u8[16] = [0; 16];
        let _, _, ok_bad = wing::parse_proxy_v2(bad_preamble[..]);
        sub.assert_false(ok_bad, "bad preamble rejected");

        // Wrong version (0x11 instead of 0x21)
        var bad_ver: u8[..32] = [];
        for b in wing::PROXY_V2_PREAMBLE { bad_ver.push(b); }
        bad_ver.push(0x11); bad_ver.push(0x11); bad_ver.push(0); bad_ver.push(0);
        let _, _, ok_ver = wing::parse_proxy_v2(bad_ver[..]);
        sub.assert_false(ok_ver, "version != 2 rejected");

        // Truncated payload length claim
        var trunc_wire: u8[..32] = [];
        for b in wing::PROXY_V2_PREAMBLE { trunc_wire.push(b); }
        trunc_wire.push(0x21); trunc_wire.push(0x11);
        trunc_wire.push(0x00); trunc_wire.push(100); // claim 100 bytes but only 16 present
        let _, _, ok_len = wing::parse_proxy_v2(trunc_wire[..]);
        sub.assert_false(ok_len, "truncated payload rejected");
    };
}

// ============================================================================
// 3. PROXY Protocol v2 TLV (Type-Length-Value) Metadata
// ============================================================================
fn test_proxy_v2_tlvs(t: core::T&) {
    t.run("PROXY-v2-TLV-01: ALPN, Authority, and Unique ID") { sub =>
        var hdr = wing::ProxyHeader {
            version: wing::ProxyProtocolVersion.V2,
            command: wing::ProxyCommand.Proxy,
            family: wing::ProxyAddressFamily.Inet4,
            transport: wing::ProxyTransportProtocol.Stream,
            src_ipv4: [192, 168, 1, 100],
            dst_ipv4: [10, 0, 0, 1],
            src_port: 45678,
            dst_port: 443,
            ..
        };
        hdr.alpn.append("h2");
        hdr.authority.append("secure.api.internal");
        hdr.unique_id.append("trace-c0ffee-9988");

        var wire: u8[..256] = [];
        let ok_fmt = wing::format_proxy_v2(hdr, wire);
        sub.assert_true(ok_fmt, "format_proxy_v2 with TLVs succeeds");

        // Parse back
        let back_hdr, consumed, ok_parse = wing::parse_proxy_v2(wire[..]);
        sub.assert_true(ok_parse, "parse_proxy_v2 succeeds on serialized TLVs");
        sub.assert_eq(consumed, wire.len, "consumed full wire with TLVs");
        sub.assert_bytes_eq(back_hdr.alpn[..], "h2", "ALPN TLV matches");
        sub.assert_bytes_eq(back_hdr.authority[..], "secure.api.internal", "Authority/SNI TLV matches");
        sub.assert_bytes_eq(back_hdr.unique_id[..], "trace-c0ffee-9988", "Unique ID TLV matches");
    };

    t.run("PROXY-v2-TLV-02: SSL/TLS Metadata & Sub-TLVs") { sub =>
        var hdr = wing::ProxyHeader {
            version: wing::ProxyProtocolVersion.V2,
            command: wing::ProxyCommand.Proxy,
            family: wing::ProxyAddressFamily.Inet4,
            transport: wing::ProxyTransportProtocol.Stream,
            src_ipv4: [10, 20, 30, 40],
            dst_ipv4: [10, 0, 0, 2],
            src_port: 33445,
            dst_port: 8443,
            ..
        };
        hdr.ssl.has_ssl = true;
        hdr.ssl.client_flags = wing::PP2_CLIENT_SSL | wing::PP2_CLIENT_CERT_CONN;
        hdr.ssl.verify_result = 0; // successfully verified client cert
        hdr.ssl.version.append("TLSv1.3");
        hdr.ssl.cipher.append("TLS_AES_128_GCM_SHA256");
        hdr.ssl.client_cn.append("client.tenant42.prod");

        var wire: u8[..512] = [];
        let ok_fmt = wing::format_proxy_v2(hdr, wire);
        sub.assert_true(ok_fmt, "format_proxy_v2 with SSL TLV succeeds");

        // Parse back
        let back_hdr, consumed, ok_parse = wing::parse_proxy_v2(wire[..]);
        sub.assert_true(ok_parse, "parse_proxy_v2 parses SSL TLVs cleanly");
        sub.assert_eq(consumed, wire.len, "consumed entire buffer");
        sub.assert_true(back_hdr.ssl.has_ssl, "SSL flag set");
        sub.assert_eq(back_hdr.ssl.client_flags, wing::PP2_CLIENT_SSL | wing::PP2_CLIENT_CERT_CONN, "client flags preserved");
        sub.assert_eq(back_hdr.ssl.verify_result, 0, "verify_result is 0");
        sub.assert_bytes_eq(back_hdr.ssl.version[..], "TLSv1.3", "SSL version matches");
        sub.assert_bytes_eq(back_hdr.ssl.cipher[..], "TLS_AES_128_GCM_SHA256", "Cipher matches");
        sub.assert_bytes_eq(back_hdr.ssl.client_cn[..], "client.tenant42.prod", "Client CN matches");
    };
}

// ============================================================================
// 4. Stream Stripping & Server Pipeline Integration
// ============================================================================
fn test_proxy_server_integration(t: core::T&) {
    t.run("Auto-Detection and Stream Stripping") { sub =>
        let stream = "PROXY TCP4 203.0.113.195 10.0.0.1 54321 80\r\nGET /index.html HTTP/1.1\r\nHost: example.com\r\n\r\n";
        var proxy_hdr = wing::ProxyHeader { .. };
        let rest, has_proxy = wing::detect_and_strip_proxy_header(stream, proxy_hdr);

        sub.assert_true(has_proxy, "PROXY header detected and stripped");
        sub.assert_bytes_eq(proxy_hdr.src_ip_str[..], "203.0.113.195", "Client IP extracted from PROXY v1");
        sub.assert_bytes_eq(rest[..15], "GET /index.html", "Remaining stream starts with HTTP request");

        // Non-proxy stream returns original stream unchanged
        let non_proxy = "GET /status HTTP/1.1\r\nHost: test.com\r\n\r\n";
        var empty_hdr = wing::ProxyHeader { .. };
        let rest2, has_proxy2 = wing::detect_and_strip_proxy_header(non_proxy, empty_hdr);
        sub.assert_false(has_proxy2, "No PROXY header detected on plain HTTP");
        sub.assert_bytes_eq(rest2, non_proxy, "Plain HTTP stream unchanged");
    };

    t.run("HttpServer with accept_proxy_protocol = true") { sub =>
        var server = wing::new_http_server("127.0.0.1", 8080);
        server.accept_proxy_protocol = true;
        wing::add_get_route(server, "/api/hello", 101);

        // Prepend PROXY v1 header before HTTP/1.1 wire request
        let wire_in = "PROXY TCP4 198.51.100.77 10.0.0.1 61234 8080\r\nGET /api/hello HTTP/1.1\r\nHost: 127.0.0.1\r\n\r\n";
        var wire_out: u8[..512] = [];

        let outcome, ok = wing::handle_connection_wire(server, "127.0.0.1", wire_in, 1700000000, wire_out);
        sub.assert_true(ok, "handle_connection_wire succeeds with PROXY header");
        sub.assert_true(outcome == wing::PipelineOutcome.Handled, "Pipeline handled route");
        sub.assert_gt(wire_out.len, 0, "Response generated");
        sub.assert_bytes_eq(wire_out[..15], "HTTP/1.1 200 OK", "Server returned 200 OK");
        sub.assert_eq(server.requests_processed, 1, "Requests counter incremented");
    };
}

fn main() {
    var runner = core::new_runner("HAProxy PROXY Protocol v1 & v2 Conformance Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. PROXY Protocol v1 (Text) Conformance", test_proxy_v1_conformance);
    core::run_case(runner, "2. PROXY Protocol v2 (Binary) Conformance", test_proxy_v2_conformance);
    core::run_case(runner, "3. PROXY Protocol v2 TLV Metadata", test_proxy_v2_tlvs);
    core::run_case(runner, "4. Stream Stripping & Server Integration", test_proxy_server_integration);
    let ok = core::finish(runner);
    assert(ok);
}
