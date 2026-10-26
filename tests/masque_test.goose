// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for MASQUE protocols:
// - RFC 9297: HTTP Datagrams & Capsule Protocol
// - RFC 9298: Proxying UDP in HTTP (CONNECT-UDP)
// - RFC 9484: Proxying IP in HTTP (CONNECT-IP)
// - RFC 9221: An Unreliable Datagram Extension to QUIC
import std;
import core from "..";
import wing from "..";

fn test_rfc9297_capsules_and_datagrams(t: core::T&) {
    t.run("Capsule Protocol Framing & Zero-Copy Decode") { sub =>
        var wire: u8[>..] = [];
        let raw_payload = "test_capsule_payload_bytes";
        let enc_ok = wing::encode_http_capsule(wire, wing::CAPSULE_DATAGRAM, raw_payload);
        sub.assert_true(enc_ok, "encode_http_capsule succeeded");

        let c, dec_ok = wing::parse_http_capsule(wire[..]);
        sub.assert_true(dec_ok, "parse_http_capsule succeeded");
        sub.assert_eq(c.capsule_type, wing::CAPSULE_DATAGRAM, "Type is CAPSULE_DATAGRAM (0x00)");
        sub.assert_bytes_eq(c.payload, raw_payload, "Payload bytes match exactly");

        // Truncated capsule wire detection
        let short_wire = wire[..wire.len - 3];
        let _, trunc_ok = wing::parse_http_capsule(short_wire);
        sub.assert_false(trunc_ok, "Truncated capsule detected and rejected");

        // Capsule-Protocol RFC 9297 Section 3.4 / RFC 8941 validation
        sub.assert_true(wing::is_capsule_protocol_negotiated("?1"), "Standard ?1");
        sub.assert_true(wing::is_capsule_protocol_negotiated(" ?1; param=value "), "Structured ?1 with params");
        sub.assert_false(wing::is_capsule_protocol_negotiated("?0"), "?0 rejected");

        var mock_hdrs = wing::new_header_map();
        wing::append_header(mock_hdrs, "capsule-protocol", "?1");
        sub.assert_true(mock_hdrs.has_capsule_protocol(), "has_capsule_protocol on HeaderMap");
    };

    t.run("HTTP Datagrams over QUIC (Quarter Stream ID + Context ID)") { sub =>
        var dgram_wire: u8[>..] = [];
        let udp_sample = "dns_query_udp_payload";
        let quarter_stream_id: u64 = 2; // Stream ID 8 / 4 = 2
        let context_id: u64 = 0;        // Default uncompressed context

        let enc_ok = wing::encode_http_datagram(dgram_wire, quarter_stream_id, context_id, udp_sample);
        sub.assert_true(enc_ok, "encode_http_datagram ok");

        let q_id, ctx_id, payload, dec_ok = wing::decode_http_datagram(dgram_wire[..]);
        sub.assert_true(dec_ok, "decode_http_datagram ok");
        sub.assert_eq(q_id, 2, "Quarter stream ID matches (2)");
        sub.assert_eq(ctx_id, 0, "Context ID matches (0)");
        sub.assert_bytes_eq(payload, udp_sample, "Payload matches");

        // QUIC DATAGRAM frame (RFC 9221 Type 0x31 with length)
        var quic_frame_wire: u8[>..] = [];
        let frame_ok = wing::encode_quic_datagram_frame(quic_frame_wire, dgram_wire[..], true);
        sub.assert_true(frame_ok, "encode_quic_datagram_frame ok");

        let parsed_dgram, end_off, frame_dec_ok = wing::decode_quic_datagram_frame(quic_frame_wire[..], 0);
        sub.assert_true(frame_dec_ok, "decode_quic_datagram_frame ok");
        sub.assert_bytes_eq(parsed_dgram, dgram_wire[..], "Datagram bytes match inside QUIC frame");
    };
}

fn test_rfc9298_connect_udp(t: core::T&) {
    t.run("URI Template Formatting and Parsing") { sub =>
        var path_buf: u8[..256] = [];
        wing::format_connect_udp_path(path_buf, "1.1.1.1", 53);
        sub.assert_bytes_eq(path_buf[..], "/.well-known/masque/udp/1.1.1.1/53/", "Format IPv4 53");

        let host, port, ok = wing::parse_connect_udp_path(path_buf[..]);
        sub.assert_true(ok, "parse_connect_udp_path ok");
        sub.assert_bytes_eq(host[..], "1.1.1.1", "Host parsed correctly");
        sub.assert_eq(port, 53, "Port parsed correctly (53)");

        // Domain name target
        var domain_path: u8[..256] = [];
        wing::format_connect_udp_path(domain_path, "dns.google", 853);
        let d_host, d_port, d_ok = wing::parse_connect_udp_path(domain_path[..]);
        sub.assert_true(d_ok, "parse domain target ok");
        sub.assert_bytes_eq(d_host[..], "dns.google", "Domain target parsed");
        sub.assert_eq(d_port, 853, "Port 853 parsed");

        // Invalid paths
        let _, _, bad1 = wing::parse_connect_udp_path("/random/path/foo");
        sub.assert_false(bad1, "Random path rejected");

        let _, _, bad2 = wing::parse_connect_udp_path("/.well-known/masque/udp/1.1.1.1/notaport/");
        sub.assert_false(bad2, "Non-numeric port rejected");
    };

    t.run("In-Stream DATAGRAM Capsule Serialization") { sub =>
        var wire: u8[>..] = [];
        let udp_data = "\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00\x07example\x03com\x00\x00\x01\x00\x01";
        let enc_ok = wing::encode_connect_udp_datagram_capsule(wire, 0, udp_data);
        sub.assert_true(enc_ok, "encode_connect_udp_datagram_capsule ok");

        let c, ok_c = wing::parse_http_capsule(wire[..]);
        sub.assert_true(ok_c, "parse outer capsule ok");
        sub.assert_eq(c.capsule_type, wing::CAPSULE_DATAGRAM, "Capsule type is 0x00");

        let ctx_id, parsed_udp, ok_udp = wing::parse_connect_udp_datagram(c.payload);
        sub.assert_true(ok_udp, "parse_connect_udp_datagram ok");
        sub.assert_eq(ctx_id, 0, "Context ID is 0");
        sub.assert_bytes_eq(parsed_udp, udp_data, "UDP payload matches");
    };
}

fn test_rfc9484_connect_ip(t: core::T&) {
    t.run("ADDRESS_REQUEST & ADDRESS_ASSIGN Capsules") { sub =>
        // 1. Client creates Address Request
        var req = wing::IpAddressRequest {
            request_id: 1,
            ip_version: 4,
            prefix_len: 32,
            ..
        };
        req.requested_ip.append([10, 0, 0, 42]);

        var req_wire: u8[>..] = [];
        let req_enc_ok = wing::encode_address_request_capsule(req_wire, req);
        sub.assert_true(req_enc_ok, "encode_address_request_capsule ok");

        let c_req, c_req_ok = wing::parse_http_capsule(req_wire[..]);
        sub.assert_true(c_req_ok, "parse request capsule ok");
        sub.assert_eq(c_req.capsule_type, wing::CAPSULE_ADDRESS_REQUEST, "Type is ADDRESS_REQUEST (0x1F)");

        let dec_req, dec_req_ok = wing::decode_address_request_capsule(c_req.payload);
        sub.assert_true(dec_req_ok, "decode_address_request_capsule ok");
        sub.assert_eq(dec_req.request_id, 1, "Request ID matches (1)");
        sub.assert_eq(dec_req.ip_version, 4, "IPv4");
        sub.assert_eq(dec_req.prefix_len, 32, "Prefix len 32");
        sub.assert_bytes_eq(dec_req.requested_ip[..], [10, 0, 0, 42], "IP matches 10.0.0.42");

        // 2. Server creates Address Assign
        var assign = wing::IpAddressAssign {
            request_id: 1,
            ip_version: 4,
            prefix_len: 24,
            ..
        };
        assign.assigned_ip.append([192, 168, 1, 100]);

        var assign_wire: u8[>..] = [];
        let assign_enc_ok = wing::encode_address_assign_capsule(assign_wire, assign);
        sub.assert_true(assign_enc_ok, "encode_address_assign_capsule ok");

        let c_assign, c_assign_ok = wing::parse_http_capsule(assign_wire[..]);
        sub.assert_true(c_assign_ok, "parse assign capsule ok");
        sub.assert_eq(c_assign.capsule_type, wing::CAPSULE_ADDRESS_ASSIGN, "Type is ADDRESS_ASSIGN (0x1E)");

        let dec_assign, dec_assign_ok = wing::decode_address_assign_capsule(c_assign.payload);
        sub.assert_true(dec_assign_ok, "decode_address_assign_capsule ok");
        sub.assert_eq(dec_assign.request_id, 1, "Request ID matches (1)");
        sub.assert_eq(dec_assign.prefix_len, 24, "Prefix len 24");
        sub.assert_bytes_eq(dec_assign.assigned_ip[..], [192, 168, 1, 100], "Assigned IP matches 192.168.1.100");
    };

    t.run("ROUTE_ADVERTISEMENT Capsule") { sub =>
        var route = wing::RouteAdvertisement {
            ip_version: 4,
            prefix_len: 8,
            ..
        };
        route.ip_prefix.append([10, 0, 0, 0]);

        var route_wire: u8[>..] = [];
        let enc_ok = wing::encode_route_advertisement_capsule(route_wire, route);
        sub.assert_true(enc_ok, "encode_route_advertisement_capsule ok");

        let c, c_ok = wing::parse_http_capsule(route_wire[..]);
        sub.assert_true(c_ok, "parse route capsule ok");
        sub.assert_eq(c.capsule_type, wing::CAPSULE_ROUTE_ADVERTISEMENT, "Type is ROUTE_ADVERTISEMENT (0x20)");

        let dec_route, dec_route_ok = wing::decode_route_advertisement_capsule(c.payload);
        sub.assert_true(dec_route_ok, "decode_route_advertisement_capsule ok");
        sub.assert_eq(dec_route.ip_version, 4, "IPv4");
        sub.assert_eq(dec_route.prefix_len, 8, "Prefix len 8");
        sub.assert_bytes_eq(dec_route.ip_prefix[..], [10, 0, 0, 0], "Prefix 10.0.0.0/8 matches");
    };
}

fn test_masque_client_sessions_and_tunneling(t: core::T&) {
    t.run("CONNECT-UDP Handshake & End-to-End Tunneling via Client") { sub =>
        var client = wing::new_client();

        // Configure mock proxy accepting CONNECT-UDP
        wing::mock_route(client, "CONNECT", "https://proxy.privacy.org/.well-known/masque/udp/1.1.1.1/53/", 200, "");
        wing::add_mock_header(client, "Capsule-Protocol", "?1");

        // 1. Client connects via CONNECT-UDP
        let tunnel, resp, err = wing::connect_udp(client, "https://proxy.privacy.org", "1.1.1.1", 53, 4, false);
        sub.assert_true(wing::ok(err), "connect_udp handshake succeeded");
        sub.assert_eq(wing::status(resp), 200, "200 OK");
        sub.assert_true(tunnel.state == wing::MasqueTunnelState.Established, "Tunnel state is Established");

        // 2. Client sends UDP packet through tunnel (in-stream capsule mode via UFCS)
        var tunnel_mut = copy(tunnel);
        var wire_out: u8[>..] = [];
        let dns_query = "fake_dns_wire_query";
        let send_ok = tunnel_mut.send_packet(dns_query, wire_out);
        sub.assert_true(send_ok, "tunnel.send_packet UFCS succeeded");
        sub.assert_eq(tunnel_mut.packets_sent, 1, "1 packet sent recorded");
        sub.assert_eq(tunnel_mut.bytes_sent, dns_query.len as u64, "Bytes sent matches");

        // 3. Client receives UDP response packet from wire via UFCS
        var packet_in: u8[>..] = [];
        let recv_ok = tunnel_mut.receive_capsule(wire_out[..], packet_in);
        sub.assert_true(recv_ok, "tunnel.receive_capsule UFCS succeeded");
        sub.assert_bytes_eq(packet_in[..], dns_query, "Received packet content matches sent query");
        sub.assert_eq(tunnel_mut.packets_received, 1, "1 packet received recorded");
    };

    t.run("CONNECT-IP Handshake & Address Assignment via Client") { sub =>
        var client = wing::new_client();

        // Configure mock VPN gateway accepting CONNECT-IP
        wing::mock_route(client, "CONNECT", "https://vpn.corp.com/.well-known/masque/ip/", 200, "");
        wing::add_mock_header(client, "Capsule-Protocol", "?1");

        // 1. Client connects via CONNECT-IP
        let tunnel, resp, err = wing::connect_ip(client, "https://vpn.corp.com", 0, false);
        sub.assert_true(wing::ok(err), "connect_ip handshake succeeded");
        sub.assert_true(tunnel.state == wing::MasqueTunnelState.Established, "Tunnel is Established");

        // 2. Simulate server sending ADDRESS_ASSIGN capsule
        var tunnel_mut = copy(tunnel);
        var assign = wing::IpAddressAssign {
            request_id: 10,
            ip_version: 4,
            prefix_len: 24,
            ..
        };
        assign.assigned_ip.append([10, 8, 0, 5]);

        var assign_capsule_wire: u8[>..] = [];
        wing::encode_address_assign_capsule(assign_capsule_wire, assign);

        var dummy_pkt: u8[>..] = [];
        let recv_ok = wing::tunnel_receive_capsule(tunnel_mut, assign_capsule_wire[..], dummy_pkt);
        sub.assert_true(recv_ok, "ADDRESS_ASSIGN capsule ingested");
        sub.assert_bytes_eq(tunnel_mut.assigned_ip[..], [10, 8, 0, 5], "Tunnel assigned IP is 10.8.0.5");
        sub.assert_eq(tunnel_mut.assigned_prefix_len, 24, "Tunnel prefix length is /24");
    };

    t.run("Proxy Rejection (Missing Capsule-Protocol Header)") { sub =>
        var client = wing::new_client();

        // Mock proxy returning 200 OK without Capsule-Protocol: ?1
        wing::mock_route(client, "CONNECT", "https://bad-proxy.org/.well-known/masque/udp/8.8.8.8/53/", 200, "");

        let tunnel, resp, err = wing::connect_udp(client, "https://bad-proxy.org", "8.8.8.8", 53);
        sub.assert_false(wing::ok(err), "Failed due to missing Capsule-Protocol");
        sub.assert_eq(err.code, 502, "Error 502 Bad Gateway");
        sub.assert_true(tunnel.state == wing::MasqueTunnelState.Failed, "Tunnel state is Failed");
    };
}

fn main() {
    var runner = core::new_runner("MASQUE Protocol Suite (RFC 9297, 9298, 9484, 9221)", core::Verbosity.Verbose);
    core::run_case(runner, "1. RFC 9297 Capsules & HTTP Datagrams", test_rfc9297_capsules_and_datagrams);
    core::run_case(runner, "2. RFC 9298 MASQUE CONNECT-UDP", test_rfc9298_connect_udp);
    core::run_case(runner, "3. RFC 9484 MASQUE CONNECT-IP", test_rfc9484_connect_ip);
    core::run_case(runner, "4. MASQUE Client Sessions & Tunneling", test_masque_client_sessions_and_tunneling);
    let ok = core::finish(runner);
    assert(ok);
}
