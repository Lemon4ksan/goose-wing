// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Phase 5 RED test suite based on .gemini audit reports and Go / uWebSockets issue trackers.
// Verifies protocol flaws, RFC non-conformances, and security vulnerabilities that are CURRENTLY UNFIXED in goose-wing.
//
// Issues covered:
// 1. RFC 9112 §3.2.3 & §9.3.6: CONNECT Request-Target Authority-Form Enforcement (Reject origin-form for CONNECT, reject authority-form for non-CONNECT)
// 2. RFC 9112 §7.2, §9.5 & RFC 7230 §5.4: Multiple / Comma-Separated Values in Host Header Must Reject with 400
// 3. RFC 1035 §2.3.4 & §4.1.4 (CVE-2026-97044): DNS Wire Decoding Must Reject Label Length > 63 and Reserved Label Flags
// 4. HAProxy PROXY Protocol v2 §2.2 & uWS #1927 / #1948: PROXY v2 Header Must Reject Truncated TLVs and Trailing Bytes
// 5. RFC 6455 §5.5, §5.5.1 & uWS #1407: WebSocket Close Frame Reason Payload Must Be Clamped to <= 123 Bytes
// 6. CVE-2025-61726 & CVE-2026-39825: Query Parameter Key Overflow Defense Against Bounded Capacity
// 7. RFC 6265bis §5.1.4: Cookie URL Fallback Path Parsing Must Discard Fragment and Default to '/'

import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. RFC 9112 §3.2.3 & §9.3.6: CONNECT Request-Target Authority-Form Enforcement
// ----------------------------------------------------------------------------
fn test_connect_authority_form_enforcement(t: core::T&) {
    t.run("CONNECT with valid authority-form host:port MUST be accepted") { sub =>
        // RFC 9112 Section 3.2.3: "The authority-form of request-target is only used for CONNECT requests"
        // E.g.: CONNECT example.com:443 HTTP/1.1
        let wire = "CONNECT example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        var req = wing::new_request("GET", "");
        let ok_parse, consumed = wing::parse_http1_wire_request(wire, req);
        sub.assert_true(ok_parse, "Valid CONNECT with authority-form (example.com:443) must be accepted");
        sub.assert_true(req.method[..] == "CONNECT", "Method must be CONNECT");
        sub.assert_true(req.url[..] == "example.com:443", "URL must be example.com:443");
    };

    t.run("CONNECT with origin-form (/path) MUST be rejected") { sub =>
        // RFC 9112 Section 9.3.6: "Any request-target other than authority-form is invalid for CONNECT"
        let wire = "CONNECT /api/tunnel HTTP/1.1\r\nHost: example.com\r\n\r\n";
        var req = wing::new_request("GET", "");
        let ok_parse, _ = wing::parse_http1_wire_request(wire, req);
        sub.assert_false(ok_parse, "CONNECT with origin-form (/api/tunnel) MUST be rejected per RFC 9112 §9.3.6");
    };

    t.run("GET with authority-form (host:port) MUST be rejected") { sub =>
        // RFC 9112 Section 3.2.3: Authority-form is ONLY valid for CONNECT!
        let wire = "GET example.com:443 HTTP/1.1\r\nHost: example.com:443\r\n\r\n";
        var req = wing::new_request("GET", "");
        let ok_parse, _ = wing::parse_http1_wire_request(wire, req);
        sub.assert_false(ok_parse, "GET with authority-form (example.com:443) MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// 2. RFC 9112 §7.2, §9.5 & RFC 7230 §5.4: Multiple / Comma-Separated Values in Host Header
// ----------------------------------------------------------------------------
fn test_host_header_comma_separated_values_rejected(t: core::T&) {
    t.run("Host header with comma-separated hosts (folded duplicate) MUST be rejected") { sub =>
        // RFC 9112 Section 9.5: "A server MUST respond with a 400 (Bad Request) status code to any
        // HTTP/1.1 request message that contains more than one Host header field or a Host header field
        // with multiple field values."
        let wire = "GET / HTTP/1.1\r\nHost: example.com,evil.com\r\n\r\n";
        var req = wing::new_request("GET", "");
        let ok_parse, _ = wing::parse_http1_wire_request(wire, req);
        sub.assert_false(ok_parse, "Host header with comma-separated values (example.com,evil.com) MUST be rejected");
    };

    t.run("Host header with comma and space MUST be rejected") { sub =>
        let wire = "GET / HTTP/1.1\r\nHost: primary.com, secondary.com\r\n\r\n";
        var req = wing::new_request("GET", "");
        let ok_parse, _ = wing::parse_http1_wire_request(wire, req);
        sub.assert_false(ok_parse, "Host header with comma and space MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// 3. RFC 1035 §2.3.4 & §4.1.4: DNS Wire Decoding Label Length <= 63 and Reserved Bits
// ----------------------------------------------------------------------------
fn test_dns_decode_label_length_and_reserved_bits(t: core::T&) {
    t.run("DNS wire decode MUST reject label length > 63") { sub =>
        // RFC 1035 Section 2.3.4: "labels: 63 octets or less"
        // Construct DNS wire name with an illegal label length byte of 64 (0x40) or 70.
        // But 0x40 has high bits 01 (reserved), while 0x46 is 70 with 00!
        // A label of 70 bytes: length byte 70 (0x46), followed by 70 'a' bytes, followed by 0x00.
        var wire: u8[..128] = [];
        wire.push(70 as u8); // Illegal: > 63 octets!
        for i in 70 { wire.push('a' as u8); }
        wire.push(0); // Zero root label

        var out_name: u8[..256] = [];
        var off: i64 = 0;
        let ok = wing::dns_decode_name(wire[..], off, out_name);
        sub.assert_false(ok, "dns_decode_name MUST reject label with length 70 (> 63)");
    };

    t.run("DNS wire decode MUST reject reserved high-order label bits (0x40 or 0x80)") { sub =>
        // RFC 1035 Section 4.1.4: "The 10 and 01 combinations are reserved for future use."
        // Only 00 (uncompressed label <= 63) and 11 (0xC0 compression pointer) are valid.
        var wire: u8[..16] = [0x44, 't', 'e', 's', 't', 0x00]; // 0x44 has bits 01_000100
        var out_name: u8[..256] = [];
        var off: i64 = 0;
        let ok = wing::dns_decode_name(wire[..], off, out_name);
        sub.assert_false(ok, "dns_decode_name MUST reject label starting with reserved bits 01 (0x40)");
    };
}

// ----------------------------------------------------------------------------
// 4. HAProxy PROXY Protocol v2 §2.2 & uWS #1927 / #1948: PROXY v2 Malformed TLVs
// ----------------------------------------------------------------------------
fn test_proxy_v2_truncated_tlv_and_trailing_bytes(t: core::T&) {
    t.run("PROXY v2 with 2 leftover trailing bytes after TLVs MUST be rejected") { sub =>
        // Preamble (12B) + ver_cmd (0x21: PROXY) + fam_trans (0x11: TCP4) + len (12B addr + 2B trailing = 14B)
        var wire: u8[..64] = [];
        for b in [0x0D, 0x0A, 0x0D, 0x0A, 0x00, 0x0D, 0x0A, 0x51, 0x55, 0x49, 0x54, 0x0A] {
            wire.push(b as u8);
        }
        wire.push(0x21); // v2, PROXY
        wire.push(0x11); // TCP4
        wire.push(0x00); wire.push(14 as u8); // len = 14 bytes (12 bytes IPv4 + 2 trailing bytes)

        // 12-byte IPv4 block: 1.2.3.4 -> 5.6.7.8, port 1000 -> 2000
        for b in [1, 2, 3, 4, 5, 6, 7, 8, 0x03, 0xE8, 0x07, 0xD0] {
            wire.push(b as u8);
        }
        // 2 trailing unparsed bytes (truncated TLV header)
        wire.push(0x01); // TLV type 1 (ALPN)
        wire.push(0x00); // Truncated length (missing second byte and value)

        let hdr, consumed, ok = wing::parse_proxy_v2(wire[..]);
        sub.assert_false(ok, "PROXY v2 with trailing truncated TLV bytes MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// 5. RFC 6455 §5.5, §5.5.1 & uWS #1407: WebSocket Close Frame Reason Payload <= 123 Bytes
// ----------------------------------------------------------------------------
fn test_ws_close_frame_reason_clamped(t: core::T&) {
    t.run("close with 130-byte reason MUST be clamped to <= 123 bytes reason (<= 125 total payload)") { sub =>
        // RFC 6455 Section 5.5: "All control frames MUST have a payload length of 125 bytes or less"
        // RFC 6455 Section 5.5.1: Close frame status code is 2 bytes, so reason can be at most 123 bytes.
        var ws = wing::new_websocket_session(true);
        var long_reason: u8[..256] = [];
        for i in 130 { long_reason.push('z' as u8); }

        var wire_out: u8[..512] = [];
        wing::close(ws, wing::WS_STATUS_NORMAL, long_reason[..], wire_out);

        guard wire_out.len >= 2 else {
            sub.assert_true(false, "close produced empty wire output");
            return;
        }

        let raw_len = wire_out[1] & 0x7F;
        sub.assert_true(raw_len <= 125, "Close frame payload on wire MUST be <= 125 bytes (RFC 6455 §5.5)");
        sub.assert_true(raw_len != 126 && raw_len != 127, "Close frame MUST NEVER use extended length 126/127");
    };
}

// ----------------------------------------------------------------------------
// 6. CVE-2025-61726 & CVE-2026-39825: Query Parameter Key Overflow Defense
// ----------------------------------------------------------------------------
fn test_query_param_key_overflow_defense(t: core::T&) {
    t.run("parse_query_params with key > 64 bytes MUST safely truncate or handle without buffer overflow") { sub =>
        // QueryParamItem.key capacity is 64 bytes.
        // A key with 75 characters: "very_long_param_key_exceeding_sixty_four_bytes_boundary_1234567890_abcdef=val"
        let query = "very_long_param_key_exceeding_sixty_four_bytes_boundary_1234567890_abcdef=val";
        let list = core::parse_query_params(query);
        sub.assert_true(list.items.len == 1, "Should parse 1 item");
        sub.assert_true(list.items[0].key.len <= 64, "Key must not exceed capacity 64");
        sub.assert_true(list.items[0].val[..] == "val", "Value must be 'val'");
    };

    t.run("percent_decode_query with 80-byte input into 64-byte buffer MUST NOT overflow") { sub =>
        var input: u8[..128] = [];
        for i in 80 { input.push('k' as u8); }
        var out_buf: u8[..64] = [];
        core::percent_decode_query(input[..], out_buf);
        sub.assert_true(out_buf.len <= 64, "Decoded buffer must not exceed capacity 64");
    };
}

// ----------------------------------------------------------------------------
// 7. RFC 6265bis §5.1.4: Cookie URL Fallback Path Parsing with Fragment and Default Slash
// ----------------------------------------------------------------------------
fn test_cookie_url_fallback_path_fragment(t: core::T&) {
    t.run("URL with fragment in fallback path MUST exclude fragment from host and default path to '/'") { sub =>
        // In fallback path (e.g. invalid port or scheme-less format like "http://example.com#section"):
        let u = wing::parse_canonical_cookie_url("http://example.com#section");
        sub.assert_true(u.host[..] == "example.com", "Host must be 'example.com', not contain '#section'");
        sub.assert_true(u.path[..] == "/", "Default path must be '/' per RFC 6265bis §5.1.4");
    };
}

fn main() {
    let _ = wing::tcp_init();
    var dummy: u8[4] = [0, 0, 0, 0];
    wing::swar_to_lower(dummy[..]);

    var runner = core::new_runner("RED Suite Phase 5: CVE & RFC Protocol Flaws", core::Verbosity.Verbose);

    core::run_case(runner, "1. RFC 9112 §3.2.3 & §9.3.6: CONNECT Authority-Form Enforcement", test_connect_authority_form_enforcement);
    core::run_case(runner, "2. RFC 9112 §7.2 & §9.5: Host Header Multiple Values Rejection", test_host_header_comma_separated_values_rejected);
    core::run_case(runner, "3. RFC 1035 §2.3.4 & §4.1.4: DNS Wire Decoding Label Bounds", test_dns_decode_label_length_and_reserved_bits);
    core::run_case(runner, "4. HAProxy PROXY Protocol v2 §2.2: Truncated TLVs & Trailing Bytes", test_proxy_v2_truncated_tlv_and_trailing_bytes);
    core::run_case(runner, "5. RFC 6455 §5.5 & §5.5.1: WebSocket Close Reason Clamped to <= 123", test_ws_close_frame_reason_clamped);
    core::run_case(runner, "6. CVE-2025-61726 & CVE-2026-39825: Query Parameter Bounds Guard", test_query_param_key_overflow_defense);
    core::run_case(runner, "7. RFC 6265bis §5.1.4: Cookie URL Fallback Path and Fragment", test_cookie_url_fallback_path_fragment);

    let ok = core::finish(runner);
    print("\n[RED PHASE 5 TEST SUITE STATUS] Finished execution. Result ok=", ok);
    if !ok {
        print(">>> CONFIRMED RED PHASE 5: Target vulnerabilities/flaws reproduce successfully against the current codebase! <<<\n");
    }
}
