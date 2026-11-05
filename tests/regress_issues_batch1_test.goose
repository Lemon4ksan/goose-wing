// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Issue Regression Suite Batch 1 (Phases 1-5)
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// Issues covered:
//   1. Go #78948 (CVE-2026-39825): Query parameter count truncation & smuggling in parse_query_params.
//   2. Go #82350: Preserving stale Request.Host across cross-origin / scheme-relative redirects.
//   3. Go #82343: RFC 2231 extended boundary parameter (boundary*=) and boundary validation in MediaType.
//   4. Go #78760 (CVE-2026-39821): Pure ASCII Punycode label in URL host rejection (http://xn--test-.com/).
//   5. uWebSockets #1949 / RFC 9112 §3.2: Host header containing query or fragment rejection in wire parser.
//   6. Go #77108 (CVE-2025-61726): Query parameter length DoS protection in validate_query_param_count.

// ----------------------------------------------------------------------------
// 1. Go #78948 / CVE-2026-39825: Query Parameter Truncation & Smuggling
// ----------------------------------------------------------------------------
fn test_query_param_truncation_smuggling(t: lit::T&) {
    t.run("Parameters exceeding 32 must not be silently dropped without indication") { sub =>
        // Ensure wing native symbols are linked
        var dummy: u8[..4] = "test";
        wing::swar_to_lower(dummy[..]);

        // Construct a query string with 35 parameters where the 33rd parameter is a security-sensitive flag.
        // In fixed-capacity parsers (capacity = 32), parameters beyond 32 are silently ignored.
        // Downstream backends parsing up to 1024 parameters see admin=true, but the proxy/WAF does not!
        var raw_query: u8[..1024] = "?";
        for i in 32 {
            raw_query.append("p");
            var num_buf: u8[..8] = [];
            format(num_buf, i);
            raw_query.append(num_buf[..]);
            raw_query.append("=val&");
        }
        raw_query.append("admin=true&role=superuser&access=full");

        let q = core::parse_query_params(raw_query[..]);

        // A secure parser must either:
        // (a) successfully parse parameters beyond 32, OR
        // (b) report/fail on truncated queries so hidden parameters cannot be smuggled.
        sub.assert_true(core::has_query_param(q, "admin"), "Critical parameter 'admin' after 32nd item must NOT be silently lost");
        sub.assert_bytes_eq(core::get_query_param(q, "admin"), "true", "Parameter 'admin' must have value 'true'");
    };
}

// ----------------------------------------------------------------------------
// 2. Go #82350: Host Header Leakage Across Cross-Origin Redirects
// ----------------------------------------------------------------------------
fn test_redirect_stale_host_header_leakage(t: lit::T&) {
    t.run("Outbound Host header must not be retained on cross-origin redirect") { sub =>
        // When a request has an explicit custom Host header, redirecting to a different origin
        // MUST strip or update the Host header to match the new destination authority (Go #82350).
        var headers = wing::HeaderMap { .. };
        wing::append_header(headers, "Host", "internal-vault.corp.local");
        wing::append_header(headers, "X-Custom", "keep");

        let origin_target = core::new_url("https://evil-phishing.com/harvest");

        var rinfo = wing::RedirectInfo {
            status_code:         302,
            new_url:             origin_target,
            is_cross_origin:     true,
            is_scheme_downgrade: false,
            is_port_changed:     false,
            clear_body:          true,
            new_referrer:        [],
        };

        wing::sanitize_headers_on_redirect(headers, rinfo, wing::RedirectSanitizeOptions { .. });

        // Host header pointing to the previous host MUST be stripped to prevent host header injection / routing desync
        let host_idx = wing::find_header_index(headers, "Host");
        sub.assert_true(host_idx < 0, "Stale Host header from source origin must be stripped on cross-origin redirect (Go #82350)");
    };
}

// ----------------------------------------------------------------------------
// 3. Go #82343: RFC 2231 Extended Multipart Boundary & Boundary Validation
// ----------------------------------------------------------------------------
fn test_multipart_boundary_rfc2231_and_validation(t: lit::T&) {
    t.run("boundary* extended parameter must be rejected or not override boundary (Go #82343)") { sub =>
        // In RFC 2231 / Go #82343: Content-Type with boundary*=utf-8''injected%0D%0A
        // An intermediary WAF sees boundary=normal, but a server honoring boundary* parses injected parts.
        // RFC 7578 / RFC 2046 strictly restricts boundary characters (1..70 bchars, no CRLF).
        let ct_header = "multipart/form-data; boundary=safe_boundary; boundary*=utf-8''injected_boundary";
        let mt, ok = wing::parse_media_type(ct_header);
        sub.assert_true(ok);

        let chosen_boundary = wing::param(mt, "boundary");
        sub.assert_bytes_eq(chosen_boundary, "safe_boundary", "RFC 2231 boundary* must NOT override plain boundary parameter");
        sub.assert_false(wing::has_param(mt, "boundary*"), "boundary* extended notation should not be accepted as a valid parameter");
    };

    t.run("Boundary containing CRLF or invalid characters must fail parse_media_type") { sub =>
        // Boundary with CRLF or control characters is a request smuggling vector
        let ct_crlf = "multipart/form-data; boundary=bad\r\nboundary";
        let _, ok1 = wing::parse_media_type(ct_crlf);
        sub.assert_false(ok1, "Media type with CRLF in boundary value must be rejected");

        // Boundary with raw quotes or invalid punctuation
        let ct_invalid_chars = "multipart/form-data; boundary=bad@boundary#123";
        let mt2, ok2 = wing::parse_media_type(ct_invalid_chars);
        let b2 = wing::param(mt2, "boundary");
        // Boundary chars must conform to RFC 2046 bchars
        sub.assert_false(wing::validate_boundary_string(b2), "RFC 2046 rejects '@' and '#' in boundary tokens");
    };
}

// ----------------------------------------------------------------------------
// 4. Go #78760 / CVE-2026-39821: Pure ASCII Punycode URL Host Rejection
// ----------------------------------------------------------------------------
fn test_pure_ascii_punycode_url_host_rejection(t: lit::T&) {
    t.run("URL with pure ASCII Punycode host xn--test-.com must be rejected (Go #78760)") { sub =>
        // Punycode label "xn--test-" contains no non-ASCII delta.
        // Per UTS 46 Revision 33 & Go #78760, accepting pure ASCII Punycode allows domain validation bypasses.
        let u = core::new_url("http://xn--test-.com/api");
        sub.assert_false(u.valid, "URL with pure ASCII Punycode host xn--test-.com MUST be marked invalid");
    };
}

// ----------------------------------------------------------------------------
// 5. uWebSockets #1949 / RFC 9112 §3.2: Host Header Query or Fragment Rejection in HTTP/1.0
// ----------------------------------------------------------------------------
fn test_host_header_query_fragment_rejection(t: lit::T&) {
    t.run("HTTP/1.0 request with query in Host header must be rejected") { sub =>
        // RFC 9112 §3.2 & uWebSockets #1949: If a Host header is provided, the authority
        // MUST NOT contain query '?' or fragment '#', even if protocol is HTTP/1.0.
        // Currently, server/server.goose:169 guards Host character checks with:
        //   if proto_slice == "HTTP/1.1" { ... }
        // which leaves HTTP/1.0 vulnerable to host authority injection!
        var req = wing::new_request("GET", "/api");
        let wire: const u8[:] = "GET /api HTTP/1.0\r\nHost: example.com?foo=bar\r\n\r\n";
        let ok, _ = wing::parse_http1_wire_request(wire, req);
        sub.assert_false(ok, "Host header with query '?' in HTTP/1.0 must be rejected per RFC 9112 §3.2 and uWS #1949");
    };

    t.run("HTTP/1.0 request with fragment in Host header must be rejected") { sub =>
        var req = wing::new_request("GET", "/api");
        let wire: const u8[:] = "GET /api HTTP/1.0\r\nHost: example.com#fragment\r\n\r\n";
        let ok, _ = wing::parse_http1_wire_request(wire, req);
        sub.assert_false(ok, "Host header with fragment '#' in HTTP/1.0 must be rejected per RFC 9112 §3.2 and uWS #1949");
    };
}

// ----------------------------------------------------------------------------
// 6. Go #77108 / CVE-2025-61726: Query Parameter DoS Guard Against Oversized Tokens
// ----------------------------------------------------------------------------
fn test_query_param_oversized_token_dos_guard(t: lit::T&) {
    t.run("validate_query_param_count must reject query strings with tokens > 256 bytes") { sub =>
        // To prevent fixed-capacity array crashes in parse_query_params (u8[..256] cap),
        // query validation before parsing MUST check individual parameter lengths (Go #77108).
        // A single 300-byte token in query string without & passes validate_query_param_count(query, 1024),
        // but crashes the server parser if length checks are missing!
        var raw_query: u8[..600] = "?token=";
        for i in 300 {
            raw_query.push('A');
        }

        // The query validator should detect that an individual token exceeds the maximum safe parameter buffer (256 bytes)
        let is_valid = core::validate_query_param_count(raw_query[..], 1024);
        sub.assert_false(is_valid, "validate_query_param_count must reject oversized tokens > 256 bytes to prevent parser array abort");
    };
}

// --- Component: regress_issues_batch02 ---
// Phase 2 RED test suite based on .gemini audit reports and Go / uWebSockets issue trackers.
// Verifies protocol flaws, RFC non-conformances, and security bypasses that are CURRENTLY UNFIXED in goose-wing.
//
// Issues covered:
// 1. RFC 9110 §8.6 & Go #81642 / uWS #1370: Status 204 No Content Body Leakage (HTTP Smuggling)
// 2. Go #78172 & RFC 3986 §3.2.2 / RFC 9112 §3.2: Malformed IP-Literal Host Header Acceptance
// 3. Go #80282 & RFC 3986 §5.2.4: Deep Path Dot-Segment Collapse Truncation Bug
// 4. RFC 9110 §7.6.1 & Go #82065: Connection Header Hop-by-Hop 16-Token Truncation Leak
// 5. RFC 9449 §4.3: DPoP Proof URI Substring Prefix Collision Bypass
// 6. Go #62235 & RFC 6874 §2: Scoped IPv6 Link-Local URL Zone ID %25 Acceptance

// ----------------------------------------------------------------------------
// 1. RFC 9110 §8.6 / uWS #1370 / Go #81642: Status 204/304 Body Leakage on Wire
// ----------------------------------------------------------------------------
fn test_status_204_body_suppression_on_wire(t: lit::T&) {
    t.run("Status 204 No Content must not serialize message body to wire") { sub =>
        // RFC 9110 Section 8.6 & Section 6.4.1:
        // A 204 (No Content) response MUST NOT include a message body.
        // In server/server.goose:540, serialize_http1_response appends res.body[..]
        // directly to the wire when body.len > 0, despite status 204 omitting Content-Length.
        // This causes HTTP response splitting / smuggling on persistent connections!
        var res = wing::Response { .. };
        res.status_code = 204;
        res.body.append("LEAKED_PAYLOAD_SMUGGLING");

        var wire_out: u8[..1024] = [];
        wing::serialize_http1_response(res, "GooseWing", wire_out);

        let has_body = find(wire_out[..], "LEAKED_PAYLOAD_SMUGGLING") >= 0;
        sub.assert_false(has_body, "Status 204 response MUST NOT emit message body to wire per RFC 9110 §8.6");
    };
}

// ----------------------------------------------------------------------------
// 2. Go #78172 & RFC 3986 §3.2.2 / RFC 9112 §3.2: Malformed IP-Literal Host
// ----------------------------------------------------------------------------
fn test_malformed_ip_literal_host_rejection(t: lit::T&) {
    t.run("Empty IP-literal Host '[]' must be rejected with 400 Bad Request") { sub =>
        // RFC 9112 §3.2 & RFC 3986 §3.2.2: Host header with empty brackets "[]"
        // is structurally invalid and must be rejected by the server parser.
        var req = wing::new_request("GET", "/");
        let wire: const u8[:] = "GET / HTTP/1.1\r\nHost: []\r\n\r\n";
        let ok, _ = wing::parse_http1_wire_request(wire, req);
        sub.assert_false(ok, "Host: [] must be rejected per RFC 3986 §3.2.2 and Go #78172");
    };

    t.run("Unclosed bracket IP-literal Host '[::1' must be rejected") { sub =>
        var req = wing::new_request("GET", "/");
        let wire: const u8[:] = "GET / HTTP/1.1\r\nHost: [::1\r\n\r\n";
        let ok, _ = wing::parse_http1_wire_request(wire, req);
        sub.assert_false(ok, "Host: [::1 must be rejected per RFC 3986 §3.2.2 and Go #78172");
    };

    t.run("Invalid IP-literal characters '[invalid_host]' must be rejected") { sub =>
        var req = wing::new_request("GET", "/");
        let wire: const u8[:] = "GET / HTTP/1.1\r\nHost: [invalid_host]\r\n\r\n";
        let ok, _ = wing::parse_http1_wire_request(wire, req);
        sub.assert_false(ok, "Host: [invalid_host] must be rejected per RFC 3986 §3.2.2 and Go #78172");
    };
}

// ----------------------------------------------------------------------------
// 3. Go #80282 & RFC 3986 §5.2.4: Deep Path Dot-Segment Collapse Truncation
// ----------------------------------------------------------------------------
fn test_deep_path_dot_segment_collapse(t: lit::T&) {
    t.run("Paths deeper than 64 segments must correctly pop with '..'") { sub =>
        // In core/url/parser.goose:925, seg_starts has fixed capacity 64:
        //   var seg_starts: i32[..64] = [];
        // When normalizing a path with 65 segments followed by '/leaf/..',
        // segment 65 cannot be pushed to seg_starts. A subsequent '..' pops
        // to seg_starts[63], obliterating segments 64 and 65 entirely!
        var raw_url: u8[..2000] = "http://example.com";
        for i in 65 {
            raw_url.append("/d");
        }
        raw_url.append("/leaf/..");

        let u = core::new_url(raw_url[..]);
        let p = core::pathname(u);

        // Per RFC 3986 §5.2.4, /leaf/.. must pop only /leaf, preserving all 65 /d segments.
        // It must end with "/d/" (dot-segment pop retains directory context) and retain all 65 segments.
        sub.assert_true(core::ends_with(p, "/d/"), "Deep path with >64 segments must preserve segment 65 after '..' pop");
        sub.assert_eq(p.len, 131, "Path must retain all 65 segments (131 bytes)");
    };
}

// ----------------------------------------------------------------------------
// 4. RFC 9110 §7.6.1 & Go #82065: Connection Header 16-Token Truncation Leak
// ----------------------------------------------------------------------------
fn test_connection_header_hop_by_hop_token_capacity(t: lit::T&) {
    t.run("Custom hop-by-hop headers past index 16 must not leak across intermediary") { sub =>
        // In http/headers.goose:1455 (collect_connection_tokens), out_tokens has cap 16:
        //   out_tokens: u8[..64][..16]&
        // If a Connection header specifies > 16 tokens (e.g. h1..h17), the 17th token
        // is silently dropped, causing strip_hop_by_hop_headers to retain 'h17'!
        var src = wing::HeaderMap { .. };
        wing::append_header(src, "Connection", "h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17");
        wing::append_header(src, "h17", "confidential-token");

        var dst = wing::HeaderMap { .. };
        wing::strip_hop_by_hop_headers(src, dst);

        sub.assert_false(wing::has_header(dst, "h17"), "Hop-by-hop header h17 must be stripped per RFC 9110 §7.6.1");
    };
}

// ----------------------------------------------------------------------------
// 5. RFC 9449 §4.3: DPoP Proof URI Substring Prefix Collision Bypass
// ----------------------------------------------------------------------------
fn test_dpop_proof_uri_prefix_collision(t: lit::T&) {
    t.run("DPoP proof minted for subpath must not authorize parent URI via substring match") { sub =>
        // RFC 9449 §4.3: The 'htu' claim MUST match the target URI exactly after normalization.
        // In auth/dpop.goose:261, verify_dpop_uri uses core::contains(claims_json, norm_expected_uri),
        // allowing a proof minted for 'https://example.com/user-restricted' or 'https://example.com/user.evil.com'
        // to authenticate requests to 'https://example.com/user'!
        let claims_with_extended_path: const u8[:] = "{\"htu\":\"https://example.com/user-restricted\",\"htm\":\"GET\"}";
        let valid = wing::verify_dpop_uri(claims_with_extended_path, "https://example.com/user");
        sub.assert_false(valid, "DPoP verify_dpop_uri must reject URI prefix mismatch (RFC 9449 §4.3)");
    };

    t.run("DPoP proof with query string in 'htu' must be rejected") { sub =>
        // RFC 9449 Section 4.3:
        // "The htu claim MUST NOT contain a query or fragment. If present, the proof MUST be rejected."
        let claims_with_query: const u8[:] = "{\"htu\":\"https://example.com/user?leak=1\",\"htm\":\"GET\"}";
        let valid = wing::verify_dpop_uri(claims_with_query, "https://example.com/user");
        sub.assert_false(valid, "DPoP proof with query in 'htu' must be rejected per RFC 9449 §4.3");
    };
}

// ----------------------------------------------------------------------------
// 6. Go #62235 & RFC 6874 §2: Scoped IPv6 Link-Local URL Zone ID %25 Acceptance
// ----------------------------------------------------------------------------
fn test_scoped_ipv6_link_local_url_acceptance(t: lit::T&) {
    t.run("URL with RFC 6874 percent-encoded Zone ID [fe80::1%25eth0] must be valid") { sub =>
        // RFC 6874 Section 2:
        //   IP-literal = "[" IPv6address "%25" ZoneID "]"
        // A link-local scoped IPv6 literal with percent-encoded '%25' zone ID is standard
        // per RFC 6874 and WHATWG URL standard.
        // In core/url/parser.goose, parse_and_compress_ipv6 rejects any '%' token,
        // causing valid scoped link-local URLs to be marked invalid!
        let u = core::new_url("http://[fe80::1%25eth0]:8080/api");
        sub.assert_true(u.valid, "Scoped IPv6 URL with %25 Zone ID must be valid per RFC 6874 §2 and Go #62235");
    };
}

// --- Component: regress_issues_batch03 ---
// Phase 3 regression test suite based on .gemini audit reports and Go / uWebSockets issue trackers.
//
// Issues covered:
// 1. Go #81508 & RFC 9110 §14.1.2: Unsupported Range Unit Must Return 200 OK (Not 416)
// 2. Go #21096 & RFC 9110 §7.6.1 / RFC 9113: Forwarding 'TE: trailers' for gRPC (Not Stripped)
// 3. RFC 6455 §8.1 / §7.4.1 / Autobahn 6.4.1: Close Frame with Invalid UTF-8 Must Fail with 1007 (Not 1002)
// 4. RFC 7692 §5.1 / uWS #1164: RSV1 Set on WebSocket Continuation Frame Must Fail with 1002
// 5. Go #76635 & RFC 6455 §4.1: Empty Path in WebSocket Handshake Must Default to '/'
// 6. Go #78569 & CVE-2026-25679 follow-up: parse_url_view Trailing Garbage on IPv6 Brackets [::1]evil.com
// 7. RFC 9112 Section 4: Status Line - HTTP Wire Response Status Line Whitespace & 4-Digit Smuggling (uWS #1949)

// ----------------------------------------------------------------------------
// 1. Go #81508 & RFC 9110 §14.1.2: Unsupported Range Unit Must Return 200 OK
// ----------------------------------------------------------------------------
fn test_unsupported_range_unit_ignored(t: lit::T&) {
    t.run("Unrecognized Range unit (e.g. items=0-10) must be ignored and return 200 OK") { sub =>
        var out_status: i32 = 0;
        var out_headers = wing::HeaderMap { .. };
        var out_body: u8[>..] = [];

        let payload: const u8[:] = "Hello World Range Test";
        let mod_time = core::unix(1700000000);

        wing::serve_range_request(
            "items=0-10",
            "",
            "\"etag123\"",
            mod_time,
            payload.len as i64,
            "text/plain",
            out_status,
            out_headers,
            out_body,
        ) { start, len, buf =>
            buf.append(payload[start..(start + len)]);
        };

        sub.assert_eq(out_status, 200, "Unrecognized Range unit must be ignored and return 200 OK (Go #81508 / RFC 9110 §14.1.2)");
        sub.assert_bytes_eq(out_body[..], payload, "Must return complete representation when Range unit is ignored");
    };
}

// ----------------------------------------------------------------------------
// 2. Go #21096 & RFC 9110 §7.6.1 / RFC 9113: Forwarding 'TE: trailers' for gRPC
// ----------------------------------------------------------------------------
fn test_grpc_te_trailers_preserved(t: lit::T&) {
    t.run("TE: trailers header must NOT be stripped by strip_hop_by_hop_headers") { sub =>
        var src = wing::HeaderMap { .. };
        wing::append_header(src, "TE", "trailers");
        wing::append_header(src, "Connection", "keep-alive");
        wing::append_header(src, "X-Custom", "preserve-me");

        var dst = wing::HeaderMap { .. };
        wing::strip_hop_by_hop_headers(src, dst);

        sub.assert_true(wing::has_header(dst, "TE"), "TE: trailers must be preserved across proxies for gRPC (Go #21096)");
        let te_val = wing::get_header(dst, "TE");
        sub.assert_bytes_eq(te_val, "trailers", "TE value must remain 'trailers'");
        sub.assert_false(wing::has_header(dst, "Connection"), "Connection header must be stripped");
        sub.assert_true(wing::has_header(dst, "X-Custom"), "Regular headers must be retained");
    };

    t.run("TE with non-trailers (e.g. TE: gzip, deflate) must be stripped") { sub =>
        var src = wing::HeaderMap { .. };
        wing::append_header(src, "TE", "gzip, deflate");
        wing::append_header(src, "X-Custom", "keep");

        var dst = wing::HeaderMap { .. };
        wing::strip_hop_by_hop_headers(src, dst);

        sub.assert_false(wing::has_header(dst, "TE"), "TE without 'trailers' must be stripped as hop-by-hop");
    };
}

// ----------------------------------------------------------------------------
// 3. RFC 6455 §8.1 / §7.4.1 / Autobahn 6.4.1: Close Frame Invalid UTF-8 (1007)
// ----------------------------------------------------------------------------
fn test_close_frame_invalid_utf8_status_1007(t: lit::T&) {
    t.run("Close frame with invalid UTF-8 payload must fail with 1007 (not 1002)") { sub =>
        var ws = wing::new_websocket_session(false);

        var wire: u8[..64] = [];
        wire.push(0x88); // FIN=1, Opcode=8 (Close)
        wire.push(0x84); // Masked=1, Len=4
        wire.push(0x00); wire.push(0x00); wire.push(0x00); wire.push(0x00);
        wire.push(0x03); wire.push(0xE8); // Status code 1000
        wire.push(0xFF); wire.push(0xFF); // Invalid UTF-8 bytes

        var out_view = wing::WsMessageView { .. };
        var out_reply: u8[..256] = [];

        let handled = wing::receive_view(ws, wire[..], out_view, out_reply);
        sub.assert_true(handled, "Receive handled incoming invalid UTF-8 close frame");
        sub.assert_true(ws.is_closed, "Connection closed on invalid UTF-8");
        sub.assert_eq(ws.close_code, rfc::WS_STATUS_INVALID_PAYLOAD, "Close status code MUST be 1007 (Invalid Payload), NOT 1002");
    };
}

// ----------------------------------------------------------------------------
// 4. RFC 7692 §5.1 / uWS #1164: RSV1 Set on Continuation Frame Must Fail (1002)
// ----------------------------------------------------------------------------
fn test_continuation_rsv1_rejected(t: lit::T&) {
    t.run("Continuation frame with RSV1 set must be rejected with protocol error 1002") { sub =>
        var ws = wing::new_websocket_session(false);
        wing::enable_permessage_deflate(ws);

        var f1: u8[..64] = [];
        f1.push(0x41); // FIN=0, RSV1=1, Opcode=1 (Text)
        f1.push(0x84); // Masked=1, Len=4
        f1.push(0x00); f1.push(0x00); f1.push(0x00); f1.push(0x00);
        f1.append("test");

        var out_view = wing::WsMessageView { .. };
        var out_reply: u8[..256] = [];
        let ok1 = wing::receive_view(ws, f1[..], out_view, out_reply);
        sub.assert_true(ok1, "First fragment accepted");
        sub.assert_false(ws.is_closed, "WS still open after fragment 1");

        var f2: u8[..64] = [];
        f2.push(0xC0); // FIN=1, RSV1=1, Opcode=0 (Continuation with RSV1!)
        f2.push(0x84); // Masked=1, Len=4
        f2.push(0x00); f2.push(0x00); f2.push(0x00); f2.push(0x00);
        f2.append("data");

        let ok2 = wing::receive_view(ws, f2[..], out_view, out_reply);
        sub.assert_true(ok2, "Frame 2 processed");
        sub.assert_true(ws.is_closed, "WebSocket connection MUST be closed on continuation frame with RSV1 set");
        sub.assert_eq(ws.close_code, rfc::WS_STATUS_PROTOCOL_ERROR, "Close code MUST be 1002 (Protocol Error)");
    };
}

// ----------------------------------------------------------------------------
// 5. Go #76635 & RFC 6455 §4.1: Empty Path in WebSocket Handshake Must Default to '/'
// ----------------------------------------------------------------------------
fn test_ws_handshake_empty_path_defaults_to_slash(t: lit::T&) {
    t.run("build_handshake_request with empty path must serialize 'GET / HTTP/1.1'") { sub =>
        var ws = wing::new_websocket_session(true);
        var wire_out: u8[..512] = [];

        wing::build_handshake_request(ws, "example.com", "", "dGhlIHNhbXBsZSBub25jZQ==", wire_out);

        let has_double_space = find(wire_out[..], "GET  HTTP/1.1") >= 0;
        sub.assert_false(has_double_space, "Must NOT format malformed 'GET  HTTP/1.1' with double space");

        let starts_with_get_slash = core::starts_with(wire_out[..], "GET / HTTP/1.1\r\n");
        sub.assert_true(starts_with_get_slash, "Empty path MUST serialize as 'GET / HTTP/1.1\r\n' (Go #76635 / RFC 6455 §4.1)");
    };
}

// ----------------------------------------------------------------------------
// 6. Go #78569 & CVE-2026-25679 follow-up: parse_url_view Trailing Garbage on IPv6 Brackets
// ----------------------------------------------------------------------------
fn test_parse_url_view_ipv6_bracket_trailing_garbage(t: lit::T&) {
    t.run("parse_url_view must reject trailing host garbage after closing bracket [::1]evil.com") { sub =>
        let view, err = core::parse_url_view("http://[::1]evil.com/api");
        sub.assert_false(view.valid, "parse_url_view MUST reject host with trailing garbage after bracket [::1]evil.com (Go #78569)");
        sub.assert_true(err != core::UrlParseError.None, "Must return parse error for malformed IPv6 host");
    };
}

// ----------------------------------------------------------------------------
// 7. RFC 9112 Section 4: Status Line - HTTP Wire Response Status Line Whitespace & 4-Digit Smuggling (uWS #1949)
// ----------------------------------------------------------------------------
fn test_http1_wire_response_status_line_validation(t: lit::T&) {
    t.run("parse_http1_wire_response must reject 4-digit status code 'HTTP/1.1 2000 OK'") { sub =>
        var res = wing::Response { .. };
        let wire: const u8[:] = "HTTP/1.1 2000 OK\r\nContent-Length: 0\r\n\r\n";
        let ok, _ = wing::parse_http1_wire_response(wire, res);
        sub.assert_false(ok, "parse_http1_wire_response MUST reject 4-digit status codes like '2000'");
    };

    t.run("parse_http1_wire_response must reject non-SP whitespace 'HTTP/1.1\\t200 OK'") { sub =>
        var res = wing::Response { .. };
        let wire_tab: const u8[:] = "HTTP/1.1\t200 OK\r\nContent-Length: 0\r\n\r\n";
        let ok_tab, _ = wing::parse_http1_wire_response(wire_tab, res);
        sub.assert_false(ok_tab, "parse_http1_wire_response MUST reject Tab (\\t) between HTTP-version and status code");
    };
}

// --- Component: regress_issues_batch04 ---
// Phase 4 RED test suite based on .gemini audit reports and Go / uWebSockets issue trackers.
// Verifies protocol flaws, RFC non-conformances, and security vulnerabilities that are CURRENTLY UNFIXED in goose-wing.
//
// Issues covered:
// 1. RFC 9110 §6.5.1 & Go #81143: Disallow Content-Type and Content-Encoding in Chunked Trailers
// 2. RFC 9110 §14.1.2 & Go #81858 (CVE-2026-78667): Range Requests Exceeding Max Ranges Must Return 200 OK (Not 416)
// 3. RFC 9112 §6.1 & RFC 7230 §3.3.3: Invalid Response Transfer-Encoding Must Reject (Not Fall Through to Content-Length)
// 4. RFC 3986 §3.2.2 & Go #75678 (CVE-2025-47912): parse_url_view Must Reject Non-IPv6 Bracketed Hosts ([google.com], [127.0.0.1])
// 5. RFC 3986 §2 / RFC 9112 §3.2 & CVE-2023-26159: parse_url_view Must Reject Unencoded CRLF in Host and Path
// 6. RFC 6455 §5.5 & uWS #1407: WebSocket Control Frame Encoding with Payload > 125 Must Never Emit Extended Length (126/127)

// ----------------------------------------------------------------------------
// 1. RFC 9110 §6.5.1 & Go #81143: Disallow Content-Type and Content-Encoding in Trailers
// ----------------------------------------------------------------------------
fn test_forbidden_trailer_fields(t: lit::T&) {
    t.run("Content-Type in chunked trailer must be rejected as DisallowedTrailer") { sub =>
        // RFC 9110 Section 6.5.1:
        // "A sender MUST NOT generate a trailer that contains any of the following fields:
        // ... Content-Encoding, Content-Type, Content-Range."
        // A recipient MUST NOT process forbidden fields as metadata of the payload.
        var out_body: u8[>..] = [];
        var out_trailers = wing::HeaderMap { .. };
        let chunk_wire: const u8[:] = "5\r\nHello\r\n0\r\nContent-Type: text/html\r\n\r\n";

        let err, _ = wing::decode_chunked_body_with_trailers(chunk_wire, out_body, out_trailers);
        sub.assert_eq(err, wing::ChunkedDecodeError.DisallowedTrailer, "Content-Type trailer must be rejected with DisallowedTrailer (RFC 9110 §6.5.1)");
    };

    t.run("Content-Encoding in chunked trailer must be rejected as DisallowedTrailer") { sub =>
        var out_body: u8[>..] = [];
        var out_trailers = wing::HeaderMap { .. };
        let chunk_wire: const u8[:] = "5\r\nHello\r\n0\r\nContent-Encoding: gzip\r\n\r\n";

        let err, _ = wing::decode_chunked_body_with_trailers(chunk_wire, out_body, out_trailers);
        sub.assert_eq(err, wing::ChunkedDecodeError.DisallowedTrailer, "Content-Encoding trailer must be rejected with DisallowedTrailer (RFC 9110 §6.5.1)");
    };
}

// ----------------------------------------------------------------------------
// 2. RFC 9110 §14.1.2 & Go #81858 (CVE-2026-78667): Exceeded Ranges Must Return 200 OK
// ----------------------------------------------------------------------------
fn test_exceeded_max_ranges_returns_200(t: lit::T&) {
    t.run("Range request with > 16 ranges must be ignored and served with 200 OK") { sub =>
        // RFC 9110 Section 14.1.2 & Go #81858 (CVE-2026-78667):
        // "An origin server MAY ignore a Range header field containing more than one range,
        // or containing ranges with excessive overhead... and return the entire selected
        // representation with a 200 (OK) status code."
        // In http/multipart.goose:668, serve_range_request returns 416 for ExceededMaxRanges!
        var out_status: i32 = 0;
        var out_headers = wing::HeaderMap { .. };
        var out_body: u8[>..] = [];

        let payload: const u8[:] = "0123456789abcdefghijklmnopqrstuvwxyz";
        let mod_time = core::unix(1700000000);

        // 17 small ranges exceeds max_ranges=16
        let excessive_range = "bytes=0-1,2-3,4-5,6-7,8-9,10-11,12-13,14-15,16-17,18-19,20-21,22-23,24-25,26-27,28-29,30-31,32-33";

        wing::serve_range_request(
            excessive_range,
            "",
            "\"etag123\"",
            mod_time,
            payload.len,
            "text/plain",
            out_status,
            out_headers,
            out_body,
        ) { start, len, buf =>
            buf.append(payload[start..(start + len)]);
        };

        sub.assert_eq(out_status, 200, "Excessive range count must be ignored and return 200 OK (Go #81858 / CVE-2026-78667)");
        sub.assert_bytes_eq(out_body[..], payload, "Must return complete representation when excessive ranges are ignored");
    };
}

// ----------------------------------------------------------------------------
// 3. RFC 9112 §6.1 & RFC 7230 §3.3.3: Invalid Response Transfer-Encoding Rejection
// ----------------------------------------------------------------------------
fn test_response_invalid_transfer_encoding_rejected(t: lit::T&) {
    t.run("Response with invalid Transfer-Encoding and Content-Length must NOT fall through") { sub =>
        // RFC 9112 Section 6.1:
        // "If a Transfer-Encoding header field is present in a response and the chunked transfer
        // coding is not the final transfer coding, the recipient MUST treat the response as an
        // error or close the connection without reading the body."
        // Currently, parse_http1_wire_response falls through to Content-Length!
        var res = wing::Response { .. };
        let wire: const u8[:] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked, identity\r\nContent-Length: 5\r\n\r\nhello";
        let ok, _ = wing::parse_http1_wire_response(wire, res);

        sub.assert_false(ok, "parse_http1_wire_response MUST reject response with invalid Transfer-Encoding (RFC 9112 §6.1)");
    };

    t.run("Response with unknown Transfer-Encoding must be rejected") { sub =>
        var res = wing::Response { .. };
        let wire_unknown: const u8[:] = "HTTP/1.1 200 OK\r\nTransfer-Encoding: bogus\r\nContent-Length: 4\r\n\r\ntest";
        let ok_unk, _ = wing::parse_http1_wire_response(wire_unknown, res);

        sub.assert_false(ok_unk, "parse_http1_wire_response MUST reject response with unknown Transfer-Encoding 'bogus'");
    };
}

// ----------------------------------------------------------------------------
// 4. RFC 3986 §3.2.2 & Go #75678 (CVE-2025-47912): parse_url_view Non-IPv6 Bracket Rejection
// ----------------------------------------------------------------------------
fn test_parse_url_view_non_ipv6_bracketed_host(t: lit::T&) {
    t.run("parse_url_view must reject bracketed domain name [google.com]") { sub =>
        // RFC 3986 Section 3.2.2:
        // IP-literal = "[" ( IPv6address / IPvFuture ) "]"
        // Hostnames and IPv4 addresses MUST NOT be enclosed in square brackets.
        // Currently, parse_url_view accepts 'http://[google.com]/path' with view.valid == true!
        let view, err = core::parse_url_view("http://[google.com]/path");
        sub.assert_false(view.valid, "parse_url_view MUST reject hostname in square brackets [google.com] (Go #75678 / CVE-2025-47912)");
        sub.assert_true(err != core::UrlParseError.None, "Must return parse error for bracketed hostname");
    };

    t.run("parse_url_view must reject bracketed IPv4 address [127.0.0.1]") { sub =>
        let view_ip, err_ip = core::parse_url_view("http://[127.0.0.1]/path");
        sub.assert_false(view_ip.valid, "parse_url_view MUST reject IPv4 address in square brackets [127.0.0.1]");
        sub.assert_true(err_ip != core::UrlParseError.None, "Must return parse error for bracketed IPv4 address");
    };
}

// ----------------------------------------------------------------------------
// 5. RFC 3986 §2 / RFC 9112 §3.2 & CVE-2023-26159: CRLF in URL View Host and Path
// ----------------------------------------------------------------------------
fn test_parse_url_view_crlf_rejection(t: lit::T&) {
    t.run("parse_url_view must reject unencoded CRLF in host") { sub =>
        // Unencoded CRLF in URL host enables HTTP request smuggling and host header injection.
        let view, err = core::parse_url_view("http://evil\r\n.com/path");
        sub.assert_false(view.valid, "parse_url_view MUST reject CRLF in host (CVE-2023-26159)");
        sub.assert_true(err != core::UrlParseError.None, "Must return parse error for CRLF in host");
    };

    t.run("parse_url_view must reject unencoded CRLF in path") { sub =>
        // Unencoded CRLF in URL path enables HTTP request line splitting and header injection.
        let view, err = core::parse_url_view("http://example.com/path\r\nInjected-Header: 1");
        sub.assert_false(view.valid, "parse_url_view MUST reject CRLF in path (CVE-2023-26159)");
        sub.assert_true(err != core::UrlParseError.None, "Must return parse error for CRLF in path");
    };
}

// ----------------------------------------------------------------------------
// 6. RFC 6455 §5.5 & uWS #1407: WebSocket Control Frame Encoding Clamps to <= 125
// ----------------------------------------------------------------------------
fn test_ws_control_frame_encoding_size_limit(t: lit::T&) {
    t.run("send_ping with payload > 125 must NEVER serialize extended length (126/127)") { sub =>
        // RFC 6455 Section 5.5:
        // "All control frames MUST have a payload length of 125 bytes or less and MUST NOT be fragmented."
        // An implementation MUST NOT encode a control frame with payload length > 125.
        // Currently, encode_ws_frame emits 0x7E (126) or 0x7F (127), which is wire-invalid!
        var ws = wing::new_websocket_session(true);
        var big_ping: u8[..256] = [];
        for i in 130 { big_ping.push('x' as u8); }

        var wire_out: u8[..512] = [];
        wing::send_ping(ws, big_ping[..], wire_out);

        guard wire_out.len >= 2 else {
            sub.assert_true(false, "send_ping produced empty wire output");
            return;
        }

        // Byte 1 has mask bit and 7-bit length
        let raw_len = wire_out[1] & 0x7F;
        sub.assert_true(raw_len <= 125, "Control frame payload length on wire MUST be <= 125 (RFC 6455 §5.5)");
        sub.assert_true(raw_len != 126 && raw_len != 127, "Control frame MUST NEVER use extended length 126 or 127");
    };
}

// --- Component: regress_issues_batch05 ---
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

// ----------------------------------------------------------------------------
// 1. RFC 9112 §3.2.3 & §9.3.6: CONNECT Request-Target Authority-Form Enforcement
// ----------------------------------------------------------------------------
fn test_connect_authority_form_enforcement(t: lit::T&) {
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
fn test_host_header_comma_separated_values_rejected(t: lit::T&) {
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
fn test_dns_decode_label_length_and_reserved_bits(t: lit::T&) {
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
        var off:      i64       = 0;
        let ok = wing::dns_decode_name(wire[..], off, out_name);
        sub.assert_false(ok, "dns_decode_name MUST reject label with length 70 (> 63)");
    };

    t.run("DNS wire decode MUST reject reserved high-order label bits (0x40 or 0x80)") { sub =>
        // RFC 1035 Section 4.1.4: "The 10 and 01 combinations are reserved for future use."
        // Only 00 (uncompressed label <= 63) and 11 (0xC0 compression pointer) are valid.
        var wire:     u8[..16]  = [0x44, 't', 'e', 's', 't', 0x00]; // 0x44 has bits 01_000100
        var out_name: u8[..256] = [];
        var off:      i64       = 0;
        let ok = wing::dns_decode_name(wire[..], off, out_name);
        sub.assert_false(ok, "dns_decode_name MUST reject label starting with reserved bits 01 (0x40)");
    };
}

// ----------------------------------------------------------------------------
// 4. HAProxy PROXY Protocol v2 §2.2 & uWS #1927 / #1948: PROXY v2 Malformed TLVs
// ----------------------------------------------------------------------------
fn test_proxy_v2_truncated_tlv_and_trailing_bytes(t: lit::T&) {
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
fn test_ws_close_frame_reason_clamped(t: lit::T&) {
    t.run("close with 130-byte reason MUST be clamped to <= 123 bytes reason (<= 125 total payload)") { sub =>
        // RFC 6455 Section 5.5: "All control frames MUST have a payload length of 125 bytes or less"
        // RFC 6455 Section 5.5.1: Close frame status code is 2 bytes, so reason can be at most 123 bytes.
        var ws = wing::new_websocket_session(true);
        var long_reason: u8[..256] = [];
        for i in 130 { long_reason.push('z' as u8); }

        var wire_out: u8[..512] = [];
        wing::close(ws, rfc::WS_STATUS_NORMAL, long_reason[..], wire_out);

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
fn test_query_param_key_overflow_defense(t: lit::T&) {
    t.run("parse_query_params with key > 64 bytes MUST safely truncate or handle without buffer overflow") { sub =>
        // In legacy implementation, QueryParamItem.key capacity was 64 bytes.
        // With zero-copy token slicing, wire slicing avoids fixed stack arrays, sets overflow flag,
        // and accurately preserves key/value offsets without buffer overrun.
        let query = "very_long_param_key_exceeding_sixty_four_bytes_boundary_1234567890_abcdef=val";
        let list = core::parse_query_params(query);
        sub.assert_true(list.tokens.len == 1, "Should parse 1 item");
        sub.assert_true(list.overflow, "Oversized key must set overflow flag");
        let k = core::query_token_key(list.tokens[0], list.wire);
        let v = core::query_token_val(list.tokens[0], list.wire);
        sub.assert_true(k.len > 64, "Zero-copy key slice preserves wire length");
        sub.assert_bytes_eq(v, "val", "Value must be 'val'");
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
fn test_cookie_url_fallback_path_fragment(t: lit::T&) {
    t.run("URL with fragment in fallback path MUST exclude fragment from host and default path to '/'") { sub =>
        // In fallback path (e.g. invalid port or scheme-less format like "http://example.com#section"):
        let u = wing::parse_canonical_cookie_url("http://example.com#section");
        sub.assert_true(u.host[..] == "example.com", "Host must be 'example.com', not contain '#section'");
        sub.assert_true(u.path[..] == "/", "Default path must be '/' per RFC 6265bis §5.1.4");
    };
}

fn main() {
    var runner = lit::new_runner("Issue Regression Suite Batch 1 (Phases 1-5)", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. Go #78948 (CVE-2026-39825) Query Parameter Truncation & Smuggling", test_query_param_truncation_smuggling);
    lit::run_case(runner, "2. Go #82350 Stale Host Header Leakage Across Redirects", test_redirect_stale_host_header_leakage);
    lit::run_case(runner, "3. Go #82343 RFC 2231 Extended Multipart Boundary & Validation", test_multipart_boundary_rfc2231_and_validation);
    lit::run_case(runner, "4. Go #78760 (CVE-2026-39821) Pure ASCII Punycode URL Host Rejection", test_pure_ascii_punycode_url_host_rejection);
    lit::run_case(runner, "5. uWebSockets #1949 / RFC 9112 §3.2 Host Header Query & Fragment Rejection", test_host_header_query_fragment_rejection);
    lit::run_case(runner, "6. Go #77108 (CVE-2025-61726) Query Param Oversized Token DoS Guard", test_query_param_oversized_token_dos_guard);
    lit::run_case(runner, "7. RFC 9110 §8.6 / uWS #1370 / Go #81642: Status 204 Body Leakage", test_status_204_body_suppression_on_wire);
    lit::run_case(runner, "8. Go #78172 & RFC 3986 §3.2.2 / RFC 9112 §3.2: Malformed Host", test_malformed_ip_literal_host_rejection);
    lit::run_case(runner, "9. Go #80282 & RFC 3986 §5.2.4: Deep Path Collapse Truncation", test_deep_path_dot_segment_collapse);
    lit::run_case(runner, "10. RFC 9110 §7.6.1 & Go #82065: Connection Hop-by-Hop Truncation", test_connection_header_hop_by_hop_token_capacity);
    lit::run_case(runner, "11. RFC 9449 §4.3: DPoP Proof URI Substring Bypass", test_dpop_proof_uri_prefix_collision);
    lit::run_case(runner, "12. Go #62235 & RFC 6874 §2: Scoped IPv6 Link-Local URL Zone ID", test_scoped_ipv6_link_local_url_acceptance);
    lit::run_case(runner, "13. Go #81508 & RFC 9110 §14.1.2: Unsupported Range Unit Must Return 200 OK", test_unsupported_range_unit_ignored);
    lit::run_case(runner, "14. Go #21096 & RFC 9110 §7.6.1: Forwarding TE: trailers for gRPC", test_grpc_te_trailers_preserved);
    lit::run_case(runner, "15. RFC 6455 §8.1 / §7.4.1 / Autobahn 6.4.1: Close Invalid UTF-8 Status 1007", test_close_frame_invalid_utf8_status_1007);
    lit::run_case(runner, "16. RFC 7692 §5.1 / uWS #1164: RSV1 on Continuation Frame Rejection", test_continuation_rsv1_rejected);
    lit::run_case(runner, "17. Go #76635 & RFC 6455 §4.1: Empty Path in WS Handshake Defaults to '/'", test_ws_handshake_empty_path_defaults_to_slash);
    lit::run_case(runner, "18. Go #78569 & CVE-2026-25679 follow-up: parse_url_view [::1]evil.com Rejection", test_parse_url_view_ipv6_bracket_trailing_garbage);
    lit::run_case(runner, "19. RFC 9112 Section 4: Status Line - HTTP Wire Response Status Line Validation (uWS #1949)", test_http1_wire_response_status_line_validation);
    lit::run_case(runner, "20. RFC 9110 §6.5.1 & Go #81143: Disallow Content-Type and Content-Encoding in Trailers", test_forbidden_trailer_fields);
    lit::run_case(runner, "21. RFC 9110 §14.1.2 & Go #81858: Range Requests Exceeding Max Ranges Return 200 OK", test_exceeded_max_ranges_returns_200);
    lit::run_case(runner, "22. RFC 9112 §6.1 & RFC 7230 §3.3.3: Invalid Response Transfer-Encoding Rejection", test_response_invalid_transfer_encoding_rejected);
    lit::run_case(runner, "23. RFC 3986 §3.2.2 & Go #75678: parse_url_view Non-IPv6 Bracket Rejection", test_parse_url_view_non_ipv6_bracketed_host);
    lit::run_case(runner, "24. RFC 3986 §2 / RFC 9112 §3.2 & CVE-2023-26159: CRLF in URL View Host and Path", test_parse_url_view_crlf_rejection);
    lit::run_case(runner, "25. RFC 6455 §5.5 & uWS #1407: WebSocket Control Frame Encoding Clamps to <= 125", test_ws_control_frame_encoding_size_limit);
    lit::run_case(runner, "26. RFC 9112 §3.2.3 & §9.3.6: CONNECT Authority-Form Enforcement", test_connect_authority_form_enforcement);
    lit::run_case(runner, "27. RFC 9112 §7.2 & §9.5: Host Header Multiple Values Rejection", test_host_header_comma_separated_values_rejected);
    lit::run_case(runner, "28. RFC 1035 §2.3.4 & §4.1.4: DNS Wire Decoding Label Bounds", test_dns_decode_label_length_and_reserved_bits);
    lit::run_case(runner, "29. HAProxy PROXY Protocol v2 §2.2: Truncated TLVs & Trailing Bytes", test_proxy_v2_truncated_tlv_and_trailing_bytes);
    lit::run_case(runner, "30. RFC 6455 §5.5 & §5.5.1: WebSocket Close Reason Clamped to <= 123", test_ws_close_frame_reason_clamped);
    lit::run_case(runner, "31. CVE-2025-61726 & CVE-2026-39825: Query Parameter Bounds Guard", test_query_param_key_overflow_defense);
    lit::run_case(runner, "32. RFC 6265bis §5.1.4: Cookie URL Fallback Path and Fragment", test_cookie_url_fallback_path_fragment);

    let ok = lit::finish(runner);
    assert(ok);
}
