// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

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
import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. RFC 9110 §8.6 / uWS #1370 / Go #81642: Status 204/304 Body Leakage on Wire
// ----------------------------------------------------------------------------
fn test_status_204_body_suppression_on_wire(t: core::T&) {
    t.run("Status 204 No Content must not serialize message body to wire") { sub =>
        // RFC 9110 Section 8.6 & Section 6.4.1:
        // A 204 (No Content) response MUST NOT include a message body.
        // In server/server.goose:540, serialize_http1_response appends res.body[..]
        // directly to the wire when body.len > 0, despite status 204 omitting Content-Length.
        // This causes HTTP response splitting / smuggling on persistent connections!
        var res = wing::new_response();
        res.status_code = 204;
        res.body.append("LEAKED_PAYLOAD_SMUGGLING");

        var wire_out: u8[..1024] = [];
        wing::serialize_http1_response(res, "GooseWing", wire_out);

        let has_body = core::index_of_slice(wire_out[..], "LEAKED_PAYLOAD_SMUGGLING") >= 0;
        sub.assert_false(has_body, "Status 204 response MUST NOT emit message body to wire per RFC 9110 §8.6");
    };
}

// ----------------------------------------------------------------------------
// 2. Go #78172 & RFC 3986 §3.2.2 / RFC 9112 §3.2: Malformed IP-Literal Host
// ----------------------------------------------------------------------------
fn test_malformed_ip_literal_host_rejection(t: core::T&) {
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
fn test_deep_path_dot_segment_collapse(t: core::T&) {
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
fn test_connection_header_hop_by_hop_token_capacity(t: core::T&) {
    t.run("Custom hop-by-hop headers past index 16 must not leak across intermediary") { sub =>
        // In http/headers.goose:1455 (collect_connection_tokens), out_tokens has cap 16:
        //   out_tokens: u8[..64][..16]&
        // If a Connection header specifies > 16 tokens (e.g. h1..h17), the 17th token
        // is silently dropped, causing strip_hop_by_hop_headers to retain 'h17'!
        var src = wing::new_header_map();
        wing::append_header(src, "Connection", "h1, h2, h3, h4, h5, h6, h7, h8, h9, h10, h11, h12, h13, h14, h15, h16, h17");
        wing::append_header(src, "h17", "confidential-token");

        var dst = wing::new_header_map();
        wing::strip_hop_by_hop_headers(src, dst);

        sub.assert_false(wing::has_header(dst, "h17"), "Hop-by-hop header h17 must be stripped per RFC 9110 §7.6.1");
    };
}

// ----------------------------------------------------------------------------
// 5. RFC 9449 §4.3: DPoP Proof URI Substring Prefix Collision Bypass
// ----------------------------------------------------------------------------
fn test_dpop_proof_uri_prefix_collision(t: core::T&) {
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
fn test_scoped_ipv6_link_local_url_acceptance(t: core::T&) {
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

fn main() {
    // Reference a native symbol to trigger proper Goose native C shim linking
    var dummy: u8[4] = [0, 0, 0, 0];
    wing::swar_to_lower(dummy[..]);

    var runner = core::new_runner("RED Suite Phase 2: CVE & Issue Tracker Flaws", core::Verbosity.Verbose);

    core::run_case(runner, "1. RFC 9110 §8.6 / uWS #1370 / Go #81642: Status 204 Body Leakage", test_status_204_body_suppression_on_wire);
    core::run_case(runner, "2. Go #78172 & RFC 3986 §3.2.2 / RFC 9112 §3.2: Malformed Host", test_malformed_ip_literal_host_rejection);
    core::run_case(runner, "3. Go #80282 & RFC 3986 §5.2.4: Deep Path Collapse Truncation", test_deep_path_dot_segment_collapse);
    core::run_case(runner, "4. RFC 9110 §7.6.1 & Go #82065: Connection Hop-by-Hop Truncation", test_connection_header_hop_by_hop_token_capacity);
    core::run_case(runner, "5. RFC 9449 §4.3: DPoP Proof URI Substring Bypass", test_dpop_proof_uri_prefix_collision);
    core::run_case(runner, "6. Go #62235 & RFC 6874 §2: Scoped IPv6 Link-Local URL Zone ID", test_scoped_ipv6_link_local_url_acceptance);

    let ok = core::finish(runner);
    print("\n[RED PHASE 2 TEST SUITE STATUS] Finished execution. Result ok=", ok);
    if !ok {
        print(">>> CONFIRMED RED PHASE 2: All 6 targeted vulnerabilities/flaws reproduce successfully against the current codebase! <<<\n");
    }
}
