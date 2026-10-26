// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Red test suite verifying uncovered edge cases and vulnerabilities from:
//   1. Go #78948 (CVE-2026-39825): Query parameter count truncation & smuggling in parse_query_params.
//   2. Go #82350: Preserving stale Request.Host across cross-origin / scheme-relative redirects.
//   3. Go #82343: RFC 2231 extended boundary parameter (boundary*=) and boundary validation in MediaType.
//   4. Go #78760 (CVE-2026-39821): Pure ASCII Punycode label in URL host rejection (http://xn--test-.com/).
//   5. uWebSockets #1949 / RFC 9112 §3.2: Host header containing query or fragment rejection in wire parser.
//   6. Go #77108 (CVE-2025-61726): Query parameter length DoS protection in validate_query_param_count.
import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. Go #78948 / CVE-2026-39825: Query Parameter Truncation & Smuggling
// ----------------------------------------------------------------------------
fn test_query_param_truncation_smuggling(t: core::T&) {
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
fn test_redirect_stale_host_header_leakage(t: core::T&) {
    t.run("Outbound Host header must not be retained on cross-origin redirect") { sub =>
        // When a request has an explicit custom Host header, redirecting to a different origin
        // MUST strip or update the Host header to match the new destination authority (Go #82350).
        var headers: wing::HeaderItem[..32] = [];
        headers.push(wing::make_header("Host", "internal-vault.corp.local"));
        headers.push(wing::make_header("X-Custom", "keep"));

        let origin_target = core::new_url("https://evil-phishing.com/harvest");

        var rinfo = wing::RedirectInfo {
            status_code: 302,
            new_url: origin_target,
            is_cross_origin: true,
            is_scheme_downgrade: false,
            is_port_changed: false,
            clear_body: true,
            new_referrer: [],
        };

        wing::sanitize_headers_on_redirect(headers, rinfo, false, false, false, false);

        // Host header pointing to the previous host MUST be stripped to prevent host header injection / routing desync
        let host_idx = wing::find_header_index(headers[..], "Host");
        sub.assert_true(host_idx < 0, "Stale Host header from source origin must be stripped on cross-origin redirect (Go #82350)");
    };
}

// ----------------------------------------------------------------------------
// 3. Go #82343: RFC 2231 Extended Multipart Boundary & Boundary Validation
// ----------------------------------------------------------------------------
fn test_multipart_boundary_rfc2231_and_validation(t: core::T&) {
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
fn test_pure_ascii_punycode_url_host_rejection(t: core::T&) {
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
fn test_host_header_query_fragment_rejection(t: core::T&) {
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
fn test_query_param_oversized_token_dos_guard(t: core::T&) {
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

fn main() {
    var runner = core::new_runner("RED Suite: Uncovered CVE & Issue Tracker Flaws", core::Verbosity.Verbose);

    core::run_case(runner, "1. Go #78948 (CVE-2026-39825) Query Parameter Truncation & Smuggling", test_query_param_truncation_smuggling);
    core::run_case(runner, "2. Go #82350 Stale Host Header Leakage Across Redirects", test_redirect_stale_host_header_leakage);
    core::run_case(runner, "3. Go #82343 RFC 2231 Extended Multipart Boundary & Validation", test_multipart_boundary_rfc2231_and_validation);
    core::run_case(runner, "4. Go #78760 (CVE-2026-39821) Pure ASCII Punycode URL Host Rejection", test_pure_ascii_punycode_url_host_rejection);
    core::run_case(runner, "5. uWebSockets #1949 / RFC 9112 §3.2 Host Header Query & Fragment Rejection", test_host_header_query_fragment_rejection);
    core::run_case(runner, "6. Go #77108 (CVE-2025-61726) Query Param Oversized Token DoS Guard", test_query_param_oversized_token_dos_guard);

    let ok = core::finish(runner);
    print("\n[RED TEST SUITE STATUS] Finished execution. Result ok=", ok);
    if !ok {
        print(">>> CONFIRMED RED: The targeted vulnerabilities/flaws reproduce successfully against the current codebase! <<<\n");
    }
}
