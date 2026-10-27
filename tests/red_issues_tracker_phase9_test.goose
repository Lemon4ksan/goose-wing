// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Phase 9 RED test suite based on .gemini issue trackers and RFC specifications.
// Verifies protocol flaws, RFC non-conformances, and security edge cases:
//
// 1. RFC 9112 §7.2 / RFC 3986 §3.2.2 & uWebSockets #1949: HTTP/1.1 Host Header Character Validation & Duplicate Rejection
// 2. RFC 9113 §8.3.1 & uWebSockets #1949: HTTP/2 :authority Pseudo-Header Forbidden Characters
// 3. RFC 9113 §8.1.2: HTTP/2 Trailer Section Disallowed Header Fields
// 4. RFC 9114 §4.3: HTTP/3 / QPACK Duplicate Pseudo-Headers & Order Invariants
// 5. RFC 9113 §6.5.2: HTTP/2 Client SETTINGS Frame Rejection of SETTINGS_ENABLE_PUSH != 0
// 6. RFC 3986 §3.2.2 & Go #77578 (CVE-2026-25679) / CVE-2025-47912: URL Bracketed Host Validation
// 7. RFC 9110 §15.4 & Go #73816 (CVE-2025-4673): Cross-Origin Redirect Sensitive Header Stripping

import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. RFC 9112 §7.2 / RFC 3986 §3.2.2 & uWebSockets #1949: HTTP/1.1 Host Validation
// ----------------------------------------------------------------------------
fn test_h1_host_header_validation_and_duplicates(t: core::T&) {
    t.run("Host header with path, query, fragment or userinfo MUST be rejected (uWS #1949)") { sub =>
        // RFC 9112 Section 7.2:
        // Host = uri-host [ ":" port ]
        // Must not contain path (/), query (?), fragment (#), or userinfo (@)
        var map1 = wing::new_header_map();
        let err_path = wing::parse_headers("Host: example.com/path\r\n\r\n", map1);
        sub.assert_false(wing::is_ok(err_path), "Host with path '/' MUST be rejected");

        var map2 = wing::new_header_map();
        let err_query = wing::parse_headers("Host: example.com?q=1\r\n\r\n", map2);
        sub.assert_false(wing::is_ok(err_query), "Host with query '?' MUST be rejected");

        var map3 = wing::new_header_map();
        let err_hash = wing::parse_headers("Host: example.com#frag\r\n\r\n", map3);
        sub.assert_false(wing::is_ok(err_hash), "Host with fragment '#' MUST be rejected");

        var map4 = wing::new_header_map();
        let err_at = wing::parse_headers("Host: user@example.com\r\n\r\n", map4);
        sub.assert_false(wing::is_ok(err_at), "Host with userinfo '@' MUST be rejected");

        var map_ok = wing::new_header_map();
        let err_ok = wing::parse_headers("Host: example.com:8080\r\n\r\n", map_ok);
        sub.assert_true(wing::is_ok(err_ok), "Clean Host 'example.com:8080' is valid");
    };

    t.run("Duplicate Host headers in HTTP/1.1 MUST be rejected (RFC 9112 §7.2)") { sub =>
        var map_dup = wing::new_header_map();
        let err_dup = wing::parse_headers("Host: example.com\r\nHost: evil.com\r\n\r\n", map_dup);
        sub.assert_false(wing::is_ok(err_dup), "Duplicate Host headers MUST be rejected (smuggling protection)");
    };
}

// ----------------------------------------------------------------------------
// 2. RFC 9113 §8.3.1 & uWebSockets #1949: HTTP/2 :authority Forbidden Characters
// ----------------------------------------------------------------------------
fn test_h2_authority_character_validation(t: core::T&) {
    t.run(":authority with path, query, fragment or userinfo MUST return ERR_PROTOCOL_ERROR") { sub =>
        var headers = wing::DecodedH2HeaderList { .. };
        let ok_meth = wing::validate_header_ordering_and_rules(headers, ":method", "GET");
        sub.assert_eq(ok_meth, wing::ERR_NO_ERROR, ":method GET accepted");
        headers.fields.push(wing::DecodedH2Header { name: ":method", value: "GET", .. });

        let err_path = wing::validate_header_ordering_and_rules(headers, ":authority", "example.com/api");
        sub.assert_eq(err_path, wing::ERR_PROTOCOL_ERROR, ":authority with '/' MUST return ERR_PROTOCOL_ERROR");

        let err_query = wing::validate_header_ordering_and_rules(headers, ":authority", "example.com?foo=1");
        sub.assert_eq(err_query, wing::ERR_PROTOCOL_ERROR, ":authority with '?' MUST return ERR_PROTOCOL_ERROR");

        let err_hash = wing::validate_header_ordering_and_rules(headers, ":authority", "example.com#sec");
        sub.assert_eq(err_hash, wing::ERR_PROTOCOL_ERROR, ":authority with '#' MUST return ERR_PROTOCOL_ERROR");

        let err_user = wing::validate_header_ordering_and_rules(headers, ":authority", "admin@example.com");
        sub.assert_eq(err_user, wing::ERR_PROTOCOL_ERROR, ":authority with '@' MUST return ERR_PROTOCOL_ERROR");

        let ok_auth = wing::validate_header_ordering_and_rules(headers, ":authority", "example.com:443");
        sub.assert_eq(ok_auth, wing::ERR_NO_ERROR, ":authority 'example.com:443' is valid");
    };
}

// ----------------------------------------------------------------------------
// 3. RFC 9113 §8.1.2: HTTP/2 Trailer Section Disallowed Header Fields
// ----------------------------------------------------------------------------
fn test_h2_trailer_disallowed_fields(t: core::T&) {
    t.run("Disallowed headers in HTTP/2 trailers MUST return ERR_PROTOCOL_ERROR (RFC 9113 §8.1.2)") { sub =>
        var trailers = wing::DecodedH2HeaderList { is_trailer: true, .. };

        let err_cl = wing::validate_header_ordering_and_rules(trailers, "content-length", "100");
        sub.assert_eq(err_cl, wing::ERR_PROTOCOL_ERROR, "content-length in trailers MUST return PROTOCOL_ERROR");

        let err_te = wing::validate_header_ordering_and_rules(trailers, "transfer-encoding", "chunked");
        sub.assert_eq(err_te, wing::ERR_PROTOCOL_ERROR, "transfer-encoding in trailers MUST return PROTOCOL_ERROR");

        let err_host = wing::validate_header_ordering_and_rules(trailers, "host", "evil.com");
        sub.assert_eq(err_host, wing::ERR_PROTOCOL_ERROR, "host in trailers MUST return PROTOCOL_ERROR");

        let err_conn = wing::validate_header_ordering_and_rules(trailers, "connection", "close");
        sub.assert_eq(err_conn, wing::ERR_PROTOCOL_ERROR, "connection in trailers MUST return PROTOCOL_ERROR");

        let err_tr = wing::validate_header_ordering_and_rules(trailers, "trailer", "x-foo");
        sub.assert_eq(err_tr, wing::ERR_PROTOCOL_ERROR, "trailer in trailers MUST return PROTOCOL_ERROR");

        let ok_custom = wing::validate_header_ordering_and_rules(trailers, "x-checksum-sha256", "abc123def");
        sub.assert_eq(ok_custom, wing::ERR_NO_ERROR, "Allowed trailer header 'x-checksum-sha256' is valid");
    };
}

// ----------------------------------------------------------------------------
// 4. RFC 9114 §4.3: HTTP/3 / QPACK Duplicate Pseudo-Headers & Order Invariants
// ----------------------------------------------------------------------------
fn test_h3_pseudo_header_invariants(t: core::T&) {
    t.run("Duplicate :status or pseudo-headers after regular headers MUST be rejected (RFC 9114 §4.3)") { sub =>
        let settings = wing::H3Settings { .. };
        var conn = wing::new_h3_client_connection(settings);

        // Open request stream
        let s_id, ok_open = conn.open_request_stream();
        sub.assert_true(ok_open, "Stream opened");

        // Encode QPACK headers with duplicate :status
        var qpack_dup: u8[>..] = [0x00, 0x00];
        wing::encode_qpack_field(qpack_dup, ":status", "200");
        wing::encode_qpack_field(qpack_dup, ":status", "500");

        var wire_dup: u8[>..] = [];
        wing::encode_h3_headers_frame(wire_dup, qpack_dup[..]);

        let res_dup = conn.handle_stream_data(s_id, true, wire_dup[..], false);
        sub.assert_eq(res_dup, wing::H3_ERR_GENERAL_PROTOCOL, "Duplicate :status MUST return H3_ERR_GENERAL_PROTOCOL");

        // Test pseudo-header after regular header
        var conn2 = wing::new_h3_client_connection(settings);
        let s_id2, ok_open2 = conn2.open_request_stream();
        sub.assert_true(ok_open2, "Stream opened");

        var qpack_order: u8[>..] = [0x00, 0x00];
        wing::encode_qpack_field(qpack_order, "content-type", "text/plain");
        wing::encode_qpack_field(qpack_order, ":status", "200");

        var wire_order: u8[>..] = [];
        wing::encode_h3_headers_frame(wire_order, qpack_order[..]);

        let res_order = conn2.handle_stream_data(s_id2, true, wire_order[..], false);
        sub.assert_eq(res_order, wing::H3_ERR_GENERAL_PROTOCOL, "Pseudo-header after regular header MUST return H3_ERR_GENERAL_PROTOCOL");
    };
}

// ----------------------------------------------------------------------------
// 5. RFC 9113 §6.5.2: HTTP/2 Client Rejection of SETTINGS_ENABLE_PUSH != 0
// ----------------------------------------------------------------------------
fn test_h2_client_settings_enable_push_rejection(t: core::T&) {
    t.run("Client receiving SETTINGS_ENABLE_PUSH != 0 MUST return PROTOCOL_ERROR (RFC 9113 §6.5.2)") { sub =>
        // Server receiving ENABLE_PUSH = 1 from client is VALID
        let ok_server = wing::validate_settings_parameter(wing::SETTING_ENABLE_PUSH, 1, false);
        sub.assert_eq(ok_server, wing::ERR_NO_ERROR, "Server receiving ENABLE_PUSH=1 from client is valid");

        // Client receiving ENABLE_PUSH = 1 from server MUST be rejected
        let err_client = wing::validate_settings_parameter(wing::SETTING_ENABLE_PUSH, 1, true);
        sub.assert_eq(err_client, wing::ERR_PROTOCOL_ERROR, "Client receiving ENABLE_PUSH=1 from server MUST return ERR_PROTOCOL_ERROR");

        // Client receiving ENABLE_PUSH = 0 from server is VALID
        let ok_client0 = wing::validate_settings_parameter(wing::SETTING_ENABLE_PUSH, 0, true);
        sub.assert_eq(ok_client0, wing::ERR_NO_ERROR, "Client receiving ENABLE_PUSH=0 from server is valid");
    };
}

// ----------------------------------------------------------------------------
// 6. RFC 3986 §3.2.2 & Go #77578 / CVE-2025-47912: URL Bracketed Host Validation
// ----------------------------------------------------------------------------
fn test_url_bracketed_host_validation(t: core::T&) {
    t.run("IPv4 and non-IP hostnames in brackets MUST be rejected (CVE-2025-47912)") { sub =>
        let u1 = core::new_url("http://[127.0.0.1]/");
        sub.assert_false(u1.valid, "http://[127.0.0.1]/ MUST NOT be accepted as valid URL");

        let u2 = core::new_url("http://[example.com]/");
        sub.assert_false(u2.valid, "http://[example.com]/ MUST NOT be accepted as valid URL");

        let u_valid = core::new_url("http://[::1]/");
        sub.assert_true(u_valid.valid, "http://[::1]/ is a valid IPv6 URL");
    };

    t.run("IPv6 brackets not at start of host MUST be rejected (Go #77578 / CVE-2026-25679)") { sub =>
        let u_bad_pre = core::new_url("http://foo[::1]/");
        sub.assert_false(u_bad_pre.valid, "http://foo[::1]/ MUST be rejected");

        let u_bad_mid = core::new_url("http://example.com[::1]:80/");
        sub.assert_false(u_bad_mid.valid, "http://example.com[::1]:80/ MUST be rejected");
    };
}

// ----------------------------------------------------------------------------
// 7. RFC 9110 §15.4 & Go #73816 (CVE-2025-4673): Redirect Sensitive Header Stripping
// ----------------------------------------------------------------------------
fn test_redirect_sensitive_header_stripping(t: core::T&) {
    t.run("Proxy-Authorization and Authorization purged on cross-origin redirect (CVE-2025-4673)") { sub =>
        var headers: wing::HeaderItem[..32] = [];
        headers.push(wing::make_header("Authorization", "Bearer secret123"));
        headers.push(wing::make_header("Proxy-Authorization", "Basic proxysecret"));
        headers.push(wing::make_header("User-Agent", "GooseWing/1.0"));

        let red_info = wing::RedirectInfo {
            is_cross_origin: true,
            is_scheme_downgrade: false,
            is_port_changed: false,
            clear_body: false,
            ..
        };

        wing::sanitize_headers_on_redirect(headers, red_info, false, false, false, false);

        let has_auth = wing::find_header_index(headers[..], "Authorization") >= 0;
        sub.assert_false(has_auth, "Authorization header MUST be stripped on cross-origin redirect");

        let has_proxy_auth = wing::find_header_index(headers[..], "Proxy-Authorization") >= 0;
        sub.assert_false(has_proxy_auth, "Proxy-Authorization MUST be stripped on cross-origin redirect (CVE-2025-4673)");

        let has_ua = wing::find_header_index(headers[..], "User-Agent") >= 0;
        sub.assert_true(has_ua, "User-Agent header is preserved across redirect");
    };
}

fn main() {
    var runner = core::new_runner("RED Suite Phase 9: Tracker Issues & RFC Invariants", core::Verbosity.Verbose);
    core::run_case(runner, "1. RFC 9112 §7.2 / RFC 3986 §3.2.2 & uWS #1949: HTTP/1.1 Host Header Validation", test_h1_host_header_validation_and_duplicates);
    core::run_case(runner, "2. RFC 9113 §8.3.1 & uWS #1949: HTTP/2 :authority Forbidden Characters", test_h2_authority_character_validation);
    core::run_case(runner, "3. RFC 9113 §8.1.2: HTTP/2 Trailer Section Disallowed Header Fields", test_h2_trailer_disallowed_fields);
    core::run_case(runner, "4. RFC 9114 §4.3: HTTP/3 / QPACK Duplicate Pseudo-Headers & Order Invariants", test_h3_pseudo_header_invariants);
    core::run_case(runner, "5. RFC 9113 §6.5.2: HTTP/2 Client SETTINGS Frame Rejection of SETTINGS_ENABLE_PUSH != 0", test_h2_client_settings_enable_push_rejection);
    core::run_case(runner, "6. RFC 3986 §3.2.2 & Go #77578 / CVE-2025-47912: URL Bracketed Host Validation", test_url_bracketed_host_validation);
    core::run_case(runner, "7. RFC 9110 §15.4 & Go #73816 (CVE-2025-4673): Redirect Sensitive Header Stripping", test_redirect_sensitive_header_stripping);
    let ok = core::finish(runner);
    assert(ok);
}
