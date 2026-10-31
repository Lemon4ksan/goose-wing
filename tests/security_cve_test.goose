// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for uncovered CVEs:
//   1. CVE-2021-28918 & CVE-2021-29922: Octal, Hex, Dword, and Shorthand IPv4 SSRF Bypass.
//   2. CVE-2024-24790 & RFC 6761: localhost, uncompressed IPv6, IPv4-compatible, NAT64 & 6to4 SSRF.
//   3. CVE-2023-26159 & RFC 9110: CRLF and Control-Character Injection in Headers.
//   4. CVE-2022-27776 & CVE-2023-43804: Port-change Credential Leaks, Signature Stripping & Conditional Headers.
//   5. CVE-2023-27534 & CVE-2022-35252: Cookie URL Userinfo/Fragment/Path Discrepancies and Query-Hash Ordering.
//   6. CVE-2016-8616: PSL Supercookie and CTL Injection via Netscape Cookie Import.
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// ----------------------------------------------------------------------------
// 1. CVE-2021-28918 & CVE-2021-29922: Octal, Hex, Dword, Shorthand IPv4 SSRF
// ----------------------------------------------------------------------------
fn test_cve_ipv4_formats_ssrf(t: lit::T&) {
    var session = wing::new_session();
    wing::enable_ssrf_guard(session, true);

    let targets: const u8[..64][..6] = [
        "http://0177.0.0.1/admin",
        "http://2130706433/admin",
        "http://0x7f000001/admin",
        "http://0x7f.0.0.1/admin",
        "http://127.1/admin",
        "http://10.1/internal",
    ];

    for &url in targets {
        var req = wing::new_get(url[..]);
        let _, err = wing::execute_request(session, req);
        t.assert_false(wing::ok(err), "IPv4 format bypass must be blocked");
    }
}

// ----------------------------------------------------------------------------
// 2. CVE-2024-24790 & RFC 6761: Localhost, Uncompressed IPv6 & Tunnel SSRF
// ----------------------------------------------------------------------------
fn test_cve_localhost_and_ipv6_tunnels_ssrf(t: lit::T&) {
    var session = wing::new_session();
    wing::enable_ssrf_guard(session, true);

    let lh_targets: const u8[..64][..3] = [
        "http://localhost/admin",
        "http://localhost./admin",
        "http://service.localhost/admin",
    ];
    for &url in lh_targets {
        var req_lh = wing::new_get(url[..]);
        let _, err_lh = wing::execute_request(session, req_lh);
        t.assert_false(wing::ok(err_lh), "RFC 6761 localhost target must be blocked");
    }

    // DNS Rebinding with Uncompressed IPv6 Loopback
    wing::mock_route(session, "GET", "http://rebind-uncompressed.com/api", 200, "ok");
    wing::add_mock_resolved_ip(session, "0:0:0:0:0:0:0:1");

    var req = wing::new_get("http://rebind-uncompressed.com/api");
    let _, err = wing::execute_request(session, req);
    t.assert_false(wing::ok(err), "DNS rebinding with 0:0:0:0:0:0:0:1 must be blocked");

    let tunnel_targets: const u8[..64][..5] = [
        "http://[::127.0.0.1]/status",
        "http://[64:ff9b::127.0.0.1]/status",
        "http://[64:ff9b:1::127.0.0.1]/status",
        "http://[::ffff:0:127.0.0.1]/status",
        "http://[2002:7f00:1::]/status",
    ];
    for &url in tunnel_targets {
        var req_t = wing::new_get(url[..]);
        let _, err_t = wing::execute_request(session, req_t);
        t.assert_false(wing::ok(err_t), "IPv6 tunnel/compatible loopback must be blocked");
    }
}

// ----------------------------------------------------------------------------
// 3. CVE-2023-26159 & RFC 9110 Section 5.5: CRLF / Control-Char Header Injection
// ----------------------------------------------------------------------------
fn test_cve_crlf_header_injection(t: lit::T&) {
    t.run("Header Name with CRLF or Control Characters must be Sanitized/Rejected") { sub =>
        var req = wing::new_get("https://example.com/api");
        wing::set_header(req, "X-Injected\r\nEvil: true", "valid-value");

        var has_injected_crlf = false;
        for hdr in req.headers {
            for b in hdr.name {
                if b == '\r' || b == '\n' || b == 0 {
                    has_injected_crlf = true;
                }
            }
        }
        sub.assert_false(has_injected_crlf, "Header name must not contain raw CRLF or NUL control characters");
    };

    t.run("Header Value with CRLF must be Sanitized/Rejected") { sub =>
        var req = wing::new_get("https://example.com/api");
        wing::set_header(req, "X-Test", "value\r\nSet-Cookie: pwned=true");

        var has_injected_crlf = false;
        for hdr in req.headers {
            for b in hdr.value {
                if b == '\r' || b == '\n' || b == 0 {
                    has_injected_crlf = true;
                }
            }
        }
        sub.assert_false(has_injected_crlf, "Header value must not contain raw CRLF or NUL control characters");
    };
}

// ----------------------------------------------------------------------------
// 4. CVE-2022-27776 & CVE-2023-43804: Port-Change Credential Leak & Representation Headers
// ----------------------------------------------------------------------------
fn test_cve_port_change_and_representation_headers(t: lit::T&) {
    t.run("CVE-2022-27776: Port Change on Trusted Host Must Strip Authorization") { sub =>
        var req = wing::new_get("https://example.com:443/login");
        wing::set_header(req, "Authorization", "Bearer top_secret");
        wing::set_header(req, "X-API-Key", "secret-key-123");

        // Redirect to same hostname example.com, but different port 8443
        let redirect_info = wing::compute_redirect_info(
            "GET", 302, "https://example.com:443/login", "https://example.com:8443/admin",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://example.com:443/login",
            wing::RedirectOptions { .. },
        );

        sub.assert_true(redirect_info.is_cross_origin, "different port must be cross-origin");

        // Even with trusted_location_forwarding = true, port change must NOT leak credentials!
        wing::sanitize_headers_on_redirect(
            req.headers,
            redirect_info,
            wing::RedirectSanitizeOptions { enable_referer: true, trusted_location_forwarding: true },
        );

        var has_auth = false;
        var has_key = false;
        for hdr in req.headers {
            if core::eq_ascii_fold(hdr.name[..], "Authorization") { has_auth = true; }
            if core::eq_ascii_fold(hdr.name[..], "X-API-Key") { has_key = true; }
        }
        sub.assert_false(has_auth, "Authorization must be stripped across port change even if hostname is trusted");
        sub.assert_false(has_key, "X-API-Key must be stripped across port change even if hostname is trusted");
    };

    t.run("Cross-Origin Redirect Must Strip Signatures and CSRF Tokens") { sub =>
        var req = wing::new_post("https://example.com/api");
        wing::sign_hmac_sha256(req, "secret");
        wing::set_header(req, "X-CSRF-Token", "csrf-token-abc");

        let redirect_info = wing::compute_redirect_info(
            "POST", 302, "https://example.com/api", "https://other.com/api",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://example.com/api",
            wing::RedirectOptions { .. },
        );

        wing::sanitize_headers_on_redirect(
            req.headers,
            redirect_info,
            wing::RedirectSanitizeOptions { enable_referer: true },
        );

        var has_sig = false;
        var has_csrf = false;
        for hdr in req.headers {
            if core::eq_ascii_fold(hdr.name[..], "X-Signature-256") { has_sig = true; }
            if core::eq_ascii_fold(hdr.name[..], "X-CSRF-Token") { has_csrf = true; }
        }
        sub.assert_false(has_sig, "X-Signature-256 must be stripped on cross-origin redirect");
        sub.assert_false(has_csrf, "X-CSRF-Token must be stripped on cross-origin redirect");
    };

    t.run("Method Mutation to GET Must Strip Conditional / Representation Headers") { sub =>
        var req = wing::new_post("https://example.com/upload");
        wing::set_header(req, "If-Match", "\"etag-123\"");
        wing::set_header(req, "If-None-Match", "\"etag-456\"");
        wing::set_header(req, "Expect", "100-continue");

        let redirect_info = wing::compute_redirect_info(
            "POST", 303, "https://example.com/upload", "https://example.com/status",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://example.com/upload",
            wing::RedirectOptions { .. },
        );
        sub.assert_true(redirect_info.clear_body, "303 clears body");

        wing::sanitize_headers_on_redirect(
            req.headers,
            redirect_info,
            wing::RedirectSanitizeOptions { enable_referer: true },
        );

        var has_if_match = false;
        var has_if_none_match = false;
        var has_expect = false;
        for hdr in req.headers {
            if core::eq_ascii_fold(hdr.name[..], "If-Match") { has_if_match = true; }
            if core::eq_ascii_fold(hdr.name[..], "If-None-Match") { has_if_none_match = true; }
            if core::eq_ascii_fold(hdr.name[..], "Expect") { has_expect = true; }
        }
        sub.assert_false(has_if_match, "If-Match must be stripped when method mutates to GET");
        sub.assert_false(has_if_none_match, "If-None-Match must be stripped when method mutates to GET");
        sub.assert_false(has_expect, "Expect must be stripped when method mutates to GET");
    };
}

// ----------------------------------------------------------------------------
// 5. CVE-2023-27534 & CVE-2022-35252: Cookie URL Ambiguity & Query Ordering
// ----------------------------------------------------------------------------
fn test_cve_cookie_url_and_query_ordering(t: lit::T&) {
    t.run("parse_canonical_cookie_url: Userinfo and Fragment Isolation") { sub =>
        let u = wing::parse_canonical_cookie_url("https://user:pass@example.com:8443/a/b#section/1");
        sub.assert_bytes_eq(u.host[..], "example.com", "host must not include userinfo");
        sub.assert_eq(u.port, 8443, "port must be 8443");
        sub.assert_bytes_eq(u.path[..], "/a/b", "path must not include fragment");
    };

    t.run("set_cookie_header: Normalizes Path Dot-Segments") { sub =>
        var jar = wing::CanonicalCookieJar { .. };
        let clock = lit::new_mock_clock();

        let ok = wing::set_cookie_header(jar, "https://example.com/admin/../public", "sid=xyz", clock.now_us);
        sub.assert_true(ok, "cookie accepted");
        sub.assert_eq(jar.cookies.len, 1);
        if jar.cookies.len > 0 {
            sub.assert_bytes_eq(jar.cookies[0].path[..], "/", "default path must normalize /admin/.. to /");
        }
    };

    t.run("build_effective_url: Query Parameters Must Precede Fragment") { sub =>
        var out:    u8[..2048]           = [];
        var params: wing::QueryItem[..2] = [];
        var q1 = wing::QueryItem { .. };
        q1.key.append("tab");
        q1.value.append("profile");
        params.push(q1);

        wing::build_effective_url("https://example.com/account#overview", "", params[..], out);
        sub.assert_bytes_eq(out[..], "https://example.com/account?tab=profile#overview", "query parameters must be placed before fragment");
    };
}

// ----------------------------------------------------------------------------
// 6. CVE-2016-8616: PSL Supercookie & CTL Injection via Netscape Store Import
// ----------------------------------------------------------------------------
fn test_cve_netscape_import_security(t: lit::T&) {
    t.run("Netscape Import: Public Suffix Domain Supercookie Must Be Rejected") { sub =>
        var jar = wing::CanonicalCookieJar { .. };
        let clock = lit::new_mock_clock();

        let netscape_psl = "co.uk\tTRUE\t/\tFALSE\t0\tsupercookie\tevil\n";
        let count = wing::import_netscape(jar, netscape_psl, clock.now_us);

        sub.assert_eq(count, 0, "supercookie on public suffix co.uk must not be imported");
        sub.assert_eq(jar.cookies.len, 0, "jar must remain empty");
    };

    t.run("Netscape Import: CTL Character in Cookie Must Be Rejected") { sub =>
        var jar = wing::CanonicalCookieJar { .. };
        let clock = lit::new_mock_clock();

        let netscape_ctl = "example.com\tTRUE\t/\tFALSE\t0\tbad\x01name\tval\n";
        let count = wing::import_netscape(jar, netscape_ctl, clock.now_us);

        sub.assert_eq(count, 0, "cookie with CTL byte in name must not be imported");
        sub.assert_eq(jar.cookies.len, 0, "jar must remain empty");
    };
}

// ----------------------------------------------------------------------------
// 7. CVE-2026-94441: Unencrypted H2 vs HTTPS Transport & Pool Isolation
// ----------------------------------------------------------------------------
fn test_cve_2026_94441_h2_scheme_isolation(t: lit::T&) {
    t.run("PoolKey Scheme Isolation: Plaintext H2c Must Never Match HTTPS") { sub =>
        let nak = wing::new_network_anonymization_key("https://service.com");
        let direct = wing::new_direct_proxy_chain();
        let policy = wing::TlsAndDnsPolicy { .. };

        let key_https = wing::new_pool_key(wing::PoolScheme.Https, "service.com", 443, direct, nak, policy);
        let key_h2c = wing::new_pool_key(wing::PoolScheme.H2c, "service.com", 80, direct, nak, policy);
        let key_http = wing::new_pool_key(wing::PoolScheme.Http, "service.com", 80, direct, nak, policy);

        sub.assert_false(wing::pool_key_equals(key_https, key_h2c), "HTTPS key must never match unencrypted H2c");
        sub.assert_false(wing::pool_key_equals(key_https, key_http), "HTTPS key must never match unencrypted HTTP");
        sub.assert_false(wing::pool_key_equals(key_h2c, key_http), "H2c key must never match HTTP");
    };

    t.run("H2 IP Coalescing: Plaintext H2c Must Never Coalesce with HTTPS") { sub =>
        let nak = wing::new_network_anonymization_key("https://secure.com");
        let key_https = wing::new_pool_key(wing::PoolScheme.Https, "secure.com", 443, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });
        let key_h2c = wing::new_pool_key(wing::PoolScheme.H2c, "secure.com", 80, wing::new_direct_proxy_chain(), nak, wing::TlsAndDnsPolicy { .. });

        var conn_unencrypted = wing::PooledConnection {
            conn_id:    1,
            key:        key_h2c,
            protocol:   wing::NegotiatedProtocol.Http2,
            cert_valid: false,
            ..
        };
        conn_unencrypted.resolved_ip.append("93.184.216.34");

        // Attempt to coalesce an unencrypted H2 connection for an HTTPS target
        let can_coalesce, is_neg = wing::can_coalesce_h2_connection(conn_unencrypted, key_https, "93.184.216.34");
        sub.assert_false(can_coalesce, "Unencrypted HTTP/2 connection must NEVER coalesce for HTTPS request (CVE-2026-94441)");

        // StreamPool acquire must fail to match unencrypted socket for HTTPS
        var pool = wing::new_stream_pool(6, 32, 10);
        pool.conns.push(conn_unencrypted);

        let acq_id, ok_acq = wing::acquire_pooled_connection(pool, key_https, "93.184.216.34", 1000000000);
        sub.assert_false(ok_acq, "Acquire never returns unencrypted H2 socket for https:// request");
    };
}

// ----------------------------------------------------------------------------
// 8. CVE-2026-56866 & CVE-2026-94439: CONNECT Tunnel Desync & Buffer Hygiene
// ----------------------------------------------------------------------------
fn test_cve_connect_tunnel_security(t: lit::T&) {
    t.run("CVE-2026-56866: Prefix Data Injection Detection in CONNECT Response") { sub =>
        // Clean 200 OK CONNECT response
        let clean = "HTTP/1.1 200 Connection Established\r\n\r\n";
        let err_clean = wing::verify_connect_tunnel_response(clean, 0);
        sub.assert_true(err_clean == wing::ConnectTunnelError.None, "Clean 200 CONNECT approved");

        // Trailing bytes injected after \r\n\r\n
        let smuggled = "HTTP/1.1 200 Connection Established\r\n\r\nGET /smuggled HTTP/1.1\r\n";
        let err_smuggled = wing::verify_connect_tunnel_response(smuggled, 0);
        sub.assert_true(err_smuggled == wing::ConnectTunnelError.TunnelBufferedTooManyBytes, "Smuggled prefix caught by leftover buffer check");

        // Leftover bytes in client output sink
        let err_sink = wing::verify_connect_tunnel_response(clean, 8);
        sub.assert_true(err_sink == wing::ConnectTunnelError.TunnelBufferedTooManyBytes, "Sink buffer leftover bytes caught");
    };

    t.run("CVE-2026-56866 & CVE-2026-94439: Discard Sockets on Non-200 Rejection") { sub =>
        // 407 Proxy Authentication Required
        let resp_407 = "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";
        let err_407 = wing::verify_connect_tunnel_response(resp_407, 0);
        sub.assert_true(err_407 == wing::ConnectTunnelError.ProxyAuthRequired, "407 mapped to ProxyAuthRequired");

        // 502 Bad Gateway
        let resp_502 = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        let err_502 = wing::verify_connect_tunnel_response(resp_502, 0);
        sub.assert_true(err_502 == wing::ConnectTunnelError.ConnectFailed, "502 mapped to ConnectFailed");

        // Connection must be marked closed and never returned to pool
        var conn = wing::PooledConnection {
            conn_id:          42,
            no_new_exchanges: true,
            closed:           true,
            ..
        };
        sub.assert_false(wing::is_connection_healthy(conn, 1000000000, false), "Failed CONNECT connection is strictly unhealthy");
    };
}

// ----------------------------------------------------------------------------
// 9. CVE-2025-4673 & CVE-2021-33197: Proxy-Authorization & Hop-by-Hop Stripping
// ----------------------------------------------------------------------------
fn test_cve_proxy_authorization_leakage(t: lit::T&) {
    t.run("CVE-2025-4673: Strip Proxy-Authorization Before Origin Request") { sub =>
        var headers: wing::HeaderItem[..32] = [];
        headers.push(wing::make_header("Host", "target.com"));
        headers.push(wing::make_header("Proxy-Authorization", "Basic proxy_secret_cred"));
        headers.push(wing::make_header("PROXY-AUTHORIZATION", "Basic UPPERCASE_SECRET"));
        headers.push(wing::make_header("Proxy-Authenticate", "Basic realm=proxy"));
        headers.push(wing::make_header("Proxy-Connection", "Keep-Alive"));
        headers.push(wing::make_header("Authorization", "Bearer origin_token"));

        wing::sanitize_tunnel_headers_for_origin(headers);

        sub.assert_eq(headers.len, 2, "All proxy headers stripped");
        sub.assert_bytes_eq(headers[0].name[..], "Host", "Host header preserved");
        sub.assert_bytes_eq(headers[1].name[..], "Authorization", "Origin bearer token preserved");
    };

    t.run("CVE-2025-4673: Cross-Origin Redirect Must Strip Proxy-Authorization") { sub =>
        var req = wing::new_get("https://proxy.origin.com/resource");
        wing::set_header(req, "Proxy-Authorization", "Basic secret_proxy_tok");
        wing::set_header(req, "Authorization", "Bearer user_token");

        let redirect_info = wing::compute_redirect_info(
            "GET", 302, "https://proxy.origin.com/resource", "https://other-domain.com/landing",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://proxy.origin.com/resource",
            wing::RedirectOptions { .. },
        );

        wing::sanitize_headers_on_redirect(req.headers, redirect_info, wing::RedirectSanitizeOptions { .. });

        var has_proxy_auth = false;
        var has_user_auth = false;
        for hdr in req.headers {
            if core::eq_ascii_fold(hdr.name[..], "Proxy-Authorization") { has_proxy_auth = true; }
            if core::eq_ascii_fold(hdr.name[..], "Authorization") { has_user_auth = true; }
        }
        sub.assert_false(has_proxy_auth, "Proxy-Authorization must be stripped on cross-origin redirect (CVE-2025-4673)");
        sub.assert_false(has_user_auth, "Authorization must be stripped on cross-origin redirect");
    };
}

// ----------------------------------------------------------------------------
// 10. CVE-2025-22870: IPv6 Zone ID Proxy Bypass & SSRF Defense
// ----------------------------------------------------------------------------
fn test_cve_ipv6_zone_id_proxy_bypass(t: lit::T&) {
    var session = wing::new_session();
    wing::enable_ssrf_guard(session, true);

    // IPv6 link-local with zone ID
    var req_ll = wing::new_get("http://[fe80::1%25eth0]/admin");
    let res_ll, err_ll = wing::execute_request(session, req_ll);
    t.assert_false(wing::ok(err_ll), "Link-local IPv6 with zone ID must be blocked by SSRF guard (CVE-2025-22870)");
}

// ----------------------------------------------------------------------------
// 11. Go #81671 & RFC 9110: QUERY Method Replayability
// ----------------------------------------------------------------------------
fn test_go_81671_query_method_replayable(t: lit::T&) {
    t.run("Go #81671: QUERY Method Replayability on Stale Socket Drop") { sub =>
        sub.assert_true(wing::is_idempotent_method("QUERY"), "QUERY is semantically idempotent per RFC 9110");
        sub.assert_true(wing::is_idempotent_method("query"), "QUERY case-insensitive check matches");

        var req = wing::new_request("QUERY", "https://api.io/search");
        wing::text(req, "{\"filter\": \"status=active\"}");

        // On reused socket before response headers arrived, QUERY is replayable
        let can_retry = wing::should_retry_tier1_stale_socket(true, req);
        sub.assert_true(can_retry, "QUERY request replayable on stale Keep-Alive connection drop (Go #81671)");

        // If body is unrewindable, must NOT retry (protecting payload integrity)
        req.rewindable = false;
        let cant_retry_unrewind = wing::should_retry_tier1_stale_socket(true, req);
        sub.assert_false(cant_retry_unrewind, "Unrewindable QUERY request must not be retried");
    };
}

// ----------------------------------------------------------------------------
// Suite Entry Point
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 12. Go #58547 / CVE-2023-24538: MIME Parameter Escaped Quotes & Semicolons
// ----------------------------------------------------------------------------
fn test_cve_2023_24538_mime_param_escaped_quotes(t: lit::T&) {
    t.run("Escaped quote with semicolon inside parameter value (Go #58547)") { sub =>
        let raw_ct = "text/html; title=\"hello \\\"; foo=bar\"; charset=utf-8";
        let mt, ok = wing::parse_media_type(raw_ct);
        sub.assert_true(ok, "MIME parsing must succeed with escaped quote and semicolon");
        sub.assert_bytes_eq(mt.mime_type[..], "text/html", "Mime type text/html");
        sub.assert_eq(mt.params.len, 2, "Must have exactly 2 parameters");
        sub.assert_bytes_eq(mt.params[0].name[..], "title", "Param 0 name is title");
        sub.assert_bytes_eq(mt.params[0].value[..], "hello \"; foo=bar", "Param 0 value preserves internal semicolon");
        sub.assert_bytes_eq(mt.params[1].name[..], "charset", "Param 1 name is charset");
        sub.assert_bytes_eq(mt.params[1].value[..], "utf-8", "Param 1 value is utf-8");
    };
}

// ----------------------------------------------------------------------------
// 13. RFC 6455 & Go WebSocket Issue #328: RSV Bit Invariants & Masking Enforcement
// ----------------------------------------------------------------------------
fn test_rfc6455_websocket_security_invariants(t: lit::T&) {
    t.run("RSV1/RSV2/RSV3 bit injection MUST trigger 1002 Protocol Error") { sub =>
        var client_ws = wing::new_websocket_session(true);

        // Frame with RSV1 = 1 (0x40)
        let rsv1_frame: u8[2] = [0xC1, 0x00]; // FIN=1, RSV1=1, Opcode=1 (Text), Length=0
        var msg = wing::WsMessage { .. };
        var reply: u8[>..] = [];
        let handled = client_ws.receive(rsv1_frame[..], msg, reply);
        sub.assert_true(client_ws.is_closed, "Connection closed on non-zero RSV bit");
        sub.assert_eq(client_ws.close_code, wing::WS_STATUS_PROTOCOL_ERROR, "Protocol error 1002 on RSV bit");
    };

    t.run("Client receiving masked frame MUST trigger 1002 Protocol Error (RFC 6455 Section 5.1)") { sub =>
        var client_ws = wing::new_websocket_session(true);

        // Masked server frame sent to client
        let mask: u8[4] = [1, 2, 3, 4];
        var masked_frame: u8[>..] = [];
        wing::encode_ws_frame(masked_frame, wing::WS_OPCODE_TEXT, "hello", true, mask, true);

        var msg = wing::WsMessage { .. };
        var reply: u8[>..] = [];
        client_ws.receive(masked_frame[..], msg, reply);
        sub.assert_true(client_ws.is_closed, "Client MUST fail connection on masked frame from server");
        sub.assert_eq(client_ws.close_code, wing::WS_STATUS_PROTOCOL_ERROR, "1002 Protocol Error on masked server frame");
    };

    t.run("Server receiving unmasked frame MUST trigger 1002 Protocol Error (RFC 6455 Section 5.1)") { sub =>
        var server_ws = wing::new_websocket_session(false); // is_client = false

        // Unmasked client frame sent to server
        let no_mask: u8[4] = [0, 0, 0, 0];
        var unmasked_frame: u8[>..] = [];
        wing::encode_ws_frame(unmasked_frame, wing::WS_OPCODE_TEXT, "hello", false, no_mask, true);

        var msg = wing::WsMessage { .. };
        var reply: u8[>..] = [];
        server_ws.receive(unmasked_frame[..], msg, reply);
        sub.assert_true(server_ws.is_closed, "Server MUST fail connection on unmasked frame from client");
        sub.assert_eq(server_ws.close_code, wing::WS_STATUS_PROTOCOL_ERROR, "1002 Protocol Error on unmasked client frame");
    };
}

// ----------------------------------------------------------------------------
// 14. Go #40928 & RFC 7301 Section 3.1: ALPN NUL Byte Injection & Empty List
// ----------------------------------------------------------------------------
fn test_cve_alpn_nul_byte_and_empty_list(t: lit::T&) {
    t.run("ALPN with embedded NUL byte MUST be rejected (RFC 7301 Section 3.1)") { sub =>
        // Protocol list: ["h2\0", "h2"] -> 1st entry has embedded NUL byte
        let alpn_nul: u8[9] = [0x00, 0x07, 0x03, 'h', '2', 0x00, 0x02, 'h', '2'];
        let res = wing::negotiate_alpn(alpn_nul[..], false);
        sub.assert_true(res == wing::NegotiatedAlpn.None, "ALPN with embedded NUL byte must negotiate None (RFC 7301)");
    };

    t.run("ALPN with empty list (0 length) MUST be rejected") { sub =>
        let alpn_zero_list: u8[2] = [0x00, 0x00];
        let res = wing::negotiate_alpn(alpn_zero_list[..], false);
        sub.assert_true(res == wing::NegotiatedAlpn.None, "ALPN with 0-length list must negotiate None");
    };
}
// ----------------------------------------------------------------------------
// 15. Go #66434 / #63855 & RFC 7578 Section 4.7: Content-Transfer-Encoding Rejection
// ----------------------------------------------------------------------------
fn test_cve_rfc7578_reject_content_transfer_encoding(t: lit::T&) {
    t.run("Multipart form-data part containing Content-Transfer-Encoding MUST be rejected") { sub =>
        let boundary = "boundary123";
        let body = "--boundary123\r\nContent-Disposition: form-data; name=\"upload\"\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--boundary123--\r\n";

        let msg, err = wing::parse_multipart(body, boundary);
        sub.assert_false(wing::is_ok(err), "RFC 7578 Section 4.7: Content-Transfer-Encoding in multipart MUST be rejected");
        sub.assert_false(msg.valid, "Multipart message marked invalid");
    };
}

// ----------------------------------------------------------------------------
// 16. Go #64433 / CVE-2023-39326: Chunk Extension Line Overflow Defense
// ----------------------------------------------------------------------------
fn test_cve_2023_39326_chunk_extension_overflow(t: lit::T&) {
    t.run("Chunk size line with excessive extension (> 1024 bytes) MUST be rejected") { sub =>
        var raw: u8[>..] = [];
        raw.append("5;ext=");
        for i in 1050 { raw.push('A'); }
        raw.append("\r\nhello\r\n0\r\n\r\n");

        var out: u8[>..] = [];
        let err = wing::decode_chunked_body(raw[..], out);
        sub.assert_true(err == wing::ChunkedDecodeError.InvalidChunkExtension, "Excessive chunk extension must be rejected with InvalidChunkExtension");
    };
}

// ----------------------------------------------------------------------------
// 17. Go #60997 & RFC 6265bis: CookieJar Secure Cookie Exemption on Localhost
// ----------------------------------------------------------------------------
fn test_go_60997_localhost_secure_cookies(t: lit::T&) {
    var session = wing::new_session();

    wing::mock_route(session, "GET", "http://localhost:8080/login", 200, "ok");
    wing::add_mock_set_cookie(session, "sid=local_secret; Secure; HttpOnly; SameSite=None; Path=/");

    let req1 = wing::new_get("http://localhost:8080/login");
    let res1, err1 = wing::execute_request(session, req1);
    t.assert_true(wing::ok(err1), "Login request to localhost succeeded");
    t.assert_bytes_eq(wing::cookie(session, "sid"), "local_secret", "Secure cookie must be accepted on http://localhost");

    wing::mock_route(session, "GET", "http://localhost:8080/api", 200, "data");

    let req2 = wing::new_get("http://localhost:8080/api");
    let res2, err2 = wing::execute_request(session, req2);
    t.assert_true(wing::ok(err2), "API request to localhost succeeded");
}

// ----------------------------------------------------------------------------
// 18. Go #81741 / CVE-2026-94440 & Go #65383 / CVE-2023-45290: Multipart Memory Limit
// ----------------------------------------------------------------------------
fn test_cve_2026_94440_multipart_memory_header_accounting(t: lit::T&) {
    t.run("Multipart form memory limit must account for header bytes (Go #81741 & CVE-2026-94440)") { sub =>
        let boundary = "bound999";
        var body: u8[>..] = [];
        body.append("--bound999\r\nContent-Disposition: form-data; name=\"field\"\r\nX-Padding: ");
        for i in 1200 { body.push('X'); }
        body.append("\r\n\r\nsmall_payload\r\n--bound999--\r\n");

        var options = wing::MultipartOptions { .. };
        options.max_memory_bytes = 1000; // Small limit: 1000 bytes

        let msg, err = wing::parse_multipart(body[..], boundary, options);
        sub.assert_true(err == wing::MultipartError.ExceededMaxMemory, "Form with 1200-byte header must exceed 1000-byte max_memory_bytes");
        sub.assert_false(msg.valid, "Multipart marked invalid on memory limit breach");
    };
}

// ----------------------------------------------------------------------------
// 19. Go #16875 & RFC 9110 Section 7.6.1: Proxy Hop-by-Hop Header Sanitization
// ----------------------------------------------------------------------------
fn test_rfc9110_proxy_hop_by_hop_sanitization(t: lit::T&) {
    t.run("Proxy header sanitization must strip standard hop-by-hop headers and connection tokens (RFC 9110 & Go #16875)") { sub =>
        var headers: wing::HeaderItem[..32] = [];
        headers.push(wing::make_header("Host", "origin.example.com", false));
        headers.push(wing::make_header("Proxy-Authorization", "Basic c2VjcmV0", false));
        headers.push(wing::make_header("Connection", "keep-alive, x-forwarded-hop", false));
        headers.push(wing::make_header("Keep-Alive", "timeout=5", false));
        headers.push(wing::make_header("Transfer-Encoding", "chunked", false));
        headers.push(wing::make_header("X-Forwarded-Hop", "strip-me", false));
        headers.push(wing::make_header("Accept", "application/json", false));

        wing::sanitize_tunnel_headers_for_origin(headers);

        sub.assert_eq(headers.len, 2, "Only non-hop-by-hop headers (Host, Accept) should remain");
        sub.assert_bytes_eq(headers[0].name[..], "Host", "Header 0 is Host");
        sub.assert_bytes_eq(headers[1].name[..], "Accept", "Header 1 is Accept");
    };
}

// ----------------------------------------------------------------------------
// 20. Go #78762 & RFC 9113 Section 8.3.1: HTTP/2 :path Pseudo-Header Validation
// ----------------------------------------------------------------------------
fn test_rfc9113_http2_path_pseudo_header_validation(t: lit::T&) {
    t.run("HTTP/2 :path with absolute URL MUST be rejected (RFC 9113 Section 8.3.1 & Go #78762)") { sub =>
        var dt_enc = internal::new_dynamic_table(4096);
        var raw_bytes: u8[>..] = [];
        internal::encode_hpack_field(dt_enc, raw_bytes, ":path", "http://evil.com/admin", internal::HpackIndexing.None, false);

        var dt_dec = internal::new_dynamic_table(4096);
        var out_list = internal::DecodedH2HeaderList { .. };
        let err = internal::decode_hpack_header_block(dt_dec, raw_bytes[..], out_list, 8192, true);
        sub.assert_eq(err, internal::ERR_PROTOCOL_ERROR, "Absolute URL in :path MUST return ERR_PROTOCOL_ERROR");
    };

    t.run("HTTP/2 :path empty MUST be rejected") { sub =>
        var dt_enc = internal::new_dynamic_table(4096);
        var raw_bytes: u8[>..] = [];
        internal::encode_hpack_field(dt_enc, raw_bytes, ":path", "", internal::HpackIndexing.None, false);

        var dt_dec = internal::new_dynamic_table(4096);
        var out_list = internal::DecodedH2HeaderList { .. };
        let err = internal::decode_hpack_header_block(dt_dec, raw_bytes[..], out_list, 8192, true);
        sub.assert_eq(err, internal::ERR_PROTOCOL_ERROR, "Empty :path MUST return ERR_PROTOCOL_ERROR");
    };
}

// ----------------------------------------------------------------------------
// 21. Go #75672 / CVE-2025-58186: Cookie Parsing Memory Exhaustion / Flood Defense
// ----------------------------------------------------------------------------
fn test_cve_2025_58186_cookie_parsing_memory_exhaustion(t: lit::T&) {
    t.run("Cookie header with 250 small pairs must be bounded to max_cookies (Go #75672)") { sub =>
        var raw_hdr: u8[>..] = [];
        for i in 250 {
            raw_hdr.append("c");
            format(raw_hdr, i);
            raw_hdr.push('=');
            format(raw_hdr, i);
            raw_hdr.append("; ");
        }

        var out: wing::CanonicalCookie[>..] = [];
        wing::parse_server_cookie_header(raw_hdr[..], out);
        sub.assert_eq(out.len, 100, "Server-side cookie parsing MUST be capped at 100 to prevent DoS (CVE-2025-58186)");
    };
}

// ----------------------------------------------------------------------------
// 22. Go #79944 & RFC 6055: FQDN Trailing Dot Host-Only Cookie Matching
// ----------------------------------------------------------------------------
fn test_rfc6055_fqdn_trailing_dot_cookie_matching(t: lit::T&) {
    t.run("Host-only cookie must match FQDN with trailing dot (RFC 6055 & Go #79944)") { sub =>
        var c = wing::CanonicalCookie { host_only: true, .. };
        c.domain.append("example.com");

        sub.assert_true(wing::matches_domain(c, "example.com"), "Matches exact host");
        sub.assert_true(wing::matches_domain(c, "example.com."), "Must match FQDN with trailing dot");
        sub.assert_false(wing::matches_domain(c, "evil.com"), "Must not match different domain");
    };
}

fn main() {
    let _ = wing::tcp_init();
    var dummy: u8[4] = [0, 0, 0, 0];
    wing::swar_to_lower(dummy[..]);

    var runner = lit::new_runner("CVE Regression Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. CVE-2021-28918 & CVE-2021-29922 (Octal/Hex/Dword/Shorthand IPv4 SSRF)", test_cve_ipv4_formats_ssrf);
    lit::run_case(runner, "2. CVE-2024-24790 & RFC 6761 (Localhost, Uncompressed IPv6 & Tunnel SSRF)", test_cve_localhost_and_ipv6_tunnels_ssrf);
    lit::run_case(runner, "3. CVE-2023-26159 & RFC 9110 (CRLF / Control-Char Header Injection)", test_cve_crlf_header_injection);
    lit::run_case(runner, "4. CVE-2022-27776 & CVE-2023-43804 (Port Change Credential Leaks & Headers)", test_cve_port_change_and_representation_headers);
    lit::run_case(runner, "5. CVE-2023-27534 & CVE-2022-35252 (Cookie URL Ambiguity & Query Ordering)", test_cve_cookie_url_and_query_ordering);
    lit::run_case(runner, "6. CVE-2016-8616 (PSL Supercookie & CTL Injection in Store Import)", test_cve_netscape_import_security);
    lit::run_case(runner, "7. CVE-2026-94441 (Unencrypted H2 vs HTTPS Scheme & Pool Isolation)", test_cve_2026_94441_h2_scheme_isolation);
    lit::run_case(runner, "8. CVE-2026-56866 & CVE-2026-94439 (CONNECT Tunnel Desync & Buffer Hygiene)", test_cve_connect_tunnel_security);
    lit::run_case(runner, "9. CVE-2025-4673 & CVE-2021-33197 (Proxy-Authorization Leakage & Header Stripping)", test_cve_proxy_authorization_leakage);
    lit::run_case(runner, "10. CVE-2025-22870 (IPv6 Zone ID Proxy Bypass & SSRF Defense)", test_cve_ipv6_zone_id_proxy_bypass);
    lit::run_case(runner, "11. Go #81671 & RFC 9110 (QUERY Method Replayability)", test_go_81671_query_method_replayable);
    lit::run_case(runner, "12. Go #58547 (MIME Parameter Escaped Quotes & Semicolons)", test_cve_2023_24538_mime_param_escaped_quotes);
    lit::run_case(runner, "13. RFC 6455 & Go WS #328 (RSV Bit Invariants & Masking Rules)", test_rfc6455_websocket_security_invariants);
    lit::run_case(runner, "14. Go #40928 & RFC 7301 (ALPN NUL Injection & Empty List)", test_cve_alpn_nul_byte_and_empty_list);
    lit::run_case(runner, "15. Go #66434 & RFC 7578 (Content-Transfer-Encoding Rejection)", test_cve_rfc7578_reject_content_transfer_encoding);
    lit::run_case(runner, "16. Go #64433 / CVE-2023-39326 (Chunk Extension Line Overflow Defense)", test_cve_2023_39326_chunk_extension_overflow);
    lit::run_case(runner, "17. Go #60997 & RFC 6265bis (Localhost Secure Cookie Exemption)", test_go_60997_localhost_secure_cookies);
    lit::run_case(runner, "18. Go #81741 & CVE-2026-94440 (Multipart Memory Limit Overhead)", test_cve_2026_94440_multipart_memory_header_accounting);
    lit::run_case(runner, "19. Go #16875 & RFC 9110 (Proxy Hop-by-Hop Header Sanitization)", test_rfc9110_proxy_hop_by_hop_sanitization);
    lit::run_case(runner, "20. Go #78762 & RFC 9113 (HTTP/2 :path Pseudo-Header Validation)", test_rfc9113_http2_path_pseudo_header_validation);
    lit::run_case(runner, "21. Go #75672 & CVE-2025-58186 (Cookie Parsing Memory Exhaustion)", test_cve_2025_58186_cookie_parsing_memory_exhaustion);
    lit::run_case(runner, "22. Go #79944 & RFC 6055 (FQDN Trailing Dot Cookie Matching)", test_rfc6055_fqdn_trailing_dot_cookie_matching);

    let ok = lit::finish(runner);
    assert(ok);
}
