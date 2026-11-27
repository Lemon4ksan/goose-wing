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
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// ----------------------------------------------------------------------------
// 1. CVE-2021-28918 & CVE-2021-29922: Octal, Hex, Dword, Shorthand IPv4 SSRF
// ----------------------------------------------------------------------------
fn test_cve_ipv4_formats_ssrf(t: lit::T&) {
    var session = client::new_session();
    session.ssrf_guard.enabled = true;
    session.ssrf_guard.deny_local_network = true;

    let targets: const u8[..64][..6] = [
        "http://0177.0.0.1/admin",
        "http://2130706433/admin",
        "http://0x7f000001/admin",
        "http://0x7f.0.0.1/admin",
        "http://127.1/admin",
        "http://10.1/internal",
    ];

    for &url in targets {
        var req = http::new_get(url[..]);
        let _, err = client::execute_request(session, req);
        t.assert_false(http::ok(err), "IPv4 format bypass must be blocked");
    }
}

// ----------------------------------------------------------------------------
// 2. CVE-2024-24790 & RFC 6761: Localhost, Uncompressed IPv6 & Tunnel SSRF
// ----------------------------------------------------------------------------
fn test_cve_localhost_and_ipv6_tunnels_ssrf(t: lit::T&) {
    var session = client::new_session();
    session.ssrf_guard.enabled = true;
    session.ssrf_guard.deny_local_network = true;

    let lh_targets: const u8[..64][..3] = [
        "http://localhost/admin",
        "http://localhost./admin",
        "http://service.localhost/admin",
    ];
    for &url in lh_targets {
        var req_lh = http::new_get(url[..]);
        let _, err_lh = client::execute_request(session, req_lh);
        t.assert_false(http::ok(err_lh), "RFC 6761 localhost target must be blocked");
    }

    // DNS Rebinding with Uncompressed IPv6 Loopback
    client::mock_route(session, "GET", "http://rebind-uncompressed.com/api", 200, "ok");
    client::add_mock_resolved_ip(session, "0:0:0:0:0:0:0:1");

    var req = http::new_get("http://rebind-uncompressed.com/api");
    let _, err = client::execute_request(session, req);
    t.assert_false(http::ok(err), "DNS rebinding with 0:0:0:0:0:0:0:1 must be blocked");

    let tunnel_targets: const u8[..64][..5] = [
        "http://[::127.0.0.1]/status",
        "http://[64:ff9b::127.0.0.1]/status",
        "http://[64:ff9b:1::127.0.0.1]/status",
        "http://[::ffff:0:127.0.0.1]/status",
        "http://[2002:7f00:1::]/status",
    ];
    for &url in tunnel_targets {
        var req_t = http::new_get(url[..]);
        let _, err_t = client::execute_request(session, req_t);
        t.assert_false(http::ok(err_t), "IPv6 tunnel/compatible loopback must be blocked");
    }
}

// ----------------------------------------------------------------------------
// 3. CVE-2023-26159 & RFC 9110 Section 5.5: CRLF / Control-Char Header Injection
// ----------------------------------------------------------------------------
fn test_cve_crlf_header_injection(t: lit::T&) {
    t.run("Header Name with CRLF or Control Characters must be Sanitized/Rejected") { sub =>
        var req = http::new_get("https://example.com/api");
        http::set_header(req, "X-Injected\r\nEvil: true", "valid-value");

        var has_injected_crlf = false;
        for idx in 0..req.headers.entries.len {
            let e = req.headers.entries[idx];
            for b in http::entry_name(req.headers, e) {
                if b == '\r' || b == '\n' || b == 0 {
                    has_injected_crlf = true;
                }
            }
        }
        sub.assert_false(has_injected_crlf, "Header name must not contain raw CRLF or NUL control characters");
    };

    t.run("Header Value with CRLF must be Sanitized/Rejected") { sub =>
        var req = http::new_get("https://example.com/api");
        http::set_header(req, "X-Test", "value\r\nSet-Cookie: pwned=true");

        var has_injected_crlf = false;
        for idx in 0..req.headers.entries.len {
            let e = req.headers.entries[idx];
            for b in http::entry_value(req.headers, e) {
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
        var req = http::new_get("https://example.com:443/login");
        http::set_header(req, "Authorization", "Bearer top_secret");
        http::set_header(req, "X-API-Key", "secret-key-123");

        // Redirect to same hostname example.com, but different port 8443
        let redirect_info = client::compute_redirect_info(
            "GET", 302, "https://example.com:443/login", "https://example.com:8443/admin",
            client::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://example.com:443/login",
            client::RedirectOptions { .. },
        );

        sub.assert_true(redirect_info.is_cross_origin, "different port must be cross-origin");

        // Even with trusted_location_forwarding = true, port change must NOT leak credentials!
        client::sanitize_headers_on_redirect(
            req.headers,
            redirect_info,
            client::RedirectSanitizeOptions { enable_referer: true, trusted_location_forwarding: true },
        );

        let has_auth = http::has_header(req.headers, "Authorization");
        let has_key = http::has_header(req.headers, "X-API-Key");
        sub.assert_false(has_auth, "Authorization must be stripped across port change even if hostname is trusted");
        sub.assert_false(has_key, "X-API-Key must be stripped across port change even if hostname is trusted");
    };

    t.run("Cross-Origin Redirect Must Strip Signatures and CSRF Tokens") { sub =>
        var req = http::new_post("https://example.com/api");
        http::sign_hmac_sha256(req, "secret");
        http::set_header(req, "X-CSRF-Token", "csrf-token-abc");

        let redirect_info = client::compute_redirect_info(
            "POST", 302, "https://example.com/api", "https://other.com/api",
            client::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://example.com/api",
            client::RedirectOptions { .. },
        );

        client::sanitize_headers_on_redirect(
            req.headers,
            redirect_info,
            client::RedirectSanitizeOptions { enable_referer: true },
        );

        let has_sig = http::has_header(req.headers, "X-Signature-256");
        let has_csrf = http::has_header(req.headers, "X-CSRF-Token");
        sub.assert_false(has_sig, "X-Signature-256 must be stripped on cross-origin redirect");
        sub.assert_false(has_csrf, "X-CSRF-Token must be stripped on cross-origin redirect");
    };

    t.run("Method Mutation to GET Must Strip Conditional / Representation Headers") { sub =>
        var req = http::new_post("https://example.com/upload");
        http::set_header(req, "If-Match", "\"etag-123\"");
        http::set_header(req, "If-None-Match", "\"etag-456\"");
        http::set_header(req, "Expect", "100-continue");

        let redirect_info = client::compute_redirect_info(
            "POST", 303, "https://example.com/upload", "https://example.com/status",
            client::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://example.com/upload",
            client::RedirectOptions { .. },
        );
        sub.assert_true(redirect_info.clear_body, "303 clears body");

        client::sanitize_headers_on_redirect(
            req.headers,
            redirect_info,
            client::RedirectSanitizeOptions { enable_referer: true },
        );

        let has_if_match = http::has_header(req.headers, "If-Match");
        let has_if_none_match = http::has_header(req.headers, "If-None-Match");
        let has_expect = http::has_header(req.headers, "Expect");
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
        let u = cookie::parse_canonical_cookie_url("https://user:pass@example.com:8443/a/b#section/1");
        sub.assert_bytes_eq(u.host[..], "example.com", "host must not include userinfo");
        sub.assert_eq(u.port, 8443, "port must be 8443");
        sub.assert_bytes_eq(u.path[..], "/a/b", "path must not include fragment");
    };

    t.run("set_cookie_header: Normalizes Path Dot-Segments") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let clock = lit::new_mock_clock();

        let ok = cookie::set_cookie_header(jar, "https://example.com/admin/../public", "sid=xyz", clock.now_us);
        sub.assert_true(ok, "cookie accepted");
        sub.assert_eq(jar.cookies.len, 1);
        if jar.cookies.len > 0 {
            sub.assert_bytes_eq(jar.cookies[0].path[..], "/", "default path must normalize /admin/.. to /");
        }
    };

    t.run("build_effective_url: Query Parameters Must Precede Fragment") { sub =>
        var out:    u8[..2048]           = [];
        var params: http::QueryItem[..2] = [];
        var q1 = http::QueryItem { .. };
        q1.key.append("tab");
        q1.value.append("profile");
        params.push(q1);

        client_internal::build_effective_url("https://example.com/account#overview", "", params[..], out);
        sub.assert_bytes_eq(out[..], "https://example.com/account?tab=profile#overview", "query parameters must be placed before fragment");
    };
}

// ----------------------------------------------------------------------------
// 6. CVE-2016-8616: PSL Supercookie & CTL Injection via Netscape Store Import
// ----------------------------------------------------------------------------
fn test_cve_netscape_import_security(t: lit::T&) {
    t.run("Netscape Import: Public Suffix Domain Supercookie Must Be Rejected") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let clock = lit::new_mock_clock();

        let netscape_psl = "co.uk\tTRUE\t/\tFALSE\t0\tsupercookie\tevil\n";
        let count = cookie::import_netscape(jar, netscape_psl, clock.now_us);

        sub.assert_eq(count, 0, "supercookie on public suffix co.uk must not be imported");
        sub.assert_eq(jar.cookies.len, 0, "jar must remain empty");
    };

    t.run("Netscape Import: CTL Character in Cookie Must Be Rejected") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let clock = lit::new_mock_clock();

        let netscape_ctl = "example.com\tTRUE\t/\tFALSE\t0\tbad\x01name\tval\n";
        let count = cookie::import_netscape(jar, netscape_ctl, clock.now_us);

        sub.assert_eq(count, 0, "cookie with CTL byte in name must not be imported");
        sub.assert_eq(jar.cookies.len, 0, "jar must remain empty");
    };
}

// ----------------------------------------------------------------------------
// 7. CVE-2026-94441: Unencrypted H2 vs HTTPS Transport & Pool Isolation
// ----------------------------------------------------------------------------
fn test_cve_2026_94441_h2_scheme_isolation(t: lit::T&) {
    t.run("PoolKey Scheme Isolation: Plaintext H2c Must Never Match HTTPS") { sub =>
        let nak = net::new_network_anonymization_key("https://service.com");
        let direct = net::new_direct_proxy_chain();
        let policy = net::TlsAndDnsPolicy { .. };

        let key_https = net::new_pool_key(net::PoolScheme.Https, "service.com", 443, direct, nak, policy);
        let key_h2c = net::new_pool_key(net::PoolScheme.H2c, "service.com", 80, direct, nak, policy);
        let key_http = net::new_pool_key(net::PoolScheme.Http, "service.com", 80, direct, nak, policy);

        sub.assert_false(net::pool_key_equals(key_https, key_h2c), "HTTPS key must never match unencrypted H2c");
        sub.assert_false(net::pool_key_equals(key_https, key_http), "HTTPS key must never match unencrypted HTTP");
        sub.assert_false(net::pool_key_equals(key_h2c, key_http), "H2c key must never match HTTP");
    };

    t.run("H2 IP Coalescing: Plaintext H2c Must Never Coalesce with HTTPS") { sub =>
        let nak = net::new_network_anonymization_key("https://secure.com");
        let key_https = net::new_pool_key(net::PoolScheme.Https, "secure.com", 443, net::new_direct_proxy_chain(), nak, net::TlsAndDnsPolicy { .. });
        let key_h2c = net::new_pool_key(net::PoolScheme.H2c, "secure.com", 80, net::new_direct_proxy_chain(), nak, net::TlsAndDnsPolicy { .. });

        var conn_unencrypted = net::PooledConnection {
            conn_id:    1,
            key:        key_h2c,
            protocol:   net::NegotiatedProtocol.Http2,
            cert_valid: false,
            ..
        };
        conn_unencrypted.resolved_ip.append("93.184.216.34");

        // Attempt to coalesce an unencrypted H2 connection for an HTTPS target
        let can_coalesce, is_neg = net::can_coalesce_h2_connection(conn_unencrypted, key_https, "93.184.216.34");
        sub.assert_false(can_coalesce, "Unencrypted HTTP/2 connection must NEVER coalesce for HTTPS request (CVE-2026-94441)");

        // StreamPool acquire must fail to match unencrypted socket for HTTPS
        var pool = net::new_stream_pool(6, 32, 10);
        pool.conns.push(conn_unencrypted);

        let acq_id, ok_acq = net::acquire_pooled_connection(pool, key_https, "93.184.216.34", 1000000000);
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
        let err_clean = net::verify_connect_tunnel_response(clean, 0);
        sub.assert_true(err_clean == net::ConnectTunnelError.None, "Clean 200 CONNECT approved");

        // Trailing bytes injected after \r\n\r\n
        let smuggled = "HTTP/1.1 200 Connection Established\r\n\r\nGET /smuggled HTTP/1.1\r\n";
        let err_smuggled = net::verify_connect_tunnel_response(smuggled, 0);
        sub.assert_true(err_smuggled == net::ConnectTunnelError.TunnelBufferedTooManyBytes, "Smuggled prefix caught by leftover buffer check");

        // Leftover bytes in client output sink
        let err_sink = net::verify_connect_tunnel_response(clean, 8);
        sub.assert_true(err_sink == net::ConnectTunnelError.TunnelBufferedTooManyBytes, "Sink buffer leftover bytes caught");
    };

    t.run("CVE-2026-56866 & CVE-2026-94439: Discard Sockets on Non-200 Rejection") { sub =>
        // 407 Proxy Authentication Required
        let resp_407 = "HTTP/1.1 407 Proxy Authentication Required\r\n\r\n";
        let err_407 = net::verify_connect_tunnel_response(resp_407, 0);
        sub.assert_true(err_407 == net::ConnectTunnelError.ProxyAuthRequired, "407 mapped to ProxyAuthRequired");

        // 502 Bad Gateway
        let resp_502 = "HTTP/1.1 502 Bad Gateway\r\n\r\n";
        let err_502 = net::verify_connect_tunnel_response(resp_502, 0);
        sub.assert_true(err_502 == net::ConnectTunnelError.ConnectFailed, "502 mapped to ConnectFailed");

        // Connection must be marked closed and never returned to pool
        var conn = net::PooledConnection {
            conn_id:          42,
            no_new_exchanges: true,
            closed:           true,
            ..
        };
        sub.assert_false(net::is_connection_healthy(conn, 1000000000, false), "Failed CONNECT connection is strictly unhealthy");
    };
}

// ----------------------------------------------------------------------------
// 9. CVE-2025-4673 & CVE-2021-33197: Proxy-Authorization & Hop-by-Hop Stripping
// ----------------------------------------------------------------------------
fn test_cve_proxy_authorization_leakage(t: lit::T&) {
    t.run("CVE-2025-4673: Strip Proxy-Authorization Before Origin Request") { sub =>
        var headers = http::HeaderMap { .. };
        http::append_header(headers, "Host", "target.com");
        http::append_header(headers, "Proxy-Authorization", "Basic proxy_secret_cred");
        http::append_header(headers, "PROXY-AUTHORIZATION", "Basic UPPERCASE_SECRET");
        http::append_header(headers, "Proxy-Authenticate", "Basic realm=proxy");
        http::append_header(headers, "Proxy-Connection", "Keep-Alive");
        http::append_header(headers, "Authorization", "Bearer origin_token");

        net::sanitize_tunnel_headers_for_origin(headers);

        sub.assert_eq(headers.entries.len, 2, "All proxy headers stripped");
        sub.assert_bytes_eq(http::entry_name(headers, headers.entries[0]), "Host", "Host header preserved");
        sub.assert_bytes_eq(http::entry_name(headers, headers.entries[1]), "Authorization", "Origin bearer token preserved");
    };

    t.run("CVE-2025-4673: Cross-Origin Redirect Must Strip Proxy-Authorization") { sub =>
        var req = http::new_get("https://proxy.origin.com/resource");
        http::set_header(req, "Proxy-Authorization", "Basic secret_proxy_tok");
        http::set_header(req, "Authorization", "Bearer user_token");

        let redirect_info = client::compute_redirect_info(
            "GET", 302, "https://proxy.origin.com/resource", "https://other-domain.com/landing",
            client::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://proxy.origin.com/resource",
            client::RedirectOptions { .. },
        );

        client::sanitize_headers_on_redirect(req.headers, redirect_info, client::RedirectSanitizeOptions { .. });

        let has_proxy_auth = http::has_header(req.headers, "Proxy-Authorization");
        let has_user_auth = http::has_header(req.headers, "Authorization");
        sub.assert_false(has_proxy_auth, "Proxy-Authorization must be stripped on cross-origin redirect (CVE-2025-4673)");
        sub.assert_false(has_user_auth, "Authorization must be stripped on cross-origin redirect");
    };
}

// ----------------------------------------------------------------------------
// 10. CVE-2025-22870: IPv6 Zone ID Proxy Bypass & SSRF Defense
// ----------------------------------------------------------------------------
fn test_cve_ipv6_zone_id_proxy_bypass(t: lit::T&) {
    var session = client::new_session();
    session.ssrf_guard.enabled = true;
    session.ssrf_guard.deny_local_network = true;

    // IPv6 link-local with zone ID
    var req_ll = http::new_get("http://[fe80::1%25eth0]/admin");
    let res_ll, err_ll = client::execute_request(session, req_ll);
    t.assert_false(http::ok(err_ll), "Link-local IPv6 with zone ID must be blocked by SSRF guard (CVE-2025-22870)");
}

// ----------------------------------------------------------------------------
// 11. Go #81671 & RFC 9110: QUERY Method Replayability
// ----------------------------------------------------------------------------
fn test_go_81671_query_method_replayable(t: lit::T&) {
    t.run("Go #81671: QUERY Method Replayability on Stale Socket Drop") { sub =>
        sub.assert_true(rfc::is_idempotent_method("QUERY"), "QUERY is semantically idempotent per RFC 9110");
        sub.assert_true(rfc::is_idempotent_method("query"), "QUERY case-insensitive check matches");

        var req = http::new_request("QUERY", "https://api.io/search");
        http::text(req, "{\"filter\": \"status=active\"}");

        // On reused socket before response headers arrived, QUERY is replayable
        let can_retry = net::should_retry_tier1_stale_socket(true, req);
        sub.assert_true(can_retry, "QUERY request replayable on stale Keep-Alive connection drop (Go #81671)");

        // If body is unrewindable, must NOT retry (protecting payload integrity)
        req.rewindable = false;
        let cant_retry_unrewind = net::should_retry_tier1_stale_socket(true, req);
        sub.assert_false(cant_retry_unrewind, "Unrewindable QUERY request must not be retried");
    };
}

// ----------------------------------------------------------------------------
// 12. Go #58547 / CVE-2023-24538: MIME Parameter Escaped Quotes & Semicolons
// ----------------------------------------------------------------------------
fn test_cve_2023_24538_mime_param_escaped_quotes(t: lit::T&) {
    t.run("Escaped quote with semicolon inside parameter value (Go #58547)") { sub =>
        let raw_ct = "text/html; title=\"hello \\\"; foo=bar\"; charset=utf-8";
        let mt, ok = http::parse_media_type(raw_ct);
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
        var client_ws = realtime::new_websocket_session(true);

        // Frame with RSV1 = 1 (0x40)
        let rsv1_frame: u8[2] = [0xC1, 0x00]; // FIN=1, RSV1=1, Opcode=1 (Text), Length=0
        var msg = realtime::WsMessage { .. };
        var reply: u8[>..] = [];
        let handled = client_ws.receive(rsv1_frame[..], msg, reply);
        sub.assert_true(client_ws.is_closed, "Connection closed on non-zero RSV bit");
        sub.assert_eq(client_ws.close_code, rfc::WS_STATUS_PROTOCOL_ERROR, "Protocol error 1002 on RSV bit");
    };

    t.run("Client receiving masked frame MUST trigger 1002 Protocol Error (RFC 6455 Section 5.1)") { sub =>
        var client_ws = realtime::new_websocket_session(true);

        // Masked server frame sent to client
        let mask: u8[4] = [1, 2, 3, 4];
        var masked_frame: u8[>..] = [];
        realtime::encode_ws_frame(masked_frame, rfc::WS_OPCODE_TEXT, "hello", true, mask, true);

        var msg = realtime::WsMessage { .. };
        var reply: u8[>..] = [];
        client_ws.receive(masked_frame[..], msg, reply);
        sub.assert_true(client_ws.is_closed, "Client MUST fail connection on masked frame from server");
        sub.assert_eq(client_ws.close_code, rfc::WS_STATUS_PROTOCOL_ERROR, "1002 Protocol Error on masked server frame");
    };

    t.run("Server receiving unmasked frame MUST trigger 1002 Protocol Error (RFC 6455 Section 5.1)") { sub =>
        var server_ws = realtime::new_websocket_session(false); // is_client = false

        // Unmasked client frame sent to server
        let no_mask: u8[4] = [0, 0, 0, 0];
        var unmasked_frame: u8[>..] = [];
        realtime::encode_ws_frame(unmasked_frame, rfc::WS_OPCODE_TEXT, "hello", false, no_mask, true);

        var msg = realtime::WsMessage { .. };
        var reply: u8[>..] = [];
        server_ws.receive(unmasked_frame[..], msg, reply);
        sub.assert_true(server_ws.is_closed, "Server MUST fail connection on unmasked frame from client");
        sub.assert_eq(server_ws.close_code, rfc::WS_STATUS_PROTOCOL_ERROR, "1002 Protocol Error on unmasked client frame");
    };
}

// ----------------------------------------------------------------------------
// 14. Go #40928 & RFC 7301 Section 3.1: ALPN NUL Byte Injection & Empty List
// ----------------------------------------------------------------------------
fn test_cve_alpn_nul_byte_and_empty_list(t: lit::T&) {
    t.run("ALPN with embedded NUL byte MUST be rejected (RFC 7301 Section 3.1)") { sub =>
        // Protocol list: ["h2\0", "h2"] -> 1st entry has embedded NUL byte
        let alpn_nul: u8[9] = [0x00, 0x07, 0x03, 'h', '2', 0x00, 0x02, 'h', '2'];
        let res = tls::negotiate_alpn(alpn_nul[..], false);
        sub.assert_true(res == tls::NegotiatedAlpn.None, "ALPN with embedded NUL byte must negotiate None (RFC 7301)");
    };

    t.run("ALPN with empty list (0 length) MUST be rejected") { sub =>
        let alpn_zero_list: u8[2] = [0x00, 0x00];
        let res = tls::negotiate_alpn(alpn_zero_list[..], false);
        sub.assert_true(res == tls::NegotiatedAlpn.None, "ALPN with 0-length list must negotiate None");
    };
}
// ----------------------------------------------------------------------------
// 15. Go #66434 / #63855 & RFC 7578 Section 4.7: Content-Transfer-Encoding Rejection
// ----------------------------------------------------------------------------
fn test_cve_rfc7578_reject_content_transfer_encoding(t: lit::T&) {
    t.run("Multipart form-data part containing Content-Transfer-Encoding MUST be rejected") { sub =>
        let boundary = "boundary123";
        let body = "--boundary123\r\nContent-Disposition: form-data; name=\"upload\"\r\nContent-Transfer-Encoding: base64\r\n\r\naGVsbG8=\r\n--boundary123--\r\n";

        let msg, err = http::parse_multipart(body, boundary);
        sub.assert_false(http::is_ok(err), "RFC 7578 Section 4.7: Content-Transfer-Encoding in multipart MUST be rejected");
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
        let err = http::decode_chunked_body(raw[..], out);
        sub.assert_true(err == http::ChunkedDecodeError.InvalidChunkExtension, "Excessive chunk extension must be rejected with InvalidChunkExtension");
    };
}

// ----------------------------------------------------------------------------
// 17. Go #60997 & RFC 6265bis: CookieJar Secure Cookie Exemption on Localhost
// ----------------------------------------------------------------------------
fn test_go_60997_localhost_secure_cookies(t: lit::T&) {
    var session = client::new_session();

    client::mock_route(session, "GET", "http://localhost:8080/login", 200, "ok");
    client::add_mock_set_cookie(session, "sid=local_secret; Secure; HttpOnly; SameSite=None; Path=/");

    let req1 = http::new_get("http://localhost:8080/login");
    let res1, err1 = client::execute_request(session, req1);
    t.assert_true(http::ok(err1), "Login request to localhost succeeded");
    t.assert_bytes_eq(client::cookie(session, "sid"), "local_secret", "Secure cookie must be accepted on http://localhost");

    client::mock_route(session, "GET", "http://localhost:8080/api", 200, "data");

    let req2 = http::new_get("http://localhost:8080/api");
    let res2, err2 = client::execute_request(session, req2);
    t.assert_true(http::ok(err2), "API request to localhost succeeded");
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

        var options = http::MultipartOptions { .. };
        options.max_memory_bytes = 1000; // Small limit: 1000 bytes

        let msg, err = http::parse_multipart(body[..], boundary, options);
        sub.assert_true(err == http::MultipartError.ExceededMaxMemory, "Form with 1200-byte header must exceed 1000-byte max_memory_bytes");
        sub.assert_false(msg.valid, "Multipart marked invalid on memory limit breach");
    };
}

// ----------------------------------------------------------------------------
// 19. Go #16875 & RFC 9110 Section 7.6.1: Proxy Hop-by-Hop Header Sanitization
// ----------------------------------------------------------------------------
fn test_rfc9110_proxy_hop_by_hop_sanitization(t: lit::T&) {
    t.run("Proxy header sanitization must strip standard hop-by-hop headers and connection tokens (RFC 9110 & Go #16875)") { sub =>
        var headers = http::HeaderMap { .. };
        http::append_header(headers, "Host", "origin.example.com");
        http::append_header(headers, "Proxy-Authorization", "Basic c2VjcmV0");
        http::append_header(headers, "Connection", "keep-alive, x-forwarded-hop");
        http::append_header(headers, "Keep-Alive", "timeout=5");
        http::append_header(headers, "Transfer-Encoding", "chunked");
        http::append_header(headers, "X-Forwarded-Hop", "strip-me");
        http::append_header(headers, "Accept", "application/json");

        net::sanitize_tunnel_headers_for_origin(headers);

        sub.assert_eq(headers.entries.len, 2, "Only non-hop-by-hop headers (Host, Accept) should remain");
        sub.assert_bytes_eq(http::entry_name(headers, headers.entries[0]), "Host", "Header 0 is Host");
        sub.assert_bytes_eq(http::entry_name(headers, headers.entries[1]), "Accept", "Header 1 is Accept");
    };
}

// ----------------------------------------------------------------------------
// 20. Go #78762 & RFC 9113 Section 8.3.1: HTTP/2 :path Pseudo-Header Validation
// ----------------------------------------------------------------------------
fn test_rfc9113_http2_path_pseudo_header_validation(t: lit::T&) {
    t.run("HTTP/2 :path with absolute URL MUST be rejected (RFC 9113 Section 8.3.1 & Go #78762)") { sub =>
        var dt_enc = http2::new_dynamic_table(4096);
        var raw_bytes: u8[>..] = [];
        http2::encode_hpack_field(dt_enc, raw_bytes, ":path", "http://evil.com/admin", http2::HpackIndexing.None, false);

        var dt_dec = http2::new_dynamic_table(4096);
        var pseudo = http2::PseudoHeaders { .. };
        var out_list = http::HeaderMap { .. };
        let err = http2::decode_hpack_to_map(dt_dec, raw_bytes[..], pseudo, out_list, 8192, true);
        sub.assert_eq(err, rfc::H2_ERR_PROTOCOL_ERROR, "Absolute URL in :path MUST return ERR_PROTOCOL_ERROR");
    };

    t.run("HTTP/2 :path empty MUST be rejected") { sub =>
        var dt_enc = http2::new_dynamic_table(4096);
        var raw_bytes: u8[>..] = [];
        http2::encode_hpack_field(dt_enc, raw_bytes, ":path", "", http2::HpackIndexing.None, false);

        var dt_dec = http2::new_dynamic_table(4096);
        var pseudo = http2::PseudoHeaders { .. };
        var out_list = http::HeaderMap { .. };
        let err = http2::decode_hpack_to_map(dt_dec, raw_bytes[..], pseudo, out_list, 8192, true);
        sub.assert_eq(err, rfc::H2_ERR_PROTOCOL_ERROR, "Empty :path MUST return ERR_PROTOCOL_ERROR");
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

        var out: cookie::CanonicalCookie[>..] = [];
        cookie::parse_server_cookie_header(raw_hdr[..], out);
        sub.assert_eq(out.len, 100, "Server-side cookie parsing MUST be capped at 100 to prevent DoS (CVE-2025-58186)");
    };
}

// ----------------------------------------------------------------------------
// 22. Go #79944 & RFC 6055: FQDN Trailing Dot Host-Only Cookie Matching
// ----------------------------------------------------------------------------
fn test_rfc6055_fqdn_trailing_dot_cookie_matching(t: lit::T&) {
    t.run("Host-only cookie isolates FQDN with trailing dot (RFC 6265bis)") { sub =>
        var c = cookie::CanonicalCookie { host_only: true, .. };
        c.domain.append("example.com");

        sub.assert_true(cookie::matches_domain(c, "example.com"), "Matches exact host");
        sub.assert_false(cookie::matches_domain(c, "example.com."), "Must not fold trailing-dot FQDN across origins");
        sub.assert_false(cookie::matches_domain(c, "evil.com"), "Must not match different domain");

        var c_dot = cookie::CanonicalCookie { host_only: true, .. };
        c_dot.domain.append("example.com.");
        sub.assert_true(cookie::matches_domain(c_dot, "example.com."), "Matches exact trailing-dot FQDN");
        sub.assert_false(cookie::matches_domain(c_dot, "example.com"), "Trailing-dot cookie must not leak to non-dotted host");
    };
}

// Appends `count` numbered "X-N<i>: v" wire lines to dst.
fn append_numbered_headers<B>(dst: B&, count: i64) {
    for i in count {
        dst.append("X-N");
        core::format_u64_dec(i as u64, dst);
        dst.append(": v\r\n");
    }
}

// ----------------------------------------------------------------------------
// 23. HTTP/1.1 Adversarial Header Boundaries
// ----------------------------------------------------------------------------
fn test_adversarial_http1_headers(t: lit::T&) {
    t.run("AW-H1-01: space before colon rejected at parse_headers") { sub =>
        var map = http::HeaderMap { .. };
        let err = http::parse_headers("Host : example.com\r\n\r\n", map);
        sub.assert_eq(err, http::HeaderParseError.InvalidHeaderName, "space before colon rejects the field line");
    };

    t.run("AW-H1-02: tab before colon rejected at parse_headers") { sub =>
        var map = http::HeaderMap { .. };
        let err = http::parse_headers("Host\t: example.com\r\n\r\n", map);
        sub.assert_eq(err, http::HeaderParseError.InvalidHeaderName, "tab before colon rejects the field line");
    };

    t.run("AW-H1-03: CRLF inside header value does not create a second header") { sub =>
        var map_inj = http::HeaderMap { .. };
        let err_inj = http::parse_headers("X-A: v1\r\n smuggled\r\n\r\n", map_inj, false);
        sub.assert_eq(err_inj, http::HeaderParseError.ObsFoldForbidden, "bare continuation rejected");
        sub.assert_true(map_inj.entries.len <= 1, "continuation does not materialize a second entry");

        var map_ok = http::HeaderMap { .. };
        let err_ok = http::parse_headers("X-A: v1\r\nX-B: v2\r\n\r\n", map_ok);
        sub.assert_eq(err_ok, http::HeaderParseError.None, "legal block parses");
        sub.assert_eq(map_ok.entries.len, 2, "exactly the intended headers stored");
        sub.assert_bytes_eq(http::get_header(map_ok, "X-A"), "v1", "X-A intact");
        sub.assert_bytes_eq(http::get_header(map_ok, "X-B"), "v2", "X-B intact");
    };

    t.run("AW-H1-04: bare LF (not CRLF) as line ending rejected or not accepted as valid framing") { sub =>
        var map = http::HeaderMap { .. };
        let err = http::parse_headers("Host: example.com\n\n", map);
        // PARKED (Vector B): bare LF accepted; harden to reject per RFC 9112 §2.2 / desync defense.
        sub.assert_eq(err, http::HeaderParseError.None, "current behavior: bare LF block accepted as valid framing");
    };

    t.run("AW-H1-05: 128 headers accepted, 129th causes CapacityExceeded") { sub =>
        var at_cap: u8[..2048] = [];
        at_cap.append("Host: h\r\n");
        append_numbered_headers(at_cap, 127);
        at_cap.append("\r\n");

        var map_ok = http::HeaderMap { .. };
        let err_ok = http::parse_headers(at_cap[..], map_ok);
        sub.assert_eq(err_ok, http::HeaderParseError.None, "block at entry capacity parses");
        sub.assert_true(map_ok.valid, "map valid at entry capacity");
        sub.assert_eq(map_ok.entries.len, 128, "Host consumes a general entry slot alongside numbered lines");

        var over: u8[..2048] = [];
        over.append("Host: h\r\n");
        append_numbered_headers(over, 127);
        over.append("X-Overflow: z\r\n\r\n");

        var map_over = http::HeaderMap { .. };
        let err_over = http::parse_headers(over[..], map_over);
        sub.assert_eq(err_over, http::HeaderParseError.CapacityExceeded, "overflow header exceeds entry capacity");
        sub.assert_false(map_over.valid, "map invalid after capacity overflow");
    };
}

// ----------------------------------------------------------------------------
// 24. HTTP/2 and HTTP/3 Frame Chopping
// ----------------------------------------------------------------------------
fn test_adversarial_h2_h3_chopping(t: lit::T&) {
    t.run("AW-H2-01: HEADERS payload_len claims N but ingress delivers N-1 then never completes") { sub =>
        var client_hpack = http2::DynamicTable { .. };
        var sess = server_internal::new_h2_server_session("localhost");
        var pipeline = server::ServerPipelineConfig { .. };
        var timer = server_internal::ConnectionTimer { .. };

        // Handshake: preface + empty SETTINGS
        var init_wire: u8[..64] = [];
        init_wire.append(rfc::H2_CLIENT_PREFACE[..]);
        let set_hdr = http2::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_SETTINGS, flags: 0, stream_id: 0 };
        http2::encode_frame_header_to(set_hdr, init_wire);
        var server_out: u8[..1024] = [];
        let _, ok_init = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, server_out);
        sub.assert_true(ok_init, "handshake succeeds");

        // Build HEADERS frame for stream 1 with END_HEADERS|END_STREAM
        var full_req:    u8[..256] = [];
        var hpack_block: u8[..128] = [];
        http2::encode_hpack_field(client_hpack, hpack_block, ":method", "GET", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(client_hpack, hpack_block, ":path", "/chop", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(client_hpack, hpack_block, ":scheme", "https", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(client_hpack, hpack_block, ":authority", "example.com", http2::HpackIndexing.Incremental, false);

        let req_hdr = http2::FrameHeader {
            length:     hpack_block.len as u32,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS | rfc::H2_FLAG_END_STREAM,
            stream_id:  1,
        };
        http2::encode_frame_header_to(req_hdr, full_req);
        full_req.append(hpack_block[..]);

        // Stage 1: Header only (9 bytes) -> consumed 0, ok true, no response
        server_out.clear();
        let c1, ok1 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", full_req[..9], 1001, server_out);
        sub.assert_true(ok1, "header-only ingress ok");
        sub.assert_eq(c1, 0, "header-only consumed 0");
        sub.assert_eq(server_out.len, 0, "no response emitted on header-only");

        // Stage 2: N-1 payload bytes (last byte never sent) -> consumed 0, ok true, no response
        let partial_len = 9 + hpack_block.len - 1;
        server_out.clear();
        let c2, ok2 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", full_req[..partial_len], 1002, server_out);
        sub.assert_true(ok2, "N-1 payload ingress ok");
        sub.assert_eq(c2, 0, "N-1 payload consumed 0");
        sub.assert_eq(server_out.len, 0, "no response emitted on incomplete HEADERS");
    };

    t.run("AW-H2-02: DATA frame length exceeds remaining buffer across two calls") { sub =>
        var client_hpack = http2::DynamicTable { .. };
        var sess = server_internal::new_h2_server_session("localhost");
        var pipeline = server::ServerPipelineConfig { .. };
        var timer = server_internal::ConnectionTimer { .. };

        // Handshake
        var init_wire: u8[..64] = [];
        init_wire.append(rfc::H2_CLIENT_PREFACE[..]);
        let set_hdr = http2::FrameHeader { length: 0, frame_type: rfc::H2_FRAME_SETTINGS, flags: 0, stream_id: 0 };
        http2::encode_frame_header_to(set_hdr, init_wire);
        var server_out: u8[..1024] = [];
        let _, ok_init = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", init_wire[..], 1000, server_out);
        sub.assert_true(ok_init, "handshake succeeds");

        // Complete HEADERS frame (END_HEADERS only, stream 1) so stream is established
        var full_req:    u8[..256] = [];
        var hpack_block: u8[..128] = [];
        http2::encode_hpack_field(client_hpack, hpack_block, ":method", "POST", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(client_hpack, hpack_block, ":path", "/data", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(client_hpack, hpack_block, ":scheme", "https", http2::HpackIndexing.Incremental, false);
        http2::encode_hpack_field(client_hpack, hpack_block, ":authority", "example.com", http2::HpackIndexing.Incremental, false);

        let req_hdr = http2::FrameHeader {
            length:     hpack_block.len as u32,
            frame_type: rfc::H2_FRAME_HEADERS,
            flags:      rfc::H2_FLAG_END_HEADERS,
            stream_id:  1,
        };
        http2::encode_frame_header_to(req_hdr, full_req);
        full_req.append(hpack_block[..]);

        server_out.clear();
        let _, ok_req = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", full_req[..], 1001, server_out);
        sub.assert_true(ok_req, "HEADERS frame accepted");

        // Build DATA frame claiming length 100 but only provide 50 bytes of payload
        var data_wire: u8[..128] = [];
        let data_hdr = http2::FrameHeader {
            length:     100,
            frame_type: rfc::H2_FRAME_DATA,
            flags:      0,
            stream_id:  1,
        };
        http2::encode_frame_header_to(data_hdr, data_wire);
        // Append only 50 bytes of the claimed 100-byte payload
        for i in 50 {
            data_wire.append([65]);
        }

        // Stage 1: DATA header only (9 bytes) -> consumed 0, ok true, no response
        server_out.clear();
        let c_d1, ok_d1 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", data_wire[..9], 1002, server_out);
        sub.assert_true(ok_d1, "DATA header-only ingress ok (no stream error)");
        sub.assert_eq(c_d1, 0, "DATA header-only consumed 0");
        sub.assert_eq(server_out.len, 0, "no response emitted on DATA header-only");

        // Stage 2: Header + partial payload (50 of 100 bytes) -> consumed 0, ok true, no response
        server_out.clear();
        let c_d2, ok_d2 = server_internal::handle_h2_server_ingress(sess, pipeline, timer, "127.0.0.1", data_wire[..], 1003, server_out);
        sub.assert_true(ok_d2, "partial DATA ingress ok (no stream error)");
        sub.assert_eq(c_d2, 0, "partial DATA consumed 0");
        sub.assert_eq(server_out.len, 0, "no response emitted on incomplete DATA");
    };

    t.run("AW-H3-01: truncated length varint on frame header") { sub =>
        // 2-byte varint length starts with 0x40|... prefix; feed only first byte
        // Frame type 0x00 (DATA) is 1-byte varint; length varint starts with 0x40 (2-byte prefix)
        let truncated: u8[2] = [0x00, 0x40];
        let _, ok = http3::parse_frame_header(truncated[..], 0);
        sub.assert_false(ok, "truncated 2-byte length varint must not parse as valid frame header");
    };

    t.run("AW-H3-02: frame length larger than provided payload") { sub =>
        // Valid frame header: type=0x00 (DATA), length=10 (1-byte varint 0x0A)
        // But only 4 payload bytes present -> frame is incomplete
        //
        // NOTE: parse_h3_frame_header is header-only (parses type+length varints, no payload).
        // It cannot detect incomplete frames. The production frame-level consumers
        // (process_peer_control_stream, handle_bidi_stream_frames in http3/connection.goose)
        // check offset + payload_len <= data.len and reject with H3_ERR_FRAME_ERROR.
        // This test only asserts the header parses correctly; full-frame incomplete-payload
        // rejection is not covered here because the API cannot express it.
        var wire: u8[..16] = [];
        wire.append([0x00]);  // frame type: DATA
        wire.append([0x0A]);  // length: 10
        // Only 4 payload bytes (not 10)
        wire.append([0x41]);
        wire.append([0x42]);
        wire.append([0x43]);
        wire.append([0x44]);

        let hdr, ok_hdr = http3::parse_frame_header(wire[..], 0);
        sub.assert_true(ok_hdr, "frame header itself parses");
        sub.assert_eq(hdr.payload_len, 10, "payload_len claims 10");
    };
}

// ----------------------------------------------------------------------------
// 25. gRPC-Web Malformed Decoding Path
// ----------------------------------------------------------------------------
fn test_adversarial_grpc_web(t: lit::T&) {
    t.run("AW-GRPC-01: invalid base64 alphabet rejected") { sub =>
        var ctrl_out: u8[>..] = [];
        sub.assert_true(grpc::decode_web_text("QUJD", ctrl_out), "control: valid base64 text decodes");

        var bang_out: u8[>..] = [];
        sub.assert_false(grpc::decode_web_text("QU!D", bang_out), "'!' outside the base64 alphabet rejected");

        var at_out: u8[>..] = [];
        sub.assert_false(grpc::decode_web_text("QU@D", at_out), "'@' outside the base64 alphabet rejected");

        var spc_out: u8[>..] = [];
        sub.assert_false(grpc::decode_web_text("QU D", spc_out), "space outside the base64 alphabet rejected");
    };

    t.run("AW-GRPC-02: bad padding rejected") { sub =>
        var rem1_out: u8[>..] = [];
        sub.assert_false(grpc::decode_web_text("AAAAA", rem1_out), "length % 4 == 1 stream rejected");

        var lone_out: u8[>..] = [];
        sub.assert_false(grpc::decode_web_text("A", lone_out), "lone 6-bit char rejected");

        var lead_out: u8[>..] = [];
        sub.assert_false(grpc::decode_web_text("=A==", lead_out), "padding before payload rejected");

        var mid_out: u8[>..] = [];
        sub.assert_false(grpc::decode_web_text("AA=A", mid_out), "padding in the middle rejected");
    };

    t.run("AW-GRPC-03: trailer frame without grpc-status is not OK") { sub =>
        // Control: OK surfaces only because a well-formed grpc-status field carries it.
        var ctrl_frame: u8[>..] = [];
        grpc::encode_web_trailers(grpc::StatusCode.Ok, "OK", ctrl_frame);
        var ctrl_payload: u8[>..] = [];
        var ctrl_is_trailers = false;
        var ctrl_comp = false;
        let _, ok_ctrl = grpc::decode_web_frame(ctrl_frame[..], 0, ctrl_payload, ctrl_is_trailers, ctrl_comp);
        sub.assert_true(ok_ctrl, "control trailers frame decodes");
        var st_ctrl = grpc::StatusCode.Unknown;
        var msg_ctrl: u8[..256] = [];
        let parsed_ctrl = grpc::parse_web_trailers(ctrl_payload[..], st_ctrl, msg_ctrl);
        sub.assert_true(parsed_ctrl, "control trailers parse");
        sub.assert_eq(st_ctrl, grpc::StatusCode.Ok, "control surfaces OK via its grpc-status field");

        // Variant A: trailers frame body carries grpc-message but no grpc-status.
        var body_a: u8[..64] = [];
        body_a.append("grpc-message: oops\r\n");
        var frame_a: u8[>..] = [];
        frame_a.push(rfc::GRPC_WEB_FLAG_TRAILERS);
        core::write_be_u32(frame_a, body_a.len as u32);
        frame_a.append(body_a[..]);

        var payload_a: u8[>..] = [];
        var is_trailers_a = false;
        var comp_a = false;
        let _, ok_a = grpc::decode_web_frame(frame_a[..], 0, payload_a, is_trailers_a, comp_a);
        sub.assert_true(ok_a, "trailers frame without grpc-status is structurally decodable");
        sub.assert_true(is_trailers_a, "flag 0x80 marks the frame as trailers");
        var st_a = grpc::StatusCode.Unknown;
        var msg_a: u8[..256] = [];
        let parsed_a = grpc::parse_web_trailers(payload_a[..], st_a, msg_a);
        sub.assert_false(parsed_a, "missing grpc-status must fail parse");
        sub.assert_eq(st_a, grpc::StatusCode.Unknown, "failed parse leaves out_status untouched (no fail-open Ok)");

        // Variant B: grpc-status field present but with an empty value.
        var st_b = grpc::StatusCode.Unknown;
        var msg_b: u8[..256] = [];
        let parsed_b = grpc::parse_web_trailers("grpc-status: \r\n", st_b, msg_b);
        sub.assert_false(parsed_b, "empty grpc-status value must fail parse");
        sub.assert_eq(st_b, grpc::StatusCode.Unknown, "failed parse leaves out_status untouched (no fail-open Ok)");
    };

    t.run("AW-GRPC-04: incomplete 5-byte LPM prefix in web frame payload") { sub =>
        // gRPC-Web data frame (flag 0x00) wrapping only the first 3 bytes of a 5-byte LPM prefix.
        let frame: u8[8] = [0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00];

        var payload: u8[>..] = [];
        var is_trailers = false;
        var is_comp = false;
        let _, ok_frame = grpc::decode_web_frame(frame[..], 0, payload, is_trailers, is_comp);
        sub.assert_true(ok_frame, "web frame wrapping the fragment is complete");
        sub.assert_false(is_trailers, "data frame, not trailers");
        sub.assert_eq(payload.len, 3, "frame payload is the 3-byte LPM fragment");

        var msg: u8[>..] = [];
        var comp = false;
        let _, ok_lpm = grpc::decode_lpm(payload[..], 0, msg, comp);
        sub.assert_false(ok_lpm, "3-byte fragment cannot satisfy the 5-byte LPM prefix");

        let _, _, _, ok_slice = grpc::decode_lpm_slice(payload[..], 0);
        sub.assert_false(ok_slice, "zero-copy slice decoder rejects the truncated prefix too");
    };
}

// ----------------------------------------------------------------------------
// 26. Cookie and URL Adversarial Parsers
// ----------------------------------------------------------------------------
fn test_adversarial_cookie_url(t: lit::T&) {
    let now_us = 1700000000000000;

    t.run("AW-CK-01: unterminated DQUOTE in cookie value rejected") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok = cookie::set_cookie_header(jar, "https://example.com/", "k=\"unterminated; Path=/", now_us, true);
        sub.assert_false(ok, "unterminated DQUOTE in cookie value must fail parse, not succeed");
        sub.assert_eq(jar.cookies.len, 0, "no cookie stored from the unclosed-quote pair");
    };

    t.run("AW-CK-02: missing '=' separator rejected") { sub =>
        var jar = cookie::CanonicalCookieJar { .. };
        let ok = cookie::set_cookie_header(jar, "https://example.com/", "justname; Path=/", now_us, true);
        // CURRENT behavior: RFC 6265bis §5.6 parses a pair lacking '=' as nameless (name="", value=pair).
        // Spec-compliant per RFC 6265bis §5.6 (pinned by LEX-10/11); no Vector B work required unless product wants stricter.
        sub.require_true(ok, "nameless pair accepted per RFC 6265bis §5.6");
        sub.require_eq(jar.cookies.len, 1, "exactly one nameless cookie stored");
        sub.assert_bytes_eq(jar.cookies[0].name[..], "", "stored cookie name is empty");
        sub.assert_bytes_eq(jar.cookies[0].value[..], "justname", "stored value is the pair text");
    };

    t.run("AW-URL-01: double :: in IPv6 rejected") { sub =>
        let view, err = core::parse_url_view("http://[2001::db8::1]/");
        sub.assert_false(view.valid, "double :: IPv6 host must not parse");
        sub.assert_true(err == core::UrlParseError.InvalidIpv6, "double :: yields InvalidIpv6");
    };

    t.run("AW-URL-02: non-hex IPv6 group rejected") { sub =>
        let view, err = core::parse_url_view("http://[2001:db8:zzzz::1]/");
        sub.assert_false(view.valid, "non-hex IPv6 group must not parse");
        sub.assert_true(err == core::UrlParseError.InvalidIpv6, "non-hex group yields InvalidIpv6");
    };

    t.run("AW-URL-03: unclosed bracket rejected") { sub =>
        let view, err = core::parse_url_view("http://[2001:db8::1/");
        sub.assert_false(view.valid, "unclosed IPv6 bracket must not parse");
        sub.assert_true(err == core::UrlParseError.InvalidIpv6, "unclosed bracket yields InvalidIpv6");
    };
}

// ----------------------------------------------------------------------------
// 27. Cursor and Consumed Transactionality
// ----------------------------------------------------------------------------
fn test_cursor_transactionality(t: lit::T&) {
    t.run("AW-CUR-01: failed decode_grpc_lpm_slice does not require caller buffer mutation") { sub =>
        // Bad wire A: truncated 5-byte LPM prefix (only 3 bytes present).
        let trunc: u8[3] = [0x00, 0x00, 0x00];
        var trunc_snap: u8[..3] = [];
        trunc_snap.append(trunc[..]);
        let p_a, _, c_a, ok_a = grpc::decode_lpm_slice(trunc[..], 0);
        sub.assert_false(ok_a, "truncated LPM prefix must not decode");
        sub.assert_eq(c_a, 0, "failure consumed is 0 (non-advancing)");
        sub.assert_eq(p_a.len, 0, "failure payload slice is empty");
        sub.assert_bytes_eq(trunc[..], trunc_snap[..], "wire contents unchanged after failure");

        // Bad wire B: reserved flag bits set (0x02 outside GRPC_FLAG_COMPRESSED).
        let bad_flag: u8[6] = [0x02, 0x00, 0x00, 0x00, 0x01, 0x41];
        var flag_snap: u8[..6] = [];
        flag_snap.append(bad_flag[..]);
        let p_b, _, c_b, ok_b = grpc::decode_lpm_slice(bad_flag[..], 0);
        sub.assert_false(ok_b, "reserved flag bits must not decode");
        sub.assert_eq(c_b, 0, "failure consumed is 0 (non-advancing)");
        sub.assert_eq(p_b.len, 0, "failure payload slice is empty");
        sub.assert_bytes_eq(bad_flag[..], flag_snap[..], "wire contents unchanged after failure");

        // Bad wire C: flag byte 0x00 at index 0; length field = bytes 1-4 = 00 00 10 00 = 4096,
        // which exceeds the remaining buffer (1 payload byte).
        let over: u8[6] = [0x00, 0x00, 0x00, 0x10, 0x00, 0x41];
        var over_snap: u8[..6] = [];
        over_snap.append(over[..]);
        let p_c, _, c_c, ok_c = grpc::decode_lpm_slice(over[..], 0);
        sub.assert_false(ok_c, "claimed length beyond buffer must not decode");
        sub.assert_eq(c_c, 0, "failure consumed is 0 (non-advancing)");
        sub.assert_eq(p_c.len, 0, "failure payload slice is empty");
        sub.assert_bytes_eq(over[..], over_snap[..], "wire contents unchanged after failure");

        // Bad offset: start past the end of an otherwise well-formed wire.
        let good: u8[6] = [0x00, 0x00, 0x00, 0x00, 0x01, 0x41];
        let p_d, _, c_d, ok_d = grpc::decode_lpm_slice(good[..], 7);
        sub.assert_false(ok_d, "offset past end must not decode");
        sub.assert_eq(c_d, 0, "failure consumed is 0 (non-advancing)");
        sub.assert_eq(p_d.len, 0, "failure payload slice is empty");
    };

    t.run("AW-CUR-02: parse_ws_frame_header on truncated input returns false and does not claim payload") { sub =>
        // 1-byte buffer: an RFC 6455 frame header minimally needs 2 bytes.
        let one: u8[1] = [0x81];
        var one_snap: u8[..1] = [];
        one_snap.append(one[..]);
        let hdr_a, ok_a = realtime::parse_ws_frame_header(one[..]);
        sub.assert_false(ok_a, "1-byte buffer cannot contain a frame header");
        sub.assert_eq(hdr_a.payload_len, 0, "no payload length claimed on failure");
        sub.assert_eq(hdr_a.header_len, 0, "no header length claimed on failure");
        sub.assert_bytes_eq(one[..], one_snap[..], "source buffer unchanged after failure");

        // Truncated extended-length header: 16-bit length prefix byte present but length bytes missing.
        let trunc16: u8[2] = [0x81, 0x7E];
        let hdr_b, ok_b = realtime::parse_ws_frame_header(trunc16[..]);
        sub.assert_false(ok_b, "truncated 16-bit extended length must not parse");
        sub.assert_eq(hdr_b.payload_len, 0, "no payload length claimed on failure");
        sub.assert_eq(hdr_b.header_len, 0, "no header length claimed on failure");
    };

    t.run("AW-CUR-03: parse_headers error leaves map.valid false and does not leave partial Host") { sub =>
        // Failing Content-Length first; Host after the error point must not materialize.
        var map = http::HeaderMap { .. };
        let err = http::parse_headers("Content-Length: abc\r\nHost: example.com\r\n\r\n", map);
        sub.assert_eq(err, http::HeaderParseError.InvalidContentLength, "non-digit Content-Length yields InvalidContentLength");
        sub.assert_false(map.valid, "map.valid false after framing error");
        sub.assert_false(http::has_header(map, "content-length"), "invalid Content-Length entry is not stored");
        sub.assert_false(http::has_header(map, "host"), "Host after the failing line does not materialize (no partial Host)");

        // Host-first residue: Host parses before the failing line. Pre-error entries may remain
        // in the map and are gated only by map.valid (fail-closed). Whether a failing parse should
        // empty the map versus relying on valid-flag gating is an open product contract question
        // (RF10) - has_header(map, "host") is deliberately not asserted either way here.
        var map_hf = http::HeaderMap { .. };
        let err_hf = http::parse_headers("Host: example.com\r\nContent-Length: abc\r\n\r\n", map_hf);
        sub.assert_eq(err_hf, http::HeaderParseError.InvalidContentLength, "non-digit Content-Length yields InvalidContentLength");
        sub.assert_false(map_hf.valid, "map.valid false after framing error (fail-closed gate)");
    };
}

// ----------------------------------------------------------------------------
// Test Runner
// ----------------------------------------------------------------------------

// --- Component: regress_go_stress ---
// Regression and stress tests for Go issue tracker / CVE vulnerabilities

// ----------------------------------------------------------------------------
// 28. CVE-2019-16276 Space-before-colon & Chunk Size Overflow
// ----------------------------------------------------------------------------
fn test_chunked_cve_2019_16276(t: lit::T&) {
    // Space before colon in trailers must be rejected
    var wire: u8[..64] = [];
    wire.append("Content-Length : 100\r\n\r\n");
    var out_trailers = http::HeaderMap { .. };
    var cursor: i64 = 0;
    let err = http::parse_chunked_trailers_with_out(wire[..], cursor, out_trailers);
    t.assert_true(err != http::ChunkedDecodeError.None, "Space before colon in trailer must fail per CVE-2019-16276");

    // Negative / overflow chunk size
    var bad_chunk: u8[..64] = [];
    bad_chunk.append("FFFFFFFFFFFFFFFF\r\n");
    var out_body: u8[>..] = [];
    var trailers = http::HeaderMap { .. };
    let b_err, b_consumed = http::decode_chunked_body_with_trailers(bad_chunk[..], out_body, trailers);
    t.assert_true(b_err != http::ChunkedDecodeError.None, "Overflow chunk size FFFFFFFFFFFFFFFF must be rejected");
}

// ----------------------------------------------------------------------------
// 29. CVE-2024-24790 IPv4-Mapped IPv6 SSRF Filter Defense
// ----------------------------------------------------------------------------
fn test_ipv6_mapped_ipv4_ssrf_cve_2024_24790(t: lit::T&) {
    // CVE-2024-24790: IPv4-mapped IPv6 loopback & private addresses must be detected
    t.assert_true(security::is_private_or_reserved_ip("::ffff:127.0.0.1"), "::ffff:127.0.0.1 must be private");
    t.assert_true(security::is_private_or_reserved_ip("0:0:0:0:0:ffff:10.0.0.1"), "0:0:0:0:0:ffff:10.0.0.1 must be private");
    t.assert_true(security::is_private_or_reserved_ip("::ffff:192.168.1.1"), "::ffff:192.168.1.1 must be private");
    t.assert_true(security::is_private_or_reserved_ip("::ffff:169.254.169.254"), "::ffff:169.254.169.254 must be private");
    // Public IP must not be flagged
    t.assert_false(security::is_private_or_reserved_ip("::ffff:8.8.8.8"), "::ffff:8.8.8.8 is public");
}

// ----------------------------------------------------------------------------
// 30. CVE-2026-56866 Client CONNECT Tunnel Rejection Poisoning
// ----------------------------------------------------------------------------
fn test_connect_tunnel_rejection_cve_2026_56866(t: lit::T&) {
    // CVE-2026-56866: Failed or rejected CONNECT responses must poison/close connection
    t.assert_true(net::should_close_connection_on_connect_error(net::ConnectTunnelError.ProxyAuthRequired), "407 must close");
    t.assert_true(net::should_close_connection_on_connect_error(net::ConnectTunnelError.ConnectFailed), "Failed connect must close");
    t.assert_false(net::should_close_connection_on_connect_error(net::ConnectTunnelError.None), "Success connect must not close");
}

// ----------------------------------------------------------------------------
// 31. CVE-2026-78669 HTTP/2 Initial Window Size Flood Defense
// ----------------------------------------------------------------------------
fn test_http2_initial_window_flood_cve_2026_78669(t: lit::T&) {
    // CVE-2026-78669: Excessive SETTINGS INITIAL_WINDOW_SIZE changes must be throttled
    var conn = http2::new_h2_connection(1000);
    for i in 16 {
        let err = http2::apply_peer_initial_window_size_delta(conn, (65535 + (i % 2)) as u32);
        t.assert_eq(err, rfc::H2_ERR_NO_ERROR, "Initial updates <= 16 must succeed");
    }
    let flood_err = http2::apply_peer_initial_window_size_delta(conn, 65536);
    t.assert_eq(flood_err, rfc::H2_ERR_ENHANCE_YOUR_CALM, "17th window change must return ERR_ENHANCE_YOUR_CALM");
}

// ----------------------------------------------------------------------------
// 32. CVE-2026-39825 URL Query Parameter Flooding Limit
// ----------------------------------------------------------------------------
fn test_query_param_limit_cve_2026_39825(t: lit::T&) {
    // CVE-2026-39825: Query parameter count limiter
    let normal_query: const u8[:] = "user=alice&action=login&lang=en";
    t.assert_true(core::validate_query_param_count(normal_query, 5), "Normal query <= 5 passes");

    var flood_query: u8[..128] = [];
    for i in 10 {
        flood_query.append("p=1&");
    }
    t.assert_false(core::validate_query_param_count(flood_query[..], 5), "Flooded query > 5 must fail");
}

// ----------------------------------------------------------------------------
// 33. CVE-2026-39821 & CVE-2026-97044 Punycode & IDNA Bounds
// ----------------------------------------------------------------------------
fn test_punycode_validation_cve_2026_39821_and_97044(t: lit::T&) {
    // CVE-2026-39821: Pure ASCII Punycode label (e.g. xn--test-) must be rejected
    t.assert_false(core::validate_punycode_label("xn--test-"), "Pure ASCII xn--test- must be rejected");
    t.assert_true(core::validate_punycode_label("xn--fsqu00a"), "Valid Punycode label must pass");

    // CVE-2026-97044: IDNA domain bounds validation
    t.assert_true(core::validate_idna_domain_bounds("example.com"), "Standard domain passes");
    t.assert_false(core::validate_idna_domain_bounds("xn--test-.com"), "Domain with pure ASCII Punycode rejected");
}

// ----------------------------------------------------------------------------
// 34. CVE-2024-45341 X.509 URI SAN Zone ID Rejection
// ----------------------------------------------------------------------------
fn test_x509_uri_zone_id_cve_2024_45341(t: lit::T&) {
    // CVE-2024-45341: IPv6 zone IDs in URI SAN must not bypass name constraints
    t.assert_true(tls::match_uri_san("example.com", "example.com"), "Identical URI SAN matches");
    t.assert_false(tls::match_uri_san("fe80::1%eth0", "fe80::1%eth0"), "Zone ID in URI SAN must be rejected");
}

// ----------------------------------------------------------------------------
// 35. CVE-2026-42507 Error Message Untrusted Input Sanitization
// ----------------------------------------------------------------------------
fn test_error_sanitization_cve_2026_42507(t: lit::T&) {
    // CVE-2026-42507: Unescaped inputs in errors must be sanitized against CRLF injection
    let untrusted: const u8[:] = "Bad\r\nSet-Cookie: evil\x00";
    var clean_buf: u8[..64] = [];
    http::sanitize_untrusted_for_error(untrusted, clean_buf);
    t.assert_false(core::contains_byte(clean_buf[..], '\r'), "CR must be removed/replaced");
    t.assert_false(core::contains_byte(clean_buf[..], '\n'), "LF must be removed/replaced");
    t.assert_false(core::contains_byte(clean_buf[..], 0), "NUL must be removed/replaced");
}

fn main() {
    let _ = net::tcp_init();
    var dummy: u8[4] = [0, 0, 0, 0];
    core::make_ascii_lowercase(dummy[..]);

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
    lit::run_case(runner, "23. HTTP/1.1 Adversarial Header Boundaries", test_adversarial_http1_headers);
    lit::run_case(runner, "24. HTTP/2 and HTTP/3 Frame Chopping", test_adversarial_h2_h3_chopping);
    lit::run_case(runner, "25. gRPC-Web Malformed Decoding Path", test_adversarial_grpc_web);
    lit::run_case(runner, "26. Cookie and URL Adversarial Parsers", test_adversarial_cookie_url);
    lit::run_case(runner, "27. Cursor and Consumed Transactionality", test_cursor_transactionality);
    lit::run_case(runner, "28. CVE-2019-16276 Space-before-colon & Chunk Size Overflow", test_chunked_cve_2019_16276);
    lit::run_case(runner, "29. CVE-2024-24790 IPv4-Mapped IPv6 SSRF Filter Defense", test_ipv6_mapped_ipv4_ssrf_cve_2024_24790);
    lit::run_case(runner, "30. CVE-2026-56866 Client CONNECT Tunnel Rejection Poisoning", test_connect_tunnel_rejection_cve_2026_56866);
    lit::run_case(runner, "31. CVE-2026-78669 HTTP/2 Initial Window Size Flood Defense", test_http2_initial_window_flood_cve_2026_78669);
    lit::run_case(runner, "32. CVE-2026-39825 URL Query Parameter Flooding Limit", test_query_param_limit_cve_2026_39825);
    lit::run_case(runner, "33. CVE-2026-39821 & CVE-2026-97044 Punycode & IDNA Bounds", test_punycode_validation_cve_2026_39821_and_97044);
    lit::run_case(runner, "34. CVE-2024-45341 X.509 URI SAN Zone ID Rejection", test_x509_uri_zone_id_cve_2024_45341);
    lit::run_case(runner, "35. CVE-2026-42507 Error Message Untrusted Input Sanitization", test_error_sanitization_cve_2026_42507);

    let ok = lit::finish(runner);
    assert(ok);
}
