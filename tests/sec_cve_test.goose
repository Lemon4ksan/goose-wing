// Verification suite for uncovered CVEs:
//   1. CVE-2021-28918 & CVE-2021-29922: Octal, Hex, Dword, and Shorthand IPv4 SSRF Bypass.
//   2. CVE-2024-24790 & RFC 6761: localhost, uncompressed IPv6, IPv4-compatible, NAT64 & 6to4 SSRF.
//   3. CVE-2023-26159 & RFC 9110: CRLF and Control-Character Injection in Headers.
//   4. CVE-2022-27776 & CVE-2023-43804: Port-change Credential Leaks, Signature Stripping & Conditional Headers.
//   5. CVE-2023-27534 & CVE-2022-35252: Cookie URL Userinfo/Fragment/Path Discrepancies and Query-Hash Ordering.
//   6. CVE-2016-8616: PSL Supercookie and CTL Injection via Netscape Cookie Import.
import std;
import wing from "..";

// ----------------------------------------------------------------------------
// 1. CVE-2021-28918 & CVE-2021-29922: Octal, Hex, Dword, Shorthand IPv4 SSRF
// ----------------------------------------------------------------------------
fn test_cve_ipv4_formats_ssrf(t: wing::T&) {
    t.run("Octal IPv4 (0177.0.0.1) must be blocked as Loopback") { sub =>
        var session = wing::new_session();
        wing::enable_ssrf_guard(session, true);

        var req_oct = wing::new_get("http://0177.0.0.1/admin");
        let res_oct, err_oct = wing::execute_request(session, req_oct);
        sub.assert_false(wing::ok(err_oct), "0177.0.0.1 octal loopback must be blocked by SSRF guard");
    };

    t.run("Dword/Integer IPv4 (2130706433) must be blocked as Loopback") { sub =>
        var session = wing::new_session();
        wing::enable_ssrf_guard(session, true);

        var req_int = wing::new_get("http://2130706433/admin");
        let res_int, err_int = wing::execute_request(session, req_int);
        sub.assert_false(wing::ok(err_int), "2130706433 integer loopback must be blocked by SSRF guard");
    };

    t.run("Hex IPv4 (0x7f000001 and 0x7f.0.0.1) must be blocked as Loopback") { sub =>
        var session = wing::new_session();
        wing::enable_ssrf_guard(session, true);

        var req_hex1 = wing::new_get("http://0x7f000001/admin");
        let res_hex1, err_hex1 = wing::execute_request(session, req_hex1);
        sub.assert_false(wing::ok(err_hex1), "0x7f000001 hex loopback must be blocked");

        var req_hex2 = wing::new_get("http://0x7f.0.0.1/admin");
        let res_hex2, err_hex2 = wing::execute_request(session, req_hex2);
        sub.assert_false(wing::ok(err_hex2), "0x7f.0.0.1 dotted-hex loopback must be blocked");
    };

    t.run("Shorthand IPv4 (127.1 and 10.1) must be blocked") { sub =>
        var session = wing::new_session();
        wing::enable_ssrf_guard(session, true);

        var req_s1 = wing::new_get("http://127.1/admin");
        let res_s1, err_s1 = wing::execute_request(session, req_s1);
        sub.assert_false(wing::ok(err_s1), "127.1 shorthand loopback must be blocked");

        var req_s2 = wing::new_get("http://10.1/internal");
        let res_s2, err_s2 = wing::execute_request(session, req_s2);
        sub.assert_false(wing::ok(err_s2), "10.1 shorthand private 10.0.0.1 must be blocked");
    };
}

// ----------------------------------------------------------------------------
// 2. CVE-2024-24790 & RFC 6761: Localhost, Uncompressed IPv6 & Tunnel SSRF
// ----------------------------------------------------------------------------
fn test_cve_localhost_and_ipv6_tunnels_ssrf(t: wing::T&) {
    t.run("RFC 6761: localhost, localhost. and *.localhost must be blocked") { sub =>
        var session = wing::new_session();
        wing::enable_ssrf_guard(session, true);

        var req_lh1 = wing::new_get("http://localhost/admin");
        let res_lh1, err_lh1 = wing::execute_request(session, req_lh1);
        sub.assert_false(wing::ok(err_lh1), "http://localhost must be blocked by SSRF guard");

        var req_lh2 = wing::new_get("http://localhost./admin");
        let res_lh2, err_lh2 = wing::execute_request(session, req_lh2);
        sub.assert_false(wing::ok(err_lh2), "http://localhost. (FQDN) must be blocked by SSRF guard");

        var req_lh3 = wing::new_get("http://service.localhost/admin");
        let res_lh3, err_lh3 = wing::execute_request(session, req_lh3);
        sub.assert_false(wing::ok(err_lh3), "http://service.localhost must be blocked by SSRF guard");
    };

    t.run("DNS Rebinding with Uncompressed IPv6 Loopback") { sub =>
        var session = wing::new_session();
        wing::enable_ssrf_guard(session, true);

        wing::mock_route(session, "GET", "http://rebind-uncompressed.com/api", 200, "ok");
        wing::add_mock_resolved_ip(session, "0:0:0:0:0:0:0:1");

        var req = wing::new_get("http://rebind-uncompressed.com/api");
        let res, err = wing::execute_request(session, req);
        sub.assert_false(wing::ok(err), "DNS rebinding with 0:0:0:0:0:0:0:1 must be blocked");
    };

    t.run("IPv4-Compatible IPv6 and NAT64 Tunnels") { sub =>
        var session = wing::new_session();
        wing::enable_ssrf_guard(session, true);

        // IPv4-compatible loopback [::127.0.0.1]
        var req_compat = wing::new_get("http://[::127.0.0.1]/status");
        let res_c, err_c = wing::execute_request(session, req_compat);
        sub.assert_false(wing::ok(err_c), "[::127.0.0.1] IPv4-compatible loopback must be blocked");

        // NAT64 well-known prefix [64:ff9b::127.0.0.1]
        var req_nat64 = wing::new_get("http://[64:ff9b::127.0.0.1]/status");
        let res_nat, err_nat = wing::execute_request(session, req_nat64);
        sub.assert_false(wing::ok(err_nat), "[64:ff9b::127.0.0.1] NAT64 loopback must be blocked");

        // 6to4 tunnel [2002:7f00:1::]
        var req_6to4 = wing::new_get("http://[2002:7f00:1::]/status");
        let res_6to4, err_6to4 = wing::execute_request(session, req_6to4);
        sub.assert_false(wing::ok(err_6to4), "[2002:7f00:1::] 6to4 loopback must be blocked");
    };
}

// ----------------------------------------------------------------------------
// 3. CVE-2023-26159 & RFC 9110 Section 5.5: CRLF / Control-Char Header Injection
// ----------------------------------------------------------------------------
fn test_cve_crlf_header_injection(t: wing::T&) {
    t.run("Header Name with CRLF or Control Characters must be Sanitized/Rejected") { sub =>
        var req = wing::new_get("https://example.com/api");
        wing::header(req, "X-Injected\r\nEvil: true", "valid-value");

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
        wing::header(req, "X-Test", "value\r\nSet-Cookie: pwned=true");

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
fn test_cve_port_change_and_representation_headers(t: wing::T&) {
    t.run("CVE-2022-27776: Port Change on Trusted Host Must Strip Authorization") { sub =>
        var req = wing::new_get("https://example.com:443/login");
        wing::header(req, "Authorization", "Bearer top_secret");
        wing::header(req, "X-API-Key", "secret-key-123");

        // Redirect to same hostname example.com, but different port 8443
        let redirect_info = wing::compute_redirect_info(
            "GET", 302, "https://example.com:443/login", "https://example.com:8443/admin",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://example.com:443/login",
            false, false
        );

        sub.assert_true(redirect_info.is_cross_origin, "different port must be cross-origin");

        // Even with trusted_location_forwarding = true, port change must NOT leak credentials!
        wing::sanitize_headers_on_redirect(req.headers, redirect_info, false, false, true, true);

        var has_auth = false;
        var has_key = false;
        for hdr in req.headers {
            if wing::eq_ascii_fold(hdr.name[..], "Authorization") { has_auth = true; }
            if wing::eq_ascii_fold(hdr.name[..], "X-API-Key") { has_key = true; }
        }
        sub.assert_false(has_auth, "Authorization must be stripped across port change even if hostname is trusted");
        sub.assert_false(has_key, "X-API-Key must be stripped across port change even if hostname is trusted");
    };

    t.run("Cross-Origin Redirect Must Strip Signatures and CSRF Tokens") { sub =>
        var req = wing::new_post("https://example.com/api");
        wing::sign_hmac_sha256(req, "secret");
        wing::header(req, "X-CSRF-Token", "csrf-token-abc");

        let redirect_info = wing::compute_redirect_info(
            "POST", 302, "https://example.com/api", "https://other.com/api",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://example.com/api",
            false, false
        );

        wing::sanitize_headers_on_redirect(req.headers, redirect_info, false, false, true, false);

        var has_sig = false;
        var has_csrf = false;
        for hdr in req.headers {
            if wing::eq_ascii_fold(hdr.name[..], "X-Signature-256") { has_sig = true; }
            if wing::eq_ascii_fold(hdr.name[..], "X-CSRF-Token") { has_csrf = true; }
        }
        sub.assert_false(has_sig, "X-Signature-256 must be stripped on cross-origin redirect");
        sub.assert_false(has_csrf, "X-CSRF-Token must be stripped on cross-origin redirect");
    };

    t.run("Method Mutation to GET Must Strip Conditional / Representation Headers") { sub =>
        var req = wing::new_post("https://example.com/upload");
        wing::header(req, "If-Match", "\"etag-123\"");
        wing::header(req, "If-None-Match", "\"etag-456\"");
        wing::header(req, "Expect", "100-continue");

        let redirect_info = wing::compute_redirect_info(
            "POST", 303, "https://example.com/upload", "https://example.com/status",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://example.com/upload",
            false, false
        );
        sub.assert_true(redirect_info.clear_body, "303 clears body");

        wing::sanitize_headers_on_redirect(req.headers, redirect_info, false, false, true, false);

        var has_if_match = false;
        var has_if_none_match = false;
        var has_expect = false;
        for hdr in req.headers {
            if wing::eq_ascii_fold(hdr.name[..], "If-Match") { has_if_match = true; }
            if wing::eq_ascii_fold(hdr.name[..], "If-None-Match") { has_if_none_match = true; }
            if wing::eq_ascii_fold(hdr.name[..], "Expect") { has_expect = true; }
        }
        sub.assert_false(has_if_match, "If-Match must be stripped when method mutates to GET");
        sub.assert_false(has_if_none_match, "If-None-Match must be stripped when method mutates to GET");
        sub.assert_false(has_expect, "Expect must be stripped when method mutates to GET");
    };
}

// ----------------------------------------------------------------------------
// 5. CVE-2023-27534 & CVE-2022-35252: Cookie URL Ambiguity & Query Ordering
// ----------------------------------------------------------------------------
fn test_cve_cookie_url_and_query_ordering(t: wing::T&) {
    t.run("parse_canonical_cookie_url: Userinfo and Fragment Isolation") { sub =>
        let u = wing::parse_canonical_cookie_url("https://user:pass@example.com:8443/a/b#section/1");
        sub.assert_bytes_eq(u.host[..], "example.com", "host must not include userinfo");
        sub.assert_eq(u.port, 8443, "port must be 8443");
        sub.assert_bytes_eq(u.path[..], "/a/b", "path must not include fragment");
    };

    t.run("set_cookie_header: Normalizes Path Dot-Segments") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let clock = wing::new_mock_clock();

        let ok = wing::set_cookie_header(jar, "https://example.com/admin/../public", "sid=xyz", clock.now_us);
        sub.assert_true(ok, "cookie accepted");
        sub.assert_eq(jar.cookies.len, 1);
        if jar.cookies.len > 0 {
            sub.assert_bytes_eq(jar.cookies[0].path[..], "/", "default path must normalize /admin/.. to /");
        }
    };

    t.run("build_effective_url: Query Parameters Must Precede Fragment") { sub =>
        var out: u8[..2048] = [];
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
fn test_cve_netscape_import_security(t: wing::T&) {
    t.run("Netscape Import: Public Suffix Domain Supercookie Must Be Rejected") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let clock = wing::new_mock_clock();

        let netscape_psl = "co.uk\tTRUE\t/\tFALSE\t0\tsupercookie\tevil\n";
        let count = wing::import_canonical_netscape(jar, netscape_psl, clock.now_us);

        sub.assert_eq(count, 0, "supercookie on public suffix co.uk must not be imported");
        sub.assert_eq(jar.cookies.len, 0, "jar must remain empty");
    };

    t.run("Netscape Import: CTL Character in Cookie Must Be Rejected") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let clock = wing::new_mock_clock();

        let netscape_ctl = "example.com\tTRUE\t/\tFALSE\t0\tbad\x01name\tval\n";
        let count = wing::import_canonical_netscape(jar, netscape_ctl, clock.now_us);

        sub.assert_eq(count, 0, "cookie with CTL byte in name must not be imported");
        sub.assert_eq(jar.cookies.len, 0, "jar must remain empty");
    };
}

// ----------------------------------------------------------------------------
// 7. CVE-2026-94441: Unencrypted H2 vs HTTPS Transport & Pool Isolation
// ----------------------------------------------------------------------------
fn test_cve_2026_94441_h2_scheme_isolation(t: wing::T&) {
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
            conn_id: 1,
            key: key_h2c,
            protocol: wing::NegotiatedProtocol.Http2,
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
fn test_cve_connect_tunnel_security(t: wing::T&) {
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
            conn_id: 42,
            no_new_exchanges: true,
            closed: true,
            ..
        };
        sub.assert_false(wing::is_connection_healthy(conn, 1000000000, false), "Failed CONNECT connection is strictly unhealthy");
    };
}

// ----------------------------------------------------------------------------
// 9. CVE-2025-4673 & CVE-2021-33197: Proxy-Authorization & Hop-by-Hop Stripping
// ----------------------------------------------------------------------------
fn test_cve_proxy_authorization_leakage(t: wing::T&) {
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
        wing::header(req, "Proxy-Authorization", "Basic secret_proxy_tok");
        wing::header(req, "Authorization", "Bearer user_token");

        let redirect_info = wing::compute_redirect_info(
            "GET", 302, "https://proxy.origin.com/resource", "https://other-domain.com/landing",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://proxy.origin.com/resource",
            false, false
        );

        wing::sanitize_headers_on_redirect(req.headers, redirect_info, false, false, false, false);

        var has_proxy_auth = false;
        var has_user_auth = false;
        for hdr in req.headers {
            if wing::eq_ascii_fold(hdr.name[..], "Proxy-Authorization") { has_proxy_auth = true; }
            if wing::eq_ascii_fold(hdr.name[..], "Authorization") { has_user_auth = true; }
        }
        sub.assert_false(has_proxy_auth, "Proxy-Authorization must be stripped on cross-origin redirect (CVE-2025-4673)");
        sub.assert_false(has_user_auth, "Authorization must be stripped on cross-origin redirect");
    };
}

// ----------------------------------------------------------------------------
// 10. CVE-2025-22870: IPv6 Zone ID Proxy Bypass & SSRF Defense
// ----------------------------------------------------------------------------
fn test_cve_ipv6_zone_id_proxy_bypass(t: wing::T&) {
    t.run("IPv6 Link-Local with Zone ID (fe80::1%eth0) Blocked by SSRF Guard") { sub =>
        var session = wing::new_session();
        wing::enable_ssrf_guard(session, true);

        // IPv6 link-local with zone ID
        var req_ll = wing::new_get("http://[fe80::1%25eth0]/admin");
        let res_ll, err_ll = wing::execute_request(session, req_ll);
        sub.assert_false(wing::ok(err_ll), "Link-local IPv6 with zone ID must be blocked by SSRF guard (CVE-2025-22870)");
    };
}

// ----------------------------------------------------------------------------
// 11. Go #81671 & RFC 9110: QUERY Method Replayability
// ----------------------------------------------------------------------------
fn test_go_81671_query_method_replayable(t: wing::T&) {
    t.run("Go #81671: QUERY Method Replayability on Stale Socket Drop") { sub =>
        sub.assert_true(wing::is_idempotent_method("QUERY"), "QUERY is semantically idempotent per RFC 9110");
        sub.assert_true(wing::is_idempotent_method("query"), "QUERY case-insensitive check matches");

        var req = wing::new_request("QUERY", "https://api.io/search");
        wing::text(req, "{\"filter\": \"status=active\"}");

        // On reused socket before response headers arrived, QUERY is replayable
        let can_retry = wing::should_retry_tier1_stale_socket(true, false, req);
        sub.assert_true(can_retry, "QUERY request replayable on stale Keep-Alive connection drop (Go #81671)");

        // If body is unrewindable, must NOT retry (protecting payload integrity)
        req.rewindable = false;
        let cant_retry_unrewind = wing::should_retry_tier1_stale_socket(true, false, req);
        sub.assert_false(cant_retry_unrewind, "Unrewindable QUERY request must not be retried");
    };
}

// ----------------------------------------------------------------------------
// Suite Entry Point
// ----------------------------------------------------------------------------
fn main() {
    var runner = wing::new_runner("CVE Regression Suite", wing::Verbosity.Verbose);

    wing::run_case(runner, "1. CVE-2021-28918 & CVE-2021-29922 (Octal/Hex/Dword/Shorthand IPv4 SSRF)", test_cve_ipv4_formats_ssrf);
    wing::run_case(runner, "2. CVE-2024-24790 & RFC 6761 (Localhost, Uncompressed IPv6 & Tunnel SSRF)", test_cve_localhost_and_ipv6_tunnels_ssrf);
    wing::run_case(runner, "3. CVE-2023-26159 & RFC 9110 (CRLF / Control-Char Header Injection)", test_cve_crlf_header_injection);
    wing::run_case(runner, "4. CVE-2022-27776 & CVE-2023-43804 (Port Change Credential Leaks & Headers)", test_cve_port_change_and_representation_headers);
    wing::run_case(runner, "5. CVE-2023-27534 & CVE-2022-35252 (Cookie URL Ambiguity & Query Ordering)", test_cve_cookie_url_and_query_ordering);
    wing::run_case(runner, "6. CVE-2016-8616 (PSL Supercookie & CTL Injection in Store Import)", test_cve_netscape_import_security);
    wing::run_case(runner, "7. CVE-2026-94441 (Unencrypted H2 vs HTTPS Scheme & Pool Isolation)", test_cve_2026_94441_h2_scheme_isolation);
    wing::run_case(runner, "8. CVE-2026-56866 & CVE-2026-94439 (CONNECT Tunnel Desync & Buffer Hygiene)", test_cve_connect_tunnel_security);
    wing::run_case(runner, "9. CVE-2025-4673 & CVE-2021-33197 (Proxy-Authorization Leakage & Header Stripping)", test_cve_proxy_authorization_leakage);
    wing::run_case(runner, "10. CVE-2025-22870 (IPv6 Zone ID Proxy Bypass & SSRF Defense)", test_cve_ipv6_zone_id_proxy_bypass);
    wing::run_case(runner, "11. Go #81671 & RFC 9110 (QUERY Method Replayability)", test_go_81671_query_method_replayable);

    let ok = wing::finish(runner);
    assert(ok);
}
