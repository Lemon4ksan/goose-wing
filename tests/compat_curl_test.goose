// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: curl Protocol & Wire Behavioral Compatibility Suite
// Ported behavioral test vectors and conformance checks from curl (tests/data/test*).
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// ----------------------------------------------------------------------------
// 1. HTTP Redirect Method Mutation & Payload Stripping
// Corresponds to curl tests:
//   test1011: HTTP POST with 301 redirect (RFC 9110 Section 15.4.2)
//   test1076: HTTP POST with 302 redirect (RFC 9110 Section 15.4.3)
//   test1332: HTTP POST with 303 redirect (RFC 9110 Section 15.4.4)
//   test1579: Custom PUT with 303 redirect => GET
//   test1983: HTTP DELETE with 303 redirect => GET
//   test1325: HTTP 308 redirect with POST (RFC 9110 Section 15.4.9)
//   test1580: Custom PUT with 308 redirect => PUT preserved
// ----------------------------------------------------------------------------
fn test_curl_redirect_method_mutation(t: lit::T&) {
    t.run("curl test1011 & test1076: POST with 301 and 302 rewrites to GET and clears body") { sub =>
        // 301 Moved Permanently
        let info_301 = wing::compute_redirect_info(
            "POST", 301, "https://example.com/api/v1/submit", "https://example.com/api/v2/submit",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://example.com/api/v1/submit",
        );
        sub.assert_bytes_eq(info_301.new_method[..], "GET", "301 mutates POST to GET");
        sub.assert_true(info_301.clear_body, "301 signals clear_body");

        // 302 Found
        let info_302 = wing::compute_redirect_info(
            "POST", 302, "https://example.com/login", "https://example.com/home",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://example.com/login",
        );
        sub.assert_bytes_eq(info_302.new_method[..], "GET", "302 mutates POST to GET");
        sub.assert_true(info_302.clear_body, "302 signals clear_body");

        // Verify payload headers stripped when clear_body is true
        var req = wing::new_post("https://example.com/api/v1/submit");
        wing::set_header(req, "Content-Length", "1024");
        wing::set_header(req, "Content-Type", "application/json");
        wing::set_header(req, "Transfer-Encoding", "chunked");
        wing::set_header(req, "Accept", "text/html");

        wing::sanitize_headers_on_redirect(req.headers, info_301);
        sub.assert_false(wing::has_header(req, "Content-Length"), "Content-Length stripped");
        sub.assert_false(wing::has_header(req, "Content-Type"), "Content-Type stripped");
        sub.assert_false(wing::has_header(req, "Transfer-Encoding"), "Transfer-Encoding stripped");
        sub.assert_true(wing::has_header(req, "Accept"), "Accept header preserved");
    };

    t.run("curl test1332, test1579, test1983: 303 See Other rewrites all non-GET/HEAD methods to GET") { sub =>
        // POST -> GET
        let info_post = wing::compute_redirect_info(
            "POST", 303, "https://example.com/orders", "https://example.com/orders/42",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://example.com/orders",
        );
        sub.assert_bytes_eq(info_post.new_method[..], "GET", "303 mutates POST to GET");
        sub.assert_true(info_post.clear_body, "body cleared");

        // PUT -> GET
        let info_put = wing::compute_redirect_info(
            "PUT", 303, "https://example.com/files/upload", "https://example.com/files/view",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://example.com/files/upload",
        );
        sub.assert_bytes_eq(info_put.new_method[..], "GET", "303 mutates PUT to GET");
        sub.assert_true(info_put.clear_body, "body cleared");

        // DELETE -> GET
        let info_del = wing::compute_redirect_info(
            "DELETE", 303, "https://example.com/item/1", "https://example.com/item/deleted",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://example.com/item/1",
        );
        sub.assert_bytes_eq(info_del.new_method[..], "GET", "303 mutates DELETE to GET");
        sub.assert_true(info_del.clear_body, "body cleared");
    };

    t.run("curl test1325 & test1580: 307 and 308 strictly preserve method and body") { sub =>
        // 307 Temporary Redirect with POST
        let info_307 = wing::compute_redirect_info(
            "POST", 307, "https://example.com/api/post", "https://backup.example.com/api/post",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://example.com/api/post",
        );
        sub.assert_bytes_eq(info_307.new_method[..], "POST", "307 preserves POST");
        sub.assert_false(info_307.clear_body, "307 does not clear body");

        // 308 Permanent Redirect with PUT
        let info_308 = wing::compute_redirect_info(
            "PUT", 308, "https://example.com/blob", "https://storage.example.com/blob",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://example.com/blob",
        );
        sub.assert_bytes_eq(info_308.new_method[..], "PUT", "308 preserves PUT");
        sub.assert_false(info_308.clear_body, "308 does not clear body");

        // Headers preserved when clear_body is false
        var req_308 = wing::new_post("https://example.com/blob");
        wing::set_header(req_308, "Content-Length", "2048");
        wing::set_header(req_308, "Content-Type", "application/octet-stream");
        wing::sanitize_headers_on_redirect(req_308.headers, info_308);
        sub.assert_true(wing::has_header(req_308, "Content-Length"), "Content-Length preserved on 308");
        sub.assert_true(wing::has_header(req_308, "Content-Type"), "Content-Type preserved on 308");
    };
}

// ----------------------------------------------------------------------------
// 2. Cross-Origin Sensitive Credential Stripping
// Corresponds to curl tests:
//   test317: HTTP with custom Authorization: and redirect to new host
//   test318: HTTP with custom Authorization: same host preserves auth
//   test330: HTTP with custom Cookie: and redirect to new host
//   test778: HTTP --oauth2-bearer redirect to new host (stripped)
//   test1077: Cross-origin redirect credential defense
//   test3106: HTTPS to HTTP downgrade strips credentials
// ----------------------------------------------------------------------------
fn test_curl_cross_origin_sanitization(t: lit::T&) {
    t.run("curl test317, test330, test778, test1077: cross-origin hop strips credentials and Host") { sub =>
        let redirect_info = wing::compute_redirect_info(
            "GET", 302, "https://auth.example.com/user", "https://untrusted.cdn.net/assets",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://auth.example.com/user",
        );
        sub.assert_true(redirect_info.is_cross_origin, "detected cross-origin hop");

        var req = wing::new_get("https://auth.example.com/user");
        wing::set_header(req, "Authorization", "Bearer topsecret_oauth_token");
        wing::set_header(req, "Proxy-Authorization", "Basic dXNlcjpwYXNz");
        wing::set_header(req, "Cookie", "session=active_login; secure_pref=1");
        wing::set_header(req, "X-API-Key", "private_api_key_888");
        wing::set_header(req, "Host", "auth.example.com");
        wing::set_header(req, "X-Request-ID", "req-12345");

        wing::sanitize_headers_on_redirect(req.headers, redirect_info);

        sub.assert_false(wing::has_header(req, "Authorization"), "Authorization stripped on cross-origin");
        sub.assert_false(wing::has_header(req, "Proxy-Authorization"), "Proxy-Authorization stripped");
        sub.assert_false(wing::has_header(req, "Cookie"), "Cookie stripped on cross-origin");
        sub.assert_false(wing::has_header(req, "X-API-Key"), "X-API-Key stripped");
        sub.assert_false(wing::has_header(req, "Host"), "Stale Host header stripped");
        sub.assert_true(wing::has_header(req, "X-Request-ID"), "Safe custom header preserved");
    };

    t.run("curl test318: same-origin redirect preserves Authorization and credentials") { sub =>
        let redirect_info = wing::compute_redirect_info(
            "GET", 302, "https://auth.example.com/v1/profile", "https://auth.example.com/v2/profile",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://auth.example.com/v1/profile",
        );
        sub.assert_false(redirect_info.is_cross_origin, "same-origin hop");
        sub.assert_false(redirect_info.is_scheme_downgrade, "no downgrade");

        var req = wing::new_get("https://auth.example.com/v1/profile");
        wing::set_header(req, "Authorization", "Bearer valid_token");
        wing::set_header(req, "X-Request-ID", "req-same-origin");

        wing::sanitize_headers_on_redirect(req.headers, redirect_info);
        sub.assert_true(wing::has_header(req, "Authorization"), "Authorization preserved on same-origin");
        sub.assert_true(wing::has_header(req, "X-Request-ID"), "X-Request-ID preserved");
    };

    t.run("curl test3106: HTTPS to HTTP scheme downgrade strips credentials even on same host") { sub =>
        let redirect_info = wing::compute_redirect_info(
            "GET", 302, "https://secure.example.com/area", "http://secure.example.com/area",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://secure.example.com/area",
        );
        sub.assert_true(redirect_info.is_scheme_downgrade, "detected scheme downgrade");

        var req = wing::new_get("https://secure.example.com/area");
        wing::set_header(req, "Authorization", "Bearer downgrade_token");
        wing::set_header(req, "Cookie", "secure_sess=secret");

        wing::sanitize_headers_on_redirect(req.headers, redirect_info);
        sub.assert_false(wing::has_header(req, "Authorization"), "Authorization stripped on downgrade");
        sub.assert_false(wing::has_header(req, "Cookie"), "Cookie stripped on downgrade");
    };
}

// ----------------------------------------------------------------------------
// 3. Location URL Resolution: Query Strings, Dot Segments & Protocols
// Corresponds to curl tests:
//   test1031: HTTP Location: following to a query string (?query)
//   test1314: HTTP Location: following a // prefixed url
//   test49:   HTTP follow redirect with ../
//   test50:   HTTP follow redirect with ../../
//   test52:   HTTP follow redirect with ./-prefix
//   test1413: HTTP redirect with fragment in new URL
// ----------------------------------------------------------------------------
fn test_curl_location_url_resolution(t: lit::T&) {
    t.run("curl test1031: Location with relative query string (?page=2)") { sub =>
        let base_url = core::new_url("https://example.com/search?page=1");
        let target, err = core::parse_url_with_base("?page=2", base_url);
        sub.assert_true(target.valid, "URL parsed with query base");
        sub.assert_bytes_eq(core::pathname(target), "/search", "path preserved");
        sub.assert_bytes_eq(core::search(target), "?page=2", "query updated");
    };

    t.run("curl test1314: Location with protocol-relative URL (//cdn.domain.org/path)") { sub =>
        let base_url = core::new_url("https://example.com/landing");
        let target, err = core::parse_url_with_base("//cdn.example.org/bundles/app.js", base_url);
        sub.assert_true(target.valid, "Protocol-relative URL valid");
        sub.assert_bytes_eq(core::scheme(target), "https", "inherits https scheme");
        sub.assert_bytes_eq(core::hostname(target), "cdn.example.org", "target host derived");
        sub.assert_bytes_eq(core::pathname(target), "/bundles/app.js", "target path derived");
    };

    t.run("curl test49, test50, test52: Relative dot segment paths (../ and ./)") { sub =>
        let base_url = core::new_url("http://example.com/dir/sub/current.html");

        // ./sibling.html
        let target1, _ = core::parse_url_with_base("./sibling.html", base_url);
        sub.assert_bytes_eq(core::pathname(target1), "/dir/sub/sibling.html", "./ resolves to same directory");

        // ../parent.html
        let target2, _ = core::parse_url_with_base("../parent.html", base_url);
        sub.assert_bytes_eq(core::pathname(target2), "/dir/parent.html", "../ pops one directory level");

        // ../../root.html
        let target3, _ = core::parse_url_with_base("../../root.html", base_url);
        sub.assert_bytes_eq(core::pathname(target3), "/root.html", "../../ pops two directory levels");
    };

    t.run("curl test1413: Location target fragment preserved") { sub =>
        let info = wing::compute_redirect_info(
            "GET", 302, "https://example.com/doc", "https://example.com/doc#section3",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://example.com/doc",
        );
        sub.assert_true(info.error == wing::RedirectError.None, "clean redirect");
        sub.assert_bytes_eq(core::hash(info.new_url), "#section3", "hash fragment preserved in target");
    };
}

// ----------------------------------------------------------------------------
// 4. Redirect Loop & Invalid Location Guards
// Corresponds to curl tests:
//   test25: looping HTTP Location: following with --max-redirs
//   test54: HTTP with blank Location:
// ----------------------------------------------------------------------------
fn test_curl_redirect_guards_and_limits(t: lit::T&) {
    t.run("curl test25: redirect loop exceeding max_redirects returns error") { sub =>
        var session = wing::new_session();
        session.max_redirects = 3;

        // Infinite 302 loop: /step1 -> /step2 -> /step1 ...
        wing::mock_route(session, "GET", "https://example.com/step1", 302, "");
        wing::add_mock_header(session, "Location", "https://example.com/step2");

        wing::mock_route(session, "GET", "https://example.com/step2", 302, "");
        wing::add_mock_header(session, "Location", "https://example.com/step1");

        var req = wing::new_get("https://example.com/step1");
        let res, err = wing::execute_request(session, req);

        sub.assert_false(wing::ok(err), "loop exceeding max_redirs produces error");
        sub.assert_bytes_eq(err.stage[..], "redirect", "failed at redirect stage");
    };

    t.run("curl test54: blank or missing Location header produces MissingLocation error") { sub =>
        let info_blank = wing::compute_redirect_info(
            "GET", 302, "https://example.com/start", "   ",
            wing::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://example.com/start",
        );
        sub.assert_true(info_blank.error == wing::RedirectError.MissingLocation, "blank location flagged MissingLocation");
    };
}

// ----------------------------------------------------------------------------
// 5. Cookie Path Matching Hierarchy & Security Prefixes
// Corresponds to curl tests:
//   test61:   HTTP with various cookies and custom Host:
//   test172:  HTTP with cookies file and custom added cookie
//   test329:  HTTP cookie with Max-Age=0
//   test1228: HTTP cookie path match
//   test1415: Delete expired cookies
//   test1561: Cookies set over HTTP cannot override secure ones
//   test2311: Cookie from file: prefixes case sensitive (__Secure-, __Host-)
// ----------------------------------------------------------------------------
fn test_curl_cookie_path_matching_and_prefix_rules(t: lit::T&) {
    t.run("curl test172 & test1228: RFC 6265 path matching hierarchy") { sub =>
        // Path /sub matches exact /sub, child paths /sub/ and /sub/page
        sub.assert_true(wing::cookie_path_match("/sub", "/sub"), "Exact match matches");
        sub.assert_true(wing::cookie_path_match("/sub/", "/sub"), "Subpath with slash matches");
        sub.assert_true(wing::cookie_path_match("/sub/page", "/sub"), "Nested child path matches");

        // Non-delimiter suffix /subprefix and unrelated paths must NOT match
        sub.assert_false(wing::cookie_path_match("/subprefix", "/sub"), "Prefix without delimiter must NOT match");
        sub.assert_false(wing::cookie_path_match("/other", "/sub"), "Unrelated path must NOT match");
        sub.assert_false(wing::cookie_path_match("/dir", "/dir/page"), "Parent path cannot match child cookie path");

        // Request URL with query string: pathname is /sub, so cookie is sent
        var jar = wing::CanonicalCookieJar { .. };
        wing::set_cookie_header(jar, "https://example.com/sub", "sub_cookie=active; Path=/sub", 1000000);
        var out_hdr: u8[..256] = [];
        wing::build_cookie_header(jar, "https://example.com/sub?filter=active", out_hdr, 1000000);
        sub.assert_contains(out_hdr[..], "sub_cookie=active", "Cookie sent for URL with query string");
    };

    t.run("curl test1561 & test2311: __Secure- and __Host- security prefix rules (RFC 6265bis)") { sub =>
        var jar = wing::CanonicalCookieJar { .. };

        // 1. __Secure- rejected over insecure HTTP
        let ok_sec_http = wing::set_cookie_header(jar, "http://example.com/", "__Secure-token=123", 1000000);
        sub.assert_false(ok_sec_http, "__Secure- on http:// must be rejected");

        // 2. __Secure- rejected over HTTPS if Secure attribute is omitted
        let ok_sec_nosec = wing::set_cookie_header(jar, "https://example.com/", "__Secure-token=123", 1000000);
        sub.assert_false(ok_sec_nosec, "__Secure- without Secure attribute must be rejected");

        // 3. __Secure- accepted over HTTPS with Secure attribute
        let ok_sec_valid = wing::set_cookie_header(jar, "https://example.com/", "__Secure-token=123; Secure", 1000000);
        sub.assert_true(ok_sec_valid, "__Secure- with Secure over https:// accepted");

        // 4. __Host- rejected if Domain attribute is present
        let ok_host_dom = wing::set_cookie_header(jar, "https://example.com/", "__Host-sid=abc; Secure; Domain=example.com; Path=/", 1000000);
        sub.assert_false(ok_host_dom, "__Host- with Domain attribute must be rejected");

        // 5. __Host- rejected if Path is not '/'
        let ok_host_badpath = wing::set_cookie_header(jar, "https://example.com/app", "__Host-sid=abc; Secure; Path=/app", 1000000);
        sub.assert_false(ok_host_badpath, "__Host- with non-root Path must be rejected");

        // 6. __Host- accepted with Secure, no Domain, and Path=/
        let ok_host_valid = wing::set_cookie_header(jar, "https://example.com/", "__Host-sid=abc; Secure; Path=/", 1000000);
        sub.assert_true(ok_host_valid, "__Host- with Secure and Path=/ accepted");

        // 7. curl test1561: Insecure HTTP cannot overwrite Secure cookie
        let ok_overwrite = wing::set_cookie_header(jar, "http://example.com/", "__Secure-token=corrupted", 2000000);
        sub.assert_false(ok_overwrite, "insecure HTTP cannot overwrite pre-existing secure cookie");
    };

    t.run("curl test329 & test1415: Max-Age=0 cookie expiration") { sub =>
        var jar = wing::CanonicalCookieJar { .. };

        // Set valid session cookie
        let ok_init = wing::set_cookie_header(jar, "https://example.com/", "session=active; Secure", 1000000);
        sub.assert_true(ok_init, "session cookie stored");

        // Overwrite with Max-Age=0 (immediate eviction per RFC 6265)
        let ok_evict = wing::set_cookie_header(jar, "https://example.com/", "session=deleted; Max-Age=0; Secure", 1500000);
        sub.assert_true(ok_evict, "Max-Age=0 processed");

        var out_hdr: u8[..256] = [];
        wing::build_cookie_header(jar, "https://example.com/", out_hdr, 1500000);
        sub.assert_not_contains(out_hdr[..], "session=", "expired cookie excluded from outgoing request");
    };
}

// ----------------------------------------------------------------------------
// 6. Netscape cookies.txt Ingestion
// Corresponds to curl tests:
//   test46:   HTTP with cookies and store in cookie jar
//   test62:   HTTP, send cookies when using custom Host:
//   test3104: CURLOPT_COOKIELIST with Netscape format
// ----------------------------------------------------------------------------
fn test_curl_netscape_cookiejar_import(t: lit::T&) {
    t.run("curl test46 & test3104: Netscape cookies.txt format parser") { sub =>
        let netscape_data: const u8[:] = "# Netscape HTTP Cookie File\n# http://curl.se/rfc/cookie_spec.html\n.example.com\tTRUE\t/\tTRUE\t2147483647\tauth_token\tsecret_bearer_999\n#HttpOnly_.bank.com\tTRUE\t/account\tTRUE\t2147483647\tsession_id\tsess_safe_123\n";

        var jar = wing::CanonicalCookieJar { .. };
        let imported = wing::import_netscape(jar, netscape_data, 1000000);

        sub.assert_eq(imported, 2, "Both valid Netscape lines imported");
        sub.assert_eq(jar.cookies.len, 2, "CanonicalCookieJar contains 2 cookies");

        // Verify first cookie
        let c1 = jar.cookies[0];
        sub.assert_bytes_eq(c1.name[..], "auth_token", "first cookie name");
        sub.assert_bytes_eq(c1.value[..], "secret_bearer_999", "first cookie value");
        sub.assert_bytes_eq(c1.domain[..], ".example.com", "first cookie domain");
        sub.assert_bytes_eq(c1.path[..], "/", "first cookie path");
        sub.assert_true(c1.secure, "first cookie secure flag");
        sub.assert_false(c1.httponly, "first cookie not HttpOnly");

        // Verify second cookie with #HttpOnly_ prefix
        let c2 = jar.cookies[1];
        sub.assert_bytes_eq(c2.name[..], "session_id", "second cookie name");
        sub.assert_bytes_eq(c2.value[..], "sess_safe_123", "second cookie value");
        sub.assert_bytes_eq(c2.domain[..], ".bank.com", "second cookie domain");
        sub.assert_bytes_eq(c2.path[..], "/account", "second cookie path");
        sub.assert_true(c2.secure, "second cookie secure flag");
        sub.assert_true(c2.httponly, "second cookie HttpOnly flag recognized from prefix");
    };
}

// ----------------------------------------------------------------------------
// 7. HTTP CONNECT Tunneling & Proxy Protocol
// Corresponds to curl tests:
//   test80:   HTTP 1.0/1.1 CONNECT with proxytunnel and proxy Basic auth
//   test183:  HTTP GET two URLs over a single proxy with persistent connection
//   test1287: HTTP over proxy-tunnel ignore TE and CL in CONNECT 2xx responses
// ----------------------------------------------------------------------------
fn test_curl_connect_tunneling_and_proxy_rules(t: lit::T&) {
    t.run("curl test80: build HTTP CONNECT tunnel request with auth") { sub =>
        var out_req: u8[..1024] = [];
        wing::build_http_connect_request(
            "internal.target.corp",
            8443,
            "Basic dXNlcjpwYXNz",
            "goose-wing/1.0",
            out_req,
        );

        let req_str = out_req[..];
        sub.assert_contains(req_str, "CONNECT internal.target.corp:8443 HTTP/1.1\r\n", "CONNECT request line");
        sub.assert_contains(req_str, "Host: internal.target.corp:8443\r\n", "Host header matching target");
        sub.assert_contains(req_str, "Proxy-Authorization: Basic dXNlcjpwYXNz\r\n", "Proxy-Authorization present");
        sub.assert_contains(req_str, "Proxy-Connection: Keep-Alive\r\n\r\n", "Proxy-Connection header");
    };

    t.run("curl test1287: ignore Content-Length and Transfer-Encoding in CONNECT 2xx response") { sub =>
        // RFC 9110 / curl test1287: A 2xx response to CONNECT has no message body.
        // Content-Length and Transfer-Encoding must be ignored.
        let resp_cl_te = "HTTP/1.1 200 Connection Established\r\nContent-Length: 1234\r\nTransfer-Encoding: chunked\r\nFunny-Header: yes\r\n\r\n";
        let err = wing::verify_connect_tunnel_response(resp_cl_te, 0);
        sub.assert_true(err == wing::ConnectTunnelError.None, "200 CONNECT response accepted despite CL and TE headers");
    };

    t.run("curl test80: proxy headers stripped before origin forwarding") { sub =>
        var req = wing::new_get("http://internal.target.corp:8443");
        wing::set_header(req, "Host", "internal.target.corp:8443");
        wing::set_header(req, "Proxy-Authorization", "Basic dXNlcjpwYXNz");
        wing::set_header(req, "Proxy-Connection", "Keep-Alive");
        wing::set_header(req, "Authorization", "Bearer origin_token");

        wing::sanitize_tunnel_headers_for_origin(req.headers);

        sub.assert_false(wing::has_header(req, "Proxy-Authorization"), "Proxy-Authorization stripped");
        sub.assert_false(wing::has_header(req, "Proxy-Connection"), "Proxy-Connection stripped");
        sub.assert_true(wing::has_header(req, "Host"), "Origin Host preserved");
        sub.assert_true(wing::has_header(req, "Authorization"), "Origin Authorization preserved");
    };
}

// ----------------------------------------------------------------------------
// 8. Expect 100-continue & Fast-Fail Server Evaluation
// Corresponds to curl tests:
//   test357:  HTTP PUT with Expect: 100-continue and 417 response
//   test1129: HTTP POST expect 100-continue with a 404
//   test1130: HTTP POST forced expect 100-continue with a 404
// ----------------------------------------------------------------------------
fn test_curl_expect_100_continue(t: lit::T&) {
    t.run("curl test1129 & test1130: Expect header validation") { sub =>
        var req_valid = wing::new_request("POST", "/upload");
        wing::set_header(req_valid, "Expect", "100-continue");
        sub.assert_true(wing::validate_pipeline_expect_header(req_valid), "100-continue is recognized as valid");

        var req_case = wing::new_request("POST", "/upload");
        wing::set_header(req_case, "Expect", "100-Continue");
        sub.assert_true(wing::validate_pipeline_expect_header(req_case), "case-insensitive 100-Continue is valid");

        var req_invalid = wing::new_request("POST", "/upload");
        wing::set_header(req_invalid, "Expect", "unknown-token-xyz");
        sub.assert_false(wing::validate_pipeline_expect_header(req_invalid), "unrecognized Expect token rejected");
    };

    t.run("curl test357: unsupported Expect token rejected with 417 Expectation Failed") { sub =>
        let quota = wing::new_gcra_quota(100, core::secs(1), 10);
        var cfg = wing::new_server_pipeline_config("example.com", quota);
        wing::add_route(cfg.router, "POST", "/upload", 42);

        var timer = internal::new_connection_timer(30000000000, 1000000000);

        var req = wing::new_request("POST", "/upload");
        wing::set_header(req, "Sec-Fetch-Site", "same-origin");
        wing::set_header(req, "Expect", "unsupported-feature");

        var res = wing::Response { .. };
        var fut = internal::new_inline_handler_future(0);
        let outcome = wing::execute_pipeline(cfg, timer, "127.0.0.1", req, 1000000000, res, fut);

        sub.assert_true(outcome == wing::PipelineOutcome.ExpectationFailed, "pipeline outcome is ExpectationFailed");
        sub.assert_eq(res.status_code, 417, "status code 417 Expectation Failed per RFC 9110");
    };
}

// ----------------------------------------------------------------------------
// 9. Malformed Chunked Hex Sizes (curl test 1941, 1936)
// Vectors:
//   - Non-hex chunk length (e.g. 1Z\r\n..., foo\r\n, +5\r\n, 0x10\r\n)
//   - 64-bit integer overflow in chunk length (FFFFFFFFFFFFFFFF\r\n, oversized hex)
//   - Chunk extension handling (valid 1A;ext=val\r\n vs invalid/corrupted extensions)
//   - Missing CRLF after chunk data bytes
// ----------------------------------------------------------------------------
fn test_curl_malformed_chunk_hex_sizes(t: lit::T&) {
    t.run("curl test 1941, 1936: non-hex chunk length rejected by ChunkedFsmDecoder and stream decoders") { sub =>
        // Vector 1: '1Z' non-hex chunk size
        var fsm1 = internal::new_chunk_fsm_decoder();
        let st1, _, _ = internal::chunk_fsm_feed(fsm1, "1Z\r\nHello\r\n0\r\n\r\n");
        sub.assert_eq(st1, internal::ChunkFsmStatus.Error, "1Z non-hex rejected by ChunkFsmDecoder");

        var dec1 = wing::ChunkedStreamDecoder { .. };
        var out1: u8[..64] = [];
        let ok1, _ = wing::feed_chunked_stream(dec1, "1Z\r\nHello\r\n0\r\n\r\n", out1);
        sub.assert_false(ok1, "1Z non-hex rejected by ChunkedStreamDecoder");
        sub.assert_eq(dec1.error_code, wing::ChunkedDecodeError.InvalidChunkSizeHex, "error code InvalidChunkSizeHex");

        var body1: u8[>..] = [];
        var trailers1 = wing::HeaderMap { .. };
        let err1, _ = wing::decode_chunked_body_with_trailers("1Z\r\nHello\r\n0\r\n\r\n", body1, trailers1);
        sub.assert_eq(err1, wing::ChunkedDecodeError.InvalidChunkSizeHex, "decode_chunked_body rejects 1Z");

        // Vector 2: 'foo' non-hex chunk size
        var fsm2 = internal::new_chunk_fsm_decoder();
        let st2, _, _ = internal::chunk_fsm_feed(fsm2, "foo\r\nHello\r\n0\r\n\r\n");
        sub.assert_eq(st2, internal::ChunkFsmStatus.Error, "foo non-hex rejected by ChunkFsmDecoder");

        var dec2 = wing::ChunkedStreamDecoder { .. };
        var out2: u8[..64] = [];
        let ok2, _ = wing::feed_chunked_stream(dec2, "foo\r\nHello\r\n0\r\n\r\n", out2);
        sub.assert_false(ok2, "foo non-hex rejected by ChunkedStreamDecoder");
        sub.assert_eq(dec2.error_code, wing::ChunkedDecodeError.InvalidChunkSizeHex, "error code InvalidChunkSizeHex for foo");

        // Vector 3: '+5' leading plus sign rejected
        var body3: u8[>..] = [];
        let err3 = wing::decode_chunked_body("+5\r\nHello\r\n0\r\n\r\n", body3);
        sub.assert_eq(err3, wing::ChunkedDecodeError.InvalidChunkSizeHex, "plus sign in chunk size rejected");

        // Vector 4: '0x10' C-style hex prefix rejected
        var body4: u8[>..] = [];
        let err4 = wing::decode_chunked_body("0x10\r\nHello\r\n0\r\n\r\n", body4);
        sub.assert_eq(err4, wing::ChunkedDecodeError.InvalidChunkSizeHex, "0x prefix in chunk size rejected");
    };

    t.run("curl test 1941, 1936: 64-bit integer overflow and oversized hex chunk length rejected") { sub =>
        // Vector 1: FFFFFFFFFFFFFFFF (16 F's - integer overflow)
        var fsm1 = internal::new_chunk_fsm_decoder();
        let st1, _, _ = internal::chunk_fsm_feed(fsm1, "FFFFFFFFFFFFFFFF\r\nfoo\r\n0\r\n\r\n");
        sub.assert_eq(st1, internal::ChunkFsmStatus.Error, "FFFFFFFFFFFFFFFF overflow rejected by ChunkFsmDecoder");

        var dec1 = wing::ChunkedStreamDecoder { .. };
        var out1: u8[..64] = [];
        let ok1, _ = wing::feed_chunked_stream(dec1, "FFFFFFFFFFFFFFFF\r\nfoo\r\n0\r\n\r\n", out1);
        sub.assert_false(ok1, "FFFFFFFFFFFFFFFF overflow rejected by ChunkedStreamDecoder");
        sub.assert_eq(dec1.error_code, wing::ChunkedDecodeError.ChunkSizeOverflow, "error code ChunkSizeOverflow");

        var body1: u8[>..] = [];
        let err1 = wing::decode_chunked_body("FFFFFFFFFFFFFFFF\r\nfoo\r\n0\r\n\r\n", body1);
        sub.assert_eq(err1, wing::ChunkedDecodeError.ChunkSizeOverflow, "decode_chunked_body rejects FFFFFFFFFFFFFFFF overflow");

        // Vector 2: 17-digit hex overflow
        var fsm2 = internal::new_chunk_fsm_decoder();
        let st2, _, _ = internal::chunk_fsm_feed(fsm2, "10000000000000000\r\nfoo\r\n0\r\n\r\n");
        sub.assert_eq(st2, internal::ChunkFsmStatus.Error, "17-digit hex overflow rejected by ChunkFsmDecoder");

        var dec2 = wing::ChunkedStreamDecoder { .. };
        var out2: u8[..64] = [];
        let ok2, _ = wing::feed_chunked_stream(dec2, "10000000000000000\r\nfoo\r\n0\r\n\r\n", out2);
        sub.assert_false(ok2, "17-digit hex overflow rejected by ChunkedStreamDecoder");
        sub.assert_eq(dec2.error_code, wing::ChunkedDecodeError.ChunkSizeOverflow, "error code ChunkSizeOverflow for 17 digits");
    };

    t.run("curl test 1941, 1936: chunk extension handling for valid and corrupted extensions") { sub =>
        // Vector 1: Valid chunk extension 1A;ext=val (26 bytes: 'a'..'z')
        let raw_1a = "1A;ext=val\r\nabcdefghijklmnopqrstuvwxyz\r\n0\r\n\r\n";

        var fsm1 = internal::new_chunk_fsm_decoder();
        let st1, _, chunk1 = internal::chunk_fsm_feed(fsm1, raw_1a);
        sub.assert_eq(st1, internal::ChunkFsmStatus.YieldChunk, "FSM yields chunk for 1A;ext=val");
        sub.assert_bytes_eq(chunk1, "abcdefghijklmnopqrstuvwxyz", "FSM yields 26 payload bytes");

        var dec1 = wing::ChunkedStreamDecoder { .. };
        var out1: u8[..64] = [];
        let ok1, cons1 = wing::feed_chunked_stream(dec1, raw_1a, out1);
        sub.assert_true(ok1, "ChunkedStreamDecoder parses 1A;ext=val cleanly");
        sub.assert_bytes_eq(out1[..], "abcdefghijklmnopqrstuvwxyz", "emitted chunk payload matches");
        sub.assert_true(wing::is_complete(dec1), "stream is complete");
        sub.assert_eq(cons1, raw_1a.len, "all bytes consumed");

        var body1: u8[>..] = [];
        var trailers1 = wing::HeaderMap { .. };
        let err1, _ = wing::decode_chunked_body_with_trailers(raw_1a, body1, trailers1);
        sub.assert_eq(err1, wing::ChunkedDecodeError.None, "decoded 1A with extension cleanly");
        sub.assert_bytes_eq(body1[..], "abcdefghijklmnopqrstuvwxyz", "decoded body matches");

        // Vector 2: Quoted-string extension with escaped quote
        let raw_quote = "5;desc=\"quoted \\\"val\\\"\"\r\nHello\r\n0\r\n\r\n";
        var body_q: u8[>..] = [];
        var trailers_q = wing::HeaderMap { .. };
        let err_q, _ = wing::decode_chunked_body_with_trailers(raw_quote, body_q, trailers_q);
        sub.assert_eq(err_q, wing::ChunkedDecodeError.None, "quoted extension parsed cleanly");
        sub.assert_bytes_eq(body_q[..], "Hello", "quoted extension payload matches");

        // Vector 3: Corrupted extension with missing name before '=' (5;=val)
        var fsm_bad1 = internal::new_chunk_fsm_decoder();
        let st_bad1, _, _ = internal::chunk_fsm_feed(fsm_bad1, "5;=val\r\nHello\r\n0\r\n\r\n");
        sub.assert_eq(st_bad1, internal::ChunkFsmStatus.Error, "FSM rejects missing extension name");

        var dec_bad1 = wing::ChunkedStreamDecoder { .. };
        var out_bad1: u8[..64] = [];
        let ok_bad1, _ = wing::feed_chunked_stream(dec_bad1, "5;=val\r\nHello\r\n0\r\n\r\n", out_bad1);
        sub.assert_false(ok_bad1, "ChunkedStreamDecoder rejects missing extension name");

        // Vector 4: Unclosed quoted string in extension
        var fsm_bad2 = internal::new_chunk_fsm_decoder();
        let st_bad2, _, _ = internal::chunk_fsm_feed(fsm_bad2, "5;foo=\"unclosed\r\nHello\r\n0\r\n\r\n");
        sub.assert_eq(st_bad2, internal::ChunkFsmStatus.Error, "FSM rejects unclosed quote in extension");

        var body_bad2: u8[>..] = [];
        var tr_bad2 = wing::HeaderMap { .. };
        let err_bad2, _ = wing::decode_chunked_body_with_trailers("5;foo=\"unclosed\r\nHello\r\n0\r\n\r\n", body_bad2, tr_bad2);
        sub.assert_ne(err_bad2, wing::ChunkedDecodeError.None, "unclosed quote rejected by decoder");

        // Vector 5: Non-token char in extension name (5;foo@bar=1)
        var fsm_bad3 = internal::new_chunk_fsm_decoder();
        let st_bad3, _, _ = internal::chunk_fsm_feed(fsm_bad3, "5;foo@bar=1\r\nHello\r\n0\r\n\r\n");
        sub.assert_eq(st_bad3, internal::ChunkFsmStatus.Error, "FSM rejects @ in extension name");
    };

    t.run("curl test 1941, 1936: missing CRLF after chunk data bytes rejected") { sub =>
        // Vector 1: Replaced CRLF with non-CRLF bytes (4\r\nWikiAB0\r\n\r\n)
        var fsm1 = internal::new_chunk_fsm_decoder();
        let st1, _, _ = internal::chunk_fsm_feed(fsm1, "4\r\nWikiAB0\r\n\r\n");
        sub.assert_eq(st1, internal::ChunkFsmStatus.Error, "FSM rejects missing CRLF after chunk data");

        var dec1 = wing::ChunkedStreamDecoder { .. };
        var out1: u8[..64] = [];
        let ok1, _ = wing::feed_chunked_stream(dec1, "4\r\nWikiAB0\r\n\r\n", out1);
        sub.assert_false(ok1, "ChunkedStreamDecoder rejects missing CRLF after data");
        sub.assert_eq(dec1.error_code, wing::ChunkedDecodeError.MalformedChunkEnding, "error code MalformedChunkEnding");

        var body1: u8[>..] = [];
        let err1 = wing::decode_chunked_body("4\r\nWikiAB0\r\n\r\n", body1);
        sub.assert_eq(err1, wing::ChunkedDecodeError.MalformedChunkEnding, "decode_chunked_body rejects missing CRLF");

        // Vector 2: Bare LF after chunk data (4\r\nWiki\n0\r\n\r\n)
        var dec2 = wing::ChunkedStreamDecoder { .. };
        var out2: u8[..64] = [];
        let ok2, _ = wing::feed_chunked_stream(dec2, "4\r\nWiki\n0\r\n\r\n", out2);
        sub.assert_false(ok2, "ChunkedStreamDecoder rejects bare LF after chunk data");
        sub.assert_eq(dec2.error_code, wing::ChunkedDecodeError.BareLfInChunkData, "error code BareLfInChunkData");

        var body2: u8[>..] = [];
        let err2 = wing::decode_chunked_body("4\r\nWiki\n0\r\n\r\n", body2);
        sub.assert_eq(err2, wing::ChunkedDecodeError.BareLfInChunkData, "decode_chunked_body rejects bare LF");
    };
}

// ----------------------------------------------------------------------------
// 10. Premature Connection Close / Truncated Body (curl test 150, 584)
// Vectors:
//   - Content-Length: 50 with truncated 20-byte payload rejected as unexpected EOF
//   - Chunked response terminating before terminal 0\r\n\r\n rejected as incomplete
//   - Mid-chunk truncation (< chunk-size) rejected as UnexpectedEof
// ----------------------------------------------------------------------------
fn test_curl_premature_close_truncated_body(t: lit::T&) {
    t.run("curl test 150, 584: Content-Length 50 with truncated 20-byte body detected by wire parser and stream reader") { sub =>
        // Vector 1: parse_http1_wire_response with Content-Length: 50 but only 20 bytes received
        let truncated_wire = "HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n12345678901234567890";
        var res_trunc = wing::Response { .. };
        let ok_wire, cons_wire = wing::parse_http1_wire_response(truncated_wire, res_trunc);
        sub.assert_false(ok_wire, "parse_http1_wire_response rejects truncated body when Content-Length: 50 has only 20 bytes");
        sub.assert_eq(cons_wire, 0, "consumed is 0 on truncated response");

        // Vector 2: Full wire response with exactly 50 body bytes succeeds
        let full_wire = "HTTP/1.1 200 OK\r\nContent-Length: 50\r\n\r\n12345678901234567890123456789012345678901234567890";
        var res_full = wing::Response { .. };
        let ok_full, cons_full = wing::parse_http1_wire_response(full_wire, res_full);
        sub.assert_true(ok_full, "full wire response with complete 50 bytes accepted");
        sub.assert_eq(cons_full, full_wire.len, "all wire bytes consumed");
        sub.assert_eq(res_full.body.len, 50, "body length is exactly 50");

        // Vector 3: StreamReader progress and truncation detection
        var partial_resp = wing::Response { status_code: 200, .. };
        wing::set_header(partial_resp, "Content-Length", "50");
        partial_resp.body.append("12345678901234567890"); // 20 bytes received before close
        var reader = wing::new_stream_reader(partial_resp);
        var chunk_buf: u8[..128] = [];
        let st, is_eof = wing::read_chunk(reader, 128, chunk_buf);
        sub.assert_eq(st, wing::StreamReadStatus.Data, "read available 20 bytes from partial stream");
        sub.assert_true(is_eof, "reader reached EOF on closed stream");
        sub.assert_eq(reader.bytes_read, 20, "reader read only 20 bytes");
        sub.assert_eq(reader.content_length, 50, "reader recorded Content-Length 50");

        let prog = wing::stream_progress(reader);
        sub.assert_true(prog.is_finished, "stream reader marked finished at EOF");
        sub.assert_lt(prog.bytes_processed, (prog.total_bytes as u64), "bytes processed (20) < total bytes (50)");
        sub.assert_eq(prog.percent, 40.0, "progress percent accurately reports 40% on premature close");
    };

    t.run("curl test 150, 584: chunked response terminating before terminal 0\\r\\n\\r\\n chunk rejected") { sub =>
        // Vector 1: Complete chunk data but missing final 0\r\n\r\n
        let chunk_wire_trunc = "5\r\nHello\r\n";
        var body1: u8[>..] = [];
        var trailers1 = wing::HeaderMap { .. };
        let err1, _ = wing::decode_chunked_body_with_trailers(chunk_wire_trunc, body1, trailers1);
        sub.assert_eq(err1, wing::ChunkedDecodeError.UnexpectedEof, "decode_chunked_body detects missing 0\\r\\n\\r\\n as UnexpectedEof");

        let wire_resp = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n";
        var res_chunk_trunc = wing::Response { .. };
        let ok_trunc, _ = wing::parse_http1_wire_response(wire_resp, res_chunk_trunc);
        sub.assert_false(ok_trunc, "parse_http1_wire_response rejects truncated chunked response missing 0\\r\\n\\r\\n");

        var dec_stream = wing::ChunkedStreamDecoder { .. };
        var out_stream: u8[..64] = [];
        let ok_stream, _ = wing::feed_chunked_stream(dec_stream, chunk_wire_trunc, out_stream);
        sub.assert_true(ok_stream, "partial chunk processed without syntax error");
        sub.assert_false(wing::is_complete(dec_stream), "decoder incomplete without terminal 0\\r\\n\\r\\n");
        sub.assert_bytes_eq(out_stream[..], "Hello", "first chunk payload received");

        // Vector 2: Truncated mid-chunk payload (3 of 5 bytes)
        let mid_chunk = "5\r\nHel";
        var body2: u8[>..] = [];
        var trailers2 = wing::HeaderMap { .. };
        let err2, _ = wing::decode_chunked_body_with_trailers(mid_chunk, body2, trailers2);
        sub.assert_eq(err2, wing::ChunkedDecodeError.UnexpectedEof, "mid-chunk truncation rejected as UnexpectedEof");

        var fsm_mid = internal::new_chunk_fsm_decoder();
        let st_mid, _, chunk_mid = internal::chunk_fsm_feed(fsm_mid, mid_chunk);
        sub.assert_eq(st_mid, internal::ChunkFsmStatus.YieldChunk, "FSM yields partial 3 bytes");
        sub.assert_bytes_eq(chunk_mid, "Hel", "partial chunk slice emitted");
        sub.assert_true((fsm_mid.state & internal::CHUNK_STATE_IS_CHUNKED) != 0, "FSM remains chunked waiting for remaining bytes");

        // Vector 3: Truncated mid-trailer line
        let trunc_tr = "5\r\nHello\r\n0\r\nExpires: Wed, 21 Oct 2026";
        var body3: u8[>..] = [];
        var trailers3 = wing::HeaderMap { .. };
        let err3, _ = wing::decode_chunked_body_with_trailers(trunc_tr, body3, trailers3);
        sub.assert_eq(err3, wing::ChunkedDecodeError.UnexpectedEof, "truncated trailer line rejected as UnexpectedEof");
    };
}

// ----------------------------------------------------------------------------
// 11. Chunked Trailing Headers (curl test 188, 1090)
// Vectors:
//   - Chunked response followed by trailers (Expires, X-Checksum, Server-Timing)
//   - Multiple trailers extracted and case-insensitively accessible
//   - ChunkedStreamDecoder incremental processing with trailers
//   - Prohibited trailer smuggling defenses per RFC 9112 Section 7.1.2
// ----------------------------------------------------------------------------
fn test_curl_chunked_trailing_headers(t: lit::T&) {
    t.run("curl test 188, 1090: chunked response followed by trailers parsed and accessible") { sub =>
        // Vector 1: Full wire response with chunked body and multiple trailers
        let wire = "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n5\r\nHello\r\n6\r\n World\r\n0\r\nExpires: Wed, 21 Oct 2026 07:28:00 GMT\r\nX-Checksum: sha256-abc123xyz\r\nServer-Timing: total;dur=42.5\r\n\r\n";
        var res = wing::Response { .. };
        let ok_wire, cons_wire = wing::parse_http1_wire_response(wire, res);
        sub.assert_true(ok_wire, "parse_http1_wire_response succeeds with trailers");
        sub.assert_eq(cons_wire, wire.len, "all wire bytes consumed");
        sub.assert_bytes_eq(res.body[..], "Hello World", "reassembled chunked body matches");

        sub.assert_true(wing::has_trailer(res, "Expires"), "has Expires trailer");
        sub.assert_bytes_eq(wing::trailer(res, "Expires"), "Wed, 21 Oct 2026 07:28:00 GMT", "Expires trailer value matches");
        sub.assert_true(wing::has_trailer(res, "X-Checksum"), "has X-Checksum trailer");
        sub.assert_bytes_eq(wing::trailer(res, "X-Checksum"), "sha256-abc123xyz", "X-Checksum trailer value matches");
        sub.assert_true(wing::has_trailer(res, "Server-Timing"), "has Server-Timing trailer");
        sub.assert_bytes_eq(wing::trailer(res, "Server-Timing"), "total;dur=42.5", "Server-Timing value matches");
        sub.assert_false(wing::has_trailer(res, "Non-Existent"), "absent trailer returns false");
        sub.assert_bytes_eq(wing::trailer(res, "Non-Existent"), "", "absent trailer returns empty slice");

        // Vector 2: Direct chunked body decoding with trailers
        let chunk_wire = "5\r\nHello\r\n0\r\nExpires: Wed, 21 Oct 2026 07:28:00 GMT\r\n\r\n";
        var body_raw: u8[>..] = [];
        var trailers_raw = wing::HeaderMap { .. };
        let err_raw, cons_raw = wing::decode_chunked_body_with_trailers(chunk_wire, body_raw, trailers_raw);
        sub.assert_eq(err_raw, wing::ChunkedDecodeError.None, "clean decode with single trailer");
        sub.assert_eq(cons_raw, chunk_wire.len, "exact bytes consumed");
        sub.assert_bytes_eq(body_raw[..], "Hello", "payload matches");
        sub.assert_eq(trailers_raw.entries.len, 1, "exactly 1 trailer extracted");
        sub.assert_bytes_eq(wing::entry_name(trailers_raw, trailers_raw.entries[0]), "Expires", "trailer name is Expires");
        sub.assert_bytes_eq(wing::entry_value(trailers_raw, trailers_raw.entries[0]), "Wed, 21 Oct 2026 07:28:00 GMT", "trailer value matches");

        // Vector 3: Case-insensitive trailer lookup and multiple fields
        let multi_tr = "4\r\ntest\r\n0\r\nExpires: Wed, 21 Oct 2026 07:28:00 GMT\r\nETag: \"abc-123\"\r\nVary: Accept-Encoding\r\n\r\n";
        var body_m: u8[>..] = [];
        var tr_m = wing::HeaderMap { .. };
        let err_m, _ = wing::decode_chunked_body_with_trailers(multi_tr, body_m, tr_m);
        sub.assert_eq(err_m, wing::ChunkedDecodeError.None, "decoded 3 trailers cleanly");
        sub.assert_eq(tr_m.entries.len, 3, "3 trailers extracted into array");

        var res_m = wing::Response { .. };
        wing::append_all_headers(tr_m, res_m.trailers);
        sub.assert_true(wing::has_trailer(res_m, "expires"), "case-insensitive 'expires' found");
        sub.assert_bytes_eq(wing::trailer(res_m, "EXPIRES"), "Wed, 21 Oct 2026 07:28:00 GMT", "case-insensitive 'EXPIRES' lookup matches");
        sub.assert_true(wing::has_trailer(res_m, "etag"), "etag found");
        sub.assert_bytes_eq(wing::trailer(res_m, "etag"), "\"abc-123\"", "etag value matches");
        sub.assert_true(wing::has_trailer(res_m, "vary"), "vary found");
        sub.assert_bytes_eq(wing::trailer(res_m, "VARY"), "Accept-Encoding", "vary value matches");
    };

    t.run("curl test 188, 1090: ChunkedStreamDecoder incremental processing with trailers") { sub =>
        let chunk_data = "5\r\nHello\r\n0\r\nExpires: Wed, 21 Oct 2026 07:28:00 GMT\r\n\r\n";
        var dec = wing::ChunkedStreamDecoder { .. };
        var body: u8[..64] = [];
        let ok, cons = wing::feed_chunked_stream(dec, chunk_data, body);
        sub.assert_true(ok, "feed_chunked_stream parsed successfully");
        sub.assert_true(wing::is_complete(dec), "decoder marked Complete");
        sub.assert_eq(cons, chunk_data.len, "all stream bytes consumed");
        sub.assert_bytes_eq(body[..], "Hello", "body payload extracted");
        sub.assert_eq(dec.trailers.entries.len, 1, "exactly 1 trailer captured");
        sub.assert_bytes_eq(wing::entry_name(dec.trailers, dec.trailers.entries[0]), "Expires", "decoder trailer name");
        sub.assert_bytes_eq(wing::entry_value(dec.trailers, dec.trailers.entries[0]), "Wed, 21 Oct 2026 07:28:00 GMT", "decoder trailer value");

        var resp_copy = wing::Response { .. };
        wing::append_all_headers(dec.trailers, resp_copy.trailers);
        sub.assert_true(wing::has_trailer(resp_copy, "Expires"), "Response has copied trailer");
        sub.assert_bytes_eq(wing::trailer(resp_copy, "Expires"), "Wed, 21 Oct 2026 07:28:00 GMT", "copied trailer value matches");
    };

    t.run("curl test 188, 1090: Disallowed trailer security defenses per RFC 9112 Section 7.1.2") { sub =>
        var body_p: u8[>..] = [];
        var trailers_p = wing::HeaderMap { .. };

        // Content-Length in trailer (framing conflict smuggling)
        let cl_wire = "4\r\nwiki\r\n0\r\nContent-Length: 10\r\n\r\n";
        let e_cl, _ = wing::decode_chunked_body_with_trailers(cl_wire, body_p, trailers_p);
        sub.assert_eq(e_cl, wing::ChunkedDecodeError.DisallowedTrailer, "Content-Length trailer rejected");

        // Transfer-Encoding in trailer
        let te_wire = "4\r\nwiki\r\n0\r\nTransfer-Encoding: chunked\r\n\r\n";
        let e_te, _ = wing::decode_chunked_body_with_trailers(te_wire, body_p, trailers_p);
        sub.assert_eq(e_te, wing::ChunkedDecodeError.DisallowedTrailer, "Transfer-Encoding trailer rejected");

        // Host in trailer
        let host_wire = "4\r\nwiki\r\n0\r\nHost: evil.com\r\n\r\n";
        let e_host, _ = wing::decode_chunked_body_with_trailers(host_wire, body_p, trailers_p);
        sub.assert_eq(e_host, wing::ChunkedDecodeError.DisallowedTrailer, "Host trailer rejected");

        // Set-Cookie in trailer
        let cookie_wire = "4\r\nwiki\r\n0\r\nSet-Cookie: session=hijack\r\n\r\n";
        let e_cookie, _ = wing::decode_chunked_body_with_trailers(cookie_wire, body_p, trailers_p);
        sub.assert_eq(e_cookie, wing::ChunkedDecodeError.DisallowedTrailer, "Set-Cookie trailer rejected");

        // Authorization in trailer
        let auth_wire = "4\r\nwiki\r\n0\r\nAuthorization: Bearer secret\r\n\r\n";
        let e_auth, _ = wing::decode_chunked_body_with_trailers(auth_wire, body_p, trailers_p);
        sub.assert_eq(e_auth, wing::ChunkedDecodeError.DisallowedTrailer, "Authorization trailer rejected");

        // Pseudo-header in trailer (:status: 200)
        let pseudo_wire = "4\r\nwiki\r\n0\r\n:status: 200\r\n\r\n";
        let e_pseudo, _ = wing::decode_chunked_body_with_trailers(pseudo_wire, body_p, trailers_p);
        sub.assert_eq(e_pseudo, wing::ChunkedDecodeError.DisallowedTrailer, ":status pseudo-header trailer rejected");
    };
}

// ----------------------------------------------------------------------------
// 12. URL Port Boundary Parsing (curl unit1653.c & unit1675.c)
// ----------------------------------------------------------------------------
fn test_curl_url_port_boundaries(t: lit::T&) {
    t.run("curl unit1653: valid port boundaries and default port stripping") { sub =>
        // Standard HTTP port 80
        let u_80 = core::new_url("http://example.com:80/");
        sub.assert_true(u_80.valid, "http port 80 is valid");
        sub.assert_eq(core::effective_port(u_80), 80, "effective port is 80");
        sub.assert_bytes_eq(core::port_str(u_80), "", "default http port stripped from wire port_str");

        // Non-default port 443 on HTTP
        let u_443 = core::new_url("http://example.com:443/");
        sub.assert_true(u_443.valid, "http port 443 is valid");
        sub.assert_eq(core::effective_port(u_443), 443, "effective port is 443");
        sub.assert_eq(u_443.port, 443, "explicit non-default port is 443");
        sub.assert_bytes_eq(core::port_str(u_443), "443", "port_str is 443");

        // Maximum 16-bit integer port boundary: 65535
        let u_max = core::new_url("http://example.com:65535/");
        sub.assert_true(u_max.valid, "max port 65535 is valid");
        sub.assert_eq(core::effective_port(u_max), 65535, "effective port is 65535");
        sub.assert_eq(u_max.port, 65535, "url.port is 65535");
        sub.assert_bytes_eq(core::port_str(u_max), "65535", "port_str is 65535");

        // Minimum 16-bit integer port boundary: 0
        let u_0 = core::new_url("http://example.com:0/");
        sub.assert_true(u_0.valid, "port 0 is valid");
        sub.assert_eq(core::effective_port(u_0), 0, "effective port is 0");
        sub.assert_eq(u_0.port, 0, "url.port is 0");
    };

    t.run("curl unit1653: invalid and overflowing port numbers rejected") { sub =>
        // Port exceeding uint16 ceiling (65536)
        let u_65536, err_65536 = core::parse_url("http://example.com:65536/");
        sub.assert_false(u_65536.valid, "port 65536 must fail parsing");
        sub.assert_true(err_65536 == core::UrlParseError.InvalidPort, "err is InvalidPort");

        // Large decimal overflow (999999)
        let u_999999, err_999999 = core::parse_url("http://example.com:999999/");
        sub.assert_false(u_999999.valid, "port 999999 must fail parsing");
        sub.assert_true(err_999999 == core::UrlParseError.InvalidPort, "err is InvalidPort");

        // Negative port (-1)
        let u_neg, err_neg = core::parse_url("http://example.com:-1/");
        sub.assert_false(u_neg.valid, "negative port must fail parsing");
        sub.assert_true(err_neg == core::UrlParseError.InvalidPort, "err is InvalidPort");

        // Non-numeric port (:abc)
        let u_abc, err_abc = core::parse_url("http://example.com:abc/");
        sub.assert_false(u_abc.valid, "non-numeric port :abc must fail parsing");
        sub.assert_true(err_abc == core::UrlParseError.InvalidPort, "err is InvalidPort");
    };

    t.run("curl unit1675: omitted default ports have correct effective ports") { sub =>
        // Omitted port on http scheme defaults to 80
        let u_http = core::new_url("http://example.com");
        sub.assert_true(u_http.valid, "http URL without port is valid");
        sub.assert_eq(core::effective_port(u_http), 80, "http effective port is 80");
        sub.assert_true(u_http.port < 0, "omitted port field is negative / unassigned");
        sub.assert_bytes_eq(core::port_str(u_http), "", "omitted port string is empty");

        // Omitted port on https scheme defaults to 443
        let u_https = core::new_url("https://example.com");
        sub.assert_true(u_https.valid, "https URL without port is valid");
        sub.assert_eq(core::effective_port(u_https), 443, "https effective port is 443");
        sub.assert_true(u_https.port < 0, "omitted port field is negative / unassigned");
        sub.assert_bytes_eq(core::port_str(u_https), "", "omitted port string is empty");
    };
}

// ----------------------------------------------------------------------------
// 13. IPv6 Bracketed and Scoped Addresses (curl test 241, 1056, 1230)
// ----------------------------------------------------------------------------
fn test_curl_ipv6_addresses(t: lit::T&) {
    t.run("curl test 241 & 1230: numerical IPv6 host and custom port parsing") { sub =>
        // Loopback IPv6 with custom port
        let u_loopback = core::new_url("http://[::1]:8080/path");
        sub.assert_true(u_loopback.valid, "IPv6 [::1]:8080 is valid");
        sub.assert_bytes_eq(core::hostname(u_loopback), "[::1]", "hostname is bracketed [::1]");
        sub.assert_eq(core::effective_port(u_loopback), 8080, "effective port is 8080");
        sub.assert_eq(u_loopback.port, 8080, "explicit port is 8080");
        sub.assert_bytes_eq(core::pathname(u_loopback), "/path", "pathname is /path");
        sub.assert_true(core::is_ip_address_literal(core::hostname(u_loopback)), "host is IP literal");
    };

    t.run("curl test 1056: scoped IPv6 with zone ID and IPv4-mapped addresses") { sub =>
        // Scoped link-local IPv6 with zone ID (%25eth0)
        let u_scoped = core::new_url("http://[fe80::1%25eth0]:80/");
        sub.assert_true(u_scoped.valid, "scoped IPv6 with zone ID is valid");
        sub.assert_bytes_eq(core::hostname(u_scoped), "[fe80::1%25eth0]", "zone ID preserved in hostname");
        sub.assert_eq(core::effective_port(u_scoped), 80, "effective port is 80");
        sub.assert_true(core::is_ip_address_literal(core::hostname(u_scoped)), "scoped host is IP literal");

        // IPv4-mapped IPv6 address
        let u_mapped = core::new_url("http://[::ffff:192.168.1.1]:80/");
        sub.assert_true(u_mapped.valid, "IPv4-mapped IPv6 is valid");
        sub.assert_bytes_eq(core::hostname(u_mapped), "[::ffff:c0a8:101]", "IPv4-mapped hex normalized");
        sub.assert_eq(core::effective_port(u_mapped), 80, "effective port is 80");
        sub.assert_true(core::is_ip_address_literal(core::hostname(u_mapped)), "mapped host is IP literal");
    };

    t.run("curl test 241 error vectors: malformed and empty bracketed IPv6 rejected") { sub =>
        // Missing closing bracket
        let u_unclosed, err_unclosed = core::parse_url("http://[::1/path");
        sub.assert_false(u_unclosed.valid, "unclosed bracket MUST be rejected");
        sub.assert_true(err_unclosed == core::UrlParseError.InvalidIpv6, "err is InvalidIpv6");

        // Empty brackets []
        let u_empty, err_empty = core::parse_url("http://[]/");
        sub.assert_false(u_empty.valid, "empty brackets [] MUST be rejected");
        sub.assert_true(err_empty == core::UrlParseError.InvalidIpv6, "err is InvalidIpv6");
    };
}

// ----------------------------------------------------------------------------
// 14. Path and Search Normalization (curl test 40, 42, 1138)
// ----------------------------------------------------------------------------
fn test_curl_path_and_search_normalization(t: lit::T&) {
    t.run("curl test 42: percent-encoding roundtrip in pathname") { sub =>
        let u_space = core::new_url("http://example.com/test%20space");
        sub.assert_true(u_space.valid, "URL with percent-encoded space is valid");
        sub.assert_bytes_eq(core::pathname(u_space), "/test%20space", "percent encoding preserved in pathname");
        sub.assert_bytes_eq(core::href(u_space), "http://example.com/test%20space", "href roundtrip matched");
    };

    t.run("curl test 40: query string separation with multiple question marks") { sub =>
        let u_query = core::new_url("http://example.com/path?a=1?b=2");
        sub.assert_true(u_query.valid, "URL with multiple question marks is valid");
        sub.assert_bytes_eq(core::pathname(u_query), "/path", "pathname terminated at first question mark");
        sub.assert_bytes_eq(core::search(u_query), "?a=1?b=2", "second ? preserved in search query");
    };

    t.run("curl test 1138: userinfo authority credentials accessible") { sub =>
        let u_auth = core::new_url("http://user:pass@example.com/");
        sub.assert_true(u_auth.valid, "URL with userinfo credentials is valid");
        sub.assert_bytes_eq(core::username(u_auth), "user", "username parsed correctly");
        sub.assert_bytes_eq(core::password(u_auth), "pass", "password parsed correctly");
        sub.assert_true(core::has_credentials(u_auth), "has_credentials is true");
        sub.assert_bytes_eq(core::hostname(u_auth), "example.com", "hostname isolated from authority");
        sub.assert_bytes_eq(core::pathname(u_auth), "/", "pathname is root slash");
    };
}

// ----------------------------------------------------------------------------
// 15. Cookie Header 8KB Limits & Truncation (curl test 427, 442, 443)
// ----------------------------------------------------------------------------

fn fill_repeated_pattern<B>(out: B&, count: i32, token: const u8[:]) {
    for i in count {
        out.append(token);
    }
}

fn add_test_cookies<J>(jar: J&, count: i32, host: const u8[:], prefix: const u8[:], val: const u8[:]) {
    for idx in count {
        var nbuf: u8[..32] = [];
        format(nbuf, prefix, idx as i64);
        jar.add(nbuf[..], val)
            .with_host(host)
            .with_path("/");
    }
}

// curl test 427 & 443: Maximum Cookie header 8KB limit and boundary truncation.
fn test_curl_427_cookie_header_8kb_limit(t: lit::T&) {
    t.run("curl test 427: Maximum Cookie header 8KB limit and boundary truncation") { sub =>
        var jar = wing::CanonicalCookieJar { .. };

        // Value of 3200 bytes (repeat 400 x 'abcdefgh' per curl test 427)
        var val_3200: u8[..3210] = [];
        fill_repeated_pattern(val_3200, 400, "abcdefgh");

        jar.add("long1", val_3200[..])
            .with_host("example.com")
            .with_path("/");

        jar.add("long2", val_3200[..])
            .with_host("example.com")
            .with_path("/");

        jar.add("long3", val_3200[..])
            .with_host("example.com")
            .with_path("/");

        // Header buffer bounded to 8192 bytes (Invariant 17)
        var out_hdr: u8[..8192] = [];
        wing::build_cookie_header(jar, "https://example.com/", out_hdr, 1000000);

        // long1 (~3206B) + long2 (~3208B) fits; long3 would exceed 8192, so formatting stops cleanly
        sub.assert_true(out_hdr.len <= 8192, "Cookie header bounded within 8192 bytes");
        sub.assert_contains(out_hdr[..], "long1=", "First matching cookie included");
        sub.assert_contains(out_hdr[..], "long2=", "Second matching cookie included");
        sub.assert_not_contains(out_hdr[..], "long3=", "Third cookie omitted due to 8KB buffer limit");
        sub.assert_false(core::ends_with(out_hdr[..], "; "), "No dangling delimiter on truncation");
    };
}

// curl test 443: 20 large cookies (500B each) capped cleanly within 8KB.
// ----------------------------------------------------------------------------
// 16. 20 Large Cookies Truncation (curl 443)
// ----------------------------------------------------------------------------
fn test_curl_443_many_large_cookies_truncation(t: lit::T&) {
    t.run("curl test 443: 20 large cookies (500B each) capped cleanly within 8KB") { sub =>
        var jar = wing::CanonicalCookieJar { .. };

        var val_500: u8[..512] = [];
        fill_repeated_pattern(val_500, 500, "a");

        // Add 20 cookies of ~500 bytes each
        add_test_cookies(jar, 20, "attack.invalid", "huge-", val_500[..]);

        var out_hdr: u8[..8192] = [];
        wing::build_cookie_header(jar, "https://attack.invalid/", out_hdr, 1000000);

        sub.assert_true(out_hdr.len <= 8192, "Cookie header bounded within 8192 bytes");
        sub.assert_contains(out_hdr[..], "huge-0=", "Initial cookies included");
        sub.assert_not_contains(out_hdr[..], "huge-19=", "Overflow cookies omitted without panics");
        sub.assert_false(core::ends_with(out_hdr[..], "; "), "No dangling delimiter on truncation");
    };
}

// curl test 442: high cookie count stops cleanly at buffer boundary.
// ----------------------------------------------------------------------------
// 17. High Cookie Count Buffer Boundary (curl 442)
// ----------------------------------------------------------------------------
fn test_curl_442_cookie_count_buffer_boundary(t: lit::T&) {
    t.run("curl test 442: high cookie count stops cleanly at buffer boundary") { sub =>
        var jar = wing::CanonicalCookieJar { .. };

        add_test_cookies(jar, 150, "example.org", "c", "v");

        // Enterprise-scale 8KB buffer per Invariant 17
        var enterprise_buf: u8[..8192] = [];
        wing::build_cookie_header(jar, "https://example.org/", enterprise_buf, 1000000);
        sub.assert_true(enterprise_buf.len <= 8192, "Bounded within 8192 bytes");
        sub.assert_contains(enterprise_buf[..], "c0=v", "Initial cookie present");
        sub.assert_contains(enterprise_buf[..], "c149=v", "High cookie count present");
        sub.assert_false(core::ends_with(enterprise_buf[..], "; "), "No dangling delimiter");
    };
}

// ----------------------------------------------------------------------------
// 18. Domain Tailmatching & Prefix Collision Defense (curl test 1216, 1218, 171)
// ----------------------------------------------------------------------------

// curl test 1216 & 1218: RFC 6265 Section 5.1.3 domain tailmatching and prefix defense.
fn test_curl_domain_tailmatching_prefix_defense(t: lit::T&) {
    t.run("curl test 1216 & 1218: Subdomain match and prefix collision defense") { sub =>
        var jar = wing::CanonicalCookieJar { .. };
        let ok = wing::set_cookie_header(jar, "http://example.com/c/1216", "session=1; Domain=.example.com; Path=/", 1000000);
        sub.assert_true(ok, "Domain cookie accepted");

        // Subdomain matches .example.com
        var h_sub: u8[..256] = [];
        wing::build_cookie_header(jar, "http://sub.example.com/c/1216", h_sub, 1000000);
        sub.assert_contains(h_sub[..], "session=1", "Matches subdomain");

        // Deep subdomain matches .example.com
        var h_deep: u8[..256] = [];
        wing::build_cookie_header(jar, "http://deep.sub.example.com/c/1216", h_deep, 1000000);
        sub.assert_contains(h_deep[..], "session=1", "Matches deep subdomain");

        // Exact domain matches
        var h_exact: u8[..256] = [];
        wing::build_cookie_header(jar, "http://example.com/c/1216", h_exact, 1000000);
        sub.assert_contains(h_exact[..], "session=1", "Matches exact domain");

        // Prefix collisions MUST NOT match (curl test 1216/1218: bexample.fake does not match example.fake)
        var h_bad: u8[..256] = [];
        wing::build_cookie_header(jar, "http://badexample.com/c/1216", h_bad, 1000000);
        sub.assert_eq(h_bad.len, 0, "Prefix collision badexample.com must NOT match");

        var h_not: u8[..256] = [];
        wing::build_cookie_header(jar, "http://not-example.com/c/1216", h_not, 1000000);
        sub.assert_eq(h_not.len, 0, "Prefix collision not-example.com must NOT match");
    };

    t.run("Direct predicate verification: wing::cookie_domain_match") { sub =>
        sub.assert_true(wing::cookie_domain_match("sub.example.com", "example.com"), "Subdomain match");
        sub.assert_true(wing::cookie_domain_match("deep.sub.example.com", "example.com"), "Deep subdomain match");
        sub.assert_true(wing::cookie_domain_match("example.com", "example.com"), "Exact domain match");
        sub.assert_false(wing::cookie_domain_match("badexample.com", "example.com"), "Prefix collision rejected");
        sub.assert_false(wing::cookie_domain_match("not-example.com", "example.com"), "Hyphenated prefix rejected");
    };

    t.run("curl test 171: Dot prefixed domain normalized and matched") { sub =>
        var jar171 = wing::CanonicalCookieJar { .. };
        let ok171 = wing::set_cookie_header(jar171, "http://z.x.com/171", "XToken=xt; Domain=.z.x.com; Path=/", 1000000);
        sub.assert_true(ok171, "Leading dot normalized");

        var h171: u8[..256] = [];
        wing::build_cookie_header(jar171, "http://z.x.com/171", h171, 1000000);
        sub.assert_contains(h171[..], "XToken=xt", "z.x.com matches .z.x.com cookie");

        var h171_sub: u8[..256] = [];
        wing::build_cookie_header(jar171, "http://sub.z.x.com/171", h171_sub, 1000000);
        sub.assert_contains(h171_sub[..], "XToken=xt", "sub.z.x.com matches .z.x.com cookie");
    };
}

// ----------------------------------------------------------------------------
// 19. Single-Label Host & IP Address Semantics (curl test 331)
// ----------------------------------------------------------------------------

// curl test 331 & RFC 6265 Section 5.1.3: Unqualified hostnames and IP literal exact equality.
fn test_curl_single_label_and_ip_matching(t: lit::T&) {
    t.run("curl test 331: Single-label unqualified host 'moo'") { sub =>
        var jar_moo = wing::CanonicalCookieJar { .. };
        let ok_moo = wing::set_cookie_header(jar_moo, "http://moo/we/want/331", "moo=yes; Path=/", 1000000);
        sub.assert_true(ok_moo, "Single-label host-only cookie accepted");

        var h_moo: u8[..256] = [];
        wing::build_cookie_header(jar_moo, "http://moo/we/want/3310002", h_moo, 1000000);
        sub.assert_contains(h_moo[..], "moo=yes", "Matches exact unqualified host moo");

        var h_badmoo: u8[..256] = [];
        wing::build_cookie_header(jar_moo, "http://othermoo/we/want/3310002", h_badmoo, 1000000);
        sub.assert_eq(h_badmoo.len, 0, "Does not match othermoo");

        var h_moocom: u8[..256] = [];
        wing::build_cookie_header(jar_moo, "http://moo.com/we/want/3310002", h_moocom, 1000000);
        sub.assert_eq(h_moocom.len, 0, "Does not match moo.com");
    };

    t.run("RFC 6265 Section 5.1.3: IP Address literal requires exact equality") { sub =>
        var c_ip = wing::new_canonical_cookie("ip_cookie", "ip_val");
        c_ip.with_domain("192.168.1.1", false);

        sub.assert_true(c_ip.matches_domain("192.168.1.1"), "Exact IP match succeeds");
        sub.assert_false(c_ip.matches_domain("192.168.1.100"), "192.168.1.100 must NOT match 192.168.1.1");
        sub.assert_false(c_ip.matches_domain("sub.192.168.1.1"), "Sub-domain of IP must NOT match");
        sub.assert_false(c_ip.matches_domain("192.168.1.1.com"), "FQDN suffix of IP must NOT match");
        sub.assert_false(wing::cookie_domain_match("192.168.1.100", "192.168.1.1"), "Domain match rejects IP mismatch");

        // IPv6 literal matching
        var c_ipv6 = wing::new_canonical_cookie("ipv6_cookie", "v6");
        c_ipv6.with_domain("2001:db8::1", true);
        sub.assert_true(c_ipv6.matches_domain("[2001:db8::1]"), "IPv6 with brackets matches");
        sub.assert_false(c_ipv6.matches_domain("[2001:db8::2]"), "Different IPv6 rejected");
    };
}

// ----------------------------------------------------------------------------
// 20. Public Suffix List (PSL) Rejection & Acceptance (curl test 1136, 1476)
// ----------------------------------------------------------------------------

// curl test 1136 & 1476: Supercookie prevention across ICANN and Private PSL boundaries.
fn test_curl_psl_supercookie_rejection(t: lit::T&) {
    t.run("curl test 1476: TLD and ccTLD supercookies rejected (com, co.uk)") { sub =>
        var jar = wing::CanonicalCookieJar { .. };

        // ICANN generic TLD: Domain=com rejected
        let ok_com = wing::set_cookie_header(jar, "https://app.example.com/", "sid=1; Domain=com; Path=/", 1000000);
        sub.assert_false(ok_com, "Domain=com must be rejected as ICANN public suffix");

        // ICANN multi-level ccTLD: Domain=co.uk rejected
        let ok_couk = wing::set_cookie_header(jar, "https://curl.co.uk/", "super=oops; Domain=co.uk; Path=/", 1000000);
        sub.assert_false(ok_couk, "Domain=co.uk must be rejected as ICANN ccTLD public suffix");

        // Case-insensitivity: Domain=co.UK rejected (curl test 1476)
        let ok_couk_case = wing::set_cookie_header(jar, "https://curl.co.uk/", "super=oops; Domain=co.UK; Path=/", 1000000);
        sub.assert_false(ok_couk_case, "Mixed-case Domain=co.UK must be rejected as public suffix");

        sub.assert_eq(jar.cookies.len, 0, "No supercookies stored in jar");
    };

    t.run("Private PSL section: github.io multi-tenant boundary protection") { sub =>
        var jar = wing::CanonicalCookieJar { .. };

        // Setting Domain=github.io from tenant.github.io must be rejected
        let ok_gh = wing::set_cookie_header(jar, "https://alice.github.io/", "cross=bad; Domain=github.io; Path=/", 1000000);
        sub.assert_false(ok_gh, "Domain=github.io must be rejected to prevent cross-tenant supercookie");

        // Setting Domain=api.github.io on https://api.github.io/ is accepted as eTLD+1
        let ok_api = wing::set_cookie_header(jar, "https://api.github.io/", "auth=token123; Domain=api.github.io; Path=/", 1000000);
        sub.assert_true(ok_api, "Setting Domain=api.github.io on api.github.io is accepted");

        // Outgoing request to https://api.github.io/v1 sends the cookie
        var h_api: u8[..256] = [];
        wing::build_cookie_header(jar, "https://api.github.io/v1", h_api, 1000000);
        sub.assert_contains(h_api[..], "auth=token123", "api.github.io cookie sent on subpath");

        // Different tenant https://other.github.io does NOT receive api.github.io cookie
        var h_other: u8[..256] = [];
        wing::build_cookie_header(jar, "https://other.github.io/v1", h_other, 1000000);
        sub.assert_eq(h_other.len, 0, "other.github.io must NOT receive api.github.io cookie");
    };
}

// curl test 1136 & 1476: Wildcard and exception rules with mixed-case hostnames.
// ----------------------------------------------------------------------------
// 21. PSL Wildcards, Exceptions, and Mixed Case (curl 1136, 1476)
// ----------------------------------------------------------------------------
fn test_curl_psl_wildcard_exception_and_case(t: lit::T&) {
    t.run("curl test 1476: Valid eTLD+1 accepted with mixed-case domain property") { sub =>
        var jar = wing::CanonicalCookieJar { .. };

        // curl.co.UK with Domain=CURL.CO.UK accepted per curl test 1476
        let ok_curl = wing::set_cookie_header(jar, "http://curl.co.UK/", "fine=yesyes; Domain=CURL.CO.UK; Path=/", 1000000);
        sub.assert_true(ok_curl, "Valid eTLD+1 accepted with mixed-case domain property");

        var h_curl: u8[..256] = [];
        wing::build_cookie_header(jar, "http://curl.co.UK/", h_curl, 1000000);
        sub.assert_contains(h_curl[..], "fine=yesyes", "curl.co.UK cookie sent on matching request");
    };

    t.run("curl test 1136: Wildcard (*.ck) and exception (!www.ck) rules") { sub =>
        var jar = wing::CanonicalCookieJar { .. };

        // Wildcard rule *.ck: example.ck is a public suffix -> Domain=example.ck rejected
        let ok_ck1 = wing::set_cookie_header(jar, "http://www.example.ck/", "test1=forbidden1; Domain=example.ck; Path=/", 1000000);
        sub.assert_false(ok_ck1, "Domain=example.ck rejected under wildcard rule *.ck");

        // www.example.ck is valid eTLD+1 under *.ck -> accepted
        let ok_ck2 = wing::set_cookie_header(jar, "http://www.example.ck/", "test2=allowed2; Domain=www.example.ck; Path=/", 1000000);
        sub.assert_true(ok_ck2, "Domain=www.example.ck accepted as eTLD+1");

        // Base domain ck is TLD public suffix -> rejected
        let ok_ck3 = wing::set_cookie_header(jar, "http://www.ck/", "test3=forbidden3; Domain=ck; Path=/", 1000000);
        sub.assert_false(ok_ck3, "Domain=ck rejected as TLD");

        // Exception rule !www.ck: www.ck is NOT a public suffix, it is a valid eTLD+1
        let ok_ck4 = wing::set_cookie_header(jar, "http://www.ck/", "test4=allowed4; Domain=www.ck; Path=/", 1000000);
        sub.assert_true(ok_ck4, "Domain=www.ck accepted under exception rule !www.ck");
    };
}

fn main() {
    var runner = lit::new_runner("curl Behavioral Compatibility Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. Redirect Method Mutation & Payload Stripping (curl 1011, 1076, 1325, 1332)", test_curl_redirect_method_mutation);
    lit::run_case(runner, "2. Cross-Origin Sensitive Credential Stripping (curl 317, 318, 330, 1077)", test_curl_cross_origin_sanitization);
    lit::run_case(runner, "3. Location URL Resolution & Dot Segments (curl 49, 50, 52, 1031, 1314)", test_curl_location_url_resolution);
    lit::run_case(runner, "4. Redirect Loop & Missing Location Guards (curl 25, 54)", test_curl_redirect_guards_and_limits);
    lit::run_case(runner, "5. Cookie Path Matching & Security Prefixes (curl 61, 172, 329, 1228, 1561, 2311)", test_curl_cookie_path_matching_and_prefix_rules);
    lit::run_case(runner, "6. Netscape cookies.txt Ingestion (curl 46, 62, 3104)", test_curl_netscape_cookiejar_import);
    lit::run_case(runner, "7. HTTP CONNECT Proxy Tunneling & Response Parsing (curl 80, 1287)", test_curl_connect_tunneling_and_proxy_rules);
    lit::run_case(runner, "8. Expect 100-continue & Fast-Fail Server Evaluation (curl 357, 1129, 1130)", test_curl_expect_100_continue);
    lit::run_case(runner, "9. Malformed Chunked Hex Sizes (curl 1941, 1936)", test_curl_malformed_chunk_hex_sizes);
    lit::run_case(runner, "10. Premature Connection Close & Truncated Body (curl 150, 584)", test_curl_premature_close_truncated_body);
    lit::run_case(runner, "11. Chunked Trailing Headers (curl 188, 1090)", test_curl_chunked_trailing_headers);
    lit::run_case(runner, "12. URL Port Boundary Parsing (curl unit1653, unit1675)", test_curl_url_port_boundaries);
    lit::run_case(runner, "13. IPv6 Bracketed and Scoped Addresses (curl 241, 1056, 1230)", test_curl_ipv6_addresses);
    lit::run_case(runner, "14. Path and Search Normalization (curl 40, 42, 1138)", test_curl_path_and_search_normalization);
    lit::run_case(runner, "15. Cookie Header 8KB Limit (curl 427)", test_curl_427_cookie_header_8kb_limit);
    lit::run_case(runner, "16. 20 Large Cookies Truncation (curl 443)", test_curl_443_many_large_cookies_truncation);
    lit::run_case(runner, "17. High Cookie Count Buffer Boundary (curl 442)", test_curl_442_cookie_count_buffer_boundary);
    lit::run_case(runner, "18. Domain Tailmatching & Prefix Collision Defense (curl 171, 1216, 1218)", test_curl_domain_tailmatching_prefix_defense);
    lit::run_case(runner, "19. Single-Label Host & IP Address Semantics (curl 331)", test_curl_single_label_and_ip_matching);
    lit::run_case(runner, "20. Public Suffix List Supercookie Rejection (curl 1136, 1476)", test_curl_psl_supercookie_rejection);
    lit::run_case(runner, "21. PSL Wildcards, Exceptions, and Mixed Case (curl 1136, 1476)", test_curl_psl_wildcard_exception_and_case);

    let ok = lit::finish(runner);
    assert(ok);
}
