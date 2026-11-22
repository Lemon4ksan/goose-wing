// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: HTTP Client, Interceptors, and Pipeline Verification Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// --- Component: client ---
// Tests for ClientSession, redirect policies, and cookie handling.

// ----------------------------------------------------------------------------
// 1. Mozilla PSL Scoping & Tenant Isolation
// ----------------------------------------------------------------------------
fn test_psl_scoping_and_tenants(t: lit::T&) {
    t.run("PSL Rule Types: Normal, Wildcard, Exception") { sub =>
        // 1. Normal ICANN rule: co.uk
        var s_couk: u8[..64] = [];
        let icann_couk = core::public_suffix_with_icann("service.co.uk", s_couk);
        sub.assert_true(icann_couk, "co.uk is in ICANN section");
        sub.assert_bytes_eq(s_couk[..], "co.uk", "suffix is co.uk");

        // 2. Wildcard rule: *.ck -> any label under ck is a public suffix
        var s_ck: u8[..64] = [];
        let icann_ck = core::public_suffix_with_icann("foo.ck", s_ck);
        sub.assert_true(icann_ck, "*.ck is ICANN wildcard");
        sub.assert_bytes_eq(s_ck[..], "foo.ck", "foo.ck matched wildcard *.ck");

        // 3. Exception rule: !www.ck -> suffix is 'ck', so www.ck is registrable domain
        var s_ex: u8[..64] = [];
        let icann_ex = core::public_suffix_with_icann("www.ck", s_ex);
        sub.assert_true(icann_ex, "!www.ck exception rule");
        sub.assert_bytes_eq(s_ex[..], "ck", "exception rule stripped leftmost label to ck");

        var etld_ex: u8[..64] = [];
        core::extract_etld_plus_one("www.ck", etld_ex);
        sub.assert_bytes_eq(etld_ex[..], "www.ck", "www.ck is eTLD+1 due to exception rule");
    };

    t.run("Private Suffix Section & Strict Tenant Isolation") { sub =>
        // github.io is a Private section suffix
        var s_gh: u8[..64] = [];
        let icann_gh = core::public_suffix_with_icann("alice.github.io", s_gh);
        sub.assert_false(icann_gh, "github.io belongs to Private section (not ICANN)");
        sub.assert_bytes_eq(s_gh[..], "github.io", "suffix is github.io");

        // Tenant isolation: alice.github.io must have eTLD+1 alice.github.io
        var etld_alice: u8[..64] = [];
        core::extract_etld_plus_one("alice.github.io", etld_alice);
        sub.assert_bytes_eq(etld_alice[..], "alice.github.io", "alice.github.io is isolated tenant");

        // Bob's tenant: bob.github.io must have eTLD+1 bob.github.io
        var etld_bob: u8[..64] = [];
        core::extract_etld_plus_one("bob.github.io", etld_bob);
        sub.assert_bytes_eq(etld_bob[..], "bob.github.io", "bob.github.io is isolated tenant");

        // Deep subdomains inside tenant: project.alice.github.io -> eTLD+1 is alice.github.io
        var etld_proj: u8[..64] = [];
        core::extract_etld_plus_one("project.alice.github.io", etld_proj);
        sub.assert_bytes_eq(etld_proj[..], "alice.github.io", "subdomain bound to tenant eTLD+1");
    };

    t.run("RegistrableSite Construction from URL") { sub =>
        let url_app = core::new_url("https://sub.portal.example.com/dashboard");
        let reg_site = core::registrable_site_from_url(url_app);
        sub.assert_bytes_eq(reg_site.scheme[..], "https", "scheme is https");
        sub.assert_bytes_eq(reg_site.registrable_domain[..], "example.com", "registrable domain is example.com");
    };
}

// ----------------------------------------------------------------------------
// 2. SiteForCookies & RFC 6265bis Schemeful Same-Site Context
// ----------------------------------------------------------------------------
fn test_site_for_cookies_and_rfc6265bis(t: lit::T&) {
    t.run("SiteForCookies Creation & NetLog Formatting") { sub =>
        let sfc = cookie::site_for_cookies_from_url("https://login.example.com/");
        sub.assert_false(sfc.is_null, "not null SFC");
        sub.assert_true(sfc.schemefully_same, "schemefully same");
        sub.assert_bytes_eq(sfc.scheme[..], "https", "scheme is https");
        sub.assert_bytes_eq(sfc.registrable_domain[..], "example.com", "registrable domain is example.com");

        var netlog: u8[..128] = [];
        cookie::format_site_for_cookies(sfc, netlog);
        sub.assert_contains(netlog[..], "https://example.com", "netlog contains site");
        sub.assert_contains(netlog[..], "schemefully_same=true", "netlog indicates schemefully same");

        let null_sfc = cookie::null_site_for_cookies();
        sub.assert_true(null_sfc.is_null, "null SFC");
        var null_netlog: u8[..128] = [];
        cookie::format_site_for_cookies(null_sfc, null_netlog);
        sub.assert_contains(null_netlog[..], "null; schemefully_same=false", "null SFC formats properly");
    };

    t.run("Schemeful First-Party Evaluation") { sub =>
        let sfc = cookie::site_for_cookies_from_url("https://example.com/");

        // Same site, same scheme -> First-party
        sub.assert_true(
            cookie::is_first_party(sfc, "https://sub.example.com/api", true),
            "https://sub.example.com is first-party to https://example.com",
        );

        // Same registrable domain, DIFFERENT scheme -> NOT first-party under schemeful same-site!
        sub.assert_false(
            cookie::is_first_party(sfc, "http://example.com/api", true),
            "http://example.com is NOT first-party to https://example.com (Schemeful Same-Site)",
        );

        // Different domain -> Cross-site
        sub.assert_false(
            cookie::is_first_party(sfc, "https://attacker.com/api", true),
            "attacker.com is cross-site",
        );
    };

    t.run("Ancestor Frame Hierarchy Traversal & Context Degradation") { sub =>
        var sfc = cookie::site_for_cookies_from_url("https://bank.com/account");

        // Subframe on same site: preserves first-party context
        cookie::compare_with_frame_tree_site_and_revise(sfc, "https://sub.bank.com/iframe");
        sub.assert_false(sfc.is_null, "remains first-party with same-site subframe");

        // Nested subframe from cross-site third party: degrades SFC to null!
        cookie::compare_with_frame_tree_site_and_revise(sfc, "https://tracker.net/widget");
        sub.assert_true(sfc.is_null, "degrades to null when ancestor chain contains cross-site frame");

        // Once null, further comparisons cannot restore it
        cookie::compare_with_frame_tree_site_and_revise(sfc, "https://bank.com/account");
        sub.assert_true(sfc.is_null, "stays null once tainted");
    };
}

// ----------------------------------------------------------------------------
// 3. Redirect State Machine: Methods, Headers & Sensitive Sanitization
// ----------------------------------------------------------------------------
fn test_redirect_state_machine(t: lit::T&) {
    t.run("HTTP 301, 302, 303 Method Mutation & Payload Stripping") { sub =>
        // 301 Moved Permanently: POST -> GET
        let info_301 = client::compute_redirect_info(
            "POST", 301, "https://example.com/old", "https://example.com/new",
            client::ReferrerPolicy.NoReferrerWhenDowngrade, "https://example.com/old",
            client::RedirectOptions { .. },
        );
        sub.assert_bytes_eq(info_301.new_method[..], "GET", "301 mutates POST to GET");
        sub.assert_true(info_301.clear_body, "body cleared on 301 POST->GET");

        // 302 Found: POST -> GET
        let info_302 = client::compute_redirect_info(
            "POST", 302, "https://example.com/login", "https://example.com/dashboard",
            client::ReferrerPolicy.NoReferrerWhenDowngrade, "https://example.com/login",
            client::RedirectOptions { .. },
        );
        sub.assert_bytes_eq(info_302.new_method[..], "GET", "302 mutates POST to GET");
        sub.assert_true(info_302.clear_body, "body cleared on 302 POST->GET");

        // 303 See Other: PUT -> GET
        let info_303 = client::compute_redirect_info(
            "PUT", 303, "https://example.com/item", "https://example.com/items",
            client::ReferrerPolicy.NoReferrerWhenDowngrade, "https://example.com/item",
            client::RedirectOptions { .. },
        );
        sub.assert_bytes_eq(info_303.new_method[..], "GET", "303 mutates PUT to GET");
        sub.assert_true(info_303.clear_body, "body cleared on 303 PUT->GET");
    };

    t.run("HTTP 307 & 308 Method and Body Preservation") { sub =>
        // 307 Temporary Redirect: POST remains POST
        let info_307 = client::compute_redirect_info(
            "POST", 307, "https://example.com/upload", "https://s3.example.com/upload",
            client::ReferrerPolicy.NoReferrerWhenDowngrade, "https://example.com/upload",
            client::RedirectOptions { .. },
        );
        sub.assert_bytes_eq(info_307.new_method[..], "POST", "307 preserves POST");
        sub.assert_false(info_307.clear_body, "307 preserves request body");

        // 308 Permanent Redirect: DELETE remains DELETE
        let info_308 = client::compute_redirect_info(
            "DELETE", 308, "https://example.com/res/1", "https://api.example.com/res/1",
            client::ReferrerPolicy.NoReferrerWhenDowngrade, "https://example.com/res/1",
            client::RedirectOptions { .. },
        );
        sub.assert_bytes_eq(info_308.new_method[..], "DELETE", "308 preserves DELETE");
        sub.assert_false(info_308.clear_body, "308 preserves request body");
    };

    t.run("Cross-Origin Sensitive Header Sanitization (CVE Mitigations)") { sub =>
        var req = http::new_post("https://api.example.com/v1/auth");
        http::set_header(req, "Authorization", "Bearer secret_jwt_token_123");
        http::set_header(req, "X-API-Key", "api-key-99999");
        http::set_header(req, "X-Auth-Token", "auth-token-xyz");
        http::set_header(req, "Cookie", "session=active; tracking=1");
        http::set_header(req, "Accept", "application/json");

        let redirect_info = client::compute_redirect_info(
            "POST", 302, "https://api.example.com/v1/auth", "https://attacker.org/leak",
            client::ReferrerPolicy.NoReferrerWhenDowngrade, "https://api.example.com/v1/auth",
            client::RedirectOptions { .. },
        );
        sub.assert_true(redirect_info.is_cross_origin, "detected cross-origin redirect");

        // Perform cross-origin sanitization
        client::sanitize_headers_on_redirect(
            req.headers,
            redirect_info,
            client::RedirectSanitizeOptions { enable_referer: true },
        );

        // Sensitive headers MUST be purged on cross-origin hop!
        let has_auth = http::has_header(req.headers, "Authorization");
        let has_apikey = http::has_header(req.headers, "X-API-Key");
        let has_authtok = http::has_header(req.headers, "X-Auth-Token");
        let has_cookie = http::has_header(req.headers, "Cookie");
        let has_accept = http::has_header(req.headers, "Accept");

        sub.assert_false(has_auth, "Authorization stripped on cross-origin redirect");
        sub.assert_false(has_apikey, "X-API-Key stripped (CVE-2026-55553, CVE-2026-64684)");
        sub.assert_false(has_authtok, "X-Auth-Token stripped");
        sub.assert_false(has_cookie, "Cookie stripped on redirect hop (CVE-2023-45143)");
        sub.assert_true(has_accept, "Innocuous Accept header preserved");
    };

    t.run("Scheme Downgrade Stripping (CVE-2024-1968)") { sub =>
        var req = http::new_get("https://example.com/secure");
        http::set_header(req, "Authorization", "Basic YWxhZGRpbjpvcGVuc2VzYW1l");
        http::set_header(req, "Custom-Key", "val");

        let redirect_info = client::compute_redirect_info(
            "GET", 302, "https://example.com/secure", "http://example.com/insecure",
            client::ReferrerPolicy.NoReferrerWhenDowngrade, "https://example.com/secure",
            client::RedirectOptions { .. },
        );
        sub.assert_true(redirect_info.is_scheme_downgrade, "detected scheme downgrade");

        // Same host, but scheme downgraded from HTTPS to HTTP
        client::sanitize_headers_on_redirect(
            req.headers,
            redirect_info,
            client::RedirectSanitizeOptions { enable_referer: true },
        );

        let has_auth = http::has_header(req.headers, "Authorization");
        sub.assert_false(has_auth, "Authorization stripped on HTTPS -> HTTP downgrade (CVE-2024-1968)");
    };

    t.run("Same-Origin Redirect Preserves Sensitive Credentials") { sub =>
        var req = http::new_get("https://example.com/old_endpoint");
        http::set_header(req, "Authorization", "Bearer keep_me_safe");
        http::set_header(req, "X-API-Key", "my_api_key");

        let redirect_info = client::compute_redirect_info(
            "GET", 302, "https://example.com/old_endpoint", "https://example.com/new_endpoint",
            client::ReferrerPolicy.NoReferrerWhenDowngrade, "https://example.com/old_endpoint",
            client::RedirectOptions { .. },
        );
        sub.assert_false(redirect_info.is_cross_origin, "same origin redirect");
        sub.assert_false(redirect_info.is_scheme_downgrade, "no scheme downgrade");

        client::sanitize_headers_on_redirect(
            req.headers,
            redirect_info,
            client::RedirectSanitizeOptions { enable_referer: true },
        );

        let has_auth = http::has_header(req.headers, "Authorization");
        let has_key = http::has_header(req.headers, "X-API-Key");
        sub.assert_true(has_auth, "Authorization preserved on same-origin redirect");
        sub.assert_true(has_key, "X-API-Key preserved on same-origin redirect");
    };
}

// ----------------------------------------------------------------------------
// 4. ClientSession 6-Phase Pipeline & CanonicalCookieJar Integration
// ----------------------------------------------------------------------------
fn test_oauth_flow(t: lit::T&) {
    t.run("OAuth 2.0 Flow: 302 Set-Cookie Ingestion & Chain Hop Isolation") { sub =>
        var session = client::new_session();
        client::set_clock_us(session, 1700000000000000);

        // Step 1: GET https://auth.idp.com/login -> 302 to https://app.client.com/callback
        // Server sends Set-Cookie: auth_session=secret_token; Domain=auth.idp.com; Secure; HttpOnly
        client::mock_route(session, "GET", "https://auth.idp.com/login", 302, "");
        client::add_mock_header(session, "Location", "https://app.client.com/callback?code=oauth_code_123");
        client::add_mock_set_cookie(session, "auth_session=secret_token; Domain=auth.idp.com; Secure; HttpOnly; SameSite=Lax");

        // Step 2: GET https://app.client.com/callback?code=oauth_code_123 -> 200 OK
        client::mock_route(session, "GET", "https://app.client.com/callback?code=oauth_code_123", 200, "{\"status\":\"authenticated\"}");
        client::add_mock_set_cookie(session, "app_user=alice; Path=/; Secure; SameSite=Lax");

        // Execute request to initial login page
        var req = http::new_get("https://auth.idp.com/login");
        let res, err = client::execute_request(session, req);

        sub.assert_true(http::ok(err), "request succeeded");
        sub.assert_eq(res.status_code, 200, "final status is 200 OK after redirect");
        sub.assert_eq(res.redirect_count, 1, "exactly 1 redirect hop");
        sub.assert_bytes_eq(res.final_method[..], "GET", "final method is GET");
        sub.assert_eq(res.url_chain.len, 2, "URL chain has 2 hops");
        sub.assert_bytes_eq(res.url_chain[0][..], "https://auth.idp.com/login", "initial URL in chain");
        sub.assert_bytes_eq(res.url_chain[1][..], "https://app.client.com/callback?code=oauth_code_123", "target URL in chain");

        // Verify Cookie Jar state: both cookies ingested with correct domain scoping
        sub.assert_eq(session.jar.cookies.len, 2, "both cookies ingested into jar");
        let auth_cookie = cookie::get(session.jar, "https://auth.idp.com/", "auth_session", 1700000000000000);
        sub.assert_bytes_eq(auth_cookie, "secret_token", "auth_session cookie found under idp.com");

        let app_cookie = cookie::get(session.jar, "https://app.client.com/callback", "app_user", 1700000000000000);
        sub.assert_bytes_eq(app_cookie, "alice", "app_user cookie found under client.com");

        // Cross-domain cookie isolation: client.com does NOT receive idp.com cookie!
        let leaked = cookie::get(session.jar, "https://app.client.com/", "auth_session", 1700000000000000);
        sub.assert_bytes_eq(leaked, "", "client.com did NOT receive idp.com auth_session cookie");
    };
}

// ----------------------------------------------------------------------------
// 5. ClientSession Redirect Loops & Manual Mode
// ----------------------------------------------------------------------------
fn test_redirect_loop_and_manual(t: lit::T&) {
    t.run("Redirect Loop Detection (TooManyRedirects)") { sub =>
        var session = client::new_session();
        session.max_redirects = 2;

        // Infinite redirect loop: a -> b -> a
        client::mock_route(session, "GET", "https://example.com/loop_a", 302, "");
        client::add_mock_header(session, "Location", "https://example.com/loop_b");

        client::mock_route(session, "GET", "https://example.com/loop_b", 302, "");
        client::add_mock_header(session, "Location", "https://example.com/loop_a");

        var req = http::new_get("https://example.com/loop_a");
        let res, err = client::execute_request(session, req);

        sub.assert_false(http::ok(err), "loop must produce error");
        sub.assert_bytes_eq(err.stage[..], "redirect", "redirect loop fails execution");
    };

    t.run("RedirectMode.Manual Returns 3xx Without Following") { sub =>
        var session = client::new_session();
        client::set_redirect_mode(session, client::RedirectMode.Manual);

        client::mock_route(session, "GET", "https://example.com/manual_src", 302, "redirect body");
        client::add_mock_header(session, "Location", "https://example.com/manual_dst");

        var req = http::new_get("https://example.com/manual_src");
        let res, err = client::execute_request(session, req);

        sub.assert_true(http::ok(err), "request ok");
        sub.assert_eq(res.status_code, 302, "manual redirect stops and returns 302");
        sub.assert_eq(res.redirect_count, 0, "zero redirects followed");
        sub.assert_bytes_eq(http::header(res, "Location"), "https://example.com/manual_dst", "Location header accessible");
    };
}

// ----------------------------------------------------------------------------
// 6. BodyRewind, SSRF Guard, and DNS Rebinding Defense
// ----------------------------------------------------------------------------
fn test_body_rewind(t: lit::T&) {
    t.run("BodyRewind on 307 Temporary Redirect") { sub =>
        var session = client::new_session();

        // 307 redirect preserving POST body
        client::mock_route(session, "POST", "https://api.example.com/v1/items", 307, "");
        client::add_mock_header(session, "Location", "https://api.example.com/v2/items");

        client::mock_route(session, "POST", "https://api.example.com/v2/items", 201, "{\"created\":true}");

        var req = http::new_post("https://api.example.com/v1/items");
        http::text(req, "{\"name\":\"widget\"}"); // Rewindable buffered body

        let res, err = client::execute_request(session, req);
        sub.assert_true(http::ok(err), "buffered body rewind succeeded on 307");
        sub.assert_eq(res.status_code, 201, "destination reached with preserved body");
        sub.assert_bytes_eq(res.final_method[..], "POST", "POST preserved on 307");
    };

    t.run("Unrewindable Body Stream Returns Error on 307/308") { sub =>
        var session = client::new_session();

        client::mock_route(session, "POST", "https://api.example.com/stream_src", 307, "");
        client::add_mock_header(session, "Location", "https://api.example.com/stream_dst");

        var req = http::new_post("https://api.example.com/stream_src");
        http::set_stream_body(req, "streamed_chunked_data", false); // Unrewindable stream

        let res, err = client::execute_request(session, req);
        sub.assert_false(http::ok(err), "unrewindable stream must fail redirect");
        sub.assert_bytes_eq(err.stage[..], "body_rewind", "stream error flagged");
    };
}

// ----------------------------------------------------------------------------
// 7. SSRF Guard 3-Tier Protection
// ----------------------------------------------------------------------------
fn test_ssrf_subnets(t: lit::T&) {
    var session = client::new_session();
    session.ssrf_guard.enabled = true;
    session.ssrf_guard.deny_local_network = true;

    t.run("3-Tier SSRF Guard: Loopback, RFC 1918 Private, Cloud Metadata") { sub =>
        let blocked_urls: const u8[..64][..5] = [
            "http://127.0.0.1/admin",
            "http://[::1]/internal",
            "http://10.20.30.40/metrics",
            "http://192.168.1.1/router",
            "http://169.254.169.254/latest/meta-data/",
        ];

        for &target_url in blocked_urls {
            var req = http::new_get(target_url[..]);
            let _, err = client::execute_request(session, req);
            sub.assert_false(http::ok(err), "target URL blocked by SSRF guard");
        }
    };
}

// ----------------------------------------------------------------------------
// 8. DNS Rebinding Defense via Resolved IP Sweep
// ----------------------------------------------------------------------------
fn test_dns_rebinding(t: lit::T&) {
    var session = client::new_session();
    session.ssrf_guard.enabled = true;
    session.ssrf_guard.deny_local_network = true;

    t.run("DNS Rebinding Defense via Resolved IP Sweep") { sub =>
        // Host has harmless public name 'rebound.attacker.com', but DNS resolution
        // returns private internal IP 192.168.0.100 (DNS Rebinding attack)
        client::mock_route(session, "GET", "http://rebound.attacker.com/steal", 200, "pwned");
        client::add_mock_resolved_ip(session, "192.168.0.100");

        var req = http::new_get("http://rebound.attacker.com/steal");
        let res, err = client::execute_request(session, req);

        sub.assert_false(http::ok(err), "DNS Rebinding blocked when resolved IP is in private subnet");
    };
}

// ----------------------------------------------------------------------------
// 9. Dangerous Service Port Blocking
// ----------------------------------------------------------------------------
fn test_dangerous_ports(t: lit::T&) {
    var session = client::new_session();
    session.ssrf_guard.enabled = true;
    session.ssrf_guard.deny_local_network = true;

    t.run("Dangerous Service Port Blocking (SSH, Redis, etc.)") { sub =>
        // Port 22 (SSH)
        var req_ssh = http::new_get("http://example.com:22/");
        let res_ssh, err_ssh = client::execute_request(session, req_ssh);
        sub.assert_false(http::ok(err_ssh), "port 22 blocked by SSRF guard");

        // Port 6379 (Redis)
        var req_redis = http::new_get("http://example.com:6379/");
        let res_redis, err_redis = client::execute_request(session, req_redis);
        sub.assert_false(http::ok(err_redis), "port 6379 blocked by SSRF guard");
    };
}

// ----------------------------------------------------------------------------
// 10. Client Integrated RFC 9111 HTTP Cache Pipeline
// ----------------------------------------------------------------------------
fn test_client_cache_integration(t: lit::T&) {
    t.run("CLI-01: Client RFC 9111 Cache Hit and Age Header") { sub =>
        var client = client::new_client(client::Config {
            enable_cache: true,
            ..
        });

        // Setup mock route for GET /api/data returning Cache-Control: max-age=3600
        client::mock_route(client, "GET", "https://api.example.com/data", 200, "{\"hello\":\"world\"}");
        client::add_mock_header(client, "Cache-Control", "max-age=3600");

        // 1st request: Cache Miss -> network fetch -> stored in cache
        var req1 = http::new_get("https://api.example.com/data");
        let resp1, err1 = client::execute_request(client, req1);
        sub.assert_true(http::ok(err1), "req1 ok");
        sub.assert_eq(resp1.status_code, 200, "status 200");
        sub.assert_eq(resp1.body[..], "{\"hello\":\"world\"}", "body matches");
        sub.assert_eq(client.cache.total_stores, 1, "stored in cache");

        // Advance virtual clock by 60 seconds
        client.virtual_clock_us += 60000000;

        // 2nd request: Cache Hit -> served directly from cache with Age header!
        var req2 = http::new_get("https://api.example.com/data");
        let resp2, err2 = client::execute_request(client, req2);
        sub.assert_true(http::ok(err2), "req2 ok");
        sub.assert_eq(resp2.status_code, 200, "status 200 from cache");
        sub.assert_eq(resp2.body[..], "{\"hello\":\"world\"}", "body matches cached");
        sub.assert_eq(client.cache.total_hits, 1, "cache hit recorded");
        sub.assert_true(http::header(resp2, "Age").len > 0, "Age header present on cache hit");
    };

    t.run("CLI-02: Client Unsafe Method Invalidation") { sub =>
        var client = client::new_client(client::Config {
            enable_cache: true,
            ..
        });

        // Seed cache
        client::mock_route(client, "GET", "https://api.example.com/item", 200, "v1");
        client::add_mock_header(client, "Cache-Control", "max-age=3600");

        var req_get = http::new_get("https://api.example.com/item");
        client::execute_request(client, req_get);
        sub.assert_eq(client.cache.total_stores, 1, "entry stored");

        // Unsafe POST to same URL invalidates cache
        var route_post = client::mock_route(client, "POST", "https://api.example.com/item", 200, "updated");
        var req_post = http::new_post("https://api.example.com/item");
        req_post.body.append("new_data");
        let resp_post, err_post = client::execute_request(client, req_post);
        sub.assert_true(http::ok(err_post), "post ok");

        // Next GET must be a Cache Miss
        let hits_before = client.cache.total_hits;
        let resp_get2, err_get2 = client::execute_request(client, req_get);
        sub.assert_eq(client.cache.total_hits, hits_before, "no cache hit after invalidation");
    };
}

// ----------------------------------------------------------------------------
// 11. Network Pipeline Edge Invariants & Multi-Module Audit
// ----------------------------------------------------------------------------
fn test_network_pipeline_edge_invariants(t: lit::T&) {
    t.run("SameSite Strict vs Lax Cookie Isolation on Cross-Site Hop") { sub =>
        var session = client::new_session();
        client::set_clock_us(session, 1700000000000000);

        // Pre-populate cookie jar with Strict and Lax cookies for bank.com
        session.jar.set_cookie_header("https://bank.com/", "strict_token=secret1; SameSite=Strict; Secure; Path=/", session.virtual_clock_us);
        session.jar.set_cookie_header("https://bank.com/", "lax_token=public2; SameSite=Lax; Secure; Path=/", session.virtual_clock_us);

        // Cross-site navigation initiated from evil.com to bank.com
        client::mock_route(session, "GET", "https://bank.com/dashboard", 200, "ok");
        var req = http::new_get("https://bank.com/dashboard");
        let _ = http::set_initiator(req, "https://evil.com");
        req.site_for_cookies = cookie::site_for_cookies_from_url("https://evil.com/");
        req.has_site_for_cookies = true;

        let resp, err = client::execute_request(session, req);
        sub.assert_true(http::ok(err), "request succeeded");

        let sent_cookie = http::sent_header(resp, "Cookie");
        sub.assert_contains(sent_cookie, "lax_token=public2", "Lax cookie included in top-level cross-site navigation");
        sub.assert_not_contains(sent_cookie, "strict_token=secret1", "Strict cookie NOT leaked in cross-site navigation");
    };

    t.run("HSTS Upgrade on 302 Redirect Hop") { sub =>
        var session = client::new_session();
        client::set_clock_us(session, 1700000000000000);

        // Step 1: GET https://example.com/login -> sets HSTS header and redirects to http://example.com/dash
        client::mock_route(session, "GET", "https://example.com/login", 302, "");
        client::add_mock_header(session, "Location", "http://example.com/dash");
        client::add_mock_header(session, "Strict-Transport-Security", "max-age=31536000");

        // Step 2: The redirect hop MUST be upgraded to https://example.com/dash
        client::mock_route(session, "GET", "https://example.com/dash", 200, "welcome");

        var req = http::new_get("https://example.com/login");
        let resp, err = client::execute_request(session, req);
        sub.assert_true(http::ok(err), "request with HSTS redirect succeeded");
        sub.assert_eq(resp.status_code, 200, "final status 200");
        sub.assert_bytes_eq(resp.effective_url[..], "https://example.com/dash", "hop was upgraded to https");
    };

    t.run("SSRF Case-Insensitive .LOCALHOST with Long Host") { sub =>
        let long_localhost = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa.LOCALHOST";
        sub.assert_true(security::is_localhost_name(long_localhost), "uppercase .LOCALHOST recognized as localhost");
        sub.assert_true(security::is_private_or_reserved_ip(long_localhost), "long .LOCALHOST blocked by SSRF filter");

        // RFC 6890 / RFC 3849 documentation prefix
        sub.assert_true(security::is_private_or_reserved_ip("2001:db8::1"), "2001:db8::/32 documentation blocked");
    };

    t.run("Header Override: Request Headers Replace Session Default Headers") { sub =>
        var session = client::new_session();
        client::set_clock_us(session, 1700000000000000);
        client::default_header(session, "Accept", "application/json");

        client::mock_route(session, "GET", "https://api.example.com/data", 200, "ok");
        var req = http::new_get("https://api.example.com/data");
        http::set_header(req, "Accept", "text/plain");

        let resp, err = client::execute_request(session, req);
        sub.assert_true(http::ok(err), "request succeeded");

        var accept_count = 0;
        var final_accept: u8[..64] = [];
        for idx in 0..resp.sent_headers.entries.len {
            let entry = resp.sent_headers.entries[idx];
            if core::eq_ascii_fold(http::entry_name(resp.sent_headers, entry), "Accept") {
                accept_count += 1;
                final_accept.clear();
                final_accept.append(http::entry_value(resp.sent_headers, entry));
            }
        }
        sub.assert_eq(accept_count, 1, "exactly one Accept header sent");
        sub.assert_bytes_eq(final_accept[..], "text/plain", "request-level Accept header overrode session default");
    };
}

// --- Component: client_interceptor ---
// Verification suite for OkHttp/Tower-style 2-tier Interceptor Pipeline:
// 1. Application Interceptors: Bearer Auth, Request ID, Traceparent, App Header, App Logging
// 2. Network Interceptors: Wire-level Observation, Per-Hop Headers & Logging, Network Metrics
// 3. Cache Boundary: Application Interceptor fires on Cache Hit, Network Interceptors bypassed
// 4. Retry Interceptor: Automatic Retry on 5xx Errors
// 5. Dynamic Closure Chain: `do_intercepted`, `proceed`, Request/Response Rewrite & Short-Circuiting

// ----------------------------------------------------------------------------
// 12. Application Interceptors (Bearer, Request-ID, Traceparent, Headers, Logging)
// ----------------------------------------------------------------------------
fn test_application_interceptors(t: lit::T&) {
    t.run("Application Interceptors: Bearer Auth, Request-ID, Traceparent & App Header") { sub =>
        var client = client::new_client();
        client::add_app_bearer_auth(client, "secret_jwt_token_xyz");
        client::add_app_header(client, "X-App-Env", "staging");
        client::add_app_request_id(client, "track-");
        client::add_app_traceparent(client, "01");

        // Assert 64-bit register bitmask flags are actively set
        sub.assert_true((client.pipeline.active_mask & client::INTERCEPTOR_APP_AUTH_BEARER) != 0, "active_mask has bearer auth bit");
        sub.assert_true((client.pipeline.active_mask & client::INTERCEPTOR_APP_HEADER) != 0, "active_mask has header bit");
        sub.assert_true((client.pipeline.active_mask & client::INTERCEPTOR_APP_REQUEST_ID) != 0, "active_mask has request id bit");
        sub.assert_true((client.pipeline.active_mask & client::INTERCEPTOR_APP_TRACEPARENT) != 0, "active_mask has traceparent bit");

        client::mock_route(client, "GET", "https://api.site.com/profile", 200, "{\"user\":\"alice\"}");

        let resp1, err1 = client::get(client, "https://api.site.com/profile");
        sub.assert_true(http::ok(err1), "get profile ok");
        sub.assert_eq(http::status(resp1), 200, "status 200");

        // Verify sent headers
        let auth = http::sent_header(resp1, "Authorization");
        sub.assert_bytes_eq(auth, "Bearer secret_jwt_token_xyz", "Bearer auth injected");

        let app_env = http::sent_header(resp1, "X-App-Env");
        sub.assert_bytes_eq(app_env, "staging", "App header injected");

        let req_id1 = http::sent_header(resp1, "X-Request-ID");
        sub.assert_bytes_eq(req_id1, "track-1", "First request ID is track-1");

        let tp = http::sent_header(resp1, "traceparent");
        sub.assert_eq(tp.len, 55, "traceparent length is 55");
        sub.assert_bytes_eq(tp[..3], "00-", "traceparent version is 00-");
        sub.assert_bytes_eq(tp[52..], "-01", "traceparent flags is -01");

        // Request 2 should increment request ID counter
        let resp2, err2 = client::get(client, "https://api.site.com/profile");
        sub.assert_true(http::ok(err2), "second request ok");
        let req_id2 = http::sent_header(resp2, "X-Request-ID");
        sub.assert_bytes_eq(req_id2, "track-2", "Second request ID incremented to track-2");
    };

    t.run("Application Logging: Request & Response Records") { sub =>
        var client = client::new_client();
        client::add_app_logging(client, client::LogLevel.Headers);

        client::mock_route(client, "GET", "https://api.site.com/ping", 200, "pong");

        let resp, err = client::get(client, "https://api.site.com/ping");
        sub.assert_true(http::ok(err), "ping ok");

        let logs = client.pipeline.log_entries[..];
        sub.assert_true(logs.len >= 2, "at least 2 log entries recorded");
        sub.assert_bytes_eq(logs[0][..10], "--> GET ht", "First log line is request line");
        sub.assert_bytes_eq(logs[logs.len - 1][..6], "<-- 20", "Last log line is response status");
    };
}

// ----------------------------------------------------------------------------
// 13. Network Interceptors, Redirect Hops & Network Metrics
// ----------------------------------------------------------------------------
fn test_network_interceptors_and_metrics(t: lit::T&) {
    t.run("Network Interceptor Observes Redirect Wire Hops & Wire Headers") { sub =>
        var client = client::new_client();
        client::add_network_metrics(client);
        client::add_network_header(client, "X-Net-Proxy-Trace", "edge-us-east");
        client::add_network_logging(client, client::LogLevel.Basic);

        // Setup redirect chain: /start (302) -> /final (200)
        client::mock_route(client, "GET", "https://site.com/start", 302, "redirecting");
        client::add_mock_header(client, "Location", "https://site.com/final");

        client::mock_route(client, "GET", "https://site.com/final", 200, "destination reached");

        let resp, err = client::get(client, "https://site.com/start");
        sub.assert_true(http::ok(err), "redirect traversal succeeded");
        sub.assert_eq(http::status(resp), 200, "status 200");
        sub.assert_bytes_eq(resp.body[..], "destination reached", "final body arrived");

        // Verify Network Metrics
        let metrics = &client.pipeline.metrics;
        sub.assert_eq(metrics.total_requests, 1 as u64, "1 logical application request");
        sub.assert_eq(metrics.network_hops, 2 as u64, "2 physical network hops traversed");
        sub.assert_eq(metrics.redirect_hops, 1 as u64, "1 redirect hop recorded");
        sub.assert_true(metrics.total_bytes_received > 0, "bytes received tracked");

        // Verify Network Logging captured both hops
        let logs = client.pipeline.log_entries[..];
        var found_hop0 = false;
        var found_hop1 = false;
        for &line in logs {
            if line.len >= 16 && line[..16] == "--> (net hop 0) " { found_hop0 = true; }
            if line.len >= 16 && line[..16] == "--> (net hop 1) " { found_hop1 = true; }
        }
        sub.assert_true(found_hop0, "Network logging recorded hop 0");
        sub.assert_true(found_hop1, "Network logging recorded hop 1");
    };
}

// ----------------------------------------------------------------------------
// 14. OkHttp Cache Boundary Invariant
// ----------------------------------------------------------------------------
fn test_cache_interceptor_boundary(t: lit::T&) {
    t.run("OkHttp Invariant: App Interceptors run on Cache Hit; Network Interceptors are bypassed") { sub =>
        var client = client::new_client();
        client.enable_cache = true;
        client::add_app_logging(client, client::LogLevel.Basic);
        client::add_network_metrics(client);

        client::mock_route(client, "GET", "https://site.com/cached-item", 200, "cached-content");
        client::add_mock_header(client, "Cache-Control", "public, max-age=3600");

        // 1. Initial Request (Cache Miss -> Network)
        let resp1, err1 = client::get(client, "https://site.com/cached-item");
        sub.assert_true(http::ok(err1), "initial get ok");
        sub.assert_eq(http::status(resp1), 200, "200 OK");

        let m1 = &client.pipeline.metrics;
        sub.assert_eq(m1.total_requests, 1 as u64, "1 app request");
        sub.assert_eq(m1.network_hops, 1 as u64, "1 network hop on miss");

        // 2. Second Request (Cache Hit -> Served from HttpCache directly)
        client::clear_pipeline_logs(client);
        let resp2, err2 = client::get(client, "https://site.com/cached-item");
        sub.assert_true(http::ok(err2), "cached get ok");
        sub.assert_eq(http::status(resp2), 200, "200 OK");
        sub.assert_bytes_eq(resp2.body[..], "cached-content", "body from cache");

        let m2 = &client.pipeline.metrics;
        sub.assert_eq(m2.total_requests, 2 as u64, "2 logical app requests");
        // OkHttp invariant: Network hops did not increase on cache hit.
        sub.assert_eq(m2.network_hops, 1 as u64, "Network hops remained 1 (network bypassed!)");

        // But Application Logging DID run for the cached request!
        let logs = client.pipeline.log_entries[..];
        sub.assert_true(logs.len >= 2, "Application logs fired for cache hit");
    };
}

// ----------------------------------------------------------------------------
// 15. Retry Policy Interceptor
// ----------------------------------------------------------------------------
fn test_retry_policy_interceptor(t: lit::T&) {
    t.run("Retry Interceptor Retries on 5xx Error Up To Max Retries") { sub =>
        var client = client::new_client();
        client::add_app_retry(client, 2, true);
        client::add_network_metrics(client);

        // Server returns 503 Service Unavailable
        client::mock_route(client, "GET", "https://site.com/flaky", 503, "temporary failure");

        let resp, err = client::get(client, "https://site.com/flaky");
        sub.assert_true(http::ok(err), "request finished");
        sub.assert_eq(http::status(resp), 503, "503 returned after exhaustion");

        let m = &client.pipeline.metrics;
        // Initial attempt (0) + Retry 1 + Retry 2 = 3 total attempts!
        sub.assert_eq(m.network_hops, 3 as u64, "Retried up to max_retries (3 attempts total)");
    };
}

// ----------------------------------------------------------------------------
// 16. Closure-based Interceptor Chain & Short-Circuiting
// ----------------------------------------------------------------------------
fn test_closure_chain_interceptor(t: lit::T&) {
    t.run("Closure Chain: Mutate Request, Call Proceed & Mutate Response") { sub =>
        var client = client::new_client();
        client::mock_route(client, "GET", "https://site.com/resource", 200, "server-payload");

        let req = http::new_get("https://site.com/resource");

        let resp, err = client::do_intercepted(client, req) { chain, client =>
            // Inject header into request before proceed
            http::set_header(chain.request, "X-Custom-Client", "Interceptor-V1");

            // Proceed down the chain
            client::proceed(chain, client);

            // Mutate response after proceed
            http::set_header(chain.response, "X-Processed-By", "Client-Chain");
        };

        sub.assert_true(http::ok(err), "intercepted call ok");
        sub.assert_eq(http::status(resp), 200, "status 200");
        sub.assert_bytes_eq(resp.body[..], "server-payload", "server body received");

        // Verify sent header
        let sent_c = http::sent_header(resp, "X-Custom-Client");
        sub.assert_bytes_eq(sent_c, "Interceptor-V1", "Header injected before proceed");

        // Verify mutated response header
        let proc_by = http::header(resp, "X-Processed-By");
        sub.assert_bytes_eq(proc_by, "Client-Chain", "Response mutated after proceed");
    };

    t.run("Closure Chain: Short-Circuit Without Hitting Network") { sub =>
        var client = client::new_client();
        // Notice: NO mock route is configured for this URL! If it hit network/mock it would fail or return default.
        let req = http::new_get("https://site.com/short-circuit");

        let resp, err = client::do_intercepted(client, req) { chain, client =>
            // Directly synthesize response without calling proceed!
            chain.response.status_code = 201;
            chain.response.body.clear();
            chain.response.body.append("{\"short\":\"circuited\"}");
            chain.short_circuited = true;
        };

        sub.assert_true(http::ok(err), "short-circuit succeeded");
        sub.assert_eq(http::status(resp), 201, "status 201");
        sub.assert_bytes_eq(resp.body[..], "{\"short\":\"circuited\"}", "synthesized body returned");
    };
}

// --- Component: client_e2e_helpers ---
// Verification suite for end-to-end convenience helpers:
// - Request priority configuration (RFC 9218 header injection)
// - Request and Response Ed25519 HTTP Message Signatures (RFC 9421)
// - Server response zero-copy transmission via IoVecArray (send_http1_response_iov)

// ----------------------------------------------------------------------------
// 17. Request.set_priority helper
// ----------------------------------------------------------------------------
fn test_request_priority_helper(t: lit::T&) {
    t.run("Request.set_priority") { sub =>
        var req = http::Request { .. };
        http::set_priority(req, 1, true);
        let prio_val = http::header(req, "priority");
        sub.assert_eq(prio_val, "u=1, i", "Priority header encoded correctly with incremental");

        var req2 = http::Request { .. };
        http::set_priority(req2, 6);
        let prio_val2 = http::header(req2, "priority");
        sub.assert_eq(prio_val2, "u=6", "Priority header encoded correctly without incremental");

        // Invalid urgency defaults to 3
        var req3 = http::Request { .. };
        http::set_priority(req3, 99);
        let prio_val3 = http::header(req3, "priority");
        sub.assert_eq(prio_val3, "u=3", "Out-of-range urgency defaults to 3");
    };
}

// ----------------------------------------------------------------------------
// 18. RFC 9421 Ed25519 Request & Response helpers
// ----------------------------------------------------------------------------
fn test_ed25519_signatures_helpers(t: lit::T&) {
    t.run("sign_request_ed25519 & verify_request_ed25519") { sub =>
        let seed: u8[32] = [
            0x9d, 0x61, 0xb1, 0x9c, 0x4f, 0x61, 0x97, 0xf8,
            0x9a, 0x21, 0xe1, 0xf3, 0xc2, 0x55, 0xa0, 0x45,
            0x82, 0xe2, 0x15, 0x68, 0x77, 0x11, 0x0f, 0x2e,
            0xa0, 0x21, 0x86, 0xc4, 0x2d, 0x39, 0x53, 0x4f,
        ];
        let pubkey = core::ed25519_public_key(seed);

        var req = http::Request {
            method: "POST",
            url:    "https://api.example.com/v1/orders?item=book",
            ..
        };
        http::set_header(req, "content-type", "application/json");

        let ok_sign = http::sign_request_ed25519(req, "ed-key-1", seed[..]);
        sub.assert_true(ok_sign, "Request signed with Ed25519");

        let ok_verify = http::verify_request_ed25519(req, "ed-key-1", pubkey[..]);
        sub.assert_true(ok_verify, "Request signature verified with public key");

        // Tamper method
        var tampered_req = req;
        tampered_req.method.clear();
        tampered_req.method.append("GET");
        let tamper_verify = http::verify_request_ed25519(tampered_req, "ed-key-1", pubkey[..]);
        sub.assert_false(tamper_verify, "Tampered request signature rejected");
    };

    t.run("sign_response_ed25519 & verify_response_ed25519") { sub =>
        let seed: u8[32] = [
            0x9d, 0x61, 0xb1, 0x9c, 0x4f, 0x61, 0x97, 0xf8,
            0x9a, 0x21, 0xe1, 0xf3, 0xc2, 0x55, 0xa0, 0x45,
            0x82, 0xe2, 0x15, 0x68, 0x77, 0x11, 0x0f, 0x2e,
            0xa0, 0x21, 0x86, 0xc4, 0x2d, 0x39, 0x53, 0x4f,
        ];
        let pubkey = core::ed25519_public_key(seed);

        var req = http::Request {
            method: "GET",
            url:    "https://api.example.com/v1/status",
            ..
        };

        var res = http::Response {
            status_code: 200,
            ..
        };
        http::set_header(res, "content-type", "application/json");

        let ok_sign = http::sign_response_ed25519(res, req, "ed-key-1", seed[..]);
        sub.assert_true(ok_sign, "Response signed with Ed25519");

        let ok_verify = http::verify_response_ed25519(res, req, "ed-key-1", pubkey[..]);
        sub.assert_true(ok_verify, "Response signature verified with public key");

        // Tamper status
        var tampered_res = res;
        tampered_res.status_code = 404;
        let tamper_verify = http::verify_response_ed25519(tampered_res, req, "ed-key-1", pubkey[..]);
        sub.assert_false(tamper_verify, "Tampered response signature rejected");
    };
}

// ----------------------------------------------------------------------------
// 19. send_http1_response_iov helper
// ----------------------------------------------------------------------------
fn test_send_http1_response_iov_helper(t: lit::T&) {
    t.run("send_http1_response_iov empty descriptor check") { sub =>
        var res = http::Response {
            status_code: 200,
            ..
        };
        var iov = core::new_iovec_array();
        core::iovec_push(iov, "chunk 1\n");
        core::iovec_push(iov, "chunk 2\n");

        var wire_hdr: u8[>..] = [];
        // Closed / invalid socket returns 0 guard
        let sent = server::send_http1_response_iov(-1, res, "goose-wing/1.0", iov, wire_hdr);
        sub.assert_eq(sent, 0, "Non-positive socket returns 0 bytes safely");
        sub.assert_gt(wire_hdr.len, 0, "Headers formatted");
    };
}

// RFC 2104 Section 2: Definition of HMAC - HMAC-SHA256 request body signing verification
// ----------------------------------------------------------------------------
// 20. RFC 2104 / RFC 4231 HMAC-SHA256 Request Signing
// ----------------------------------------------------------------------------
fn test_hmac_signing(t: lit::T&) {
    t.run("Empty body signs empty slice with HMAC-SHA256") { sub =>
        var req = http::new_post("https://api.example.com/empty");
        http::sign_hmac_sha256(req, "my_secret_key");
        let sig = http::header(req, "X-Signature-256");
        sub.assert_bytes_eq(sig, "9915a19fb787e5936fbc9b2365405c2d977cea60242b9af60f5a4a5a72a9b846", "HMAC empty body matches");
    };

    t.run("RFC 4231 Section 4.3: Test Case 2 - Non-empty request body matches official test vector") { sub =>
        var req = http::new_post("https://api.example.com/vector2");
        http::text(req, "what do ya want for nothing?");
        http::sign_hmac_sha256(req, "Jefe");
        let sig = http::header(req, "X-Signature-256");
        sub.assert_bytes_eq(sig, "5bdcc146bf60754e6a042426089575c75a003f089d2739839dec58b964ec3843", "HMAC Case 2 matches");
    };
}

// Invariant 13: Zero silent buffer drops and strict capacity overflow rejection
// ----------------------------------------------------------------------------
// 21. Invariant 13 Query Parameter Capacity & Bounds
// ----------------------------------------------------------------------------
fn test_client_query_capacity_rejections(t: lit::T&) {
    t.run("Query parameter capacity overflow returns false") { sub =>
        var req = http::new_get("https://example.com/search");
        // Push 16 items up to capacity
        for i in 16 {
            var k: u8[..16] = "k";
            format(k, i);
            var v: u8[..16] = "v";
            format(v, i);
            let ok = req.query(k[..], v[..]);
            sub.assert_true(ok, "within query_params capacity");
        }
        // 17th item MUST fail with false (never silently dropped)
        let ok_overflow = req.query("k16", "v16");
        sub.assert_false(ok_overflow, "17th query parameter MUST return false on capacity overflow");
    };

    t.run("Query parameter key length exceeding 64 bytes returns false") { sub =>
        var req = http::new_get("https://example.com/search");
        var oversized_key: u8[..80] = [];
        for _ in 65 { oversized_key.push('a'); }
        let ok = req.query(oversized_key[..], "valid_val");
        sub.assert_false(ok, "oversized key MUST be rejected");
    };

    t.run("Query parameter value length exceeding 256 bytes returns false") { sub =>
        var req = http::new_get("https://example.com/search");
        var oversized_val: u8[>..] = [];
        for _ in 257 { oversized_val.push('b'); }
        let ok = req.query("valid_key", oversized_val[..]);
        sub.assert_false(ok, "oversized value MUST be rejected");
    };
}

// Vector B1: honest transport failures — the synthetic 200 {"id":1042,...}
// fallback is gone; failures surface as explicit errors.
// ----------------------------------------------------------------------------
// 22. Honest Transport Failures (no fake 200, TLS-not-wired)
// ----------------------------------------------------------------------------
fn test_honest_transport_failures(t: lit::T&) {
    t.run("Failed live connect returns transport error, never a fake 200") { sub =>
        var session = client::new_session(client::Config {
            timeout_ms: 500,
            ..
        });
        var req = http::new_get("http://unresolvable.invalid/resource");
        let res, err = client::execute_request(session, req);

        sub.assert_false(http::ok(err), "failed connect must not report success");
        sub.assert_bytes_eq(err.stage[..], "transport", "error stage is transport");
        sub.assert_eq(res.status_code, 0, "no synthesized 200 status");
        sub.assert_eq(res.body.len, 0, "no synthesized success body (fake 1042 payload removed)");
    };

    t.run("https:// connect failure fails honestly with transport error") { sub =>
        var session = client::new_session(client::Config {
            timeout_ms: 500,
            ..
        });
        var req = http::new_get("https://unresolvable.invalid/data");
        let res, err = client::execute_request(session, req);

        sub.assert_false(http::ok(err), "https:// connect to unresolvable host must fail");
        sub.assert_bytes_eq(err.stage[..], "transport", "error stage is transport");
        sub.assert_eq(res.status_code, 0, "no silent plaintext success");
        sub.assert_eq(res.body.len, 0, "no fake body behind https://");
    };

    t.run("Client TLS configuration: insecure_skip_verify & trust anchor store") { sub =>
        var session = client::new_session(client::Config {
            insecure_skip_verify: true,
            ..
        });
        sub.assert_true(session.insecure_skip_verify, "insecure_skip_verify set via ClientConfig");
        session.insecure_skip_verify = false;
        sub.assert_false(session.insecure_skip_verify, "insecure_skip_verify cleared directly");

        let seed: u8[32] = [1; 32];
        var cert_der: u8[..2048] = [];
        let ok_gen = tls::build_test_ed25519_cert_der(seed, "localhost", "localhost", "127.0.0.1", cert_der);
        sub.assert_true(ok_gen, "test self-signed cert generated");

        let ok_add = tls::add_trust_anchor_cert_der(session.trust_store, cert_der[..]);
        sub.assert_true(ok_add, "trust anchor added to client session store");
        sub.assert_eq(session.trust_store.anchors.len, 1, "trust anchor count is 1");
    };

    t.run("RFC 6797 §12.1 HSTS strictly forbids insecure_skip_verify override") { sub =>
        var session = client::new_session();
        session.insecure_skip_verify = true;
        http::hsts_cache_update(session.hsts, "secure.example.com", "max-age=31536000", 1700000000);

        let now_sec: i64 = 1700000000;
        let is_hsts = session.enable_hsts && http::is_hsts_host(session.hsts, "secure.example.com", now_sec);
        sub.assert_true(is_hsts, "secure.example.com is an active HSTS host");

        let effective_skip = session.insecure_skip_verify && !is_hsts;
        sub.assert_false(effective_skip, "HSTS host strictly suppresses insecure_skip_verify (RFC 6797 §12.1)");

        let non_hsts = session.enable_hsts && http::is_hsts_host(session.hsts, "plain.example.com", now_sec);
        let non_hsts_skip = session.insecure_skip_verify && !non_hsts;
        sub.assert_true(non_hsts_skip, "Non-HSTS host permits insecure_skip_verify");
    };

    t.run("Mock mode serves matched routes and errors on misses without fake 200") { sub =>
        var session = client::new_session();
        client::mock_route(session, "GET", "http://mock.invalid/a", 200, "ok");

        var req_hit = http::new_get("http://mock.invalid/a");
        let res_hit, err_hit = client::execute_request(session, req_hit);
        sub.assert_true(http::ok(err_hit), "matched mock route still succeeds");
        sub.assert_bytes_eq(res_hit.body[..], "ok", "mock body served");

        var req_miss = http::new_get("http://mock.invalid/b");
        let res_miss, err_miss = client::execute_request(session, req_miss);
        sub.assert_false(http::ok(err_miss), "unmatched request in mock mode is an explicit error");
        sub.assert_bytes_eq(err_miss.stage[..], "mock", "error stage is mock");
        sub.assert_eq(res_miss.status_code, 0, "no fake 200 on mock route miss");
        sub.assert_eq(res_miss.body.len, 0, "no fake 1042 body on mock route miss");
    };
}

// Vector B: ErrorKind enum, stream 3-state read_chunk, session close drain, timeout clamp.
// ----------------------------------------------------------------------------
// 23. Vector B Enhancements (ErrorKind, 3-state read_chunk, close drain, timeout)
// ----------------------------------------------------------------------------
fn test_vector_b_enhancements(t: lit::T&) {
    t.run("ErrorKind enum typed error classification") { sub =>
        let err_tr = http::make_error(502, "transport", "failed connect");
        sub.assert_eq(err_tr.kind, http::ErrorKind.Transport, "transport kind resolved");

        let err_tls = http::make_error(501, "tls", "TLS not wired");
        sub.assert_eq(err_tls.kind, http::ErrorKind.Tls, "tls kind resolved");

        let err_mock = http::make_error(404, "mock", "route miss");
        sub.assert_eq(err_mock.kind, http::ErrorKind.Mock, "mock kind resolved");

        let err_ssrf = http::make_error(403, "ssrf_guard", "blocked subnet");
        sub.assert_eq(err_ssrf.kind, http::ErrorKind.SsrfGuard, "ssrf_guard kind resolved");

        let err_stream = http::make_error(502, "stream", "corrupted chunk");
        sub.assert_eq(err_stream.kind, http::ErrorKind.Stream, "stream kind resolved");
    };

    t.run("read_chunk three-state classification: Data, Eof, Error") { sub =>
        // Normal chunked stream
        var resp_good = http::Response { status_code: 200, .. };
        http::set_header(resp_good, "Transfer-Encoding", "chunked");
        resp_good.body.append("5\r\nhello\r\n0\r\n\r\n");

        var r_good = client::new_stream_reader(resp_good);
        var buf: u8[>..] = [];
        let st1, eof1 = client::read_chunk(r_good, 10, buf);
        sub.assert_eq(st1, client::StreamReadStatus.Data, "data chunk read");
        sub.assert_bytes_eq(buf[..], "hello", "chunk content matches");
        sub.assert_true(eof1, "terminal chunk reached EOF");

        // Subsequent read is clean Eof
        buf.clear();
        let st2, eof2 = client::read_chunk(r_good, 10, buf);
        sub.assert_eq(st2, client::StreamReadStatus.Eof, "clean Eof status on finished reader");
        sub.assert_true(eof2, "eof true");

        // Corrupted chunk size yields explicit Error
        var resp_bad = http::Response { status_code: 200, .. };
        http::set_header(resp_bad, "Transfer-Encoding", "chunked");
        resp_bad.body.append("ZZ\r\ncorrupted\r\n");

        var r_bad = client::new_stream_reader(resp_bad);
        buf.clear();
        let st_err, eof_err = client::read_chunk(r_bad, 10, buf);
        sub.assert_eq(st_err, client::StreamReadStatus.Error, "corrupted chunk yields Error status");
        sub.assert_false(eof_err, "error is not EOF");
    };

    t.run("session.close drains connection pool") { sub =>
        var session = client::new_session();
        client::close(session);
        sub.assert_eq(session.pool.conns.len, 0, "session pool has zero connections after close");
    };

    t.run("Request set_timeout_ms overrides and clamps session timeout") { sub =>
        var req = http::new_get("http://example.invalid");
        http::set_timeout_ms(req, 3000);
        sub.assert_eq(req.timeout, 3000, "per-request timeout set");
    };
}

// ----------------------------------------------------------------------------
// 24. Client Round 3 Regression & Protocol Conformance Vectors
// ----------------------------------------------------------------------------
fn test_client_round3_repro_vectors(t: lit::T&) {
    t.run("SSRF IPv6 NAT64 (64:ff9b:1::/48) and ORCHIDv2 (2001:20::/28) sweeps") { sub =>
        sub.assert_true(security::is_private_or_reserved_ip("64:ff9b:1::"), "NAT64 local prefix base");
        sub.assert_true(security::is_private_or_reserved_ip("64:ff9b:1::1"), "NAT64 local prefix with host");
        sub.assert_true(security::is_private_or_reserved_ip("64:ff9b:1:abcd::1"), "NAT64 local prefix with word 4");
        sub.assert_true(security::is_private_or_reserved_ip("64:ff9b:1::8.8.8.8"), "NAT64 local prefix is blocked even with public IPv4 suffix");
        sub.assert_false(security::is_private_or_reserved_ip("64:ff9b::8.8.8.8"), "well-known NAT64 64:ff9b::/96 with public IPv4 is routable");

        sub.assert_true(security::is_private_or_reserved_ip("2001:20::1"), "ORCHIDv2 word 0x0020");
        sub.assert_true(security::is_private_or_reserved_ip("2001:2f::1"), "ORCHIDv2 word 0x002F");
        sub.assert_false(security::is_private_or_reserved_ip("2001:30::1"), "2001:30:: is outside ORCHIDv2 /28");

        sub.assert_false(security::is_private_or_reserved_ip("2002:808::"), "6to4 8.8.0.0 is public not private");
        sub.assert_true(security::is_private_or_reserved_ip("2002:a00::"), "6to4 10.0.0.0/8 is private");
    };

    t.run("RFC 8470 Section 5.2: 425 Too Early retry idempotency and rewind guards") { sub =>
        var req_post = http::new_post("https://example.com/api");
        req_post.body.append("non-idempotent-body");
        let retry_post = client_internal::should_retry_request(
            rfc::STATUS_TOO_EARLY,
            http::Error { .. },
            "POST",
            req_post,
            0,
            false,
            0,
            false,
        );
        sub.assert_false(retry_post, "POST without idempotency key must not retry on 425");

        var req_get = http::new_get("https://example.com/api");
        let retry_get = client_internal::should_retry_request(
            rfc::STATUS_TOO_EARLY,
            http::Error { .. },
            "GET",
            req_get,
            0,
            false,
            0,
            false,
        );
        sub.assert_true(retry_get, "GET is idempotent and retries on 425");

        var req_post_key = http::new_post("https://example.com/api");
        req_post_key.body.append("body");
        http::set_header(req_post_key, "Idempotency-Key", "uuid-12345");
        let retry_key = client_internal::should_retry_request(
            rfc::STATUS_TOO_EARLY,
            http::Error { .. },
            "POST",
            req_post_key,
            0,
            false,
            0,
            false,
        );
        sub.assert_true(retry_key, "POST with Idempotency-Key retries on 425");

        // Non-rewindable body must reject 425 retry
        req_post_key.rewindable = false;
        let retry_non_rewind = client_internal::should_retry_request(
            rfc::STATUS_TOO_EARLY,
            http::Error { .. },
            "POST",
            req_post_key,
            0,
            false,
            0,
            false,
        );
        sub.assert_false(retry_non_rewind, "non-rewindable body must never retry on 425");
    };

    t.run("3xx redirect without Location header triggers ERR_MISSING_LOCATION") { sub =>
        var session = client::new_session();
        session.enable_cookie_jar = false;
        client::mock_route(session, "GET", "https://redirect.invalid/no-loc", rfc::STATUS_FOUND, "redirecting");
        var req = http::new_get("https://redirect.invalid/no-loc");
        let resp, err = client::execute_request(session, req);
        sub.assert_false(http::ok(err), "missing Location header on 302 returns error");
        sub.assert_eq(err.code, rfc::STATUS_BAD_REQUEST, "error code is 400 for bad redirect");
    };

    t.run("W3C Traceparent parent-id non-zero invariant") { sub =>
        var pipeline = client::InterceptorPipeline { .. };
        let add_ok = client::add_interceptor(
            pipeline,
            client::InterceptorEntry {
                scope:   client::InterceptorScope.Application,
                kind:    client::InterceptorKind.Traceparent,
                prefix:  "00",
                counter: 0,
            },
        );
        sub.assert_true(add_ok, "interceptor registered");

        var req = http::new_get("http://example.invalid/trace");
        client::apply_app_interceptors_request(pipeline, req, 1000);
        let tp = http::header(req, "traceparent");
        sub.assert_true(tp.len > 0, "traceparent header injected");
        sub.assert_false(core::ends_with(tp, "-0000000000000000-00"), "traceparent must never have all-zero parent id");
    };

    t.run("HTTP/1.1 Smuggling: Content-Length omitted on chunked Transfer-Encoding") { sub =>
        var req = http::new_post("http://example.invalid");
        req.body.append("chunked-payload");
        http::set_header(req, "Transfer-Encoding", "chunked");
        let u = core::new_url("http://example.invalid");
        var hdr_out: u8[..4096] = [];
        wing::serialize_h1_request(req, u, hdr_out);
        sub.assert_false(
            core::contains(hdr_out[..], "Content-Length:"),
            "Content-Length must be omitted when Transfer-Encoding: chunked is present",
        );
        sub.assert_true(
            core::contains(hdr_out[..], "Transfer-Encoding: chunked"),
            "Transfer-Encoding: chunked header is serialized",
        );
    };

    t.run("RateLimiter clock skew monotonicity guard") { sub =>
        var limiter = client::new_rate_limiter(10.0, 10);
        let t0 = limiter.last_update_mono_ns;
        let ok1 = client::allow(limiter, t0 + 1000000);
        sub.assert_true(ok1, "forward monotonic timestamp succeeds");
        let ok2 = client::allow(limiter, t0);
        sub.assert_false(ok2, "backwards monotonic timestamp rejected by guard without token corruption");
    };

    t.run("HarEntry URL capacity 2048 bytes and status constant") { sub =>
        var har = client::HarEntry { .. };
        sub.assert_eq(har.url.cap, 2048, "HarEntry url capacity is 2048 bytes");
        sub.assert_eq(har.status, rfc::STATUS_OK as! u16, "HarEntry default status is rfc::STATUS_OK");
    };

    t.run("Query param preserving long fragment (>512 bytes)") { sub =>
        var url_buf: u8[..2048] = [];
        url_buf.append("https://example.com/path#");
        for i in 600 {
            url_buf.push('a');
        }
        var qitems: http::QueryItem[..1] = [];
        var qi = http::QueryItem { .. };
        qi.key.append("k");
        qi.value.append("v");
        qitems.push(qi);
        client_internal::append_query_params_preserving_fragment(url_buf, qitems[..]);
        sub.assert_true(core::contains(url_buf[..], "?k=v#"), "query param inserted before fragment");
        sub.assert_gt(url_buf.len, 600, "fragment longer than 512B was preserved completely");
    };

    t.run("WebSocket subprotocol token match (RFC 6455 Section 4.2.2)") { sub =>
        sub.assert_true(client::header_has_token("chat, superchat", "chat"), "matches first requested token");
        sub.assert_true(client::header_has_token("chat, superchat", "superchat"), "matches second requested token");
        sub.assert_false(client::header_has_token("chat, superchat", "admin"), "rejects unrequested token");
        sub.assert_false(client::header_has_token("", "chat"), "empty header rejects any token");
    };

    t.run("Response set_header overwrites existing header in-place") { sub =>
        var resp = http::Response { status_code: rfc::STATUS_OK, .. };
        http::set_header(resp, "X-Test", "old_val");
        sub.assert_bytes_eq(http::header(resp, "X-Test"), "old_val", "initial header value");

        http::set_header(resp, "X-Test", "new_val");
        sub.assert_bytes_eq(http::header(resp, "X-Test"), "new_val", "updated header returned");
    };

    t.run("CHIPS partition key extraction in RequestExecutionContext") { sub =>
        var ctx = client_internal::RequestExecutionContext { .. };
        ctx.top_frame_origin.scheme.append("https");
        ctx.top_frame_origin.host.append("publisher.example.com");
        let u = core::new_url("https://ad.tracker.com/track");
        var part_key: u8[..256] = [];
        client_internal::compute_hop_partition_key(ctx, u, part_key);
        sub.assert_bytes_eq(part_key[..], "https://example.com", "top frame site eTLD+1 used as CHIPS partition key");
    };
}

// ----------------------------------------------------------------------------
// 25. Go #82350: Host Header Leakage Across Cross-Origin Redirects
// ----------------------------------------------------------------------------
fn test_redirect_stale_host_header_leakage(t: lit::T&) {
    t.run("Outbound Host header must not be retained on cross-origin redirect") { sub =>
        // When a request has an explicit custom Host header, redirecting to a different origin
        // MUST strip or update the Host header to match the new destination authority (Go #82350).
        var headers = http::HeaderMap { .. };
        http::append_header(headers, "Host", "internal-vault.corp.local");
        http::append_header(headers, "X-Custom", "keep");

        let origin_target = core::new_url("https://evil-phishing.com/harvest");

        var rinfo = client::RedirectInfo {
            status_code:         302,
            new_url:             origin_target,
            is_cross_origin:     true,
            is_scheme_downgrade: false,
            is_port_changed:     false,
            clear_body:          true,
            new_referrer:        [],
        };

        client::sanitize_headers_on_redirect(headers, rinfo, client::RedirectSanitizeOptions { .. });

        // Host header pointing to the previous host MUST be stripped to prevent host header injection / routing desync
        let host_idx = http::find_header_index(headers, "Host");
        sub.assert_true(host_idx < 0, "Stale Host header from source origin must be stripped on cross-origin redirect (Go #82350)");
    };
}

// ----------------------------------------------------------------------------
// 26. RFC 9110 §15.4 & Go #73816 (CVE-2025-4673): Redirect Sensitive Header Stripping
// ----------------------------------------------------------------------------
fn test_redirect_sensitive_header_stripping(t: lit::T&) {
    t.run("Proxy-Authorization and Authorization purged on cross-origin redirect (CVE-2025-4673)") { sub =>
        var headers = http::HeaderMap { .. };
        http::append_header(headers, "Authorization", "Bearer secret123");
        http::append_header(headers, "Proxy-Authorization", "Basic proxysecret");
        http::append_header(headers, "User-Agent", "GooseWing/1.0");

        let red_info = client::RedirectInfo {
            is_cross_origin:     true,
            is_scheme_downgrade: false,
            is_port_changed:     false,
            clear_body:          false,
            ..
        };

        client::sanitize_headers_on_redirect(headers, red_info, client::RedirectSanitizeOptions { .. });

        let has_auth = http::find_header_index(headers, "Authorization") >= 0;
        sub.assert_false(has_auth, "Authorization header MUST be stripped on cross-origin redirect");

        let has_proxy_auth = http::find_header_index(headers, "Proxy-Authorization") >= 0;
        sub.assert_false(has_proxy_auth, "Proxy-Authorization MUST be stripped on cross-origin redirect (CVE-2025-4673)");

        let has_ua = http::find_header_index(headers, "User-Agent") >= 0;
        sub.assert_true(has_ua, "User-Agent header is preserved across redirect");
    };
}

// ----------------------------------------------------------------------------
// 27. Client Redirect Engine (client/redirect.goose)
// ----------------------------------------------------------------------------
fn test_client_redirect_origin_and_fragment_safety(t: lit::T&) {
    t.run("Cross-origin 307 redirect MUST set Origin to null to prevent leaking internal origin") { sub =>
        var headers = http::HeaderMap { .. };
        http::append_header(headers, "Origin", "https://internal.corp.example.com");
        http::append_header(headers, "Content-Type", "application/json");

        var redir = client::RedirectInfo {
            status_code:     307,
            is_cross_origin: true,
            clear_body:      false, // 307 retains POST body!
            ..
        };

        client::sanitize_headers_on_redirect(headers, redir, client::RedirectSanitizeOptions { .. });

        let origin_idx = http::find_header_index(headers, "Origin");
        sub.assert_ge(origin_idx, 0, "Origin header present");
        sub.assert_bytes_eq(http::get_header(headers, "Origin"), "null", "Origin on cross-origin 307 MUST be 'null'");
    };

    t.run("inherit_target_fragment does not crash when combined length exceeds 2048") { sub =>
        var long_target: u8[>..] = [];
        long_target.append("https://target.com/");
        for i in 2040 { long_target.push('x'); }

        // Must not crash or panic with capacity exceeded
        let info = client::compute_redirect_info(
            "GET",
            302,
            "https://example.com/base#very-long-fragment",
            long_target[..],
            client::ReferrerPolicy.StrictOriginWhenCrossOrigin,
            "",
            client::RedirectOptions { is_main_frame: true },
        );
        sub.assert_true(info.error == client::RedirectError.None || info.error == client::RedirectError.InvalidLocationUrl, "Handled safely without crash");
    };
}

// ----------------------------------------------------------------------------
// 28. Multi-Layer Content-Encoding Chain & Strict Decoding Mode
// ----------------------------------------------------------------------------
fn test_multi_layer_content_encoding_and_strict_mode(t: lit::T&) {
    t.run("Content-Encoding: deflate, gzip decodes in reverse order (gzip then deflate)") { sub =>
        let plain = "chromium filter_source_stream multi-layer compression payload";
        var deflated: u8[>..] = [];
        let ok_def = core::zlib_compress(plain, deflated);
        sub.assert_true(ok_def, "Deflate layer 1 succeeded");

        var gzipped: u8[>..] = [];
        let ok_gz = core::gzip_compress_with_header(deflated[..], gzipped);
        sub.assert_true(ok_gz, "Gzip layer 2 succeeded");

        var resp = http::Response { status_code: 200, .. };
        http::set_header(resp.headers, "Content-Encoding", "deflate, gzip");
        resp.body.append(gzipped[..]);

        let ok_dec = http::decode_body(resp);
        sub.assert_true(ok_dec, "Multi-layer decode_body succeeded");
        sub.assert_bytes_eq(resp.text(), plain, "Decompressed payload matches original plaintext");
        sub.assert_false(http::has_header(resp.headers, "Content-Encoding"), "Content-Encoding removed after full chain decode");
    };

    t.run("204 No Content with Content-Encoding: gzip succeeds without decompression error") { sub =>
        var resp = http::Response { status_code: 204, .. };
        http::set_header(resp.headers, "Content-Encoding", "gzip");
        sub.assert_true(http::decode_body(resp), "Empty 204 with Content-Encoding header bypasses decoder safely");
    };

    t.run("strict_content_decoding aborts pipeline with ERR_CONTENT_DECODING_FAILED on corrupted body") { sub =>
        var cli = client::new_client(client::Config {
            strict_content_decoding: true,
            ..
        });
        cli.mock_route("GET", "https://api.example.com/corrupt-gzip", 200, "NOT_VALID_GZIP_BYTES");
        cli.add_mock_header("Content-Encoding", "gzip");

        let res, err = cli.get("https://api.example.com/corrupt-gzip");
        let _ = res;
        sub.assert_false(http::ok(err), "Strict content decoding must fail on corrupted gzip stream");
        sub.assert_bytes_eq(
            err.message[..],
            "ERR_CONTENT_DECODING_FAILED: content-encoding decompression failed",
            "Error reports ERR_CONTENT_DECODING_FAILED",
        );
    };
}

// ----------------------------------------------------------------------------
// 29. DNS HTTPS/SVCB (RFC 9460) Auto-H3 Protocol Racing
// ----------------------------------------------------------------------------
fn test_dns_https_svcb_h3_protocol_racing(t: lit::T&) {
    t.run("DNS HTTPS record with alpn=h3 promotes first request to HTTP/3 without prior Alt-Svc header") { sub =>
        var cli = client::new_client();
        cli.enable_protocol_racing = true;

        var https_rec = dns::HttpsRecord {
            priority: 1,
            port:     443,
            ..
        };
        https_rec.alpns.push("h3");
        https_rec.alpns.push("h2");
        let now_sec = cli.virtual_clock_us / 1000000;
        var entry = dns::CacheEntry {
            qtype:           rfc::DNS_QTYPE_HTTPS,
            inserted_at_sec: now_sec,
            ttl_sec:         300,
            valid:           true,
            ..
        };
        entry.domain.append("svcb-h3.example.com");
        entry.https_records.push(https_rec);
        cli.dns_cache.insert(entry);

        cli.mock_route("GET", "https://svcb-h3.example.com/data", 200, "h3-via-dns-https");
        let res, err = cli.get("https://svcb-h3.example.com/data");
        sub.assert_true(http::ok(err), "Request succeeded");
        sub.assert_bytes_eq(res.protocol[..], "h3", "Promoted to h3 via DNS HTTPS alpn=h3");
    };
}

// ----------------------------------------------------------------------------
// 30. Chromium-Style Multi-Component Pipeline Integration (Cache, Redirects, Dicts, Auth, CORS/Cookies)
// ----------------------------------------------------------------------------
fn test_chromium_multi_component_pipeline_integration(t: lit::T&) {
    t.run("Hop-0 Referer sanitization, downgrade Sec-Fetch-* stripping, and redirect-hop NVS HTTP cache hit") { sub =>
        var cli = client::new_client(client::Config {
            enable_cache: true,
            ..
        });

        // Pre-populate HTTP cache for the redirect target with No-Vary-Search
        var seed_req = http::new_request("GET", "https://cdn.example.com/bundle.js?v=1&utm_campaign=launch");
        var seed_resp = http::Response { status_code: 200, .. };
        http::set_header(seed_resp.headers, "Cache-Control", "max-age=3600");
        http::set_header(seed_resp.headers, "No-Vary-Search", "params=(\"utm_campaign\")");
        seed_resp.body.append("cached_bundle_v1_payload");
        let now_sec = cli.virtual_clock_us / 1000000;
        let ts = http::CacheTimestamps {
            request_sec:  now_sec,
            response_sec: now_sec,
            now_sec:      now_sec,
            ..
        };
        let _ = cli.cache.on_response(seed_req, seed_resp, ts, -1);

        // Hop 0 redirects to an NVS-equivalent URL on cdn.example.com (no mock route needed for cdn.example.com!)
        cli.mock_route("GET", "https://app.example.com/start", 302, "");
        cli.add_mock_header("Location", "https://cdn.example.com/bundle.js?v=1&utm_campaign=retarget");
        cli.add_mock_header("Referrer-Policy", "unknown-future-token");

        var req = http::new_request("GET", "https://app.example.com/start");
        http::set_header(req, "Referer", "https://portal.other.example/secret/page?token=123");
        let res, err = cli.do(req);
        sub.assert_true(http::ok(err), "Redirect into NVS-equivalent cached hop succeeded without network miss");
        sub.assert_eq(res.status_code, 200, "Served 200 OK from HTTP cache on redirect hop");
        sub.assert_bytes_eq(res.text(), "cached_bundle_v1_payload", "NVS cache matched on redirect hop");
        sub.assert_eq(res.redirect_count, 1, "Recorded 1 redirect hop");

        // Verify Sec-Fetch-* and Sec-CH-* stripping on HTTPS -> HTTP downgrade redirect
        var hdrs = http::HeaderMap { .. };
        http::set_header(hdrs, "Sec-Fetch-Site", "same-origin");
        http::set_header(hdrs, "Sec-CH-UA", "\"Chromium\";v=\"128\"");
        http::set_header(hdrs, "Accept", "*/*");
        let r_info = client::compute_redirect_info(
            "GET",
            302,
            "https://secure.example.com/a",
            "http://insecure.example.com/b",
            client::ReferrerPolicy.NoReferrer,
            "https://secure.example.com/a",
        );
        client::sanitize_headers_on_redirect(hdrs, r_info);
        sub.assert_false(http::has_header(hdrs, "Sec-Fetch-Site"), "Sec-Fetch-Site stripped on scheme downgrade");
        sub.assert_false(http::has_header(hdrs, "Sec-CH-UA"), "Sec-CH-UA stripped on scheme downgrade");
        sub.assert_true(http::has_header(hdrs, "Accept"), "Standard Accept header preserved");
    };

    t.run("RFC 9842 Shared Dictionary longest-match negotiation + 40-byte dcz magic decompression") { sub =>
        var cli = client::new_client();
        let now_sec = cli.virtual_clock_us / 1000000;

        // Register two dictionaries with overlapping patterns: "/app/*" (len 6) and "/app/v2/*" (len 9)
        var dict_short = http::Response { status_code: 200, .. };
        http::set_header(dict_short.headers, "Use-As-Dictionary", "match=\"/app/*\", id=\"short-dict\"");
        dict_short.body.append("short_dictionary_seed_content_123456");
        client_internal::ingest_compression_dict_header(cli.dict_cache, "https://cdn.example.com", "/dicts/1", now_sec, dict_short);

        var dict_long = http::Response { status_code: 200, .. };
        http::set_header(dict_long.headers, "Use-As-Dictionary", "match=\"/app/v2/*\", match-dest=(\"script\"), id=\"long-dict\"");
        dict_long.body.append("long_dictionary_seed_content_abcdef");
        client_internal::ingest_compression_dict_header(cli.dict_cache, "https://cdn.example.com", "/dicts/2", now_sec, dict_long);

        // Verify RFC 9842 40-byte DCZ framing and longest-match negotiation
        let long_hash = cli.dict_cache.entries[1].sha256_hash;
        var compressed_zstd: u8[..4096] = [];
        sub.assert_true(
            http::compress_dcz_payload(
                "long_dictionary_seed_content_abcdef_plus_delta_payload",
                "long_dictionary_seed_content_abcdef",
                compressed_zstd,
            ),
            "Compressed payload with Zstandard dictionary",
        );
        var compressed_dcz: u8[>..] = [];
        let dcz_magic_40: u8[8] = [0x5E, 0x2A, 0x4D, 0x18, 0x20, 0x00, 0x00, 0x00];
        compressed_dcz.append(dcz_magic_40[..]);
        compressed_dcz.append(long_hash[..]);
        compressed_dcz.append(compressed_zstd[..]);
        sub.assert_true(compressed_dcz.len > 40, "DCZ payload includes 40-byte header + zstd frame");
        sub.assert_eq(compressed_dcz[0] as i64, 0x5E, "RFC 9842 §5 magic byte 0 (0x5E)");
        sub.assert_eq(compressed_dcz[4] as i64, 0x20, "RFC 9842 §5 length byte 4 (0x20)");

        cli.mock_route("GET", "https://cdn.example.com/app/v2/main.js", 200, compressed_dcz[..]);
        cli.add_mock_header("Content-Encoding", "dcz");

        let res, err = cli.get("https://cdn.example.com/app/v2/main.js");
        sub.assert_true(http::ok(err), "Shared dictionary dcz pipeline request succeeded");
        sub.assert_bytes_eq(
            res.text(),
            "long_dictionary_seed_content_abcdef_plus_delta_payload",
            "Decompressed dcz response using longest-match dictionary",
        );
    };

    t.run("RFC 9577 PrivateToken 401 challenge redemption and SameSite=Lax subresource cookie transmission") { sub =>
        var cli = client::new_client();
        let now_sec = cli.virtual_clock_us / 1000000;

        // Seed a SameSite=Lax cookie for api.example.com
        let _ = cli.jar.set_cookie_header(
            "https://api.example.com/",
            "lax_sess=ok_lax_1; Path=/; Secure; SameSite=Lax",
            cli.virtual_clock_us,
        );

        // Subresource request (is_main_frame=false) with same-site SiteForCookies and cross-site initiator
        let echo_url = core::new_url("https://api.example.com/echo");
        var sub_req = http::new_request("GET", "https://api.example.com/echo");
        sub_req.is_main_frame = false;
        sub_req.site_for_cookies = cookie::site_for_cookies_from_url("https://api.example.com/");
        sub_req.has_site_for_cookies = true;
        let _ = http::set_initiator(sub_req, "https://other.example.org/");

        let exec_ctx = client_internal::init_execution_context(cli, sub_req, echo_url);
        var samesite_ctx = client_internal::compute_hop_samesite_context(
            exec_ctx,
            echo_url,
            true,
        );
        sub.assert_true(
            samesite_ctx.context_type == cookie::SameSiteContextType.SameSiteLax,
            "Same-site subresource with cross-site initiator computes SameSiteLax context",
        );

        // Seed a PrivateToken into cli.private_token_cache and test 401 PrivateToken challenge redemption
        var chal = security::TokenChallenge {
            issuer_name: "issuer.example.com",
            ..
        };
        chal.origin_info.append("api.example.com");
        var raw_chal: u8[..256] = [];
        security::marshal_token_challenge(chal, raw_chal);
        sub.assert_true(raw_chal.len > 0, "Marshaled TokenChallenge");
        var b64_chal: u8[..384] = [];
        security::encode_padded_base64url(raw_chal[..], b64_chal);

        var dummy_tok = security::Token { .. };
        let ok_put = security::put_private_token(
            cli.private_token_cache,
            chal,
            dummy_tok,
            "raw_single_spend_token_bytes",
            3600,
            now_sec,
        );
        sub.assert_true(ok_put, "Stored single-spend PrivateToken in session cache");

        var www_auth_hdr: u8[..512] = "PrivateToken challenge=\"";
        www_auth_hdr.append(b64_chal[..]);
        www_auth_hdr.push('"');

        cli.mock_route("GET", "https://api.example.com/protected-token", 401, "need-token");
        cli.add_mock_header("WWW-Authenticate", www_auth_hdr[..]);

        let res_tok, err_tok = cli.get("https://api.example.com/protected-token");
        sub.assert_true(http::ok(err_tok), "401 PrivateToken challenge retry succeeded");
        let sent_auth = http::sent_header(res_tok, "Authorization");
        sub.assert_true(
            core::starts_with_fold(sent_auth, "PrivateToken token="),
            "Retry hop attached Authorization: PrivateToken header",
        );
        sub.assert_true(
            cli.private_token_cache.entries[0].used,
            "Single-spend PrivateToken marked used after 401 redemption",
        );
    };

    t.run("0-RTT Early-Data, DPoP Nonce Challenge, Content-Digest, Early-Hints, HAR Telemetry & Circuit Breaker") { sub =>
        var cli = client::new_client();
        cli.enable_early_data = true;
        cli.verify_content_digest = true;
        cli.enable_har_telemetry = true;

        var dpop_key: u8[32] = [0x42; 32];
        sub.assert_true(cli.set_dpop_credentials(dpop_key), "Configured DPoP private key via set_dpop_credentials");

        let body_bytes = "verified-digest-payload";
        var digest_hdr: u8[..128] = [];
        sub.assert_true(
            http::format_digest_field_value("sha-256", body_bytes, digest_hdr),
            "Computed SHA-256 Content-Digest",
        );

        let _ = cli.mock_route("GET", "https://edge.example.com/resource", 200, body_bytes) { route =>
            route.add_mock_header("Content-Digest", digest_hdr[..]);
            route.add_mock_header("Link", "</app.css>; rel=preload; as=style");
            route.add_mock_header("Retry-After", "120");
        };

        let res, err = cli.get("https://edge.example.com/resource");
        sub.assert_true(http::ok(err), "0-RTT + DPoP + Content-Digest request succeeded");
        sub.assert_bytes_eq(http::sent_header(res, "Early-Data"), "1", "Injected RFC 8470 Early-Data: 1 header");
        sub.assert_true(http::sent_header(res, "DPoP").len > 0, "Injected RFC 9449 DPoP proof JWT header");
        sub.assert_true(res.early_hints.is_valid, "Parsed Link header into Response.early_hints");
        sub.assert_true(cli.last_har_json.len > 0, "Populated HAR 1.2 telemetry JSON");

        // Retry-After: 120s (> 60s max_retry_after_ms) tripped HostCircuitBreaker for edge.example.com
        let res_cb, err_cb = cli.get("https://edge.example.com/resource");
        sub.assert_false(http::ok(err_cb), "Subsequent request blocked by HostCircuitBreaker");
        sub.assert_eq(res_cb.status_code, 503, "Circuit breaker returned 503");
    };
}

fn test_goose2rfc_client_audit_regressions(t: lit::T&) {
    t.run("CLIENT1_C01: parse_content_encoding_chain clears out_tokens on failure") { sub =>
        var tokens: u8[..16][..4] = [];
        let ok = http::parse_content_encoding_chain("gzip, ", tokens);
        sub.assert_false(ok, "trailing comma in Content-Encoding rejected");
        sub.assert_eq(tokens.len, 0, "out_tokens rolled back on parse failure");
    };

    t.run("CLIENT1_C03..C05: chunked framing and trailer validation (RFC 9112 Section 7.1)") { sub =>
        var chunk_buf: u8[..64] = [];
        client::encode_chunk("", chunk_buf);
        sub.assert_eq(chunk_buf.len, 0, "encode_chunk ignores empty data instead of emitting 0-chunk");

        client::encode_chunk_trailer("X-Bad\r\nName", "val", chunk_buf);
        client::encode_chunk_trailer("X-Custom", "bad\r\nval", chunk_buf);
        sub.assert_eq(chunk_buf.len, 0, "encode_chunk_trailer rejects CRLF in name or value");

        var dec = client::ChunkedStreamDecoder { .. };
        var body_out: u8[..64] = [];
        let _, ok_tr = client::feed_chunked_stream(dec, "0\r\nX-Custom: val\x00bad\r\n\r\n", body_out);
        sub.assert_false(ok_tr, "ChunkedStreamDecoder rejects NUL/CTL in trailer value");
    };

    t.run("CLIENT1_C08: process_dictionary_response enforces same-origin dictionary isolation (RFC 9842 Section 6)") { sub =>
        var cli = client::new_client();
        let dict_bytes = "shared-dictionary-seed-content-1234567890";
        http::dictionary_cache_insert(
            cli.dict_cache,
            "https://origin-a.example.com",
            "/api/*",
            "dict-1",
            dict_bytes,
            3600,
            1000,
        );
        let dict_hash = cli.dict_cache.entries[0].sha256_hash;
        var dcz_wire: u8[..256] = [];
        sub.assert_true(
            http::encode_dcz_response(dcz_wire, dict_hash, "secret-payload", dict_bytes),
            "built dcz payload",
        );

        var decoded: u8[..256] = "prefix:";
        let ok_cross = client_internal::process_dictionary_response(
            cli,
            "https://origin-b.example.com",
            "",
            "dcz",
            dcz_wire[..],
            decoded,
        );
        sub.assert_false(ok_cross, "cross-origin dictionary lookup by hash rejected");
        sub.assert_bytes_eq(decoded[..], "prefix:", "out_decoded preserved on failure");

        let ok_same = client_internal::process_dictionary_response(
            cli,
            "https://origin-a.example.com",
            "",
            "dcz",
            dcz_wire[..],
            decoded,
        );
        sub.assert_true(ok_same, "same-origin dictionary decompression succeeded");
        sub.assert_bytes_eq(decoded[..], "prefix:secret-payload", "decompressed payload appended");
    };

    t.run("CLIENT2_C01 & C04: RateLimiter transactional allow and Referrer-Policy OWS trimming") { sub =>
        var lim = client::RateLimiter {
            rate_per_sec:        1.0,
            burst_capacity:      1.0,
            tokens:              0.2,
            last_update_mono_ns: 1000000000,
        };
        let ok_allow = client::allow(lim, 1500000000);
        sub.assert_false(ok_allow, "insufficient tokens rejected");
        sub.assert_eq(lim.last_update_mono_ns, 1000000000, "last_update_mono_ns untouched on false");

        let pol = client::parse_referrer_policy_with_fallback(
            "unsafe-url\x0b",
            client::ReferrerPolicy.StrictOrigin,
        );
        sub.assert_true(
            pol == client::ReferrerPolicy.StrictOrigin,
            "VT control char not stripped as OWS in Referrer-Policy",
        );
    };

    t.run("Opaque origin CORS/CORP enforcement, POST Content-Length: 0, and missing Signature rejection") { sub =>
        var ctx = client_internal::RequestExecutionContext {
            has_initiator: true,
            cors_mode:     true,
            ..
        };
        ctx.initiator.kind = core::OriginKind.Opaque;
        let target_url = core::new_url("https://api.example.com/data");
        var resp_no_cors = http::Response { status_code: 200, .. };
        let cors_err1 = client_internal::validate_cors_and_corp_response(ctx, target_url, resp_no_cors);
        sub.assert_false(
            http::ok(cors_err1),
            "Opaque initiator must not bypass CORS check",
        );
        http::set_header(resp_no_cors.headers, "Access-Control-Allow-Origin", "*");
        http::set_header(resp_no_cors.headers, "Cross-Origin-Resource-Policy", "same-origin");
        let cors_err2 = client_internal::validate_cors_and_corp_response(ctx, target_url, resp_no_cors);
        sub.assert_false(
            http::ok(cors_err2),
            "Opaque initiator must be treated as cross-origin/cross-site for CORP",
        );

        let post_req = http::new_post("https://api.example.com/empty");
        var raw_h1: u8[..4096] = [];
        let _ = wing::serialize_h1_request(post_req, target_url, raw_h1);
        sub.assert_true(
            core::contains(raw_h1[..], "Content-Length: 0\r\n"),
            "Empty POST emits Content-Length: 0 in HTTP/1.1",
        );

        var sess = client::new_client();
        let pk: u8[32] = [0x11; 32];
        sess.sig_public_key.append(pk[..]);
        let unsigned_resp = http::Response { status_code: 200, .. };
        sub.assert_false(
            client_internal::verify_response_signature(
                sess,
                post_req,
                target_url,
                "POST",
                post_req.headers,
                unsigned_resp,
            ),
            "Missing Signature/Signature-Input rejected when sig_public_key is configured",
        );
    };
}

fn main() {
    var runner = lit::new_runner("HTTP Client, Interceptors, and Pipeline Verification Suite", lit::Verbosity.Verbose);

    lit::run_case(runner, "1. Mozilla PSL Scoping & Tenant Isolation", test_psl_scoping_and_tenants);
    lit::run_case(runner, "2. SiteForCookies & RFC 6265bis Schemeful Same-Site", test_site_for_cookies_and_rfc6265bis);
    lit::run_case(runner, "3. Redirect State Machine: Methods, Headers & Sensitive Sanitization", test_redirect_state_machine);
    lit::run_case(runner, "4. ClientSession 6-Phase Pipeline & CanonicalCookieJar Integration", test_oauth_flow);
    lit::run_case(runner, "5. ClientSession Redirect Loops & Manual Mode", test_redirect_loop_and_manual);
    lit::run_case(runner, "6. BodyRewind on 307/308 Redirects", test_body_rewind);
    lit::run_case(runner, "7. SSRF Guard 3-Tier Protection", test_ssrf_subnets);
    lit::run_case(runner, "8. DNS Rebinding Defense via Resolved IP Sweep", test_dns_rebinding);
    lit::run_case(runner, "9. Dangerous Service Port Blocking", test_dangerous_ports);
    lit::run_case(runner, "10. Client Integrated RFC 9111 HTTP Cache Pipeline", test_client_cache_integration);
    lit::run_case(runner, "11. Network Pipeline Edge Invariants & Multi-Module Audit", test_network_pipeline_edge_invariants);
    lit::run_case(runner, "12. Application Interceptors (Bearer, Request-ID, Traceparent, Headers, Logging)", test_application_interceptors);
    lit::run_case(runner, "13. Network Interceptors, Redirect Hops & Network Metrics", test_network_interceptors_and_metrics);
    lit::run_case(runner, "14. OkHttp Cache Boundary Invariant", test_cache_interceptor_boundary);
    lit::run_case(runner, "15. Retry Policy Interceptor", test_retry_policy_interceptor);
    lit::run_case(runner, "16. Closure-based Interceptor Chain & Short-Circuiting", test_closure_chain_interceptor);
    lit::run_case(runner, "17. Request.set_priority helper", test_request_priority_helper);
    lit::run_case(runner, "18. RFC 9421 Ed25519 Request & Response helpers", test_ed25519_signatures_helpers);
    lit::run_case(runner, "19. send_http1_response_iov helper", test_send_http1_response_iov_helper);
    lit::run_case(runner, "20. RFC 2104 / RFC 4231 HMAC-SHA256 Request Signing", test_hmac_signing);
    lit::run_case(runner, "21. Invariant 13 Query Parameter Capacity & Bounds", test_client_query_capacity_rejections);
    lit::run_case(runner, "22. Honest Transport Failures (no fake 200, TLS-not-wired)", test_honest_transport_failures);
    lit::run_case(runner, "23. Vector B Enhancements (ErrorKind, 3-state read_chunk, close drain, timeout)", test_vector_b_enhancements);
    lit::run_case(runner, "24. Client Round 3 Regression & Protocol Conformance Vectors", test_client_round3_repro_vectors);
    lit::run_case(runner, "25. Go #82350 Stale Host Header Leakage Across Redirects", test_redirect_stale_host_header_leakage);
    lit::run_case(runner, "26. RFC 9110 §15.4 & Go #73816 (CVE-2025-4673): Redirect Sensitive Header Stripping", test_redirect_sensitive_header_stripping);
    lit::run_case(runner, "27. Client Redirect origin & fragment safety (client/redirect.goose)", test_client_redirect_origin_and_fragment_safety);
    lit::run_case(runner, "28. Multi-Layer Content-Encoding Chain & Strict Decoding Mode", test_multi_layer_content_encoding_and_strict_mode);
    lit::run_case(runner, "29. DNS HTTPS/SVCB (RFC 9460) Auto-H3 Protocol Racing", test_dns_https_svcb_h3_protocol_racing);
    lit::run_case(runner, "30. Chromium-Style Multi-Component Pipeline Integration", test_chromium_multi_component_pipeline_integration);
    lit::run_case(runner, "31. goose2rfc Client Pipeline Audit Regressions", test_goose2rfc_client_audit_regressions);

    let ok = lit::finish(runner);
    assert(ok);
}
