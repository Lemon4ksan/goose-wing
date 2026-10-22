// Verification Suite for ClientSession, WHATWG URL & Redirects
// Conforming to WHATWG URL, Mozilla PSL, RFC 9110, RFC 6265bis, and WHATWG Fetch §4.5.
import std;
import wing from "..";

// ----------------------------------------------------------------------------
// 1. WHATWG URL Parser, IPv6 RFC 5952 Compression, and Origin
// ----------------------------------------------------------------------------
fn test_url_parser_and_origin(t: wing::T&) {
    t.run("Absolute URL Normalization & Default Port Stripping") { sub =>
        // Default port 80 for HTTP is stripped from authority
        let url_http = wing::new_url("HTTP://Example.COM:80/path/to/resource?query=1#frag");
        sub.assert_true(url_http.valid, "valid HTTP url");
        sub.assert_bytes_eq(wing::scheme(url_http), "http", "scheme normalized to lowercase");
        sub.assert_bytes_eq(wing::host(url_http), "example.com", "host normalized to lowercase");
        sub.assert_eq(wing::effective_port(url_http), 80, "effective port is 80");
        sub.assert_bytes_eq(wing::port_str(url_http), "", "default port stripped from port string");
        sub.assert_bytes_eq(wing::pathname(url_http), "/path/to/resource", "pathname preserved");
        sub.assert_bytes_eq(wing::search(url_http), "?query=1", "search query parsed");
        sub.assert_bytes_eq(wing::hash(url_http), "#frag", "fragment parsed");
        sub.assert_true(wing::is_special(url_http), "http is a special scheme");

        // Non-default port 8080 for HTTP is preserved
        let url_custom_port = wing::new_url("https://secure.example.com:8443/api");
        sub.assert_true(url_custom_port.valid, "valid custom port url");
        sub.assert_bytes_eq(wing::scheme(url_custom_port), "https", "https scheme");
        sub.assert_bytes_eq(wing::hostname(url_custom_port), "secure.example.com", "hostname without port");
        sub.assert_bytes_eq(wing::host(url_custom_port), "secure.example.com:8443", "host includes port");
        sub.assert_eq(wing::effective_port(url_custom_port), 8443, "effective port 8443");
        sub.assert_bytes_eq(wing::port_str(url_custom_port), "8443", "port string is 8443");
        sub.assert_bytes_eq(wing::pathname(url_custom_port), "/api", "pathname is /api");
    };

    t.run("IPv6 Zero-Run Compression (RFC 5952)") { sub =>
        // Full 8-group IPv6 with zero runs compressed to ::
        let url_ipv6 = wing::new_url("http://[2001:0db8:0000:0000:0000:ff00:0042:8329]/");
        sub.assert_true(url_ipv6.valid, "valid IPv6 url");
        sub.assert_bytes_eq(wing::host(url_ipv6), "[2001:db8::ff00:42:8329]", "zero run compressed per RFC 5952");

        // Loopback IPv6 ::1
        let url_loopback = wing::new_url("http://[0000:0000:0000:0000:0000:0000:0000:0001]:8080/");
        sub.assert_true(url_loopback.valid, "valid loopback IPv6");
        sub.assert_bytes_eq(wing::hostname(url_loopback), "[::1]", "loopback hostname compressed to [::1]");
        sub.assert_bytes_eq(wing::host(url_loopback), "[::1]:8080", "host includes port 8080");
        sub.assert_eq(wing::effective_port(url_loopback), 8080, "port 8080 preserved");

        // IPv4-mapped IPv6 [::ffff:192.168.1.1]
        let url_mapped = wing::new_url("http://[::ffff:192.168.1.1]/");
        sub.assert_true(url_mapped.valid, "valid IPv4-mapped IPv6");
        sub.assert_bytes_eq(wing::host(url_mapped), "[::ffff:c0a8:101]", "IPv4-mapped hex normalized");
    };

    t.run("Dot-Segment Normalization & Relative Resolution") { sub =>
        // Path dot-segment collapsing
        let url_dots = wing::new_url("https://example.com/a/b/../c/./d");
        sub.assert_bytes_eq(wing::pathname(url_dots), "/a/c/d", "dot segments collapsed");

        // Relative resolution against base URL
        let base_url = wing::new_url("https://example.com/v1/auth/login.html");
        sub.assert_true(base_url.valid, "base url valid");

        // Relative path navigation ../dashboard
        let rel_url = wing::new_url("../dashboard", base_url);
        sub.assert_true(rel_url.valid, "relative url valid");
        sub.assert_bytes_eq(wing::href(rel_url), "https://example.com/v1/dashboard", "resolved ../ relative to base");

        // Root-relative path /logout
        let root_rel = wing::new_url("/logout", base_url);
        sub.assert_true(root_rel.valid, "root-relative url valid");
        sub.assert_bytes_eq(wing::href(root_rel), "https://example.com/logout", "resolved root-relative to base");
    };

    t.run("Origin Model: Tuple vs Opaque and Serialization") { sub =>
        let url1 = wing::new_url("https://example.com/path");
        let url2 = wing::new_url("https://example.com:443/other");
        let url3 = wing::new_url("http://example.com/path");
        let url4 = wing::new_url("https://example.com:8443/path");

        let orig1 = wing::origin_from_url(url1);
        let orig2 = wing::origin_from_url(url2);
        let orig3 = wing::origin_from_url(url3);
        let orig4 = wing::origin_from_url(url4);

        // Same origin: https://example.com == https://example.com:443
        sub.assert_true(wing::is_same_origin(orig1, orig2), "same origin matches");

        // Cross-origin: scheme mismatch (https vs http)
        sub.assert_false(wing::is_same_origin(orig1, orig3), "scheme mismatch is cross-origin");

        // Cross-origin: port mismatch (443 vs 8443)
        sub.assert_false(wing::is_same_origin(orig1, orig4), "port mismatch is cross-origin");

        // Origin serialization
        var orig_str: u8[..64] = [];
        wing::serialize_origin(orig1, orig_str);
        sub.assert_bytes_eq(orig_str[..], "https://example.com", "origin serialized without default port");

        // Opaque origin
        let opaque_a = wing::new_opaque_origin();
        let opaque_b = wing::new_opaque_origin();
        sub.assert_true(opaque_a.kind == wing::OriginKind.Opaque, "opaque kind");
        sub.assert_false(wing::is_same_origin(opaque_a, opaque_b), "two opaque origins never match");

        var opaque_str: u8[..32] = [];
        wing::serialize_origin(opaque_a, opaque_str);
        sub.assert_bytes_eq(opaque_str[..], "null", "opaque origin serializes to 'null'");
    };
}

// ----------------------------------------------------------------------------
// 2. Mozilla PSL Scoping & Tenant Isolation
// ----------------------------------------------------------------------------
fn test_psl_scoping_and_tenants(t: wing::T&) {
    t.run("PSL Rule Types: Normal, Wildcard, Exception") { sub =>
        // 1. Normal ICANN rule: co.uk
        var s_couk: u8[..64] = [];
        let icann_couk = wing::public_suffix_with_icann("service.co.uk", s_couk);
        sub.assert_true(icann_couk, "co.uk is in ICANN section");
        sub.assert_bytes_eq(s_couk[..], "co.uk", "suffix is co.uk");

        // 2. Wildcard rule: *.ck -> any label under ck is a public suffix
        var s_ck: u8[..64] = [];
        let icann_ck = wing::public_suffix_with_icann("foo.ck", s_ck);
        sub.assert_true(icann_ck, "*.ck is ICANN wildcard");
        sub.assert_bytes_eq(s_ck[..], "foo.ck", "foo.ck matched wildcard *.ck");

        // 3. Exception rule: !www.ck -> suffix is 'ck', so www.ck is registrable domain
        var s_ex: u8[..64] = [];
        let icann_ex = wing::public_suffix_with_icann("www.ck", s_ex);
        sub.assert_true(icann_ex, "!www.ck exception rule");
        sub.assert_bytes_eq(s_ex[..], "ck", "exception rule stripped leftmost label to ck");

        var etld_ex: u8[..64] = [];
        wing::extract_etld_plus_one("www.ck", etld_ex);
        sub.assert_bytes_eq(etld_ex[..], "www.ck", "www.ck is eTLD+1 due to exception rule");
    };

    t.run("Private Suffix Section & Strict Tenant Isolation") { sub =>
        // github.io is a Private section suffix
        var s_gh: u8[..64] = [];
        let icann_gh = wing::public_suffix_with_icann("alice.github.io", s_gh);
        sub.assert_false(icann_gh, "github.io belongs to Private section (not ICANN)");
        sub.assert_bytes_eq(s_gh[..], "github.io", "suffix is github.io");

        // Tenant isolation: alice.github.io must have eTLD+1 alice.github.io
        var etld_alice: u8[..64] = [];
        wing::extract_etld_plus_one("alice.github.io", etld_alice);
        sub.assert_bytes_eq(etld_alice[..], "alice.github.io", "alice.github.io is isolated tenant");

        // Bob's tenant: bob.github.io must have eTLD+1 bob.github.io
        var etld_bob: u8[..64] = [];
        wing::extract_etld_plus_one("bob.github.io", etld_bob);
        sub.assert_bytes_eq(etld_bob[..], "bob.github.io", "bob.github.io is isolated tenant");

        // Deep subdomains inside tenant: project.alice.github.io -> eTLD+1 is alice.github.io
        var etld_proj: u8[..64] = [];
        wing::extract_etld_plus_one("project.alice.github.io", etld_proj);
        sub.assert_bytes_eq(etld_proj[..], "alice.github.io", "subdomain bound to tenant eTLD+1");
    };

    t.run("RegistrableSite Construction from URL") { sub =>
        let url_app = wing::new_url("https://sub.portal.example.com/dashboard");
        let reg_site = wing::registrable_site_from_url(url_app);
        sub.assert_bytes_eq(reg_site.scheme[..], "https", "scheme is https");
        sub.assert_bytes_eq(reg_site.registrable_domain[..], "example.com", "registrable domain is example.com");
    };
}

// ----------------------------------------------------------------------------
// 3. SiteForCookies & RFC 6265bis Schemeful Same-Site Context
// ----------------------------------------------------------------------------
fn test_site_for_cookies_and_rfc6265bis(t: wing::T&) {
    t.run("SiteForCookies Creation & NetLog Formatting") { sub =>
        let sfc = wing::site_for_cookies_from_url("https://login.example.com/");
        sub.assert_false(sfc.is_null, "not null SFC");
        sub.assert_true(sfc.schemefully_same, "schemefully same");
        sub.assert_bytes_eq(sfc.scheme[..], "https", "scheme is https");
        sub.assert_bytes_eq(sfc.registrable_domain[..], "example.com", "registrable domain is example.com");

        var netlog: u8[..128] = [];
        wing::format_site_for_cookies(netlog, sfc);
        sub.assert_contains(netlog[..], "https://example.com", "netlog contains site");
        sub.assert_contains(netlog[..], "schemefully_same=true", "netlog indicates schemefully same");

        let null_sfc = wing::null_site_for_cookies();
        sub.assert_true(null_sfc.is_null, "null SFC");
        var null_netlog: u8[..128] = [];
        wing::format_site_for_cookies(null_netlog, null_sfc);
        sub.assert_contains(null_netlog[..], "null; schemefully_same=false", "null SFC formats properly");
    };

    t.run("Schemeful First-Party Evaluation") { sub =>
        let sfc = wing::site_for_cookies_from_url("https://example.com/");

        // Same site, same scheme -> First-party
        sub.assert_true(
            wing::is_first_party(sfc, "https://sub.example.com/api", true),
            "https://sub.example.com is first-party to https://example.com"
        );

        // Same registrable domain, DIFFERENT scheme -> NOT first-party under schemeful same-site!
        sub.assert_false(
            wing::is_first_party(sfc, "http://example.com/api", true),
            "http://example.com is NOT first-party to https://example.com (Schemeful Same-Site)"
        );

        // Different domain -> Cross-site
        sub.assert_false(
            wing::is_first_party(sfc, "https://attacker.com/api", true),
            "attacker.com is cross-site"
        );
    };

    t.run("Ancestor Frame Hierarchy Traversal & Context Degradation") { sub =>
        var sfc = wing::site_for_cookies_from_url("https://bank.com/account");

        // Subframe on same site: preserves first-party context
        wing::compare_with_frame_tree_site_and_revise(sfc, "https://sub.bank.com/iframe");
        sub.assert_false(sfc.is_null, "remains first-party with same-site subframe");

        // Nested subframe from cross-site third party: degrades SFC to null!
        wing::compare_with_frame_tree_site_and_revise(sfc, "https://tracker.net/widget");
        sub.assert_true(sfc.is_null, "degrades to null when ancestor chain contains cross-site frame");

        // Once null, further comparisons cannot restore it
        wing::compare_with_frame_tree_site_and_revise(sfc, "https://bank.com/account");
        sub.assert_true(sfc.is_null, "stays null once tainted");
    };
}

// ----------------------------------------------------------------------------
// 4. Redirect State Machine: Methods, Headers & Sensitive Sanitization
// ----------------------------------------------------------------------------
fn test_redirect_state_machine(t: wing::T&) {
    t.run("HTTP 301, 302, 303 Method Mutation & Payload Stripping") { sub =>
        // 301 Moved Permanently: POST -> GET
        let info_301 = wing::compute_redirect_info(
            "POST", 301, "https://example.com/old", "https://example.com/new",
            wing::ReferrerPolicy.NoReferrerWhenDowngrade, "https://example.com/old",
            false, false
        );
        sub.assert_bytes_eq(info_301.new_method[..], "GET", "301 mutates POST to GET");
        sub.assert_true(info_301.clear_body, "body cleared on 301 POST->GET");

        // 302 Found: POST -> GET
        let info_302 = wing::compute_redirect_info(
            "POST", 302, "https://example.com/login", "https://example.com/dashboard",
            wing::ReferrerPolicy.NoReferrerWhenDowngrade, "https://example.com/login",
            false, false
        );
        sub.assert_bytes_eq(info_302.new_method[..], "GET", "302 mutates POST to GET");
        sub.assert_true(info_302.clear_body, "body cleared on 302 POST->GET");

        // 303 See Other: PUT -> GET
        let info_303 = wing::compute_redirect_info(
            "PUT", 303, "https://example.com/item", "https://example.com/items",
            wing::ReferrerPolicy.NoReferrerWhenDowngrade, "https://example.com/item",
            false, false
        );
        sub.assert_bytes_eq(info_303.new_method[..], "GET", "303 mutates PUT to GET");
        sub.assert_true(info_303.clear_body, "body cleared on 303 PUT->GET");
    };

    t.run("HTTP 307 & 308 Method and Body Preservation") { sub =>
        // 307 Temporary Redirect: POST remains POST
        let info_307 = wing::compute_redirect_info(
            "POST", 307, "https://example.com/upload", "https://s3.example.com/upload",
            wing::ReferrerPolicy.NoReferrerWhenDowngrade, "https://example.com/upload",
            false, false
        );
        sub.assert_bytes_eq(info_307.new_method[..], "POST", "307 preserves POST");
        sub.assert_false(info_307.clear_body, "307 preserves request body");

        // 308 Permanent Redirect: DELETE remains DELETE
        let info_308 = wing::compute_redirect_info(
            "DELETE", 308, "https://example.com/res/1", "https://api.example.com/res/1",
            wing::ReferrerPolicy.NoReferrerWhenDowngrade, "https://example.com/res/1",
            false, false
        );
        sub.assert_bytes_eq(info_308.new_method[..], "DELETE", "308 preserves DELETE");
        sub.assert_false(info_308.clear_body, "308 preserves request body");
    };

    t.run("Cross-Origin Sensitive Header Sanitization (CVE Mitigations)") { sub =>
        var req = wing::new_post("https://api.example.com/v1/auth");
        wing::header(req, "Authorization", "Bearer secret_jwt_token_123");
        wing::header(req, "X-API-Key", "api-key-99999");
        wing::header(req, "X-Auth-Token", "auth-token-xyz");
        wing::header(req, "Cookie", "session=active; tracking=1");
        wing::header(req, "Accept", "application/json");

        let redirect_info = wing::compute_redirect_info(
            "POST", 302, "https://api.example.com/v1/auth", "https://attacker.org/leak",
            wing::ReferrerPolicy.NoReferrerWhenDowngrade, "https://api.example.com/v1/auth",
            false, false
        );
        sub.assert_true(redirect_info.is_cross_origin, "detected cross-origin redirect");

        // Perform cross-origin sanitization
        wing::sanitize_headers_on_redirect(req.headers, redirect_info, false, false, true, false);

        // Sensitive headers MUST be purged on cross-origin hop!
        var has_auth = false;
        var has_apikey = false;
        var has_authtok = false;
        var has_cookie = false;
        var has_accept = false;

        for hdr in req.headers {
            if wing::eq_ascii_fold(hdr.name[..], "Authorization") { has_auth = true; }
            if wing::eq_ascii_fold(hdr.name[..], "X-API-Key") { has_apikey = true; }
            if wing::eq_ascii_fold(hdr.name[..], "X-Auth-Token") { has_authtok = true; }
            if wing::eq_ascii_fold(hdr.name[..], "Cookie") { has_cookie = true; }
            if wing::eq_ascii_fold(hdr.name[..], "Accept") { has_accept = true; }
        }

        sub.assert_false(has_auth, "Authorization stripped on cross-origin redirect");
        sub.assert_false(has_apikey, "X-API-Key stripped (CVE-2026-55553, CVE-2026-64684)");
        sub.assert_false(has_authtok, "X-Auth-Token stripped");
        sub.assert_false(has_cookie, "Cookie stripped on redirect hop (CVE-2023-45143)");
        sub.assert_true(has_accept, "Innocuous Accept header preserved");
    };

    t.run("Scheme Downgrade Stripping (CVE-2024-1968)") { sub =>
        var req = wing::new_get("https://example.com/secure");
        wing::header(req, "Authorization", "Basic YWxhZGRpbjpvcGVuc2VzYW1l");
        wing::header(req, "Custom-Key", "val");

        let redirect_info = wing::compute_redirect_info(
            "GET", 302, "https://example.com/secure", "http://example.com/insecure",
            wing::ReferrerPolicy.NoReferrerWhenDowngrade, "https://example.com/secure",
            false, false
        );
        sub.assert_true(redirect_info.is_scheme_downgrade, "detected scheme downgrade");

        // Same host, but scheme downgraded from HTTPS to HTTP
        wing::sanitize_headers_on_redirect(req.headers, redirect_info, false, false, true, false);

        var has_auth = false;
        for hdr in req.headers {
            if wing::eq_ascii_fold(hdr.name[..], "Authorization") { has_auth = true; }
        }
        sub.assert_false(has_auth, "Authorization stripped on HTTPS -> HTTP downgrade (CVE-2024-1968)");
    };

    t.run("Same-Origin Redirect Preserves Sensitive Credentials") { sub =>
        var req = wing::new_get("https://example.com/old_endpoint");
        wing::header(req, "Authorization", "Bearer keep_me_safe");
        wing::header(req, "X-API-Key", "my_api_key");

        let redirect_info = wing::compute_redirect_info(
            "GET", 302, "https://example.com/old_endpoint", "https://example.com/new_endpoint",
            wing::ReferrerPolicy.NoReferrerWhenDowngrade, "https://example.com/old_endpoint",
            false, false
        );
        sub.assert_false(redirect_info.is_cross_origin, "same origin redirect");
        sub.assert_false(redirect_info.is_scheme_downgrade, "no scheme downgrade");

        wing::sanitize_headers_on_redirect(req.headers, redirect_info, false, false, true, false);

        var has_auth = false;
        var has_key = false;
        for hdr in req.headers {
            if wing::eq_ascii_fold(hdr.name[..], "Authorization") { has_auth = true; }
            if wing::eq_ascii_fold(hdr.name[..], "X-API-Key") { has_key = true; }
        }
        sub.assert_true(has_auth, "Authorization preserved on same-origin redirect");
        sub.assert_true(has_key, "X-API-Key preserved on same-origin redirect");
    };
}

// ----------------------------------------------------------------------------
// 5. ClientSession 6-Phase Pipeline & CanonicalCookieJar Integration
// ----------------------------------------------------------------------------
fn test_clientsession_pipeline_and_cookies(t: wing::T&) {
    t.run("OAuth 2.0 Flow: 302 Set-Cookie Ingestion & Chain Hop Isolation") { sub =>
        var session = wing::new_session();
        wing::set_clock_us(session, 1700000000000000);

        // Step 1: GET https://auth.idp.com/login -> 302 to https://app.client.com/callback
        // Server sends Set-Cookie: auth_session=secret_token; Domain=auth.idp.com; Secure; HttpOnly
        wing::mock_route(session, "GET", "https://auth.idp.com/login", 302, "");
        wing::add_mock_header(session, "Location", "https://app.client.com/callback?code=oauth_code_123");
        wing::add_mock_set_cookie(session, "auth_session=secret_token; Domain=auth.idp.com; Secure; HttpOnly; SameSite=Lax");

        // Step 2: GET https://app.client.com/callback?code=oauth_code_123 -> 200 OK
        wing::mock_route(session, "GET", "https://app.client.com/callback?code=oauth_code_123", 200, "{\"status\":\"authenticated\"}");
        wing::add_mock_set_cookie(session, "app_user=alice; Path=/; Secure; SameSite=Lax");

        // Execute request to initial login page
        var req = wing::new_get("https://auth.idp.com/login");
        let res, err = wing::execute_request(session, req);

        sub.assert_true(wing::ok(err), "request succeeded");
        sub.assert_eq(res.status_code, 200, "final status is 200 OK after redirect");
        sub.assert_eq(res.redirect_count, 1, "exactly 1 redirect hop");
        sub.assert_bytes_eq(res.final_method[..], "GET", "final method is GET");
        sub.assert_eq(res.url_chain.len, 2, "URL chain has 2 hops");
        sub.assert_bytes_eq(res.url_chain[0][..], "https://auth.idp.com/login", "initial URL in chain");
        sub.assert_bytes_eq(res.url_chain[1][..], "https://app.client.com/callback?code=oauth_code_123", "target URL in chain");

        // Verify Cookie Jar state: both cookies ingested with correct domain scoping
        sub.assert_eq(session.jar.cookies.len, 2, "both cookies ingested into jar");
        let auth_cookie = wing::get(session.jar, "https://auth.idp.com/", "auth_session", 1700000000000000);
        sub.assert_bytes_eq(auth_cookie, "secret_token", "auth_session cookie found under idp.com");

        let app_cookie = wing::get(session.jar, "https://app.client.com/callback", "app_user", 1700000000000000);
        sub.assert_bytes_eq(app_cookie, "alice", "app_user cookie found under client.com");

        // Cross-domain cookie isolation: client.com does NOT receive idp.com cookie!
        let leaked = wing::get(session.jar, "https://app.client.com/", "auth_session", 1700000000000000);
        sub.assert_bytes_eq(leaked, "", "client.com did NOT receive idp.com auth_session cookie");
    };

    t.run("Redirect Loop Detection (TooManyRedirects)") { sub =>
        var session = wing::new_session();
        wing::set_max_redirects(session, 2);

        // Infinite redirect loop: a -> b -> a
        wing::mock_route(session, "GET", "https://example.com/loop_a", 302, "");
        wing::add_mock_header(session, "Location", "https://example.com/loop_b");

        wing::mock_route(session, "GET", "https://example.com/loop_b", 302, "");
        wing::add_mock_header(session, "Location", "https://example.com/loop_a");

        var req = wing::new_get("https://example.com/loop_a");
        let res, err = wing::execute_request(session, req);

        sub.assert_false(wing::ok(err), "loop must produce error");
        sub.assert_bytes_eq(err.stage[..], "redirect", "redirect loop fails execution");
    };

    t.run("RedirectMode.Manual Returns 3xx Without Following") { sub =>
        var session = wing::new_session();
        wing::set_redirect_mode(session, wing::RedirectMode.Manual);

        wing::mock_route(session, "GET", "https://example.com/manual_src", 302, "redirect body");
        wing::add_mock_header(session, "Location", "https://example.com/manual_dst");

        var req = wing::new_get("https://example.com/manual_src");
        let res, err = wing::execute_request(session, req);

        sub.assert_true(wing::ok(err), "request ok");
        sub.assert_eq(res.status_code, 302, "manual redirect stops and returns 302");
        sub.assert_eq(res.redirect_count, 0, "zero redirects followed");
        sub.assert_bytes_eq(wing::header(res, "Location"), "https://example.com/manual_dst", "Location header accessible");
    };
}

// ----------------------------------------------------------------------------
// 6. BodyRewind, SSRF Guard, and DNS Rebinding Defense
// ----------------------------------------------------------------------------
fn test_body_rewind_and_ssrf_guard(t: wing::T&) {
    t.run("BodyRewind on 307 Temporary Redirect") { sub =>
        var session = wing::new_session();

        // 307 redirect preserving POST body
        wing::mock_route(session, "POST", "https://api.example.com/v1/items", 307, "");
        wing::add_mock_header(session, "Location", "https://api.example.com/v2/items");

        wing::mock_route(session, "POST", "https://api.example.com/v2/items", 201, "{\"created\":true}");

        var req = wing::new_post("https://api.example.com/v1/items");
        wing::text(req, "{\"name\":\"widget\"}"); // Rewindable buffered body

        let res, err = wing::execute_request(session, req);
        sub.assert_true(wing::ok(err), "buffered body rewind succeeded on 307");
        sub.assert_eq(res.status_code, 201, "destination reached with preserved body");
        sub.assert_bytes_eq(res.final_method[..], "POST", "POST preserved on 307");
    };

    t.run("Unrewindable Body Stream Returns Error on 307/308") { sub =>
        var session = wing::new_session();

        wing::mock_route(session, "POST", "https://api.example.com/stream_src", 307, "");
        wing::add_mock_header(session, "Location", "https://api.example.com/stream_dst");

        var req = wing::new_post("https://api.example.com/stream_src");
        wing::set_stream_body(req, "streamed_chunked_data", false); // Unrewindable stream

        let res, err = wing::execute_request(session, req);
        sub.assert_false(wing::ok(err), "unrewindable stream must fail redirect");
        sub.assert_bytes_eq(err.stage[..], "body_rewind", "stream error flagged");
    };

    t.run("3-Tier SSRF Guard: Loopback, RFC 1918 Private, Cloud Metadata") { sub =>
        var session = wing::new_session();
        wing::enable_ssrf_guard(session, true);

        // 1. Loopback IPv4 (127.0.0.1)
        var req_loop = wing::new_get("http://127.0.0.1/admin");
        let res_loop, err_loop = wing::execute_request(session, req_loop);
        sub.assert_false(wing::ok(err_loop), "127.0.0.1 blocked by SSRF guard");

        // 2. Loopback IPv6 ([::1])
        var req_loop6 = wing::new_get("http://[::1]/internal");
        let res_loop6, err_loop6 = wing::execute_request(session, req_loop6);
        sub.assert_false(wing::ok(err_loop6), "[::1] blocked by SSRF guard");

        // 3. RFC 1918 10.0.0.0/8
        var req_priv10 = wing::new_get("http://10.20.30.40/metrics");
        let res_priv10, err_priv10 = wing::execute_request(session, req_priv10);
        sub.assert_false(wing::ok(err_priv10), "10.x.x.x blocked by SSRF guard");

        // 4. RFC 1918 192.168.0.0/16
        var req_priv192 = wing::new_get("http://192.168.1.1/router");
        let res_priv192, err_priv192 = wing::execute_request(session, req_priv192);
        sub.assert_false(wing::ok(err_priv192), "192.168.x.x blocked by SSRF guard");

        // 5. Cloud Metadata service (169.254.169.254)
        var req_meta = wing::new_get("http://169.254.169.254/latest/meta-data/");
        let res_meta, err_meta = wing::execute_request(session, req_meta);
        sub.assert_false(wing::ok(err_meta), "169.254.169.254 cloud metadata blocked by SSRF guard");
    };

    t.run("DNS Rebinding Defense via Resolved IP Sweep") { sub =>
        var session = wing::new_session();
        wing::enable_ssrf_guard(session, true);

        // Host has harmless public name 'rebound.attacker.com', but DNS resolution
        // returns private internal IP 192.168.0.100 (DNS Rebinding attack)
        wing::mock_route(session, "GET", "http://rebound.attacker.com/steal", 200, "pwned");
        wing::add_mock_resolved_ip(session, "192.168.0.100");

        var req = wing::new_get("http://rebound.attacker.com/steal");
        let res, err = wing::execute_request(session, req);

        sub.assert_false(wing::ok(err), "DNS Rebinding blocked when resolved IP is in private subnet");
    };

    t.run("Dangerous Service Port Blocking (SSH, Redis, etc.)") { sub =>
        var session = wing::new_session();
        wing::enable_ssrf_guard(session, true);

        // Port 22 (SSH)
        var req_ssh = wing::new_get("http://example.com:22/");
        let res_ssh, err_ssh = wing::execute_request(session, req_ssh);
        sub.assert_false(wing::ok(err_ssh), "port 22 blocked by SSRF guard");

        // Port 6379 (Redis)
        var req_redis = wing::new_get("http://example.com:6379/");
        let res_redis, err_redis = wing::execute_request(session, req_redis);
        sub.assert_false(wing::ok(err_redis), "port 6379 blocked by SSRF guard");
    };
}

// ----------------------------------------------------------------------------
// Suite Entry Point
// ----------------------------------------------------------------------------
fn main() {
    var runner = wing::new_runner("Client Session, URL & Redirect Verification Suite", wing::Verbosity.Verbose);

    wing::run_case(runner, "1. WHATWG URL Parser, IPv6 RFC 5952 Compression & Origin", test_url_parser_and_origin);
    wing::run_case(runner, "2. Mozilla PSL Scoping & Tenant Isolation", test_psl_scoping_and_tenants);
    wing::run_case(runner, "3. SiteForCookies & RFC 6265bis Schemeful Same-Site", test_site_for_cookies_and_rfc6265bis);
    wing::run_case(runner, "4. Redirect State Machine: Methods, Headers & Sensitive Sanitization", test_redirect_state_machine);
    wing::run_case(runner, "5. ClientSession 6-Phase Pipeline & CanonicalCookieJar Integration", test_clientsession_pipeline_and_cookies);
    wing::run_case(runner, "6. BodyRewind, SSRF Guard & DNS Rebinding Defense", test_body_rewind_and_ssrf_guard);

    let ok = wing::finish(runner);
    assert(ok);
}
