// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Security tests for cookie prefixes, SSRF filter bypasses, and port validation.
import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. RFC 6265bis Section 5.6: __Host- & __Secure- Cookie Prefix Enforcement
// ----------------------------------------------------------------------------
fn test_host_and_secure_cookie_prefix_smuggling(t: core::T&) {
    var clock = core::new_mock_clock();

    t.run("HOST-01: __Host- cookie with Domain=127.0.0.1 literal must be rejected") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        // RFC 6265bis Section 5.6.2: Must not include a Domain attribute
        let ok = wing::set_cookie_header(jar, "https://127.0.0.1/", "__Host-auth=secret123; Domain=127.0.0.1; Secure; Path=/", clock.now_us);
        sub.assert_false(ok, "__Host- with Domain=127.0.0.1 must be rejected per RFC 6265bis");
        sub.assert_eq(jar.cookies.len, 0, "Jar must not store __Host- cookie with Domain attribute");
    };

    t.run("HOST-02: __Host- cookie with Domain=localhost must be rejected") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let ok = wing::set_cookie_header(jar, "https://localhost/", "__Host-token=secret456; Domain=localhost; Secure; Path=/", clock.now_us);
        sub.assert_false(ok, "__Host- with Domain=localhost must be rejected per RFC 6265bis");
        sub.assert_eq(jar.cookies.len, 0, "Jar must not store __Host- cookie with Domain attribute on localhost");
    };

    t.run("HOST-03: __Host- cookie with empty or dot Domain attribute must be rejected") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let ok1 = wing::set_cookie_header(jar, "https://example.com/", "__Host-sess=val; Domain=; Secure; Path=/", clock.now_us);
        sub.assert_false(ok1, "__Host- with empty Domain= attribute must be rejected");

        let ok2 = wing::set_cookie_header(jar, "https://example.com/", "__Host-sess=val; Domain=.; Secure; Path=/", clock.now_us);
        sub.assert_false(ok2, "__Host- with Domain=. attribute must be rejected");

        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("HOST-04: Direct parse_canonical_set_cookie must reject __Host- with Domain attribute") { sub =>
        let cookie, cause, ok = wing::parse_canonical_set_cookie(
            "__Host-key=secret; Domain=example.com; Secure; Path=/",
            "example.com",
            "/",
            clock.now_us
        );
        sub.assert_false(ok, "parse_canonical_set_cookie must return false for __Host- with Domain attribute");
    };

    t.run("HOST-05: __Host- cookie with non-root path must be rejected") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let ok = wing::set_cookie_header(jar, "https://example.com/api/", "__Host-tok=val; Path=/api; Secure", clock.now_us);
        sub.assert_false(ok, "__Host- cookie with Path=/api must be rejected (must be Path=/)");
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("HOST-06: __Host- cookie over plain HTTP must be rejected") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let ok = wing::set_cookie_header(jar, "http://example.com/", "__Host-tok=val; Secure; Path=/", clock.now_us);
        sub.assert_false(ok, "__Host- cookie over http:// must be rejected (requires secure channel)");
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("HOST-07: __Host- cookie without Secure attribute must be rejected") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let ok = wing::set_cookie_header(jar, "https://example.com/", "__Host-tok=val; Path=/", clock.now_us);
        sub.assert_false(ok, "__Host- cookie without Secure attribute must be rejected");
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("HOST-08: Valid __Host- cookie on HTTPS with Path=/ is stored and retrieved") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let ok = wing::set_cookie_header(jar, "https://example.com/", "__Host-auth=valid_secret; Secure; Path=/", clock.now_us);
        sub.assert_true(ok, "Valid __Host- cookie must be accepted");
        sub.assert_eq(jar.cookies.len, 1);
        sub.assert_eq(jar.get("__Host-auth"), "valid_secret");
    };

    t.run("SECURE-01: __Secure- cookie without Secure attribute must be rejected") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let ok = wing::set_cookie_header(jar, "https://example.com/", "__Secure-id=12345; Path=/", clock.now_us);
        sub.assert_false(ok, "__Secure- cookie without Secure attribute must be rejected");
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("SECURE-02: __Secure- cookie over plain HTTP must be rejected") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let ok = wing::set_cookie_header(jar, "http://example.com/", "__Secure-id=12345; Secure; Path=/", clock.now_us);
        sub.assert_false(ok, "__Secure- cookie over plain http:// must be rejected");
        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("SECURE-03: Valid __Secure- cookie with Domain and sub-path on HTTPS is accepted") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let ok = wing::set_cookie_header(jar, "https://sub.example.com/api/", "__Secure-id=ok123; Secure; Domain=example.com; Path=/api", clock.now_us);
        sub.assert_true(ok, "__Secure- cookie with Domain and sub-path must be accepted on HTTPS");
        sub.assert_eq(jar.cookies.len, 1);
    };

    t.run("SECURE-04: Case-folded prefixes (__HOST- and __secure-) are strictly enforced") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let ok1 = wing::set_cookie_header(jar, "https://example.com/", "__HOST-key=val; Domain=example.com; Secure; Path=/", clock.now_us);
        sub.assert_false(ok1, "Case-folded __HOST- with Domain must be rejected");

        let ok2 = wing::set_cookie_header(jar, "https://example.com/", "__secure-tok=val; Path=/", clock.now_us);
        sub.assert_false(ok2, "Case-folded __secure- without Secure attribute must be rejected");
    };

    t.run("SECURE-05: Cookie Crumbles / Nameless cookie prefix injection rejected") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        let ok = wing::set_cookie_header(jar, "https://example.com/", "=__Host-sess=stolen; Secure; Path=/", clock.now_us);
        sub.assert_false(ok, "Nameless cookie containing __Host- prefix in value must be rejected (SHAD-01)");
    };

    t.run("SECURE-06: Non-secure HTTP cannot overwrite an existing secure __Secure- cookie") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        // 1. Secure set over HTTPS
        let ok1 = wing::set_cookie_header(jar, "https://example.com/", "__Secure-token=legit; Secure; Path=/", clock.now_us);
        sub.assert_true(ok1);

        // 2. Insecure attempt to overwrite over plain HTTP
        let ok2 = wing::set_cookie_header(jar, "http://example.com/", "__Secure-token=malicious; Path=/", clock.now_us + 1000);
        sub.assert_false(ok2, "Insecure HTTP request must not overwrite secure cookie");
        sub.assert_eq(jar.get("__Secure-token"), "legit", "Original secure value must be preserved");
    };
}

// ----------------------------------------------------------------------------
// 2. SSRF Filter Bypasses & IPv6 Zone ID / Scope ID Proxy Smuggling
// ----------------------------------------------------------------------------
fn test_ssrf_filter_bypasses(t: core::T&) {
    t.run("SSRF-01: NAT64 prefix to 0.0.0.0 (64:ff9b:: and 64:ff9b::0.0.0.0) must be blocked") { sub =>
        sub.assert_true(wing::is_private_or_reserved_ip("64:ff9b::"), "NAT64 empty suffix (0.0.0.0) must be reserved");
        sub.assert_true(wing::is_private_or_reserved_ip("64:ff9b::0.0.0.0"), "NAT64 0.0.0.0 must be reserved");
        sub.assert_true(wing::is_private_or_reserved_ip("[64:ff9b::]"), "NAT64 bracketed empty suffix must be reserved");
    };

    t.run("SSRF-02: IPv6 Multicast (ff00::/8) must be blocked") { sub =>
        sub.assert_true(wing::is_private_or_reserved_ip("ff02::1"), "IPv6 all-nodes multicast must be reserved");
        sub.assert_true(wing::is_private_or_reserved_ip("ff01::1"), "IPv6 node-local multicast must be reserved");
        sub.assert_true(wing::is_private_or_reserved_ip("[ff05::2]"), "IPv6 site-local multicast must be reserved");
    };

    t.run("SSRF-03: IPv6 Site-Local (fec0::/10) must be blocked") { sub =>
        sub.assert_true(wing::is_private_or_reserved_ip("fec0::1"), "IPv6 site-local fec0::1 must be reserved");
        sub.assert_true(wing::is_private_or_reserved_ip("[feff::ffff]"), "IPv6 site-local feff::ffff must be reserved");
    };

    t.run("SSRF-04: Trailing-dot IP literal (127.0.0.1. and 0.0.0.0.) must be blocked") { sub =>
        sub.assert_true(wing::is_private_or_reserved_ip("127.0.0.1."), "127.0.0.1. with trailing dot must be blocked");
        sub.assert_true(wing::is_private_or_reserved_ip("0.0.0.0."), "0.0.0.0. with trailing dot must be blocked");
        sub.assert_true(wing::is_private_or_reserved_ip("10.0.0.1."), "10.0.0.1. with trailing dot must be blocked");
    };

    t.run("SSRF-05: IPv6 Zone ID / Scope ID Proxy Smuggling & SSRF Bypass (CVE-2025-22870)") { sub =>
        // In CVE-2025-22870, [::1%25.example.com]:80 bypassed proxy filters because .example.com was treated as host
        // Goose recognizes stripped base ::1 and fe80::1 as reserved/loopback/link-local:
        sub.assert_true(wing::is_private_or_reserved_ip("[::1%25.example.com]"), "Bracketed ::1 with %25 zone ID must be blocked");
        sub.assert_true(wing::is_private_or_reserved_ip("::1%25.example.com"), "Bare ::1 with %25 zone ID must be blocked");
        sub.assert_true(wing::is_private_or_reserved_ip("::1%eth0"), "Bare ::1 with %eth0 interface scope must be blocked");
        sub.assert_true(wing::is_private_or_reserved_ip("::1%lo"), "Bare ::1 with %lo interface scope must be blocked");
        sub.assert_true(wing::is_private_or_reserved_ip("[fe80::1%25eth0]"), "Link-local with %25 scope must be blocked");
        sub.assert_true(wing::is_private_or_reserved_ip("fe80::1%eth0"), "Link-local with interface scope must be blocked");
        sub.assert_true(wing::is_private_or_reserved_ip("ff02::1%eth0"), "Multicast with interface scope must be blocked");

        // Public IPs with scope ID should not be misclassified as private:
        sub.assert_false(wing::is_private_or_reserved_ip("2606:4700:4700::1111%eth0"), "Public IPv6 with scope must not be blocked as private");
    };

    t.run("SSRF-06: WHATWG URL parser invalidates bracketed IPv6 with zone ID, immune by design") { sub =>
        let u1 = core::new_url("http://[::1%25.example.com]:80/api");
        sub.assert_false(u1.valid, "URL parser must invalidate [::1%25.example.com]");

        let u2 = core::new_url("http://[::1%eth0]:80/api");
        sub.assert_false(u2.valid, "URL parser must invalidate [::1%eth0]");
    };
}

// ----------------------------------------------------------------------------
// 3. Dangerous Service Ports & Port 0 SSRF Bypass
// ----------------------------------------------------------------------------
fn test_dangerous_service_ports(t: core::T&) {
    t.run("PORT-01: Dangerous service ports (Port 0, FTP 21, Telnet 23, MySQL 3306, Postgres 5432, MongoDB 27017)") { sub =>
        sub.assert_true(wing::is_dangerous_service_port(0), "Port 0 must be dangerous");
        sub.assert_true(wing::is_dangerous_service_port(21), "Port 21 (FTP) must be dangerous");
        sub.assert_true(wing::is_dangerous_service_port(23), "Port 23 (Telnet) must be dangerous");
        sub.assert_true(wing::is_dangerous_service_port(3306), "Port 3306 (MySQL) must be dangerous");
        sub.assert_true(wing::is_dangerous_service_port(5432), "Port 5432 (PostgreSQL) must be dangerous");
        sub.assert_true(wing::is_dangerous_service_port(27017), "Port 27017 (MongoDB) must be dangerous");
    };

    t.run("PORT-02: validate_url_against_ssrf blocks Port 0 and Dangerous Ports") { sub =>
        var policy = wing::SsrfGuardPolicy { enabled: true, .. };

        // Port 0 request
        let u_p0 = core::new_url("http://example.com:0/api");
        let err_p0 = wing::validate_url_against_ssrf(u_p0, policy);
        sub.assert_ne(err_p0, wing::RedirectError.None, "Port 0 URL must be blocked by SSRF guard");

        // Port 3306 request
        let u_mysql = core::new_url("http://example.com:3306/db");
        let err_mysql = wing::validate_url_against_ssrf(u_mysql, policy);
        sub.assert_ne(err_mysql, wing::RedirectError.None, "Port 3306 URL must be blocked by SSRF guard");

        // Trailing-dot loopback URL request
        let u_dot = core::new_url("http://127.0.0.1./admin");
        let err_dot = wing::validate_url_against_ssrf(u_dot, policy);
        sub.assert_ne(err_dot, wing::RedirectError.None, "http://127.0.0.1./ with trailing dot must be blocked by SSRF guard");
    };

    t.run("PORT-03: validate_url_against_ssrf blocks Redis (6379), Memcached (11211), and Docker (2375)") { sub =>
        var policy = wing::SsrfGuardPolicy { enabled: true, .. };

        let u_redis = core::new_url("http://example.com:6379/");
        let err_redis = wing::validate_url_against_ssrf(u_redis, policy);
        sub.assert_ne(err_redis, wing::RedirectError.None, "Redis 6379 must be blocked");

        let u_mem = core::new_url("http://example.com:11211/");
        let err_mem = wing::validate_url_against_ssrf(u_mem, policy);
        sub.assert_ne(err_mem, wing::RedirectError.None, "Memcached 11211 must be blocked");

        let u_doc = core::new_url("http://example.com:2375/");
        let err_doc = wing::validate_url_against_ssrf(u_doc, policy);
        sub.assert_ne(err_doc, wing::RedirectError.None, "Docker daemon 2375 must be blocked");
    };
}

// ----------------------------------------------------------------------------
// 4. Public Suffix Boundary Attacks & FQDN Edge Cases
// ----------------------------------------------------------------------------
fn test_public_suffix_boundary_attacks(t: core::T&) {
    var clock = core::new_mock_clock();

    t.run("PSL-01: Supercookie prevention on ICANN public suffixes") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        // example.com cannot set cookie for .com
        let ok1 = wing::set_cookie_header(jar, "https://example.com/", "super=bad; Domain=com; Secure; Path=/", clock.now_us);
        sub.assert_false(ok1, "Setting Domain=com must be rejected");

        // attacker.co.uk cannot set cookie for .co.uk
        let ok2 = wing::set_cookie_header(jar, "https://attacker.co.uk/", "super=bad; Domain=co.uk; Secure; Path=/", clock.now_us);
        sub.assert_false(ok2, "Setting Domain=co.uk must be rejected");

        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("PSL-02: Private PSL section boundary protection") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        // tenant.github.io cannot set cookie for .github.io
        let ok1 = wing::set_cookie_header(jar, "https://tenant.github.io/", "cross=bad; Domain=github.io; Secure; Path=/", clock.now_us);
        sub.assert_false(ok1, "Setting Domain=github.io must be rejected");

        // sub.amazonaws.com cannot set cookie for .amazonaws.com
        let ok2 = wing::set_cookie_header(jar, "https://sub.amazonaws.com/", "cross=bad; Domain=amazonaws.com; Secure; Path=/", clock.now_us);
        sub.assert_false(ok2, "Setting Domain=amazonaws.com must be rejected");

        sub.assert_eq(jar.cookies.len, 0);
    };

    t.run("PSL-03: Mozilla PSL Wildcards & Exception rules (!city.kobe.jp)") { sub =>
        var jar = wing::new_canonical_cookie_jar();
        // !city.kobe.jp is an exception rule: city.kobe.jp is NOT a public suffix!
        let ok_kobe = wing::set_cookie_header(jar, "https://sub.city.kobe.jp/", "area=kobe; Domain=city.kobe.jp; Secure; Path=/", clock.now_us);
        sub.assert_true(ok_kobe, "Domain=city.kobe.jp must be accepted due to !city.kobe.jp exception");

        // other.kobe.jp is under *.kobe.jp wildcard: it IS a public suffix!
        let ok_other = wing::set_cookie_header(jar, "https://sub.other.kobe.jp/", "area=bad; Domain=other.kobe.jp; Secure; Path=/", clock.now_us);
        sub.assert_false(ok_other, "Domain=other.kobe.jp must be rejected under *.kobe.jp wildcard");
    };

    t.run("PSL-04: FQDN Trailing-dot normalization (industry benchmark)") { sub =>
        var etld1: u8[..128] = [];
        core::extract_etld_plus_one("example.com.", etld1);
        sub.assert_eq(etld1[..], "example.com", "example.com. with trailing dot must derive example.com");

        var etld2: u8[..128] = [];
        core::extract_etld_plus_one("sub.example.com.", etld2);
        sub.assert_eq(etld2[..], "example.com", "sub.example.com. must derive example.com");

        let matches = wing::cookie_domain_match("sub.example.com.", ".example.com.");
        sub.assert_true(matches, "cookie_domain_match must handle trailing dot FQDN");
    };

    t.run("PSL-05: IP address literal immunity (industry benchmark)") { sub =>
        var etld_ip: u8[..128] = [];
        core::extract_etld_plus_one("127.0.0.1", etld_ip);
        sub.assert_eq(etld_ip[..], "127.0.0.1", "IP literal must not be parsed through PSL");

        // RFC 6265 Section 5.1.3: domain matching MUST NOT match suffixes on IP addresses
        let match_ip = wing::cookie_domain_match("192.168.1.1", "168.1.1");
        sub.assert_false(match_ip, "IP address must never match sub-domain suffixes");
    };

    t.run("PSL-06: Case insensitivity in PSL evaluations (industry benchmark)") { sub =>
        var etld_upper: u8[..128] = [];
        core::extract_etld_plus_one("FOO.EXAMPLE.COM", etld_upper);
        sub.assert_eq(etld_upper[..], "example.com", "Uppercase FOO.EXAMPLE.COM must derive lowercase example.com");

        sub.assert_true(wing::is_public_suffix_domain("CO.UK"), "CO.UK must be recognized as public suffix");
        sub.assert_true(wing::is_public_suffix_domain("Com"), "Com must be recognized as public suffix");
    };
}

// ----------------------------------------------------------------------------
// 5. Token Bucket & GCRA Burst / Concurrency Limits
// ----------------------------------------------------------------------------
fn test_rate_limiter_burst_and_concurrency(t: core::T&) {
    t.run("RATE-01: Burst capacity boundary (1/s emission, burst=5 allows 6 requests)") { sub =>
        let quota = wing::new_gcra_quota(1, core::seconds(1), 5); // T=1s, tau=5s
        var cell = wing::GcraCell { tat_ns: 0 };
        let now_ns: u64 = 10000000000; // t=10s

        // 6 back-to-back requests (1 initial + 5 burst)
        for i in 6 {
            let dec = wing::gcra_check_n(quota, cell, 1, now_ns);
            sub.assert_true(wing::is_allowed(dec), "Request within burst capacity must be allowed");
        }

        // 7th request must be rejected
        let dec7 = wing::gcra_check_n(quota, cell, 1, now_ns);
        sub.assert_false(wing::is_allowed(dec7), "7th request exceeding burst capacity must be rejected");

        match dec7 {
            Rejected r => {
                sub.assert_true(r.retry_after_ns > 0, "Rejected decision must report positive retry_after");
            },
            _ => { sub.assert_true(false, "Expected Rejected decision"); },
        };
    };

    t.run("RATE-02: Cost > burst pitfall ") { sub =>
        let quota = wing::new_gcra_quota(1, core::seconds(1), 5);
        var cell = wing::GcraCell { tat_ns: 0 };
        let now_ns: u64 = 10000000000;

        // Requesting 10 cells when burst=5 is impossible and rejected immediately
        let dec = wing::gcra_check_n(quota, cell, 10, now_ns);
        sub.assert_false(wing::is_allowed(dec), "Cost exceeding burst capacity must be rejected");
        sub.assert_eq(cell.tat_ns, 0, "TAT cell must remain unmutated on rejection");
    };

    t.run("RATE-03: Integer overflow saturation defense") { sub =>
        let quota = wing::new_gcra_quota(1, core::seconds(1), 5);
        var cell = wing::GcraCell { tat_ns: 0 };
        let now_ns: u64 = 10000000000;

        // Passing huge cost_n (0xFFFFFFFFFFFFFFFF) must saturate and reject without wrap-around
        let dec = wing::gcra_check_n(quota, cell, 0xFFFFFFFFFFFFFFFF, now_ns);
        sub.assert_false(wing::is_allowed(dec), "Saturated huge cost must be rejected");
    };

    t.run("RATE-04: Zero-cost inspection does not advance TAT") { sub =>
        let quota = wing::new_gcra_quota(1, core::seconds(1), 5);
        var cell = wing::GcraCell { tat_ns: 10000000000 };
        let now_ns: u64 = 10000000000;

        let dec = wing::gcra_check_n(quota, cell, 0, now_ns);
        sub.assert_true(wing::is_allowed(dec), "Zero-cost inspection is allowed");
        sub.assert_eq(cell.tat_ns, 10000000000, "Zero-cost check must not advance TAT");
    };

    t.run("RATE-05: Priority slot reservation (gcra_reserve_n)") { sub =>
        let quota = wing::new_gcra_quota(1, core::seconds(1), 0); // 1 req/sec, no burst
        var cell = wing::GcraCell { tat_ns: 0 };
        let now_ns: u64 = 10000000000;

        // 1st request succeeds
        let dec1 = wing::gcra_reserve_n(quota, cell, 1, now_ns, 2000000000);
        sub.assert_true(wing::is_allowed(dec1));

        // 2nd request arrives immediately: can reserve within max_wait_ns (2s)
        let dec2 = wing::gcra_reserve_n(quota, cell, 1, now_ns, 2000000000);
        sub.assert_true(wing::is_allowed(dec2), "Slot must be reserved within max_wait");
        match dec2 {
            Reserved r => {
                sub.assert_eq(r.wait_ns, 1000000000, "Wait time is exactly 1 emission interval (1s)");
            },
            _ => { sub.assert_true(false, "Expected Reserved decision"); },
        };
    };

    t.run("RATE-06: 256-shard rate limiter protects distinct client keys") { sub =>
        let quota = wing::new_gcra_quota(1, core::seconds(1), 1);
        var limiter = wing::new_sharded_limiter(quota);
        let now_ns: u64 = 5000000000;

        let dec_ip1 = wing::check_rate_limit(limiter, "192.168.1.100", 1, now_ns);
        sub.assert_true(wing::is_allowed(dec_ip1));

        let dec_ip2 = wing::check_rate_limit(limiter, "10.0.0.50", 1, now_ns);
        sub.assert_true(wing::is_allowed(dec_ip2), "Distinct client key must have independent rate quota");
    };

    t.run("RATE-07: Probabilistic GCRA DDoS mitigation under flood") { sub =>
        let quota = wing::new_gcra_quota(1000, core::seconds(1), 100);
        var pgcra = wing::new_probabilistic_gcra(quota, 20); // 5% sample rate

        var allowed_count = 0;
        let now_ns: u64 = 1000000000;
        for i in 100 {
            let dec = wing::check_rate_limit(pgcra, 1, now_ns);
            if wing::is_allowed(dec) {
                allowed_count++;
            }
        }
        sub.assert_true(allowed_count > 50, "Probabilistic filter allows majority of requests under normal sampling");
    };
}

// ----------------------------------------------------------------------------
// 6. Singleflight Thundering Herd & Cache Stampede Defense
// ----------------------------------------------------------------------------
fn test_singleflight_thundering_herd(t: core::T&) {
    t.run("FLIGHT-01: Duplicate call suppression (10 concurrent requests, exactly 1 leader)") { sub =>
        var g = core::new_singleflight_group();
        let key = "cache:user:profile:42";

        var leader_count = 0;
        var follower_count = 0;

        // 10 callers concurrently request the same key
        for caller_id in 10 {
            let is_lead, val, shared = core::start_or_join(g, key);
            if is_lead {
                leader_count++;
            } else {
                follower_count++;
            }
        }

        sub.assert_eq(leader_count, 1, "Exactly ONE caller must be designated as leader");
        sub.assert_eq(follower_count, 9, "9 callers must join as followers (duplicate suppression)");
        sub.assert_eq(core::waiter_count(g, key), 9, "Waiter count must be 9");
        sub.assert_true(core::is_in_flight(g, key), "Key must be marked in-flight");
    };

    t.run("FLIGHT-02: Result broadcast and shared flag accuracy ") { sub =>
        var g = core::new_singleflight_group();
        let key = "db:query:orders";

        // Leader starts
        let is_lead1, _, _ = core::start_or_join(g, key);
        sub.assert_true(is_lead1);

        // Follower 1 joins
        let is_lead2, _, _ = core::start_or_join(g, key);
        sub.assert_false(is_lead2);

        // Leader finishes computation with result 8888
        let finish_ok, waiters = core::finish_call(g, key, 8888, true);
        sub.assert_true(finish_ok);
        sub.assert_eq(waiters, 1);

        // Verify shared status and result value
        sub.assert_true(core::is_shared(g, key), "Result was shared between leader and follower");
        let cached_val, ok = core::result_value(g, key);
        sub.assert_true(ok);
        sub.assert_eq(cached_val, 8888);
    };

    t.run("FLIGHT-03: Unshared execution (single caller)") { sub =>
        var g = core::new_singleflight_group();
        let key = "db:query:rare_item";

        let is_lead, _, _ = core::start_or_join(g, key);
        sub.assert_true(is_lead);

        let finish_ok, waiters = core::finish_call(g, key, 42, true);
        sub.assert_true(finish_ok);
        sub.assert_eq(waiters, 0, "No waiters joined");
        sub.assert_false(core::is_shared(g, key), "Single caller execution must not be marked shared");
    };

    t.run("FLIGHT-04: Explicit Forget & re-execution ") { sub =>
        var g = core::new_singleflight_group();
        let key = "cache:stock:price";

        // Initial run
        core::start_or_join(g, key);
        core::finish_call(g, key, 100, true);

        // Forget key
        let forgot = core::forget(g, key);
        sub.assert_true(forgot, "forget must successfully remove the key");

        // Subsequent call must execute as new leader
        let is_lead_next, _, _ = core::start_or_join(g, key);
        sub.assert_true(is_lead_next, "After forget, next call must be a new leader");
    };

    t.run("FLIGHT-05: ForgetUnshared proposal ") { sub =>
        var g = core::new_singleflight_group();

        // 1. Shared key
        core::start_or_join(g, "key_shared");
        core::start_or_join(g, "key_shared"); // waiter joined
        core::finish_call(g, "key_shared", 1, true);

        // forget_unshared must NOT forget a shared key
        let forgot_shared = core::forget_unshared(g, "key_shared");
        sub.assert_false(forgot_shared, "forget_unshared must not remove shared key");

        // 2. Unshared key
        core::start_or_join(g, "key_unshared");
        core::finish_call(g, "key_unshared", 2, true);

        // forget_unshared MUST forget unshared key
        let forgot_unshared = core::forget_unshared(g, "key_unshared");
        sub.assert_true(forgot_unshared, "forget_unshared must remove unshared key");
    };

    t.run("FLIGHT-06: Error / Failure unblocking ") { sub =>
        var g = core::new_singleflight_group();
        let key = "db:broken_query";

        // Leader starts
        let is_lead, _, _ = core::start_or_join(g, key);
        sub.assert_true(is_lead);

        // Follower joins
        let is_lead2, _, _ = core::start_or_join(g, key);
        sub.assert_false(is_lead2);

        // Leader fails
        let finish_ok, waiters = core::finish_call(g, key, 0, false);
        sub.assert_true(finish_ok);
        sub.assert_eq(waiters, 1);

        let res, ok = core::result_value(g, key);
        sub.assert_false(ok, "Result value must record failure status without deadlocking");
        sub.assert_false(core::is_in_flight(g, key), "Key must not remain in-flight after failure");
    };
}

// ----------------------------------------------------------------------------
// Suite Entry Point
// ----------------------------------------------------------------------------
fn main() {
    var runner = core::new_runner("Perimeter Security Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. RFC 6265bis Section 5.6 (__Host- & __Secure- Prefix Invariants)", test_host_and_secure_cookie_prefix_smuggling);
    core::run_case(runner, "2. SSRF Filter Bypasses & IPv6 Zone ID Proxy Smuggling (CVE-2025-22870)", test_ssrf_filter_bypasses);
    core::run_case(runner, "3. Dangerous Service Ports & Port 0 SSRF Bypass", test_dangerous_service_ports);
    core::run_case(runner, "4. Public Suffix Boundary Attacks & FQDN Edge Cases (Go PSL Bugs)", test_public_suffix_boundary_attacks);
    core::run_case(runner, "5. Token Bucket & GCRA Burst / Concurrency Limits (Go Rate Limiter Bugs)", test_rate_limiter_burst_and_concurrency);
    core::run_case(runner, "6. Singleflight Thundering Herd & Cache Stampede Defense (Go Singleflight Bugs)", test_singleflight_thundering_herd);

    let ok = core::finish(runner);
    assert(ok);
}
