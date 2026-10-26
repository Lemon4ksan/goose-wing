// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for RFC 7838 Alt-Svc upgrade and Chromium-style Speculative Protocol Racing.
// Verifies:
// 1. Zero-heap Alt-Svc header learning and origin caching.
// 2. Promotion of TCP (HTTP/1.1 / HTTP/2) connections to HTTP/3 (QUIC).
// 3. Speculative racing between Alternative Job (H3) and Main Job (TCP).
// 4. Firewall UDP drop simulation, seamless fallback to TCP without user error.
// 5. Chromium-identical exponential failure backoff (5s, 10s, 20s... 320s).
// 6. Fast-path TCP bypass during backoff window.
// 7. Success recovery and failure counter reset.
// 8. RFC 7838 `clear` directive cache purging.
// 9. RFC 7838 Section 2.1 security invariant: Alt-Svc ignored on unencrypted HTTP.
// 10. Max-age (TTL) expiration.
import std;
import core from "..";
import wing from "..";

fn test_altsvc_learning_and_h3_promotion(t: core::T&) {
    t.run("Cold Request Learns Alt-Svc and Next Request Upgrades to HTTP/3") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000); // t = 1700000000s

        // 1. Setup mock route returning Alt-Svc header
        wing::mock_route(client, "GET", "https://api.example.com/v1/user", 200, "{\"id\":1}");
        wing::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=86400; persist=1");

        // Before request: cache has no entry
        sub.assert_false(wing::has_altsvc_h3(client, "api.example.com:443"), "no prior Alt-Svc for api.example.com");

        // 2. Cold request: executed over standard TCP (HTTP/1.1)
        let resp1, err1 = wing::get(client, "https://api.example.com/v1/user");
        sub.assert_true(wing::ok(err1), "cold request succeeds");
        sub.assert_eq(wing::status(resp1), 200, "200 OK");
        sub.assert_eq(wing::protocol(resp1), "HTTP/1.1", "cold request served via HTTP/1.1");
        sub.assert_false(wing::is_http3(resp1), "not HTTP/3 yet");

        // 3. Verify Alt-Svc was ingested into client cache
        sub.assert_true(wing::has_altsvc_h3(client, "api.example.com:443"), "Alt-Svc cached for api.example.com:443");
        sub.assert_true(wing::has_altsvc_h3(client, "https://api.example.com/v1/user"), "URL origin lookup works");

        // 4. Second request: Alt-Svc candidate found -> upgraded to HTTP/3!
        let resp2, err2 = wing::get(client, "https://api.example.com/v1/user");
        sub.assert_true(wing::ok(err2), "second request succeeds");
        sub.assert_eq(wing::protocol(resp2), "h3", "second request upgraded to h3 via Alt-Svc!");
        sub.assert_true(wing::is_http3(resp2), "is_http3 helper returns true");
    };
}

fn test_chromium_protocol_racing_and_udp_fallback(t: core::T&) {
    t.run("UDP Firewall Block: TCP Wins Race, Zero Error, Backoff Recorded") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000); // t0 = 1700000000s (sec)

        // Seed Alt-Svc cache
        wing::mock_route(client, "GET", "https://fast.edge.net/data", 200, "{\"ready\":true}");
        wing::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=3600");

        let resp_seed, err_seed = wing::get(client, "https://fast.edge.net/data");
        sub.assert_true(wing::ok(err_seed), "seed request ok");
        sub.assert_true(wing::has_altsvc_h3(client, "fast.edge.net:443"), "Alt-Svc cached");

        // Now simulate corporate firewall blocking UDP/QUIC (e.g. timeout or packet drop)
        wing::set_mock_quic_blocked(client, true);

        // Request during UDP blockage: Protocol Race starts
        // Alternative Job (H3) times out / blocked -> Main Job (TCP) wins the race!
        let resp_blocked, err_blocked = wing::get(client, "https://fast.edge.net/data");
        sub.assert_true(wing::ok(err_blocked), "request succeeds without user error");
        sub.assert_eq(wing::status(resp_blocked), 200, "200 OK via TCP fallback");
        sub.assert_eq(wing::protocol(resp_blocked), "HTTP/1.1", "served via TCP Main Job");

        // Check Chromium failure penalization: origin is now marked broken!
        sub.assert_true(wing::is_altsvc_broken(client, "fast.edge.net:443"), "origin fast.edge.net marked broken");
        sub.assert_false(wing::has_altsvc_h3(client, "fast.edge.net:443"), "has_altsvc_h3 suppressed during backoff");

        // Request 1 second later (within 5s initial backoff window):
        wing::set_clock_us(client, 1700000001000000); // t0 + 1s
        let resp_cached_tcp, err_cached_tcp = wing::get(client, "https://fast.edge.net/data");
        sub.assert_true(wing::ok(err_cached_tcp), "fast-path TCP succeeds");
        sub.assert_eq(wing::protocol(resp_cached_tcp), "HTTP/1.1", "bypassed QUIC race without delay");

        // Advance virtual clock past 5s backoff window (t0 + 6s)
        wing::set_clock_us(client, 1700000006000000); // t0 + 6s
        sub.assert_false(wing::is_altsvc_broken(client, "fast.edge.net:443"), "backoff expired after 5s");
        sub.assert_true(wing::has_altsvc_h3(client, "fast.edge.net:443"), "H3 candidate available again");

        // Now firewall allows UDP again:
        wing::set_mock_quic_blocked(client, false);
        let resp_recovered, err_recovered = wing::get(client, "https://fast.edge.net/data");
        sub.assert_true(wing::ok(err_recovered), "recovered request ok");
        sub.assert_eq(wing::protocol(resp_recovered), "h3", "H3 race won after recovery!");
        sub.assert_false(wing::is_altsvc_broken(client, "fast.edge.net:443"), "broken status cleared on success");
    };

    t.run("Exponential Failure Backoff Progression (5s -> 10s)") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000); // t0

        wing::mock_route(client, "GET", "https://flaky.cdn.com/res", 200, "flaky");
        wing::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=86400");
        let _, _ = wing::get(client, "https://flaky.cdn.com/res");

        // Failure 1: backoff is 5s
        wing::set_mock_quic_blocked(client, true);
        let _, _ = wing::get(client, "https://flaky.cdn.com/res");
        sub.assert_true(wing::is_altsvc_broken(client, "flaky.cdn.com:443"), "broken attempt 1");

        // At t0 + 6s: backoff 1 has expired
        wing::set_clock_us(client, 1700000006000000);
        sub.assert_false(wing::is_altsvc_broken(client, "flaky.cdn.com:443"), "expired at t0+6s");

        // Failure 2: backoff doubles to 10s (broken until t0 + 6s + 10s = t0 + 16s)
        let _, _ = wing::get(client, "https://flaky.cdn.com/res");
        sub.assert_true(wing::is_altsvc_broken(client, "flaky.cdn.com:443"), "broken attempt 2");

        // At t0 + 12s: still broken (12 < 16)
        wing::set_clock_us(client, 1700000012000000);
        sub.assert_true(wing::is_altsvc_broken(client, "flaky.cdn.com:443"), "still broken at t0+12s");

        // At t0 + 17s: backoff 2 expired (17 >= 16)
        wing::set_clock_us(client, 1700000017000000);
        sub.assert_false(wing::is_altsvc_broken(client, "flaky.cdn.com:443"), "expired at t0+17s");
    };
}

fn test_altsvc_clear_and_ttl_expiration(t: core::T&) {
    t.run("Alt-Svc: clear Purges Origin from Cache Immediately") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000);

        wing::mock_route(client, "GET", "https://service.org/item", 200, "item");
        wing::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=86400");
        let _, _ = wing::get(client, "https://service.org/item");
        sub.assert_true(wing::has_altsvc_h3(client, "service.org:443"), "cached");

        // Server sends `Alt-Svc: clear` (RFC 7838 Section 3.1)
        wing::mock_route(client, "POST", "https://service.org/logout", 200, "bye");
        wing::add_mock_header(client, "Alt-Svc", "clear");
        let _, _ = wing::post(client, "https://service.org/logout") { _ => };

        sub.assert_false(wing::has_altsvc_h3(client, "service.org:443"), "origin purged after clear");

        // Subsequent request uses standard TCP
        let resp3, _ = wing::get(client, "https://service.org/item");
        sub.assert_eq(wing::protocol(resp3), "HTTP/1.1", "served via HTTP/1.1 after clear");
    };

    t.run("Max-Age (ma) Expiration") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000); // t0

        wing::mock_route(client, "GET", "https://short-lived.com/status", 200, "ok");
        wing::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=3"); // TTL = 3 seconds
        let _, _ = wing::get(client, "https://short-lived.com/status");
        sub.assert_true(wing::has_altsvc_h3(client, "short-lived.com:443"), "cached at t0");

        // Advance 2 seconds (still valid)
        wing::set_clock_us(client, 1700000002000000); // t0 + 2s
        sub.assert_true(wing::has_altsvc_h3(client, "short-lived.com:443"), "valid at t0+2s (< 3s)");

        // Advance 4 seconds (expired)
        wing::set_clock_us(client, 1700000004000000); // t0 + 4s
        sub.assert_false(wing::has_altsvc_h3(client, "short-lived.com:443"), "expired at t0+4s (>= 3s)");
    };
}

fn test_rfc7838_security_and_options(t: core::T&) {
    t.run("RFC 7838 Section 2.1: Alt-Svc MUST be Ignored on Insecure HTTP") { sub =>
        var client = wing::new_client();
        wing::set_clock_us(client, 1700000000000000);

        // Plain HTTP server attempts to send Alt-Svc
        wing::mock_route(client, "GET", "http://insecure.site/api", 200, "insecure");
        wing::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=86400");

        let resp, err = wing::get(client, "http://insecure.site/api");
        sub.assert_true(wing::ok(err), "http request ok");

        // MUST NOT be cached because transport was unencrypted HTTP!
        sub.assert_false(wing::has_altsvc_h3(client, "insecure.site:80"), "Alt-Svc ignored over insecure HTTP");
    };

    t.run("Manual Disabling of Alt-Svc or Protocol Racing") { sub =>
        var client = wing::new_client();
        wing::enable_altsvc(client, false); // Alt-Svc disabled

        wing::mock_route(client, "GET", "https://disabled.com/data", 200, "data");
        wing::add_mock_header(client, "Alt-Svc", "h3=\":443\"; ma=86400");

        let resp1, _ = wing::get(client, "https://disabled.com/data");
        sub.assert_false(wing::has_altsvc_h3(client, "disabled.com:443"), "not cached when disabled");

        let resp2, _ = wing::get(client, "https://disabled.com/data");
        sub.assert_eq(wing::protocol(resp2), "HTTP/1.1", "remains HTTP/1.1");
    };
}

fn main() {
    var runner = core::new_runner("RFC 7838 Alt-Svc & Chromium Protocol Racing Suite", core::Verbosity.Verbose);
    core::run_case(runner, "1. Alt-Svc Learning & HTTP/3 Promotion", test_altsvc_learning_and_h3_promotion);
    core::run_case(runner, "2. Protocol Racing & UDP Firewall Fallback", test_chromium_protocol_racing_and_udp_fallback);
    core::run_case(runner, "3. Alt-Svc Clear Directive & TTL Expiration", test_altsvc_clear_and_ttl_expiration);
    core::run_case(runner, "4. RFC 7838 Insecure Transport Security & Toggles", test_rfc7838_security_and_options);
    let ok = core::finish(runner);
    assert(ok);
}
