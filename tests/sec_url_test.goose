// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Tests for URL and query string parsing edge cases.
import std;
import core from "..";
import wing from "..";

fn test_semicolon_query_splitting_defense(t: core::T&) {
    t.run("QUERY-01: Semicolon is treated as literal content, NOT parameter separator (CVE-2021-31525)") { sub =>
        // In naive implementations, before 1.17, "a=1;b=2" was split into two parameters a=1 and b=2.
        // Under WHATWG URL, only '&' is a delimiter; ';' is literal data.
        let raw = "?a=1;b=2";
        let q = core::parse_query_params(raw);
        sub.assert_eq(q.items.len, 1, "Query string with semicolon must NOT be split into multiple parameters");
        sub.assert_bytes_eq(core::get_query_param(q, "a"), "1;b=2", "Value of 'a' must be '1;b=2' verbatim");
        sub.assert_false(core::has_query_param(q, "b"), "Parameter 'b' must NOT exist (no parameter splitting on semicolon)");
    };

    t.run("QUERY-02: Canonical ampersand '&' parameter splitting") { sub =>
        let raw = "?foo=bar&baz=qux&num=42";
        let q = core::parse_query_params(raw);
        sub.assert_eq(q.items.len, 3);
        sub.assert_bytes_eq(core::get_query_param(q, "foo"), "bar");
        sub.assert_bytes_eq(core::get_query_param(q, "baz"), "qux");
        sub.assert_bytes_eq(core::get_query_param(q, "num"), "42");
    };

    t.run("QUERY-03: Percent-decoding and '+' space normalization in query keys and values") { sub =>
        let raw = "?search=hello+world%21&user%5Fid=alice%40example.com";
        let q = core::parse_query_params(raw);
        sub.assert_eq(q.items.len, 2);
        sub.assert_bytes_eq(core::get_query_param(q, "search"), "hello world!", "+ decoded to space and %21 to !");
        sub.assert_bytes_eq(core::get_query_param(q, "user_id"), "alice@example.com", "%5F decoded to _ and %40 to @");
    };

    t.run("QUERY-04: Empty parameters and flag-only parameters") { sub =>
        let raw = "?active&filter=&category=tech";
        let q = core::parse_query_params(raw);
        sub.assert_eq(q.items.len, 3);
        sub.assert_true(core::has_query_param(q, "active"));
        sub.assert_bytes_eq(core::get_query_param(q, "active"), "", "Flag-only parameter has empty value");
        sub.assert_true(core::has_query_param(q, "filter"));
        sub.assert_bytes_eq(core::get_query_param(q, "filter"), "", "Empty value parameter has empty value");
        sub.assert_bytes_eq(core::get_query_param(q, "category"), "tech");
    };
}

fn test_ipv6_host_security_bypasses(t: core::T&) {
    t.run("IPV6-01: Bracketed IPv6 not at start of host rejection (CVE-2026-25679)") { sub =>
        // Host with prefix before bracket: bad[::1]
        let u1 = core::new_url("http://bad[::1]/");
        sub.assert_false(u1.valid, "Host with prefix before [ must be rejected");

        // Host with suffix after bracket: [::1]bad
        let u2 = core::new_url("http://[::1]bad/");
        sub.assert_false(u2.valid, "Host with suffix after ] must be rejected");

        // Host with domain and bracket: evil.com[::1]
        let u3 = core::new_url("http://evil.com[::1]/");
        sub.assert_false(u3.valid, "evil.com[::1] must be rejected");
    };

    t.run("IPV6-02: Insufficient validation of bracketed IPv6 hostnames (CVE-2025-47912)") { sub =>
        // Missing closing bracket
        let u1 = core::new_url("http://[::1/path");
        sub.assert_false(u1.valid, "Unclosed [ must be rejected");

        // Empty bracket
        let u2 = core::new_url("http://[]/");
        sub.assert_false(u2.valid, "Empty [] host must be rejected");

        // Triple colons in IPv6
        let u3 = core::new_url("http://[:::1]/");
        sub.assert_false(u3.valid, "Triple colon [:::1] must be rejected");

        // Invalid hex characters in IPv6
        let u4 = core::new_url("http://[2001:db8::zzzz]/");
        sub.assert_false(u4.valid, "Non-hex characters in IPv6 must be rejected");
    };
}

fn test_port_number_boundaries_and_overflow(t: core::T&) {
    t.run("PORT-01: Port > 65535 rejection ") { sub =>
        // Boundary: 65536
        let u1 = core::new_url("http://example.com:65536/");
        sub.assert_false(u1.valid, "Port 65536 must be rejected as invalid port");

        // 70000
        let u2 = core::new_url("http://example.com:70000/");
        sub.assert_false(u2.valid, "Port 70000 must be rejected");

        // 999999
        let u3 = core::new_url("http://example.com:999999/");
        sub.assert_false(u3.valid, "Port 999999 must be rejected");

        // Max valid port 65535
        let u4 = core::new_url("http://example.com:65535/");
        sub.assert_true(u4.valid, "Port 65535 must be accepted");
        sub.assert_eq(core::effective_port(u4), 65535);
    };

    t.run("PORT-02: Non-numeric and malformed port rejection ") { sub =>
        // Non-numeric port
        let u1 = core::new_url("http://example.com:foo/");
        sub.assert_false(u1.valid, "Non-numeric port :foo must be rejected");

        // Alphanumeric port
        let u2 = core::new_url("http://example.com:80a/");
        sub.assert_false(u2.valid, "Alphanumeric port :80a must be rejected");

        // Multiple colons in non-IPv6 host
        let u3 = core::new_url("http://example.com:80:90/");
        sub.assert_false(u3.valid, "Multiple colons in host authority must be rejected");
    };
}

fn test_path_traversal_and_userinfo(t: core::T&) {
    t.run("TRAV-01: Mixed percent-encoded dot segments sanitization ") { sub =>
        // .%2e ("..")
        let u1 = core::new_url("https://example.com/api/.%2e/admin");
        sub.assert_true(u1.valid);
        sub.assert_bytes_eq(core::pathname(u1), "/admin", ".%2e collapsed as ..");

        // %2e. ("..")
        let u2 = core::new_url("https://example.com/api/%2e./admin");
        sub.assert_true(u2.valid);
        sub.assert_bytes_eq(core::pathname(u2), "/admin", "%2e. collapsed as ..");

        // %2e%2e ("..")
        let u3 = core::new_url("https://example.com/api/%2e%2e/admin");
        sub.assert_true(u3.valid);
        sub.assert_bytes_eq(core::pathname(u3), "/admin", "%2e%2e collapsed as ..");
    };

    t.run("USER-01: Userinfo credentials with special characters ") { sub =>
        // User with @ escaped in username
        let u1 = core::new_url("https://alice%40example.com:secret@api.service.com/");
        sub.assert_true(u1.valid);
        sub.assert_bytes_eq(core::username(u1), "alice%40example.com");
        sub.assert_bytes_eq(core::password(u1), "secret");
        sub.assert_bytes_eq(core::host(u1), "api.service.com", "Host correctly isolated from userinfo @");

        // Raw @ in password properly escaped to %40
        let u2 = core::new_url("https://bob:p@ss@service.com/");
        sub.assert_true(u2.valid);
        sub.assert_bytes_eq(core::username(u2), "bob");
        sub.assert_bytes_eq(core::host(u2), "service.com");
    };
}

fn main() {
    var runner = core::new_runner("URL & Query Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. Semicolon Query Splitting Defense (CVE-2021-31525)", test_semicolon_query_splitting_defense);
    core::run_case(runner, "2. IPv6 Host Security Bypasses (CVE-2026-25679 & CVE-2025-47912)", test_ipv6_host_security_bypasses);
    core::run_case(runner, "3. Port Number Boundaries & Overflow Defense ", test_port_number_boundaries_and_overflow);
    core::run_case(runner, "4. Path Traversal & Userinfo Isolation ", test_path_traversal_and_userinfo);

    let ok = core::finish(runner);
    assert(ok);
}
