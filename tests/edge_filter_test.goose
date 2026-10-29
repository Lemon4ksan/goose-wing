// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Test Suite for Goose-Wing Programmable L7 Edge Filter Engine.
import std;
import core from "..";
import wing from "..";

fn test_edge_filter_lifecycle_and_evaluation(t: core::T&) {
    t.run("Case 1: Edge Filter Rule Registration and Path Filtering") { sub =>
        var filter = wing::new_edge_filter();
        sub.assert_true(filter.enabled, "Filter enabled by default");
        sub.assert_eq(filter.rules.len, 0, "Initial rules empty");

        // Add rules:
        // 1. Block /admin without header
        let r_admin = wing::make_edge_filter_rule(
            "admin-protect",
            "/admin",
            wing::EdgeFilterVerdict.BlockForbidden,
        );
        sub.assert_true(wing::add_edge_filter_rule(filter, r_admin), "Admin rule added");

        // 2. Throttle /api/heavy
        let r_heavy = wing::make_edge_filter_rule(
            "heavy-throttle",
            "/api/heavy",
            wing::EdgeFilterVerdict.ThrottleRate,
        );
        sub.assert_true(wing::add_edge_filter_rule(filter, r_heavy), "Heavy throttle rule added");

        // Evaluate /public/index.html -> Pass
        var empty_headers: wing::HeaderItem[..4] = [];
        let v1 = wing::evaluate_edge_filter(filter, "GET", "/public/index.html", empty_headers[..]);
        sub.assert_true(v1 == wing::EdgeFilterVerdict.Pass, "Public path passes");

        // Evaluate /admin/users -> BlockForbidden (403)
        let v2 = wing::evaluate_edge_filter(filter, "POST", "/admin/users", empty_headers[..]);
        sub.assert_true(v2 == wing::EdgeFilterVerdict.BlockForbidden, "Admin path blocked");

        // Evaluate /api/heavy/compute -> ThrottleRate (429)
        let v3 = wing::evaluate_edge_filter(filter, "POST", "/api/heavy/compute", empty_headers[..]);
        sub.assert_true(v3 == wing::EdgeFilterVerdict.ThrottleRate, "Heavy path throttled");

        sub.assert_eq(filter.total_inspected as i64, 3, "Total inspected count");
        sub.assert_eq(filter.total_blocked as i64, 2, "Total blocked count");
    };

    t.run("Case 2: Required Header Condition") { sub =>
        var filter = wing::new_edge_filter();
        var rule = wing::make_edge_filter_rule("api-key-gate", "/v1/secure", wing::EdgeFilterVerdict.BlockForbidden);
        rule.required_header.append("X-API-Key");
        let _ = wing::add_edge_filter_rule(filter, rule);

        // Missing header -> Block
        var hdrs_missing: wing::HeaderItem[..4] = [];
        hdrs_missing.push(wing::make_header("Authorization", "Bearer tok", false));
        let v_deny = wing::evaluate_edge_filter(filter, "GET", "/v1/secure/data", hdrs_missing[..]);
        sub.assert_true(v_deny == wing::EdgeFilterVerdict.BlockForbidden, "Missing required header blocked");

        // Present header -> Pass
        var hdrs_ok: wing::HeaderItem[..4] = [];
        hdrs_ok.push(wing::make_header("X-API-Key", "secret-key-123", false));
        let v_allow = wing::evaluate_edge_filter(filter, "GET", "/v1/secure/data", hdrs_ok[..]);
        sub.assert_true(v_allow == wing::EdgeFilterVerdict.Pass, "Present required header allowed");
    };
}

fn main() {
    var runner = core::new_runner("Goose-Wing Edge Filter Test Suite", core::Verbosity.Verbose);
    core::run_case(runner, "test_edge_filter_lifecycle_and_evaluation", test_edge_filter_lifecycle_and_evaluation);
    let ok = core::finish(runner);
    assert(ok);
}
