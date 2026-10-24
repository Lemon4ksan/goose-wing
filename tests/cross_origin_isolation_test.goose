// Verification suite for W3C Cross-Origin Isolation (COOP, COEP, CORP):
// - Header parsing for Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, Cross-Origin-Resource-Policy
// - W3C HTML5 §7.2 crossOriginIsolated state computation
// - Subresource embedding permission enforcement under require-corp sandbox
import std;
import core from "..";
import wing from "..";

fn test_cross_origin_isolation(t: core::T&) {
    t.run("Policy Header Parsing") { sub =>
        sub.assert_true(wing::parse_coop("same-origin") == wing::CoopPolicy.SameOrigin, "COOP same-origin");
        sub.assert_true(wing::parse_coop("same-origin-allow-popups") == wing::CoopPolicy.SameOriginAllowPopups, "COOP allow-popups");
        sub.assert_true(wing::parse_coop("unsafe-none") == wing::CoopPolicy.UnsafeNone, "COOP unsafe-none");

        sub.assert_true(wing::parse_coep("require-corp") == wing::CoepPolicy.RequireCorp, "COEP require-corp");
        sub.assert_true(wing::parse_coep("credentialless") == wing::CoepPolicy.Credentialless, "COEP credentialless");

        sub.assert_true(wing::parse_corp("cross-origin") == wing::CorpPolicy.CrossOrigin, "CORP cross-origin");
        sub.assert_true(wing::parse_corp("same-origin") == wing::CorpPolicy.SameOrigin, "CORP same-origin");
        sub.assert_true(wing::parse_corp("same-site") == wing::CorpPolicy.SameSite, "CORP same-site");
    };

    t.run("crossOriginIsolated Status Computation (W3C HTML §7.2)") { sub =>
        var ctx = wing::CrossOriginIsolationContext { .. };

        // 1. Both COOP same-origin and COEP require-corp -> ISOLATED
        wing::update_isolation_context(ctx, "same-origin", "require-corp", "https://app.secure.com");
        sub.assert_true(ctx.is_cross_origin_isolated, "Context is crossOriginIsolated");
        sub.assert_bytes_eq(ctx.document_origin[..], "https://app.secure.com", "Origin stored");

        // 2. COOP same-origin and COEP credentialless -> ISOLATED
        wing::update_isolation_context(ctx, "same-origin", "credentialless", "https://app.secure.com");
        sub.assert_true(ctx.is_cross_origin_isolated, "Credentialless also grants crossOriginIsolated");

        // 3. COOP missing or unsafe-none -> NOT isolated
        wing::update_isolation_context(ctx, "unsafe-none", "require-corp", "https://app.secure.com");
        sub.assert_false(ctx.is_cross_origin_isolated, "Not isolated without COOP same-origin");

        // 4. COEP missing or unsafe-none -> NOT isolated
        wing::update_isolation_context(ctx, "same-origin", "unsafe-none", "https://app.secure.com");
        sub.assert_false(ctx.is_cross_origin_isolated, "Not isolated without COEP");
    };

    t.run("Subresource Loading Policy Enforcement") { sub =>
        var isolated_ctx = wing::CrossOriginIsolationContext { .. };
        wing::update_isolation_context(isolated_ctx, "same-origin", "require-corp", "https://main.app.com");

        // Same-origin subresource: always allowed
        sub.assert_true(
            wing::is_subresource_allowed(isolated_ctx, "https://main.app.com", ""),
            "Same-origin resource always allowed"
        );

        // Cross-origin with CORP: cross-origin: allowed
        sub.assert_true(
            wing::is_subresource_allowed(isolated_ctx, "https://cdn.other.com", "cross-origin"),
            "Cross-origin subresource with CORP: cross-origin allowed"
        );

        // Cross-origin with missing CORP: BLOCKED by require-corp
        sub.assert_false(
            wing::is_subresource_allowed(isolated_ctx, "https://cdn.other.com", ""),
            "Cross-origin subresource without CORP BLOCKED by require-corp"
        );

        // Cross-origin with CORP: same-origin: BLOCKED
        sub.assert_false(
            wing::is_subresource_allowed(isolated_ctx, "https://cdn.other.com", "same-origin"),
            "Cross-origin subresource declaring same-origin BLOCKED"
        );
    };
}

fn main() {
    var runner = core::new_runner("W3C Cross-Origin Isolation Suite (COOP/COEP/CORP)", core::Verbosity.Verbose);
    core::run_case(runner, "1. Cross-Origin Isolation & Subresource Policies", test_cross_origin_isolation);
    let ok = core::finish(runner);
    assert(ok);
}
