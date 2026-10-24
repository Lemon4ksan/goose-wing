// Tests for Fetch Metadata resource isolation and CORS policy validation.
import std;
import core from "..";
import wing from "..";

// ----------------------------------------------------------------------------
// 1. W3C Fetch Metadata 9-Row Decision Matrix
// ----------------------------------------------------------------------------
fn test_fetch_metadata_decision_matrix(t: core::T&) {
    t.run("Row 1: Direct User Navigation (Sec-Fetch-Site: none)") { sub =>
        let guard_cfg = wing::new_cross_origin_guard();
        var ctx = wing::FetchContext {
            site: wing::SecFetchSite.None,
            mode: wing::SecFetchMode.Navigate,
            dest: wing::SecFetchDest.Document,
            method_is_safe: true,
            ..
        };
        let decision = wing::evaluate_fetch_metadata(guard_cfg, ctx);
        let ok = match decision {
            Allow => true,
            _ => false,
        };
        sub.assert_true(ok, "direct navigation allowed");
    };

    t.run("Row 2: Same-Origin SOP Requests") { sub =>
        let guard_cfg = wing::new_cross_origin_guard();
        var ctx = wing::FetchContext {
            site: wing::SecFetchSite.SameOrigin,
            mode: wing::SecFetchMode.Cors,
            dest: wing::SecFetchDest.Empty,
            method_is_safe: false, // POST/PUT mutation
            ..
        };
        let decision = wing::evaluate_fetch_metadata(guard_cfg, ctx);
        let ok = match decision {
            Allow => true,
            _ => false,
        };
        sub.assert_true(ok, "same-origin mutations allowed under SOP");
    };

    t.run("Row 3: Same-Site Subdomain Policy") { sub =>
        var guard_cfg = wing::new_cross_origin_guard();
        guard_cfg.allow_same_site = false;

        // Safe method GET across subdomains
        var ctx_safe = wing::FetchContext {
            site: wing::SecFetchSite.SameSite,
            method_is_safe: true,
            ..
        };
        let dec_safe = wing::evaluate_fetch_metadata(guard_cfg, ctx_safe);
        let ok_safe = match dec_safe {
            Allow => true,
            _ => false,
        };
        sub.assert_true(ok_safe, "same-site safe reads allowed");

        // Unsafe method POST across subdomains without allow_same_site
        var ctx_unsafe = wing::FetchContext {
            site: wing::SecFetchSite.SameSite,
            method_is_safe: false,
            ..
        };
        let dec_unsafe = wing::evaluate_fetch_metadata(guard_cfg, ctx_unsafe);
        let ok_reject = match dec_unsafe {
            RejectForbidden r => r.reason == wing::CsrfRejectReason.DisallowedSameSiteSubdomain,
            _ => false,
        };
        sub.assert_true(ok_reject, "same-site mutations rejected when allow_same_site=false");

        // When allow_same_site = true
        guard_cfg.allow_same_site = true;
        let dec_allowed = wing::evaluate_fetch_metadata(guard_cfg, ctx_unsafe);
        let ok_allowed = match dec_allowed {
            Allow => true,
            _ => false,
        };
        sub.assert_true(ok_allowed, "same-site mutations allowed when allow_same_site=true");
    };

    t.run("Row 4: Cross-Site State Mutation (POST/PUT/DELETE) Blocked") { sub =>
        let guard_cfg = wing::new_cross_origin_guard();
        var ctx = wing::FetchContext {
            site: wing::SecFetchSite.CrossSite,
            mode: wing::SecFetchMode.Cors,
            dest: wing::SecFetchDest.Empty,
            method_is_safe: false,
            ..
        };
        let dec = wing::evaluate_fetch_metadata(guard_cfg, ctx);
        let ok = match dec {
            RejectForbidden r => r.reason == wing::CsrfRejectReason.CrossSiteStateMutation,
            _ => false,
        };
        sub.assert_true(ok, "cross-site mutation rejected with CrossSiteStateMutation");
    };

    t.run("Row 5: Top-Level Cross-Site Navigation & First-Login CSRF Defense") { sub =>
        var guard_cfg = wing::new_cross_origin_guard();
        guard_cfg.require_user_activation_on_sensitive_nav = true;

        // Normal top-level document navigation (e.g. following a link to a blog post)
        var ctx_normal = wing::FetchContext {
            site: wing::SecFetchSite.CrossSite,
            mode: wing::SecFetchMode.Navigate,
            dest: wing::SecFetchDest.Document,
            method_is_safe: true,
            is_sensitive_navigation_route: false,
            ..
        };
        let dec_normal = wing::evaluate_fetch_metadata(guard_cfg, ctx_normal);
        let ok_normal = match dec_normal {
            Allow => true,
            _ => false,
        };
        sub.assert_true(ok_normal, "normal cross-site GET navigation allowed");

        // Sensitive route (e.g. /auth/login, /transfer) WITHOUT user activation (First-Login CSRF)
        var ctx_sensitive = wing::FetchContext {
            site: wing::SecFetchSite.CrossSite,
            mode: wing::SecFetchMode.Navigate,
            dest: wing::SecFetchDest.Document,
            method_is_safe: true,
            is_sensitive_navigation_route: true,
            user_activated: false,
            ..
        };
        let dec_sensitive = wing::evaluate_fetch_metadata(guard_cfg, ctx_sensitive);
        let ok_reject = match dec_sensitive {
            RejectForbidden r => r.reason == wing::CsrfRejectReason.MissingUserActivationOnSensitiveNav,
            _ => false,
        };
        sub.assert_true(ok_reject, "sensitive navigation without user activation rejected (First-Login CSRF blocked)");

        // Sensitive route WITH user activation (user explicitly clicked button/link)
        ctx_sensitive.user_activated = true;
        let dec_activated = wing::evaluate_fetch_metadata(guard_cfg, ctx_sensitive);
        let ok_activated = match dec_activated {
            Allow => true,
            _ => false,
        };
        sub.assert_true(ok_activated, "sensitive navigation with user activation allowed");
    };

    t.run("Row 6: Clickjacking, Framing & XSSI Rejection") { sub =>
        let guard_cfg = wing::new_cross_origin_guard();

        let evil_dests: const wing::SecFetchDest[5] = [
            wing::SecFetchDest.Iframe,
            wing::SecFetchDest.Frame,
            wing::SecFetchDest.Object,
            wing::SecFetchDest.Embed,
            wing::SecFetchDest.Script,
        ];

        for d in evil_dests {
            var ctx = wing::FetchContext {
                site: wing::SecFetchSite.CrossSite,
                dest: d,
                method_is_safe: true,
                ..
            };
            let dec = wing::evaluate_fetch_metadata(guard_cfg, ctx);
            let ok = match dec {
                RejectForbidden r => r.reason == wing::CsrfRejectReason.CrossSiteFramingOrXssi,
                _ => false,
            };
            sub.assert_true(ok, "cross-site framing / script embedding rejected");
        }
    };

    t.run("Row 7: Cross-Site Subresources (Static Assets)") { sub =>
        var guard_cfg = wing::new_cross_origin_guard();
        guard_cfg.allow_cross_site_static_assets = true;

        var ctx_img = wing::FetchContext {
            site: wing::SecFetchSite.CrossSite,
            dest: wing::SecFetchDest.Image,
            method_is_safe: true,
            ..
        };
        let dec_img = wing::evaluate_fetch_metadata(guard_cfg, ctx_img);
        let ok_img = match dec_img {
            Allow => true,
            _ => false,
        };
        sub.assert_true(ok_img, "cross-site image allowed when configured");

        var ctx_other = wing::FetchContext {
            site: wing::SecFetchSite.CrossSite,
            dest: wing::SecFetchDest.Other,
            method_is_safe: true,
            ..
        };
        let dec_other = wing::evaluate_fetch_metadata(guard_cfg, ctx_other);
        let ok_reject = match dec_other {
            RejectForbidden r => r.reason == wing::CsrfRejectReason.CrossSiteUnauthorizedSubresource,
            _ => false,
        };
        sub.assert_true(ok_reject, "cross-site other subresource rejected");
    };

    t.run("Row 8: Fallback Mode (Origin / Referer Validation)") { sub =>
        var guard_cfg = wing::new_cross_origin_guard();
        wing::add_trusted_origin(guard_cfg, "https://partner.example.com");

        // Matching target host
        var ctx_same_host = wing::FetchContext {
            site: wing::SecFetchSite.Missing, // missing Sec-Fetch-*
            has_origin: true,
            method_is_safe: false,
            ..
        };
        ctx_same_host.origin.append("https://app.example.com");
        ctx_same_host.target_host.append("app.example.com");
        let dec_same = wing::evaluate_fetch_metadata(guard_cfg, ctx_same_host);
        let ok_same = match dec_same {
            Allow => true,
            _ => false,
        };
        sub.assert_true(ok_same, "fallback matching host allowed");

        // Trusted partner origin
        var ctx_partner = wing::FetchContext {
            site: wing::SecFetchSite.Missing,
            has_origin: true,
            method_is_safe: false,
            ..
        };
        ctx_partner.origin.append("https://partner.example.com");
        ctx_partner.target_host.append("app.example.com");
        let dec_partner = wing::evaluate_fetch_metadata(guard_cfg, ctx_partner);
        let ok_partner = match dec_partner {
            Allow => true,
            _ => false,
        };
        sub.assert_true(ok_partner, "fallback trusted partner allowed");

        // Mismatched untrusted origin on mutation
        var ctx_attacker = wing::FetchContext {
            site: wing::SecFetchSite.Missing,
            has_origin: true,
            method_is_safe: false,
            ..
        };
        ctx_attacker.origin.append("https://attacker.evil.com");
        ctx_attacker.target_host.append("app.example.com");
        let dec_att = wing::evaluate_fetch_metadata(guard_cfg, ctx_attacker);
        let ok_att = match dec_att {
            RejectForbidden r => r.reason == wing::CsrfRejectReason.OriginHostMismatch,
            _ => false,
        };
        sub.assert_true(ok_att, "mismatched attacker origin rejected");
    };

    t.run("Row 9: Fail-Closed Cookie Gate") { sub =>
        let guard_cfg = wing::new_cross_origin_guard();

        // Request with session cookie but ZERO browser security headers (no Sec-Fetch-*, no Origin, no Referer)
        var ctx_blind = wing::FetchContext {
            site: wing::SecFetchSite.Missing,
            has_origin: false,
            has_referer: false,
            has_session_cookie: true,
            method_is_safe: false,
            ..
        };
        let dec_blind = wing::evaluate_fetch_metadata(guard_cfg, ctx_blind);
        let ok_blind = match dec_blind {
            RejectForbidden r => r.reason == wing::CsrfRejectReason.MissingBrowserHeadersWithSessionCookie,
            _ => false,
        };
        sub.assert_true(ok_blind, "fail-closed: state mutation with session cookie lacking browser headers is rejected");
    };

    t.run("Path Exemptions & Webhooks") { sub =>
        var guard_cfg = wing::new_cross_origin_guard();
        wing::add_exempt_path(guard_cfg, "/api/webhook/stripe");

        var ctx = wing::FetchContext {
            site: wing::SecFetchSite.CrossSite,
            method_is_safe: false,
            ..
        };
        ctx.path.clear();
        ctx.path.append("/api/webhook/stripe");

        let dec = wing::evaluate_fetch_metadata(guard_cfg, ctx);
        let is_exempt = match dec {
            AllowExempt => true,
            _ => false,
        };
        sub.assert_true(is_exempt, "exempt path unconditionally allowed");
    };
}

// ----------------------------------------------------------------------------
// 2. Response Isolation Headers (Vary & HSTS)
// ----------------------------------------------------------------------------
fn test_isolation_headers_injection(t: core::T&) {
    t.run("Mandatory Vary and HSTS Headers") { sub =>
        var res = wing::new_response();
        wing::apply_isolation_headers(res);

        var has_vary = false;
        var has_hsts = false;

        for &hdr in res.headers {
            if core::eq_ascii_fold(hdr.name[..], "Vary") {
                has_vary = true;
                sub.assert_contains(hdr.value[..], "Sec-Fetch-Site", "Vary contains Sec-Fetch-Site");
                sub.assert_contains(hdr.value[..], "Origin", "Vary contains Origin");
            }
            if core::eq_ascii_fold(hdr.name[..], "Strict-Transport-Security") {
                has_hsts = true;
                sub.assert_contains(hdr.value[..], "max-age=", "HSTS specifies max-age");
                sub.assert_contains(hdr.value[..], "includeSubDomains", "HSTS includes subdomains");
            }
        }

        sub.assert_true(has_vary, "Vary header present on protected response");
        sub.assert_true(has_hsts, "Strict-Transport-Security header present");
    };
}

// ----------------------------------------------------------------------------
// 3. Protocol-Specific CORS Matching & Credentials Security
// ----------------------------------------------------------------------------
fn test_cors_policy_and_matching(t: core::T&) {
    t.run("Protocol-Specific Subdomain Wildcard Matching") { sub =>
        let pattern = "https://*.example.com";

        // Valid HTTPS subdomains
        sub.assert_true(wing::match_cors_origin_pattern("https://api.example.com", pattern), "https api subdomain matches");
        sub.assert_true(wing::match_cors_origin_pattern("https://stage.app.example.com", pattern), "nested subdomain matches");

        // Protocol mismatch: HTTP must NOT match HTTPS pattern!
        sub.assert_false(wing::match_cors_origin_pattern("http://api.example.com", pattern), "insecure HTTP rejected against HTTPS pattern");

        // Domain mismatch
        sub.assert_false(wing::match_cors_origin_pattern("https://attacker-example.com", pattern), "suffix confusion attack rejected");
        sub.assert_false(wing::match_cors_origin_pattern("https://example.com", pattern), "apex domain rejected by wildcard prefix");
    };

    t.run("CORS Preflight (OPTIONS) & Actual Request Evaluation") { sub =>
        var policy = wing::new_cors_policy();
        wing::add_allowed_origin(policy, "https://portal.example.com");
        policy.allow_credentials = true;
        policy.max_age_sec = 7200;

        // Preflight request
        var preflight_req = wing::new_request("OPTIONS", "/api/v1/resource");
        preflight_req.headers.push(wing::make_header("Origin", "https://portal.example.com"));
        preflight_req.headers.push(wing::make_header("Access-Control-Request-Method", "POST"));
        preflight_req.headers.push(wing::make_header("Access-Control-Request-Headers", "Content-Type, Authorization"));

        var preflight_res = wing::new_response();
        let preflight_res_code = wing::evaluate_cors(policy, preflight_req, preflight_res);
        sub.assert_true(preflight_res_code == wing::CorsResult.AllowedPreflight, "preflight handled cleanly");
        sub.assert_eq(preflight_res.status_code, 204, "preflight returns 204 No Content");

        var has_allow_origin = false;
        var has_allow_creds = false;
        var has_max_age = false;

        for &hdr in preflight_res.headers {
            if core::eq_ascii_fold(hdr.name[..], "Access-Control-Allow-Origin") {
                has_allow_origin = true;
                sub.assert_eq(hdr.value[..], "https://portal.example.com", "origin mirrored");
            }
            if core::eq_ascii_fold(hdr.name[..], "Access-Control-Allow-Credentials") {
                has_allow_creds = true;
                sub.assert_eq(hdr.value[..], "true", "credentials allowed");
            }
            if core::eq_ascii_fold(hdr.name[..], "Access-Control-Max-Age") {
                has_max_age = true;
                sub.assert_eq(hdr.value[..], "7200", "max age matches");
            }
        }

        sub.assert_true(has_allow_origin, "Access-Control-Allow-Origin present");
        sub.assert_true(has_allow_creds, "Access-Control-Allow-Credentials present");
        sub.assert_true(has_max_age, "Access-Control-Max-Age present");
    };

    t.run("CORS Wildcard with Credentials Rejection") { sub =>
        var policy = wing::new_cors_policy();
        wing::add_allowed_origin(policy, "*");
        policy.allow_credentials = true; // Illegal combination per W3C CORS / Fetch spec

        var req = wing::new_request("GET", "/api/data");
        req.headers.push(wing::make_header("Origin", "https://untrusted.com"));

        var res = wing::new_response();
        let res_code = wing::evaluate_cors(policy, req, res);
        sub.assert_true(res_code == wing::CorsResult.InvalidConfig, "wildcard with allow_credentials rejected with InvalidConfig");
    };
}

// ----------------------------------------------------------------------------
// Suite Runner
// ----------------------------------------------------------------------------
fn main() {
    var runner = core::new_runner("Fetch Metadata & CORS Suite", core::Verbosity.Verbose);

    core::run_case(runner, "1. W3C Fetch Metadata 9-Row Decision Matrix", test_fetch_metadata_decision_matrix);
    core::run_case(runner, "2. Response Isolation Headers (Vary & HSTS)", test_isolation_headers_injection);
    core::run_case(runner, "3. Protocol-Specific CORS Matching & Credentials Security", test_cors_policy_and_matching);

    let ok = core::finish(runner);
    assert(ok);
}
