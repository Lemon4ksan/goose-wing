// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

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

        sub.assert_true(res.has_header("Vary"), "Vary header present on protected response");
        sub.assert_contains(res.header("Vary"), "Sec-Fetch-Site", "Vary contains Sec-Fetch-Site");
        sub.assert_contains(res.header("Vary"), "Origin", "Vary contains Origin");
        sub.assert_true(res.has_header("Strict-Transport-Security"), "Strict-Transport-Security header present");
        sub.assert_contains(res.header("Strict-Transport-Security"), "max-age=", "HSTS specifies max-age");
        sub.assert_contains(res.header("Strict-Transport-Security"), "includeSubDomains", "HSTS includes subdomains");
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

        sub.assert_true(preflight_res.has_header("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin present");
        sub.assert_eq(preflight_res.header("Access-Control-Allow-Origin"), "https://portal.example.com", "origin mirrored");
        sub.assert_true(preflight_res.has_header("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials present");
        sub.assert_eq(preflight_res.header("Access-Control-Allow-Credentials"), "true", "credentials allowed");
        sub.assert_true(preflight_res.has_header("Access-Control-Max-Age"), "Access-Control-Max-Age present");
        sub.assert_eq(preflight_res.header("Access-Control-Max-Age"), "7200", "max age matches");
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

    t.run("CORS Multi-Origin Wildcard with Credentials Rejection (Fetch §3.2.2)") { sub =>
        var policy = wing::new_cors_policy();
        wing::add_allowed_origin(policy, "https://portal.example.com");
        wing::add_allowed_origin(policy, "*");
        policy.allow_credentials = true; // Illegal per Fetch spec §3.2.2 even if multiple origins present

        var req = wing::new_request("GET", "/api/data");
        req.headers.push(wing::make_header("Origin", "https://portal.example.com"));

        var res = wing::new_response();
        let res_code = wing::evaluate_cors(policy, req, res);
        sub.assert_true(res_code == wing::CorsResult.InvalidConfig, "wildcard in multi-origin with allow_credentials rejected with InvalidConfig");
    };

    t.run("CORS Null Origin & Sandboxed Iframe Rejection (RFC 6454)") { sub =>
        // 1. Wildcard policy without credentials must NOT match Origin: null (sandboxed iframe / data: URI bypass)
        var wild_policy = wing::new_cors_policy();
        wing::add_allowed_origin(wild_policy, "*");
        wild_policy.allow_credentials = false;

        var iframe_req = wing::new_request("GET", "/api/data");
        iframe_req.headers.push(wing::make_header("Origin", "null"));
        var iframe_res = wing::new_response();
        let wild_null_code = wing::evaluate_cors(wild_policy, iframe_req, iframe_res);
        sub.assert_true(wild_null_code == wing::CorsResult.RejectedOrigin, "Origin: null rejected against wildcard pattern");
        sub.assert_false(iframe_res.has_header("Access-Control-Allow-Origin"), "never reflect Access-Control-Allow-Origin: null");

        // 2. Case-insensitive "NULL" rejection when allow_credentials is true
        var cred_policy = wing::new_cors_policy();
        wing::add_allowed_origin(cred_policy, "https://app.example.com");
        cred_policy.allow_credentials = true;

        var upper_null_req = wing::new_request("GET", "/api/user");
        upper_null_req.headers.push(wing::make_header("Origin", "NULL"));
        var upper_null_res = wing::new_response();
        let upper_code = wing::evaluate_cors(cred_policy, upper_null_req, upper_null_res);
        sub.assert_true(upper_code == wing::CorsResult.RejectedOrigin, "Origin: NULL rejected when credentials enabled");
    };
}

// ----------------------------------------------------------------------------
// 4. Constant-Time CSRF Token Validation & OTP Mask Verification
// ----------------------------------------------------------------------------
fn test_csrf_constant_time_tokens(t: core::T&) {
    t.run("Double-Submit Token Validation (subtle_equal)") { sub =>
        let tok1 = "3b9a1f4c7e2d8a0b5c4f3e2d1a0b9c8d";
        let tok2 = "3b9a1f4c7e2d8a0b5c4f3e2d1a0b9c8d";
        let tok3 = "3b9a1f4c7e2d8a0b5c4f3e2d1a0b9c8e"; // last byte differs
        let tok4 = "3b9a1f4c7e2d8a0b"; // shorter

        sub.assert_true(wing::validate_csrf_token(tok1, tok2), "matching tokens valid");
        sub.assert_false(wing::validate_csrf_token(tok1, tok3), "differing last byte invalid");
        sub.assert_false(wing::validate_csrf_token(tok1, tok4), "different length invalid");
        sub.assert_false(wing::validate_csrf_token("", ""), "empty tokens invalid");
    };

    t.run("Masked CSRF Token Verification (OTP XOR)") { sub =>
        let raw: const u8[16] = [
            0x12, 0x34, 0x56, 0x78, 0x9a, 0xbc, 0xde, 0xf0,
            0xfe, 0xdc, 0xba, 0x98, 0x76, 0x54, 0x32, 0x10,
        ];
        let mask1: const u8[16] = [
            0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55,
            0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55, 0xaa, 0x55,
        ];
        var masked1: u8[..32] = [];
        sub.assert_true(wing::mask_csrf_token(mask1[..], raw[..], masked1), "masking succeeds");
        sub.assert_eq(masked1.len, 32, "masked token is 32 bytes");
        sub.assert_true(wing::verify_masked_csrf_token(masked1[..], raw[..]), "masked token 1 verifies against raw secret");

        // Different mask for same secret
        let mask2: const u8[16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        ];
        var masked2: u8[..32] = [];
        sub.assert_true(wing::mask_csrf_token(mask2[..], raw[..], masked2), "masking 2 succeeds");
        sub.assert_true(wing::verify_masked_csrf_token(masked2[..], raw[..]), "masked token 2 verifies against same raw secret");

        // Tampered masked token
        masked1[20] ^= 0x01;
        sub.assert_false(wing::verify_masked_csrf_token(masked1[..], raw[..]), "tampered token fails verification");

        // Wrong length
        sub.assert_false(wing::verify_masked_csrf_token(masked1[..16], raw[..]), "truncated token fails verification");
    };

    t.run("Constant-Time Case-Fold Origin Host Comparison") { sub =>
        sub.assert_true(wing::subtle_equal_ascii_fold("example.com", "EXAMPLE.COM"), "case-insensitive match");
        sub.assert_true(wing::subtle_equal_ascii_fold("secure.bank.com:8443", "secure.bank.com:8443"), "identical match");
        sub.assert_false(wing::subtle_equal_ascii_fold("attacker.com", "victim.com"), "different hosts mismatch");
        sub.assert_false(wing::subtle_equal_ascii_fold("victim.com.evil", "victim.com"), "prefix mismatch");
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
    core::run_case(runner, "4. Constant-Time CSRF Token Validation & OTP Mask Verification", test_csrf_constant_time_tokens);

    let ok = core::finish(runner);
    assert(ok);
}
