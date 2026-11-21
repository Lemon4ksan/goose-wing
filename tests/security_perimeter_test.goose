// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Consolidated Verification Suite: Application Perimeter Security, CSRF, HSTS, and Policy Suite
//
// RUN: goose build -o %t.exe %s
// RUN: %t.exe
import std;
import core from "..";
import wing from "..";
import lit from "github.com/Lemon4ksan/goose-lit@v0.1.0";

// --- Component: security_cross_origin ---
// Verification suite for W3C Cross-Origin Isolation (COOP, COEP, CORP):
// - Header parsing for Cross-Origin-Opener-Policy, Cross-Origin-Embedder-Policy, Cross-Origin-Resource-Policy
// - W3C HTML5 §7.2 crossOriginIsolated state computation
// - Subresource embedding permission enforcement under require-corp sandbox

// ----------------------------------------------------------------------------
// 1. Cross-Origin Isolation & Subresource Policies
// ----------------------------------------------------------------------------
fn test_cross_origin_isolation(t: lit::T&) {
    t.run("Policy Header Parsing") { sub =>
        sub.assert_true(security::parse_coop("same-origin") == security::CoopPolicy.SameOrigin, "COOP same-origin");
        sub.assert_true(security::parse_coop("same-origin-allow-popups") == security::CoopPolicy.SameOriginAllowPopups, "COOP allow-popups");
        sub.assert_true(security::parse_coop("unsafe-none") == security::CoopPolicy.UnsafeNone, "COOP unsafe-none");
        sub.assert_true(security::parse_coop(" same-origin \t") == security::CoopPolicy.SameOrigin, "COOP same-origin with LWS");

        sub.assert_true(security::parse_coep("require-corp") == security::CoepPolicy.RequireCorp, "COEP require-corp");
        sub.assert_true(security::parse_coep("credentialless") == security::CoepPolicy.Credentialless, "COEP credentialless");
        sub.assert_true(security::parse_coep(" require-corp ") == security::CoepPolicy.RequireCorp, "COEP require-corp with LWS");

        sub.assert_true(security::parse_corp("cross-origin") == security::CorpPolicy.CrossOrigin, "CORP cross-origin");
        sub.assert_true(security::parse_corp("same-origin") == security::CorpPolicy.SameOrigin, "CORP same-origin");
        sub.assert_true(security::parse_corp("same-site") == security::CorpPolicy.SameSite, "CORP same-site");
        sub.assert_true(security::parse_corp(" same-site ") == security::CorpPolicy.SameSite, "CORP same-site with LWS");
    };

    t.run("crossOriginIsolated Status Computation (W3C HTML §7.2)") { sub =>
        var ctx = security::CrossOriginIsolationContext { .. };

        // 1. Both COOP same-origin and COEP require-corp -> ISOLATED
        security::update_isolation_context(ctx, "same-origin", "require-corp", "https://app.secure.com");
        sub.assert_true(ctx.is_cross_origin_isolated, "Context is crossOriginIsolated");
        sub.assert_bytes_eq(ctx.document_origin[..], "https://app.secure.com", "Origin stored");

        // 2. COOP same-origin and COEP credentialless -> ISOLATED
        security::update_isolation_context(ctx, "same-origin", "credentialless", "https://app.secure.com");
        sub.assert_true(ctx.is_cross_origin_isolated, "Credentialless also grants crossOriginIsolated");

        // 3. COOP missing or unsafe-none -> NOT isolated
        security::update_isolation_context(ctx, "unsafe-none", "require-corp", "https://app.secure.com");
        sub.assert_false(ctx.is_cross_origin_isolated, "Not isolated without COOP same-origin");

        // 4. COEP missing or unsafe-none -> NOT isolated
        security::update_isolation_context(ctx, "same-origin", "unsafe-none", "https://app.secure.com");
        sub.assert_false(ctx.is_cross_origin_isolated, "Not isolated without COEP");

        // 5. Update directly from HeaderMap via UFCS
        var headers = http::HeaderMap { .. };
        http::append_header(headers, "cross-origin-opener-policy", "same-origin");
        http::append_header(headers, "cross-origin-embedder-policy", "require-corp");
        ctx.update_from_headers(headers, "https://service.internal");
        sub.assert_true(ctx.is_cross_origin_isolated, "HeaderMap UFCS update_from_headers isolated");
        sub.assert_bytes_eq(ctx.document_origin[..], "https://service.internal", "HeaderMap origin stored");
    };

    t.run("Subresource Loading Policy Enforcement") { sub =>
        var isolated_ctx = security::CrossOriginIsolationContext { .. };
        security::update_isolation_context(isolated_ctx, "same-origin", "require-corp", "https://main.app.com");

        // Same-origin subresource: always allowed
        sub.assert_true(
            security::is_subresource_allowed(isolated_ctx, "https://main.app.com", ""),
            "Same-origin resource always allowed",
        );

        // Cross-origin with CORP: cross-origin: allowed
        sub.assert_true(
            security::is_subresource_allowed(isolated_ctx, "https://cdn.other.com", "cross-origin"),
            "Cross-origin subresource with CORP: cross-origin allowed",
        );

        // Same-site subresource (subdomain) with CORP: same-site: allowed under require-corp
        sub.assert_true(
            security::is_subresource_allowed(isolated_ctx, "https://static.app.com", "same-site"),
            "Same-site subresource with CORP: same-site allowed",
        );

        // Insecure HTTP subresource into HTTPS document with same-site CORP: BLOCKED (WHATWG Fetch §4.5.7)
        sub.assert_false(
            security::is_subresource_allowed(isolated_ctx, "http://static.app.com", "same-site"),
            "Insecure HTTP subresource into HTTPS document with same-site CORP BLOCKED",
        );

        // Cross-site subresource with CORP: same-site: BLOCKED
        sub.assert_false(
            security::is_subresource_allowed(isolated_ctx, "https://cdn.evil.com", "same-site"),
            "Cross-site subresource with CORP: same-site BLOCKED",
        );

        // Cross-origin with missing CORP: BLOCKED by require-corp
        sub.assert_false(
            security::is_subresource_allowed(isolated_ctx, "https://cdn.other.com", ""),
            "Cross-origin subresource without CORP BLOCKED by require-corp",
        );

        // Cross-origin with CORP: same-origin: BLOCKED
        sub.assert_false(
            security::is_subresource_allowed(isolated_ctx, "https://cdn.other.com", "same-origin"),
            "Cross-origin subresource declaring same-origin BLOCKED",
        );
    };
}

// --- Component: security_csrf ---
// Tests for Fetch Metadata resource isolation and CORS policy validation.

// ----------------------------------------------------------------------------
// 2. W3C Fetch Metadata 9-Row Decision Matrix
// ----------------------------------------------------------------------------
fn test_fetch_metadata_decision_matrix(t: lit::T&) {
    t.run("Row 1: Direct User Navigation (Sec-Fetch-Site: none)") { sub =>
        let guard_cfg = security::CrossOriginGuard { .. };
        var ctx = security::FetchContext {
            site:           security::SecFetchSite.None,
            mode:           security::SecFetchMode.Navigate,
            dest:           security::SecFetchDest.Document,
            method_is_safe: true,
            ..
        };
        let decision = security::evaluate_fetch_metadata(guard_cfg, ctx);
        let ok = match decision {
            Allow => true,
            _ => false,
        };
        sub.assert_true(ok, "direct navigation allowed");
    };

    t.run("Row 2: Same-Origin SOP Requests") { sub =>
        let guard_cfg = security::CrossOriginGuard { .. };
        var ctx = security::FetchContext {
            site:           security::SecFetchSite.SameOrigin,
            mode:           security::SecFetchMode.Cors,
            dest:           security::SecFetchDest.Empty,
            method_is_safe: false, // POST/PUT mutation
            ..
        };
        let decision = security::evaluate_fetch_metadata(guard_cfg, ctx);
        let ok = match decision {
            Allow => true,
            _ => false,
        };
        sub.assert_true(ok, "same-origin mutations allowed under SOP");
    };

    t.run("Row 3: Same-Site Subdomain Policy") { sub =>
        var guard_cfg = security::CrossOriginGuard { .. };
        guard_cfg.allow_same_site = false;

        // Safe method GET across subdomains
        var ctx_safe = security::FetchContext {
            site:           security::SecFetchSite.SameSite,
            method_is_safe: true,
            ..
        };
        let dec_safe = security::evaluate_fetch_metadata(guard_cfg, ctx_safe);
        let ok_safe = match dec_safe {
            Allow => true,
            _ => false,
        };
        sub.assert_true(ok_safe, "same-site safe reads allowed");

        // Unsafe method POST across subdomains without allow_same_site
        var ctx_unsafe = security::FetchContext {
            site:           security::SecFetchSite.SameSite,
            method_is_safe: false,
            ..
        };
        let dec_unsafe = security::evaluate_fetch_metadata(guard_cfg, ctx_unsafe);
        let ok_reject = match dec_unsafe {
            RejectForbidden r => r.reason == security::CsrfRejectReason.DisallowedSameSiteSubdomain,
            _ => false,
        };
        sub.assert_true(ok_reject, "same-site mutations rejected when allow_same_site=false");

        // When allow_same_site = true
        guard_cfg.allow_same_site = true;
        let dec_allowed = security::evaluate_fetch_metadata(guard_cfg, ctx_unsafe);
        let ok_allowed = match dec_allowed {
            Allow => true,
            _ => false,
        };
        sub.assert_true(ok_allowed, "same-site mutations allowed when allow_same_site=true");
    };

    t.run("Row 4: Cross-Site State Mutation (POST/PUT/DELETE) Blocked") { sub =>
        let guard_cfg = security::CrossOriginGuard { .. };
        var ctx = security::FetchContext {
            site:           security::SecFetchSite.CrossSite,
            mode:           security::SecFetchMode.Cors,
            dest:           security::SecFetchDest.Empty,
            method_is_safe: false,
            ..
        };
        let dec = security::evaluate_fetch_metadata(guard_cfg, ctx);
        let ok = match dec {
            RejectForbidden r => r.reason == security::CsrfRejectReason.CrossSiteStateMutation,
            _ => false,
        };
        sub.assert_true(ok, "cross-site mutation rejected with CrossSiteStateMutation");
    };

    t.run("Row 5: Top-Level Cross-Site Navigation & First-Login CSRF Defense") { sub =>
        var guard_cfg = security::CrossOriginGuard { .. };
        guard_cfg.require_user_activation_on_sensitive_nav = true;

        // Normal top-level document navigation (e.g. following a link to a blog post)
        var ctx_normal = security::FetchContext {
            site:                          security::SecFetchSite.CrossSite,
            mode:                          security::SecFetchMode.Navigate,
            dest:                          security::SecFetchDest.Document,
            method_is_safe:                true,
            is_sensitive_navigation_route: false,
            ..
        };
        let dec_normal = security::evaluate_fetch_metadata(guard_cfg, ctx_normal);
        let ok_normal = match dec_normal {
            Allow => true,
            _ => false,
        };
        sub.assert_true(ok_normal, "normal cross-site GET navigation allowed");

        // Sensitive route (e.g. /auth/login, /transfer) WITHOUT user activation (First-Login CSRF)
        var ctx_sensitive = security::FetchContext {
            site:                          security::SecFetchSite.CrossSite,
            mode:                          security::SecFetchMode.Navigate,
            dest:                          security::SecFetchDest.Document,
            method_is_safe:                true,
            is_sensitive_navigation_route: true,
            user_activated:                false,
            ..
        };
        let dec_sensitive = security::evaluate_fetch_metadata(guard_cfg, ctx_sensitive);
        let ok_reject = match dec_sensitive {
            RejectForbidden r => r.reason == security::CsrfRejectReason.MissingUserActivationOnSensitiveNav,
            _ => false,
        };
        sub.assert_true(ok_reject, "sensitive navigation without user activation rejected (First-Login CSRF blocked)");

        // Sensitive route WITH user activation (user explicitly clicked button/link)
        ctx_sensitive.user_activated = true;
        let dec_activated = security::evaluate_fetch_metadata(guard_cfg, ctx_sensitive);
        let ok_activated = match dec_activated {
            Allow => true,
            _ => false,
        };
        sub.assert_true(ok_activated, "sensitive navigation with user activation allowed");
    };

    t.run("Row 6: Clickjacking, Framing & XSSI Rejection") { sub =>
        let guard_cfg = security::CrossOriginGuard { .. };

        let evil_dests: const security::SecFetchDest[5] = [
            security::SecFetchDest.Iframe,
            security::SecFetchDest.Frame,
            security::SecFetchDest.Object,
            security::SecFetchDest.Embed,
            security::SecFetchDest.Script,
        ];

        for d in evil_dests {
            var ctx = security::FetchContext {
                site:           security::SecFetchSite.CrossSite,
                dest:           d,
                method_is_safe: true,
                ..
            };
            let dec = security::evaluate_fetch_metadata(guard_cfg, ctx);
            let ok = match dec {
                RejectForbidden r => r.reason == security::CsrfRejectReason.CrossSiteFramingOrXssi,
                _ => false,
            };
            sub.assert_true(ok, "cross-site framing / script embedding rejected");
        }
    };

    t.run("Row 7: Cross-Site Subresources (Static Assets)") { sub =>
        var guard_cfg = security::CrossOriginGuard { .. };
        guard_cfg.allow_cross_site_static_assets = true;

        var ctx_img = security::FetchContext {
            site:           security::SecFetchSite.CrossSite,
            dest:           security::SecFetchDest.Image,
            method_is_safe: true,
            ..
        };
        let dec_img = security::evaluate_fetch_metadata(guard_cfg, ctx_img);
        let ok_img = match dec_img {
            Allow => true,
            _ => false,
        };
        sub.assert_true(ok_img, "cross-site image allowed when configured");

        var ctx_other = security::FetchContext {
            site:           security::SecFetchSite.CrossSite,
            dest:           security::SecFetchDest.Other,
            method_is_safe: true,
            ..
        };
        let dec_other = security::evaluate_fetch_metadata(guard_cfg, ctx_other);
        let ok_reject = match dec_other {
            RejectForbidden r => r.reason == security::CsrfRejectReason.CrossSiteUnauthorizedSubresource,
            _ => false,
        };
        sub.assert_true(ok_reject, "cross-site other subresource rejected");
    };

    t.run("Row 8: Fallback Mode (Origin / Referer Validation)") { sub =>
        var guard_cfg = security::CrossOriginGuard { .. };
        security::add_trusted_origin(guard_cfg, "https://partner.example.com");

        // Matching target host
        var ctx_same_host = security::FetchContext {
            site:           security::SecFetchSite.Missing, // missing Sec-Fetch-*
            has_origin:     true,
            method_is_safe: false,
            ..
        };
        ctx_same_host.origin.append("https://app.example.com");
        ctx_same_host.target_host.append("app.example.com");
        let dec_same = security::evaluate_fetch_metadata(guard_cfg, ctx_same_host);
        let ok_same = match dec_same {
            Allow => true,
            _ => false,
        };
        sub.assert_true(ok_same, "fallback matching host allowed");

        // Trusted partner origin
        var ctx_partner = security::FetchContext {
            site:           security::SecFetchSite.Missing,
            has_origin:     true,
            method_is_safe: false,
            ..
        };
        ctx_partner.origin.append("https://partner.example.com");
        ctx_partner.target_host.append("app.example.com");
        let dec_partner = security::evaluate_fetch_metadata(guard_cfg, ctx_partner);
        let ok_partner = match dec_partner {
            Allow => true,
            _ => false,
        };
        sub.assert_true(ok_partner, "fallback trusted partner allowed");

        // Mismatched untrusted origin on mutation
        var ctx_attacker = security::FetchContext {
            site:           security::SecFetchSite.Missing,
            has_origin:     true,
            method_is_safe: false,
            ..
        };
        ctx_attacker.origin.append("https://attacker.evil.com");
        ctx_attacker.target_host.append("app.example.com");
        let dec_att = security::evaluate_fetch_metadata(guard_cfg, ctx_attacker);
        let ok_att = match dec_att {
            RejectForbidden r => r.reason == security::CsrfRejectReason.OriginHostMismatch,
            _ => false,
        };
        sub.assert_true(ok_att, "mismatched attacker origin rejected");
    };

    t.run("Row 9: Fail-Closed Cookie Gate") { sub =>
        let guard_cfg = security::CrossOriginGuard { .. };

        // Request with session cookie but ZERO browser security headers (no Sec-Fetch-*, no Origin, no Referer)
        var ctx_blind = security::FetchContext {
            site:               security::SecFetchSite.Missing,
            has_origin:         false,
            has_referer:        false,
            has_session_cookie: true,
            method_is_safe:     false,
            ..
        };
        let dec_blind = security::evaluate_fetch_metadata(guard_cfg, ctx_blind);
        let ok_blind = match dec_blind {
            RejectForbidden r => r.reason == security::CsrfRejectReason.MissingBrowserHeadersWithSessionCookie,
            _ => false,
        };
        sub.assert_true(ok_blind, "fail-closed: state mutation with session cookie lacking browser headers is rejected");
    };

    t.run("Path Exemptions & Webhooks") { sub =>
        var guard_cfg = security::CrossOriginGuard { .. };
        security::add_exempt_path(guard_cfg, "/api/webhook/stripe");

        var ctx = security::FetchContext {
            site:           security::SecFetchSite.CrossSite,
            method_is_safe: false,
            ..
        };
        ctx.path.clear();
        ctx.path.append("/api/webhook/stripe");

        let dec = security::evaluate_fetch_metadata(guard_cfg, ctx);
        let is_exempt = match dec {
            AllowExempt => true,
            _ => false,
        };
        sub.assert_true(is_exempt, "exempt path unconditionally allowed");
    };

    t.run("Row 10: extract_fetch_context extracts URL path for exempt routing") { sub =>
        var guard_cfg = security::CrossOriginGuard { .. };
        security::add_exempt_path(guard_cfg, "/api/webhook/stripe");

        var req = http::new_request("POST", "https://api.example.com/api/webhook/stripe?signature=abc123#frag");
        http::set_header(req, "Sec-Fetch-Site", "cross-site");
        let ctx = security::extract_fetch_context(req, "api.example.com");

        sub.assert_bytes_eq(ctx.path[..], "/api/webhook/stripe", "path extracted cleanly without query or host");
        let dec = security::evaluate_fetch_metadata(guard_cfg, ctx);
        let is_exempt = match dec {
            AllowExempt => true,
            _ => false,
        };
        sub.assert_true(is_exempt, "exempt path recognized via extract_fetch_context");
    };

    t.run("Row 11: extract_host_from_url rejects opaque 'null' origin") { sub =>
        let host = security::extract_host_from_url("null");
        sub.assert_eq(host.len, 0, "opaque 'null' origin produces empty host");
    };
}

// ----------------------------------------------------------------------------
// 3. Response Isolation Headers (Vary & HSTS)
// ----------------------------------------------------------------------------
fn test_isolation_headers_injection(t: lit::T&) {
    t.run("Mandatory Vary and HSTS Headers") { sub =>
        var res = http::Response { .. };
        security::apply_isolation_headers(res);

        sub.assert_true(res.has_header("Vary"), "Vary header present on protected response");
        sub.assert_contains(res.header("Vary"), "Sec-Fetch-Site", "Vary contains Sec-Fetch-Site");
        sub.assert_contains(res.header("Vary"), "Origin", "Vary contains Origin");
        sub.assert_true(res.has_header("Strict-Transport-Security"), "Strict-Transport-Security header present");
        sub.assert_contains(res.header("Strict-Transport-Security"), "max-age=", "HSTS specifies max-age");
        sub.assert_contains(res.header("Strict-Transport-Security"), "includeSubDomains", "HSTS includes subdomains");
    };
}

// ----------------------------------------------------------------------------
// 4. Protocol-Specific CORS Matching & Credentials Security
// ----------------------------------------------------------------------------
fn test_cors_policy_and_matching(t: lit::T&) {
    t.run("Protocol-Specific Subdomain Wildcard Matching") { sub =>
        let pattern = "https://*.example.com";

        // Valid HTTPS subdomains
        sub.assert_true(security::match_cors_origin_pattern("https://api.example.com", pattern), "https api subdomain matches");
        sub.assert_true(security::match_cors_origin_pattern("https://stage.app.example.com", pattern), "nested subdomain matches");

        // Protocol mismatch: HTTP must NOT match HTTPS pattern!
        sub.assert_false(security::match_cors_origin_pattern("http://api.example.com", pattern), "insecure HTTP rejected against HTTPS pattern");

        // Domain mismatch
        sub.assert_false(security::match_cors_origin_pattern("https://attacker-example.com", pattern), "suffix confusion attack rejected");
        sub.assert_false(security::match_cors_origin_pattern("https://example.com", pattern), "apex domain rejected by wildcard prefix");
        sub.assert_false(security::match_cors_origin_pattern("https://attacker.com", "https://*.com"), "TLD wildcard pattern rejected");
    };

    t.run("CORS Preflight (OPTIONS) & Actual Request Evaluation") { sub =>
        var policy = security::CorsPolicy { .. };
        security::add_allowed_origin(policy, "https://portal.example.com");
        policy.allow_credentials = true;
        policy.max_age_sec = 7200;

        // Preflight request
        var preflight_req = http::new_request("OPTIONS", "/api/v1/resource");
        http::set_header(preflight_req, "Origin", "https://portal.example.com");
        http::set_header(preflight_req, "Access-Control-Request-Method", "POST");
        http::set_header(preflight_req, "Access-Control-Request-Headers", "Content-Type, Authorization");

        var preflight_res = http::Response { .. };
        let preflight_res_code = security::evaluate_cors(policy, preflight_req, preflight_res);
        sub.assert_true(preflight_res_code == security::CorsResult.AllowedPreflight, "preflight handled cleanly");
        sub.assert_eq(preflight_res.status_code, 204, "preflight returns 204 No Content");

        sub.assert_true(preflight_res.has_header("Access-Control-Allow-Origin"), "Access-Control-Allow-Origin present");
        sub.assert_eq(preflight_res.header("Access-Control-Allow-Origin"), "https://portal.example.com", "origin mirrored");
        sub.assert_true(preflight_res.has_header("Access-Control-Allow-Credentials"), "Access-Control-Allow-Credentials present");
        sub.assert_eq(preflight_res.header("Access-Control-Allow-Credentials"), "true", "credentials allowed");
        sub.assert_true(preflight_res.has_header("Access-Control-Max-Age"), "Access-Control-Max-Age present");
        sub.assert_eq(preflight_res.header("Access-Control-Max-Age"), "7200", "max age matches");
        sub.assert_true(preflight_res.has_header("Vary"), "Vary header present on dynamic origin");
        sub.assert_eq(preflight_res.header("Vary"), "Origin", "Vary mirrors Origin");
    };

    t.run("CORS Wildcard with Credentials Rejection") { sub =>
        var policy = security::CorsPolicy { .. };
        security::add_allowed_origin(policy, "*");
        policy.allow_credentials = true; // Illegal combination per W3C CORS / Fetch spec

        var req = http::new_request("GET", "/api/data");
        http::set_header(req, "Origin", "https://untrusted.com");

        var res = http::Response { .. };
        let res_code = security::evaluate_cors(policy, req, res);
        sub.assert_true(res_code == security::CorsResult.InvalidConfig, "wildcard with allow_credentials rejected with InvalidConfig");
    };

    t.run("CORS Multi-Origin Wildcard with Credentials Rejection (Fetch §3.2.2)") { sub =>
        var policy = security::CorsPolicy { .. };
        security::add_allowed_origin(policy, "https://portal.example.com");
        security::add_allowed_origin(policy, "*");
        policy.allow_credentials = true; // Illegal per Fetch spec §3.2.2 even if multiple origins present

        var req = http::new_request("GET", "/api/data");
        http::set_header(req, "Origin", "https://portal.example.com");

        var res = http::Response { .. };
        let res_code = security::evaluate_cors(policy, req, res);
        sub.assert_true(res_code == security::CorsResult.InvalidConfig, "wildcard in multi-origin with allow_credentials rejected with InvalidConfig");
    };

    t.run("CORS Null Origin & Sandboxed Iframe Rejection (RFC 6454)") { sub =>
        // 1. Wildcard policy without credentials must NOT match Origin: null (sandboxed iframe / data: URI bypass)
        var wild_policy = security::CorsPolicy { .. };
        security::add_allowed_origin(wild_policy, "*");
        wild_policy.allow_credentials = false;

        var iframe_req = http::new_request("GET", "/api/data");
        http::set_header(iframe_req, "Origin", "null");
        var iframe_res = http::Response { .. };
        let wild_null_code = security::evaluate_cors(wild_policy, iframe_req, iframe_res);
        sub.assert_true(wild_null_code == security::CorsResult.RejectedOrigin, "Origin: null rejected against wildcard pattern");
        sub.assert_false(iframe_res.has_header("Access-Control-Allow-Origin"), "never reflect Access-Control-Allow-Origin: null");

        // 2. Case-insensitive "NULL" rejection when allow_credentials is true
        var cred_policy = security::CorsPolicy { .. };
        security::add_allowed_origin(cred_policy, "https://app.example.com");
        cred_policy.allow_credentials = true;

        var upper_null_req = http::new_request("GET", "/api/user");
        http::set_header(upper_null_req, "Origin", "NULL");
        var upper_null_res = http::Response { .. };
        let upper_code = security::evaluate_cors(cred_policy, upper_null_req, upper_null_res);
        sub.assert_true(upper_code == security::CorsResult.RejectedOrigin, "Origin: NULL rejected when credentials enabled");
    };
}

// ----------------------------------------------------------------------------
// 5. Constant-Time CSRF Token Validation & OTP Mask Verification
// ----------------------------------------------------------------------------
fn test_csrf_constant_time_tokens(t: lit::T&) {
    t.run("Double-Submit Token Validation (subtle_equal)") { sub =>
        let tok1 = "3b9a1f4c7e2d8a0b5c4f3e2d1a0b9c8d";
        let tok2 = "3b9a1f4c7e2d8a0b5c4f3e2d1a0b9c8d";
        let tok3 = "3b9a1f4c7e2d8a0b5c4f3e2d1a0b9c8e"; // last byte differs
        let tok4 = "3b9a1f4c7e2d8a0b"; // shorter

        sub.assert_true(security::validate_csrf_token(tok1, tok2), "matching tokens valid");
        sub.assert_false(security::validate_csrf_token(tok1, tok3), "differing last byte invalid");
        sub.assert_false(security::validate_csrf_token(tok1, tok4), "different length invalid");
        sub.assert_false(security::validate_csrf_token("", ""), "empty tokens invalid");
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
        sub.assert_true(security::mask_csrf_token(mask1[..], raw[..], masked1), "masking succeeds");
        sub.assert_eq(masked1.len, 32, "masked token is 32 bytes");
        sub.assert_true(security::verify_masked_csrf_token(masked1[..], raw[..]), "masked token 1 verifies against raw secret");

        // Different mask for same secret
        let mask2: const u8[16] = [
            0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
            0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10,
        ];
        var masked2: u8[..32] = [];
        sub.assert_true(security::mask_csrf_token(mask2[..], raw[..], masked2), "masking 2 succeeds");
        sub.assert_true(security::verify_masked_csrf_token(masked2[..], raw[..]), "masked token 2 verifies against same raw secret");

        // Tampered masked token
        masked1[20] ^= 0x01;
        sub.assert_false(security::verify_masked_csrf_token(masked1[..], raw[..]), "tampered token fails verification");

        // Wrong length
        sub.assert_false(security::verify_masked_csrf_token(masked1[..16], raw[..]), "truncated token fails verification");
    };

    t.run("Constant-Time Case-Fold Origin Host Comparison") { sub =>
        sub.assert_true(security::subtle_equal_ascii_fold("example.com", "EXAMPLE.COM"), "case-insensitive match");
        sub.assert_true(security::subtle_equal_ascii_fold("secure.bank.com:8443", "secure.bank.com:8443"), "identical match");
        sub.assert_false(security::subtle_equal_ascii_fold("attacker.com", "victim.com"), "different hosts mismatch");
        sub.assert_false(security::subtle_equal_ascii_fold("victim.com.evil", "victim.com"), "prefix mismatch");
    };
}

// --- Component: security_edge_filter ---
// Test Suite for Goose-Wing Programmable L7 Edge Filter Engine.

// ----------------------------------------------------------------------------
// 6. Edge Filter Lifecycle and Evaluation
// ----------------------------------------------------------------------------
fn test_edge_filter_lifecycle_and_evaluation(t: lit::T&) {
    t.run("Case 1: Edge Filter Rule Registration and Path Filtering") { sub =>
        var filter = server::EdgeFilter { .. };
        sub.assert_true(filter.enabled, "Filter enabled by default");
        sub.assert_eq(filter.rules.len, 0, "Initial rules empty");

        // Add rules:
        // 1. Block /admin without header
        let r_admin = server::make_edge_filter_rule(
            "admin-protect",
            "/admin",
            server::EdgeFilterVerdict.BlockForbidden,
        );
        sub.assert_true(server::add_edge_filter_rule(filter, r_admin), "Admin rule added");

        // 2. Throttle /api/heavy
        let r_heavy = server::make_edge_filter_rule(
            "heavy-throttle",
            "/api/heavy",
            server::EdgeFilterVerdict.ThrottleRate,
        );
        sub.assert_true(server::add_edge_filter_rule(filter, r_heavy), "Heavy throttle rule added");

        // Evaluate /public/index.html -> Pass
        var empty_headers = http::HeaderMap { .. };
        let v1 = server::evaluate_edge_filter(filter, "GET", "/public/index.html", empty_headers);
        sub.assert_true(v1 == server::EdgeFilterVerdict.Pass, "Public path passes");

        // Evaluate /admin/users -> BlockForbidden (403)
        let v2 = server::evaluate_edge_filter(filter, "POST", "/admin/users", empty_headers);
        sub.assert_true(v2 == server::EdgeFilterVerdict.BlockForbidden, "Admin path blocked");

        // Evaluate /api/heavy/compute -> ThrottleRate (429)
        let v3 = server::evaluate_edge_filter(filter, "POST", "/api/heavy/compute", empty_headers);
        sub.assert_true(v3 == server::EdgeFilterVerdict.ThrottleRate, "Heavy path throttled");

        sub.assert_eq(filter.total_inspected as i64, 3, "Total inspected count");
        sub.assert_eq(filter.total_blocked as i64, 2, "Total blocked count");
    };

    t.run("Case 2: Required Header Condition") { sub =>
        var filter = server::EdgeFilter { .. };
        var rule = server::make_edge_filter_rule("api-key-gate", "/v1/secure", server::EdgeFilterVerdict.BlockForbidden);
        rule.required_header.append("X-API-Key");
        let _ = server::add_edge_filter_rule(filter, rule);

        // Missing header -> Block
        var hdrs_missing = http::HeaderMap { .. };
        http::append_header(hdrs_missing, "Authorization", "Bearer tok");
        let v_deny = server::evaluate_edge_filter(filter, "GET", "/v1/secure/data", hdrs_missing);
        sub.assert_true(v_deny == server::EdgeFilterVerdict.BlockForbidden, "Missing required header blocked");

        // Present header -> Pass
        var hdrs_ok = http::HeaderMap { .. };
        http::append_header(hdrs_ok, "X-API-Key", "secret-key-123");
        let v_allow = server::evaluate_edge_filter(filter, "GET", "/v1/secure/data", hdrs_ok);
        sub.assert_true(v_allow == server::EdgeFilterVerdict.Pass, "Present required header allowed");
    };
}

// --- Component: security_hsts ---
// Verification suite for RFC 6797 HTTP Strict Transport Security (HSTS):
// 1. Header parsing (max-age, includeSubDomains, preload)
// 2. Static Preload List matcher (.dev, .app TLDs & major secure domains)
// 3. Dynamic HSTS Cache learning & pre-flight URL auto-upgrade (http:// -> https://)
// 4. Subdomain inheritance with `includeSubDomains`
// 5. Deletion of Known HSTS Host (`max-age=0`)
// 6. RFC 6797 Section 8.1 Security Invariant: Rejection of HSTS over insecure HTTP

// ----------------------------------------------------------------------------
// 7. HSTS Header Directive Parsing
// ----------------------------------------------------------------------------
fn test_hsts_header_parsing(t: lit::T&) {
    t.run("Parse max-age, includeSubDomains, and preload") { sub =>
        let raw = "max-age=31536000; includeSubDomains; preload";
        let d, ok = http::parse_hsts_header(raw);
        sub.assert_true(ok, "hsts parsed successfully");
        sub.assert_eq(d.max_age_sec, 31536000, "max-age is 1 year in seconds");
        sub.assert_true(d.include_subdomains, "includeSubDomains is true");
        sub.assert_true(d.preload, "preload is true");

        // Case-insensitive and whitespace-tolerant
        let raw2 = "  includeSubDomains ;  MAX-AGE = 86400  ";
        let d2, ok2 = http::parse_hsts_header(raw2);
        sub.assert_true(ok2, "case-insensitive hsts parsed");
        sub.assert_eq(d2.max_age_sec, 86400, "max-age 86400");
        sub.assert_true(d2.include_subdomains, "includeSubDomains matched");
        sub.assert_false(d2.preload, "preload not present");
    };
}

// ----------------------------------------------------------------------------
// 8. Chromium Static Preload List & .dev/.app Auto-Upgrade
// ----------------------------------------------------------------------------
fn test_hsts_preload_list_auto_upgrade(t: lit::T&) {
    t.run("Chromium Preload List: Google, GitHub & .dev/.app TLDs Auto-Upgraded to HTTPS") { sub =>
        var client = client::new_client();

        // 1. Static preloaded domain (github.com & expanded preload domains)
        sub.assert_true(client::is_hsts(client, "github.com"), "github.com is preloaded HSTS");
        sub.assert_true(client::is_hsts(client, "api.github.com"), "api.github.com inherits HSTS");
        sub.assert_true(client::is_hsts(client, "stripe.com"), "stripe.com is preloaded HSTS");
        sub.assert_true(client::is_hsts(client, "api.stripe.com"), "api.stripe.com inherits HSTS");
        sub.assert_true(client::is_hsts(client, "proton.me"), "proton.me is preloaded HSTS");
        sub.assert_true(client::is_hsts(client, "1password.com"), "1password.com is preloaded HSTS");

        // 2. HSTS TLD (.dev, .app, .page, .bank, .insurance, .chrome, .goog, .youtube, .zip)
        sub.assert_true(client::is_hsts(client, "myproject.dev"), ".dev TLD is always HSTS");
        sub.assert_true(client::is_hsts(client, "coolservice.app"), ".app TLD is always HSTS");
        sub.assert_true(client::is_hsts(client, "secure.insurance"), ".insurance TLD is always HSTS");
        sub.assert_true(client::is_hsts(client, "portal.chrome"), ".chrome TLD is always HSTS");
        sub.assert_true(client::is_hsts(client, "archive.zip"), ".zip TLD is always HSTS");

        // 3. Regular non-HSTS domain
        sub.assert_false(client::is_hsts(client, "example.com"), "example.com is not HSTS");

        // 4. Test pre-flight URL rewrite
        // Mock the HTTPS route
        client::mock_route(client, "GET", "https://github.com/trending", 200, "{\"repos\":[]}");

        // Client initiates GET with http://github.com/trending
        let resp, err = client::get(client, "http://github.com/trending");
        sub.assert_true(http::ok(err), "request succeeded");
        sub.assert_eq(http::status(resp), 200, "status 200");
        // Effective URL must be https://, not cleartext http://!
        sub.assert_bytes_eq(resp.effective_url[..8], "https://", "URL was transparently upgraded to https:// before dispatch");

        // 5. Userinfo and IPv6 authority handling in split_http_url and hsts_upgrade_url
        let u_host, u_port, u_rem, u_ok = http::split_http_url("http://alice:secret@github.com:8080/org/repo?x=1");
        sub.assert_true(u_ok, "split_http_url with userinfo ok");
        sub.assert_bytes_eq(u_host, "github.com", "host extracted after userinfo@");
        sub.assert_bytes_eq(u_port, "8080", "port extracted after host");
        sub.assert_bytes_eq(u_rem, "/org/repo?x=1", "remainder preserved");

        var upgraded_userinfo: u8[..256] = [];
        sub.assert_true(
            http::hsts_upgrade_url(client.hsts, "http://alice:secret@github.com:8080/org/repo", 1700000000, upgraded_userinfo),
            "hsts_upgrade_url upgrades URL with userinfo",
        );
        sub.assert_bytes_eq(
            upgraded_userinfo[..],
            "https://alice:secret@github.com:8080/org/repo",
            "userinfo and custom port preserved during HSTS upgrade",
        );

        let v6_host, v6_port, v6_rem, v6_ok = http::split_http_url("http://[2001:db8::1]:8080/status");
        sub.assert_true(v6_ok, "split_http_url with IPv6 literal ok");
        sub.assert_bytes_eq(v6_host, "[2001:db8::1]", "IPv6 bracketed host preserved without splitting on internal colons");
        sub.assert_bytes_eq(v6_port, "8080", "IPv6 port extracted cleanly");
        sub.assert_bytes_eq(v6_rem, "/status", "IPv6 remainder preserved");
        sub.assert_false(
            http::hsts_upgrade_url(client.hsts, "http://[2001:db8::1]:8080/status", 1700000000, upgraded_userinfo),
            "RFC 6797 §8.1.1: IPv6 literal is never an HSTS host",
        );
    };
}

// ----------------------------------------------------------------------------
// 9. Dynamic HSTS Cache Lifecycle, Subdomains & Security Invariants
// ----------------------------------------------------------------------------
fn test_dynamic_hsts_cache_lifecycle(t: lit::T&) {
    t.run("Dynamic Learning: Response Header Upgrades Subsequent Cleartext Requests") { sub =>
        var client = client::new_client();
        client::set_clock_us(client, 1700000000000000); // t0

        sub.assert_false(client::is_hsts(client, "mycorp.internal"), "not HSTS initially");

        // 1. Visit HTTPS site which serves Strict-Transport-Security header
        client::mock_route(client, "GET", "https://mycorp.internal/login", 200, "login-page");
        client::add_mock_header(client, "Strict-Transport-Security", "max-age=3600; includeSubDomains");

        let resp1, err1 = client::get(client, "https://mycorp.internal/login");
        sub.assert_true(http::ok(err1), "initial https login ok");

        // Client has now recorded HSTS for mycorp.internal and its subdomains
        sub.assert_true(client::is_hsts(client, "mycorp.internal"), "now known HSTS host");
        sub.assert_true(client::is_hsts(client, "api.mycorp.internal"), "subdomain also protected");

        // 2. Next request: user enters plain http://mycorp.internal/dashboard
        client::mock_route(client, "GET", "https://mycorp.internal/dashboard", 200, "dashboard-secure-content");

        let resp2, err2 = client::get(client, "http://mycorp.internal/dashboard");
        sub.assert_true(http::ok(err2), "dashboard request ok");
        sub.assert_bytes_eq(resp2.effective_url[..8], "https://", "http:// upgraded to https:// preventing SSL stripping");
        sub.assert_bytes_eq(resp2.body[..], "dashboard-secure-content", "secure content returned");
    };

    t.run("HSTS Deletion Directive (max-age=0)") { sub =>
        var client = client::new_client();
        client::set_clock_us(client, 1700000000000000);

        // Learn HSTS
        client::mock_route(client, "GET", "https://service.org/start", 200, "ok");
        client::add_mock_header(client, "Strict-Transport-Security", "max-age=7200");
        let _, _ = client::get(client, "https://service.org/start");
        sub.assert_true(client::is_hsts(client, "service.org"), "hsts active");

        // Server sends max-age=0 to revoke HSTS
        client::mock_route(client, "GET", "https://service.org/revoke", 200, "revoked");
        client::add_mock_header(client, "Strict-Transport-Security", "max-age=0");
        let _, _ = client::get(client, "https://service.org/revoke");

        // Host must now be deleted from known HSTS hosts
        sub.assert_false(client::is_hsts(client, "service.org"), "hsts revoked via max-age=0");
    };

    t.run("RFC 6797 Section 8.1 Security Invariant: Rejection Over Insecure HTTP") { sub =>
        var client = client::new_client();
        client::set_clock_us(client, 1700000000000000);

        // Insecure plain HTTP server tries to assert HSTS
        client::mock_route(client, "GET", "http://insecure.test/page", 200, "insecure-page");
        client::add_mock_header(client, "Strict-Transport-Security", "max-age=31536000");

        let _, _ = client::get(client, "http://insecure.test/page");

        // RFC 6797 Section 8.1: Must be rejected and ignored!
        sub.assert_false(client::is_hsts(client, "insecure.test"), "HSTS header ignored over plain HTTP");
    };

    t.run("HSTS Cache Persistence (save_hsts_cache / load_hsts_cache) & 128-Entry Capacity") { sub =>
        var client1 = client::new_client();
        client::set_clock_us(client1, 1700000000000000);

        // Populate 20 distinct dynamic HSTS hosts (exceeding old 16-entry cap)
        for i in 20 {
            var host_buf: u8[..64] = [];
            host_buf.append("host");
            format(host_buf, i);
            host_buf.append(".example.org");
            sub.assert_true(
                http::hsts_cache_update(client1.hsts, host_buf[..], "max-age=3600; includeSubDomains; preload", 1700000000),
                "hsts_cache_update succeeds for all 20 hosts",
            );
        }

        // Verify all 20 hosts remain active without eviction
        for i in 20 {
            var host_buf: u8[..64] = [];
            host_buf.append("host");
            format(host_buf, i);
            host_buf.append(".example.org");
            sub.assert_true(client::is_hsts(client1, host_buf[..]), "all 20 hosts retained in 128-entry HstsCache");
        }

        // Serialize HSTS cache
        var persisted: u8[>..] = [];
        let saved_count = client::export_hsts(client1, persisted);
        sub.assert_eq(saved_count, 20, "all 20 active entries exported");

        // Load into a fresh client at t = 1700000500
        var client2 = client::new_client();
        client::set_clock_us(client2, 1700000500000000);
        let loaded_count = client::import_hsts(client2, persisted[..]);
        sub.assert_eq(loaded_count, 20, "all 20 unexpired entries imported");
        sub.assert_true(client::is_hsts(client2, "sub.host0.example.org"), "imported subdomain HSTS active");
        sub.assert_true(client::is_hsts(client2, "host19.example.org"), "imported 20th host HSTS active");

        // Loading after expiry (t = 1700004000) skips expired entries
        var client3 = client::new_client();
        client::set_clock_us(client3, 1700004000000000);
        let expired_loaded = client::import_hsts(client3, persisted[..]);
        sub.assert_eq(expired_loaded, 0, "expired entries skipped on import");
    };
}

// --- Component: security_protocol ---
// Tests for SSRF guard filtering, scheme downgrade sanitization, and URL resolution.

// ----------------------------------------------------------------------------
// Round 1: IPv4-Mapped IPv6 SSRF Defense
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 10. IPv4-Mapped IPv6 SSRF Defense
// ----------------------------------------------------------------------------
fn test_ipv4_mapped_ipv6_ssrf(t: lit::T&) {
    t.run("IPv4-Mapped IPv6 Loopback and Private Address SSRF Blocking") { sub =>
        var session = client::new_session();
        session.ssrf_guard.enabled = true;
        session.ssrf_guard.deny_local_network = true;

        // 1. IPv4-mapped loopback (127.0.0.1)
        var req_loop = http::new_get("http://[::ffff:127.0.0.1]/admin");
        let res_loop, err_loop = client::execute_request(session, req_loop);
        sub.assert_false(http::ok(err_loop), "[::ffff:127.0.0.1] loopback must be blocked by SSRF guard");

        // 2. IPv4-mapped cloud metadata (169.254.169.254)
        var req_meta = http::new_get("http://[::ffff:169.254.169.254]/latest/meta-data/");
        let res_meta, err_meta = client::execute_request(session, req_meta);
        sub.assert_false(http::ok(err_meta), "[::ffff:169.254.169.254] cloud metadata must be blocked by SSRF guard");

        // 3. IPv4-mapped RFC 1918 private subnet (10.0.0.1)
        var req_priv10 = http::new_get("http://[::ffff:10.0.0.1]/internal");
        let res_priv10, err_priv10 = client::execute_request(session, req_priv10);
        sub.assert_false(http::ok(err_priv10), "[::ffff:10.0.0.1] private 10.x must be blocked by SSRF guard");

        // 4. IPv4-mapped RFC 1918 private subnet (192.168.1.1)
        var req_priv192 = http::new_get("http://[::ffff:192.168.1.1]/router");
        let res_priv192, err_priv192 = client::execute_request(session, req_priv192);
        sub.assert_false(http::ok(err_priv192), "[::ffff:192.168.1.1] private 192.168.x must be blocked by SSRF guard");

        // 5. IPv4-mapped RFC 1918 private subnet (172.16.0.1)
        var req_priv172 = http::new_get("http://[::ffff:172.16.0.1]/backend");
        let res_priv172, err_priv172 = client::execute_request(session, req_priv172);
        sub.assert_false(http::ok(err_priv172), "[::ffff:172.16.0.1] private 172.16.x must be blocked by SSRF guard");

        // 6. Direct hex-format IPv4-mapped loopback [::ffff:7f00:1]
        var req_hex_loop = http::new_get("http://[::ffff:7f00:1]/status");
        let res_hex_loop, err_hex_loop = client::execute_request(session, req_hex_loop);
        sub.assert_false(http::ok(err_hex_loop), "[::ffff:7f00:1] hex loopback must be blocked by SSRF guard");

        // 7. Direct hex-format IPv4-mapped cloud metadata [::ffff:a9fe:a9fe]
        var req_hex_meta = http::new_get("http://[::ffff:a9fe:a9fe]/meta");
        let res_hex_meta, err_hex_meta = client::execute_request(session, req_hex_meta);
        sub.assert_false(http::ok(err_hex_meta), "[::ffff:a9fe:a9fe] hex metadata must be blocked by SSRF guard");
    };

    t.run("DNS Rebinding with IPv4-Mapped IPv6 Resolved Address") { sub =>
        var session = client::new_session();
        session.ssrf_guard.enabled = true;
        session.ssrf_guard.deny_local_network = true;

        // Hostname resolves to IPv4-mapped loopback address
        client::mock_route(session, "GET", "http://rebind.target.com/api", 200, "ok");
        client::add_mock_resolved_ip(session, "::ffff:127.0.0.1");

        var req = http::new_get("http://rebind.target.com/api");
        let res, err = client::execute_request(session, req);
        sub.assert_false(http::ok(err), "DNS rebinding with ::ffff:127.0.0.1 must be blocked");

        // Hostname resolves to hex IPv4-mapped loopback address ::ffff:7f00:1
        client::mock_route(session, "GET", "http://rebind2.target.com/api", 200, "ok");
        client::add_mock_resolved_ip(session, "::ffff:7f00:1");

        var req2 = http::new_get("http://rebind2.target.com/api");
        let res2, err2 = client::execute_request(session, req2);
        sub.assert_false(http::ok(err2), "DNS rebinding with ::ffff:7f00:1 must be blocked");
    };
}

// ----------------------------------------------------------------------------
// Round 2: Scheme Downgrade Header Sanitization
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 11. Scheme Downgrade Header Sanitization
// ----------------------------------------------------------------------------
fn test_scheme_downgrade_with_trusted_hosts(t: lit::T&) {
    t.run("sanitize_headers_on_redirect: Scheme Downgrade to Trusted Host Strips Sensitive Headers") { sub =>
        var req = http::new_get("https://example.com/secure");
        http::set_header(req, "Authorization", "Basic YWxhZGRpbjpvcGVuc2VzYW1l");
        http::set_header(req, "X-API-Key", "super-secret-token");
        http::set_header(req, "Custom-Key", "public-data");

        let redirect_info = client::compute_redirect_info(
            "GET", 302, "https://example.com/secure", "http://example.com/insecure",
            client::ReferrerPolicy.NoReferrerWhenDowngrade, "https://example.com/secure",
            client::RedirectOptions { .. },
        );
        sub.assert_true(redirect_info.is_scheme_downgrade, "scheme downgrade detected");

        // When trusted_location_forwarding is true, scheme downgrade MUST STILL strip sensitive headers per RFC 9110
        client::sanitize_headers_on_redirect(
            req.headers,
            redirect_info,
            client::RedirectSanitizeOptions { enable_referer: true, trusted_location_forwarding: true },
        );

        let has_auth = http::has_header(req.headers, "Authorization");
        let has_api_key = http::has_header(req.headers, "X-API-Key");
        let has_custom = http::has_header(req.headers, "Custom-Key");

        sub.assert_false(has_auth, "Authorization must be stripped on scheme downgrade even if host is trusted");
        sub.assert_false(has_api_key, "X-API-Key must be stripped on scheme downgrade even if host is trusted");
        sub.assert_true(has_custom, "Non-sensitive header Custom-Key is preserved");
    };

    t.run("ClientSession End-to-End: Scheme Downgrade to Trusted Host Strips Credentials") { sub =>
        var session = client::new_session();
        client::trust_location_host(session, "example.com");

        // Route 1: HTTPS endpoint redirects to HTTP on trusted host example.com
        client::mock_route(session, "GET", "https://example.com/login", 302, "");
        client::add_mock_header(session, "Location", "http://example.com/cleartext_api");

        // Route 2: Destination cleartext HTTP endpoint
        client::mock_route(session, "GET", "http://example.com/cleartext_api", 200, "{\"ok\":true}");

        var req = http::new_get("https://example.com/login");
        http::set_header(req, "Authorization", "Bearer top_secret_credential");

        let res, err = client::execute_request(session, req);
        sub.assert_true(http::ok(err), "request succeeded");
        sub.assert_eq(res.status_code, 200, "final status 200");

        let sent_auth = http::has_sent_header(res, "Authorization");
        sub.assert_false(sent_auth, "Authorization header must not be sent over cleartext HTTP on scheme downgrade");
    };

    t.run("Cross-Origin HTTPS -> HTTPS to Trusted Host Preserves Credentials") { sub =>
        var req = http::new_get("https://app.client.com/data");
        http::set_header(req, "Authorization", "Bearer shared_token");

        // Cross-origin redirect, but both ends are secure HTTPS
        let redirect_info = client::compute_redirect_info(
            "GET", 302, "https://app.client.com/data", "https://api.trusted.com/data",
            client::ReferrerPolicy.StrictOriginWhenCrossOrigin, "https://app.client.com/data",
            client::RedirectOptions { .. },
        );
        sub.assert_true(redirect_info.is_cross_origin, "cross origin redirect");
        sub.assert_false(redirect_info.is_scheme_downgrade, "no scheme downgrade");

        // With trusted_location_forwarding = true on HTTPS -> HTTPS, credentials are preserved
        client::sanitize_headers_on_redirect(
            req.headers,
            redirect_info,
            client::RedirectSanitizeOptions { enable_referer: true, trusted_location_forwarding: true },
        );

        let has_auth = http::has_header(req.headers, "Authorization");
        sub.assert_true(has_auth, "Authorization is preserved for trusted cross-origin HTTPS -> HTTPS");
    };
}

// ----------------------------------------------------------------------------
// Round 3: File URL Windows Drive Compliance
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 12. File URL Windows Drive Compliance
// ----------------------------------------------------------------------------
fn test_file_url_windows_drive_compliance(t: lit::T&) {
    t.run("WHATWG URL Section 4.4: Windows Drive Letter Pipe Normalization (| to :)") { sub =>
        // 1. file:///C|/... must normalize to file:///C:/...
        let u_pipe, err_pipe = core::parse_url("file:///C|/Users/admin/report.pdf");
        sub.assert_true(u_pipe.valid, "file:///C|/... is valid file url");
        sub.assert_bytes_eq(core::pathname(u_pipe), "/C:/Users/admin/report.pdf", "pathname normalized pipe to colon /C:/");
        sub.assert_bytes_eq(core::href(u_pipe), "file:///C:/Users/admin/report.pdf", "href normalized pipe to colon");

        // 2. Native file_path extraction succeeds on normalized drive letter
        var os_path: u8[..256] = [];
        let ok_path = core::file_path(u_pipe, os_path);
        sub.assert_true(ok_path, "file_path succeeded on pipe-normalized drive URL");
        sub.assert_bytes_eq(os_path[..], "C:\\Users\\admin\\report.pdf", "extracted native Windows backslash path");

        // 3. new_file_url with pipe notation C|\... normalizes to file:///C:/...
        let u_pipe_native = core::new_file_url("C|\\Projects\\app\\main.goose");
        sub.assert_true(u_pipe_native.valid, "new_file_url accepts C|\\ path");
        sub.assert_bytes_eq(core::pathname(u_pipe_native), "/C:/Projects/app/main.goose", "new_file_url normalized C| to /C:/");
    };

    t.run("WHATWG URL Section 4.4: Root-Relative Path Preserves Base Windows Drive Letter") { sub =>
        let base_file = core::new_url("file:///C:/Users/admin/app/index.html");
        sub.assert_true(base_file.valid, "base file URL is valid");

        // 1. Root-relative forward slash /assets/logo.png resolves to file:///C:/assets/logo.png
        let rel_slash = core::new_url("/assets/logo.png", base_file);
        sub.assert_true(rel_slash.valid, "resolved root-relative URL is valid");
        sub.assert_bytes_eq(core::href(rel_slash), "file:///C:/assets/logo.png", "drive letter C: preserved on root-relative /assets/logo.png");

        var path_slash: u8[..256] = [];
        let ok_slash = core::file_path(rel_slash, path_slash);
        sub.assert_true(ok_slash, "file_path succeeded on resolved root-relative URL");
        sub.assert_bytes_eq(path_slash[..], "C:\\assets\\logo.png", "extracted Windows path retains drive letter");

        // 2. Root-relative backslash \styles\app.css resolves to file:///C:/styles/app.css
        let rel_bs = core::new_url("\\styles\\app.css", base_file);
        sub.assert_true(rel_bs.valid, "resolved root-relative backslash URL is valid");
        sub.assert_bytes_eq(core::href(rel_bs), "file:///C:/styles/app.css", "drive letter C: preserved on root-relative \\styles\\app.css");

        var path_bs: u8[..256] = [];
        let ok_bs = core::file_path(rel_bs, path_bs);
        sub.assert_true(ok_bs, "file_path succeeded on backslash resolved URL");
        sub.assert_bytes_eq(path_bs[..], "C:\\styles\\app.css", "extracted Windows path from backslash retains drive letter");

        // 3. Explicit alternative drive letter in reference overrides base drive letter
        let rel_other = core::new_url("/E:/data/store.db", base_file);
        sub.assert_bytes_eq(core::href(rel_other), "file:///E:/data/store.db", "explicit drive E: overrides base drive C:");
    };
}

// --- Component: security_txt ---
// Verification Suite for RFC 9116 (A File Format to Aid in Security Vulnerability Disclosure - security.txt).

// ----------------------------------------------------------------------------
// 13. RFC 9116 security.txt Validation Matrix
// ----------------------------------------------------------------------------
fn test_security_txt_valid_matrix(t: lit::T&) {
    t.run("1. Valid security.txt Parsing with Comments and PGP Armor") { sub =>
        let valid_payload = "# RFC 9116 security.txt disclosure policy\n-----BEGIN PGP SIGNED MESSAGE-----\nHash: SHA256\n\nContact: mailto:security@example.com\nContact: https://example.com/security\nExpires: 2030-12-31T23:59:59Z\nEncryption: https://example.com/pgp-key.txt\nCanonical: https://example.com/.well-known/security.txt\nAcknowledgments: https://example.com/hall-of-fame\nPolicy: https://example.com/disclosure-policy\nHiring: https://example.com/security-jobs\nPreferred-Languages: en, ru, de\n\n-----BEGIN PGP SIGNATURE-----\nVersion: OpenPrivacy\n...\n";

        let now_epoch: i64 = 1700000000; // Nov 2023
        let sec = http::parse_security_txt(valid_payload, now_epoch);

        sub.assert_true(sec.is_valid, "Valid security.txt marked valid");
        sub.assert_eq(sec.status, http::SEC_TXT_OK, "Status is SEC_TXT_OK");
        sub.assert_eq(sec.contact.len, 2, "2 contacts parsed");
        sub.assert_bytes_eq(sec.contact[0][..], "mailto:security@example.com", "Contact 1 matches");
        sub.assert_bytes_eq(sec.contact[1][..], "https://example.com/security", "Contact 2 matches");
        sub.assert_bytes_eq(sec.expires[..], "2030-12-31T23:59:59Z", "Expires matches");
        sub.assert_true(sec.expires_unix > now_epoch, "Expires timestamp is in future");
        sub.assert_eq(sec.encryption.len, 1, "1 encryption URI");
        sub.assert_bytes_eq(sec.canonical[0][..], "https://example.com/.well-known/security.txt", "Canonical matches");
        sub.assert_bytes_eq(sec.preferred_languages[..], "en, ru, de", "Preferred-Languages matches");
    };

    t.run("2. Mandatory Contact Field Enforcement (RFC 9116 §2.5.3)") { sub =>
        let missing_contact = "Expires: 2030-12-31T23:59:59Z\nCanonical: https://example.com/.well-known/security.txt\n";

        let sec = http::parse_security_txt(missing_contact, 0);
        sub.assert_false(sec.is_valid, "Missing contact must not be valid");
        sub.assert_eq(sec.status, http::SEC_TXT_ERR_MISSING_CONTACT, "Status indicates missing contact");
    };

    t.run("3. Mandatory Expires Field Enforcement (RFC 9116 §2.5.5)") { sub =>
        let missing_expires = "Contact: mailto:security@example.com\n";

        let sec = http::parse_security_txt(missing_expires, 0);
        sub.assert_false(sec.is_valid, "Missing expires must not be valid");
        sub.assert_eq(sec.status, http::SEC_TXT_ERR_MISSING_EXPIRES, "Status indicates missing expires");
    };

    t.run("4. Duplicate Expires Rejection") { sub =>
        let dup_expires = "Contact: mailto:security@example.com\nExpires: 2030-12-31T23:59:59Z\nExpires: 2031-12-31T23:59:59Z\n";

        let sec = http::parse_security_txt(dup_expires, 0);
        sub.assert_false(sec.is_valid, "Duplicate expires must be rejected");
        sub.assert_eq(sec.status, http::SEC_TXT_ERR_DUPLICATE_EXPIRES, "Status indicates duplicate expires");
    };

    t.run("5. Expired / Stale Timestamp Rejection") { sub =>
        let stale_txt = "Contact: mailto:security@example.com\nExpires: 2021-01-01T00:00:00Z\n";

        let now_epoch: i64 = 1700000000; // Nov 2023
        let sec = http::parse_security_txt(stale_txt, now_epoch);
        sub.assert_false(sec.is_valid, "Stale file must not be valid");
        sub.assert_true(sec.is_expired, "is_expired flag set");
        sub.assert_eq(sec.status, http::SEC_TXT_ERR_EXPIRED, "Status indicates expired file");
    };

    t.run("6. Canonical HTTPS Requirement (RFC 9116 §2.5.2)") { sub =>
        let insecure_canonical = "Contact: mailto:security@example.com\nExpires: 2030-12-31T23:59:59Z\nCanonical: http://example.com/.well-known/security.txt\n";

        let sec = http::parse_security_txt(insecure_canonical, 0);
        sub.assert_false(sec.is_valid, "Non-HTTPS canonical must fail");
        sub.assert_eq(sec.status, http::SEC_TXT_ERR_INVALID_CANONICAL, "Status indicates invalid canonical");
    };

    t.run("7. Roundtrip Format and Parse") { sub =>
        var orig = http::SecurityTxt { .. };
        orig.contact.push("mailto:cert@company.org");
        orig.expires.append("2032-06-30T12:00:00Z");
        orig.canonical.push("https://company.org/.well-known/security.txt");
        orig.policy.push("https://company.org/security-policy");
        orig.preferred_languages.append("en");

        var wire: u8[>..] = [];
        http::format_security_txt(orig, wire);

        let parsed = http::parse_security_txt(wire[..], 0);
        sub.assert_true(parsed.is_valid, "Formatted wire text re-parses as valid");
        sub.assert_bytes_eq(parsed.contact[0][..], "mailto:cert@company.org", "Roundtrip contact matches");
        sub.assert_bytes_eq(parsed.expires[..], "2032-06-30T12:00:00Z", "Roundtrip expires matches");
        sub.assert_bytes_eq(parsed.canonical[0][..], "https://company.org/.well-known/security.txt", "Roundtrip canonical matches");
        sub.assert_bytes_eq(parsed.policy[0][..], "https://company.org/security-policy", "Roundtrip policy matches");
        sub.assert_bytes_eq(parsed.preferred_languages[..], "en", "Roundtrip languages match");
    };

    t.run("8. Path Validation Helpers") { sub =>
        sub.assert_true(http::is_security_txt_path("/.well-known/security.txt"), "Standard well-known path matches");
        sub.assert_true(http::is_security_txt_path("/security.txt"), "Legacy root path matches");
        sub.assert_false(http::is_security_txt_path("/security"), "Non-matching path rejected");
        sub.assert_false(http::is_security_txt_path("/.well-known/other"), "Other well-known path rejected");
    };
}

// --- Component: security_ecosystem ---
// Verification Suite for Advanced Protocol Systems:
// - RFC 7838 Alt-Svc & H3 Promotion Engine
// - RFC 8297 103 Early Hints & RFC 8470 0-RTT Anti-Replay Guard
// - W3C No-Vary-Search Cache Normalization
// - RFC 9297 HTTP Capsules & RFC 9298 MASQUE CONNECT-UDP
// - HAR 1.2 Telemetry & Microsecond Waterfall Timing
// - Network Isolation Keys (NIK) State Partitioning

// ----------------------------------------------------------------------------
// 14. RFC 7838 Alt-Svc & H3 Promotion Engine
// ----------------------------------------------------------------------------
fn test_altsvc_and_h3_promotion(t: lit::T&) {
    t.run("1. RFC 7838 Alt-Svc Parsing & Format") { sub =>
        let raw = "h3=\":443\"; ma=86400; persist=1, h2=\"alt.example.com:8443\"; ma=3600";
        var endpoints: http::AltSvcEndpoint[..4] = [];
        let ok, is_clear = http::parse_altsvc_header(raw, endpoints);

        sub.assert_true(ok, "Parse valid Alt-Svc header");
        sub.assert_false(is_clear, "Not a clear directive");
        sub.assert_eq(endpoints.len, 2, "2 endpoints parsed");

        // Endpoint 1: h3
        sub.assert_bytes_eq(endpoints[0].proto[..], "h3", "Endpoint 1 proto is h3");
        sub.assert_eq(endpoints[0].port, 443, "Endpoint 1 port is 443");
        sub.assert_eq(endpoints[0].max_age_sec as i64, 86400, "Endpoint 1 max-age is 86400");
        sub.assert_true(endpoints[0].persist, "Endpoint 1 persist flag is true");

        // Endpoint 2: h2
        sub.assert_bytes_eq(endpoints[1].proto[..], "h2", "Endpoint 2 proto is h2");
        sub.assert_bytes_eq(endpoints[1].host[..], "alt.example.com", "Endpoint 2 alternate host");
        sub.assert_eq(endpoints[1].port, 8443, "Endpoint 2 port is 8443");
        sub.assert_eq(endpoints[1].max_age_sec as i64, 3600, "Endpoint 2 max-age is 3600");

        // Clear directive
        var empty_eps: http::AltSvcEndpoint[..4] = [];
        let ok_clr, is_clr = http::parse_altsvc_header("clear", empty_eps);
        sub.assert_true(ok_clr, "Parse clear succeeds");
        sub.assert_true(is_clr, "Is clear flag true");

        // Server-side format
        var server_hdr: u8[>..] = [];
        http::format_altsvc_header(server_hdr, "h3", 443, 86400, true);
        sub.assert_bytes_eq(server_hdr[..], "h3=\":443\"; ma=86400; persist=1", "Server Alt-Svc formatted");
    };

    t.run("2. Alt-Svc Cache Promotion & Backoff on Failure") { sub =>
        var cache = http::AltSvcCache { .. };
        let origin = "example.com:443";
        let raw = "h3=\":443\"; ma=1000";

        // Insert at t = 1000
        http::update(cache, origin, raw, 1000);

        // Lookup at t = 1500 (500s elapsed < 1000s max-age)
        var promoted_ep = http::AltSvcEndpoint { .. };
        let has_h3 = http::lookup_h3(cache, origin, 1500, promoted_ep);
        sub.assert_true(has_h3, "Lookup succeeds and promotes to HTTP/3");
        sub.assert_bytes_eq(promoted_ep.proto[..], "h3", "Promoted proto is h3");
        sub.assert_eq(promoted_ep.port, 443, "Promoted port is 443");

        // Simulate connection failure (e.g. UDP blocked by firewall)
        http::record_failure(cache, origin, 1501);

        // Immediate subsequent lookup at t = 1502 must fail (broken_until_sec active)
        var fail_ep = http::AltSvcEndpoint { .. };
        let is_broken = http::lookup_h3(cache, origin, 1502, fail_ep);
        sub.assert_false(is_broken, "Immediate lookup after failure returns false (backoff active)");

        // Clear directive invalidation
        http::update(cache, origin, "clear", 1600);
        let cleared = http::lookup_h3(cache, origin, 1600, fail_ep);
        sub.assert_false(cleared, "Clear directive purged origin from cache");
    };
}

// ----------------------------------------------------------------------------
// 15. RFC 8297 Early Hints & RFC 8470 0-RTT Anti-Replay
// ----------------------------------------------------------------------------
fn test_early_hints_and_replay_guard(t: lit::T&) {
    t.run("1. RFC 8297 103 Early Hints Link Preload / Preconnect") { sub =>
        let link_hdr = "</style.css>; rel=preload; as=style, <https://cdn.example.com>; rel=preconnect";
        let hints, ok = http::parse_early_hints(103, link_hdr);

        sub.assert_true(ok, "Parse 103 Early Hints response");
        sub.assert_eq(hints.links.len, 2, "2 links parsed");

        // Link 1: preload
        sub.assert_bytes_eq(hints.links[0].uri[..], "/style.css", "Link 1 URI");
        sub.assert_true(http::early_hint_is_preload(hints.links[0]), "Link 1 is preload");
        sub.assert_bytes_eq(hints.links[0].as_type[..], "style", "Link 1 as=style");

        // Link 2: preconnect
        sub.assert_bytes_eq(hints.links[1].uri[..], "https://cdn.example.com", "Link 2 URI");
        sub.assert_true(http::early_hint_is_preconnect(hints.links[1]), "Link 2 is preconnect");
    };

    t.run("2. RFC 8470 0-RTT Anti-Replay & 425 Too Early Recovery") { sub =>
        // Safe methods allowed in 0-RTT
        sub.assert_true(rfc::is_safe_for_early_data("GET"), "GET is safe for 0-RTT");
        sub.assert_true(rfc::is_safe_for_early_data("HEAD"), "HEAD is safe for 0-RTT");

        // Mutating methods forbidden by default
        sub.assert_false(rfc::is_safe_for_early_data("POST"), "POST is mutating, forbidden in 0-RTT");
        sub.assert_false(rfc::is_safe_for_early_data("DELETE"), "DELETE is mutating, forbidden in 0-RTT");

        let dec_post = client::evaluate_early_data_request("POST", false);
        sub.assert_eq(dec_post, client::EarlyDataDecision.RejectMutating, "POST evaluated as RejectMutating");

        // Server returns 425 Too Early
        let dec_425 = client::evaluate_early_data_response(425, true);
        sub.assert_eq(dec_425, client::EarlyDataDecision.RetryOn1Rtt, "425 triggers transparent 1-RTT retry");

        // Header format
        var req_hdr: u8[>..] = [];
        client::append_early_data_header(req_hdr);
        sub.assert_bytes_eq(req_hdr[..], "Early-Data: 1\r\n", "Early-Data header appended");
    };
}

// ----------------------------------------------------------------------------
// 16. W3C No-Vary-Search Cache Normalization
// ----------------------------------------------------------------------------
fn test_no_vary_search_cache(t: lit::T&) {
    t.run("1. W3C No-Vary-Search Header Parser") { sub =>
        let raw = "params, except=(\"id\" \"page\"), key-order";
        let nvs, ok = http::parse_no_vary_search(raw);

        sub.assert_true(ok, "Parse No-Vary-Search header");
        sub.assert_true(nvs.ignore_all_params, "params flag ignores all params by default");
        sub.assert_eq(nvs.except_params.len, 2, "2 excepted params");
        sub.assert_bytes_eq(nvs.except_params[0][..], "id", "Excepted param 0 is id");
        sub.assert_bytes_eq(nvs.except_params[1][..], "page", "Excepted param 1 is page");
        sub.assert_false(nvs.key_order_matters, "key-order flag means order does not matter");
    };

    t.run("2. Query Parameter Normalization for Cache Hits") { sub =>
        let raw = "params, except=(\"id\")";
        let nvs, _ = http::parse_no_vary_search(raw);

        // Input URL with marketing tracking tags and id in between
        let input_query = "utm_source=twitter&id=42&utm_medium=social&fbclid=XYZ123";
        var normalized: u8[>..] = [];
        http::normalize_query_for_cache(input_query, nvs, normalized);

        sub.assert_bytes_eq(normalized[..], "id=42", "Tracking parameters stripped, only excepted id preserved");

        // Parameter order sorting
        let unordered = "b=2&a=1&c=3";
        let nvs_order, _ = http::parse_no_vary_search("key-order");
        var sorted_q: u8[>..] = [];
        http::normalize_query_for_cache(unordered, nvs_order, sorted_q);
        sub.assert_bytes_eq(sorted_q[..], "a=1&b=2&c=3", "Parameters sorted alphabetically by key");
    };
}

// ----------------------------------------------------------------------------
// 17. RFC 9297 HTTP Capsules & MASQUE CONNECT-UDP
// ----------------------------------------------------------------------------
fn test_masque_capsules_and_datagrams(t: lit::T&) {
    t.run("1. RFC 9297 Capsule Codec") { sub =>
        var wire: u8[..256] = [];
        let payload = "capsule_data_payload";
        sub.assert_true(net::encode_http_capsule(wire, rfc::CAPSULE_DATAGRAM, payload), "encode capsule");

        let c, ok = net::parse_http_capsule(wire[..]);
        sub.assert_true(ok, "parse capsule");
        sub.assert_eq(c.capsule_type, rfc::CAPSULE_DATAGRAM, "Capsule type is DATAGRAM (0x00)");
        sub.assert_bytes_eq(c.payload, payload, "Payload matches original");
    };

    t.run("2. MASQUE CONNECT-UDP (RFC 9298) Tunneling") { sub =>
        var path: u8[..256] = [];
        net::format_connect_udp_path(path, "1.1.1.1", 53);
        sub.assert_bytes_eq(path[..], "/.well-known/masque/udp/1.1.1.1/53/", "MASQUE URI template path");

        // UDP packet datagram capsule
        var datagram_capsule: u8[..256] = [];
        let fake_dns_query = "dns_packet_bytes";
        sub.assert_true(
            net::encode_connect_udp_datagram_capsule(datagram_capsule, 0, fake_dns_query),
            "encode datagram capsule",
        );

        let parsed_capsule, ok_c = net::parse_http_capsule(datagram_capsule[..]);
        sub.assert_true(ok_c, "parse datagram capsule");
        sub.assert_eq(parsed_capsule.capsule_type, rfc::CAPSULE_DATAGRAM, "Type is DATAGRAM");

        let ctx_id, udp_packet, ok_udp = net::parse_connect_udp_datagram(parsed_capsule.payload);
        sub.assert_true(ok_udp, "parse connect-udp datagram");
        sub.assert_eq(ctx_id, 0, "Context ID is 0");
        sub.assert_bytes_eq(udp_packet, fake_dns_query, "Decapsulated UDP packet matches");
    };
}

// ----------------------------------------------------------------------------
// 18. HAR 1.2 Telemetry Waterfall & Network Isolation Keys
// ----------------------------------------------------------------------------
fn test_har_telemetry_and_isolation(t: lit::T&) {
    t.run("1. HAR 1.2 Telemetry & Timing Waterfall Serializer") { sub =>
        let timings = client::RequestTimings {
            blocked_us: 100,
            dns_us:     1250,
            connect_us: 8400,
            ssl_us:     15200,
            send_us:    150,
            wait_us:    25400,
            receive_us: 3200,
        };
        let total_us = client::compute_total_timing_us(timings);
        sub.assert_eq(total_us, 53700, "Total duration 53.7 ms = 53700 us");

        var entry = client::HarEntry {
            status:         200,
            request_bytes:  450,
            response_bytes: 12500,
            timings:        timings,
            ..
        };
        entry.started_iso8601.append("2026-10-24T18:00:00.000Z");
        entry.method.append("GET");
        entry.url.append("https://api.example.com/v1/data");
        entry.http_version.append("HTTP/3");
        entry.status_text.append("OK");

        var json_buf: u8[>..] = [];
        client::serialize_har_entry_json(entry, json_buf);

        sub.assert_contains(json_buf[..], "\"time\":53.70", "HAR entry includes total time");
        sub.assert_contains(json_buf[..], "\"url\":\"https://api.example.com/v1/data\"", "HAR entry includes URL");
        sub.assert_contains(json_buf[..], "\"httpVersion\":\"HTTP/3\"", "HAR entry includes HTTP version");
        sub.assert_contains(json_buf[..], "\"ssl\":15.20", "HAR entry includes SSL handshake time");
    };

    t.run("2. Network Isolation Keys (NIK) State Partitioning") { sub =>
        let nik = net::new_network_isolation_key("https://site-a.com", "https://site-b.com");
        sub.assert_false(nik.is_empty, "NIK is not empty");
        sub.assert_true(nik.is_cross_site, "Cross-site NIK detected");

        var partitioned_key: u8[>..] = [];
        net::format_partitioned_key(nik, "example.com:443", partitioned_key);
        sub.assert_bytes_eq(
            partitioned_key[..],
            "example.com:443{https://site-a.com,https://site-b.com}",
            "Partitioned socket/cache key includes NIK tuple",
        );

        // Empty NIK fallback
        let empty_nik = net::empty_network_isolation_key();
        var raw_key: u8[>..] = [];
        net::format_partitioned_key(empty_nik, "example.com:443", raw_key);
        sub.assert_bytes_eq(raw_key[..], "example.com:443", "Empty NIK leaves key unpartitioned");
    };
}

// ----------------------------------------------------------------------------
// 19. Hardened Security Layer Invariants (Audit Findings)
// ----------------------------------------------------------------------------
fn test_hardened_security_invariants(t: lit::T&) {
    t.run("Sharded GCRA Limiter Saturated Shard Fail-Closed Rejection") { sub =>
        let quota = security::new_gcra_quota(1, wing::secs(1), 1);
        var limiter = security::new_sharded_limiter(quota);
        let now_ns: u64 = 10000000000;

        // Saturate shard 0 with 16 active unexpired client slots
        for i in 16 {
            var slot = security::KeyedGcraSlot { active: true, .. };
            slot.key.append("shard0_client_");
            slot.key.push(('a' + (i as u8)));
            slot.cell.tat_ns = now_ns + 5000000000; // unexpired in the future
            limiter.shards[0].slots.push(slot);
        }

        var target_key: u8[..16] = [];
        for k in 1000 {
            var cand: u8[..16] = "key_";
            cand.push(('0' + (((k / 100) % 10) as u8)));
            cand.push(('0' + (((k / 10) % 10) as u8)));
            cand.push(('0' + ((k % 10) as u8)));
            if (core::fnv1a_64(cand[..]) & 0xFF) == 0 {
                target_key.clear();
                target_key.append(cand[..]);
                break;
            }
        }
        sub.assert_true(target_key.len > 0, "hash candidate found for shard 0");

        let dec_overflow = security::check_rate_limit(limiter, target_key[..], 1, now_ns);
        sub.assert_false(security::is_allowed(dec_overflow), "17th key in saturated shard rejected fail-closed");
    };

    t.run("Probabilistic GCRA Accurate Remaining Burst on Unsampled Requests") { sub =>
        let quota = security::new_gcra_quota(10, wing::secs(1), 10);
        var pgcra = security::new_probabilistic_gcra(quota, 100);
        let now_ns: u64 = 1000000000;

        pgcra.cell.tat_ns = now_ns + 500000000;

        let dec = security::check_rate_limit(pgcra, 1, now_ns);
        sub.assert_true(security::is_allowed(dec), "unsampled request allowed");
        match dec {
            Allowed a => {
                sub.assert_true(a.remaining_burst < 10, "remaining_burst reflects prior TAT cell state");
                sub.assert_eq(a.new_tat_ns, pgcra.cell.tat_ns, "new_tat_ns is current cell TAT without modification");
            },
            _ => { sub.assert_true(false, "expected allowed decision"); },
        };
    };

    t.run("Privacy Pass Token Type High-Byte Preservation (RFC 9577)") { sub =>
        var tok = security::Token { .. };
        tok.token_type = 0xDA5A;
        for i in 32 { tok.nonce[i] = (i + 1) as u8; }
        for i in 32 { tok.challenge_digest[i] = (i + 10) as u8; }
        tok.token_key_id.append("key-id-01");
        tok.authenticator.append("auth-sig-99");

        var wire: u8[>..] = [];
        security::marshal_token(tok, wire);

        let parsed, ok = security::unmarshal_token(wire[..], tok.token_key_id.len, tok.authenticator.len);
        sub.assert_true(ok, "Token unmarshaled cleanly");
        sub.assert_eq(parsed.token_type, 0xDA5A, "high byte 0xDA preserved without truncation");
    };

    t.run("CryptoJar Output Buffer Re-use Clean Truncation") { sub =>
        var store = security::KeyStore { .. };
        let raw_key: u8[32] = [0x55; 32];
        let slot = security::KeySlot { key_id: 1, master_key: raw_key, created_at_sec: 1700000000, .. };
        security::add_key(store, slot);

        var jar = security::new_private_jar(store, false);
        var sealed: u8[>..] = [];
        security::seal_binary(jar, "sess", "user=alice", 1700000010, 0x1234567890ABCDEF, sealed);

        var out: u8[>..] = [];
        out.append("OLD_DIRTY_DATA_PREFIX_");
        let ok = security::open_binary(jar, "sess", sealed[..], 1700000020, out);
        sub.assert_true(ok, "private jar opened");
        sub.assert_bytes_eq(out[..], "user=alice", "out buffer cleared before writing, no dirty data prepend");

        var sjar = security::new_signed_jar(store);
        var signed: u8[>..] = [];
        security::seal_binary(sjar, "prefs", "theme=dark", 1700000010, signed);

        out.clear();
        out.append("OLD_DIRTY_DATA_PREFIX_");
        let sok = security::open_binary(sjar, "prefs", signed[..], 1700000020, out);
        sub.assert_true(sok, "signed jar opened");
        sub.assert_bytes_eq(out[..], "theme=dark", "out_payload cleared before appending");

        var b64_signed: u8[..256] = [];
        let ok_b64_seal = security::seal(sjar, "prefs", "theme=dark", 1700000010, b64_signed);
        sub.assert_true(ok_b64_seal, "signed jar b64 seal ok");
        var b64_opened: u8[..256] = [];
        let ok_b64_open = security::open(sjar, "prefs", b64_signed[..], 1700000020, b64_opened);
        sub.assert_true(ok_b64_open, "signed jar b64 open ok");
        sub.assert_bytes_eq(b64_opened[..], "theme=dark", "signed jar b64 roundtrip matches");
    };
}

// ----------------------------------------------------------------------------
// 20. Security Audit Regression Suite (FIND-SEC-001 .. FIND-SEC-011)
// ----------------------------------------------------------------------------
fn test_security_audit_regressions(t: lit::T&) {
    t.run("FIND-SEC-001..004: CryptoJar Timestamp Overflow, Bounds, Key Revocation & Dead Code Integration") { sub =>
        var store = security::KeyStore { .. };
        let raw_key: u8[32] = [0x42; 32];
        let slot1 = security::KeySlot { key_id: 1, master_key: raw_key, created_at_sec: 1700000000, .. };
        sub.assert_true(security::add_key(store, slot1), "add slot 1");

        // Duplicate key_id must not create unrevokable shadow slot
        sub.assert_false(security::add_key(store, slot1), "reject duplicate key_id 1");

        // Corrupt active_idx out of bounds must return false safely without panic
        store.active_idx = 5;
        let _, ok_corrupt_active = security::active_key(store);
        sub.assert_false(ok_corrupt_active, "out-of-bounds active_idx rejected safely");
        store.active_idx = 0;

        // needs_rotation and is_cookie_timestamp_valid with negative/extreme timestamps
        sub.assert_true(security::is_cookie_timestamp_valid(store, 1700000000, 1700000100), "valid cookie timestamp");
        sub.assert_false(security::is_cookie_timestamp_valid(store, -9000000000000000000, 1700000100), "negative i64 timestamp rejected without overflow");
        sub.assert_false(security::needs_rotation(store.keys[0], 1700000100), "fresh key does not need rotation");
        store.keys[0].expires_at_sec = 1700050000;
        sub.assert_true(security::needs_rotation(store.keys[0], 1700000100), "key expiring within 24h needs rotation");
        sub.assert_false(security::needs_rotation(store.keys[0], -9000000000000000000), "extreme negative now_sec handled without overflow");
        store.keys[0].expires_at_sec = 0;

        // Pre-MAC unauthenticated wire cookie_sec = 0x8000000000000000 (i64::MIN) must not panic or bypass TTL
        var pjar = security::new_private_jar(store, false);
        var forged_wire: u8[..64] = [];
        forged_wire.push(0x01); // WIRE_VER_HKDF_AES256GCM
        core::append_u32_be(forged_wire, 1);
        core::append_u64_be(forged_wire, 0x8000000000000000); // i64::MIN when cast
        for i in 32 { forged_wire.push(0xAA); }
        var out_plain: u8[..64] = [];
        sub.assert_false(
            security::open_binary(pjar, "sess", forged_wire[..], 1700000000, out_plain),
            "unauthenticated high-bit timestamp rejected without signed overflow",
        );

        // PrivateJar base64url seal/open roundtrip and undersized buffer rejection
        var b64_priv: u8[..256] = [];
        sub.assert_true(
            security::seal(pjar, "sess", "secret_val", 1700000000, 99, b64_priv),
            "private_jar_seal base64url succeeded",
        );
        var opened_priv: u8[..64] = [];
        sub.assert_true(
            security::open(pjar, "sess", b64_priv[..], 1700000010, opened_priv),
            "private_jar_open base64url succeeded",
        );
        sub.assert_bytes_eq(opened_priv[..], "secret_val", "private_jar base64url roundtrip");

        sub.assert_false(
            security::seal_binary(pjar, "", "secret_val", 1700000000, 99, opened_priv),
            "empty cookie_name in private_jar_seal_binary must return false",
        );

        var sjar = security::new_signed_jar(store);
        var s_wire: u8[..128] = [];
        sub.assert_true(security::seal_binary(sjar, "prefs", "long_payload_value", 1700000000, s_wire), "signed seal");
        sub.assert_false(
            security::open_binary(sjar, "", s_wire[..], 1700000005, opened_priv),
            "empty cookie_name in signed_jar_open_binary must return false",
        );
    };

    t.run("FIND-SEC-005..007: CSRF Query/Fragment Path Smuggling, Scheme/Referer & Duplicate Sec-Fetch-Site") { sub =>
        // Query and fragment containing '/' on root URL must not smuggle exempt path
        sub.assert_bytes_eq(
            security::extract_path_from_url("https://example.com?redirect=/api/webhook/stripe"),
            "/",
            "query slash must not be extracted as URL path",
        );
        sub.assert_bytes_eq(
            security::extract_path_from_url("https://example.com#/api/webhook/stripe"),
            "/",
            "fragment slash must not be extracted as URL path",
        );

        // Backslash in authority must be rejected by extract_host_from_url
        sub.assert_bytes_eq(
            security::extract_host_from_url("https://evil.com\\@example.com"),
            "",
            "backslash userinfo smuggling rejected",
        );
        sub.assert_bytes_eq(
            security::extract_host_from_url("https://evil.com\\path"),
            "",
            "backslash in host rejected",
        );

        // Trusted origin Referer with path must match trusted_origins entry
        var cfg = security::CrossOriginGuard { .. };
        sub.assert_true(security::add_trusted_origin(cfg, "https://partner.example.com"), "add trusted origin");
        sub.assert_true(security::add_exempt_path(cfg, "/api/webhook/stripe"), "add exempt path");

        var ctx_ref = security::FetchContext {
            site:           security::SecFetchSite.Missing,
            method_is_safe: false,
            has_origin:     false,
            has_referer:    true,
            ..
        };
        ctx_ref.referer.append("https://partner.example.com/checkout/pay?step=2");
        ctx_ref.target_host.append("app.example.com");
        ctx_ref.path.clear();
        ctx_ref.path.append("/pay");
        let dec_ref = security::evaluate_fetch_metadata(cfg, ctx_ref);
        let ok_ref = match dec_ref {
            Allow => true,
            _ => false,
        };
        sub.assert_true(ok_ref, "Referer with path matches trusted origin");

        // Cross-scheme downgrade Origin: http://app.example.com -> target https://app.example.com must be blocked
        var ctx_downgrade = security::FetchContext {
            site:           security::SecFetchSite.Missing,
            method_is_safe: false,
            has_origin:     true,
            ..
        };
        ctx_downgrade.origin.append("http://app.example.com");
        ctx_downgrade.target_host.append("app.example.com");
        ctx_downgrade.path.clear();
        ctx_downgrade.path.append("/transfer");
        let dec_downgrade = security::evaluate_fetch_metadata(cfg, ctx_downgrade);
        let ok_downgrade = match dec_downgrade {
            RejectForbidden r => r.reason == security::CsrfRejectReason.OriginHostMismatch,
            _ => false,
        };
        sub.assert_true(
            ok_downgrade,
            "HTTP origin against HTTPS target blocked in fallback check",
        );
        sub.assert_bytes_eq(
            security::csrf_reject_reason_to_string(security::CsrfRejectReason.OriginHostMismatch),
            "OriginHostMismatch",
            "reject reason string",
        );

        // Duplicate Sec-Fetch-Site header must not downgrade CrossSite to Missing
        var req_dup = http::new_request("POST", "https://app.example.com/transfer");
        http::append_header(req_dup.headers, "Sec-Fetch-Site", "cross-site");
        http::append_header(req_dup.headers, "Sec-Fetch-Site", "");
        let extracted_dup = security::extract_fetch_context(req_dup, "app.example.com");
        sub.assert_true(
            extracted_dup.site == security::SecFetchSite.CrossSite,
            "empty duplicate Sec-Fetch-Site must not overwrite CrossSite",
        );
    };

    t.run("FIND-SEC-008: CORS Subdomain Backslash, Vary Token Match & Non-Preflight OPTIONS") { sub =>
        sub.assert_false(
            security::match_cors_origin_pattern("https://evil.com\\.example.com", "https://*.example.com"),
            "backslash in CORS subdomain rejected",
        );

        // Vary: X-Origin must still receive Origin token
        var res_vary = http::Response { status_code: 200, .. };
        res_vary.set_header("Vary", "X-Origin");
        security::apply_cors_vary_header(res_vary);
        sub.assert_bytes_eq(res_vary.header("Vary"), "X-Origin, Origin", "Vary: X-Origin is not confused with Origin");

        // Regular OPTIONS without Access-Control-Request-Method is not a preflight
        var cors_cfg = security::CorsPolicy { .. };
        let _ = security::add_allowed_origin(cors_cfg, "https://app.example.com");
        var req_opt = http::new_request("OPTIONS", "https://api.example.com/info");
        http::set_header(req_opt, "Origin", "https://app.example.com");
        var res_opt = http::Response { status_code: 200, .. };
        let cors_res = security::evaluate_cors(cors_cfg, req_opt, res_opt);
        sub.assert_true(
            cors_res == security::CorsResult.AllowedActual,
            "OPTIONS without Access-Control-Request-Method handled as actual request, not preflight",
        );
    };

    t.run("FIND-SEC-009: Cross-Origin Isolation IPv6 Hostname, Opaque Null Origin & Parameterized Headers") { sub =>
        sub.assert_true(
            security::parse_coop("same-origin; report-to=\"coop-ep\"") == security::CoopPolicy.SameOrigin,
            "parse_coop strips structured parameters",
        );
        sub.assert_true(
            security::parse_coep("require-corp; report-to=\"coep-ep\"") == security::CoepPolicy.RequireCorp,
            "parse_coep strips structured parameters",
        );
        sub.assert_true(
            security::parse_corp("same-origin; report-to=\"corp-ep\"") == security::CorpPolicy.SameOrigin,
            "parse_corp strips structured parameters",
        );

        // Distinct IPv6 origins must not both truncate to "[" and match as same-site
        var iso_ctx = security::CrossOriginIsolationContext {
            coop: security::CoopPolicy.SameOrigin,
            coep: security::CoepPolicy.RequireCorp,
            ..
        };
        iso_ctx.document_origin.append("https://[::1]:8443");
        sub.assert_false(
            security::is_subresource_allowed(iso_ctx, "https://[2001:db8::1]:8443", "same-site"),
            "different IPv6 hosts must not match as same-site",
        );

        // Opaque "null" origins must never match as same-origin
        var null_ctx = security::CrossOriginIsolationContext {
            coop: security::CoopPolicy.SameOrigin,
            coep: security::CoepPolicy.RequireCorp,
            ..
        };
        null_ctx.document_origin.append("null");
        sub.assert_false(
            security::is_subresource_allowed(null_ctx, "null", "same-origin"),
            "opaque null origins must not match as same-origin",
        );
    };

    t.run("FIND-SEC-010..011: Privacy Pass Framing/Challenge & Probabilistic GCRA Overflow") { sub =>
        // Empty issuer_name (iss_len == 0) must be rejected per RFC 9577 §2.1.1
        var bad_chal_wire: u8[..16] = [0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00];
        let _, ok_bad_chal = security::unmarshal_token_challenge(bad_chal_wire[..]);
        sub.assert_false(
            ok_bad_chal,
            "empty issuer_name rejected by unmarshal_token_challenge",
        );

        // PrivateToken prefix collision ("PrivateTokenFoo ...") must be rejected
        var out_key: u8[..128] = [];
        let _, _, ok_prefix = security::parse_private_token_challenge(
            "PrivateTokenFoo challenge=\"Y2hhbA==\", token-key=\"a2V5\"",
            out_key,
        );
        sub.assert_false(
            ok_prefix,
            "PrivateTokenFoo scheme prefix rejected",
        );

        // attach_private_token formats and sets Authorization header with '='-padded base64url
        var req_pt = http::new_request("GET", "https://api.example.com/resource");
        security::attach_private_token(req_pt, "tok_raw_bytes");
        sub.assert_bytes_eq(
            http::header(req_pt, "Authorization"),
            "PrivateToken token=\"dG9rX3Jhd19ieXRlcw==\"",
            "attach_private_token sets padded base64url Authorization header per RFC 9577 §2.2.2",
        );

        var sec_pst: u8[..128] = [];
        security::format_sec_private_state_token("tok_raw_bytes", sec_pst);
        sub.assert_bytes_eq(
            sec_pst[..],
            "dG9rX3Jhd19ieXRlcw==",
            "format_sec_private_state_token emits padded base64url",
        );

        // Probabilistic GCRA with huge cost_n must saturate and reject, not wrap to 0
        let quota = security::new_gcra_quota(10, wing::secs(1), 10);
        var pgcra = security::new_probabilistic_gcra(quota, 20);
        let huge_dec = security::gcra_check_n(quota, pgcra.cell, 0x4000000000000000, 0xFFFFFFFFFFFFFFF0);
        sub.assert_false(security::is_allowed(huge_dec), "huge cost near u64::MAX rejected without saturation bypass");
        for step in 50 {
            let d = security::check_rate_limit(pgcra, 0x8000000000000000, 1000000000);
            if !security::is_allowed(d) {
                break;
            }
            sub.assert_true(step < 49, "sampled huge cost must be rejected within 50 steps");
        }
    };
}

// ----------------------------------------------------------------------------
// F007: RFC 6797 HSTS Duplicate Directives & Valueless Invariants
// ----------------------------------------------------------------------------
// ----------------------------------------------------------------------------
// 21. F007 RFC 6797 HSTS Invariants
// ----------------------------------------------------------------------------
fn test_f007_hsts_rfc6797_invariants(t: lit::T&) {
    t.run("parse_hsts_header rejects duplicate includeSubDomains directive") { sub =>
        let dir, ok = http::parse_hsts_header("max-age=31536000; includeSubDomains; includeSubDomains");
        sub.assert_false(ok, "Duplicate includeSubDomains MUST be rejected per RFC 6797 §6.1");
    };

    t.run("parse_hsts_header rejects duplicate preload directive") { sub =>
        let dir, ok = http::parse_hsts_header("max-age=31536000; preload; preload");
        sub.assert_false(ok, "Duplicate preload MUST be rejected per RFC 6797 §6.1");
    };

    t.run("parse_hsts_header rejects includeSubDomains with value") { sub =>
        let dir, ok = http::parse_hsts_header("max-age=31536000; includeSubDomains=true");
        sub.assert_false(ok, "includeSubDomains directive with value MUST be rejected per RFC 6797 §6.1.2");
    };

    t.run("hsts_cache_update updates is_preload on existing cache entry") { sub =>
        var cache = http::HstsCache { .. };
        let ok1 = http::hsts_cache_update(cache, "example.com", "max-age=31536000", 1000);
        sub.assert_true(ok1, "Initial HSTS entry stored without preload");

        // Now update same host with preload directive
        let ok2 = http::hsts_cache_update(cache, "example.com", "max-age=31536000; preload", 2000);
        sub.assert_true(ok2, "Update HSTS entry with preload succeeds");
        sub.assert_true(cache.entries[0].is_preload, "Existing cache entry is_preload must be updated to true");
    };
}

// ----------------------------------------------------------------------------
// 22. CORS Wildcard Origin Authority Smuggling & CSRF Userinfo Spoofing
// ----------------------------------------------------------------------------
fn test_cors_wildcard_origin_smuggling_and_csrf_userinfo(t: lit::T&) {
    t.run("match_cors_origin_pattern: reject path/query/userinfo suffix confusion") { sub =>
        let pattern = "https://*.example.com";

        // Path suffix confusion: evil.com/.example.com
        let res_path = security::match_cors_origin_pattern("https://evil.com/.example.com", pattern);
        sub.assert_false(res_path, "evil.com/.example.com MUST NOT match *.example.com");

        // Query suffix confusion: evil.com?.example.com
        let res_query = security::match_cors_origin_pattern("https://evil.com?.example.com", pattern);
        sub.assert_false(res_query, "evil.com?.example.com MUST NOT match *.example.com");

        // Hash suffix confusion: evil.com#.example.com
        let res_hash = security::match_cors_origin_pattern("https://evil.com#.example.com", pattern);
        sub.assert_false(res_hash, "evil.com#.example.com MUST NOT match *.example.com");

        // Userinfo suffix confusion: evil.com@.example.com
        let res_user = security::match_cors_origin_pattern("https://evil.com@.example.com", pattern);
        sub.assert_false(res_user, "evil.com@.example.com MUST NOT match *.example.com");

        // Empty subdomain: .example.com
        let res_dot = security::match_cors_origin_pattern("https://.example.com", pattern);
        sub.assert_false(res_dot, ".example.com MUST NOT match *.example.com");

        // Consecutive dots: sub..example.com
        let res_ddot = security::match_cors_origin_pattern("https://sub..example.com", pattern);
        sub.assert_false(res_ddot, "sub..example.com MUST NOT match *.example.com");

        // Valid subdomain match
        let res_valid = security::match_cors_origin_pattern("https://api.example.com", pattern);
        sub.assert_true(res_valid, "valid subdomain api.example.com matches *.example.com");
    };

    t.run("extract_host_from_url: reject userinfo spoofing in Origin/Referer") { sub =>
        // Attacker sends Origin/Referer with target host in userinfo:
        // https://example.com@evil.com/path
        // If userinfo is not stripped or rejected, host comparison might be confused
        let spoofed = "https://example.com@evil.com/path";
        let host = security::extract_host_from_url(spoofed);
        sub.assert_eq(host.len, 0, "URL with userinfo @ MUST return empty host to reject spoofing");

        let valid_url = "https://valid.example.com:8080/path";
        let valid_host = security::extract_host_from_url(valid_url);
        sub.assert_bytes_eq(valid_host, "valid.example.com:8080", "valid host extracted");
    };
}

// ----------------------------------------------------------------------------
// 23. CORS Preflight Method/Header Validation, Client CORS & HSTS Localhost Exemption
// ----------------------------------------------------------------------------
fn test_cors_preflight_validation_and_hsts_localhost(t: lit::T&) {
    t.run("evaluate_cors rejects disallowed preflight method and headers while accepting simple headers") { sub =>
        var policy = security::CorsPolicy {
            allowed_methods: "GET, POST",
            allowed_headers: "X-Custom-Token",
            ..
        };
        let _ = security::add_allowed_origin(policy, "*");

        var req_bad_method = http::new_request("OPTIONS", "https://api.example.com/resource");
        http::set_header(req_bad_method, "Origin", "https://app.example.com");
        http::set_header(req_bad_method, "Access-Control-Request-Method", "DELETE");
        var resp_bad_m = http::Response { .. };
        let dec_bad_m = security::evaluate_cors(policy, req_bad_method, resp_bad_m);
        sub.assert_true(dec_bad_m == security::CorsResult.RejectedPreflightMethod, "Disallowed DELETE preflight method rejected");

        var req_bad_hdr = http::new_request("OPTIONS", "https://api.example.com/resource");
        http::set_header(req_bad_hdr, "Origin", "https://app.example.com");
        http::set_header(req_bad_hdr, "Access-Control-Request-Method", "POST");
        http::set_header(req_bad_hdr, "Access-Control-Request-Headers", "X-Custom-Token, X-Forbidden-Header");
        var resp_bad_h = http::Response { .. };
        let dec_bad_h = security::evaluate_cors(policy, req_bad_hdr, resp_bad_h);
        sub.assert_true(dec_bad_h == security::CorsResult.RejectedPreflightHeaders, "Disallowed preflight header rejected");

        var req_ok = http::new_request("OPTIONS", "https://api.example.com/resource");
        http::set_header(req_ok, "Origin", "https://app.example.com");
        http::set_header(req_ok, "Access-Control-Request-Method", "POST");
        http::set_header(req_ok, "Access-Control-Request-Headers", "Accept, Content-Language, X-Custom-Token");
        var resp_ok = http::Response { .. };
        let dec_ok = security::evaluate_cors(policy, req_ok, resp_ok);
        sub.assert_true(dec_ok == security::CorsResult.AllowedPreflight, "Valid preflight method and headers accepted");
    };

    t.run("verify_client_cors_response enforces ACAO, ACAC, and tainted origin rules") { sub =>
        var hdrs = http::HeaderMap { .. };
        http::set_header(hdrs, "Access-Control-Allow-Origin", "*");
        sub.assert_true(
            security::verify_client_cors_response(hdrs, "https://app.example.com"),
            "Uncredentialed wildcard ACAO passes",
        );
        let cred_opts = security::ClientCorsVerifyOptions { include_credentials: true, .. };
        sub.assert_false(
            security::verify_client_cors_response(hdrs, "https://app.example.com", cred_opts),
            "Credentialed wildcard ACAO rejected per Fetch spec",
        );

        http::set_header(hdrs, "Access-Control-Allow-Origin", "null");
        http::set_header(hdrs, "Access-Control-Allow-Credentials", "true");
        let tainted_cred_opts = security::ClientCorsVerifyOptions {
            tainted_origin:      true,
            include_credentials: true,
        };
        sub.assert_true(
            security::verify_client_cors_response(hdrs, "https://app.example.com", tainted_cred_opts),
            "Tainted origin matches ACAO: null with ACAC: true",
        );
    };

    t.run("HSTS exempts localhost and .localhost from upgrades even if dynamic entry was inserted") { sub =>
        var cache = http::HstsCache { .. };
        let _ = http::hsts_cache_update(cache, "localhost", "max-age=31536000; includeSubDomains", 1000);
        sub.assert_false(http::is_hsts_host(cache, "localhost", 1010), "localhost is exempt from HSTS upgrades");
        sub.assert_false(http::is_hsts_host(cache, "sub.localhost", 1010), "sub.localhost is exempt from HSTS upgrades");
    };
}

// ----------------------------------------------------------------------------
// 24. goose2rfc Security Audit Regressions (SEC2_C08 & SEC1_C01..C09)
// ----------------------------------------------------------------------------
fn test_goose2rfc_security_audit_regressions(t: lit::T&) {
    t.run("SEC2_C08: Privacy Pass challenge parameter grammar, empty token-key & comma separator") { sub =>
        var chal = security::TokenChallenge {
            token_type:  0x0002,
            issuer_name: "issuer.example",
            ..
        };
        var chal_wire: u8[..256] = [];
        security::marshal_token_challenge(chal, chal_wire);
        var b64_chal: u8[..384] = [];
        security::encode_padded_base64url(chal_wire[..], b64_chal);

        var out_key: u8[..128] = [];

        // 1. Empty token-key="" must be rejected
        var hdr_empty_key: u8[..512] = "PrivateToken challenge=\"";
        hdr_empty_key.append(b64_chal[..]);
        hdr_empty_key.append("\", token-key=\"\"");
        let _, _, ok_empty_key = security::parse_private_token_challenge(hdr_empty_key[..], out_key);
        sub.assert_false(
            ok_empty_key,
            "empty token-key rejected per RFC 9577 §2.1.2",
        );

        // 2. Missing comma between auth-params must be rejected
        var hdr_no_comma: u8[..512] = "PrivateToken challenge=\"";
        hdr_no_comma.append(b64_chal[..]);
        hdr_no_comma.append("\" max-age=60");
        let _, _, ok_no_comma = security::parse_private_token_challenge(hdr_no_comma[..], out_key);
        sub.assert_false(
            ok_no_comma,
            "missing comma delimiter between auth-params rejected per RFC 9110 §11.2",
        );

        // 3. Unquoted '=' in parameter value must be rejected
        var hdr_unquoted_eq: u8[..512] = "PrivateToken challenge=\"";
        hdr_unquoted_eq.append(b64_chal[..]);
        hdr_unquoted_eq.append("\", token-key=a2V5==");
        let _, _, ok_unquoted_eq = security::parse_private_token_challenge(hdr_unquoted_eq[..], out_key);
        sub.assert_false(
            ok_unquoted_eq,
            "unquoted '=' in auth-param token rejected per RFC 9577 §2.1.2",
        );

        // 4. SEC-4: Padded base64url accepted while unpadded challenge / token-key rejected (RFC 9577 §2.1.2)
        var chal_pad = security::TokenChallenge {
            token_type:  0x0002,
            issuer_name: "issuer.example.com",
            ..
        };
        var chal_pad_wire: u8[..256] = [];
        security::marshal_token_challenge(chal_pad, chal_pad_wire);
        var padded_chal_b64:   u8[..384] = [];
        var unpadded_chal_b64: u8[..384] = [];
        security::encode_padded_base64url(chal_pad_wire[..], padded_chal_b64);
        core::base64url_encode(chal_pad_wire[..], unpadded_chal_b64);

        var hdr_padded_ok: u8[..512] = "PrivateToken challenge=\"";
        hdr_padded_ok.append(padded_chal_b64[..]);
        hdr_padded_ok.append("\", token-key=\"AQIDBA==\", max-age=60");
        let _, _, ok_padded_ok = security::parse_private_token_challenge(hdr_padded_ok[..], out_key);
        sub.assert_true(
            ok_padded_ok,
            "padded base64url challenge and token-key accepted per RFC 9577 §2.1.2",
        );

        var hdr_unpadded_chal: u8[..512] = "PrivateToken challenge=\"";
        hdr_unpadded_chal.append(unpadded_chal_b64[..]);
        hdr_unpadded_chal.append("\", token-key=\"AQIDBA==\"");
        let _, _, ok_unpadded_chal = security::parse_private_token_challenge(hdr_unpadded_chal[..], out_key);
        sub.assert_false(
            ok_unpadded_chal,
            "unpadded base64url challenge rejected per RFC 9577 §2.1.2",
        );

        var hdr_unpadded_key: u8[..512] = "PrivateToken challenge=\"";
        hdr_unpadded_key.append(padded_chal_b64[..]);
        hdr_unpadded_key.append("\", token-key=\"AQIDBA\"");
        let _, _, ok_unpadded_key = security::parse_private_token_challenge(hdr_unpadded_key[..], out_key);
        sub.assert_false(
            ok_unpadded_key,
            "unpadded base64url token-key rejected per RFC 9577 §2.1.2",
        );
    };

    t.run("SEC1_C01..C09: Origin port validation, default port normalization, SF tokens & CORS policy") { sub =>
        // SEC1_C01 & SEC1_C06: Empty host before colon and invalid port rejected
        sub.assert_bytes_eq(security::extract_origin_from_url("https://:443/path"), "", "empty host before colon rejected");
        sub.assert_bytes_eq(security::extract_origin_from_url("https://example.com:abc/path"), "", "non-digit port rejected");
        sub.assert_bytes_eq(security::extract_hostname_from_origin("https://example.com:99999"), "", "out-of-range port rejected");
        sub.assert_bytes_eq(security::extract_hostname_from_origin("https://[::1]:abc"), "", "IPv6 non-digit port rejected");

        // SEC1_C01: Default port normalization (:443 for https, :80 for http) in CSRF fallback check
        let guard_cfg = security::CrossOriginGuard { .. };
        var ctx_port = security::FetchContext {
            site:           security::SecFetchSite.Missing,
            method_is_safe: false,
            has_origin:     true,
            ..
        };
        ctx_port.origin.append("https://app.example.com:443");
        ctx_port.target_host.append("app.example.com");
        ctx_port.path.clear();
        ctx_port.path.append("/transfer");
        let dec_port = security::evaluate_fetch_metadata(guard_cfg, ctx_port);
        sub.assert_true(
            security::is_allowed(dec_port),
            "HTTPS default port :443 normalized in CSRF fallback origin check",
        );

        // SEC1_C03: validate_cors_policy rejects "null" with credentials, negative max-age < -1, and bad tokens
        var cred_null = security::CorsPolicy { allow_credentials: true, .. };
        let _ = security::add_allowed_origin(cred_null, "null");
        sub.assert_false(security::validate_cors_policy(cred_null), "null origin with allow_credentials rejected");

        var neg_age = security::CorsPolicy { max_age_sec: -2, .. };
        sub.assert_false(security::validate_cors_policy(neg_age), "max_age_sec < -1 rejected");

        // SEC1_C07 & SEC1_C08: Case-sensitive lowercase SF tokens & unclosed quote parameter rejection
        sub.assert_true(security::parse_coop("SAME-ORIGIN") == security::CoopPolicy.Unknown, "uppercase COOP rejected");
        sub.assert_true(security::parse_coep("REQUIRE-CORP") == security::CoepPolicy.Unknown, "uppercase COEP rejected");
        sub.assert_true(security::parse_corp("SAME-ORIGIN") == security::CorpPolicy.Unknown, "uppercase CORP rejected");
        sub.assert_true(
            security::parse_coop("same-origin; report-to=\"unclosed") == security::CoopPolicy.Unknown,
            "unclosed quote in SF parameter rejected",
        );
        sub.assert_true(security::parse_sec_fetch_site("SAME-ORIGIN") == security::SecFetchSite.Unknown, "uppercase Sec-Fetch-Site rejected");
        sub.assert_true(security::parse_sec_fetch_mode("NAVIGATE") == security::SecFetchMode.Other, "uppercase Sec-Fetch-Mode rejected");
        sub.assert_true(security::parse_sec_fetch_dest("DOCUMENT") == security::SecFetchDest.Other, "uppercase Sec-Fetch-Dest rejected");

        // SEC1_C09: Oversize target_host (> 256B) fails closed by clearing ctx.target_host
        var long_host: u8[..300] = [];
        for i in 260 { long_host.push('a'); }
        long_host.append(".com");
        var req_long = http::new_request("POST", "/transfer");
        let ctx_long = security::extract_fetch_context(req_long, long_host[..]);
        sub.assert_eq(ctx_long.target_host.len, 0, "oversize target_host cleared fail-closed");

        // Wildcard method/header rejected when allow_credentials == true
        var cred_wild_m = security::CorsPolicy { allow_credentials: true, .. };
        let _ = security::add_allowed_origin(cred_wild_m, "https://app.example.com");
        cred_wild_m.allowed_methods.clear();
        cred_wild_m.allowed_methods.append("*");
        sub.assert_false(security::validate_cors_policy(cred_wild_m), "wildcard method with allow_credentials rejected");

        // CryptoJar append into non-empty buffer preserves prefix and enforces key expiration
        var store = security::KeyStore { .. };
        let kslot = security::KeySlot {
            key_id:         7,
            master_key:     [0x42; 32],
            created_at_sec: 1000,
            expires_at_sec: 2000,
            revoked:        false,
            ..
        };
        sub.assert_true(security::add_key(store, kslot), "key added");
        let pjar = security::PrivateJar { store: store, use_hkdf_aes: false };
        var wire: u8[..256] = [];
        sub.assert_true(
            security::seal_binary(pjar, "sid", "world", 1500, 99, wire),
            "seal before key expiry succeeds",
        );
        var wire_exp: u8[..256] = [];
        sub.assert_false(
            security::seal_binary(pjar, "sid", "world", 2001, 99, wire_exp),
            "seal after key expiry rejected",
        );
        var out_buf: u8[..64] = [];
        out_buf.append("hello ");
        let slot_active, ok_act = security::active_key(pjar.store);
        sub.assert_true(ok_act, "active key found");
        sub.assert_true(
            security_internal::open_binary_xchacha20(pjar, slot_active, "sid", wire[..], 1500, out_buf),
            "append into non-empty out_plaintext succeeds",
        );
        sub.assert_bytes_eq(out_buf[..], "hello world", "existing prefix preserved on open_binary_xchacha20");
    };
}

fn main() {
    let title = "Application Perimeter Security, CSRF, HSTS, and Policy Suite";
    var runner = lit::new_runner(title, lit::Verbosity.Verbose);

    lit::run_case(runner, "1. Cross-Origin Isolation & Subresource Policies", test_cross_origin_isolation);
    lit::run_case(runner, "2. W3C Fetch Metadata 9-Row Decision Matrix", test_fetch_metadata_decision_matrix);
    lit::run_case(runner, "3. Response Isolation Headers (Vary & HSTS)", test_isolation_headers_injection);
    lit::run_case(runner, "4. Protocol-Specific CORS Matching & Credentials Security", test_cors_policy_and_matching);
    lit::run_case(runner, "5. Constant-Time CSRF Token Validation & OTP Mask Verification", test_csrf_constant_time_tokens);
    lit::run_case(runner, "6. Edge Filter Lifecycle and Evaluation", test_edge_filter_lifecycle_and_evaluation);
    lit::run_case(runner, "7. HSTS Header Directive Parsing", test_hsts_header_parsing);
    lit::run_case(runner, "8. Chromium Static Preload List & .dev/.app Auto-Upgrade", test_hsts_preload_list_auto_upgrade);
    lit::run_case(runner, "9. Dynamic HSTS Cache Lifecycle, Subdomains & Security Invariants", test_dynamic_hsts_cache_lifecycle);
    lit::run_case(runner, "10. IPv4-Mapped IPv6 SSRF Defense", test_ipv4_mapped_ipv6_ssrf);
    lit::run_case(runner, "11. Scheme Downgrade Header Sanitization", test_scheme_downgrade_with_trusted_hosts);
    lit::run_case(runner, "12. File URL Windows Drive Compliance", test_file_url_windows_drive_compliance);
    lit::run_case(runner, "13. RFC 9116 security.txt Validation Matrix", test_security_txt_valid_matrix);
    lit::run_case(runner, "14. RFC 7838 Alt-Svc & H3 Promotion Engine", test_altsvc_and_h3_promotion);
    lit::run_case(runner, "15. RFC 8297 Early Hints & RFC 8470 0-RTT Anti-Replay", test_early_hints_and_replay_guard);
    lit::run_case(runner, "16. W3C No-Vary-Search Cache Normalization", test_no_vary_search_cache);
    lit::run_case(runner, "17. RFC 9297 HTTP Capsules & MASQUE CONNECT-UDP", test_masque_capsules_and_datagrams);
    lit::run_case(runner, "18. HAR 1.2 Telemetry Waterfall & Network Isolation Keys", test_har_telemetry_and_isolation);
    lit::run_case(runner, "19. Hardened Security Layer Invariants", test_hardened_security_invariants);
    lit::run_case(runner, "20. Security Audit Regressions (FIND-SEC-001..011)", test_security_audit_regressions);
    lit::run_case(runner, "21. F007 RFC 6797 HSTS Invariants", test_f007_hsts_rfc6797_invariants);
    lit::run_case(runner, "22. CORS Wildcard Origin Authority Smuggling & CSRF Userinfo Spoofing", test_cors_wildcard_origin_smuggling_and_csrf_userinfo);
    lit::run_case(runner, "23. CORS Preflight Validation, Client CORS & HSTS Localhost Exemption", test_cors_preflight_validation_and_hsts_localhost);
    lit::run_case(runner, "24. goose2rfc Security Audit Regressions (SEC2_C08 & SEC1_C01..C09)", test_goose2rfc_security_audit_regressions);

    let ok = lit::finish(runner);
    assert(ok);
}
