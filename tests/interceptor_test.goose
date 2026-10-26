// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Verification suite for OkHttp/Tower-style 2-tier Interceptor Pipeline:
// 1. Application Interceptors: Bearer Auth, Request ID, Traceparent, App Header, App Logging
// 2. Network Interceptors: Wire-level Observation, Per-Hop Headers & Logging, Network Metrics
// 3. Cache Boundary: Application Interceptor fires on Cache Hit, Network Interceptors bypassed
// 4. Retry Interceptor: Automatic Retry on 5xx Errors
// 5. Dynamic Closure Chain: `do_intercepted`, `proceed`, Request/Response Rewrite & Short-Circuiting
import std;
import core from "..";
import wing from "..";

fn test_application_interceptors(t: core::T&) {
    t.run("Application Interceptors: Bearer Auth, Request-ID, Traceparent & App Header") { sub =>
        var client = wing::new_client();
        wing::add_app_bearer_auth(client, "secret_jwt_token_xyz");
        wing::add_app_header(client, "X-App-Env", "staging");
        wing::add_app_request_id(client, "track-");
        wing::add_app_traceparent(client, "01");

        wing::mock_route(client, "GET", "https://api.site.com/profile", 200, "{\"user\":\"alice\"}");

        let resp1, err1 = wing::get(client, "https://api.site.com/profile");
        sub.assert_true(wing::ok(err1), "get profile ok");
        sub.assert_eq(wing::status(resp1), 200, "status 200");

        // Verify sent headers
        let auth = wing::sent_header(resp1, "Authorization");
        sub.assert_bytes_eq(auth, "Bearer secret_jwt_token_xyz", "Bearer auth injected");

        let app_env = wing::sent_header(resp1, "X-App-Env");
        sub.assert_bytes_eq(app_env, "staging", "App header injected");

        let req_id1 = wing::sent_header(resp1, "X-Request-ID");
        sub.assert_bytes_eq(req_id1, "track-1", "First request ID is track-1");

        let tp = wing::sent_header(resp1, "traceparent");
        sub.assert_eq(tp.len, 55, "traceparent length is 55");
        sub.assert_bytes_eq(tp[..3], "00-", "traceparent version is 00-");
        sub.assert_bytes_eq(tp[52..], "-01", "traceparent flags is -01");

        // Request 2 should increment request ID counter
        let resp2, err2 = wing::get(client, "https://api.site.com/profile");
        sub.assert_true(wing::ok(err2), "second request ok");
        let req_id2 = wing::sent_header(resp2, "X-Request-ID");
        sub.assert_bytes_eq(req_id2, "track-2", "Second request ID incremented to track-2");
    };

    t.run("Application Logging: Request & Response Records") { sub =>
        var client = wing::new_client();
        wing::add_app_logging(client, wing::LogLevel.Headers);

        wing::mock_route(client, "GET", "https://api.site.com/ping", 200, "pong");

        let resp, err = wing::get(client, "https://api.site.com/ping");
        sub.assert_true(wing::ok(err), "ping ok");

        let logs = wing::pipeline_logs(client);
        sub.assert_true(logs.len >= 2, "at least 2 log entries recorded");
        sub.assert_bytes_eq(logs[0][..10], "--> GET ht", "First log line is request line");
        sub.assert_bytes_eq(logs[logs.len - 1][..6], "<-- 20", "Last log line is response status");
    };
}

fn test_network_interceptors_and_metrics(t: core::T&) {
    t.run("Network Interceptor Observes Redirect Wire Hops & Wire Headers") { sub =>
        var client = wing::new_client();
        wing::add_network_metrics(client);
        wing::add_network_header(client, "X-Net-Proxy-Trace", "edge-us-east");
        wing::add_network_logging(client, wing::LogLevel.Basic);

        // Setup redirect chain: /start (302) -> /final (200)
        wing::mock_route(client, "GET", "https://site.com/start", 302, "redirecting");
        wing::add_mock_header(client, "Location", "https://site.com/final");

        wing::mock_route(client, "GET", "https://site.com/final", 200, "destination reached");

        let resp, err = wing::get(client, "https://site.com/start");
        sub.assert_true(wing::ok(err), "redirect traversal succeeded");
        sub.assert_eq(wing::status(resp), 200, "status 200");
        sub.assert_bytes_eq(resp.body[..], "destination reached", "final body arrived");

        // Verify Network Metrics
        let metrics = wing::network_metrics(client);
        sub.assert_eq(metrics.total_requests, 1 as u64, "1 logical application request");
        sub.assert_eq(metrics.network_hops, 2 as u64, "2 physical network hops traversed");
        sub.assert_eq(metrics.redirect_hops, 1 as u64, "1 redirect hop recorded");
        sub.assert_true(metrics.total_bytes_received > 0, "bytes received tracked");

        // Verify Network Logging captured both hops
        let logs = wing::pipeline_logs(client);
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

fn test_cache_interceptor_boundary(t: core::T&) {
    t.run("OkHttp Invariant: App Interceptors run on Cache Hit; Network Interceptors are bypassed") { sub =>
        var client = wing::new_client();
        client.enable_cache = true;
        wing::add_app_logging(client, wing::LogLevel.Basic);
        wing::add_network_metrics(client);

        wing::mock_route(client, "GET", "https://site.com/cached-item", 200, "cached-content");
        wing::add_mock_header(client, "Cache-Control", "public, max-age=3600");

        // 1. Initial Request (Cache Miss -> Network)
        let resp1, err1 = wing::get(client, "https://site.com/cached-item");
        sub.assert_true(wing::ok(err1), "initial get ok");
        sub.assert_eq(wing::status(resp1), 200, "200 OK");

        let m1 = wing::network_metrics(client);
        sub.assert_eq(m1.total_requests, 1 as u64, "1 app request");
        sub.assert_eq(m1.network_hops, 1 as u64, "1 network hop on miss");

        // 2. Second Request (Cache Hit -> Served from HttpCache directly)
        wing::clear_pipeline_logs(client);
        let resp2, err2 = wing::get(client, "https://site.com/cached-item");
        sub.assert_true(wing::ok(err2), "cached get ok");
        sub.assert_eq(wing::status(resp2), 200, "200 OK");
        sub.assert_bytes_eq(resp2.body[..], "cached-content", "body from cache");

        let m2 = wing::network_metrics(client);
        sub.assert_eq(m2.total_requests, 2 as u64, "2 logical app requests");
        // Crucial OkHttp invariant: Network hops DID NOT increase on cache hit!
        sub.assert_eq(m2.network_hops, 1 as u64, "Network hops remained 1 (network bypassed!)");

        // But Application Logging DID run for the cached request!
        let logs = wing::pipeline_logs(client);
        sub.assert_true(logs.len >= 2, "Application logs fired for cache hit");
    };
}

fn test_retry_policy_interceptor(t: core::T&) {
    t.run("Retry Interceptor Retries on 5xx Error Up To Max Retries") { sub =>
        var client = wing::new_client();
        wing::add_app_retry(client, 2, true);
        wing::add_network_metrics(client);

        // Server returns 503 Service Unavailable
        wing::mock_route(client, "GET", "https://site.com/flaky", 503, "temporary failure");

        let resp, err = wing::get(client, "https://site.com/flaky");
        sub.assert_true(wing::ok(err), "request finished");
        sub.assert_eq(wing::status(resp), 503, "503 returned after exhaustion");

        let m = wing::network_metrics(client);
        // Initial attempt (0) + Retry 1 + Retry 2 = 3 total attempts!
        sub.assert_eq(m.network_hops, 3 as u64, "Retried up to max_retries (3 attempts total)");
    };
}

fn test_closure_chain_interceptor(t: core::T&) {
    t.run("Closure Chain: Mutate Request, Call Proceed & Mutate Response") { sub =>
        var client = wing::new_client();
        wing::mock_route(client, "GET", "https://site.com/resource", 200, "server-payload");

        let req = wing::new_get("https://site.com/resource");

        let resp, err = wing::do_intercepted(client, req) { chain, client =>
            // Inject header into request before proceed
            chain.request.headers.push(wing::make_header("X-Custom-Client", "Interceptor-V1"));

            // Proceed down the chain
            wing::proceed(chain, client);

            // Mutate response after proceed
            chain.response.headers.push(wing::make_header("X-Processed-By", "Client-Chain"));
        };

        sub.assert_true(wing::ok(err), "intercepted call ok");
        sub.assert_eq(wing::status(resp), 200, "status 200");
        sub.assert_bytes_eq(resp.body[..], "server-payload", "server body received");

        // Verify sent header
        let sent_c = wing::sent_header(resp, "X-Custom-Client");
        sub.assert_bytes_eq(sent_c, "Interceptor-V1", "Header injected before proceed");

        // Verify mutated response header
        let proc_by = wing::header(resp, "X-Processed-By");
        sub.assert_bytes_eq(proc_by, "Client-Chain", "Response mutated after proceed");
    };

    t.run("Closure Chain: Short-Circuit Without Hitting Network") { sub =>
        var client = wing::new_client();
        // Notice: NO mock route is configured for this URL! If it hit network/mock it would fail or return default.
        let req = wing::new_get("https://site.com/short-circuit");

        let resp, err = wing::do_intercepted(client, req) { chain, client =>
            // Directly synthesize response without calling proceed!
            chain.response.status_code = 201;
            chain.response.body.clear();
            chain.response.body.append("{\"short\":\"circuited\"}");
            chain.short_circuited = true;
        };

        sub.assert_true(wing::ok(err), "short-circuit succeeded");
        sub.assert_eq(wing::status(resp), 201, "status 201");
        sub.assert_bytes_eq(resp.body[..], "{\"short\":\"circuited\"}", "synthesized body returned");
    };
}

fn main() {
    var runner = core::new_runner("Interceptor Pipeline Suite (OkHttp/Tower-style)", core::Verbosity.Verbose);
    core::run_case(runner, "1. Application Interceptors (Bearer, Request-ID, Traceparent, Headers, Logging)", test_application_interceptors);
    core::run_case(runner, "2. Network Interceptors, Redirect Hops & Network Metrics", test_network_interceptors_and_metrics);
    core::run_case(runner, "3. OkHttp Cache Boundary Invariant", test_cache_interceptor_boundary);
    core::run_case(runner, "4. Retry Policy Interceptor", test_retry_policy_interceptor);
    core::run_case(runner, "5. Closure-based Interceptor Chain & Short-Circuiting", test_closure_chain_interceptor);
    let ok = core::finish(runner);
    assert(ok);
}
