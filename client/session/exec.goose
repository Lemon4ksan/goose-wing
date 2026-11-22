// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Top-level client request execution entrypoint with interceptors, retries, and circuit breaking.
namespace client;

import std;
import core;
import http.request;
import http.response;
import net.retry;
import client.interceptor;
import client.client;
import client.internal;
import .hop_auth_internal;
import .pipeline_internal;

// Executes an HTTP request through application interceptors, retry budgets, circuit breakers,
// and the composable L7 client stage pipeline.
fn execute_request(session: Client&, req: const http::Request&) -> http::Response, http::Error {
    let start_us = session.virtual_clock_us;
    let now_ns = core::mul_sat_i64(start_us, 1000);

    let parsed_url, url_err = core::parse_url(req.url[..]);
    let target_host = if url_err == core::UrlParseError.None { parsed_url.host() } else { "" };
    if target_host.len > 0 && net::is_host_circuit_broken(session.circuit_breaker, target_host, now_ns) {
        let err_cb = http::make_error(503, "circuit_breaker", "host circuit broken by Retry-After");
        return http::Response { status_code: 503, .. }, err_cb;
    }
    net::record_primary_request(session.retry_budget, now_ns);

    let retry_pol, has_retry = find_retry_policy(session.pipeline);

    var attempts:      i32 = 0;
    var prev_sleep_ms: i64 = 0;
    var rng_seed:      u64 = (start_us as u64) ^ 0x9E3779B97F4A7C15;
    var final_req = copy(req);
    var final_resp = http::Response { .. };
    var final_err = http::Error { .. };
    loop {
        // Application Interceptors (Request Hook) per attempt
        final_req = copy(req);
        final_req.disallow_early_data = req.disallow_early_data || attempts > 0;
        apply_app_interceptors_request(session.pipeline, final_req, session.virtual_clock_us);

        let resp, err = client_internal::execute_request_inner(session, final_req);
        final_resp = copy(resp);
        final_err = err;
        client_internal::evaluate_response_retry_after(session, target_host, final_resp, now_ns);

        let retry = client_internal::should_retry_request(
            final_resp.status_code, final_err, final_req.method[..], final_req,
            attempts, has_retry, retry_pol.max_retries, retry_pol.retry_on_5xx,
        );
        if retry && net::allow_retry_budget(session.retry_budget, now_ns) {
            let sleep_ms = net::compute_backoff_jitter_ms(session.backoff_config, attempts, prev_sleep_ms, rng_seed);
            session.virtual_clock_us = core::add_sat_i64(session.virtual_clock_us, core::mul_sat_i64(sleep_ms, 1000));
            attempts = core::add_sat_i64(attempts, 1) as! i32;
            continue;
        }
        break;
    }

    // Application Interceptors (Response Hook)
    let total_dur_us = core::sub_sat_i64(session.virtual_clock_us, start_us);
    client_internal::apply_app_interceptors_response(session.pipeline, final_req, final_resp, final_err, total_dur_us);
    client_internal::record_client_har_telemetry(session, final_req, final_resp, total_dur_us);
    return final_resp, final_err;
}
