// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// OkHttp/Tower-style 2-tier Interceptor Pipeline (Application & Network Interceptors).
// Compliant with OkHttp Interceptor specification & Tower Service Layer design:
// - Application Interceptors: Run once per logical call, observe uncompressed/unrouted intent,
//   can rewrite/short-circuit.
// - Network Interceptors: Run on each wire hop (redirects, retries, Alt-Svc racing), observe wire headers & transport.
namespace client;

import std;
import core;
import http.request;
import http.headers;
import http.trace;
import .internal;

// ---- Interceptor Bitmask Constants (64-bit register layout) --------------

const INTERCEPTOR_APP_LOGGING:     u64 = (1 as u64) << 0;
const INTERCEPTOR_APP_AUTH_BEARER: u64 = (1 as u64) << 1;
const INTERCEPTOR_APP_HEADER:      u64 = (1 as u64) << 2;
const INTERCEPTOR_APP_REQUEST_ID:  u64 = (1 as u64) << 3;
const INTERCEPTOR_APP_TRACEPARENT: u64 = (1 as u64) << 4;
const INTERCEPTOR_APP_RETRY:       u64 = (1 as u64) << 5;

const INTERCEPTOR_NET_LOGGING: u64 = (1 as u64) << 16;
const INTERCEPTOR_NET_HEADER:  u64 = (1 as u64) << 17;
const INTERCEPTOR_NET_METRICS: u64 = (1 as u64) << 18;

const INTERCEPTOR_APP_ALL: u64 = 0x000000000000FFFF;
const INTERCEPTOR_NET_ALL: u64 = 0x00000000FFFF0000;

// ---- Interceptor Scope & Kinds -------------------------------------------

enum InterceptorScope {
    Application,
    Network,
}

enum InterceptorKind {
    None,
    Logging,
    AuthBearer,
    Header,
    RequestId,
    Traceparent,
    RetryPolicy,
    Metrics,
}

enum LogLevel {
    None,
    Basic,   // Method, URL, Status, Duration
    Headers, // Basic + Request/Response Headers
    Body,    // Headers + Body preview
}

// ---- Configuration Models ------------------------------------------------

struct InterceptorEntry {
    scope:        InterceptorScope = InterceptorScope.Application,
    kind:         InterceptorKind  = InterceptorKind.None,
    log_level:    LogLevel         = LogLevel.Basic,
    header_name:  u8[..64]         = [],
    header_val:   u8[..4096]       = [],
    prefix:       u8[..32]         = [],
    counter:      u64              = 0,
    max_retries:  i32              = 0,
    retry_on_5xx: bool             = true,
    enabled:      bool             = true,
}

struct RetryPolicy {
    max_retries:  i32  = 0,
    retry_on_5xx: bool = false,
}

struct NetworkMetrics {
    total_requests:           u64 = 0,
    network_hops:             u64 = 0,
    redirect_hops:            u64 = 0,
    total_bytes_sent:         u64 = 0,
    total_bytes_received:     u64 = 0,
    last_request_duration_us: i64 = 0,
    last_hop_duration_us:     i64 = 0,
}

struct InterceptorHeader {
    name: u8[..64]   = [],
    val:  u8[..4096] = [],
}

// Compact InterceptorPipeline with 64-bit register dispatch.
// Replaces 3.5 KB entry array on the stack with a 64-bit bitmask and flat parameters.
struct InterceptorPipeline {
    active_mask:         u64                    = 0,
    bearer_token:        u8[..4096]             = [],
    app_headers:         InterceptorHeader[..4] = [],
    net_headers:         InterceptorHeader[..4] = [],
    req_id_prefix:       u8[..32]               = [],
    req_id_counter:      u64                    = 1,
    traceparent_flag:    u8[..2]                = [],
    traceparent_counter: u64                    = 1,
    app_log_level:       LogLevel               = LogLevel.Basic,
    net_log_level:       LogLevel               = LogLevel.Basic,
    max_retries:         i32                    = 0,
    retry_on_5xx:        bool                   = true,
    metrics:             NetworkMetrics         = NetworkMetrics { .. },
    log_entries:         u8[..128][..8]         = [],
    record_logs:         bool                   = true,
}

// ---- Pipeline Builders ---------------------------------------------------

fn add_interceptor(pipeline: InterceptorPipeline&, entry: InterceptorEntry) -> bool {
    guard entry.enabled else { return true; }
    match entry.scope {
        Application => match entry.kind {
            Logging => {
                pipeline.active_mask |= INTERCEPTOR_APP_LOGGING;
                pipeline.app_log_level = entry.log_level;
                return true;
            },
            AuthBearer => {
                let raw_tok = entry.header_val[..];
                let stripped = if raw_tok.starts_with_fold("Bearer ") { raw_tok[7..] } else { raw_tok };
                return add_bearer_auth(pipeline, stripped);
            },
            Header => {
                return add_header(pipeline, InterceptorScope.Application, entry.header_name[..], entry.header_val[..]);
            },
            RequestId => {
                guard pipeline.req_id_prefix.try_set(entry.prefix[..]) else { return false; }
                pipeline.active_mask |= INTERCEPTOR_APP_REQUEST_ID;
                pipeline.req_id_counter = max(1, entry.counter);
                return true;
            },
            Traceparent => {
                guard add_traceparent(pipeline, entry.prefix[..]) else { return false; }
                pipeline.traceparent_counter = max(1, entry.counter);
                return true;
            },
            RetryPolicy => {
                pipeline.active_mask |= INTERCEPTOR_APP_RETRY;
                pipeline.max_retries = entry.max_retries;
                pipeline.retry_on_5xx = entry.retry_on_5xx;
                return true;
            },
            _ => {
                return false;
            },
        },
        Network => match entry.kind {
            Logging => {
                pipeline.active_mask |= INTERCEPTOR_NET_LOGGING;
                pipeline.net_log_level = entry.log_level;
                return true;
            },
            Header => {
                return add_header(pipeline, InterceptorScope.Network, entry.header_name[..], entry.header_val[..]);
            },
            Metrics => {
                pipeline.active_mask |= INTERCEPTOR_NET_METRICS;
                return true;
            },
            _ => {
                return false;
            },
        },
    };
    return false;
}

fn add_logging(pipeline: InterceptorPipeline&, scope: InterceptorScope, level: LogLevel) -> bool {
    match scope {
        Application => {
            pipeline.active_mask |= INTERCEPTOR_APP_LOGGING;
            pipeline.app_log_level = level;
            return true;
        },
        Network => {
            pipeline.active_mask |= INTERCEPTOR_NET_LOGGING;
            pipeline.net_log_level = level;
            return true;
        },
    };
    return false;
}

fn add_bearer_auth(pipeline: InterceptorPipeline&, token: const u8[:]) -> bool {
    guard "Bearer ".len + token.len <= pipeline.bearer_token.cap else { return false; }
    pipeline.active_mask |= INTERCEPTOR_APP_AUTH_BEARER;
    let _ = pipeline.bearer_token.try_set("Bearer ");
    let _ = pipeline.bearer_token.try_append(token);
    return true;
}

fn add_header(pipeline: InterceptorPipeline&, scope: InterceptorScope, name: const u8[:], val: const u8[:]) -> bool {
    match scope {
        Application => {
            guard client_internal::upsert_interceptor_header(pipeline.app_headers, name, val) else {
                return false;
            }
            pipeline.active_mask |= INTERCEPTOR_APP_HEADER;
            return true;
        },
        Network => {
            guard client_internal::upsert_interceptor_header(pipeline.net_headers, name, val) else {
                return false;
            }
            pipeline.active_mask |= INTERCEPTOR_NET_HEADER;
            return true;
        },
    };
    return false;
}

fn add_request_id(pipeline: InterceptorPipeline&, prefix: const u8[:] = "req-") -> bool {
    guard pipeline.req_id_prefix.try_set(prefix) else { return false; }
    pipeline.active_mask |= INTERCEPTOR_APP_REQUEST_ID;
    pipeline.req_id_counter = 1;
    return true;
}

fn add_traceparent(pipeline: InterceptorPipeline&, sample_flag: const u8[:] = "01") -> bool {
    guard sample_flag.len == 2
        && core::is_ascii_hexdigit(sample_flag[0])
        && core::is_ascii_hexdigit(sample_flag[1])
        && pipeline.traceparent_flag.try_set(sample_flag) else {
        return false;
    }
    pipeline.active_mask |= INTERCEPTOR_APP_TRACEPARENT;
    pipeline.traceparent_counter = 1;
    return true;
}

fn add_retry(pipeline: InterceptorPipeline&, max_retries: i32, retry_on_5xx: bool = true) -> bool {
    pipeline.active_mask |= INTERCEPTOR_APP_RETRY;
    pipeline.max_retries = max_retries;
    pipeline.retry_on_5xx = retry_on_5xx;
    return true;
}

fn add_metrics(pipeline: InterceptorPipeline&) -> bool {
    pipeline.active_mask |= INTERCEPTOR_NET_METRICS;
    return true;
}

// Returns the configured application retry policy and whether retry is enabled.
fn find_retry_policy(pipeline: const InterceptorPipeline&) -> RetryPolicy, bool {
    if (pipeline.active_mask & INTERCEPTOR_APP_RETRY) != 0 {
        return RetryPolicy {
            max_retries:  pipeline.max_retries,
            retry_on_5xx: pipeline.retry_on_5xx,
        }, true;
    }
    return RetryPolicy { .. }, false;
}

// ---- Application & Network Interceptor Request Hooks ---------------------

fn apply_app_interceptors_request(
    pipeline: InterceptorPipeline&,
    req:      http::Request&,
    clock_us: i64,
) {
    let mask = pipeline.active_mask;
    guard (mask & INTERCEPTOR_APP_ALL) != 0 else { return; }

    if (mask & INTERCEPTOR_APP_AUTH_BEARER) != 0 && http::header(req, "Authorization").len == 0 {
        http::sensitive_header(req, "Authorization", pipeline.bearer_token[..]);
    }
    if (mask & INTERCEPTOR_APP_HEADER) != 0 {
        for &hdr in pipeline.app_headers {
            if http::header(req, hdr.name[..]).len == 0 {
                http::set_header(req, hdr.name[..], hdr.val[..]);
            }
        }
    }
    if (mask & INTERCEPTOR_APP_REQUEST_ID) != 0 && http::header(req, "X-Request-ID").len == 0 {
        var val_buf: u8[..64] = [];
        format(val_buf, pipeline.req_id_prefix[..], pipeline.req_id_counter);
        pipeline.req_id_counter += 1;
        http::set_header(req, "X-Request-ID", val_buf[..]);
    }
    if (mask & INTERCEPTOR_APP_TRACEPARENT) != 0 && http::header(req, "traceparent").len == 0 {
        var tp_buf: u8[..64] = [];
        client_internal::generate_traceparent(
            pipeline.traceparent_counter, clock_us, pipeline.traceparent_flag[..], tp_buf,
        );
        pipeline.traceparent_counter += 1;
        http::set_header(req, "traceparent", tp_buf[..]);
    }
    if (mask & INTERCEPTOR_APP_LOGGING) != 0 {
        client_internal::log_interceptor_request(pipeline, req, pipeline.app_log_level);
    }
}

fn apply_network_interceptors_request(
    pipeline:   InterceptorPipeline&,
    headers:    http::HeaderMap&,
    target_url: const u8[:],
    method:     const u8[:],
    body_len:   i64,
    hop_index:  i64,
) {
    pipeline.metrics.network_hops += 1;
    if body_len > 0 {
        pipeline.metrics.total_bytes_sent += body_len as! u64;
    }

    let mask = pipeline.active_mask;
    guard (mask & INTERCEPTOR_NET_ALL) != 0 else { return; }

    if (mask & INTERCEPTOR_NET_HEADER) != 0 {
        for &hdr in pipeline.net_headers {
            if !http::has_header(headers, hdr.name[..]) {
                http::set_header(headers, hdr.name[..], hdr.val[..]);
            }
        }
    }
    if (mask & INTERCEPTOR_NET_LOGGING) != 0 {
        client_internal::log_network_interceptor_request(
            pipeline,
            headers,
            target_url,
            method,
            hop_index,
            pipeline.net_log_level,
        );
    }
}
