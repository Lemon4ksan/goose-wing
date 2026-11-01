// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// OkHttp/Tower-style 2-tier Interceptor Pipeline (Application & Network Interceptors).
// Compliant with OkHttp Interceptor specification & Tower Service Layer design:
// - Application Interceptors: Run once per logical call, observe uncompressed/unrouted intent,
//   can rewrite/short-circuit.
// - Network Interceptors: Run on each wire hop (redirects, retries, Alt-Svc racing), observe wire headers & transport.
namespace wing;

import std;
import client.request;
import http.headers;

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
    header_val:   u8[..256]        = [],
    prefix:       u8[..32]         = [],
    counter:      u64              = 0,
    max_retries:  i32              = 0,
    retry_on_5xx: bool             = true,
    enabled:      bool             = true,
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

struct InterceptorPipeline {
    entries:     InterceptorEntry[..8] = [],
    metrics:     NetworkMetrics        = NetworkMetrics { .. },
    log_entries: u8[..128][..32]       = [],
    record_logs: bool                  = true,
}

// ---- Pipeline Builders ---------------------------------------------------

fn add_interceptor(pipeline: InterceptorPipeline&, entry: InterceptorEntry) -> bool {
    guard pipeline.entries.len < pipeline.entries.cap else { return false; }
    pipeline.entries.push(entry);
    return true;
}

fn add_logging(pipeline: InterceptorPipeline&, scope: InterceptorScope, level: LogLevel) -> bool {
    let entry = InterceptorEntry {
        scope:     scope,
        kind:      InterceptorKind.Logging,
        log_level: level,
        enabled:   true,
        ..
    };
    return add_interceptor(pipeline, entry);
}

fn add_bearer_auth(pipeline: InterceptorPipeline&, token: const u8[:]) -> bool {
    var entry = InterceptorEntry {
        scope:   InterceptorScope.Application,
        kind:    InterceptorKind.AuthBearer,
        enabled: true,
        ..
    };
    entry.header_name.append("Authorization");
    entry.header_val.append("Bearer ");
    entry.header_val.append(token);
    return add_interceptor(pipeline, entry);
}

fn add_header(pipeline: InterceptorPipeline&, scope: InterceptorScope, name: const u8[:], val: const u8[:]) -> bool {
    var entry = InterceptorEntry {
        scope:   scope,
        kind:    InterceptorKind.Header,
        enabled: true,
        ..
    };
    entry.header_name.append(name);
    entry.header_val.append(val);
    return add_interceptor(pipeline, entry);
}

fn add_request_id(pipeline: InterceptorPipeline&, prefix: const u8[:] = "req-") -> bool {
    var entry = InterceptorEntry {
        scope:   InterceptorScope.Application,
        kind:    InterceptorKind.RequestId,
        enabled: true,
        ..
    };
    entry.header_name.append("X-Request-ID");
    entry.prefix.append(prefix);
    entry.counter = 1;
    return add_interceptor(pipeline, entry);
}

fn add_traceparent(pipeline: InterceptorPipeline&, sample_flag: const u8[:] = "01") -> bool {
    var entry = InterceptorEntry {
        scope:   InterceptorScope.Application,
        kind:    InterceptorKind.Traceparent,
        enabled: true,
        ..
    };
    entry.header_name.append("traceparent");
    entry.prefix.append(sample_flag);
    entry.counter = 1;
    return add_interceptor(pipeline, entry);
}

fn add_retry(pipeline: InterceptorPipeline&, max_retries: i32, retry_on_5xx: bool = true) -> bool {
    let entry = InterceptorEntry {
        scope:        InterceptorScope.Application,
        kind:         InterceptorKind.RetryPolicy,
        max_retries:  max_retries,
        retry_on_5xx: retry_on_5xx,
        enabled:      true,
        ..
    };
    return add_interceptor(pipeline, entry);
}

fn add_metrics(pipeline: InterceptorPipeline&) -> bool {
    let entry = InterceptorEntry {
        scope:   InterceptorScope.Network,
        kind:    InterceptorKind.Metrics,
        enabled: true,
        ..
    };
    return add_interceptor(pipeline, entry);
}

// Queries if an application retry policy is configured
fn find_retry_policy(pipeline: const InterceptorPipeline&, out_retries: i32&, out_retry_5xx: bool&) -> bool {
    for &entry in pipeline.entries {
        if entry.enabled && entry.kind == InterceptorKind.RetryPolicy {
            out_retries = entry.max_retries;
            out_retry_5xx = entry.retry_on_5xx;
            return true;
        }
    }
    return false;
}

// ---- Formatting Utilities ------------------------------------------------

// W3C TraceContext traceparent generator:
// Format: 00-{32 hex trace_id}-{16 hex parent_id}-{2 hex flags}
fn generate_traceparent<B>(counter: u64, clock_us: i64, flag: const u8[:], out: B&) {
    out.append("00-");
    core::format_u64_hex_fixed(clock_us as! u64, 16, out, false);
    core::format_u64_hex_fixed(counter ^ 0xa5a5a5a5a5a5a5a5, 16, out, false);
    out.append("-");
    core::format_u64_hex_fixed(counter, 16, out, false);
    out.append("-");
    if flag.len == 2 {
        out.append(flag);
    } else {
        out.append("01");
    }
}

fn push_log(pipeline: InterceptorPipeline&, msg: const u8[:]) {
    guard pipeline.record_logs && pipeline.log_entries.len < pipeline.log_entries.cap else { return; }
    var entry: u8[..128] = [];
    entry.append(msg);
    pipeline.log_entries.push(entry);
}

fn log_interceptor_request(pipeline: InterceptorPipeline&, req: const Request&, lvl: LogLevel) {
    guard lvl != LogLevel.None else { return; }
    var line: u8[..256] = [];
    format(line, "--> ", req.method[..], " ", req.url[..]);
    push_log(pipeline, line[..]);

    if lvl == LogLevel.Headers || lvl == LogLevel.Body {
        for &h in req.headers {
            var h_line: u8[..256] = [];
            format(h_line, "--> ", h.name[..], ": ", h.value[..]);
            push_log(pipeline, h_line[..]);
        }
    }
    if lvl == LogLevel.Body && req.body.len > 0 {
        var b_line: u8[..256] = [];
        format(b_line, "--> (body ", req.body.len, " bytes)");
        push_log(pipeline, b_line[..]);
    }
}

fn log_interceptor_response(
    pipeline:    InterceptorPipeline&,
    resp:        const Response&,
    err:         const Error&,
    lvl:         LogLevel,
    duration_us: i64,
) {
    guard lvl != LogLevel.None else { return; }
    var line: u8[..256] = [];
    if ok(err) {
        format(line, "<-- ", resp.status_code, " (", duration_us, " us)");
    } else {
        format(line, "<-- FAILED (", err.message[..], ")");
    }
    push_log(pipeline, line[..]);

    if ok(err) && (lvl == LogLevel.Headers || lvl == LogLevel.Body) {
        for &h in resp.headers {
            var h_line: u8[..256] = [];
            format(h_line, "<-- ", h.name[..], ": ", h.value[..]);
            push_log(pipeline, h_line[..]);
        }
    }
    if ok(err) && lvl == LogLevel.Body && resp.body.len > 0 {
        var b_line: u8[..256] = [];
        format(b_line, "<-- (body ", resp.body.len, " bytes)");
        push_log(pipeline, b_line[..]);
    }
}

fn log_network_interceptor_request(
    pipeline:   InterceptorPipeline&,
    headers:    const HeaderItem[..32]&,
    target_url: const u8[:],
    method:     const u8[:],
    hop_index:  i64,
    lvl:        LogLevel,
) {
    guard lvl != LogLevel.None else { return; }
    var line: u8[..256] = [];
    format(line, "--> (net hop ", hop_index, ") ", method, " ", target_url);
    push_log(pipeline, line[..]);

    if lvl == LogLevel.Headers || lvl == LogLevel.Body {
        for &h in headers {
            var h_line: u8[..256] = [];
            format(h_line, "--> (net) ", h.name[..], ": ", h.value[..]);
            push_log(pipeline, h_line[..]);
        }
    }
}

// ---- Application Interceptor Hooks ---------------------------------------

fn apply_app_interceptors_request(
    pipeline: InterceptorPipeline&,
    req:      Request&,
    clock_us: i64,
) {
    for &entry in pipeline.entries {
        guard entry.enabled && entry.scope == InterceptorScope.Application else { continue; }

        if entry.kind == InterceptorKind.AuthBearer {
            // Only add if not already present, updating Bloom filter and sensitivity flag
            if header(req, "Authorization").len == 0 {
                sensitive_header(req, "Authorization", entry.header_val[..]);
            }
        } else if entry.kind == InterceptorKind.Header {
            let h_name = entry.header_name[..];
            if header(req, h_name).len == 0 {
                set_header(req, h_name, entry.header_val[..]);
            }
        } else if entry.kind == InterceptorKind.RequestId {
            if header(req, "X-Request-ID").len == 0 {
                var val_buf: u8[..64] = [];
                format(val_buf, entry.prefix[..], entry.counter);
                entry.counter += 1;
                set_header(req, "X-Request-ID", val_buf[..]);
            }
        } else if entry.kind == InterceptorKind.Traceparent {
            if header(req, "traceparent").len == 0 {
                var tp_buf: u8[..64] = [];
                generate_traceparent(entry.counter, clock_us, entry.prefix[..], tp_buf);
                entry.counter += 1;
                set_header(req, "traceparent", tp_buf[..]);
            }
        } else if entry.kind == InterceptorKind.Logging {
            log_interceptor_request(pipeline, req, entry.log_level);
        }
    }
}

fn apply_app_interceptors_response(
    pipeline:    InterceptorPipeline&,
    req:         const Request&,
    resp:        Response&,
    err:         const Error&,
    duration_us: i64,
) {
    pipeline.metrics.total_requests += 1;
    pipeline.metrics.last_request_duration_us = duration_us;

    for &entry in pipeline.entries {
        guard entry.enabled && entry.scope == InterceptorScope.Application else { continue; }

        if entry.kind == InterceptorKind.Logging {
            log_interceptor_response(pipeline, resp, err, entry.log_level, duration_us);
        }
    }
}

// ---- Network Interceptor Hooks ------------------------------------------

fn apply_network_interceptors_request(
    pipeline:   InterceptorPipeline&,
    headers:    HeaderItem[..32]&,
    target_url: const u8[:],
    method:     const u8[:],
    body_len:   i64,
    hop_index:  i64,
) {
    pipeline.metrics.network_hops += 1;
    if body_len > 0 {
        pipeline.metrics.total_bytes_sent += body_len as! u64;
    }

    for &entry in pipeline.entries {
        guard entry.enabled && entry.scope == InterceptorScope.Network else { continue; }

        if entry.kind == InterceptorKind.Header {
            let h_name = entry.header_name[..];
            if !has_header(headers[..], h_name) {
                guard headers.len < headers.cap else { continue; }
                headers.push(make_header(h_name, entry.header_val[..]));
            }
        } else if entry.kind == InterceptorKind.Logging {
            log_network_interceptor_request(
                pipeline,
                headers,
                target_url,
                method,
                hop_index,
                entry.log_level,
            );
        }
    }
}

fn apply_network_interceptors_response(
    pipeline:        InterceptorPipeline&,
    resp:            Response&,
    hop_index:       i64,
    hop_duration_us: i64,
) {
    pipeline.metrics.last_hop_duration_us = hop_duration_us;
    pipeline.metrics.total_bytes_received += resp.body.len as! u64;

    for &entry in pipeline.entries {
        guard entry.enabled && entry.scope == InterceptorScope.Network else { continue; }

        if entry.kind == InterceptorKind.Logging {
            let lvl = entry.log_level;
            if lvl != LogLevel.None {
                var line: u8[..256] = [];
                format(line, "<-- (net hop ", hop_index, ") ", resp.status_code, " (", hop_duration_us, " us)");
                push_log(pipeline, line[..]);
            }
        }
    }
}
