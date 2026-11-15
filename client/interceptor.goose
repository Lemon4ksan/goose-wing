// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// OkHttp/Tower-style 2-tier Interceptor Pipeline (Application & Network Interceptors).
// Compliant with OkHttp Interceptor specification & Tower Service Layer design:
// - Application Interceptors: Run once per logical call, observe uncompressed/unrouted intent,
//   can rewrite/short-circuit.
// - Network Interceptors: Run on each wire hop (redirects, retries, Alt-Svc racing), observe wire headers & transport.
namespace wing;

import std;
import core from "..";
import http.request;
import http.headers;
import http.trace;

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

fn upsert_interceptor_header(list: InterceptorHeader[..4]&, name: const u8[:], val: const u8[:]) -> bool {
    var item = InterceptorHeader { .. };
    guard item.name.try_set(name) && item.val.try_set(val) else { return false; }
    for &entry in list {
        if entry.name[..].eq_ascii_fold(name) {
            return entry.val.try_set(val);
        }
    }
    return list.try_push(item);
}

fn add_header(pipeline: InterceptorPipeline&, scope: InterceptorScope, name: const u8[:], val: const u8[:]) -> bool {
    match scope {
        Application => {
            guard upsert_interceptor_header(pipeline.app_headers, name, val) else {
                return false;
            }
            pipeline.active_mask |= INTERCEPTOR_APP_HEADER;
            return true;
        },
        Network => {
            guard upsert_interceptor_header(pipeline.net_headers, name, val) else {
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

// Queries if an application retry policy is configured
fn find_retry_policy(pipeline: const InterceptorPipeline&, out_retries: i32&, out_retry_5xx: bool&) -> bool {
    if (pipeline.active_mask & INTERCEPTOR_APP_RETRY) != 0 {
        out_retries = pipeline.max_retries;
        out_retry_5xx = pipeline.retry_on_5xx;
        return true;
    }
    return false;
}

// ---- Formatting Utilities ------------------------------------------------

// W3C TraceContext traceparent generator:
// Format: 00-{32 hex trace_id}-{16 hex parent_id}-{2 hex flags}
fn generate_traceparent<B>(counter: u64, clock_us: i64, flag: const u8[:], out: B&) {
    let hi = clock_us as! u64;
    let lo = counter ^ 0xa5a5a5a5a5a5a5a5;
    let trace_id: u8[16] = [
        ((hi >> 56) & 0xFF) as u8, ((hi >> 48) & 0xFF) as u8,
        ((hi >> 40) & 0xFF) as u8, ((hi >> 32) & 0xFF) as u8,
        ((hi >> 24) & 0xFF) as u8, ((hi >> 16) & 0xFF) as u8,
        ((hi >> 8) & 0xFF) as u8, (hi & 0xFF) as u8,
        ((lo >> 56) & 0xFF) as u8, ((lo >> 48) & 0xFF) as u8,
        ((lo >> 40) & 0xFF) as u8, ((lo >> 32) & 0xFF) as u8,
        ((lo >> 24) & 0xFF) as u8, ((lo >> 16) & 0xFF) as u8,
        ((lo >> 8) & 0xFF) as u8, (lo & 0xFF) as u8,
    ];
    let parent_id: u8[8] = [
        ((counter >> 56) & 0xFF) as u8, ((counter >> 48) & 0xFF) as u8,
        ((counter >> 40) & 0xFF) as u8, ((counter >> 32) & 0xFF) as u8,
        ((counter >> 24) & 0xFF) as u8, ((counter >> 16) & 0xFF) as u8,
        ((counter >> 8) & 0xFF) as u8, (counter & 0xFF) as u8,
    ];
    var tp = new_traceparent(trace_id, parent_id, flag != "00");
    if flag.len == 2 {
        let parsed_f, ok_f = parse_hex_u8(flag, 0);
        if ok_f {
            tp.trace_flags = parsed_f;
        }
    }
    format_traceparent(tp, out);
}

fn push_log(pipeline: InterceptorPipeline&, msg: const u8[:]) {
    guard pipeline.record_logs else { return; }
    var entry: u8[..128] = [];
    let n = min(msg.len, entry.cap);
    let _ = entry.try_set(msg[..n]);
    let _ = pipeline.log_entries.try_push(entry);
}

fn log_interceptor_request(pipeline: InterceptorPipeline&, req: const Request&, lvl: LogLevel) {
    guard lvl != LogLevel.None else { return; }
    var line: u8[..256] = [];
    let u_len = min(req.url.len, 180);
    format(line, "--> ", req.method[..], " ", req.url[..u_len]);
    push_log(pipeline, line[..]);

    if lvl == LogLevel.Headers || lvl == LogLevel.Body {
        for &e in req.headers.entries {
            let h_name = entry_name(req.headers, e);
            let h_val = if is_sensitive(e) || is_heuristic_sensitive_header(h_name) {
                "[REDACTED]"
            } else {
                entry_value(req.headers, e)
            };
            let v_len = min(h_val.len, 160);
            var h_line: u8[..256] = [];
            format(h_line, "--> ", h_name, ": ", h_val[..v_len]);
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
        let m_len = min(err.message.len, 180);
        format(line, "<-- FAILED (", err.message[..m_len], ")");
    }
    push_log(pipeline, line[..]);

    if ok(err) && (lvl == LogLevel.Headers || lvl == LogLevel.Body) {
        for &e in resp.headers.entries {
            let h_name = entry_name(resp.headers, e);
            let h_val = if is_sensitive(e) || is_heuristic_sensitive_header(h_name) {
                "[REDACTED]"
            } else {
                entry_value(resp.headers, e)
            };
            let v_len = min(h_val.len, 160);
            var h_line: u8[..256] = [];
            format(h_line, "<-- ", h_name, ": ", h_val[..v_len]);
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
    headers:    const HeaderMap&,
    target_url: const u8[:],
    method:     const u8[:],
    hop_index:  i64,
    lvl:        LogLevel,
) {
    guard lvl != LogLevel.None else { return; }
    var line: u8[..256] = [];
    let u_len = min(target_url.len, 160);
    format(line, "--> (net hop ", hop_index, ") ", method, " ", target_url[..u_len]);
    push_log(pipeline, line[..]);

    if lvl == LogLevel.Headers || lvl == LogLevel.Body {
        for &e in headers.entries {
            let h_name = entry_name(headers, e);
            let h_val = if is_sensitive(e) || is_heuristic_sensitive_header(h_name) {
                "[REDACTED]"
            } else {
                entry_value(headers, e)
            };
            let v_len = min(h_val.len, 150);
            var h_line: u8[..256] = [];
            format(h_line, "--> (net) ", h_name, ": ", h_val[..v_len]);
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
    let mask = pipeline.active_mask;
    if (mask & INTERCEPTOR_APP_ALL) == 0 {
        return;
    }

    if (mask & INTERCEPTOR_APP_AUTH_BEARER) != 0 {
        if header(req, "Authorization").len == 0 {
            sensitive_header(req, "Authorization", pipeline.bearer_token[..]);
        }
    }
    if (mask & INTERCEPTOR_APP_HEADER) != 0 {
        for &hdr in pipeline.app_headers {
            if header(req, hdr.name[..]).len == 0 {
                set_header(req, hdr.name[..], hdr.val[..]);
            }
        }
    }
    if (mask & INTERCEPTOR_APP_REQUEST_ID) != 0 {
        if header(req, "X-Request-ID").len == 0 {
            var val_buf: u8[..64] = [];
            format(val_buf, pipeline.req_id_prefix[..], pipeline.req_id_counter);
            pipeline.req_id_counter += 1;
            set_header(req, "X-Request-ID", val_buf[..]);
        }
    }
    if (mask & INTERCEPTOR_APP_TRACEPARENT) != 0 {
        if header(req, "traceparent").len == 0 {
            var tp_buf: u8[..64] = [];
            generate_traceparent(pipeline.traceparent_counter, clock_us, pipeline.traceparent_flag[..], tp_buf);
            pipeline.traceparent_counter += 1;
            set_header(req, "traceparent", tp_buf[..]);
        }
    }
    if (mask & INTERCEPTOR_APP_LOGGING) != 0 {
        log_interceptor_request(pipeline, req, pipeline.app_log_level);
    }
}

fn apply_app_interceptors_response(
    pipeline:    InterceptorPipeline&,
    _req:        const Request&,
    resp:        Response&,
    err:         const Error&,
    duration_us: i64,
) {
    pipeline.metrics.total_requests += 1;
    pipeline.metrics.last_request_duration_us = duration_us;

    if (pipeline.active_mask & INTERCEPTOR_APP_LOGGING) != 0 {
        log_interceptor_response(pipeline, resp, err, pipeline.app_log_level, duration_us);
    }
}

// ---- Network Interceptor Hooks ------------------------------------------

fn apply_network_interceptors_request(
    pipeline:   InterceptorPipeline&,
    headers:    HeaderMap&,
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
    if (mask & INTERCEPTOR_NET_ALL) == 0 {
        return;
    }

    if (mask & INTERCEPTOR_NET_HEADER) != 0 {
        for &hdr in pipeline.net_headers {
            if !has_header(headers, hdr.name[..]) {
                set_header(headers, hdr.name[..], hdr.val[..]);
            }
        }
    }
    if (mask & INTERCEPTOR_NET_LOGGING) != 0 {
        log_network_interceptor_request(
            pipeline,
            headers,
            target_url,
            method,
            hop_index,
            pipeline.net_log_level,
        );
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

    if (pipeline.active_mask & INTERCEPTOR_NET_LOGGING) != 0 {
        let lvl = pipeline.net_log_level;
        if lvl != LogLevel.None {
            var line: u8[..256] = [];
            format(line, "<-- (net hop ", hop_index, ") ", resp.status_code, " (", hop_duration_us, " us)");
            push_log(pipeline, line[..]);
        }
    }
}
