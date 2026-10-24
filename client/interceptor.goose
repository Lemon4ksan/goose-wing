// OkHttp/Tower-style 2-tier Interceptor Pipeline (Application & Network Interceptors).
// Compliant with OkHttp Interceptor specification & Tower Service Layer design:
// - Application Interceptors: Run once per logical call, observe uncompressed/unrouted intent, can rewrite/short-circuit.
// - Network Interceptors: Run on each wire hop (redirects, retries, Alt-Svc racing), observe wire headers & transport.
namespace wing;

import std;
import client.profile;
import client.request;
import client.response;

// ---- 1. Interceptor Scope & Kinds -------------------------------------------

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

// ---- 2. Configuration Models ------------------------------------------------

struct InterceptorEntry {
    scope: InterceptorScope = InterceptorScope.Application,
    kind: InterceptorKind = InterceptorKind.None,
    log_level: LogLevel = LogLevel.Basic,
    header_name: u8[..64] = [],
    header_val: u8[..256] = [],
    prefix: u8[..32] = [],
    counter: u64 = 0,
    max_retries: i32 = 0,
    retry_on_5xx: bool = true,
    enabled: bool = true,
}

struct NetworkMetrics {
    total_requests: u64 = 0,
    network_hops: u64 = 0,
    redirect_hops: u64 = 0,
    total_bytes_sent: u64 = 0,
    total_bytes_received: u64 = 0,
    last_request_duration_us: i64 = 0,
    last_hop_duration_us: i64 = 0,
}

struct InterceptorPipeline {
    entries: InterceptorEntry[..8] = [],
    metrics: NetworkMetrics = NetworkMetrics { .. },
    log_entries: u8[..128][..32] = [],
    record_logs: bool = true,
}

fn new_interceptor_pipeline() -> InterceptorPipeline {
    return InterceptorPipeline { .. };
}

// ---- 3. Pipeline Builders ---------------------------------------------------

fn add_interceptor(pipeline: InterceptorPipeline&, entry: InterceptorEntry) -> bool {
    guard pipeline.entries.len < pipeline.entries.cap else { return false; }
    pipeline.entries.push(entry);
    return true;
}

fn add_pipeline_logging(pipeline: InterceptorPipeline&, scope: InterceptorScope, level: LogLevel) -> bool {
    let entry = InterceptorEntry {
        scope: scope,
        kind: InterceptorKind.Logging,
        log_level: level,
        enabled: true,
        ..
    };
    return add_interceptor(pipeline, entry);
}

fn add_pipeline_bearer_auth(pipeline: InterceptorPipeline&, token: const u8[:]) -> bool {
    var entry = InterceptorEntry {
        scope: InterceptorScope.Application,
        kind: InterceptorKind.AuthBearer,
        enabled: true,
        ..
    };
    entry.header_name.append("Authorization");
    entry.header_val.append("Bearer ");
    entry.header_val.append(token);
    return add_interceptor(pipeline, entry);
}

fn add_pipeline_header(pipeline: InterceptorPipeline&, scope: InterceptorScope, name: const u8[:], val: const u8[:]) -> bool {
    var entry = InterceptorEntry {
        scope: scope,
        kind: InterceptorKind.Header,
        enabled: true,
        ..
    };
    entry.header_name.append(name);
    entry.header_val.append(val);
    return add_interceptor(pipeline, entry);
}

fn add_pipeline_request_id(pipeline: InterceptorPipeline&, prefix: const u8[:] = "req-") -> bool {
    var entry = InterceptorEntry {
        scope: InterceptorScope.Application,
        kind: InterceptorKind.RequestId,
        enabled: true,
        ..
    };
    entry.header_name.append("X-Request-ID");
    entry.prefix.append(prefix);
    entry.counter = 1;
    return add_interceptor(pipeline, entry);
}

fn add_pipeline_traceparent(pipeline: InterceptorPipeline&, sample_flag: const u8[:] = "01") -> bool {
    var entry = InterceptorEntry {
        scope: InterceptorScope.Application,
        kind: InterceptorKind.Traceparent,
        enabled: true,
        ..
    };
    entry.header_name.append("traceparent");
    entry.prefix.append(sample_flag);
    entry.counter = 1;
    return add_interceptor(pipeline, entry);
}

fn add_pipeline_retry(pipeline: InterceptorPipeline&, max_retries: i32, retry_on_5xx: bool = true) -> bool {
    let entry = InterceptorEntry {
        scope: InterceptorScope.Application,
        kind: InterceptorKind.RetryPolicy,
        max_retries: max_retries,
        retry_on_5xx: retry_on_5xx,
        enabled: true,
        ..
    };
    return add_interceptor(pipeline, entry);
}

fn add_pipeline_metrics(pipeline: InterceptorPipeline&) -> bool {
    let entry = InterceptorEntry {
        scope: InterceptorScope.Network,
        kind: InterceptorKind.Metrics,
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

// ---- 4. Formatting Utilities ------------------------------------------------

fn hex_char(nibble: u8) -> u8 {
    return if nibble < 10 { '0' + nibble } else { 'a' + (nibble - 10) };
}

fn format_hex_u64<B>(val: u64, out: B&) {
    for i in 16 {
        let shift = ((15 - i) * 4) as u64;
        let nibble = ((val >> shift) & 0xF) as u8;
        out.push(hex_char(nibble));
    }
}

// W3C TraceContext traceparent generator:
// Format: 00-{32 hex trace_id}-{16 hex parent_id}-{2 hex flags}
fn generate_traceparent<B>(counter: u64, clock_us: i64, flag: const u8[:], out: B&) {
    out.append("00-");
    format_hex_u64(clock_us as! u64, out);
    format_hex_u64(counter ^ 0xa5a5a5a5a5a5a5a5, out);
    out.append("-");
    format_hex_u64(counter, out);
    out.append("-");
    if flag.len == 2 {
        out.append(flag);
    } else {
        out.append("01");
    }
}

fn push_pipeline_log(pipeline: InterceptorPipeline&, msg: const u8[:]) {
    guard pipeline.record_logs else { return; }
    if pipeline.log_entries.len < pipeline.log_entries.cap {
        var entry: u8[..128] = [];
        entry.append(msg);
        pipeline.log_entries.push(entry);
    }
}

// ---- 5. Application Interceptor Hooks ---------------------------------------

fn apply_app_interceptors_request(
    pipeline: InterceptorPipeline&,
    req: Request&,
    clock_us: i64
) {
    for i in pipeline.entries.len {
        guard pipeline.entries[i].enabled && pipeline.entries[i].scope == InterceptorScope.Application else { continue; }

        if pipeline.entries[i].kind == InterceptorKind.AuthBearer {
            // Only add if not already present
            if header(req, "Authorization").len == 0 {
                req.headers.push(make_header("Authorization", pipeline.entries[i].header_val[..]));
            }
        } else if pipeline.entries[i].kind == InterceptorKind.Header {
            let h_name = pipeline.entries[i].header_name[..];
            if header(req, h_name).len == 0 {
                req.headers.push(make_header(h_name, pipeline.entries[i].header_val[..]));
            }
        } else if pipeline.entries[i].kind == InterceptorKind.RequestId {
            if header(req, "X-Request-ID").len == 0 {
                var val_buf: u8[..64] = [];
                val_buf.append(pipeline.entries[i].prefix[..]);
                format(val_buf, pipeline.entries[i].counter);
                pipeline.entries[i].counter += 1;
                req.headers.push(make_header("X-Request-ID", val_buf[..]));
            }
        } else if pipeline.entries[i].kind == InterceptorKind.Traceparent {
            if header(req, "traceparent").len == 0 {
                var tp_buf: u8[..64] = [];
                generate_traceparent(pipeline.entries[i].counter, clock_us, pipeline.entries[i].prefix[..], tp_buf);
                pipeline.entries[i].counter += 1;
                req.headers.push(make_header("traceparent", tp_buf[..]));
            }
        } else if pipeline.entries[i].kind == InterceptorKind.Logging {
            let lvl = pipeline.entries[i].log_level;
            if lvl != LogLevel.None {
                var line: u8[..256] = [];
                line.append("--> ");
                line.append(req.method[..]);
                line.append(" ");
                line.append(req.url[..]);
                push_pipeline_log(pipeline, line[..]);

                if lvl == LogLevel.Headers || lvl == LogLevel.Body {
                    for &h in req.headers {
                        var h_line: u8[..256] = [];
                        h_line.append("--> ");
                        h_line.append(h.name[..]);
                        h_line.append(": ");
                        h_line.append(h.value[..]);
                        push_pipeline_log(pipeline, h_line[..]);
                    }
                }
                if lvl == LogLevel.Body && req.body.len > 0 {
                    var b_line: u8[..256] = [];
                    b_line.append("--> (body ");
                    format(b_line, req.body.len);
                    b_line.append(" bytes)");
                    push_pipeline_log(pipeline, b_line[..]);
                }
            }
        }
    }
}

fn apply_app_interceptors_response(
    pipeline: InterceptorPipeline&,
    req: const Request&,
    resp: Response&,
    err: const Error&,
    duration_us: i64
) {
    pipeline.metrics.total_requests += 1;
    pipeline.metrics.last_request_duration_us = duration_us;

    for i in pipeline.entries.len {
        guard pipeline.entries[i].enabled && pipeline.entries[i].scope == InterceptorScope.Application else { continue; }

        if pipeline.entries[i].kind == InterceptorKind.Logging {
            let lvl = pipeline.entries[i].log_level;
            if lvl != LogLevel.None {
                var line: u8[..256] = [];
                line.append("<-- ");
                if ok(err) {
                    format(line, resp.status_code);
                    line.append(" (");
                    format(line, duration_us);
                    line.append(" us)");
                } else {
                    line.append("FAILED (");
                    line.append(err.message[..]);
                    line.append(")");
                }
                push_pipeline_log(pipeline, line[..]);

                if ok(err) && (lvl == LogLevel.Headers || lvl == LogLevel.Body) {
                    for &h in resp.headers {
                        var h_line: u8[..256] = [];
                        h_line.append("<-- ");
                        h_line.append(h.name[..]);
                        h_line.append(": ");
                        h_line.append(h.value[..]);
                        push_pipeline_log(pipeline, h_line[..]);
                    }
                }
                if ok(err) && lvl == LogLevel.Body && resp.body.len > 0 {
                    var b_line: u8[..256] = [];
                    b_line.append("<-- (body ");
                    format(b_line, resp.body.len);
                    b_line.append(" bytes)");
                    push_pipeline_log(pipeline, b_line[..]);
                }
            }
        }
    }
}

// ---- 6. Network Interceptor Hooks ------------------------------------------

fn apply_network_interceptors_request(
    pipeline: InterceptorPipeline&,
    headers: HeaderItem[..32]&,
    target_url: const u8[:],
    method: const u8[:],
    body_len: i64,
    hop_index: i64
) {
    pipeline.metrics.network_hops += 1;
    if body_len > 0 {
        pipeline.metrics.total_bytes_sent += body_len as! u64;
    }

    for i in pipeline.entries.len {
        guard pipeline.entries[i].enabled && pipeline.entries[i].scope == InterceptorScope.Network else { continue; }

        if pipeline.entries[i].kind == InterceptorKind.Header {
            let h_name = pipeline.entries[i].header_name[..];
            var found = false;
            for &h in headers {
                if eq_ascii_fold(h.name[..], h_name) {
                    found = true;
                    break;
                }
            }
            if !found {
                headers.push(make_header(h_name, pipeline.entries[i].header_val[..]));
            }
        } else if pipeline.entries[i].kind == InterceptorKind.Logging {
            let lvl = pipeline.entries[i].log_level;
            if lvl != LogLevel.None {
                var line: u8[..256] = [];
                line.append("--> (net hop ");
                format(line, hop_index);
                line.append(") ");
                line.append(method);
                line.append(" ");
                line.append(target_url);
                push_pipeline_log(pipeline, line[..]);

                if lvl == LogLevel.Headers || lvl == LogLevel.Body {
                    for &h in headers {
                        var h_line: u8[..256] = [];
                        h_line.append("--> (net) ");
                        h_line.append(h.name[..]);
                        h_line.append(": ");
                        h_line.append(h.value[..]);
                        push_pipeline_log(pipeline, h_line[..]);
                    }
                }
            }
        }
    }
}

fn apply_network_interceptors_response(
    pipeline: InterceptorPipeline&,
    resp: Response&,
    hop_index: i64,
    hop_duration_us: i64
) {
    pipeline.metrics.last_hop_duration_us = hop_duration_us;
    pipeline.metrics.total_bytes_received += resp.body.len as! u64;

    for i in pipeline.entries.len {
        guard pipeline.entries[i].enabled && pipeline.entries[i].scope == InterceptorScope.Network else { continue; }

        if pipeline.entries[i].kind == InterceptorKind.Logging {
            let lvl = pipeline.entries[i].log_level;
            if lvl != LogLevel.None {
                var line: u8[..256] = [];
                line.append("<-- (net hop ");
                format(line, hop_index);
                line.append(") ");
                format(line, resp.status_code);
                line.append(" (");
                format(line, hop_duration_us);
                line.append(" us)");
                push_pipeline_log(pipeline, line[..]);
            }
        }
    }
}
