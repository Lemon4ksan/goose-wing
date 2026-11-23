// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 7 Reverse Proxy Engine, Hop-by-Hop Header Stripping,
// Forwarded/Via Chaining, Upstream Request Dispatcher,
// Connection Leak Defense, and Backpressure Shield.
namespace proxy;

import std;
import core;
import http.headers;
import http.client_cert;
import http.early_hints;
import http.forwarded;
import http.status_diagnostics;
import http.incremental;
import net.tcp;
import net.transport;
import net.pool;
import net.upstream_pool;
import http.request;
import http.response;
import wire.h1_exchange;
import security.gcra;
import rfc.http;
import wire.h1;
import .load_balancer;
import .health_check;
import .internal;
import .headers_internal;

const TARGET_NONE: i32 = -1;

struct Config {
    strip_hop_by_hop:            bool       = true,
    append_forwarded:            bool       = true,
    emit_rfc7239_forwarded:      bool       = false,
    preserve_host:               bool       = false,
    trust_incoming_xff:          bool       = false,
    max_active_conns_per_target: i32        = 1024,
    enable_rate_limiting:        bool       = false,
    rate_limit_rps:              u64        = 100,
    rate_limit_burst:            u64        = 20,
    forward_client_cert:         bool       = false,
    client_cert_der_len:         i32        = 0,
    client_cert_der:             u8[..4096] = [],
    via_pseudonym:               u8[..32]   = "wing",
    http_version:                u8[..8]    = "HTTP/1.1",
}

// Identifies untrusted forwarding metadata headers to strip before re-injection.
// RFC 9440 Section 2.4: Processing Rules - incoming Client-Cert fields MUST be removed before forwarding.
inline fn is_forwarded_metadata_header(name: const u8[:]) -> bool {
    if name.eq_ascii_fold("x-forwarded-for") { return true; }
    if name.eq_ascii_fold("x-forwarded-proto") { return true; }
    if name.eq_ascii_fold("x-forwarded-host") { return true; }
    if name.eq_ascii_fold("x-forwarded-port") { return true; }
    if name.eq_ascii_fold("x-forwarded-server") { return true; }
    if name.eq_ascii_fold("x-forwarded-ssl") { return true; }
    if name.eq_ascii_fold("forwarded") { return true; }
    if name.eq_ascii_fold("client-cert") { return true; }
    if name.eq_ascii_fold("client-cert-chain") { return true; }
    if name.eq_ascii_fold("via") { return true; }
    return false;
}

// Filters incoming request headers and populates outgoing proxy request headers.
fn filter_and_forward_headers(
    in_headers:    const http::HeaderMap&,
    out_headers:   http::HeaderMap&,
    client_ip:     const u8[:],
    proto:         const u8[:],
    upstream_host: const u8[:],
    config:        const Config&,
) -> bool {
    guard proxy_internal::has_consistent_framing_headers(in_headers) else { return false; }
    http::reset_for_keep_alive(out_headers);
    var committed = false;
    defer if !committed { out_headers.clear(); };

    guard proxy_internal::copy_filtered_headers(in_headers, out_headers, config) else { return false; }

    // RFC 9440 §2.4: place the validated end-entity certificate in Client-Cert only when configured.
    let cert_der_len = config.client_cert_der_len;
    let actual_der_len = config.client_cert_der.len as i32;
    let eff_der_len = if cert_der_len > 0 { min(cert_der_len, actual_der_len) } else { actual_der_len };
    if config.forward_client_cert && eff_der_len > 0 && eff_der_len <= http::CLIENT_CERT_MAX_DER_LEN {
        var enc: u8[..8192] = [];
        if http::encode_client_cert(config.client_cert_der[..eff_der_len], enc) {
            guard http::append_header(out_headers, "Client-Cert", enc[..]) else { return false; }
        }
    }

    if !config.preserve_host && upstream_host.len > 0 {
        guard http::append_header(out_headers, "Host", upstream_host) else { return false; }
    }

    if config.append_forwarded {
        guard proxy_internal::inject_forwarded_metadata(
            out_headers,
            in_headers,
            client_ip,
            proto,
            config,
        ) else { return false; }
    }

    guard proxy_internal::inject_via_header(
        out_headers,
        in_headers,
        config.via_pseudonym[..],
        config.http_version[..],
    ) else { return false; }
    committed = true;
    return true;
}

// Formats upstream wire HTTP/1.1 request buffer ready for transmission.
fn serialize_upstream_request<B>(
    method:       const u8[:],
    uri:          const u8[:],
    headers:      const http::HeaderMap&,
    body:         const u8[:],
    out:          B&,
    http_version: const u8[:] = "HTTP/1.1",
) -> bool {
    out.clear();
    return wire::encode_h1_request(
        method,
        uri,
        "",
        headers,
        body,
        wire::H1HeaderFilterMode.PreserveAll,
        out,
        http_version,
    );
}

// Layer 7 Reverse Proxy Gateway instance managing an UpstreamCluster.
struct ReverseProxy {
    cluster:            UpstreamCluster              = UpstreamCluster { .. },
    warm_upstreams:     net::UpstreamPool            = net::UpstreamPool { .. },
    config:             Config                       = Config { .. },
    rate_limiter:       security::GatewayRateLimiter = security::GatewayRateLimiter { .. },
    health_checker:     ClusterHealthChecker         = ClusterHealthChecker { .. },
    total_forwarded:    u64                          = 0,
    total_dropped:      u64                          = 0,
    total_rate_limited: u64                          = 0,
    total_overloaded:   u64                          = 0,
}

fn new_reverse_proxy(policy: LbPolicy = LbPolicy.RoundRobin) -> ReverseProxy {
    return ReverseProxy {
        cluster:      new_upstream_cluster(policy),
        config:       Config { .. },
        rate_limiter: security::new_gateway_rate_limiter(100, 20),
        ..
    };
}

// Completes a dispatched proxy request cleanly, preventing active connection leaks.
fn finish_proxy_request(rp: ReverseProxy&, target_idx: i32, success: bool) {
    guard target_idx >= 0 && target_idx < rp.cluster.targets.len else { return; }
    release_upstream_connection(rp.cluster, target_idx);
    if success {
        record_upstream_success(rp.cluster, target_idx);
    } else {
        record_upstream_failure(rp.cluster, target_idx);
    }
}

// Finalizes an upstream exchange by evaluating the HTTP status code (5xx server errors
// count as upstream failures for circuit breaking) and releasing active connection state.
fn complete_upstream_exchange(
    rp:           ReverseProxy&,
    target_idx:   i32,
    status_code:  i32,
    transport_ok: bool,
    rtt_us:       u32 = 0,
) {
    let ok = transport_ok && status_code >= 100 && status_code < 500;
    finish_proxy_request(rp, target_idx, ok);
    if ok {
        let _ = on_probe_success(rp.health_checker, rp.cluster, target_idx, rtt_us);
    } else {
        let _ = on_probe_failure(rp.health_checker, rp.cluster, target_idx);
    }
}

// Aborts an in-flight proxy request due to downstream stall, timeout, or network disconnect.
fn abort_proxy_request(rp: ReverseProxy&, target_idx: i32) {
    guard target_idx >= 0 && target_idx < rp.cluster.targets.len else { return; }
    release_upstream_connection(rp.cluster, target_idx);
    record_upstream_failure(rp.cluster, target_idx);
}

// Configures gateway rate limit parameters, keeping Config and GatewayRateLimiter in sync.
fn set_proxy_rate_limit(rp: ReverseProxy&, rps: u64, burst: u64) {
    rp.config.enable_rate_limiting = true;
    rp.config.rate_limit_rps = rps;
    rp.config.rate_limit_burst = burst;
    rp.rate_limiter.config = security::new_gcra_config(rps, burst);
}

// Selects upstream target, applies GCRA rate limiting and concurrency backpressure defenses,
// rewrites headers, and serializes forward wire request.
fn prepare_proxy_request_at<B>(
    rp:         ReverseProxy&,
    method:     const u8[:],
    uri:        const u8[:],
    in_headers: const http::HeaderMap&,
    client_ip:  const u8[:],
    proto:      const u8[:],
    body:       const u8[:],
    out_wire:   B&,
    now_ns:     u64,
) -> i32, bool {
    let effective_now = if now_ns > 0 { now_ns } else { core::as_nanos(core::monotonic_now()) };

    // 1. Rate limiter defense against client flooding and downstream backpressure.
    if rp.config.enable_rate_limiting && client_ip.len > 0 && effective_now > 0 {
        let dec = security::check_gateway_rate_limit(rp.rate_limiter, client_ip, 1, effective_now);
        if !dec.allowed {
            rp.total_rate_limited = core::add_sat_u64(rp.total_rate_limited, 1);
            rp.total_dropped = core::add_sat_u64(rp.total_dropped, 1);
            return TARGET_NONE, false;
        }
    }

    // 2. Upstream target selection.
    let target_idx, ok = select_upstream(rp.cluster);
    guard ok && target_idx >= 0 && target_idx < rp.cluster.targets.len else {
        rp.total_dropped = core::add_sat_u64(rp.total_dropped, 1);
        return TARGET_NONE, false;
    }
    var committed = false;
    defer if !committed {
        release_upstream_connection(rp.cluster, target_idx);
        rp.total_dropped = core::add_sat_u64(rp.total_dropped, 1);
        out_wire.clear();
    };

    // 3. Concurrency ceiling defense against connection exhaustion.
    let target .= rp.cluster.targets[target_idx];
    let max_conns = rp.config.max_active_conns_per_target;
    if proxy_internal::is_target_concurrency_saturated(target, max_conns) {
        rp.total_overloaded = core::add_sat_u64(rp.total_overloaded, 1);
        return TARGET_NONE, false;
    }

    // 4. Header filtering and metadata injection.
    var forward_headers = http::HeaderMap { .. };
    var host_buf: u8[..160] = [];
    let ok_prep = proxy_internal::format_upstream_authority(
        target.host[..],
        target.port,
        rp.config.preserve_host,
        host_buf,
    ) &&
        filter_and_forward_headers(in_headers, forward_headers, client_ip, proto, host_buf[..], rp.config) &&
        proxy_internal::apply_max_forwards_policy(method, forward_headers) &&
        proxy_internal::ensure_forwarded_body_framing(forward_headers, body, method) &&
        serialize_upstream_request(method, uri, forward_headers, body, out_wire, rp.config.http_version[..]);
    guard ok_prep else {
        return TARGET_NONE, false;
    }

    committed = true;
    rp.total_forwarded = core::add_sat_u64(rp.total_forwarded, 1);
    return target_idx, true;
}

// Prepares an upstream wire request using the current monotonic clock timestamp.
fn prepare_proxy_request<B>(
    rp:         ReverseProxy&,
    method:     const u8[:],
    uri:        const u8[:],
    in_headers: const http::HeaderMap&,
    client_ip:  const u8[:],
    proto:      const u8[:],
    body:       const u8[:],
    out_wire:   B&,
) -> i32, bool {
    let now_ns = core::as_nanos(core::monotonic_now());
    return prepare_proxy_request_at(
        rp,
        method,
        uri,
        in_headers,
        client_ip,
        proto,
        body,
        out_wire,
        now_ns,
    );
}

// ---- Zero-Copy Streaming Forwarding & Kernel Splice Eligibility -----------

enum TransportKind {
    PlainTcp,
    Http1Connect,
    Tls,
    WebSocket,
    WebTransport,
    Unknown,
}

// Determines if a proxy tunnel can use kernel pipe forwarding (`splice(2)`).
// Restricted strictly to plain L4 TCP and unencrypted HTTP/1.1 CONNECT tunnels;
// TLS, WebSocket (RFC 6455 §5.3 XOR masking), and WebTransport (UDP datagrams)
// require userspace ring-buffer processing.
fn can_use_kernel_splice(kind: TransportKind, is_encrypted: bool) -> bool {
    guard !is_encrypted else { return false; }
    return kind == TransportKind.PlainTcp || kind == TransportKind.Http1Connect;
}

// Userspace zero-copy ring-buffer view for streaming chunk transfers (Invariant 10 & 13).
struct StreamRing {
    buf:        u8[..16384] = [],
    read_pos:   i64         = 0,
    total_read: u64         = 0,
    total_sent: u64         = 0,
}

// Vends unread slice directly from the streaming ring buffer (Invariant 10).
fn incoming_slice(ring: const StreamRing&) -> const u8[:] {
    guard ring.read_pos >= 0 && ring.read_pos <= ring.buf.len else { return ""; }
    return ring.buf[ring.read_pos..ring.buf.len];
}

// Advances read cursor after downstream/upstream consumption, resetting when fully drained.
fn advance_read(ring: StreamRing&, consumed: i64) -> bool {
    guard consumed >= 0 && ring.read_pos >= 0 && ring.read_pos <= ring.buf.len else { return false; }
    let next_pos = core::add_sat_u64(ring.read_pos as u64, consumed as u64);
    guard next_pos <= (ring.buf.len as u64) else { return false; }
    ring.read_pos = next_pos as i64;
    ring.total_sent = core::add_sat_u64(ring.total_sent, consumed as u64);
    if ring.read_pos == ring.buf.len {
        ring.buf.clear();
        ring.read_pos = 0;
    }
    return true;
}

// Compacts unread tail to index 0 to reclaim contiguous tail capacity.
fn compact_stream_ring(ring: StreamRing&) {
    guard ring.read_pos > 0 else { return; }
    ring.buf.compact_wire_buffer(ring.read_pos);
    ring.read_pos = 0;
}

// Appends incoming payload chunk into the bounded 16 KB ring buffer.
// Enforces Invariant 13: fails closed with explicit `false` on capacity overflow.
fn feed_stream_chunk(ring: StreamRing&, chunk: const u8[:]) -> bool {
    let needed = core::add_sat_u64(ring.buf.len as u64, chunk.len as u64);
    if needed > (ring.buf.cap as u64) {
        compact_stream_ring(ring);
    }
    guard ring.buf.try_append(chunk) else { return false; }
    ring.total_read = core::add_sat_u64(ring.total_read, chunk.len as u64);
    return true;
}

// Transfers a bounded chunk from `src` ring to `dst` ring, applying RFC 6455 Section 5.3
// Client-to-Server Masking when forwarding WebSocket frames in userspace.
fn forward_userspace_stream_chunk(
    src:     StreamRing&,
    dst:     StreamRing&,
    kind:    TransportKind,
    ws_mask: u8[4],
) -> i64, bool {
    let view = incoming_slice(src);
    guard view.len > 0 else { return 0, true; }
    let needed = core::add_sat_u64(dst.buf.len as u64, view.len as u64);
    if needed > (dst.buf.cap as u64) {
        compact_stream_ring(dst);
    }
    guard core::add_sat_u64(dst.buf.len as u64, view.len as u64) <= (dst.buf.cap as u64) else {
        return 0, false;
    }

    if kind == TransportKind.WebSocket {
        // RFC 6455 Section 5.3: Client-to-Server Masking - Octet i of transformed data is XORed with masking-key octet i MOD 4.
        var masked: u8[..16384] = [];
        guard view.len <= masked.cap else { return 0, false; }
        let base_offset = src.total_sent;
        for i in view.len {
            let mask_idx = (core::add_sat_u64(base_offset, i as u64) & 3) as i64;
            masked.push(view[i] ^ ws_mask[mask_idx]);
        }
        guard dst.buf.try_append(masked[..]) else { return 0, false; }
    } else {
        guard dst.buf.try_append(view) else { return 0, false; }
    }

    let n = view.len;
    dst.total_read = core::add_sat_u64(dst.total_read, n as u64);
    let _ = advance_read(src, n);
    return n, true;
}

// ---- Live Pooled Upstream Execution ----------------------------------------

enum WireReuse {
    Close,
    KeepAlive,
}

// Registers a pre-warmed backend socket into the proxy's `UpstreamPool` for zero-RTT keep-alive reuse.
fn park_proxy_upstream_conn(
    rp:              ReverseProxy&,
    fd:              i32,
    host:            const u8[:],
    port:            u16,
    tls_fingerprint: u64 = 0,
    nik:             u64 = 0,
) -> bool {
    guard fd >= 0 && host.len > 0 && port > 0 else { return false; }
    let pool_key = net::new_pool_key(
        net::PoolScheme.Http,
        host,
        port,
        net::new_direct_proxy_chain(),
        net::NetworkAnonymizationKey { .. },
        net::TlsAndDnsPolicy { .. },
    );
    return net::register_upstream_conn(rp.warm_upstreams, fd, pool_key.origin_endpoint, tls_fingerprint, nik);
}

fn exchange_prepared_wire_on_conn(
    conn:       net::PooledConnection&,
    method:     const u8[:],
    wire_req:   const u8[:],
    out_resp:   http::Response&,
    timeout_ms: u32,
) -> WireReuse, bool {
    var eh = http::EarlyHintsResponse { .. };
    return proxy_internal::exchange_prepared_wire_impl(
        conn, method, wire_req, out_resp, eh, proxy_internal::HintCaptureMode.Ignore, timeout_ms,
    );
}

fn exchange_prepared_wire_on_conn_with_hints(
    conn:         net::PooledConnection&,
    method:       const u8[:],
    wire_req:     const u8[:],
    out_upstream: UpstreamResponse&,
    timeout_ms:   u32,
) -> WireReuse, bool {
    var eh = http::EarlyHintsResponse { .. };
    let reuse, ok = proxy_internal::exchange_prepared_wire_impl(
        conn, method, wire_req, out_upstream.resp, eh, proxy_internal::HintCaptureMode.Capture, timeout_ms,
    );
    out_upstream.early_hints = eh;
    out_upstream.has_early_hints = eh.is_valid;
    return reuse, ok;
}

// ---- Upstream `X-Accel-*` Control Headers, `Location` Rewriting & `103` Capture ----

struct UpstreamAccelControl {
    disable_buffering:     bool       = false,
    incremental_preferred: bool       = false,
    has_accel_expires:     bool       = false,
    accel_expires_sec:     i64        = 0,
    limit_rate_bps:        u64        = 0,
    accel_redirect:        u8[..1024] = [],
}

struct UpstreamResponse {
    early_hints:     http::EarlyHintsResponse = http::EarlyHintsResponse { .. },
    has_early_hints: bool                     = false,
    accel:           UpstreamAccelControl     = UpstreamAccelControl { .. },
    resp:            http::Response           = http::Response { .. },
}

// Parses `X-Accel-*` control header values into `accel` (Nginx `ngx_http_upstream_headers_in` parity).
//
// Example:
//   name = "X-Accel-Buffering", val = "no"
//   returns: true (is X-Accel header), accel.disable_buffering = true
fn parse_x_accel_control_header(name: const u8[:], val: const u8[:], accel: UpstreamAccelControl&) -> bool {
    let trimmed = val.trim_lws();
    if name.eq_ascii_fold("x-accel-buffering") {
        if trimmed.eq_ascii_fold("no") {
            accel.disable_buffering = true;
        } else if trimmed.eq_ascii_fold("yes") {
            accel.disable_buffering = false;
        }
        return true;
    }
    if name.eq_ascii_fold("x-accel-expires") {
        if trimmed.eq_ascii_fold("off") {
            accel.has_accel_expires = true;
            accel.accel_expires_sec = 0;
        } else {
            let s_slice = if trimmed.len > 1 && trimmed[0] == '@' { trimmed[1..] } else { trimmed };
            let secs, ok = s_slice.parse_u64_dec();
            if ok {
                accel.has_accel_expires = true;
                accel.accel_expires_sec = secs as i64;
            }
        }
        return true;
    }
    if name.eq_ascii_fold("x-accel-limit-rate") {
        let rate, ok = trimmed.parse_u64_dec();
        if ok {
            accel.limit_rate_bps = rate;
        }
        return true;
    }
    if name.eq_ascii_fold("x-accel-redirect") {
        guard accel.accel_redirect.len == 0 && proxy_internal::is_valid_accel_redirect_target(trimmed) else {
            return false;
        }
        return accel.accel_redirect.try_set(trimmed);
    }
    return name.starts_with_fold("x-accel-");
}

fn try_rewrite_upstream_url<B>(
    url_val:            const u8[:],
    backend_url_prefix: const u8[:],
    public_url_prefix:  const u8[:],
    out:                B&,
) -> const u8[:], bool {
    guard proxy_internal::matches_backend_url_prefix(url_val, backend_url_prefix) else {
        return url_val, true;
    }
    let suffix = url_val[backend_url_prefix.len..];
    guard !(public_url_prefix.len == 0 && core::starts_with(suffix, "//")) else {
        return "", false;
    }
    var committed = false;
    defer if !committed { out.clear(); };
    guard out.try_set(public_url_prefix) else { return "", false; }
    guard out.try_append(suffix) else { return "", false; }
    committed = true;
    return out[..], true;
}

// Parses `X-Accel-*` control headers, strips hop-by-hop and `X-Accel-*` headers,
// and rewrites `Location` and `Content-Location` prefixes matching `backend_url_prefix`.
fn process_and_filter_upstream_response_headers<B>(
    in_headers:         const http::HeaderMap&,
    backend_url_prefix: const u8[:],
    public_url_prefix:  const u8[:],
    out_headers:        http::HeaderMap&,
    out_location_buf:   B&,
    accel:              UpstreamAccelControl&,
) -> bool {
    guard proxy_internal::has_consistent_framing_headers(in_headers) else { return false; }
    out_headers.clear();
    out_location_buf.clear();
    accel = UpstreamAccelControl { .. };
    var committed = false;
    defer if !committed {
        out_headers.clear();
        out_location_buf.clear();
        accel = UpstreamAccelControl { .. };
    };
    if http::is_incremental_requested(in_headers) {
        accel.incremental_preferred = true;
        accel.disable_buffering = true;
    }
    var first_loc_entry_idx: i64 = -1;
    for entry_idx in in_headers.entries.len {
        guard proxy_internal::filter_single_upstream_response_header(
            in_headers,
            entry_idx,
            backend_url_prefix,
            public_url_prefix,
            out_headers,
            out_location_buf,
            accel,
            first_loc_entry_idx,
        ) else {
            return false;
        }
    }
    committed = true;
    return true;
}

// Captures `Link` headers from an upstream `103 Early Hints` interim response into `out_upstream`.
fn capture_upstream_early_hints(in_resp: const http::Response&, out_upstream: UpstreamResponse&) {
    guard in_resp.status_code == 103 else { return; }
    for &entry in in_resp.headers.entries {
        let name = http::entry_name(in_resp.headers, entry);
        if name.eq_ascii_fold("link") {
            let val = http::entry_value(in_resp.headers, entry);
            if http::parse_link_header(val, out_upstream.early_hints.links) {
                out_upstream.early_hints.is_valid = out_upstream.early_hints.links.len > 0;
                out_upstream.has_early_hints = out_upstream.early_hints.is_valid;
            }
        }
    }
}

// Executes a full reverse proxy exchange over `StreamPool`: selects an upstream target,
// rewrites and serializes the HTTP/1.1 request (`prepare_proxy_request_at`), acquires or dials
// a pooled backend connection, reads the upstream response, and records health via `complete_upstream_exchange`.
fn execute_proxy_exchange(
    rp:         ReverseProxy&,
    pool:       net::StreamPool&,
    method:     const u8[:],
    uri:        const u8[:],
    in_headers: const http::HeaderMap&,
    client_ip:  const u8[:],
    proto:      const u8[:],
    body:       const u8[:],
    out_resp:   http::Response&,
    timeout_ms: u32 = 5000,
    now_ns:     u64 = 0,
) -> bool {
    let effective_now = if now_ns > 0 { now_ns } else { core::as_nanos(core::monotonic_now()) };
    var wire_req: u8[..16384] = [];
    let target_idx, ok_prep = prepare_proxy_request_at(
        rp, method, uri, in_headers, client_ip, proto, body, wire_req, effective_now,
    );
    guard ok_prep && target_idx >= 0 else { return false; }

    let target .= rp.cluster.targets[target_idx];
    let now_i64 = effective_now as i64;
    let conn_id, warm_fd, ok_conn = proxy_internal::acquire_or_dial_upstream_conn(
        pool, rp.warm_upstreams, target, timeout_ms, now_i64,
    );
    guard ok_conn && conn_id > 0 else {
        complete_upstream_exchange(rp, target_idx, 0, false);
        return false;
    }

    let c_idx = pool.find_connection_index(conn_id);
    guard c_idx >= 0 else {
        if warm_fd >= 0 {
            let _ = net::release_upstream_conn(rp.warm_upstreams, warm_fd, net::EPOLLRDHUP);
        } else {
            pool.close_pooled_connection(conn_id);
        }
        complete_upstream_exchange(rp, target_idx, 0, false);
        return false;
    }

    pool.conns[c_idx].rx_buf.clear();
    let start_inst = core::monotonic_now();
    let reuse, ok_ex = exchange_prepared_wire_on_conn(
        pool.conns[c_idx], method, wire_req[..], out_resp, timeout_ms,
    );
    var headers_valid = ok_ex && !out_resp.had_te_cl_conflict;
    if headers_valid {
        var filtered_hdrs = http::HeaderMap { .. };
        var loc_buf: u8[..512] = [];
        var accel = UpstreamAccelControl { .. };
        headers_valid = process_and_filter_upstream_response_headers(
            out_resp.headers, "", "", filtered_hdrs, loc_buf, accel,
        );
        if headers_valid {
            out_resp.headers = filtered_hdrs;
        }
    }
    let can_reuse = headers_valid && reuse == WireReuse.KeepAlive && pool.conns[c_idx].rx_buf.len == 0;
    proxy_internal::finalize_proxy_upstream_conn(rp, pool, conn_id, c_idx, warm_fd, can_reuse, now_i64);
    if headers_valid {
        var ps_entry = http::ProxyStatusEntry {
            received_status: out_resp.status_code,
            ..
        };
        let _ = ps_entry.proxy_name.try_set(rp.config.via_pseudonym[..]);
        let _ = ps_entry.next_hop.try_set(target.host[..]);
        var ps_buf: u8[..256] = [];
        http::format_proxy_status(ps_entry, ps_buf);
        out_resp.set_header("Proxy-Status", ps_buf[..]);
    }
    let recorded_status = if headers_valid { out_resp.status_code } else { 0 };
    let rtt_us = if headers_valid { proxy_internal::calc_probe_rtt_us(start_inst) } else { 0 };
    complete_upstream_exchange(rp, target_idx, recorded_status, headers_valid, rtt_us);
    return headers_valid;
}
