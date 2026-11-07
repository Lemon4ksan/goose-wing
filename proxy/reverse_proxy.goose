// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 7 Reverse Proxy Engine, Hop-by-Hop Header Stripping,
// Forwarded/Via Chaining, Upstream Request Dispatcher,
// Connection Leak Defense, and Backpressure Shield (RFC 9110 §7.6).
namespace wing;

import std;
import core from "..";
import http.headers;
import http.client_cert;
import http.early_hints;
import net.tcp;
import net.transport;
import net.pool;
import client.request;
import client.response;
import client.session.h1_exchange;
import proxy.gcra;
import proxy.load_balancer;
import wire.h1;

const PROXY_TARGET_NONE: i32 = -1;

struct ProxyConfig {
    strip_hop_by_hop:            bool       = true,
    append_forwarded:            bool       = true,
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

// Helper to format chained X-Forwarded-For value without dynamic heap allocation.
fn format_chained_xff(buf: u8[..1024]&, existing_xff: const u8[:], client_ip: const u8[:]) -> bool {
    let needed = core::add_sat_u64(core::add_sat_u64(existing_xff.len as u64, 2), client_ip.len as u64);
    guard needed <= (buf.cap as u64) else { return false; }
    buf.clear();
    buf.append(existing_xff);
    buf.append(", ");
    buf.append(client_ip);
    return true;
}

// Appends client IP to X-Forwarded-For header, chaining with existing entries if present.
fn append_chained_xff(out_headers: HeaderMap&, existing_xff: const u8[:], client_ip: const u8[:]) -> bool {
    var chained: u8[..1024] = [];
    guard format_chained_xff(chained, existing_xff, client_ip) else { return false; }
    return append_header(out_headers, "X-Forwarded-For", chained[..]);
}

fn append_forwarded_for(out_headers: HeaderMap&, existing_xff: const u8[:], client_ip: const u8[:]) -> bool {
    guard client_ip.len > 0 else { return true; }
    if existing_xff.len > 0 {
        return append_chained_xff(out_headers, existing_xff, client_ip);
    }
    return append_header(out_headers, "X-Forwarded-For", client_ip);
}

// Identifies untrusted forwarding metadata headers to strip before re-injection.
// RFC 9440 §2.4: incoming Client-Cert* fields MUST be removed or overwritten before forwarding.
inline fn is_forwarded_metadata_header(name: const u8[:]) -> bool {
    if eq_ascii_fold(name, "x-forwarded-for") { return true; }
    if eq_ascii_fold(name, "x-forwarded-proto") { return true; }
    if eq_ascii_fold(name, "x-forwarded-host") { return true; }
    if eq_ascii_fold(name, "x-forwarded-port") { return true; }
    if eq_ascii_fold(name, "x-forwarded-server") { return true; }
    if eq_ascii_fold(name, "x-forwarded-ssl") { return true; }
    if eq_ascii_fold(name, "forwarded") { return true; }
    if eq_ascii_fold(name, "client-cert") { return true; }
    if eq_ascii_fold(name, "client-cert-chain") { return true; }
    if eq_ascii_fold(name, "via") { return true; }
    return false;
}

// Determines if an incoming header should be forwarded to upstream.
fn should_forward_header(
    name:       const u8[:],
    val:        const u8[:],
    in_headers: const HeaderMap&,
    config:     const ProxyConfig&,
) -> bool {
    if eq_ascii_fold(name, "host") {
        return config.preserve_host;
    }
    if is_forwarded_metadata_header(name) {
        return false;
    }
    // RFC 9112 Section 6.3: Transfer-Encoding overrides Content-Length.
    // An intermediary MUST remove Content-Length before forwarding if Transfer-Encoding is present.
    if eq_ascii_fold(name, "content-length") && has_header(in_headers, "transfer-encoding") {
        return false;
    }
    guard config.strip_hop_by_hop else { return true; }

    if is_hop_by_hop_header_name(name) {
        // RFC 9110: TE may only be forwarded if the value is trailers
        return eq_ascii_fold(name, "te") && eq_ascii_fold(core::trim_lws(val), "trailers");
    }

    if is_token_in_connection_header_map(in_headers, name) {
        return false;
    }

    return true;
}

// Checks a single Content-Length entry against previously recorded value (RFC 9112 §6.3).
inline fn check_cl_match(val: const u8[:], first_found: bool&, target_val: i64&) -> bool {
    var parsed_cl: i64 = 0;
    guard validate_content_length_value(val, parsed_cl) else { return false; }
    if !first_found {
        target_val = parsed_cl;
        first_found = true;
        return true;
    }
    return parsed_cl == target_val;
}

// RFC 9112 Section 6.3 & Section 6.1: Validates framing header integrity before forwarding.
// Duplicate differing Content-Length headers, duplicate Transfer-Encoding headers, or
// conflicting Content-Length + Transfer-Encoding headers are rejected (Smuggling Protection).
fn has_consistent_framing_headers(in_headers: const HeaderMap&) -> bool {
    // RFC 9110 Section 7.6.1: Connection — A sender MUST NOT send a connection option corresponding
    // to an end-to-end framing or routing field such as Content-Length or Host.
    guard !is_token_in_connection_header_map(in_headers, "content-length") else { return false; }
    guard !is_token_in_connection_header_map(in_headers, "host") else { return false; }

    var first_cl_found = false;
    var first_cl_val: i64 = 0;
    var has_te = false;

    for i in in_headers.entries.len {
        let entry = in_headers.entries[i];
        let name = in_headers.raw_buf[entry.name_begin..entry.name_end];

        if eq_ascii_fold(name, "content-length") {
            let val = in_headers.raw_buf[entry.values_begin..entry.values_end];
            guard check_cl_match(val, first_cl_found, first_cl_val) else { return false; }
        }
        if eq_ascii_fold(name, "transfer-encoding") {
            guard !has_te else { return false; }
            has_te = true;
        }
    }
    // RFC 9112 Section 6.1: Reject TE/CL smuggling conflict before forwarding
    guard !(first_cl_found && has_te) else { return false; }
    return true;
}

// Copies filtered client headers into proxy request header map.
// Enforces RFC 9112 §6.3: deduplicates identical Content-Length headers into a single occurrence.
fn copy_filtered_headers(
    in_headers:  const HeaderMap&,
    out_headers: HeaderMap&,
    config:      const ProxyConfig&,
) -> bool {
    for i in in_headers.entries.len {
        let entry = in_headers.entries[i];
        let name = in_headers.raw_buf[entry.name_begin..entry.name_end];
        let val = in_headers.raw_buf[entry.values_begin..entry.values_end];

        if eq_ascii_fold(name, "content-length") && has_header(out_headers, "content-length") {
            continue;
        }

        if should_forward_header(name, val, in_headers, config) {
            guard append_header(out_headers, name, val) else { return false; }
        }
    }
    return true;
}

// Helper to format Via header value without dynamic heap allocation.
fn format_via(buf: u8[..64]&, pseudonym: const u8[:], http_version: const u8[:]) -> bool {
    let ver_str = if http_version.len >= 6 && starts_with(http_version, "HTTP/") {
        http_version[5..]
    } else if http_version.len > 0 {
        http_version
    } else {
        "1.1"
    };
    let needed = core::add_sat_u64(core::add_sat_u64(ver_str.len as u64, 1), pseudonym.len as u64);
    guard needed <= (buf.cap as u64) else { return false; }
    buf.clear();
    buf.append(ver_str);
    buf.append(" ");
    buf.append(pseudonym);
    return true;
}

// Injects Via header (RFC 9110 §7.6.3).
fn inject_via_header(
    out_headers:  HeaderMap&,
    in_headers:   const HeaderMap&,
    pseudonym:    const u8[:],
    http_version: const u8[:],
) -> bool {
    var combined: u8[..1024] = [];
    let has_existing = has_header(in_headers, "Via");
    if has_existing {
        guard get_combined(in_headers, "Via", combined, 950) else { return false; }
    }
    guard pseudonym.len > 0 else {
        guard combined.len > 0 else { return true; }
        return append_header(out_headers, "Via", combined[..]);
    }
    var via_buf: u8[..64] = [];
    guard format_via(via_buf, pseudonym, http_version) else { return false; }
    guard combined.len > 0 else {
        return append_header(out_headers, "Via", via_buf[..]);
    }
    combined.append(", ");
    combined.append(via_buf[..]);
    return append_header(out_headers, "Via", combined[..]);
}

// Injects forwarded client IP into X-Forwarded-For, respecting trust boundary.
fn append_forwarded_metadata_xff(
    out_headers:        HeaderMap&,
    in_headers:         const HeaderMap&,
    client_ip:          const u8[:],
    trust_incoming_xff: bool,
) -> bool {
    guard trust_incoming_xff && has_header(in_headers, "X-Forwarded-For") else {
        return append_forwarded_for(out_headers, "", client_ip);
    }
    var combined_buf: u8[..1024] = [];
    guard get_combined(in_headers, "X-Forwarded-For", combined_buf, 1024) else { return false; }
    return append_forwarded_for(out_headers, combined_buf[..], client_ip);
}

// Injects standard proxy forwarding headers (RFC 7239 / de facto).
fn inject_forwarded_metadata(
    out_headers: HeaderMap&,
    in_headers:  const HeaderMap&,
    client_ip:   const u8[:],
    proto:       const u8[:],
    config:      const ProxyConfig&,
) -> bool {
    guard append_forwarded_metadata_xff(
        out_headers,
        in_headers,
        client_ip,
        config.trust_incoming_xff,
    ) else { return false; }

    let orig_host = get_header(in_headers, "Host");
    if proto.len > 0 {
        guard append_header(out_headers, "X-Forwarded-Proto", proto) else { return false; }
    }
    let existing_xf_host = get_header(in_headers, "X-Forwarded-Host");
    if config.trust_incoming_xff && existing_xf_host.len > 0 {
        guard append_header(out_headers, "X-Forwarded-Host", existing_xf_host) else { return false; }
    } else if orig_host.len > 0 && !config.preserve_host {
        guard append_header(out_headers, "X-Forwarded-Host", orig_host) else { return false; }
    }
    return true;
}

// Filters incoming request headers and populates outgoing proxy request headers.
fn filter_and_forward_headers(
    in_headers:    const HeaderMap&,
    out_headers:   HeaderMap&,
    client_ip:     const u8[:],
    proto:         const u8[:],
    upstream_host: const u8[:],
    config:        const ProxyConfig&,
) -> bool {
    guard has_consistent_framing_headers(in_headers) else { return false; }
    reset_for_keep_alive(out_headers);

    guard copy_filtered_headers(in_headers, out_headers, config) else { return false; }

    // RFC 9440 §2.4: place the validated end-entity certificate in Client-Cert only when configured.
    let cert_der_len = config.client_cert_der_len;
    let actual_der_len = config.client_cert_der.len as i32;
    let eff_der_len = if cert_der_len > 0 && cert_der_len <= actual_der_len {
        cert_der_len
    } else {
        actual_der_len
    };
    if config.forward_client_cert && eff_der_len > 0 && eff_der_len <= CLIENT_CERT_MAX_DER_LEN {
        var enc: u8[..8192] = [];
        let n = encode_client_cert(config.client_cert_der[..eff_der_len], enc);
        if n > 0 {
            guard append_header(out_headers, "Client-Cert", enc[..n]) else { return false; }
        }
    }

    if !config.preserve_host && upstream_host.len > 0 {
        guard append_header(out_headers, "Host", upstream_host) else { return false; }
    }

    if config.append_forwarded {
        guard inject_forwarded_metadata(
            out_headers,
            in_headers,
            client_ip,
            proto,
            config,
        ) else { return false; }
    }

    guard inject_via_header(
        out_headers,
        in_headers,
        config.via_pseudonym[..],
        config.http_version[..],
    ) else { return false; }
    return true;
}

// Formats upstream wire HTTP/1.1 request buffer ready for transmission.
fn serialize_upstream_request<B>(
    method:       const u8[:],
    uri:          const u8[:],
    headers:      const HeaderMap&,
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
    cluster:            UpstreamCluster    = UpstreamCluster { .. },
    config:             ProxyConfig        = ProxyConfig { .. },
    rate_limiter:       GatewayRateLimiter = GatewayRateLimiter { .. },
    total_forwarded:    u64                = 0,
    total_dropped:      u64                = 0,
    total_rate_limited: u64                = 0,
    total_overloaded:   u64                = 0,
}

fn new_reverse_proxy(policy: LbPolicy = LbPolicy.RoundRobin) -> ReverseProxy {
    return ReverseProxy {
        cluster:      new_upstream_cluster(policy),
        config:       ProxyConfig { .. },
        rate_limiter: new_gateway_rate_limiter(100, 20),
        ..
    };
}

fn record_proxy_dropped(proxy: ReverseProxy&) {
    proxy.total_dropped = core::add_sat_u64(proxy.total_dropped, 1);
}

fn record_proxy_forwarded(proxy: ReverseProxy&) {
    proxy.total_forwarded = core::add_sat_u64(proxy.total_forwarded, 1);
}

fn record_proxy_rate_limited(proxy: ReverseProxy&) {
    proxy.total_rate_limited = core::add_sat_u64(proxy.total_rate_limited, 1);
}

fn record_proxy_overloaded(proxy: ReverseProxy&) {
    proxy.total_overloaded = core::add_sat_u64(proxy.total_overloaded, 1);
}

// Checks if an upstream target has exceeded its maximum concurrent active connections.
inline fn is_target_concurrency_saturated(target: const UpstreamTarget&, max_conns: i32) -> bool {
    guard max_conns > 0 else { return false; }
    return target.active_conns > max_conns;
}

// Completes a dispatched proxy request cleanly, preventing active connection leaks.
fn finish_proxy_request(proxy: ReverseProxy&, target_idx: i32, success: bool) {
    guard target_idx >= 0 && target_idx < proxy.cluster.targets.len else { return; }
    release_upstream_connection(proxy.cluster, target_idx);
    if success {
        record_upstream_success(proxy.cluster, target_idx);
    } else {
        record_upstream_failure(proxy.cluster, target_idx);
    }
}

// Finalizes an upstream exchange by evaluating the HTTP status code (5xx server errors
// count as upstream failures for circuit breaking) and releasing active connection state.
fn complete_upstream_exchange(proxy: ReverseProxy&, target_idx: i32, status_code: i32, transport_ok: bool) {
    let ok = transport_ok && status_code >= 100 && status_code < 500;
    finish_proxy_request(proxy, target_idx, ok);
}

// Aborts an in-flight proxy request due to downstream stall, timeout, or network disconnect.
fn abort_proxy_request(proxy: ReverseProxy&, target_idx: i32) {
    guard target_idx >= 0 && target_idx < proxy.cluster.targets.len else { return; }
    release_upstream_connection(proxy.cluster, target_idx);
    record_upstream_failure(proxy.cluster, target_idx);
}

// Configures gateway rate limit parameters, keeping ProxyConfig and GatewayRateLimiter in sync.
fn set_proxy_rate_limit(proxy: ReverseProxy&, rps: u64, burst: u64) {
    proxy.config.enable_rate_limiting = true;
    proxy.config.rate_limit_rps = rps;
    proxy.config.rate_limit_burst = burst;
    proxy.rate_limiter.config = new_gcra_config(rps, burst);
}

// Formats upstream Host authority per RFC 9110 §7.2 and RFC 3986 §3.2.2,
// bracketing bare IPv6 literals and avoiding duplicate :port suffixes.
fn format_upstream_authority(host: const u8[:], port: u16, preserve_host: bool, out: u8[..128]&) -> bool {
    guard host.len > 0 && host.len <= 112 else { return false; }
    out.clear();
    let _, after_colon, has_colon = core::split_once_byte(host, ':');
    let is_bracketed = starts_with(host, "[");
    let is_bare_ipv6 = !is_bracketed && has_colon && find(after_colon, ":") >= 0;
    if is_bare_ipv6 {
        out.push('[');
        out.append(host);
        out.push(']');
    } else {
        out.append(host);
    }
    let has_port = if is_bare_ipv6 {
        false
    } else if is_bracketed {
        find(host, "]:") >= 0
    } else {
        has_colon
    };
    if !preserve_host && !has_port && port != 80 && port != 443 && port > 0 {
        out.append(":");
        core::format_u64_dec(port, out);
    }
    return true;
}

// Validates that forwarded Content-Length matches body.len or injects Content-Length when needed (RFC 9112 §6.2).
// Emits `Content-Length: 0` on empty `POST`, `PUT`, or `PATCH` requests lacking Transfer-Encoding.
fn ensure_forwarded_body_framing(
    forward_headers: HeaderMap&,
    body:            const u8[:],
    method:          const u8[:] = "",
) -> bool {
    let has_cl = has_header(forward_headers, "content-length");
    if has_cl {
        var parsed_cl: i64 = 0;
        guard validate_content_length_value(get_header(forward_headers, "content-length"), parsed_cl) else {
            return false;
        }
        return parsed_cl == body.len;
    }
    let has_te = has_header(forward_headers, "transfer-encoding");
    if body.len == 0 && !has_cl && !has_te {
        if method == "POST" || method == "PUT" || method == "PATCH" {
            return append_header(forward_headers, "Content-Length", "0");
        }
        return true;
    }
    guard body.len > 0 && !has_te else { return true; }
    var cl_buf: u8[..32] = [];
    core::format_u64_dec(body.len as u64, cl_buf);
    return append_header(forward_headers, "Content-Length", cl_buf[..]);
}

// Selects upstream target, applies GCRA rate limiting and concurrency backpressure defenses,
// rewrites headers, and serializes forward wire request.
fn prepare_proxy_request_at<B>(
    proxy:      ReverseProxy&,
    method:     const u8[:],
    uri:        const u8[:],
    in_headers: const HeaderMap&,
    client_ip:  const u8[:],
    proto:      const u8[:],
    body:       const u8[:],
    out_wire:   B&,
    now_ns:     u64,
) -> i32, bool {
    let effective_now = if now_ns > 0 { now_ns } else { core::as_nanos(core::monotonic_now()) };

    // 1. Rate limiter defense against client flooding and downstream backpressure
    if proxy.config.enable_rate_limiting && client_ip.len > 0 && effective_now > 0 {
        let dec = check_gateway_rate_limit(proxy.rate_limiter, client_ip, 1, effective_now);
        if !dec.allowed {
            record_proxy_rate_limited(proxy);
            record_proxy_dropped(proxy);
            return PROXY_TARGET_NONE, false;
        }
    }

    // 2. Upstream target selection
    let target_idx, ok = select_upstream(proxy.cluster);
    guard ok && target_idx >= 0 && target_idx < proxy.cluster.targets.len else {
        record_proxy_dropped(proxy);
        return PROXY_TARGET_NONE, false;
    }

    // 3. Concurrency ceiling defense against connection exhaustion
    let max_conns = proxy.config.max_active_conns_per_target;
    if is_target_concurrency_saturated(proxy.cluster.targets[target_idx], max_conns) {
        release_upstream_connection(proxy.cluster, target_idx);
        record_proxy_overloaded(proxy);
        record_proxy_dropped(proxy);
        return PROXY_TARGET_NONE, false;
    }

    // 4. Header filtering and metadata injection
    var forward_headers = HeaderMap { .. };
    var host_buf: u8[..128] = [];
    let target = proxy.cluster.targets[target_idx];
    let ok_prep = format_upstream_authority(target.host[..], target.port, proxy.config.preserve_host, host_buf)
        && filter_and_forward_headers(in_headers, forward_headers, client_ip, proto, host_buf[..], proxy.config)
        && ensure_forwarded_body_framing(forward_headers, body, method)
        && serialize_upstream_request(method, uri, forward_headers, body, out_wire, proxy.config.http_version[..]);
    guard ok_prep else {
        release_upstream_connection(proxy.cluster, target_idx);
        record_proxy_dropped(proxy);
        return PROXY_TARGET_NONE, false;
    }

    record_proxy_forwarded(proxy);
    return target_idx, true;
}

// Compatibility wrapper for prepare_proxy_request without explicit timestamp.
fn prepare_proxy_request<B>(
    proxy:      ReverseProxy&,
    method:     const u8[:],
    uri:        const u8[:],
    in_headers: const HeaderMap&,
    client_ip:  const u8[:],
    proto:      const u8[:],
    body:       const u8[:],
    out_wire:   B&,
) -> i32, bool {
    let now_ns = core::as_nanos(core::monotonic_now());
    return prepare_proxy_request_at(
        proxy,
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

const PROXY_STREAM_CHUNK_MAX: i64 = 16384;

enum ProxyTransportKind {
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
fn can_use_kernel_splice(kind: ProxyTransportKind, is_encrypted: bool) -> bool {
    guard !is_encrypted else { return false; }
    return kind == ProxyTransportKind.PlainTcp || kind == ProxyTransportKind.Http1Connect;
}

// Userspace zero-copy ring-buffer view for streaming chunk transfers (Invariant 10 & 13).
struct ProxyStreamRing {
    buf:        u8[..16384] = [],
    read_pos:   i64         = 0,
    total_read: u64         = 0,
    total_sent: u64         = 0,
}

// Vends unread slice directly from the streaming ring buffer (Invariant 10).
fn incoming_slice(ring: const ProxyStreamRing&) -> const u8[:] {
    guard ring.read_pos >= 0 && ring.read_pos <= ring.buf.len else { return ""; }
    return ring.buf[ring.read_pos..ring.buf.len];
}

// Advances read cursor after downstream/upstream consumption, resetting when fully drained.
fn advance_read(ring: ProxyStreamRing&, consumed: i64) -> bool {
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
fn compact_stream_ring(ring: ProxyStreamRing&) {
    guard ring.read_pos > 0 else { return; }
    if ring.read_pos >= ring.buf.len {
        ring.buf.clear();
        ring.read_pos = 0;
        return;
    }
    let active_len = core::sub_sat_u64(ring.buf.len as u64, ring.read_pos as u64) as i64;
    for i in active_len {
        let src_idx = core::add_sat_u64(ring.read_pos as u64, i as u64) as i64;
        ring.buf[i] = ring.buf[src_idx];
    }
    while ring.buf.len > active_len {
        ring.buf.pop();
    }
    ring.read_pos = 0;
}

// Appends incoming payload chunk into the bounded 16 KB ring buffer.
// Enforces Invariant 13: fails closed with explicit `false` on capacity overflow.
fn feed_stream_chunk(ring: ProxyStreamRing&, chunk: const u8[:]) -> bool {
    let needed = core::add_sat_u64(ring.buf.len as u64, chunk.len as u64);
    if needed > (ring.buf.cap as u64) {
        compact_stream_ring(ring);
    }
    let post_needed = core::add_sat_u64(ring.buf.len as u64, chunk.len as u64);
    guard post_needed <= (ring.buf.cap as u64) else { return false; }
    ring.buf.append(chunk);
    ring.total_read = core::add_sat_u64(ring.total_read, chunk.len as u64);
    return true;
}

// Transfers a bounded chunk from `src` ring to `dst` ring, applying RFC 6455 Section 5.3
// Client-to-Server Masking when forwarding WebSocket frames in userspace.
fn forward_userspace_stream_chunk(
    src:     ProxyStreamRing&,
    dst:     ProxyStreamRing&,
    kind:    ProxyTransportKind,
    ws_mask: u8[4],
) -> i64, bool {
    let view = incoming_slice(src);
    guard view.len > 0 else { return 0, true; }
    let needed = core::add_sat_u64(dst.buf.len as u64, view.len as u64);
    if needed > (dst.buf.cap as u64) {
        compact_stream_ring(dst);
    }
    let post_needed = core::add_sat_u64(dst.buf.len as u64, view.len as u64);
    guard post_needed <= (dst.buf.cap as u64) else { return 0, false; }

    if kind == ProxyTransportKind.WebSocket {
        // RFC 6455 Section 5.3: Client-to-Server Masking - Octet i of transformed data is XORed with masking-key octet i MOD 4.
        var masked: u8[..16384] = [];
        let base_offset = src.total_sent;
        for i in view.len {
            let mask_idx = (core::add_sat_u64(base_offset, i as u64) & 3) as i64;
            masked.push(view[i] ^ ws_mask[mask_idx]);
        }
        dst.buf.append(masked[..]);
    } else {
        dst.buf.append(view);
    }

    let n = view.len;
    dst.total_read = core::add_sat_u64(dst.total_read, n as u64);
    advance_read(src, n);
    return n, true;
}

// ---- Live Pooled Upstream Execution ----------------------------------------

fn acquire_or_dial_upstream_conn(
    pool:       StreamPool&,
    target:     const UpstreamTarget&,
    timeout_ms: u32,
    now_ns:     i64,
) -> i32, bool {
    let pool_key = new_pool_key(
        PoolScheme.Http,
        target.host[..],
        target.port,
        new_direct_proxy_chain(),
        NetworkAnonymizationKey { .. },
        TlsAndDnsPolicy { .. },
    );
    let existing_cid, has_pooled = acquire_pooled_connection(pool, pool_key, "", now_ns);
    if has_pooled && existing_cid > 0 {
        return existing_cid, true;
    }
    let sock = tcp_connect(target.host[..], target.port, timeout_ms);
    guard sock > 0 else { return -1, false; }
    var t = Transport.Tcp { fd: sock };
    let new_cid = register_connection(pool, pool_key, NegotiatedProtocol.Http11, t, "", 1, now_ns);
    guard new_cid > 0 else {
        t.close();
        return -1, false;
    }
    return new_cid, true;
}

fn read_and_parse_upstream_headers(
    conn:       PooledConnection&,
    out_resp:   Response&,
    timeout_ms: u32,
) -> i64, bool {
    let hdr_end_idx, ok_hdr = read_response_headers(conn, timeout_ms);
    let rx = conn.rx_buf[..];
    guard ok_hdr && hdr_end_idx >= 0 && hdr_end_idx + 4 <= rx.len else { return -1, false; }
    guard parse_response_headers(rx[..hdr_end_idx], out_resp) else { return -1, false; }
    return hdr_end_idx + 4, true;
}

fn exchange_prepared_wire_on_conn(
    conn:       PooledConnection&,
    method:     const u8[:],
    wire_req:   const u8[:],
    out_resp:   Response&,
    timeout_ms: u32,
) -> bool, bool {
    var early_hints = EarlyHintsResponse { .. };
    var has_eh = false;
    return exchange_prepared_wire_on_conn_with_hints(
        conn, method, wire_req, out_resp, early_hints, has_eh, timeout_ms,
    );
}

fn exchange_prepared_wire_on_conn_with_hints(
    conn:            PooledConnection&,
    method:          const u8[:],
    wire_req:        const u8[:],
    out_resp:        Response&,
    out_early_hints: EarlyHintsResponse&,
    has_early_hints: bool&,
    timeout_ms:      u32,
) -> bool, bool {
    reset_response(out_resp);
    out_early_hints = EarlyHintsResponse { .. };
    has_early_hints = false;
    guard send_all(conn.transport, wire_req) else { return false, false; }

    var dummy_req = new_request(method, "/");
    // RFC 9110 Section 15.2: Informational 1xx — Cap consecutive 1xx interim responses to 5.
    for interim_step in 6 {
        guard interim_step < 5 else { return false, false; }
        let leftover_start, ok_hdr = read_and_parse_upstream_headers(conn, out_resp, timeout_ms);
        let rx = conn.rx_buf[..];
        guard ok_hdr && leftover_start >= 0 && leftover_start <= rx.len else { return false, false; }
        let is_interim = out_resp.status_code >= 100 && out_resp.status_code < 200 && out_resp.status_code != 101;
        if is_interim {
            if out_resp.status_code == 103 {
                var up_tmp = UpstreamResponse { early_hints: out_early_hints, has_early_hints: has_early_hints, .. };
                capture_upstream_early_hints(out_resp, up_tmp);
                out_early_hints = up_tmp.early_hints;
                has_early_hints = up_tmp.has_early_hints;
            }
            drain_rx_buf(conn.rx_buf, leftover_start);
            continue;
        }
        var leftover: u8[..8192] = [];
        guard leftover.try_set(rx[leftover_start..]) else { return false, false; }
        conn.rx_buf.clear();
        return pump_response_body(conn, dummy_req, out_resp, leftover[..], timeout_ms);
    }
    return false, false;
}

// ---- Upstream `X-Accel-*` Control Headers, `Location` Rewriting & `103` Capture ----

struct UpstreamAccelControl {
    disable_buffering: bool      = false,
    has_accel_expires: bool      = false,
    accel_expires_sec: i64       = 0,
    limit_rate_bps:    u64       = 0,
    accel_redirect:    u8[..256] = [],
}

struct UpstreamResponse {
    early_hints:     EarlyHintsResponse   = EarlyHintsResponse { .. },
    has_early_hints: bool                 = false,
    accel:           UpstreamAccelControl = UpstreamAccelControl { .. },
    resp:            Response             = Response { .. },
}

// Parses `X-Accel-*` control header values into `accel` (Nginx `ngx_http_upstream_headers_in` parity).
//
// Example:
//   name = "X-Accel-Buffering", val = "no"
//   returns: true (is X-Accel header), accel.disable_buffering = true
fn parse_x_accel_control_header(name: const u8[:], val: const u8[:], accel: UpstreamAccelControl&) -> bool {
    let trimmed = core::trim_lws(val);
    if eq_ascii_fold(name, "x-accel-buffering") {
        if eq_ascii_fold(trimmed, "no") {
            accel.disable_buffering = true;
        } else if eq_ascii_fold(trimmed, "yes") {
            accel.disable_buffering = false;
        }
        return true;
    }
    if eq_ascii_fold(name, "x-accel-expires") {
        if eq_ascii_fold(trimmed, "off") {
            accel.has_accel_expires = true;
            accel.accel_expires_sec = 0;
        } else {
            let s_slice = if trimmed.len > 1 && trimmed[0] == '@' { trimmed[1..] } else { trimmed };
            let secs, ok = core::parse_u64_dec(s_slice);
            if ok {
                accel.has_accel_expires = true;
                accel.accel_expires_sec = secs as i64;
            }
        }
        return true;
    }
    if eq_ascii_fold(name, "x-accel-limit-rate") {
        let rate, ok = core::parse_u64_dec(trimmed);
        if ok {
            accel.limit_rate_bps = rate;
        }
        return true;
    }
    if eq_ascii_fold(name, "x-accel-redirect") {
        let _ = accel.accel_redirect.try_set(trimmed);
        return true;
    }
    return starts_with_fold(name, "x-accel-");
}

// Rewrites an upstream `Location` header if it starts with `backend_url_prefix`.
fn rewrite_upstream_location_header(
    loc_val:            const u8[:],
    backend_url_prefix: const u8[:],
    public_url_prefix:  const u8[:],
    out_location_buf:   u8[..512]&,
) -> const u8[:] {
    guard backend_url_prefix.len > 0 && starts_with(loc_val, backend_url_prefix) else {
        return loc_val;
    }
    let suffix = loc_val[backend_url_prefix.len..];
    let needed = core::add_sat_u64(public_url_prefix.len as u64, suffix.len as u64);
    guard needed <= (out_location_buf.cap as u64) else { return loc_val; }
    out_location_buf.clear();
    out_location_buf.append(public_url_prefix);
    out_location_buf.append(suffix);
    return out_location_buf[..];
}

// Parses `X-Accel-*` control headers, strips hop-by-hop and `X-Accel-*` headers,
// and rewrites `Location` prefixes matching `backend_url_prefix` to `public_url_prefix`.
fn process_and_filter_upstream_response_headers(
    in_headers:         const HeaderMap&,
    backend_url_prefix: const u8[:],
    public_url_prefix:  const u8[:],
    out_headers:        HeaderMap&,
    out_location_buf:   u8[..512]&,
    accel:              UpstreamAccelControl&,
) -> bool {
    out_headers.clear();
    accel = UpstreamAccelControl { .. };
    for &entry in in_headers.entries {
        let name = entry_name(in_headers, entry);
        let val = entry_value(in_headers, entry);
        if parse_x_accel_control_header(name, val, accel) {
            continue;
        }
        if is_hop_by_hop_header_name(name) || is_token_in_connection_header_map(in_headers, name) {
            continue;
        }
        if eq_ascii_fold(name, "location") {
            let rewritten = rewrite_upstream_location_header(
                val, backend_url_prefix, public_url_prefix, out_location_buf,
            );
            guard append_header(out_headers, name, rewritten) else { return false; }
            continue;
        }
        guard append_header(out_headers, name, val) else { return false; }
    }
    return true;
}

// Captures `Link` headers from an upstream `103 Early Hints` interim response into `out_upstream`.
fn capture_upstream_early_hints(in_resp: const Response&, out_upstream: UpstreamResponse&) {
    guard in_resp.status_code == 103 else { return; }
    for &entry in in_resp.headers.entries {
        let name = entry_name(in_resp.headers, entry);
        if eq_ascii_fold(name, "link") {
            let val = entry_value(in_resp.headers, entry);
            if parse_link_header(val, out_upstream.early_hints.links) {
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
    proxy:      ReverseProxy&,
    pool:       StreamPool&,
    method:     const u8[:],
    uri:        const u8[:],
    in_headers: const HeaderMap&,
    client_ip:  const u8[:],
    proto:      const u8[:],
    body:       const u8[:],
    out_resp:   Response&,
    timeout_ms: u32 = 5000,
    now_ns:     u64 = 0,
) -> bool {
    let effective_now = if now_ns > 0 { now_ns } else { core::as_nanos(core::monotonic_now()) };
    var wire_req: u8[..16384] = [];
    let target_idx, ok_prep = prepare_proxy_request_at(
        proxy, method, uri, in_headers, client_ip, proto, body, wire_req, effective_now,
    );
    guard ok_prep && target_idx >= 0 else { return false; }

    let target = proxy.cluster.targets[target_idx];
    let now_i64 = effective_now as i64;
    let conn_id, ok_conn = acquire_or_dial_upstream_conn(pool, target, timeout_ms, now_i64);
    guard ok_conn && conn_id > 0 else {
        complete_upstream_exchange(proxy, target_idx, 0, false);
        return false;
    }

    let c_idx = pool.find_connection_index(conn_id);
    guard c_idx >= 0 else {
        pool.close_pooled_connection(conn_id);
        complete_upstream_exchange(proxy, target_idx, 0, false);
        return false;
    }

    pool.conns[c_idx].rx_buf.clear();
    let ok_ex, keep_alive = exchange_prepared_wire_on_conn(
        pool.conns[c_idx], method, wire_req[..], out_resp, timeout_ms,
    );
    if ok_ex && keep_alive && pool.conns[c_idx].rx_buf.len == 0 {
        pool.release_connection(conn_id, now_i64);
    } else {
        pool.close_pooled_connection(conn_id);
    }
    complete_upstream_exchange(proxy, target_idx, out_resp.status_code, ok_ex);
    return ok_ex;
}
