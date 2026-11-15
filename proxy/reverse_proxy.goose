// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 7 Reverse Proxy Engine, Hop-by-Hop Header Stripping,
// Forwarded/Via Chaining, Upstream Request Dispatcher,
// Connection Leak Defense, and Backpressure Shield.
namespace wing;

import std;
import core from "..";
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
import proxy.load_balancer;
import proxy.health_check;
import rfc.http;
import wire.h1;
import wire.pipeline;
import wire.service;

const PROXY_TARGET_NONE: i32 = -1;

struct ProxyConfig {
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

// Helper to format chained X-Forwarded-For value without dynamic heap allocation.
fn format_chained_xff(buf: u8[..1024]&, existing_xff: const u8[:], client_ip: const u8[:]) -> bool {
    var committed = false;
    defer if !committed { buf.clear(); };
    guard buf.try_set(existing_xff) else { return false; }
    guard buf.try_append(", ") else { return false; }
    guard buf.try_append(client_ip) else { return false; }
    committed = true;
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

inline fn is_standard_h2_request_pseudo(name: const u8[:]) -> bool {
    return name == ":method" ||
        name == ":scheme" ||
        name == ":authority" ||
        name == ":path" ||
        name == ":protocol";
}

// Determines if an incoming header should be forwarded to upstream.
fn should_forward_header(
    name:       const u8[:],
    val:        const u8[:],
    in_headers: const HeaderMap&,
    config:     const ProxyConfig&,
) -> bool {
    if name.eq_ascii_fold("host") {
        return config.preserve_host;
    }
    if is_forwarded_metadata_header(name) {
        return false;
    }
    if name.eq_ascii_fold("max-forwards") {
        return true;
    }
    // RFC 9112 Section 6.3: Message Body Length - remove Content-Length if Transfer-Encoding is present.
    if name.eq_ascii_fold("content-length") && has_header(in_headers, "transfer-encoding") {
        return false;
    }
    guard config.strip_hop_by_hop else { return true; }

    if is_hop_by_hop_header_name(name) {
        // RFC 9110 Section 7.6.1: Connection - TE may only be forwarded if the value is trailers.
        return name.eq_ascii_fold("te") && val.trim_lws().eq_ascii_fold("trailers");
    }

    if is_token_in_connection_header_map(in_headers, name) {
        return false;
    }

    return true;
}

// Checks a single Content-Length entry against previously recorded value.
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

inline fn append_canonical_content_length(out_headers: HeaderMap&, name: const u8[:], val: const u8[:]) -> bool {
    var parsed_cl: i64 = 0;
    guard validate_content_length_value(val, parsed_cl) else { return false; }
    var cl_buf: u8[..24] = [];
    parsed_cl.format_i64_dec(cl_buf);
    return append_header(out_headers, name, cl_buf[..]);
}

// Validates framing header integrity before forwarding.
// Duplicate differing Content-Length headers, duplicate or invalid Transfer-Encoding headers, or
// conflicting Content-Length + Transfer-Encoding headers are rejected.
fn has_consistent_framing_headers(in_headers: const HeaderMap&) -> bool {
    // RFC 9110 Section 7.6.1: Connection - MUST NOT send connection option for end-to-end framing or routing fields.
    guard !is_token_in_connection_header_map(in_headers, "content-length") else { return false; }
    guard !is_token_in_connection_header_map(in_headers, "transfer-encoding") else { return false; }
    guard !is_token_in_connection_header_map(in_headers, "host") else { return false; }
    guard !is_token_in_connection_header_map(in_headers, "max-forwards") else { return false; }

    var first_cl_found = false;
    var first_cl_val: i64 = 0;
    var has_te = false;

    for i in in_headers.entries.len {
        let entry = in_headers.entries[i];
        let name = in_headers.raw_buf[entry.name_begin..entry.name_end];
        let val = in_headers.raw_buf[entry.values_begin..entry.values_end];

        if name.eq_ascii_fold("content-length") {
            guard check_cl_match(val, first_cl_found, first_cl_val) else { return false; }
        }
        if name.eq_ascii_fold("transfer-encoding") {
            guard !has_te && validate_transfer_encoding_value(val) else { return false; }
            has_te = true;
        }
    }
    // RFC 9112 Section 6.3: Message Body Length - reject messages with both Transfer-Encoding and Content-Length.
    guard !(first_cl_found && has_te) else { return false; }
    return true;
}

// Copies filtered client headers into proxy request header map.
// Deduplicates and canonicalizes Content-Length headers into a single decimal occurrence.
fn copy_filtered_headers(
    in_headers:  const HeaderMap&,
    out_headers: HeaderMap&,
    config:      const ProxyConfig&,
) -> bool {
    for i in in_headers.entries.len {
        let entry = in_headers.entries[i];
        let name = in_headers.raw_buf[entry.name_begin..entry.name_end];
        let val = in_headers.raw_buf[entry.values_begin..entry.values_end];

        if is_standard_h2_request_pseudo(name) {
            continue;
        }
        // RFC 9113 Section 8.3: HTTP Control Data - reject non-standard or unstripped pseudo-headers.
        guard is_valid_header_name(name) && is_valid_header_value(val) else { return false; }

        if name.eq_ascii_fold("content-length") {
            if !has_header(out_headers, "content-length") && should_forward_header(name, val, in_headers, config) {
                guard append_canonical_content_length(out_headers, name, val) else { return false; }
            }
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
    var committed = false;
    defer if !committed { buf.clear(); };
    guard buf.try_set(ver_str) else { return false; }
    guard buf.try_append(" ") else { return false; }
    guard buf.try_append(pseudonym) else { return false; }
    committed = true;
    return true;
}

// Extracts the `received-by` pseudonym or host[:port] token from a single RFC 9110 Via hop.
//
// Example:
//   hop = "1.1 wing-gw (Goose)"
//   returns: "wing-gw"
inline fn extract_via_received_by(hop: const u8[:]) -> const u8[:] {
    let trimmed = hop.trim_lws();
    var idx: i64 = 0;
    while idx < trimmed.len && !core::is_lws(trimmed[idx]) {
        idx = core::add_sat_i64(idx, 1);
    }
    let after_proto = trimmed[idx..].trim_lws_start();
    var end_idx: i64 = 0;
    while end_idx < after_proto.len && !core::is_lws(after_proto[end_idx]) {
        end_idx = core::add_sat_i64(end_idx, 1);
    }
    return after_proto[..end_idx];
}

fn has_via_pseudonym_loop(combined_via: const u8[:], pseudonym: const u8[:]) -> bool {
    guard combined_via.len > 0 && pseudonym.len > 0 else { return false; }
    var tok = core::make_byte_tokenizer(combined_via, ',');
    while true {
        let hop, ok = core::token_next(tok);
        if !ok {
            break;
        }
        let received_by = extract_via_received_by(hop);
        if received_by.len > 0 && received_by.eq_ascii_fold(pseudonym) {
            return true;
        }
    }
    return false;
}

// Injects Via header and rejects self-forwarding loops.
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
        // RFC 9110 Section 7.6.3: Via - detect forwarding loops when own pseudonym is already present.
        guard !has_via_pseudonym_loop(combined[..], pseudonym) else { return false; }
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
    guard combined.try_append(", ") && combined.try_append(via_buf[..]) else { return false; }
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

inline fn populate_forwarded_for_node(elem: ForwardedElement&, client_ip: const u8[:]) -> bool {
    // RFC 7239 Section 6: Node Identifiers - IPv6 addresses MUST be enclosed in square brackets.
    if client_ip.contains_byte(':') && !starts_with(client_ip, "[") {
        return elem.for_node.try_set("[") &&
            elem.for_node.try_append(client_ip) &&
            elem.for_node.try_push(']');
    }
    return elem.for_node.try_set(client_ip);
}

// Injects standard proxy forwarding headers.
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
    if config.emit_rfc7239_forwarded {
        var elem = ForwardedElement { .. };
        guard elem.by.try_set(config.via_pseudonym[..]) else { return false; }
        guard populate_forwarded_for_node(elem, client_ip) else { return false; }
        guard elem.host.try_set(orig_host) else { return false; }
        guard elem.proto.try_set(proto) else { return false; }
        guard append_forwarded_header(out_headers, elem) else { return false; }
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
    var committed = false;
    defer if !committed { out_headers.clear(); };

    guard copy_filtered_headers(in_headers, out_headers, config) else { return false; }

    // RFC 9440 §2.4: place the validated end-entity certificate in Client-Cert only when configured.
    let cert_der_len = config.client_cert_der_len;
    let actual_der_len = config.client_cert_der.len as i32;
    let eff_der_len = if cert_der_len > 0 { min(cert_der_len, actual_der_len) } else { actual_der_len };
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
    committed = true;
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
    cluster:            UpstreamCluster      = UpstreamCluster { .. },
    warm_upstreams:     UpstreamPool         = UpstreamPool { .. },
    config:             ProxyConfig          = ProxyConfig { .. },
    rate_limiter:       GatewayRateLimiter   = GatewayRateLimiter { .. },
    health_checker:     ClusterHealthChecker = ClusterHealthChecker { .. },
    total_forwarded:    u64                  = 0,
    total_dropped:      u64                  = 0,
    total_rate_limited: u64                  = 0,
    total_overloaded:   u64                  = 0,
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
    if ok {
        let _ = on_probe_success(proxy.health_checker, proxy.cluster, target_idx, 1000);
    } else {
        let _ = on_probe_failure(proxy.health_checker, proxy.cluster, target_idx);
    }
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
    var committed = false;
    defer if !committed { out.clear(); };
    let _, after_colon, has_colon = host.split_once_byte(':');
    let is_bracketed = starts_with(host, "[");
    let is_bare_ipv6 = !is_bracketed && has_colon && after_colon.contains_byte(':');
    if is_bare_ipv6 {
        guard out.try_set("[") else { return false; }
        guard out.try_append(host) else { return false; }
        guard out.try_push(']') else { return false; }
    } else {
        guard out.try_set(host) else { return false; }
    }
    let has_port = if is_bracketed { find(host, "]:") >= 0 } else { has_colon && !is_bare_ipv6 };
    if !preserve_host && !has_port && port != 80 && port != 443 && port > 0 {
        guard out.try_append(":") else { return false; }
        port.format_u64_dec(out);
    }
    committed = true;
    return true;
}

// Validates that forwarded Content-Length matches body.len or injects Content-Length when needed.
// Emits `Content-Length: 0` on empty `POST`, `PUT`, or `PATCH` requests lacking Transfer-Encoding.
fn ensure_forwarded_body_framing(
    forward_headers: HeaderMap&,
    body:            const u8[:],
    method:          const u8[:] = "",
) -> bool {
    let has_cl = has_header(forward_headers, "content-length");
    let has_te = has_header(forward_headers, "transfer-encoding");
    guard !(has_cl && has_te) else { return false; }
    if has_cl {
        var parsed_cl: i64 = 0;
        guard validate_content_length_value(get_header(forward_headers, "content-length"), parsed_cl) else {
            return false;
        }
        return parsed_cl == body.len;
    }
    if body.len == 0 && !has_cl && !has_te {
        if method == "POST" || method == "PUT" || method == "PATCH" {
            return append_header(forward_headers, "Content-Length", "0");
        }
        return true;
    }
    guard body.len > 0 && !has_te else { return true; }
    var cl_buf: u8[..32] = [];
    body.len.format_i64_dec(cl_buf);
    return append_header(forward_headers, "Content-Length", cl_buf[..]);
}

// Enforces RFC 9110 Section 7.6.2 Max-Forwards hop decrement and zero-hop halt on TRACE and OPTIONS.
fn apply_max_forwards_policy(method: const u8[:], forward_headers: HeaderMap&) -> bool {
    guard method.eq_ascii_fold("TRACE") || method.eq_ascii_fold("OPTIONS") else {
        return true;
    }
    var found = false;
    var hops: u64 = 0;
    for &entry in forward_headers.entries {
        let name = entry_name(forward_headers, entry);
        if !name.eq_ascii_fold("max-forwards") {
            continue;
        }
        let val = entry_value(forward_headers, entry).trim_lws();
        let parsed, ok = val.parse_u64_dec();
        guard ok else { return false; }
        if !found {
            hops = parsed;
            found = true;
        } else {
            guard parsed == hops else { return false; }
        }
    }
    guard found else { return true; }
    // RFC 9110 Section 7.6.2: Max-Forwards - MUST NOT forward the request when Max-Forwards is zero.
    guard hops > 0 else { return false; }
    var mf_buf: u8[..24] = [];
    let next_hops = core::sub_sat_u64(hops, 1);
    next_hops.format_u64_dec(mf_buf);
    return set_or_replace(forward_headers, "Max-Forwards", mf_buf[..]);
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
    var committed = false;
    defer if !committed {
        release_upstream_connection(proxy.cluster, target_idx);
        record_proxy_dropped(proxy);
        out_wire.clear();
    };

    // 3. Concurrency ceiling defense against connection exhaustion
    let max_conns = proxy.config.max_active_conns_per_target;
    if is_target_concurrency_saturated(proxy.cluster.targets[target_idx], max_conns) {
        record_proxy_overloaded(proxy);
        return PROXY_TARGET_NONE, false;
    }

    // 4. Header filtering and metadata injection
    var forward_headers = HeaderMap { .. };
    var host_buf: u8[..128] = [];
    let target = proxy.cluster.targets[target_idx];
    let ok_prep = format_upstream_authority(target.host[..], target.port, proxy.config.preserve_host, host_buf)
        && filter_and_forward_headers(in_headers, forward_headers, client_ip, proto, host_buf[..], proxy.config)
        && apply_max_forwards_policy(method, forward_headers)
        && ensure_forwarded_body_framing(forward_headers, body, method)
        && serialize_upstream_request(method, uri, forward_headers, body, out_wire, proxy.config.http_version[..]);
    guard ok_prep else {
        return PROXY_TARGET_NONE, false;
    }

    committed = true;
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
    ring.buf.compact_wire_buffer(ring.read_pos);
    ring.read_pos = 0;
}

// Appends incoming payload chunk into the bounded 16 KB ring buffer.
// Enforces Invariant 13: fails closed with explicit `false` on capacity overflow.
fn feed_stream_chunk(ring: ProxyStreamRing&, chunk: const u8[:]) -> bool {
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

    if kind == ProxyTransportKind.WebSocket {
        // RFC 6455 Section 5.3: Client-to-Server Masking - Octet i of transformed data is XORed with masking-key octet i MOD 4.
        var masked: u8[..16384] = [];
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
    advance_read(src, n);
    return n, true;
}

// ---- Live Pooled Upstream Execution ----------------------------------------

inline fn transport_from_upstream_fd(fd: i32) -> Transport {
    let pipe_slot, is_b_end, is_virt = decode_virtual_pipe_fd(fd);
    if is_virt {
        return Transport.Virtual { pipe_slot: pipe_slot, is_b_end: is_b_end };
    }
    return Transport.Tcp { fd: fd };
}

// Registers a pre-warmed backend socket into the proxy's `UpstreamPool` for zero-RTT keep-alive reuse.
fn park_proxy_upstream_conn(
    proxy:           ReverseProxy&,
    fd:              i32,
    host:            const u8[:],
    port:            u16,
    tls_fingerprint: u64 = 0,
    nik:             u64 = 0,
) -> bool {
    guard fd >= 0 && host.len > 0 && port > 0 else { return false; }
    let pool_key = new_pool_key(
        PoolScheme.Http,
        host,
        port,
        new_direct_proxy_chain(),
        NetworkAnonymizationKey { .. },
        TlsAndDnsPolicy { .. },
    );
    return register_upstream_conn(proxy.warm_upstreams, fd, pool_key.origin_endpoint, tls_fingerprint, nik);
}

fn acquire_or_dial_upstream_conn(
    pool:       StreamPool&,
    warm_pool:  UpstreamPool&,
    target:     const UpstreamTarget&,
    timeout_ms: u32,
    now_ns:     i64,
) -> i32, i32, bool {
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
        return existing_cid, -1, true;
    }
    let warm_fd, has_warm = acquire_upstream_conn(warm_pool, pool_key.origin_endpoint, 0, 0);
    if has_warm && warm_fd >= 0 {
        let warm_t = transport_from_upstream_fd(warm_fd);
        let warm_cid = register_connection(pool, pool_key, NegotiatedProtocol.Http11, warm_t, "", 1, now_ns);
        guard warm_cid > 0 else {
            let _ = release_upstream_conn(warm_pool, warm_fd, EPOLLRDHUP);
            return -1, -1, false;
        }
        return warm_cid, warm_fd, true;
    }
    let sock = tcp_connect(target.host[..], target.port, timeout_ms);
    guard sock > 0 else { return -1, -1, false; }
    var t = Transport.Tcp { fd: sock };
    let new_cid = register_connection(pool, pool_key, NegotiatedProtocol.Http11, t, "", 1, now_ns);
    guard new_cid > 0 else {
        t.close();
        return -1, -1, false;
    }
    return new_cid, -1, true;
}

inline fn finalize_proxy_upstream_conn(
    proxy:     ReverseProxy&,
    pool:      StreamPool&,
    conn_id:   i32,
    c_idx:     i64,
    warm_fd:   i32,
    can_reuse: bool,
    now_ns:    i64,
) {
    if warm_fd >= 0 {
        pool.conns[c_idx].transport = Transport.Disconnected;
        pool.close_pooled_connection(conn_id);
        let ev: u32 = if can_reuse { 0 } else { EPOLLRDHUP };
        let _ = release_upstream_conn(proxy.warm_upstreams, warm_fd, ev);
        return;
    }
    if can_reuse {
        pool.release_connection(conn_id, now_ns);
    } else {
        pool.close_pooled_connection(conn_id);
    }
}

fn read_and_parse_upstream_headers(
    conn:       PooledConnection&,
    out_resp:   Response&,
    timeout_ms: u32,
) -> i64, bool {
    let hdr_end_idx, ok_hdr = read_response_headers(conn, timeout_ms);
    let rx = conn.rx_buf[..];
    let body_start = core::add_sat_i64(hdr_end_idx, 4);
    guard ok_hdr && hdr_end_idx >= 0 && body_start <= rx.len else { return -1, false; }
    guard parse_response_headers(rx[..hdr_end_idx], out_resp) else { return -1, false; }
    return body_start, true;
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
    // RFC 9110 Section 15.2: Informational 1xx - cap consecutive 1xx interim responses to 5.
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
            conn.rx_buf.compact_wire_buffer(leftover_start);
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
    disable_buffering:     bool       = false,
    incremental_preferred: bool       = false,
    has_accel_expires:     bool       = false,
    accel_expires_sec:     i64        = 0,
    limit_rate_bps:        u64        = 0,
    accel_redirect:        u8[..1024] = [],
}

struct UpstreamResponse {
    early_hints:     EarlyHintsResponse   = EarlyHintsResponse { .. },
    has_early_hints: bool                 = false,
    accel:           UpstreamAccelControl = UpstreamAccelControl { .. },
    resp:            Response             = Response { .. },
}

inline fn is_valid_accel_redirect_target(target: const u8[:]) -> bool {
    guard target.len > 0 && target[0] == '/' && !starts_with(target, "//") else {
        return false;
    }
    return wire::is_valid_h1_request_target(target);
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
        guard accel.accel_redirect.len == 0 && is_valid_accel_redirect_target(trimmed) else {
            return false;
        }
        return accel.accel_redirect.try_set(trimmed);
    }
    return name.starts_with_fold("x-accel-");
}

inline fn matches_backend_url_prefix(url_val: const u8[:], backend_url_prefix: const u8[:]) -> bool {
    guard backend_url_prefix.len > 0 && url_val.len >= backend_url_prefix.len else {
        return false;
    }
    let scheme_idx = core::find(backend_url_prefix, "://");
    if scheme_idx >= 0 {
        let auth_start = core::add_sat_i64(scheme_idx, 3);
        guard backend_url_prefix.len > auth_start else { return false; }
        let slash_rel = backend_url_prefix[auth_start..].index_of_byte('/');
        if slash_rel >= 0 {
            let origin_len = core::add_sat_i64(auth_start, slash_rel);
            let origin_ok = url_val[..origin_len].eq_ascii_fold(backend_url_prefix[..origin_len]);
            let path_ok = starts_with(url_val[origin_len..], backend_url_prefix[origin_len..]);
            guard origin_ok && path_ok else { return false; }
        } else {
            guard url_val[..backend_url_prefix.len].eq_ascii_fold(backend_url_prefix) else {
                return false;
            }
        }
    } else {
        guard starts_with(url_val, backend_url_prefix) else { return false; }
    }

    if ends_with(backend_url_prefix, "/") {
        return true;
    }
    let rem = url_val[backend_url_prefix.len..];
    return rem.len == 0 || rem[0] == '/' || rem[0] == '?' || rem[0] == '#';
}

fn try_rewrite_upstream_url<B>(
    url_val:            const u8[:],
    backend_url_prefix: const u8[:],
    public_url_prefix:  const u8[:],
    out_buf:            B&,
) -> const u8[:], bool {
    guard matches_backend_url_prefix(url_val, backend_url_prefix) else {
        return url_val, true;
    }
    let suffix = url_val[backend_url_prefix.len..];
    guard !(public_url_prefix.len == 0 && starts_with(suffix, "//")) else {
        return "", false;
    }
    var committed = false;
    defer if !committed { out_buf.clear(); };
    guard out_buf.try_set(public_url_prefix) else { return "", false; }
    guard out_buf.try_append(suffix) else { return "", false; }
    committed = true;
    return out_buf[..], true;
}

inline fn filter_single_upstream_response_header(
    in_headers:          const HeaderMap&,
    entry_idx:           i64,
    backend_url_prefix:  const u8[:],
    public_url_prefix:   const u8[:],
    out_headers:         HeaderMap&,
    out_location_buf:    u8[..512]&,
    accel:               UpstreamAccelControl&,
    first_loc_entry_idx: i64&,
) -> bool {
    let entry = in_headers.entries[entry_idx];
    let name = entry_name(in_headers, entry);
    let val = entry_value(in_headers, entry);
    if name == ":status" {
        return true;
    }
    // RFC 9110 Section 5.1: Field Names - reject malformed or unstripped pseudo-headers in responses.
    guard is_valid_header_name(name) && is_valid_header_value(val) else { return false; }

    if name.starts_with_fold("x-accel-") {
        return parse_x_accel_control_header(name, val, accel);
    }
    if is_hop_by_hop_header_name(name) || is_token_in_connection_header_map(in_headers, name) {
        return true;
    }
    if name.eq_ascii_fold("content-length") {
        if !has_header(out_headers, "content-length") {
            return append_canonical_content_length(out_headers, name, val);
        }
        return true;
    }
    if name.eq_ascii_fold("location") {
        // RFC 9110 Section 10.2.2: Location - reject conflicting duplicate Location header fields.
        let clean_loc = val.trim_lws();
        if first_loc_entry_idx >= 0 {
            let prev_loc = entry_value(in_headers, in_headers.entries[first_loc_entry_idx]).trim_lws();
            return clean_loc == prev_loc;
        }
        first_loc_entry_idx = entry_idx;
        let rewritten, ok_loc = try_rewrite_upstream_url(
            clean_loc, backend_url_prefix, public_url_prefix, out_location_buf,
        );
        guard ok_loc else { return false; }
        return append_header(out_headers, name, rewritten);
    }
    if name.eq_ascii_fold("content-location") {
        // RFC 9110 Section 8.7: Content-Location - rewrite matching internal backend origin prefix.
        var cloc_buf: u8[..512] = [];
        let rewritten_cloc, ok_cloc = try_rewrite_upstream_url(
            val.trim_lws(), backend_url_prefix, public_url_prefix, cloc_buf,
        );
        guard ok_cloc else { return false; }
        return append_header(out_headers, name, rewritten_cloc);
    }
    return append_header(out_headers, name, val);
}

// Parses `X-Accel-*` control headers, strips hop-by-hop and `X-Accel-*` headers,
// and rewrites `Location` and `Content-Location` prefixes matching `backend_url_prefix`.
fn process_and_filter_upstream_response_headers(
    in_headers:         const HeaderMap&,
    backend_url_prefix: const u8[:],
    public_url_prefix:  const u8[:],
    out_headers:        HeaderMap&,
    out_location_buf:   u8[..512]&,
    accel:              UpstreamAccelControl&,
) -> bool {
    out_headers.clear();
    out_location_buf.clear();
    accel = UpstreamAccelControl { .. };
    guard has_consistent_framing_headers(in_headers) else { return false; }
    var committed = false;
    defer if !committed {
        out_headers.clear();
        out_location_buf.clear();
        accel = UpstreamAccelControl { .. };
    };
    if is_incremental_requested(in_headers) {
        accel.incremental_preferred = true;
        accel.disable_buffering = true;
    }
    var first_loc_entry_idx: i64 = -1;
    for entry_idx in in_headers.entries.len {
        guard filter_single_upstream_response_header(
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
fn capture_upstream_early_hints(in_resp: const Response&, out_upstream: UpstreamResponse&) {
    guard in_resp.status_code == 103 else { return; }
    for &entry in in_resp.headers.entries {
        let name = entry_name(in_resp.headers, entry);
        if name.eq_ascii_fold("link") {
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
    let conn_id, warm_fd, ok_conn = acquire_or_dial_upstream_conn(
        pool, proxy.warm_upstreams, target, timeout_ms, now_i64,
    );
    guard ok_conn && conn_id > 0 else {
        complete_upstream_exchange(proxy, target_idx, 0, false);
        return false;
    }

    let c_idx = pool.find_connection_index(conn_id);
    guard c_idx >= 0 else {
        if warm_fd >= 0 {
            let _ = release_upstream_conn(proxy.warm_upstreams, warm_fd, EPOLLRDHUP);
        } else {
            pool.close_pooled_connection(conn_id);
        }
        complete_upstream_exchange(proxy, target_idx, 0, false);
        return false;
    }

    pool.conns[c_idx].rx_buf.clear();
    let ok_ex, keep_alive = exchange_prepared_wire_on_conn(
        pool.conns[c_idx], method, wire_req[..], out_resp, timeout_ms,
    );
    var headers_valid = ok_ex;
    if ok_ex {
        var filtered_hdrs = HeaderMap { .. };
        var loc_buf: u8[..512] = [];
        var accel = UpstreamAccelControl { .. };
        headers_valid = process_and_filter_upstream_response_headers(
            out_resp.headers, "", "", filtered_hdrs, loc_buf, accel,
        );
        if headers_valid {
            out_resp.headers = filtered_hdrs;
        }
    }
    let can_reuse = headers_valid && keep_alive && pool.conns[c_idx].rx_buf.len == 0;
    finalize_proxy_upstream_conn(proxy, pool, conn_id, c_idx, warm_fd, can_reuse, now_i64);
    if headers_valid {
        var ps_entry = ProxyStatusEntry {
            received_status: out_resp.status_code,
            ..
        };
        ps_entry.proxy_name.try_set(proxy.config.via_pseudonym[..]);
        ps_entry.next_hop.try_set(target.host[..]);
        var ps_buf: u8[..256] = [];
        format_proxy_status(ps_entry, ps_buf);
        out_resp.set_header("Proxy-Status", ps_buf[..]);
    }
    let recorded_status = if headers_valid { out_resp.status_code } else { 0 };
    complete_upstream_exchange(proxy, target_idx, recorded_status, headers_valid);
    return headers_valid;
}

// ---- Resilient Upstream Proxy Service Layer (`wire/service.goose` Integration) ----

// Zero-allocation upstream proxy service stage binding `ReverseProxy` and `StreamPool` to `wire::exchange`.
struct UpstreamProxyService {
    proxy:      ReverseProxy = ReverseProxy { .. },
    pool:       StreamPool   = StreamPool { .. },
    client_ip:  u8[..64]     = [],
    proto:      u8[..8]      = "http",
    timeout_ms: u32          = 5000,
    now_ns:     u64          = 0,
}

// Outer request-hygiene guard stage composed via `wire::stack_service` ahead of resilience layers.
struct ProxyRequestGuard {
    require_consistent_framing: bool = true,
}

// Validates framing consistency before entering the upstream retry/singleflight/breaker stack.
fn exchange(stage: const ProxyRequestGuard&, req: const Request&, res: Response&) -> wire::StageVerdict {
    if stage.require_consistent_framing && !has_consistent_framing_headers(req.headers) {
        res.status_code = rfc::STATUS_BAD_REQUEST;
        return wire::StageVerdict.ShortCircuit { status_code: rfc::STATUS_BAD_REQUEST as u16 };
    }
    return wire::StageVerdict.Continue;
}

// Returns true when `req` uses an idempotent HTTP method eligible for retry (RFC 9110 Section 9.2.2).
inline fn is_retryable_request(req: const Request&) -> bool {
    return rfc::is_idempotent_method(req.method[..]);
}

// Returns the canonical service routing and singleflight key for an HTTP `Request`.
inline fn service_key(req: const Request&) -> const u8[:] {
    if req.url.len > 0 {
        return req.url[..];
    }
    return req.header("Host");
}

// Evaluates GCRA rate-limit allowance for `key` at `now_ns` (UFCS hook for `wire::RateLimitService`).
fn allow_service_key(limiter: GatewayRateLimiter&, key: const u8[:], now_ns: u64) -> bool {
    guard key.len > 0 && now_ns > 0 else { return true; }
    let dec = check_gateway_rate_limit(limiter, key, 1, now_ns);
    return dec.allowed;
}

// Executes a single upstream proxy attempt and maps transport or 502/503 failures to `StageVerdict.Abort`.
fn exchange(svc: UpstreamProxyService&, req: const Request&, res: Response&) -> wire::StageVerdict {
    let ok = execute_proxy_exchange(
        svc.proxy,
        svc.pool,
        req.method[..],
        req.url[..],
        req.headers,
        svc.client_ip[..],
        svc.proto[..],
        req.body[..],
        res,
        svc.timeout_ms,
        svc.now_ns,
    );
    guard ok else {
        if res.status_code == 0 {
            res.status_code = rfc::STATUS_BAD_GATEWAY;
        }
        return wire::StageVerdict.Abort { err_code: rfc::STATUS_BAD_GATEWAY };
    }
    if res.status_code == rfc::STATUS_BAD_GATEWAY || res.status_code == rfc::STATUS_SERVICE_UNAVAILABLE {
        return wire::StageVerdict.Abort { err_code: res.status_code };
    }
    return wire::StageVerdict.Continue;
}

// Executes an HTTP `Request` through the full zero-allocation `wire/service.goose` resilience stack
// (request framing guard, GCRA rate limiter, token-bucket retry, circuit breaker, and singleflight).
fn execute_resilient_proxy_exchange(
    proxy:        ReverseProxy&,
    pool:         StreamPool&,
    req:          const Request&,
    client_ip:    const u8[:],
    proto:        const u8[:],
    out_resp:     Response&,
    max_attempts: i32 = 3,
    timeout_ms:   u32 = 5000,
    now_ns:       u64 = 0,
) -> wire::StageVerdict {
    let effective_now = if now_ns > 0 { now_ns } else { core::as_nanos(core::monotonic_now()) };
    var base = UpstreamProxyService {
        proxy:      proxy,
        pool:       pool,
        timeout_ms: timeout_ms,
        now_ns:     effective_now,
        ..
    };
    let _ = base.client_ip.try_set(client_ip);
    let _ = base.proto.try_set(if proto.len > 0 { proto } else { "http" });

    var sf_svc = wire::new_singleflight_service(base);
    let fail_thresh = max(proxy.health_checker.config.unhealthy_threshold, 1);
    let cooldown_ms = max(proxy.health_checker.config.interval_ms, 1000);
    var cb_svc = wire::new_circuit_breaker_service(sf_svc, fail_thresh, cooldown_ms);
    if !proxy.cluster.circuit_open {
        wire::reset_breaker(cb_svc);
    }
    wire::advance_breaker_clock(cb_svc, effective_now >> 20);

    var retry_svc = wire::new_retry_service(cb_svc, max_attempts);
    var rl_svc = wire::new_rate_limit_service(retry_svc, proxy.rate_limiter, effective_now);
    var pipeline = wire::stack_service(ProxyRequestGuard { .. }, rl_svc);
    let verdict = pipeline.exchange(req, out_resp);

    proxy = pipeline.inner.inner.inner.inner.inner.proxy;
    pool = pipeline.inner.inner.inner.inner.inner.pool;
    if proxy.config.enable_rate_limiting {
        proxy.rate_limiter = pipeline.inner.limiter;
    }
    return verdict;
}

// Convenience overload building a `Request` from raw components and invoking `execute_resilient_proxy_exchange`.
fn execute_resilient_proxy_exchange(
    proxy:        ReverseProxy&,
    pool:         StreamPool&,
    method:       const u8[:],
    uri:          const u8[:],
    in_headers:   const HeaderMap&,
    client_ip:    const u8[:],
    proto:        const u8[:],
    body:         const u8[:],
    out_resp:     Response&,
    max_attempts: i32 = 3,
    timeout_ms:   u32 = 5000,
    now_ns:       u64 = 0,
) -> bool {
    var req = new_request(method, uri);
    req.headers = in_headers;
    guard req.body.try_set(body) else { return false; }
    let verdict = execute_resilient_proxy_exchange(
        proxy,
        pool,
        req,
        client_ip,
        proto,
        out_resp,
        max_attempts,
        timeout_ms,
        now_ns,
    );
    return verdict == wire::StageVerdict.Continue;
}
