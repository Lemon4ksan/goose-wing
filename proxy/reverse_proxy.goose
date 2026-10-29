// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Layer 7 Reverse Proxy Engine, Hop-by-Hop Header Stripping,
// Forwarded/Via Chaining, and Upstream Request Dispatcher (RFC 9110 §7.6).
namespace wing;

import std;
import core from "..";
import http.headers;
import proxy.load_balancer;

const PROXY_TARGET_NONE: i32 = -1;

struct ProxyConfig {
    strip_hop_by_hop: bool = true,
    append_forwarded: bool = true,
    preserve_host: bool = false,
    via_pseudonym: u8[..32] = "wing",
    http_version: u8[..8] = "HTTP/1.1",
}

fn new_proxy_config() -> ProxyConfig {
    return ProxyConfig { .. };
}

// Helper to format chained X-Forwarded-For value without in-branch bounded buffer operations.
fn format_chained_xff(buf: u8[>..]&, existing_xff: const u8[:], client_ip: const u8[:]) {
    buf.clear();
    buf.append(existing_xff);
    buf.append(", ");
    buf.append(client_ip);
}

// Appends client IP to X-Forwarded-For header, chaining with existing entries if present.
fn append_chained_xff(out_headers: HeaderMap&, existing_xff: const u8[:], client_ip: const u8[:]) -> bool {
    var chained: u8[>..] = [];
    format_chained_xff(chained, existing_xff, client_ip);
    return append_header(out_headers, "X-Forwarded-For", chained[..]);
}

fn append_forwarded_for(out_headers: HeaderMap&, existing_xff: const u8[:], client_ip: const u8[:]) -> bool {
    guard client_ip.len > 0 else { return true; }
    if existing_xff.len > 0 {
        return append_chained_xff(out_headers, existing_xff, client_ip);
    }
    return append_header(out_headers, "X-Forwarded-For", client_ip);
}

// Determines if an incoming header should be forwarded to upstream.
fn should_forward_header(
    name: const u8[:],
    val: const u8[:],
    in_headers: const HeaderMap&,
    preserve_host: bool,
    strip_hop: bool,
) -> bool {
    if eq_ascii_fold(name, "host") {
        return preserve_host;
    }
    if eq_ascii_fold(name, "x-forwarded-for") {
        return false;
    }
    guard strip_hop else { return true; }

    if is_hop_by_hop_header_name(name) {
        // RFC 9110: TE may only be forwarded if the value is trailers
        return eq_ascii_fold(name, "te") && eq_ascii_fold(core::trim_lws(val), "trailers");
    }

    if is_token_in_connection_header_map(in_headers, name) {
        return false;
    }

    return true;
}

// Copies filtered client headers into proxy request header map.
fn copy_filtered_headers(
    in_headers: const HeaderMap&,
    out_headers: HeaderMap&,
    preserve_host: bool,
    strip_hop: bool,
) {
    for i in in_headers.entries.len {
        let entry = in_headers.entries[i];
        let name = in_headers.raw_buf[entry.name_begin..entry.name_end];
        let val = in_headers.raw_buf[entry.values_begin..entry.values_end];

        if should_forward_header(name, val, in_headers, preserve_host, strip_hop) {
            append_header(out_headers, name, val);
        }
    }
}

// Helper to format Via header value without in-branch bounded buffer operations.
fn format_via(buf: u8[>..]&, pseudonym: const u8[:]) {
    buf.clear();
    buf.append("1.1 ");
    buf.append(pseudonym);
}

// Injects Via header (RFC 9110 §7.6.3).
fn inject_via_header(out_headers: HeaderMap&, pseudonym: const u8[:]) {
    guard pseudonym.len > 0 else { return; }
    var via_buf: u8[>..] = [];
    format_via(via_buf, pseudonym);
    append_header(out_headers, "Via", via_buf[..]);
}

// Injects standard proxy forwarding headers (RFC 7239 / de facto).
fn inject_forwarded_metadata(
    out_headers: HeaderMap&,
    in_headers: const HeaderMap&,
    client_ip: const u8[:],
    proto: const u8[:],
    preserve_host: bool,
) {
    let existing_xff = get_header(in_headers, "X-Forwarded-For");
    let orig_host = get_header(in_headers, "Host");

    append_forwarded_for(out_headers, existing_xff, client_ip);

    if proto.len > 0 {
        append_header(out_headers, "X-Forwarded-Proto", proto);
    }
    if orig_host.len > 0 && !preserve_host {
        append_header(out_headers, "X-Forwarded-Host", orig_host);
    }
}

// Filters incoming request headers and populates outgoing proxy request headers.
fn filter_and_forward_headers(
    in_headers: const HeaderMap&,
    out_headers: HeaderMap&,
    client_ip: const u8[:],
    proto: const u8[:],
    upstream_host: const u8[:],
    config: const ProxyConfig&,
) -> bool {
    reset_for_keep_alive(out_headers);

    copy_filtered_headers(in_headers, out_headers, config.preserve_host, config.strip_hop_by_hop);

    if !config.preserve_host && upstream_host.len > 0 {
        append_header(out_headers, "Host", upstream_host);
    }

    if config.append_forwarded {
        inject_forwarded_metadata(out_headers, in_headers, client_ip, proto, config.preserve_host);
    }

    inject_via_header(out_headers, config.via_pseudonym[..]);
    return true;
}

// Formats upstream wire HTTP/1.1 request buffer ready for transmission.
fn serialize_upstream_request(
    method: const u8[:],
    uri: const u8[:],
    headers: const HeaderMap&,
    body: const u8[:],
    out: u8[>..]&,
) {
    out.clear();
    out.append(method);
    out.append(" ");
    out.append(if uri.len > 0 { uri } else { "/" });
    out.append(" HTTP/1.1\r\n");

    for i in headers.entries.len {
        let entry = headers.entries[i];
        let name = headers.raw_buf[entry.name_begin..entry.name_end];
        let val = headers.raw_buf[entry.values_begin..entry.values_end];
        out.append(name);
        out.append(": ");
        out.append(val);
        out.append("\r\n");
    }

    out.append("\r\n");
    if body.len > 0 {
        out.append(body);
    }
}

// Layer 7 Reverse Proxy Gateway instance managing an UpstreamCluster.
struct ReverseProxy {
    cluster: UpstreamCluster = UpstreamCluster { .. },
    config: ProxyConfig = ProxyConfig { .. },
    total_forwarded: u64 = 0,
    total_dropped: u64 = 0,
}

fn new_reverse_proxy(policy: LbPolicy = LbPolicy.RoundRobin) -> ReverseProxy {
    return ReverseProxy {
        cluster: new_upstream_cluster(policy),
        config: new_proxy_config(),
        ..
    };
}

fn record_proxy_dropped(proxy: ReverseProxy&) {
    proxy.total_dropped = proxy.total_dropped + 1;
}

fn record_proxy_forwarded(proxy: ReverseProxy&) {
    proxy.total_forwarded = proxy.total_forwarded + 1;
}

// Selects upstream target, rewrites headers, and serializes forward wire request.
fn prepare_proxy_request(
    proxy: ReverseProxy&,
    method: const u8[:],
    uri: const u8[:],
    in_headers: const HeaderMap&,
    client_ip: const u8[:],
    proto: const u8[:],
    body: const u8[:],
    out_wire: u8[>..]&,
) -> i32, bool {
    let target_idx, ok = select_upstream(proxy.cluster);
    guard ok && target_idx >= 0 else {
        record_proxy_dropped(proxy);
        return PROXY_TARGET_NONE, false;
    }

    var forward_headers = new_header_map();
    let upstream_host = proxy.cluster.targets[target_idx].host[..];

    filter_and_forward_headers(
        in_headers,
        forward_headers,
        client_ip,
        proto,
        upstream_host,
        proxy.config,
    );

    serialize_upstream_request(method, uri, forward_headers, body, out_wire);
    record_proxy_forwarded(proxy);
    return target_idx, true;
}
