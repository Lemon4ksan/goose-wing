// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Internal live network hop orchestration (DNS, H3 racing, pool, H2/H1 dispatch) and offline MockExchange.
namespace client_internal;

import std;
import core;
import rfc.http;
import http.response;
import http.headers;
import http.altsvc;
import security.ssrf;
import realtime.websocket;
import net.pool;
import net.isolation;
import net.proxy;
import net.happy_eyeballs;
import net.transport;
import wire.pipeline;
import client.redirect;
import client.client;
import client.internal;
import .mock;
import .tls_hop_internal;
import .dns_dial_internal;
import .hop_context_internal;
import .stage_bricks_internal;
import .h3_internal;
import .h1_h2_internal;

fn validate_mock_route_dns(
    route:        const client::MockExchange&,
    guard_config: const security::SsrfGuardPolicy&,
) -> client::RedirectError {
    if route.resolved_ips.len == 0 {
        return client::RedirectError.None;
    }
    var ips_slice: const u8[:][4] = ["", "", "", ""];
    for idx in route.resolved_ips.len {
        ips_slice[idx] = route.resolved_ips[idx][..];
    }
    return validate_resolved_ips_against_ssrf(ips_slice[..route.resolved_ips.len], guard_config);
}

fn build_mock_response(
    route:        const client::MockExchange&,
    current_url:  const core::Url&,
    sent_headers: const http::HeaderMap&,
) -> http::Response {
    var resp = http::Response {
        status_code:   route.status_code,
        effective_url: copy(current_url.href),
        ..
    };
    if route.protocol.len > 0 {
        let _ = resp.protocol.try_set(route.protocol[..]);
    }
    http::copy_headers(route.headers, resp.headers);
    for &e in resp.headers.entries {
        http::update_response_presence(resp, http::entry_name(resp.headers, e));
    }
    resp.body.append(route.body[..]);
    http::copy_headers(sent_headers, resp.sent_headers);
    return resp;
}

fn resolve_mock_protocol_racing(
    session:    client::Session&,
    route:      const client::MockExchange&,
    is_https:   bool,
    origin_buf: const u8[:],
    has_h3:     bool,
    now_sec:    i64,
    resp:       http::Response&,
) {
    if !has_h3 {
        if route.protocol.len > 0 {
            let _ = resp.protocol.try_set(route.protocol[..]);
        }
        return;
    }

    let race_eligible = net::should_create_dns_alpn_h3_job(net::H3JobOptions {
        is_https:                   is_https,
        quic_enabled:               session.enable_protocol_racing,
        uses_proxy:                 session.proxy_url.len > 0,
        has_available_quic_session: false,
    });
    if race_eligible || session.enable_altsvc {
        if route.simulate_quic_blocked {
            http::record_failure(session.altsvc, origin_buf, now_sec);
            let proto = if route.protocol.len > 0 { route.protocol[..] } else { "HTTP/1.1" };
            let _ = resp.protocol.try_set(proto);
        } else {
            http::record_success(session.altsvc, origin_buf);
            let _ = resp.protocol.try_set("h3");
        }
    }
}

fn try_match_mock_route(
    session:     client::Session&,
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    has_h3:      bool,
    origin_buf:  const u8[:],
    curr_path:   const u8[:],
    now_sec:     i64,
    out_dns_err: client::RedirectError&,
    out_resp:    http::Response&,
) -> bool {
    let curr_href = current_url.href[..];
    let curr_method = ctx.current_method[..];
    let is_https = current_url.is_secure_scheme();

    var matched_idx: i64 = -1;
    for &route, i in session.mock_routes {
        let method_match = route.method.len == 0 || route.method[..].eq_ascii_fold(curr_method);
        let url_match = route.pattern_url[..] == curr_href || core::starts_with(curr_href, route.pattern_url[..]);
        if method_match && url_match {
            matched_idx = i;
            break;
        }
    }
    guard matched_idx >= 0 else { return false; }

    let route .= session.mock_routes[matched_idx];
    let dns_err = validate_mock_route_dns(route, session.ssrf_guard);
    if dns_err != client::RedirectError.None {
        out_dns_err = dns_err;
        out_resp = http::Response {
            status_code:   rfc::STATUS_FORBIDDEN,
            effective_url: copy(current_url.href),
            ..
        };
        return true;
    }

    let mock_resp = build_mock_response(route, current_url, ctx.headers);
    out_resp = copy(mock_resp);
    if route.status_code == rfc::STATUS_SWITCHING_PROTOCOLS {
        let sent_key = http::find_header(ctx.headers, "sec-websocket-key");
        if sent_key.len > 0 && out_resp.header("sec-websocket-accept").len == 0 {
            var accept_buf: u8[..64] = [];
            realtime::compute_websocket_accept(sent_key, accept_buf);
            out_resp.set_header("Sec-WebSocket-Accept", accept_buf[..]);
        }
    }

    resolve_mock_protocol_racing(session, route, is_https, origin_buf, has_h3, now_sec, out_resp);
    ingest_transport_response_headers(session, current_url, is_https, origin_buf, curr_path, now_sec, out_resp);
    return true;
}

fn try_race_live_h3_hop(
    session:     client::Session&,
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    origin_buf:  const u8[:],
    h3_ep:       const http::AltSvcEndpoint&,
    now_sec:     i64,
    resp:        http::Response&,
) -> bool {
    let saved_t = ctx.timeout_ms;
    if session.read_timeout_ms > 0 {
        ctx.timeout_ms = calc_phase_timeout_ms(session.read_timeout_ms, session.timeout_ms, saved_t);
    }
    let ok_h3 = execute_live_h3_hop(session, ctx, current_url, origin_buf, h3_ep, now_sec, resp);
    ctx.timeout_ms = saved_t;
    if ok_h3 {
        session.altsvc.record_success(origin_buf);
        return true;
    }
    session.altsvc.record_failure(origin_buf, now_sec);
    return false;
}

fn build_live_hop_pool_key(
    ctx:         const RequestExecutionContext&,
    host_str:    const u8[:],
    port_num:    u16,
    is_https:    bool,
    proxy_chain: const net::ProxyChain&,
) -> net::PoolKey {
    let site_site = if ctx.top_frame_origin.host.len > 0 {
        ctx.top_frame_origin.host[..]
    } else if !ctx.site_for_cookies.is_null && ctx.site_for_cookies.registrable_domain.len > 0 {
        ctx.site_for_cookies.registrable_domain[..]
    } else {
        host_str
    };
    let pool_scheme = if is_https { net::PoolScheme.Https } else { net::PoolScheme.Http };
    let nik = net::new_network_isolation_key(site_site, site_site);
    return net::new_pool_key(
        pool_scheme,
        host_str,
        port_num,
        proxy_chain,
        net::nik_to_anonymization_key(nik, ctx.had_cross_site_hop),
        net::TlsAndDnsPolicy { .. },
    );
}

fn dispatch_acquired_pooled_hop(
    session:     client::Session&,
    conn_id:     i32,
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    is_https:    bool,
    origin_buf:  const u8[:],
    now_sec:     i64,
    now_ns:      i64,
    resp:        http::Response&,
) -> http::Error {
    let curr_path = current_url.pathname();
    let c_idx = session.pool.find_connection_index(conn_id);
    let is_h2 = c_idx >= 0 && c_idx < session.pool.conns.len &&
        session.pool.conns[c_idx].protocol == net::NegotiatedProtocol.Http2;
    if is_h2 {
        let ok_h2 = dispatch_pooled_h2_hop(
            session, conn_id, ctx.current_method[..], ctx, current_url, is_https,
            origin_buf, curr_path, now_sec, now_ns, resp,
        );
        guard ok_h2 else {
            return http::make_error(rfc::STATUS_BAD_GATEWAY, "transport", "HTTP/2 exchange failed");
        }
        return http::Error { .. };
    }

    let saved_h1_t = ctx.timeout_ms;
    if session.read_timeout_ms > 0 {
        ctx.timeout_ms = calc_phase_timeout_ms(session.read_timeout_ms, session.timeout_ms, saved_h1_t);
    }
    let ok_hop = dispatch_pooled_h1_hop(
        session, conn_id, ctx.current_method[..], ctx, current_url, is_https,
        origin_buf, curr_path, now_sec, now_ns, resp,
    );
    ctx.timeout_ms = saved_h1_t;
    guard ok_hop else {
        return http::make_error(rfc::STATUS_BAD_GATEWAY, "transport", "HTTP/1.1 exchange failed");
    }
    return http::Error { .. };
}

fn execute_live_network_hop(
    session:     client::Session&,
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    is_https:    bool,
    origin_buf:  const u8[:],
    has_h3:      bool,
    h3_ep:       const http::AltSvcEndpoint&,
    resp:        http::Response&,
) -> http::Error {
    let now_us = client::effective_clock_us(session);
    let now_ns = core::mul_sat_i64(now_us, 1000);
    let now_sec = div_euclid(now_us, 1000000);
    let now_ms = div_euclid(now_us, 1000);
    let host_str = current_url.hostname();
    sync_session_pool_knobs(session);
    guard !is_ssrf_blocked_ip(session.ssrf_guard, host_str) else {
        return http::make_error(rfc::STATUS_FORBIDDEN, "ssrf_guard", "SSRF: private IP blocked");
    }

    let port_num = current_url.effective_port() as u16;
    var eff_proxy_url: u8[..256] = [];
    let proxy_chain, ok_proxy = resolve_effective_hop_proxy(session, host_str, is_https, eff_proxy_url);
    guard ok_proxy else {
        return http::make_error(rfc::STATUS_BAD_REQUEST, "proxy", "invalid proxy configuration");
    }
    var dns_candidates: net::DnsCandidate[..32] = [];
    var ech_list:       u8[..512]               = [];
    let needs_local_dns = proxy_chain.is_direct ||
        (proxy_chain.servers.len > 0 && proxy_chain.servers[0].scheme == net::ProxyScheme.Socks5);
    if needs_local_dns {
        let dns_err = resolve_and_validate_live_host(session, host_str, port_num, now_sec, dns_candidates, ech_list);
        guard http::ok(dns_err) else { return dns_err; }
    }
    if !proxy_chain.is_direct {
        net::sanitize_tunnel_headers_for_origin(ctx.headers);
    }
    if has_h3 && is_https && proxy_chain.is_direct && session.enable_protocol_racing &&
        try_race_live_h3_hop(session, ctx, current_url, origin_buf, h3_ep, now_sec, resp) {
        return http::Error { .. };
    }

    let pool_key = build_live_hop_pool_key(ctx, host_str, port_num, is_https, proxy_chain);
    let first_ip = if dns_candidates.len > 0 { dns_candidates[0].ip[..] } else { "" };
    var conn_id, has_pooled = session.pool.acquire_pooled_connection(pool_key, first_ip, now_ns);
    if !has_pooled {
        let conn_t = calc_phase_timeout_ms(session.connect_timeout_ms, session.timeout_ms, ctx.timeout_ms);
        let tls_t = calc_phase_timeout_ms(session.tls_handshake_timeout_ms, session.timeout_ms, ctx.timeout_ms);
        let new_id, conn_err = establish_pooled_connection(
            session, pool_key, eff_proxy_url[..], proxy_chain, host_str, port_num, is_https,
            dns_candidates[..], ech_list[..], conn_t, tls_t, now_sec, now_ms, now_ns,
        );
        guard http::ok(conn_err) else { return conn_err; }
        conn_id = new_id;
    }
    return dispatch_acquired_pooled_hop(
        session, conn_id, ctx, current_url, is_https, origin_buf, now_sec, now_ns, resp,
    );
}

fn execute_mock_or_echo_hop(
    session:     client::Session&,
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
) -> http::Response, http::Error {
    var origin_buf: u8[..128] = [];
    format_url_origin(current_url, origin_buf);
    let now_sec = div_euclid(client::effective_clock_us(session), 1000000);
    let is_https = current_url.is_secure_scheme();

    var candidate_h3_ep = http::AltSvcEndpoint { .. };
    var has_h3 = false;
    if session.enable_altsvc && is_https {
        has_h3 = http::lookup_h3(session.altsvc, origin_buf[..], now_sec, candidate_h3_ep);
    }
    let race_dns_h3 = !has_h3 && is_https && session.enable_protocol_racing
        && !http::is_broken(session.altsvc, origin_buf[..], now_sec);
    if race_dns_h3 {
        let port_num = current_url.effective_port() as u16;
        let dns_ep, ok_dns_h3 = lookup_dns_https_h3_endpoint(
            session.dns_cache, current_url.hostname(), port_num, now_sec,
        );
        if ok_dns_h3 {
            candidate_h3_ep = dns_ep;
            has_h3 = true;
        }
    }

    let curr_path = current_url.pathname();
    if wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_DICT_NEGOTIATE) {
        let _ = stage_client_dict_negotiate(
            ctx.headers, session.dict_cache, session.enable_compression_dict,
            origin_buf[..], curr_path, is_https, now_sec,
        );
    } else {
        http::remove_header_by_name(ctx.headers, "Available-Dictionary");
        http::remove_header_by_name(ctx.headers, "Dictionary-ID");
    }

    var resp = http::Response { .. };
    var dns_rebinding_err = client::RedirectError.None;
    let matched = try_match_mock_route(
        session, ctx, current_url, has_h3, origin_buf[..], curr_path, now_sec, dns_rebinding_err, resp,
    );
    if matched {
        if dns_rebinding_err != client::RedirectError.None {
            return resp, http::make_error(
                rfc::STATUS_FORBIDDEN, "ssrf_guard", redirect_error_to_string(dns_rebinding_err),
            );
        }
        return resp, http::Error { .. };
    }

    if session.mock_routes.len == 0 {
        let live_err = execute_live_network_hop(
            session, ctx, current_url, is_https, origin_buf[..], has_h3, candidate_h3_ep, resp,
        );
        return resp, live_err;
    }

    return resp, http::make_error(rfc::STATUS_BAD_GATEWAY, "mock", "no matching mock route for request");
}
