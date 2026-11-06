// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Execution pipeline, redirect state machine, and hop orchestration (Chromium net::URLRequest 6-phase pipeline).
namespace wing;

import std;
import cookie.constants;
import cookie.canonical;
import cookie.policy;
import cookie.engine;
import client.profile;
import client.request;
import client.response;
import client.redirect;
import client.interceptor;
import http.headers;
import http.cache.cache_control;
import http.cache.freshness;
import http.cache.validators;
import http.cache.engine;
import http.altsvc;
import http.compression_dict;
import http.hsts;
import auth.digest;
import realtime.websocket;
import client.session.ssrf;
import client.session.mock;
import client.client;
import client.session.cookie_bridge;
import client.session.h1_exchange;
import net.pool;
import net.proxy;
import net.dns;
import net.happy_eyeballs;
import net.retry;
import http2.framing;
import http2.hpack;
import http3.framing;
import http3.qpack;
import http3.connection;
import quic.packet;
import quic.frames;
import quic.connection;
import wire.types;
import wire.hpack;
import wire.h2;
import wire.pipeline;
import client.session.stages;

// ---- url resolution helpers ------------------------------------------------

// Escapes special delimiters and control characters in a query parameter component (RFC 3986 §3.4).
//
// Example:
//   raw = "a&b=c", out = []
//   returns: true, out = "a%26b%3Dc"
fn append_query_component(raw: const u8[:], out: u8[..2048]&) -> bool {
    for b in raw {
        if b == ' ' {
            guard out.try_append("%20") else { return false; }
        } else if b == '&' {
            guard out.try_append("%26") else { return false; }
        } else if b == '=' {
            guard out.try_append("%3D") else { return false; }
        } else if b == '#' {
            guard out.try_append("%23") else { return false; }
        } else if b == '+' {
            guard out.try_append("%2B") else { return false; }
        } else if b == '%' {
            guard out.try_append("%25") else { return false; }
        } else if b < 0x20 || b >= 0x7F {
            guard out.try_push('%') else { return false; }
            let hi = (b >> 4) & 0x0F;
            let lo = b & 0x0F;
            let hi_c = if hi < 10 { '0' + hi } else { 'A' + hi - 10 };
            guard out.try_push(hi_c) else { return false; }
            let lo_c = if lo < 10 { '0' + lo } else { 'A' + lo - 10 };
            guard out.try_push(lo_c) else { return false; }
        } else {
            guard out.try_push(b) else { return false; }
        }
    }
    return true;
}

inline fn append_single_query_param(
    query_item: const QueryItem&,
    sep:        u8,
    out:        u8[..2048]&,
) -> bool {
    guard out.try_push(sep) else { return false; }
    guard append_query_component(query_item.key[..], out) else { return false; }
    guard out.try_push('=') else { return false; }
    return append_query_component(query_item.value[..], out);
}

// Appends query parameters to a URL buffer, preserving trailing fragment if present (RFC 3986 Section 4.1).
fn append_query_params_preserving_fragment(
    out:          u8[..2048]&,
    query_params: const QueryItem[:],
) {
    guard query_params.len > 0 else { return; }

    var hash_pos = -1;
    var has_query_mark = false;
    for scan_idx in out.len {
        let b = out[scan_idx];
        if b == '?' && hash_pos < 0 { has_query_mark = true; }
        else if b == '#' && hash_pos < 0 { hash_pos = scan_idx; }
    }

    var hash_buf: u8[..2048] = [];
    if hash_pos >= 0 {
        hash_buf.append(out[hash_pos..]);
        out.resize(hash_pos);
    }

    for &query_item, param_idx in query_params {
        let sep: u8 = if param_idx == 0 && !has_query_mark { '?' } else { '&' };
        guard append_single_query_param(query_item, sep, out) else { break; }
    }

    if hash_buf.len > 0 {
        out.try_append(hash_buf[..]);
    }
}

// Builds the effective request URL from base_url, req_url, and query_params.
// Fragments are preserved and appended after query parameters (RFC 3986 Section 4.1).
fn build_effective_url(
    base_url:     const u8[:],
    req_url:      const u8[:],
    query_params: const QueryItem[:],
    out:          u8[..2048]&,
) {
    out.clear();
    let parsed_base = core::new_url(base_url);
    if parsed_base.valid {
        let eff_url = resolve_endpoint(parsed_base, req_url);
        out.append(href(eff_url));
    } else if req_url.len >= 7 && (req_url[..7] == "http://" || (req_url.len >= 8 && req_url[..8] == "https://")) {
        out.append(req_url);
    } else {
        out.append(base_url);
        if base_url.len > 0 && base_url[base_url.len - 1] != '/' && (req_url.len == 0 || req_url[0] != '/') {
            out.push('/');
        }
        out.append(req_url);
    }

    append_query_params_preserving_fragment(out, query_params);
}

// ---- 6-phase execution context & orchestration ------------------------------

struct RequestExecutionContext {
    url_chain:               core::Url[..16]     = [],
    current_method:          u8[..16]            = [],
    headers:                 HeaderMap           = HeaderMap { .. },
    rewind_buf:              u8[..4096]          = [],
    rewindable:              bool                = true,
    body_consumed:           bool                = false,
    initiator:               core::Origin        = core::Origin { .. },
    has_initiator:           bool                = false,
    top_frame_origin:        core::Origin        = core::Origin { .. },
    site_for_cookies:        SiteForCookies      = SiteForCookies { .. },
    first_party_policy:      FirstPartyURLPolicy = FirstPartyURLPolicy.UPDATE_FIRST_PARTY_URL_ON_REDIRECT,
    is_main_frame:           bool                = true,
    is_reload:               bool                = false,
    redirect_mode:           RedirectMode        = RedirectMode.Follow,
    redirect_count:          i64                 = 0,
    max_redirects:           i64                 = 10,
    tainted_origin:          bool                = false,
    had_cross_site_hop:      bool                = false,
    cors_mode:               bool                = false,
    auth_retried:            bool                = false,
    current_referrer:        u8[..2048]          = [],
    current_referrer_policy: ReferrerPolicy      = ReferrerPolicy.StrictOriginWhenCrossOrigin,
    timeout_ms:              i64                 = 0,
    body:                    u8[>..]             = [],
}

fn validate_hop_prerequisites(session: const Session&, current_url: const core::Url&) -> Error {
    if session.https_only && scheme(current_url) != "https" {
        return make_error(rfc::STATUS_BAD_REQUEST, "ssrf_guard", "https_only policy violated");
    }
    let ssrf_err = validate_url_against_ssrf(current_url, session.ssrf_guard);
    if ssrf_err != RedirectError.None {
        return make_error(rfc::STATUS_FORBIDDEN, "ssrf_guard", redirect_error_to_string(ssrf_err));
    }
    return Error { .. };
}

fn finalize_success_response(ctx: const RequestExecutionContext&, resp: Response&) {
    resp.redirect_count = ctx.redirect_count;
    resp.final_method.clear();
    resp.final_method.append(ctx.current_method[..]);
    for &hop_u in ctx.url_chain {
        guard resp.url_chain.len < resp.url_chain.cap else { break; }
        var u_str: u8[..256] = [];
        u_str.append(href(hop_u));
        resp.url_chain.push(u_str);
    }
}

fn apply_redirect_transition(
    session:       const Session&,
    ctx:           RequestExecutionContext&,
    redirect_info: const RedirectInfo&,
) -> Error {
    ctx.had_cross_site_hop = ctx.had_cross_site_hop || redirect_info.is_cross_site_tainted;
    ctx.site_for_cookies = redirect_info.new_site_for_cookies;
    ctx.current_method.clear();
    ctx.current_method.append(redirect_info.new_method[..]);
    ctx.current_referrer.clear();
    ctx.current_referrer.append(redirect_info.new_referrer[..]);
    ctx.current_referrer_policy = redirect_info.new_referrer_policy;

    if redirect_info.clear_body {
        ctx.body.clear();
        ctx.rewind_buf.clear();
        ctx.rewindable = false;
        ctx.body_consumed = false;
    } else {
        // 307 or 308 redirect preserves method and body
        if !ctx.rewindable && ctx.body_consumed {
            return make_error(rfc::STATUS_BAD_REQUEST, "body_rewind", "http: cannot rewind body");
        }
        ctx.body.clear();
        ctx.body.append(ctx.rewind_buf[..]);
        ctx.body_consumed = false;
    }

    let is_trusted = is_trusted_location_host(session, hostname(redirect_info.new_url));
    sanitize_headers_on_redirect(
        ctx.headers,
        redirect_info,
        RedirectSanitizeOptions {
            cors_mode:                   ctx.cors_mode,
            tainted_origin:              ctx.tainted_origin,
            enable_referer:              session.enable_referer,
            trusted_location_forwarding: is_trusted,
        },
    );
    return Error { .. };
}

fn merge_session_and_request_headers(
    headers:         HeaderMap&,
    default_headers: const HeaderMap&,
    req_headers:     const HeaderMap&,
    profile:         Profile,
) {
    copy_headers(default_headers, headers);
    for &e in req_headers.entries {
        let name = entry_name(req_headers, e);
        remove_header_by_name(headers, name);
    }
    append_all_headers(req_headers, headers);
    if profile != Profile.None {
        let has_ae = find_header(headers, "accept-encoding").len > 0;
        if !has_ae {
            set_header(headers, "Accept-Encoding", "zstd, br, gzip");
        }
    }
}

fn init_execution_context(
    session:        const Session&,
    req:            const Request&,
    parsed_initial: const core::Url&,
) -> RequestExecutionContext {
    var ctx = RequestExecutionContext {
        current_method:          copy(req.method),
        rewindable:              req.rewindable,
        body_consumed:           false,
        cors_mode:               req.cors_mode,
        tainted_origin:          req.tainted_origin,
        is_main_frame:           req.is_main_frame,
        is_reload:               req.is_reload,
        redirect_mode:           session.redirect_mode,
        redirect_count:          0,
        max_redirects:           session.max_redirects,
        first_party_policy:      req.first_party_policy,
        current_referrer_policy: session.default_referrer_policy,
        timeout_ms:              req.timeout,
        ..
    };

    if session.default_referrer_policy != ReferrerPolicy.StrictOriginWhenCrossOrigin {
        ctx.current_referrer_policy = session.default_referrer_policy;
    }

    let req_ref = header(req, "Referer");
    if req_ref.len > 0 {
        ctx.current_referrer.append(req_ref);
    }

    ctx.body.append(req.body[..]);
    if req.rewind_buf.len > 0 {
        ctx.rewind_buf.append(req.rewind_buf[..]);
    } else if req.rewindable && req.body.len <= 4096 {
        ctx.rewind_buf.append(req.body[..]);
    } else if ctx.body.len > 0 {
        ctx.rewindable = false;
    }

    if req.has_initiator {
        ctx.initiator = copy(req.initiator);
        ctx.has_initiator = true;
    } else {
        ctx.initiator = core::origin_from_url(parsed_initial);
        ctx.has_initiator = true;
    }

    if req.has_site_for_cookies {
        ctx.site_for_cookies = copy(req.site_for_cookies);
    } else {
        ctx.site_for_cookies = site_for_cookies_from_parsed_url(parsed_initial);
    }

    merge_session_and_request_headers(ctx.headers, session.default_headers, req.headers, session.profile);

    ctx.url_chain.push(parsed_initial);
    return ctx;
}

fn process_redirect_hop(
    session:     Session&,
    ctx:         RequestExecutionContext&,
    resp:        Response&,
    current_url: const core::Url&,
    loc_hdr:     const u8[:],
) -> bool, Error {
    if ctx.redirect_mode == RedirectMode.Manual {
        return false, Error { .. };
    }
    if ctx.redirect_mode == RedirectMode.Error {
        return false, make_error(rfc::STATUS_BAD_REQUEST, "redirect", "redirects disabled by mode");
    }
    if ctx.redirect_count >= ctx.max_redirects {
        return false, make_error(rfc::STATUS_BAD_REQUEST, "redirect", "maximum redirect hops exceeded");
    }
    guard ctx.url_chain.len < ctx.url_chain.cap else {
        return false, make_error(rfc::STATUS_BAD_REQUEST, "redirect", "maximum redirect hops exceeded");
    }

    let ref_policy_hdr = header(resp, "Referrer-Policy");
    let redirect_info = compute_redirect_info(
        resp.status_code,
        ctx.current_method[..],
        current_url,
        loc_hdr,
        ref_policy_hdr,
        ctx.current_referrer_policy,
        ctx.current_referrer[..],
        ctx.site_for_cookies,
        ctx.first_party_policy,
        ctx.url_chain[..],
        ctx.initiator,
        RedirectOptions {
            has_initiator:      ctx.has_initiator,
            cors_mode:          ctx.cors_mode,
            tainted_origin:     ctx.tainted_origin,
            is_main_frame:      ctx.is_main_frame,
            had_cross_site_hop: ctx.had_cross_site_hop,
        },
    );

    guard redirect_info.error == RedirectError.None else {
        return false, make_error(rfc::STATUS_BAD_REQUEST, "redirect", redirect_error_to_string(redirect_info.error));
    }

    let redirect_err = apply_redirect_transition(session, ctx, redirect_info);
    guard ok(redirect_err) else { return false, redirect_err; }

    ctx.url_chain.push(redirect_info.new_url);
    ctx.redirect_count += 1;
    return true, Error { .. };
}

fn append_available_dict_header(headers: HeaderMap&, dict_b64: const u8[:]) {
    set_header(headers, "Available-Dictionary", dict_b64);
    let val = find_header(headers, "accept-encoding");
    guard val.len > 0 else { return; }
    var already_has = false;
    if val.len >= 3 {
        for k in val.len - 2 {
            if val[k] == 'd' && val[k + 1] == 'c' && val[k + 2] == 'b' {
                already_has = true;
                break;
            }
        }
    }
    if !already_has {
        var new_ae: u8[..256] = [];
        new_ae.append(val);
        new_ae.append(", dcb, dcz");
        set_header(headers, "Accept-Encoding", new_ae[..]);
    }
}

fn resolve_mock_protocol_racing(
    session:    Session&,
    route:      const MockExchange&,
    is_https:   bool,
    origin_buf: const u8[:],
    has_h3:     bool,
    now_sec:    i64,
    resp:       Response&,
) {
    if !has_h3 {
        if route.protocol.len > 0 {
            resp.protocol.clear();
            resp.protocol.append(route.protocol[..]);
        }
        return;
    }

    let race_eligible = should_create_dns_alpn_h3_job(H3JobOptions {
        is_https:                   is_https,
        quic_enabled:               session.enable_protocol_racing,
        uses_proxy:                 session.proxy_url.len > 0,
        has_available_quic_session: false,
    });
    if race_eligible || session.enable_altsvc {
        if route.simulate_quic_blocked {
            record_failure(session.altsvc, origin_buf, now_sec);
            resp.protocol.clear();
            let proto = if route.protocol.len > 0 { route.protocol[..] } else { "HTTP/1.1" };
            resp.protocol.append(proto);
        } else {
            record_success(session.altsvc, origin_buf);
            resp.protocol.clear();
            resp.protocol.append("h3");
        }
    }
}

fn ingest_compression_dict_header(
    dict_cache: DictionaryCache&,
    origin_buf: const u8[:],
    curr_path:  const u8[:],
    now_sec:    i64,
    resp:       Response&,
) {
    let dict_hdr = header(resp, "Use-As-Dictionary");
    guard dict_hdr.len > 0 else { return; }
    let d_params, ok_p = parse_use_as_dictionary_header(dict_hdr);
    guard ok_p else { return; }
    let pat = if d_params.match_pattern.len > 0 {
        d_params.match_pattern[..]
    } else {
        curr_path
    };
    dictionary_cache_insert(
        dict_cache,
        origin_buf,
        pat,
        d_params.id[..],
        resp.body[..],
        d_params.ttl_sec,
        now_sec,
    );
}

fn ingest_transport_response_headers(
    session:     Session&,
    current_url: const core::Url&,
    is_https:    bool,
    origin_buf:  const u8[:],
    curr_path:   const u8[:],
    now_sec:     i64,
    resp:        Response&,
) {
    if wire::is_egress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_OUT_ALT_SVC) {
        let _ = stage_client_alt_svc(
            resp,
            current_url,
            is_https,
            origin_buf,
            curr_path,
            now_sec,
            session.altsvc,
            session.enable_altsvc,
            session.hsts,
            session.enable_hsts,
            session.dict_cache,
            session.enable_compression_dict,
        );
    }

    if wire::is_egress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_OUT_DECOMPRESS) {
        let _ = stage_client_decompress(resp, session.dict_cache);
    }
}

fn try_match_mock_route(
    session:     Session&,
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    has_h3:      bool,
    origin_buf:  const u8[:],
    curr_path:   const u8[:],
    now_sec:     i64,
    out_dns_err: RedirectError&,
    out_resp:    Response&,
) -> bool {
    let curr_href = href(current_url);
    let curr_method = ctx.current_method[..];
    let is_https = current_url.is_secure_scheme();

    for &route in session.mock_routes {
        let method_match = route.method.len == 0 || eq_ascii_fold(route.method[..], curr_method);
        let url_match = route.pattern_url[..] == curr_href || starts_with(curr_href, route.pattern_url[..]);
        guard method_match && url_match else { continue; }

        let dns_err = validate_mock_route_dns(route, session.ssrf_guard);
        if dns_err != RedirectError.None {
            out_dns_err = dns_err;
            out_resp = Response {
                status_code:   rfc::STATUS_FORBIDDEN,
                effective_url: copy(current_url.href),
                ..
            };
            return true;
        }

        let mock_resp = build_mock_response(route, current_url, ctx.headers);
        out_resp = copy(mock_resp);
        if route.status_code == rfc::STATUS_SWITCHING_PROTOCOLS {
            let sent_key = find_header(ctx.headers, "sec-websocket-key");
            if sent_key.len > 0 && out_resp.header("sec-websocket-accept").len == 0 {
                var accept_buf: u8[..64] = [];
                compute_websocket_accept(sent_key, accept_buf);
                out_resp.set_header("Sec-WebSocket-Accept", accept_buf[..]);
            }
        }

        resolve_mock_protocol_racing(session, route, is_https, origin_buf, has_h3, now_sec, out_resp);
        ingest_transport_response_headers(session, current_url, is_https, origin_buf, curr_path, now_sec, out_resp);
        return true;
    }
    return false;
}

// Resolves effective timeout with bounds clamping (1ms .. 600,000ms / 10min).
// Per-request timeout overrides session timeout when set > 0.
inline fn calc_effective_timeout_ms(session_timeout: i64, req_timeout: i64) -> u32 {
    let raw = if req_timeout > 0 { req_timeout } else { session_timeout };
    if raw <= 0 { return 1; }
    if raw > 600000 { return 600000; }
    return raw as u32;
}

fn dispatch_pooled_h1_hop(
    session:     Session&,
    conn_id:     i32,
    curr_method: const u8[:],
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    is_https:    bool,
    origin_buf:  const u8[:],
    curr_path:   const u8[:],
    now_sec:     i64,
    now_ns:      i64,
    resp:        Response&,
) -> bool {
    let c_idx = session.pool.find_connection_index(conn_id);
    guard c_idx >= 0 else { return false; }

    var hop_req = Request { .. };
    hop_req.method.clear();
    hop_req.method.append(curr_method);
    copy_headers(ctx.headers, hop_req.headers);
    hop_req.body.append(ctx.body[..]);

    let eff_timeout = calc_effective_timeout_ms(session.timeout_ms, ctx.timeout_ms);
    let ok_ex, keep_alive = execute_h1_exchange(
        session.pool.conns[c_idx],
        hop_req,
        current_url,
        resp,
        eff_timeout,
    );
    guard ok_ex else {
        session.pool.close_pooled_connection(conn_id);
        return false;
    }

    resp.effective_url = copy(current_url.href);
    copy_headers(ctx.headers, resp.sent_headers);
    ingest_transport_response_headers(
        session, current_url, is_https, origin_buf, curr_path, now_sec, resp,
    );
    if keep_alive {
        session.pool.release_connection(conn_id, now_ns);
    } else {
        session.pool.close_pooled_connection(conn_id);
    }
    return true;
}

fn resolve_hop_proxy_chain(session: const Session&) -> ProxyChain {
    if session.proxy_url.len == 0 {
        return new_direct_proxy_chain();
    }
    let p_url = core::new_url(session.proxy_url[..]);
    guard p_url.valid else { return new_direct_proxy_chain(); }
    let p_scheme = if scheme(p_url) == "https" {
        ProxyScheme.Https
    } else if scheme(p_url) == "socks5h" {
        ProxyScheme.Socks5h
    } else if scheme(p_url) == "socks5" {
        ProxyScheme.Socks5
    } else {
        ProxyScheme.Http
    };
    let raw_port = core::effective_port(p_url);
    let p_port: u16 = if raw_port > 0 {
        raw_port as u16
    } else if p_scheme == ProxyScheme.Socks5 || p_scheme == ProxyScheme.Socks5h {
        1080
    } else if p_scheme == ProxyScheme.Https {
        443
    } else {
        80
    };
    let ps = new_proxy_server(p_scheme, hostname(p_url), p_port);
    return new_single_proxy_chain(ps);
}

fn format_ipv4_u32(ip4: u32, out: u8[..64]&) {
    out.clear();
    let b0 = ((ip4 >> 24) & 0xFF) as u64;
    let b1 = ((ip4 >> 16) & 0xFF) as u64;
    let b2 = ((ip4 >> 8) & 0xFF) as u64;
    let b3 = (ip4 & 0xFF) as u64;
    core::format_u64_dec(b0, out);
    out.push('.');
    core::format_u64_dec(b1, out);
    out.push('.');
    core::format_u64_dec(b2, out);
    out.push('.');
    core::format_u64_dec(b3, out);
}

fn format_ipv6_bytes(ip6: const u8[16]&, out: u8[..64]&) {
    out.clear();
    let hex_chars: const u8[:] = "0123456789abcdef";
    for g in 8 {
        if g > 0 { out.push(':'); }
        let hi = ip6[g * 2];
        let lo = ip6[g * 2 + 1];
        out.push(hex_chars[((hi >> 4) & 0x0F) as i64]);
        out.push(hex_chars[(hi & 0x0F) as i64]);
        out.push(hex_chars[((lo >> 4) & 0x0F) as i64]);
        out.push(hex_chars[(lo & 0x0F) as i64]);
    }
}

fn collect_ipv4_dns_candidates(
    ssrf_guard: const SsrfGuardPolicy&,
    a_entry:    const DnsCacheEntry&,
    port_num:   u16,
    out_list:   DnsCandidate[..8]&,
) -> bool {
    var ip4_buf: u8[..64] = [];
    for ip4 in a_entry.ipv4_hints {
        format_ipv4_u32(ip4, ip4_buf);
        if ssrf_guard.enabled && ssrf_guard.deny_local_network {
            guard !is_private_or_reserved_ip(ip4_buf[..]) else { return false; }
        }
        if out_list.len < 8 {
            out_list.push(new_dns_candidate(AddressFamily.IPv4, ip4_buf[..], port_num, L4Protocol.Tcp, 40));
        }
    }
    return true;
}

fn collect_ipv6_dns_candidates(
    ssrf_guard: const SsrfGuardPolicy&,
    aaaa_entry: const DnsCacheEntry&,
    port_num:   u16,
    out_list:   DnsCandidate[..8]&,
) -> bool {
    var ip6_buf: u8[..64] = [];
    for &ip6 in aaaa_entry.ipv6_hints {
        format_ipv6_bytes(ip6, ip6_buf);
        if ssrf_guard.enabled && ssrf_guard.deny_local_network {
            guard !is_private_or_reserved_ip(ip6_buf[..]) else { return false; }
        }
        if out_list.len < 8 {
            out_list.push(new_dns_candidate(AddressFamily.IPv6, ip6_buf[..], port_num, L4Protocol.Tcp, 50));
        }
    }
    return true;
}

fn resolve_and_validate_live_host(
    session:        Session&,
    host_str:       const u8[:],
    port_num:       u16,
    now_sec:        i64,
    out_candidates: DnsCandidate[..32]&,
    out_ech_list:   u8[..512]&,
) -> Error {
    out_candidates.clear();
    out_ech_list.clear();
    let now_ms = now_sec * 1000;
    var task = new_dns_race_task(port_num);

    var a_entry = DnsCacheEntry { .. };
    let a_stat = session.dns_cache.dns_cache_lookup(host_str, rfc::DNS_QTYPE_A, now_sec, a_entry);
    if a_stat != DnsCacheStatus.Expired {
        guard collect_ipv4_dns_candidates(session.ssrf_guard, a_entry, port_num, task.ipv4_candidates) else {
            return make_error(rfc::STATUS_FORBIDDEN, "ssrf_guard", "SSRF: DNS rebinding to private IP blocked");
        }
        task.a_status = DnsQueryStatus.Success;
    }

    var aaaa_entry = DnsCacheEntry { .. };
    let aaaa_stat = session.dns_cache.dns_cache_lookup(host_str, rfc::DNS_QTYPE_AAAA, now_sec, aaaa_entry);
    if aaaa_stat != DnsCacheStatus.Expired {
        guard collect_ipv6_dns_candidates(session.ssrf_guard, aaaa_entry, port_num, task.ipv6_candidates) else {
            return make_error(rfc::STATUS_FORBIDDEN, "ssrf_guard", "SSRF: DNS rebinding to private IP blocked");
        }
        task.aaaa_status = DnsQueryStatus.Success;
    }

    if session.enable_ech || session.auto_ech_discovery {
        var https_entry = DnsCacheEntry { .. };
        let h_stat = session.dns_cache.dns_cache_lookup(host_str, rfc::DNS_QTYPE_HTTPS, now_sec, https_entry);
        if h_stat != DnsCacheStatus.Expired && https_entry.https_records.len > 0 {
            if https_entry.https_records[0].has_ech {
                out_ech_list.append(https_entry.https_records[0].ech_config_list[..]);
            }
        }
    }

    let _ = task.check_dns_resolution_delay_tick(now_ms + rfc::HE_RESOLUTION_DELAY_MS);
    interleave_candidates_he(task.ipv6_candidates[..], task.ipv4_candidates[..], out_candidates);
    if out_candidates.len == 0 {
        out_candidates.push(new_dns_candidate(AddressFamily.IPv4, host_str, port_num, L4Protocol.Tcp, 40));
    }
    return Error { .. };
}

fn dial_live_tcp_or_proxy(
    proxy_url:   const u8[:],
    proxy_chain: const ProxyChain&,
    host_str:    const u8[:],
    port_num:    u16,
    candidates:  const DnsCandidate[:],
    eff_timeout: u32,
    now_ms:      i64,
    out_ip:      u8[..64]&,
) -> i64, Error {
    out_ip.clear();
    if !proxy_chain.is_direct && proxy_chain.servers.len > 0 {
        let ps = proxy_chain.servers[0];
        let sock = native_tcp_connect(ps.host[..], ps.port, eff_timeout);
        guard sock > 0 else {
            return -1, make_error(rfc::STATUS_BAD_GATEWAY, "transport", "Proxy TCP connect failed");
        }
        let p_url = core::new_url(proxy_url);
        let p_user = core::username(p_url);
        let p_pass = core::password(p_url);
        if ps.scheme == ProxyScheme.Socks5 || ps.scheme == ProxyScheme.Socks5h {
            let use_ip = ps.scheme == ProxyScheme.Socks5 && candidates.len > 0;
            let t_host = if use_ip { candidates[0].ip[..] } else { host_str };
            let s_err = socks5_client_handshake(sock, ps.scheme, t_host, port_num, p_user, p_pass, eff_timeout);
            if s_err != Socks5Error.None {
                native_tcp_close(sock);
                return -1, make_error(rfc::STATUS_BAD_GATEWAY, "transport", "SOCKS5 handshake failed");
            }
        } else {
            var proxy_auth: u8[..256] = [];
            if p_user.len > 0 {
                var cred_raw: u8[..160] = [];
                cred_raw.append(p_user);
                cred_raw.push(':');
                cred_raw.append(p_pass);
                var cred_b64: u8[..224] = [];
                core::base64_encode(cred_raw[..], cred_b64);
                core::secure_zeroize_slice(cred_raw[..]);
                proxy_auth.append("Basic ");
                proxy_auth.append(cred_b64[..]);
            }
            let c_err = http_connect_client_handshake(
                sock, host_str, port_num, proxy_auth[..], "goose-wing/1.0", eff_timeout,
            );
            if c_err != ConnectTunnelError.None {
                native_tcp_close(sock);
                return -1, make_error(rfc::STATUS_BAD_GATEWAY, "transport", "HTTP CONNECT tunnel failed");
            }
        }
        out_ip.append(ps.host[..]);
        return sock, Error { .. };
    }
    var mgr = new_attempt_manager();
    mgr.start_attempt_race(candidates, now_ms);
    for &cand in candidates {
        let sock = native_tcp_connect(cand.ip[..], cand.port, eff_timeout);
        if sock > 0 {
            if mgr.attempts.len > 0 { let _ = mgr.bind_winner_attempt(mgr.attempts[0].attempt_id, false); }
            out_ip.append(cand.ip[..]);
            return sock, Error { .. };
        }
        let _ = mgr.tick_attempt_manager(now_ms + mgr.effective_cad_ms);
    }
    return -1, make_error(rfc::STATUS_BAD_GATEWAY, "transport", "TCP connect failed");
}

fn encode_h2_client_request<B>(
    curr_method:  const u8[:],
    current_url:  const core::Url&,
    is_https:     bool,
    ctx:          const RequestExecutionContext&,
    enc_dt:       internal::DynamicTable&,
    stream_id:    u32,
    send_preface: bool,
    out_wire:     B&,
) -> bool {
    out_wire.clear();
    let scheme_str: const u8[:] = if is_https { "https" } else { "http" };
    let auth_str = core::host(current_url);
    var path_buf: u8[..2048] = [];
    let p_str = core::pathname(current_url);
    if p_str.len > 0 { path_buf.append(p_str); } else { path_buf.push('/'); }
    let q_str = core::search(current_url);
    if q_str.len > 0 { path_buf.append(q_str); }
    guard path_buf.len <= 1024 else { return false; }

    var pseudo = internal::H2PseudoHeaders {
        has_method:    true,
        has_scheme:    true,
        has_authority: true,
        has_path:      true,
        ..
    };
    pseudo.method.append(curr_method);
    pseudo.scheme.append(scheme_str);
    pseudo.authority.append(auth_str);
    pseudo.path.append(path_buf[..]);
    let proto_hdr = find_header(ctx.headers, ":protocol");
    if proto_hdr.len > 0 {
        pseudo.has_protocol = true;
        pseudo.protocol.append(proto_hdr);
    }

    if send_preface {
        guard out_wire.try_append(rfc::H2_CLIENT_PREFACE) else { return false; }
        let empty_settings: wire::WireSetting[..1] = [];
        guard wire::encode_settings_frame(empty_settings[..], out_wire) else { return false; }
    }

    let has_body = ctx.body.len > 0;
    guard wire::encode_h2_headers_frame_from_map(
        enc_dt,
        stream_id,
        pseudo,
        ctx.headers,
        !has_body,
        out_wire,
        16384,
    ) else { return false; }

    var rem = ctx.body[..];
    while rem.len > 0 {
        let chunk_len = min(rem.len, rfc::H2_DEFAULT_MAX_FRAME_SIZE as i64);
        let is_last = chunk_len >= rem.len;
        guard wire::encode_data_frame(stream_id, rem[..chunk_len], is_last, out_wire) else {
            return false;
        }
        rem = rem[chunk_len..];
    }
    return true;
}

fn process_h2_response_frame<B>(
    hdr:       const internal::FrameHeader&,
    payload:   const u8[:],
    stream_id: u32,
    is_head:   bool,
    dec_dt:    internal::DynamicTable&,
    resp:      Response&,
    got_hdrs:  bool&,
    out_ctrl:  B&,
) -> bool, bool {
    if hdr.frame_type == rfc::H2_FRAME_SETTINGS && hdr.stream_id == 0 {
        if (hdr.flags & rfc::H2_FLAG_ACK) == 0 {
            let ack_hdr = wire::WireFrameHeader {
                length: 0, frame_type: rfc::H2_FRAME_SETTINGS, flags: rfc::H2_FLAG_ACK, stream_id: 0,
            };
            let _ = wire::encode_frame_header(ack_hdr, out_ctrl);
        }
        return true, false;
    }
    if hdr.frame_type == rfc::H2_FRAME_PING && hdr.stream_id == 0 {
        if (hdr.flags & rfc::H2_FLAG_ACK) == 0 && payload.len == 8 {
            var ping_data: u8[8] = [0; 8];
            for i in 8 { ping_data[i] = payload[i]; }
            let _ = wire::encode_ping_frame(ping_data, true, out_ctrl);
        }
        return true, false;
    }
    if hdr.frame_type == rfc::H2_FRAME_RST_STREAM && hdr.stream_id == stream_id { return false, false; }
    if hdr.frame_type == rfc::H2_FRAME_GOAWAY { return false, false; }
    if hdr.frame_type == rfc::H2_FRAME_WINDOW_UPDATE { return true, false; }
    if hdr.frame_type == rfc::H2_FRAME_HEADERS && hdr.stream_id == stream_id {
        let frag, f_err = internal::extract_headers_frame_payload(hdr, payload);
        guard f_err == rfc::H2_ERR_NO_ERROR else { return false, false; }
        var pseudo = internal::H2PseudoHeaders { .. };
        if !got_hdrs {
            let d_err = wire::decode_hpack_to_map(dec_dt, frag, pseudo, resp.headers, 8192, false);
            guard d_err == rfc::H2_ERR_NO_ERROR else { return false, false; }
            if pseudo.status > 0 { resp.status_code = pseudo.status; }
            for &e in resp.headers.entries {
                update_response_presence(resp, entry_name(resp.headers, e));
            }
            if pseudo.status < 100 || pseudo.status >= 200 { got_hdrs = true; }
        } else {
            let d_err = wire::decode_hpack_to_map(dec_dt, frag, pseudo, resp.trailers, 8192, false);
            guard d_err == rfc::H2_ERR_NO_ERROR else { return false, false; }
        }
        let end_stream = (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0 ||
            (got_hdrs && (is_head || rfc::is_empty_body_status(resp.status_code)));
        return true, end_stream;
    }
    if hdr.frame_type == rfc::H2_FRAME_DATA && hdr.stream_id == stream_id {
        let d_slice, d_err = internal::extract_padded_frame_payload(hdr, payload);
        guard d_err == rfc::H2_ERR_NO_ERROR else { return false, false; }
        resp.body.append(d_slice);
        if d_slice.len > 0 {
            let inc = d_slice.len as u32;
            let _ = wire::encode_window_update_frame(0, inc, out_ctrl);
            let _ = wire::encode_window_update_frame(stream_id, inc, out_ctrl);
        }
        return true, (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0;
    }
    return true, false;
}

fn shift_consumed_rx_bytes<B>(rx_accum: B&, consumed: i64) {
    guard consumed > 0 && consumed <= rx_accum.len else { return; }
    let tail = rx_accum[consumed..];
    let rem = tail.len;
    for b, i in tail {
        rx_accum[i] = b;
    }
    while rx_accum.len > rem {
        rx_accum.pop();
    }
}

fn drain_h2_response_frames<B1, B2>(
    rx_accum:  B1&,
    stream_id: u32,
    is_head:   bool,
    dec_dt:    internal::DynamicTable&,
    resp:      Response&,
    got_hdrs:  bool&,
    out_ctrl:  B2&,
) -> bool, bool {
    var consumed: i64 = 0;
    while rx_accum.len - consumed >= 9 {
        let hdr, h_err = internal::parse_frame_header(rx_accum[consumed..], 16384);
        guard h_err == rfc::H2_ERR_NO_ERROR else { return false, false; }
        let frame_total = 9 + (hdr.length as i64);
        guard rx_accum.len - consumed >= frame_total else { break; }
        let payload = rx_accum[consumed + 9..consumed + frame_total];
        consumed += frame_total;
        let ok_f, done = process_h2_response_frame(
            hdr, payload, stream_id, is_head, dec_dt, resp, got_hdrs, out_ctrl,
        );
        guard ok_f else {
            shift_consumed_rx_bytes(rx_accum, consumed);
            return false, false;
        }
        if done {
            shift_consumed_rx_bytes(rx_accum, consumed);
            return true, true;
        }
    }
    shift_consumed_rx_bytes(rx_accum, consumed);
    return true, false;
}

fn recv_h2_response_loop(
    tp:          Transport&,
    stream_id:   u32,
    is_head:     bool,
    dec_dt:      internal::DynamicTable&,
    eff_timeout: u32,
    resp:        Response&,
) -> bool {
    var rx_accum: u8[..65536] = [];
    var chunk:    u8[4096]    = [0; 4096];
    var got_hdrs = false;
    var is_done = false;
    for step in 4096 {
        let n = tp.recv_slice(chunk[..], eff_timeout);
        if n > 0 {
            guard rx_accum.try_append(chunk[..n]) else { return false; }
        }
        var ctrl_out: u8[..256] = [];
        let ok_f, done = drain_h2_response_frames(
            rx_accum,
            stream_id,
            is_head,
            dec_dt,
            resp,
            got_hdrs,
            ctrl_out,
        );
        guard ok_f else { return false; }
        if ctrl_out.len > 0 {
            let _ = send_all(tp, ctrl_out[..]);
        }
        if done {
            is_done = true;
            break;
        }
        if n <= 0 { break; }
    }
    return got_hdrs && is_done;
}

fn dispatch_pooled_h2_hop(
    session:     Session&,
    conn_id:     i32,
    curr_method: const u8[:],
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    is_https:    bool,
    origin_buf:  const u8[:],
    curr_path:   const u8[:],
    now_sec:     i64,
    now_ns:      i64,
    resp:        Response&,
) -> bool {
    let c_idx = session.pool.find_connection_index(conn_id);
    guard c_idx >= 0 else { return false; }
    let stream_id = session.pool.conns[c_idx].next_h2_stream_id;
    let send_preface = !session.pool.conns[c_idx].h2_preface_sent;
    var wire_out: u8[..65536] = [];
    guard encode_h2_client_request(
        curr_method,
        current_url,
        is_https,
        ctx,
        session.pool.conns[c_idx].hpack_enc,
        stream_id,
        send_preface,
        wire_out,
    ) else {
        session.pool.close_pooled_connection(conn_id);
        return false;
    }
    guard send_all(session.pool.conns[c_idx].transport, wire_out[..]) else {
        session.pool.close_pooled_connection(conn_id);
        return false;
    }
    session.pool.conns[c_idx].h2_preface_sent = true;
    session.pool.conns[c_idx].next_h2_stream_id += 2;
    reset_response(resp);
    resp.protocol.clear();
    resp.protocol.append("HTTP/2");
    let eff_timeout = calc_effective_timeout_ms(session.timeout_ms, ctx.timeout_ms);
    let is_head = curr_method == "HEAD";
    let got_hdrs = recv_h2_response_loop(
        session.pool.conns[c_idx].transport,
        stream_id,
        is_head,
        session.pool.conns[c_idx].hpack_dec,
        eff_timeout,
        resp,
    );
    guard got_hdrs else { session.pool.close_pooled_connection(conn_id); return false; }
    resp.effective_url = copy(current_url.href);
    copy_headers(ctx.headers, resp.sent_headers);
    ingest_transport_response_headers(session, current_url, is_https, origin_buf, curr_path, now_sec, resp);
    session.pool.release_connection(conn_id, now_ns);
    return true;
}

fn encode_h3_client_request<B>(
    h3_conn:     internal::H3Connection&,
    sid:         u64,
    ctx:         const RequestExecutionContext&,
    current_url: const core::Url&,
    out_wire:    B&,
) -> bool {
    out_wire.clear();
    var path_buf: u8[..2048] = [];
    let p_str = core::pathname(current_url);
    if p_str.len > 0 { path_buf.append(p_str); } else { path_buf.push('/'); }
    let q_str = core::search(current_url);
    if q_str.len > 0 { path_buf.append(q_str); }
    guard path_buf.len <= 1024 else { return false; }

    let has_body = ctx.body.len > 0;
    guard internal::send_request_headers(
        h3_conn, sid, ctx.current_method[..], "https", core::host(current_url),
        path_buf[..], ctx.headers, !has_body, out_wire,
    ) else { return false; }

    if has_body {
        guard internal::send_request_data(h3_conn, sid, ctx.body[..], true, out_wire) else {
            return false;
        }
    }
    return true;
}

fn execute_live_h3_hop(
    session:     Session&,
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    origin_buf:  const u8[:],
    h3_ep:       const AltSvcEndpoint&,
    now_sec:     i64,
    resp:        Response&,
) -> bool {
    let target_host = if h3_ep.host.len > 0 { h3_ep.host[..] } else { core::hostname(current_url) };
    let target_port = if h3_ep.port > 0 { h3_ep.port } else { core::effective_port(current_url) as u16 };
    if session.ssrf_guard.enabled && session.ssrf_guard.deny_local_network &&
        (is_private_or_reserved_ip(target_host) || is_dangerous_service_port(target_port)) {
        return false;
    }
    let udp_fd = udp_bind("0.0.0.0", 0);
    guard udp_fd > 0 else { return false; }

    let h3_settings = H3Settings { .. };
    var h3_conn = internal::new_h3_client_connection(h3_settings);
    let sid, ok_s = internal::open_request_stream(h3_conn);
    guard ok_s else {
        tcp_close(udp_fd);
        return false;
    }
    var req_wire: u8[..4096] = [];
    guard encode_h3_client_request(h3_conn, sid, ctx, current_url, req_wire) else {
        tcp_close(udp_fd);
        return false;
    }
    let curr_path = core::pathname(current_url);
    let sent = native_udp_sendto(udp_fd, req_wire[..], target_host, target_port);
    if sent <= 0 {
        tcp_close(udp_fd);
        return false;
    }
    var rx_buf:    u8[1472] = [0; 1472];
    var peer_ip4:  u32      = 0;
    var peer_port: u16      = 0;
    let eff_timeout = calc_effective_timeout_ms(session.timeout_ms, ctx.timeout_ms);
    let recvd = native_udp_recvfrom(udp_fd, rx_buf[..], min(eff_timeout, 250), peer_ip4, peer_port);
    tcp_close(udp_fd);
    guard recvd > 0 else { return false; }

    let h_err = internal::handle_stream_data(h3_conn, sid, true, rx_buf[..recvd], true);
    guard h_err == rfc::H3_ERR_NO_ERROR else { return false; }
    let sc, ok_sc = internal::get_status_code(h3_conn, sid);
    guard ok_sc else { return false; }

    reset_response(resp);
    resp.status_code = sc;
    resp.protocol.clear();
    resp.protocol.append("HTTP/3");
    let _ = internal::copy_stream_headers(h3_conn, sid, resp.headers);
    for &e in resp.headers.entries {
        update_response_presence(resp, entry_name(resp.headers, e));
    }
    let _ = internal::copy_stream_trailers(h3_conn, sid, resp.trailers);
    let body_slice, ok_b = internal::get_response_body(h3_conn, sid);
    if ok_b { resp.body.append(body_slice); }
    resp.effective_url = copy(current_url.href);
    copy_headers(ctx.headers, resp.sent_headers);
    ingest_transport_response_headers(session, current_url, true, origin_buf, curr_path, now_sec, resp);
    return true;
}

// Opens or reuses a pooled TCP/TLS/HTTP2/HTTP3 connection and executes one live network hop.
// Returns an ok Error when `resp` holds the exchange response; connect and
// exchange failures surface as explicit transport errors, never fake successes.
fn execute_live_network_hop(
    session:     Session&,
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    is_https:    bool,
    origin_buf:  const u8[:],
    has_h3:      bool,
    h3_ep:       const AltSvcEndpoint&,
    resp:        Response&,
) -> Error {
    let now_ns = session.virtual_clock_us * 1000;
    let now_sec = session.virtual_clock_us / 1000000;
    let now_ms = session.virtual_clock_us / 1000;
    let host_str = core::hostname(current_url);
    if session.ssrf_guard.enabled {
        if is_private_or_reserved_ip(host_str) {
            return make_error(rfc::STATUS_FORBIDDEN, "ssrf_guard", "SSRF: private IP blocked");
        }
    }

    let port_num = core::effective_port(current_url) as u16;
    var dns_candidates: DnsCandidate[..32] = [];
    var ech_list:       u8[..512]          = [];
    let dns_err = resolve_and_validate_live_host(session, host_str, port_num, now_sec, dns_candidates, ech_list);
    if !ok(dns_err) {
        return dns_err;
    }

    let proxy_chain = resolve_hop_proxy_chain(session);
    if !proxy_chain.is_direct {
        sanitize_tunnel_headers_for_origin(ctx.headers);
    }
    if has_h3 && is_https && proxy_chain.is_direct && session.enable_protocol_racing {
        if execute_live_h3_hop(session, ctx, current_url, origin_buf, h3_ep, now_sec, resp) {
            session.altsvc.record_success(origin_buf);
            return Error { .. };
        }
        session.altsvc.record_failure(origin_buf, now_sec);
    }

    let site_site = if ctx.top_frame_origin.host.len > 0 {
        ctx.top_frame_origin.host[..]
    } else if !ctx.site_for_cookies.is_null && ctx.site_for_cookies.registrable_domain.len > 0 {
        ctx.site_for_cookies.registrable_domain[..]
    } else {
        host_str
    };

    let pool_scheme = if is_https { PoolScheme.Https } else { PoolScheme.Http };
    let pool_key = new_pool_key(
        pool_scheme,
        host_str,
        port_num,
        proxy_chain,
        new_network_anonymization_key(site_site, ctx.had_cross_site_hop),
        TlsAndDnsPolicy { .. },
    );

    let first_ip = if dns_candidates.len > 0 { dns_candidates[0].ip[..] } else { "" };
    var conn_id, has_pooled = session.pool.acquire_pooled_connection(pool_key, first_ip, now_ns);
    if !has_pooled {
        let eff_timeout = calc_effective_timeout_ms(session.timeout_ms, ctx.timeout_ms);
        var dialed_ip: u8[..64] = [];
        let sock, dial_err = dial_live_tcp_or_proxy(
            session.proxy_url[..], proxy_chain, host_str, port_num, dns_candidates[..], eff_timeout, now_ms, dialed_ip,
        );
        if !ok(dial_err) {
            return dial_err;
        }
        var t = Transport.Disconnected;
        var neg_proto = NegotiatedProtocol.Http11;
        if is_https {
            let host_is_hsts = session.enable_hsts && session.hsts.is_hsts_host(host_str, now_sec);
            let effective_insecure_skip = session.insecure_skip_verify && !host_is_hsts;

            var tls_cfg = TlsClientHandshakeConfig { .. };
            tls_cfg.server_name.append(host_str);
            tls_cfg.alpn.append("h2,http/1.1");
            tls_cfg.trust_store = session.trust_store;
            tls_cfg.insecure_skip_verify = effective_insecure_skip;
            tls_cfg.virtual_clock_sec = if session.virtual_clock_us == 1700000000000000 { 0 } else { now_sec };
            if ech_list.len > 0 {
                tls_cfg.ech_config_list.append(ech_list[..]);
            }

            let slot_idx, ok_tls = tls_client_handshake(sock, tls_cfg);
            guard ok_tls else {
                native_tcp_close(sock);
                return make_error(rfc::STATUS_BAD_GATEWAY, "tls", "TLS 1.3 handshake failed");
            }
            if tls_session_alpn(slot_idx) == "h2" {
                neg_proto = NegotiatedProtocol.Http2;
            }
            t = Transport.Tls {
                fd:            sock,
                record_seq_rx: 0,
                record_seq_tx: 0,
                cipher_slot:   slot_idx,
            };
        } else {
            if session.http2_prior_knowledge {
                neg_proto = NegotiatedProtocol.Http2;
            }
            t = Transport.Tcp { fd: sock };
        }
        let max_streams: i32 = if neg_proto == NegotiatedProtocol.Http2 { 100 } else { 1 };
        conn_id = register_connection(session.pool, pool_key, neg_proto, t, dialed_ip[..], max_streams, now_ns);
        guard conn_id > 0 else {
            t.close();
            return make_error(rfc::STATUS_BAD_GATEWAY, "transport", "connection pool registration failed");
        }
        has_pooled = true;
    }

    let curr_path = core::pathname(current_url);
    let c_idx = session.pool.find_connection_index(conn_id);
    if c_idx >= 0 && session.pool.conns[c_idx].protocol == NegotiatedProtocol.Http2 {
        let ok_h2 = dispatch_pooled_h2_hop(
            session, conn_id, ctx.current_method[..], ctx, current_url, is_https,
            origin_buf, curr_path, now_sec, now_ns, resp,
        );
        guard ok_h2 else {
            return make_error(rfc::STATUS_BAD_GATEWAY, "transport", "HTTP/2 exchange failed");
        }
        return Error { .. };
    }

    let ok_hop = dispatch_pooled_h1_hop(
        session, conn_id, ctx.current_method[..], ctx, current_url, is_https,
        origin_buf, curr_path, now_sec, now_ns, resp,
    );
    guard ok_hop else {
        return make_error(rfc::STATUS_BAD_GATEWAY, "transport", "HTTP/1.1 exchange failed");
    }
    return Error { .. };
}

// Executes a mock response hop or a live pooled HTTP/1.1 hop, verifying IP
// addresses against SSRF policies. Returns an explicit Error when no hop could
// be executed; never synthesizes a success response.
fn execute_mock_or_echo_hop(
    session:     Session&,
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
) -> Response, Error {
    var origin_buf: u8[..128] = [];
    format_url_origin(current_url, origin_buf);
    let now_sec = session.virtual_clock_us / 1000000;
    let is_https = current_url.is_secure_scheme();

    var candidate_h3_ep = AltSvcEndpoint { .. };
    var has_h3 = false;
    if session.enable_altsvc && is_https {
        has_h3 = lookup_h3(session.altsvc, origin_buf[..], now_sec, candidate_h3_ep);
    }

    let curr_path = core::pathname(current_url);
    if wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_DICT_NEGOTIATE) {
        let _ = stage_client_dict_negotiate(
            ctx.headers,
            session.dict_cache,
            session.enable_compression_dict,
            origin_buf[..],
            curr_path,
            is_https,
            now_sec,
        );
    } else {
        remove_header_by_name(ctx.headers, "Available-Dictionary");
    }

    var resp = Response { .. };
    var dns_rebinding_err = RedirectError.None;
    let matched = try_match_mock_route(
        session,
        ctx,
        current_url,
        has_h3,
        origin_buf[..],
        curr_path,
        now_sec,
        dns_rebinding_err,
        resp,
    );
    if matched {
        if dns_rebinding_err != RedirectError.None {
            return resp, make_error(rfc::STATUS_FORBIDDEN, "ssrf_guard", redirect_error_to_string(dns_rebinding_err));
        }
        return resp, Error { .. };
    }

    // Live pooled network transaction when no mock routes are registered
    if session.mock_routes.len == 0 {
        let live_err = execute_live_network_hop(
            session, ctx, current_url, is_https, origin_buf[..], has_h3, candidate_h3_ep, resp,
        );
        return resp, live_err;
    }

    // Mock mode is active (routes registered) but none matched this request
    return resp, make_error(rfc::STATUS_BAD_GATEWAY, "mock", "no matching mock route for request");
}

fn compute_401_auth_header(
    session:         Client&,
    ctx:             RequestExecutionContext&,
    current_url:     const core::Url&,
    www_auth:        const u8[:],
    auth_header_val: u8[..4096]&,
) -> bool {
    if starts_with_fold(www_auth, "Digest") {
        let chal, ok_c = parse_digest_challenge(www_auth);
        guard ok_c else { return false; }
        let uri_path = core::pathname(current_url);
        let uri_search = core::search(current_url);
        var uri_target: u8[..2048] = [];
        if uri_path.len > 0 {
            uri_target.append(uri_path);
        } else {
            uri_target.push('/');
        }
        if uri_search.len > 0 {
            uri_target.append(uri_search);
        }
        var c_creds = DigestCredentials { .. };
        c_creds.username.append(session.creds.username[..]);
        c_creds.password.append(session.creds.password[..]);

        let ok_d = compute_digest_response(
            chal,
            c_creds,
            ctx.current_method[..],
            uri_target[..],
            session.creds.nonce_counter,
            session.creds.cnonce[..],
            ctx.body[..],
            auth_header_val,
        );
        core::secure_zeroize_slice(c_creds.password[..]);
        guard ok_d else { return false; }
        session.creds.nonce_counter += 1;
        return true;
    }
    if starts_with_fold(www_auth, "Basic") {
        // RFC 7617 §2: username MUST NOT contain colon
        guard core::index_of_byte(session.creds.username[..], ':') < 0 else { return false; }
        var user_pass: u8[..140] = [];
        user_pass.append(session.creds.username[..]);
        user_pass.push(':');
        user_pass.append(session.creds.password[..]);
        var b64_user_pass: u8[..200] = [];
        core::base64_encode(user_pass[..], b64_user_pass);
        core::secure_zeroize_slice(user_pass[..]);
        auth_header_val.append("Basic ");
        auth_header_val.append(b64_user_pass[..]);
        return true;
    }
    return false;
}

fn find_auth_header_from_response(
    session:         Client&,
    ctx:             RequestExecutionContext&,
    current_url:     const core::Url&,
    resp:            const Response&,
    auth_header_val: u8[..4096]&,
) -> bool {
    // Scan all WWW-Authenticate headers, prioritizing Digest over Basic
    for &e in resp.headers.entries {
        let h_name = entry_name(resp.headers, e);
        let h_val = entry_value(resp.headers, e);
        if eq_ascii_fold(h_name, "WWW-Authenticate") && starts_with_fold(h_val, "Digest") {
            if compute_401_auth_header(session, ctx, current_url, h_val, auth_header_val) {
                return true;
            }
        }
    }
    for &e in resp.headers.entries {
        let h_name = entry_name(resp.headers, e);
        let h_val = entry_value(resp.headers, e);
        if eq_ascii_fold(h_name, "WWW-Authenticate") && starts_with_fold(h_val, "Basic") {
            if compute_401_auth_header(session, ctx, current_url, h_val, auth_header_val) {
                return true;
            }
        }
    }
    return false;
}

inline fn prepare_auth_retry_hop(
    session:       Client&,
    ctx:           RequestExecutionContext&,
    current_url:   const core::Url&,
    samesite_eval: const SameSiteCookieContext&,
    safe_method:   bool,
    resp:          const Response&,
    auth_val:      const u8[:],
) {
    ctx.auth_retried = true;
    if ctx.body.len > 0 {
        ctx.body.clear();
        ctx.body.append(ctx.rewind_buf[..]);
    }
    if session.enable_cookie_jar {
        ingest_hop_response_cookies(session, ctx, current_url, samesite_eval, resp.headers);
        prepare_hop_cookie_header(session, ctx, current_url, samesite_eval, safe_method);
    }
    set_header(ctx.headers, "Authorization", auth_val, true);
}

fn execute_request_inner(session: Client&, req: const Request&) -> Response, Error {
    var noop = wire::NoOpStage {};
    return execute_client_pipeline_with_stage(session, req, noop);
}

inline fn should_retry_request(
    status_code: i32,
    err:         Error,
    method:      const u8[:],
    req:         const Request&,
    attempts:    i32,
    has_retry:   bool,
    max_retries: i32,
    retry_5xx:   bool,
) -> bool {
    let is_idem = rfc::is_idempotent_method(method) || has_idempotency_key(req);
    let can_retry = is_idem && (req.body.len == 0 || req.rewindable);
    guard can_retry else { return false; }

    if status_code == rfc::STATUS_TOO_EARLY {
        return attempts < 3;
    }
    guard has_retry && attempts < max_retries else { return false; }
    let retryable = !ok(err) || (retry_5xx && status_code >= rfc::STATUS_INTERNAL_SERVER_ERROR && status_code <= 599);
    return retryable;
}

fn execute_request(session: Client&, req: const Request&) -> Response, Error {
    let start_us = session.virtual_clock_us;

    var max_retries: i32  = 0;
    var retry_5xx:   bool = false;
    let has_retry = find_retry_policy(session.pipeline, max_retries, retry_5xx);

    var attempts: i32 = 0;
    loop {
        // Phase -1: Application Interceptors (Request Hook) per attempt
        var active_req = copy(req);
        apply_app_interceptors_request(session.pipeline, active_req, session.virtual_clock_us);

        let resp, err = execute_request_inner(session, active_req);

        let retry = should_retry_request(
            resp.status_code, err, active_req.method[..], active_req,
            attempts, has_retry, max_retries, retry_5xx,
        );
        if retry {
            attempts += 1;
            continue;
        }

        // Phase 6: Application Interceptors (Response Hook)
        var final_resp = resp;
        let total_dur_us = session.virtual_clock_us - start_us;
        apply_app_interceptors_response(session.pipeline, active_req, final_resp, err, total_dur_us);
        return copy(final_resp), err;
    }
    return Response { .. }, make_error(rfc::STATUS_INTERNAL_SERVER_ERROR, "client", "request execution failed");
}
