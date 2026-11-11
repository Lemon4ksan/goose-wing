// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Execution pipeline, redirect state machine, and hop orchestration (Chromium net::URLRequest 6-phase pipeline).
namespace wing;

import std;
import core from "../..";
import cookie.constants;
import cookie.canonical;
import cookie.policy;
import cookie.engine;
import client.profile;
import client.request;
import client.response;
import client.redirect;
import client.interceptor;
import client.telemetry;
import client.replay_guard;
import http.headers;
import http.cache.cache_control;
import http.cache.freshness;
import http.cache.validators;
import http.cache.engine;
import http.altsvc;
import http.compression_dict;
import http.hsts;
import auth.digest;
import security.cors;
import security.cross_origin_isolation;
import security.privacypass;
import realtime.websocket;
import client.session.ssrf;
import client.session.mock;
import client.client;
import client.session.cookie_bridge;
import client.session.h1_exchange;
import net.pool;
import net.isolation;
import net.proxy;
import dns.cache;
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

inline fn append_single_query_param(
    query_item: const QueryItem&,
    sep:        u8,
    out:        u8[..2048]&,
) -> bool {
    guard out.try_push(sep) else { return false; }
    guard core::append_query_component(query_item.key[..], out) else { return false; }
    guard out.try_push('=') else { return false; }
    return core::append_query_component(query_item.value[..], out);
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
        let _ = hash_buf.try_set(out[hash_pos..]);
        out.resize(hash_pos);
    }

    for &query_item, param_idx in query_params {
        let sep: u8 = if param_idx == 0 && !has_query_mark { '?' } else { '&' };
        guard append_single_query_param(query_item, sep, out) else { break; }
    }

    if hash_buf.len > 0 {
        let _ = out.try_append(hash_buf[..]);
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
        let eff_url = parsed_base.resolve_endpoint(req_url);
        let _ = out.try_append(eff_url.href[..]);
    } else if req_url.starts_with_fold("http://") || req_url.starts_with_fold("https://") {
        let _ = out.try_append(req_url);
    } else {
        let _ = out.try_append(base_url);
        if base_url.len > 0 && base_url[base_url.len - 1] != '/' && (req_url.len == 0 || req_url[0] != '/') {
            let _ = out.try_push('/');
        }
        let _ = out.try_append(req_url);
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
    if session.https_only && current_url.scheme() != "https" {
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
    let _ = resp.final_method.try_set(ctx.current_method[..]);
    resp.url_chain.clear();
    for &hop_u in ctx.url_chain {
        var u_str: u8[..256] = [];
        let h = hop_u.href[..];
        let n = min(h.len, u_str.cap);
        let _ = u_str.try_set(h[..n]);
        guard resp.url_chain.try_push(u_str) else { break; }
    }
}

fn apply_redirect_transition(
    session:       const Session&,
    ctx:           RequestExecutionContext&,
    redirect_info: const RedirectInfo&,
) -> Error {
    ctx.had_cross_site_hop = ctx.had_cross_site_hop || redirect_info.is_cross_site_tainted;
    if ctx.cors_mode && redirect_info.is_cross_origin && ctx.url_chain.len > 0 {
        let prev_idx = core::sub_sat_i64(ctx.url_chain.len, 1);
        let prev_orig = core::origin_from_url(ctx.url_chain[prev_idx]);
        if !ctx.has_initiator || !core::is_same_origin(ctx.initiator, prev_orig) {
            ctx.tainted_origin = true;
        }
    }
    if ctx.is_main_frame && ctx.first_party_policy == FirstPartyURLPolicy.UPDATE_FIRST_PARTY_URL_ON_REDIRECT {
        ctx.top_frame_origin = core::origin_from_url(redirect_info.new_url);
    }
    ctx.site_for_cookies = redirect_info.new_site_for_cookies;
    ctx.auth_retried = false;
    let _ = ctx.current_method.try_set(redirect_info.new_method[..]);
    let _ = ctx.current_referrer.try_set(redirect_info.new_referrer[..]);
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

    let is_trusted = is_trusted_location_host(session, redirect_info.new_url.hostname());
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
        let _ = ctx.current_referrer.try_set(req_ref);
    }

    ctx.body.append(req.body[..]);
    if req.rewind_buf.len > 0 {
        let _ = ctx.rewind_buf.try_set(req.rewind_buf[..]);
    } else if req.rewindable && req.body.len <= 4096 {
        let _ = ctx.rewind_buf.try_set(req.body[..]);
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

    if ctx.top_frame_origin.host.len == 0 {
        ctx.top_frame_origin = core::origin_from_url(parsed_initial);
    }

    if req.has_site_for_cookies {
        ctx.site_for_cookies = copy(req.site_for_cookies);
    } else {
        ctx.site_for_cookies = site_for_cookies_from_parsed_url(parsed_initial);
    }

    merge_session_and_request_headers(ctx.headers, session.default_headers, req.headers, session.profile);
    sanitize_initial_request_referrer(session, ctx, parsed_initial);
    let _ = ctx.url_chain.try_push(parsed_initial);
    return ctx;
}

// Sanitizes the Hop-0 request `Referer` header and `ctx.current_referrer` according to `ctx.current_referrer_policy`.
//
// Example:
//   ctx.current_referrer = "https://a.example/secret?k=1", parsed_initial = "https://b.example/api", policy = StrictOriginWhenCrossOrigin
//   sets ctx.current_referrer = "https://a.example/" and Referer header = "https://a.example/"
fn sanitize_initial_request_referrer(
    session:        const Session&,
    ctx:            RequestExecutionContext&,
    parsed_initial: const core::Url&,
) {
    guard ctx.current_referrer.len > 0 else { return; }
    let parsed_ref = core::new_url(ctx.current_referrer[..]);
    guard parsed_ref.valid else { return; }
    let ref_same = parsed_ref.is_same_origin_url(parsed_initial);
    let ref_down = (parsed_ref.scheme() == "https" && parsed_initial.scheme() == "http");
    var sanitized_ref: u8[..2048] = [];
    compute_new_referrer(
        parsed_ref,
        parsed_initial,
        ctx.current_referrer_policy,
        RedirectReferrerOptions {
            is_cross_origin: !ref_same || ref_down,
            is_downgrade:    ref_down,
        },
        sanitized_ref,
    );
    let _ = ctx.current_referrer.try_set(sanitized_ref[..]);
    if session.enable_referer && sanitized_ref.len > 0 {
        set_header(ctx.headers, "Referer", sanitized_ref[..]);
    } else {
        remove_header_by_name(ctx.headers, "Referer");
    }
}

// RFC 9110 Section 15.4: Redirection 3xx - Checks whether response headers contain conflicting Location fields.
fn has_conflicting_location_headers(headers: const HeaderMap&, loc_hdr: const u8[:]) -> bool {
    let expected_loc = loc_hdr.trim_lws();
    for &e in headers.entries {
        guard entry_name(headers, e).eq_ascii_fold("location") else { continue; }
        if entry_value(headers, e).trim_lws() != expected_loc {
            return true;
        }
    }
    return false;
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
    if ctx.redirect_count >= ctx.max_redirects || ctx.url_chain.len >= ctx.url_chain.cap {
        return false, make_error(rfc::STATUS_BAD_REQUEST, "redirect", "maximum redirect hops exceeded");
    }
    if has_conflicting_location_headers(resp.headers, loc_hdr) {
        return false, make_error(
            rfc::STATUS_BAD_GATEWAY, "redirect", redirect_error_to_string(RedirectError.MultipleLocationHeaders),
        );
    }

    // RFC 6797 Section 8.3: URI Loading and Port Mapping - Upgrade http:// redirect target for known HSTS hosts.
    var upgraded_loc_buf: u8[..2048] = [];
    var hsts_upgraded = false;
    let hsts_stage_on = wire::is_ingress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_IN_URL_HSTS);
    if session.enable_hsts && hsts_stage_on && loc_hdr.len > 0 {
        let prelim_target, prelim_err = core::parse_url_with_base(loc_hdr.trim_lws(), current_url);
        if prelim_err == core::UrlParseError.None && prelim_target.valid && !prelim_target.is_secure_scheme() {
            let now_sec = div_euclid(session.virtual_clock_us, 1000000);
            hsts_upgraded = hsts_upgrade_url(session.hsts, prelim_target.href[..], now_sec, upgraded_loc_buf);
        }
    }
    let eff_loc = if hsts_upgraded { upgraded_loc_buf[..] } else { loc_hdr };

    let ref_policy_hdr = header(resp, "Referrer-Policy");
    var redirect_info = compute_redirect_info(
        resp.status_code,
        ctx.current_method[..],
        current_url,
        eff_loc,
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
    redirect_info.insecure_scheme_was_upgraded = hsts_upgraded;

    guard redirect_info.error == RedirectError.None else {
        return false, make_error(rfc::STATUS_BAD_REQUEST, "redirect", redirect_error_to_string(redirect_info.error));
    }

    let redirect_err = apply_redirect_transition(session, ctx, redirect_info);
    guard ok(redirect_err) else { return false, redirect_err; }

    let _ = ctx.url_chain.try_push(redirect_info.new_url);
    ctx.redirect_count += 1;
    return true, Error { .. };
}

fn append_available_dict_header(headers: HeaderMap&, dict_b64: const u8[:]) {
    set_header(headers, "Available-Dictionary", dict_b64);
    let val = find_header(headers, "accept-encoding");
    if val.len == 0 {
        set_header(headers, "Accept-Encoding", "dcb, dcz");
        return;
    }
    if !header_has_token(val, "dcb") {
        var new_ae: u8[..256] = [];
        guard new_ae.try_set(val) && new_ae.try_append(", dcb, dcz") else { return; }
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
            let _ = resp.protocol.try_set(route.protocol[..]);
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
            let proto = if route.protocol.len > 0 { route.protocol[..] } else { "HTTP/1.1" };
            let _ = resp.protocol.try_set(proto);
        } else {
            record_success(session.altsvc, origin_buf);
            let _ = resp.protocol.try_set("h3");
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
    let enc = header(resp, "Content-Encoding");
    if enc.len > 0 {
        guard decode_body_with_dictionary(resp, dict_cache) else { return; }
    }
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
    let defer_to_strict_stage = session.strict_content_decoding || session.verify_content_digest;
    if !defer_to_strict_stage &&
        wire::is_egress_stage_enabled(session.wire_pipeline, wire::STAGE_ID_CLI_OUT_DECOMPRESS) {
        let _ = stage_client_decompress(resp, session.dict_cache);
    }

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
    let curr_href = current_url.href[..];
    let curr_method = ctx.current_method[..];
    let is_https = current_url.is_secure_scheme();

    for &route in session.mock_routes {
        let method_match = route.method.len == 0 || route.method[..].eq_ascii_fold(curr_method);
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
    return min(max(raw, 1), 600000) as u32;
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

    var released = false;
    defer if !released { session.pool.close_pooled_connection(conn_id); };

    var hop_req = Request { .. };
    let _ = hop_req.method.try_set(curr_method);
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
    guard ok_ex else { return false; }

    resp.effective_url = copy(current_url.href);
    copy_headers(ctx.headers, resp.sent_headers);
    ingest_transport_response_headers(
        session, current_url, is_https, origin_buf, curr_path, now_sec, resp,
    );
    if keep_alive && resp.is_http1() && resp.status_code != rfc::STATUS_SWITCHING_PROTOCOLS {
        session.pool.release_connection(conn_id, now_ns);
        released = true;
    }
    return true;
}

fn resolve_hop_proxy_chain(session: const Session&) -> ProxyChain {
    if session.proxy_url.len == 0 {
        return new_direct_proxy_chain();
    }
    let p_url = core::new_url(session.proxy_url[..]);
    guard p_url.valid else { return new_direct_proxy_chain(); }
    let p_scheme = if p_url.scheme() == "https" {
        ProxyScheme.Https
    } else if p_url.scheme() == "socks5h" {
        ProxyScheme.Socks5h
    } else if p_url.scheme() == "socks5" {
        ProxyScheme.Socks5
    } else {
        ProxyScheme.Http
    };
    let raw_port = p_url.effective_port();
    let p_port: u16 = if raw_port > 0 {
        raw_port as u16
    } else if p_scheme == ProxyScheme.Socks5 || p_scheme == ProxyScheme.Socks5h {
        1080
    } else if p_scheme == ProxyScheme.Https {
        443
    } else {
        80
    };
    let ps = new_proxy_server(p_scheme, p_url.hostname(), p_port);
    return new_single_proxy_chain(ps);
}

fn collect_ipv4_dns_candidates(
    ssrf_guard: const SsrfGuardPolicy&,
    a_entry:    const DnsCacheEntry&,
    port_num:   u16,
    out_list:   DnsCandidate[..8]&,
) -> bool {
    var ip4_buf: u8[..64] = [];
    for ip4 in a_entry.ipv4_hints {
        core::format_ipv4_u32(ip4, ip4_buf);
        if ssrf_guard.enabled && ssrf_guard.deny_local_network {
            guard !is_private_or_reserved_ip(ip4_buf[..]) else { return false; }
        }
        let _ = out_list.try_push(new_dns_candidate(AddressFamily.IPv4, ip4_buf[..], port_num, L4Protocol.Tcp, 40));
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
        core::format_ipv6_bytes(ip6, ip6_buf);
        if ssrf_guard.enabled && ssrf_guard.deny_local_network {
            guard !is_private_or_reserved_ip(ip6_buf[..]) else { return false; }
        }
        let _ = out_list.try_push(new_dns_candidate(AddressFamily.IPv6, ip6_buf[..], port_num, L4Protocol.Tcp, 50));
    }
    return true;
}

fn append_svcb_hint_candidate(
    ssrf_guard: const SsrfGuardPolicy&,
    ip_str:     const u8[:],
    fam:        AddressFamily,
    eff_port:   u16,
    priority:   u8,
    out_list:   DnsCandidate[..8]&,
) -> bool {
    if ssrf_guard.enabled && ssrf_guard.deny_local_network {
        guard !is_private_or_reserved_ip(ip_str) else { return false; }
    }
    let _ = out_list.try_push(new_dns_candidate(fam, ip_str, eff_port, L4Protocol.Tcp, priority));
    return true;
}

fn collect_https_svcb_hint_candidates(
    ssrf_guard: const SsrfGuardPolicy&,
    meta:       const ConnectionEndpointMetadata&,
    eff_port:   u16,
    task:       DnsRaceTask&,
) -> bool {
    if task.ipv6_candidates.len == 0 {
        for &ip6_str in meta.ipv6_hints {
            guard append_svcb_hint_candidate(
                ssrf_guard, ip6_str[..], AddressFamily.IPv6, eff_port, 50, task.ipv6_candidates,
            ) else { return false; }
        }
    }
    if task.ipv4_candidates.len == 0 {
        for &ip4_str in meta.ipv4_hints {
            guard append_svcb_hint_candidate(
                ssrf_guard, ip4_str[..], AddressFamily.IPv4, eff_port, 40, task.ipv4_candidates,
            ) else { return false; }
        }
    }
    return true;
}

fn resolve_https_svcb_record(
    session:      Session&,
    host_str:     const u8[:],
    port_num:     u16,
    now_sec:      i64,
    task:         DnsRaceTask&,
    out_ech_list: u8[..512]&,
) -> bool {
    var https_entry = DnsCacheEntry { .. };
    let h_stat = session.dns_cache.dns_cache_lookup(host_str, rfc::DNS_QTYPE_HTTPS, now_sec, https_entry);
    guard h_stat != DnsCacheStatus.Expired && https_entry.https_records.len > 0 else { return true; }
    let meta, eff_port = extract_https_svcb_metadata(https_entry.https_records[0], port_num);
    task.metadata = meta;
    task.https_status = DnsQueryStatus.Success;
    if (session.enable_ech || session.auto_ech_discovery) && https_entry.https_records[0].has_ech {
        let _ = out_ech_list.try_set(https_entry.https_records[0].ech_config_list[..]);
    }
    return collect_https_svcb_hint_candidates(session.ssrf_guard, meta, eff_port, task);
}

fn lookup_dns_https_h3_endpoint(
    dns_cache:    const DnsCache&,
    host_str:     const u8[:],
    default_port: u16,
    now_sec:      i64,
    out_ep:       AltSvcEndpoint&,
) -> bool {
    var https_entry = DnsCacheEntry { .. };
    let h_stat = dns_cache.dns_cache_lookup(host_str, rfc::DNS_QTYPE_HTTPS, now_sec, https_entry);
    guard h_stat != DnsCacheStatus.Expired && https_entry.https_records.len > 0 else { return false; }
    let meta, eff_port = extract_https_svcb_metadata(https_entry.https_records[0], default_port);
    guard meta.alpn_h3 else { return false; }
    out_ep = AltSvcEndpoint {
        port:        eff_port,
        max_age_sec: 86400,
        persist:     false,
        ..
    };
    let _ = out_ep.proto.try_set("h3");
    let target_h = if meta.target_name.len > 0 { meta.target_name[..] } else { host_str };
    let _ = out_ep.host.try_append(target_h);
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
    let now_ms = core::mul_sat_i64(now_sec, 1000);
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

    guard resolve_https_svcb_record(session, host_str, port_num, now_sec, task, out_ech_list) else {
        return make_error(rfc::STATUS_FORBIDDEN, "ssrf_guard", "SSRF: HTTPS SVCB hint to private IP blocked");
    }

    let _ = task.check_dns_resolution_delay_tick(core::add_sat_i64(now_ms, rfc::HE_RESOLUTION_DELAY_MS));
    let pref_fam, _ = lookup_preferred_family(session.af_cache, host_str, now_sec);
    interleave_candidates_by_preference(task.ipv6_candidates[..], task.ipv4_candidates[..], pref_fam, out_candidates);
    if out_candidates.len == 0 {
        let _ = out_candidates.try_push(new_dns_candidate(AddressFamily.IPv4, host_str, port_num, L4Protocol.Tcp, 40));
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
        guard sock > 0 else { return -1, make_error(rfc::STATUS_BAD_GATEWAY, "transport", "Proxy TCP connect failed"); }
        var proxy_ready = false;
        defer if !proxy_ready { native_tcp_close(sock); };
        let p_url = core::new_url(proxy_url);
        let p_user = p_url.username();
        let p_pass = p_url.password();
        if ps.scheme == ProxyScheme.Socks5 || ps.scheme == ProxyScheme.Socks5h {
            let use_ip = ps.scheme == ProxyScheme.Socks5 && candidates.len > 0;
            let t_host = if use_ip { candidates[0].ip[..] } else { host_str };
            let s_err = socks5_client_handshake(sock, ps.scheme, t_host, port_num, p_user, p_pass, eff_timeout);
            guard s_err == Socks5Error.None else {
                return -1, make_error(rfc::STATUS_BAD_GATEWAY, "transport", "SOCKS5 handshake failed");
            }
        } else {
            var proxy_auth: u8[..256] = [];
            if p_user.len > 0 {
                var cred_raw: u8[..160] = [];
                format(cred_raw, p_user, ":", p_pass);
                var cred_b64: u8[..224] = [];
                core::base64_encode(cred_raw[..], cred_b64);
                core::secure_zeroize_slice(cred_raw[..]);
                format(proxy_auth, "Basic ", cred_b64[..]);
                core::secure_zeroize_slice(cred_b64[..]);
            }
            let c_err = http_connect_client_handshake(
                sock, host_str, port_num, proxy_auth[..], "goose-wing/1.0", eff_timeout,
            );
            core::secure_zeroize_slice(proxy_auth[..]);
            guard c_err == ConnectTunnelError.None else {
                return -1, make_error(rfc::STATUS_BAD_GATEWAY, "transport", "HTTP CONNECT tunnel failed");
            }
        }
        proxy_ready = true;
        let _ = out_ip.try_set(ps.host[..]);
        return sock, Error { .. };
    }
    var mgr = new_attempt_manager();
    mgr.start_attempt_race(candidates, now_ms);
    for &cand in candidates {
        let sock = native_tcp_connect(cand.ip[..], cand.port, eff_timeout);
        if sock > 0 {
            if mgr.attempts.len > 0 {
                let _ = mgr.bind_winner_attempt(mgr.attempts[core::sub_sat_i64(mgr.attempts.len, 1)].attempt_id, false);
            }
            let _ = out_ip.try_set(cand.ip[..]);
            return sock, Error { .. };
        }
        let _ = mgr.tick_attempt_manager(core::add_sat_i64(now_ms, mgr.effective_cad_ms));
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
    let saved_len = out_wire.len;
    var committed = false;
    defer if !committed { out_wire.resize(saved_len); };
    out_wire.clear();
    let scheme_str: const u8[:] = if is_https { "https" } else { "http" };
    let auth_str = current_url.host();
    var path_buf: u8[..2048] = [];
    let p_str = current_url.pathname();
    if p_str.len > 0 { let _ = path_buf.try_append(p_str); } else { let _ = path_buf.try_push('/'); }
    let q_str = current_url.search();
    if q_str.len > 0 { let _ = path_buf.try_append(q_str); }
    guard path_buf.len <= 1024 else { return false; }

    var pseudo = internal::H2PseudoHeaders {
        has_method: true, has_scheme: true, has_authority: true, has_path: true, ..
    };
    let _ = pseudo.method.try_set(curr_method);
    let _ = pseudo.scheme.try_set(scheme_str);
    let _ = pseudo.authority.try_set(auth_str);
    let _ = pseudo.path.try_set(path_buf[..]);
    let proto_hdr = find_header(ctx.headers, ":protocol");
    if proto_hdr.len > 0 {
        pseudo.has_protocol = true;
        let _ = pseudo.protocol.try_set(proto_hdr);
    }
    if send_preface {
        guard out_wire.try_append(rfc::H2_CLIENT_PREFACE) else { return false; }
        let empty_settings: wire::WireSetting[..1] = [];
        guard wire::encode_settings_frame(empty_settings[..], out_wire) else { return false; }
    }
    guard wire::encode_h2_headers_frame_from_map(
        enc_dt, stream_id, pseudo, ctx.headers, ctx.body.len == 0, out_wire, 16384,
    ) else { return false; }
    var rem = ctx.body[..];
    while rem.len > 0 {
        let chunk_len = min(rem.len, rfc::H2_DEFAULT_MAX_FRAME_SIZE as i64);
        guard wire::encode_data_frame(stream_id, rem[..chunk_len], chunk_len >= rem.len, out_wire) else {
            return false;
        }
        rem = rem[chunk_len..];
    }
    committed = true;
    return true;
}

fn process_h2_control_frame<B>(
    hdr:     const internal::FrameHeader&,
    payload: const u8[:],
    out:     B&,
) {
    if hdr.frame_type == rfc::H2_FRAME_SETTINGS && (hdr.flags & rfc::H2_FLAG_ACK) == 0 {
        let ack_hdr = wire::WireFrameHeader {
            length: 0, frame_type: rfc::H2_FRAME_SETTINGS, flags: rfc::H2_FLAG_ACK, stream_id: 0,
        };
        let _ = wire::encode_frame_header(ack_hdr, out);
    } else if hdr.frame_type == rfc::H2_FRAME_PING && (hdr.flags & rfc::H2_FLAG_ACK) == 0 && payload.len == 8 {
        var ping_data: u8[8] = [0; 8];
        for i in 8 { ping_data[i] = payload[i]; }
        let _ = wire::encode_ping_frame(ping_data, true, out);
    }
}

inline fn record_h2_rst_stream_error(payload: const u8[:], resp: Response&) {
    guard payload.len >= 4 else { return; }
    let rst_code = core::read_be_u32(payload, 0);
    var rst_buf: u8[..16] = [];
    rst_code.format_u64_dec(rst_buf);
    let _ = append_header(resp.trailers, "x-wing-h2-rst-code", rst_buf[..]);
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
    if hdr.stream_id == 0 && (hdr.frame_type == rfc::H2_FRAME_SETTINGS || hdr.frame_type == rfc::H2_FRAME_PING) {
        process_h2_control_frame(hdr, payload, out_ctrl);
        return true, false;
    }
    if hdr.frame_type == rfc::H2_FRAME_RST_STREAM && hdr.stream_id == stream_id {
        record_h2_rst_stream_error(payload, resp);
        return false, false;
    }
    if hdr.frame_type == rfc::H2_FRAME_GOAWAY { return false, false; }
    if hdr.frame_type == rfc::H2_FRAME_WINDOW_UPDATE { return true, false; }
    let saved_resp = copy(resp);
    let saved_got = got_hdrs;
    var committed = false;
    defer if !committed { resp = copy(saved_resp); got_hdrs = saved_got; };
    if hdr.frame_type == rfc::H2_FRAME_HEADERS && hdr.stream_id == stream_id {
        let frag, f_err = internal::extract_headers_frame_payload(hdr, payload);
        guard f_err == rfc::H2_ERR_NO_ERROR else { return false, false; }
        var pseudo = internal::H2PseudoHeaders { .. };
        if !got_hdrs {
            let d_err = wire::decode_hpack_to_map(dec_dt, frag, pseudo, resp.headers, 8192, false);
            guard d_err == rfc::H2_ERR_NO_ERROR else { return false, false; }
            if pseudo.status > 0 { resp.status_code = pseudo.status; }
            for &e in resp.headers.entries { update_response_presence(resp, entry_name(resp.headers, e)); }
            if pseudo.status >= 100 && pseudo.status < 200 {
                guard (hdr.flags & rfc::H2_FLAG_END_STREAM) == 0 else { return false, false; }
                resp.headers.clear();
                resp.presence_mask = 0;
            } else {
                got_hdrs = true;
            }
        } else {
            guard (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0 else { return false, false; }
            pseudo.is_trailer = true;
            let d_err = wire::decode_hpack_to_map(dec_dt, frag, pseudo, resp.trailers, 8192, false);
            guard d_err == rfc::H2_ERR_NO_ERROR && !pseudo.has_status else { return false, false; }
        }
        let end_s = (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0 ||
            (got_hdrs && (is_head || rfc::is_empty_body_status(resp.status_code)));
        committed = true;
        return true, end_s;
    }
    if hdr.frame_type == rfc::H2_FRAME_DATA && hdr.stream_id == stream_id {
        let d_slice, d_err = internal::extract_padded_frame_payload(hdr, payload);
        guard d_err == rfc::H2_ERR_NO_ERROR else { return false, false; }
        resp.body.append(d_slice);
        if hdr.length > 0 {
            let _ = wire::encode_window_update_frame(0, hdr.length, out_ctrl);
            let _ = wire::encode_window_update_frame(stream_id, hdr.length, out_ctrl);
        }
        committed = true;
        return true, (hdr.flags & rfc::H2_FLAG_END_STREAM) != 0;
    }
    committed = true;
    return true, false;
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
    defer rx_accum.compact_wire_buffer(consumed);
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
            return false, false;
        }
        if done {
            return true, true;
        }
    }
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
        var ctrl_out: u8[..4096] = [];
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
    var released = false;
    defer if !released { session.pool.close_pooled_connection(conn_id); };

    let conn .= session.pool.conns[c_idx];
    let stream_id = conn.next_h2_stream_id;
    let send_preface = !conn.h2_preface_sent;
    var wire_out: u8[..65536] = [];
    guard encode_h2_client_request(
        curr_method,
        current_url,
        is_https,
        ctx,
        conn.hpack_enc,
        stream_id,
        send_preface,
        wire_out,
    ) else {
        return false;
    }
    guard send_all(conn.transport, wire_out[..]) else {
        return false;
    }
    conn.h2_preface_sent = true;
    conn.next_h2_stream_id += 2;
    reset_response(resp);
    let _ = resp.protocol.try_set("HTTP/2");
    let eff_timeout = calc_effective_timeout_ms(session.timeout_ms, ctx.timeout_ms);
    let is_head = curr_method == "HEAD";
    let got_hdrs = recv_h2_response_loop(
        conn.transport,
        stream_id,
        is_head,
        conn.hpack_dec,
        eff_timeout,
        resp,
    );
    guard got_hdrs else { return false; }
    resp.effective_url = copy(current_url.href);
    copy_headers(ctx.headers, resp.sent_headers);
    ingest_transport_response_headers(session, current_url, is_https, origin_buf, curr_path, now_sec, resp);
    session.pool.release_connection(conn_id, now_ns);
    released = true;
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
    let p_str = current_url.pathname();
    if p_str.len > 0 { let _ = path_buf.try_append(p_str); } else { let _ = path_buf.try_push('/'); }
    let q_str = current_url.search();
    if q_str.len > 0 { let _ = path_buf.try_append(q_str); }
    guard path_buf.len <= 1024 else { return false; }

    let has_body = ctx.body.len > 0;
    guard internal::send_request_headers(
        h3_conn, sid, ctx.current_method[..], "https", current_url.host(),
        path_buf[..], ctx.headers, !has_body, out_wire,
    ) else { return false; }

    if has_body {
        guard internal::send_request_data(h3_conn, sid, ctx.body[..], true, out_wire) else {
            return false;
        }
    }
    return true;
}

// Executes an Unencrypted H3 over UDP (Datagram Direct) client hop (RFC 9114 framing + QPACK)
// when racing against a direct HTTP/3 UDP endpoint (`serve_h3` / `handle_h3_server_datagram`).
// For encrypted RFC 9000 + RFC 9001 TLS 1.3 QUIC v1 sessions, use `QuicConnection` + `H3Connection`.
fn execute_live_h3_hop(
    session:     Session&,
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    origin_buf:  const u8[:],
    h3_ep:       const AltSvcEndpoint&,
    now_sec:     i64,
    resp:        Response&,
) -> bool {
    let target_host = if h3_ep.host.len > 0 { h3_ep.host[..] } else { current_url.hostname() };
    let target_port = if h3_ep.port > 0 { h3_ep.port } else { current_url.effective_port() as u16 };
    if session.ssrf_guard.enabled && session.ssrf_guard.deny_local_network &&
        (is_private_or_reserved_ip(target_host) || is_dangerous_service_port(target_port)) {
        return false;
    }
    let udp_fd = udp_bind("0.0.0.0", 0);
    guard udp_fd > 0 else { return false; }
    defer tcp_close(udp_fd);

    let h3_settings = H3Settings { .. };
    var h3_conn = internal::new_h3_client_connection(h3_settings);
    let sid, ok_s = internal::open_request_stream(h3_conn);
    guard ok_s else { return false; }
    var req_wire: u8[..4096] = [];
    guard encode_h3_client_request(h3_conn, sid, ctx, current_url, req_wire) else { return false; }
    let curr_path = current_url.pathname();
    let sent = native_udp_sendto(udp_fd, req_wire[..], target_host, target_port);
    guard sent > 0 else { return false; }
    var rx_buf:    u8[1472] = [0; 1472];
    var peer_ip4:  u32      = 0;
    var peer_port: u16      = 0;
    let eff_timeout = calc_effective_timeout_ms(session.timeout_ms, ctx.timeout_ms);
    let recvd = udp_recvfrom(udp_fd, rx_buf[..], min(eff_timeout, 250), peer_ip4, peer_port);
    guard recvd > 0 else { return false; }

    let h_err = internal::handle_stream_data(h3_conn, sid, true, rx_buf[..recvd], true);
    guard h_err == rfc::H3_ERR_NO_ERROR else { return false; }
    let sc, ok_sc = internal::get_status_code(h3_conn, sid);
    guard ok_sc else { return false; }

    reset_response(resp);
    resp.status_code = sc;
    let _ = resp.protocol.try_set("HTTP/3");
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
    let host_str = current_url.hostname();
    if session.ssrf_guard.enabled {
        if is_private_or_reserved_ip(host_str) {
            return make_error(rfc::STATUS_FORBIDDEN, "ssrf_guard", "SSRF: private IP blocked");
        }
    }

    let port_num = current_url.effective_port() as u16;
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
    let nik = new_network_isolation_key(site_site, site_site);
    let pool_key = new_pool_key(
        pool_scheme,
        host_str,
        port_num,
        proxy_chain,
        nik_to_anonymization_key(nik, ctx.had_cross_site_hop),
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
        let win_fam = if dialed_ip[..].contains_byte(':') { AddressFamily.IPv6 } else { AddressFamily.IPv4 };
        record_preferred_family(session.af_cache, host_str, win_fam, now_sec);
        var t = Transport.Disconnected;
        var neg_proto = NegotiatedProtocol.Http11;
        if is_https {
            let host_is_hsts = session.enable_hsts && session.hsts.is_hsts_host(host_str, now_sec);
            let effective_insecure_skip = session.insecure_skip_verify && !host_is_hsts;

            var tls_cfg = TlsClientHandshakeConfig { .. };
            let _ = tls_cfg.server_name.try_set(host_str);
            let _ = tls_cfg.alpn.try_set("h2,http/1.1");
            tls_cfg.trust_store = session.trust_store;
            tls_cfg.insecure_skip_verify = effective_insecure_skip;
            tls_cfg.virtual_clock_sec = if session.virtual_clock_us == 1700000000000000 { 0 } else { now_sec };
            if ech_list.len > 0 {
                let _ = tls_cfg.ech_config_list.try_set(ech_list[..]);
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

    let curr_path = current_url.pathname();
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
    if !has_h3 && is_https && session.enable_protocol_racing {
        let port_num = current_url.effective_port() as u16;
        if !is_broken(session.altsvc, origin_buf[..], now_sec) {
            has_h3 = lookup_dns_https_h3_endpoint(
                session.dns_cache,
                current_url.hostname(),
                port_num,
                now_sec,
                candidate_h3_ep,
            );
        }
    }

    let curr_path = current_url.pathname();
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
        remove_header_by_name(ctx.headers, "Dictionary-ID");
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

// RFC 9110 Section 11.1: Authentication Scheme - Checks that `hdr` begins with `scheme_tok`
// followed by end-of-string or BWS/SP delimiter (`' '` or `'\t'`).
inline fn has_auth_scheme_prefix(hdr: const u8[:], scheme_tok: const u8[:]) -> bool {
    let s = hdr.trim_lws();
    guard s.starts_with_fold(scheme_tok) else { return false; }
    return s.len == scheme_tok.len || s[scheme_tok.len] == ' ' || s[scheme_tok.len] == '\t';
}

fn compute_401_auth_header(
    session:         Client&,
    ctx:             RequestExecutionContext&,
    current_url:     const core::Url&,
    www_auth:        const u8[:],
    auth_header_val: u8[..4096]&,
) -> bool {
    auth_header_val.clear();
    if has_auth_scheme_prefix(www_auth, "Digest") {
        let chal, ok_c = parse_digest_challenge(www_auth);
        guard ok_c else { return false; }
        guard !ctx.auth_retried || chal.stale else { return false; }
        let uri_path = current_url.pathname();
        let uri_search = current_url.search();
        var uri_target: u8[..2048] = [];
        if uri_path.len > 0 {
            let _ = uri_target.try_append(uri_path);
        } else {
            let _ = uri_target.try_push('/');
        }
        if uri_search.len > 0 {
            let _ = uri_target.try_append(uri_search);
        }
        var c_creds = DigestCredentials { .. };
        let _ = c_creds.username.try_set(session.creds.username[..]);
        let _ = c_creds.password.try_set(session.creds.password[..]);

        var active_chal = chal;
        if chal.stale && session.creds.last_digest.valid {
            let _ = sync_digest_stale_challenge(
                session.creds.last_digest,
                chal,
                c_creds,
                session.creds.nonce_counter,
            );
            active_chal = session.creds.last_digest;
        } else {
            session.creds.last_digest = chal;
        }

        let ok_d = compute_digest_response(
            active_chal,
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
    if has_auth_scheme_prefix(www_auth, rfc::SCHEME_PRIVATE_TOKEN) {
        var chal = TokenChallenge { .. };
        var tok_key: u8[..512] = [];
        var max_age: i64       = 0;
        guard parse_private_token_challenge(www_auth, chal, tok_key, max_age) else { return false; }
        var popped_tok = Token { .. };
        var raw_tok: u8[..512] = [];
        let now_sec = div_euclid(session.virtual_clock_us, 1000000);
        guard get_private_token(session.private_token_cache, chal, now_sec, popped_tok, raw_tok) else {
            return false;
        }
        format_private_token_authorization(raw_tok[..], auth_header_val);
        return true;
    }
    if has_auth_scheme_prefix(www_auth, "Basic") {
        // RFC 7617 Section 2: The 'Basic' Authentication Scheme - user-id MUST NOT contain a colon.
        guard !session.creds.username[..].contains_byte(':') else { return false; }
        var user_pass: u8[..260] = [];
        guard user_pass.try_append(session.creds.username[..])
            && user_pass.try_push(':')
            && user_pass.try_append(session.creds.password[..]) else {
            core::secure_zeroize_slice(user_pass[..]);
            return false;
        }
        var b64_user_pass: u8[..360] = [];
        core::base64_encode(user_pass[..], b64_user_pass);
        core::secure_zeroize_slice(user_pass[..]);
        let _ = auth_header_val.try_append("Basic ");
        let _ = auth_header_val.try_append(b64_user_pass[..]);
        core::secure_zeroize_slice(b64_user_pass[..]);
        return true;
    }
    return false;
}

fn try_find_scheme_auth_header(
    session:         Client&,
    ctx:             RequestExecutionContext&,
    current_url:     const core::Url&,
    resp:            const Response&,
    scheme_prefix:   const u8[:],
    auth_header_val: u8[..4096]&,
) -> bool {
    for &e in resp.headers.entries {
        let h_name = entry_name(resp.headers, e);
        let h_val = entry_value(resp.headers, e);
        if h_name.eq_ascii_fold("WWW-Authenticate") && has_auth_scheme_prefix(h_val, scheme_prefix) {
            if compute_401_auth_header(session, ctx, current_url, h_val, auth_header_val) {
                return true;
            }
        }
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
    // Scan all WWW-Authenticate headers, prioritizing PrivateToken -> Digest -> Basic
    if !ctx.auth_retried && session.private_token_cache.entries.len > 0 {
        let p_scheme = rfc::SCHEME_PRIVATE_TOKEN;
        if try_find_scheme_auth_header(session, ctx, current_url, resp, p_scheme, auth_header_val) {
            return true;
        }
    }
    guard session.creds.has_credentials else { return false; }
    if try_find_scheme_auth_header(session, ctx, current_url, resp, "Digest", auth_header_val) {
        return true;
    }
    if !ctx.auth_retried {
        return try_find_scheme_auth_header(session, ctx, current_url, resp, "Basic", auth_header_val);
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
    ctx.body_consumed = false;
    if session.enable_cookie_jar {
        ingest_hop_response_cookies(session, ctx, current_url, samesite_eval, resp.headers);
        remove_header_by_name(ctx.headers, "Cookie");
        prepare_hop_cookie_header(session, ctx, current_url, samesite_eval, safe_method);
    }
    set_header(ctx.headers, "Authorization", auth_val, true);
}

fn execute_request_inner(session: Client&, req: const Request&) -> Response, Error {
    var noop = wire::NoOpStage {};
    return execute_client_pipeline_with_stage(session, req, noop);
}

inline fn evaluate_response_retry_after(
    session:  Client&,
    host_str: const u8[:],
    resp:     const Response&,
    now_ns:   i64,
) {
    let ra_val = resp.header("Retry-After");
    guard ra_val.len > 0 else { return; }
    let now_ms = div_euclid(session.virtual_clock_us, 1000);
    let wait_ms, ok_ra = parse_retry_after_ms(ra_val, now_ms);
    if ok_ra {
        let _ = trip_circuit_breaker_if_exceeded(session.circuit_breaker, host_str, wait_ms, now_ns);
    }
}

inline fn record_client_har_telemetry(
    session:      Client&,
    req:          const Request&,
    resp:         const Response&,
    total_dur_us: i64,
) {
    guard session.enable_har_telemetry else { return; }
    let status_u16 = (resp.status_code as u64) as! u16;
    var entry = HarEntry {
        status:         status_u16,
        request_bytes:  req.body.len,
        response_bytes: resp.body.len,
        timings: RequestTimings {
            wait_us: max(0, total_dur_us),
            ..
        },
        ..
    };
    entry.started_iso8601.try_set("2026-01-01T00:00:00.000Z");
    entry.method.try_set(req.method[..]);
    entry.url.try_set(req.url[..]);
    let har_ver = if resp.is_http3() {
        "HTTP/3"
    } else if resp.is_http1() || protocol(resp).len == 0 {
        "HTTP/1.1"
    } else {
        protocol(resp)
    };
    entry.http_version.try_set(har_ver);
    session.last_har_json.clear();
    serialize_har_entry_json(entry, session.last_har_json);
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
    if !ok(err) && attempts == 0 {
        let tier1 = evaluate_tier1_retry(err.code, false, req, status_code > 0);
        if tier1.retry_immediately {
            return true;
        }
    }

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
    let now_ns = start_us * 1000;

    let parsed_url, url_err = core::parse_url(req.url[..]);
    let target_host = if url_err == core::UrlParseError.None { parsed_url.host() } else { "" };
    if target_host.len > 0 && is_host_circuit_broken(session.circuit_breaker, target_host, now_ns) {
        let err_cb = make_error(503, "circuit_breaker", "host circuit broken by Retry-After");
        return Response { status_code: 503, .. }, err_cb;
    }
    record_primary_request(session.retry_budget, now_ns);

    var max_retries: i32  = 0;
    var retry_5xx:   bool = false;
    let has_retry = find_retry_policy(session.pipeline, max_retries, retry_5xx);

    var attempts:      i32 = 0;
    var prev_sleep_ms: i64 = 0;
    var rng_seed:      u64 = (start_us as u64) ^ 0x9E3779B97F4A7C15;
    loop {
        // Phase -1: Application Interceptors (Request Hook) per attempt
        var active_req = copy(req);
        apply_app_interceptors_request(session.pipeline, active_req, session.virtual_clock_us);

        let resp, err = execute_request_inner(session, active_req);
        evaluate_response_retry_after(session, target_host, resp, now_ns);

        let retry = should_retry_request(
            resp.status_code, err, active_req.method[..], active_req,
            attempts, has_retry, max_retries, retry_5xx,
        );
        if retry && allow_retry_budget(session.retry_budget, now_ns) {
            let sleep_ms = compute_backoff_jitter_ms(session.backoff_config, attempts, prev_sleep_ms, rng_seed);
            session.virtual_clock_us += sleep_ms * 1000;
            attempts += 1;
            continue;
        }

        // Phase 6: Application Interceptors (Response Hook)
        var final_resp = resp;
        let total_dur_us = session.virtual_clock_us - start_us;
        apply_app_interceptors_response(session.pipeline, active_req, final_resp, err, total_dur_us);
        record_client_har_telemetry(session, active_req, final_resp, total_dur_us);
        return copy(final_resp), err;
    }
    return Response { .. }, make_error(rfc::STATUS_INTERNAL_SERVER_ERROR, "client", "request execution failed");
}
