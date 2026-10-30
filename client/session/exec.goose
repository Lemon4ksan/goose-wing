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
import net.retry;

// ---- url resolution helpers ------------------------------------------------

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

    var hash_buf: u8[..512] = [];
    if hash_pos >= 0 {
        hash_buf.append(out[hash_pos..]);
        out.resize(hash_pos);
    }

    for &query_item, param_idx in query_params {
        if param_idx == 0 && !has_query_mark {
            out.push('?');
        } else {
            out.push('&');
        }
        out.append(query_item.key[..]);
        out.push('=');
        out.append(query_item.value[..]);
    }

    if hash_buf.len > 0 {
        out.append(hash_buf[..]);
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
    headers:                 HeaderItem[..32]    = [],
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
    body:                    u8[>..]             = [],
}

fn validate_hop_prerequisites(session: const Session&, current_url: const core::Url&) -> Error {
    if session.https_only && scheme(current_url) != "https" {
        return make_error(400, "ssrf_guard", "https_only policy violated");
    }
    let ssrf_err = validate_url_against_ssrf(current_url, session.ssrf_guard);
    if ssrf_err != RedirectError.None {
        return make_error(403, "ssrf_guard", redirect_error_to_string(ssrf_err));
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
        ctx.body_consumed = false;
    } else {
        // 307 or 308 redirect preserves method and body
        if !ctx.rewindable && ctx.body_consumed {
            return make_error(400, "body_rewind", "http: cannot rewind body");
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
    headers:         HeaderItem[..32]&,
    default_headers: const HeaderItem[..16]&,
    req_headers:     const HeaderItem[..32]&,
    profile:         Profile,
) {
    for &default_hdr in default_headers {
        headers.push(copy(default_hdr));
    }
    for &req_hdr in req_headers {
        remove_header_by_name(headers, req_hdr.name[..]);
        headers.push(copy(req_hdr));
    }
    if profile != Profile.None {
        let has_ae = find_header(headers[..], "accept-encoding").len > 0;
        if !has_ae {
            headers.push(make_header("Accept-Encoding", "zstd, br, gzip"));
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
        return false, make_error(310, "redirect", "redirects disabled by mode");
    }
    if ctx.redirect_count >= ctx.max_redirects {
        return false, make_error(310, "redirect", "maximum redirect hops exceeded");
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
        return false, make_error(310, "redirect", redirect_error_to_string(redirect_info.error));
    }

    let redirect_err = apply_redirect_transition(session, ctx, redirect_info);
    guard ok(redirect_err) else { return false, redirect_err; }

    ctx.url_chain.push(redirect_info.new_url);
    ctx.redirect_count += 1;
    return true, Error { .. };
}

fn append_available_dict_header(headers: HeaderItem[..32]&, dict_b64: const u8[:]) {
    remove_header_by_name(headers, "Available-Dictionary");
    headers.push(make_header("Available-Dictionary", dict_b64));
    var ae_idx = -1;
    for i in headers.len {
        if eq_ascii_fold(headers[i].name[..], "accept-encoding") {
            ae_idx = i;
            break;
        }
    }
    if ae_idx < 0 {
        return;
    }
    let val = headers[ae_idx].value[..];
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
        headers[ae_idx].value.append(", dcb, dcz");
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
    if session.enable_altsvc && is_https {
        let alt_svc_val = header(resp, "Alt-Svc");
        if alt_svc_val.len > 0 {
            update(session.altsvc, origin_buf, alt_svc_val, now_sec);
        }
    }

    if session.enable_hsts && is_https {
        let hsts_val = header(resp, "Strict-Transport-Security");
        if hsts_val.len > 0 {
            hsts_cache_update(session.hsts, core::hostname(current_url), hsts_val, now_sec);
        }
    }

    if session.enable_compression_dict && is_https {
        ingest_compression_dict_header(session.dict_cache, origin_buf, curr_path, now_sec, resp);
    }

    let enc = header(resp, "Content-Encoding");
    if enc.len > 0 {
        decode_body_with_dictionary(resp, session.dict_cache);
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
                status_code:   403,
                effective_url: copy(current_url.href),
                ..
            };
            return true;
        }

        out_resp = build_mock_response(route, current_url, ctx.headers[..]);
        if route.status_code == 101 {
            let sent_key = find_header(ctx.headers[..], "sec-websocket-key");
            if sent_key.len > 0 && out_resp.header("sec-websocket-accept").len == 0 {
                var accept_buf: u8[..64] = [];
                compute_websocket_accept(sent_key, accept_buf);
                out_resp.headers.push(make_header("Sec-WebSocket-Accept", accept_buf[..]));
            }
        }

        resolve_mock_protocol_racing(session, route, is_https, origin_buf, has_h3, now_sec, out_resp);
        ingest_transport_response_headers(session, current_url, is_https, origin_buf, curr_path, now_sec, out_resp);
        return true;
    }
    return false;
}

fn copy_sent_headers(headers: const HeaderItem[..32]&, sent_headers: HeaderItem[..32]&) {
    for &sent_h in headers {
        sent_headers.push(copy(sent_h));
    }
}

// Executes a mock or echo response hop, verifying IP addresses against SSRF policies.
fn execute_mock_or_echo_hop(
    session:     Session&,
    ctx:         RequestExecutionContext&,
    current_url: const core::Url&,
    out_dns_err: RedirectError&,
) -> Response {
    out_dns_err = RedirectError.None;
    let curr_href = href(current_url);
    let curr_method = ctx.current_method[..];

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
    var matched_dict_b64: u8[..64] = [];
    var has_dict = false;
    if session.enable_compression_dict && is_https {
        has_dict = dictionary_lookup_for_request(
            session.dict_cache,
            origin_buf[..],
            curr_path,
            now_sec,
            matched_dict_b64,
        );
    }
    remove_header_by_name(ctx.headers, "Available-Dictionary");
    if has_dict {
        append_available_dict_header(ctx.headers, matched_dict_b64[..]);
    }

    var resp = Response { .. };
    let matched = try_match_mock_route(
        session,
        ctx,
        current_url,
        has_h3,
        origin_buf[..],
        curr_path,
        now_sec,
        out_dns_err,
        resp,
    );
    if matched {
        return resp;
    }

    // Default mock response
    resp.status_code = 200;
    resp.effective_url = copy(current_url.href);
    resp.headers.push(make_header("Content-Type", "application/json"));
    resp.headers.push(make_header("Server", "goose-wing/1.0"));
    resp.body.append("{\"id\":1042,\"status\":\"confirmed\",\"ok\":true}");

    if has_h3 && session.enable_altsvc {
        record_success(session.altsvc, origin_buf[..]);
        resp.protocol.clear();
        resp.protocol.append("h3");
    }

    ingest_transport_response_headers(session, current_url, is_https, origin_buf[..], curr_path, now_sec, resp);

    copy_sent_headers(ctx.headers, resp.sent_headers);
    return resp;
}

fn compute_401_auth_header(
    session:         Client&,
    ctx:             RequestExecutionContext&,
    current_url:     const core::Url&,
    www_auth:        const u8[:],
    auth_header_val: u8[..512]&,
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
        guard ok_d else { return false; }
        session.creds.nonce_counter += 1;
        return true;
    }
    if starts_with_fold(www_auth, "Basic") {
        var user_pass: u8[..140] = [];
        user_pass.append(session.creds.username[..]);
        user_pass.push(':');
        user_pass.append(session.creds.password[..]);
        var b64_user_pass: u8[..200] = [];
        core::base64_encode(user_pass[..], b64_user_pass);
        auth_header_val.append("Basic ");
        auth_header_val.append(b64_user_pass[..]);
        return true;
    }
    return false;
}

fn handle_401_auth_retry(
    session:           Client&,
    ctx:               RequestExecutionContext&,
    current_url:       const core::Url&,
    samesite_eval:     const SameSiteCookieContext&,
    safe_method:       bool,
    resp:              Response&,
    dns_rebinding_err: RedirectError&,
) -> bool, Error {
    guard resp.status_code == 401 && session.creds.has_credentials && !ctx.auth_retried else {
        return false, Error { .. };
    }
    let www_auth = header(resp, "WWW-Authenticate");
    guard www_auth.len > 0 else { return false, Error { .. }; }

    var auth_header_val: u8[..512] = [];
    guard compute_401_auth_header(session, ctx, current_url, www_auth, auth_header_val) else {
        return false, Error { .. };
    }

    ctx.auth_retried = true;
    ingest_hop_response_cookies(session, ctx, current_url, samesite_eval, resp.set_cookies);
    prepare_hop_cookie_header(session, ctx, current_url, samesite_eval, safe_method);

    remove_header_by_name(ctx.headers, "Authorization");
    ctx.headers.push(make_header("Authorization", auth_header_val[..]));

    resp = execute_mock_or_echo_hop(session, ctx, current_url, dns_rebinding_err);
    if dns_rebinding_err != RedirectError.None {
        return true, make_error(403, "ssrf_guard", redirect_error_to_string(dns_rebinding_err));
    }
    return true, Error { .. };
}

fn execute_single_hop(
    session:              Client&,
    ctx:                  RequestExecutionContext&,
    req:                  const Request&,
    cache_ts:             CacheTimestamps&,
    cache_revalidate_idx: i64,
    out_resp:             Response&,
) -> bool, Error {
    var current_url = ctx.url_chain[ctx.url_chain.len - 1];

    // RFC 6797 HSTS Upgrade on redirect hops
    if session.enable_hsts && !current_url.is_secure_scheme() {
        var upgraded_url: u8[..2048] = [];
        let now_sec = session.virtual_clock_us / 1000000;
        if hsts_upgrade_url(session.hsts, current_url.href[..], now_sec, upgraded_url) {
            let parsed_upgraded, parse_err = core::parse_url(upgraded_url[..]);
            if parsed_upgraded.valid {
                ctx.url_chain[ctx.url_chain.len - 1] = parsed_upgraded;
                current_url = parsed_upgraded;
            }
        }
    }

    // Phase 1: Pre-validation of Hop
    let pre_err = validate_hop_prerequisites(session, current_url);
    guard ok(pre_err) else { return false, pre_err; }

    // Phase 2 & 3: Compute SameSite Context & Synthesize Fresh Cookie Header
    let safe_method = is_safe_http_method(ctx.current_method[..]);
    let samesite_eval = compute_hop_samesite_context(ctx, current_url, safe_method);
    prepare_hop_cookie_header(session, ctx, current_url, samesite_eval, safe_method);

    // Phase 3.5: Network Interceptors (Request Hook)
    let hop_start_us = session.virtual_clock_us;
    apply_network_interceptors_request(
        session.pipeline,
        ctx.headers,
        current_url.href[..],
        ctx.current_method[..],
        ctx.body.len,
        ctx.redirect_count,
    );

    // Phase 4: Network Transaction & Ingest Set-Cookie Before 3xx Analysis
    var dns_rebinding_err = RedirectError.None;
    out_resp = execute_mock_or_echo_hop(session, ctx, current_url, dns_rebinding_err);
    guard dns_rebinding_err == RedirectError.None else {
        return false, make_error(403, "ssrf_guard", redirect_error_to_string(dns_rebinding_err));
    }

    // Phase 4.1: RFC 7616 Digest & RFC 7617 Basic 401 Authenticator Loop
    let did_retry, auth_err = handle_401_auth_retry(
        session,
        ctx,
        current_url,
        samesite_eval,
        safe_method,
        out_resp,
        dns_rebinding_err,
    );
    guard ok(auth_err) else { return false, auth_err; }

    // Phase 4.2: Network Interceptors (Response Hook)
    let hop_dur_us = session.virtual_clock_us - hop_start_us;
    apply_network_interceptors_response(session.pipeline, out_resp, ctx.redirect_count, hop_dur_us);

    ctx.body_consumed = true;
    ingest_hop_response_cookies(session, ctx, current_url, samesite_eval, out_resp.set_cookies);

    // Phase 4.5: RFC 9111 HTTP Cache Update & 304 Freshening
    if session.enable_cache {
        cache_ts.response_time = cache_ts.now;
        var hop_req = copy(req);
        hop_req.url.clear();
        hop_req.url.append(current_url.href[..]);
        let resp_dec = on_response(session.cache, hop_req, out_resp, cache_ts, cache_revalidate_idx);
        if resp_dec.kind == ResponseDecisionKind.FreshenAndReturn {
            out_resp = copy(resp_dec.response);
        }
    }

    // Phase 5: 3xx Detection & ComputeRedirectInfo
    let loc_hdr = header(out_resp, "Location");
    let is_red = is_redirect(out_resp) && loc_hdr.len > 0;

    if is_red {
        session.pipeline.metrics.redirect_hops += 1;
    } else {
        finalize_success_response(ctx, out_resp);
        return false, Error { .. };
    }

    let should_continue, red_err = process_redirect_hop(session, ctx, out_resp, current_url, loc_hdr);
    guard ok(red_err) else { return false, red_err; }
    return should_continue, Error { .. };
}

fn check_cache_and_inject_headers(
    session:        Client&,
    req:            const Request&,
    raw_eff_url:    const u8[:],
    cache_ts:       const CacheTimestamps&,
    ctx:            RequestExecutionContext&,
    out_resp:       Response&,
    out_err:        Error&,
    revalidate_idx: i64&,
) -> bool {
    guard session.enable_cache else { return false; }
    var lookup_req = copy(req);
    lookup_req.url.clear();
    lookup_req.url.append(raw_eff_url);
    let lookup_dec = lookup(session.cache, lookup_req, cache_ts.now);
    if lookup_dec.kind == LookupResultKind.Hit {
        out_resp = copy(lookup_dec.cached_response);
        out_err = Error { .. };
        return true;
    }
    if lookup_dec.kind == LookupResultKind.Fail504 {
        out_resp = Response {
            status_code: 504,
            ..
        };
        out_resp.effective_url.append(raw_eff_url);
        out_err = make_error(504, "cache", "504 Gateway Timeout (only-if-cached miss)");
        return true;
    }
    if lookup_dec.kind == LookupResultKind.Revalidate {
        revalidate_idx = lookup_dec.entry_idx;
        if revalidate_idx >= 0 && revalidate_idx < session.cache.entries.len {
            let cond_map = session.cache.entries[revalidate_idx].build_revalidation_headers();
            for &c_entry in cond_map.entries {
                let c_name = cond_map.raw_buf[c_entry.name_begin..c_entry.name_end];
                let c_val = cond_map.raw_buf[c_entry.values_begin..c_entry.values_end];
                ctx.headers.push(make_header(c_name, c_val));
            }
        }
    }
    return false;
}

fn execute_request_inner(session: Client&, req: const Request&) -> Response, Error {
    var raw_eff_url: u8[..2048] = [];
    build_effective_url(session.base_url[..], req.url[..], req.query_params[..], raw_eff_url);

    // Phase -0.5: RFC 6797 HSTS Pre-Flight URL Upgrade (http:// -> https://)
    if session.enable_hsts {
        var upgraded_url: u8[..2048] = [];
        let now_sec = session.virtual_clock_us / 1000000;
        if hsts_upgrade_url(session.hsts, raw_eff_url[..], now_sec, upgraded_url) {
            raw_eff_url.clear();
            raw_eff_url.append(upgraded_url[..]);
        }
    }

    let parsed_initial, parse_err = core::parse_url(raw_eff_url[..]);
    guard parsed_initial.valid else {
        return Response { .. }, make_error(400, "url_parse", "invalid request url");
    }

    let req_time = session.virtual_clock_us / 1000000;
    let req_time_ns = ((session.virtual_clock_us % 1000000) * 1000) as u32;
    var cache_ts = CacheTimestamps {
        request_time: core::unix(req_time, req_time_ns),
        now:          core::unix(req_time, req_time_ns),
    };

    var ctx = init_execution_context(session, req, parsed_initial);

    // Phase 0: RFC 9111 HTTP Cache Lookup & Conditional Header Injection
    var cache_resp = Response { .. };
    var cache_err = Error { .. };
    var cache_revalidate_idx: i64 = -1;
    let cache_hit = check_cache_and_inject_headers(
        session,
        req,
        raw_eff_url[..],
        cache_ts,
        ctx,
        cache_resp,
        cache_err,
        cache_revalidate_idx,
    );
    if cache_hit {
        return cache_resp, cache_err;
    }

    // Main redirect execution loop (Chromium net::URLRequest 6-phase pipeline)
    while ctx.redirect_count <= ctx.max_redirects {
        var resp = Response { .. };
        let should_continue, hop_err = execute_single_hop(
            session,
            ctx,
            req,
            cache_ts,
            cache_revalidate_idx,
            resp,
        );
        guard ok(hop_err) else { return resp, hop_err; }
        if !should_continue {
            return resp, Error { .. };
        }
    }

    return Response { .. }, make_error(310, "redirect", "maximum redirect hops exceeded");
}

fn execute_request(session: Client&, req: const Request&) -> Response, Error {
    let start_us = session.virtual_clock_us;

    // Phase -1: Application Interceptors (Request Hook)
    var active_req = copy(req);
    apply_app_interceptors_request(session.pipeline, active_req, start_us);

    var max_retries: i32  = 0;
    var retry_5xx:   bool = false;
    let has_retry = find_retry_policy(session.pipeline, max_retries, retry_5xx);

    var attempts: i32 = 0;
    while true {
        let resp, err = execute_request_inner(session, active_req);
        if has_retry && attempts < max_retries {
            let can_retry = is_idempotent_method(active_req.method[..]) || has_idempotency_key(active_req);
            let retryable = !ok(err) || (retry_5xx && resp.status_code >= 500 && resp.status_code <= 599);
            if can_retry && retryable {
                attempts += 1;
                continue;
            }
        }

        // Phase 6: Application Interceptors (Response Hook)
        var final_resp = resp;
        let total_dur_us = session.virtual_clock_us - start_us;
        apply_app_interceptors_response(session.pipeline, active_req, final_resp, err, total_dur_us);
        return copy(final_resp), err;
    }
    return Response { .. }, make_error(500, "client", "request execution failed");
}
