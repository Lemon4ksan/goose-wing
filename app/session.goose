// Session state, configuration, and execution pipeline for goose-wing.
// URL, ClientSession, Redirect State Machine, 3-Tier SSRF Guard, and CanonicalCookieJar.
//
// Core Types:
//   SsrfGuardPolicy         - 3-tier SSRF defense policy (loopback, private ranges, cloud metadata, dangerous ports).
//   SessionConfig           - Declarative initial configuration for ClientSession.
//   Session                 - Stateful HTTP client session with cookie jar, redirect state machine, and SSRF guard.
//   MockExchange            - Deterministic mock routing exchange for unit and end-to-end integration testing.
//   RequestExecutionContext - Internal pipeline state container tracking hop history, headers, and security contexts.
//
// Standards & Specifications:
//   Chromium net::URLRequest 6-phase pipeline architecture.
//   RFC 9110 HTTP Redirection, Method mutation, and Request.GetBody body rewinding.
//   RFC 6265bis Schemeful Same-Site & CHIPS partition key injection.
//   RFC 1918 / RFC 3927 Cloud metadata & DNS rebinding protection.
namespace wing;

import std;
import core.url;
import cookie.constants;
import cookie.canonical;
import cookie.policy;
import cookie.engine;
import app.profile;
import app.request;
import app.response;
import app.redirect;

// ---- ssrf guard policy and 3-tier checks -----------------------------------

struct SsrfGuardPolicy {
    enabled: bool = false,
    https_only: bool = false,
    deny_local_network: bool = true,
    allowed_ports: i32[..16] = [],
    denied_ports: i32[..16] = [],
}

fn new_ssrf_guard_policy() -> SsrfGuardPolicy {
    return SsrfGuardPolicy {
        enabled: true,
        https_only: false,
        deny_local_network: true,
        allowed_ports: [],
        denied_ports: [],
    };
}

fn is_private_ipv4(clean_ip: const u8[:]) -> bool {
    var dot_count = 0;
    var octets: i32[4] = [0, 0, 0, 0];
    var octet_idx = 0;
    var current_num = 0;
    var digits_count = 0;

    for char_byte in clean_ip {
        if char_byte == '.' {
            if digits_count == 0 || current_num > 255 || octet_idx >= 3 { return false; }
            octets[octet_idx] = current_num as i32;
            octet_idx++;
            current_num = 0;
            digits_count = 0;
            dot_count++;
        } else if char_byte >= '0' && char_byte <= '9' {
            current_num = current_num * 10 + (char_byte - '0');
            digits_count++;
            if digits_count > 3 { return false; }
        } else {
            return false;
        }
    }
    if dot_count != 3 || digits_count == 0 || current_num > 255 || octet_idx != 3 {
        return false;
    }
    octets[3] = current_num as i32;

    let octet0 = octets[0];
    let octet1 = octets[1];

    if octet0 == 0 { return true; }                             // 0.0.0.0/8
    if octet0 == 10 { return true; }                            // 10.0.0.0/8
    if octet0 == 127 { return true; }                           // 127.0.0.0/8 Loopback
    if octet0 == 169 && octet1 == 254 { return true; }          // 169.254.0.0/16 Link-Local / Cloud Metadata
    if octet0 == 172 && (octet1 >= 16 && octet1 <= 31) { return true; } // 172.16.0.0/12
    if octet0 == 192 && octet1 == 168 { return true; }          // 192.168.0.0/16
    if octet0 == 100 && (octet1 >= 64 && octet1 <= 127) { return true; } // 100.64.0.0/10 CGNAT
    if octet0 >= 224 { return true; }                           // 224.0.0.0/4 Multicast & Reserved

    return false;
}

// IP Literal Classification for RFC 1918, RFC 3927 (Link-Local / Cloud Metadata), Loopback
fn is_private_or_reserved_ip(ip_str: const u8[:]) -> bool {
    guard ip_str.len > 0 else { return false; }

    // Check IPv6 loopback and special ranges
    if ip_str == "::1" || ip_str == "[::1]" || ip_str == "::" || ip_str == "[::]" {
        return true;
    }
    let clean_ip = if ip_str.len > 2 && ip_str[0] == '[' && ip_str[ip_str.len - 1] == ']' {
        ip_str[1..ip_str.len - 1]
    } else {
        ip_str
    };

    if starts_with(clean_ip, "fc") || starts_with(clean_ip, "fd") || // Unique Local fc00::/7
       starts_with(clean_ip, "fe8") || starts_with(clean_ip, "fe9") || // Link-local fe80::/10
       starts_with(clean_ip, "fea") || starts_with(clean_ip, "feb") {
        return true;
    }

    // IPv4-mapped IPv6 ::ffff:x.x.x.x
    if starts_with(clean_ip, "::ffff:") {
        return is_private_ipv4(clean_ip[7..]);
    }

    return is_private_ipv4(clean_ip);
}

fn is_dangerous_service_port(port_num: i32) -> bool {
    return port_num == 22 ||    // SSH
           port_num == 25 ||    // SMTP
           port_num == 6379 ||  // Redis
           port_num == 11211 || // Memcached
           port_num == 2375 ||  // Docker
           port_num == 2376;
}

fn validate_url_against_ssrf(url_val: const Url&, policy: const SsrfGuardPolicy&) -> RedirectError {
    guard policy.enabled else { return RedirectError.None; }

    if policy.https_only && scheme(url_val) != "https" {
        return RedirectError.SchemeDowngradeBlocked;
    }

    let port_val = effective_port(url_val);
    if policy.denied_ports.len > 0 {
        for denied in policy.denied_ports {
            if port_val == denied { return RedirectError.SsrfBlockedUrl; }
        }
    }
    if policy.allowed_ports.len > 0 {
        var port_allowed = false;
        for allowed in policy.allowed_ports {
            if port_val == allowed { port_allowed = true; break; }
        }
        if !port_allowed { return RedirectError.SsrfBlockedUrl; }
    } else if policy.deny_local_network && is_dangerous_service_port(port_val) {
        return RedirectError.SsrfBlockedUrl;
    }

    let host_str = hostname(url_val);
    if policy.deny_local_network {
        if is_private_or_reserved_ip(host_str) {
            return RedirectError.SsrfBlockedIp;
        }
    }

    return RedirectError.None;
}

fn validate_resolved_ips_against_ssrf(ips: const u8[:][:], policy: const SsrfGuardPolicy&) -> RedirectError {
    guard policy.enabled && policy.deny_local_network else { return RedirectError.None; }
    for ip in ips {
        if is_private_or_reserved_ip(ip) {
            return RedirectError.SsrfBlockedIp;
        }
    }
    return RedirectError.None;
}

// ---- mock routing for deterministic multi-hop testing ----------------------

struct MockExchange {
    pattern_url: u8[..256] = [],
    method: u8[..16] = [],
    status_code: i32 = 200,
    headers: HeaderItem[..16] = [],
    set_cookies: u8[..256][..8] = [],
    resolved_ips: u8[..64][..4] = [],
    body: u8[..2048] = [],
}

// ---- session configuration and state ---------------------------------------

struct SessionConfig {
    base_url: const u8[:] = "",
    profile: Profile = Profile.None,
    proxy_url: const u8[:] = "",
    timeout_ms: i64 = 15000,
    follow_redirects: bool = true,
    cookie_jar: bool = true,
}

struct Session {
    base_url: u8[..256] = [],
    profile: Profile = Profile.None,
    proxy_url: u8[..256] = [],
    timeout_ms: i64 = 15000,
    follow_redirects: bool = true,
    redirect_mode: RedirectMode = RedirectMode.Follow,
    max_redirects: i64 = 10,
    https_only: bool = false,
    enable_referer: bool = true,
    default_referrer_policy: ReferrerPolicy = ReferrerPolicy.StrictOriginWhenCrossOrigin,
    default_headers: HeaderItem[..16] = [],
    ssrf_guard: SsrfGuardPolicy = SsrfGuardPolicy { .. },
    virtual_clock_us: i64 = 1700000000000000,
    trusted_location_hosts: u8[..128][..8] = [],
    mock_routes: MockExchange[..16] = [],
    jar: CanonicalCookieJar = CanonicalCookieJar { .. },
}

// ---- session factories -----------------------------------------------------

fn new_session() -> Session {
    var sess = Session {
        jar: new_canonical_cookie_jar(),
        ssrf_guard: SsrfGuardPolicy { .. },
        ..
    };
    return sess;
}

fn new_session(cfg: SessionConfig) -> Session {
    var session = Session {
        profile: cfg.profile,
        timeout_ms: cfg.timeout_ms,
        follow_redirects: cfg.follow_redirects,
        jar: new_canonical_cookie_jar(),
        ssrf_guard: SsrfGuardPolicy { .. },
        ..
    };
    session.base_url.append(cfg.base_url);
    session.proxy_url.append(cfg.proxy_url);
    return session;
}

fn new_session(base_url: const u8[:]) -> Session {
    var session = new_session();
    session.base_url.append(base_url);
    return session;
}

fn new_session<F: fn(Session&)>(base_url: const u8[:]) -> Session {
    var session = new_session(base_url);
    F(&session);
    return session;
}

fn new_session<F: fn(Session&)>() -> Session {
    var session = new_session();
    F(&session);
    return session;
}

// ---- ufcs session mutators & configuration ---------------------------------

fn set_base_url(session: Session&, url: const u8[:]) {
    session.base_url.clear();
    session.base_url.append(url);
}

fn set_profile(session: Session&, profile: Profile) {
    session.profile = profile;
}

fn set_proxy(session: Session&, proxy_url: const u8[:]) {
    session.proxy_url.clear();
    session.proxy_url.append(proxy_url);
}

fn set_timeout_ms(session: Session&, ms: i64) {
    session.timeout_ms = ms;
}

fn set_redirect_mode(session: Session&, mode: RedirectMode) {
    session.redirect_mode = mode;
    session.follow_redirects = (mode == RedirectMode.Follow);
}

fn set_max_redirects(session: Session&, count: i64) {
    session.max_redirects = count;
}

fn set_https_only(session: Session&, enabled: bool) {
    session.https_only = enabled;
    session.ssrf_guard.https_only = enabled;
}

fn set_enable_referer(session: Session&, enabled: bool) {
    session.enable_referer = enabled;
}

fn set_referrer_policy(session: Session&, policy: ReferrerPolicy) {
    session.default_referrer_policy = policy;
}

fn enable_ssrf_guard(session: Session&, deny_local_network: bool = true) {
    session.ssrf_guard.enabled = true;
    session.ssrf_guard.deny_local_network = deny_local_network;
}

fn allow_port(session: Session&, port_num: i32) {
    if session.ssrf_guard.allowed_ports.len < 16 {
        session.ssrf_guard.allowed_ports.push(port_num);
    }
}

fn deny_port(session: Session&, port_num: i32) {
    if session.ssrf_guard.denied_ports.len < 16 {
        session.ssrf_guard.denied_ports.push(port_num);
    }
}

fn set_clock_us(session: Session&, now_us: i64) {
    session.virtual_clock_us = now_us;
}

fn trust_location_host(session: Session&, host_name: const u8[:]) {
    if session.trusted_location_hosts.len < 8 {
        var host_buf: u8[..128] = [];
        host_buf.append(host_name);
        to_lower(host_buf[..]);
        session.trusted_location_hosts.push(host_buf);
    }
}

fn is_trusted_location_host(session: const Session&, host_name: const u8[:]) -> bool {
    for &h in session.trusted_location_hosts {
        if eq_ascii_fold(h[..], host_name) { return true; }
    }
    return false;
}

fn mock_route(
    session: Session&,
    method: const u8[:],
    pattern_url: const u8[:],
    status_code: i32,
    body_str: const u8[:]
) -> MockExchange& {
    var route = MockExchange {
        status_code: status_code,
        ..
    };
    route.method.append(method);
    route.pattern_url.append(pattern_url);
    route.body.append(body_str);
    return session.mock_routes.push(route);
}

fn add_mock_set_cookie(route: MockExchange&, set_cookie_raw: const u8[:]) {
    if route.set_cookies.len < 8 {
        var cookie_buf: u8[..256] = [];
        cookie_buf.append(set_cookie_raw);
        route.set_cookies.push(cookie_buf);
    }
}

fn add_mock_set_cookie(session: Session&, set_cookie_raw: const u8[:]) {
    if session.mock_routes.len > 0 {
        add_mock_set_cookie(session.mock_routes[session.mock_routes.len - 1], set_cookie_raw);
    }
}

fn add_mock_header(route: MockExchange&, name: const u8[:], value: const u8[:]) {
    if route.headers.len < 16 {
        route.headers.push(make_header(name, value));
    }
}

fn add_mock_header(session: Session&, name: const u8[:], value: const u8[:]) {
    if session.mock_routes.len > 0 {
        add_mock_header(session.mock_routes[session.mock_routes.len - 1], name, value);
    }
}

fn add_mock_resolved_ip(route: MockExchange&, ip_str: const u8[:]) {
    if route.resolved_ips.len < 4 {
        var ip_buf: u8[..64] = [];
        ip_buf.append(ip_str);
        route.resolved_ips.push(ip_buf);
    }
}

fn add_mock_resolved_ip(session: Session&, ip_str: const u8[:]) {
    if session.mock_routes.len > 0 {
        add_mock_resolved_ip(session.mock_routes[session.mock_routes.len - 1], ip_str);
    }
}

fn set_cookie(session: Session&, name: const u8[:], value: const u8[:]) {
    var raw_hdr: u8[..2048] = [];
    raw_hdr.append(name);
    raw_hdr.push('=');
    raw_hdr.append(value);
    raw_hdr.append("; Path=/");
    if session.base_url.len > 0 {
        set_cookie_header(session.jar, session.base_url[..], raw_hdr[..], session.virtual_clock_us);
    } else {
        set_cookie_header(session.jar, "https://example.com/", raw_hdr[..], session.virtual_clock_us);
    }
}

fn cookie(session: const Session&, name: const u8[:]) -> const u8[:] {
    return get(session.jar, name);
}

fn default_header(session: Session&, name: const u8[:], value: const u8[:]) {
    if session.default_headers.len < 16 {
        session.default_headers.push(make_header(name, value));
    }
}

// ---- url resolution helper -------------------------------------------------

fn build_effective_url(
    base_url: const u8[:],
    req_url: const u8[:],
    query_params: const QueryItem[:],
    out: u8[..2048]&
) {
    out.clear();
    let parsed_base = new_url(base_url);
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

    if query_params.len > 0 {
        var has_query_mark = false;
        for char_byte in out {
            if char_byte == '?' { has_query_mark = true; break; }
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
    }
}

// ---- 6-phase execution pipeline (execute_pipeline) -------------------------

struct RequestExecutionContext {
    url_chain: Url[..16] = [],
    current_method: u8[..16] = [],
    headers: HeaderItem[..32] = [],
    rewind_buf: u8[..4096] = [],
    rewindable: bool = true,
    body_consumed: bool = false,
    initiator: Origin = Origin { .. },
    has_initiator: bool = false,
    top_frame_origin: Origin = Origin { .. },
    site_for_cookies: SiteForCookies = SiteForCookies { .. },
    first_party_policy: FirstPartyURLPolicy = FirstPartyURLPolicy.UPDATE_FIRST_PARTY_URL_ON_REDIRECT,
    is_main_frame: bool = true,
    is_reload: bool = false,
    redirect_mode: RedirectMode = RedirectMode.Follow,
    redirect_count: i64 = 0,
    max_redirects: i64 = 10,
    tainted_origin: bool = false,
    had_cross_site_hop: bool = false,
    cors_mode: bool = false,
    current_referrer: u8[..2048] = [],
    current_referrer_policy: ReferrerPolicy = ReferrerPolicy.StrictOriginWhenCrossOrigin,
    body: u8[>..] = [],
}

fn validate_hop_prerequisites(session: const Session&, current_url: const Url&) -> Error {
    if session.https_only && scheme(current_url) != "https" {
        return make_error(400, "ssrf_guard", "https_only policy violated");
    }
    let ssrf_err = validate_url_against_ssrf(current_url, session.ssrf_guard);
    if ssrf_err != RedirectError.None {
        return make_error(403, "ssrf_guard", redirect_error_to_string(ssrf_err));
    }
    return no_error();
}

fn compute_hop_samesite_context(
    ctx: const RequestExecutionContext&,
    current_url: const Url&,
    safe_method: bool,
) -> SameSiteCookieContext {
    var samesite_ctx_type = SameSiteContextType.CrossSite;
    let is_first_p = is_first_party(ctx.site_for_cookies, href(current_url), true);

    if ctx.is_main_frame {
        if ctx.had_cross_site_hop {
            samesite_ctx_type = if safe_method { SameSiteContextType.SameSiteLax } else { SameSiteContextType.CrossSite };
        } else if is_first_p {
            samesite_ctx_type = SameSiteContextType.SameSiteStrict;
        } else if safe_method {
            samesite_ctx_type = SameSiteContextType.SameSiteLax;
        } else {
            samesite_ctx_type = SameSiteContextType.SameSiteLaxMethodUnsafe;
        }
    } else {
        if ctx.had_cross_site_hop || !is_first_p {
            samesite_ctx_type = SameSiteContextType.CrossSite;
        } else {
            samesite_ctx_type = SameSiteContextType.SameSiteStrict;
        }
    }

    return SameSiteCookieContext {
        context_type: samesite_ctx_type,
        schemefully_same: ctx.site_for_cookies.schemefully_same,
        is_reload: ctx.is_reload,
        had_cross_site_hop: ctx.had_cross_site_hop,
    };
}

fn prepare_hop_cookie_header(
    session: Session&,
    ctx: RequestExecutionContext&,
    current_url: const Url&,
    samesite_eval: const SameSiteCookieContext&,
    safe_method: bool,
) {
    var matched_cookies: CanonicalCookie[>..] = [];
    get_canonical_cookies_for_request(
        session.jar,
        hostname(current_url),
        pathname(current_url),
        scheme(current_url),
        effective_port(current_url),
        is_secure_scheme(current_url),
        true,
        "",
        session.virtual_clock_us,
        matched_cookies,
        samesite_eval.context_type != SameSiteContextType.CrossSite,
        ctx.is_main_frame,
        safe_method
    );

    remove_header_by_name(ctx.headers, "Cookie");
    if matched_cookies.len > 0 {
        var cookie_hdr_val: u8[..2048] = [];
        format_cookie_header_value(cookie_hdr_val, matched_cookies[..]);
        if cookie_hdr_val.len > 0 && ctx.headers.len < 32 {
            ctx.headers.push(make_header("Cookie", cookie_hdr_val[..], true));
        }
    }
}

fn ingest_hop_response_cookies(
    session: Session&,
    ctx: const RequestExecutionContext&,
    current_url: const Url&,
    samesite_eval: const SameSiteCookieContext&,
    set_cookies: const u8[..256][..16]&,
) {
    for &set_cookie_str in set_cookies {
        var def_path: u8[..256] = [];
        default_cookie_path_calc(pathname(current_url), def_path);
        var parsed_cookie, parse_cause, cookie_ok = parse_canonical_set_cookie(set_cookie_str[..], hostname(current_url), def_path[..], session.virtual_clock_us);
        if cookie_ok {
            let can_write, code = can_set_canonical_cookie_for_context(
                parsed_cookie,
                samesite_eval,
                ctx.is_main_frame,
                is_secure_scheme(current_url)
            );
            if can_write {
                set_cookie_header(session.jar, href(current_url), set_cookie_str[..], session.virtual_clock_us);
            }
        }
    }
}

fn finalize_success_response(ctx: const RequestExecutionContext&, resp: Response&) {
    resp.redirect_count = ctx.redirect_count;
    resp.final_method.clear();
    resp.final_method.append(ctx.current_method[..]);
    for &hop_u in ctx.url_chain {
        if resp.url_chain.len < 16 {
            var u_str: u8[..256] = [];
            u_str.append(href(hop_u));
            resp.url_chain.push(u_str);
        }
    }
}

fn apply_redirect_transition(
    session: const Session&,
    ctx: RequestExecutionContext&,
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
        ctx.cors_mode,
        ctx.tainted_origin,
        session.enable_referer,
        is_trusted
    );
    return no_error();
}

fn init_execution_context(session: const Session&, req: const Request&, parsed_initial: const Url&) -> RequestExecutionContext {
    var ctx = RequestExecutionContext {
        current_method: copy(req.method),
        rewindable: req.rewindable,
        body_consumed: false,
        cors_mode: req.cors_mode,
        tainted_origin: req.tainted_origin,
        is_main_frame: req.is_main_frame,
        is_reload: req.is_reload,
        redirect_mode: session.redirect_mode,
        redirect_count: 0,
        max_redirects: session.max_redirects,
        first_party_policy: req.first_party_policy,
        current_referrer_policy: session.default_referrer_policy,
        ..
    };

    ctx.body.append(req.body[..]);
    ctx.rewind_buf.append(req.rewind_buf[..]);

    if req.has_initiator {
        ctx.initiator = copy(req.initiator);
        ctx.has_initiator = true;
    } else {
        ctx.initiator = origin_from_url(parsed_initial);
        ctx.has_initiator = true;
    }

    if req.has_site_for_cookies {
        ctx.site_for_cookies = copy(req.site_for_cookies);
    } else {
        ctx.site_for_cookies = site_for_cookies_from_parsed_url(parsed_initial);
    }

    for &default_hdr in session.default_headers {
        ctx.headers.push(copy(default_hdr));
    }
    for &req_hdr in req.headers {
        ctx.headers.push(copy(req_hdr));
    }

    ctx.url_chain.push(parsed_initial);
    return ctx;
}

fn execute_request(session: Session&, req: const Request&) -> Response, Error {
    var raw_eff_url: u8[..2048] = [];
    build_effective_url(session.base_url[..], req.url[..], req.query_params[..], raw_eff_url);

    let parsed_initial, parse_err = parse_url(raw_eff_url[..]);
    guard parsed_initial.valid else {
        return Response { .. }, make_error(400, "url_parse", "invalid request url");
    }

    var ctx = init_execution_context(session, req, parsed_initial);

    // Main redirect execution loop (Chromium net::URLRequest 6-phase pipeline)
    while ctx.redirect_count <= ctx.max_redirects {
        let current_url = ctx.url_chain[ctx.url_chain.len - 1];

        // Phase 1: Pre-validation of Hop
        let pre_err = validate_hop_prerequisites(session, current_url);
        guard ok(pre_err) else { return Response { .. }, pre_err; }

        // Phase 2 & 3: Compute SameSite Context & Synthesize Fresh Cookie Header
        let safe_method = is_safe_http_method(ctx.current_method[..]);
        let samesite_eval = compute_hop_samesite_context(ctx, current_url, safe_method);
        prepare_hop_cookie_header(session, ctx, current_url, samesite_eval, safe_method);

        // Phase 4: Network Transaction & Ingest Set-Cookie Before 3xx Analysis
        var dns_rebinding_err = RedirectError.None;
        var resp = execute_mock_or_echo_hop(session, ctx, current_url, dns_rebinding_err);
        guard dns_rebinding_err == RedirectError.None else {
            return Response { .. }, make_error(403, "ssrf_guard", redirect_error_to_string(dns_rebinding_err));
        }
        ctx.body_consumed = true;
        ingest_hop_response_cookies(session, ctx, current_url, samesite_eval, resp.set_cookies);

        // Phase 5: 3xx Detection & ComputeRedirectInfo
        let loc_hdr = header(resp, "Location");
        let is_red = is_redirect(resp) && loc_hdr.len > 0;

        if !is_red {
            finalize_success_response(ctx, resp);
            return resp, no_error();
        }

        if ctx.redirect_mode == RedirectMode.Manual {
            resp.redirect_count = ctx.redirect_count;
            return resp, no_error();
        }
        if ctx.redirect_mode == RedirectMode.Error {
            return resp, make_error(310, "redirect", "redirects disabled by mode");
        }
        if ctx.redirect_count >= ctx.max_redirects {
            return resp, make_error(310, "redirect", "maximum redirect hops exceeded");
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
            ctx.has_initiator,
            ctx.cors_mode,
            ctx.tainted_origin,
            ctx.is_main_frame,
            ctx.had_cross_site_hop
        );

        guard redirect_info.error == RedirectError.None else {
            return resp, make_error(310, "redirect", redirect_error_to_string(redirect_info.error));
        }

        // Phase 6: Sanitization & Body Rewind
        let redirect_err = apply_redirect_transition(session, ctx, redirect_info);
        guard ok(redirect_err) else { return resp, redirect_err; }

        ctx.url_chain.push(redirect_info.new_url);
        ctx.redirect_count += 1;
    }

    return Response { .. }, make_error(310, "redirect", "maximum redirect hops exceeded");
}

fn validate_mock_route_dns(route: const MockExchange&, guard_config: const SSRFGuardConfig&) -> RedirectError {
    if route.resolved_ips.len == 0 {
        return RedirectError.None;
    }
    var ips_slice: const u8[:][4] = ["", "", "", ""];
    for idx in route.resolved_ips.len {
        ips_slice[idx] = route.resolved_ips[idx][..];
    }
    return validate_resolved_ips_against_ssrf(ips_slice[..route.resolved_ips.len], guard_config);
}

fn execute_mock_or_echo_hop(
    session: Session&,
    ctx: RequestExecutionContext&,
    current_url: const Url&,
    out_dns_err: RedirectError&
) -> Response {
    out_dns_err = RedirectError.None;
    let curr_href = href(current_url);
    let curr_method = ctx.current_method[..];

    // Check mock routes
    for &route in session.mock_routes {
        if (route.method.len == 0 || eq_ascii_fold(route.method[..], curr_method)) &&
           (route.pattern_url[..] == curr_href || starts_with(curr_href, route.pattern_url[..])) {
            // Validate DNS IPs for SSRF Rebinding Guard
            let dns_err = validate_mock_route_dns(route, session.ssrf_guard);
            if dns_err != RedirectError.None {
                out_dns_err = dns_err;
                return Response {
                    status_code: 403,
                    effective_url: copy(current_url.href),
                    ..
                };
            }

            var resp = Response {
                status_code: route.status_code,
                effective_url: copy(current_url.href),
                ..
            };
            for &h in route.headers {
                resp.headers.push(copy(h));
            }
            for &sc in route.set_cookies {
                resp.set_cookies.push(copy(sc));
            }
            resp.body.append(route.body[..]);
            for &sent_h in ctx.headers {
                resp.sent_headers.push(copy(sent_h));
            }
            return resp;
        }
    }

    // Default mock response
    var resp = Response {
        status_code: 200,
        effective_url: copy(current_url.href),
        ..
    };
    resp.headers.push(make_header("Content-Type", "application/json"));
    resp.headers.push(make_header("Server", "goose-wing/1.0"));
    resp.body.append("{\"id\":1042,\"status\":\"confirmed\",\"ok\":true}");

    for &sent_h in ctx.headers {
        resp.sent_headers.push(copy(sent_h));
    }
    return resp;
}

// ---- high-level dispatch entry points --------------------------------------

fn do(session: Session&, req: const Request&) -> Response, Error {
    return execute_request(session, req);
}

// Last-mile closure overload: clones `req`, applies `F(&copy_req)`, and dispatches
fn do<F: fn(Request&)>(session: Session&, req: const Request&) -> Response, Error {
    var modified = copy(req);
    F(&modified);
    return do(session, modified);
}

// ---- express verbs ---------------------------------------------------------

fn get(session: Session&, url: const u8[:]) -> Response, Error {
    let req = new_request("GET", url);
    return do(session, req);
}

fn get<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("GET", url);
    F(&req);
    return do(session, req);
}

fn post<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("POST", url);
    F(&req);
    return do(session, req);
}

fn post_json<T>(session: Session&, url: const u8[:], payload: const T&) -> Response, Error {
    var req = new_request("POST", url);
    json(req, payload);
    return do(session, req);
}

fn put<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("PUT", url);
    F(&req);
    return do(session, req);
}

fn put_json<T>(session: Session&, url: const u8[:], payload: const T&) -> Response, Error {
    var req = new_request("PUT", url);
    json(req, payload);
    return do(session, req);
}

fn delete(session: Session&, url: const u8[:]) -> Response, Error {
    let req = new_request("DELETE", url);
    return do(session, req);
}

fn delete<F: fn(Request&)>(session: Session&, url: const u8[:]) -> Response, Error {
    var req = new_request("DELETE", url);
    F(&req);
    return do(session, req);
}
