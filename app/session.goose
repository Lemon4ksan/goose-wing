// Session state, configuration, and execution pipeline for goose-wing.
// URL, ClientSession, Redirect State Machine, 3-Tier SSRF Guard, and CanonicalCookieJar.
namespace wing;

import std;
import core.url;
import cookie.constants;
import cookie.canonical;
import cookie.policy;
import cookie.engine;
import app.profile;
import app.cookie;
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
    var num = 0;
    var digits = 0;

    for b in clean_ip {
        if b == '.' {
            if digits == 0 || num > 255 || octet_idx >= 3 { return false; }
            octets[octet_idx] = num as i32;
            octet_idx++;
            num = 0;
            digits = 0;
            dot_count++;
        } else if b >= '0' && b <= '9' {
            num = num * 10 + (b - '0');
            digits++;
            if digits > 3 { return false; }
        } else {
            return false;
        }
    }
    if dot_count != 3 || digits == 0 || num > 255 || octet_idx != 3 {
        return false;
    }
    octets[3] = num as i32;

    let o0 = octets[0];
    let o1 = octets[1];

    if o0 == 0 { return true; }                         // 0.0.0.0/8
    if o0 == 10 { return true; }                        // 10.0.0.0/8
    if o0 == 127 { return true; }                       // 127.0.0.0/8 Loopback
    if o0 == 169 && o1 == 254 { return true; }          // 169.254.0.0/16 Link-Local / Cloud Metadata
    if o0 == 172 && (o1 >= 16 && o1 <= 31) { return true; } // 172.16.0.0/12
    if o0 == 192 && o1 == 168 { return true; }          // 192.168.0.0/16
    if o0 == 100 && (o1 >= 64 && o1 <= 127) { return true; } // 100.64.0.0/10 CGNAT
    if o0 >= 224 { return true; }                       // 224.0.0.0/4 Multicast & Reserved

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

fn is_dangerous_service_port(p: i32) -> bool {
    return p == 22 ||   // SSH
           p == 25 ||   // SMTP
           p == 6379 || // Redis
           p == 11211 || // Memcached
           p == 2375 || // Docker
           p == 2376;
}

fn validate_url_against_ssrf(url_val: const Url&, policy: const SsrfGuardPolicy&) -> RedirectError {
    guard policy.enabled else { return RedirectError.None; }

    if policy.https_only && scheme(url_val) != "https" {
        return RedirectError.SchemeDowngradeBlocked;
    }

    let p = effective_port(url_val);
    if policy.denied_ports.len > 0 {
        for denied in policy.denied_ports {
            if p == denied { return RedirectError.SsrfBlockedUrl; }
        }
    }
    if policy.allowed_ports.len > 0 {
        var port_allowed = false;
        for allowed in policy.allowed_ports {
            if p == allowed { port_allowed = true; break; }
        }
        if !port_allowed { return RedirectError.SsrfBlockedUrl; }
    } else if policy.deny_local_network && is_dangerous_service_port(p) {
        return RedirectError.SsrfBlockedUrl;
    }

    let h = hostname(url_val);
    if policy.deny_local_network {
        if is_private_or_reserved_ip(h) {
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

// ---- session factories ----

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

fn allow_port(session: Session&, p: i32) {
    if session.ssrf_guard.allowed_ports.len < 16 {
        session.ssrf_guard.allowed_ports.push(p);
    }
}

fn deny_port(session: Session&, p: i32) {
    if session.ssrf_guard.denied_ports.len < 16 {
        session.ssrf_guard.denied_ports.push(p);
    }
}

fn set_clock_us(session: Session&, now_us: i64) {
    session.virtual_clock_us = now_us;
}

fn trust_location_host(session: Session&, host_name: const u8[:]) {
    if session.trusted_location_hosts.len < 8 {
        var h: u8[..128] = [];
        h.append(host_name);
        to_lower(h[..]);
        session.trusted_location_hosts.push(h);
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
        var sc: u8[..256] = [];
        sc.append(set_cookie_raw);
        route.set_cookies.push(sc);
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
        var ip: u8[..64] = [];
        ip.append(ip_str);
        route.resolved_ips.push(ip);
    }
}

fn add_mock_resolved_ip(session: Session&, ip_str: const u8[:]) {
    if session.mock_routes.len > 0 {
        add_mock_resolved_ip(session.mock_routes[session.mock_routes.len - 1], ip_str);
    }
}

fn set_cookie(session: Session&, name: const u8[:], value: const u8[:]) {
    var raw_hdr: u8[..512] = [];
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

// ---- url resolution helper ----

fn build_effective_url(
    base_url: const u8[:],
    req_url: const u8[:],
    query_params: const QueryItem[:],
    out: u8[..512]&
) {
    out.clear();
    if req_url.len >= 7 && (req_url[..7] == "http://" || (req_url.len >= 8 && req_url[..8] == "https://")) {
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
    current_referrer: u8[..512] = [],
    current_referrer_policy: ReferrerPolicy = ReferrerPolicy.StrictOriginWhenCrossOrigin,
    body: u8[>..] = [],
}

fn execute_request(session: Session&, req: const Request&) -> Response, Error {
    var raw_eff_url: u8[..512] = [];
    build_effective_url(session.base_url[..], req.url[..], req.query_params[..], raw_eff_url);

    let parsed_initial, parse_err = parse_url(raw_eff_url[..]);
    guard parsed_initial.valid else {
        return Response { .. }, make_error(400, "url_parse", "invalid request url");
    }

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

    // Default headers and request headers
    for &dh in session.default_headers {
        ctx.headers.push(copy(dh));
    }
    for &rh in req.headers {
        ctx.headers.push(copy(rh));
    }

    ctx.url_chain.push(parsed_initial);

    // Main redirect execution loop
    while ctx.redirect_count <= ctx.max_redirects {
        let current_url = ctx.url_chain[ctx.url_chain.len - 1];

        // --------------------------------------------------------------------
        // Phase 1: Pre-validation of Hop
        // --------------------------------------------------------------------
        if session.https_only && scheme(current_url) != "https" {
            return Response { .. }, make_error(400, "ssrf_guard", "https_only policy violated");
        }
        let ssrf_err = validate_url_against_ssrf(current_url, session.ssrf_guard);
        if ssrf_err != RedirectError.None {
            return Response { .. }, make_error(403, "ssrf_guard", redirect_error_to_string(ssrf_err));
        }

        // --------------------------------------------------------------------
        // Phase 2: Compute SameSiteCookieContext & Read CanonicalCookieJar
        // --------------------------------------------------------------------
        var samesite_ctx_type = SameSiteContextType.CrossSite;
        let is_first_p = is_first_party(ctx.site_for_cookies, href(current_url), true);
        let safe_method = is_safe_http_method(ctx.current_method[..]);

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

        let samesite_eval = SameSiteCookieContext {
            context_type: samesite_ctx_type,
            schemefully_same: ctx.site_for_cookies.schemefully_same,
            is_reload: ctx.is_reload,
            had_cross_site_hop: ctx.had_cross_site_hop,
        };

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

        // --------------------------------------------------------------------
        // Phase 3: Synthesize Fresh Cookie Header (CVE-2023-45143 Defense)
        // --------------------------------------------------------------------
        remove_header_by_name(ctx.headers, "Cookie");
        if matched_cookies.len > 0 {
            var cookie_hdr_val: u8[..512] = [];
            format_cookie_header_value(cookie_hdr_val, matched_cookies[..]);
            if cookie_hdr_val.len > 0 && ctx.headers.len < 32 {
                ctx.headers.push(make_header("Cookie", cookie_hdr_val[..], true));
            }
        }

        // --------------------------------------------------------------------
        // Phase 4: Network Transaction & Ingest Set-Cookie Before 3xx Analysis
        // --------------------------------------------------------------------
        var dns_rebinding_err = RedirectError.None;
        var resp = execute_mock_or_echo_hop(session, ctx, current_url, dns_rebinding_err);
        if dns_rebinding_err != RedirectError.None {
            return Response { .. }, make_error(403, "ssrf_guard", redirect_error_to_string(dns_rebinding_err));
        }
        ctx.body_consumed = true;

        // Ingest response Set-Cookie headers into CanonicalCookieJar
        for &sc in resp.set_cookies {
            var def_path: u8[..256] = [];
            default_cookie_path_calc(pathname(current_url), def_path);
            var parsed_c, cause, ok_c = parse_canonical_set_cookie(sc[..], hostname(current_url), def_path[..], session.virtual_clock_us);
            if ok_c {
                let can_write, code = can_set_canonical_cookie_for_context(
                    parsed_c,
                    samesite_eval,
                    ctx.is_main_frame,
                    is_secure_scheme(current_url)
                );
                if can_write {
                    set_cookie_header(session.jar, href(current_url), sc[..], session.virtual_clock_us);
                }
            }
        }

        // --------------------------------------------------------------------
        // Phase 5: 3xx Detection & ComputeRedirectInfo
        // --------------------------------------------------------------------
        let loc_hdr = header(resp, "Location");
        let is_red = is_redirect(resp) && loc_hdr.len > 0;

        if !is_red {
            // Final response reached
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
            return resp, no_error();
        }

        // Redirect received
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

        // --------------------------------------------------------------------
        // Phase 6: Sanitization & Body Rewind (Request.GetBody Pattern)
        // --------------------------------------------------------------------
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
                return resp, make_error(400, "body_rewind", "http: cannot rewind body");
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

        ctx.url_chain.push(redirect_info.new_url);
        ctx.redirect_count += 1;
    }

    return Response { .. }, make_error(310, "redirect", "maximum redirect hops exceeded");
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
            if route.resolved_ips.len > 0 {
                var ips_slice: const u8[:][4] = ["", "", "", ""];
                for idx in route.resolved_ips.len {
                    ips_slice[idx] = route.resolved_ips[idx][..];
                }
                let dns_err = validate_resolved_ips_against_ssrf(ips_slice[..route.resolved_ips.len], session.ssrf_guard);
                if dns_err != RedirectError.None {
                    out_dns_err = dns_err;
                    return Response {
                        status_code: 403,
                        effective_url: copy(current_url.href),
                        ..
                    };
                }
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

// ---- high-level dispatch entry points ----

fn do(session: Session&, req: const Request&) -> Response, Error {
    return execute_request(session, req);
}

// Last-mile closure overload: clones `req`, applies `F(&copy_req)`, and dispatches
fn do<F: fn(Request&)>(session: Session&, req: const Request&) -> Response, Error {
    var modified = copy(req);
    F(&modified);
    return do(session, modified);
}

// ---- express verbs ----

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
