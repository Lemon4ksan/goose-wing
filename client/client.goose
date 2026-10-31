// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Client session facade, configuration models, and lifecycle methods.
namespace wing;

import std;
import cookie.constants;
import cookie.canonical;
import cookie.policy;
import cookie.engine;
import fingerprint.ja4;
import fingerprint.profile;
import client.profile;
import client.request;
import client.response;
import client.redirect;
import http.headers;
import http.cache.cache_control;
import http.cache.freshness;
import http.cache.validators;
import http.cache.engine;
import net.dns;
import tls.ech;
import http.altsvc;
import net.happy_eyeballs;
import http.compression_dict;
import http.hsts;
import client.interceptor;
import client.stream;
import client.session.ssrf;
import client.session.mock;
import net.pool;

// ---- client configuration and state ----------------------------------------

struct ClientConfig {
    base_url:                const u8[:]  = "",
    profile:                 Profile      = Profile.Wing,
    proxy_url:               const u8[:]  = "",
    timeout_ms:              i64          = 15000,
    follow_redirects:        bool         = true,
    cookie_jar:              bool         = true,
    enable_cache:            bool         = false,
    cache_options:           CacheOptions = CacheOptions { .. },
    enable_altsvc:           bool         = true,
    enable_protocol_racing:  bool         = true,
    quic_race_delay_ms:      i64          = 200,
    enable_compression_dict: bool         = true,
}

type SessionConfig = ClientConfig;

struct ClientCredentials {
    username:        u8[..64] = [],
    password:        u8[..64] = [],
    has_credentials: bool     = false,
    nonce_counter:   u32      = 1,
    cnonce:          u8[..32] = "f2/IZUnWe0rEzWeA",
}

struct Client {
    base_url:                u8[..256]         = [],
    profile:                 Profile           = Profile.Wing,
    profile_spec:            BrowserProfile    = BrowserProfile { .. },
    proxy_url:               u8[..256]         = [],
    timeout_ms:              i64               = 15000,
    follow_redirects:        bool              = true,
    redirect_mode:           RedirectMode      = RedirectMode.Follow,
    max_redirects:           i64               = 10,
    https_only:              bool              = false,
    enable_referer:          bool              = true,
    default_referrer_policy: ReferrerPolicy    = ReferrerPolicy.StrictOriginWhenCrossOrigin,
    default_headers:         HeaderItem[..16]  = [],
    ssrf_guard:              SsrfGuardPolicy   = SsrfGuardPolicy { .. },
    virtual_clock_us:        i64               = 1700000000000000,
    trusted_location_hosts:  u8[..128][..8]    = [],
    mock_routes:             MockExchange[..8] = [],

    // RFC 9111 HTTP Cache Engine
    cache:        HttpCache = HttpCache { .. },
    enable_cache: bool      = false,

    // RFC 8484 DNS-over-HTTPS (DoH) & RFC 9460 Automated ECH Discovery
    doh:                DohResolver = DohResolver { .. },
    enable_doh:         bool        = false,
    enable_ech:         bool        = false,
    auto_ech_discovery: bool        = false,
    dns_cache:          DnsCache    = DnsCache { .. },

    // RFC 7838 Alt-Svc & Chromium Protocol Racing
    altsvc:                 AltSvcCache = AltSvcCache { .. },
    enable_altsvc:          bool        = true,
    enable_protocol_racing: bool        = true,
    quic_race_delay_ms:     i64         = 200,

    // Compression Dictionary Transport (Chrome 123+ dcz/dcb)
    dict_cache:              DictionaryCache = DictionaryCache { .. },
    enable_compression_dict: bool            = true,

    // OkHttp/Tower-style 2-tier Interceptor Pipeline (Application & Network)
    pipeline: InterceptorPipeline = InterceptorPipeline { .. },

    // RFC 7616 Digest & RFC 7617 Basic Authenticator
    creds: ClientCredentials = ClientCredentials { .. },

    // RFC 6797 HTTP Strict Transport Security (HSTS)
    hsts:        HstsCache = HstsCache { .. },
    enable_hsts: bool      = true,

    // L4 / L7 Resilient connection pool (Keep-Alive, IP coalescing, WantQueue)
    pool: StreamPool = StreamPool { .. },

    // Resizable field must be final
    jar: CanonicalCookieJar = CanonicalCookieJar { .. },
}

type Session = Client;

// ---- client factories ------------------------------------------------------

fn new_client() -> Client {
    var c = Client {
        profile:                 Profile.Wing,
        ssrf_guard:              SsrfGuardPolicy { .. },
        cache:                   new_http_cache(),
        enable_cache:            false,
        altsvc:                  AltSvcCache { .. },
        enable_altsvc:           true,
        enable_protocol_racing:  true,
        quic_race_delay_ms:      200,
        dict_cache:              DictionaryCache { .. },
        enable_compression_dict: true,
        pipeline:                InterceptorPipeline { .. },
        hsts:                    HstsCache { .. },
        enable_hsts:             true,
        pool:                    new_stream_pool(),
        jar:                     CanonicalCookieJar { .. },
        ..
    };
    let def_p = wing_default_profile();
    apply_profile(c, def_p);
    return c;
}

fn new_client(cfg: ClientConfig) -> Client {
    var client = Client {
        profile:                 cfg.profile,
        timeout_ms:              cfg.timeout_ms,
        follow_redirects:        cfg.follow_redirects,
        redirect_mode:           if cfg.follow_redirects { RedirectMode.Follow } else { RedirectMode.Manual },
        ssrf_guard:              SsrfGuardPolicy { .. },
        cache:                   new_http_cache(cfg.cache_options),
        enable_cache:            cfg.enable_cache,
        altsvc:                  AltSvcCache { .. },
        enable_altsvc:           cfg.enable_altsvc,
        enable_protocol_racing:  cfg.enable_protocol_racing,
        quic_race_delay_ms:      cfg.quic_race_delay_ms,
        dict_cache:              DictionaryCache { .. },
        enable_compression_dict: cfg.enable_compression_dict,
        pipeline:                InterceptorPipeline { .. },
        hsts:                    HstsCache { .. },
        enable_hsts:             true,
        pool:                    new_stream_pool(),
        jar:                     CanonicalCookieJar { .. },
        ..
    };
    client.base_url.append(cfg.base_url);
    client.proxy_url.append(cfg.proxy_url);
    if cfg.profile != Profile.None {
        set_profile(client, cfg.profile);
    }
    return client;
}

fn new_client(base_url: const u8[:]) -> Client {
    var client = new_client();
    client.base_url.append(base_url);
    return client;
}

fn new_client<F: fn(Client&)>(base_url: const u8[:]) -> Client {
    var client = new_client(base_url);
    F(&client);
    return client;
}

fn new_client<F: fn(Client&)>() -> Client {
    var client = new_client();
    F(&client);
    return client;
}

inline fn new_session() -> Client { return new_client(); }
inline fn new_session(cfg: ClientConfig) -> Client { return new_client(cfg); }
inline fn new_session(base_url: const u8[:]) -> Client { return new_client(base_url); }
fn new_session<F: fn(Client&)>(base_url: const u8[:]) -> Client {
    var client = new_client(base_url);
    F(&client);
    return client;
}
fn new_session<F: fn(Client&)>() -> Client {
    var client = new_client();
    F(&client);
    return client;
}

// ---- ufcs session mutators & configuration ---------------------------------

fn set_base_url(session: Session&, url: const u8[:]) {
    session.base_url.clear();
    session.base_url.append(url);
}

fn apply_profile(client: Client&, profile: const BrowserProfile&) {
    client.profile = profile.kind;
    client.profile_spec = profile;
    client.default_headers.clear();
    if profile.user_agent.len > 0 {
        client.default_headers.push(make_header("User-Agent", profile.user_agent[..]));
    }
    if profile.accept.len > 0 {
        client.default_headers.push(make_header("Accept", profile.accept[..]));
    }
    if profile.accept_encoding.len > 0 {
        client.default_headers.push(make_header("Accept-Encoding", profile.accept_encoding[..]));
    }
    if profile.accept_language.len > 0 {
        client.default_headers.push(make_header("Accept-Language", profile.accept_language[..]));
    }
    if profile.upgrade_insecure_requests.len > 0 {
        client.default_headers.push(make_header("Upgrade-Insecure-Requests", profile.upgrade_insecure_requests[..]));
    }
    for &h in profile.extra_headers {
        guard client.default_headers.len < client.default_headers.cap else { break; }
        client.default_headers.push(copy(h));
    }
}

fn set_profile(session: Session&, profile: Profile) {
    session.profile = profile;
    if profile == Profile.None {
        session.profile_spec = none_profile();
        session.default_headers.clear();
        return;
    }
    if profile == Profile.Wing {
        let p = wing_default_profile();
        apply_profile(session, p);
    }
}

fn set_profile(session: Session&, profile: const BrowserProfile&) {
    apply_profile(session, profile);
}

fn set_user_agent(session: Session&, ua: const u8[:]) {
    set_header(session.default_headers, "User-Agent", ua);
    set_user_agent(session.profile_spec, ua);
}

fn user_agent(session: const Session&) -> const u8[:] {
    let ua = find_header(session.default_headers[..], "user-agent");
    if ua.len > 0 { return ua; }
    return profile_user_agent(session.profile);
}

fn ja4(session: const Session&) -> u8[..64] {
    return ja4(session.profile_spec);
}

fn p0f(session: const Session&) -> u8[..128] {
    return p0f(session.profile_spec);
}

fn akamai(session: const Session&) -> u8[..256] {
    return akamai(session.profile_spec);
}

fn akamai_hash(session: const Session&) -> u8[..32] {
    return akamai_hash(session.profile_spec);
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

// ---- dns-over-https & automated ech discovery (rfc 8484, rfc 9460) ----------

fn enable_doh(session: Session&, endpoint: const u8[:] = "https://cloudflare-dns.com/dns-query", use_post: bool = true) {
    session.enable_doh = true;
    session.doh.endpoint.clear();
    session.doh.endpoint.append(endpoint);
    session.doh.use_post = use_post;
}

fn enable_ech(session: Session&, auto_discover: bool = true) {
    session.enable_ech = true;
    session.auto_ech_discovery = auto_discover;
    if auto_discover && !session.enable_doh {
        session.enable_doh = true;
    }
}

// Dispatches a DNS-over-HTTPS wire query using an isolated HTTP client transport
// to ensure application credentials, custom headers, and interceptors do not leak to public resolvers.
fn doh_query(
    session:  Session&,
    domain:   const u8[:],
    qtype:    u16,
    tx_id:    u16,
    out_resp: DnsResponse&,
) -> bool {
    var req = new_request(if session.doh.use_post { "POST" } else { "GET" }, "");

    if session.doh.use_post {
        req.url.append(session.doh.endpoint[..]);
        set_header(req, "content-type", "application/dns-message");
        set_header(req, "accept", "application/dns-message");
        guard build_dns_query(domain, qtype, tx_id, req.body) else { return false; }
    } else {
        guard build_doh_get_url(session.doh.endpoint[..], domain, qtype, req.url) else { return false; }
        set_header(req, "accept", "application/dns-message");
    }

    var doh_client = new_client();
    doh_client.virtual_clock_us = session.virtual_clock_us;
    doh_client.proxy_url.append(session.proxy_url[..]);
    doh_client.timeout_ms = session.timeout_ms;
    doh_client.ssrf_guard = copy(session.ssrf_guard);
    doh_client.mock_routes = copy(session.mock_routes);

    let res, err = do(doh_client, req);
    guard ok(err) && res.status_code == 200 else { return false; }

    return parse_dns_response(res.body[..], out_resp);
}

fn lookup_cached_ech_config(
    dns_cache: const DnsCache&,
    domain:    const u8[:],
    now_sec:   i64,
    out_ech:   u8[..512]&,
) -> bool {
    var cached = DnsCacheEntry { .. };
    let cache_status = dns_cache_lookup(dns_cache, domain, DNS_QTYPE_HTTPS, now_sec, cached);
    if cache_status == DnsCacheStatus.Fresh {
        for &rec in cached.https_records {
            if rec.has_ech && rec.ech_config_list.len > 0 {
                out_ech.append(rec.ech_config_list[..]);
                return true;
            }
        }
    }
    out_ech.clear();
    return false;
}

fn discover_and_cache_ech_config(
    session: Session&,
    domain:  const u8[:],
    now_sec: i64,
    out_ech: u8[..512]&,
) -> bool {
    guard session.enable_doh && session.auto_ech_discovery else { return false; }

    var dns_resp = DnsResponse { .. };
    // RFC 8484 §4.1: DoH clients SHOULD set DNS ID to 0 for maximum HTTP cacheability
    guard doh_query(session, domain, DNS_QTYPE_HTTPS, 0, dns_resp) else { return false; }

    var cache_entry = DnsCacheEntry {
        qtype:           DNS_QTYPE_HTTPS,
        inserted_at_sec: now_sec,
        ttl_sec:         300,
        valid:           true,
        ..
    };
    cache_entry.domain.append(domain);

    var found_ech = false;
    for &rec in dns_resp.https_records {
        if cache_entry.https_records.len < 4 {
            cache_entry.https_records.push(rec);
        }
        if rec.has_ech && rec.ech_config_list.len > 0 && !found_ech {
            out_ech.append(rec.ech_config_list[..]);
            found_ech = true;
        }
    }

    dns_cache_insert(session.dns_cache, cache_entry);
    return found_ech;
}

// Discovers or extracts ECHConfigList for a domain.
// First checks local DnsCache; if missing/expired and DoH is enabled, performs RFC 9460 Type 65 discovery.
fn resolve_ech_config(
    session: Session&,
    domain:  const u8[:],
    now_sec: i64,
    out_ech: u8[..512]&,
) -> bool {
    out_ech.clear();
    if lookup_cached_ech_config(session.dns_cache, domain, now_sec, out_ech) {
        return true;
    }
    if discover_and_cache_ech_config(session, domain, now_sec, out_ech) {
        return true;
    }
    // Fallback: If discovery failed, check if a stale entry is available
    var cached = DnsCacheEntry { .. };
    let stale_status = dns_cache_lookup(session.dns_cache, domain, DNS_QTYPE_HTTPS, 0, cached);
    if stale_status == DnsCacheStatus.Fresh || stale_status == DnsCacheStatus.Stale {
        for &rec in cached.https_records {
            if rec.has_ech && rec.ech_config_list.len > 0 {
                out_ech.append(rec.ech_config_list[..]);
                return true;
            }
        }
    }
    out_ech.clear();
    return false;
}

// ---- alt-svc & protocol racing configuration (rfc 7838, rfc 8305) ----------

fn enable_altsvc(session: Session&, enabled: bool = true) {
    session.enable_altsvc = enabled;
}

fn enable_protocol_racing(session: Session&, enabled: bool = true, quic_delay_ms: i64 = 200) {
    session.enable_protocol_racing = enabled;
    session.quic_race_delay_ms = quic_delay_ms;
}

fn has_altsvc_h3(session: const Session&, target: const u8[:]) -> bool {
    var origin_buf: u8[..128] = [];
    resolve_target_origin(target, origin_buf);
    let now_sec = session.virtual_clock_us / 1000000;
    var ep = AltSvcEndpoint { .. };
    return lookup_h3(session.altsvc, origin_buf[..], now_sec, ep);
}

fn is_altsvc_broken(session: const Session&, target: const u8[:]) -> bool {
    var origin_buf: u8[..128] = [];
    resolve_target_origin(target, origin_buf);
    let now_sec = session.virtual_clock_us / 1000000;
    return is_broken(session.altsvc, origin_buf[..], now_sec);
}

// ---- compression dictionary transport configuration (chrome 123+ dcz/dcb) --

fn enable_compression_dict(session: Session&, enabled: bool = true) {
    session.enable_compression_dict = enabled;
}

fn has_dictionary_for(session: const Session&, target_url: const u8[:]) -> bool {
    var origin_buf: u8[..128] = [];
    resolve_target_origin(target_url, origin_buf);
    var path_buf: u8[..256] = [];
    let parsed, err = core::parse_url(target_url);
    if parsed.valid {
        path_buf.append(core::pathname(parsed));
    } else {
        path_buf.append("/");
    }
    let now_sec = session.virtual_clock_us / 1000000;
    var dummy_hash: u8[..64] = [];
    return dictionary_lookup_for_request(session.dict_cache, origin_buf[..], path_buf[..], now_sec, dummy_hash);
}

// ---- interceptor pipeline configuration (okhttp/tower-style) ---------------

fn add_app_logging(session: Session&, level: LogLevel = LogLevel.Basic) -> bool {
    return add_logging(session.pipeline, InterceptorScope.Application, level);
}

fn add_network_logging(session: Session&, level: LogLevel = LogLevel.Basic) -> bool {
    return add_logging(session.pipeline, InterceptorScope.Network, level);
}

fn add_app_bearer_auth(session: Session&, token: const u8[:]) -> bool {
    return add_bearer_auth(session.pipeline, token);
}

fn add_app_header(session: Session&, name: const u8[:], val: const u8[:]) -> bool {
    return add_header(session.pipeline, InterceptorScope.Application, name, val);
}

fn add_network_header(session: Session&, name: const u8[:], val: const u8[:]) -> bool {
    return add_header(session.pipeline, InterceptorScope.Network, name, val);
}

fn add_app_request_id(session: Session&, prefix: const u8[:] = "req-") -> bool {
    return add_request_id(session.pipeline, prefix);
}

fn add_app_traceparent(session: Session&, sample_flag: const u8[:] = "01") -> bool {
    return add_traceparent(session.pipeline, sample_flag);
}

fn add_app_retry(session: Session&, max_retries: i32, retry_on_5xx: bool = true) -> bool {
    return add_retry(session.pipeline, max_retries, retry_on_5xx);
}

fn add_network_metrics(session: Session&) -> bool {
    return add_metrics(session.pipeline);
}

fn clear_pipeline_logs(session: Session&) {
    session.pipeline.log_entries.clear();
}

// ---- authentication credentials configuration (rfc 7616 digest & basic) ----

fn set_credentials(session: Session&, username: const u8[:], password: const u8[:]) {
    session.creds.username.clear();
    session.creds.username.append(username);
    session.creds.password.clear();
    session.creds.password.append(password);
    session.creds.has_credentials = true;
    session.creds.nonce_counter = 1;
}

fn clear_credentials(session: Session&) {
    session.creds.has_credentials = false;
    session.creds.username.clear();
    session.creds.password.clear();
    session.creds.nonce_counter = 1;
}

// ---- hsts configuration (rfc 6797 strict transport security) ---------------

fn enable_hsts(session: Session&, enabled: bool = true) {
    session.enable_hsts = enabled;
}

fn enable_hsts_preload(session: Session&, enabled: bool = true) {
    session.hsts.enable_preload_list = enabled;
}

fn is_hsts(session: const Session&, hostname: const u8[:]) -> bool {
    let now_sec = session.virtual_clock_us / 1000000;
    return is_hsts_host(session.hsts, hostname, now_sec);
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
    return session.trusted_location_hosts.any() { eq_ascii_fold(it[..], host_name) };
}

// ---- mock route registration methods ---------------------------------------

fn mock_route(
    session:     Session&,
    method:      const u8[:],
    pattern_url: const u8[:],
    status_code: i32,
    body_str:    const u8[:],
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

fn add_mock_set_cookie(session: Session&, set_cookie_raw: const u8[:]) {
    if session.mock_routes.len > 0 {
        add_mock_set_cookie(session.mock_routes[session.mock_routes.len - 1], set_cookie_raw);
    }
}

fn add_mock_header(session: Session&, name: const u8[:], value: const u8[:]) {
    if session.mock_routes.len > 0 {
        add_mock_header(session.mock_routes[session.mock_routes.len - 1], name, value);
    }
}

fn add_mock_resolved_ip(session: Session&, ip_str: const u8[:]) {
    if session.mock_routes.len > 0 {
        add_mock_resolved_ip(session.mock_routes[session.mock_routes.len - 1], ip_str);
    }
}

fn set_mock_quic_blocked(session: Session&, blocked: bool = true) {
    if session.mock_routes.len > 0 {
        set_mock_quic_blocked(session.mock_routes[session.mock_routes.len - 1], blocked);
    }
}

fn set_mock_protocol(session: Session&, proto: const u8[:]) {
    if session.mock_routes.len > 0 {
        set_mock_protocol(session.mock_routes[session.mock_routes.len - 1], proto);
    }
}

fn add_mock_websocket(session: Session&, url_pattern: const u8[:], subprotocol: const u8[:] = "") {
    var route = MockExchange {
        status_code: 101,
        ..
    };
    route.method.append("GET");
    route.pattern_url.append(url_pattern);
    route.headers.push(make_header("Upgrade", "websocket"));
    route.headers.push(make_header("Connection", "Upgrade"));
    if subprotocol.len > 0 {
        route.headers.push(make_header("Sec-WebSocket-Protocol", subprotocol));
    }
    session.mock_routes.push(route);
}

fn add_mock_sse(session: Session&, url_pattern: const u8[:], sample_events: const u8[:] = "") {
    var route = MockExchange {
        status_code: 200,
        ..
    };
    route.method.append("GET");
    route.pattern_url.append(url_pattern);
    route.headers.push(make_header("Content-Type", "text/event-stream"));
    route.headers.push(make_header("Cache-Control", "no-cache"));
    route.headers.push(make_header("Connection", "keep-alive"));
    if sample_events.len > 0 {
        route.body.append(sample_events);
    }
    session.mock_routes.push(route);
}

// ---- cookie & default header helpers ---------------------------------------

fn set_cookie(session: Session&, name: const u8[:], value: const u8[:]) {
    var raw_hdr: u8[..2048] = [];
    raw_hdr.append(name);
    raw_hdr.push('=');
    raw_hdr.append(value);
    raw_hdr.append("; Path=/");
    if session.base_url.len > 0 {
        session.jar.set_cookie_header(session.base_url[..], raw_hdr[..], session.virtual_clock_us);
    } else {
        session.jar.set_cookie_header("https://example.com/", raw_hdr[..], session.virtual_clock_us);
    }
}

fn cookie(session: const Session&, name: const u8[:]) -> const u8[:] {
    return session.jar.get(name);
}

fn default_header(session: Session&, name: const u8[:], value: const u8[:]) {
    if session.default_headers.len < 16 {
        session.default_headers.push(make_header(name, value));
    }
}
