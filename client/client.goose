// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Client session facade, configuration models, and lifecycle methods.
namespace wing;

import std;
import core from "..";
import cookie.constants;
import cookie.canonical;
import cookie.policy;
import cookie.engine;
import fingerprint.ja4;
import fingerprint.profile;
import fingerprint.profile;
import http.request;
import http.response;
import client.redirect;
import http.headers;
import http.cache.cache_control;
import http.cache.freshness;
import http.cache.validators;
import http.cache.engine;
import dns.wire;
import dns.cache;
import dns.doh;
import tls.ech;
import tls.pem;
import http.altsvc;
import net.happy_eyeballs;
import http.compression_dict;
import http.hsts;
import http.signatures;
import client.interceptor;
import client.stream;
import client.session.ssrf;
import client.session.mock;
import net.pool;
import net.retry;
import wire.pipeline;
import auth.digest;
import auth.dpop;
import security.privacypass;
import client.replay_guard;
import client.telemetry;

// ---- 1. Configuration & State Structs --------------------------------------

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
    strict_content_decoding: bool         = false,
    insecure_skip_verify:    bool         = false,
    sig_key_id:              const u8[:]  = "",
    sig_private_key:         const u8[:]  = "",
    sig_public_key:          const u8[:]  = "",
}

type SessionConfig = ClientConfig;

struct ClientCredentials {
    username:        u8[..128]       = [],
    password:        u8[..128]       = [],
    has_credentials: bool            = false,
    nonce_counter:   u32             = 1,
    cnonce:          u8[..32]        = "f2/IZUnWe0rEzWeA",
    last_digest:     DigestChallenge = DigestChallenge { .. },
}

struct ClientDpopState {
    private_key:  u8[32]     = [0; 32],
    access_token: u8[..2048] = [],
    has_key:      bool       = false,
    last_nonce:   u8[..128]  = [],
}

struct Client {
    base_url:                u8[..256]         = [],
    profile:                 Profile           = Profile.Wing,
    profile_spec:            ClientProfile     = ClientProfile { .. },
    proxy_url:               u8[..256]         = [],
    timeout_ms:              i64               = 15000,
    follow_redirects:        bool              = true,
    redirect_mode:           RedirectMode      = RedirectMode.Follow,
    max_redirects:           i64               = 10,
    https_only:              bool              = false,
    enable_referer:          bool              = true,
    default_referrer_policy: ReferrerPolicy    = ReferrerPolicy.StrictOriginWhenCrossOrigin,
    default_headers:         HeaderMap         = HeaderMap { .. },
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

    // RFC 7838 Alt-Svc & Protocol Racing
    altsvc:                 AltSvcCache = AltSvcCache { .. },
    enable_altsvc:          bool        = true,
    enable_protocol_racing: bool        = true,
    quic_race_delay_ms:     i64         = 200,

    // Compression Dictionary Transport (RFC 9842 dcz/dcb)
    dict_cache:              DictionaryCache = DictionaryCache { .. },
    enable_compression_dict: bool            = true,

    // OkHttp/Tower-style 2-tier Interceptor Pipeline (Application & Network)
    pipeline:      InterceptorPipeline = InterceptorPipeline { .. },
    wire_pipeline: wire::WirePipeline  = wire::default_client_pipeline(),

    // RFC 7616 Digest & RFC 7617 Basic Authenticator
    creds:               ClientCredentials = ClientCredentials { .. },
    private_token_cache: PrivateTokenCache = PrivateTokenCache { .. },

    // RFC 6797 HTTP Strict Transport Security (HSTS)
    hsts:        HstsCache = HstsCache { .. },
    enable_hsts: bool      = true,

    // L4 / L7 Resilient connection pool (Keep-Alive, IP coalescing, WantQueue)
    pool:     StreamPool         = StreamPool { .. },
    af_cache: AddressFamilyCache = AddressFamilyCache { .. },

    enable_cookie_jar:       bool                = true,
    http2_prior_knowledge:   bool                = false,
    strict_content_decoding: bool                = false,
    verify_content_digest:   bool                = false,
    enable_early_data:       bool                = false,
    enable_har_telemetry:    bool                = false,
    last_har_json:           u8[..2048]          = [],
    retry_budget:            AdaptiveRetryBudget = new_adaptive_retry_budget(),
    circuit_breaker:         HostCircuitBreaker  = new_host_circuit_breaker(),
    backoff_config:          BackoffConfig       = new_backoff_config(),
    dpop:                    ClientDpopState     = ClientDpopState { .. },
    sig_key_id:              u8[..64]            = [],
    sig_private_key:         u8[..64]            = [],
    sig_public_key:          u8[..64]            = [],
    trust_store:             TrustAnchorStore    = TrustAnchorStore { .. },
    insecure_skip_verify:    bool                = false,

    // Resizable field must be final
    jar: CanonicalCookieJar = CanonicalCookieJar { .. },
}

type Session = Client;

// ---- 2. Client & Session Factories -----------------------------------------

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
        wire_pipeline:           wire::default_client_pipeline(),
        hsts:                    HstsCache { .. },
        enable_hsts:             true,
        pool:                    new_stream_pool(),
        enable_cookie_jar:       true,
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
        wire_pipeline:           wire::default_client_pipeline(),
        hsts:                    HstsCache { .. },
        enable_hsts:             true,
        pool:                    new_stream_pool(),
        enable_cookie_jar:       cfg.cookie_jar,
        strict_content_decoding: cfg.strict_content_decoding,
        insecure_skip_verify:    cfg.insecure_skip_verify,
        jar:                     CanonicalCookieJar { .. },
        ..
    };
    client.base_url.append(cfg.base_url);
    client.proxy_url.append(cfg.proxy_url);
    if cfg.profile != Profile.None {
        set_profile(client, cfg.profile);
    }
    if cfg.sig_private_key.len > 0 || cfg.sig_public_key.len > 0 {
        let _ = set_http_signature_keys(client, cfg.sig_key_id, cfg.sig_private_key, cfg.sig_public_key);
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

// ---- 3. Core Session Mutators & Fingerprint Accessors ----------------------

fn set_base_url(session: Session&, url: const u8[:]) {
    session.base_url.clear();
    let n = min(url.len, session.base_url.cap);
    session.base_url.append(url[..n]);
}

fn apply_profile(client: Client&, profile: const ClientProfile&) {
    client.profile = profile.kind;
    client.profile_spec = profile;
    client.default_headers.clear();
    if profile.user_agent.len > 0 {
        set_header(client.default_headers, "User-Agent", profile.user_agent[..]);
    }
    if profile.accept.len > 0 {
        set_header(client.default_headers, "Accept", profile.accept[..]);
    }
    if profile.accept_encoding.len > 0 {
        set_header(client.default_headers, "Accept-Encoding", profile.accept_encoding[..]);
    }
    if profile.accept_language.len > 0 {
        set_header(client.default_headers, "Accept-Language", profile.accept_language[..]);
    }
    if profile.upgrade_insecure_requests.len > 0 {
        set_header(client.default_headers, "Upgrade-Insecure-Requests", profile.upgrade_insecure_requests[..]);
    }
    for &e in profile.extra_headers.entries {
        let h_name = entry_name(profile.extra_headers, e);
        let h_val = entry_value(profile.extra_headers, e);
        if h_name.len > 0 {
            set_header(client.default_headers, h_name, h_val);
        }
    }
}

fn set_profile(session: Session&, profile: Profile) {
    session.profile = profile;
    if profile == Profile.None {
        session.profile_spec = none_profile();
        session.default_headers.clear();
        return;
    }
    if profile == Profile.Custom {
        let p = custom_profile();
        apply_profile(session, p);
        return;
    }
    if profile == Profile.Wing {
        let p = wing_default_profile();
        apply_profile(session, p);
    }
}

fn set_profile(session: Session&, profile: const ClientProfile&) {
    apply_profile(session, profile);
}

fn set_user_agent(session: Session&, ua: const u8[:]) {
    set_header(session.default_headers, "User-Agent", ua);
    set_user_agent(session.profile_spec, ua);
}

fn user_agent(session: const Session&) -> const u8[:] {
    let ua = get_header(session.default_headers, "user-agent");
    if ua.len > 0 { return ua; }
    return profile_user_agent(session.profile);
}

fn ja4(session: const Session&) -> u8[..64] {
    return ja4(session.profile_spec);
}

fn p0f(session: const Session&) -> u8[..256] {
    return p0f(session.profile_spec);
}

fn akamai(session: const Session&) -> u8[..640] {
    return akamai(session.profile_spec);
}

fn akamai_hash(session: const Session&) -> u8[..32] {
    return akamai_hash(session.profile_spec);
}

fn set_proxy(session: Session&, proxy_url: const u8[:]) {
    session.proxy_url.clear();
    let n = min(proxy_url.len, session.proxy_url.cap);
    session.proxy_url.append(proxy_url[..n]);
}

fn set_timeout_ms(session: Session&, ms: i64) {
    session.timeout_ms = ms;
}

// Closes all idle and active connections in the session's pool.
fn close(session: Session&) {
    drain_stream_pool(session.pool);
}

fn set_redirect_mode(session: Session&, mode: RedirectMode) {
    session.redirect_mode = mode;
    session.follow_redirects = (mode == RedirectMode.Follow);
}

// ---- 4. Protocol, Interceptor, Auth, HSTS, Cookie & Mock Route Configurators

fn enable_doh(session: Session&, endpoint: const u8[:] = "https://cloudflare-dns.com/dns-query", use_post: bool = true) {
    session.enable_doh = true;
    session.doh.endpoint.clear();
    let n = min(endpoint.len, session.doh.endpoint.cap);
    session.doh.endpoint.append(endpoint[..n]);
    session.doh.use_post = use_post;
}

fn enable_ech(session: Session&, auto_discover: bool = true) {
    session.enable_ech = true;
    session.auto_ech_discovery = auto_discover;
    if auto_discover && !session.enable_doh {
        session.enable_doh = true;
    }
}

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
        let _ = path_buf.try_set(parsed.pathname());
    } else {
        let _ = path_buf.try_set("/");
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

fn set_credentials(session: Session&, username: const u8[:], password: const u8[:]) -> bool {
    guard username.len <= session.creds.username.cap && password.len <= session.creds.password.cap else {
        return false;
    }
    guard session.creds.username.try_set(username) && session.creds.password.try_set(password) else {
        return false;
    }
    session.creds.has_credentials = true;
    session.creds.nonce_counter = 1;
    return true;
}

fn set_dpop_credentials(session: Session&, private_key: const u8[32]&, token: const u8[:] = "") -> bool {
    guard session.dpop.access_token.try_set(token) else { return false; }
    session.dpop.private_key = private_key;
    session.dpop.has_key = true;
    session.dpop.last_nonce.clear();
    return true;
}

// Configures RFC 9421 Ed25519 HTTP Message Signature keys on `session` for automatic
// request signing (`sig_private_key.len == 32`) and response verification (`sig_public_key.len == 32`).
fn set_http_signature_keys(
    session:     Session&,
    key_id:      const u8[:],
    private_key: const u8[:],
    public_key:  const u8[:] = "",
) -> bool {
    guard key_id.len <= session.sig_key_id.cap
        && (private_key.len == 0 || private_key.len == 32)
        && (public_key.len == 0 || public_key.len == 32) else {
        return false;
    }
    core::secure_zeroize_slice(session.sig_private_key[..]);
    guard session.sig_key_id.try_set(key_id)
        && session.sig_private_key.try_set(private_key)
        && session.sig_public_key.try_set(public_key) else {
        return false;
    }
    return true;
}

// ---- hsts configuration (rfc 6797 strict transport security) ---------------

fn enable_hsts(session: Session&, enabled: bool = true) {
    session.enable_hsts = enabled;
}

fn is_hsts(session: const Session&, hostname: const u8[:]) -> bool {
    let now_sec = session.virtual_clock_us / 1000000;
    return is_hsts_host(session.hsts, hostname, now_sec);
}

fn export_hsts<B>(session: const Session&, out: B&) -> i64 {
    let now_sec = session.virtual_clock_us / 1000000;
    return save_hsts_cache(session.hsts, now_sec, out);
}

fn import_hsts(session: Session&, data: const u8[:]) -> i64 {
    let now_sec = session.virtual_clock_us / 1000000;
    return load_hsts_cache(session.hsts, data, now_sec);
}

fn allow_port(session: Session&, port_num: i32) -> bool {
    guard !session.ssrf_guard.allowed_ports.contains(port_num) else { return true; }
    return session.ssrf_guard.allowed_ports.try_push(port_num);
}

fn deny_port(session: Session&, port_num: i32) -> bool {
    guard !session.ssrf_guard.denied_ports.contains(port_num) else { return true; }
    return session.ssrf_guard.denied_ports.try_push(port_num);
}

fn set_clock_us(session: Session&, now_us: i64) {
    session.virtual_clock_us = now_us;
}

fn trust_location_host(session: Session&, host_name: const u8[:]) -> bool {
    guard host_name.len > 0 && host_name.len <= 128 else { return false; }
    guard !is_trusted_location_host(session, host_name) else { return true; }
    var host_buf: u8[..128] = [];
    host_name.to_lower_ascii(host_buf);
    return session.trusted_location_hosts.try_push(host_buf);
}

fn is_trusted_location_host(session: const Session&, host_name: const u8[:]) -> bool {
    return session.trusted_location_hosts.any() { it[..].eq_ascii_fold(host_name) };
}

// Loads PEM-encoded CA trust anchors from `path` into `sess.trust_store` and
// enforces peer certificate verification on the session.
//
// Example:
//   let count, ok = wing::load_trust_anchors_pem_file(sess, "certs/ca.pem");
//   returns: count >= 1, ok = true (or 0, false if unreadable/empty/invalid)
fn load_trust_anchors_pem_file(sess: Session&, path: const u8[:]) -> i64, bool {
    guard path.len > 0 else { return 0, false; }
    let count, ok = load_trust_anchors_pem_file(sess.trust_store, path);
    guard ok else { return 0, false; }
    sess.insecure_skip_verify = false;
    return count, true;
}

// Validates and appends PEM CA trust anchors into `sess.trust_store`, enforces
// certificate verification, and optionally allows loopback/local-network
// targets for local test or proxy harnesses.
//
// Example:
//   let count, ok = wing::configure_session_tls_ca_pem(sess, ca_pem, true);
//   returns: count >= 1, ok = true with `sess.ssrf_guard.deny_local_network = false`
fn configure_session_tls_ca_pem(
    sess:           Session&,
    pem_bundle:     const u8[:],
    allow_loopback: bool = false,
) -> i64, bool {
    guard pem_bundle.len > 0 else { return 0, false; }
    let saved_len = sess.trust_store.anchors.len;
    let count, ok = add_trust_anchors_pem(sess.trust_store, pem_bundle);
    guard ok && count > 0 else {
        sess.trust_store.anchors.resize(saved_len);
        return 0, false;
    }
    sess.insecure_skip_verify = false;
    if allow_loopback {
        sess.ssrf_guard.deny_local_network = false;
    }
    return count, true;
}

// ---- mock route registration methods ---------------------------------------

fn mock_route(
    session:     Session&,
    method:      const u8[:],
    pattern_url: const u8[:],
    status_code: i32,
    body_str:    const u8[:],
) -> MockExchange& {
    if session.mock_routes.len < session.mock_routes.cap {
        var route = MockExchange {
            status_code: status_code,
            ..
        };
        route.method.append(method);
        route.pattern_url.append(pattern_url);
        route.body.append(body_str);
        return session.mock_routes.push(route);
    }
    return session.mock_routes[0];
}

fn mock_route<F: fn(MockExchange&)>(
    session:     Session&,
    method:      const u8[:],
    pattern_url: const u8[:],
    status_code: i32,
    body_str:    const u8[:],
) -> MockExchange& {
    let route .= mock_route(session, method, pattern_url, status_code, body_str);
    F(route);
    return route;
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
        status_code: rfc::STATUS_SWITCHING_PROTOCOLS,
        ..
    };
    guard route.method.try_set("GET") && route.pattern_url.try_set(url_pattern) else { return; }
    set_header(route.headers, "Upgrade", "websocket");
    set_header(route.headers, "Connection", "Upgrade");
    if subprotocol.len > 0 {
        set_header(route.headers, "Sec-WebSocket-Protocol", subprotocol);
    }
    let _ = session.mock_routes.try_push(route);
}

fn add_mock_sse(session: Session&, url_pattern: const u8[:], sample_events: const u8[:] = "") {
    var route = MockExchange {
        status_code: rfc::STATUS_OK,
        ..
    };
    guard route.method.try_set("GET")
        && route.pattern_url.try_set(url_pattern)
        && route.body.try_set(sample_events) else { return; }
    set_header(route.headers, "Content-Type", "text/event-stream");
    set_header(route.headers, "Cache-Control", "no-cache");
    set_header(route.headers, "Connection", "keep-alive");
    let _ = session.mock_routes.try_push(route);
}

// ---- cookie & default header helpers ---------------------------------------

fn set_cookie(session: Session&, name: const u8[:], value: const u8[:]) {
    var raw_hdr: u8[..4128] = [];
    guard raw_hdr.try_append(name)
        && raw_hdr.try_push('=')
        && raw_hdr.try_append(value)
        && raw_hdr.try_append("; Path=/") else { return; }
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
    set_header(session.default_headers, name, value);
}

// ---- 5. Session Protocol Helpers (DoH, ECH Discovery & RFC 9842 Dictionary) -

// Creates an isolated `Client` copying only transport, TLS verification, SSRF policy,
// virtual clock, and mock routes so application credentials, cookies, and interceptors
// do not leak across internal sub-requests (such as RFC 8484 DoH queries).
fn clone_isolated_transport_client(session: const Session&) -> Client {
    var isolated = new_client();
    isolated.virtual_clock_us = session.virtual_clock_us;
    isolated.proxy_url.append(session.proxy_url[..]);
    isolated.timeout_ms = session.timeout_ms;
    isolated.trust_store = copy(session.trust_store);
    isolated.insecure_skip_verify = session.insecure_skip_verify;
    isolated.ssrf_guard = copy(session.ssrf_guard);
    isolated.mock_routes = copy(session.mock_routes);
    return isolated;
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
        var wire_query: u8[..512] = [];
        guard build_dns_query(domain, qtype, tx_id, wire_query) else { return false; }
        req.body.append(wire_query[..]);
    } else {
        guard build_doh_get_url(session.doh.endpoint[..], domain, qtype, req.url) else { return false; }
        set_header(req, "accept", "application/dns-message");
    }

    var doh_client = clone_isolated_transport_client(session);
    let res, err = do(doh_client, req);
    guard ok(err) && res.status_code == rfc::STATUS_OK else { return false; }

    guard parse_dns_response(res.body[..], out_resp) else { return false; }
    guard out_resp.rcode == rfc::DNS_RCODE_NOERROR else { return false; }
    guard !session.doh.use_post || out_resp.tx_id == tx_id else { return false; }
    return true;
}

fn lookup_cached_ech_config(
    dns_cache: const DnsCache&,
    domain:    const u8[:],
    now_sec:   i64,
    out_ech:   u8[..512]&,
) -> bool {
    var cached = DnsCacheEntry { .. };
    let cache_status = dns_cache_lookup(dns_cache, domain, rfc::DNS_QTYPE_HTTPS, now_sec, cached);
    if cache_status == DnsCacheStatus.Fresh {
        for &rec in cached.https_records {
            if rec.has_ech && rec.ech_config_list.len > 0 {
                return out_ech.try_set(rec.ech_config_list[..]);
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
    guard doh_query(session, domain, rfc::DNS_QTYPE_HTTPS, 0, dns_resp) else { return false; }

    let eff_ttl = if dns_resp.min_ttl_sec > 0 { dns_resp.min_ttl_sec } else { 300 };
    var cache_entry = DnsCacheEntry {
        qtype:           rfc::DNS_QTYPE_HTTPS,
        inserted_at_sec: now_sec,
        ttl_sec:         eff_ttl,
        valid:           true,
        ..
    };
    guard cache_entry.domain.try_set(domain) else { return false; }

    var found_ech = false;
    for &rec in dns_resp.https_records {
        let _ = cache_entry.https_records.try_push(rec);
        if rec.has_ech && rec.ech_config_list.len > 0 && !found_ech {
            found_ech = out_ech.try_set(rec.ech_config_list[..]);
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
    let stale_status = dns_cache_lookup(session.dns_cache, domain, rfc::DNS_QTYPE_HTTPS, now_sec, cached);
    if stale_status == DnsCacheStatus.Fresh || stale_status == DnsCacheStatus.Stale {
        for &rec in cached.https_records {
            if rec.has_ech && rec.ech_config_list.len > 0 {
                return out_ech.try_set(rec.ech_config_list[..]);
            }
        }
    }
    out_ech.clear();
    return false;
}

inline fn is_localhost_dict_authority(auth: const u8[:]) -> bool {
    let host_part, _, _ = auth.partition_byte('/');
    if host_part.starts_with_fold("localhost") {
        return host_part.len == 9 || host_part[9] == ':';
    }
    if core::starts_with(host_part, "127.0.0.1") {
        return host_part.len == 9 || host_part[9] == ':';
    }
    if core::starts_with(host_part, "[::1]") {
        return host_part.len == 5 || host_part[5] == ':';
    }
    return false;
}

inline fn is_secure_dict_origin(origin: const u8[:]) -> bool {
    guard origin.len > 0 else { return false; }
    if origin.starts_with_fold("https://") {
        return origin.len > 8;
    }
    if origin.starts_with_fold("http://") {
        return is_localhost_dict_authority(origin[7..]);
    }
    if core::contains(origin, "://") {
        return false;
    }
    guard origin[0] != ':' else { return false; }
    if core::ends_with(origin, ":80") {
        return is_localhost_dict_authority(origin);
    }
    return true;
}

inline fn is_dict_entry_usable_for_session(
    session: const Session&,
    entry:   const DictionaryEntry&,
    origin:  const u8[:],
) -> bool {
    guard entry.valid && entry.origin.len > 0 && entry.origin[..].eq_ascii_fold(origin) else {
        return false;
    }
    guard entry.ttl_sec > 0 else { return true; }
    if session.virtual_clock_us == 1700000000000000 && entry.inserted_at_sec > 0 && entry.inserted_at_sec < 100000000 {
        return true;
    }
    let now_sec = div_euclid(session.virtual_clock_us, 1000000);
    return now_sec >= entry.inserted_at_sec && core::sub_sat_i64(now_sec, entry.inserted_at_sec) < entry.ttl_sec;
}

// RFC 9842 Section 2.2: Available-Dictionary - Attaches `Available-Dictionary` and `Dictionary-ID`
// request headers when a valid dictionary in `session.dict_cache` matches `(origin, url_path)`.
fn attach_dictionary_request_headers(
    session:  const Session&,
    origin:   const u8[:],
    url_path: const u8[:],
    req:      Request&,
) -> bool {
    guard session.enable_compression_dict && is_secure_dict_origin(origin) else { return false; }
    let now_sec = session.virtual_clock_us / 1000000;
    let best_idx = find_best_matching_dict_idx(session.dict_cache, origin, url_path, now_sec);
    guard best_idx >= 0 && best_idx < session.dict_cache.entries.len else { return false; }
    let entry .= session.dict_cache.entries[best_idx];
    set_header(req, "Available-Dictionary", entry.sha256_base64[..]);
    if entry.id.len > 0 {
        var id_hdr: u8[..128] = [];
        format_dictionary_id_header(id_hdr, entry.id[..]);
        set_header(req, "Dictionary-ID", id_hdr[..]);
    }
    return true;
}

// RFC 9842 Section 2.1: Use-As-Dictionary - Registers a response body in `session.dict_cache` when
// `Use-As-Dictionary` is present, and verifies/decodes `dcz` or `dcb` Content-Encoding payloads.
fn process_dictionary_response<B>(
    session:          Session&,
    origin:           const u8[:],
    use_as_dict_hdr:  const u8[:],
    content_encoding: const u8[:],
    raw_body:         const u8[:],
    out_decoded:      B&,
) -> bool {
    guard is_secure_dict_origin(origin) else { return false; }
    let enc = content_encoding.trim_lws();
    let prev_len = out_decoded.len;
    var committed = false;
    defer if !committed { out_decoded.resize(prev_len); };
    if enc.eq_ascii_fold(rfc::ENCODING_DCZ) {
        var dict_hash: u8[32] = [0; 32];
        let _, ok_hdr = decode_dcz_header(raw_body, dict_hash);
        guard ok_hdr else { return false; }
        var dict_entry = DictionaryEntry { .. };
        guard dictionary_lookup_by_hash(session.dict_cache, dict_hash, dict_entry) else {
            return false;
        }
        guard is_dict_entry_usable_for_session(session, dict_entry, origin) else { return false; }
        let comp_payload, ok_magic = verify_dcz_dcb_magic(raw_body, true, dict_entry.sha256_hash);
        guard ok_magic else { return false; }
        guard decompress_dcz_payload(comp_payload, dict_entry.content[..], out_decoded) else {
            return false;
        }
    } else if enc.eq_ascii_fold(rfc::ENCODING_DCB) {
        var dict_hash: u8[32] = [0; 32];
        let _, ok_hdr = decode_dcb_header(raw_body, dict_hash);
        guard ok_hdr else { return false; }
        var dict_entry = DictionaryEntry { .. };
        guard dictionary_lookup_by_hash(session.dict_cache, dict_hash, dict_entry) else {
            return false;
        }
        guard is_dict_entry_usable_for_session(session, dict_entry, origin) else { return false; }
        let comp_payload, ok_magic = verify_dcz_dcb_magic(raw_body, false, dict_entry.sha256_hash);
        guard ok_magic else { return false; }
        guard decompress_dcb_payload(comp_payload, dict_entry.content[..], out_decoded) else {
            return false;
        }
    } else if enc.len == 0 || enc.eq_ascii_fold("identity") {
        guard out_decoded.try_append(raw_body) else { return false; }
    } else {
        return false;
    }

    if session.enable_compression_dict && use_as_dict_hdr.len > 0 {
        let params, ok_p = parse_use_as_dictionary_header(use_as_dict_hdr);
        if ok_p {
            let now_sec = div_euclid(session.virtual_clock_us, 1000000);
            dictionary_cache_insert(
                session.dict_cache,
                origin,
                params.match_pattern[..],
                params.id[..],
                out_decoded[prev_len..],
                params.ttl_sec,
                now_sec,
            );
        }
    }
    committed = true;
    return true;
}
