// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Client session facade, configuration models, and lifecycle methods.
namespace client;

import std;
import core;
import rfc.http;
import rfc.dns;
import cookie.constants;
import cookie.canonical;
import cookie.policy;
import cookie.engine;
import fingerprint.ja4;
import fingerprint.profile;
import http.request;
import http.response;
import http.problem;
import http.json_codec;
import http.json_helpers;
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
import tls.backend;
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
import net.tcp;
import net.retry;
import wire.pipeline;
import auth.digest;
import auth.dpop;
import security.privacypass;
import security.ssrf;
import client.replay_guard;
import client.telemetry;
import .stream_facade_internal;
import .session.tls_hop_internal;
import .session.dns_dial_internal;
import .session.hop_context_internal;

// ---- 1. Configuration & State Structs --------------------------------------

struct Config {
    base_url:                   const u8[:]          = "",
    profile:                    fingerprint::Profile = fingerprint::Profile.Wing,
    proxy_url:                  const u8[:]          = "",
    timeout_ms:                 i64                  = 15000,
    connect_timeout_ms:         i64                  = 0,
    tls_handshake_timeout_ms:   i64                  = 0,
    read_timeout_ms:            i64                  = 0,
    pool_idle_timeout_ms:       i64                  = 0,
    follow_redirects:           bool                 = true,
    redirect_mode:              RedirectMode         = RedirectMode.Follow,
    max_redirects:              i64                  = 10,
    https_only:                 bool                 = false,
    enable_referer:             bool                 = true,
    default_referrer_policy:    ReferrerPolicy       = ReferrerPolicy.StrictOriginWhenCrossOrigin,
    cookie_jar:                 bool                 = true,
    enable_cache:               bool                 = false,
    cache_options:              http::CacheOptions   = http::CacheOptions { .. },
    enable_hsts:                bool                 = true,
    enable_doh:                 bool                 = false,
    enable_ech:                 bool                 = false,
    enable_altsvc:              bool                 = true,
    enable_protocol_racing:     bool                 = true,
    quic_race_delay_ms:         i64                  = 200,
    enable_compression_dict:    bool                 = true,
    http2_prior_knowledge:      bool                 = false,
    auto_decompress:            bool                 = true,
    max_response_body_bytes:    i64                  = 0,
    max_retries:                i32                  = 0,
    strict_content_decoding:    bool                 = false,
    verify_content_digest:      bool                 = false,
    enable_early_data:          bool                 = false,
    enable_har_telemetry:       bool                 = false,
    allow_loopback_ssrf:        bool                 = false,
    insecure_skip_verify:       bool                 = false,
    tls_expired_leaf_grace_sec: i64                  = 0,
    tls_backend:                tls::TlsBackendKind  = tls::TlsBackendKind.PureGoose,
    tls_min_version:            tls::TlsMinVersion   = tls::TlsMinVersion.Tls13,
    tls_ca_file:                const u8[:]          = "",
    tls_use_system_roots:       bool                 = true,
    tls_client_cert_file:       const u8[:]          = "",
    tls_client_key_file:        const u8[:]          = "",
    tls_enable_pq_hybrid:       bool                 = false,
    tls_alpn:                   const u8[:]          = "",
    tls_enable_session_tickets: bool                 = true,
    tls_require_ocsp_stapling:  bool                 = false,
    tls_crl_file:               const u8[:]          = "",
    tls_keylog_file:            const u8[:]          = "",
    enable_ktls_offload:        bool                 = false,
    ip_family:                  net::IpFamily        = net::IpFamily.Auto,
    local_bind_addr:            const u8[:]          = "",
    tcp_nodelay:                bool                 = true,
    tcp_keepalive_idle_sec:     i32                  = 30,
    tcp_keepalive_intvl_sec:    i32                  = 5,
    tcp_keepalive_cnt:          i32                  = 3,
    disable_keepalive:          bool                 = false,
    max_conns_per_host:         i32                  = 0,
    use_env_proxy:              bool                 = false,
    sig_key_id:                 const u8[:]          = "",
    sig_private_key:            const u8[:]          = "",
    sig_public_key:             const u8[:]          = "",
    allow_legacy_md5_digest:    bool                 = false,
}

type SessionConfig = Config;

struct Credentials {
    username:        u8[..128]             = [],
    password:        u8[..128]             = [],
    has_credentials: bool                  = false,
    nonce_counter:   u32                   = 1,
    cnonce:          u8[..32]              = [],
    last_digest:     auth::DigestChallenge = auth::DigestChallenge { .. },
}

struct DpopState {
    private_key:  u8[32]     = [0; 32],
    access_token: u8[..2048] = [],
    has_key:      bool       = false,
    last_nonce:   u8[..128]  = [],
}

struct ResolveOverride {
    host: u8[..128] = [],
    port: u16       = 0,
    ip:   u8[..64]  = [],
}

struct Client {
    base_url:                u8[..256]                  = [],
    profile:                 fingerprint::Profile       = fingerprint::Profile.Wing,
    profile_spec:            fingerprint::ClientProfile = fingerprint::ClientProfile { .. },
    proxy_url:               u8[..256]                  = [],
    timeout_ms:              i64                        = 15000,
    follow_redirects:        bool                       = true,
    redirect_mode:           RedirectMode               = RedirectMode.Follow,
    max_redirects:           i64                        = 10,
    https_only:              bool                       = false,
    enable_referer:          bool                       = true,
    default_referrer_policy: ReferrerPolicy             = ReferrerPolicy.StrictOriginWhenCrossOrigin,
    default_headers:         http::HeaderMap            = http::HeaderMap { .. },
    ssrf_guard:              security::SsrfGuardPolicy  = security::SsrfGuardPolicy { enabled: false, .. },
    virtual_clock_us:        i64                        = 0,
    trusted_location_hosts:  u8[..128][..8]             = [],
    mock_routes:             MockExchange[..8]          = [],

    // RFC 9111 HTTP Cache Engine
    cache:        http::Cache = http::Cache { .. },
    enable_cache: bool        = false,

    // RFC 8484 DNS-over-HTTPS (DoH) & RFC 9460 Automated ECH Discovery
    doh:                dns::DohResolver = dns::DohResolver { .. },
    enable_doh:         bool             = false,
    enable_ech:         bool             = false,
    auto_ech_discovery: bool             = false,
    dns_cache:          dns::Cache       = dns::Cache { .. },

    // RFC 7838 Alt-Svc & Protocol Racing
    altsvc:                 http::AltSvcCache = http::AltSvcCache { .. },
    enable_altsvc:          bool              = true,
    enable_protocol_racing: bool              = true,
    quic_race_delay_ms:     i64               = 200,

    // Compression Dictionary Transport (RFC 9842 dcz/dcb)
    dict_cache:              http::DictionaryCache = http::DictionaryCache { .. },
    enable_compression_dict: bool                  = true,

    // OkHttp/Tower-style 2-tier Interceptor Pipeline (Application & Network)
    pipeline:      InterceptorPipeline = InterceptorPipeline { .. },
    wire_pipeline: wire::WirePipeline  = wire::default_client_pipeline(),

    // RFC 7616 Digest & RFC 7617 Basic Authenticator
    creds:               Credentials                 = Credentials { .. },
    private_token_cache: security::PrivateTokenCache = security::PrivateTokenCache { .. },

    // RFC 6797 HTTP Strict Transport Security (HSTS)
    hsts:        http::HstsCache = http::HstsCache { .. },
    enable_hsts: bool            = true,

    // L4 / L7 Resilient connection pool (Keep-Alive, IP coalescing, WantQueue)
    pool:     net::StreamPool         = net::StreamPool { .. },
    af_cache: net::AddressFamilyCache = net::AddressFamilyCache { .. },

    enable_cookie_jar:          bool                     = true,
    http2_prior_knowledge:      bool                     = false,
    strict_content_decoding:    bool                     = false,
    verify_content_digest:      bool                     = false,
    enable_early_data:          bool                     = false,
    enable_har_telemetry:       bool                     = false,
    last_har_json:              u8[..2048]               = [],
    retry_budget:               net::AdaptiveRetryBudget = net::new_adaptive_retry_budget(),
    circuit_breaker:            net::HostCircuitBreaker  = net::new_host_circuit_breaker(),
    backoff_config:             net::BackoffConfig       = net::new_backoff_config(),
    dpop:                       DpopState                = DpopState { .. },
    sig_key_id:                 u8[..64]                 = [],
    sig_private_key:            u8[..64]                 = [],
    sig_public_key:             u8[..64]                 = [],
    trust_store:                tls::TrustAnchorStore    = tls::TrustAnchorStore { .. },
    insecure_skip_verify:       bool                     = false,
    tls_expired_leaf_grace_sec: i64                      = 0,
    tls_backend:                tls::TlsBackendKind      = tls::TlsBackendKind.PureGoose,
    tls_min_version:            tls::TlsMinVersion       = tls::TlsMinVersion.Tls13,
    tls_ca_file:                u8[..256]                = [],
    tls_use_system_roots:       bool                     = true,
    tls_client_cert_file:       u8[..256]                = [],
    tls_client_key_file:        u8[..256]                = [],
    tls_enable_pq_hybrid:       bool                     = false,
    tls_alpn:                   u8[..64]                 = [],
    tls_enable_session_tickets: bool                     = true,
    tls_require_ocsp_stapling:  bool                     = false,
    tls_crl_file:               u8[..256]                = [],
    tls_keylog_file:            u8[..256]                = [],
    enable_ktls_offload:        bool                     = false,
    connect_timeout_ms:         i64                      = 0,
    tls_handshake_timeout_ms:   i64                      = 0,
    read_timeout_ms:            i64                      = 0,
    pool_idle_timeout_ms:       i64                      = 0,
    ip_family:                  net::IpFamily            = net::IpFamily.Auto,
    local_bind_addr:            u8[..64]                 = [],
    tcp_nodelay:                bool                     = true,
    tcp_keepalive_idle_sec:     i32                      = 30,
    tcp_keepalive_intvl_sec:    i32                      = 5,
    tcp_keepalive_cnt:          i32                      = 3,
    disable_keepalive:          bool                     = false,
    max_conns_per_host:         i32                      = 0,
    use_env_proxy:              bool                     = false,
    no_proxy_rules:             u8[..128][..16]          = [],
    resolve_overrides:          ResolveOverride[..16]    = [],
    allow_loopback_ssrf:        bool                     = false,
    max_retries:                i32                      = 0,
    auto_decompress:            bool                     = true,
    max_response_body_bytes:    i64                      = 0,
    allow_legacy_md5_digest:    bool                     = false,
    has_invalid_tls_config:     bool                     = false,
    has_invalid_sig_config:     bool                     = false,

    // Resizable field must be final
    jar: cookie::CanonicalCookieJar = cookie::CanonicalCookieJar { .. },
}

type Session = Client;

// ---- 2. Client & Session Factories -----------------------------------------

fn new_client() -> Client {
    let def_p = fingerprint::wing_default_profile();
    let def_hdrs = client_internal::build_profile_headers(def_p);
    return Client {
        profile:                 def_p.kind,
        profile_spec:            def_p,
        default_headers:         def_hdrs,
        ssrf_guard:              security::SsrfGuardPolicy { enabled: false, .. },
        cache:                   http::Cache { .. },
        enable_cache:            false,
        altsvc:                  http::AltSvcCache { .. },
        enable_altsvc:           true,
        enable_protocol_racing:  true,
        quic_race_delay_ms:      200,
        dict_cache:              http::DictionaryCache { .. },
        enable_compression_dict: true,
        pipeline:                InterceptorPipeline { .. },
        wire_pipeline:           wire::default_client_pipeline(),
        hsts:                    http::HstsCache { .. },
        enable_hsts:             true,
        pool:                    net::new_stream_pool(),
        enable_cookie_jar:       true,
        jar:                     cookie::CanonicalCookieJar { .. },
        ..
    };
}

fn new_client(cfg: Config) -> Client {
    var base_buf:    u8[..256] = [];
    var proxy_buf:   u8[..256] = [];
    var ca_file_buf: u8[..256] = [];
    let _ = base_buf.try_set(cfg.base_url);
    let _ = proxy_buf.try_set(cfg.proxy_url);
    let bad_ca_cfg = cfg.tls_ca_file.len > 0 && !ca_file_buf.try_set(cfg.tls_ca_file);

    let prof_spec = client_internal::resolve_profile_spec(cfg.profile);
    let def_hdrs = client_internal::build_profile_headers(prof_spec);

    var c = Client {
        base_url:                base_buf,
        profile:                 prof_spec.kind,
        profile_spec:            prof_spec,
        proxy_url:               proxy_buf,
        timeout_ms:              cfg.timeout_ms,
        default_headers:         def_hdrs,
        ssrf_guard:              security::SsrfGuardPolicy { enabled: false, .. },
        cache:                   http::Cache { options: cfg.cache_options, .. },
        enable_cache:            cfg.enable_cache,
        altsvc:                  http::AltSvcCache { .. },
        enable_altsvc:           cfg.enable_altsvc,
        enable_protocol_racing:  cfg.enable_protocol_racing,
        quic_race_delay_ms:      cfg.quic_race_delay_ms,
        dict_cache:              http::DictionaryCache { .. },
        enable_compression_dict: cfg.enable_compression_dict,
        pipeline:                InterceptorPipeline { .. },
        wire_pipeline:           wire::default_client_pipeline(),
        hsts:                    http::HstsCache { .. },
        pool:                    net::new_stream_pool(),
        enable_cookie_jar:       cfg.cookie_jar,
        strict_content_decoding: cfg.strict_content_decoding,
        insecure_skip_verify:    cfg.insecure_skip_verify,
        tls_backend:             cfg.tls_backend,
        tls_min_version:         cfg.tls_min_version,
        tls_ca_file:             ca_file_buf,
        tls_use_system_roots:    cfg.tls_use_system_roots,
        allow_legacy_md5_digest: cfg.allow_legacy_md5_digest,
        has_invalid_tls_config:  bad_ca_cfg,
        jar:                     cookie::CanonicalCookieJar { .. },
        ..
    };
    let has_sig = cfg.sig_private_key.len > 0 || cfg.sig_public_key.len > 0;
    if has_sig && !c.set_http_signature_keys(cfg.sig_key_id, cfg.sig_private_key, cfg.sig_public_key) {
        c.has_invalid_sig_config = true;
    }
    client_internal::apply_client_config_knobs(c, cfg);
    return c;
}

fn new_client(base_url: const u8[:]) -> Client {
    let def_p = fingerprint::wing_default_profile();
    let def_hdrs = client_internal::build_profile_headers(def_p);
    var base_buf: u8[..256] = [];
    let _ = base_buf.try_set(base_url);
    return Client {
        base_url:                base_buf,
        profile:                 def_p.kind,
        profile_spec:            def_p,
        default_headers:         def_hdrs,
        ssrf_guard:              security::SsrfGuardPolicy { enabled: false, .. },
        cache:                   http::Cache { .. },
        enable_cache:            false,
        altsvc:                  http::AltSvcCache { .. },
        enable_altsvc:           true,
        enable_protocol_racing:  true,
        quic_race_delay_ms:      200,
        dict_cache:              http::DictionaryCache { .. },
        enable_compression_dict: true,
        pipeline:                InterceptorPipeline { .. },
        wire_pipeline:           wire::default_client_pipeline(),
        hsts:                    http::HstsCache { .. },
        enable_hsts:             true,
        pool:                    net::new_stream_pool(),
        enable_cookie_jar:       true,
        jar:                     cookie::CanonicalCookieJar { .. },
        ..
    };
}

fn new_client<F: fn(Client&)>(base_url: const u8[:]) -> Client {
    var c = new_client(base_url);
    F(&c);
    return c;
}

fn new_client<F: fn(Client&)>() -> Client {
    var c = new_client();
    F(&c);
    return c;
}

inline fn new_session() -> Client { return new_client(); }
inline fn new_session(cfg: Config) -> Client { return new_client(cfg); }
inline fn new_session(base_url: const u8[:]) -> Client { return new_client(base_url); }
fn new_session<F: fn(Client&)>(base_url: const u8[:]) -> Client {
    var c = new_client(base_url);
    F(&c);
    return c;
}
fn new_session<F: fn(Client&)>() -> Client {
    var c = new_client();
    F(&c);
    return c;
}

// ---- 3. Core Session Mutators & Fingerprint Accessors ----------------------

fn set_base_url(session: Session&, url: const u8[:]) {
    let n = min(url.len, session.base_url.cap);
    let _ = session.base_url.try_set(url[..n]);
}

fn set_profile(session: Session&, profile: fingerprint::Profile) {
    session.profile = profile;
    if profile == fingerprint::Profile.None {
        session.profile_spec = fingerprint::none_profile();
        session.default_headers.clear();
        return;
    }
    if profile == fingerprint::Profile.Custom {
        let p = fingerprint::custom_profile();
        client_internal::apply_profile(session, p);
        return;
    }
    if profile == fingerprint::Profile.Wing {
        let p = fingerprint::wing_default_profile();
        client_internal::apply_profile(session, p);
    }
}

fn set_profile(session: Session&, profile: const fingerprint::ClientProfile&) {
    client_internal::apply_profile(session, profile);
}

fn set_user_agent(session: Session&, ua: const u8[:]) {
    http::set_header(session.default_headers, "User-Agent", ua);
    session.profile_spec.set_user_agent(ua);
}

fn user_agent(session: const Session&) -> const u8[:] {
    let ua = http::get_header(session.default_headers, "user-agent");
    if ua.len > 0 { return ua; }
    return session.profile.user_agent();
}

fn ja4(session: const Session&) -> u8[..64] {
    return session.profile_spec.ja4();
}

fn p0f(session: const Session&) -> u8[..256] {
    return session.profile_spec.format_p0f();
}

fn akamai(session: const Session&) -> u8[..640] {
    return session.profile_spec.format_akamai();
}

fn akamai_hash(session: const Session&) -> u8[..32] {
    return session.profile_spec.akamai_hash();
}

// Validates and configures an outbound proxy (`http://`, `https://`, `socks5://`, `socks5h://`)
// on `session`, or clears the proxy when `proxy_url` is empty. Drains pooled connections on change.
fn set_proxy(session: Session&, proxy_url: const u8[:]) -> bool {
    if proxy_url.len == 0 {
        core::secure_zeroize_slice(session.proxy_url[..]);
        session.proxy_url.clear();
        net::drain_stream_pool(session.pool);
        return true;
    }
    guard proxy_url.len <= session.proxy_url.cap else { return false; }
    let p_url = core::new_url(proxy_url);
    guard p_url.valid && p_url.hostname().len > 0 else { return false; }
    let sc = p_url.scheme();
    let valid_scheme = sc == "http" || sc == "https" || sc == "socks5" || sc == "socks5h";
    guard valid_scheme else { return false; }
    core::secure_zeroize_slice(session.proxy_url[..]);
    guard session.proxy_url.try_set(proxy_url) else { return false; }
    net::drain_stream_pool(session.pool);
    return true;
}

fn set_timeout_ms(session: Session&, ms: i64) {
    session.timeout_ms = ms;
}

// Closes all idle and active connections in the session's pool.
fn close(session: Session&) {
    net::drain_stream_pool(session.pool);
}

fn set_redirect_mode(session: Session&, mode: RedirectMode) {
    session.redirect_mode = mode;
    session.follow_redirects = (mode == RedirectMode.Follow);
}

// ---- 4. Protocol, Interceptor, Auth, HSTS, Cookie & Mock Route Configurators

fn enable_doh(session: Session&, endpoint: const u8[:] = "https://cloudflare-dns.com/dns-query", use_post: bool = true) {
    session.enable_doh = true;
    let n = min(endpoint.len, session.doh.endpoint.cap);
    let _ = session.doh.endpoint.try_set(endpoint[..n]);
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
    client_internal::resolve_target_origin(target, origin_buf);
    let now_sec = div_euclid(effective_clock_us(session), 1000000);
    var ep = http::AltSvcEndpoint { .. };
    return http::lookup_h3(session.altsvc, origin_buf[..], now_sec, ep);
}

fn is_altsvc_broken(session: const Session&, target: const u8[:]) -> bool {
    var origin_buf: u8[..128] = [];
    client_internal::resolve_target_origin(target, origin_buf);
    let now_sec = div_euclid(effective_clock_us(session), 1000000);
    return http::is_broken(session.altsvc, origin_buf[..], now_sec);
}

// ---- compression dictionary transport configuration (chrome 123+ dcz/dcb) --

fn enable_compression_dict(session: Session&, enabled: bool = true) {
    session.enable_compression_dict = enabled;
}

fn has_dictionary_for(session: const Session&, target_url: const u8[:]) -> bool {
    var origin_buf: u8[..128] = [];
    client_internal::resolve_target_origin(target_url, origin_buf);
    var path_buf: u8[..256] = [];
    let parsed, _ = core::parse_url(target_url);
    if parsed.valid {
        let _ = path_buf.try_set(parsed.pathname());
    } else {
        let _ = path_buf.try_set("/");
    }
    let now_sec = div_euclid(effective_clock_us(session), 1000000);
    let _, found = http::dictionary_lookup_for_request(session.dict_cache, origin_buf[..], path_buf[..], now_sec);
    return found;
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
    session.has_invalid_sig_config = false;
    return true;
}

// ---- hsts configuration (rfc 6797 strict transport security) ---------------

fn enable_hsts(session: Session&, enabled: bool = true) {
    session.enable_hsts = enabled;
}

fn is_hsts(session: const Session&, hostname: const u8[:]) -> bool {
    let now_sec = div_euclid(effective_clock_us(session), 1000000);
    return http::is_hsts_host(session.hsts, hostname, now_sec);
}

fn export_hsts<B>(session: const Session&, out: B&) -> i64 {
    let now_sec = div_euclid(effective_clock_us(session), 1000000);
    return http::save_hsts_cache(session.hsts, now_sec, out);
}

fn import_hsts(session: Session&, data: const u8[:]) -> i64 {
    let now_sec = div_euclid(effective_clock_us(session), 1000000);
    return http::load_hsts_cache(session.hsts, data, now_sec);
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

// Returns the active clock in microseconds: explicit `virtual_clock_us` when > 0,
// or the live system/simulation wall clock (`core::now().unix_micro()`) otherwise.
fn effective_clock_us(session: const Session&) -> i64 {
    if session.virtual_clock_us > 0 {
        return session.virtual_clock_us;
    }
    return core::now().unix_micro();
}

fn trust_location_host(session: Session&, host_name: const u8[:]) -> bool {
    guard host_name.len > 0 && host_name.len <= 128 else { return false; }
    guard !client_internal::is_trusted_location_host(session, host_name) else { return true; }
    var host_buf: u8[..128] = [];
    host_name.to_lower_ascii(host_buf);
    return session.trusted_location_hosts.try_push(host_buf);
}

// Loads PEM-encoded CA trust anchors from `path` into `sess.trust_store` and
// enforces peer certificate verification on the session.
//
// Example:
//   let count, ok = sess.load_trust_anchors_pem_file("certs/ca.pem");
//   returns: count >= 1, ok = true (or 0, false if unreadable/empty/invalid)
fn load_trust_anchors_pem_file(sess: Session&, path: const u8[:]) -> i64, bool {
    guard path.len > 0 else { return 0, false; }
    let count, ok = tls::load_trust_anchors_pem_file(sess.trust_store, path);
    guard ok else { return 0, false; }
    sess.insecure_skip_verify = false;
    return count, true;
}

// Validates and appends PEM CA trust anchors into `sess.trust_store`, enforces
// certificate verification, and optionally allows loopback/local-network
// targets for local test or proxy harnesses.
//
// Example:
//   let count, ok = sess.configure_session_tls_ca_pem(ca_pem, true);
//   returns: count >= 1, ok = true with `sess.ssrf_guard.deny_local_network = false`
fn configure_session_tls_ca_pem(
    sess:           Session&,
    pem_bundle:     const u8[:],
    allow_loopback: bool = false,
) -> i64, bool {
    guard pem_bundle.len > 0 else { return 0, false; }
    let saved_len = sess.trust_store.anchors.len;
    let count, ok = tls::add_trust_anchors_pem(sess.trust_store, pem_bundle);
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

// Selects the pluggable TLS backend on `session` and drains pooled connections if changed.
fn set_tls_backend(session: Session&, kind: tls::TlsBackendKind) {
    if session.tls_backend != kind {
        session.tls_backend = kind;
        net::drain_stream_pool(session.pool);
    }
}

// Configures the minimum TLS version floor on `session` and drains pooled connections if changed.
fn set_tls_min_version(session: Session&, ver: tls::TlsMinVersion) {
    if session.tls_min_version != ver {
        session.tls_min_version = ver;
        net::drain_stream_pool(session.pool);
    }
}

// Configures a PEM CA bundle file path for pluggable TLS backends on `session`.
// Enforces peer certificate verification when `path` is non-empty and drains pooled connections.
fn set_tls_ca_file(session: Session&, path: const u8[:]) -> bool {
    guard session.tls_ca_file.try_set(path) else { return false; }
    if path.len > 0 {
        session.insecure_skip_verify = false;
    }
    net::drain_stream_pool(session.pool);
    return true;
}

// Configures a bounded grace window (clamped to 0..MAX_EXPIRED_LEAF_GRACE_SEC) allowing recently
// expired leaf certificates while keeping full CA chain, SAN, and TLS 1.3 signature checks strict.
fn set_tls_expired_leaf_grace_sec(session: Session&, grace_sec: i64) {
    let clamped = min(max(grace_sec, 0), tls::MAX_EXPIRED_LEAF_GRACE_SEC);
    if session.tls_expired_leaf_grace_sec != clamped {
        session.tls_expired_leaf_grace_sec = clamped;
        net::drain_stream_pool(session.pool);
    }
}

// Controls whether OS system root certificates are loaded when no custom CA bundle or trust store is set.
fn set_tls_use_system_roots(session: Session&, enabled: bool) {
    if session.tls_use_system_roots != enabled {
        session.tls_use_system_roots = enabled;
        net::drain_stream_pool(session.pool);
    }
}

// Configures client mTLS PEM certificate and private key paths on `session`.
// Both paths must either be empty (to clear mTLS) or non-empty and within capacity.
fn set_tls_client_cert(session: Session&, cert_file: const u8[:], key_file: const u8[:]) -> bool {
    let both_empty = cert_file.len == 0 && key_file.len == 0;
    let both_set = cert_file.len > 0 && key_file.len > 0;
    guard (both_empty || both_set)
        && cert_file.len <= session.tls_client_cert_file.cap
        && key_file.len <= session.tls_client_key_file.cap else {
        return false;
    }
    let _ = session.tls_client_cert_file.try_set(cert_file);
    let _ = session.tls_client_key_file.try_set(key_file);
    net::drain_stream_pool(session.pool);
    return true;
}

// Configures comma-separated ALPN protocol offers (e.g. `"http/1.1"` or `"h2,http/1.1"`).
// Pass an empty slice to restore the default `"h2,http/1.1"` offer.
fn set_tls_alpn(session: Session&, alpn_csv: const u8[:]) -> bool {
    guard alpn_csv.len <= session.tls_alpn.cap else { return false; }
    if alpn_csv.len > 0 {
        var check_wire: u8[..64] = [];
        guard client_internal::encode_alpn_csv_to_wire(alpn_csv, check_wire) else { return false; }
    }
    let _ = session.tls_alpn.try_set(alpn_csv);
    net::drain_stream_pool(session.pool);
    return true;
}

// Enables or disables X25519MLKEM768 post-quantum hybrid key exchange on `session`.
fn set_tls_enable_pq_hybrid(session: Session&, enabled: bool) {
    if session.tls_enable_pq_hybrid != enabled {
        session.tls_enable_pq_hybrid = enabled;
        net::drain_stream_pool(session.pool);
    }
}

// Enables or disables TLS 1.3 session ticket caching and PSK resumption on `session`.
fn set_tls_enable_session_tickets(session: Session&, enabled: bool) {
    if session.tls_enable_session_tickets != enabled {
        session.tls_enable_session_tickets = enabled;
        net::drain_stream_pool(session.pool);
    }
}

// Requires stapled OCSP responses from TLS peers (fail-closed) when `required` is true.
fn set_tls_require_ocsp_stapling(session: Session&, required: bool) {
    if session.tls_require_ocsp_stapling != required {
        session.tls_require_ocsp_stapling = required;
        net::drain_stream_pool(session.pool);
    }
}

// Configures an X.509 CRL file path (DER or PEM) for certificate revocation checks.
fn set_tls_crl_file(session: Session&, path: const u8[:]) -> bool {
    guard session.tls_crl_file.try_set(path) else { return false; }
    net::drain_stream_pool(session.pool);
    return true;
}

// Configures an NSS SSLKEYLOGFILE path for TLS 1.3 traffic secret logging.
fn set_tls_keylog_file(session: Session&, path: const u8[:]) -> bool {
    guard session.tls_keylog_file.try_set(path) else { return false; }
    net::drain_stream_pool(session.pool);
    return true;
}

// Constrains outbound TCP connections to IPv4, IPv6, or automatic dual-stack selection.
fn set_ip_family(session: Session&, family: net::IpFamily) {
    if session.ip_family != family {
        session.ip_family = family;
        net::drain_stream_pool(session.pool);
    }
}

// Enables or disables automatic Content-Encoding decompression on HTTP responses.
fn set_auto_decompress(session: Session&, enabled: bool) {
    session.auto_decompress = enabled;
}

// Sets the maximum permitted response body size in bytes (`0` disables the limit).
fn set_max_response_body_bytes(session: Session&, max_bytes: i64) {
    session.max_response_body_bytes = max(max_bytes, 0);
}

// Registers a static `(host, port) -> ip` TCP dial override (similar to `curl --resolve`)
// while preserving the original `Host` header, TLS SNI, and certificate hostname verification.
fn add_resolve_override(
    session: Session&,
    host:    const u8[:],
    port:    u16,
    ip:      const u8[:],
) -> bool {
    let h_trim = host.trim_lws().trim_end_byte('.');
    let ip_trim = ip.trim_lws();
    guard h_trim.len > 0 && h_trim.len <= 128 && ip_trim.len > 0 && ip_trim.len <= 64 else {
        return false;
    }
    let _, ok_ip = core::parse_ip_addr(ip_trim);
    guard ok_ip else { return false; }

    var low_host: u8[..128] = [];
    h_trim.to_lower_ascii(low_host);
    for &ov in session.resolve_overrides {
        if ov.port == port && ov.host[..] == low_host[..] {
            guard ov.ip.try_set(ip_trim) else { return false; }
            net::drain_stream_pool(session.pool);
            return true;
        }
    }
    var entry = ResolveOverride { port: port, .. };
    guard entry.host.try_set(low_host[..]) && entry.ip.try_set(ip_trim) else { return false; }
    guard session.resolve_overrides.try_push(entry) else { return false; }
    net::drain_stream_pool(session.pool);
    return true;
}

// Registers a `NO_PROXY` bypass pattern (exact host, `.suffix`, `*`, CIDR, or `localhost`).
fn add_no_proxy(session: Session&, pattern: const u8[:]) -> bool {
    let pat = pattern.trim_ascii_space();
    guard pat.len > 0 && pat.len <= 128 else { return false; }
    for &existing in session.no_proxy_rules {
        if existing[..].eq_ascii_fold(pat) { return true; }
    }
    var pat_buf: u8[..128] = [];
    guard pat_buf.try_set(pat) else { return false; }
    return session.no_proxy_rules.try_push(pat_buf);
}

// Evaluates whether `host` bypasses configured or environment proxies via `no_proxy_rules`
// (and `NO_PROXY` / `no_proxy` when `session.use_env_proxy` is true).
fn is_no_proxy_host(session: const Session&, host: const u8[:]) -> bool {
    let norm_host = client_internal::normalize_no_proxy_host(host);
    guard norm_host.len > 0 else { return false; }
    for &rule in session.no_proxy_rules {
        if client_internal::match_no_proxy_pattern(rule[..], norm_host) {
            return true;
        }
    }
    if session.use_env_proxy {
        return client_internal::matches_env_no_proxy(norm_host);
    }
    return false;
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

fn add_mock_websocket(session: Session&, url_pattern: const u8[:], subprotocol: const u8[:] = "") {
    var route = MockExchange {
        status_code: rfc::STATUS_SWITCHING_PROTOCOLS,
        ..
    };
    guard route.method.try_set("GET") && route.pattern_url.try_set(url_pattern) else { return; }
    http::set_header(route.headers, "Upgrade", "websocket");
    http::set_header(route.headers, "Connection", "Upgrade");
    if subprotocol.len > 0 {
        http::set_header(route.headers, "Sec-WebSocket-Protocol", subprotocol);
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
    http::set_header(route.headers, "Content-Type", "text/event-stream");
    http::set_header(route.headers, "Cache-Control", "no-cache");
    http::set_header(route.headers, "Connection", "keep-alive");
    let _ = session.mock_routes.try_push(route);
}

// ---- cookie & default header helpers ---------------------------------------

fn set_cookie(session: Session&, name: const u8[:], value: const u8[:]) {
    var raw_hdr: u8[..4128] = [];
    guard raw_hdr.try_append(name)
        && raw_hdr.try_push('=')
        && raw_hdr.try_append(value)
        && raw_hdr.try_append("; Path=/") else { return; }
    let now_us = effective_clock_us(session);
    if session.base_url.len > 0 {
        session.jar.set_cookie_header(session.base_url[..], raw_hdr[..], now_us);
    } else {
        session.jar.set_cookie_header("https://example.com/", raw_hdr[..], now_us);
    }
}

fn cookie(session: const Session&, name: const u8[:]) -> const u8[:] {
    return session.jar.get(name);
}

fn default_header(session: Session&, name: const u8[:], value: const u8[:]) {
    http::set_header(session.default_headers, name, value);
}

// ---- 5. ECH Discovery ------------------------------------------------------

// Discovers or extracts ECHConfigList for a domain.
// Checks local `dns::Cache` first; if missing/expired and DoH is enabled, performs RFC 9460 Type 65 discovery.
fn resolve_ech_config(
    session: Session&,
    domain:  const u8[:],
    now_sec: i64,
) -> u8[..512], bool {
    let cached_ech, ok_cached = client_internal::lookup_cached_ech_config(session.dns_cache, domain, now_sec);
    if ok_cached {
        return cached_ech, true;
    }
    let disc_ech, ok_disc = client_internal::discover_and_cache_ech_config(session, domain, now_sec);
    if ok_disc {
        return disc_ech, true;
    }
    // Fallback: if discovery failed, check if a stale entry is available.
    var stale_ech: u8[..512] = [];
    let cached, stale_status = session.dns_cache.lookup(domain, rfc::DNS_QTYPE_HTTPS, now_sec);
    if cached && (stale_status == dns::CacheStatus.Fresh || stale_status == dns::CacheStatus.Stale) {
        for &rec in cached.https_records {
            if rec.has_ech && rec.ech_config_list.len > 0 {
                let ok_set = stale_ech.try_set(rec.ech_config_list[..]);
                return stale_ech, ok_set;
            }
        }
    }
    return stale_ech, false;
}

// ---- 6. Ergonomic Session Control, Credential Wipe, and Problem Decode -----

// Toggles loopback SSRF allowance consistently on both `Session.allow_loopback_ssrf`
// and `Session.ssrf_guard.deny_local_network`.
fn set_allow_loopback_ssrf(session: Session&, allow: bool) {
    session.allow_loopback_ssrf = allow;
    session.ssrf_guard.deny_local_network = !allow;
}

// Configures Bearer authentication strictly scoped to `session.base_url`'s origin
// (`scheme://host[:port]`) so credentials are never injected into third-party absolute URLs.
fn set_base_url_bearer_auth(session: Session&, token: const u8[:]) -> bool {
    guard session.base_url.len > 0 && token.len > 0 else { return false; }
    let parsed, url_err = core::parse_url(session.base_url[..]);
    guard url_err == core::UrlParseError.None && parsed.valid else { return false; }
    return add_scoped_bearer_auth(session.pipeline, token);
}

fn wipe_sensitive_interceptor_headers(hdrs: InterceptorHeader[..4]&) {
    for &h in hdrs {
        if http::is_heuristic_sensitive_header(h.name[..]) {
            core::secure_zeroize_slice(h.val[..]);
            h.val.clear();
        }
    }
}

fn wipe_sensitive_default_headers(hdrs: http::HeaderMap&) {
    var has_sens = false;
    for &e in hdrs.entries {
        let name = http::entry_name(hdrs, e);
        if http::is_sensitive(e) || http::is_heuristic_sensitive_header(name) {
            has_sens = true;
        }
    }
    guard has_sens else { return; }
    var kept_names: u8[..64][..16]  = [];
    var kept_vals:  u8[..256][..16] = [];
    for &e in hdrs.entries {
        let name = http::entry_name(hdrs, e);
        let sens = http::is_sensitive(e) || http::is_heuristic_sensitive_header(name);
        if !sens && kept_names.len < 16 {
            var n_buf: u8[..64]  = [];
            var v_buf: u8[..256] = [];
            if n_buf.try_set(name) && v_buf.try_set(http::entry_value(hdrs, e)) {
                let _ = kept_names.try_push(n_buf);
                let _ = kept_vals.try_push(v_buf);
            }
        }
    }
    core::secure_zeroize_slice(hdrs.raw_buf[..]);
    hdrs.clear();
    for i in kept_names.len {
        http::set_header(hdrs, kept_names[i][..], kept_vals[i][..]);
    }
}

// Wipes stored Bearer, Basic/Digest, DPoP, HTTP Signature private key, proxy URL, and
// sensitive header credentials held inside `session`.
fn zeroize_auth(session: Session&) {
    core::secure_zeroize_slice(session.pipeline.bearer_token[..]);
    session.pipeline.bearer_token.clear();
    session.pipeline.active_mask &= ~(INTERCEPTOR_APP_AUTH_BEARER | INTERCEPTOR_APP_AUTH_BEARER_SCOPED);

    core::secure_zeroize_slice(session.sig_private_key[..]);
    session.sig_private_key.clear();

    core::secure_zeroize_slice(session.proxy_url[..]);
    session.proxy_url.clear();

    core::secure_zeroize_slice(session.dpop.private_key[..]);
    core::secure_zeroize_slice(session.dpop.access_token[..]);
    session.dpop.access_token.clear();
    session.dpop.has_key = false;

    core::secure_zeroize_slice(session.creds.username[..]);
    core::secure_zeroize_slice(session.creds.password[..]);
    session.creds.username.clear();
    session.creds.password.clear();
    session.creds.has_credentials = false;

    wipe_sensitive_interceptor_headers(session.pipeline.app_headers);
    wipe_sensitive_interceptor_headers(session.pipeline.net_headers);
    wipe_sensitive_default_headers(session.default_headers);
}

// Converts a non-2xx HTTP response into a bounded `http::Error` by parsing RFC 9457
// `ProblemDetails` (if present) and UTF-8-safely truncating into `stage` (64B) and `message` (256B).
fn error_from_problem_response(resp: const http::Response&) -> http::Error {
    var prob = http::ProblemDetails { .. };
    let has_prob = http::parse_problem_details(resp.body[..], prob);
    let phrase = rfc::status_phrase(resp.status_code);
    let st_src = if has_prob && prob.title.len > 0 { prob.title[..] } else { phrase };
    let msg_src = if has_prob && prob.detail.len > 0 { prob.detail[..] } else { phrase };
    var out_err = http::Error {
        kind: http::ErrorKind.Protocol,
        code: resp.status_code,
        ..
    };
    let _ = out_err.stage.try_set(http::truncate_utf8_safe(st_src, out_err.stage.cap));
    let _ = out_err.message.try_set(http::truncate_utf8_safe(msg_src, out_err.message.cap));
    return out_err;
}

// Decodes a 2xx JSON response into `T`, returning transport errors unchanged, translating
// non-2xx responses (including RFC 9457 JSON) without buffer panics, and skipping `204`/empty bodies.
//
// Example:
//   resp.status_code = 422, resp.body = "{\"title\":\"Invalid\",\"detail\":\"bad field\"}"
//   returns: (default<T>(), http::Error { kind: Protocol, code: 422, stage: "Invalid", message: "bad field" })
fn decode_json_or_problem<T>(resp: const http::Response&, err: const http::Error&) -> T, http::Error {
    guard http::ok(err) else { return T { .. }, err; }
    guard resp.status_code >= 200 && resp.status_code < 300 else {
        return T { .. }, error_from_problem_response(resp);
    }
    var out = T { .. };
    var has_fields = false;
    const for <N, A> in fields<T> {
        let _ = N;
        has_fields = true;
    }
    if resp.status_code == rfc::STATUS_NO_CONTENT || resp.body.len == 0 || !has_fields {
        return out, http::Error { .. };
    }
    let dec_err = http::json(resp, out);
    return out, dec_err;
}
