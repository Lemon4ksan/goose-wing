# `security`

`security` (`namespace security;`) provides W3C CORS and Cross-Origin Isolation,
Fetch Metadata CSRF protection, AEAD and HMAC cookie jars, Privacy Pass tokens,
RFC 9180 HPKE, SSRF filtering, and GCRA rate limiting.

```goose
import wing;

let quota = security::new_gcra_quota(100, wing::secs(60), 20);
var limiter = security::new_sharded_limiter(quota);
let decision = limiter.check_rate_limit("tenant-42", 1, 1700000000000000000);
let ok = decision.is_allowed();
```

## Public API Reference

### 1. Cross-Origin Resource Sharing (CORS) (`security/cors.goose`)

```goose
enum CorsResult {
    NoCors,
    AllowedActual,
    AllowedPreflight,
    RejectedOrigin,
    RejectedPreflightMethod,
    RejectedPreflightHeaders,
    InvalidConfig,
}

struct CorsPolicy {
    allow_credentials:          bool            = false,
    reject_non_matching_origin: bool            = false,
    allowed_origins:            u8[..128][..16] = [],
    allowed_methods:            u8[..128]       = "GET, POST, PUT, DELETE, PATCH, OPTIONS, QUERY",
    allowed_headers:            u8[..256]       = "Content-Type, Authorization, X-Requested-With, X-API-Key",
    expose_headers:             u8[..256]       = "Content-Length, X-Trace-Id, RateLimit-Limit, RateLimit-Reset",
    max_age_sec:                i64             = 86400,
}

struct ClientCorsVerifyOptions {
    tainted_origin:      bool = false,
    include_credentials: bool = false,
}

fn add_allowed_origin(policy: CorsPolicy&, origin_pattern: const u8[:]) -> bool
fn match_cors_origin_pattern(candidate: const u8[:], pattern: const u8[:]) -> bool
fn is_origin_allowed(policy: const CorsPolicy&, origin_str: const u8[:]) -> bool
fn validate_cors_policy(policy: const CorsPolicy&) -> bool
inline fn apply_cors_vary_header<Res>(res: Res&)
fn are_cors_request_headers_allowed(allowed_list: const u8[:], requested_list: const u8[:], allow_wildcard: bool = true) -> bool
fn verify_client_cors_response<H>(resp_headers: const H&, request_origin: const u8[:], opts: ClientCorsVerifyOptions = ClientCorsVerifyOptions { .. }) -> bool
fn evaluate_cors<Req, Res>(policy: const CorsPolicy&, req: const Req&, res: Res&) -> CorsResult
```

`CorsPolicy` stores up to 16 allowed origin patterns (`u8[..128][..16]`).
`match_cors_origin_pattern` matches exact origins or wildcard subdomain patterns
such as `https://*.example.com` after validating RFC 1035 DNS label syntax.
`validate_cors_policy` rejects configurations that combine a literal `*` or
`null` origin with `allow_credentials = true`. `evaluate_cors` validates the
policy, checks the `Origin` header, appends `Vary` headers via
`apply_cors_vary_header`, and populates preflight or actual response headers.

### 2. Cross-Origin Isolation (`security/cross_origin_isolation.goose`)

```goose
enum CoopPolicy { Unknown, UnsafeNone, SameOriginAllowPopups, SameOrigin }
enum CoepPolicy { Unknown, UnsafeNone, Credentialless, RequireCorp }
enum CorpPolicy { Unknown, None, SameOrigin, SameSite, CrossOrigin }

struct CrossOriginIsolationContext {
    coop:                     CoopPolicy = CoopPolicy.UnsafeNone,
    coep:                     CoepPolicy = CoepPolicy.UnsafeNone,
    is_cross_origin_isolated: bool       = false,
    document_origin:          u8[..128]  = [],
}

fn parse_coop(val: const u8[:]) -> CoopPolicy
fn parse_coep(val: const u8[:]) -> CoepPolicy
fn parse_corp(val: const u8[:]) -> CorpPolicy
fn extract_hostname_from_origin(origin_or_url: const u8[:]) -> const u8[:]
fn update_isolation_context(ctx: CrossOriginIsolationContext&, coop_header: const u8[:], coep_header: const u8[:], document_origin: const u8[:]) -> bool
fn update_from_headers<H>(ctx: CrossOriginIsolationContext&, headers: const H&, document_origin: const u8[:]) -> bool
fn is_subresource_allowed(ctx: const CrossOriginIsolationContext&, subresource_origin: const u8[:], subresource_corp_header: const u8[:]) -> bool
fn apply_strict_cross_origin_isolation<Res>(res: Res&)
```

`parse_coop`, `parse_coep`, and `parse_corp` strip RFC 8941 Structured Field
parameters (`; report-to=...`) before matching W3C HTML §7.2 and Fetch §4.5
policy tokens, rejecting multi-item comma lists. `update_isolation_context` and
`update_from_headers` set `is_cross_origin_isolated = true` only when `coop ==
CoopPolicy.SameOrigin` and `coep` is `RequireCorp` or `Credentialless`.
`is_subresource_allowed` enforces `Cross-Origin-Resource-Policy` checks on
embedded subresources.

### 3. Cryptographic Cookie Jars (`security/crypto_jar.goose`)

```goose
struct KeySlot {
    key_id:         u32    = 0,
    master_key:     u8[32] = [0; 32],
    signing_key:    u8[32] = [0; 32],
    encryption_key: u8[32] = [0; 32],
    created_at_sec: i64    = 0,
    expires_at_sec: i64    = 0,
    revoked:        bool   = false,
}

struct KeyStore {
    keys:                     KeySlot[..8] = [],
    active_idx:               i64          = 0,
    max_age_sec:              i64          = 2592000,
    clock_skew_tolerance_sec: i64          = 300,
}

struct PrivateJar {
    store:        KeyStore = KeyStore { .. },
    use_hkdf_aes: bool     = false,
}

struct SignedJar {
    store: KeyStore = KeyStore { .. },
}

fn add_key(store: KeyStore&, slot: const KeySlot&) -> bool
fn active_key(store: const KeyStore&) -> KeySlot, bool
fn set_active_key_id(store: KeyStore&, key_id: u32) -> bool
fn find_key(store: const KeyStore&, key_id: u32) -> KeySlot, bool
fn revoke_key(store: KeyStore&, key_id: u32) -> bool
fn needs_rotation(slot: const KeySlot&, now_sec: i64) -> bool
fn is_cookie_timestamp_valid(store: const KeyStore&, cookie_u: u64, now_sec: i64) -> bool
fn is_cookie_timestamp_valid(store: const KeyStore&, cookie_sec: i64, now_sec: i64) -> bool
fn new_private_jar(store: KeyStore, use_hkdf_aes: bool = false) -> PrivateJar
fn seal_binary<B>(jar: const PrivateJar&, cookie_name: const u8[:], plaintext: const u8[:], now_sec: i64, nonce_seed: u64, out: B&) -> bool
fn open_binary<B>(jar: const PrivateJar&, cookie_name: const u8[:], raw_wire: const u8[:], now_sec: i64, out: B&) -> bool
fn seal<B>(jar: const PrivateJar&, cookie_name: const u8[:], plaintext: const u8[:], now_sec: i64, nonce_seed: u64, out: B&) -> bool
fn open<B>(jar: const PrivateJar&, cookie_name: const u8[:], encoded_val: const u8[:], now_sec: i64, out: B&) -> bool
fn new_signed_jar(store: KeyStore) -> SignedJar
fn seal_binary<B>(jar: const SignedJar&, cookie_name: const u8[:], payload: const u8[:], now_sec: i64, out: B&) -> bool
fn open_binary<B>(jar: const SignedJar&, cookie_name: const u8[:], raw_wire: const u8[:], now_sec: i64, out: B&) -> bool
fn seal<B>(jar: const SignedJar&, cookie_name: const u8[:], payload: const u8[:], now_sec: i64, out: B&) -> bool
fn open<B>(jar: const SignedJar&, cookie_name: const u8[:], encoded_val: const u8[:], now_sec: i64, out: B&) -> bool
```

`KeyStore` holds up to 8 `KeySlot` entries with HKDF-SHA256 domain-separated
signing and encryption subkeys. `PrivateJar` seals cookies with
`XChaCha20-Poly1305` (wire version `0x01`, 53-byte overhead) or
`HKDF-SHA256 + AES-256-GCM` (wire version `0x02`, 65-byte overhead), binding the
wire version, `key_id`, 64-bit creation timestamp, and `cookie_name` into the
AEAD Additional Authenticated Data (AAD) to prevent cross-cookie swapping and
replay. `SignedJar` authenticates payloads with `HMAC-SHA256` (wire version
`0x03`, 45-byte overhead) verified via `core::ct_eq_tag32`.

### 4. W3C Fetch Metadata & Masked CSRF Tokens (`security/csrf.goose`)

```goose
enum SecFetchSite { Unknown, SameOrigin, SameSite, CrossSite, None, Missing }
enum SecFetchMode { Navigate, SameOrigin, Cors, NoCors, WebSocket, Other }
enum SecFetchDest { Document, NestedDocument, Iframe, Frame, Embed, Object, Script, Image, Style, Font, Empty, Other }
enum CsrfTargetScheme { Https, Http }

enum CsrfRejectReason {
    CrossSiteStateMutation,
    DisallowedSameSiteSubdomain,
    CrossSiteFramingOrXssi,
    CrossSiteUnauthorizedSubresource,
    OriginHostMismatch,
    MissingBrowserHeadersWithSessionCookie,
    MissingUserActivationOnSensitiveNav,
}

enum CsrfDecision {
    Allow,
    RejectForbidden { reason: CsrfRejectReason },
    AllowExempt,
}

struct CrossOriginGuard {
    allow_same_site:                          bool            = false,
    require_user_activation_on_sensitive_nav: bool            = true,
    allow_cross_site_static_assets:           bool            = true,
    trusted_origins:                          u8[..128][..16] = [],
    exempt_paths:                             u8[..128][..16] = [],
}

struct FetchContext {
    method_is_safe:                bool         = true,
    method:                        u8[..16]     = "GET",
    site:                          SecFetchSite = SecFetchSite.Missing,
    mode:                          SecFetchMode = SecFetchMode.Other,
    dest:                          SecFetchDest = SecFetchDest.Other,
    user_activated:                bool         = false,
    has_origin:                    bool         = false,
    origin:                        u8[..256]    = [],
    has_referer:                   bool         = false,
    referer:                       u8[..512]    = [],
    target_scheme:                 u8[..16]     = "https",
    target_host:                   u8[..256]    = [],
    path:                          u8[..512]    = "/",
    has_session_cookie:            bool         = false,
    has_explicit_auth:             bool         = false,
    is_sensitive_navigation_route: bool         = false,
}

fn parse_sec_fetch_site(val: const u8[:]) -> SecFetchSite
fn parse_sec_fetch_mode(val: const u8[:]) -> SecFetchMode
fn parse_sec_fetch_dest(val: const u8[:]) -> SecFetchDest
fn csrf_reject_reason_to_string(reason: CsrfRejectReason) -> const u8[:]
fn is_allowed(decision: const CsrfDecision&) -> bool
fn add_trusted_origin(guard_cfg: CrossOriginGuard&, origin_str: const u8[:]) -> bool
fn add_exempt_path(guard_cfg: CrossOriginGuard&, path_str: const u8[:]) -> bool
fn subtle_equal_ascii_fold(a: const u8[:], b: const u8[:]) -> bool
fn validate_csrf_token(cookie_token: const u8[:], request_token: const u8[:]) -> bool
fn mask_csrf_token<B>(mask: const u8[:], raw_secret: const u8[:], out: B&) -> bool
fn generate_masked_csrf_token<B>(raw_secret: const u8[:], out: B&) -> bool
fn verify_masked_csrf_token(masked_token: const u8[:], expected_unmasked: const u8[:]) -> bool
fn extract_origin_from_url(url_or_origin: const u8[:]) -> const u8[:]
fn extract_host_from_url(url_or_origin: const u8[:]) -> const u8[:]
fn extract_path_from_url(raw: const u8[:]) -> const u8[:]
fn extract_fetch_context<Req>(req: const Req&, target_host: const u8[:] = "", is_sensitive_nav: bool = false, target_scheme: CsrfTargetScheme = CsrfTargetScheme.Https) -> FetchContext
fn evaluate_fetch_metadata(guard_cfg: const CrossOriginGuard&, ctx: const FetchContext&) -> CsrfDecision
fn evaluate_request_csrf<Req>(guard_cfg: const CrossOriginGuard&, req: const Req&, target_host: const u8[:], is_sensitive_nav: bool = false, target_scheme: CsrfTargetScheme = CsrfTargetScheme.Https) -> CsrfDecision
fn apply_isolation_headers<Res>(res: Res&)
```

`evaluate_fetch_metadata` evaluates `FetchContext` against the W3C Fetch
Metadata decision matrix (`Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`)
and falls back to `Origin` and `Referer` host verification when Fetch Metadata
headers are absent. `mask_csrf_token` and `verify_masked_csrf_token` apply
One-Time-Pad (OTP) XOR masking (`mask || (mask ^ secret)`) and constant-time
comparison (`core::ct_eq_bytes`) to mitigate BREACH compression side channels.

### 5. Privacy Pass (`security/privacypass.goose`)

```goose
struct TokenChallenge {
    token_type:         u16       = rfc::TOKEN_TYPE_BLIND_RSA,
    issuer_name:        u8[..128] = [],
    redemption_context: u8[..32]  = [],
    origin_info:        u8[..256] = [],
}

struct Token {
    token_type:       u16       = rfc::TOKEN_TYPE_BLIND_RSA,
    nonce:            u8[32]    = [0; 32],
    challenge_digest: u8[32]    = [0; 32],
    token_key_id:     u8[..32]  = [],
    authenticator:    u8[..256] = [],
}

struct CachedToken {
    challenge_digest: u8[32]    = [0; 32],
    token:            Token     = Token { .. },
    raw_token:        u8[..512] = [],
    expires_at_sec:   i64       = 0,
    used:             bool      = false,
}

struct PrivateTokenCache {
    entries: CachedToken[..16] = [],
}

fn marshal_token_challenge<B>(challenge: const TokenChallenge&, out: B&) -> bool
fn unmarshal_token_challenge(data: const u8[:]) -> TokenChallenge, bool
fn compute_challenge_digest(challenge: const TokenChallenge&) -> u8[32]
fn marshal_token<B>(token: const Token&, out: B&) -> bool
fn unmarshal_token(data: const u8[:], key_id_len: i64, auth_len: i64) -> Token, bool
fn parse_private_token_challenge<B>(header_val: const u8[:], out: B&) -> TokenChallenge, i64, bool
fn encode_padded_base64url<B>(data: const u8[:], out: B&) -> bool
fn format_private_token_authorization<B>(token_bytes: const u8[:], out: B&) -> bool
fn format_sec_private_state_token<B>(token_bytes: const u8[:], out: B&) -> bool
fn put_private_token(cache: PrivateTokenCache&, challenge: const TokenChallenge&, token: const Token&, raw_token: const u8[:], ttl_sec: i64, now_sec: i64) -> bool
fn get_private_token<B>(cache: PrivateTokenCache&, challenge: const TokenChallenge&, now_sec: i64, out: B&) -> Token, bool
fn pop_private_token<B>(cache: PrivateTokenCache&, challenge_digest: const u8[32]&, now_sec: i64, out: B&) -> bool
fn attach_private_token<R>(req: R&, token_bytes: const u8[:]) -> bool
fn has_private_token_challenge<Res>(res: const Res&) -> bool
```

Implements RFC 9576, RFC 9577, and RFC 9578 `PrivateToken` wire serialization
and challenge parsing. `unmarshal_token_challenge` validates that
`redemption_context` is either 0 or 32 bytes and that no trailing bytes remain.
`PrivateTokenCache` stores up to 16 single-use tokens indexed by the 32-byte
`SHA-256(TokenChallenge)` digest (`compute_challenge_digest`);
`get_private_token` and `pop_private_token` mark the entry as `used` upon
retrieval.

### 6. GCRA Rate Limiter (`security/rate_limiter.goose`)

```goose
struct GcraQuota {
    emission_interval_ns: u64 = 1000000000,
    delay_tolerance_ns:   u64 = 0,
    limit:                u64 = 1,
    period_ns:            u64 = 1000000000,
    burst:                u64 = 0,
}

enum RateLimitDecision {
    Allowed { remaining_burst: u64, new_tat_ns: u64, reset_after_ns: u64 },
    Reserved { wait_ns: u64, new_tat_ns: u64 },
    Rejected { retry_after_ns: u64, current_tat_ns: u64, insufficient_capacity: bool = false },
}

struct GcraCell { tat_ns: u64 = 0 }

struct KeyedGcraSlot {
    key:    u8[..64] = [],
    cell:   GcraCell = GcraCell { .. },
    active: bool     = false,
}

struct GcraShard { slots: KeyedGcraSlot[..16] = [] }

struct ShardedGcraLimiter {
    quota:  GcraQuota      = GcraQuota { .. },
    shards: GcraShard[256] = [GcraShard { .. }; 256],
}

struct ProbabilisticGcra {
    quota:         GcraQuota = GcraQuota { .. },
    cell:          GcraCell  = GcraCell { .. },
    sample_rate:   u64       = 20,
    rng_state:     u64       = 0,
    window_pos:    u64       = 0,
    window_target: u64       = 0,
    initialized:   bool      = false,
}

struct GcraJitter {
    min_ns: i64 = 0,
    max_ns: i64 = 0,
}

fn new_gcra_quota(limit: u64, period_ns: i64, burst: u64 = 0) -> GcraQuota
fn new_sharded_limiter(quota: GcraQuota) -> ShardedGcraLimiter
fn new_probabilistic_gcra(quota: GcraQuota, sample_rate: u64 = 20) -> ProbabilisticGcra
fn format_gcra_key(key_str: const u8[:]) -> u8[..64]
fn gcra_check_n(quota: const GcraQuota&, cell: GcraCell&, cost_n: u64, now_ns: u64) -> RateLimitDecision
fn gcra_reserve_n(quota: const GcraQuota&, cell: GcraCell&, cost_n: u64, now_ns: u64, max_wait_ns: u64) -> RateLimitDecision
fn check_rate_limit(limiter: ShardedGcraLimiter&, key_str: const u8[:], cost_n: u64, now_ns: u64) -> RateLimitDecision
fn check_rate_limit(pgcra: ProbabilisticGcra&, cost_n: u64, now_ns: u64) -> RateLimitDecision
fn is_allowed(decision: const RateLimitDecision&) -> bool
fn is_insufficient_capacity(decision: const RateLimitDecision&) -> bool
fn to_gcra_decision(decision: const RateLimitDecision&) -> GcraDecision
fn apply_jitter_to_decision(d: GcraDecision&, jitter: const GcraJitter&, prng_state: u64&)
fn apply_jitter_to_decision(d: RateLimitDecision&, jitter: const GcraJitter&, prng_state: u64&)
fn retain_recent_shards(limiter: ShardedGcraLimiter&, drop_below_ns: i64) -> i64
fn apply_rate_limit_headers<Res>(res: Res&, quota: const GcraQuota&, decision: const RateLimitDecision&)
```

`gcra_check_n` tracks Theoretical Arrival Time (`tat_ns`) with a 5-second
backward clock-drift clamp so NTP adjustments cannot lock out clients.
`ShardedGcraLimiter` partitions tenant keys across 256 shards of up to 16
`KeyedGcraSlot` entries (4,096 active tenants total). `apply_rate_limit_headers`
formats `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, and
`Retry-After` headers.

### 7. Gateway GCRA, HPKE, & SSRF Policy (`security/gcra.goose`, `security/hpke.goose`, `security/ssrf.goose`)

```goose
struct GcraConfig {
    emission_interval_ns: u64 = 1000000,
    tau_ns:               u64 = 5000000,
    max_burst:            u64 = 5,
    limit_window_ns:      u64 = 6000000,
}

struct GcraDecision {
    allowed:               bool = false,
    remaining_burst:       u64  = 0,
    retry_after_ns:        u64  = 0,
    reset_after_ns:        u64  = 0,
    wait_ns:               i64  = 0,
    tat_ns:                u64  = 0,
    insufficient_capacity: bool = false,
}

struct GatewayClientEntry {
    client_id:           u8[..64] = [],
    cell:                GcraCell = GcraCell { .. },
    last_seen_ns:        u64      = 0,
    consecutive_rejects: u32      = 0,
    in_use:              bool     = false,
}

struct GatewayRateLimiter {
    config:         GcraConfig               = GcraConfig { .. },
    entries:        GatewayClientEntry[..64] = [],
    fallback_cell:  GcraCell                 = GcraCell { .. },
    total_allowed:  u64                      = 0,
    total_rejected: u64                      = 0,
}

enum HpkeRole { Uninitialized, Sender, Recipient }

struct HpkeContext {
    key:             u8[32]   = [0; 32],
    base_nonce:      u8[12]   = [0; 12],
    seq:             u64      = 0,
    exporter_secret: u8[32]   = [0; 32],
    aead_id:         u16      = 0,
    kem_id:          u16      = 0,
    kdf_id:          u16      = 0,
    key_len:         u16      = 0,
    nonce_len:       u16      = 0,
    role:            HpkeRole = HpkeRole.Uninitialized,
}

struct SsrfGuardPolicy {
    enabled:            bool      = true,
    https_only:         bool      = false,
    deny_local_network: bool      = true,
    allowed_ports:      i32[..16] = [],
    denied_ports:       i32[..16] = [],
}

fn new_gcra_config(rate_per_sec: u64, burst_capacity: u64) -> GcraConfig
fn gcra_check(config: const GcraConfig&, cell: GcraCell&, cost: u64, now_ns: u64) -> GcraDecision
fn gcra_peek(config: const GcraConfig&, cell: const GcraCell&, cost: u64, now_ns: u64) -> GcraDecision
fn gcra_penalize(config: const GcraConfig&, cell: GcraCell&, penalty_ns: u64, now_ns: u64)
fn gcra_reset(cell: GcraCell&)
fn new_gateway_rate_limiter(rate_per_sec: u64, burst_capacity: u64) -> GatewayRateLimiter
fn find_client_slot(limiter: const GatewayRateLimiter&, client_id: const u8[:]) -> i64, bool
fn check_gateway_rate_limit(limiter: GatewayRateLimiter&, client_id: const u8[:], cost: u64, now_ns: u64) -> GcraDecision
fn penalize_gateway_client(limiter: GatewayRateLimiter&, client_id: const u8[:], penalty_ns: u64, now_ns: u64)
fn evict_idle_gateway_clients(limiter: GatewayRateLimiter&, max_idle_ns: u64, now_ns: u64) -> i32
fn reset_gateway_rate_limiter(limiter: GatewayRateLimiter&)
fn allow_service_key(limiter: GatewayRateLimiter&, key: const u8[:], now_ns: u64) -> bool
fn zeroize_hpke_context(ctx: HpkeContext&)
fn hpke_labeled_expand(suite_id: const u8[:], prk: const u8[:], label: const u8[:], info: const u8[:], length: u16, out: u8[:]) -> bool
fn hpke_setup_base_s(pkR: const u8[32]&, info: const u8[:], kem_id: u16, kdf_id: u16, aead_id: u16, ephemeral_sk: const u8[32]&, out_enc: u8[32]&, out_ctx: HpkeContext&) -> bool
fn hpke_setup_base_r(enc: const u8[32]&, skR: const u8[32]&, info: const u8[:], kem_id: u16, kdf_id: u16, aead_id: u16, out_ctx: HpkeContext&) -> bool
fn hpke_seal<B>(ctx: HpkeContext&, aad: const u8[:], pt: const u8[:], out: B&) -> bool
fn hpke_open<B>(ctx: HpkeContext&, aad: const u8[:], ct_with_tag: const u8[:], out: B&) -> bool
fn hpke_export(ctx: const HpkeContext&, exporter_context: const u8[:], out: u8[:]) -> bool
fn hpke_seal_base<B>(pkR: const u8[32]&, info: const u8[:], aad: const u8[:], pt: const u8[:], ephemeral_sk: const u8[32]&, aead_id: u16, out_enc: u8[32]&, out: B&) -> bool
fn hpke_seal_base_random<B>(pkR: const u8[32]&, info: const u8[:], aad: const u8[:], pt: const u8[:], aead_id: u16, out_enc: u8[32]&, out: B&) -> bool
fn hpke_open_base<B>(enc: const u8[32]&, skR: const u8[32]&, info: const u8[:], aad: const u8[:], ct_with_tag: const u8[:], aead_id: u16, out: B&) -> bool
fn new_ssrf_guard_policy() -> SsrfGuardPolicy
fn is_localhost_name(host: const u8[:]) -> bool
fn is_private_or_reserved_ip(ip_str: const u8[:]) -> bool
inline fn is_non_canonical_ipv4(host: const u8[:]) -> bool
inline fn is_cloud_metadata_domain(host: const u8[:]) -> bool
inline fn is_forbidden_internal_host(host: const u8[:]) -> bool
fn is_dangerous_service_port(port_num: i32) -> bool
fn is_cloud_metadata_or_reserved_ip(ip_str: const u8[:]) -> bool
inline fn is_valid_resolved_ip_literal(ip_str: const u8[:]) -> bool
```

`security/gcra.goose` tracks per-client gateway arrival cells across 64 bounded
LRU entries (`GatewayClientEntry[..64]`). `security/hpke.goose` implements RFC
9180 HPKE Base mode (`DHKEM(X25519, HKDF-SHA256)`) shared by Oblivious HTTP
(`http/ohttp.goose`) and TLS 1.3 ECH (`tls/ech.goose`). `security/ssrf.goose`
classifies loopback, RFC 1918, carrier-grade NAT, link-local, multicast, IPv6
ULA, and CIDR targets for client sessions and JWKS fetchers.
