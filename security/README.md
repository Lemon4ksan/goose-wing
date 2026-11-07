# `security`

`security` provides W3C Cross-Origin Resource Sharing (CORS), Cross-Origin
Isolation (`COOP`, `COEP`, `CORP`), Fetch Metadata CSRF protection, AEAD and
HMAC cookie jars, IETF Privacy Pass tokens, and Generic Cell Rate Algorithm
(GCRA) rate limiting.

```goose
import wing;
import core;

let quota = wing::new_gcra_quota(100, core::Duration { nanos: 60000000000 }, 20);
var limiter = wing::new_sharded_limiter(quota);
let decision = wing::check_rate_limit(limiter, "tenant-42", 1, 1700000000000000000);
let ok = wing::is_allowed(decision);
```

## Public API Reference

### 1. Cross-Origin Resource Sharing (CORS) (`security/cors.goose`)

```goose
enum CorsResult { NoCors, AllowedActual, AllowedPreflight, RejectedOrigin, InvalidConfig }

struct CorsPolicy {
    allow_credentials:          bool            = false,
    reject_non_matching_origin: bool            = false,
    allowed_origins:            u8[..128][..16] = [],
    allowed_methods:            u8[..128]       = "GET, POST, PUT, DELETE, PATCH, OPTIONS, QUERY",
    allowed_headers:            u8[..256]       = "Content-Type, Authorization, X-Requested-With, X-API-Key",
    expose_headers:             u8[..256]       = "Content-Length, X-Trace-Id, RateLimit-Limit, RateLimit-Reset",
    max_age_sec:                i64             = 86400,
}

fn add_allowed_origin(policy: CorsPolicy&, origin_pattern: const u8[:]) -> bool
fn match_cors_origin_pattern(candidate: const u8[:], pattern: const u8[:]) -> bool
fn is_origin_allowed(policy: const CorsPolicy&, origin_str: const u8[:]) -> bool
fn has_wildcard_origin(policy: const CorsPolicy&) -> bool
fn validate_cors_policy(policy: const CorsPolicy&) -> bool
inline fn apply_cors_vary_header<Res>(res: Res&)
fn apply_cors_preflight_headers<Res>(policy: const CorsPolicy&, res: Res&)
fn evaluate_cors<Req, Res>(policy: const CorsPolicy&, req: const Req&, res: Res&) -> CorsResult
```

`CorsPolicy` stores up to 16 allowed origin patterns (`u8[..128][..16]`).
`match_cors_origin_pattern` matches exact origins or wildcard subdomain patterns
such as `https://*.example.com` after validating RFC 1035 DNS label syntax.
`validate_cors_policy` rejects configurations that combine a literal `*` origin
(`has_wildcard_origin`) with `allow_credentials = true`. `evaluate_cors`
validates the policy, checks the `Origin` header, appends `Vary` headers via
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
fn update_from_headers(ctx: CrossOriginIsolationContext&, headers: const HeaderMap&, document_origin: const u8[:]) -> bool
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
    slots:                    KeySlot[..8] = [],
    active_idx:               i32          = -1,
    max_age_sec:              i64          = 86400,
    clock_skew_tolerance_sec: i64          = 300,
}

struct PrivateJar {
    store:        KeyStore = KeyStore { .. },
    use_hkdf_aes: bool     = false,
}

struct SignedJar {
    store: KeyStore = KeyStore { .. },
}

fn zeroize_jar_key_slot(slot: KeySlot&)
fn add_key(store: KeyStore&, slot: core::KeySlot) -> bool
fn active_key(store: const KeyStore&) -> KeySlot, bool
fn set_active_key_id(store: KeyStore&, key_id: u32) -> bool
fn find_key(store: const KeyStore&, key_id: u32) -> KeySlot, bool
fn revoke_key(store: KeyStore&, key_id: u32) -> bool
fn needs_rotation(slot: const KeySlot&, now_sec: i64) -> bool
fn is_cookie_timestamp_valid(store: const KeyStore&, timestamp_sec: i64, now_sec: i64) -> bool
fn generate_jar_entropy(seed: u64, now_sec: i64, domain: u64 = 0) -> u8[32]
fn new_private_jar(store: KeyStore, use_hkdf_aes: bool = false) -> PrivateJar
fn private_jar_seal_binary<B>(jar: const PrivateJar&, cookie_name: const u8[:], plaintext: const u8[:], now_sec: i64, nonce_seed: u64, out: B&) -> bool
fn private_jar_open_binary<B>(jar: const PrivateJar&, cookie_name: const u8[:], wire: const u8[:], now_sec: i64, out_plaintext: B&) -> bool
fn private_jar_seal<B>(jar: const PrivateJar&, cookie_name: const u8[:], plaintext: const u8[:], now_sec: i64, nonce_seed: u64, out: B&) -> bool
fn private_jar_open<B>(jar: const PrivateJar&, cookie_name: const u8[:], encoded_val: const u8[:], now_sec: i64, out_plaintext: B&) -> bool
fn new_signed_jar(store: KeyStore) -> SignedJar
fn signed_jar_seal_binary<B>(jar: const SignedJar&, cookie_name: const u8[:], payload: const u8[:], now_sec: i64, out: B&) -> bool
fn signed_jar_open_binary<B>(jar: const SignedJar&, cookie_name: const u8[:], wire: const u8[:], now_sec: i64, out_payload: B&) -> bool
fn signed_jar_seal<B>(jar: const SignedJar&, cookie_name: const u8[:], payload: const u8[:], now_sec: i64, out: B&) -> bool
fn signed_jar_open<B>(jar: const SignedJar&, cookie_name: const u8[:], encoded_val: const u8[:], now_sec: i64, out_payload: B&) -> bool
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
    allow_same_site:                         bool            = false,
    require_user_activation_on_sensitive_nav: bool           = true,
    block_framing_and_embedding:             bool            = true,
    strict_subresource_isolation:            bool            = true,
    allow_missing_headers_without_cookie:    bool            = true,
    trusted_origins:                         u8[..128][..16] = [],
    exempt_paths:                            u8[..128][..16] = [],
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
fn add_trusted_origin(cfg: CrossOriginGuard&, origin: const u8[:]) -> bool
fn add_exempt_path(cfg: CrossOriginGuard&, path_prefix: const u8[:]) -> bool
fn is_path_exempt(cfg: const CrossOriginGuard&, path: const u8[:]) -> bool
fn is_origin_trusted(cfg: const CrossOriginGuard&, origin: const u8[:]) -> bool
fn extract_fetch_context<Req>(req: const Req&, target_host: const u8[:], is_sensitive_nav: bool = false) -> FetchContext
fn evaluate_fetch_metadata(cfg: const CrossOriginGuard&, ctx: const FetchContext&) -> CsrfDecision
fn apply_isolation_headers<Res>(res: Res&)
fn validate_csrf_token(cookie_token: const u8[:], request_token: const u8[:]) -> bool
fn mask_csrf_token<B>(mask: const u8[:], raw_secret: const u8[:], out: B&) -> bool
fn verify_masked_csrf_token(masked_token: const u8[:], expected_unmasked: const u8[:]) -> bool
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
    token_type:         u16       = 0x0002,
    issuer_name:        u8[..128] = [],
    redemption_context: u8[..32]  = [],
    origin_info:        u8[..256] = [],
}

struct Token {
    token_type:       u16       = 0x0002,
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
fn unmarshal_token_challenge(data: const u8[:], out: TokenChallenge&) -> bool
fn compute_challenge_digest(challenge: const TokenChallenge&) -> u8[32], bool
fn marshal_token<B>(token: const Token&, out: B&) -> bool
fn unmarshal_token(data: const u8[:], key_id_len: i64, auth_len: i64, out: Token&) -> bool
fn parse_private_token_challenge<B>(header_val: const u8[:], out_challenge: TokenChallenge&, out_token_key: B&, out_max_age_sec: i64&) -> bool
fn format_private_token_authorization<B>(token_bytes: const u8[:], out: B&)
fn format_sec_private_state_token<B>(token_bytes: const u8[:], out: B&)
fn put_private_token(cache: PrivateTokenCache&, challenge: const TokenChallenge&, token: const Token&, raw_token: const u8[:], ttl_sec: i64, now_sec: i64) -> bool
fn get_private_token(cache: PrivateTokenCache&, challenge: const TokenChallenge&, now_sec: i64, out_token: Token&, out_raw: u8[..512]&) -> bool
fn pop_private_token<B>(cache: PrivateTokenCache&, challenge_digest: const u8[32]&, now_sec: i64, out_raw_token: B&) -> bool
fn attach_private_token<R>(req: R&, token_bytes: const u8[:])
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

struct GcraDecision {
    allowed:        bool = false,
    remaining:      u64  = 0,
    reset_after_ns: u64  = 0,
    retry_after_ns: u64  = 0,
}

struct GcraCell { tat_ns: u64 = 0 }

struct KeyedGcraSlot {
    key_hash:       u64      = 0,
    key:            u8[..64] = [],
    tat_ns:         u64      = 0,
    last_access_ns: u64      = 0,
    occupied:       bool     = false,
}

struct GcraShard { slots: KeyedGcraSlot[64] = [KeyedGcraSlot { .. }; 64] }

struct ShardedGcraLimiter {
    quota:  GcraQuota     = GcraQuota { .. },
    shards: GcraShard[16] = [GcraShard { .. }; 16],
}

struct ProbabilisticGcra {
    quota:       GcraQuota = GcraQuota { .. },
    cell:        GcraCell  = GcraCell { .. },
    sample_rate: u64       = 20,
}

struct GcraJitter {
    min_jitter_ns: i64  = 0,
    max_jitter_ns: i64  = 0,
    enabled:       bool = false,
}

fn new_gcra_quota(limit: u64, period_dur: core::Duration, burst: u64 = 0) -> GcraQuota
fn new_sharded_limiter(quota: GcraQuota) -> ShardedGcraLimiter
fn new_probabilistic_gcra(quota: GcraQuota, sample_rate: u64 = 20) -> ProbabilisticGcra
fn gcra_check_n(quota: const GcraQuota&, cell: GcraCell&, cost_n: u64, now_ns: u64) -> RateLimitDecision
fn gcra_reserve_n(quota: const GcraQuota&, cell: GcraCell&, cost_n: u64, now_ns: u64, max_wait_ns: u64) -> RateLimitDecision
fn check_rate_limit(limiter: ShardedGcraLimiter&, key_str: const u8[:], cost_n: u64, now_ns: u64) -> RateLimitDecision
fn check_rate_limit(pgcra: ProbabilisticGcra&, cost_n: u64, now_ns: u64) -> RateLimitDecision
fn is_allowed(decision: const RateLimitDecision&) -> bool
fn is_insufficient_capacity(decision: const RateLimitDecision&) -> bool
fn to_gcra_decision(decision: const RateLimitDecision&) -> GcraDecision
fn sample_gcra_jitter_ns(jitter: const GcraJitter&, prng_state: u64&) -> i64
fn apply_jitter_to_decision(d: GcraDecision&, jitter: const GcraJitter&, prng_state: u64&)
fn apply_jitter_to_decision(d: RateLimitDecision&, jitter: const GcraJitter&, prng_state: u64&)
fn retain_recent_shards(limiter: ShardedGcraLimiter&, drop_below_ns: i64) -> i64
fn apply_rate_limit_headers<Res>(res: Res&, quota: const GcraQuota&, decision: const RateLimitDecision&)
```

`gcra_check_n` tracks Theoretical Arrival Time (`tat_ns`) with a 5-second
backward clock-drift clamp (`GCRA_MAX_CLOCK_DRIFT_NS`) so NTP adjustments cannot
lock out clients. `ShardedGcraLimiter` partitions tenant keys across 16 shards
of 64 `KeyedGcraSlot` entries (1,024 active tenants total) with LRU slot
replacement when a shard is full. `apply_rate_limit_headers` formats
`RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, `RateLimit-Policy`,
and `Retry-After` headers.
