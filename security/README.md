# `security`

Package `security` provides perimeter defense, access control, and cryptographic protection for `goose-wing`. It includes W3C Cross-Origin Resource Sharing (CORS), Cross-Origin Isolation (`COOP`, `COEP`, `CORP`), W3C Fetch Metadata CSRF isolation, constant-time masked CSRF tokens, encrypted/signed cookie jars (`XChaCha20-Poly1305` / `HKDF-AES-256-GCM` / `HMAC-SHA256`), IETF Privacy Pass (RFC 9576 / RFC 9577 / RFC 9578), and Generic Cell Rate Algorithm (GCRA) rate limiting.

All components adhere to zero-allocation memory constraints on wire evaluation paths and maintain constant-time comparisons (`core::ct_eq_bytes`, `core::ct_eq_tag32`) to prevent timing side-channel leaks.

## Public API Reference

### 1. Cross-Origin Resource Sharing (CORS) (`security/cors.goose`)

Declarative W3C CORS policy engine with preflight caching, strict DNS label wildcard subdomain matching, and credential validation.

- **`enum CorsResult`**: Evaluation outcome (`NoCors`, `AllowedActual`, `AllowedPreflight`, `RejectedOrigin`, `InvalidConfig`).
- **`struct CorsPolicy`**: Declarative CORS policy configuration (`allow_credentials`, `allowed_origins`, `allowed_methods`, `allowed_headers`, `expose_headers`, `max_age_sec`).
- **`fn add_allowed_origin(policy: CorsPolicy&, origin_pattern: const u8[:]) -> bool`**: Registers an allowed origin pattern.
- **`fn match_cors_origin_pattern(candidate: const u8[:], pattern: const u8[:]) -> bool`**: Matches origin against exact or wildcard (`https://*.example.com`) pattern.
- **`fn validate_cors_policy(policy: const CorsPolicy&) -> bool`**: Validates policy configuration invariants (e.g. forbids `*` with `allow_credentials`).
- **`fn apply_cors_vary_header(res: Response&)`**: Appends `Origin`, `Access-Control-Request-Method`, and `Access-Control-Request-Headers` to `Vary`.
- **`fn evaluate_cors(policy: const CorsPolicy&, req: const Request&, res: Response&) -> CorsResult`**: Evaluates incoming request and populates CORS response headers.

### 2. Cross-Origin Isolation (`security/cross_origin_isolation.goose`)

Spectre and cross-site leak defenses implementing W3C HTML §7.2 (`COOP`, `COEP`) and Fetch §4.5 (`CORP`).

- **`enum CoopPolicy`**: Cross-Origin Opener Policy (`Unknown`, `UnsafeNone`, `SameOriginAllowPopups`, `SameOrigin`).
- **`enum CoepPolicy`**: Cross-Origin Embedder Policy (`Unknown`, `UnsafeNone`, `Credentialless`, `RequireCorp`).
- **`enum CorpPolicy`**: Cross-Origin Resource Policy (`Unknown`, `None`, `SameOrigin`, `SameSite`, `CrossOrigin`).
- **`struct CrossOriginIsolationContext`**: Browser / client-side cross-origin isolation context tracking `coop`, `coep`, `is_cross_origin_isolated`, and `document_origin`.
- **`fn parse_coop(val: const u8[:]) -> CoopPolicy`**: Parses `Cross-Origin-Opener-Policy` header value (stripping RFC 8941 Structured Field parameters).
- **`fn parse_coep(val: const u8[:]) -> CoepPolicy`**: Parses `Cross-Origin-Embedder-Policy` header value.
- **`fn parse_corp(val: const u8[:]) -> CorpPolicy`**: Parses `Cross-Origin-Resource-Policy` header value.
- **`fn update_isolation_context(ctx: CrossOriginIsolationContext&, coop_hdr: const u8[:], coep_hdr: const u8[:], doc_origin: const u8[:])`**: Updates isolation state from COOP/COEP header strings.
- **`fn update_from_headers(ctx: CrossOriginIsolationContext&, headers: const HeaderMap&, doc_origin: const u8[:])`**: Extracts COOP/COEP from `HeaderMap` and updates isolation state.
- **`fn is_subresource_allowed(ctx: const CrossOriginIsolationContext&, resource_origin: const u8[:], corp_hdr: const u8[:], has_credentials: bool = false) -> bool`**: Enforces CORP and COEP (`require-corp` / `credentialless`) on subresource responses.
- **`fn apply_strict_cross_origin_isolation(res: Response&)`**: Injects strict `same-origin` COOP/CORP and `require-corp` COEP headers.

### 3. Cryptographic Cookie Jars (`security/crypto_jar.goose`)

Authenticated encryption (AEAD) and HMAC-SHA256 integrity protection for stateful session cookies with key ring rotation, context binding (AAD), and replay timestamp validation.

- **`struct KeyStore`**: Key ring holding up to 8 `core::KeySlot` entries, `active_idx`, `max_age_sec`, and `clock_skew_tolerance_sec`.
- **`struct PrivateJar`**: Encrypted cookie jar using `XChaCha20-Poly1305` (wire `0x02`) or `HKDF-SHA256 + AES-256-GCM` (wire `0x01`).
- **`struct SignedJar`**: Authenticated cookie jar using `HMAC-SHA256` (wire `0x03`).
- **`fn add_key(store: KeyStore&, slot: core::KeySlot, make_active: bool = true) -> bool`**: Adds unique key slot to key store.
- **`fn active_key(store: const KeyStore&) -> core::KeySlot, bool`**: Returns active key slot for sealing.
- **`fn find_key(store: const KeyStore&, key_id: u32) -> core::KeySlot, bool`**: Finds non-revoked key slot by `key_id`.
- **`fn revoke_key(store: KeyStore&, key_id: u32) -> bool`**: Zeroizes and revokes key slot(s) matching `key_id`.
- **`fn needs_rotation(slot: const core::KeySlot&, now_sec: i64) -> bool`**: Checks whether key is within 24 hours of expiration.
- **`fn is_cookie_timestamp_valid(store: const KeyStore&, cookie_sec: i64, now_sec: i64) -> bool`**: Validates cookie timestamp against max age and clock skew tolerance.
- **`fn new_private_jar(store: KeyStore, use_hkdf_aes: bool = false) -> PrivateJar`**: Constructs encrypted cookie jar.
- **`fn private_jar_seal_binary<B>(jar: const PrivateJar&, cookie_name: const u8[:], plaintext: const u8[:], now_sec: i64, nonce_seed: u64, out: B&) -> bool`**: Encrypts and authenticates payload into binary wire format.
- **`fn private_jar_open_binary<B>(jar: const PrivateJar&, cookie_name: const u8[:], raw_wire: const u8[:], now_sec: i64, out_plaintext: B&) -> bool`**: Verifies tag, timestamp, and context binding, and decrypts binary wire payload.
- **`fn private_jar_seal<B>(jar: const PrivateJar&, cookie_name: const u8[:], plaintext: const u8[:], now_sec: i64, nonce_seed: u64, out: B&) -> bool`**: Seals and Base64URL-encodes cookie payload.
- **`fn private_jar_open<B>(jar: const PrivateJar&, cookie_name: const u8[:], encoded_val: const u8[:], now_sec: i64, out_plaintext: B&) -> bool`**: Base64URL-decodes and opens encrypted cookie payload.
- **`fn new_signed_jar(store: KeyStore) -> SignedJar`**: Constructs HMAC-signed cookie jar.
- **`fn signed_jar_seal_binary<B>(jar: const SignedJar&, cookie_name: const u8[:], payload: const u8[:], now_sec: i64, out: B&) -> bool`**: Signs payload into binary wire format.
- **`fn signed_jar_open_binary<B>(jar: const SignedJar&, cookie_name: const u8[:], raw_wire: const u8[:], now_sec: i64, out_payload: B&) -> bool`**: Verifies constant-time HMAC tag and timestamp, writing payload to `out_payload`.
- **`fn signed_jar_seal<B>(jar: const SignedJar&, cookie_name: const u8[:], payload: const u8[:], now_sec: i64, out: B&) -> bool`**: Signs and Base64URL-encodes cookie payload.
- **`fn signed_jar_open<B>(jar: const SignedJar&, cookie_name: const u8[:], encoded_val: const u8[:], now_sec: i64, out_payload: B&) -> bool`**: Base64URL-decodes and verifies signed cookie payload.

### 4. W3C Fetch Metadata & Masked CSRF Tokens (`security/csrf.goose`)

Server-side cross-origin request forgery defense using the 9-row W3C Fetch Metadata decision matrix (`Sec-Fetch-Site`, `Sec-Fetch-Mode`, `Sec-Fetch-Dest`), `Origin`/`Referer` fallback validation, and One-Time-Pad (OTP) XOR masked anti-CSRF tokens preventing BREACH compression side-channels.

- **`enum CsrfDecision`**: Evaluation result (`Allow`, `RejectForbidden { reason: CsrfRejectReason }`, `AllowExempt`).
- **`enum CsrfRejectReason`**: Rejection reason (`CrossSiteStateMutation`, `DisallowedSameSiteSubdomain`, `CrossSiteFramingOrXssi`, `CrossSiteUnauthorizedSubresource`, `OriginHostMismatch`, `MissingBrowserHeadersWithSessionCookie`, `MissingUserActivationOnSensitiveNav`).
- **`struct CrossOriginGuard`**: CSRF policy configuration (`allow_same_site`, `require_user_activation_on_sensitive_nav`, `block_framing_and_embedding`, `strict_subresource_isolation`, `allow_missing_headers_without_cookie`, `trusted_origins`, `exempt_paths`).
- **`struct FetchContext`**: Extracted 5-attribute Fetch Metadata request vector.
- **`fn add_trusted_origin(cfg: CrossOriginGuard&, origin: const u8[:]) -> bool`**: Adds trusted cross-site origin.
- **`fn add_exempt_path(cfg: CrossOriginGuard&, path_prefix: const u8[:]) -> bool`**: Adds exempt URL path prefix.
- **`fn extract_fetch_context(req: const Request&, target_host: const u8[:], is_sensitive_nav: bool = false) -> FetchContext`**: Extracts Fetch Metadata attributes from `Request`.
- **`fn evaluate_fetch_metadata(cfg: const CrossOriginGuard&, ctx: const FetchContext&) -> CsrfDecision`**: Evaluates `FetchContext` against the 9-row Fetch Metadata matrix and fallback rules.
- **`fn apply_isolation_headers(res: Response&, enable_hsts: bool = true)`**: Appends `Vary: Sec-Fetch-Dest, Sec-Fetch-Mode, Sec-Fetch-Site` and optional HSTS headers.
- **`fn mask_csrf_token(secret: u8[32], mask_pad: u8[32]) -> u8[64]`**: Generates 64-byte OTP-masked CSRF token.
- **`fn verify_masked_csrf_token(masked_token: const u8[:], expected_secret: u8[32]) -> bool`**: Unmasks and verifies 64-byte token in constant time.
- **`fn verify_csrf_token_ raw(candidate: const u8[:], expected: const u8[:]) -> bool`**: Constant-time verification of raw CSRF token slices (`verify_csrf_token_raw`).

### 5. Privacy Pass (`security/privacypass.goose`)

IETF RFC 9576 / RFC 9577 / RFC 9578 architecture for anonymous cryptographic authorization tokens (`PrivateToken` HTTP authentication scheme).

- **`struct TokenChallenge`**: Parsed RFC 9577 §2.1.1 `TokenChallenge` structure (`token_type`, `issuer_name`, `redemption_context`, `origin_info`).
- **`struct Token`**: Parsed RFC 9577 §2.2.1 token structure (`token_type`, `nonce`, `challenge_digest`, `token_key_id`, `authenticator`).
- **`struct PrivateTokenCache`**: Client-side single-use token cache (up to 16 `CachedToken` entries).
- **`fn marshal_token_challenge<B>(challenge: const TokenChallenge&, out: B&)`**: Serializes `TokenChallenge` to wire format.
- **`fn unmarshal_token_challenge(data: const u8[:], out: TokenChallenge&) -> bool`**: Parses `TokenChallenge` from wire format.
- **`fn compute_challenge_digest(challenge: const TokenChallenge&) -> u8[32]`**: Computes `SHA-256(TokenChallenge)`.
- **`fn marshal_token<B>(token: const Token&, out: B&)`**: Serializes `Token` to wire format.
- **`fn unmarshal_token(data: const u8[:], out: Token&, key_id_len: i64 = 32) -> bool`**: Parses `Token` from wire format.
- **`fn parse_private_token_challenge<B>(header_val: const u8[:], out_challenge: TokenChallenge&, out_token_key: B&, out_max_age: i64&) -> bool`**: Parses `WWW-Authenticate: PrivateToken` header value.
- **`fn format_private_token_auth<B>(raw_token: const u8[:], out: B&)`**: Formats `Authorization: PrivateToken token="..."` header value.
- **`fn put_private_token(cache: PrivateTokenCache&, challenge_digest: u8[32], raw_token: const u8[:], now_sec: i64, ttl_sec: i64 = 300) -> bool`**: Stores token in cache.
- **`fn pop_private_token<B>(cache: PrivateTokenCache&, challenge_digest: u8[32], now_sec: i64, out_raw_token: B&) -> bool`**: Pops single-use token from cache.
- **`fn attach_private_token(req: Request&, raw_token: const u8[:])`**: Attaches `Authorization: PrivateToken` header to request.
- **`fn has_private_token_challenge(resp: const Response&) -> bool`**: Checks `401 Unauthorized` response for `PrivateToken` challenge.

### 6. GCRA Rate Limiter (`security/rate_limiter.goose`)

Generic Cell Rate Algorithm (GCRA) with micro-sharded lockless tables, probabilistic sampling, and IETF `RateLimit-*` / `Retry-After` header synthesis.

- **`struct GcraQuota`**: Rate limit quota (`emission_interval_ns`, `delay_tolerance_ns`, `limit`, `period_ns`, `burst`).
- **`enum RateLimitDecision`**: Admission outcome (`Allowed`, `Reserved`, `Rejected`).
- **`struct GcraCell`**: Single TAT state cell (`tat_ns`).
- **`struct ShardedRateLimiter`**: 16-shard multi-tenant GCRA rate limiter (64 entries per shard) with LRU eviction.
- **`struct ProbabilisticGcra`**: Probabilistic sampling wrapper around `GcraQuota` and `GcraCell`.
- **`fn new_gcra_quota(limit: u64, period_dur: core::Duration, burst: u64 = 0) -> GcraQuota`**: Constructs GCRA quota.
- **`fn gcra_check_n(quota: const GcraQuota&, cell: GcraCell&, cost_n: u64, now_ns: u64) -> RateLimitDecision`**: Evaluates arrival of `cost_n` units against TAT.
- **`fn gcra_reserve_n(quota: const GcraQuota&, cell: GcraCell&, cost_n: u64, now_ns: u64, max_wait_ns: u64) -> RateLimitDecision`**: Reserves capacity for `cost_n` units up to `max_wait_ns`.
- **`fn check_rate_limit(limiter: ShardedRateLimiter&, key: const u8[:], cost_n: u64, now_ns: u64) -> RateLimitDecision`**: Evaluates tenant key against sharded GCRA state.
- **`fn check_rate_limit(pgcra: ProbabilisticGcra&, cost_n: u64, now_ns: u64) -> RateLimitDecision`**: Evaluates request with probabilistic cost scaling.
- **`fn apply_rate_limit_headers(res: Response&, quota: const GcraQuota&, decision: const RateLimitDecision&)`**: Synthesizes `RateLimit-Limit`, `RateLimit-Remaining`, `RateLimit-Reset`, `RateLimit-Policy`, and `Retry-After` (on `Rejected`) headers.
