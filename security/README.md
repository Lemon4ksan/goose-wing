# `security`

Package `security` provides perimeter defense, access control, and cryptographic protection for `goose-wing`. It includes W3C Cross-Origin Resource Sharing (CORS), Cross-Origin Isolation (COOP, COEP, CORP), W3C Fetch Metadata CSRF isolation, constant-time masked CSRF tokens, encrypted/signed cookie jars (ChaCha20-Poly1305 / AES-256-GCM / HMAC-SHA256), IETF Privacy Pass (RFC 9576 / RFC 9577), and Generic Cell Rate Algorithm (GCRA) rate limiting.

All components adhere to zero-allocation memory constraints on wire evaluation paths and maintain constant-time comparisons (`core::ct_eq_bytes`) to prevent timing side-channel leaks.

## Public API Reference

### 1. Cross-Origin Resource Sharing (CORS) (`security/cors.goose`)

Declarative W3C CORS policy engine with preflight caching, wildcard matching, and credential validation.

- **`enum CorsDecision`**: Evaluation outcome (`Allowed`, `Denied`, `PreflightSuccess`, `InvalidConfig`).
- **`struct CorsPolicy`**: Declarative CORS policy configuration.
- **`fn add_allowed_origin(policy: CorsPolicy&, origin_pattern: const u8[:]) -> bool`**: Registers allowed origin pattern.
- **`fn evaluate_cors_request(policy: const CorsPolicy&, req: const Request&, res: Response&) -> CorsDecision`**: Evaluates incoming request against policy.
- **`fn set_cors_headers(res: Response&, policy: const CorsPolicy&, req_origin: const u8[:], req_method: const u8[:])`**: Synthesizes standard CORS response headers.

### 2. Cross-Origin Isolation & Fetch Metadata (`security/cross_origin_isolation.goose`)

Spectre and cross-site leak defenses implementing W3C COOP, COEP, CORP, and the 9-row Fetch Metadata isolation matrix.

- **`enum CoepPolicy`**: Cross-Origin Embedder Policy (`UnsafeNone`, `RequireCorp`, `Credentialless`).
- **`enum CoopPolicy`**: Cross-Origin Opener Policy (`UnsafeNone`, `SameOriginAllowPopups`, `SameOrigin`).
- **`enum CorpPolicy`**: Cross-Origin Resource Policy (`SameSite`, `SameOrigin`, `CrossOrigin`).
- **`struct CrossOriginIsolationConfig`**: Master cross-origin isolation configuration.
- **`fn apply_cross_origin_isolation(res: Response&, cfg: const CrossOriginIsolationConfig&)`**: Applies COOP/COEP/CORP response headers.
- **`fn evaluate_fetch_metadata(sec_fetch_site: const u8[:], sec_fetch_mode: const u8[:], sec_fetch_dest: const u8[:], method: const u8[:]) -> bool`**: Validates request against Sec-Fetch-* isolation matrix.

### 3. Cryptographic Cookie Jars (`security/crypto_jar.goose`)

Authenticated encryption (AEAD) and HMAC integrity protection for stateful session cookies without server-side database lookups.

- **`enum JarCipher`**: AEAD algorithm (`ChaCha20Poly1305`, `Aes256Gcm`).
- **`struct PrivateJar`**: Sealed cookie jar providing confidentiality and authenticity.
- **`struct SignedJar`**: Authenticated cookie jar providing integrity.
- **`fn new_private_jar(secret_key: const u8[:], cipher: JarCipher = JarCipher.ChaCha20Poly1305) -> PrivateJar`**: Constructs private jar.
- **`fn new_signed_jar(secret_key: const u8[:]) -> SignedJar`**: Constructs signed jar.
- **`fn private_jar_seal<B>(jar: const PrivateJar&, cookie_name: const u8[:], plaintext: const u8[:], now_sec: i64, out: B&) -> bool`**: Encrypts and authenticates cookie payload.
- **`fn private_jar_open(jar: const PrivateJar&, cookie_name: const u8[:], encoded_val: const u8[:], now_sec: i64, out_plaintext: u8[>..]&) -> bool`**: Decrypts and verifies cookie payload.
- **`fn signed_jar_seal<B>(jar: const SignedJar&, cookie_name: const u8[:], value: const u8[:], out: B&) -> bool`**: Signs cookie value with HMAC.
- **`fn signed_jar_open<B>(jar: const SignedJar&, cookie_name: const u8[:], encoded_val: const u8[:], out_val: B&) -> bool`**: Verifies HMAC and returns original value.

### 4. Masked CSRF Tokens (`security/csrf.goose`)

One-Time-Pad (OTP) XOR masked anti-CSRF tokens preventing BREACH compression side-channel attacks on echoed secrets.

- **`struct CsrfConfig`**: CSRF configuration holding token length.
- **`fn generate_masked_csrf_token<B>(raw_token: const u8[:], out: B&) -> bool`**: Generates masked CSRF token.
- **`fn verify_masked_csrf_token(masked_token: const u8[:], expected_raw: const u8[:]) -> bool`**: Constant-time verification of masked token against expected secret.

### 5. Privacy Pass (`security/privacypass.goose`)

IETF RFC 9576 / RFC 9577 architecture for anonymous cryptographic authorization tokens.

- **`struct TokenChallenge`**: Parsed RFC 9576 challenge payload.
- **`struct PrivacyPassToken`**: Parsed RFC 9577 redemption token.
- **`fn unmarshal_token_challenge(wire: const u8[:]) -> TokenChallenge, bool`**: Parses binary token challenge wire frame.
- **`fn unmarshal_token(wire: const u8[:]) -> PrivacyPassToken, bool`**: Parses binary Privacy Pass token wire frame.

### 6. GCRA Rate Limiter (`security/rate_limiter.goose`)

Leaky bucket as a meter (Generic Cell Rate Algorithm) with micro-sharded lockless tables and IETF `RateLimit-*` header synthesis.

- **`struct GcraQuota`**: Rate limit quota holding emission interval, burst tolerance, and period limits.
- **`struct ShardedLimiter`**: Micro-sharded lockless GCRA limiter.
- **`fn new_gcra_quota(limit_per_period: u64, period_ns: u64, burst_tolerance: u64 = 0) -> GcraQuota`**: Constructs rate limit quota.
- **`fn new_sharded_limiter(quota: GcraQuota) -> ShardedLimiter`**: Constructs micro-sharded rate limiter.
- **`fn check_rate_limit(limiter: ShardedLimiter&, key: const u8[:], now_ns: u64) -> bool, u64`**: Evaluates key arrival time against GCRA theoretical arrival time (TAT).
- **`fn apply_rate_limit_headers(res: Response&, quota: GcraQuota, remaining: u64, reset_sec: u64)`**: Synthesizes RFC RateLimit-Limit, RateLimit-Remaining, and RateLimit-Reset headers.
