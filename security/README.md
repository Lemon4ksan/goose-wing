# `security`

Package `security` provides perimeter defense, access control, and cryptographic protection for `goose-wing`. It includes W3C Cross-Origin Resource Sharing (CORS), Cross-Origin Isolation (COOP, COEP, CORP), W3C Fetch Metadata CSRF isolation, constant-time masked CSRF tokens, encrypted/signed cookie jars (ChaCha20-Poly1305 / AES-256-GCM / HMAC-SHA256), IETF Privacy Pass (RFC 9576 / RFC 9577), and Generic Cell Rate Algorithm (GCRA) rate limiting.

All components adhere to zero-allocation memory constraints on wire evaluation paths and maintain constant-time comparisons (`core::ct_eq_bytes`) to prevent timing side-channel leaks.

## Public API Reference

### 1. Cross-Origin Resource Sharing (CORS) (`security/cors.goose`)

Declarative W3C CORS policy engine with preflight caching, wildcard matching, and credential validation.

```goose
enum CorsDecision {
    Allowed,
    Denied,
    PreflightSuccess,
    InvalidConfig,
}

struct CorsPolicy {
    allow_credentials: bool            = false,
    allowed_origins:   u8[..128][..16] = [],
    allowed_methods:   u8[..128]       = "GET, POST, PUT, DELETE, PATCH, OPTIONS, QUERY",
    allowed_headers:   u8[..256]       = "Content-Type, Authorization, X-Requested-With, X-API-Key",
    expose_headers:    u8[..256]       = "Content-Length, X-Trace-Id, RateLimit-Limit, RateLimit-Reset",
    max_age_sec:       i64             = 86400, // 24 hours
}

fn add_allowed_origin(policy: CorsPolicy&, origin_pattern: const u8[:]) -> bool;
fn evaluate_cors_request(policy: const CorsPolicy&, req: const Request&, res: Response&) -> CorsDecision;
fn set_cors_headers(res: Response&, policy: const CorsPolicy&, req_origin: const u8[:], req_method: const u8[:]);
```

### 2. Cross-Origin Isolation & Fetch Metadata (`security/cross_origin_isolation.goose`)

Spectre and cross-site leak defenses implementing W3C COOP, COEP, CORP, and the 9-row Fetch Metadata isolation matrix.

```goose
enum CoepPolicy {
    UnsafeNone,
    RequireCorp,
    Credentialless,
}

enum CoopPolicy {
    UnsafeNone,
    SameOriginAllowPopups,
    SameOrigin,
}

enum CorpPolicy {
    SameSite,
    SameOrigin,
    CrossOrigin,
}

struct CrossOriginIsolationConfig {
    coep: CoepPolicy = CoepPolicy.RequireCorp,
    coop: CoopPolicy = CoopPolicy.SameOrigin,
    corp: CorpPolicy = CorpPolicy.SameOrigin,
}

fn apply_cross_origin_isolation(res: Response&, cfg: const CrossOriginIsolationConfig&);
fn evaluate_fetch_metadata(
    sec_fetch_site: const u8[:],
    sec_fetch_mode: const u8[:],
    sec_fetch_dest: const u8[:],
    method:         const u8[:],
) -> bool;
```

### 3. Cryptographic Cookie Jars (`security/crypto_jar.goose`)

Authenticated encryption (AEAD) and HMAC integrity protection for stateful session cookies without server-side database lookups.

```goose
enum JarCipher {
    ChaCha20Poly1305,
    Aes256Gcm,
}

struct PrivateJar { .. }
struct SignedJar { .. }

fn new_private_jar(secret_key: const u8[:], cipher: JarCipher = JarCipher.ChaCha20Poly1305) -> PrivateJar;
fn new_signed_jar(secret_key: const u8[:]) -> SignedJar;

// Encrypted sealed jar (confidentiality + authenticity)
fn private_jar_seal<B>(jar: const PrivateJar&, cookie_name: const u8[:], plaintext: const u8[:], now_sec: i64, out: B&) -> bool;
fn private_jar_open(jar: const PrivateJar&, cookie_name: const u8[:], encoded_val: const u8[:], now_sec: i64, out_plaintext: u8[>..]&) -> bool;

// Authenticated signed jar (integrity only)
fn signed_jar_seal<B>(jar: const SignedJar&, cookie_name: const u8[:], value: const u8[:], out: B&) -> bool;
fn signed_jar_open<B>(jar: const SignedJar&, cookie_name: const u8[:], encoded_val: const u8[:], out_val: B&) -> bool;
```

### 4. Masked CSRF Tokens (`security/csrf.goose`)

One-Time-Pad (OTP) XOR masked anti-CSRF tokens preventing BREACH compression side-channel attacks on echoed secrets.

```goose
struct CsrfConfig {
    token_length: i64 = 32,
}

fn generate_masked_csrf_token<B>(raw_token: const u8[:], out: B&) -> bool;
fn verify_masked_csrf_token(masked_token: const u8[:], expected_raw: const u8[:]) -> bool;
```

### 5. Privacy Pass (`security/privacypass.goose`)

IETF RFC 9576 / RFC 9577 architecture for anonymous cryptographic authorization tokens.

```goose
struct TokenChallenge {
    token_type:       u16       = 0,
    issuer_name_len:  u16       = 0,
    issuer_name:      u8[..256] = [],
    redemption_ctx:   u8[..32]  = [],
    origin_info_len:  u16       = 0,
    origin_info:      u8[..256] = [],
}

struct PrivacyPassToken {
    token_type: u16        = 0,
    key_id:     u8[32]     = [0; 32],
    nonce:      u8[32]     = [0; 32],
    challenge:  u8[32]     = [0; 32],
    payload:    u8[..1024] = [],
}

fn unmarshal_token_challenge(wire: const u8[:]) -> TokenChallenge, bool;
fn unmarshal_token(wire: const u8[:]) -> PrivacyPassToken, bool;
```

### 6. GCRA Rate Limiter (`security/rate_limiter.goose`)

Leaky bucket as a meter (Generic Cell Rate Algorithm) with micro-sharded lockless tables and IETF `RateLimit-*` header synthesis.

```goose
struct GcraQuota {
    emission_interval_ns: u64 = 1000000000,
    burst_tolerance_ns:   u64 = 0,
    limit:                u64 = 1,
    period_ns:            u64 = 1000000000,
}

struct ShardedLimiter { .. }

fn new_gcra_quota(limit_per_period: u64, period_ns: u64, burst_tolerance: u64 = 0) -> GcraQuota;
fn new_sharded_limiter(quota: GcraQuota) -> ShardedLimiter;

// Evaluates key against GCRA theoretical arrival time (TAT)
// Returns: (allowed, retry_after_ns)
fn check_rate_limit(limiter: ShardedLimiter&, key: const u8[:], now_ns: u64) -> bool, u64;

// Synthesizes RFC RateLimit-Limit, RateLimit-Remaining, and RateLimit-Reset headers
fn apply_rate_limit_headers(res: Response&, quota: GcraQuota, remaining: u64, reset_sec: u64);
```
