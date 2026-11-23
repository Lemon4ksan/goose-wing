# `auth`

HTTP authentication, OAuth 2.0 security primitives, and JOSE token stacks.

Public entrypoints live in `namespace auth;` across `auth/types.goose`,
`auth/digest*.goose`, `auth/pkce.goose`, `auth/device_grant.goose`,
`auth/introspection.goose`, `auth/dpop*.goose`, `auth/jwk.goose`,
`auth/jwks.goose`, `auth/acme.goose`, `auth/jwt*.goose`, and `auth/jwe.goose`.
Internal helpers are isolated in `namespace auth_internal;` across
`auth/internal.goose`, `auth/oauth_internal.goose`,
`auth/digest_internal.goose`, `auth/dpop_leaf_internal.goose`,
`auth/dpop_internal.goose`, `auth/jwk_internal.goose`,
`auth/jwks_internal.goose`, and `auth/jwt_internal.goose`.

```goose
import wing;

let pair, ok = auth::create_pkce_pair();
var header = auth::new_jwt_header(auth::JwtAlg.HS256, "k1");
var claims = auth::JwtClaims { sub: "user_1", exp: 1800000000, .. };
let _ = auth::set_audience(claims, "https://api.example.com");
var token: u8[>..] = [];
let signed = auth::sign_jwt_hmac(header, claims, "0123456789abcdef0123456789abcdef", token);
```

## Public API

### HTTP Digest authentication (`auth/digest.goose`, `auth/digest_core.goose`, RFC 7616)

```goose
struct DigestChallenge {
    realm:             u8[..128] = [],
    nonce:             u8[..128] = [],
    algorithm:         u8[..32]  = "MD5",
    qop:               u8[..32]  = [],
    opaque:            u8[..128] = [],
    domain:            u8[..128] = [],
    stale:             bool      = false,
    userhash:          bool      = false,
    has_explicit_algo: bool      = false,
    valid:             bool      = false,
}

struct DigestCredentials {
    username: u8[..128] = [],
    password: u8[..128] = [],
}

fn parse_digest_challenge(raw_header: const u8[:]) -> DigestChallenge, bool
fn parse_digest_param_key(raw: const u8[:], idx: i64&) -> const u8[:], bool
fn parse_quoted_param<B>(s: const u8[:], out: B&) -> i64, bool
fn parse_digest_param_val<B>(raw: const u8[:], idx: i64&, out: B&) -> bool
fn digest_hash_hex(algorithm: const u8[:], data: const u8[:]) -> u8[..64]
fn calculate_digest_ha1(algo: const u8[:], username: const u8[:], realm: const u8[:], password: const u8[:], nonce: const u8[:], cnonce: const u8[:]) -> u8[..64]
fn calculate_digest_ha2(algo: const u8[:], method: const u8[:], uri: const u8[:], is_auth_int: bool, body: const u8[:]) -> u8[..64]
fn calculate_digest_response(algo: const u8[:], ha1_hex: const u8[:], nonce: const u8[:], nc_str: const u8[:], cnonce: const u8[:], active_qop: const u8[:], ha2_hex: const u8[:]) -> u8[..64]
fn append_digest_uri<B>(out: B&, uri: const u8[:]) -> bool
fn resolve_userhash(username: const u8[:], realm: const u8[:], algo: const u8[:]) -> u8[..64]
fn qop_list_has_token(raw_qop: const u8[:], target: const u8[:]) -> bool
fn compute_digest_response<B>(challenge: const DigestChallenge&, creds: const DigestCredentials&, method: const u8[:], uri: const u8[:], nc: u32, cnonce: const u8[:], body: const u8[:], out: B&) -> bool
fn serialize_digest_auth<B>(effective_user: const u8[:], realm: const u8[:], nonce: const u8[:], uri: const u8[:], algo: const u8[:], response_hex: const u8[:], active_qop: const u8[:], nc_str: const u8[:], cnonce: const u8[:], opaque: const u8[:], userhash: bool, out: B&) -> bool
fn sync_digest_stale_challenge(stored: DigestChallenge&, incoming: const DigestChallenge&, creds: const DigestCredentials&, nc: u32&) -> bool
fn refresh_digest_stale_nonce(stored: DigestChallenge&, raw_header: const u8[:], creds: const DigestCredentials&, nc: u32&) -> bool
```

`parse_digest_challenge` parses an incoming `WWW-Authenticate: Digest` header
into fixed `u8[..128]` parameter buffers and rejects duplicate keys or
unsupported algorithms. `digest_hash_hex`, `calculate_digest_ha1`,
`calculate_digest_ha2`, and `calculate_digest_response` compute lowercase hex
digests for `MD5`, `SHA-256`, and `SHA-512-256` (including `-sess` variants and
`auth` or `auth-int` quality of protection). When `userhash=true` (RFC 7616
Section 3.4.4), `resolve_userhash` hashes `username:realm` so the raw username
never appears in `Authorization`. `sync_digest_stale_challenge` and
`refresh_digest_stale_nonce` update the client's nonce and reset `nc` to `1`
when `stale=true` without repeating password derivation.

### OAuth 2.0 PKCE, device grant, and introspection (`auth/pkce.goose`, `auth/device_grant.goose`, `auth/introspection.goose`)

```goose
struct PkcePair {
    verifier:  u8[..128] = [],
    challenge: u8[..128] = [],
    method:    u8[..16]  = "S256",
}

struct DeviceAuthResponse {
    device_code:               u8[..128] = [],
    user_code:                 u8[..32]  = [],
    verification_uri:          u8[..256] = [],
    verification_uri_complete: u8[..256] = [],
    expires_in_sec:            i64       = 0,
    interval_sec:              i64       = rfc::DEFAULT_DEVICE_POLL_INTERVAL_SEC,
}

enum DevicePollStatus { Granted, AuthorizationPending, SlowDown, AccessDenied, ExpiredToken, TransportError }
enum TokenTypeHint { None, AccessToken, RefreshToken }

struct IntrospectionResponse {
    active:     bool           = false,
    scope:      u8[..256]      = [],
    client_id:  u8[..128]      = [],
    username:   u8[..128]      = [],
    token_type: u8[..32]       = [],
    sub:        u8[..128]      = [],
    iss:        u8[..128]      = [],
    jti:        u8[..128]      = [],
    aud:        u8[..128][..8] = [],
    exp:        i64            = -1,
    iat:        i64            = -1,
    nbf:        i64            = -1,
}

fn create_pkce_pair(entropy: const u8[:] = "", method: const u8[:] = "S256") -> PkcePair, bool
fn encode_external_entropy<B>(entropy: const u8[:], out: B&) -> bool
fn generate_code_verifier<B>(out: B&, entropy: const u8[:] = "") -> bool
fn compute_code_challenge<B>(verifier: const u8[:], method: const u8[:], out: B&) -> bool
fn validate_code_challenge(verifier: const u8[:], challenge: const u8[:], method: const u8[:] = "S256") -> bool
fn validate_code_challenge_strict(verifier: const u8[:], challenge: const u8[:], method: const u8[:] = "S256") -> bool
fn is_valid_code_verifier(v: const u8[:]) -> bool
fn is_valid_code_challenge(challenge: const u8[:], method: const u8[:] = "S256") -> bool
fn is_valid_code_challenge_strict(challenge: const u8[:], method: const u8[:] = "S256") -> bool
fn parse_device_auth_response(raw_json: const u8[:]) -> DeviceAuthResponse, bool
fn step_device_poll_interval(status: DevicePollStatus, current_interval_sec: i64, max_backoff_sec: i64) -> i64, bool
fn encode_token_endpoint_form<B>(token: const u8[:], hint: TokenTypeHint, out: B&) -> bool
fn parse_introspection_response(raw_json: const u8[:]) -> IntrospectionResponse, bool
fn encode_oauth2_basic_auth<B>(client_id: const u8[:], client_secret: const u8[:], out: B&) -> bool
fn decode_oauth2_basic_auth<B1, B2>(header_val: const u8[:], out_id: B1&, out_secret: B2&) -> bool
```

PKCE enforces verifiers of 43 to 128 unreserved bytes and generates `S256`
challenges by default. The `*_strict` variants reject `"plain"` downgrades per
RFC 9700 Section 2.1.1. `step_device_poll_interval` takes `status` first for
UFCS ergonomics and adds 5 seconds on `SlowDown` (RFC 8628 Section 3.5).
`parse_introspection_response` clears all token metadata if `"active": false`.
`encode_oauth2_basic_auth` and `decode_oauth2_basic_auth` percent-encode and
decode client credentials in HTTP Basic headers per RFC 6749 Section 2.3.1.

### OAuth 2.0 DPoP (`auth/dpop.goose`, `auth/dpop_claims.goose`, RFC 9449)

```goose
struct DPoPJwkInfo {
    valid:           bool      = true,
    kty_ok:          bool      = false,
    has_private_key: bool      = false,
    kty:             u8[..8]   = [],
    alg:             u8[..16]  = [],
    crv:             u8[..16]  = [],
    x:               u8[..64]  = [],
    y:               u8[..64]  = [],
    n:               u8[..768] = [],
    e:               u8[..16]  = [],
}

struct DPoPClaims {
    jti:     u8[..512] = [],
    htm:     u8[..16]  = [],
    htu:     u8[..256] = [],
    iat:     i64       = -1,
    nonce:   u8[..512] = [],
    ath:     u8[..64]  = [],
    jkt:     u8[..64]  = [],
    has_iat: bool      = false,
}

struct DPoPJtiEntry {
    jti_hash:       u8[32] = [0; 32],
    expires_at_sec: i64    = 0,
}

struct DPoPReplayCache {
    entries: DPoPJtiEntry[..1024] = [],
}

fn normalize_dpop_target_uri<B>(raw_uri: const u8[:], out: B&) -> bool
fn compute_dpop_ath<B>(access_token: const u8[:], out: B&) -> bool
fn generate_dpop_jti<B>(out: B&, entropy: const u8[:] = "") -> bool
fn build_dpop_claims_json<B>(method: const u8[:], norm_uri: const u8[:], access_token: const u8[:], nonce: const u8[:], now_sec: i64, jti: const u8[:], out: B&) -> bool
fn is_matching_dpop_alg(alg_val: const u8[:], expected_alg: const u8[:]) -> bool
fn parse_dpop_header_jwk_info<B>(header_json: const u8[:], out_alg: B&, out_jwk: DPoPJwkInfo&) -> bool
fn verify_dpop_header<B>(header_json: const u8[:], expected_alg: const u8[:], out_alg: B&, out_jwk: DPoPJwkInfo&) -> bool
fn verify_dpop_header(header_json: const u8[:], expected_alg: const u8[:] = "EdDSA") -> bool
fn parse_dpop_claims(claims_json: const u8[:], out: DPoPClaims&) -> bool
fn verify_dpop_jti(claims_json: const u8[:]) -> bool
fn verify_dpop_method(claims_json: const u8[:], expected_method: const u8[:]) -> bool
fn verify_dpop_uri(claims_json: const u8[:], expected_uri: const u8[:]) -> bool
fn verify_dpop_iat(claims_json: const u8[:], now_sec: i64, max_age_sec: i64, max_skew_sec: i64) -> bool
fn verify_dpop_jkt(claims_json: const u8[:], expected_jkt: const u8[:]) -> bool
fn verify_dpop_claims(claims: const DPoPClaims&, expected_method: const u8[:], expected_uri: const u8[:], access_token: const u8[:] = "", expected_nonce: const u8[:] = "", now_sec: i64 = 0, max_age_sec: i64 = 300, max_skew_sec: i64 = 60, expected_jkt: const u8[:] = "") -> bool
fn matches_dpop_jkt_thumbprint(jwk_pub: const u8[32]&, claims_jkt: const u8[:], expected_jkt: const u8[:]) -> bool
fn verify_dpop_key_binding(key: const u8[:], expected_jkt: const u8[:], alg: const u8[:], jwk_info: const DPoPJwkInfo&) -> bool
fn create_dpop_proof<B>(key: const u8[:], method: const u8[:], target_uri: const u8[:], access_token: const u8[:], nonce: const u8[:], now_sec: i64, jti: const u8[:], out: B&) -> bool
fn create_dpop_proof_es256<B>(priv_key: const u8[32]&, method: const u8[:], target_uri: const u8[:], access_token: const u8[:], nonce: const u8[:], now_sec: i64, jti: const u8[:], out: B&) -> bool
fn verify_dpop_proof(jwt: const u8[:], key: const u8[:], expected_method: const u8[:], expected_uri: const u8[:], access_token: const u8[:] = "", expected_nonce: const u8[:] = "", now_sec: i64 = 0, max_age_sec: i64 = 300, max_skew_sec: i64 = 60, expected_jkt: const u8[:] = "", expected_alg: const u8[:] = "EdDSA") -> bool
fn attach_dpop<R>(req: R&, proof: const u8[:], access_token: const u8[:] = "")
fn extract_dpop_nonce(headers: const wing::HeaderMap&) -> const u8[:], bool
fn extract_dpop_nonce<B>(headers: const wing::HeaderMap&, out: B&) -> bool
fn check_and_record_dpop_jti(cache: DPoPReplayCache&, jti: const u8[:], now_sec: i64, ttl_sec: i64 = 300, max_skew_sec: i64 = 60, iat_sec: i64 = 0) -> bool
fn verify_dpop_proof_with_replay_cache(cache: DPoPReplayCache&, jwt: const u8[:], key: const u8[:], expected_method: const u8[:], expected_uri: const u8[:], now_sec: i64, access_token: const u8[:] = "", expected_nonce: const u8[:] = "", max_age_sec: i64 = 300, max_skew_sec: i64 = 60, expected_jkt: const u8[:] = "", expected_alg: const u8[:] = "EdDSA") -> bool
```

DPoP proofs bind HTTP method (`htm`), normalized target URI (`htu`), `iat`,
server `nonce`, and access token hash (`ath`) to an embedded ephemeral key
(`EdDSA`, `ES256`, `RS256`, or `PS256`). Embedded JWKs with private fields (`d`,
`k`, `p`, `q`, `oth`) are rejected. `verify_dpop_proof_with_replay_cache` takes
`cache` first for UFCS ergonomics and enforces single-use `jti` tracking inside
`DPoPReplayCache`.

### JSON Web Keys & Key Sets (`auth/jwk.goose`, `auth/jwks.goose`, RFC 7517, RFC 7638)

```goose
enum JwkKeyType { Unknown, OKP, Oct, EC, RSA }

const JWK_OP_SIGN:    u8 = 1;
const JWK_OP_VERIFY:  u8 = 2;
const JWK_OP_ENCRYPT: u8 = 4;

struct JwksKey {
    kty:              JwkKeyType = JwkKeyType.Unknown,
    crv:              u8[..32]   = "",
    alg:              JwtAlg     = JwtAlg.Unspecified,
    use:              u8[..16]   = "",
    kid:              u8[..64]   = [],
    symmetric_key:    u8[..128]  = [],
    public_key:       u8[32]     = [0; 32],
    ec_x:             u8[..48]   = [],
    ec_y:             u8[..48]   = [],
    rsa_n:            u8[..512]  = [],
    rsa_e:            u8[..8]    = [],
    x5t_s256:         u8[..44]   = [],
    key_ops:          u8         = 0,
    valid:            bool       = false,
    has_invalid_type: bool       = false,
}

struct Jwks {
    keys: JwksKey[..16] = [],
}

fn add_ed25519_key(jwks: Jwks&, kid: const u8[:], pub_key: const u8[32]) -> bool
fn add_es256_key(jwks: Jwks&, kid: const u8[:], x: const u8[:], y: const u8[:]) -> bool
fn add_rsa_key(jwks: Jwks&, kid: const u8[:], alg: JwtAlg, n_be: const u8[:], e_be: const u8[:]) -> bool
fn add_symmetric_key(jwks: Jwks&, kid: const u8[:], alg: JwtAlg, secret_key: const u8[:]) -> bool
fn serialize_jwks<B>(jwks: const Jwks&, out: B&) -> bool
fn parse_jwks_json(json_bytes: const u8[:], out_jwks: Jwks&) -> bool
fn find_key(jwks: const Jwks&, kid: const u8[:]) -> i64, bool
fn resolve_jwks_key_index(jwks: const Jwks&, kid: const u8[:]) -> i64, bool
fn validate_jwks_key_compatibility(key: const JwksKey&, header_alg: JwtAlg) -> JwtError
fn verify_jwt(jwks: const Jwks&, token: const u8[:], options: const JwtValidationOptions&, now_unix_sec: i64, out_header: JwtHeader&, out_claims: JwtClaims&) -> JwtError
fn compute_canonical_jwk<B>(key: const JwksKey&, out: B&) -> bool
fn compute_jwk_thumbprint<B>(key: const JwksKey&, out: B&) -> bool
fn zeroize_jwks_key(key: JwksKey&)
fn zeroize_jwks(jwks: Jwks&)
fn is_safe_remote_jwks_url(raw_url: const u8[:]) -> bool
```

`parse_jwks_json` parses up to 16 keys (`OKP` Ed25519, `EC` P-256, `RSA`, and
`oct`), validates embedded `x5c` certificate chains and `x5t#S256` thumbprints,
and rejects any key carrying private parameters (`d`, `p`, `q`, `dp`, `dq`,
`qi`, `oth`). `verify_jwt` dispatches by `kid` while enforcing strict
`kty`/`alg`/`use`/`key_ops` compatibility and preventing key-confusion attacks.
`is_safe_remote_jwks_url` restricts JWKS fetch targets to `https://` hosts
outside internal/SSRF CIDR ranges.

### ACME HTTP-01 challenges (`auth/acme.goose`, RFC 8555)

```goose
struct AcmeChallenge {
    token:    u8[..64]  = [],
    key_auth: u8[..256] = [],
}

fn validate_acme_token(token: const u8[:]) -> bool
fn build_acme_key_authorization<B>(token: const u8[:], thumbprint_b64url: const u8[:], out: B&) -> bool
fn build_acme_http01_path<B>(token: const u8[:], out: B&) -> bool
fn match_acme_http01(path: const u8[:], token: const u8[:]) -> bool
fn find_acme_challenge<B>(table: const AcmeChallenge[..8]&, path: const u8[:], out: B&) -> bool
```

`validate_acme_token` checks that an HTTP-01 token has 22 to 64 Base64URL
characters (>= 128 bits of entropy) without path traversal bytes.
`build_acme_key_authorization` writes `<token>.<thumbprint>` into `out`, and
`build_acme_http01_path` formats `/.well-known/acme-challenge/<token>`.
`match_acme_http01` and `find_acme_challenge` match incoming request paths in
constant time.

### JSON Web Tokens and JWE (`auth/jwt.goose`, `auth/jwt_core.goose`, `auth/jwe.goose`)

```goose
const DEFAULT_JWT_LEEWAY_SECONDS: i64 = 60;
const MAX_JWT_TOKEN_LEN:          i64 = 8192;
const MAX_JWT_HEADER_PART_LEN:    i64 = 1365;
const MAX_JWT_CLAIMS_PART_LEN:    i64 = 2730;

enum JwtAlg { Unspecified, None, HS256, HS384, HS512, EdDSA, ES256, RS256, PS256, Unknown }

enum JwtError {
    None, MalformedToken, InvalidBase64, InvalidHeaderJson, InvalidClaimsJson,
    UnsupportedAlgorithm, AlgorithmMismatch, SignatureInvalid, TokenExpired,
    TokenNotYetValid, IssuerMismatch, AudienceMismatch, SubjectMismatch,
    KeyNotFound, CriticalHeaderUnsupported, TypeMismatch,
}

struct CritParam { name: u8[..32] = [] }

struct JwtHeader {
    alg:     JwtAlg         = JwtAlg.HS256,
    typ:     u8[..32]       = "JWT",
    kid:     u8[..64]       = [],
    cty:     u8[..32]       = [],
    crit:    CritParam[..8] = [],
    b64:     bool           = true,
    has_b64: bool           = false,
}

struct JwtClaimItem {
    key:      u8[..64]  = [],
    val_str:  u8[..256] = [],
    val_num:  i64       = 0,
    val_bool: bool      = false,
    is_num:   bool      = false,
    is_bool:  bool      = false,
}

struct JwtClaims {
    iss:           u8[..128]          = [],
    sub:           u8[..128]          = [],
    aud:           u8[..128]          = [],
    audiences:     u8[..128][..8]     = [],
    jti:           u8[..64]           = [],
    exp:           i64                = -1,
    nbf:           i64                = -1,
    iat:           i64                = -1,
    custom_claims: JwtClaimItem[..16] = [],
    raw_payload:   u8[..2048]         = [],
}

struct JwtValidationOptions {
    expected_alg:              JwtAlg         = JwtAlg.HS256,
    expected_issuer:           u8[..128]      = [],
    expected_audience:         u8[..128]      = [],
    expected_subject:          u8[..128]      = [],
    expected_typ:              u8[..32]       = [],
    supported_crit:            CritParam[..8] = [],
    allowed_issuers:           u8[..128][..4] = [],
    allowed_audiences:         u8[..128][..4] = [],
    leeway_seconds:            i64            = DEFAULT_JWT_LEEWAY_SECONDS,
    min_remaining_ttl_seconds: i64            = 0,
    require_exp:               bool           = true,
    require_nbf:               bool           = false,
    allow_none_alg:            bool           = false,
    validate_aud_when_present: bool           = true,
}

fn parse_jwt_alg(s: const u8[:]) -> JwtAlg
fn new_jwt_header(alg: JwtAlg = JwtAlg.HS256, kid: const u8[:] = "") -> JwtHeader
fn add_header_crit(header: JwtHeader&, name: const u8[:]) -> bool
fn serialize_jwt_header<B>(header: const JwtHeader&, out: B&) -> bool
fn parse_jwt_header_json(json_bytes: const u8[:], out_header: JwtHeader&) -> bool
fn set_audience(claims: JwtClaims&, aud: const u8[:]) -> bool
fn add_audience(claims: JwtClaims&, aud: const u8[:]) -> bool
fn set_claim(claims: JwtClaims&, key: const u8[:], val: const u8[:]) -> bool
fn set_claim_int(claims: JwtClaims&, key: const u8[:], val: i64) -> bool
fn set_claim_bool(claims: JwtClaims&, key: const u8[:], val: bool) -> bool
fn claim_str(claims: const JwtClaims&, key: const u8[:]) -> const u8[:]
fn claim_int(claims: const JwtClaims&, key: const u8[:]) -> i64, bool
fn claim_bool(claims: const JwtClaims&, key: const u8[:]) -> bool, bool
fn serialize_jwt_claims<B>(claims: const JwtClaims&, out: B&) -> bool
fn parse_jwt_claims_json(json_bytes: const u8[:], out_claims: JwtClaims&) -> bool
fn default_jwt_validation_options(expected_alg: JwtAlg = JwtAlg.HS256) -> JwtValidationOptions
fn add_supported_crit(opts: JwtValidationOptions&, name: const u8[:]) -> bool
fn split_jwt_parts(token: const u8[:]) -> i64, i64, bool
fn validate_jwt_expiration(exp: i64, require_exp: bool, leeway: i64, now_unix_sec: i64) -> bool
fn validate_jwt_not_before(nbf: i64, require_nbf: bool, leeway: i64, now_unix_sec: i64) -> bool
fn verify_jwt_algorithm(header_alg: JwtAlg, expected_alg: JwtAlg, allow_none: bool) -> JwtError
fn is_matching_jwt_typ(header_typ: const u8[:], expected_typ: const u8[:]) -> bool
fn validate_jwt_identity_claims(claims: const JwtClaims&, options: const JwtValidationOptions&) -> JwtError
fn validate_jwt_claims_rules(claims: const JwtClaims&, options: const JwtValidationOptions&, now_unix_sec: i64) -> JwtError
fn verify_jwt_hmac_signature(alg: JwtAlg, secret_key: const u8[:], signing_input: const u8[:], sig_bytes: const u8[:]) -> bool
fn verify_jwt_eddsa_signature(public_key: const u8[32], signing_input: const u8[:], sig_bytes: const u8[:]) -> bool
fn verify_jwt_rsa_signature(alg: JwtAlg, n_be: const u8[:], e_be: const u8[:], signing_input: const u8[:], sig_bytes: const u8[:]) -> bool
fn sign_jwt_hmac<B>(header: const JwtHeader&, claims: const JwtClaims&, secret_key: const u8[:], out: B&) -> bool
fn verify_jwt_hmac(token: const u8[:], secret_key: const u8[:], options: const JwtValidationOptions&, now_unix_sec: i64, out_header: JwtHeader&, out_claims: JwtClaims&) -> JwtError
fn sign_jwt_eddsa<B>(header: const JwtHeader&, claims: const JwtClaims&, seed_key: const u8[32]&, out: B&) -> bool
fn verify_jwt_eddsa(token: const u8[:], public_key: const u8[32], options: const JwtValidationOptions&, now_unix_sec: i64, out_header: JwtHeader&, out_claims: JwtClaims&) -> JwtError
fn sign_jwt_es256<B>(header: const JwtHeader&, claims: const JwtClaims&, priv_key: const u8[32]&, out: B&) -> bool
fn verify_jwt_es256(token: const u8[:], public_key: const u8[:], options: const JwtValidationOptions&, now_unix_sec: i64, out_header: JwtHeader&, out_claims: JwtClaims&) -> JwtError
fn sign_jwt_rs256<B>(header: const JwtHeader&, claims: const JwtClaims&, n_be: const u8[:], d_be: const u8[:], out: B&) -> bool
fn sign_jwt_ps256<B>(header: const JwtHeader&, claims: const JwtClaims&, n_be: const u8[:], d_be: const u8[:], salt: const u8[:], out: B&) -> bool
fn verify_jwt_rsa(token: const u8[:], n_be: const u8[:], e_be: const u8[:], options: const JwtValidationOptions&, now_unix_sec: i64, out_header: JwtHeader&, out_claims: JwtClaims&) -> JwtError
fn decode_jwt_header(hdr_b64: const u8[:], out_header: JwtHeader&) -> JwtError
fn decode_jwt_claims(clm_b64: const u8[:], out_claims: JwtClaims&) -> JwtError
fn parse_jwt_header_only(token: const u8[:], out_header: JwtHeader&) -> JwtError
fn parse_jwt_unverified(token: const u8[:], out_header: JwtHeader&, out_claims: JwtClaims&) -> JwtError
fn verify_jws_unencoded_hs256(compact_token: const u8[:], secret: const u8[:]) -> bool
fn concat_kdf_sha256(z: const u8[32]&, alg_id: const u8[:], apu: const u8[:], apv: const u8[:], key_bits: u32) -> u8[32], bool
fn jwe_seal_dir_a256gcm<B>(protected_b64: const u8[:], cek: const u8[32]&, iv: const u8[12]&, plaintext: const u8[:], out: B&) -> bool
fn jwe_seal_dir_a256gcm_random_iv<B>(protected_b64: const u8[:], cek: const u8[32]&, plaintext: const u8[:], out: B&) -> bool
fn jwe_open_dir_a256gcm<B>(compact_token: const u8[:], cek: const u8[32]&, out: B&) -> bool
```

By default, `allow_none_alg` is `false` (RFC 8725 Section 3.1) and `require_exp`
is `true`. Signature verification runs before claims parsing, unknown critical
header parameters (`crit`) are rejected, and all HMAC/digest checks use
constant-time comparison (`core::ct_eq_bytes`).

## Invariants

- Symmetric keys, HA1 values, and intermediate signing buffers are wiped via
  `core::secure_zeroize_*` across normal returns and early error paths.
- Digest `sync_digest_stale_challenge` enforces algorithm downgrade protection
  (rejecting downgrade from SHA-256 to MD5).
- Unrecognized `alg` or `kty` values parse as explicit `Unknown` variants.
- `out: B&` builders roll back cleanly via `defer if !committed` on overflow or
  invalid preconditions without leaking partial output.

## Verification

```bash
goose check wing.goose
goose format --check auth
goosemarklint check auth/README.md
python scripts/verify_readme_signatures.py
goose-lit tests/auth_test.goose
goose-lit tests/lit/lit_auth_and_jwt.goose
goose-lit tests/lit/verify_rfc7520_jose.goose
```
