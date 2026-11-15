# `auth`

`auth` implements HTTP and OAuth 2.0 authentication protocols with stack-bounded
wire framing, constant-time cryptographic verification, and JSON Web Key Sets.

```goose
import wing;

let pair, ok = wing::create_pkce_pair();
var header = wing::new_jwt_header(wing::JwtAlg.HS256, "key-1");
var claims = wing::JwtClaims { exp: 1800000000, .. };
let _ = wing::set_audience(claims, "https://api.example.com");
var token: u8[..512] = [];
let signed = wing::sign_jwt_hmac(header, claims, "0123456789abcdef0123456789abcdef", token);
```

## Public API

### HTTP Digest Authentication (`auth/digest.goose`, RFC 7616)

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

fn parse_digest_challenge(raw: const u8[:]) -> DigestChallenge, bool
fn digest_hash_hex(algo: const u8[:], data: const u8[:]) -> u8[..64], bool
fn calculate_digest_ha1(algo: const u8[:], username: const u8[:], realm: const u8[:], password: const u8[:], nonce: const u8[:], cnonce: const u8[:]) -> u8[..64], bool
fn calculate_digest_ha2(algo: const u8[:], method: const u8[:], uri: const u8[:], qop: const u8[:], body: const u8[:]) -> u8[..64], bool
fn calculate_digest_response(algo: const u8[:], ha1: const u8[:], nonce: const u8[:], nc: const u8[:], cnonce: const u8[:], qop: const u8[:], ha2: const u8[:]) -> u8[..64], bool
fn resolve_userhash(algo: const u8[:], username: const u8[:], realm: const u8[:], out: u8[..128]&) -> bool
fn resolve_digest_user(userhash: bool, algo: const u8[:], username: const u8[:], realm: const u8[:], out_user_hash: u8[..128]&) -> const u8[:], bool
fn compute_digest_response<B>(challenge: const DigestChallenge&, creds: const DigestCredentials&, method: const u8[:], uri: const u8[:], nc: u32, cnonce: const u8[:], body: const u8[:], out_header: B&) -> bool
fn serialize_digest_auth<B>(effective_user: const u8[:], realm: const u8[:], nonce: const u8[:], uri: const u8[:], algo: const u8[:], response_hex: const u8[:], active_qop: const u8[:], nc_str: const u8[:], cnonce: const u8[:], opaque: const u8[:], userhash: bool, sink: B&) -> bool
fn sync_digest_stale_challenge(active_challenge: DigestChallenge&, next_challenge: const DigestChallenge&, nc: u32&) -> bool
fn refresh_digest_stale_nonce<B>(active_challenge: DigestChallenge&, www_auth_header: const u8[:], creds: const DigestCredentials&, method: const u8[:], uri: const u8[:], nc: u32&, cnonce: const u8[:], body: const u8[:], out_auth_header: B&) -> bool
```

`parse_digest_challenge` parses an incoming `WWW-Authenticate: Digest` header
into fixed `u8[..128]` parameter buffers and rejects duplicate keys or
unsupported algorithms. `digest_hash_hex`, `calculate_digest_ha1`,
`calculate_digest_ha2`, and `calculate_digest_response` compute lowercase hex
digests for `MD5`, `SHA-256`, and `SHA-512-256` (including `-sess` variants and
`auth` or `auth-int` quality of protection). When `userhash=true` (RFC 7616
§3.4.4), `resolve_userhash` and `resolve_digest_user` hash `username:realm`.
`sync_digest_stale_challenge` and `refresh_digest_stale_nonce` update the stored
challenge and reset `nc` to `1` only when `stale=true` while blocking algorithm
downgrades to `MD5`.

### OAuth 2.0 PKCE, Device Grant, Introspection & Basic Auth (`auth/pkce.goose`, RFC 7636, RFC 8628, RFC 7662, RFC 7009)

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
    interval_sec:              i64       = 5,
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
fn generate_code_verifier<B>(out: B&, entropy: const u8[:]) -> bool
fn compute_code_challenge<B>(verifier: const u8[:], method: const u8[:], out: B&) -> bool
fn validate_code_challenge(verifier: const u8[:], challenge: const u8[:], method: const u8[:]) -> bool
fn validate_code_challenge_strict(verifier: const u8[:], challenge: const u8[:], method: const u8[:] = "S256") -> bool
fn is_valid_code_verifier(v: const u8[:]) -> bool
fn is_valid_code_challenge(c: const u8[:], method: const u8[:]) -> bool
fn is_valid_code_challenge_strict(challenge: const u8[:], method: const u8[:] = "S256") -> bool
fn parse_device_auth_response(raw_json: const u8[:]) -> DeviceAuthResponse, bool
fn step_device_poll_interval(current_interval_sec: i64, max_backoff_sec: i64, status: DevicePollStatus) -> i64, bool
fn encode_token_endpoint_form<B>(token: const u8[:], hint: TokenTypeHint, out: B&) -> bool
fn parse_introspection_response(raw_json: const u8[:]) -> IntrospectionResponse, bool
fn encode_oauth2_basic_auth<B>(client_id: const u8[:], client_secret: const u8[:], out_header_val: B&) -> bool
fn decode_oauth2_basic_auth(header_val: const u8[:], out_id: u8[..256]&, out_secret: u8[..256]&) -> bool
```

PKCE verifiers require 43 to 128 URI unreserved characters (at least 32 bytes of
entropy when supplied by the caller), and `S256` challenges require 43 unpadded
Base64URL characters with canonical zero padding bits on the final character.
`validate_code_challenge_strict` and `is_valid_code_challenge_strict` reject
`plain` downgrades per RFC 9700. `step_device_poll_interval` adds 5 seconds to
the polling interval on `SlowDown` (RFC 8628 §3.5).
`parse_introspection_response` requires an explicit boolean `"active"` field and
clears all metadata when `active` is `false`. `encode_oauth2_basic_auth` and
`decode_oauth2_basic_auth` apply `application/x-www-form-urlencoded` to
`client_id` and `client_secret` before Base64 encoding per RFC 6749 §2.3.1.

### OAuth 2.0 DPoP (`auth/dpop.goose`, RFC 9449)

```goose
struct DPoPConfig {
    key:     u8[..64]  = [],
    nonce:   u8[..128] = [],
    alg:     u8[..16]  = "EdDSA",
    enabled: bool      = false,
}

struct DPoPJwkInfo {
    kty: u8[..8]   = [],
    crv: u8[..16]  = [],
    x:   u8[..64]  = [],
    y:   u8[..64]  = [],
    n:   u8[..768] = [],
    e:   u8[..16]  = [],
}

struct DPoPClaims {
    jti:     u8[..128] = [],
    htm:     u8[..16]  = [],
    htu:     u8[..256] = [],
    iat:     i64       = -1,
    nonce:   u8[..128] = [],
    ath:     u8[..64]  = [],
    jkt:     u8[..64]  = [],
    has_iat: bool      = false,
}

struct DPoPJtiEntry {
    jti:            u8[..128] = [],
    expires_at_sec: i64       = 0,
}

struct DPoPReplayCache {
    entries: DPoPJtiEntry[..128] = [],
}

fn normalize_dpop_target_uri<B>(raw_uri: const u8[:], out: B&) -> bool
fn compute_dpop_ath<B>(access_token: const u8[:], out: B&)
fn generate_dpop_jti<B>(out: B&, entropy: const u8[:] = "")
fn create_dpop_proof<B>(key: const u8[:], method: const u8[:], target_uri: const u8[:], access_token: const u8[:] = "", nonce: const u8[:] = "", now_sec: i64 = 0, jti: const u8[:] = "", out: B&) -> bool
fn create_dpop_proof_es256<B>(priv_key: const u8[32]&, method: const u8[:], target_uri: const u8[:], access_token: const u8[:] = "", nonce: const u8[:] = "", now_sec: i64 = 0, jti: const u8[:] = "", out: B&) -> bool
fn verify_dpop_header(header_json: const u8[:], expected_alg: const u8[:], out_alg: u8[..16]&, out_jwk: DPoPJwkInfo&) -> bool
fn verify_dpop_signature(signing_input: const u8[:], sig_b64: const u8[:], key: const u8[:]) -> bool
fn verify_dpop_signature_with_jwk(signing_input: const u8[:], sig_b64: const u8[:], alg: const u8[:], jwk_info: const DPoPJwkInfo&) -> bool
fn parse_dpop_claims(claims_json: const u8[:], out: DPoPClaims&) -> bool
fn verify_dpop_claims(claims: const DPoPClaims&, expected_method: const u8[:], expected_uri: const u8[:], access_token: const u8[:] = "", expected_nonce: const u8[:] = "", now_sec: i64 = 0, max_age_sec: i64 = 300, max_skew_sec: i64 = 60, expected_jkt: const u8[:] = "") -> bool
fn verify_dpop_key_binding(key: const u8[:], expected_jkt: const u8[:], alg: const u8[:], jwk_info: const DPoPJwkInfo&) -> bool
fn verify_dpop_proof(jwt: const u8[:], key: const u8[:], expected_method: const u8[:], expected_uri: const u8[:], access_token: const u8[:] = "", expected_nonce: const u8[:] = "", now_sec: i64 = 0, max_age_sec: i64 = 300, max_skew_sec: i64 = 60, expected_jkt: const u8[:] = "", expected_alg: const u8[:] = "EdDSA") -> bool
fn verify_dpop_proof_with_replay_cache(jwt: const u8[:], key: const u8[:], expected_method: const u8[:], expected_uri: const u8[:], now_sec: i64, cache: DPoPReplayCache&, access_token: const u8[:] = "", expected_nonce: const u8[:] = "", max_age_sec: i64 = 300, max_skew_sec: i64 = 60, expected_jkt: const u8[:] = "", expected_alg: const u8[:] = "EdDSA") -> bool
fn check_and_record_dpop_jti(cache: DPoPReplayCache&, jti: const u8[:], now_sec: i64, ttl_sec: i64 = 300, max_skew_sec: i64 = 60) -> bool
fn extract_dpop_nonce(headers: const HeaderMap&) -> const u8[:], bool
fn extract_dpop_nonce<B>(headers: const HeaderMap&, out_nonce: B&) -> bool
fn attach_dpop<R>(req: R&, proof: const u8[:], access_token: const u8[:] = "")
```

DPoP proofs bind an asymmetric `EdDSA` or `ES256` signature to the HTTP method
(`htm`), normalized target URI (`htu`, stripped of query and fragment per RFC
9449 §4.2), and access token SHA-256 hash (`ath`). `verify_dpop_header` requires
`typ: "dpop+jwt"`, an asymmetric algorithm, and an embedded public JWK without
private key fields (`d`, `p`, `q`, `k`). `DPoPReplayCache` stores SHA-256 `jti`
digests in a bounded ring buffer so `verify_dpop_proof_with_replay_cache` and
`check_and_record_dpop_jti` reject replayed proofs within the freshness window.

### JSON Web Key Sets (`auth/jwks.goose`, RFC 7517, RFC 7638, RFC 8725)

```goose
enum JwkKeyType { OKP, Oct, EC, RSA, Unknown }

struct JwksKey {
    kty:           JwkKeyType = JwkKeyType.Unknown,
    crv:           u8[..32]   = "",
    alg:           JwtAlg     = JwtAlg.Unspecified,
    use:           u8[..16]   = "",
    kid:           u8[..64]   = [],
    symmetric_key: u8[..64]   = [],
    public_key:    u8[32]     = [0; 32],
    ec_x:          u8[..48]   = [],
    ec_y:          u8[..48]   = [],
    rsa_n:         u8[..512]  = [],
    rsa_e:         u8[..8]    = [],
}

struct Jwks {
    keys: JwksKey[..16] = [],
}

fn add_ed25519_key(jwks: Jwks&, kid: const u8[:], pub_key: const u8[32]) -> bool
fn add_es256_key(jwks: Jwks&, kid: const u8[:], x: const u8[32]&, y: const u8[32]&) -> bool
fn add_rsa_key(jwks: Jwks&, kid: const u8[:], alg: const u8[:], n_bytes: const u8[:], e_bytes: const u8[:]) -> bool
fn add_symmetric_key(jwks: Jwks&, kid: const u8[:], alg: const u8[:], secret: const u8[:]) -> bool
fn parse_jwks_json(raw_json: const u8[:], jwks: Jwks&) -> bool
fn serialize_jwks<B>(jwks: const Jwks&, out: B&)
fn find_key(jwks: const Jwks&, kid: const u8[:]) -> i32
fn resolve_jwks_key_index(jwks: const Jwks&, header: const JwtHeader&) -> i32
fn validate_jwks_key_compatibility(key: const JwksKey&, required_alg: JwtAlg) -> JwtError
fn verify(jwks: const Jwks&, token: const u8[:], options: const JwtValidationOptions&, now_unix_sec: i64, out_header: JwtHeader&, out_claims: JwtClaims&) -> JwtError
fn compute_canonical_jwk<B>(key: const JwksKey&, out: B&) -> bool
fn compute_jwk_thumbprint<B>(key: const JwksKey&, out: B&) -> bool
fn zeroize_jwks_key(key: JwksKey&)
fn zeroize_jwks(jwks: Jwks&)
fn is_safe_remote_jwks_url(raw_url: const u8[:]) -> bool
```

`Jwks` holds up to 16 `JwksKey` entries covering `OKP` (Ed25519), `EC` (P-256),
`RSA` (`RS256` and `PS256`), and symmetric `oct` (HMAC) keys. `parse_jwks_json`
validates P-256 curve points, canonical RSA big-endian modulus/exponent
encoding, minimum 128-bit symmetric key length, and `use` / `key_ops`
consistency while rejecting any public JWK containing private key components.
`compute_canonical_jwk` and `compute_jwk_thumbprint` produce the
lexicographically ordered RFC 7638 JSON representation and its 43-character
Base64URL SHA-256 digest (`jkt`). `is_safe_remote_jwks_url` enforces HTTPS on
standard port and rejects loopback, RFC 1918 private IPv4, RFC 6598 CGNAT, and
cloud metadata endpoints (RFC 8725 §3.12).

### ACME HTTP-01 Challenges (`auth/acme.goose`, RFC 8555)

```goose
struct AcmeChallenge {
    token:        u8[..64]  = [],
    key_auth:     u8[..256] = [],
    key_auth_len: i32       = 0,
}

fn acme_validate_token(token: const u8[:]) -> bool
fn acme_key_authorization(token: const u8[:], thumbprint_b64url: const u8[:], out: u8[..256]&) -> i32
fn acme_http01_path(token: const u8[:], out: u8[..128]&) -> i32
fn acme_match_http01(path: const u8[:], token: const u8[:]) -> bool
fn acme_find_challenge(table: const AcmeChallenge[..8]&, path: const u8[:], out_body: u8[..256]&, out_len: i32&) -> bool
```

`acme_validate_token` checks that an HTTP-01 token is 1 to 64 Base64URL bytes
(`[A-Za-z0-9_-]`), rejecting path separators, dots, and padding.
`acme_key_authorization` writes `<token>.<thumbprint>` into `out` and
`acme_http01_path` formats `/.well-known/acme-challenge/<token>`, returning `-1`
if capacity is exceeded. `acme_match_http01` and `acme_find_challenge` match
incoming paths against up to 8 provisioned `AcmeChallenge` slots using
constant-time suffix comparison.

### JSON Web Tokens & JWE (`auth/jwt.goose`, RFC 7515, RFC 7516, RFC 7519, RFC 8725)

```goose
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
    str_val:  u8[..256] = [],
    int_val:  i64       = 0,
    bool_val: bool      = false,
    val_type: u8        = 0,
}

struct JwtClaims {
    iss:    u8[..128]        = [],
    sub:    u8[..128]        = [],
    aud:    u8[..128][..8]   = [],
    jti:    u8[..128]        = [],
    exp:    i64              = -1,
    nbf:    i64              = -1,
    iat:    i64              = -1,
    custom: JwtClaimItem[..16] = [],
}

struct JwtValidationOptions {
    expected_alg:      JwtAlg         = JwtAlg.HS256,
    expected_issuer:   u8[..128]      = [],
    expected_subject:  u8[..128]      = [],
    expected_audience: u8[..128]      = [],
    expected_typ:      u8[..32]       = [],
    supported_crit:    CritParam[..8] = [],
    clock_skew_sec:    i64            = 60,
    max_token_age_sec: i64            = 0,
    require_exp:       bool           = false,
}

fn new_jwt_header(alg: JwtAlg, kid: const u8[:] = "") -> JwtHeader
fn add_header_crit(header: JwtHeader&, ext_name: const u8[:]) -> bool
fn serialize_jwt_header<B>(header: const JwtHeader&, out: B&)
fn parse_jwt_header_json(json_bytes: const u8[:], out: JwtHeader&) -> bool
fn set_audience(claims: JwtClaims&, aud: const u8[:]) -> bool
fn add_audience(claims: JwtClaims&, aud: const u8[:]) -> bool
fn set_claim(claims: JwtClaims&, key: const u8[:], val: const u8[:]) -> bool
fn set_claim_int(claims: JwtClaims&, key: const u8[:], val: i64) -> bool
fn set_claim_bool(claims: JwtClaims&, key: const u8[:], val: bool) -> bool
fn claim_str(claims: const JwtClaims&, key: const u8[:]) -> const u8[:]
fn claim_int(claims: const JwtClaims&, key: const u8[:]) -> i64, bool
fn claim_bool(claims: const JwtClaims&, key: const u8[:]) -> bool, bool
fn serialize_jwt_claims<B>(claims: const JwtClaims&, out: B&)
fn parse_jwt_claims_json(json_bytes: const u8[:], out: JwtClaims&) -> bool
fn default_jwt_validation_options(expected_alg: JwtAlg) -> JwtValidationOptions
fn add_supported_crit(opts: JwtValidationOptions&, ext_name: const u8[:]) -> bool
fn sign_jwt_hmac<B>(header: const JwtHeader&, claims: const JwtClaims&, secret_key: const u8[:], out_token: B&) -> bool
fn verify_jwt_hmac(token: const u8[:], secret_key: const u8[:], options: const JwtValidationOptions&, now_unix_sec: i64, out_header: JwtHeader&, out_claims: JwtClaims&) -> JwtError
fn sign_jwt_eddsa<B>(header: const JwtHeader&, claims: const JwtClaims&, seed_key: const u8[32], out_token: B&) -> bool
fn verify_jwt_eddsa(token: const u8[:], public_key: const u8[32], options: const JwtValidationOptions&, now_unix_sec: i64, out_header: JwtHeader&, out_claims: JwtClaims&) -> JwtError
fn sign_jwt_es256<B>(header: const JwtHeader&, claims: const JwtClaims&, private_key: const u8[32]&, out_token: B&) -> bool
fn verify_jwt_es256(token: const u8[:], public_x: const u8[32]&, public_y: const u8[32]&, options: const JwtValidationOptions&, now_unix_sec: i64, out_header: JwtHeader&, out_claims: JwtClaims&) -> JwtError
fn sign_jwt_rs256<B>(header: const JwtHeader&, claims: const JwtClaims&, n_bytes: const u8[:], d_bytes: const u8[:], out_token: B&) -> bool
fn sign_jwt_ps256<B>(header: const JwtHeader&, claims: const JwtClaims&, n_bytes: const u8[:], d_bytes: const u8[:], salt: const u8[32]&, out_token: B&) -> bool
fn verify_jwt_rsa(token: const u8[:], n_bytes: const u8[:], e_bytes: const u8[:], options: const JwtValidationOptions&, now_unix_sec: i64, out_header: JwtHeader&, out_claims: JwtClaims&) -> JwtError
fn parse_jwt_header_only(token: const u8[:], out_header: JwtHeader&) -> JwtError
fn parse_jwt_unverified(token: const u8[:], out_header: JwtHeader&, out_claims: JwtClaims&) -> JwtError
fn verify_jws_unencoded_hs256(compact_detached_token: const u8[:], detached_payload: const u8[:], secret_key: const u8[:]) -> JwtError
fn concat_kdf_sha256(shared_secret_z: const u8[:], alg_id: const u8[:], apu: const u8[:], apv: const u8[:], key_datalen_bits: u32, out_key: u8[:]) -> bool
fn jwe_seal_dir_a256gcm<B>(cek: const u8[32]&, iv: const u8[12]&, plaintext: const u8[:], kid: const u8[:] = "", out_compact: B&) -> bool
fn jwe_open_dir_a256gcm<B>(compact_jwe: const u8[:], cek: const u8[32]&, out_plaintext: B&) -> bool
```

JWT verification pins `header.alg` to `options.expected_alg`, rejects `alg:
"none"` by default, checks minimum HMAC key lengths per RFC 7518 §3.2 (`32`
bytes for `HS256`, `48` for `HS384`, `64` for `HS512`), validates `crit` headers
against `options.supported_crit`, and verifies `exp`, `nbf`, `iat`, `iss`,
`sub`, `aud`, and `typ` (RFC 8725). `verify_jws_unencoded_hs256` implements RFC
7797 `b64=false` detached payload verification. `concat_kdf_sha256` implements
NIST SP 800-56A `Concat KDF` for `ECDH-ES`, and `jwe_seal_dir_a256gcm` /
`jwe_open_dir_a256gcm` provide RFC 7516 JWE Compact Serialization with direct
`A256GCM` authenticated encryption.

## Invariants

| Invariant | Mechanism |
| :--- | :--- |
| Zero heap allocation | Parsing, decoding, and formatting use stack-bounded arrays (`u8[..N]`) and byte slices (`const u8[:]`). |
| Constant-time verification | MACs, signatures, hashes, and secrets use `core::ct_eq_bytes` to prevent timing side channels. |
| RFC 8725 defenses | Rejects `none` by default, pins expected algorithms, checks `crit` headers, and validates `typ`. |
| SSRF mitigation | Remote JWKS URLs require HTTPS on standard port and block loopback, RFC 1918, RFC 6598, and metadata hosts. |
| Capacity safety | Bounded output buffers reject oversize inputs without silent truncation. |

## Verification

```bash
python tools/test_runner.py -p "*auth*"
python tools/test_runner.py --check-only
python scripts/lint_invariants.py --target-file auth/jwks.goose --strict-examples
python scripts/verify_wing_gate.py auth/pkce.goose --max-gcrap 25
```
