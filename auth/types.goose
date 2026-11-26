// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Public types, enums, and protocol bounds for HTTP and OAuth 2.0 authentication.
namespace auth;

import std;
import core;
import rfc.http;

// ---- ACME HTTP-01 Challenges (RFC 8555 §8.1 / §8.3) ----------------------

// HTTP-01 responder table entry: one provisioned challenge per slot.
struct AcmeChallenge {
    token:    u8[..64]  = [],
    key_auth: u8[..256] = [],
}

// ---- OAuth 2.0 Device Authorization Grant (RFC 8628) ---------------------

struct DeviceAuthResponse {
    device_code:               u8[..128] = [],
    user_code:                 u8[..32]  = [],
    verification_uri:          u8[..256] = [],
    verification_uri_complete: u8[..256] = [],
    expires_in_sec:            i64       = 0,
    interval_sec:              i64       = rfc::DEFAULT_DEVICE_POLL_INTERVAL_SEC,
}

enum DevicePollStatus {
    Granted,
    AuthorizationPending,
    SlowDown,
    AccessDenied,
    ExpiredToken,
    TransportError,
}

// ---- HTTP Digest Access Authentication (RFC 7616) ------------------------

struct DigestChallenge {
    realm:             u8[..128] = [],
    nonce:             u8[..128] = [],
    algorithm:         u8[..32]  = "MD5", // RFC 7616 §3.4 default when omitted
    qop:               u8[..32]  = [],    // Empty by default (RFC 2069 legacy mode when omitted)
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

// ---- OAuth 2.0 PKCE (RFC 7636) -------------------------------------------

struct PkcePair {
    verifier:  u8[..128] = [],
    challenge: u8[..128] = [],
    method:    u8[..16]  = "S256",
}

// ---- OAuth 2.0 Introspection & Revocation (RFC 7662 / RFC 7009) ----------

enum TokenTypeHint {
    None,
    AccessToken,
    RefreshToken,
}

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

// ---- JSON Web Tokens & Signatures (RFC 7515 / RFC 7519 / RFC 8725) -------

const DEFAULT_JWT_LEEWAY_SECONDS: i64 = 60;
const MAX_JWT_TOKEN_LEN:          i64 = 8192;
const MAX_JWT_HEADER_PART_LEN:    i64 = 1365;
const MAX_JWT_CLAIMS_PART_LEN:    i64 = 2730;

enum JwtAlg {
    Unspecified, // Omitted in key/options (RFC 7517 §4.4)
    None,        // Explicit "none" algorithm (RFC 7518 §3.6, disallowed by default per RFC 8725 §3.1)
    HS256,       // HMAC using SHA-256 (RFC 7518 Section 3.2)
    HS384,       // HMAC using SHA-384
    HS512,       // HMAC using SHA-512
    EdDSA,       // Ed25519 digital signature (RFC 8037 Section 3.1)
    ES256,       // ECDSA using P-256 and SHA-256 (RFC 7518 Section 3.4)
    RS256,       // RSASSA-PKCS1-v1_5 using SHA-256 (RFC 7518 Section 3.3)
    PS256,       // RSASSA-PSS using SHA-256 and MGF1 with SHA-256 (RFC 7518 Section 3.5)
    Unknown,     // Unsupported or unrecognized algorithm (RFC 7515 §4.1.1)
}

enum JwtError {
    None,
    MalformedToken,            // Missing dots, wrong part count (must be exactly 3 parts)
    InvalidBase64,             // Base64URL decoding failed
    InvalidHeaderJson,         // Header JSON could not be parsed
    InvalidClaimsJson,         // Claims JSON could not be parsed
    UnsupportedAlgorithm,      // Unknown algorithm or 'none' when not explicitly allowed
    AlgorithmMismatch,         // Token header alg does not match expected verification alg
    SignatureInvalid,          // Cryptographic signature check failed
    TokenExpired,              // exp claim is before now - leeway
    TokenNotYetValid,          // nbf claim is after now + leeway
    IssuerMismatch,            // iss claim does not match expected issuer
    AudienceMismatch,          // aud claim does not match expected audience
    SubjectMismatch,           // sub claim does not match expected subject
    KeyNotFound,               // kid requested by token not found in JWKS
    CriticalHeaderUnsupported, // crit header contains unsupported param (RFC 7515 §4.1.11 / RFC 8725 §3.8)
    TypeMismatch,              // typ header does not match expected type (RFC 8725 §3.11 / RFC 9068)
}

struct CritParam {
    name: u8[..32] = [],
}

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
    cnf_jkt:       u8[..128]          = [],
    custom_claims: JwtClaimItem[..16] = [],
    raw_payload:   u8[..2048]         = [],
}

struct JwtValidationOptions {
    expected_alg:              JwtAlg         = JwtAlg.HS256,
    expected_issuer:           u8[..128]      = [],
    expected_audience:         u8[..128]      = [],
    expected_subject:          u8[..128]      = [],
    expected_typ:              u8[..32]       = [],  // RFC 8725 §3.11 & RFC 9068: Explicit type verification
    supported_crit:            CritParam[..8] = [],  // RFC 7515 §4.1.11 / RFC 8725 §3.8: Supported critical parameters
    allowed_issuers:           u8[..128][..4] = [],
    allowed_audiences:         u8[..128][..4] = [],
    leeway_seconds:            i64            = DEFAULT_JWT_LEEWAY_SECONDS,
    min_remaining_ttl_seconds: i64            = 0,
    require_exp:               bool           = true,
    require_nbf:               bool           = false,
    allow_none_alg:            bool           = false, // RFC 8725 §3.1: Strictly false by default
    validate_aud_when_present: bool           = true,  // RFC 7519 §4.1.3: Reject non-empty aud when unconfigured
}

// ---- JSON Web Keys & Key Sets (RFC 7517 / RFC 7518 / RFC 8037) -----------

enum JwkKeyType {
    Unknown,
    OKP,    // Octet Key Pair (RFC 8037: Ed25519)
    Oct,    // Symmetric Octet Sequence (RFC 7518: HMAC)
    EC,     // Elliptic Curve (RFC 7518: ECDSA P-256)
    RSA,    // RSA Key (RFC 7518: RSASSA-PKCS1-v1_5 / RSASSA-PSS)
}

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

// ---- OAuth 2.0 DPoP (RFC 9449) -------------------------------------------

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

struct DPoPJtiEntry {
    jti_hash:       u8[32] = [0; 32],
    expires_at_sec: i64    = 0,
}

struct DPoPReplayCache {
    entries: DPoPJtiEntry[..1024] = [],
}
