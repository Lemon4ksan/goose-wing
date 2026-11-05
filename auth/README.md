# `auth`

## Overview

RFC-compliant implementations of core HTTP and OAuth authentication protocols. Provides zero-allocation wire framing, cryptographic token signing and verification, JSON Web Key Sets (JWKS), and Application-Layer Proof-of-Possession (DPoP).

## Public API

### HTTP Digest Authentication (RFC 7616)

- **`struct DigestChallenge`**: Parsed challenge container (`realm`, `nonce`, `opaque`, `algorithm`, `qop`, `userhash`, `stale`).
- **`struct DigestCredentials`**: User credentials container (`username`, `password`).
- **`fn parse_digest_challenge(raw: const u8[:]) -> DigestChallenge, bool`**: Parses an incoming `WWW-Authenticate: Digest` header.
- **`fn compute_digest_response<B>(challenge: const DigestChallenge&, creds: const DigestCredentials&, method: const u8[:], uri: const u8[:], nc: u32, cnonce: const u8[:], body: const u8[:], out_header: B&) -> bool`**: Computes RFC 7616 cryptographic response digest.
- **`fn serialize_digest_auth<B>(effective_user: const u8[:], realm: const u8[:], nonce: const u8[:], uri: const u8[:], algo: const u8[:], response_hex: const u8[:], active_qop: const u8[:], nc_str: const u8[:], cnonce: const u8[:], opaque: const u8[:], userhash: bool, sink: B&) -> bool`**: Formats an RFC 7616 `Authorization: Digest` header.

### OAuth 2.0 PKCE (RFC 7636)

- **`struct PkcePair`**: Pair container holding `verifier` and `challenge`.
- **`fn create_pkce_pair(entropy: const u8[:] = "", method: const u8[:] = "S256") -> PkcePair, bool`**: Generates a high-entropy code verifier and its S256 challenge.
- **`fn generate_code_verifier<B>(out: B&, entropy: const u8[:]) -> bool`**: Generates an RFC 7636 verifier string (43–128 unreserved characters).
- **`fn compute_code_challenge<B>(verifier: const u8[:], method: const u8[:], out: B&) -> bool`**: Computes an `S256` or `plain` code challenge.
- **`fn validate_code_challenge(verifier: const u8[:], challenge: const u8[:], method: const u8[:]) -> bool`**: Validates a verifier against an authorization challenge using constant-time comparison.
- **`fn is_valid_code_verifier(v: const u8[:]) -> bool`**: Verifies length (43–128) and unreserved character grammar.
- **`fn is_valid_code_challenge(c: const u8[:], method: const u8[:]) -> bool`**: Verifies challenge length and character grammar.

### OAuth 2.0 DPoP (RFC 9449)

- **`struct DPoPClaims`**: Validated proof claims (`jti`, `htm`, `htu`, `iat`, `nonce`, `ath`, `jkt`).
- **`struct DPoPReplayCache`**: Bounded ring-buffer tracking recent `jti` tokens to defend against replay attacks.
- **`fn create_dpop_proof<B>(key: const u8[:], method: const u8[:], target_uri: const u8[:], access_token: const u8[:], nonce: const u8[:], now_sec: i64, jti: const u8[:], out: B&) -> bool`**: Generates an asymmetric Ed25519 DPoP proof JWT.
- **`fn verify_dpop_proof(jwt: const u8[:], key: const u8[:], expected_method: const u8[:], expected_uri: const u8[:], access_token: const u8[:] = "", expected_nonce: const u8[:] = "", now_sec: i64 = 0, max_age_sec: i64 = 300, max_skew_sec: i64 = 60, expected_jkt: const u8[:] = "", expected_alg: const u8[:] = "EdDSA") -> bool`**: Validates DPoP proof signature, lifetime, target URI, HTTP method, and access token binding (`ath`).
- **`fn verify_dpop_proof_with_replay_cache(jwt: const u8[:], key: const u8[:], expected_method: const u8[:], expected_uri: const u8[:], now_sec: i64, cache: DPoPReplayCache&, access_token: const u8[:] = "", expected_nonce: const u8[:] = "", max_age_sec: i64 = 300, max_skew_sec: i64 = 60, expected_jkt: const u8[:] = "", expected_alg: const u8[:] = "EdDSA") -> bool`**: Validates DPoP proof and enforces single-use via replay cache.
- **`fn attach_dpop<R>(req: R&, proof: const u8[:], access_token: const u8[:] = "")`**: Attaches `DPoP` and `Authorization: DPoP <token>` headers to a request.

### JSON Web Key Sets (RFC 7517, RFC 7638, RFC 8725)

- **`enum JwkKeyType`**: Key family variants (`OKP`, `Oct`, `Unknown`).
- **`struct JwksKey`**: Key container holding Ed25519 public key or symmetric HMAC key.
- **`struct Jwks`**: Stack-bounded collection of up to 16 keys.
- **`fn parse_jwks_json(raw_json: const u8[:], jwks: Jwks&) -> bool`**: Parses JSON Web Key Set.
- **`fn serialize_jwks<B>(jwks: const Jwks&, out: B&)`**: Serializes JWKS into JSON string.
- **`fn find_key(jwks: const Jwks&, kid: const u8[:]) -> i64`**: Finds key index in JWKS by identifier (`kid`).
- **`fn compute_jwk_thumbprint<B>(key: const JwksKey&, out: B&) -> bool`**: Computes canonical RFC 7638 SHA-256 thumbprint.
- **`fn is_safe_remote_jwks_url(raw_url: const u8[:]) -> bool`**: SSRF validation for JWKS endpoint retrieval (RFC 8725 §3.12).

### ACME HTTP-01 Challenges (RFC 8555)

- **`fn acme_validate_token(token: const u8[:]) -> bool`**: Validates HTTP-01 token syntax (RFC 8555 §8.3).
- **`fn acme_key_authorization(token: const u8[:], thumbprint_b64url: const u8[:], out: u8[..256]&) -> i32`**: Builds the `<token>.<thumbprint>` key authorization string (RFC 8555 §8.1).
- **`fn acme_http01_path(token: const u8[:], out: u8[..128]&) -> i32`**: Formats the `/.well-known/acme-challenge/<token>` URI path.
- **`fn acme_match_http01(path: const u8[:], token: const u8[:]) -> bool`**: Matches an incoming request path against a token.
- **`fn acme_find_challenge(table: const AcmeChallenge[..8]&, path: const u8[:], out_body: u8[..256]&, out_len: i32&) -> bool`**: Looks up the challenge response payload in the responder table.

### JSON Web Tokens (RFC 7515, RFC 7519, RFC 8725)

- **`enum JwtAlg`**: Algorithm enum (`HS256`, `HS384`, `HS512`, `EdDSA`, `None`, `Unknown`).
- **`enum JwtError`**: Detailed verification error codes.
- **`struct JwtHeader`**: JOSE header attributes (`alg`, `typ`, `kid`, `crit`).
- **`struct JwtClaims`**: Standard registered claims and custom payload fields.
- **`struct JwtValidationOptions`**: Verification constraints (required issuer, audience, algorithm, clock skew).
- **`fn sign_jwt_hmac<B>(header: const JwtHeader&, claims: const JwtClaims&, secret_key: const u8[:], out_token: B&) -> bool`**: Serializes and signs HMAC JWT.
- **`fn verify_jwt_hmac(token: const u8[:], secret_key: const u8[:], options: const JwtValidationOptions&, now_unix_sec: i64, out_header: JwtHeader&, out_claims: JwtClaims&) -> JwtError`**: Verifies HMAC signature and claims.
- **`fn sign_jwt_eddsa<B>(header: const JwtHeader&, claims: const JwtClaims&, seed_key: const u8[32], out_token: B&) -> bool`**: Serializes and signs Ed25519 JWT.
- **`fn verify_jwt_eddsa(token: const u8[:], public_key: const u8[32], options: const JwtValidationOptions&, now_unix_sec: i64, out_header: JwtHeader&, out_claims: JwtClaims&) -> JwtError`**: Verifies Ed25519 signature and claims.

## Invariants

- **Zero heap allocation**: Parsing, decoding, and formatting use stack-bounded arrays and zero-copy byte slice views (`const u8[:]`).
- **Constant-time verification**: MACs, signatures, hashes, and secrets are verified with `core::ct_eq_bytes` to prevent timing side channels.
- **RFC 8725 security best practices**: Rejects `none` algorithm by default, enforces algorithm pinning, verifies `crit` headers, and enforces explicit token typing (`typ`).
- **SSRF mitigation**: Remote JWKS URLs require HTTPS with standard port and strictly reject loopback, private IPv4 (RFC 1918), CGNAT (RFC 6598), and internal cloud metadata hostnames.
- **Capacity safety**: Invariant 13 buffer guards reject oversize inputs explicitly without silent truncation.

## Verification

- Run auth unit test suite: `python tools/test_runner.py -p "*auth*"`
- Run full typecheck: `python tools/test_runner.py --check-only`
- Run invariant audit: `python scripts/lint_invariants.py --target-file auth/jwks.goose --strict-examples`
- Hardware complexity gate: `python scripts/verify_wing_gate.py auth/pkce.goose --max-gcrap 25`
