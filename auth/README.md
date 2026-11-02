# `auth`

## Overview
RFC-compliant implementations of core HTTP and OAuth authentication protocols. Provides zero-allocation wire framing, cryptographic token signing and verification, JSON Web Key Sets (JWKS), and Application-Layer Proof-of-Possession (DPoP).

## Public API

### HTTP Digest Authentication (RFC 7616)
- **`struct DigestChallenge`**: Parsed challenge container (`realm`, `nonce`, `opaque`, `algorithm`, `qop`, `userhash`, `stale`).
- **`struct DigestCredentials`**: User credentials container (`username`, `password`).
- **`fn parse_digest_challenge(raw: const u8[:]) -> DigestChallenge, bool`**: Parses an incoming `WWW-Authenticate: Digest` header.
- **`fn compute_digest_response<B>(chal: const DigestChallenge&, creds: const DigestCredentials&, method: const u8[:], uri: const u8[:], cnonce: const u8[:], nc: u32, body: const u8[:], out: B&) -> bool`**: Computes RFC 7616 cryptographic response digest.
- **`fn serialize_digest_auth<B>(chal: const DigestChallenge&, creds: const DigestCredentials&, method: const u8[:], uri: const u8[:], cnonce: const u8[:], nc: u32, body: const u8[:], out: B&) -> bool`**: Formats an RFC 7616 `Authorization: Digest` header.

### OAuth 2.0 PKCE (RFC 7636)
- **`struct PkcePair`**: Pair container holding `verifier` and `challenge`.
- **`fn generate_pkce_pair(out_pair: PkcePair&, entropy: const u8[:]) -> bool`**: Generates a high-entropy code verifier and its S256 challenge.
- **`fn generate_code_verifier<B>(out: B&, entropy: const u8[:]) -> bool`**: Generates an RFC 7636 verifier string (43–128 unreserved characters).
- **`fn compute_code_challenge<B>(verifier: const u8[:], method: const u8[:], out: B&) -> bool`**: Computes an `S256` or `plain` code challenge.
- **`fn validate_code_challenge(verifier: const u8[:], challenge: const u8[:], method: const u8[:]) -> bool`**: Validates a verifier against an authorization challenge using constant-time comparison.
- **`fn is_valid_code_verifier(v: const u8[:]) -> bool`**: Verifies length (43–128) and unreserved character grammar.
- **`fn is_valid_code_challenge(c: const u8[:], method: const u8[:]) -> bool`**: Verifies challenge length and character grammar.

### OAuth 2.0 DPoP (RFC 9449)
- **`struct DPoPClaims`**: Validated proof claims (`jti`, `htm`, `htu`, `iat`, `nonce`, `ath`).
- **`struct DpopReplayCache`**: Bounded ring-buffer tracking recent `jti` tokens to defend against replay attacks.
- **`fn create_dpop_proof<B>(key: const u8[:], method: const u8[:], target_uri: const u8[:], access_token: const u8[:], nonce: const u8[:], now_sec: i64, jti: const u8[:], out: B&) -> bool`**: Generates an asymmetric Ed25519 DPoP proof JWT.
- **`fn verify_dpop_proof(proof_jwt: const u8[:], expected_method: const u8[:], expected_uri: const u8[:], expected_nonce: const u8[:], access_token: const u8[:], now_sec: i64, out: DPoPClaims&) -> bool`**: Validates DPoP proof signature, lifetime, target URI, HTTP method, and access token binding (`ath`).
- **`fn verify_dpop_proof_with_replay_cache(proof_jwt: const u8[:], expected_method: const u8[:], expected_uri: const u8[:], expected_nonce: const u8[:], access_token: const u8[:], now_sec: i64, cache: DpopReplayCache&, out: DPoPClaims&) -> bool`**: Validates DPoP proof and enforces single-use via replay cache.
- **`fn attach_dpop<B>(proof_jwt: const u8[:], out: B&) -> bool`**: Serializes `DPoP: <token>` header into wire buffer.

### JSON Web Key Sets (RFC 7517, RFC 7638, RFC 8725)
- **`enum JwkKeyType`**: Key family variants (`OKP`, `Oct`, `Unknown`).
- **`struct JwksKey`**: Key container holding Ed25519 public key or symmetric HMAC key.
- **`struct Jwks`**: Stack-bounded collection of up to 16 keys.
- **`fn parse_jwks_json(raw_json: const u8[:], jwks: Jwks&) -> bool`**: Parses JSON Web Key Set.
- **`fn serialize_jwks<B>(jwks: const Jwks&, out: B&) -> bool`**: Serializes JWKS into JSON string.
- **`fn find_key(jwks: const Jwks&, kid: const u8[:]) -> const JwksKey&, bool`**: Finds key by identifier (`kid`).
- **`fn compute_jwk_thumbprint<B>(key: const JwksKey&, out: B&) -> bool`**: Computes canonical RFC 7638 SHA-256 thumbprint.
- **`fn is_safe_remote_jwks_url(raw_url: const u8[:]) -> bool`**: SSRF validation for JWKS endpoint retrieval (RFC 8725 §3.12).

### ACME HTTP-01 Challenges (RFC 8555)
- **`fn acme_validate_token(token: const u8[:]) -> bool`** / **`fn acme_key_authorization(token: const u8[:], thumbprint_b64url: const u8[:], out: u8[..256]&) -> i32`** / **`fn acme_http01_path(token: const u8[:], out: u8[..128]&) -> i32`** / **`fn acme_match_http01(path: const u8[:], token: const u8[:]) -> bool`** / **`fn acme_find_challenge(table: const AcmeChallenge[..8]&, path: const u8[:], out_body: u8[..256]&, out_len: i32&) -> bool`**: HTTP-01 token validation, key authorization, path construction/matching, and challenge responder lookup (RFC 8555 §8.1/§8.3).

### JSON Web Tokens (RFC 7515, RFC 7519, RFC 8725)
- **`enum JwtAlg`**: Algorithm enum (`HS256`, `HS384`, `HS512`, `EdDSA`, `None`, `Unknown`).
- **`enum JwtError`**: Detailed verification error codes.
- **`struct JwtHeader`**: JOSE header attributes (`alg`, `typ`, `kid`, `crit`).
- **`struct JwtClaims`**: Standard registered claims and custom payload fields.
- **`struct JwtValidationOptions`**: Verification constraints (required issuer, audience, algorithm, clock skew).
- **`fn sign_jwt_hmac<B>(alg: JwtAlg, secret_key: const u8[:], claims_json: const u8[:], out_token: B&) -> JwtError`**: Serializes and signs HMAC JWT.
- **`fn verify_jwt_hmac(token: const u8[:], secret_key: const u8[:], options: const JwtValidationOptions&, now_unix_sec: i64, out_header: JwtHeader&, out_claims: JwtClaims&) -> JwtError`**: Verifies HMAC signature and claims.
- **`fn sign_jwt_eddsa<B>(private_key: const u8[32], claims_json: const u8[:], out_token: B&) -> JwtError`**: Serializes and signs Ed25519 JWT.
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
