# `client`

## Overview

High-performance HTTP client engine providing zero-allocation request/response representation, automatic content decompression (gzip, brotli, zstd, dcz/dcb), OkHttp-style application/network interceptor chains, resilient connection pooling, and client fingerprint emulation (JA4).

## Public API

### Configuration & Lifecycle

- **`struct ClientConfig`**: Configuration container (`base_url`, `profile`, `proxy_url`, `timeout_ms`, `follow_redirects`, `cookie_jar`, `enable_cache`, etc.).
- **`struct Client`**: Primary HTTP client instance holding transport pools, caches, policies, and interceptors.
- **`fn new_client() -> Client`**: Creates a default Client instance.
- **`fn new_client(cfg: ClientConfig) -> Client`**: Creates a Client configured with specific parameters.
- **`fn new_client(base_url: const u8[:]) -> Client`**: Creates a Client with a pre-configured base URL.
- **`fn set_profile(client: Client&, profile: Profile)`**: Configures browser TLS/HTTP fingerprint profile (JA4/Akamai).
- **`fn set_timeout_ms(client: Client&, ms: i64)`**: Sets default request timeout in milliseconds.
- **`fn default_header(client: Client&, name: const u8[:], val: const u8[:])`**: Sets persistent default header.
- **`fn enable_doh(client: Client&, endpoint: const u8[:] = "...", use_post: bool = true)`**: Enables RFC 8484 DNS-over-HTTPS resolution.
- **`fn close(client: Client&)`**: Closes and drains all idle and active connections in the connection pool.

### Request Model (RFC 9110)

- **`struct Request`**: Zero-copy request representation (`method`, `url`, `headers`, `query_params`, `body`, `timeout`, `cors_mode`).
- **`fn new_request() -> Request`**: Creates an empty request.
- **`fn new_get(url: const u8[:]) -> Request`**: Creates a `GET` request.
- **`fn new_post(url: const u8[:], body: const u8[:]) -> Request`**: Creates a `POST` request with payload.
- **`fn set_header(req: Request&, name: const u8[:], value: const u8[:])`**: Adds or replaces a request header.
- **`fn remove_header(req: Request&, name: const u8[:]) -> bool`**: Removes a header by name.
- **`fn bearer(req: Request&, token: const u8[:])`**: Sets RFC 6750 `Authorization: Bearer <token>` header.
- **`fn query(req: Request&, key: const u8[:], value: const u8[:]) -> bool`**: Appends a bounded URL query parameter.
- **`fn set_priority(req: Request&, urgency: i32, incremental: bool)`**: Sets RFC 9218 `Priority` header.
- **`fn sign_hmac_sha256(req: Request&, secret_key: const u8[:])`**: Signs request payload with HMAC-SHA256 (`X-Signature-256`).

### Response Model (RFC 9110)

- **`struct Response`**: HTTP response container (`status_code`, `effective_url`, `headers`, `trailers`, `body`, `elapsed_us`).
- **`res.status_code`**: Integer HTTP status code (200, 404, etc.).
- **`res.body`**: Response payload buffer (`u8[>..]`).
- **`res.is_success()`**: Helper checking if `status_code` is in 200..299 range.
- **`find_header(res.headers[..], name)`**: Case-insensitive header lookup slice.
- **`has_header(res.headers[..], name)`**: Checks if header exists.
- **`fn decode_body(res: Response&) -> bool`**: Automatically decompresses response body (`gzip`, `deflate`, `br`, `zstd`).

### Interceptors & Policies

- **`struct InterceptorPipeline`**: OkHttp-style 2-tier application and network interceptor container powered by 64-bit register bitmask dispatch (`active_mask: u64`). Stack footprint compacted from ~3.5 KB to < 450 bytes (>87% reduction) with branch-predictor-friendly macro-fused bit-test dispatch.
- **`struct RedirectPolicy`**: Redirect limits and cross-origin sensitive header sanitization rules (RFC 9110 §15.4).
- **`struct RetryPolicy`**: Exponential backoff with jitter and idempotency guards.

### Streaming Body I/O

- **`struct StreamReader`**: Bounded reader for chunked and streaming response bodies.
- **`struct StreamWriter`**: Bounded writer for streaming request payloads.

## Invariants

- **Zero allocation request framing**: Header lookups, query serialization, and URL manipulations operate exclusively on bounded stack arrays and `const u8[:]` slices.
- **Invariant 13 capacity enforcement**: Query items, headers, and trailer collections reject overflow explicitly with `guard` checks without silent truncation.
- **Sensitive header isolation**: Authorization, Cookie, and Proxy-Authorization headers are automatically stripped on cross-origin redirects (RFC 9110 §15.4).
- **Constant-time cryptographic operations**: HMAC request signatures use `core::ct_eq_bytes` to prevent timing leaks.

## Verification

- Client test suite: `python tools/test_runner.py -p "*client*"`
- Full typecheck: `python tools/test_runner.py --check-only`
- Invariant audit: `python scripts/lint_invariants.py --target-file client/request.goose --strict-examples`
