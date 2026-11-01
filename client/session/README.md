# `client/session`

## Overview
Stateful HTTP session execution engine orchestrating the 6-phase pipeline (Interceptors -> Cache -> Redirects -> L4/L7 Transport -> Cookies -> Response), RFC 6265bis cookie jar integration, convenience HTTP verbs, and SSRF security perimeter.

## Public API

### Session Lifecycle
- **`type Session = Client;`**: Stateful session facade representing an ongoing browsing or API session.
- **`type SessionConfig = ClientConfig;`**: Session configuration container.
- **`fn new_session() -> Session`**: Creates a stateful session with default cookie jar, redirect engine, and connection pool.
- **`fn new_session(cfg: SessionConfig) -> Session`**: Creates a session configured with explicit cache, proxy, and timeout options.
- **`fn new_session(base_url: const u8[:]) -> Session`**: Creates a session with a base target URL.

### Core Pipeline Execution
- **`fn do(session: Session&, req: Request&) -> Response, Error`**: Executes a request through the full 6-phase pipeline:
  1. *Application Interceptors*: Mutates requests or short-circuits execution.
  2. *RFC 9111 HTTP Cache*: Returns cached response or sets conditional validation headers (`If-None-Match`, `If-Modified-Since`).
  3. *Redirect Engine*: Tracks hops, detects loops, and strips sensitive headers on cross-origin navigation.
  4. *Network Transport*: Dispatches wire transmission over HTTP/1.1, HTTP/2, or HTTP/3 connection pools.
  5. *RFC 6265bis Cookie Bridge*: Ingests `Set-Cookie` directives into the session's `CanonicalCookieJar`.
  6. *Network Interceptors & Telemetry*: Measures latency and records wire metrics.

### Convenience HTTP Verbs
- **`fn get(session: Session&, url: const u8[:]) -> Response, Error`**: Dispatches a `GET` request.
- **`fn post(session: Session&, url: const u8[:], body: const u8[:]) -> Response, Error`**: Dispatches a `POST` request.
- **`fn put(session: Session&, url: const u8[:], body: const u8[:]) -> Response, Error`**: Dispatches a `PUT` request.
- **`fn delete(session: Session&, url: const u8[:]) -> Response, Error`**: Dispatches a `DELETE` request.
- **`fn patch(session: Session&, url: const u8[:], body: const u8[:]) -> Response, Error`**: Dispatches a `PATCH` request.
- **`fn head(session: Session&, url: const u8[:]) -> Response, Error`**: Dispatches a `HEAD` request.
- **`fn download_stream<F: fn(const StreamProgress&)>(session: Session&, url: const u8[:], chunk_size: i64, out_body: u8[>..]&) -> Response, Error`**: Streams a response body to an output sink while invoking a progress callback.

### Security & Testing
- **`struct SsrfGuardPolicy`**: SSRF perimeter rules blocking private IPv4 (RFC 1918), CGNAT (RFC 6598), loopback, link-local (RFC 3927), cloud metadata endpoints, and dangerous ports.
- **`fn set_ssrf_policy(session: Session&, policy: SsrfGuardPolicy)`**: Configures session SSRF protection.
- **`fn add_mock_response(session: Session&, method: const u8[:], url: const u8[:], status: i32, body: const u8[:])`**: Registers deterministic offline mock responses for integration testing.

## Invariants
- **Body rewind on redirect**: On 307 (Temporary Redirect) and 308 (Permanent Redirect), request bodies are restored from `rewind_buf` to preserve payload integrity (RFC 9110 §15.4.8).
- **Schemeful Same-Site cookie isolation**: Cookies are segregated according to RFC 6265bis schemeful same-site rules to prevent cross-site leakage across plain HTTP and HTTPS.
- **SSRF defense in depth**: Validates both the raw target URL hostname and all resolved IP addresses before socket connection to prevent DNS rebinding attacks.

## Verification
- Client session suite: `python tools/test_runner.py -p "*client*"`
- Full typecheck: `python tools/test_runner.py --check-only`
- Invariant audit: `python scripts/lint_invariants.py --target-file client/session/exec.goose --strict-examples`
