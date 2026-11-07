# `client`

Package `client` provides the zero-allocation HTTP client models, content
decompression (`gzip`, `deflate`, `br`, `zstd`, `dcb`, `dcz`), two-tier
application and network interceptor pipelines, browser TLS/HTTP2 profiles, 0-RTT
replay guards (RFC 8470), and HAR 1.2 telemetry export for `goose-wing`.

```goose
var c = new_client("https://example.com");
set_profile(c, Profile.Chrome120);
var req = new_get("/index.html");
set_header(req, "Accept", "text/html");
```

## Public API

### 1. Configuration & Lifecycle (`client/client.goose`, `client/profile.goose`)

```goose
enum Profile { Default, Chrome120, Firefox121, Safari17, Curl }
struct ClientConfig {
    base_url: u8[..512], user_agent: u8[..256], timeout_ms: i64,
    follow_redirects: bool, max_redirects: i32, verify_tls: bool,
    profile: Profile, enable_cookies: bool, enable_cache: bool,
    enable_alt_svc: bool, enable_h3: bool, proxy_url: u8[..256],
    max_response_body_size: i64, enable_ssrf_guard: bool,
    ssrf_https_only: bool, doh_endpoint_url: u8[..256]
}
struct Client { ... }
fn profile_user_agent(p: Profile) -> const u8[:]
fn profile_name(p: Profile) -> const u8[:]
fn new_client() -> Client
fn new_client(cfg: ClientConfig) -> Client
fn new_client(base_url: const u8[:]) -> Client
fn set_profile(session: Session&, profile: Profile)
fn set_timeout_ms(session: Session&, ms: i64)
fn set_proxy(session: Session&, proxy_url: const u8[:])
fn set_redirect_mode(session: Session&, mode: RedirectMode)
fn enable_doh(session: Session&, endpoint: const u8[:] = "https://cloudflare-dns.com/dns-query", use_post: bool = true)
fn enable_ech(session: Session&, auto_discover: bool = true)
fn enable_altsvc(session: Session&, enabled: bool = true)
fn enable_protocol_racing(session: Session&, enabled: bool = true, quic_delay_ms: i64 = 200)
fn enable_compression_dict(session: Session&, enabled: bool = true)
fn close(session: Session&)
```

`Client` owns the connection pool, RFC 9111 cache, cookie jar, HSTS store,
`Alt-Svc` table, and RFC 9842 compression dictionary store. `set_profile` aligns
the `User-Agent`, TLS 1.3 cipher/extension order (JA3/JA4), HTTP/2 `SETTINGS`,
and pseudo-header ordering (`:method`, `:authority`, `:scheme`, `:path`) with
the selected `Profile`. `close` is idempotent and drains all pooled transport
descriptors.

### 2. Request Model (`client/request.goose`, RFC 9110)

```goose
struct Request {
    method: u8[..16], url: u8[..2048], headers: HeaderMap,
    trailers: HeaderMap, query_params: QueryParam[..32],
    rewind_buf: u8[..4096], body: u8[>..], timeout: i64, cors_mode: bool
}
fn reset_request(req: Request&)
fn new_request(method: const u8[:], url: const u8[:]) -> Request
fn new_get(url: const u8[:]) -> Request
fn new_post(url: const u8[:]) -> Request
fn new_query(url: const u8[:], body: const u8[:], content_type: const u8[:] = "application/json") -> Request
fn set_header(req: Request&, name: const u8[:], value: const u8[:]) -> Request&
fn remove_header(req: Request&, name: const u8[:]) -> Request&
fn bearer(req: Request&, token: const u8[:]) -> Request&
fn query(req: Request&, key: const u8[:], value: const u8[:]) -> Request&
fn set_priority(req: Request&, urgency: u8, incremental: bool = false) -> Request&
fn sign_hmac_sha256(req: Request&, secret_key: const u8[:], header_name: const u8[:] = "X-Signature-256") -> Request&
```

`Request` stores up to 32 query parameters (`QueryParam[..32]`), a 2048-byte
target URL (`u8[..2048]`), and a 4096-byte `rewind_buf` used to replay bodies
across `307 Temporary Redirect` and `308 Permanent Redirect` hops without
re-allocating. Builder functions (`set_header`, `bearer`, `query`,
`set_priority`, `sign_hmac_sha256`) mutate `req` in place and return `Request&`
for method chaining.

### 3. Response Model (`client/response.goose`, RFC 9110)

```goose
struct Response {
    status_code: i32, status_text: u8[..64], headers: HeaderMap,
    trailers: HeaderMap, body: u8[>..], elapsed_ms: i64,
    redirect_count: i32, final_url: u8[..2048], from_cache: bool,
    timings: RequestTimings, protocol: u8[..16]
}
fn is_ok(resp: const Response&) -> bool
fn is_redirect(resp: const Response&) -> bool
fn find_header(resp: const Response&, name: const u8[:]) -> const u8[:]
fn has_header(resp: const Response&, name: const u8[:]) -> bool
fn decode_body(resp: Response&) -> bool
```

`is_ok` returns `true` for status codes in `200..299`, and `is_redirect` matches
`301`, `302`, `303`, `307`, and `308`. `decode_body` inspects `Content-Encoding`
(`gzip`, `deflate`, `br`, `zstd`, `dcb`, `dcz`), replaces `resp.body` with the
decompressed payload in place, and returns `false` if decompression fails or
exceeds configured bomb limits.

### 4. Interceptors, Redirects, Backoff & Rate Limiting (`client/interceptor.goose`, `client/redirect.goose`, `client/policy.goose`)

```goose
struct InterceptorPipeline { active_mask: u64, ... }
struct InterceptorEntry { ... }
enum InterceptorScope { Application, Network }
enum LogLevel { None, Basic, Headers, Body }
enum RedirectMode { Follow, Manual, Error }
enum ReferrerPolicy {
    NoReferrer, NoReferrerWhenDowngrade, Origin, OriginWhenCrossOrigin,
    SameOrigin, StrictOrigin, StrictOriginWhenCrossOrigin, UnsafeUrl
}
enum RedirectError {
    None, MaxRedirectsExceeded, LoopDetected, MissingLocationHeader,
    HttpsToHttpDowngradeBlocked, RedirectModeError
}
struct RedirectOptions {
    mode: RedirectMode, referrer_policy: ReferrerPolicy, max_redirects: i32,
    strict_301_302_post_to_get: bool, block_https_to_http_downgrade: bool,
    strip_sensitive_headers_on_cross_origin: bool
}
struct RedirectInfo {
    should_redirect: bool, new_method: u8[..16], target_url: u8[..2048],
    is_cross_origin: bool, preserve_body: bool
}
struct Backoff { base_delay_ms: i64, max_delay_ms: i64, factor: i64, jitter: bool }
struct RateLimiter { tokens: f64, capacity: f64, refill_rate_per_ms: f64, last_ms: i64 }
fn add_interceptor(pipeline: InterceptorPipeline&, entry: InterceptorEntry) -> bool
fn add_header(pipeline: InterceptorPipeline&, scope: InterceptorScope, name: const u8[:], val: const u8[:]) -> bool
fn add_logging(pipeline: InterceptorPipeline&, scope: InterceptorScope, level: LogLevel) -> bool
fn add_bearer_auth(pipeline: InterceptorPipeline&, token: const u8[:]) -> bool
fn add_request_id(pipeline: InterceptorPipeline&, prefix: const u8[:] = "req-") -> bool
fn add_traceparent(pipeline: InterceptorPipeline&, sample_flag: const u8[:] = "01") -> bool
fn add_retry(pipeline: InterceptorPipeline&, max_retries: i32 = 3, retry_on_5xx: bool = true) -> bool
fn compute_redirect_info(status_code: i32, req_method: const u8[:], location_header: const u8[:], current_url: const u8[:]) -> RedirectInfo
fn sanitize_headers_on_redirect(req: Request&)
fn new_backoff(base_delay_ms: i64, max_delay_ms: i64, factor: i64 = 2, jitter: bool = true) -> Backoff
fn delay(b: const Backoff&, attempt: i32, rng_seed: u64 = 0) -> i64
fn new_rate_limiter(rate_per_sec: f64, burst: f64) -> RateLimiter
fn allow(rl: RateLimiter&, now_ms: i64, tokens: f64 = 1.0) -> bool
```

`InterceptorPipeline` dispatches up to 64 application and network interceptors
gated by `active_mask`. `compute_redirect_info` implements RFC 9110 §15.4 method
rewriting (`POST` -> `GET` on `301`/`302`/`303`, method and body preservation on
`307`/`308`), while `sanitize_headers_on_redirect` strips `Authorization`,
`Cookie`, and `Proxy-Authorization` across cross-origin hops.

### 5. 0-RTT Early Data Replay Guard (`client/replay_guard.goose`, RFC 8470)

```goose
enum EarlyDataDecision { Allowed0Rtt, DeferTo1Rtt, RetryOn1Rtt }
fn evaluate_early_data_request(method: const u8[:], allow_early_data_flag: bool) -> EarlyDataDecision
fn evaluate_early_data_response(status_code: i32, was_sent_in_early_data: bool) -> EarlyDataDecision
fn append_early_data_header(req: Request&, handshake_complete: bool)
```

Enforces RFC 8470 0-RTT anti-replay rules: `evaluate_early_data_request`
restricts TLS 1.3 / QUIC 0-RTT transmission to safe idempotent methods (`GET`,
`HEAD`, `OPTIONS`, `TRACE`), `append_early_data_header` attaches `Early-Data: 1`
when the handshake is not yet complete, and `evaluate_early_data_response`
triggers a transparent 1-RTT retry (`RetryOn1Rtt`) on `425 Too Early`.

### 6. Streaming Body I/O (`client/stream.goose`)

```goose
struct ChunkWriter { trailers: HeaderMap, finished: bool, buffer: u8[>..] }
enum ChunkedStreamState { ChunkSizeLine, ChunkData, ChunkDataCrlf, Trailers, Complete, Error }
struct ChunkedStreamDecoder { ... }
enum StreamReadStatus { Data, Eof, Error }
struct StreamProgress { bytes_processed: u64, total_bytes: i64, percent: f64, is_finished: bool }
struct StreamReader { ... }
struct ArenaSink { max_bytes: i64 }
fn write_chunk(writer: ChunkWriter&, data: const u8[:])
fn add_trailer(writer: ChunkWriter&, name: const u8[:], val: const u8[:]) -> bool
fn finish_chunk_writer(writer: ChunkWriter&)
fn feed_chunked_stream<B>(dec: ChunkedStreamDecoder&, input: const u8[:], out_body: B&, max_emit: i64 = -1) -> bool, i64
fn new_stream_reader(resp: const Response&) -> StreamReader
fn read_chunk<B>(reader: StreamReader&, max_bytes: i64, out: B&) -> StreamReadStatus, bool
fn read_all<B>(reader: StreamReader&, out: B&) -> u64
fn trailer(reader: const StreamReader&, name: const u8[:]) -> const u8[:]
fn stream_progress(reader: const StreamReader&) -> StreamProgress
fn pump_chunk_fsm<Sink, B>(dec: internal::ChunkFsmDecoder&, wire: const u8[:], sink: Sink, out: B&) -> internal::ChunkFsmStatus, i64
```

`ChunkWriter` frames outbound RFC 9112 §7.1 chunked bodies with up to 16
trailing header fields (`HeaderField[..16]`) emitted by `finish_chunk_writer`.
`ChunkedStreamDecoder` parses inbound chunked streams incrementally via
`feed_chunked_stream` or `pump_chunk_fsm`, rejecting malformed hex lengths or
missing CRLF terminators with `false`.

### 7. Request Timings & HAR 1.2 Telemetry (`client/telemetry.goose`)

```goose
struct RequestTimings {
    blocked_us: i64, dns_us: i64, connect_us: i64, tls_us: i64,
    send_us: i64, wait_us: i64, receive_us: i64, total_us: i64, ttfb_us: i64
}
struct HarEntry { ... }
fn compute_total_timing_us(t: RequestTimings&)
fn format_us_as_ms<B>(us: i64, out: B&)
fn serialize_har_entry_json<B>(entry: const HarEntry&, out: B&)
```

`compute_total_timing_us` sums microsecond phase durations into `total_us` and
calculates time-to-first-byte (`ttfb_us`), while `serialize_har_entry_json`
exports request, response, and timing breakdowns as a HAR 1.2 JSON object.

## Verification

Run the client test suite and full typecheck with:

```bash
python tools/test_runner.py -p "*client*"
python tools/test_runner.py --check-only
```
