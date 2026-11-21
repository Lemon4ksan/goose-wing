# `client`

Package `client` (`namespace client;`, internal helpers in
`namespace client_internal;`) provides the zero-allocation HTTP client models,
content decompression (`gzip`, `deflate`, `br`, `zstd`, `dcb`, `dcz`), two-tier
application and network interceptor pipelines, configurable TLS/HTTP2 client
profiles, 0-RTT replay guards (RFC 8470), chunked streaming I/O, typed endpoint
contracts, and HAR 1.2 telemetry export for `goose-wing`.

```goose
var c = client::new_client("https://example.com");
c.set_profile(fingerprint::Profile.Wing);
var req = wing::new_request("GET", "/index.html");
req.set_header("Accept", "text/html");
```

## Public API

### 1. Configuration and lifecycle (`client/client.goose`)

```goose
struct Config {
    base_url: const u8[:], profile: fingerprint::Profile,
    proxy_url: const u8[:], timeout_ms: i64, follow_redirects: bool,
    cookie_jar: bool, enable_cache: bool, cache_options: wing::CacheOptions,
    enable_altsvc: bool, enable_protocol_racing: bool,
    quic_race_delay_ms: i64, enable_compression_dict: bool,
    strict_content_decoding: bool, insecure_skip_verify: bool,
    tls_backend: tls::TlsBackendKind, tls_min_version: tls::TlsMinVersion,
    tls_ca_file: const u8[:], sig_key_id: const u8[:],
    sig_private_key: const u8[:], sig_public_key: const u8[:],
}
type SessionConfig = Config;
struct Credentials { ... }
struct DpopState { ... }
struct Client { ... }
type Session = Client;

fn new_client() -> Client
fn new_client(cfg: Config) -> Client
fn new_client(base_url: const u8[:]) -> Client
fn new_session() -> Client
fn new_session(cfg: Config) -> Client
fn new_session(base_url: const u8[:]) -> Client
fn set_base_url(session: Session&, url: const u8[:])
fn set_profile(session: Session&, profile: fingerprint::Profile)
fn set_profile(session: Session&, profile: const fingerprint::ClientProfile&)
fn set_user_agent(session: Session&, ua: const u8[:])
fn user_agent(session: const Session&) -> const u8[:]
fn set_timeout_ms(session: Session&, ms: i64)
fn set_proxy(session: Session&, proxy_url: const u8[:])
fn set_redirect_mode(session: Session&, mode: RedirectMode)
fn enable_doh(session: Session&, endpoint: const u8[:] = "https://cloudflare-dns.com/dns-query", use_post: bool = true)
fn enable_ech(session: Session&, auto_discover: bool = true)
fn enable_altsvc(session: Session&, enabled: bool = true)
fn enable_protocol_racing(session: Session&, enabled: bool = true, quic_delay_ms: i64 = 200)
fn enable_compression_dict(session: Session&, enabled: bool = true)
fn enable_hsts(session: Session&, enabled: bool = true)
fn set_credentials(session: Session&, username: const u8[:], password: const u8[:]) -> bool
fn set_dpop_credentials(session: Session&, private_key: const u8[32]&, token: const u8[:] = "") -> bool
fn set_http_signature_keys(session: Session&, key_id: const u8[:], private_key: const u8[:], public_key: const u8[:] = "") -> bool
fn load_trust_anchors_pem_file(sess: Session&, path: const u8[:]) -> i64, bool
fn configure_session_tls_ca_pem(sess: Session&, pem_bundle: const u8[:], allow_loopback: bool = false) -> i64, bool
fn set_tls_backend(session: Session&, kind: tls::TlsBackendKind)
fn set_tls_min_version(session: Session&, ver: tls::TlsMinVersion)
fn set_tls_ca_file(session: Session&, path: const u8[:]) -> bool
fn lookup_cached_ech_config(dns_cache: const dns::Cache&, domain: const u8[:], now_sec: i64) -> u8[..512], bool
fn resolve_ech_config(session: Session&, domain: const u8[:], now_sec: i64) -> u8[..512], bool
fn attach_dictionary_request_headers(session: const Session&, origin: const u8[:], url_path: const u8[:], req: wing::Request&) -> bool
fn process_dictionary_response<B>(session: Session&, origin: const u8[:], use_as_dict_hdr: const u8[:], content_encoding: const u8[:], raw_body: const u8[:], out: B&) -> bool
fn close(session: Session&)
```

`Client` (`Session`) owns the connection pool, RFC 9111 cache, cookie jar, HSTS
store, `Alt-Svc` table, and RFC 9842 compression dictionary store. `set_profile`
aligns the `User-Agent`, TLS 1.3 cipher/extension order (JA3/JA4), HTTP/2
`SETTINGS`, and pseudo-header ordering (`:method`, `:authority`, `:scheme`,
`:path`) with the selected `fingerprint::Profile`. When `enable_protocol_racing`
is active against a direct HTTP/3 UDP endpoint (`serve_h3`),
`execute_live_h3_hop` does an unencrypted H3 over UDP (datagram direct) exchange
using RFC 9114 framing and QPACK; full encrypted QUIC v1 + TLS 1.3 sessions use
`quic::Connection` and `http3::Connection`. `tls_backend` defaults to
`tls::TlsBackendKind.PureGoose` with `tls::TlsMinVersion.Tls13`, keeping the
native TLS 1.3 fast path unchanged; selecting `SystemOpenSsl`, `SystemSchannel`,
`SystemSecureTransport`, or `Auto` opens a `net::Transport.TlsBackend` channel
with automatic `h2` / `http/1.1` ALPN dispatch. `close` is idempotent and drains
all pooled transport descriptors.

### 2. Interceptors, redirects, backoff, and rate limiting (`client/interceptor.goose`, `client/redirect.goose`, `client/policy.goose`)

```goose
struct RetryPolicy { max_retries: i32, retry_on_5xx: bool }
struct InterceptorPipeline { active_mask: u64, ... }
struct InterceptorEntry { ... }
enum InterceptorScope { Application, Network }
enum InterceptorKind { None, Logging, AuthBearer, Header, RequestId, Traceparent, RetryPolicy, Metrics }
enum LogLevel { None, Basic, Headers, Body }
enum RedirectMode { Follow, Manual, Error }
enum ReferrerPolicy {
    NoReferrer, NoReferrerWhenDowngrade, Origin, OriginWhenCrossOrigin,
    SameOrigin, StrictOrigin, StrictOriginWhenCrossOrigin, UnsafeUrl
}
enum RedirectError {
    None, MissingLocation, MultipleLocationHeaders, InvalidLocationUrl,
    ForbiddenRedirectScheme, CorsCredentialsInRedirectUrl,
    SchemeDowngradeBlocked, TooManyRedirects, RedirectBlockedByPolicy,
    CannotRewindBody, SsrfBlockedUrl, SsrfBlockedIp
}
struct RedirectOptions { ... }
struct RedirectSanitizeOptions { ... }
struct RedirectInfo { ... }
struct Backoff { base_ns: i64, max_ns: i64, factor: f64 }
struct RateLimiter { rate_per_sec: f64, burst_capacity: f64, tokens: f64, last_update_mono_ns: i64 }

fn add_interceptor(pipeline: InterceptorPipeline&, entry: InterceptorEntry) -> bool
fn add_header(pipeline: InterceptorPipeline&, scope: InterceptorScope, name: const u8[:], val: const u8[:]) -> bool
fn add_logging(pipeline: InterceptorPipeline&, scope: InterceptorScope, level: LogLevel) -> bool
fn add_bearer_auth(pipeline: InterceptorPipeline&, token: const u8[:]) -> bool
fn add_request_id(pipeline: InterceptorPipeline&, prefix: const u8[:] = "req-") -> bool
fn add_traceparent(pipeline: InterceptorPipeline&, sample_flag: const u8[:] = "01") -> bool
fn add_retry(pipeline: InterceptorPipeline&, max_retries: i32, retry_on_5xx: bool = true) -> bool
fn add_metrics(pipeline: InterceptorPipeline&) -> bool
fn find_retry_policy(pipeline: const InterceptorPipeline&) -> RetryPolicy, bool
fn parse_referrer_policy_with_fallback(val: const u8[:], fallback: ReferrerPolicy) -> ReferrerPolicy
fn compute_redirect_info(current_method: const u8[:], status_code: i32, current_url_str: const u8[:], location_header: const u8[:], current_referrer_policy: ReferrerPolicy, current_referrer: const u8[:], options: RedirectOptions = RedirectOptions { .. }) -> RedirectInfo
fn sanitize_headers_on_redirect(headers: wing::HeaderMap&, redirect_info: const RedirectInfo&, options: RedirectSanitizeOptions = RedirectSanitizeOptions { .. })
fn record_redirect_hop_cache_headers(taint: RedirectHopCacheTaint&, hop_headers: const wing::HeaderMap&)
fn apply_custom_redirect_strip(headers: wing::HeaderMap&, is_cross_origin: bool, policy: const CustomRedirectStripPolicy&)
fn new_backoff(base_ns: i64, max_ns: i64, factor: f64 = 2.0) -> Backoff
fn delay(backoff: const Backoff&, attempt: i64) -> i64
fn new_rate_limiter(rate_per_sec: f64, burst: i64) -> RateLimiter
fn allow(limiter: RateLimiter&, now_mono: i64) -> bool
fn allow(limiter: RateLimiter&) -> bool
```

`InterceptorPipeline` dispatches application and network interceptors gated by
`active_mask`. `compute_redirect_info` implements RFC 9110 Section 15.4 method
rewriting (`POST` -> `GET` on `301`/`302`/`303`, method and body preservation on
`307`/`308`), while `sanitize_headers_on_redirect` strips `Authorization`,
`Cookie`, `DPoP`, `Signature`, and `Proxy-Authorization` across cross-origin
hops.

### 3. 0-RTT early data replay guard (`client/replay_guard.goose`, RFC 8470)

```goose
enum EarlyDataDecision { Allow, RejectMutating, RetryOn1Rtt }
fn evaluate_early_data_request(method: const u8[:], allow_mutating_override: bool = false) -> EarlyDataDecision
fn evaluate_early_data_response(status_code: u16, was_sent_early: bool) -> EarlyDataDecision
fn append_early_data_header<B>(out: B&) -> bool
```

Enforces RFC 8470 0-RTT anti-replay rules: `evaluate_early_data_request`
restricts TLS 1.3 / QUIC 0-RTT transmission to safe idempotent methods (`GET`,
`HEAD`, `OPTIONS`, `TRACE`), `append_early_data_header` appends `Early-Data: 1`
with capacity validation, and `evaluate_early_data_response` triggers a 1-RTT
retry (`RetryOn1Rtt`) on `425 Too Early`.

### 4. Streaming body I/O (`client/stream.goose`)

```goose
struct ChunkWriter { trailers: wing::HeaderMap, finished: bool, buffer: u8[>..] }
enum ChunkedStreamState { ChunkSizeLine, ChunkData, ChunkDataCrlf, Trailers, Complete, Error }
struct ChunkedStreamDecoder { ... }
enum StreamReadStatus { Data, Eof, Error }
struct StreamProgress { bytes_processed: u64, total_bytes: i64, percent: f64, is_finished: bool }
struct StreamReader { ... }

fn encode_chunk<B>(data: const u8[:], out: B&) -> bool
fn encode_chunk_end<B>(out: B&) -> bool
fn encode_chunk_trailer<B>(name: const u8[:], val: const u8[:], out: B&) -> bool
fn encode_chunked_payload<B>(body: const u8[:], trailers: const wing::HeaderMap&, chunk_size: i64, out: B&) -> bool
fn write_chunk(writer: ChunkWriter&, data: const u8[:])
fn add_trailer(writer: ChunkWriter&, name: const u8[:], val: const u8[:]) -> bool
fn finish_chunk_writer(writer: ChunkWriter&)
fn is_complete(dec: const ChunkedStreamDecoder&) -> bool
fn has_error(dec: const ChunkedStreamDecoder&) -> bool
fn feed_chunked_stream<B>(dec: ChunkedStreamDecoder&, input: const u8[:], out: B&, max_emit: i64 = -1) -> i64, bool
fn parse_content_length_value(cl: const u8[:]) -> i64, bool
fn new_stream_reader(resp: const wing::Response&) -> StreamReader
fn read_chunk<B>(reader: StreamReader&, max_bytes: i64, out: B&) -> StreamReadStatus, bool
fn read_all<B>(reader: StreamReader&, out: B&) -> u64
fn trailer(reader: const StreamReader&, name: const u8[:]) -> const u8[:]
fn copy_trailers_to_response(reader: const StreamReader&, resp: wing::Response&)
fn stream_progress(reader: const StreamReader&) -> StreamProgress
```

`ChunkWriter` frames outbound RFC 9112 Section 7.1 chunked bodies with up to 16
trailing header fields emitted by `finish_chunk_writer`. `ChunkedStreamDecoder`
parses inbound chunked streams incrementally via `feed_chunked_stream`
(returning `(consumed, ok)` and rolling back `out` on framing error).

### 5. Typed endpoint contracts and HAR 1.2 telemetry (`client/contract.goose`, `client/telemetry.goose`)

```goose
struct EmptyPart {}
struct EndpointSpec<Params, Query, ReqBody, ResBody> { method: u8[..16], path_template: u8[..256] }
struct RequestTimings {
    blocked_us: i64, dns_us: i64, connect_us: i64, ssl_us: i64,
    send_us: i64, wait_us: i64, receive_us: i64,
}
struct HarEntry { ... }

fn type_is_non_empty<T>() -> bool
fn build_contract_request<Params, Query, ReqBody, ResBody>(spec: const EndpointSpec<Params, Query, ReqBody, ResBody>&, base_url: const u8[:], params: const Params&, query_dto: const Query&, body_dto: const ReqBody&, out_req: wing::Request&) -> bool
fn call_endpoint<Params, Query, ReqBody, ResBody>(c: Client&, spec: const EndpointSpec<Params, Query, ReqBody, ResBody>&, base_url: const u8[:], params: const Params&, query_dto: const Query&, body_dto: const ReqBody&) -> ResBody, wing::Response, wing::Error
fn compute_total_timing_us(t: const RequestTimings&) -> i64
fn serialize_har_entry_json<B>(entry: const HarEntry&, out: B&)
```

`compute_total_timing_us` sums microsecond phase durations with saturating
addition, while `serialize_har_entry_json` exports request, response, and timing
breakdowns as a HAR 1.2 JSON object.

## Verification

Run the client test suite and full typecheck with:

```bash
python tools/test_runner.py -p "*client*"
python tools/test_runner.py --check-only
```
