# `client`

Package `client` (`namespace client;`) provides the HTTP/1.1, HTTP/2, and HTTP/3
client session facade, TLS and proxy controls, SSRF and DNS-rebinding defenses,
interceptors, redirect handling, 0-RTT replay checks (RFC 8470), chunked
streaming I/O, typed endpoint contracts, and HAR 1.2 telemetry export.

Internal hop, framing, and stage helpers live in `namespace client_internal;`.

## Quick start

```goose
import wing;

var c = client::new_client("https://api.example.com");
defer c.close();

let resp, err = c.get("/v1/health");
if http::ok(err) && resp.status_code == 200 {
    print("body:", resp.body[..]);
}
```

## Task recipes

### GET and POST JSON

Use `get`, `post`, `put`, `delete`, or `query` on a `Client` (`Session`).
Trailing blocks receive `req: http::Request&` for headers, query parameters, and
request bodies.

```goose
var c = client::new_client("https://api.example.com");
defer c.close();

let resp, err = c.post("/v1/items") { req =>
    req.set_header("Content-Type", "application/json");
    req.set_header("Accept", "application/json");
    req.body.append("{\"name\":\"widget\"}");
};
```

### Timeouts, retries, proxies, and IP family

Configure split timeouts (`connect_timeout_ms`, `tls_handshake_timeout_ms`,
`read_timeout_ms`, `pool_idle_timeout_ms`), automatic retries, proxy bypasses,
static host overrides, and response body limits through `Config` or setter
methods.

```goose
var c = client::new_client(client::Config {
    base_url:                 "https://api.example.com",
    timeout_ms:               15000,
    connect_timeout_ms:       3000,
    tls_handshake_timeout_ms: 4000,
    read_timeout_ms:          8000,
    pool_idle_timeout_ms:     60000,
    max_retries:              2,
    ip_family:                net::IpFamily.Ipv4Only,
    use_env_proxy:            true,
    max_response_body_bytes:  4194304,
    ..
});
defer c.close();

let _ = c.set_proxy("http://127.0.0.1:8080");
let _ = c.add_no_proxy(".internal.local");
let _ = c.add_resolve_override("api.example.com", 443, "203.0.113.10");
```

### TLS, mTLS, CA bundles, and SSRF defense

By default, `Client` uses the native TLS 1.3 stack (`PureGoose`) and blocks
loopback, link-local, private, and cloud-metadata IP ranges after DNS resolution
before dialing. Load a custom CA bundle, client mTLS credentials, or CRL file,
or switch to an OS TLS backend as needed.

```goose
var c = client::new_client("https://mtls.example.com");
defer c.close();

let _, ok_ca = c.load_trust_anchors_pem_file("certs/ca.pem");
let _ = c.set_tls_client_cert("certs/client.pem", "certs/client.key");
let _ = c.set_tls_crl_file("certs/revoked.crl.pem");
c.set_tls_require_ocsp_stapling(true);
let _ = c.allow_port(443);
let _ = c.deny_port(25);
```

### Streaming downloads and chunked uploads

Stream large request bodies with `post_chunked` (RFC 9112 Section 7.1) and track
download progress incrementally with `download_stream`.

```goose
var c = client::new_client("https://files.example.com");
defer c.close();

let up_resp, up_err = c.post_chunked("/upload") { writer =>
    writer.write_chunk("first part ");
    writer.write_chunk("second part");
    let _ = writer.add_trailer("X-Checksum", "sha256:...");
};

var body: u8[>..] = [];
let dl_resp, dl_err = c.download_stream("/archive.bin", 16384, body) { prog =>
    print("bytes:", prog.bytes_processed, "done:", prog.is_finished);
};
```

### WebSocket, SSE, and MASQUE tunnels

Upgrade directly from a `Client` to RFC 6455 WebSocket sessions, W3C Server-Sent
Events streams, or RFC 9298 / RFC 9484 MASQUE tunnels.

```goose
var c = client::new_client("https://realtime.example.com");
defer c.close();

let ws_sess, ws_resp, ws_err = c.ws("/socket") { req =>
    req.set_header("Sec-WebSocket-Protocol", "chat");
};
let sse_sub, sse_resp, sse_err = c.sse("/events");
let udp_tun, udp_resp, udp_err = c.connect_udp(
    "https://proxy.example.com/.well-known/masque/udp/{target_host}/{target_port}/",
    "198.51.100.4",
    443,
);
```

## Public API

### Client lifecycle and core configuration (`client/client.goose`)

Create, configure, and close `Client` (`Session`) instances owning a connection
pool, RFC 9111 cache, cookie jar, HSTS store, `Alt-Svc` table, and compression
dictionary cache.

```goose
struct Config { ... }
type SessionConfig = Config;
struct Client { ... }
type Session = Client;

fn new_client() -> Client
fn new_client(cfg: Config) -> Client
fn new_client(base_url: const u8[:]) -> Client
fn new_session() -> Client
fn new_session(cfg: Config) -> Client
fn new_session(base_url: const u8[:]) -> Client
fn close(session: Session&)

fn set_base_url(session: Session&, url: const u8[:])
fn set_profile(session: Session&, profile: fingerprint::Profile)
fn set_user_agent(session: Session&, ua: const u8[:])
fn set_timeout_ms(session: Session&, ms: i64)
fn set_redirect_mode(session: Session&, mode: RedirectMode)
fn set_auto_decompress(session: Session&, enabled: bool)
fn set_max_response_body_bytes(session: Session&, max_bytes: i64)
fn default_header(session: Session&, name: const u8[:], value: const u8[:])
fn set_cookie(session: Session&, name: const u8[:], value: const u8[:])
fn cookie(session: const Session&, name: const u8[:]) -> const u8[:]
```

### TLS, proxies, DNS, and security controls (`client/client.goose`)

Configure TLS backends, trust anchors, mTLS credentials, ALPN, revocation
checks, proxies, static IP overrides, HSTS, and SSRF port rules on a session.

```goose
fn load_trust_anchors_pem_file(sess: Session&, path: const u8[:]) -> i64, bool
fn configure_session_tls_ca_pem(sess: Session&, pem_bundle: const u8[:], allow_loopback: bool = false) -> i64, bool
fn set_tls_backend(session: Session&, kind: tls::TlsBackendKind)
fn set_tls_min_version(session: Session&, ver: tls::TlsMinVersion)
fn set_tls_ca_file(session: Session&, path: const u8[:]) -> bool
fn set_tls_use_system_roots(session: Session&, enabled: bool)
fn set_tls_client_cert(session: Session&, cert_file: const u8[:], key_file: const u8[:]) -> bool
fn set_tls_alpn(session: Session&, alpn_csv: const u8[:]) -> bool
fn set_tls_enable_pq_hybrid(session: Session&, enabled: bool)
fn set_tls_enable_session_tickets(session: Session&, enabled: bool)
fn set_tls_require_ocsp_stapling(session: Session&, required: bool)
fn set_tls_crl_file(session: Session&, path: const u8[:]) -> bool
fn set_tls_keylog_file(session: Session&, path: const u8[:]) -> bool

fn set_proxy(session: Session&, proxy_url: const u8[:]) -> bool
fn add_no_proxy(session: Session&, pattern: const u8[:]) -> bool
fn is_no_proxy_host(session: const Session&, host: const u8[:]) -> bool
fn set_ip_family(session: Session&, family: net::IpFamily)
fn add_resolve_override(session: Session&, host: const u8[:], port: u16, ip: const u8[:]) -> bool

fn allow_port(session: Session&, port_num: i32) -> bool
fn deny_port(session: Session&, port_num: i32) -> bool
fn enable_hsts(session: Session&, enabled: bool = true)
fn is_hsts(session: const Session&, hostname: const u8[:]) -> bool
```

### Protocols, authentication, and offline mocks (`client/client.goose`)

Toggle DoH/ECH/Alt-Svc/HTTP3 racing and compression dictionaries, configure
Digest/Basic/DPoP/RFC 9421 credentials, and register mock routes for tests.

```goose
fn enable_doh(session: Session&, endpoint: const u8[:] = "https://cloudflare-dns.com/dns-query", use_post: bool = true)
fn enable_ech(session: Session&, auto_discover: bool = true)
fn resolve_ech_config(session: Session&, domain: const u8[:], now_sec: i64) -> u8[..512], bool
fn enable_altsvc(session: Session&, enabled: bool = true)
fn enable_protocol_racing(session: Session&, enabled: bool = true, quic_delay_ms: i64 = 200)
fn enable_compression_dict(session: Session&, enabled: bool = true)

fn set_credentials(session: Session&, username: const u8[:], password: const u8[:]) -> bool
fn set_dpop_credentials(session: Session&, private_key: const u8[32]&, token: const u8[:] = "") -> bool
fn set_http_signature_keys(session: Session&, key_id: const u8[:], private_key: const u8[:], public_key: const u8[:] = "") -> bool

fn mock_route(session: Session&, method: const u8[:], pattern_url: const u8[:], status_code: i32, body_str: const u8[:]) -> MockExchange&
fn add_mock_header(session: Session&, name: const u8[:], value: const u8[:])
fn add_mock_set_cookie(session: Session&, set_cookie_raw: const u8[:])
fn add_mock_resolved_ip(session: Session&, ip_str: const u8[:])
fn set_mock_quic_blocked(session: Session&, blocked: bool = true)
fn add_mock_websocket(session: Session&, url_pattern: const u8[:], subprotocol: const u8[:] = "")
fn add_mock_sse(session: Session&, url_pattern: const u8[:], sample_events: const u8[:] = "")
```

### Interceptors, redirects, backoff, and rate limiting

Configure two-tier interceptors, RFC 9110 redirect policy, exponential backoff,
and token-bucket rate limiting (`client/interceptor.goose`,
`client/redirect.goose`, `client/policy.goose`).

```goose
enum InterceptorScope { Application, Network }
enum LogLevel { None, Basic, Headers, Body }
enum RedirectMode { Follow, Manual, Error }
enum ReferrerPolicy { ... }
enum RedirectError { ... }
struct Backoff { base_ns: i64, max_ns: i64, factor: f64 }
struct RateLimiter { rate_per_sec: f64, burst_capacity: f64, tokens: f64, last_update_mono_ns: i64 }

fn add_header(pipeline: InterceptorPipeline&, scope: InterceptorScope, name: const u8[:], val: const u8[:]) -> bool
fn add_logging(pipeline: InterceptorPipeline&, scope: InterceptorScope, level: LogLevel) -> bool
fn add_bearer_auth(pipeline: InterceptorPipeline&, token: const u8[:]) -> bool
fn add_request_id(pipeline: InterceptorPipeline&, prefix: const u8[:] = "req-") -> bool
fn add_traceparent(pipeline: InterceptorPipeline&, sample_flag: const u8[:] = "01") -> bool
fn add_retry(pipeline: InterceptorPipeline&, max_retries: i32, retry_on_5xx: bool = true) -> bool
fn add_metrics(pipeline: InterceptorPipeline&) -> bool
fn new_backoff(base_ns: i64, max_ns: i64, factor: f64 = 2.0) -> Backoff
fn delay(backoff: const Backoff&, attempt: i64) -> i64
fn new_rate_limiter(rate_per_sec: f64, burst: i64) -> RateLimiter
fn allow(limiter: RateLimiter&, now_mono: i64) -> bool
```

### 0-RTT early data, streaming body I/O, contracts, and HAR telemetry

Check RFC 8470 0-RTT safety (`client/replay_guard.goose`), stream chunked bodies
(`client/stream.goose`), call typed JSON contracts (`client/contract.goose`),
and serialize HAR 1.2 entries (`client/telemetry.goose`).

```goose
enum EarlyDataDecision { Allow, RejectMutating, RetryOn1Rtt }
struct ChunkWriter { ... }
struct StreamProgress { bytes_processed: u64, total_bytes: i64, percent: f64, is_finished: bool }
struct StreamReader { ... }
struct EndpointSpec<Params, Query, ReqBody, ResBody> { method: u8[..16], path_template: u8[..256] }
struct HarEntry { ... }

fn evaluate_early_data_request(method: const u8[:], allow_mutating_override: bool = false) -> EarlyDataDecision
fn evaluate_early_data_response(status_code: u16, was_sent_early: bool) -> EarlyDataDecision
fn write_chunk(writer: ChunkWriter&, data: const u8[:])
fn add_trailer(writer: ChunkWriter&, name: const u8[:], val: const u8[:]) -> bool
fn finish_chunk_writer(writer: ChunkWriter&)
fn new_stream_reader(resp: const http::Response&) -> StreamReader
fn read_chunk<B>(reader: StreamReader&, max_bytes: i64, out: B&) -> StreamReadStatus, bool
fn read_all<B>(reader: StreamReader&, out: B&) -> u64
fn stream_progress(reader: const StreamReader&) -> StreamProgress
fn call_endpoint<Params, Query, ReqBody, ResBody>(c: Client&, spec: const EndpointSpec<Params, Query, ReqBody, ResBody>&, base_url: const u8[:], params: const Params&, query_dto: const Query&, body_dto: const ReqBody&) -> ResBody, http::Response, http::Error
fn serialize_har_entry_json<B>(entry: const HarEntry&, out: B&)
```

See [client/session/README.md](session/README.md) for HTTP verbs, programmable
pipeline stages, SSRF URL validation, and offline mock exchanges.

## Verification

```bash
python tools/test_runner.py -p "*client*"
python tools/test_runner.py --check-only
```
