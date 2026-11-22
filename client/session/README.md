# `client/session`

Package `client/session` (`namespace client;`) implements request dispatch,
express HTTP verbs, streaming uploads and downloads, WebSocket/SSE/MASQUE
upgrades, programmable L7 pipeline stages, SSRF URL validation, and offline mock
exchanges.

Internal transport, DNS/proxy dialing, TLS handshakes, HTTP/1.1, HTTP/2, HTTP/3
framing, cookie bridging, and stage conveyor helpers live in
`namespace client_internal;` (`*_internal.goose`).

## Quick start

```goose
import wing;

var s = client::new_session("https://api.example.com");
defer s.close();

let resp, err = s.get("/v1/health");
if http::ok(err) {
    print("status:", resp.status_code);
}
```

## Task recipes

### GET, POST JSON, and intercepted dispatch

Send requests directly with `get`, `post`, `put`, `delete`, or `query`, or wrap
dispatch with `do_intercepted` and `proceed` for per-call instrumentation.

```goose
var s = client::new_session("https://api.example.com");
defer s.close();

let resp, err = s.post("/v1/orders") { req =>
    req.set_header("Content-Type", "application/json");
    req.body.append("{\"sku\":\"abc\"}");
};

let req = http::new_request("GET", "/v1/orders");
let i_resp, i_err = s.do_intercepted(req) { chain, sess =>
    chain.request.set_header("X-Trace", "123");
    chain.proceed(sess);
};
```

### Timeouts, retries, proxies, and IP family

Session dispatch inherits timeout, retry, proxy, `NO_PROXY`, IP family, and
resolve-override settings configured on `Client` (`Session`).

```goose
var s = client::new_session(client::Config {
    base_url:           "https://api.example.com",
    connect_timeout_ms: 2000,
    read_timeout_ms:    5000,
    max_retries:        2,
    ip_family:          net::IpFamily.Ipv4Only,
    ..
});
defer s.close();

let _ = s.set_proxy("socks5h://127.0.0.1:1080");
let resp, err = s.get("/v1/status");
```

### TLS, mTLS, CA bundles, and SSRF defense

Every live hop validates the target URL with `validate_url_against_ssrf` and
checks resolved DNS IPs before opening a socket, closing DNS-rebinding TOCTOU
windows.

```goose
var s = client::new_session("https://internal.example.com");
defer s.close();

let _, _ = s.load_trust_anchors_pem_file("certs/ca.pem");
let _ = s.set_tls_client_cert("certs/client.pem", "certs/client.key");
let parsed, _ = core::parse_url("http://169.254.169.254/latest/meta-data/");
let ssrf_err = client::validate_url_against_ssrf(parsed, s.ssrf_guard);
```

### Streaming downloads and chunked uploads

Upload chunked payloads with trailers using `post_chunked`, or stream response
chunks into a buffer with progress callbacks using `download_stream`.

```goose
let up_resp, up_err = s.post_chunked("/v1/ingest") { writer =>
    writer.write_chunk("chunk-a");
    writer.write_chunk("chunk-b");
};

var payload: u8[>..] = [];
let dl_resp, dl_err = s.download_stream("/v1/export.csv", 8192, payload) { p =>
    print("received:", p.bytes_processed);
};
```

### WebSocket, SSE, and MASQUE tunnels

Open RFC 6455 WebSocket sessions, W3C EventSource (SSE) subscriptions, and RFC
9298 / RFC 9484 MASQUE `CONNECT-UDP` or `CONNECT-IP` tunnels.

```goose
let ws_sess, ws_resp, ws_err = s.ws("wss://echo.example.com/ws");
let sse_sub, sse_resp, sse_err = s.sse("https://stream.example.com/events");
let tun, tun_resp, tun_err = s.connect_ip("https://proxy.example.com/masque/ip");
```

### Custom pipeline stages and offline mocks

Specialize `client::on_stage` or `client::on_custom_slot` for a custom stage
struct and run it through `execute_pipeline_with_stage`. Register deterministic
offline responses with `mock_route` and `MockExchange` helpers to test
redirects, cookies, QUIC fallback, and DNS-rebinding guards without sockets.

```goose
var s = client::new_session("https://api.example.com");
defer s.close();

let route .= s.mock_route("GET", "https://api.example.com/v1/item", 200, "ok");
route.add_mock_header("Cache-Control", "max-age=60");
route.add_mock_resolved_ip("93.184.216.34");
let resp, err = s.get("/v1/item");
```

## Public API

### Request execution and HTTP verbs (`exec.goose`, `verbs.goose`)

Dispatch HTTP requests, run per-call interceptors, stream chunked bodies, and
upgrade connections to WebSocket, SSE, or MASQUE tunnels.

```goose
struct InterceptorChain { ... }

fn execute_request(session: Client&, req: const http::Request&) -> http::Response, http::Error
fn do(session: Session&, req: const http::Request&) -> http::Response, http::Error
fn do<F: fn(http::Request&)>(session: Session&, req: const http::Request&) -> http::Response, http::Error
fn proceed(chain: InterceptorChain&, session: Session&)
fn do_intercepted<F: fn(InterceptorChain&, Session&)>(session: Session&, req: const http::Request&) -> http::Response, http::Error

fn get(session: Session&, url: const u8[:]) -> http::Response, http::Error
fn get<F: fn(http::Request&)>(session: Session&, url: const u8[:]) -> http::Response, http::Error
fn post<F: fn(http::Request&)>(session: Session&, url: const u8[:]) -> http::Response, http::Error
fn put<F: fn(http::Request&)>(session: Session&, url: const u8[:]) -> http::Response, http::Error
fn delete(session: Session&, url: const u8[:]) -> http::Response, http::Error
fn delete<F: fn(http::Request&)>(session: Session&, url: const u8[:]) -> http::Response, http::Error
fn query(session: Session&, url: const u8[:], body: const u8[:], content_type: const u8[:]) -> http::Response, http::Error
fn query<F: fn(http::Request&)>(session: Session&, url: const u8[:], body: const u8[:], content_type: const u8[:]) -> http::Response, http::Error
fn post_chunked<F: fn(ChunkWriter&)>(session: Session&, url: const u8[:]) -> http::Response, http::Error
fn download_stream<F: fn(const StreamProgress&)>(session: Session&, url: const u8[:], chunk_size: i64, out_body: u8[>..]&) -> http::Response, http::Error

fn ws(session: Session&, url: const u8[:]) -> realtime::WebSocketSession, http::Response, http::Error
fn ws<F: fn(http::Request&)>(session: Session&, url: const u8[:]) -> realtime::WebSocketSession, http::Response, http::Error
fn sse(session: Session&, url: const u8[:]) -> realtime::SseSubscription, http::Response, http::Error
fn sse<F: fn(http::Request&)>(session: Session&, url: const u8[:]) -> realtime::SseSubscription, http::Response, http::Error
fn connect_udp(session: Session&, proxy_url: const u8[:], target_host: const u8[:], target_port: u16, stream_id: u64 = 0, use_datagrams: bool = true) -> net::MasqueTunnelSession, http::Response, http::Error
fn connect_ip(session: Session&, proxy_url: const u8[:], stream_id: u64 = 0, use_datagrams: bool = true) -> net::MasqueTunnelSession, http::Response, http::Error
```

### Programmable client stages (`stages.goose`)

Inject compile-time user stages into `session.wire_pipeline` at pre-flight,
pre-hop, post-hop, or custom slot hooks.

```goose
struct StageCtx { ... }

fn on_stage<Stage>(_stage: Stage&, _phase: wire::ClientHookPhase, _ctx: StageCtx&) -> wire::StageVerdict
fn on_custom_slot<Stage>(_stage: Stage&, _slot_id: i64, _ctx: StageCtx&, _headers: http::HeaderMap&, _out_resp: http::Response&) -> wire::StageVerdict
fn execute_pipeline_with_stage<UserStage>(session: Client&, req: const http::Request&, user_stage: UserStage&) -> http::Response, http::Error
```

### SSRF validation and offline mock exchanges (`ssrf.goose`, `mock.goose`)

Enforce SSRF URL rules and attach headers, cookies, resolved IPs, or QUIC
blackhole simulation to offline `MockExchange` routes.

```goose
struct MockExchange { ... }

fn validate_url_against_ssrf(url_val: const core::Url&, policy: const security::SsrfGuardPolicy&) -> RedirectError
fn add_mock_header(route: MockExchange&, name: const u8[:], value: const u8[:])
fn add_mock_set_cookie(route: MockExchange&, cookie_str: const u8[:])
fn add_mock_resolved_ip(route: MockExchange&, ip_str: const u8[:])
fn set_mock_quic_blocked(route: MockExchange&, blocked: bool = true)
```

## Internal architecture

Internal session logic lives in `namespace client_internal;` across thematic
modules: `dns_dial_internal.goose` (DNS, SVCB, proxy/TCP dialing),
`tls_hop_internal.goose` (TLS handshakes, mTLS/CRL loading, HSTS, config knobs),
`hop_context_internal.goose` (request context, URL/redirect transitions, cookie
bridge), `hop_auth_internal.goose` (401/Digest/DPoP/Early-Data auth, retry
policy, compression dictionaries), `stage_bricks_internal.goose` (L7 stage
evaluation bricks), `h1_h2_internal.goose` (pooled H1/H2 framing and loops),
`h3_internal.goose` (H3 datagram hop), `hop_dispatch_internal.goose` (live and
mock hop dispatch), `pipeline_internal.goose` (preflight/ingress/egress
conveyor), and `realtime_internal.goose` (WebSocket, SSE, and MASQUE setup).

## Verification

```bash
python tools/test_runner.py -p client_pipeline_test
goose-lit tests/lit/lit_client_pipeline.goose
```
