# `client/session`

Package `client/session` implements the stateful HTTP session engine that
orchestrates the composable L7 client stage pipeline, HTTP/1.1 wire exchange,
RFC 6265bis schemeful Same-Site cookie bridging, convenience HTTP verbs, SSRF
perimeter defense, and deterministic offline mock routing.

```goose
var s = new_session("https://api.example.com");
let resp, err = get(s, "/v1/health");
close(s);
```

## Public API

### 1. Session Lifecycle & Core Execution (`client/session/verbs.goose`, `client/session/exec.goose`)

```goose
type Session = Client;
type SessionConfig = ClientConfig;
struct RequestExecutionContext { ... }
struct InterceptorChain { index: i64 }
fn new_session() -> Session
fn new_session(cfg: SessionConfig) -> Session
fn new_session(base_url: const u8[:]) -> Session
fn build_effective_url(base_url: const u8[:], req_url: const u8[:], query_params: const QueryParam[:], out: u8[..2048]&) -> bool
fn execute_live_network_hop(c: Client&, hop_req: const Request&, target_url: const u8[:]) -> Response, Error
fn execute_request(c: Client&, req: const Request&) -> Response, Error
fn do(c: Client&, req: const Request&) -> Response, Error
fn proceed(c: Client&, chain: InterceptorChain&, req: Request&) -> Response, Error
fn do_intercepted(c: Client&, req: const Request&) -> Response, Error
```

`build_effective_url` joins `base_url`, `req_url`, and percent-encoded
`query_params` into a bounded 2048-byte buffer (`u8[..2048]`), returning `false`
on capacity overflow. `do` and `execute_request` drive `req` through any
registered `InterceptorChain` (`do_intercepted` / `proceed`) and the
bitmask-gated L7 client stage pipeline across HTTP/3, HTTP/2, or HTTP/1.1
transport pools (`execute_live_network_hop`).

### 2. Composable L7 Client Stage Bricks (`client/session/stages.goose`)

```goose
struct ClientStageCtx {
    hop_req: Request, resp: Response, effective_url: u8[..2048],
    hop_count: i32, status_code: i32, cached_etag: u8[..128],
    cached_last_mod: u8[..64], has_stale_entry: bool
}
fn on_client_stage(stage: const wire::NoOpStage&, phase: wire::ClientHookPhase, ctx: ClientStageCtx&) -> wire::StageVerdict
fn execute_client_pipeline_with_stage<UserStage>(c: Client&, req: const Request&, pipe: const wire::WirePipeline&, user_stage: UserStage&) -> Response, Error
fn stage_client_url_hsts(c: Client&, req: const Request&, effective_url: u8[..2048]&, hop_req: Request&, pipe: const wire::WirePipeline&, out_err: Error&) -> wire::StageVerdict
fn stage_client_ssrf_guard(c: const Client&, effective_url: const u8[:], out_err: Error&) -> wire::StageVerdict
fn stage_client_cache_lookup(c: Client&, hop_req: Request&, effective_url: const u8[:], pipe: const wire::WirePipeline&, cached_etag: u8[..128]&, cached_last_mod: u8[..64]&, has_stale_entry: bool&, out_resp: Response&) -> wire::StageVerdict
fn stage_client_cookie_load(c: Client&, hop_req: Request&, effective_url: const u8[:], redirect_hops: i32, initial_url: const u8[:], pipe: const wire::WirePipeline&)
fn stage_client_dict_negotiate(c: const Client&, hop_req: Request&, effective_url: const u8[:], pipe: const wire::WirePipeline&)
fn stage_client_auth_header(c: Client&, hop_req: Request&, effective_url: const u8[:])
fn stage_client_cookie_store(c: Client&, resp: const Response&, effective_url: const u8[:], initial_url: const u8[:], pipe: const wire::WirePipeline&)
fn stage_client_alt_svc(c: Client&, resp: const Response&, effective_url: const u8[:], pipe: const wire::WirePipeline&)
fn stage_client_decompress(c: const Client&, hop_req: const Request&, resp: Response&, pipe: const wire::WirePipeline&, out_err: Error&) -> wire::StageVerdict
fn stage_client_cache_store(c: Client&, hop_req: const Request&, resp: Response&, effective_url: const u8[:], has_stale_entry: bool, pipe: const wire::WirePipeline&)
fn stage_client_auth_challenge(c: Client&, hop_req: Request&, resp: const Response&, auth_retried: bool&, pipe: const wire::WirePipeline&) -> wire::StageVerdict
fn stage_client_redirect(c: Client&, hop_req: Request&, resp: const Response&, effective_url: u8[..2048]&, redirect_hops: i32&, auth_retried: bool&, visited_urls: u8[..512][..21]&, visited_count: i32&, rewind_body: const u8[:], pipe: const wire::WirePipeline&, out_err: Error&) -> wire::StageVerdict
```

Each stage brick checks its corresponding bit in `pipe.ingress_mask`
(`wire::STAGE_CLI_IN_*`) or `pipe.egress_mask` (`wire::STAGE_CLI_OUT_*`) and
returns a `wire::StageVerdict` (`Continue`, `ShortCircuit`, `RetryAuth`,
`FollowRedirect`, or `Abort`). `stage_client_redirect` tracks up to 21 visited
512-byte URLs (`u8[..512][..21]`) to detect redirect loops, rewinds request
bodies from `rewind_body` on `307`/`308`, and strips sensitive headers on
cross-origin transitions.

### 3. HTTP/1.1 Wire Exchange (`client/session/h1_exchange.goose`)

```goose
enum H1ExchangeState { Idle, SendingRequest, ReadingStatusLine, ReadingHeaders, ReadingBody, Complete, ClosedError }
fn serialize_h1_request<B>(req: const Request&, parsed_url: const ParsedUrl&, user_agent: const u8[:], default_headers: const HeaderField[:], keep_alive: bool, out: B&)
fn parse_h1_status_line(line: const u8[:], resp: Response&) -> bool
fn parse_h1_header_block(raw_block: const u8[:], resp: Response&) -> i64, bool, bool
fn parse_response_headers(raw_headers: const u8[:], resp: Response&) -> bool
fn execute_h1_exchange(tp: Transport&, req: const Request&, parsed_url: const ParsedUrl&, user_agent: const u8[:], default_headers: const HeaderField[:], max_body_size: i64, keep_alive: bool = true) -> Response, Error, bool
```

`parse_h1_header_block` parses the status line and headers from `raw_block` and
returns `(content_length, is_chunked, ok)`, rejecting conflicting
`Content-Length` and `Transfer-Encoding` headers to prevent request/response
smuggling. `execute_h1_exchange` runs a complete keep-alive exchange over `tp`
and returns a trailing `bool` indicating whether the connection remains clean
for pool reuse.

### 4. Cookie Bridge (`client/session/cookie_bridge.goose`, RFC 6265bis)

```goose
fn compute_hop_samesite_context(initial_url: const u8[:], hop_url: const u8[:], is_safe_navigation: bool) -> CookieSameSiteContext
fn compute_hop_partition_key(initial_url: const u8[:], out_site: u8[..128]&)
fn prepare_hop_cookie_header(jar: CanonicalCookieJar&, initial_url: const u8[:], hop_url: const u8[:], method: const u8[:], now_epoch_sec: i64, out_cookie_val: u8[..2048]&)
fn ingest_hop_response_cookies(jar: CanonicalCookieJar&, initial_url: const u8[:], hop_url: const u8[:], resp: const Response&, now_epoch_sec: i64)
```

Bridges redirect hops into `CanonicalCookieJar` with RFC 6265bis schemeful
Same-Site evaluation and CHIPS (`Partitioned`) top-level site keys
(`u8[..128]`). `prepare_hop_cookie_header` serializes matching cookies into a
2048-byte `Cookie` header buffer (`u8[..2048]`).

### 5. Convenience HTTP Verbs & Realtime Upgrades (`client/session/verbs.goose`)

```goose
fn get(c: Client&, url: const u8[:]) -> Response, Error
fn post(c: Client&, url: const u8[:], body: const u8[:], content_type: const u8[:] = "text/plain") -> Response, Error
fn post_json(c: Client&, url: const u8[:], json_body: const u8[:]) -> Response, Error
fn put(c: Client&, url: const u8[:], body: const u8[:], content_type: const u8[:] = "text/plain") -> Response, Error
fn put_json(c: Client&, url: const u8[:], json_body: const u8[:]) -> Response, Error
fn delete(c: Client&, url: const u8[:]) -> Response, Error
fn query(c: Client&, url: const u8[:], body: const u8[:], content_type: const u8[:] = "application/json") -> Response, Error
fn post_chunked(c: Client&, url: const u8[:], cw: ChunkWriter&, content_type: const u8[:] = "application/octet-stream") -> Response, Error
fn put_chunked(c: Client&, url: const u8[:], cw: ChunkWriter&, content_type: const u8[:] = "application/octet-stream") -> Response, Error
fn download_stream<F: fn(const u8[:])>(c: Client&, url: const u8[:]) -> Response, Error
fn ws(c: Client&, url: const u8[:]) -> WebSocketSession, Response, Error
fn sse(c: Client&, url: const u8[:], out_events: SseEvent[..16]&) -> SseSubscription, Response, Error
fn sse_reconnect(c: Client&, sub: SseSubscription&, out_events: SseEvent[..16]&) -> Response, Error
fn connect_udp(c: Client&, proxy_url: const u8[:], target_host: const u8[:], target_port: u16) -> MasqueTunnelSession, Response, Error
fn connect_ip(c: Client&, proxy_url: const u8[:], target_pattern: const u8[:] = "*") -> MasqueTunnelSession, Response, Error
```

Provides single-call wrappers for standard HTTP verbs, chunked uploads,
streaming downloads (`download_stream`), RFC 6455 WebSocket upgrades (`ws`), W3C
Server-Sent Events subscriptions (`sse` and `sse_reconnect`, parsing up to 16
initial events into `SseEvent[..16]`), and RFC 9298 / RFC 9484 MASQUE tunnels
(`connect_udp`, `connect_ip`).

### 6. SSRF Security Perimeter (`client/session/ssrf.goose`)

```goose
struct SsrfGuardPolicy {
    block_private_ips: bool, block_loopback: bool, block_link_local: bool,
    block_cgnat: bool, block_dangerous_ports: bool, https_only: bool
}
fn new_ssrf_guard_policy() -> SsrfGuardPolicy
fn is_private_or_reserved_ip(ip_or_host: const u8[:], policy: const SsrfGuardPolicy&) -> bool
fn is_dangerous_service_port(port: u16) -> bool
fn validate_url_against_ssrf(url: const u8[:], policy: const SsrfGuardPolicy&) -> Error
fn validate_resolved_ips_against_ssrf(ips: const u8[:][..8], ip_count: i64, policy: const SsrfGuardPolicy&) -> Error
```

Defends outbound requests against Server-Side Request Forgery and DNS rebinding:
`is_private_or_reserved_ip` rejects RFC 1918 private ranges, loopback
(`127.0.0.0/8`, `::1`), RFC 3927 link-local / cloud metadata
(`169.254.169.254`), RFC 6598 CGNAT, RFC 4193 ULA, IPv4-mapped IPv6 (`::ffff:`),
and octal/hex/dword IPv4 encodings. `validate_resolved_ips_against_ssrf`
inspects up to 8 DNS-resolved IP literals (`const u8[:][..8]`) after resolution
and before socket connect.

### 7. Deterministic Offline Mock Exchanges (`client/session/mock.goose`)

```goose
struct MockExchange { ... }
fn add_mock_header(m: MockExchange&, name: const u8[:], value: const u8[:]) -> MockExchange&
fn add_mock_set_cookie(m: MockExchange&, cookie_val: const u8[:]) -> MockExchange&
fn add_mock_resolved_ip(m: MockExchange&, ip: const u8[:]) -> MockExchange&
fn set_mock_quic_blocked(m: MockExchange&, blocked: bool) -> MockExchange&
fn set_mock_protocol(m: MockExchange&, proto: const u8[:]) -> MockExchange&
fn build_mock_response(m: const MockExchange&) -> Response
```

Allows deterministic unit testing of redirect chains, cookie jars, QUIC
blackhole fallbacks (`set_mock_quic_blocked`), and SSRF DNS rebinding defenses
(`add_mock_resolved_ip`) without opening live network sockets.

## Verification

Run the client session test suite and full typecheck with:

```bash
python tools/test_runner.py -p "*client*"
python tools/test_runner.py --check-only
```
