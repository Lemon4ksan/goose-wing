# `client/session`

Package `client/session` (`namespace client;`, internal helpers in
`namespace client_internal;`) implements the stateful HTTP session engine that
orchestrates the composable L7 client stage pipeline, HTTP/1.1, HTTP/2, and
HTTP/3 wire hops, RFC 6265bis schemeful Same-Site cookie bridging, convenience
HTTP verbs, SSRF perimeter defense, and deterministic offline mock routing.

```goose
var s = client::new_session("https://api.example.com");
let resp, err = s.get("/v1/health");
s.close();
```

## Public API

### 1. Execution pipeline and hop helpers (`client/session/exec.goose`)

```goose
struct RequestExecutionContext { ... }
enum H2RecvStatus { Continue, Complete, Error }
struct H2RecvState { ... }

fn append_query_params_preserving_fragment<B>(out: B&, query_params: const wing::QueryItem[:])
fn build_effective_url<B>(base_url: const u8[:], req_url: const u8[:], query_params: const wing::QueryItem[:], out: B&)
fn apply_redirect_transition(session: const Session&, ctx: RequestExecutionContext&, redirect_info: const RedirectInfo&) -> wing::Error
fn init_execution_context(session: const Session&, req: const wing::Request&, parsed_initial: const core::Url&) -> RequestExecutionContext
fn ingest_compression_dict_header(dict_cache: wing::DictionaryCache&, origin_buf: const u8[:], curr_path: const u8[:], now_sec: i64, resp: wing::Response&)
fn dispatch_pooled_h1_hop(session: Session&, conn_id: i32, curr_method: const u8[:], ctx: RequestExecutionContext&, current_url: const core::Url&, is_https: bool, origin_buf: const u8[:], curr_path: const u8[:], now_sec: i64, now_ns: i64, resp: wing::Response&) -> bool
fn resolve_hop_proxy_chain(session: const Session&) -> wing::ProxyChain
fn encode_h2_request<B>(curr_method: const u8[:], current_url: const core::Url&, is_https: bool, ctx: const RequestExecutionContext&, enc_dt: http2::DynamicTable&, stream_id: u32, send_preface: bool, out: B&) -> bool
fn process_h2_response_frame<B>(hdr: const http2::FrameHeader&, payload: const u8[:], stream_id: u32, is_head: bool, dec_dt: http2::DynamicTable&, resp: wing::Response&, state: H2RecvState&, out_ctrl: B&) -> H2RecvStatus
fn drain_h2_response_frames<B1, B2>(rx_accum: B1&, stream_id: u32, is_head: bool, dec_dt: http2::DynamicTable&, resp: wing::Response&, state: H2RecvState&, out_ctrl: B2&) -> H2RecvStatus
fn recv_h2_response_loop(conn: wing::PooledConnection&, stream_id: u32, is_head: bool, eff_timeout: u32, resp: wing::Response&) -> bool
fn encode_h3_request<B>(h3_conn: http3::Connection&, sid: u64, ctx: const RequestExecutionContext&, current_url: const core::Url&, out: B&) -> bool
fn execute_live_h3_hop(session: Session&, ctx: RequestExecutionContext&, current_url: const core::Url&, origin_buf: const u8[:], h3_ep: const wing::AltSvcEndpoint&, now_sec: i64, resp: wing::Response&) -> bool
fn compute_401_auth_header<B>(session: Client&, ctx: RequestExecutionContext&, current_url: const core::Url&, www_auth: const u8[:], out: B&) -> bool
fn prepare_auth_retry_hop(session: Client&, ctx: RequestExecutionContext&, current_url: const core::Url&, samesite_eval: const cookie::SameSiteCookieContext&, safe_method: bool, resp: const wing::Response&, auth_val: const u8[:])
fn should_retry_request(status_code: i32, err: wing::Error, method: const u8[:], req: const wing::Request&, attempts: i32, has_retry: bool, max_retries: i32, retry_5xx: bool) -> bool
fn execute_request(session: Client&, req: const wing::Request&) -> wing::Response, wing::Error
```

`build_effective_url` joins `base_url`, `req_url`, and percent-encoded query
parameters while preserving any trailing URL fragment. `execute_request` drives
requests through application interceptors, retry budgets, circuit breakers, and
the bitmask-gated L7 client stage pipeline across HTTP/3, HTTP/2, or HTTP/1.1
transport pools.

### 2. Composable L7 client stage bricks (`client/session/stages.goose`)

```goose
struct StageCtx { ... }

fn stage_cache_lookup<Cache>(req: const wing::Request&, eff_url: const u8[:], now_sec: i64, headers: wing::HeaderMap&, out_resp: wing::Response&, cache: Cache&, enable_cache: bool, method_override: const u8[:] = "") -> wire::StageVerdict, i64
fn stage_cookie_load<Jar>(headers: wing::HeaderMap&, current_url: const core::Url&, samesite_eval: const cookie::SameSiteCookieContext&, is_main_frame: bool, part_key: const u8[:], safe_method: bool, now_us: i64, jar: Jar&, enable_jar: bool) -> wire::StageVerdict
fn stage_cache_store<Cache>(req: const wing::Request&, headers: const wing::HeaderMap&, effective_url: const u8[:], method: const u8[:], out_resp: wing::Response&, cache_ts: wing::CacheTimestamps&, revalidate_idx: i64, cache: Cache&, enable_cache: bool) -> wire::StageVerdict
fn validate_cors_and_corp_response(ctx: const RequestExecutionContext&, current_url: const core::Url&, resp: const wing::Response&) -> wing::Error
fn verify_response_signature(session: const Client&, req: const wing::Request&, current_url: const core::Url&, method: const u8[:], headers: const wing::HeaderMap&, resp: const wing::Response&) -> bool
fn is_noop_stage<Stage>(_stage: const Stage&) -> bool
fn on_stage<Stage>(_stage: Stage&, _phase: wire::ClientHookPhase, _ctx: StageCtx&) -> wire::StageVerdict
fn on_custom_slot<Stage>(_stage: Stage&, _slot_id: i64, _ctx: StageCtx&, _headers: wing::HeaderMap&, _out_resp: wing::Response&) -> wire::StageVerdict
fn run_pre_hop_stages<UserStage>(session: Client&, ctx: RequestExecutionContext&, current_url: core::Url&, samesite_eval: cookie::SameSiteCookieContext&, safe_method: bool, now_sec: i64, out_resp: wing::Response&, out_err: wing::Error&, user_stage: UserStage&) -> wire::StageVerdict
fn execute_pipeline_with_stage<UserStage>(session: Client&, req: const wing::Request&, user_stage: UserStage&) -> wing::Response, wing::Error
```

Each stage brick evaluates its corresponding slot in `session.wire_pipeline` and
returns a `wire::StageVerdict` (`Continue`, `ShortCircuit`, `RetryAuth`,
`FollowRedirect`, or `Abort`). Callers can specialize `client::on_stage` or
`client::on_custom_slot` for custom `<UserStage>` types.

### 3. Cookie bridge (`client/session/cookie_bridge.goose`, RFC 6265bis)

```goose
fn compute_hop_samesite_context(ctx: const RequestExecutionContext&, current_url: const core::Url&, safe_method: bool) -> cookie::SameSiteCookieContext
fn compute_hop_partition_key<B>(ctx: const RequestExecutionContext&, current_url: const core::Url&, out: B&)
fn prepare_hop_cookie_header(session: Session&, ctx: RequestExecutionContext&, current_url: const core::Url&, samesite_eval: const cookie::SameSiteCookieContext&, safe_method: bool)
fn ingest_hop_response_cookies(session: Session&, ctx: const RequestExecutionContext&, current_url: const core::Url&, samesite_eval: const cookie::SameSiteCookieContext&, resp_headers: const wing::HeaderMap&)
```

Bridges redirect hops into `cookie::CanonicalCookieJar` with RFC 6265bis
schemeful Same-Site evaluation and CHIPS (`Partitioned`) top-level site keys.

### 4. Convenience HTTP verbs and realtime upgrades (`client/session/verbs.goose`)

```goose
struct InterceptorChain { ... }

fn do(session: Session&, req: const wing::Request&) -> wing::Response, wing::Error
fn proceed(chain: InterceptorChain&, session: Session&)
fn do_intercepted<F: fn(InterceptorChain&, Session&)>(session: Session&, req: const wing::Request&) -> wing::Response, wing::Error
fn get(session: Session&, url: const u8[:]) -> wing::Response, wing::Error
fn post<F: fn(wing::Request&)>(session: Session&, url: const u8[:]) -> wing::Response, wing::Error
fn put<F: fn(wing::Request&)>(session: Session&, url: const u8[:]) -> wing::Response, wing::Error
fn delete(session: Session&, url: const u8[:]) -> wing::Response, wing::Error
fn query(session: Session&, url: const u8[:], body: const u8[:], content_type: const u8[:]) -> wing::Response, wing::Error
fn post_chunked<F: fn(ChunkWriter&)>(session: Session&, url: const u8[:]) -> wing::Response, wing::Error
fn download_stream<F: fn(const StreamProgress&)>(session: Session&, url: const u8[:], chunk_size: i64, out_body: u8[>..]&) -> wing::Response, wing::Error
fn header_has_token(hdr: const u8[:], token: const u8[:]) -> bool
fn ws(session: Session&, url: const u8[:]) -> realtime::WebSocketSession, wing::Response, wing::Error
fn is_sse_content_type(ct: const u8[:]) -> bool
fn sse(session: Session&, url: const u8[:]) -> realtime::SseSubscription, wing::Response, wing::Error
fn connect_udp(session: Session&, proxy_url: const u8[:], target_host: const u8[:], target_port: u16, stream_id: u64 = 0, use_datagrams: bool = true) -> wing::MasqueTunnelSession, wing::Response, wing::Error
fn connect_ip(session: Session&, proxy_url: const u8[:], stream_id: u64 = 0, use_datagrams: bool = true) -> wing::MasqueTunnelSession, wing::Response, wing::Error
```

Provides single-call UFCS methods on `Session` for standard HTTP verbs, chunked
uploads, streaming downloads (`download_stream`), RFC 6455 WebSocket upgrades
(`ws`), W3C Server-Sent Events subscriptions (`sse`), and RFC 9298 / RFC 9484
MASQUE tunnels (`connect_udp`, `connect_ip`).

### 5. SSRF perimeter and offline mock exchanges (`client/session/ssrf.goose`, `client/session/mock.goose`)

```goose
struct MockExchange { ... }

fn validate_url_against_ssrf(url_val: const core::Url&, policy: const security::SsrfGuardPolicy&) -> RedirectError
fn add_mock_header(route: MockExchange&, name: const u8[:], value: const u8[:])
fn add_mock_set_cookie(route: MockExchange&, cookie_str: const u8[:])
fn add_mock_resolved_ip(route: MockExchange&, ip_str: const u8[:])
fn set_mock_quic_blocked(route: MockExchange&, blocked: bool = true)
```

`validate_url_against_ssrf` checks outbound URLs against
`security::SsrfGuardPolicy` and returns a typed `RedirectError`. `MockExchange`
supports deterministic unit testing of redirect chains, cookie jars, QUIC
blackhole fallbacks (`set_mock_quic_blocked`), and DNS rebinding defenses
(`add_mock_resolved_ip`) without opening live network sockets.

## Verification

Run the client session test suite and full typecheck with:

```bash
python tools/test_runner.py -p "*client*"
python tools/test_runner.py --check-only
```
