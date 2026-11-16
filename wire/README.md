# `wire`

Package `wire` provides the shared framing glue and L7 stage/service combinators
for `goose-wing`: Sans-IO HTTP/1.1, HTTP/2, and HTTP/3 codecs, pooled HTTP/1.1
exchange helpers, composable `WirePipeline` stage bitmasks, and `LayeredService`
resilience wrappers.

```goose
var out: u8[..256] = [];
let ok = wire::encode_ping_frame([1, 2, 3, 4, 5, 6, 7, 8], false, out);
```

## Public API reference

### 1. Framing types (`wire/types.goose`)

```goose
struct WireSetting { id: u16, val: u32 }
struct WireFrameHeader { length: u32, frame_type: u8, flags: u8, stream_id: u32 }
inline fn h2_setting(setting_id: u16, setting_val: u32) -> WireSetting
```

### 2. L7 stage pipeline (`wire/pipeline.goose`)

```goose
enum PipelineRole { Client, Server }
enum StageVerdict {
    Continue, ShortCircuit { status_code: u16 },
    RetryAuth, FollowRedirect, Abort { err_code: i32 }
}
struct PipelineState { verdict: StageVerdict }
enum ClientHookPhase { PreFlight, PreWireHop, PostWireHop }
enum ServerHookPhase {
    PreRoute, PostAuth, BodyChunk, RouteHandler, ResumeHandler,
    PreSerialize, OnError, AfterResponse
}
struct NoOpStage {}
struct StageChain<First, Next> { first: First, next: Next }
struct StageBinding { stage_id: u8, param_slot: u8 }
struct WirePipeline {
    role: PipelineRole, ingress_stages: u8[..64], egress_stages: u8[..64],
    custom_bindings: StageBinding[..64], ingress_mask: u64, egress_mask: u64,
    has_custom_order: bool, is_valid: bool
}
fn begin_pipeline() -> PipelineState
fn can_continue(p: const PipelineState&) -> bool
fn step(p: PipelineState&, next: StageVerdict) -> bool
fn chain_stages<First, Next>(first: First, next: Next) -> StageChain<First, Next>
fn default_client_pipeline() -> WirePipeline
fn default_server_pipeline() -> WirePipeline
fn add_ingress_stage(pipe: WirePipeline&, stage_id: u8) -> bool
fn add_egress_stage(pipe: WirePipeline&, stage_id: u8) -> bool
fn add_stage_binding(pipe: WirePipeline&, stage_id: u8, param_slot: u8 = 0) -> bool
fn clear_stage_bindings(pipe: WirePipeline&)
fn replace_ingress_bindings(pipe: WirePipeline&, bindings: const StageBinding[:]) -> bool
fn is_ingress_stage_enabled(pipe: const WirePipeline&, stage_id: u8) -> bool
fn is_egress_stage_enabled(pipe: const WirePipeline&, stage_id: u8) -> bool
fn enable_ingress_stage(pipe: WirePipeline&, mask_bit: u64)
fn disable_ingress_stage(pipe: WirePipeline&, mask_bit: u64)
fn enable_egress_stage(pipe: WirePipeline&, mask_bit: u64)
fn disable_egress_stage(pipe: WirePipeline&, mask_bit: u64)
```

`WirePipeline` tracks 64-bit stage bitmasks (`ingress_mask` and `egress_mask`)
and optional ordered `StageBinding` entries for client and server L7 pipelines.
Custom middleware hooks compose at compile time via `chain_stages(first, next)`.

### 3. Resilience service combinators (`wire/service.goose`)

```goose
struct LayeredService<Outer, Inner> { outer: Outer, inner: Inner }
struct RetryService<Inner> { ... }
struct RateLimitService<Inner, Limiter> { ... }
struct CircuitBreakerService<Inner> { ... }
struct SingleflightService<Inner> { ... }
fn stack_service<Outer, Inner>(outer: Outer, inner: Inner) -> LayeredService<Outer, Inner>
fn new_retry_service<Inner>(inner: Inner, max_attempts: i32 = 3) -> RetryService<Inner>
fn new_rate_limit_service<Inner, Limiter>(inner: Inner, limiter: Limiter, now_ns: u64 = 0) -> RateLimitService<Inner, Limiter>
fn new_circuit_breaker_service<Inner>(inner: Inner, failure_threshold: u32 = 5, cooldown_ms: u64 = 5000) -> CircuitBreakerService<Inner>
fn new_singleflight_service<Inner>(inner: Inner) -> SingleflightService<Inner>
```

### 4. Sans-IO codecs (`wire/h1.goose`, `wire/h1_exchange.goose`, `wire/hpack.goose`, `wire/h2.goose`, `wire/h3.goose`)

- `wire/h1.goose`: HTTP/1.1 request and response wire framing
  (`encode_h1_request`, `encode_h1_response`, `decode_h1_response_head`,
  `scan_h1_wire_field_name`, `parse_h1_wire_status_line`).
- `wire/h1_exchange.goose`: Pooled HTTP/1.1 exchange driver over
  `wing::Transport` (`execute_h1_exchange`, `read_response_headers`,
  `pump_response_body`).
- `wire/hpack.goose`: RFC 7541 HPACK primitives and `HeaderMap` codecs
  (`encode_hpack_from_map`, `decode_hpack_to_map`, `hpack_encode_int`,
  `hpack_decode_int`, `hpack_decode_string`).
- `wire/h2.goose`: RFC 9113 and RFC 9218 HTTP/2 frame encoders and slice reader
  (`WireH2FrameReader`, `read_wire_h2_frame`, `encode_frame_header`,
  `parse_frame_header`, `decode_h2_frame_header`, `encode_settings_frame`,
  `encode_window_update_frame`, `encode_priority_update_frame`,
  `encode_rst_stream_frame`, `encode_ping_frame`, `encode_data_frame`,
  `encode_h2_headers_frame_from_map`).
- `wire/h3.goose`: RFC 9114 and RFC 9204 HTTP/3 and QPACK `HeaderMap` codecs
  (`encode_h3_headers_from_map`, `decode_h3_headers_to_map`,
  `encode_h3_data_frame`).
