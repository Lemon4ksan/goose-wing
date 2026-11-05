// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Vulkan-style Pipeline State Objects (PSO) and Tier 2 Composable L7 Stage Pipeline.
namespace wire;

import std;
import .result;
import .types;
import .cmd;

// Pipeline bind point distinguishing transmission from reception pipelines.
enum WirePipelineBindPoint {
    Transmit,
    Receive,
}

// Pipeline role separating client and server stage bitmasks and stage slots.
enum PipelineRole {
    Client,
    Server,
}

// Uniform verdict returned by every Tier 2 L7 pipeline stage.
enum StageVerdict {
    Continue,
    ShortCircuit { status_code: u16 },
    RetryAuth,
    FollowRedirect,
    Abort { err_code: i32 },
}

// Step-by-step code combinator for assembling custom L7 stage pipelines without branching boilerplate.
struct PipelineState {
    verdict: StageVerdict = StageVerdict.Continue,
}

// Initializes a new PipelineState in the Continue state.
inline fn begin_pipeline() -> PipelineState {
    return PipelineState { verdict: StageVerdict.Continue };
}

// Returns true when the pipeline has not short-circuited, retried, redirected, or aborted.
inline fn can_continue(p: const PipelineState&) -> bool {
    return match p.verdict {
        Continue => true,
        _ => false,
    };
}

// Advances the pipeline state with `next` if the pipeline was previously in `Continue`.
// Returns true if the pipeline remains in `Continue` after this step.
inline fn step(p: PipelineState&, next: StageVerdict) -> bool {
    match p.verdict {
        Continue => {
            p.verdict = next;
        },
        _ => {},
    };
    return can_continue(p);
}

// Fixed compile-time generic hook phases for Server pipelines.
enum ServerHookPhase {
    PreRoute,
    PostAuth,
    PreSerialize,
}

// Fixed compile-time generic hook phases for Client pipelines.
enum ClientHookPhase {
    PreFlight,
    PreWireHop,
    PostWireHop,
}

// Default zero-cost no-op user stage when no custom <UserStage> is provided.
struct NoOpStage {}

// Compile-time zero-allocation stage combinator chaining two independent `<First, Next>` user stages.
// Allows composing an unlimited number of modular stage structs (`chain_stages(s1, chain_stages(s2, s3))`)
// without heap allocation, virtual dispatch, or numeric slot limits.
struct StageChain<First, Next> {
    first: First,
    next:  Next,
}

// Combines two user stage structs into a single `StageChain<First, Next>` pipeline hook.
inline fn chain_stages<First, Next>(first: First, next: Next) -> StageChain<First, Next> {
    return StageChain<First, Next> {
        first: first,
        next:  next,
    };
}

// ---- Built-In Stage Slot Identifiers (0..47) and Bitmasks -------------------

// Server Ingress Stage Slot IDs (0..11) and Bitmasks
const STAGE_ID_SRV_IN_SLOWLORIS:       u8 = 0;
const STAGE_ID_SRV_IN_EXPECT_100:      u8 = 1;
const STAGE_ID_SRV_IN_EDGE_FILTER:     u8 = 2;
const STAGE_ID_SRV_IN_RATELIMIT_IP:    u8 = 3;
const STAGE_ID_SRV_IN_ROUTE_MATCH:     u8 = 4;
const STAGE_ID_SRV_IN_RATELIMIT_ROUTE: u8 = 5;
const STAGE_ID_SRV_IN_CORS:            u8 = 6;
const STAGE_ID_SRV_IN_CSRF:            u8 = 7;
const STAGE_ID_SRV_IN_AUTH_COOKIE:     u8 = 8;
const STAGE_ID_SRV_IN_AUTH_JWT:        u8 = 9;
const STAGE_ID_SRV_IN_CACHE_LOOKUP:    u8 = 10;
const STAGE_ID_SRV_IN_DECOMPRESS:      u8 = 11;

const STAGE_SRV_IN_SLOWLORIS:       u64 = (1 as u64) << 0;
const STAGE_SRV_IN_EXPECT_100:      u64 = (1 as u64) << 1;
const STAGE_SRV_IN_EDGE_FILTER:     u64 = (1 as u64) << 2;
const STAGE_SRV_IN_RATELIMIT_IP:    u64 = (1 as u64) << 3;
const STAGE_SRV_IN_ROUTE_MATCH:     u64 = (1 as u64) << 4;
const STAGE_SRV_IN_RATELIMIT_ROUTE: u64 = (1 as u64) << 5;
const STAGE_SRV_IN_CORS:            u64 = (1 as u64) << 6;
const STAGE_SRV_IN_CSRF:            u64 = (1 as u64) << 7;
const STAGE_SRV_IN_AUTH_COOKIE:     u64 = (1 as u64) << 8;
const STAGE_SRV_IN_AUTH_JWT:        u64 = (1 as u64) << 9;
const STAGE_SRV_IN_CACHE_LOOKUP:    u64 = (1 as u64) << 10;
const STAGE_SRV_IN_DECOMPRESS:      u64 = (1 as u64) << 11;

const STAGE_SRV_IN_DEFAULT_MASK: u64 =
    STAGE_SRV_IN_SLOWLORIS |
    STAGE_SRV_IN_EXPECT_100 |
    STAGE_SRV_IN_EDGE_FILTER |
    STAGE_SRV_IN_RATELIMIT_IP |
    STAGE_SRV_IN_ROUTE_MATCH |
    STAGE_SRV_IN_CORS |
    STAGE_SRV_IN_CSRF |
    STAGE_SRV_IN_AUTH_COOKIE;

// Server Egress Stage Slot IDs (0..8) and Bitmasks
const STAGE_ID_SRV_OUT_ETAG:             u8 = 0;
const STAGE_ID_SRV_OUT_COMPRESS_GZIP:    u8 = 1;
const STAGE_ID_SRV_OUT_COMPRESS_BR:      u8 = 2;
const STAGE_ID_SRV_OUT_COMPRESS_ZSTD:    u8 = 3;
const STAGE_ID_SRV_OUT_CACHE_STORE:      u8 = 4;
const STAGE_ID_SRV_OUT_SECURITY_HEADERS: u8 = 5;
const STAGE_ID_SRV_OUT_ALT_SVC:          u8 = 6;
const STAGE_ID_SRV_OUT_METRICS:          u8 = 7;
const STAGE_ID_SRV_OUT_ACCESS_LOG:       u8 = 8;

const STAGE_SRV_OUT_ETAG:             u64 = (1 as u64) << 0;
const STAGE_SRV_OUT_COMPRESS_GZIP:    u64 = (1 as u64) << 1;
const STAGE_SRV_OUT_COMPRESS_BR:      u64 = (1 as u64) << 2;
const STAGE_SRV_OUT_COMPRESS_ZSTD:    u64 = (1 as u64) << 3;
const STAGE_SRV_OUT_CACHE_STORE:      u64 = (1 as u64) << 4;
const STAGE_SRV_OUT_SECURITY_HEADERS: u64 = (1 as u64) << 5;
const STAGE_SRV_OUT_ALT_SVC:          u64 = (1 as u64) << 6;
const STAGE_SRV_OUT_METRICS:          u64 = (1 as u64) << 7;
const STAGE_SRV_OUT_ACCESS_LOG:       u64 = (1 as u64) << 8;

const STAGE_SRV_OUT_DEFAULT_MASK: u64 =
    STAGE_SRV_OUT_SECURITY_HEADERS |
    STAGE_SRV_OUT_METRICS;

// Client Ingress (Pre-Hop) Stage Slot IDs (0..5) and Bitmasks
const STAGE_ID_CLI_IN_URL_HSTS:         u8 = 0;
const STAGE_ID_CLI_IN_SSRF_GUARD:       u8 = 1;
const STAGE_ID_CLI_IN_CACHE_LOOKUP:     u8 = 2;
const STAGE_ID_CLI_IN_COOKIE_LOAD:      u8 = 3;
const STAGE_ID_CLI_IN_DICT_NEGOTIATE:   u8 = 4;
const STAGE_ID_CLI_IN_INTERCEPTOR_AUTH: u8 = 5;

const STAGE_CLI_IN_URL_HSTS:         u64 = (1 as u64) << 0;
const STAGE_CLI_IN_SSRF_GUARD:       u64 = (1 as u64) << 1;
const STAGE_CLI_IN_CACHE_LOOKUP:     u64 = (1 as u64) << 2;
const STAGE_CLI_IN_COOKIE_LOAD:      u64 = (1 as u64) << 3;
const STAGE_CLI_IN_DICT_NEGOTIATE:   u64 = (1 as u64) << 4;
const STAGE_CLI_IN_INTERCEPTOR_AUTH: u64 = (1 as u64) << 5;

const STAGE_CLI_IN_DEFAULT_MASK: u64 =
    STAGE_CLI_IN_URL_HSTS |
    STAGE_CLI_IN_SSRF_GUARD |
    STAGE_CLI_IN_CACHE_LOOKUP |
    STAGE_CLI_IN_COOKIE_LOAD |
    STAGE_CLI_IN_DICT_NEGOTIATE |
    STAGE_CLI_IN_INTERCEPTOR_AUTH;

// Client Egress (Post-Hop) Stage Slot IDs (0..5) and Bitmasks
const STAGE_ID_CLI_OUT_COOKIE_STORE:   u8 = 0;
const STAGE_ID_CLI_OUT_ALT_SVC:        u8 = 1;
const STAGE_ID_CLI_OUT_DECOMPRESS:     u8 = 2;
const STAGE_ID_CLI_OUT_CACHE_STORE:    u8 = 3;
const STAGE_ID_CLI_OUT_AUTH_CHALLENGE: u8 = 4;
const STAGE_ID_CLI_OUT_REDIRECT:       u8 = 5;

const STAGE_CLI_OUT_COOKIE_STORE:   u64 = (1 as u64) << 0;
const STAGE_CLI_OUT_ALT_SVC:        u64 = (1 as u64) << 1;
const STAGE_CLI_OUT_DECOMPRESS:     u64 = (1 as u64) << 2;
const STAGE_CLI_OUT_CACHE_STORE:    u64 = (1 as u64) << 3;
const STAGE_CLI_OUT_AUTH_CHALLENGE: u64 = (1 as u64) << 4;
const STAGE_CLI_OUT_REDIRECT:       u64 = (1 as u64) << 5;

const STAGE_CLI_OUT_DEFAULT_MASK: u64 =
    STAGE_CLI_OUT_COOKIE_STORE |
    STAGE_CLI_OUT_ALT_SVC |
    STAGE_CLI_OUT_DECOMPRESS |
    STAGE_CLI_OUT_CACHE_STORE |
    STAGE_CLI_OUT_AUTH_CHALLENGE |
    STAGE_CLI_OUT_REDIRECT;

// Pipeline layout defining static protocol limits and push constants (VkPipelineLayout).
struct WirePipelineLayout {
    max_frame_size: u32      = 16384,
    push_constants: u8[..64] = [],
}

// Pipeline creation parameters (VkGraphicsPipelineCreateInfo / VkComputePipelineCreateInfo).
struct WirePipelineCreateInfo {
    bind_point:   WirePipelineBindPoint = WirePipelineBindPoint.Transmit,
    role:         PipelineRole          = PipelineRole.Client,
    layout:       WirePipelineLayout    = WirePipelineLayout { .. },
    ingress_mask: u64                   = STAGE_CLI_IN_DEFAULT_MASK,
    egress_mask:  u64                   = STAGE_CLI_OUT_DEFAULT_MASK,
    flags:        u32                   = 0,
}

// Declarative Pipeline State Object (VkPipeline) and Programmable Stage Conveyor.
struct WirePipeline {
    bind_point:     WirePipelineBindPoint = WirePipelineBindPoint.Transmit,
    role:           PipelineRole          = PipelineRole.Client,
    layout:         WirePipelineLayout    = WirePipelineLayout { .. },
    ingress_stages: u8[..24]              = [],
    egress_stages:  u8[..24]              = [],
    ingress_mask:   u64                   = STAGE_CLI_IN_DEFAULT_MASK,
    egress_mask:    u64                   = STAGE_CLI_OUT_DEFAULT_MASK,
    is_valid:       bool                  = true,
}

// Appends a stage slot ID to `pipe.ingress_stages` and enables its corresponding bit in `pipe.ingress_mask`.
fn add_ingress_stage(pipe: WirePipeline&, stage_id: u8) -> bool {
    guard pipe.ingress_stages.len < pipe.ingress_stages.cap && stage_id < 64 else { return false; }
    pipe.ingress_stages.push(stage_id);
    pipe.ingress_mask = pipe.ingress_mask | ((1 as u64) << stage_id);
    return true;
}

// Appends a stage slot ID to `pipe.egress_stages` and enables its corresponding bit in `pipe.egress_mask`.
fn add_egress_stage(pipe: WirePipeline&, stage_id: u8) -> bool {
    guard pipe.egress_stages.len < pipe.egress_stages.cap && stage_id < 64 else { return false; }
    pipe.egress_stages.push(stage_id);
    pipe.egress_mask = pipe.egress_mask | ((1 as u64) << stage_id);
    return true;
}

inline fn is_ingress_stage_enabled(pipe: const WirePipeline&, stage_id: u8) -> bool {
    guard stage_id < 64 else { return false; }
    return (pipe.ingress_mask & ((1 as u64) << stage_id)) != 0;
}

inline fn is_egress_stage_enabled(pipe: const WirePipeline&, stage_id: u8) -> bool {
    guard stage_id < 64 else { return false; }
    return (pipe.egress_mask & ((1 as u64) << stage_id)) != 0;
}

inline fn enable_ingress_stage(pipe: WirePipeline&, mask_bit: u64) {
    pipe.ingress_mask = pipe.ingress_mask | mask_bit;
}

inline fn disable_ingress_stage(pipe: WirePipeline&, mask_bit: u64) {
    pipe.ingress_mask = pipe.ingress_mask & (~mask_bit);
}

inline fn enable_egress_stage(pipe: WirePipeline&, mask_bit: u64) {
    pipe.egress_mask = pipe.egress_mask | mask_bit;
}

inline fn disable_egress_stage(pipe: WirePipeline&, mask_bit: u64) {
    pipe.egress_mask = pipe.egress_mask & (~mask_bit);
}

// Constructs the default Client `WirePipeline` with standard pre-hop and post-hop stages.
fn default_client_pipeline() -> WirePipeline {
    var p = WirePipeline {
        bind_point:   WirePipelineBindPoint.Transmit,
        role:         PipelineRole.Client,
        ingress_mask: STAGE_CLI_IN_DEFAULT_MASK,
        egress_mask:  STAGE_CLI_OUT_DEFAULT_MASK,
        is_valid:     true,
        ..
    };
    p.ingress_stages.push(STAGE_ID_CLI_IN_URL_HSTS);
    p.ingress_stages.push(STAGE_ID_CLI_IN_SSRF_GUARD);
    p.ingress_stages.push(STAGE_ID_CLI_IN_CACHE_LOOKUP);
    p.ingress_stages.push(STAGE_ID_CLI_IN_COOKIE_LOAD);
    p.ingress_stages.push(STAGE_ID_CLI_IN_DICT_NEGOTIATE);
    p.ingress_stages.push(STAGE_ID_CLI_IN_INTERCEPTOR_AUTH);

    p.egress_stages.push(STAGE_ID_CLI_OUT_COOKIE_STORE);
    p.egress_stages.push(STAGE_ID_CLI_OUT_ALT_SVC);
    p.egress_stages.push(STAGE_ID_CLI_OUT_DECOMPRESS);
    p.egress_stages.push(STAGE_ID_CLI_OUT_CACHE_STORE);
    p.egress_stages.push(STAGE_ID_CLI_OUT_AUTH_CHALLENGE);
    p.egress_stages.push(STAGE_ID_CLI_OUT_REDIRECT);
    return p;
}

// Constructs the default Server `WirePipeline` with standard ingress and egress stages.
fn default_server_pipeline() -> WirePipeline {
    var p = WirePipeline {
        bind_point:   WirePipelineBindPoint.Receive,
        role:         PipelineRole.Server,
        ingress_mask: STAGE_SRV_IN_DEFAULT_MASK,
        egress_mask:  STAGE_SRV_OUT_DEFAULT_MASK,
        is_valid:     true,
        ..
    };
    p.ingress_stages.push(STAGE_ID_SRV_IN_SLOWLORIS);
    p.ingress_stages.push(STAGE_ID_SRV_IN_EXPECT_100);
    p.ingress_stages.push(STAGE_ID_SRV_IN_EDGE_FILTER);
    p.ingress_stages.push(STAGE_ID_SRV_IN_RATELIMIT_IP);
    p.ingress_stages.push(STAGE_ID_SRV_IN_ROUTE_MATCH);
    p.ingress_stages.push(STAGE_ID_SRV_IN_RATELIMIT_ROUTE);
    p.ingress_stages.push(STAGE_ID_SRV_IN_CORS);
    p.ingress_stages.push(STAGE_ID_SRV_IN_CSRF);
    p.ingress_stages.push(STAGE_ID_SRV_IN_AUTH_COOKIE);
    p.ingress_stages.push(STAGE_ID_SRV_IN_AUTH_JWT);
    p.ingress_stages.push(STAGE_ID_SRV_IN_CACHE_LOOKUP);
    p.ingress_stages.push(STAGE_ID_SRV_IN_DECOMPRESS);

    p.egress_stages.push(STAGE_ID_SRV_OUT_ETAG);
    p.egress_stages.push(STAGE_ID_SRV_OUT_COMPRESS_GZIP);
    p.egress_stages.push(STAGE_ID_SRV_OUT_COMPRESS_BR);
    p.egress_stages.push(STAGE_ID_SRV_OUT_COMPRESS_ZSTD);
    p.egress_stages.push(STAGE_ID_SRV_OUT_CACHE_STORE);
    p.egress_stages.push(STAGE_ID_SRV_OUT_SECURITY_HEADERS);
    p.egress_stages.push(STAGE_ID_SRV_OUT_ALT_SVC);
    p.egress_stages.push(STAGE_ID_SRV_OUT_METRICS);
    p.egress_stages.push(STAGE_ID_SRV_OUT_ACCESS_LOG);
    return p;
}

// Creates an immutable Pipeline State Object (VkCreateGraphicsPipelines).
fn create_wire_pipeline(
    dev:  const WireDevice&,
    info: const WirePipelineCreateInfo&,
) -> WirePipeline, WireResult {
    guard dev.is_active else {
        return WirePipeline { is_valid: false, .. }, WireResult.ErrorInitializationFailed;
    }
    var pipe = if info.role == PipelineRole.Server {
        default_server_pipeline()
    } else {
        default_client_pipeline()
    };
    pipe.bind_point = info.bind_point;
    pipe.layout = info.layout;
    pipe.ingress_mask = info.ingress_mask;
    pipe.egress_mask = info.egress_mask;
    pipe.is_valid = true;
    return pipe, WireResult.Success;
}

// Binds a Pipeline State Object to the command buffer (VkCmdBindPipeline).
fn cmd_bind_pipeline(
    cmd:        WireCommandBuffer&,
    bind_point: WirePipelineBindPoint,
    pipe:       const WirePipeline&,
) -> WireResult {
    guard cmd.state == WireCommandBufferState.Recording else {
        cmd.has_error = true;
        return WireResult.ErrorCommandNotRecording;
    }
    guard pipe.is_valid && pipe.bind_point == bind_point else {
        cmd.has_error = true;
        return WireResult.ErrorInitializationFailed;
    }
    return WireResult.Success;
}

// Destroys a pipeline object and releases its configuration (VkDestroyPipeline).
fn destroy_wire_pipeline(pipe: WirePipeline&) {
    pipe.is_valid = false;
}
