// SPDX-License-Identifier: Apache-2.0
// Copyright (c) 2026 Lemon4ksan

// Vulkan-style Pipeline State Objects (PSO) and Tier 2 Composable L7 Stage Pipeline.
namespace wire;

import std;
import core from "..";
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
    BodyChunk,
    RouteHandler,
    PreSerialize,
    OnError,
    AfterResponse,
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

// Server Ingress Stage Slot IDs (0..13) and Bitmasks
const STAGE_ID_SRV_IN_SLOWLORIS:         u8 = 0;
const STAGE_ID_SRV_IN_EXPECT_100:        u8 = 1;
const STAGE_ID_SRV_IN_EDGE_FILTER:       u8 = 2;
const STAGE_ID_SRV_IN_RATELIMIT_IP:      u8 = 3;
const STAGE_ID_SRV_IN_ROUTE_MATCH:       u8 = 4;
const STAGE_ID_SRV_IN_RATELIMIT_ROUTE:   u8 = 5;
const STAGE_ID_SRV_IN_CORS:              u8 = 6;
const STAGE_ID_SRV_IN_CSRF:              u8 = 7;
const STAGE_ID_SRV_IN_AUTH_COOKIE:       u8 = 8;
const STAGE_ID_SRV_IN_AUTH_JWT:          u8 = 9;
const STAGE_ID_SRV_IN_CACHE_LOOKUP:      u8 = 10;
const STAGE_ID_SRV_IN_DECOMPRESS:        u8 = 11;
const STAGE_ID_SRV_IN_CONTENT_DIGEST:    u8 = 12;
const STAGE_ID_SRV_IN_RATELIMIT_SUBJECT: u8 = 13;

const STAGE_SRV_IN_SLOWLORIS:         u64 = (1 as u64) << 0;
const STAGE_SRV_IN_EXPECT_100:        u64 = (1 as u64) << 1;
const STAGE_SRV_IN_EDGE_FILTER:       u64 = (1 as u64) << 2;
const STAGE_SRV_IN_RATELIMIT_IP:      u64 = (1 as u64) << 3;
const STAGE_SRV_IN_ROUTE_MATCH:       u64 = (1 as u64) << 4;
const STAGE_SRV_IN_RATELIMIT_ROUTE:   u64 = (1 as u64) << 5;
const STAGE_SRV_IN_CORS:              u64 = (1 as u64) << 6;
const STAGE_SRV_IN_CSRF:              u64 = (1 as u64) << 7;
const STAGE_SRV_IN_AUTH_COOKIE:       u64 = (1 as u64) << 8;
const STAGE_SRV_IN_AUTH_JWT:          u64 = (1 as u64) << 9;
const STAGE_SRV_IN_CACHE_LOOKUP:      u64 = (1 as u64) << 10;
const STAGE_SRV_IN_DECOMPRESS:        u64 = (1 as u64) << 11;
const STAGE_SRV_IN_CONTENT_DIGEST:    u64 = (1 as u64) << 12;
const STAGE_SRV_IN_RATELIMIT_SUBJECT: u64 = (1 as u64) << 13;

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

// Programmable User Stage Slot IDs (16..19) and Bitmasks
const STAGE_ID_USER_0: u8 = 16;
const STAGE_ID_USER_1: u8 = 17;
const STAGE_ID_USER_2: u8 = 18;
const STAGE_ID_USER_3: u8 = 19;

const STAGE_USER_0: u64 = (1 as u64) << 16;
const STAGE_USER_1: u64 = (1 as u64) << 17;
const STAGE_USER_2: u64 = (1 as u64) << 18;
const STAGE_USER_3: u64 = (1 as u64) << 19;

inline fn is_user_stage_slot(stage_id: u8) -> bool {
    return stage_id >= STAGE_ID_USER_0 && stage_id <= STAGE_ID_USER_3;
}

inline fn is_valid_stage_id(stage_id: u8) -> bool {
    return stage_id < 64;
}

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

// Vulkan-style descriptor slot binding associating a pipeline stage ID with a parameter slot (0..3).
struct StageBinding {
    stage_id:   u8 = 0,
    param_slot: u8 = 0,
}

// Declarative Pipeline State Object (VkPipeline) and Programmable Stage Conveyor.
struct WirePipeline {
    bind_point:       WirePipelineBindPoint = WirePipelineBindPoint.Transmit,
    role:             PipelineRole          = PipelineRole.Client,
    layout:           WirePipelineLayout    = WirePipelineLayout { .. },
    ingress_stages:   u8[..64]              = [],
    egress_stages:    u8[..64]              = [],
    custom_bindings:  StageBinding[..64]    = [],
    ingress_mask:     u64                   = STAGE_CLI_IN_DEFAULT_MASK,
    egress_mask:      u64                   = STAGE_CLI_OUT_DEFAULT_MASK,
    has_custom_order: bool                  = false,
    is_valid:         bool                  = true,
}

const MAX_PIPELINE_STAGES: i64 = 64;
const VALID_STAGE_MASK:    u64 = 0xFFFFFFFFFFFFFFFF;

const DEFAULT_CLI_IN_STAGES: const u8[6] = [
    STAGE_ID_CLI_IN_URL_HSTS,
    STAGE_ID_CLI_IN_SSRF_GUARD,
    STAGE_ID_CLI_IN_CACHE_LOOKUP,
    STAGE_ID_CLI_IN_COOKIE_LOAD,
    STAGE_ID_CLI_IN_DICT_NEGOTIATE,
    STAGE_ID_CLI_IN_INTERCEPTOR_AUTH,
];

const DEFAULT_CLI_OUT_STAGES: const u8[6] = [
    STAGE_ID_CLI_OUT_ALT_SVC,
    STAGE_ID_CLI_OUT_DECOMPRESS,
    STAGE_ID_CLI_OUT_AUTH_CHALLENGE,
    STAGE_ID_CLI_OUT_COOKIE_STORE,
    STAGE_ID_CLI_OUT_CACHE_STORE,
    STAGE_ID_CLI_OUT_REDIRECT,
];

const DEFAULT_SRV_IN_STAGES: const u8[12] = [
    STAGE_ID_SRV_IN_SLOWLORIS,
    STAGE_ID_SRV_IN_EXPECT_100,
    STAGE_ID_SRV_IN_EDGE_FILTER,
    STAGE_ID_SRV_IN_RATELIMIT_IP,
    STAGE_ID_SRV_IN_ROUTE_MATCH,
    STAGE_ID_SRV_IN_RATELIMIT_ROUTE,
    STAGE_ID_SRV_IN_CORS,
    STAGE_ID_SRV_IN_CSRF,
    STAGE_ID_SRV_IN_AUTH_COOKIE,
    STAGE_ID_SRV_IN_AUTH_JWT,
    STAGE_ID_SRV_IN_CACHE_LOOKUP,
    STAGE_ID_SRV_IN_DECOMPRESS,
];

const DEFAULT_SRV_OUT_STAGES: const u8[9] = [
    STAGE_ID_SRV_OUT_ETAG,
    STAGE_ID_SRV_OUT_COMPRESS_GZIP,
    STAGE_ID_SRV_OUT_COMPRESS_BR,
    STAGE_ID_SRV_OUT_COMPRESS_ZSTD,
    STAGE_ID_SRV_OUT_CACHE_STORE,
    STAGE_ID_SRV_OUT_SECURITY_HEADERS,
    STAGE_ID_SRV_OUT_ALT_SVC,
    STAGE_ID_SRV_OUT_METRICS,
    STAGE_ID_SRV_OUT_ACCESS_LOG,
];

// Returns true when every set bit in `sub` is also set in `sup`.
inline fn stage_mask_subset_of(sub: u64, sup: u64) -> bool {
    return (sub & (~sup)) == 0;
}

// Returns the number of active stage bits set within `VALID_STAGE_MASK`.
inline fn count_enabled_stages(mask: u64) -> i64 {
    return popcount(mask & VALID_STAGE_MASK);
}

// Invokes `F(stage_id)` for each enabled stage bit in `mask` in ascending slot order in O(popcount) steps.
inline fn each_enabled_stage<F>(var mask: u64) {
    while mask != 0 {
        let stage_id = (ctz(mask) as u8);
        F(stage_id);
        mask = mask & core::sub_sat_u64(mask, 1);
    }
}

// Validates that `mask` contains only defined stage slot bits within `VALID_STAGE_MASK` (`FlagBoundary.STRICT`).
inline fn is_valid_stage_mask(mask: u64) -> bool {
    return stage_mask_subset_of(mask, VALID_STAGE_MASK) && count_enabled_stages(mask) <= MAX_PIPELINE_STAGES;
}

// Appends a stage slot ID to `pipe.ingress_stages` and enables its corresponding bit in `pipe.ingress_mask`.
fn add_ingress_stage(pipe: WirePipeline&, stage_id: u8) -> bool {
    guard is_valid_stage_id(stage_id) else { return false; }
    if !pipe.ingress_stages[..].contains_byte(stage_id) {
        guard pipe.ingress_stages.try_push(stage_id) else { return false; }
    }
    pipe.ingress_mask = pipe.ingress_mask | core::shl_sat_u64(1, stage_id);
    return true;
}

// Appends a stage slot ID to `pipe.egress_stages` and enables its corresponding bit in `pipe.egress_mask`.
fn add_egress_stage(pipe: WirePipeline&, stage_id: u8) -> bool {
    guard is_valid_stage_id(stage_id) else { return false; }
    if !pipe.egress_stages[..].contains_byte(stage_id) {
        guard pipe.egress_stages.try_push(stage_id) else { return false; }
    }
    pipe.egress_mask = pipe.egress_mask | core::shl_sat_u64(1, stage_id);
    return true;
}

// Appends a parameterized stage binding to `pipe.custom_bindings` and enables `pipe.has_custom_order`.
fn add_stage_binding(pipe: WirePipeline&, stage_id: u8, param_slot: u8 = 0) -> bool {
    guard is_valid_stage_id(stage_id) && param_slot < 4 else { return false; }
    guard pipe.custom_bindings.try_push(StageBinding {
        stage_id:   stage_id,
        param_slot: param_slot,
    }) else {
        return false;
    }
    pipe.has_custom_order = true;
    pipe.ingress_mask = pipe.ingress_mask | core::shl_sat_u64(1, stage_id);
    return true;
}

// Clears custom stage bindings and restores bitmask-driven stage ordering.
fn clear_stage_bindings(pipe: WirePipeline&) {
    pipe.custom_bindings.clear();
    pipe.has_custom_order = false;
}

// Transactionally replaces `pipe.custom_bindings` and `pipe.ingress_mask` for runtime xDS / control-plane updates.
fn replace_ingress_bindings(pipe: WirePipeline&, bindings: const StageBinding[:]) -> bool {
    guard bindings.len <= MAX_PIPELINE_STAGES else { return false; }
    let saved_bindings = pipe.custom_bindings;
    let saved_mask = pipe.ingress_mask;
    let saved_custom = pipe.has_custom_order;
    var committed = false;
    defer if !committed {
        pipe.custom_bindings = saved_bindings;
        pipe.ingress_mask = saved_mask;
        pipe.has_custom_order = saved_custom;
    };
    pipe.custom_bindings.clear();
    var new_mask: u64 = 0;
    for &b in bindings {
        guard is_valid_stage_id(b.stage_id) && b.param_slot < 4 else { return false; }
        guard pipe.custom_bindings.try_push(b) else { return false; }
        new_mask = new_mask | core::shl_sat_u64(1, b.stage_id);
    }
    pipe.ingress_mask = new_mask;
    pipe.has_custom_order = bindings.len > 0;
    committed = true;
    return true;
}

inline fn is_ingress_stage_enabled(pipe: const WirePipeline&, stage_id: u8) -> bool {
    guard is_valid_stage_id(stage_id) else { return false; }
    return (pipe.ingress_mask & core::shl_sat_u64(1, stage_id)) != 0;
}

inline fn is_egress_stage_enabled(pipe: const WirePipeline&, stage_id: u8) -> bool {
    guard is_valid_stage_id(stage_id) else { return false; }
    return (pipe.egress_mask & core::shl_sat_u64(1, stage_id)) != 0;
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
    let _ = p.ingress_stages.try_set(DEFAULT_CLI_IN_STAGES[..]);
    let _ = p.egress_stages.try_set(DEFAULT_CLI_OUT_STAGES[..]);
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
    let _ = p.ingress_stages.try_set(DEFAULT_SRV_IN_STAGES[..]);
    let _ = p.egress_stages.try_set(DEFAULT_SRV_OUT_STAGES[..]);
    return p;
}

// Creates an immutable Pipeline State Object (VkCreateGraphicsPipelines).
fn create_wire_pipeline(
    dev:  const WireDevice&,
    info: const WirePipelineCreateInfo&,
) -> WirePipeline, WireResult {
    guard dev.is_active && is_valid_stage_mask(info.ingress_mask) && is_valid_stage_mask(info.egress_mask) else {
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
    each_enabled_stage(info.ingress_mask) { stage_id =>
        let _ = add_ingress_stage(pipe, stage_id);
    };
    each_enabled_stage(info.egress_mask) { stage_id =>
        let _ = add_egress_stage(pipe, stage_id);
    };
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
