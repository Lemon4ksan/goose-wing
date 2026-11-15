# `wire`

Package `wire` provides a Vulkan-style explicit zero-allocation networking
hierarchy, command buffer recording, composable L7 stage pipelines, Sans-IO
HTTP/1.1, HTTP/2, and HTTP/3 codecs, and batched transport queue submission for
`goose-wing`.

```goose
var cmd = wire_kit::new_command_buffer();
wire_kit::begin_command_buffer(cmd, wire_kit::WireCommandBufferBeginInfo { flags: 0 });
wire_kit::write_h2_preface(cmd);
wire_kit::end_command_buffer(cmd);
```

## Architecture & Vulkan Pipeline Mapping

The `wire` subsystem implements a 7-tier explicit networking architecture
mapping 1:1 to Khronos Vulkan 1.3 and 1.4 concepts:

| Tier | `wire` Type | Vulkan Equivalent | Source File | Role |
| :--- | :--- | :--- | :--- | :--- |
| **1** | `WireInstance` | `VkInstance` | `wire/types.goose` | Root runtime instance managing driver discovery and capabilities |
| **2** | `WirePhysicalDevice` | `VkPhysicalDevice` | `wire/types.goose` | Queries physical transport capabilities, driver kind, and queue families |
| **3** | `WireDevice` | `VkDevice` | `wire/types.goose` | Logical device handle configuring active socket features and queue allocations |
| **4** | `WireCommandPool` | `VkCommandPool` | `wire/pool.goose` | Explicit 64 KB memory allocator managing command buffer allocation and reset |
| **5** | `WirePipeline` | `VkPipeline` | `wire/pipeline.goose` | Pipeline State Objects (PSO) binding framing policies and stage bitmasks |
| **6** | `WireCommandBuffer` | `VkCommandBuffer` | `wire/cmd.goose` | Zero-allocation sequential command recorder with explicit FSM lifecycle |
| **7** | `WireQueue`, `WireFence`, `WireSemaphore` | `VkQueue`, `VkFence`, `VkSemaphore` | `wire/submit.goose`, `wire/sync.goose` | Batched network queue submission with CPU fences and timeline semaphores |

## Public API Reference

### 1. Result Codes (`wire/result.goose`)

```goose
enum WireResult {
    Success, NotReady, Timeout, Incomplete, ErrorOutOfHostMemory,
    ErrorOutOfDeviceMemory, ErrorInitializationFailed, ErrorDeviceLost,
    ErrorInvalidStreamId, ErrorFrameTooLarge, ErrorCommandRecordingActive,
    ErrorCommandNotRecording, ErrorCommandBufferLocked, ErrorUnknown
}
fn is_success(r: WireResult) -> bool
fn is_error(r: WireResult) -> bool
```

`is_success` returns `true` for completion states (`Success` and `Incomplete`),
while `is_error` returns `true` for any negative operational or state validation
failure (`ErrorOutOfHostMemory` through `ErrorUnknown`).

### 2. Instance, Physical & Logical Devices (`wire/types.goose`)

```goose
enum WireDriverKind { Auto, Standard, WindowsRIO, IoUring, Kqueue, AfXdp, Dpdk, SmartNicOffload, Mock }
struct WireDeviceConfig {
    driver: WireDriverKind, tcp_nodelay: bool, tcp_keepalive: bool,
    has_dont_fragment: bool, ip_ttl: i32, rx_buf_size: i32,
    tx_buf_size: i32, wscale: i32, mss: i32
}
struct WireSetting { id: u16, val: u32 }
struct WireFrameHeader { length: u32, frame_type: u8, flags: u8, stream_id: u32 }
struct WireQueueFamilyProperties { queue_flags: u32, queue_count: u32 }
struct WirePhysicalDeviceProperties {
    device_id: u32, driver_kind: WireDriverKind, max_buffer_capacity: u64,
    max_batch_size: u32, hardware_checksum: bool, zero_copy_supported: bool
}
struct WirePhysicalDeviceFeatures {
    hpack_compression: bool, tcp_zero_copy: bool, hardware_tls: bool, raw_frames: bool
}
struct WirePhysicalDevice {
    properties: WirePhysicalDeviceProperties,
    features: WirePhysicalDeviceFeatures,
    queue_family: WireQueueFamilyProperties
}
struct WireInstance { api_version: u32, device_count: u32, supported_drivers: u32 }
struct WireDeviceCreateInfo { config: WireDeviceConfig, enabled_features: WirePhysicalDeviceFeatures }
struct WireDevice {
    physical_device: WirePhysicalDevice, config: WireDeviceConfig,
    enabled_features: WirePhysicalDeviceFeatures, is_active: bool
}
fn enumerate_physical_devices(inst: const WireInstance&, out: WirePhysicalDevice[..4]&) -> WireResult
fn create_wire_device(phys: const WirePhysicalDevice&, info: const WireDeviceCreateInfo&) -> WireDevice, WireResult
fn destroy_wire_device(dev: WireDevice&)
```

`enumerate_physical_devices` populates up to 4 transport devices
(`WirePhysicalDevice[..4]`) supported by `inst`. `create_wire_device` validates
requested `enabled_features` against `phys.features` and returns an active
`WireDevice`; `destroy_wire_device` marks the device inactive.

### 3. Command Pool Allocator (`wire/pool.goose`)

```goose
const WIRE_COMMAND_POOL_CREATE_TRANSIENT_BIT: u32 = 0x01;
const WIRE_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT: u32 = 0x02;
const WIRE_COMMAND_POOL_RESET_RELEASE_RESOURCES_BIT: u32 = 0x01;
struct WireCommandPoolCreateInfo { flags: u32, queue_family_index: u32 }
struct WireCommandPool {
    flags: u32, queue_family_index: u32, allocated_count: u32,
    is_valid: bool, arena: u8[..65536]
}
fn create_command_pool(dev: const WireDevice&, info: const WireCommandPoolCreateInfo&) -> WireCommandPool, WireResult
fn reset_command_pool(pool: WireCommandPool&, flags: u32) -> WireResult
fn trim_command_pool(pool: WireCommandPool&)
fn destroy_command_pool(pool: WireCommandPool&)
```

`WireCommandPool` manages a bounded 64 KB (`u8[..65536]`) backing arena for
command buffer slices. `reset_command_pool` reclaims all sub-allocated bytes in
a single bulk pointer reset without individual buffer frees.

### 4. Pipeline State Objects & Composable L7 Stage Pipeline (`wire/pipeline.goose`)

```goose
enum PipelineRole { Client, Server }
enum StageVerdict {
    Continue, ShortCircuit { status_code: u16 },
    RetryAuth, FollowRedirect, Abort { err_code: i32 }
}
struct PipelineState { verdict: StageVerdict }
enum ClientHookPhase { PreFlight, PreWireHop, PostWireHop }
enum ServerHookPhase { PreRoute, PostAuth, RouteHandler, PreSerialize }
struct NoOpStage {}
struct StageChain<First, Next> { first: First, next: Next }
enum WirePipelineBindPoint { Transmit, Receive }
struct WirePipelineLayout { max_frame_size: u32, push_constants: u8[..64] }
struct WirePipelineCreateInfo {
    bind_point: WirePipelineBindPoint, role: PipelineRole,
    layout: WirePipelineLayout, ingress_mask: u64, egress_mask: u64, flags: u32
}
struct WirePipeline {
    bind_point: WirePipelineBindPoint, role: PipelineRole,
    layout: WirePipelineLayout, ingress_stages: u8[..24],
    egress_stages: u8[..24], ingress_mask: u64, egress_mask: u64, is_valid: bool
}
fn begin_pipeline() -> PipelineState
fn can_continue(p: const PipelineState&) -> bool
fn step(p: PipelineState&, next: StageVerdict) -> bool
fn chain_stages<First, Next>(first: First, next: Next) -> StageChain<First, Next>
fn default_client_pipeline() -> WirePipeline
fn default_server_pipeline() -> WirePipeline
fn add_ingress_stage(pipe: WirePipeline&, stage_id: u8) -> bool
fn add_egress_stage(pipe: WirePipeline&, stage_id: u8) -> bool
fn is_ingress_stage_enabled(pipe: const WirePipeline&, stage_id: u8) -> bool
fn is_egress_stage_enabled(pipe: const WirePipeline&, stage_id: u8) -> bool
fn enable_ingress_stage(pipe: WirePipeline&, mask_bit: u64)
fn disable_ingress_stage(pipe: WirePipeline&, mask_bit: u64)
fn enable_egress_stage(pipe: WirePipeline&, mask_bit: u64)
fn disable_egress_stage(pipe: WirePipeline&, mask_bit: u64)
fn create_wire_pipeline(dev: const WireDevice&, info: const WirePipelineCreateInfo&) -> WirePipeline, WireResult
fn cmd_bind_pipeline(cmd: WireCommandBuffer&, bind_point: WirePipelineBindPoint, pipe: const WirePipeline&) -> WireResult
fn destroy_wire_pipeline(pipe: WirePipeline&)
```

`WirePipeline` binds protocol framing limits (`WirePipelineLayout`) and 64-bit
stage bitmasks (`ingress_mask` and `egress_mask`) into an immutable Pipeline
State Object. Custom middleware stages compose at compile time via
`chain_stages(first, next)` without virtual dispatch or heap closures.

| Role & Direction | Built-in Stage Bitmask Constants |
| :--- | :--- |
| **Client Ingress** | `STAGE_CLI_IN_URL_HSTS`, `STAGE_CLI_IN_SSRF_GUARD`, `STAGE_CLI_IN_CACHE_LOOKUP`, `STAGE_CLI_IN_COOKIE_LOAD`, `STAGE_CLI_IN_DICT_NEGOTIATE`, `STAGE_CLI_IN_INTERCEPTOR_AUTH`, `STAGE_CLI_IN_DEFAULT_MASK` |
| **Client Egress** | `STAGE_CLI_OUT_COOKIE_STORE`, `STAGE_CLI_OUT_ALT_SVC`, `STAGE_CLI_OUT_DECOMPRESS`, `STAGE_CLI_OUT_CACHE_STORE`, `STAGE_CLI_OUT_AUTH_CHALLENGE`, `STAGE_CLI_OUT_REDIRECT`, `STAGE_CLI_OUT_DEFAULT_MASK` |
| **Server Ingress** | `STAGE_SRV_IN_SLOWLORIS`, `STAGE_SRV_IN_EXPECT_100`, `STAGE_SRV_IN_EDGE_FILTER`, `STAGE_SRV_IN_RATELIMIT_IP`, `STAGE_SRV_IN_ROUTE_MATCH`, `STAGE_SRV_IN_RATELIMIT_ROUTE`, `STAGE_SRV_IN_CORS`, `STAGE_SRV_IN_CSRF`, `STAGE_SRV_IN_AUTH_COOKIE`, `STAGE_SRV_IN_AUTH_JWT`, `STAGE_SRV_IN_CACHE_LOOKUP`, `STAGE_SRV_IN_DECOMPRESS`, `STAGE_SRV_IN_DEFAULT_MASK` |
| **Server Egress** | `STAGE_SRV_OUT_ETAG`, `STAGE_SRV_OUT_COMPRESS_GZIP`, `STAGE_SRV_OUT_COMPRESS_BR`, `STAGE_SRV_OUT_COMPRESS_ZSTD`, `STAGE_SRV_OUT_CACHE_STORE`, `STAGE_SRV_OUT_SECURITY_HEADERS`, `STAGE_SRV_OUT_ALT_SVC`, `STAGE_SRV_OUT_METRICS`, `STAGE_SRV_OUT_ACCESS_LOG`, `STAGE_SRV_OUT_DEFAULT_MASK` |

### 5. Synchronization2 Primitives (`wire/sync.goose`)

```goose
const WIRE_PIPELINE_STAGE_NONE: u64 = 0x00000000;
const WIRE_PIPELINE_STAGE_HOST_BIT: u64 = 0x00000001;
const WIRE_PIPELINE_STAGE_TRANSFER_BIT: u64 = 0x00000002;
const WIRE_PIPELINE_STAGE_SOCKET_BIT: u64 = 0x00000004;
const WIRE_PIPELINE_STAGE_NIC_TX_BIT: u64 = 0x00000008;
const WIRE_PIPELINE_STAGE_ALL_COMMANDS: u64 = 0x00000010;
enum WireFenceStatus { Unsignaled, Signaled }
struct WireFenceCreateInfo { flags: u32 }
struct WireFence { status: WireFenceStatus, signaled_val: u64, is_valid: bool }
enum WireSemaphoreType { Binary, Timeline }
struct WireSemaphoreCreateInfo { semaphore_type: WireSemaphoreType, initial_value: u64 }
struct WireSemaphore { semaphore_type: WireSemaphoreType, value: u64, is_valid: bool }
struct WireSubmitInfo {
    stage_mask: u64, wait_semaphore: u64,
    signal_semaphore: u64, bytes_submitted: u64
}
fn create_wire_fence(dev: const WireDevice&, info: const WireFenceCreateInfo&) -> WireFence, WireResult
fn reset_wire_fence(fence: WireFence&) -> WireResult
fn wait_for_wire_fence(fence: const WireFence&, timeout_ns: u64) -> WireResult
fn get_wire_fence_status(fence: const WireFence&) -> WireResult
fn destroy_wire_fence(fence: WireFence&)
fn create_wire_semaphore(dev: const WireDevice&, info: const WireSemaphoreCreateInfo&) -> WireSemaphore, WireResult
fn signal_wire_semaphore(sem: WireSemaphore&, val: u64) -> WireResult
fn wait_wire_semaphore(sem: const WireSemaphore&, val: u64) -> WireResult
fn destroy_wire_semaphore(sem: WireSemaphore&)
```

`WireFence` synchronizes host CPU completion checks against queue submissions.
`WireSemaphore` supports both `Binary` (`0` or `1`) and monotonic `Timeline`
counters; calling `signal_wire_semaphore` on a timeline semaphore with
`val < sem.value` returns `WireResult.ErrorInitializationFailed`.

### 6. Command Buffer Recording & FSM (`wire/cmd.goose`)

```goose
enum WireCommandBufferState { Initial, Recording, RecordingHeaders, Executable, Pending, Invalid }
struct WireCommandBufferBeginInfo { flags: u32 }
struct WireCommandBuffer {
    buf: u8[..16384], hpack_staging: u8[..8192],
    has_error: bool, state: WireCommandBufferState, flags: u32
}
fn allocate_command_buffer(pool: WireCommandPool&) -> WireCommandBuffer, WireResult
fn allocate_pool_arena_slice(pool: WireCommandPool&, byte_count: i64) -> u8[:], WireResult
fn commit_command_buffer_to_arena(pool: WireCommandPool&, cmd: const WireCommandBuffer&) -> const u8[:], WireResult
fn free_command_buffer(pool: WireCommandPool&, cmd: WireCommandBuffer&)
fn new_command_buffer() -> WireCommandBuffer
fn begin_command_buffer(cmd: WireCommandBuffer&, info: const WireCommandBufferBeginInfo&) -> WireResult
fn end_command_buffer(cmd: WireCommandBuffer&) -> WireResult
fn reset_command_buffer(cmd: WireCommandBuffer&, flags: u32 = 0) -> WireResult
fn available(cmd: const WireCommandBuffer&) -> i64
fn reset(cmd: WireCommandBuffer&)
fn write_u8(cmd: WireCommandBuffer&, val: u8) -> bool
fn write_u16_be(cmd: WireCommandBuffer&, val: u16) -> bool
fn write_u24_be(cmd: WireCommandBuffer&, val: u32) -> bool
fn write_u32_be(cmd: WireCommandBuffer&, val: u32) -> bool
fn write_raw(cmd: WireCommandBuffer&, data: const u8[:]) -> bool
fn write_h2_preface(cmd: WireCommandBuffer&) -> bool
fn write_h2_frame_header(cmd: WireCommandBuffer&, length: u32, frame_type: u8, flags: u8, stream_id: u32) -> bool
fn write_h2_settings(cmd: WireCommandBuffer&, flags: u8, pairs: const u32[:]) -> bool
fn write_h2_window_update(cmd: WireCommandBuffer&, stream_id: u32, increment: u32) -> bool
fn write_h2_priority_update(cmd: WireCommandBuffer&, prioritized_stream_id: u32, priority_field_value: const u8[:]) -> bool
fn write_h2_rst_stream(cmd: WireCommandBuffer&, stream_id: u32, error_code: u32) -> bool
fn write_h2_ping(cmd: WireCommandBuffer&, opaque_data: const u8[:], is_ack: bool) -> bool
fn write_h2_data(cmd: WireCommandBuffer&, stream_id: u32, payload: const u8[:], end_stream: bool) -> bool
fn begin_h2_headers(cmd: WireCommandBuffer&, stream_id: u32, end_stream: bool, end_headers: bool = true) -> bool
fn hpack_indexed(cmd: WireCommandBuffer&, index: u64) -> bool
fn hpack_literal_without_indexing(cmd: WireCommandBuffer&, name: const u8[:], value: const u8[:]) -> bool
fn hpack_literal_never_indexed(cmd: WireCommandBuffer&, name: const u8[:], value: const u8[:]) -> bool
fn end_h2_headers(cmd: WireCommandBuffer&) -> bool
fn cmd_encode_h1_request(cmd: WireCommandBuffer&, method: const u8[:], path: const u8[:], host: const u8[:], headers: const wing::HeaderMap&, body: const u8[:]) -> bool
fn cmd_encode_h1_response(cmd: WireCommandBuffer&, status_code: u16, reason: const u8[:], headers: const wing::HeaderMap&, body: const u8[:]) -> bool
fn cmd_encode_h2_headers_map(cmd: WireCommandBuffer&, stream_id: u32, status_code: u16, headers: const wing::HeaderMap&, end_stream: bool) -> bool
fn cmd_encode_h3_headers_map(cmd: WireCommandBuffer&, status_code: u16, headers: const wing::HeaderMap&) -> bool
```

`WireCommandBuffer` records protocol frames into a 16 KB buffer (`u8[..16384]`)
with an 8 KB HPACK staging arena (`u8[..8192]`). Recording follows a strict
lifecycle (`Initial` -> `Recording` -> `Executable`): `begin_h2_headers`
transitions to `RecordingHeaders` while accumulating HPACK fields in
`hpack_staging`, and `end_h2_headers` emits the 9-byte HTTP/2 `HEADERS` frame
header followed by the staged block before returning to `Recording`. Any
capacity overflow sets `cmd.has_error = true` and causes `end_command_buffer` to
reject the transition to `Executable`.

### 7. Tier 1 Sans-IO Codecs (`wire/h1.goose`, `wire/hpack.goose`, `wire/h2.goose`, `wire/h3.goose`)

```goose
// HTTP/1.1 Wire Codec (wire/h1.goose, RFC 9112)
enum H1HeaderFilterMode { PreserveAll, StripHopByHop }
fn encode_h1_request<B>(method: const u8[:], target: const u8[:], host: const u8[:], headers: const wing::HeaderMap&, body: const u8[:], filter_mode: H1HeaderFilterMode, out: B&, http_version: const u8[:] = "HTTP/1.1") -> bool
fn encode_h1_response<B>(status_code: u16, reason: const u8[:], server_name: const u8[:], headers: const wing::HeaderMap&, body: const u8[:], is_head_request: bool, out: B&) -> bool
fn scan_h1_wire_field_name(src: const u8[:]) -> i64, bool
fn parse_h1_wire_status_line(line: const u8[:], out_status: u16&) -> bool
fn decode_h1_response_head(raw: const u8[:], out_status: u16&, out_headers: wing::HeaderMap&, allow_obs_fold: bool = false) -> i64, wing::HeaderParseError

// HPACK Primitive & Map Codec (wire/hpack.goose, RFC 7541)
fn hpack_encode_int<B>(out: B&, val: u64, prefix_bits: u8, prefix_mask: u8) -> bool
fn hpack_encode_indexed<B>(out: B&, index: u64) -> bool
fn hpack_encode_string<B>(out: B&, str: const u8[:]) -> bool
fn hpack_encode_literal_without_indexing<B>(out: B&, name: const u8[:], val: const u8[:]) -> bool
fn hpack_encode_literal_never_indexed<B>(out: B&, name: const u8[:], val: const u8[:]) -> bool
fn hpack_decode_int(src: const u8[:], offset: u64&, prefix_bits: u8) -> u64, bool
fn hpack_decode_string<B>(src: const u8[:], offset: u64&, out: B&) -> bool
fn encode_hpack_from_map<B>(dt: h2_internal::DynamicTable&, pseudo: const h2_internal::H2PseudoHeaders&, headers: const wing::HeaderMap&, out: B&, use_huffman: bool = true) -> bool
fn decode_hpack_to_map(dt: h2_internal::DynamicTable&, src: const u8[:], out_pseudo: h2_internal::H2PseudoHeaders&, out_headers: wing::HeaderMap&, max_header_list_size: u32 = 8192, validate_http2_rules: bool = true) -> u32

// HTTP/2 Frame Codec (wire/h2.goose, RFC 9113 & RFC 9218)
struct WireH2FrameReader { src: const u8[:], cursor: i64 }
fn encode_frame_header<B>(hdr: const WireFrameHeader&, out: B&) -> bool
fn parse_frame_header(buf: const u8[:]) -> WireFrameHeader, u32, bool
fn decode_h2_frame_header(raw: const u8[:], max_frame_size: u32 = 16384) -> WireFrameHeader, u32
fn encode_settings_frame<B>(settings: const WireSetting[:], out: B&) -> bool
fn encode_window_update_frame<B>(stream_id: u32, increment: u32, out: B&) -> bool
fn encode_priority_update_frame<B>(prioritized_stream_id: u32, urgency: u8, incremental: bool, out: B&) -> bool
fn encode_rst_stream_frame<B>(stream_id: u32, error_code: u32, out: B&) -> bool
fn encode_ping_frame<B>(payload: const u8[8], is_ack: bool, out: B&) -> bool
fn encode_data_frame<B>(stream_id: u32, payload: const u8[:], end_stream: bool, out: B&) -> bool
fn read_wire_h2_frame(raw: const u8[:], cursor: i64&) -> WireFrameHeader, const u8[:], bool
fn encode_h2_headers_frame_from_map<B>(dt: h2_internal::DynamicTable&, stream_id: u32, pseudo: const h2_internal::H2PseudoHeaders&, headers: const wing::HeaderMap&, end_stream: bool, out: B&, max_frame_size: u32 = 16384) -> bool

// HTTP/3 & QPACK Frame Codec (wire/h3.goose, RFC 9114 & RFC 9204)
fn encode_h3_headers_from_map<B1, B2>(tbl: h3_internal::QpackTable&, stream_id: u64, pseudo: const h3_internal::H3PseudoHeaders&, headers: const wing::HeaderMap&, out_enc_stream: B1&, out_frame: B2&) -> bool
fn decode_h3_headers_to_map(tbl: h3_internal::QpackTable&, stream_id: u64, qpack_payload: const u8[:], out_pseudo: h3_internal::H3PseudoHeaders&, out_headers: wing::HeaderMap&, max_field_section: u64 = 16384) -> h3_internal::QpackError
fn encode_h3_data_frame<B>(data: const u8[:], out: B&) -> bool
```

These Sans-IO codecs serialize and parse wire frames directly over caller
buffers (`out: B&`) and `wing::HeaderMap` instances. `hpack_decode_int`,
`hpack_decode_string`, and `read_wire_h2_frame` guarantee transactional cursor
semantics: on truncation or overflow they restore `offset` / `cursor` to its
initial value and return `false`.

### 8. Transport Queue Batch Submission (`wire/submit.goose`)

```goose
struct WireQueue {
    fd: i64, driver: WireDriverKind, config: WireDeviceConfig,
    bytes_sent: u64, bytes_received: u64, is_connected: bool
}
fn get_device_queue(device: const WireDevice&, queue_family_index: u32, queue_index: u32) -> WireQueue
fn new_wire_queue(cfg: const WireDeviceConfig&) -> WireQueue
fn connect_wire_queue(q: WireQueue&, host: const u8[:], port: u16, timeout_ms: u32 = 5000) -> bool
fn submit(q: WireQueue&, cmd: const WireCommandBuffer&) -> i64, bool
fn submit_slice(q: WireQueue&, data: const u8[:]) -> i64, bool
fn queue_submit_batch(q: WireQueue&, cmd_bufs: const WireCommandBuffer[:], info: const WireSubmitInfo&, fence: WireFence&) -> i64, WireResult
fn submit_to_transport(q: WireQueue&, cmd: const WireCommandBuffer&, transport: wing::Transport&) -> WireResult
fn submit_to_cork(cmd: const WireCommandBuffer&, cork: core::CorkBuffer&) -> bool
fn submit_to_cork(q: WireQueue&, cmd: const WireCommandBuffer&, cork: wing::ServerCork&, transport: wing::Transport&) -> WireResult
fn poll_recv(q: WireQueue&, out: u8[:], timeout_ms: u32 = 0) -> i64, bool
fn close_wire_queue(q: WireQueue&)
```

`submit` and `queue_submit_batch` require every `WireCommandBuffer` to be in the
`Executable` state (`!cmd.has_error`), draining all recorded octets across the
socket or `wing::Transport` and signaling the completion `WireFence` and
`WireSemaphore`. `submit_to_cork` coalesces small frames into a
`core::CorkBuffer` or `wing::ServerCork` arena and flushes to `transport` once
the watermark is reached.
