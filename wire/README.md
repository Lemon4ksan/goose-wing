# `wire`

Vulkan-style explicit zero-allocation networking, physical device hierarchy, command buffer recording, HPACK integer/string codecs, and batch queue submission for `goose-wing`.

## Architecture & Vulkan Pipeline Mapping

The `wire` subsystem implements a 7-tier explicit networking architecture mapping 1:1 to Khronos Vulkan 1.3/1.4 concepts:

1. **`WireInstance` (`VkInstance`)**: Root runtime instance managing driver discovery and capabilities.
2. **`WirePhysicalDevice` (`VkPhysicalDevice`)**: Queries physical transport capabilities, driver kind, and queue families.
3. **`WireDevice` (`VkDevice`)**: Logical device handle configuring active socket features and queue family allocations.
4. **`WireCommandPool` (`VkCommandPool`)**: Explicit 64 KB memory allocator managing command buffer allocation, recycling, and trimming.
5. **`WirePipeline` (`VkPipeline`)**: Pipeline State Objects (PSO) binding framing policies and layout constants.
6. **`WireCommandBuffer` (`VkCommandBuffer`)**: Zero-allocation sequential command recorder with FSM lifecycle (`Initial`, `Recording`, `RecordingHeaders`, `Executable`, `Pending`, `Invalid`).
7. **`WireQueue` & Synchronization2 (`VkQueue`, `VkFence`, `VkSemaphore`)**: Batched network queue submission with full-drain send, CPU fences, and timeline semaphores.

---

## Public API Reference

### Result Codes (`result.goose`)

- **`enum WireResult`**: Typed result codes mapping directly to `VkResult` (`Success`, `NotReady`, `Timeout`, `Incomplete`, `ErrorOutOfHostMemory`, `ErrorOutOfDeviceMemory`, `ErrorInitializationFailed`, `ErrorDeviceLost`, `ErrorInvalidStreamId`, `ErrorFrameTooLarge`, `ErrorCommandRecordingActive`, `ErrorCommandNotRecording`, `ErrorCommandBufferLocked`, `ErrorUnknown`).
- **`fn is_success(r: WireResult) -> bool`**: Returns true if result indicates successful completion.
- **`fn is_error(r: WireResult) -> bool`**: Returns true if result indicates an operational or validation error.

### Instance, Physical & Logical Devices (`types.goose`)

- **`enum WireDriverKind`**: Transport hardware driver family (`Standard`, `WindowsRIO`, `IoUring`, `Kqueue`, `AfXdp`, `Mock`).
- **`struct WireDeviceConfig`**: Low-level socket creation parameters (`driver`, `tcp_nodelay`, `tcp_keepalive`, `has_dont_fragment`, `ip_ttl`, `rx_buf_size`, `tx_buf_size`, `wscale`, `mss`).
- **`struct WireQueueFamilyProperties`**: Queue family capabilities (`queue_flags: u32`, `queue_count: u32`).
- **`struct WirePhysicalDeviceProperties`**: Physical limits (`device_id`, `driver_kind`, `max_buffer_capacity`, `max_batch_size`, `hardware_checksum`, `zero_copy_supported`).
- **`struct WirePhysicalDeviceFeatures`**: Fine-grained acceleration flags (`hpack_compression`, `tcp_zero_copy`, `hardware_tls`, `raw_frames`).
- **`struct WirePhysicalDevice`**: Physical transport device representation (`properties`, `features`, `queue_family`).
- **`struct WireInstance`**: Root instance context (`api_version`, `device_count`, `supported_drivers`).
- **`struct WireDeviceCreateInfo`**: Logical device creation info (`config`, `enabled_features`).
- **`struct WireDevice`**: Active logical device handle managing queues and memory resources (`physical_device`, `config`, `enabled_features`, `is_active`).
- **`fn enumerate_physical_devices(inst: const WireInstance&, out: WirePhysicalDevice[..4]&) -> WireResult`**: Enumerates available physical transport devices.
- **`fn create_wire_device(phys: const WirePhysicalDevice&, info: const WireDeviceCreateInfo&) -> WireDevice, WireResult`**: Instantiates a logical WireDevice.
- **`fn destroy_wire_device(dev: WireDevice&)`**: Shuts down logical device and marks inactive.

### Command Pool Allocator (`pool.goose`)

- **`struct WireCommandPoolCreateInfo`**: Creation info (`flags: u32`, `queue_family_index: u32`).
- **`struct WireCommandPool`**: Bounded 64 KB memory allocator arena (`flags`, `queue_family_index`, `allocated_count`, `is_valid`, `arena`).
- **Pool Creation Flags**: `WIRE_COMMAND_POOL_CREATE_TRANSIENT_BIT` (`0x01`), `WIRE_COMMAND_POOL_CREATE_RESET_COMMAND_BUFFER_BIT` (`0x02`).
- **Pool Reset Flags**: `WIRE_COMMAND_POOL_RESET_RELEASE_RESOURCES_BIT` (`0x01`).
- **`fn create_command_pool(dev: const WireDevice&, info: const WireCommandPoolCreateInfo&) -> WireCommandPool, WireResult`**: Allocates command pool from device.
- **`fn reset_command_pool(pool: WireCommandPool&, flags: u32) -> WireResult`**: Resets all pool allocations.
- **`fn trim_command_pool(pool: WireCommandPool&)`**: Trims unused memory capacity in pool arena.
- **`fn destroy_command_pool(pool: WireCommandPool&)`**: Invalidates pool and releases arena memory.

### Pipeline State Objects (`pipeline.goose`)

- **`enum WirePipelineBindPoint`**: Protocol pipeline direction (`Transmit`, `Receive`).
- **`struct WirePipelineLayout`**: Protocol sizing and push constants (`max_frame_size: u32`, `push_constants: u8[..64]`).
- **`struct WirePipelineCreateInfo`**: Pipeline creation info (`bind_point`, `layout`, `flags`).
- **`struct WirePipeline`**: Immutable pipeline state object (`bind_point`, `layout`, `is_valid`).
- **`fn create_wire_pipeline(dev: const WireDevice&, info: const WirePipelineCreateInfo&) -> WirePipeline, WireResult`**: Creates immutable PSO.
- **`fn cmd_bind_pipeline(cmd: WireCommandBuffer&, bind_point: WirePipelineBindPoint, pipe: const WirePipeline&) -> WireResult`**: Binds PSO to command buffer.
- **`fn destroy_wire_pipeline(pipe: WirePipeline&)`**: Releases pipeline state object.

### Synchronization2 Primitives (`sync.goose`)

- **Pipeline Stage Flags**: `WIRE_PIPELINE_STAGE_NONE` (`0x00`), `WIRE_PIPELINE_STAGE_HOST_BIT` (`0x01`), `WIRE_PIPELINE_STAGE_TRANSFER_BIT` (`0x02`), `WIRE_PIPELINE_STAGE_SOCKET_BIT` (`0x04`), `WIRE_PIPELINE_STAGE_NIC_TX_BIT` (`0x08`), `WIRE_PIPELINE_STAGE_ALL_COMMANDS` (`0x10`).
- **`enum WireFenceStatus`**: Fence state (`Unsignaled`, `Signaled`).
- **`struct WireFence`**: Host-device synchronization primitive (`status`, `signaled_val`, `is_valid`).
- **`fn create_wire_fence(dev: const WireDevice&, info: const WireFenceCreateInfo&) -> WireFence, WireResult`**: Creates a synchronization fence.
- **`fn reset_wire_fence(fence: WireFence&) -> WireResult`**: Resets fence to Unsignaled state.
- **`fn wait_for_wire_fence(fence: const WireFence&, timeout_ns: u64) -> WireResult`**: Polls or waits for fence signaling.
- **`fn get_wire_fence_status(fence: const WireFence&) -> WireResult`**: Queries non-blocking fence status.
- **`fn destroy_wire_fence(fence: WireFence&)`**: Destroys fence primitive.
- **`enum WireSemaphoreType`**: Semaphore kind (`Binary`, `Timeline`).
- **`struct WireSemaphore`**: Inter-batch synchronization primitive (`semaphore_type`, `value`, `is_valid`).
- **`fn create_wire_semaphore(dev: const WireDevice&, info: const WireSemaphoreCreateInfo&) -> WireSemaphore, WireResult`**: Creates semaphore.
- **`fn signal_wire_semaphore(sem: WireSemaphore&, val: u64) -> WireResult`**: Advances semaphore counter.
- **`fn wait_wire_semaphore(sem: const WireSemaphore&, val: u64) -> WireResult`**: Waits for semaphore counter threshold.
- **`fn destroy_wire_semaphore(sem: WireSemaphore&)`**: Destroys semaphore.
- **`struct WireSubmitInfo`**: Batch synchronization descriptor (`stage_mask`, `wait_semaphore`, `signal_semaphore`, `bytes_submitted`).

### Command Buffer Recording & FSM (`cmd.goose`)

- **`enum WireCommandBufferState`**: Lifecycle states (`Initial`, `Recording`, `RecordingHeaders`, `Executable`, `Pending`, `Invalid`).
- **`struct WireCommandBuffer`**: 16 KB binary frame recorder with 8 KB HPACK staging arena (`buf: u8[..16384]`, `hpack_staging: u8[..8192]`, `has_error: bool`, `state: WireCommandBufferState`, `flags: u32`).
- **`fn allocate_command_buffer(pool: WireCommandPool&) -> WireCommandBuffer, WireResult`**: Allocates buffer from pool in Initial state.
- **`fn free_command_buffer(pool: WireCommandPool&, cmd: WireCommandBuffer&)`**: Frees buffer back to pool.
- **`fn new_command_buffer() -> WireCommandBuffer`**: Instantiates a direct-recording command buffer.
- **`fn begin_command_buffer(cmd: WireCommandBuffer&, info: const WireCommandBufferBeginInfo&) -> WireResult`**: Transitions to Recording state.
- **`fn end_command_buffer(cmd: WireCommandBuffer&) -> WireResult`**: Validates buffer and transitions to Executable state.
- **`fn reset_command_buffer(cmd: WireCommandBuffer&, flags: u32) -> WireResult`**: Resets buffer back to Initial state.
- **`fn len(cmd: const WireCommandBuffer&) -> i64`**: Returns recorded wire byte count.
- **`fn available(cmd: const WireCommandBuffer&) -> i64`**: Returns remaining byte capacity in 16 KB buffer.
- **`fn reset(cmd: WireCommandBuffer&)`**: Clears recorded frame octets and error flags.
- **`fn write_u8(cmd: WireCommandBuffer&, val: u8) -> bool`**: Writes an 8-bit octet.
- **`fn write_u16_be(cmd: WireCommandBuffer&, val: u16) -> bool`**: Writes big-endian 16-bit integer.
- **`fn write_u24_be(cmd: WireCommandBuffer&, val: u32) -> bool`**: Writes 24-bit integer with range validation ($\le \text{0x00FFFFFF}$).
- **`fn write_u32_be(cmd: WireCommandBuffer&, val: u32) -> bool`**: Writes big-endian 32-bit integer.
- **`fn write_raw(cmd: WireCommandBuffer&, data: const u8[:]) -> bool`**: Appends raw byte slice.
- **`fn write_h2_preface(cmd: WireCommandBuffer&) -> bool`**: Appends 24-byte HTTP/2 client connection preface.
- **`fn write_h2_frame_header(cmd: WireCommandBuffer&, hdr: const WireFrameHeader&) -> bool`**: Writes 9-byte binary frame header.
- **`fn write_h2_settings(cmd: WireCommandBuffer&, settings: const WireSetting[:]) -> bool`**: Writes HTTP/2 SETTINGS frame.
- **`fn write_h2_window_update(cmd: WireCommandBuffer&, stream_id: u32, increment: u32) -> bool`**: Writes WINDOW_UPDATE frame.
- **`fn write_h2_priority_update(cmd: WireCommandBuffer&, prioritized_stream_id: u32, urgency: u8, incremental: bool) -> bool`**: Writes RFC 9218 PRIORITY_UPDATE frame.
- **`fn write_h2_rst_stream(cmd: WireCommandBuffer&, stream_id: u32, error_code: u32) -> bool`**: Writes RST_STREAM frame.
- **`fn write_h2_ping(cmd: WireCommandBuffer&, payload: const u8[8], is_ack: bool) -> bool`**: Writes 8-byte PING frame.
- **`fn write_h2_data(cmd: WireCommandBuffer&, stream_id: u32, payload: const u8[:], end_stream: bool) -> bool`**: Writes DATA frame.
- **`fn begin_h2_headers(cmd: WireCommandBuffer&, stream_id: u32, flags: u8) -> bool`**: Opens dynamic HEADERS block and enters RecordingHeaders state.
- **`fn hpack_indexed(cmd: WireCommandBuffer&, index: u64) -> bool`**: Encodes indexed header field into staging arena.
- **`fn hpack_literal_without_indexing(cmd: WireCommandBuffer&, name: const u8[:], val: const u8[:]) -> bool`**: Encodes literal header without indexing.
- **`fn hpack_literal_never_indexed(cmd: WireCommandBuffer&, name: const u8[:], val: const u8[:]) -> bool`**: Encodes literal header never indexed.
- **`fn end_h2_headers(cmd: WireCommandBuffer&) -> bool`**: Closes HEADERS block, back-patches length, and returns to Recording state.

### Transport Queue Batch Submission (`submit.goose`)

- **`struct WireQueue`**: Physical transport queue state (`fd: i64`, `driver: WireDriverKind`, `config: WireDeviceConfig`, `bytes_sent: u64`, `bytes_received: u64`, `is_connected: bool`).
- **`fn get_device_queue(device: const WireDevice&, queue_family_index: u32, queue_index: u32) -> WireQueue`**: Obtains queue from logical device.
- **`fn new_wire_queue(cfg: const WireDeviceConfig&) -> WireQueue`**: Initializes independent transport queue.
- **`fn connect_wire_queue(q: WireQueue&, host: const u8[:], port: u16, timeout_ms: u32 = 5000) -> bool`**: Establishes TCP transport connection.
- **`fn submit(q: WireQueue&, cmd: const WireCommandBuffer&) -> i64, bool`**: Transmits command buffer with full-drain loop.
- **`fn submit_slice(q: WireQueue&, data: const u8[:]) -> i64, bool`**: Transmits raw slice directly with full-drain loop.
- **`fn queue_submit_batch(q: WireQueue&, cmd_bufs: const WireCommandBuffer[:], info: const WireSubmitInfo&, fence: WireFence&) -> i64, WireResult`**: Atomically transmits batch of command buffers and signals completion fence.
- **`fn poll_recv(q: WireQueue&, out: u8[:], timeout_ms: u32 = 0) -> i64, bool`**: Polls transport socket for incoming octets.
- **`fn close_wire_queue(q: WireQueue&)`**: Closes transport socket and resets `fd = -1`.
