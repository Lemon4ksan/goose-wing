# `wire`

Vulkan-style zero-allocation wire framing primitives, command buffer recording, HPACK integer/string codecs, and transport queue batch submission for `goose-wing`.

## Public API

### Types & Wire Constants (`types.goose`, RFC 9113, RFC 9218)

- **`enum WireDriverKind`**: Transport hardware driver family (`Standard`, `WindowsRIO`, `IoUring`, `Kqueue`, `AfXdp`, `Mock`).
- **`struct WireDeviceConfig`**: Physical socket and driver configuration (`driver`, `tcp_nodelay`, `tcp_keepalive`, `has_dont_fragment`, `ip_ttl`, `rx_buf_size`, `tx_buf_size`, `wscale`, `mss`).
- **`struct WireSetting`**: Single HTTP/2 SETTINGS entry (`id: u16`, `val: u32`).
- **`fn h2_setting(setting_id: u16, setting_val: u32) -> WireSetting`**: Constructs setting parameter entry.
- **`struct WireFrameHeader`**: 9-byte HTTP/2 binary frame header (`length: u32`, `frame_type: u8`, `flags: u8`, `stream_id: u32`).
- **Frame Type Constants**: `H2_FRAME_DATA` (`0x00`), `H2_FRAME_HEADERS` (`0x01`), `H2_FRAME_PRIORITY` (`0x02`), `H2_FRAME_RST_STREAM` (`0x03`), `H2_FRAME_SETTINGS` (`0x04`), `H2_FRAME_PUSH_PROMISE` (`0x05`), `H2_FRAME_PING` (`0x06`), `H2_FRAME_GOAWAY` (`0x07`), `H2_FRAME_WINDOW_UPDATE` (`0x08`), `H2_FRAME_CONTINUATION` (`0x09`), `H2_FRAME_PRIORITY_UPDATE` (`0x10`).
- **Frame Flag Constants**: `H2_FLAG_NONE` (`0x00`), `H2_FLAG_END_STREAM` (`0x01`), `H2_FLAG_ACK` (`0x01`), `H2_FLAG_END_HEADERS` (`0x04`), `H2_FLAG_PADDED` (`0x08`), `H2_FLAG_PRIORITY` (`0x20`).
- **Setting ID Constants**: `H2_SETTING_HEADER_TABLE_SIZE` (`0x01`), `H2_SETTING_ENABLE_PUSH` (`0x02`), `H2_SETTING_MAX_CONCURRENT_STREAMS` (`0x03`), `H2_SETTING_INITIAL_WINDOW_SIZE` (`0x04`), `H2_SETTING_MAX_FRAME_SIZE` (`0x05`), `H2_SETTING_MAX_HEADER_LIST_SIZE` (`0x06`), `H2_SETTING_ENABLE_CONNECT_PROTO` (`0x08`), `H2_SETTING_NO_RFC7540_PRIORITIES` (`0x09`).
- **Connection Preface**: `H2_CLIENT_PREFACE: const u8[24]`: 24-byte client connection preface (`PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n`).

### Command Buffer Recording (`cmd.goose`)

- **`struct WireCommandBuffer`**: Zero-allocation sequential command recorder (`buf: u8[..4096]`, `hpack_staging: u8[..2048]`, `has_error: bool`).
- **`fn new_command_buffer() -> WireCommandBuffer`**: Initializes empty command buffer recorder.
- **`fn len(cmd: const WireCommandBuffer&) -> i64`**: Returns recorded byte count.
- **`fn available(cmd: const WireCommandBuffer&) -> i64`**: Returns available byte capacity remaining.
- **`fn reset(cmd: WireCommandBuffer&)`**: Clears recorded frame bytes and errors for buffer reuse.
- **`fn write_u8(cmd: WireCommandBuffer&, val: u8) -> bool`**: Appends an 8-bit integer.
- **`fn write_u16_be(cmd: WireCommandBuffer&, val: u16) -> bool`**: Appends big-endian 16-bit integer.
- **`fn write_u24_be(cmd: WireCommandBuffer&, val: u32) -> bool`**: Appends big-endian 24-bit frame length.
- **`fn write_u32_be(cmd: WireCommandBuffer&, val: u32) -> bool`**: Appends big-endian 32-bit integer.
- **`fn write_raw(cmd: WireCommandBuffer&, data: const u8[:]) -> bool`**: Appends raw byte slice.
- **`fn write_h2_preface(cmd: WireCommandBuffer&) -> bool`**: Appends HTTP/2 24-byte client connection preface.
- **`fn write_h2_frame_header(cmd: WireCommandBuffer&, hdr: const WireFrameHeader&) -> bool`**: Encodes 9-byte frame header into recorder.
- **`fn write_h2_settings(cmd: WireCommandBuffer&, settings: const WireSetting[:]) -> bool`**: Encodes SETTINGS frame.
- **`fn write_h2_window_update(cmd: WireCommandBuffer&, stream_id: u32, increment: u32) -> bool`**: Encodes WINDOW_UPDATE frame.
- **`fn write_h2_priority_update(cmd: WireCommandBuffer&, prioritized_stream_id: u32, urgency: u8, incremental: bool) -> bool`**: Encodes RFC 9218 PRIORITY_UPDATE frame.
- **`fn write_h2_rst_stream(cmd: WireCommandBuffer&, stream_id: u32, error_code: u32) -> bool`**: Encodes RST_STREAM frame.
- **`fn write_h2_ping(cmd: WireCommandBuffer&, payload: const u8[8], is_ack: bool) -> bool`**: Encodes PING frame.
- **`fn write_h2_data(cmd: WireCommandBuffer&, stream_id: u32, payload: const u8[:], end_stream: bool) -> bool`**: Encodes DATA frame.
- **`fn begin_h2_headers(cmd: WireCommandBuffer&, stream_id: u32, flags: u8) -> bool`**: Opens staged HPACK HEADERS block.
- **`fn hpack_indexed(cmd: WireCommandBuffer&, index: u64) -> bool`**: Appends indexed header representation into staged block.
- **`fn hpack_literal_without_indexing(cmd: WireCommandBuffer&, name: const u8[:], val: const u8[:]) -> bool`**: Appends literal header field without indexing.
- **`fn hpack_literal_never_indexed(cmd: WireCommandBuffer&, name: const u8[:], val: const u8[:]) -> bool`**: Appends literal header field never indexed.
- **`fn end_h2_headers(cmd: WireCommandBuffer&) -> bool`**: Closes staged HEADERS block, emitting 9-byte frame header and HPACK payload.

### HTTP/2 Frame Codecs (`h2.goose`, RFC 9113)

- **`fn encode_frame_header<B>(hdr: const WireFrameHeader&, out: B&) -> bool`**: Serializes 9-byte binary frame header.
- **`fn parse_frame_header(buf: const u8[:]) -> WireFrameHeader, u32, bool`**: Zero-allocation frame header parser.
- **`fn encode_settings_frame<B>(settings: const WireSetting[:], out: B&) -> bool`**: Encodes SETTINGS frame into target buffer.
- **`fn encode_window_update_frame<B>(stream_id: u32, increment: u32, out: B&) -> bool`**: Encodes WINDOW_UPDATE frame.
- **`fn encode_priority_update_frame<B>(prioritized_stream_id: u32, urgency: u8, incremental: bool, out: B&) -> bool`**: Encodes RFC 9218 PRIORITY_UPDATE frame.
- **`fn encode_rst_stream_frame<B>(stream_id: u32, error_code: u32, out: B&) -> bool`**: Encodes RST_STREAM frame.
- **`fn encode_ping_frame<B>(payload: const u8[8], is_ack: bool, out: B&) -> bool`**: Encodes PING frame.
- **`fn encode_data_frame<B>(stream_id: u32, payload: const u8[:], end_stream: bool, out: B&) -> bool`**: Encodes DATA frame.
- **`fn encode_headers_frame<B>(stream_id: u32, hpack_block: const u8[:], end_stream: bool, end_headers: bool, out: B&) -> bool`**: Encodes HEADERS frame with pre-encoded HPACK block.

### HPACK Low-Level Codecs (`hpack.goose`, RFC 7541)

- **`fn hpack_encode_int<B>(out: B&, val: u64, prefix_bits: u8, prefix_mask: u8) -> bool`**: Encodes variable-length integer with N-bit prefix.
- **`fn hpack_decode_int(src: const u8[:], offset: u64&, prefix_bits: u8) -> u64, bool`**: Decodes variable-length integer from slice and advances cursor.
- **`fn hpack_encode_indexed<B>(out: B&, index: u64) -> bool`**: Encodes 7-bit indexed header representation.
- **`fn hpack_encode_string<B>(out: B&, str: const u8[:]) -> bool`**: Encodes 7-bit prefix length uncompressed string.
- **`fn hpack_decode_string(src: const u8[:], offset: u64&, out: u8[:]) -> u64, bool`**: Decodes string literal into buffer.
- **`fn hpack_encode_literal_without_indexing<B>(out: B&, name: const u8[:], val: const u8[:]) -> bool`**: Encodes literal header without indexing.
- **`fn hpack_encode_literal_never_indexed<B>(out: B&, name: const u8[:], val: const u8[:]) -> bool`**: Encodes literal header never indexed.

### Transport Queue Batch Submission (`submit.goose`)

- **`struct WireQueue`**: Physical transport queue state (`fd: i64`, `driver: WireDriverKind`, `config: WireDeviceConfig`, `bytes_sent: u64`, `bytes_received: u64`, `is_connected: bool`).
- **`fn new_wire_queue(cfg: const WireDeviceConfig&) -> WireQueue`**: Initializes a wire queue instance.
- **`fn connect_wire_queue(q: WireQueue&, host: const u8[:], port: u16, timeout_ms: u32 = 5000) -> bool`**: Connects physical transport socket and applies socket configuration.
- **`fn submit(q: WireQueue&, cmd: const WireCommandBuffer&) -> i64, bool`**: Flushes recorded command buffer to network descriptor.
- **`fn submit_slice(q: WireQueue&, data: const u8[:]) -> i64, bool`**: Sends raw byte slice directly to queue.
- **`fn poll_recv(q: WireQueue&, out: u8[:], timeout_ms: u32 = 0) -> i64, bool`**: Polls transport socket for incoming wire octets into caller buffer.
- **`fn close_wire_queue(q: WireQueue&)`**: Shuts down transport socket descriptor.
