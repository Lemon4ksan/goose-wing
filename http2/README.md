# `http2`

Zero-allocation HTTP/2 protocol engine (RFC 9113), HPACK header compression (RFC 7541), and extensible priority scheduler (RFC 9218).

## Public API

### Frame Definition & Binary Framing (`framing.goose`, RFC 9113 §4)

- **`struct FrameHeader`**: 9-byte binary frame header (`length: u32`, `frame_type: u8`, `flags: u8`, `stream_id: u32`).
- **`fn parse_frame_header(buf: const u8[:], max_frame_size: u32 = 16384) -> FrameHeader, u32`**: Zero-allocation parser validating 9-byte wire frame prefix, size ceiling, and reserved bit masking.
- **`fn parse_settings_payload(payload: const u8[:], out_settings: u16[..16]&, out_values: u32[..16]&) -> u32`**: Parses and validates settings key-value pairs against RFC 9113 parameter ranges.
- **`fn parse_window_update_payload(payload: const u8[:]) -> u32, u32`**: Extracts 31-bit window increment and validates non-zero increment constraint.
- **`fn parse_rst_stream_payload(payload: const u8[:]) -> u32, u32`**: Extracts 32-bit error code.
- **`fn parse_goaway_payload(payload: const u8[:]) -> u32, u32, const u8[:], u32`**: Extracts last-stream-ID, error code, and debug data slice.
- **`fn parse_priority_update_payload(payload: const u8[:]) -> u32, wing::PriorityParam, u32`**: Decodes RFC 9218 priority updates with validation.
- **Protocol Constants**:
  - Frame Types: `FRAME_DATA` (`0x00`), `FRAME_HEADERS` (`0x01`), `FRAME_PRIORITY` (`0x02`), `FRAME_RST_STREAM` (`0x03`), `FRAME_SETTINGS` (`0x04`), `FRAME_PUSH_PROMISE` (`0x05`), `FRAME_PING` (`0x06`), `FRAME_GOAWAY` (`0x07`), `FRAME_WINDOW_UPDATE` (`0x08`), `FRAME_CONTINUATION` (`0x09`), `FRAME_PRIORITY_UPDATE` (`0x10`, RFC 9218).
  - Frame Flags: `FLAG_END_STREAM` (`0x01`), `FLAG_ACK` (`0x01`), `FLAG_END_HEADERS` (`0x04`), `FLAG_PADDED` (`0x08`), `FLAG_PRIORITY` (`0x20`).
  - Error Codes: `ERR_NO_ERROR` (`0x00`), `ERR_PROTOCOL_ERROR` (`0x01`), `ERR_INTERNAL_ERROR` (`0x02`), `ERR_FLOW_CONTROL_ERROR` (`0x03`), `ERR_SETTINGS_TIMEOUT` (`0x04`), `ERR_STREAM_CLOSED` (`0x05`), `ERR_FRAME_SIZE_ERROR` (`0x06`), `ERR_REFUSED_STREAM` (`0x07`), `ERR_CANCEL` (`0x08`), `ERR_COMPRESSION_ERROR` (`0x09`), `ERR_CONNECT_ERROR` (`0x0A`), `ERR_ENHANCE_YOUR_CALM` (`0x0B`).
  - Settings: `SETTING_HEADER_TABLE_SIZE` (`0x01`), `SETTING_ENABLE_PUSH` (`0x02`), `SETTING_MAX_CONCURRENT_STREAMS` (`0x03`), `SETTING_INITIAL_WINDOW_SIZE` (`0x04`), `SETTING_MAX_FRAME_SIZE` (`0x05`), `SETTING_MAX_HEADER_LIST_SIZE` (`0x06`), `SETTING_ENABLE_CONNECT_PROTO` (`0x08`).

### HTTP/2 Extension Frames (`frames.goose`, RFC 8336, RFC 7838)

- **`fn parse_origin_frame(payload: const u8[:], stream_id: u32, out_entries: const u8[:][..16]&) -> u32, u32`**: Parses RFC 8336 ORIGIN frame payload on stream 0.
- **`fn parse_altsvc_frame(payload: const u8[:], stream_id: u32) -> H2AltSvcFrame, u32`**: Parses RFC 7838 ALTSVC frame payload.
- **`fn encode_origin_frame_single(origin: const u8[:], out: u8[:]&) -> u32`**: Serializes single ORIGIN frame entry.
- **`fn encode_altsvc_frame(origin: const u8[:], alt_svc_value: const u8[:], out: u8[:]&) -> u32`**: Serializes RFC 7838 ALTSVC frame.

### HPACK Compression & Canonical Dynamic Table (`hpack.goose`, RFC 7541)

- **`struct DynamicTable`**: Bounded circular buffer managing HPACK dynamic table entries with eviction accounting and generations.
- **`struct DecodedH2Header`**: Decoded header name-value pair view.
- **`struct DecodedH2HeaderList`**: Bounded collection of decoded request/response headers with validated pseudo-header presence.
- **`fn new_dynamic_table(max_size: u32) -> DynamicTable`**: Initializes HPACK dynamic table with specified capacity.
- **`fn decode_hpack_header_block(dt: DynamicTable&, src: const u8[:], out: DecodedH2HeaderList&, max_header_list_size: u32 = 8192, validate_http2_rules: bool = true) -> u32`**: Decodes indexed, literal, and Huffman-encoded header blocks.

### Connection State & Stream Multiplexing (`connection.goose`)

- **`struct H2Connection`**: Connection-level state machine coordinating flow control, stream lifecycles, and anti-DoS rate limiting.
- **`struct H2Stream`**: Stream-level state machine conforming to RFC 9113 §5.1 transitions (`Idle`, `Open`, `HalfClosedLocal`, `HalfClosedRemote`, `Closed`).
- **`fn new_h2_connection(now_ms: u64 = 0, max_header_list: u32 = 8192, behind_proxy: bool = false, is_server: bool = true, enable_push: bool = false) -> H2Connection`**: Initializes an HTTP/2 connection state.
- **`fn on_ingress_frame_header(s: H2Connection&, hdr: const FrameHeader&, now_ms: u64) -> u32`**: Validates frame ingress against continuation state, stream bounds, and empty-frame flood thresholds.
- **`fn apply_window_update(s: H2Connection&, stream_id: u32, increment: u32) -> u32`**: Applies flow control increment to connection or stream window.
- **`fn apply_priority_update(s: H2Connection&, prioritized_stream_id: u32, prio: wing::PriorityParam) -> u32`**: Updates stream scheduling priority.
- **`fn schedule_next_write(s: H2Connection&, max_frame_len: u32) -> u32, u32, bool`**: RFC 9218 strict urgency and incremental round-robin stream scheduler.
