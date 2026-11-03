# `http3`

Zero-allocation HTTP/3 protocol engine (RFC 9114), QPACK header compression (RFC 9204), and QUIC transport multiplexer.

## Public API

### HTTP/3 Binary Framing (`framing.goose`, RFC 9114 §7)

- **`struct H3FrameHeader`**: Variable-length frame header (`frame_type: u64`, `length: u64`).
- **`fn parse_h3_frame_header(data: const u8[:], offset: u64&) -> H3FrameHeader, bool`**: Streaming parser decoding RFC 9000 variable-length integer frame headers.
- **`fn encode_h3_frame_header<B>(out: B&, frame_type: u64, length: u64) -> bool`**: Serializes variable-length integer frame header.
- **`fn encode_h3_data_frame<B>(out: B&, payload: const u8[:]) -> bool`**: Serializes an HTTP/3 `DATA` frame.
- **`fn encode_h3_headers_frame<B>(out: B&, payload: const u8[:]) -> bool`**: Serializes an HTTP/3 `HEADERS` frame.
- **`fn encode_h3_settings_frame<B>(out: B&, settings: const H3Settings&) -> bool`**: Encodes `SETTINGS` frame with QPACK table capacity, blocked streams, and datagram parameters.
- **`fn parse_h3_settings_frame(payload: const u8[:], out_settings: H3Settings&) -> u64`**: Parses and validates peer settings payload against RFC 9114 ranges.
- **Frame & Stream Constants**:
  - Frame Types: `H3_FRAME_DATA` (`0x00`), `H3_FRAME_HEADERS` (`0x01`), `H3_FRAME_CANCEL_PUSH` (`0x03`), `H3_FRAME_SETTINGS` (`0x04`), `H3_FRAME_PUSH_PROMISE` (`0x05`), `H3_FRAME_GOAWAY` (`0x07`), `H3_FRAME_MAX_PUSH_ID` (`0x0D`), `H3_FRAME_PRIORITY_UPDATE_REQUEST` (`0xF0700`), `H3_FRAME_PRIORITY_UPDATE_PUSH` (`0xF0701`).
  - Unidirectional Stream Types: `H3_STREAM_CONTROL` (`0x00`), `H3_STREAM_PUSH` (`0x01`), `H3_STREAM_QPACK_ENCODER` (`0x02`), `H3_STREAM_QPACK_DECODER` (`0x03`).

### QPACK Compression & Dynamic Table (`qpack.goose`, RFC 9204)

- **`struct HeaderField`**: Decompressed HTTP header representation (`name: u8[..256]`, `value: u8[..4096]`, `never_index: bool`).
- **`struct QpackTable`**: Bounded dynamic table managing inserts, evictions, unacked stream references, and blocked stream queues with zero heap allocations.
- **`enum QpackError`**: Decompression and instruction errors (`None`, `DecompressionFailed`, `EncoderStreamError`, `DecoderStreamError`, `BlockedStreamsExhausted`, `StreamBlocked`, `HeaderListTooLarge`, `ClosedCriticalStream`, `StreamCreationError`, `FrameEncodingError`).
- **`fn new_qpack_table(max_capacity: u64 = 4096, max_blocked: u32 = 16, initial_capacity: u64 = 4096) -> QpackTable`**: Constructs a new QPACK table.
- **`fn decode_qpack_section<F>(tbl: const QpackTable&, src: const u8[:], out_fields: F&, max_field_section: u64 = 16384) -> QpackError`**: Decodes encoded field section enforcing Header Accordion defenses (CVE-2026-12523 / CVE-2026-40898).
- **`fn decode_or_block_qpack_section<F>(tbl: QpackTable&, stream_id: u64, src: const u8[:], out_fields: F&, max_field_section: u64 = 16384) -> QpackError`**: Decodes an encoded field section or records stream as blocked if Required Insert Count exceeds Insert Count (RFC 9204 §2.1.2).
- **`fn encode_qpack_field<B>(out: B&, name: const u8[:], val: const u8[:], use_huffman: bool = true, never_index: bool = false)`**: Serializes a header line into QPACK wire format with static table index lookup and literal encoding.

### Connection State & Stream Multiplexing (`connection.goose`)

- **`struct H3Settings`**: HTTP/3 configuration parameters (`qpack_max_table_capacity`, `max_field_section_size`, `qpack_blocked_streams`, `enable_connect_protocol`, `h3_datagram`).
- **`struct H3Connection`**: HTTP/3 connection state machine coordinating unidirectional control streams, QPACK streams, and bidirectional request streams.
- **`struct H3StreamEntry`**: Bidirectional request stream state machine (RFC 9114 §4.1).
- **`fn new_h3_client_connection(settings: const H3Settings& = H3Settings { .. }) -> H3Connection`**: Initializes an HTTP/3 client endpoint.
- **`fn new_h3_server_connection(settings: const H3Settings& = H3Settings { .. }) -> H3Connection`**: Initializes an HTTP/3 server endpoint.
- **`fn handle_stream_data(conn: H3Connection&, stream_id: u64, is_bidi: bool, data: const u8[:], fin: bool) -> u64`**: Ingress dispatcher routing stream bytes to control, QPACK, or request handlers.
- **`fn open_request_stream(conn: H3Connection&) -> u64, bool`**: Allocates an active bidirectional request stream slot.
- **`fn send_request_headers<B>(conn: H3Connection&, stream_id: u64, method: const u8[:], scheme: const u8[:], authority: const u8[:], path: const u8[:], headers: const wing::HeaderMap&, end_stream: bool, out: B&) -> bool`**: Frames and serializes client request headers.
- **`fn send_request_data<B>(conn: H3Connection&, stream_id: u64, data: const u8[:], end_stream: bool, out: B&) -> bool`**: Frames and serializes request payload chunks.
