# `http3`

Zero-allocation HTTP/3 protocol engine (RFC 9114), QPACK header compression (RFC
9204), and QUIC transport multiplexer.

## Public API

### HTTP/3 Binary Framing (`framing.goose`, RFC 9114 §7, RFC 9218, RFC 9412)

```goose
struct H3FrameHeader {
    frame_type:  u64,
    payload_len: u64,
    header_len:  u64,
}

fn parse_h3_frame_header(src: const u8[:], offset: u64) -> H3FrameHeader, bool
fn encode_h3_frame_header<B>(out: B&, frame_type: u64, payload_len: u64) -> bool
fn encode_h3_data_frame<B>(out: B&, data: const u8[:]) -> bool
fn encode_h3_headers_frame<B>(out: B&, qpack_field_section: const u8[:]) -> bool
fn encode_h3_push_promise<B>(out: B&, push_id: u64, qpack_field_section: const u8[:]) -> bool
fn encode_h3_settings_frame<B>(out: B&, settings: const H3Settings&) -> bool
fn parse_h3_settings_frame(payload: const u8[:], out_settings: H3Settings&) -> u64
fn encode_h3_goaway_frame<B>(out: B&, stream_id: u64) -> bool
fn parse_h3_goaway_frame(payload: const u8[:]) -> u64, bool
fn encode_h3_cancel_push<B>(out: B&, push_id: u64) -> bool
fn parse_h3_cancel_push(payload: const u8[:]) -> u64, bool
fn encode_h3_max_push_id<B>(out: B&, push_id: u64) -> bool
fn parse_h3_max_push_id(payload: const u8[:]) -> u64, bool
fn encode_h3_priority_update_request<B>(out: B&, stream_id: u64, prio: const wing::PriorityParam&) -> bool
fn parse_h3_priority_update_request(payload: const u8[:], default_incremental: bool = false) -> u64, wing::PriorityParam, bool
fn encode_h3_priority_update_push<B>(out: B&, push_id: u64, prio: const wing::PriorityParam&) -> bool
fn parse_h3_priority_update_push(payload: const u8[:], default_incremental: bool = false) -> u64, wing::PriorityParam, bool
fn encode_h3_origin_frame<B>(out: B&, origins: const (const u8[:])[:]) -> bool
fn parse_h3_origin_frame(payload: const u8[:], out_origins: u8[..128][..16]&) -> bool
```

`H3FrameHeader` decodes RFC 9000 variable-length integer frame types and payload
lengths starting at `offset`, reporting the consumed prefix size in
`header_len`. `parse_h3_settings_frame` validates peer `SETTINGS` parameters
(QPACK table capacity, blocked streams, Extended CONNECT, WebTransport, and H3
datagrams) while rejecting reserved HTTP/2 setting identifiers per RFC 9114
§7.2.4.1. `parse_h3_origin_frame` unpacks up to 16 ASCII origins of up to 128
bytes each (`u8[..128][..16]`) per RFC 9412.

| Category | Constants |
| :--- | :--- |
| Frame Types | `H3_FRAME_DATA` (`0x00`), `H3_FRAME_HEADERS` (`0x01`), `H3_FRAME_CANCEL_PUSH` (`0x03`), `H3_FRAME_SETTINGS` (`0x04`), `H3_FRAME_PUSH_PROMISE` (`0x05`), `H3_FRAME_GOAWAY` (`0x07`), `H3_FRAME_ORIGIN` (`0x0C`), `H3_FRAME_MAX_PUSH_ID` (`0x0D`), `H3_FRAME_PRIORITY_UPDATE_REQUEST` (`0xF0700`), `H3_FRAME_PRIORITY_UPDATE_PUSH` (`0xF0701`) |
| Unidirectional Stream Types | `H3_STREAM_CONTROL` (`0x00`), `H3_STREAM_PUSH` (`0x01`), `H3_STREAM_QPACK_ENCODER` (`0x02`), `H3_STREAM_QPACK_DECODER` (`0x03`) |

```goose
let settings = wing::H3Settings { .. };
var conn = h3_internal::new_h3_client_connection(settings);
let stream_id, ok = h3_internal::open_request_stream(conn);
```

### QPACK Compression & Dynamic Table (`qpack.goose`, RFC 9204)

```goose
struct H3PseudoHeaders
struct HeaderField
struct QpackTable
enum QpackError {
    None, DecompressionFailed, EncoderStreamError, DecoderStreamError,
    BlockedStreamsExhausted, StreamBlocked, HeaderListTooLarge,
    ClosedCriticalStream, StreamCreationError, FrameEncodingError,
    MessageError,
}

fn new_qpack_table(max_capacity: u64 = 4096, max_blocked: u32 = 16, initial_capacity: u64 = 4096) -> QpackTable
fn qpack_set_capacity(tbl: QpackTable&, new_cap: u64) -> bool
fn qpack_process_encoder_instruction(tbl: QpackTable&, src: const u8[:], offset: u64) -> u64, QpackError
fn qpack_process_decoder_instruction(tbl: QpackTable&, src: const u8[:], offset: u64) -> u64, QpackError
fn decode_qpack_to_map(tbl: const QpackTable&, src: const u8[:], out_pseudo: H3PseudoHeaders&, out_headers: wing::HeaderMap&, max_field_section: u64 = 16384) -> QpackError
fn decode_or_block_qpack_to_map(tbl: QpackTable&, stream_id: u64, src: const u8[:], out_pseudo: H3PseudoHeaders&, out_headers: wing::HeaderMap&, max_field_section: u64 = 16384) -> QpackError
fn decode_qpack_section<F>(tbl: const QpackTable&, src: const u8[:], out_fields: F&, max_field_section: u64 = 16384) -> QpackError
fn decode_or_block_qpack_section<F>(tbl: QpackTable&, stream_id: u64, src: const u8[:], out_fields: F&, max_field_section: u64 = 16384) -> QpackError
fn encode_qpack_field<B>(out: B&, name: const u8[:], val: const u8[:], use_huffman: bool = true)
fn encode_qpack_field_dynamic<B1, B2>(tbl: QpackTable&, stream_id: u64, base: u64, name: const u8[:], val: const u8[:], out_section: B1&, out_enc_stream: B2&, max_dyn_abs_used: u64&, used_any_dyn: bool&, use_huffman: bool = true)
```

`QpackTable` manages dynamic table insertions, evictions, pinned unacknowledged
stream references, and blocked stream queues (`max_blocked`). `HeaderField`
holds a decompressed field (`name: u8[..256]`, `value: u8[..4096]`,
`never_index: bool`), while `decode_qpack_to_map` and
`decode_or_block_qpack_to_map` decode field sections directly into
`H3PseudoHeaders` (`:method`, `:scheme`, `:authority`, `:path`, `:protocol`,
`:status`, and `content_length`) and `wing::HeaderMap`. When a section's
Required Insert Count exceeds the current Insert Count (RFC 9204 §2.1.2), the
`_or_block_` functions queue `stream_id` in `blocked_streams` and return
`QpackError.StreamBlocked`. `qpack_process_encoder_instruction` and
`qpack_process_decoder_instruction` return the next byte offset and a
`QpackError` status.

### Connection State & Stream Multiplexing (`connection.goose`)

```goose
enum H3ConnRole { Client, Server }
enum H3ConnState { Initial, Ready, GoingAway, Closed }
struct H3Connection
struct H3StreamEntry

fn new_h3_client_connection(settings: const wing::H3Settings&) -> H3Connection
fn new_h3_server_connection(settings: const wing::H3Settings&) -> H3Connection
fn encode_client_preambles<B1, B2, B3>(conn: H3Connection&, out_ctrl: B1&, out_qpack_enc: B2&, out_qpack_dec: B3&) -> bool
fn handle_stream_data(conn: H3Connection&, stream_id: u64, is_bidi: bool, data: const u8[:], fin: bool) -> u64
fn open_request_stream(conn: H3Connection&) -> u64, bool
fn send_request_headers<B>(conn: H3Connection&, stream_id: u64, method: const u8[:], scheme: const u8[:], authority: const u8[:], path: const u8[:], extra_headers: const wing::HeaderMap&, end_stream: bool, out: B&) -> bool
fn send_request_data<B>(conn: H3Connection&, stream_id: u64, data: const u8[:], end_stream: bool, out: B&) -> bool
fn send_response_headers_body_and_trailers<B>(conn: H3Connection&, stream_id: u64, status_code: i32, extra_headers: const wing::HeaderMap&, body: const u8[:], trailers: const wing::HeaderMap&, out: B&) -> bool
fn apply_h3_stream_priority(conn: H3Connection&, stream_id: u64, prio: const wing::PriorityParam&) -> bool
fn select_next_h3_tx_stream(conn: H3Connection&) -> u64, bool
```

`H3Connection` coordinates unidirectional control streams, QPACK encoder and
decoder streams, push streams, and bidirectional request streams
(`H3StreamEntry`, RFC 9114 §4.1). `handle_stream_data` demultiplexes incoming
stream slices and unblocks waiting QPACK streams as encoder instructions arrive.
`apply_h3_stream_priority` and `select_next_h3_tx_stream` schedule outbound
request streams according to RFC 9218 urgency and incremental parameters.
