# `http3`

Zero-allocation HTTP/3 protocol engine (RFC 9114), QPACK header compression (RFC
9204), and QUIC transport multiplexer in `namespace http3;` (internal helpers in
`namespace h3_internal;`).

## Public API

### HTTP/3 Binary Framing (`framing.goose`, RFC 9114 §7, RFC 9218, RFC 9412)

```goose
struct FrameHeader {
    frame_type:  u64 = 0,
    payload_len: u64 = 0,
    header_len:  u64 = 0,
}

fn parse_frame_header(src: const u8[:], offset: u64) -> FrameHeader, bool
fn encode_frame_header<B>(out: B&, frame_type: u64, payload_len: u64) -> bool
fn encode_data_frame<B>(out: B&, data: const u8[:]) -> bool
fn encode_headers_frame<B>(out: B&, qpack_field_section: const u8[:]) -> bool
fn encode_push_promise<B>(out: B&, push_id: u64, qpack_field_section: const u8[:]) -> bool
fn encode_settings_frame<B>(out: B&, settings: const fingerprint::H3Settings&) -> bool
fn parse_settings_frame(payload: const u8[:]) -> fingerprint::H3Settings, u64
fn encode_goaway_frame<B>(out: B&, stream_id: u64) -> bool
fn parse_goaway_frame(payload: const u8[:]) -> u64, bool
fn encode_cancel_push<B>(out: B&, push_id: u64) -> bool
fn parse_cancel_push(payload: const u8[:]) -> u64, bool
fn encode_max_push_id<B>(out: B&, push_id: u64) -> bool
fn parse_max_push_id(payload: const u8[:]) -> u64, bool
fn encode_priority_update_request<B>(out: B&, stream_id: u64, prio: const wing::PriorityParam&) -> bool
fn parse_priority_update_request(payload: const u8[:], default_incremental: bool = false) -> u64, wing::PriorityParam, bool
fn encode_priority_update_push<B>(out: B&, push_id: u64, prio: const wing::PriorityParam&) -> bool
fn parse_priority_update_push(payload: const u8[:], default_incremental: bool = false) -> u64, wing::PriorityParam, bool
fn encode_origin_frame<B>(out: B&, origins: const (const u8[:])[:]) -> bool
fn parse_origin_frame(payload: const u8[:], out_origins: u8[..128][..16]&) -> bool
```

`FrameHeader` decodes RFC 9000 variable-length integer frame types and payload
lengths starting at `offset`, reporting the consumed prefix size in
`header_len`. `parse_settings_frame` returns `(H3Settings, u64)` and validates
peer `SETTINGS` parameters (QPACK table capacity, blocked streams, Extended
CONNECT, WebTransport, and H3 datagrams) while rejecting reserved HTTP/2 setting
identifiers per RFC 9114 §7.2.4.1. `parse_origin_frame` unpacks up to 16 ASCII
origins of up to 128 bytes each (`u8[..128][..16]`) per RFC 9412.

| Category | Constants |
| :--- | :--- |
| Frame Types | `rfc::H3_FRAME_DATA` (`0x00`), `rfc::H3_FRAME_HEADERS` (`0x01`), `rfc::H3_FRAME_CANCEL_PUSH` (`0x03`), `rfc::H3_FRAME_SETTINGS` (`0x04`), `rfc::H3_FRAME_PUSH_PROMISE` (`0x05`), `rfc::H3_FRAME_GOAWAY` (`0x07`), `H3_FRAME_ORIGIN` (`0x0C`), `rfc::H3_FRAME_MAX_PUSH_ID` (`0x0D`), `rfc::H3_FRAME_PRIORITY_UPDATE_REQUEST` (`0xF0700`), `rfc::H3_FRAME_PRIORITY_UPDATE_PUSH` (`0xF0701`) |
| Unidirectional Stream Types | `rfc::H3_STREAM_CONTROL` (`0x00`), `rfc::H3_STREAM_PUSH` (`0x01`), `rfc::H3_STREAM_QPACK_ENCODER` (`0x02`), `rfc::H3_STREAM_QPACK_DECODER` (`0x03`) |

```goose
let settings = fingerprint::H3Settings { .. };
var conn = http3::new_client_connection(settings);
let stream_id, ok = conn.open_request_stream();
```

### QPACK Compression & Dynamic Table (`qpack.goose`, `qpack_codec.goose`, RFC 9204)

```goose
struct PseudoHeaders
struct HeaderField
struct QpackTable
enum QpackError {
    None, StreamBlocked, DecompressionFailed, EncoderStreamError,
    DecoderStreamError, HeaderListTooLarge, BlockedStreamsExhausted,
    ClosedCriticalStream, StreamCreationError, FrameEncodingError,
    MessageError,
}

fn new_qpack_table(max_capacity: u64 = 4096, max_blocked: u32 = 16, initial_capacity: u64 = 4096) -> QpackTable
fn qpack_set_capacity(tbl: QpackTable&, new_cap: u64) -> bool
fn qpack_lookup_absolute(tbl: const QpackTable&, abs_idx: u64) -> const u8[:], const u8[:], bool
fn qpack_process_encoder_instruction(tbl: QpackTable&, src: const u8[:], offset: u64) -> u64, QpackError
fn qpack_process_decoder_instruction(tbl: QpackTable&, src: const u8[:], offset: u64) -> u64, QpackError
fn decode_qpack_to_map(tbl: const QpackTable&, src: const u8[:], out_pseudo: PseudoHeaders&, out_headers: wing::HeaderMap&, max_field_section: u64 = 16384) -> QpackError
fn decode_or_block_qpack_to_map(tbl: QpackTable&, stream_id: u64, src: const u8[:], out_pseudo: PseudoHeaders&, out_headers: wing::HeaderMap&, max_field_section: u64 = 16384) -> QpackError
fn decode_or_track_blocked_qpack_to_map(tbl: QpackTable&, stream_id: u64, src: const u8[:], out_pseudo: PseudoHeaders&, out_headers: http::HeaderMap&, max_field_section: u64 = 16384) -> QpackError
fn decode_or_track_blocked_qpack_to_map_spill(tbl: QpackTable&, stream_id: u64, src: const u8[:], out_pseudo: PseudoHeaders&, out_headers: http::HeaderMap&, out_arena: http::OverflowArena&, max_field_section: u64 = 65535) -> QpackError
fn decode_qpack_section<F>(tbl: const QpackTable&, src: const u8[:], out_fields: F&, max_field_section: u64 = 16384) -> QpackError
fn decode_or_block_qpack_section<F>(tbl: QpackTable&, stream_id: u64, src: const u8[:], out_fields: F&, max_field_section: u64 = 16384, is_push_promise: bool = false, push_id: u64 = 0) -> QpackError
fn encode_qpack_field<B>(out: B&, name: const u8[:], val: const u8[:], use_huffman: bool = true) -> bool
fn encode_qpack_field_dynamic<B1, B2>(tbl: QpackTable&, stream_id: u64, base: u64, name: const u8[:], val: const u8[:], out_section: B1&, out_enc_stream: B2&, max_dyn_abs_used: u64&, used_any_dyn: bool&, use_huffman: bool = true) -> bool
```

`QpackTable` manages dynamic table insertions, evictions, pinned unacknowledged
stream references, and blocked stream queues (`max_blocked`).
`qpack_lookup_absolute` returns zero-copy slices directly into `tbl.arena`.
`HeaderField` holds a decompressed field (`name: u8[..256]`, `value:
u8[..4096]`, `never_index: bool`), while `decode_qpack_to_map` and
`decode_or_block_qpack_to_map` decode field sections directly into
`PseudoHeaders` (`:method`, `:scheme`, `:authority`, `:path`, `:protocol`,
`:status`, and `content_length`) and `wing::HeaderMap`. When a section's
Required Insert Count exceeds the current Insert Count (RFC 9204 §2.1.2), the
`_or_block_` functions queue `stream_id` in `blocked_streams` and return
`QpackError.StreamBlocked`. `qpack_process_encoder_instruction` and
`qpack_process_decoder_instruction` return the next byte offset and a
`QpackError` status.

### Connection State & Stream Multiplexing (`connection.goose`)

```goose
enum ConnRole { Client, Server }
enum ConnState { Connecting, Active, Draining, Closed }
enum StreamKind { Request, Control, QpackEncoder, QpackDecoder, Push, UnknownUni }
enum StreamState { Idle, Open, HalfClosedLocal, HalfClosedRemote, Closed }
struct Connection
struct StreamEntry

fn new_client_connection(settings: const fingerprint::H3Settings&) -> Connection
fn new_server_connection(settings: const fingerprint::H3Settings&) -> Connection
fn encode_client_preambles<B1, B2, B3>(conn: Connection&, out_ctrl: B1&, out_qpack_enc: B2&, out_qpack_dec: B3&) -> bool
fn handle_stream_data(conn: Connection&, stream_id: u64, is_bidi: bool, data: const u8[:], fin: bool) -> u64
fn open_request_stream(conn: Connection&) -> u64, bool
fn send_request_headers<B>(conn: Connection&, stream_id: u64, method: const u8[:], scheme: const u8[:], authority: const u8[:], path: const u8[:], extra_headers: const wing::HeaderMap&, end_stream: bool, out: B&) -> bool
fn send_request_data<B>(conn: Connection&, stream_id: u64, data: const u8[:], end_stream: bool, out: B&) -> bool
fn send_response_headers_body_and_trailers<B>(conn: Connection&, stream_id: u64, status_code: i32, extra_headers: const wing::HeaderMap&, body: const u8[:], trailers: const wing::HeaderMap&, out: B&) -> bool
fn apply_stream_priority(conn: Connection&, stream_id: u64, prio: const wing::PriorityParam&) -> bool
fn select_next_tx_stream(conn: Connection&) -> u64, bool
```

`Connection` coordinates unidirectional control streams, QPACK encoder and
decoder streams, push streams, and bidirectional request streams (`StreamEntry`,
RFC 9114 §4.1). `handle_stream_data` demultiplexes incoming stream slices and
unblocks waiting QPACK streams as encoder instructions arrive.
`apply_stream_priority` and `select_next_tx_stream` schedule outbound request
streams according to RFC 9218 urgency and incremental parameters.

### Edge Server Session (`server_session.goose`)

```goose
struct H3EdgeEvent { .. }
struct H3EdgeEventView { .. }

fn h3_edge_poll_event(sess: H3EdgeSession&, out_ev: H3EdgeEvent&) -> bool
fn h3_edge_poll_event_spill(sess: H3EdgeSession&, out_ev: H3EdgeEvent&, out_arena: http::OverflowArena&) -> bool
fn h3_edge_poll_event_view(sess: H3EdgeSession&, out_ev: H3EdgeEventView&) -> bool
fn h3_edge_encode_response_headers(sess: H3EdgeSession&, status_code: i32, headers: const http::HeaderMap&, out_wire: u8[>..]&) -> bool
fn h3_edge_encode_response_headers_spill(sess: H3EdgeSession&, status_code: i32, headers: const http::HeaderMap&, arena: const http::OverflowArena&, out_wire: u8[>..]&) -> bool
```

`H3EdgeSession` decodes up to 64 KiB / 512-entry field sections into pooled
storage reclaimed on poll, reset, or close. `h3_edge_poll_event_spill` populates
`http::OverflowArena`, `h3_edge_poll_event_view` yields zero-copy
`http::HeaderView` slices backed by slot staging buffers, and
`h3_edge_encode_response_headers_spill` encodes up to 64 KiB response headers.
