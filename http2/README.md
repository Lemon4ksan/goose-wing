# `http2`

Zero-allocation HTTP/2 protocol engine (RFC 9113), HPACK header compression (RFC
7541), and extensible priority scheduler (RFC 9218).

## Public API

### Frame Definition & Binary Framing (`framing.goose`, RFC 9113 §4)

```goose
struct FrameHeader {
    length:     u32,
    frame_type: u8,
    flags:      u8,
    stream_id:  u32,
}

fn parse_frame_header(buf: const u8[:], max_frame_size: u32 = 16384) -> FrameHeader, u32
fn encode_frame_header(hdr: const FrameHeader&, out: u8[9]&)
fn encode_frame_header_to<B>(hdr: const FrameHeader&, out: B&)
fn validate_frame_header_rules(hdr: const FrameHeader&, max_frame_size: u32 = 16384) -> u32
fn extract_padded_frame_payload(hdr: const FrameHeader&, payload: const u8[:]) -> const u8[:], u32
fn extract_headers_frame_payload(hdr: const FrameHeader&, payload: const u8[:], no_rfc7540_priorities: bool = true) -> const u8[:], u32
fn validate_settings_parameter(param_id: u16, val: u32, receiver_is_client: bool = false) -> u32
fn parse_priority_update_payload(payload: const u8[:], default_incremental: bool = false) -> u32, wing::PriorityParam, u32
fn encode_priority_update_payload<B>(prioritized_stream_id: u32, prio: const wing::PriorityParam&, out: B&)
```

`FrameHeader` represents the 9-byte binary HTTP/2 frame prefix.
`parse_frame_header` and `validate_frame_header_rules` mask the reserved stream
ID bit, check `max_frame_size`, and enforce per-frame stream association rules
per RFC 9113 §6, returning `ERR_NO_ERROR` (`0x00`) or an HTTP/2 error code.
`extract_padded_frame_payload` strips optional `FLAG_PADDED` bytes from `DATA`,
`HEADERS`, or `PUSH_PROMISE` frames, and `extract_headers_frame_payload` strips
legacy RFC 7540 priority fields while rejecting self-dependent stream IDs (RFC
9113 §5.3.1).

| Category | Constants |
| :--- | :--- |
| Frame Types | `FRAME_DATA` (`0x00`), `FRAME_HEADERS` (`0x01`), `FRAME_PRIORITY` (`0x02`), `FRAME_RST_STREAM` (`0x03`), `FRAME_SETTINGS` (`0x04`), `FRAME_PUSH_PROMISE` (`0x05`), `FRAME_PING` (`0x06`), `FRAME_GOAWAY` (`0x07`), `FRAME_WINDOW_UPDATE` (`0x08`), `FRAME_CONTINUATION` (`0x09`), `FRAME_PRIORITY_UPDATE` (`0x10`, RFC 9218) |
| Frame Flags | `FLAG_END_STREAM` (`0x01`), `FLAG_ACK` (`0x01`), `FLAG_END_HEADERS` (`0x04`), `FLAG_PADDED` (`0x08`), `FLAG_PRIORITY` (`0x20`) |
| Error Codes | `ERR_NO_ERROR` (`0x00`), `ERR_PROTOCOL_ERROR` (`0x01`), `ERR_INTERNAL_ERROR` (`0x02`), `ERR_FLOW_CONTROL_ERROR` (`0x03`), `ERR_SETTINGS_TIMEOUT` (`0x04`), `ERR_STREAM_CLOSED` (`0x05`), `ERR_FRAME_SIZE_ERROR` (`0x06`), `ERR_REFUSED_STREAM` (`0x07`), `ERR_CANCEL` (`0x08`), `ERR_COMPRESSION_ERROR` (`0x09`), `ERR_CONNECT_ERROR` (`0x0A`), `ERR_ENHANCE_YOUR_CALM` (`0x0B`) |
| Settings | `SETTING_HEADER_TABLE_SIZE` (`0x01`), `SETTING_ENABLE_PUSH` (`0x02`), `SETTING_MAX_CONCURRENT_STREAMS` (`0x03`), `SETTING_INITIAL_WINDOW_SIZE` (`0x04`), `SETTING_MAX_FRAME_SIZE` (`0x05`), `SETTING_MAX_HEADER_LIST_SIZE` (`0x06`), `SETTING_ENABLE_CONNECT_PROTO` (`0x08`) |

```goose
let hdr, err = internal::parse_frame_header(wire_buf);
if err == 0 {
    var conn = internal::new_h2_connection();
    let status = internal::on_ingress_frame_header(conn, hdr, 1000);
}
```

### HTTP/2 Extension Frames (`frames.goose`, RFC 8336, RFC 7838)

```goose
struct H2AltSvcFrame

fn parse_origin_frame(payload: const u8[:], stream_id: u32, out_entries: const u8[:][..16]&) -> u32, u32
fn encode_origin_frame<B>(out: B&, origins: const u8[:][..16]&) -> bool
fn encode_origin_frame_single<B>(out: B&, origin: const u8[:]) -> bool
fn parse_altsvc_frame(payload: const u8[:], stream_id: u32) -> H2AltSvcFrame, u32
fn encode_altsvc_frame<B>(out: B&, origin: const u8[:], alt_svc_val: const u8[:], stream_id: u32) -> bool
```

Encodes and decodes RFC 8336 `ORIGIN` (`0x0C`) frames on stream 0 (up to 16
entries in `const u8[:][..16]`) and RFC 7838 `ALTSVC` (`0x0A`) frames
(`H2AltSvcFrame` holding `origin` and `alt_svc_val` slices).

### HPACK Compression & Canonical Dynamic Table (`hpack.goose`, RFC 7541)

```goose
struct DynamicTable
struct HpackHeaderField
struct H2PseudoHeaders
enum HpackIndexing { Incremental, WithoutIndexing, NeverIndexed }

fn new_dynamic_table(max_allowed: u64 = 4096) -> DynamicTable
fn insert_header(dt: DynamicTable&, name: const u8[:], val: const u8[:], never_index: bool = false)
fn update_dynamic_table_max_size(dt: DynamicTable&, new_max: u64) -> bool
fn decode_hpack_field_step_to_map(dt: DynamicTable&, src: const u8[:], offset: u64, updates_allowed: bool&, update_count: u32&, out_pseudo: H2PseudoHeaders&, out_headers: wing::HeaderMap&, max_header_list_size: u32, validate_http2_rules: bool) -> u64, u32
fn decode_hpack_to_map(dt: DynamicTable&, src: const u8[:], out_pseudo: H2PseudoHeaders&, out_headers: wing::HeaderMap&, max_header_list_size: u32 = 8192, validate_http2_rules: bool = true) -> u32
fn encode_hpack_field<B>(dt: DynamicTable&, out: B&, name: const u8[:], val: const u8[:], indexing: HpackIndexing = HpackIndexing.Incremental, use_huffman: bool = true) -> bool
fn select_hpack_indexing(name: const u8[:], val: const u8[:], max_table_size: i64) -> HpackIndexing
```

`DynamicTable` manages HPACK dynamic entries (`HpackHeaderField`) in a circular
ring buffer and 4 KB arena with O(1) generation-stamped hash lookups.
`decode_hpack_to_map` and `decode_hpack_field_step_to_map` decode HPACK blocks
directly into `H2PseudoHeaders` (`:method`, `:scheme`, `:authority`, `:path`,
`:protocol`, `:status`) and `wing::HeaderMap` while enforcing RFC 9113 §8.2
pseudo-header ordering and `max_header_list_size` limits.
`select_hpack_indexing` chooses `NeverIndexed` or `WithoutIndexing` for
sensitive, volatile, or oversized header fields.

### Connection State & Stream Multiplexing (`connection.goose`)

```goose
struct TokenBucket
enum H2StreamState { Idle, Open, HalfClosedLocal, HalfClosedRemote, Closed }
struct H2Stream
struct H2Connection

fn new_h2_connection(now_ms: u64 = 0, max_header_list: u32 = 8192, behind_proxy: bool = false) -> H2Connection
fn on_ingress_frame_header(s: H2Connection&, hdr: const FrameHeader&, now_ms: u64) -> u32
fn on_data_frame_received(s: H2Connection&, hdr: const FrameHeader&, payload_len: u32) -> u32
fn apply_peer_initial_window_size_delta(s: H2Connection&, new_init_win: u32) -> u32
fn apply_window_update(s: H2Connection&, stream_id: u32, increment: u32) -> u32
fn apply_goaway(s: H2Connection&, last_stream_id: u32, error_code: u32) -> u32
fn apply_priority_update(s: H2Connection&, prioritized_stream_id: u32, prio: wing::PriorityParam) -> u32
fn enqueue_stream_send_bytes(s: H2Connection&, stream_id: u32, bytes: u32) -> bool
fn schedule_next_write(s: H2Connection&, max_frame_len: u32) -> u32, u32, bool
```

`H2Connection` coordinates stream lifecycles (`H2Stream`, `H2StreamState`),
connection and stream flow-control windows, and rate limiting via `TokenBucket`
(defending against CVE-2023-44487 Rapid Reset, `CONTINUATION` floods,
`PING`/`SETTINGS` floods, and empty-frame streaks). `schedule_next_write`
implements an RFC 9218 stream scheduler across urgency buckets `0..7` with
incremental round-robin sharing and anti-starvation yielding.
