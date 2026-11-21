# `http2`

Zero-allocation HTTP/2 protocol engine (RFC 9113), HPACK header compression (RFC
7541), and extensible priority scheduler (RFC 9218).

Public types and codecs live in `namespace http2`; internal static tables and
low-level helpers live in `namespace h2_internal`.

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
per RFC 9113 §6, returning `rfc::H2_ERR_NO_ERROR` (`0x00`) or an HTTP/2 error
code. `extract_padded_frame_payload` strips optional `rfc::H2_FLAG_PADDED` bytes
from `DATA`, `HEADERS`, or `PUSH_PROMISE` frames, and
`extract_headers_frame_payload` strips legacy RFC 7540 priority fields while
rejecting self-dependent stream IDs (RFC 9113 §5.3.1).

| Category | Constants |
| :--- | :--- |
| Frame Types | `rfc::H2_FRAME_DATA` (`0x00`), `rfc::H2_FRAME_HEADERS` (`0x01`), `rfc::H2_FRAME_PRIORITY` (`0x02`), `rfc::H2_FRAME_RST_STREAM` (`0x03`), `rfc::H2_FRAME_SETTINGS` (`0x04`), `rfc::H2_FRAME_PUSH_PROMISE` (`0x05`), `rfc::H2_FRAME_PING` (`0x06`), `rfc::H2_FRAME_GOAWAY` (`0x07`), `rfc::H2_FRAME_WINDOW_UPDATE` (`0x08`), `rfc::H2_FRAME_CONTINUATION` (`0x09`), `rfc::H2_FRAME_PRIORITY_UPDATE` (`0x10`, RFC 9218) |
| Frame Flags | `rfc::H2_FLAG_END_STREAM` (`0x01`), `rfc::H2_FLAG_ACK` (`0x01`), `rfc::H2_FLAG_END_HEADERS` (`0x04`), `rfc::H2_FLAG_PADDED` (`0x08`), `rfc::H2_FLAG_PRIORITY` (`0x20`) |
| Error Codes | `rfc::H2_ERR_NO_ERROR` (`0x00`), `rfc::H2_ERR_PROTOCOL_ERROR` (`0x01`), `rfc::H2_ERR_INTERNAL_ERROR` (`0x02`), `rfc::H2_ERR_FLOW_CONTROL_ERROR` (`0x03`), `rfc::H2_ERR_SETTINGS_TIMEOUT` (`0x04`), `rfc::H2_ERR_STREAM_CLOSED` (`0x05`), `rfc::H2_ERR_FRAME_SIZE_ERROR` (`0x06`), `rfc::H2_ERR_REFUSED_STREAM` (`0x07`), `rfc::H2_ERR_CANCEL` (`0x08`), `rfc::H2_ERR_COMPRESSION_ERROR` (`0x09`), `rfc::H2_ERR_CONNECT_ERROR` (`0x0A`), `rfc::H2_ERR_ENHANCE_YOUR_CALM` (`0x0B`) |
| Settings | `rfc::H2_SETTING_HEADER_TABLE_SIZE` (`0x01`), `rfc::H2_SETTING_ENABLE_PUSH` (`0x02`), `rfc::H2_SETTING_MAX_CONCURRENT_STREAMS` (`0x03`), `rfc::H2_SETTING_INITIAL_WINDOW_SIZE` (`0x04`), `rfc::H2_SETTING_MAX_FRAME_SIZE` (`0x05`), `rfc::H2_SETTING_MAX_HEADER_LIST_SIZE` (`0x06`), `rfc::H2_SETTING_ENABLE_CONNECT_PROTO` (`0x08`) |

```goose
let hdr, err = http2::parse_frame_header(wire_buf);
if err == 0 {
    var conn = http2::new_h2_connection();
    let status = conn.on_ingress_frame_header(hdr, 1000);
}
```

### HTTP/2 Extension Frames (`frames.goose`, RFC 8336, RFC 7838)

```goose
struct AltSvcFrame

fn parse_origin_frame(payload: const u8[:], stream_id: u32, out_entries: const u8[:][..16]&, flags: u8 = 0) -> u32, u32
fn encode_origin_frame<B>(out: B&, origins: const u8[:][..16]&) -> bool
fn parse_altsvc_frame(payload: const u8[:], stream_id: u32) -> AltSvcFrame, u32
fn encode_altsvc_frame<B>(out: B&, origin: const u8[:], alt_svc_val: const u8[:], stream_id: u32) -> bool
```

Encodes and decodes RFC 8336 `ORIGIN` (`0x0C`) frames on stream 0 (up to 16
entries in `const u8[:][..16]`) and RFC 7838 `ALTSVC` (`0x0A`) frames
(`AltSvcFrame` holding `origin` and `alt_svc_value` slices).

### HPACK Compression & Canonical Dynamic Table (`hpack.goose`, RFC 7541)

```goose
struct DynamicTable
struct HpackHeaderField
struct PseudoHeaders
enum HpackIndexing { Incremental, None, NeverIndexed }

fn new_dynamic_table(max_allowed: u64 = 4096) -> DynamicTable
fn insert_header(dt: DynamicTable&, name: const u8[:], val: const u8[:], never_index: bool = false)
fn update_dynamic_table_max_size(dt: DynamicTable&, new_max: u64) -> bool
fn clear_pseudo_headers(p: PseudoHeaders&, keep_trailer_flag: bool = true)
fn decode_hpack_field_step_to_map(dt: DynamicTable&, src: const u8[:], offset: u64, updates_allowed: bool&, update_count: u32&, out_pseudo: PseudoHeaders&, out_headers: wing::HeaderMap&, max_header_list_size: u32, validate_http2_rules: bool) -> u64, u32
fn decode_hpack_to_map(dt: DynamicTable&, src: const u8[:], out_pseudo: PseudoHeaders&, out_headers: wing::HeaderMap&, max_header_list_size: u32 = 8192, validate_http2_rules: bool = true) -> u32
fn encode_hpack_field<B>(dt: DynamicTable&, out: B&, name: const u8[:], val: const u8[:], indexing: HpackIndexing = HpackIndexing.Incremental, use_huffman: bool = true) -> bool
fn select_hpack_indexing(name: const u8[:], val: const u8[:], max_table_size: i64) -> HpackIndexing
```

`DynamicTable` manages HPACK dynamic entries (`HpackHeaderField`) in a circular
ring buffer and 4 KB arena with O(1) generation-stamped hash lookups.
`decode_hpack_to_map` and `decode_hpack_field_step_to_map` decode HPACK blocks
directly into `PseudoHeaders` (`:method`, `:scheme`, `:authority`, `:path`,
`:protocol`, `:status`) and `wing::HeaderMap` while enforcing RFC 9113 §8.2
pseudo-header ordering and `max_header_list_size` limits.
`select_hpack_indexing` chooses `NeverIndexed` or `None` for sensitive,
volatile, or oversized header fields.

### Connection State & Stream Multiplexing (`connection.goose`)

```goose
enum StreamState { Idle, ReservedLocal, ReservedRemote, Open, HalfClosedLocal, HalfClosedRemote, Closed }
struct Stream
struct Connection

fn new_h2_connection(now_ms: u64 = 0, max_header_list: u32 = 8192, behind_proxy: bool = false) -> Connection
fn find_stream_idx(s: const Connection&, stream_id: u32) -> i32, bool
fn find_closed_stream_idx(s: const Connection&, stream_id: u32) -> i32, bool
fn open_stream(s: Connection&, stream_id: u32, end_stream: bool)
fn close_local_stream(s: Connection&, stream_id: u32)
fn reset_stream(s: Connection&, stream_id: u32)
fn on_ingress_frame_header(s: Connection&, hdr: const FrameHeader&, now_ms: u64) -> u32
fn on_data_frame_received(s: Connection&, hdr: const FrameHeader&, payload_len: u32) -> u32
fn apply_peer_initial_window_size_delta(s: Connection&, new_init_win: u32) -> u32
fn apply_window_update(s: Connection&, stream_id: u32, increment: u32) -> u32
fn apply_goaway(s: Connection&, last_stream_id: u32, error_code: u32) -> u32
fn apply_priority_update(s: Connection&, prioritized_stream_id: u32, prio: wing::PriorityParam) -> u32
fn enqueue_stream_send_bytes(s: Connection&, stream_id: u32, bytes: u32) -> bool
fn schedule_next_write(s: Connection&, max_frame_len: u32) -> u32, u32, bool
```

`Connection` coordinates stream lifecycles (`Stream`, `StreamState`), connection
and stream flow-control windows, and rate limiting via `core::TokenBucket`
(defending against CVE-2023-44487 Rapid Reset, `CONTINUATION` floods,
`PING`/`SETTINGS` floods, and empty-frame streaks). `schedule_next_write`
implements an RFC 9218 stream scheduler across urgency buckets `0..7` with
incremental round-robin sharing and anti-starvation yielding.
