# `realtime`

`realtime` (`namespace realtime;`) provides the real-time streaming and pub/sub
subsystem for `goose-wing`, supporting WebSockets (RFC 6455, RFC 7692, RFC 8441,
RFC 9220), Server-Sent Events (W3C EventSource), WebTransport over HTTP/3
(draft-ietf-webtrans-http3-16, RFC 9221, RFC 9297), and MQTT v5.0 pub/sub topic
routing.

Internal-only helpers, masks, and state mechanics live in
`namespace realtime_internal` (`realtime/internal.goose`).

```goose
import wing;

var ws = realtime::new_websocket_session(true);
var out: u8[..256] = [];
ws.send_text("hello", out);
```

## Public API Reference

### 1. WebSocket Framing & Session Engine (`realtime/websocket.goose`)

```goose
enum WsSendStatus { Success, Backpressure, Dropped, Closed }
enum WsHeartbeatAction { None, SendPing, CloseIdle, CloseMaxLifetime }
enum WsRole { Client, Server }

struct WsFrameHeader {
    fin:         bool  = true,
    rsv1:        bool  = false,
    rsv2:        bool  = false,
    rsv3:        bool  = false,
    opcode:      u8    = rfc::WS_OPCODE_TEXT,
    masked:      bool  = false,
    mask_key:    u8[4] = [0; 4],
    payload_len: u64   = 0,
    header_len:  u16   = 0,
}
struct WsBehavior {
    compression:                 u16      = WS_COMPRESS_DISABLED,
    max_payload_length:          u64      = 65536,
    idle_timeout_s:              u32      = 120,
    max_lifetime_s:              u32      = 0,
    max_backpressure:            u64      = 1048576,
    close_on_backpressure_limit: bool     = false,
    reset_idle_timeout_on_send:  bool     = true,
    send_pings_automatically:    bool     = false,
    subprotocol:                 u8[..64] = [],
    handler_id:                  i32      = -1,
}
struct WebSocketSession { .. }
struct WsPendingUpgrade { .. }
struct WsMessage {
    opcode:       u8          = rfc::WS_OPCODE_TEXT,
    data:         u8[..16384] = [],
    close_code:   u16         = 0,
    close_reason: u8[..128]   = [],
    is_valid:     bool        = false,
}
struct WsMessageView {
    opcode:        u8          = rfc::WS_OPCODE_TEXT,
    payload:       const u8[:] = "",
    close_code:    u16         = 0,
    close_reason:  const u8[:] = "",
    is_valid:      bool        = false,
    is_compressed: bool        = false,
}

fn unmask_websocket_shifted(frame: u8[:], header_len: i64, payload_len: i64, mask_key: const u8[4]&) -> u8[:]
fn apply_mask_in_place(data: u8[:], mask_key: const u8[4]&)
fn mask_websocket_payload(data: u8[:], mask_key: const u8[4]&)
fn parse_ws_frame_header(src: const u8[:]) -> WsFrameHeader, bool
fn encode<B>(hdr: const WsFrameHeader&, out: B&)
fn encode_ws_frame<B>(out: B&, opcode: u8, payload: const u8[:], is_client: bool = true, mask_key: const u8[4] = [0 as u8; 4], fin: bool = true)
fn calc_ws_frame_len(payload_len: u64, is_client: bool) -> u64
fn encode_close_payload<B>(out: B&, status_code: u16, reason: const u8[:])
fn parse_close_payload(payload: const u8[:]) -> u16, const u8[:], bool
fn new_ws_behavior(handler_id: i32 = -1) -> WsBehavior
fn new_websocket_session(is_client: bool = true) -> WebSocketSession
fn set_max_payload_length(ws: WebSocketSession&, max_len: u64)
fn arm_heartbeat(ws: WebSocketSession&, wheel: const core::TickTimerWheel&)
fn disarm_heartbeat(ws: WebSocketSession&)
fn ws_advance_lifetime(ws: WebSocketSession&, elapsed_seconds: u32 = 1)
fn touch(ws: WebSocketSession&, wheel: const core::TickTimerWheel&)
fn check_heartbeat(ws: WebSocketSession&, wheel: const core::TickTimerWheel&) -> WsHeartbeatAction
fn tick_heartbeat<B>(ws: WebSocketSession&, wheel: const core::TickTimerWheel&, out_wire: B&) -> WsHeartbeatAction
fn new_ws_pending_upgrade(sock_fd: i64, client_key: const u8[:], route_idx: i32 = -1, subprotocol: const u8[:] = "", extensions: const u8[:] = "") -> WsPendingUpgrade
fn abort(pending: WsPendingUpgrade&)
fn abort_with_hook<AbortFn: fn(i64, u64)>(pending: WsPendingUpgrade&)
fn set_user_data(pending: WsPendingUpgrade&, data: const u8[:]) -> bool
fn set_user_tag(pending: WsPendingUpgrade&, tag: u64)
fn set_user_data(ws: WebSocketSession&, data: const u8[:]) -> bool
fn set_user_tag(ws: WebSocketSession&, tag: u64)
fn set_max_backpressure(ws: WebSocketSession&, max_bytes: u64, close_on_limit: bool = false)
fn notify_buffered<B>(ws: WebSocketSession&, bytes_added: u64, out_close: B&) -> WsSendStatus
fn notify_drained(ws: WebSocketSession&, bytes_drained: u64) -> bool
fn enable_permessage_deflate(ws: WebSocketSession&, mode: u16 = WS_COMPRESS_SHARED_COMPRESSOR, opts: WsContextTakeoverOptions = WsContextTakeoverOptions { server_no_context: true, client_no_context: true })
fn build_handshake_request<B>(ws: const WebSocketSession&, host: const u8[:], path: const u8[:], client_key: const u8[:], out: B&)
fn send_text<B>(ws: WebSocketSession&, text: const u8[:], out: B&)
fn send_text_with_status<B>(ws: WebSocketSession&, text: const u8[:], out: B&, compress: bool = false) -> WsSendStatus
fn send_text_compressed_with_status<B>(ws: WebSocketSession&, text: const u8[:], shared_comp: SharedWsCompressor&, out: B&, compress: bool = true) -> WsSendStatus
fn send_binary<B>(ws: WebSocketSession&, data: const u8[:], out: B&)
fn send_binary_with_status<B>(ws: WebSocketSession&, data: const u8[:], out: B&, compress: bool = false) -> WsSendStatus
fn send_binary_compressed_with_status<B>(ws: WebSocketSession&, data: const u8[:], shared_comp: SharedWsCompressor&, out: B&, compress: bool = true) -> WsSendStatus
fn send_ping<B>(ws: WebSocketSession&, ping_payload: const u8[:], out: B&)
fn send_pong<B>(ws: WebSocketSession&, pong_payload: const u8[:], out: B&)
fn send_fragment<B>(ws: WebSocketSession&, opcode: u8, payload: const u8[:], fin: bool, out: B&)
fn close_at<B>(ws: WebSocketSession&, status_code: u16, reason: const u8[:], now_ms: u64, out: B&)
fn is_close_handshake_expired(ws: const WebSocketSession&, now_ms: u64) -> bool
fn close<B>(ws: WebSocketSession&, status_code: u16, reason: const u8[:], out: B&)
fn is_ws_masking_valid(role: WsRole, masked: bool) -> bool
fn receive_view<B>(ws: WebSocketSession&, wire: u8[:], out_view: WsMessageView&, out_reply: B&) -> bool
fn consume_frame_view<B>(ws: WebSocketSession&, wire: u8[:], out_view: WsMessageView&, out_reply: B&) -> i64, bool
fn receive<B>(ws: WebSocketSession&, wire: u8[:], out_msg: WsMessage&, out_reply: B&) -> bool
fn drain_ws_session_frames<Stage, FragBuf, OutBuf>(conn_fd: i64, ws: WebSocketSession&, stage: Stage&, in_slice: u8[:], frag_buf: FragBuf&, out_wire: OutBuf&) -> i64
fn serve_ws_session_buf<Stage, InBuf, FragBuf, OutBuf>(conn_fd: i64, ws: WebSocketSession&, stage: Stage&, in_buf: InBuf&, frag_buf: FragBuf&, out_wire: OutBuf&)
fn serve_ws_session_buf<InBuf, FragBuf, OutBuf>(conn_fd: i64, ws: WebSocketSession&, in_buf: InBuf&, frag_buf: FragBuf&, out_wire: OutBuf&)
```

`WebSocketSession` handles fragmented message reassembly with streaming UTF-8
DFA validation, 64-bit/32-bit SWAR and SIMD XOR unmasking
(`apply_mask_in_place`, `mask_websocket_payload`, `unmask_websocket_shifted`),
heartbeat timers (`arm_heartbeat`, `tick_heartbeat`), and egress backpressure
(`notify_buffered`, `notify_drained`). `ws.consume_frame_view(...)` returns
`(bytes_consumed, ok)` and populates `WsMessageView` with a zero-copy slice over
the receive buffer.

### 2. WebSocket Handshakes (`realtime/ws_handshake.goose`)

```goose
enum WsError {
    None,
    InvalidStatusCode,
    MissingUpgradeHeader,
    MissingConnectionHeader,
    InvalidAcceptKey,
    InvalidSubprotocol,
    InvalidExtension,
}

fn compute_websocket_accept<B>(client_key: const u8[:], out: B&)
fn is_valid_websocket_key(key: const u8[:]) -> bool
fn validate_websocket_accept(client_key: const u8[:], server_accept: const u8[:]) -> bool
fn generate_websocket_key<B>(random_16: const u8[16]&, out: B&)
fn has_subprotocol_token(list: const u8[:], target: const u8[:]) -> bool
fn validate_client_upgrade_response(status_code: u16, headers: const wing::HeaderMap&, raw_buf: const u8[:], client_key: const u8[:], offered_protocols: const u8[:], offered_extensions: const u8[:] = "") -> const u8[:], WsError
fn ws_upgrade_request(req: const wing::Request&, out_resp: wing::Response&, subprotocol: const u8[:] = "") -> WebSocketSession, bool
fn is_websocket_upgrade_request(req: const wing::Request&) -> bool
fn is_h2_websocket_request(req: const wing::Request&) -> bool
fn validate_h2_websocket_request(req: const wing::Request&) -> bool
fn format_h2_websocket_request(req: wing::Request&, path: const u8[:], authority: const u8[:], scheme: const u8[:] = "https", subprotocol: const u8[:] = "")
fn ws_h2_upgrade_request(req: const wing::Request&, out_resp: wing::Response&, subprotocol: const u8[:] = "") -> WebSocketSession, bool
fn is_h2_websocket_response(res: const wing::Response&) -> bool
fn format_h3_websocket_request(req: wing::Request&, path: const u8[:], authority: const u8[:], scheme: const u8[:] = "https", subprotocol: const u8[:] = "")
fn validate_h3_websocket_request(req: const wing::Request&) -> bool
fn ws_h3_upgrade_request(req: const wing::Request&, out_resp: wing::Response&, subprotocol: const u8[:] = "") -> WebSocketSession, bool
fn format_h3_websocket_response(res: wing::Response&, subprotocol: const u8[:] = "")
fn is_h3_websocket_response(res: const wing::Response&) -> bool
fn is_extended_connect_request(req: const wing::Request&) -> bool
fn ws_encapsulate_stream_data<B>(out: B&, opcode: u8, payload: const u8[:], is_client: bool, mask_key: const u8[4] = [0x11, 0x22, 0x33, 0x44])
```

Implements HTTP/1.1 `101 Switching Protocols` upgrades (RFC 6455), HTTP/2
Extended CONNECT (RFC 8441), and HTTP/3 Extended CONNECT (RFC 9220).

### 3. `permessage-deflate` Compression (`realtime/ws_deflate.goose`)

```goose
const WS_COMPRESS_DISABLED:            u16 = 0;
const WS_COMPRESS_SHARED_COMPRESSOR:   u16 = 1;
const WS_COMPRESS_SHARED_DECOMPRESSOR: u16 = 1 << 8;
const WS_COMPRESS_DEDICATED:           u16 = 15 << 4 | 8;

struct SharedWsCompressor { .. }
struct DedicatedWsCompressor {
    window_kb:          i64         = 32,
    history:            u8[..65536] = [],
    compress_buf:       u8[..65536] = [],
    decompress_buf:     u8[..65536] = [],
    total_compressed:   u64         = 0,
    total_uncompressed: u64         = 0,
    total_decompressed: u64         = 0,
}
struct WsContextTakeoverOptions {
    server_no_context: bool = false,
    client_no_context: bool = false,
}
struct PerMessageDeflateConfig {
    server_max_window_bits:     u8   = rfc::WS_PMD_MAX_WINDOW_BITS,
    client_max_window_bits:     u8   = rfc::WS_PMD_MAX_WINDOW_BITS,
    server_no_context_takeover: bool = false,
    client_no_context_takeover: bool = false,
}

fn ws_deflate_message_slice(shared: SharedWsCompressor&, raw: const u8[:], reset_window: bool = true) -> const u8[:], bool
fn ws_deflate_message<B>(shared: SharedWsCompressor&, raw: const u8[:], out_wire: B&, reset_window: bool = true) -> bool
fn ws_inflate_message<B>(shared: SharedWsCompressor&, compressed: const u8[:], out_plain: B&, max_payload: i64 = 65536, reset_window: bool = true) -> bool
fn new_dedicated_ws_compressor(window_kb: i64 = 32) -> DedicatedWsCompressor
fn deflate_message_dedicated<B>(dedicated: DedicatedWsCompressor&, raw: const u8[:], out_wire: B&, reset_window: bool = false) -> bool
fn inflate_message_dedicated<B>(dedicated: DedicatedWsCompressor&, compressed: const u8[:], out_plain: B&, max_payload: i64 = 65536, reset_window: bool = false) -> bool
fn encode_ws_frame_compressed<B>(out: B&, opcode: u8, compressed_payload: const u8[:], masked: bool = false, mask_key: const u8[4]& = [0, 0, 0, 0], fin: bool = true)
fn ws_has_broken_compression(user_agent: const u8[:]) -> bool
fn negotiate_permessage_deflate(ext_header: const u8[:], server_cfg: const PerMessageDeflateConfig&) -> PerMessageDeflateConfig, bool
fn append_permessage_deflate_response<B>(cfg: const PerMessageDeflateConfig&, out: B&)
fn set_context_takeover(ws: WebSocketSession&, opts: WsContextTakeoverOptions)
fn ws_should_reset_compressor(ws: const WebSocketSession&) -> bool
fn ws_should_reset_decompressor(ws: const WebSocketSession&) -> bool
```

Implements RFC 7692 `permessage-deflate` negotiation, Safari 15.0-15.3
workaround detection, shared zero-alloc reactor compression, and dedicated
sliding-window compression contexts.

### 4. Pub/Sub Topic Tree (`realtime/topic_tree.goose`, OASIS MQTT v5.0)

```goose
enum PubSubError { None, InvalidTopic, MessageTooLarge, CapacityExceeded }

struct RetainedEntry {
    active:    bool       = false,
    is_binary: bool       = false,
    topic:     u8[..128]  = [],
    payload:   u8[..1024] = [],
}
struct PreparedMessage { .. }
struct TopicTree { .. }

fn match_topic(pattern: const u8[:], topic: const u8[:]) -> bool
fn is_valid_topic_filter(pattern: const u8[:]) -> bool
fn is_valid_publish_topic(topic: const u8[:]) -> bool
fn subscribe_ex(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> i32, i32, bool
fn subscribe(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool
fn subscribe_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool
fn unsubscribe_ex(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> i32, i32, bool
fn unsubscribe(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool
fn unsubscribe_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool
fn unsubscribe_all(tree: TopicTree&, sock_fd: i64) -> i32
fn unsubscribe_all_with_hook<HookFn: fn(const u8[:], i32, i32, i64)>(tree: TopicTree&, sock_fd: i64) -> i32
fn is_subscribed(tree: const TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool
fn subscriber_count(tree: const TopicTree&, pattern: const u8[:]) -> i32
fn socket_subscription_count(tree: const TopicTree&, sock_fd: i64) -> i32
fn get_socket_topics(tree: const TopicTree&, sock_fd: i64, out_topics: u8[..64][..32]&) -> i32
fn iterate_socket_topics<IterFn: fn(const u8[:])>(tree: const TopicTree&, sock_fd: i64) -> i32
fn add_distinct_subscriber(tree: TopicTree&, topic: const u8[:], sub_id: u32) -> i32, bool
fn add_distinct_subscriber(out_fds: i64[..512]&, seen_mask: u64[4]&, fd: i64) -> i32, bool
fn find_subscribers_checked(tree: const TopicTree&, topic: const u8[:], out_fds: i64[..512]&) -> i64, bool
fn find_subscribers(tree: const TopicTree&, topic: const u8[:], out_fds: i64[..512]&) -> i64
fn publish_frame(tree: TopicTree&, topic: const u8[:], frame_wire: const u8[:]) -> i64
fn publish(tree: TopicTree&, topic: const u8[:], message: const u8[:], opcode: u8 = rfc::WS_OPCODE_TEXT) -> i64
fn publish_text(tree: TopicTree&, topic: const u8[:], text: const u8[:]) -> i64
fn publish_binary(tree: TopicTree&, topic: const u8[:], data: const u8[:]) -> i64
fn prepare_message(out_msg: PreparedMessage&, payload: const u8[:], opcode: u8 = rfc::WS_OPCODE_TEXT) -> bool
fn prepare_message_compressed(out_msg: PreparedMessage&, payload: const u8[:], shared_comp: SharedWsCompressor&, opcode: u8 = rfc::WS_OPCODE_TEXT) -> bool
fn publish_prepared(tree: TopicTree&, topic: const u8[:], msg: const PreparedMessage&) -> i64
fn drain_subscriber(tree: TopicTree&, node_idx: i32) -> i64
fn drain(tree: TopicTree&) -> i64
fn publish_batch(tree: TopicTree&, topic: const u8[:], payload: const u8[:], opcode: u8 = rfc::WS_OPCODE_TEXT, sender_fd: i64 = -1) -> i64
fn drainable_count(tree: const TopicTree&) -> i32
fn subscriber_needs_drain(tree: const TopicTree&, sock_fd: i64) -> bool
fn subscriber_queued_messages(tree: const TopicTree&, sock_fd: i64) -> i32
fn publish_retained(tree: TopicTree&, topic: const u8[:], payload: const u8[:], is_binary: bool) -> u32, PubSubError
fn subscribe_with_retained(tree: TopicTree&, sub_id: u64, pattern: const u8[:]) -> PubSubError
```

`TopicTree` routes messages across 256 topic buckets, 4096 subscriptions, 64
retained messages (`RetainedEntry`), and 64 queued batch messages without heap
allocation. `subscribe_ex` and `unsubscribe_ex` return `(old_count, new_count,
ok)`.

### 5. Server-Sent Events (`realtime/sse.goose`, W3C EventSource)

```goose
struct SseEvent {
    event:    u8[..64]   = [],
    data:     u8[..4096] = [],
    id:       u8[..128]  = [],
    retry_ms: u32        = 0,
    is_valid: bool       = false,
}
struct SseParser { .. }
struct SseSubscription {
    parser:    SseParser  = SseParser { .. },
    url:       u8[..2048] = [],
    connected: bool       = false,
}

fn sse_feed<E>(p: SseParser&, chunk: const u8[:], out_events: E&)
fn sse_flush(p: SseParser&)
fn sse_format_event<B>(out: B&, event_type: const u8[:], data: const u8[:], id: const u8[:] = "", retry_ms: u32 = 0)
fn new_sse_subscription(url: const u8[:] = "") -> SseSubscription
fn sse_build_request_headers<B>(sub: const SseSubscription&, host: const u8[:], path: const u8[:], out: B&)
fn consume<E>(sub: SseSubscription&, chunk: const u8[:], out_events: E&)
fn prepare_request(sub: const SseSubscription&, req: wing::Request&)
fn init_response(res: wing::Response&)
```

`SseParser` parses streaming chunks across `CR`, `LF`, and `CRLF` line endings,
strips leading UTF-8 BOM sequences, ignores `:` comment lines, and emits
completed `SseEvent` records into `out_events`. `sse_flush` discards incomplete
trailing fields at EOF per W3C EventSource Section 9.2.6 while preserving
`last_event_id` and `retry_ms`.

### 6. WebTransport over HTTP/3 (`realtime/webtransport.goose`)

```goose
enum WebTransportStreamKind { Bidirectional, Unidirectional, Unknown }
enum WebTransportSessionState { Closed, Connecting, Active, Draining }

struct WebTransportSession { .. }
struct WebTransportDatagram { session_id: u64 = 0, payload: u8[..1500] = [] }
struct WebTransportUniStreamHeader { session_id: u64 = 0, header_len: i64 = 0 }
struct WebTransportBidiStreamHeader { session_id: u64 = 0, header_len: i64 = 0 }
struct WebTransportCloseSession { error_code: u32 = 0, reason: u8[..1024] = [] }
struct WebTransportStreamReset { stream_id: u64 = 0, error_code: u32 = 0 }
struct WebTransportStreamStopSending { stream_id: u64 = 0, error_code: u32 = 0 }
struct WebTransportStreamPayload { .. }
struct WebTransportDemuxer { .. }

fn read_varint(wire: const u8[:], idx: i64&) -> u64, bool
fn format_webtransport_connect_request(req: wing::Request&, url_target: const u8[:])
fn is_webtransport_connect_request(req: const wing::Request&) -> bool
fn format_webtransport_connect_response(res: wing::Response&)
fn handle_webtransport_response(session: WebTransportSession&, res: const wing::Response&) -> bool
fn encode_webtransport_uni_stream_header<B>(session_id: u64, out: B&)
fn decode_webtransport_uni_stream_header(wire: const u8[:]) -> WebTransportUniStreamHeader, bool
fn encode_webtransport_bidi_stream_header<B>(session_id: u64, out: B&)
fn decode_webtransport_bidi_stream_header(wire: const u8[:]) -> WebTransportBidiStreamHeader, bool
fn encode_webtransport_datagram<B>(session_id: u64, payload: const u8[:], out: B&)
fn decode_webtransport_datagram(wire: const u8[:], out: WebTransportDatagram&) -> bool
fn encode_quic_datagram_frame<B>(datagram_payload: const u8[:], out: B&)
fn decode_quic_datagram_frame<B>(wire: const u8[:], out_payload: B&) -> bool
fn webtransport_code_to_http_code(app_err: u32) -> u64
fn http_code_to_webtransport_code(h3_err: u64) -> u32, bool
fn encode_webtransport_close_session<B>(error_code: u32, reason: const u8[:], out: B&)
fn decode_webtransport_close_session(payload: const u8[:], out: WebTransportCloseSession&) -> bool
fn encode_webtransport_drain_session<B>(out: B&)
fn decode_webtransport_drain_session(payload: const u8[:]) -> bool
fn encode_webtransport_reset_stream<B>(stream_id: u64, error_code: u32, out: B&)
fn decode_webtransport_reset_stream(payload: const u8[:]) -> WebTransportStreamReset, bool
fn encode_webtransport_stop_sending<B>(stream_id: u64, error_code: u32, out: B&)
fn decode_webtransport_stop_sending(payload: const u8[:]) -> WebTransportStreamStopSending, bool
fn close_webtransport_session(session: WebTransportSession&, code: u32, reason: const u8[:])
fn drain_webtransport_session(session: WebTransportSession&)
fn is_webtransport_session_open(session: const WebTransportSession&) -> bool
fn demux_webtransport_bidi_stream(wire: const u8[:]) -> u64, const u8[:], bool
fn demux_webtransport_uni_stream(wire: const u8[:]) -> u64, const u8[:], bool
fn register_webtransport_session(demuxer: WebTransportDemuxer&, session_id: u64) -> bool
fn set_webtransport_session_state(demuxer: WebTransportDemuxer&, session_id: u64, state: WebTransportSessionState) -> bool
fn get_webtransport_session_state(demuxer: const WebTransportDemuxer&, session_id: u64) -> WebTransportSessionState, bool
fn drain_webtransport_demuxer_session(demuxer: WebTransportDemuxer&, session_id: u64) -> bool
fn close_webtransport_demuxer_session(demuxer: WebTransportDemuxer&, session_id: u64, code: u32, reason: const u8[:]) -> bool
fn demux_webtransport_stream(demuxer: WebTransportDemuxer&, stream_id: u64, wire: const u8[:], fin: bool, out: WebTransportStreamPayload&) -> bool
```

Implements Extended CONNECT `:protocol = webtransport` handshakes,
unidirectional (`0x54`) and bidirectional (`0x41`) stream framing,
quarter-stream ID datagrams, HTTP/3 error code translation, and session capsules
(`CLOSE_WEBTRANSPORT_SESSION`, `DRAIN_WEBTRANSPORT_SESSION`, `WT_RESET_STREAM`,
`WT_STOP_SENDING`).
