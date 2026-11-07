# Real-Time Streaming & Pub/Sub (`realtime/`)

Real-time streaming and bidirectional communications subsystem supporting
WebSockets (RFC 6455, RFC 7692, RFC 8441), Server-Sent Events (W3C EventSource),
WebTransport over HTTP/3 (RFC 9297), and MQTT v5.0 Pub/Sub topic routing.

```goose
import wing;

var ws = new_websocket_session(true);
var out: u8[..256] = [];
send_text(ws, "hello", out);
```

## Public API

### WebSocket Protocol Engine (`realtime/websocket.goose`, RFC 6455, RFC 7692, RFC 8441)

```goose
struct WsFrameHeader {
    fin: bool, rsv1: bool, rsv2: bool, rsv3: bool,
    opcode: u8, masked: bool, mask_key: u8[4],
    payload_len: u64, header_len: i64,
}
struct PerMessageDeflateConfig {
    enabled: bool,
    server_no_context_takeover: bool,
    client_no_context_takeover: bool,
    server_max_window_bits: u8,
    client_max_window_bits: u8,
}
struct SharedWsCompressor { .. }
struct DedicatedWsCompressor {
    sliding_window: u8[..32768],
    max_window_size: i64,
    context_takeover: bool,
}
struct WebSocketSession { .. }
struct WsMessage { opcode: u8, payload: u8[>..] }
struct WsMessageView { opcode: u8, payload: const u8[:] }
struct WsBehavior {
    max_payload_length: u64,
    idle_timeout_sec: u32,
    compression: bool,
    max_backpressure: u64,
}
struct WsPendingUpgrade { .. }
enum WsRole { Client, Server }
enum WsSendStatus { Success, Dropped, BackpressureLimitReached }
enum WsHeartbeatAction { None, SendPing, CloseTimeout }

fn new_websocket_session(is_client: bool = true) -> WebSocketSession
fn new_ws_pending_upgrade(sock_fd: i64, client_key: const u8[:], route_idx: i32 = -1, subprotocol: const u8[:] = "", extensions: const u8[:] = "") -> WsPendingUpgrade
fn set_user_data(pending: WsPendingUpgrade&, data: const u8[:]) -> bool
fn set_user_tag(pending: WsPendingUpgrade&, tag: u64)
fn abort(pending: WsPendingUpgrade&)
fn abort_with_hook<AbortFn: fn(i64, u64)>(pending: WsPendingUpgrade&)
fn new_dedicated_ws_compressor(window_bits: u8 = 15, takeover: bool = true) -> DedicatedWsCompressor
fn deflate_message_dedicated<B>(comp: DedicatedWsCompressor&, input: const u8[:], out: B&) -> bool
fn inflate_message_dedicated<B>(comp: DedicatedWsCompressor&, compressed_payload: const u8[:], out: B&) -> bool
fn negotiate_permessage_deflate(ext_header: const u8[:], server_cfg: const PerMessageDeflateConfig&) -> PerMessageDeflateConfig, bool
fn append_permessage_deflate_response<B>(cfg: const PerMessageDeflateConfig&, out: B&)
fn parse_ws_frame_header(src: const u8[:]) -> WsFrameHeader, bool
fn encode_ws_frame<B>(out: B&, opcode: u8, fin: bool, masked: bool, mask_key: const u8[4]&, payload: const u8[:])
fn encode_ws_frame_compressed<B>(out: B&, opcode: u8, fin: bool, masked: bool, mask_key: const u8[4]&, payload: const u8[:], compressor: SharedWsCompressor&)
fn apply_mask_in_place(data: u8[:], mask_key: const u8[4]&)
fn unmask_websocket_shifted(frame: u8[:], header_len: i64, payload_len: i64, mask_key: const u8[4]&) -> u8[:]
fn receive_view<B>(ws: WebSocketSession&, wire: u8[:], out_view: WsMessageView&, out_reply: B&) -> bool
fn consume_frame_view<B>(ws: WebSocketSession&, wire: u8[:], out_view: WsMessageView&, out_reply: B&) -> i64, bool
fn send_text<B>(ws: WebSocketSession&, text: const u8[:], out: B&)
fn send_binary<B>(ws: WebSocketSession&, data: const u8[:], out: B&)
fn send_ping<B>(ws: WebSocketSession&, ping_payload: const u8[:], out: B&)
fn send_pong<B>(ws: WebSocketSession&, pong_payload: const u8[:], out: B&)
fn close<B>(ws: WebSocketSession&, status_code: u16, reason: const u8[:], out: B&)
fn ws_upgrade_request(req: const Request&, res: Response&, subprotocols: const u8[:][..4] = []) -> bool
fn is_websocket_upgrade_request(req: const Request&) -> bool
fn ws_h2_upgrade_request(req: const Request&, res: Response&, subprotocol: const u8[:] = "") -> bool
fn ws_h3_upgrade_request(req: const Request&, res: Response&, subprotocol: const u8[:] = "") -> bool
fn serve_ws_session_buf<OnMsgFn>(ws: WebSocketSession&, client_ip: const u8[:], wire_in: u8[:], out_wire: u8[>..]&) -> bool
fn arm_heartbeat(ws: WebSocketSession&, wheel: const TickTimerWheel&)
fn tick_heartbeat<B>(ws: WebSocketSession&, wheel: const TickTimerWheel&, out_wire: B&) -> WsHeartbeatAction
fn set_max_backpressure(ws: WebSocketSession&, max_bytes: u64, close_on_limit: bool = false)
```

`WebSocketSession` manages HTTP/1.1 (`101 Switching Protocols`) and HTTP/2 or
HTTP/3 Extended CONNECT (`RFC 8441`) upgrades, fragmented message reassembly,
64-bit/32-bit SWAR in-place XOR unmasking (`apply_mask_in_place`,
`unmask_websocket_shifted`), RFC 7692 `permessage-deflate` compression
(stripping the trailing `0x00 0x00 0xFF 0xFF` sync marker), heartbeat timers,
and egress backpressure limits. `consume_frame_view` returns `(bytes_consumed,
ok)` and populates `WsMessageView` with a zero-copy slice over the receive
buffer.

### Pub/Sub Topic Tree (`realtime/topic_tree.goose`, OASIS MQTT v5.0 §4.7)

```goose
enum PubSubError {
    None, InvalidTopicFilter, TopicTooLong, SubscriptionTableFull,
    BucketTableFull, SocketNotFound, RetainTableFull,
}
struct TopicTree { .. }
struct RetainedEntry {
    topic: u8[..128],
    payload: u8[..1024],
    opcode: u8,
    active: bool,
}
struct PreparedMessage { .. }
struct TopicSubscriptionEvent { .. }

fn match_topic(pattern: const u8[:], topic: const u8[:]) -> bool
fn is_valid_topic_filter(pattern: const u8[:]) -> bool
fn is_valid_publish_topic(topic: const u8[:]) -> bool
fn subscribe(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool
fn subscribe_ex(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> PubSubError
fn subscribe_with_hook<HookFn>(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool
fn unsubscribe(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool
fn unsubscribe_ex(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> PubSubError
fn unsubscribe_all(tree: TopicTree&, sock_fd: i64) -> i32
fn is_subscribed(tree: const TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool
fn subscriber_count(tree: const TopicTree&, pattern: const u8[:]) -> i32
fn socket_subscription_count(tree: const TopicTree&, sock_fd: i64) -> i32
fn publish_text(tree: TopicTree&, topic: const u8[:], text: const u8[:]) -> i64
fn publish_binary(tree: TopicTree&, topic: const u8[:], data: const u8[:]) -> i64
fn publish_retained(tree: TopicTree&, topic: const u8[:], payload: const u8[:], is_binary: bool) -> u32, PubSubError
fn subscribe_with_retained(tree: TopicTree&, sub_id: u64, pattern: const u8[:]) -> PubSubError
fn prepare_message(out_msg: PreparedMessage&, payload: const u8[:], opcode: u8 = rfc::WS_OPCODE_TEXT) -> bool
fn prepare_message_compressed(out_msg: PreparedMessage&, payload: const u8[:], shared_comp: SharedWsCompressor&, opcode: u8 = rfc::WS_OPCODE_TEXT) -> bool
fn publish_prepared(tree: TopicTree&, topic: const u8[:], msg: const PreparedMessage&) -> i64
fn publish_batch(tree: TopicTree&, topic: const u8[:], payload: const u8[:], opcode: u8 = rfc::WS_OPCODE_TEXT, sender_fd: i64 = -1) -> i64
fn drain(tree: TopicTree&) -> i64
```

`TopicTree` routes messages across 256 topic buckets, 4096 subscriptions, 64
retained messages (`RetainedEntry`), and 64 queued batch messages without heap
allocation. `match_topic` evaluates MQTT single-level (`+`) and multi-level
(`#`) wildcards; `prepare_message` and `prepare_message_compressed` pre-format
raw and deflated RFC 6455 frames once into `PreparedMessage` for fan-out via
`publish_prepared`.

### Server-Sent Events (`realtime/sse.goose`, W3C EventSource)

```goose
struct SseEvent {
    event: u8[..64],
    data: u8[..4096],
    id: u8[..128],
    retry_ms: i64,
    has_id: bool,
}
struct SseParser { .. }
struct SseSubscription { .. }

fn new_sse_subscription(url: const u8[:] = "") -> SseSubscription
fn sse_feed<E>(p: SseParser&, chunk: const u8[:], out_events: E&)
fn sse_flush<E>(p: SseParser&, out_events: E&)
fn sse_format_event<B>(out: B&, event_type: const u8[:], data: const u8[:], id: const u8[:] = "", retry_ms: i64 = -1)
fn prepare_request(sub: const SseSubscription&, req: Request&)
fn init_response(res: Response&)
```

`SseParser` parses streaming chunks across `CR`, `LF`, and `CRLF` line endings,
strips leading UTF-8 BOM sequences, ignores `:` comment lines, and emits
completed `SseEvent` records into `out_events`. `prepare_request` sets client
`Accept: text/event-stream` and `Last-Event-ID` headers, while `init_response`
configures server response headers for unbuffered event streaming.

### WebTransport over HTTP/3 (`realtime/webtransport.goose`, RFC 9297)

```goose
struct WebTransportSession { .. }
struct WebTransportDatagram { session_id: u64, payload: u8[..1500] }
struct WebTransportSessionEntry { .. }
struct WebTransportStreamRoute { .. }
struct WebTransportStreamPayload { .. }
struct WebTransportDemuxer {
    sessions: WebTransportSessionEntry[..16],
    stream_routes: WebTransportStreamRoute[..64],
}
enum WebTransportStreamKind { ControlOrHttp3, WebTransportUni, WebTransportBidi }
enum WebTransportSessionState { Connecting, Connected, Draining, Closed }

fn format_webtransport_connect_request(req: Request&, path: const u8[:], authority: const u8[:])
fn is_webtransport_connect_request(req: const Request&) -> bool
fn format_webtransport_connect_response(res: Response&)
fn encode_webtransport_uni_stream_header<B>(session_id: u64, out: B&)
fn decode_webtransport_uni_stream_header(wire: const u8[:], idx: i64&) -> u64, bool
fn encode_webtransport_bidi_stream_header<B>(session_id: u64, out: B&)
fn decode_webtransport_bidi_stream_header(wire: const u8[:], idx: i64&) -> u64, bool
fn encode_webtransport_datagram<B>(session_id: u64, payload: const u8[:], out: B&)
fn decode_webtransport_datagram(wire: const u8[:], idx: i64&) -> u64, const u8[:], bool
fn register_webtransport_session(demuxer: WebTransportDemuxer&, session_id: u64) -> bool
fn demux_webtransport_stream(demuxer: WebTransportDemuxer&, stream_id: u64, wire: const u8[:], fin: bool, out: WebTransportStreamPayload&) -> bool
fn close_webtransport_session<B>(sess: WebTransportSession&, error_code: u32, reason: const u8[:], out_capsule: B&)
fn drain_webtransport_session<B>(sess: WebTransportSession&, out_capsule: B&)
```

Implements RFC 9297 `:protocol: webtransport` Extended CONNECT handshakes
(`200 OK` with `Sec-Webtransport-Http3-Draft: draft02`), unidirectional stream
headers (`0x54`), bidirectional frame headers (`0x41`), quarter-stream ID varint
datagrams (`WebTransportDatagram`), and `CLOSE_WEBTRANSPORT_SESSION` (`0x2843`)
and `DRAIN_WEBTRANSPORT_SESSION` (`0x78AE`) capsules. On truncated varints or
mismatched stream prefixes, the `decode_webtransport_*` functions return
`false`.
