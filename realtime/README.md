# `realtime`

Package `realtime` (`namespace realtime;`) implements WebSockets (RFC 6455, RFC
7692 `permessage-deflate`, RFC 8441 HTTP/2, RFC 9220 HTTP/3), Server-Sent Events
(W3C EventSource), MQTT v5.0 wildcard pub/sub fan-out (`TopicTree`), and
WebTransport over HTTP/3 (draft-ietf-webtrans-http3-16, RFC 9221, RFC 9297).

Internal frame-loop mechanics, sliding-window helpers, handshake scanners, and
varint codecs live in `namespace realtime_internal;` across
`realtime/internal.goose`, `realtime/ws_pmd_internal.goose`, and
`realtime/pubsub_wt_internal.goose`.

## Quick start

```goose
import wing;

var ws = realtime::new_websocket_session(true);
var out: u8[..256] = [];
ws.send_text("hello", out);
print("wire bytes: ", out.len, "\n");
```

## Task recipes

### WebSocket server and client with RFC 7692 `permessage-deflate`

Upgrade an HTTP/1.1 request to a server `WebSocketSession` with
`ws_upgrade_request`, negotiate `permessage-deflate` parameters from the client
`Sec-WebSocket-Extensions` header, and run the frame loop with caller-owned
buffers via `serve_ws_session_buf`:

```goose
var resp = http::Response { .. };
var ws, ok = realtime::ws_upgrade_request(req, resp, "chat");
guard ok else { return; }

let server_pmd = realtime::PerMessageDeflateConfig {
    server_max_window_bits:     15,
    client_max_window_bits:     15,
    server_no_context_takeover: false,
    client_no_context_takeover: false,
};
let negotiated, use_pmd = realtime::negotiate_permessage_deflate(ext_hdr, server_pmd);
if use_pmd {
    ws.enable_permessage_deflate(
        realtime::WS_COMPRESS_DEDICATED,
        realtime::WsContextTakeoverOptions {
            server_no_context: negotiated.server_no_context_takeover,
            client_no_context: negotiated.client_no_context_takeover,
        },
    );
}

var in_buf:   u8[>..] = [];
var frag_buf: u8[>..] = [];
var out_wire: u8[>..] = [];
realtime::serve_ws_session_buf(conn_fd, ws, in_buf, frag_buf, out_wire);
```

On the client side, build the RFC 6455 upgrade request with
`build_handshake_request`, verify the `101 Switching Protocols` response with
`validate_client_upgrade_response`, and receive zero-copy frame slices using
`consume_frame_view`:

```goose
var cli = realtime::new_websocket_session(true);
var view = realtime::WsMessageView { .. };
var reply: u8[..256] = [];
let consumed, handled = cli.consume_frame_view(wire_slice, view, reply);
```

### Server-Sent Events (SSE)

Emit SSE responses on a server by initializing `text/event-stream` headers via
`init_response` and formatting events with `sse_format_event`:

```goose
var res = http::Response { .. };
realtime::init_response(res);

var wire: u8[..512] = [];
realtime::sse_format_event(wire, "update", "{\"seq\":1}", "ev-1", 3000);
```

Consume chunked SSE streams on a client using `SseSubscription` (handles UTF-8
BOM stripping, `CR`/`LF`/`CRLF` boundaries, `:` comments, and `Last-Event-ID`):

```goose
var sub = realtime::new_sse_subscription("https://api.example.com/events");
var events: realtime::SseEvent[..8] = [];
sub.consume("event: update\ndata: hello\n\n", events);
```

### `TopicTree` pub/sub fan-out

Route WebSocket messages across MQTT v5.0 `+` (single-level) and `#`
(multi-level) wildcards with duplicate suppression across overlapping patterns.
Use `publish_batch` plus `drain` to coalesce writes across high-fanout
subscribers, or `publish_retained` for last-known state:

```goose
var tree = realtime::TopicTree { .. };
let _ = tree.subscribe(conn_fd, "sensors/+/temp");
let _ = tree.publish_text("sensors/room1/temp", "21.5");

let _ = tree.publish_batch("sensors/room1/temp", "21.6");
let sent = tree.drain();
```

### WebTransport sessions and streams

Format and validate HTTP/3 Extended CONNECT `:protocol = webtransport`
handshakes, demultiplex unidirectional (`0x54`) and bidirectional (`0x41`) QUIC
streams per session, and exchange quarter-stream-ID datagrams:

```goose
var req = http::Request { .. };
realtime::format_webtransport_connect_request(req, "https://wt.example.com/chat");

var demux = realtime::WebTransportDemuxer { .. };
let _ = realtime::register_webtransport_session(demux, 4);

var out_stream = realtime::WebTransportStreamPayload { .. };
let routed = realtime::demux_webtransport_stream(demux, 8, wire, false, out_stream);

var dgram_wire: u8[..1600] = [];
realtime::encode_webtransport_datagram(4, "ping", dgram_wire);
```

## Public API reference

### WebSocket framing, sessions, and drivers (`realtime/websocket.goose`)

Frame parsing and encoding, 64-bit SWAR/SIMD masking, fragmented UTF-8 session
state, heartbeat tick-wheel timers, backpressure tracking, and session loops.

```goose
enum WsSendStatus { Success, Backpressure, Dropped, Closed }
enum WsHeartbeatAction { None, SendPing, CloseIdle, CloseMaxLifetime }
enum WsRole { Client, Server }
struct WsFrameHeader { .. }
struct WsBehavior { .. }
struct WebSocketSession { .. }
struct WsPendingUpgrade { .. }
struct WsMessage { .. }
struct WsMessageView { .. }

fn apply_mask_in_place(data: u8[:], mask_key: const u8[4]&)
fn mask_websocket_payload(data: u8[:], mask_key: const u8[4]&)
fn unmask_websocket_shifted(frame: u8[:], header_len: i64, payload_len: i64, mask_key: const u8[4]&) -> u8[:]
fn parse_ws_frame_header(src: const u8[:]) -> WsFrameHeader, bool
fn encode<B>(hdr: const WsFrameHeader&, out: B&)
fn encode_ws_frame<B>(out: B&, opcode: u8, payload: const u8[:], is_client: bool = true, mask_key: const u8[4] = [0 as u8; 4], fin: bool = true)
fn encode_close_payload<B>(out: B&, status_code: u16, reason: const u8[:])
fn parse_close_payload(payload: const u8[:]) -> u16, const u8[:], bool
fn new_ws_behavior(handler_id: i32 = -1) -> WsBehavior
fn new_websocket_session(is_client: bool = true) -> WebSocketSession
fn set_max_payload_length(ws: WebSocketSession&, max_len: u64)
fn arm_heartbeat(ws: WebSocketSession&, wheel: const core::TickTimerWheel&)
fn disarm_heartbeat(ws: WebSocketSession&)
fn touch(ws: WebSocketSession&, wheel: const core::TickTimerWheel&)
fn tick_heartbeat<B>(ws: WebSocketSession&, wheel: const core::TickTimerWheel&, out_wire: B&) -> WsHeartbeatAction
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
fn close<B>(ws: WebSocketSession&, status_code: u16, reason: const u8[:], out: B&)
fn close_at<B>(ws: WebSocketSession&, status_code: u16, reason: const u8[:], now_ms: u64, out: B&)
fn receive_view<B>(ws: WebSocketSession&, wire: u8[:], out_view: WsMessageView&, out_reply: B&) -> bool
fn consume_frame_view<B>(ws: WebSocketSession&, wire: u8[:], out_view: WsMessageView&, out_reply: B&) -> i64, bool
fn receive<B>(ws: WebSocketSession&, wire: u8[:], out_msg: WsMessage&, out_reply: B&) -> bool
fn serve_ws_session_buf<Stage, InBuf, FragBuf, OutBuf>(conn_fd: i64, ws: WebSocketSession&, stage: Stage&, in_buf: InBuf&, frag_buf: FragBuf&, out_wire: OutBuf&)
fn serve_ws_session_buf<InBuf, FragBuf, OutBuf>(conn_fd: i64, ws: WebSocketSession&, in_buf: InBuf&, frag_buf: FragBuf&, out_wire: OutBuf&)
```

### WebSocket handshakes (`realtime/ws_handshake.goose`)

HTTP/1.1 `101 Switching Protocols` upgrades (RFC 6455), HTTP/2 Extended CONNECT
(RFC 8441), and HTTP/3 Extended CONNECT (RFC 9220).

```goose
enum WsError { None, InvalidStatusCode, MissingUpgradeHeader, MissingConnectionHeader, InvalidAcceptKey, InvalidSubprotocol, InvalidExtension }

fn compute_websocket_accept<B>(client_key: const u8[:], out: B&)
fn is_valid_websocket_key(key: const u8[:]) -> bool
fn validate_websocket_accept(client_key: const u8[:], server_accept: const u8[:]) -> bool
fn generate_websocket_key<B>(random_16: const u8[16]&, out: B&)
fn has_subprotocol_token(list: const u8[:], target: const u8[:]) -> bool
fn validate_client_upgrade_response(status_code: u16, headers: const http::HeaderMap&, raw_buf: const u8[:], client_key: const u8[:], offered_protocols: const u8[:], offered_extensions: const u8[:] = "") -> const u8[:], WsError
fn ws_upgrade_request(req: const http::Request&, out_resp: http::Response&, subprotocol: const u8[:] = "") -> WebSocketSession, bool
fn is_websocket_upgrade_request(req: const http::Request&) -> bool
fn format_h2_websocket_request(req: http::Request&, path: const u8[:], authority: const u8[:], scheme: const u8[:] = "https", subprotocol: const u8[:] = "")
fn ws_h2_upgrade_request(req: const http::Request&, out_resp: http::Response&, subprotocol: const u8[:] = "") -> WebSocketSession, bool
fn format_h3_websocket_request(req: http::Request&, path: const u8[:], authority: const u8[:], scheme: const u8[:] = "https", subprotocol: const u8[:] = "")
fn ws_h3_upgrade_request(req: const http::Request&, out_resp: http::Response&, subprotocol: const u8[:] = "") -> WebSocketSession, bool
fn is_extended_connect_request(req: const http::Request&) -> bool
fn ws_encapsulate_stream_data<B>(out: B&, opcode: u8, payload: const u8[:], is_client: bool, mask_key: const u8[4] = [0x11, 0x22, 0x33, 0x44])
```

### `permessage-deflate` compression (`realtime/ws_deflate.goose`)

RFC 7692 extension negotiation, shared reactor compressors, dedicated sliding
windows, compressed RSV1 frame encoding, and Safari 15.0-15.3 detection.

```goose
struct SharedWsCompressor { .. }
struct DedicatedWsCompressor { .. }
struct WsContextTakeoverOptions { server_no_context: bool = false, client_no_context: bool = false }
struct PerMessageDeflateConfig { .. }

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

### Pub/sub topic tree (`realtime/topic_tree.goose`)

Zero-allocation MQTT v5.0 topic wildcard matching, distinct subscriber lookup,
pre-encoded broadcast, batched drain queues, and retained messages.

```goose
enum PubSubError { None, InvalidTopic, MessageTooLarge, CapacityExceeded }
struct RetainedEntry { .. }
struct PreparedMessage { .. }
struct TopicTree { .. }

fn match_topic(pattern: const u8[:], topic: const u8[:]) -> bool
fn is_valid_topic_filter(pattern: const u8[:]) -> bool
fn is_valid_publish_topic(topic: const u8[:]) -> bool
fn subscribe(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool
fn subscribe_ex(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> i32, i32, bool
fn unsubscribe(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool
fn unsubscribe_all(tree: TopicTree&, sock_fd: i64) -> i32
fn is_subscribed(tree: const TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool
fn subscriber_count(tree: const TopicTree&, pattern: const u8[:]) -> i32
fn find_subscribers(tree: const TopicTree&, topic: const u8[:], out_fds: i64[..512]&) -> i64
fn find_subscribers_checked(tree: const TopicTree&, topic: const u8[:], out_fds: i64[..512]&) -> i64, bool
fn publish(tree: TopicTree&, topic: const u8[:], message: const u8[:], opcode: u8 = rfc::WS_OPCODE_TEXT) -> i64
fn publish_text(tree: TopicTree&, topic: const u8[:], text: const u8[:]) -> i64
fn publish_binary(tree: TopicTree&, topic: const u8[:], data: const u8[:]) -> i64
fn prepare_message(out_msg: PreparedMessage&, payload: const u8[:], opcode: u8 = rfc::WS_OPCODE_TEXT) -> bool
fn prepare_message_compressed(out_msg: PreparedMessage&, payload: const u8[:], shared_comp: SharedWsCompressor&, opcode: u8 = rfc::WS_OPCODE_TEXT) -> bool
fn publish_prepared(tree: TopicTree&, topic: const u8[:], msg: const PreparedMessage&) -> i64
fn publish_batch(tree: TopicTree&, topic: const u8[:], payload: const u8[:], opcode: u8 = rfc::WS_OPCODE_TEXT, sender_fd: i64 = -1) -> i64
fn drain(tree: TopicTree&) -> i64
fn publish_retained(tree: TopicTree&, topic: const u8[:], payload: const u8[:], is_binary: bool) -> u32, PubSubError
fn subscribe_with_retained(tree: TopicTree&, sub_id: u64, pattern: const u8[:]) -> PubSubError
```

### Server-Sent Events (`realtime/sse.goose`)

Streaming W3C EventSource parser, `Last-Event-ID` subscription state, and
server-side SSE response formatting.

```goose
struct SseEvent { .. }
struct SseParser { .. }
struct SseSubscription { .. }

fn sse_feed<E>(p: SseParser&, chunk: const u8[:], out_events: E&)
fn sse_flush(p: SseParser&)
fn sse_format_event<B>(out: B&, event_type: const u8[:], data: const u8[:], id: const u8[:] = "", retry_ms: u32 = 0)
fn new_sse_subscription(url: const u8[:] = "") -> SseSubscription
fn sse_build_request_headers<B>(sub: const SseSubscription&, host: const u8[:], path: const u8[:], out: B&)
fn consume<E>(sub: SseSubscription&, chunk: const u8[:], out_events: E&)
fn prepare_request(sub: const SseSubscription&, req: http::Request&)
fn init_response(res: http::Response&)
```

### WebTransport over HTTP/3 (`realtime/webtransport.goose`)

Extended CONNECT session setup, unidirectional and bidirectional stream framing,
datagrams, HTTP/3 error-code mapping, session capsules, and multi-session
demultiplexing.

```goose
enum WebTransportStreamKind { Bidirectional, Unidirectional, Unknown }
enum WebTransportSessionState { Closed, Connecting, Active, Draining }
struct WebTransportSession { .. }
struct WebTransportDatagram { .. }
struct WebTransportStreamPayload { .. }
struct WebTransportDemuxer { .. }

fn format_webtransport_connect_request(req: http::Request&, url_target: const u8[:])
fn is_webtransport_connect_request(req: const http::Request&) -> bool
fn format_webtransport_connect_response(res: http::Response&)
fn handle_webtransport_response(session: WebTransportSession&, res: const http::Response&) -> bool
fn encode_webtransport_uni_stream_header<B>(session_id: u64, out: B&)
fn decode_webtransport_uni_stream_header(wire: const u8[:]) -> WebTransportUniStreamHeader, bool
fn encode_webtransport_bidi_stream_header<B>(session_id: u64, out: B&)
fn decode_webtransport_bidi_stream_header(wire: const u8[:]) -> WebTransportBidiStreamHeader, bool
fn encode_webtransport_datagram<B>(session_id: u64, payload: const u8[:], out: B&)
fn decode_webtransport_datagram(wire: const u8[:], out: WebTransportDatagram&) -> bool
fn webtransport_code_to_http_code(app_err: u32) -> u64
fn http_code_to_webtransport_code(h3_err: u64) -> u32, bool
fn encode_webtransport_close_session<B>(error_code: u32, reason: const u8[:], out: B&)
fn decode_webtransport_close_session(payload: const u8[:], out: WebTransportCloseSession&) -> bool
fn encode_webtransport_drain_session<B>(out: B&)
fn encode_webtransport_reset_stream<B>(stream_id: u64, error_code: u32, out: B&)
fn encode_webtransport_stop_sending<B>(stream_id: u64, error_code: u32, out: B&)
fn close_webtransport_session(session: WebTransportSession&, code: u32, reason: const u8[:])
fn drain_webtransport_session(session: WebTransportSession&)
fn is_webtransport_session_open(session: const WebTransportSession&) -> bool
fn register_webtransport_session(demuxer: WebTransportDemuxer&, session_id: u64) -> bool
fn drain_webtransport_demuxer_session(demuxer: WebTransportDemuxer&, session_id: u64) -> bool
fn close_webtransport_demuxer_session(demuxer: WebTransportDemuxer&, session_id: u64, code: u32, reason: const u8[:]) -> bool
fn demux_webtransport_stream(demuxer: WebTransportDemuxer&, stream_id: u64, wire: const u8[:], fin: bool, out: WebTransportStreamPayload&) -> bool
```
