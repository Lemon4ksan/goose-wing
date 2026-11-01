# `realtime`

Real-time streaming and bidirectional communications subsystem supporting WebSockets (RFC 6455, RFC 7692, RFC 8441), Server-Sent Events (W3C EventSource), WebTransport over HTTP/3 (RFC 9297), and MQTT-compatible high-performance Pub/Sub topic routing.

## Public API

### WebSocket Protocol Engine (`websocket.goose`, RFC 6455, RFC 7692, RFC 8441)

- **`struct WsFrameHeader`**: Decoded wire frame header (`fin`, `rsv1`, `rsv2`, `rsv3`, `opcode`, `masked`, `mask_key: u8[4]`, `payload_len`, `header_len`).
- **`struct WebSocketSession`**: State machine managing connection lifecycle, compression state, heartbeat timers, and backpressure.
- **`struct WsMessage`**: Materialized complete WebSocket message (`opcode: u8`, `payload: u8[>..]`).
- **`struct WsMessageView`**: Zero-copy payload slice view over socket receive buffers (`opcode: u8`, `payload: const u8[:]`).
- **`struct WsBehavior`**: Declarative event hooks for open, message, drain, ping, pong, and close events.
- **`struct WsPendingUpgrade`**: Asynchronous handshake transaction with user-data attachment and abort safety.
- **`enum WsRole`**: Connection role polarity (`Client`, `Server`).
- **`enum WsSendStatus`**: Backpressure send result (`Success`, `Dropped`, `BackpressureLimitReached`).
- **`enum WsHeartbeatAction`**: Scheduled heartbeat sweeper action (`None`, `SendPing`, `CloseTimeout`).
- **`fn new_websocket_session(is_client: bool = true) -> WebSocketSession`**: Initializes a WebSocket session state.
- **`fn parse_ws_frame_header(src: const u8[:]) -> WsFrameHeader, bool`**: Zero-allocation frame header decoder validating lengths and reserved bits.
- **`fn encode_ws_frame<B>(out: B&, opcode: u8, fin: bool, masked: bool, mask_key: const u8[4]&, payload: const u8[:])`**: Encodes an RFC 6455 binary frame.
- **`fn encode_ws_frame_compressed<B>(out: B&, opcode: u8, fin: bool, masked: bool, mask_key: const u8[4]&, payload: const u8[:], compressor: SharedWsCompressor&)`**: Encodes an RFC 7692 compressed frame setting RSV1.
- **`fn apply_mask_in_place(data: u8[:], mask_key: const u8[4]&)`**: Pure Goose 64-bit/32-bit SWAR in-place XOR unmasking.
- **`fn unmask_websocket_shifted(frame: u8[:], header_len: i64, payload_len: i64, mask_key: const u8[4]&) -> u8[:]`**: Zero-copy unmasking that shifts unmasked payload over the frame header in the receive buffer.
- **`fn receive_view<B>(ws: WebSocketSession&, wire: u8[:], out_view: WsMessageView&, out_reply: B&) -> bool`**: Processes ingress wire bytes, returning a zero-copy unmasked view for completed messages.
- **`fn consume_frame_view<B>(ws: WebSocketSession&, wire: u8[:], out_view: WsMessageView&, out_reply: B&) -> i64, bool`**: Incremental frame demuxer returning bytes consumed and valid message views.
- **`fn send_text<B>(ws: WebSocketSession&, text: const u8[:], out: B&)`**: Serializes a UTF-8 text message.
- **`fn send_binary<B>(ws: WebSocketSession&, data: const u8[:], out: B&)`**: Serializes a binary message.
- **`fn send_ping<B>(ws: WebSocketSession&, ping_payload: const u8[:], out: B&)`**: Serializes an unsolicited or keepalive ping frame.
- **`fn send_pong<B>(ws: WebSocketSession&, pong_payload: const u8[:], out: B&)`**: Serializes a pong response frame.
- **`fn close<B>(ws: WebSocketSession&, status_code: u16, reason: const u8[:], out: B&)`**: Sends an RFC 6455 close frame and transitions session state.
- **`fn ws_upgrade_request(req: const Request&, res: Response&, subprotocols: const u8[:][..4] = []) -> bool`**: Validates HTTP/1.1 upgrade headers and synthesizes a 101 Switching Protocols response.
- **`fn is_websocket_upgrade_request(req: const Request&) -> bool`**: Returns `true` if request contains valid `Upgrade: websocket` headers.
- **`fn ws_h2_upgrade_request(req: const Request&, res: Response&, subprotocol: const u8[:] = "") -> bool`**: Handles RFC 8441 Extended CONNECT upgrades over HTTP/2.
- **`fn ws_h3_upgrade_request(req: const Request&, res: Response&, subprotocol: const u8[:] = "") -> bool`**: Handles Extended CONNECT upgrades over HTTP/3.
- **`fn arm_heartbeat(ws: WebSocketSession&, wheel: const TickTimerWheel&)`**: Arms session keepalive timer in tick timer wheel.
- **`fn tick_heartbeat<B>(ws: WebSocketSession&, wheel: const TickTimerWheel&, out_wire: B&) -> WsHeartbeatAction`**: Sweeps session idle timeout and synthesizes ping frames.
- **`fn set_max_backpressure(ws: WebSocketSession&, max_bytes: u64, close_on_limit: bool = false)`**: Configures egress backpressure threshold.

### Pub/Sub Topic Tree (`topic_tree.goose`, OASIS MQTT v5.0 §4.7)

- **`struct TopicTree`**: Zero-heap subscription routing engine managing 256 topic buckets, 4096 subscriptions, and message palettes.
- **`struct PreparedMessage`**: Pre-formatted RFC 6455 frame buffer pre-encoding raw and compressed frames for single-pass multi-subscriber broadcasts.
- **`struct TopicSubscriptionEvent`**: Lifecycle descriptor emitted on join and leave events.
- **`fn match_topic(pattern: const u8[:], topic: const u8[:]) -> bool`**: Evaluates MQTT topic filters with `+` (single-level) and `#` (multi-level) wildcards.
- **`fn is_valid_topic_filter(pattern: const u8[:]) -> bool`**: Validates MQTT filter syntax invariants (wildcard placements and delimiters).
- **`fn is_valid_publish_topic(topic: const u8[:]) -> bool`**: Validates concrete publish topic names (disallows wildcards).
- **`fn subscribe(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool`**: Subscribes a socket descriptor to a topic pattern.
- **`fn subscribe_with_hook<HookFn>(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool`**: Subscribes with a join notification callback.
- **`fn unsubscribe(tree: TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool`**: Removes a specific topic subscription.
- **`fn unsubscribe_all(tree: TopicTree&, sock_fd: i64) -> i32`**: Purges all topic subscriptions for a disconnecting socket.
- **`fn is_subscribed(tree: const TopicTree&, sock_fd: i64, pattern: const u8[:]) -> bool`**: Returns subscription membership status.
- **`fn subscriber_count(tree: const TopicTree&, pattern: const u8[:]) -> i32`**: Returns total active subscribers matching a topic bucket.
- **`fn socket_subscription_count(tree: const TopicTree&, sock_fd: i64) -> i32`**: Returns total active subscriptions for a single socket.
- **`fn publish_text(tree: TopicTree&, topic: const u8[:], text: const u8[:]) -> i64`**: Broadcasts a UTF-8 text message to all matching subscribers.
- **`fn publish_binary(tree: TopicTree&, topic: const u8[:], data: const u8[:]) -> i64`**: Broadcasts a binary message to all matching subscribers.
- **`fn prepare_message(msg: PreparedMessage&, payload: const u8[:], opcode: u8 = WS_OPCODE_TEXT)`**: Pre-encodes a broadcast message once.
- **`fn prepare_message_compressed(msg: PreparedMessage&, payload: const u8[:], opcode: u8 = WS_OPCODE_TEXT)`**: Pre-encodes both raw and deflated frames.
- **`fn publish_prepared(tree: TopicTree&, topic: const u8[:], msg: const PreparedMessage&)`**: Zero-copy broadcast of pre-formatted message.
- **`fn drain(tree: TopicTree&) -> i64`**: Flushes queued batch messages to blocked subscribers.

### Server-Sent Events (`sse.goose`, W3C EventSource)

- **`struct SseEvent`**: Decoded event representation (`event: u8[..64]`, `data: u8[..4096]`, `id: u8[..128]`, `retry_ms: u32`, `is_valid: bool`).
- **`struct SseParser`**: Zero-heap streaming parser handling CR, LF, and CRLF line endings, UTF-8 BOM stripping, and comment filtering.
- **`struct SseSubscription`**: Client-side SSE stream receiver managing reconnection IDs and event dispatch.
- **`fn new_sse_subscription(url: const u8[:] = "") -> SseSubscription`**: Initializes an SSE client subscription.
- **`fn sse_feed<E>(p: SseParser&, chunk: const u8[:], out_events: E&)`**: Feeds a stream chunk into parser, extracting all completed `SseEvent` items.
- **`fn sse_flush<E>(p: SseParser&, out_events: E&)`**: Dispatches any trailing pending event at stream termination.
- **`fn sse_format_event<B>(out: B&, event_type: const u8[:], data: const u8[:], id: const u8[:] = "", retry_ms: u32 = 0)`**: Formats an SSE event into standard wire format with multi-line `data:` support.
- **`fn prepare_request(sub: const SseSubscription&, req: Request&)`**: Sets W3C EventSource headers (`Accept: text/event-stream`, `Last-Event-ID`).
- **`fn init_response(res: Response&)`**: Initializes server response headers for SSE streaming with disabled buffering.

### WebTransport over HTTP/3 (`webtransport.goose`, RFC 9297)

- **`struct WebTransportSession`**: Session state tracking session ID, stream routes, and lifecycle state.
- **`struct WebTransportDatagram`**: Out-of-order unreliable datagram packet representation.
- **`struct WebTransportDemuxer`**: Multi-session demuxer routing HTTP/3 stream IDs and datagrams to registered sessions.
- **`enum WebTransportStreamKind`**: Stream archetype (`Unidirectional`, `Bidirectional`).
- **`enum WebTransportSessionState`**: Session state (`Open`, `Draining`, `Closed`).
- **`fn format_webtransport_connect_request(req: Request&, path: const u8[:], authority: const u8[:])`**: Formats an HTTP/3 Extended CONNECT request.
- **`fn is_webtransport_connect_request(req: const Request&) -> bool`**: Validates WebTransport `:protocol: webtransport` pseudo-headers.
- **`fn format_webtransport_connect_response(res: Response&)`**: Generates 200 OK CONNECT response.
- **`fn encode_webtransport_uni_stream_header<B>(session_id: u64, out: B&)`**: Encodes unidirectional stream type prefix (`0x54`).
- **`fn decode_webtransport_uni_stream_header(wire: const u8[:], idx: i64&) -> u64, bool`**: Decodes unidirectional stream header.
- **`fn encode_webtransport_bidi_stream_header<B>(session_id: u64, out: B&)`**: Encodes bidirectional stream type prefix (`0x41`).
- **`fn decode_webtransport_bidi_stream_header(wire: const u8[:], idx: i64&) -> u64, bool`**: Decodes bidirectional stream header.
- **`fn encode_webtransport_datagram<B>(session_id: u64, payload: const u8[:], out: B&)`**: Encodes a WebTransport datagram with quarter-stream ID varint.
- **`fn decode_webtransport_datagram(wire: const u8[:], idx: i64&) -> u64, const u8[:], bool`**: Decodes a WebTransport datagram.
- **`fn close_webtransport_session(session: WebTransportSession&, code: u32, reason: const u8[:])`**: Initiates orderly session closure.
- **`fn drain_webtransport_session(session: WebTransportSession&)`**: Sends a session draining signal to peer.
