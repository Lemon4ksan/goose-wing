# `quic`

Zero-allocation QUIC transport protocol engine (RFC 9000), loss recovery and congestion control (RFC 9002), and connection migration manager.

## Public API

### Packet Encoding & Framing (`packet.goose`, RFC 9000 §17)

- **`struct QuicPacket`**: Parsed Long or Short header packet representation (`packet_type`, `version`, `dcid`, `scid`, `packet_number`, `payload`).
- **`fn parse_quic_packet_header(raw: const u8[:]) -> QuicPacket, u64, bool`**: Zero-allocation parser validating packet type, connection IDs, and packet number bounds.
- **`fn encode_long_header_packet<B>(out: B&, pkt_type: u8, version: u32, dcid: const u8[:], scid: const u8[:], token: const u8[:], pn: u64, payload: const u8[:]) -> bool`**: Serializes an RFC 9000 Long Header packet (Initial, 0-RTT, Handshake, Retry).
- **`fn encode_short_header_packet<B>(out: B&, dcid: const u8[:], pn: u64, key_phase: bool, payload: const u8[:]) -> bool`**: Serializes an RFC 9000 1-RTT Short Header packet.
- **Packet Type Constants**: `QUIC_PKT_INITIAL` (`0x00`), `QUIC_PKT_0RTT` (`0x01`), `QUIC_PKT_HANDSHAKE` (`0x02`), `QUIC_PKT_RETRY` (`0x03`).

### Frame Codecs (`frames.goose`, RFC 9000 §19)

- **`struct QuicFrame`**: Typed frame discriminator (`frame_type`, `stream_frame`, `ack_frame`, `reset_stream_frame`, `stop_sending_frame`, `crypto_frame`, `connection_close_frame`).
- **`fn parse_quic_frame(raw: const u8[:], offset: u64&) -> QuicFrame, bool`**: Streaming zero-allocation frame demuxer.
- **`fn encode_stream_frame<B>(out: B&, stream_id: u64, offset: u64, data: const u8[:], fin: bool) -> bool`**: Encodes an RFC 9000 §19.8 `STREAM` frame.
- **`fn encode_crypto_frame<B>(out: B&, offset: u64, data: const u8[:]) -> bool`**: Encodes an RFC 9000 §19.6 `CRYPTO` frame.
- **`fn encode_connection_close_frame<B>(out: B&, error_code: u64, frame_type: u64, reason: const u8[:]) -> bool`**: Encodes an RFC 9000 §19.19 `CONNECTION_CLOSE` frame.

### ACK Framing & Loss Recovery (`AckFrame.goose`, RFC 9000 §19.3 & RFC 9002)

- **`struct QuicAckFrame`**: Parsed ACK frame holding largest acknowledged, ACK delay, first ACK range, and bounded gap ranges (`ack_ranges: QuicAckRange[..16]`).
- **`fn encode_quic_ack_frame<B>(out: B&, frame: const QuicAckFrame&) -> bool`**: Serializes an ACK frame with gap encoding.
- **`fn parse_quic_ack_frame(raw: const u8[:], offset: u64&) -> QuicAckFrame, bool`**: Decodes wire ACK frames with optimistic ACK defense.

### Flow Control & Stream State (`flow_control.goose`, `stream.goose`)

- **`struct FlowController`**: Connection-level and stream-level credit tracker enforcing monotonic `MAX_DATA` and `MAX_STREAM_DATA` invariants.
- **`fn init_flow_controller(initial_max: u64, window: u64) -> FlowController`**: Initializes a flow controller.
- **`fn update_max_data(fc: FlowController&, new_max: u64) -> bool`**: Applies peer credit window updates.
- **`fn consume_flow_credit(fc: FlowController&, bytes_consumed: u64) -> bool`**: Checks and deducts available transmit credit.
- **`struct QuicStream`**: RFC 9000 §3 stream state machine with receive and send ring buffers.
- **`fn init_quic_stream(stream_id: u64, initial_window: u64) -> QuicStream`**: Initializes a stream descriptor.

### Transport Coordination & Path Management (`connection.goose`, `migration.goose`, `dplpmtud.goose`)

- **`struct QuicConnection`**: Master QUIC connection coordinator managing packet number spaces, encryption levels, anti-amplification limits, and stream multiplexing.
- **`fn new_quic_client_connection(dcid: const u8[:], scid: const u8[:]) -> QuicConnection`**: Initializes client QUIC session.
- **`fn new_quic_server_connection(dcid: const u8[:], scid: const u8[:]) -> QuicConnection`**: Initializes server QUIC session.
- **`fn quic_conn_process_packet(conn: QuicConnection&, raw: const u8[:], now_us: u64) -> bool`**: Ingress packet processor validating headers, decrypting payload, and dispatching frames.
- **`struct QuicPath`**: Path validation, anti-amplification 3x ceiling, and migration FSM.
- **`struct QuicPmtuDiscovery`**: DPLPMTUD probe generator and state machine (RFC 8899).
- **`struct QuicCongestionController`**: BBR and CUBIC congestion controller with pacing engine (RFC 9002, RFC 9438).
