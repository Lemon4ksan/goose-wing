# `quic`

Zero-allocation QUIC transport protocol engine (RFC 9000), loss recovery and congestion control (RFC 9002), and connection migration manager.

## Public API

### Packet Encoding & Framing (`packet.goose`, RFC 9000 §17, RFC 9369)

- **`struct QuicHeader`**: Parsed Long or Short header packet representation (`header_type`, `version`, `dcid`, `scid`, `packet_number`, `header_len`, `payload_length`, `pn_length`).
- **`fn parse_quic_header(raw: const u8[:], dcid_len: u8 = 0) -> QuicHeader, bool`**: Zero-allocation parser validating packet type, connection IDs, and packet number bounds.
- **`fn encode_long_header<B>(out: B&, hdr: const QuicHeader&) -> bool`**: Serializes an RFC 9000 / RFC 9369 Long Header packet (Initial, 0-RTT, Handshake, Retry).
- **`fn encode_short_header<B>(out: B&, hdr: const QuicHeader&) -> bool`**: Serializes an RFC 9000 1-RTT Short Header packet.
- **Packet Type Constants**: `QUIC_PKT_INITIAL` (`0x00`), `QUIC_PKT_0RTT` (`0x01`), `QUIC_PKT_HANDSHAKE` (`0x02`), `QUIC_PKT_RETRY` (`0x03`).

### Frame Codecs (`frames.goose`, RFC 9000 §19)

- **`struct QuicFrame`**: Typed frame discriminator (`frame_type`, `stream_id`, `offset`, `length`, `max_data`, `error_code`, `final_size`, `fin`, `payload`).
- **`fn decode_quic_frame_cursor(src: const u8[:], idx: i64&) -> QuicFrame, bool`**: Streaming zero-allocation frame demuxer advancing cursor.
- **`fn encode_stream_frame<B>(out: B&, stream_id: u64, offset: u64, data: const u8[:], flags: QuicStreamFlags) -> bool`**: Encodes an RFC 9000 §19.8 `STREAM` frame.
- **`fn encode_crypto_frame<B>(out: B&, offset: u64, data: const u8[:]) -> bool`**: Encodes an RFC 9000 §19.6 `CRYPTO` frame.
- **`fn encode_connection_close_frame<B>(out: B&, error_code: u64, frame_type: u64, reason: const u8[:]) -> bool`**: Encodes an RFC 9000 §19.19 `CONNECTION_CLOSE` frame.

### ACK Framing & Loss Recovery (`AckFrame.goose`, RFC 9000 §19.3 & RFC 9002)

- **`struct AckFrame`**: Parsed ACK frame holding largest acknowledged, ACK delay, first ACK range, bounded gap ranges (`ranges: AckInterval[..64]`), and ECN counts.
- **`fn encode_ack_frame<B>(out: B&, ack: const AckFrame&) -> bool`**: Serializes an ACK frame with gap encoding and optional ECN counters.
- **`fn decode_ack_frame(src: const u8[:], offset: u64) -> AckFrame, u64, bool`**: Decodes wire ACK frames with optimistic ACK defense and ECN counts.
- **`struct PnSpaceState`**: Tracks per-space packet numbers, sent/received packets, and cryptographic key states (`hp_key`, `aead_key`, `aead_iv`, `keys_installed`).
- **`fn quic_install_pn_space_keys(space: PnSpaceState&, hp_key: const u8[:], aead_key: const u8[:], aead_iv: const u8[:], cipher_suite: u16) -> bool`**: Installs cryptographic keys for a packet number space.

### Flow Control & Stream State (`flow_control.goose`, `stream.goose`)

- **`struct QuicFlowControl`**: Connection-level credit tracker enforcing monotonic `MAX_DATA` and auto-tuning renewal thresholds.
- **`fn new_quic_flow_control(initial_max_data_remote: u64, local_window: u64) -> QuicFlowControl`**: Initializes a flow controller.
- **`fn quic_fc_update_remote_max_data(fc: QuicFlowControl&, new_limit: u64) -> bool`**: Applies peer credit window updates.
- **`fn quic_fc_check_conn_window_update(fc: QuicFlowControl&) -> bool, u64`**: Evaluates whether a connection-level `MAX_DATA` frame should be sent.
- **`struct QuicStream`**: RFC 9000 §3 stream state machine with out-of-order reassembly descriptors and flow control tracking.
- **`fn new_quic_stream(stream_id: u64, initial_window: u64) -> QuicStream`**: Initializes a stream descriptor.
- **`struct QuicStreamTable`**: Stream multiplexing table with terminal slot reuse and flow control tracking.

### Transport Coordination & Path Management (`connection.goose`, `migration.goose`, `dplpmtud.goose`, `bbr.goose`)

- **`struct QuicConnection`**: Master QUIC connection coordinator managing packet number spaces, encryption levels, anti-amplification limits, and stream multiplexing.
- **`fn new_quic_client_connection(server_dcid: const u8[:], client_scid: const u8[:]) -> QuicConnection`**: Initializes client QUIC session.
- **`fn new_quic_server_connection(scid: const u8[:]) -> QuicConnection`**: Initializes server QUIC session.
- **`fn quic_conn_process_datagram(conn: QuicConnection&, dgram: const u8[:], now_us: u64, out_ack: AckFrame&) -> bool, bool`**: Ingress datagram processor parsing coalesced packets, decrypting payloads, and dispatching frames.
- **`struct QuicPath`**: Network path representation tracking state, challenge token, bytes sent/received, and amplification ceiling.
- **`struct QuicMigrationManager`**: Connection migration state machine manager for path probing and validation (RFC 9000 §9).
- **`struct Dplpmtud`**: DPLPMTUD probe generator, PMTU search state machine, and raise timers (RFC 8899).
- **`struct BbrState`**: BBRv3 congestion controller with bandwidth estimation, pacing engine, and cycle state machine (RFC 9002).
