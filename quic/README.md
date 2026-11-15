# `quic`

Zero-allocation QUIC transport protocol engine (RFC 9000, RFC 9369), loss
recovery and congestion control (RFC 9002), DPLPMTUD (RFC 8899), and connection
migration manager.

## Public API

### Packet Encoding, Header Protection & Reassembly (`packet.goose`, RFC 9000 §17, RFC 9001 §5.4, RFC 9369)

```goose
enum QuicHeaderType {
    Initial, ZeroRtt, Handshake, Retry, VersionNegotiation, OneRtt,
}
struct QuicHeader
struct ReassemblyBuffer

fn quic_encode_varint<B>(out: B&, val: u64) -> bool
fn quic_decode_varint(src: const u8[:], offset: u64) -> u64, u64, bool
fn parse_quic_header(src: const u8[:], dcid_len_short: u8 = 0) -> QuicHeader, bool
fn encode_quic_long_header<B>(out: B&, hdr: const QuicHeader&, pn_len: u8, pn_bits: u8) -> bool
fn encode_quic_header<B>(out: B&, hdr: const QuicHeader&, pn_len: u8) -> bool
fn encode_stateless_reset_packet<B>(out: B&, rand_bytes: const u8[:], token: const u8[16]&) -> bool
fn apply_header_protection(pkt: u8[:], pn_offset: u32, pn_len: u8, hp_mask: const u8[5]&)
fn remove_header_protection(pkt: u8[:], pn_offset: u32, hp_mask: const u8[5]&) -> u8, u64
fn compute_quic_hp_masks_batch(cipher_suite: u16, hp_key: const u8[:], samples: const u8[16][:], out_masks: u8[5][:]) -> i64
fn decode_packet_number(largest_acked_pn: u64, truncated_pn: u64, pn_len: u8) -> u64
fn insert_fragment(buf: ReassemblyBuffer&, offset: u64, payload: const u8[:], is_fin: bool) -> bool
fn read_contiguous<B>(buf: ReassemblyBuffer&, out: B&, max_bytes: i64 = -1) -> u64
fn encode_quic_datagram_frame<B>(out: B&, payload: const u8[:], with_length: bool = true) -> bool
fn decode_quic_datagram_frame(src: const u8[:], offset: u64, packet_end: u64 = 0) -> const u8[:], u64, bool
```

`QuicHeader` holds parsed Long or Short header fields (`header_type`, `version`,
`dcid`, `scid`, `token`, `packet_number`, `header_len`, `payload_length`,
`pn_length`, `key_phase`). `quic_decode_varint` decodes an RFC 9000 §16
variable-length integer (1, 2, 4, or 8 bytes) starting at `offset` and returns
`(value, consumed_len, ok)`. `remove_header_protection` strips the 5-byte
`hp_mask` in-place (AES-128-ECB, AES-256-ECB, or ChaCha20 via
`compute_quic_hp_masks_batch`) and returns `(pn_len, truncated_pn)`, which
`decode_packet_number` expands to the full 62-bit packet number (RFC 9000
Appendix A.3). `ReassemblyBuffer` reassembles out-of-order `STREAM` and `CRYPTO`
fragments in a 16 KB `SegmentedArena` with up to 64 interval descriptors
(`intervals: Interval[..64]`).

```goose
var conn = quic_internal::new_quic_client_connection(server_dcid, client_scid);
let ok = quic_internal::quic_conn_install_initial_keys(conn, server_dcid);
```

### Frame Codecs & Transport Parameters (`frames.goose`, RFC 9000 §18–19)

```goose
enum QuicFrameType {
    Padding, Ping, Ack, ResetStream, StopSending, Crypto, NewToken, Stream,
    MaxData, MaxStreamData, MaxStreamsBidi, MaxStreamsUni, DataBlocked,
    StreamDataBlocked, StreamsBlockedBidi, StreamsBlockedUni,
    NewConnectionId, RetireConnectionId, PathChallenge, PathResponse,
    ConnectionCloseQuic, ConnectionCloseApp, HandshakeDone, Datagram,
    AckFrequency, ImmediateAck,
}
struct QuicFrame
struct QuicTransportParams
struct QuicAckFrequencyFrame

fn decode_quic_frame_cursor(src: const u8[:], idx: i64&) -> QuicFrame, bool
fn decode_quic_frame(src: const u8[:], offset: u64) -> QuicFrame, u64, bool
fn encode_stream_frame<B>(out: B&, stream_id: u64, offset: u64, data: const u8[:], flags: QuicStreamFlags = QuicStreamFlags { .. }) -> bool
fn encode_crypto_frame<B>(out: B&, offset: u64, data: const u8[:]) -> bool
fn encode_reset_stream_frame<B>(out: B&, stream_id: u64, error_code: u64, final_size: u64) -> bool
fn encode_stop_sending_frame<B>(out: B&, stream_id: u64, error_code: u64) -> bool
fn encode_max_data_frame<B>(out: B&, max_data: u64) -> bool
fn encode_max_stream_data_frame<B>(out: B&, stream_id: u64, max_stream_data: u64) -> bool
fn encode_max_streams_frame<B>(out: B&, max_streams: u64, is_bidi: bool) -> bool
fn encode_new_conn_id_frame<B>(out: B&, seq: u64, retire_prior_to: u64, conn_id: const u8[:], stateless_reset_token: const u8[16]&) -> bool
fn encode_retire_conn_id_frame<B>(out: B&, seq: u64) -> bool
fn encode_path_challenge_frame<B>(out: B&, data: const u8[8]&) -> bool
fn encode_path_response_frame<B>(out: B&, data: const u8[8]&) -> bool
fn encode_connection_close_frame<B>(out: B&, error_code: u64, frame_type: u64, reason: const u8[:], is_app: bool = false) -> bool
fn encode_quic_transport_params<B>(out: B&, tp: const QuicTransportParams&, is_server: bool) -> bool
fn decode_quic_transport_params(src: const u8[:], is_server: bool, out_tp: QuicTransportParams&) -> bool
```

`decode_quic_frame_cursor` demultiplexes a single `QuicFrame` (`QuicFrameType`
and associated stream, flow-control, connection ID, path challenge,
`QuicAckFrequencyFrame`, or close fields) and advances `idx` on success.
`decode_quic_frame` decodes at `offset` and returns `(frame, next_offset, ok)`.
`QuicTransportParams` models RFC 9000 §18 transport parameters including flow
limits, `max_idle_timeout`, `active_connection_id_limit`, `preferred_address`,
`version_information` (RFC 9368), `max_datagram_frame_size` (RFC 9221), and
`min_ack_delay`; `decode_quic_transport_params` rejects duplicate parameters and
role-forbidden fields.

### ACK Framing, Loss Recovery & PTO Timers (`AckFrame.goose`, RFC 9000 §19.3 & RFC 9002)

```goose
enum PnSpaceId { Initial, Handshake, ApplicationData }
struct AckFrame
struct PnSpaceState
struct RttState

fn encode_ack_frame<B>(out: B&, ack: const AckFrame&) -> bool
fn decode_ack_frame(src: const u8[:], offset: u64) -> AckFrame, u64, bool
fn build_ack_frame(ranges: const AckInterval[..64]&, ack_delay: u64, is_ecn: bool = false) -> AckFrame, bool
fn quic_install_pn_space_keys(space: PnSpaceState&, hp_key: const u8[:], aead_key: const u8[:], aead_iv: const u8[:], cipher_suite: u16 = 0x1301) -> bool
fn update_rtt(rtt: RttState&, latest_rtt: u64, ack_delay: u64, handshake_confirmed: bool, now_us: u64)
fn detect_lost_packets<B>(space: PnSpaceState&, rtt: const RttState&, now_us: u64, out_lost: B&) -> bool
fn evaluate_pto_timer(spaces: const PnSpaceState[3]&, rtt: const RttState&, pto_count: u32, now_us: u64, ctx: PtoContext) -> PtoTimerDecision
```

`AckFrame` stores largest acknowledged, ACK delay, first ACK range, up to 64 gap
ranges (`ranges: AckRange[..64]`), and ECN counters built from descending
`AckInterval[..64]` blocks. `PnSpaceState` tracks packet numbers, sent/received
packets, ECN state, and keys (`hp_key`, `aead_key`, `aead_iv`, `keys_installed`)
for each `PnSpaceId`. `RttState` maintains `smoothed_rtt`, `rttvar`, `min_rtt`,
and `max_ack_delay` (RFC 9002 §5). `detect_lost_packets` applies the RFC 9002
§6.1 packet threshold (`kPacketThreshold = 3`) and time threshold
($\frac{9}{8} \max(\text{smoothed\_rtt}, \text{latest\_rtt})$), while
`evaluate_pto_timer` computes Loss Time and Probe Timeout (PTO) deadlines across
all 3 packet number spaces (`PnSpaceState[3]`).

### Flow Control & Stream State (`flow_control.goose`, `stream.goose`)

```goose
struct QuicFlowControl
struct QuicStream
struct QuicStreamTable

fn new_quic_flow_control(initial_max_data_remote: u64, local_window: u64) -> QuicFlowControl
fn quic_fc_can_send(fc: const QuicFlowControl&, s: const QuicStream&, offset: u64, len: u64) -> bool, bool, bool
fn quic_fc_record_recv_stream(fc: QuicFlowControl&, s: QuicStream&, offset: u64, len: u64) -> bool, u64
fn quic_fc_update_remote_max_data(fc: QuicFlowControl&, new_limit: u64) -> bool
fn quic_fc_check_conn_window_update(fc: QuicFlowControl&) -> bool, u64
fn new_quic_stream(stream_id: u64, max_recv_flow: u64 = 65536) -> QuicStream
fn quic_table_get_or_open_stream(tbl: QuicStreamTable&, stream_id: u64, default_recv_flow: u64 = 65536) -> i32, bool
fn quic_table_open_local_stream(tbl: QuicStreamTable&, is_bidi: bool, default_recv_flow: u64 = 65536) -> u64, i32, bool
```

`QuicFlowControl` tracks connection-level send/receive credit, enforces
monotonic `MAX_DATA` updates, and triggers auto-tuning window renewals via
`quic_fc_check_conn_window_update`. `QuicStream` implements the RFC 9000 §3
stream state machine (`QuicSendState`, `QuicRecvState`), and `QuicStreamTable`
multiplexes active streams with terminal slot reuse, concurrency bounds, and
evicted closed-stream tracking.

### Transport Coordination, Migration, DPLPMTUD & Congestion Control (`connection.goose`, `migration.goose`, `dplpmtud.goose`, `bbr.goose`)

```goose
// quic/connection.goose
struct QuicConnection
fn new_quic_client_connection(server_dcid: const u8[:], client_scid: const u8[:]) -> QuicConnection
fn new_quic_server_connection(scid: const u8[:]) -> QuicConnection
fn quic_conn_install_initial_keys(conn: QuicConnection&, dcid: const u8[:], version: u32 = rfc::QUIC_VERSION_1) -> bool
fn quic_seal_packet<B>(space: const PnSpaceState&, hdr: const QuicHeader&, pn_len: u8, plaintext: const u8[:], out_pkt: B&) -> bool
fn quic_conn_process_datagram(conn: QuicConnection&, dgram: const u8[:], now_us: u64, out_ack: AckFrame&) -> bool, bool

// quic/migration.goose (RFC 9000 §9)
struct QuicEndpointAddr
struct QuicPreferredAddress
struct QuicMigrationManager

// quic/dplpmtud.goose (RFC 8899)
struct Dplpmtud
fn generate_ping_probe<B>(out: B&, target_size: u32) -> bool
fn generate_path_challenge_probe<B>(out: B&, data: const u8[8]&, target_size: u32) -> bool
fn dplpmtud_on_probe_acked(d: Dplpmtud&, acked_size: u32) -> bool
fn dplpmtud_on_probe_lost(d: Dplpmtud&, lost_size: u32) -> bool

// quic/bbr.goose
struct Pacer
struct BbrState
struct CubicState
fn bbr_bdp(bw_bps: u64, min_rtt_us: u64) -> u64
fn bbr_update_pacing_and_cwnd(bbr: BbrState&)
fn bbr_on_congestion_signal(bbr: BbrState&, bytes_in_flight: u64, loss_bytes: u64, total_acked_bytes: u64, ecn_ce_count: u64, new_acked_packets: u64)
fn bbr_advance_cycle(bbr: BbrState&, round_done: bool)
fn cubic_on_ack(cubic: CubicState&, now_us: u64, rtt_us: u64, bytes_in_flight: u64, mss_bytes: u64 = 1200) -> u64
fn cubic_on_loss(cubic: CubicState&, now_us: u64)
```

`QuicConnection` coordinates packet number spaces, encryption levels,
anti-amplification limits, stream multiplexing, and ingress datagram demuxing
(`quic_conn_process_datagram`). `QuicMigrationManager` handles RFC 9000 §9 path
probing (`PATH_CHALLENGE` / `PATH_RESPONSE`), `QuicEndpointAddr` validation, and
`QuicPreferredAddress` migration. `Dplpmtud` implements RFC 8899 Datagram
Packetization Layer PMTUD probe generation, step search, and blackhole recovery.
`bbr.goose` provides a leaky-bucket `Pacer`, a BBRv3 controller (`BbrState`)
with bandwidth-delay product estimation and ECN/loss response, and an RFC 9438
`CubicState` controller with application-limited epoch freezing.
