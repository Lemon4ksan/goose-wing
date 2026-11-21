# `quic`

Zero-allocation QUIC transport protocol engine (RFC 9000, RFC 9369), loss
recovery and congestion control (RFC 9002), DPLPMTUD (RFC 8899), and connection
migration manager.

All public transport types, packet/frame codecs, state machines, and controllers
live in `namespace quic;`. Internal demuxers, sub-decoders, and arena mechanics
are isolated in `namespace quic_internal;`.

## Public API

### Packet Encoding, Header Protection & Reassembly (`packet.goose`, RFC 9000 §17, RFC 9001 §5.4, RFC 9369)

```goose
enum QuicHeaderType {
    Initial, ZeroRtt, Handshake, Retry, OneRtt, VersionNegotiation,
}
struct QuicHeader
struct PathState
struct Interval
struct SegmentedArena
struct ReassemblyBuffer

fn encode_varint<B>(val: u64, out: B&) -> bool
fn decode_varint_cursor(src: const u8[:], idx: i64&) -> u64, bool
fn decode_varint(src: const u8[:], offset: u64) -> u64, u64, bool
fn is_client_stream(id: u64) -> bool
fn is_server_stream(id: u64) -> bool
fn is_bidi_stream(id: u64) -> bool
fn is_uni_stream(id: u64) -> bool
fn parse_header(src: const u8[:], dcid_len_short: u8 = 0) -> QuicHeader, bool
fn encode_header<B>(hdr: const QuicHeader&, pn_len: u8, out: B&) -> bool
fn encode_stateless_reset_packet<B>(rand_bytes: const u8[:], token: const u8[16]&, out: B&) -> bool
fn compute_hp_masks_batch(cipher_suite: u16, hp_key: const u8[:], samples: const u8[16][:], masks: u8[5][:]) -> i64
fn apply_header_protection(pkt: u8[:], pn_offset: u32, pn_len: u8, hp_mask: const u8[5]&)
fn remove_header_protection(pkt: u8[:], pn_offset: u32, hp_mask: const u8[5]&) -> u8, u64
fn decode_packet_number_checked(largest_acked_pn: u64, truncated_pn: u64, pn_len: u8) -> u64, bool
fn decode_packet_number(largest_acked_pn: u64, truncated_pn: u64, pn_len: u8) -> u64
fn new_path_state(ip: const u8[16]&, port: u16, validated: bool = false) -> PathState
fn can_send(path: const PathState&, packet_bytes: u64) -> bool
fn on_bytes_received(path: PathState&, bytes: u64)
fn on_bytes_sent(path: PathState&, bytes: u64)
fn validate(path: PathState&)
fn new_reassembly_buffer(max_flow_limit: u64 = 1048576) -> ReassemblyBuffer
fn insert_fragment(buf: ReassemblyBuffer&, offset: u64, payload: const u8[:], is_fin: bool) -> bool
fn read_contiguous<B>(buf: ReassemblyBuffer&, out: B&, max_bytes: i64 = -1) -> u64
```

`QuicHeader` holds parsed Long or Short header fields (`header_type`, `version`,
`dcid`, `scid`, `token`, `packet_number`, `header_len`, `payload_length`,
`pn_length`, `key_phase`). `decode_varint` decodes an RFC 9000 §16
variable-length integer (1, 2, 4, or 8 bytes) starting at `offset` and returns
`(value, next_offset, ok)`. `remove_header_protection` strips the 5-byte
`hp_mask` in-place (AES-128-ECB, AES-256-ECB, or ChaCha20 via
`compute_hp_masks_batch`) and returns `(pn_len, truncated_pn)`, which
`decode_packet_number` expands to the full 62-bit packet number (RFC 9000
Appendix A.3). `ReassemblyBuffer` reassembles out-of-order `STREAM` and `CRYPTO`
fragments in a 16 KB `SegmentedArena` with up to 64 interval descriptors
(`intervals: Interval[..64]`).

```goose
var conn = quic::new_client_connection(server_dcid, client_scid);
let ok = conn.install_initial_keys(server_dcid);
```

### Frame Codecs & Transport Parameters (`frames.goose`, RFC 9000 §18-19)

```goose
enum QuicFrameType {
    Padding, Ping, Ack, AckEcn, ResetStream, StopSending, Crypto, NewToken, Stream,
    MaxData, MaxStreamData, MaxStreamsBidi, MaxStreamsUni, DataBlocked,
    StreamDataBlocked, StreamsBlockedBidi, StreamsBlockedUni,
    NewConnectionId, RetireConnectionId, PathChallenge, PathResponse,
    HandshakeDone, ImmediateAck, ConnectionClose, ConnectionCloseApp,
    Datagram, AckFrequency, Unknown,
}
struct QuicFrame
struct QuicTransportParams
struct QuicAckFrequencyFrame
struct QuicStreamFlags

fn decode_frame_cursor(src: const u8[:], idx: i64&) -> QuicFrame, bool
fn decode_frame(src: const u8[:], offset: u64) -> QuicFrame, u64, bool
fn encode_padding_frame<B>(out: B&, count: u64 = 1) -> bool
fn encode_ping_frame<B>(out: B&) -> bool
fn encode_stream_frame<B>(stream_id: u64, offset: u64, data: const u8[:], out: B&, flags: QuicStreamFlags = QuicStreamFlags { .. }) -> bool
fn encode_crypto_frame<B>(offset: u64, data: const u8[:], out: B&) -> bool
fn encode_reset_stream_frame<B>(stream_id: u64, error_code: u64, final_size: u64, out: B&) -> bool
fn encode_stop_sending_frame<B>(stream_id: u64, error_code: u64, out: B&) -> bool
fn encode_max_data_frame<B>(max_data: u64, out: B&) -> bool
fn encode_max_stream_data_frame<B>(stream_id: u64, max_stream_data: u64, out: B&) -> bool
fn encode_max_streams_frame<B>(max_streams: u64, is_bidi: bool, out: B&) -> bool
fn encode_new_conn_id_frame<B>(seq: u64, retire_prior_to: u64, conn_id: const u8[:], stateless_reset_token: const u8[16]&, out: B&) -> bool
fn encode_retire_conn_id_frame<B>(seq: u64, out: B&) -> bool
fn encode_path_challenge_frame<B>(data: const u8[8]&, out: B&) -> bool
fn encode_path_response_frame<B>(data: const u8[8]&, out: B&) -> bool
fn encode_handshake_done_frame<B>(out: B&) -> bool
fn encode_ack_frequency_frame<B>(f: const QuicAckFrequencyFrame&, out: B&) -> bool
fn decode_ack_frequency_frame(c: core::ByteCursor&) -> QuicAckFrequencyFrame, bool
fn encode_connection_close_frame<B>(error_code: u64, frame_type: u64, reason: const u8[:], out: B&, is_app: bool = false) -> bool
fn encode_datagram_frame<B>(payload: const u8[:], out: B&, with_length: bool = true) -> bool
fn decode_datagram_frame(src: const u8[:], offset: u64, packet_end: u64 = 0) -> const u8[:], u64, bool
fn encode_transport_params<B>(tp: const QuicTransportParams&, is_server: bool, out: B&) -> bool
fn decode_transport_params(src: const u8[:], is_server: bool) -> QuicTransportParams, bool
```

`decode_frame_cursor` demultiplexes a single `QuicFrame` (`QuicFrameType` and
associated stream, flow-control, connection ID, path challenge,
`QuicAckFrequencyFrame`, or close fields) and advances `idx` on success.
`decode_frame` decodes at `offset` and returns `(frame, next_offset, ok)`.
`QuicTransportParams` models RFC 9000 §18 transport parameters including flow
limits, `max_idle_timeout`, `active_connection_id_limit`, `preferred_address`,
`version_information` (RFC 9368), `max_datagram_frame_size` (RFC 9221), and
`min_ack_delay`; `decode_transport_params` rejects duplicate parameters and
role-forbidden fields, returning `(QuicTransportParams, bool)`.

### ACK Framing, Loss Recovery & PTO Timers (`AckFrame.goose`, RFC 9000 §19.3 & RFC 9002)

```goose
enum PnSpaceId { Initial, Handshake, ApplicationData }
enum QuicEcnState { Testing, Unknown, Capable, Failed }
enum PtoTimerMode { None, LossTime, AntiAmplification, AntiDeadlock, StandardPto }
struct AckFrame
struct PnSpaceState
struct RttState
struct PtoTimerDecision
struct PtoContext

fn install_keys(space: PnSpaceState&, hp_key: const u8[:], aead_key: const u8[:], aead_iv: const u8[:], cipher_suite: u16 = 0x1301) -> bool
fn encode_ack_frame<B>(ack: const AckFrame&, out: B&) -> bool
fn decode_ack_frame(src: const u8[:], offset: u64) -> AckFrame, u64, bool
fn build_ack_frame(ranges: const AckInterval[..64]&, ack_delay: u64, is_ecn: bool = false) -> AckFrame, bool
fn parse_and_validate_ack<B>(space: const PnSpaceState&, ack: const AckFrame&, out: B&) -> bool
fn record_received_pn(ranges: AckInterval[..64]&, pn: u64) -> bool
fn update_rtt(rtt: RttState&, latest_rtt: u64, ack_delay: u64, handshake_confirmed: bool, now_us: u64)
fn validate_ecn(space: PnSpaceState&, ack: const AckFrame&, ecn_acked_pkts: u64) -> u64, bool
fn detect_lost_packets<B>(space: PnSpaceState&, rtt: const RttState&, now_us: u64, out: B&) -> bool
fn compute_pto_duration(rtt: const RttState&, pto_count: u32, is_app_data: bool) -> u64
fn evaluate_pto_timer(spaces: const PnSpaceState[3]&, rtt: const RttState&, pto_count: u32, now_us: u64, ctx: PtoContext) -> PtoTimerDecision
```

`AckFrame` stores largest acknowledged, ACK delay, first ACK range, up to 64 gap
ranges (`ranges: AckRange[..64]`), and ECN counters built from descending
`AckInterval[..64]` blocks. `PnSpaceState` tracks packet numbers, sent/received
packets, ECN state, and keys (`hp_key`, `aead_key`, `aead_iv`, `keys_installed`)
for each `PnSpaceId`. `RttState` maintains `smoothed_rtt_us`, `rttvar_us`,
`min_rtt_us`, and `max_ack_delay_us` (RFC 9002 §5). `space.detect_lost_packets`
applies the RFC 9002 §6.1 packet threshold (`kPacketThreshold = 3`) and time
threshold ($\frac{9}{8} \max(\text{smoothed\_rtt}, \text{latest\_rtt})$), while
`evaluate_pto_timer` computes Loss Time and Probe Timeout (PTO) deadlines across
all 3 packet number spaces (`PnSpaceState[3]`).

### Flow Control & Stream State (`flow_control.goose`, `stream.goose`)

```goose
enum QuicRole { Client, Server }
enum QuicSendState { Ready, Send, DataSent, DataRecvd, ResetSent, ResetRecvd }
enum QuicRecvState { Receive, SizeKnown, DataRecvd, DataRead, ResetRecvd, ResetRead }
struct FlowSendCheck
struct QuicFlowControl
struct QuicStream
struct QuicStreamTable

fn new_flow_control(initial_max_data_remote: u64, local_window: u64) -> QuicFlowControl
fn remaining_conn_credit(fc: const QuicFlowControl&) -> u64
fn remaining_stream_credit(s: const QuicStream&) -> u64
fn can_send(fc: const QuicFlowControl&, s: const QuicStream&, offset: u64, len: u64) -> FlowSendCheck
fn record_send(fc: QuicFlowControl&, s: QuicStream&, offset: u64, len: u64) -> bool
fn record_recv_stream(fc: QuicFlowControl&, s: QuicStream&, offset: u64, len: u64) -> u64, bool
fn record_recv_reset(fc: QuicFlowControl&, s: QuicStream&, final_size: u64) -> u64, bool
fn on_app_read(fc: QuicFlowControl&, s: QuicStream&, bytes_read: u64)
fn update_remote_max_data(fc: QuicFlowControl&, new_limit: u64) -> bool
fn update_send_max_data(s: QuicStream&, new_limit: u64) -> bool
fn check_conn_window_update(fc: QuicFlowControl&) -> u64, bool
fn check_stream_window_update(s: QuicStream&, stream_window_size: u64) -> u64, bool

fn new_stream(stream_id: u64, max_recv_flow: u64 = 65536) -> QuicStream
fn on_send_data(s: QuicStream&, offset: u64, len: u64, fin: bool) -> u64, bool
fn on_send_reset(s: QuicStream&, error_code: u64, final_size: u64) -> u64, bool
fn on_send_ack(s: QuicStream&, all_data_acked: bool) -> bool
fn on_recv_stream_frame(s: QuicStream&, offset: u64, len: u64, fin: bool) -> u64, bool
fn on_recv_reset(s: QuicStream&, error_code: u64, final_size: u64) -> u64, bool
fn on_recv_stop_sending(s: QuicStream&, error_code: u64, role: QuicRole) -> u64, bool
fn on_app_read(s: QuicStream&, bytes: u64) -> bool
fn on_app_read_reset(s: QuicStream&) -> bool
fn is_send_closed(s: const QuicStream&) -> bool
fn is_recv_closed(s: const QuicStream&) -> bool
fn is_terminal(s: const QuicStream&, role: QuicRole) -> bool
fn new_stream_table(role: QuicRole) -> QuicStreamTable
fn find_stream(tbl: const QuicStreamTable&, stream_id: u64) -> i32, bool
fn is_evicted_closed_stream(tbl: const QuicStreamTable&, stream_id: u64) -> bool
fn get_or_open_stream(tbl: QuicStreamTable&, stream_id: u64, default_recv_flow: u64 = 65536) -> i32, bool
fn open_local_stream(tbl: QuicStreamTable&, is_bidi: bool, default_recv_flow: u64 = 65536) -> u64, i32, bool
```

`QuicFlowControl` tracks connection-level send/receive credit, enforces
monotonic `MAX_DATA` updates, and triggers auto-tuning window renewals via
`fc.check_conn_window_update()`. `QuicStream` implements the RFC 9000 §3 stream
state machine (`QuicSendState`, `QuicRecvState`), and `QuicStreamTable`
multiplexes active streams with terminal slot reuse, concurrency bounds, and
evicted closed-stream tracking.

### Transport Coordination, Migration, DPLPMTUD & Congestion Control (`connection.goose`, `migration.goose`, `dplpmtud.goose`, `bbr.goose`)

```goose
// quic/connection.goose
enum QuicConnState { Initial, Handshake, Established, Closing, Draining, Closed }
struct ProcessResult
struct QuicConnection

fn new_client_connection(server_dcid: const u8[:], client_scid: const u8[:]) -> QuicConnection
fn new_server_connection(scid: const u8[:]) -> QuicConnection
fn can_send(conn: const QuicConnection&, bytes: u64) -> bool
fn advance_state(conn: QuicConnection&, new_state: QuicConnState)
fn close(conn: QuicConnection&, err_code: u64)
fn on_ack(conn: QuicConnection&, ack_frame: const AckFrame&, now_us: u64 = 100000, space_id: PnSpaceId = PnSpaceId.ApplicationData) -> bool
fn record_sent(conn: QuicConnection&, space_id: PnSpaceId, pn: u64, size_bytes: u64, ack_eliciting: bool, now_us: u64)
fn migrate(conn: QuicConnection&, new_addr: const QuicEndpointAddr&, token: const u8[8]&)
fn on_probe_acked(conn: QuicConnection&, acked_size: u32) -> bool
fn on_probe_lost(conn: QuicConnection&, lost_size: u32) -> bool
fn is_frame_allowed_in_packet(ftype: QuicFrameType, htype: QuicHeaderType) -> bool
fn process_payload(conn: QuicConnection&, payload: const u8[:], htype: QuicHeaderType = QuicHeaderType.OneRtt, now_us: u64 = 100000) -> ProcessResult
fn install_initial_keys(conn: QuicConnection&, dcid: const u8[:], version: u32 = rfc::QUIC_VERSION_1) -> bool
fn seal_packet<B>(space: const PnSpaceState&, hdr: const QuicHeader&, pn_len: u8, plaintext: const u8[:], out: B&) -> bool
fn process_datagram(conn: QuicConnection&, dgram: const u8[:], now_us: u64, ack: AckFrame&) -> ProcessResult

// quic/migration.goose (RFC 9000 §9)
enum PathValidationState { Initiated, Validating, Validated, Failed }
struct QuicEndpointAddr
struct QuicPath
struct QuicMigrationManager
struct QuicPreferredAddress

fn new_endpoint_addr(ip: const u8[:], port: u16) -> QuicEndpointAddr
fn addr_eq(a: const QuicEndpointAddr&, b: const QuicEndpointAddr&) -> bool
fn decode_preferred_address(src: const u8[:]) -> QuicPreferredAddress, bool
fn new_migration_manager(initial_addr: const QuicEndpointAddr&) -> QuicMigrationManager
fn can_send(path: const QuicPath&, bytes_to_send: u64) -> bool
fn generate_path_challenge_token(rng_seed: u64&) -> u8[8]
fn verify_path_response_token(expected: const u8[8]&, received: const u8[:]) -> bool
fn start_probing(mgr: QuicMigrationManager&, new_addr: const QuicEndpointAddr&, token: const u8[8]&)
fn probe_preferred_address(mgr: QuicMigrationManager&, pref: const QuicPreferredAddress&, prefer_ipv6: bool, token: const u8[8]&) -> bool
fn on_path_response(mgr: QuicMigrationManager&, response_data: const u8[:]) -> bool
fn complete(mgr: QuicMigrationManager&) -> bool
fn fail_probing(mgr: QuicMigrationManager&)
fn retry_probe(mgr: QuicMigrationManager&) -> bool

// quic/dplpmtud.goose (RFC 8899)
enum DplpmtudState { Search, Base, SearchComplete, Error }
struct Dplpmtud

fn calc_dplpmtud_probe_payload_size(target_mtu: u32, overhead_bytes: u32) -> u32
fn generate_ping_probe<B>(target_size: u32, out: B&) -> bool
fn generate_path_challenge_probe<B>(data: const u8[8]&, target_size: u32, out: B&) -> bool
fn on_probe_acked(d: Dplpmtud&, acked_size: u32) -> bool
fn on_probe_lost(d: Dplpmtud&, lost_size: u32) -> bool
fn on_search_timer(d: Dplpmtud&, now_ms: u64)

// quic/bbr.goose
enum BbrMode { Startup, Drain, ProbeBwDown, ProbeBwCruise, ProbeBwRefill, ProbeBwUp, ProbeRtt }
struct Pacer
struct BbrState
struct CubicState

fn new_pacer(initial_rate_bps: u64 = 10000000) -> Pacer
fn can_send(pacer: Pacer&, now_us: u64, packet_bytes: u64) -> u64, bool
fn bbr_bdp(bw_bps: u64, min_rtt_us: u64) -> u64
fn check_probe_rtt(bbr: BbrState&, now_us: u64, rtt_sample_us: u64)
fn update_pacing_and_cwnd(bbr: BbrState&)
fn on_congestion_signal(bbr: BbrState&, bytes_in_flight: u64, loss_bytes: u64, total_acked_bytes: u64, ecn_ce_count: u64, new_acked_packets: u64)
fn advance_cycle(bbr: BbrState&, round_done: bool)
fn on_ack(cubic: CubicState&, now_us: u64, rtt_us: u64, bytes_in_flight: u64, mss_bytes: u64 = 1200) -> u64
fn on_loss(cubic: CubicState&, now_us: u64, pkt_sent_us: u64 = 0)
```

`QuicConnection` coordinates packet number spaces, encryption levels,
anti-amplification limits, stream multiplexing, and ingress datagram demuxing
(`conn.process_datagram(dgram, now_us, ack)`). `QuicMigrationManager` handles
RFC 9000 §9 path probing (`PATH_CHALLENGE` / `PATH_RESPONSE`),
`QuicEndpointAddr` validation, and `QuicPreferredAddress` migration. `Dplpmtud`
implements RFC 8899 Datagram Packetization Layer PMTUD probe generation, step
search, and blackhole recovery. `bbr.goose` provides a leaky-bucket `Pacer`, a
BBRv3 controller (`BbrState`) with bandwidth-delay product estimation and
ECN/loss response, and an RFC 9438 `CubicState` controller with
application-limited epoch freezing.
